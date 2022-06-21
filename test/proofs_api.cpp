//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE proofs_api_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <filcrypto.h>

BOOST_AUTO_TEST_SUITE(proofs_api_test_suite)

BOOST_AUTO_TEST_CASE(test_write_with_and_without_alignment) {
  fil_RegisteredSealProof registered_proof = fil_RegisteredSealProof::fil_RegisteredSealProof_StackedDrg2KiBV1;

  // write some bytes to a temp file to be used as the byte source
  let mut rng = thread_rng();
  let buf : Vec<u8> = (0..508).map(| _ | rng.gen()).collect();

  // first temp file occupies 4 nodes in a merkle tree built over the
  // destination (after preprocessing)
  let mut src_file_a = tempfile::tempfile() ? ;
  src_file_a.write_all(&buf[0..127])        ? ;
  src_file_a.seek(SeekFrom::Start(0))       ? ;

  // second occupies 16 nodes
  let mut src_file_b = tempfile::tempfile() ? ;
  src_file_b.write_all(&buf[0..508])        ? ;
  src_file_b.seek(SeekFrom::Start(0))       ? ;

  // create a temp file to be used as the byte destination
  let dest = tempfile::tempfile() ? ;

  // transmute temp files to file descriptors
  let src_fd_a = src_file_a.into_raw_fd();
  let src_fd_b = src_file_b.into_raw_fd();
  let dst_fd = dest.into_raw_fd();

  // write the first file
  unsafe {
    let resp =
        fil_write_without_alignment(registered_proof, src_fd_a, 127, dst_fd);

    if (*resp)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp).error_msg);
        panic !("write_without_alignment failed: {:?}", msg);
      }

    BOOST_CHECK_EQUAL((*resp).total_write_unpadded, 127,
                "should have added 127 bytes of (unpadded) left alignment");
  }

  // write the second
  unsafe {
    let existing = vec ![127u64];

    let resp = fil_write_with_alignment(registered_proof, src_fd_b, 508, dst_fd,
                                        existing.as_ptr(), existing.size(), );

    if (*resp)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp).error_msg);
        panic !("write_with_alignment failed: {:?}", msg);
      }

    BOOST_CHECK_EQUAL((*resp).left_alignment_unpadded, 381,
                "should have added 381 bytes of (unpadded) left alignment");
  }
}

BOOST_AUTO_TEST_CASE(test_proof_types) {
  let seal_types = vec ![
    fil_RegisteredSealProof::StackedDrg2KiBV1,
    fil_RegisteredSealProof::StackedDrg8MiBV1,
    fil_RegisteredSealProof::StackedDrg512MiBV1,
    fil_RegisteredSealProof::StackedDrg32GiBV1,
  ];

  let post_types = vec ![
    fil_RegisteredPoStProof::StackedDrgWinning2KiBV1,
    fil_RegisteredPoStProof::StackedDrgWinning8MiBV1,
    fil_RegisteredPoStProof::StackedDrgWinning512MiBV1,
    fil_RegisteredPoStProof::StackedDrgWinning32GiBV1,
    fil_RegisteredPoStProof::StackedDrgWindow2KiBV1,
    fil_RegisteredPoStProof::StackedDrgWindow8MiBV1,
    fil_RegisteredPoStProof::StackedDrgWindow512MiBV1,
    fil_RegisteredPoStProof::StackedDrgWindow32GiBV1,
  ];

  let num_ops = (seal_types.size() + post_types.size()) * 6;

  let mut pairs : Vec<(&str, *mut fil_StringResponse)> =
                      Vec::with_capacity(num_ops);

  unsafe {
for
  st in seal_types {
    pairs.push(("get_seal_params_cid", fil_get_seal_params_cid(st)));
    pairs.push(
        ("get_seal_verify_key_cid", fil_get_seal_verifying_key_cid(st), ));
    pairs.push(("get_seal_verify_key_cid", fil_get_seal_params_path(st)));
    pairs.push(
        ("get_seal_verify_key_cid", fil_get_seal_verifying_key_path(st), ));
    pairs.push(
        ("get_seal_circuit_identifier", fil_get_seal_circuit_identifier(st), ));
    pairs.push(("get_seal_version", fil_get_seal_version(st)));
  }

for (pt : post_types) {
  pairs.push(("get_post_params_cid", fil_get_post_params_cid(pt)));
  pairs.push(("get_post_verify_key_cid", fil_get_post_verifying_key_cid(pt), ));
  pairs.push(("get_post_params_path", fil_get_post_params_path(pt)));
  pairs.push(
      ("get_post_verifying_key_path", fil_get_post_verifying_key_path(pt), ));
  pairs.push(
      ("get_post_circuit_identifier", fil_get_post_circuit_identifier(pt), ));
  pairs.push(("get_post_version", fil_get_post_version(pt)));
}
  }

  for (label, r)
    in pairs {
      unsafe {
        BOOST_CHECK_EQUAL((*r).status_code, FCPResponseStatus::FCPNoError,
                    "non-success exit code from {:?}: {:?}", label,
                    c_str_to_rust_str((*r).error_msg));

        let x = CStr::from_ptr((*r).string_val);
        let y = x.to_str().unwrap();

        assert !(!y.is_empty());

        fil_destroy_string_response(r);
      }
    }

  Ok(())
}

BOOST_AUTO_TEST_CASE(test_sealing) {
  let wrap = | x | fil_32ByteArray{inner : x};

  // miscellaneous setup and shared values
  let registered_proof_seal = fil_RegisteredSealProof::StackedDrg2KiBV1;
  let registered_proof_winning_post =
      fil_RegisteredPoStProof::StackedDrgWinning2KiBV1;
  let registered_proof_window_post =
      fil_RegisteredPoStProof::StackedDrgWindow2KiBV1;

  let cache_dir = tempfile::tempdir() ? ;
  let cache_dir_path = cache_dir.into_path();

  let prover_id = fil_32ByteArray {
  inner:
    [1u8; 32]
  };
  let randomness = fil_32ByteArray {
  inner:
    [7u8; 32]
  };
  let sector_id = 42;
  let seed = fil_32ByteArray {
  inner:
    [5u8; 32]
  };
  let ticket = fil_32ByteArray {
  inner:
    [6u8; 32]
  };

  // create a byte source (a user's piece)
  let mut rng = thread_rng();
  let buf_a : Vec<u8> = (0..2032).map(| _ | rng.gen()).collect();

  let mut piece_file_a = tempfile::tempfile() ? ;
  piece_file_a.write_all(&buf_a[0..127])      ? ;
  piece_file_a.seek(SeekFrom::Start(0))       ? ;

  let mut piece_file_b = tempfile::tempfile() ? ;
  piece_file_b.write_all(&buf_a[0..1016])     ? ;
  piece_file_b.seek(SeekFrom::Start(0))       ? ;

  // create the staged sector (the byte destination)
  let(staged_file, staged_path) = tempfile::NamedTempFile::new () ?.keep() ? ;

  // create a temp file to be used as the byte destination
  let(sealed_file, sealed_path) = tempfile::NamedTempFile::new () ?.keep() ? ;

  // last temp file is used to output unsealed bytes
  let(unseal_file, unseal_path) = tempfile::NamedTempFile::new () ?.keep() ? ;

  // transmute temp files to file descriptors
  let piece_file_a_fd = piece_file_a.into_raw_fd();
  let piece_file_b_fd = piece_file_b.into_raw_fd();
  let staged_sector_fd = staged_file.into_raw_fd();

  unsafe {
    let resp_a1 = fil_write_without_alignment(
        registered_proof_seal, piece_file_a_fd, 127, staged_sector_fd, );

    if (*resp_a1)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp_a1).error_msg);
        panic !("write_without_alignment failed: {:?}", msg);
      }

    let existing_piece_sizes = vec ![127];

    let resp_a2 = fil_write_with_alignment(
        registered_proof_seal, piece_file_b_fd, 1016, staged_sector_fd,
        existing_piece_sizes.as_ptr(), existing_piece_sizes.size(), );

    if (*resp_a2)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp_a2).error_msg);
        panic !("write_with_alignment failed: {:?}", msg);
      }

    let pieces = vec ![
      fil_PublicPieceInfo{
        num_bytes : 127,
        comm_p : (*resp_a1).comm_p,
      },
      fil_PublicPieceInfo{
        num_bytes : 1016,
        comm_p : (*resp_a2).comm_p,
      },
    ];

    let resp_x = fil_generate_data_commitment(registered_proof_seal,
                                              pieces.as_ptr(), pieces.size());

    if (*resp_x)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp_x).error_msg);
        panic !("generate_data_commitment failed: {:?}", msg);
      }

    let cache_dir_path_c_str =
        rust_str_to_c_str(cache_dir_path.to_str().unwrap());
    let staged_path_c_str = rust_str_to_c_str(staged_path.to_str().unwrap());
    let replica_path_c_str = rust_str_to_c_str(sealed_path.to_str().unwrap());
    let unseal_path_c_str = rust_str_to_c_str(unseal_path.to_str().unwrap());

    let resp_b1 = fil_seal_pre_commit_phase1(
        registered_proof_seal, cache_dir_path_c_str, staged_path_c_str,
        replica_path_c_str, sector_id, prover_id, ticket, pieces.as_ptr(),
        pieces.size(), );

    if (*resp_b1)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp_b1).error_msg);
        panic !("seal_pre_commit_phase1 failed: {:?}", msg);
      }

    let resp_b2 =
        fil_seal_pre_commit_phase2((*resp_b1).seal_pre_commit_phase1_output_ptr,
                                   (*resp_b1).seal_pre_commit_phase1_output_len,
                                   cache_dir_path_c_str, replica_path_c_str, );

    if (*resp_b2)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp_b2).error_msg);
        panic !("seal_pre_commit_phase2 failed: {:?}", msg);
      }

    let pre_computed_comm_d = &(*resp_x).comm_d;
    let pre_commit_comm_d = &(*resp_b2).comm_d;

    BOOST_CHECK_EQUAL(format !("{:x?}", &pre_computed_comm_d),
                format !("{:x?}", &pre_commit_comm_d),
                "pre-computed CommD and pre-commit CommD don't match");

    let resp_c1 = fil_seal_commit_phase1(
        registered_proof_seal, wrap((*resp_b2).comm_r), wrap((*resp_b2).comm_d),
        cache_dir_path_c_str, replica_path_c_str, sector_id, prover_id, ticket,
        seed, pieces.as_ptr(), pieces.size(), );

    if (*resp_c1)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp_c1).error_msg);
        panic !("seal_commit_phase1 failed: {:?}", msg);
      }

    let resp_c2 = fil_seal_commit_phase2(
        (*resp_c1).seal_commit_phase1_output_ptr,
        (*resp_c1).seal_commit_phase1_output_len, sector_id, prover_id, );

    if (*resp_c2)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp_c2).error_msg);
        panic !("seal_commit_phase2 failed: {:?}", msg);
      }

    let resp_d = fil_verify_seal(registered_proof_seal, wrap((*resp_b2).comm_r),
                                 wrap((*resp_b2).comm_d), prover_id, ticket,
                                 seed, sector_id, (*resp_c2).proof_ptr,
                                 (*resp_c2).proof_len, );

    if (*resp_d)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp_d).error_msg);
        panic !("seal_commit failed: {:?}", msg);
      }

    assert !((*resp_d).is_valid, "proof was not valid");

    let resp_e = fil_unseal_range(
        registered_proof_seal, cache_dir_path_c_str, sealed_file.into_raw_fd(),
        unseal_file.into_raw_fd(), sector_id, prover_id, ticket,
        wrap((*resp_b2).comm_d), 0, 2032, );

    if (*resp_e)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp_e).error_msg);
        panic !("unseal failed: {:?}", msg);
      }

    // ensure unsealed bytes match what we had in our piece
    let mut buf_b = Vec::with_capacity(2032);
    let mut f = std::fs::File::open(unseal_path) ? ;

    let _ = f.read_to_end(&mut buf_b) ? ;

    let piece_a_len = (*resp_a1).total_write_unpadded as usize;
    let piece_b_len = (*resp_a2).total_write_unpadded as usize;
    let piece_b_prefix_len = (*resp_a2).left_alignment_unpadded as usize;

    let alignment = vec ![0; piece_b_prefix_len];

    let expected =
        [
          &buf_a[0..piece_a_len],
          &alignment[..],
          &buf_a[0..(piece_b_len - piece_b_prefix_len)],
        ]
            .concat();

    BOOST_CHECK_EQUAL(format !("{:x?}", &expected), format !("{:x?}", &buf_b),
                "original bytes don't match unsealed bytes");

    // generate a PoSt

    let sectors = vec ![sector_id];
    let resp_f = fil_generate_winning_post_sector_challenge(
        registered_proof_winning_post, randomness, sectors.size() as u64,
        prover_id, );

    if (*resp_f)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp_f).error_msg);
        panic !("generate_candidates failed: {:?}", msg);
      }

    // exercise the ticket-finalizing code path (but don't do anything
    // with the results
    let result : &[u64] = from_raw_parts((*resp_f).ids_ptr, (*resp_f).ids_len);

    if result
      .is_empty() { panic !("generate_candidates produced no results"); }

    let private_replicas = vec ![fil_PrivateReplicaInfo{
      registered_proof : registered_proof_winning_post,
      cache_dir_path : cache_dir_path_c_str,
      comm_r : (*resp_b2).comm_r,
      replica_path : replica_path_c_str,
      sector_id,
    }];

    // winning post

    let resp_h =
        fil_generate_winning_post(randomness, private_replicas.as_ptr(),
                                  private_replicas.size(), prover_id, );

    if (*resp_h)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp_h).error_msg);
        panic !("generate_winning_post failed: {:?}", msg);
      }
    let public_replicas = vec ![fil_PublicReplicaInfo{
      registered_proof : registered_proof_winning_post,
      sector_id,
      comm_r : (*resp_b2).comm_r,
    }];

    let resp_i = fil_verify_winning_post(
        randomness, public_replicas.as_ptr(), public_replicas.size(),
        (*resp_h).proofs_ptr, (*resp_h).proofs_len, prover_id, );

    if (*resp_i)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp_i).error_msg);
        panic !("verify_winning_post failed: {:?}", msg);
      }

    if
      !(*resp_i).is_valid {
        panic !("verify_winning_post rejected the provided proof as invalid");
      }

    // window post

    let private_replicas = vec ![fil_PrivateReplicaInfo{
      registered_proof : registered_proof_window_post,
      cache_dir_path : cache_dir_path_c_str,
      comm_r : (*resp_b2).comm_r,
      replica_path : replica_path_c_str,
      sector_id,
    }];

    let resp_j = fil_generate_window_post(randomness, private_replicas.as_ptr(),
                                          private_replicas.size(), prover_id, );

    if (*resp_j)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp_j).error_msg);
        panic !("generate_window_post failed: {:?}", msg);
      }

    let public_replicas = vec ![fil_PublicReplicaInfo{
      registered_proof : registered_proof_window_post,
      sector_id,
      comm_r : (*resp_b2).comm_r,
    }];

    let resp_k = fil_verify_window_post(
        randomness, public_replicas.as_ptr(), public_replicas.size(),
        (*resp_j).proofs_ptr, (*resp_j).proofs_len, prover_id, );

    if (*resp_k)
      .status_code != FCPResponseStatus::FCPNoError {
        let msg = c_str_to_rust_str((*resp_k).error_msg);
        panic !("verify_window_post failed: {:?}", msg);
      }

    if
      !(*resp_k).is_valid {
        panic !("verify_window_post rejected the provided proof as invalid");
      }

    fil_destroy_write_without_alignment_response(resp_a1);
    fil_destroy_write_with_alignment_response(resp_a2);
    fil_destroy_generate_data_commitment_response(resp_x);

    fil_destroy_seal_pre_commit_phase1_response(resp_b1);
    fil_destroy_seal_pre_commit_phase2_response(resp_b2);
    fil_destroy_seal_commit_phase1_response(resp_c1);
    fil_destroy_seal_commit_phase2_response(resp_c2);

    fil_destroy_verify_seal_response(resp_d);
    fil_destroy_unseal_range_response(resp_e);

    fil_destroy_generate_winning_post_sector_challenge(resp_f);
    fil_destroy_generate_winning_post_response(resp_h);
    fil_destroy_verify_winning_post_response(resp_i);

    fil_destroy_generate_window_post_response(resp_j);
    fil_destroy_verify_window_post_response(resp_k);

    c_str_to_rust_str(cache_dir_path_c_str);
    c_str_to_rust_str(staged_path_c_str);
    c_str_to_rust_str(replica_path_c_str);
    c_str_to_rust_str(unseal_path_c_str);
  }

  Ok(())
}
}

BOOST_AUTO_TEST_SUITE_END()