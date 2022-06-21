//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE bls_api_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <filcrypto.h>

BOOST_AUTO_TEST_SUITE(bls_api_test_suite)

BOOST_AUTO_TEST_CASE(key_verification) {
      let private_key = (*fil_private_key_generate()).private_key.inner;
      let public_key =
      (*fil_private_key_public_key(&private_key[0])).public_key.inner;
      let message = b "hello world";
      let digest = (*fil_hash(&message[0], message.size())).digest.inner;
      let signature =
      (*fil_private_key_sign(&private_key[0], &message[0], message.size()))
      .signature.inner;
      let verified = fil_verify(&signature[0], &digest[0], digest.size(),
      &public_key[0], public_key.size(), );

      BOOST_CHECK_EQUAL(1, verified);

      let flattened_messages = message;
      let message_sizes = [message.size()];
      let verified = fil_hash_verify(
      signature.as_ptr(), flattened_messages.as_ptr(),
      flattened_messages.size(), message_sizes.as_ptr(), message_sizes.size(),
      public_key.as_ptr(), public_key.size(), );

      BOOST_CHECK_EQUAL(1, verified);

      let different_message = b "bye world";
      let different_digest =
      (*fil_hash(&different_message[0], different_message.size()))
      .digest.inner;
      let not_verified = fil_verify(&signature[0], &different_digest[0],
      different_digest.size(), &public_key[0],
      public_key.size(), );

      BOOST_CHECK_EQUAL(0, not_verified);

      // garbage verification
      let different_digest = vec ![ 0, 1, 2, 3, 4 ];
      let not_verified = fil_verify(&signature[0], &different_digest[0],
      different_digest.size(), &public_key[0],
      public_key.size(), );

      BOOST_CHECK_EQUAL(0, not_verified);
}

BOOST_AUTO_TEST_CASE(private_key_with_seed) {
      let seed = fil_32ByteArray {
        inner:
        [5u8; 32]
      };
      let private_key =
      (*fil_private_key_generate_with_seed(seed)).private_key.inner;
      BOOST_CHECK_EQUAL(
      [
      115, 245, 77,  209, 4,   57,  40,  107, 10,  153, 141,
      16,  153, 172, 85,  197, 125, 163, 35,  217, 108, 241,
      64,  235, 231, 220, 131, 1,   77,  253, 176, 19
      ],
      private_key);
}

BOOST_AUTO_TEST_SUITE_END()