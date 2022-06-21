use std::collections::btree_map::BTreeMap;
use std::path::PathBuf;
use std::slice::from_raw_parts;

use log::info;

use anyhow::{ensure, Result};
use ffi_toolkit::{c_str_to_pbuf, c_str_to_rust_str};
use filecoin_proofs_api::{PrivateReplicaInfo, PublicReplicaInfo, SectorId};

use crate::proofs::types::{fil_PoStProof, PoStProof};

use super::types::{fil_PrivateReplicaInfo, fil_PublicReplicaInfo, fil_RegisteredPoStProof};

#[derive(Debug, Clone)]
struct PublicReplicaInfoTmp {
    pub registered_proof: fil_RegisteredPoStProof,
    pub comm_r: [u8; 32],
    pub sector_id: u64,
}

#[cfg(feature = "gpu")]
pub fn init_gpu_pool() {
    let _ = &bellperson::gpu::DEVICE_POOL.devices.iter().for_each(|d| {
        info!("Initializing device: {} (Bus-id: {})",
              d.lock().unwrap().device().name(),
              d.lock().unwrap().device().bus_id().unwrap()
        );
    });
}

#[cfg(not(feature = "gpu"))]
pub fn init_gpu_pool() {}

pub fn init_binded_threadpool() -> Result<(), rayon::ThreadPoolBuildError> {
    use thread_binder::ThreadPoolBuilder;

    ThreadPoolBuilder::new()
        .num_threads(num_cpus::get())
        .build_global()
}

#[allow(clippy::type_complexity)]
pub unsafe fn to_public_replica_info_map(
    replicas_ptr: *const fil_PublicReplicaInfo,
    replicas_len: libc::size_t,
) -> Result<BTreeMap<SectorId, PublicReplicaInfo>> {
    use rayon::prelude::*;

    if std::env::var("FIL_PROOFS_CORE_BINDED_THREADPOOL")
        .and_then(|v| match v.parse() {
            Ok(val) => Ok(val),
            Err(_) => {
                print!("Invalid FIL_PROOFS_CORE_BINDED_THREADPOOL! Defaulting to {}", false);
                Ok(false)
            }
        })
        .unwrap_or(false) {
        if init_binded_threadpool().is_err() {
            print!("Core-binded threadpool was already initialized");
        };
    }

    if std::env::var("FIL_ZK_PRECOMPILE_GPU_CORES")
        .and_then(|v| match v.parse() {
            Ok(val) => Ok(val),
            Err(_) => {
                print!("Invalid FIL_ZK_PRECOMPILE_GPU_CORES! Defaulting to {}", false);
                Ok(false)
            }
        })
        .unwrap_or(false) {
        init_gpu_pool();
    }

    ensure!(!replicas_ptr.is_null(), "replicas_ptr must not be null");

    let mut replicas = Vec::new();

    for ffi_info in from_raw_parts(replicas_ptr, replicas_len) {
        replicas.push(PublicReplicaInfoTmp {
            sector_id: ffi_info.sector_id,
            registered_proof: ffi_info.registered_proof,
            comm_r: ffi_info.comm_r,
        });
    }

    let map = replicas
        .into_par_iter()
        .map(|info| {
            let PublicReplicaInfoTmp {
                registered_proof,
                comm_r,
                sector_id,
            } = info;

            (
                SectorId::from(sector_id),
                PublicReplicaInfo::new(registered_proof.into(), comm_r),
            )
        })
        .collect();

    Ok(map)
}

#[derive(Debug, Clone)]
struct PrivateReplicaInfoTmp {
    pub registered_proof: fil_RegisteredPoStProof,
    pub cache_dir_path: std::path::PathBuf,
    pub comm_r: [u8; 32],
    pub replica_path: std::path::PathBuf,
    pub sector_id: u64,
}

pub unsafe fn to_private_replica_info_map(
    replicas_ptr: *const fil_PrivateReplicaInfo,
    replicas_len: libc::size_t,
) -> Result<BTreeMap<SectorId, PrivateReplicaInfo>> {
    use rayon::prelude::*;

    if std::env::var("FIL_PROOFS_CORE_BINDED_THREADPOOL")
        .and_then(|v| match v.parse() {
            Ok(val) => Ok(val),
            Err(_) => {
                print!("Invalid FIL_PROOFS_CORE_BINDED_THREADPOOL! Defaulting to {}", false);
                Ok(false)
            }
        })
        .unwrap_or(false) {
        if init_binded_threadpool().is_err() {
            print!("Core-binded threadpool was already initialized");
        };
    }

    if std::env::var("FIL_ZK_PRECOMPILE_GPU_CORES")
        .and_then(|v| match v.parse() {
            Ok(val) => Ok(val),
            Err(_) => {
                print!("Invalid FIL_ZK_PRECOMPILE_GPU_CORES! Defaulting to {}", false);
                Ok(false)
            }
        })
        .unwrap_or(false) {
        init_gpu_pool();
    }

    ensure!(!replicas_ptr.is_null(), "replicas_ptr must not be null");

    let replicas: Vec<_> = from_raw_parts(replicas_ptr, replicas_len)
        .iter()
        .map(|ffi_info| {
            let cache_dir_path = c_str_to_pbuf(ffi_info.cache_dir_path);
            let replica_path = c_str_to_rust_str(ffi_info.replica_path).to_string();

            PrivateReplicaInfoTmp {
                registered_proof: ffi_info.registered_proof,
                cache_dir_path,
                comm_r: ffi_info.comm_r,
                replica_path: PathBuf::from(replica_path),
                sector_id: ffi_info.sector_id,
            }
        })
        .collect();

    let map = replicas
        .into_par_iter()
        .map(|info| {
            let PrivateReplicaInfoTmp {
                registered_proof,
                cache_dir_path,
                comm_r,
                replica_path,
                sector_id,
            } = info;

            (
                SectorId::from(sector_id),
                PrivateReplicaInfo::new(
                    registered_proof.into(),
                    comm_r,
                    cache_dir_path,
                    replica_path,
                ),
            )
        })
        .collect();

    Ok(map)
}

pub unsafe fn c_to_rust_post_proofs(
    post_proofs_ptr: *const fil_PoStProof,
    post_proofs_len: libc::size_t,
) -> Result<Vec<PoStProof>> {
    ensure!(
        !post_proofs_ptr.is_null(),
        "post_proofs_ptr must not be null"
    );

    let out = from_raw_parts(post_proofs_ptr, post_proofs_len)
        .iter()
        .map(|fpp| PoStProof {
            registered_proof: fpp.registered_proof.into(),
            proof: from_raw_parts(fpp.proof_ptr, fpp.proof_len).to_vec(),
        })
        .collect();

    Ok(out)
}
