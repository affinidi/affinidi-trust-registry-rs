#[cfg(feature = "storage-csv")]
pub mod csv_file_storage;
#[cfg(feature = "storage-ddb")]
pub mod ddb_storage;
#[cfg(feature = "storage-fjall")]
pub mod fjall_storage;
/// In-memory store. Dependency-free and always compiled, so a host embedding
/// the registry always has a working backend without picking a feature.
pub mod local_storage;
#[cfg(feature = "storage-redis")]
pub mod redis_storage;
