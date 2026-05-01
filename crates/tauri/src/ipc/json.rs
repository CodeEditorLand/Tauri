// LAND-PATCH B3.P1: simd-json facade for the IPC hot path.
//
// `format_callback.rs::format`, `protocol.rs` response shaping, and
// `channel.rs` binary streaming all hit `serde_json::to_string` on
// the per-invoke critical path. Stock serde_json is fine for small
// payloads but its single-byte state machine maxes out at ~350 MB/s
// on x86_64 / Apple Silicon. simd-json's serializer hits ~1.5 GB/s
// on the structured-flat shapes we serialise.
//
// Behind the `land-simd-json` Cargo feature. When the feature is
// off, all functions delegate to `serde_json` for upstream parity.
//
// Errors are normalised to `serde_json::Error` so call sites do not
// need to thread a different error type. simd-json errors are
// converted via `serde::ser::Error::custom`.

use serde::Serialize;

#[cfg(feature = "land-simd-json")]
use serde::ser::Error as _;

/// Serialise `value` into a JSON string. Mirror of
/// `serde_json::to_string` semantics; routes through simd-json's
/// serializer when the `land-simd-json` feature is enabled.
#[inline]
pub fn to_string<T: ?Sized + Serialize>(value: &T) -> Result<String, serde_json::Error> {
  #[cfg(feature = "land-simd-json")]
  {
    simd_json::serde::to_string(value).map_err(|error| serde_json::Error::custom(error.to_string()))
  }
  #[cfg(not(feature = "land-simd-json"))]
  {
    serde_json::to_string(value)
  }
}

/// Serialise `value` into a JSON byte buffer.
#[inline]
pub fn to_vec<T: ?Sized + Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
  #[cfg(feature = "land-simd-json")]
  {
    simd_json::serde::to_vec(value).map_err(|error| serde_json::Error::custom(error.to_string()))
  }
  #[cfg(not(feature = "land-simd-json"))]
  {
    serde_json::to_vec(value)
  }
}
