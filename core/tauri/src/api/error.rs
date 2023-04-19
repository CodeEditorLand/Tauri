// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

/// The error types.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
  /// Command error.
  #[error("Command Error: {0}")]
  Command(String),
  /// The path operation error.
  #[error("Path Error: {0}")]
  Path(String),
  /// The path StripPrefixError error.
  #[error("Path Error: {0}")]
  PathPrefix(#[from] std::path::StripPrefixError),
  /// Error showing the dialog.
  #[error("Dialog Error: {0}")]
  Dialog(String),
  /// The dialog operation was cancelled by the user.
  #[error("user cancelled the dialog")]
  DialogCancelled,
  /// The network error.
  #[error("Network Error: {0}")]
  Network(#[from] reqwest::Error),
  /// Invalid HTTP header value.
  #[error(transparent)]
  HttpHeaderValue(#[from] http::header::InvalidHeaderValue),
  /// Invalid HTTP header value.
  #[error(transparent)]
  HttpHeader(#[from] http::header::InvalidHeaderName),
  /// Failed to convert bytes to string.
  #[error(transparent)]
  Utf8(#[from] std::string::FromUtf8Error),
  /// HTTP form to must be an object.
  #[error("http form must be an object")]
  InvalidHttpForm,
  /// Semver error.
  #[error(transparent)]
  Semver(#[from] semver::Error),
  /// JSON error.
  #[error(transparent)]
  Json(#[from] serde_json::Error),
  /// IO error.
  #[error(transparent)]
  Io(#[from] std::io::Error),
  /// Ignore error.
  #[error("failed to walkdir: {0}")]
  Ignore(#[from] ignore::Error),
  /// ZIP error.
  #[cfg(feature = "fs-extract-api")]
  #[error(transparent)]
  Zip(#[from] zip::result::ZipError),
  /// Extract error.
  #[cfg(feature = "fs-extract-api")]
  #[error("Failed to extract: {0}")]
  Extract(String),
  /// Url error.
  #[error(transparent)]
  Url(#[from] url::ParseError),
  /// failed to detect the current platform.
  #[error("failed to detect platform: {0}")]
  FailedToDetectPlatform(String),
  /// Shell error.
  #[error("shell error: {0}")]
  Shell(String),
  /// Unknown program name.
  #[error("unknown program name: {0}")]
  UnknownProgramName(String),
  /// HTTP error.
  #[error(transparent)]
  Http(#[from] http::Error),
}
