// Copyright 2019-2024 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use std::{borrow::Cow, io::Read, sync::Arc};

use http::{
  header::{HeaderName, HeaderValue, CONTENT_TYPE},
  HeaderMap, Request, Response as HttpResponse, StatusCode,
};
use mime_guess;
use tauri_utils::config::HeaderAddition;

// --- Use crate:: paths for types defined within the tauri crate ---
use crate::{
  manager::AppManager,
  webview::{UriSchemeProtocolHandler, WebResourceRequestHandler},
  Runtime,
};

// --- Import types needed for the mobile dev proxy conditionally ---
#[cfg(all(dev, mobile))]
use {
  bytes::Bytes,
  // rustls_pemfile, // Commented out: Not used in bypass logic
  std::{collections::HashMap, /* io::Cursor, */ sync::Mutex, time::Duration}, // Commented out Cursor
  // Import rustls types THROUGH ureq's re-export (Needed for NoServerVerification impl)
  ureq::rustls::{
    client::{
      self,
      danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::ring::default_provider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig,
    DigitallySignedStruct,
    Error as RustlsError, // RootCertStore commented out
    SignatureScheme,      // RootCertStore, // Commented out: Not used in bypass logic
  },
  // Other needed types
  ureq::{Agent, AgentBuilder},
};

// --- Define the state type unconditionally ---
// Still potentially needed as a type key if state retrieval is restored later
type CustomCaCertPemState = Arc<Option<Vec<u8>>>;

// --- Define CachedResponse conditionally ---
#[cfg(all(dev, mobile))]
#[derive(Clone)]
struct CachedResponse {
  status: http::StatusCode,
  headers: http::HeaderMap,
  body: Bytes,
}

// --- DANGEROUS: Certificate Verifier that trusts everything ---
// This struct implements the trait needed to bypass verification
#[cfg(all(dev, mobile))]
#[derive(Debug)]
struct NoServerVerification;

#[cfg(all(dev, mobile))]
impl ServerCertVerifier for NoServerVerification {
  // Called by rustls to verify the server certificate. We just say OK.
  fn verify_server_cert(
    &self,
    _end_entity: &CertificateDer<'_>, // The server's certificate
    _intermediates: &[CertificateDer<'_>], // Any intermediate certs provided
    _server_name: &ServerName<'_>,    // The hostname we connected to
    _ocsp_response: &[u8],            // Stapled OCSP response, if any
    _now: UnixTime,                   // Current time
  ) -> Result<ServerCertVerified, RustlsError> {
    // log::warn!("[TauriProtocol::DANGEROUS] Bypassing all TLS server certificate verification!");
    // Indicates verification passed, without doing any checks.
    Ok(ServerCertVerified::assertion())
  }

  // Called by rustls to verify signatures in TLS 1.2 handshakes. We say OK.
  fn verify_tls12_signature(
    &self,
    _message: &[u8],              // Data that was signed
    _cert: &CertificateDer<'_>,   // Certificate whose public key was used
    _dss: &DigitallySignedStruct, // The signature structure
  ) -> Result<HandshakeSignatureValid, RustlsError> {
    // log::warn!("[TauriProtocol::DANGEROUS] Bypassing TLS 1.2 signature verification!");
    Ok(HandshakeSignatureValid::assertion())
  }

  // Called by rustls to verify signatures in TLS 1.3 handshakes. We say OK.
  fn verify_tls13_signature(
    &self,
    _message: &[u8],
    _cert: &CertificateDer<'_>,
    _dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, RustlsError> {
    // log::warn!("[TauriProtocol::DANGEROUS] Bypassing TLS 1.3 signature verification!");
    Ok(HandshakeSignatureValid::assertion())
  }

  // Returns the list of signature schemes this verifier supports.
  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    // Return the default schemes supported by the crypto provider (ring)
    default_provider()
      .signature_verification_algorithms
      .supported_schemes()
  }
}
// --- End DANGEROUS ---

pub fn get<R: Runtime>(
  manager: Arc<AppManager<R>>,
  window_origin: &str,
  web_resource_request_handler: Option<Box<WebResourceRequestHandler>>,
) -> UriSchemeProtocolHandler {
  // --- Conditionally get url_base and response_cache only for mobile dev ---
  #[cfg(all(dev, mobile))]
  let url_base = {
    let mut url = manager
      .get_url(window_origin.starts_with("https"))
      .as_str()
      .to_string();
    if url.ends_with('/') {
      url.pop();
    }
    // log::debug!(
    //   "[TauriProtocol::get] Determined dev server base URL: {}",
    //   url
    // );
    url
  };
  #[cfg(all(dev, mobile))]
  let response_cache = Arc::new(Mutex::new(HashMap::new()));

  let window_origin = window_origin.to_string();
  let manager_clone = manager.clone(); // Clone Arc for the closure

  Box::new(move |_webview_id, request, responder| {
    // Prefix unused webview_id
    let request_uri_string = request.uri().to_string();
    // log::debug!(
    //   "[TauriProtocol] Handling request for URI: {}",
    //   request_uri_string
    // );

    // Use the cloned manager inside the closure
    match get_response(
      request,
      &manager_clone,
      &window_origin,
      web_resource_request_handler.as_deref(),
      // --- Conditionally pass proxy-specific args ---
      #[cfg(all(dev, mobile))]
      (&url_base, &response_cache),
      &request_uri_string, // Pass original URI for logging
    ) {
      Ok(response) => {
        // log::debug!(
        //   "[TauriProtocol] Responding with status: {}",
        //   response.status()
        // );
        responder.respond(response)
      }
      Err(e) => {
        // log::error!(
        //   "[TauriProtocol] Error processing request for {}: {}",
        //   request_uri_string,
        //   e
        // );
        responder.respond(
          HttpResponse::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(CONTENT_TYPE, mime::TEXT_PLAIN.essence_str())
            .header("Access-Control-Allow-Origin", &window_origin)
            .body(
              format!(
                "Tauri protocol error: Failed to handle request. Error: {}",
                e
              )
              .into_bytes(),
            )
            .unwrap_or_else(|build_err| {
              // log::error!(
              //   "[TauriProtocol] Failed to build error response: {}",
              //   build_err
              // );
              HttpResponse::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error".as_bytes().to_vec().into())
                .unwrap()
            }),
        )
      }
    }
  })
}

fn get_response<R: Runtime>(
  request: Request<Vec<u8>>,
  manager: &AppManager<R>, // Manager is implemented for AppManager
  window_origin: &str,
  web_resource_request_handler: Option<&WebResourceRequestHandler>,
  // --- Conditionally accept proxy-specific args ---
  #[cfg(all(dev, mobile))] (url_base, response_cache): (
    &str,
    &Arc<Mutex<HashMap<String, CachedResponse>>>,
  ),
  original_request_uri: &str, // Keep original URI for logging/MIME guess
) -> Result<HttpResponse<Cow<'static, [u8]>>, Box<dyn std::error::Error>> {
  // log::trace!("[TauriProtocol::get_response] Start processing.");

  // Store original requested path for potential MIME guessing later
  let original_req_path = request.uri().path().to_string();

  let mut response_builder = HttpResponse::builder()
    .add_configured_headers(manager.config.app.security.headers.as_ref())
    .header("Access-Control-Allow-Origin", window_origin);

  // --- Main logic split based on platform/dev status ---

  // --- Mobile Development Proxy Path (Using ureq with DANGEROUS bypass) ---
  #[cfg(all(dev, mobile))]
  let response = {
    // log::debug!(
    //   "[TauriProtocol::get_response] Entering mobile dev proxy path (ureq - DANGEROUS BYPASS)..."
    // );
    let path_to_proxy = request
      .uri()
      .path_and_query()
      .map(|pq| pq.as_str().trim_start_matches('/'))
      .unwrap_or("");
    if path_to_proxy.is_empty() && request.uri().path() == "/" {
      // log::debug!(
      //   "[TauriProtocol::get_response] Request is for root '/'. Using empty path for proxy."
      // );
    } else if path_to_proxy.is_empty() {
      // log::warn!("[TauriProtocol::get_response] Could not extract path from mobile dev URI: {}. Using empty path.", request.uri());
    }
    // log::trace!(
    //   "[TauriProtocol::get_response] Path to proxy: {}",
    //   path_to_proxy
    // );
    let decoded_path = path_to_proxy; // Assuming no double decoding needed here
    let full_request_url = format!("{}/{}", url_base.trim_end_matches('/'), decoded_path);
    // log::info!(
    //   "[TauriProtocol::get_response] Attempting proxy (ureq - DANGEROUS BYPASS) to: {}",
    //   full_request_url
    // );

    // --- Build ureq Agent with DANGEROUS TLS Config ---
    // log::warn!("[TauriProtocol::get_response] Building ureq agent with DANGEROUS certificate verification bypass!");

    // Create a TLS config builder, configuring it to bypass verification
    let dangerous_tls_config = Arc::new(
      ClientConfig::builder() // Use ClientConfig from ureq::rustls import
        // Skip root cert loading logic
        .dangerous() // Enable dangerous options
        .with_custom_certificate_verifier(Arc::new(NoServerVerification)) // Use the bypass verifier
        .with_no_client_auth(),
    );

    // Build agent with the dangerous config
    let agent = AgentBuilder::new()
      .tls_config(dangerous_tls_config) // Pass the dangerous config
      .timeout_connect(Duration::from_secs(15)) // Set reasonable timeouts
      .timeout_read(Duration::from_secs(60))
      .timeout_write(Duration::from_secs(15))
      .build();

    // log::trace!("[TauriProtocol::get_response] DANGEROUS ureq agent created.");
    // --- End DANGEROUS Agent Build ---

    // Build and send request using ureq (synchronous)
    let method = request.method().as_str();
    // log::trace!(
    //   "[TauriProtocol::get_response] Building ureq request: {} {}",
    //   method,
    //   full_request_url
    // );
    let mut ureq_request = agent.request(method, &full_request_url);

    // Copy headers from incoming request to outgoing proxy request
    // log::trace!("[TauriProtocol::get_response] Copying headers to ureq request:");
    for (name, value) in request.headers() {
      if name != http::header::HOST && name != http::header::CONTENT_LENGTH {
        if let Ok(value_str) = value.to_str() {
          // log::trace!(
          //   "[TauriProtocol::get_response]   - Header: {} = {}",
          //   name.as_str(),
          //   value_str
          // );
          ureq_request = ureq_request.set(name.as_str(), value_str);
        } else {
          // log::warn!(
          //   "[TauriProtocol::get_response]   - Skipping non-string header: {}",
          //   name
          // );
        }
      } else {
        // log::trace!(
        //   "[TauriProtocol::get_response]   - Skipping Header: {}",
        //   name
        // );
      }
    }

    // Store request body before consuming request object for sending
    let request_body_vec = request.body().clone(); // Clone body to send

    // log::info!(
    //   "[TauriProtocol::get_response] Sending proxy request (ureq - DANGEROUS) to: {}",
    //   full_request_url
    // );
    // Send request (blocking)
    let result = if !request_body_vec.is_empty() {
      // log::trace!(
      //   "[TauriProtocol::get_response] Sending ureq request with body ({} bytes).",
      //   request_body_vec.len()
      // );
      ureq_request.send_bytes(&request_body_vec) // Send with body using reference
    } else {
      // log::trace!("[TauriProtocol::get_response] Sending ureq request without body.");
      ureq_request.call()
    };

    match result {
      // Match on the result of call() or send_bytes()
      Ok(proxy_response) => {
        // --- Process ureq Response ---
        let status_code = proxy_response.status();
        // Convert u16 status code to http::StatusCode
        let status = StatusCode::from_u16(status_code).map_err(|e| {
          format!(
            "Invalid status code from ureq response: {}: {}",
            status_code, e
          )
        })?;
        // log::info!(
        //   "[TauriProtocol::get_response] Received ureq proxy response status (DANGEROUS): {}",
        //   status
        // );

        let mut response_cache_ = response_cache.lock().unwrap();
        let mut cached_response_entry = None;

        if status == StatusCode::NOT_MODIFIED {
          // log::debug!(
          //   "[TauriProtocol::get_response] Status 304. Checking cache for {}",
          //   full_request_url
          // );
          cached_response_entry = response_cache_.get(&full_request_url).cloned(); // Clone cached entry if found
          if cached_response_entry.is_none() {
            // log::warn!(
            //   "[TauriProtocol::get_response] Received 304 but no cache entry for {}",
            //   full_request_url
            // );
          }
        }

        // Determine final response data (either from cache or fetch fresh)
        let final_response_data = if let Some(cached_entry) = cached_response_entry {
          // log::debug!(
          //   "[TauriProtocol::get_response] Using cached response for {}",
          //   full_request_url
          // );
          cached_entry
        } else {
          // log::debug!(
          //   "[TauriProtocol::get_response] Processing fresh ureq response body for {}",
          //   full_request_url
          // );
          // Extract headers into http::HeaderMap
          let mut headers = http::HeaderMap::new();
          for name_str in proxy_response.headers_names() {
            if let Some(value_str) = proxy_response.header(&name_str) {
              // Use HeaderName::from_bytes for robustness
              match HeaderName::from_bytes(name_str.as_bytes()) {
                Ok(hn) => {
                  // Use HeaderValue::from_str (usually safe for values)
                  match HeaderValue::from_str(value_str) {
                    Ok(hv) => {
                      headers.append(hn, hv);
                    } // Append header
                    // Err(e) => log::warn!(
                    //   "[TauriProtocol] Invalid header value for '{}': {}",
                    //   name_str,
                    //   e
                    // ),
                  }
                }
                // Err(e) => log::warn!("[TauriProtocol] Invalid header name '{}': {}", name_str, e),
              }
            }
          }
          // log::trace!("[TauriProtocol::get_response] Extracted headers from ureq response.");

          // Read body into Vec<u8> then Bytes
          let mut body_reader = proxy_response.into_reader();
          let mut body_vec = Vec::new();
          body_reader.read_to_end(&mut body_vec)?; // Propagate IO errors
          let body_bytes = Bytes::from(body_vec);
          // log::debug!(
          //   "[TauriProtocol::get_response] Read {} bytes from ureq response body.",
          //   body_bytes.len()
          // );

          // Create data structure to cache
          let response_to_cache = CachedResponse {
            status,
            headers,
            body: body_bytes,
          };
          // Cache successful responses
          if status.is_success() || status == StatusCode::NOT_MODIFIED {
            // log::debug!(
            //   "[TauriProtocol::get_response] Caching ureq response (Status: {}) for {}",
            //   status,
            //   full_request_url
            // );
            response_cache_.insert(full_request_url.clone(), response_to_cache.clone());
          } else {
            // log::warn!("[TauriProtocol::get_response] Not caching unsuccessful ureq response (Status: {}) for {}", status, full_request_url);
          }
          response_to_cache // Use the newly fetched data
        };

        // Build response for webview, adding MIME guess if needed
        let mut final_headers = final_response_data.headers.clone(); // Clone headers to potentially modify

        // log::trace!("[TauriProtocol::get_response] Building response for webview (from ureq)...");

        // --- Check and Set Content-Type if missing ---
        if !final_headers.contains_key(http::header::CONTENT_TYPE) {
          // log::warn!("[TauriProtocol::get_response] Upstream response missing Content-Type for '{}'. Guessing based on original request path: '{}'", full_request_url, original_req_path);
          // Use mime_guess crate
          let guess = mime_guess::from_path(&original_req_path).first_or_octet_stream();
          match HeaderValue::from_str(guess.as_ref()) {
            Ok(content_type_val) => {
              // log::info!(
              //   "[TauriProtocol::get_response] Setting guessed Content-Type: {}",
              //   guess.as_ref()
              // );
              final_headers.insert(http::header::CONTENT_TYPE, content_type_val);
            }
            Err(e) => {
              // log::error!("[TauriProtocol::get_response] Failed to create HeaderValue for guessed MIME '{}': {}", guess.as_ref(), e);
            }
          }
        }
        // --- End Content-Type Check ---

        // Add final headers to the builder
        for (name, value) in final_headers.iter() {
          // Iterate modified headers
          // Filter headers that shouldn't be passed back directly
          if name != http::header::CONTENT_ENCODING
            && name != http::header::TRANSFER_ENCODING
            && name != http::header::CONNECTION
          {
            // log::trace!(
            //   "[TauriProtocol::get_response]   - Response Header: {} = {:?}",
            //   name,
            //   value
            // );
            response_builder = response_builder.header(name.clone(), value.clone());
          } else {
            // log::trace!(
            //   "[TauriProtocol::get_response]   - Skipping Response Header: {}",
            //   name
            // );
          }
        }
        // Build the final response body
        response_builder
          .status(final_response_data.status)
          .body(final_response_data.body.to_vec().into())? // Convert Bytes -> Vec -> Cow
      } // End Ok case
      Err(ureq_error) => {
        // log::error!(
        //   "[TauriProtocol::get_response] Failed DANGEROUS ureq proxy request to {}: {:?}",
        //   full_request_url.as_str(),
        //   ureq_error
        // );
        // Log the error source chain
        if let ureq::Error::Transport(transport_error) = &ureq_error {
          // log::error!(
          //   "[TauriProtocol::get_response] DANGEROUS ureq Transport Error details: {}",
          //   transport_error
          // );
          let mut opt_source = transport_error.source();
          while let Some(source) = opt_source {
            // log::error!(
            //   "[TauriProtocol::get_response] DANGEROUS Transport source: {:?}",
            //   source
            // );
            opt_source = source.source();
          }
        }
        // Propagate the error to the outer handler
        return Err(Box::new(ureq_error));
      } // End Err case
    } // End Match
  }; // End of #[cfg(all(dev, mobile))] block

  // --- Fallback / Production / Desktop Dev path ---
  #[cfg(not(all(dev, mobile)))]
  let response = {
    // log::debug!("[TauriProtocol::get_response] Entering non-mobile-dev asset loading path...");
    let use_https_scheme = request.uri().scheme() == Some(&http::uri::Scheme::HTTPS);

    // Calculate asset path from the request URI path
    let asset_path = request
      .uri()
      .path_and_query()
      .map(|pq| pq.as_str().trim_start_matches('/'))
      .unwrap_or("") // Default to empty if no path (should load index)
      .to_string();

    // log::debug!(
    //   "[TauriProtocol::get_response] Attempting to load asset: {}",
    //   asset_path
    // );

    let asset = match manager.get_asset(asset_path.clone(), use_https_scheme) {
      Ok(a) => a,
      Err(e) => {
        // log::error!(
        //   "[TauriProtocol::get_response] Failed to get asset '{}': {:?}",
        //   asset_path,
        //   e
        // );
        // Return a 404 Not Found response for asset errors
        return Ok(
          HttpResponse::builder()
            .status(StatusCode::NOT_FOUND)
            .header(CONTENT_TYPE, mime::TEXT_PLAIN.essence_str())
            .header("Access-Control-Allow-Origin", window_origin)
            .body(
              format!("Asset not found: /{}", asset_path)
                .into_bytes()
                .into(),
            )?,
        );
      }
    };

    // log::debug!(
    //   "[TauriProtocol::get_response] Asset loaded (MIME: {})",
    //   asset.mime_type
    // );
    // Set Content-Type from asset FIRST
    response_builder = response_builder.header(CONTENT_TYPE, &asset.mime_type);
    if let Some(csp) = &asset.csp_header {
      // log::trace!("[TauriProtocol::get_response] Adding CSP header from asset.");
      response_builder = response_builder.header("Content-Security-Policy", csp);
    }
    // Add other configured headers AFTER setting essential ones like Content-Type
    response_builder =
      response_builder.add_configured_headers(manager.config.app.security.headers.as_ref());
    response_builder.body(asset.bytes.into())?
  };

  // Apply web resource request handler if present
  let mut final_response = response; // Assign the result from the correct cfg block
  if let Some(handler) = &web_resource_request_handler {
    // log::debug!("[TauriProtocol::get_response] Applying WebResourceRequestHandler...");
    // Pass the original request (ownership might move here depending on handler signature)
    // and the mutable final response
    handler(request, &mut final_response);
  }

  // log::trace!("[TauriProtocol::get_response] Final response ready.");
  Ok(final_response) // Return the potentially modified final response
}
