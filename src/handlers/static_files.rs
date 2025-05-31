use crate::models::HealthResponse;
use crate::settings::VouchrsSettings;
use actix_web::{web, HttpResponse, Result};
use log::debug;
use std::fs;

/// Health check endpoint
/// 
/// # Errors
/// Returns an error if health status cannot be determined
pub async fn health() -> Result<HttpResponse> {
    let response = HealthResponse {
        status: "ok".to_string(),
        message: "Vouchrs OIDC Reverse Proxy is running".to_string(),
    };
    Ok(HttpResponse::Ok().json(response))
}

/// Serve static files from the configured static directory
///
/// # Errors
///
/// Returns an error if:
/// - The requested file cannot be read
/// - The file path is invalid
pub async fn serve_static(
    path: web::Path<String>,
    settings: web::Data<VouchrsSettings>,
) -> Result<HttpResponse> {
    let filename = path.into_inner();
    let file_path = format!("{}/{}", settings.static_files.assets_folder, filename);

    debug!("Attempting to serve static file: {file_path}");

    if let Ok(contents) = fs::read(&file_path) {
        let content_type = match file_path.split('.').next_back() {
            Some("html") => "text/html",
            Some("css") => "text/css",
            Some("js") => "application/javascript",
            Some("png") => "image/png",
            Some("jpg" | "jpeg") => "image/jpeg",
            Some("gif") => "image/gif",
            Some("svg") => "image/svg+xml",
            Some("ico") => "image/x-icon",
            _ => "text/plain",
        };

        Ok(HttpResponse::Ok().content_type(content_type).body(contents))
    } else {
        debug!("Static file not found: {file_path}");
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "not_found",
            "message": "File not found"
        })))
    }
}
