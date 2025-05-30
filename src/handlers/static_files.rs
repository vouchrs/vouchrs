use crate::models::HealthResponse;
use crate::settings::VouchrsSettings;
use actix_web::{web, HttpResponse, Result};
use log::debug;
use std::fs;

pub async fn health() -> Result<HttpResponse> {
    let response = HealthResponse {
        status: "ok".to_string(),
        message: "Vouchrs OIDC Reverse Proxy is running".to_string(),
    };
    Ok(HttpResponse::Ok().json(response))
}

pub async fn serve_static(
    path: web::Path<String>,
    settings: web::Data<VouchrsSettings>,
) -> Result<HttpResponse> {
    let filename = path.into_inner();
    let file_path = format!("{}/{}", settings.static_files.assets_folder, filename);

    debug!("Attempting to serve static file: {}", file_path);

    match fs::read(&file_path) {
        Ok(contents) => {
            let content_type = match file_path.split('.').next_back() {
                Some("html") => "text/html",
                Some("css") => "text/css",
                Some("js") => "application/javascript",
                Some("png") => "image/png",
                Some("jpg") | Some("jpeg") => "image/jpeg",
                Some("gif") => "image/gif",
                Some("svg") => "image/svg+xml",
                Some("ico") => "image/x-icon",
                _ => "text/plain",
            };

            Ok(HttpResponse::Ok().content_type(content_type).body(contents))
        }
        Err(_) => {
            debug!("Static file not found: {}", file_path);
            Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "not_found",
                "message": "File not found"
            })))
        }
    }
}
