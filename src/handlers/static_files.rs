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

    fs::read(&file_path).map_or_else(|_| {
        debug!("Static file not found: {file_path}");
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "not_found",
            "message": "File not found"
        })))
    }, |contents| {
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
    })
}

// Helper function to get sign-in page HTML (reused from original handlers)
#[must_use]
pub fn get_sign_in_page(settings: &VouchrsSettings) -> String {
    let html_path = format!("{}/sign-in.html", settings.static_files.assets_folder);
    std::fs::read_to_string(&html_path).unwrap_or_else(|_| generate_dynamic_sign_in_page(settings))
}

// Generate dynamic sign-in page with providers from configuration
#[must_use]
pub fn generate_dynamic_sign_in_page(settings: &VouchrsSettings) -> String {
    let provider_buttons = generate_provider_buttons(settings);
    let brand_name = settings.application.redirect_base_url.clone();
    
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In - {brand_name}</title>
    <style>{}</style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <h1>Sign In</h1>
            <p>Choose your authentication provider</p>
            <div class="button-container">
                {provider_buttons}
            </div>
            <div class="footer">
                <p>Protected by <a href="https://github.com/vouchrs/vouchrs" target="_blank">Vouchrs</a></p>
            </div>
        </div>
    </div>
</body>
</html>"#,
        get_sign_in_styles(),
        brand_name = brand_name,
        provider_buttons = provider_buttons
    )
}

fn generate_provider_buttons(settings: &VouchrsSettings) -> String {
    settings
        .get_enabled_providers()
        .iter()
        .map(|provider| {
            let display_name = provider.display_name.as_ref()
                .unwrap_or(&provider.name)
                .clone();
            let provider_class = format!("provider-{}", provider.name.to_lowercase());
            format!(
                r#"<a href="/oauth2/sign_in?provider={}" class="provider-button {}">
                    <span>Continue with {}</span>
                </a>"#,
                provider.name, provider_class, display_name
            )
        })
        .collect::<Vec<_>>()
        .join("\n                ")
}

#[allow(clippy::too_many_lines)]
const fn get_sign_in_styles() -> &'static str {
    r"
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            width: 100%;
            max-width: 400px;
        }
        
        .login-box {
            background: white;
            border-radius: 10px;
            box-shadow: 0 14px 28px rgba(0,0,0,0.12), 0 10px 10px rgba(0,0,0,0.08);
            padding: 40px;
        }
        
        h1 {
            color: #333;
            font-size: 28px;
            font-weight: 600;
            text-align: center;
            margin-bottom: 10px;
        }
        
        p {
            color: #666;
            text-align: center;
            margin-bottom: 30px;
        }
        
        .button-container {
            display: flex;
            flex-direction: column;
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .provider-button {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 12px 20px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 500;
            font-size: 16px;
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }
        
        .provider-button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        /* Provider-specific colors */
        .provider-google {
            background: #4285f4;
            color: white;
        }
        
        .provider-google:hover {
            background: #3367d6;
        }
        
        .provider-github {
            background: #24292e;
            color: white;
        }
        
        .provider-github:hover {
            background: #1a1e22;
        }
        
        .provider-microsoft {
            background: #0078d4;
            color: white;
        }
        
        .provider-microsoft:hover {
            background: #0063b1;
        }
        
        .provider-apple {
            background: #000;
            color: white;
        }
        
        .provider-apple:hover {
            background: #333;
        }
        
        /* Generic provider style */
        .provider-button:not(.provider-google):not(.provider-github):not(.provider-microsoft):not(.provider-apple) {
            background: #6366f1;
            color: white;
        }
        
        .provider-button:not(.provider-google):not(.provider-github):not(.provider-microsoft):not(.provider-apple):hover {
            background: #5558e3;
        }
        
        .footer {
            text-align: center;
            padding-top: 20px;
            border-top: 1px solid #e9ecef;
        }
        
        .footer p {
            color: #999;
            font-size: 14px;
            margin: 0;
        }
        
        .footer a {
            color: #6366f1;
            text-decoration: none;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
        
        @media (max-width: 480px) {
            .login-box {
                padding: 30px 20px;
            }
            
            h1 {
                font-size: 24px;
            }
        }
    "
}
