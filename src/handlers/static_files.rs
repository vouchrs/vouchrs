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
    <style>{styles}</style>
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
                <p>Protected by <a href="https://github.com/vouchrs/vouchrs" target="_blank">Vouchrs</a> <span class="version">v{version}</span></p>
            </div>
        </div>
    </div>
</body>
</html>"#,
        styles = get_sign_in_styles(),
        brand_name = brand_name,
        provider_buttons = provider_buttons,
        version = crate::VERSION
    )
}

fn generate_provider_buttons(settings: &VouchrsSettings) -> String {
    // Define 5 vibrant colors to cycle through
    let colors = [
        "#4285f4", // Blue
        "#ea4335", // Red
        "#34a853", // Green
        "#000000", // Black
        "#8e44ad", // Purple
    ];
    
    settings
        .get_enabled_providers()
        .iter()
        .enumerate() // Add index for color rotation
        .map(|(index, provider)| {
            let display_name = provider.display_name.as_ref()
                .unwrap_or(&provider.name)
                .clone();
            
            // Generate both standard provider class and our color class
            let provider_class = format!("provider-{}", provider.name.to_lowercase());
            
            // Use index % 5 to rotate through our colors
            let color_index = index % colors.len();
            let color = colors[color_index];
            
            // Create a dynamic style attribute with the color
            format!(
                r#"<a href="/oauth2/sign_in?provider={}" class="provider-button {}" style="background-color: {}">
                    <span>Continue with {}</span>
                </a>"#,
                provider.name, provider_class, color, display_name
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
            color: white; /* Text color for all buttons */
        }
        
        .provider-button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            filter: brightness(90%); /* Darken on hover */
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
        
        .version {
            color: #999;
            font-size: 12px;
            margin-left: 5px;
            opacity: 0.7;
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
