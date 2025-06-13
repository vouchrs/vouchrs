use crate::models::HealthResponse;
use crate::settings::VouchrsSettings;
use actix_web::{web, HttpResponse, Result};
use std::fs;

/// Initialize static files - generate sign-in.html in the generated content folder
///
/// HTML content is always generated unless the assets path has been explicitly set.
/// This allows Docker users to mount custom static content without having it overwritten.
///
/// # Errors
/// Returns an error if file operations fail
pub fn initialize_static_files(settings: &VouchrsSettings) -> std::io::Result<()> {
    let generated_folder = &settings.static_files.generated_content_folder;

    // Create generated content folder if it doesn't exist
    fs::create_dir_all(generated_folder)?;

    // Always generate HTML content unless assets_folder was explicitly set
    // This prevents overwriting custom content in Docker volume mounts
    if settings.static_files.assets_folder_explicitly_set {
        println!("⏭️  Skipping HTML generation - assets folder explicitly set");
    } else {
        let html_path = format!("{generated_folder}/sign-in.html");
        let html_content = generate_sign_in_html(settings);
        fs::write(&html_path, html_content)?;
        println!("✅ Generated sign-in.html");
    }

    Ok(())
}

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

/// Serve static files from both the assets folder and generated content folder
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

    // Try generated content folder first (for HTML files)
    let generated_file_path = format!(
        "{}/{}",
        settings.static_files.generated_content_folder, filename
    );

    // Then try assets folder (for CSS, JS, images)
    let assets_file_path = format!("{}/{}", settings.static_files.assets_folder, filename);

    // If assets folder was explicitly set, prefer it over generated content folder
    let file_path = if settings.static_files.assets_folder_explicitly_set
        && std::path::Path::new(&assets_file_path).exists()
    {
        println!("✅ Using custom static file from {assets_file_path}");
        assets_file_path
    } else if std::path::Path::new(&generated_file_path).exists() {
        generated_file_path
    } else if std::path::Path::new(&assets_file_path).exists() {
        assets_file_path
    } else {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "not_found",
            "message": "File not found"
        })));
    };

    match fs::read(&file_path) {
        Ok(contents) => {
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
        }
        Err(_) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "read_error",
            "message": "Failed to read file"
        }))),
    }
}

/// Get sign-in page HTML - checks custom assets folder first, then generated content folder
///
/// # Panics
/// Panics if the sign-in HTML file is not found in either location
#[must_use]
pub fn get_sign_in_page(settings: &VouchrsSettings) -> String {
    // If assets folder was explicitly set, check for custom sign-in.html first
    if settings.static_files.assets_folder_explicitly_set {
        let custom_html_path = format!("{}/sign-in.html", settings.static_files.assets_folder);
        if let Ok(custom_html) = std::fs::read_to_string(&custom_html_path) {
            println!("✅ Using custom sign-in.html from {custom_html_path}");
            return custom_html;
        }
    }

    // Fallback to generated content folder
    let html_path = format!(
        "{}/sign-in.html",
        settings.static_files.generated_content_folder
    );
    std::fs::read_to_string(&html_path).unwrap_or_else(|_| {
        // This should not happen if initialization was successful
        panic!("Sign-in HTML file not found at {html_path}. Call initialize_static_files() first.")
    })
}

/// Generate sign-in HTML from template
fn generate_sign_in_html(settings: &VouchrsSettings) -> String {
    let provider_buttons = generate_provider_buttons(settings);
    let brand_name = settings.application.redirect_base_url.clone();

    // Conditionally include passkey JavaScript
    let passkey_script = if settings.passkeys.enabled {
        r#"<script src="/auth/static/passkey-signin.js"></script>"#
    } else {
        ""
    };

    // Use embedded template
    let template = get_html_template();

    template
        .replace("{{brand_name}}", &brand_name)
        .replace("{{provider_buttons}}", &provider_buttons)
        .replace("{{passkey_script}}", passkey_script)
        .replace("{{version}}", crate::VERSION)
}

fn generate_provider_buttons(settings: &VouchrsSettings) -> String {
    let mut buttons = Vec::new();

    // Generate OAuth provider buttons
    for provider in settings.get_enabled_providers() {
        let display_name = provider
            .display_name
            .as_ref()
            .unwrap_or(&provider.name)
            .clone();

        // Generate provider class
        let provider_class = format!("provider-{}", provider.name.to_lowercase());

        // Get provider icon
        let provider_icon = get_provider_icon(&provider.name.to_lowercase());

        // Create button with icon
        buttons.push(format!(
            r#"<a href="/auth/sign_in?provider={}" class="provider-button {}">
                    {}
                    <span>Continue with {}</span>
                </a>"#,
            provider.name, provider_class, provider_icon, display_name
        ));
    }

    // Add passkey button if passkeys are enabled
    if settings.passkeys.enabled {
        buttons.push(
            r#"<button id="passkey-signin" class="provider-button provider-passkey">
                    <span class="provider-icon passkey-icon">🔑</span>
                    <span>Continue with Passkey</span>
                </button>"#
                .to_string(),
        );
    }

    buttons.join("\n                ")
}

/// HTML template for sign-in page
const fn get_html_template() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In - {{brand_name}}</title>
    <link rel="stylesheet" href="/auth/static/sign-in.css">
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo-container">
                <img src="/auth/static/vouchrs-logo.svg" alt="Vouchrs" class="logo">
            </div>
            <h1>Sign In</h1>
            <p>Choose your authentication provider</p>
            <div class="button-container">
                {{provider_buttons}}
            </div>
            <div id="redirect-indicator" class="redirect-indicator" style="display: none;"></div>
            <div class="footer">
                <p>Protected by <a href="https://github.com/vouchrs/vouchrs" target="_blank">Vouchrs</a> <span class="version">v{{version}}</span></p>
            </div>
        </div>
    </div>
    {{passkey_script}}
</body>
</html>"#
}

/// Get SVG icon for a specific OAuth provider
fn get_provider_icon(provider_name: &str) -> &'static str {
    match provider_name {
        "google" => "<svg class=\"provider-icon\" version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 48 48\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" style=\"display: block;\">
                        <path fill=\"#EA4335\" d=\"M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z\"></path>
                        <path fill=\"#4285F4\" d=\"M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z\"></path>
                        <path fill=\"#FBBC05\" d=\"M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z\"></path>
                        <path fill=\"#34A853\" d=\"M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z\"></path>
                        <path fill=\"none\" d=\"M0 0h48v48H0z\"></path>
                    </svg>",
        "apple" => "<svg class=\"provider-icon\" xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\" fill=\"white\">
                        <path d=\"M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09l.01-.01zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z\"/>
                    </svg>",
        // Default generic icon for all other providers
        _ => "<svg class=\"provider-icon\" xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"white\">
                        <path d=\"M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z\"/>
                    </svg>",
    }
}
