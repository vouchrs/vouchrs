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
    let generated_file_path = format!("{}/{}", settings.static_files.generated_content_folder, filename);

    // Then try assets folder (for CSS, JS, images)
    let assets_file_path = format!("{}/{}", settings.static_files.assets_folder, filename);

    // Try generated content folder first
    let file_path = if std::path::Path::new(&generated_file_path).exists() {
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
        Err(_) => {
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "read_error",
                "message": "Failed to read file"
            })))
        }
    }
}

/// Get sign-in page HTML - reads from generated content folder
///
/// # Panics
/// Panics if the sign-in HTML file is not found. Call `initialize_static_files()` first.
#[must_use]
pub fn get_sign_in_page(settings: &VouchrsSettings) -> String {
    let html_path = format!("{}/sign-in.html", settings.static_files.generated_content_folder);
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
        r#"<script src="/oauth2/static/passkey-signin.js"></script>"#
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
        let display_name = provider.display_name.as_ref()
            .unwrap_or(&provider.name)
            .clone();

        // Generate provider class
        let provider_class = format!("provider-{}", provider.name.to_lowercase());

        // Create button without inline style - CSS handles the colors
        buttons.push(format!(
            r#"<a href="/oauth2/sign_in?provider={}" class="provider-button {}">
                    <span>Continue with {}</span>
                </a>"#,
            provider.name, provider_class, display_name
        ));
    }

    // Add passkey button if passkeys are enabled
    if settings.passkeys.enabled {
        buttons.push(
            r#"<button id="passkey-signin" class="provider-button provider-passkey">
                    <span>🔑 Continue with Passkey</span>
                </button>"#.to_string()
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
    <link rel="stylesheet" href="/oauth2/static/sign-in.css">
</head>
<body>
    <div class="container">
        <div class="login-box">
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
