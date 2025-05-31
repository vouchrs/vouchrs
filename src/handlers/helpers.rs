// Helper functions used across JWT handlers
use crate::settings::VouchrsSettings;
use base64::{engine::general_purpose, Engine as _};

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

fn get_sign_in_styles() -> &'static str {
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

/// Helper function to decode JWT token payload without verification
/// This is used for debugging purposes only to inspect token claims
/// 
/// # Errors
/// 
/// Returns an error if:
/// - The JWT format is invalid (not 3 parts separated by dots)
/// - Base64 decoding fails
/// - UTF-8 decoding fails
/// - JSON parsing fails
pub fn decode_jwt_payload(token: &str) -> Result<serde_json::Value, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    let payload_b64 = parts[1];
    let payload_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .or_else(|_| general_purpose::STANDARD.decode(payload_b64))
        .map_err(|_| "Base64 decode failed")?;

    let payload_str = String::from_utf8(payload_bytes).map_err(|_| "UTF-8 decode failed")?;

    serde_json::from_str(&payload_str).map_err(|_| "JSON parse failed".to_string())
}
