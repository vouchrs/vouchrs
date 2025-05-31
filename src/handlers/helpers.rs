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
    let enabled_providers = settings.get_enabled_providers();

    let provider_buttons = if enabled_providers.is_empty() {
        "<p>No OAuth providers are configured. Please check your configuration.</p>".to_string()
    } else {
        enabled_providers
            .iter()
            .map(|provider| {
                let class = format!("{}-btn", provider.name);
                format!(
                    r#"<a href="/oauth2/sign_in?provider={}" class="provider-btn {}">
            Sign in with {}
        </a>"#,
                    provider.name,
                    class,
                    provider.display_name.as_deref().unwrap_or(&provider.name)
                )
            })
            .collect::<Vec<_>>()
            .join("\n        ")
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vouchrs OIDC Reverse Proxy - Sign In</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 400px;
            width: 100%;
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
            font-size: 2.5rem;
        }}
        .subtitle {{
            color: #666;
            margin-bottom: 30px;
            font-size: 1.1rem;
        }}
        .provider-btn {{
            display: block;
            width: 100%;
            padding: 12px 20px;
            margin: 10px 0;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 500;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            box-sizing: border-box;
        }}
        .provider-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.15);
        }}
        .provider-btn:nth-child(5n+1) {{
            background: #4285f4;  /* Google blue */
            color: white;
        }}
        .provider-btn:nth-child(5n+2) {{
            background: #ea4335;  /* Red */
            color: white;
        }}
        .provider-btn:nth-child(5n+3) {{
            background: #34a853;  /* Green */
            color: white;
        }}
        .provider-btn:nth-child(5n+4) {{
            background:rgb(0, 0, 0);  /* Black */
            color: white;
        }}
        .provider-btn:nth-child(5n+5) {{
            background: #0078d4;  /* Microsoft blue */
            color: white;
        }}
        .footer {{
            margin-top: 30px;
            color: #999;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Vouchrs OIDC Reverse Proxy</h1>
        <p class="subtitle">Choose your provider to sign in</p>
        
        {provider_buttons}
        
        <div class="footer">
            <p>An OIDC proxy service</p>
        </div>
    </div>
</body>
</html>"#
    )
}

/// Helper function to decode JWT token payload without verification
/// This is used for debugging purposes only to inspect token claims
/// 
/// # Errors
/// Returns an error if the JWT format is invalid, base64 decoding fails, 
/// UTF-8 decoding fails, or JSON parsing fails
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
