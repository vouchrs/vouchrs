use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use vouchrs::{
    handlers::{
        health, jwt_oauth_callback, jwt_oauth_debug, oauth_sign_in, oauth_sign_out,
        jwt_oauth_userinfo, serve_static, proxy_upstream
    },
    oauth::OAuthConfig,
    session::SessionManager,
    settings::VouchrsSettings,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load configuration from Settings.toml and environment variables
    // This also loads .env file and initializes the logger
    let settings = VouchrsSettings::load()
        .map_err(|e| std::io::Error::other(format!("Failed to load settings: {e}")))?;

    // Initialize OAuth configuration with config-driven providers
    let mut oauth_config = OAuthConfig::new();
    oauth_config
        .initialize_from_settings(&settings)
        .await
        .map_err(|e| {
            std::io::Error::other(format!("Failed to initialize OAuth providers: {e}"))
        })?;

    println!("✓ Using JWT-based stateless sessions with encrypted cookies");
    start_server_with_jwt(oauth_config, settings).await
}

/// Start the server with JWT-based stateless sessions
/// 
/// # Errors
/// 
/// Returns an error if:
/// - Server binding fails
/// - Server fails to start
async fn start_server_with_jwt(
    oauth_config: OAuthConfig,
    settings: VouchrsSettings,
) -> std::io::Result<()> {
    let bind_address = settings.get_bind_address();
    print_startup_info(&bind_address, "JWT (Stateless)", &settings);

    // Initialize session manager with encryption key from settings
    let session_manager = SessionManager::new(
        settings.jwt.session_secret.as_bytes(),
        settings.cookies.secure,
    );

    // Configure CORS for SPAs
    let cors_origins = settings.get_cors_origins();

    HttpServer::new(move || {
        let cors_origins = cors_origins.clone();
        let cors = Cors::default()
            .allowed_origin_fn(move |origin, _| {
                cors_origins
                    .iter()
                    .any(|allowed| allowed == origin.to_str().unwrap_or(""))
            })
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec!["Authorization", "Content-Type", "Accept"])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(oauth_config.clone()))
            .app_data(web::Data::new(settings.clone()))
            .app_data(web::Data::new(session_manager.clone()))
            .wrap(cors)
            .wrap(Logger::default())
            .configure(configure_services)
    })
    .bind(&bind_address)?
    .run()
    .await
}

fn configure_services(cfg: &mut web::ServiceConfig) {
    cfg
        // OAuth2 endpoints - using JWT handlers for stateless operation
        .route("/oauth2/sign_in", web::get().to(oauth_sign_in))
        .route("/oauth2/sign_out", web::get().to(oauth_sign_out))
        .route("/oauth2/sign_out", web::post().to(oauth_sign_out))
        .route("/oauth2/callback", web::get().to(jwt_oauth_callback))
        .route("/oauth2/callback", web::post().to(jwt_oauth_callback))
        .route("/oauth2/debug", web::get().to(jwt_oauth_debug))
        .route("/oauth2/userinfo", web::get().to(jwt_oauth_userinfo))
        // Static files endpoint
        .route("/oauth2/static/{filename:.*}", web::get().to(serve_static))
        // Health endpoint
        .route("/ping", web::get().to(health))
        // Catch-all proxy for any other path - provider determined from session
        .default_service(
            web::route()
                .guard(actix_web::guard::fn_guard(|req| {
                    let path = req.head().uri.path();
                    !path.starts_with("/oauth2") && !path.starts_with("/ping")
                }))
                .to(proxy_upstream),
        );
}

fn print_startup_info(bind_address: &str, session_backend: &str, settings: &VouchrsSettings) {
    println!(
        "Starting Vouchrs OIDC Reverse Proxy on http://{bind_address}"
    );
    println!("Session Backend: {session_backend}");
    println!();
    println!("OAuth2 endpoints:");
    println!("  GET  /oauth2/sign_in  - Login/logout page");
    println!("  GET|POST /oauth2/sign_out - Clear session");
    println!("  GET|POST /oauth2/callback - OAuth callback (POST for Apple form_post)");
    println!();
    println!("OAuth callback URL for identity providers:");
    println!(
        "  {}/oauth2/callback",
        settings.application.redirect_base_url
    );
    println!();
    if session_backend == "JWT (Stateless)" {
        println!("Sidecar Proxy endpoints (with automatic OAuth token injection):");
        println!("  ALL {{any path}}                   - Proxy to upstream service as-is");
        println!("                                    (except /oauth2/* and /health)");
        println!(
            "                                    Upstream URL: {}",
            settings.proxy.upstream_url
        );
        println!();
    }
    println!("System endpoints:");
    println!("  GET  /ping            - Health check");
    println!("  GET  /oauth2/static/* - Static files (HTML, CSS, JS, images)");
    println!(
        "  Static files folder: {}",
        settings.static_files.assets_folder
    );
}
