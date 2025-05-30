// Integration test for JWT settings and user cookie functionality
use vouchrs::utils::test_helpers::{create_test_session, create_test_settings};
use vouchrs::jwt_session::{JwtSessionManager};
use vouchrs::utils::user_agent::UserAgentInfo;
use vouchrs::models::VouchrsUserData;

/// Helper function to create test user data with optional context
fn create_test_user_data(
    email: &str,
    name: Option<String>,
    provider: &str,
    provider_id: &str,
    client_ip: Option<&str>,
    user_agent_info: Option<&UserAgentInfo>
) -> VouchrsUserData {
    VouchrsUserData {
        email: email.to_string(),
        name,
        provider: provider.to_string(),
        provider_id: provider_id.to_string(),
        client_ip: client_ip.map(|ip| ip.to_string()),
        user_agent: user_agent_info.and_then(|ua| ua.user_agent.clone()),
        platform: user_agent_info.and_then(|ua| ua.platform.clone()),
        lang: user_agent_info.and_then(|ua| ua.lang.clone()),
        mobile: user_agent_info.map(|ua| ua.mobile as i32).unwrap_or(0),
        session_start: Some(chrono::Utc::now().timestamp()), // Adding session_start as Unix timestamp for test
    }
}


#[test]
fn test_user_cookie_contains_required_fields() {
    // Create a session with proper provider_id set
    let session = create_test_session();
    
    let settings = create_test_settings();
    
    // Create user agent info with platform
    let user_agent_info = UserAgentInfo {
        user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string()),
        platform: Some("macOS".to_string()),
        lang: Some("en-US".to_string()),
        mobile: 0,
    };
    
    // Create user data manually since we now have separate token and user data
    let user_data = create_test_user_data(
        "test@example.com",
        Some("Test User".to_string()),
        &session.provider,
        "123456789",
        Some("192.168.1.1"),
        Some(&user_agent_info)
    );
    
    // Verify user data contains all required fields
    assert_eq!(user_data.provider, session.provider, "Provider should match session");
    assert_eq!(user_data.client_ip, Some("192.168.1.1".to_string()), "Client IP should be set");
    assert_eq!(user_data.platform, Some("macOS".to_string()), "Platform should be extracted from user agent");
    assert_eq!(user_data.lang, Some("en-US".to_string()), "Language should be set");
    assert_eq!(user_data.mobile, 0, "Mobile flag should be set");
    
    // Test user cookie encryption/decryption
    let jwt_manager = JwtSessionManager::new(settings.jwt.session_secret.as_bytes(), false);
    let user_cookie = jwt_manager.create_user_cookie(&user_data)
        .expect("Should create user cookie");
    
    // Verify cookie has correct properties
    assert_eq!(user_cookie.name(), "vouchrs_user");
    assert_eq!(user_cookie.http_only(), Some(true), "User cookie should be HTTP-only");
    assert_eq!(user_cookie.path(), Some("/"));
    
    // Test that we can decrypt the user data back using a mock request
    use actix_web::test::TestRequest;
    let test_req = TestRequest::default()
        .cookie(user_cookie.clone())
        .to_http_request();
    
    let decrypted_data = jwt_manager.get_user_data_from_request(&test_req)
        .expect("Should get user data from request")
        .expect("Should have user data");
    
    assert_eq!(decrypted_data.email, user_data.email);
    assert_eq!(decrypted_data.provider, user_data.provider);
    assert_eq!(decrypted_data.platform, user_data.platform);
    
    println!("✅ All user cookie functionality verified successfully");
}

#[test]
fn test_minimal_user_data() {
    // Test creating user data with minimal information
    let session = create_test_session();
    
    let settings = create_test_settings();
    
    // Create user data without user agent info or client IP
    let user_data = create_test_user_data(
        "test@example.com",
        Some("Test User".to_string()),
        &session.provider,
        "123456789",
        None,
        None
    );
    
    // Verify required fields are present
    assert_eq!(user_data.provider, session.provider);
    assert_eq!(user_data.client_ip, None, "Client IP should be None when not provided");
    assert_eq!(user_data.platform, None, "Platform should be None when not provided");
    assert_eq!(user_data.mobile, 0, "Mobile should default to 0");
    
    // Test encryption/decryption with minimal data
    let jwt_manager = JwtSessionManager::new(settings.jwt.session_secret.as_bytes(), false);
    let user_cookie = jwt_manager.create_user_cookie(&user_data)
        .expect("Should create user cookie");
    
    // Test that we can decrypt the user data back using a mock request
    use actix_web::test::TestRequest;
    let test_req = TestRequest::default()
        .cookie(user_cookie.clone())
        .to_http_request();
    
    let decrypted_data = jwt_manager.get_user_data_from_request(&test_req)
        .expect("Should get user data from request")
        .expect("Should have user data");
    
    assert_eq!(decrypted_data.email, user_data.email);
    assert_eq!(decrypted_data.client_ip, None);
    
    println!("✅ Minimal user data test passed");
}
