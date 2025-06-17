use actix_web::test;
use chrono::Utc;
use vouchrs::{models::VouchrsUserData, session::SessionManager};

/// Test persistent user data across authentication sessions
#[actix_web::test]
async fn test_persistent_user_data_preservation() {
    // Create test session manager with basic settings
    let test_key = b"test-encryption-key-32-bytes-min";
    let session_manager = SessionManager::new(
        test_key, false, // cookie_secure
        false, // bind_session_to_ip
        24,    // session_duration_hours
        24,    // session_expiration_hours
        0,     // session_refresh_hours
    );

    // Create initial user data with email and name populated
    let initial_user_data = VouchrsUserData::new(
        "user@example.com".to_string(),
        Some("John Doe".to_string()),
        "google".to_string(),
        "12345".to_string(),
        Some("192.168.1.1".to_string()),
        Some("Mozilla/5.0".to_string()),
        Some("macOS".to_string()),
        Some("en-US".to_string()),
        0,
        Some(Utc::now().timestamp()),
    );

    // Create an initial user cookie
    let initial_cookie = session_manager
        .cookie_factory()
        .create_user_cookie(&initial_user_data)
        .expect("Should create initial user cookie");

    // Create a test request with the existing cookie
    let req = test::TestRequest::get()
        .uri("/")
        .cookie(initial_cookie)
        .to_http_request();

    // Create new user data with empty email and no name (simulating usernameless auth)
    let new_user_data = VouchrsUserData::new(
        String::new(), // Empty email
        None,          // No name
        "google".to_string(),
        "12345".to_string(), // Same provider_id
        Some("192.168.1.1".to_string()),
        Some("Mozilla/5.0".to_string()),
        Some("macOS".to_string()),
        Some("en-US".to_string()),
        0,
        Some(Utc::now().timestamp()),
    );

    // Create user cookie with persistence - should preserve existing email and name
    let persistent_cookie = session_manager
        .cookie_factory()
        .create_user_cookie_with_persistence(&req, &new_user_data)
        .expect("Should create persistent user cookie");

    // Decrypt the persistent cookie to verify data was preserved
    let preserved_data: VouchrsUserData = vouchrs::utils::crypto::decrypt_data(
        persistent_cookie.value(),
        session_manager.encryption_key(),
    )
    .expect("Should decrypt persistent cookie");

    // Verify that email and name were preserved from the existing cookie
    assert_eq!(
        preserved_data.email, "user@example.com",
        "Email should be preserved from existing cookie"
    );
    assert_eq!(
        preserved_data.name,
        Some("John Doe".to_string()),
        "Name should be preserved from existing cookie"
    );

    // Verify other fields were updated from new data
    assert_eq!(preserved_data.provider, "google");
    assert_eq!(preserved_data.provider_id, "12345");
    assert_eq!(preserved_data.client_ip, Some("192.168.1.1".to_string()));
}

/// Test that user data is not preserved when provider_id differs
#[actix_web::test]
async fn test_no_persistence_different_provider_id() {
    let test_key = b"test-encryption-key-32-bytes-min";
    let session_manager = SessionManager::new(test_key, false, false, 24, 24, 0);

    // Create initial user data with a different provider_id
    let initial_user_data = VouchrsUserData::new(
        "user@example.com".to_string(),
        Some("John Doe".to_string()),
        "google".to_string(),
        "different_id".to_string(),
        Some("192.168.1.1".to_string()),
        Some("Mozilla/5.0".to_string()),
        Some("macOS".to_string()),
        Some("en-US".to_string()),
        0,
        Some(Utc::now().timestamp()),
    );

    let initial_cookie = session_manager
        .cookie_factory()
        .create_user_cookie(&initial_user_data)
        .expect("Should create initial user cookie");

    let req = test::TestRequest::get()
        .uri("/")
        .cookie(initial_cookie)
        .to_http_request();

    // Create new user data with different provider_id
    let new_user_data = VouchrsUserData::new(
        String::new(),
        None,
        "google".to_string(),
        "12345".to_string(), // Different provider_id
        Some("192.168.1.1".to_string()),
        Some("Mozilla/5.0".to_string()),
        Some("macOS".to_string()),
        Some("en-US".to_string()),
        0,
        Some(Utc::now().timestamp()),
    );

    let new_cookie = session_manager
        .cookie_factory()
        .create_user_cookie_with_persistence(&req, &new_user_data)
        .expect("Should create new user cookie");

    let result_data: VouchrsUserData =
        vouchrs::utils::crypto::decrypt_data(new_cookie.value(), session_manager.encryption_key())
            .expect("Should decrypt new cookie");

    // Verify that no data was preserved (empty email, no name)
    assert_eq!(
        result_data.email, "",
        "Email should not be preserved with different provider_id"
    );
    assert_eq!(
        result_data.name, None,
        "Name should not be preserved with different provider_id"
    );
    assert_eq!(result_data.provider_id, "12345");
}

/// Test that new non-empty values override existing values
#[actix_web::test]
async fn test_new_values_override_existing() {
    let test_key = b"test-encryption-key-32-bytes-min";
    let session_manager = SessionManager::new(test_key, false, false, 24, 24, 0);

    // Create initial user data
    let initial_user_data = VouchrsUserData::new(
        "old@example.com".to_string(),
        Some("Old Name".to_string()),
        "google".to_string(),
        "12345".to_string(),
        Some("192.168.1.1".to_string()),
        Some("Mozilla/5.0".to_string()),
        Some("macOS".to_string()),
        Some("en-US".to_string()),
        0,
        Some(Utc::now().timestamp()),
    );

    let initial_cookie = session_manager
        .cookie_factory()
        .create_user_cookie(&initial_user_data)
        .expect("Should create initial user cookie");

    let req = test::TestRequest::get()
        .uri("/")
        .cookie(initial_cookie)
        .to_http_request();

    // Create new user data with non-empty values
    let new_user_data = VouchrsUserData::new(
        "new@example.com".to_string(), // Non-empty email
        Some("New Name".to_string()),  // Non-empty name
        "google".to_string(),
        "12345".to_string(),
        Some("192.168.1.1".to_string()),
        Some("Mozilla/5.0".to_string()),
        Some("macOS".to_string()),
        Some("en-US".to_string()),
        0,
        Some(Utc::now().timestamp()),
    );

    let result_cookie = session_manager
        .cookie_factory()
        .create_user_cookie_with_persistence(&req, &new_user_data)
        .expect("Should create result user cookie");

    let result_data: VouchrsUserData = vouchrs::utils::crypto::decrypt_data(
        result_cookie.value(),
        session_manager.encryption_key(),
    )
    .expect("Should decrypt result cookie");

    // Verify that new non-empty values override existing values
    assert_eq!(
        result_data.email, "new@example.com",
        "New non-empty email should override existing"
    );
    assert_eq!(
        result_data.name,
        Some("New Name".to_string()),
        "New non-empty name should override existing"
    );
}
