# Stateless OAuth Flow

## Overview

Vouchrs implements a **stateless OAuth flow** where authentication state is embedded directly in the OAuth `state` parameter instead of being stored server-side. This eliminates the need for session storage during the OAuth handshake.

## Flow Description

### 1. OAuth Initiation
**Location**: `src/handlers/auth.rs` - `oauth_sign_in()`

When a user initiates OAuth authentication:
```
GET /auth/sign_in?provider=google&rd=https://example.com/dashboard
```

The system creates a cryptographically protected state parameter:
```rust
// Create OAuth state with CSRF protection
let oauth_state = OAuthState {
    state: csrf_token,    // Crypto-secure CSRF token (192-bit entropy)
    provider: provider.clone(),  // Provider name (e.g., "google")
    redirect_url: rd.clone(),  // Optional redirect URL
};

// Encrypt the entire state to prevent tampering
let encrypted_state = session_manager.encrypt_data(&oauth_state)?;
```

**Example encrypted state**: `FoS9lPOT9ctSc5P4Cga_BilM-MQBqB6r0kOKVXBWVifjKU5bSHZmGOXHMdLjzTXG2WiEwlhGFcp8ZIXH7mJ2S9pvPTjr0Sjz64Yf5g6HMPYDXKkZXGs-tqvrws0h-noKo3gf4WlGORf-ftb8EZF_Tal3qzovE6klWPkYMn0zp03D_bkTgxUrjXOezbaQF28`

### 2. OAuth Provider Redirect
**Location**: `src/oauth.rs` - `get_auth_url()`

The encrypted state parameter is sent in the authorization URL:
```
https://accounts.google.com/oauth/authorize?
  client_id=...&
  redirect_uri=http://localhost:8080/auth/oauth2/callback&
  response_type=code&
  scope=openid email profile&
  state=FoS9lPOT9ctSc5P4Cga_BilM-MQBqB6r0kOKVXBWVifjKU5bSHZmGOXHMdLjzTXG2WiEwlhGFcp8ZIXH7mJ2S9pvPTjr0Sjz64Yf5g6HMPYDXKkZXGs-tqvrws0h-noKo3gf4WlGORf-ftb8EZF_Tal3qzovE6klWPkYMn0zp03D_bkTgxUrjXOezbaQF28
```

### 3. OAuth Callback Processing
**Location**: `src/oauth.rs` - `get_state_from_callback()`

When the OAuth provider redirects back, the system decrypts and validates the received state parameter:

```rust
pub async fn get_state_from_callback(
    &self,
    callback_params: &CallbackParams,
    session_manager: &SessionManager,
) -> Result<OAuthState, String> {
    let received_state = &callback_params.state;

    // Decrypt and validate the encrypted state
    match session_manager.decrypt_data::<OAuthState>(received_state) {
        Ok(oauth_state) => {
            tracing::debug!("Successfully decrypted OAuth state");
            return Ok(oauth_state);
        }
        Err(e) => {
            tracing::error!("Failed to decrypt state: {}", e);
            return Err("Invalid or tampered state parameter".to_string());
        }
    }
}
```

**Security Benefits:**
- **Tamper Protection**: Encrypted state cannot be modified by attackers
- **Integrity Verification**: Any tampering will cause decryption to fail
- **Provider Name Security**: Provider configuration cannot be manipulated

### 4. Redirect URL Consumption
**Location**: `src/handlers/callback.rs` - `build_and_finalize_session()`

The extracted redirect URL is validated and used for the final post-authentication redirect:

```rust
let redirect_to = params.redirect_url.unwrap_or_else(|| "/".to_string());
let validated_redirect = validate_post_auth_redirect(&redirect_to)
    .unwrap_or_else(|_| "/".to_string());  // Safe fallback
```

## 5. Provider Name Usage in Token Exchange

The provider name extracted from the OAuth state is critical for the token exchange process. Here's how it's used:

### Token Exchange Process

When `oauth_config.exchange_code_for_tokens(&oauth_state.provider, &code)` is called:

1. **Provider Lookup**: The provider name is used to look up the correct `RuntimeProvider` configuration:
   ```rust
   let runtime_provider = self
       .providers
       .get(provider)  // Uses provider name as key
       .ok_or_else(|| format!("Provider {provider} not configured"))?;
   ```

2. **Provider-Specific Configuration**: The `RuntimeProvider` contains:
   - `auth_url`: Authorization endpoint URL
   - `token_url`: Token endpoint URL
   - `client_id`: OAuth client ID
   - `client_secret`: OAuth client secret (or None for JWT-based auth)
   - `settings`: Provider-specific settings including JWT signing config

3. **Endpoint Selection**: Uses provider-specific token endpoint:
   ```rust
   let response = self
       .http_client
       .post(&runtime_provider.token_url)  // Provider-specific URL
       .form(params)
       .send()
   ```

4. **Authentication Method**: Handles different authentication methods per provider:
   - **Regular OAuth**: Uses `client_secret` from configuration
   - **Apple (JWT-based)**: Generates client secret using JWT signing configuration

   ```rust
   if let Some(ref secret) = runtime_provider.client_secret {
       // Regular OAuth with client secret
       params.insert("client_secret".to_string(), secret.clone());
   } else if let Some(ref jwt_config) = runtime_provider.settings.jwt_signing {
       // JWT signing (Apple)
       let client_secret = generate_apple_client_secret(jwt_config, &client_id)?;
       params.insert("client_secret".to_string(), client_secret);
   }
   ```

### Multi-Provider Support

The provider name enables Vouchrs to support multiple OAuth providers simultaneously by:

1. **Runtime Configuration Selection**: Uses provider name to lookup correct endpoints, credentials, and settings
2. **Protocol Adaptation**: Handles provider-specific authentication methods (client secrets vs JWT signing)
3. **Security Isolation**: Prevents credential mixing and ensures proper endpoint routing

Each provider (Google, Apple, GitHub) requires unique URLs, credentials, and authentication protocols. The provider name serves as the key to select the correct configuration during token exchange.

## State Parameter Format

The OAuth state is encrypted using AES-256-GCM with a 96-bit nonce:

| Component | Description | Example |
|-----------|-------------|---------|
| **Encrypted State** | Base64URL-encoded encrypted OAuth state containing CSRF token, provider, and redirect URL | `FoS9lPOT9ctSc5P4Cga_BilM-MQBqB6r0kOKVXBWVifjKU5bSHZmGOXHMdLjzTXG2WiEwlhGFcp8ZIXH7mJ2S9pvPTjr0Sjz64Yf5g6HMPYDXKkZXGs-tqvrws0h-noKo3gf4WlGORf-ftb8EZF_Tal3qzovE6klWPkYMn0zp03D_bkTgxUrjXOezbaQF28` |

**Format Details:**
- **Encryption**: AES-256-GCM authenticated encryption
- **Nonce**: 96-bit random nonce (prepended to ciphertext)
- **Encoding**: Base64URL without padding
- **Length**: Typically 180-200 characters depending on content size

## Security Considerations

- **CSRF Protection**: Crypto-secure tokens prevent cross-site request forgery
- **Transport Security**: State travels over HTTPS (encrypted in transit)
- **Cryptographic Protection**: State parameter is encrypted with AES-256-GCM to prevent tampering
- **Provider Name Security**: Encrypted state prevents provider confusion attacks
- **Integrity Verification**: Any tampering with the state parameter causes decryption to fail
- **Short-Lived**: State is only valid for the OAuth flow duration

## Benefits

1. **Stateless**: No server-side session storage required during OAuth flow
2. **Scalable**: Works across multiple server instances without shared state
3. **Simple**: Self-contained state parameter eliminates complexity
4. **Standard Compliant**: Follows OAuth 2.0 specification for state parameter usage
5. **Secure**: Cryptographically protected against tampering and manipulation

## Code Locations

| Function | File | Purpose |
|----------|------|---------|
| `oauth_sign_in()` | `src/handlers/auth.rs` | Creates encrypted state parameter |
| `get_auth_url()` | `src/oauth.rs` | Embeds encrypted state in authorization URL |
| `get_state_from_callback()` | `src/oauth.rs` | Decrypts and validates state from callback |
| `exchange_code_for_tokens()` | `src/oauth.rs` | Uses provider name for token exchange |
| `build_and_finalize_session()` | `src/handlers/callback.rs` | Consumes redirect URL for post-auth redirect |

## Example Flow

1. **User Request**: `/auth/sign_in?provider=google&rd=/dashboard`
2. **State Creation**: `FoS9lPOT9ctSc5P4Cga_BilM-MQBqB6r0kOKVXBWVifjKU5bSHZmGOXHMdLjzTXG2WiEwlhGFcp8ZIXH7mJ2S9pvPTjr0Sjz64Yf5g6HMPYDXKkZXGs-tqvrws0h-noKo3gf4WlGORf-ftb8EZF_Tal3qzovE6klWPkYMn0zp03D_bkTgxUrjXOezbaQF28` (encrypted OAuth state)
3. **OAuth Redirect**: User sent to Google with encrypted state parameter
4. **OAuth Callback**: Google returns with same encrypted state parameter
5. **State Decryption**: Decrypt and extract provider (`google`) and redirect URL (`/dashboard`)
6. **Token Exchange**: Complete OAuth flow with extracted provider information
7. **Redirect Consumption**: Validate and redirect user to `/dashboard`
