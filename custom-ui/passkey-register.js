/**
 * Passkey Registration for Vouchrs
 * Version: 0.2.0
 *
 * Provides passkey registration functionality:
 * - Cross-platform passkey registration (Chrome, Safari, 1Password, Bitwarden, etc.)
 * - Mobile platform authenticators (TouchID, FaceID, Android Biometric)
 * - Robust error handling and timeout management
 * - Built-in email validation
 *
 * Optimizations:
 * - Platform-specific credential handling
 * - Cross-browser compatibility fallbacks
 * - Enhanced timeout management for different platforms
 * - Secure credential cleanup on failures
 * - User-friendly error messages
 */

// Simple email validation
function validateEmail(email) {
    return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email);
}

// Utility functions
function showStatus(message, type = 'info') {
    // Since we removed the status div, just log for debugging
    console.log(`[${type.toUpperCase()}] ${message}`);

    // For critical errors, show browser alert
    if (type === 'error') {
        alert(message);
    }
}

function hideStatus() {
    // No-op since we removed the status div
    console.log('[INFO] Status hidden');
}

function setLoading(button, loading) {
    if (loading) {
        button.disabled = true;
        button.classList.add('loading');
    } else {
        button.disabled = false;
        button.classList.remove('loading');
    }
}

function setSuccess(button, success) {
    if (success) {
        button.classList.remove('loading');
        button.classList.add('success');
        button.disabled = true;
    } else {
        button.classList.remove('success');
        button.disabled = false;
    }
}

/**
 * Base64URL to ArrayBuffer conversion
 * @param {string} base64url - Base64URL encoded string
 * @returns {ArrayBuffer} Decoded buffer
 */
function base64urlToBuffer(base64url) {
    if (!base64url || typeof base64url !== 'string') {
        throw new Error(`Invalid base64url input: ${base64url}. Expected a non-empty string.`);
    }
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
    const binary = atob(padded);
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return buffer;
}

/**
 * ArrayBuffer to Base64URL conversion
 * @param {ArrayBuffer} buffer - Buffer to encode
 * @returns {string} Base64URL encoded string
 */
function bufferToBase64url(buffer) {
    if (!buffer) {
        throw new Error(`Invalid buffer input: ${buffer}. Expected an ArrayBuffer.`);
    }
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Make API requests to the Vouchrs server
 * @param {string} endpoint - API endpoint path
 * @param {Object} options - Fetch options
 * @returns {Promise<Object>} Response data
 */
async function apiRequest(endpoint, options = {}) {
    const defaultOptions = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
        },
        credentials: 'same-origin',
        ...options
    };

    try {
        const response = await fetch(endpoint, defaultOptions);
        const data = await response.json();

        if (!response.ok) {
            data.status = response.status;
            throw data;
        }

        return data;
    } catch (error) {
        // Log errors for debugging while avoiding sensitive information
        console.error('API Request failed:', {
            endpoint,
            error: error.message || error.error || 'Unknown error'
        });
        throw error;
    }
}

/**
 * Detect platform capabilities for optimization
 * @returns {Object} Platform detection results
 */
function detectPlatform() {
    const userAgent = navigator.userAgent.toLowerCase();
    const isMobile = /android|webos|iphone|ipad|ipod|blackberry|iemobile|opera mini/i.test(userAgent);
    const isDesktop = !isMobile;
    const isApple = /iphone|ipad|ipod|mac/i.test(userAgent);
    const isAndroid = /android/i.test(userAgent);

    return {
        isMobile,
        isDesktop,
        isApple,
        isAndroid
    };
}

/**
 * Create credential with desktop fallback mechanism
 * @param {Object} options - Credential creation options
 * @returns {Promise<PublicKeyCredential>} Created credential
 */
async function createCredentialWithFallback(options) {
    // Try cross-platform first
    try {
        showStatus('Trying external authenticators (password managers, security keys)...', 'info');
        options.authenticatorSelection = {
            authenticatorAttachment: "cross-platform",
            userVerification: "discouraged",
            requireResidentKey: false,
            residentKey: "discouraged"
        };
        options.timeout = 30000;

        const credential = await navigator.credentials.create({
            publicKey: options,
            signal: AbortSignal.timeout(options.timeout)
        });

        showStatus('External authenticator connected successfully!', 'info');
        return credential;
    } catch (error) {
        // Check if recoverable error
        const isRecoverable = ['NotAllowedError', 'AbortError', 'NotSupportedError'].includes(error.name) ||
            error.message?.includes('cancelled') ||
            error.message?.includes('timeout');

        if (!isRecoverable) throw error;

        // Fallback to platform authenticators
        showStatus('Trying built-in authenticators (Windows Hello, Touch ID, etc.)...', 'info');
        await new Promise(resolve => setTimeout(resolve, 500));

        options.authenticatorSelection = {
            authenticatorAttachment: "platform",
            userVerification: "required",
            requireResidentKey: true,
            residentKey: "preferred"
        };
        options.timeout = 120000;

        const credential = await navigator.credentials.create({
            publicKey: options,
            signal: AbortSignal.timeout(options.timeout)
        });

        showStatus('Built-in authenticator activated successfully!', 'info');
        return credential;
    }
}

/**
 * Register a new passkey for the user
 * Handles both mobile and desktop platforms with appropriate optimizations
 */
async function registerPasskey() {
    const email = document.getElementById('email').value.trim();
    const displayName = document.getElementById('displayName').value.trim();
    const registerBtn = document.getElementById('register-btn');

    // Input validation
    if (!email || !displayName) {
        showStatus('Please enter both email address and display name', 'error');
        return;
    }

    // Use simple email validation
    if (!validateEmail(email)) {
        showStatus('Please enter a valid email address', 'error');
        return;
    }

    if (displayName.length < 2) {
        showStatus('Display name must be at least 2 characters', 'error');
        return;
    }

    setLoading(registerBtn, true);
    hideStatus();

    try {
        const platform = detectPlatform();
        showStatus('Starting passkey registration...', 'info');

        // Fetch passkey creation options from the server
        const _options = await apiRequest('/oauth2/passkey/register/start', {
            body: JSON.stringify({
                name: displayName,
                email: email
            })
        });

        showStatus('Creating your passkey...', 'info');

        // Parse options with fallback
        let options;
        if (PublicKeyCredential.parseCreationOptionsFromJSON) {
            try {
                options = PublicKeyCredential.parseCreationOptionsFromJSON(_options.creation_options);
            } catch {
                options = null;
            }
        }

        if (!options) {
            options = _options.creation_options.publicKey;
            options.challenge = base64urlToBuffer(options.challenge);
            options.user.id = base64urlToBuffer(options.user.id);
            if (options.excludeCredentials) {
                options.excludeCredentials = options.excludeCredentials.map(cred => ({
                    ...cred,
                    id: base64urlToBuffer(cred.id)
                }));
            }
        }

        // Add extensions for better cross-platform support
        options.extensions = options.extensions || {};
        options.extensions.credProtect = {
            credentialProtectionPolicy: "userVerificationRequired",
            enforceCredentialProtectionPolicy: false
        };

        // Create passkey with platform-specific options
        let credential;

        if (platform.isMobile) {
            // Mobile: Use platform authenticators
            options.authenticatorSelection = {
                authenticatorAttachment: "platform",
                userVerification: "required",
                requireResidentKey: true,
                residentKey: "preferred"
            };
            options.timeout = 180000; // 3 minutes

            credential = await navigator.credentials.create({ publicKey: options });
        } else {
            // Desktop: Try cross-platform first, then platform
            credential = await createCredentialWithFallback(options);
        }

        if (!credential) {
            throw new Error('Passkey creation was cancelled');
        }

        showStatus('Completing registration...', 'info');

        // Convert credential to JSON
        const credentialData = credential.toJSON?.() || {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            response: {
                attestationObject: bufferToBase64url(credential.response.attestationObject),
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON)
            },
            type: credential.type
        };

        // Complete registration
        const registrationData = {
            credential_response: credentialData,
            registration_state: _options.registration_state,
            user_data: _options.user_data
        };

        try {
            const result = await apiRequest('/oauth2/passkey/register/complete', {
                body: JSON.stringify(registrationData)
            });

            showStatus('Passkey created successfully! Redirecting...', 'success');

            // Clear redirect tracking and show success
            sessionStorage?.removeItem('redirectCount');
            sessionStorage?.removeItem('hasTriedAutoAuth');
            setSuccess(registerBtn, true);

            // Redirect after showing success
            setTimeout(() => {
                setSuccess(registerBtn, false);
                setLoading(registerBtn, false);
                window.location.href = result.redirect_url || '/';
            }, 500);

        } catch (e) {
            // Clean up failed credentials
            try {
                await PublicKeyCredential.signalUnknownCredential?.({
                    rpId: options.rp?.id,
                    credentialId: credentialData.id,
                });
            } catch { /* Silent cleanup failure */ }
            throw e;
        }

    } catch (error) {
        const platform = detectPlatform();
        let errorMessage = `Registration failed: ${error.message || error.error || 'Unknown error'}`;

        // Provide user-friendly error messages
        if (error.name === 'NotAllowedError') {
            errorMessage = platform.isDesktop
                ? 'Registration was cancelled. Both external and built-in authenticators were tried. Please try again.'
                : 'Registration was cancelled or failed. Please try again.';
        } else if (error.name === 'SecurityError') {
            errorMessage = 'Security error: Please ensure you are on a secure connection (HTTPS).';
        } else if (error.name === 'NotSupportedError') {
            errorMessage = platform.isDesktop
                ? 'No compatible authenticators found. Please ensure you have Windows Hello, Touch ID, or a compatible security key available.'
                : 'Biometric authentication not available. Please check your device settings.';
        }

        showStatus(errorMessage, 'error');
    } finally {
        setLoading(registerBtn, false);
    }
}

/**
 * Initialize the passkey registration interface
 */
document.addEventListener('DOMContentLoaded', function () {
    // Verify WebAuthn support
    if (!window.PublicKeyCredential) {
        showStatus('WebAuthn is not supported in this browser. Please use a modern browser or form-based sign-in.', 'error');
        document.getElementById('register-btn').disabled = true;
        return;
    }

    // Set up event listener for registration button
    document.getElementById('register-btn').addEventListener('click', registerPasskey);

    // Log readiness
    const platform = detectPlatform();
    const platformType = platform.isMobile ? 'mobile device' : 'desktop';
    console.log(`[INFO] Passkey registration ready! Optimized for ${platformType}.`);
});
