/**
 * Passkey Registration for Vouchrs
 * Version: 2.0.0
 *
 * Provides passkey registration functionality:
 * - Cross-platform passkey registration (Chrome, Safari, 1Password, Bitwarden, etc.)
 * - Mobile platform authenticators (TouchID, FaceID, Android Biometric)
 * - Robust error handling and timeout management
 * - Email validation using SafeJS library
 *
 * Optimizations:
 * - Platform-specific credential handling
 * - Cross-browser compatibility fallbacks
 * - Enhanced timeout management for different platforms
 * - Secure credential cleanup on failures
 * - User-friendly error messages
 * - SafeJS for secure input validation
 */

// SafeJS v1.0.1 - Email validation functionality (Enhanced)
// https://github.com/Hiren2001/SafeJS - MIT License
const Safe = {
    validateEmail: function (email) {
        // Enhanced email regex that supports + signs and other valid characters
        // Supports: user+tag@domain.com, user.name@domain.com, user-name@domain.co.uk
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        return emailRegex.test(email);
    }
};

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

    // Use SafeJS for email validation
    if (!Safe.validateEmail(email)) {
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

        let options;

        // Try modern JSON parsing first (better for mobile)
        if (PublicKeyCredential.parseCreationOptionsFromJSON) {
            try {
                options = PublicKeyCredential.parseCreationOptionsFromJSON(_options.creation_options);
            } catch (e) {
                options = null;
            }
        }

        // Fallback to manual parsing (better for desktop)
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

        // Platform-specific authenticator preferences
        if (platform.isMobile) {
            // Mobile: Prefer built-in platform authenticators (TouchID, FaceID, etc.)
            options.authenticatorSelection = {
                authenticatorAttachment: "platform",
                userVerification: "required",
                requireResidentKey: true,
                residentKey: "preferred"
            };
            options.timeout = 180000; // 3 minutes for mobile biometric setup
        } else {
            // Desktop: Prefer cross-platform authenticators (password managers)
            options.authenticatorSelection = {
                authenticatorAttachment: "cross-platform",
                userVerification: "required",
                requireResidentKey: true,
                residentKey: "preferred"
            };
            options.timeout = 120000; // 2 minutes for desktop
        }

        // Add extensions for better cross-platform support
        if (!options.extensions) {
            options.extensions = {};
        }

        // Enable credential protection extension
        options.extensions.credProtect = {
            credentialProtectionPolicy: "userVerificationRequired",
            enforceCredentialProtectionPolicy: false
        };

        // Cross-browser credential creation with timeout handling
        let credential;
        if (platform.isDesktop) {
            // Desktop: Enhanced timeout control for password manager integration
            const abortController = new AbortController();
            const timeoutId = setTimeout(() => abortController.abort(), options.timeout);

            try {
                credential = await navigator.credentials.create({
                    publicKey: options,
                    signal: abortController.signal
                });
                clearTimeout(timeoutId);
            } catch (error) {
                clearTimeout(timeoutId);
                throw error;
            }
        } else {
            // Mobile: Direct approach for platform authenticators
            credential = await navigator.credentials.create({
                publicKey: options
            });
        }

        if (!credential) {
            throw new Error('Passkey creation was cancelled');
        }

        showStatus('Completing registration...', 'info');

        // Convert credential to JSON with cross-browser compatibility
        let credentialData;
        if (typeof credential.toJSON === 'function') {
            try {
                credentialData = credential.toJSON.call(credential);
            } catch (e) {
                credentialData = null; // Fallback to manual conversion
            }
        }

        if (!credentialData) {
            // Manual conversion for older browsers
            credentialData = {
                id: credential.id,
                rawId: bufferToBase64url(credential.rawId),
                response: {
                    attestationObject: bufferToBase64url(credential.response.attestationObject),
                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON)
                },
                type: credential.type
            };
        }

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

            // Show success state on button
            setSuccess(registerBtn, true);

            // Redirect to the same destination as successful authentication with a slight delay to show success state
            setTimeout(() => {
                // Reset button state before redirect to prevent "back button" issues
                setSuccess(registerBtn, false);
                setLoading(registerBtn, false);
                window.location.href = result.redirect_url || '/';
            }, 500);

        } catch (e) {
            // Clean up failed credentials if supported
            if (PublicKeyCredential.signalUnknownCredential && options.rp) {
                try {
                    await PublicKeyCredential.signalUnknownCredential({
                        rpId: options.rp.id,
                        credentialId: credentialData.id,
                    });
                } catch (signalError) {
                    // Silent cleanup failure - not critical
                }
            }
            throw e;
        }

    } catch (error) {
        let errorMessage = `Registration failed: ${error.message || error.error || 'Unknown error'}`;

        // Provide user-friendly error messages
        if (error.name === 'NotAllowedError') {
            errorMessage = 'Registration was cancelled or failed. Please try again.';
        } else if (error.name === 'SecurityError') {
            errorMessage = 'Security error: Please ensure you are on a secure connection (HTTPS).';
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

    // Console log that the system is ready
    const platform = detectPlatform();
    const platformType = platform.isMobile ? 'mobile device' : 'desktop';
    console.log(`[INFO] Passkey registration ready! Optimized for ${platformType}.`);
});
