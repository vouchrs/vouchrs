/**
 * Universal Passkey Implementation for Vouchrs
 * Version: 0.2.0
 *
 * Provides automatic passkey detection and authentication with fallback to registration:
 * - Automatic detection of available passkeys
 *  * - Mobile platform authenticators (TouchID, FaceID, Android Biometric)
 * - Usernameless authentication flows
 * - Automatic redirect to registration when no passkeys are available
 * - Robust error handling and timeout management
 *
 * Optimizations:
 * - Platform-specific credential handling
 * - Cross-browser compatibility fallbacks
 * - Enhanced timeout management for different platforms
 * - Secure credential cleanup on failures
 * - User-friendly error messages and automatic registration fallback
 */

// Utility functions
function showStatus(message, type = 'info') {
    // Log for debugging
    console.log(`[${type.toUpperCase()}] ${message}`);

    // Show in the redirect indicator for user feedback
    const indicator = document.getElementById('redirect-indicator');
    if (indicator) {
        indicator.textContent = message;
        indicator.className = `redirect-indicator ${type}`;
        indicator.style.display = 'block';
    }

    // For critical errors, show browser alert as fallback
    if (type === 'error' && !indicator) {
        alert(message);
    }
}

function hideStatus() {
    console.log('[INFO] Status hidden');
    const indicator = document.getElementById('redirect-indicator');
    if (indicator) {
        indicator.style.display = 'none';
    }
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
 * Authenticate user with existing passkey or redirect to registration
 * Supports usernameless authentication across platforms with automatic detection
 */
async function authenticateWithPasskey() {
    const signinBtn = document.getElementById('passkey-signin');

    setLoading(signinBtn, true);
    hideStatus();

    try {
        const platform = detectPlatform();
        showStatus('Checking for available passkeys...', 'info');

        // First, try to get authentication options to see if there are any passkeys
        let _options;
        try {
            _options = await apiRequest('/auth/passkey/auth/start', {
                body: JSON.stringify({}) // Empty body for usernameless auth
            });
        } catch (error) {
            // If we can't start auth (e.g., no passkeys), redirect to registration
            if (error.status === 404 || error.message?.includes('no passkeys') || error.error?.includes('no passkeys')) {
                showStatus('No passkeys found. Redirecting to registration...', 'info');
                setTimeout(() => {
                    // Redirect to the registration form with context
                    window.location.href = '/auth/static/passkey-register.html?from=signin&reason=no-passkeys';
                }, 1500);
                return;
            }
            throw error;
        }

        showStatus('Passkeys found! Choose your passkey...', 'info');

        // Parse authentication options with cross-browser compatibility
        let options;

        if (platform.isDesktop) {
            // Desktop: Manual parsing for better password manager compatibility
            options = _options.request_options.publicKey;
            options.challenge = base64urlToBuffer(options.challenge);
            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map(cred => ({
                    ...cred,
                    id: base64urlToBuffer(cred.id)
                }));
            }
        } else {
            // Mobile: Try modern JSON parsing first, fallback to manual
            if (PublicKeyCredential.parseRequestOptionsFromJSON) {
                try {
                    options = PublicKeyCredential.parseRequestOptionsFromJSON(_options.request_options);
                } catch (e) {
                    // Fallback to manual parsing
                    options = _options.request_options.publicKey;
                    options.challenge = base64urlToBuffer(options.challenge);
                    if (options.allowCredentials) {
                        options.allowCredentials = options.allowCredentials.map(cred => ({
                            ...cred,
                            id: base64urlToBuffer(cred.id)
                        }));
                    }
                }
            } else {
                // Manual parsing for older mobile browsers
                options = _options.request_options.publicKey;
                options.challenge = base64urlToBuffer(options.challenge);
                if (options.allowCredentials) {
                    options.allowCredentials = options.allowCredentials.map(cred => ({
                        ...cred,
                        id: base64urlToBuffer(cred.id)
                    }));
                }
            }
        }

        // Configure for usernameless authentication
        if (options.allowCredentials) {
            delete options.allowCredentials; // Allow all available passkeys
        }

        if (options.authenticatorSelection) {
            delete options.authenticatorSelection; // Remove restrictions for password managers
        }

        // Set authentication requirements
        options.userVerification = "required";

        // Platform-optimized timeouts
        if (platform.isMobile) {
            options.timeout = 180000; // 3 minutes for mobile
        } else {
            options.timeout = 120000; // 2 minutes for desktop
        }

        // Add extensions for better compatibility
        if (!options.extensions) {
            options.extensions = {};
        }

        // Cross-browser credential retrieval with timeout handling
        let credential;
        if (platform.isDesktop) {
            // Desktop: Enhanced timeout control for password manager integration
            const abortController = new AbortController();
            const timeoutId = setTimeout(() => abortController.abort(), options.timeout);

            try {
                credential = await navigator.credentials.get({
                    publicKey: options,
                    mediation: 'optional', // Allow password manager picker
                    signal: abortController.signal
                });
                clearTimeout(timeoutId);
            } catch (error) {
                clearTimeout(timeoutId);
                throw error;
            }
        } else {
            // Mobile: Direct approach for platform authenticators
            credential = await navigator.credentials.get({
                publicKey: options,
                mediation: 'optional'
            });
        }

        if (!credential) {
            throw new Error('Authentication was cancelled or no passkeys available');
        }

        showStatus('Completing authentication...', 'info');

        // Convert credential to JSON with cross-browser compatibility
        let credentialData;
        if (typeof credential.toJSON === 'function') {
            try {
                credentialData = credential.toJSON.call(credential);
                // Normalize empty userHandle to null
                if (credentialData.response && credentialData.response.userHandle === '') {
                    credentialData.response.userHandle = null;
                }
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
                    authenticatorData: bufferToBase64url(credential.response.authenticatorData),
                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                    signature: bufferToBase64url(credential.response.signature),
                    userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null
                },
                type: credential.type
            };
        }

        // Prepare authentication request
        const authenticationData = {
            credential_response: credentialData,
            user_data: _options.user_data || null // Support both traditional and usernameless auth
        };

        try {
            const result = await apiRequest('/auth/passkey/auth/complete', {
                body: JSON.stringify(authenticationData)
            });

            showStatus('Authentication successful! Redirecting...', 'success');

            // Show success state on button
            setSuccess(signinBtn, true);

            // Redirect to original destination with a slight delay to show success state
            setTimeout(() => {
                // Clear the status message and reset button state before redirect
                hideStatus();
                setSuccess(signinBtn, false);
                setLoading(signinBtn, false);
                window.location.href = result.redirect_url || '/';
            }, 500);

        } catch (e) {
            // Clean up unknown credentials if supported
            if (e.status === 404 && PublicKeyCredential.signalUnknownCredential && options.rpId) {
                try {
                    await PublicKeyCredential.signalUnknownCredential.call(PublicKeyCredential, {
                        rpId: options.rpId,
                        credentialId: credentialData.id,
                    });
                } catch (signalError) {
                    // Silent cleanup failure - not critical
                }
            }
            throw e;
        }

    } catch (error) {
        let errorMessage = `Authentication failed: ${error.message || error.error || 'Unknown error'}`;

        // Handle specific cases where we should redirect to registration
        if (error.name === 'NotAllowedError') {
            showStatus('Passkey authentication cancelled. Forwarding to registration...', 'info');
            setTimeout(() => {
                window.location.href = '/auth/static/passkey-register.html?from=signin&reason=cancelled';
            }, 2000);
            return;
        } else if (error.name === 'SecurityError') {
            errorMessage = 'Security error: Please ensure you are on a secure connection (HTTPS).';
        } else if (error.name === 'AbortError') {
            errorMessage = 'Authentication timed out. Please try again.';
        } else if (error.status === 404 || error.message?.includes('no passkeys') || error.error?.includes('no passkeys')) {
            showStatus('No passkeys found. Forwarding to registration...', 'info');
            setTimeout(() => {
                window.location.href = '/auth/static/passkey-register.html';
            }, 1500);
            return;
        }

        showStatus(errorMessage, 'error');
        // Only clear loading state on error (success state is handled separately)
        setLoading(signinBtn, false);
    }
}

/**
 * Initialize the passkey authentication interface
 */
document.addEventListener('DOMContentLoaded', function () {
    // Verify WebAuthn support
    if (!window.PublicKeyCredential) {
        showStatus('WebAuthn is not supported in this browser. Please use a modern browser or form-based sign-in.', 'error');
        document.getElementById('passkey-signin').disabled = true;
        return;
    }

    // Set up event listener for sign-in button
    document.getElementById('passkey-signin').addEventListener('click', authenticateWithPasskey);

    // Console log that the system is ready
    const platform = detectPlatform();
    const platformType = platform.isMobile ? 'mobile device' : 'desktop';
    console.log(`[INFO] Passkey system ready! Optimized for ${platformType}.`);
});
