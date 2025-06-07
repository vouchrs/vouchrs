// One-Button Passkey Implementation
// Based on Google Chrome Labs passkey demo patterns
// Optimized for Android password manager compatibility

// Utility functions
function showStatus(message, type = 'info') {
    const statusElement = document.getElementById('status');
    statusElement.className = `status ${type}`;
    statusElement.textContent = message;
    statusElement.style.display = 'block';
}

function hideStatus() {
    document.getElementById('status').style.display = 'none';
}

function setLoading(button, loading) {
    if (loading) {
        button.disabled = true;
        const originalText = button.textContent;
        button.innerHTML = '<span class="spinner"></span>' + originalText;
        button.classList.add('loading');
    } else {
        button.disabled = false;
        button.innerHTML = button.textContent.replace(/^.*?([\w\s]+)$/, '$1');
        button.classList.remove('loading');
    }
}

// Base64URL encoding/decoding helpers (needed for manual parsing fallback)
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

// API helper function
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
        console.error('API Request failed:', error);
        throw error;
    }
}

// Modern passkey registration using Chrome Labs patterns
async function registerPasskey() {
    const email = document.getElementById('email').value.trim();
    const displayName = document.getElementById('displayName').value.trim();
    const registerBtn = document.getElementById('register-btn');

    if (!email || !displayName) {
        showStatus('Please enter both email address and display name', 'error');
        return;
    }

    if (!email.includes('@') || !email.includes('.') || email.length < 5) {
        showStatus('Please enter a valid email address', 'error');
        return;
    }

    setLoading(registerBtn, true);
    hideStatus();

    try {
        showStatus('Starting passkey registration...', 'info');

        // Fetch passkey creation options from the server
        const _options = await apiRequest('/oauth2/passkey/register/start', {
            body: JSON.stringify({
                name: displayName,
                email: email
            })
        });

        showStatus('Creating your passkey...', 'info');

        // Use the modern JSON parsing method if available
        let options;
        if (PublicKeyCredential.parseCreationOptionsFromJSON) {
            options = PublicKeyCredential.parseCreationOptionsFromJSON(_options.creation_options);
        } else {
            // Fallback to manual parsing for older browsers
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

        // Optimize for both desktop and mobile password managers
        options.authenticatorSelection = {
            // For desktop password managers: prefer cross-platform
            authenticatorAttachment: "cross-platform", // This specifically helps desktop password managers
            userVerification: "required",
            requireResidentKey: true,
            residentKey: "preferred" // Use preferred instead of required for better compatibility
        };

        // Set reasonable timeout - shorter for desktop responsiveness
        options.timeout = 120000; // 2 minutes for registration

        // Add extensions for better desktop password manager compatibility
        if (!options.extensions) {
            options.extensions = {};
        }
        // Enable credential protection extension for better cross-platform support
        options.extensions.credProtect = {
            credentialProtectionPolicy: "userVerificationRequired",
            enforceCredentialProtectionPolicy: false
        };

        console.log('Creating credential with options:', options);

        // Create the credential with enhanced desktop/mobile compatibility
        const credential = await navigator.credentials.create({
            publicKey: options,
            // Add signal for better timeout handling on desktop (like in working test page)
            signal: AbortSignal.timeout(120000) // 2 minute timeout matching the options
        });

        if (!credential) {
            throw new Error('No credential was created - user may have cancelled');
        }

        showStatus('Completing registration...', 'info');

        // Convert credential to JSON format (modern approach)
        let credentialData;
        if (credential.toJSON) {
            credentialData = credential.toJSON();
        } else {
            // Fallback for older browsers
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

            showStatus('Passkey created successfully! You can now sign in with it.', 'success');

            // Store user data for potential authentication
            if (_options.user_data) {
                localStorage.setItem('passkey_user_data', _options.user_data);
            }

        } catch (e) {
            // Signal unknown credential for cleanup if supported
            if (PublicKeyCredential.signalUnknownCredential && options.rp) {
                try {
                    await PublicKeyCredential.signalUnknownCredential({
                        rpId: options.rp.id,
                        credentialId: credentialData.id,
                    });
                    console.info('Unknown credential signaled to password manager for cleanup');
                } catch (signalError) {
                    console.warn('Failed to signal unknown credential:', signalError);
                }
            }
            throw e;
        }

    } catch (error) {
        console.error('Registration failed:', error);
        showStatus(`Registration failed: ${error.message || error.error || 'Unknown error'}`, 'error');
    } finally {
        setLoading(registerBtn, false);
    }
}

// Modern passkey authentication using Chrome Labs patterns
async function authenticateWithPasskey() {
    const signinBtn = document.getElementById('passkey-signin');

    setLoading(signinBtn, true);
    hideStatus();

    try {
        showStatus('Starting passkey authentication...', 'info');

        // Fetch passkey request options from the server
        const _options = await apiRequest('/oauth2/passkey/auth/start', {
            body: JSON.stringify({}) // Empty body for usernameless auth
        });

        showStatus('Choose your passkey...', 'info');

        // Use the modern JSON parsing method if available
        let options;
        if (PublicKeyCredential.parseRequestOptionsFromJSON) {
            options = PublicKeyCredential.parseRequestOptionsFromJSON(_options.request_options);
        } else {
            // Fallback to manual parsing for older browsers
            options = _options.request_options.publicKey;
            options.challenge = base64urlToBuffer(options.challenge);
            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map(cred => ({
                    ...cred,
                    id: base64urlToBuffer(cred.id)
                }));
            }
        }

        // For usernameless auth, don't restrict allowCredentials
        // This allows password managers to show all available passkeys
        delete options.allowCredentials;

        // Optimize for both desktop and mobile password managers
        options.userVerification = "required";
        options.timeout = 120000; // 2 minutes - shorter for desktop responsiveness

        // Add extensions for better desktop password manager compatibility
        if (!options.extensions) {
            options.extensions = {};
        }

        console.log('Getting credential with options:', options);

        // Get the credential with enhanced desktop/mobile compatibility
        const credential = await navigator.credentials.get({
            publicKey: options,
            mediation: 'optional', // Allow password manager picker
            // Add signal for better timeout handling on desktop (like in working test page)
            signal: AbortSignal.timeout(120000) // 2 minute timeout
        });

        if (!credential) {
            throw new Error('No credential was returned - user may have cancelled');
        }

        showStatus('Completing authentication...', 'info');

        // Convert credential to JSON format (modern approach)
        let credentialData;
        if (credential.toJSON) {
            credentialData = credential.toJSON();
        } else {
            // Fallback for older browsers
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

        // Complete authentication
        const authenticationData = {
            credential_response: credentialData,
            authentication_state: _options.authentication_state,
            user_data: localStorage.getItem('passkey_user_data') // Try stored data first
        };

        try {
            const result = await apiRequest('/oauth2/passkey/auth/complete', {
                body: JSON.stringify(authenticationData)
            });

            showStatus('Authentication successful! Redirecting...', 'success');

            // Redirect to the original destination or home
            setTimeout(() => {
                window.location.href = result.redirect_url || '/';
            }, 1000);

        } catch (e) {
            // Signal unknown credential if supported and error is 404
            if (e.status === 404 && PublicKeyCredential.signalUnknownCredential && options.rpId) {
                try {
                    await PublicKeyCredential.signalUnknownCredential({
                        rpId: options.rpId,
                        credentialId: credentialData.id,
                    });
                    console.info('Unknown credential signaled to password manager for cleanup');
                } catch (signalError) {
                    console.warn('Failed to signal unknown credential:', signalError);
                }
            }
            throw e;
        }

    } catch (error) {
        console.error('Authentication failed:', error);
        let errorMessage = `Authentication failed: ${error.message || error.error || 'Unknown error'}`;

        if (error.name === 'NotAllowedError') {
            errorMessage = 'Authentication was cancelled or no passkeys available. Please try again or register a new passkey.';
        } else if (error.name === 'SecurityError') {
            errorMessage = 'Security error: Please ensure you are on a secure connection (HTTPS).';
        }

        showStatus(errorMessage, 'error');
    } finally {
        setLoading(signinBtn, false);
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', function () {
    // Check WebAuthn support
    if (!window.PublicKeyCredential) {
        showStatus('WebAuthn is not supported in this browser. Please use a modern browser or the form-based sign-in.', 'error');
        document.getElementById('passkey-signin').disabled = true;
        document.getElementById('register-btn').disabled = true;
        return;
    }

    // Set up event listeners
    document.getElementById('passkey-signin').addEventListener('click', authenticateWithPasskey);
    document.getElementById('register-btn').addEventListener('click', registerPasskey);

    // Check for modern WebAuthn features
    const hasModernFeatures = !!(
        PublicKeyCredential.parseCreationOptionsFromJSON &&
        PublicKeyCredential.parseRequestOptionsFromJSON
    );

    console.log('WebAuthn support detected:', {
        basic: !!window.PublicKeyCredential,
        modern: hasModernFeatures,
        signals: !!PublicKeyCredential.signalUnknownCredential
    });

    // Show initial status
    showStatus('Ready! Click "Sign in with passkey" to authenticate or create a new passkey below.', 'info');
});
