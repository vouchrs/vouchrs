// Passkey Test JavaScript
// WebAuthn passkey registration and authentication functionality

// Global state
let currentUser = null;
let registrationOptions = null;
let authenticationOptions = null;

// Utility functions
function showStatus(elementId, message, type = 'info', data = null) {
    const element = document.getElementById(elementId);
    element.className = `status ${type}`;
    element.innerHTML = message;
    if (data) {
        element.innerHTML += `<div class="response-data">${JSON.stringify(data, null, 2)}</div>`;
    }
    element.style.display = 'block';
}

function hideStatus(elementId) {
    document.getElementById(elementId).style.display = 'none';
}

function setLoading(buttonId, loading) {
    const button = document.getElementById(buttonId);
    if (loading) {
        button.disabled = true;
        button.innerHTML = '<span class="spinner"></span>' + button.textContent;
        button.classList.add('loading');
    } else {
        button.disabled = false;
        button.innerHTML = button.textContent.replace(/^.*?([A-Z])/, '$1');
        button.classList.remove('loading');
    }
}

// Base64URL encoding/decoding helpers
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
        },
        credentials: 'include',
        ...options
    };

    try {
        const response = await fetch(endpoint, defaultOptions);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || `HTTP ${response.status}: ${response.statusText}`);
        }

        return data;
    } catch (error) {
        console.error('API Request failed:', error);
        throw error;
    }
}

// Registration flow
async function startRegistration() {
    const username = document.getElementById('registerUsername').value.trim();
    const displayName = document.getElementById('registerDisplayName').value.trim();

    if (!username || !displayName) {
        showStatus('registerStatus', 'Please enter both username and display name', 'error');
        return;
    }

    setLoading('registerBtn', true);
    hideStatus('registerStatus');

    try {
        showStatus('registerStatus', 'Starting registration...', 'info');

        const options = await apiRequest('/oauth2/passkey/register/start', {
            body: JSON.stringify({
                name: displayName,
                email: username.includes('@') ? username : `${username}@example.com`
            })
        });

        registrationOptions = options;
        showStatus('registerStatus', 'Registration options received, creating credential...', 'info', options);

        // Validate response structure
        if (!options.creation_options || !options.creation_options.publicKey) {
            throw new Error('Invalid response: missing creation_options.publicKey');
        }
        const publicKeyOptions = options.creation_options.publicKey;

        if (!publicKeyOptions.challenge) {
            throw new Error('Invalid response: missing challenge in publicKey options');
        }
        if (!publicKeyOptions.user || !publicKeyOptions.user.id) {
            throw new Error('Invalid response: missing user.id in publicKey options');
        }

        // Convert challenge and user ID from base64url to ArrayBuffer
        publicKeyOptions.challenge = base64urlToBuffer(publicKeyOptions.challenge);
        publicKeyOptions.user.id = base64urlToBuffer(publicKeyOptions.user.id);

        // Convert excludeCredentials if present
        if (publicKeyOptions.excludeCredentials) {
            publicKeyOptions.excludeCredentials = publicKeyOptions.excludeCredentials.map(cred => ({
                ...cred,
                id: base64urlToBuffer(cred.id)
            }));
        }

        // Add better options for password manager compatibility
        publicKeyOptions.authenticatorSelection = {
            authenticatorAttachment: "cross-platform", // Allow external authenticators
            userVerification: "preferred", // Prefer but don't require user verification
            requireResidentKey: true, // Enable discoverable credentials
            residentKey: "preferred" // Prefer resident keys for better UX
        };

        // Ensure timeout is reasonable for password managers
        if (!publicKeyOptions.timeout || publicKeyOptions.timeout > 120000) {
            publicKeyOptions.timeout = 120000; // 2 minutes max
        }

        console.log('Creating credential with options:', publicKeyOptions);

        // Create the credential with enhanced options for password manager detection
        const credential = await navigator.credentials.create({
            publicKey: publicKeyOptions,
            // Signal is important for abort handling
            signal: AbortSignal.timeout(120000) // 2 minute timeout
        });

        if (!credential) {
            throw new Error('No credential was created - user may have cancelled');
        }

        showStatus('registerStatus', 'Credential created, completing registration...', 'info');

        // Complete registration
        await completeRegistration(credential);

    } catch (error) {
        console.error('Registration failed:', error);
        showStatus('registerStatus', `Registration failed: ${error.message}`, 'error');
    } finally {
        setLoading('registerBtn', false);
    }
}

async function completeRegistration(credential) {
    try {
        const registrationData = {
            credential_response: {
                id: credential.id,
                rawId: bufferToBase64url(credential.rawId),
                response: {
                    attestationObject: bufferToBase64url(credential.response.attestationObject),
                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON)
                },
                type: credential.type
            },
            registration_state: registrationOptions.registration_state,
            user_data: registrationOptions.user_data
        };

        const result = await apiRequest('/oauth2/passkey/register/complete', {
            body: JSON.stringify(registrationData)
        });

        currentUser = {
            username: document.getElementById('registerUsername').value,
            displayName: document.getElementById('registerDisplayName').value,
            user_handle: result.user_handle,
            credential_id: result.credential_id
        };

        showStatus('registerStatus', 'Registration completed successfully! Copy the user_data below for authentication.', 'success', result);

        // Store user data locally for easy authentication
        if (registrationOptions && registrationOptions.user_data) {
            localStorage.setItem('passkey_user_data', registrationOptions.user_data);
            document.getElementById('authUserData').value = registrationOptions.user_data;
            showStatus('registerStatus', 'User data has been stored locally for automatic authentication!', 'info');
        }

        updateUserInfo();

    } catch (error) {
        console.error('Registration completion failed:', error);
        showStatus('registerStatus', `Registration completion failed: ${error.message}`, 'error');
    }
}

// Authentication flow
async function startAuthentication() {
    const username = document.getElementById('authUsername').value.trim();
    let userData = document.getElementById('authUserData').value.trim();

    // If no user data entered, try to get it from localStorage
    if (!userData) {
        userData = localStorage.getItem('passkey_user_data');
        if (userData) {
            document.getElementById('authUserData').value = userData;
            showStatus('authStatus', 'Using stored user data for authentication...', 'info');
        } else {
            showStatus('authStatus', 'No stored user data found. Please register first or enter user data manually.', 'error');
            return;
        }
    }

    setLoading('authBtn', true);
    hideStatus('authStatus');

    try {
        showStatus('authStatus', 'Starting authentication...', 'info');

        const requestBody = username ? { username } : {};
        const options = await apiRequest('/oauth2/passkey/auth/start', {
            body: JSON.stringify(requestBody)
        });

        authenticationOptions = options;
        showStatus('authStatus', 'Authentication options received, getting credential...', 'info', options);

        // Convert challenge from base64url to ArrayBuffer
        options.request_options.publicKey.challenge = base64urlToBuffer(options.request_options.publicKey.challenge);

        // Convert allowCredentials if present
        if (options.request_options.publicKey.allowCredentials) {
            options.request_options.publicKey.allowCredentials = options.request_options.publicKey.allowCredentials.map(cred => ({
                ...cred,
                id: base64urlToBuffer(cred.id)
            }));
        }

        // Enhance options for password manager compatibility
        options.request_options.publicKey.userVerification = "preferred";

        // Ensure timeout is reasonable
        if (!options.request_options.publicKey.timeout || options.request_options.publicKey.timeout > 120000) {
            options.request_options.publicKey.timeout = 120000; // 2 minutes max
        }

        console.log('Getting credential with options:', options.request_options.publicKey);

        // Get the credential with enhanced options
        const credential = await navigator.credentials.get({
            publicKey: options.request_options.publicKey,
            // Add mediation for better password manager integration
            mediation: 'optional', // Allow conditional UI
            // Signal for timeout handling
            signal: AbortSignal.timeout(120000) // 2 minute timeout
        });

        if (!credential) {
            throw new Error('No credential was returned - user may have cancelled');
        }

        showStatus('authStatus', 'Credential obtained, completing authentication...', 'info');

        // Complete authentication
        await completeAuthentication(credential);

    } catch (error) {
        console.error('Authentication failed:', error);
        showStatus('authStatus', `Authentication failed: ${error.message}`, 'error');
    } finally {
        setLoading('authBtn', false);
    }
}

async function completeAuthentication(credential) {
    try {
        const authenticationData = {
            credential_response: {
                id: credential.id,
                rawId: bufferToBase64url(credential.rawId),
                response: {
                    authenticatorData: bufferToBase64url(credential.response.authenticatorData),
                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                    signature: bufferToBase64url(credential.response.signature),
                    userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null
                },
                type: credential.type
            },
            authentication_state: authenticationOptions.authentication_state,
            user_data: document.getElementById('authUserData').value.trim()
        };

        const result = await apiRequest('/oauth2/passkey/auth/complete', {
            body: JSON.stringify(authenticationData)
        });

        showStatus('authStatus', 'Authentication completed successfully!', 'success', result);

        // Update current user info if we have it
        if (result.user) {
            currentUser = result.user;
        }
        updateUserInfo();

    } catch (error) {
        console.error('Authentication completion failed:', error);
        showStatus('authStatus', `Authentication completion failed: ${error.message}`, 'error');
    }
}

// User information
function updateUserInfo() {
    const userInfoDiv = document.getElementById('userInfo');

    if (currentUser) {
        userInfoDiv.innerHTML = `
            <div class="user-info">
                <h3>Current User</h3>
                <p><strong>Username:</strong> ${currentUser.username || 'N/A'}</p>
                <p><strong>Display Name:</strong> ${currentUser.displayName || currentUser.display_name || 'N/A'}</p>
                <p><strong>User ID:</strong> ${currentUser.id || 'N/A'}</p>
                ${currentUser.credentials ? `
                    <div class="credentials-list">
                        <p><strong>Credentials:</strong></p>
                        ${currentUser.credentials.map(cred => `
                            <div class="credential-item">ID: ${cred.id}</div>
                        `).join('')}
                    </div>
                ` : ''}
            </div>
        `;
        userInfoDiv.style.display = 'block';
    } else {
        userInfoDiv.style.display = 'none';
    }
}

async function getUserInfo() {
    setLoading('getUserInfoBtn', true);

    try {
        // Try to get user info from the server
        const userInfo = await apiRequest('/oauth2/user', { method: 'GET' });
        currentUser = userInfo;
        updateUserInfo();
        showStatus('debugStatus', 'User info retrieved successfully', 'success', userInfo);
    } catch (error) {
        showStatus('debugStatus', `Failed to get user info: ${error.message}`, 'warning');
        updateUserInfo(); // Still update with local info if available
    } finally {
        setLoading('getUserInfoBtn', false);
    }
}

// Debug functions
function checkWebAuthnSupport() {
    setLoading('checkSupportBtn', true);

    const support = {
        webauthn: !!window.PublicKeyCredential,
        platform: false,
        crossPlatform: false,
        conditionalMediation: false,
        userAgent: navigator.userAgent,
        location: window.location.origin
    };

    const checks = [];

    if (window.PublicKeyCredential) {
        checks.push(
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
                .then(available => support.platform = available),
            PublicKeyCredential.isConditionalMediationAvailable?.()
                .then(available => support.conditionalMediation = available)
                .catch(() => support.conditionalMediation = false)
        );
    }

    Promise.all(checks).then(() => {
        const message = support.webauthn
            ? 'WebAuthn is supported!'
            : 'WebAuthn is not supported in this browser';

        const type = support.webauthn ? 'success' : 'error';

        // Add additional password manager detection hints
        const pmHints = [];
        if (support.crossPlatform !== false) pmHints.push('Cross-platform authenticators supported');
        if (support.conditionalMediation) pmHints.push('Conditional mediation available (good for password managers)');
        if (window.location.protocol === 'https:') pmHints.push('HTTPS detected (required for passkeys)');
        else pmHints.push('⚠️ HTTP detected - passkeys require HTTPS in production');

        const extendedMessage = message + '\n\nPassword Manager Compatibility:\n' + pmHints.join('\n');

        showStatus('debugStatus', extendedMessage, type, support);
    }).finally(() => {
        setLoading('checkSupportBtn', false);
    });
}

async function testPasswordManagerDetection() {
    setLoading('testPMDetectionBtn', true);

    try {
        showStatus('debugStatus', 'Testing password manager detection...', 'info');

        // Create a minimal test credential request to see if password managers respond
        const testOptions = {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rp: {
                name: "Test for Password Manager",
                id: window.location.hostname
            },
            user: {
                id: crypto.getRandomValues(new Uint8Array(16)),
                name: "test@example.com",
                displayName: "Password Manager Test"
            },
            pubKeyCredParams: [
                { alg: -7, type: "public-key" }, // ES256
                { alg: -257, type: "public-key" } // RS256
            ],
            authenticatorSelection: {
                authenticatorAttachment: "cross-platform",
                userVerification: "preferred",
                requireResidentKey: true,
                residentKey: "preferred"
            },
            attestation: "none",
            timeout: 30000 // Short timeout for test
        };

        console.log('Testing with minimal options:', testOptions);

        // Try to create a test credential
        const testCredential = await navigator.credentials.create({
            publicKey: testOptions
        });

        if (testCredential) {
            showStatus('debugStatus', '✅ Password manager responded to test! This looks promising for actual registration.', 'success');
        } else {
            showStatus('debugStatus', '⚠️ No response from password manager in test.', 'warning');
        }

    } catch (error) {
        let message = '❌ Password manager test failed: ' + error.message;

        if (error.name === 'AbortError') {
            message += '\n\nThis might mean: User cancelled or no password manager available.';
        } else if (error.name === 'NotSupportedError') {
            message += '\n\nThis might mean: WebAuthn not supported or specific options not supported.';
        } else if (error.name === 'SecurityError') {
            message += '\n\nThis might mean: HTTPS required or domain mismatch.';
        }

        showStatus('debugStatus', message, 'warning');
    } finally {
        setLoading('testPMDetectionBtn', false);
    }
}

function clearTestData() {
    currentUser = null;
    registrationOptions = null;
    authenticationOptions = null;

    // Clear form fields
    document.getElementById('registerUsername').value = 'testuser';
    document.getElementById('registerDisplayName').value = 'Test User';
    document.getElementById('authUsername').value = '';
    document.getElementById('authUserData').value = '';

    // Clear stored user data
    localStorage.removeItem('passkey_user_data');

    // Hide all status messages
    hideStatus('registerStatus');
    hideStatus('authStatus');
    hideStatus('debugStatus');
    updateUserInfo();

    showStatus('debugStatus', 'Test data cleared (including stored user data)', 'info');
}

// Usernameless authentication using discoverable credentials
async function startUsernamelessAuthentication() {
    setLoading('authUsernamelessBtn', true);
    hideStatus('authStatus');

    try {
        showStatus('authStatus', 'Starting usernameless authentication...', 'info');

        // Request authentication options without specifying a user
        const options = await apiRequest('/oauth2/passkey/auth/start', {
            body: JSON.stringify({}) // Empty body - no username specified
        });

        authenticationOptions = options;
        showStatus('authStatus', 'Authentication options received, presenting credentials...', 'info', options);

        // Debug: Check if challenge exists
        if (!options.request_options || !options.request_options.publicKey || !options.request_options.publicKey.challenge) {
            throw new Error('Invalid response: missing challenge in request options');
        }

        // Convert challenge from base64url to ArrayBuffer
        options.request_options.publicKey.challenge = base64urlToBuffer(options.request_options.publicKey.challenge);

        // For usernameless auth, we don't set allowCredentials - this allows
        // the authenticator to present all discoverable credentials for this domain
        delete options.request_options.publicKey.allowCredentials;

        // Enhance options for discoverable credential authentication
        options.request_options.publicKey.userVerification = "required"; // Require user verification for security
        options.request_options.publicKey.timeout = 120000; // 2 minutes max

        console.log('Getting discoverable credential with options:', options.request_options.publicKey);

        // Get the credential - the authenticator will present available credentials
        const credential = await navigator.credentials.get({
            publicKey: options.request_options.publicKey,
            mediation: 'optional' // Allow the authenticator to show credential picker
        });

        if (!credential) {
            throw new Error('No credential was returned - user may have cancelled or no passkeys available');
        }

        showStatus('authStatus', 'Credential obtained, completing authentication...', 'info');

        // Complete authentication with the discovered credential
        await completeUsernamelessAuthentication(credential);

    } catch (error) {
        console.error('Usernameless authentication failed:', error);
        let errorMessage = `Usernameless authentication failed: ${error.message}`;

        if (error.name === 'NotAllowedError') {
            errorMessage += '\n\nThis might mean: No passkeys available for this site, user cancelled, or operation timed out.';
        } else if (error.name === 'SecurityError') {
            errorMessage += '\n\nThis might mean: HTTPS required or domain mismatch.';
        }

        showStatus('authStatus', errorMessage, 'error');
    } finally {
        setLoading('authUsernamelessBtn', false);
    }
}

async function completeUsernamelessAuthentication(credential) {
    try {
        const authenticationData = {
            credential_response: {
                id: credential.id,
                rawId: bufferToBase64url(credential.rawId),
                response: {
                    authenticatorData: bufferToBase64url(credential.response.authenticatorData),
                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                    signature: bufferToBase64url(credential.response.signature),
                    userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null
                },
                type: credential.type
            },
            authentication_state: authenticationOptions.authentication_state,
            // For usernameless auth, we don't need user_data - the credential contains the user info
            user_data: null
        };

        const result = await apiRequest('/oauth2/passkey/auth/complete', {
            body: JSON.stringify(authenticationData)
        });

        showStatus('authStatus', 'Usernameless authentication completed successfully!', 'success', result);

        // Update current user info if we have it
        if (result.user) {
            currentUser = result.user;
        }
        updateUserInfo();

    } catch (error) {
        console.error('Usernameless authentication completion failed:', error);
        showStatus('authStatus', `Usernameless authentication completion failed: ${error.message}`, 'error');
    }
}

// Event listeners
document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('registerBtn').addEventListener('click', startRegistration);
    document.getElementById('authBtn').addEventListener('click', startAuthentication);
    document.getElementById('authUsernamelessBtn').addEventListener('click', startUsernamelessAuthentication);
    document.getElementById('getUserInfoBtn').addEventListener('click', getUserInfo);
    document.getElementById('checkSupportBtn').addEventListener('click', checkWebAuthnSupport);
    document.getElementById('testPMDetectionBtn').addEventListener('click', testPasswordManagerDetection);
    document.getElementById('clearDataBtn').addEventListener('click', clearTestData);
    document.getElementById('usernamelessAuthBtn').addEventListener('click', startUsernamelessAuthentication);

    // Load stored user data if available
    const storedUserData = localStorage.getItem('passkey_user_data');
    if (storedUserData) {
        document.getElementById('authUserData').value = storedUserData;
        showStatus('debugStatus', 'Loaded stored user data for authentication', 'info');
    }

    // Check WebAuthn support on load
    checkWebAuthnSupport();
});
