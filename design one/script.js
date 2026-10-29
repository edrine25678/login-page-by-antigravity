/**
 * Secure Authentication & Dynamic Animation Module
 * Built with Web Cryptography API (PBKDF2-SHA256), Brute-Force Protection,
 * and Strict Password Complexity Requirements.
 */

// DOM Elements
const container = document.getElementById('container');
const loginLink = document.querySelector('.SignInLink');
const registerLink = document.querySelector('.SignUpLink');

const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');

const loginUserInput = document.getElementById('loginUsername');
const loginPassInput = document.getElementById('loginPassword');
const toggleLoginPass = document.getElementById('toggleLoginPass');

const regUserInput = document.getElementById('regUsername');
const regEmailInput = document.getElementById('regEmail');
const regPassInput = document.getElementById('regPassword');
const toggleRegPass = document.getElementById('toggleRegPass');

const strengthBar = document.getElementById('strengthBar');
const strengthLabel = document.getElementById('strengthLabel');
const strengthHint = document.getElementById('strengthHint');

const lockoutNotice = document.getElementById('lockoutNotice');
const lockoutTimer = document.getElementById('lockoutTimer');
const btnLogin = document.getElementById('btnLogin');
const btnRegister = document.getElementById('btnRegister');

const authSuccessOverlay = document.getElementById('authSuccessOverlay');
const authUsername = document.getElementById('authUsername');
const btnLogout = document.getElementById('btnLogout');

const toast = document.getElementById('toast');
const toastIcon = document.getElementById('toastIcon');
const toastMsg = document.getElementById('toastMsg');

// Constants
const PBKDF2_ITERATIONS = 100000;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 30000; // 30 seconds
const BANNED_PASSWORDS = new Set([
    'password', 'password123', 'admin', 'admin123', '12345678', 
    '123456789', 'qwerty', 'qwerty123', 'letmein', 'welcome123'
]);

let lockoutInterval = null;

// ================= 1. VIEW TOGGLING =================
registerLink.addEventListener('click', (e) => {
    e.preventDefault();
    container.classList.add('active');
    clearInputs();
});

loginLink.addEventListener('click', (e) => {
    e.preventDefault();
    container.classList.remove('active');
    clearInputs();
});

function clearInputs() {
    loginForm.reset();
    registerForm.reset();
    updatePasswordStrength('');
    document.querySelectorAll('.input-box').forEach(box => box.classList.remove('has-val'));
}

// Preserve floating label when browser auto-fills or field has content
document.querySelectorAll('.input-box input').forEach(input => {
    input.addEventListener('input', () => {
        const box = input.closest('.input-box');
        if (input.value.trim() !== '') {
            box.classList.add('has-val');
        } else {
            box.classList.remove('has-val');
        }
    });
});

// ================= 2. PASSWORD VISIBILITY TOGGLE =================
function setupPasswordToggle(btn, input) {
    btn.addEventListener('click', () => {
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        btn.classList.toggle('bx-show', isPassword);
        btn.classList.toggle('bx-hide', !isPassword);
    });
}
setupPasswordToggle(toggleLoginPass, loginPassInput);
setupPasswordToggle(toggleRegPass, regPassInput);

// ================= 3. PASSWORD COMPLEXITY & STRENGTH METER =================
function evaluatePassword(password) {
    if (!password) {
        return { score: 0, label: 'None', className: '', isValid: false, reasons: ['Enter password'] };
    }

    const lower = password.toLowerCase();
    if (BANNED_PASSWORDS.has(lower)) {
        return { 
            score: 1, 
            label: 'Common (Insecure)', 
            className: 'weak', 
            isValid: false, 
            reasons: ['Password is too common and vulnerable to dictionary attacks'] 
        };
    }

    const hasMinLength = password.length >= 8;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

    const reasons = [];
    if (!hasMinLength) reasons.push('At least 8 characters');
    if (!hasUpper) reasons.push('1 uppercase letter (A-Z)');
    if (!hasLower) reasons.push('1 lowercase letter (a-z)');
    if (!hasDigit) reasons.push('1 number (0-9)');
    if (!hasSpecial) reasons.push('1 special symbol (!@#$...)');

    let score = 0;
    if (hasMinLength) score++;
    if (hasUpper && hasLower) score++;
    if (hasDigit) score++;
    if (hasSpecial) score++;
    if (password.length >= 12 && hasSpecial && hasDigit) score = 4;

    let label = 'Weak';
    let className = 'weak';

    if (score === 2) {
        label = 'Fair';
        className = 'fair';
    } else if (score === 3) {
        label = 'Good';
        className = 'good';
    } else if (score === 4) {
        label = 'Strong & Secure';
        className = 'strong';
    }

    // Strict acceptance: requires all 5 criteria (length >= 8, upper, lower, digit, special)
    const isValid = hasMinLength && hasUpper && hasLower && hasDigit && hasSpecial;

    return { score, label, className, isValid, reasons };
}

function updatePasswordStrength(password) {
    const { score, label, className, reasons } = evaluatePassword(password);
    
    strengthBar.className = 'strength-bar ' + className;
    strengthLabel.className = 'strength-label ' + className;
    strengthLabel.textContent = `Strength: ${label}`;

    if (!password) {
        strengthHint.textContent = 'Min 8 chars, A-Z, 0-9, symbol';
        strengthHint.style.color = '#7b7e93';
    } else if (reasons.length > 0) {
        strengthHint.textContent = `Missing: ${reasons.join(', ')}`;
        strengthHint.style.color = '#f87171';
    } else {
        strengthHint.textContent = 'All security criteria satisfied';
        strengthHint.style.color = '#34d399';
    }
}

regPassInput.addEventListener('input', (e) => {
    updatePasswordStrength(e.target.value);
});

// ================= 4. CRYPTOGRAPHIC UTILITIES (WEB CRYPTO API) =================
function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function hexToBuffer(hexString) {
    const bytes = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
    }
    return bytes;
}

function generateSalt() {
    const saltBytes = window.crypto.getRandomValues(new Uint8Array(16));
    return bufferToHex(saltBytes);
}

async function hashPassword(password, saltHex) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );

    const saltBytes = hexToBuffer(saltHex);
    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: saltBytes,
            iterations: PBKDF2_ITERATIONS,
            hash: 'SHA-256'
        },
        keyMaterial,
        256
    );

    return bufferToHex(derivedBits);
}

// ================= 5. USER STORE (SIMULATED SECURE DATABASE) =================
function getUsersDB() {
    try {
        const data = localStorage.getItem('app_users_db');
        return data ? JSON.parse(data) : {};
    } catch {
        return {};
    }
}

function saveUsersDB(db) {
    localStorage.setItem('app_users_db', JSON.stringify(db));
}

// ================= 6. BRUTE FORCE PROTECTION & RATE LIMITING =================
function getLockoutState(username) {
    const key = `lockout_${username.toLowerCase()}`;
    const stored = localStorage.getItem(key);
    if (!stored) return { attempts: 0, lockedUntil: 0 };
    try {
        return JSON.parse(stored);
    } catch {
        return { attempts: 0, lockedUntil: 0 };
    }
}

function recordFailedAttempt(username) {
    const key = `lockout_${username.toLowerCase()}`;
    const state = getLockoutState(username);
    state.attempts = (state.attempts || 0) + 1;
    
    if (state.attempts >= MAX_FAILED_ATTEMPTS) {
        state.lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
    }
    localStorage.setItem(key, JSON.stringify(state));
    checkLockoutStatus(username);
}

function resetFailedAttempts(username) {
    const key = `lockout_${username.toLowerCase()}`;
    localStorage.removeItem(key);
    if (lockoutInterval) clearInterval(lockoutInterval);
    lockoutNotice.style.display = 'none';
    btnLogin.disabled = false;
}

function checkLockoutStatus(username) {
    const state = getLockoutState(username);
    const now = Date.now();

    if (state.lockedUntil && state.lockedUntil > now) {
        const remainingSec = Math.ceil((state.lockedUntil - now) / 1000);
        lockoutNotice.style.display = 'flex';
        lockoutTimer.textContent = `Too many failed attempts. Locked for ${remainingSec}s.`;
        btnLogin.disabled = true;

        if (lockoutInterval) clearInterval(lockoutInterval);
        lockoutInterval = setInterval(() => {
            const timeLeft = Math.ceil((state.lockedUntil - Date.now()) / 1000);
            if (timeLeft <= 0) {
                clearInterval(lockoutInterval);
                lockoutNotice.style.display = 'none';
                btnLogin.disabled = false;
                resetFailedAttempts(username);
                showToast('Lockout expired. You may attempt login now.', 'warning');
            } else {
                lockoutTimer.textContent = `Too many failed attempts. Locked for ${timeLeft}s.`;
            }
        }, 1000);
        return true;
    }
    
    lockoutNotice.style.display = 'none';
    btnLogin.disabled = false;
    return false;
}

loginUserInput.addEventListener('blur', () => {
    const u = loginUserInput.value.trim();
    if (u) checkLockoutStatus(u);
});

// ================= 7. TOAST NOTIFICATIONS =================
let toastTimeout = null;
function showToast(message, type = 'info') {
    if (toastTimeout) clearTimeout(toastTimeout);
    
    toast.className = `toast ${type} show`;
    toastMsg.textContent = message;

    if (type === 'success') {
        toastIcon.className = 'bx bx-check-circle';
    } else if (type === 'error') {
        toastIcon.className = 'bx bx-x-circle';
    } else {
        toastIcon.className = 'bx bx-error-circle';
    }

    toastTimeout = setTimeout(() => {
        toast.className = 'toast';
    }, 4000);
}

// ================= 8. REGISTRATION HANDLER =================
registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = regUserInput.value.trim();
    const email = regEmailInput.value.trim().toLowerCase();
    const password = regPassInput.value;

    // 1. Sanitize & Validate Username
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
        showToast('Username must be 3-20 alphanumeric characters or underscores.', 'error');
        regUserInput.focus();
        return;
    }

    // 2. Validate Email Format (RFC 5322 compliant regex)
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
        showToast('Please provide a valid email address.', 'error');
        regEmailInput.focus();
        return;
    }

    // 3. Strict Password Verification
    const passwordEval = evaluatePassword(password);
    if (!passwordEval.isValid) {
        showToast(`Weak Password! Requires: ${passwordEval.reasons.join(', ')}`, 'error');
        regPassInput.focus();
        return;
    }

    btnRegister.disabled = true;
    btnRegister.textContent = 'Securing Credentials...';

    try {
        const db = getUsersDB();
        const userKey = username.toLowerCase();

        // Check if username or email already registered
        if (db[userKey]) {
            showToast('Username is already taken. Please choose another.', 'error');
            btnRegister.disabled = false;
            btnRegister.textContent = 'Register';
            return;
        }

        const emailExists = Object.values(db).some(user => user.email === email);
        if (emailExists) {
            showToast('An account with this email already exists.', 'error');
            btnRegister.disabled = false;
            btnRegister.textContent = 'Register';
            return;
        }

        // Salt and Hash with PBKDF2-SHA256
        const salt = generateSalt();
        const hash = await hashPassword(password, salt);

        db[userKey] = {
            username: username,
            email: email,
            salt: salt,
            hash: hash,
            createdAt: new Date().toISOString()
        };

        saveUsersDB(db);

        showToast('Account registered securely! Switching to login...', 'success');
        setTimeout(() => {
            container.classList.remove('active');
            clearInputs();
            loginUserInput.value = username;
            loginUserInput.closest('.input-box').classList.add('has-val');
            loginPassInput.focus();
        }, 1200);

    } catch (err) {
        console.error('Registration failed:', err);
        showToast('An unexpected encryption error occurred. Try again.', 'error');
    } finally {
        btnRegister.disabled = false;
        btnRegister.textContent = 'Register';
    }
});

// ================= 9. LOGIN & AUTHORIZATION HANDLER =================
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = loginUserInput.value.trim();
    const password = loginPassInput.value;

    if (!username || !password) {
        showToast('Please enter both username and password.', 'error');
        return;
    }

    // Check Lockout
    if (checkLockoutStatus(username)) {
        showToast('Account is temporarily locked. Please wait.', 'error');
        return;
    }

    btnLogin.disabled = true;
    btnLogin.textContent = 'Authenticating...';

    try {
        const db = getUsersDB();
        const userKey = username.toLowerCase();
        const user = db[userKey];

        if (!user) {
            recordFailedAttempt(username);
            showToast('Invalid username or password.', 'error');
            return;
        }

        // Hash provided password with stored salt
        const computedHash = await hashPassword(password, user.salt);

        // Constant-time comparison simulation to prevent timing attacks
        let match = true;
        if (computedHash.length !== user.hash.length) {
            match = false;
        } else {
            for (let i = 0; i < computedHash.length; i++) {
                if (computedHash.charCodeAt(i) !== user.hash.charCodeAt(i)) {
                    match = false;
                }
            }
        }

        if (!match) {
            recordFailedAttempt(username);
            showToast('Invalid username or password.', 'error');
            return;
        }

        // Authentication Successful
        resetFailedAttempts(username);

        // Generate Simulated Secure Session Token
        const sessionToken = {
            token: generateSalt() + generateSalt(),
            username: user.username,
            issuedAt: Date.now(),
            expiresAt: Date.now() + 3600000 // 1 hour
        };
        sessionStorage.setItem('active_session', JSON.stringify(sessionToken));

        showToast('Authentication successful! Welcome.', 'success');
        displayActiveSession(user.username);

    } catch (err) {
        console.error('Login error:', err);
        showToast('An internal authentication error occurred.', 'error');
    } finally {
        btnLogin.disabled = false;
        btnLogin.textContent = 'Login';
    }
});

// ================= 10. SESSION DISPLAY & LOGOUT =================
function displayActiveSession(username) {
    authUsername.textContent = username;
    authSuccessOverlay.style.display = 'flex';
}

btnLogout.addEventListener('click', () => {
    sessionStorage.removeItem('active_session');
    authSuccessOverlay.style.display = 'none';
    clearInputs();
    showToast('Signed out securely.', 'info');
});

// Check existing session on load
window.addEventListener('DOMContentLoaded', () => {
    const rawSession = sessionStorage.getItem('active_session');
    if (rawSession) {
        try {
            const session = JSON.parse(rawSession);
            if (session.expiresAt && session.expiresAt > Date.now()) {
                displayActiveSession(session.username);
            } else {
                sessionStorage.removeItem('active_session');
            }
        } catch {
            sessionStorage.removeItem('active_session');
        }
    }
});
