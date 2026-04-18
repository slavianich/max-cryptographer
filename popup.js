// Cryptography parameters required by the task.
const PBKDF2_ITERATIONS = 150000; // >= 100000
const SALT_LENGTH = 16;
const NONCE_LENGTH = 12;
const AES_KEY_LENGTH = 256;

let currentMode = 'encrypt';

const encryptTab = document.getElementById('encryptTab');
const decryptTab = document.getElementById('decryptTab');
const inputText = document.getElementById('inputText');
const passwordInput = document.getElementById('password');
const outputText = document.getElementById('outputText');
const actionButton = document.getElementById('actionButton');
const statusEl = document.getElementById('status');

encryptTab.addEventListener('click', () => setMode('encrypt'));
decryptTab.addEventListener('click', () => setMode('decrypt'));
actionButton.addEventListener('click', onAction);

function setMode(mode) {
  currentMode = mode;
  const encryptActive = mode === 'encrypt';

  encryptTab.classList.toggle('active', encryptActive);
  decryptTab.classList.toggle('active', !encryptActive);
  encryptTab.setAttribute('aria-selected', String(encryptActive));
  decryptTab.setAttribute('aria-selected', String(!encryptActive));
  actionButton.textContent = encryptActive ? 'Encrypt' : 'Decrypt';
  clearStatus();
}

async function onAction() {
  clearStatus();

  const payload = inputText.value;
  const password = passwordInput.value;

  if (!payload || !password) {
    setStatus('Input and password are required', true);
    return;
  }

  actionButton.disabled = true;

  try {
    if (currentMode === 'encrypt') {
      const result = await encryptText(payload, password);
      outputText.value = result;
      setStatus('Encryption successful', false);
    } else {
      const result = await decryptText(payload, password);
      outputText.value = result;
      setStatus('Decryption successful', false);
    }
  } catch (error) {
    // Required behavior: wrong password or malformed input should produce this message.
    if (currentMode === 'decrypt') {
      setStatus('Decryption failed', true);
    } else {
      setStatus('Encryption failed', true);
    }
  } finally {
    actionButton.disabled = false;
  }
}

async function encryptText(plainText, password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));

  const key = await deriveKey(password, salt);
  const data = encoder.encode(plainText);

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    data
  );

  // Output format: base64(salt + nonce + ciphertext)
  const packed = concatUint8Arrays(salt, nonce, new Uint8Array(cipherBuffer));
  return uint8ToBase64(packed);
}

async function decryptText(encodedInput, password) {
  const decoder = new TextDecoder();
  const packed = base64ToUint8(encodedInput.trim());

  if (packed.length <= SALT_LENGTH + NONCE_LENGTH) {
    throw new Error('Invalid payload length');
  }

  const salt = packed.slice(0, SALT_LENGTH);
  const nonce = packed.slice(SALT_LENGTH, SALT_LENGTH + NONCE_LENGTH);
  const ciphertext = packed.slice(SALT_LENGTH + NONCE_LENGTH);

  const key = await deriveKey(password, salt);
  const plainBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    ciphertext
  );

  return decoder.decode(plainBuffer);
}

async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    passwordKey,
    { name: 'AES-GCM', length: AES_KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

function concatUint8Arrays(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;

  for (const arr of arrays) {
    combined.set(arr, offset);
    offset += arr.length;
  }

  return combined;
}

function uint8ToBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary);
}

function base64ToUint8(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function setStatus(message, isError) {
  statusEl.textContent = message;
  statusEl.classList.toggle('error', isError);
  statusEl.classList.toggle('ok', !isError);
}

function clearStatus() {
  statusEl.textContent = '';
  statusEl.classList.remove('error', 'ok');
}
