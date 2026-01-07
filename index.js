/**
 * JWSPlugin - Insomnia Plugin for JWS Signature Generation
 *
 * Supports:
 * - HMAC algorithms: HS256, HS384, HS512
 * - RSA algorithms: RS256, RS384, RS512, PS256, PS384, PS512
 * - ECDSA algorithms: ES256, ES384, ES512
 * - Detached payload mode (RFC 7515)
 * - Unencoded payload mode (RFC 7797)
 */

const crypto = require('crypto');

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Base64URL encode a string or buffer
 */
function base64UrlEncode(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buffer
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Base64URL decode a string
 */
function base64UrlDecode(input) {
  let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padding = base64.length % 4;
  if (padding) {
    base64 += '='.repeat(4 - padding);
  }
  return Buffer.from(base64, 'base64');
}

/**
 * Get the crypto algorithm name from JWS algorithm
 */
function getCryptoAlgorithm(jwsAlgorithm) {
  const mapping = {
    'HS256': 'sha256',
    'HS384': 'sha384',
    'HS512': 'sha512',
    'RS256': 'RSA-SHA256',
    'RS384': 'RSA-SHA384',
    'RS512': 'RSA-SHA512',
    'PS256': 'RSA-SHA256',
    'PS384': 'RSA-SHA384',
    'PS512': 'RSA-SHA512',
    'ES256': 'SHA256',
    'ES384': 'SHA384',
    'ES512': 'SHA512',
  };
  return mapping[jwsAlgorithm];
}

/**
 * Convert DER signature to JWS format for ECDSA
 */
function derToJws(derSignature, algorithm) {
  const componentLength = {
    'ES256': 32,
    'ES384': 48,
    'ES512': 66,
  }[algorithm];

  // Parse DER signature
  let offset = 2;
  if (derSignature[1] & 0x80) {
    offset += (derSignature[1] & 0x7f);
  }

  // Extract R
  const rLength = derSignature[offset + 1];
  let r = derSignature.slice(offset + 2, offset + 2 + rLength);
  offset += 2 + rLength;

  // Extract S
  const sLength = derSignature[offset + 1];
  let s = derSignature.slice(offset + 2, offset + 2 + sLength);

  // Remove leading zeros and pad to component length
  while (r.length > componentLength && r[0] === 0) r = r.slice(1);
  while (s.length > componentLength && s[0] === 0) s = s.slice(1);

  const rPadded = Buffer.alloc(componentLength);
  const sPadded = Buffer.alloc(componentLength);
  r.copy(rPadded, componentLength - r.length);
  s.copy(sPadded, componentLength - s.length);

  return Buffer.concat([rPadded, sPadded]);
}

/**
 * Normalize a PEM key by converting literal \n to actual newlines
 */
function normalizeKey(key) {
  if (!key) return key;
  return key.replace(/\\n/g, '\n');
}

/**
 * Check if the input looks like a file path to a keystore
 */
function isKeystorePath(input) {
  if (!input) return false;
  const normalized = input.trim();
  // Check for common keystore extensions
  if (normalized.endsWith('.p12') || normalized.endsWith('.pfx')) return true;
  // Check for absolute paths with keystore extensions
  if ((normalized.startsWith('/') || normalized.startsWith('~') || /^[A-Za-z]:[\\/]/.test(normalized)) &&
      (normalized.includes('.p12') || normalized.includes('.pfx'))) return true;
  return false;
}

/**
 * Check if the input looks like a PKCS#12 keystore (base64-encoded binary)
 * Kept for backwards compatibility
 */
function isPkcs12(input) {
  if (!input) return false;
  const normalized = input.trim();
  // PEM keys start with -----BEGIN
  if (normalized.startsWith('-----BEGIN')) return false;
  // File paths are handled separately
  if (isKeystorePath(normalized)) return false;
  // Check if it's valid base64 and reasonably long (keystores are usually > 1KB)
  try {
    const decoded = Buffer.from(normalized, 'base64');
    return decoded.length > 500 && normalized.length > 100;
  } catch {
    return false;
  }
}

/**
 * Read keystore from file path
 */
function readKeystoreFile(filePath) {
  const fs = require('fs');
  const path = require('path');

  // Expand ~ to home directory
  let resolvedPath = filePath.trim();
  if (resolvedPath.startsWith('~')) {
    const homedir = require('os').homedir();
    resolvedPath = path.join(homedir, resolvedPath.slice(1));
  }

  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Keystore file not found: ${resolvedPath}`);
  }

  return fs.readFileSync(resolvedPath);
}

/**
 * Extract private key from PKCS#12 keystore
 */
function extractKeyFromPkcs12(p12Data, password, keyAlias) {
  let forge;
  try {
    forge = require('node-forge');
  } catch (e) {
    throw new Error('PKCS#12 keystore support requires node-forge. Run: npm install node-forge');
  }

  try {
    // Handle both Buffer and base64 string input
    let p12Der;
    if (Buffer.isBuffer(p12Data)) {
      p12Der = p12Data.toString('binary');
    } else {
      p12Der = forge.util.decode64(p12Data);
    }

    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password || '');

    // Find the private key - try by alias first if provided
    let privateKey = null;

    // Get all bags
    const bags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    const keyBags = bags[forge.pki.oids.pkcs8ShroudedKeyBag] || [];

    // Also check unencrypted key bags
    const bags2 = p12.getBags({ bagType: forge.pki.oids.keyBag });
    const keyBags2 = bags2[forge.pki.oids.keyBag] || [];

    const allKeyBags = [...keyBags, ...keyBags2];

    if (allKeyBags.length === 0) {
      throw new Error('No private key found in keystore');
    }

    // If alias specified, find matching key
    if (keyAlias) {
      for (const bag of allKeyBags) {
        const bagAlias = bag.attributes?.friendlyName?.[0] ||
                         bag.attributes?.localKeyId?.[0];
        if (bagAlias === keyAlias) {
          privateKey = bag.key;
          break;
        }
      }
      if (!privateKey) {
        // List available aliases for helpful error
        const availableAliases = allKeyBags
          .map(b => b.attributes?.friendlyName?.[0] || b.attributes?.localKeyId?.[0])
          .filter(Boolean);
        throw new Error(`Key alias '${keyAlias}' not found. Available: ${availableAliases.join(', ') || '(none)'}`);
      }
    } else {
      // No alias specified - use first key
      privateKey = allKeyBags[0].key;
    }

    return forge.pki.privateKeyToPem(privateKey);
  } catch (e) {
    if (e.message.includes('Invalid password') || e.message.includes('PKCS#12 MAC')) {
      throw new Error('Invalid keystore password');
    }
    if (e.message.includes('Key alias')) {
      throw e;
    }
    throw new Error(`Failed to parse keystore: ${e.message}`);
  }
}

/**
 * Resolve the private key - handles PEM, PKCS#12 keystore file, or HMAC secret
 */
function resolvePrivateKey(keyInput, keystorePassword, keyAlias) {
  if (!keyInput) return keyInput;

  const trimmed = keyInput.trim();

  // Check if it's a keystore file path
  if (isKeystorePath(trimmed)) {
    const keystoreData = readKeystoreFile(trimmed);
    return extractKeyFromPkcs12(keystoreData, keystorePassword || '', keyAlias || '');
  }

  // Check if it's base64-encoded keystore (backwards compatibility)
  if (isPkcs12(trimmed)) {
    return extractKeyFromPkcs12(trimmed, keystorePassword || '', keyAlias || '');
  }

  // Otherwise treat as PEM key or HMAC secret
  return normalizeKey(trimmed);
}

/**
 * Sign data using the specified algorithm and key
 */
function sign(algorithm, key, data, keystorePassword, keyAlias) {
  const cryptoAlg = getCryptoAlgorithm(algorithm);
  const resolvedKey = resolvePrivateKey(key, keystorePassword, keyAlias);

  // HMAC algorithms
  if (algorithm.startsWith('HS')) {
    const hmac = crypto.createHmac(cryptoAlg, resolvedKey);
    hmac.update(data);
    return hmac.digest();
  }

  // RSA algorithms
  if (algorithm.startsWith('RS')) {
    const signer = crypto.createSign(cryptoAlg);
    signer.update(data);
    return signer.sign(resolvedKey);
  }

  // RSA-PSS algorithms
  if (algorithm.startsWith('PS')) {
    const signer = crypto.createSign(cryptoAlg);
    signer.update(data);
    return signer.sign({
      key: resolvedKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });
  }

  // ECDSA algorithms
  if (algorithm.startsWith('ES')) {
    const signer = crypto.createSign(cryptoAlg);
    signer.update(data);
    const derSignature = signer.sign(resolvedKey);
    return derToJws(derSignature, algorithm);
  }

  throw new Error(`Unsupported algorithm: ${algorithm}`);
}

/**
 * Generate a JWS signature
 */
function generateJws(options) {
  const {
    algorithm = 'RS256',
    payload,
    privateKey,
    keystorePassword,
    keyAlias,
    detached = true,
    unencoded = false,
    keyId,
    additionalHeaders = {},
  } = options;

  // Build JWS header
  const header = {
    alg: algorithm,
    typ: 'JWT',
    ...additionalHeaders,
  };

  // Add key ID if provided
  if (keyId) {
    header.kid = keyId;
  }

  // Handle unencoded payload (RFC 7797)
  if (unencoded) {
    header.b64 = false;
    header.crit = header.crit ? [...header.crit, 'b64'] : ['b64'];
  }

  // Encode header
  const encodedHeader = base64UrlEncode(JSON.stringify(header));

  // Encode or prepare payload
  let signaturePayload;
  if (unencoded) {
    signaturePayload = payload;
  } else {
    signaturePayload = base64UrlEncode(payload);
  }

  // Create signing input
  const signingInput = `${encodedHeader}.${signaturePayload}`;

  // Generate signature
  const signature = sign(algorithm, privateKey, signingInput, keystorePassword, keyAlias);
  const encodedSignature = base64UrlEncode(signature);

  // Return detached or compact serialization
  if (detached) {
    return `${encodedHeader}..${encodedSignature}`;
  } else {
    return `${encodedHeader}.${base64UrlEncode(payload)}.${encodedSignature}`;
  }
}

// =============================================================================
// INSOMNIA TEMPLATE TAG
// =============================================================================

module.exports.templateTags = [
  {
    name: 'jwsSignature',
    displayName: 'JWS Signature',
    description: 'Generate a JWS signature for the request payload',
    args: [
      {
        displayName: 'Algorithm',
        description: 'JWS signing algorithm',
        type: 'enum',
        defaultValue: 'RS256',
        options: [
          { displayName: 'HS256 (HMAC SHA-256)', value: 'HS256' },
          { displayName: 'HS384 (HMAC SHA-384)', value: 'HS384' },
          { displayName: 'HS512 (HMAC SHA-512)', value: 'HS512' },
          { displayName: 'RS256 (RSA SHA-256)', value: 'RS256' },
          { displayName: 'RS384 (RSA SHA-384)', value: 'RS384' },
          { displayName: 'RS512 (RSA SHA-512)', value: 'RS512' },
          { displayName: 'PS256 (RSA-PSS SHA-256)', value: 'PS256' },
          { displayName: 'PS384 (RSA-PSS SHA-384)', value: 'PS384' },
          { displayName: 'PS512 (RSA-PSS SHA-512)', value: 'PS512' },
          { displayName: 'ES256 (ECDSA P-256)', value: 'ES256' },
          { displayName: 'ES384 (ECDSA P-384)', value: 'ES384' },
          { displayName: 'ES512 (ECDSA P-521)', value: 'ES512' },
        ],
      },
      {
        displayName: 'Private Key / Keystore',
        description: 'PEM private key, HMAC secret, or path to PKCS#12 keystore (.p12/.pfx)',
        type: 'string',
        placeholder: '/path/to/keystore.p12',
      },
      {
        displayName: 'Keystore Password',
        description: 'Password for PKCS#12 keystore (leave empty if using PEM key)',
        type: 'string',
        placeholder: '{{ _.jws_keystore_password }}',
      },
      {
        displayName: 'Key Alias',
        description: 'Alias of the key in PKCS#12 keystore (leave empty to use first key)',
        type: 'string',
        placeholder: '{{ _.jws_key_alias }}',
      },
      {
        displayName: 'Payload Source',
        description: 'Where to get the payload from',
        type: 'enum',
        defaultValue: 'request_body',
        options: [
          { displayName: 'Request Body', value: 'request_body' },
          { displayName: 'Custom Value', value: 'custom' },
        ],
      },
      {
        displayName: 'Custom Payload',
        description: 'Custom payload (only used if Payload Source is "Custom Value")',
        type: 'string',
        placeholder: '{"data": "value"}',
      },
      {
        displayName: 'Detached Payload',
        description: 'Use detached payload mode (header..signature)',
        type: 'boolean',
        defaultValue: true,
      },
      {
        displayName: 'Unencoded Payload (RFC 7797)',
        description: 'Use unencoded payload for signature calculation',
        type: 'boolean',
        defaultValue: false,
      },
      {
        displayName: 'Key ID (kid)',
        description: 'Optional Key ID to include in JWS header',
        type: 'string',
        placeholder: 'my-key-id',
      },
      {
        displayName: 'Additional Headers (JSON)',
        description: 'Additional JWS header fields as JSON object',
        type: 'string',
        placeholder: '{"x5t": "..."}',
      },
    ],

    async run(
      context,
      algorithm,
      privateKey,
      keystorePassword,
      keyAlias,
      payloadSource,
      customPayload,
      detached,
      unencoded,
      keyId,
      additionalHeadersJson,
    ) {
      // Validate private key
      if (!privateKey || privateKey.trim() === '') {
        throw new Error('Private key or secret is required');
      }

      // Get payload
      let payload;
      if (payloadSource === 'request_body') {
        const request = context.request;
        if (request && request.getBody) {
          const body = request.getBody();
          payload = body.text || '';
        } else {
          payload = '';
        }
      } else {
        payload = customPayload || '';
      }

      // Parse additional headers
      let additionalHeaders = {};
      if (additionalHeadersJson && additionalHeadersJson.trim() !== '') {
        try {
          additionalHeaders = JSON.parse(additionalHeadersJson);
        } catch (e) {
          throw new Error(`Invalid additional headers JSON: ${e.message}`);
        }
      }

      // Generate JWS
      try {
        return generateJws({
          algorithm,
          payload,
          privateKey,
          keystorePassword: keystorePassword || undefined,
          keyAlias: keyAlias || undefined,
          detached,
          unencoded,
          keyId: keyId || undefined,
          additionalHeaders,
        });
      } catch (error) {
        throw new Error(`JWS generation failed: ${error.message}`);
      }
    },
  },
];

// =============================================================================
// REQUEST HOOK (Alternative method - auto-adds header)
// =============================================================================

module.exports.requestHooks = [
  async (context) => {
    const request = context.request;

    // Check if JWS auto-sign is enabled via environment variable
    const autoSign = await context.store.getItem('jws:autoSign');
    if (!autoSign) return;

    const config = JSON.parse(autoSign);

    // Get the signing key from environment
    const privateKey = await context.store.getItem('jws:privateKey');
    if (!privateKey) return;

    // Get keystore password and alias if stored
    const keystorePassword = await context.store.getItem('jws:keystorePassword');
    const keyAlias = await context.store.getItem('jws:keyAlias');

    // Get request body
    const body = request.getBody();
    const payload = body.text || '';

    // Generate signature
    const signature = generateJws({
      algorithm: config.algorithm || 'RS256',
      payload,
      privateKey,
      keystorePassword: keystorePassword || undefined,
      keyAlias: keyAlias || undefined,
      detached: config.detached !== false,
      unencoded: config.unencoded || false,
      keyId: config.keyId,
      additionalHeaders: config.additionalHeaders || {},
    });

    // Add header
    const headerName = config.headerName || 'X-JWS-Signature';
    request.setHeader(headerName, signature);
  },
];

// =============================================================================
// WORKSPACE ACTIONS (UI buttons)
// =============================================================================

module.exports.workspaceActions = [
  {
    label: 'Configure JWS Auto-Sign',
    icon: 'fa-key',
    action: async (context, _models) => {
      const { app } = context;

      // Prompt for configuration
      const algorithm = await app.prompt('JWS Algorithm', {
        defaultValue: 'RS256',
        label: 'Select algorithm (HS256, RS256, ES256, etc.)',
      });

      if (!algorithm) return;

      const privateKey = await app.prompt('Private Key / Keystore', {
        label: 'Enter PEM key, HMAC secret, or base64-encoded PKCS#12 keystore',
        inputType: 'textarea',
      });

      if (!privateKey) return;

      const keystorePassword = await app.prompt('Keystore Password (optional)', {
        label: 'Password for PKCS#12 keystore (leave empty for PEM keys)',
      });

      const keyAlias = await app.prompt('Key Alias (optional)', {
        label: 'Alias of key in keystore (leave empty to use first key)',
      });

      const headerName = await app.prompt('Header Name', {
        defaultValue: 'X-JWS-Signature',
        label: 'HTTP header name for the signature',
      });

      const keyId = await app.prompt('Key ID (optional)', {
        label: 'Optional key identifier for JWS header (kid)',
      });

      // Store configuration
      await context.store.setItem('jws:autoSign', JSON.stringify({
        algorithm,
        headerName: headerName || 'X-JWS-Signature',
        keyId: keyId || undefined,
        detached: true,
        unencoded: false,
      }));

      await context.store.setItem('jws:privateKey', privateKey);
      if (keystorePassword) {
        await context.store.setItem('jws:keystorePassword', keystorePassword);
      }
      if (keyAlias) {
        await context.store.setItem('jws:keyAlias', keyAlias);
      }

      await app.alert('Success', 'JWS auto-sign configured. Signatures will be added to requests automatically.');
    },
  },
  {
    label: 'Disable JWS Auto-Sign',
    icon: 'fa-times',
    action: async (context, _models) => {
      await context.store.removeItem('jws:autoSign');
      await context.store.removeItem('jws:privateKey');
      await context.store.removeItem('jws:keystorePassword');
      await context.store.removeItem('jws:keyAlias');
      await context.app.alert('Success', 'JWS auto-sign disabled.');
    },
  },
];

// =============================================================================
// EXPORT UTILITY FOR EXTERNAL USE
// =============================================================================

module.exports.generateJws = generateJws;
module.exports.base64UrlEncode = base64UrlEncode;
module.exports.base64UrlDecode = base64UrlDecode;

// Keystore utilities (exported for testing)
module.exports.isPkcs12 = isPkcs12;
module.exports.isKeystorePath = isKeystorePath;
module.exports.extractKeyFromPkcs12 = extractKeyFromPkcs12;
module.exports.readKeystoreFile = readKeystoreFile;
module.exports.resolvePrivateKey = resolvePrivateKey;
module.exports.normalizeKey = normalizeKey;


