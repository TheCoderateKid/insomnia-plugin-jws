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
 * Sign data using the specified algorithm and key
 */
function sign(algorithm, key, data) {
  const cryptoAlg = getCryptoAlgorithm(algorithm);
  const normalizedKey = normalizeKey(key);

  // HMAC algorithms
  if (algorithm.startsWith('HS')) {
    const hmac = crypto.createHmac(cryptoAlg, normalizedKey);
    hmac.update(data);
    return hmac.digest();
  }

  // RSA algorithms
  if (algorithm.startsWith('RS')) {
    const signer = crypto.createSign(cryptoAlg);
    signer.update(data);
    return signer.sign(normalizedKey);
  }

  // RSA-PSS algorithms
  if (algorithm.startsWith('PS')) {
    const signer = crypto.createSign(cryptoAlg);
    signer.update(data);
    return signer.sign({
      key: normalizedKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });
  }

  // ECDSA algorithms
  if (algorithm.startsWith('ES')) {
    const signer = crypto.createSign(cryptoAlg);
    signer.update(data);
    const derSignature = signer.sign(normalizedKey);
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
  const signature = sign(algorithm, privateKey, signingInput);
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
        displayName: 'Private Key (PEM) or Secret',
        description: 'Private key in PEM format for RSA/ECDSA, or secret for HMAC. Can use environment variable.',
        type: 'string',
        placeholder: '-----BEGIN PRIVATE KEY-----\n...',
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

    // Get request body
    const body = request.getBody();
    const payload = body.text || '';

    // Generate signature
    const signature = generateJws({
      algorithm: config.algorithm || 'RS256',
      payload,
      privateKey,
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

      const privateKey = await app.prompt('Private Key / Secret', {
        label: 'Enter your private key (PEM) or HMAC secret',
        inputType: 'textarea',
      });

      if (!privateKey) return;

      const headerName = await app.prompt('Header Name', {
        defaultValue: 'X-JWS-Signature',
        label: 'HTTP header name for the signature',
      });

      const keyId = await app.prompt('Key ID (optional)', {
        label: 'Optional key identifier',
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

      await app.alert('Success', 'JWS auto-sign configured. Signatures will be added to requests automatically.');
    },
  },
  {
    label: 'Disable JWS Auto-Sign',
    icon: 'fa-times',
    action: async (context, _models) => {
      await context.store.removeItem('jws:autoSign');
      await context.store.removeItem('jws:privateKey');
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

