/**
 * JWSPlugin Test Suite
 */

const crypto = require('crypto');
const plugin = require('../index');

// Test key fixtures
const testKeys = {
  // RSA 2048-bit key pair for testing
  rsaPrivate: `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7o5MFSJ5JXRkv
pxPF5v8KzZl7mGXcQNkLW8YIxMyUzdHcCTg9mTnR4KLtKPJbR5Y3wQCiVFxzgf3c
vwD3wvD5qNq0oJKqLWwEvMYV6WB5vDewSsJkWZFLwKJ6r0kZfPM5iPZ7VT8wVPBH
R0hhT3XEixcfR1E8OhD8nWvR7mXpVPUDxPZpHZ6oPbPXKV7+6D4w4QMrLPYT8XjF
xvP/B7P5aKjqNqy7jQz0F7Y3L7CifFQ6kkY3FxP6VvPt3M6OKf9+B4V3qdPxQzQP
VCPL9D5xM3GBJj0F6cXcM7xK0MZ/T4jH+5sKZRqnPq0xPF+8aQoA/Lz8T3x9K7j0
F0aY3aPNAgMBAAECggEAGZ2qAY0BJvz83G6XwpPxEJCnZ1VT8CfZQJfPbLw3qRqP
FxOF/PvCChe3M0OQJx3tPCnfLNbP0xKM6gVWDKJxhQ0zL5RL4YCFvVxK5M6Uxmh1
R9PFwHX9YDwM7wnYzJvK3G5Y6s0P9pXLJFwRNfHQf2eMNp0Y5vZhv0kT3P4VxaLi
8cQPYCOGWvz0fwvP5vFHq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3L
BxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3
LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxQKBgQDpwOH7bK3lRp0F5Y3L
BxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3
LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y
3LBxP8vP4xq5Y3LBxP8vP4xq5YwKBgQDNpL3l5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y
3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5
Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq
5Y3LBxP8vP4xq5YwKBgFHq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3
LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y
3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5Y3LBxP8vP4xq5
-----END PRIVATE KEY-----`,

  // HMAC secret for testing
  hmacSecret: 'test-secret-key-for-hmac-signing-minimum-256-bits',

  // EC P-256 key for testing
  ecPrivate: null, // Generated in beforeAll
};

// Generate EC key for tests
beforeAll(() => {
  const { privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  testKeys.ecPrivate = privateKey.export({ type: 'pkcs8', format: 'pem' });

  // Also generate a proper RSA key
  const rsaKeyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  testKeys.rsaPrivate = rsaKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  testKeys.rsaPublic = rsaKeyPair.publicKey.export({ type: 'spki', format: 'pem' });
});

describe('JWSPlugin', () => {
  describe('Module Exports', () => {
    test('should export templateTags array', () => {
      expect(plugin.templateTags).toBeDefined();
      expect(Array.isArray(plugin.templateTags)).toBe(true);
    });

    test('should export jwsSignature template tag', () => {
      const jwsTag = plugin.templateTags.find(t => t.name === 'jwsSignature');
      expect(jwsTag).toBeDefined();
      expect(jwsTag.displayName).toBe('JWS Signature');
    });

    test('should export requestHooks array', () => {
      expect(plugin.requestHooks).toBeDefined();
      expect(Array.isArray(plugin.requestHooks)).toBe(true);
    });

    test('should export workspaceActions array', () => {
      expect(plugin.workspaceActions).toBeDefined();
      expect(Array.isArray(plugin.workspaceActions)).toBe(true);
    });

    test('should export generateJws function', () => {
      expect(plugin.generateJws).toBeDefined();
      expect(typeof plugin.generateJws).toBe('function');
    });

    test('should export base64UrlEncode function', () => {
      expect(plugin.base64UrlEncode).toBeDefined();
      expect(typeof plugin.base64UrlEncode).toBe('function');
    });

    test('should export base64UrlDecode function', () => {
      expect(plugin.base64UrlDecode).toBeDefined();
      expect(typeof plugin.base64UrlDecode).toBe('function');
    });
  });

  describe('base64UrlEncode', () => {
    test('should encode string correctly', () => {
      const result = plugin.base64UrlEncode('hello world');
      expect(result).toBe('aGVsbG8gd29ybGQ');
    });

    test('should encode buffer correctly', () => {
      const result = plugin.base64UrlEncode(Buffer.from('hello world'));
      expect(result).toBe('aGVsbG8gd29ybGQ');
    });

    test('should not contain + or / or =', () => {
      // Test with data that would normally produce these characters
      const result = plugin.base64UrlEncode(Buffer.from([251, 255, 254, 253]));
      expect(result).not.toContain('+');
      expect(result).not.toContain('/');
      expect(result).not.toContain('=');
    });

    test('should handle empty input', () => {
      const result = plugin.base64UrlEncode('');
      expect(result).toBe('');
    });

    test('should handle JSON objects', () => {
      const obj = { alg: 'RS256', typ: 'JWT' };
      const result = plugin.base64UrlEncode(JSON.stringify(obj));
      expect(result).toBeTruthy();
      expect(result).not.toContain('=');
    });
  });

  describe('base64UrlDecode', () => {
    test('should decode string correctly', () => {
      const result = plugin.base64UrlDecode('aGVsbG8gd29ybGQ');
      expect(result.toString()).toBe('hello world');
    });

    test('should handle URL-safe characters', () => {
      const encoded = plugin.base64UrlEncode(Buffer.from([251, 255, 254, 253]));
      const decoded = plugin.base64UrlDecode(encoded);
      expect(decoded).toEqual(Buffer.from([251, 255, 254, 253]));
    });

    test('should be inverse of encode', () => {
      const original = 'test data 123!@#';
      const encoded = plugin.base64UrlEncode(original);
      const decoded = plugin.base64UrlDecode(encoded);
      expect(decoded.toString()).toBe(original);
    });
  });

  describe('generateJws', () => {
    describe('HMAC algorithms', () => {
      test('should generate HS256 signature', () => {
        const result = plugin.generateJws({
          algorithm: 'HS256',
          payload: '{"test": true}',
          privateKey: testKeys.hmacSecret,
          detached: false,
        });

        expect(result).toBeTruthy();
        const parts = result.split('.');
        expect(parts.length).toBe(3);
      });

      test('should generate HS384 signature', () => {
        const result = plugin.generateJws({
          algorithm: 'HS384',
          payload: '{"test": true}',
          privateKey: testKeys.hmacSecret,
          detached: false,
        });

        expect(result).toBeTruthy();
        const parts = result.split('.');
        expect(parts.length).toBe(3);
      });

      test('should generate HS512 signature', () => {
        const result = plugin.generateJws({
          algorithm: 'HS512',
          payload: '{"test": true}',
          privateKey: testKeys.hmacSecret,
          detached: false,
        });

        expect(result).toBeTruthy();
        const parts = result.split('.');
        expect(parts.length).toBe(3);
      });

      test('should produce consistent signatures for same input', () => {
        const options = {
          algorithm: 'HS256',
          payload: '{"test": true}',
          privateKey: testKeys.hmacSecret,
          detached: false,
        };

        const result1 = plugin.generateJws(options);
        const result2 = plugin.generateJws(options);

        expect(result1).toBe(result2);
      });
    });

    describe('RSA algorithms', () => {
      test('should generate RS256 signature', () => {
        const result = plugin.generateJws({
          algorithm: 'RS256',
          payload: '{"test": true}',
          privateKey: testKeys.rsaPrivate,
          detached: false,
        });

        expect(result).toBeTruthy();
        const parts = result.split('.');
        expect(parts.length).toBe(3);
      });

      test('should generate RS384 signature', () => {
        const result = plugin.generateJws({
          algorithm: 'RS384',
          payload: '{"test": true}',
          privateKey: testKeys.rsaPrivate,
          detached: false,
        });

        expect(result).toBeTruthy();
      });

      test('should generate RS512 signature', () => {
        const result = plugin.generateJws({
          algorithm: 'RS512',
          payload: '{"test": true}',
          privateKey: testKeys.rsaPrivate,
          detached: false,
        });

        expect(result).toBeTruthy();
      });

      test('should generate verifiable RS256 signature', () => {
        const payload = '{"test": true}';
        const result = plugin.generateJws({
          algorithm: 'RS256',
          payload,
          privateKey: testKeys.rsaPrivate,
          detached: false,
        });

        const parts = result.split('.');
        const signatureInput = `${parts[0]}.${parts[1]}`;
        const signature = plugin.base64UrlDecode(parts[2]);

        const verify = crypto.createVerify('RSA-SHA256');
        verify.update(signatureInput);
        const isValid = verify.verify(testKeys.rsaPublic, signature);

        expect(isValid).toBe(true);
      });
    });

    describe('RSA-PSS algorithms', () => {
      test('should generate PS256 signature', () => {
        const result = plugin.generateJws({
          algorithm: 'PS256',
          payload: '{"test": true}',
          privateKey: testKeys.rsaPrivate,
          detached: false,
        });

        expect(result).toBeTruthy();
        const parts = result.split('.');
        expect(parts.length).toBe(3);
      });

      test('should generate PS384 signature', () => {
        const result = plugin.generateJws({
          algorithm: 'PS384',
          payload: '{"test": true}',
          privateKey: testKeys.rsaPrivate,
          detached: false,
        });

        expect(result).toBeTruthy();
      });

      test('should generate PS512 signature', () => {
        const result = plugin.generateJws({
          algorithm: 'PS512',
          payload: '{"test": true}',
          privateKey: testKeys.rsaPrivate,
          detached: false,
        });

        expect(result).toBeTruthy();
      });
    });

    describe('ECDSA algorithms', () => {
      test('should generate ES256 signature', () => {
        const result = plugin.generateJws({
          algorithm: 'ES256',
          payload: '{"test": true}',
          privateKey: testKeys.ecPrivate,
          detached: false,
        });

        expect(result).toBeTruthy();
        const parts = result.split('.');
        expect(parts.length).toBe(3);

        // ES256 signature should be 64 bytes (32 + 32)
        const sigBytes = plugin.base64UrlDecode(parts[2]);
        expect(sigBytes.length).toBe(64);
      });
    });

    describe('Detached payload mode', () => {
      test('should generate detached JWS with empty payload section', () => {
        const result = plugin.generateJws({
          algorithm: 'HS256',
          payload: '{"test": true}',
          privateKey: testKeys.hmacSecret,
          detached: true,
        });

        const parts = result.split('.');
        expect(parts.length).toBe(3);
        expect(parts[1]).toBe(''); // Empty payload section
      });

      test('should have format header..signature', () => {
        const result = plugin.generateJws({
          algorithm: 'RS256',
          payload: '{"data": "value"}',
          privateKey: testKeys.rsaPrivate,
          detached: true,
        });

        expect(result).toMatch(/^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$/);
      });
    });

    describe('Unencoded payload mode (RFC 7797)', () => {
      test('should include b64 header when unencoded', () => {
        const result = plugin.generateJws({
          algorithm: 'HS256',
          payload: '{"test": true}',
          privateKey: testKeys.hmacSecret,
          detached: false,
          unencoded: true,
        });

        const parts = result.split('.');
        const header = JSON.parse(plugin.base64UrlDecode(parts[0]).toString());

        expect(header.b64).toBe(false);
        expect(header.crit).toContain('b64');
      });

      test('should work with detached and unencoded together', () => {
        const result = plugin.generateJws({
          algorithm: 'RS256',
          payload: '{"test": true}',
          privateKey: testKeys.rsaPrivate,
          detached: true,
          unencoded: true,
        });

        const parts = result.split('.');
        expect(parts[1]).toBe('');

        const header = JSON.parse(plugin.base64UrlDecode(parts[0]).toString());
        expect(header.b64).toBe(false);
      });
    });

    describe('Header options', () => {
      test('should include key ID when provided', () => {
        const result = plugin.generateJws({
          algorithm: 'HS256',
          payload: '{"test": true}',
          privateKey: testKeys.hmacSecret,
          detached: false,
          keyId: 'my-key-123',
        });

        const parts = result.split('.');
        const header = JSON.parse(plugin.base64UrlDecode(parts[0]).toString());

        expect(header.kid).toBe('my-key-123');
      });

      test('should include additional headers', () => {
        const result = plugin.generateJws({
          algorithm: 'HS256',
          payload: '{"test": true}',
          privateKey: testKeys.hmacSecret,
          detached: false,
          additionalHeaders: {
            iss: 'my-app',
            x5t: 'abc123',
          },
        });

        const parts = result.split('.');
        const header = JSON.parse(plugin.base64UrlDecode(parts[0]).toString());

        expect(header.iss).toBe('my-app');
        expect(header.x5t).toBe('abc123');
      });

      test('should always include alg and typ', () => {
        const result = plugin.generateJws({
          algorithm: 'RS256',
          payload: '{"test": true}',
          privateKey: testKeys.rsaPrivate,
          detached: false,
        });

        const parts = result.split('.');
        const header = JSON.parse(plugin.base64UrlDecode(parts[0]).toString());

        expect(header.alg).toBe('RS256');
        expect(header.typ).toBe('JWT');
      });
    });

    describe('Error handling', () => {
      test('should throw for unsupported algorithm', () => {
        expect(() => {
          plugin.generateJws({
            algorithm: 'INVALID',
            payload: '{"test": true}',
            privateKey: testKeys.hmacSecret,
            detached: false,
          });
        }).toThrow();
      });

      test('should throw for invalid RSA key', () => {
        expect(() => {
          plugin.generateJws({
            algorithm: 'RS256',
            payload: '{"test": true}',
            privateKey: 'not-a-valid-key',
            detached: false,
          });
        }).toThrow();
      });
    });
  });

  describe('Template Tag', () => {
    const jwsTag = plugin.templateTags.find(t => t.name === 'jwsSignature');

    test('should have correct number of arguments', () => {
      expect(jwsTag.args.length).toBe(10);
    });

    test('should have algorithm as first argument with enum type', () => {
      const algArg = jwsTag.args[0];
      expect(algArg.displayName).toBe('Algorithm');
      expect(algArg.type).toBe('enum');
      expect(algArg.options.length).toBeGreaterThan(0);
    });

    test('should have all expected algorithms in options', () => {
      const algArg = jwsTag.args[0];
      const algorithms = algArg.options.map(o => o.value);

      expect(algorithms).toContain('HS256');
      expect(algorithms).toContain('RS256');
      expect(algorithms).toContain('PS256');
      expect(algorithms).toContain('ES256');
    });

    test('should have run function', () => {
      expect(typeof jwsTag.run).toBe('function');
    });

    test('run should throw when private key is missing', async () => {
      const context = {
        request: {
          getBody: () => ({ text: '{}' }),
        },
      };

      await expect(
        jwsTag.run(context, 'HS256', '', '', '', 'request_body', '', true, false, '', ''),
      ).rejects.toThrow('Private key or secret is required');
    });

    test('run should generate signature with valid inputs', async () => {
      const context = {
        request: {
          getBody: () => ({ text: '{"test": true}' }),
        },
      };

      const result = await jwsTag.run(
        context,
        'HS256',
        testKeys.hmacSecret,
        '', // keystorePassword
        '', // keyAlias
        'request_body',
        '',
        true, // detached
        false, // unencoded
        '',
        '',
      );

      expect(result).toBeTruthy();
      expect(result).toMatch(/^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$/);
    });

    test('run should use custom payload when specified', async () => {
      const context = {
        request: {
          getBody: () => ({ text: 'request body' }),
        },
      };

      const customPayload = '{"custom": "payload"}';
      const result = await jwsTag.run(
        context,
        'HS256',
        testKeys.hmacSecret,
        '', // keystorePassword
        '', // keyAlias
        'custom',
        customPayload,
        false,
        false,
        '',
        '',
      );

      // Verify the payload in the JWT
      const parts = result.split('.');
      const decodedPayload = plugin.base64UrlDecode(parts[1]).toString();
      expect(decodedPayload).toBe(customPayload);
    });

    test('run should handle additional headers JSON', async () => {
      const context = {
        request: {
          getBody: () => ({ text: '{}' }),
        },
      };

      const result = await jwsTag.run(
        context,
        'HS256',
        testKeys.hmacSecret,
        '', // keystorePassword
        '', // keyAlias
        'request_body',
        '',
        false,
        false,
        'my-key-id',
        '{"iss": "test-app"}',
      );

      const parts = result.split('.');
      const header = JSON.parse(plugin.base64UrlDecode(parts[0]).toString());

      expect(header.kid).toBe('my-key-id');
      expect(header.iss).toBe('test-app');
    });

    test('run should throw for invalid additional headers JSON', async () => {
      const context = {
        request: {
          getBody: () => ({ text: '{}' }),
        },
      };

      await expect(
        jwsTag.run(
          context,
          'HS256',
          testKeys.hmacSecret,
          '', // keystorePassword
          '', // keyAlias
          'request_body',
          '',
          false,
          false,
          '',
          'invalid json{',
        ),
      ).rejects.toThrow('Invalid additional headers JSON');
    });
  });

  describe('Workspace Actions', () => {
    test('should have configure action', () => {
      const configAction = plugin.workspaceActions.find(
        a => a.label === 'Configure JWS Auto-Sign',
      );
      expect(configAction).toBeDefined();
      expect(configAction.icon).toBe('fa-key');
      expect(typeof configAction.action).toBe('function');
    });

    test('should have disable action', () => {
      const disableAction = plugin.workspaceActions.find(
        a => a.label === 'Disable JWS Auto-Sign',
      );
      expect(disableAction).toBeDefined();
      expect(disableAction.icon).toBe('fa-times');
      expect(typeof disableAction.action).toBe('function');
    });
  });

  describe('Request Hook', () => {
    test('should export at least one request hook', () => {
      expect(plugin.requestHooks.length).toBeGreaterThanOrEqual(1);
    });

    test('request hook should be a function', () => {
      expect(typeof plugin.requestHooks[0]).toBe('function');
    });

    test('request hook should not throw when autoSign is not configured', async () => {
      const context = {
        store: {
          getItem: jest.fn().mockResolvedValue(null),
        },
        request: {
          getBody: () => ({ text: '{}' }),
          setHeader: jest.fn(),
        },
      };

      await expect(plugin.requestHooks[0](context)).resolves.not.toThrow();
    });
  });

  describe('Key Normalization', () => {
    test('normalizeKey should convert escaped newlines to real newlines', () => {
      const input = '-----BEGIN PRIVATE KEY-----\\nMIIEvg...\\n-----END PRIVATE KEY-----';
      const result = plugin.normalizeKey(input);
      expect(result).toBe('-----BEGIN PRIVATE KEY-----\nMIIEvg...\n-----END PRIVATE KEY-----');
    });

    test('normalizeKey should handle null input', () => {
      expect(plugin.normalizeKey(null)).toBe(null);
    });

    test('normalizeKey should handle undefined input', () => {
      expect(plugin.normalizeKey(undefined)).toBe(undefined);
    });

    test('normalizeKey should not modify strings without escaped newlines', () => {
      const input = 'simple-secret-key';
      expect(plugin.normalizeKey(input)).toBe(input);
    });
  });

  describe('PKCS#12 Detection', () => {
    test('isPkcs12 should return false for PEM keys', () => {
      const pemKey = '-----BEGIN PRIVATE KEY-----\nMIIEvg...\n-----END PRIVATE KEY-----';
      expect(plugin.isPkcs12(pemKey)).toBe(false);
    });

    test('isPkcs12 should return false for null input', () => {
      expect(plugin.isPkcs12(null)).toBe(false);
    });

    test('isPkcs12 should return false for empty string', () => {
      expect(plugin.isPkcs12('')).toBe(false);
    });

    test('isPkcs12 should return false for short strings', () => {
      expect(plugin.isPkcs12('short')).toBe(false);
    });

    test('isPkcs12 should return false for HMAC secrets', () => {
      expect(plugin.isPkcs12('my-hmac-secret-key')).toBe(false);
    });

    test('isPkcs12 should return false for keystore file paths', () => {
      expect(plugin.isPkcs12('/path/to/keystore.p12')).toBe(false);
      expect(plugin.isPkcs12('~/keys/my-key.pfx')).toBe(false);
    });

    test('isPkcs12 should return true for valid base64 encoded data of sufficient length', () => {
      // Create a large enough base64 string that mimics a keystore
      const fakeKeystoreData = Buffer.alloc(600).fill('A');
      const base64Data = fakeKeystoreData.toString('base64');
      expect(plugin.isPkcs12(base64Data)).toBe(true);
    });
  });

  describe('Keystore Path Detection', () => {
    test('isKeystorePath should return true for .p12 files', () => {
      expect(plugin.isKeystorePath('/path/to/keystore.p12')).toBe(true);
      expect(plugin.isKeystorePath('keystore.p12')).toBe(true);
      expect(plugin.isKeystorePath('~/keys/my-key.p12')).toBe(true);
    });

    test('isKeystorePath should return true for .pfx files', () => {
      expect(plugin.isKeystorePath('/path/to/keystore.pfx')).toBe(true);
      expect(plugin.isKeystorePath('keystore.pfx')).toBe(true);
      expect(plugin.isKeystorePath('C:\\keys\\my-key.pfx')).toBe(true);
    });

    test('isKeystorePath should return false for non-keystore paths', () => {
      expect(plugin.isKeystorePath('/path/to/key.pem')).toBe(false);
      expect(plugin.isKeystorePath('secret-key')).toBe(false);
      expect(plugin.isKeystorePath('')).toBe(false);
      expect(plugin.isKeystorePath(null)).toBe(false);
    });

    test('isKeystorePath should return false for PEM keys', () => {
      const pemKey = '-----BEGIN PRIVATE KEY-----\nMIIEvg...\n-----END PRIVATE KEY-----';
      expect(plugin.isKeystorePath(pemKey)).toBe(false);
    });
  });

  describe('Key Resolution', () => {
    test('resolvePrivateKey should return normalized PEM key', () => {
      const input = '-----BEGIN PRIVATE KEY-----\\nMIIEvg...\\n-----END PRIVATE KEY-----';
      const result = plugin.resolvePrivateKey(input, null, null);
      expect(result).toContain('-----BEGIN PRIVATE KEY-----');
      expect(result).toContain('\n');
    });

    test('resolvePrivateKey should return null for null input', () => {
      expect(plugin.resolvePrivateKey(null, null, null)).toBe(null);
    });

    test('resolvePrivateKey should return HMAC secret unchanged', () => {
      const secret = 'my-hmac-secret-key-at-least-256-bits-long';
      const result = plugin.resolvePrivateKey(secret, null, null);
      expect(result).toBe(secret);
    });
  });

  describe('Keystore Extraction', () => {
    // These tests require node-forge to be installed
    let forgeAvailable = false;

    beforeAll(() => {
      try {
        require('node-forge');
        forgeAvailable = true;
      } catch (e) {
        forgeAvailable = false;
      }
    });

    test('extractKeyFromPkcs12 should throw helpful error when node-forge is not available', () => {
      // This test only makes sense if forge is NOT available
      if (forgeAvailable) {
        // If forge is available, just verify the function exists
        expect(typeof plugin.extractKeyFromPkcs12).toBe('function');
        return;
      }

      expect(() => {
        plugin.extractKeyFromPkcs12('fake-base64', 'password', null);
      }).toThrow('node-forge');
    });

    // Conditional tests that only run if node-forge is available
    test('extractKeyFromPkcs12 should throw for invalid base64', () => {
      if (!forgeAvailable) {
        expect(true).toBe(true); // Skip
        return;
      }

      expect(() => {
        plugin.extractKeyFromPkcs12('not-valid-base64!!!', 'password', null);
      }).toThrow();
    });

    test('extractKeyFromPkcs12 should throw for invalid password', () => {
      if (!forgeAvailable) {
        expect(true).toBe(true); // Skip
        return;
      }

      // Create a minimal valid-looking base64 that will fail password check
      const fakeData = Buffer.from('invalid-pkcs12-data').toString('base64');
      expect(() => {
        plugin.extractKeyFromPkcs12(fakeData, 'wrong-password', null);
      }).toThrow();
    });
  });

  describe('generateJws with Keystore Options', () => {
    test('generateJws should accept keystorePassword option', () => {
      // Even without actual keystore, should not throw for the option itself
      const result = plugin.generateJws({
        algorithm: 'HS256',
        payload: 'test',
        privateKey: testKeys.hmacSecret,
        keystorePassword: null,
        keyAlias: null,
        detached: true,
      });

      expect(result).toBeTruthy();
      expect(result).toMatch(/^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$/);
    });

    test('generateJws should accept keyAlias option', () => {
      const result = plugin.generateJws({
        algorithm: 'HS256',
        payload: 'test',
        privateKey: testKeys.hmacSecret,
        keystorePassword: null,
        keyAlias: 'ignored-for-pem',
        detached: true,
      });

      expect(result).toBeTruthy();
    });

    test('generateJws should work with PEM key and empty keystore options', () => {
      const result = plugin.generateJws({
        algorithm: 'RS256',
        payload: '{"test": true}',
        privateKey: testKeys.rsaPrivate,
        keystorePassword: '',
        keyAlias: '',
        detached: false,
      });

      const parts = result.split('.');
      expect(parts.length).toBe(3);
    });
  });
});

