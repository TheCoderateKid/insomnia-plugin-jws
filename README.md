# JWSPlugin - Insomnia JWS Signature Generator

[![Test JWSPlugin](https://github.com/thecoderatekid/insomnia-plugin-jws/actions/workflows/test.yml/badge.svg)](https://github.com/thecoderatekid/insomnia-plugin-jws/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/thecoderatekid/insomnia-plugin-jws/branch/main/graph/badge.svg)](https://codecov.io/gh/thecoderatekid/insomnia-plugin-jws)

An Insomnia plugin for generating JWS (JSON Web Signature) signatures, including support for detached payload mode commonly used in API authentication.

## Features

- **Multiple Algorithms**: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512
- **Detached Payload Mode**: Generates `header..signature` format (RFC 7515)
- **Unencoded Payload Mode**: RFC 7797 support with `b64: false`
- **Issued At Header**: Automatic `iat` timestamp with `crit: ["iat"]` for replay protection
- **PEM Keys**: Standard PEM-formatted private keys
- **PKCS#12 Keystores**: Support for .p12/.pfx keystores with password and key alias
- **Template Tag**: Use `{% jwsSignature %}` anywhere in your requests
- **Auto-Sign Hook**: Automatically add JWS headers to all requests
- **Workspace Actions**: UI buttons for easy configuration

## Installation

Clone the repo directly into your Insomnia plugins folder:

**macOS:**
```bash
cd ~/Library/Application\ Support/Insomnia/plugins
git clone https://github.com/thecoderatekid/insomnia-plugin-jws.git
```

**Linux:**
```bash
cd ~/.config/Insomnia/plugins
git clone https://github.com/thecoderatekid/insomnia-plugin-jws.git
```

**Windows:**
```bash
cd %APPDATA%\Insomnia\plugins
git clone https://github.com/thecoderatekid/insomnia-plugin-jws.git
```

Then restart Insomnia. That's it — no `npm install` required for PEM keys.

**For PKCS#12 Keystore Support:**
```bash
cd ~/.config/Insomnia/plugins/insomnia-plugin-jws  # or your OS path
npm install
```

## Quick Start

### 1. Set Up Environment Variables

Go to **Environment** (Ctrl+E / Cmd+E) and add your signing credentials:

```json
{
  "jws_private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvg...\n-----END PRIVATE KEY-----",
  "jws_key_id": "my-signing-key-001"
}
```

> **Important**: Replace actual newlines in your PEM key with `\n` so it stays valid JSON.

### 2. Add JWS Signature Header

1. Add a header to your request (e.g., `X-JWS-Signature`)
2. Click the header value field
3. Press `Ctrl+Space` to open autocomplete
4. Search for "JWS Signature" and select it
5. Configure the options:
   - **Algorithm**: RS256 (or your preferred algorithm)
   - **Private Key / Keystore**: `{{ _.jws_private_key }}`
   - **Key ID (kid)**: `{{ _.jws_key_id }}`
   - **Payload Source**: Request Body
   - **Detached Payload**: ✓ (checked)
   - **Include Issued At (iat)**: ✓ (checked)

### 3. Send Request

The plugin will automatically sign your request body and add the signature header.

## Template Tag Options

| Option | Description | Example |
|--------|-------------|---------|
| Algorithm | Signing algorithm | RS256, ES256, HS256, etc. |
| Private Key / Keystore | PEM key, HMAC secret, or path to .p12/.pfx | `{{ _.jws_keystore_path }}` |
| Keystore Password | Password for PKCS#12 keystore | `{{ _.jws_keystore_password }}` |
| Key Alias | Alias of key in keystore | `{{ _.jws_key_alias }}` |
| Payload Source | Where to get the payload | Request Body or Custom Value |
| Custom Payload | Custom payload string | `{"custom": "data"}` |
| Detached Payload | Use `header..signature` format | true/false |
| Unencoded Payload | RFC 7797 mode | true/false |
| Key ID (kid) | Key ID for JWS header | `{{ _.jws_key_id }}` |
| Include Issued At (iat) | Add iat timestamp with crit: ["iat"] | true (default) |
| Additional Headers | Extra JWS header fields | `{"iss": "my-app"}` |

## Usage Examples

### RS256 with Detached Payload

Environment:
```json
{
  "jws_private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvg...\n-----END PRIVATE KEY-----",
  "jws_key_id": "my-signing-key-001"
}
```

Header value:
```
{% jwsSignature 'RS256', '{{ _.jws_private_key }}', '', '', 'request_body', '', true, false, '{{ _.jws_key_id }}', true, '' %}
```

Output: `eyJhbGciOiJSUzI1NiIsImtpZCI6Im15LXNpZ25pbmcta2V5LTAwMSIsImlhdCI6MTcwNDY3MjAwMCwiY3JpdCI6WyJpYXQiXX0..signature`

**Generated JWS Header:**
```json
{
  "alg": "RS256",
  "kid": "my-signing-key-001",
  "iat": 1704672000,
  "crit": ["iat"]
}
```

### ES256 with Key ID

```
{% jwsSignature 'ES256', '{{ _.jws_private_key }}', '', '', 'request_body', '', true, false, '{{ _.jws_key_id }}', true, '' %}
```

### HS256 with Custom Headers

```
{% jwsSignature 'HS256', '{{ _.hmac_secret }}', '', '', 'request_body', '', false, false, '', true, '{"iss":"my-app"}' %}
```

### PKCS#12 Keystore

Environment:
```json
{
  "jws_keystore_path": "/path/to/keystore.p12",
  "jws_keystore_password": "changeit",
  "jws_key_alias": "my-signing-key",
  "jws_key_id": "key-001"
}
```

Header value:
```
{% jwsSignature 'RS256', '{{ _.jws_keystore_path }}', '{{ _.jws_keystore_password }}', '{{ _.jws_key_alias }}', 'request_body', '', true, false, '{{ _.jws_key_id }}', true, '' %}
```

### Unencoded Payload (RFC 7797)

Some APIs require signatures over the raw payload without base64 encoding:

```
{% jwsSignature 'RS256', '{{ _.jws_private_key }}', '', '', 'request_body', '', true, true, '', true, '' %}
```

This adds `"b64": false` and `"crit": ["b64", "iat"]` to the JWS header.

## Key Formats

### RSA Keys (RS256, RS384, RS512, PS256, PS384, PS512)

PKCS#8 format (recommended):
```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQE...
-----END PRIVATE KEY-----
```

PKCS#1 format:
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
```

### EC Keys (ES256, ES384, ES512)

```
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEILvM6...
-----END EC PRIVATE KEY-----
```

**Algorithm/Curve mapping:**
- ES256 → P-256 (prime256v1)
- ES384 → P-384 (secp384r1)
- ES512 → P-521 (secp521r1)

### HMAC (HS256, HS384, HS512)

Plain string secret (minimum 256 bits recommended):
```
my-super-secret-key-at-least-32-characters
```

### PKCS#12 Keystore (.p12 / .pfx)

For enterprise environments using Java-style keystores:

1. **Add to your Insomnia environment:**
   ```json
   {
     "jws_keystore_path": "/path/to/your-keystore.p12",
     "jws_keystore_password": "your-keystore-password",
     "jws_key_alias": "my-signing-key"
   }
   ```

2. **Use in template tag:**
   - Private Key / Keystore: `{{ _.jws_keystore_path }}`
   - Keystore Password: `{{ _.jws_keystore_password }}`
   - Key Alias: `{{ _.jws_key_alias }}`

**Example paths:**
- macOS/Linux: `/Users/you/keys/keystore.p12` or `~/keys/keystore.p12`
- Windows: `C:\Users\you\keys\keystore.pfx`

**Notes:**
- If you don't specify a key alias, the first private key in the keystore will be used
- If you specify an alias that doesn't exist, the error message will list available aliases
- Keystore support requires running `npm install` in the plugin folder (installs `node-forge`)
- Base64-encoded keystores are still supported for backwards compatibility

## Auto-Sign Mode

Automatically add JWS signatures to all requests:

1. Click the dropdown menu in your workspace
2. Select **Configure JWS Auto-Sign**
3. Enter your algorithm, private key/keystore, and header name
4. All requests will automatically include the JWS signature

To disable: Select **Disable JWS Auto-Sign** from the same menu.

## Troubleshooting

### "Private key or secret is required"
Ensure you've provided a valid key. Check that your environment variable name matches.

### "JWS generation failed: error:0909006C:PEM routines"
Your key format is incorrect. Ensure:
- Full PEM headers are included (`-----BEGIN PRIVATE KEY-----`)
- Newlines are escaped as `\n` in JSON environment variables
- No extra whitespace or characters

### "Key alias 'xxx' not found"
The specified alias doesn't exist in the keystore. The error message lists available aliases.

### "Invalid keystore password"
Wrong password for the PKCS#12 keystore.

### Signature doesn't verify
1. Check that the algorithm matches between signing and verification
2. For detached payloads, ensure the verifier reconstructs the full JWS correctly
3. For unencoded payloads, ensure the verifier handles RFC 7797

### Request body is empty
If using "Request Body" as payload source, ensure your request actually has a body.

### Private key appearing in URL
Don't paste the PEM key directly in the template tag. Always use an environment variable:
- ✗ Wrong: `{% jwsSignature 'RS256', '-----BEGIN...', ... %}`
- ✓ Correct: `{% jwsSignature 'RS256', '{{ _.jws_private_key }}', ... %}`

## API Reference

The plugin exports utilities for programmatic use:

```javascript
const { generateJws, base64UrlEncode } = require('insomnia-plugin-jws');

const signature = generateJws({
  algorithm: 'RS256',
  payload: '{"test": true}',
  privateKey: '-----BEGIN PRIVATE KEY-----...',
  keystorePassword: null,  // for PKCS#12 file path
  keyAlias: null,          // for PKCS#12 with multiple keys
  detached: true,
  unencoded: false,
  keyId: 'my-key',
  includeIat: true,        // adds iat timestamp and crit: ["iat"]
  additionalHeaders: { iss: 'my-app' },
});
```

**Generated header structure:**
```json
{
  "alg": "RS256",
  "kid": "my-key",
  "iat": 1704672000,
  "crit": ["iat"],
  "iss": "my-app"
}
```

## Development

### Setup

```bash
git clone https://github.com/thecoderatekid/insomnia-plugin-jws.git
cd insomnia-plugin-jws
npm install
```

### Running Tests

```bash
npm test              # Run all tests
npm run test:coverage # Run with coverage
npm run test:watch    # Watch mode
npm run lint          # Run linter
npm run lint:fix      # Fix linting issues
```

### Test Coverage

The test suite covers:
- All signing algorithms (HS*, RS*, PS*, ES*)
- Detached and attached payload modes
- Unencoded payload mode (RFC 7797)
- Header customization (kid, additional headers)
- PKCS#12 keystore detection and extraction
- Key normalization
- Template tag functionality
- Error handling

## License

MIT
