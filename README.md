# JWSPlugin - Insomnia JWS Signature Generator

[![Test JWSPlugin](https://github.com/thecoderatekid/insomnia-plugin-jws/actions/workflows/test.yml/badge.svg)](https://github.com/thecoderatekid/insomnia-plugin-jws/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/thecoderatekid/insomnia-plugin-jws/branch/main/graph/badge.svg)](https://codecov.io/gh/thecoderatekid/insomnia-plugin-jws)

An Insomnia plugin for generating JWS (JSON Web Signature) signatures, including support for detached payload mode commonly used in API authentication.

## Features

- **Multiple Algorithms**: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512
- **Detached Payload Mode**: Generates `header..signature` format (RFC 7515)
- **Unencoded Payload Mode**: RFC 7797 support with `b64: false`
- **Template Tag**: Use `{% jwsSignature %}` anywhere in your requests
- **Auto-Sign Hook**: Automatically add JWS headers to all requests
- **Workspace Actions**: UI buttons for easy configuration

## Installation

### Option 1: Manual Installation

1. Find your Insomnia plugins folder:
   - **macOS**: `~/Library/Application Support/Insomnia/plugins/`
   - **Windows**: `%APPDATA%\Insomnia\plugins\`
   - **Linux**: `~/.config/Insomnia/plugins/`

2. Create the plugin folder:
   ```bash
   mkdir -p ~/.config/Insomnia/plugins/insomnia-plugin-jws
   ```

3. Copy `package.json` and `index.js` to that folder

4. Restart Insomnia

### Option 2: NPM Link (Development)

```bash
cd insomnia-plugin-jws
npm link
cd ~/.config/Insomnia/plugins
npm link insomnia-plugin-jws
```

## Usage

### Method 1: Template Tag (Recommended)

Use the `jwsSignature` template tag in any header value:

1. Add a header to your request (e.g., `X-JWS-Signature`)
2. Click the header value field
3. Press `Ctrl+Space` to open autocomplete
4. Search for "JWS Signature"
5. Configure the options:

| Option | Description |
|--------|-------------|
| Algorithm | Signing algorithm (RS256, ES256, HS256, etc.) |
| Private Key | Your PEM key or HMAC secret |
| Payload Source | Use request body or custom value |
| Custom Payload | Only if Payload Source is "Custom Value" |
| Detached Payload | Enable for `header..signature` format |
| Unencoded Payload | Enable for RFC 7797 compliance |
| Key ID | Optional `kid` header field |
| Additional Headers | Extra JWS header fields as JSON |

### Method 2: Auto-Sign (All Requests)

1. Click the dropdown menu in your workspace
2. Select "Configure JWS Auto-Sign"
3. Enter your algorithm, private key, and header name
4. All requests will automatically include the JWS signature

To disable: Select "Disable JWS Auto-Sign" from the same menu.

### Method 3: Environment Variables

Store your key in an environment variable and reference it:

1. In your environment, add:
   ```json
   {
     "jws_private_key": "-----BEGIN PRIVATE KEY-----\n..."
   }
   ```

2. In the template tag's Private Key field, use:
   ```
   {{ _.jws_private_key }}
   ```

## Examples

### RS256 with Detached Payload

```
Header: X-JWS-Signature
Value: {% jwsSignature 'RS256', '{{ _.private_key }}', 'request_body', '', true, false, '', '' %}
```

Result: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..signature`

### ES256 with Key ID

```
Header: Signature
Value: {% jwsSignature 'ES256', '{{ _.ec_key }}', 'request_body', '', true, false, 'my-key-123', '' %}
```

Result: `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im15LWtleS0xMjMifQ..signature`

### HS256 with Custom Headers

```
Header: Authorization
Value: {% jwsSignature 'HS256', 'my-secret', 'request_body', '', false, false, '', '{"iss":"my-app"}' %}
```

### Unencoded Payload (RFC 7797)

Some APIs require signatures over the raw payload without base64 encoding:

```
Header: X-JWS-Signature  
Value: {% jwsSignature 'RS256', '{{ _.key }}', 'request_body', '', true, true, '', '' %}
```

This adds `"b64": false` and `"crit": ["b64"]` to the JWS header.

## Key Formats

### RSA Keys (RS256, RS384, RS512, PS256, PS384, PS512)

```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQE...
-----END PRIVATE KEY-----
```

Or PKCS#1 format:
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

Just use a plain string secret:
```
my-super-secret-key
```

## Troubleshooting

### "Private key or secret is required"
Ensure you've provided a valid key. If using environment variables, check the syntax.

### "JWS generation failed: error:0909006C:PEM routines"
Your key format is incorrect. Ensure it includes the full PEM headers and proper newlines.

### Signature doesn't verify
1. Check that the algorithm matches between signing and verification
2. For detached payloads, ensure the verifier reconstructs the full JWS correctly
3. For unencoded payloads, ensure the verifier handles RFC 7797

### Request body is empty
If using "Request Body" as payload source, ensure your request actually has a body set.

## API Reference

The plugin exports utilities for programmatic use:

```javascript
const { generateJws, base64UrlEncode } = require('insomnia-plugin-jws');

const signature = generateJws({
  algorithm: 'RS256',
  payload: '{"test": true}',
  privateKey: '-----BEGIN PRIVATE KEY-----...',
  detached: true,
  unencoded: false,
  keyId: 'my-key',
  additionalHeaders: { iss: 'my-app' },
});
```

## License

MIT

## Development

### Setup

```bash
git clone https://github.com/YOUR_USERNAME/insomnia-plugin-jws.git
cd insomnia-plugin-jws
npm install
```

### Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch

# Run linter
npm run lint

# Fix linting issues
npm run lint:fix
```

### CI/CD

This project uses GitHub Actions for continuous integration. On every push and pull request:

1. **Test Job**: Runs the test suite across Node.js 18.x, 20.x, and 22.x
2. **Integration Test Job**: Runs integration tests
3. **Validate Plugin Job**: Validates the plugin structure and exports

See `.github/workflows/test.yml` for the full workflow configuration.

### Test Coverage

The test suite covers:
- All signing algorithms (HS*, RS*, PS*, ES*)
- Detached and attached payload modes
- Unencoded payload mode (RFC 7797)
- Header customization (kid, additional headers)
- Template tag functionality
- Error handling

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`npm test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request
