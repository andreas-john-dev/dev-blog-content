# AWS Cognito OAuth2 Token Retrieval Script

This Python script implements an OAuth2 authentication flow for AWS Cognito using the Authorization Code Grant type. It authenticates users via a browser-based login and retrieves access tokens.

## Key Components

- **`CognitoTokens`**: A dataclass that stores the OAuth2 tokens returned by Cognito (ID token, access token, refresh token, and expiration time)

- **`CognitoHTTPServerHandler`**: A custom HTTP request handler that captures the OAuth2 authorization code from Cognito's callback redirect. When it receives the code, it automatically exchanges it for tokens by calling the token endpoint

- **`CognitoHTTPServer`**: An extended HTTPServer class that includes a `tokens` attribute to store the retrieved authentication tokens

- **`CognitoTokenHandler`**: The main orchestrator that manages the authentication flow by:
  1. Opening the Cognito authorization URL in the user's browser
  2. Starting a temporary local HTTP server on port 8080 to receive the callback
  3. Waiting for the authorization code and exchanging it for tokens
  4. Returning the complete set of tokens

## Authentication Flow

1. User runs the script
2. Browser opens to Cognito's login page
3. User authenticates (potentially via SAML IdP based on Cognito configuration)
4. Cognito redirects back to `http://localhost:8080` with an authorization code
5. Script exchanges the code for tokens via Cognito's token endpoint
6. Script displays all tokens (ID, access, refresh) and expiration time

## Configuration

The script requires configuration of the following placeholders before use:

- `COGNITO_CLIENT_ID`: Your Cognito App Client ID (e.g., `1h57kf5cpq17m0eml12EXAMPLE`)
- `COGNITO_DOMAIN`: Your Cognito domain URL (e.g., `https://your-domain.auth.us-east-1.amazoncognito.com`)

**Important**: The Cognito App Client settings must include `http://localhost:8080` in the allowed callback URLs (redirect URIs). Without this configuration, the OAuth2 flow will fail with a redirect URI mismatch error.

## Usage

This script is designed for development/testing scenarios where you need to obtain Cognito tokens programmatically without implementing a full web application.

```bash
python cognito-token.py
```
