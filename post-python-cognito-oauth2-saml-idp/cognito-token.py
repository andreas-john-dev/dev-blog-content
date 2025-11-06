from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
from webbrowser import open_new

import requests

PORT = 8080
REDIRECT_URL = f'http://localhost:{PORT}'

COGNITO_CLIENT_ID = '<YOUR_COGNITO_CLIENT_ID>'  # e.g., 1h57kf5cpq17m0eml12EXAMPLE
COGNITO_DOMAIN = '<YOUR_COGNITO_DOMAIN>'  # e.g., https://your-domain.auth.us-east-1.amazoncognito.com

TOKEN_URL = f'{COGNITO_DOMAIN}/oauth2/token'
AUTHORIZE_URL = (
    f'{COGNITO_DOMAIN}/oauth2/authorize'
    f'?client_id={COGNITO_CLIENT_ID}'
    f'&redirect_uri={REDIRECT_URL}'
    f'&response_type=code'
    f'&scope=openid+profile+email'
)


@dataclass(frozen=True)
class CognitoTokens:
    """Container for OAuth2 tokens returned by Cognito."""
    id_token: str
    access_token: str
    refresh_token: str
    expires_in_seconds: int


class CognitoHTTPServerHandler(BaseHTTPRequestHandler):
    """HTTP request handler that captures OAuth2 authorization code."""

    def do_GET(self):
        """Handle GET request from OAuth2 redirect."""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # Parse query parameters from callback URL
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        
        if 'code' in query_params:
            auth_code = query_params['code'][0]
            self.wfile.write(
                bytes(
                    '<html><h1>Authentication successful!</h1>'
                    '<p>You may now close this window.</p></html>',
                    'utf-8'
                )
            )
            # Exchange authorization code for tokens
            self.server.tokens: CognitoTokens = self._exchange_code_for_tokens(auth_code) # type: ignore
        else:
            self.wfile.write(
                bytes(
                    '<html><h1>Authentication failed</h1>'
                    '<p>No authorization code received.</p></html>',
                    'utf-8'
                )
            )

    def log_message(self, format, *args):
        """Suppress HTTP server logs for cleaner output."""
        return

    def _exchange_code_for_tokens(self, code: str) -> CognitoTokens:
        """Exchange authorization code for OAuth2 tokens.
        
        Args:
            code: The authorization code received from the callback
            
        Returns:
            CognitoTokens object containing all tokens
        """
        body = {
            'grant_type': 'authorization_code',
            'client_id': COGNITO_CLIENT_ID,
            'code': code,
            'redirect_uri': REDIRECT_URL
        }
        print('Exchanging authorization code for tokens...')
        response = requests.post(
            TOKEN_URL,
            data=body,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=10
        )
        response.raise_for_status()

        response_body = response.json()
        return CognitoTokens(
            id_token=response_body['id_token'],
            access_token=response_body['access_token'],
            refresh_token=response_body['refresh_token'],
            expires_in_seconds=response_body['expires_in'],
        )


class CognitoHTTPServer(HTTPServer):
    """Custom HTTPServer with tokens attribute."""
    tokens: CognitoTokens | None = None


class CognitoTokenHandler:
    """Main handler for OAuth2 authentication flow."""

    def get_tokens(self) -> CognitoTokens:
        """Initiate OAuth2 flow and retrieve tokens.
        
        Returns:
            CognitoTokens object containing authentication tokens
        """
        # Start temporary HTTP server to receive callback
        open_new(AUTHORIZE_URL)

        print(f"Waiting for authentication callback on {REDIRECT_URL}...")
        http_server = CognitoHTTPServer(('localhost', PORT), CognitoHTTPServerHandler)
        http_server.handle_request()
        
        if http_server.tokens is None:
            raise RuntimeError("Failed to retrieve tokens from Cognito.")
        return http_server.tokens 



if __name__ == '__main__':
    token_handler = CognitoTokenHandler()
    tokens = token_handler.get_tokens()
    
    print('\n' + '='*80)
    print('Authentication Successful!')
    print('='*80)
    print(f'\nID Token:\n{tokens.id_token}')
    print('\n' + '-'*80)
    print(f'\nAccess Token:\n{tokens.access_token}')
    print('\n' + '-'*80)
    print(f'\nRefresh Token:\n{tokens.refresh_token}')
    print(f'\nExpires in: {tokens.expires_in_seconds} seconds')