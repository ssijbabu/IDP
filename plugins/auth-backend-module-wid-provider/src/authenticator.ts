// src/authenticator-msal.ts
import {
  OAuthAuthenticator,
  OAuthAuthenticatorLogoutInput
} from '@backstage/plugin-auth-node';
import {
  PublicClientApplication,
  InteractionRequiredAuthError,
} from '@azure/msal-node';
import {
  AzureFederatedConfig,
  AzureTokenResponse,
  AzureUserProfile
} from './types';

// --- Helper Functions ---

function initializeMsalClient(config: AzureFederatedConfig): PublicClientApplication {
  const clientConfig = {
    auth: {
      clientId: config.clientId,
      authority: `https://login.microsoftonline.com/${config.tenantId}`,
      clientSecret: config.clientSecret,
      // For federated credentials, MSAL.js can handle them via system environment
    },
    system: {
      loggerOptions: {
        loggerCallback: (_level: any, message: string) => {
          console.log(`[MSAL] ${message}`);
        },
        piiLoggingEnabled: false,
        logLevel: 'Warning' as any,
      },
    },
  };

  return new PublicClientApplication(clientConfig);
}


function decodeJWT(token: string): any {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }
  const payload = parts[1];
  const decoded = Buffer.from(payload, 'base64').toString('utf-8');
  return JSON.parse(decoded);
}


async function getUserProfile(
  _msalClient: PublicClientApplication,
  accessToken: string,
  idToken?: string
): Promise<AzureUserProfile> {
  // Strategy 1: Use ID Token claims (fastest)
  if (idToken) {
    const payload = decodeJWT(idToken);
    return {
      sub: payload.sub || payload.oid,
      name: payload.name,
      email: payload.email,
      preferred_username: payload.preferred_username,
      oid: payload.oid,
    };
  }

  // Strategy 2: Fetch from MS Graph API
  const response = await fetch('https://graph.microsoft.com/v1.0/me', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to fetch user profile from MS Graph: ${errorText}`);
  }

  const profile = await response.json();
  return {
    sub: profile.id,
    name: profile.displayName,
    email: profile.mail || profile.userPrincipalName,
    preferred_username: profile.userPrincipalName,
    oid: profile.id,
  };
}


async function acquireTokenSilent(
  msalClient: PublicClientApplication,
  refreshToken: string
): Promise<AzureTokenResponse> {
  const silentFlowRequest: any = {
    scopes: ['openid', 'profile', 'email', 'User.Read', 'offline_access'],
    refreshToken: refreshToken,
    forceRefresh: false,
  };

  try {
    const response = await msalClient.acquireTokenByRefreshToken(silentFlowRequest);

    if (!response) {
      throw new Error('Token refresh returned no response');
    }

    return {
      access_token: response.accessToken,
      token_type: 'Bearer',
      expires_in: response.expiresOn
        ? Math.floor((response.expiresOn.getTime() - Date.now()) / 1000)
        : 3600,
      scope: response.scopes?.join(' ') || 'openid profile email User.Read offline_access',
      id_token: response.idToken,
      refresh_token: (response as any).refreshToken,
    };
  } catch (error) {
    if (error instanceof InteractionRequiredAuthError) {
      throw new Error('Interactive sign-in required.  Refresh token may have expired.');
    }
    throw error;
  }
}

// --- Authenticator Logic ---

export const azureFederatedAuthenticator: OAuthAuthenticator<
  AzureFederatedConfig,
  AzureUserProfile
> = {

  initialize({ callbackUrl, config }) {
    const tenantId = config.getString('tenantId');
    const clientId = config.getString('clientId');
    const clientSecret = config.getOptionalString('clientSecret');
    const federatedTokenFile = config.getOptionalString('federatedTokenFile');

    if (!clientSecret && !federatedTokenFile) {
      throw new Error('Configuration error: Either "clientSecret" or "federatedTokenFile" must be provided.');
    }

    return {
      tenantId,
      clientId,
      clientSecret,
      federatedTokenFile,
      callbackUrl,
    };
  },

  async start(_input, ctx) {
    const { tenantId, clientId, callbackUrl } = ctx;

    // MSAL.js builds the authorization URL for you
    const state = Buffer.from(JSON.stringify({
      nonce: Math.random().toString(36).substring(7),
      timestamp: Date.now()
    })).toString('base64');

    const authorizationUrl = new URL(
      `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`
    );

    // Set all required OAuth parameters
    authorizationUrl.searchParams.set('client_id', clientId);
    authorizationUrl.searchParams.set('response_type', 'code');
    authorizationUrl.searchParams.set('redirect_uri', callbackUrl);
    authorizationUrl.searchParams.set('response_mode', 'query');
    authorizationUrl.searchParams.set('scope', 'openid profile email User.Read offline_access');
    authorizationUrl.searchParams.set('state', state);

    return {
      url: authorizationUrl.toString(),
      status: 302,
    };
  },

  async authenticate(input, ctx) {
    const { req } = input;
    const config = ctx;

    // Extract authorization code from callback
    const url = new URL(req.url, `http://${req.headers.host}`);
    const code = url.searchParams.get('code');

    if (!code) {
      throw new Error('No authorization code received');
    }

    // Initialize MSAL client
    const msalClient = initializeMsalClient(config);

    // Exchange authorization code for tokens using MSAL.js
    const tokenRequest = {
      code: code,
      scopes: ['openid', 'profile', 'email', 'User.Read', 'offline_access'],
      redirectUri: config.callbackUrl,
    };

    let tokenResponse: any;
    try {
      tokenResponse = await msalClient.acquireTokenByCode(tokenRequest);
    } catch (error) {
      throw new Error(`Token exchange failed: ${error}`);
    }

    if (!tokenResponse) {
      throw new Error('Token response is empty');
    }

    // Get user profile
    const userProfile = await getUserProfile(
      msalClient,
      tokenResponse.accessToken,
      tokenResponse.idToken
    );

    // Return full authentication result
    return {
      fullProfile: userProfile,
      session: {
        accessToken: tokenResponse.accessToken,
        tokenType: tokenResponse.tokenType || 'Bearer',
        expiresInSeconds: tokenResponse.expiresOn
          ? Math.floor((tokenResponse.expiresOn.getTime() - Date.now()) / 1000)
          : 3600,
        scope: tokenResponse.scopes?.join(' ') || 'openid profile email User.Read offline_access',
        idToken: tokenResponse.idToken,
        refreshToken: (tokenResponse as any).refreshToken,
      },
    };
  },

  async refresh(input, ctx) {
    const { refreshToken } = input;
    const config = ctx;

    if (!refreshToken) {
      throw new Error('No refresh token provided');
    }

    // Initialize MSAL client
    const msalClient = initializeMsalClient(config);

    // Use MSAL's built-in refresh mechanism
    const tokenResponse = await acquireTokenSilent(msalClient, refreshToken);

    // Get user profile
    const userProfile = await getUserProfile(
      msalClient,
      tokenResponse.access_token,
      tokenResponse.id_token
    );

    return {
      fullProfile: userProfile,
      session: {
        accessToken: tokenResponse.access_token,
        tokenType: tokenResponse.token_type,
        expiresInSeconds: tokenResponse.expires_in,
        scope: tokenResponse.scope,
        idToken: tokenResponse.id_token,
        refreshToken: tokenResponse.refresh_token,
      },
    };
  },

  async logout(input: OAuthAuthenticatorLogoutInput, ctx: AzureFederatedConfig) {
    // MSAL.js provides a logout method, but for backend OAuth logout,
    // we still construct the Azure AD logout URL
    const logoutUrl = new URL(
      `https://login.microsoftonline.com/${ctx.tenantId}/oauth2/v2.0/logout`
    );

    logoutUrl.searchParams.set('post_logout_redirect_uri', input.req.baseUrl);

    throw {
      status: 302,
      headers: {
        Location: logoutUrl.toString(),
      },
    };
  },

  async defaultProfileTransform(result) {
    return {
      profile: {
        email: result.fullProfile.email,
        displayName: result.fullProfile.name,
        picture: undefined,
      },
    };
  },
};