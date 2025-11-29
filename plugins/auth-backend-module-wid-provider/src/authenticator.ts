// src/authenticator.ts
import { 
  OAuthAuthenticator,
  OAuthAuthenticatorLogoutInput
} from '@backstage/plugin-auth-node';
import { 
  AzureFederatedConfig, 
  AzureTokenResponse, 
  AzureUserProfile 
} from './types';

// --- Helper Functions ---

async function getFederatedToken(federatedTokenFile: string): Promise<string> {
  const { readFile } = await import('fs/promises');
  try {
    const token = await readFile(federatedTokenFile, 'utf-8');
    return token.trim();
  } catch (error) {
    throw new Error(`Failed to read federated token: ${error}`);
  }
}

async function exchangeCodeForToken(
  code: string,
  config: AzureFederatedConfig,
): Promise<AzureTokenResponse> {
  const tokenEndpoint = `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`;
  
  const params = new URLSearchParams({
    client_id: config.clientId,
    scope: 'openid profile email User.Read offline_access',
    code: code,
    redirect_uri: config.callbackUrl,
    grant_type: 'authorization_code',
  });

  if (config.clientSecret) {
    params.set('client_secret', config.clientSecret);
  } else if (config.federatedTokenFile) {
    const clientAssertion = await getFederatedToken(config.federatedTokenFile);
    params.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    params.set('client_assertion', clientAssertion);
  } else {
    throw new Error('Either clientSecret or federatedTokenFile must be provided.');
  }

  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Token exchange failed: ${errorText}`);
  }

  return await response.json();
}

async function refreshAccessToken(
  refreshToken: string,
  config: AzureFederatedConfig,
): Promise<AzureTokenResponse> {
  const tokenEndpoint = `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`;
  
  const params = new URLSearchParams({
    client_id: config.clientId,
    scope: 'openid profile email User.Read offline_access',
    refresh_token: refreshToken,
    grant_type: 'refresh_token',
  });

  if (config.clientSecret) {
    params.set('client_secret', config.clientSecret);
  } else if (config.federatedTokenFile) {
    const clientAssertion = await getFederatedToken(config.federatedTokenFile);
    params.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    params.set('client_assertion', clientAssertion);
  }

  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Token refresh failed: ${errorText}`);
  }

  return await response.json();
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
  accessToken: string,
  idToken?: string
): Promise<AzureUserProfile> {
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
    
    const state = Buffer.from(JSON.stringify({ 
      nonce: Math.random().toString(36).substring(7),
      timestamp: Date.now()
    })).toString('base64');
    
    const authorizationUrl = new URL(
      `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`
    );
    
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
    
    const url = new URL(req.url, `http://${req.headers.host}`);
    const code = url.searchParams.get('code');
    
    if (!code) {
      throw new Error('No authorization code received');
    }

    const tokenResponse = await exchangeCodeForToken(code, config);

    const userProfile = await getUserProfile(
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

  async refresh(input, ctx) {
    const { refreshToken } = input;
    const config = ctx;

    if (!refreshToken) {
      throw new Error('No refresh token provided');
    }

    const tokenResponse = await refreshAccessToken(refreshToken, config);

    const userProfile = await getUserProfile(
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
    // 1. Construct the Azure AD logout URL using the tenant ID from the context (ctx).
    const logoutUrl = new URL(
      `https://login.microsoftonline.com/${ctx.tenantId}/oauth2/v2.0/logout`
    );

    // 2. Set the post_logout_redirect_uri to redirect the user back to the Backstage base URL
    //    (e.g., the login screen) after Azure AD has logged them out.
    logoutUrl.searchParams.set('post_logout_redirect_uri', input.req.baseUrl);

    // 3. Perform the redirect using the Backstage required pattern (throwing a response object).
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