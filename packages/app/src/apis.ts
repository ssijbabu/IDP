import {
  ScmIntegrationsApi,
  scmIntegrationsApiRef,
  ScmAuth,
} from '@backstage/integration-react';
import {
  AnyApiFactory,
  configApiRef,
  createApiFactory,
  createApiRef,
  OAuthApi,
} from '@backstage/core-plugin-api';

export const azureFederatedAuthApiRef = createApiRef<OAuthApi>({
  id: 'auth.azure-federated',
});

export const apis: AnyApiFactory[] = [
  createApiFactory({
    api: scmIntegrationsApiRef,
    deps: { configApi: configApiRef },
    factory: ({ configApi }) => ScmIntegrationsApi.fromConfig(configApi),
  }),
  ScmAuth.createDefaultApiFactory(),
  createApiFactory({
    api: azureFederatedAuthApiRef,
    deps: {},
    factory: () => {
      // Create a complete OAuth API implementation for Azure
      return {
        // BackstageIdentityApi methods
        getBackstageIdentity: async () => {
          // This returns the Backstage user identity from the backend session
          const response = await fetch('/api/auth/me', {
            credentials: 'include',
          });
          if (!response.ok) {
            throw new Error('Failed to get user identity');
          }
          const data = await response.json();
          return {
            userEntityRef: data.identity.userEntityRef,
            ownershipEntityRefs: data.identity.ownershipEntityRefs || [],
          };
        },

        // ProfileInfoApi methods
        getProfile: async () => {
          const response = await fetch('/api/auth/me', {
            credentials: 'include',
          });
          if (!response.ok) {
            return {
              displayName: undefined,
              email: undefined,
              picture: undefined,
            };
          }
          const data = await response.json();
          return {
            displayName: data.profile?.displayName,
            email: data.profile?.email,
            picture: data.profile?.picture,
          };
        },

        // SessionApi methods
        getSession: async () => {
          const response = await fetch('/api/auth/me', {
            credentials: 'include',
          });
          if (!response.ok) {
            return undefined;
          }
          const data = await response.json();
          return {
            accessToken: data.accessToken,
            refreshToken: data.refreshToken,
          };
        },

        // OAuthApi methods
        getAccessToken: async () => {
          const response = await fetch('/api/auth/me', {
            credentials: 'include',
          });
          if (!response.ok) {
            return undefined as any;
          }
          const data = await response.json();
          return data.accessToken;
        },

        logout: async () => {
          // Logout handled by backend
          await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'include',
          }).catch(() => {
            // Ignore errors, just redirect
          });
        },
      } as any;
    },
  }),
];
