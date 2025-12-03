import {
  ScmIntegrationsApi,
  scmIntegrationsApiRef,
  ScmAuth,
} from '@backstage/integration-react';

import { OAuth2 } from '@backstage/core-app-api';

import {
  AnyApiFactory,
  ApiRef,
  configApiRef,
  createApiFactory,
  createApiRef,
  OpenIdConnectApi,
  ProfileInfoApi,
  BackstageIdentityApi,
  SessionApi,
  discoveryApiRef,
  oauthRequestApiRef,
} from '@backstage/core-plugin-api';

export const azureFederatedAuthApiRef: ApiRef<
  OpenIdConnectApi & // The OIDC API that will handle authentification
  ProfileInfoApi & // Profile API for requesting user profile info from the auth provider in question
  BackstageIdentityApi & // Backstage Identity API to handle and associate the user profile with backstage identity
  SessionApi // Sesssion API, to handle the session the user will have while logged in
> = createApiRef({
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
    deps: {
      discoveryApi: discoveryApiRef,
      oauthRequestApi: oauthRequestApiRef,
      configApi: configApiRef
    },
    factory: ({ discoveryApi, oauthRequestApi, configApi }) => OAuth2.create({
      configApi,
      discoveryApi,
      oauthRequestApi,
      provider: {
        id: 'oidc',
        title: 'Azure Federated',
        icon: () => null
      },
      environment: configApi.getOptionalString('auth.environment'),
      defaultScopes: ['openid', 'profile', 'email', 'offline_access'],
      popupOptions: {
        size: {
          // fullscreen: true
          // or specify popup width and height
          width: 1000,
          height: 1000,
        }
      }
    })
  })
];
