// src/module.ts
import { createBackendModule } from '@backstage/backend-plugin-api';
import {
  authProvidersExtensionPoint,
  createOAuthProviderFactory,
} from '@backstage/plugin-auth-node';
import { azureFederatedAuthenticator } from './authenticator';
import { azureSignInResolver } from './resolver';
import { AzureUserProfile } from './types';


export const authModuleWidProvider = createBackendModule({
  pluginId: 'auth',
  moduleId: 'azure-federated-provider',
  register(reg) {
    reg.registerInit({
      deps: {
        providers: authProvidersExtensionPoint,
      },
      async init({ providers }) {
        providers.registerProvider({
          providerId: 'azure-federated',
          factory: createOAuthProviderFactory<AzureUserProfile>({
            authenticator: azureFederatedAuthenticator,
            signInResolver: azureSignInResolver,
          }),
        });
      },
    });
  },
});