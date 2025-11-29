// src/module.ts
import { createBackendModule } from '@backstage/backend-plugin-api';
import {
  authProvidersExtensionPoint,
  createOAuthProviderFactory,
} from '@backstage/plugin-auth-node';
import { azureFederatedAuthenticator } from './authenticator';
import { azureSignInResolver } from './resolver';
import { AzureUserProfile } from './types'; // <-- Import the type for the factory


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
          // FIX: Pass the generic type <AzureUserProfile> to align the authenticator and resolver.
          factory: createOAuthProviderFactory<AzureUserProfile>({
            authenticator: azureFederatedAuthenticator,
            signInResolver: azureSignInResolver,
          }),
        });
      },
    });
  },
});