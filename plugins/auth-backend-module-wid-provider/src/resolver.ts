// src/resolver.ts
import { stringifyEntityRef, DEFAULT_NAMESPACE } from '@backstage/catalog-model';
import { 
  SignInResolver,
  OAuthAuthenticatorResult, 
} from '@backstage/plugin-auth-node';

import { AzureUserProfile } from './types'; 

/**
 * Backstage Catalog sign-in resolver that maps the authenticated user profile 
 * to a Backstage User entity using the email's local part.
 */
// 1. We apply the correct generic type to the exported resolver constant.
export const azureSignInResolver: SignInResolver<OAuthAuthenticatorResult<AzureUserProfile>> = async (
  // 2. We use standard destructuring: 'profile' is the full result object.
  { profile }, 
  ctx, 
) => {
  // 3. We explicitly tell TypeScript that 'profile' is the OAuthAuthenticatorResult
  //    (We no longer need to check if 'fullProfile' exists because the generic guarantees it).
  const result = profile as OAuthAuthenticatorResult<AzureUserProfile>;
  const userProfile = result.fullProfile; 

  if (!userProfile.email) {
    throw new Error('User profile does not contain an email');
  }

  // Use the local part of the email as the entity name
  const [localPart] = userProfile.email.split('@');
  
  return ctx.signInWithCatalogUser({
    entityRef: stringifyEntityRef({
      kind: 'User',
      name: localPart.toLowerCase(),
      namespace: DEFAULT_NAMESPACE,
    }),
  });
};