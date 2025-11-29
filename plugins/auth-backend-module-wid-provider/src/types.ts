// src/types.ts

/**
 * Configuration options for the Azure Federated Provider, including
 * Workload Identity Federation (WIF) fields.
 */
export interface AzureFederatedConfig {
  tenantId: string;
  clientId: string;
  clientSecret?: string;
  federatedTokenFile?: string;
  callbackUrl: string;
}

/**
 * Expected user profile data from Azure/ID Token claims or MS Graph.
 */
export interface AzureUserProfile {
  sub: string; // Subject identifier (often immutable ID)
  name: string;
  email: string;
  preferred_username?: string;
  oid: string; // Object ID (immutable ID for the user object)
}

/**
 * Expected token response structure from the Azure AD token endpoint.
 */
export interface AzureTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
  id_token?: string;
  refresh_token?: string;
}