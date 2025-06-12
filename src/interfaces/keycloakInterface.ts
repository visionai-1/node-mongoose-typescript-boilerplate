import { IUser } from './userInterface';

// ====================================
// 🔐 KEYCLOAK CONFIGURATION
// ====================================

export interface KeycloakConfig {
  url: string;
  realm: string;
  clientId: string;
  clientSecret?: string;
  publicClient?: boolean;
  scope?: string;
  redirectUri?: string;
  postLogoutRedirectUri?: string;
}

// ====================================
// 🎫 KEYCLOAK TOKEN INTERFACES
// ====================================

export interface KeycloakTokenSet {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  expires_in: number;
  refresh_expires_in?: number;
  scope?: string;
  session_state?: string;
}

export interface KeycloakTokenPayload {
  exp: number;
  iat: number;
  jti: string;
  iss: string;
  aud: string | string[];
  sub: string;
  typ: string;
  azp: string;
  session_state?: string;
  acr?: string;
  scope?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  given_name?: string;
  family_name?: string;
  email?: string;
  realm_access?: {
    roles: string[];
  };
  resource_access?: {
    [key: string]: {
      roles: string[];
    };
  };
}

// ====================================
// 👤 KEYCLOAK USER SESSION
// ====================================

export interface KeycloakUserSession {
  sessionId: string;
  userId: string;
  user: IUser;
  tokenSet: KeycloakTokenSet;
  tokenPayload: KeycloakTokenPayload;
  expiresAt: Date;
  refreshExpiresAt?: Date;
  isActive: boolean;
  lastActivity: Date;
  createdAt: Date;
  accessCount: number;
  browserInfo?: string;
  roles: string[];
  permissions: string[];
}

// ====================================
// 🔄 KEYCLOAK AUTHENTICATION
// ====================================

export interface KeycloakAuthRequest {
  username?: string;
  password?: string;
  code?: string;
  refreshToken?: string;
  grantType: 'password' | 'authorization_code' | 'refresh_token' | 'client_credentials';
  scope?: string;
}

export interface KeycloakAuthResponse {
  success: boolean;
  tokenSet?: KeycloakTokenSet;
  user?: IUser;
  error?: string;
  errorDescription?: string;
}

export interface KeycloakLogoutRequest {
  refreshToken?: string;
  sessionId?: string;
}

export interface KeycloakUserInfo {
  sub: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  given_name?: string;
  family_name?: string;
  email?: string;
  roles?: string[];
}

// ====================================
// 🔍 KEYCLOAK TOKEN INTROSPECTION
// ====================================

export interface KeycloakTokenIntrospection {
  active: boolean;
  scope?: string;
  client_id?: string;
  username?: string;
  token_type?: string;
  exp?: number;
  iat?: number;
  sub?: string;
  aud?: string | string[];
  iss?: string;
  jti?: string;
}

// ====================================
// ⚙️ KEYCLOAK SERVICE OPTIONS
// ====================================

export interface KeycloakServiceOptions {
  autoRefreshToken?: boolean;
  refreshThresholdSeconds?: number;
  enableUserInfo?: boolean;
  enableTokenIntrospection?: boolean;
  logLevel?: 'debug' | 'info' | 'warn' | 'error' | 'none';
}

export interface KeycloakError extends Error {
  error: string;
  error_description?: string;
  statusCode?: number;
  response?: any;
} 