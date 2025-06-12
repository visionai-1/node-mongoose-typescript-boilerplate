import axios from 'axios';
import { 
  KeycloakConfig, 
  KeycloakTokenSet, 
  KeycloakTokenPayload, 
  KeycloakAuthRequest, 
  KeycloakAuthResponse,
  KeycloakUserSession,
  KeycloakUserInfo,
  KeycloakTokenIntrospection,
  KeycloakLogoutRequest,
  KeycloakServiceOptions,
  KeycloakError
} from '../interfaces/keycloakInterface';
import { IUser } from '../interfaces/userInterface';
import { isTokenExpired, decodeJWT } from '../utils';

// ====================================
// 🔧 DEFAULT CONFIGURATION
// ====================================

const defaultOptions: KeycloakServiceOptions = {
  autoRefreshToken: true,
  refreshThresholdSeconds: 30,
  enableUserInfo: true,
  enableTokenIntrospection: false,
  logLevel: 'info',
};

// ====================================
// 🔐 KEYCLOAK SERVICE
// ====================================

export class KeycloakService {
  private static instance: KeycloakService | null = null;
  private config: KeycloakConfig;
  private options: KeycloakServiceOptions;
  private axiosInstance: any;
  private tokenEndpoint: string;
  private userInfoEndpoint: string;
  private introspectionEndpoint: string;
  private logoutEndpoint: string;
  private authorizationEndpoint: string;

  private constructor(config: KeycloakConfig, options: KeycloakServiceOptions = {}) {
    this.config = config;
    this.options = { ...defaultOptions, ...options };
    
    // Build Keycloak endpoints
    const baseUrl = `${config.url}/realms/${config.realm}/protocol/openid-connect`;
    this.tokenEndpoint = `${baseUrl}/token`;
    this.userInfoEndpoint = `${baseUrl}/userinfo`;
    this.introspectionEndpoint = `${baseUrl}/token/introspect`;
    this.logoutEndpoint = `${baseUrl}/logout`;
    this.authorizationEndpoint = `${baseUrl}/auth`;

    // Create axios instance for Keycloak API calls
    this.axiosInstance = axios.create({
      timeout: 30000,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    this.setupInterceptors();
  }

  // ====================================
  // 🏭 SINGLETON MANAGEMENT
  // ====================================

  public static initialize(config: KeycloakConfig, options?: KeycloakServiceOptions): KeycloakService {
    if (this.instance) {
      this.instance.dispose();
    }
    this.instance = new KeycloakService(config, options);
    return this.instance;
  }

  public static getInstance(): KeycloakService {
    if (!this.instance) {
      throw new Error('KeycloakService not initialized. Call initialize() first.');
    }
    return this.instance;
  }

  public static reset(): void {
    if (this.instance) {
      this.instance.dispose();
    }
    this.instance = null;
  }

  public static isInitialized(): boolean {
    return this.instance !== null;
  }

  private setupInterceptors(): void {
    // Request interceptor for logging
    this.axiosInstance.interceptors.request.use(
      (config) => {
        if (this.options.logLevel === 'debug') {
          console.log(`[KeycloakService] Request: ${config.method?.toUpperCase()} ${config.url}`);
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor for error handling
    this.axiosInstance.interceptors.response.use(
      (response) => response,
      (error) => {
        const keycloakError: KeycloakError = new Error(
          error.response?.data?.error_description || error.response?.data?.error || error.message
        ) as KeycloakError;
        
        keycloakError.error = error.response?.data?.error || 'unknown_error';
        keycloakError.error_description = error.response?.data?.error_description;
        keycloakError.statusCode = error.response?.status;
        keycloakError.response = error.response?.data;

        if (this.options.logLevel !== 'none') {
          console.error('[KeycloakService] Error:', keycloakError);
        }

        return Promise.reject(keycloakError);
      }
    );
  }

  // ====================================
  // 🔑 AUTHENTICATION METHODS
  // ====================================

  public async authenticate(request: KeycloakAuthRequest): Promise<KeycloakAuthResponse> {
    try {
      const tokenSet = await this.getToken(request);
      const user = await this.createUserFromToken(tokenSet);
      
      return {
        success: true,
        tokenSet,
        user,
      };
    } catch (error) {
      const keycloakError = error as KeycloakError;
      return {
        success: false,
        error: keycloakError.error,
        errorDescription: keycloakError.error_description,
      };
    }
  }

  public async authenticateWithPassword(username: string, password: string, scope?: string): Promise<KeycloakAuthResponse> {
    return this.authenticate({
      username,
      password,
      grantType: 'password',
      scope: scope || 'openid profile email',
    });
  }

  public async authenticateWithCode(code: string, redirectUri?: string): Promise<KeycloakAuthResponse> {
    return this.authenticate({
      code,
      grantType: 'authorization_code',
      scope: 'openid profile email',
    });
  }

  public async refreshToken(refreshToken: string): Promise<KeycloakTokenSet> {
    const response = await this.authenticate({
      refreshToken,
      grantType: 'refresh_token',
    });

    if (!response.success || !response.tokenSet) {
      throw new Error(response.errorDescription || response.error || 'Token refresh failed');
    }

    return response.tokenSet;
  }

  // ====================================
  // 🎫 TOKEN MANAGEMENT
  // ====================================

  private async getToken(request: KeycloakAuthRequest): Promise<KeycloakTokenSet> {
    const params = new URLSearchParams();
    params.append('client_id', this.config.clientId);
    
    if (this.config.clientSecret) {
      params.append('client_secret', this.config.clientSecret);
    }

    params.append('grant_type', request.grantType);

    switch (request.grantType) {
      case 'password':
        if (!request.username || !request.password) {
          throw new Error('Username and password are required for password grant');
        }
        params.append('username', request.username);
        params.append('password', request.password);
        if (request.scope) params.append('scope', request.scope);
        break;

      case 'authorization_code':
        if (!request.code) {
          throw new Error('Code is required for authorization code grant');
        }
        params.append('code', request.code);
        params.append('redirect_uri', this.config.redirectUri || '');
        break;

      case 'refresh_token':
        if (!request.refreshToken) {
          throw new Error('Refresh token is required for refresh token grant');
        }
        params.append('refresh_token', request.refreshToken);
        break;

      case 'client_credentials':
        if (request.scope) params.append('scope', request.scope);
        break;

      default:
        throw new Error(`Unsupported grant type: ${request.grantType}`);
    }

    const response = await this.axiosInstance.post(this.tokenEndpoint, params);
    return response.data as KeycloakTokenSet;
  }

  public decodeToken(token: string): KeycloakTokenPayload {
    return decodeJWT(token) as KeycloakTokenPayload;
  }

  public isTokenValid(token: string): boolean {
    try {
      return !isTokenExpired(token);
    } catch {
      return false;
    }
  }

  public async introspectToken(token: string): Promise<KeycloakTokenIntrospection> {
    const params = new URLSearchParams();
    params.append('client_id', this.config.clientId);
    if (this.config.clientSecret) {
      params.append('client_secret', this.config.clientSecret);
    }
    params.append('token', token);

    const response = await this.axiosInstance.post(this.introspectionEndpoint, params);
    return response.data as KeycloakTokenIntrospection;
  }

  // ====================================
  // 👤 USER MANAGEMENT
  // ====================================

  private async createUserFromToken(tokenSet: KeycloakTokenSet): Promise<IUser> {
    const tokenPayload = this.decodeToken(tokenSet.access_token);
    let userInfo: KeycloakUserInfo | null = null;

    // Get additional user info if enabled
    if (this.options.enableUserInfo && tokenSet.access_token) {
      try {
        userInfo = await this.getUserInfo(tokenSet.access_token);
      } catch (error) {
        if (this.options.logLevel !== 'none') {
          console.warn('[KeycloakService] Failed to fetch user info:', error);
        }
      }
    }

    return {
      id: tokenPayload.sub,
      username: tokenPayload.preferred_username || userInfo?.preferred_username || tokenPayload.sub,
      email: tokenPayload.email || userInfo?.email || '',
      firstName: tokenPayload.given_name || userInfo?.given_name || '',
      lastName: tokenPayload.family_name || userInfo?.family_name || '',
      fullName: tokenPayload.name || userInfo?.name || `${tokenPayload.given_name || ''} ${tokenPayload.family_name || ''}`.trim(),
      isActive: true,
      emailVerified: tokenPayload.email_verified || userInfo?.email_verified || false,
      roles: this.extractRoles(tokenPayload),
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  public async getUserInfo(accessToken: string): Promise<KeycloakUserInfo> {
    const response = await this.axiosInstance.get(this.userInfoEndpoint, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
    return response.data as KeycloakUserInfo;
  }

  private extractRoles(tokenPayload: KeycloakTokenPayload): string[] {
    const roles: string[] = [];

    // Extract realm roles
    if (tokenPayload.realm_access?.roles) {
      roles.push(...tokenPayload.realm_access.roles);
    }

    // Extract client roles
    if (tokenPayload.resource_access) {
      Object.values(tokenPayload.resource_access).forEach(clientAccess => {
        if (clientAccess.roles) {
          roles.push(...clientAccess.roles);
        }
      });
    }

    return [...new Set(roles)]; // Remove duplicates
  }

  // ====================================
  // 🔄 SESSION MANAGEMENT
  // ====================================

  public createUserSession(
    tokenSet: KeycloakTokenSet,
    user: IUser,
    sessionId: string,
    browserInfo?: string
  ): KeycloakUserSession {
    const tokenPayload = this.decodeToken(tokenSet.access_token);
    const now = new Date();
    const expiresAt = new Date(tokenPayload.exp * 1000);
    const refreshExpiresAt = tokenSet.refresh_expires_in 
      ? new Date(now.getTime() + tokenSet.refresh_expires_in * 1000)
      : undefined;

    return {
      sessionId,
      userId: user.id,
      user,
      tokenSet,
      tokenPayload,
      expiresAt,
      refreshExpiresAt,
      isActive: true,
      lastActivity: now,
      createdAt: now,
      accessCount: 0,
      browserInfo,
      roles: this.extractRoles(tokenPayload),
      permissions: [], // Can be extended based on roles
    };
  }

  public shouldRefreshToken(session: KeycloakUserSession): boolean {
    if (!this.options.autoRefreshToken || !session.tokenSet.refresh_token) {
      return false;
    }

    const now = new Date();
    const refreshThreshold = this.options.refreshThresholdSeconds! * 1000;
    
    return (session.expiresAt.getTime() - now.getTime()) < refreshThreshold;
  }

  public async refreshUserSession(session: KeycloakUserSession): Promise<KeycloakUserSession> {
    if (!session.tokenSet.refresh_token) {
      throw new Error('No refresh token available');
    }

    const newTokenSet = await this.refreshToken(session.tokenSet.refresh_token);
    const newUser = await this.createUserFromToken(newTokenSet);
    
    return this.createUserSession(newTokenSet, newUser, session.sessionId, session.browserInfo);
  }

  // ====================================
  // 🚪 LOGOUT METHODS
  // ====================================

  public async logout(request: KeycloakLogoutRequest): Promise<void> {
    const params = new URLSearchParams();
    params.append('client_id', this.config.clientId);
    
    if (this.config.clientSecret) {
      params.append('client_secret', this.config.clientSecret);
    }

    if (request.refreshToken) {
      params.append('refresh_token', request.refreshToken);
    }

    if (this.config.postLogoutRedirectUri) {
      params.append('post_logout_redirect_uri', this.config.postLogoutRedirectUri);
    }

    try {
      await this.axiosInstance.post(this.logoutEndpoint, params);
    } catch (error) {
      if (this.options.logLevel !== 'none') {
        console.warn('[KeycloakService] Logout warning:', error);
      }
      // Don't throw error for logout - it might fail if token is already invalid
    }
  }

  // ====================================
  // 🔗 URL GENERATION
  // ====================================

  public getAuthorizationUrl(state?: string, nonce?: string): string {
    const params = new URLSearchParams();
    params.append('client_id', this.config.clientId);
    params.append('redirect_uri', this.config.redirectUri || '');
    params.append('response_type', 'code');
    params.append('scope', this.config.scope || 'openid profile email');
    
    if (state) params.append('state', state);
    if (nonce) params.append('nonce', nonce);

    return `${this.authorizationEndpoint}?${params.toString()}`;
  }

  public getLogoutUrl(redirectUri?: string): string {
    const params = new URLSearchParams();
    params.append('client_id', this.config.clientId);
    
    if (redirectUri || this.config.postLogoutRedirectUri) {
      params.append('post_logout_redirect_uri', redirectUri || this.config.postLogoutRedirectUri!);
    }

    return `${this.logoutEndpoint}?${params.toString()}`;
  }

  // ====================================
  // 🧹 CLEANUP
  // ====================================

  public dispose(): void {
    if (this.axiosInstance) {
      this.axiosInstance.interceptors.request.clear();
      this.axiosInstance.interceptors.response.clear();
    }
  }

  // ====================================
  // ⚙️ CONFIGURATION
  // ====================================

  public getConfig(): KeycloakConfig {
    return { ...this.config };
  }

  public updateOptions(options: Partial<KeycloakServiceOptions>): void {
    this.options = { ...this.options, ...options };
  }

  public getOptions(): KeycloakServiceOptions {
    return { ...this.options };
  }
}

// ====================================
// 📤 EXPORTS
// ====================================

export default KeycloakService;