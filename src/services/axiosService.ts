import axios from 'axios';
import { MultiUserAxiosConfig, AxiosInterceptorConfig } from '../interfaces/axiosInterface';
import { KeycloakConfig, KeycloakServiceOptions } from '../interfaces/keycloakInterface';
import { IUser } from '../interfaces/userInterface';
import { isTokenExpired } from '../utils';
// import KeycloakService from './keycloakService';
import * as UserService from './userService';
import { SessionData } from './userService';

// ====================================
// 🔧 DEFAULT CONFIGURATION
// ====================================

const defaultConfig: AxiosInterceptorConfig = {
  baseURL: process.env.API_BASE_URL || 'http://localhost:3000/api',
  timeout: 30000,
  defaultHeaders: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
};

let axiosService: MultiUserAxiosService | null = null;

class MultiUserAxiosService {
  private static instance: MultiUserAxiosService | null = null;
  private static config: AxiosInterceptorConfig | null = null;

  private axiosInstance: any;
  private activeSessionId: string | null = null;

  private constructor(config: AxiosInterceptorConfig) {
    this.axiosInstance = axios.create({
      baseURL: config.baseURL,
      timeout: config.timeout || 30000,
      headers: {
        'Content-Type': 'application/json',
        ...config.defaultHeaders,
      },
    });

    this.setupInterceptors();
  }

  // ====================================
  // 🏭 SINGLETON MANAGEMENT
  // ====================================

  public static async initialize(config: AxiosInterceptorConfig): Promise<MultiUserAxiosService> {
    if (this.instance) {
      this.instance.dispose();
    }

    // Initialize the UserService
    UserService.initializeUserService();
    
    this.config = config;
    this.instance = new MultiUserAxiosService(config);
    
    // Set global instance
    axiosService = this.instance;
    
    return this.instance;
  }

  public static reset(): void {
    if (this.instance) {
      this.instance.dispose();
    }
    this.instance = null;
    this.config = null;
    axiosService = null;
    
    // Reset UserService
    UserService.resetUserService();
  }

  public static isInitialized(): boolean {
    return this.instance !== null;
  }

  public dispose(): void {
    // Clear axios instance
    if (this.axiosInstance) {
      this.axiosInstance.interceptors.request.clear();
      this.axiosInstance.interceptors.response.clear();
    }
    this.activeSessionId = null;
  }

  // ====================================
  // 🔧 INTERCEPTORS SETUP
  // ====================================

  private setupInterceptors(): void {
    // Request interceptor
    this.axiosInstance.interceptors.request.use(
      async (config: any) => {
        if (!MultiUserAxiosService.isInitialized()) {
          throw new Error('MultiUserAxiosService not properly initialized');
        }

        const customConfig = config as any & MultiUserAxiosConfig;
        
        if (!customConfig.skipAuth) {
          const sessionId = customConfig.sessionId || this.activeSessionId;
          
          if (sessionId) {
            const session = await UserService.getSessionById(sessionId);
            
            if (!session) {
              throw new Error(`Session ${sessionId} not found. Please authenticate again.`);
            }
            
            if (!session.isActive) {
              throw new Error(`Session ${sessionId} is inactive. Please authenticate again.`);
            }
            
            // Check session validity
            const isValid = await UserService.isSessionValid(sessionId);
            if (!isValid) {
              throw new Error(`Session ${sessionId} has expired. Please authenticate again.`);
            }

            // Get access token based on session type
            const accessToken = session.type === 'custom' 
              ? session.accessToken 
              : session.tokenSet.access_token;
            
            // Add authentication headers
            config.headers['Authorization'] = `Bearer ${accessToken}`;
            config.headers['X-User-ID'] = session.userId;
            config.headers['X-Session-ID'] = sessionId;
          } else {
            throw new Error('No active session found. Please authenticate to access this resource.');
          }
        }

        config.metadata = {
          ...config.metadata,
          requestStartTime: Date.now(),
          serviceVersion: '2.0.0'
        };

        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor
    this.axiosInstance.interceptors.response.use(
      (response: any) => {
        const requestStartTime = response.config.metadata?.requestStartTime;
        if (requestStartTime) {
          response.metadata = {
            ...response.metadata,
            responseTime: Date.now() - requestStartTime
          };
        }
        return response;
      },
      async (error: any) => {
        const originalRequest = error.config;

        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;

          const sessionId = originalRequest.sessionId || this.activeSessionId;
          if (sessionId && !originalRequest.skipAuth) {
            const session = await UserService.getSessionById(sessionId);
            
            if (session) {
              const refreshToken = session.type === 'custom' 
                ? session.refreshToken 
                : session.tokenSet.refresh_token;

              if (refreshToken) {
                try {
                  const newTokens = await this.refreshToken(sessionId);
                  if (newTokens) {
                    const accessToken = session.type === 'custom'
                      ? newTokens.accessToken
                      : newTokens.access_token;
                    originalRequest.headers['Authorization'] = `Bearer ${accessToken}`;
                    return this.axiosInstance(originalRequest);
                  }
                } catch (refreshError) {
                  await UserService.removeSession(sessionId);
                  return Promise.reject(new Error(`Token refresh failed: ${refreshError.message}`));
                }
              } else {
                await UserService.removeSession(sessionId);
                return Promise.reject(new Error('Session invalid and no refresh token available'));
              }
            }
          }
        }

        return Promise.reject(error);
      }
    );
  }

  // ====================================
  // 📝 SESSION MANAGEMENT
  // ====================================

  public async createUserSession(userId: string, user: IUser, accessToken: string, refreshToken?: string, expiresAt?: Date, browserInfo?: string): Promise<string> {
    this.validateServiceState();
    
    const sessionId = await UserService.createUserSession(
      userId,
      user,
      accessToken,
      refreshToken,
      expiresAt,
      browserInfo
    );

    if (!this.activeSessionId) {
      this.activeSessionId = sessionId;
    }

    return sessionId;
  }

  public async createKeycloakSession(userId: string, user: IUser, tokenSet: any, browserInfo?: string): Promise<string> {
    this.validateServiceState();
    
    const sessionId = await UserService.createKeycloakUserSession(
      userId,
      user,
      tokenSet,
      browserInfo
    );

    if (!this.activeSessionId) {
      this.activeSessionId = sessionId;
    }

    return sessionId;
  }

  public async switchActiveSession(sessionId: string): Promise<boolean> {
    this.validateServiceState();
    
    const isValid = await UserService.isSessionValid(sessionId);
    if (isValid) {
      this.activeSessionId = sessionId;
      return true;
    }
    return false;
  }

  public async removeSession(sessionId: string): Promise<boolean> {
    this.validateServiceState();
    
    const result = await UserService.removeSession(sessionId);
    
    if (this.activeSessionId === sessionId) {
      this.activeSessionId = null;
    }
    
    return result;
  }

  public async getActiveSession(): Promise<SessionData | null> {
    this.validateServiceState();
    
    if (this.activeSessionId) {
      return await UserService.getSessionById(this.activeSessionId);
    }
    return null;
  }

  public async getUserSession(userId: string): Promise<SessionData | null> {
    this.validateServiceState();
    return await UserService.getActiveUserSession(userId);
  }

  public async getSessionByToken(accessToken: string): Promise<SessionData | null> {
    this.validateServiceState();
    return await UserService.getSessionByToken(accessToken);
  }

  // Legacy methods for backward compatibility
  public async addUserSession(userId: string, user: IUser, accessToken: string, refreshToken?: string, expiresAt?: Date): Promise<void> {
    await this.createUserSession(userId, user, accessToken, refreshToken, expiresAt);
  }

  public async removeUserSession(userId: string): Promise<void> {
    this.validateServiceState();
    await UserService.removeUserSessions(userId);
  }

  public async clearAllSessions(): Promise<void> {
    this.validateServiceState();
    await UserService.clearAllSessions();
    this.activeSessionId = null;
  }

  public async isTokenExpired(userId: string): Promise<boolean> {
    this.validateServiceState();
    
    const session = await UserService.getActiveUserSession(userId);
    if (!session) return true;
    
    const accessToken = session.type === 'custom' 
      ? session.accessToken 
      : session.tokenSet.access_token;
    
    return isTokenExpired(accessToken);
  }

  public async isSessionTokenExpired(sessionId: string): Promise<boolean> {
    this.validateServiceState();
    return !(await UserService.isSessionValid(sessionId));
  }

  // ====================================
  // 🔄 TOKEN REFRESH
  // ====================================

  private async refreshToken(sessionId: string): Promise<any> {
    const session = await UserService.getSessionById(sessionId);
    if (!session) return null;

    if (session.type === 'keycloak') {
      if (!session.tokenSet.refresh_token) return null;

      try {
        // TODO: Implement Keycloak token refresh when KeycloakService is fixed
        // const keycloakService = KeycloakService.getInstance();
        // const newTokenSet = await keycloakService.refreshToken(session.tokenSet.refresh_token);
        
        // For now, return null to indicate refresh failed
        console.warn('[AxiosService] Keycloak token refresh temporarily disabled');
        return null;
      } catch (error) {
        throw new Error(`Keycloak token refresh failed: ${error.message}`);
      }
    } else {
      // For custom sessions, implement your custom refresh logic here
      if (!session.refreshToken) return null;
      
      try {
        const response = await axios.post('/auth/refresh', {
          refreshToken: session.refreshToken,
        });

        const newTokens = response.data as any;
        await UserService.updateSession(sessionId, {
          accessToken: newTokens.accessToken,
          refreshToken: newTokens.refreshToken || session.refreshToken,
          expiresAt: new Date(newTokens.expiresAt || Date.now() + 24 * 60 * 60 * 1000),
        } as any);

        return newTokens;
      } catch (error) {
        throw new Error(`Custom token refresh failed: ${error.message}`);
      }
    }
  }

  // ====================================
  // 🌐 HTTP METHODS
  // ====================================

  public async get(url: string, config?: any & MultiUserAxiosConfig): Promise<any> {
    this.validateServiceState();
    return this.axiosInstance.get(url, config);
  }

  public async post(url: string, data?: any, config?: any & MultiUserAxiosConfig): Promise<any> {
    this.validateServiceState();
    return this.axiosInstance.post(url, data, config);
  }

  public async put(url: string, data?: any, config?: any & MultiUserAxiosConfig): Promise<any> {
    this.validateServiceState();
    return this.axiosInstance.put(url, data, config);
  }

  public async patch(url: string, data?: any, config?: any & MultiUserAxiosConfig): Promise<any> {
    this.validateServiceState();
    return this.axiosInstance.patch(url, data, config);
  }

  public async delete(url: string, config?: any & MultiUserAxiosConfig): Promise<any> {
    this.validateServiceState();
    return this.axiosInstance.delete(url, config);
  }

  // ====================================
  // 🔧 UTILITIES
  // ====================================

  private validateServiceState(): void {
    if (!MultiUserAxiosService.isInitialized()) {
      throw new Error('MultiUserAxiosService not initialized. Call initializeAxiosService() first.');
    }
    
    if (!this.axiosInstance) {
      throw new Error('Axios instance not available. Service may not be properly configured.');
    }
  }

  public getAxiosInstance(): any {
    this.validateServiceState();
    return this.axiosInstance;
  }
}

// ====================================
// 🔧 CORE AXIOS UTILITIES
// ====================================

export const initializeAxiosService = async (customConfig?: Partial<AxiosInterceptorConfig>) => {
  const config = { ...defaultConfig, ...customConfig };
  return await MultiUserAxiosService.initialize(config);
};

export const resetAxiosService = () => {
  MultiUserAxiosService.reset();
};

export const getAxiosServiceSessionStats = async () => {
  if (!axiosService) {
    throw new Error('AxiosService not initialized');
  }
  return await UserService.getSessionStats();
};

// ====================================
// 📤 EXPORTS
// ====================================

export default MultiUserAxiosService;
export { axiosService };
