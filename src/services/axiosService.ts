import axios from 'axios';
import { MultiUserAxiosConfig, AxiosInterceptorConfig } from '../interfaces/axiosInterface';
import { IUser } from '../interfaces/userInterface';
import * as UserService from './userService';
import { Session } from './userService';

// ====================================
// 🔧 DEFAULT CONFIGURATION
// ====================================

const defaultConfig: AxiosInterceptorConfig = {
  baseURL: '',
  timeout: 30000,
  defaultHeaders: {
    'Content-Type': 'application/json',
  },
  validateStatus: (status: number) => status >= 200 && status < 300,
};

// ====================================
// 🔄 SERVICE STATE
// ====================================

let axiosService: MultiUserAxiosService | null = null;

class MultiUserAxiosService {
  private static instance: MultiUserAxiosService | null = null;
  private static config: AxiosInterceptorConfig | null = null;

  private axiosInstance: any;
  private activeSessionId: string | null = null;

  private constructor(config: AxiosInterceptorConfig) {
    this.axiosInstance = axios.create({
      ...defaultConfig,
      ...config,
      headers: {
        ...defaultConfig.defaultHeaders,
        ...config.defaultHeaders,
      },
    });

    this.setupInterceptors();
  }

  // ====================================
  // 🏭 SINGLETON MANAGEMENT
  // ====================================

  public static initialize(config: AxiosInterceptorConfig): MultiUserAxiosService {
    if (this.instance) {
      this.instance.dispose();
    }
    this.instance = new MultiUserAxiosService(config);
    return this.instance;
  }

  public static getInstance(): MultiUserAxiosService {
    if (!this.instance) {
      throw new Error('MultiUserAxiosService not initialized. Call initialize() first.');
    }
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
    if (this.axiosInstance) {
      this.axiosInstance.interceptors.request.clear();
      this.axiosInstance.interceptors.response.clear();
    }
    this.activeSessionId = null;
  }

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
              throw new Error(`Session ${sessionId} not found`);
            }
            
            // Check session validity
            const isValid = await UserService.isSessionValid(sessionId);
            if (!isValid) {
              throw new Error(`Session ${sessionId} has expired. Please authenticate again.`);
            }
            
            // Add authentication headers
            config.headers['Authorization'] = `Bearer ${session.accessToken}`;
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
        
        // Handle token refresh
        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;
          
          try {
            const sessionId = originalRequest.sessionId || this.activeSessionId;
            if (sessionId && !originalRequest.skipAuth) {
              const session = await UserService.getSessionById(sessionId);
              
              if (session) {
                if (session.refreshToken) {
                  try {
                    const newTokens = await this.refreshToken(sessionId);
                    if (newTokens) {
                      originalRequest.headers['Authorization'] = `Bearer ${newTokens.accessToken}`;
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
          } catch (error) {
            return Promise.reject(error);
          }
        }
        
        return Promise.reject(error);
      }
    );
  }

  // ====================================
  // 🔑 SESSION MANAGEMENT
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
    
    this.activeSessionId = sessionId;
    return sessionId;
  }

  public async setActiveSession(sessionId: string): Promise<boolean> {
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

  public async getActiveSession(): Promise<Session | null> {
    this.validateServiceState();
    
    if (this.activeSessionId) {
      return await UserService.getSessionById(this.activeSessionId);
    }
    return null;
  }

  public async getUserSession(userId: string): Promise<Session | null> {
    this.validateServiceState();
    return await UserService.getActiveUserSession(userId);
  }

  public async getSessionByToken(accessToken: string): Promise<Session | null> {
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
    return await UserService.isUserTokenExpired(userId);
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

    if (!session.refreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const response = await this.axiosInstance.post('/auth/refresh', {
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
      throw new Error(`Token refresh failed: ${error.message}`);
    }
  }

  // ====================================
  // 📡 HTTP METHODS
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
// 📤 EXPORTS
// ====================================

export const initializeAxiosService = (config: AxiosInterceptorConfig): MultiUserAxiosService => {
  axiosService = MultiUserAxiosService.initialize(config);
  return axiosService;
};

export const getAxiosService = (): MultiUserAxiosService => {
  if (!axiosService) {
    throw new Error('AxiosService not initialized');
  }
  return axiosService;
};

export const resetAxiosService = (): void => {
  MultiUserAxiosService.reset();
};

export const getSessionStats = async () => {
  if (!axiosService) {
    throw new Error('AxiosService not initialized');
  }
  return await UserService.getSessionStats();
};

export default MultiUserAxiosService;
