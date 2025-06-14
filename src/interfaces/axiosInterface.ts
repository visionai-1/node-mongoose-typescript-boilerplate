import { IUser } from './userInterface';

export interface UserSession {
  user: IUser;
  accessToken: string;
  refreshToken?: string;
  expiresAt: Date;
  isActive: boolean;
}

export interface MultiUserAxiosConfig {
  userId?: string;
  skipAuth?: boolean;
  retryOnTokenExpiry?: boolean;
}

export interface AxiosInterceptorConfig {
  baseURL: string;
  timeout?: number;
  defaultHeaders?: Record<string, string>;
  validateStatus?: (status: number) => boolean;
}

export interface TokenRefreshResponse {
  accessToken: string;
  refreshToken?: string;
  expiresAt: Date;
}

export interface ApiErrorResponse {
  error: {
    message: string;
    code: string;
    details?: any;
  };
} 