import { IUser } from '../interfaces/userInterface';
import { KeycloakTokenSet } from '../interfaces/keycloakInterface';
import { isTokenExpired, decodeJWT } from '../utils';
import { v4 as uuidv4 } from 'uuid';

// ====================================
// 📝 SESSION INTERFACES
// ====================================

export interface BaseSession {
  sessionId: string;
  userId: string;
  user: IUser;
  isActive: boolean;
  createdAt: Date;
  lastActivity: Date;
  accessCount: number;
  browserInfo?: string;
  type: 'custom' | 'keycloak';
}

export interface CustomSession extends BaseSession {
  type: 'custom';
  accessToken: string;
  refreshToken?: string;
  expiresAt: Date;
}

export interface KeycloakSession extends BaseSession {
  type: 'keycloak';
  tokenSet: KeycloakTokenSet;
  roles: string[];
  permissions: string[];
  expiresAt: Date;
  refreshExpiresAt?: Date;
}

export type SessionData = CustomSession | KeycloakSession;

// ====================================
// 🔧 MODULE STATE - IN-MEMORY SESSION STORE
// ====================================

let sessions: Map<string, SessionData> = new Map();
let userSessionMappings: Map<string, Set<string>> = new Map();
let cleanupInterval: NodeJS.Timeout | null = null;

// ====================================
// 🧹 CLEANUP FUNCTIONS
// ====================================

/**
 * Start automatic cleanup of expired sessions
 */
const startCleanupProcess = (): void => {
  if (cleanupInterval) return; // Already started
  
  cleanupInterval = setInterval(() => {
    performCleanup();
  }, 5 * 60 * 1000); // Every 5 minutes
};

/**
 * Perform cleanup of expired sessions
 */
const performCleanup = (): void => {
  const now = new Date();
  let cleanedCount = 0;
  
  for (const [sessionId, session] of sessions.entries()) {
    if (session.expiresAt < now || !session.isActive) {
      removeSessionFromStore(sessionId);
      cleanedCount++;
    }
  }
  
  if (cleanedCount > 0) {
    console.log(`[UserService] Cleaned up ${cleanedCount} expired sessions`);
  }
};

/**
 * Stop cleanup process
 */
const stopCleanupProcess = (): void => {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
  }
};

// ====================================
// 🔧 PRIVATE HELPER FUNCTIONS
// ====================================

/**
 * Remove session from in-memory store
 */
const removeSessionFromStore = (sessionId: string): void => {
  const session = sessions.get(sessionId);
  if (session) {
    sessions.delete(sessionId);
    
    // Remove from user mapping
    const userSessions = userSessionMappings.get(session.userId);
    if (userSessions) {
      userSessions.delete(sessionId);
      if (userSessions.size === 0) {
        userSessionMappings.delete(session.userId);
      }
    }
  }
};

/**
 * Add session to user mapping
 */
const addSessionToUserMapping = (userId: string, sessionId: string): void => {
  if (!userSessionMappings.has(userId)) {
    userSessionMappings.set(userId, new Set());
  }
  userSessionMappings.get(userId)!.add(sessionId);
};

/**
 * Update session activity
 */
const updateSessionActivity = (sessionId: string): void => {
  const session = sessions.get(sessionId);
  if (session) {
    session.lastActivity = new Date();
    session.accessCount++;
  }
};

// ====================================
// 📝 SESSION CREATION FUNCTIONS
// ====================================

/**
 * Create a new user session with custom authentication
 */
export const createUserSession = async (
  userId: string,
  user: IUser,
  accessToken: string,
  refreshToken?: string,
  expiresAt?: Date,
  browserInfo?: string
): Promise<string> => {
  const sessionId = uuidv4();
  const now = new Date();
  
  const session: CustomSession = {
    sessionId,
    userId,
    user,
    type: 'custom',
    accessToken,
    refreshToken,
    expiresAt: expiresAt || new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours default
    isActive: true,
    createdAt: now,
    lastActivity: now,
    accessCount: 0,
    browserInfo,
  };

  sessions.set(sessionId, session);
  addSessionToUserMapping(userId, sessionId);
  
  // Start cleanup process if not already started
  startCleanupProcess();
  
  return sessionId;
};

/**
 * Create a new user session with Keycloak authentication
 */
export const createKeycloakUserSession = async (
  userId: string,
  user: IUser,
  tokenSet: KeycloakTokenSet,
  browserInfo?: string
): Promise<string> => {
  const sessionId = uuidv4();
  const now = new Date();
  
  // Decode token to get expiration and roles
  const tokenPayload = decodeJWT(tokenSet.access_token);
  const expiresAt = new Date(tokenPayload.exp * 1000);
  const refreshExpiresAt = tokenSet.refresh_expires_in 
    ? new Date(Date.now() + tokenSet.refresh_expires_in * 1000)
    : undefined;

  // Extract roles
  const roles: string[] = [];
  if (tokenPayload.realm_access?.roles) {
    roles.push(...tokenPayload.realm_access.roles);
  }
  if (tokenPayload.resource_access) {
    Object.values(tokenPayload.resource_access).forEach((clientAccess: any) => {
      if (clientAccess.roles) {
        roles.push(...clientAccess.roles);
      }
    });
  }

  const session: KeycloakSession = {
    sessionId,
    userId,
    user,
    type: 'keycloak',
    tokenSet,
    roles: [...new Set(roles)],
    permissions: [],
    expiresAt,
    refreshExpiresAt,
    isActive: true,
    createdAt: now,
    lastActivity: now,
    accessCount: 0,
    browserInfo,
  };

  sessions.set(sessionId, session);
  addSessionToUserMapping(userId, sessionId);
  
  // Start cleanup process if not already started
  startCleanupProcess();
  
  return sessionId;
};

// ====================================
// 📖 SESSION RETRIEVAL FUNCTIONS
// ====================================

/**
 * Get active session for a user
 */
export const getActiveUserSession = async (userId: string): Promise<SessionData | null> => {
  const userSessions = userSessionMappings.get(userId);
  if (!userSessions) return null;
  
  for (const sessionId of userSessions) {
    const session = sessions.get(sessionId);
    if (session && session.isActive && await isSessionValid(sessionId)) {
      updateSessionActivity(sessionId);
      return session;
    }
  }
  
  return null;
};

/**
 * Get all sessions for a user
 */
export const getUserSessions = async (userId: string): Promise<SessionData[]> => {
  const userSessions = userSessionMappings.get(userId);
  if (!userSessions) return [];
  
  const validSessions: SessionData[] = [];
  
  for (const sessionId of userSessions) {
    const session = sessions.get(sessionId);
    if (session && session.isActive && await isSessionValid(sessionId)) {
      validSessions.push(session);
    }
  }
  
  return validSessions;
};

/**
 * Get session by session ID
 */
export const getSessionById = async (sessionId: string): Promise<SessionData | null> => {
  const session = sessions.get(sessionId);
  if (!session) return null;
  
  if (await isSessionValid(sessionId)) {
    updateSessionActivity(sessionId);
    return session;
  }
  
  return null;
};

/**
 * Find session by access token
 */
export const getSessionByToken = async (accessToken: string): Promise<SessionData | null> => {
  for (const session of sessions.values()) {
    if (session.type === 'custom' && session.accessToken === accessToken) {
      if (await isSessionValid(session.sessionId)) {
        updateSessionActivity(session.sessionId);
        return session;
      }
    } else if (session.type === 'keycloak' && session.tokenSet.access_token === accessToken) {
      if (await isSessionValid(session.sessionId)) {
        updateSessionActivity(session.sessionId);
        return session;
      }
    }
  }
  
  return null;
};

// ====================================
// 🔄 SESSION MANAGEMENT FUNCTIONS
// ====================================

/**
 * Update session data
 */
export const updateSession = async (sessionId: string, updates: Partial<SessionData>): Promise<boolean> => {
  const session = sessions.get(sessionId);
  if (!session) return false;

  // Merge updates
  Object.assign(session, updates, { lastActivity: new Date() });
  
  return true;
};

/**
 * Remove a specific session
 */
export const removeSession = async (sessionId: string): Promise<boolean> => {
  if (sessions.has(sessionId)) {
    removeSessionFromStore(sessionId);
    return true;
  }
  return false;
};

/**
 * Remove all sessions for a user
 */
export const removeUserSessions = async (userId: string): Promise<number> => {
  const userSessions = userSessionMappings.get(userId);
  if (!userSessions) return 0;
  
  const sessionIds = Array.from(userSessions);
  let removedCount = 0;
  
  for (const sessionId of sessionIds) {
    if (await removeSession(sessionId)) {
      removedCount++;
    }
  }
  
  return removedCount;
};

/**
 * Clear all sessions
 */
export const clearAllSessions = async (): Promise<number> => {
  const sessionCount = sessions.size;
  sessions.clear();
  userSessionMappings.clear();
  return sessionCount;
};

// ====================================
// 🔍 SESSION VALIDATION FUNCTIONS
// ====================================

/**
 * Check if session is valid
 */
export const isSessionValid = async (sessionId: string): Promise<boolean> => {
  const session = sessions.get(sessionId);
  if (!session || !session.isActive) return false;

  // Check expiration
  const now = new Date();
  if (session.expiresAt < now) {
    removeSessionFromStore(sessionId);
    return false;
  }

  // Check token expiration
  try {
    if (session.type === 'custom') {
      if (isTokenExpired(session.accessToken)) {
        removeSessionFromStore(sessionId);
        return false;
      }
    } else if (session.type === 'keycloak') {
      if (isTokenExpired(session.tokenSet.access_token)) {
        removeSessionFromStore(sessionId);
        return false;
      }
    }
  } catch (error) {
    removeSessionFromStore(sessionId);
    return false;
  }

  return true;
};

/**
 * Check if user token is expired
 */
export const isUserTokenExpired = async (userId: string): Promise<boolean> => {
  const session = await getActiveUserSession(userId);
  if (!session) return true;

  const accessToken = session.type === 'custom' 
    ? session.accessToken 
    : session.tokenSet.access_token;

  return isTokenExpired(accessToken);
};

/**
 * Check if specific session token is expired
 */
export const isSessionTokenExpired = async (sessionId: string): Promise<boolean> => {
  return !(await isSessionValid(sessionId));
};

// ====================================
// 📊 STATISTICS & MONITORING FUNCTIONS
// ====================================

/**
 * Get session statistics
 */
export const getSessionStats = async (): Promise<{
  totalSessions: number;
  activeSessions: number;
  userCount: number;
  keycloakSessions: number;
  customSessions: number;
}> => {
  const now = new Date();
  let activeSessions = 0;
  let keycloakSessions = 0;
  let customSessions = 0;
  const userIds = new Set<string>();

  for (const session of sessions.values()) {
    userIds.add(session.userId);
    
    if (session.isActive && session.expiresAt > now) {
      activeSessions++;
    }
    
    if (session.type === 'keycloak') {
      keycloakSessions++;
    } else {
      customSessions++;
    }
  }

  return {
    totalSessions: sessions.size,
    activeSessions,
    userCount: userIds.size,
    keycloakSessions,
    customSessions,
  };
};

/**
 * Get sessions count per user
 */
export const getUserSessionCounts = async (): Promise<{ [userId: string]: number }> => {
  const counts: { [userId: string]: number } = {};
  
  for (const [userId, sessionIds] of userSessionMappings) {
    counts[userId] = sessionIds.size;
  }
  
  return counts;
};

// ====================================
// 🔧 UTILITY FUNCTIONS
// ====================================

/**
 * Extract user info from session
 */
export const getUserFromSession = (session: SessionData): IUser => {
  return session.user;
};

/**
 * Get access token from session
 */
export const getAccessTokenFromSession = (session: SessionData): string => {
  return session.type === 'custom' 
    ? session.accessToken 
    : session.tokenSet.access_token;
};

/**
 * Get refresh token from session
 */
export const getRefreshTokenFromSession = (session: SessionData): string | undefined => {
  return session.type === 'custom' 
    ? session.refreshToken 
    : session.tokenSet.refresh_token;
};

/**
 * Check if session is Keycloak session
 */
export const isKeycloakSession = (session: SessionData): session is KeycloakSession => {
  return session.type === 'keycloak';
};

/**
 * Check if session is custom session
 */
export const isCustomSession = (session: SessionData): session is CustomSession => {
  return session.type === 'custom';
};

// ====================================
// 🔄 SYSTEM MANAGEMENT
// ====================================

/**
 * Reset the session service (clear all sessions and stop cleanup)
 */
export const resetUserService = (): void => {
  sessions.clear();
  userSessionMappings.clear();
  stopCleanupProcess();
};

/**
 * Initialize the session service
 */
export const initializeUserService = (): void => {
  startCleanupProcess();
};

// ====================================
// 🎯 FUNCTIONAL COMPOSITION HELPERS
// ====================================

/**
 * Compose session validation with action execution
 */
export const withSessionValidation = <T>(
  action: (session: SessionData) => Promise<T>
) => async (sessionId: string): Promise<T | null> => {
  const session = await getSessionById(sessionId);
  if (!session) return null;
  
  const isValid = await isSessionValid(sessionId);
  if (!isValid) return null;
  
  return await action(session);
};

/**
 * Compose user session lookup with action execution
 */
export const withUserSession = <T>(
  action: (session: SessionData) => Promise<T>
) => async (userId: string): Promise<T | null> => {
  const session = await getActiveUserSession(userId);
  if (!session) return null;
  
  return await action(session);
};

/**
 * Create a session filter function
 */
export const createSessionFilter = (
  predicate: (session: SessionData) => boolean
) => (sessions: SessionData[]): SessionData[] => {
  return sessions.filter(predicate);
};

/**
 * Session mapper function
 */
export const mapSessions = <T>(
  mapper: (session: SessionData) => T
) => (sessions: SessionData[]): T[] => {
  return sessions.map(mapper);
};

/**
 * Pipe function for composing operations
 */
export const pipe = <T, U>(fn1: (arg: T) => U) => (value: T): U => fn1(value);

/**
 * Compose multiple functions - variadic pipe
 */
export const compose = <T>(...fns: Array<(arg: any) => any>) => (value: T) =>
  fns.reduce((acc, fn) => fn(acc), value);

/**
 * Session data pipeline - example of functional composition
 */
export const createSessionPipeline = () => {
  const filterActiveSessions = createSessionFilter(session => session.isActive);
  const filterKeycloakSessions = createSessionFilter(isKeycloakSession);
  const mapToUserIds = mapSessions(session => session.userId);
  
  const getActiveKeycloakUserIds = (sessions: SessionData[]): string[] => {
    return mapToUserIds(filterKeycloakSessions(filterActiveSessions(sessions)));
  };
  
  return {
    filterActiveSessions,
    filterKeycloakSessions,
    mapToUserIds,
    getActiveKeycloakUserIds,
  };
};

// ====================================
// 📦 LEGACY COMPATIBILITY
// ====================================

/**
 * Legacy getUserSession function (alias for getActiveUserSession)
 */
export const getUserSession = getActiveUserSession;

/**
 * Legacy isTokenExpiredForUser function (alias for isUserTokenExpired)
 */
export const isTokenExpiredForUser = isUserTokenExpired;

// ====================================
// 📤 DEFAULT EXPORT (Functional API Object)
// ====================================

/**
 * Functional User Service API
 */
const UserServiceAPI = {
  // Core session functions
  createUserSession,
  createKeycloakUserSession,
  getActiveUserSession,
  getUserSessions,
  getSessionById,
  getSessionByToken,
  updateSession,
  removeSession,
  removeUserSessions,
  clearAllSessions,
  
  // Validation functions
  isSessionValid,
  isUserTokenExpired,
  isSessionTokenExpired,
  
  // Statistics functions
  getSessionStats,
  getUserSessionCounts,
  
  // Utility functions
  getUserFromSession,
  getAccessTokenFromSession,
  getRefreshTokenFromSession,
  isKeycloakSession,
  isCustomSession,
  
  // Functional composition helpers
  withSessionValidation,
  withUserSession,
  createSessionFilter,
  mapSessions,
  pipe,
  compose,
  createSessionPipeline,
  
  // System functions
  resetUserService,
  initializeUserService,
  
  // Legacy aliases
  getUserSession,
  isTokenExpiredForUser,
} as const;

export default UserServiceAPI; 