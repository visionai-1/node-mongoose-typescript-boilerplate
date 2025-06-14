import { IUser } from '../interfaces/userInterface';
import { isTokenExpired } from '../utils';
import { v4 as uuidv4 } from 'uuid';

// ====================================
// 📝 SESSION INTERFACES
// ====================================

export interface Session {
  sessionId: string;
  userId: string;
  user: IUser;
  isActive: boolean;
  createdAt: Date;
  lastActivity: Date;
  accessCount: number;
  browserInfo?: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt: Date;
}

// ====================================
// 🔧 MODULE STATE - IN-MEMORY SESSION STORE
// ====================================

let sessions: Map<string, Session> = new Map();
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
 * Create a new user session
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
  
  const session: Session = {
    sessionId,
    userId,
    user,
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

// ====================================
// 📖 SESSION RETRIEVAL FUNCTIONS
// ====================================

/**
 * Get active session for a user
 */
export const getActiveUserSession = async (userId: string): Promise<Session | null> => {
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
export const getUserSessions = async (userId: string): Promise<Session[]> => {
  const userSessions = userSessionMappings.get(userId);
  if (!userSessions) return [];
  
  const validSessions: Session[] = [];
  
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
export const getSessionById = async (sessionId: string): Promise<Session | null> => {
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
export const getSessionByToken = async (accessToken: string): Promise<Session | null> => {
  for (const session of sessions.values()) {
    if (session.accessToken === accessToken) {
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
export const updateSession = async (sessionId: string, updates: Partial<Session>): Promise<boolean> => {
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
    if (isTokenExpired(session.accessToken)) {
      removeSessionFromStore(sessionId);
      return false;
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

  return isTokenExpired(session.accessToken);
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
}> => {
  const now = new Date();
  let activeSessions = 0;
  const userIds = new Set<string>();

  for (const session of sessions.values()) {
    userIds.add(session.userId);
    
    if (session.isActive && session.expiresAt > now) {
      activeSessions++;
    }
  }

  return {
    totalSessions: sessions.size,
    activeSessions,
    userCount: userIds.size,
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
export const getUserFromSession = (session: Session): IUser => {
  return session.user;
};

/**
 * Get access token from session
 */
export const getAccessTokenFromSession = (session: Session): string => {
  return session.accessToken;
};

/**
 * Get refresh token from session
 */
export const getRefreshTokenFromSession = (session: Session): string | undefined => {
  return session.refreshToken;
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
  action: (session: Session) => Promise<T>
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
  action: (session: Session) => Promise<T>
) => async (userId: string): Promise<T | null> => {
  const session = await getActiveUserSession(userId);
  if (!session) return null;
  
  return await action(session);
};

/**
 * Create a session filter function
 */
export const createSessionFilter = (
  predicate: (session: Session) => boolean
) => (sessions: Session[]): Session[] => {
  return sessions.filter(predicate);
};

/**
 * Session mapper function
 */
export const mapSessions = <T>(
  mapper: (session: Session) => T
) => (sessions: Session[]): T[] => {
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
  
  // Functional composition helpers
  withSessionValidation,
  withUserSession,
  createSessionFilter,
  mapSessions,
  pipe,
  compose,
  
  // System functions
  resetUserService,
  initializeUserService,
  
  // Legacy aliases
  getUserSession,
  isTokenExpiredForUser,
} as const;

export default UserServiceAPI; 