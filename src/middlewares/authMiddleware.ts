import { Request, Response, NextFunction } from 'express';
import { validateToken, extractToken, isTokenExpired } from '../utils';
import * as UserService from '../services/userService';
import { SessionData } from '../services/userService';
import HttpError from '../utils/httpError';

// Extend Request interface to include session data
declare global {
    namespace Express {
        interface Request {
            tokenPayload?: any;
            sessionData?: SessionData;
            userId?: string;
            sessionId?: string;
        }
    }
}

const requireAuth = async function (req: Request, res: Response, next: NextFunction) {
    try {
        // 1. Extract and validate Authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            throw new HttpError({
                title: 'unauthorized',
                detail: 'Missing authorization header',
                code: 401,
            });
        }

        // 2. Extract token from header
        const token = extractToken(authHeader);
        if (!token) {
            throw new HttpError({
                title: 'unauthorized',
                detail: 'Invalid authorization header format',
                code: 401,
            });
        }

        // 3. Check token expiration first (fast check)
        if (isTokenExpired(token)) {
            throw new HttpError({
                title: 'unauthorized',
                detail: 'Token has expired',
                code: 401,
            });
        }

        // 4. Validate token structure and payload
        const payload = validateToken(token);
        if (payload['tokenType'] !== 'access') {
            throw new HttpError({
                title: 'unauthorized',
                detail: 'Invalid token type',
                code: 401,
            });
        }

        // 5. Extract and validate user ID
        const userId = payload['id'];
        if (!userId) {
            throw new HttpError({
                title: 'unauthorized',
                detail: 'Invalid token payload - missing user ID',
                code: 401,
            });
        }

        // 6. Enhanced session validation using in-memory sessions
        let sessionData: SessionData | null = null;
        
        try {
            // Find session by token
            sessionData = await UserService.getSessionByToken(token);
            
            if (sessionData) {
                // Verify token belongs to correct user
                if (sessionData.userId !== userId) {
                    throw new HttpError({
                        title: 'unauthorized',
                        detail: 'Token user mismatch',
                        code: 401,
                    });
                }

                // Check if session is active and valid
                const isValid = await UserService.isSessionValid(sessionData.sessionId);
                if (!isValid) {
                    throw new HttpError({
                        title: 'unauthorized',
                        detail: 'Session has expired or is invalid',
                        code: 401,
                    });
                }

                // Attach session data to request
                req.sessionId = sessionData.sessionId;
                req.sessionData = sessionData;
            }
            // If no session found, continue with token-only validation
            
        } catch (error) {
            // If session validation fails but token is valid, continue
            if (error instanceof HttpError) {
                throw error;
            }
            // Log session error but don't fail the request
            console.warn('[AuthMiddleware] Session validation warning:', error.message);
        }

        // 7. Attach validated data to request
        req.tokenPayload = payload;
        req.userId = userId;
        
        // 8. Proceed to next middleware
        next();

    } catch (error) {
        // Handle all authentication errors consistently
        if (error instanceof HttpError) {
            next(error);
        } else if (error.opts?.title === 'invalid_token') {
            next(
                new HttpError({
                    title: 'unauthorized',
                    detail: 'Invalid or malformed token',
                    code: 401,
                })
            );
        } else {
            next(
                new HttpError({
                    title: 'unauthorized',
                    detail: 'Authentication failed',
                    code: 401,
                })
            );
        }
    }
};

// ====================================
// 📤 EXPORTS
// ====================================

/**
 * Default export - comprehensive token validation middleware
 * @description Validates JWT tokens and manages user sessions
 */
export default requireAuth;

/**
 * Named exports for different use cases and clarity
 */  // Short name for common usage