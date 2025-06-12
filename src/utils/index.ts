import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import otpMaster from '../models/otpMaster';
import HttpError from './httpError';
import { OtpType } from './enums/index';

/**
 * 🛠️ Utility Functions Collection
 * Enhanced with TypeScript types, validation, and error handling
 */

// ====================================
// 🔐 JWT UTILITIES
// ====================================

export interface JWTPayload {
    id?: string;
    email?: string;
    role?: string;
    tokenType?: 'access' | 'refresh';
    [key: string]: any;
}

export interface JWTOptions {
    expiresIn?: string | number;
    issuer?: string;
    audience?: string;
    subject?: string;
}

export interface DecodedToken extends JWTPayload {
    iat: number;
    exp: number;
    iss?: string;
    aud?: string;
    sub?: string;
}

/**
 * 🎯 Generate JWT token with enhanced options and validation
 * @param payload - The data to encode in the JWT
 * @param options - JWT options (expiry, issuer, etc.)
 * @returns Signed JWT token string
 */
export const generateJWT = (
    payload: JWTPayload = {},
    options: JWTOptions = {}
): string => {
    const privateKey = process.env.JWT_SECRETS;
    
    if (!privateKey) {
        throw new HttpError({
            title: 'jwt_config_error',
            detail: 'JWT secret not configured',
            code: 500,
        });
    }

    const defaultOptions: JWTOptions = {
        expiresIn: '1h',
    };

    const finalOptions = { ...defaultOptions, ...options };

    try {
        return jwt.sign(payload, privateKey, finalOptions);
    } catch (error) {
        throw new HttpError({
            title: 'jwt_generation_error',
            detail: 'Failed to generate JWT token',
            code: 500,
        });
    }
};

/**
 * 🔒 Generate JWT for password reset with password-specific secret
 * @param password - User's current password for secret generation
 * @param payload - The data to encode in the JWT
 * @param options - JWT options
 * @returns Signed JWT token string
 */
export const generateForgotPasswordJWT = (
    password: string,
    payload: JWTPayload = {},
    options: JWTOptions = {}
): string => {
    const baseSecret = process.env.JWT_SECRETS;
    
    if (!baseSecret) {
        throw new HttpError({
            title: 'jwt_config_error',
            detail: 'JWT secret not configured',
            code: 500,
        });
    }

    if (!password || password.trim().length === 0) {
        throw new HttpError({
            title: 'invalid_password',
            detail: 'Password is required for reset token generation',
            code: 400,
        });
    }

    const passwordSpecificSecret = baseSecret + password;
    const defaultOptions: JWTOptions = {
        expiresIn: '1h',
    };

    const finalOptions = { ...defaultOptions, ...options };

    try {
        return jwt.sign(payload, passwordSpecificSecret, finalOptions);
    } catch (error) {
        throw new HttpError({
            title: 'jwt_generation_error',
            detail: 'Failed to generate password reset token',
            code: 500,
        });
    }
};

/**
 * ✅ Validate and decode JWT token
 * @param token - JWT token to validate
 * @returns Decoded token payload
 */
export const validateToken = (token: string): DecodedToken => {
    const publicKey = process.env.JWT_SECRETS;
    
    if (!publicKey) {
        throw new HttpError({
            title: 'jwt_config_error',
            detail: 'JWT secret not configured',
            code: 500,
        });
    }

    if (!token || token.trim().length === 0) {
        throw new HttpError({
            title: 'invalid_token',
            detail: 'Token is required',
            code: 400,
        });
    }

    try {
        return jwt.verify(token, publicKey) as DecodedToken;
    } catch (error) {
        const jwtError = error as jwt.JsonWebTokenError;
        
        let errorMessage = 'Invalid token';
        if (jwtError.name === 'TokenExpiredError') {
            errorMessage = 'Token has expired';
        } else if (jwtError.name === 'JsonWebTokenError') {
            errorMessage = 'Malformed token';
        }

        throw new HttpError({
            title: 'invalid_token',
            detail: errorMessage,
            code: 401,
        });
    }
};

/**
 * 🔓 Validate password reset JWT token
 * @param password - User's current password
 * @param token - JWT token to validate
 * @returns Decoded token payload
 */
export const validateForgotPasswordJWT = (
    password: string,
    token: string
): DecodedToken => {
    const baseSecret = process.env.JWT_SECRETS;
    
    if (!baseSecret) {
        throw new HttpError({
            title: 'jwt_config_error',
            detail: 'JWT secret not configured',
            code: 500,
        });
    }

    if (!password || password.trim().length === 0) {
        throw new HttpError({
            title: 'invalid_password',
            detail: 'Password is required for token validation',
            code: 400,
        });
    }

    if (!token || token.trim().length === 0) {
        throw new HttpError({
            title: 'invalid_token',
            detail: 'Reset token is required',
            code: 400,
        });
    }

    const passwordSpecificSecret = baseSecret + password;

    try {
        return jwt.verify(token, passwordSpecificSecret) as DecodedToken;
    } catch (error) {
        const jwtError = error as jwt.JsonWebTokenError;
        
        let errorMessage = 'Password reset link has expired or is invalid';
        if (jwtError.name === 'TokenExpiredError') {
            errorMessage = 'Password reset link has expired';
        }

        throw new HttpError({
            title: 'invalid_token',
            detail: errorMessage,
            code: 400,
        });
    }
};

/**
 * 📤 Extract JWT token from Authorization header
 * @param authHeader - Authorization header value
 * @returns Extracted token or null if invalid format
 */
export const extractToken = (authHeader: string): string | null => {
    if (!authHeader || typeof authHeader !== 'string') {
        return null;
    }

    const BEARER_PREFIX = 'Bearer ';
    if (authHeader.startsWith(BEARER_PREFIX)) {
        const token = authHeader.slice(BEARER_PREFIX.length).trim();
        return token.length > 0 ? token : null;
    }

    return null;
};

// ====================================
// 🔑 PASSWORD UTILITIES
// ====================================

export interface PasswordConfig {
    length?: number;
    includeUppercase?: boolean;
    includeLowercase?: boolean;
    includeNumbers?: boolean;
    includeSymbols?: boolean;
}

/**
 * 🎲 Generate a secure random password
 * @param config - Password generation configuration
 * @returns Generated password string
 */
export const generateRandomPassword = (config: PasswordConfig = {}): string => {
    const {
        length = 12,
        includeUppercase = true,
        includeLowercase = true,
        includeNumbers = true,
        includeSymbols = false
    } = config;

    if (length < 8 || length > 128) {
        throw new HttpError({
            title: 'invalid_password_length',
            detail: 'Password length must be between 8 and 128 characters',
            code: 400,
        });
    }

    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    let charset = '';
    const requiredChars: string[] = [];

    if (includeLowercase) {
        charset += lowercase;
        requiredChars.push(getRandomChar(lowercase));
    }

    if (includeUppercase) {
        charset += uppercase;
        requiredChars.push(getRandomChar(uppercase));
    }

    if (includeNumbers) {
        charset += numbers;
        requiredChars.push(getRandomChar(numbers));
    }

    if (includeSymbols) {
        charset += symbols;
        requiredChars.push(getRandomChar(symbols));
    }

    if (charset.length === 0) {
        throw new HttpError({
            title: 'invalid_charset',
            detail: 'At least one character type must be included',
            code: 400,
        });
    }

    // Generate password ensuring required characters are included
    let password = '';
    
    // Add required characters first
    for (const char of requiredChars) {
        password += char;
    }

    // Fill remaining length with random characters
    for (let i = requiredChars.length; i < length; i++) {
        password += getRandomChar(charset);
    }

    // Shuffle the password to avoid predictable patterns
    return shuffleString(password);
};

// ====================================
// 🔢 OTP UTILITIES
// ====================================

export interface OTPConfig {
    length?: number;
    expiryMinutes?: number;
}

export interface OTPResult {
    otp: string;
    expiryTime: Date;
}

export interface OTPVerificationResult {
    isValid: boolean;
    otpId?: string;
    message: string;
}

/**
 * 🎯 Generate a random OTP
 * @param config - OTP configuration options
 * @returns Generated OTP string
 */
export const generateOtp = (config: OTPConfig = {}): string => {
    const { length = 6 } = config;

    if (length < 4 || length > 10) {
        throw new HttpError({
            title: 'invalid_otp_length',
            detail: 'OTP length must be between 4 and 10 characters',
            code: 400,
        });
    }

    const digits = '0123456789';
    let otp = '';

    for (let i = 0; i < length; i++) {
        const randomIndex = crypto.randomInt(0, digits.length);
        otp += digits[randomIndex];
    }

    return otp;
};

/**
 * ✅ Verify OTP against stored value with enhanced validation
 * @param userId - User ID associated with the OTP
 * @param otp - OTP to verify
 * @param type - Type of OTP (email verification, password reset, etc.)
 * @returns Verification result with detailed feedback
 */
export const verifyOtp = async (
    userId: string,
    otp: string,
    type: string
): Promise<OTPVerificationResult> => {
    // Enhanced input validation
    if (!userId || userId.trim().length === 0) {
        return {
            isValid: false,
            message: 'User ID is required'
        };
    }

    if (!otp || otp.trim().length === 0) {
        return {
            isValid: false,
            message: 'OTP is required'
        };
    }

    if (!type || type.trim().length === 0) {
        return {
            isValid: false,
            message: 'OTP type is required'
        };
    }

    try {
        // Find the OTP record
        const existingOtp = await otpMaster.findOne({
            userId: userId.trim(),
            otp: otp.trim(),
            type: type.trim(),
        });

        if (!existingOtp) {
            return {
                isValid: false,
                message: 'Invalid OTP or OTP not found'
            };
        }

        // Check expiry
        const currentDate = new Date();
        if (existingOtp.otpExpiration && existingOtp.otpExpiration < currentDate) {
            // Clean up expired OTP
            await otpMaster.deleteOne({ _id: existingOtp._id });
            
            return {
                isValid: false,
                message: 'OTP has expired'
            };
        }

        return {
            isValid: true,
            otpId: existingOtp._id,
            message: 'OTP verified successfully'
        };

    } catch (error) {
        throw new HttpError({
            title: 'otp_verification_error',
            detail: 'Failed to verify OTP',
            code: 500,
        });
    }
};

/**
 * 💾 Generate and store OTP for a user
 * @param userId - User ID
 * @param type - OTP type
 * @param config - OTP configuration
 * @returns Generated OTP and expiry time
 */
export const generateAndStoreOtp = async (
    userId: string,
    type: OtpType,
    config: OTPConfig = {}
): Promise<OTPResult> => {
    const { expiryMinutes = 15 } = config;
    const otp = generateOtp(config);
    
    const expiryTime = new Date();
    expiryTime.setMinutes(expiryTime.getMinutes() + expiryMinutes);

    try {
        // Remove any existing OTPs for this user and type
        await otpMaster.deleteMany({
            userId,
            type
        });

        // Create new OTP record
        const otpRecord = new otpMaster({
            userId,
            otp,
            type,
            otpExpiration: expiryTime
        });

        await otpRecord.save();

        return {
            otp,
            expiryTime
        };

    } catch (error) {
        throw new HttpError({
            title: 'otp_storage_error',
            detail: 'Failed to store OTP',
            code: 500,
        });
    }
};

// ====================================
// 🔧 HELPER FUNCTIONS
// ====================================

/**
 * Get random character from a string using crypto
 */
function getRandomChar(charset: string): string {
    const randomIndex = crypto.randomInt(0, charset.length);
    return charset[randomIndex];
}

/**
 * Shuffle string characters using Fisher-Yates algorithm
 */
function shuffleString(str: string): string {
    const arr = str.split('');
    for (let i = arr.length - 1; i > 0; i--) {
        const j = crypto.randomInt(0, i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr.join('');
}

/**
 * 🧹 Clean up expired OTPs from database
 * @returns Number of expired OTPs removed
 */
export const cleanupExpiredOtps = async (): Promise<number> => {
    try {
        const currentDate = new Date();
        const result = await otpMaster.deleteMany({
            otpExpiration: { $lt: currentDate }
        });

        return result.deletedCount || 0;
    } catch (error) {
        throw new HttpError({
            title: 'otp_cleanup_error',
            detail: 'Failed to cleanup expired OTPs',
            code: 500,
        });
    }
};

/**
 * 🔐 Generate secure token for various purposes
 * @param length - Token length
 * @param encoding - Output encoding
 * @returns Secure random token
 */
export const generateSecureToken = (
    length: number = 32,
    encoding: 'hex' | 'base64' = 'hex'
): string => {
    if (length < 16 || length > 256) {
        throw new HttpError({
            title: 'invalid_token_length',
            detail: 'Token length must be between 16 and 256 characters',
            code: 400,
        });
    }

    const bytes = crypto.randomBytes(Math.ceil(length / 2));
    
    switch (encoding) {
        case 'base64':
            return bytes.toString('base64').slice(0, length);
        case 'hex':
        default:
            return bytes.toString('hex').slice(0, length);
    }
};

/**
 * ⏰ Check if token is expired without throwing error
 * @param token - JWT token to check
 * @returns True if token is expired
 */
export const isTokenExpired = (token: string): boolean => {
    try {
        const decoded = jwt.decode(token) as DecodedToken;
        if (!decoded || !decoded.exp) {
            return true;
        }
        
        const currentTime = Math.floor(Date.now() / 1000);
        return decoded.exp < currentTime;
    } catch {
        return true;
    }
};

// Export type guards from existing module
export { isPopulatedRole, getRoleName } from './typeGuards';

/**
 * 🔓 Decode JWT token without verification (for Keycloak compatibility)
 * @param token - JWT token to decode
 * @returns Decoded token payload
 */
export const decodeJWT = (token: string): any => {
    return jwt.decode(token);
};
