import Joi from 'joi';
import { extractToken } from '../utils';

export const authorizationHeaderSchema = Joi.object({
    authorization: Joi.string()
        .trim()
        .required()
        .messages({
            'string.empty': 'Missing authentication header',
            'any.required': 'Missing authentication header'
        })
        .custom((value, helpers) => {
            // Extract token from Bearer format
            const token = extractToken(value);
            if (!token) {
                return helpers.error('any.invalid');
            }
            
            // Basic JWT format validation (3 parts separated by dots)
            const jwtParts = token.split('.');
            if (jwtParts.length !== 3) {
                return helpers.error('any.invalid');
            }
            
            return token; // Return extracted token
        }, 'JWT Bearer Token Validation')
        .messages({
            'any.invalid': 'Invalid Authorization header, must be Bearer authorization'
        })
});

/**
 * Email validation schema
 * Validates and normalizes email addresses
 */
export const emailSchema = Joi.string()
    .trim()
    .required()
    .min(3)
    .max(100)
    .email({ tlds: { allow: false } }) // Allow all TLDs
    .lowercase()
    .messages({
        'string.empty': 'Email address is required',
        'string.min': 'Email address must be between 3 and 100 characters',
        'string.max': 'Email address must be between 3 and 100 characters',
        'string.email': 'Email address is not valid',
        'any.required': 'Email address is required'
    });

/**
 * Login password schema
 * Simple validation for login (different from registration)
 */
export const loginPasswordSchema = Joi.string()
    .trim()
    .required()
    .max(255)
    .messages({
        'string.empty': 'Password is required',
        'string.max': 'Password must not exceed 255 characters',
        'any.required': 'Password is required'
    });

/**
 * Complete login request schema
 */
export const loginRequestSchema = {
    body: Joi.object({
        email: emailSchema,
        password: loginPasswordSchema
    })
};

/**
 * Forgot password request schema
 */
export const forgotPasswordRequestSchema = {
    body: Joi.object({
        email: emailSchema
    })
};

/**
 * Verify OTP request schema
 */
export const verifyOtpRequestSchema = {
    body: Joi.object({
        email: emailSchema,
        otp: Joi.string()
            .trim()
            .required()
            .min(2)
            .max(255)
            .messages({
                'string.empty': 'Otp is required',
                'string.min': 'Otp must be between 2 and 255 characters',
                'string.max': 'Otp must be between 2 and 255 characters',
                'any.required': 'Otp is required'
            })
    })
};

/**
 * Reset password request schema
 */
export const resetPasswordRequestSchema = {
    body: Joi.object({
        email: emailSchema,
        otp: Joi.string()
            .trim()
            .required()
            .min(2)
            .max(255)
            .messages({
                'string.empty': 'Otp is required',
                'string.min': 'Otp must be between 2 and 255 characters',
                'string.max': 'Otp must be between 2 and 255 characters',
                'any.required': 'Otp is required'
            }),
        password: Joi.string()
            .trim()
            .required()
            .min(8)
            .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])'))
            .messages({
                'string.empty': 'Password is required',
                'string.min': 'Password should not be empty and at a minimum eight characters',
                'string.pattern.base': 'Password must contain at least one lowercase letter, one uppercase letter, one number and one special character',
                'any.required': 'Password is required'
            }),
        confirmPassword: Joi.string()
            .trim()
            .required()
            .valid(Joi.ref('password'))
            .messages({
                'string.empty': 'Confirm Password is required',
                'any.only': 'Password confirmation does not match password',
                'any.required': 'Confirm Password is required'
            })
    })
};


export const protectedRouteSchema = {
    headers: authorizationHeaderSchema
};


export default {
    loginRequestSchema,
    forgotPasswordRequestSchema,
    verifyOtpRequestSchema,
    resetPasswordRequestSchema,
    protectedRouteSchema,
    authorizationHeaderSchema,
    emailSchema,
    loginPasswordSchema
}; 