import Joi from 'joi';
import { emailSchema } from './authSchemas';

// ====================================
// 👤 USER JOI SCHEMAS
// ====================================

/**
 * Strong password validation schema
 * Used for registration and password changes
 */
export const passwordSchema = Joi.string()
    .trim()
    .required()
    .min(8)
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])'))
    .messages({
        'string.empty': 'Password should not be empty and at a minimum eight characters',
        'string.min': 'Password should not be empty and at a minimum eight characters',
        'string.pattern.base': 'Password must contain at least one lowercase letter, one uppercase letter, one number and one special character',
        'any.required': 'Password should not be empty and at a minimum eight characters'
    });

/**
 * Confirm password schema
 * Validates password confirmation matches original password
 */
export const confirmPasswordSchema = Joi.string()
    .trim()
    .required()
    .valid(Joi.ref('password'))
    .messages({
        'string.empty': 'Confirm password should not be empty and at a minimum eight characters',
        'any.only': 'Password confirmation does not match password',
        'any.required': 'Confirm password should not be empty and at a minimum eight characters'
    });

/**
 * Reset password schema with different field names
 */
export const resetPasswordSchema = Joi.string()
    .trim()
    .required()
    .min(8)
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])'))
    .messages({
        'string.empty': 'newPassword should not be empty and at a minimum eight characters',
        'string.min': 'newPassword should not be empty and at a minimum eight characters',
        'string.pattern.base': 'New password must contain at least one lowercase letter, one uppercase letter, one number and one special character',
        'any.required': 'newPassword should not be empty and at a minimum eight characters'
    });

/**
 * Confirmation password for reset operations
 */
export const confirmationPasswordSchema = Joi.string()
    .trim()
    .required()
    .valid(Joi.ref('newPassword'))
    .messages({
        'string.empty': 'confirmationPassword should not be empty and at a minimum eight characters',
        'any.only': 'Confirmation password does not match password',
        'any.required': 'confirmationPassword should not be empty and at a minimum eight characters'
    });

/**
 * User ID parameter schema
 */
export const userIdParamSchema = Joi.object({
    userId: Joi.string()
        .required()
        .trim()
        .min(1)
        .messages({
            'string.empty': 'User ID is required',
            'any.required': 'User ID is required',
            'string.min': 'User ID cannot be empty'
        })
});

/**
 * Required text field schema generator
 */
export const createRequiredTextField = (fieldName: string, displayName: string, min: number = 2, max: number = 255) => {
    return Joi.string()
        .trim()
        .required()
        .min(min)
        .max(max)
        .messages({
            'string.empty': `${displayName} is required`,
            'string.min': `${displayName} must be between ${min} and ${max} characters`,
            'string.max': `${displayName} must be between ${min} and ${max} characters`,
            'any.required': `${displayName} is required`
        });
};

/**
 * Optional text field schema generator
 */
export const createOptionalTextField = (fieldName: string, displayName: string, min: number = 2, max: number = 255) => {
    return Joi.string()
        .trim()
        .optional()
        .allow('', null)
        .min(min)
        .max(max)
        .messages({
            'string.min': `${displayName} must be between ${min} and ${max} characters`,
            'string.max': `${displayName} must be between ${min} and ${max} characters`
        });
};

/**
 * User signup request schema
 */
export const userSignupRequestSchema = {
    body: Joi.object({
        email: emailSchema,
        password: passwordSchema,
        confirmPassword: confirmPasswordSchema
    })
};

/**
 * Verify email request schema
 */
export const verifyEmailRequestSchema = {
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
 * User update request schema
 */
export const userUpdateRequestSchema = {
    params: userIdParamSchema,
    body: Joi.object({
        firstName: createRequiredTextField('firstName', 'FirstName'),
        lastName: createRequiredTextField('lastName', 'LastName'),
        dateOfBirth: createRequiredTextField('dateOfBirth', 'Date Of Birth'),
        residence: createRequiredTextField('residence', 'Residence'),
        avatar: createRequiredTextField('avatar', 'Avatar')
    })
};

/**
 * Get user by ID request schema
 */
export const getUserByIdRequestSchema = {
    params: userIdParamSchema
};

/**
 * Get all users request schema (no specific validation needed, but can add query params)
 */
export const getAllUsersRequestSchema = {
    query: Joi.object({
        page: Joi.number().integer().min(1).optional(),
        limit: Joi.number().integer().min(1).max(100).optional(),
        search: Joi.string().trim().optional().allow(''),
        sort: Joi.string().trim().optional().allow('')
    }).options({ allowUnknown: true })
};

// ====================================
// 📤 EXPORTS
// ====================================

export default {
    userSignupRequestSchema,
    verifyEmailRequestSchema,
    userUpdateRequestSchema,
    getUserByIdRequestSchema,
    getAllUsersRequestSchema,
    passwordSchema,
    confirmPasswordSchema,
    resetPasswordSchema,
    confirmationPasswordSchema,
    userIdParamSchema,
    createRequiredTextField,
    createOptionalTextField
}; 