import Joi from 'joi';

// ====================================
// 🔧 COMMON JOI SCHEMAS
// ====================================

/**
 * Boolean field validation schema
 * @param fieldName - Name of the field
 * @param displayName - Display name for error messages
 * @param allowedValues - Array of allowed boolean values
 * @param optional - Whether the field is optional
 */
export const createBooleanField = (
    fieldName: string,
    displayName: string,
    allowedValues: boolean[] = [true, false],
    optional: boolean = true
) => {
    let schema = Joi.boolean()
        .valid(...allowedValues)
        .messages({
            'boolean.base': `${displayName} should be boolean`,
            'any.only': `${displayName} must be a boolean: [${allowedValues.join(',')}]`
        });

    if (optional) {
        schema = schema.optional().allow(null);
    } else {
        schema = schema.required().messages({
            'any.required': `${displayName} must be provided`
        });
    }

    return schema;
};

/**
 * Required text field validation schema
 * @param fieldName - Name of the field
 * @param displayName - Display name for error messages
 * @param min - Minimum length
 * @param max - Maximum length
 */
export const createRequiredTextField = (
    fieldName: string,
    displayName: string,
    min: number = 2,
    max: number = 255
) => {
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
 * Optional text field validation schema
 * @param fieldName - Name of the field
 * @param displayName - Display name for error messages
 * @param min - Minimum length
 * @param max - Maximum length
 * @param nullable - Whether null values are allowed
 */
export const createOptionalTextField = (
    fieldName: string,
    displayName: string,
    min: number = 2,
    max: number = 255,
    nullable: boolean = true
) => {
    let schema = Joi.string()
        .trim()
        .min(min)
        .max(max)
        .messages({
            'string.min': `${displayName} must be between ${min} and ${max} characters`,
            'string.max': `${displayName} must be between ${min} and ${max} characters`
        });

    if (nullable) {
        schema = schema.optional().allow('', null);
    } else {
        schema = schema.optional().allow('');
    }

    return schema;
};

/**
 * ID parameter validation schema
 * @param fieldName - Name of the ID field (e.g., 'userId', 'roleId')
 * @param displayName - Display name for error messages
 */
export const createIdParamSchema = (fieldName: string, displayName: string) => {
    return Joi.object({
        [fieldName]: Joi.string()
            .required()
            .trim()
            .min(1)
            .messages({
                'string.empty': `${displayName} is required`,
                'any.required': `${displayName} is required`,
                'string.min': `${displayName} cannot be empty`
            })
    });
};

/**
 * Pagination query schema
 */
export const paginationQuerySchema = Joi.object({
    page: Joi.number()
        .integer()
        .min(1)
        .optional()
        .default(1)
        .messages({
            'number.base': 'Page must be a number',
            'number.integer': 'Page must be an integer',
            'number.min': 'Page must be greater than 0'
        }),
    limit: Joi.number()
        .integer()
        .min(1)
        .max(100)
        .optional()
        .default(10)
        .messages({
            'number.base': 'Limit must be a number',
            'number.integer': 'Limit must be an integer',
            'number.min': 'Limit must be greater than 0',
            'number.max': 'Limit cannot exceed 100'
        }),
    search: Joi.string()
        .trim()
        .optional()
        .allow('')
        .max(255)
        .messages({
            'string.max': 'Search term cannot exceed 255 characters'
        }),
    sort: Joi.string()
        .trim()
        .optional()
        .allow('')
        .max(100)
        .messages({
            'string.max': 'Sort field cannot exceed 100 characters'
        }),
    order: Joi.string()
        .valid('ASC', 'DESC', 'asc', 'desc')
        .optional()
        .default('ASC')
        .messages({
            'any.only': 'Order must be ASC or DESC'
        })
}).options({ allowUnknown: true });

/**
 * Date validation schema
 */
export const dateSchema = Joi.alternatives().try(
    Joi.date().iso(),
    Joi.string().isoDate(),
    Joi.number().integer().min(0)
).messages({
    'alternatives.match': 'Date must be a valid ISO date string, Date object, or timestamp',
    'date.format': 'Date must be in ISO format',
    'string.isoDate': 'Date string must be in ISO format'
});

/**
 * Email validation schema (reusable)
 */
export const emailSchema = Joi.string()
    .trim()
    .email({ tlds: { allow: false } })
    .lowercase()
    .max(100)
    .messages({
        'string.email': 'Must be a valid email address',
        'string.max': 'Email cannot exceed 100 characters'
    });

/**
 * UUID validation schema
 */
export const uuidSchema = Joi.string()
    .uuid({ version: ['uuidv4'] })
    .messages({
        'string.guid': 'Must be a valid UUID'
    });

/**
 * Phone number validation schema
 */
export const phoneSchema = Joi.string()
    .pattern(/^[\+]?[1-9][\d]{0,15}$/)
    .messages({
        'string.pattern.base': 'Must be a valid phone number'
    });

/**
 * URL validation schema
 */
export const urlSchema = Joi.string()
    .uri({ scheme: ['http', 'https'] })
    .messages({
        'string.uri': 'Must be a valid URL'
    });

/**
 * Base64 validation schema
 */
export const base64Schema = Joi.string()
    .base64()
    .messages({
        'string.base64': 'Must be a valid base64 encoded string'
    });

// ====================================
// 📤 EXPORTS
// ====================================

export default {
    createBooleanField,
    createRequiredTextField,
    createOptionalTextField,
    createIdParamSchema,
    paginationQuerySchema,
    dateSchema,
    emailSchema,
    uuidSchema,
    phoneSchema,
    urlSchema,
    base64Schema
}; 