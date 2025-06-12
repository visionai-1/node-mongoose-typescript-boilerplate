import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';
import HttpError from '../utils/httpError';

export interface JoiValidationSchema {
    body?: Joi.ObjectSchema;
    params?: Joi.ObjectSchema;
    query?: Joi.ObjectSchema;
    headers?: Joi.ObjectSchema;
}

export interface JoiValidationOptions {
    abortEarly?: boolean;
    allowUnknown?: boolean;
    stripUnknown?: boolean;
    skipFunctions?: boolean;
}

export const validateJoi = (
    schema: JoiValidationSchema,
    options: JoiValidationOptions = {}
) => {
    // Default validation options
    const defaultOptions: JoiValidationOptions = {
        abortEarly: false,        // Show all validation errors
        allowUnknown: false,      // Don't allow unknown fields
        stripUnknown: true,       // Remove unknown fields
        skipFunctions: true,      // Skip function validation
        ...options
    };

    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            const validationErrors: string[] = [];

            // Validate request body
            if (schema.body) {
                const { error, value } = schema.body.validate(req.body, defaultOptions);
                if (error) {
                    const bodyErrors = error.details.map(detail => `Body: ${detail.message}`);
                    validationErrors.push(...bodyErrors);
                } else {
                    req.body = value; // Use sanitized/transformed value
                }
            }

            // Validate URL parameters
            if (schema.params) {
                const { error, value } = schema.params.validate(req.params, defaultOptions);
                if (error) {
                    const paramErrors = error.details.map(detail => `Params: ${detail.message}`);
                    validationErrors.push(...paramErrors);
                } else {
                    req.params = value;
                }
            }

            // Validate query string
            if (schema.query) {
                const { error, value } = schema.query.validate(req.query, defaultOptions);
                if (error) {
                    const queryErrors = error.details.map(detail => `Query: ${detail.message}`);
                    validationErrors.push(...queryErrors);
                } else {
                    req.query = value;
                }
            }

            // Validate headers
            if (schema.headers) {
                const { error, value } = schema.headers.validate(req.headers, defaultOptions);
                if (error) {
                    const headerErrors = error.details.map(detail => `Headers: ${detail.message}`);
                    validationErrors.push(...headerErrors);
                } else {
                    // Don't override headers completely, just update specific ones
                    Object.assign(req.headers, value);
                }
            }

            // If there are validation errors, throw HttpError
            if (validationErrors.length > 0) {
                throw new HttpError({
                    title: 'validation_error',
                    detail: validationErrors.join('; '),
                    code: 400,
                });
            }

            // All validations passed
            next();

        } catch (error) {
            if (error instanceof HttpError) {
                next(error);
            } else {
                next(
                    new HttpError({
                        title: 'validation_error',
                        detail: 'Request validation failed',
                        code: 400,
                    })
                );
            }
        }
    };
};

/**
 * Quick validation helper for body-only validation
 * @param bodySchema - Joi schema for request body
 * @param options - Optional validation options
 */
export const validateBody = (bodySchema: Joi.ObjectSchema, options?: JoiValidationOptions) => {
    return validateJoi({ body: bodySchema }, options);
};

/**
 * Quick validation helper for params-only validation
 * @param paramsSchema - Joi schema for URL parameters
 * @param options - Optional validation options
 */
export const validateParams = (paramsSchema: Joi.ObjectSchema, options?: JoiValidationOptions) => {
    return validateJoi({ params: paramsSchema }, options);
};

/**
 * Quick validation helper for query-only validation
 * @param querySchema - Joi schema for query string
 * @param options - Optional validation options
 */
export const validateQuery = (querySchema: Joi.ObjectSchema, options?: JoiValidationOptions) => {
    return validateJoi({ query: querySchema }, options);
};

/**
 * Quick validation helper for headers-only validation
 * @param headersSchema - Joi schema for headers
 * @param options - Optional validation options
 */
export const validateHeaders = (headersSchema: Joi.ObjectSchema, options?: JoiValidationOptions) => {
    return validateJoi({ headers: headersSchema }, options);
};

// ====================================
// 📤 EXPORTS
// ====================================

export default validateJoi; 