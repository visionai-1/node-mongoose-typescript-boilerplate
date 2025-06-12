// ====================================
// 📋 CENTRAL SCHEMA EXPORTS
// ====================================

// Auth schemas
export {
    loginRequestSchema,
    forgotPasswordRequestSchema,
    verifyOtpRequestSchema,
    resetPasswordRequestSchema,
    protectedRouteSchema,
    authorizationHeaderSchema,
    emailSchema as authEmailSchema,
    loginPasswordSchema
} from './authSchemas';

// User schemas
export {
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
    createRequiredTextField as userCreateRequiredTextField,
    createOptionalTextField as userCreateOptionalTextField
} from './userSchemas';

// Common schemas
export {
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
} from './commonSchemas';

// Default exports
export { default as authSchemas } from './authSchemas';
export { default as userSchemas } from './userSchemas';
export { default as commonSchemas } from './commonSchemas'; 