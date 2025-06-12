import { Router } from 'express';
import { validateJoi } from '../../middlewares/joiValidationMiddleware';
import { authController, userController } from '../../controllers';
import {
    loginRequestSchema,
    forgotPasswordRequestSchema,
    verifyOtpRequestSchema,
    resetPasswordRequestSchema
} from '../../schemas/authSchemas';
import { userSignupRequestSchema, verifyEmailRequestSchema } from '../../schemas/userSchemas';

//AUTH ROUTES//
const _router: Router = Router({
    mergeParams: true,
});

//USER LOGIN
_router
    .route('/login')
    .post(validateJoi(loginRequestSchema), authController.login);

//USER FORGOT PASSWORD
_router
    .route('/forgot-password')
    .post(validateJoi(forgotPasswordRequestSchema), authController.forgotPassword);

//USER SIGNUP
_router
    .route('/sign-up')
    .post(validateJoi(userSignupRequestSchema), userController.createUser);

//USER VERFIY THERE EMAIL
_router
    .route('/verify-email')
    .post(validateJoi(verifyEmailRequestSchema), userController.verifyEmail);

//USER VERIFY OTP FOR FORGOT PASSWORD
_router
    .route('/verify-otp')
    .post(validateJoi(verifyOtpRequestSchema), authController.verifyForgetPassword);

//USER RESET PASSWORD FOR FORGOT PASSWORD
_router
    .route('/reset-password')
    .post(validateJoi(resetPasswordRequestSchema), authController.resetPassword);

//EXPORT
export const router = _router;
