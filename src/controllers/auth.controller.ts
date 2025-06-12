import { NextFunction, Request, Response } from 'express';
import HttpError from '../utils/httpError';
import { jsonOne } from '../utils/general';
import { matchedData } from 'express-validator';
import User, { IUserModel } from '../models/user';
import { generateJWT } from '../utils';
import generateResetPasswordTemplate from '../templates/resetPasswordTemplate';
import MailService from '../services/mailService';
import { generateOtp, verifyOtp } from '../utils';
import otpMaster from '../models/otpMaster';
import { OtpType } from '../utils/enums';
import { compare, hash } from 'bcrypt';
import { AuthInterface } from '../interfaces/authInterface';
import { getRoleName } from '../utils/typeGuards';
import Logging from '../library/Logging';

// Constants for error messages
const ERROR_MESSAGES = {
    EMAIL_NOT_VERIFIED: 'Please confirm your account by confirmation email OTP and try again',
    INVALID_CREDENTIALS: 'You have entered an invalid email address or password',
    INVALID_EMAIL: 'You have entered an invalid email address',
    EXPIRED_OTP: 'This OTP has expired',
    INVALID_OTP: 'This OTP is invalid',
} as const;

// Constants for success messages
const SUCCESS_MESSAGES = {
    PASSWORD_RESET_OTP_SENT: 'Forget Password OTP sent successfully',
    OTP_VERIFIED: 'Able to reset the password',
    PASSWORD_UPDATED: 'Password updated successfully',
} as const;

//GENERATE TOKEN FOR LOGIN
const tokenBuilder = async (user: IUserModel): Promise<{ accessToken: string }> => {
    const accessToken = generateJWT(
        {
            id: user._id,
            role: getRoleName(user.role),
            tokenType: 'access',
        },
        {
            issuer: user.email,
            subject: user.email,
            audience: 'root',
        }
    );

    return {
        accessToken,
    };
};

/**
 * Validates user credentials and email verification status
 * @param user - User from database
 * @param isValidPass - Password validation result
 * @throws HttpError if validation fails
 */
const validateUserForLogin = (user: IUserModel | null, isValidPass: boolean): void => {
    if (!user || !isValidPass) {
        throw new HttpError({
            title: 'bad_login',
            detail: ERROR_MESSAGES.INVALID_CREDENTIALS,
            code: 400,
        });
    }

    if (!user.isEmailVerified) {
        throw new HttpError({
            title: 'bad_request',
            detail: ERROR_MESSAGES.EMAIL_NOT_VERIFIED,
            code: 400,
        });
    }
};

/**
 * Validates user for password reset operations
 * @param user - User from database
 * @throws HttpError if validation fails
 */
const validateUserForPasswordReset = (user: IUserModel | null): void => {
    if (!user) {
        throw new HttpError({
            title: 'bad_request',
            detail: ERROR_MESSAGES.INVALID_EMAIL,
            code: 400,
        });
    }

    if (!user.isEmailVerified) {
        throw new HttpError({
            title: 'bad_request',
            detail: ERROR_MESSAGES.EMAIL_NOT_VERIFIED,
            code: 400,
        });
    }
};

//USER LOGIN
const login = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<AuthInterface> => {
    const timer = Logging.startTimer();
    
    try {
        const bodyData = matchedData(req, {
            includeOptionals: true,
            locations: ['body'],
        });

        const { email, password } = bodyData;

        Logging.auth('Login attempt', { 
            email: email.replace(/(.{2}).*@/, '$1***@'), // Mask email for security
            ip: req.socket.remoteAddress 
        });

        const user = await User.findOne({ email }).populate('role');
        const isValidPass = user ? await compare(password, user.password) : false;
        
        validateUserForLogin(user, isValidPass);

        //CREATE TOKEN
        const token = await tokenBuilder(user!);
        const response = {
            user: user!,
            accessToken: token.accessToken,
        };

        Logging.auth('Login successful', { 
            userId: user!._id,
            email: email.replace(/(.{2}).*@/, '$1***@'),
            role: getRoleName(user!.role),
            ip: req.socket.remoteAddress
        });

        timer.done({ message: 'User login completed' });
        return jsonOne<AuthInterface>(res, 200, response);
    } catch (error) {
        Logging.auth('Login failed', { 
            email: req.body.email?.replace(/(.{2}).*@/, '$1***@'),
            error: error.message,
            ip: req.socket.remoteAddress
        });
        timer.done({ message: 'User login failed', error: error.message });
        next(error);
    }
};

//USER FORGOT PASSWORD
const forgotPassword = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        const { email } = req.body;
        
        Logging.auth('Password reset requested', { 
            email: email.replace(/(.{2}).*@/, '$1***@'),
            ip: req.socket.remoteAddress 
        });

        const user = await User.findOne({ email }).populate('role');

        validateUserForPasswordReset(user);

        const tokenExpiration = new Date();
        tokenExpiration.setMinutes(tokenExpiration.getMinutes() + 10);

        const otp: string = generateOtp({ length: 6 });

        const newOtp = new otpMaster({
            userId: user!._id,
            type: OtpType.FORGET,
            otp,
            otpExpiration: tokenExpiration,
        });
        await newOtp.save();

        //GENERATE OTP AND SEND ON MAIL
        const emailTemplate = generateResetPasswordTemplate(
            otp,
            user!.firstName
        );

        //SEND FORGOT PASSWORD EMAIL
        const mailService = MailService.getInstance();
        await mailService.sendMail(req.headers['X-Request-Id'], {
            to: email,
            subject: 'Reset Password',
            html: emailTemplate.html,
        });

        Logging.email('Password reset OTP sent', { 
            userId: user!._id,
            email: email.replace(/(.{2}).*@/, '$1***@'),
            otpExpiration: tokenExpiration.toISOString()
        });
        
        return jsonOne<string>(
            res,
            200,
            SUCCESS_MESSAGES.PASSWORD_RESET_OTP_SENT
        );
    } catch (e) {
        Logging.auth('Password reset request failed', { 
            email: req.body.email?.replace(/(.{2}).*@/, '$1***@'),
            error: e.message,
            ip: req.socket.remoteAddress
        });
        next(e);
    }
};

//VERIFY OTP FOR FORGOT PASSWORD
const verifyForgetPassword = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        const { email, otp } = req.body;

        Logging.auth('OTP verification attempt', { 
            email: email.replace(/(.{2}).*@/, '$1***@'),
            ip: req.socket.remoteAddress 
        });

        const user = await User.findOne({ email }).populate('role');
        
        if (!user) {
            Logging.auth('OTP verification failed - user not found', { 
                email: email.replace(/(.{2}).*@/, '$1***@'),
                ip: req.socket.remoteAddress 
            });
            throw new HttpError({
                title: 'bad_request',
                detail: ERROR_MESSAGES.INVALID_EMAIL,
                code: 400,
            });
        }

        //CHECK FOR OTP
        const isOtpValid = await verifyOtp(user._id, otp, OtpType.FORGET);
        if (!isOtpValid) {
            Logging.auth('OTP verification failed - invalid/expired OTP', { 
                userId: user._id,
                email: email.replace(/(.{2}).*@/, '$1***@'),
                ip: req.socket.remoteAddress 
            });
            throw new HttpError({
                title: 'bad_request',
                detail: ERROR_MESSAGES.EXPIRED_OTP,
                code: 400,
            });
        }

        Logging.auth('OTP verification successful', { 
            userId: user._id,
            email: email.replace(/(.{2}).*@/, '$1***@'),
            ip: req.socket.remoteAddress 
        });

        return jsonOne<string>(res, 200, SUCCESS_MESSAGES.OTP_VERIFIED);
    } catch (e) {
        next(e);
    }
};

//RESET PASSWORD
const resetPassword = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        const { email, otp, password } = req.body;

        Logging.auth('Password reset attempt', { 
            email: email.replace(/(.{2}).*@/, '$1***@'),
            ip: req.socket.remoteAddress 
        });

        const user = await User.findOne({ email });
        
        if (!user) {
            throw new HttpError({
                title: 'bad_request',
                detail: ERROR_MESSAGES.INVALID_EMAIL,
                code: 400,
            });
        }

        //CHECK FOR OTP
        const isOtpValid = await verifyOtp(user._id, otp, OtpType.FORGET);
        if (!isOtpValid) {
            Logging.auth('Password reset failed - invalid OTP', { 
                userId: user._id,
                email: email.replace(/(.{2}).*@/, '$1***@'),
                ip: req.socket.remoteAddress 
            });
            throw new HttpError({
                title: 'bad_request',
                detail: ERROR_MESSAGES.INVALID_OTP,
                code: 400,
            });
        }

        //ADD NEW PASSWORD
        const hashPassword = await hash(password, 12);
        user.password = hashPassword;

        await user.save();
        await otpMaster.findByIdAndDelete(isOtpValid);

        Logging.auth('Password reset successful', { 
            userId: user._id,
            email: email.replace(/(.{2}).*@/, '$1***@'),
            ip: req.socket.remoteAddress 
        });

        return jsonOne<string>(res, 200, SUCCESS_MESSAGES.PASSWORD_UPDATED);
    } catch (e) {
        Logging.auth('Password reset failed', { 
            email: req.body.email?.replace(/(.{2}).*@/, '$1***@'),
            error: e.message,
            ip: req.socket.remoteAddress
        });
        next(e);
    }
};

//EXPORT
export default {
    login,
    forgotPassword,
    verifyForgetPassword,
    resetPassword,
};
