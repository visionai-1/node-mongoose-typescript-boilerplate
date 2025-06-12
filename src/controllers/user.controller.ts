import { NextFunction, Request, Response } from 'express';
import HttpError from '../utils/httpError';
import { jsonOne, jsonAll } from '../utils/general';
import { generateOtp, verifyOtp } from '../utils';
import verifyEmailTamplate from '../templates/verifyEmailTemplate';
import MailService from '../services/mailService';
import { RoleType, OtpType } from '../utils/enums';
import User, { IUserModel } from '../models/user';
import Role from '../models/role';
import otpMaster from '../models/otpMaster';
import { hash } from 'bcrypt';
import { IUser } from '../interfaces';

// ====================================
// 📋 CONSTANTS
// ====================================

const ERROR_MESSAGES = {
    EMAIL_ALREADY_USED: 'Email address is already used',
    ROLE_NOT_FOUND: 'User role not found',
    INVALID_EMAIL: 'You have entered an invalid email address',
    EMAIL_ALREADY_VERIFIED: 'User Email Is Already Verified',
    INVALID_OTP: 'This OTP is invalid',
    USER_NOT_FOUND: 'User Not Found',
    ACCESS_FORBIDDEN: 'Access Forbidden',
} as const;

const SUCCESS_MESSAGES = {
    EMAIL_VERIFICATION_SUCCESS: 'Email Verification Successful',
} as const;

const CONFIG = {
    OTP_EXPIRATION_MINUTES: 10,
    OTP_LENGTH: 6,
    PASSWORD_HASH_ROUNDS: 12,
    DEFAULT_PAGE: 1,
    DEFAULT_LIMIT: 10,
} as const;

// ====================================
// 🔧 HELPER FUNCTIONS
// ====================================

/**
 * Get pagination options from request query
 */
const getPaginationOptions = (req: Request) => ({
    page: Number(req.query.page) || CONFIG.DEFAULT_PAGE,
    limit: Number(req.query.limit) || CONFIG.DEFAULT_LIMIT,
});

/**
 * Create pagination metadata
 */
const createPaginationMeta = (total: number, page: number, limit: number) => ({
    total,
    limit,
    totalPages: Math.ceil(total / limit),
    currentPage: page,
});

/**
 * Find user by ID with error handling
 */
const findUserById = async (userId: string): Promise<IUserModel> => {
    const user = await User.findById(userId);
    if (!user) {
        throw new HttpError({
            title: 'bad_request',
            detail: ERROR_MESSAGES.USER_NOT_FOUND,
            code: 400,
        });
    }
    return user;
};

/**
 * Find user role with error handling
 */
const findUserRole = async (): Promise<any> => {
    const role = await Role.findOne({ name: RoleType.USER });
    if (!role) {
        throw new HttpError({
            title: 'role',
            detail: ERROR_MESSAGES.ROLE_NOT_FOUND,
            code: 422,
        });
    }
    return role;
};

/**
 * Check if email already exists
 */
const checkEmailExists = async (email: string): Promise<void> => {
    const userExist = await User.exists({ email });
    if (userExist) {
        throw new HttpError({
            title: 'emailAddress',
            detail: ERROR_MESSAGES.EMAIL_ALREADY_USED,
            code: 422,
        });
    }
};

/**
 * Generate and save OTP for user
 */
const generateAndSaveOTP = async (userId: string): Promise<string> => {
    const tokenExpiration = new Date();
    tokenExpiration.setMinutes(tokenExpiration.getMinutes() + CONFIG.OTP_EXPIRATION_MINUTES);

    const otp = generateOtp({ length: CONFIG.OTP_LENGTH });

    const newOtp = new otpMaster({
        userId,
        type: OtpType.VERIFICATION,
        otp,
        otpExpiration: tokenExpiration,
    });
    
    await newOtp.save();
    return otp;
};

/**
 * Send verification email
 */
const sendVerificationEmail = async (requestId: string | string[] | undefined, email: string, otp: string): Promise<void> => {
    const emailTemplate = verifyEmailTamplate(otp);
    const mailService = MailService.getInstance();
    
    await mailService.sendMail(requestId, {
        to: email,
        subject: 'Verify OTP',
        html: emailTemplate.html,
    });
};

/**
 * Validate user access permissions
 */
const validateUserAccess = (tokenPayload: any, targetUserId: string): void => {
    const userId = tokenPayload['id'];
    if (userId !== targetUserId) {
        throw new HttpError({
            title: 'forbidden',
            detail: ERROR_MESSAGES.ACCESS_FORBIDDEN,
            code: 403,
        });
    }
};

// ====================================
// 🎯 CONTROLLER FUNCTIONS
// ====================================

/**
 * Create new user and send verification email
 */
const createUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { firstName, lastName, avatar, email, password } = req.body;
        
        // Validate email uniqueness
        await checkEmailExists(email);
        
        // Get user role
        const role = await findUserRole();
        
        // Create user with hashed password
        const hashPassword = await hash(password, CONFIG.PASSWORD_HASH_ROUNDS);
        const user = new User({
            firstName,
            lastName,
            avatar,
            email,
            password: hashPassword,
            role: role._id,
        });
        
        const savedUser = await user.save();

        // Generate and save OTP
        const otp = await generateAndSaveOTP(savedUser._id);

        // Send verification email
        await sendVerificationEmail(req.headers['X-Request-Id'], email, otp);
        
        return jsonOne<IUserModel>(res, 201, savedUser);
    } catch (error) {
        next(error);
    }
};

/**
 * Verify user email with OTP
 */
const verifyEmail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { email, otp } = req.body;
        
        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            throw new HttpError({
                title: 'bad_request',
                detail: ERROR_MESSAGES.INVALID_EMAIL,
                code: 400,
            });
        }
        
        // Check if already verified
        if (user.isEmailVerified) {
            return jsonOne<string>(res, 200, ERROR_MESSAGES.EMAIL_ALREADY_VERIFIED);
        }

        // Verify OTP
        const isOtpValid = await verifyOtp(user._id, otp, OtpType.VERIFICATION);
        if (!isOtpValid) {
            throw new HttpError({
                title: 'bad_request',
                detail: ERROR_MESSAGES.INVALID_OTP,
                code: 400,
            });
        }
        
        // Update user verification status
        user.isEmailVerified = true;
        await user.save();
        
        // Clean up OTP
        await otpMaster.findByIdAndDelete(isOtpValid);
        
        return jsonOne<string>(res, 200, SUCCESS_MESSAGES.EMAIL_VERIFICATION_SUCCESS);
    } catch (error) {
        next(error);
    }
};

/**
 * Get user details by ID
 */
const getUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { userId } = req.params;
        const user = await User.findById(userId).populate('role');
        
        if (!user) {
            throw new HttpError({
                title: 'bad_request',
                detail: ERROR_MESSAGES.USER_NOT_FOUND,
                code: 400,
            });
        }

        return jsonOne<IUser>(res, 200, user);
    } catch (error) {
        next(error);
    }
};

/**
 * Get all users with pagination
 */
const getAllUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { page, limit } = getPaginationOptions(req);
        
        // Get total count and users
        const [count, users] = await Promise.all([
            User.countDocuments({}),
            User.find()
                .populate('role')
                .limit(limit)
                .skip((page - 1) * limit)
                .sort({ createdAt: -1 })
        ]);
        
        // Create pagination metadata
        const meta = createPaginationMeta(count, page, limit);
        
        return jsonAll<IUserModel[]>(res, 200, users, meta);
    } catch (error) {
        next(error);
    }
};

/**
 * Update user details
 */
const updateUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { userId } = req.params;
        const payload = req['tokenPayload'];
        const updateData = req.body;

        // Validate user access
        validateUserAccess(payload, userId);
        
        // Ensure user exists
        await findUserById(userId);

        // Update user with profile completion status
        const savedUser = await User.findOneAndUpdate(
            { _id: userId },
            {
                firstName: updateData.firstName,
                lastName: updateData.lastName,
                gender: updateData.gender,
                dateOfBirth: updateData.dateOfBirth,
                residence: updateData.residence,
                avatar: updateData.avatar,
                isProfileCompleted: true,
            },
            { new: true }
        );
        
        return jsonOne<IUserModel>(res, 200, savedUser);
    } catch (error) {
        next(error);
    }
};

// ====================================
// 📤 EXPORTS
// ====================================

export default {
    createUser,
    verifyEmail,
    getUser,
    getAllUser,
    updateUser,
};
