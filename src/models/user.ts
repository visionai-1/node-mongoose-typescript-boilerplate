import mongoose, { Document, Schema } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import { IRole, IUser, IUserPopulated } from '../interfaces';
import { string } from 'joi';

// Extend IUser with Document, omitting conflicting 'id' property
export interface IUserModel extends Omit<IUser, 'id'>, Document {
    _id: string;
}

// Extend IUserPopulated with Document, omitting conflicting 'id' property
export interface IUserModelPopulated extends Omit<IUserPopulated, 'id'>, Document {
    _id: string;
}

// Define User Schema
const UserSchema: Schema<IUserModel> = new Schema(
    {
        _id: {
            type: String,
            default: uuidv4,
        },
        firstName: {
            type: String,
            default: '',
        },
        lastName: {
            type: String,
            default: '',
        },
        gender: {
            type: String,
            enum: ['male', 'female', 'other'],
            default: 'male',
        },
        dateOfBirth: {
            type: Date,
            default: null,
        },
        residence: {
            type: String,
            default: '',
        },
        avatar: {
            type: String,
            default: '',
        },
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
        },
        password: {
            type: String,
            required: true,
            minlength: 8,
        },
        role: {
            type: String,
            ref: 'Role',
        },
        isEmailVerified: {
            type: Boolean,
            default: false,
        },
        isProfileCompleted: {
            type: Boolean,
            default: false,
        },
    },
    {
        timestamps: true,
        versionKey: false, // Removes __v
    }
);

// Export model
export default mongoose.model<IUserModel>('User', UserSchema);
