import { Types } from "mongoose";
import { IRole } from "./roleInterface";

export interface IUser {
  id?: string; // User ID (for Keycloak compatibility)
  firstName?: string;
  lastName?: string;
  fullName?: string; // Full name (for Keycloak compatibility)
  username?: string; // Username (for Keycloak compatibility)
  gender?: 'male' | 'female' | 'other';
  dateOfBirth?: Date | null;
  residence?: string;
  avatar?: string;
  profilePicture?: string;
  email: string;
  password?: string; // Optional for Keycloak users
  role?: string;  // Role ID as string (optional for Keycloak)
  roles?: string[]; // Multiple roles (for Keycloak compatibility)
  isEmailVerified?: boolean;
  emailVerified?: boolean; // Alternative naming (for Keycloak compatibility)
  isProfileCompleted?: boolean;
  isActive?: boolean;
  provider?: 'email' | 'google' | 'facebook' | 'keycloak';
  lastLogin?: Date | null;
  verified?: boolean;
  metadata?: Record<string, any>;
  createdAt?: Date;
  updatedAt?: Date;
}

// Interface for user with populated role
export interface IUserPopulated extends Omit<IUser, 'role'> {
  role: IRole;
}
