import { IRole } from '../interfaces';

/**
 * Type guard to check if a role is populated
 * @param role - The role to check (string ID or populated IRole object)
 * @returns true if role is populated IRole object
 */
export const isPopulatedRole = (role: string | IRole | any): role is IRole => {
    return typeof role === 'object' && role !== null && 'name' in role;
};

/**
 * Safely get role name from either populated role or role ID
 * @param role - The role (string ID or populated IRole object)
 * @returns The role name or the role ID if not populated
 */
export const getRoleName = (role: string | IRole | any): string => {
    return isPopulatedRole(role) ? role.name : role;
}; 