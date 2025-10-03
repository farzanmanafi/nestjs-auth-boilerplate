import { UserProfile } from "./auth.types";

export interface CreateUserRequest {
  email: string;
  password?: string;
  firstName: string;
  lastName: string;
  ssoProvider?: string;
  ssoId?: string;
}

export interface UpdateUserRequest {
  firstName?: string;
  lastName?: string;
  email?: string;
}

export interface UserFilterOptions {
  isActive?: boolean;
  emailVerified?: boolean;
  ssoProvider?: string;
  createdAfter?: Date;
  createdBefore?: Date;
}

export interface UserSearchOptions {
  query?: string;
  page?: number;
  limit?: number;
  sortBy?: 'createdAt' | 'email' | 'firstName' | 'lastName';
  sortOrder?: 'ASC' | 'DESC';
}

export interface PaginatedUsers {
  users: UserProfile[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface UserActivity {
  userId: string;
  action: string;
  details?: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
  timestamp: Date;
}

export interface UserPermissions {
  canRead: boolean;
  canWrite: boolean;
  canDelete: boolean;
  canManageUsers: boolean;
  canViewAnalytics: boolean;
}

export interface UserRole {
  id: string;
  name: string;
  description: string;
  permissions: UserPermissions;
}

export interface UserWithRoles extends UserProfile {
  roles: UserRole[];
  permissions: UserPermissions;
}