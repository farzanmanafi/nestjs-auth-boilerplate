
export interface AuthPayload {
  sub: string;
  email: string;
  iat?: number;
  exp?: number;
}

export interface RefreshTokenPayload {
  sub: string;
  tokenId: string;
  iat?: number;
  exp?: number;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

export interface AuthResponse {
  user: UserProfile;
  tokens: AuthTokens;
  twoFactorRequired?: boolean;
}

export interface UserProfile {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  emailVerified: boolean;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface TwoFactorSetupResponse {
  qrCode: string;
  secret: string;
  backupCodes?: string[];
}

export interface SSOProfile {
  id: string;
  email: string;
  firstName?: string;
  lastName?: string;
  provider: 'auth0' | 'google' | 'facebook' | 'github';
  providerId: string;
}

export interface PasswordResetRequest {
  email: string;
  token: string;
  expiresAt: Date;
}

export interface EmailVerificationRequest {
  email: string;
  token: string;
  expiresAt: Date;
}

export interface SessionInfo {
  id: string;
  userId: string;
  userAgent?: string;
  ipAddress?: string;
  createdAt: Date;
  expiresAt: Date;
  isActive: boolean;
}
