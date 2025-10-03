import { registerAs } from '@nestjs/config';
import { JwtModuleOptions } from '@nestjs/jwt';

export interface JwtConfig {
  secret: string;
  expiresIn: string;
  refreshSecret: string;
  refreshExpiresIn: string;
}

export const jwtConfig = registerAs('jwt', (): JwtConfig => ({
  secret: process.env.JWT_SECRET || 'your-default-secret-change-in-production',
  expiresIn: process.env.JWT_EXPIRES_IN || '15m',
  refreshSecret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-change-in-production',
  refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
}));

export const jwtModuleConfig = registerAs('jwtModule', (): JwtModuleOptions => ({
  secret: process.env.JWT_SECRET || 'your-default-secret-change-in-production',
  signOptions: {
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
  },
}));