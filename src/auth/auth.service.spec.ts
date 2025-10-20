import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Repository } from 'typeorm';
import { getRepositoryToken } from '@nestjs/typeorm';
import {
  ConflictException,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';
import { v4 as uuid } from 'uuid';

import { User } from '../users/entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { PasswordReset } from './entities/password-reset.entity';
import { TwoFactorAuth } from './entities/two-factor-auth.entity';
import { EmailService } from '../email/email.service';
import { SignUpDto } from './dto/signup.dto';
import { SignInDto } from './dto/signin.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

// Mock uuid
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'test-uuid'),
}));

// Mock bcrypt
jest.mock('bcrypt', () => ({
  hash: jest.fn(),
  compare: jest.fn(),
}));

// Mock speakeasy
jest.mock('speakeasy', () => ({
  totp: {
    verify: jest.fn(),
  },
  generateSecret: jest.fn(),
}));

// Mock qrcode
jest.mock('qrcode', () => ({
  toDataURL: jest.fn(),
}));

describe('AuthService', () => {
  let authService: AuthService;
  let userRepository: Repository<User>;
  let refreshTokenRepository: Repository<RefreshToken>;
  let passwordResetRepository: Repository<PasswordReset>;
  let twoFactorRepository: Repository<TwoFactorAuth>;
  let jwtService: JwtService;
  let configService: ConfigService;
  let emailService: EmailService;

  const mockUser: User = {
    id: 'user-id',
    email: 'test@example.com',
    password: 'hashed-password',
    firstName: 'John',
    lastName: 'Doe',
    emailVerified: false,
    emailVerificationToken: 'test-uuid',
    ssoProvider: null,
    ssoId: null,
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    refreshTokens: [],
    twoFactorAuth: null,
  };

  const mockRefreshToken: RefreshToken = {
    id: 'token-id',
    token: 'refresh-token-uuid',
    userId: 'user-id',
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
    userAgent: null,
    ipAddress: null,
    createdAt: new Date(),
    user: mockUser,
  };

  const mockPasswordReset: PasswordReset = {
    id: 'reset-id',
    token: 'reset-token',
    userId: 'user-id',
    expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
    createdAt: new Date(),
    user: mockUser,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(User),
          useValue: {
            findOne: jest.fn(),
            create: jest.fn(),
            save: jest.fn(),
            update: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(RefreshToken),
          useValue: {
            findOne: jest.fn(),
            create: jest.fn(),
            save: jest.fn(),
            delete: jest.fn(),
            find: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(PasswordReset),
          useValue: {
            findOne: jest.fn(),
            create: jest.fn(),
            save: jest.fn(),
            delete: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(TwoFactorAuth),
          useValue: {
            findOne: jest.fn(),
            create: jest.fn(),
            save: jest.fn(),
            delete: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn(() => 'access-token'),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string, defaultValue?: any) => {
              const config = {
                BCRYPT_ROUNDS: 12,
                PASSWORD_RESET_EXPIRES_IN: 3600000,
                'jwt.refreshExpiresIn': '7d',
                'jwt.secret': 'test-secret',
                'jwt.expiresIn': '15m',
                BACKEND_URL: 'http://localhost:3001',
                FRONTEND_URL: 'http://localhost:3000',
                APP_NAME: 'Test App',
              };
              return config[key] || defaultValue;
            }),
          },
        },
        {
          provide: EmailService,
          useValue: {
            sendVerificationEmail: jest.fn(),
            sendPasswordResetEmail: jest.fn(),
            sendWelcomeEmail: jest.fn(),
          },
        },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    refreshTokenRepository = module.get<Repository<RefreshToken>>(
      getRepositoryToken(RefreshToken),
    );
    passwordResetRepository = module.get<Repository<PasswordReset>>(
      getRepositoryToken(PasswordReset),
    );
    twoFactorRepository = module.get<Repository<TwoFactorAuth>>(
      getRepositoryToken(TwoFactorAuth),
    );
    jwtService = module.get<JwtService>(JwtService);
    configService = module.get<ConfigService>(ConfigService);
    emailService = module.get<EmailService>(EmailService);

    // Reset all mocks before each test
    jest.clearAllMocks();
  });

  describe('signUp', () => {
    const signUpDto: SignUpDto = {
      email: 'newuser@example.com',
      password: 'Password123!',
      firstName: 'Jane',
      lastName: 'Smith',
    };

    it('should successfully sign up a new user', async () => {
      const savedUser = { ...mockUser, ...signUpDto, id: 'new-user-id' };

      jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);
      jest.spyOn(userRepository, 'create').mockReturnValue(savedUser as User);
      jest.spyOn(userRepository, 'save').mockResolvedValue(savedUser as User);
      jest
        .spyOn(refreshTokenRepository, 'create')
        .mockReturnValue(mockRefreshToken);
      jest
        .spyOn(refreshTokenRepository, 'save')
        .mockResolvedValue(mockRefreshToken);
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-password');

      const result = await authService.signUp(signUpDto);

      expect(result).toBeDefined();
      expect(result.user.email).toBe(signUpDto.email);
      expect(result.user.firstName).toBe(signUpDto.firstName);
      expect(result.user.lastName).toBe(signUpDto.lastName);
      expect(result.tokens.accessToken).toBe('access-token');
      expect(result.tokens.refreshToken).toBe('test-uuid');

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { email: signUpDto.email },
      });
      expect(bcrypt.hash).toHaveBeenCalledWith(signUpDto.password, 12);
      expect(emailService.sendVerificationEmail).toHaveBeenCalledWith(
        signUpDto.email,
        'test-uuid',
      );
    });

    it('should throw ConflictException if user already exists', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser);

      await expect(authService.signUp(signUpDto)).rejects.toThrow(
        ConflictException,
      );
      expect(userRepository.save).not.toHaveBeenCalled();
      expect(emailService.sendVerificationEmail).not.toHaveBeenCalled();
    });

    it('should handle database save error', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);
      jest
        .spyOn(userRepository, 'save')
        .mockRejectedValue(new Error('Database error'));
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-password');

      await expect(authService.signUp(signUpDto)).rejects.toThrow(
        'Database error',
      );
    });
  });

  describe('signIn', () => {
    const signInDto: SignInDto = {
      email: 'test@example.com',
      password: 'Password123!',
    };

    it('should successfully sign in a user', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);
      jest
        .spyOn(refreshTokenRepository, 'create')
        .mockReturnValue(mockRefreshToken);
      jest
        .spyOn(refreshTokenRepository, 'save')
        .mockResolvedValue(mockRefreshToken);

      const result = await authService.signIn(signInDto);

      expect(result).toBeDefined();
      expect(result.user.email).toBe(mockUser.email);
      expect(result.tokens.accessToken).toBe('access-token');
      expect(result.tokens.refreshToken).toBe('test-uuid');
      expect(result.twoFactorRequired).toBeUndefined();
    });

    it('should return twoFactorRequired if 2FA is enabled', async () => {
      const userWith2FA = {
        ...mockUser,
        twoFactorAuth: { isEnabled: true },
      };

      jest
        .spyOn(userRepository, 'findOne')
        .mockResolvedValue(userWith2FA as User);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const result = await authService.signIn(signInDto);

      expect(result.twoFactorRequired).toBe(true);
      expect(result.tokens.accessToken).toBe('');
      expect(result.tokens.refreshToken).toBe('');
    });

    it('should throw UnauthorizedException for invalid credentials', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(authService.signIn(signInDto)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException if user not found', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);

      await expect(authService.signIn(signInDto)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(bcrypt.compare).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException if account is deactivated', async () => {
      const inactiveUser = { ...mockUser, isActive: false };
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(inactiveUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      await expect(authService.signIn(signInDto)).rejects.toThrow(
        new UnauthorizedException('Account is deactivated'),
      );
    });
  });

  describe('refreshToken', () => {
    it('should successfully refresh access token', async () => {
      jest
        .spyOn(refreshTokenRepository, 'findOne')
        .mockResolvedValue(mockRefreshToken);

      const result = await authService.refreshToken('refresh-token-uuid');

      expect(result).toBeDefined();
      expect(result.accessToken).toBe('access-token');
      expect(jwtService.sign).toHaveBeenCalledWith({
        sub: mockUser.id,
        email: mockUser.email,
      });
    });

    it('should throw UnauthorizedException for invalid token', async () => {
      jest.spyOn(refreshTokenRepository, 'findOne').mockResolvedValue(null);

      await expect(authService.refreshToken('invalid-token')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException for expired token', async () => {
      const expiredToken = {
        ...mockRefreshToken,
        expiresAt: new Date(Date.now() - 1000), // Expired 1 second ago
      };

      jest
        .spyOn(refreshTokenRepository, 'findOne')
        .mockResolvedValue(expiredToken);

      await expect(
        authService.refreshToken('refresh-token-uuid'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('logout', () => {
    it('should successfully logout user', async () => {
      const deleteResult = { affected: 1, raw: [] };
      jest
        .spyOn(refreshTokenRepository, 'delete')
        .mockResolvedValue(deleteResult as any);

      const result = await authService.logout('refresh-token-uuid');

      expect(result).toEqual({ message: 'Logged out successfully' });
      expect(refreshTokenRepository.delete).toHaveBeenCalledWith({
        token: 'refresh-token-uuid',
      });
    });

    it('should return already logged out if token not found', async () => {
      const deleteResult = { affected: 0, raw: [] };
      jest
        .spyOn(refreshTokenRepository, 'delete')
        .mockResolvedValue(deleteResult as any);

      const result = await authService.logout('non-existent-token');

      expect(result).toEqual({ message: 'Already logged out' });
    });
  });

  describe('forgotPassword', () => {
    it('should send password reset email if user exists', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser);
      jest
        .spyOn(passwordResetRepository, 'create')
        .mockReturnValue(mockPasswordReset);
      jest
        .spyOn(passwordResetRepository, 'save')
        .mockResolvedValue(mockPasswordReset);

      const result = await authService.forgotPassword('test@example.com');

      expect(result).toEqual({
        message: 'If email exists, reset link has been sent',
      });
      expect(emailService.sendPasswordResetEmail).toHaveBeenCalledWith(
        'test@example.com',
        'test-uuid',
      );
    });

    it('should return generic message if user does not exist', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);

      const result = await authService.forgotPassword(
        'nonexistent@example.com',
      );

      expect(result).toEqual({
        message: 'If email exists, reset link has been sent',
      });
      expect(passwordResetRepository.save).not.toHaveBeenCalled();
      expect(emailService.sendPasswordResetEmail).not.toHaveBeenCalled();
    });

    it('should handle email service error gracefully', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser);
      jest
        .spyOn(passwordResetRepository, 'create')
        .mockReturnValue(mockPasswordReset);
      jest
        .spyOn(passwordResetRepository, 'save')
        .mockResolvedValue(mockPasswordReset);
      jest
        .spyOn(emailService, 'sendPasswordResetEmail')
        .mockRejectedValue(new Error('Email service error'));

      await expect(
        authService.forgotPassword('test@example.com'),
      ).rejects.toThrow('Email service error');
    });
  });

  describe('resetPassword', () => {
    const resetPasswordDto: ResetPasswordDto = {
      token: 'reset-token',
      newPassword: 'NewPassword123!',
    };

    it('should successfully reset password', async () => {
      jest
        .spyOn(passwordResetRepository, 'findOne')
        .mockResolvedValue(mockPasswordReset);
      jest.spyOn(userRepository, 'update').mockResolvedValue({} as any);
      jest
        .spyOn(passwordResetRepository, 'delete')
        .mockResolvedValue({} as any);
      (bcrypt.hash as jest.Mock).mockResolvedValue('new-hashed-password');

      const result = await authService.resetPassword(resetPasswordDto);

      expect(result).toEqual({ message: 'Password reset successful' });
      expect(bcrypt.hash).toHaveBeenCalledWith(
        resetPasswordDto.newPassword,
        12,
      );
      expect(userRepository.update).toHaveBeenCalledWith(mockUser.id, {
        password: 'new-hashed-password',
      });
      expect(passwordResetRepository.delete).toHaveBeenCalledWith({
        token: resetPasswordDto.token,
      });
    });

    it('should throw BadRequestException for invalid token', async () => {
      jest.spyOn(passwordResetRepository, 'findOne').mockResolvedValue(null);

      await expect(authService.resetPassword(resetPasswordDto)).rejects.toThrow(
        BadRequestException,
      );
      expect(userRepository.update).not.toHaveBeenCalled();
    });

    it('should throw BadRequestException for expired token', async () => {
      const expiredReset = {
        ...mockPasswordReset,
        expiresAt: new Date(Date.now() - 1000), // Expired 1 second ago
      };

      jest
        .spyOn(passwordResetRepository, 'findOne')
        .mockResolvedValue(expiredReset);

      await expect(authService.resetPassword(resetPasswordDto)).rejects.toThrow(
        new BadRequestException('Invalid or expired reset token'),
      );
      expect(userRepository.update).not.toHaveBeenCalled();
    });

    it('should handle database update error', async () => {
      jest
        .spyOn(passwordResetRepository, 'findOne')
        .mockResolvedValue(mockPasswordReset);
      jest
        .spyOn(userRepository, 'update')
        .mockRejectedValue(new Error('Database error'));
      (bcrypt.hash as jest.Mock).mockResolvedValue('new-hashed-password');

      await expect(authService.resetPassword(resetPasswordDto)).rejects.toThrow(
        'Database error',
      );
      expect(passwordResetRepository.delete).not.toHaveBeenCalled();
    });
  });

  describe('verifyEmail', () => {
    it('should successfully verify email', async () => {
      const userWithToken = {
        ...mockUser,
        emailVerificationToken: 'verification-token',
      };

      jest.spyOn(userRepository, 'findOne').mockResolvedValue(userWithToken);
      jest.spyOn(userRepository, 'save').mockResolvedValue({
        ...userWithToken,
        emailVerified: true,
        emailVerificationToken: null,
      });

      const result = await authService.verifyEmail('verification-token');

      expect(result).toEqual({ message: 'Email verified successfully' });
      expect(userRepository.save).toHaveBeenCalledWith({
        ...userWithToken,
        emailVerified: true,
        emailVerificationToken: null,
      });
    });

    it('should throw BadRequestException for invalid token', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);

      await expect(authService.verifyEmail('invalid-token')).rejects.toThrow(
        new BadRequestException('Invalid verification token'),
      );
      expect(userRepository.save).not.toHaveBeenCalled();
    });

    it('should handle database save error', async () => {
      const userWithToken = {
        ...mockUser,
        emailVerificationToken: 'verification-token',
      };

      jest.spyOn(userRepository, 'findOne').mockResolvedValue(userWithToken);
      jest
        .spyOn(userRepository, 'save')
        .mockRejectedValue(new Error('Database error'));

      await expect(
        authService.verifyEmail('verification-token'),
      ).rejects.toThrow('Database error');
    });
  });

  describe('Edge Cases and Error Handling', () => {
    describe('Token Generation', () => {
      it('should handle different refresh token expiration formats', async () => {
        const signInDto: SignInDto = {
          email: 'test@example.com',
          password: 'Password123!',
        };

        // Test with hours format
        jest
          .spyOn(configService, 'get')
          .mockImplementation((key: string, defaultValue?: any) => {
            const config = {
              BCRYPT_ROUNDS: 12,
              PASSWORD_RESET_EXPIRES_IN: 3600000,
              'jwt.refreshExpiresIn': '24h', // Changed to hours
              'jwt.secret': 'test-secret',
              'jwt.expiresIn': '15m',
              BACKEND_URL: 'http://localhost:3001',
              FRONTEND_URL: 'http://localhost:3000',
              APP_NAME: 'Test App',
            };
            return config[key] || defaultValue;
          });

        jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser);
        (bcrypt.compare as jest.Mock).mockResolvedValue(true);
        jest
          .spyOn(refreshTokenRepository, 'create')
          .mockReturnValue(mockRefreshToken);
        jest
          .spyOn(refreshTokenRepository, 'save')
          .mockResolvedValue(mockRefreshToken);

        const result = await authService.signIn(signInDto);
        expect(result.tokens).toBeDefined();
      });

      it('should handle minutes format for token expiration', async () => {
        const signInDto: SignInDto = {
          email: 'test@example.com',
          password: 'Password123!',
        };

        jest
          .spyOn(configService, 'get')
          .mockImplementation((key: string, defaultValue?: any) => {
            const config = {
              BCRYPT_ROUNDS: 12,
              PASSWORD_RESET_EXPIRES_IN: 3600000,
              'jwt.refreshExpiresIn': '30m', // Changed to minutes
              'jwt.secret': 'test-secret',
              'jwt.expiresIn': '15m',
              BACKEND_URL: 'http://localhost:3001',
              FRONTEND_URL: 'http://localhost:3000',
              APP_NAME: 'Test App',
            };
            return config[key] || defaultValue;
          });

        jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser);
        (bcrypt.compare as jest.Mock).mockResolvedValue(true);
        jest
          .spyOn(refreshTokenRepository, 'create')
          .mockReturnValue(mockRefreshToken);
        jest
          .spyOn(refreshTokenRepository, 'save')
          .mockResolvedValue(mockRefreshToken);

        const result = await authService.signIn(signInDto);
        expect(result.tokens).toBeDefined();
      });

      it('should use default expiration for invalid format', async () => {
        const signInDto: SignInDto = {
          email: 'test@example.com',
          password: 'Password123!',
        };

        jest
          .spyOn(configService, 'get')
          .mockImplementation((key: string, defaultValue?: any) => {
            const config = {
              BCRYPT_ROUNDS: 12,
              PASSWORD_RESET_EXPIRES_IN: 3600000,
              'jwt.refreshExpiresIn': 'invalid', // Invalid format
              'jwt.secret': 'test-secret',
              'jwt.expiresIn': '15m',
              BACKEND_URL: 'http://localhost:3001',
              FRONTEND_URL: 'http://localhost:3000',
              APP_NAME: 'Test App',
            };
            return config[key] || defaultValue;
          });

        jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser);
        (bcrypt.compare as jest.Mock).mockResolvedValue(true);
        jest
          .spyOn(refreshTokenRepository, 'create')
          .mockReturnValue(mockRefreshToken);
        jest
          .spyOn(refreshTokenRepository, 'save')
          .mockResolvedValue(mockRefreshToken);

        const result = await authService.signIn(signInDto);
        expect(result.tokens).toBeDefined();
      });
    });
  });
});
