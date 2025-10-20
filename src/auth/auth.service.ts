import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';
import { v4 as uuid } from 'uuid';

import { User } from '../users/entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { PasswordReset } from './entities/password-reset.entity';
import { TwoFactorAuth } from './entities/two-factor-auth.entity';
import { SignUpDto } from './dto/signup.dto';
import { SignInDto } from './dto/signin.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { EmailService } from '../email/email.service';
import {
  AuthResponse,
  AuthTokens,
  UserProfile,
  TwoFactorSetupResponse,
  SSOProfile,
  SessionInfo,
} from '../common/types/auth.types';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: Repository<RefreshToken>,
    @InjectRepository(PasswordReset)
    private passwordResetRepository: Repository<PasswordReset>,
    @InjectRepository(TwoFactorAuth)
    private twoFactorRepository: Repository<TwoFactorAuth>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private emailService: EmailService,
  ) {}

  // ==========================================
  // BASIC AUTH OPERATIONS
  // ==========================================

  /**
   * SignUp a new user.
   * @param {SignUpDto} signUpDto - SignUp data transfer object.
   * @returns {Promise<AuthResponse>} - Promise resolving with AuthResponse object containing user and tokens.
   * @throws {ConflictException} - If user already exists.
   */
  async signUp(signUpDto: SignUpDto): Promise<AuthResponse> {
    const { email, password, firstName, lastName } = signUpDto;

    // Check if user already exists
    const existingUser = await this.userRepository.findOne({
      where: { email },
    });
    if (existingUser) {
      throw new ConflictException('User already exists');
    }

    // Hash password
    const saltRounds = Number(this.configService.get('BCRYPT_ROUNDS', 12));
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = this.userRepository.create({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      emailVerified: false,
      emailVerificationToken: uuid(),
    });

    const savedUser = await this.userRepository.save(user);

    // Send verification email
    await this.emailService.sendVerificationEmail(
      savedUser.email,
      savedUser.emailVerificationToken,
    );

    // Generate tokens
    const tokens = await this.generateTokens(savedUser);

    return {
      user: this.mapUserToProfile(savedUser),
      tokens,
    };
  }

  /**
   * Signs in a user
   *
   * @param {SignInDto} signInDto - signin request
   * @returns {Promise<AuthResponse>} - user profile and tokens
   * @throws {UnauthorizedException} - if invalid credentials
   * @throws {UnauthorizedException} - if account is deactivated
   */
  async signIn(signInDto: SignInDto): Promise<AuthResponse> {
    const { email, password } = signInDto;

    // Find user
    const user = await this.userRepository.findOne({
      where: { email },
      relations: ['twoFactorAuth'],
    });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Account is deactivated');
    }

    // Check if 2FA is enabled
    if (user.twoFactorAuth && user.twoFactorAuth.isEnabled) {
      return {
        user: this.mapUserToProfile(user),
        tokens: { accessToken: '', refreshToken: '' },
        twoFactorRequired: true,
      };
    }

    // Generate tokens
    const tokens = await this.generateTokens(user);

    return {
      user: this.mapUserToProfile(user),
      tokens,
    };
  }

  /**
   * Log out user by deleting the refresh token associated with their user.
   *
   * @param refreshToken - The refresh token to delete.
   * @returns A promise that resolves to an object with a single property 'message' that contains a success message.
   * @throws {UnauthorizedException} - If the refresh token is invalid or has expired.
   */
  async refreshToken(refreshToken: string): Promise<{ accessToken: string }> {
    // 1. Find refresh token in database
    const tokenEntity = await this.refreshTokenRepository.findOne({
      where: { token: refreshToken },
      relations: ['user'],
    });

    // 2. Check if token exists and hasn't expired
    if (!tokenEntity || tokenEntity.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // 3. Generate NEW access token
    const accessToken = this.jwtService.sign({
      sub: tokenEntity.user.id,
      email: tokenEntity.user.email,
    });

    // 4. Return new access token
    return { accessToken };
  }

  /**
   * Log out user by deleting the refresh token associated with their user.
   * @param refreshToken - The refresh token to delete.
   * @returns A promise that resolves to an object with a single property 'message' that contains a success message.
   */
  async logout(refreshToken: string): Promise<{ message: string }> {
    // Find and delete the refresh token
    const result = await this.refreshTokenRepository.delete({
      token: refreshToken,
    });

    if (result.affected === 0) {
      // Token doesn't exist - might be already logged out
      // Don't throw error, just return success
      return { message: 'Already logged out' };
    }

    return { message: 'Logged out successfully' };
  }

  // ==========================================
  // PASSWORD RESET
  // ==========================================

  /**
   * Forgot password.
   * If email exists, a reset link will be sent to the email address.
   * @param {string} email - Email address to send the reset link to.
   * @returns {Promise<{ message: string }>} - Promise resolving with success message.
   */
  async forgotPassword(email: string): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({ where: { email } });

    if (!user) {
      // Don't reveal if email exists
      return { message: 'If email exists, reset link has been sent' };
    }

    // Create reset token
    const resetToken = uuid();
    const expiresAt = new Date();
    const expiresInMs = Number(
      this.configService.get('PASSWORD_RESET_EXPIRES_IN', 3600000),
    ); // 1 hour
    expiresAt.setTime(expiresAt.getTime() + expiresInMs);

    const passwordReset = this.passwordResetRepository.create({
      userId: user.id,
      token: resetToken,
      expiresAt,
    });

    await this.passwordResetRepository.save(passwordReset);

    // Send reset email
    await this.emailService.sendPasswordResetEmail(email, resetToken);

    return { message: 'If email exists, reset link has been sent' };
  }

  /**
   * Resets user password.
   * @param {ResetPasswordDto} resetPasswordDto - Reset password data transfer object.
   * @returns {Promise<{ message: string }>} - Promise resolving with success message.
   * @throws {BadRequestException} - If reset token is invalid or expired.
   */
  async resetPassword(
    resetPasswordDto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    const { token, newPassword } = resetPasswordDto;

    const passwordReset = await this.passwordResetRepository.findOne({
      where: { token },
      relations: ['user'],
    });

    if (!passwordReset || passwordReset.expiresAt < new Date()) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    // Hash new password
    const saltRounds = Number(this.configService.get('BCRYPT_ROUNDS', 12));
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update user password
    await this.userRepository.update(passwordReset.userId, {
      password: hashedPassword,
    });

    // Delete used reset token
    await this.passwordResetRepository.delete({ token });

    return { message: 'Password reset successful' };
  }

  // ==========================================
  // TWO-FACTOR AUTHENTICATION
  // ==========================================

  async setupTwoFactor(userId: string): Promise<TwoFactorSetupResponse> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `${this.configService.get('APP_NAME', 'App')} (${user.email})`,
      issuer: this.configService.get('APP_NAME', 'App'),
    });

    // Save secret (not enabled yet)
    let twoFactorAuth = await this.twoFactorRepository.findOne({
      where: { userId },
    });

    if (!twoFactorAuth) {
      twoFactorAuth = this.twoFactorRepository.create({
        userId,
        secret: secret.base32,
        isEnabled: false,
      });
    } else {
      twoFactorAuth.secret = secret.base32;
      twoFactorAuth.isEnabled = false;
    }

    await this.twoFactorRepository.save(twoFactorAuth);

    // Generate QR code
    const qrCode = await qrcode.toDataURL(secret.otpauth_url);

    return {
      qrCode,
      secret: secret.base32,
    };
  }

  async verifyTwoFactor(
    userId: string,
    token: string,
  ): Promise<{ message: string }> {
    const twoFactorAuth = await this.twoFactorRepository.findOne({
      where: { userId },
    });

    if (!twoFactorAuth) {
      throw new BadRequestException('Two-factor authentication not set up');
    }

    const verified = speakeasy.totp.verify({
      secret: twoFactorAuth.secret,
      encoding: 'base32',
      token,
      window: 1,
    });

    if (!verified) {
      throw new UnauthorizedException('Invalid two-factor token');
    }

    // Enable 2FA
    twoFactorAuth.isEnabled = true;
    await this.twoFactorRepository.save(twoFactorAuth);

    return { message: 'Two-factor authentication enabled successfully' };
  }

  async authenticateWithTwoFactor(
    email: string,
    password: string,
    token: string,
  ): Promise<AuthResponse> {
    const user = await this.userRepository.findOne({
      where: { email },
      relations: ['twoFactorAuth'],
    });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.twoFactorAuth || !user.twoFactorAuth.isEnabled) {
      throw new BadRequestException('Two-factor authentication not enabled');
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorAuth.secret,
      encoding: 'base32',
      token,
      window: 1,
    });

    if (!verified) {
      throw new UnauthorizedException('Invalid two-factor token');
    }

    const tokens = await this.generateTokens(user);

    return {
      user: this.mapUserToProfile(user),
      tokens,
    };
  }

  async disableTwoFactor(
    userId: string,
    token: string,
  ): Promise<{ message: string }> {
    const twoFactorAuth = await this.twoFactorRepository.findOne({
      where: { userId },
    });

    if (!twoFactorAuth || !twoFactorAuth.isEnabled) {
      throw new BadRequestException('Two-factor authentication not enabled');
    }

    const verified = speakeasy.totp.verify({
      secret: twoFactorAuth.secret,
      encoding: 'base32',
      token,
      window: 1,
    });

    if (!verified) {
      throw new UnauthorizedException('Invalid two-factor token');
    }

    await this.twoFactorRepository.delete({ userId });

    return { message: 'Two-factor authentication disabled successfully' };
  }

  // ==========================================
  // SSO HANDLERS
  // ==========================================
  async handleAuth0Callback(profile: SSOProfile): Promise<AuthResponse> {
    return this.handleSSOCallback(profile, 'auth0');
  }

  async handleGoogleCallback(profile: SSOProfile): Promise<AuthResponse> {
    return this.handleSSOCallback(profile, 'google');
  }

  private async handleSSOCallback(
    profile: SSOProfile,
    provider: string,
  ): Promise<AuthResponse> {
    const email = profile.email;

    let user = await this.userRepository.findOne({ where: { email } });

    if (!user) {
      // Create new user
      user = this.userRepository.create({
        email,
        firstName: profile.firstName || '',
        lastName: profile.lastName || '',
        emailVerified: true,
        ssoProvider: provider,
        ssoId: profile.providerId,
      });
      user = await this.userRepository.save(user);
    } else if (!user.ssoProvider) {
      // Link existing account
      user.ssoProvider = provider;
      user.ssoId = profile.providerId;
      user.emailVerified = true;
      await this.userRepository.save(user);
    }

    const tokens = await this.generateTokens(user);

    return {
      user: this.mapUserToProfile(user),
      tokens,
    };
  }

  // ==========================================
  // EMAIL VERIFICATION
  // ==========================================

  /**
   * Verify email address.
   * @param {string} token - Email verification token.
   * @returns {Promise<{ message: string }>} - Promise resolving with object containing success message.
   * @throws {BadRequestException} - If verification token is invalid.
   */
  async verifyEmail(token: string): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({
      where: { emailVerificationToken: token },
    });

    if (!user) {
      throw new BadRequestException('Invalid verification token');
    }

    user.emailVerified = true;
    user.emailVerificationToken = null;
    await this.userRepository.save(user);

    return { message: 'Email verified successfully' };
  }

  // ==========================================
  // SESSION MANAGEMENT
  // ==========================================
  async getProfile(userId: string): Promise<UserProfile> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return this.mapUserToProfile(user);
  }

  async getActiveSessions(userId: string): Promise<SessionInfo[]> {
    const sessions = await this.refreshTokenRepository.find({
      where: { userId },
      order: { createdAt: 'DESC' },
    });

    return sessions.map((session) => ({
      id: session.id,
      userId: session.userId,
      userAgent: session.userAgent,
      ipAddress: session.ipAddress,
      createdAt: session.createdAt,
      expiresAt: session.expiresAt,
      isActive: session.expiresAt > new Date(),
    }));
  }

  async revokeSession(
    userId: string,
    sessionId: string,
  ): Promise<{ message: string }> {
    await this.refreshTokenRepository.delete({ id: sessionId, userId });
    return { message: 'Session revoked successfully' };
  }

  // ==========================================
  // UTILITY METHODS
  // ==========================================

  /**
   * Generates access and refresh tokens for a given user.
   * @param user The user entity to generate tokens for.
   * @returns A promise containing the access and refresh tokens.
   */
  private async generateTokens(user: User): Promise<AuthTokens> {
    // 1. Create payload with user info
    const payload = { sub: user.id, email: user.email }; // "sub" = subject (standard JWT claim)

    // 2. Sign(create) ACCESS TOKEN (short-lived: 15 minutes)
    const accessToken = this.jwtService.sign(payload);

    // 3. Generate REFRESH TOKEN (long-lived: 7 days)
    const refreshToken = uuid();

    // Calculate expiration(Reads how long the refresh token should last — default 7 days if not set.)
    const refreshExpiresIn = this.configService.get(
      'jwt.refreshExpiresIn',
      '7d',
    );

    //Creates a Date object to calculate when the refresh token expires.
    const expiresAt = new Date();

    // Parse expiration string (e.g., "7d", "24h", "30m")
    const timeValue = parseInt(refreshExpiresIn);
    const timeUnit = refreshExpiresIn.replace(timeValue.toString(), '');

    switch (timeUnit) {
      case 'd':
        expiresAt.setDate(expiresAt.getDate() + timeValue);
        break;
      case 'h':
        expiresAt.setHours(expiresAt.getHours() + timeValue);
        break;
      case 'm':
        expiresAt.setMinutes(expiresAt.getMinutes() + timeValue);
        break;
      default:
        expiresAt.setDate(expiresAt.getDate() + 7); // Default 7 days
    }

    // Save refresh token
    const refreshTokenEntity = this.refreshTokenRepository.create({
      token: refreshToken,
      userId: user.id,
      expiresAt,
    });

    await this.refreshTokenRepository.save(refreshTokenEntity);

    return { accessToken, refreshToken };
  }

  /**
   * Maps a User entity to a UserProfile object.
   * @param user The User entity to map.
   * @returns A UserProfile object containing user information.
   */
  private mapUserToProfile(user: User): UserProfile {
    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  async validateUser(payload: any): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { id: payload.sub },
    });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    return user;
  }
}
