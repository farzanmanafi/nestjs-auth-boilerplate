import {
  Controller,
  Post,
  Body,
  Get,
  Query,
  UseGuards,
  Req,
  Res,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Response, Request } from 'express';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';

import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup.dto';
import { SignInDto } from './dto/signin.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { VerifyTwoFactorDto } from './dto/verify-two-factor.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { GetUser } from './decorators/get-user.decorator';
import { User } from '../users/entities/user.entity';
import { SignUpDec } from './decorators/signup.decorator';
import { SigninDec } from './decorators/signin.decorator';
import { RefreshDec } from './decorators/refresh-token.decorator';
import { LogoutDec } from './decorators/logout.decorator';
import { ForgetPasswordDec } from './decorators/forget-password.decorator';
import { ResetPasswordDec } from './decorators/reset-passworf.decorator';
import { VerifyEmailDec } from './decorators/verify-email.decorator';
import { SetupTwoFactorDec } from './decorators/setup-two-factor.decorator';
import { VerifyTwoFactorDec } from './decorators/verify-two-factor.decorator';
import { AuthenticateWithTwoFactorDec } from './decorators/authenticate-with-two-factor.decorator';
import { AuthenticateWithTwoFactorDto } from './dto/authenticate-with-two-factor.dto';
import { DisableTwoFactorDto } from './dto/disable-two-factor.dto';
import { DisableTwoFactorDec } from './decorators/disable-two-factor.decorator';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * Signs up a new user.
   * @param {SignUpDto} signUpDto - Details of the user to be signed up.
   * @returns {Promise<AuthResponse>} - User signed up successfully with tokens.
   */
  @Post('signup')
  @SignUpDec()
  async signUp(@Body() signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }

  /**
   * Signs in an existing user.
   * @param {SignInDto} signInDto - Credentials of the user to be signed in.
   * @returns {Promise<AuthResponse>} - User signed in successfully with tokens.
   */
  @Post('signin')
  @SigninDec()
  async signIn(@Body() signInDto: SignInDto) {
    return this.authService.signIn(signInDto);
  }

  /**
   * Refreshes an access token with a given refresh token.
   * @param refreshTokenDto - Refresh token to be used to generate a new access token.
   * @returns {Promise<AuthResponse>} - New access token generated successfully with refresh token.
   */
  @Post('refresh')
  @RefreshDec()
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshToken(refreshTokenDto.refreshToken);
  }

  /**
   * Log out user by deleting the refresh token associated with their user.
   * This endpoint can be called by anyone, as the refresh token itself is the proof of identity.
   * @param body.refreshToken - The refresh token to be deleted.
   * @returns {Promise<{ message: string }>} - Promise resolving with success message.
   */
  @Post('logout')
  @LogoutDec()
  async logout(@Body() body: { refreshToken: string }) {
    // No @UseGuards - anyone can call this
    // The refresh token itself is the proof of identity
    return this.authService.logout(body.refreshToken);
  }

  /**
   * Forgot password.
   * Sends a password reset link to the user's email address if email exists.
   * @param {ForgotPasswordDto} forgotPasswordDto - Forgot password data transfer object.
   * @returns {Promise<{ message: string }>} - Promise resolving with success message if email exists.
   */
  @Post('forgot-password')
  @ForgetPasswordDec()
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto.email);
  }

  /**
   * Resets a user's password.
   * @param {ResetPasswordDto} resetPasswordDto - Reset password data transfer object.
   * @returns {Promise<void>} - Promise resolving when the password has been reset successfully.
   */
  @Post('reset-password')
  @ResetPasswordDec()
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(resetPasswordDto);
  }

  /**
   * Verify email address using a given token.
   * @param token - Verification token received in the email.
   * @returns {Promise<void>} - Promise resolving when the email address is verified.
   */
  @Get('verify-email')
  @VerifyEmailDec()
  async verifyEmail(@Query('token') token: string) {
    return this.authService.verifyEmail(token);
  }

  // =========================================
  // TWO-FACTOR AUTHENTICATION
  // ==========================================

  /**
   * Generates a QR code and secret for setting up two-factor authentication.
   * User must scan the QR code with an authenticator app.
   * @returns {Promise<{ qrCode: string, secret: string }>} - Promise resolving with QR code and secret for two-factor authentication setup.
   */
  @Post('2fa/setup')
  @SetupTwoFactorDec()
  @UseGuards(JwtAuthGuard)
  async setupTwoFactor(@GetUser() user: User) {
    return this.authService.setupTwoFactor(user.id);
  }

  /**
   * Verify two-factor authentication setup.
   * @param user - Logged in user.
   * @param verifyTwoFactorDto - Verify two-factor authentication data transfer object.
   * @returns {Promise<{ message: string }>} - Promise resolving with success message if two-factor authentication setup is verified successfully.
   */
  @Post('2fa/verify')
  @VerifyTwoFactorDec()
  @UseGuards(JwtAuthGuard)
  async verifyTwoFactor(
    @GetUser() user: User,
    @Body() verifyTwoFactorDto: VerifyTwoFactorDto,
  ) {
    return this.authService.verifyTwoFactor(user.id, verifyTwoFactorDto.token);
  }

  /**
   * Authenticate with two-factor authentication.
   * @param {AuthenticateWithTwoFactorDto} authenticateWithTwoFactorDto - Authenticate with two-factor authentication data transfer object.
   * @returns {Promise<{ user: UserProfile, tokens: AuthTokens }>} - Promise resolving with user profile and authentication tokens on successful authentication.
   */
  @Post('2fa/authenticate')
  @AuthenticateWithTwoFactorDec()
  async authenticateWithTwoFactor(
    @Body() authenticateWithTwoFactorDto: AuthenticateWithTwoFactorDto,
  ) {
    return this.authService.authenticateWithTwoFactor(
      authenticateWithTwoFactorDto.email,
      authenticateWithTwoFactorDto.password,
      authenticateWithTwoFactorDto.token,
    );
  }

  /**
   * Disable two-factor authentication for a user.
   * @param user - Logged in user.
   * @param disableTwoFactorDto - Disable two-factor authentication data transfer object.
   * @returns {Promise<{ message: string }>} - Promise resolving when two-factor authentication has been disabled successfully.
   */
  @Post('2fa/disable')
  @DisableTwoFactorDec()
  @UseGuards(JwtAuthGuard)
  async disableTwoFactor(
    @GetUser() user: User,
    @Body() disableTwoFactorDto: DisableTwoFactorDto,
  ) {
    return this.authService.disableTwoFactor(
      user.id,
      disableTwoFactorDto.token,
    );
  }

  // ==========================================
  // AUTH0 INTEGRATION
  // ==========================================
  @Get('auth0')
  @ApiOperation({ summary: 'Auth0 login' })
  @UseGuards(AuthGuard('auth0'))
  async auth0Login() {
    // Auth0 will handle the redirect
  }

  @Get('auth0/callback')
  @ApiOperation({ summary: 'Auth0 callback' })
  @UseGuards(AuthGuard('auth0'))
  async auth0Callback(@Req() req: Request, @Res() res: Response) {
    const result = await this.authService.handleAuth0Callback(req.user as any);
    res.redirect(
      `${process.env.FRONTEND_URL}/auth/success?token=${result.tokens.accessToken}`,
    );
  }

  // ==========================================
  // SSO (Google OAuth)
  // ==========================================
  @Get('google')
  @ApiOperation({ summary: 'Google OAuth login' })
  @UseGuards(AuthGuard('google'))
  async googleLogin() {
    // Google will handle the redirect
  }

  @Get('google/callback')
  @ApiOperation({ summary: 'Google OAuth callback' })
  @UseGuards(AuthGuard('google'))
  async googleCallback(@Req() req: Request, @Res() res: Response) {
    const result = await this.authService.handleGoogleCallback(req.user as any);
    res.redirect(
      `${process.env.FRONTEND_URL}/auth/success?token=${result.tokens.accessToken}`,
    );
  }

  // ==========================================
  // PROFILE & SESSION MANAGEMENT
  // ==========================================
  @Get('profile')
  @ApiOperation({ summary: 'Get user profile' })
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  async getProfile(@GetUser() user: User) {
    return this.authService.getProfile(user.id);
  }

  @Get('sessions')
  @ApiOperation({ summary: 'Get active sessions' })
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  async getActiveSessions(@GetUser() user: User) {
    return this.authService.getActiveSessions(user.id);
  }

  @Post('sessions/revoke')
  @ApiOperation({ summary: 'Revoke session' })
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  async revokeSession(
    @GetUser() user: User,
    @Body() body: { sessionId: string },
  ) {
    return this.authService.revokeSession(user.id, body.sessionId);
  }
}
