
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

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @ApiOperation({ summary: 'User registration' })
  @HttpCode(HttpStatus.CREATED)
  async signUp(@Body() signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }

  @Post('signin')
  @ApiOperation({ summary: 'User login' })
  @HttpCode(HttpStatus.OK)
  async signIn(@Body() signInDto: SignInDto) {
    return this.authService.signIn(signInDto);
  }

  @Post('refresh')
  @ApiOperation({ summary: 'Refresh access token' })
  @HttpCode(HttpStatus.OK)
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshToken(refreshTokenDto.refreshToken);
  }

  @Post('logout')
  @ApiOperation({ summary: 'User logout' })
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  async logout(@GetUser() user: User, @Body() body: { refreshToken: string }) {
    return this.authService.logout(user.id, body.refreshToken);
  }

  @Post('forgot-password')
  @ApiOperation({ summary: 'Request password reset' })
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto.email);
  }

  @Post('reset-password')
  @ApiOperation({ summary: 'Reset password with token' })
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(resetPasswordDto);
  }

  @Get('verify-email')
  @ApiOperation({ summary: 'Verify email address' })
  async verifyEmail(@Query('token') token: string) {
    return this.authService.verifyEmail(token);
  }

  // ==========================================
  // TWO-FACTOR AUTHENTICATION
  // ==========================================
  @Post('2fa/setup')
  @ApiOperation({ summary: 'Setup two-factor authentication' })
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  async setupTwoFactor(@GetUser() user: User) {
    return this.authService.setupTwoFactor(user.id);
  }

  @Post('2fa/verify')
  @ApiOperation({ summary: 'Verify two-factor authentication setup' })
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  async verifyTwoFactor(
    @GetUser() user: User,
    @Body() verifyTwoFactorDto: VerifyTwoFactorDto,
  ) {
    return this.authService.verifyTwoFactor(user.id, verifyTwoFactorDto.token);
  }

  @Post('2fa/authenticate')
  @ApiOperation({ summary: 'Authenticate with two-factor code' })
  async authenticateWithTwoFactor(@Body() body: { email: string; password: string; token: string }) {
    return this.authService.authenticateWithTwoFactor(body.email, body.password, body.token);
  }

  @Post('2fa/disable')
  @ApiOperation({ summary: 'Disable two-factor authentication' })
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  async disableTwoFactor(@GetUser() user: User, @Body() body: { token: string }) {
    return this.authService.disableTwoFactor(user.id, body.token);
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
    res.redirect(`${process.env.FRONTEND_URL}/auth/success?token=${result.tokens.accessToken}`);
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
    res.redirect(`${process.env.FRONTEND_URL}/auth/success?token=${result.tokens.accessToken}`);
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
  async revokeSession(@GetUser() user: User, @Body() body: { sessionId: string }) {
    return this.authService.revokeSession(user.id, body.sessionId);
  }
}