import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

class MockJwtAuthGuard {
  canActivate() {
    return true;
  }
}

describe('AuthController', () => {
  let app: INestApplication;
  let controller: AuthController;
  let authService: jest.Mocked<AuthService>;

  beforeEach(async () => {
    const moduleRef: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: {
            signUp: jest.fn(),
            signIn: jest.fn(),
            refreshToken: jest.fn(),
            logout: jest.fn(),
            forgotPassword: jest.fn(),
            resetPassword: jest.fn(),
            verifyEmail: jest.fn(),
            setupTwoFactor: jest.fn(),
            verifyTwoFactor: jest.fn(),
            authenticateWithTwoFactor: jest.fn(),
            disableTwoFactor: jest.fn(),
            handleAuth0Callback: jest.fn(),
            handleGoogleCallback: jest.fn(),
            getProfile: jest.fn(),
            getActiveSessions: jest.fn(),
            revokeSession: jest.fn(),
          },
        },
        {
          provide: JwtAuthGuard,
          useClass: MockJwtAuthGuard,
        },
      ],
    }).compile();

    controller = moduleRef.get<AuthController>(AuthController);
    authService = moduleRef.get(AuthService);

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('should sign up a new user', async () => {
    const dto = {
      email: 'new@example.com',
      password: 'Passw0rd!',
      firstName: 'New',
      lastName: 'User',
    } as any;
    const expected = {
      user: { id: '1', email: dto.email },
      tokens: { accessToken: 'a', refreshToken: 'r' },
    };
    authService.signUp.mockResolvedValue(expected as any);

    const res = await controller.signUp(dto);

    expect(authService.signUp).toHaveBeenCalledWith(dto);
    expect(res).toEqual(expected);
  });

  it('should sign in an existing user', async () => {
    const dto = { email: 'e@example.com', password: 'p' } as any;
    const expected = {
      user: { id: '1', email: dto.email },
      tokens: { accessToken: 'a', refreshToken: 'r' },
    };
    authService.signIn.mockResolvedValue(expected as any);

    const res = await controller.signIn(dto);

    expect(authService.signIn).toHaveBeenCalledWith(dto);
    expect(res).toEqual(expected);
  });

  it('should refresh access token', async () => {
    const dto = { refreshToken: 'rt' } as any;
    const expected = { accessToken: 'new-access' };
    authService.refreshToken.mockResolvedValue(expected as any);

    const res = await controller.refreshToken(dto);

    expect(authService.refreshToken).toHaveBeenCalledWith('rt');
    expect(res).toEqual(expected);
  });

  it('should logout user with refresh token', async () => {
    const body = { refreshToken: 'rt' };
    const expected = { message: 'Logged out successfully' };
    authService.logout.mockResolvedValue(expected as any);

    const res = await controller.logout(body);

    expect(authService.logout).toHaveBeenCalledWith('rt');
    expect(res).toEqual(expected);
  });

  it('should initiate forgot password flow', async () => {
    const dto = { email: 'e@example.com' } as any;
    const expected = { message: 'If email exists, reset link has been sent' };
    authService.forgotPassword.mockResolvedValue(expected as any);

    const res = await controller.forgotPassword(dto);

    expect(authService.forgotPassword).toHaveBeenCalledWith('e@example.com');
    expect(res).toEqual(expected);
  });

  it('should reset password', async () => {
    const dto = { token: 't', newPassword: 'NewPass123!' } as any;
    const expected = { message: 'Password reset successful' };
    authService.resetPassword.mockResolvedValue(expected as any);

    const res = await controller.resetPassword(dto);

    expect(authService.resetPassword).toHaveBeenCalledWith(dto);
    expect(res).toEqual(expected);
  });

  it('should verify email', async () => {
    const token = 'verif-token';
    const expected = { message: 'Email verified successfully' };
    authService.verifyEmail.mockResolvedValue(expected as any);

    const res = await controller.verifyEmail(token);

    expect(authService.verifyEmail).toHaveBeenCalledWith(token);
    expect(res).toEqual(expected);
  });

  it('should setup two-factor for authenticated user', async () => {
    const user = { id: 'u1' } as any;
    const expected = { qrCode: 'qrcode', secret: 'secret' };
    authService.setupTwoFactor.mockResolvedValue(expected as any);

    const res = await controller.setupTwoFactor(user);

    expect(authService.setupTwoFactor).toHaveBeenCalledWith('u1');
    expect(res).toEqual(expected);
  });

  it('should verify two-factor token for setup', async () => {
    const user = { id: 'u1' } as any;
    const dto = { token: '123456' } as any;
    const expected = {
      message: 'Two-factor authentication enabled successfully',
    };
    authService.verifyTwoFactor.mockResolvedValue(expected as any);

    const res = await controller.verifyTwoFactor(user, dto);

    expect(authService.verifyTwoFactor).toHaveBeenCalledWith('u1', '123456');
    expect(res).toEqual(expected);
  });

  it('should authenticate with two-factor token', async () => {
    const body = { email: 'e@example.com', password: 'p', token: '123456' };
    const expected = {
      user: { id: '1' },
      tokens: { accessToken: 'a', refreshToken: 'r' },
    };
    authService.authenticateWithTwoFactor.mockResolvedValue(expected as any);

    const res = await controller.authenticateWithTwoFactor(body);

    expect(authService.authenticateWithTwoFactor).toHaveBeenCalledWith(
      'e@example.com',
      'p',
      '123456',
    );
    expect(res).toEqual(expected);
  });

  it('should disable two-factor for authenticated user', async () => {
    const user = { id: 'u1' } as any;
    const body = { token: '123456' };
    const expected = {
      message: 'Two-factor authentication disabled successfully',
    };
    authService.disableTwoFactor.mockResolvedValue(expected as any);

    const res = await controller.disableTwoFactor(user, body);

    expect(authService.disableTwoFactor).toHaveBeenCalledWith('u1', '123456');
    expect(res).toEqual(expected);
  });

  it('should get profile for authenticated user', async () => {
    const user = { id: 'u1' } as any;
    const expected = { id: 'u1', email: 'e@example.com' };
    authService.getProfile.mockResolvedValue(expected as any);

    const res = await controller.getProfile(user);

    expect(authService.getProfile).toHaveBeenCalledWith('u1');
    expect(res).toEqual(expected);
  });

  it('should get active sessions for authenticated user', async () => {
    const user = { id: 'u1' } as any;
    const expected = [{ id: 's1' }];
    authService.getActiveSessions.mockResolvedValue(expected as any);

    const res = await controller.getActiveSessions(user);

    expect(authService.getActiveSessions).toHaveBeenCalledWith('u1');
    expect(res).toEqual(expected);
  });

  it('should revoke a session for authenticated user', async () => {
    const user = { id: 'u1' } as any;
    const body = { sessionId: 's1' };
    const expected = { message: 'Session revoked' };
    authService.revokeSession.mockResolvedValue(expected as any);

    const res = await controller.revokeSession(user, body);

    expect(authService.revokeSession).toHaveBeenCalledWith('u1', 's1');
    expect(res).toEqual(expected);
  });
});
