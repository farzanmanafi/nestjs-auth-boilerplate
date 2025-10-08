// src/auth/strategies/jwt.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private authService: AuthService,
  ) {
    super({
      // 1. Tell Passport where to find the JWT
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      // 2. Don't accept expired tokens
      ignoreExpiration: false,
      // 3. Secret key to verify signature
      secretOrKey:
        configService.get('jwt.secret') || configService.get('JWT_SECRET'),
    });
  }

  async validate(payload: any) {
    // Payload = { sub: 'user-id', email: 'user@example.com' }

    // 5. Load full user from database and return it
    return this.authService.validateUser(payload);
  }
}
