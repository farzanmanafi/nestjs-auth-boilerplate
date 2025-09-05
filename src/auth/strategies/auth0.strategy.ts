// src/auth/strategies/auth0.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-auth0';
import { ConfigService } from '@nestjs/config';
import { SSOProfile } from '@/common/types/auth.types';

@Injectable()
export class Auth0Strategy extends PassportStrategy(Strategy, 'auth0') {
  constructor(private configService: ConfigService) {
    super({
      domain: configService.get('AUTH0_DOMAIN'),
      clientID: configService.get('AUTH0_CLIENT_ID'),
      clientSecret: configService.get('AUTH0_CLIENT_SECRET'),
      callbackURL: configService.get('AUTH0_CALLBACK_URL'),
      scope: 'openid email profile',
    });
  }

  async validate(accessToken: string, refreshToken: string, extraParams: any, profile: any): Promise<SSOProfile> {
  return {
    id: profile.id,
    email: profile.emails?.[0]?.value || profile.email,
    firstName: profile.name?.givenName || profile.given_name || '',
    lastName: profile.name?.familyName || profile.family_name || '',
    provider: 'auth0',
    providerId: profile.id,
  };
}
}