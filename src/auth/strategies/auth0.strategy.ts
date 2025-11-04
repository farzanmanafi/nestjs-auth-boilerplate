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
      state: false,
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    extraParams: any,
    profile: any,
  ): Promise<SSOProfile> {
    // Auth0 profile structure typically has the data in _json
    const jsonProfile = profile._json || profile;

    console.log('Auth0 raw profile:', JSON.stringify(profile, null, 2)); // Debug log

    return {
      id: profile.id || jsonProfile.sub || jsonProfile.user_id,
      email:
        jsonProfile.email ||
        profile.emails?.[0]?.value ||
        jsonProfile.email_verified,
      firstName:
        jsonProfile.given_name ||
        profile.name?.givenName ||
        jsonProfile.nickname ||
        '',
      lastName: jsonProfile.family_name || profile.name?.familyName || '',
      provider: 'auth0',
      providerId: profile.id || jsonProfile.sub || jsonProfile.user_id,
    };
  }
}
