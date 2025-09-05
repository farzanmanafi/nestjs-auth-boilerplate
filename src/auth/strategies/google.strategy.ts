import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';
import { SSOProfile } from '@/common/types/auth.types';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private configService: ConfigService) {
    super({
      clientID: configService.get('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.get('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
  }

async validate(
  accessToken: string,
  refreshToken: string,
  profile: any,
  done: VerifyCallback,
): Promise<any> {
  const user: SSOProfile = {
    id: profile.id,
    email: profile.emails?.[0]?.value,
    firstName: profile.name?.givenName || '',
    lastName: profile.name?.familyName || '',
    provider: 'google',
    providerId: profile.id,
  };
  done(null, user);
}
}