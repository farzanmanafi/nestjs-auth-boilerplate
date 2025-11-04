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
      scope: ['openid', 'email', 'profile'],
      state: false,
      passReqToCallback: true,
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    extraParams: any,
    profile: any,
  ): Promise<SSOProfile> {
    // ❗ CRITICAL: Log the full profile to see the structure and confirm where the email is located
    console.log('Auth0 raw profile:', JSON.stringify(profile, null, 2));

    // 1. Try to extract email from the standard Passport emails array
    let email = profile.emails?.[0]?.value;

    // 2. If not found, check the _json object (where Auth0 often puts it)
    if (!email) {
      email = profile._json?.email;
    }

    // Extract other required fields
    const providerId = profile.id || profile._json?.sub;
    const firstName =
      profile.name?.givenName ||
      profile._json?.given_name ||
      profile._json?.nickname ||
      '';
    const lastName =
      profile.name?.familyName || profile._json?.family_name || '';

    // The SSOProfile MUST have an email field for your AuthService validation to pass
    return {
      id: providerId,
      email: email,
      firstName: firstName,
      lastName: lastName,
      provider: 'auth0',
      providerId: providerId,
    };
  }
}
