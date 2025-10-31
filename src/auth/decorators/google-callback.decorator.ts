import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiOkResponse,
  ApiUnauthorizedResponse,
  ApiQuery,
} from '@nestjs/swagger';
import { UnauthorizedExceptionDto } from '@/shared/dto/unauthorized-Exception.dto';

export function GoogleCallbackDec() {
  return applyDecorators(
    ApiOperation({
      summary: 'Google OAuth callback',
      description:
        'Handles the callback from Google after successful authentication. Google redirects here with authentication codes. This endpoint exchanges the code for user information and creates/updates the user account.',
    }),
    ApiQuery({
      name: 'code',
      required: false,
      description: 'Authorization code from Google',
      example: 'GOOGLE_AUTHORIZATION_CODE',
    }),
    ApiQuery({
      name: 'state',
      required: false,
      description: 'State parameter for CSRF protection',
      example: 'STATE_TOKEN',
    }),
    ApiOkResponse({
      description: 'Redirects to frontend with access token',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: 'Redirecting to frontend with authentication token...',
          },
          redirectUrl: {
            type: 'string',
            example:
              'http://localhost:3000/auth/success?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          },
        },
      },
    }),
    ApiUnauthorizedResponse({
      description: 'Authentication failed or invalid callback',
      type: UnauthorizedExceptionDto,
    }),
  );
}
