import { applyDecorators } from '@nestjs/common';
import { ApiOperation, ApiOkResponse } from '@nestjs/swagger';

export function GoogleLoginDec() {
  return applyDecorators(
    ApiOperation({
      summary: 'Initiate Google OAuth login',
      description:
        'Redirects user to Google login page for authentication. After successful authentication, Google will redirect back to the callback URL.',
    }),
    ApiOkResponse({
      description: 'Redirects to Google authentication page',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: 'Redirecting to Google...',
          },
        },
      },
    }),
  );
}
