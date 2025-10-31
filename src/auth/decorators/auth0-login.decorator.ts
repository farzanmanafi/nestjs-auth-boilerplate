import { applyDecorators } from '@nestjs/common';
import { ApiOperation, ApiOkResponse, ApiTags } from '@nestjs/swagger';

export function Auth0LoginDec() {
  return applyDecorators(
    ApiOperation({
      summary: 'Initiate Auth0 login',
      description:
        'Redirects user to Auth0 login page for authentication. After successful authentication, Auth0 will redirect back to the callback URL.',
    }),
    ApiOkResponse({
      description: 'Redirects to Auth0 authentication page',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: 'Redirecting to Auth0...',
          },
        },
      },
    }),
  );
}
