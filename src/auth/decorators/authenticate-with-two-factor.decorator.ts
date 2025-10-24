import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiBody,
  ApiOkResponse,
  ApiUnauthorizedResponse,
  ApiBadRequestResponse,
} from '@nestjs/swagger';
import { UnauthorizedExceptionDto } from '@/shared/dto/unauthorized-Exception.dto';
import { BadRequestDto } from '@/shared/dto/bad-request.dto';
import { AuthenticateWithTwoFactorDto } from '../dto/authenticate-with-two-factor.dto';

export function AuthenticateWithTwoFactorDec() {
  return applyDecorators(
    ApiOperation({
      summary: 'Authenticate with two-factor code',
      description:
        'Complete sign-in process by providing email, password, and 6-digit two-factor authentication code. Use this endpoint when signIn returns twoFactorRequired: true.',
    }),
    ApiBody({
      description: 'User credentials with two-factor authentication code',
      type: AuthenticateWithTwoFactorDto,
    }),
    ApiOkResponse({
      description: 'Authentication successful with valid two-factor code',
      schema: {
        type: 'object',
        properties: {
          user: {
            type: 'object',
            properties: {
              id: {
                type: 'string',
                example: 'bc57c084-9e8f-4bd9-b974-6cb4513ebbc5',
              },
              email: { type: 'string', example: 'maris.manaf@example.com' },
              firstName: { type: 'string', example: 'Maris' },
              lastName: { type: 'string', example: 'Manaf' },
              emailVerified: { type: 'boolean', example: true },
              isActive: { type: 'boolean', example: true },
              createdAt: { type: 'string', format: 'date-time' },
              updatedAt: { type: 'string', format: 'date-time' },
            },
          },
          tokens: {
            type: 'object',
            properties: {
              accessToken: {
                type: 'string',
                example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
              },
              refreshToken: {
                type: 'string',
                example: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
              },
            },
          },
        },
      },
    }),
    ApiUnauthorizedResponse({
      description: 'Invalid credentials or invalid two-factor token',
      type: UnauthorizedExceptionDto,
    }),
    ApiBadRequestResponse({
      description:
        'Bad request. Two-factor authentication not enabled for this user.',
      type: BadRequestDto,
    }),
  );
}
