import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiBody,
  ApiOkResponse,
  ApiUnauthorizedResponse,
  ApiBadRequestResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { VerifyTwoFactorDto } from '../dto/verify-two-factor.dto';
import { UnauthorizedExceptionDto } from '@/shared/dto/unauthorized-Exception.dto';
import { BadRequestDto } from '@/shared/dto/bad-request.dto';

export function VerifyTwoFactorDec() {
  return applyDecorators(
    ApiOperation({
      summary: 'Verify two-factor authentication setup',
      description:
        'Verify the 6-digit code from authenticator app to complete two-factor authentication setup. This must be called after setupTwoFactor.',
    }),
    ApiBearerAuth('JWT-auth'),
    ApiBody({
      description: '6-digit verification code from authenticator app',
      type: VerifyTwoFactorDto,
    }),
    ApiOkResponse({
      description: 'Two-factor authentication enabled successfully',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: 'Two-factor authentication enabled successfully',
          },
        },
      },
    }),
    ApiUnauthorizedResponse({
      description: 'Unauthorized. Missing or invalid authentication token, or invalid two-factor token.',
      type: UnauthorizedExceptionDto,
    }),
    ApiBadRequestResponse({
      description: 'Bad request. Two-factor authentication not set up or invalid token format.',
      type: BadRequestDto,
    }),
  );
}