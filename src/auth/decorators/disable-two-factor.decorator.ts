import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiBody,
  ApiOkResponse,
  ApiUnauthorizedResponse,
  ApiBadRequestResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { DisableTwoFactorDto } from '../dto/disable-two-factor.dto';
import { UnauthorizedExceptionDto } from '@/shared/dto/unauthorized-Exception.dto';
import { BadRequestDto } from '@/shared/dto/bad-request.dto';

export function DisableTwoFactorDec() {
  return applyDecorators(
    ApiOperation({
      summary: 'Disable two-factor authentication',
      description:
        'Disable two-factor authentication for the current user. Requires a valid 6-digit code from the authenticator app to confirm the action.',
    }),
    ApiBearerAuth('JWT-auth'),
    ApiBody({
      description:
        '6-digit verification code from authenticator app to confirm disabling',
      type: DisableTwoFactorDto,
    }),
    ApiOkResponse({
      description: 'Two-factor authentication disabled successfully',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: 'Two-factor authentication disabled successfully',
          },
        },
      },
    }),
    ApiUnauthorizedResponse({
      description:
        'Unauthorized. Missing or invalid authentication token, or invalid two-factor code.',
      type: UnauthorizedExceptionDto,
    }),
    ApiBadRequestResponse({
      description:
        'Bad request. Two-factor authentication not enabled or invalid token format.',
      type: BadRequestDto,
    }),
  );
}
