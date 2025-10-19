import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiBadRequestResponse,
  ApiParam,
  ApiOkResponse,
} from '@nestjs/swagger';

import { BadRequestDto } from 'src/shared/dto/bad-request.dto';
export function VerifyEmailDec() {
  return applyDecorators(
    ApiOperation({ summary: 'Verify user email' }),
    ApiParam({
      name: 'token',
      description: 'Email verification token',
      required: true,
    }),
    ApiOkResponse({
      description: 'Email verified successfully.',
      type: Object,
    }),
    ApiBadRequestResponse({
      type: BadRequestDto,
      description: 'Bad request. Invalid or expired token.',
    }),
  );
}
