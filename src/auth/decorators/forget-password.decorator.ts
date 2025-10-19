import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiBody,
  ApiOkResponse,
  ApiBadRequestResponse,
} from '@nestjs/swagger';
import { BadRequestDto } from 'src/shared/dto/bad-request.dto';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';

export function ForgetPasswordDec() {
  return applyDecorators(
    ApiOperation({
      summary: 'Request password reset',
      description: 'Request password reset link to be sent to the user',
    }),
    ApiBody({
      description: 'Email address to send password reset link',
      type: ForgotPasswordDto,
    }),
    ApiOkResponse({
      description: 'Password reset link sent successfully',
    }),
    ApiBadRequestResponse({
      description: 'Bad request. Invalid email format.',
      type: BadRequestDto,
    }),
  );
}
