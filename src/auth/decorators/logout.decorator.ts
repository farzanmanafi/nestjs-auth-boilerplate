import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiOkResponse,
  ApiUnauthorizedResponse,
  ApiBadRequestResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { BadRequestDto } from 'src/shared/dto/bad-request.dto';

export function LogoutDec() {
  return applyDecorators(
    ApiOperation({ summary: 'Log out the currently authenticated user' }),
    ApiBearerAuth('JWT-auth'),
    ApiOkResponse({
      description: 'User logged out successfully.',
      schema: {
        example: {
          status: 'success',
          message: 'You have been logged out successfully.',
        },
      },
    }),
    ApiBadRequestResponse({
      description: 'Bad request. Something went wrong while logging out.',
      type: BadRequestDto,
    }),
    ApiUnauthorizedResponse({
      description: 'Unauthorized. Missing or invalid authentication token.',
    }),
  );
}
