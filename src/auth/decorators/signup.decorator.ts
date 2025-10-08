import { UserResponseDto } from '@/users/dto/user-response.dto';
import { SignUpDto } from '../dto/signup.dto';
import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiBody,
  ApiCreatedResponse,
  ApiBadRequestResponse,
  ApiConflictResponse,
} from '@nestjs/swagger';
import { BadRequestDto } from 'src/shared/dto/bad-request.dto';

export function SignUpDec() {
  return applyDecorators(
    ApiOperation({ summary: 'Sign up a new user' }),
    ApiBody({
      description: 'Details of the user to be signed up',
      type: SignUpDto,
    }),
    ApiCreatedResponse({
      description: 'User signed up successfully.',
      type: UserResponseDto,
    }),
    ApiBadRequestResponse({
      description: 'Bad request. Invalid body parameters.',
      type: BadRequestDto,
    }),
    ApiConflictResponse({
      description: 'Conflict. User with this email already exists.',
    }),
  );
}
