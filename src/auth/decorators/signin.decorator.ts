import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiBody,
  ApiCreatedResponse,
  ApiBadRequestResponse,
  ApiConflictResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { BadRequestDto } from 'src/shared/dto/bad-request.dto';
import { SignInDto } from '../dto/signin.dto';
import { UnauthorizedExceptionDto } from '@/shared/dto/unauthorized-Exception.dto';
import { TokenResponseDto } from '../dto/token-response.dto';
export const SigninDec = (): MethodDecorator => {
  return applyDecorators(
    ApiOperation({
      summary: 'Sign in',
      description: 'Sign in and get an access token',
    }),
    ApiBody({
      description: 'User credentials',
      type: SignInDto,
    }),
    ApiCreatedResponse({
      description: 'Signed in successfully',
      type: TokenResponseDto,
    }),
    ApiBadRequestResponse({
      description: 'Invalid request',
      type: BadRequestDto,
    }),
    ApiUnauthorizedResponse({
      description: 'Invalid credentials',
      type: UnauthorizedExceptionDto,
    }),
  );
};
