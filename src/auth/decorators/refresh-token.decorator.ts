import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiBody,
  ApiOkResponse,
  ApiUnauthorizedResponse,
  ApiBadRequestResponse,
} from '@nestjs/swagger';
import { RefreshTokenDto } from '../dto/refresh-token.dto';
import { TokenResponseDto } from '../dto/token-response.dto';
import { BadRequestDto } from 'src/shared/dto/bad-request.dto';
import { UnauthorizedExceptionDto } from '@/shared/dto/unauthorized-Exception.dto';

export function RefreshDec() {
  return applyDecorators(
    ApiOperation({ summary: 'Refresh access token using refresh token' }),
    ApiBody({
      description: 'Refresh token details',
      type: RefreshTokenDto,
    }),
    ApiOkResponse({
      description: 'Tokens refreshed successfully',
      type: TokenResponseDto,
    }),
    ApiUnauthorizedResponse({
      description: 'Unauthorized. Invalid or expired refresh token.',
      type: UnauthorizedExceptionDto,
    }),
    ApiBadRequestResponse({
      description: 'Bad request. Invalid body parameters.',
      type: BadRequestDto,
    }),
  );
}
