import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiOkResponse,
  ApiUnauthorizedResponse,
  ApiBearerAuth,
  ApiNotFoundResponse,
} from '@nestjs/swagger';
import { UnauthorizedExceptionDto } from '@/shared/dto/unauthorized-Exception.dto';
import { NotFoundExceptionDto } from '@/shared/dto/not-found-exception.dto';

export function SetupTwoFactorDec() {
  return applyDecorators(
    ApiOperation({
      summary: 'Setup two-factor authentication',
      description:
        'Generate a QR code and secret for setting up two-factor authentication. User must scan the QR code with an authenticator app.',
    }),
    ApiBearerAuth('JWT-auth'),
    ApiOkResponse({
      description: 'Two-factor authentication setup initiated successfully',
      schema: {
        type: 'object',
        properties: {
          qrCode: {
            type: 'string',
            description: 'Base64 encoded QR code image for authenticator app',
            example: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...',
          },
          secret: {
            type: 'string',
            description: 'Base32 encoded secret key for manual entry',
            example: 'JBSWY3DPEHPK3PXP',
          },
        },
      },
    }),
    ApiUnauthorizedResponse({
      description: 'Unauthorized. Missing or invalid authentication token.',
      type: UnauthorizedExceptionDto,
    }),
    ApiNotFoundResponse({
      description: 'User not found',
      type: NotFoundExceptionDto,
    }),
  );
}
