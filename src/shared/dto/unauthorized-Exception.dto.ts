import { ApiProperty } from '@nestjs/swagger';

export class UnauthorizedExceptionDto {
  @ApiProperty({ example: 401, description: 'HTTP status code' })
  statusCode: number;

  @ApiProperty({ example: 'Unauthorized', description: 'Error message' })
  message: string;

  @ApiProperty({
    example: 'You are not authorized to access this resource',
    description: 'Detailed reason for the error',
  })
  error: string;
}
