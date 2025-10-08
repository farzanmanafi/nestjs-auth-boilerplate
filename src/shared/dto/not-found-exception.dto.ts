import { ApiProperty } from '@nestjs/swagger';

export class NotFoundExceptionDto {
  @ApiProperty({
    example: 'Not Found',
    description: 'The error message',
  })
  error: string;

  @ApiProperty({
    example: 404,
    description: 'The error status code',
  })
  statusCode: number;

  @ApiProperty({
    example: 'Not Found',
    description: 'The error message',
  })
  message: string;
}
