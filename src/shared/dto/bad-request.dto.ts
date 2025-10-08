import { ApiProperty } from '@nestjs/swagger';

export class BadRequestDto {
  @ApiProperty({ example: 400, description: 'HTTP status code' })
  statusCode: number;

  @ApiProperty({ example: 'Bad Request', description: 'Error message' })
  message: string;

  @ApiProperty({
    description: 'Validation errors (if any)',
  })
  errors: string[];
}
