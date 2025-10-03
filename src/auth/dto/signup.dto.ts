import {
  IsEmail,
  IsString,
  MinLength,
  MaxLength,
  IsOptional,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SignUpDto {
  @ApiProperty({ example: 'Maris.manaf@example.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'SecurePassword123!' })
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  password: string;

  @ApiProperty({ example: 'Maris' })
  @IsString()
  @MaxLength(50)
  firstName: string;

  @ApiProperty({ example: 'manaf' })
  @IsString()
  @MaxLength(50)
  lastName: string;
}
