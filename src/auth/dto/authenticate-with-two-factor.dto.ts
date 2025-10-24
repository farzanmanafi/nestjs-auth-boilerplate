import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MinLength, MaxLength } from 'class-validator';

export class AuthenticateWithTwoFactorDto {
  @ApiProperty({ example: 'maris.manaf@example.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'SecurePassword123!' })
  @IsString()
  password: string;

  @ApiProperty({
    example: '123456',
    description: '6-digit code from authenticator app',
  })
  @IsString()
  @MinLength(6)
  @MaxLength(6)
  token: string;
}
