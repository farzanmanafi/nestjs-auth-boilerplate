import { ApiProperty } from '@nestjs/swagger';
import { IsString, MinLength, MaxLength } from 'class-validator';

export class DisableTwoFactorDto {
  @ApiProperty({
    example: '123456',
    description:
      '6-digit verification code from authenticator app to confirm disabling 2FA',
  })
  @IsString()
  @MinLength(6)
  @MaxLength(6)
  token: string;
}
