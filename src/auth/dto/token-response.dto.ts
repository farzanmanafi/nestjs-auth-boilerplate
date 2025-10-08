import { ApiProperty } from '@nestjs/swagger';
import { IsNumber, IsString } from 'class-validator';

export class TokenResponseDto {
  /**
   * The access token returned after a successful authentication.
   * Example: access-token-uuid
   */
  @ApiProperty({
    description: 'Access token for authentication ',
    // example: 'access-token-uuid'
  })
  @IsString()
  accessToken: string;

  /**
   * The refresh token returned after a successful authentication.
   * Example: refresh-token-uuid
   */
  @ApiProperty({
    description: 'Refresh token to get a new access token ',
    example: 'refresh-token-uuid',
  })
  @IsString()
  refreshToken: string;

  /**
   * The expiration time of the access token in seconds.
   * Example: 3600
   */
  @ApiProperty({
    description: 'When the access token expires (in seconds)',
    example: 3600,
  })
  @IsNumber()
  expiresIn: number;
}
