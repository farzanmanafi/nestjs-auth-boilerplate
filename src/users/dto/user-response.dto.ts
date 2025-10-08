import { UserPermissions } from '@/common/types/user.types';
import { ApiProperty } from '@nestjs/swagger';

export class UserResponseDto {
  @ApiProperty({ example: 'maris.manaf@example.com' })
  readonly email: string;

  @ApiProperty({ example: 'Maris' })
  readonly firstName: string;

  @ApiProperty({ example: 'manaf' })
  readonly lastName: string;

  @ApiProperty({ example: true })
  readonly isActive: boolean;

  @ApiProperty({ example: ['user:read', 'user:write'] })
  readonly roles: string[];

  @ApiProperty({ example: { canRead: true, canWrite: true } })
  readonly permissions: UserPermissions;

  constructor(partial: Partial<UserResponseDto>) {
    Object.assign(this, partial);
  }
}
