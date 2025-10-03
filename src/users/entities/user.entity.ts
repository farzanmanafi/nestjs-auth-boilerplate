import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  OneToOne,
} from 'typeorm';
import { RefreshToken } from '../../auth/entities/refresh-token.entity';
import { TwoFactorAuth } from '../../auth/entities/two-factor-auth.entity';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column({ nullable: true })
  password: string;

  @Column()
  firstName: string;

  @Column()
  lastName: string;

  @Column({ default: false })
  emailVerified: boolean;

  @Column({ nullable: true })
  emailVerificationToken: string;

  @Column({ nullable: true })
  ssoProvider: string;

  @Column({ nullable: true })
  ssoId: string;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
  refreshTokens: RefreshToken[];

  @OneToOne(() => TwoFactorAuth, (twoFactor) => twoFactor.user)
  twoFactorAuth: TwoFactorAuth;
}