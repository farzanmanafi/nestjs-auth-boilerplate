import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToOne,
  JoinColumn,
} from 'typeorm';
import { User } from '../../users/entities/user.entity';

@Entity('two_factor_auth')
export class TwoFactorAuth {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  userId: string;

  @Column()
  secret: string;

  @Column({ default: false })
  isEnabled: boolean;

  @OneToOne(() => User, (user) => user.twoFactorAuth, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;
}
