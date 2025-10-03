import { registerAs } from '@nestjs/config';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { DataSource, DataSourceOptions } from 'typeorm';
import { User } from '../users/entities/user.entity';
import { RefreshToken } from '../auth/entities/refresh-token.entity';
import { PasswordReset } from '../auth/entities/password-reset.entity';
import { TwoFactorAuth } from '../auth/entities/two-factor-auth.entity';

export const databaseConfig = registerAs('database', (): TypeOrmModuleOptions => ({
  type: 'postgres',
  host: process.env.DATABASE_HOST || 'localhost',
  port: parseInt(process.env.DATABASE_PORT, 10) || 5432,
  username: process.env.DATABASE_USERNAME || 'postgres',
  password: process.env.DATABASE_PASSWORD || 'password',
  database: process.env.DATABASE_NAME || 'nestjs_auth',
  entities: [User, RefreshToken, PasswordReset, TwoFactorAuth],
  synchronize: process.env.NODE_ENV !== 'production' && process.env.DATABASE_SYNCHRONIZE === 'true',
  logging: process.env.NODE_ENV === 'development',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  migrations: ['dist/migrations/*.js'],
  migrationsTableName: 'migrations',
}));

// Export for TypeORM CLI
export const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  host: process.env.DATABASE_HOST || 'localhost',
  port: parseInt(process.env.DATABASE_PORT, 10) || 5432,
  username: process.env.DATABASE_USERNAME || 'postgres',
  password: process.env.DATABASE_PASSWORD || 'password',
  database: process.env.DATABASE_NAME || 'nestjs_auth',
  entities: ['src/**/*.entity.ts'],
  synchronize: false,
  migrations: ['src/migrations/*.ts'],
  migrationsTableName: 'migrations',
};

const dataSource = new DataSource(dataSourceOptions);
export default dataSource;