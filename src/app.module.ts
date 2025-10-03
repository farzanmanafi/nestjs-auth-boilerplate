import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';

import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { EmailModule } from './email/email.module';

// Configuration imports
import { databaseConfig } from './config/database.config';
import { jwtConfig } from './config/jwt.config';
import { emailConfig } from './config/email.config';

// Common utilities
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor';
import { AppController } from './app.controller';

@Module({
  imports: [
    // Configuration
    ConfigModule.forRoot({
      isGlobal: true,
      load: [databaseConfig, jwtConfig, emailConfig],
      envFilePath: ['.env.local', '.env'],
    }),

    // Database
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) =>
        configService.get('database'),
      inject: [ConfigService],
    }),

    // Feature modules
    AuthModule,
    UsersModule,
    EmailModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_FILTER, // Filter = catches errors globally (standard error response).
      useClass: HttpExceptionFilter,
    },
    {
      provide: APP_INTERCEPTOR, // Interceptor = wraps requests globally (logging, timing, or changing responses).
      useClass: LoggingInterceptor,
    },
  ],
})
export class AppModule {}
