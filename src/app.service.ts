
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AppService {
  constructor(private configService: ConfigService) {}

  getHealth() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      environment: this.configService.get('NODE_ENV', 'development'),
    };
  }

  getStatus() {
    return {
      application: this.configService.get('APP_NAME', 'NestJS Auth Boilerplate'),
      version: '1.0.0',
      environment: this.configService.get('NODE_ENV', 'development'),
      database: 'connected',
      timestamp: new Date().toISOString(),
    };
  }
}
