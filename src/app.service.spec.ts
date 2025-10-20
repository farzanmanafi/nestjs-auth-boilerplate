import { Test, TestingModule } from '@nestjs/testing';
import { AppService } from './app.service';
import { ConfigService } from '@nestjs/config';

describe('AppService', () => {
  let appService: AppService;
  let configService: ConfigService;

  beforeEach(async () => {
    const mockConfigService = {
      get: jest.fn((key: string, defaultValue?: string) => {
        const config = {
          NODE_ENV: 'test',
          APP_NAME: 'My Test App',
        };
        return config[key] || defaultValue;
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AppService,
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    appService = module.get<AppService>(AppService);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(appService).toBeDefined();
  });

  it('should return health info', () => {
    const result = appService.getHealth();

    expect(result.status).toBe('ok');
    expect(result.environment).toBe('test');
    expect(result.timestamp).toBeDefined();
  });

  it('should return status info', () => {
    const result = appService.getStatus();

    expect(result.application).toBe('My Test App');
    expect(result.environment).toBe('test');
    expect(result.database).toBe('connected');
    expect(result.version).toBe('1.0.0');
    expect(result.timestamp).toBeDefined();
  });
});
