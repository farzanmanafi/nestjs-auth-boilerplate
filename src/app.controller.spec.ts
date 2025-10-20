import { Test, TestingModule } from '@nestjs/testing';
import { AppController } from './app.controller';
import { AppService } from './app.service';

describe('AppController', () => {
  let appController: AppController;
  let appService: AppService;

  beforeEach(async () => {
    // Mock AppService
    const mockAppService = {
      getHealth: jest.fn(() => ({
        status: 'ok',
        environment: 'test',
        timestamp: '2025-10-20T00:00:00.000Z',
      })),
      getStatus: jest.fn(() => ({
        application: 'My Test App',
        version: '1.0.0',
        environment: 'test',
        database: 'connected',
        timestamp: '2025-10-20T00:00:00.000Z',
      })),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
      providers: [{ provide: AppService, useValue: mockAppService }],
    }).compile();

    appController = module.get<AppController>(AppController);
    appService = module.get<AppService>(AppService);
  });

  it('should be defined', () => {
    expect(appController).toBeDefined();
  });

  it('should return health info', () => {
    const result = appController.getHealth();

    expect(result).toEqual({
      status: 'ok',
      environment: 'test',
      timestamp: '2025-10-20T00:00:00.000Z',
    });

    expect(appService.getHealth).toHaveBeenCalled(); // Ensure the service was called
  });

  it('should return status info', () => {
    const result = appController.getStatus();

    expect(result).toEqual({
      application: 'My Test App',
      version: '1.0.0',
      environment: 'test',
      database: 'connected',
      timestamp: '2025-10-20T00:00:00.000Z',
    });

    expect(appService.getStatus).toHaveBeenCalled(); // Ensure the service was called
  });
});
