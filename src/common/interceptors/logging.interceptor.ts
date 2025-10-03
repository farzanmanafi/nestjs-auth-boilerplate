
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { Request, Response } from 'express';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LoggingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();
    const { method, url, headers, body } = request;
    const userAgent = headers['user-agent'] || '';
    const ip = request.ip || request.connection.remoteAddress;

    const now = Date.now();

    // Log request
    this.logger.log(`Incoming Request: ${method} ${url} - ${userAgent} - ${ip}`);

    // Don't log sensitive data
    const sanitizedBody = this.sanitizeBody(body);
    if (Object.keys(sanitizedBody).length > 0) {
      this.logger.debug(`Request Body: ${JSON.stringify(sanitizedBody)}`);
    }

    return next.handle().pipe(
      tap({
        next: (data) => {
          const responseTime = Date.now() - now;
          this.logger.log(
            `Outgoing Response: ${method} ${url} ${response.statusCode} - ${responseTime}ms`,
          );
          
          if (process.env.NODE_ENV === 'development' && data) {
            this.logger.debug(`Response Data: ${JSON.stringify(this.sanitizeResponse(data))}`);
          }
        },
        error: (error) => {
          const responseTime = Date.now() - now;
          this.logger.error(
            `Error Response: ${method} ${url} ${error.status || 500} - ${responseTime}ms`,
            error.message,
          );
        },
      }),
    );
  }

  private sanitizeBody(body: any): any {
    if (!body || typeof body !== 'object') {
      return {};
    }

    const sensitiveFields = ['password', 'token', 'secret', 'authorization'];
    const sanitized = { ...body };

    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    });

    return sanitized;
  }

  private sanitizeResponse(data: any): any {
    if (!data || typeof data !== 'object') {
      return data;
    }

    const sensitiveFields = ['password', 'secret', 'token'];
    const sanitized = Array.isArray(data) ? [...data] : { ...data };

    const sanitizeObject = (obj: any) => {
      if (obj && typeof obj === 'object') {
        sensitiveFields.forEach(field => {
          if (obj[field]) {
            obj[field] = '[REDACTED]';
          }
        });

        // Recursively sanitize nested objects
        Object.keys(obj).forEach(key => {
          if (typeof obj[key] === 'object' && obj[key] !== null) {
            sanitizeObject(obj[key]);
          }
        });
      }
    };

    sanitizeObject(sanitized);
    return sanitized;
  }
}
