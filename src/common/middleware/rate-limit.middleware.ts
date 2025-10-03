
// ==============================================
// FILE: src/common/middleware/rate-limit.middleware.ts
// ==============================================
import { Injectable, NestMiddleware, HttpStatus } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { ConfigService } from '@nestjs/config';

interface RateLimitStore {
  [key: string]: {
    requests: number;
    resetTime: number;
  };
}

@Injectable()
export class RateLimitMiddleware implements NestMiddleware {
  private store: RateLimitStore = {};
  private readonly maxRequests: number;
  private readonly windowMs: number;

  constructor(private configService: ConfigService) {
    this.maxRequests = this.configService.get('RATE_LIMIT_MAX', 100);
    this.windowMs = this.configService.get('RATE_LIMIT_TTL', 60) * 1000; // Convert to ms
  }

  use(req: Request, res: Response, next: NextFunction): void {
    const key = this.generateKey(req);
    const now = Date.now();
    
    // Clean expired entries
    this.cleanExpiredEntries(now);

    // Get or create entry for this client
    let entry = this.store[key];
    if (!entry || now > entry.resetTime) {
      entry = {
        requests: 0,
        resetTime: now + this.windowMs,
      };
      this.store[key] = entry;
    }

    // Increment request count
    entry.requests++;

    // Set rate limit headers
    res.set({
      'X-RateLimit-Limit': this.maxRequests.toString(),
      'X-RateLimit-Remaining': Math.max(0, this.maxRequests - entry.requests).toString(),
      'X-RateLimit-Reset': Math.ceil(entry.resetTime / 1000).toString(),
    });

    // Check if limit exceeded
    if (entry.requests > this.maxRequests) {
      res.status(HttpStatus.TOO_MANY_REQUESTS).json({
        statusCode: HttpStatus.TOO_MANY_REQUESTS,
        message: 'Too many requests, please try again later',
        error: 'Too Many Requests',
        retryAfter: Math.ceil((entry.resetTime - now) / 1000),
      });
      return;
    }

    next();
  }

  private generateKey(req: Request): string {
    // Use IP address and user agent for rate limiting
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || '';
    return `${ip}:${Buffer.from(userAgent).toString('base64').substring(0, 10)}`;
  }

  private cleanExpiredEntries(now: number): void {
    Object.keys(this.store).forEach(key => {
      if (now > this.store[key].resetTime) {
        delete this.store[key];
      }
    });
  }
}
