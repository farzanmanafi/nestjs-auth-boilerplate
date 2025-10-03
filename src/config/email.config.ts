
import { registerAs } from '@nestjs/config';

export interface EmailConfig {
  smtp: {
    host: string;
    port: number;
    secure: boolean;
    auth: {
      user: string;
      pass: string;
    };
  };
  from: string;
  templates: {
    verification: string;
    passwordReset: string;
    welcome: string;
  };
}

export const emailConfig = registerAs('email', (): EmailConfig => ({
  smtp: {
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT, 10) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER || '',
      pass: process.env.SMTP_PASS || '',
    },
  },
  from: process.env.EMAIL_FROM || 'noreply@yourapp.com',
  templates: {
    verification: 'verification',
    passwordReset: 'password-reset',
    welcome: 'welcome',
  },
}));
