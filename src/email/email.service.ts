
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { readFileSync } from 'fs';
import { join } from 'path';
import * as handlebars from 'handlebars';
import { EmailConfig } from '../config/email.config';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;
  private emailConfig: EmailConfig;

  constructor(private configService: ConfigService) {
    this.emailConfig = this.configService.get<EmailConfig>('email');
this.transporter = nodemailer.createTransport({    
    host: this.emailConfig.smtp.host,
      port: this.emailConfig.smtp.port,
      secure: this.emailConfig.smtp.secure,
      auth: {
        user: this.emailConfig.smtp.auth.user,
        pass: this.emailConfig.smtp.auth.pass,
      },
    });
  }

  async sendVerificationEmail(email: string, token: string): Promise<void> {
    try {
      const verificationUrl = `${this.configService.get('BACKEND_URL')}/auth/verify-email?token=${token}`;
      
      const template = this.loadTemplate(this.emailConfig.templates.verification);
      const html = template({
        verificationUrl,
        appName: this.configService.get('APP_NAME'),
      });

      await this.transporter.sendMail({
        from: this.emailConfig.from,
        to: email,
        subject: 'Verify Your Email Address',
        html,
      });

      this.logger.log(`Verification email sent to ${email}`);
    } catch (error) {
      this.logger.error('Failed to send verification email', error);
      throw error;
    }
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    try {
      const resetUrl = `${this.configService.get('FRONTEND_URL')}/auth/reset-password?token=${token}`;
      
      const template = this.loadTemplate(this.emailConfig.templates.passwordReset);
      const html = template({
        resetUrl,
        appName: this.configService.get('APP_NAME'),
      });

      await this.transporter.sendMail({
        from: this.emailConfig.from,
        to: email,
        subject: 'Reset Your Password',
        html,
      });

      this.logger.log(`Password reset email sent to ${email}`);
    } catch (error) {
      this.logger.error('Failed to send password reset email', error);
      throw error;
    }
  }

  async sendWelcomeEmail(email: string, firstName: string): Promise<void> {
    try {
      const template = this.loadTemplate(this.emailConfig.templates.welcome);
      const html = template({
        firstName,
        appName: this.configService.get('APP_NAME'),
        loginUrl: `${this.configService.get('FRONTEND_URL')}/auth/signin`,
      });

      await this.transporter.sendMail({
        from: this.emailConfig.from,
        to: email,
        subject: `Welcome to ${this.configService.get('APP_NAME')}!`,
        html,
      });

      this.logger.log(`Welcome email sent to ${email}`);
    } catch (error) {
      this.logger.error('Failed to send welcome email', error);
      throw error;
    }
  }

  private loadTemplate(templateName: string): handlebars.TemplateDelegate {
    try {
      const templatePath = join(process.cwd(), 'src', 'email', 'templates', `${templateName}.hbs`);
      const templateSource = readFileSync(templatePath, 'utf8');
      return handlebars.compile(templateSource);
    } catch (error) {
      this.logger.warn(`Template ${templateName} not found, using fallback`);
      return this.getFallbackTemplate(templateName);
    }
  }

  private getFallbackTemplate(templateName: string): handlebars.TemplateDelegate {
    const templates = {
      verification: `
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><title>Verify Your Email</title></head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2>Verify Your Email</h2>
            <p>Click the link below to verify your email address:</p>
            <p><a href="{{verificationUrl}}" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email</a></p>
            <p>If the button doesn't work, copy and paste this link: {{verificationUrl}}</p>
          </div>
        </body>
        </html>
      `,
      'password-reset': `
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><title>Reset Your Password</title></head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2>Reset Your Password</h2>
            <p>Click the link below to reset your password:</p>
            <p><a href="{{resetUrl}}" style="background: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request this, please ignore this email.</p>
          </div>
        </body>
        </html>
      `,
      welcome: `
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><title>Welcome!</title></head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2>Welcome to {{appName}}!</h2>
            <p>Hello {{firstName}},</p>
            <p>Welcome to our platform!</p>
            <p><a href="{{loginUrl}}" style="background: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Login Now</a></p>
          </div>
        </body>
        </html>
      `,
    };

    return handlebars.compile(templates[templateName] || '<p>{{message}}</p>');
  }
}