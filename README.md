# 🔐 NestJS Authentication Boilerplate

A comprehensive, production-ready authentication system built with NestJS, featuring JWT tokens, two-factor authentication, SSO integration, and more.

## ✨ Features

- 🔑 **Complete Authentication Flow** - Signup, signin, logout with JWT
- 🔄 **Token Management** - Access tokens with refresh token rotation
- 📧 **Email Verification** - Secure email verification flow
- 🔐 **Password Management** - Forgot/reset password functionality
- 🛡️ **Two-Factor Authentication** - TOTP with QR code setup
- 🌐 **SSO Integration** - Auth0 and Google OAuth support
- 👥 **Session Management** - Multiple session handling and revocation
- 🔒 **Security Best Practices** - Password hashing, rate limiting, validation
- 📱 **Mobile Ready** - JWT-based stateless authentication
- 📚 **API Documentation** - Swagger/OpenAPI integration
- 🧪 **Testing Ready** - Comprehensive test structure
- 🚀 **Production Ready** - Docker support and environment configs

## 🛠️ Tech Stack

- **Framework**: NestJS
- **Database**: PostgreSQL with TypeORM
- **Authentication**: JWT, Passport.js
- **Validation**: class-validator
- **Documentation**: Swagger/OpenAPI
- **Email**: Nodemailer
- **2FA**: Speakeasy
- **Password Hashing**: bcrypt
- **Testing**: Jest

## 🚀 Quick Start

### Prerequisites

- Node.js (v18 or higher)
- PostgreSQL
- npm or yarn

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/nestjs-auth-boilerplate.git
   cd nestjs-auth-boilerplate