# Two-Factor Authentication (2FA) Implementation in Go

This repository contains a simple implementation of Two-Factor Authentication (2FA) in Go using the Gin web framework and Redis for OTP storage.

## Overview

The provided Go code demonstrates a basic 2FA flow, including user registration, login, OTP generation, and token validation. It uses a Redis database to store OTPs temporarily.

## Features

1. User Registration (`SignUpUser`):
   - Users can sign up by providing their email, username, and password.
   - Passwords are hashed using bcrypt for security.

2. User Login (`Login`):
   - Users can log in using their email and password.
   - One-Time Passcodes (OTPs) are generated and sent to the user's email for additional verification.

3. OTP Generation (`generateTOTP`):
   - OTPs are generated using the TOTP algorithm, which is a time-based OTP.
   - The TOTP secret is stored securely on the server.

4. OTP Validation (`ValidateOTP`):
   - Users submit the OTP received via email for validation.
   - The server validates the OTP, and upon success, issues a JSON Web Token (JWT) for authentication.

5. JWT Token Refresh (`RefreshToken`):
   - Provides a mechanism to refresh the JWT token, extending the user's session.

## Dependencies

- [Gin](https://github.com/gin-gonic/gin): HTTP web framework.
- [Golang JWT](https://github.com/golang-jwt/jwt): JSON Web Token implementation.
- [GoMail](https://github.com/go-gomail/gomail): Email sending library.
- [GoValidator](https://github.com/asaskevich/govalidator): Validator package for Go.
- [Badoux Checkmail](https://github.com/badoux/checkmail): Email validation package.
- [Go-Redis](https://github.com/go-redis/redis): Redis client for Go.
- [OTP TOTP](https://github.com/pquerna/otp): One-Time Password (OTP) library.

## Environment Variables

- `Sender_email`: Email address used to send OTPs.
- `Sender_pass`: Password for the sender email account.
- `smtpServer`: SMTP server address.
- `smtpPort`: SMTP server port.
- `DB_URL`: PostGres Database connection URL
- `REDIS_URL`: Redis cache connection URL

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/navaneesh/2FA.git
