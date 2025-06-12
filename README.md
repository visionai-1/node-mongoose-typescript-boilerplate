# Node TypeScript Boilerplate Mongoose

The main purpose of this repository is to show a good end-to-end project setup and workflow for writing a Mongoose Node.js Express code in TypeScript complete with middleware, models, routes, and types.

This example comes with a complete REST API to handle Authentication and CRUD features on Users and their corresponding Profile.

## Tech Stack

**Server:** Node, Express, TypeScript, ts-node
**Database:** MongoDB with Mongoose
**Authentication:** JWT with bcrypt
**Email:** Nodemailer
**Validation:** Express Validator

## MongoDB Setup

### 1. Create MongoDB Atlas Account
1. Go to [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
2. Create a free account and set up a cluster
3. Create a database user with read/write permissions
4. Whitelist your IP address (or use `0.0.0.0/0` for development)

### 2. Get Connection Details
1. In Atlas, click "Connect" on your cluster
2. Choose "Connect your application"
3. Copy the connection string
4. Note your username and password

## Run Locally

### 1. Clone the project
```bash
  git clone https://github.com/chiragmehta900/node-typescript-boilerplate-mongoose
  cd node-typescript-boilerplate-mongoose
```

### 2. Install dependencies
```bash
  npm install
```

### 3. Setup Environment Variables
```bash
# Copy the sample environment file
cp .env-sample .env

# Edit .env with your actual values
# Required variables:
# - MONGO_DB_USER: Your MongoDB Atlas username
# - MONGO_DB_PASSWORD: Your MongoDB Atlas password  
# - JWT_SECRETS: A secure random string (min 32 characters)
```

### 4. Build the TypeScript code
```bash
npm run build
```

### 5. Start the development server
```bash
# Terminal 1: Watch for TypeScript changes
npm run watch

# Terminal 2: Start the server with auto-reload
  npm run dev
```

The server will start on `http://localhost:5000`

## Health Checks

- **Basic ping**: `GET /ping` - Returns server status with database connection info
- **Detailed health**: `GET /health` - Returns comprehensive health status including database state

## Environment Variables

Create a `.env` file based on `.env-sample`:

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `NODE_ENV` | Environment mode | Yes | `local` or `production` |
| `MONGO_DB_USER` | MongoDB Atlas username | Yes | `myuser` |
| `MONGO_DB_PASSWORD` | MongoDB Atlas password | Yes | `mypassword123` |
| `MONGO_CLUSTER` | MongoDB cluster hostname | No* | `cluster0.abc123.mongodb.net` |
| `MONGO_DATABASE` | Database name | No* | `sharefi` |
| `JWT_SECRETS` | JWT signing secret | Yes | `super-secret-key-32-chars-min` |
| `SMTP_HOST` | Email server host | No | `smtp.gmail.com` |
| `SMTP_PORT` | Email server port | No | `587` |
| `SMTP_USERNAME` | Email username | No | `user@gmail.com` |
| `SMTP_PASSWORD` | Email password/app password | No | `app-password` |
| `SMTP_SENDER` | Default sender email | No | `noreply@yourapp.com` |

*Has default values

## Troubleshooting MongoDB Connection

### Common Issues:

1. **"URI contained empty userinfo section"**
   - Make sure `MONGO_DB_USER` and `MONGO_DB_PASSWORD` are set in `.env`
   - Check that the values are not empty or contain only spaces

2. **"Server selection timed out"**
   - Verify your IP is whitelisted in MongoDB Atlas
   - Check your internet connection
   - Try using `0.0.0.0/0` in Atlas IP whitelist for testing

3. **"Authentication failed"**
   - Verify username and password are correct
   - Make sure the user has proper database permissions
   - Try encoding special characters in credentials

4. **DNS resolution issues**
   - Check if `MONGO_CLUSTER` is correctly set
   - Try using full connection string instead of SRV

### Debug Mode:
Set `NODE_ENV=local` to enable MongoDB debug logging for troubleshooting.

## API Documentation

### Authentication Endpoints
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/forgot-password` - Request password reset
- `POST /api/v1/auth/verify-otp` - Verify OTP for password reset
- `POST /api/v1/auth/reset-password` - Reset password with OTP

### User Endpoints
- `POST /api/v1/user/sign-up` - User registration
- `POST /api/v1/user/verify-email` - Verify email with OTP
- `GET /api/v1/user/fetch/:userId` - Get user by ID
- `GET /api/v1/user/fetch` - Get all users (paginated)
- `PATCH /api/v1/user/update/:userId` - Update user profile

### Role Endpoints
- `GET /api/v1/role/list` - Get all roles

## Production Deployment

### Environment Setup
1. Set `NODE_ENV=production`
2. Use strong, unique values for `JWT_SECRETS`
3. Configure proper SMTP settings for email
4. Set up proper MongoDB Atlas security (IP whitelisting, strong passwords)

### Build and Start
```bash
npm run build
npm start
```

## Features

- ✅ **Type Safety**: Full TypeScript implementation with strict mode
- ✅ **Authentication**: JWT-based auth with email verification
- ✅ **Database**: MongoDB with Mongoose ODM and proper connection handling
- ✅ **Email**: Nodemailer integration for OTP and notifications
- ✅ **Validation**: Express Validator for input validation
- ✅ **Security**: bcrypt password hashing, input sanitization
- ✅ **Error Handling**: Centralized error handling with custom error types
- ✅ **Health Checks**: Built-in health monitoring endpoints
- ✅ **Production Ready**: Proper connection pooling, graceful shutdown, logging

## Project Structure

| Directory | Description |
|-----------|-------------|
| `src/config/` | Configuration files (database, environment) |
| `src/controllers/` | Request handlers and business logic |
| `src/interfaces/` | TypeScript type definitions |
| `src/library/` | Utility libraries (logging, etc.) |
| `src/middlewares/` | Express middlewares (auth, validation) |
| `src/models/` | Mongoose models and schemas |
| `src/routes/` | API route definitions |
| `src/services/` | External service integrations (email, etc.) |
| `src/templates/` | Email templates |
| `src/utils/` | Helper functions and utilities |
| `src/validators/` | Input validation schemas |
| `dist/` | Compiled JavaScript output |

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Commit your changes: `git commit -am 'Add feature'`
5. Push to the branch: `git push origin feature-name`
6. Create a Pull Request

## License

This project is licensed under the ISC License.

