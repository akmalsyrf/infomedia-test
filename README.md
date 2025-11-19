# Boilerplate Go API

A Go REST API boilerplate with authentication, JWT tokens, and OpenAPI specification. Built with Gin, GORM, and modern Go best practices.

## Features

- 🔐 **Authentication System**
  - User registration and login
  - JWT access and refresh tokens
  - Refresh token rotation
  - Password change functionality
  - Protected routes with middleware

- 📚 **OpenAPI Specification**
  - Complete API documentation
  - Auto-generated server code
  - Postman collection generation

- 🗄️ **Database Support**
  - PostgreSQL
  - SQLite (development/testing)
  - GORM ORM with migrations

- 🏗️ **Architecture**
  - Clean architecture with layers (handlers, services, repositories)
  - Dependency injection with Google Wire
  - Structured logging with zerolog
  - Configuration management with Viper

- 🧪 **Testing**
  - Unit tests for handlers, services, and repositories
  - Test coverage reporting

- 🐳 **Docker Support**
  - Multi-stage Dockerfile
  - Docker Compose for local development
  - PostgreSQL service included

## Tech Stack

- **Go 1.22.5**
- **Gin** - HTTP web framework
- **GORM** - ORM library
- **PostgreSQL/SQLite** - Database
- **JWT** - Token-based authentication
- **Wire** - Dependency injection
- **Viper** - Configuration management
- **Zerolog** - Structured logging
- **OpenAPI** - API specification

## Prerequisites

- Go 1.22.5 or higher
- PostgreSQL (optional)
- Docker and Docker Compose (optional)
- Make (optional, for convenience commands)

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd boilerplate-go
   ```

2. **Install dependencies**
   ```bash
   go mod download
   ```

3. **Generate code**
   ```bash
   make generate
   ```
   
   This will:
   - Generate API code from OpenAPI specification
   - Generate Wire dependency injection code

## Configuration

The application can be configured using:
- Environment variables
- `config.yaml` file
- `.env` file

Copy the example config file:
```bash
cp config.yaml.example config.yaml
```

Edit `config.yaml` with your settings:

```yaml
# Server Configuration
SERVER_PORT: "8080"

# Database Configuration
DATABASE_TYPE: "postgres"  # or "sqlite"
DATABASE_DSN: "postgres://user:password@localhost/dbname?sslmode=disable"

# JWT Configuration
JWT_SECRET: "your-secret-key-here"
JWT_ACCESS_TOKEN_EXPIRY: 15  # minutes
JWT_REFRESH_TOKEN_EXPIRY: 7   # days
JWT_REFRESH_TOKEN_ROTATION: true

# Password Configuration
PASSWORD_MIN_LENGTH: 8

# Email Configuration (Optional)
EMAIL_ENABLED: false
EMAIL_SMTP_HOST: "smtp.gmail.com"
EMAIL_SMTP_PORT: 587
EMAIL_SMTP_USERNAME: "your-email@gmail.com"
EMAIL_SMTP_PASSWORD: "your-app-password"
EMAIL_FROM_ADDRESS: "your-email@gmail.com"
EMAIL_FROM_NAME: "Boilerplate API"
```

### Environment Variables

You can also set configuration via environment variables:
```bash
export SERVER_PORT=8080
export DATABASE_TYPE=postgres
export DATABASE_DSN="postgres://user:password@localhost/dbname?sslmode=disable"
export JWT_SECRET="your-secret-key"
```

## Running the Application

### Local Development

1. **Using Make (recommended)**
   ```bash
   make run
   ```

2. **Direct Go command**
   ```bash
   go run ./cmd/server
   ```

3. **Build and run**
   ```bash
   go build -o server ./cmd/server
   ./server
   ```

The server will start on `http://localhost:8080` (or the port specified in your config).

### Using Docker Compose

1. **Start services**
   ```bash
   docker-compose up -d
   ```

2. **View logs**
   ```bash
   docker-compose logs -f app
   ```

3. **Stop services**
   ```bash
   docker-compose down
   ```

### Docker Build

```bash
docker build -t boilerplate-api .
docker run -p 8080:8080 boilerplate-api
```

## API Endpoints

### Authentication

- `POST /api/v1/register` - Register a new user
- `POST /api/v1/login` - Login and get tokens
- `POST /api/v1/refresh` - Refresh access token
- `POST /api/v1/change-password` - Change password (requires auth)
- `GET /api/v1/me` - Get current user info (requires auth)

### Health Check

- `GET /health` - Health check endpoint

## API Documentation

### View OpenAPI Documentation

```bash
make show_docs
```

This will attempt to start a Redocly preview server. Alternatively, you can:

1. **Using Redocly CLI**
   ```bash
   npm install -g @redocly/cli
   redocly preview-docs api/openapi.yml
   ```

2. **Using Swagger UI**
   ```bash
   npm install -g swagger-ui-serve
   swagger-ui-serve api/openapi.yml
   ```

3. **Online Viewer**
   - Visit https://editor.swagger.io/
   - Upload `api/openapi.yml`

### Generate Postman Collection

```bash
make postman
```

This generates `postman-collection.json` from the OpenAPI specification.

## Testing

### Run all tests
```bash
make test
```

### Run tests with coverage
```bash
make test-coverage
```

This generates:
- `coverage.out` - Coverage data file
- `coverage.html` - HTML coverage report

## Project Structure

```
boilerplate-go/
├── api/                    # OpenAPI specification
│   ├── components/         # Schema definitions
│   └── paths/              # API endpoint definitions
├── bin/                    # Build scripts
├── cmd/
│   └── server/             # Application entry point
├── generated/
│   └── api/                # Auto-generated API code
├── internal/
│   ├── composers/          # Wire dependency injection
│   ├── config/             # Configuration management
│   ├── db/                 # Database initialization
│   ├── handlers/           # HTTP handlers
│   ├── http/
│   │   └── middleware/     # HTTP middleware
│   ├── models/             # Data models
│   ├── repositories/       # Data access layer
│   └── services/           # Business logic layer
├── config.yaml.example     # Example configuration
├── docker-compose.yml      # Docker Compose configuration
├── Dockerfile              # Docker build file
├── Makefile                # Make commands
└── go.mod                  # Go dependencies
```

## Development Workflow

### Code Generation

After modifying the OpenAPI specification:

```bash
make generate
```

This regenerates:
- API types and server code
- Wire dependency injection code

### Clean Build Artifacts

```bash
make clean
```

Removes:
- Generated API code
- Test coverage files
- SQLite database files

## Make Commands

| Command | Description |
|---------|-------------|
| `make run` | Run the application |
| `make test` | Run all tests |
| `make test-coverage` | Run tests with coverage report |
| `make generate` | Generate API and Wire code |
| `make generate_api` | Generate API code only |
| `make wire` | Generate Wire code only |
| `make clean` | Clean build artifacts |
| `make show_docs` | Show OpenAPI documentation |
| `make postman` | Generate Postman collection |

## Security Considerations

- **JWT Secret**: Always use a strong, random secret key in production
- **Password Requirements**: Configure minimum password length
- **HTTPS**: Use HTTPS in production environments
- **Database**: Use secure database connections with SSL in production
- **Environment Variables**: Never commit secrets to version control

## Support

For issues and questions, please open an issue on the repository.

