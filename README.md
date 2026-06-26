# api-server
Backend API service

## Configuration

This service uses environment variables for auth configuration:

- `JWT_SECRET_KEY` (required when creating/decoding JWTs)
- `JWT_ALGORITHM` (optional, default: `HS256`)
- `ACCESS_TOKEN_TTL_SECONDS` (optional, default: `3600`)
