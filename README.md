# auth-api

TypeScript + Express authentication API with PostgreSQL, Argon2 password hashing, JWT access tokens, and refresh-session cookies.

## Setup

1. Copy `.env.example` to `.env` and set real secrets.
2. Create the database tables from `migrations/001_init.sql`.
3. Install dependencies with `npm install`.
4. Start the server with `npm run dev`.

## Scripts

- `npm run dev` starts the API in watch mode.
- `npm run build` compiles the project into `dist`.
- `npm start` runs the compiled server.

## Endpoints

- `GET /health`
- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /auth/me`

## Notes

- Authentication is cookie-based with HTTP-only access and refresh tokens.
- The database stores users and server-side sessions so logout and refresh token rotation are enforceable.