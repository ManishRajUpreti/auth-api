import argon2 from "argon2";
import crypto from "node:crypto";

import { env } from "../config/env";
import { query } from "../db";
import type { LoginInput, RegisterInput, User } from "../types/auth";
import { AppError } from "../utils/errors";
import { verifyRefreshToken } from "../utils/jwt";
import { getTokenExpiryFromDuration, hashToken, verifyTokenHash } from "../utils/tokens";
import { signAccessToken, signRefreshToken, type AuthTokenPayload } from "../utils/jwt";

interface RequestContext {
  userAgent?: string;
  ipAddress?: string;
}

interface AuthResult {
  user: User;
  accessToken: string;
  refreshToken: string;
}

type UserRow = {
  id: string;
  email: string;
  password_hash: string;
  created_at: Date;
  updated_at: Date;
};

type SessionRow = {
  id: string;
  user_id: string;
  refresh_token_hash: string;
  expires_at: Date;
};

function toUser(row: Pick<UserRow, "id" | "email" | "created_at" | "updated_at">): User {
  return {
    id: row.id,
    email: row.email,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

async function createAuthResult(userRow: Pick<UserRow, "id" | "email" | "created_at" | "updated_at">, context: RequestContext): Promise<AuthResult> {
  const user = toUser(userRow);
  const sessionId = crypto.randomUUID();
  const payloadBase: AuthTokenPayload = {
    userId: user.id,
    sessionId,
    email: user.email,
  };
  const accessToken = signAccessToken(payloadBase);
  const refreshToken = signRefreshToken({ userId: user.id, sessionId });

  await query(
    `
      INSERT INTO sessions (
        id,
        user_id,
        refresh_token_hash,
        user_agent,
        ip_address,
        expires_at
      )
      VALUES ($1, $2, $3, $4, $5, $6)
    `,
    [
      sessionId,
      user.id,
      hashToken(refreshToken),
      context.userAgent ?? null,
      context.ipAddress ?? null,
      new Date(Date.now() + getTokenExpiryFromDuration(env.JWT_REFRESH_TTL)),
    ],
  );

  return { user, accessToken, refreshToken };
}

export async function register(input: RegisterInput, context: RequestContext): Promise<AuthResult> {
  const normalizedEmail = input.email.trim().toLowerCase();
  const existingUser = await query<{ id: string }>(
    `SELECT id FROM users WHERE email = $1 LIMIT 1`,
    [normalizedEmail],
  );

  if (existingUser.rows.length > 0) {
    throw new AppError(409, "An account with that email already exists");
  }

  const passwordHash = await argon2.hash(input.password);

  const userResult = await query<UserRow>(
    `
      INSERT INTO users (email, password_hash)
      VALUES ($1, $2)
      RETURNING id, email, password_hash, created_at, updated_at
    `,
    [normalizedEmail, passwordHash],
  );

  return createAuthResult(userResult.rows[0], context);
}

export async function login(input: LoginInput, context: RequestContext): Promise<AuthResult> {
  const normalizedEmail = input.email.trim().toLowerCase();
  const userResult = await query<UserRow>(
    `
      SELECT id, email, password_hash, created_at, updated_at
      FROM users
      WHERE email = $1
      LIMIT 1
    `,
    [normalizedEmail],
  );

  const user = userResult.rows[0];
  if (!user) {
    throw new AppError(401, "Invalid email or password");
  }

  const passwordMatches = await argon2.verify(user.password_hash, input.password);
  if (!passwordMatches) {
    throw new AppError(401, "Invalid email or password");
  }

  return createAuthResult(user, context);
}

export async function refresh(refreshToken: string, context: RequestContext): Promise<AuthResult> {
  const tokenPayload = verifyRefreshToken(refreshToken);

  const sessionResult = await query<SessionRow>(
    `
      SELECT id, user_id, refresh_token_hash, expires_at
      FROM sessions
      WHERE id = $1
        AND user_id = $2
        AND revoked_at IS NULL
        AND expires_at > NOW()
      LIMIT 1
    `,
    [tokenPayload.sessionId, tokenPayload.userId],
  );

  const session = sessionResult.rows[0];
  if (!session) {
    throw new AppError(401, "Session is no longer valid");
  }

  if (!verifyTokenHash(refreshToken, session.refresh_token_hash)) {
    throw new AppError(401, "Refresh token is invalid");
  }

  const userResult = await query<Pick<UserRow, "id" | "email" | "created_at" | "updated_at">>(
    `
      SELECT id, email, created_at, updated_at
      FROM users
      WHERE id = $1
      LIMIT 1
    `,
    [session.user_id],
  );

  const userRow = userResult.rows[0];
  if (!userRow) {
    throw new AppError(401, "User no longer exists");
  }

  const user = toUser(userRow);
  const nextAccessToken = signAccessToken({
    userId: user.id,
    sessionId: session.id,
    email: user.email,
  });
  const nextRefreshToken = signRefreshToken({ userId: user.id, sessionId: session.id });

  await query(
    `
      UPDATE sessions
      SET refresh_token_hash = $1,
          expires_at = $2,
          updated_at = NOW()
      WHERE id = $3
    `,
    [
      hashToken(nextRefreshToken),
      new Date(Date.now() + getTokenExpiryFromDuration(env.JWT_REFRESH_TTL)),
      session.id,
    ],
  );

  return {
    user,
    accessToken: nextAccessToken,
    refreshToken: nextRefreshToken,
  };
}

export async function revokeSession(sessionId: string) {
  await query(
    `
      UPDATE sessions
      SET revoked_at = NOW(),
          updated_at = NOW()
      WHERE id = $1
    `,
    [sessionId],
  );
}

export async function getCurrentUser(userId: string): Promise<User> {
  const result = await query<Pick<UserRow, "id" | "email" | "created_at" | "updated_at">>(
    `
      SELECT id, email, created_at, updated_at
      FROM users
      WHERE id = $1
      LIMIT 1
    `,
    [userId],
  );

  const user = result.rows[0];
  if (!user) {
    throw new AppError(404, "User not found");
  }

  return toUser(user);
}