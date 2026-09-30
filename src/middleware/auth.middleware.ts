import type { NextFunction, Request, Response } from "express";

import { ACCESS_TOKEN_COOKIE } from "../config/cookies";
import { query } from "../db";
import { AppError } from "../utils/errors";
import { verifyAccessToken } from "../utils/jwt";

function readBearerToken(authorizationHeader?: string) {
  if (!authorizationHeader) {
    return null;
  }

  const [scheme, token] = authorizationHeader.split(" ");
  if (scheme !== "Bearer" || !token) {
    return null;
  }

  return token;
}

export async function requireAuth(req: Request, _res: Response, next: NextFunction) {
  try {
    const token = req.cookies?.[ACCESS_TOKEN_COOKIE] ?? readBearerToken(req.headers.authorization);

    if (!token) {
      throw new AppError(401, "Authentication required");
    }

    const payload = verifyAccessToken(token);

    const sessionResult = await query<{ id: string; user_id: string }>(
      `
        SELECT id, user_id
        FROM sessions
        WHERE id = $1
          AND user_id = $2
          AND revoked_at IS NULL
          AND expires_at > NOW()
        LIMIT 1
      `,
      [payload.sessionId, payload.userId],
    );

    const session = sessionResult.rows[0];
    if (!session) {
      throw new AppError(401, "Session is no longer valid");
    }

    const userResult = await query<{ id: string; email: string; created_at: Date; updated_at: Date }>(
      `
        SELECT id, email, created_at, updated_at
        FROM users
        WHERE id = $1
        LIMIT 1
      `,
      [payload.userId],
    );

    const user = userResult.rows[0];
    if (!user) {
      throw new AppError(401, "User no longer exists");
    }

    req.authUser = {
      id: user.id,
      email: user.email,
      createdAt: user.created_at.toISOString(),
      updatedAt: user.updated_at.toISOString(),
    };
    req.authSessionId = session.id;
    next();
  } catch (error) {
    next(error);
  }
}