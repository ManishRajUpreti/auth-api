import jwt from "jsonwebtoken";
import type { SignOptions } from "jsonwebtoken";

import { env } from "../config/env";

export interface AuthTokenPayload {
  userId: string;
  sessionId: string;
  email: string;
}

interface RefreshTokenPayload {
  userId: string;
  sessionId: string;
}

interface DecodedTokenPayload {
  userId: string;
  sessionId: string;
  email?: string;
  tokenType: "access" | "refresh";
}

function ensureDecodedPayload(payload: string | jwt.JwtPayload | undefined, expectedType: "access" | "refresh"): DecodedTokenPayload {
  if (!payload || typeof payload === "string") {
    throw new Error("Invalid token payload");
  }

  const userId = payload.userId;
  const sessionId = payload.sessionId;
  const tokenType = payload.tokenType;

  if (typeof userId !== "string" || typeof sessionId !== "string" || tokenType !== expectedType) {
    throw new Error("Invalid token payload");
  }

  const email = typeof payload.email === "string" ? payload.email : undefined;

  return {
    userId,
    sessionId,
    email,
    tokenType,
  };
}

export function signAccessToken(payload: AuthTokenPayload): string {
  const options: SignOptions = {
    expiresIn: env.JWT_ACCESS_TTL as SignOptions["expiresIn"],
  };

  return jwt.sign({ ...payload, tokenType: "access" }, env.JWT_ACCESS_SECRET, options);
}

export function signRefreshToken(payload: RefreshTokenPayload): string {
  const options: SignOptions = {
    expiresIn: env.JWT_REFRESH_TTL as SignOptions["expiresIn"],
  };

  return jwt.sign({ ...payload, tokenType: "refresh" }, env.JWT_REFRESH_SECRET, options);
}

export function verifyAccessToken(token: string): DecodedTokenPayload {
  const payload = jwt.verify(token, env.JWT_ACCESS_SECRET);
  return ensureDecodedPayload(payload as string | jwt.JwtPayload | undefined, "access");
}

export function verifyRefreshToken(token: string): DecodedTokenPayload {
  const payload = jwt.verify(token, env.JWT_REFRESH_SECRET);
  return ensureDecodedPayload(payload as string | jwt.JwtPayload | undefined, "refresh");
}