import type { CookieOptions } from "express";

import { env } from "./env";

export const ACCESS_TOKEN_COOKIE = "auth_access_token";
export const REFRESH_TOKEN_COOKIE = "auth_refresh_token";

export function getCookieOptions(maxAgeMs?: number): CookieOptions {
  return {
    httpOnly: true,
    secure: env.COOKIE_SECURE,
    sameSite: env.COOKIE_SAMESITE,
    domain: env.COOKIE_DOMAIN || undefined,
    path: "/",
    ...(typeof maxAgeMs === "number" ? { maxAge: maxAgeMs } : {}),
  };
}