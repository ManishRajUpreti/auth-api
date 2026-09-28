import type { NextFunction, Request, Response } from "express";

import { ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE, getCookieOptions } from "../config/cookies";
import { env } from "../config/env";
import { getCurrentUser, login, refresh, register, revokeSession } from "../services/auth.service";
import { AppError } from "../utils/errors";
import { loginSchema, registerSchema } from "../utils/validation";
import { parseDurationToMs } from "../utils/time";

function authContextFromRequest(req: Request) {
  return {
    userAgent: req.get("user-agent") ?? undefined,
    ipAddress: req.ip,
  };
}

function setAuthCookies(res: Response, accessToken: string, refreshToken: string) {
  res.cookie(ACCESS_TOKEN_COOKIE, accessToken, getCookieOptions(parseDurationToMs(env.JWT_ACCESS_TTL)));
  res.cookie(REFRESH_TOKEN_COOKIE, refreshToken, getCookieOptions(parseDurationToMs(env.JWT_REFRESH_TTL)));
}

function clearAuthCookies(res: Response) {
  res.clearCookie(ACCESS_TOKEN_COOKIE, getCookieOptions());
  res.clearCookie(REFRESH_TOKEN_COOKIE, getCookieOptions());
}

export async function registerController(req: Request, res: Response, next: NextFunction) {
  try {
    const input = registerSchema.parse(req.body);
    const result = await register(input, authContextFromRequest(req));

    setAuthCookies(res, result.accessToken, result.refreshToken);
    res.status(201).json({ user: result.user });
  } catch (error) {
    next(error);
  }
}

export async function loginController(req: Request, res: Response, next: NextFunction) {
  try {
    const input = loginSchema.parse(req.body);
    const result = await login(input, authContextFromRequest(req));

    setAuthCookies(res, result.accessToken, result.refreshToken);
    res.status(200).json({ user: result.user });
  } catch (error) {
    next(error);
  }
}

export async function refreshController(req: Request, res: Response, next: NextFunction) {
  try {
    const refreshToken = req.cookies?.[REFRESH_TOKEN_COOKIE];
    if (!refreshToken) {
      throw new AppError(401, "Refresh token is required");
    }

    const result = await refresh(refreshToken, authContextFromRequest(req));
    setAuthCookies(res, result.accessToken, result.refreshToken);
    res.status(200).json({ user: result.user });
  } catch (error) {
    next(error);
  }
}

export async function logoutController(req: Request, res: Response, next: NextFunction) {
  try {
    if (req.authSessionId) {
      await revokeSession(req.authSessionId);
    }

    clearAuthCookies(res);
    res.status(204).send();
  } catch (error) {
    next(error);
  }
}

export async function getCurrentUserController(req: Request, res: Response, next: NextFunction) {
  try {
    if (!req.authUser) {
      throw new AppError(401, "Authentication required");
    }

    const user = await getCurrentUser(req.authUser.id);
    res.status(200).json({ user });
  } catch (error) {
    next(error);
  }
}