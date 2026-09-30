import dotenv from "dotenv";
import crypto from "node:crypto";
import { z } from "zod";

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  DATABASE_URL: z.string().optional(),
  JWT_ACCESS_SECRET: z.string().optional(),
  JWT_REFRESH_SECRET: z.string().optional(),
  JWT_ACCESS_TTL: z.string().regex(/^\d+(ms|s|m|h|d)$/, "JWT_ACCESS_TTL must be a duration like 15m or 1h").default("15m"),
  JWT_REFRESH_TTL: z.string().regex(/^\d+(ms|s|m|h|d)$/, "JWT_REFRESH_TTL must be a duration like 7d").default("7d"),
  COOKIE_SECURE: z.string().optional(),
  COOKIE_DOMAIN: z.string().optional(),
  COOKIE_SAMESITE: z.enum(["lax", "strict", "none"]).default("lax"),
});

const parsed = envSchema.parse(process.env);

function requireValue(value: string | undefined, name: string): string {
  if (!value) {
    throw new Error(`${name} is required. Add it to .env or export it in your shell.`);
  }

  return value;
}

const isProduction = parsed.NODE_ENV === "production";

export const env = {
  ...parsed,
  DATABASE_URL: parsed.DATABASE_URL ?? (isProduction ? requireValue(undefined, "DATABASE_URL") : "postgres://postgres:postgres@localhost:5432/auth_api"),
  JWT_ACCESS_SECRET:
    parsed.JWT_ACCESS_SECRET ??
    (isProduction ? requireValue(undefined, "JWT_ACCESS_SECRET") : crypto.randomBytes(32).toString("hex")),
  JWT_REFRESH_SECRET:
    parsed.JWT_REFRESH_SECRET ??
    (isProduction ? requireValue(undefined, "JWT_REFRESH_SECRET") : crypto.randomBytes(32).toString("hex")),
  COOKIE_SECURE: parsed.COOKIE_SECURE ? parsed.COOKIE_SECURE === "true" : isProduction,
};