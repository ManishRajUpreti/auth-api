import crypto from "node:crypto";

export function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function verifyTokenHash(token: string, expectedHash: string): boolean {
  const actualHash = hashToken(token);
  const actualBuffer = Buffer.from(actualHash, "hex");
  const expectedBuffer = Buffer.from(expectedHash, "hex");

  if (actualBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

export function getTokenExpiryFromDuration(duration: string): number {
  const match = /^(\d+)(ms|s|m|h|d)$/.exec(duration);

  if (!match) {
    throw new Error(`Invalid duration: ${duration}`);
  }

  const amount = Number(match[1]);
  const unit = match[2];

  switch (unit) {
    case "ms":
      return amount;
    case "s":
      return amount * 1_000;
    case "m":
      return amount * 60_000;
    case "h":
      return amount * 3_600_000;
    case "d":
      return amount * 86_400_000;
    default:
      throw new Error(`Unsupported duration unit: ${unit}`);
  }
}