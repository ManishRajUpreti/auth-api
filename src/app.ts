import express from "express";
import cookieParser from "cookie-parser";

import { authRouter } from "./routes/auth.routes";
import { AppError } from "./utils/errors";

export function createApp() {
  const app = express();

  app.use(express.json());
  app.use(cookieParser());

  app.get("/", (_req, res) => {
    res.json({ message: "Auth API is running", health: "/health" });
  });

  app.get("/health", (_req, res) => {
    res.json({ message: "API is running" });
  });

  app.get("/favicon.ico", (_req, res) => {
    res.status(204).end();
  });

  app.use("/auth", authRouter);

  app.use((req, res) => {
    res.status(404).json({ error: `Route ${req.method} ${req.originalUrl} not found` });
  });

  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    if (err instanceof AppError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }

    if (err instanceof Error) {
      res.status(500).json({ error: err.message });
      return;
    }

    res.status(500).json({ error: "Unexpected server error" });
  });

  return app;
}