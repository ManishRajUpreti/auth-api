import { Router } from "express";

import { requireAuth } from "../middleware/auth.middleware";
import {
  getCurrentUserController,
  loginController,
  logoutController,
  refreshController,
  registerController,
} from "../controllers/auth.controller";

export const authRouter = Router();

authRouter.post("/register", registerController);
authRouter.post("/login", loginController);
authRouter.post("/refresh", refreshController);
authRouter.post("/logout", requireAuth, logoutController);
authRouter.get("/me", requireAuth, getCurrentUserController);