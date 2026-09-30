export interface User {
  id: string;
  email: string;
  createdAt: string;
  updatedAt: string;
}

export interface RegisterInput {
  email: string;
  password: string;
}

export interface LoginInput {
  email: string;
  password: string;
}

declare global {
  namespace Express {
    interface Request {
      authUser?: User;
      authSessionId?: string;
    }
  }
}

export {};