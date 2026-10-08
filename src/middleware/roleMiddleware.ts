import { Response, NextFunction } from "express";
import { AuthRequest } from "./authMiddleware";

export const authorizeRoles = (...allowedRoles: string[]) => {
  return (
    req: AuthRequest,
    res: Response,
    next: NextFunction
  ): void => {
    const userRole = req.user?.role;

    if (!userRole) {
      res.status(401).json({
        error: "Unauthorized",
      });
      return;
    }

    if (!allowedRoles.includes(userRole)) {
      res.status(403).json({
        error: "Access denied. Insufficient permissions.",
      });
      return;
    }

    next();
  };
};