import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export interface AuthRequest extends Request {
  user?: {
    userId: string;
    role: string;
  };
}

export const authenticateToken = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  try {
    // Get Authorization header
    const authHeader = req.headers.authorization;

    // Check if token exists
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res.status(401).json({
        error: "Access token is required",
      });
      return;
    }

    // Extract token
    const token = authHeader.split(" ")[1];

    // Get JWT secret
    const jwtSecret = process.env.JWT_SECRET;

    if (!jwtSecret) {
      res.status(500).json({
        error: "JWT secret is not configured",
      });
      return;
    }

    // Verify token
    const decoded = jwt.verify(token, jwtSecret) as {
      userId: string;
      role: string;
    };

    // Attach user information to request
    req.user = {
      userId: decoded.userId,
      role: decoded.role,
    };

    // Continue to protected route
    next();
  } catch (error) {
    res.status(403).json({
      error: "Invalid or expired token",
    });
  }
};