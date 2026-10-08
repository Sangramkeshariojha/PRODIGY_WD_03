import { Router, Response } from "express";
import {
  authenticateToken,
  AuthRequest,
} from "../middleware/authMiddleware";
import { authorizeRoles } from "../middleware/roleMiddleware";
import { prisma } from "../lib/prisma";

const router = Router();

// GET /users/profile
// Any authenticated user
router.get(
  "/profile",
  authenticateToken,
  async (req: AuthRequest, res: Response): Promise<void> => {
    try {
      const userId = req.user?.userId;

      if (!userId) {
        res.status(401).json({
          error: "Unauthorized",
        });
        return;
      }

      const user = await prisma.user.findUnique({
        where: {
          id: userId,
        },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          createdAt: true,
        },
      });

      if (!user) {
        res.status(404).json({
          error: "User not found",
        });
        return;
      }

      res.status(200).json({
        message: "Protected profile accessed successfully",
        user,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Failed to fetch profile",
      });
    }
  }
);

// USER ONLY
router.get(
  "/user-area",
  authenticateToken,
  authorizeRoles("USER"),
  (_req: AuthRequest, res: Response): void => {
    res.status(200).json({
      message: "Welcome to the USER area",
    });
  }
);

// ADMIN ONLY
router.get(
  "/admin-area",
  authenticateToken,
  authorizeRoles("ADMIN"),
  (_req: AuthRequest, res: Response): void => {
    res.status(200).json({
      message: "Welcome to the ADMIN area",
    });
  }
);

// OWNER ONLY
router.get(
  "/owner-area",
  authenticateToken,
  authorizeRoles("OWNER"),
  (_req: AuthRequest, res: Response): void => {
    res.status(200).json({
      message: "Welcome to the OWNER area",
    });
  }
);

export default router;