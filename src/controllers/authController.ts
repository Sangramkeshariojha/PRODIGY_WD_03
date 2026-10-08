import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma";

// REGISTER USER
export const register = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { name, email, password } = req.body;

    // Basic validation
    if (
      typeof name !== "string" ||
      name.trim().length < 2 ||
      typeof email !== "string" ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      typeof password !== "string" ||
      password.length < 6
    ) {
      res.status(400).json({
        error:
          "Name must be at least 2 characters, email must be valid, and password must be at least 6 characters",
      });
      return;
    }

    // Check if email already exists
    const existingUser = await prisma.user.findUnique({
      where: {
        email: email.trim(),
      },
    });

    if (existingUser) {
      res.status(409).json({
        error: "A user with this email already exists",
      });
      return;
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user
    const user = await prisma.user.create({
      data: {
        name: name.trim(),
        email: email.trim(),
        passwordHash,
      },
    });

    // Never return the password hash
    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Failed to register user",
    });
  }
};

// LOGIN USER
export const login = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { email, password } = req.body;

    // Basic validation
    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      res.status(400).json({
        error: "Email and password are required",
      });
      return;
    }

    // Find user by email
    const user = await prisma.user.findUnique({
      where: {
        email: email.trim(),
      },
    });

    if (!user) {
      res.status(401).json({
        error: "Invalid email or password",
      });
      return;
    }

    // Compare password with stored bcrypt hash
    const passwordMatches = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!passwordMatches) {
      res.status(401).json({
        error: "Invalid email or password",
      });
      return;
    }

    // Get JWT secret
    const jwtSecret = process.env.JWT_SECRET;

    if (!jwtSecret) {
      res.status(500).json({
        error: "JWT secret is not configured",
      });
      return;
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        userId: user.id,
        role: user.role,
      },
      jwtSecret,
      {
        expiresIn: "1d",
      }
    );

    // Send response
    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Failed to login",
    });
  }
};