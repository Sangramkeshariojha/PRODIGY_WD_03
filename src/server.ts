import express from "express";
import dotenv from "dotenv";
import authRoutes from "./routes/authRoutes";
import userRoutes from "./routes/userRoutes";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// Middleware
app.use(express.json());

// Home route
app.get("/", (_req, res) => {
  res.json({
    message: "PRODIGY_WD_03 Authentication API is running",
  });
});

// Authentication routes
app.use("/auth", authRoutes);

// User routes
app.use("/users", userRoutes);

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});