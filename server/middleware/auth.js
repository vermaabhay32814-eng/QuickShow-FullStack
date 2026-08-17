import { clerkClient } from "@clerk/express";

export const protectAdmin = async (req, res, next) => {
  try {
    // req.auth is an object provided by clerkMiddleware — do NOT call it
    const userId = req.auth?.userId;

    if (!userId) {
      return res.status(401).json({ success: false, message: "not authorized" });
    }

    const user = await clerkClient.users.getUser(userId);

    if (user?.privateMetadata?.role !== "admin") {
      return res.status(403).json({ success: false, message: "not authorized" });
    }

    next();
  } catch (error) {
    console.error("protectAdmin error:", error);
    return res.status(500).json({ success: false, message: "not authorized" });
  }
};
