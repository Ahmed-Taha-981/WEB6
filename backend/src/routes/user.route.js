import express from 'express';
import User from "../models/user.model.js";
import { protectRoute, authorizeRoles } from "../middleware/auth.middleware.js";

const router = express.Router();

// Public route - accessible by everyone
router.get("/public", (req, res) => {
    res.status(200).json({ message: "This is a public endpoint accessible by everyone" });
});

// Protected route - authenticated users only
router.get("/protected", protectRoute, (req, res) => {
    res.status(200).json({ 
        message: "This is a protected endpoint for authenticated users only",
        user: {
            id: req.user._id,
            username: req.user.username,
            role: req.user.role
        }
    });
});

// Moderator route - only for moderator and admin
router.get("/moderator", protectRoute, authorizeRoles("moderator", "admin"), (req, res) => {
    res.status(200).json({ 
        message: "This is a moderator endpoint, accessible by moderators and admins only",
        user: {
            id: req.user._id,
            username: req.user.username,
            role: req.user.role
        }
    });
});

// Admin route - only for admin
router.get("/admin", protectRoute, authorizeRoles("admin"), (req, res) => {
    res.status(200).json({ 
        message: "This is an admin endpoint, accessible by admins only",
        user: {
            id: req.user._id,
            username: req.user.username,
            role: req.user.role
        }
    });
});

// Get all users - admin only
router.get("/", protectRoute, authorizeRoles("admin"), async (req, res) => {
    try {
        const users = await User.find().select("-password");
        res.status(200).json(users);
    } catch (error) {
        console.error("Error getting users:", error.message);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Get user by ID - admin only
router.get("/:id", protectRoute, authorizeRoles("admin"), async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select("-password");
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json(user);
    } catch (error) {
        console.error("Error getting user:", error.message);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Update user role - admin only
router.put("/:id/role", protectRoute, authorizeRoles("admin"), async (req, res) => {
    try {
        const { role } = req.body;
        
        // Validate role
        if (!role || !['user', 'moderator', 'admin'].includes(role)) {
            return res.status(400).json({ message: "Invalid role. Must be 'user', 'moderator', or 'admin'" });
        }
        
        // Find user
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        
        // Update role
        user.role = role;
        await user.save();
        
        res.status(200).json({ 
            message: `User role updated to ${role} successfully`,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error("Error updating user role:", error.message);
        res.status(500).json({ message: "Internal server error" });
    }
});

export default router; 