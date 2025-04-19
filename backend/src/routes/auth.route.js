import express from 'express';
import { 
    login, 
    logout, 
    signup, 
    updateProfile, 
    getProfile, 
    validateToken 
} from "../controllers/auth.controller.js";
import { 
    protectRoute, 
    loginLimiter, 
    registrationLimiter 
} from "../middleware/auth.middleware.js";

const router = express.Router();

// Authentication routes with rate limiting
router.post("/signup", registrationLimiter, signup);
router.post("/login", loginLimiter, login);
router.post("/logout", logout);

// Profile routes - protected
router.get("/profile", protectRoute, getProfile);
router.put("/profile", protectRoute, updateProfile);

// Token validation
router.get("/validate", protectRoute, validateToken);

export default router; 