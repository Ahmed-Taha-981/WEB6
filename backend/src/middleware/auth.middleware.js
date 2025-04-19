import jwt from 'jsonwebtoken';
import User from '../models/user.model.js';
import rateLimit from 'express-rate-limit';

export const protectRoute = async (req, res, next) => {
    try {
        // Check for token in Authorization header or cookie
        let token;
        const authHeader = req.headers.authorization;
        
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.split(' ')[1];
        } else if (req.cookies.jwt) {
            token = req.cookies.jwt;
        }
        
        if (!token) {
            return res.status(401).json({ message: 'Not authorized, no token' });
        }

        try {
            // Verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            // Get user from database
            const user = await User.findById(decoded.userId).select('-password');
            if(!user) {
                return res.status(404).json({ message: 'User not found' });
            }
            
            // Attach user to request object
            req.user = user;
            next();
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                return res.status(401).json({ message: 'Token expired' });
            }
            return res.status(401).json({ message: 'Not authorized, token failed' });
        }
    } catch (error) {
        console.log("Error in protectRoute middleware:", error.message);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

// Role-based authorization middleware
export const authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ message: 'Not authorized' });
        }
        
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ 
                message: `Role (${req.user.role}) is not authorized to access this resource` 
            });
        }
        
        next();
    };
};

// Rate limiting middleware for login route
export const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 login attempts per IP within windowMs
    message: { message: 'Too many login attempts, please try again later' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Rate limiting middleware for registration route
export const registrationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 registration attempts per IP within windowMs
    message: { message: 'Too many registration attempts, please try again later' },
    standardHeaders: true,
    legacyHeaders: false,
}); 