import { generateToken, isValidEmail, isStrongPassword } from '../lib/utils.js';
import User from '../models/user.model.js';
import bcrypt from 'bcryptjs';
import cloudinary from '../lib/cloudinary.js';

export const signup = async (req, res) => {
    const { username, email, password } = req.body;
    try {
        // Check for required fields
        if (!username || !email || !password) {
            return res.status(400).json({ message: 'Please fill all required fields' });
        }
        
        // Validate email format
        if (!isValidEmail(email)) {
            return res.status(400).json({ message: 'Please provide a valid email address' });
        }
        
        // Validate password strength
        if (!isStrongPassword(password)) {
            return res.status(400).json({ 
                message: 'Password must be at least 8 characters long and include at least one number and one special character' 
            });
        }
        
        // Check if user already exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            if (existingUser.email === email) {
                return res.status(400).json({ message: 'Email already in use' });
            }
            if (existingUser.username === username) {
                return res.status(400).json({ message: 'Username already taken' });
            }
        }
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Create new user with default role 'user'
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            role: 'user', // Default role for security
        });
        
        // Save user to database
        await newUser.save();
        
        // Generate JWT token
        generateToken(newUser._id, res);
        
        // Return user data without password
        res.status(201).json({
            _id: newUser._id,
            username: newUser.username,
            email: newUser.email,
            role: newUser.role
        });
    } catch (error) {
        console.log("Error in signup controller:", error.message);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

export const login = async (req, res) => {
    const { email, password } = req.body;
    try {
        // Check for required fields
        if (!email || !password) {
            return res.status(400).json({ message: 'Please provide email and password' });
        }
        
        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        // Verify password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate JWT token
        generateToken(user._id, res);
        
        // Return user data without password
        res.status(200).json({
            _id: user._id,
            username: user.username,
            email: user.email,
            role: user.role,
            profilePic: user.profilePic
        });
    } catch (error) {
        console.log("Error in login controller:", error.message);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

export const logout = (req, res) => {
    try {
        // Clear JWT cookie
        res.cookie('jwt', '', { maxAge: 0 });
        res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
        console.log("Error in logout controller:", error.message);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

export const getProfile = (req, res) => {
    try {
        // User already attached to request by protectRoute middleware
        res.status(200).json(req.user);
    } catch (error) {
        console.log("Error in getProfile controller:", error.message);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

export const updateProfile = async (req, res) => {
    try {
        const { email, password } = req.body;
        const userId = req.user._id;
        
        // Check if anything to update
        if (!email && !password) {
            return res.status(400).json({ message: 'Nothing to update' });
        }
        
        // Prepare update object
        const updateData = {};
        
        // Validate and update email if provided
        if (email) {
            if (!isValidEmail(email)) {
                return res.status(400).json({ message: 'Please provide a valid email address' });
            }
            
            // Check if email is already in use by another user
            const existingUser = await User.findOne({ email });
            if (existingUser && existingUser._id.toString() !== userId.toString()) {
                return res.status(400).json({ message: 'Email already in use' });
            }
            
            updateData.email = email;
        }
        
        // Validate and update password if provided
        if (password) {
            if (!isStrongPassword(password)) {
                return res.status(400).json({ 
                    message: 'Password must be at least 8 characters long and include at least one number and one special character' 
                });
            }
            
            // Hash new password
            const salt = await bcrypt.genSalt(10);
            updateData.password = await bcrypt.hash(password, salt);
        }
        
        // Update user
        const updatedUser = await User.findByIdAndUpdate(
            userId, 
            updateData, 
            { new: true }
        ).select('-password');
        
        res.status(200).json(updatedUser);
    } catch (error) {
        console.log("Error in updateProfile controller:", error.message);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

export const validateToken = (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ 
                valid: false,
                message: 'User not found or token invalid' 
            });
        }
        
        res.status(200).json({ 
            valid: true, 
            user: {
                _id: req.user._id,
                username: req.user.username,
                email: req.user.email,
                role: req.user.role,
                profilePic: req.user.profilePic
            }
        });
    } catch (error) {
        console.log("Error in validateToken controller:", error.message);
        return res.status(500).json({ 
            valid: false,
            message: 'Internal server error during token validation' 
        });
    }
}; 