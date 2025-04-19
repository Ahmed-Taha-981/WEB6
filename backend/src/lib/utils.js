import jwt from 'jsonwebtoken';

export const generateToken = (userId, res) => {
    const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
         expiresIn: '1h' 
    });
    
    res.cookie('jwt', token, { 
        maxAge: 60*60*1000, // 1 hour in milliseconds
        httpOnly: true, // The cookie is not accessible via JavaScript (this prevents XSS attacks)
        sameSite: 'strict', // The cookie is not sent along with cross-site requests (this prevents CSRF attacks)
        secure: process.env.NODE_ENV !== 'development', // The cookie is only sent over HTTPS in production
    });

    return token;
};

// Function to validate email format
export const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

// Function to validate password strength
export const isStrongPassword = (password) => {
    // Check for minimum length of 8 characters
    if (password.length < 8) return false;
    
    // Check for at least one number
    const hasNumber = /\d/.test(password);
    if (!hasNumber) return false;
    
    // Check for at least one special character
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    if (!hasSpecial) return false;
    
    return true;
}; 