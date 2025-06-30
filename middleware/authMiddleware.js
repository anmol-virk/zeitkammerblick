const jwt = require("jsonwebtoken");
const User = require('../models/user.model')

const authMiddleware = async (req, res, next) => {
  console.log(req)
  const token = req.headers.authorization?.split(' ')[1]; 
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id)
  
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: "Invalid or expired token." });
  }
};

module.exports = { authMiddleware };
