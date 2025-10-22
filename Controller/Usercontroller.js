const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../mongo/Userlogin/user");

// Function to generate JWT
const generateToken = (userId) => {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined in environment variables");
  }
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: "25d" });
};

// @desc    Register user
const register = async (req, res, next) => {
  try {
    const { username, emailid, password, mobilenumber } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ emailid });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Check password length
    if (!password || password.length < 8) {
      return res.status(400).json({ message: "Password must be at least 8 characters long" });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const newUser = await User.create({
      username,
      emailid,
      mobilenumber,
      password: hashedPassword,
    });

    // Generate JWT token
    const token = generateToken(newUser._id);

    // Send response
    res.status(201).json({
      user: { id: newUser._id, username: newUser.username, emailid: newUser.emailid, mobilenumber: newUser.mobilenumber },
      token,
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Login user
const login = async (req, res, next) => {
  try {
    const { emailid, password } = req.body;

    // Find user by email
    const user = await User.findOne({ emailid });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Generate JWT token
    const token = generateToken(user._id);

    // Send response
    res.status(200).json({
      user: { id: user._id, username: user.username, emailid: user.emailid, mobilenumber: user.mobilenumber },
      token,
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Get user profile
const getuserprofile = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(user);
  } catch (error) {
    next(error);
  }
};

module.exports = {
  register,
  login,
  getuserprofile,
};
