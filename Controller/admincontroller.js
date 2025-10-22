const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const admin = require("../mongo/adminlogin/admin");

// Function to generate JWT
const generateToken = (adminId) => {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined in environment variables");
  }
  return jwt.sign({ id: adminId }, process.env.JWT_SECRET, { expiresIn: "25d" });
};

// @desc    Register admin
const adminregister = async (req, res, next) => {
  try {
    const { pancard, officeemailid, password, mobilenumber } = req.body;

    // Check if admin already exists
    const existingAdmin = await admin.findOne({ officeemailid });
    if (existingAdmin) {
      return res.status(400).json({ message: "Admin already exists" });
    }

    // Check password length
    if (!password || password.length < 8) {
      return res.status(400).json({ message: "Password must be at least 8 characters long" });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new admin
    const newAdmin = await admin.create({
      pancard,
      officeemailid,
      mobilenumber,
      password: hashedPassword,
    });

    // Generate JWT token
    const token = generateToken(newUser._id);

    // Send response
    res.status(201).json({
      user: { id: newAdmin._id, pancard: newAdmin.pancard, officeemailid: newAdmin.officeemailid, mobilenumber: newAdmin.mobilenumber },
      token,
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Login user
const adminlogin = async (req, res, next) => {
  try {
    const { emailid, password } = req.body;

    // Find admin by email
    const admin = await admin.findOne({ officeemailid });
    if (!admin) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Generate JWT token
    const token = generateToken(user._id);

    // Send response
    res.status(200).json({
      admin: { id: admin._id, pancard: admin.pancard, officeemailid: admin.officeemailid, mobilenumber: admin.mobilenumber },
      token,
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Get admin profile
const getadminprofile = async (req, res, next) => {
  try {
    const admin = await admin.findById(req.user.id).select("-password");
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }
    res.json(admin);
  } catch (error) {
    next(error);
  }
};

module.exports = {
  adminregister,
  adminlogin,
  getadminprofile,
};
