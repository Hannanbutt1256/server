const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
require("dotenv").config();

const app = express();
app.use(
  cors({
    origin: "*",
  })
);

app.use(express.json());

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("DB connected successfully");
  })
  .catch((err) => {
    console.log("Error in DB connection", err);
  });

// User Schema
const userSchema = new mongoose.Schema({
  userName: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isOnline: { type: Boolean, default: false }, // New field to track online status
});

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const User = mongoose.model("User", userSchema);

// Register endpoint
app.post("/api/register", async (req, res) => {
  const { userName, email, password } = req.body;

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already registered." });
    }

    const user = new User({
      userName,
      email,
      password,
    });

    await user.save();
    return res.status(201).json({
      message:
        "User registered successfully. Please wait for admin verification.",
      user: { id: user._id, email: user.email, userName: user.userName },
    });
  } catch (err) {
    console.error("Error saving user:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});
//Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Set the user as online
    user.isOnline = true;
    await user.save();

    return res.json({
      message: "Login successful",
      user: {
        id: user._id,
        email: user.email,
        userName: user.userName,
      },
    });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});
//Logout
app.post("/api/logout", async (req, res) => {
  const { email } = req.body;

  // Validate input
  if (!email) {
    return res.status(400).json({ message: "Email is required." });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User not found." });
    }

    // Set the user as offline
    user.isOnline = false;
    await user.save();

    return res.json({ message: "Logout successful." });
  } catch (err) {
    console.error("Error during logout:", err);
    return res.status(500).json({ message: "Internal server error." });
  }
});

// Get total number of users
app.get("/api/users/total", async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    return res.json({ totalUsers });
  } catch (err) {
    console.error("Error fetching total users:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/users/online", async (req, res) => {
  try {
    const onlineUsers = await User.countDocuments({ isOnline: true });
    return res.json({ onlineUsers });
  } catch (err) {
    console.error("Error fetching online users:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Server setup
const server = app.listen(process.env.PORT, () => {
  console.log(`Server running at port: ${process.env.PORT}`);
});
