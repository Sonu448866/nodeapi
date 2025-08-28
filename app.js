import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import cors from "cors";
import { config } from "dotenv";
import express from "express";

config({
  path: "config.env",
});

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "http://localhost:3000",
    methods: ["GET", "PUT", "POST", "DELETE"],
    credentials: true,
  })
);

//sendtoken
const sendToken = (user, res, message, statusCode = 200) => {
  const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET_KEY);
  res
    .status(statusCode)
    .cookie("token", token, {
      httpOnly: true,
      maxAge: 15 * 60 * 1000,

      secure: process.env.NODE_ENV == "Development" ? false : true,
      sameSite: process.env.NODE_ENV == "Development" ? "lax" : "none",
    })
    .json({
      success: true,
      message,
    });
};

//isAuthanticated
const isAuthanticated = async (req, res, next) => {
  const { token } = req.cookies;
  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Login First",
    });
  }
  try {
    const decodedData = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = await User.findById(decodedData._id);
    next();
  } catch (e) {
    return res.status(401).json({
      sucess: false,
      message: "Invalid Token",
    });
  }
};

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI, {
    dbName: "backendapii",
  })
  .then((c) => console.log(`✅ MongoDB connected ${c.connection.host}`))
  .catch((e) => console.log("❌ MongoDB error:", e));

// Schema
const itemschema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  category: {
    type: String,
    required: true,
  },
  location: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  createdDate: {
    type: Date,
    default: Date.now,
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
});

const Item = mongoose.model("Item", itemschema);

const userSchema = new mongoose.Schema({
  name: String,
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    select: false,
    required: true,
  },
  createDate: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.model("User", userSchema);

// Route
app.post("/api/item/new", isAuthanticated, async (req, res) => {
  try {
    const { title, category, location, description, email } = req.body;

    const item = await Item.create({
      title,
      category,
      location,
      description,
      email,
      user: req.user._id,
    });

    res.status(201).json({
      success: true,
      message: "Registered Successfully",
      item,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/api/", async (req, res) => {
  try {
    const items = await Item.find().sort({ createdDate: -1 });
    res.json({
      count: items.length,
      items,
    });
  } catch (e) {
    res.status(500).json({
      message: "Error",
    });
  }
});

app.get("/api/item/:id", isAuthanticated, async (req, res) => {
  try {
    const { id } = req.params;

    const item = await Item.findById(id);
    res.json({
      success: true,
      item,
    });
  } catch (e) {
    res.status(500).json({
      success: false,
      message: "Error",
    });
  }
});

app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  let user = await User.findOne({ email });
  if (user) {
    return res.status(400).json({
      success: false,
      message: "user alredy exist",
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  user = await User.create({
    name,
    email,
    password: hashedPassword,
  });
  sendToken(user, res, "Registered Successfully", 201);
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email }).select("+password");
  if (!user) {
    return res.status(400).json({
      success: false,
      message: "Invalid email or password",
    });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({
      success: false,
      message: "Incorrect password",
    });
  }
  sendToken(user, res, `Welcome Back:${user.name}`, 200);
});

app.get("/api/logout", isAuthanticated, (req, res) => {
  try {
    res
      .status(200)
      .cookie("token", " ", {
        expires: new Date(0),
        httpOnly: true,
        secure: process.env.NODE_ENV == "Development" ? false : true,
        sameSite: process.env.NODE_ENV == "Development" ? "lax" : "none",
      })
      .json({
        success: true,
        message: "Logout Successfully",
      });
  } catch (e) {
    res.json({
      success: false,
      message: "Error",
    });
  }
});

app.get("/api/getMyDetail", isAuthanticated, async (req, res) => {
  try {
    const userid = req.user._id;

    const item = await Item.find({ user: userid }).sort({ createdDate: -1 });

    res.status(200).json({
      success: true,
      item,
    });
  } catch (e) {
    res.status(500).json({
      success: false,
      message: e.message,
    });
  }
});

// Start server
app.listen(process.env.PORT, () => {
  console.log(`🚀 Server is running on port ${process.env.PORT}`);
});
