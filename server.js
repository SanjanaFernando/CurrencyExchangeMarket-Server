const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET_KEY || "fallback_secret_key";

app.use(bodyParser.json());
app.use(cors());

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", () => {
  console.log("Connected to MongoDB");
});

const accountSchema = new mongoose.Schema({
  userId: String,
  amount: Number,
  pwd: String,
  username: String,
});

const Account = mongoose.model("Account", accountSchema);

const authenticateJWT = (req, res, next) => {
  const token =
    req.header("Authorization") && req.header("Authorization").split(" ")[1];
  if (!token) {
    return res
      .status(401)
      .json({ message: "Access denied, no token provided." });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (ex) {
    res.status(400).json({ message: "Invalid token." });
  }
};
app.delete("/api/admin/users/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await Account.deleteOne({ userId });
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error", error });
  }
});
app.get("/api/admin/users", authenticateJWT, async (req, res) => {
  try {
    const users = await Account.find({}, "userId username amount");
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: "Internal server error", error });
  }
});

app.put("/api/admin/users/:userId", authenticateJWT, async (req, res) => {
  const { userId } = req.params;
  const { amount } = req.body;
  try {
    const user = await Account.findOneAndUpdate(
      { userId },
      { amount },
      { new: true }
    );
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ message: "Amount updated", user });
  } catch (error) {
    res.status(500).json({ message: "Internal server error", error });
  }
});

app.post("/login", async (req, res) => {
  const { userId, pwd } = req.body;

  console.log("Received login request:", { userId, pwd }); // Debugging log

  try {
    // Check for admin credentials
    if (userId === "admin" && pwd === "000") {
      console.log("Admin login successful"); // Debugging log
      const token = jwt.sign({ userId: "admin" }, SECRET_KEY, {
        expiresIn: "1h",
      });
      return res
        .status(200)
        .json({ message: "Admin login successful", token, userId: "admin" });
    }

    const user = await Account.findOne({ userId });

    if (!user) {
      console.log("Invalid credentials: user not found"); // Debugging log
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isPasswordValid = await bcrypt.compare(pwd, user.pwd);
    if (!isPasswordValid) {
      console.log("Invalid credentials: incorrect password"); // Debugging log
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user.userId }, SECRET_KEY, {
      expiresIn: "1h",
    });

    res
      .status(200)
      .json({ message: "Login successful", token, userId: user.userId });
  } catch (error) {
    console.error("Internal server error:", error); // Debugging log
    res.status(500).json({ message: "Internal server error", error });
  }
});
app.post("/transfer", authenticateJWT, async (req, res) => {
  const { senderId, recipientId, amount } = req.body;

  try {
    const sender = await Account.findOne({ userId: senderId });
    const recipient = await Account.findOne({ userId: recipientId });

    if (!sender || !recipient) {
      return res.status(404).json({ message: "Sender or recipient not found" });
    }

    if (sender.amount < amount) {
      return res.status(400).json({ message: "Insufficient funds" });
    }

    sender.amount -= amount;
    recipient.amount += amount;

    await sender.save();
    await recipient.save();

    res.status(200).json({
      message: `Transferred ${amount} from User ${senderId} to User ${recipientId}`,
    });
  } catch (error) {
    res.status(500).json({ message: "Internal server error", error });
  }
});

app.put("/signup", async (req, res) => {
  const { userId, username, pwd } = req.body;

  if (!userId || !username || !pwd) {
    return res
      .status(400)
      .json({ message: "User ID, username, and password are required" });
  }

  try {
    const existingUser = await Account.findOne({ userId });

    if (existingUser) {
      return res.status(409).json({ message: "User ID already exists" });
    }

    const hashedPwd = await bcrypt.hash(pwd, 10);

    await Account.create({ userId, username, pwd: hashedPwd, amount: 0 });

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error", error });
  }
});

app.get("/user/:userId", authenticateJWT, async (req, res) => {
  const { userId } = req.params;

  try {
    const user = await Account.findOne({ userId }, "userId amount username");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: "Internal server error", error });
  }
});

app.delete("/user/:userId", authenticateJWT, async (req, res) => {
  const { userId } = req.params;

  try {
    const result = await Account.deleteOne({ userId });
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error", error });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
