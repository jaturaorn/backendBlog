const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const cors = require("cors");

const app = express();
const prisma = new PrismaClient();

app.use(express.json());
app.use(cors());

// login & register

app.post("/register", async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: "Please provide all fields" });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser)
      return res.status(400).json({ error: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { email, password: hashedPassword, name },
    });

    res
      .status(201)
      .json({ message: "User registered successfully", userId: user.id });
  } catch (error) {
    console.error("Register Error:", error);
    res
      .status(500)
      .json({ error: "Internal Server Error", details: error.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    // 1. find User
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user)
      return res.status(401).json({ error: "Invalid email or password" });

    // 2. Verify password (real vs. hashed)
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      return res.status(401).json({ error: "Invalid email or password" });

    // 3. Create a token (store the user's ID inside).
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res.json({
      message: "Login successful",
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied, no token provided" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid or expired token" });
    req.userId = decoded.userId;
    next();
  });
};

// posts

app.get("/posts", async (req, res) => {
  try {
    const posts = await prisma.post.findMany({
      include: {
        author: {
          select: { name: true, email: true },
        },
      },
      orderBy: {
        createdAt: "desc",
      },
    });
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/posts", authenticateToken, async (req, res) => {
  try {
    const { title, content } = req.body;

    const newPost = await prisma.post.create({
      data: {
        title,
        content,
        authorId: req.userId,
      },
    });

    res.status(201).json(newPost);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/posts/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params; // id ตรงนี้จะเป็น String เช่น "659af..."
    const { title, content } = req.body;

    // 1. ค้นหา Post (ไม่ต้องใช้ Number() ครอบ id)
    const post = await prisma.post.findUnique({
      where: { id: id }, // ส่งค่า id ที่เป็น String เข้าไปได้เลย
    });

    if (!post) return res.status(404).json({ error: "ไม่พบโพสต์นี้" });

    // 2. เช็คสิทธิ์ (authorId ใน MongoDB ก็เป็น String จึงเทียบกันได้เลย)
    if (post.authorId !== req.userId) {
      return res.status(403).json({ error: "คุณไม่มีสิทธิ์แก้ไขโพสต์นี้" });
    }

    // 3. ทำการอัปเดต
    const updatePost = await prisma.post.update({
      where: { id: id },
      data: { title, content },
    });

    res.json(updatePost);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/posts/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const post = await prisma.post.findUnique({
      where: { id: id },
    });

    if (!post) return res.status(404).json({ error: "ไม่พบโพสต์นี้" });
    if (post.authorId !== req.userId)
      return res.status(403).json({ error: "คุณไม่มีสิทธิ์ลบโพสต์นี้" });

    await prisma.post.delete({
      where: { id: id },
    });

    res.json({ message: "ลบโพสต์เรียบร้อยแล้ว" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => console.log("Server running on port 3000"));
