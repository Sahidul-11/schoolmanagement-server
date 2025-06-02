const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion } = require("mongodb");

dotenv.config();

const app = express();
const port = process.env?.PORT || 5100;

app.use(cors());
app.use(express.json());

// MongoDB connection
const uri = process.env?.MONGO_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// JWT middleware  to protect ..but no need at this moment..............

function verifyToken(req, res, next) {
  const authHeader = req?.headers?.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized - No token provided" });
  }

  const token = authHeader?.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env?.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Forbidden - Invalid token" });
  }
}

async function run() {
  try {
    await client.connect();
    const db = client?.db("schoolManagement");
    const studentsCollection = db?.collection("students");
    const parentsCollection = db?.collection("parents");

    // ---------------- LOGIN ----------------
    app.post("/login", async (req, res) => {
      const { email, password } = req?.body;

      if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
      }

      try {
        let user = await studentsCollection?.findOne({ email });
        let userRole = "student";

        if (!user) {
          user = await parentsCollection?.findOne({ email });
          userRole = "parent";
        }

        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        const isPasswordValid = await bcrypt.compare(password, user?.password);
        if (!isPasswordValid) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign(
          {
            id: user?._id,
            name: user?.name,
            email: user?.email,
            role: userRole,
          },
          process.env?.JWT_SECRET,
          { expiresIn: process.env?.JWT_EXPIRES_IN || "1d" }
        );

        res.status(200).json({
          message: "Login successful",
          token,
          user: {
            id: user?._id,
            name: user?.name,
            email: user?.email,
            role: userRole,
          },
        });
      } catch (error) {
        res.status(500).json({ message: "Internal server error", error });
      }
    });

    // ---------------- STUDENT REGISTER ----------------
    app.put("/student", async (req, res) => {
      const { name, email, password, studentClass, educationCode, number } = req?.body;

      if (!email || !password || !number || !educationCode) {
        return res.status(400).json({ message: "Required fields are missing" });
      }

      try {
        const existingUser = await studentsCollection?.findOne({ email, number, educationCode });
        if (existingUser) {
          return res.status(409).json({ message: "Student already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 8);

        const newUser = {
          name,
          email,
          password: hashedPassword,
          studentClass,
          educationCode,
          number,
          createdAt: new Date(),
        };

        const result = await studentsCollection?.insertOne(newUser);

        res.status(201).json({ message: "User registered successfully", result });
      } catch (error) {
        res.status(500).json({ message: "Internal server error", error });
      }
    });

    //............PARENT REGISTER ----------------
    app.put("/parent", async (req, res) => {
      const { name, email, password, number, relationship, childStudentId } = req?.body;

      if (!email || !password || !number || !relationship || !childStudentId) {
        return res.status(400).json({ message: "Required fields are missing" });
      }

      try {
        const existingParent = await parentsCollection?.findOne({ email, number, childStudentId });
        if (existingParent) {
          return res.status(409).json({ message: "Parent already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 8);

        const newParent = {
          name,
          email,
          password: hashedPassword,
          number,
          relationship,
          childStudentId,
          createdAt: new Date(),
        };

        const result = await parentsCollection?.insertOne(newParent);

        res.status(201).json({ message: "Parent registered successfully", result });
      } catch (error) {
        res.status(500).json({ message: "Internal server error", error });
      }
    });

    app.get("/ch", async (req, res) => {
      res.send("okay");
    });

    // ---------------- PROTECTED ROUTE ----------------

    console.log("Connected to MongoDB!");
  } catch (err) {
    console.error(err);
  }
}

run();

app.get("/", (req, res) => {
  res.send("Server is running");
});

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
