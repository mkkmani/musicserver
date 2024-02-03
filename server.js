const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const cors = require('cors');

require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// const tempUri = 'mongodb://localhost:27017/music';
const mongoUri = process.env.MONGO_URI
const port = process.env.PORT

// Define schemas using mongoose.Schema
const adminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  mobile: { type: String, required: true },
  password: { type: String, required: true }
});

const Admin = mongoose.model('Admin', adminSchema);

const studentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  mobile: { type: Number, required: true },
  email: { type: String, required: true },
  password: { type: String, required: true }
});

const Student = mongoose.model('Student', studentSchema);

const imagesSchema = new mongoose.Schema({
  title: { type: String, required: true },
  url:{ type: String, required: true }
})

const Image = mongoose.model('Image', imagesSchema)

const eventImagesSchema = new mongoose.Schema({
  name: { type: String, required: true },
  url:{ type: String, required: true }
})

const EventImages = mongoose.model('EventImages', eventImagesSchema)


// Connect to MongoDB
const  connectToDatabase = async() => {
  try {
    await mongoose.connect(mongoUri);
    console.log('Database connected successfully');
    app.listen(port || 5009, () => {
      console.log(`Server is running on port ${port}`);
    });
  } catch (error) {
    console.error('Error in database connection:', error);
    process.exit(1)
  }
}

// Middleware for token authentication
const tokenAuthentication = (req, res, next) => {
  const authHeader = req.header('Authorization');

  if (!authHeader) {
    return res.status(401).json({ message: 'Unauthorized: Access token missing' });
  }

  try {
    const token = authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'Unauthorized: Invalid token format' });
    }

    const validToken = jwt.verify(token, process.env.MY_SECRET_CODE);

    if (validToken) {
      req.details = req.body;
      next();
    } else {
      res.status(401).json({ message: 'Unauthorized: Invalid token' });
    }
  } catch (error) {
    console.error('Error in token authentication:', error.message);
    res.status(403).json({ message: 'Forbidden: Error in token authentication' });
  }
};

// Routes

// Admin signup
app.post('/admin/signup', async (req, res) => {
  const { name, mobile, email, password } = req.body;
  try {
    const existingUser = await Admin.findOne({ $or: [{ mobile: mobile }, { email: email }] });
    if (existingUser) {
      return res.status(409).json({ message: 'Mobile or email already exists' });
    }
    const hashedPass = await bcrypt.hash(password, 10);
    const newAdmin = new Admin({
      name,
      mobile,
      email,
      password: hashedPass
    });
    await newAdmin.save();
    return res.status(200).json({ message: 'Admin added successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Admin login
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await Admin.findOne({ $or: [{ mobile: username }, { email: username }] });
    if (!user) {
      return res.status(404).json({ message: 'Admin not found' });
    }
    const verifyPassword = await bcrypt.compare(password, user.password);
    if (verifyPassword) {
      const payload = { id: user._id, mobile: user.mobile, email: user.email };
      const jwtToken = jwt.sign(payload, process.env.MY_SECRET_CODE, { expiresIn: '1h' });
      return res.status(200).json({ jwtToken });
    } else {
      return res.status(401).json({ message: 'Invalid password' });
    }
  } catch (error) {
    console.error('Error in admin login:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Student signup
app.post('/student/signup', async (req, res) => {
  const { name, mobile, email, password } = req.body;
  try {
    const existingUser = await Student.findOne({ $or: [{ mobile: mobile }, { email: email }] });
    if (existingUser) {
      return res.status(409).json({ message: 'Mobile or email already exists' });
    }
    const hashedPass = await bcrypt.hash(password, 10);
    const newStudent = new Student({
      name,
      mobile,
      email,
      password: hashedPass
    });
    await newStudent.save();
    return res.status(200).json({ message: 'Student added successfully' });
  } catch (error) {
    console.error('Error in student signup:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Student login
app.post('/student/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await Student.findOne({ $or: [{ mobile: username }, { email: username }] });
    if (!user) {
      return res.status(404).json({ message: 'Student not found' });
    }
    const verifyPassword = await bcrypt.compare(password, user.password);
    if (verifyPassword) {
      const payload = { id: user._id, mobile: user.mobile, email: user.email };
      const jwtToken = jwt.sign(payload, process.env.MY_SECRET_CODE, { expiresIn: '1h' });
      return res.status(200).json({ jwtToken });
    } else {
      return res.status(401).json({ message: 'Invalid password' });
    }
  } catch (error) {
    console.error('Error in student login:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Video post
app.post('/video', tokenAuthentication, async (req, res) => {
  const { title, url } = req.details;
  try {
    const newVideo = new Video({
      title,
      url
    });
    await newVideo.save();
    res.status(200).json({ message: 'Video added successfully' });
  } catch (error) {
    console.error('Error adding video:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Connect to MongoDB and start the server
connectToDatabase();
