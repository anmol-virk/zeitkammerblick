const express = require("express")
const axios = require("axios")
const cors = require("cors")
const jwt = require("jsonwebtoken")
require("dotenv").config()
const mongoose = require("mongoose");
const { v4: uuidv4 } = require('uuid');
const multer = require("multer")
const cloudinary = require("cloudinary")
const fs = require("fs")
const path = require('path')

const { authMiddleware } = require("./middleware/authMiddleware.js")
const  Album  = require('./models/album.model')
const  User  = require('./models/user.model')
const  Image  = require('./models/image.model')

const app = express()
const PORT = process.env.PORT || 4001
const { initializeDatabase } = require("./db/db.connect")
const cookieParser = require("cookie-parser")

app.use(express.json())
app.use(cors({ 
  credentials: true, 
  origin: [ 
    process.env.FRONTEND_URL,
    `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
  ]
}))
app.use(cookieParser());

initializeDatabase()

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
})

//multer
const storage = multer.diskStorage({})
const upload = multer({ storage })


const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, userId: user.userId },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );
};

app.get("/", (req, res) => {
    res.redirect(process.env.FRONTEND_URL)
})

app.get("/auth/google", (req, res) => {
    const googleAuthUrl = `https://accounts.google.com/o/oauth2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}/auth/google/callback&response_type=code&scope=profile email`;

    res.redirect(googleAuthUrl)
})

app.get("/auth/google/callback", async (req, res) => {
    const { code } = req.query

    if(!code) {
        return res.status(400).send("Authorization code not provided.")
    }

    try {
      const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        code,
        grant_type: "authorization_code",
        redirect_uri: `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}/auth/google/callback`,
      },
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" }
      }
    )
    const accessToken = tokenResponse.data.access_token;
   
    const userInfoResponse = await axios.get(
      "https://www.googleapis.com/oauth2/v2/userinfo",
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const { id: googleId, email } = userInfoResponse.data;

    //check if user exists
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ email, googleId, userId: uuidv4() });
      await user.save();
    }

    const jwtToken = generateToken(user);

    res.cookie("token", jwtToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
   
    return res.redirect(`${process.env.FRONTEND_URL}/albums`)
    } catch(error) {
      console.error(error)
    }
})

//creating album
app.post("/albums", authMiddleware, async (req, res) => {
    try {
        const { albumId, name, description, sharedUsers } = req.body;
        const ownerId = req.user._id
        const album = new Album({
          albumId,
          name,
          description,
          ownerId,
          sharedUsers
        });
        if (!mongoose.Types.ObjectId.isValid(ownerId)) {
          return res.status(400).json({ error: 'Invalid ownerId' });
        }
        if (!name) {
          return res.status(400).json({ error: 'Album name is required' });
        }
        await album.save();
        await album.populate("ownerId", "email")
        res.status(201).json({ message: 'Album created successfully', album });
    } catch (error){
      console.error('Error creating album:', error);
        res.status(500).json({error: "Error creating album."})
    }
})

   //get all albums
   app.get("/albums", authMiddleware, async (req, res) => {
    try {
      const albums = await Album.find({
        $or: [
          { ownerId: req.user._id },
          { sharedUsers: req.user.email }
        ]
      }).populate("ownerId", "email");
      res.status(200).json({ albums });
   
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch albums.", error });
    }
  });

//update album
app.put("/albums/:id", authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const { name, description } = req.body;
      const album = await Album.findById(id);
  
      if (!album) {
        return res.status(404).json({ error: 'Album not found' });
      }
      if (album.ownerId.toString() !== req.user._id.toString()) {
        return res.status(403).json({ error: 'You are not authorized to update this album' });
      }
  
  if (name) album.name = name;
  if (description) album.description = description; 
       await album.save();
  
      res.status(200).json({ message: 'Album updated successfully', album });
    } catch (error) {
      console.error("Error updating album:", error.message);
      res.status(500).json({ error: 'Error updating album', details: error.message });
    }
  })

  //share album
  app.post("/albums/:albumId/share", authMiddleware, async (req, res) => {
    try {
      const { albumId } = req.params;
      const { sharedUsers } = req.body;
  
      const album = await Album.findById(albumId);
      if (!album) {
        return res.status(404).json({ error: 'Album not found' });
      }
  
      if (album.ownerId.toString() !== req.user._id.toString()) {
        return res.status(403).json({ error: 'You are not authorized to share this album' });
      }
  
      if (!sharedUsers || !Array.isArray(sharedUsers) || !sharedUsers.every(email => typeof email === 'string' && email.includes('@'))) {
        return res.status(400).json({ error: 'Invalid emails format' });
      }
  
      // Validate emails exist in the system
      const validUsers = await User.find({ email: { $in: sharedUsers } });
      const validEmails = validUsers.map((user) => user.email);
  
      album.sharedUsers.push(...validEmails);
      album.sharedUsers = [...new Set(album.sharedUsers)]; 
  
      await album.save();
  
      res.status(200).json({ message: 'Album shared successfully', album });
    } catch (error) {
      res.status(500).json({ error: 'Error sharing album', details: error.message });
    }
  })

  //delete album
  app.delete("/albums/:albumId", authMiddleware, async (req, res) => {
    try {
      const { albumId } = req.params;
  
      const album = await Album.findById(albumId);
  
      if (!album) {
        return res.status(404).json({ error: 'Album not found' });
      }
  
      if (album.ownerId.toString() !== req.user._id.toString()) {
        return res.status(403).json({ error: 'You are not authorized to delete this album' });
      }
      await Image.deleteMany({ albumId });
      await Album.findByIdAndDelete(albumId);
  
      res.status(200).json({ message: 'Album and associated images deleted successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Error deleting album', details: error.message });
    }
  })

  //upload image
  app.post("/albums/:albumId/images", authMiddleware, upload.single("file"), async (req, res) => {
    try {
      const { albumId } = req.params;
      const { tags, person, isFavorite } = req.body;
  
      const album = await Album.findById(albumId);
  
      if (!album) {
        return res.status(404).json({ error: 'Album not found' });
      }
      if (album.ownerId.toString() !== req.user._id.toString()) {
        return res.status(403).json({ error: 'You do not have access to this album' });
      }
  
      if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
      }
  
      const file = req.file;

      const fileSize = fs.statSync(file.path).size;
      const fileType = path.extname(file.originalname).toLowerCase();
  
      if (!['.jpg', '.jpeg', '.png', '.gif'].includes(fileType)) {
        return res.status(400).json({ error: 'Only image files are allowed (jpg, png, gif)' });
      }
      const maxSize = 5 * 1024 * 1024;
      if (fileSize > maxSize) {
        fs.unlinkSync(file.path); 
        return res.status(400).json({ error: 'File size exceeds the 5MB limit' });
      }
      
    const result = await cloudinary.uploader.upload(file.path, {
      folder: "uploads", 
      resource_type: 'image',
    });
  
      const image = new Image({
        imageId: uuidv4(),
        albumId,
        name: file.originalname,
        size: fileSize,
        tags: tags ? JSON.parse(tags.split(',')) : [],
        person,
        isFavorite: isFavorite === 'true',
        comments: [],
        uploadedAt: new Date(),
        imageUrl: result.secure_url
      });
  
      await image.save();
      fs.unlinkSync(file.path)
      res.status(201).json({ message: 'Image uploaded successfully', image });
    } catch (error) {

      if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
      res.status(500).json({ error: 'Error uploading image', details: error.message });
    }
  })
  //get images
  app.get('/albums/:albumId/images/all', authMiddleware, async (req, res) => {
    try {
      const { albumId } = req.params;
  
      if (!albumId) {
        return res.status(400).json({ success: false, message: 'Album ID is required' });
      }
      
      const album = await Album.findById(albumId);
      if (!album) {
        return res.status(404).json({ success: false, error: 'Album not found' });
      }
      const hasAccess =
        album.ownerId.toString() === req.user._id.toString() ||
        album.sharedUsers.includes(req.user.email);
  
      if (!hasAccess) {
        return res.status(403).json({ success: false, error: 'Access denied to this album' });
      }
  
      const images = await Image.find({ albumId });
      res.status(200).json({ success: true, data: images });
    } catch (error) {
      res.status(500).json({ success: false, message: 'Error fetching images', error: error.message });
    }
  });
  //favorite image
  app.put('/albums/:albumId/images/:imageId/favorite', authMiddleware, async (req, res) => {
    try {
      const { albumId, imageId } = req.params;
      const { isFavorite } = req.body;
  
      const album = await Album.findById(albumId);
      if (!album) {
        return res.status(404).json({ error: 'Album not found' });
      }
  
      if (album.ownerId.toString() !== req.user._id.toString() && !album.sharedUsers.includes(req.user.email)) {
        return res.status(403).json({ error: 'You do not have access to this album' });
      }
  
      const image = await Image.findOne({ imageId });
      if (!image) {
        return res.status(404).json({ error: 'Image not found' });
      }
  
      if (image.albumId.toString() !== album._id.toString()) {
        return res.status(400).json({ error: 'Image does not belong to this album' });
      }
      image.isFavorite = isFavorite === true || isFavorite === "true"
      await image.save();
  
      res.status(200).json({ message: 'Image updated successfully', image });
    } catch (error) {
      res.status(500).json({ error: 'Error updating image', details: error.message });
    }
  });
  // get all favorite images
  app.get('/albums/:albumId/images/favorites', authMiddleware, async (req, res) => {
    const { albumId } = req.params;
 
    try {
      if (!mongoose.Types.ObjectId.isValid(albumId)) {
        return res.status(400).json({ error: 'Invalid album ID format' });
      }
      const favoriteImages = await Image.find( {albumId: new mongoose.Types.ObjectId(albumId),
        isFavorite: true,
      });
  
      if (!favoriteImages.length) {
        return res.status(200).json({ message: 'No favorite images found', images: [] });
      }
      res.status(200).json({ images: favoriteImages });
    } catch (error) {
      console.error('Error fetching favorite images:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });
  //get images by tags
  app.get('/albums/:albumId/images', authMiddleware, async (req, res) => {
    const { albumId } = req.params;
    const { tags } = req.query;
  
    try {
       const query = {albumId};

      if (!mongoose.Types.ObjectId.isValid(albumId)) {
        return res.status(400).json({ error: 'Invalid album ID' });
      }
  
      if (tags) {   
         query.tags = {$regex: tags.trim(), $options:'i'}
      }
  
      const images = await Image.find(query);
  
      res.status(200).json({ 
        message: images.length ? 'Images found' : 'No images found',
        data: images 
      });
    } catch (error) {
      console.error('Error fetching images by tags:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });
  //add cmnt to img
  app.post('/albums/:albumId/images/:imageId/comments', authMiddleware, async (req, res) => {
    try {
      const { albumId, imageId } = req.params;
      const { comment } = req.body;
      if (!comment) {
        return res.status(400).json({ error: 'Comment is required' });
      }
  
      const album = await Album.findById(albumId);
      if (!album) {
        return res.status(404).json({ error: 'Album not found' });
      }
  
      if (album.ownerId.toString() !== req.user._id.toString() && !album.sharedUsers.includes(req.user.email)) {
        return res.status(403).json({ error: 'You do not have access to this album' });
      }

      const image = await Image.findOne({ imageId });
      if (!image) {
        return res.status(404).json({ error: 'Image not found' });
      }
      if (image.albumId.toString() !== album._id.toString()) {
        return res.status(400).json({ error: 'Image does not belong to this album' });
      }
      image.comments.push(comment);
      await image.save();
  
      res.status(200).json({ message: 'Comment added successfully', image });
    } catch (error) {
      res.status(500).json({ error: 'Error adding comment', details: error.message });
    }
  });
//delete image
app.delete('/albums/:albumId/images/:imageId', authMiddleware, async (req, res) => {
    try {
      const { albumId, imageId } = req.params;
  
      const album = await Album.findById(albumId);
      if (!album) {
        return res.status(404).json({ error: 'Album not found' });
      }

      if (album.ownerId.toString() !== req.user._id.toString()) {
        return res.status(403).json({ error: 'You do not have access to this album' });
      }
  
      const image = await Image.findOne({imageId});
      if (!image) {
        return res.status(404).json({ error: 'Image not found' });
      }
  
      await Image.findOneAndDelete({imageId});
  
      res.status(200).json({ message: 'Image deleted successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Error deleting image', details: error.message });
    }
  });

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`)
})
module.exports = app