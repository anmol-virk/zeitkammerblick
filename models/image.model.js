const mongoose = require('mongoose');

const ImageSchema = new mongoose.Schema({
  imageId: { type: String, unique: true, required: true },
  albumId: { type: mongoose.Schema.Types.ObjectId, ref: 'Album', required: true },
  name: { type: String, required: true },
  tags: [{ type: String }],
  person: { type: String },
  isFavorite: { type: Boolean, default: false },
  comments: [{ type: String }],
  size: { type: Number, required: true },
  imageUrl: { type: String, required: true },
  uploadedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Image', ImageSchema);
