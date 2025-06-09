const mongoose = require('mongoose');

const AlbumSchema = new mongoose.Schema({
  albumId: { type: String },
  name: { type: String, required: true },
  description: { type: String },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  sharedUsers: [{ type: String }],
});

module.exports = mongoose.model('Album', AlbumSchema);
