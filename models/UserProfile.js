
const mongoose = require('mongoose');

const UserProfileSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
  },
  bio: {
    type: String,
    trim: true,
    maxlength: 500,
  },
  location: {
    type: String,
    trim: true,
    maxlength: 100,
  },
  website: {
    type: String,
    trim: true,
    maxlength: 200,
  },
  social: {
    twitter: String,
    linkedin: String,
    github: String,
  },
  // Forum-specific fields
  forumSignature: {
    type: String,
    trim: true,
    maxlength: 250,
  },
  reputation: {
    type: Number,
    default: 0,
  },
  badges: [
    {
      name: String,
      description: String,
      awardedAt: Date,
    },
  ],
  achievements: [
    {
      name: String,
      description: String,
      unlockedAt: Date,
    },
  ],
  forumStats: {
    posts: {
      type: Number,
      default: 0,
    },
    threads: {
      type: Number,
      default: 0,
    },
    likesReceived: {
      type: Number,
      default: 0,
    },
    solutions: {
      type: Number,
      default: 0,
    },
  },
  lastSeen: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model('UserProfile', UserProfileSchema);


