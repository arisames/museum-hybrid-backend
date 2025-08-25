
const asyncHandler = require("express-async-handler");
const userProfileService = require("../services/userProfileService");

// @desc    Get current user's profile
// @route   GET /api/profile/me
// @access  Private
exports.getMyProfile = asyncHandler(async (req, res) => {
  const profile = await userProfileService.getMyProfile(req.user.id);
  res.json(profile);
});

// @desc    Create or update user profile
// @route   POST /api/profile
// @access  Private
exports.createOrUpdateProfile = asyncHandler(async (req, res) => {
  const profileData = req.body;
  const profile = await userProfileService.createOrUpdateProfile(req.user.id, profileData);
  res.json(profile);
});

// @desc    Get all profiles
// @route   GET /api/profile
// @access  Public (or Admin)
exports.getAllProfiles = asyncHandler(async (req, res) => {
  const profiles = await userProfileService.getAllProfiles();
  res.json(profiles);
});

// @desc    Get profile by user ID
// @route   GET /api/profile/user/:user_id
// @access  Public
exports.getProfileByUserId = asyncHandler(async (req, res) => {
  const profile = await userProfileService.getProfileByUserId(req.params.user_id);
  res.json(profile);
});


