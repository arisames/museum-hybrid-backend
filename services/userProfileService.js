const UserProfile = require("../models/UserProfile");
const { NotFoundError } = require("../utils/CustomError");

const getMyProfile = async (userId) => {
  const profile = await UserProfile.findOne({ user: userId }).populate(
    "user",
    ["username", "email"]
  );

  if (!profile) {
    throw new NotFoundError("Profile not found");
  }
  return profile;
};

const createOrUpdateProfile = async (userId, profileData) => {
  const profileFields = {};
  profileFields.user = userId;
  if (profileData.bio) profileFields.bio = profileData.bio;
  if (profileData.location) profileFields.location = profileData.location;
  profileFields.website = profileData.website === "" ? undefined : profileData.website;
  if (profileData.forumSignature) profileFields.forumSignature = profileData.forumSignature;

  profileFields.social = {};
  if (profileData.twitter) profileFields.social.twitter = profileData.twitter;
  if (profileData.linkedin) profileFields.social.linkedin = profileData.linkedin;
  if (profileData.github) profileFields.social.github = profileData.github;

  let profile = await UserProfile.findOne({ user: userId });

  if (profile) {
    profile = await UserProfile.findOneAndUpdate(
      { user: userId },
      { $set: profileFields },
      { new: true }
    );
    return profile;
  }

  profile = new UserProfile(profileFields);
  await profile.save();
  return profile;
};

const getAllProfiles = async () => {
  const profiles = await UserProfile.find().populate("user", ["username", "email"]);
  return profiles;
};

const getProfileByUserId = async (userId) => {
  const profile = await UserProfile.findOne({ user: userId }).populate(
    "user",
    ["username", "email"]
  );

  if (!profile) {
    throw new NotFoundError("Profile not found");
  }
  return profile;
};

module.exports = {
  getMyProfile,
  createOrUpdateProfile,
  getAllProfiles,
  getProfileByUserId,
};


