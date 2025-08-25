
const express = require("express");
const router = express.Router();
const { protect } = require("../middleware/authMiddleware");
const { validate } = require("../middleware/validationMiddleware");
const { createOrUpdateProfileSchema } = require("../validation/userProfileValidation");
const { authorizeRoles } = require("../middleware/rbacMiddleware");
const {
  getMyProfile,
  createOrUpdateProfile,
  getAllProfiles,
  getProfileByUserId,
} = require("../controllers/userProfileController");

router.route("/me").get(protect, authorizeRoles("user", "admin", "curator"), getMyProfile);
router.route("/").post(protect, authorizeRoles("user", "admin", "curator"), validate(createOrUpdateProfileSchema), createOrUpdateProfile).get(authorizeRoles("admin", "curator"), getAllProfiles);
router.route("/user/:user_id").get(authorizeRoles("user", "admin", "curator"), getProfileByUserId);

module.exports = router;


