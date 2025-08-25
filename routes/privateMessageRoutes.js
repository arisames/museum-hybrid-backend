const express = require("express");
const router = express.Router();
const { protect } = require("../middleware/authMiddleware");
const { validate } = require("../middleware/validationMiddleware");
const { sendMessageSchema, markMessageReadStatusSchema } = require("../validation/messageValidation");
const { authorizeRoles } = require("../middleware/rbacMiddleware");
const {
  sendMessage,
  getMessages,
  getMessageById,
  markMessageReadStatus,
  deleteMessage,
  getUnreadMessageCount,
} = require("../controllers/privateMessageController");

router.route("/").post(protect, authorizeRoles("user", "admin", "curator"), validate(sendMessageSchema), sendMessage).get(protect, authorizeRoles("user", "admin", "curator"), getMessages);
router.route("/unread/count").get(protect, authorizeRoles("user", "admin", "curator"), getUnreadMessageCount);
router
  .route("/:id")
  .get(protect, authorizeRoles("user", "admin", "curator"), getMessageById)
  .delete(protect, authorizeRoles("user", "admin", "curator"), deleteMessage);
router.route("/:id/read").put(protect, authorizeRoles("user", "admin", "curator"), validate(markMessageReadStatusSchema), markMessageReadStatus);

module.exports = router;


