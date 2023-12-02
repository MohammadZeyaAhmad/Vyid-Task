const express = require("express");
const app = express();
const router = express.Router();
const {
  register,
  login,
  logout,
  updateUserPassword,
  verifyEmail,
  forgotPassword,
  resetPassword,
  getCurrentUser,
  updateCurrentUser,
  deleteCurrentUser,
} = require("../controllers/auth");
const {
  authenticateUser
} = require("../middleware/authentication");

router.route("/register").post(register);

router.route("/login").post(login);

router.route("/details").get(authenticateUser, getCurrentUser);

router.route("/update").put(authenticateUser, updateCurrentUser);

router.route("/delete").delete(authenticateUser, deleteCurrentUser);

router.route("/logout").get(logout);

router.route("/resetPassword").put(resetPassword);

router.route("/updatePassword").put(authenticateUser, updateUserPassword);

router.route("/verifyEmail").post(verifyEmail);

router.route("/forgotPassword").post( forgotPassword);

module.exports = router;
