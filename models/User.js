const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const validator=require("validator");
const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      minlength: 3,
      maxlength: 50,
    },
    email: {
      type: String,
      trim: true,
      lowercase: true,
      required: [true, "Please provide email"],
      validate: {
        validator: validator.isEmail,
        message: "Please provide valid email",
      },
    },
    user_name: {
      type: String,
      required: true,
    },
    bio: {
      type: String,
    },
    password: {
      type: String,
      minlength: 6,
      required: true,
    },
    age: {
      type: Number,
    },
    is_active: {
      type: Boolean,
      required: true,
      default: true,
    },
    verificationToken: String,
    passwordToken: {
      type: String,
    },
    passwordTokenExpirationDate: {
      type: Date,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

UserSchema.pre("save", async function () {
  
  if(this.password==null) return;
  if (!this.isModified("password")) return;
  
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

UserSchema.methods.comparePassword = async function (password) {
  const isMatch = await bcrypt.compare(password, this.password);
  return isMatch;
};

UserSchema.methods.compareResetToken = async function (token) {

  const isMatch = await bcrypt.compare(token, this.passwordToken);
  return isMatch;
};

module.exports = mongoose.model("User", UserSchema);
