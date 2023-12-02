const User = require("../models/User");
const { StatusCodes } = require("http-status-codes");
const CustomError = require("../errors");
const {
  attachCookiesToResponse,
  createTokenUser,
  createJWT,
  createHash,
} = require("../utils");
const crypto = require("crypto");


const register = async (req, res) => {
 
  const AlreadyExists = await User.findOne({
   $or: [ { email: req.body.email }, { user_name: req.body.user_name } ],
    is_active: true,
  });

  if (AlreadyExists) {
    throw new CustomError.BadRequestError("User already exists with given email or user_name");
  }

  const verificationToken = crypto.randomBytes(40).toString("hex");
  
   await User.create({
    ...req.body,
    verificationToken,
  });
   
  res.status(StatusCodes.CREATED).json({
    msg: "Success! Please use your token to verify account",
    token:verificationToken
  });
};

const login = async (req, res) => {
  req.body.email = req.body.email.toLowerCase();
  const { email, password } = req.body;

  if (!email || !password) {
    throw new CustomError.BadRequestError("Please provide email and password");
  }
  const user = await User.findOne({email,is_active:true });

  if (!user) {
    throw new CustomError.UnauthenticatedError("No user exists with the given email");
  }

  if (!user.isVerified) {
    throw new CustomError.UnauthenticatedError("Please verify your email");
  }

  const isPasswordCorrect = await user.comparePassword(req.body.password);
  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError("Invalid password");
  }

  const tokenUser = createTokenUser(user);
  const token = createJWT({ payload: tokenUser });
  attachCookiesToResponse({ res, user: tokenUser, token });
  res.status(StatusCodes.OK).json({ user: tokenUser, token });
};

const verifyEmail = async (req, res) => {
  const { verificationToken, email } = req.query;

  const user = await User.findOne({ email,is_active:true });

  if (!user) {
    throw new CustomError.UnauthenticatedError("Verification Failed");
  }

  if (user.isVerified) {
   res.status(StatusCodes.OK).json({ msg: "Email Already Verified" });
    return;
  }

  if (user.verificationToken !== verificationToken) {
    res.status(StatusCodes.OK).json({ msg: "Verification Failed" });
    return;
  }

  (user.isVerified = true);
  user.verificationToken = "";

  await user.save();

  res.status(StatusCodes.OK).json({ msg:"Email Verified" });

  // res.redirect(`${process.env.FRONT_END_URI}/verification/success`);
};

const logout = async (req, res) => {
  res.cookie("token", "logout", {
    httpOnly: true,
    expires: new Date(Date.now() + 1000),
  });
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer")) {
    let token = authHeader.split(" ")[1];
    token = null;
  }
  res.status(StatusCodes.OK).json({ msg: "user logged out!" });
};

const updateUserPassword = async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    throw new CustomError.BadRequestError("Please provide both values");
  }
  const user = await User.findOne({ _id: req.user.userId });

  const isPasswordCorrect = await user.comparePassword(oldPassword);
  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError("Invalid Password");
  }
  user.password = newPassword;
  user.password_updated = true;
 
 
  await user.save({ validateBeforeSave: true });
  res.status(StatusCodes.OK).json({ msg: "Success! Password Updated." });
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;
  if (!email) {
    throw new CustomError.BadRequestError("Please provide valid email");
  }

  let  user = await User.findOne({ email:email.toLowerCase()});

  if (!email) {
    throw new CustomError.NotFoundError("No user found for given email");
  }

  if (user) {
    const passwordToken = crypto.randomBytes(70).toString("hex");
    // send email
    
    const tenMinutes = 1000 * 60 * 10;
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes);

    user.passwordToken = createHash(passwordToken);
    user.passwordTokenExpirationDate = passwordTokenExpirationDate;
    user= await user.save();
    res
      .status(StatusCodes.OK)
      .json({
        msg: "Please use your token to update password",
        token: passwordToken,
      });
  }

  
};

const resetPassword = async (req, res) => {
  const { token, email, password } = req.body;
  if (!token || !email || !password) {
    throw new CustomError.BadRequestError("Please provide all values");
  }
  const user = await User.findOne({ email:email.toLowerCase(),is_active:true});
  if (!user) {
    throw new CustomError.NotFoundError("No User found for given email");
  }
  if (user) {
    const currentDate = new Date();
    if (
      user.passwordToken &&
      user.passwordToken === createHash(token) &&
      user.passwordTokenExpirationDate > currentDate
    ) {
     
      user.password = password;
      user.passwordToken = null;
      user.passwordTokenExpirationDate = null;
      await user.save();
    } else {
      throw new CustomError.BadRequestError("Password reset link has expired");
    }
  }
  

  res
    .status(StatusCodes.CREATED)
    .json({ result: "Password updated successfully" });
};

const getCurrentUser = async (req, res) => {
  const user = await User.findOne(
    { _id: req.user.userId },
    {
      name: 1,
      email: 1,
      bio: 1,
      age: 1,
      user_name: 1,
    }
  );
  res.status(StatusCodes.OK).json({ user });
};

const updateCurrentUser = async (req, res) => {
  
  if (
    req.body.is_active ||
    req.body.is_verified 
  ) {
    throw new CustomError.UnauthorizedError(
      "You are not allowed to do this action"
    );
  }
  const user = await User.findOneAndUpdate({ _id: req.user.userId }, req.body, {
    new: true,
    runValidators: true,
  });
  res.status(StatusCodes.OK).json({ user });
};



const deleteCurrentUser = async (req, res) => {
  let  user = await User.findOne({ _id: req.user.userId });
  const isPasswordCorrect = await user.comparePassword(req.body.password);
  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError("Incorrect password");
  }
   user = await User.findOneAndDelete({ _id: req.user.userId });
  res.status(StatusCodes.OK).json({ msg:"Account deleted successfully" });
};

module.exports = {
  register,
  login,
  logout,
  updateUserPassword,
  verifyEmail,
  forgotPassword,
  resetPassword,
  getCurrentUser,
  updateCurrentUser,
  deleteCurrentUser
};
