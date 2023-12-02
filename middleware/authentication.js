const { signedCookies } = require("cookie-parser");
const CustomError = require("../errors");
const { isTokenValid } = require("../utils");

const authenticateUser = async (req, res, next) => {
  let token = req.signedCookies.token;

 
  if (!token) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer")) {
      token = authHeader.split(" ")[1];
      
    }
  }

  if (!token) {
   
    throw new CustomError.UnauthenticatedError("Authentication Invalid");
  }

  try {
    const { name, user_name, userId } =
      isTokenValid({
        token,
      });
    req.user = {
      name,
      user_name,
      userId,
    };
    next();
  } catch (error) {
    throw new CustomError.UnauthenticatedError("Authentication Invalid");
  }
};

const authorizePermissions = (...roles) => {
  return (req, res, next) => {
    
    if (!roles.includes(req.user.role)) {
      throw new CustomError.UnauthorizedError(
        "Unauthorized to access this route"
      );
    }

    next();
  };
};

module.exports = {
  authenticateUser,
  authorizePermissions,
};
