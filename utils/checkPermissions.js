const CustomError = require('../errors');

const chechPermissions = (requestUser, resourceUserId) => {

 
  if (requestUser.userId === resourceUserId.toString()) return;
  throw new CustomError.UnauthorizedError(
    'Not authorized to access this route'
  );
};

module.exports = chechPermissions;
