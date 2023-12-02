const createTokenUser = (user) => {
  
  return {
    name: user.name?user.name:null,
    user_name: user.user_name,
    userId: user._id,
    email:user.email
  };
};

module.exports = createTokenUser;
