const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const User = require("../models/User");
const passport = require("passport");

// @DESC To register any user (Player, Manager, Admin)

const registerUser = async (userDetails, role, res) => {
  try {
    // Validate the user
    let usernameAvailable = await validateUsername(userDetails.username);

    if (!usernameAvailable) {
      return res.status(400).send("User name has already been registered");
    }

    // Validate the email
    let emailAvailable = await validateEmail(userDetails.email);

    if (!emailAvailable) {
      return res.status(400).send("Email has already been registered");
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(userDetails.password, salt);
    const newUser = new User({
      ...userDetails,
      password: hashedPassword,
      role
    });

    // Save the new user to the database
    await newUser.save();
    return res.status(201).send("New user registered");
  } catch (error) {
    return res.status(500).send("User registration failed");
  }
};

const loginUser = async (userCreds, role, res) => {
  let { username, password } = userCreds;
  // First check if the username is in the database
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(404).send("User name not found");
  }
  //Next check the role is a match
  if (user.role !== role) {
    return res.status(403).send("User role does not exist");
  }
  // User and role now validated. Next check the password
  let isMatch = await bcrypt.compare(password, user.password);
  if (isMatch) {
    //Create a token and return it to the user
    let token = jwt.sign(
      {
        user_id: user._id,
        role: user.role,
        username: user.username,
        email: user.email
      },
      config.get("jwtSecret"),
      { expiresIn: "7 days" }
    );
    let result = {
      username: user.username,
      role: user.role,
      email: user.email,
      token: `Bearer ${token}`,
      expiresIn: 168
    };
    console.log(result);
    return res.status(200).json(result);
  } else {
    return res.status(403).send("Password is incorrect");
  }
};

// Passport Middleware
const authUser = passport.authenticate("jwt", { session: false });

const serializeUser = user => {
  return {
    username: user.username,
    email: user.email,
    _id: user._id,
    name: user.name,
    updatedAt: user.updatedAt,
    createdAt: user.createdAt
  };
};

const checkRole = roles => (req, res, next) => {
  console.log("checkRole req.user: ", req.user.role);
  console.log("checkRole roles: ", roles);

  !roles.includes(req.user.role)
    ? res.status(401).json("Unauthorised role")
    : next();

  // if (roles.includes(req.user.role)) {
  //   next();
  // }
  // return res.status(401).send("Unauthorized role");
};

const validateUsername = async username => {
  let userUnique = await User.findOne({ username });
  return userUnique ? false : true;
};

const validateEmail = async email => {
  let emailUnique = await User.findOne({ email });
  return emailUnique ? false : true;
};

module.exports = {
  authUser,
  serializeUser,
  checkRole,
  loginUser,
  registerUser
};
