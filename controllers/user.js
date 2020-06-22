const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("../models/user");

require('dotenv').config()


// sign up logic
exports.createUser = (req, res, next) => {
  let { name, email, password } = req.body;
  name = name.toLowerCase();
  email = email.toLowerCase();
  bcrypt.hash(password, 10).then(hash => {
    const user = new User({
      name,
      email,
      password: hash
    });
    user
      .save()
      .then(result => {
        res
          .status(201)
          .json({ message: "User created Sucessfully", result: result });
      })
      .catch(err => {
        console.log('err!!!', err)
        res.status(500).json({
          message: "Invalid authentication creditials!"
        });
      });
  });
};

// login logic
exports.userLogin = (req, res, next) => {
  let fetchedUser;
  User.findOne({ email: req.body.email })
    .then(user => {
      if (!user) {
        return res.status(401).json({ message: "User does not exist!" });
      }
      fetchedUser = user;
      return bcrypt.compare(req.body.password, user.password);
    })
    .then(result => {
      if (!result) {
        return res.status(401).json({ message: "Incorrect Password!" });
      }
      const token = jwt.sign(
        {
          email: fetchedUser && fetchedUser.email,
          userId: fetchedUser && fetchedUser._id,
          name: fetchedUser && fetchedUser.name
        },
        process.env.JWT_KEY,
        { expiresIn: "10h" }
      );

      return res
        .status(200)
        .json({
          message: "Login Success",
          token: token,
          expiresIn: 36000000,
          userId: fetchedUser && fetchedUser._id
        });
    })
    .catch(error => {
      console.log('err!!!', err)
      return res
        .status(401)
        .json({ message: "Invalid authentication credentials!" });
    });
};
