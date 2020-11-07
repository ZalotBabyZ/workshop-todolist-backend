const db = require("../models");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");

const register = async (req, res) => {
  const { username, password, name } = req.body;
  const targetUser = await db.User.findOne({ where: { username } });

  if (targetUser) {
    res.status(400).send({ message: "Username already taken." });
  } else {
    // GEN SALT
    const salt = bcryptjs.genSaltSync(Number(process.env.SALT_ROUND));
    // HASH PASSWORD WITH SALT
    const hashedPWD = bcryptjs.hashSync(password, salt);
    // STORE to Database
    await db.User.create({
      username,
      name,
      password: hashedPWD
    });
    // Send Response

    res.status(201).send({ message: "User created" });
  }
};

const login = async (req, res) => {
  const { username, password } = req.body;
  const targetUser = await db.User.findOne({ where: { username } });

  if (!targetUser) {
    res.status(400).send({ message: "username or password is wrong." });
  } else {
    if (bcryptjs.compareSync(password, targetUser.password)) {
      const token = jwt.sign({ id: targetUser.id }, process.env.SECRET , { expiresIn: 3600 });
      res.status(200).send({ token });
    } else {
      res.status(400).send({ message: "username or password is wrong." });
    }

  }
};

module.exports = {
  register,
  login
};