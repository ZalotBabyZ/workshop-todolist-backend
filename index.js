require("dotenv").config();
const express = require("express");
const app = express();
const db = require("./models");
const userRoutes = require("./routes/user");
const todoRoutes = require("./routes/todo");
const cors = require('cors');

require("./config/passport")

app.use(cors())
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use("/users", userRoutes);
app.use("/todos", todoRoutes);

app.listen(process.env.PORT, () => {
  console.log("Server is running");
});

db.sequelize.sync()
  .then(() => {
    console.log("Data sync");
  })
  .catch(err => {
    console.log(err);
  });