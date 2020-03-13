const express = require("express");
const connectDB = require("./config/db");
const path = require("path");
// const cors = require("cors");
const passport = require("passport");

const app = express();

// Connect DB
connectDB();

// Init Middleware
// app.use(cors);
app.use(express.json({ extended: false }));
app.use(passport.initialize());

require("./middlewares/passport")(passport);

// User Router Middleware
app.use("/api/users", require("./routes/users"));
// DEFINE ROUTES:

// Register, retrieve, update, delete user objects from the database
// app.use("/api/users", require("./routes/users"));

// login, logout, get web tokens etc
// app.use("/api/auth", require("./routes/auth"));

// Serve static assets in production
if (process.env.NODE_ENV === "production") {
  app.use(express.static("client/build"));

  app.get("*", (req, res) =>
    res.sendFile(path.resolve(__dirname, "client", "build", "index.html"))
  );
}

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server started on port ${PORT}...`));
