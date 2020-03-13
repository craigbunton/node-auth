const router = require("express").Router();
const {
  authUser,
  serializeUser,
  checkRole,
  registerUser,
  loginUser
} = require("../utils/Auth");
// ---------------------------------------------------------
// Player Registration Route
router.post("/register-player", async (req, res) => {
  await registerUser(req.body, "player", res);
});

// Manager Registration Route
router.post("/register-manager", async (req, res) => {
  await registerUser(req.body, "manager", res);
});

// Admin Registration Route
router.post("/register-admin", async (req, res) => {
  await registerUser(req.body, "admin", res);
});

// ---------------------------------------------------------
// Player Login Route
router.post("/login-player", async (req, res) => {
  console.log("Login player req.body: ", req.body);
  await loginUser(req.body, "player", res);
});

// Manager Login Route
router.post("/login-manager", async (req, res) => {
  await loginUser(req.body, "manager", res);
});

// Admin Login Route
router.post("/login-admin", async (req, res) => {
  await loginUser(req.body, "admin", res);
});

// ---------------------------------------------------------
// Profile Route
router.get("/profile", authUser, async (req, res) => {
  return res.json(serializeUser(req.user));
});

// ---------------------------------------------------------
// Player Protected Route
router.get(
  "/player-protected",
  authUser,
  checkRole(["player", "manager", "admin"]),
  async (req, res) => {
    return res
      .status(200)
      .send("Protected route: only player, manager, admin allowed");
  }
);

// Manager Protected Route
router.get(
  "/manager-protected",
  authUser,
  checkRole(["manager", "admin"]),
  async (req, res) => {
    return res.status(200).send("Protected route: only manager, admin allowed");
  }
);

// Admin Protected Route
router.get(
  "/admin-protected",
  authUser,
  checkRole(["admin"]),
  async (req, res) => {
    return res.status(200).send("Protected route: only admin allowed");
  }
);

module.exports = router;
