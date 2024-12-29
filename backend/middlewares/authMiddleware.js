import jwt from "jsonwebtoken";
import asynchHandler from "./asyncHandler.js";

const authenticate = asynchHandler(async (req, res) => {
  let token;
  token = req.cookies.jwt;

  if (token) {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.userId).select("-password");
    next();
    res.status(200).json({
      message: "",
    });
    try {
    } catch (error) {
      res.status(401);
      throw new Error("Not authroised. Token failure.");
    }
  } else {
    res.status(401);
    throw new Error("Not authorized. Token failed.");
  }
});

// check if user is admin
const authorizeAdmin = (req, res, next) => {
  if (req.user && req.user.isAdmin) {
    next();
  } else {
    res.status(401).send("Not authorized as an Admin.");
  }
};
export { authenticate, authorizeAdmin };
