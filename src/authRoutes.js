const express = require("express");

const {register, login, getdb, verifyOtp, verifyOtp2, getotp, getrecord, createRecord, viewRecord, myRecord, change, changePassword} = require("./authController.js");
const auth = require("../Middleware/auth.js");

const Router = express.Router();

Router.post("/register", register);
Router.post("/login", login);
Router.post("/verifyOtp", verifyOtp);
Router.post("/verifyOtp2", verifyOtp2);
Router.post("/createRecord", auth, createRecord);
Router.post("/viewRecord", auth, viewRecord);
Router.get("/myRecord", auth, myRecord);
Router.post("/change", change);
Router.post("/changePassword", auth, changePassword)

// Testing routes
Router.get("/getdb", getdb);
Router.get("/getotp", getotp);
Router.get("/getrecord", getrecord);

module.exports = Router;
