const express = require("express");
const dotenv = require("dotenv").config();

const dbConnect = require("../config/dbConnect.js");
const authRoutes = require("./authRoutes.js");
const { eventNames } = require("../DBModel/user.js");

dbConnect();

const app = express();
app.use(express.json());

app.use(express.static("Assets"));

app.use("/api/auth", authRoutes);


const PORT = process.env.PORT || 7001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});