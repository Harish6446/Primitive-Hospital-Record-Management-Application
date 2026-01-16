const mongoose = require("mongoose");

const otpSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        index: true
    },

    otp: {
        type: String,
        required: true
    },

    createdAt: {
        type: Date,
        default: Date.now,
        expires: 300 // auto-delete after 5 minutes
    }
});


module.exports = mongoose.model("OTP", otpSchema);