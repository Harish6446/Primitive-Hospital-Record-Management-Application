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

    role: {
        type: String, 
        required: false, 
        enum: ["doctor", "nurse", "patient"]
    }, 

    createdAt: {
        type: Date,
        default: Date.now,
        expires: 300 // auto-delete after 5 minutes
    }
});


module.exports = mongoose.model("OTP", otpSchema);
