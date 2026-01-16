const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
    {   
        email: {
            type: String
        }, 

        username: {
            type: String, 
            required: true, 
            unique: true
        }, 

        password: {
            type: String, 
            required: true,
        }, 

        role: {
            type: String, 
            required: true, 
            enum: ["doctor", "nurse", "patient"]
        }
    }, 
    {timestamps: true, }
);


module.exports = mongoose.model("User", userSchema);
