const mongoose = require("mongoose");

const recordScheme = new mongoose.Schema(
    {
        patientName: {
            type: String, 
            required: true
        }, 

        encryptedData: {
            type: String, 
            required: true
        }, 

        iv: {
            type: String, 
            required: true
        }, 

        signature: {
            type: String, 
            required: true
        }, 

        createdBy: {
            type: String, 
            required: true
        }
    }, 
    {timestamps: true, }
);

module.exports = mongoose.model("Record", recordScheme);
