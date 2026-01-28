const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const User = require("../DBModel/user.js");
const OTP = require("../DBModel/OTP.js");
const Record = require("../DBModel/records.js");
const {encodeData, decodeData, encrypt, decrypt, signData, verifySignature, transporter, wrapKey, unwrapKey} = require("./helperFuncs.js");


// Registering a new User
const register = async (req, res) => {
    try{
        const {email, username, password, role} = req.body;

        if (!username || !password || !role) {
            return res.status(400).json({ message: "Required fields missing" });
        }

        if (await User.findOne({username: username, role: role})){
            return res.status(400).json({message: "Username with this role already exists"});
        }

        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(password, salt);
        
        if (email){
            newUser = new User({email: email, username: username, password: hashedPassword, role: role});
            await newUser.save();
        } else {
            newUser = new User({username: username, password: hashedPassword, role: role});
            await newUser.save();
        }

        res.status(201).json({message: `User registered with username ${username}`});
    } catch (err) {
        res.status(500).json({message: `${err}`});
    }
};



// Logging in already existing user
const login = async (req, res) => {
    try{
        const {username, password, role} = req.body;
        const user = await User.findOne({username, role});

        if (!user){
            return res.status(404).json({message: `${role} with username ${username} not found`});
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch){
            res.status(500).json({message: "Invalid Credentials"});
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        await OTP.deleteMany({ username });
        
        await OTP.create({
            username: username, 
            otp: otp, 
            role: role
        });
        
        if (user.email){
            await transporter.sendMail({
                from: 'medsafe6437@gmail.com', 
                to: user.email, 
                subject: `OTP Verification for ${username}`, 
                text: `Your OTP is ${otp}`
            });
            return res.status(200).json({
                success: true, 
                message: "OTP Generated", 
                username, 
                role
            });
        } else {
            return res.status(200).json({
                success: true, 
                message: "OTP Generated", 
                username, 
                role, 
                otp
            });
        }

    } catch (err) {
        res.status(500).json({message: `${err}`});
    }
};



// Verifying OTP for 2-Factor authentication during login
const verifyOtp = async (req, res) => {
    try{
        const {username, role, otp} = req.body;

        const otpRecord = await OTP.findOne({username, role, otp});
        if (!otpRecord) {
            await OTP.deleteMany({username});
            return res.status(400).json({message: "Invalid username or expired OTP, returning to login page"});
        }

        await OTP.deleteOne({_id: otpRecord._id});

        const user = await User.findOne({username, role});

        const token = jwt.sign(
            {id: user._id, username: user.username, role: user.role}, 
            process.env.JWT_SECRET, 
            {expiresIn: "1h"}
        );

        res.json({
            success: true, 
            username: user.username, 
            token
        });
    } catch (err) {
        res.status(500).json({message: `${err}`});
    }
};



// Verifying OTP for 2-Factor authentication during password change
const verifyOtp2 = async (req, res) => {
    try {
        const {username, otp} = req.body;

        const otpRecord = await OTP.findOne({username, otp});
        if (!otpRecord) {
            await OTP.deleteMany({username});
            return res.status(400).json({message: "Invalid username or expired OTP, returning to login page"});
        }

        await OTP.deleteOne({_id: otpRecord._id});

        const user = await User.findOne({username});

        const token = jwt.sign(
            {username, purpose: "password_reset"}, 
            process.env.JWT_SECRET, 
            {expiresIn: "10m"}
        );

        res.json({
            success: true, 
            username: user.username, 
            token
        });
    } catch(err) {
        console.log("Cannot oonnect to Server");
    }
};



// Create a new medical record for a existing patient
const createRecord = async (req, res) => {
    try {
        const {patientName, medicalData} = req.body;
        
        const patient = await User.findOne({username: patientName, role: 'patient'});
        if (patient){
            const key = crypto.randomBytes(32);
            const encoded = encodeData(medicalData);
            const {encryptedData, iv} = encrypt(encoded, key);
            const wrappedKey = wrapKey(key);
            const signature = signData(encryptedData);
        
            await Record.create({
                patientName,
                encryptedData,
                wrappedKey, 
                iv,
                signature: signature,
                createdBy: req.user.username
            });

            res.status(200).json({ message: "Record created" });
        } else {
            res.status(300).json({message: `Patient ${patientName} doen not exist`});
        }
    } catch(err) {
        res.status(500).json({message: `${err}`});
    }
};



// View medical records of existing patients
const viewRecord = async (req, res) => {
    try {
        const {patientName} = req.body;

        const record = await Record.find({patientName});
        const output = record.map(r => {
            const isAuthentic = verifySignature(r.encryptedData, r.signature);
            if (!isAuthentic){
                return {
                    patientName: r.patientName, 
                    medicalData: "ERROR: Data tampering detected! integrity check failed", 
                    createdBy: r.createdBy, 
                    integrityStatus: "Compromised"
                };
            }

            const key = unwrapKey(r.wrappedKey);
            const decrypted = decrypt(r.encryptedData, r.iv, key);
            const decoded = decodeData(decrypted);
            return {
                patientName: r.patientName, 
                medicalData: decoded, 
                createdBy: r.createdBy, 
                integrityStatus: "Verified"
            };
        });

        return res.status(200).json(output);
    } catch(err) {
        res.status(500).json({message: `${err}`});
    }
}



// Patient viewing his record
const myRecord = async (req, res) => {
    try {
        const patientName = req.user.username;

        const record = await Record.find({patientName});

        const output = record.map(r => {
            const isAuthentic = verifySignature(r.encryptedData, r.signature);
            if (!isAuthentic){
                return {
                    patientName: r.patientName, 
                    medicalData: "ERROR: Record tampering detected, integrity check failed", 
                    createdBy: r.createdBy, 
                    integrityStatus: "Compromised"
                };
            }

            const key = unwrapKey(r.wrappedKey);
            const decrypted = decrypt(r.encryptedData, r.iv, key);
            const decoded = decodeData(decrypted);
            return {
                patientName: r.patientName, 
                medicalData: decoded, 
                createdBy: r.createdBy, 
                integrityStatus: "Verified"
            };
        });

        return res.status(200).json(output);
    } catch(err) {
       res.status(500).json({message: `${err}`});
    }
}



// Password Change process upto sending OTP
const change = async (req, res) => {
    try {
        const {email} = req.body;

        const user = await User.findOne({email});

        if (!user){
            return res.status(404).json({message: `User with email ${email} not found`});
        }

        const username = user.username;
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        await OTP.deleteMany({username});
        
        await OTP.create({
            username, 
            otp
        });

        await transporter.sendMail({
            from: 'medsafe6437@gmail.com', 
            to: user.email, 
            subject: "Password Reset OTP", 
            text: `Your OTP is ${otp}`
        });
        return res.status(200).json({
            success: true, 
            message: "OTP Generated", 
            username
        });
    } catch(err) {
        res.status(500).json({message: `${err}`});
    }
}



// Password changing process - After verifying OTP
const changePassword = async (req, res) => {
    try {
        const {newPass} = req.body;
        const username = req.user.username;

        if (!newPass) {
            return res.status(400).json({ message: "New password required" });
        }

        const user = await User.findOne({username});
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(newPass, salt);

        const result = await User.updateMany(
            { username: username }, 
            { $set: { password: hashedPassword } }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ message: "No user entries found to update" });
        }

        return res.status(200).json({message: `Password updated for ${result.modifiedCount} entries under username: ${username}`});
    } catch(err) {
        return res.status(500).json({message: `${err}`});
    }
}



// Testing Functions during development
const getdb = async (req, res) => {
    try{
        const users = await User.find();

        res.status(200).json({
            success: true,
            count: users.length,
            data: users
        });
    } catch (err){
        res.status(500).json({message: `${err}`});
    }
};

const getotp = async (req, res) => {
    try{
        const otps = await OTP.find();

        res.status(200).json({
            success: true, 
            count: otps.length, 
            data: otps
        });
    } catch (err) {
        res.status(500).json({message: `${err}`});
    }
};

const getrecord = async (req, res) => {
    try{
        const records = await Record.find();

        res.status(200).json({
            success: true, 
            count: records.length, 
            data: records
        })
    } catch (err) {
        res.status(500).json({message: `${err}`});
    }
}

module.exports = {register, login, getdb, verifyOtp, verifyOtp2, getotp, getrecord, createRecord, viewRecord, myRecord, change, changePassword};
