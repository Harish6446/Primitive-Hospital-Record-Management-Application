const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const User = require("../DBModel/user.js");
const OTP = require("../DBModel/OTP.js");
const Record = require("../DBModel/records.js");



function encodeData(data) {
    return Buffer.from(data, "utf8").toString("base64");
}

function decodeData(encoded) {
    return Buffer.from(encoded, "base64").toString("utf8");
}

const algorithm = "aes-256-cbc";
const SECRET_KEY = crypto.createHash("sha256").update("medical-secret").digest();

function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, SECRET_KEY, iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return { encryptedData: encrypted, iv: iv.toString("hex") };
}

function decrypt(encrypted, iv) {
    const decipher = crypto.createDecipheriv(
        algorithm,
        SECRET_KEY,
        Buffer.from(iv, "hex")
    );
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
}

function signData(data) {
    return crypto
        .createHmac("sha256", "sign-secret")
        .update(data)
        .digest("hex");
}


const transporter = nodemailer.createTransport({
    service: 'gmail', 
    auth: {
        user: 'medsafe6437@gmail.com', 
        pass: 'rzgdvnprcmsokxgw'
    }
});



const register = async (req, res) => {
    try{
        const {email, username, password, role} = req.body;

        if (!username || !password || !role) {
            return res.status(400).json({ message: "Required fields missing" });
        }

        if (await User.findOne({username})){
            return res.status(400).json({message: "Username already exists"});
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

const login = async (req, res) => {
    try{
        const {username, password} = req.body;
        const user = await User.findOne({username});

        if (!user){
            return res.status(404).json({message: `User with username ${username} not found`});
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch){
            res.status(500).json({message: "Invalid Credentials"});
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        await OTP.deleteMany({ username });
        
        await OTP.create({
            username, 
            otp
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
                username
            });
        } else {
            return res.status(200).json({
                success: true, 
                message: "OTP Generated", 
                username, 
                otp
            });
        }

    } catch (err) {
        res.status(500).json({message: `${err}`});
    }
};

const verifyOtp = async (req, res) => {
    try{
        const {username, otp} = req.body;

        const otpRecord = await OTP.findOne({username, otp});
        if (!otpRecord) {
            await OTP.deleteMany({username});
            return res.status(400).json({message: "Invalid username or expired OTP, returning to login page"});
        }

        await OTP.deleteOne({_id: otpRecord._id});

        const user = await User.findOne({username});

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

const createRecord = async (req, res) => {
    try {
        const {patientName, medicalData} = req.body;
        const encoded = encodeData(medicalData);
        const {encryptedData, iv} = encrypt(encoded);
        const signature = signData(encryptedData);
        
        const patient = await User.findOne({patientName});
        if (patient){
            const encoded = encodeData(medicalData);
            const {encryptedData, iv} = encrypt(encoded);
            const signature = signData(encryptedData);
        
            await Record.create({
                patientName,
                encryptedData,
                iv,
                signature,
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

const viewRecord = async (req, res) => {
    try {
        const {patientName} = req.body;

        const record = await Record.find({patientName});
        const output = record.map(r => {
            const decrypted = decrypt(r.encryptedData, r.iv);
            const decoded = decodeData(decrypted);

            return {
                patientName: r.patientName, 
                medicalData: decoded, 
                createdBy: r.createdBy
            };
        });

        return res.status(200).json(output);
    } catch(err) {
        res.status(500).json({message: `${err}`});
    }
}

const myRecord = async (req, res) => {
    try {
        const patientName = req.user.username;

        const record = await Record.find({patientName});

        const output = record.map(r => {
            const decrypted = decrypt(r.encryptedData, r.iv);
            const decoded = decodeData(decrypted);

            return {
                patientName: r.patientName, 
                medicalData: decoded, 
                createdBy: r.createdBy
            };
        });

        return res.status(200).json(output);
    } catch(err) {
       res.status(500).json({message: `${err}`});
    }
}


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

        user.password = hashedPassword;

        await user.save();

        return res.status(200).json({message: `Password for ${username} has been changed`});
    } catch(err) {
        return res.status(500).json({message: `${err}`});
    }
}


// Testing Functions

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
