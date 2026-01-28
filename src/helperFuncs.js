const bcrypt = require("bcrypt");
const crypto = require("crypto");
const nodemailer = require("nodemailer");


function encodeData(data) {
    return Buffer.from(data, "utf8").toString("base64");
}

function decodeData(encoded) {
    return Buffer.from(encoded, "base64").toString("utf8");
}

const algorithm = "aes-256-cbc";


const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {modulusLength: 2049});


function encrypt(text, dynamicKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, dynamicKey, iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return { encryptedData: encrypted, iv: iv.toString("hex") };
}


function decrypt(encrypted, iv, dynamicKey) {
    const decipher = crypto.createDecipheriv(algorithm, dynamicKey, Buffer.from(iv, "hex"));
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
}


function wrapKey(symmetricKey){
    return crypto.publicEncrypt(publicKey, symmetricKey).toString("base64");
}


function unwrapKey(wrappedKey){
    return crypto.privateDecrypt(privateKey, Buffer.from(wrappedKey, "base64"));
}


function signData(data) {
    return crypto
        .createHmac("sha256", "sign-secret")
        .update(data)
        .digest("hex");
}


function verifySignature(data, signature) {
    const expectedSignature = crypto.createHmac("sha256", "sign-secret").update(data).digest("hex");
    return signature === expectedSignature;
}


const transporter = nodemailer.createTransport({
    service: 'gmail', 
    auth: {
        user: 'medsafe6437@gmail.com', 
        pass: 'rzgdvnprcmsokxgw'
    }
});


module.exports = {encodeData, decodeData, encrypt, decrypt, signData, verifySignature, transporter, wrapKey, unwrapKey};
