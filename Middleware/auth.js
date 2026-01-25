const jwt = require("jsonwebtoken");
const {accessControlMatrix} = require("../config/RBACMatrix");

module.exports = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: "Token missing" });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;

        const allowedRules = accessControlMatrix[req.path];

        if (allowedRules && !allowedRules.includes(req.user.role)){
            return res.status(403).json({
                message: `Access denied: ${req.user.role}s cannot access this resource.`
            });
        }
        next();
    } catch (err) {
        return res.status(401).json({ message: "Invalid token" });
    }
};
