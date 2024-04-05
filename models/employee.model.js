const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const EmployeeSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    }
}, { timestamps: true });

// Hash password before saving to database
EmployeeSchema.pre("save", async function (next) {
    try {
        // Check if the password is modified, if not, move to the next middleware
        if (!this.isModified("password")) {
            return next();
        }
        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(this.password, salt);
        this.password = hashedPassword;
        next();
    } catch (error) {
        next(error);
    }
});

// Method to generate JWT token for an employee
EmployeeSchema.methods.generateAuthToken = function () {
    const token = jwt.sign({ _id: this._id }, process.env.JWT_SECRET);
    return token;
};

const EmployeeModel = mongoose.model("employee", EmployeeSchema);
module.exports = EmployeeModel;
