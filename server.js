const express = require('express');
const bodyParser = require('body-parser');
const { db, connect } = require('./db.js');
const path = require('path');
const dotenv = require('dotenv');
const cors = require('cors');
const passport = require('passport');
const bcrypt = require('bcrypt'); // Import bcrypt
const jwt = require('jsonwebtoken'); // Import jwt

const EmployeeModel = require('./models/employee.model.js');

const app = express();

dotenv.config({ path: path.resolve(__dirname, 'server', '.env') });

connect().then(() => {
    console.log('Connected to database successfully!');

    app.use(bodyParser.json());
    app.use(cors());
    app.use(passport.initialize());

    // Passport configuration here...

    app.post('/login', async (req, res) => {
        try {
            const { email, password } = req.body;

            // Find the employee with the provided email
            const employee = await EmployeeModel.findOne({ email });

            // If no employee is found with the provided email, respond with a 404 status and an error message
            if (!employee) {
                return res.status(404).json({ error: 'Employee not found' });
            }

            // Compare the provided password with the hashed password stored in the database
            const passwordMatch = await bcrypt.compare(password, employee.password);

            // If the passwords don't match, respond with a 401 status and an error message
            if (!passwordMatch) {
                return res.status(401).json({ error: 'Incorrect password' });
            }

            // Generate JWT token
            const token = jwt.sign({ userId: employee._id }, process.env.JWT_SECRET);

            // Respond with token
            res.status(200).json({ token });
        } catch (error) {
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    app.post('/register', async (req, res) => {
        try {
            const { name, email, password } = req.body;

            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Create a new employee with the hashed password
            const newEmployee = await EmployeeModel.create({ name, email, password: hashedPassword });
            res.status(201).json(newEmployee);
        } catch (error) {
            res.status(400).json({ error: 'Failed to create employee.' });
        }
    });

    const PORT = process.env.PORT || 3000;

    app.listen(PORT, () => {
        console.log(`Listening on port ${PORT}`);
    });
}).catch(err => {
    console.error('Error connecting to database:', err);
    process.exit(1);
});
