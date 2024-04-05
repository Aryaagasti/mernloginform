const mongoose = require('mongoose');
require('dotenv').config();

// Define the MongoDB connection URL
// const mongoURL = process.env.MONGODB_URL_LOCAL // Replace 'mydatabase' with your database name
 mongoose.connect("mongodb://127.0.0.1:27017/employee")
 

//  const mongoURL = process.env.MONGODB_URI;

// Set up MongoDB connection
async function connect() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log("Connected to MongoDB server");
    } catch (error) {
        console.error("Error connecting to MongoDB:", error);
    }
}
// Get the default connection
// Mongoose maintains a default connection object representing the MongoDB connection.
const db = mongoose.connection;

// Define event listeners for database connection

db.on('connected', () => {
    console.log('Connected to MongoDB server');
});

db.on('error', (err) => {
    console.error('MongoDB connection error:', err);
});

db.on('disconnected', () => {
    console.log('MongoDB disconnected');
});

// Export the database connection
module.exports = {db,connect};

