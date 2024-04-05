const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const { ExtractJwt } = require('passport-jwt');
const bcrypt = require('bcrypt');
const EmployeeModel = require('./models/employee.model');

passport.use('login', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, async (email, password, done) => {
    try {
        const employee = await EmployeeModel.findOne({ email });

        if (!employee) {
            return done(null, false, { message: 'User not found' });
        }

        const isValidPassword = await bcrypt.compare(password, employee.password);
        if (!isValidPassword) {
            return done(null, false, { message: 'Invalid password' });
        }

        return done(null, employee, { message: 'Logged in successfully' });
    } catch (error) {
        return done(error);
    }
}));

passport.use(new JwtStrategy({
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
}, async (jwtPayload, done) => {
    try {
        const employee = await EmployeeModel.findById(jwtPayload.userId);
        if (!employee) {
            return done(null, false, { message: 'User not found' });
        }
        return done(null, employee);
    } catch (error) {
        return done(error);
    }
}));
