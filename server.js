const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const User = require('./models/user');
const routes = require('./routes');
const { spawn } = require('child_process'); // Import child_process module
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session setup
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: false
}));

// Passport setup
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            const user = await User.findOne({ username });
            if (!user) {
                return done(null, false, { message: 'Incorrect username.' });
            }
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return done(null, false, { message: 'Incorrect password.' });
            }
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// Use routes
app.use('/', routes);

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);

    // Start bot.js
    const botProcess = spawn('node', ['bot.js'], { stdio: 'inherit' });

    botProcess.on('error', (err) => {
        console.error('Failed to start bot.js:', err);
    });

    botProcess.on('exit', (code, signal) => {
        if (code !== null) {
            console.log(`bot.js exited with code ${code}`);
        } else {
            console.log(`bot.js was killed with signal ${signal}`);
        }
    });
});
