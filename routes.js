const express = require('express');
const passport = require('passport');
const bcrypt = require('bcrypt');
const User = require('./models/user');
const router = express.Router();

// Middleware to set session roles and highest role
function setSessionRoles(req) {
    if (req.isAuthenticated()) {
        const excludedRoles = [
            'Commissioned Officers', 'General Grade Officers', 'Field Grade Officers',
            'Company Grade Officers', 'Enlisted Personnel', 'Senior Non-Commissioned Officers',
            'Non-Commissioned Officers', 'Enlisted Airmen'
        ];

        // Log all roles from the user object
        console.log(`All roles for user ${req.user.username}: ${req.user.roles.join(', ')}`);

        // Filter out excluded roles
        const userRoles = req.user.roles.filter(role => !excludedRoles.includes(role));

        // Log filtered roles
        console.log(`Filtered roles for user ${req.user.username}: ${userRoles.join(', ')}`);

        // Determine the highest role
        const highestRole = userRoles.length > 0 ? userRoles[0] : null; // Assuming roles are ordered by importance

        // Store roles and highest role in session
        req.session.roles = userRoles;
        req.session.highestRole = highestRole;

        // Console log the highest role
        console.log(`Highest role for user ${req.user.username}: ${highestRole}`);
    }
}

router.get('/', (req, res) => {
    res.render('login'); // Render the login.ejs view
});

// Render login page
router.get('/login', (req, res) => {
    res.render('login');
});

// Handle login
router.post('/login', async (req, res, next) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user) {
            // No user found with the given username
            return res.status(401).send('Access denied: Username not found.');
        }

        if (!user.password) {
            // New user, no password set
            const hashedPassword = await bcrypt.hash(password, 10);
            user.password = hashedPassword;
            await user.save();
            return res.redirect('/dashboard');
        }

        // Existing user, verify password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).send('Access denied: Incorrect password.');
        }

        // Authenticate user
        req.login(user, (err) => {
            if (err) return next(err);

            // Set session roles and highest role
            setSessionRoles(req);

            return res.redirect('/dashboard');
        });

    } catch (err) {
        return next(err);
    }
});

// Render dashboard page
router.get('/dashboard', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }
    res.render('dashboard', {
        highestRole: req.session.highestRole || 'No role assigned'
    });
});

// Render forms page
router.get('/forms', (req, res) => {
    res.render('forms');
});

// Render members page
router.get('/members', (req, res) => {
    res.render('members');
});

// Render profile page
router.get('/profile', (req, res) => {
    res.render('profile');
});

// Add more routes as needed

module.exports = router;
