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
        console.log(`All roles for user ${req.user.username}: ${req.user.roles.map(role => role.name).join(', ')}`);

        // Filter out excluded roles
        const userRoles = req.user.roles.filter(role => !excludedRoles.includes(role.name));

        // Log filtered roles
        console.log(`Filtered roles for user ${req.user.username}: ${userRoles.map(role => role.name).join(', ')}`);

        // Determine the highest role
        const highestRole = userRoles.length > 0 ? userRoles[0] : null; // Assuming roles are ordered by importance

        // Store roles and highest role in session
        req.session.roles = userRoles;
        req.session.highestRole = highestRole ? highestRole.name : null;
        req.session.highestRoleId = highestRole ? highestRole.id : null;

        // Console log the highest role
        console.log(`Highest role for user ${req.user.username}: ${req.session.highestRole}`);
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
        const user = await User.findOne({ username }).populate('roles');

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

    // Define a mapping from role IDs to image filenames
    const roleImageMap = {
        '1302347816496271472': 'first-sergeant1.png',
        '1302347762687414394': 'first-sergeant2.png',
        '1302347657372504104': 'first-sergeant3.png',
        // Add other role IDs and their corresponding images here
    };

    res.render('dashboard', {
        highestRole: req.session.highestRole || 'No role assigned',
        roleImageMap: roleImageMap,
        highestRoleId: req.session.highestRoleId
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
