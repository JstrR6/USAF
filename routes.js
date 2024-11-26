const express = require('express');
const passport = require('passport');
const bcrypt = require('bcrypt');
const User = require('./models/user');
const router = express.Router();

// Middleware to check authentication
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

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

// Middleware to add user data to all routes
router.use((req, res, next) => {
    res.locals.user = req.user || null;
    res.locals.highestRole = req.session?.highestRole || 'No role assigned';
    res.locals.path = req.path;
    next();
});

router.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

// Render login page
router.get('/login', (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/dashboard');
    }
    res.render('login', {
        title: 'Login'
    });
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

// Logout route
router.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        res.redirect('/login');
    });
});

// Render dashboard page
router.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard', {
        title: 'Dashboard'
    });
});

// Render forms page
router.get('/forms', isAuthenticated, (req, res) => {
    res.render('forms', {
        title: 'Forms'
    });
});

// Render members page
router.get('/members', isAuthenticated, async (req, res, next) => {
    try {
        const members = await User.find({})
            .select('username roles xp')
            .populate('roles');

        const formattedMembers = members.map(member => {
            const userRoles = member.roles.filter(role => {
                const excludedRoles = [
                    'Commissioned Officers', 'General Grade Officers', 'Field Grade Officers',
                    'Company Grade Officers', 'Enlisted Personnel', 'Senior Non-Commissioned Officers',
                    'Non-Commissioned Officers', 'Enlisted Airmen'
                ];
                return !excludedRoles.includes(role.name);
            });

            return {
                username: member.username,
                highestRole: userRoles.length > 0 ? userRoles[0].name : 'No role assigned',
                xp: member.xp || 0
            };
        });

        res.render('members', {
            title: 'Members',
            members: formattedMembers
        });
    } catch (err) {
        next(err);
    }
});

// Render profile page
router.get('/profile', isAuthenticated, (req, res) => {
    res.render('profile', {
        title: 'Profile'
    });
});

// Error handling middleware
router.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).render('error', {
        title: 'Error',
        error: 'Something went wrong!'
    });
});

module.exports = router;