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
    if (req.isAuthenticated() && req.user) {
        const excludedRoles = [
            'Commissioned Officers', 'General Grade Officers', 'Field Grade Officers',
            'Company Grade Officers', 'Enlisted Personnel', 'Senior Non-Commissioned Officers',
            'Non-Commissioned Officers', 'Enlisted', 'Donor', '@everyone'
        ];

        // Ensure roles exist and are in the correct format
        const userRoles = Array.isArray(req.user.roles) ? req.user.roles : [];

        // Filter out excluded roles and ensure role has a name property
        const filteredRoles = userRoles.filter(role => {
            const roleName = role?.name;
            return roleName && !excludedRoles.includes(roleName);
        });

        // Log all roles from the user object
        console.log(`All roles for user ${req.user.username}:`, userRoles.map(role => role?.name).filter(Boolean).join(', '));
        console.log(`Filtered roles for user ${req.user.username}:`, filteredRoles.map(role => role.name).join(', '));

        // Determine the highest role
        const highestRole = filteredRoles.length > 0 ? filteredRoles[0] : null;

        // Store roles and highest role in session
        req.session.roles = filteredRoles;
        req.session.highestRole = highestRole ? highestRole.name : 'No role assigned';
        req.session.highestRoleId = highestRole ? highestRole.id : null;

        // Console log the highest role
        console.log(`Highest role for user ${req.user.username}:`, req.session.highestRole);
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
        const user = await User.findOne({ username })
            .populate({
                path: 'roles',
                select: 'name id'
            });

        if (!user) {
            return res.status(401).send('Access denied: Username not found.');
        }

        // Log user data for debugging
        console.log('Found user:', {
            username: user.username,
            roles: JSON.stringify(user.roles)
        });

        if (!user.password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            user.password = hashedPassword;
            await user.save();
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).send('Access denied: Incorrect password.');
        }

        req.login(user, (err) => {
            if (err) return next(err);
            setSessionRoles(req);
            return res.redirect('/dashboard');
        });

    } catch (err) {
        console.error('Login error:', err);
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
            .populate({
                path: 'roles',
                select: 'name id'
            });

        const formattedMembers = members.map(member => {
            const userRoles = (member.roles || []).filter(role => {
                const excludedRoles = [
                    'Commissioned Officers', 'General Grade Officers', 'Field Grade Officers',
                    'Company Grade Officers', 'Enlisted Personnel', 'Senior Non-Commissioned Officers',
                    'Non-Commissioned Officers', 'Enlisted', 'Donor', '@everyone'
                ];
                return role?.name && !excludedRoles.includes(role.name);
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
        console.error('Members error:', err);
        next(err);
    }
});

// Render profile page
router.get('/profile', isAuthenticated, (req, res) => {
    res.render('profile', {
        title: 'Profile'
    });
});

<<<<<<< HEAD
// Find user API endpoint
router.get('/api/users/:username', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username });
        if (user) {
            res.json({ success: true });
        } else {
            res.json({ success: false });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Submit training API endpoint
router.post('/api/training/submit', async (req, res) => {
    try {
        const { trainer, trainees, xpAmount } = req.body;
        const needsApproval = xpAmount >= 10;

        // Create training record
        const training = new Training({
            trainer,
            trainees,
            xpAmount,
            needsApproval,
            awarded: !needsApproval // Auto award if doesn't need approval
        });
        await training.save();

        // If doesn't need approval, update XP for trainees
        if (!needsApproval) {
            for (const trainee of trainees) {
                await User.findOneAndUpdate(
                    { username: trainee },
                    { $inc: { xp: xpAmount } }
                );
            }
        }

        res.json({ 
            success: true, 
            needsApproval,
            message: needsApproval ? 'Training submitted for approval' : 'Training submitted and XP awarded'
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

=======
// Training Form route
router.get('/forms/training', isAuthenticated, (req, res) => {
    res.render('forms/training', {
        title: 'Training Form'
    });
});

// Promotion Form route
router.get('/forms/promotion', isAuthenticated, (req, res) => {
    res.render('forms/promotion', {
        title: 'Promotion Form'
    });
});

// Award Form route
router.get('/forms/award', isAuthenticated, (req, res) => {
    res.render('forms/award', {
        title: 'Award Form'
    });
});

>>>>>>> 5e15f3df39d369e322c1da93f54166733784b6e9
// Error handling middleware
router.use((err, req, res, next) => {
    console.error('Error:', err.stack);
    res.status(500).render('error', {
        title: 'Error',
        error: 'Something went wrong!'
    });
});

module.exports = router;