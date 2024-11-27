const express = require('express');
const passport = require('passport');
const bcrypt = require('bcrypt');
const User = require('./models/user');
const Training = require('./models/training');
const Promotion = require('./models/promotion');
const bot = require('./bot');
const Placement = require('./models/placement');
const router = express.Router();

// Middleware to check authentication
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

// Middleware to set session roles and check officer status
function setSessionRoles(req) {
    if (req.isAuthenticated() && req.user) {
        const excludedRoles = [
            'Commissioned Officers', 'General Grade Officers', 'Field Grade Officers',
            'Company Grade Officers', 'Enlisted Personnel', 'Senior Non-Commissioned Officers',
            'Non-Commissioned Officers', 'Enlisted', 'Donor', '@everyone'
        ];

        const userRoles = Array.isArray(req.user.roles) ? req.user.roles : [];
        const filteredRoles = userRoles.filter(role => {
            const roleName = role?.name;
            return roleName && !excludedRoles.includes(roleName);
        });

        req.session.roles = filteredRoles;
        req.session.highestRole = filteredRoles.length > 0 ? filteredRoles[0].name : 'No role assigned';
        req.session.highestRoleId = filteredRoles.length > 0 ? filteredRoles[0].id : null;
    }
}

// Middleware to check if user is an officer
function isOfficer(req, res, next) {
    const officerRanks = [
        'Second Lieutenant', 'First Lieutenant', 'Captain', 'Major',
        'Lieutenant Colonel', 'Colonel', 'Brigadier General', 'Major General',
        'Lieutenant General', 'General', 'General of the Army'
    ];

    const hasOfficerRole = req.user.roles && req.user.roles.some(role => 
        officerRanks.includes(role.name)
    );

    if (hasOfficerRole) {
        return next();
    }
    res.redirect('/forms');
}

// Middleware to add user data to all routes
router.use((req, res, next) => {
    res.locals.user = req.user || null;
    res.locals.highestRole = req.session?.highestRole || 'No role assigned';
    res.locals.path = req.path;
    next();
});

// Basic routes
router.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

router.get('/login', (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/dashboard');
    }
    res.render('login', { title: 'Login' });
});

router.post('/login', async (req, res, next) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username }).populate({
            path: 'roles',
            select: 'name id'
        });

        if (!user) {
            return res.status(401).send('Access denied: Username not found.');
        }

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

router.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        res.redirect('/login');
    });
});

// Main page routes
router.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard', { title: 'Dashboard' });
});

router.get('/forms', isAuthenticated, (req, res) => {
    res.render('forms', { title: 'Forms' });
});

router.get('/profile', isAuthenticated, (req, res) => {
    res.render('profile', { title: 'Profile' });
});

// Members route
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
        next(err);
    }
});

// Training routes
router.get('/forms/training', isAuthenticated, (req, res) => {
    res.render('forms/training', { title: 'Training Form' });
});

router.get('/forms/training/verify/:username', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username });
        res.json({ success: !!user });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.post('/forms/training/submit', isAuthenticated, async (req, res) => {
    try {
        const { trainer, trainees, xpAmount } = req.body;
        const needsApproval = xpAmount >= 10;
        
        const traineesList = trainees.split(',').map(t => t.trim());
        const foundTrainees = await User.find({ username: { $in: traineesList } });
        
        if (foundTrainees.length !== traineesList.length) {
            return res.json({ success: false, message: 'One or more trainees not found' });
        }

        const trainingRecord = new Training({
            trainer,
            trainees: traineesList,
            xpAmount,
            needsApproval,
            awarded: !needsApproval
        });
        
        await trainingRecord.save();

        if (!needsApproval) {
            for (const trainee of traineesList) {
                await User.findOneAndUpdate(
                    { username: trainee },
                    { $inc: { xp: xpAmount } }
                );
            }
        }

        res.json({ 
            success: true, 
            needsApproval,
            message: needsApproval ? 
                'Training submitted and pending approval (XP ≥ 10)' : 
                'Training submitted and XP awarded successfully'
        });

    } catch (error) {
        console.error('Training submission error:', error);
        res.status(500).json({ success: false, message: 'Error submitting training' });
    }
});

// Approvals routes
router.get('/forms/approvals', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const trainings = await Training.find({
            needsApproval: true,
            awarded: false
        }).sort({ dateSubmitted: -1 });

        res.render('forms/approvals', {
            title: 'Pending Approvals',
            trainings
        });
    } catch (error) {
        next(error);
    }
});

router.post('/forms/approvals/handle', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const { trainingId, action } = req.body;
        const training = await Training.findById(trainingId);

        if (!training) {
            return res.json({ success: false, message: 'Training not found' });
        }

        if (action === 'approve') {
            training.needsApproval = false;
            training.awarded = true;
            await training.save();

            for (const trainee of training.trainees) {
                await User.findOneAndUpdate(
                    { username: trainee },
                    { $inc: { xp: training.xpAmount } }
                );
            }
        } else if (action === 'discard') {
            await Training.findByIdAndDelete(trainingId);
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error handling approval:', error);
        res.status(500).json({ success: false, message: 'Error handling approval' });
    }
});

// All Trainings routes
router.get('/forms/alltrainings', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = 10;
        
        const [trainings, total] = await Promise.all([
            Training.find({})
                .sort({ dateSubmitted: -1 })
                .skip((page - 1) * limit)
                .limit(limit),
            Training.countDocuments(),
        ]);

        const [totalXPAwarded, pendingApprovals] = await Promise.all([
            Training.aggregate([
                { $match: { awarded: true } },
                { $group: { _id: null, total: { $sum: "$xpAmount" } } }
            ]),
            Training.countDocuments({ needsApproval: true, awarded: false })
        ]);

        res.render('forms/alltrainings', {
            title: 'All Trainings',
            trainings,
            currentPage: page,
            totalPages: Math.ceil(total / limit),
            totalTrainings: total,
            totalXPAwarded: totalXPAwarded[0]?.total || 0,
            pendingApprovals
        });
    } catch (error) {
        next(error);
    }
});

router.post('/forms/alltrainings/filter', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const { search, status, sort, date } = req.body;
        let query = {};

        if (search) {
            query.$or = [
                { trainer: new RegExp(search, 'i') },
                { trainees: new RegExp(search, 'i') }
            ];
        }

        if (status !== 'all') {
            if (status === 'approved') {
                query.awarded = true;
            } else if (status === 'pending') {
                query.needsApproval = true;
                query.awarded = false;
            }
        }

        if (date) {
            const filterDate = new Date(date);
            query.dateSubmitted = {
                $gte: filterDate,
                $lt: new Date(filterDate.getTime() + 24 * 60 * 60 * 1000)
            };
        }

        let sortOption = {};
        switch (sort) {
            case 'oldest':
                sortOption = { dateSubmitted: 1 };
                break;
            case 'xp-high':
                sortOption = { xpAmount: -1 };
                break;
            case 'xp-low':
                sortOption = { xpAmount: 1 };
                break;
            default:
                sortOption = { dateSubmitted: -1 };
        }

        const trainings = await Training.find(query).sort(sortOption);
        res.json({ success: true, trainings });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Error filtering trainings' });
    }
});

router.get('/forms/alltrainings/export', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const trainings = await Training.find({});
        const csv = [
            'Trainer,Trainees,XP Amount,Status,Date',
            ...trainings.map(t => {
                const status = t.awarded ? 'Approved' : (t.needsApproval ? 'Pending' : 'Processing');
                return `${t.trainer},${t.trainees.join(';')},${t.xpAmount},${status},${t.dateSubmitted}`;
            })
        ].join('\n');
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=trainings.csv');
        res.send(csv);
    } catch (error) {
        console.error('Export error:', error);
        res.status(500).send('Error exporting trainings');
    }
});

router.get('/forms/promotion', isAuthenticated, (req, res) => {
    res.render('forms/promotion', {
        title: 'Promotion Form'
    });
});

router.get('/forms/promotion/verify/:username', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username });
        if (user && user.roles && user.roles.length > 0) {
            res.json({
                success: true,
                username: user.username,
                currentRank: user.roles[0].name
            });
        } else {
            res.json({ success: false });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Submit promotion request
router.post('/forms/promotion/submit', isAuthenticated, async (req, res) => {
    try {
        const { username, currentRank, promotionRank, reason, submittedBy } = req.body;

        const promotion = new Promotion({
            username,
            currentRank,
            promotionRank,
            reason,
            submittedBy
        });

        await promotion.save();
        res.json({ success: true });
    } catch (error) {
        console.error('Promotion submission error:', error);
        res.status(500).json({ success: false, message: 'Error submitting promotion' });
    }
});

router.get('/forms/pendingpromotions', isAuthenticated, async (req, res) => { // Added async
    // Check if user has officer rank
    const officerRanks = [
        'Second Lieutenant',
        'First Lieutenant',
        'Captain',
        'Major',
        'Lieutenant Colonel',
        'Colonel',
        'Brigadier General',
        'Major General',
        'Lieutenant General',
        'General',
        'General of the Army'
    ];

    const hasOfficerRole = req.user.roles && req.user.roles.some(role => 
        officerRanks.includes(role.name)
    );

    if (!hasOfficerRole) {
        return res.redirect('/forms');
    }

    try {
        const promotions = await Promotion.find({ status: 'pending' })  // Added await
            .sort({ dateSubmitted: -1 });

        console.log('Found promotions:', promotions); // Debug log

        res.render('forms/pendingpromotions', {
            title: 'Pending Promotions',
            promotions
        });
    } catch (error) {
        console.error('Error fetching pending promotions:', error);
        res.status(500).render('error', {
            title: 'Error',
            error: 'Error fetching promotions'
        });
    }
});
// Handle promotion approval/rejection
router.post('/forms/promotions/handle', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const { promotionId, action } = req.body;
        const promotion = await Promotion.findById(promotionId);

        if (!promotion) {
            return res.json({ success: false, message: 'Promotion request not found' });
        }

        if (action === 'approve') {
            // Get user's Discord ID
            const user = await User.findOne({ username: promotion.username });
            if (!user || !user.discordId) {
                return res.json({ success: false, message: 'User Discord account not found' });
            }

            // Update Discord role
            const roleUpdated = await bot.updateUserRole(user.discordId, promotion.promotionRank);
            if (!roleUpdated) {
                return res.json({ success: false, message: 'Failed to update Discord role' });
            }

            // Update promotion status
            promotion.status = 'approved';
            await promotion.save();

            // Update user's rank in database
            await User.findOneAndUpdate(
                { username: promotion.username },
                { $set: { 'roles.0.name': promotion.promotionRank } }
            );

        } else if (action === 'reject') {
            promotion.status = 'rejected';
            await promotion.save();
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error handling promotion:', error);
        res.status(500).json({ success: false, message: 'Error handling promotion' });
    }
});

router.get('/forms/placement', isAuthenticated, isOfficer, (req, res) => {
    res.render('forms/placement', {
        title: 'Placement Form'
    });
});

// Verify user and get current placement
router.get('/forms/placement/verify/:username', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username });
        if (user) {
            // You might want to add a currentPlacement field to your User model
            // or handle it differently based on your needs
            res.json({
                success: true,
                username: user.username,
                currentPlacement: user.currentPlacement || 'None'
            });
        } else {
            res.json({ success: false });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Submit placement request
router.post('/forms/placement/submit', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const { username, currentPlacement, newPlacement, placementRank, submittedBy } = req.body;

        const placement = new Placement({
            username,
            currentPlacement,
            newPlacement,
            placementRank,
            submittedBy,
            status: 'pending'
        });

        await placement.save();
        res.json({ success: true });
    } catch (error) {
        console.error('Placement submission error:', error);
        res.status(500).json({ success: false, message: 'Error submitting placement' });
    }
});

// Error handling middleware
router.use((err, req, res, next) => {
    console.error('Error:', err.stack);
    res.status(500).render('error', {
        title: 'Error',
        error: 'Something went wrong!'
    });
});

module.exports = router;