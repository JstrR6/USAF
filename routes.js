const express = require('express');
const passport = require('passport');
const bcrypt = require('bcrypt');
const User = require('./models/user');
const Training = require('./models/training');
const Promotion = require('./models/promotion');
const bot = require('./bot');
const { updateUserRole } = require('./bot');
const Placement = require('./models/placement');
const Unit = require('./models/unit');
const Award = require('./models/award');
const UserNote = require('./models/usernote');
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


// XP thresholds for ranks
const XP_THRESHOLDS = [
    { xp: 0, rank: 'Citizen' },
    { xp: 1, rank: 'Private' },
    { xp: 10, rank: 'Private First Class' },
    { xp: 25, rank: 'Specialist' },
    { xp: 40, rank: 'Corporal' },
    { xp: 60, rank: 'Sergeant' },
    { xp: 80, rank: 'Staff Sergeant' },
    { xp: 100, rank: 'Sergeant First Class' },
    { xp: 125, rank: 'Master Sergeant' },
    { xp: 150, rank: 'First Sergeant' },
    { xp: 175, rank: 'Sergeant Major' },
    { xp: 250, rank: 'Command Sergeant Major' }
];

// Calculate progress towards next rank
function calculateProgress(currentXP) {
    const currentRank = XP_THRESHOLDS.find(threshold => currentXP >= threshold.xp);
    const nextRank = XP_THRESHOLDS.find(threshold => threshold.xp > currentXP);
    if (!nextRank) return 100;

    const progress = ((currentXP - currentRank.xp) / (nextRank.xp - currentRank.xp)) * 100;
    return Math.min(Math.max(progress, 0), 100);
}

// Main page routes
router.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard', { title: 'Dashboard' });
    try {
        const user = await User.findById(req.session.userId);
        if (!user) return res.redirect('/login');

        const nextRank = XP_THRESHOLDS.find(threshold => threshold.xp > user.xp);
        const nextRankXP = nextRank ? nextRank.xp : user.xp;

        res.render('dashboard', {
            user,
            nextRankXP,
            calculateProgress: calculateProgress(user.xp)
        });
    } catch (error) {
        console.error('Error loading dashboard:', error);
        res.redirect('/login');
    }
});

router.get('/forms', isAuthenticated, (req, res) => {
    res.render('forms', { title: 'Forms' });
});

router.get('/profile', isAuthenticated, async (req, res) => {
    try {
        // Get user data with roles
        const user = await User.findById(req.user._id)
            .populate({
                path: 'roles',
                select: 'name id'
            });

        // Get current placement
        const currentPlacement = await Placement.findOne(
            { username: user.username, status: 'approved' },
            {},
            { sort: { 'dateSubmitted': -1 } }
        );

        // Get all training records
        const trainingsAsTrainer = await Training.find({
            trainer: user.username,
            awarded: true
        }).sort({ dateSubmitted: -1 });

        const trainingsAsTrainee = await Training.find({
            trainees: user.username,
            awarded: true
        }).sort({ dateSubmitted: -1 });

        // Get promotion history
        const promotions = await Promotion.find({
            username: user.username,
            status: 'approved'
        }).sort({ dateSubmitted: -1 });

        // Get awards with full details
        const awards = await Award.find({
            username: user.username,
            status: 'approved'
        }).sort({ dateSubmitted: -1 });

        // Calculate award counts
        const awardCounts = {};
        let totalAwards = 0;
        awards.forEach(award => {
            awardCounts[award.award] = (awardCounts[award.award] || 0) + 1;
            totalAwards++;
        });

        // Filter roles
        const excludedRoles = [
            'Commissioned Officers', 'General Grade Officers', 'Field Grade Officers',
            'Company Grade Officers', 'Enlisted Personnel', 'Senior Non-Commissioned Officers',
            'Non-Commissioned Officers', 'Enlisted', 'Donor', '@everyone'
        ];

        const filteredRoles = user.roles.filter(role => 
            role?.name && !excludedRoles.includes(role.name)
        );

        const currentRank = filteredRoles.length > 0 ? filteredRoles[0].name : 'No Rank';

        // Calculate training statistics
        const trainingStats = {
            totalAsTrainer: trainingsAsTrainer.length,
            totalAsTrainee: trainingsAsTrainee.length,
            xpEarned: trainingsAsTrainee.reduce((sum, t) => sum + t.xpAmount, 0)
        };

        res.render('profile', {
            title: 'Profile',
            user,
            currentRank,
            placement: currentPlacement,
            awards,
            awardCounts,
            totalAwards,
            promotions,
            trainingStats
        });
    } catch (error) {
        console.error('Profile error:', error);
        next(error);
    }
});

// Basic - Show all members
router.get('/members', isAuthenticated, async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = 10;
        const skip = (page - 1) * limit;

        // Fetch total member count
        const totalMembers = await User.countDocuments();

        // Fetch all members with pagination
        const users = await User.find({})
            .skip(skip)
            .limit(limit)
            .populate({
                path: 'roles',
                select: 'name'
            });

        // Fetch the latest placements for all members
        const placements = await Placement.aggregate([
            { $match: { status: 'approved' } },
            { $sort: { dateSubmitted: -1 } },
            { $group: { _id: '$username', latestPlacement: { $first: '$newPlacement' } } }
        ]);

        // Create a map of placements for quick lookup
        const placementMap = placements.reduce((map, placement) => {
            map[placement._id] = placement.latestPlacement;
            return map;
        }, {});

        // Format members with placement data
        const formattedMembers = users.map(user => ({
            username: user.username,
            highestRole: (user.roles || [])[0]?.name || 'No role assigned',
            xp: user.xp || 0,
            placement: placementMap[user.username] || 'Not Assigned'
        }));

        const officerRanks = [
            'Second Lieutenant', 'First Lieutenant', 'Captain', 'Major',
            'Lieutenant Colonel', 'Colonel', 'Brigadier General', 'Major General',
            'Lieutenant General', 'General', 'General of the Army'
        ];

        const isOfficer = req.user.roles.some(role => officerRanks.includes(role.name));

        res.render('members', {
            title: 'Members',
            members: formattedMembers,
            isOfficer,
            currentPage: page,
            totalPages: Math.ceil(totalMembers / limit),
            officerRanks // Pass ranks for filter dropdown
        });
    } catch (err) {
        console.error('Error loading members:', err);
        next(err);
    }
});

// Add filter route
router.get('/members/filter', isAuthenticated, async (req, res) => {
    try {
        const { username, rank, specificRank, placement, status } = req.query;
        let query = {};

        // Username filter
        if (username) {
            query.username = { $regex: username, $options: 'i' }; // Case-insensitive search
        }

        // Specific rank filter
        if (specificRank) {
            query['roles.name'] = specificRank;
        }

        // Status filter (using last login)
        if (status) {
            const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
            query.lastLogin = status === 'active'
                ? { $gte: thirtyDaysAgo }
                : { $lt: thirtyDaysAgo };
        }

        // Fetch users based on the query
        const users = await User.find(query).populate({
            path: 'roles',
            select: 'name'
        });

        // Fetch latest placements for all users
        const placements = await Placement.aggregate([
            { $match: { status: 'approved' } },
            { $sort: { dateSubmitted: -1 } },
            { $group: { _id: '$username', latestPlacement: { $first: '$newPlacement' } } }
        ]);

        const placementMap = placements.reduce((map, placement) => {
            map[placement._id] = placement.latestPlacement;
            return map;
        }, {});

        // Filter users by placement if a placement filter is applied
        let filteredUsers = users;
        if (placement) {
            filteredUsers = users.filter(user => {
                const userPlacement = placementMap[user.username] || 'Not Assigned';
                return userPlacement === placement;
            });
        }

        // Format users with their placements
        const formattedUsers = filteredUsers.map(user => ({
            username: user.username,
            highestRole: user.roles?.[0]?.name || 'No role assigned',
            xp: user.xp || 0,
            placement: placementMap[user.username] || 'Not Assigned'
        }));

        // Rank sorting
        if (rank === 'asc' || rank === 'desc') {
            const rankOrder = [
                'Citizen', 'Private', 'Private First Class', 'Specialist',
                'Corporal', 'Sergeant', 'Staff Sergeant', 'Sergeant First Class',
                'Master Sergeant', 'First Sergeant', 'Sergeant Major',
                'Command Sergeant Major', 'Sergeant Major of the Army',
                'Second Lieutenant', 'First Lieutenant', 'Captain', 'Major',
                'Lieutenant Colonel', 'Colonel', 'Brigadier General',
                'Major General', 'Lieutenant General', 'General',
                'General of the Army'
            ];

            formattedUsers.sort((a, b) => {
                const aRank = rankOrder.indexOf(a.highestRole);
                const bRank = rankOrder.indexOf(b.highestRole);
                return rank === 'asc' ? aRank - bRank : bRank - aRank;
            });
        }

        res.json({ success: true, members: formattedUsers });
    } catch (error) {
        console.error('Error fetching members with placements:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get all unique placements and ranks
router.get('/members/filter-options', isAuthenticated, async (req, res) => {
    try {
        const units = await Unit.find().distinct('name');
        const ranks = [
            'Citizen',
            'Private',
            'Private First Class',
            'Specialist',
            'Corporal',
            'Sergeant',
            'Staff Sergeant',
            'Sergeant First Class',
            'Master Sergeant',
            'First Sergeant',
            'Sergeant Major',
            'Command Sergeant Major',
            'Sergeant Major of the Army',
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

        res.json({ success: true, units, ranks });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Notes system routes
router.get('/members/notes/:username', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const notes = await UserNote.find({ username: req.params.username })
            .sort({ dateAdded: -1 });
        res.json({ success: true, notes });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.post('/members/notes/add', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const { username, noteType, content } = req.body;
        
        const note = new UserNote({
            username,
            noteType,
            content,
            addedBy: req.user.username
        });
        
        await note.save();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Member search route
router.get('/members/search', isAuthenticated, async (req, res) => {
    try {
        const searchQuery = req.query.username;
        const members = await User.find({
            username: { $regex: searchQuery, $options: 'i' }
        })
        .select('username roles xp')
        .populate({
            path: 'roles',
            select: 'name id'
        });

        const excludedRoles = [
            'Commissioned Officers', 'General Grade Officers', 'Field Grade Officers',
            'Company Grade Officers', 'Enlisted Personnel', 'Senior Non-Commissioned Officers',
            'Non-Commissioned Officers', 'Enlisted', 'Donor', '@everyone'
        ];

        const formattedMembers = members.map(member => {
            const userRoles = (member.roles || []).filter(role => {
                return role?.name && !excludedRoles.includes(role.name);
            });

            return {
                username: member.username,
                highestRole: userRoles.length > 0 ? userRoles[0].name : 'No role assigned',
                xp: member.xp || 0
            };
        });

        res.json({ success: true, members: formattedMembers });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
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
        console.log('Searching for username:', req.params.username);

        const user = await User.findOne({ username: req.params.username })
            .populate({
                path: 'roles',
                select: 'name id'
            });

        console.log('Found user:', user);

        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        // Log the raw roles for debugging
        console.log('User roles before filtering:', user.roles);

        // Filter out excluded roles
        const excludedRoles = [
            'Commissioned Officers', 'General Grade Officers', 'Field Grade Officers',
            'Company Grade Officers', 'Enlisted Personnel', 'Senior Non-Commissioned Officers',
            'Non-Commissioned Officers', 'Enlisted', 'Donor', '@everyone'
        ];

        // Make sure roles is an array and handle null/undefined roles
        const roles = Array.isArray(user.roles) ? user.roles : [];
        
        const filteredRoles = roles.filter(role => 
            role && role.name && !excludedRoles.includes(role.name)
        );

        console.log('Filtered roles:', filteredRoles);

        const currentRank = filteredRoles.length > 0 ? filteredRoles[0].name : 'None';
        console.log('Current rank:', currentRank);

        return res.json({
            success: true,
            username: user.username,
            currentRank: currentRank
        });

    } catch (error) {
        console.error('Error in promotion verify:', error);
        return res.status(500).json({ 
            success: false, 
            error: error.message 
        });
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
            // Fetch the most recent placement for this user
            const currentPlacement = await Placement.findOne(
                { username: user.username, status: 'approved' },
                {},
                { sort: { 'dateSubmitted': -1 } }
            );
            
            res.json({
                success: true,
                username: user.username,
                currentPlacement: currentPlacement ? `${currentPlacement.newPlacement} - ${currentPlacement.placementRank}` : 'None'
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
            status: 'approved'  // Auto-approve since officer submitted
        });

        await placement.save();
        res.json({ success: true });
    } catch (error) {
        console.error('Placement submission error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error submitting placement' 
        });
    }
});

// Get all units
router.get('/api/units', isAuthenticated, async (req, res) => {
    try {
        const units = await Unit.find().sort({ type: 1, name: 1 });
        res.json(units);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching units' });
    }
});

// Create new unit
router.post('/api/units', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const unit = new Unit(req.body);
        await unit.save();
        res.json(unit);
    } catch (error) {
        res.status(500).json({ error: 'Error creating unit' });
    }
});

// Award Form route
router.get('/forms/award', isAuthenticated, (req, res) => {
    res.render('forms/award', {
        title: 'Award Form'
    });
});

// Verify user for award
router.get('/forms/award/verify/:username', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username });
        if (user) {
            res.json({
                success: true,
                username: user.username
            });
        } else {
            res.json({ success: false });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Submit award request
router.post('/forms/award/submit', isAuthenticated, async (req, res) => {
    try {
        const { username, award, reason, submittedBy } = req.body;

        const awardRecord = new Award({
            username,
            award,
            reason,
            submittedBy
        });

        await awardRecord.save();
        res.json({ success: true });
    } catch (error) {
        console.error('Award submission error:', error);
        res.status(500).json({ success: false, message: 'Error submitting award' });
    }
});

// Pending Awards route (officers only)
router.get('/forms/pendingawards', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const awards = await Award.find({ status: 'pending' })
            .sort({ dateSubmitted: -1 });

        res.render('forms/pendingawards', {
            title: 'Pending Awards',
            awards
        });
    } catch (error) {
        console.error('Error fetching pending awards:', error);
        next(error);
    }
});

// Handle award approval/rejection
router.post('/forms/awards/handle', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const { awardId, action } = req.body;
        const award = await Award.findById(awardId);

        if (!award) {
            return res.json({ success: false, message: 'Award request not found' });
        }

        award.status = action === 'approve' ? 'approved' : 'rejected';
        await award.save();

        res.json({ success: true });
    } catch (error) {
        console.error('Error handling award:', error);
        res.status(500).json({ success: false, message: 'Error handling award' });
    }
});

router.get('/forms/commission', isAuthenticated, isOfficer, (req, res) => {
    res.render('forms/commission', {
        title: 'Commission Form'
    });
});

// Process commission
router.post('/forms/commission/process', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const { username } = req.body;

        const user = await User.findOne({ username })
            .populate({
                path: 'roles',
                select: 'name id'
            });

        if (!user) {
            return res.json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        // Check if user is already an officer
        const officerRanks = [
            'Second Lieutenant', 'First Lieutenant', 'Captain', 'Major',
            'Lieutenant Colonel', 'Colonel', 'Brigadier General', 'Major General',
            'Lieutenant General', 'General', 'General of the Army'
        ];

        const currentRank = user.roles.find(role => 
            officerRanks.includes(role.name)
        )?.name;

        if (currentRank) {
            // If they're an officer, create a pending promotion to next rank
            const currentRankIndex = officerRanks.indexOf(currentRank);
            if (currentRankIndex < officerRanks.length - 1) {
                const promotion = new Promotion({
                    username: user.username,
                    currentRank: currentRank,
                    promotionRank: officerRanks[currentRankIndex + 1],
                    reason: 'Officer Promotion',
                    submittedBy: req.user.username,
                    status: 'pending'
                });

                await promotion.save();

                return res.json({
                    success: true,
                    message: 'Promotion request submitted for approval'
                });
            } else {
                return res.json({
                    success: false,
                    message: 'Already at highest officer rank'
                });
            }
        }

        // If not an officer, direct commission to Second Lieutenant
        const discordUpdateSuccess = await bot.updateUserRole(user.discordId, 'Second Lieutenant');

        if (!discordUpdateSuccess) {
            return res.json({
                success: false,
                message: 'Error updating Discord role'
            });
        }

        // Create approved promotion record for new commission
        const promotion = new Promotion({
            username: user.username,
            currentRank: user.roles[0]?.name || 'None',
            promotionRank: 'Second Lieutenant',
            reason: 'Officer Commission',
            submittedBy: req.user.username,
            status: 'approved'
        });

        await promotion.save();

        res.json({
            success: true,
            message: 'User successfully commissioned to Second Lieutenant'
        });

    } catch (error) {
        console.error('Commission error:', error);
        res.status(500).json({
            success: false,
            message: 'Error processing commission'
        });
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