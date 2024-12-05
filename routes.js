// Routes.js

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

// Render dashboard page
router.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard', {
        title: 'Dashboard'
    });
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

        // Ranks to exclude
        const excludedRanks = [
            'Commissioned Officers', 'General Grade Officers', 'Field Grade Officers',
            'Company Grade Officers', 'Enlisted Personnel', 'Senior Non-Commissioned Officers',
            'Non-Commissioned Officers', 'Enlisted', 'Donor', '@everyone'
        ];

        // Fetch total member count excluding specific ranks
        const totalMembers = await User.countDocuments({
            'roles.name': { $nin: excludedRanks }
        });

        // Fetch all members with pagination and exclude specific ranks
        const users = await User.find({ 'roles.name': { $nin: excludedRanks } })
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
        let query = { 'roles.name': { $nin: [
            'Commissioned Officers', 'General Grade Officers', 'Field Grade Officers',
            'Company Grade Officers', 'Enlisted Personnel', 'Senior Non-Commissioned Officers',
            'Non-Commissioned Officers', 'Enlisted', 'Donor', '@everyone'
        ] } };

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

            // Update promotion status and add approver info
            promotion.status = 'approved';
            promotion.approvedBy = req.user.username;
            promotion.dateApproved = new Date();
            await promotion.save();

            // Update user's rank in database
            await User.findOneAndUpdate(
                { username: promotion.username },
                { $set: { 'roles.0.name': promotion.promotionRank } }
            );

        } else if (action === 'reject') {
            promotion.status = 'rejected';
            promotion.approvedBy = req.user.username;
            promotion.dateApproved = new Date();
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

router.get('/forms/allpromotions', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = 10;
        
        const [promotions, total] = await Promise.all([
            Promotion.find({})
                .sort({ dateSubmitted: -1 })
                .skip((page - 1) * limit)
                .limit(limit),
            Promotion.countDocuments(),
        ]);

        const [totalApproved, pendingCount] = await Promise.all([
            Promotion.countDocuments({ status: 'approved' }),
            Promotion.countDocuments({ status: 'pending' })
        ]);

        res.render('forms/allpromotions', {
            title: 'All Promotions',
            promotions,
            currentPage: page,
            totalPages: Math.ceil(total / limit),
            totalPromotions: total,
            totalApproved,
            pendingCount
        });
    } catch (error) {
        next(error);
    }
});

// Add filter route
router.post('/forms/allpromotions/filter', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const { search, status, sort, date } = req.body;
        let query = {};

        if (search) {
            query.$or = [
                { username: new RegExp(search, 'i') },
                { submittedBy: new RegExp(search, 'i') }
            ];
        }

        if (status !== 'all') {
            query.status = status;
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
            case 'newest':
                sortOption = { dateSubmitted: -1 };
                break;
            default:
                sortOption = { dateSubmitted: -1 };
        }

        const promotions = await Promotion.find(query).sort(sortOption);
        res.json({ success: true, promotions });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Error filtering promotions' });
    }
});

// Add export route
router.get('/forms/allpromotions/export', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const promotions = await Promotion.find({});
        const csv = [
            'Username,Current Rank,Promotion Rank,Status,Submitted By,Date Submitted,Approved By,Date Approved',
            ...promotions.map(p => {
                return `${p.username},${p.currentRank},${p.promotionRank},${p.status},${p.submittedBy},${p.dateSubmitted},${p.approvedBy || ''},${p.dateApproved || ''}`;
            })
        ].join('\n');
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=promotions.csv');
        res.send(csv);
    } catch (error) {
        console.error('Export error:', error);
        res.status(500).send('Error exporting promotions');
    }
});

router.get('/forms/auditlog', isAuthenticated, isOfficer, async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = 10;
        const skip = (page - 1) * limit;

        // Fetch activities (trainings, promotions, etc.)
        const [trainings, promotions, awards, placements] = await Promise.all([
            Training.find().sort({ dateSubmitted: -1 }),
            Promotion.find().sort({ dateSubmitted: -1 }),
            Award.find().sort({ dateSubmitted: -1 }),
            Placement.find().sort({ dateSubmitted: -1 })
        ]);

        const allActivities = [
            ...trainings.map(t => ({
                type: 'Training',
                username: t.trainees.join(', '),
                performedBy: t.trainer,
                details: `XP Amount: ${t.xpAmount}`,
                status: t.awarded ? 'Approved' : (t.needsApproval ? 'Pending' : 'Processing'),
                date: t.dateSubmitted
            })),
            ...promotions.map(p => ({
                type: 'Promotion',
                username: p.username,
                performedBy: p.submittedBy,
                details: `${p.currentRank} → ${p.promotionRank}`,
                status: p.status,
                date: p.dateSubmitted,
                approvedBy: p.approvedBy,
                dateApproved: p.dateApproved
            })),
            ...awards.map(a => ({
                type: 'Award',
                username: a.username,
                performedBy: a.submittedBy,
                details: a.award,
                status: a.status,
                date: a.dateSubmitted
            })),
            ...placements.map(p => ({
                type: 'Placement',
                username: p.username,
                performedBy: p.submittedBy,
                details: `${p.currentPlacement || 'None'} → ${p.newPlacement} as ${p.placementRank}`,
                status: p.status,
                date: p.dateSubmitted
            }))
        ];

        // Calculate statistics
        const stats = {
            total: allActivities.length,
            byType: {
                Training: trainings.length,
                Promotion: promotions.length,
                Award: awards.length,
                Placement: placements.length
            },
            byStatus: {
                Pending: allActivities.filter(a => a.status === 'Pending').length,
                Approved: allActivities.filter(a => a.status === 'Approved').length,
                Rejected: allActivities.filter(a => a.status === 'Rejected').length
            }
        };

        // Paginate activities
        const paginatedActivities = allActivities.slice(skip, skip + limit);
        const totalPages = Math.ceil(allActivities.length / limit);

        // Render the audit log page
        res.render('forms/auditlog', {
            title: 'Audit Log',
            activities: paginatedActivities,
            stats: stats || { total: 0, byType: {}, byStatus: {} }, // Default empty stats
            currentPage: page,
            totalPages
        });
    } catch (error) {
        console.error('Error loading audit log:', error);
        next(error);
    }
});

// Filter route
router.post('/forms/auditlog/filter', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const { search, type, status, startDate, endDate, noteType } = req.body;

        const [trainings, promotions, awards, placements, notes] = await Promise.all([
            Training.find(),
            Promotion.find(),
            Award.find(),
            Placement.find(),
            UserNote.find(noteType && noteType !== 'all' ? { type: noteType } : {})
        ]);

        let allActivities = [
            ...trainings.map(t => ({
                type: 'Training',
                username: t.trainees.join(', '),
                performedBy: t.trainer,
                details: `XP Amount: ${t.xpAmount}`,
                status: t.awarded ? 'Approved' : (t.needsApproval ? 'Pending' : 'Processing'),
                date: t.dateSubmitted
            })),
            ...promotions.map(p => ({
                type: 'Promotion',
                username: p.username,
                performedBy: p.submittedBy,
                details: `${p.currentRank} → ${p.promotionRank}`,
                status: p.status,
                date: p.dateSubmitted,
                approvedBy: p.approvedBy,
                dateApproved: p.dateApproved
            })),
            ...awards.map(a => ({
                type: 'Award',
                username: a.username,
                performedBy: a.submittedBy,
                details: a.award,
                status: a.status,
                date: a.dateSubmitted
            })),
            ...placements.map(p => ({
                type: 'Placement',
                username: p.username,
                performedBy: p.submittedBy,
                details: `${p.currentPlacement || 'None'} → ${p.newPlacement} as ${p.placementRank}`,
                status: p.status,
                date: p.dateSubmitted
            })),
            ...notes.map(n => ({
                type: 'Note',
                username: n.userId, // Replace with a user lookup if necessary
                performedBy: n.createdBy,
                details: n.content,
                status: n.type,
                date: n.date
            }))
        ];

        // Apply filters
        if (search) {
            const searchRegex = new RegExp(search, 'i');
            allActivities = allActivities.filter(a =>
                searchRegex.test(a.username) ||
                searchRegex.test(a.performedBy) ||
                searchRegex.test(a.details)
            );
        }

        if (type !== 'all') {
            allActivities = allActivities.filter(a => a.type === type);
        }

        if (status !== 'all') {
            allActivities = allActivities.filter(a => a.status === status);
        }

        if (startDate && endDate) {
            const start = new Date(startDate);
            const end = new Date(endDate);
            allActivities = allActivities.filter(a =>
                a.date >= start && a.date <= end
            );
        }

        res.json({ success: true, activities: allActivities });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Error filtering logs' });
    }
});

// Export route for audit log
router.get('/forms/auditlog/export', isAuthenticated, isOfficer, async (req, res) => {
    try {
        // Get data from all schemas
        const [trainings, promotions, awards, placements] = await Promise.all([
            Training.find(),
            Promotion.find(),
            Award.find(),
            Placement.find()
        ]);

        // Combine all activities
        const allActivities = [
            ...trainings.map(t => ({
                type: 'Training',
                username: t.trainees.join('; '),
                performedBy: t.trainer,
                details: `XP Amount: ${t.xpAmount}`,
                status: t.awarded ? 'Approved' : (t.needsApproval ? 'Pending' : 'Processing'),
                date: t.dateSubmitted
            })),
            ...promotions.map(p => ({
                type: 'Promotion',
                username: p.username,
                performedBy: p.submittedBy,
                details: `${p.currentRank} → ${p.promotionRank}`,
                status: p.status,
                date: p.dateSubmitted,
                approvedBy: p.approvedBy,
                dateApproved: p.dateApproved
            })),
            ...awards.map(a => ({
                type: 'Award',
                username: a.username,
                performedBy: a.submittedBy,
                details: a.award,
                status: a.status,
                date: a.dateSubmitted
            })),
            ...placements.map(p => ({
                type: 'Placement',
                username: p.username,
                performedBy: p.submittedBy,
                details: `${p.currentPlacement || 'None'} → ${p.newPlacement} as ${p.placementRank}`,
                status: p.status,
                date: p.dateSubmitted
            }))
        ].sort((a, b) => b.date - a.date);

        const csv = [
            'Type,Username,Performed By,Details,Status,Date,Approved By,Date Approved',
            ...allActivities.map(activity => {
                return `${activity.type},${activity.username},${activity.performedBy},${activity.details},${activity.status},${activity.date}${activity.approvedBy ? ',' + activity.approvedBy : ','}${activity.dateApproved ? ',' + activity.dateApproved : ','}`;
            })
        ].join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=auditlog.csv');
        res.send(csv);
    } catch (error) {
        console.error('Export error:', error);
        res.status(500).send('Error exporting audit log');
    }
});

router.get('/forms/disciplinary', isAuthenticated, isOfficer, (req, res) => {
    res.render('forms/disciplinary', {
        title: 'Disciplinary Form'
    });
});

router.get('/forms/disciplinary/verify/:username', isAuthenticated, isOfficer, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username })
            .populate({
                path: 'roles',
                select: 'name id'
            });

        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        // List of excluded ranks
        const excludedRoles = [
            'Commissioned Officers', 'General Grade Officers', 'Field Grade Officers',
            'Company Grade Officers', 'Enlisted Personnel', 'Senior Non-Commissioned Officers',
            'Non-Commissioned Officers', 'Enlisted', 'Donor', '@everyone'
        ];

        // Filter roles and get current rank
        const filteredRoles = user.roles.filter(role => 
            role?.name && !excludedRoles.includes(role.name)
        );

        if (filteredRoles.length === 0) {
            return res.json({ 
                success: false, 
                message: 'Invalid rank for disciplinary action' 
            });
        }

        const targetRank = filteredRoles[0].name;

        // Define officer ranks in order of hierarchy
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

        const submitterRank = req.user.roles[0]?.name;
        const isTargetOfficer = officerRanks.includes(targetRank);

        if (isTargetOfficer) {
            const submitterRankIndex = officerRanks.indexOf(submitterRank);
            const targetRankIndex = officerRanks.indexOf(targetRank);

            if (submitterRankIndex <= targetRankIndex) {
                return res.json({ 
                    success: false, 
                    message: 'You cannot take disciplinary action against an officer of equal or higher rank.' 
                });
            }
        }

        return res.json({
            success: true,
            username: user.username,
            currentRank: targetRank,
            currentXP: user.xp || 0,
            isOfficer: isTargetOfficer
        });

    } catch (error) {
        return res.status(500).json({ success: false, error: error.message });
    }
});

router.post('/forms/disciplinary/submit', isAuthenticated, isOfficer, async (req, res) => {
    try {
        console.log('Received disciplinary submission:', req.body); // Debug log

        const { username, article, details } = req.body;
        
        if (!username || !article || !details) {
            console.log('Missing required fields:', { username, article, details }); // Debug log
            return res.status(400).json({ 
                success: false, 
                message: 'Missing required fields' 
            });
        }

        const user = await User.findOne({ username });
        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        let result = null;
        switch(article) {
            case '1': // Warning
                result = await new UserNote({
                    username,
                    noteType: 'Warning',
                    content: `[Article 1] ${details.reason}`,
                    addedBy: req.user.username
                }).save();
                break;

            case '2': // XP Reduction
                let xpReduction = 0;
                if (details.type === 'manual') {
                    xpReduction = parseInt(details.amount);
                } else {
                    const percentage = parseInt(details.percentage);
                    xpReduction = Math.floor(user.xp * (percentage / 100));
                }
                
                user.xp = Math.max(0, user.xp - xpReduction);
                await user.save();

                result = await new UserNote({
                    username,
                    noteType: 'Warning',
                    content: `[Article 2] XP Reduction: ${xpReduction}XP - ${details.reason}`,
                    addedBy: req.user.username
                }).save();
                break;

            case '3': // Demotion
                const currentRank = details.currentRank;
                const newRank = details.newRank;
                
                // Update Discord role
                const roleUpdated = await bot.updateUserRole(user.discordId, newRank);
                if (!roleUpdated) {
                    throw new Error('Failed to update Discord role');
                }
                
                // Set XP to minimum for new rank
                const ranks = [
                    { rank: 'Citizen', xp: 0 },
                    { rank: 'Private', xp: 1 },
                    { rank: 'Private First Class', xp: 10 },
                    { rank: 'Specialist', xp: 25 },
                    { rank: 'Corporal', xp: 40 },
                    { rank: 'Sergeant', xp: 60 },
                    { rank: 'Staff Sergeant', xp: 80 },
                    { rank: 'Sergeant First Class', xp: 100 },
                    { rank: 'Master Sergeant', xp: 125 },
                    { rank: 'First Sergeant', xp: 150 },
                    { rank: 'Sergeant Major', xp: 175 },
                    { rank: 'Command Sergeant Major', xp: 250 }
                ];
                
                const rankData = ranks.find(r => r.rank === newRank);
                user.xp = rankData ? rankData.xp : 0;
                await user.save();

                result = await new UserNote({
                    username,
                    noteType: 'Warning',
                    content: `[Article 3] Demotion from ${currentRank} to ${newRank} - ${details.reason}`,
                    addedBy: req.user.username
                }).save();
                break;

            case '4': // Discharge
                const citizenRole = await bot.updateUserRole(user.discordId, 'Citizen');
                if (!citizenRole) {
                    throw new Error('Failed to update Discord role to Citizen');
                }
                
                user.xp = 0;
                await user.save();

                result = await new UserNote({
                    username,
                    noteType: 'Warning',
                    content: `[Article 4] Discharged: ${details.reason}`,
                    addedBy: req.user.username
                }).save();
                break;

            default:
                return res.status(400).json({ 
                    success: false, 
                    message: 'Invalid article type' 
                });
        }

        console.log('Disciplinary action completed:', result); // Debug log
        res.json({ success: true, message: 'Disciplinary action completed successfully' });
    } catch (error) {
        console.error('Disciplinary action error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message || 'Error processing disciplinary action'
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