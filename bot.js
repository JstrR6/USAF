const { Client, GatewayIntentBits, Events } = require('discord.js');
const mongoose = require('mongoose');
const User = require('./models/user');

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

// Function to determine rank based on XP
function getRankByXP(xp) {
    for (let i = XP_THRESHOLDS.length - 1; i >= 0; i--) {
        if (xp >= XP_THRESHOLDS[i].xp) {
            return XP_THRESHOLDS[i].rank;
        }
    }
    return 'Citizen';
}

// Configure bot with necessary intents
const client = new Client({ 
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildPresences
    ] 
});

// Connect to MongoDB with error handling
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB Connected Successfully'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// Handle database connection errors
mongoose.connection.on('error', err => {
    console.error('MongoDB Error:', err);
});

// Bot startup
client.once(Events.ClientReady, async () => {
    console.log(`Bot logged in as ${client.user.tag}`);
    await syncAllUsers();
    startAutoSync();
});

// Main function to sync a single user
async function syncUserData(member) {
    try {
        const roles = member.roles.cache.map(role => ({
            id: role.id,
            name: role.name
        }));

        const user = await User.findOneAndUpdate(
            { discordId: member.user.id },
            {
                $set: {
                    username: member.user.username,
                    discordId: member.user.id,
                    roles
                }
            },
            { upsert: true, new: true }
        );

        // Check if user needs promotion based on XP
        const newRank = getRankByXP(user.xp);
        const currentRank = user.roles.find(role => role.name === newRank);
        if (!currentRank) {
            await updateUserRole(member.user.id, newRank);
        }
    } catch (error) {
        console.error(`Error syncing user ${member.user.username}:`, error);
    }
}

// Function to sync all users
async function syncAllUsers() {
    try {
        const guild = client.guilds.cache.first();
        if (!guild) throw new Error('Guild not found');

        const members = await guild.members.fetch();

        const batchSize = 10; // Number of users to process in each batch
        const memberList = [...members.values()];

        for (let i = 0; i < memberList.length; i += batchSize) {
            const batch = memberList.slice(i, i + batchSize);
            await Promise.all(batch.map(member => syncUserData(member)));
        }

        console.log('Full user sync completed.');
    } catch (error) {
        console.error('Error during full sync:', error);
    }
}

// Auto sync every 5 minutes
function startAutoSync() {
    setInterval(async () => {
        console.log('Starting automatic sync...');
        await syncAllUsers();
    }, 5 * 60 * 1000); // 5 minutes
}

// Event handlers for real-time updates
client.on(Events.GuildMemberUpdate, async (oldMember, newMember) => {
    if (oldMember.roles.cache.size !== newMember.roles.cache.size ||
        !oldMember.roles.cache.every(role => newMember.roles.cache.has(role.id))) {
        await syncUserData(newMember);
    }
});

client.on(Events.GuildMemberAdd, async (member) => {
    await syncUserData(member);
});

// Error handling
client.on(Events.Error, error => {
    console.error('Discord client error:', error);
});

process.on('unhandledRejection', error => {
    console.error('Unhandled promise rejection:', error);
});

// Login bot with error handling
client.login(process.env.DISCORD_BOT_TOKEN)
    .catch(err => console.error('Bot login error:', err));

module.exports = client;

async function updateUserRole(discordId, newRank) {
    try {
        const guild = client.guilds.cache.first();
        if (!guild) {
            console.log('No guild found');
            return false;
        }

        const member = await guild.members.fetch(discordId);
        if (!member) {
            console.log('Member not found');
            return false;
        }

        // Define rank categories
        const rankCategories = {
            'Citizen': [],
            'Private': ['Enlisted', 'Enlisted Personnel'],
            'Private First Class': ['Enlisted', 'Enlisted Personnel'],
            'Specialist': ['Enlisted', 'Enlisted Personnel'],
            'Corporal': ['Enlisted', 'Enlisted Personnel'],
            'Sergeant': ['Non-Commissioned Officers', 'Enlisted Personnel'],
            'Staff Sergeant': ['Non-Commissioned Officers', 'Enlisted Personnel'],
            'Sergeant First Class': ['Non-Commissioned Officers', 'Enlisted Personnel'],
            'Master Sergeant': ['Non-Commissioned Officers', 'Enlisted Personnel'],
            'First Sergeant': ['Non-Commissioned Officers', 'Enlisted Personnel'],
            'Sergeant Major': ['Senior Non-Commissioned Officers', 'Enlisted Personnel'],
            'Command Sergeant Major': ['Senior Non-Commissioned Officers', 'Enlisted Personnel'],
            'Sergeant Major of the Army': ['Senior Non-Commissioned Officers', 'Enlisted Personnel'],
            'Second Lieutenant': ['Commissioned Officers', 'Company Grade Officers'],
            'First Lieutenant': ['Commissioned Officers', 'Company Grade Officers'],
            'Captain': ['Commissioned Officers', 'Company Grade Officers'],
            'Major': ['Commissioned Officers', 'Field Grade Officers'],
            'Lieutenant Colonel': ['Commissioned Officers', 'Field Grade Officers'],
            'Colonel': ['Commissioned Officers', 'Field Grade Officers'],
            'Brigadier General': ['Commissioned Officers', 'General Grade Officers'],
            'Major General': ['Commissioned Officers', 'General Grade Officers'],
            'Lieutenant General': ['Commissioned Officers', 'General Grade Officers'],
            'General': ['Commissioned Officers', 'General Grade Officers'],
            'General of the Army': ['Commissioned Officers', 'General Grade Officers']
        };

        // All possible categories to remove
        const allCategories = [
            'Enlisted',
            'Non-Commissioned Officers',
            'Senior Non-Commissioned Officers',
            'Enlisted Personnel',
            'Company Grade Officers',
            'Field Grade Officers',
            'General Grade Officers',
            'Commissioned Officers'
        ];

        // Remove all current rank roles and categories
        const rolesToRemove = member.roles.cache.filter(role => {
            const roleName = role.name;
            return Object.keys(rankCategories).includes(roleName) || 
                   allCategories.includes(roleName);
        });

        for (const [_, role] of rolesToRemove) {
            await member.roles.remove(role);
        }

        // Add new rank role
        const newRankRole = guild.roles.cache.find(role => role.name === newRank);
        if (newRankRole) {
            await member.roles.add(newRankRole);
        } else {
            console.log(`Rank role ${newRank} not found`);
            return false;
        }

        // Add category roles
        const categoriesToAdd = rankCategories[newRank] || [];
        for (const category of categoriesToAdd) {
            const categoryRole = guild.roles.cache.find(role => role.name === category);
            if (categoryRole) {
                await member.roles.add(categoryRole);
            } else {
                console.log(`Category role ${category} not found`);
            }
        }

        console.log(`Updated ${member.user.username}'s role to ${newRank} with categories:`, categoriesToAdd);
        return true;
    } catch (error) {
        console.error('Error updating Discord roles:', error);
        return false;
    }
}

// Function to update a user's XP and promote them if necessary
async function updateUserXP(userId, newXP) {
    try {
        const user = await User.findById(userId);
        if (!user) throw new Error('User not found');

        const newRank = getRankByXP(newXP);
        const currentRank = user.roles.find(role => role.name === newRank);

        if (!currentRank) {
            console.log(`Promoting ${user.username} to ${newRank}`);
            await updateUserRole(user.discordId, newRank);

            // Update user roles in database
            user.roles = [{ name: newRank }];
        }

        user.xp = newXP;
        await user.save();
    } catch (error) {
        console.error('Error updating user XP:', error);
    }
}

// Export the function
module.exports.updateUserRole = updateUserRole;