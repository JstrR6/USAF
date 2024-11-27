const { Client, GatewayIntentBits, Events } = require('discord.js');
const mongoose = require('mongoose');
const User = require('./models/user');

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
        // Map Discord roles to the format our schema expects
        const roles = member.roles.cache.map(role => ({
            id: role.id,
            name: role.name
        }));

        // Update or create user in database
        const userData = {
            username: member.user.username,
            discordId: member.user.id,
            roles: roles
        };

        await User.findOneAndUpdate(
            { discordId: member.user.id },
            { $set: userData },
            { upsert: true, new: true }
        );

        console.log(`Successfully synced user: ${member.user.username}`);
    } catch (err) {
        console.error(`Error syncing user ${member.user.username}:`, err);
    }
}

// Function to sync all users
async function syncAllUsers() {
    try {
        const guild = client.guilds.cache.first();
        if (!guild) {
            console.log('No guild found');
            return;
        }

        const members = await guild.members.fetch();
        console.log(`Starting sync for ${members.size} members`);

        for (const [_, member] of members) {
            await syncUserData(member);
        }

        console.log('Full user sync completed');
    } catch (err) {
        console.error('Error during full sync:', err);
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