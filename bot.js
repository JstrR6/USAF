const { Client, GatewayIntentBits } = require('discord.js');
const mongoose = require('mongoose');
const User = require('./models/user');

const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers] });

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('Error connecting to MongoDB:', err);
});

client.once('ready', () => {
    console.log('Discord bot is online!');

    // Set interval to update user data every minute
    setInterval(async () => {
        try {
            const guild = client.guilds.cache.first(); // Assuming the bot is in one server
            if (!guild) return;

            const members = await guild.members.fetch();

            members.forEach(async (member) => {
                const { user } = member;
                const username = user.username;
                const discordId = user.id;
                const roles = member.roles.cache.map(role => role.name);

                // Find user in the database
                let dbUser = await User.findOne({ username });

                if (dbUser) {
                    // Update existing user
                    dbUser.discordId = discordId;
                    dbUser.roles = roles;
                    await dbUser.save();
                } else {
                    // Create new user
                    dbUser = new User({
                        username,
                        discordId,
                        roles,
                        xp: 0 // Initialize XP or handle as needed
                    });
                    await dbUser.save();
                }
            });

            console.log('User data updated.');
        } catch (err) {
            console.error('Error updating user data:', err);
        }
    }, 60000); // 60000 ms = 1 minute
});

client.login(process.env.DISCORD_BOT_TOKEN);
