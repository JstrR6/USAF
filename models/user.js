const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    discordId: { type: String, required: true },
    roles: { type: [String], default: [] },
    xp: { type: Number, default: 0 }
});

module.exports = mongoose.model('User', userSchema);
