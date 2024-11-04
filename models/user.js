const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema({
    id: String,
    name: String
});

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    discordId: String,
    roles: [roleSchema],
    xp: { type: Number, default: 0 }
});

module.exports = mongoose.model('User', userSchema);
