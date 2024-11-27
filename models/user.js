const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema({
    id: String,
    name: String
});

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    discordId: {
        type: String,
        unique: true
    },
    roles: [roleSchema],
    xp: {
        type: Number,
        default: 0,
        min: 0
    }
}, {
    timestamps: true  // Adds createdAt and updatedAt timestamps
});

module.exports = mongoose.model('User', userSchema);