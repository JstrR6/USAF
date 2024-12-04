const mongoose = require('mongoose');

const promotionSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    currentRank: {
        type: String,
        required: true
    },
    promotionRank: {
        type: String,
        required: true
    },
    reason: {
        type: String,
        required: true
    },
    submittedBy: {
        type: String,
        required: true
    },
    dateSubmitted: {
        type: Date,
        default: Date.now
    },
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending'
    },
    approvedBy: {
        type: String,
        default: null
    },
    dateApproved: {
        type: Date,
        default: null
    }
});

module.exports = mongoose.model('Promotion', promotionSchema);