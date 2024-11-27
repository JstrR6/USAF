const mongoose = require('mongoose');

const trainingSchema = new mongoose.Schema({
    trainer: {
        type: String,
        required: true
    },
    trainees: [{
        type: String,
        required: true
    }],
    xpAmount: {
        type: Number,
        required: true,
        min: 0
    },
    awarded: {
        type: Boolean,
        default: false
    },
    needsApproval: {
        type: Boolean,
        default: false
    },
    dateSubmitted: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Training', trainingSchema);