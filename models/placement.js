const mongoose = require('mongoose');

const placementSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    currentPlacement: {
        type: String,
        default: 'None'
    },
    newPlacement: {
        type: String,
        required: true
    },
    placementRank: {
        type: String,
        enum: [
            'Commander',
            'Deputy Commander',
            'Senior Enlisted Leader',
            'Section Chief',
            'Non-Commissioned Officer In Charge',
            'Squad Sergeant',
            'Squad Leader',
            'Soldier'
        ],
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
        enum: ['pending', 'approved'],
        default: 'approved'
    }
});

module.exports = mongoose.model('Placement', placementSchema);