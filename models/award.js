const mongoose = require('mongoose');

const awardSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    award: {
        type: String,
        required: true,
        enum: [
            'Medal of Honor',
            'Distinguished Service Cross',
            'Distinguished Service Medal',
            'Silver Star',
            'Legion of Merit',
            'Distinguished Flying Cross',
            'Bronze Star Medal',
            'Purple Heart',
            'Air Medal',
            'Army Commendation Medal',
            'Army Achievement Medal',
            'Valorous Unit Award',
            'Good Conduct Medal',
            'Soldiers Medal',
            'Supreme Leadership Medal',
            'Command Excellence Medal',
            'Strategic Valor Medal',
            'Distinguished Field Service Medal',
            'Meritorious Leadership Medal',
            'General Officer Excellence Medal',
            'Field Grade Officer Service Medal',
            'Officer Commissioning Medal',
            'SNCO Leadership Medal',
            'NCO Advancement Medal'
        ]
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
    }
});

module.exports = mongoose.model('Award', awardSchema);