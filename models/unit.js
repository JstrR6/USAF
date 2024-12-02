const mongoose = require('mongoose');

const unitSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    type: {
        type: String,
        enum: ['Army', 'Corps', 'Division', 'Brigade', 'Battalion', 'Company', 'Platoon', 'Section', 'Squad'],
        required: true
    },
    parent: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Unit'
    },
    commander: String,
    deputyCommander: String,
    seniorEnlistedLeader: String,
    sectionChief: String,
    ncoic: String,
    squadSergeant: String,
    squadLeader: String
});

module.exports = mongoose.model('Unit', unitSchema);