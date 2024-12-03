const mongoose = require('mongoose');

const userNoteSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    noteType: {
        type: String,
        enum: ['Warning', 'Training', 'Recommendation', 'General'],
        required: true
    },
    content: {
        type: String,
        required: true
    },
    addedBy: {
        type: String,
        required: true
    },
    dateAdded: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('UserNote', userNoteSchema);