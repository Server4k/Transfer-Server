const mongoose = require('mongoose')

const User = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    quotes: [{
        _id: { type: mongoose.Schema.Types.ObjectId, auto: true },
        text: { type: String, required: true }
    }]
})

module.exports = mongoose.model('User', User)
