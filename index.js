// Required dependencies
const express = require('express')
const app = express()
const cors = require('cors')
const mongoose = require('mongoose')
const User = require('./models/user.model')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const crypto = require('crypto')
require('dotenv').config()

// Middleware
app.use(cors(
    {
      origin : ["https://transfer-client.vercel.app"],
        method : ["POST", "GET", "PUT", "DELETE"],
        credentials: true
    }
        ));
app.use(express.json())

// Environment variables
const PORT = 80
const MONGODB_URI = process.env.MONGODB_URI
const JWT_SECRET = process.env.JWT_SECRET
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex') // Ensure 32-byte key
const IV_LENGTH = 16 // For AES, this is always 16


// Encryption utilities
const encrypt = (text) => {
    const iv = crypto.randomBytes(IV_LENGTH)
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv)
    let encrypted = cipher.update(text)
    encrypted = Buffer.concat([encrypted, cipher.final()])
    return iv.toString('hex') + ':' + encrypted.toString('hex')
}

const decrypt = (text) => {
    const textParts = text.split(':')
    const iv = Buffer.from(textParts.shift(), 'hex')
    const encryptedText = Buffer.from(textParts.join(':'), 'hex')
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv)
    let decrypted = decipher.update(encryptedText)
    decrypted = Buffer.concat([decrypted, decipher.final()])
    return decrypted.toString()
}

// MongoDB connection
mongoose.connect(MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch((err) => console.error('MongoDB connection error:', err))

// Register and Login routes remain the same
app.post('/api/register', async (req,res) => {
    try {
        const newPassword = await bcrypt.hash(req.body.password, 10)
        const user = await User.create({
            name: req.body.name,
            email: req.body.email,
            password: newPassword,
        })
        res.json({status: 'ok'})
    } catch (err) {
        res.json({status: 'error', error: 'Duplicate email'})
    }
})

app.post('/api/login', async (req,res) => {
    const user = await User.findOne({
        email: req.body.email,
    })

    if(!user) {
        return res.json({status: 'error', error: 'invalid login'})
    }

    const isPasswordValid = await bcrypt.compare(req.body.password, user.password)

    if (isPasswordValid) {
        const token = jwt.sign({
            Name: user.name,
            email: user.email,
        }, JWT_SECRET, { expiresIn: '1h' })

        return res.json({ status: 'ok', user: token })
    } else {
        return res.json({ status: 'error', user: false })
    }
})

// Modified quote endpoints with encryption
app.get('/api/quotes', async (req, res) => {
    try {
        const token = req.headers['x-access-token']
        const decode = jwt.verify(token, JWT_SECRET)
        const email = decode.email
        const user = await User.findOne({ email: email })

        // Decrypt all quotes before sending
        const decryptedQuotes = user.quotes.map(quote => {
            try {
                return decrypt(quote)
            } catch (err) {
                console.error('Decryption error:', err)
                return null // Handle quotes that can't be decrypted
            }
        }).filter(quote => quote !== null)

        return res.json({ status: 'ok', quotes: decryptedQuotes })
    } catch (err) {
        console.log(err)
        res.json({ status: 'error', error: 'invalid token' })
    }
})

app.post('/api/quote', async (req, res) => {
    try {
        const token = req.headers['x-access-token']
        const decode = jwt.verify(token, JWT_SECRET)
        const email = decode.email
        
        // Encrypt the quote before saving
        const encryptedQuote = encrypt(req.body.quote)
        
        const user = await User.findOne({ email: email })
        user.quotes.push(encryptedQuote)
        await user.save()

        res.json({ 
            status: 'ok', 
            quote: req.body.quote,
            quoteId: user.quotes.length - 1
        })
    } catch (err) {
        console.log(err)
        res.json({ status: 'error', error: 'Invalid token' })
    }
})

app.delete('/api/quote/:quoteId', async (req, res) => {
    try {
        const token = req.headers['x-access-token']
        const decode = jwt.verify(token, JWT_SECRET)
        const email = decode.email
        const quoteId = decodeURIComponent(req.params.quoteId)

        const user = await User.findOne({ email: email })
        user.quotes = user.quotes.filter((_, index) => index.toString() !== quoteId.toString())
        await user.save()

        res.json({ status: 'ok', message: 'Quote deleted' })
    } catch (err) {
        console.log(err)
        res.json({ status: 'error', error: 'Invalid token' })
    }
})

app.put('/api/quote/:quoteId', async (req, res) => {
    try {
        const token = req.headers['x-access-token']
        const decode = jwt.verify(token, JWT_SECRET)
        const email = decode.email
        const quoteId = decodeURIComponent(req.params.quoteId)

        // Encrypt the updated quote
        const encryptedQuote = encrypt(req.body.quote)

        const user = await User.findOne({ email: email })
        const quoteIndex = user.quotes.findIndex((_, index) => index.toString() === quoteId.toString())
        
        if (quoteIndex !== -1) {
            user.quotes[quoteIndex] = encryptedQuote
            await user.save()
            res.json({ status: 'ok', quote: req.body.quote })
        } else {
            res.json({ status: 'error', error: 'Quote not found' })
        }
    } catch (err) {
        console.log(err)
        res.json({ status: 'error', error: 'Invalid token' })
    }
})

app.get('/api/test', (req, res) => {
  res.json({ message: 'Test API is working!' });
});

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`)
})
