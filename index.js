const express = require('express')
const app = express()
const cors = require('cors')
const mongoose = require('mongoose')
const User = require('./models/user.model')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
require('dotenv').config()

app.use(cors( 
    {
    origin : ["https://transfer-client.vercel.app"],
        methods: ["POST", "GET", "PUT", "DELETE", "OPTIONS"],
        credentials: true 
    } ));

app.use(express.json())

const PORT = 80
const MONGODB_URI = process.env.MONGODB_URI
const JWT_SECRET = process.env.JWT_SECRET

mongoose.connect(MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch((err) => console.error('MongoDB connection error:', err))

// Previous register and login endpoints remain the same...
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

// Updated quote endpoints
app.get('/api/quotes', async (req, res) => {
    try {
        const token = req.headers['x-access-token'];
        const decoded = jwt.verify(token, JWT_SECRET);
        const email = decoded.email;
        const user = await User.findOne({ email: email });

        if (!user) {
            return res.json({ status: 'error', error: 'User not found' });
        }

        // Ensure consistent quote structure
        const quotesWithIds = user.quotes.map(quote => {
            if (typeof quote === 'string') {
                return {
                    _id: new mongoose.Types.ObjectId(),
                    text: quote
                };
            }
            return quote;
        });

        // Update user with structured quotes if necessary
        if (quotesWithIds !== user.quotes) {
            user.quotes = quotesWithIds;
            await user.save();
        }

        return res.json({ status: 'ok', quotes: quotesWithIds });
    } catch (err) {
        console.log(err);
        res.json({ status: 'error', error: 'invalid token' });
    }
});

app.post('/api/quote', async (req, res) => {
    try {
        const token = req.headers['x-access-token'];
        const decoded = jwt.verify(token, JWT_SECRET);
        const email = decoded.email;
        
        const user = await User.findOne({ email: email });
        if (!user) {
            return res.json({ status: 'error', error: 'User not found' });
        }

        const newQuote = {
            _id: new mongoose.Types.ObjectId(),
            text: req.body.quote
        };

        user.quotes.push(newQuote);
        await user.save();

        res.json({ 
            status: 'ok', 
            quote: newQuote.text,
            quoteId: newQuote._id 
        });
    } catch (err) {
        console.log(err);
        res.json({ status: 'error', error: 'Invalid token' });
    }
});

app.delete('/api/quote/:quoteId', async (req, res) => {
    try {
        const token = req.headers['x-access-token'];
        const decoded = jwt.verify(token, JWT_SECRET);
        const email = decoded.email;
        const quoteId = req.params.quoteId;

        const user = await User.findOne({ email: email });
        if (!user) {
            return res.json({ status: 'error', error: 'User not found' });
        }

        user.quotes = user.quotes.filter(quote => quote._id.toString() !== quoteId);
        await user.save();

        res.json({ status: 'ok', message: 'Quote deleted' });
    } catch (err) {
        console.log(err);
        res.json({ status: 'error', error: 'Invalid token or quote not found' });
    }
});

app.put('/api/quote/:quoteId', async (req, res) => {
    try {
        const token = req.headers['x-access-token'];
        const decoded = jwt.verify(token, JWT_SECRET);
        const email = decoded.email;
        const quoteId = req.params.quoteId;

        const user = await User.findOne({ email: email });
        if (!user) {
            return res.json({ status: 'error', error: 'User not found' });
        }

        const quoteIndex = user.quotes.findIndex(quote => quote._id.toString() === quoteId);
        
        if (quoteIndex === -1) {
            return res.json({ status: 'error', error: 'Quote not found' });
        }

        user.quotes[quoteIndex] = {
            _id: user.quotes[quoteIndex]._id,
            text: req.body.quote
        };

        await user.save();
        res.json({ status: 'ok', quote: req.body.quote });
    } catch (err) {
        console.log(err);
        res.json({ status: 'error', error: 'Invalid token or quote not found' });
    }
});

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`)
})
