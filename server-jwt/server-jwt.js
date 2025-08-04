const express = require('express');
const jwt = require('jsonwebtoken');
const redis = require('redis');
const bcrypt = require('bcrypt');
const app = express();

app.use(express.json());

// Redis client setup
const redisClient = redis.createClient({
    host: 'localhost',
    port: 6379
});

redisClient.on('error', (err) => console.log('Redis Client Error', err));
redisClient.connect();

// Registration endpoint
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        // Check if user exists
        const existingUser = await redisClient.get(`user:${username}`);
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Generate new user ID
        const userId = await redisClient.incr('nextUserId');
        
        // Hash password and store user data
        const hashedPassword = await bcrypt.hash(password, 10);
        const userData = JSON.stringify({ id: userId, password: hashedPassword });
        await redisClient.set(`user:${username}`, userData);
        
        res.status(201).json({ message: `User ${username} registered successfully`, userId });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const userData = await redisClient.get(`user:${username}`);
        if (!userData) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const { id, password: hashedPassword } = JSON.parse(userData);
        const isValid = await bcrypt.compare(password, hashedPassword);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const user = { id, username };
        const token = jwt.sign(user, 'thesis-secret-123', { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// Protected endpoint
/*
app.get('/protected', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const user = jwt.verify(token, 'thesis-secret-123');
        res.json({ message: 'Authenticated', user });
    } catch (err) {
        res.status(401).json({ error: 'Unauthorized' });
    }
});
*/

// Logout endpoint (client-side token invalidation)
app.post('/logout', (req, res) => {
    // In JWT, logout is typically handled client-side by removing the token
    res.json({ message: 'Logout successful - please remove token client-side' });
});

// Start server
app.listen(3001, () => console.log('Server-JWT running on port 3001'));