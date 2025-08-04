const express = require('express');
const redis = require('redis');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

// Redis client setup
const redisClient = redis.createClient({
    host: 'localhost',
    port: 6379
});

redisClient.on('error', (err) => console.log('Redis Client Error', err));
redisClient.connect();

// Import RedisStore after Redis client is created
const RedisStore = require('connect-redis').default;

// Middleware
app.use(bodyParser.json());
app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 1000 * 60 * 60 } // 1 hour
}));

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
        
        res.status(201).json({ message: `User ${username} registered successfully`, userId: userId });
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

        req.session.user = { username, id };
        res.json({ message: 'Login successful', username, password, userId: id });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// Logout endpoint
app.post('/logout', (req, res) => {
    if (req.session.user) {
        req.session.destroy((err) => {
            if (err) {
                return res.status(500).json({ error: 'Logout failed' });
            }
            res.json({ message: 'Logout successful' });
        });
    } else {
        res.status(401).json({ error: 'Not logged in' });
    }
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});