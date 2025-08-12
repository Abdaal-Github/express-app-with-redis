const express = require('express');
const redis = require('redis');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const client = require('prom-client');

const app = express();
const port = 3001;

// Redis client setup
const redisClient = redis.createClient({
    host: 'localhost',
    port: 6379
});

redisClient.on('error', (err) => console.log('Redis Client Error', err));
redisClient.connect();

// Prometheus metrics setup
const register = new client.Registry();
client.collectDefaultMetrics({ register });
const httpRequestDuration = new client.Histogram({
    name: 'http_request_duration_seconds',
    help: 'Duration of HTTP requests in seconds',
    labelNames: ['method', 'route', 'code'],
    buckets: [0.1, 0.3, 0.5, 1, 3, 5]
});
const httpRequestsTotal = new client.Counter({
    name: 'http_requests_total',
    help: 'Total number of HTTP requests',
    labelNames: ['method', 'route', 'code']
});
register.registerMetric(httpRequestDuration);
register.registerMetric(httpRequestsTotal);

// Middleware
app.use(express.json());

// Metrics middleware
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = (Date.now() - start) / 1000;
        httpRequestDuration.labels(req.method, req.path, res.statusCode).observe(duration);
        httpRequestsTotal.labels(req.method, req.path, res.statusCode).inc();
    });
    next();
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
});

// Registration endpoint
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    try {
        const existingUser = await redisClient.get(`user:${username}`);
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        const userId = await redisClient.incr('nextUserId');
        const hashedPassword = await bcrypt.hash(password, 10);
        const userData = JSON.stringify({ id: userId, password: hashedPassword });
        await redisClient.set(`user:${username}`, userData);
        res.status(201).json({ message: `User ${username} registered successfully`, userId });
    } catch (error) {
        console.error('Registration error:', error);
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
        const token = jwt.sign({ username, id }, 'thesis-secret-123', { expiresIn: '1h' });
        res.json({ message: 'Login successful', token, userId: id });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Protected endpoint
app.get('/protected', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    try {
        const user = jwt.verify(token, 'thesis-secret-123');
        res.json({ message: 'Authenticated', user });
    } catch (error) {
        console.error('Protected endpoint error:', error);
        res.status(401).json({ error: 'Invalid or expired token' });
    }
});

// Logout endpoint
app.post('/logout', (req, res) => {
    res.json({ message: 'Logout successful (discard token client-side)' });
});

// Start server
app.listen(port, () => {
    console.log(`JWT Server running at http://localhost:${port}`);
});