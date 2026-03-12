const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'prompt-analyzer-secret-' + Date.now();

if (!CLAUDE_API_KEY) {
  console.error('Missing CLAUDE_API_KEY environment variable');
  process.exit(1);
}

if (!DATABASE_URL) {
  console.error('Missing DATABASE_URL environment variable');
  process.exit(1);
}

// Neon PostgreSQL connection
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Create users table on startup
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  console.log('Database ready');
}
initDB().catch(err => {
  console.error('Database init failed:', err.message);
  process.exit(1);
});

// Auth middleware
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Login required' });
  }
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Signup
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Account already exists' });
    }

    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, hash]);

    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, email });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const result = await pool.query('SELECT email, password_hash FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, email });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Protected analyze endpoint
app.post('/api/analyze', requireAuth, async (req, res) => {
  const { prompt } = req.body;

  if (!prompt || !prompt.trim()) {
    return res.status(400).json({ error: 'Prompt is required' });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': CLAUDE_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-3-haiku-20240307',
        max_tokens: 2048,
        messages: [{
          role: 'user',
          content: `You are a prompt engineering expert. Analyze the following user prompt and return ONLY valid JSON (no markdown, no code fences) in this exact format:

{
  "clarity": <1-100>,
  "specificity": <1-100>,
  "efficiency": <1-100>,
  "structure": <1-100>,
  "strengths": ["...", "..."],
  "improvements": ["...", "..."],
  "missing_context": ["...", "..."],
  "questions": ["...", "..."],
  "optimized": "..."
}

Scoring criteria:
- clarity: How clear and unambiguous is the prompt? Are instructions easy to follow?
- specificity: Does it give enough context, constraints, and desired output format?
- efficiency: Is it concise without unnecessary words? Could it achieve the same result with fewer tokens?
- structure: Is the prompt well-organized? Does it use clear sections, formatting, or logical flow?

For "strengths", highlight what the user did well.
For "improvements", give actionable suggestions to make the prompt clearer AND shorter.
For "missing_context", identify specific details the user should add — e.g. audience, tone, format, constraints, examples, edge cases, role/persona, or success criteria that would help the AI understand the task better.
For "questions", list 2-4 clarifying questions the user should answer before submitting this prompt — things that would eliminate ambiguity and produce a much better AI response.
For "optimized", rewrite the prompt to be maximally effective while using fewer tokens. Include any missing context you recommended.

User prompt to analyze:
"""
${prompt}
"""`
        }]
      })
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      return res.status(response.status).json({ error: err.error?.message || 'Claude API error' });
    }

    const data = await response.json();
    const text = data.content[0].text;
    // Extract JSON if wrapped in markdown code fences
    const jsonMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/) || [null, text];
    let jsonStr = jsonMatch[1].trim();
    // Fix newlines inside JSON string values by escaping them properly
    // Replace raw newlines inside strings with \\n
    jsonStr = jsonStr.replace(/"([^"]*?)"/gs, (match) => {
      return match.replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t');
    });
    const result = JSON.parse(jsonStr);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Prompt Analyzer running at http://localhost:${PORT}`);
});
