const express = require('express');
const router = express.Router();
const path = require('path');

// --- APIs ---

// Simple test route
router.get("/download/docs/hello", (req, res) => {
            return res.status(403).send('test');
});
// Nested routes for /api/download/latest
//router.use('/download/docs', require('./users'));


// --- Frontend Static Routes (Vite or React) ---

// Serve static files
router.use(express.static(path.join(__dirname, '../../frontend/dist')));

// Serve index.html on root
router.get('/', function (req, res) {
  res.sendFile(path.join(__dirname, '../../frontend/dist', 'index.html'));
});

// Fallback (must go last)
router.get('*', function (req, res) {
  res.status(404).json({ error: "Not Found" }); // safer for API fallback
});

module.exports = router;
