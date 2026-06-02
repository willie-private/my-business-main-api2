const express = require('express');
const serverless = require('serverless-http');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const app = express();


// Middleware
app.use(compression());
app.use(helmet());
app.use(cors());
app.use(morgan('dev'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// Prevent .npl downloads
app.use((req, res, next) => {
  if (/\.(npl)$/i.test(req.url) && /Mozilla|Chrome|Firefox|Safari|Edge/i.test(req.get('User-Agent'))) {
    console.log('Blocked .npl file:', req.url);
    return res.status(403).send('');
  }
  next();
});

// Static and routes
app.use(express.static(path.join(__dirname, '../public')));
app.use(require('../app/controllers'));

// 404 handler
app.use((req, res) => {
  res.status(404).send('Not Found');
});

// Vercel export
module.exports = app;
module.exports.handler = serverless(app);

// Local dev
if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`🚀 Local server running at http://localhost:${port}`);
  });
}
