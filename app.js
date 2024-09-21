var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const { exec } = require('child_process');
var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var cors = require('cors')


var app = express();

app.use(logger('dev'));
app.use(cors({
    origin: '*', // Replace with your frontend domain
    methods: ['GET', 'POST'],
    credentials: true, // Enable this if your request requires cookies or authentication
  }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);
app.post('/api/preauth', (req, res) => {
    const { clientmac, clientip } = req.body;

    if (!clientmac && !clientip) {
        return res.status(400).json({ message: 'Client MAC or IP address is required.' });
    }

    // Preauthorize using the MAC address
    exec(`sudo ndsctl auth ${clientip}`, (error, stdout, stderr) => {
        if (error) {
            console.error(`Preauth error: ${error}`);
            console.log(error)
            return res.status(500).json({ message: 'Preauthorization failed.' });
        }
        console.log(`Preauthorized client: ${clientip}`);
        res.status(200).json({ message: 'Preauthorization successful.' });
    });
});

/**
 * API for Unauthorization
 * Unauthorize a client after authentication
 */
app.post('/api/unauth', (req, res) => {
    console.log(req)
    const { clientip } = req.body;

    if (!clientip) {
        return res.status(400).json({ message: 'Client Ip address is required.' });
    }

    // Unauthorize the client using the MAC address
    exec(`sudo ndsctl unauth ${clientip}`, (error, stdout, stderr) => {
        if (error) {
            console.error(`Unauth error: ${error}`);
            return res.status(500).json({ message: 'Unauthorization failed.' });
        }
        console.log(`Unauthorized client: ${clientmac}`);
        res.status(200).json({ message: 'Unauthorization successful.' });
    });
});

module.exports = app;
