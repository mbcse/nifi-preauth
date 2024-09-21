const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const { exec } = require('child_process');
const cors = require('cors');

const app = express();

app.use(logger('dev'));

const timeoutWindow = 180000;
let timeoutIds = {};

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST'],
    credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/preauth', async (req, res) => {
    const { clientmac, clientip } = req.body;

    if (!clientmac && !clientip) {
        return res.status(400).json({ message: 'Client MAC or IP address is required.' });
    }

    const success = await authorize(clientip);
    if (success) {
        res.status(200).json({ message: 'Preauthorization successful.' });
    } else {
        res.status(500).json({ message: 'Preauthorization failed.' });
    }
});

app.post('/api/unauth', async (req, res) => {
    const { clientip } = req.body;

    if (!clientip) {
        return res.status(400).json({ message: 'Client IP address is required.' });
    }

    const success = await deauthorize(clientip);
    if (success) {
        res.status(200).json({ message: 'Unauthorization successful.' });
    } else {
        res.status(500).json({ message: 'Unauthorization failed.' });
    }
});

app.post('/api/verified', (req, res) => {
    const { clientip } = req.body;

    if (!clientip) {
        return res.status(400).json({ message: 'Client IP address is required.' });
    }

    clearTimeout(timeoutIds[clientip]);
    delete timeoutIds[clientip];

    res.status(200).json({ message: 'Verified successful.' });
});

const authorize = (clientip) => {
    return new Promise((resolve, reject) => {
        if (!timeoutIds.hasOwnProperty(clientip)) {
            exec(`sudo /usr/bin/ndsctl auth ${clientip}`, (error, stdout, stderr) => {
                if (error) {
                    console.error(`Preauth error: ${error}`);
                    return resolve(false);
                }
                console.log(`Preauthorized client: ${clientip}`);

                timeoutIds[clientip] = setTimeout(() => {
                    deauthorize(clientip);
                }, timeoutWindow);

                resolve(true);
            });
        } else {
            clearTimeout(timeoutIds[clientip]);
            timeoutIds[clientip] = setTimeout(() => {
                deauthorize(clientip);
            }, timeoutWindow);
            resolve(true);
        }
    });
};

const deauthorize = (clientip) => {
    return new Promise((resolve, reject) => {
        exec(`sudo /usr/bin/ndsctl deauth ${clientip}`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Unauth error: ${error}`);
                return resolve(false);
            }
            console.log(`Unauthorized client: ${clientip}`);
            clearTimeout(timeoutIds[clientip]);
            delete timeoutIds[clientip];
            resolve(true);
        });
    });
};

module.exports = app;
