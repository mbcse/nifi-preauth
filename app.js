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

const timeoutWindow = 180000

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

let timeoutIds = {
}

setInterval(() => {
    console.log('Timeouts:', timeoutIds);
},5000)

app.post('/api/preauth', (req, res) => {
    const { clientmac, clientip } = req.body;

    if (!clientmac && !clientip) {
        return res.status(400).json({ message: 'Client MAC or IP address is required.' });
    }

    // Preauthorize using the MAC address

    const success = authorize(clientip)
    if(success){
        res.status(200).json({ message: 'Preauthorization successful.' });
    }else{
        res.status(500).json({ message: 'Preauthorization failed.' });
    }   


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

    const success = deauthroize(clientip)

    if(success){
        res.status(200).json({ message: 'Unauthorization successful.' });
    }else
    {
        res.status(500).json({ message: 'Unauthorization failed.' });
    }
   
});


app.post('/api/verified', (req, res) => {
    console.log(req)
    const { clientip } = req.body;

    if (!clientip) {
        return res.status(400).json({ message: 'Client Ip address is required.' });
    }

    clearTimeout(timeoutIds[clientip]);
    delete timeoutIds[clientip];

    res.status(200).json({ message: 'Verified successful.' });
   
});


const authorize = (clientip, res) => {
    try{

        if(!timeoutIds.hasOwnProperty(clientip)){
            exec(`sudo /usr/bin/ndsctl auth ${clientip}`, (error, stdout, stderr) => {
                if (error) {
                    console.error(`Preauth error: ${error}`);
                    console.log(error)
                    return false;
                }
                console.log(`Preauthorized client: ${clientip}`);

                timeoutIds[clientip] = setTimeout(() => {
                    deauthroize(clientip)
                }, timeoutWindow);

                return true;
            });

            

        }else{
            clearTimeout(timeoutIds[clientip]);
            timeoutIds[clientip] = setTimeout(() => {
                deauthroize(clientip)
            }, timeoutWindow);
            return true
        }


    }catch(err) {
        console.log(err)
        res.status(500).json({ message: 'Preauthorization failed.' });
        return false;
    }
}


const deauthroize = (clientip, res) => {

     try {
        // Unauthorize the client using the MAC address
        exec(`sudo /usr/bin/ndsctl deauth ${clientip}`, (error, stdout, stderr) => {
           if (error) {
               console.error(`Unauth error: ${error}`);
               return false
           }
           console.log(`Unauthorized client: ${clientip}`);
           clearTimeout(timeoutIds[clientip]);
           delete timeoutIds[clientip];
           return true
       });
       
     } catch (error) {
        console.log(error)
        res.status(200).json({ message: 'Unauthorization successful.' });
        if(timeoutIds.hasOwnProperty(clientip)){
            return false
        }else{
            return true
        }
     }
}

module.exports = app;
