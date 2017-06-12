#!/usr/bin/env node
'use strict';


const path = require('path');
const bodyParser = require('body-parser');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const tls = require('tls');
const port = 3000;
//var api = require('./routes/api');

const options = {
    key: fs.readFileSync('certs/private/xbruteserver.key'),
    cert: fs.readFileSync('certs/certs/xbruteserver.crt'),
    ca: fs.readFileSync('certs/certs/xbruteCA.crt'), // authority chain for the clients
    passphrase: 'frasfarfsa',
    requestCert: true, // ask for a client cert
    ciphers: [
 		'ECDHE-RSA-AES128-GCM-SHA256',
 		'ECDHE-ECDSA-AES128-GCM-SHA256',
 		'ECDHE-RSA-AES256-GCM-SHA384',
 		'ECDHE-ECDSA-AES256-GCM-SHA384',
 		'DHE-RSA-AES128-GCM-SHA256',
 		'ECDHE-RSA-AES128-SHA256',
 		'DHE-RSA-AES128-SHA256',
 		'ECDHE-RSA-AES256-SHA384',
 		'DHE-RSA-AES256-SHA384',
 		'ECDHE-RSA-AES256-SHA256',
 		'DHE-RSA-AES256-SHA256',
 		'HIGH',
 		'!aNULL',
 		'!eNULL',
 		'!EXPORT',
 		'!DES',
 		'!RC4',
 		'!MD5',
 		'!PSK',
 		'!SRP',
 		'!CAMELLIA'
	].join(':'),
    honorCipherOrder: true
    //rejectUnauthorized: false, // act on unauthorized clients at the app level
};


var server = tls.createServer(options, (socket) => {
  //socket.write('welcome!\n');
    socket.addListener("data", function (data) {
            console.log("Data received: " + data);
    });
  socket.setEncoding('utf8');
  socket.pipe(socket);
})

.on('connection', function(c)
{
    console.log('insecure connection');
})

.on('secureConnection', function (c)
{
    // c.authorized will be true if the client cert presented validates with our CA
    console.log('secure connection; client authorized: ', c.authorized);
})

.listen(port, function() {
    console.log('server listening on port ' + port + '\n');
});
