const express = require('express');
const dotenv = require('dotenv');
const path = require('path');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const createError = require('http-errors');
const cors = require('cors');
const oauthRoute = require('./routes/auth_routes');
const authMiddleWare = require('./middleware/auth');
const fs = require('fs');
const jose = require('node-jose');

const port = 7000;
const app = express(); 
dotenv.config({
  path: path.join(__dirname, '../.env')
});

//middleware
app.use(express.json()); 
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

//csrf middle ware
var csrfProtection = csrf({ cookie: true });
/*app.all('*', (req, res, next) => {
  if(process.env.NODE_ENV === 'development') {
    return next();
  } else {
    return csrfProtection(req, res, next);
  }
}, (req, res, next) => {
  //res.cookie('XSRF-TOKEN', req.csrfToken());
  next();
});*/
app.use(csrfProtection);

//CORS middle ware
const corsOptions = {
  origin: (origin, callback) => {
    if (process.env.ALLOWED_ORIGINS && process.env.NODE_ENV !== 'development') {
      const whiteList = process.env.ALLOWED_ORIGINS.split(',');
      if(whiteList.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    } else {
      callback(null, true);
    }
  },
  methods: ['GET','POST','DELETE','UPDATE','PUT','PATCH', 'OPTION'],
  allowedHeaders: [
    'Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization', 'csrf-token',
    'xsrf-token', 'x-csrf-token', 'x-xsrf-token'
  ]
}
app.use(cors(corsOptions));

app.use('/oauth', oauthRoute) //oauth route

//routes
app.get('/', (req, res) => {
  res.cookie('XSRF-TOKEN', req.csrfToken(), { httpOnly: false });
  res.json({"status": "Success", "message": "Hello world"});
});

/**
 * This JWKS route is used to get the JWK from auth api
 * In real time microservice architecture, all APIs will use this route to get
 * Public key to verify the incoming JWT token
 * This public key can be cached in reddis or mem-cache to avoid triggering this route for 
 * every incoming request.
 */
app.get('/jwks', authMiddleWare.authenticate, async (req, res) => {
  try {
    const ks = fs.readFileSync('./certs/keys.json');
    const keyStore = await jose.JWK.asKeyStore(ks.toString());
    
    res.send(keyStore.toJSON());
  } catch (error) {
    console.error(error);
    res.status(401).json({
      "status": "failed",
      "message": "Error occurred"
    })
  }  
})

//handling unhandled error
app.use((err, req, res, next) => {
  if (err.code == 'EBADCSRFTOKEN') {
    // handle CSRF token errors here
    res.status(403).json({ code: 403, message: err.message });
  } else {
    return next(createError(404));
  } 
});

app.listen(port, () => {
  console.log(`app is listening at port ${port} by Process ${process.pid}`);
});



