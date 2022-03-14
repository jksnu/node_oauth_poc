const util = require('../util/utils');
const jwtutil = require("../util/jwt_utils");
const fs = require('fs');
const jose = require('node-jose');
const jwktopem = require('jwk-to-pem');

async function authenticate(req, res, next) {
  const loginFailedJson = {
    "status": "failed",
    "message": "Either auth token is expired or invalid. Please login again"
  };
  try {    
    const authToken = req.headers["authorization"];
    if(!authToken || authToken.indexOf('null') !== -1) {
      res.status(401).json(loginFailedJson);
    } else {
      const tokenParts = authToken.split(" ");
      const token = tokenParts[1];
      /**
       * Verifying JWT token by reading public key from public.pem
       */
      //const publicKey = getPublicKeyFromPublicPem();
      //const tokenVerifyRes = jwtutil.verifyJwt(token, publicKey); 
      //const userDecodedResult = tokenVerifyRes.decoded;

      /**
       * Here, verifying token by using public key from keys.json by using node-jose package
       */
      const publicKey = await getPublicKeyByJose();
      const tokenVerifyRes = jwtutil.verifyJwt(token, publicKey);
      const userDecodedResult = tokenVerifyRes.decoded.sub;

      if(!tokenVerifyRes.valid || tokenVerifyRes.expired || !userDecodedResult) {
        res.status(401).json(loginFailedJson);  
      } else {
        //const userSession = util.getActiveUserSession(userDecodedResult.email);
        util.getActiveUserSession(userDecodedResult.email);
        /**
         * Here, user details got from the incoming authrization token must be verified from DB
         * As, I have not implemented db in this POC, 
         * So I am skipping this verification
         */
        /*if(userSession && userSession.length === 1) {
          req["authUser"] = {
            email: userSession[0].email,
            id: userSession[0].identityProviderDetail.id
          }
          next();
        }else {
          res.status(401).json(loginFailedJson);
        }  */
        req["authUser"] = {
          email: userDecodedResult.email
        }
        next(); //This next() should be trigger if user details is verified from db in above commented code      
      }   
    }    
  } catch (error) {
    console.error(error);
    res.status(401).json(loginFailedJson)
  }
}
/**
 * Reading key from public .pem file
 * @returns 
 */
/*function getPublicKeyFromPublicPem() {
  try {
    const publicKey = fs.readFileSync('./certs/public.pem', "utf8");
    return publicKey;
  } catch (error) {
    throw error;
  }
}*/

async function getPublicKeyByJose() {
  try {    
    const ks = fs.readFileSync('./certs/keys.json');
    const keyStore = await jose.JWK.asKeyStore(ks.toString());
    const keyStoreJson = keyStore.toJSON();
    const [ firstKey ] = keyStoreJson.keys;
    const publicKey = jwktopem(firstKey);
    return publicKey;
  } catch (error) {
    console.error(error);
    throw error;
  }
}

module.exports = {
  authenticate
}