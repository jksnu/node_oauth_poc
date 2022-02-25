const util = require('../util/utils');
const jwtutil = require("../util/jwt_utils");

function authenticate(req, res, next) {
  try {
    const loginFailedJson = {
      "status": "failed",
      "message": "Either auth token is expired or invalid. Please login again"
    };
    const authToken = req.headers["authorization"];
    if(!authToken || authToken.indexOf('null') !== -1) {
      res.status(401).json(loginFailedJson);
    } else {
      const tokenParts = authToken.split(" ");
      const token = tokenParts[1];
      const tokenVerifyRes = jwtutil.verifyJwt(token);
      if(!tokenVerifyRes.valid || tokenVerifyRes.expired || !tokenVerifyRes.decoded) {
        res.status(401).json(loginFailedJson);  
      } else {
        const userSession = util.getActiveUserSession(tokenVerifyRes.decoded.email);
        if(userSession && userSession.length === 1) {
          req["authUser"] = {
            email: userSession[0].email,
            id: userSession[0].identityProviderDetail.id
          }
          next();
        }else {
          res.status(401).json(loginFailedJson);
        }        
      }      
    }    
  } catch (error) {
    console.error(error);
    res.status(401).json(loginFailedJson)
  }
}

module.exports = {
  authenticate
}