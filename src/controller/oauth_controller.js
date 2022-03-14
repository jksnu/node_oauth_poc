const authService = require('../service/oauth_service');
const util = require('../util/utils');
const jwtUtil = require('../util/jwt_utils');

async function googleOauthHandler(req, res) {
  try {
    //get auth code from query string
    const code = req.query.code;

    //get id and access token with the code
    const userTokenData = await authService.getGoogleOauthToken(code);
    const userData = await authService.getGoogleUser(userTokenData.id_token, userTokenData.access_token);
    if(!userData.verified_email) {
      throw new Error("Google user's email is not verified");
    }

    //upsert the user. This should be actually DB operation
    const otherData = {
      "Name": userData.name,
      "Provider": "Google",
      "idFromProvider": userData.id,
      "loggedIn": true
    }
    util.addUser(userData.email, undefined, otherData);

    //create a session
    //Here we should create a session object and keep in db
    //As I have not implemented Db for this POC, so I am keeping it in a class variable
    util.logoutPreviousSession(userData.email);
    let sessionTemplate = util.getSessionTemplate();
    sessionTemplate.email = userData.email;
    sessionTemplate.identityProviderType = "Google";
    sessionTemplate.identityProviderDetail = {
      id: userData.id
    };
    sessionTemplate.timestamp = new Date();
    sessionTemplate.isActiveNow = true;  
    sessionTemplate.userAgent = req.headers["user-agent"] || "";
    util.createSesssion(sessionTemplate);

    //Create access and refresh token
    const jwtPayload = {
      "username": userData.name,
      "email": userData.email
    };
    //const accessToken = jwtUtil.signJwt(jwtPayload); //Signing by reading private key from private.pem
    const accessToken = await jwtUtil.signJwtByJose(jwtPayload); //Signing by JOSE package by reading data from keys.json
    

    //set cookies

    //redirect back to client
    //return {"access_token": accessToken};
    res.redirect("http://localhost:4200/#/login?access_token="+accessToken);
  } catch (error) {
    console.error(error);
    res.status(401).redirect("http://localhost:4200/#/login?staus=failed");
  }  
}

module.exports = {
  googleOauthHandler
}