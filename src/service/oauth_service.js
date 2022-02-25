const constObj = require('../util/constants');
const axios = require('axios');
const qs = require('qs');

async function getGoogleOauthToken(code) {
  try {
    const url = constObj.GOOGLE_OAUTH_ATTRIBUTE.GOOGLE_OAUTH_TOKEN_API;
    const inputBody = {
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: constObj.GOOGLE_OAUTH_ATTRIBUTE.TOKEN_REDIRECT_API,
      grant_type: constObj.GOOGLE_OAUTH_ATTRIBUTE.GRANT_TYPE
    }
    const res = await axios.post(url, 
      qs.stringify(inputBody),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        }
      });
    return res.data;
  } catch (error) {
    console.error(error);
    throw error;
  }
}

async function getGoogleUser(id_token, access_token) {
  try {
    const url = `${constObj.GOOGLE_OAUTH_ATTRIBUTE.GOOGLE_OAUTH_USER_API}?alt=json&access_token=${access_token}`;
    const res = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${id_token}`
      }
    });
    return res.data;
  } catch (error) {
    console.error(error);
    throw error;
  }
}

module.exports = {
  getGoogleOauthToken, getGoogleUser
}