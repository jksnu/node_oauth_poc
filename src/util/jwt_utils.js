const jwt = require('jsonwebtoken');
const fs = require('fs');
const jose = require('node-jose');
const ms = require('ms');

const jwtSignOption = {
  expiresIn:  "10min",
  algorithm:  "RS256"
};
const verifyOptions = {
  expiresIn:  "10min",
  algorithm:  ["RS256"]
};

/**
 * This function is signing the JWT token by using public key from private.pem file
 * @param {*} payload 
 * @returns 
 */
function signJwt(payload) {
  try {
    const privateKey = fs.readFileSync('./certs/private.pem', "utf8");
    return jwt.sign(payload, privateKey, jwtSignOption);
  } catch (error) {
    throw error 
  }  
}

/**
 * This function is verifying the JWT token by using public key from public.pem file
 * @param {*} token 
 * @returns 
 */
function verifyJwt(token, publicKey) {
  try {
    const decoded = jwt.verify(token, publicKey, verifyOptions);
    return {
      valid: true,
      expired: false,
      decoded,
    };
  } catch (e) {
    console.error(e);
    return {
      valid: false,
      expired: e.message === "jwt expired",
      decoded: null,
    };
  }
}

/**
 * This function is signing the JWT token by using node-jose package by getting data from keys.json
 * keys.json file is being generated by generateKeysByJose() in this jwt_utils class
 * @param {*} payload 
 * @returns 
 */
 async function signJwtByJose(payload) {
  try {
    const ks = fs.readFileSync('./certs/keys.json')
    const keyStore = await jose.JWK.asKeyStore(ks.toString())
    const [key] = keyStore.all({ use: 'sig' })
    
    const opt = { compact: true, jwk: key, fields: { typ: 'jwt' } }
    const tokenPayload = JSON.stringify({
      exp: Math.floor((Date.now() + ms('10m')) / 1000),
      iat: Math.floor(Date.now() / 1000),
      sub: payload,
    })
    const token = await jose.JWS.createSign(opt, key)
      .update(tokenPayload)
      .final()
    return token;
  } catch (error) {
    throw error 
  }  
}

/**
 * It is used to generate public and private key in keys.json file by using node-jose package
 * It is alternate of directly using public.pem and private.pem
 * It is mainly used to implement JWKS
 */
function generateKeysByJose() {
  const keyStore = jose.JWK.createKeyStore()
  keyStore.generate('RSA', 2048, {alg: 'RS256', use: 'sig' })
  .then(result => {
    fs.writeFileSync(
      'keys.json', 
      JSON.stringify(keyStore.toJSON(true), null, '  ')
    )
  })
  .catch(e => {
    console.error(e);
  });
}

module.exports = {
  signJwt, verifyJwt, signJwtByJose
}