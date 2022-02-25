const jwt = require('jsonwebtoken');

const jwtSignOption = {
  expiresIn:  "10min",
  algorithm:  "RS256"
};
const verifyOptions = {
  expiresIn:  "10min",
  algorithm:  ["RS256"]
};

function signJwt(payload) {
  return jwt.sign(payload, process.env.PRIVATE_KEY, jwtSignOption);
}

function verifyJwt(token) {
  try {
    const decoded = jwt.verify(token, process.env.PUBLIC_KEY, verifyOptions);
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

module.exports = {
  signJwt, verifyJwt
}