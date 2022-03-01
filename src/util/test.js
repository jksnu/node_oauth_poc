/*const fs = require('fs');

const fdata = fs.readFileSync('../../certs/private.pem', "utf8");

console.log(fdata);*/

const jose = require('node-jose');
const fs = require('fs');

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