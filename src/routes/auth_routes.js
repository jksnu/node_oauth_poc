const express = require('express');
const router = express.Router();
const utils = require('../util/utils');
const oauthCtrl = require('../controller/oauth_controller');

//Code for google authentication starts here
router.get('/google', (req, res) => {
  oauthCtrl.googleOauthHandler(req, res)
  .then(data => {
    res.json(data);
  })
  .catch(err => {
    console.error(err);
    res.status(401).json({
      "status": "failed",
      "message": "Login failed"
    })

  })
});
//Code for google authentication ends here

module.exports = router;