const express = require('express');
const router = express.Router();
const utils = require('../util/utils');

router.post('/registerUser', (req, res) => {  
  const username = req.body.username;
  const password = req.body.password;
  utils.addUser(username, password);
  res.json('User is registered successfully');
});

router.get('/users', (req, res) => {
  res.json(utils.getUsers());
});

router.delete('/delete/:username', (req, res) => {
  const username = req.params.username;
  const user = utils.getUser(username);
  utils.deleteUser(username);
  if(user && user.length > 0 && user[0].identityProvider) {
    utils.deactivateSession(user[0].identityProvider.idFromProvider);
  }  
  res.json("User is deleted successfully");
});

router.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  utils.login(username, password);
  res.json("User has logged in successfully");
});

router.post('/logout', (req, res) => {
  const username = req.body.username;
  utils.logout(username);
  utils.deactivateSession(req.authUser.id);
  res.json("User has logged out successfully");
});

module.exports = router;