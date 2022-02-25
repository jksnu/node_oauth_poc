const users = [{
  "username": "admin",
  "password": "admin",
  "loggedIn": false
}];

const userSessions = [];

function getSessionTemplate() {
  return {
    "email": "",
    "timestamp": "",
    "identityProviderType": "",
    "identityProviderDetail": {},
    "isActiveNow": false,
    "userAgent": ""
  }
}

function logoutPreviousSession(emailId) {
  for(let session of this.userSessions) {
    if(session.email === emailId) {
      session.isActiveNow = false;
    }
  }
}

function createSesssion(sessionObj) {
  this.userSessions.push(sessionObj);
}

function addUser(username, password, identityProvider) {
  const filteredUsers = this.users.filter((user) => {
    if(user.username === username) {
      return true;
    }
  });
  if(filteredUsers.length === 0) {
    this.users.push({
      "username": username,
      "password": password,
      "loggedIn": false,
      "identityProvider": identityProvider
    });
  }
}

function deleteUser(username) {
  const filteredUsers = this.users.filter((user) => {
    if(user.username !== username) {
      return true;
    }
  });
  this.users = filteredUsers;
}

function getUsers() {
  return this.users;
}

function getUser(username) {
  return this.users.filter(user => user.username === username);
}

function getUserSession(emailId) {
  return this.userSessions.filter(user => user.email === emailId);
}

function getActiveUserSession(emailId) {
  return this.userSessions.filter(user => user.email === emailId && user.isActiveNow);
}

function login(username, password) {
  for(let user of this.users) {
    if(user.username === username && user.password === password) {
      user.loggedIn = true;
    }
  }
}

function logout(username) {
  for(let user of this.users) {
    if(user.username === username) {
      user.loggedIn = false;
    }
  }
}

function deactivateSession(id) {
  for(let user of this.userSessions) {
    if(user.identityProviderDetail.id === id) {
      user.isActiveNow = false;
    }
  }
}

module.exports = {
  addUser, deleteUser, login, logout, getUsers, users, getSessionTemplate, createSesssion, logoutPreviousSession,
  userSessions, getUserSession, deactivateSession, getUser, getActiveUserSession
}