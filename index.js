var _ = require('lodash');
var shortid = require('shortid');
var async = require('async');
var debug = require('debug')('4front:membership');
var jwt = require('jwt-simple');

require('simple-errors');

var userNameRegexPattern = /[a-z\-\.]{2,20}/i;

// The set of recognized user properties that should be copied over
// from the providerUser to the 4front user.
var addtlProviderUserProperties = ['username', 'avatar', 'email', 'displayName'];

module.exports = function(options) {
  if (!options.database)
    throw new Error("Missing database option");

  if (!_.isArray(options.identityProviders) || options.identityProviders.length === 0)
    throw new Error("No identityProviders specified");

  if (!options.jwtTokenSecret)
    throw new Error("Missing jwtTokenSecret option");

  _.defaults(options || {}, {
    jwtTokenExpireMinutes: 30 // Default to JWT expiration of 30 minutes
  });

  var exports = {};

  // Create a new user
  exports.createUser = function(providerUser, callback) {
    // Validate user details
    if (_.isEmpty(providerUser.username) || userNameRegexPattern.test(providerUser.username) !== true)
      return callback(Error.create("Invalid username", {code: "invalidUsername"}));

    debug("creating user %s", providerUser.username);

    getIdentityProvider(providerUser.provider, function(err, identityProvider) {
      if (err) return callback(err);

      // If the providerUserId is not known, ask the identityProvider to translate
      // the username to potentially some other unique identifier.
      if (!providerUser.userId) {
        identityProvider.getUserId(providerUser.username, function(err, userId) {
          if (err) return callback(err);

          providerUser.userId = userId;
          createUser(providerUser, identityProvider, callback);
        });
      }
      else {
        createUser(providerUser, identityProvider, callback);
      }
    });
  };

  // Update the user's profile
  exports.updateProfile = function(user, callback) {
    var userId = user.userId;
    var updateAttributes = _.pick(addtlProviderUserProperties);

    if (_.isEmpty(updateAttributes))
      return callback(null, user);

    options.database.updateUser(user, callback);
  };

  // Find a user with the specified username
  exports.findUser = function(query, providerName, callback) {
    if (_.isFunction(providerName)) {
      callback = providerName;
      providerName = null;
    }

    getIdentityProvider(providerName, function(err, identityProvider) {
      if (err) return callback(err);

      // First check if a providerUserId is specified
      if (query.providerUserId) {
        options.database.findUser(providerUserId, identityProvider.providerName, callback);
      }
      // If there's a username, ask the identityProvider to translate the username
      // to some posssibly different unique id.
      else if (query.username) {
        query.username = query.username.toLowerCase();
        identityProvider.getUserId(query.username, function(err, userId) {
          if (err) return callback(err);

          options.database.findUser(userId, identityProvider.providerName, callback);
        });
      }
      else {
        callback(new Error("Either username or providerUserId must be provided in the query arg"));
      }
    });
  };

  // Special login for when the providerUser object is already in possession by the caller.
  exports.providerLogin = function(providerUser, providerName, callback) {
    if (_.isFunction(providerName)) {
      callback = providerName;
      providerName = providerUser.provider;
    }

    getIdentityProvider(providerName, function(err, identityProvider) {
      if (err) return callback(err);

      providerLogin(providerUser, identityProvider, callback);
    });
  };

  // Login with a username and password
  exports.login = function(username, password, providerName, callback) {
    var providerUser, loggedInUser;

    if (_.isFunction(providerName)) {
      callback = providerName;
      providerName = null;
    }

    getIdentityProvider(providerName, function(err, identityProvider) {
      if (err) return callback(err);

      // Force all usernames to be lowercase to avoid case differences
      // when looking up a user.
      username = username.toLowerCase();

      debug("authenticating user %s with provider %s", username, identityProvider.providerName);
      identityProvider.authenticate(username, password, function(err, providerUser) {
        if (err) return callback(err);

        if (!providerUser)
          return callback(Error.create("Could not authenticate user", {code: 'invalidCredentials'}));

        providerLogin(providerUser, identityProvider, callback);
      });
    });
  };

  return exports;

  function createUser(providerUser, identityProvider, callback) {
    debug("create user %s", providerUser.username);

    var userData = _.extend({
      // Support special case where the new Aerobatic user has the same
      // id as the providerUser.
      userId: providerUser.forceSameId === true ? providerUser.userId : shortid.generate(),
      providerUserId: providerUser.userId,
      provider: identityProvider.providerName,
      lastLogin: new Date()
    }, _.pick(providerUser, addtlProviderUserProperties));

    options.database.createUser(userData, callback);
  }

  function providerLogin(providerUser, identityProvider, callback) {
    var loggedInUser;
    async.series([
      function(cb) {
        debug("find user %s", providerUser.userId);
        options.database.findUser(providerUser.userId, identityProvider.providerName, function(err, user) {
          if (err) return cb(err);
          loggedInUser = user;
          cb();
        });
      },
      function(cb) {
        if (!loggedInUser) {
          options.logger.info({
            code: "4front:login:newUserCreated",
            provider:identityProvider.providerName,
            username: providerUser.username
          }, "New user");

          createUser(providerUser, identityProvider, function(err, user) {
            if (err) return cb(err);
            loggedInUser = user;
            cb();
          });
        }
        else {
          options.logger.info({
            code: "4front:login:userLoggedIn",
            provider:identityProvider.providerName,
            username: loggedInUser.username
          }, "User login");

          debug("update login data for user %s", loggedInUser.username);
          // Tack on additional attributes to the user.
          _.extend(loggedInUser, _.pick(providerUser, addtlProviderUserProperties));

          loggedInUser.lastLogin = new Date();
          options.database.updateUser(loggedInUser, cb);
        }
      }
    ], function(err) {
      if (err) return callback(err);

      // Create a JWT for the user
      // Generate a login token that expires in the configured number of minutes
      var expires = Date.now() + (1000 * 60 * options.jwtTokenExpireMinutes);

      debug("issuing jwt expiring in %s minutes", options.jwtTokenExpireMinutes);
      var token = jwt.encode({
        iss: loggedInUser.userId,
        exp: expires
      }, options.jwtTokenSecret);

      loggedInUser.jwt = {
        expires: expires,
        token: token
      };

      // Tack on the groups and roles from the providerUser. This is only
      // applicable to some identity providers like ldap.
      _.extend(loggedInUser, _.pick(providerUser, 'groups', 'roles'));

      callback(null, loggedInUser);
    });
  }

  function getIdentityProvider(providerName, callback) {
    // If no identity provider is specified, use the default one
    var provider;
    if (_.isEmpty(providerName)) {
      provider = _.find(options.identityProviders, {default: true});

      // If no identityProvider was explicitly specified
      // as the default, use the first one.
      if (!provider)
        provider = options.identityProviders[0];
    }
    else {
      provider = _.find(options.identityProviders, {name: providerName});
      if (!provider)
        return callback(Error.create("Invalid identityProvider " + providerName, {code: "invalidIdentityProvider"}));
    }

    callback(null, provider);
  }
};
