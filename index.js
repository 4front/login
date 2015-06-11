var _ = require('lodash');
var shortid = require('shortid');
var async = require('async');
var debug = require('debug')('4front:login');
var jwt = require('jwt-simple');

module.exports = function(options) {
  if (!options.database)
    throw new Error("Missing database option");

  if (_.isArray(options.identityProviders) === false || options.identityProviders.length === 0)
    throw new Error("No identityProviders specified");

  if (!options.jwtTokenSecret)
    throw new Error("Missing jwtTokenSecret option");

  _.defaults(options || {}, {
    jwtTokenExpireMinutes: 30 // Default to JWT expiration of 30 minutes
  });

  return function(username, password, providerName, callback) {
    var providerUser, identityProvider, loggedInUser;

    // Allow for an alternative call where the first argument is
    // the providerUser rather than username/password.
    if (_.isObject(username)) {
      providerUser = username;
      callback = providerName;
      providerName = password;

      return providerLogin(providerUser, providerName, callback);
    }

    // Force all usernames to be lowercase to avoid case differences
    // when looking up a user.
    username = username.toLowerCase();

    // If no identity provider is specified, use the default one
    if (_.isEmpty(providerName)) {
      identityProvider = _.find(options.identityProviders, {default: true});
      if (!identityProvider)
        return callback(new Error("No default identityProvider found"));

      providerName = identityProvider.name;
    }
    else {
      identityProvider = _.find(options.identityProviders, {name: providerName});
      if (!identityProvider)
        return callback(new Error("Invalid identityProvider " + providerName));
    }

    identityProvider.authenticate(username, password, function(err, user) {
      if (err) return callback(err);

      providerUser = user;
      if (!providerUser)
        return callback(null, null);

      providerLogin(providerUser, providerName, callback);
    });

    function providerLogin(providerUser, providerName, callback) {
      var user;
      async.series([
        function(cb) {
          getExistingUser(providerUser, providerName, cb);
        },
        function(cb) {
          if (!loggedInUser) {
            options.logger.info({code: "4front:login:newUserCreated", provider:providerName, username: username}, "New user");
            createUser(providerUser, providerName, cb);
          }
          else {
            options.logger.info({code: "4front:login:userLoggedIn", provider:providerName, username: username}, "User login");
            updateUser(providerUser, cb);
          }
        },
        function(cb) {
          // Load user details
          loadUserDetails(cb);
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

        callback(null, loggedInUser);
      });
    }

    function getExistingUser(providerUser, providerName, cb) {
      options.database.findUser(providerUser.userId, providerName, function(err, user) {
        if (err) return cb(err);
        loggedInUser = user;
        cb();
      });
    }

    function createUser(providerUser, providerName, cb) {
      debug("user %s does not exist, creating.", providerUser.userId);

      var userData = _.extend({
        // Support special case where the new Aerobatic user has the same
        // id as the providerUser.
        userId: providerUser.forceSameId === true ? providerUser.userId : shortid.generate(),
        providerUserId: providerUser.userId,
        provider: providerName,
        lastLogin: new Date()
      }, _.pick(providerUser, 'avatar', 'username', 'email'));

      options.database.createUser(userData, function(err, user) {
        if (err) return cb(err);
        loggedInUser = user;
        cb();
      });
    }

    function updateUser(providerUser, cb) {
      debug("update user %s as part of login", loggedInUser.userId);
      // Tack on additional attributes to the user.
      _.extend(loggedInUser, _.omit(providerUser, 'userId'));
      loggedInUser.lastLogin = new Date();

      options.database.updateUser(loggedInUser, function(err, user) {
        if (err) return cb(err);

        loggedInUser = user;
        cb();
      });
    }

    function loadUserDetails(cb) {
      options.database.listUserOrgs(loggedInUser.userId, function(err, orgs) {
        if (err) return cb(err);

        loggedInUser.orgs = orgs;
        cb();
      });
    }
  };
};
