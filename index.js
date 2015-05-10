var _ = require('lodash');
var shortid = require('shortid');
var async = require('async');
var debug = require('debug')('4front:user-login');
var jwt = require('jwt-simple');

module.exports = function(options) {
  if (!options.database)
    throw new Error("Missing database option");

  if (_.isObject(options.identityProviders) === false)
    throw new Error("Missing identityProviders option");

  if (!options.jwtTokenSecret)
    throw new Error("Missing jwtTokenSecret option");

  _.defaults(options || {}, {
    jwtTokenExpireMinutes: 30 // Default to JWT expiration of 30 minutes
  });

  return function(username, password, providerName, callback) {
    var loggedInUser;

    var identityProvider = options.identityProviders[providerName];
    if (!identityProvider)
      return callback(new Error("Invalid identityProvider " + providerName));

    identityProvider.authenticate(username, password, function(err, providerUser) {
      if (err) return callback(err);

      if (!providerUser)
        return callback(null, null);

      var user;
      async.series([
        function(cb) {
          getExistingUser(providerUser, providerName, cb);
        },
        function(cb) {
          if (!loggedInUser)
            createUser(providerUser, providerName, cb);
          else
            updateUser(providerUser, cb);
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
    });


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
        userId: shortid.generate(),
        providerUserId: providerUser.userId,
        provider: providerName,
        lastLogin: new Date()
      }, _.omit(providerUser, 'userId'));

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
