var assert = require('assert');
var shortid = require('shortid');
var sinon = require('sinon');
var jwt = require('jwt-simple');
var login = require('..');

require('dash-assert');

describe('login', function() {
  var self;

  beforeEach(function() {
    self = this;

    this.userId = shortid.generate();
    this.providerUserId = shortid.generate();
    this.providerName = 'ActiveDirectory';

    this.options = {
      jwtTokenSecret: 'token_secret',
      database: {
        findUser: sinon.spy(function(providerUserId, provider, callback) {
          callback(null, {
            userId: self.userId,
            providerUserId: providerUserId,
            provider: provider
          });
        }),
        createUser: sinon.spy(function(userData, callback) {
          callback(null, userData);
        }),
        updateUser: sinon.spy(function(userData, callback) {
          callback(null, userData);
        }),
        listUserOrgs: function(userId, callback) {
          callback(null, [{orgId: '1', name: 'test org'}])
        }
      },
      identityProviders: {
        ActiveDirectory: {
          authenticate: function(username, password, callback) {
            callback(null, {
              userId: self.providerUserId,
              username: username,
              email: 'test@email.com'
            });
          }
        }
      }
    };

    this.login = login(this.options);
  });

  it('missing provider user returns null', function(done) {
    this.options.identityProviders.ActiveDirectory.authenticate = function(username, password, callback) {
      callback(null, null);
    };

    this.login('username', 'password', this.providerName, function(err, user) {
      if (err) return done(err);

      assert.isNull(user);
      done();
    });
  });

  it('creates new user', function(done) {
    this.options.database.findUser = sinon.spy(function(providerUserId, provider, callback) {
      callback(null, null);
    });

    this.login('username', 'password', this.providerName, function(err, user) {
      if (err) return done(err);

      assert.isTrue(self.options.database.findUser.calledWith(self.providerUserId, self.providerName));
      assert.isTrue(self.options.database.createUser.calledWith(sinon.match({
        providerUserId: self.providerUserId,
        provider: self.providerName,
        email: 'test@email.com'
      })));
      assert.isFalse(self.options.database.updateUser.called);

      assert.equal(user.providerUserId, self.providerUserId);
      done();
    });
  });

  it('updates existing user', function(done) {
    this.login('username', 'password', this.providerName, function(err, user) {
      if (err) return done(err);

      assert.isTrue(self.options.database.findUser.calledWith(
        self.providerUserId, self.providerName));

      assert.isTrue(self.options.database.updateUser.calledWith(sinon.match({
        providerUserId: self.providerUserId,
        provider: self.providerName,
        email: 'test@email.com'
      })));

      assert.isFalse(self.options.database.createUser.called);

      assert.equal(user.providerUserId, self.providerUserId);
      done();
    });
  });

  it('gets back a valid JWT', function(done) {
    this.login('username', 'password', this.providerName, function(err, user) {
      if (err) return done(err);

      assert.isObject(user.jwt);
      assert.isNumber(user.jwt.expires);
      assert.isTrue(user.jwt.expires > Date.now());
      assert.isString(user.jwt.token);

      var accessToken = jwt.decode(user.jwt.token, self.options.jwtTokenSecret);
      assert.equal(accessToken.exp, user.jwt.expires);

      done();
    });
  });

  it('throws error for invalid identity provider', function(done) {
    this.login('username', 'password', 'InvalidProvider', function(err, user) {
      assert.isNotNull(err);
      assert.ok(/Invalid identityProvider/.test(err.message));
      done();
    });
  });
});
