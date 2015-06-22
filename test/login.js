var assert = require('assert');
var _ = require('lodash');
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
    this.providerName = 'dummy';

    this.options = {
      jwtTokenSecret: 'token_secret',
      database: {
        findUser: sinon.spy(function(providerUserId, providerName, callback) {
          callback(null, {
            userId: self.userId,
            providerUserId: providerUserId,
            provider: providerName
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
      logger: {
        info: _.noop
      },
      identityProviders: [
        {
          name: this.providerName,
          authenticate: function(username, password, callback) {
            callback(null, {
              userId: self.providerUserId,
              username: username,
              email: 'test@email.com',
              provider: self.providerName
            });
          }
        }
      ]
    };

    this.login = login(this.options);
  });

  it('missing provider user throws invalidCredentials error', function(done) {
    this.options.identityProviders[0].authenticate = function(username, password, callback) {
      callback(null, null);
    };

    this.login('username', 'password', this.providerName, function(err, user) {
      assert.equal(err.code, 'invalidCredentials');
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

  it('uses default identityProvider if none specified', function(done) {
    this.options.identityProviders[0].default = true;

    this.login('username', 'password', null, function(err, user) {
      if (err) return done(err);

      assert.equal(user.provider, self.providerName);
      assert.ok(self.options.database.findUser.calledWith(self.providerUserId, self.providerName));

      done();
    });
  });

  it('throws error if no default identity provider', function(done) {
    this.login('username', 'password', null, function(err, user) {
      assert.ok(/No default identityProvider/.test(err.message));
      done();
    });
  });

  it('providerUser for of login function', function(done) {
    this.options.database.findUser = sinon.spy(function(providerUserId, provider, callback) {
      callback(null, null);
    });

    var providerUser = {
      userId: shortid.generate(),
      username: 'bob',
      email: 'bob@test.com',
      forceSameId: true
    };

    this.login(providerUser, 'provider', function(err, user) {
      assert.equal(user.providerUserId, providerUser.userId);

      // The forceSameId property should cause the user to inherit the
      // providerUserId.
      assert.equal(user.userId, providerUser.userId);
      assert.equal(user.username, providerUser.username);

      done();
    });
  });
});
