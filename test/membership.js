var assert = require('assert');
var _ = require('lodash');
var shortid = require('shortid');
var sinon = require('sinon');
var jwt = require('jwt-simple');
var membership = require('..');

require('dash-assert');

describe('membership', function() {
  var self;

  beforeEach(function() {
    self = this;

    this.userId = shortid.generate();
    this.providerUserId = shortid.generate().toLowerCase();

    // Currently assuming the providerUserId is the same as the username.
    this.username = this.providerUserId;
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
          callback(null, self.userOrgs);
        }
      },
      logger: {
        info: _.noop
      },
      identityProviders: [{
        providerName: this.providerName,
        authenticate: function(username, password, callback) {
          callback(null, {
            userId: self.providerUserId,
            username: self.username,
            email: 'test@email.com',
            provider: self.providerName
          });
        },
        getUserId: sinon.spy(function(username, callback) {
          callback(null, self.providerUserId);
        })
      }]
    };

    this.membership = membership(this.options);
  });

  describe('login', function() {
    it('missing user throws invalidCredentials error', function(done) {
      this.options.identityProviders[0].authenticate = function(username, password, callback) {
        callback(null, null);
      };

      this.membership.login('username', 'password', function(err) {
        assert.equal(err.code, 'invalidCredentials');
        done();
      });
    });

    it('non-existent provider user creates new user', function(done) {
      this.options.database.findUser = sinon.spy(function(username, provider, callback) {
        callback(null, null);
      });

      this.membership.login('username', 'password', function(err, user) {
        if (err) return done(err);

        assert.isTrue(self.options.database.findUser.calledWith(self.providerUserId, self.providerName));
        assert.isTrue(self.options.database.createUser.calledWith(sinon.match({
          providerUserId: self.providerUserId,
          provider: self.providerName,
          email: 'test@email.com'
        })));
        assert.isFalse(self.options.database.updateUser.called);

        assert.equal(user.providerUserId, self.providerUserId);
        assert.equal(user.username, self.username);

        done();
      });
    });

    it('updates existing user', function(done) {
      this.membership.login(this.username, 'password', function(err, user) {
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
      this.membership.login(self.username, 'password', function(err, user) {
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
      this.membership.login('username', 'password', 'InvalidProvider', function(err) {
        assert.isNotNull(err);
        assert.ok(/Invalid identityProvider/.test(err.message));
        done();
      });
    });

    it('uses default identityProvider if none specified', function(done) {
      this.options.identityProviders[0].default = true;

      this.membership.login(self.username, 'password', null, function(err, user) {
        if (err) return done(err);

        assert.equal(user.provider, self.providerName);
        assert.ok(self.options.database.findUser.calledWith(self.providerUserId, self.providerName));

        done();
      });
    });

    it('throws error if no default identity provider', function(done) {
      this.membership.login('username', 'password', 'invalidProvider', function(err) {
        assert.equal(err.code, 'invalidIdentityProvider');
        done();
      });
    });
  });

  describe('providerLogin', function() {
    it('valid login', function(done) {
      this.options.database.findUser = sinon.spy(function(username, provider, callback) {
        callback(null, null);
      });

      var providerUser = {
        userId: shortid.generate(),
        username: this.username,
        email: 'bob@test.com',
        forceSameId: true
      };

      this.membership.providerLogin(providerUser, function(err, user) {
        assert.equal(user.providerUserId, providerUser.userId);

        // The forceSameId property should cause the user to inherit the
        // providerUserId.
        assert.equal(user.userId, providerUser.userId);
        assert.equal(user.username, providerUser.username);

        done();
      });
    });
  });

  describe('create user', function() {
    it('success', function(done) {
      var providerUser = {
        userId: this.providerUserId,
        username: this.username,
        displayName: 'Bob Smith',
        ignoredProperty: 5
      };

      this.membership.createUser(providerUser, function(err, user) {
        if (err) return done(err);

        assert.isFalse(self.options.identityProviders[0].getUserId.called);

        assert.isTrue(self.options.database.createUser.calledWith(sinon.match({
          providerUserId: self.providerUserId,
          provider: self.providerName,
          username: self.username,
          displayName: 'Bob Smith'
        })));

        assert.ok(_.isDate(user.lastLogin));
        assert.isString(user.userId);

        done();
      });
    });

    it('invalid username returns error', function(done) {
      this.membership.createUser({userId: this.providerUserId, username: '&#$U*$'}, function(err) {
        assert.equal(err.code, 'invalidUsername');
        done();
      });
    });

    it('missing userId causes identityProvider.getUserId to be called', function(done) {
      this.membership.createUser({username: 'joe'}, function(err) {
        assert.ok(self.options.identityProviders[0].getUserId.calledWith('joe'));

        done();
      });
    });
  });

  it('update profile', function(done) {
    var user = {
      userId: self.userId,
      displayName: 'Foo Bar',
      badProperty: 2
    };

    this.membership.updateProfile(user, function(err) {
      if (err) return done(err);

      assert.isTrue(self.options.database.updateUser.calledWith({
        userId: self.userId,
        displayName: user.displayName
      }));

      done();
    });
  });

  describe('find user', function() {
    it('existing user', function(done) {
      this.membership.findUser({username: self.username}, function(err, user) {
        if (err) return done(err);

        assert.isTrue(self.options.identityProviders[0].getUserId.calledWith(self.username));

        assert.isTrue(self.options.database.findUser.calledWith(
          self.providerUserId, self.providerName));

        assert.equal(user.providerUserId, self.providerUserId);
        assert.equal(user.provider, self.providerName);

        done();
      });
    });

    it('missing user', function(done) {
      this.options.database.findUser = function(query, providerName, cb) {
        cb(null, null);
      };

      this.membership.findUser({username: self.username}, function(err, user) {
        if (err) return done(err);

        assert.isNull(user);
        done();
      });
    });
  });
});
