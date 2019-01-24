(function(module) {
	"use strict";

	var User = require.main.require('./src/user'),
		Groups = require.main.require('./src/groups'),
		meta = require.main.require('./src/meta'),
		db = require.main.require('./src/database'),
		passport = module.parent.require('passport'),
		fs = module.parent.require('fs'),
		path = module.parent.require('path'),
		nconf = module.parent.require('nconf'),
		winston = module.parent.require('winston'),
		async = module.parent.require('async'),
		{GraphQLClient} = require('graphql-request');

	var authenticationController = require.main.require('./src/controllers/authentication');
	const query = `{
            my {
              self {
                id
                username
                name
                email
              }
            }
          }`
	var constants = Object.freeze({
			type: 'oauth2',	// Either 'oauth' or 'oauth2'
			name: 'altizure',	// Something unique to your OAuth provider in lowercase, like "github", or "nodebb"
			oauth2: {
				authorizationURL: 'https://api.altizure.cn/auth/start',
				tokenURL: 'https://api.altizure.cn/auth/exchange',
				clientID: 'Sg95ZszwkCjy6ItCzZaDA1IAFxAHTaU4sGNKUVU',
				clientSecret: 'bfPQeuPDE5fxZuui6xv0rIYUA0qxLbjGmkk7guixma'
			},
			userRoute: 'https://api.altizure.com/graphql' // This is the address to your app's "user profile" API endpoint (expects JSON)
		}),
		configOk = false,
		OAuth = {}, passportOAuth, opts;

	if (!constants.name) {
		winston.error('[sso-oauth] Please specify a name for your OAuth provider (library.js:32)');
	} else if (!constants.type || (constants.type !== 'oauth' && constants.type !== 'oauth2')) {
		winston.error('[sso-oauth] Please specify an OAuth strategy to utilise (library.js:31)');
	} else if (!constants.userRoute) {
		winston.error('[sso-oauth] User Route required (library.js:31)');
	} else {
		configOk = true;
	}

	OAuth.getStrategy = function(strategies, callback) {
		if (configOk) {
			passportOAuth = require('passport-oauth')['OAuth2Strategy'];

			if (constants.type === 'oauth2') {
				// OAuth 2 options
				opts = constants.oauth2;
				opts.callbackURL = nconf.get('url') + '/auth/' + constants.name + '/callback';

				passportOAuth.Strategy.prototype.userProfile = function(accessToken, done) {
					const client = new GraphQLClient('https://api.altizure.com/graphql', {
						headers: {
							'method': "POST",
							'Content-Type': 'application/json',
							'key': 'Sg95ZszwkCjy6ItCzZaDA1IAFxAHTaU4sGNKUVU',
							'altitoken': accessToken,
						}
					})
					client.request(query).then(data => {
						try{
							OAuth.parseUserReturn(data.my.self, function(err, profile) {
								if (err) return done(err);
								profile.provider = constants.name;
								done(null, profile);
							});
						}catch (e) {
							done(e)
						}
					})
				};
			}

			opts.passReqToCallback = true;

			passport.use(constants.name, new passportOAuth(opts, function(req, token, secret, profile, done) {
				OAuth.login({
					oAuthid: profile.id,
					handle: profile.displayName,
					email: profile.emails,
					isAdmin: profile.isAdmin
				}, function(err, user) {
					if (err) {
						return done(err);
					}
					authenticationController.onSuccessfulLogin(req, user.uid);
					done(null, user);
				});
			}));

			strategies.push({
				name: constants.name,
				url: '/auth/' + constants.name,
				callbackURL: '/auth/' + constants.name + '/callback',
				icon: 'fa-check-square',
				scope: (constants.scope || '').split(',')
			});

			callback(null, strategies);
		} else {
			callback(new Error('OAuth Configuration is invalid'));
		}
	};

	OAuth.parseUserReturn = function(data, callback) {
		// Alter this section to include whatever data is necessary
		// NodeBB *requires* the following: id, displayName, emails.
		// Everything else is optional.

		// Find out what is available by uncommenting this line:
		// console.log(data);

		var profile = {};
		profile.id = data.id;
		profile.displayName = data.name;
		profile.emails = data.email;

		// Do you want to automatically make somebody an admin? This line might help you do that...
		profile.isAdmin = data.email === '390447783@qq.com' ? true : false;

		// Delete or comment out the next TWO (2) lines when you are ready to proceed
		// process.stdout.write('===\nAt this point, you\'ll need to customise the above section to id, displayName, and emails into the "profile" object.\n===');
		// return callback(new Error('Congrats! So far so good -- please see server log for details'));

		callback(null, profile);
	}

	OAuth.login = function(payload, callback) {
		OAuth.getUidByOAuthid(payload.oAuthid, function(err, uid) {
			if(err) {
				return callback(err);
			}

			if (uid !== null) {
				// Existing User
				callback(null, {
					uid: uid
				});
			} else {
				// New User
				var success = function(uid) {
					// Save provider-specific information to the user
					User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
					db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

					if (payload.isAdmin) {
						Groups.join('administrators', uid, function(err) {
							callback(null, {
								uid: uid
							});
						});
					} else {
						callback(null, {
							uid: uid
						});
					}
				};

				User.getUidByEmail(payload.email, function(err, uid) {
					if(err) {
						return callback(err);
					}

					if (!uid) {
						User.create({
							username: payload.handle,
							email: payload.email
						}, function(err, uid) {
							if(err) {
								return callback(err);
							}

							success(uid);
						});
					} else {
						success(uid); // Existing account -- merge
					}
				});
			}
		});
	};

	OAuth.getUidByOAuthid = function(oAuthid, callback) {
		db.getObjectField(constants.name + 'Id:uid', oAuthid, function(err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	OAuth.deleteUserData = function(data, callback) {
		async.waterfall([
			async.apply(User.getUserField, data.uid, constants.name + 'Id'),
			function(oAuthIdToDelete, next) {
				db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
			}
		], function(err) {
			if (err) {
				winston.error('[sso-oauth] Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
				return callback(err);
			}

			callback(null, data);
		});
	};

	module.exports = OAuth;
}(module));
