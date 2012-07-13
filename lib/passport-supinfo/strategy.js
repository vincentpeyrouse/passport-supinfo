/**
 * Module dependencies.
 */
var util = require('util')
  , OpenIDStrategy = require('passport-openid').Strategy
  , BadRequestError = require('passport-openid').BadRequestError
  , InternalOpenIDError = require('passport-openid').InternalOpenIDError;

/**
 * `Strategy` constructor.
 *
 * The SUPINFO authentication strategy authenticates requests by delegating to
 * id.supinfo.com using the OpenID 2.0 protocol.
 *
 * Applications must supply a `validate` callback which accepts an `identifier`,
 * and optionally a service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `returnURL`  URL to which id.supinfo.com will redirect the user after authentication
 *   - `realm`      the part of URL-space for which an OpenID authentication request is valid
 *
 * Examples:
 *
 *     passport.use(new SUPINFOStrategy({
 *         returnURL: 'http://localhost:3000/auth/supinfo/return',
 *         realm: 'http://localhost:3000/'
 *       },
 *       function(identifier, profile, done) {
 *         User.findByOpenID(identifier, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, validate) {
  options = options || {};
  options.providerURL = 'https://id.supinfo.com/Server.aspx';
  options.profile = true;

  OpenIDStrategy.call(this, options, validate);
  this.name = 'supinfo';
}


/**
 * Inherit from `OpenIDStrategy`.
 */
util.inherits(Strategy, OpenIDStrategy);


/**
 * Authenticate request by delegating to an OpenID provider using OpenID 2.0
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {
  if (req.query && req.query['openid.mode']) {
    // The request being authenticated contains an `openid.mode` parameter in
    // the query portion of the URL.  This indicates that the OpenID Provider
    // is responding to a prior authentication request with either a positive or
    // negative assertion.  If a positive assertion is received, it will be
    // verified according to the rules outlined in the OpenID 2.0 specification.
    
    // NOTE: node-openid (0.3.1), which is used internally, will treat a cancel
    //       response as an error, setting `err` in the verifyAssertion
    //       callback.  However, for consistency with Passport semantics, a
    //       cancel response should be treated as an authentication failure,
    //       rather than an exceptional error.  As such, this condition is
    //       trapped and handled prior to being given to node-openid.
    
    if (req.query['openid.mode'] === 'cancel') { return this.fail({ message: 'OpenID authentication canceled' }); }
    
    var self = this;
    this._relyingParty.verifyAssertion(req.url, function(err, result) {
      if (err) { return self.error(new InternalOpenIDError('Failed to verify assertion', err)); }
      if (!result.authenticated) { return self.error(new Error('OpenID authentication failed')); }
      
      var profile = self._parseProfileExt(result, req.query);
      
      function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
      }
      
      var arity = self._verify.length;
      
      var idBooster = result.claimedIdentifier.split('/')[result.claimedIdentifier.split('/').length-1];
      
      if (self._passReqToCallback) {
        if (arity == 4 || self._profile) {
          self._verify(req, idBooster, profile, verified);
        } else {
          self._verify(req, idBooster, verified);
        }
      } else {
        if (arity == 3 || self._profile) {
          self._verify(idBooster, profile, verified);
        } else {
          self._verify(idBooster, verified);
        }
      }
    });
  } else {
    // The request being authenticated is initiating OpenID authentication.  By
    // default, an `openid_identifier` parameter is expected as a parameter,
    // typically input by a user into a form.
    //
    // During the process of initiating OpenID authentication, discovery will be
    // performed to determine the endpoints used to authenticate with the user's
    // OpenID provider.  Optionally, and by default, an association will be
    // established with the OpenID provider which is used to verify subsequent
    // protocol messages and reduce round trips.
  
    var identifier = undefined;
    if (req.body && req.body[this._identifierField]) {
      identifier = req.body[this._identifierField];
    } else if (req.query && req.query[this._identifierField]) {
      identifier = req.query[this._identifierField];
    } else if (this._providerURL) {
      identifier = this._providerURL;
    }
    
    identifier = "https://id.supinfo.com/me/" + identifier;
    
    if (!identifier) { return this.fail(new BadRequestError('Missing OpenID identifier')); }

    var self = this;
    this._relyingParty.authenticate(identifier, false, function(err, providerUrl) {
      if (err || !providerUrl) { return self.error(new InternalOpenIDError('Failed to discover OP endpoint URL', err)); }
      self.redirect(providerUrl);
    });
  }
}


/**
 * Parse user profile from OpenID response.
 *
 * Profile exchange can take place via OpenID extensions, the two common ones in
 * use are Simple Registration and Attribute Exchange.  If an OpenID provider
 * supports these extensions, the parameters will be parsed to build the user's
 * profile.
 *
 * @param {Object} params
 * @api private
 */
Strategy.prototype._parseProfileExt = function(params, args) {
  var profile = {};
  
  var identifier = params['claimedIdentifier'].split('/');
  profile.idBooster = identifier[identifier.length-1];
  
  profile.fullName = params['fullname'];
  
  profile.role = params['alias1'];

  if (params['alias2'] == 'N/A') {
    profile.campus = 'N/A';
    profile.campusID = 'N/A';
  } else {
    var campus = params['alias2'].split(';');
    profile.campusID = campus[0];
    profile.campus = campus[1];  
  }
  
  if (profile.role == 'Student') {
    switch (params['alias4'].split(';')[1]) {
      case '1':
        profile.level = 'B1'+params['alias3'];
        break;
      case '2':
        profile.level = 'B2'+params['alias3'];
        break;
      case '3':
        profile.level = 'B3'+params['alias3'];
        break;
      case '4':
        profile.level = 'M1'+params['alias3'];
        break;
      case '5':
        profile.level = 'M2'+params['alias3'];
        break;
      default:
        profile.level = 'N/A'
        break;
    }
  }

  profile.ranks= new Array();
  if (args['openid.alias3.count.alias5'] != '1') {
    for (var i=1; i<=args['openid.alias3.count.alias5'];i++) {
      profile.ranks.push(args['openid.alias3.value.alias5.'+i]);
    }
  } else {
    profile.ranks.push(args['openid.alias3.value.alias5']);
  }

  profile.fullProfSubjects = new Array();
  if (args['openid.alias3.count.alias6'] != '1') {
    for (var i=1; i<=args['openid.alias3.count.alias6'];i++) {
      profile.fullProfSubjects.push(args['openid.alias3.value.alias6.'+i]);
    }
  } else {
    profile.fullProfSubjects.push(args['openid.alias3.value.alias6']);
  }
  
  profile.teacherSubjects = new Array();
  if (args['openid.alias3.count.alias7'] != '1') {
    for (var i=1; i<=args['openid.alias3.count.alias7'];i++) {
      profile.teacherSubjects.push(args['openid.alias3.value.alias7.'+i]);
    }
  } else {
    profile.teacherSubjects.push(args['openid.alias3.value.alias7']);
  }

  return profile;
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;