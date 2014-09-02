/*!
 * cookie-session
 * Copyright(c) 2013 Jonathan Ong
 * Copyright(c) 2014-2015 Douglas Christopher Wilson
 * MIT Licensed
 */

'use strict'

/**
 * Module dependencies.
 * @private
 */

var crypto = require('crypto');
var debug = require('debug')('cookie-session');
var Cookies = require('cookies');
var onHeaders = require('on-headers');

/**
 * Module exports.
 * @public
 */

module.exports = cookieSession

/**
 * Create a new cookie session middleware.
 *
 * @param {object} [options]
 * @param {boolean} [options.httpOnly=true]
 * @param {array} [options.keys]
 * @param {string} [options.name=express:sess] Name of the cookie to use
 * @param {boolean} [options.overwrite=true]
 * @param {string} [options.secret]
 * @param {boolean} [options.signed=true]
 * @return {function} middleware
 * @public
 */

function cookieSession(options) {
  var opts = options || {}

  // name - previously "opts.key"
  var name = opts.name || opts.key || 'express:sess';

  // secrets
  var keys = opts.keys;
  if (!keys && opts.secret) keys = [opts.secret];

  // defaults
  if (null == opts.overwrite) opts.overwrite = true;
  if (null == opts.httpOnly) opts.httpOnly = true;
  if (null == opts.signed) opts.signed = true;
  if (null == opts.encrypted) opts.encrypted = false;

  if (!keys && (opts.signed || opts.encrypted)){
    throw new Error('.keys required.');
  }

  debug('session options %j', opts);

  return function _cookieSession(req, res, next){
    var cookies = req.sessionCookies = new Cookies(req, res, keys);
    var sess, json, decoded;

    // to pass to Session()
    req.sessionOptions = Object.create(opts)
    req.sessionKey = name;
    req.sessionEncryptionKeys = keys;

    req.__defineGetter__('session', function(){
      // already retrieved
      if (sess) return sess;

      // unset
      if (false === sess) return null;

      json = cookies.get(name, req.sessionOptions)

      if (json) {
        debug('parse %s', json);
        try {
          if (opts.encrypted){
            decoded = decrypt(json, keys);
          }else{
            decoded = decode(json);
          }
          sess = new Session(req, decoded);
        } catch (err) {
          // backwards compatibility:
          // create a new session if parsing fails.
          // new Buffer(string, 'base64') does not seem to crash
          // when `string` is not base64-encoded.
          // but `JSON.parse(string)` will crash.
          if (!(err instanceof SyntaxError) && !(err instanceof TypeError)) throw err;
          sess = new Session(req);
        }
      } else {
        debug('new session');
        sess = new Session(req);
      }

      return sess;
    });

    req.__defineSetter__('session', function(val){
      if (null == val) return sess = false;
      if ('object' == typeof val) return sess = new Session(req, val);
      throw new Error('req.session can only be set as null or an object.');
    });

    onHeaders(res, function setHeaders() {
      if (sess === undefined) {
        // not accessed
        return;
      }

      try {
        if (sess === false) {
          // remove
          cookies.set(name, '', req.sessionOptions)
        } else if (!json && !sess.length) {
          // do nothing if new and not populated
        } else if (sess.changed(json, keys)) {
          // save
          sess.save();
        }
      } catch (e) {
        debug('error saving session %s', e.message);
      }
    });

    next();
  }
};

/**
 * Session model.
 *
 * @param {Context} ctx
 * @param {Object} obj
 * @private
 */

function Session(ctx, obj) {
  this._ctx = ctx

  Object.defineProperty(this, 'isNew', {
    value: !obj
  })

  if (obj) {
    for (var key in obj) {
      this[key] = obj[key]
    }
  }
}

/**
 * JSON representation of the session.
 *
 * @return {Object}
 * @public
 */

Session.prototype.inspect =
Session.prototype.toJSON = function toJSON() {
  var keys = Object.keys(this)
  var obj = {}

  for (var i = 0; i < keys.length; i++) {
    var key = keys[i]

    if (key[0] !== '_') {
      obj[key] = this[key]
    }
  }

  return obj
}

/**
 * Check if the session has changed relative to the `prev`
 * JSON value from the request.
 *
 * @param {String} [prev]
 * @return {Boolean}
 * @private
 */

Session.prototype.changed = function(prev, keys){
  if (!prev) return true;
  var ctx = this._ctx;
  var opts = ctx.sessionOptions;
  if (opts.encrypted){
    this._json = encrypt(this, keys);
  } else{
    this._json = encode(this);
  }
  return this._json != prev;
};

/**
 * Return how many values there are in the session object.
 * Used to see if it's "populated".
 *
 * @return {Number}
 * @public
 */

Session.prototype.__defineGetter__('length', function(){
  return Object.keys(this.toJSON()).length;
});

/**
 * populated flag, which is just a boolean alias of .length.
 *
 * @return {Boolean}
 * @public
 */

Session.prototype.__defineGetter__('populated', function(){
  return !!this.length;
});

/**
 * Save session changes by performing a Set-Cookie.
 *
 * @private
 */

Session.prototype.save = function(){
  var ctx = this._ctx;
  var opts = ctx.sessionOptions;
  var encoded;
  if (opts.encrypted){
    encoded = encrypt(this, ctx.sessionEncryptionKeys);
  }else{
    encoded = encode(this);
  }
  var json = this._json || encoded;
  var opts = ctx.sessionOptions;
  var name = ctx.sessionKey;

  debug('save %s', json);
  ctx.sessionCookies.set(name, json, opts);
};

/**
 * Decode the base64 cookie value to an object.
 *
 * @param {String} string
 * @return {Object}
 * @private
 */

function decode(string) {
  var body = new Buffer(string, 'base64').toString('utf8');
  return JSON.parse(body);
}

/**
 * Encode an object into a base64-encoded JSON string.
 *
 * @param {Object} body
 * @return {String}
 * @private
 */

function encode(body) {
  var str = JSON.stringify(body)
  return new Buffer(str).toString('base64')
}

/**
 * Decrypt the base64 cookie value to an object.
 *
 * @param {String} string
 * @param {String[]} keys key[0] is used for decryption. There is no support
 *                        multiple keys.
 * @return {Object}
 * @api private
 */

function decrypt(string, keys) {
  var decipher = crypto.createDecipher('aes256', keys[0]);
  var decrypted = decipher.update(string, 'base64', 'utf8') + decipher.final('utf8');
  return JSON.parse(decrypted);
}

/**
 * Encrypt an object into a base64 aes256-encrypted JSON string.
 *
 * @param {Object} body
 * @param {String[]} keys key[0] is used for encryption. There is no support
 *                        multiple keys.
 * @return {String}
 * @api private
 */

function encrypt(body, keys) {
  body = JSON.stringify(body);
  var cipher = crypto.createCipher('aes256', keys[0]);
  var encrypted = cipher.update(body, 'utf8', 'base64') + cipher.final('base64');
  return encrypted;
}
