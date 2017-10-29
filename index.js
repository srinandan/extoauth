'use strict';
/**
 *
 */

var debug = require('debug')('plugin:extoauth');
var request = require('request');
var rs = require('jsrsasign');
var JWS = rs.jws.JWS;

const authHeaderRegex = /Bearer (.+)/;
const acceptAlg = ['RS256'];

var acceptField = {};
acceptField.alg = acceptAlg;

module.exports.init = function (config, logger, stats) {

  var publickeys = {};
  var publickey_url = config.publickey_url;
  var client_id = config.client_id || 'client_id';
  var iss = config.iss;
  var exp = config.exp;
  //set keyType to pem if the endpoint returns a single pem file
  var keyType = config.keyType || 'jwk';

  if (iss) {
    debug("Issuer " + iss);
    acceptField.iss = [];
    acceptField.iss[0] = iss;
  }

  request({
        url: publickey_url,
        method: 'GET'
      }, function (err, response, body) {
        if (err) {
          debug('publickey gateway timeout');
          console.log(err);
        } else {
          debug("loaded public keys");
		  if (config.keyType == 'jwk') {
	          publickeys = JSON.parse(body);		  	
		  } else {
			  //the body should contain a single pem
			  publickeys = body; 
		  }
        }
    }
  );

  function getJWK(kid) {
    if (publickeys.keys && publickeys.keys.constructor == Array) {
      for (var i = 0; i < publickeys.keys.length; i ++) {
        if (publickeys.keys[i].kid == kid) {
          return publickeys.keys[i];
        }
      }
      debug ("no public key that matches kid found");
      return "";      
    } else if (publickeys[kid]) {//handle cases like https://www.googleapis.com/oauth2/v1/certs
      return publickeys[kid];
    } else { //if the publickeys url does not return arrays, then use the only public key
      debug("returning default public key");
      return publickeys;
    }
  }
  
  function validateJWT(pem, payload, exp) {
	  var isValid = false;
      if (exp) {
        debug("JWT Expiry enabled");
        acceptField.verifyAt = rs.KJUR.jws.IntDate.getNow();
        isValid = rs.jws.JWS.verifyJWT(payload, pem, acceptField);
      } else {
        debug("JWT Expiry disabled");
        isValid = rs.jws.JWS.verify(payload, pem, acceptAlg);
      }  
	  return isValid;
  }

  return {
    onrequest: function(req, res, next) {
      debug('plugin onrequest');
	  var isValid = false;
      try {
        var jwtpayload = authHeaderRegex.exec(req.headers['authorization']);
		
        if (!jwtpayload || jwtpayload.length < 2) {
        	debug ("ERROR - JWT Token Missing in Auth header");
        }
        else {
          var jwtdecode = JWS.parse(jwtpayload[1]);
          if (jwtdecode.headerObj) {
			var kid = jwtdecode.headerObj.kid;  
			if (keyType != 'jwk') {
				debug("key type is PEM");
				isValid = validateJWT(publickeys, jwtpayload[1], exp);
                if(isValid) {
                  delete (req.headers['authorization']);//removing the auth header
                  req.headers['x-api-key'] = jwtdecode.payloadObj[client_id];                
                } else {
                  debug("ERROR - JWT is invalid");
                }					
			}
            else if (!kid && keyType == 'jwk') {
              debug ("ERROR - JWT Missing kid in header");
            } 
			else {
              var jwk = getJWK(kid);
              if (!jwk) {
                debug("ERROR - Could not find public key to match kid");
              } else {
                var publickey = rs.KEYUTIL.getKey(jwk);
                var pem = rs.KEYUTIL.getPEM(publickey);  
                isValid = validateJWT(pem, jwtpayload[1], exp);
                if(isValid) {
                  delete (req.headers['authorization']);//removing the auth header
                  req.headers['x-api-key'] = jwtdecode.payloadObj[client_id];                
                } else {
                  debug("ERROR - JWT is invalid");
                }            
              }
            }            
          } else {
			debug ("ERROR - Missing header in JWT");
          }
        } 
      } catch (err) {
        debug("ERROR - " + err);
      }
      next();
    }
  };
}
