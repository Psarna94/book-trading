'use strict';

var mongoose = require('mongoose');
var passport = require('passport');
var config = require('../config/environment');
var jwt = require('jsonwebtoken');
var expressJwt = require('express-jwt');
var compose = require('composable-middleware');
var User = require('../api/user/user.model');
var validateJwt = expressJwt({ secret: config.secrets.session });

/**
 * Attach the user object to every request if authenticated
 * otherwise return 403
 **/

function isAuthenticated() {
    return compose()
        //validating the JWT here
        .use(function (req, res, next) {
            if (req.query && req.query.hasOwnProperty('access_token')) {
                req.headers.authorization = 'Bearer' + req.query.access_token;
            }

            validateJwt(req, res, next);
        })
        .use(function (req, res, next) {
            User.findById(req.user._id, function (err, user) {
                if (err) return next(err);
                if (!user) return res.status(401).send('Unauthorized');

                req.user = user;
                next();
            })
        })
}

/**
 *Checks if the user meets the minimum role of the route
 */
function hasRole(roleRequired) {
    if (!roleRequired) throw new Error('Required roll needs to be set');

    return compose()
        .use(isAuthenticated())
        .use(function meetsRequirement(req, res, next) {
            if (config.userRoles.indexOf(req.user.role) >= config.userRoles.indexOf(roleRequired)) {
                next();
            } else {
                res.status(403).send('Forbidden');
            }
        });
}

function isOwner() {
    return compose()
        .use(isAuthenticated)
        .use(function meetsRequirements(req, res, next) {
            if (req.user.name === req.params.name) {
                next();
            } else {
                res.status(403).send('Forbidden');
            }
        });
}

function signToken(id){
    return jwt.sign({_id:id}, config.secrets.session,{expiresInMinutes: 60*5});
}

exports.isAuthenticated = isAuthenticated;
exports.hasRole = hasRole;
exports.signToken = signToken;
//exports.setTokenCookie = setTokenCookie;

