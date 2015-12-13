'use strict';

var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var crypto = require('crypto');

var UserSchema = new Schema({
    name          : String,
    email         : {type: String, lowercase: true},
    role          : {
        type   : String,
        default: 'user'
    },
    hashedPassword: String,
    provider      : String,
    salt          : String
});

/**
 * DECLARING VIRTUALS, fields that can be used on the model but do not get persisted to the DB.
 */

UserSchema
    .virtual('password')
    .set(function (password) {
        this._password = password;
        this.salt = this.makeSalt();
        this.hashedPassword = this.encryptPassword(password);
    });

UserSchema
    .virtual('profile')
    .get(function () {
        return{
            'name': this.name,
            'role': this.role
        }
    });

UserSchema
    .virtual('token')
    .get(function () {
        return{
            '_id' : this._id,
            'role': this.role
        }
    });

/**
 * Validation required on the Userschema
 */

UserSchema
    .path('email')
    .validate(function (email, respond) {
        if(email.length){
            respond(true);
        };
    }, 'Email field cannot be left blank');

UserSchema
    .path('hashedPassword')
    .validate(function (hashedPassword) {
        return hashedPassword.length;
    });

UserSchema
    .path('email')
    .validate(function (value, respond) {
        var self = this;
        this.constructor.findOne({email: value}, function (err, user) {
            if (err) throw err;
            if (user) {
                if (self.id === user.id) {
                    return respond(true);
                }
                return respond(false);
            }
        })
    }, 'This Email is already taken');

var validatePresenceOf = function (value) {
    return value && value.length;
};

UserSchema
    .pre('save', function (next) {
        if (!this.isNew) return next();

        if (!validatePresenceOf(this.hashedPassword)) {
            next(new Error('Invalid Password'));
        } else {
            next();
        }
    });

/**
 *Methods on the UserSchema
 */

UserSchema.methods = {
    makeSalt: function () {
        return crypto.randomBytes(16).toString('Base64');
    },

    encryptPassword: function (password) {
        if (!password || !this.salt) {
            return ''
        }
        var salt = new Buffer(this.salt, 'Base64');
        return crypto.pbkdf2Sync(password, salt, 10000, 64).toString('base64');
    }
}

module.exports = mongoose.model('User', UserSchema);