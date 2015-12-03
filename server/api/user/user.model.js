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

module.exports = mongoose.model('User', UserSchema);