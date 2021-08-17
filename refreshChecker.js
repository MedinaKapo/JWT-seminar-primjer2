const jwt = require('jsonwebtoken')
const config = require('./config')
const cookie = require('cookie-parser')
module.exports = (req, res, next) => {
    const token = req.cookies.refresh_token

    if (token) {
        // provjeri tajnu i da li je istekao
        jwt.verify(token, config.refreshTokenSecret, function(err, decoded) {
            if (err) {
                res.status(401).redirect('/api/logout');
            }
            req.decoded = decoded;
            next();
        });
    } else {
        //ako nema tokena
        res.status(401).redirect('/api/logout');
    }
}