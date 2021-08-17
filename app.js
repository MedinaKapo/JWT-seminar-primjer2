const express = require('express')
const jwt = require('jsonwebtoken')
const router = express.Router()
const config = require('./config')
const tokenList = {}
const app = express()
const cookie = require('cookie-parser')
app.use(cookie())
var XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
var xhr = new XMLHttpRequest();
const mysql = require('mysql');
app.use(express.static(__dirname));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
router.use(express.json());
router.use(express.urlencoded({ extended: true }));

//konekcija na bazu
var pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'wtseminar'
});

pool.getConnection(function(error, connection) {
    if (error) throw error;
    console.log('Connected');
});

router.get('/', (req, res) => {
    res.sendFile('/forma.html', { root: __dirname });
})

app.get('/forma', function(req, res) {
    res.sendFile('/forma.html', { root: __dirname });
});

router.get('/pogresno', function(req, res) {
    res.sendFile('/pogresno.html', { root: __dirname });
});

router.get('/index', function(req, res) {

    res.sendFile('/index.html', { root: __dirname });

});

var user2;
var ref2;
var tok2;
var kontrola = null;
router.post('/login', (req, res) => {
    const imeKorisnika = req.body.ime;
    console.log(req.body.ime);
    const emilKorisnika = req.body.email;
    if (imeKorisnika && emilKorisnika) {
        var sql = "SELECT id FROM korisnici WHERE ime=? AND email=?";
        pool.query(sql, [imeKorisnika, emilKorisnika], async function(err, result) {
            if (err) throw err;
            if (result.length == 0) {
                console.log('Greska');
                res.redirect('/pogresno');
                res.end();
            }
            kontrola = result;
        })

        const user = {
            "email": emilKorisnika,
            "name": imeKorisnika
        }
        user2 = user;

        const token = jwt.sign(user, config.secret, { expiresIn: config.tokenLife })
        const refreshToken = jwt.sign(user, config.refreshTokenSecret, { expiresIn: config.refreshTokenLife })
        ref2 = refreshToken;
        tok2 = token;
        const response = {
            "status": "Logged in",
            "token": token,
            "refreshToken": refreshToken,
        }
        tokenList[refreshToken] = response
        return res.status(200).cookie("access_token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
        }).cookie("refresh_token", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
        }).sendFile('/index.html', { root: __dirname });
    } else {
        res.redirect('/api/pogresno');
    }
})

function rezerva(req, res) {
    if ((ref2) && (ref2 in tokenList)) {
        const token = jwt.sign(user2, config.secret, { expiresIn: config.tokenLife })
        tokenList[ref2].token = token

        res.cookie("access_token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
        }).json({ access_token: token }).status(200);
    }
}
router.get('/tokeni', function(req, res) {
    res.send(tok2);
});

router.get('/tokeniref', function(req, res) {
    res.send(ref2);
});

router.get('/tokenrefresh', (req, res) => {

    const cookieData = req.cookies.refresh_token
    if ((cookieData) && (cookieData in tokenList)) {

        const token = jwt.sign(user2, config.secret, { expiresIn: config.tokenLife })
        const refreshToken = jwt.sign(user2, config.refreshTokenSecret, { expiresIn: config.refreshTokenLife })
        const response = {
            "status": "Logged in",
            "token": token,
            "refreshToken": refreshToken,
        }
        tokenList[refreshToken] = response
        tok2 = token;
        ref2 = refreshToken;
        return res.status(200).cookie("access_token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
        }).cookie("refresh_token", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
        }).json({ acc: tok2, ref: ref2 });
    } else {
        res.status(404).send('Greska')
    }

})

router.post('/token', (req, res) => {
    const tijelo = req.body
    const cookieData = req.cookies.refresh_token
    if ((cookieData) && (cookieData in tokenList)) {
        const user = {
            "email": tijelo.email,
            "name": tijelo.name
        }
        const token = jwt.sign(user2, config.secret, { expiresIn: config.tokenLife })
        const response = {
            "token": token,
        }
        tokenList[cookieData].token = token
        res
            .cookie("access_token", token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
            }).json({ access_token: token }).status(200);
    } else {
        res.status(404).send('Greska')
    }
})

router.get("/logout", (req, res) => {

    return res
        .clearCookie("access_token")
        .clearCookie("refresh_token")
        .status(200)
        .sendFile('/logout.html', { root: __dirname });
});



router.use(require('./refreshChecker'))
    //router.use(require('./tokenChecker'))
router.get('/secure', (req, res) => {
    router.use(require('./tokenChecker'))
    if (res.status(401)) {
        if ((ref2) && (ref2 in tokenList)) {
            const token = jwt.sign(user2, config.secret, { expiresIn: config.tokenLife })
            tokenList[ref2].token = token
            tok2 = token;
            res.status(200).cookie("access_token", token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
            });
        }
    }
    res.sendFile('/alive.html', { root: __dirname });
})

router.get('/informacije', (req, res) => {
    if (req.headers && req.cookies.access_token && req.cookies.refresh_token) {
        const token = req.body.token || req.query.token || req.cookies.access_token
        jwt.verify(token, config.secret, function(err, decoded) {
            if (err) {
                return res.status(401).json({ "error": true, "message": 'Unauthorized access.' });
            }
            dekodirano = decoded;
            res.json({ ime: dekodirano.name, email: dekodirano.email });
        });
    } else {
        res.redirect('/api/logout');
    }

})

//app.use(bodyParser.json())
app.use('/api', router)
app.listen(config.port || process.env.port || 3000);