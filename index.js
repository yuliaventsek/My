const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const express = require('express');
const app = express();
const bodyParser = require("body-parser");
const mysql = require('mysql');
const crypto = require('crypto');
var session = require('express-session');
var MySQLStore = require('express-mysql-session')(session);

app.use(express.static('public'));

app.use(session({
    key: 'session_cookie_name',
    secret: 'session_cookie_secret',
    store: new MySQLStore({
        host: 'localhost',
        port: 3306,
        user: 'root',
        database: 'cookie_user'
    }),
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24,

    }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(express.static('public'));
app.set("view engine", "ejs");

const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    database: "music_gallery",
    password: "",
    multipleStatements: true
});
connection.connect(function (err) {
    if (err) {
        return console.error("Ошибка: " + err.message);
    }
    else {
        console.log("Подключение к серверу MySQL успешно установлено");
    }
});




const customFields = {
    usernameField: 'uname',
    passwordField: 'pw',
};

// Passport JS
const verifyCallback = (username, password, done) => {

    connection.query('SELECT * FROM users WHERE username= ? ', [username], function (error, results, fields) {
        if (error)
            return done(error);

        if (results.length == 0) {
            return done(null, false);
        }
        const isValid = validPassword(password, results[0].hash, results[0].salt);
        user = { user_id: results[0].user_id, username: results[0].username, hash: results[0].hash, salt: results[0].salt };
        if (isValid) {
            return done(null, user);
        }
        else {
            return done(null, false);
        }
    });
}

const strategy = new LocalStrategy(customFields, verifyCallback);
passport.use(strategy);


passport.serializeUser((user, done) => {
    console.log("inside serialize");
    done(null, user.user_id)
});








passport.deserializeUser(function (user_id, done) {
    console.log('deserializeUser' + user_id);
    connection.query('SELECT * FROM users WHERE user_id = ?', [user_id], function (error, results) {
        done(null, results[0]);
    });
});


// middleware
function validPassword(password, hash, salt) {
    var hashVerify = crypto.pbkdf2Sync(password, salt, 10000, 60, 'sha512').toString('hex');
    return hash === hashVerify;
}

function genPassword(password) {
    var salt = crypto.randomBytes(32).toString('hex');
    var genhash = crypto.pbkdf2Sync(password, salt, 10000, 60, 'sha512').toString('hex');
    return { salt: salt, hash: genhash };
}






function isAuth(req, res, next) {
    if (req.isAuthenticated()) {
        next();
    }
    else {
        res.redirect('/notAuthorized');
    }
}


function isAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.isAdmin == 1) {
        next()
    }
    else {
        res.redirect('/notAuthorizedAdmin');
    }
}





function userExists(req, res, next) {
    connection.query('SELECT * FROM users WHERE username=?', [req.body.uname], function (error, results, fields) {
        if (error) {
            console.lof("Error");
        }
        else if (results.length > 0) {
            res.redirect('/userAlreadyExists')
        }
        else {
            next()
        }
    });
}







app.get('/', (req, res, next) => {
    res.send('<h1>Home</h1><p> Please <a href="/register">register</a></p>');
});

app.get('/login', (req, res, next) => {
    res.render('login')
});

app.get('/logout', (req, res, next) => {
    req.logout(function (err) {
        if (err) { return next(err); }
        res.redirect('/login')
    })
});

app.get('/login-failure', (req, res, next) => {
    res.send('You entered the wrong password.');
});

app.get('/register', (req, res, next) => {
    res.render('register')
});

app.post('/register', userExists, (req, res, next) => {
    console.log(req.body.pw);
    const saltHash = genPassword(req.body.pw);
    console.log(saltHash);
    const salt = saltHash.salt;
    const hash = saltHash.hash;
    const name = req.body.name;
    const surname = req.body.surname;
    const username = req.body.uname;
    const email = req.body.email;
    const birthday = req.body.birthday;
    const country = req.body.country;

    connection.query('Insert into users(name, surname, username, email, birthday, country, hash, salt, isAdmin) values(?,?,?,?,?,?,?,?,0) ', [name, surname, username, email, birthday, country, hash, salt], function (error, results, fields) {
        if (error) {
            console.log("Error");
        }
        else {
            console.log("Successfully Entered");
        }
    });
    res.redirect('/login');
});

app.post('/login', passport.authenticate('local', { failureRedirect: '/login-failure', successRedirect: '/main' }));

app.get('/protected-route', isAuth, (req, res, next) => {
    res.send('<h1>You are authenticated</h1><p><a href="/logout">Logout and reload</a></p>');
});

app.get('/admin-route', isAdmin, (req, res, next) => {
    res.send('<h1>You are admin</h1><p><a href="/logout">Logout and reload</a></p>');
});

app.get('/notAuthorized', (req, res, next) => {
    res.send('<h1>You are not authorized to view the resource </h1><p><a href="/login">Retry Login</a></p>');
});

app.get('/notAuthorisedAdmin', (req, res, next) => {
    res.send('<h1>You are not authorized to view the resource as you are not the admin of the page</h1><p><a href="/login">Retry to Login as admin</a></p>');
});

app.get('/userAlreadyExists', (req, res, next) => {
    res.send('<h1>Sorry this username is taken</h1><p><a href="/register">Register with different username</a></p>');
});





app.get('/main', (req, res, next) => {
    console.log(req.user);
    res.render('main')
});

app.get('/profile', function (req, res) {
    connection.query('SELECT * FROM users WHERE user_id = ?', [req.user.user_id], function (err, result) {
        if (err) throw err;
        res.render('profile', { data: result });
    });
});



// app.post('/delete/:id', function (req, res, next) {
//     var sql = 'DELETE FROM users WHERE user_id = ?';
//     var id = req.params.id;
//     console.log(id)
//     connection.query(sql, [id], function (err, result) {
//       if (err) {
//         throw err;
//       }
//       console.log(result.affectedRows + ' row(s) updated');
//     });
//     res.redirect('/logout');
//   });

app.get('/add', (req, res, next) => {
    console.log(req.user);
    res.render('add')
});

app.post('/add', (req, res, next) => {
    const songname = req.body.songname;
    const musician = req.body.musician;
    const year = req.body.year;
    const genre = req.body.genre;


    connection.query('Insert into musicinfo(songname, musician, year, genre) values(?,?,?,?) ', [songname, musician, year, genre], function (error, results, fields) {
        if (error) {
            console.log("Error");
        }
        else {
            console.log("Successfully Added");
        }
    });
    res.redirect('/main');
});



app.get('/subscription', function (req, res) {
    console.log('get works')
    connection.query('SELECT * FROM subscriptions', function (err, result) {
        if (err) throw err;
        console.log(result)
        console.log('get works')
        res.render('subscription', { information: result })
    });
});

app.get('/payment/:type', function (req, res, next) {
    var sql = 'SELECT * FROM subscriptions WHERE type = ?';
    var type = req.params.type;
    console.log(type)
    connection.query(sql, [type], function (err, result) {
        if (err) {
            throw err;
        }
        console.log(result)
        res.render('payment', {
            data: result
        });
    });
})

app.post('/payment/:type', (req, res, next) => {
    
    const email = req.body.email;
    const card = req.body.card;
    const cvv = req.body.cvv;

    connection.query('Insert into payment (email, card, cvv) values(?,?,?) ', [email, card, cvv], function (error, results, fields) {
        if (error) {
            console.log("Error");
        }
        else {
            console.log("Successfully");
        }
    });
    res.redirect('/main');
});







app.listen(3306, function () {
    console.log('App listening on port 8080!')
});