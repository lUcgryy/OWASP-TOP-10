const express = require('express');
const bodyparser = require('body-parser');
const session = require('express-session');
const {v4: uuidv4} = require('uuid');
const http = require('http');
const https = require('https');
const fs = require('fs');
const db = require('./db');

const app = express();

const port = process.env.PORT || 3000;
const securePort = process.env.SECURE_PORT || 3443;

const options = {
	key: fs.readFileSync(__dirname + '/certs/private.key'),
	cert: fs.readFileSync(__dirname + '/certs/certificate.pem'),
};

app.use(bodyparser.json());
app.use(bodyparser.urlencoded({ extended: true}));
app.use(session({
	secret: uuidv4(),
	resave: false,
	saveUninitialized: true
}))

app.set('view engine', 'ejs')


app.get('/', (req, res) => {
    res.render('index', {title: 'Hello World'});
});

app.get('/login', (req, res) => {
    res.render('login', {title: 'Login'});
});

app.post('/login', async (req, res) => {
    username = req.body.username;
    password = req.body.password;
    if (!username || !password) {
        res.render('login', {title: "Login", noti: "Please enter username and password"});
        return;
    }
    data = [username, password];
    const checkUser = await db.executeQuery('Select * from users where username = ? and password = ?', data)
    if (checkUser.length === 0) {
        res.render('login', {title: "Login", noti: "Invalid username or password"});
    } else {
        req.session.user = username;
        res.redirect('/admin');
    }
});

function checkLogin(req, res, next) {
    if (!req.session.user) {
        res.redirect('/login');
    }
    next();
}

app.get('/admin', checkLogin, (req, res) => {
    res.render('admin', {title: 'Admin'});
});

app.post('/admin', checkLogin, async (req, res) => {
    username = req.body.username;
    password1 = req.body.password1;
    password2 = req.body.password2;
    if (!username || !password1 || !password2) {
        res.render('admin', {title: "Admin", noti: "Please enter all fields"});
        return;
    }
    if (password1 !== password2) {
        res.render('admin', {title: "Admin", noti: "Password is not match"});
        return;
    }
    checkUser = await db.executeQuery('Select * from users where username = ?', [username]);
    if (checkUser.length !== 0) {
        res.render('admin', {title: "Admin", noti: "Username is already exist"});
        return;
    }
    data = [username, password1];
    await db.executeQuery('Insert into users (username, password) values (?, ?)', data);
    res.render('admin', {title: "Admin", noti: "User added successfully"});
    console.log('Insert user successfully');
});
app.use(function(req, res) {
	res.status(400);
	res.render('404', {title: '404: File Not Found'});
});

app.use(function(error, req, res, next) {
	res.status(500);
	res.render('500', {title:'500: Lỗi Server', error: error});
});

var server = http.createServer(app);
server.listen(port, () => {
	console.log(`Server is running at port ${port}`);
});

var secureServer = https.createServer(options, app);
secureServer.listen(securePort, () => {
	console.log(`Server is running at port ${securePort}`);
});
