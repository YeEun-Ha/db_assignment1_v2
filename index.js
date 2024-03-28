require('./utils');

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;


const database = include('databaseConnection');
const db_utils = include('database/db_utils');
const db_users = include('database/users');
const success = db_utils.printMySQLVersion();


const port = process.env.PORT || 3070;

const app = express();

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

// var users = [];

// /* secret information section */
// const mongodb_user = "hye829900";
// const mongodb_password = "WCdK5lG0ooVCw73s";
// const node_session_secret = "f0d5359e-2d72-4f8f-8959-b1354a543271";
// const mongodb_session_secret ="f6fbec89-7c15-4c72-af0f-696990e1da0d";

const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
// /* END secret section */

app.set('view engine', 'ejs');
// app.set('views', path.join(__dirname, '/../Views'));  


app.use(express.urlencoded({extended: false}));
// console.log(`mongodb+srv://${mongodb_user}:${mongodb_password}@cluster0.dqd1fyd.mongodb.net/sessions`)

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@cluster0.dqd1fyd.mongodb.net/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true    
}
));

// app.use('/', sessionValidation);

app.get('/', (req,res) => {
    // res.send("<h1>Hello World!</h1>");
    if (req.session.username) {
        res.render("loggedin", {username: req.session.username});
    } else{
        res.render("index");
    }
});

app.get('/about', (req,res) => {
    var color = req.query.color;
    if (!color) {
        color = "black";
    }

    // res.send(`<h1 style='color:${color};'>About</h1>`);
    res.render("about", {color: color} );
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;

    // var html = `
    //     email address:
    //     <form action='/submitEmail' method='post'>
    //         <input name='email' type='text' placeholder='email'>
    //         <button>Submit</button>
    //     </form>
    // `;
    // if (missingEmail) {
    //     html += "<br> email is required";
    // }
    // res.send(html);

    res.render("contact", {missing: missingEmail});
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        // res.send("Thanks for subscribing with your email: "+email);
        res.render("submitEmail", {email: email});
    }
});

app.get('/createTables', async (req,res) => {

    const create_tables = include('database/create_tables');

    var success = create_tables.createTables();
    if (success) {
        res.render("successMessage", {message: "Created tables."} );
    }
    else {
        res.render("errorMessage", {error: "Failed to create tables."} );
    }
});

app.get('/signup', (req,res) => {
    var missingUsername = req.query.missingName;
    var missingPassword = req.query.missingPass;
    var missingBoth = req.query.missingBoth;

    // var html = `
    // <form action='/submitUser' method='post'>
    // <input name='username' type='text' placeholder='username'>
    // <input name='password' type='password' placeholder='password'>
    // <button>Submit</button>
    // </form>
    // `;
    
    // res.send(html);
    res.render("createUser", {missingName: missingUsername, missingPass: missingPassword, missingBoth: missingBoth});
}); 

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

    if (!username || !password) {       
        if (!username && !password) {
            res.redirect('/signup?missingBoth=1');
        } else if(!username) {
            res.redirect('/signup?missingName=1');
        } else if (!password){
            res.redirect('/signup?missingPass=1');  
        }
        return
    }

    // users.push({ username: username, password: password });

    var hashedPassword = bcrypt.hashSync(password, saltRounds);

    // users.push({ username: username, password: hashedPassword });

    // var usershtml = "";
    // for (i = 0; i < users.length; i++) {
    //     usershtml += "<li>" + users[i].username + ": " + users[i].password + "</li>";
    // }
    // var html = "<ul>" + usershtml + "</ul>";
    // res.send(html);


    var success = await db_users.createUser({ user: username, hashedPassword: hashedPassword });

    if (success) {
        // var results = await db_users.getUsers();

        // // res.render("submitUser",{users:users});
        // res.render("submitUser",{users:results});
        res.redirect('/login');
    }
    else {
        res.render("errorMessage", {error: "Failed to create user."} );
    }
});


app.get('/login', (req,res) => {
    var loginFail = req.query.badlogin;
    // var html = `
    // log in
    // <form action='/loggingin' method='post'>
    // <input name='username' type='text' placeholder='username'>
    // <input name='password' type='password' placeholder='password'>
    // <button>Submit</button>
    // </form>
    // `;
    // res.send(html);

    res.render("login", {failedLogin: loginFail});
});


app.post('/loggingin', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

    // var usershtml = "";
    // for (i = 0; i < users.length; i++) {
    //     if (users[i].username == username) {
    //         if (bcrypt.compareSync(password, users[i].password)) {
    var results = await db_users.getUser({ user: username, hashedPassword: password });
    if (results) {
        if (results.length == 1) { //there should only be 1 user in the db that matches
            if (bcrypt.compareSync(password, results[0].password)) {
                req.session.authenticated = true;
                req.session.username = username;
                req.session.user_type = results[0].type;
                req.session.cookie.maxAge = expireTime;

                res.redirect('/loggedIn');
                return;
            }
            else{
                console.log("invalid password");
            }
        } else {
            console.log('invalid number of users matched: '+results.length+" (expected 1).");
            res.redirect('/login?badlogin=1');
            return;            
        }
    }

    console.log('user not found');

    //user and password combination not found
    res.redirect("/login?badlogin=1");
});


function isValidSession(req) {
	if (req.session.authenticated) {
		return true;
	}
	return false;
}

function sessionValidation(req, res, next) {
	if (!isValidSession(req)) {
		req.session.destroy();
		res.redirect('/');
		return;
	}
	else {
		next();
	}
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
	if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
	}
	else {
		next();
	}
}

app.use('/loggedin', sessionValidation);
app.use('/loggedin/admin', adminAuthorization);

app.get('/loggedin', (req,res) => {
    // if (!req.session.authenticated) {
    //     res.redirect('/login');
    // }
    
    // var html = `
    // You are logged in! :D
    // `;
    // res.send(html);
    res.render("loggedin", {username: req.session.username});
});

app.get('/loggedin/info', (req,res) => {
    res.render("loggedin-info");
});

app.get('/loggedin/admin', (req,res) => {
    res.render("admin");
});


app.use('/members', sessionValidation);

app.get('/members', (req,res) => {
    let randomNum = Math.floor(Math.random() * 3) + 1;
    res.render("formembers", {username: req.session.username, user_type: req.session.user_type, randomNum: randomNum});
});


app.get('/cat/:id', (req,res) => {
    var cat = req.params.id;

    // if (cat == 1) {
    //     res.send("Fluffy: <img src='/cat1.jpg' style='width:250px;'>");
    // } else if (cat == 2) {
    //     res.send("Socks: <img src='/cat2.jpg' style='width:250px;'>");
    // } else {
    //     res.send("Invalid cat id: "+cat);
    // }

    res.render("cat", {cat: cat});
});

app.get('/logout', (req,res) => {
    req.session.destroy(e => {
        if (e) {
            console.log("error destroying session: ", e);
        }
        res.redirect('/');
    });
});


app.get('/api', (req,res) => {
	var user = req.session.user;
    var user_type = req.session.user_type;
	console.log("api hit ");

	var jsonResponse = {
		success: false,
		data: null,
		date: new Date()
	};

	
	if (!isValidSession(req)) {
		jsonResponse.success = false;
		res.status(401);  //401 == bad user
		res.json(jsonResponse);
		return;
	}

	if (typeof id === 'undefined') {
		jsonResponse.success = true;
		if (user_type === "admin") {
			jsonResponse.data = ["A","B","C","D"];
		}
		else {
			jsonResponse.data = ["A","B"];
		}
	}
	else {
		if (!isAdmin(req)) {
			jsonResponse.success = false;
			res.status(403);  //403 == good user, but, user should not have access
			res.json(jsonResponse);
			return;
		}
		jsonResponse.success = true;
		jsonResponse.data = [id + " - details"];
	}

	res.json(jsonResponse);

});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
    // res.send("Page not found - 404 :D");
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 