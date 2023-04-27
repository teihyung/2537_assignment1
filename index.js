
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
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

app.get('/', (req,res) => {
    const html = `
            <button><a href="/login">Login</a></button>
            <br></br>
            <button><a href="/createUser">Create User</a></button>`;
    res.send(html);
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.send("<h1 style='color:"+color+";'>Patrick Guichon</h1>");
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: "+email);
    }
});


app.get('/createUser', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='email' type='text' placeholder='email'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var email = req.body.email;
    var username = req.body.username;
    var password = req.body.password;

    // Check if all fields are present
    if (!email || !username || !password) {
        var errorMsg = "";
        if (!email) {
            errorMsg += "Please provide an email address. ";
        }
        if (!username) {
            errorMsg += "Please provide a username. ";
        }
        if (!password) {
            errorMsg += "Please provide a password. ";
        }
        errorMsg += "<a href='/login'>Go back to login page</a>";
        res.send(errorMsg);
        return;
    }

    const schema = Joi.object(
        {   
            email: Joi.string().email().required(),
            username: Joi.string().alphanum().max(20).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({email,username, password});
    if (validationResult.error != null) {
       console.log(validationResult.error);
       res.redirect("/createUser");
       return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({email: email, username: username, password: hashedPassword});
    console.log("Inserted user");

    // Log the user in and redirect them to the members page
    req.session.authenticated = true;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
});



app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var username = req.body.username;
    var password = req.body.password;

    const schema = Joi.object(
        {   
            email: Joi.string().email().required(),
            username: Joi.string().alphanum().max(20).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate(username);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({email: email}).project({email: 1, password: 1, _id: 1}).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        var errorMsg = "Incorrect email or password.";
        errorMsg += "<a href='/login'>try again</a>";
        res.send(errorMsg);
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/loggedIn');
        return;
    }
    else {
        console.log("incorrect password");
        var errorMsg = "Incorrect email or password.";
        errorMsg += "<a href='/login'>try again</a>";
        res.send(errorMsg);
        return;
    }
});

app.get('/loggedin', async (req,res) => {
    if (!req.session.authenticated) {
        return res.redirect('/login');
    }
    try {
      const result = await userCollection.find({email: req.session.email}).project({username: 1}).toArray();
      var html = `
      <h2>Hello, ${result[0].username}.</h2>
      <button onclick="window.location.href='/members'">go to members page</button>
      <br></br>
      <button onclick="window.location.href='/logout'">Log out</button>`;
      res.send(html);
    } catch (error) {
      console.log(error);
      res.redirect('/login');
    }
  });

app.get('/logout', (req,res) => {
	req.session.destroy();
    var html = `
    You are logged out.
    <a href="/">go back to main</a>
    `;
    res.send(html);
});

app.get('/members', async (req,res) => {
  if (req.session.authenticated) {
    try {
      const result = await userCollection.find({email: req.session.email}).project({username: 1}).toArray();
      const photoId = Math.floor(Math.random() * 3) + 1; // generate a random number between 1 to 3
      var html = `
        <h2>Hello, ${result[0].username}.</h2>
        `;
      if (photoId === 1) {
        html += `
          <div>Java: <img src='/java.jpg' style='width:250px;'></div>
          `;
      } else if (photoId === 2) {
        html += `
          <div>C: <img src='/c.jpg' style='width:250px;'></div>
          `;
      } else if (photoId === 3) {
        html += `
          <div>JavaScript: <img src='/javascript.jpg' style='width:250px;'></div>
          `;
      }
      html += `
        <br></br>
        <button onclick="window.location.href='/logout'">Log out</button>
        `;
      res.send(html);
      return;
    } catch (error) {
      console.log(error);
      res.redirect('/login');
    }
  } else  {
      res.redirect('/login');
      return;
  }
});

app.use(express.static(__dirname + "/public"));

// app.get('/cat/:id', (req,res) => {

//     var cat = req.params.id;

//     if (cat == 1) {
//         res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
//     }
//     else if (cat == 2) {
//         res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
//     }
//     else {
//         res.send("Invalid cat id: "+cat);
//     }
// });


app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 