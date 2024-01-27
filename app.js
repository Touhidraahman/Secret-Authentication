//jshint esversion:6
require('dotenv').config()
const express = require("express"); 
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-find-or-create");
// const bcrypt = require("bcrypt");  //commenting for using passport
// const saltRounds = 10;             //commenting for using passport
// const md5 = require("md5");        //commenting for using bcrypt
// const encrypt = require("mongoose-encryption");    //commenting for using md5


const app = express();

app.set('view engine','ejs');

app.use(bodyParser.urlencoded({extended: true}));

app.use(express.static("public"));

app.use(session({
    secret: "Our Little Secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:/userDb", {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });  //commenting for using md5

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/oauth/google/secrets",
    userProfileUrl: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {

    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

app.get("/oauth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
});

app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res){
    const submittedSecrets = req.body.secret;

    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = submittedSecrets;
                foundUser.save(function(){
                    res.redirect("/secrets");
                })
            }
        }
    });
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    User.find({"secret": {$ne: null}}).then((foundUser)=>{
        if(foundUser){
            res.render("secrets", {userWithSecret: foundUser});
        }
    }).catch((err)=>{
        console.log(err);
    })
});

app.get("/logout", function(req, res){
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
})

app.post("/register", function(req, res){

    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //     const newUser = new User({
    //     email: req.body.username,        //commenting for using passport
    //     password: hash
    // });

    // newUser.save().then(()=>{
    //     res.render("secrets");
    // }).catch((err)=>{
    //     console.log(err);
    // })

    // });
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    });
    
});

app.post("/login", function(req, res){
    // const username = req.body.username;
    // const password = req.body.password;       //commenting for using passport

    // User.findOne({ email: username}).then((foundUser)=>{
    //     if(foundUser){
    //         bcrypt.compare(password, foundUser.password, function(err, result) {
    //             if(result === true){
    //                 res.render("secrets");
    //             }
    //         });
            
    //     }
    // }).catch((err)=>{
    //     console.log(err);
    // })

    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.logIn(user, function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    })
});




app.listen(3000,function(){
    console.log("Server Started on Port 3000");
});