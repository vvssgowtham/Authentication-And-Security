//jshint esversion:6
require('dotenv').config();//here we are not assigning any variables because we want to use it continuously keep it at top only.
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');//using sessions to implement salting+hashing along with cookies
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
//const bcrypt = require('bcryptjs'); //LEVEL 4
//const saltRounds = 10;
//const md5 = require('md5'); LEVEL : 3
// const encrypt = require('mongoose-encryption'); LEVEL : 2

const app = express();

app.use(express.static("public"));//this is for using css files
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    //inside this curly bracket we are using javascript objects with number of properties
    //secret is the long string that is being choosed and this is something that we gonna keep as secret in our .env file 
    // to understand remaining properties refer to documentation
    secret: "Our little secret.",
    resave : false,
    saveUninitialized : false
}));

app.use(passport.initialize());
app.use(passport.session());//here we are using passport use session

mongoose.connect('mongodb://127.0.0.1:27017/userDB',{useNewUrlParser : true});

//setting up database 
const userSchema = new mongoose.Schema({
    email : String,
    password : String
});//we need schema inorder to use the plugin 

//used to hash and salt passwords and to sace out users into mongodb database 
userSchema.plugin(passportLocalMongoose);

// This is accessing our .env variables console.log(process.env.SECRET)

//the above and below steps were needed because it gives encryption to our database

/*
LEVEL 2 : 
userSchema.plugin(encrypt,{secret : process.env.SECRET,encryptedFields : ["password"]});
*/

//Its important to add the encrypt plugin to the schema before creation of mongoose model because we are passing the schema to the model creation.
//the problem with this above encrypt is it encrypts entire database sometimes we don't want to encrypt complete data inside database and leave some fields unencrypted to do that we add option i.e { encryptedFeilds ['fieldNames which want to encrypt']}.


//By using userSchema a new model is created
const User = new mongoose.model("User",userSchema);

// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());


app.get('/',function(req,res){
    res.render('home.ejs');
});

//this means whenever user moves to login page browser sends request to the server and waits for response
app.get('/login',function(req,res){
    res.render('login.ejs');
});

app.get('/register',function(req,res){
    res.render('register.ejs');
})

app.get('/secrets',function(req,res){
    //Here we check if the user is authenticated means checking whether the user is previously logged in or not if logged in redirect to secrets page otherwise to login page.
    if(req.isAuthenticated()){
        res.render('secrets.ejs');
    } else {
        res.redirect('/login');
    }
});

app.get('/logout',function(req,res){
    //check out the documentation of passportjs for logout() method which is deauthenticating the user
    req.logout();//This is nothing but deauthenticating the user
    res.redirect("/");
});

app.post('/register',function(req,res){
    //In the documentation of localMongoose there will be some code explaining us how to register a user
    //modelname.register() username is passed as object
    User.register({username: req.body.username},req.body.password,function(err,user){
        //here user is newly registered user
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req,res,function(){
                //this callback is only triggered if the authentication is successful i.e we manage to successfully  setup a cookie that saved current logged in session.
                res.redirect("/secrets");//since session is created and remembered that particular user logged in he/she can redirect directly to "/secrets" route because the cookie will remember all the password that were entered
            })
        }
        //if there is no error using passport we are going to authenticate the user and the type of authentication we are performing is ( local )
    })
});
//After registering if you see mongocompass you will observe that both salt and hash exists which says that "passportLocalMongoose" will salt and hash our password 

app.post('/login',function(req,res){
    
    const user = new User({
        username : req.body.username,
        password : req.body.password
    });

    //passport is being used inorder to login the user and authenticate the user. Inorder to do that we are going to use the login() availble in passportjs documentation.
    //here below the user is someone : The new user that comes from the login credentials the user provided on our loggin page
    //callback function is used to check whether the user entered id exist in the database or not.
    req.login(user,function(err){
        if(err){
            console.log(err);
        } else {
            passport.authenticate('local')(req,res,function(){
                res.redirect('/secrets');
            })
        }
    })
})
//both when successfully registered and successfully logged in then we are going to send the cookie to the browser and tell the browser to hold that cookie because the cookie has few pieces of information that tells our server about the information mainly that we are authorized to view any of the pages that require authentication.

app.listen(3000,function(){
    console.log('listening on port 3000');
})

//At first a message or password is completely visible to everyone - LEVEL 1 encryption
/*
LEVEL 2 encryption - encryption is done by right and left shift of msgs something like that for this encryption mongoose-encryption is used to encrypt.
In this level encryption when we call save automatically behind the scenes mongoose-encryption will encrypt the fields and later on when we try to find() then at that stage mongoose-encrypt will decrypt the fields to check for the password is correct or not(As per the example).
*/
//After this once you check the password that you have entered in the mongodb compass you will observe that password is encrypted

//LEVEL 3 encryption - We use Hashing technique to encrypt the passwords