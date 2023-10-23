//jshint esversion:6
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');

const app = express();

app.use(express.static("public"));//this is for using css files
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));


mongoose.connect('mongodb://127.0.0.1:27017/userDB',{useNewUrlParser : true});

//setting up database 
const userSchema = new mongoose.Schema({
    email : String,
    password : String
});

//this secret variable value is the reference value which we will use for encrypting the database
const secret = "Thisisourlittlesecret.";
//the above and below steps were needed because it gives encryption to our database
userSchema.plugin(encrypt,{secret : secret,encryptedFields : ["password"]});
//Its important to add the encrypt plugin to the schema before creation of mongoose model because we are passing the schema to the model creation.
//the problem with this above encrypt is it encrypts entire database sometimes we don't want to encrypt complete data inside database and leave some fields unencrypted to do that we add option i.e { encryptedFeilds ['fieldNames which want to encrypt']}.


//By using userSchema a new model is created
const User = new mongoose.model("User",userSchema);

app.get('/',function(req,res){
    res.render('home.ejs');
})

//this means whenever user moves to login page browser sends request to the server and waits for response
app.get('/login',function(req,res){
    res.render('login.ejs');
})

app.get('/register',function(req,res){
    res.render('register.ejs');
})

app.post('/register',function(req,res){
    const newUser = new User({
        email : req.body.username,
        password : req.body.password
    });

    newUser.save().then(function(){
        res.render('secrets.ejs');
    }).catch(function(err){
        console.log(err);
    })
})

app.post('/login',function(req,res){
    const userName = req.body.username;
    const password = req.body.password;

    //this means from the collection find where the email field is matching with our username field
    //remember that the usename field is the one that user entered whereas email is the one in our database

    User.findOne({email : userName}).then(function(foundUser){
        //if user if found then check for password
        if(foundUser){
            if(foundUser.password === password){
                res.render("secrets.ejs");
            }
        }
    }).catch(function(err){
        console.log(err);
    });
})

app.listen(3000,function(){
    console.log('listening on port 3000');
})

//At first a message or password is completely visible to everyone - LEVEL 1 encryption
/*
LEVEL 2 encryption - encryption is done by right and left shift of msgs something like that for this encryption mongoose-encryption is used to encrypt.
In this level encryption when we call save automatically behind the scenes mongoose-encryption will encrypt the fields and later on when we try to find() then at that stage mongoose-encrypt will decrypt the fields to check for the password is correct or not(As per the example).
*/
//After this once you check the password that you have entered in the mongodb compass you will observe that password is encrypted