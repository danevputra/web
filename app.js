const express = require('express');
const path = require('path');
const mysql = require('mysql');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const fileUpload = require('express-fileupload');

dotenv.config({
    path : './.env',
});

const app = express();
const db = mysql.createConnection({
    host : process.env.DATABASE_HOST,
    user : process.env.DATABASE_USER,
    password : process.env.DATABASE_PASSWORD,
    database : process.env.DATABASE
});

const publicDirectory = path.join(__dirname,'./public');
app.use(express.static(publicDirectory));

app.use (express.urlencoded({extended : false}));
app.use (express.json());
app.use(cookieParser());
app.use(fileUpload());

app.set('view engine', 'hbs');

db.connect((error)=>{
    if (error)
        console.log(error);
    else
        console.log("mysql connected");
});

//Define Routes
app.use('/',require('./routes/pages'));
app.use('/auth',require('./routes/auth'));

app.listen(5000, () =>{
    console.log("Server started on port 5000");
});