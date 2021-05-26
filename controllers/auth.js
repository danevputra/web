const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const {promisify} = require('util');
const path = require('path');
const xss = require("xss");

const db = mysql.createConnection({
    host : process.env.DATABASE_HOST,
    user : process.env.DATABASE_USER,
    password : process.env.DATABASE_PASSWORD,
    database : process.env.DATABASE
});

exports.register = (req, res) =>{
    //console.log(req.body);

    //const {name,email,password,passwordConfirm,alamat,deskripsi,jenis,telepon} = req.body;
    const name = xss(req.body.name); 
    const email = xss(req.body.email); 
    const password = xss(req.body.password); 
    const passwordConfirm = xss(req.body.passwordConfirm); 
    const alamat = xss(req.body.alamat); 
    const deskripsi = xss(req.body.deskripsi); 
    const jenis = xss(req.body.jenis); 
    const telepon = xss(req.body.telepon); 
    const file = req.files.photo;
    const img=file.name;
    const img_name = new Date().getTime()+'_'+img;
    //console.log(img_name);

    db.query('SELECT email FROM users WHERE email = ?',[email],async (error,result) =>{
        if(error) console.log(error);
        if (result.length>0){
            return res.render('register',{
                message : 'Email tersebut telah terdaftar'
            });
        }
        else if (password != passwordConfirm){
            return res.render('register',{
                message : 'Password tidak cocok'
            });
        }
        let hashedPassword = await bcrypt.hash(password,8);
        console.log(hashedPassword);
        if(file.mimetype == "image/jpeg" ||file.mimetype == "image/png"||file.mimetype == "image/gif"){
            if (file.size<=50000)
            {
                file.mv('public/images/profile/'+img_name, function(err) {
                                
                    if (err)
                        return res.status(500).send(err);
                    else
                    {
                        db.query ('INSERT INTO users SET ?',{name : name, email : email, password:hashedPassword,photo:img_name,alamat:alamat,deskripsi:deskripsi,jenis:jenis,telepon:telepon},(error,result)=>{
                            if (error) console.log(error);
                            else {
                                console.log(result);
                                return res.render('login',{
                                    message : 'Akun telah terdaftar. Silakan login'
                                });
                            }
                        });
                    }
                });
            }
            else {
                res.render('register',{
                    message: "Ukuran foto terlalu besar"
                });
              }
        }else {
            res.render('register',{
                message: "Allowed format .png,.gif,.jpeg"
            });
          }
    });
}

exports.login = async(req,res) =>{
    try {
        //const {email,password} = req.body;
        const email = xss(req.body.email);
        const password = xss(req.body.password);
        if(!email || !password){
            return res.status(400).render('login',{
                message : 'Mohon isikan email dan password'
            });
        }
        db.query('SELECT * FROM users WHERE email = ?', [email],async(error,result)=>{
            //console.log(result);
            if(!result || !(await bcrypt.compare(password,result[0].password))){
                res.status(401).render('login',{
                    message : 'Email atau Password salah'
                });
            }
            else{
                const id = result[0].id;

                const token = jwt.sign({id},process.env.JWT_SECRET,{
                    expiresIn: process.env.JWT_EXPIRES_IN
                });
                //console.log("The token is : "+token);

                const cookieOptions = {
                    expires : new Date(
                        Date.now() + process.env.JWT_COOKIE_EXPIRES *24*60*60*1000
                    ),
                    httpOnly: true
                }
                res.cookie('jwt',token,cookieOptions);
                res.status(200).redirect('/');
            }
        });
    } catch (error) {
        console.log(error)
    }
}

exports.isLoggedIn = async (req,res,next) => {
    // console.log(req.cookies);
    if(req.cookies.jwt){
        try {
            const decoded = await promisify(jwt.verify)(req.cookies.jwt,process.env.JWT_SECRET);
            console.log(decoded);
            db.query('SELECT users.id, users.name, users.email,users.alamat,users.jenis,users.deskripsi, users.photo, jenis.nama, users.telepon FROM users JOIN jenis ON users.jenis = jenis.id WHERE users.id = ?',[decoded.id],(error,result)=>{
                console.log(result);
                if(!result){
                    return next();
                }

                req.user = result[0];
                return next();
            });
        } catch (error) {
            return next();
        }
    }
    else
        next();
}

exports.logout = async (req,res) => {
    res.cookie('jwt','logout',{
        expires : new Date(Date.now()+2*1000),
        httpOnly : true
    });
    res.status(200).redirect('/');
}

exports.connect = (req,res) =>{
    const umkm = xss(req.body.umkm);
    const nama = '%' + umkm + '%';
    // console.log(umkm);
    db.query("SELECT users.id, users.name, users.email,users.alamat,users.jenis,users.deskripsi, users.photo, jenis.nama, users.telepon FROM users JOIN jenis ON users.jenis = jenis.id WHERE users.name LIKE ?",[nama],(error,result)=>{
        if(error) console.log(error);
        else {
            res.render('connect',{
                temu : result
            });
        }
    });
}