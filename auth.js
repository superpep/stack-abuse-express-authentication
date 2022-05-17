const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken");
const secret = 'xurroLlargQueHiHaQueFicarEnUnArxiuDeConfiguracióINoAci'



const getHashedPassword = (password) => {
    const salt = bcrypt.genSaltSync(10);
    return bcrypt.hashSync(password, salt);
}

const isValidPass = (password, hash) => {
   return bcrypt.compareSync(password, hash);
}

const generateAuthToken = (user) => {
    return jwt.sign({
        name: user.name,
        email: user.email,
        id: user.id,
        role: user.role
    }, secret, {expiresIn: '2h'});
}

function authenticateJWT(req, res, next){
    const token = req.cookies['AuthToken']
    if (token) {
        jwt.verify(token, secret, (err, user) => {
            if (err) {
                return res.sendStatus(403); 
            }
            req.user = user;
            next();
        });
    } else { 
            res.render('login', {
                message: 'Please login to continue',
                messageClass: 'alert-danger'
            });
        }
};

function authorizeAdmin(req, res, next){
    if(req.user.role === 'admin') {
        next()
    } else {
        res.sendStatus(401); 
    }
};


module.exports = { getHashedPassword, isValidPass, generateAuthToken, authenticateJWT, authorizeAdmin}