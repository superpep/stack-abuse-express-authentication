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
        jwt.verify(token, secret, (err, user) => { // Verifiquem el token passant-li la nostra secret key.
            if (err) { // Si dona error, el token és invalid
                return res.sendStatus(403); 
            }
            req.user = user;
            next();
        });
    } else { // Si va per aci és perque no s'ha trovat la capçalera 'AuthToken' o ve buida (logout). Per tant ha de fer login
            res.render('login', {
                message: 'Please login to continue',
                messageClass: 'alert-danger'
            });
        }
};

function authorizeAdmin(req, res, next){ // Este middleware autoriza a los administradores. Quien implemente este middleware significa que solo se podrá acceder si el usuario es admin
    if(req.user.role === 'admin') {
        next()
    } else {
        res.sendStatus(401); 
    }
};


module.exports = { getHashedPassword, isValidPass, generateAuthToken, authenticateJWT, authorizeAdmin}