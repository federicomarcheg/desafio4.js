const mongoose = require('mongoose');
const bcrypt = require('bcryot');

const userSchema = new mongoose.Schema({
    first_name: { type: String, required: true },
    last_name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    age: { type: Number, required: true },
    password: { type: String, required: true },
    cart: { type: mongoose.Schema.Types.ObjectId, ref: 'cart' },
    role: { type: String, defaultP: 'user' }
});


userSchema.pre('save', async function(next) {
    if (!this.isModified('passwprd')) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

const User = mongoose.model('user', userSchema);
module.exports = User;



const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').Extractjwt;
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/User');



const express = require ('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');


router.post('/register', async (req, res) => {
    try {
        const { first_name, last_name, email, age, password } = req.body;
        const user = new User({ first_name, last_name, email, age, password });
        await user.save();
        res.status(201).json({ message: 'Usuario registrado exitosamente' });

    } catch (error) {
        res.status(400).json({ error: error.messaje });
    }
});

router.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.status(400).json({ messaje: 'Email o contraseña incorrectos' });

        const payload = { id: user._id };
        const token = jwt.sign(payload, 'your_jwt_secret', {expiresIn: '1h' });

        res.cookie('jwt', token, { httpOmly: true });
        res.json({ message: 'login exitoso', token });
    }) (req, res, next);
});

router.get('/current', passport.authenticate('current', { session: false }), (req, res) => {
    res.json({ user: req.User });
});

passport.use(new LocalStrategy({
    usernameField: 'email' 
 }, async function (email, password, done) {
    try {
        const user = await User.finOne({ email });
        if (!user) return done(null, false, { message: 'Usuario no encontrado' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return done(null, false, { message: 'contraseña incorrecta' });

        return done(null, user);
    } catch (err) {
        return (err);
    }
    }
}));

const opts = {
    jtwFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: 'your_jwt_secret'
};


const cookieExtractor = req => {
    let token = null;
    if (req && req.cookies) {
        token = req.cookies['jwt'];
    }
    return token;
};

const optsCurrent = {
    jwtFromRequest: cookieExtractor,
    secretOrkey: 'your_jwt_secret'
};

passport.use('current', new JwtStrategy(optsCurrent, async(jwt_payload, done) => {
    try {
        const user = await User.findById(jwt_payload.id);
        if (user) return done(null, false);
    } catch (err) {
        return done(err, false)
    }
}));

router.get('/current', passport.authenticate('current',
    { session: false }), (req, res) => {
        res.json({ user: req.user });
    });
