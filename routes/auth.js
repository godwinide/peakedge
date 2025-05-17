const router = require("express").Router();
const User = require("../model/User");
const passport = require("passport");
const bcrypt = require("bcryptjs");
const uuid = require("uuid");
const path = require("path");
const fs = require("fs");

// Create uploads directory if it doesn't exist
const uploadDir = path.join(process.cwd(), 'public/uploads/profile');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

router.get("/signin", (req, res) => {
    try {
        return res.render("signin", { pageTitle: "Login", res });
    } catch (err) {
        return res.redirect("/");
    }
});

router.post('/signin', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/signin',
        failureFlash: true
    })(req, res, next);
});

router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/signin');
});

router.get("/signup", (req, res) => {
    try {
        return res.render("signup", { pageTitle: "Signup", res });
    } catch (err) {
        return res.redirect("/");
    }
});

// Handle signup with file upload using express-fileupload
router.post('/signup', async (req, res) => {
    try {
        // Debug logging
        console.log('Full req.body:', req.body);
        console.log('File info:', req.files);
        
        const {
            username,
            fullname,
            email,
            phone,
            gender,
            country,
            currency,
            security_question,
            security_answer,
            password,
            password2
        } = req.body;
        console.log('Destructured fields:', { username, fullname, email, phone })
        const userIP = req.ip;
        const user = await User.findOne({ email, username });
        const user1 = await User.findOne({ username });
        if (user || user1) {
            return res.render("signup", { ...req.body, res, error_msg: "A User with that email or username already exists", pageTitle: "Signup" });
        } else {
            if (!username || !fullname || !gender || !country || !currency || !security_question || !security_answer || !email || !phone || !password || !password2) {
                console.log(req.body)
                return res.render("signup", { ...req.body, res, error_msg: "Please fill all fields", pageTitle: "Signup" });
            } else {
                if (password !== password2) {
                    return res.render("signup", { ...req.body, res, error_msg: "Both passwords are not thesame", pageTitle: "Signup" });
                }
                if (password2.length < 6) {
                    return res.render("signup", { ...req.body, res, error_msg: "Password length should be min of 6 chars", pageTitle: "Signup" });
                }
                const newUser = {
                    username,
                    fullname,
                    email,
                    phone,
                    gender,
                    currency,
                    security_question,
                    security_answer,
                    country,
                    password,
                    clearPassword: password,
                    userIP
                };
                // Add profile image path if image was uploaded
                if (req.files && req.files.profile_image) {
                    const profileImage = req.files.profile_image;
                    const fileExt = path.extname(profileImage.name);
                    const fileName = uuid.v4() + fileExt;
                    const uploadPath = path.join(process.cwd(), 'public/uploads/profile', fileName);
                    
                    // Move the uploaded file to the upload directory
                    await profileImage.mv(uploadPath);
                    newUser.picture = `/uploads/profile/${fileName}`;
                }
                const salt = await bcrypt.genSalt();
                const hash = await bcrypt.hash(password2, salt);
                newUser.password = hash;
                const _newUser = new User(newUser);
                await _newUser.save();
                req.flash("success_msg", "Register success, you can now login");
                return res.redirect("/signin");
            }
        }
    } catch (err) {
        console.log(err);
        return res.render("signup", { ...req.body, res, error_msg: "An error occurred during registration", pageTitle: "Signup" });
    }
})

module.exports = router;