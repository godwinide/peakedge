const express = require("express");
const cors = require("cors");
const app = express();
const flash = require('connect-flash');
const session = require('express-session');
const passport = require("passport")
const expressLayout = require("express-ejs-layouts");
const fileUpload = require("express-fileupload");

// CONFIGS
require("dotenv").config();
require("./config/db")();
require('./config/passport')(passport);
// MIDDLEWARES
app.use(cors());
app.use(express.static('./public'))
app.use(expressLayout);
app.set("view engine", "ejs");
app.use(express.urlencoded({
  extended: true
}));
app.use(express.json());
app.use(fileUpload({
  limits: {
    fileSize: 1024 * 1024 * 5 // 5MB max file size
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Not an image! Please upload only images.'), false);
    }
  }
}))
app.use(flash());
app.use(
  session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
  })
);
// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Global variables
app.use(function (req, res, next) {
  res.locals.sitename = "Peak Edge Trade"
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  next();
});

const PORT = process.env.PORT || 2022;

// URLS
// app.use("*", require("./routes/down"))
app.use("/", require("./routes/index"));
app.use("/", require("./routes/auth"));
app.use("/", require("./routes/user"));
app.use("/admin", require("./routes/admin/index"));
app.use("/admin", require("./routes/admin/auth"));
app.use("*", (req, res) => {
  try {
    return res.redirect("/")
  } catch (err) {
    return res.redirect("/");
  }
});

app.listen(PORT, () => console.log(`server started on port ${PORT}`));