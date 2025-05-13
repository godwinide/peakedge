const router = require("express").Router();

router.get("/", (req, res) => {
    try {
        return res.render("index", { pageTitle: "Welcome", req, res });
    }
    catch (err) {
        return res.redirect("/");
    }
});

router.get("/about", (req, res) => {
    try {
        return res.render("about", { pageTitle: "About Us", req, res });
    }
    catch (err) {
        return res.redirect("/");
    }
});

router.get("/investment", (req, res) => {
    try {
        return res.render("investment", { pageTitle: "Investment", req, res });
    }
    catch (err) {
        return res.redirect("/");
    }
});

router.get("/partners", (req, res) => {
    try {
        return res.render("partners", { pageTitle: "Partners", req, res });
    }
    catch (err) {
        return res.redirect("/");
    }
});

router.get("/contact", (req, res) => {
    try {
        return res.render("support", { pageTitle: "contact", req, res });
    }
    catch (err) {
        return res.redirect("/");
    }
});

router.get("/terms", (req, res) => {
    try {
        return res.render("terms", { pageTitle: "Terms", req, res });
    }
    catch (err) {
        return res.redirect("/");
    }
});

router.get("/forgot_password", (req, res) => {
    try {
        return res.render("forgot", { pageTitle: "Forgot Password", req, res });
    }
    catch (err) {
        return res.redirect("/");
    }
});



module.exports = router;