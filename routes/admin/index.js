const router = require("express").Router();
const User = require("../../model/User");
const History = require("../../model/History");
const Site = require("../../model/Site");
const { ensureAdmin } = require("../../config/auth");
const bcrypt = require("bcryptjs/dist/bcrypt");

router.get("/", ensureAdmin, async (req, res) => {
    try {
        const customers = await User.find({ isAdmin: false });
        const history = await History.find({});
        const total_bal = customers.reduce((prev, cur) => prev + Number(cur.balance), 0);
        return res.render("admin/index", { layout: "admin/layout", res, pageTitle: "Welcome", customers, history, total_bal, req });
    }
    catch (err) {
        return res.redirect("/admin");
    }
});

router.get("/edit-user/:id", ensureAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const customer = await User.findOne({ _id: id });
        return res.render("admin/editUser", { layout: "admin/layout", res, pageTitle: "Welcome", customer, req });
    }
    catch (err) {
        return res.redirect("/admin");
    }
});

router.post("/edit-user/:id", ensureAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const {
            email,
            username,
            phone,
            currency,
            country,
            security_question,
            security_answer,
            balance,
            total_deposit,
            active_deposit,
            last_deposit,
            total_earned,
            last_withdraw,
            total_withdraw,
            pending_withdrawal,
            withdrawal_fee,
            userIP,
            requireUpgrade,
            account_plan,
            pin
        } = req.body;
        await User.updateOne({ _id: id }, {
            email,
            username,
            phone,
            currency,
            country,
            security_question,
            security_answer,
            last_withdraw,
            last_deposit,
            userIP,
            pending_withdrawal: pending_withdrawal || 0,
            balance: balance || 0,
            pin: pin || Number(String(Math.random()).slice(2, 8)),
            total_deposit: total_deposit || 0,
            total_earned: total_earned || 0,
            active_deposit: active_deposit || 0,
            total_withdraw: total_withdraw || 0,
            withdrawal_fee: withdrawal_fee || 0,
            requireUpgrade,
            account_plan: account_plan || "STARTER ($1,000 - $10,000)"
        });
        req.flash("success_msg", "account updated");
        return res.redirect("/admin/edit-user/" + id);
    }
    catch (err) {
        console.log(err);
        return res.redirect("/admin");
    }
});

router.get("/delete-account/:id", ensureAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!id) {
            return res.redirect("/admin");
        }
        await User.deleteOne({ _id: id });
        return res.redirect("/admin");
    } catch (err) {
        return res.redirect("/admin")
    }
});

router.get("/deposit", ensureAdmin, async (req, res) => {
    try {
        const customers = await User.find({});
        return res.render("admin/deposit", { res, layout: "admin/layout", pageTitle: "Deposit", customers, req });
    } catch (err) {
        return res.redirect("/admin")
    }
});

router.post("/deposit", ensureAdmin, async (req, res) => {
    try {
        const { amount, userID, debt } = req.body;
        if (!amount || !userID || !debt) {
            req.flash("error_msg", "Please provide all fields");
            return res.redirect("/admin/deposit");
        }
        const customer = await User.findOne({ _id: userID });
        const newHistData = {
            type: "Credit",
            userID,
            amount,
            status: 'successful',
            account: customer.email
        }
        const newHist = new History(newHistData);
        await newHist.save();

        await User.updateOne({ _id: userID }, {
            balance: Number(customer.balance) + Number(amount),
            active_deposit: Number(customer.active_deposit) + Number(amount),
            debt,
            total_deposit: Number(customer.total_deposit) + Number(amount)
        });

        req.flash("success_msg", "Deposit successful");
        return res.redirect("/admin/deposit");

    } catch (err) {
        console.log(err);
        return res.redirect("/admin");
    }
})

router.get("/change-password", ensureAdmin, async (req, res) => {
    try {
        return res.render("admin/changePassword", { res, layout: "admin/layout", pageTitle: "Change Password", req });
    } catch (err) {
        console.log(err);
        return res.redirect("/admin");
    }
})

router.post("/change-password", ensureAdmin, async (req, res) => {
    try {
        const { password, password2 } = req.body;
        console.log(req.body);
        if (!password || !password2) {
            req.flash("error_msg", "Please provide fill all fields");
            return res.redirect("/admin/change-password");
        }
        else if (password !== password2) {
            req.flash("error_msg", "Both passwords must be same");
            return res.redirect("/admin/change-password");
        }
        else if (password.length < 6) {
            req.flash("error_msg", "Password too short")
            return res.redirect("/admin/change-password");
        } else {
            const salt = await bcrypt.genSalt();
            const hash = await bcrypt.hash(password2, salt);
            await User.updateOne({ _id: req.user.id }, {
                password: hash
            });
            req.flash("success_msg", "password updated successfully");
            return res.redirect("/admin/change-password");
        }

    } catch (err) {
        console.log(err);
        return res.redirect("/admin");
    }
});

router.get("/site-settings", ensureAdmin, async (req, res) => {
    try {
        const site = await Site.findOne();
        const walletAddress = site?.wallet || "";
        return res.render("admin/siteSettings", { layout: "admin/layout", res, pageTitle: "Welcome", walletAddress, req });
    }
    catch (err) {
        console.log(err);
        return res.redirect("/admin");
    }
});

router.post("/site-settings", ensureAdmin, async (req, res) => {
    try {
        const { walletAddress } = req.body;
        if (!walletAddress) {
            req.flash("error_msg", "Please enter your wallet address");
            return res.redirect("/admin/site-settings")
        }
        await Site.updateMany({}, { wallet: walletAddress });
        req.flash("success_msg", "site updated successfully");
        return res.redirect("/admin/site-settings");
    }
    catch (err) {
        console.log(err);
        return res.redirect("/admin");
    }
});

router.post("/credit-account", ensureAdmin, async (req, res) => {
    try {
        const { amount, userId, creditType } = req.body;
        const customer = await User.findOne({ _id: userId });
        const newHist = new History({
            type: creditType,
            userID: userId,
            amount,
            status: 'successful'
        });
        await newHist.save();
        if(creditType === 'Profit'){
            customer.balance += Math.abs(amount);
            customer.total_earned += Math.abs(amount);
            await customer.save();
        }else {
            customer.balance += Math.abs(amount);
            customer.active_deposit += Math.abs(amount);
            await customer.save();
        }
        req.flash("success_msg", "Credit successful");
        return res.redirect(`/admin/edit-user/${userId}`);
    }
    catch (err) {
        console.log(err);
        return res.redirect("/admin");
    }
});

module.exports = router;