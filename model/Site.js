const { model, Schema } = require("mongoose");

const SiteSchema = new Schema({
    wallet: {
        type: String,
        required: true
    }
});

module.exports = Site = model("Site", SiteSchema);