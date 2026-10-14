const { Router } = require('express');
var express = require('express');
var router = express.Router();
const axios = require('axios');
const { parse } = require('cookie');
const fs = require('fs');


router.get('/', async (req, res) => {
    try {
        const url = req.query.url;
        const parsedUrl = new URL(url);
        if (parsedUrl.hostname.endsWith('.baidu.com')) {
            const { data } = await axios.get(url, { timeout: 3000 });
            res.send(data);
        } else {
            res.status(400).send("Invalid URL<!--endsWith('.baidu.com')-->");
        }
    } catch (e) {
        console.log(e);
        res.status(400).send('Could not access, check the url param plz');
    }
});

router.get('/hint', async (req, res) => {
    res.send("hint is here, and port 3456 have good thing<br \>" + 
    "<!--the libuv version is:" + process.versions.uv + "-->" +
   "<!--the node version is:" + process.versions.node + "-->" + "and if you are really sure about the answer, then maybe you could try more times~")
});

const internalApp = express();
internalApp.get('/secret', (req, res) => {
    res.send("flag_is_here");
});
internalApp.listen(3456);

module.exports = router;
