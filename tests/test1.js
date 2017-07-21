const multi_hashing = require("../")

var buf = new Buffer('string for hashing','utf8');

console.log(multi_hashing.quark(buf))
