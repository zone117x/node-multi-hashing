node-multi-hashing
===============

Cryptocurrency hashing functions for node.js.

Usage
-----

Install

```bash
npm install multi-hashing
```


Hash your data

```javascript
var multiHashing = require('multi-hashing');

var data = new Buffer("hash me good bro");
var hashed = multiHashing.x11(data); //returns a 32 byte buffer

console.log(hashed);
//<SlowBuffer 0b de 16 ef 2d 92 e4 35 65 c6 6c d8 92 d9 66 b4 3d 65 ..... >
```

Credits
-------

* Creators of the SHA2 and SHA3 hashing algorithms used here
* X11 & Quark creators