node-multi-hashing
===============

Cryptocurrency hashing functions for node.js.

Usage
-----

Install

```bash
npm install multi-hashing
```

So far this native Node.js addon can do the following hashing algos

```javascript
var multiHashing = require('multi-hashing');

var algorithms = ['quark', 'x11', 'scrypt', 'scryptn', scryptjane', 'keccak', 'bcrypt'];

var data = new Buffer("hash me good bro");

var hashedData = algorithms.map(function(algo){
    if (algo === 'scryptjane'){
        //scryptjane needs block.nTime and nChainStartTime (found in coin source)
        var yaCoinChainStartTime = 1367991200;
        var timestamp = Math.round(Date.now() / 1000);
        return algorithms[algo](data, nTime, yaCoinChainStartTime);
    }
    else{
        return return algorithms[algo](data);
    }
});


console.log(hashedData);
//<SlowBuffer 0b de 16 ef 2d 92 e4 35 65 c6 6c d8 92 d9 66 b4 3d 65 ..... >

//Another example...
var hashedScryptData = multiHashing.scrypt(new Buffer(32));

```

Credits
-------

* Creators of the SHA2 and SHA3 hashing algorithms used here
* X11 & Quark creators