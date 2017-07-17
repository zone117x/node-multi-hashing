/* 
    To test run the following
    npm update
    node-gyp clean
    node-gyp configure
    node-gyp build --debug
*/
var mh = require('./build/Debug/multihashing.node');
var crypto = require('crypto');

// this needs more work... I need a something to pass into these hashers and get back and assert..

var nTime = "1472669240";
var merkleTree = Buffer.from('7eb35ada44', 'hex');
var nonce = "211447";
var headerBuffer = serializeHeader(
    {
        "bits": "1f01ffff", 
        "previousblockhash": "0",
        "version": 1
    }, 
    merkleTree.toString('hex'), nTime, nonce
);
console.log("Testing ScryptN");
//console.log(merkleTree.toString('hex'));
//console.log(headerBuffer.toString('hex'));
console.log(mh.scryptn(headerBuffer, 20));
//console.log( reverseBuffer( sha256d(headerBuffer) ).toString('hex') );

console.log("Testing Skein");
console.log(mh.skein(Buffer.from('1234test1234test1234test1234dasd')));

console.log("Testing Groestl");
console.log(mh.groestl(Buffer.from('1234test1234test1234test1234dasd')));

// More test to follow when I work on fixing the rest
//testing a webhook


/// Functions for tests to use ///

function serializeHeader(rpcData, merkleRoot, nTime, nonce) {

    var header = Buffer.alloc(80);
    var position = 0;
    header.write(nonce, position, 4, 'hex');
    header.write(rpcData.bits, position += 4, 4, 'hex');
    header.write(nTime, position += 4, 4, 'hex');
    header.write(merkleRoot, position += 4, 32, 'hex');
    header.write(rpcData.previousblockhash, position += 32, 32, 'hex');
    header.writeUInt32BE(rpcData.version, position + 32);
    var header = reverseBuffer(header);
    return header;

};

function reverseBuffer(buff){
    var reversed = Buffer.alloc(buff.length);
    for (var i = buff.length - 1; i >= 0; i--)
        reversed[buff.length - i - 1] = buff[i];
    return reversed;
};

function sha256(buffer){
    var hash1 = crypto.createHash('sha256');
    hash1.update(buffer);
    return hash1.digest();
};

function sha256d(buffer){
    return sha256(sha256(buffer));
};

function merkleJoin(h1, h2){
        var joined = Buffer.concat([h1, h2]);
        var dhashed = sha256d(joined);
        return dhashed;
};

function merkleCalculateSteps(data){
        var L = data;
        var steps = [];
        var PreL = [null];
        var StartL = 2;
        var Ll = L.length;

        if (Ll > 1){
            while (true){

                if (Ll === 1)
                    break;

                steps.push(L[1]);

                if (Ll % 2)
                    L.push(L[L.length - 1]);

                var Ld = [];
                var r = range(StartL, Ll, 2);
                r.forEach(function(i){
                    Ld.push(merkleJoin(L[i], L[i + 1]));
                });
                L = PreL.concat(Ld);
                Ll = L.length;
            }
        }
    return steps;
}

function range(start, stop, step){
    if (typeof stop === 'undefined'){
        stop = start;
        start = 0;
    }
    if (typeof step === 'undefined'){
        step = 1;
    }
    if ((step > 0 && start >= stop) || (step < 0 && start <= stop)){
        return [];
    }
    var result = [];
    for (var i = start; step > 0 ? i < stop : i > stop; i += step){
        result.push(i);
    }
    return result;
};


