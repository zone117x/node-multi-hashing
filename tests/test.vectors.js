const fs = require('fs')
const assert = require('assert')
const multiHashing = require('bindings')('multihashing.node')

// get all algorithms.
var algos = [];
Object.getOwnPropertyNames(multiHashing).forEach(function(algo) {
  if(typeof multiHashing[algo] === 'function')
    algos.push(algo);
});

// newly added algos.
var added = {};

//
// select sets of test vectors
// SETS=set1,set2,mytest
//
var sets = [ "set1", "set2", "set3" ];
if (process.env.SETS) {
  sets = process.env.SETS.split(",");
}

//
// skip some algos for quick test
//
// SKIPS=scryptjane,bscrypt,cryptonight mocha -gc ...
// or disable all skips
// SKIP=x mocha -gc ...
//
var skipalgos = [ 'bcrypt', 'scryptjane' ]; // disable bcrypt for now
if (process.env.SKIPS) {
  skipalgos = process.env.SKIPS.split(",");
}

sets.forEach(function(set) {
var vectors;
var update = false;

// check test vectors
if (fs.existsSync(__dirname + "/vectors/" + set + ".json")) {
  vectors = require("./vectors/" + set + ".json");
} else {
  if (fs.existsSync(__dirname + "/vectors/" + set + "-input.json")) {
    vectors = require("./vectors/" + set + "-input.json");
  } else {
    vectors = require("./vectors/input.json");
  }
  update = true;
}

// force update.
if (process.env.UPDATE) {
  update = true;
}

var buffers = vectors["strings"].map(function(str) {
  return Buffer.from(str);
});

if (!vectors["hex"]) {
  vectors["hex"] = buffers.map(function(buf) {
    return buf.toString("hex");
  });
}

// hash results
var results = {};

describe("Basic algo tests with " + set + "-vectors", function() {
  this.timeout(60000);

  algos.push("@");
  algos.forEach(function(algo) {
    // excluded alogs
    if (vectors["exclude-algos"]) {
      if (vectors["exclude-algos"].indexOf(algo) != -1) {
        return;
      }
    }

    if (algo == "@") {
      if (process.env.NODE_DEV !== 'dev' && !update) {
        return;
      }
      it("check newly added algos for " + set + '...', function() {
        if (Object.keys(added).length > 0) {
          var expect = JSON.stringify(vectors, null, 2);

          var save = {};
          if (vectors['info']) {
            save['info'] = vectors['info'];
            if (save['info']['date']) {
              save['info']['updated'] = Date();
            } else {
              save['info']['date'] = Date();
            }
          } else {
            save['info'] = { 'description': 'Simple test vectors', 'date': Date(), 'license': 'CCL0' };
          }

          save['strings'] = vectors['strings'];
          if (vectors['exclude-algos']) {
            save['exclude-algos'] = vectors['exclude-algos'];
          }
          save['hex'] = vectors['hex'];
          Object.keys(results).forEach(function(algo) {
            save[algo] = JSON.parse(JSON.stringify(results[algo]));
          });

          var actual = JSON.stringify(save, null, 2);
          // save/update results.
          fd = fs.openSync(__dirname + "/vectors/" + set + ".json", 'w');
          fs.writeSync(fd, actual + "\n");
          fs.closeSync(fd);

          assert.deepEqual(actual, expect);
        } else {
          this.skip();
        }
      });
      return;
    }

    it(algo + " algo.", function() {
      // do not test some alogs.
      if (skipalgos.indexOf(algo) != -1) {
        this.skip();
        return;
      }

      if (algo == 'argon2d' || algo == 'argon2i' || algo == 'argon2id') {
        //var tValue = 2, mValue = 500, pValue = 8; // argon2d_dyn_hash
        var tValue = 1, mValue = 250, pValue = 4; // argon2d_crds_gate
        results[algo] = buffers.map(function(buf, i) {
          var ret = multiHashing[algo](buf, tValue, mValue, pValue);
          return ret.toString('hex');
	});
      } else if (algo == 'cryptonight') {
        console.log("      * " + algo);
        results[algo] = {};
        for (var variant = 0; variant <= 4; ++variant) {
          var height = 1806260;
          results[algo][variant] = buffers.map(function(buf, i) {
            var ret = multiHashing['cryptonight'](buf, variant, height + i);
            return ret.toString('hex');
	  });
          console.log("      - variant = " + variant);
        }
      } else if (algo == 'cryptonightfast') {
        console.log("      * " + algo);
        results[algo] = {};
        for (var variant = 0; variant <= 1; ++variant) {
          results[algo][variant] = buffers.map(function(buf, i) {
            var ret = multiHashing['cryptonightfast'](buf, variant == 0 ? true : variant);
            return ret.toString('hex');
	  });
          console.log("      - variant = " + (variant == 0 ? 'fast' : variant));
        }
      } else if (algo == 'scryptn') {
        var Nfactor = 100;
        results[algo] = buffers.map(function(buf, i) {
          var ret = multiHashing[algo](buf, Nfactor + i);
          return ret.toString('hex');
	});
      } else if (algo == 'scrypt') {
        var nVal = 10, rVal = 20;
        results[algo] = buffers.map(function(buf, i) {
          var ret = multiHashing[algo](buf, nVal, rVal);
          return ret.toString('hex');
	});
      } else if (algo == 'boolberry') {
        var height = 1233320;
        var scratch_pad = Buffer.alloc(64);
        scratch_pad.fill("deadbeef");
        results[algo] = buffers.map(function(buf, i) {
          var ret = multiHashing[algo](buf, scratch_pad, height + i);
          return ret.toString('hex');
	});
      } else if (algo == 'scryptjane') {
        //scryptjane needs block.nTime and nChainStartTime (found in coin source)
        var yaCoinChainStartTime = 1367991200;
        var nTime = Math.round(Date.now() / 1000);
        results[algo] = buffers.map(function(buf) {
          var ret = multiHashing[algo](buf, nTime, yaCoinChainStartTime, 4, 30);
          return ret.toString('hex');
	});
      } else if (algo == 'neoscrypt') {
        results[algo] = buffers.map(function(buf, i) {
          var ret = multiHashing[algo](buf, null);
          return ret.toString('hex');
	});
      } else {
        results[algo] = buffers.map(function(buf) {
          var ret = multiHashing[algo](buf);
          return ret.toString('hex');
	});
      }

      // vectors result
      if (vectors[algo] && results[algo]) {
        assert.deepEqual(results[algo], vectors[algo]);
      } else {
        var ret = {};
        ret[algo] = results[algo];
        added[algo] = results[algo];
        update = true;

        console.log(JSON.stringify(ret, null, 2));

        assert.deepEqual(results[algo], vectors[algo]);
        this.skip();
      }
    });
  });
});

});
