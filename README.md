# sm3js
[![Build Status](https://travis-ci.org/emmansun/sm3js.svg?branch=main)](https://travis-ci.org/emmansun/sm3js)
[![npm version](https://badge.fury.io/js/gmsm-sm3js.svg)](https://badge.fury.io/js/gmsm-sm3js)
[![NPM Downloads][npm-downloads-image]][npm-url]

**sm3js is a pure Javascript implementation of the GM-Standards SM3 hash functions.**

If you use sm3 with NodeJs, please use nodejs crypto directly.


    const crypto = require('crypto');
    
    function sm3Digest(content) {
      const h = crypto.createHash('sm3');
      return h.update(content).digest('hex');
    }
    
    // sm3Digest('abc') === '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'


[npm-downloads-image]: https://badgen.net/npm/dm/gmsm-sm3js
[npm-url]: https://npmjs.org/package/gmsm-sm3js
