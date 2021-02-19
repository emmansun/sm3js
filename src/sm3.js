const Long = require('long')

const SM3_CHUNK = 64
const SM3_SIZE = 32
const SM3_BLOCKSIZE = 64
const SM3_IV32 = new Uint32Array([
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
  0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
])
const SM3_T = [0x79cc4519, 0x7a879d8a]

const ERROR_MSG_INPUT = 'Input must be an string, Buffer or Uint8Array'

function uint8 (n) {
  return n & 0xff
}

function uint32 (n) {
  return n & 0xffffffff
}

function rotateLeft32 (x, k) {
  const n = 32
  const s = k & (n - 1)
  return (x << s) | (x >>> (n - s))
}

function _t (j) {
  j = uint8(j)
  if (j < 16) {
    return SM3_T[0]
  }
  return SM3_T[1]
}

function _p0 (x) {
  return x ^ rotateLeft32(x, 9) ^ rotateLeft32(x, 17)
}

function _p1 (x) {
  return x ^ rotateLeft32(x, 15) ^ rotateLeft32(x, 23)
}

function _ff (j, x, y, z) {
  if (j < 16) {
    return x ^ y ^ z
  }
  return (x & y) | (x & z) | (y & z)
}

function _gg (j, x, y, z) {
  if (j < 16) {
    return x ^ y ^ z
  }
  return (x & y) | (~x & z)
}

// For convenience, let people hash a string, not just a Uint8Array
function normalizeInput (input) {
  let ret
  if (input instanceof Uint8Array) {
    ret = input
  } else if (input instanceof Buffer) {
    ret = new Uint8Array(input)
  } else if (typeof (input) === 'string') {
    ret = new Uint8Array(Buffer.from(input, 'utf8'))
  } else {
    throw new Error(ERROR_MSG_INPUT)
  }
  return ret
}

// Converts a Uint8Array to a hexadecimal string
// For example, toHex([255, 0, 255]) returns "ff00ff"
function toHex (bytes) {
  return Array.prototype.map.call(bytes, function (n) {
    return (n < 16 ? '0' : '') + n.toString(16)
  }).join('')
}

function fromHex (hexStr) {
  if (typeof hexStr !== 'string' || hexStr.length % 2 === 1) {
    throw new Error('Invalid hex string')
  }
  const bytes = []
  for (let i = 0; i < hexStr.length; i += 2) {
    bytes.push(parseInt(hexStr.substr(i, 2), 16))
  }
  return new Uint8Array(bytes)
}

// For performance testing: generates N bytes of input, hashes M times
// Measures and prints MB/second hash performance each time
function testSpeed (hashFn, N, M) {
  let startMs = new Date().getTime()

  const input = new Uint8Array(N)
  for (let i = 0; i < N; i++) {
    input[i] = i % 256
  }
  const genMs = new Date().getTime()
  console.log('Generated random input in ' + (genMs - startMs) + 'ms')
  startMs = genMs

  for (let i = 0; i < M; i++) {
    const hashHex = hashFn(input)
    const hashMs = new Date().getTime()
    const ms = hashMs - startMs
    startMs = hashMs
    console.log('Hashed in ' + ms + 'ms: ' + hashHex.substring(0, 20) + '...')
    console.log(Math.round(N / (1 << 20) / (ms / 1000) * 100) / 100 + ' MB PER SECOND')
  }
}

function copy (dst, start, src) {
  let i = start
  for (; i < dst.length && (i - start) < src.length; i++) {
    dst[i] = src[i - start]
  }
  return i - start
}

class Digest {
  constructor () {
    this.h = new Uint32Array(8)
    this.x = new Uint8Array(SM3_CHUNK)
    this.nx = 0
    this.len = new Long(0, 0, true)
  }

  clone () {
    const target = new Digest()
    target.nx = this.nx
    target.len = new Long(this.len.low, this.len.high, true)
    target.h = new Uint32Array(8)
    copy(target.h, 0, this.h)
    target.x = new Uint8Array(SM3_CHUNK)
    copy(target.x, 0, this.x)
  }

  size () {
    return SM3_SIZE
  }

  blockSize () {
    return SM3_BLOCKSIZE
  }

  reset () {
    for (let i = 0; i < 8; i++) {
      this.h[i] = SM3_IV32[i]
    }
    this.x.fill(0)
    this.nx = 0
    this.len = new Long(0, 0, true)
  }

  block (input) {
    const h = new Uint32Array(8)
    const a = new Uint32Array(8)
    const w = new Uint32Array(68)
    const w1 = new Uint32Array(64)
    for (let i = 0; i < 8; i++) {
      h[i] = this.h[i]
    }
    while (input.length >= SM3_CHUNK) {
      for (let i = 0; i < 16; i++) {
        const j = 4 * i
        w[i] = uint32(input[j] << 24 | input[j + 1] << 16 | input[j + 2] << 8 | input[j + 3])
      }
      for (let i = 16; i < 68; i++) {
        w[i] = _p1(w[i - 16] ^ w[i - 9] ^ rotateLeft32(w[i - 3], 15)) ^ rotateLeft32(w[i - 13], 7) ^ w[i - 6]
      }

      for (let i = 0; i < 64; i++) {
        w1[i] = w[i] ^ w[i + 4]
      }
      for (let i = 0; i < 8; i++) {
        a[i] = h[i]
      }
      for (let i = 0; i < 64; i++) {
        const ss1 = rotateLeft32(rotateLeft32(a[0], 12) + a[4] + rotateLeft32(_t(i), i), 7)
        const ss2 = ss1 ^ rotateLeft32(a[0], 12)
        const tt1 = _ff(i, a[0], a[1], a[2]) + a[3] + ss2 + w1[i]
        const tt2 = _gg(i, a[4], a[5], a[6]) + a[7] + ss1 + w[i]
        a[3] = a[2]
        a[2] = rotateLeft32(a[1], 9)
        a[1] = a[0]
        a[0] = tt1
        a[7] = a[6]
        a[6] = rotateLeft32(a[5], 19)
        a[5] = a[4]
        a[4] = _p0(tt2)
      }
      for (let i = 0; i < 8; i++) {
        h[i] ^= a[i]
      }
      input = input.subarray(SM3_CHUNK)
    }
    for (let i = 0; i < 8; i++) {
      this.h[i] = h[i]
    }
  }

  write (input) {
    input = normalizeInput(input)
    this.len = this.len.add(input.length)
    if (this.nx > 0) {
      const n = copy(this.x, this.nx, input)
      this.nx += n
      if (this.nx === SM3_CHUNK) {
        this.block(this.x)
        this.nx = 0
      }
      input = input.subarray(n)
    }
    if (input.length >= SM3_CHUNK) {
      const n = input.length & ~(SM3_CHUNK - 1)
      this.block(input.subarray(0, n))
      input = input.subarray(n)
    }
    if (input.length > 0) {
      this.nx = copy(this.x, 0, input)
    }
  }

  update (input) {
    this.write(input)
  }

  checkSum () {
    let len = new Long(this.len.low, this.len.high, true)
    const tmp = new Uint8Array(64)
    tmp[0] = 0x80
    const m = this.len.mod(64).getLowBits()
    if (m < 56) {
      this.write(tmp.subarray(0, 56 - m))
    } else {
      this.write(tmp.subarray(0, 64 + 56 - m))
    }
    len = len.shl(3)
    tmp.set(len.toBytesBE())
    this.write(tmp.subarray(0, 8))
    if (this.nx !== 0) {
      throw new Error('d.nx != 0')
    }

    const digest = new Uint8Array(SM3_SIZE)
    for (let i = 0; i < 8; i++) {
      digest[i * 4] = uint8(this.h[i] >> 24)
      digest[i * 4 + 1] = uint8(this.h[i] >> 16)
      digest[i * 4 + 2] = uint8(this.h[i] >> 8)
      digest[i * 4 + 3] = uint8(this.h[i])
    }
    return digest
  }

  sum (input) {
    const clone = this.clone()
    const hash = clone.checkSum()
    if (!input) {
      return hash
    }
    input = normalizeInput(input)
    const output = new Uint8Array(input.length + hash.length)
    output.set(input)
    output.set(hash, input.length)
    return output
  }

  finalize () {
    return this.checkSum()
  }
}

function sm3New () {
  const d = new Digest()
  d.reset()
  return d
}

function sm3Sum (data) {
  const d = new Digest()
  d.reset()
  d.write(data)
  return d.checkSum()
}

function sm3SumHex (data) {
  return toHex(sm3Sum(data))
}

module.exports = {
  create: sm3New,
  sum: sm3Sum,
  fromHex: fromHex,
  toHex: toHex,
  sumHex: sm3SumHex,
  testSpeed: testSpeed
}
