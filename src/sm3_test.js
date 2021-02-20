const test = require('tape')
const { toHex } = require('./sm3')
const sm3 = require('./sm3')

test('SM3 basic', function (t) {
  t.equal(sm3.sumHex('abc'),
    '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')

  t.equal(sm3.sumHex(sm3.fromHex('616263')),
    '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')

  t.equal(sm3.sumHex('abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd'),
    'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')

  t.equal(sm3.sumHex('abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd'),
    '6888fa292df4b51341e82e3072fbdd63598439c64eda318a81756ca71a7a6c15')

  t.end()
})

test('Input types', function (t) {
  // Supports string, Uint8Array, and Buffer inputs
  // We already verify that sm3.sum('abc') produces the correct hash above
  t.equal(sm3.sumHex(new Uint8Array([97, 98, 99])), sm3.sumHex('abc'))
  t.equal(sm3.sumHex(Buffer.from([97, 98, 99])), sm3.sumHex('abc'))
  t.end()
})

test('SM3 performance', function (t) {
  const N = 1 << 22 // number of bytes to hash
  const RUNS = 3 // how often to repeat, to allow JIT to finish

  console.log('Benchmarking sm3.sum(' + (N >> 20) + ' MB input)')
  sm3.testSpeed(sm3.sumHex, N, RUNS)
  t.end()
})

test('KDF', function (t) {
  const dataHex = '64D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE58D225ECA784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78'
  const expected = '006e30dae231b071dfad8aa379e90264491603'
  const result = sm3.kdf(sm3.fromHex(dataHex), 19)
  t.equal(toHex(result), expected)
  t.end()
})
