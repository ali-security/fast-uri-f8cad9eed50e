'use strict'

// Adapted from upstream fastify/fast-uri test/scheme-validation.test.js for a
// tree without scheme validation. Upstream rejects percent-encoded schemes
// with "URI scheme is malformed."; this version has no scheme validation, so
// these tests assert what holds here instead: a percent-encoded scheme is
// never decoded, never selects a scheme handler, and can not be normalized or
// resolved into a live javascript:, data: or vbscript: scheme.

const test = require('tape')
const fastURI = require('..')

// RFC 3986 section 3.1 does not allow percent-encoding in a scheme.
const encodedSchemes = [
  '%4Aavascript:alert(1)',
  '%6aavascript:alert(1)',
  'foo%2Bbar:value',
  '%u006Aavascript:1',
  'ht%74ps://example.com/',
  'ma%69lto:user@example.org',
  '%64ata:text/html,x'
]

const LIVE_SCHEME = /^(?:javascript|data|vbscript):/i

// The scheme exactly as written in the input.
function rawScheme (uri) {
  return uri.slice(0, uri.indexOf(':'))
}

// The input with its scheme percent-decoded, i.e. what the vulnerable parser
// turned it into.
function decodedForm (uri) {
  return unescape(rawScheme(uri)) + uri.slice(uri.indexOf(':'))
}

test('parse keeps valid schemes and never decodes an encoded scheme', (t) => {
  // This tree does not lowercase the parsed scheme (upstream does that as
  // part of scheme validation), so the scheme is compared case-insensitively.
  const validSchemes = [
    ['a:value', 'a'],
    ['HTTP://example.com/', 'http'],
    ['a1+.-:value', 'a1+.-'],
    ['foo+bar:value', 'foo+bar']
  ]

  for (const [uri, scheme] of validSchemes) {
    const parsed = fastURI.parse(uri)
    t.equal(parsed.error, undefined, uri)
    t.equal(String(parsed.scheme).toLowerCase(), scheme, uri + ' scheme')
  }

  for (const uri of encodedSchemes) {
    const parsed = fastURI.parse(uri)
    t.equal(parsed.scheme, rawScheme(uri), uri + ' scheme is not decoded')
    t.notEqual(String(parsed.scheme).indexOf('%'), -1, uri + ' scheme keeps its percent escape')
  }
  t.end()
})

test('percent-encoded schemes do not select scheme handlers', (t) => {
  t.equal(
    fastURI.normalize('ht%74ps://example.com:443'),
    'ht%74ps://example.com:443',
    'HTTP normalization does not run for an encoded scheme'
  )

  // 3.x has no mailto scheme handler (added in v4); use the ws handler to
  // verify that a percent-encoded scheme does not select its scheme handler
  const ws = fastURI.parse('w%73://example.com/a?b')
  t.equal(ws.resourceName, undefined, 'ws parsing does not run for an encoded scheme')
  t.equal(ws.scheme, 'w%73', 'the encoded ws scheme is kept as-is')
  t.equal(
    fastURI.parse(fastURI.normalize('w%73://example.com/a?b')).resourceName,
    undefined,
    'normalization does not turn an encoded scheme into ws'
  )
  t.end()
})

test('normalization cannot synthesize a scheme from encoded input', (t) => {
  const inputs = [
    '%6Aavascript:alert(1)',
    '%4A%41%56%41%53%43%52%49%50%54:alert(1)',
    '%u006Aavascript:alert(1)',
    'j%61vascript:alert(1)',
    '%64ata:text/html,<script>alert(1)</script>',
    'vb%73cript:msgbox(1)'
  ]

  for (const uri of inputs) {
    const parsed = fastURI.parse(uri)
    t.notOk(LIVE_SCHEME.test(String(parsed.scheme) + ':'), uri + ' parsed scheme is not decoded')
    const normalized = fastURI.normalize(uri)
    t.notOk(LIVE_SCHEME.test(normalized), uri + ' does not normalize to a live scheme')
    t.equal(normalized.indexOf(rawScheme(uri) + ':'), 0, uri + ' keeps its encoded scheme when normalized')
    t.notOk(LIVE_SCHEME.test(fastURI.resolve('https://example.com/app/', uri)), uri + ' does not resolve to a live scheme')
  }

  t.equal(fastURI.equal('%68ttp://a/', 'http://a/'), false, 'encoded scheme does not alias a plain scheme')
  t.end()
})

test('normalize preserves percent-encoded schemes', (t) => {
  for (const uri of encodedSchemes) {
    const normalized = fastURI.normalize(uri)
    t.equal(normalized.indexOf(rawScheme(uri) + ':'), 0, uri)
    t.equal(fastURI.parse(normalized).scheme, rawScheme(uri), uri + ' reparses to the encoded scheme')
  }
  t.end()
})

test('equal does not match an encoded scheme to its decoded form', (t) => {
  for (const uri of encodedSchemes) {
    t.equal(fastURI.equal(uri, decodedForm(uri), {}), false, uri)
  }
  t.end()
})

test('resolve keeps an encoded scheme in either input', (t) => {
  t.equal(
    fastURI.resolve('%6Aavascript:/base/', 'child'),
    '%6Aavascript:/base/child',
    'encoded base scheme'
  )
  t.equal(
    fastURI.resolve('https://allowed.example/app/', '%6Aavascript:alert(1)'),
    '%6Aavascript:alert(1)',
    'encoded relative reference scheme'
  )
  t.end()
})

test('serialize and component normalization do not decode component schemes', (t) => {
  t.equal(
    fastURI.serialize({ scheme: 'foo+bar', path: 'value' }),
    'foo+bar:value',
    'valid scheme is serialized'
  )
  t.equal(
    fastURI.serialize({ scheme: 'foo%2Bbar', path: 'value' }),
    'foo%2Bbar:value',
    'percent-encoded scheme is serialized without decoding'
  )
  t.notOk(
    LIVE_SCHEME.test(fastURI.serialize({ scheme: '%6Aavascript', path: 'alert(1)' })),
    'encoded scheme does not serialize as javascript:'
  )
  t.equal(
    fastURI.normalize({ scheme: '%6Aavascript', path: 'alert(1)' }).scheme,
    '%6Aavascript',
    'normalizing a component does not decode its scheme'
  )
  t.equal(
    fastURI.resolveComponent(
      { scheme: 'https', host: 'allowed.example', path: '/app/' },
      { scheme: '%6Aavascript', path: 'alert(1)' }
    ).scheme,
    '%6Aavascript',
    'resolveComponent does not decode the reference scheme'
  )
  t.end()
})
