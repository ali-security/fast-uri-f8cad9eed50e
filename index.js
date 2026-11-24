'use strict'

const { normalizeIPv6, removeDotSegments, removeDotSegmentsRelative, recomposeAuthority, normalizePercentEncoding, normalizePathEncoding, escapePreservingEscapes, reescapeHostDelimiters, isIPv4, nonSimpleDomain } = require('./lib/utils')
const { SCHEMES, getSchemeHandler } = require('./lib/schemes')

const MALFORMED_HOST_ERROR = 'URI host is malformed.'
// ASCII characters outside the RFC 3986 reg-name set (unreserved, sub-delims
// and "%" for pct-encoded): C0 controls, space, DEL, and "#/:<>?@[\]^`{|}.
const FORBIDDEN_DOMAIN_HOST_CHARACTER = /[\0-\x20"#/:<>?@[\\\]^`{|}\x7F]/u

/**
 * @template {import('./types/index').URIComponent|string} T
 * @param {T} uri
 * @param {import('./types/index').Options} [options]
 * @returns {T}
 */
function normalize (uri, options) {
  if (typeof uri === 'string') {
    uri = /** @type {T} */ (normalizeString(uri, options))
  } else if (typeof uri === 'object') {
    uri = /** @type {T} */ (parse(serialize(uri, options), options))
  }
  return uri
}

/**
 * @param {string} baseURI
 * @param {string} relativeURI
 * @param {import('./types/index').Options} [options]
 * @returns {string}
 */
function resolve (baseURI, relativeURI, options) {
  const schemelessOptions = options ? Object.assign({ scheme: 'null' }, options) : { scheme: 'null' }
  const { parsed: baseParsed, malformedAuthorityOrPort: baseMalformed, malformedHost: baseMalformedHost } = parseWithStatus(baseURI, schemelessOptions)
  const { parsed: relativeParsed, malformedAuthorityOrPort: relativeMalformed, malformedHost: relativeMalformedHost } = parseWithStatus(relativeURI, schemelessOptions)
  if (baseMalformed || relativeMalformed || baseMalformedHost || relativeMalformedHost) {
    throw new Error(baseParsed.error || relativeParsed.error || 'URI is malformed.')
  }
  const resolved = resolveComponent(baseParsed, relativeParsed, schemelessOptions, true)
  // Canonicalize the resolved host against the *final* scheme. A scheme-relative
  // reference ("//host/…") resolved against a scheme-bearing base would otherwise
  // return a host that reparses as a different authority (host-allowlist bypass).
  const resolvedSchemeHandler = getSchemeHandler((options && options.scheme) || resolved.scheme)
  const resolvedHost = resolved.host
  const resolvedHostIsIP = resolvedHost !== undefined && resolvedHost !== '' &&
    (isIPv4(resolvedHost) || normalizeIPv6(resolvedHost).isIPV6)
  // Inputs are parsed scheme-neutrally, so delimiters and controls in a domain
  // host are only detected here, once the final scheme is known. They always
  // fail closed, including in percent-encoded hosts.
  if (hasForbiddenDomainHost(resolved, options || {}, resolvedSchemeHandler, resolvedHostIsIP)) {
    throw new Error(MALFORMED_HOST_ERROR)
  }
  canonicalizeHost(resolved, options || {}, resolvedSchemeHandler, resolvedHostIsIP)
  // Percent escapes in an ASCII reg-name are encoded data. The WHATWG hostname
  // parser can reject them even though fast-uri preserves them safely as RFC
  // 3986 data. A raw non-ASCII host must still fail closed if conversion fails.
  const encodedASCIIHost = resolvedHost && resolvedHost.indexOf('%') !== -1 &&
    !/\P{ASCII}/u.test(resolvedHost)
  if (resolved.error && !encodedASCIIHost) {
    throw new Error(resolved.error)
  }
  schemelessOptions.skipEscape = true
  return serialize(resolved, schemelessOptions)
}

/**
 * @param {import ('./types/index').URIComponent} base
 * @param {import ('./types/index').URIComponent} relative
 * @param {import('./types/index').Options} [options]
 * @param {boolean} [skipNormalization=false]
 * @returns {import ('./types/index').URIComponent}
 */
function resolveComponent (base, relative, options, skipNormalization) {
  /** @type {import('./types/index').URIComponent} */
  const target = {}
  if (!skipNormalization) {
    base = parse(serialize(base, options), options) // normalize base component
    relative = parse(serialize(relative, options), options) // normalize relative component
  }
  options = options || {}

  if (!options.tolerant && relative.scheme) {
    target.scheme = relative.scheme
    // target.authority = relative.authority;
    target.userinfo = relative.userinfo
    target.host = relative.host
    target.port = relative.port
    target.path = removeDotSegments(relative.path || '')
    target.query = relative.query
  } else {
    if (relative.userinfo !== undefined || relative.host !== undefined || relative.port !== undefined) {
      // target.authority = relative.authority;
      target.userinfo = relative.userinfo
      target.host = relative.host
      target.port = relative.port
      target.path = removeDotSegments(relative.path || '')
      target.query = relative.query
    } else {
      if (!relative.path) {
        target.path = base.path
        if (relative.query !== undefined) {
          target.query = relative.query
        } else {
          target.query = base.query
        }
      } else {
        if (relative.path[0] === '/') {
          target.path = removeDotSegments(relative.path)
        } else {
          const baseHasAuthority = base.userinfo !== undefined || base.host !== undefined || base.port !== undefined
          if (baseHasAuthority && !base.path) {
            target.path = '/' + relative.path
          } else if (!base.path) {
            target.path = relative.path
          } else {
            target.path = base.path.slice(0, base.path.lastIndexOf('/') + 1) + relative.path
          }
          target.path = !base.scheme && !baseHasAuthority && target.path[0] !== '/'
            ? removeDotSegmentsRelative(target.path)
            : removeDotSegments(target.path)
        }
        target.query = relative.query
      }
      // target.authority = base.authority;
      target.userinfo = base.userinfo
      target.host = base.host
      target.port = base.port
    }
    target.scheme = base.scheme
  }

  target.fragment = relative.fragment

  return target
}

/**
 * @param {import ('./types/index').URIComponent|string} uriA
 * @param {import ('./types/index').URIComponent|string} uriB
 * @param {import ('./types/index').Options} options
 * @returns {boolean}
 */
function equal (uriA, uriB, options) {
  const normalizedA = normalizeComparableURI(uriA, options)
  const normalizedB = normalizeComparableURI(uriB, options)

  return normalizedA !== undefined && normalizedB !== undefined && normalizedA.toLowerCase() === normalizedB.toLowerCase()
}

/**
 * @param {Readonly<import('./types/index').URIComponent>} cmpts
 * @param {import('./types/index').Options} [opts]
 * @returns {string}
 */
function serialize (cmpts, opts) {
  const component = {
    host: cmpts.host,
    scheme: cmpts.scheme,
    userinfo: cmpts.userinfo,
    port: cmpts.port,
    path: cmpts.path,
    query: cmpts.query,
    nid: cmpts.nid,
    nss: cmpts.nss,
    uuid: cmpts.uuid,
    fragment: cmpts.fragment,
    reference: cmpts.reference,
    resourceName: cmpts.resourceName,
    secure: cmpts.secure,
    error: ''
  }
  const options = Object.assign({}, opts)
  const uriTokens = []

  // find scheme handler
  const schemeHandler = getSchemeHandler(options.scheme || component.scheme)

  // perform scheme specific serialization
  if (schemeHandler && schemeHandler.serialize) schemeHandler.serialize(component, options)

  if (component.path !== undefined) {
    if (!options.skipEscape) {
      component.path = escapePreservingEscapes(component.path)

      if (component.scheme !== undefined) {
        component.path = component.path.split('%3A').join(':')
      }
    } else {
      component.path = normalizePercentEncoding(component.path)
    }
  }

  if (options.reference !== 'suffix' && component.scheme) {
    uriTokens.push(component.scheme, ':')
  }

  const authority = recomposeAuthority(component)
  if (authority !== undefined) {
    if (options.reference !== 'suffix') {
      uriTokens.push('//')
    }

    uriTokens.push(authority)

    if (component.path && component.path[0] !== '/') {
      uriTokens.push('/')
    }
  }
  if (component.path !== undefined) {
    let s = component.path

    if (!options.absolutePath && (!schemeHandler || !schemeHandler.absolutePath)) {
      // A relative-path reference keeps its unresolvable leading ".." segments
      // and must never become root-relative (RFC 3986 section 5.2.4 applies to
      // merged target paths, not to the reference itself). A reference with no
      // emitted scheme and no authority is such a relative-path reference.
      s = (!component.scheme || options.reference === 'suffix') && authority === undefined && s[0] !== '/'
        ? removeDotSegmentsRelative(s)
        : removeDotSegments(s)
    }

    if (
      authority === undefined &&
      s[0] === '/' &&
      s[1] === '/'
    ) {
      // don't allow the path to start with "//"
      s = '/%2F' + s.slice(2)
    }

    uriTokens.push(s)
  }

  if (component.query !== undefined) {
    uriTokens.push('?', component.query)
  }

  if (component.fragment !== undefined) {
    uriTokens.push('#', component.fragment)
  }
  return uriTokens.join('')
}

const URI_PARSE = /^(?:([^#/:?]+):)?(?:\/\/((?:([^#/?@]*)@)?(\[[^#/?\]]+\]|[^#/:?]*)(?::(\d*))?))?([^#?]*)(?:\?([^#]*))?(?:#((?:.|[\n\r])*))?/u

// Captures the authority component (between "//" and the next "/", "?" or "#"),
// with or without a scheme prefix, for the literal-backslash rejection below.
const AUTHORITY_PREFIX = /^(?:[^#/:?]+:)?\/\/([^/?#]*)/

// Captures the leading authority-introducer region after an optional scheme: a
// run of forward slashes, backslashes, and the characters the WHATWG URL parser
// removes before parsing (TAB U+0009, LF U+000A, CR U+000D). A valid introducer
// is exactly "//". Node treats "\" as "/" on special schemes and strips those
// characters first, so forms like "\\", "/\", "\/", "/<TAB>/", or a leading
// "<TAB>//" reach an authority in Node while fast-uri's URI_PARSE folds them into
// the path group (host confusion / SSRF / redirect bypass).
const AUTHORITY_INTRODUCER_REGION = /^(?:[^#/:?]+:)?([/\\\t\n\r]*)/

/**
 * @param {import('./types/index').URIComponent} parsed
 * @param {RegExpMatchArray} matches
 * @returns {string|undefined}
 */
function getParseError (parsed, matches) {
  if (matches[2] !== undefined && parsed.path && parsed.path[0] !== '/') {
    return 'URI path must start with "/" when authority is present.'
  }

  if (typeof parsed.port === 'number' && (parsed.port < 0 || parsed.port > 65535)) {
    return 'URI port is malformed.'
  }

  return undefined
}

/**
 * Whether the host is a bracketed IP literal (RFC 3986 `IP-literal`).
 * An unterminated `[` is not a literal, so it must still be validated as a
 * reg-name instead of being waved through as an IP.
 *
 * @param {string} host
 * @returns {boolean}
 */
function isIPLiteral (host) {
  return host[0] === '[' && host[host.length - 1] === ']'
}

/**
 * Convert a Unicode IDN host to its ASCII form when the effective scheme uses
 * domain hosts and cannot handle IRIs. Sets parsed.error on failure.
 *
 * @param {import('./types/index').URIComponent} parsed
 * @param {import('./types/index').Options} options
 * @param {{ domainHost?: boolean, unicodeSupport?: boolean }|undefined} schemeHandler
 * @param {boolean} isIP
 * @returns {boolean} whether host conversion failed
 */
function canonicalizeHost (parsed, options, schemeHandler, isIP) {
  if (hasForbiddenDomainHost(parsed, options, schemeHandler, isIP)) {
    parsed.error = parsed.error || MALFORMED_HOST_ERROR
    return true
  }

  if (
    !options.unicodeSupport &&
    (!schemeHandler || !schemeHandler.unicodeSupport) &&
    parsed.host &&
    // A complete bracketed IP literal is never a domain name. Handing it to the
    // WHATWG parser would let a malformed literal be silently rewritten into a
    // different host (e.g. "[1:2:3:4:5:6:7::8]" -> "[1:2:3:4:5:6:7:8]"), which
    // is exactly what normalizeIPv6 now refuses to do. An *unterminated*
    // bracket is not a literal, so it must still fail the domain conversion.
    !(parsed.host[0] === '[' && parsed.host[parsed.host.length - 1] === ']') &&
    (options.domainHost || (schemeHandler && schemeHandler.domainHost)) &&
    isIP === false &&
    nonSimpleDomain(parsed.host)
  ) {
    let url
    try {
      url = new URL('http://' + parsed.host)
    } catch (e) {
      parsed.error = parsed.error || "Host's domain name can not be converted to ASCII: " + e
      return true
    }
    // The WHATWG parser must have read the whole input as a host. Anything
    // else means it found a delimiter fast-uri did not, so its hostname would
    // describe a different authority.
    if (!isHostOnlyURL(url)) {
      parsed.error = parsed.error || MALFORMED_HOST_ERROR
      return true
    }
    parsed.host = url.hostname
  }
  return false
}

/**
 * Whether a domain host contains an ASCII character that RFC 3986 does not
 * allow in a reg-name (unreserved, sub-delims, or pct-encoded). Such a host is
 * rejected instead of being handed to the WHATWG URL parser, which would treat
 * "@" as a userinfo delimiter (silently dropping the data before it) and strip
 * TAB, LF, and CR. Non-ASCII characters remain allowed for IDNs.
 *
 * @param {import('./types/index').URIComponent} parsed
 * @param {import('./types/index').Options} options
 * @param {{ domainHost?: boolean }|undefined} schemeHandler
 * @param {boolean} isIP
 * @returns {boolean}
 */
function hasForbiddenDomainHost (parsed, options, schemeHandler, isIP) {
  return Boolean(
    parsed.host &&
    isIP === false &&
    !isIPLiteral(parsed.host) &&
    (options.domainHost || (schemeHandler && schemeHandler.domainHost)) &&
    FORBIDDEN_DOMAIN_HOST_CHARACTER.test(parsed.host)
  )
}

/**
 * @param {URL} url
 * @returns {boolean}
 */
function isHostOnlyURL (url) {
  return url.username === '' &&
    url.password === '' &&
    url.port === '' &&
    url.pathname === '/' &&
    url.search === '' &&
    url.hash === '' &&
    url.hostname !== ''
}

/**
 * @param {string} uri
 * @param {import('./types/index').Options} [opts]
 * @returns {{ parsed: import('./types/index').URIComponent, malformedAuthorityOrPort: boolean }}
 */
function parseWithStatus (uri, opts) {
  const options = Object.assign({}, opts)
  /** @type {import('./types/index').URIComponent} */
  const parsed = {
    scheme: undefined,
    userinfo: undefined,
    host: '',
    port: undefined,
    path: '',
    query: undefined,
    fragment: undefined
  }

  let malformedAuthorityOrPort = false
  let malformedHost = false
  let malformedIPLiteral = false

  let isIP = false
  if (options.reference === 'suffix') {
    if (options.scheme) {
      uri = options.scheme + ':' + uri
    } else {
      uri = '//' + uri
    }
  }

  // A literal backslash (U+005C) is not a valid RFC 3986 URI character and is
  // not an authority delimiter. Reject it in the authority rather than
  // rewriting it: normalizing "\" -> "/" (WHATWG error recovery) could silently
  // change the resource identified by an otherwise-invalid input, and lets "\"
  // act as a host delimiter here while Node's native URL parses a different
  // host (SSRF / redirect / origin-allowlist bypass). Percent-encoded %5C is
  // untouched and remains valid encoded data.
  const authorityMatch = uri.match(AUTHORITY_PREFIX)
  if (authorityMatch !== null && authorityMatch[1].indexOf('\\') !== -1) {
    parsed.error = 'URI authority must not contain a literal backslash.'
    malformedAuthorityOrPort = true
  }

  // Reject a malformed or whitespace-smuggled authority introducer. fast-uri
  // only recognizes a literal "//"; anything else in the leading separator run
  // (a backslash, or a "//" that appears only after removing the TAB/LF/CR that
  // Node strips) means the authority fast-uri parses differs from the one Node's
  // URL resolves. Reject rather than rewrite, mirroring the literal-backslash
  // guard above. Percent-encoded forms (%5C, %09) are untouched, valid data.
  const introducerMatch = uri.match(AUTHORITY_INTRODUCER_REGION)
  if (introducerMatch !== null) {
    const region = introducerMatch[1]
    const normalizedRegion = region.replace(/[\t\n\r]/g, '')
    // Two or more leading separators introduce an authority.
    if (normalizedRegion.length >= 2) {
      if (normalizedRegion.slice(0, 2) !== '//') {
        parsed.error = parsed.error || 'URI authority must not contain a literal backslash.'
        malformedAuthorityOrPort = true
      } else if (region.length !== normalizedRegion.length) {
        parsed.error = parsed.error || 'URI authority introducer must not contain whitespace.'
        malformedAuthorityOrPort = true
      }
    }
  }

  const matches = uri.match(URI_PARSE)

  if (matches) {
    // store each component
    parsed.scheme = matches[1]
    parsed.userinfo = matches[3]
    parsed.host = matches[4]
    parsed.port = parseInt(matches[5], 10)
    parsed.path = matches[6] || ''
    parsed.query = matches[7]
    parsed.fragment = matches[8]

    // fix port number
    if (isNaN(parsed.port)) {
      parsed.port = matches[5]
    }

    const parseError = getParseError(parsed, matches)
    if (parseError !== undefined) {
      parsed.error = parsed.error || parseError
      malformedAuthorityOrPort = true
    }

    if (parsed.host) {
      const ipv4result = isIPv4(parsed.host)
      if (ipv4result === false) {
        const bracketedIPLiteral = isIPLiteral(parsed.host)
        const hasIPLiteralBracket = parsed.host.indexOf('[') !== -1 || parsed.host.indexOf(']') !== -1
        const ipv6result = normalizeIPv6(parsed.host)
        isIP = ipv6result.isIPV6 || ipv6result.isIPVFuture === true
        malformedIPLiteral = hasIPLiteralBracket && (!bracketedIPLiteral || ipv6result.error === true)
        parsed.host = isIP ? ipv6result.host : ipv6result.host.toLowerCase()

        if (malformedIPLiteral) {
          parsed.error = parsed.error || MALFORMED_HOST_ERROR
          malformedAuthorityOrPort = true
        }
      } else {
        isIP = true
      }
    }
    if (parsed.scheme === undefined && parsed.userinfo === undefined && parsed.host === undefined && parsed.port === undefined && parsed.query === undefined && !parsed.path) {
      parsed.reference = 'same-document'
    } else if (parsed.scheme === undefined) {
      parsed.reference = 'relative'
    } else if (parsed.fragment === undefined) {
      parsed.reference = 'absolute'
    } else {
      parsed.reference = 'uri'
    }

    // check for reference errors
    if (options.reference && options.reference !== 'suffix' && options.reference !== parsed.reference) {
      parsed.error = parsed.error || 'URI is not a ' + options.reference + ' reference.'
    }

    // find scheme handler
    const schemeHandler = getSchemeHandler(options.scheme || parsed.scheme)

    // convert Unicode IDN -> ASCII IDN when the effective scheme uses domain hosts
    if (!malformedIPLiteral) {
      malformedHost = canonicalizeHost(parsed, options, schemeHandler, isIP)
    }

    if (uri.indexOf('%') !== -1 && parsed.host !== undefined && !malformedIPLiteral) {
      // Decode only current unreserved escapes, once. Using unescape() here
      // decodes every escape and lets a nested escape (e.g. %252e -> %2e -> .)
      // reparse as a live delimiter, redirecting to a different host.
      let host = isIP ? parsed.host : normalizePercentEncoding(parsed.host, true)
      if (!isIP) {
        // Fold reg-name case after decoding unreserved octets. The second
        // pass only restores uppercase hex in escapes that remain encoded.
        host = normalizePercentEncoding(host.toLowerCase())
      }
      // Resolution parses both inputs with the internal `null` scheme before
      // the effective scheme is known. Keep raw host delimiters for that step
      // so resolve() can reject them for domain-host schemes; the resolved
      // authority is encoded when it is serialized.
      parsed.host = isIP || options.scheme !== 'null' ? reescapeHostDelimiters(host, isIP) : host
    }

    if (!schemeHandler || (schemeHandler && !schemeHandler.skipNormalize)) {
      // RFC 3986 section 3.1 does not allow percent-encoding in a scheme, so
      // the scheme is never decoded. Decoding would let inert input such as
      // `%6Aavascript:` become a live `javascript:` scheme.
      if (parsed.path) {
        parsed.path = normalizePathEncoding(parsed.path)
      }
      if (parsed.fragment) {
        try {
          parsed.fragment = encodeURI(decodeURIComponent(parsed.fragment))
        } catch {
          parsed.error = parsed.error || 'URI malformed'
        }
      }
    }

    // perform scheme specific parsing
    if (schemeHandler && schemeHandler.parse) {
      schemeHandler.parse(parsed, options)
    }
  } else {
    parsed.error = parsed.error || 'URI can not be parsed.'
  }
  return { parsed, malformedAuthorityOrPort, malformedHost }
}

/**
 * @param {string} uri
 * @param {import('./types/index').Options} [opts]
 * @returns
 */
function parse (uri, opts) {
  return parseWithStatus(uri, opts).parsed
}

/**
 * @param {string} uri
 * @param {import('./types/index').Options} [opts]
 * @returns {string}
 */
function normalizeString (uri, opts) {
  return normalizeStringWithStatus(uri, opts).normalized
}

/**
 * @param {string} uri
 * @param {import('./types/index').Options} [opts]
 * @returns {{ normalized: string, malformedAuthorityOrPort: boolean, malformedHost: boolean }}
 */
function normalizeStringWithStatus (uri, opts) {
  const { parsed, malformedAuthorityOrPort, malformedHost } = parseWithStatus(uri, opts)
  return {
    normalized: malformedAuthorityOrPort || malformedHost ? uri : serialize(parsed, opts),
    malformedAuthorityOrPort,
    malformedHost
  }
}

/**
 * @param {import ('./types/index').URIComponent|string} uri
 * @param {import('./types/index').Options} [opts]
 * @returns {string|undefined}
 */
function normalizeComparableURI (uri, opts) {
  if (typeof uri === 'string') {
    const { normalized, malformedAuthorityOrPort, malformedHost } = normalizeStringWithStatus(uri, opts)
    return malformedAuthorityOrPort || malformedHost ? undefined : normalized
  }

  if (typeof uri === 'object') {
    try {
      return serialize(uri, opts)
    } catch {
      // A component that can not be serialized safely (e.g. a malformed port)
      // can not be compared; fail closed.
      return undefined
    }
  }
}

const fastUri = {
  SCHEMES,
  normalize,
  resolve,
  resolveComponent,
  equal,
  serialize,
  parse
}

module.exports = fastUri
module.exports.default = fastUri
module.exports.fastUri = fastUri
