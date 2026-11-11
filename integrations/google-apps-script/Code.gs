/**
 * TermsrvPatcherUnified — free Google Apps Script -> GitHub Issues bridge.
 *
 * RUN AS: deployer's Google account. ACCESS: Anyone (anonymous).
 * GITHUB_ISSUES_TOKEN exists ONLY in Apps Script > Project settings >
 * Script properties. Never embed it in EXE, source, public URLs or responses.
 *
 * The public endpoint is intentionally bounded but cannot guarantee that
 * anonymous callers are genuine application users. Keep rate limits low.
 * GitHub Issues in this repository are PUBLIC.
 */
const REPORT_REPOSITORY = 'sgennadi/TermsrvPatcherUnified';
const ISSUE_API = 'https://api.github.com/repos/' + REPORT_REPOSITORY + '/issues';
const ISSUE_LIMIT_PER_UTC_DAY = 15;
const MAX_REPORT_LENGTH = 8192;
const REQUIRED_FIELDS = Object.freeze([
  'schema', 'id', 'timestamp_utc', 'project', 'component', 'error_type',
  'code', 'level', 'version', 'platform', 'architecture', 'fingerprint',
  'windows_release', 'windows_build', 'windows_ubr', 'dll_version', 'dll_sha256'
]);
const ISSUE_NAMES = Object.freeze([
  'Schema', 'Project', 'Component', 'Version', 'Severity', 'Error class',
  'Error code', 'Observed UTC', 'OS', 'Architecture', 'Fingerprint',
  'Windows release', 'Windows build', 'Windows UBR', 'DLL version', 'DLL SHA-256'
]);

function output_(result) {
  return ContentService.createTextOutput(JSON.stringify(result))
    .setMimeType(ContentService.MimeType.JSON);
}

// Public, read-only deployment capability check. No token, credentials,
// issue data or GitHub write is exposed. Older deployments lack capabilities;
// owners can use this to verify that the updated code is ACTUALLY deployed.
function doGet() {
  return output_({
    ok: true,
    service: 'TermsrvPatcherUnified diagnostics',
    method: 'POST',
    gateway_schema_version: 2,
    capabilities: ['universal-diagnostics/v1', 'termsrv-compatibility/v1']
  });
}

function sha256_(text) {
  const bytes = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256, text, Utilities.Charset.UTF_8);
  return bytes.map(b => ('0' + (b & 255).toString(16)).slice(-2)).join('');
}

function validReport_(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return false;
  // Accept either flat typed data or exactly {"event":typedData}.
  if (Object.prototype.hasOwnProperty.call(input, 'event')) {
    if (Object.keys(input).length !== 1) return false;
    input = input.event;
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) return false;
  const keys = Object.keys(input);
  if (keys.length !== REQUIRED_FIELDS.length ||
      keys.some(k => !REQUIRED_FIELDS.includes(k))) return false;

  const r = input;
  if (r.schema !== 'universal-diagnostics/v1' ||
      r.project !== REPORT_REPOSITORY || r.platform !== 'Windows' ||
      r.architecture !== 'AMD64' ||
      typeof r.id !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(r.id) ||
      typeof r.component !== 'string' ||
      !/^[A-Za-z][A-Za-z0-9 _-]{0,55}$/.test(r.component) ||
      typeof r.error_type !== 'string' ||
      !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(r.error_type) ||
      typeof r.code !== 'string' ||
      !/^(?:0x[A-Fa-f0-9]{1,8}|[A-Za-z0-9_-]{1,32})$/.test(r.code) ||
      !['info', 'warning', 'error'].includes(r.level) ||
      typeof r.version !== 'string' ||
      !/^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$/.test(r.version) ||
      typeof r.timestamp_utc !== 'string' ||
      !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(r.timestamp_utc) ||
      typeof r.windows_release !== 'string' ||
      !/^[A-Za-z0-9._-]{1,20}$/.test(r.windows_release) ||
      !Number.isInteger(r.windows_build) ||
      r.windows_build < 19041 || r.windows_build > 99999 ||
      !Number.isInteger(r.windows_ubr) ||
      r.windows_ubr < 0 || r.windows_ubr > 999999 ||
      typeof r.dll_version !== 'string' ||
      !/^[0-9]{1,5}(?:\.[0-9]{1,8}){1,4}$/.test(r.dll_version) ||
      typeof r.dll_sha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(r.dll_sha256) ||
      typeof r.fingerprint !== 'string' ||
      !/^[a-f0-9]{64}$/.test(r.fingerprint)) return false;

  const seen = Date.parse(r.timestamp_utc);
  const now = Date.now();
  if (!Number.isFinite(seen) ||
      seen > now + 5 * 60 * 1000 ||
      seen < now - 90 * 24 * 3600 * 1000 ||
      new Date(seen).toISOString().replace('.000Z', 'Z') !== r.timestamp_utc) return false;

  const expectedFingerprint = sha256_(
    [r.project, r.component, r.error_type, r.code]
      .map(v => v.toLowerCase()).join('|'));
  return r.fingerprint === expectedFingerprint ? r : false;
}

function issueBody_(r) {
  const values = [
    r.schema, r.project, r.component, r.version, r.level, r.error_type,
    r.code, r.timestamp_utc, r.platform, r.architecture, r.fingerprint,
    r.windows_release, String(r.windows_build), String(r.windows_ubr),
    r.dll_version, r.dll_sha256
  ];
  return '<!-- udx-report-id:' + r.id + ' -->\n' +
    '<!-- udx-compatibility-observation:v1 -->\n' +
    '## Anonymous UniversalDiagnostics\n\n' +
    ISSUE_NAMES.map((name, i) => '- ' + name + ': ' + values[i]).join('\n') +
    '\n\nOnly reviewed typed metadata. No descriptions, logs, secrets, hostnames or account identifiers.\n';
}


const COMPATIBILITY_COMMENT_API = ISSUE_API + '/1/comments';
const COMPATIBILITY_ISSUE_URL = 'https://github.com/' + REPORT_REPOSITORY + '/issues/1';
const COMPATIBILITY_LIMIT_PER_UTC_DAY = 30;
const COMPATIBILITY_FIELDS = Object.freeze([
  'schema', 'id', 'timestamp_utc', 'project', 'kind', 'body'
]);

// The public gateway is not an authentication service. Parse precisely the
// previously reviewed C# metadata grammar; never forward arbitrary comments,
// Markdown, URLs, paths, filenames, or user text to GitHub.
function parseCompatibilityBody_(body, kind) {
  if (typeof body !== 'string' || body.length > 6144 ||
      /[\r\u0000]/.test(body)) return false;
  const fields = kind === 'successful_apply'
    ? ['windows', 'release', 'build', 'ubr', 'file', 'dll', 'app',
       'mode', 'original_sha256', 'patched_sha256', 'edits']
    : ['architecture', 'file', 'dll', 'app', 'original_sha256',
       'original_crc32', 'patched_sha256', 'patched_crc32', 'edits'];
  const header = kind === 'successful_apply' ? 'termsrv-success/v2' : 'termsrv-offline/v1';
  const lines = body.split('\n');
  if (lines.length !== fields.length + 1 || lines[0] !== header) return false;
  const r = {};
  for (let i = 0; i < fields.length; i++) {
    const prefix = fields[i] + '=';
    if (!lines[i + 1].startsWith(prefix)) return false;
    r[fields[i]] = lines[i + 1].slice(prefix.length);
  }
  if (r.file !== 'termsrv.dll' ||
      !/^[0-9]{1,5}(?:\.[0-9]{1,8}){1,4}$/.test(r.dll) && r.dll !== 'Unknown' ||
      !/^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$/.test(r.app) ||
      !/^[0-9a-f]{64}$/.test(r.original_sha256) ||
      !/^[0-9a-f]{64}$/.test(r.patched_sha256) ||
      r.original_sha256 === r.patched_sha256) return false;
  if (kind === 'successful_apply') {
    if (!['Windows 10', 'Windows 11'].includes(r.windows) ||
        !/^[A-Za-z0-9._-]{1,20}$/.test(r.release) ||
        !/^[0-9]{1,5}(?:\.[0-9]{1,8}){1,4}$/.test(r.dll) ||
        !['automatic', 'manual'].includes(r.mode)) return false;
    for (const [key, low, high] of [['build', 19041, 99999], ['ubr', 0, 999999]]) {
      if (!/^[0-9]+$/.test(r[key])) return false;
      const value = Number(r[key]);
      if (!Number.isSafeInteger(value) || value < low || value > high) return false;
    }
  } else {
    if (!['x86', 'x64'].includes(r.architecture) ||
        !/^[0-9A-F]{8}$/.test(r.original_crc32) ||
        !/^[0-9A-F]{8}$/.test(r.patched_crc32)) return false;
  }
  const edits = r.edits.split('|');
  if (edits.length < 1 || edits.length > 16) return false;
  let lastEnd = 0;
  for (const edit of edits) {
    const match = /^0x([0-9A-F]{8}):((?:[0-9A-F]{2}){1,64})>((?:[0-9A-F]{2}){1,64})$/.exec(edit);
    if (!match) return false;
    const offset = parseInt(match[1], 16);
    const before = match[2], after = match[3];
    if (offset < lastEnd || before.length !== after.length || before === after)
      return false;
    lastEnd = offset + before.length / 2;
  }
  return r;
}

function validCompatibility_(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).length !== 1 ||
      !Object.prototype.hasOwnProperty.call(input, 'event')) return false;
  const r = input.event;
  if (!r || typeof r !== 'object' || Array.isArray(r) ||
      Object.keys(r).length !== COMPATIBILITY_FIELDS.length ||
      Object.keys(r).some(k => !COMPATIBILITY_FIELDS.includes(k)) ||
      r.schema !== 'termsrv-compatibility/v1' ||
      r.project !== REPORT_REPOSITORY ||
      !['successful_apply', 'offline_file'].includes(r.kind) ||
      typeof r.id !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(r.id) ||
      typeof r.timestamp_utc !== 'string' ||
      !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(r.timestamp_utc))
    return false;
  const seen = Date.parse(r.timestamp_utc), now = Date.now();
  if (!Number.isFinite(seen) ||
      seen > now + 5 * 60 * 1000 ||
      seen < now - 90 * 24 * 3600 * 1000 ||
      new Date(seen).toISOString().replace('.000Z', 'Z') !== r.timestamp_utc ||
      !parseCompatibilityBody_(r.body, r.kind))
    return false;
  return r;
}

function publishCompatibility_(report, token) {
  const response = UrlFetchApp.fetch(COMPATIBILITY_COMMENT_API, {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify({body: report.body}),
    followRedirects: false,
    muteHttpExceptions: true,
    headers: {
      Authorization: 'Bearer ' + token,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'TermsrvPatcherUnified-ReportGateway'
    }
  });
  if (response.getResponseCode() !== 201)
    return {ok: false, error: 'github_not_confirmed'};
  let result;
  try { result = JSON.parse(response.getContentText()); }
  catch (_) { return {ok: false, error: 'github_receipt_invalid'}; }
  const url = String(result.html_url || '');
  if (!/^https:\/\/github\.com\/sgennadi\/TermsrvPatcherUnified\/issues\/1#issuecomment-[1-9][0-9]*$/.test(url))
    return {ok: false, error: 'github_receipt_invalid'};
  return {ok: true, issue_url: COMPATIBILITY_ISSUE_URL, comment_url: url};
}

function doPost(event) {
  try {
    if (!event || !event.postData ||
        typeof event.postData.contents !== 'string' ||
        event.postData.contents.length > MAX_REPORT_LENGTH) {
      return output_({ok: false, error: 'invalid_request'});
    }
    let input;
    try { input = JSON.parse(event.postData.contents); }
    catch (_) { return output_({ok: false, error: 'invalid_json'}); }
    const compatibility = validCompatibility_(input);
    const report = compatibility ? null : validReport_(input);
    if (!compatibility && !report) return output_({ok: false, error: 'invalid_evidence'});

    const properties = PropertiesService.getScriptProperties();
    const token = properties.getProperty('GITHUB_ISSUES_TOKEN');
    if (!token) return output_({ok: false, error: 'not_configured'});

    // Lock prevents parallel submissions from bypassing our global cap.
    const lock = LockService.getScriptLock();
    if (!lock.tryLock(2500)) return output_({ok: false, error: 'busy'});
    try {
      const cache = CacheService.getScriptCache();
      const dedupKey = (compatibility ? 'cpx_' : 'udx_') +
        (compatibility ? compatibility.id : report.id);
      const cached = cache.get(dedupKey);
      if (cached) {
        if (compatibility)
          return output_({ok: true, issue_url: COMPATIBILITY_ISSUE_URL,
            comment_url: cached, duplicate: true});
        return output_({ok: true, issue_url: cached, duplicate: true});
      }

      const day = Utilities.formatDate(new Date(), 'Etc/UTC', 'yyyyMMdd');
      const countKey = (compatibility ? 'comments_' : 'issues_') + day;
      const count = Number(properties.getProperty(countKey) || '0');
      const dayLimit = compatibility ? COMPATIBILITY_LIMIT_PER_UTC_DAY : ISSUE_LIMIT_PER_UTC_DAY;
      if (count >= dayLimit)
        return output_({ok: false, error: 'daily_limit'});

      if (compatibility) {
        const receipt = publishCompatibility_(compatibility, token);
        if (!receipt.ok) return output_(receipt);
        properties.setProperty(countKey, String(count + 1));
        cache.put(dedupKey, receipt.comment_url, 21600);
        return output_(receipt);
      }

      const payload = JSON.stringify({
        title: '[Diagnostics] TermsrvPatcherUnified ' + report.id.slice(0, 8),
        body: issueBody_(report)
      });
      const response = UrlFetchApp.fetch(ISSUE_API, {
        method: 'post',
        contentType: 'application/json',
        payload: payload,
        followRedirects: false,
        muteHttpExceptions: true,
        headers: {
          Authorization: 'Bearer ' + token,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
          'User-Agent': 'TermsrvPatcherUnified-ReportGateway'
        }
      });
      if (response.getResponseCode() !== 201)
        return output_({ok: false, error: 'github_not_confirmed'});

      const result = JSON.parse(response.getContentText());
      const url = String(result.html_url || '');
      if (!/^https:\/\/github\.com\/sgennadi\/TermsrvPatcherUnified\/issues\/[1-9][0-9]*$/.test(url))
        return output_({ok: false, error: 'github_receipt_invalid'});

      properties.setProperty(countKey, String(count + 1));
      cache.put(dedupKey, url, 21600);
      return output_({ok: true, issue_url: url});
    } finally {
      lock.releaseLock();
    }
  } catch (_) {
    // No token, stack, raw payload or GitHub error body in public responses.
    return output_({ok: false, error: 'temporarily_unavailable'});
  }
}
