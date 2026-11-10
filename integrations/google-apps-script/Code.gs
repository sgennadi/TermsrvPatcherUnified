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

function doGet() {
  return output_({ok: true, service: 'TermsrvPatcherUnified diagnostics', method: 'POST'});
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
    const report = validReport_(input);
    if (!report) return output_({ok: false, error: 'invalid_evidence'});

    const properties = PropertiesService.getScriptProperties();
    const token = properties.getProperty('GITHUB_ISSUES_TOKEN');
    if (!token) return output_({ok: false, error: 'not_configured'});

    // Lock prevents parallel submissions from bypassing our global cap.
    const lock = LockService.getScriptLock();
    if (!lock.tryLock(2500)) return output_({ok: false, error: 'busy'});
    try {
      const cache = CacheService.getScriptCache();
      const dedupKey = 'udx_' + report.id;
      const cached = cache.get(dedupKey);
      if (cached) return output_({ok: true, issue_url: cached, duplicate: true});

      const day = Utilities.formatDate(new Date(), 'Etc/UTC', 'yyyyMMdd');
      const countKey = 'issues_' + day;
      const count = Number(properties.getProperty(countKey) || '0');
      if (count >= ISSUE_LIMIT_PER_UTC_DAY)
        return output_({ok: false, error: 'daily_limit'});

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
