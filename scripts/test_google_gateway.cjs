#!/usr/bin/env node
// Offline-only tests for the public Apps Script gateway. Never contacts Google/GitHub.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');

const githubPosts = [];
const cache = new Map();
const properties = new Map([
  ['GITHUB_ISSUES_TOKEN', 'FAKE_TEST_ONLY_NEVER_SEND'],
  ['GITHUB_M365_ISSUES_TOKEN', 'FAKE_TEST_ONLY_NEVER_SEND']
]);
const iso = () => new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
const githubResponse = (status, json) => ({
  getResponseCode: () => status,
  getContentText: () => JSON.stringify(json)
});
let commentNumber = 1500;
let issueNumber = 500;
const sandbox = {
  Date, JSON, Object, Array, String, Number, RegExp,
  ContentService: {
    MimeType: {JSON: 'json'},
    createTextOutput: body => ({
      text: body,
      setMimeType() { return this; }
    })
  },
  Utilities: {
    DigestAlgorithm: {SHA_256: 'sha256'},
    Charset: {UTF_8: 'utf-8'},
    computeDigest: (_, value) => [...crypto.createHash('sha256').update(value).digest()],
    formatDate: (date, tz, fmt) => {
      assert.equal(tz, 'Etc/UTC');
      assert.equal(fmt, 'yyyyMMdd');
      return date.toISOString().slice(0, 10).replaceAll('-', '');
    }
  },
  CacheService: {getScriptCache: () => ({
    get: key => cache.get(key) || null,
    put: (key, val) => cache.set(key, val)
  })},
  PropertiesService: {getScriptProperties: () => ({
    getProperty: key => properties.get(key) || null,
    setProperty: (key, val) => properties.set(key, val)
  })},
  LockService: {getScriptLock: () => ({
    tryLock: () => true,
    releaseLock: () => {}
  })},
  UrlFetchApp: {fetch: (url, opts) => {
    assert.equal(opts.method, 'post');
    assert.equal(opts.followRedirects, false);
    assert.match(opts.headers.Authorization, /^Bearer FAKE_TEST_ONLY_NEVER_SEND$/);
    githubPosts.push({url, body: JSON.parse(opts.payload)});
    if (url.endsWith('/issues/1/comments'))
      return githubResponse(201, {
        html_url: 'https://github.com/sgennadi/TermsrvPatcherUnified/issues/1#issuecomment-' + (++commentNumber)
      });
    assert.ok(url.endsWith('/issues'), 'only the approved API may be used');
    const repo = url === 'https://api.github.com/repos/sgennadi/Microsoft365AuthRepair/issues'
      ? 'Microsoft365AuthRepair' : 'TermsrvPatcherUnified';
    assert.equal(url, 'https://api.github.com/repos/sgennadi/' + repo + '/issues');
    return githubResponse(201, {
      html_url: 'https://github.com/sgennadi/' + repo + '/issues/' + (++issueNumber)
    });
  }}
};
vm.createContext(sandbox);
const code = fs.readFileSync('integrations/google-apps-script/Code.gs', 'utf8');
vm.runInContext(code, sandbox, {filename: 'Code.gs', timeout: 5000});
const post = event => JSON.parse(sandbox.doPost({
  postData: {contents: JSON.stringify({event})}
}).text);
const change = (report, fields) => ({...report, ...fields});
const initialBody = [
  'termsrv-success/v2',
  'windows=Windows 11', 'release=26H2', 'build=26300', 'ubr=9711',
  'file=termsrv.dll', 'dll=10.0.26100.9549', 'app=1.0.4',
  'mode=automatic', 'original_sha256=' + 'a'.repeat(64),
  'patched_sha256=' + 'b'.repeat(64), 'edits=0x00000220:11223344>AABBCCDD'
].join('\n');
const offlineBody = [
  'termsrv-offline/v1',
  'architecture=x64', 'file=termsrv.dll', 'dll=10.0.26100.9549',
  'app=1.0.4', 'original_sha256=' + 'a'.repeat(64), 'original_crc32=1234ABCD',
  'patched_sha256=' + 'b'.repeat(64), 'patched_crc32=AABBCCDD',
  'edits=0x00000220:11223344>AABBCCDD'
].join('\n');
const compat = (kind, body) => ({
  schema: 'termsrv-compatibility/v1',
  id: crypto.randomUUID(),
  timestamp_utc: iso(),
  project: 'sgennadi/TermsrvPatcherUnified',
  kind,
  body
});
let checks = 0;
function eq(actual, expected, label) {
  assert.deepEqual(actual, expected, label);
  checks++;
}
function truth(value, label) {
  assert.ok(value, label);
  checks++;
}
const health = JSON.parse(sandbox.doGet().text);
truth(health.ok === true && health.gateway_schema_version === 3 &&
      health.capabilities.includes('universal-diagnostics/v1') &&
      health.capabilities.includes('termsrv-compatibility/v1') &&
      health.capabilities.includes('microsoft365-auth-repair/v1'),
  'read-only GET advertises both supported reporting schemas without GitHub writes');
eq(githubPosts.length, 0, 'GET capability check never creates an Issue or comment');
const report = compat('successful_apply', initialBody);
let receipt = post(report);
truth(receipt.ok && receipt.issue_url.endsWith('/issues/1') &&
      /^https:\/\/github\.com\/sgennadi\/TermsrvPatcherUnified\/issues\/1#issuecomment-[0-9]+$/.test(receipt.comment_url),
  'successful Apply receives verifiable comment receipt');
eq(githubPosts.length, 1, 'only one GitHub write');
eq(githubPosts[0].body.body, initialBody, 'server posts only sanitized structured comment');
receipt = post(report);
truth(receipt.ok && receipt.duplicate === true, 'same event id is idempotent in cache');
eq(githubPosts.length, 1, 'replay performs no second write');
receipt = post(compat('offline_file', offlineBody));
truth(receipt.ok && receipt.comment_url.includes('#issuecomment-'),
  'offline copy posted as separate schema');
eq(githubPosts.length, 2, 'separate event creates one comment');
const badBodies = [
  initialBody + '\naccount=PRIVATE',
  initialBody.replace('a'.repeat(64), 'X'.repeat(64)),
  initialBody.replace('b'.repeat(64), 'a'.repeat(64)),
  initialBody.replace('0x00000220', '0x0000022G'),
  initialBody.replace('11223344>AABBCCDD', '11223344>11223344'),
  initialBody.replace('0x00000220:11223344>AABBCCDD',
                      '0x00000220:11223344>AABBCCDD|0x00000221:1122>FFFF'),
  initialBody.replace('release=26H2', 'release=/private/path'),
  initialBody.replace('build=26300', 'build=999999999')
];
for (const body of badBodies)
  eq(post(compat('successful_apply', body)).error, 'invalid_evidence',
     'unsafe compatibility report rejected');
eq(post(compat('offline_file', initialBody)).error, 'invalid_evidence',
   'cannot relabel system Apply as offline');
eq(post(compat('successful_apply', offlineBody)).error, 'invalid_evidence',
   'cannot relabel offline result as successful Apply');
eq(post(change(compat('successful_apply', initialBody), {extra: 'PRIVATE'})).error,
   'invalid_evidence', 'extra metadata field rejected');
eq(post(change(compat('successful_apply', initialBody), {timestamp_utc:'2000-01-01T00:00:00Z'})).error,
   'invalid_evidence', 'stale timestamps rejected');
eq(githubPosts.length, 2, 'no malicious payload reaches GitHub');
const diagComponent = 'RdpSettings';
const diagType = 'InvalidOperationException';
const diagCode = '0x80131509';
const fingerprint = crypto.createHash('sha256').update(
  ['sgennadi/TermsrvPatcherUnified', diagComponent, diagType, diagCode]
    .map(x => x.toLowerCase()).join('|')).digest('hex');
const diagnostic = {
  schema: 'universal-diagnostics/v1',
  id: crypto.randomUUID(), timestamp_utc: iso(),
  project: 'sgennadi/TermsrvPatcherUnified',
  component: diagComponent, error_type: diagType, code: diagCode, level: 'error',
  version: '1.0.4', platform: 'Windows', architecture: 'AMD64', fingerprint,
  windows_release: '26H2', windows_build: 26300, windows_ubr: 9711,
  dll_version: '10.0.26100.9549', dll_sha256: 'a'.repeat(64)
};
receipt = post(diagnostic);
truth(receipt.ok && receipt.issue_url.endsWith('/issues/501') && !receipt.comment_url,
  'legacy anonymous diagnostics still creates its own Issue');
eq(githubPosts.length, 3, 'legacy issue path unchanged');

const m365Component = 'EntraWAMBroker';
const m365Type = 'USER_REPORT';
const m365Code = 'WAM_REVIEW';
const m365Fingerprint = crypto.createHash('sha256')
  .update(['sgennadi/Microsoft365AuthRepair', m365Component, m365Type, m365Code]
    .map(x => x.toLowerCase()).join('|')).digest('hex');
const m365Report = {
  schema: 'universal-diagnostics/v1', id: crypto.randomUUID(),
  timestamp_utc: iso(), project: 'sgennadi/Microsoft365AuthRepair',
  component: m365Component, error_type: m365Type, code: m365Code,
  level: 'info', version: '1.0.1-preview.1', platform: 'Windows',
  architecture: 'ARM64', fingerprint: m365Fingerprint
};
let countBefore = githubPosts.length;
receipt = post(m365Report);
truth(receipt.ok && /^https:\/\/github\.com\/sgennadi\/Microsoft365AuthRepair\/issues\/[0-9]+$/.test(receipt.issue_url),
  'strict universal M365 report routes to its own GitHub repository');
eq(githubPosts.length, countBefore + 1, 'M365 report creates exactly one Issue');
truth(githubPosts.at(-1).url === 'https://api.github.com/repos/sgennadi/Microsoft365AuthRepair/issues' &&
  !githubPosts.at(-1).body.body.includes('private'),
  'M365 route has its own GitHub API target, no free-form metadata');
receipt = post(m365Report);
truth(receipt.ok && receipt.duplicate === true, 'M365 duplicate report gets cached receipt');
eq(githubPosts.length, countBefore + 1, 'no duplicate GitHub Issues');
for (const invalid of [
  change(m365Report, {summary: 'MY PRIVATE ACCOUNT'}),
  change(m365Report, {project: 'sgennadi/TermsrvPatcherUnified'}),
  change(m365Report, {fingerprint: 'b'.repeat(64)}),
  change(m365Report, {component: 'Entra WAM / BAD PATH'}),
  change(m365Report, {architecture: 'Other'}),
  change(m365Report, {timestamp_utc: '2000-01-01T00:00:00Z'})
]) eq(post(invalid).error, 'invalid_evidence', 'unsafe M365 field rejected');
eq(githubPosts.length, countBefore + 1, 'unsafe M365 attempts create no issues');
properties.delete('GITHUB_M365_ISSUES_TOKEN');
eq(post(change(m365Report, {id: crypto.randomUUID()})).error,
  'not_configured', 'M365 token must be separately configured on server');
properties.set('GITHUB_M365_ISSUES_TOKEN', 'FAKE_TEST_ONLY_NEVER_SEND');

properties.delete('GITHUB_ISSUES_TOKEN');
eq(post(compat('successful_apply', initialBody)).error, 'not_configured',
   'missing server-side GitHub PAT fails closed');
eq(githubPosts.length, 3, 'missing PAT must never submit');
console.log('PASS: ' + checks + ' offline Google compatibility gateway checks; no HTTP or real reports.');
