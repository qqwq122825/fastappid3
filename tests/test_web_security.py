"""Offline console regressions: fake HTTP streams and a stubbed JavaScript DOM."""
from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from email.message import Message
from html.parser import HTMLParser
from unittest.mock import Mock, patch


# Exercise saved source snapshots with exactly the same tests during rollback.
_source = os.environ.get('WEB_TEST_SOURCE')
if _source:
    _spec = importlib.util.spec_from_file_location('web_under_test', _source)
    web = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(web)
else:
    import web


def make_handler(path, payload=None, *, cookie=None, raw=None, length=None):
    handler = object.__new__(web.Handler)
    handler.path = path
    handler.headers = Message()
    handler.headers['Content-Type'] = 'application/json'
    if cookie is not None:
        handler.headers['Cookie'] = cookie
    body = raw if raw is not None else json.dumps(payload).encode('utf-8')
    handler.headers['Content-Length'] = str(len(body) if length is None else length)
    handler.rfile = io.BytesIO(body)
    handler.wfile = io.BytesIO()
    handler.close_connection = False
    handler._json = Mock(side_effect=lambda value: value)
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    return handler


class ConsoleRequestTests(unittest.TestCase):
    def cookie(self):
        return 'gsa_auth=' + web._cookie_token()

    def test_exact_auth_cookie_is_accepted(self):
        handler = make_handler('/api/state', cookie='theme=light; ' + self.cookie())
        self.assertTrue(handler._authorized())

    def test_cookie_substrings_are_not_credentials(self):
        token = web._cookie_token()
        for cookie in (f'other_gsa_auth={token}', f'gsa_auth={token}extra',
                       f'session=gsa_auth={token}', f'gsa_auth="{token}extra"'):
            with self.subTest(cookie=cookie):
                self.assertFalse(make_handler('/api/state', cookie=cookie)._authorized())

    def test_missing_malformed_and_non_ascii_cookies_are_rejected(self):
        for cookie in (None, '', 'gsa_auth="unterminated', 'gsa_auth=\u00e9'):
            with self.subTest(cookie=cookie):
                self.assertFalse(make_handler('/api/state', cookie=cookie)._authorized())

    def test_saving_configuration_requires_login(self):
        handler = make_handler('/api/set-api', {'api': 'https://fixture.invalid/?num=1'})
        with patch.object(web, 'save_api') as save:
            response = handler._do_post()
        save.assert_not_called()
        self.assertTrue(response.get('need_login'))

    def test_authenticated_configuration_save_still_works(self):
        handler = make_handler('/api/set-api', {'api': 'https://fixture.invalid/?num=1'},
                               cookie=self.cookie())
        with patch.object(web, 'validate_proxy_api', return_value=True) as validate, \
             patch.object(web, 'save_api') as save:
            response = handler._do_post()
        validate.assert_called_once_with('https://fixture.invalid/?num={num}')
        save.assert_called_once_with('https://fixture.invalid/?num={num}')
        self.assertTrue(response['ok'])

    def test_diagnostics_reports_runtime_and_opt_in_benchmark(self):
        handler = make_handler('/api/diagnostics?benchmark=1', cookie=self.cookie())
        fixture = {'threading_lock': {'operations_per_second': 123}}
        with patch.object(web, 'is_running', return_value=False), \
             patch.object(web, 'runtime_benchmark', return_value=fixture) as bench:
            response = handler._do_get()
        bench.assert_called_once_with()
        self.assertEqual(fixture, response['benchmark'])
        self.assertIn('python', response['runtime'])
        self.assertIn('srp_backend', response['runtime'])

    def test_diagnostics_does_not_benchmark_during_a_task(self):
        handler = make_handler('/api/diagnostics?benchmark=1', cookie=self.cookie())
        with patch.object(web, 'is_running', return_value=True), \
             patch.object(web, 'runtime_benchmark') as bench:
            response = handler._do_get()
        bench.assert_not_called()
        self.assertIn('任务运行中', response['benchmark_error'])

    def test_runtime_benchmark_has_lock_and_srp_measurements(self):
        result = web.runtime_benchmark(thread_count=2, lock_loops=2, srp_loops=1)
        self.assertEqual(4, result['threading_lock']['operations'])
        self.assertEqual(4, result['semaphore_1']['operations'])
        self.assertEqual(1, result['srp']['operations'])
        self.assertGreater(result['srp']['milliseconds_per_operation'], 0)

    def test_supplier_error_is_rejected_before_configuration_save(self):
        handler = make_handler('/api/set-api', {'api': 'https://fixture.invalid/?num=1'},
                               cookie=self.cookie())
        with patch.object(web, 'validate_proxy_api',
                          side_effect=ValueError('供应商未返回代理：29776密码错误')), \
             patch.object(web, 'save_api') as save:
            response = handler._do_post()
        save.assert_not_called()
        self.assertIn('29776密码错误', response['error'])

    def test_masked_password_can_never_overwrite_saved_credential(self):
        handler = make_handler('/api/set-api',
                               {'api': 'https://proxy.invalid/list?password=***&num=1'},
                               cookie=self.cookie())
        with patch.object(web, 'validate_proxy_api') as validate, \
             patch.object(web, 'save_api') as save:
            response = handler._do_post()
        validate.assert_not_called()
        save.assert_not_called()
        self.assertIn('隐藏后的地址', response['error'])

    def test_invalid_secrets_json_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(web, 'HERE', directory):
            path = os.path.join(directory, 'secrets.json')
            original = b'{"keep": true,}'
            with open(path, 'wb') as handle:
                handle.write(original)
            with self.assertRaisesRegex(ValueError, '原文件未修改'):
                web.save_api('https://fixture.invalid/?num={num}')
            with open(path, 'rb') as handle:
                self.assertEqual(original, handle.read())

    def test_valid_secrets_save_preserves_fields_and_uses_private_mode(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(web, 'HERE', directory):
            path = os.path.join(directory, 'secrets.json')
            with open(path, 'w', encoding='utf-8') as handle:
                json.dump({'keep': 'value'}, handle)
            web.save_api('https://fixture.invalid/?num={num}')
            with open(path, encoding='utf-8') as handle:
                saved = json.load(handle)
            self.assertEqual('value', saved['keep'])
            self.assertEqual('https://fixture.invalid/?num={num}', saved['proxy_api'])
            self.assertEqual(0o600, stat.S_IMODE(os.stat(path).st_mode))

    def test_proxy_api_is_redacted_from_command_log(self):
        secret = 'https://proxy.invalid/list?token=fixture-secret&num={num}'
        logged = web.command_for_log(['python', 'run_mp.py', '--api', secret,
                                      '--threads', '100'])
        self.assertNotIn('fixture-secret', logged)
        self.assertNotIn(secret, logged)
        self.assertIn('--api', logged)
        self.assertIn('<proxy-api-redacted>', logged)
        self.assertEqual('socks5://user:***@proxy.invalid:9000/?token=***',
                         web.mask_api('socks5://user:secret@proxy.invalid:9000/?token=abc'))

    def test_invalid_secrets_json_error_reaches_client(self):
        handler = make_handler('/api/set-api', {'api': 'https://fixture.invalid/?num=1'},
                               cookie=self.cookie())
        with patch.object(web, 'validate_proxy_api', return_value=True), \
             patch.object(web, 'save_api', side_effect=ValueError('原文件未修改')):
            response = handler._do_post()
        self.assertIn('原文件未修改', response['error'])

    def test_login_can_set_cookie_without_existing_session(self):
        handler = make_handler('/api/login', {'password': 'fixture-password'})
        with patch.object(web, 'PASSWORD', 'fixture-password'):
            handler._do_post()
        self.assertEqual({'ok': True}, json.loads(handler.wfile.getvalue()))
        self.assertTrue(any(call.args[0] == 'Set-Cookie'
                            for call in handler.send_header.call_args_list))

    def test_non_object_json_is_reported_as_input_error(self):
        for payload in (None, [], 'text', 123, True):
            with self.subTest(payload=payload):
                handler = make_handler('/api/set-api', payload, cookie=self.cookie())
                with patch.object(web, 'save_api') as save:
                    response = handler._do_post()
                self.assertIn('error', response)
                save.assert_not_called()

    def test_invalid_content_length_is_rejected_before_reading(self):
        for length in ('invalid', -1):
            with self.subTest(length=length):
                handler = make_handler('/api/login', {}, length=length)
                handler.rfile = Mock()
                response = handler._do_post()
                self.assertIn('error', response)
                handler.rfile.read.assert_not_called()
                self.assertTrue(handler.close_connection)

    def test_oversize_body_closes_connection_without_reading(self):
        handler = make_handler('/api/login', {}, length=64 * 1024 * 1024 + 1)
        handler.rfile = Mock()
        self.assertIn('error', handler._do_post())
        handler.rfile.read.assert_not_called()
        self.assertTrue(handler.close_connection)

    def test_empty_stop_request_is_still_valid(self):
        handler = make_handler('/api/stop', cookie=self.cookie(), raw=b'')
        with patch.object(web, 'stop_job', return_value={'ok': True}) as stop:
            response = handler._do_post()
        self.assertEqual({'ok': True}, response)
        stop.assert_called_once_with()

    def test_clear_devices_endpoint_calls_idle_pool_cleanup(self):
        handler = make_handler('/api/clear-devices', {}, cookie=self.cookie())
        with patch.object(web, 'clear_devices', return_value={'ok': True, 'cleared': 3}) as clear:
            response = handler._do_post()
        self.assertEqual({'ok': True, 'cleared': 3}, response)
        clear.assert_called_once_with()

    def test_clear_devices_removes_only_project_device_root(self):
        with tempfile.TemporaryDirectory() as directory:
            data = os.path.join(directory, 'data')
            root = os.path.join(data, 'devices-simple')
            os.makedirs(os.path.join(root, 'fixture'))
            with open(os.path.join(root, 'fixture', 'state.json'), 'w', encoding='utf-8') as handle:
                handle.write('{}')
            keep = os.path.join(data, 'accounts.txt')
            with open(keep, 'w', encoding='utf-8') as handle:
                handle.write('fixture')
            with patch.object(web, 'HERE', directory), \
                 patch.object(web, 'DEVICE_ROOT', root), \
                 patch.object(web, 'is_running', return_value=False):
                response = web.clear_devices()
            self.assertTrue(response['ok'])
            self.assertFalse(os.path.exists(root))
            self.assertTrue(os.path.exists(keep))

    def test_clear_devices_works_without_worker_dependencies_and_resets_live_count(self):
        with tempfile.TemporaryDirectory() as directory:
            data = os.path.join(directory, 'data')
            root = os.path.join(data, 'devices-simple')
            live = os.path.join(data, 'live.json')
            key = hashlib.sha256(web.DEVICE_ORIGIN.encode()).hexdigest()[:24]
            for slot in ('01', '02', '03'):
                os.makedirs(os.path.join(root, key, 'devices', slot))
            with open(live, 'w', encoding='utf-8') as handle:
                json.dump({'finished': True, 'device_registered': 3000,
                           'device_ready': 3000}, handle)
            with patch.object(web, 'HERE', directory), \
                 patch.object(web, 'LIVE', live), \
                 patch.object(web, 'DEVICE_ROOT', root), \
                 patch.object(web, 'is_running', return_value=False):
                response = web.clear_devices()
            self.assertEqual(3, response['cleared'])
            self.assertFalse(os.path.exists(root))
            with open(live, encoding='utf-8') as handle:
                state = json.load(handle)
            self.assertEqual(0, state['device_registered'])
            self.assertEqual(0, state['device_ready'])

    def test_clear_devices_refuses_while_task_is_running(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(web, 'HERE', directory), \
             patch.object(web, 'DEVICE_ROOT', os.path.join(directory, 'data', 'devices-simple')), \
             patch.object(web, 'is_running', return_value=True):
            response = web.clear_devices()
        self.assertIn('任务运行中', response['error'])

    def test_idle_state_reports_persistent_device_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = os.path.join(directory, 'devices-simple')
            key = hashlib.sha256(web.DEVICE_ORIGIN.encode()).hexdigest()[:24]
            devices = os.path.join(root, key, 'devices')
            for slot in ('01', '02', '03'):
                os.makedirs(os.path.join(devices, slot))
            live = os.path.join(directory, 'live.json')
            with open(live, 'w', encoding='utf-8') as handle:
                json.dump({'finished': True, 'device_registered': 999}, handle)
            with patch.object(web, 'LIVE', live), \
                 patch.object(web, 'DEVICE_ROOT', root), \
                 patch.object(web, '_active_task_record', return_value=None):
                state = web._live_state_uncached()
            self.assertEqual(3, state['device_registered'])
            self.assertEqual(3, state['device_ready'])
            self.assertEqual(3, state['device_total'])
            self.assertEqual('2026.11.28.11', state['version'])

    def test_linux_process_group_cpu_sums_parent_and_children(self):
        parent = '1 (parent) S 0 77 0 0 0 0 0 0 0 0 200 100 0 0 0 0 0 0 0 0\n'
        child = '2 (child) S 1 77 0 0 0 0 0 0 0 0 50 25 0 0 0 0 0 0 0 0\n'
        other = '3 (other) S 1 88 0 0 0 0 0 0 0 0 900 900 0 0 0 0 0 0 0 0\n'
        with patch.object(web.os.path, 'isdir', return_value=True), \
             patch.object(web.os, 'listdir', return_value=['1', '2', '3']), \
             patch.object(web.os, 'sysconf', return_value=100), \
             patch('builtins.open', side_effect=[io.StringIO(parent),
                                                 io.StringIO(child),
                                                 io.StringIO(other)]):
            self.assertEqual(3.75, web._process_group_cpu_seconds(77))

    def test_new_multi_process_run_removes_stale_result_files(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(web, 'HERE', directory), \
             patch.object(web, 'LIVE', os.path.join(directory, 'data', 'live.json')):
            data = os.path.join(directory, 'data')
            os.makedirs(data)
            stale = [os.path.join(data, 'live.json'),
                     os.path.join(data, 'live-p0.json'),
                     os.path.join(data, 'mp-p0.jsonl')]
            for path in stale:
                with open(path, 'w', encoding='utf-8') as handle:
                    handle.write('stale')
            keep = os.path.join(data, 'accounts.txt')
            with open(keep, 'w', encoding='utf-8') as handle:
                handle.write('fixture')
            web._LIVE_CACHE.update(at=123.0, data={'recent': ['stale']})
            web._reset_run_artifacts(2)
            self.assertTrue(all(not os.path.exists(path) for path in stale))
            self.assertTrue(os.path.exists(keep))
            self.assertEqual({'at': 0.0, 'data': None}, web._LIVE_CACHE)

    def test_unauthenticated_raw_upload_does_not_write_files(self):
        handler = make_handler('/api/upload', raw=b'fixture')
        handler.headers.replace_header('Content-Type', 'application/octet-stream')
        handler._upload = Mock()
        response = handler._do_post()
        self.assertTrue(response.get('need_login'))
        handler._upload.assert_not_called()

    def test_export_filename_does_not_accept_header_control_characters(self):
        for status in ('all\r\nX-Fixture: marker', '\u96ea', 'x' * 500):
            with self.subTest(status=status):
                handler = make_handler('/api/export')
                with patch('glob.glob', return_value=[]), \
                     patch('builtins.open', side_effect=FileNotFoundError):
                    handler._export(status, 'txt')
                values = [call.args[1] for call in handler.send_header.call_args_list
                          if call.args[0] == 'Content-Disposition']
                self.assertEqual(1, len(values))
                self.assertNotIn('\r', values[0])
                self.assertNotIn('\n', values[0])
                self.assertTrue(values[0].isascii())
                self.assertLess(len(values[0]), 150)

    def test_rejected_body_response_advertises_connection_close(self):
        handler = make_handler('/api/login')
        handler.close_connection = True
        handler._send(b'{}')
        handler.send_header.assert_any_call('Connection', 'close')


class ParsedHTML(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.text = []
        self.titles = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.titles.extend(value for key, value in attrs if key == 'title')

    def handle_data(self, data):
        self.text.append(data)


@unittest.skipUnless(shutil.which('node'), 'Node.js is required for inline JavaScript tests')
class ConsoleRenderingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = '<b>fixture</b> & "quoted"'
        row = {key: cls.fixture for key in
               ('email', 'status', 'detail', 'cpu', 'thread_cpu_ms', 'slot', 'http', 'ec')}
        row.update(ms=1250, attempts=2)
        # Run the actual inline page script. Browser APIs are inert stubs, and
        # initial fetch calls never resolve; no network or worker is involved.
        script = r'''
const fs = require('node:fs');
const vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, {
    value: '1', style: {}, classList: {add(){}, remove(){}},
    addEventListener(){}, focus(){}, innerHTML: '', textContent: ''
  });
  return elements.get(id);
}
const context = vm.createContext({
  document: {getElementById: element}, window: {},
  fetch: () => new Promise(() => {}), setInterval(){}, setTimeout(){},
  clearTimeout(){}, AbortController, console, fixtureRow: input.row,
  fixtureText: input.fixture
});
new vm.Script(input.source, {filename: 'web-inline.js'}).runInContext(context);
(async () => {
  const row = vm.runInContext('rowHtml(fixtureRow, fixtureText)', context);
  vm.runInContext("LAST = {done: 1, recent: [fixtureRow]}; $('filter').value = 'all'; renderRowsOld();", context);
  const legacy = element('rows').innerHTML;
  context.fetch = async () => ({json: async () => ({error: input.fixture})});
  await vm.runInContext('TICK_RUNNING = false; tick()', context);
  const error = element('stateTag').innerHTML;
  vm.runInContext("HIST={rows:[fixtureRow],total:1}; LAST={done:1,recent:[fixtureRow]}; $('filter').value='timeout'; renderRows();", context);
  context.fetch = async () => ({ok: true, status: 200,
    text: async () => JSON.stringify({ok:true,total:2})});
  await vm.runInContext('start()', context);
  const reset = vm.runInContext("({filter:$('filter').value,hist:HIST,last:LAST,rows:$('rows').innerHTML,hint:$('tblHint').textContent})", context);
  console.log(JSON.stringify({row, legacy, error, reset}));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
        source = web.PAGE.split('<script>', 1)[1].split('</script>', 1)[0]
        result = subprocess.run(
            [shutil.which('node'), '-e', script],
            input=json.dumps({'source': source, 'row': row, 'fixture': cls.fixture}),
            capture_output=True, text=True, timeout=10, check=True)
        cls.rendered = json.loads(result.stdout)

    def test_result_text_is_not_interpreted_as_markup(self):
        for name in ('row', 'legacy'):
            with self.subTest(renderer=name):
                parsed = ParsedHTML(self.rendered[name])
                self.assertNotIn('b', parsed.tags)
                self.assertIn(self.fixture, ''.join(parsed.text))

    def test_detail_tooltip_preserves_literal_text(self):
        for name in ('row', 'legacy'):
            with self.subTest(renderer=name):
                self.assertEqual([self.fixture], ParsedHTML(self.rendered[name]).titles)

    def test_duration_keeps_seconds_format(self):
        for name in ('row', 'legacy'):
            with self.subTest(renderer=name):
                self.assertIn('1.25', ParsedHTML(self.rendered[name]).text)

    def test_error_text_is_not_interpreted_as_markup(self):
        parsed = ParsedHTML(self.rendered['error'])
        self.assertNotIn('b', parsed.tags)
        self.assertIn(self.fixture, ''.join(parsed.text))

    def test_successful_start_clears_old_rows_and_filter(self):
        reset = self.rendered['reset']
        self.assertEqual('all', reset['filter'])
        self.assertIsNone(reset['hist'])
        self.assertEqual(0, reset['last']['done'])
        self.assertEqual(2, reset['last']['total'])
        self.assertEqual([], reset['last']['recent'])
        self.assertIn('还没有结果', reset['rows'])
        self.assertEqual('实时刷新', reset['hint'])

    def test_page_exposes_clear_devices_control(self):
        self.assertIn('id="clearDevices"', web.PAGE)

    def test_page_exposes_device_usage_limit(self):
        self.assertIn('id="deviceMaxUses"', web.PAGE)
        self.assertIn('device_max_uses:deviceMaxUses', web.PAGE)
        self.assertIn("const DEVICE_MAX_USES_KEY = 'gsa.device_max_uses'", web.PAGE)
        self.assertIn('const deviceMaxUses = saveDeviceMaxUses();', web.PAGE)
        self.assertIn('localStorage.getItem(DEVICE_MAX_USES_KEY)', web.PAGE)
        self.assertIn('class="device-maintenance"', web.PAGE)
        self.assertIn('class="btn danger-outline"', web.PAGE)
        self.assertIn('class="task-actions"', web.PAGE)
        self.assertIn("post('/api/clear-devices')", web.PAGE)
        self.assertIn('确定清空所有已注册设备', web.PAGE)

    def test_total_concurrency_is_split_across_processes(self):
        self.assertIn('type="hidden" id="processes" value="8"', web.PAGE)
        self.assertIn('id="totalConcurrency" value="800"', web.PAGE)
        self.assertIn('id="threads" value="100"', web.PAGE)
        self.assertIn("const t=Math.max(1, Math.ceil(requested/p));", web.PAGE)
        self.assertIn("$('threads').value=String(t);", web.PAGE)
        self.assertIn("$('totalConcurrency').addEventListener('input', refreshHint)", web.PAGE)

    def test_result_rows_show_device_identity_and_usage(self):
        self.assertIn('>设备ID</th>', web.PAGE)
        self.assertIn('>使用</th>', web.PAGE)
        self.assertIn("r.device_id || '--'", web.PAGE)
        self.assertIn('deviceUses > deviceLimit', web.PAGE)
        self.assertIn("deviceOver?'⚠ '", web.PAGE)

    def test_valid_results_have_summary_counter_and_filter(self):
        self.assertIn('id="sValid"', web.PAGE)
        self.assertIn('<option value="valid">密码正确</option>', web.PAGE)
        self.assertIn("setStat('sValid', by.valid)", web.PAGE)
        self.assertIn("valid:'密码正确'", web.PAGE)
        self.assertNotIn('id="sMac"', web.PAGE)
        self.assertNotIn('<option value="need_mac">需要真机</option>', web.PAGE)
        self.assertIn('(by.need_mac||0)', web.PAGE)

    def test_web_review_result_has_visible_column_and_labels(self):
        self.assertIn('>Web复核</th>', web.PAGE)
        self.assertIn('function webReviewHtml(r)', web.PAGE)
        self.assertIn("web_timeout:'复核超时'", web.PAGE)
        self.assertIn("repair_unspecified:'仍无法细分'", web.PAGE)
        self.assertIn('authType=${r.web_auth_type}', web.PAGE)
        self.assertIn('`\u6362IP ${r.web_proxy_rotations}`', web.PAGE)
        self.assertIn("need_2fa:'双重验证'", web.PAGE)
        self.assertIn('仅 au=repair 需要 Web 复核', web.PAGE)


if __name__ == '__main__':
    unittest.main()
