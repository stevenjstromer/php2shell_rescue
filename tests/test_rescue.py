import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

SRC = pathlib.Path(__file__).resolve().parents[1] / 'php2shell_rescue.py'
spec = importlib.util.spec_from_file_location('rescue', SRC)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

class TestBasics(unittest.TestCase):
    def test_change_config_preserves_others_and_enforces_mitigation(self):
        old = b'# comment\nLoadModule php_module /usr/local/old/libphp.so\nListen 80\n'
        new = r.change_config(old, '/usr/local/new/libphp.so', 'php_module', True)
        self.assertIn(b'LoadModule php_module /usr/local/new/libphp.so', new)
        self.assertIn(b'php_admin_flag session.upload_progress.enabled Off', new)
        self.assertEqual(new.count(b'Listen 80'), 1)
        with self.assertRaises(r.RescueError):
            r.change_config(new, '/usr/local/another.so', 'php_module', True)

    def test_atomic_bytes_keeps_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp)/'config'
            p.write_text('old')
            os.chmod(p, 0o640)
            r.atomic_bytes(p, b'new')
            self.assertEqual(p.read_bytes(), b'new')
            self.assertEqual(p.stat().st_mode & 0o777, 0o640)

    def test_probe_must_be_loopback(self):
        for value in ['http://example.org/', 'https://127.0.0.1/', 'http://localhost/', 'http://127.0.0.2/', 'http://127.0.0.1:80/dir']:
            with self.assertRaises(r.RescueError, msg=value):
                r.validate_probe_base(value)
        self.assertEqual(r.validate_probe_base('http://127.0.0.1:8080/'), 'http://127.0.0.1:8080/')

    def test_config_entry_only_one_directive(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp)/'a.conf'
            p.write_text('# LoadModule php_module /tmp/old\nLoadModule php_module /usr/local/old.so\n')
            raw, hit, path = r.config_entry(p)
            self.assertEqual(path, '/usr/local/old.so')
            p.write_text(p.read_text() + 'LoadModule php_module /usr/local/new.so\n')
            with self.assertRaises(r.RescueError):
                r.config_entry(p)

class TestCutover(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.work = self.root/'work'; self.work.mkdir()
        os.chmod(self.work, 0o700)
        self.conf = self.root/'httpd.conf'
        self.oldmodule = self.root/'old-libphp.so'; self.oldmodule.write_bytes(b'old-lib')
        self.newmodule = self.work/'candidate/libphp.so'; self.newmodule.parent.mkdir()
        self.newmodule.write_bytes(b'new-lib')
        (self.work/'candidate/php').write_bytes(b'new-php')
        self.original = f'LoadModule php_module {self.oldmodule}\nServerName localhost\n'.encode()
        self.conf.write_bytes(self.original)
        self.manifest = dict(schema=1,state='prepared', version='8.5.12',
                             conf=str(self.conf),httpd='/usr/local/bin/httpd',apxs='/usr/local/bin/apxs',
                             service={'mode':'brew-user','brew':'/usr/local/bin/brew'}, config_sha=r.digest(self.conf),
                             oldmodule=str(self.oldmodule), oldmodule_sha=r.digest(self.oldmodule),
                             module_sha=r.digest(self.newmodule),cli_sha=r.digest(self.work/'candidate/php'))
        r.save_manifest(self.work, self.manifest)
        self.docroot=self.root/'www';self.docroot.mkdir()
        self.opts=SimpleNamespace(work=str(self.work),probe_dir=str(self.docroot),
                                  probe_base='http://127.0.0.1:8000/',host_header=None,
                                  install_root=str(self.root/'install'),yes=True)
        self.calls=[]
        def fake_apache_paths(opts):
            raw,hit,path=r.config_entry(self.conf) if r.BLOCK_START not in self.conf.read_bytes() else (self.original, next(iter(r.MOD_RE.finditer(self.original))), str(self.oldmodule))
            return dict(conf=str(self.conf),httpd=self.manifest['httpd'],apxs=self.manifest['apxs'],
                        oldmodule=str(self.oldmodule),raw=raw,hit=hit)
        self.patchers=[mock.patch.object(r,'platform_check'),mock.patch.object(r,'deployment_root',side_effect=lambda path: pathlib.Path(path)),mock.patch.object(r,'apache_paths',side_effect=fake_apache_paths),
                       mock.patch.object(r,'verify_service_identity'),
                       mock.patch.object(r,'cmd',return_value=SimpleNamespace(returncode=0,stdout='',stderr='')),
                       mock.patch.object(r,'service',side_effect=lambda b,m:self.calls.append(m))]
        for p in self.patchers:p.start()

    def tearDown(self):
        for p in reversed(self.patchers):p.stop()
        self.temp.cleanup()

    def probe_factory(self, old_modules=None, new_modules=None, wrong_version=False, new_upload='0'):
        def fake_make_probe(*args):
            p=self.docroot/'probe.php';p.write_text('probe')
            def probe():
                is_new = r.BLOCK_START in self.conf.read_bytes()
                version = ('8.5.11' if wrong_version else '8.5.12') if is_new else '8.5.6'
                return dict(php=version,sapi='apache2handler',
                            modules=(new_modules if new_modules is not None else ['json','imagick']) if is_new else
                            (old_modules if old_modules is not None else ['json','imagick']),
                            upload=new_upload if is_new else '1')
            return p,probe
        return fake_make_probe

    def test_successful_deploy_then_explicit_rollback(self):
        with mock.patch.object(r,'make_probe',side_effect=self.probe_factory()):
            r.deploy(self.opts)
            m=r.load_manifest(self.work)
            self.assertEqual(m['state'],'deployed')
            self.assertIn(r.BLOCK_START, self.conf.read_bytes())
            self.assertEqual(self.calls,['stop','start'])
            r.rollback(self.opts)
            self.assertEqual(r.load_manifest(self.work)['state'],'rolled_back')
            self.assertEqual(self.conf.read_bytes(),self.original)
            self.assertEqual(self.calls,['stop','start','stop','start'])

    def test_failed_probe_restores_original(self):
        with mock.patch.object(r,'make_probe',side_effect=self.probe_factory(wrong_version=True)):
            with self.assertRaises(r.RescueError):r.deploy(self.opts)
        self.assertEqual(self.conf.read_bytes(),self.original)
        self.assertEqual(r.load_manifest(self.work)['state'],'rolled_back')
        self.assertEqual(self.calls,['stop','start','stop','start'])

    def test_extension_loss_rolls_back(self):
        with mock.patch.object(r,'make_probe',side_effect=self.probe_factory(new_modules=['json'])):
            with self.assertRaises(r.RescueError):r.deploy(self.opts)
        self.assertEqual(self.conf.read_bytes(),self.original)
        self.assertEqual(r.load_manifest(self.work)['state'],'rolled_back')

    def test_upload_progress_fails_closed(self):
        with mock.patch.object(r,'make_probe',side_effect=self.probe_factory(new_upload='1')):
            with self.assertRaises(r.RescueError):r.deploy(self.opts)
        self.assertEqual(self.conf.read_bytes(),self.original)

    def test_config_drift_blocks_without_interruption(self):
        self.conf.write_bytes(self.original + b'# administrator edit\n')
        with self.assertRaises(r.RescueError):r.deploy(self.opts)
        self.assertEqual(self.calls,[])


# Additional regression cases remain inside a new class so they are discovered
# even when the module is imported by unittest discovery.
class TestAdditionalCutover(unittest.TestCase):
    setUp = TestCutover.setUp
    tearDown = TestCutover.tearDown
    probe_factory = TestCutover.probe_factory
    def test_user_cancel_does_not_interrupt_service(self):
        self.opts.yes = False
        with mock.patch.object(r,'make_probe',side_effect=self.probe_factory()), \
             mock.patch('builtins.input',return_value='NO'):
            with self.assertRaises(r.RescueError):
                r.deploy(self.opts)
        self.assertEqual(self.calls,[])
        self.assertEqual(self.conf.read_bytes(),self.original)
        self.assertEqual(r.load_manifest(self.work)['state'],'prepared')

    def test_apache_config_test_failure_restores_without_service_restart(self):
        def command(args,**kwargs):
            if len(args)>=2 and '-t' in args and r.BLOCK_START in self.conf.read_bytes():
                raise r.RescueError('simulated SyntaxError from httpd -t')
            return SimpleNamespace(returncode=0,stdout='',stderr='')
        with mock.patch.object(r,'cmd',side_effect=command), \
             mock.patch.object(r,'make_probe',side_effect=self.probe_factory()):
            with self.assertRaises(r.RescueError):
                r.deploy(self.opts)
        self.assertEqual(self.conf.read_bytes(),self.original)
        self.assertEqual(self.calls,[])

    def test_service_start_failure_restores_old_php(self):
        failures={'count':0}
        def unstable_service(identity,mode):
            self.calls.append(mode)
            if mode=='start' and failures['count']==0:
                failures['count']+=1
                raise r.RescueError('simulated launchd start failure')
        with mock.patch.object(r,'service',side_effect=unstable_service), \
             mock.patch.object(r,'make_probe',side_effect=self.probe_factory()):
            with self.assertRaises(r.RescueError):r.deploy(self.opts)
        self.assertEqual(self.conf.read_bytes(),self.original)
        self.assertEqual(r.load_manifest(self.work)['state'],'rolled_back')
        self.assertEqual(self.calls,['stop','start','stop','start'])

class TestServiceAdapter(unittest.TestCase):
    def test_system_launchd_commands_use_bootout_bootstrap(self):
        ident={'mode':'launchd-system','plist':'/Library/LaunchDaemons/example.httpd.plist','label':'example.httpd'}
        with mock.patch.object(r,'cmd',return_value=SimpleNamespace(returncode=0)) as call:
            r.service(ident,'stop')
            r.service(ident,'start')
        self.assertEqual(call.call_args_list[0].args[0], ['/bin/launchctl','bootout','system',ident['plist']])
        self.assertEqual(call.call_args_list[1].args[0], ['/bin/launchctl','bootstrap','system',ident['plist']])

if __name__ == '__main__':
    unittest.main()
