"""Optimizer tests. They only touch things the tests create themselves:
a temporary folder, a dummy process, and a test-only registry key."""
import os
import platform
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sentinel import optimizer

WINDOWS = platform.system() == "Windows"


class CleanTempTests(unittest.TestCase):
    def test_only_old_files_are_deleted(self):
        with tempfile.TemporaryDirectory() as d:
            old = Path(d) / "sub" / "old.tmp"
            new = Path(d) / "new.tmp"
            old.parent.mkdir()
            old.write_bytes(b"x" * 1000)
            new.write_bytes(b"y" * 10)
            three_days_ago = time.time() - 3 * 86400
            os.utime(old, (three_days_ago, three_days_ago))

            count, size = optimizer.clean_temp([d], dry_run=True)
            self.assertEqual((count, size), (1, 1000))
            self.assertTrue(old.exists(), "dry run must not delete")

            count, size = optimizer.clean_temp([d])
            self.assertEqual((count, size), (1, 1000))
            self.assertFalse(old.exists())
            self.assertFalse(old.parent.exists(), "empty folder should be removed")
            self.assertTrue(new.exists(), "recent files must be kept")


class CloseAppTests(unittest.TestCase):
    def test_close_dummy_process(self):
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            app = {"name": "dummy", "pids": [p.pid]}
            with mock.patch.object(optimizer, "_ask_yes", return_value=True):
                msg = optimizer.close_app(app)
            p.wait(timeout=10)
            self.assertTrue(msg.startswith(("Closed", "Force-closed")), msg)
        finally:
            if p.poll() is None:
                p.kill()

    def test_system_apps_are_never_closable(self):
        apps = optimizer.sample_apps(seconds=0.2)
        for name in ("svchost", "explorer", "csrss", "lsass", "kernel_task", "systemd"):
            if name in apps:
                self.assertFalse(apps[name]["closable"], name)


@unittest.skipUnless(WINDOWS, "Windows registry test")
class StartupTests(unittest.TestCase):
    BASE = r"Software\SentinelTest\CurrentVersion"

    def setUp(self):
        import winreg
        self.winreg = winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.BASE + r"\Run") as k:
            winreg.SetValueEx(k, "SentinelTestApp", 0, winreg.REG_SZ, r"C:\fake\app.exe")
        self.tmp = tempfile.TemporaryDirectory()
        self.patch = mock.patch.object(optimizer, "STARTUP_LOG", Path(self.tmp.name) / "changes.json")
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()
        subprocess.run(["reg", "delete", r"HKCU\Software\SentinelTest", "/f"], capture_output=True)

    def names(self):
        return [i["name"] for i in optimizer._list_startup_windows(self.BASE)]

    def test_disable_and_undo(self):
        self.assertIn("SentinelTestApp", self.names())
        item = next(i for i in optimizer._list_startup_windows(self.BASE) if i["name"] == "SentinelTestApp")
        self.assertIn("Turned off", optimizer.disable_startup(item))
        self.assertNotIn("SentinelTestApp", self.names())
        self.assertIn("SentinelTestApp", optimizer.undo_startup())
        self.assertIn("SentinelTestApp", self.names())


class DiagnoseTests(unittest.TestCase):
    def test_diagnose_runs_and_changes_nothing(self):
        with mock.patch.object(optimizer, "clean_temp", wraps=optimizer.clean_temp) as ct:
            issues = optimizer.diagnose(progress=False)
        for call in ct.call_args_list:
            self.assertTrue(call.kwargs.get("dry_run"), "diagnosis must only measure")
        self.assertTrue(issues)
        self.assertTrue(0 <= optimizer.health_score(issues) <= 100)

    def test_score(self):
        I = optimizer.Issue
        self.assertEqual(optimizer.health_score([I("a", "ok")]), 100)
        self.assertEqual(optimizer.health_score([I("a", "high"), I("b", "medium")]), 65)


if __name__ == "__main__":
    unittest.main()
