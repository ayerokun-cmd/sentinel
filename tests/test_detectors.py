"""Run with:  python -m unittest discover tests

Test samples are built in memory (never written to disk) so your real antivirus
doesn't quarantine them.
"""
import http.server
import json
import threading
import unittest
from email.message import EmailMessage

from sentinel import content_scanner, url_checks
from sentinel.findings import Finding
from sentinel.notify import Notifier


def titles(findings):
    return [f.title for f in findings]


class PhpShellTests(unittest.TestCase):
    def test_classic_one_liner_is_flagged(self):
        sample = "<?php " + "sys" + "tem($_GET['c']); ?>"
        out = content_scanner.scan_php_text(sample, "x.php")
        self.assertTrue(out)
        self.assertIn(out[0].severity, ("high", "critical"))

    def test_encoded_eval_is_flagged(self):
        sample = "<?php ev" + "al(base64_decode($_POST['p'])); ?>"
        out = content_scanner.scan_php_text(sample, "x.php")
        self.assertEqual(out[0].severity, "critical")

    def test_normal_php_is_clean(self):
        sample = "<?php $name = htmlspecialchars($_GET['name']); echo \"Hello $name\"; ?>"
        self.assertEqual(content_scanner.scan_php_text(sample, "x.php"), [])

    def test_php_in_image(self):
        data = b"\x89PNG\r\n\x1a\n....<?php echo 1; ?>"
        self.assertTrue(content_scanner.scan_php_in_image(data, "a.png"))


class UrlTests(unittest.TestCase):
    def test_safe_sites(self):
        for u in ["https://www.google.com/search?q=x", "https://github.com/login",
                  "https://www.paypal.com/signin", "https://login.microsoftonline.com/"]:
            self.assertEqual(url_checks.check_url(u), [], u)

    def test_fake_brand(self):
        out = url_checks.check_url("https://paypal.secure-login.xyz/verify")
        self.assertIn("Possible fake Paypal site", titles(out))
        self.assertIn("Domain ends in .xyz", titles(out))

    def test_ip_and_at_sign(self):
        self.assertIn("Link uses a raw IP address", titles(url_checks.check_url("http://45.9.1.2/a.exe")))
        self.assertIn("Link hides its real destination with '@'",
                      titles(url_checks.check_url("https://bank.com@evil.example/")))

    def test_blocklist_includes_subdomains(self):
        out = url_checks.check_url("https://cdn.malware-test.invalid/x", {"malware-test.invalid"})
        self.assertEqual(out[0].severity, "critical")


class EmailTests(unittest.TestCase):
    def make_phish(self):
        m = EmailMessage()
        m["From"] = '"support@paypal.com" <alerts@mailer.example>'
        m["Reply-To"] = "collect@other.example"
        m["Subject"] = "Urgent action required: verify your account"
        m["Authentication-Results"] = "mx.example; spf=fail; dkim=none; dmarc=fail"
        m.set_content("Your account has been suspended. Verify your account within 24 hours.")
        m.add_alternative('<p><a href="http://45.9.1.2/login">https://www.paypal.com</a></p>',
                          subtype="html")
        m.add_attachment(b"MZ fake", maintype="application", subtype="octet-stream",
                         filename="invoice.pdf.exe")
        return m.as_bytes()

    def test_phishing_email(self):
        t = titles(content_scanner.scan_email_bytes(self.make_phish(), "mail.eml"))
        self.assertIn("Sender name shows a fake address", t)
        self.assertIn("Replies go to a different domain", t)
        self.assertIn("Sender verification failed (DMARC, SPF)", t)
        self.assertIn("Disguised program attached: invoice.pdf.exe", t)
        self.assertIn("Link text hides its real destination", t)
        self.assertIn("Link uses a raw IP address", t)
        self.assertIn("Phishing-style wording", t)

    def test_normal_email(self):
        m = EmailMessage()
        m["From"] = "Sam <sam@example.com>"
        m["Subject"] = "Lunch?"
        m.set_content("Want to grab lunch tomorrow? Menu: https://www.example.com/menu")
        self.assertEqual(content_scanner.scan_email_bytes(m.as_bytes(), "ok.eml"), [])


class NotifyTests(unittest.TestCase):
    def test_webhook_receives_alert_once(self):
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        n = Notifier(level="high", desktop=False,
                     webhook=f"http://127.0.0.1:{server.server_port}/hook")
        found = [Finding("malware", "Bad thing", "critical", path="C:/x.exe"),
                 Finding("url", "Minor thing", "low")]
        self.assertEqual(n.send(found), 1)       # low is below the alert level
        self.assertEqual(n.send(found), 0)       # same finding isn't alerted twice
        server.shutdown()
        self.assertEqual(len(received), 1)
        self.assertIn("Bad thing", received[0]["text"])


if __name__ == "__main__":
    unittest.main()
