import unittest
from contextlib import nullcontext
from unittest.mock import Mock, patch

import main


class WebsiteCheckerTests(unittest.TestCase):
    def setUp(self):
        with main._VT_LOCK:
            main._VT_CACHE.clear()

    def test_normalizes_website_url_to_hostname_without_path(self):
        self.assertEqual(
            main.normalize_website_target("https://Sub.Example.com:8443/login?token=x"),
            "sub.example.com",
        )

    def test_accepts_idn_and_ip_addresses(self):
        self.assertEqual(
            main.normalize_website_target("https://bücher.example"),
            "xn--bcher-kva.example",
        )
        self.assertEqual(main.normalize_website_target("192.0.2.10"), "192.0.2.10")

    def test_rejects_invalid_or_unsafe_url_inputs(self):
        for target in ("", "ftp://example.com", "https://user:pass@example.com", "https://bad host/"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    main.normalize_website_target(target)

    def test_no_reputation_data_returns_safe_with_limited_verification(self):
        with patch.dict("os.environ", {"DNS_VIRUSTOTAL_API_KEY": ""}):
            result = main.check_website("https://ordinary.example.com/path")
        self.assertEqual(result["classification"], "SAFE")
        self.assertEqual(result["verification_status"], "LIMITED")
        self.assertIn("not configured", result["reputation_status"].lower())

    def test_credible_virus_total_suspicion_returns_suspicious(self):
        with patch(
            "main._virustotal_reputation",
            return_value={
                "available": True,
                "malicious": 0,
                "suspicious": 1,
                "source": "VirusTotal",
            },
        ):
            result = main.check_website("example.com")
        self.assertEqual(result["classification"], "SUSPICIOUS")
        self.assertEqual(result["verification_status"], "COMPLETE")
        self.assertTrue(any("suspicious detection" in reason for reason in result["reasons"]))
        self.assertEqual(result["reputation_source"], "VirusTotal")

    def test_virus_total_without_completed_stats_is_not_a_clean_result(self):
        response = Mock(status_code=200)
        response.json.return_value = {"data": {"attributes": {}}}
        with patch.dict("os.environ", {"DNS_VIRUSTOTAL_API_KEY": "test-key"}):
            with patch("main.requests.get", return_value=response):
                result = main._virustotal_reputation("example.com")
        self.assertFalse(result["available"])
        self.assertIn("no completed analysis", result["reason"].lower())

    def test_ip_target_uses_virus_total_ip_reputation_endpoint(self):
        response = Mock(status_code=200)
        response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 3}
                }
            }
        }
        with patch.dict("os.environ", {"DNS_VIRUSTOTAL_API_KEY": "test-key"}):
            with patch("main.requests.get", return_value=response) as request:
                result = main.check_website("192.0.2.10")
        self.assertEqual(result["classification"], "SAFE")
        self.assertIn("/ip_addresses/192.0.2.10", request.call_args.args[0])

    def test_virus_total_confirmed_detection_returns_suspicious(self):
        response = Mock(status_code=200)
        response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 1, "suspicious": 0, "undetected": 4}
                }
            }
        }
        with patch.dict("os.environ", {"DNS_VIRUSTOTAL_API_KEY": "test-key"}):
            with patch("main.requests.get", return_value=response):
                result = main.check_website("example.com")
        self.assertEqual(result["classification"], "SUSPICIOUS")
        self.assertEqual(result["verification_status"], "COMPLETE")
        self.assertTrue(any("VirusTotal reported 1 malicious detection" in reason for reason in result["reasons"]))

    def test_virus_total_timeout_stays_safe_but_marks_verification_limited(self):
        with patch.dict("os.environ", {"DNS_VIRUSTOTAL_API_KEY": "test-key"}):
            with patch("main.requests.get", side_effect=main.requests.Timeout):
                result = main.check_website("example.com")
        self.assertEqual(result["classification"], "SAFE")
        self.assertEqual(result["verification_status"], "LIMITED")
        self.assertIn("Timeout", result["reputation_status"])

    def test_checker_page_shows_safe_verification_limit(self):
        result = {
            "domain": "example.com",
            "classification": "SAFE",
            "verification_status": "LIMITED",
            "risk_score": 0,
            "reasons": ["VirusTotal lookup is not configured."],
            "reputation_source": None,
            "reputation_status": "VirusTotal lookup is not configured.",
        }
        with (
            patch("main.st.form", return_value=nullcontext()),
            patch("main.st.text_input", return_value="example.com"),
            patch("main.st.form_submit_button", return_value=True),
            patch("main.st.markdown") as markdown,
            patch("main.st.caption"),
            patch("main.st.info"),
            patch("main.st.success") as success,
            patch("main.st.warning") as warning,
            patch("main.st.metric"),
            patch("main.check_website", return_value=result),
        ):
            main.render_website_checker()
        markdown.assert_any_call("## Website checker")
        success.assert_called_once()
        warning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
