import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import main
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP


class DomainAnalysisTests(unittest.TestCase):
    def setUp(self):
        with main._SCAN_INTEL_CACHE_LOCK:
            main._SCAN_INTEL_CACHE.clear()

    def run_scan(
        self,
        *,
        google=None,
        virustotal=None,
        urlhaus=None,
        dns=None,
        redirect=None,
        risk_score=0,
        configured=True,
    ):
        env = {
            "DNS_GOOGLE_SAFE_BROWSING_API_KEY": "google-key" if configured else "",
            "DNS_VIRUSTOTAL_API_KEY": "vt-key" if configured else "",
            "DNS_URLHAUS_AUTH_KEY": "urlhaus-key" if configured else "",
        }
        default_provider_status = "no_data" if configured else "not_configured"
        with patch.dict("os.environ", env):
            with patch("main._resolve_website_host", return_value=dns or main._scan_check(
                "DNS resolution", "completed", "informational", "Resolved.", ["93.184.216.34"]
            )):
                with patch("main._diagnose_redirects", return_value=redirect or main._scan_check(
                    "Redirect check", "completed", "informational", "Redirects checked."
                )):
                    with patch("main._diagnose_google_safe_browsing", return_value=google or main._scan_check(
                        "Google Safe Browsing", default_provider_status, "unknown", "No reputation data."
                    )):
                        with patch("main._diagnose_virustotal", return_value=virustotal or main._scan_check(
                            "VirusTotal", default_provider_status, "unknown", "No reputation data."
                        )):
                            with patch("main._diagnose_urlhaus", return_value=urlhaus or main._scan_check(
                                "URLhaus", default_provider_status, "unknown", "No reputation data."
                            )):
                                with patch("main.analyze_domain", return_value={
                                    "risk_score": risk_score,
                                    "risk_level": "LOW RISK",
                                    "reasons": [],
                                }):
                                    return main.scan_website("https://example.com/path?x=1")

    def test_missing_reputation_is_safe_with_limited_verification(self):
        with patch("main._virustotal_reputation", return_value={"available": False, "reason": "not configured"}):
            result = main.analyze_domain("example.com")
        self.assertEqual(result["classification"], "SAFE")
        self.assertEqual(result["verification_status"], "LIMITED")
        self.assertEqual(result["risk_score"], 0)
        self.assertTrue(any("No elevated domain-structure" in reason for reason in result["reasons"]))

    def test_unusual_extension_alone_does_not_classify_domain_as_malicious(self):
        with patch("main._virustotal_reputation", return_value={"available": False, "reason": "No report."}):
            result = main.analyze_domain("ordinary-example.xyz")
        self.assertEqual(result["classification"], "SAFE")
        self.assertEqual(result["verification_status"], "LIMITED")
        self.assertEqual(result["risk_score"], 8)

    def test_clean_available_reputation_is_safe(self):
        with patch(
            "main._virustotal_reputation",
            return_value={"available": True, "malicious": 0, "suspicious": 0, "source": "VirusTotal"},
        ):
            result = main.analyze_domain("example.com")
        self.assertEqual(result["classification"], "SAFE")

    def test_missing_analysis_statistics_are_not_treated_as_clean(self):
        response = Mock()
        response.status_code = 200
        response.json.return_value = {"data": {"attributes": {}}}
        with patch.dict("os.environ", {"DNS_VIRUSTOTAL_API_KEY": "test-key"}):
            with patch("main.requests.get", return_value=response):
                reputation = main._virustotal_reputation("example.com")
        self.assertFalse(reputation["available"])
        self.assertIn("no completed analysis statistics", reputation["reason"])

    def test_scan_with_no_configured_services_is_safe_limited_and_lists_missing_checks(self):
        result = self.run_scan(configured=False)
        self.assertEqual(result["classification"], "SAFE")
        self.assertEqual(result["verification_status"], "LIMITED")
        self.assertEqual(result["status_message"], "NO KNOWN THREATS DETECTED")
        self.assertEqual(
            result["secondary_notice"],
            "Verification limited — some security checks could not be completed.",
        )
        self.assertIn("No threat-intelligence service is configured", result["reason"])
        self.assertTrue(any("not_configured" in check["status"] for check in result["checks"]))
        self.assertIn("Configure an eligible reputation service", result["recommended_action"])

    def test_scan_with_clean_sources_and_one_no_data_source_is_safe(self):
        result = self.run_scan(
            configured=True,
            google=main._scan_check("Google Safe Browsing", "completed", "clean", "No match."),
            virustotal=main._scan_check("VirusTotal", "no_data", "unknown", "No report."),
            urlhaus=main._scan_check("URLhaus", "not_configured", "unknown", "Not configured."),
        )
        self.assertEqual(result["classification"], "SAFE")
        self.assertEqual(result["verification_status"], "LIMITED")
        self.assertEqual(result["status_message"], "NO KNOWN THREATS DETECTED")
        self.assertTrue(any("VirusTotal" in check and "no report" in check.lower() for check in result["failed_checks"]))

    def test_scan_api_failures_are_safe_limited_and_diagnostic(self):
        result = self.run_scan(
            google=main._scan_check("Google Safe Browsing", "failed", "unknown", "HTTP 403."),
            virustotal=main._scan_check("VirusTotal", "not_configured", "unknown", "Not configured."),
            urlhaus=main._scan_check("URLhaus", "not_configured", "unknown", "Not configured."),
        )
        self.assertEqual(result["classification"], "SAFE")
        self.assertEqual(result["verification_status"], "LIMITED")
        self.assertEqual(result["status_message"], "NO KNOWN THREATS DETECTED")
        self.assertIn("Google Safe Browsing", result["reason"])
        self.assertTrue(any("HTTP 403" in failure for failure in result["failed_checks"]))

    def test_failed_required_dns_or_redirect_check_is_safe_limited(self):
        result = self.run_scan(
            google=main._scan_check("Google Safe Browsing", "completed", "clean", "No match."),
            virustotal=main._scan_check("VirusTotal", "not_configured", "unknown", "Not configured."),
            urlhaus=main._scan_check("URLhaus", "not_configured", "unknown", "Not configured."),
            redirect=main._scan_check("Redirect check", "failed", "unknown", "Connection timed out."),
        )
        self.assertEqual(result["classification"], "SAFE")
        self.assertEqual(result["verification_status"], "LIMITED")
        self.assertIn("Redirect check", result["reason"])
        self.assertTrue(any("Connection timed out" in failure for failure in result["failed_checks"]))

    def test_scan_without_reputation_returns_safe_with_limited_verification(self):
        result = self.run_scan(
            google=main._scan_check("Google Safe Browsing", "no_data", "unknown", "Empty response."),
            virustotal=main._scan_check("VirusTotal", "no_data", "unknown", "No report."),
            urlhaus=main._scan_check("URLhaus", "no_data", "unknown", "No data."),
        )
        self.assertEqual(result["classification"], "SAFE")
        self.assertEqual(result["verification_status"], "LIMITED")
        self.assertEqual(result["status_message"], "NO KNOWN THREATS DETECTED")
        self.assertIn("insufficient reputation evidence", result["reason"])
        self.assertIn("No reputation record was available", result["recommended_action"])
        self.assertIn("Avoid entering passwords", result["recommended_action"])

    def test_clean_completed_scan_returns_safe_without_limited_notice(self):
        result = self.run_scan(
            google=main._scan_check("Google Safe Browsing", "completed", "clean", "No match."),
            virustotal=main._scan_check("VirusTotal", "completed", "clean", "No detections."),
            urlhaus=main._scan_check("URLhaus", "completed", "clean", "No active listing."),
        )
        self.assertEqual(result["classification"], "SAFE")
        self.assertEqual(result["verification_status"], "COMPLETE")
        self.assertEqual(result["status_message"], "NO SIGNIFICANT THREATS DETECTED")
        self.assertIsNone(result["secondary_notice"])

    def test_api_error_does_not_create_clean_evidence(self):
        result = self.run_scan(
            google=main._scan_check("Google Safe Browsing", "failed", "unknown", "HTTP 503 after retries."),
            virustotal=main._scan_check("VirusTotal", "no_data", "unknown", "No report."),
            urlhaus=main._scan_check("URLhaus", "not_configured", "unknown", "Missing credentials."),
        )
        self.assertEqual(result["classification"], "SAFE")
        self.assertEqual(result["verification_status"], "LIMITED")
        self.assertNotIn("Google Safe Browsing: HTTP 503 after retries.", result["available_evidence"])
        self.assertTrue(any("HTTP 503 after retries" in item for item in result["failed_checks"]))

    def test_confirmed_threat_overrides_clean_or_failed_other_sources(self):
        result = self.run_scan(
            google=main._scan_check("Google Safe Browsing", "completed", "malicious", "Malware match."),
            virustotal=main._scan_check("VirusTotal", "failed", "unknown", "Timeout."),
            urlhaus=main._scan_check("URLhaus", "completed", "clean", "No active listing."),
        )
        self.assertEqual(result["classification"], "MALICIOUS")
        self.assertIn("malicious indicator", result["reason"])
        self.assertTrue(any("Google Safe Browsing" in item for item in result["display_reasons"]))
        self.assertTrue(result["conflicting_evidence"])

    def test_suspicious_and_confirmed_results_share_the_malicious_notice(self):
        confirmed = self.run_scan(
            google=main._scan_check("Google Safe Browsing", "completed", "malicious", "Malware match."),
            virustotal=main._scan_check("VirusTotal", "not_configured", "unknown", "Missing key."),
            urlhaus=main._scan_check("URLhaus", "not_configured", "unknown", "Missing key."),
        )
        with main._SCAN_INTEL_CACHE_LOCK:
            main._SCAN_INTEL_CACHE.clear()
        suspected = self.run_scan(
            google=main._scan_check("Google Safe Browsing", "completed", "suspicious", "Possible phishing."),
            virustotal=main._scan_check("VirusTotal", "not_configured", "unknown", "Missing key."),
            urlhaus=main._scan_check("URLhaus", "not_configured", "unknown", "Missing key."),
        )
        self.assertEqual(confirmed["classification"], "MALICIOUS")
        self.assertEqual(suspected["classification"], "MALICIOUS")
        with patch("main.st.markdown") as markdown:
            main.render_verdict_notice(
                confirmed["classification"], "example.com", confirmed["display_reasons"]
            )
            confirmed_html = markdown.call_args.args[0]
            main.render_verdict_notice(
                suspected["classification"], "example.com", suspected["display_reasons"]
            )
            suspected_html = markdown.call_args.args[0]
        for rendered in (confirmed_html, suspected_html):
            self.assertIn("verdict-malicious", rendered)
            self.assertIn("MALICIOUS WEBSITE DETECTED", rendered)
            self.assertNotIn("UNKNOWN", rendered)
        self.assertEqual(confirmed_html.count("MALICIOUS WEBSITE DETECTED"), suspected_html.count("MALICIOUS WEBSITE DETECTED"))
        self.assertIn("Google Safe Browsing: Malware match.", confirmed_html)
        self.assertIn("Google Safe Browsing: Possible phishing.", suspected_html)

    def test_limited_verdict_uses_safe_label_and_explicit_verification_notice(self):
        with patch("main.st.markdown") as markdown:
            main.render_verdict_notice(
                "UNKNOWN",
                "example.com",
                ["The reputation service returned an error."],
                verification_status="LIMITED",
            )
        rendered = markdown.call_args.args[0]
        self.assertIn('<span class="verdict-badge">SAFE</span>', rendered)
        self.assertIn("NO KNOWN THREATS DETECTED", rendered)
        self.assertIn(
            "Verification limited — some security checks could not be completed.",
            rendered,
        )
        self.assertNotIn("UNKNOWN", rendered)

    def test_suspicious_signal_and_clean_reputation_is_safe_with_conflict_recorded(self):
        result = self.run_scan(
            google=main._scan_check("Google Safe Browsing", "completed", "clean", "No match."),
            virustotal=main._scan_check("VirusTotal", "not_configured", "unknown", "Not configured."),
            urlhaus=main._scan_check("URLhaus", "not_configured", "unknown", "Not configured."),
            risk_score=8,
        )
        self.assertEqual(result["classification"], "SAFE")
        self.assertEqual(result["verification_status"], "LIMITED")
        self.assertTrue(result["conflicting_evidence"])
        self.assertIn("inconclusive", result["reason"])

    def test_redirect_probe_follows_bounded_redirects_without_downloading_page(self):
        redirect = Mock(status_code=302, headers={"Location": "https://destination.example/"})
        final = Mock(status_code=200, headers={})
        with patch("main._is_public_host", return_value=(True, "Public.")):
            with patch("main._request_with_retry", side_effect=[(redirect, 0), (final, 0)]) as request:
                result = main._diagnose_redirects("https://example.com/")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(request.call_count, 2)
        self.assertTrue(any("destination.example" in item for item in result["evidence"]))

    def test_redirect_destination_gets_its_own_reputation_checks(self):
        redirect = main._scan_check(
            "Redirect check", "completed", "informational", "Redirects checked."
        )
        redirect["final_url"] = "https://destination.example/login"
        clean = main._scan_check("Google Safe Browsing", "completed", "clean", "No match.")
        threat = main._scan_check("Google Safe Browsing", "completed", "malicious", "Phishing match.")
        not_data = main._scan_check("not used", "not_configured", "unknown", "Not configured.")

        with patch.dict("os.environ", {
            "DNS_GOOGLE_SAFE_BROWSING_API_KEY": "google-key",
            "DNS_VIRUSTOTAL_API_KEY": "",
            "DNS_URLHAUS_AUTH_KEY": "",
        }):
            with patch("main._resolve_website_host", return_value=main._scan_check(
                "DNS resolution", "completed", "informational", "Resolved."
            )):
                with patch("main._diagnose_redirects", return_value=redirect):
                    with patch("main._diagnose_google_safe_browsing", side_effect=[clean, threat]) as google_check:
                        with patch("main._diagnose_virustotal", return_value=not_data):
                            with patch("main._diagnose_urlhaus", return_value=not_data):
                                with patch("main.analyze_domain", return_value={
                                    "risk_score": 0,
                                    "risk_level": "LOW RISK",
                                    "reasons": [],
                                }):
                                    result = main.scan_website("https://example.com/")

        self.assertEqual(result["classification"], "MALICIOUS")
        self.assertEqual(result["final_domain"], "destination.example")
        self.assertEqual(google_check.call_count, 2)
        self.assertTrue(any(
            check["check"] == "Google Safe Browsing (redirect destination)"
            for check in result["checks"]
        ))

    def test_temporary_network_error_is_retried_only_within_bound(self):
        response = Mock(status_code=200)
        with patch("main.requests.request", side_effect=[main.requests.Timeout(), response]) as request:
            with patch("main.time.sleep"):
                returned_response, retries = main._request_with_retry("GET", "https://api.example/")
        self.assertIs(returned_response, response)
        self.assertEqual(retries, 1)
        self.assertEqual(request.call_count, 2)

    def test_rate_limit_is_retried_with_bounded_retry_after(self):
        limited = Mock(status_code=429, headers={"Retry-After": "0.5"})
        successful = Mock(status_code=200, headers={})
        with patch("main.requests.request", side_effect=[limited, successful]) as request:
            with patch("main.time.sleep") as sleep:
                response, retries = main._request_with_retry("GET", "https://api.example/")
        self.assertIs(response, successful)
        self.assertEqual(retries, 1)
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(0.5)
        limited.close.assert_called_once()

    def test_rate_limit_respects_long_retry_after_without_retrying_early(self):
        limited = Mock(status_code=429, headers={"Retry-After": "30"})
        with patch("main.requests.request", return_value=limited) as request:
            with patch("main.time.sleep") as sleep:
                response, retries = main._request_with_retry("GET", "https://api.example/")
        self.assertIs(response, limited)
        self.assertEqual(retries, 0)
        request.assert_called_once()
        sleep.assert_not_called()

    def test_http_timeout_status_is_retried(self):
        timed_out = Mock(status_code=408, headers={})
        successful = Mock(status_code=200, headers={})
        with patch("main.requests.request", side_effect=[timed_out, successful]) as request:
            with patch("main.time.sleep"):
                response, retries = main._request_with_retry("GET", "https://api.example/")
        self.assertIs(response, successful)
        self.assertEqual(retries, 1)
        request.assert_called_with("GET", "https://api.example/")
        timed_out.close.assert_called_once()

    def test_temporary_network_errors_stop_after_retry_limit(self):
        with patch("main.requests.request", side_effect=main.requests.Timeout()) as request:
            with patch("main.time.sleep"):
                with self.assertRaises(main.BoundedRequestError) as error:
                    main._request_with_retry("GET", "https://api.example/")
        self.assertEqual(error.exception.retries, main.MAX_REPUTATION_RETRIES)
        self.assertEqual(request.call_count, main.MAX_REPUTATION_RETRIES + 1)

    def test_dns_timeout_is_retried_with_a_bounded_attempt_count(self):
        with patch("main._bounded_getaddrinfo", side_effect=TimeoutError("lookup timed out")) as lookup:
            with patch("main.time.sleep"):
                check = main._resolve_website_host("example.com")
        self.assertEqual(check["status"], "failed")
        self.assertEqual(check["retries"], main.MAX_REPUTATION_RETRIES)
        self.assertEqual(lookup.call_count, main.MAX_REPUTATION_RETRIES + 1)

    def test_google_safe_browsing_match_is_reported_as_malicious_evidence(self):
        response = Mock(status_code=200)
        response.json.return_value = {
            "matches": [{"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM"}]
        }
        with patch.dict("os.environ", {"DNS_GOOGLE_SAFE_BROWSING_API_KEY": "test-key"}):
            with patch("main._request_with_retry", return_value=(response, 0)):
                check = main._diagnose_google_safe_browsing("https://example.com/login")
        self.assertEqual(check["verdict"], "malicious")
        self.assertIn("SOCIAL_ENGINEERING", check["evidence"][0])

    def test_virustotal_not_found_is_no_data_not_clean(self):
        response = Mock(status_code=404)
        with patch.dict("os.environ", {"DNS_VIRUSTOTAL_API_KEY": "test-key"}):
            with patch("main._request_with_retry", return_value=(response, 0)):
                check = main._diagnose_virustotal("example.com")
        self.assertEqual(check["status"], "no_data")
        self.assertEqual(check["verdict"], "unknown")

    def test_virustotal_zero_engine_results_are_no_data_not_clean(self):
        response = Mock(status_code=200)
        response.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
            }}}
        }
        with patch.dict("os.environ", {"DNS_VIRUSTOTAL_API_KEY": "test-key"}):
            with patch("main._request_with_retry", return_value=(response, 0)):
                check = main._diagnose_virustotal("example.com")
        self.assertEqual(check["status"], "no_data")
        self.assertEqual(check["verdict"], "unknown")

    def test_urlhaus_listing_is_malicious_evidence(self):
        response = Mock(status_code=200)
        response.json.return_value = {
            "query_status": "ok",
            "urls": [{"url": "https://example.com/payload.exe"}],
        }
        with patch.dict("os.environ", {"DNS_URLHAUS_AUTH_KEY": "test-key"}):
            with patch("main._request_with_retry", return_value=(response, 0)):
                check = main._diagnose_urlhaus("example.com")
        self.assertEqual(check["verdict"], "malicious")
        self.assertIn("payload.exe", check["evidence"][0])

    def test_entropy_alone_does_not_mark_domain_high_risk(self):
        with patch("main._virustotal_reputation", return_value={"available": False, "reason": "not configured"}):
            result = main.analyze_domain("x7v9q2m8k4p6b3n5.ru")
        self.assertLess(result["risk_score"], 30)
        self.assertNotEqual(result["classification"], "HIGH RISK")

    def test_behavioral_combination_reports_heuristic_anomaly(self):
        label = "a9f4d8c2b7e1f6a3d9c5b8e2"
        with patch("main._virustotal_reputation", return_value={"available": False, "reason": "not configured"}):
            result = main.analyze_domain(f"{label}.example.com", query_frequency=30, unique_subdomains=20)
        self.assertTrue(result["anomaly"])
        self.assertTrue(any("not proof of tunneling" in reason for reason in result["reasons"]))

    def test_threat_intelligence_match_is_high_risk(self):
        reputation = {"available": True, "malicious": 3, "suspicious": 0, "source": "VirusTotal"}
        with patch("main._virustotal_reputation", return_value=reputation):
            result = main.analyze_domain("example.com")
        self.assertEqual(result["risk_score"], 90)
        self.assertEqual(result["risk_level"], "HIGH RISK")
        self.assertEqual(result["classification"], "MALICIOUS")
        self.assertTrue(any("VirusTotal reported" in reason for reason in result["reasons"]))

    def test_suspicious_reputation_is_malicious_but_not_confirmed_malware(self):
        reputation = {"available": True, "malicious": 0, "suspicious": 1, "source": "VirusTotal"}
        with patch("main._virustotal_reputation", return_value=reputation):
            result = main.analyze_domain("example.com")
        self.assertEqual(result["classification"], "MALICIOUS")
        self.assertEqual(result["risk_level"], "SUSPICIOUS")
        self.assertTrue(any("Possible phishing or suspicious website" in reason for reason in result["reasons"]))
        self.assertFalse(any("Confirmed malicious indicator" in reason for reason in result["reasons"]))

    def test_strong_heuristic_finding_is_malicious_when_reputation_is_unavailable(self):
        label = "a9f4d8c2b7e1f6a3d9c5b8e2a7f4d1c8b6e3"
        with patch("main._virustotal_reputation", return_value={"available": False, "reason": "service unavailable"}):
            result = main.analyze_domain(f"{label}.one.two.three.four.example.com")
        self.assertGreaterEqual(result["risk_score"], 30)
        self.assertEqual(result["classification"], "MALICIOUS")
        self.assertTrue(any("Suspicious domain indicators crossed" in reason for reason in result["reasons"]))

    def test_common_multi_label_suffix_keeps_registered_domain(self):
        result = main.parse_domain_components("api.example.co.uk")
        self.assertEqual(result["sld"], "example")
        self.assertEqual(result["tld"], "co.uk")
        self.assertEqual(result["subdomain"], "api")

    def test_website_target_extracts_hostname_and_ignores_page_path(self):
        self.assertEqual(
            main.normalize_website_target("https://Sub.Example.com:8443/login?next=account"),
            "sub.example.com",
        )

    def test_website_target_accepts_ip_address_and_idn(self):
        self.assertEqual(main.normalize_website_target("192.0.2.10"), "192.0.2.10")
        self.assertEqual(main.normalize_website_target("https://[2001:db8::1]/"), "2001:db8::1")
        self.assertEqual(main.normalize_website_target("https://bücher.example"), "xn--bcher-kva.example")

    def test_website_target_rejects_unsupported_or_malformed_urls(self):
        for value in ("", "ftp://example.com", "https://user:secret@example.com", "https://bad host/"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    main.normalize_website_target(value)

    def test_ip_reputation_uses_virustotal_ip_endpoint(self):
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0}}}
        }
        with patch.dict("os.environ", {"DNS_VIRUSTOTAL_API_KEY": "test-key"}):
            with patch("main.requests.get", return_value=response) as request:
                result = main._virustotal_reputation("192.0.2.10")

        self.assertEqual(result["malicious"], 1)
        self.assertIn("/ip_addresses/192.0.2.10", request.call_args.args[0])


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.previous_path = main.DB_PATH
        main.DB_PATH = Path(self.temp_dir.name) / "test.db"
        self.assertEqual(main.init_db(), 0)

    def tearDown(self):
        main.DB_PATH = self.previous_path
        self.temp_dir.cleanup()

    def test_fresh_database_is_empty_and_event_key_deduplicates(self):
        self.assertEqual(main.get_dashboard_stats()["total_queries"], 0)
        values = {
            "timestamp": "2026-10-01T12:00:00.000+00:00",
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.1",
            "domain": "example.com",
            "query_type": "A",
            "risk_score": 0,
            "status": "SAFE",
            "reasons": ["No malicious indicators."],
            "anomaly": False,
            "event_key": "captured-packet-1",
        }
        self.assertIsNotNone(main.record_observation(**values))
        self.assertIsNone(main.record_observation(**values))
        self.assertEqual(main.get_dashboard_stats()["total_queries"], 1)
        profile = main.get_domain_profile("example.com")
        self.assertEqual(profile["query_count"], 1)
        self.assertEqual(profile["query_types"], ["A"])
        self.assertEqual(main.get_queries(domain_filter="example.com")[0]["domain"], "example.com")

    def test_clear_removes_observations(self):
        self.assertEqual(main.clear_observations(), 0)
        self.assertEqual(main.get_dashboard_stats()["total_queries"], 0)

    def test_dashboard_counts_only_safe_and_malicious_classifications(self):
        for index, (domain, status) in enumerate(
            (("safe.example", "SAFE"), ("bad.example", "MALICIOUS"), ("unknown.example", "UNKNOWN"))
        ):
            main.record_observation(
                timestamp=f"2026-10-01T12:00:0{index}.000+00:00",
                source_ip="192.0.2.10",
                destination_ip="192.0.2.1",
                domain=domain,
                query_type="A",
                risk_score=0,
                status=status,
                reasons=["Test evidence."],
                anomaly=False,
                event_key=f"classification-{index}",
            )

        stats = main.get_dashboard_stats()
        self.assertEqual(stats["safe_domains"], 2)
        self.assertEqual(stats["malicious_domains"], 1)
        self.assertNotIn("unknown_domains", stats)
        events = main.get_queries()
        legacy_unknown = next(event for event in events if event["domain"] == "unknown.example")
        self.assertEqual(legacy_unknown["status"], "SAFE")
        self.assertEqual(legacy_unknown["verification_status"], "LIMITED")

    def test_event_table_has_unique_display_columns_with_verification(self):
        event = {
            "timestamp": "2026-10-18T12:00:00.000+00:00",
            "domain": "example.com",
            "query_type": "A",
            "status": "SAFE",
            "verification_status": "LIMITED",
            "risk_score": 0,
            "risk_reasons": "Verification incomplete.",
        }
        with patch("main.st.dataframe") as dataframe:
            main.event_table([event])

        rendered_frame = dataframe.call_args.args[0]
        self.assertEqual(
            list(rendered_frame.columns),
            ["Time", "Domain", "Type", "Status", "Result", "Verification", "Risk score", "Detection reason"],
        )
        self.assertEqual(len(rendered_frame.columns), len(set(rendered_frame.columns)))
        self.assertEqual(rendered_frame.loc[0, "Verification"], "Limited")
        self.assertEqual(rendered_frame.loc[0, "Result"], "NO KNOWN THREATS DETECTED")

    def test_old_statuses_are_normalized_and_unverified_safe_is_limited(self):
        values = {
            "timestamp": "2026-10-01T12:00:00.000+00:00",
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.1",
            "domain": "example.com",
            "query_type": "A",
            "risk_score": 0,
            "status": "SAFE",
            "reasons": ["Reputation unavailable."],
            "anomaly": False,
            "event_key": "legacy-status",
        }
        main.record_observation(**values)
        with main.get_db_connection() as connection:
            connection.execute("UPDATE dns_queries SET status = 'HIGH RISK'")

        main.init_db()

        [event] = main.get_queries()
        self.assertEqual(event["status"], "MALICIOUS")

        with main.get_db_connection() as connection:
            connection.execute("UPDATE dns_queries SET status = 'SAFE', risk_reasons = '[]'")
        main.init_db()
        [event] = main.get_queries()
        self.assertEqual(event["status"], "SAFE")
        self.assertEqual(event["verification_status"], "LIMITED")

    def test_website_scan_history_persists_verification_and_raw_check_evidence(self):
        result = {
            "domain": "example.com",
            "final_domain": "redirect.example.com",
            "classification": "SAFE",
            "verification_status": "LIMITED",
            "status_message": "NO KNOWN THREATS DETECTED",
            "reason": "VirusTotal did not return a report.",
            "risk_score": 0,
            "checks": [{"check": "VirusTotal", "status": "no_data", "summary": "No report."}],
            "available_evidence": [],
            "failed_checks": ["VirusTotal: No report."],
            "conflicting_evidence": True,
            "recommended_action": "Rescan later.",
        }

        main.record_website_scan(result)
        [saved] = main.get_website_scans()

        self.assertEqual(saved["classification"], "SAFE")
        self.assertEqual(saved["verification_status"], "LIMITED")
        self.assertEqual(saved["checks"], result["checks"])
        self.assertEqual(saved["failed_checks"], result["failed_checks"])
        self.assertTrue(saved["conflicting_evidence"])

    def test_user_passwords_are_hashed_and_authentication_is_case_insensitive(self):
        main.create_user("Analyst_1", "long-enough-password")

        self.assertTrue(main.authenticate_user("analyst_1", "long-enough-password"))
        self.assertFalse(main.authenticate_user("Analyst_1", "wrong-password"))
        self.assertFalse(main.authenticate_user("unknown", "long-enough-password"))
        with self.assertRaisesRegex(ValueError, "already registered"):
            main.create_user("analyst_1", "another-long-password")
        with self.assertRaisesRegex(ValueError, "3-32 characters"):
            main.create_user("ab", "long-enough-password")
        with self.assertRaisesRegex(ValueError, "8 and 128 characters"):
            main.create_user("analyst_2", "short")

    def test_captured_query_and_response_are_correlated(self):
        sensor = main.DnsRealtimeMonitor()
        query = (
            IP(src="192.0.2.10", dst="192.0.2.1")
            / UDP(sport=53000, dport=53)
            / DNS(id=321, qd=DNSQR(qname="example.com", qtype="A"))
        )
        query.time = 1_800_000_000.0
        response = (
            IP(src="192.0.2.1", dst="192.0.2.10")
            / UDP(sport=53, dport=53000)
            / DNS(
                id=321,
                qr=1,
                qd=DNSQR(qname="example.com", qtype="A"),
                ancount=1,
                an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34"),
            )
        )
        response.time = query.time + 0.02

        with patch("main._virustotal_reputation", return_value={"available": False, "reason": "not configured"}):
            sensor._handle_packet(query)
            sensor._handle_packet(response)

        [event] = main.get_queries()
        self.assertEqual(event["domain"], "example.com")
        self.assertEqual(event["query_type"], "A")
        self.assertIn("93.184.216.34", event["response"])
        self.assertEqual(event["observation_source"], "local_packet_capture")


if __name__ == "__main__":
    unittest.main()
