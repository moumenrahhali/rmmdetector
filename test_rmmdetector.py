"""Tests for rmmdetector.py bug fixes and core functionality."""

import csv
import json
import os
import sys
import tempfile
import unittest

# Ensure the module can be imported from the repo root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rmmdetector


class TestProcessCompanyURLHandling(unittest.TestCase):
    """Test URL normalisation in process_company."""

    def test_empty_url_skipped(self):
        result = rmmdetector.process_company('')
        self.assertEqual(result['Detected Software'], 'Not Detected')
        self.assertIn('skipped', result['Evidence'])

    def test_whitespace_only_url_skipped(self):
        result = rmmdetector.process_company('   ')
        self.assertEqual(result['Detected Software'], 'Not Detected')
        self.assertIn('skipped', result['Evidence'])

    def test_leading_whitespace_stripped(self):
        """URL with leading whitespace should not produce a malformed URL."""
        result = rmmdetector.process_company('  zendesk.com')
        # Should correctly detect Zendesk via domain match, not crash
        self.assertEqual(result['Detected Software'], 'Zendesk')

    def test_domain_detected(self):
        result = rmmdetector.process_company('zendesk.com')
        self.assertEqual(result['Detected Software'], 'Zendesk')
        self.assertEqual(result['Category'], 'Helpdesk/ITSM')


class TestArgumentValidation(unittest.TestCase):
    """Test CLI argument validation."""

    def test_negative_retries_rejected(self):
        """--retries with a negative value should cause a SystemExit."""
        sys.argv = ['rmmdetector.py', 'in.txt', 'out.csv', '--retries', '-1']
        with self.assertRaises(SystemExit):
            rmmdetector.main()

    def test_zero_threads_rejected(self):
        """--threads 0 should cause a SystemExit."""
        sys.argv = ['rmmdetector.py', 'in.txt', 'out.csv', '--threads', '0']
        with self.assertRaises(SystemExit):
            rmmdetector.main()


class TestCSVFieldnames(unittest.TestCase):
    """Test CSV input handling edge cases."""

    def test_empty_csv_shows_error(self):
        """An empty CSV file should not crash."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write('')
            tmppath = f.name

        try:
            sys.argv = ['rmmdetector.py', tmppath, '/dev/null']
            # main() should return (not crash) when fieldnames are None
            rmmdetector.main()
        except SystemExit:
            pass  # acceptable – argparse or the exit-code path
        finally:
            os.unlink(tmppath)


class TestDNSHelpers(unittest.TestCase):
    """Test DNS helper functions with invalid input."""

    def test_get_cname_invalid_host(self):
        """get_cname should return None for non-existent domains."""
        result = rmmdetector.get_cname('this-domain-does-not-exist-xyz123.invalid')
        self.assertIsNone(result)

    def test_get_txt_records_invalid_domain(self):
        """get_txt_records should return empty list for non-existent domains."""
        result = rmmdetector.get_txt_records('this-domain-does-not-exist-xyz123.invalid')
        self.assertEqual(result, [])


class TestCheckTextSignatures(unittest.TestCase):
    """Test HTML signature detection."""

    def test_zendesk_signature(self):
        vendor, reason = rmmdetector.check_text_signatures('<div class="zendesk-widget">')
        self.assertEqual(vendor, 'Zendesk')

    def test_no_match(self):
        vendor, reason = rmmdetector.check_text_signatures('<html><body>Hello</body></html>')
        self.assertIsNone(vendor)


class TestCheckDomainSignatures(unittest.TestCase):
    """Test domain pattern matching."""

    def test_zendesk_domain(self):
        vendor, reason = rmmdetector.check_domain_signatures('support.zendesk.com')
        self.assertEqual(vendor, 'Zendesk')

    def test_unknown_domain(self):
        vendor, reason = rmmdetector.check_domain_signatures('example.com')
        self.assertIsNone(vendor)


if __name__ == '__main__':
    unittest.main()
