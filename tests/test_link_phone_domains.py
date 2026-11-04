import unittest

from app import link_phone_domains


class LinkPhoneDomainsTests(unittest.TestCase):
    def test_app_context_matches_whatever_its_case(self):
        profiles = {"detectedApps": [{"bundleID": "com.example.maps", "name": "Maps", "domains": ["api.maps.example"]}]}
        classified = {"tiles.other.example": {"appContexts": ["Maps"]}, "x.other2.example": {"appContexts": ["\u200eCOM.EXAMPLE.MAPS"]}}
        result = link_phone_domains(profiles, classified, set())
        self.assertEqual(result["detectedApps"][0]["inferredDomains"], ["tiles.other.example", "x.other2.example"])

    def test_unknown_context_is_ignored(self):
        profiles = {"detectedApps": [{"bundleID": "com.example.maps", "name": "Maps", "domains": []}]}
        result = link_phone_domains(profiles, {"a.example": {"appContexts": ["Other"]}}, set())
        self.assertNotIn("inferredDomains", result["detectedApps"][0])


if __name__ == "__main__":
    unittest.main()
