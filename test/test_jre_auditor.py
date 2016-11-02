
import sys

sys.path.append("../src/")

import unittest
from jre_auditor import JREAuditor




class TestJREAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = JREAuditor()

    def test_get_deployment_path(self):
        result = self.auditor.get_deployment_path(direc="./", filename="deployment1.config")
        self.assertEqual(result, 1)
        result = self.auditor.get_deployment_path(direc="./", filename="deployment2.config")
        self.assertEqual(result, 1)
        result = self.auditor.get_deployment_path(direc="./", filename="deployment3.config")
        self.assertEqual(result, 0)
        
    def test_get_properties_path(self):
        result = self.auditor.get_properties_path(direc="./", filename="deployment1.properties")
        self.assertEqual(result, 1)
        result = self.auditor.get_properties_path(direc="./", filename="deployment2.properties")
        self.assertEqual(result, 1)
        result = self.auditor.get_properties_path(direc="./", filename="deployment3.properties")
        self.assertEqual(result, 0)

    def test_permission_dialog_disabled(self):
        self.auditor.get_deployment_path(direc="./", filename="deployment1.config")
        self.auditor.get_properties_path(direc="./", filename="deployment1.properties")
        result = self.auditor.permission_dialog_disabled()
        self.assertTrue(result)
        self.auditor.get_deployment_path(direc="./", filename="deployment2.config")
        self.auditor.get_properties_path(direc="./", filename="deployment2.properties")
        result = self.auditor.permission_dialog_disabled()
        self.assertFalse(result)

    def test_permission_dialog_locked(self):
        self.auditor.get_deployment_path(direc="./", filename="deployment1.config")
        self.auditor.get_properties_path(direc="./", filename="deployment1.properties")
        result = self.auditor.permission_dialog_locked()
        self.assertTrue(result)
        self.auditor.get_deployment_path(direc="./", filename="deployment2.config")
        self.auditor.get_properties_path(direc="./", filename="deployment2.properties")
        result = self.auditor.permission_dialog_locked()
        self.assertFalse(result)

    def test_publisher_revocation_enabled(self):
        self.auditor.get_deployment_path(direc="./", filename="deployment1.config")
        self.auditor.get_properties_path(direc="./", filename="deployment1.properties")
        result = self.auditor.publisher_revocation_enabled()
        self.assertTrue(result)
        self.auditor.get_deployment_path(direc="./", filename="deployment2.config")
        self.auditor.get_properties_path(direc="./", filename="deployment2.properties")
        result = self.auditor.publisher_revocation_enabled()
        self.assertFalse(result)
    
    def test_publisher_revocation_locked(self):
        self.auditor.get_deployment_path(direc="./", filename="deployment1.config")
        self.auditor.get_properties_path(direc="./", filename="deployment1.properties")
        result = self.auditor.publisher_revocation_locked()
        self.assertTrue(result)
        self.auditor.get_deployment_path(direc="./", filename="deployment2.config")
        self.auditor.get_properties_path(direc="./", filename="deployment2.properties")
        result = self.auditor.publisher_revocation_locked()
        self.assertFalse(result)

    def test_certificate_validation_enabled(self):
        self.auditor.get_deployment_path(direc="./", filename="deployment1.config")
        self.auditor.get_properties_path(direc="./", filename="deployment1.properties")
        result = self.auditor.certificate_validation_enabled()
        self.assertTrue(result)
        self.auditor.get_deployment_path(direc="./", filename="deployment2.config")
        self.auditor.get_properties_path(direc="./", filename="deployment2.properties")
        result = self.auditor.certificate_validation_enabled()
        self.assertFalse(result)
    
    def test_certificate_validation_locked(self):
        self.auditor.get_deployment_path(direc="./", filename="deployment1.config")
        self.auditor.get_properties_path(direc="./", filename="deployment1.properties")
        result = self.auditor.certificate_validation_locked()
        self.assertTrue(result)
        self.auditor.get_deployment_path(direc="./", filename="deployment2.config")
        self.auditor.get_properties_path(direc="./", filename="deployment2.properties")
        result = self.auditor.certificate_validation_locked()
        self.assertFalse(result)

    def test_config_keys_set(self):
        self.auditor.get_deployment_path(direc="./", filename="deployment1.config")
        self.auditor.get_properties_path(direc="./", filename="deployment1.properties")
        result = self.auditor.config_keys_set()
        self.assertTrue(result)
        self.auditor.get_deployment_path(direc="./", filename="deployment2.config")
        self.auditor.get_properties_path(direc="./", filename="deployment2.properties")
        result = self.auditor.config_keys_set()
        self.assertFalse(result)

if __name__ == "__main__":
    print(sys.path)
    unittest.main()



