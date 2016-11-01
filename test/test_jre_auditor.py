
import sys

sys.path.append("../src/")

from jre_auditor import JREAuditor

import unittest




class TestJREAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = JREAuditor()
    def test_basic(self):
        self.assertTrue(True)

    def test_get_deployment_path(self):
        result = self.auditor.get_deployment_path(direc="./", filename="test_javaconfig1.conf")
        self.assertEqual(result, 1)
        result = self.auditor.get_deployment_path(direc="./", filename="test_javaconfig2.conf")
        self.assertEqual(result, 1)
        result = self.auditor.get_deployment_path(direc="./", filename="test_javaconfig3.conf")
        self.assertEqual(result, 0)
        
    def test_get_properties_path(self):
        result = self.auditor.get_properties_path(direc="./", filename="test_javaconfig1.conf")
        self.assertEqual(result, 1)
        result = self.auditor.get_properties_path(direc="./", filename="test_javaconfig2.conf")
        self.assertEqual(result, 1)
        result = self.auditor.get_properties_path(direc="./", filename="test_javaconfig3.conf")
        self.assertEqual(result, 0)


        
if __name__ == "__main__":
    print(sys.path)
    unittest.main()



