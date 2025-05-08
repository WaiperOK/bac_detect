import unittest
from backdoor_detector.backdoor_detector import BackdoorDetector

class TestBackdoorDetector(unittest.TestCase):
    def test_python_analysis(self):
        detector = BackdoorDetector()
        issues = detector.analyze_python_file('examples/suspicious.py')
        self.assertGreater(len(issues), 0, 'Should detect issues in suspicious.py')

if __name__ == '__main__':
    unittest.main()
