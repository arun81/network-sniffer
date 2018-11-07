import exercise
import unittest

class TestAlertLogic(unittest.TestCase):

    def test_on_threshold(self):
        """
        Test HTTP request rate equals to the threshold
        """
        _status_map = {
            'http_request_count':101, #mock request count excceding by 1%
            'running_mode':'enforce_normal' #Normal state
        } #Map tracking current status
        _alert_history = [] #Store all history alerts, store up to max_alert_entry
        _average_baseline = 100 #baseline
        _average_threshold = 1 #exceeding 1%
        exceed = exercise.process_alert(_status_map, _average_threshold, _average_baseline, _alert_history)

        self.assertEqual(exceed, 1)
        self.assertEqual(len(_alert_history), 0)
        self.assertEqual(_status_map['running_mode'], 'enforce_normal')

    def test_over_threshold(self):
        '''
        Test HTTP request rate exceeds threshold by 2%
        '''
        _status_map = {
            'http_request_count':102, #mock request count excceding by 2%
            'running_mode':'enforce_normal' #Normal state
        } #Map tracking current status
        _alert_history = [] #Store all history alerts, store up to max_alert_entry
        _average_baseline = 100 #baseline
        _average_threshold = 1 #exceeding 1%
        exceed = exercise.process_alert(_status_map, _average_threshold, _average_baseline, _alert_history)

        self.assertEqual(exceed, 2)
        self.assertEqual(len(_alert_history), 1)
        self.assertEqual(_status_map['running_mode'], 'enforce_alert')       

    def test_alert_transaction(self):
        '''
        Test alert state transition: enforce_alert->enforce_alert->enforce_dismiss->enforce_normal
        '''
        _status_map = {
            'http_request_count':103, #mock request count by 3%
            'running_mode':'enforce_alert' #Alert state
        } #Map tracking current status
        _alert_history = [] #Store all history alerts, store up to max_alert_entry
        _average_baseline = 100 #baseline
        _average_threshold = 1 #exceeding 1%
        exceed = exercise.process_alert(_status_map, _average_threshold, _average_baseline, _alert_history)

        self.assertEqual(exceed, 3)
        self.assertEqual(len(_alert_history), 1)
        self.assertEqual(_status_map['running_mode'], 'enforce_alert') 

        _status_map['http_request_count'] = 99 #mock request count below threshold
        exceed = exercise.process_alert(_status_map, _average_threshold, _average_baseline, _alert_history)
        self.assertLess(exceed, 0)
        self.assertEqual(len(_alert_history), 1)
        self.assertEqual(_status_map['running_mode'], 'enforce_dismiss') 

        _status_map['http_request_count'] = 99 #mock request count below threshold
        exceed = exercise.process_alert(_status_map, _average_threshold, _average_baseline, _alert_history)
        self.assertLess(exceed, 0)
        self.assertEqual(len(_alert_history), 1)
        self.assertEqual(_status_map['running_mode'], 'enforce_normal') 
  
if __name__ == '__main__':
    unittest.main()