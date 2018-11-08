from exercise import HttpMonitor
import unittest
from exercise_state import *

class TestAlertLogic(unittest.TestCase):

    def test_on_threshold(self):
        """
        Test HTTP request rate equals to the threshold
        """
        state = NormalState() #Normal state
        request_count = 101 #mock request count excceding by 1%
    
        _alert_history = [] #Store all history alerts, store up to max_alert_entry
        _average_baseline = 100 #baseline
        _average_threshold = 1 #exceeding 1%
        exceed = HttpMonitor.process_alert(state, request_count, _average_threshold, _average_baseline, _alert_history)

        #Assert expected values
        self.assertEqual(exceed, 1)
        self.assertEqual(len(_alert_history), 0)
        self.assertTrue(state.check_state(NormalState))

    def test_over_threshold(self):
        '''
        Test HTTP request rate exceeds threshold by 2%
        '''
        state = NormalState() #Normal state
        request_count = 102 #mock request count excceding by 2%
        _alert_history = [] #Store all history alerts, store up to max_alert_entry
        _average_baseline = 100 #baseline
        _average_threshold = 1 #exceeding 1%
        exceed = HttpMonitor.process_alert(state, request_count, _average_threshold, _average_baseline, _alert_history)

        #Assert expected values
        self.assertEqual(exceed, 2)
        self.assertEqual(len(_alert_history), 1)
        self.assertTrue(state.check_state(AlertState))       

    def test_alert_transaction(self):
        '''
        Test alert state transition: enforce_alert->enforce_alert->enforce_dismiss->enforce_normal
        '''
        state = AlertState() #Set Alert state
        request_count = 103 #mock request count excceding by 3%
        _alert_history = [] #Store all history alerts, store up to max_alert_entry
        _average_baseline = 100 #baseline
        _average_threshold = 1 #exceeding 1%
        exceed = HttpMonitor.process_alert(state, request_count, _average_threshold, _average_baseline, _alert_history)

        #Assert expected values
        self.assertEqual(exceed, 3)
        self.assertEqual(len(_alert_history), 1)
        self.assertTrue(state.check_state(AlertState)) 

        request_count = 99 #mock request count below threshold, 1st time
        exceed = HttpMonitor.process_alert(state, request_count, _average_threshold, _average_baseline, _alert_history)

        #Assert expected values
        self.assertLess(exceed, 0)
        self.assertEqual(len(_alert_history), 1)
        self.assertTrue(state.check_state(DismissState)) #Check Dismissal state

        request_count = 99 #mock request count below threshold, 2nd time
        exceed = HttpMonitor.process_alert(state, request_count, _average_threshold, _average_baseline, _alert_history)

        #Assert expected values
        self.assertLess(exceed, 0)
        self.assertEqual(len(_alert_history), 1)
        self.assertTrue(state.check_state(NormalState)) 

    def test_state_transition(self):
        '''
        Test a state transition flow
        '''
        state = LearnState() #Start with learn_baseline
        self.assertEqual(state.name, 'learn_baseline')
        state.switch(NormalState)
        self.assertEqual(state.name, 'enforce_normal')
        self.assertTrue(isinstance(state,NormalState))
        with self.assertRaises(Exception): state.switch(DismissState) #FAILED: enforce_normal -> enforce_dismiss
        self.assertTrue(isinstance(state,NormalState)) #Verify state stay normal
        state.switch(AlertState) #OK: enforce_normal -> enforce_alert
        self.assertTrue(isinstance(state,AlertState)) #Verify state set to enforce_alert
        state.switch(AlertState) #OK: stay enforce_alert
        with self.assertRaises(Exception): state.switch(NormalState) #FAILED: enforce_alert -> enforce_normal
        state.switch(DismissState) #OK: enforce_alert -> enforce_dismiss

if __name__ == '__main__':
    unittest.main()