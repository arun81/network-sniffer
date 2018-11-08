"""
Define State classes and State transition table of the HTTP monitoring program
"""
class AbstractState(object):
    """
    Abstract base class of tracking state of monitoring
    """
    name = None
    allowed = []

    def check_state(self, type):
        return isinstance(self, type)

    def switch(self, state):
        if state.name in self.allowed:
            self.__class__ = state
        else:
            raise Exception("Unsupported State transation: "+self.name+' -> '+state.name)

class LearnState(AbstractState):
    name = 'learn_baseline'
    allowed = ['learn_baseline', 'enforce_normal', 'enforce_alert']

class NormalState(AbstractState):
    name = 'enforce_normal'
    allowed = ['enforce_normal', 'enforce_alert']

class AlertState(AbstractState):
    name = 'enforce_alert'
    allowed = ['enforce_alert', 'enforce_dismiss']

class DismissState(AbstractState):
    name = 'enforce_dismiss'
    allowed = ['enforce_alert', 'enforce_normal']
