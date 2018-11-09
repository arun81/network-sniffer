try:
    from scapy.all import sniff
    from scapy import error
    import scapy_http.http
    import requests
    import os
    import platform
    import time
    from termcolor import colored, cprint
    import threading
    import argparse
    import sys
    import exercise_config #Store static settings
    from exercise_statistic import *
    from exercise_state import *
except ImportError as err:
    sys.stderr.write("ERROR: found depedancies not yet installed, run 'pip install -r requirements.txt'\n\r"+str(err)+'\n\r')
    exit(1)

class HttpMonitor(object):

    def _callback(self,packet):
        """
        Callback function invoked by tshark to notify upon new HTTP transaction arrival.

        :param packet: packet object received from tshark
        """
        response = packet.getlayer(scapy_http.http.HTTPResponse)
        request = packet.getlayer(scapy_http.http.HTTPRequest)

        #Count HTTP request
        if request:
            self.request_count += 1

        #Skip running Plug-ins during learning mode    
        if self.state.check_state(LearnState):
            return 

        #Calling all StatisticVisitors Plug-ins
        for plugin in self.statistic_plugins:
            plugin.accept_packet(packet, request, response)

    def _sniff(self):
        """
        Start calling sniff block mode in a thread, wait until exit_event set to exit 
        """
        try:
            sniff(iface=self.interface,
                promisc=False,
                filter='tcp and port '+self.filter,
                lfilter=lambda x: x.haslayer(scapy_http.http.HTTPRequest) or x.haslayer(scapy_http.http.HTTPResponse),
                prn=self._callback,
                count=0,
                stop_filter=lambda p: self.exit_event.is_set()
            )
        except OSError as err:
            sys.stderr.write ('Sniffer error: '+str(err)+'\n\r') #Likely triggered by "No such device"
        except:
            sys.stderr.write ('Unexpected Sniffer error: '+ sys.exc_info()[0]+'\n\r')

    def run(self):
        """
        Main program to process sniffed HTTP traffic and present info to the console.

        ##Todo:
        -Add other useful statistics such as:
            -max alert duration
            -average alert duration
        """

        #Launch new thread for sniffing
        sniff_thread = threading.Thread(target=self._sniff)
        sniff_thread.start()
        time.sleep(1)

        #Update dashboard as long as sniffing up working
        while sniff_thread.is_alive():
          try:
            time.sleep(self.config.timeout)

            #Learning mode...
            if self.state.check_state(LearnState):
                self.average_learning_countdown-=self.config.timeout
                if self.average_learning_countdown < 0:
                    self.average_learning_countdown = 0 #Int underflow protection
                #Calculate average baseline per <average_bucket_size>
                self.average_baseline = round(self.request_count*self.config.average_bucket_size/(self.config.average_learning_duration-self.average_learning_countdown))

                #Print learning status
                os.system('cls' if platform=='Windows' else 'clear')
                cprint ('<<<Learning mode>>>', 'white', 'on_grey')
                print ("Collected "+colored(str(self.request_count),'blue')+' HTTP request in '+str(self.config.average_learning_duration-self.average_learning_countdown)+'s')
                print ("Est. average rate: " + colored(str(self.average_baseline)+'/'+str(self.config.average_bucket_size)+'s', 'blue'))
                print (str(self.average_learning_countdown) + 's counting down...')
                #Prepare exiting learning
                if self.average_learning_countdown <= 0:
                    self.request_count = 0 #Reset HTTP request count
                    self.average_learning_countdown = self.config.average_learning_duration #Reset learning countdown for next learning
                    if self.average_baseline > 0: #Restart learning when baseline==0
                        self.state.switch(NormalState) #Set to enforcing mode after finishing learning
                    else:
                        continue #Skip during learning mode
                else:
                    continue #Skip during learning mode

            #Enforce mode...
            self.dashboard_bucket_countdown-=self.config.timeout
            self.average_bucket_countdown-=self.config.timeout

            #Update Alert status based on current request count
            if self.average_bucket_countdown <= 0:
                self.average_bucket_countdown = self.config.average_bucket_size #Reset average request countdown 
                self.process_alert(self.state, self.request_count, self.config.average_threshold, self.average_baseline, self.alert_history)
                self.request_count = 0 #Reset HTTP request count

            #Update dashboard info on screen
            if self.dashboard_bucket_countdown <= 0:
                self.dashboard_bucket_countdown = self.config.dashboard_bucket_size #Reset top-hits countdown
                #Clean up screen
                os.system('cls' if platform=='Windows' else 'clear')

                #Print baseline info
                print ('\n\r[INFO] Average baseline: '+colored(str(self.average_baseline)+'/'+str(self.config.average_bucket_size)+'s','blue')+', '+
                    'Alert threshold: '+colored(str(self.config.average_threshold)+'%','yellow')+', '+
                    'Current average: '+colored(str(self.request_count)+'/'+str(self.config.average_bucket_size)+'s','blue')+', '+
                    'Next Alert check in '+colored(str(self.average_bucket_countdown)+'s...','blue'))

                #Print Alert status
                if len(self.alert_history) > 0 and self.state.check_state(NormalState)==False:
                    if self.state.check_state(AlertState):
                        cprint ('\n\r<<<Active Alert>>>','red')
                    elif self.state.check_state(DismissState):
                        cprint ('\n\r<<<Alert Dismissed>>>','green')
                    print("High traffic generated an alert - hits="+colored(str(self.alert_history[0][0]),'yellow')+", triggered at "+time.strftime('%H:%M:%S %Y/%m/%d', time.localtime(self.alert_history[0][1])))
                    
                #Trim Alert history
                while len(self.alert_history) > 0:
                    if time.time()-self.alert_history[len(self.alert_history)-1][1] > self.config.max_retention_length:
                        self.alert_history.pop()
                    else:
                        break
                #Print Alert history
                cprint ('\n\r<<<Alert History>>>', 'yellow', 'on_grey')
                for alert in self.alert_history:
                    print("hits "+colored(str(alert[0]),'yellow')+" at "+time.strftime('%H:%M:%S %Y/%m/%d', time.localtime(alert[1])))
                    
                #Print All StatisticVisitor Plug-ins
                for plugin in self.statistic_plugins:
                    plugin.print()

          except KeyboardInterrupt:
            self.exit_event.set()
            requests.get('http://www.bbc.com')
            sniff_thread.join()
            break

    @staticmethod
    def process_alert(_state, _request_count, _average_threshold, _average_baseline, _alert_history):
        """
        Calculate current rate against threshold, manage alert state transitioning when needed.

        :param _state: AbstractState object indicates the current running state
        :param _request_count: current request count
        :param _average_threshold: alerting threshold from configuration
        :param _average_baseline: baseline learned
        :param _alert_history: array holding the history of alerts in reverse order

        :return Delta in percentage between baseline rate and the current rate
        """
        average_delta = (_request_count-_average_baseline)*100/_average_baseline #Percentage of baseline delta
        if average_delta > _average_threshold: 
            _state.switch(AlertState) #Set alert to active
            _alert_history.insert(0, [_request_count, time.time()])
        else:
            if _state.check_state(AlertState): 
                _state.switch(DismissState) #Set enforce_alert -> enforce_dismiss
            else:
                _state.switch(NormalState)
        return average_delta

    def __init__(self, interface, filter):
        """
        Intialize member variables
        """
        #Fetch configurations
        self.config = exercise_config.Config
        self.interface = interface
        self.filter = filter

        #Run-time variables
        self.average_baseline = 0 #average HTTP request rate baseline per <average_bucket_size>
        self.average_bucket_countdown = self.config.average_bucket_size #countdown in sec when to refresh average request per <average_bucket_size>
        self.dashboard_bucket_countdown = self.config.dashboard_bucket_size #countdown in sec when to refresh top-hits list
        self.average_learning_countdown = self.config.average_learning_duration #countdown in sec when to stop learning average request baseline
        self.request_count = 0 #Tracking Http Request count
        self.state = LearnState() #Starts with learning states
        self.alert_history = [] #Stores all history alerts, aged data greater than <Config.max_retention_length> are periodically removed
        self.exit_event = threading.Event()

        #Include Plug-in classes to use
        self.statistic_plugins = [ #A list of statistic plug-ins currently available, aged data greater than <Config.max_retention_length> are periodically removed
            TopHitsBySection(self.config),           #Count by uniuqe Section
            TopHitsByHost(self.config),              #Count by unique Domain
            TopHitsUploadByHost(self.config),        #Request data volume by unique Domain
            TopHitsByUserAgent(self.config),         #Count by uniuqe User-Agent
            TopHitsByHttpMethod(self.config),        #Count by uniuqe Http Method
            TopHitsByStatusCode(self.config)         #Count by unique Status line
        ]

if __name__ == '__main__':
    #Parse out commandline arguments
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="This program monitors HTTP traffic, print information and reports alert.",
    )
    parser.add_argument("--interface", "-i", help="Which interface to sniff on.", default="eth0")
    parser.add_argument("--port", "-p", help="Which port to sniff on HTTP traffic.", default="80")
    args = parser.parse_args()
    
    #Create HttpMonitor with sniffing parameters
    monitor = HttpMonitor(args.interface, args.port)
    #start sniffing now...
    monitor.run()
