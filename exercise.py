import pyshark
import urllib
import concurrent
import datetime
import os
import platform
import exercise_config #Store static settings
import time
from termcolor import colored, cprint

def sniff(capture):
    """
    Main program to process sniffed HTTP traffic and present info to the console.
    
    :param capture: tshark packet capture object for sniffing

    :raises All exceptions besides concurrent.futures.TimeoutError:

    ##Todo: 
    Add other useful statistics such as:
        -max alert duration
        -average alert duration
    """
    #Fetch static configurations
    config = exercise_config.Config

    #Run-time variables
    average_baseline = 0 #average HTTP request rate baseline per <average_bucket_size>
    average_bucket_countdown = config.average_bucket_size #countdown in sec when to refresh average request per <average_bucket_size>
    dashboard_bucket_countdown = config.dashboard_bucket_size #countdown in sec when to refresh top-hits list
    average_learning_countdown = config.average_learning_duration #countdown in sec when to stop learning average request baseline

    #Run-time data structures
    top_hits_by_section = {} #Map trakcing unique Section & count
    top_hits_by_domain = {} #Map tracking unique Host & count
    top_hits_by_useragent = {} #Map tracking unique User-Agent & count
    top_hits_by_method = {} #Map tracking unique HTTP Method & count
    top_hits_by_statuscode = {} #Map tracking unique HTTP Status code & count
    top_hits_by_req_vol_by_domain = {} #Map tracking unique Host & request volume
    status_map = {
        'http_request_count':0,
        'running_mode':'learn_baseline' #Other possible values: enforce_alert, enforce_dismiss, learn_baseline
    } #Map tracking current status
    alert_history = [] #Store all history alerts, store up to max_alert_entry

    def tshark_callback(packet):
        """
        Callback function invoked by tshark to notify upon new HTTP transaction arrival.

        :param packet: packet object received from tshark
        """
        #Count HTTP request
        if hasattr(packet.http, 'request'):
            status_map['http_request_count']+=1

        #Skip during learning mode    
        if status_map['running_mode'] == 'learn_baseline':
            return 

        if hasattr(packet.http, 'response'):
            #Collect Top hits response volume by Status code
            if hasattr(packet.http, 'response_code') and len(packet.http.response_code)>0:
                response_code = packet.http.response_code[:config.max_str_length] #Trucate overlong string
                if response_code in top_hits_by_statuscode:
                    top_hits_by_statuscode[response_code][0] += 1
                else:
                    top_hits_by_statuscode[response_code] = [1,0]
                top_hits_by_statuscode[response_code][1] = time.time()

        elif hasattr(packet.http, 'request'):
            #Collect Top hits by Host
            if hasattr(packet.http, 'host') and len(packet.http.host)>0:
                host = packet.http.host[:config.max_str_length] #Trucate overlong string
                #Collect Top hits request count by Host
                if host in top_hits_by_domain:
                    top_hits_by_domain[host][0] += 1
                else:
                    top_hits_by_domain[host] = [1,0]
                top_hits_by_domain[host][1] = time.time()

                #Collect Top hits request volume by Host
                if host in top_hits_by_req_vol_by_domain:
                    top_hits_by_req_vol_by_domain[host][0] += int(packet.length)
                else:
                    top_hits_by_req_vol_by_domain[host] = [int(packet.length),0]
                top_hits_by_req_vol_by_domain[host][1] = time.time()

            #Collect Top hits by User-Agent
            if hasattr(packet.http, 'user_agent') and len(packet.http.user_agent)>0:
                user_agent = packet.http.user_agent[:config.max_str_length] #Trucate overlong string
                if user_agent in top_hits_by_useragent:
                    top_hits_by_useragent[user_agent][0] += 1
                else:
                    top_hits_by_useragent[user_agent] = [1,0]
                top_hits_by_useragent[user_agent][1] = time.time()

            #Collect Top hits by HTTP Method
            if hasattr(packet.http, 'request_method') and len(packet.http.request_method)>0:
                request_method = packet.http.request_method[:config.max_str_length] #Trucate overlong string
                if request_method in top_hits_by_method:
                    top_hits_by_method[request_method][0] += 1
                else:
                    top_hits_by_method[request_method] = [1,0]
                top_hits_by_method[request_method][1] = time.time()

            #Collect Top hits by Section
            section_str = 'http://'+packet.http.host
            if hasattr(packet.http, 'request_uri') and len(packet.http.request_uri)>0:
                str_arr = urllib.parse.unquote(packet.http.request_uri).split('/') #Normalize URL decode path
                for string in str_arr: #Normalize multiple slash '/'
                    if len(string) > 0:
                        str_arr2 = string.split('?') #Remove request parameters
                        if len(str_arr2[0]) > 0:
                            section_str += '/'+str_arr2[0][:config.max_str_length] #Trim section to max length
                        break
            if section_str in top_hits_by_section:
                top_hits_by_section[section_str][0] += 1
            else:
                top_hits_by_section[section_str] = [1,0]
            top_hits_by_section[section_str][1] = time.time()

    def print_top_hits(title, hits):
        """
        Sort, print & trim Top N hits

        :param title: A short text description to be printed at top of the section
        :param hits: Dictionary object stores hits info in key, value pair
        """
        cprint('\n\r<<<Top Hits '+title+'>>>','white', 'on_grey')
        if len(hits) == 0: 
            return hits
        count = 0
        for key,value in sorted(hits.items(), key=lambda kv: (kv[1][0],kv[1][1]), reverse=True): #Sort by value and last timestamp
            print(key+': '+colored(str(value[0]),'blue')+' last seen: '+time.strftime('%H:%M:%S %Y/%m/%d', time.localtime(value[1])))   
            count+=1
            if count >= config.max_top_hits: #Limit top N hits to screen
                break
        #Trim hits and return
        trim_hits = sorted(hits.items(), key=lambda kv: (kv[1][1])) #Sort by last seen in asecdent
        while len(trim_hits) > 0:
            if time.time()-trim_hits[0][1][1] > config.max_retention_length:
                hits.pop(trim_hits[0][0]) #Remove aging item by key
                trim_hits.pop(0) #Sync sorted list
            else:
                break

    while True:
        try:
            capture.apply_on_packets(tshark_callback, timeout=config.timeout)
        except concurrent.futures.TimeoutError:
            pass

        #Learning mode...
        if status_map['running_mode'] == 'learn_baseline':
            average_learning_countdown-=config.timeout
            if average_learning_countdown < 0:
                average_learning_countdown = 0 #Int underflow protection
            #Calculate average baseline per <average_bucket_size>
            average_baseline = round(status_map['http_request_count']*config.average_bucket_size/(config.average_learning_duration-average_learning_countdown))

            #Print learning status
            os.system('cls' if platform=='Windows' else 'clear')
            cprint ('<<<Learning mode>>>', 'white', 'on_grey')
            print ("Collected "+colored(str(status_map['http_request_count']),'blue')+' HTTP request in '+str(config.average_learning_duration-average_learning_countdown)+'s')
            print ("Est. average rate: " + colored(str(average_baseline)+'/'+str(config.average_bucket_size)+'s', 'blue'))
            print (str(average_learning_countdown) + 's counting down...')
            #Prepare exiting learning
            if average_learning_countdown <= 0:
                status_map['http_request_count'] = 0 #Reset HTTP request count
                average_learning_countdown = config.average_learning_duration #Reset learning countdown for next learning
                if average_baseline > 0: #Restart learning when baseline==0
                    status_map['running_mode'] = 'enforce_normal' #Set to run enforcing mode
                else:
                    continue #Skip during learning mode
            else:
                continue #Skip during learning mode

        #Enforce mode...
        dashboard_bucket_countdown-=config.timeout
        average_bucket_countdown-=config.timeout

        #Update Alert status based on current request count
        if average_bucket_countdown <= 0:
            average_bucket_countdown = config.average_bucket_size #Reset average request countdown 
            process_alert(status_map, config.average_threshold, average_baseline, alert_history)

        #Update dashboard info on screen
        if dashboard_bucket_countdown <= 0:
            dashboard_bucket_countdown = config.dashboard_bucket_size #Reset top-hits countdown
            #Clean up screen
            os.system('cls' if platform=='Windows' else 'clear')

            #Print baseline info
            print ('\n\r[INFO] Average baseline: '+colored(str(average_baseline)+'/'+str(config.average_bucket_size)+'s','blue')+', Alert threshold: '+colored(str(config.average_threshold)+'%','yellow'))

            #Print Alert status
            if status_map['running_mode'] == 'enforce_alert':
                cprint ('\n\r<<<Alert Active>>>','red')
            elif status_map['running_mode'] == 'enforce_dismiss':
                cprint ('\n\r<<<Alert Dismissal>>>','green')

            #Trim Alert history
            while len(alert_history) > 0:
                if time.time()-alert_history[len(alert_history)-1][1] > config.max_retention_length:
                    alert_history.pop()
                else:
                    break
            #Print Alert history
            cprint ('\n\r<<<Alert History>>>', 'yellow', 'on_grey')
            for alert in alert_history:
                print("hits="+colored(str(alert[0]),'yellow')+", triggered at "+time.strftime('%H:%M:%S %Y/%m/%d', time.localtime(alert[1])))
                
            #Print Top hits
            print_top_hits('by Section', top_hits_by_section)
            print_top_hits('by Domain', top_hits_by_domain)
            print_top_hits('by User-Agent', top_hits_by_useragent)
            print_top_hits('by HTTP Method', top_hits_by_method)
            print_top_hits('by Status code', top_hits_by_statuscode)
            print_top_hits('Upload Volume by Domain', top_hits_by_req_vol_by_domain)

def process_alert(_status_map, _average_threshold, _average_baseline, _alert_history):
    """
    Calculate current rate against threshold, manage alert state transitioning when needed.

    :param _status_map: 
    :param _average_threshold:
    :param _average_baseline:
    :param _alert_history:

    :return Delta in percentage between baseline rate and the current rate
    """
    average_delta = (_status_map['http_request_count']-_average_baseline)*100/_average_baseline #Percentage of baseline delta
    if average_delta > _average_threshold: 
        _status_map['running_mode'] = 'enforce_alert' #Set alert to active
        _alert_history.insert(0, [_status_map['http_request_count'], time.time()])
    else:
        if _status_map['running_mode'] == 'enforce_alert': 
            _status_map['running_mode'] = 'enforce_dismiss' #Set enforce_alert -> enforce_dismiss
        else:
            _status_map['running_mode'] = 'enforce_normal'
    _status_map['http_request_count'] = 0 #Reset request count
    return average_delta

def main():
    """
    Initialize tshark stack before launching the sniffing program

    :raises All the exceptions
    """
    capture = pyshark.LiveCapture(interface='eth0', display_filter='http') #bpf_filter='tcp port 80')
    try:
        sniff(capture)
    except:
        print("Closing...")
        capture.close() #Release tshark resources
        del capture
        raise

if __name__ == '__main__':
    main()