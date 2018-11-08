try:
    import sys
    import urllib
    import time
    from termcolor import colored, cprint
except ImportError:
    sys.stderr.write("ERROR: found depedancies not yet installed, run 'pip install -r requirements.txt'\n")
    exit(1)

class StatisticVisitor(object):
    """
    Abstract base class of Statistic Plug-in
    """
    def __init__(self, config):
        self.hits = {}
        self.max_top_hits = config.max_top_hits
        self.max_retention_length = config.max_retention_length
        self.max_str_length = config.max_str_length

    """
    Sub-class shall return relevant headline text for printing
    """
    def visit_title(self):
        pass

    """
    Sub-class shall process fields of interest in the packet
    """
    def accept_packet(self, packet):
        pass

    def print(self):
        """
        Sort, print & trim Top N hits

        :param title: A short text description to be printed at top of the section
        :param hits: Dictionary object stores hits info in key, value pair
        """
        cprint('\n\r'+self.visit_title(),'white', 'on_grey')
        if len(self.hits) == 0: 
            return
        count = 0
        for key,value in sorted(self.hits.items(), key=lambda kv: (kv[1][0],kv[1][1]), reverse=True): #Sort by value and last timestamp
            print(key+': '+colored(str(value[0]),'blue')+' last seen: '+time.strftime('%H:%M:%S %Y/%m/%d', time.localtime(value[1])))   
            count+=1
            if count >= self.max_top_hits: #Limit top N hits to screen
                break
        #Trim hits and return
        trim_hits = sorted(self.hits.items(), key=lambda kv: (kv[1][1])) #Sort by last seen in asecdent
        while len(trim_hits) > 0:
            if time.time()-trim_hits[0][1][1] > self.max_retention_length:
                self.hits.pop(trim_hits[0][0]) #Remove aging item by key
                trim_hits.pop(0) #Sync sorted list
            else:
                break

class TopHitsBySection(StatisticVisitor):
    """
    Collect Top hits by Section
    """
    def visit_title(self):
        return '<<<Top Hits By Section>>>'

    def accept_packet(self, packet):
        if hasattr(packet.http, 'request') and hasattr(packet.http, 'host') and len(packet.http.host)>0:
            host = packet.http.host[:self.max_str_length] #Trucate overlong string
            section_str = 'http://'+host
            if hasattr(packet.http, 'request_uri') and len(packet.http.request_uri)>0:
                str_arr = urllib.parse.unquote(packet.http.request_uri).split('/') #Normalize URL decode path
                for string in str_arr: #Normalize multiple slash '/'
                    if len(string) > 0:
                        str_arr2 = string.split('?') #Remove request parameters
                        if len(str_arr2[0]) > 0:
                            section_str += '/'+str_arr2[0][:self.max_str_length] #Trim section to max length
                        break
            if section_str in self.hits:
                self.hits[section_str][0] += 1
            else:
                self.hits[section_str] = [1,0]
            self.hits[section_str][1] = time.time()

class TopHitsByHost(StatisticVisitor):
    """
    Collect Top hits by Host
    """
    def visit_title(self):
        return '<<<Top Hits By Domain>>>'

    def accept_packet(self, packet):
        if hasattr(packet.http, 'request') and hasattr(packet.http, 'host') and len(packet.http.host)>0:
            host = packet.http.host[:self.max_str_length] #Trucate overlong string
            #Collect Top hits request count by Host
            if host in self.hits:
                self.hits[host][0] += 1
            else:
                self.hits[host] = [1,0]
            self.hits[host][1] = time.time()

class TopHitsUploadByHost(StatisticVisitor):
    """
    Collect Top hits request volume by Host
    """
    def visit_title(self):
        return '<<<Top Hits Upload Volume By Domain>>>'

    def accept_packet(self, packet):
        if hasattr(packet.http, 'request') and hasattr(packet.http, 'host') and len(packet.http.host)>0:
            host = packet.http.host[:self.max_str_length] #Trucate overlong string
            if host in self.hits:
                self.hits[host][0] += int(packet.length)
            else:
                self.hits[host] = [int(packet.length),0]
            self.hits[host][1] = time.time()

class TopHitsByUserAgent(StatisticVisitor):
    """
    Collect Top hits by User-Agent
    """
    def visit_title(self):
        return '<<<Top Hits By User-Agent>>>'

    def accept_packet(self, packet):
        if hasattr(packet.http, 'request') and hasattr(packet.http, 'user_agent') and len(packet.http.user_agent)>0:
            user_agent = packet.http.user_agent[:self.max_str_length] #Trucate overlong string
            if user_agent in self.hits:
                self.hits[user_agent][0] += 1
            else:
                self.hits[user_agent] = [1,0]
            self.hits[user_agent][1] = time.time()

class TopHitsByHttpMethod(StatisticVisitor):
    """
    Collect Top hits by HTTP Method
    """
    def visit_title(self):
        return '<<<Top Hits By Method>>>'

    def accept_packet(self, packet):
        #Collect Top hits by HTTP Method
        if hasattr(packet.http, 'request') and hasattr(packet.http, 'request_method') and len(packet.http.request_method)>0:
            request_method = packet.http.request_method[:self.max_str_length] #Trucate overlong string
            if request_method in self.hits:
                self.hits[request_method][0] += 1
            else:
                self.hits[request_method] = [1,0]
            self.hits[request_method][1] = time.time()

class TopHitsByStatusCode(StatisticVisitor):
    """
    Collect Top hits by HTTP Status code
    """
    def visit_title(self):
        return '<<<Top Hits By Status Code>>>'

    def accept_packet(self, packet):
        if hasattr(packet.http, 'response') and hasattr(packet.http, 'response_code') and len(packet.http.response_code)>0:
            response_code = packet.http.response_code[:self.max_str_length] #Trucate overlong string
            if response_code in self.hits:
                self.hits[response_code][0] += 1
            else:
                self.hits[response_code] = [1,0]
            self.hits[response_code][1] = time.time()