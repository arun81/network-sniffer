try:
    import sys
    import urllib
    import time
    from termcolor import colored, cprint
except ImportError as err:
    sys.stderr.write("ERROR: found depedancies not yet installed, run 'pip install -r requirements.txt'\n\r"+str(err)+'\n\r')
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
    def accept_packet(self, packet, request, response):
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

    def _get_field_value(self, transaction, field_name):
        """
        Return decoded and truncated overlong string
        """    
        if field_name in transaction.fields:
            value = transaction.fields[field_name].decode("utf-8")[:self.max_str_length]
            if len(value) > 0:
                return value
        return None

class TopHitsBySection(StatisticVisitor):
    """
    Collect Top hits by Section
    """
    def visit_title(self):
        return '<<<Top Hits By Section>>>'

    def accept_packet(self, packet, request, response):
        if request:
            host = self._get_field_value(request,'Host')
            if host:
                section_str = 'http://'+host
                path = self._get_field_value(request,'Path')
                if path:
                    str_arr = urllib.parse.unquote(path).split('/') #Normalize URL decode path
                    for string in str_arr: #Normalize multiple slash '/', e.g. //folder1/folder2
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
    Collect Top hits request count by Host
    """
    def visit_title(self):
        return '<<<Top Hits By Domain>>>'

    def accept_packet(self, packet, request, response):
        if request:
            host = self._get_field_value(request,'Host')
            if host:
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

    def accept_packet(self, packet, request, response):
        if request:
            host = self._get_field_value(request,'Host')
            if host:
                if host in self.hits:
                    self.hits[host][0] += packet.payload.len
                else:
                    self.hits[host] = [packet.payload.len,0]
                self.hits[host][1] = time.time()

class TopHitsByUserAgent(StatisticVisitor):
    """
    Collect Top hits by User-Agent
    """
    def visit_title(self):
        return '<<<Top Hits By User-Agent>>>'

    def accept_packet(self, packet, request, response):
        if request:
            user_agent = self._get_field_value(request,'User-Agent')
            if user_agent:
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

    def accept_packet(self, packet, request, response):
        #Collect Top hits by HTTP Method
        if request:
            request_method = self._get_field_value(request,'Method')
            if request_method:
                if request_method in self.hits:
                    self.hits[request_method][0] += 1
                else:
                    self.hits[request_method] = [1,0]
                self.hits[request_method][1] = time.time()

class TopHitsByStatusCode(StatisticVisitor):
    """
    Collect Top hits by HTTP Status line
    """
    def visit_title(self):
        return '<<<Top Hits By Status Line>>>'

    def accept_packet(self, packet, request, response):
        if response:
            status_line = self._get_field_value(response,'Status-Line')
            if status_line:
                if status_line in self.hits:
                    self.hits[status_line][0] += 1
                else:
                    self.hits[status_line] = [1,0]
                self.hits[status_line][1] = time.time()