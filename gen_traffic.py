import time
import requests
import argparse

"""
Generate HTTP traffic every interval
"""
#Parse out commandline arguments
parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    description="This program Generate HTTP traffic every interval.",
)
parser.add_argument("--host", "-i", help="Which host to visit.", default="www.google.com")
parser.add_argument("--frequency", "-f", help="How frequent to visit Host.", default=5)
args = parser.parse_args()

while True:
    requests.get('http://'+args.host)
    print ('http://'+args.host+'... at '+time.strftime('%H:%M:%S %Y/%m/%d', time.localtime(time.time())))
    time.sleep(args.frequency)