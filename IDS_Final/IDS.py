from scapy.all import *
import argparse
import logging
from datetime import datetime
import sys
from SIDS.RuleRead import read
from AIDS.Anomaly import *
import keyboard

RED = '\033[91m'
BLUE = '\033[34m'
GREEN = '\033[32m'
ENDC = '\033[0m'

def main(filename):
    # Read the rule file and start listening.

    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    logging.basicConfig(filename= "logs\\Simple-NIDS " + str(now) + '.log',level=logging.INFO)

    print ("Simple-NIDS started.")
    # Read the rule file
    print ("Reading rule file...")
    global ruleList
    ruleList, errorCount = read(filename)
    print ("Finished reading rule file.")

    if (errorCount == 0):
        print ("All (" + str(len(ruleList)) + ") rules have been correctly read.")
    else:
        print (str(len(ruleList)) + " rules have been correctly read.")
        print (str(errorCount) + " rules have errors and could not be read.")

   
    sniffer = detect(ruleList)

    def on_esc(event):
        sniffer.stop()
        print("ESC pressed. Stopping Simple-NIDS.")
        
        

    # # Set up the 'q' key event handler
    keyboard.on_press_key("esc", on_esc)
    sniffer.start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple NIDS')
    parser.add_argument('-f', '--filename', help='Path to the rule file', required=True)
    args = parser.parse_args()
    
    ruleList = list()
    main(args.filename)
    


