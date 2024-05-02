from SIDS.Action import *
from SIDS.Protocol import *
from SIDS.IPs import *
from SIDS.Ports import *
from SIDS.Rule import *

def read(file_name):

    #Read the rules, return the rule list and error
    l = list()
    with open (file_name, 'r') as f:
        error = 0
        for line in f:
            try:
                rule = Rule(line)
                l.append(rule)
            except ValueError as e:
                error += 1
                print(rule)
    return l,error



