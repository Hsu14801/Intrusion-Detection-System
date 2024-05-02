from enum import Enum
from scapy.all import *
import re
from urllib.parse import unquote

HTTPcommands = ["GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"]
HTTPUrls = ["http://", "https://"]
Sql = ["select", "and", "or"]
# ""XSS""

def isHTTP(pkt):
    if (TCP in pkt and pkt[TCP].payload):
        data = pkt[TCP].payload
        if isinstance(data, Padding):
            # Handle Padding payload
            data = str(data.original)
        elif isinstance(data, Raw):
            # Handle Raw payload
            data = str(data.load)
        else:
            # Handle other payload types as needed
            data = str(data)
        match = re.search(r"\bHTTP\b", data)
        if match:
            # return data
            return True
        else:
            for word in HTTPcommands:
                word = r'\b{}\b'.format(re.escape(word))
                match = re.search(word.rstrip(), data)
                if match:
                    # return data
                    return True
                else:
                    return False
    else:
        return False
    #     words = data.split('/')
    #     if (len(words) >= 1 and words[0].rstrip() == "HTTP"):
    #         return True
            
    #     words = data.split(' ')
    #     # if (len(words) >= 1 and any(word in HTTPcommands for word in words)):
    #     if any(word in HTTPcommands for word in words)
    #         return True
    #     else:
    #         return False
    # else:
    #     return False
# def ispayload(pkt, content):
#     payload = None
#     if (TCP in pkt):
#         payload = pkt[TCP].payload
#     elif (UDP in pkt):
#         payload = pkt[UDP].payload
#     if (payload):
#         if isinstance(payload, Padding):
#         # Handle Padding payload
#             payload = str(payload.original)
#         elif isinstance(payload, Raw):
#         # Handle Raw payload
#             payload = pkt.getlayer(Raw).load.decode('utf-8', 'ignore')
#         payload = unquote(payload)
#         data = payload.split(' ')
#         for word in data:
#             print('words:', word)
#             match = re.search(re.escape(word.lower()), content.lower())
#             if match:
#                 return True
#             else:
#                 return False
#     else: 
#         return False
def http_url(pkt):
    # if IP in pkt:
    #     if pkt[IP].src == '172.18.36.134':
    if(TCP in pkt and pkt[TCP].payload):
        data = pkt[TCP].payload
        if isinstance(data, Padding):
            # Handle Padding payload
            data = str(data.original)
        elif isinstance(data, Raw):
            # Handle Raw payload
            data = str(data.load)
        else:
            # Handle other payload types as needed
            data = str(data)
        for word in HTTPUrls:
            word = r'\b{}\b'.format(re.escape(word))
            match = re.search(word, data)
            if match:
                # print(data,";",word)
                # sys.exit(0)
                return True
            else:
                return False
    else: 
        return False

# def SqlInjection(pkt):
#     if(TCP in pkt and pkt[TCP].payload):
#         data = pkt[TCP].payload
#         if isinstance(data, Padding):
#             # Handle Padding payload
#             data = str(data.original)
#         elif isinstance(data, Raw):
#             # Handle Raw payload
#             data = str(data.load)
#         else:
#             # Handle other payload types as needed
#             data = str(data)
#         for word in Sql:
#             word = r'\b{}\b'.format(re.escape(word))
#             match = re.search(word, data)
#             if match:
#                 return True
#                 # print(data,";",word)
#                 # sys.exit(0)
#             else:
#                 return False
#     else: 
#         return False
# sniff(prn = isHTTP, filter = "tcp")
        
    


# def isArp(pkt):