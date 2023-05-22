import schedule
import logging
from subprocess import run
import win32evtlog
from datetime import datetime, timedelta
from time import sleep
from sys import exit
import msvcrt
from configparser import ConfigParser
import re

FailureTH=3 # Failure threshold - How many failed logins from the same IP will trigger a block
FailureTime=120 # Number of minutes the threshold should be checked.
BlockMinutes=1440 # For how long each IP will be blocked after threshold (1440 = a day)
DeleteWhenExit=True # should Firewall rules  be cleared on exit
WhiteList=['127.0.0.1','127.0.0.2']
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)
""" If an IP is failing FailureTH times in the span of FailureTime it will be blocked for BlockMinutes. """
handlers=[]
IPS={}
events=[]
rule_name="RDP-BF-GUARD"
blocked_ips=['203.0.113.203']
MaxIPsPerRule=100
CurrentNumberOfRules=1

def block_ip(ip):
    logging.info(f"Blocking {ip}")
    global blocked_ips, IPS
    blocked_ips.append(ip)
    if not update_rules():
        logging.error(f'Error blocking {ip}')
    else:
        IPS.pop(ip)
        schedule.every(BlockMinutes).minutes.do(time_up,ip2=ip)
        
def unblock_ip(ip):
    logging.info(f"Unblocking {ip}")
    global blocked_ips
    blocked_ips.remove(ip)    
    if not update_rules():
        logging.error(f"Error unblocking {ip}")
    
def time_up(ip2):
    logging.debug(f"Times up for {ip2}")
    unblock_ip(ip2)
    return schedule.CancelJob
    
def IP_detected(ip,time):
    logging.debug(f'New connection detected from {ip}')
    global IPS
    if ip in IPS:
        logging.debug('Already seen from last block')
        IPS[ip][0]=IPS[ip][0][:-1]
        IPS[ip][0].insert(0,time)
    else:
        logging.debug('New IP')
        IPS[ip]=[[time-timedelta(minutes=BlockMinutes+10),]*FailureTH,1]
        IPS[ip][0][0]=time
    if check_time(ip):
        if ip not in WhiteList: block_ip(ip)
        

def check_time(ip):
    global IPS
    dt=(IPS[ip][0][0]-IPS[ip][0][-1]).total_seconds()/60
    logging.debug(f'Time to check={dt}')
    if dt<FailureTime:
        return True
    else:
        return False
        
def fw_check(): # Checking for ability to control firewall
    output=run('netsh advfirewall firewall delete rule name="EVNTGUARDTEST"', capture_output=True)
    logging.debug(str(output.stdout))
    if "No rules match the specified criteria." in str(output.stdout):
        return True
    return False


def cut_text(text,start,end):
    startLoc=text.find(start)
    endLoc=text.find(end,startLoc+1)
    if (startLoc < 0) or (endLoc < 0):
        return ("NA")
    return (text[startLoc+len(start):endLoc].translate({10:None,13:None}))
    
def get_info(xml,detectip,detectuser):
    ip=cut_text(xml,detectip[0],detectip[1])
    ip=pattern.search(ip)[0] if pattern.search(ip) != None else "NA"
    #username=cut_text(xml,detectuser[0],detectuser[1])
    username="NA" if detectuser=="NA" else cut_text(xml,detectuser[0],detectuser[1])
    return (ip,username)

def on_event(action, context, event_handle):
    logging.debug('Event recieved')
    if action == win32evtlog.EvtSubscribeActionDeliver:
        xml=win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
        logging.debug(xml)
        event_id=cut_text(xml,"<EventID>","</EventID>")
        if events[context][3] in xml:
            ip,username=get_info(xml,events[context][1],events[context][2])
            logging.info(f'[{events[context][4]}]Detected connection from {ip}, Info={username}')
              
            if (ip.strip()=="") or (ip=="NA") or (ip=="-"):
                logging.error("can't retrieve IP from event")
            else:            
                IP_detected(ip,datetime.now())        
                
def firewall_rule_exists(name):
    output=run(f'netsh advfirewall firewall show rule name="{name}"',capture_output=True)
    logging.debug(str(output.stdout))
    if "No rules match the specified criteria." in str(output.stdout):
        logging.debug('No rule detected')
        return False
    return True
    
def create_rule(name):
    logging.debug(f'Creating firewall rule {name}')
    output=run(f'netsh advfirewall firewall add rule name="{name}" dir=in action=block profile=any remoteip=1.2.3.4/32',capture_output=True)
    logging.debug(str(output.stdout))

def remove_rule(name):
    logging.debug(f"Removing rule {name}")
    output=run(f'netsh advfirewall firewall del rule name="{name}"',capture_output=True)
    logging.debug(str(output.stdout))
    if 'Deleted 1 rule' in str(output.stdout):
        return True
    return False

def update_rules():
    global CurrentNumberOfRules
    global blocked_ips
    blocked_ips=list(set(blocked_ips))
    result=True
    suffix=0
    for ruleset in range(0,len(blocked_ips),MaxIPsPerRule):
        suffix +=1
        result=update_rule(blocked_ips[ruleset:MaxIPsPerRule+ruleset],suffix)
     
    for obs_rule in range(suffix+1,CurrentNumberOfRules+1):
        if not remove_rule(rule_name+str(obs_rule)):
            logging.error(f"Error removing rule {name+str(obs_rule)}")
            result=False
    CurrentNumberOfRules=suffix
    return result
    
def update_rule(iplist,suffix):
    ip_list=''
    for ip in iplist:
        ip_list=ip_list+ip+','
    logging.debug(ip_list)
    if suffix>CurrentNumberOfRules:
        create_rule(rule_name+str(suffix))
        
    output=run(f'netsh advfirewall firewall set rule name="{rule_name+str(suffix)}" new remoteip={ip_list}',capture_output=True)
    logging.debug(str(output.stdout))
    if 'Updated 1 rule' in str(output.stdout):
        return True
    else:
        return False

def cls(): # "Clear" the screen without importing the os module
    print('\n' *100)
    

def update_rule_old():
    ip_list=''
    for ip in blocked_ips:
        ip_list=ip_list+ip+','
    logging.debug(ip_list)
    
    output=run(f'netsh advfirewall firewall set rule name="{rule_name}" new remoteip={ip_list}',capture_output=True)
    logging.debug(str(output.stdout))
    if 'Updated 1 rule' in str(output.stdout):
        return True
    else:
        return False
print ("""                                    
 (  (               (               
 )\))(   '(       ( )\     )        
((_)()\ ) )\  (   )((_) ( /(  (     
_(())\_)(|(_) )\ |(_)_  )(_)) )\ )  
\ \((_)/ /(_)_(_/(| _ )((_)_ _(_/(  
 \ \/\/ / | | ' \)) _ \/ _` | ' \)) 
  \_/\_/  |_|_||_||___/\__,_|_||_|  
                                    

""")
        
if not fw_check():
    exit("Can't control firewall - please make sure you are running as administrator and netsh can be accessed.")


logging.info('Reading config.ini for rules')
parser=ConfigParser()
parser.read('config.ini')

try:
    for section in parser.sections():
        evt=[]
        if ((parser.has_option(section,'eventfilter')) and (parser.has_option(section,'ip'))):
            evt.append(parser.get(section,'eventfilter').strip().split("|"))
            evt.append(parser.get(section,'ip').strip().split("|"))
        else:
            exit ('Error reading config file')
        if parser.has_option(section,'info'):
            evt.append(parser.get(section,'info').strip().split("|"))
        else:
            evt.append('NA')
        if parser.has_option(section,'detector'):
            evt.append(parser.get(section,'detector').strip())
        else:
            evt.append("")
        evt.append(section)
        events.append(evt)

except:
    exit ('Error reading config file')

   
if not firewall_rule_exists(rule_name+"1"): create_rule(rule_name+"1")

n=0
for event in events:
    logging.info(f'Creating event listener:{n}-{event[4]}')
    handlers.append(win32evtlog.EvtSubscribe(event[0][0],win32evtlog.EvtSubscribeToFutureEvents,None,Callback = on_event,Query=event[0][1], Context=n))
    n=n+1

pattern=re.compile(r'(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}')

prompt="Press (Q)uit or (S)tatus"
print (prompt)

Running=True
while Running:
    schedule.run_pending()
    sleep(1)
    if msvcrt.kbhit():
        key=msvcrt.getch()
        if key==b'q':
            Running=False
        elif key==b's':
            print (f"Blocked IPs (total of {len(blocked_ips)}): {blocked_ips}\nMonitored IPs (total of {len(IPS.keys())}): {list(IPS.keys())}\nFirewall Rules: {CurrentNumberOfRules}")          
        elif key==b'1':
            blocked_ips.pop()
            update_rules()
        elif key==b'c':
            cls()
        else:
            print (prompt)
    
#for handle in handlers:
#    win32evtlog.CloseEventLog(handle)

if DeleteWhenExit:
    print ("Deleting rules....")
    for rule in range(CurrentNumberOfRules):
        if not remove_rule(rule_name+str(rule+1 )): logging.error("Error removing Rule - Please manually check current configuration")
    