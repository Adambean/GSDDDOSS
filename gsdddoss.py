import sys, os, signal
import datetime

isLinux = False
if sys.platform == "linux" or sys.platform == "linux2":
	isLinux = True

import re
import subprocess
import json
import socket



isRunning = False

def signal_handler(signal, frame):
	print("\nProgram exiting gracefully.")
	isRunning = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)



if not isLinux:
	import ctypes
	def is_admin():
		try:
			return ctypes.windll.shell32.IsUserAnAdmin()
		except:
			return False
else:
	def is_admin():
		user = os.getenv("SUDO_USER")
		if user is None:
			return False
		else:
			return True



if not is_admin():
	print("Error: This script must be run with administrative / super user privileges.")
	print("(This is necessary to block IP addresses with your system's firewall.)")
	sys.exit(1)




def config_save(data, name):
	with open(name + ".json", "w", encoding="utf-8") as f:
		json.dump(data, f)

def config_load(name):
	with open(name + ".json", "r", encoding="utf-8") as f:
		return json.load(f)



if not os.path.isfile("config.json"):
	print("Warning: Configuration file not found. (A default one will be created.)\n")
	config = {}
	config["listener_addr"] = "127.0.0.1"
	config["listener_port"] = 8008
	config["command_add_block"] = ""
	config["windows_rule_ip_grouped"] = True
	config_save(config, "config")

config = config_load("config")



if not os.path.isfile("blocked.json"):
	print("Warning: Blocked list file not found. (A default one will be created.)\n")
	blocked = {}
	blocked["ips"] = {}
	config_save(blocked, "blocked")

blocked = config_load("blocked")



class badip:
	def __init__(self, ip, port):
		self.ip = ip
		self.port = port

def regex(incoming, pattern):
	regsearch = re.search(r"{}".format(pattern), incoming, re.I)
	if (regsearch):
		return badip(regsearch.group(1), regsearch.group(2))
	return None

def getall(ip):
	ret = ip
	for blockedIP in blocked["ips"]:
		ret = ret + ",{}".format(blockedIP)

	return ret

def blockip(ip): #Make one rule per IP, used to group IPs in windows but it quickly hit the firewall rule limitation.
	if (ip == "127.0.0.1" or ip == "::1"):
		print("Warning: Not blocking localhost IP address.")
		return

	blocked["ips"].append(ip)
	config_save(blocked, "blocked")

	if config["command_add_block"]:
		firewallRuleAddCommand = subprocess.call(config["command_add_block"].replace("{ip}", ip), shell=True)
	elif isLinux:
		firewallRuleAddCommand = subprocess.call("iptables -A INPUT -s {} -j DROP -m comment --comment \"GSDDDOSS blocked\"".format(ip), shell=True)
	else:
		if config["windows_rule_ip_grouped"]:
			firewallRuleCheckCommand = subprocess.call("netsh advfirewall firewall show rule name=\"GSDDDOSS blocked\" dir=in", shell=True)
			if (firewallRuleCheckCommand.returncode != 0):
				firewallRuleAddCommand = subprocess.call("netsh advfirewall firewall add rule name=\"GSDDDOSS blocked\" dir=in action=block description=\"IP addresses that have been caught by the GSDDDOSS tool.\" enable=yes profile=any interface=any remoteip=\"{}\"".format(",".join(blocked["ips"])), shell=True)
			else:
				firewallRuleAddCommand = subprocess.call("netsh advfirewall firewall set rule name=\"GSDDDOSS blocked\" dir=in new remoteip=\"{}\"".format(",".join(blocked["ips"])), shell=True)
		else:
			firewallRuleAddCommand = subprocess.call("netsh advfirewall firewall add rule name=\"GSDDDOSS blocked\" dir=in action=block description=\"IP address that has been caught by the GSDDDOSS tool.\" enable=yes profile=any interface=any remoteip=\"{}\"".format(ip), shell=True)

	if (firewallRuleAddCommand.returncode != 0):
		print("Error: Failed to block IP address \"{}\": Code {}".format(ip, firewallRuleAddCommand.returncode))
	else:
		print("Blocked IP address \"{}\".".format(ip))

iplist = {}
hotlist = {}

def count_ports(input, match):
	ret = 0
	for inp in input:
		if inp == match:
			ret = ret + 1
	return ret

def log_receiver(host=config["listener_addr"], port=config["listener_port"]):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	print("GSDDDOSS log receiver started, listening on UDP socket at \"{}:{}\".".format(host, port))
	s.bind((host,port))
	isRunning = True
	while isRunning == True:
		(data, addr) = s.recvfrom(128 * 1024)
		if not data:
			break
		yield data[4:-1].decode("utf-8") # has garbage header + ending
	s.close()

for data in log_receiver():
	# Rule: A2S abuse / Reflected DDoS
	ret = regex(data, "([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):([0-9]+)\\swas\\sblocked\\sfor\\sexceeding\\srate\\slimits$")
	if (ret != None):
		if ret.ip not in blocked["ips"]:
			if ret.ip in iplist:
				iplist[ret.ip].append(ret.port)
				counted = count_ports(iplist[ret.ip], ret.port)
				if (counted >= 3):
					print("Found a naughty IP address: {} (rate limit, repeating port was: {})".format(ret.ip, ret.port))
					blockip(ret.ip)
					if ret.ip in hotlist:
						hotlist.pop(ret.ip)

					iplist.pop(ret.ip)

				if (counted <= 1 and len(iplist[ret.ip]) > 12):
					print("Popping: {} (most likely valid person spamming browser refresh)".format(ret.ip))
					future = datetime.datetime.utcnow() + datetime.timedelta(seconds=240)
					future = future.replace(tzinfo=datetime.timezone.utc).timestamp()

					if ret.ip in hotlist:
						hotlist[ret.ip].append(future)
						timenow = datetime.datetime.utcnow()
						for hottime in hotlist[ret.ip][:]:
							timethen = datetime.datetime.utcfromtimestamp(hottime)
							if (timethen < timenow):
								hotlist.remove(hottime)

						if len(hotlist[ret.ip]) > 3:
							print("Found a naughty IP address: {} (rate limit, port blasting)".format(ret.ip))
							hotlist.pop(ret.ip)
							blockip(ret.ip)
					else:
						hotlist[ret.ip] = []
						hotlist[ret.ip].append(future)

					iplist.pop(ret.ip)
			else:
				iplist[ret.ip] = []
				iplist[ret.ip].append(ret.port)

	# Rule: Split packet
	ret = regex(data, "^([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):([0-9]+)\\stried\\sto\\ssend\\ssplit\\spacket")
	if (ret != None):
		if ret.ip not in blocked["ips"]:
			print("Found extremely naughty IP address: {} (SPLIT PACKET!)".format(ret.ip))
			blockip(ret.ip)

	# Rule: Bad RCON attempt
	ret = regex(data, "Bad\\sRcon:\\s(?:.*)\\sfrom\\s\"([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):([0-9]+)\"")
	if (ret != None):
		if ret.ip not in blocked["ips"]:
			print("Found semi-naughty IP address: {} (bad RCON)".format(ret.ip))
			blockip(ret.ip)
