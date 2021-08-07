from ProcessMappingScanner import *
import re
import subprocess
import shlex
from colorama import init
from colorama import Fore, Back, Style, Cursor
from datetime import datetime
import time
import os
import patterns
from difflib import SequenceMatcher

shells = {}

class Shell():
	def __init__(self, pid, pattern, pname, folder, ip=None, port=None, match=None):
		self.pid = pid
		self.pattern = pattern
		self.pname = pname
		self.folder = folder
		self.ip = ip
		self.port = port
		self.match = match


class Colored:
	@staticmethod
	def magenta(s):
		return Style.BRIGHT+Fore.MAGENTA+s+Fore.RESET+Style.RESET_ALL
	@staticmethod
	def green(s):
		return Style.BRIGHT+Fore.GREEN+s+Fore.RESET+Style.RESET_ALL
	@staticmethod
	def white(s):
		return Fore.WHITE+s+Fore.RESET+Style.RESET_ALL
	@staticmethod
	def cyan(s):
		return Style.BRIGHT+Fore.CYAN+s+Fore.RESET+Style.RESET_ALL
	@staticmethod
	def cyan_fine(s):
		return Fore.CYAN+s+Fore.RESET+Style.RESET_ALL
	@staticmethod
	def yellow(s):
		return Style.BRIGHT+Fore.YELLOW+s+Fore.RESET+Style.RESET_ALL
	@staticmethod
	def red(s):
		return Style.BRIGHT+Fore.RED+s+Fore.RESET+Style.RESET_ALL
	@staticmethod
	def yel_info():
		return Style.BRIGHT+Fore.CYAN+"[INFO]"+Fore.RESET+Style.RESET_ALL
	@staticmethod
	def red_warn():
		return Style.BRIGHT+Fore.RED+"[WARN]"+Fore.RESET+Style.RESET_ALL
	@staticmethod
	def rce():
		return Style.BRIGHT+Fore.RED+"[RCE]"+Fore.RESET+Style.RESET_ALL
	@staticmethod
	def de_rce():
		return "[deserialization rce]"
	@staticmethod
	def upload():
		return "[upload]"
	@staticmethod
	def de_upload():
		return "[deserialization upload]"
	@staticmethod
	def de():
		return "[deserialization]"
	@staticmethod
	def contains():
		return "[file contains]"
	@staticmethod
	def xxe():
		return "[xxe]"
	@staticmethod
	def sql():
		return "[sql]"
	@staticmethod
	def ssrf():
		return "[ssrf]"


color = Colored()

class Timed:
	@staticmethod
	def timed(de):
		get_time = datetime.now()
		time.sleep(de)
		timed = color.cyan_fine("["+str(get_time)[11:19]+"] ")
		return timed
	@staticmethod
	def timed_line(de):
		get_time = datetime.now()
		time.sleep(de)
		timed = color.cyan("["+str(get_time)[11:19]+"] ")
		return timed
	@staticmethod
	def no_color_timed(de):
		get_time = datetime.now()
		time.sleep(de)
		no_color_timed = "["+str(get_time)[11:19]+"] "
		return no_color_timed


now = Timed()

def identify_prt(name):
	#print("\r{0}{1} {2}".format(now.timed(de=0), color.yel_info(), color.red(name)), end="                ")
	print("\r{0}{1} {2}".format(now.timed(de=0), color.yel_info(), color.green(name)))
def identify_prt2(name):
	print("\r{0}{1} {2}".format(now.timed(de=0), color.rce(), color.red(name)))
def identify_prt3(name):
	print("\r{0}{1} {2}".format(now.timed(de=0), color.red_warn(), color.cyan_fine(name)))

def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

def checknet(process, op):

	ssubprocess = subprocess.Popen(['netstat', '-pent'], stdout=subprocess.PIPE)
	output, error = ssubprocess.communicate()
	ret = ''
	for line in output.splitlines():
		if 'tcp' in line.decode():
			linestr = str(line.decode())
			try:
				if op == 1:
					reta = re.search(patterns.base["NETSTATPENT"], linestr)
					if 'zsh' in reta.group(0) or 'sh' in reta.group(0) or 'bash' in reta.group(0):
						ret = re.search(patterns.base["NETPENT"], linestr)
						resreta = ret.group(0)
						process = resreta.replace('/', '')
						gfolder = getFolder(process)
						sdetected = Shell(process, 'terminal', 'terminal', gfolder)
						shells[process] = sdetected
				#resreta = re.search(process+patterns.base["NETSTATPENT"], linestr)
				#if resreta:
					#print(line.decode())
					#print(ret.group(0))
			except:
				pass

def scanproc():

	global shells
	procesos = scanAllProcessesForMapping('', isExactMatch=False)
	for proceso in procesos:
		cmd = getProcessCommandLineList(proceso)
		try:
			for lproc in cmd:
				for shell in patterns.shell:
					try:

						ip = re.search(patterns.net["IPv4"], lproc)
						port = re.search(patterns.net["PORT"], lproc)

						retshell = patterns.shell[shell]
						retshell = retshell.replace('*-IP-*', ip.group(0))
						retshell = retshell.replace('*-PORT-*', port.group(0))
						conexion = f'Ip: {ip.group(0)} Port: {port.group(0)}'

						perc = similar(retshell, lproc)
						if perc > 0.9:
							gfolder = getFolder(proceso)
							sdetected = Shell(proceso, shell, shell, gfolder, ip=ip.group(0),port=port.group(0), match=perc)
							shells[proceso] = sdetected
							
					except:
						pass
					if patterns.shell[shell] in lproc:
						perc = similar(patterns.shell[shell], lproc)
						gfolder = getFolder(proceso)
						sdetected = Shell(proceso, shell, shell, gfolder, match=perc)
						shells[proceso] = sdetected
		except:
			pass
	checknet(str('zsh'), 1)

def getFolder(pid_process):
	cmdr = str(f'readlink -e /proc/{pid_process}/cwd')
	#print(cmdr)
	sp = subprocess.Popen(shlex.split(cmdr), stdout=subprocess.PIPE)
	while True:
		output = sp.stdout.readline()
		if sp.poll() is not None:

			break
		if output:
			return output.strip().decode()

def kill_pid(pid):
	os.kill(int(pid),9)

def alert(p):
	os.system(f"notify-send 'RCE DETECTED!' 'Shell  ==> "+str(p.pattern)+"/"+str(p.pid)+"' -u low -i error")
	if not p.match == None:
		percentage = "{:.0%}".format(p.match)
		identify_prt2(f'Shell ==> {str(p.pattern)}/{str(p.pid)} ==> Match: {percentage}')
	else:
		identify_prt2(f'Shell ==> {str(p.pattern)}/{str(p.pid)}')
	if not p.ip == None:
		identify_prt3(f'Shell ==> {str(p.pattern)}/{str(p.pid)} ==> Ip: {p.ip} Port: {p.port}')
	if not p.folder == None:
		identify_prt2(f'Shell ==> {str(p.pattern)}/{str(p.pid)} ==> Folder: {p.folder}')
	kill_pid(p.pid)
	identify_prt('KILLED ==> '+str(p.pattern)+'/'+str(p.pid))
	os.system(f"notify-send 'RCE KILLED!' 'PID: {str(p.pid)}' -u low -i checkbox-checked-symbolic")



while True:
	scanproc()
	

	for key in list(shells.keys()):
		current_shell = shells[key]
		alert(current_shell)
	shells = {}
	time.sleep(600)
#cmd2 = scanProcessForOpenFile(int(135915), '', isExactMatch=False, ignoreCase=True)
#print(cmd2)



