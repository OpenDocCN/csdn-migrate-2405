# Python 网络编程学习手册（三）

> 原文：[`zh.annas-archive.org/md5/b9ea58a6220e445a9f19c9c78aff8a58`](https://zh.annas-archive.org/md5/b9ea58a6220e445a9f19c9c78aff8a58)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：与远程系统交互

如果您的计算机连接到互联网或**局域网**（**LAN**），那么现在是时候与网络上的其他计算机进行通信了。在典型的家庭、办公室或校园局域网中，您会发现许多不同类型的计算机连接到网络上。一些计算机充当特定服务的服务器，例如文件服务器、打印服务器、用户认证管理服务器等。在本章中，我们将探讨网络中的计算机如何相互交互以及如何通过 Python 脚本访问一些服务。以下任务列表将为您提供本章涵盖的主题的概述：

+   使用`paramiko`访问 SSH 终端

+   通过 SFTP 传输文件

+   通过 FTP 传输文件

+   阅读 SNMP 数据包

+   阅读 LDAP 数据包

+   使用 SAMBA 共享文件

这一章需要一些第三方软件包，如`paramiko`、`pysnmp`等。您可以使用操作系统的软件包管理工具进行安装。以下是在 Ubuntu 14、python3 中安装`paramiko`模块以及本章涵盖的其他主题的理解所需的其他模块的快速操作指南：

```py
**sudo apt-get install python3**
**sudo apt-get install python3-setuptools**
**sudo easy_install3 paramiko**
**sudo easy_install3 python3-ldap**
**sudo easy_install3 pysnmp**
**sudo easy_install3 pysmb**

```

# 使用 Python 进行安全外壳访问

SSH 已经成为一种非常流行的网络协议，用于在两台计算机之间进行安全数据通信。它提供了出色的加密支持，使得无关的第三方在传输过程中无法看到数据的内容。SSH 协议的详细信息可以在这些 RFC 文档中找到：RFC4251-RFC4254，可在[`www.rfc-editor.org/rfc/rfc4251.txt`](http://www.rfc-editor.org/rfc/rfc4251.txt)上找到。

Python 的`paramiko`库为基于 SSH 的网络通信提供了非常好的支持。您可以使用 Python 脚本来从 SSH-based 远程管理中获益，例如远程命令行登录、命令执行以及两台网络计算机之间的其他安全网络服务。您可能还对使用基于`paramiko`的`pysftp`模块感兴趣。有关此软件包的更多详细信息可以在 PyPI 上找到：[`pypi.python.org/pypi/pysftp/`](https://pypi.python.org/pypi/pysftp/)。

SSH 是一种客户端/服务器协议。双方都使用 SSH 密钥对加密通信。每个密钥对都有一个私钥和一个公钥。公钥可以发布给任何可能感兴趣的人。私钥始终保持私密，并且除了密钥所有者之外，不允许任何人访问。

SSH 公钥和私钥可以由外部或内部证书颁发机构生成并进行数字签名。但这给小型组织带来了很多额外开销。因此，作为替代，可以使用`ssh-keygen`等实用工具随机生成密钥。公钥需要提供给所有参与方。当 SSH 客户端首次连接到服务器时，它会在一个名为`~/.ssh/known_hosts`的特殊文件上注册服务器的公钥。因此，随后连接到服务器可以确保客户端与之前通话的是同一台服务器。在服务器端，如果您希望限制对具有特定 IP 地址的某些客户端的访问，则可以将允许主机的公钥存储到另一个名为`ssh_known_hosts`的特殊文件中。当然，如果重新构建机器，例如服务器机器，那么服务器的旧公钥将与`~/.ssh/known_hosts`文件中存储的公钥不匹配。因此，SSH 客户端将引发异常并阻止您连接到它。您可以从该文件中删除旧密钥，然后尝试重新连接，就像第一次一样。

我们可以使用`paramiko`模块创建一个 SSH 客户端，然后将其连接到 SSH 服务器。这个模块将提供`SSHClient()`类。

```py
ssh_client = paramiko.SSHClient()
```

默认情况下，此客户端类的实例将拒绝未知的主机密钥。因此，您可以设置接受未知主机密钥的策略。内置的`AutoAddPolicy()`类将在发现时添加主机密钥。现在，您需要在`ssh_client`对象上运行`set_missing_host_key_policy()`方法以及以下参数。

```py
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
```

如果您想要限制仅连接到某些主机，那么您可以定义自己的策略并将其替换为`AutoAddPolicy()`类。

您可能还希望使用`load_system_host_keys()`方法添加系统主机密钥。

```py
ssh_client.load_system_host_keys()
```

到目前为止，我们已经讨论了如何加密连接。然而，SSH 需要您的身份验证凭据。这意味着客户端需要向服务器证明特定用户在交谈，而不是其他人。有几种方法可以做到这一点。最简单的方法是使用用户名和密码组合。另一种流行的方法是使用基于密钥的身份验证方法。这意味着用户的公钥可以复制到服务器上。有一个专门的工具可以做到这一点。这是随后版本的 SSH 附带的。以下是如何使用`ssh-copy-id`的示例。

```py
**ssh-copy-id -i ~/.ssh/id_rsa.pub faruq@debian6box.localdomain.loc**

```

此命令将 faruq 用户的 SSH 公钥复制到`debian6box.localdomain.loc`机器：

在这里，我们可以简单地调用`connect()`方法以及目标主机名和 SSH 登录凭据。要在目标主机上运行任何命令，我们需要通过将命令作为其参数来调用`exec_command()`方法。

```py
ssh_client.connect(hostname, port, username, password)
stdin, stdout, stderr = ssh_client.exec_command(cmd)
```

以下代码清单显示了如何对目标主机进行 SSH 登录，然后运行简单的`ls`命令：

```py
#!/usr/bin/env python3

import getpass
import paramiko

HOSTNAME = 'localhost'
PORT = 22

def run_ssh_cmd(username, password, cmd, hostname=HOSTNAME, port=PORT):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(\
        paramiko.AutoAddPolicy())
    ssh_client.load_system_host_keys()
    ssh_client.connect(hostname, port, username, password)
    stdin, stdout, stderr = ssh_client.exec_command(cmd)
    print(stdout.read())

if __name__ == '__main__':
    username = input("Enter username: ")
    password = getpass.getpass(prompt="Enter password: ")
    cmd = 'ls -l /dev'
    run_ssh_cmd(username, password, cmd)
```

在运行之前，我们需要确保目标主机（在本例中为本地主机）上运行 SSH 服务器守护程序。如下面的截图所示，我们可以使用`netstat`命令来执行此操作。此命令将显示所有监听特定端口的运行服务：

![使用 Python 访问安全外壳](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_01.jpg)

前面的脚本将与本地主机建立 SSH 连接，然后运行`ls -l /dev/`命令。此脚本的输出将类似于以下截图：

![使用 Python 访问安全外壳](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_02.jpg)

## 检查 SSH 数据包

看到客户端和服务器之间的网络数据包交换将会非常有趣。我们可以使用本机`tcpdump`命令或第三方 Wireshark 工具来捕获网络数据包。使用`tcpdump`，您可以指定目标网络接口（`-i lo`）和端口号（端口`22`）选项。在以下数据包捕获会话中，在 SSH 客户端/服务器通信会话期间显示了五次数据包交换：

```py
**root@debian6box:~# tcpdump -i lo port 22**
**tcpdump: verbose output suppressed, use -v or -vv for full protocol decode**
**listening on lo, link-type EN10MB (Ethernet), capture size 65535 bytes**
**12:18:19.761292 IP localhost.50768 > localhost.ssh: Flags [S], seq 3958510356, win 32792, options [mss 16396,sackOK,TS val 57162360 ecr 0,nop,wscale 6], length 0**
**12:18:19.761335 IP localhost.ssh > localhost.50768: Flags [S.], seq 1834733028, ack 3958510357, win 32768, options [mss 16396,sackOK,TS val 57162360 ecr 57162360,nop,wscale 6], length 0**
**12:18:19.761376 IP localhost.50768 > localhost.ssh: Flags [.], ack 1, win 513, options [nop,nop,TS val 57162360 ecr 57162360], length 0**
**12:18:19.769430 IP localhost.50768 > localhost.ssh: Flags [P.], seq 1:25, ack 1, win 513, options [nop,nop,TS val 57162362 ecr 57162360], length 24**
**12:18:19.769467 IP localhost.ssh > localhost.50768: Flags [.], ack 25, win 512, options [nop,nop,TS val 57162362 ecr 57162362], length 0**

```

尽管使用`tcpdump`非常快速和简单，但该命令不会像其他 GUI 工具（如 Wireshark）那样解释它。前面的会话可以在 Wireshark 中捕获，如下面的截图所示：

![检查 SSH 数据包](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_03.jpg)

这清楚地显示了前三个数据包如何完成 TCP 握手过程。然后，随后的 SSH 数据包协商了客户端和服务器之间的连接。看到客户端和服务器如何协商加密协议是很有趣的。在这个例子中，客户端端口是`50768`，服务器端口是`22`。客户端首先启动 SSH 数据包交换，然后指示它想要使用`SSHv2`协议进行通信。然后，服务器同意并继续数据包交换。

# 通过 SFTP 传输文件

SSH 可以有效地用于在两个计算机节点之间安全地传输文件。在这种情况下使用的协议是**安全文件传输协议**（**SFTP**）。Python 的`paramiko`模块将提供创建 SFTP 会话所需的类。然后，此会话可以执行常规的 SSH 登录。

```py
ssh_transport = paramiko.Transport(hostname, port)
ssh_transport.connect(username='username', password='password')
```

SFTP 会话可以从 SSH 传输中创建。paramiko 在 SFTP 会话中的工作将支持诸如`get()`之类的正常 FTP 命令。

```py
 sftp_session = paramiko.SFTPClient.from_transport(ssh_transport)
 sftp_session.get(source_file, target_file)
```

正如您所看到的，SFTP 的`get`命令需要源文件的路径和目标文件的路径。在下面的示例中，脚本将通过 SFTP 下载位于用户主目录中的`test.txt`文件：

```py
#!/usr/bin/env python3

import getpass
import paramiko

HOSTNAME = 'localhost'
PORT = 22
FILE_PATH = '/tmp/test.txt'

def sftp_download(username, password, hostname=HOSTNAME, port=PORT):
    ssh_transport = paramiko.Transport(hostname, port)
    ssh_transport.connect(username=username, password=password)
    sftp_session = paramiko.SFTPClient.from_transport(ssh_transport)
    file_path = input("Enter filepath: ") or FILE_PATH
    target_file = file_path.split('/')[-1]
    sftp_session.get(file_path, target_file)
    print("Downloaded file from: %s" %file_path)
    sftp_session.close()

if __name__ == '__main__':
    hostname = input("Enter the target hostname: ")
    port = input("Enter the target port: ")
    username = input("Enter yur username: ")
    password = getpass.getpass(prompt="Enter your password: ")
    sftp_download(username, password, hostname, int(port))
```

在这个例子中，使用 SFTP 下载了一个文件。请注意，`paramiko`使用`SFTPClient.from_transport(ssh_transport)`类创建了 SFTP 会话。

脚本可以按照以下截图所示运行。在这里，我们将首先创建一个名为`/tmp/test.txt`的临时文件，然后完成 SSH 登录，然后使用 SFTP 下载该文件。最后，我们将检查文件的内容。

![通过 SFTP 传输文件](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_04.jpg)

# 使用 FTP 传输文件

与 SFTP 不同，FTP 使用明文文件传输方法。这意味着通过网络传输的任何用户名或密码都可以被不相关的第三方检测到。尽管 FTP 是一种非常流行的文件传输协议，但人们经常使用它将文件从他们的个人电脑传输到远程服务器。

在 Python 中，`ftplib`是一个用于在远程机器之间传输文件的内置模块。您可以使用`FTP()`类创建一个匿名 FTP 客户端连接。

```py
ftp_client = ftplib.FTP(path, username, email)   
```

然后，您可以调用正常的 FTP 命令，例如`CWD`。为了下载二进制文件，您需要创建一个文件处理程序，如下所示：

```py
file_handler = open(DOWNLOAD_FILE_NAME, 'wb')
```

为了从远程主机检索二进制文件，可以使用此处显示的语法以及`RETR`命令：

```py
ftp_client.retrbinary('RETR remote_file_name', file_handler.write)
```

在下面的代码片段中，可以看到完整的 FTP 文件下载示例：

```py
#!/usr/bin/env python
import ftplib

FTP_SERVER_URL = 'ftp.kernel.org'
DOWNLOAD_DIR_PATH = '/pub/software/network/tftp'
DOWNLOAD_FILE_NAME = 'tftp-hpa-0.11.tar.gz'

def ftp_file_download(path, username, email):
    # open ftp connection
    ftp_client = ftplib.FTP(path, username, email)
    # list the files in the download directory
    ftp_client.cwd(DOWNLOAD_DIR_PATH)
    print("File list at %s:" %path)
    files = ftp_client.dir()
    print(files)
    # downlaod a file
    file_handler = open(DOWNLOAD_FILE_NAME, 'wb')
    #ftp_cmd = 'RETR %s ' %DOWNLOAD_FILE_NAME
    ftp_client.retrbinary('RETR tftp-hpa-0.11.tar.gz', file_handler.write)
    file_handler.close()
    ftp_client.quit()

if __name__ == '__main__':
    ftp_file_download(path=FTP_SERVER_URL,  username='anonymous', email='nobody@nourl.com')
```

上述代码说明了如何从[ftp.kernel.org](http://ftp.kernel.org)下载匿名 FTP，这是托管 Linux 内核的官方网站。`FTP()`类接受三个参数，如远程服务器上的初始文件系统路径、用户名和`ftp`用户的电子邮件地址。对于匿名下载，不需要用户名和密码。因此，可以从`/pub/software/network/tftp`路径上找到的`tftp-hpa-0.11.tar.gz`文件中下载脚本。

## 检查 FTP 数据包

如果我们在公共网络接口的端口`21`上在 Wireshark 中捕获 FTP 会话，那么我们可以看到通信是如何以明文形式进行的。这将向您展示为什么应该优先使用 SFTP。在下图中，我们可以看到，在成功与客户端建立连接后，服务器发送横幅消息:`220` 欢迎来到 kernel.org。随后，客户端将匿名发送登录请求。作为回应，服务器将要求密码。客户端可以发送用户的电子邮件地址进行身份验证。

检查 FTP 数据包

令人惊讶的是，您会发现密码已经以明文形式发送。在下面的截图中，显示了密码数据包的内容。它显示了提供的虚假电子邮件地址`nobody@nourl.com`。

![检查 FTP 数据包](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_06.jpg)

# 获取简单网络管理协议数据

SNMP 是一种广泛使用的网络协议，用于网络路由器（如交换机、服务器等）通信设备的配置、性能数据和控制设备的命令。尽管 SNMP 以“简单”一词开头，但它并不是一个简单的协议。在内部，每个设备的信息都存储在一种称为**管理信息库**（**MIB**）的信息数据库中。SNMP 协议根据协议版本号提供不同级别的安全性。在 SNMP `v1`和`v2c`中，数据受到称为 community 字符串的密码短语的保护。在 SNMP `v3`中，需要用户名和密码来存储数据。并且，数据可以通过 SSL 进行加密。在我们的示例中，我们将使用 SNMP 协议的`v1`和`v2c`版本。

SNMP 是一种基于客户端/服务器的网络协议。服务器守护程序向客户端提供请求的信息。在您的计算机上，如果已安装和配置了 SNMP，则可以使用`snmpwalk`实用程序命令通过以下语法查询基本系统信息：

```py
**# snmpwalk -v2c -c public localhost**
**iso.3.6.1.2.1.1.1.0 = STRING: "Linux debian6box 2.6.32-5-686 #1 SMP Tue May 13 16:33:32 UTC 2014 i686"**
**iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10**
**iso.3.6.1.2.1.1.3.0 = Timeticks: (88855240) 10 days, 6:49:12.40**
**iso.3.6.1.2.1.1.4.0 = STRING: "Me <me@example.org>"**
**iso.3.6.1.2.1.1.5.0 = STRING: "debian6box"**
**iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"**

```

上述命令的输出将显示 MIB 编号及其值。例如，MIB 编号`iso.3.6.1.2.1.1.1.0`显示它是一个字符串类型的值，如`Linux debian6box 2.6.32-5-686 #1 SMP Tue May 13 16:33:32 UTC 2014 i686`。

在 Python 中，您可以使用一个名为`pysnmp`的第三方库来与`snmp`守护程序进行交互。您可以使用 pip 安装`pysnmp`模块。

```py
**$ pip install pysnmp**

```

该模块为`snmp`命令提供了一个有用的包装器。让我们学习如何创建一个`snmpwalk`命令。首先，导入一个命令生成器。

```py
from pysnmp.entity.rfc3413.oneliner import cmdgen
cmd_generator = cmdgen.CommandGenerator()
```

然后假定`snmpd`守护程序在本地机器的端口`161`上运行，并且 community 字符串已设置为 public，定义连接的必要默认值。

```py
SNMP_HOST = 'localhost'
SNMP_PORT = 161
SNMP_COMMUNITY = 'public'
```

现在使用必要的数据调用`getCmd()`方法。

```py
    error_notify, error_status, error_index, var_binds = cmd_generator.getCmd(
        cmdgen.CommunityData(SNMP_COMMUNITY),
        cmdgen.UdpTransportTarget((SNMP_HOST, SNMP_PORT)),
        cmdgen.MibVariable('SNMPv2-MIB', 'sysDescr', 0),
        lookupNames=True, lookupValues=True
    )
```

您可以看到`cmdgen`接受以下参数：

+   `CommunityData()`: 将 community 字符串设置为 public。

+   `UdpTransportTarget()`: 这是主机目标，`snmp`代理正在运行的地方。这是由主机名和 UDP 端口组成的一对。

+   `MibVariable`: 这是一个值元组，包括 MIB 版本号和 MIB 目标字符串（在本例中为`sysDescr`；这是指系统的描述）。

该命令的输出由一个四值元组组成。其中三个与命令生成器返回的错误有关，第四个与绑定返回数据的实际变量有关。

以下示例显示了如何使用前面的方法从运行的 SNMP 守护程序中获取 SNMP 主机描述字符串：

```py
from pysnmp.entity.rfc3413.oneliner import cmdgen

SNMP_HOST = 'localhost'
SNMP_PORT = 161
SNMP_COMMUNITY = 'public'

if __name__ == '__manin__':
    cmd_generator = cmdgen.CommandGenerator()

    error_notify, error_status, error_index, var_binds = cmd_generator.getCmd(
        cmdgen.CommunityData(SNMP_COMMUNITY),
        cmdgen.UdpTransportTarget((SNMP_HOST, SNMP_PORT)),
        cmdgen.MibVariable('SNMPv2-MIB', 'sysDescr', 0),
        lookupNames=True, lookupValues=True
    )

    # Check for errors and print out results
    if error_notify:
        print(error_notify)
    elif error_status:
        print(error_status)
    else:
        for name, val in var_binds:
            print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
```

运行上述示例后，将出现类似以下的输出：

```py
**$  python 5_4_snmp_read.py**
**SNMPv2-MIB::sysDescr."0" = Linux debian6box 2.6.32-5-686 #1 SMP Tue May 13 16:33:32 UTC 2014 i686**

```

## 检查 SNMP 数据包

我们可以通过捕获网络接口的端口 161 上的数据包来检查 SNMP 数据包。如果服务器在本地运行，则仅需监听`loopbook`接口即可。Wireshak 生成的`snmp-get`请求格式和`snmp-get`响应数据包格式如下截图所示：

![检查 SNMP 数据包](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_07.jpg)

作为对客户端的 SNMP 获取请求的响应，服务器将生成一个 SNMP 获取响应。这可以在以下截图中看到：

![检查 SNMP 数据包](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_08.jpg)

# 读取轻量级目录访问协议数据

长期以来，LDAP 一直被用于访问和管理分布式目录信息。这是一个在 IP 网络上运行的应用级协议。目录服务在组织中被广泛用于管理有关用户、计算机系统、网络、应用程序等信息。LDAP 协议包含大量的技术术语。它是基于客户端/服务器的协议。因此，LDAP 客户端将向正确配置的 LDAP 服务器发出请求。在初始化 LDAP 连接后，连接将需要使用一些参数进行身份验证。简单的绑定操作将建立 LDAP 会话。在简单情况下，您可以设置一个简单的匿名绑定，不需要密码或其他凭据。

如果您使用`ldapsearch`运行简单的 LDAP 查询，那么您将看到如下结果：

```py
**# ldapsearch  -x -b "dc=localdomain,dc=loc" -h 10.0.2.15 -p 389**

**# extended LDIF**
**#**
**# LDAPv3**
**# base <dc=localdomain,dc=loc> with scope subtree**
**# filter: (objectclass=*)**
**# requesting: ALL**
**#**

**# localdomain.loc**
**dn: dc=localdomain,dc=loc**
**objectClass: top**
**objectClass: dcObject**
**objectClass: organization**
**o: localdomain.loc**
**dc: localdomain**

**# admin, localdomain.loc**
**dn: cn=admin,dc=localdomain,dc=loc**
**objectClass: simpleSecurityObject**
**objectClass: organizationalRole**
**cn: admin**
**description: LDAP administrator**
**# groups, localdomain.loc**
**dn: ou=groups,dc=localdomain,dc=loc**
**ou: groups**
**objectClass: organizationalUnit**
**objectClass: top**

**# users, localdomain.loc**
**dn: ou=users,dc=localdomain,dc=loc**
**ou: users**
**objectClass: organizationalUnit**
**objectClass: top**

**# admin, groups, localdomain.loc**
**dn: cn=admin,ou=groups,dc=localdomain,dc=loc**
**cn: admin**
**gidNumber: 501**
**objectClass: posixGroup**

**# Faruque Sarker, users, localdomain.loc**
**dn: cn=Faruque Sarker,ou=users,dc=localdomain,dc=loc**
**givenName: Faruque**
**sn: Sarker**
**cn: Faruque Sarker**
**uid: fsarker**
**uidNumber: 1001**
**gidNumber: 501**
**homeDirectory: /home/users/fsarker**
**loginShell: /bin/sh**
**objectClass: inetOrgPerson**
**objectClass: posixAccount**

**# search result**
**search: 2**
**result: 0 Success**

**# numResponses: 7**
**# numEntries: 6**

```

前面的通信可以通过 Wireshark 来捕获。您需要在端口 389 上捕获数据包。如下截图所示，在成功发送`bindRequest`之后，LDAP 客户端-服务器通信将建立。以匿名方式与 LDAP 服务器通信是不安全的。为了简单起见，在下面的示例中，搜索是在不绑定任何凭据的情况下进行的。

![阅读轻量级目录访问协议数据](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_09.jpg)

Python 的第三方`python-ldap`软件包提供了与 LDAP 服务器交互所需的功能。您可以使用`pip`安装此软件包。

```py
**$ pip install python-ldap**

```

首先，您需要初始化 LDAP 连接：

```py
import ldap
   ldap_client = ldap.initialize("ldap://10.0.2.15:389/")
```

然后以下代码将展示如何执行简单的绑定操作：

```py
  ldap_client.simple_bind("dc=localdomain,dc=loc")
```

然后您可以执行 LDAP 搜索。您需要指定必要的参数，如基本 DN、过滤器和属性。以下是在 LDAP 服务器上搜索用户所需的语法示例：

```py
ldap_client.search_s( base_dn, ldap.SCOPE_SUBTREE, filter, attrs )
```

以下是使用 LDAP 协议查找用户信息的完整示例：

```py
import ldap

# Open a connection
ldap_client = ldap.initialize("ldap://10.0.2.15:389/")

# Bind/authenticate with a user with apropriate rights to add objects

ldap_client.simple_bind("dc=localdomain,dc=loc")

base_dn = 'ou=users,dc=localdomain,dc=loc'
filter = '(objectclass=person)'
attrs = ['sn']

result = ldap_client.search_s( base_dn, ldap.SCOPE_SUBTREE, filter, attrs )
print(result)
```

前面的代码将搜索 LDAP 目录子树，使用`ou=users,dc=localdomain,dc=loc`基本`DN`和`[sn]`属性。搜索限定为人员对象。

## 检查 LDAP 数据包

如果我们分析 LDAP 客户端和服务器之间的通信，我们可以看到 LDAP 搜索请求和响应的格式。我们在我们的代码中使用的参数与 LDAP 数据包的`searchRequest`部分有直接关系。如 Wireshark 生成的以下截图所示，它包含数据，如`baseObject`、`scope`和`Filter`。

![检查 LDAP 数据包](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_10.jpg)

LDAP 搜索请求生成服务器响应，如下所示：

![检查 LDAP 数据包](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_11.jpg)

当 LDAP 服务器返回搜索响应时，我们可以看到响应的格式。如前面的截图所示，它包含了搜索结果和相关属性。

以下是从 LDAP 服务器搜索用户的示例：

```py
#!/usr/bin/env python
import ldap
import ldap.modlist as modlist

LDAP_URI = "ldap://10.0.2.15:389/"
BIND_TO = "dc=localdomain,dc=loc"
BASE_DN = 'ou=users,dc=localdomain,dc=loc'
SEARCH_FILTER = '(objectclass=person)'
SEARCH_FILTER = ['sn']

if __name__ == '__main__':
    # Open a connection
    l = ldap.initialize(LDAP_URI)
    # bind to the server
    l.simple_bind(BIND_TO)
    result = l.search_s( BASE_DN, ldap.SCOPE_SUBTREE, SEARCH_FILTER, SEARCH_FILTER )
    print(result)
```

在正确配置的 LDAP 机器中，前面的脚本将返回类似以下的结果：

```py
**$ python 5_5_ldap_read_record.py**
**[('cn=Faruque Sarker,ou=users,dc=localdomain,dc=loc', {'sn': ['Sarker']})]**

```

# 使用 SAMBA 共享文件

在局域网环境中，您经常需要在不同类型的机器之间共享文件，例如 Windows 和 Linux 机器。用于在这些机器之间共享文件和打印机的协议是**服务器消息块**（**SMB**）协议或其增强版本称为**公共互联网文件系统**（**CIFS**）协议。CIFS 运行在 TCP/IP 上，由 SMB 客户端和服务器使用。在 Linux 中，您会发现一个名为 Samba 的软件包，它实现了`SMB`协议。

如果您在 Windows 框中运行 Linux 虚拟机，并借助软件（如 VirtualBox）进行文件共享测试，则可以在 Windows 机器上创建一个名为`C:\share`的文件夹，如下屏幕截图所示：

![使用 SAMBA 共享文件](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_12.jpg)

现在，右键单击文件夹，然后转到**共享**选项卡。有两个按钮：**共享**和**高级共享**。您可以单击后者，它将打开高级共享对话框。现在您可以调整共享权限。如果此共享处于活动状态，则您将能够从 Linux 虚拟机中看到此共享。如果在 Linux 框中运行以下命令，则将看到先前定义的文件共享：

```py
**$smbclient -L 10.0.2.2 -U WINDOWS_USERNAME%PASSWPRD  -W WORKGROUP**
**Domain=[FARUQUESARKER] OS=[Windows 8 9200] Server=[Windows 8 6.2]**

 **Sharename       Type      Comment**
 **---------       ----      -------**
 **ADMIN$          Disk      Remote Admin**
 **C$              Disk      Default share**
 **IPC$            IPC       Remote IPC**
 **Share           Disk**

```

以下屏幕截图显示了如何在 Windows 7 下共享文件夹，如前所述：

![使用 SAMBA 共享文件](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_13.jpg)

可以使用第三方模块`pysmb`从 Python 脚本访问前面的文件共享。您可以使用`pip`命令行工具安装`pysmb`：

```py
**$ pip install pysmb**

```

该模块提供了一个`SMBConnection`类，您可以通过该类传递必要的参数来访问 SMB/CIFS 共享。例如，以下代码将帮助您访问文件共享：

```py
from smb.SMBConnection import SMBConnection
smb_connection = SMBConnection(username, password, client_machine_name, server_name, use_ntlm_v2 = True, domain='WORKGROUP', is_direct_tcp=True)
```

如果前面的工作正常，则以下断言将为真：

```py
assert smb_connection.connect(server_ip, 445)
```

您可以使用`listShares()`方法列出共享文件：

```py
shares =  smb_connection.listShares()
for share in shares:
    print share.name
```

如果您可以使用`tmpfile`模块从 Windows 共享复制文件。例如，如果您在`C:\Share\test.rtf`路径中创建一个文件，则以下附加代码将使用 SMB 协议复制该文件：

```py
import tempfile
files = smb_connection.listPath(share.name, '/')

for file in files:
    print file.filename

file_obj = tempfile.NamedTemporaryFile()
file_attributes, filesize = smb_connection.retrieveFile('Share', '/test.rtf', file_obj)
file_obj.close()
```

如果我们将整个代码放入单个源文件中，它将如下所示：

```py
#!/usr/bin/env python
import tempfile
from smb.SMBConnection import SMBConnection

SAMBA_USER_ID = 'FaruqueSarker'
PASSWORD = 'PASSWORD'
CLIENT_MACHINE_NAME = 'debian6box'
SAMBA_SERVER_NAME = 'FARUQUESARKER'
SERVER_IP = '10.0.2.2'
SERVER_PORT = 445
SERVER_SHARE_NAME = 'Share'
SHARED_FILE_PATH = '/test.rtf'

if __name__ == '__main__':

    smb_connection = SMBConnection(SAMBA_USER_ID, PASSWORD, CLIENT_MACHINE_NAME, SAMBA_SERVER_NAME, use_ntlm_v2 = True, domain='WORKGROUP', is_direct_tcp=True)
    assert smb_connection.smb_connectionect(SERVER_IP, SERVER_PORT = 445)
    shares =  smb_connection.listShares()

    for share in shares:
        print share.name

    files = smb_connection.listPath(share.name, '/')
    for file in files:
        print file.filename

    file_obj = tempfile.NamedTemporaryFile()
    file_attributes, filesize = smb_connection.retrieveFile(SERVER_SHARE_NAME, SHARED_FILE_PATH, file_obj)

    # Retrieved file contents are inside file_obj
    file_obj.close()
```

## 检查 SAMBA 数据包

如果我们在端口`445`上捕获 SMABA 数据包，则可以看到 Windows 服务器如何通过 CIFS 协议与 Linux SAMBA 客户端进行通信。在以下两个屏幕截图中，已呈现了客户端和服务器之间的详细通信。连接设置如下截图所示：

![检查 SAMBA 数据包](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_14.jpg)

以下屏幕截图显示了如何执行文件复制会话：

![检查 SAMBA 数据包](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_15.jpg)

以下屏幕截图显示了典型的 SAMBA 数据包格式。此数据包的重要字段是`NT_STATUS`字段。通常，如果连接成功，则会显示`STATUS_SUCESS`。否则，它将打印不同的代码。如下屏幕截图所示：

![检查 SAMBA 数据包](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_05_16.jpg)

# 总结

在本章中，我们已经接触了几种网络协议和 Python 库，用于与远程系统进行交互。SSH 和 SFTP 用于安全连接和传输文件到远程主机。FTP 仍然用作简单的文件传输机制。但是，由于用户凭据以明文形式传输，因此不安全。我们还研究了处理 SNMP、LDAP 和 SAMBA 数据包的 Python 库。

在下一章中，将讨论最常见的网络协议之一，即 DNS 和 IP。我们将使用 Python 脚本探索 TCP/IP 网络。


# 第六章：IP 和 DNS

连接到网络的每台计算机都需要一个 IP 地址。在第一章中，介绍了 TCP/IP 网络编程。IP 地址使用数字标识符标记机器的网络接口，也标识了机器的位置，尽管可靠性有限。**域名系统**（**DNS**）是一种核心网络服务，将名称映射到 IP 地址，反之亦然。在本章中，我们将主要关注使用 Python 操作 IP 和 DNS 协议。除此之外，我们还将简要讨论**网络时间协议**（**NTP**），它有助于将时间与集中式时间服务器同步。以下主题将在此处讨论：

+   检索本地计算机的网络配置

+   操作 IP 地址

+   GeoIP 查找

+   使用 DNS

+   使用 NTP

# 检索本地计算机的网络配置

在做任何其他事情之前，让我们用 Python 语言问一下，*我的名字是什么？*。在网络术语中，这相当于找出机器的名称或主机的名称。在 shell 命令行上，可以使用`hostname`命令来发现这一点。在 Python 中，您可以使用 socket 模块来实现这一点。

```py
**>>> import socket**
**>>> socket.gethostname()**
**'debian6box.localdomain.loc'**

```

现在，我们想要查看本地计算机的 IP。这可以通过在 Linux 中使用`ifconfig`命令和在 Windows OS 中使用`ipconfig`命令来实现。但是，我们想要使用以下内置函数在 Python 中执行此操作：

```py
**>>> socket.gethostbyname('debian6box.localdomain.loc')**
**'10.0.2.15'**

```

如您所见，这是第一个网络接口的 IP。如果您的 DNS 或主机文件未正确配置，它还可以显示我们的环回接口（127.0.0.1）的 IP。在 Linux/UNIX 中，可以将以下行添加到您的`/etc/hosts`文件中以获取正确的 IP 地址：

```py
10.0.2.15       debian6box.localdomain.loc      debian6box
```

这个过程被称为基于主机文件的名称解析。您可以向 DNS 服务器发送查询，询问特定主机的 IP 地址。如果名称已经正确注册，那么您将从服务器收到响应。但是，在向远程服务器发出查询之前，让我们先了解一些关于网络接口和网络的更多信息。

在每个局域网中，主机被配置为充当网关，与*外部*世界通信。为了找到网络地址和子网掩码，我们可以使用 Python 第三方库 netifaces（版本> 0.10.0）。这将提取所有相关信息。例如，您可以调用`netifaces.gateways()`来查找配置为外部世界的网关。同样，您可以通过调用`netifaces.interfaces()`来枚举网络接口。如果您想要知道特定接口*eth0*的所有 IP 地址，那么可以调用`netifaces.ifaddresses('eth0')`。以下代码清单显示了如何列出本地计算机的所有网关和 IP 地址：

```py
#!/usr/bin/env python
import socket
import netifaces

if __name__ == '__main__':    
    # Find host info
    host_name = socket.gethostname()
    ip_address = socket.gethostbyname(host_name)
    print("Host name: {0}".format(host_name))

    # Get interfaces list
    ifaces = netifaces.interfaces()
    for iface in ifaces:
        ipaddrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in ipaddrs:
            ipaddr_desc = ipaddrs[netifaces.AF_INET]
            ipaddr_desc = ipaddr_desc[0]
            print("Network interface: {0}".format(iface))
            print("\tIP address: {0}".format(ipaddr_desc['addr']))
            print("\tNetmask: {0}".format(ipaddr_desc['netmask']))
    # Find the gateway
    gateways = netifaces.gateways()
    print("Default gateway: {0}".format(gateways['default'][netifaces.AF_INET][0]))
```

如果您运行此代码，则会打印本地网络配置的摘要，类似于以下内容：

```py
**$ python 6_1_local_network_config.py**
**Host name: debian6box**
**Network interface: lo**
 **IP address: 127.0.0.1**
 **Netmask: 255.0.0.0**
**Network interface: eth0**
 **IP address: 10.0.2.15**
 **Netmask: 255.255.255.0**
**Default gateway: 10.0.2.2**

```

# 操作 IP 地址

通常，您需要操作 IP 地址并对其执行某种操作。Python3 具有内置的`ipaddress`模块，可帮助您执行此任务。它具有方便的函数来定义 IP 地址和 IP 网络，并查找许多有用的信息。例如，如果您想知道给定子网中存在多少 IP 地址，例如`10.0.1.0/255.255.255.0`或`10.0.2.0/24`，则可以使用此处显示的代码片段找到它们。此模块将提供几个类和工厂函数；例如，IP 地址和 IP 网络具有单独的类。每个类都有 IP 版本 4（IPv4）和 IP 版本 6（IPv6）的变体。以下部分演示了一些功能：

## IP 网络对象

让我们导入`ipaddress`模块并定义一个`net4`网络。

```py
**>>> import ipaddress as ip**
**>>> net4 = ip.ip_network('10.0.1.0/24')**

```

现在，我们可以找到一些有用的信息，比如`net4`的`netmask`、网络/广播地址等：

```py
**>>> net4.netmask**
**IP4Address(255.255.255.0)**

```

`net4`的`netmask`属性将显示为`IP4Address`对象。如果您正在寻找其字符串表示形式，则可以调用`str()`方法，如下所示：

```py
**>>> str(net4.netmask)**
**'255.255.255.0'**

```

同样，您可以通过执行以下操作找到`net4`的网络和广播地址：

```py
**>>> str(net4.network_address)**
**10.0.1.0**
**>>> str(net4.broadcast_address)**
**10.0.1.255**

```

`net4`总共有多少个地址？这可以通过使用以下命令找到：

```py
**>>> net4.num_addresses**
**256**

```

因此，如果我们减去网络和广播地址，那么总共可用的 IP 地址将是 254。我们可以在`net4`对象上调用`hosts()`方法。它将生成一个 Python 生成器，它将提供所有主机作为`IPv4Adress`对象。

```py
**>>> all_hosts = list(net4.hosts())**
**>>> len(all_hosts)**
**254**

```

您可以通过遵循标准的 Python 列表访问表示法来访问单个 IP 地址。例如，第一个 IP 地址将是以下内容：

```py
**>>> all_hosts[0]**
**IPv4Address('10.0.1.1')**

```

您可以通过使用列表表示法来访问最后一个 IP 地址，如下所示：

```py
**>>> all_hosts[-1]**
**IPv4Address('10.0.1.1')**

```

我们还可以从`IPv4Network`对象中找到子网信息，如下所示：

```py
**>>> subnets = list( net4.subnets())**
**>>> subnets**
**[ IPv4Network('10.0.1.0/25'), IPv4Network('10.0.1.128/25')  ]**

```

任何`IPv4Network`对象都可以告诉关于其父超网的信息，这与子网相反。

```py
**>>> net4.supernet()**
**IPv4Network('10.0.1.0/23')**

```

## 网络接口对象

在`ipaddress`模块中，一个方便的类用于详细表示接口的 IP 配置。IPv4 Interface 类接受任意地址并表现得像一个网络地址对象。让我们定义并讨论我们的网络接口`eth0`，如下截图所示：

![网络接口对象](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_06_01.jpg)

正如您在前面的截图中所看到的，已经定义了一个带有`IPv4Address`类的网络接口 eth0。它具有一些有趣的属性，例如 IP、网络地址等。与网络对象一样，您可以检查地址是否为私有、保留或多播。这些地址范围已在各种 RFC 文档中定义。`ipaddress`模块的帮助页面将向您显示这些 RFC 文档的链接。您也可以在其他地方搜索这些信息。

## IP 地址对象

IP 地址类有许多其他有趣的属性。您可以对这些对象执行一些算术和逻辑操作。例如，如果一个 IP 地址大于另一个 IP 地址，那么您可以向 IP 地址对象添加数字，这将给您一个相应的 IP 地址。让我们在以下截图中看到这个演示：

![IP 地址对象](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_06_02.jpg)

`ipaddress`模块的演示

在这里，已经定义了带有私有 IP 地址`192.168.1.1`的`eth0`接口，以及已经定义了另一个私有 IP 地址`192.168.2.1`的`eth1`。同样，回环接口`lo`定义为 IP 地址`127.0.0.1`。正如您所看到的，您可以向 IP 地址添加数字，它将给您相同序列的下一个 IP 地址。

您可以检查 IP 是否属于特定网络。在这里，网络 net 是由网络地址`192.168.1.0/24`定义的，并且已经测试了`eth0`和`eth1`的成员资格。还在这里测试了一些其他有趣的属性，比如`is_loopback`，`is_private`等。

## 为您的本地区域网络规划 IP 地址

如果您想知道如何选择合适的 IP 子网，那么您可以尝试使用`ipaddress`模块。以下代码片段将展示如何根据小型私有网络所需的主机 IP 地址数量选择特定子网的示例：

```py
#!/usr/bin/env python
import ipaddress as ip

CLASS_C_ADDR = '192.168.0.0'

if __name__ == '__main__':
    not_configed = True
    while not_configed:
        prefix = input("Enter the prefixlen (24-30): ")
        prefix = int(prefix)
        if prefix not in range(23, 31):
            raise Exception("Prefixlen must be between 24 and 30")
        net_addr = CLASS_C_ADDR + '/' + str(prefix)
        print("Using network address:%s " %net_addr)
        try:
            network = ip.ip_network(net_addr)
        except:
            raise Exception("Failed to create network object")
        print("This prefix will give %s IP addresses" %(network.num_addresses))
        print("The network configuration will be")
        print("\t network address: %s" %str(network.network_address))
        print("\t netmask: %s" %str(network.netmask))
        print("\t broadcast address: %s" %str(network.broadcast_address))
        first_ip, last_ip = list(network.hosts())[0], list(network.hosts())[-1] 
        print("\t host IP addresses: from %s to %s" %(first_ip, last_ip))
        ok = input("Is this configuration OK [y/n]? ")
        ok = ok.lower()
        if ok.strip() == 'y':
            not_configed = False
```

如果您运行此脚本，它将显示类似以下内容的输出：

```py
**# python 6_2_net_ip_planner.py** 
**Enter the prefixlen (24-30): 28**
**Using network address:192.168.0.0/28** 
**This prefix will give 16 IP addresses**
**The network configuration will be**
 **network address: 192.168.0.0**
 **netmask: 255.255.255.240**
 **broadcast address: 192.168.0.15**
 **host IP addresses: from 192.168.0.1 to 192.168.0.14**
**Is this configuration OK [y/n]? n**
**Enter the prefixlen (24-30): 26**
**Using network address:192.168.0.0/26** 
**This prefix will give 64 IP addresses**
**The network configuration will be**
 **network address: 192.168.0.0**
 **netmask: 255.255.255.192**
 **broadcast address: 192.168.0.63**
 **host IP addresses: from 192.168.0.1 to 192.168.0.62**
**Is this configuration OK [y/n]? y**

```

# GeoIP 查找

有时，许多应用程序需要查找 IP 地址的位置。例如，许多网站所有者可能对跟踪其访问者的位置以及根据国家、城市等标准对其 IP 进行分类感兴趣。有一个名为**python-geoip**的第三方库，它具有一个强大的接口，可以为您提供 IP 位置查询的答案。这个库由 MaxMind 提供，还提供了将最新版本的 Geolite2 数据库作为`python-geoip-geolite2`软件包进行发布的选项。这包括由 MaxMind 创建的 GeoLite2 数据，可在[www.maxmind.com](http://www.maxmind.com)上以知识共享署名-相同方式共享 3.0 未本地化许可证下获得。您也可以从他们的网站购买商业许可证。

让我们看一个如何使用这个 Geo-lookup 库的例子：

```py
import socket
from geoip import geolite2
import argparse

if __name__ == '__main__':
    # Setup commandline arguments
    parser = argparse.ArgumentParser(description='Get IP Geolocation info')
    parser.add_argument('--hostname', action="store", dest="hostname", required=True)

    # Parse arguments
    given_args = parser.parse_args()
    hostname =  given_args.hostname
    ip_address = socket.gethostbyname(hostname)
    print("IP address: {0}".format(ip_address))

    match = geolite2.lookup(ip_address)
    if match is not None:
        print('Country: ',match.country)
        print('Continent: ',match.continent) 
        print('Time zone: ', match.timezone) 
```

此脚本将显示类似以下的输出：

```py
**$ python 6_3_geoip_lookup.py --hostname=amazon.co.uk**
**IP address: 178.236.6.251**
**Country:  IE**
**Continent:  EU**
**Time zone:  Europe/Dublin**

```

您可以从开发者网站[`pythonhosted.org/python-geoip/`](http://pythonhosted.org/python-geoip/)上找到有关此软件包的更多信息。

## DNS 查找

IP 地址可以被翻译成称为域名的人类可读字符串。DNS 是网络世界中的一个重要主题。在本节中，我们将在 Python 中创建一个 DNS 客户端，并看看这个客户端将如何通过使用 Wirshark 与服务器通信。

PyPI 提供了一些 DNS 客户端库。我们将重点关注`dnspython`库，该库可在[`www.dnspython.org/`](http://www.dnspython.org/)上找到。您可以使用`easy_install`命令或`pip`命令安装此库：

```py
**$ pip install dnspython**

```

对主机的 IP 地址进行简单查询非常简单。您可以使用`dns.resolver`子模块，如下所示：

```py
**import dns.resolver**
**answers = dns.resolver.query('python.org', 'A')**
**for rdata in answers:**
 **print('IP', rdata.to_text())**

```

如果您想进行反向查找，那么您需要使用`dns.reversename`子模块，如下所示：

```py
**import dns.reversename**
**name = dns.reversename.from_address("127.0.0.1")**
**print name**
**print dns.reversename.to_address(name)**

```

现在，让我们创建一个交互式 DNS 客户端脚本，它将完成可能的记录查找，如下所示：

```py
import dns.resolver

if __name__ == '__main__':
    loookup_continue = True
    while loookup_continue:
        name = input('Enter the DNS name to resolve: ')
        record_type = input('Enter the query type [A/MX/CNAME]: ')
        answers = dns.resolver.query(name, record_type)
        if record_type == 'A':
            print('Got answer IP address: %s' %[x.to_text() for x in answers])
        elif record_type == 'CNAME':
            print('Got answer Aliases: %s' %[x.to_text() for x in answers])
        elif record_type == 'MX':
            for rdata in answers:
                print('Got answers for Mail server records:')
                print('Mailserver', rdata.exchange.to_text(), 'has preference', rdata.preference)
            print('Record type: %s is not implemented' %record_type)
        lookup_more = input("Do you want to lookup more records? [y/n]: " )
        if lookup_more.lower() == 'n':
            loookup_continue = False
```

如果您使用一些输入运行此脚本，那么您将得到类似以下的输出：

```py
**$ python 6_4_dns_client.py** 
**Enter the DNS name to resolve: google.com**
**Enter the query type [A/MX/CNAME]: MX**
**Got answers for Mail server records:**
**Mailserver alt4.aspmx.l.google.com. has preference 50**
**Got answers for Mail server records:**
**Mailserver alt2.aspmx.l.google.com. has preference 30**
**Got answers for Mail server records:**
**Mailserver alt3.aspmx.l.google.com. has preference 40**
**Got answers for Mail server records:**
**Mailserver aspmx.l.google.com. has preference 10**
**Got answers for Mail server records:**
**Mailserver alt1.aspmx.l.google.com. has preference 20**
**Do you want to lookup more records? [y/n]: y**
**Enter the DNS name to resolve: www.python.org**
**Enter the query type [A/MX/CNAME]: A**
**Got answer IP address: ['185.31.18.223']**
**Do you want to lookup more records? [y/n]: y**
**Enter the DNS name to resolve: pypi.python.org**
**Enter the query type [A/MX/CNAME]: CNAME**
**Got answer Aliases: ['python.map.fastly.net.']**
**Do you want to lookup more records? [y/n]: n**

```

## 检查 DNS 客户端/服务器通信

在以前的章节中，也许您注意到我们如何通过使用 Wireshark 捕获客户端和服务器之间的网络数据包。这是一个示例，显示了从 PyPI 安装 Python 软件包时的会话捕获：

![检查 DNS 客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_06_03.jpg)

FDNS 客户端/服务器通信

在 Wireshark 中，您可以通过导航到**捕获** | **选项** | **捕获过滤器**来指定`端口 53`。这将捕获所有发送到/从您的计算机的 DNS 数据包。

如您在以下截图中所见，客户端和服务器有几个请求/响应周期的 DNS 记录。它是从对主机地址（A）的标准请求开始的，然后是一个合适的响应。

![检查 DNS 客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_06_04.jpg)

如果您深入查看数据包，您可以看到来自服务器的响应的请求格式，如下截图所示：

![检查 DNS 客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_06_05.jpg)

# NTP 客户端

本章将涵盖的最后一个主题是 NTP。与集中式时间服务器同步时间是任何企业网络中的关键步骤。我们想要比较各个服务器之间的日志文件，并查看每个服务器上的时间戳是否准确；日志事件可能不会相互关联。许多认证协议，如 Kerberos，严格依赖于客户端报告给服务器的时间戳的准确性。在这里，将介绍第三方 Python `ntplib`库，然后调查 NTP 客户端和服务器之间的通信。

要创建一个 NTP 客户端，您需要调用 ntplib 的`NTPCLient`类。

```py
**import ntplib**
**from time import ctime**
**c = ntplib.NTPClient()**
**response = c.request('pool.ntp.org')**
**print ctime(response.tx_time)**

```

在这里，我们选择了`pool.ntp.org`，这是一个负载平衡的网络服务器。因此，一组 NTP 服务器将准备好响应客户端的请求。让我们从 NTP 服务器返回的响应中找到更多信息。

```py
import ntplib
from time import ctime

HOST_NAME = 'pool.ntp.org'

if __name__ == '__main__':
    params = {}
    client = ntplib.NTPClient()
    response = client.request(HOST_NAME)
    print('Received time: %s' %ctime(response.tx_time))
    print('ref_clock: ',ntplib.ref_id_to_text(response.ref_id, response.stratum))
    print('stratum: ',response.stratum)
    print('last_update: ', response.ref_time)
    print('offset:  %f' %response.offset)
    print('precision: ', response.precision)
    print('root_delay: %.6f' %response.root_delay)
    print('root_dispersion: %.6f' %response.root_dispersion)
```

详细的响应将如下所示：

```py
**$ python 6_5_ntp_client.py** 
**Received time: Sat Feb 28 17:08:29 2015**
**ref_clock:  213.136.0.252**
**stratum:  2**
**last_update:  1425142998.2**
**offset:  -4.777519**
**precision:  -23**
**root_delay: 0.019608**
**root_dispersion: 0.036987**

```

上述信息是 NTP 服务器提供给客户端的。这些信息可用于确定所提供的时间服务器的准确性。例如，stratum 值 2 表示 NTP 服务器将查询另一个具有直接附加时间源的 stratum 值 1 的 NTP 服务器。有关 NTP 协议的更多信息，您可以阅读[`tools.ietf.org/html/rfc958`](https://tools.ietf.org/html/rfc958)上的 RFC 958 文档，或访问[`www.ntp.org/`](http://www.ntp.org/)。

## 检查 NTP 客户端/服务器通信

您可以通过查看捕获的数据包来了解更多关于 NTP 的信息。为此，上述 NTP 客户端/服务器通信已被捕获，如下两个截图所示：

第一张截图显示了 NTP 客户端请求。如果您查看标志字段内部，您将看到客户端的版本号。

![检查 NTP 客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_06_06.jpg)

类似地，NTP 服务器的响应显示在以下截图中：

![检查 NTP 客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_06_07.jpg)

# 总结

在本章中，讨论了用于 IP 地址操作的标准 Python 库。介绍了两个第三方库`dnspython`和`ntplib`，分别用于与 DNS 和 NTP 服务器交互。正如您通过上述示例所看到的，这些库为您提供了与这些服务通信所需的接口。

在接下来的章节中，我们将介绍 Python 中的套接字编程。这是另一个对网络程序员来说非常有趣和受欢迎的主题。在那里，您将找到用于与 BSD 套接字编程的低级和高级 Python 库。


# 第七章：使用套接字进行编程

在 Python 中与各种客户端/服务器进行交互后，您可能会渴望为自己选择的任何协议创建自定义客户端和服务器。Python 在低级网络接口上提供了很好的覆盖。一切都始于 BSD 套接字接口。正如您可以想象的那样，Python 有一个`socket`模块，为您提供了与套接字接口一起工作所需的功能。如果您以前在 C/C++等其他语言中进行过套接字编程，您会喜欢 Python 的`socket`模块。

在本章中，我们将通过创建各种 Python 脚本来探索套接字模块。

本章的亮点如下：

+   套接字基础

+   使用 TCP 套接字

+   使用 UDP 套接字

+   TCP 端口转发

+   非阻塞套接字 I/O

+   使用 SSL/TLS 保护套接字

+   创建自定义 SSL 客户端/服务器

# 套接字基础

任何编程语言中的网络编程都可以从套接字开始。但是什么是套接字？简而言之，网络套接字是实体可以进行进程间通信的虚拟端点。例如，一台计算机中的一个进程与另一台计算机上的一个进程交换数据。我们通常将发起通信的第一个进程标记为客户端，后一个进程标记为服务器。

Python 有一种非常简单的方式来开始使用套接字接口。为了更好地理解这一点，让我们先了解一下整体情况。在下图中，显示了客户端/服务器交互的流程。这将让您了解如何使用套接字 API。

![套接字基础](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_01.jpg)

通过套接字进行客户端/服务器交互

在典型客户端和服务器之间的交互中，服务器进程必须做更多的工作，正如您可能已经想到的那样。创建套接字对象后，服务器进程将该套接字绑定到特定的 IP 地址和端口。这很像使用分机号的电话连接。在公司办公室中，新员工分配了他的办公电话后，通常会被分配一个新的分机号。因此，如果有人给这位员工打电话，可以使用他的电话号码和分机号建立连接。成功绑定后，服务器进程将开始监听新的客户端连接。对于有效的客户端会话，服务器进程可以接受客户端进程的请求。此时，我们可以说服务器和客户端之间的连接已经建立。

然后客户端/服务器进入请求/响应循环。客户端进程向服务器进程发送数据，服务器进程处理数据并返回响应给客户端。当客户端进程完成时，通过关闭连接退出。此时，服务器进程可能会回到监听状态。

上述客户端和服务器之间的交互是实际情况的一个非常简化的表示。实际上，任何生产服务器进程都有多个线程或子进程来处理来自成千上万客户端的并发连接，这些连接是通过各自的虚拟通道进行的。

# 使用 TCP 套接字

在 Python 中创建套接字对象非常简单。您只需要导入`socket`模块并调用`socket()`类：

```py
from socket import*
import socket

#create a TCP socket (SOCK_STREAM)
s = socket.socket(family=AF_INET, type=SOCK_STREAM, proto=0)
print('Socket created')
```

传统上，该类需要大量参数。以下是其中一些：

+   **套接字族**：这是套接字的域，例如`AF_INET`（大约 90％的互联网套接字属于此类别）或`AF_UNIX`，有时也会使用。在 Python 3 中，您可以使用`AF_BLUETOOTH`创建蓝牙套接字。

+   **套接字类型**：根据您的需求，您需要指定套接字的类型。例如，通过分别指定`SOCK_STREAM`和`SOCK_DGRAM`来创建基于 TCP 和 UDP 的套接字。

+   **协议**：这指定了套接字族和类型内协议的变化。通常，它被留空为零。

由于许多原因，套接字操作可能不成功。例如，如果作为普通用户没有权限访问特定端口，可能无法绑定套接字。这就是为什么在创建套接字或进行一些网络绑定通信时进行适当的错误处理是个好主意。

让我们尝试将客户端套接字连接到服务器进程。以下代码是一个连接到服务器套接字的 TCP 客户端套接字的示例：

```py
import socket
import sys 

if __name__ == '__main__':

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as err:
        print("Failed to crate a socket")
        print("Reason: %s" %str(err))
        sys.exit();

    print('Socket created')

    target_host = input("Enter the target host name to connect: ")
    target_port = input("Enter the target port: ") 

    try:
        sock.connect((target_host, int(target_port)))
        print("Socket Connected to %s on port: %s" %(target_host, target_port))
    sock.shutdown(2)
    except socket.error as err:
        print("Failed to connect to %s on port %s" %(target_host, target_port))
        print("Reason: %s" %str(err))
        sys.exit();
```

如果您运行上述的 TCP 客户端，将显示类似以下的输出：

```py
**# python 7_1_tcp_client_socket.py**
**Socket created**
**Enter the target host name to connect: 'www.python.org'**
**Enter the target port: 80**
**Socket Connected to www.python.org on port: 80**

```

然而，如果由于某种原因套接字创建失败，比如无效的 DNS，将显示类似以下的输出：

```py
**# python 7_1_tcp_client_socket.py**
**Socket created**
**Enter the target host name to connect: www.asgdfdfdkflakslalalasdsdsds.invalid**
**Enter the target port: 80**
**Failed to connect to www.asgdfdfdkflakslalalasdsdsds.invalid on port 80**
**Reason: [Errno -2] Name or service not known**

```

现在，让我们与服务器交换一些数据。以下代码是一个简单 TCP 客户端的示例：

```py
import socket

HOST = 'www.linux.org' # or 'localhost'
PORT = 80
BUFSIZ = 4096
ADDR = (HOST, PORT)

if __name__ == '__main__':
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(ADDR)

    while True:
        data = 'GET / HTTP/1.0\r\n\r\n'
        if not data:
            break
        client_sock.send(data.encode('utf-8'))
        data = client_sock.recv(BUFSIZ)
        if not data:
            break
        print(data.decode('utf-8'))

    client_sock.close()
```

如果您仔细观察，您会发现上述的代码实际上创建了一个从 Web 服务器获取网页的原始 HTTP 客户端。它发送一个 HTTP 的`GET`请求来获取主页：

```py
**# python 7_2_simple_tcp_client.py**
**HTTP/1.1 200 OK**
**Date: Sat, 07 Mar 2015 16:23:02 GMT**
**Server: Apache**
**Last-Modified: Mon, 17 Feb 2014 03:19:34 GMT**
**Accept-Ranges: bytes**
**Content-Length: 111**
**Connection: close**
**Content-Type: text/html**

**<html><head><META HTTP-EQUIV="refresh" CONTENT="0;URL=/cgi- sys/defaultwebpage.cgi"></head><body></body></html>**

```

## 检查客户端/服务器通信

通过交换网络数据包进行的客户端和服务器之间的交互可以使用任何网络数据包捕获工具进行分析，比如 Wireshark。您可以配置 Wireshark 通过端口或主机过滤数据包。在这种情况下，我们可以通过端口 80 进行过滤。您可以在**捕获** | **选项**菜单下找到选项，并在**捕获过滤器**选项旁边的输入框中输入`port 80`，如下面的屏幕截图所示：

![检查客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_02.jpg)

在**接口**选项中，我们选择捕获通过任何接口传递的数据包。现在，如果您运行上述的 TCP 客户端连接到[www.linux.org](http://www.linux.org/)，您可以在 Wireshark 中看到交换的数据包序列，如下面的屏幕截图所示：

![检查客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_03.jpg)

正如您所见，前三个数据包通过客户端和服务器之间的三次握手过程建立了 TCP 连接。我们更感兴趣的是第四个数据包，它向服务器发出了 HTTP 的`GET`请求。如果您双击所选行，您可以看到 HTTP 请求的详细信息，如下面的屏幕截图所示：

![检查客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_04.jpg)

如您所见，HTTP 的`GET`请求还有其他组件，比如`请求 URI`，版本等。现在您可以检查来自 Web 服务器的 HTTP 响应到您的客户端。它是在 TCP 确认数据包之后，也就是第六个数据包之后。在这里，服务器通常发送一个 HTTP 响应代码（在本例中是`200`），内容长度和数据或网页内容。这个数据包的结构如下面的屏幕截图所示：

![检查客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_05.jpg)

通过对客户端和服务器之间的交互进行上述分析，您现在可以在基本层面上理解当您使用 Web 浏览器访问网页时发生了什么。在下一节中，您将看到如何创建自己的 TCP 服务器，并检查个人 TCP 客户端和服务器之间的交互。

## TCP 服务器

正如您从最初的客户端/服务器交互图中所理解的，服务器进程需要进行一些额外的工作。它需要绑定到套接字地址并监听传入的连接。以下代码片段显示了如何创建一个 TCP 服务器：

```py
import socket
from time import ctime

HOST = 'localhost'
PORT = 12345
BUFSIZ = 1024
ADDR = (HOST, PORT)

if __name__ == '__main__':
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(ADDR)
    server_socket.listen(5)
    server_socket.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )

    while True:
        print('Server waiting for connection...')
        client_sock, addr = server_socket.accept()
        print('Client connected from: ', addr)

        while True:
            data = client_sock.recv(BUFSIZ)
            if not data or data.decode('utf-8') == 'END':
                break
            print("Received from client: %s" % data.decode('utf- 8'))
            print("Sending the server time to client: %s"  %ctime())
            try:
                client_sock.send(bytes(ctime(), 'utf-8'))
            except KeyboardInterrupt:
                print("Exited by user")
        client_sock.close()
    server_socket.close()
```

让我们修改之前的 TCP 客户端，向任何服务器发送任意数据。以下是一个增强型 TCP 客户端的示例：

```py
import socket

HOST = 'localhost'
PORT = 12345
BUFSIZ = 256

if __name__ == '__main__':
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = input("Enter hostname [%s]: " %HOST) or HOST
    port = input("Enter port [%s]: " %PORT) or PORT

    sock_addr = (host, int(port))
    client_sock.connect(sock_addr)

    payload = 'GET TIME'
    try:
        while True:
            client_sock.send(payload.encode('utf-8'))
            data = client_sock.recv(BUFSIZ)
            print(repr(data))
            more = input("Want to send more data to server[y/n] :")
            if more.lower() == 'y':
               payload = input("Enter payload: ")
            else:
                break
    except KeyboardInterrupt:
        print("Exited by user") 

    client_sock.close()
```

如果您在一个控制台中运行上述的 TCP 服务器，另一个控制台中运行 TCP 客户端，您可以看到客户端和服务器之间的以下交互。运行 TCP 服务器脚本后，您将得到以下输出：

```py
**# python 7_3_tcp_server.py** 
**Server waiting for connection...**
**Client connected from:  ('127.0.0.1', 59961)**
**Received from client: GET TIME**

**Sending the server time to client: Sun Mar 15 12:09:16 2015**
**Server waiting for connection...**

```

当您在另一个终端上运行 TCP 客户端脚本时，您将得到以下输出：

```py
**# python 7_4_tcp_client_socket_send_data.py** 
**Enter hostname [www.linux.org]: localhost**
**Enter port [80]: 12345**
**b'Sun Mar 15 12:09:16 2015'**
**Want to send more data to server[y/n] :n**

```

## 检查客户端/服务器交互

现在，您可以再次配置 Wireshark 来捕获数据包，就像上一节讨论的那样。但是，在这种情况下，您需要指定服务器正在侦听的端口（在上面的示例中是`12345`），如下面的屏幕截图所示：

![检查客户端/服务器交互](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_06.jpg)

由于我们在非标准端口上捕获数据包，Wireshark 不会在**数据**部分解码它（如上面屏幕截图的中间窗格所示）。但是，您可以在底部窗格上看到解码后的文本，服务器的时间戳显示在右侧。

# 使用 UDP 套接字

与 TCP 不同，UDP 不会检查交换的数据报中的错误。我们可以创建类似于 TCP 客户端/服务器的 UDP 客户端/服务器。唯一的区别是在创建套接字对象时，您必须指定`SOCK_DGRAM`而不是`SOCK_STREAM`。

让我们创建一个 UDP 服务器。使用以下代码创建 UDP 服务器：

```py
from socket import socket, AF_INET, SOCK_DGRAM
maxsize = 4096

sock = socket(AF_INET,SOCK_DGRAM)
sock.bind(('',12345))
while True:    
  data, addr = sock.recvfrom(maxsize)
    resp = "UDP server sending data"    
  sock.sendto(resp,addr)
```

现在，您可以创建一个 UDP 客户端，向 UDP 服务器发送一些数据，如下面的代码所示：

```py
from socket import socket, AF_INET, SOCK_DGRAM

MAX_SIZE = 4096
PORT = 12345

if __name__ == '__main__':
    sock = socket(AF_INET,SOCK_DGRAM)
    msg = "Hello UDP server"
    sock.sendto(msg.encode(),('', PORT))
    data, addr = sock.recvfrom(MAX_SIZE)
    print("Server says:")
    print(repr(data))
```

在上面的代码片段中，UDP 客户端发送一行文本`Hello UDP server`并从服务器接收响应。下面的屏幕截图显示了客户端发送到服务器的请求：

![使用 UDP 套接字](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_07.jpg)

下面的屏幕截图显示了服务器发送给客户端的响应。在检查 UDP 客户端/服务器数据包之后，我们可以很容易地看到 UDP 比 TCP 简单得多。它通常被称为无连接协议，因为没有涉及确认或错误检查。

![使用 UDP 套接字](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_08.jpg)

# TCP 端口转发

我们可以使用 TCP 套接字编程进行一些有趣的实验，比如设置 TCP 端口转发。这有很好的用例。例如，如果您在没有 SSL 能力进行安全通信的公共服务器上运行不安全的程序（FTP 密码可以在传输过程中以明文形式看到）。由于这台服务器可以从互联网访问，您必须确保密码是加密的，才能登录到服务器。其中一种方法是使用安全 FTP 或 SFTP。我们可以使用简单的 SSH 隧道来展示这种方法的工作原理。因此，您本地 FTP 客户端和远程 FTP 服务器之间的任何通信都将通过这个加密通道进行。

让我们运行 FTP 程序到同一个 SSH 服务器主机。但是从本地机器创建一个 SSH 隧道，这将给您一个本地端口号，并将直接连接您到远程 FTP 服务器守护程序。

Python 有一个第三方的`sshtunnel`模块，它是 Paramiko 的`SSH`库的包装器。以下是 TCP 端口转发的代码片段，显示了如何实现这个概念：

```py
import sshtunnel
from getpass import getpass

ssh_host = '192.168.56.101'
ssh_port = 22
ssh_user = 'YOUR_SSH_USERNAME'

REMOTE_HOST = '192.168.56.101'
REMOTE_PORT = 21

from sshtunnel import SSHTunnelForwarder
ssh_password = getpass('Enter YOUR_SSH_PASSWORD: ')

server = SSHTunnelForwarder(
    ssh_address=(ssh_host, ssh_port),
    ssh_username=ssh_user,
    ssh_password=ssh_password,
    remote_bind_address=(REMOTE_HOST, REMOTE_PORT))

server.start()
print('Connect the remote service via local port: %s'  %server.local_bind_port)
# work with FTP SERVICE via the `server.local_bind_port.
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Exiting user user request.\n")
    server.stop()
```

让我们捕获从本地机器`192.168.0.102`到远程机器`192.168.0.101`的数据包传输。您将看到所有网络流量都是加密的。当您运行上述脚本时，您将获得一个本地端口号。使用`ftp`命令连接到该本地端口号：

```py
**$ ftp <localhost> <local_bind_port>**

```

如果您运行上述命令，那么您将得到以下屏幕截图：

![TCP 端口转发](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_09.jpg)

在上面的屏幕截图中，您看不到任何 FTP 流量。正如您所看到的，首先我们连接到本地端口`5815`（参见前三个数据包），然后突然之间与远程主机建立了加密会话。您可以继续观察远程流量，但是没有 FTP 的痕迹。

如果您还可以在远程机器（`192.168.56.101`）上捕获数据包，您可以看到 FTP 流量，如下面的屏幕截图所示：

![TCP 端口转发](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_12.jpg)

有趣的是，您可以看到您的 FTP 密码从本地机器（通过 SSH 隧道）以明文形式发送到远程计算机，而不是通过网络发送，如下图所示：

TCP 端口转发

因此，您可以将任何敏感的网络流量隐藏在 SSL 隧道中。不仅 FTP，您还可以通过 SSH 通道加密传输远程桌面会话。

# 非阻塞套接字 I/O

在本节中，我们将看到一个小的示例代码片段，用于测试非阻塞套接字 I/O。如果您知道同步阻塞连接对您的程序不是必需的，这将非常有用。以下是非阻塞 I/O 的示例：

```py
import socket

if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(0)
    sock.settimeout(0.5)
    sock.bind(("127.0.0.1", 0))

    socket_address =sock.getsockname()
    print("Asynchronous socket server launched on socket: %s" %str(socket_address))
    while(1):
        sock.listen(1)
```

此脚本将以非阻塞方式运行套接字服务器并进行监听。这意味着您可以连接更多的客户端，他们不一定会因 I/O 而被阻塞。

# 使用 TLS/SSL 保护套接字

您可能已经遇到了使用**安全套接字层**（**SSL**）或更精确地说是**传输层安全**（**TLS**）进行安全网络通信的讨论，这已被许多其他高级协议采用。让我们看看如何使用 SSL 包装普通套接字连接。Python 具有内置的`ssl`模块，可以实现此目的。

在此示例中，我们希望创建一个普通的 TCP 套接字并连接到启用了 HTTPS 的 Web 服务器。然后，我们可以使用 SSL 包装该连接并检查连接的各种属性。例如，要检查远程 Web 服务器的身份，我们可以查看 SSL 证书中的主机名是否与我们期望的相同。以下是一个基于安全套接字的客户端的示例：

```py
import socket
import ssl
from ssl import wrap_socket, CERT_NONE, PROTOCOL_TLSv1, SSLError
from ssl import SSLContext
from ssl import HAS_SNI

from pprint import pprint

TARGET_HOST = 'www.google.com'
SSL_PORT = 443
# Use the path of CA certificate file in your system
CA_CERT_PATH = '/usr/local/lib/python3.3/dist- packages/requests/cacert.pem'

def ssl_wrap_socket(sock, keyfile=None, certfile=None, cert_reqs=None, ca_certs=None, server_hostname=None, ssl_version=None):

    context = SSLContext(ssl_version)
    context.verify_mode = cert_reqs

    if ca_certs:
        try:
            context.load_verify_locations(ca_certs)
        except Exception as e:
            raise SSLError(e)

    if certfile:
        context.load_cert_chain(certfile, keyfile)

    if HAS_SNI:  # OpenSSL enabled SNI
        return context.wrap_socket(sock, server_hostname=server_hostname)

    return context.wrap_socket(sock)

if __name__ == '__main__':
    hostname = input("Enter target host:") or TARGET_HOST
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((hostname, 443))

    ssl_socket = ssl_wrap_socket(client_sock, ssl_version=PROTOCOL_TLSv1, cert_reqs=ssl.CERT_REQUIRED, ca_certs=CA_CERT_PATH, server_hostname=hostname)

    print("Extracting remote host certificate details:")
    cert = ssl_socket.getpeercert()
    pprint(cert)
    if not cert or ('commonName', TARGET_HOST) not in cert['subject'][4]:
        raise Exception("Invalid SSL cert for host %s. Check if this is a man-in-the-middle attack!" )
    ssl_socket.write('GET / \n'.encode('utf-8'))
    #pprint(ssl_socket .recv(1024).split(b"\r\n"))
    ssl_socket.close()
    client_sock.close()
```

如果运行上述示例，您将看到远程 Web 服务器（例如[`www.google.com`](http://www.google.com)）的 SSL 证书的详细信息。在这里，我们创建了一个 TCP 套接字并将其连接到 HTTPS 端口`443`。然后，该套接字连接使用我们的`ssl_wrap_socket()`函数包装成 SSL 数据包。此函数将以下参数作为参数：

+   `sock`：TCP 套接字

+   `keyfile`：SSL 私钥文件路径

+   `certfile`：SSL 公共证书路径

+   `cert_reqs`：确认是否需要来自另一方的证书以建立连接，以及是否需要验证测试

+   `ca_certs`：公共证书颁发机构证书路径

+   `server_hostname`：目标远程服务器的主机名

+   `ssl_version`：客户端要使用的预期 SSL 版本

在 SSL 套接字包装过程开始时，我们使用`SSLContext()`类创建了一个 SSL 上下文。这是必要的，以设置 SSL 连接的特定属性。除了使用自定义上下文外，我们还可以使用`ssl`模块默认提供的默认上下文，使用`create_default_context()`函数。您可以使用常量指定是否要创建客户端或服务器端套接字。以下是创建客户端套接字的示例：

```py
context = ssl.create_default_context(Purpose.SERVER_AUTH)
```

`SSLContext`对象接受 SSL 版本参数，在我们的示例中设置为`PROTOCOL_TLSv1`，或者您应该使用最新版本。请注意，SSLv2 和 SSLv3 已经被破解，严重的安全问题不能在任何生产代码中使用。

在上面的示例中，`CERT_REQUIRED`表示连接需要服务器证书，并且稍后将验证此证书。

如果已提供 CA 证书参数并提供了证书路径，则使用`load_verify_locations()`方法加载 CA 证书文件。这将用于验证对等服务器证书。如果您想在系统上使用默认证书路径，您可能会调用另一个上下文方法；`load_default_certs(purpose=Purpose.SERVER_AUTH)`。

当我们在服务器端操作时，通常使用`load_cert_chain()`方法加载密钥和证书文件，以便客户端可以验证服务器的真实性。

最后，调用`wrap_socket()`方法返回一个 SSL 包装套接字。请注意，如果`OpenSSL`库启用了**服务器名称指示**（**SNI**）支持，您可以在包装套接字时传递远程服务器的主机名。当远程服务器使用不同的 SSL 证书为单个 IP 地址使用不同的安全服务，例如基于名称的虚拟主机时，这将非常有用。

如果运行上述 SSL 客户端代码，您将看到远程服务器的 SSL 证书的各种属性，如下图所示。这用于通过调用`getpeercert()`方法验证远程服务器的真实性，并将其与返回的主机名进行比较。

![使用 TLS/SSL 保护套接字](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_13.jpg)

有趣的是，如果任何其他虚假的 Web 服务器想要假冒 Google 的 Web 服务器，除非您检查由认可的证书颁发机构签署的 SSL 证书，否则它根本无法做到这一点，除非认可的 CA 已被破坏/颠覆。对您的 Web 浏览器进行的这种形式的攻击通常被称为**中间人**（**MITM**）攻击。

## 检查标准 SSL 客户端/服务器通信

以下屏幕截图显示了 SSL 客户端与远程服务器之间的交互：

![检查标准 SSL 客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_14.jpg)

让我们来看看客户端和服务器之间的 SSL 握手过程。在 SSL 握手的第一步中，客户端向远程服务器发送一个`Hello`消息，说明它在处理密钥文件、加密消息、进行消息完整性检查等方面的能力。在下面的屏幕截图中，您可以看到客户端向服务器呈现了一组`38`个密码套件，以选择相关的算法。它还发送了 TLS 版本号`1.0`和一个随机数，用于生成用于加密后续消息交换的主密钥。这有助于防止任何第三方查看数据包内容。在`Hello`消息中看到的随机数用于生成预主密钥，双方将进一步处理以得到主密钥，然后使用该密钥生成对称密钥。

![检查标准 SSL 客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_15.jpg)

在服务器发送到客户端的第二个数据包中，服务器选择了密码套件`TLS_ECDHE_RSA_WITH_RC4_128_SHA`以连接到客户端。这大致意味着服务器希望使用 RSA 算法处理密钥，使用 RC4 进行加密，并使用 SHA 进行完整性检查（哈希）。这在以下屏幕截图中显示：

![检查标准 SSL 客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_16.jpg)

在 SSL 握手的第二阶段，服务器向客户端发送 SSL 证书。如前所述，此证书由 CA 颁发。它包含序列号、公钥、有效期和主题和颁发者的详细信息。以下屏幕截图显示了远程服务器的证书。您能在数据包中找到服务器的公钥吗？

![检查标准 SSL 客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_17.jpg)

在握手的第三阶段，客户端交换密钥并计算主密钥以加密消息并继续进一步通信。客户端还发送更改在上一阶段达成的密码规范的请求。然后指示开始加密消息。以下屏幕截图显示了这个过程：

![检查标准 SSL 客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_18.jpg)

在 SSL 握手过程的最后一个任务中，服务器为客户端的特定会话生成了一个新的会话票证。这是由于 TLS 扩展引起的，客户端通过在客户端`Hello`消息中发送一个空的会话票证扩展来宣传其支持。服务器在其服务器`Hello`消息中回答一个空的会话票证扩展。这个会话票证机制使客户端能够记住整个会话状态，服务器在维护服务器端会话缓存方面变得不那么忙碌。以下截图显示了一个呈现 SSL 会话票证的示例：

![检查标准 SSL 客户端/服务器通信](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_19.jpg)

# 创建自定义 SSL 客户端/服务器

到目前为止，我们更多地处理 SSL 或 TLS 客户端。现在，让我们简要地看一下服务器端。由于您已经熟悉 TCP/UDP 套接字服务器创建过程，让我们跳过那部分，只集中在 SSL 包装部分。以下代码片段显示了一个简单 SSL 服务器的示例：

```py
import socket
import ssl

SSL_SERVER_PORT = 8000

if __name__ == '__main__':
    server_socket = socket.socket()
    server_socket.bind(('', SSL_SERVER_PORT))
    server_socket.listen(5)
    print("Waiting for ssl client on port %s" %SSL_SERVER_PORT)
    newsocket, fromaddr = server_socket.accept()
    # Generate your server's  public certificate and private key pairs.
    ssl_conn = ssl.wrap_socket(newsocket, server_side=True, certfile="server.crt", keyfile="server.key", ssl_version=ssl.PROTOCOL_TLSv1)
    print(ssl_conn.read())
    ssl_conn.write('200 OK\r\n\r\n'.encode())
    print("Served ssl client. Exiting...")
    ssl_conn.close()
    server_socket.close()
```

正如您所看到的，服务器套接字被`wrap_socket()`方法包装，该方法使用一些直观的参数，如`certfile`、`keyfile`和`SSL`版本号。您可以通过按照互联网上找到的任何逐步指南轻松生成证书。例如，[`www.akadia.com/services/ssh_test_certificate.html`](http://www.akadia.com/services/ssh_test_certificate.html)建议通过几个步骤生成 SSL 证书。

现在，让我们制作一个简化版本的 SSL 客户端，与上述 SSL 服务器进行通信。以下代码片段显示了一个简单 SSL 客户端的示例：

```py
from socket import socket
import ssl

from pprint import pprint

TARGET_HOST ='localhost'
TARGET_PORT = 8000
CA_CERT_PATH = 'server.crt'

if __name__ == '__main__':

    sock = socket()
    ssl_conn = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_TLSv1, ca_certs=CA_CERT_PATH)
    target_host = TARGET_HOST 
    target_port = TARGET_PORT 
    ssl_conn.connect((target_host, int(target_port)))
    # get remote cert
    cert = ssl_conn.getpeercert()
    print("Checking server certificate")
    pprint(cert)
    if not cert or ssl.match_hostname(cert, target_host):
        raise Exception("Invalid SSL cert for host %s. Check if this is a man-in-the-middle attack!" %target_host )
    print("Server certificate OK.\n Sending some custom request... GET ")
    ssl_conn.write('GET / \n'.encode('utf-8'))
    print("Response received from server:")
    print(ssl_conn.read())
    ssl_conn.close()
```

运行客户端/服务器将显示类似于以下截图的输出。您能否看到与我们上一个示例客户端/服务器通信相比有什么不同？

![创建自定义 SSL 客户端/服务器](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_20.jpg)

## 检查自定义 SSL 客户端/服务器之间的交互

让我们再次检查 SSL 客户端/服务器的交互，以观察其中的差异。第一个截图显示了整个通信序列。在以下截图中，我们可以看到服务器的`Hello`和证书合并在同一消息中。

![检查自定义 SSL 客户端/服务器之间的交互](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_21.jpg)

客户端的**客户端 Hello**数据包看起来与我们之前的 SSL 连接非常相似，如下截图所示：

![检查自定义 SSL 客户端/服务器之间的交互](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_22.jpg)

服务器的**服务器 Hello**数据包有点不同。您能识别出区别吗？密码规范不同，即`TLS_RSA_WITH_AES_256_CBC_SHA`，如下截图所示：

![检查自定义 SSL 客户端/服务器之间的交互](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_23.jpg)

**客户端密钥交换**数据包看起来也很熟悉，如下截图所示：

![检查自定义 SSL 客户端/服务器之间的交互](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_24.jpg)

以下截图显示了在此连接中提供的**新会话票证**数据包：

![检查自定义 SSL 客户端/服务器之间的交互](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_25.jpg)

现在让我们来看一下应用数据。那加密了吗？对于捕获的数据包，它看起来像垃圾。以下截图显示了隐藏真实数据的加密消息。这就是我们使用 SSL/TLS 想要实现的效果。

![检查自定义 SSL 客户端/服务器之间的交互](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/B03711_07_26.jpg)

# 总结

在本章中，我们讨论了使用 Python 的`socket`和`ssl`模块进行基本的 TCP/IP 套接字编程。我们演示了如何将简单的 TCP 套接字包装为 TLS，并用于传输加密数据。我们还发现了使用 SSL 证书验证远程服务器真实性的方法。还介绍了套接字编程中的一些其他小问题，比如非阻塞套接字 I/O。每个部分中的详细数据包分析帮助我们了解套接字编程练习中发生了什么。

在下一章中，我们将学习关于套接字服务器设计，特别是流行的多线程和事件驱动方法。


# 第八章：客户端和服务器应用程序

在上一章中，我们通过使用套接字接口来查看设备之间的数据交换。在本章中，我们将使用套接字来构建网络应用程序。套接字遵循计算机网络的主要模型之一，即**客户端/服务器**模型。我们将重点关注构建服务器应用程序。我们将涵盖以下主题：

+   设计一个简单的协议

+   构建回声服务器和客户端

+   构建聊天服务器和客户端

+   多线程和事件驱动的服务器架构

+   `eventlet`和`asyncio`库

本章的示例最好在 Linux 或 Unix 操作系统上运行。Windows 套接字实现有一些特殊之处，这可能会导致一些错误条件，我们在这里不会涉及。请注意，Windows 不支持我们将在一个示例中使用的`poll`接口。如果您使用 Windows，那么您可能需要使用*ctrl* + *break*来在控制台中终止这些进程，而不是使用*ctrl* - *c*，因为在 Windows 命令提示符中，当 Python 在套接字发送或接收时阻塞时，它不会响应*ctrl* - *c*，而在本章中这种情况会经常发生！（如果像我一样，不幸地尝试在没有*break*键的 Windows 笔记本上测试这些内容，那么请准备好熟悉 Windows 任务管理器的**结束任务**按钮）。

# 客户端和服务器

客户端/服务器模型中的基本设置是一个设备，即运行服务并耐心等待客户端连接并请求服务的服务器。一个 24 小时的杂货店可能是一个现实世界的类比。商店等待顾客进来，当他们进来时，他们请求某些产品，购买它们然后离开。商店可能会进行广告以便人们知道在哪里找到它，但实际的交易发生在顾客访问商店时。

一个典型的计算示例是一个 Web 服务器。服务器在 TCP 端口上监听需要其网页的客户端。例如，当客户端，例如 Web 浏览器，需要服务器托管的网页时，它连接到服务器然后请求该页面。服务器回复页面的内容，然后客户端断开连接。服务器通过具有主机名来进行广告，客户端可以使用该主机名来发现 IP 地址，以便连接到它。

在这两种情况下，都是客户端发起任何交互-服务器纯粹是对该交互的响应。因此，运行在客户端和服务器上的程序的需求是非常不同的。

客户端程序通常面向用户和服务之间的接口。它们检索和显示服务，并允许用户与之交互。服务器程序被编写为长时间运行，保持稳定，高效地向请求服务的客户端提供服务，并可能处理大量同时连接而对任何一个客户端的体验影响最小化。

在本章中，我们将通过编写一个简单的回声服务器和客户端来查看这个模型，然后将其升级为一个可以处理多个客户端会话的聊天服务器。Python 中的`socket`模块非常适合这项任务。

# 回声协议

在编写我们的第一个客户端和服务器程序之前，我们需要决定它们将如何相互交互，也就是说，我们需要为它们的通信设计一个协议。

我们的回声服务器应该保持监听，直到客户端连接并发送一个字节字符串，然后我们希望它将该字符串回显给客户端。我们只需要一些基本规则来做到这一点。这些规则如下：

1.  通信将通过 TCP 进行。

1.  客户端将通过创建套接字连接到服务器来启动回声会话。

1.  服务器将接受连接并监听客户端发送的字节字符串。

1.  客户端将向服务器发送一个字节字符串。

1.  一旦它发送了字节字符串，客户端将等待服务器的回复

1.  当服务器从客户端接收到字节字符串时，它将把字节字符串发送回客户端。

1.  当客户端从服务器接收了字节字符串后，它将关闭其套接字以结束会话。

这些步骤足够简单。这里缺少的元素是服务器和客户端如何知道何时发送了完整的消息。请记住，应用程序将 TCP 连接视为无尽的字节流，因此我们需要决定字节流中的什么将表示消息的结束。

## 框架

这个问题被称为**分帧**，我们可以采取几种方法来处理它。主要方法如下：

1.  将其作为协议规则，每次连接只发送一个消息，一旦发送了消息，发送方将立即关闭套接字。

1.  使用固定长度的消息。接收方将读取字节数，并知道它们有整个消息。

1.  在消息前加上消息的长度。接收方将首先从流中读取消息的长度，然后读取指示的字节数以获取消息的其余部分。

1.  使用特殊字符定界符指示消息的结束。接收方将扫描传入的流以查找定界符，并且消息包括定界符之前的所有内容。

选项 1 是非常简单协议的一个很好选择。它易于实现，不需要对接收到的流进行任何特殊处理。但是，它需要为每条消息建立和拆除套接字，当服务器同时处理多条消息时，这可能会影响性能。

选项 2 再次实现简单，但只有在我们的数据以整齐的固定长度块出现时才能有效利用网络。例如，在聊天服务器中，消息长度是可变的，因此我们将不得不使用特殊字符，例如空字节，来填充消息到块大小。这仅适用于我们确切知道填充字符永远不会出现在实际消息数据中的情况。还有一个额外的问题，即如何处理长于块长度的消息。

选项 3 通常被认为是最佳方法之一。虽然编码可能比其他选项更复杂，但实现仍然相当简单，并且它有效地利用了带宽。包括每条消息的长度所带来的开销通常与消息长度相比是微不足道的。它还避免了对接收到的数据进行任何额外处理的需要，这可能是选项 4 的某些实现所需要的。

选项 4 是最节省带宽的选项，当我们知道消息中只会使用有限的字符集，例如 ASCII 字母数字字符时，这是一个很好的选择。如果是这种情况，那么我们可以选择一个定界字符，例如空字节，它永远不会出现在消息数据中，然后当遇到这个字符时，接收到的数据可以很容易地被分成消息。实现通常比选项 3 简单。虽然可以将此方法用于任意数据，即定界符也可能出现为消息中的有效字符，但这需要使用字符转义，这需要对数据进行额外的处理。因此，在这些情况下，通常更简单的是使用长度前缀。

对于我们的回显和聊天应用程序，我们将使用 UTF-8 字符集发送消息。在 UTF-8 中，除了空字节本身，空字节在任何字符中都不使用，因此它是一个很好的分隔符。因此，我们将使用空字节作为定界符来对我们的消息进行分帧。

因此，我们的规则 8 将变为：

> *消息将使用 UTF-8 字符集进行编码传输，并以空字节终止。*

现在，让我们编写我们的回显程序。

# 一个简单的回显服务器

当我们在本章中工作时，我们会发现自己在重复使用几段代码，因此为了避免重复，我们将设置一个具有有用函数的模块，我们可以在以后重复使用。创建一个名为`tincanchat.py`的文件，并将以下代码保存在其中：

```py
import socket

HOST = ''
PORT = 4040

def create_listen_socket(host, port):
    """ Setup the sockets our server will receive connection requests on """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    return sock

def recv_msg(sock):
    """ Wait for data to arrive on the socket, then parse into messages using b'\0' as message delimiter """
    data = bytearray()
    msg = ''
    # Repeatedly read 4096 bytes off the socket, storing the bytes
    # in data until we see a delimiter
    while not msg:
        recvd = sock.recv(4096)
        if not recvd:
            # Socket has been closed prematurely
            raise ConnectionError()
        data = data + recvd
        if b'\0' in recvd:
            # we know from our protocol rules that we only send
            # one message per connection, so b'\0' will always be
            # the last character
            msg = data.rstrip(b'\0')
    msg = msg.decode('utf-8')
    return msg

def prep_msg(msg):
    """ Prepare a string to be sent as a message """
    msg += '\0'
    return msg.encode('utf-8')

def send_msg(sock, msg):
    """ Send a string over a socket, preparing it first """
    data = prep_msg(msg)
    sock.sendall(data)
```

首先，我们定义一个默认接口和要侦听的端口号。在`HOST`变量中指定的空的`''`接口告诉`socket.bind（）`侦听所有可用的接口。如果要将访问限制为仅限于您的计算机，则将代码开头的`HOST`变量的值更改为`127.0.0.1`。

我们将使用`create_listen_socket（）`来设置我们的服务器监听连接。这段代码对于我们的几个服务器程序是相同的，因此重复使用它是有意义的。

`recv_msg（）`函数将被我们的回显服务器和客户端用于从套接字接收消息。在我们的回显协议中，我们的程序在等待接收消息时不需要做任何事情，因此此函数只是在循环中调用`socket.recv（）`，直到接收到整个消息为止。根据我们的分帧规则，它将在每次迭代中检查累积的数据，以查看是否收到了空字节，如果是，则将返回接收到的数据，去掉空字节并解码为 UTF-8。

`send_msg（）`和`prep_msg（）`函数一起用于对消息进行分帧和发送。我们将空字节终止和 UTF-8 编码分离到`prep_msg（）`中，因为我们将在以后单独使用它们。

## 处理接收到的数据

请注意，就字符串编码而言，我们在发送和接收函数之间划定了一条谨慎的界限。Python 3 字符串是 Unicode，而我们通过网络接收的数据是字节。我们最不想做的最后一件事就是在程序的其余部分处理这些数据的混合，因此我们将在程序的边界处仔细编码和解码数据，数据进入和离开网络的地方。这将确保我们代码的其余部分可以假定它们将使用 Python 字符串，这将在以后为我们带来很多便利。

当然，并非我们可能想要通过网络发送或接收的所有数据都是文本。例如，图像、压缩文件和音乐无法解码为 Unicode 字符串，因此需要一种不同的处理方式。通常，这将涉及将数据加载到类中，例如**Python Image Library**（**PIL**）图像，如果我们要以某种方式操作对象。

在对接收到的数据进行完整处理之前，可以在此处对接收到的数据进行基本检查，以快速标记数据中的任何问题。此类检查的一些示例如下：

+   检查接收到的数据的长度

+   检查文件的前几个字节是否有魔术数字来确认文件类型

+   检查更高级别协议头的值，例如`HTTP`请求中的`Host`头

这种检查将允许我们的应用程序在出现明显问题时快速失败。

## 服务器本身

现在，让我们编写我们的回显服务器。打开一个名为`1.1-echo-server-uni.py`的新文件，并将以下代码保存在其中：

```py
import tincanchat

HOST = tincanchat.HOST
PORT = tincanchat.PORT

def handle_client(sock, addr):
    """ Receive data from the client via sock and echo it back """
    try:
        msg = tincanchat.recv_msg(sock)  # Blocks until received
                                         # complete message
        print('{}: {}'.format(addr, msg))
        tincanchat.send_msg(sock, msg)  # Blocks until sent
    except (ConnectionError, BrokenPipeError):
        print('Socket error')
    finally:
        print('Closed connection to {}'.format(addr))
        sock.close()

if __name__ == '__main__':
    listen_sock = tincanchat.create_listen_socket(HOST, PORT)
    addr = listen_sock.getsockname()
    print('Listening on {}'.format(addr))

    while True:
        client_sock, addr = listen_sock.accept()
        print('Connection from {}'.format(addr))
        handle_client(client_sock, addr)
```

这是一个服务器可以变得多么简单的例子！首先，我们使用`create_listen_socket（）`调用设置我们的监听套接字。其次，我们进入我们的主循环，在那里我们永远监听来自客户端的传入连接，阻塞在`listen_sock.accept（）`上。当客户端连接进来时，我们调用`handle_client（）`函数，根据我们的协议处理客户端。我们为此代码创建了一个单独的函数，部分原因是为了保持主循环的整洁，部分原因是因为我们将来会想要在后续程序中重用这组操作。

这就是我们的服务器，现在我们只需要创建一个客户端来与它通信。

# 一个简单的回显客户端

创建一个名为`1.2-echo_client-uni.py`的文件，并将以下代码保存在其中：

```py
import sys, socket
import tincanchat

HOST = sys.argv[-1] if len(sys.argv) > 1 else '127.0.0.1'
PORT = tincanchat.PORT

if __name__ == '__main__':
    while True:
        try:
            sock = socket.socket(socket.AF_INET,
                                 socket.SOCK_STREAM)
            sock.connect((HOST, PORT))
            print('\nConnected to {}:{}'.format(HOST, PORT))
            print("Type message, enter to send, 'q' to quit")
            msg = input()
            if msg == 'q': break
            tincanchat.send_msg(sock, msg)  # Blocks until sent
            print('Sent message: {}'.format(msg))
            msg = tincanchat.recv_msg(sock)  # Block until
                                             # received complete
                                             # message
            print('Received echo: ' + msg)
        except ConnectionError:
            print('Socket error')
            break
        finally:
            sock.close()
            print('Closed connection to server\n')
```

如果我们在与运行客户端的计算机不同的计算机上运行服务器，则可以将服务器的 IP 地址或主机名作为命令行参数提供给客户端程序。如果不这样做，它将默认尝试连接到本地主机。

代码的第三和第四行检查服务器地址的命令行参数。一旦确定要连接的服务器，我们进入我们的主循环，该循环将一直循环，直到我们通过输入`q`来终止客户端。在主循环中，我们首先创建与服务器的连接。其次，我们提示用户输入要发送的消息，然后使用`tincanchat.send_msg()`函数发送消息。然后我们等待服务器的回复。一旦收到回复，我们打印它，然后根据我们的协议关闭连接。

尝试运行我们的客户端和服务器。通过使用以下命令在终端中运行服务器：

```py
**$ python 1.1-echo_server-uni.py**
**Listening on ('0.0.0.0', 4040)**

```

在另一个终端中，运行客户端并注意，如果您需要连接到另一台计算机，您将需要指定服务器，如下所示：

```py
**$ python 1.2-echo_client.py 192.168.0.7**
**Type message, enter to send, 'q' to quit**

```

并排运行终端是一个好主意，因为您可以同时看到程序的行为。

在客户端中输入一些消息，看看服务器如何接收并将它们发送回来。与客户端断开连接也应该在服务器上提示通知。

# 并发 I/O

如果您有冒险精神，那么您可能已经尝试过同时使用多个客户端连接到我们的服务器。如果您尝试从它们中的两个发送消息，那么您会发现它并不像我们希望的那样工作。如果您还没有尝试过，请试一试。

客户端上的工作回显会话应该是这样的：

```py
**Type message, enter to send. 'q' to quit**
**hello world**
**Sent message: hello world**
**Received echo: hello world**
**Closed connection to server**

```

然而，当尝试使用第二个连接的客户端发送消息时，我们会看到类似这样的情况：

```py
**Type message, enter to send. 'q' to quit**
**hello world**
**Sent message: hello world**

```

当发送消息时，客户端将挂起，并且不会收到回显回复。您还可能注意到，如果我们使用第一个连接的客户端发送消息，那么第二个客户端将收到其响应。那么，这里发生了什么？

问题在于服务器一次只能监听来自一个客户端的消息。一旦第一个客户端连接，服务器就会在`tincanchat.recv_msg()`中的`socket.recv()`调用处阻塞，等待第一个客户端发送消息。在此期间，服务器无法接收其他客户端的消息，因此当另一个客户端发送消息时，该客户端也会阻塞，等待服务器发送回复。

这是一个稍微牵强的例子。在这种情况下，可以通过在建立与服务器的连接之前要求用户输入来轻松解决客户端端的问题。但是在我们完整的聊天服务中，客户端需要能够同时监听来自服务器的消息，同时等待用户输入。这在我们目前的程序设置中是不可能的。

解决这个问题有两种方法。我们可以使用多个线程或进程，或者使用**非阻塞**套接字以及**事件驱动**架构。我们将研究这两种方法，首先从**多线程**开始。

# 多线程和多进程

Python 具有允许我们编写多线程和多进程应用程序的 API。多线程和多进程背后的原则很简单，即复制我们的代码并在额外的线程或进程中运行它们。操作系统会自动调度可用 CPU 核心上的线程和进程，以提供公平的处理时间分配给所有线程和进程。这有效地允许程序同时运行多个操作。此外，当线程或进程阻塞时，例如等待 IO 时，操作系统可以将线程或进程降低优先级，并将 CPU 核心分配给其他有实际计算任务的线程或进程。

以下是线程和进程之间关系的概述：

![多线程和多进程](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_08_01.jpg)

线程存在于进程内。 一个进程可以包含多个线程，但它始终至少包含一个线程，有时称为**主线程**。 同一进程中的线程共享内存，因此线程之间的数据传输只是引用共享对象的情况。 进程不共享内存，因此必须使用其他接口（如文件，套接字或专门分配的共享内存区域）来在进程之间传输数据。

当线程有操作要执行时，它们会请求操作系统线程调度程序为它们分配一些 CPU 时间，调度程序会根据各种参数（从 OS 到 OS 不等）将等待的线程分配给 CPU 核心。 同一进程中的线程可以同时在不同的 CPU 核心上运行。

尽管在前面的图中显示了两个进程，但这里并没有进行多进程处理，因为这些进程属于不同的应用程序。 显示第二个进程是为了说明 Python 线程和大多数其他程序中线程之间的一个关键区别。 这个区别就是 GIL 的存在。

## 线程和 GIL

CPython 解释器（可从[www.python.org](http://www.python.org)下载的 Python 标准版本）包含一个称为**全局解释器锁**（**GIL**）的东西。 GIL 的存在是为了确保在 Python 进程中只能同时运行一个线程，即使存在多个 CPU 核心。 有 GIL 的原因是它使 Python 解释器的底层 C 代码更容易编写和维护。 这样做的缺点是，使用多线程的 Python 程序无法利用多个核心进行并行计算。

这是一个引起很多争议的原因； 但是，对我们来说，这并不是一个大问题。 即使有 GIL 存在，仍然在 I/O 阻塞的线程被 OS 降低优先级并置于后台，因此有计算工作要做的线程可以运行。 以下图是这一点的简化说明：

![线程和全局解释器锁](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_08_02.jpg)

**等待 GIL**状态是指线程已发送或接收了一些数据，因此准备退出阻塞状态，但另一个线程拥有 GIL，因此准备好的线程被迫等待。 在许多网络应用程序中，包括我们的回显和聊天服务器，等待 I/O 的时间远远高于处理数据的时间。 只要我们没有非常多的连接（这是我们在后面讨论事件驱动架构时会讨论的情况），由 GIL 引起的线程争用相对较低，因此线程仍然是这些网络服务器应用程序的合适架构。

考虑到这一点，我们将在我们的回显服务器中使用多线程而不是多进程。 共享数据模型将简化我们需要允许聊天客户端彼此交换消息的代码，并且因为我们是 I/O 绑定的，所以我们不需要进程进行并行计算。 在这种情况下不使用进程的另一个原因是，进程在 OS 资源方面更“笨重”，因此创建新进程比创建新线程需要更长的时间。 进程还使用更多内存。

需要注意的一点是，如果您需要在网络服务器应用程序中执行密集计算（也许您需要在将大型文件发送到网络之前对其进行压缩），那么您应该调查在单独的进程中运行此操作的方法。 由于 GIL 的实现中存在一些怪癖，即使在多个 CPU 核心可用时，将单个计算密集型线程放在主要是 I/O 绑定的进程中也会严重影响所有 I/O 绑定线程的性能。 有关更多详细信息，请查看以下信息框中链接到的 David Beazley 演示文稿：

### 注意

进程和线程是不同的东物，如果你对这些区别不清楚，值得阅读一下。一个很好的起点是维基百科关于线程的文章，可以在[`en.wikipedia.org/wiki/Thread_(computing)`](http://en.wikipedia.org/wiki/Thread_(computing))找到。

本主题的一个很好的概述在 Benjamin Erb 的论文*第四章*中给出，可以在[`berb.github.io/diploma-thesis/community/`](http://berb.github.io/diploma-thesis/community/)找到。

关于 GIL 的更多信息，包括保持它在 Python 中的原因，可以在官方 Python 文档中找到，网址为[`wiki.python.org/moin/GlobalInterpreterLock`](https://wiki.python.org/moin/GlobalInterpreterLock)。

您还可以在 Nick Coghlan 的 Python 3 问答中阅读更多关于这个主题的内容，网址为[`python-notes.curiousefficiency.org/en/latest/python3/questions_and_answers.html#but-but-surely-fixing-the-gil-is-more-important-than-fixing-unicode`](http://python-notes.curiousefficiency.org/en/latest/python3/questions_and_answers.html#but-but-surely-fixing-the-gil-is-more-important-than-fixing-unicode)。

最后，David Beazley 对多核系统上 GIL 的性能进行了一些引人入胜的研究。两个重要的演示资料可以在线找到。它们提供了一个与本章相关的很好的技术背景。这些可以在[`pyvideo.org/video/353/pycon-2010--understanding-the-python-gil---82`](http://pyvideo.org/video/353/pycon-2010--understanding-the-python-gil---82)和[`www.youtube.com/watch?v=5jbG7UKT1l4`](https://www.youtube.com/watch?v=5jbG7UKT1l4)找到。

# 多线程回显服务器

多线程方法的一个好处是操作系统为我们处理线程切换，这意味着我们可以继续以过程化的方式编写程序。因此，我们只需要对服务器程序进行小的调整，使其成为多线程，并因此能够同时处理多个客户端。

创建一个名为`1.3-echo_server-multi.py`的新文件，并将以下代码添加到其中：

```py
import threading
import tincanchat

HOST = tincanchat.HOST
PORT = tincanchat.PORT

def handle_client(sock, addr):
    """ Receive one message and echo it back to client, then close
        socket """
    try:
        msg = tincanchat.recv_msg(sock)  # blocks until received
                                         # complete message
        msg = '{}: {}'.format(addr, msg)
        print(msg)
        tincanchat.send_msg(sock, msg)  # blocks until sent
    except (ConnectionError, BrokenPipeError):
        print('Socket error')
    finally:
        print('Closed connection to {}'.format(addr))
        sock.close()

if __name__ == '__main__':
    listen_sock = tincanchat.create_listen_socket(HOST, PORT)
    addr = listen_sock.getsockname()
    print('Listening on {}'.format(addr))

    while True:
        client_sock,addr = listen_sock.accept()
        # Thread will run function handle_client() autonomously
        # and concurrently to this while loop
        thread = threading.Thread(target=handle_client,
                                  args=[client_sock, addr],
                                  daemon=True)
        thread.start()
        print('Connection from {}'.format(addr))
```

您可以看到，我们刚刚导入了一个额外的模块，并修改了我们的主循环，以在单独的线程中运行`handle_client()`函数，而不是在主线程中运行它。对于每个连接的客户端，我们创建一个新的线程，只运行`handle_client()`函数。当线程在接收或发送时阻塞时，操作系统会检查其他线程是否已经退出阻塞状态，如果有任何线程退出了阻塞状态，那么它就会切换到其中一个线程。

请注意，我们在线程构造函数调用中设置了`daemon`参数为`True`。这将允许程序在我们按下*ctrl* - *c*时退出，而无需我们显式关闭所有线程。

如果您尝试使用多个客户端进行此回显服务器，则会发现第二个连接并发送消息的客户端将立即收到响应。

# 设计聊天服务器

我们已经有一个工作的回显服务器，它可以同时处理多个客户端，所以我们离一个功能齐全的聊天客户端很近了。然而，我们的服务器需要将接收到的消息广播给所有连接的客户端。听起来很简单，但我们需要克服两个问题才能实现这一点。

首先，我们的协议需要进行改进。如果我们考虑从客户端的角度来看需要发生什么，那么我们就不能再依赖简单的工作流程：

客户端连接 > 客户端发送 > 服务器发送 > 客户端断开连接。

客户现在可能随时接收消息，而不仅仅是当他们自己向服务器发送消息时。

其次，我们需要修改我们的服务器，以便向所有连接的客户端发送消息。由于我们使用多个线程来处理客户端，这意味着我们需要在线程之间建立通信。通过这样做，我们正在涉足并发编程的世界，这需要谨慎和深思熟虑。虽然线程的共享状态很有用，但在其简单性中也是具有欺骗性的。有多个控制线程异步访问和更改相同资源是竞争条件和微妙死锁错误的理想滋生地。虽然关于并发编程的全面讨论远远超出了本文的范围，但我们将介绍一些简单的原则，这些原则可以帮助保持您的理智。

# 一个聊天协议

我们协议更新的主要目的是规定客户端必须能够接受发送给它们的所有消息，无论何时发送。

理论上，一个解决方案是让我们的客户端自己建立一个监听套接字，这样服务器在有新消息要传递时就可以连接到它。在现实世界中，这个解决方案很少适用。客户端几乎总是受到某种防火墙的保护，防止任何新的入站连接连接到客户端。为了让我们的服务器连接到客户端的端口，我们需要确保任何中间的防火墙都配置为允许我们的服务器连接。这个要求会让我们的软件对大多数用户不那么吸引，因为已经有一些不需要这样做的聊天解决方案了。

如果我们不能假设服务器能够连接到客户端，那么我们需要通过仅使用客户端发起的连接到服务器来满足我们的要求。我们可以通过两种方式来做到这一点。首先，我们可以让我们的客户端默认运行在断开状态，然后定期连接到服务器，下载任何等待的消息，然后再次断开连接。或者，我们可以让我们的客户端连接到服务器，然后保持连接打开。然后他们可以持续监听连接，并在一个线程中处理服务器发送的新消息，同时在另一个线程中接受用户输入并通过相同的连接发送消息。

您可能会认出这些情景，它们是一些电子邮件客户端中可用的**拉**和**推**选项。它们被称为拉和推，是因为操作对客户端的外观。客户端要么从服务器拉取数据，要么服务器向客户端推送数据。

使用这两种方法都有利有弊，决定取决于应用程序的需求。拉取会减少服务器的负载，但会增加客户端接收消息的延迟。虽然这对于许多应用程序来说是可以接受的，比如电子邮件，在聊天服务器中，我们通常希望立即更新。虽然我们可以频繁轮询，但这会给客户端、服务器和网络带来不必要的负载，因为连接会反复建立和拆除。

推送更适合聊天服务器。由于连接保持持续打开，网络流量的量仅限于初始连接设置和消息本身。此外，客户端几乎可以立即从服务器获取新消息。

因此，我们将使用推送方法，现在我们将编写我们的聊天协议如下：

1.  通信将通过 TCP 进行。

1.  客户端将通过创建套接字连接到服务器来启动聊天会话。

1.  服务器将接受连接，监听来自客户端的任何消息，并接受它们。

1.  客户端将在连接上监听来自服务器的任何消息，并接受它们。

1.  服务器将把来自客户端的任何消息发送给所有其他连接的客户端。

1.  消息将以 UTF-8 字符集进行编码传输，并以空字节终止。

# 处理持久连接上的数据

我们持久连接方法引发的一个新问题是，我们不能再假设我们的 `socket.recv()` 调用将只包含来自一个消息的数据。在我们的回显服务器中，由于我们已经定义了协议，我们知道一旦看到空字节，我们收到的消息就是完整的，并且发送者不会再发送任何内容。也就是说，我们在最后一个 `socket.recv()` 调用中读取的所有内容都是该消息的一部分。

在我们的新设置中，我们将重用同一连接来发送无限数量的消息，这些消息不会与我们从每个 `socket.recv()` 中提取的数据块同步。因此，很可能从一个 `recv()` 调用中获取的数据将包含多个消息的数据。例如，如果我们发送以下内容：

```py
caerphilly,
illchester,
brie
```

然后在传输中它们将如下所示：

```py
caerphilly**\0**illchester**\0**brie**\0**

```

然而，由于网络传输的变化，一系列连续的 `recv()` 调用可能会接收到它们：

```py
recv 1: caerphil
recv 2: ly**\0**illches
recv 3: ter**\0**brie**\0**

```

请注意，`recv 1` 和 `recv 2` 一起包含一个完整的消息，但它们也包含下一个消息的开头。显然，我们需要更新我们的解析。一种选择是逐字节从套接字中读取数据，也就是使用 `recv(1)`，并检查每个字节是否为空字节。然而，这是一种非常低效的使用网络套接字的方式。我们希望在调用 `recv()` 时尽可能多地读取数据。相反，当我们遇到不完整的消息时，我们可以缓存多余的字节，并在下次调用 `recv()` 时使用它们。让我们这样做，将这些函数添加到 `tincanchat.py` 文件中：

```py
def parse_recvd_data(data):
    """ Break up raw received data into messages, delimited
        by null byte """
    parts = data.split(b'\0')
    msgs = parts[:-1]
    rest = parts[-1]
    return (msgs, rest)

def recv_msgs(sock, data=bytes()):
    """ Receive data and break into complete messages on null byte
       delimiter. Block until at least one message received, then
       return received messages """
    msgs = []
    while not msgs:
        recvd = sock.recv(4096)
        if not recvd:
            raise ConnectionError()
        data = data + recvd
        (msgs, rest) = parse_recvd_data(data)
    msgs = [msg.decode('utf-8') for msg in msgs]
    return (msgs, rest)
```

从现在开始，我们将在以前使用 `recv_msg()` 的地方使用 `recv_msgs()`。那么，我们在这里做什么呢？通过快速浏览 `recv_msgs()`，您可以看到它与 `recv_msg()` 类似。我们重复调用 `recv()` 并像以前一样累积接收到的数据，但现在我们将使用 `parse_recvd_data()` 进行解析，期望它可能包含多个消息。当 `parse_recvd_data()` 在接收到的数据中找到一个或多个完整的消息时，它将将它们拆分成列表并返回它们，如果在最后一个完整消息之后还有任何剩余内容，则使用 `rest` 变量另外返回这些内容。然后，`recv_msgs()` 函数解码来自 UTF-8 的消息，并返回它们和 `rest` 变量。

`rest` 值很重要，因为我们将在下次调用 `recv_msgs()` 时将其返回，并且它将被添加到 `recv()` 调用的数据前缀。这样，上次 `recv_msgs()` 调用的剩余数据就不会丢失。

因此，在我们之前的例子中，解析消息将按照以下方式进行：

| `recv_msgs` 调用 | `data` 参数 | `recv` 结果 | 累积的 `data` | `msgs` | `rest` |
| --- | --- | --- | --- | --- | --- |
| 1 | - | `'caerphil'` | `'caerphil'` | `[]` | `b''` |
| 1 | - | `'ly\0illches'` | `'caerphilly\0illches'` | `['caerphilly']` | `'illches'` |
| 2 | `'illches'` | `'ter\0brie\0'` | `'illchester\0brie\0'` | `['illchester', 'brie']` | `b''` |

在这里，我们可以看到第一个 `recv_msgs()` 调用在其第一次迭代后没有返回。它循环是因为 `msgs` 仍然为空。这就是为什么 `recv_msgs` 调用编号为 1、1 和 2 的原因。

# 一个多线程聊天服务器

因此，让我们利用这一点并编写我们的聊天服务器。创建一个名为 `2.1-chat_server-multithread.py` 的新文件，并将以下代码放入其中：

```py
import threading, queue
import tincanchat

HOST = tincanchat.HOST
PORT = tincanchat.PORT

send_queues = {}
lock = threading.Lock()

def handle_client_recv(sock, addr):
    """ Receive messages from client and broadcast them to
        other clients until client disconnects """
    rest = bytes()
    while True:
        try:
            (msgs, rest) = tincanchat.recv_msgs(sock, rest)
        except (EOFError, ConnectionError):
            handle_disconnect(sock, addr)
            break
        for msg in msgs:
            msg = '{}: {}'.format(addr, msg)
            print(msg)
            broadcast_msg(msg)

def handle_client_send(sock, q, addr):
    """ Monitor queue for new messages, send them to client as
        they arrive """
    while True:
        msg = q.get()
        if msg == None: break
        try:
            tincanchat.send_msg(sock, msg)
        except (ConnectionError, BrokenPipe):
            handle_disconnect(sock, addr)
            break

def broadcast_msg(msg):
    """ Add message to each connected client's send queue """
    with lock:
        for q in send_queues.values():
            q.put(msg)

def handle_disconnect(sock, addr):
    """ Ensure queue is cleaned up and socket closed when a client
        disconnects """
    fd = sock.fileno()
    with lock:
        # Get send queue for this client
        q = send_queues.get(fd, None)
    # If we find a queue then this disconnect has not yet
    # been handled
    if q:
        q.put(None)
        del send_queues[fd]
        addr = sock.getpeername()
        print('Client {} disconnected'.format(addr))
        sock.close()

if __name__ == '__main__':
    listen_sock = tincanchat.create_listen_socket(HOST, PORT)
    addr = listen_sock.getsockname()
    print('Listening on {}'.format(addr))

    while True:
        client_sock,addr = listen_sock.accept()
        q = queue.Queue()
        with lock:
            send_queues[client_sock.fileno()] = q
        recv_thread = threading.Thread(target=handle_client_recv,
                                       args=[client_sock, addr],
                                       daemon=True)
        send_thread = threading.Thread(target=handle_client_send,
                                       args=[client_sock, q,
                                             addr],
                                       daemon=True)
        recv_thread.start()
        send_thread.start()
        print('Connection from {}'.format(addr))
```

现在我们为每个客户端使用两个线程。一个线程处理接收到的消息，另一个线程处理发送消息的任务。这里的想法是将可能发生阻塞的每个地方都分解成自己的线程。这将为每个客户端提供最低的延迟，但这会以系统资源为代价。我们减少了可能同时处理的客户端数量。我们可以使用其他模型，比如为每个客户端使用单个线程接收消息，然后自己将消息发送给所有连接的客户端，但我选择了优化延迟。

为了方便分开线程，我们将接收代码和发送代码分别放入`handle_client_recv()`函数和`handle_client_send()`函数中。

我们的`handle_client_recv`线程负责从客户端接收消息，而`handle_client_send`线程负责向客户端发送消息，但是接收到的消息如何从接收线程传递到发送线程呢？这就是`queue`、`send_queue`、`dict`和`lock`对象发挥作用的地方。

## 队列

`Queue`是一个**先进先出**（**FIFO**）管道。您可以使用`put()`方法向其中添加项目，并使用`get()`方法将它们取出。`Queue`对象的重要之处在于它们完全是**线程安全**的。在 Python 中，除非在其文档中明确指定，否则对象通常不是线程安全的。线程安全意味着对对象的操作保证是**原子**的，也就是说，它们将始终在没有其他线程可能到达该对象并对其执行意外操作的情况下完成。

等一下，你可能会问，之前，你不是说由于全局解释器锁（GIL），操作系统在任何给定时刻只能运行一个 Python 线程吗？如果是这样，那么两个线程如何能同时对一个对象执行操作呢？嗯，这是一个公平的问题。实际上，Python 中的大多数操作实际上由许多操作组成，这些操作是在操作系统级别进行的，线程是在操作系统级别进行调度的。一个线程可以开始对一个对象进行操作，比如向`list`中添加一个项目，当线程进行到操作系统级别的操作的一半时，操作系统可能会切换到另一个线程，这个线程也开始向同一个`list`中添加。由于`list`对象在被线程滥用时（它们不是线程安全的）没有对其行为提供任何保证，接下来可能发生任何事情，而且不太可能是一个有用的结果。这种情况可以称为**竞争条件**。

线程安全对象消除了这种可能性，因此在线程之间共享状态时，绝对应该优先选择它们。

回到我们的服务器，`Queues`的另一个有用的行为是，如果在空的`Queue`上调用`get()`，那么它将阻塞，直到有东西被添加到`Queue`中。我们利用这一点在我们的发送线程中。注意，我们进入一个无限循环，第一个操作是对`Queue`调用`get()`方法。线程将在那里阻塞并耐心等待，直到有东西被添加到它的`Queue`中。而且，你可能已经猜到了，我们的接收线程将消息添加到队列中。

我们为每个发送线程创建一个`Queue`对象，并将队列存储在`send_queues`字典中。为了广播新消息给我们的接收线程，它们只需要将消息添加到`send_queues`中的每个`Queue`中，这是在`broadcast_msgs()`函数中完成的。我们等待的发送线程将解除阻塞，从它们的`Queue`中取出消息，然后将其发送给它们的客户端。

我们还添加了一个`handle_disconnect()`函数，每当客户端断开连接或套接字发生错误时都会调用该函数。该函数确保与关闭连接相关的队列被清理，并且套接字从服务器端正确关闭。

## 锁

将我们对`Queues`对象的使用与我们对`send_queues`的使用进行对比。`Dict`对象不是线程安全的，不幸的是，在 Python 中没有线程安全的关联数组类型。由于我们需要共享这个`dict`，所以我们在访问它时需要额外小心，这就是`Lock`发挥作用的地方。`Lock`对象是一种**同步原语**。这些是具有功能的特殊对象，可以帮助管理我们的线程，并确保它们不会互相干扰。

`Lock`要么被锁定，要么被解锁。线程可以通过调用`acquire()`来锁定线程，或者像我们的程序一样，将其用作上下文管理器。如果一个线程已经获取了锁，另一个线程也试图获取锁，那么第二个线程将在`acquire()`调用上阻塞，直到第一个线程释放锁或退出上下文。一次可以有无限多个线程尝试获取锁 - 除了第一个之外，所有线程都会被阻塞。通过用锁包装对非线程安全对象的所有访问，我们可以确保没有两个线程同时操作该对象。

因此，每当我们向`send_queues`添加或删除内容时，我们都会将其包装在`Lock`上下文中。请注意，当我们迭代`send_queues`时，我们也在保护它。即使我们没有改变它，我们也希望确保在我们处理它时它不会被修改。

尽管我们很小心地使用锁和线程安全的原语，但我们并没有完全保护自己免受所有可能的与线程相关的问题。由于线程同步机制本身会阻塞，因此仍然很可能会出现死锁，即两个线程同时在由另一个线程锁定的对象上阻塞。管理线程通信的最佳方法是将对共享状态的所有访问限制在代码中尽可能小的区域内。在这个服务器的情况下，这个模块可以重新设计为提供最少数量的公共方法的类。它还可以被记录下来，以阻止任何内部状态的更改。这将使线程的这一部分严格限制在这个类中。

# 多线程聊天客户端

现在我们有了一个新的、全接收和广播的聊天服务器，我们只需要一个客户端。我们之前提到，当尝试同时监听网络数据和用户输入时，我们的过程化客户端会遇到问题。现在我们对如何使用线程有了一些想法，我们可以试着解决这个问题。创建一个名为`2.2-chat_client-multithread.py`的新文本文件，并将以下代码保存在其中：

```py
import sys, socket, threading
import tincanchat

HOST = sys.argv[-1] if len(sys.argv) > 1 else '127.0.0.1'
PORT = tincanchat.PORT

def handle_input(sock):
    """ Prompt user for message and send it to server """    
    print("Type messages, enter to send. 'q' to quit")
    while True:
        msg = input()  # Blocks
        if msg == 'q':
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            break
        try:
            tincanchat.send_msg(sock, msg)  # Blocks until sent
        except (BrokenPipeError, ConnectionError):
            break

if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print('Connected to {}:{}'.format(HOST, PORT))

    # Create thread for handling user input and message sending
    thread = threading.Thread(target=handle_input,
                              args=[sock],
                              daemon=True)
    thread.start()
    rest = bytes()
    addr = sock.getsockname()
    # Loop indefinitely to receive messages from server
    while True:
        try:
            # blocks
            (msgs, rest) = tincanchat.recv_msgs(sock, rest)
            for msg in msgs:
                print(msg)
        except ConnectionError:
            print('Connection to server closed')
            sock.close()
            break
```

我们已经更新了我们的客户端，通过创建一个新线程来处理用户输入和发送消息，同时在主线程中处理接收消息，来遵守我们的新聊天协议。这允许客户端同时处理用户输入和接收消息。

请注意，这里没有共享状态，所以我们不必在`Queues`或同步原语上耍花招。

让我们来试试我们的新程序。启动多线程聊天服务器，然后启动至少两个客户端。如果可以的话，在终端中运行它们，这样你就可以同时观看它们。现在，尝试从客户端发送一些消息，看看它们是如何发送到所有其他客户端的。

# 事件驱动服务器

对于许多目的来说，线程是很好的，特别是因为我们仍然可以以熟悉的过程化、阻塞 IO 风格进行编程。但是它们的缺点是在同时管理大量连接时会遇到困难，因为它们需要为每个连接维护一个线程。每个线程都会消耗内存，并且在线程之间切换会产生一种称为**上下文切换**的 CPU 开销。虽然这对于少量线程来说不是问题，但是当需要管理许多线程时，它会影响性能。多进程也面临类似的问题。

使用**事件驱动**模型是线程和多进程的一种替代方法。在这种模型中，我们不是让操作系统自动在活动线程或进程之间切换，而是使用一个单线程，将阻塞对象（如套接字）注册到操作系统中。当这些对象准备好离开阻塞状态时，例如套接字接收到一些数据，操作系统会通知我们的程序；我们的程序可以以非阻塞模式访问这些对象，因为它知道它们处于立即可用的状态。在非阻塞模式下调用对象的调用总是立即返回。我们的应用程序围绕一个循环进行结构化，等待操作系统通知我们阻塞对象上的活动，然后处理该活动，然后回到等待状态。这个循环被称为**事件循环**。

这种方法提供了与线程和多进程相当的性能，但没有内存或上下文切换的开销，因此可以在相同的硬件上实现更大的扩展。工程应用程序能够有效处理大量同时连接的挑战在历史上被称为**c10k 问题**，指的是在单个线程中处理一万个并发连接。借助事件驱动架构，这个问题得到了解决，尽管这个术语在处理许多并发连接时仍经常被使用。

### 注意

在现代硬件上，使用多线程方法实际上可以处理一万个并发连接，也可以参考这个 Stack Overflow 问题来了解一些数字[`stackoverflow.com/questions/17593699/tcp-ip-solving-the-c10k-with-the-thread-per-client-approach`](https://stackoverflow.com/questions/17593699/tcp-ip-solving-the-c10k-with-the-thread-per-client-approach)。

现代挑战是“c10m 问题”，即一千万并发连接。解决这个问题涉及一些激进的软件甚至操作系统架构的变化。尽管这在短期内可能无法通过 Python 来解决，但可以在[`c10m.robertgraham.com/p/blog-page.html`](http://c10m.robertgraham.com/p/blog-page.html)找到有关该主题的有趣（尽管不幸是不完整的）概论。

下图显示了事件驱动服务器中进程和线程的关系：

![事件驱动服务器](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-net-prog/img/6008OS_08_03.jpg)

尽管 GIL 和操作系统线程调度器在这里是为了完整性而显示的，但在事件驱动服务器的情况下，它们对性能没有影响，因为服务器只使用一个线程。I/O 处理的调度是由应用程序完成的。

# 低级事件驱动聊天服务器

因此，事件驱动架构有一些很大的好处，但问题在于，对于低级实现，我们需要以完全不同的风格编写我们的代码。让我们编写一个事件驱动的聊天服务器来说明这一点。

请注意，这个例子在 Windows 上根本无法工作，因为 Windows 缺乏我们将在这里使用的`poll`接口。然而，Windows 支持一个名为`select`的旧接口，但它更慢，更复杂。我们稍后讨论的事件驱动框架会自动切换到`select`，如果我们在 Windows 上运行的话。

有一个称为`epoll`的`poll`的高性能替代品，它在 Linux 操作系统上可用，但它也更复杂，所以为了简单起见，我们将在这里坚持使用`poll`。同样，我们稍后讨论的框架会自动利用`epoll`。

最后，令人费解的是，Python 的`poll`接口位于一个名为`select`的模块中，因此我们将在程序中导入`select`。

创建一个名为`3.1-chat_server-poll.py`的文件，并将以下代码保存在其中：

```py
import select
import tincanchat
from types import SimpleNamespace
from collections import deque

HOST = tincanchat.HOST
PORT = tincanchat.PORT
clients = {}

def create_client(sock):
    """ Return an object representing a client """
    return SimpleNamespace(
                    sock=sock,
                    rest=bytes(),
                    send_queue=deque())

def broadcast_msg(msg):
    """ Add message to all connected clients' queues """
    data = tincanchat.prep_msg(msg)
    for client in clients.values():
        client.send_queue.append(data)
        poll.register(client.sock, select.POLLOUT)

if __name__ == '__main__':
    listen_sock = tincanchat.create_listen_socket(HOST, PORT)
    poll = select.poll()
    poll.register(listen_sock, select.POLLIN)
    addr = listen_sock.getsockname()
    print('Listening on {}'.format(addr))

    # This is the event loop. Loop indefinitely, processing events
    # on all sockets when they occur
    while True:
        # Iterate over all sockets with events
        for fd, event in poll.poll():
            # clear-up a closed socket
            if event & (select.POLLHUP | 
                        select.POLLERR |
                        select.POLLNVAL):
                poll.unregister(fd)
                del clients[fd]

            # Accept new connection, add client to clients dict
            elif fd == listen_sock.fileno():
                client_sock,addr = listen_sock.accept()
                client_sock.setblocking(False)
                fd = client_sock.fileno()
                clients[fd] = create_client(client_sock)
                poll.register(fd, select.POLLIN)
                print('Connection from {}'.format(addr))

            # Handle received data on socket
            elif event & select.POLLIN:
                client = clients[fd]
                addr = client.sock.getpeername()
                recvd = client.sock.recv(4096)
                if not recvd:
                    # the client state will get cleaned up in the
                    # next iteration of the event loop, as close()
                    # sets the socket to POLLNVAL
                    client.sock.close()
                    print('Client {} disconnected'.format(addr))
                    continue
                data = client.rest + recvd
                (msgs, client.rest) = \
                                tincanchat.parse_recvd_data(data)
                # If we have any messages, broadcast them to all
                # clients
                for msg in msgs:
                    msg = '{}: {}'.format(addr, msg)
                    print(msg)
                    broadcast_msg(msg)

            # Send message to ready client
            elif event & select.POLLOUT:
                client = clients[fd]
                data = client.send_queue.popleft()
                sent = client.sock.send(data)
                if sent < len(data):
                    client.sends.appendleft(data[sent:])
                if not client.send_queue:
                    poll.modify(client.sock, select.POLLIN)
```

这个程序的关键是我们在执行开始时创建的`poll`对象。这是一个用于内核`poll`服务的接口，它允许我们注册套接字，以便操作系统在它们准备好供我们使用时通知我们。

我们通过调用`poll.register()`方法注册套接字，将套接字作为参数与我们希望内核监视的活动类型一起传递。我们可以通过指定各种`select.POLL*`常量来监视几种条件。在这个程序中，我们使用`POLLIN`和`POLLOUT`来监视套接字何时准备好接收和发送数据。在我们的监听套接字上接受新的传入连接将被视为读取。

一旦套接字被注册到`poll`中，操作系统将监视它，并记录当套接字准备执行我们请求的活动时。当我们调用`poll.poll()`时，它返回一个列表，其中包含所有已准备好供我们使用的套接字。对于每个套接字，它还返回一个`event`标志，指示套接字的状态。我们可以使用此事件标志来判断我们是否可以从套接字读取（`POLLIN`事件）或向套接字写入（`POLLOUT`事件），或者是否发生了错误（`POLLHUP`，`POLLERR`，`POLLNVAL`事件）。

为了利用这一点，我们进入我们的事件循环，重复调用`poll.poll()`，迭代返回的准备好的对象，并根据它们的`event`标志对它们进行操作。

因为我们只在一个线程中运行，所以我们不需要在多线程服务器中使用的任何同步机制。我们只是使用一个常规的`dict`来跟踪我们的客户端。如果你以前没有遇到过，我们在`create_client()`函数中使用的`SimpleNamespace`对象只是一个创建带有`__dict__`的空对象的新习惯用法（这是必需的，因为`Object`实例没有`__dict__`，所以它们不会接受任意属性）。以前，我们可能会使用以下内容来给我们一个可以分配任意属性的对象：

```py
class Client:
  pass
client = Client()
```

Python 版本 3.3 及更高版本为我们提供了新的更明确的`SimpleNamespace`对象。

我们可以运行我们的多线程客户端与这个服务器进行通信。服务器仍然使用相同的网络协议，两个程序的架构不会影响通信。试一试，验证是否按预期工作。

这种编程风格，使用`poll`和非阻塞套接字，通常被称为**非阻塞**和**异步**，因为我们使用非阻塞模式的套接字，并且控制线程根据需要处理 I/O，而不是锁定到单个 I/O 通道直到完成。但是，你应该注意，我们的程序并不完全是非阻塞的，因为它仍然在`poll.poll()`调用上阻塞。在 I/O 绑定系统中，这几乎是不可避免的，因为当没有发生任何事情时，你必须等待 I/O 活动。

# 框架

正如你所看到的，使用这些较低级别的线程和`poll`API 编写服务器可能会相当复杂，特别是考虑到一些在生产系统中预期的事情，比如日志记录和全面的错误处理，由于简洁起见，我们的示例中没有包括。

许多人在我们之前遇到了这些问题，并且有几个库和框架可用于减少编写网络服务器的工作量。

# 基于 eventlet 的聊天服务器

`eventlet`库提供了一个高级 API，用于事件驱动编程，但它的风格模仿了我们在多线程服务器中使用的过程式阻塞 IO 风格。结果是，我们可以有效地采用多线程聊天服务器代码，对其进行一些小的修改，以使用`eventlet`，并立即获得事件驱动模型的好处！

`eventlet`库可在 PyPi 中找到，并且可以使用`pip`进行安装，如下所示：

```py
**$ pip install eventlet**
**Downloading/unpacking eventlet**

```

### 注意

如果`poll`不可用，`eventlet`库会自动退回到`select`，因此它将在 Windows 上正常运行。

安装完成后，创建一个名为`4.1-chat_server-eventlet.py`的新文件，并将以下代码保存在其中：

```py
import eventlet
import eventlet.queue as queue
import tincanchat

HOST = tincanchat.HOST
PORT = tincanchat.PORT
send_queues = {}

def handle_client_recv(sock, addr):
    """ Receive messages from client and broadcast them to
        other clients until client disconnects """
    rest = bytes()
    while True:
        try:
            (msgs, rest) = tincanchat.recv_msgs(sock)
        except (EOFError, ConnectionError):
            handle_disconnect(sock, addr)
            break
        for msg in msgs:
            msg = '{}: {}'.format(addr, msg)
            print(msg)
            broadcast_msg(msg)

def handle_client_send(sock, q, addr):
    """ Monitor queue for new messages, send them to client as
        they arrive """
    while True:
        msg = q.get()
        if msg == None: break
        try:
            tincanchat.send_msg(sock, msg)
        except (ConnectionError, BrokenPipe):
            handle_disconnect(sock, addr)
            break

def broadcast_msg(msg):
    """ Add message to each connected client's send queue """
    for q in send_queues.values():
        q.put(msg)

def handle_disconnect(sock, addr):
    """ Ensure queue is cleaned up and socket closed when a client
        disconnects """
    fd = sock.fileno()
    # Get send queue for this client
    q = send_queues.get(fd, None)
    # If we find a queue then this disconnect has not yet
    # been handled
    if q:
        q.put(None)
        del send_queues[fd]
        addr = sock.getpeername()
        print('Client {} disconnected'.format(addr))
        sock.close()

if __name__ == '__main__':
    server = eventlet.listen((HOST, PORT))
    addr = server.getsockname()
    print('Listening on {}'.format(addr))

    while True:
        client_sock,addr = server.accept()
        q = queue.Queue()
        send_queues[client_sock.fileno()] = q
        eventlet.spawn_n(handle_client_recv,
                         client_sock,
                         addr)
        eventlet.spawn_n(handle_client_send,
                         client_sock,
                         q,
                         addr)
        print('Connection from {}'.format(addr))
```

我们可以使用我们的多线程客户端进行测试，以确保它按预期工作。

正如你所看到的，它与我们的多线程服务器几乎完全相同，只是做了一些更改以使用`eventlet`。请注意，我们已经删除了同步代码和`send_queues`周围的`lock`。我们仍然使用队列，尽管它们是`eventlet`库的队列，因为我们希望保留`Queue.get()`的阻塞行为。

### 注意

在 eventlet 网站上有更多使用 eventlet 进行编程的示例，网址为[`eventlet.net/doc/examples.html`](http://eventlet.net/doc/examples.html)。

# 基于 asyncio 的聊天服务器

`asyncio`标准库模块是 Python 3.4 中的新功能，它是在标准库中围绕异步 I/O 引入一些标准化的努力。`asyncio`库使用基于协程的编程风格。它提供了一个强大的循环类，我们的程序可以将准备好的任务（称为协程）提交给它，以进行异步执行。事件循环处理任务的调度和性能优化，以处理阻塞 I/O 调用。

它内置支持基于套接字的网络，这使得构建基本服务器成为一项简单的任务。让我们看看如何做到这一点。创建一个名为`5.1-chat_server-asyncio.py`的新文件，并将以下代码保存在其中：

```py
import asyncio
import tincanchat

HOST = tincanchat.HOST
PORT = tincanchat.PORT
clients = []

class ChatServerProtocol(asyncio.Protocol):
  """ Each instance of class represents a client and the socket 
       connection to it. """

    def connection_made(self, transport):
        """ Called on instantiation, when new client connects """
           self.transport = transport
        self.addr = transport.get_extra_info('peername')
        self._rest = b''
        clients.append(self)
        print('Connection from {}'.format(self.addr))

    def data_received(self, data):
        """ Handle data as it's received. Broadcast complete
        messages to all other clients """
        data = self._rest + data
        (msgs, rest) = tincanchat.parse_recvd_data(data)
        self._rest = rest
        for msg in msgs:
            msg = msg.decode('utf-8')
            msg = '{}: {}'.format(self.addr, msg)
            print(msg)
            msg = tincanchat.prep_msg(msg)
            for client in clients:
                client.transport.write(msg)  # <-- non-blocking

    def connection_lost(self, ex):
        """ Called on client disconnect. Clean up client state """
        print('Client {} disconnected'.format(self.addr))
        clients.remove(self)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    # Create server and initialize on the event loop
    coroutine = loop.create_server(ChatServerProtocol,
                                  host=HOST,
                                  port=PORT)
    server = loop.run_until_complete(coroutine)
    # print listening socket info
    for socket in server.sockets:
        addr = socket.getsockname()
        print('Listening on {}'.format(addr))
    # Run the loop to process client connections
    loop.run_forever()
```

同样，我们可以使用我们的多线程客户端进行测试，以确保它按我们的预期工作。

让我们逐步了解代码，因为它与我们以前的服务器有很大不同。我们首先定义了服务器行为，它是`asyncio.Protocol`抽象类的子类。我们需要重写三个方法`connection_made()`、`data_received()`和`connection_lost()`。通过使用这个类，我们可以在事件循环上实例化一个新的服务器，它将监听一个套接字，并根据这三种方法的内容进行操作。我们在主要部分中使用`loop.create_server()`调用来执行这个实例化。

当新客户端连接到我们的套接字时，将调用`connection_made()`方法，这相当于`socket.accept()`接收到一个连接。它接收的`transport`参数是一个可写流对象，也就是一个`asyncio.WriteTransport`实例。我们将使用它向套接字写入数据，因此通过将其分配给`self.transport`属性来保留它。我们还通过使用`transport.get_extra_info('peername')`来获取客户端的主机和端口。这是传输的`socket.getpeername()`的等价物。然后我们设置一个`rest`属性来保存从`tincanchat.parse_recvd_data()`调用中剩下的数据，然后我们将我们的实例添加到全局的`clients`列表中，以便其他客户端可以向其进行广播。

`data_received()`方法是发生操作的地方。每次`Protocol`实例的套接字接收到任何数据时，都会调用此函数。这相当于`poll.poll()`返回`POLLIN`事件，然后我们在套接字上执行`recv()`。调用此方法时，将接收到的数据作为`data`参数传递给该方法，然后我们使用`tincanchat.parse_recvd_data()`进行解析，就像以前一样。

然后，我们遍历接收到的任何消息，并对每条消息，通过在客户端的传输对象上调用`write()`方法，将其发送到`clients`列表中的每个客户端。这里需要注意的重要一点是，`Transport.write()`调用是非阻塞的，因此会立即返回。发送只是被提交到事件循环中，以便很快安排完成。 

`connection_lost()`方法在客户端断开连接或连接丢失时被调用，这相当于`socket.recv()`返回一个空结果，或者一个`ConnectionError`。在这里，我们只是从`clients`全局列表中移除客户端。

在主模块代码中，我们获取一个事件循环，然后创建我们的`Protocol`服务器的实例。调用`loop.run_until_complete()`在事件循环上运行我们服务器的初始化阶段，设置监听套接字。然后我们调用`loop.run_forever()`，这将使我们的服务器开始监听传入的连接。

# 更多关于框架

在最后一个示例中，我打破了我们通常的过程形式，采用了面向对象的方法，原因有两个。首先，虽然可以使用`asyncio`编写纯过程风格的服务器，但这需要比我们在这里提供的更深入的理解协程。如果你感兴趣，可以阅读`asyncio`文档中的一个示例协程风格的回显服务器，网址为[`docs.python.org/3/library/asyncio-stream.html#asyncio-tcp-echo-server-streams`](https://docs.python.org/3/library/asyncio-stream.html#asyncio-tcp-echo-server-streams)。

第二个原因是，这种基于类的方法通常是在完整系统中更易管理的模型。

实际上，Python 3.4 中有一个名为`selectors`的新模块，它提供了一个基于`select`模块中 IO 原语快速构建面向对象服务器的 API（包括`poll`）。文档和示例可以在[`docs.python.org/3.4/library/selectors.html`](https://docs.python.org/3.4/library/selectors.html)中找到。

还有其他第三方事件驱动框架可用，流行的有 Tornado（[www.tornadoweb.org](http://www.tornadoweb.org)）和 circuits（[`github.com/circuits/circuits`](https://github.com/circuits/circuits)）。如果你打算为项目选择一个框架，这两个都值得进行比较。

此外，没有讨论 Python 异步 I/O 的内容是完整的，而没有提到 Twisted 框架。直到 Python 3 之前，这一直是任何严肃的异步 I/O 工作的首选解决方案。它是一个事件驱动引擎，支持大量的网络协议，性能良好，并且拥有庞大而活跃的社区。不幸的是，它还没有完全转向 Python 3（迁移进度可以在[`rawgit.com/mythmon/twisted-py3-graph/master/index.html`](https://rawgit.com/mythmon/twisted-py3-graph/master/index.html)中查看）。由于我们在本书中专注于 Python 3，我们决定不对其进行详细处理。然而，一旦它到达那里，Python 3 将拥有另一个非常强大的异步框架，这将值得你为你的项目进行调查。

# 推动我们的服务器前进

有许多事情可以做来改进我们的服务器。对于多线程系统，通常会有一种机制来限制同时使用的线程数量。这可以通过保持活动线程的计数并在超过阈值时立即关闭来自客户端的任何新传入连接来实现。

对于我们所有的服务器，我们还希望添加一个日志记录机制。我强烈推荐使用标准库`logging`模块，它的文档非常完整，包含了很多好的例子。如果你以前没有使用过，基本教程是一个很好的起点，可以在[`docs.python.org/3/howto/logging.html#logging-basic-tutorial`](https://docs.python.org/3/howto/logging.html#logging-basic-tutorial)中找到。

我们还希望更全面地处理错误。由于我们的服务器意图是长时间运行并且最小干预，我们希望确保除了关键异常之外的任何情况都不会导致进程退出。我们还希望确保处理一个客户端时发生的错误不会影响其他已连接的客户端。

最后，聊天程序还有一些基本功能可能会很有趣：让用户输入一个名字，在其他客户端上显示他们的消息旁边；添加聊天室；以及在套接字连接中添加 TLS 加密以提供隐私和安全性。

# 总结

我们研究了如何在考虑诸如连接顺序、数据传输中的数据帧等方面开发网络协议，以及这些选择对客户端和服务器程序架构的影响。

我们通过编写一个简单的回显服务器并将其升级为多客户端聊天服务器，演示了网络服务器和客户端的不同架构，展示了多线程和事件驱动模型之间的差异。我们讨论了围绕线程和事件驱动架构的性能问题。最后，我们看了一下`eventlet`和`asyncio`框架，这些框架在使用事件驱动方法时可以极大地简化服务器编写的过程。

在本书的下一章和最后一章中，我们将探讨如何将本书的几个主题融合起来，用于编写服务器端的 Web 应用程序。
