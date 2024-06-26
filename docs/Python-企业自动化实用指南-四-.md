# Python 企业自动化实用指南（四）

> 原文：[`zh.annas-archive.org/md5/0bfb2f4dbc80a06d99550674abb53d0d`](https://zh.annas-archive.org/md5/0bfb2f4dbc80a06d99550674abb53d0d)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十八章：使用 Python 构建网络扫描器

在本章中，我们将构建一个网络扫描器，它可以识别网络上的活动主机，并且我们还将扩展它以包括猜测每个主机上正在运行的操作系统以及打开/关闭的端口。通常，收集这些信息需要多个工具和一些 Linux ninja 技能来获取所需的信息，但是使用 Python，我们可以构建自己的网络扫描器代码，其中包括任何工具，并且我们可以获得定制的输出。

本章将涵盖以下主题：

+   理解网络扫描器

+   使用 Python 构建网络扫描器

+   在 GitHub 上分享您的代码

# 理解网络扫描器

网络扫描器用于扫描提供的网络 ID 范围，包括第 2 层和第 3 层。它可以发送请求并分析数十万台计算机的响应。此外，您可以扩展其功能以显示一些共享资源，通过 Samba 和 NetBIOS 协议，以及运行共享协议的服务器上的未受保护数据的内容。渗透测试中网络扫描器的另一个用途是，当白帽黑客尝试模拟对网络资源的攻击以查找漏洞并评估公司的安全性时。渗透测试的最终目标是生成一份报告，其中包含目标系统中所有弱点，以便原始点可以加强和增强安全策略，以抵御潜在的真实攻击。

# 使用 Python 构建网络扫描器

Python 工具提供了许多本地模块，并支持与套接字和 TCP/IP 一般的工作。此外，Python 可以使用系统上可用的现有第三方命令来启动所需的扫描并返回结果。这可以使用我们之前讨论过的`subprocess`模块来完成，在第九章中，*使用 Subprocess 模块*。一个简单的例子是使用 Nmap 来扫描子网，就像下面的代码中所示：

```py
import subprocess
from netaddr import IPNetwork
network = "192.168.1.0/24" p = subprocess.Popen(["sudo", "nmap", "-sP", network], stdout=subprocess.PIPE)   for line in p.stdout:
  print(line)
```

在这个例子中，我们可以看到以下内容：

+   首先，我们导入了`subprocess`模块以在我们的脚本中使用。

+   然后，我们使用`network`参数定义了要扫描的网络。请注意，我们使用了 CIDR 表示法，但我们也可以使用子网掩码，然后使用 Python 的`netaddr`模块将其转换为 CIDR 表示法。

+   `subprocess`中的`Popen()`类用于创建一个对象，该对象将发送常规的 Nmap 命令并扫描网络。请注意，我们添加了一些标志`-sP`来调整 Nmap 的操作，并将输出重定向到`subprocess.PIPE`创建的特殊管道。

+   最后，我们迭代创建的管道并打印每一行。

脚本输出如下：

**![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00222.jpeg)**在 Linux 上访问网络端口需要 root 访问权限，或者您的帐户必须属于 sudoers 组，以避免脚本中的任何问题。此外，在运行 Python 代码之前，系统上应该安装`nmap`软件包。

这是一个简单的 Python 脚本，我们可以直接使用 Nmap 工具，而不是在 Python 中使用它。然而，使用 Python 代码包装 Nmap（或任何其他系统命令）给了我们灵活性，可以定制输出并以任何方式自定义它。在下一节中，我们将增强我们的脚本并添加更多功能。

# 增强代码

尽管 Nmap 的输出给了我们对扫描网络上的活动主机的概述，但我们可以增强它并获得更好的输出视图。例如，我需要在输出的开头知道主机的总数，然后是每个主机的 IP 地址、MAC 地址和 MAC 供应商，但以表格形式，这样我就可以轻松地找到任何主机以及与之相关的所有信息。

因此，我将设计一个函数并命名为`nmap_report()`。这个函数将获取从`subprocess`管道生成的标准输出，并提取所需的信息，并以表格格式进行格式化：

```py
def nmap_report(data):
  mac_flag = ""
  ip_flag = ""
  Host_Table = PrettyTable(["IP", "MAC", "Vendor"])
  number_of_hosts = data.count("Host is up ")    for line in data.split("\n"):
  if "MAC Address:" in line:
  mac = line.split("(")[0].replace("MAC Address: ", "")
  vendor = line.split("(")[1].replace(")", "")
  mac_flag = "ready"
  elif "Nmap scan report for" in line:
  ip = re.search(r"Nmap scan report for (.*)", line).groups()[0]
  ip_flag = "ready"      if mac_flag == "ready" and ip_flag == "ready":
  Host_Table.add_row([ip, mac, vendor])
  mac_flag = ""
  ip_flag = ""    print("Number of Live Hosts is {}".format(number_of_hosts))
  print Host_Table
```

首先，我们可以通过计算传递输出中“主机已启动”的出现次数来获取活动主机的数量，并将其分配给`number_of_hosts`参数。

其次，Python 有一个很好的模块叫做`PrettyTable`，它可以创建一个文本表，并根据其中的数据处理单元大小。该模块接受表头作为列表，并使用`add_row()`函数向创建的表中添加行。因此，第一件事是导入这个模块（如果尚未安装，则安装它）。在我们的例子中，我们将传递一个包含三个项目（`IP`，`MAC`，`Vendor`）的列表给`PrettyTable`类（从`PrettyTable`模块导入），以创建表头。

现在，为了填充这个表，我们将在`\n`（回车）上进行分割。分割结果将是一个列表，我们可以迭代以获取特定信息，如 MAC 地址和 IP 地址。我们使用了一些分割和替换技巧来提取 MAC 地址。此外，我们使用了正则表达式`search`函数从输出中获取 IP 地址部分（如果启用了 DNS，则获取主机名）。

最后，我们将这些信息添加到创建的`Host_Table`中，并继续迭代下一行。

以下是完整的脚本：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   import subprocess
from netaddr import IPNetwork, AddrFormatError
from prettytable import PrettyTable
import re

def nmap_report(data):
  mac_flag = ""
  ip_flag = ""
  Host_Table = PrettyTable(["IP", "MAC", "Vendor"])
  number_of_hosts = data.count("Host is up ")    for line in data.split("\n"):
  if "MAC Address:" in line:
  mac = line.split("(")[0].replace("MAC Address: ", "")
  vendor = line.split("(")[1].replace(")", "")
  mac_flag = "ready"
  elif "Nmap scan report for" in line:
  ip = re.search(r"Nmap scan report for (.*)", line).groups()[0]
  ip_flag = "ready"      if mac_flag == "ready" and ip_flag == "ready":
  Host_Table.add_row([ip, mac, vendor])
  mac_flag = ""
  ip_flag = ""    print("Number of Live Hosts is {}".format(number_of_hosts))
  print Host_Table

network = "192.168.1.0/24"   try:
  IPNetwork(network) 
  p = subprocess.Popen(["sudo", "nmap", "-sP", network], stdout=subprocess.PIPE)
  nmap_report(p.stdout.read()) except AddrFormatError:
  print("Please Enter a valid network IP address in x.x.x.x/y format")
```

请注意，我们还使用了`netaddr.IPNetwork()`类对`subprocess`命令进行了预检查。这个类将在执行`subprocess`命令*之前*验证网络是否格式正确，否则该类将引发一个异常，应该由`AddrFormatError`异常类处理，并向用户打印一个定制的错误消息。

脚本输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00223.jpeg)

现在，如果我们将网络更改为不正确的值（子网掩码错误或网络 ID 无效），`IPNetwork()`类将抛出一个异常，并打印出这个错误消息：

```py
network = "192.168.300.0/24"  
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00224.jpeg)

# 扫描服务

主机机器上运行的服务通常会在操作系统中打开一个端口，并开始监听它，以接受传入的 TCP 通信并开始三次握手。在 Nmap 中，您可以在特定端口上发送一个 SYN 数据包，如果主机以 SYN-ACK 响应，则服务正在运行并监听该端口。

让我们测试 HTTP 端口，例如在[google.com](https://www.google.com/)上，使用`nmap`：

```py
nmap -p 80 www.google.com
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00225.jpeg)

我们可以使用相同的概念来发现路由器上运行的服务。例如，运行 BGP 守护程序的路由器将监听端口`179`以接收/更新/保持活动/通知消息。如果要监视路由器，则应启用 SNMP 服务，并应监听传入的 SNMP get/set 消息。MPLS LDP 通常会监听`646`以与其他邻居建立关系。以下是路由器上运行的常见服务及其监听端口的列表：

| **服务** | **监听端口** |
| --- | --- |
| FTP | `21` |
| SSH | `22` |
| TELNET | `23` |
| SMTP | `25` |
| HTTP | `80` |
| HTTPS | `443` |
| SNMP | `161` |
| BGP | `179` |
| LDP | `646` |
| RPCBIND | `111` |
| NETCONF | `830` |
| XNM-CLEAR-TEXT | `3221` |

我们可以创建一个包含所有这些端口的字典，并使用`subprocess`和 Nmap 对它们进行扫描。然后我们使用返回的输出来创建我们的表，列出每次扫描的开放和关闭的端口。另外，通过一些额外的逻辑，我们可以尝试相关信息来猜测设备功能的操作系统类型。例如，如果设备正在监听端口`179`（BGP 端口），那么设备很可能是网络网关，如果它监听`389`或`636`，那么设备正在运行 LDAP 应用程序，可能是公司的活动目录。这将帮助我们在渗透测试期间针对设备创建适当的攻击。

废话不多说，让我们快速把我们的想法和笔记放在下面的脚本中：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   from prettytable import PrettyTable
import subprocess
import re

def get_port_status(port, data):
  port_status = re.findall(r"{0}/tcp (\S+) .*".format(port), data)[0]
 return port_status

Router_Table = PrettyTable(["IP Address", "Opened Services"]) router_ports = {"FTP": 21,
  "SSH": 22,
  "TELNET": 23,
  "SMTP": 25,
  "HTTP": 80,
  "HTTPS": 443,
  "SNMP": 161,
  "BGP": 179,
  "LDP": 646,
  "RPCBIND": 111,
  "NETCONF": 830,
  "XNM-CLEAR-TEXT": 3221}     live_hosts = ["10.10.10.1", "10.10.10.2", "10.10.10.65"]     services_status = {} for ip in live_hosts:
  for service, port in router_ports.iteritems():
  p = subprocess.Popen(["sudo", "nmap", "-p", str(port), ip], stdout=subprocess.PIPE)
  port_status = get_port_status(port, p.stdout.read())
  services_status[service] = port_status

    services_status_joined = "\n".join("{} : {}".format(key, value) for key, value in services_status.iteritems())    Router_Table.add_row([ip, services_status_joined])     print Router_Table
```

在这个例子中，我们可以看到以下内容：

+   我们开发了一个名为`get_port_status()`的函数，用于获取 Nmap 端口扫描结果，并使用`findall()`函数内的正则表达式来搜索端口状态（打开、关闭、过滤等）。它返回端口状态结果。

+   然后，我们在`router_ports`字典中添加了映射到服务名称的服务端口，这样我们就可以使用相应的服务名称（字典键）访问任何端口值。此外，我们在`live_hosts`列表中定义了路由器主机的 IP 地址。请注意，我们可以使用`nmap`和`-sP`标志来获取活动主机，就像我们之前在之前的脚本中所做的那样。

+   现在，我们可以遍历`live_hosts`列表中的每个 IP 地址，并执行 Nmap 来扫描`router_ports`字典中的每个端口。这需要一个嵌套的`for`循环，因此对于每个设备，我们都要遍历一个端口列表，依此类推。结果将被添加到`services_status`字典中——服务名称是字典键，端口状态是字典值。

+   最后，我们将结果添加到使用`prettytable`模块创建的`Router_Table`中，以获得一个漂亮的表格。

脚本输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00226.jpeg)

# 在 GitHub 上分享您的代码

GitHub 是一个可以使用 Git 分享代码并与他人合作的地方。Git 是由 Linus Trovalds 发明和创建的源代码版本控制平台，他开始了 Linux，但在许多开发人员为其做出贡献的情况下，维护 Linux 开发成为了一个问题。他创建了一个分散式版本控制，任何人都可以获取整个代码（称为克隆或分叉），进行更改，然后将其推送回中央仓库，以与其他开发者的代码合并。Git 成为许多开发人员共同合作的首选方法。您可以通过 GitHub 提供的这个 15 分钟课程交互式地学习如何在 Git 中编码：[`try.github.io`](https://try.github.io)。

GitHub 是托管这些项目的网站，使用 Git 进行版本控制。它就像一个开发者社交媒体平台，您可以跟踪代码开发、编写维基百科，或提出问题/错误报告，并获得开发者的反馈。同一项目上的人可以讨论项目进展，并共同分享代码，以构建更好、更快的软件。此外，一些公司将您在 GitHub 账户中共享的代码和仓库视为在线简历，衡量您在感兴趣的语言中的技能和编码能力。

# 在 GitHub 上创建账户

在分享您的代码或下载其他代码之前，首先要做的是创建您的账户。

前往[`github.com/join?source=header-home`](https://github.com/join?source=header-home)，选择用户名、密码和电子邮件地址，然后点击绿色的“创建账户”按钮。

第二件事是选择您的计划。默认情况下，免费计划是可以的，因为它为您提供无限的公共仓库，并且您可以推送任何您喜欢的语言开发的代码。但是，免费计划不会使您的仓库私有，并允许其他人搜索和下载它。如果您不在公司中从事秘密或商业项目，这并不是一个不可接受的问题，但是您需要确保不在代码中分享任何敏感信息，如密码、令牌或公共 IP 地址。

# 创建和推送您的代码

现在我们准备与他人分享代码。在创建 GitHub 账户后的第一件事是创建一个仓库来托管您的文件。通常，您为每个项目创建一个仓库（而不是每个文件），它包含与彼此相关的项目资产和文件。

点击右上角的+图标，就在您的个人资料图片旁边，创建一个新的仓库：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00227.jpeg)

你将被重定向到一个新页面，在这里你可以输入你的仓库名称。请注意，你可以选择任何你喜欢的名称，但它不应与你的个人资料中的其他仓库冲突。此外，你将获得一个唯一的 URL，以便任何人都可以访问它。你可以设置仓库的设置，比如它是公开的还是私有的（只适用于付费计划），以及是否要用 README 文件初始化它。这个文件使用**markdown**文本格式编写，包括关于你的项目的信息，以及其他开发人员使用你的项目时需要遵循的步骤。

最后，你将有一个选项来添加一个`.gitignore`文件，告诉 Git 在你的目录中忽略跟踪某种类型的文件，比如日志、`pyc`编译文件、视频等：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00228.jpeg)

最后，你将创建一个仓库，并获得一个唯一的 URL。记下这个 URL，因为我们稍后将用它来推送文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00229.jpeg)

现在是分享你的代码的时候了。我将使用 PyCharm 内置的 Git 功能来完成这项工作，尽管你也可以在 CLI 中执行相同的步骤。此外，还有许多其他可用的 GUI 工具（包括 GitHub 本身提供的工具）可以管理你的 GIT 仓库。我强烈建议你在按照这些步骤之前先接受 GitHub 提供的 Git 培训（[`try.github.io`](https://try.github.io)）：

1.  转到 VCS | Import into Version Control | Create Git Repository：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00230.jpeg)

1.  选择存储项目文件的本地文件夹：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00231.jpeg)

这将在文件夹中创建一个本地的 Git 仓库。

1.  在侧边栏中突出显示所有需要跟踪的文件，右键单击它们，然后选择 Git | Add：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00232.jpeg)PyCharm 使用文件颜色代码来指示 Git 中跟踪的文件类型。当文件没有被跟踪时，它们将被标记为红色，当文件被添加到 Git 中时，它们将被标记为绿色。这样可以让你在不运行命令的情况下轻松了解文件的状态。

1.  通过转到 VCS | Git | Remotes 来定义在 GitHub 中将映射到本地仓库的远程仓库：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00233.jpeg)

1.  输入仓库名称和我们创建仓库时记下的 URL；点击两次“确定”退出窗口：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00234.jpeg)

1.  最后一步是提交你的代码。转到 VCS | Git | Commit，从打开的弹出窗口中选择你要跟踪的文件，在提交消息部分输入描述性消息，而不是点击提交，点击旁边的小箭头并选择提交和推送。可能会打开一个对话框，告诉你 Git 用户名未定义。只需输入你的名字和电子邮件，并确保选中“全局设置属性”框，然后点击设置和提交：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00235.jpeg)

PyCharm 为你提供了将代码推送到 Gerrit 进行代码审查的选项。如果你有一个，你也可以在其中分享你的文件。否则，点击推送。

将出现一个通知消息，告诉你推送成功完成：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00236.jpeg)

你可以从浏览器刷新你的 GitHub 仓库 URL，你将看到所有存储在其中的文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00237.jpeg)

现在，每当你在跟踪文件中的代码中进行任何更改并提交时，这些更改将被跟踪并添加到版本控制系统中，并可在 GitHub 上供其他用户下载和评论。

# 总结

在本章中，我们构建了我们的网络扫描器，它可以在授权的渗透测试期间使用，并学习了如何扫描设备上运行的不同服务和应用程序以检测它们的类型。此外，我们将我们的代码分享到 GitHub，以便我们可以保留我们代码的不同版本，并允许其他开发人员使用我们分享的代码并增强它，然后再次与其他人分享。
