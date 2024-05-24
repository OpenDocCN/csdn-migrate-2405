# Python Web 爬虫实用指南（三）

> 原文：[`zh.annas-archive.org/md5/AB12C428C180E19BF921ADFBD1CC8C3E`](https://zh.annas-archive.org/md5/AB12C428C180E19BF921ADFBD1CC8C3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三部分：高级概念

在本节中，您将学习如何抓取安全网站，以及处理 HTML 表单和 Web cookies。您还将探索面向目标数据的基于 Web 的 API，并使用基于 Web 的测试框架，如 Selenium。

本节包括以下章节：

+   第六章，*处理安全 Web*

+   第七章，*使用基于 Web 的 API 提取数据*

+   第八章，*使用 Selenium 抓取 Web*

+   第九章，*使用正则表达式提取数据*


# 第六章：处理安全网络

到目前为止，我们已经了解了可以用来访问和抓取网络内容的网络开发技术、数据查找技术和 Python 库。

现今存在各种形式的基于网络的安全措施，用于保护我们免受未经身份验证的使用和对敏感网络内容的未经授权访问。许多工具和技术被网站应用；有些针对用户行为，而有些针对网站内容及其可用性。

安全网络（或基于网络的安全功能）被认为是由网站实施并被希望使用或查看网站内容的最终用户所利用的技术之一。我们将从网络抓取的角度涵盖一些处理这些功能的基本概念。

在本章中，我们将学习以下主题：

+   安全网络简介

+   HTML `<form>`处理

+   处理用户身份验证

+   处理 cookie 和会话

# 技术要求

本章需要一个网络浏览器（Google Chrome 或 Mozilla Firefox）。我们将使用以下 Python 库：

+   `requests`

+   `pyquery`

如果这些库在您当前的 Python 设置中不存在，请参阅第二章，*Python 和网络 - 使用 urllib 和 Requests*，*设置事物*部分，获取有关其安装和设置的更多信息。

本章的代码文件可在本书的 GitHub 存储库中找到：[`github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python/tree/master/Chapter06`](https://github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python/tree/master/Chapter06)。

# 安全网络简介

实施基于网络的安全功能（或用于维护安全访问状态的功能）以访问信息的方式正在日益增长。随着网络技术的不断发展，网站和网络应用程序部署基本或高度复杂的安全机制。

安全的网络内容在爬取和抓取的角度上通常具有挑战性。在本节中，您将了解一些基本的基于安全的概念。我们将在接下来的章节中探讨这些概念及其实施。

接下来的章节将讨论一些安全功能概念或容易受到安全威胁的概念。这些概念可以独立或协作地在网站中使用一些基础工具或措施来实施。

# 表单处理

这也被称为 HTML `<form>`处理、表单处理或表单提交。这种方法处理和处理 HTML `<form>`内的数据。

HTML `<form>`或`<form>`标签内的元素，如`<input>`、`<option>`、`<button>`、`<textarea>`等，通常用于收集和提交数据。请访问 W3School HTML 表单（[`www.w3schools.com/html/html_forms.asp`](https://www.w3schools.com/html/html_forms.asp)）获取 HTML 表单的实际示例和详细信息。

HTTP 方法或请求方法，如`GET`、`POST`、`PUT`等，用于在网页之间访问或提交数据。有关 HTTP 的更多信息，请访问[`www.w3.org/Protocols/`](https://www.w3.org/Protocols/)。

从安全角度来看，HTML `<form>` 可以包含动态和隐藏或系统生成的值，用于管理验证、为字段提供值，或在表单提交期间执行基于安全的实现。具有诸如`<input type="hidden"...>`的字段的表单在页面上对用户可能不可见。在这种情况下，用户必须从页面源代码或基于浏览器的开发者工具获取帮助。

一个带有表单的网页可能在某些字段中显示并要求输入，并且可以在后端或源代码中包含一些额外的字段，其中可能包含用户或系统信息。这些信息在幕后被收集和处理，用于基于网页的分析、营销、用户和系统识别、安全管理等。

有关表单处理的更多信息，请参阅第三章，*使用 LXML、XPath 和 CSS 选择器*，*使用网页浏览器开发者工具访问网页内容*部分。

# Cookies 和会话

要访问由浏览网站设置的 cookie 和会话值，请参阅第一章，*网页抓取基础知识*，*开发者工具*部分的*数据查找技术*部分。现在，让我们了解一下 cookie 和会话是什么。

# Cookies

Cookie 是由网站在您的系统或计算机上生成和存储的数据。Cookie 中的数据有助于识别用户对网站的网络请求。Cookie 中存储的数据以`键:值`对的形式存储。存储在 cookie 中的数据有助于网站访问该数据，并以快速交互的形式传输某些保存的值。

Cookie 还允许网站跟踪用户资料、他们的网页习惯等，并利用这些信息进行索引、页面广告和营销活动。

基于 cookie 的数据可以持续一个会话（即从加载网页到关闭浏览器的时间）形成所谓的会话 cookie，或者持续几天、几周或几个月，这被称为永久或存储的 cookie。Cookie 还可以包含以秒为单位的过期值，一旦该值表示的时间段过去，cookie 就会过期或从系统中删除。

有关 cookie 的更多信息，请参阅第一章，*网页抓取基础知识*，*了解网页开发和技术*部分的*HTTP*部分。您也可以访问[`www.aboutcookies.org/`](https://www.aboutcookies.org/)和[`www.allaboutcookies.org/`](http://www.allaboutcookies.org/)获取更多信息。

# 会话

会话是强制两个系统之间基于状态的通信的属性。会话用于临时存储用户信息，并在用户退出浏览器或离开网站时被删除。

会话用于维护安全活动。网站生成一个唯一的标识号，也称为会话 ID 或会话密钥，用于独立跟踪他们的用户或基于安全的特性。在大多数情况下，可以使用 cookie 来跟踪会话的可用性。

# 用户认证

用户认证涉及处理和管理基于用户的身份识别过程。网站通过其注册页面提供用户注册，并收集用户对所需或可用字段的输入。用户的详细信息被保存在安全的地方，如云端或基于服务器的数据库，或任何其他安全系统。

注册用户经过验证，被允许从他们的系统登录和退出，并通过他们的用户名、密码和电子邮件地址进行识别。

表单处理、cookies、会话管理和其他基于安全性的措施可以单独或协同部署用于这个过程。

在上一章中，我们探讨并解决了基于信息可用性、访问网页、应用各种 HTTP 方法等各种情景，以及在网页抓取过程中可能实施或面临的各种措施和情况。本章的各节涉及可以实施或在网页抓取过程中可能面临的各种措施和情况。

# HTML <form>处理

在本节中，我们将处理表单处理或表单提交，以便从[`toscrape.com`](http://toscrape.com)（ViewState）搜索活动。ViewState 是基于 AJAX 的过滤表单。

这个特定的表单提交是通过 AJAX（[`www.w3schools.com/js/js_ajax_intro.asp`](https://www.w3schools.com/js/js_ajax_intro.asp)）在多个步骤中执行的。有关 AJAX 的更多信息，请访问[W3Schools AJAX](https://www.w3schools.com/js/js_ajax_intro.asp)：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/03ddba00-4ba4-4ab0-8f5d-62a9bcfa6239.png)

http://toscrape.com 中的引用部分具有各种端点

让我们设置代码。需要导入`pyquery`和`requests`库，并收集所需的 URL，以便可以使用它们。`processRequests()`函数，连同位置参数和命名参数，用于处理对所提供`url`的请求，使用基于`params`参数的 HTTP `POST` 和 `GET` 方法返回 PyQuery 对象作为响应。

我们还对迭代`authorTags`感兴趣，并分别收集`quoteAuthor`和`message`。以类似的方式，可以提取从页面获得的任何信息：

```py
from pyquery import PyQuery as pq
import requests
mainurl = "http://toscrape.com/" searchurl = "http://quotes.toscrape.com/search.aspx" filterurl = "http://quotes.toscrape.com/filter.aspx" quoteurl = "http://quotes.toscrape.com/" authorTags = [('Albert Einstein', 'success'), ('Thomas A. Edison', 'inspirational')]

def processRequests(url, params={}, customheaders={}):
    if len(params) > 0:
        response = requests.post(url, data=params, headers=customheaders)
    else:
        response = requests.get(url)   return pq(response.text)

if __name__ == '__main__':
    for authorTag in authorTags:
        authorName,tagName= authorTag
```

以下屏幕截图显示了在前面的代码中定义的`searchurl`页面的内容。存在两个单独的下拉菜单，分别用于作者和他们的标签的选项：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/6bc86d6b-01ca-4b74-baa0-214515abe53c.png)

http://quotes.toscrape.com/search.aspx 带有作者和标签的`searchurl`

让我们加载`searchurl`，如下面的代码所示，并从作者下拉菜单中选择一个作者。使用 AJAX 生成`<option>`标签，以供作者的选定`<option>`：

请参阅第三章，*使用 LXML、XPath 和 CSS 选择器*，*使用 Web 浏览器开发工具访问 Web 内容*部分，以及第一章，*Web 抓取基础知识*，*数据查找技术*和*开发人员工具*部分。

```py
#Step 1: load searchURL searchResponse = processRequests(searchurl)
author = searchResponse.find('select#author option:contains("' + authorName + '")').attr('value')
viewstate = searchResponse.find('input#__VIEWSTATE').attr('value')
tag = searchResponse.find('select#tag option').text()

print("Author: ", author)
print("ViewState: ", viewstate)
print("Tag: ", tag)
```

如您所见，使用 HTTP `GET` 调用`processRequests()`函数到`searchurl`，并将返回一个 PyQuery 对象作为响应。从`searchResponse`中，让我们收集必要的表单字段。收集诸如`author`、`viewstate`和`tag`之类的字段，并在每次迭代中获得的字段的值显示在以下输出中：

```py
Author: Albert Einstein
ViewState: NTA2MjI4NmE1Y2Q3NGFhMzhjZTgxMzM4ZWU0NjU4MmUsQWxiZXJ0IEVpbnN0ZWluLEouSy4gUm93bGluZyxKYW5lIEF1c3Rlbi............BDdW1taW5ncyxLaGFsZWQgSG9zc2VpbmksSGFycGVyIExlZSxNYWRlbGVpbmUgTCdFbmdsZQ==
Tag: ----------

Author: Thomas A. Edison
ViewState: ZjNhZTUwZDYzY2YyNDZlZmE5ODY0YTI5OWRhNDAyMDYsQWxiZXJ0IEVpbnN0ZWluLEouSy4gUm93bGluZyxKYW5lIEF1c3Rlbi............BDdW1taW5ncyxLaGFsZWQgSG9zc2VpbmksSGFycGVyIExlZSxNYWRlbGVpbmUgTCdFbmdsZQ==
Tag: ----------
```

从前面的输出中，我们可以看到`viewstate (<input id="__VIEWSTATE"..>)`在`authorTags`的两次迭代中包含唯一值。

`ViewState`是由网站生成的用于识别页面的各个状态的唯一和随机值，通常作为隐藏的`<input>`值。这种`<form>`值存在于大多数使用`<form>`和内置 ASP 或 ASP.NET 技术的网站中。`ViewState`值在客户端上使用，它保留或保持了`<form>`元素的值，以及页面的身份。使用`ViewState`是与状态管理相关的技术之一。有关更多信息，请访问来自 C#Corner 的文章，网址为[`www.c-sharpcorner.com/article/Asp-Net-state-management-techniques/`](https://www.c-sharpcorner.com/article/Asp-Net-state-management-techniques/)。

`ViewState`的值对于获取所选作者的`<option>`标签是必不可少的。正如我们在下面的代码中所看到的，`params`是使用`author`、`tag`和`__VIEWSTATE`创建的，并通过 HTTP `POST` 和`customheaders`提交到`filterurl`，通过获取`filterResponse`。以下代码显示了当`filterurl`加载了作者和默认标签时会发生什么：

```py
#Step 2: load filterurl with author and default tag params = {'author': author, 'tag': tag, '__VIEWSTATE': viewstate}
customheaders = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Referer': searchurl
}

filterResponse = processRequests(filterurl,params,customheaders)
viewstate = filterResponse.find('input#__VIEWSTATE').attr('value')
tagSuccess = filterResponse.find('select#tag option:contains("' + tagName + '")').attr('value')
submitButton = filterResponse.find('input[name="submit_button"]').attr('value')
 print("Author: ", author)
print("ViewState: ", viewstate)
print("Tag: ", tagSuccess)
print("Submit: ", submitButton)
```

迭代前面的代码将产生以下输出：

+   `http://quotes.toscrape.com/filter.aspx` 页面上选择了作者（`托马斯·爱迪生`）和标签（`鼓舞人心`）：

```py
Author: Thomas A. Edison
ViewState: ZjNhZTUwZDYzY2YyNDZlZmE5ODY0YTI5OWRhNDAyMDYsQWxiZXJ0IEVpbnN0ZWluLEouSy4gUm93bGluZyxKYW5lIEF1c3Rlbi............BDdW1taW5ncyxLaGFsZWQgSG9zc2VpbmksSGFycGVyIExlZSxNYWRlbGVpbmUgTCdFbmdsZSwtLS0tLS0tLS0t
Tag: inspirational
Submit: Search
```

+   `http://quotes.toscrape.com/filter.aspx` 页面上选择了作者（`阿尔伯特·爱因斯坦`）和标签（`成功`）：

```py
Author: Albert Einstein
ViewState: NTA2MjI4NmE1Y2Q3NGFhMzhjZTgxMzM4ZWU0NjU4MmUsQWxiZXJ0IEVpbnN0ZWluLEouSy4gUm93bGluZyxKYW5lIEF1c3Rlbi............BDdW1taW5ncyxLaGFsZWQgSG9zc2VpbmksSGFycGVyIExlZSxNYWRlbGVpbmUgTCdFbmdsZSwtLS0tLS0tLS0t
Tag: success
Submit: Search
```

现在我们已经获得了每个`authorTags`的所有过滤`<form>`参数，最后一步是提交这些参数，即`params`到`filterurl`，使用`HTTP POST`并提取结果信息：

```py
#Step 3: load filterurl with author and defined tag params = {'author': author, 'tag': tagSuccess, 'submit_button': submitButton, '__VIEWSTATE': viewstate}  customheaders = {
'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
'Content-Type': 'application/x-www-form-urlencoded',
'Referer': filterurl
}

finalResponse = processRequests(filterurl,params, customheaders)

#Step 4: Extract results quote = finalResponse.find('div.quote span.content').text()

quoteAuthor = finalResponse.find('div.quote span.author').text()
message = finalResponse.find('div.quote span.tag').text()
print("Author: ", quoteAuthor, "\nMessage: ", message)
```

正如我们所看到的，`finalResponse`是由`processRequests()`返回的 PyQuery 对象，并被解析以获取`quote`、`quoteAuthor`和`message`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/9643fb0e-196e-454a-9c83-8b5f876c893c.png)

http://quotes.toscrape.com/filter.aspx ，结果为作者和标签

使用前面的代码进行第一次迭代的输出，包括`Author`和`Message`，如下所示：

```py
Author: Albert Einstein 
Message: success
```

以下是第二次迭代的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/b0b2458d-0504-46bf-b958-96352d940f17.png)

http://quotes.toscrape.com/filter.aspx ，结果为作者和标签

使用前面的代码进行第二次迭代的输出，包括`Author`和`Message`，如下所示：

```py
Author: Thomas A. Edison 
Message: inspirational
```

在前面的代码中显示了带有搜索和过滤操作的表单处理，以及使用隐藏字段。`ViewState`值由系统在后台使用，以识别所选选项并过滤与其关联的标签，从而得到作者的引用。

最终表单提交的 HTTP `POST`参数总数为四个，而页面上只显示或允许与两个选项交互。如果对值进行任何更改，例如`viewstate`，或者如果`viewstate`在`params`中丢失，将导致空引号，如下面的代码所示：

```py
#params={'author':author,'tag':tagSuccess,'submit_button':submitButton,'__VIEWSTATE':viewstate}
params={'author':author,'tag':tagSuccess,'submit_button':submitButton,'__VIEWSTATE':viewstate+"TEST"}
#params={'author':author,'tag':tagSuccess,'submit_button':submitButton}
......
finalResponse = processRequests(filterurl,params, customheaders)
......
print("Author: ", quoteAuthor, "\nMessage: ", message)

*Quote:* 
*Author:* 
*Message:*
```

表单提交不仅取决于从页面上可见的`<form>`元素中选择的必需参数，还可能存在隐藏的值和动态生成的状态表示，应该对其进行有效处理以获得成功的输出。

在下一节中，我们将处理表单提交和用户身份验证。

# 处理用户身份验证

在本节中，我们将探讨用于处理基本用户身份验证的任务，该任务可从[`testing-ground.scraping.pro/login`](http://testing-ground.scraping.pro/login)获得。用户身份验证通常使用一组唯一的信息进行处理，例如用户名、密码、电子邮件等，以在网站上识别用户。

本节中的代码涉及登录和更改登录凭据，以及从页面获取相应的消息。

如下面的屏幕截图所示，HTML `<form>`存在两个`<input>`框，用于接受用户名和密码（即登录凭据），这些是登录所需的。登录凭据是私密和安全的信息，但对于这个特定的测试站点，这些值是可见的，预定义的，并提供的，即`Username = "admin"`和`Password = "12345"`：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/49bb51c9-b821-430e-bca9-d5412494ebb5.png)

登录页面

使用这些凭据在[`testing-ground.scraping.pro/login`](http://testing-ground.scraping.pro/login)上进行登录处理，我们需要找到页面上用于处理输入凭据的`<form>`属性，即`action`和`method`。正如我们所看到的，HTTP `POST`方法将被应用于在[`testing-ground.scraping.pro/login?mode=login`](http://testing-ground.scraping.pro/login?mode=login)上执行表单提交：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/f8794ba7-eb6f-4496-98c5-61887b4e1267.png)

检查`<form>`元素

让我们继续设置代码。需要导入`pyquery`和`requests`库，并收集所需的 URL，以便可以使用它们：

```py
from pyquery import PyQuery as pq
import requests
mainUrl = "http://testing-ground.scraping.pro" loginUrl = "http://testing-ground.scraping.pro/login" logoutUrl = "http://testing-ground.scraping.pro/login?mode=logout" postUrl="http://testing-ground.scraping.pro/login?mode=login"
```

如下面的代码所示，`responseCookies()`函数将接受从`requests.get()`获得的响应对象，然后打印头信息和 cookies 信息。同样，`processParams()`函数接受基于`<form>`的参数，将被发布，并打印从页面获得的消息：

```py
def responseCookies(response):
    headers = response.headers
    cookies = response.cookies
    print("Headers: ", headers)
    print("Cookies: ", cookies)

def processParams(params):
    response = requests.post(postUrl, data=params)
    responseB = pq(response.text)
    message = responseB.find('div#case_login h3').text()
    print("Confirm Login : ",message)

if __name__ == '__main__': 
    requests.get(logoutUrl)

    response = requests.get(mainUrl)
    responseCookies(response)

    response = requests.get(loginUrl)
    responseCookies(response)
```

现在，让我们请求`logoutUrl`来清除 cookies 和会话（如果存在）。或者，对于一个全新的过程，我们可以分别请求`mainUrl`和`loginUrl`，并检查从`responseCookies()`接收到的消息。以下是输出：

```py
Headers:{'Vary':'Accept-Encoding','Content-Type':'text/html','Connection':'Keep-Alive', ..........., 'Content-Encoding':'gzip','X-Powered-By':'PHP/5.4.4-14+deb7u12'}
Cookies: <RequestsCookieJar[]>

Headers:{'Vary':'Accept-Encoding','Content-Type':'text/html','Connection':'Keep-Alive',.............., 'Set-Cookie':'tdsess=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT',........., 'Keep-Alive':'timeout=5, max=100','X-Powered-By':'PHP/5.4.4-14+deb7u12'}
Cookies: <RequestsCookieJar[]>
```

如前面的输出所示，`mainUrl`和`loginUrl`的 cookies 为空，并且除了来自`loginUrl`的值为“tdsess = deleted; expires = Thu, 01-Jan-1970 00:00:01 GMT”的`Set-Cookie`之外，没有其他唯一的标头对可用。

现在，`responseA`从`loginUrl``<form>`元素属性名称已被收集为`username`和`password`，此信息将用于创建`paramsCorrect`和`paramsIncorrect`参数字符串，然后将其发布到`postUrl`：

```py
responseA = pq(response.text)
username = responseA.find('input[id="usr"]').attr('name')
password = responseA.find('input[id="pwd"]').attr('name')

#Welcome : Success paramsCorrect = {username: 'admin', password: '12345'} #Success print(paramsCorrect)
processParams(paramsCorrect)
```

使用提供的`paramsCorrect`参数字符串成功提交表单将导致以下输出：

```py
{'pwd': '12345', 'usr': 'admin'}
Confirm Login : WELCOME :)
```

前面的输出是从`postUrl`的响应中提取的，在这个测试案例中实际上是一个重定向页面，URL 为[`testing-ground.scraping.pro/login?mode=welcome`](http://testing-ground.scraping.pro/login?mode=welcome)：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/1f353c77-6902-4aa9-9a58-ca1eff7a36ec.png)

使用有效的登录凭据成功提交表单

让我们继续使用表单提交，但使用无效的凭据。 `paramsIncorrect`短语包含“密码”的无效值：

```py
 paramsIncorrect = {username: 'admin', password: '123456'} #Access Denied
  print(paramsIncorrect)
 processParams(paramsIncorrect)
```

上述代码将导致以下输出：

```py
{'pwd': '123456', 'usr': 'admin'}
Confirm Login : ACCESS DENIED!
```

前面的输出也可以在`loginUrl`本身找到，这次不会发生重定向：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/e971860f-eeac-4803-849b-e51502af1922.png)

访问被拒绝！（使用错误的凭据处理）

正如您所看到的，用户身份验证和表单提交是相辅相成的。通过使用正确的登录凭据，并能够使用 Python 处理表单提交过程，我们可以获得成功的输出，或者处理从网站返回的相关输出。

在下一节中，我们将通过处理包含会话的 cookie 来执行表单提交和用户身份验证。

# 处理 cookie 和会话

在本节中，我们将处理用户身份验证的表单处理，并为[`quotes.toscrape.com/login`](http://quotes.toscrape.com/login)从[`toscrape.com`](http://toscrape.com)管理 cookie 和会话。

为了登录，您需要使用 CSRF 令牌登录（任何用户名/密码都可以使用）。

让我们设置代码。需要导入`pyquery`和`requests`库，并收集并使用所需的 URL。使用“getCustomHeaders（）”函数，以及`cookieHeader`参数，用于为 URL 请求标头设置 cookie 值。使用“responseCookies（）”函数，以及`response`参数，显示`headers`和`cookies`，并从`cookies`返回`Set-Cookie`值：

```py
from pyquery import PyQuery as pq
import requests
mainUrl = "http://toscrape.com/" loginUrl = "http://quotes.toscrape.com/login"  quoteUrl = "http://quotes.toscrape.com/"   def getCustomHeaders(cookieHeader):
    return {
        'Host': 'quotes.toscrape.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Referer': 'http://quotes.toscrape.com/login',
        'Content-Type': 'application/x-www-form-urlencoded', 
        'Cookie': cookieHeader
    }

def responseCookies(response):
    headers = response.headers
    cookies = response.cookies
    print("Headers: ", headers)
    print("Cookies: ", cookies)
    return headers['Set-Cookie']

if __name__ == '__main__':
```

有关 HTTP 和 HTTP 标头的更多信息，请访问第一章，*网络抓取基础知识*，*了解 Web 开发和技术*和*HTTP*部分。有关 cookie 的更多详细信息，请访问[`www.aboutcookies.org/`](https://www.aboutcookies.org/)或[allaboutcookies.org](http://www.allaboutcookies.org/)。

现在，让我们分别加载`mainUrl`和`loginUrl`：

```py
requests.get(mainUrl)
response = requests.get(loginUrl)

```

以下屏幕截图显示了使用`loginUrl`时登录页面的外观：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/88f29d88-64ba-485a-88da-f87935e8d359.png)

从 http://quotes.toscrape.com/login 登录页面

一旦加载了`loginUrl`，我们可以检查或使用基于浏览器的开发人员工具来查找请求标头，并确认是否存在任何 cookie。我们收到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/28116440-b923-469d-9963-f06bec877377.png)

来自浏览器开发人员工具的网络面板文档标头选项卡

以下代码接受来自`response`的 cookie，并用于标头：

```py
setCookie = responseCookies(response)
print("Set-Cookie: ",setCookie)
```

正如我们从前面的屏幕截图中看到的，请求标头包含以“sessio = ....”开头的值为“Cookie”的`key`，也称为会话 ID。此信息在`response.headers`和`response.cookies`中找到，并且`responseCookies（）`函数在打印详细信息之前从`response.headers`返回 cookie 值：

```py
Headers: {'Set-Cookie': session=eyJjc3JmX3Rva2VuIjoicUlPVGNnQ2FKZmJaS3NOdmlIREFWbVdvWGtMakJkVXl1U3BScmVZTWhRd0d6dEZueFBsRSJ9.D68Log.3ANox76h0whpTRjkqNo7JRgCtWI; HttpOnly; Path=/',...,'Content-Encoding':'gzip','Content-Type':'text/html; charset=utf-8',......}

Cookies: <RequestsCookieJar[<Cookie session=eyJjc3JmX3Rva2VuIjoicUlPVGNnQ2FKZmJaS3NOdmlIREFWbVdvWGtMakJkVXl1U3BScmVZTWhRd0d6dEZueFBsRSJ9.D68Log.3ANox76h0whpTRjkqNo7JRgCtWI for quotes.toscrape.com/>]>

Set-Cookie: session=eyJjc3JmX3Rva2VuIjoicUlPVGNnQ2FKZmJaS3NOdmlIREFWbVdvWGtMakJkVXl1U3BScmVZTWhRd0d6dEZueFBsRSJ9.D68Log.3ANox76h0whpTRjkqNo7JRgCtWI; HttpOnly; Path=/
```

`requests.post()`短语使用 HTTP `POST`请求到`loginURL`，并使用已设置的`params`和`customHeaders`。`customHeaders`是使用我们之前收到的`setCookie`值创建的：

现在我们已经收到了基于 cookie 的会话值，我们需要维护这个值，以便进行成功的登录过程。

Cookies: [`www.aboutcookies.org/`](https://www.aboutcookies.org/) , [`www.allaboutcookies.org/`](http://www.allaboutcookies.org/)

在下一章中，我们将使用 Python 编程语言与 Web API 进行数据提取交互。

浏览器开发者工具中的元素面板与页面源

以下截图显示了成功的身份验证和验证信息：

在用户和网站之间保持安全措施是一项具有挑战性和危险性的任务。存在不同的安全问题需要加以管理。网络上存在各种新概念，需要有效合法地处理，以便进行网络抓取活动。

浏览器开发者工具：[`developers.google.com/web/tools/chrome-devtools/`](https://developers.google.com/web/tools/chrome-devtools/), [`developer.mozilla.org/son/docs/Tools`](https://developer.mozilla.org/son/docs/Tools)

```py
responseA = pq(response.text)
csrf_token = responseA.find('input[name="csrf_token"]').attr('value')
username = responseA.find('input[id="username"]').attr('name')
password = responseA.find('input[id="password"]').attr('name')

params = {username: 'test', password: 'test', 'csrf_token': csrf_token}
print(params)
```

让我们收集基于`<form>`的字段以及有关表单提交的更多信息：

```py
{'password':'test','username':'test','csrf_token':'jJgAHDQykMBnCFsPIZOoqdbflYRzXtSuiEmwKeGavVWxpNLUhrcT'}
```

通过`<form>`元素的`name`属性作为键和默认值构建要通过表单操作提交的参数，并分别需要接收值作为它们的值。

进一步阅读

```py
customHeaders = getCustomHeaders(setCookie)
response = requests.post(loginUrl, data=params, headers=customHeaders)
setCookie = responseCookies(response)
#print("Set-Cookie: ",setCookie)

responseB = pq(response.text)
logoutText = responseB.find('a[href*="logout"]').text()
logoutLink = responseB.find('a[href*="logout"]').attr('href')

print("Current Page : ",response.url)
print("Confirm Login : ", responseB.find('.row h2').text())
print("Logout Info : ", logoutText," & ",logoutLink)
```

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/4f8f7602-a524-4357-9a0a-79149630efe1.png)

```py
Current Page : http://quotes.toscrape.com/
Confirm Login : Top Ten tags
Logout Info : Logout & /logout
```

最后，我们收到了成功的输出，以及重定向的 URL 和有关注销的信息：

在这个例子中，`username`和`password`是开放的字符串值，`test`已经被用于两者：

没有`key`命名为`Cookie`的空`customHeaders`或`customHeaders`将无法成功进行身份验证。同样，`csrf_token`也是必需的参数。即使提供了所需的`key:value`信息对，发布的、更新的或空的`csrf_token`也将无法成功进行身份验证。

# 总结

在本章中，我们探讨了一些与安全问题相关的基本措施和技术，这些问题经常出现，对于网络抓取来说是具有挑战性的。

AJAX: [`api.jquery.com/jquery.ajax/`](http://api.jquery.com/jquery.ajax/), [`www.w3schools.com/js/js_ajax_intro.asp`](https://www.w3schools.com/js/js_ajax_intro.asp)

**跨站请求伪造**（**CSRF**）或会话劫持是一种安全措施，用于识别用户和网站之间的每个单独请求。通常，`CSRF_TOKEN`或令牌用于管理这样的机制。当用户向网站发出请求时，网站会生成一个随机字符串的令牌。处理网站的任何形式的 HTTP 请求都需要令牌值。每个成功请求的令牌值都会发生变化。包含令牌值的 HTML `<form>`可以使用已更新或已删除的令牌进行处理，但网站不会接受这些令牌。

# 从[`quotes.toscrape.com/`](http://quotes.toscrape.com/)验证的成功身份验证信息

+   会话 ID 是网站服务器为特定用户分配的唯一编号，持续一段时间或一次会话。这个 ID 可以存储在特定的`<form>`字段或 cookies 中，甚至可以附加到 URL 查询字符串中。

+   收集具有现有值和名称的表单字段，并配置`params`，得到以下输出：

+   正如我们从前面的截图中可以看到的，`<form>`正在使用 HTTP `POST`将表单字段提交到`loginUrl`，还有一个隐藏的`<input>`字段带有`csrf_token`，以及接受登录凭据的字段。

+   CSRF: [`www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)`](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))

+   HTML forms: [`www.w3schools.com/html/html_forms.asp`](https://www.w3schools.com/html/html_forms.asp), [`developer.mozilla.org/en-US/docs/Learn/HTML/Forms`](https://developer.mozilla.org/en-US/docs/Learn/HTML/Forms)

+   HTTP: [`www.w3.org/Protocols/`](https://www.w3.org/Protocols/)

+   HTTP headers: [`jkorpela.fi/http.html`](http://jkorpela.fi/http.html)

+   HTTP session: [`developer.mozilla.org/en-US/docs/Web/HTTP/Session`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Session)

+   Web scraping sandbox: [`toscrape.com/`](http://toscrape.com/)

+   Web scraper testing ground: [`testing-ground.scraping.pro/`](http://testing-ground.scraping.pro/)


# 第七章：使用基于 Web 的 API 进行数据提取

基于 Web 的 API 允许用户与网络上的信息进行交互。API 直接处理格式化模式易于使用和维护的数据。有些 API 在向用户提供数据之前还需要用户身份验证。本章将介绍使用 Python 和一些 Web API 与可用 API 进行交互和提取数据。通常，API 以可交换的文档格式（如 JSON、CSV 和 XML）提供数据。

在本章中，我们将涵盖以下主题：

+   Web API 简介

+   使用 Python 编程语言访问 Web API

+   通过 Web API 处理和提取数据

# 技术要求

本章需要使用 Web 浏览器（Google Chrome 或 Mozilla Firefox）。我们将使用以下 Python 库：

+   `requests`

+   `json`

+   `collections`

如果这些库在您当前的 Python 设置中不存在，请参考第二章，*Python 和 Web-使用 urllib 和 Requests*，在*设置事项*部分了解如何下载它们。

本章的代码文件可在本书的 GitHub 存储库中找到：[`github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python/tree/master/Chapter07`](https://github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python/tree/master/Chapter07)。

# Web API 简介

**基于 Web 的应用程序编程信息**或**基于 Web 的 API**是网站提供的接口，用于返回接收到的请求的信息。Web API（或 API）实际上是网站为用户或第三方 Web 应用程序或自动化脚本提供的 Web 服务，以便共享和交换信息。

通常，这是通过 Web 浏览器处理的**用户界面**（UI），用于从已向网站或 Web 服务器发出的请求中检索特定信息。具有任何类型大量信息的网站可以为其用户提供 Web API，以便进行信息共享。

在软件应用领域，API 以其一组设施（如方法和库）而闻名，可用于进一步增强、构建或开发应用程序。这也被称为开发者 API。

Web API 不依赖于任何编程语言。它们使得以原始格式轻松访问基于 Web 的信息，并通常以 JSON、XML 或 CSV 格式返回结构化响应。

它们遵循 HTTP 原则（请求和响应循环），但只接受预定义格式的请求和参数集以生成响应。在安全方面，许多 API 还提供身份验证工具，如 API 密钥，这是向网站发出请求所必需的。

# REST 和 SOAP

API 是由基于软件架构或原则的 Web 服务器提供的服务。**简单对象访问协议**（**SOAP**）和**表述状态转移**（**REST**）是访问 Web 服务的方法。虽然 REST 是一种架构，但 SOAP 是基于 Web 标准的协议。我们将在接下来的部分中处理 REST API。

# REST

REST（[`www.ics.uci.edu/~fielding/pubs/dissertation/rest_arch_style.htm`](https://www.ics.uci.edu/~fielding/pubs/dissertation/rest_arch_style.htm)）是一种基于一组定义和解决网络原则的软件架构风格。REST 是一种软件架构，而不是一组标准。REST 使用标准的 HTTP 协议和方法，如`GET`、`POST`、`PUT`和`DELETE`来提供服务。它是无状态的、多层的，也支持缓存。

Web API 通常被归类为 RESTful Web 服务；它们为用户和其他资源提供通信接口。RESTful Web 服务（REST API 或 Web API）（[`restfulapi.net/`](https://restfulapi.net/)）是 Web 提供的适应 REST 架构的服务。

通过 REST 提供的服务无需适应新的标准、开发或框架。大多数情况下，它将使用 GET 请求，以及已发出到 API 的查询字符串，搜索其响应。通常会跟踪 HTTP 状态码（[`restfulapi.net/http-status-codes/`](https://restfulapi.net/http-status-codes/)）（404、200、304）以确定 API 的响应。响应也可以以 JSON、XML 和 CSV 等各种格式获取。

在选择 REST 和 SOAP 之间，REST 在处理方面比 SOAP 更容易和高效，并且被许多网站提供给公众。

# SOAP

SOAP（[`www.w3.org/TR/soap/is`](https://www.w3.org/TR/soap/is)）是由 W3C 指定的一组标准，也是 Web 服务中与 REST 相对应的选择。SOAP 使用 HTTP 和 SMTP（简单邮件传输协议），用于在互联网上交换文档，以及通过远程过程。

SOAP 使用 XML 作为消息服务，也被称为基于 XML 的协议。SOAP 请求包含描述发送到服务器的方法和参数的 XML 文档（带有信封和正文）。服务器将执行接收到的方法，以及参数，并将 SOAP 响应发送回发起请求的程序。

SOAP 具有高度的可扩展性，并包括内置的错误处理。它还与其他协议（如 SMTP）一起工作。SOAP 也独立于平台和编程语言，并且主要在分布式企业环境中实现。

# Web API 的好处

信息需求与其在网络上的可用性一天比一天增长。信息来源、其可用性、设施和共享和交换技术已成为全球需求。API 是首选的数据来源之一，可用于检索数据。

API 不仅是通过 Web 浏览器与用户进行通信的一种方式-您还可以使用系统。API 允许系统和设备之间的通信，例如移动设备，尽管它们的基础系统或编程语言不同。许多移动应用程序会向某些 API 发出请求，并显示从响应中检索到的相关信息。API 不仅是用于检索数据的简单服务；它们用于交换和处理信息，甚至在不同平台和服务之间进行系统间通信。

从网络抓取的角度来看，通过 API 可用的响应或数据优于使用抓取脚本检索的数据。这是由于以下原因：

+   API 返回的数据完全特定于正在执行的请求，以及已应用于它的过滤器或参数。

+   使用 Python 库（如 BeautifulSoup、pyquery 和 lxml）解析 HTML 或 XML 并不总是必需的。

+   数据的格式是结构化的，易于处理。

+   数据清理和处理最终列表将更容易或可能不需要。

+   与编码、分析网页并应用 XPath 和 CSS 选择器来检索数据相比，处理时间会显著减少。

+   它们易于处理。

在完全从抓取的角度转向 Web API 之前，还有一些因素需要考虑，包括以下内容：

+   并非所有网站都向用户提供访问 Web API 的权限。

+   API 的响应是特定于预定义参数集的。这可能限制基于需求可以进行的确切请求，并限制立即获取的数据的可用性。

+   返回的响应受限于一定的数量，例如每个请求返回的记录数以及允许的最大请求数量。

+   尽管数据将以结构化格式可用，但它可能分布在键值对中，这可能需要一些额外的合并任务。

鉴于这些观点，我们可以看到 web API 是从网站获取信息的首选选择。

# 访问 web API 和数据格式

在本节中，我们将探讨在 web 上可用的各种 API，向它们发送请求并接收响应，然后解释它们如何通过 Python 编程语言工作。

让我们考虑以下示例 URL，`https://www.someexampledomain.com`。它提供的 API 带有参数，定位器和身份验证。通过使用这些，我们可以访问以下资源：

+   `https://api.someexampledomain.com `

+   `https://api.someexampledomain.com/resource?key1=value1&key2=value2`

+   `https://api.someexampledomain.com/resource?api_key=ACCESS_KEY&key1=value1&key2=value2`

+   `https://api.someexampledomain.com/resource/v1/2019/01`

参数或键值对的集合实际上是由 web 提供的预定义变量集。通常，API 提供有关其用法、HTTP 方法、可用键和类型或允许键接收的值的基本指南或文档，以及有关 API 支持的功能的其他信息，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/79440f5c-2a15-4d38-9fdd-7b7ccef19261.png)

来自 https://sunrise-sunset.org/api 的 API 详细信息和链接

最终用户和系统只能使用提供者允许的 API 功能和功能。

以下是一些实际 API 链接和示例调用，显示了 URL 中使用的格式和参数：

+   [`api.walmartlabs.com/v1/reviews/33093101?apiKey={apiKey}&lsPublisherId={Your LinkShare Publisher Id}&format=json`](https://developer.walmartlabs.com/docs/read/Reviews_Api)

+   [`api.nasa.gov/neo/rest/v1/feed?start_date=START_DATE&end_date=END_DATE&api_key=API_KEY`](https://api.nasa.gov/api.html#NeoWS)

+   [`api.sunrise-sunset.org/json?lat=36.7201600&lng=-4.4203400&date=today`](https://api.sunrise-sunset.org/json?lat=36.7201600&lng=-4.4203400&date=today)

+   [`api.twitter.com/1.1/search/tweets.json?q=nasa&result_type=popular`](https://developer.twitter.com/en/docs/tweets/search/api-reference/get-search-tweets)

+   [`api.geonames.org/postalCodeSearchJSON?postalcode=9011&maxRows=10&username=demo`](http://api.geonames.org/postalCodeSearchJSON?postalcode=9011&maxRows=10&username=demo)

+   [`api.geonames.org/postalCodeSearch?postalcode=9011&maxRows=10&username=demo`](http://api.geonames.org/postalCodeSearch?postalcode=9011&maxRows=10&username=demo)

+   [`api.nytimes.com/svc/mostpopular/v2/viewed/1.json?api-key=yourkey`](https://api.nytimes.com/svc/mostpopular/v2/viewed/1.json?api-key=yourkey)

+   [`maps.googleapis.com/maps/api/staticmap?center=Brooklyn+Bridge,New+York,NY&zoom=13&size=600x300&maptype=roadmap markers=color:blue%7Clabel:S%7C40.702147,-74.015794&markers=color:green%7Clabel:G%7C40.711614,-74.012318&markers=color:red%7Clabel:C%7C40.718217,-73.998284&key=YOUR_API_KEY`](https://developers.google.com/maps/documentation/maps-static/intro#quick_example)

参数，如`key`，`api_key`，`apiKey`和`api-key`，是为了安全和跟踪措施而需要的，并且在处理任何 API 请求之前需要获得。

本节中的 API 链接和示例调用与它们所列出的资源相关联。例如，[`api.twitter.com/1.1/search/tweets.json?q=nasa&result_type=popular`](https://api.twitter.com/1.1/search/tweets.json?q=nasa&result_type=popular)在[`developer.twitter.com/en/docs/tweets/search/api-reference/get-search-tweets`](https://developer.twitter.com/en/docs/tweets/search/api-reference/get-search-tweets)上列出。

# 使用 web 浏览器向 web API 发出请求

获取通过查询字符串应用的参数信息和获取 API 密钥（如果需要）是获得 API 访问权限的初步步骤。与由 Google、Twitter 和 Facebook 提供的开发者 API 相比，大多数公共或免费 API 都非常简单易懂。

API 请求可以通过 Web 浏览器进行。但是，在这一部分，我们将尝试展示访问 API 时可能遇到的一些常见情况，同时展示 RESTful API 的一些重要属性。

# 案例 1 - 访问简单的 API（请求和响应）

在这一部分，我们将使用以下 URL：[`api.sunrise-sunset.org/json?lat=27.717245&lng=85.323959&date=2019-03-04`](https://api.sunrise-sunset.org/json?lat=27.717245&lng=85.323959&date=2019-03-04)。

让我们通过一个简单的 API 处理一个请求，以获取尼泊尔加德满都的日出和日落时间（以 UTC 时间为准）。查询字符串需要为所选位置的`lat`（纬度）、`lng`（经度）和`date`提供值。如下面的截图所示，我们获得的响应是以 JSON 格式（使用浏览器扩展格式化）返回的，通过使用基于浏览器的开发者工具验证了成功的请求方法和 HTTP 状态码（`200`，即`OK`或`成功`）：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/54ee6161-e2db-4047-a9e0-a6278f6a6825.png)

来自[`api.sunrise-sunset.org/json?lat=27.717245&lng=85.323959&date=2019-03-04`](https://api.sunrise-sunset.org/json?lat=27.717245&lng=85.323959&date=2019-03-04)的响应状态码

响应以原始格式或 JSON 格式返回，如下面的代码所示。当正常获取 JSON 响应时，可以使用 Python 的`json`库进行处理。在下面的代码中，API 请求已经使用`requests`库进行处理。`requests`提供了处理 HTTP 的各种功能；例如，可以使用`status_code`获取 HTTP 状态码。可以使用`headers`获取头信息。在这里，我们对`status_code`和`headers`特别感兴趣，特别是`Content-Type`，以便我们可以计划进一步处理和可能需要使用的库：

```py
import requests
url = 'https://api.sunrise-sunset.org/json?lat=27.7172&lng=85.3239&date=2019-03-04'   results = requests.get(url) #request url
print("Status Code: ", results.status_code)
print("Headers-ContentType: ", results.headers['Content-Type'])
print("Headers: ", results.headers)

jsonResult = results.json() #read JSON content
print("Type JSON Results",type(jsonResult))
print(jsonResult)
print("SunRise & Sunset: ",jsonResult['results']['sunrise']," & ",jsonResult['results']['sunset'])
```

如我们所见，`status_code`是`200`（即`OK`），`Content-Type`是 JSON 类型。这给了我们确认，我们可以使用与 JSON 相关的库继续前进。但是，在这种情况下，我们使用了`requests`库中的`json()`函数，这减少了我们对额外库的依赖，并将响应对象转换为`dict`对象。通过收到的`dict`，我们可以使用`key:value`对访问所需的元素：

```py
Type Results <class 'requests.models.Response'>
Status Code: 200
Headers-ContentType: application/json

Headers: {'Access-Control-Allow-Origin':'*','Content-Type':'application/json','Vary':'Accept-Encoding', 'Server':'nginx','Connection':'keep-alive','Content-Encoding':'gzip','Transfer-Encoding':'chunked','Date': 'Mon, 04 Mar 2019 07:48:29 GMT'}

Type JSON Results <class 'dict'>

{'status':'OK','results':{'civil_twilight_end':'12:44:16 PM','astronomical_twilight_end':'1:38:31 PM', 'civil_twilight_begin':'12:16:32 AM','sunrise':'12:39:54 AM',......,'sunset':'12:20:54 PM','solar_noon': '6:30:24 AM','day_length':'11:41:00'}}

SunRise & Sunset: 12:39:54 AM & 12:20:54 PM** 
```

# 案例 2 - 展示 API 的状态码和信息响应

在这一部分，我们将使用以下 URL：[`api.twitter.com/1.1/search/tweets.json?q=`](https://api.twitter.com/1.1/search/tweets.json?q=)。

在这一部分，我们将处理来自 Twitter 的 API 请求。要请求的 URL 是[`api.twitter.com/1.1/search/tweets.json?q=`](https://api.twitter.com/1.1/search/tweets.json?q=)。通过使用这个 URL，我们可以很容易地确定查询字符串`q`是空的，Twitter API 期望的值没有提供。完整的 URL 应该是类似于[`api.twitter.com/1.1/search/tweets.json?q=nasa&result_type=popular`](https://api.twitter.com/1.1/search/tweets.json?q=nasa&result_type=popular)。

返回的响应是不完整的 API 调用，如下面的截图所示，还有 HTTP 状态码（`400`或`Bad Request`）以及 API 返回的消息，指出了“message”：“Bad Authentication data”的错误。有关 Twitter API 的搜索选项的更多信息，请参阅[`developer.twitter.com/en/docs/tweets/search/api-reference/get-search-tweets`](https://developer.twitter.com/en/docs/tweets/search/api-reference/get-search-tweets)：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/f65a7397-c1e0-49bb-8491-7f0fa1d67053.png)

向 Twitter API 发出的不完整请求

Twitter API 返回的响应实际上是信息，而不是错误。这种信息性的响应使 API 在被其他资源使用时更具可伸缩性和易于调试。这也是 RESTful web 服务的一个受欢迎的特性。这种信息可以通过部署 API 参数和其他要求轻松地克服。

以下代码将使用空查询字符串向 Twitter 发出请求并识别响应：

```py
import requests
import json
url = 'https://api.twitter.com/1.1/search/tweets.json?q='  
results = requests.get(url)
print("Status Code: ", results.status_code)
print("Headers: Content-Type: ", results.headers['Content-Type'])

jsonResult = results.content    #jsonResult = results.json() print(jsonResult)

jsonFinal = json.loads(jsonResult.decode())
print(jsonFinal) #print(json.loads(requests.get(url).content.decode()))   if results.status_code==400:
 print(jsonFinal['errors'][0]['message'])
else:
 pass
```

前面的代码使用`json` Python 库加载了使用`loads()`函数获得的解码`jsonResult`。我们也可以像在案例 1 中那样使用`requests`中的`json()`。`jsonFinal`现在是一个 Python 字典对象，可以被探索，以便我们可以找到它的`'key:value'`。最终输出如下：

```py
Status Code: 400
Headers: Content-Type: application/json; charset=utf-8

b'{"errors":[{"code":215,"message":"Bad Authentication data."}]}'
{'errors': [{'message': 'Bad Authentication data.', 'code': 215}]}

Bad Authentication data.
```

# 案例 3 - 展示 RESTful API 缓存功能

在本节中，我们将使用以下 URL：[`api.github.com/`](https://api.github.com/)。

GitHUb（[`github.com/`](https://github.com/)）是开发人员及其代码存储库的地方。GitHub API 在开发人员中非常有名，他们都来自不同的编程背景。正如我们在下面的截图中所看到的，响应是以 JSON 格式获得的。由于返回的 HTTP 状态码是`200`，即`OK`或`成功`，因此请求是成功的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/0d2c1add-f32e-4612-85cb-40bced919ec5.png)

来自 https://api.github.com 的响应，HTTP 状态码为 200

如您所见，我们对[`api.github.com`](https://api.github.com)进行了基本调用。返回的内容包含 API 的链接，以及一些参数供特定调用使用，例如`{/gist_id}`，`{/target}`和`{query}`。

让我们再次向 API 发送请求，但这次参数值没有任何更改或更新。我们将收到的内容与之前的响应类似，但 HTTP`状态码`将有所不同；也就是说，与 200`OK`相比，我们将获得`304 未修改`：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/0d428fad-bd13-4bcf-8561-05a4dd29ed89.png)

https://api.github.com 的 HTTP 状态码 304

这个 HTTP 状态码（`304`或`未修改`）展示了 REST 的缓存功能。由于响应没有任何更新或更新的内容，客户端缓存功能开始发挥作用。这有助于处理时间，以及带宽时间和使用。缓存是 RESTful web 服务的重要属性之一。以下是 Python 代码，显示了 RESTful API 的缓存属性，通过传递外部标头，这些标头被提供给`headers`参数，同时使用`requests.get()`发出请求获得：

```py
import requests
url = 'https://api.github.com'  #First Request results = requests.get(url)
print("Status Code: ", results.status_code)
print("Headers: ", results.headers)

#Second Request with 'headers'
etag = results.headers['ETag']
print("ETag: ",etag)

results = requests.get(url, headers={'If-None-Match': etag})
print("Status Code: ", results.status_code)
```

`requests`在代码中两次调用`url`。我们还可以看到第二个请求已经提供了`etag`作为头信息，即`If-None-Match`。这个特定的头部检查使用`ETag`键作为 HTTP 响应头获得的响应头。`ETag`用于跟踪目的，通常标识存在的资源。这展示了缓存能力。有关`ETag`的更多信息，请参阅[`developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag)。

`ETag`是从`results.headers`中收集的，并且随着获得 HTTP`状态码：304`的第二个请求一起转发。以下代码显示了输出：

```py
Status Code: 200
Headers: Content-Type: application/json; charset=utf-8
Headers: {'X-GitHub-Request-Id': 'A195:073C:37F223:79CCB0:5C8144B4', 'Status': '200 OK','ETag': 'W/"7dc470913f1fe9bb6c7355b50a0737bc"', 'Content-Encoding': 'gzip','Date': 'Thu, 07 Mar 2019 16:20:05 GMT',........, 'Content-Type': 'application/json; charset=utf-8', ....., 'Server': 'GitHub.com'}

ETag: W/"7dc470913f1fe9bb6c7355b50a0737bc"
Status Code: 304
```

在本节中，我们已经学习了各种 API，通过使用功能访问它们，并演示了与网页抓取方法相关的一些重要概念。在下一节中，我们将使用 API 来抓取数据。

# 使用 API 进行网页抓取

在这一部分，我们将请求 API 并通过它们收集所需的数据。从技术上讲，通过 API 获取的数据并不类似于进行爬取活动，因为我们不能仅从 API 中提取所需的数据并进一步处理它。

# 示例 1 - 搜索和收集大学名称和 URL

在这个例子中，我们将使用 HIPO 提供的 API（[`hipolabs.com/`](https://hipolabs.com/)）来搜索大学：[`universities.hipolabs.com/search?name=Wales`](http://universities.hipolabs.com/search?name=Wales)。

这个 API 使用一个名为`name`的查询参数，它将寻找大学名称。我们还将提供一个额外的参数`country`，其中包括美国和英国等国家名称。可以从以下 URL 请求此 API，更多信息可以在[`github.com/hipo/university-domains-list`](https://github.com/hipo/university-domains-list)找到：

+   [`universities.hipolabs.com`](http://universities.hipolabs.com)

+   [`universities.hipolabs.com/search?name=Wales`](http://universities.hipolabs.com/search?name=Wales)

+   [`universities.hipolabs.com/search?name=Medicine&country=United Kingdom`](http://universities.hipolabs.com/search?name=Medicine&country=United%20Kingdom)

让我们导入所需的库并使用`readUrl()`函数来请求 API 并返回 JSON 响应，如下面的代码所示：

```py
import requests
import json
dataSet = []
 def readUrl(search):
    results = requests.get(url+search)
    print("Status Code: ", results.status_code)
    print("Headers: Content-Type: ", results.headers['Content-Type'])
  return results.json()
```

通过返回的 JSON 响应，可以使用我们找到的键和索引检索所需的值，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/3d7a222c-075d-4d78-9049-aa13a01f34cc.png)

从 API 中获取的 JSON（格式化）

`name`和`url`被遍历并附加到`dataSet`中：

```py
url = 'http://universities.hipolabs.com/search?name=' jsonResult = readUrl('Wales') # print(jsonResult)  for university in jsonResult:
    name = university['name']
    url = university['web_pages'][0]
    dataSet.append([name,url])
 print("Total Universities Found: ",len(dataSet))
print(dataSet)
```

最终输出如下：

```py
Status Code: 200 Headers: Content-Type: application/json Total Universities Found: 10 [['University of Wales', 'http://www.wales.ac.uk/'], ['University of Wales Institute, Cardiff', 'http://www.uwic.ac.uk/'], ......., ['University of Wales, Lampeter', 'http://www.lamp.ac.uk/'], ['University of Wales, Bangor', 'http://www.bangor.ac.uk/']]  
```

# 示例 2 - 从 GitHub 事件中获取信息

在这个例子中，我们将收集关于`type`（事件类型）、`created_at`（事件创建日期）、`id`（事件标识代码）和`repo`（存储库名称）的信息。我们将使用以下 URL：[`api.github.com/events`](https://api.github.com/events)。

GitHub“事件”列出了过去 90 天内执行的公共活动。这些事件以页面形式提供，每页 30 个项目，最多显示 300 个。事件中存在各种部分，所有这些部分都揭示了关于`actor`、`repo`、`org`、`created_at`、`type`等的描述。

有关更多详细信息，请参阅以下链接：[`developer.github.com/v3/activity/events/`](https://developer.github.com/v3/activity/events/)。

以下是我们将要使用的代码：

```py
if __name__ == "__main__":
    eventTypes=[] 
    #IssueCommentEvent,WatchEvent,PullRequestReviewCommentEvent,CreateEvent
  for page in range(1, 4): #First 3 pages
        events = readUrl('events?page=' + str(page))
  for event in events:
            id = event['id']
            type = event['type']
            actor = event['actor']['display_login']
            repoUrl = event['repo']['url']
            createdAt = event['created_at']
            eventTypes.append(type)
            dataSet.append([id, type, createdAt, repoUrl, actor])

    eventInfo = dict(Counter(eventTypes))

    print("Individual Event Counts:", eventInfo)
    print("CreateEvent Counts:", eventInfo['CreateEvent'])
    print("DeleteEvent Counts:", eventInfo['DeleteEvent'])

print("Total Events Found: ", len(dataSet))
print(dataSet)
```

上述代码给出了以下输出：

```py
Status Code: 200
Headers: Content-Type: application/json; charset=utf-8
................
Status Code: 200
Headers: Content-Type: application/json; charset=utf-8

Individual Event Counts: {'IssueCommentEvent': 8, 'PushEvent': 42, 'CreateEvent': 12, 'WatchEvent': 9, 'PullRequestEvent': 10, 'IssuesEvent': 2, 'DeleteEvent': 2, 'PublicEvent': 2, 'MemberEvent': 2, 'PullRequestReviewCommentEvent': 1}

CreateEvent Counts: 12
DeleteEvent Counts: 2
Total Events Found: 90

[['9206862975','PushEvent','2019-03-08T14:53:46Z','https://api.github.com/repos/CornerYoung/MDN','CornerYoung'],'https://api.github.com/repos/OUP/INTEGRATION-ANSIBLE','peter-masters'],.....................,'2019-03-08T14:53:47Z','https://api.github.com/repos/learn-co-curriculum/hs-zhw-shoes-layout','maxwellbenton']]
```

`collections` Python 模块中的`Counter`类用于获取`eventTypes`中元素的个体计数：

```py
from collections import Counter
```

# 总结

API 提供了几个好处，我们在本章中都已经涵盖了。RESTful Web 服务的需求正在增长，并且将来会比以往更多地促进数据请求和响应。结构化、易访问、基于参数的过滤器使 API 更方便使用，并且在节省时间方面表现出色。

在下一章中，我们将学习 Selenium 以及如何使用它从网络上爬取数据。

# 进一步阅读

+   Fielding, Roy Thomas. *Architectural Styles and the Design of Network-based Software Architectures*. Doctoral dissertation, University of California, Irvine, 2000

+   REST：[`www.ics.uci.edu/~fielding/pubs/dissertation/rest_arch_style.htm`](https://www.ics.uci.edu/~fielding/pubs/dissertation/rest_arch_style.htm)

+   SOAP：[`www.w3.org/TR/soap/`](https://www.w3.org/TR/soap/)

+   一个简单的 SOAP 客户端：[`www.ibm.com/developerworks/xml/library/x-soapcl/index.html`](https://www.ibm.com/developerworks/xml/library/x-soapcl/index.html)

+   RESTful API HTTP 状态码：[`restfulapi.net/http-status-codes/`](https://restfulapi.net/http-status-codes/)

+   304 未修改：是什么以及如何修复它：[`airbrake.io/blog/http-errors/304-not-modified`](https://airbrake.io/blog/http-errors/304-not-modified)

+   ETag：[`developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag)

+   数字数据类型：[`www.stat.berkeley.edu/~spector/extension/python/notes/node22.html`](https://www.stat.berkeley.edu/~spector/extension/python/notes/node22.html)


# 第八章：使用 Selenium 进行 Web 抓取

到目前为止，我们已经学习了如何使用多种数据查找技术，并通过实现各种 Python 库来访问 Web 内容进行 Web 抓取。

Selenium 是一个 Web 应用程序测试框架，它自动化浏览操作，并可用于简单和复杂的 Web 抓取活动。 Selenium 提供了一个 Web 浏览器作为接口或自动化工具。使用 JavaScript、cookies、脚本等的动态或安全 Web 内容可以通过 Selenium 的帮助加载、测试，甚至抓取。

关于 Selenium 框架有很多东西要学习。在本章中，我们将介绍与 Web 抓取相关的框架的主要概念。

本章将涵盖以下主题：

+   Selenium 简介

+   使用 Selenium 进行 Web 抓取

# 技术要求

本章需要一个 Web 浏览器（Google Chrome 或 Mozilla Firefox），我们将使用以下 Python 库：

+   `selenium`（Python 库）

+   `re`

如果您当前的 Python 设置中没有这些库，则可以通过参考第二章中的*设置事物*部分来设置或安装它们。

除了提到的 Python 库和 Web 浏览器之外，我们还将使用 WebDriver for Google Chrome。

代码文件可在[`github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python/tree/master/Chapter08`](https://github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python/tree/master/Chapter08)上找到。

# Selenium 简介

正如我所提到的，Selenium 是一个可以用于 Web 抓取活动的 Web 应用程序框架。它也可以用作浏览器自动化工具。

与 Web 应用程序相关的任务或活动的自动化，例如以下列表中的任务，涉及在没有人类直接参与的情况下执行这些任务：

+   浏览

+   点击链接

+   保存屏幕截图

+   下载图像

+   填写 HTML `<form>` 模板和许多其他活动

Selenium 提供了一个 Web 浏览器作为接口或自动化工具。通过浏览操作的自动化，Selenium 也可以用于 Web 抓取。使用 JavaScript、cookies、脚本等的动态或安全 Web 服务可以通过 Selenium 的帮助加载、测试，甚至爬取和抓取。

Selenium 是开源的，可以跨多个平台访问。可以使用各种 Web 浏览器进行测试，这些浏览器使用可用于编程语言（如 Java 和 Python）的库。使用库创建脚本与 Selenium 交互以执行基于浏览器的自动化。

尽管在应用程序测试中使用 Selenium 在爬行和抓取等操作方面具有许多优势，但它也有其缺点，例如时间和内存消耗。 Selenium 是可扩展和有效的，但在执行其操作时速度较慢，并且消耗大量内存空间。

有关 Selenium 的更详细信息，请访问[`www.seleniumhq.org/`](https://www.seleniumhq.org/)。

在接下来的部分中，我们将设置 Selenium WebDriver 并使用 Python 库进行设置，该库可以在[`selenium-python.readthedocs.io/`](https://selenium-python.readthedocs.io/)找到。

Selenium 是一个 Web 测试框架，而 Selenium ([`pypi.org/project/selenium/`](https://pypi.org/project/selenium/))是一个绑定 Selenium WebDriver 或用于创建与 Selenium 交互的脚本的 Python 库。

应用程序测试是为了确保应用程序满足要求，并检测错误和错误以确保产品质量而进行的。它可以通过手动（借助用户的帮助）或使用自动化工具（如 Selenium）进行。在互联网上发布应用程序之前，会对基于 Web 的应用程序进行测试。

# Selenium 项目

Selenium 由多个组件或工具组成，也被称为 Selenium 项目，使其成为一个完整的基于 web 的应用程序测试框架。我们现在将看一些这些 Selenium 项目的主要组件。

# Selenium WebDriver

Selenium WebDriver 是 Selenium 的一个组件，用于自动化浏览器。通过提供各种语言绑定，如 Java、Python、JavaScript 等，使用第三方驱动程序，如 Google Chrome 驱动程序、Mozilla Gecko 驱动程序和 Opera（[`github.com/mozilla/geckodriver/`](https://github.com/mozilla/geckodriver/)）来提供命令来进行浏览器自动化。Selenium WebDriver 不依赖于任何其他软件或服务器。

WebDriver 是一个面向对象的 API，具有更新的功能，克服并解决了之前 Selenium 版本和 Selenium **Remote Control** (**RC**) 的限制。请访问 Selenium WebDriver 网页（[`www.seleniumhq.org/projects/webdriver/`](https://www.seleniumhq.org/projects/webdriver/)）获取更多信息。

# Selenium RC

Selenium RC 是一个用 Java 编程的服务器。它使用 HTTP 接受浏览器的命令，用于测试复杂的基于 AJAX 的 web 应用程序。

Selenium RC 在发布 Selenium 2（Selenium 版本 2）后已正式弃用。然而，WebDriver 包含了 Selenium RC 的主要功能。请访问[`www.seleniumhq.org/projects/remote-control/`](https://www.seleniumhq.org/projects/remote-control/) 获取更多信息。

# Selenium Grid

Selenium Grid 也是一个服务器，允许测试在多台机器上并行运行，跨多个浏览器和操作系统，分发系统负载并减少性能问题，如时间消耗。

复杂的测试用于同时处理 Selenium RC 和 Selenium Grid。自 2.0 版本发布以来，Selenium 服务器现在内置支持 WebDriver、Selenium RC 和 Selenium Grid。请访问 Selenium Grid 网页（[`www.seleniumhq.org/projects/grid/`](https://www.seleniumhq.org/projects/grid/)）获取更多信息。

# Selenium IDE

一个开源的 Selenium **集成开发环境** (**IDE**) 用于使用 Selenium 构建测试用例。它基本上是一个网页浏览器扩展，具有诸如记录和通过**图形用户** **界面** (**GUI**) 回放网页自动化等功能。

以下是 Selenium IDE 的一些关键特性：

+   可扩展且易于调试

+   韧性测试

+   跨浏览器支持

+   可以创建可以运行命令并支持控制流结构的脚本

请访问 Selenium IDE 网页（[`www.seleniumhq.org/selenium-ide/`](https://www.seleniumhq.org/selenium-ide/)）获取更多信息和安装程序。请访问 Selenium 项目网页（[`www.seleniumhq.org/projects/`](https://www.seleniumhq.org/projects/)）获取有关 Selenium 组件的更多信息。

现在我们知道了 Selenium 的用途和一些主要组件，让我们看看如何安装和使用 Selenium WebDriver 进行一般测试。

# 设置事物

为了成功实现使用 Selenium 进行浏览器自动化和应用程序测试，需要设置 WebDriver。让我们通过以下步骤来设置 Google Chrome 的 WebDriver：

1.  访问[`www.seleniumhq.org/`](https://www.seleniumhq.org/)。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/89dd533f-86a7-4e6c-903a-5c2871c08465.png) SeleniumHQ 浏览器自动化主页

1.  点击下载（或浏览至[`www.seleniumhq.org/download/`](https://www.seleniumhq.org/download/)）。

1.  在第三方驱动程序、绑定和插件部分，点击 Google Chrome Driver（或浏览至[`sites.google.com/a/chromium.org/chromedriver/`](https://sites.google.com/a/chromium.org/chromedriver/)）：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/3c2a948b-705e-484b-aa17-09037bc7600b.png) 第三方驱动程序，Selenium

1.  从 ChromeDriver - WebDriver for Chrome ([`sites.google.com/a/chromium.org/chromedriver`](https://sites.google.com/a/chromium.org/chromedriver/))，下载适用于平台的最新稳定版本的 ChromeDriver：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/1cb5ee93-dd5d-4666-97f0-9d19d5c799ed.png)

ChromeDriver 列表

1.  解压下载的`chromedriver*.zip`。应该出现一个名为`chromedriver.exe`的应用程序文件。我们可以将`.exe`文件放在包含代码的主文件夹中。

我们将在整个章节中使用谷歌浏览器和 ChromeDriver；有关使用其他浏览器的详细信息，或有关 Selenium 的更多信息，请访问 SeleniumHQ。有关安装的更多信息，请参阅[`selenium-python.readthedocs.io/installation.html`](https://selenium-python.readthedocs.io/installation.html)。

现在我们已经完成了 WebDriver 和 Selenium Python 库的设置，让我们通过 Python IDE 验证这个设置。如下面的屏幕截图所示，`selenium`包含`webdriver`模块，包括`Chrome`、`Android`、`Firefox`、`Ie`和`Opera`等子模块。当前版本是`3.14.1`：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/3c831b9c-ad14-4038-956d-7b7d7e81cc6d.png)

打印 selenium.webdriver 版本

我们将使用 Selenium 与谷歌浏览器，因此让我们探索`webdriver`中`Chrome`的内容：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/1c169341-d09d-4daf-ba71-52e874b3e558.png)

从 Selenium WebDriver 探索 Chrome。

如前面的屏幕截图所示，有许多函数将被调用和用于实现浏览器自动化。您还可以看到许多函数名称以`find_element*`开头，类似于我们在早期章节中用于爬取活动的遍历和解析函数。

在下一节中，我们将学习关于`selenium.webdriver`。

# 探索 Selenium

在本节中，我们将使用和介绍`webdriver`和`webdriver.Chrome`的各种属性，同时查看一些真实案例。接下来的章节将说明 Selenium 的使用并探索其主要属性。

# 访问浏览器属性

在本节中，我们将演示使用 Selenium 和 Chrome WebDriver 加载谷歌浏览器的 URL 并访问某些基于浏览器的功能。

首先，让我们从`selenium`中导入`webdriver`并设置到`chromedriver.exe`的路径，让我们称之为`chromedriver_path`。创建的路径将需要加载谷歌浏览器。根据应用程序位置，应提及`chromedriver.exe`的完整路径，并且对于成功实施是必需的：

```py
from selenium import webdriver
import re

#setting up path to 'chromedriver.exe'
chromedriver_path='chromedriver' #C:\\Users\\....\\...\chromedriver.exe 
```

`selenium.webdriver`用于实现各种浏览器，在本例中是谷歌浏览器。`webdriver.Chrome()`短语提供了 Chrome WebDriver 的路径，以便`chromedriver_path`用于执行。

短语`driver`是`webdriver.chrome.webdriver.WebDriver`类的对象，使用`webdriver.Chrome()`创建，现在将提供对`webdriver`的各种属性和属性的访问：

```py
driver = webdriver.Chrome(executable_path=chromedriver_path)
```

`chromedriver.exe`将在此实例或在`driver`对象创建时实例化。终端屏幕和空白的新窗口将加载谷歌浏览器，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/579126b7-c2b6-4201-8489-75cb356740da.png)

终端屏幕和空白浏览器页面

如果您在执行到目前为止的代码时遇到任何错误，请按照以下步骤执行代码：

1.  获取最新的 ChromeDriver 并替换现有的 ChromeDriver

1.  更新和验证`chromedriver_path`的`PATH`

然后使用`get()`函数从`webdriver`为谷歌浏览器提供一个 URL。

`get()`短语接受要在浏览器上加载的 URL。让我们将[`www.python.org`](https://www.python.org)作为`get()`的参数；浏览器将开始加载 URL，如下面的屏幕截图所示：

```py
driver.get('https://www.python.org')
```

如您在下面的截图中所见，地址栏下方显示了一个通知，其中包含消息**Chrome is being controlled by automated test software**。这条消息也确认了`selenium.webdriver`活动的成功执行，并且可以提供进一步的代码来操作或自动化加载的页面：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/455fd250-2530-46ec-8fba-27ae3ff539ec.png)

Chrome 浏览器加载了 https://www.python.org

在页面成功加载后，我们可以使用`driver`访问和探索其属性。为了说明这一点，让我们从 HTML `<title>`标签中提取或打印标题，并打印当前可访问的 URL：

```py
print("Title: ",driver.title) #print <title> text
Title:  Welcome to Python.org

print("Current Page URL: ",driver.current_url) #print current url, loaded in the browser
Current Page URL:  https://www.python.org/
```

如前面的代码所示，可以使用`driver.title`获取页面标题，使用`driver.current_url`找到当前页面的 URL。`current_url`短语可用于验证在加载初始 URL 后是否发生了任何 URL 重定向。让我们使用 Python 库`re`的`search()`保存页面截图：

```py
#check if pattern matches the current url loaded

if re.search(r'python.org',driver.current_url):
    driver.save_screenshot("pythonorg.png") #save screenshot with provided name
    print("Python Screenshot Saved!")
```

`save_screenshot()`短语以文件名作为图像的参数，并创建一个 PNG 图像。图像将保存在当前代码位置；也可以提供完整的目标或所需路径。

为了进一步探索，让我们从[`www.python.org`](https://www.python.org)收集网页 cookies。使用`get_cookies()`短语来检索 cookies，如下所示：

```py
#get cookie information
cookies = driver.get_cookies() 
print("Cookies obtained from python.org")
print(cookies)

Cookies obtained from python.org
[{'domain': '.python.org', 'expiry': 1619415025, 'httpOnly': False, 'name': '__utma', 'path': '/', 'secure': False, 'value': '32101439.1226541417.1556343026.1556343026.1556343026.1'},........ {'domain': '.python.org', 'expiry': 1556343625, 'httpOnly': False, 'name': '__utmt', 'path': '/', 'secure': False, 'value': '1'}]
```

可以使用`driver.page_source`获取页面源。

要手动获取页面源，请右键单击页面，然后单击“查看页面源”，或按*Ctrl* + *U*：

```py
print(driver.page_source) #page source
```

可以使用`driver.refresh()`重新加载或刷新页面。

要手动刷新页面源，请右键单击页面，然后单击“重新加载”，或按*Ctrl* + *R*：

```py
driver.refresh() #reload or refresh the browser
```

使用前面代码中的`driver`访问的功能，让我们继续加载、截图和访问[`www.google.com`](https://www.google.com)的 cookies，使用以下代码：

```py
driver.get('https://www.google.com')
print("Title: ",driver.title)
print("Current Page URL: ",driver.current_url)

if re.search(r'google.com',driver.current_url):
    driver.save_screenshot("google.png")
    print("Google Screenshot Saved!")

cookies = driver.get_cookies()
```

使用[`google.com`](http://google.com)执行的操作将在用于访问[`python.org`](http://python.org)的同一浏览器窗口上进行。有了这个，我们现在可以使用浏览器历史记录执行操作（即，我们将使用 Web 浏览器中可用的“返回”和“前进”按钮），并检索 URL，如下面的代码所示：

```py
print("Current Page URL: ",driver.current_url)

driver.back() #History back action
print("Page URL (Back): ",driver.current_url)

driver.forward() #History forward action
print("Page URL (Forward): ",driver.current_url)
```

在上述代码中，`back()`将浏览器返回到上一页，而`forward()`将其沿着浏览器历史向前移动一步。收到的输出如下：

```py
Current Page URL: https://www.google.com/
Page URL (Back): https://www.python.org/
Page URL (Forward): https://www.google.com/
```

在成功执行代码后，建议您关闭并退出驱动程序以释放系统资源。我们可以使用以下功能执行终止操作：

```py
driver.close() #close browser
driver.quit()  #quit webdriver
```

上述代码包含以下两个短语：

+   `close()`终止加载的浏览器窗口

+   `quit()`结束 WebDriver 应用程序

到目前为止，在本节中我们执行的完整代码如下：

```py
from selenium import webdriver
import re
chrome_path='chromedriver'
driver = webdriver.Chrome(executable_path=chrome_path)  #print(type(driver))
driver.get('https://www.python.org')  
print("Title: ",driver.title)
print("Current Page URL: ",driver.current_url)

if re.search(r'python.org',driver.current_url):
    driver.save_screenshot("pythonorg.png")
    print("Python Screenshot Saved!")
cookies = driver.get_cookies()

print(driver.page_source)
driver.refresh()

driver.get('https://www.google.com')
print("Title: ",driver.title)
print("Current Page URL: ",driver.current_url)
if re.search(r'google.com',driver.current_url):
    driver.save_screenshot("google.png")
    print("Google Screenshot Saved!")
cookies = driver.get_cookies()

print("Current Page URL: ",driver.current_url)
driver.back()
print("Page URL (Back): ",driver.current_url)
driver.forward()
print("Page URL (Forward): ",driver.current_url)

driver.close()
driver.quit()
```

上述代码演示了`selenium.webdriver`及其各种属性的使用。在下一节中，我们将演示`webdriver`和网页元素（网页中的元素）的使用。

# 定位网页元素

在本节中，我们将在[`automationpractice.com`](http://automationpractice.com)上进行搜索，以获取与搜索查询匹配的产品列表，演示`selenium.webdriver`的使用。网页元素是列在网页上或在页面源中找到的元素。我们还看一下一个名为`WebElement`的类，它被用作`selenium.webdriver.remote.webelement.WebElement`。

自动化实践网站（[`automationpractice.com/`](http://automationpractice.com/)）是来自[`www.seleniumframework.com`](http://www.seleniumframework.com)的一个示例电子商务网站，您可以用来练习。

首先，让我们从`selenium`中导入`webdriver`，设置`chromedriver.exe`的路径，创建`webdriver`的对象——也就是在前一节*访问浏览器属性*中实现的`driver`，并加载 URL，[`automationpractice.com`](http://automationpractice.com)：

```py
driver.get('http://automationpractice.com')
```

新的 Google Chrome 窗口将加载提供的 URL。如下图所示，找到位于购物车上方的搜索（输入）框：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/43ae769c-80e3-431a-807d-2097da75cebd.png)

从 http://automationpractice.com 检查元素（搜索框）

要继续通过脚本搜索，我们需要识别具有 HTML `<input>`的元素。请参阅第三章中的*使用 Web 浏览器开发者工具访问 Web 内容*部分，*使用 LXML、XPath 和 CSS 选择器*。

在我们的情况下，搜索框可以通过前面截图中显示的属性来识别，甚至可以使用 XPath 或 CSS 选择器：

+   `id="search_query_top"`

+   `name="search_query"`

+   `class="search_query"`

`selenium.webdriver`提供了许多定位器（用于定位元素的方法），可以方便地应用于遇到的情况。

定位器返回单个、多个或 WebElement 实例的列表，写作`selenium.webdriver.remote.webelement.WebElement`。以下是一些定位器以及简要描述：

+   `find_element_by_id()`: 通过其`id`属性来查找元素。此方法返回单个 WebElement。

+   `find_element_by_name()`: 通过其`name`属性来查找单个元素。可以使用`find_elements_by_name()`来找到或定位多个 WebElement。

+   `find_element_by_tag_name()`: 通过其 HTML 标签的名称来查找单个元素。可以使用`find_elements_by_tag_name()`来定位多个 WebElement。

+   `find_element_by_class_name()`: 通过其`class`属性来查找单个元素。可以使用`find_elements_by_class_name()`来定位多个 WebElement。

+   `find_element_by_link_text()`: 通过链接文本标识的链接来查找单个元素。可以使用`find_elements_by_link_text()`来定位多个 WebElement。

+   `find_element_by_partial_link_text()`: 通过元素携带的部分文本来查找单个元素的链接。可以使用`find_elements_by_partial_link_text()`来定位多个 WebElement。

+   `find_element_by_xpath()`: 通过提供 XPath 表达式来查找单个元素。可以使用`find_elements_by_xpath()`来定位多个 WebElement。

+   `find_element_by_css_selector()`: 通过提供 CSS 选择器来查找单个元素。可以使用`find_elements_by_css_selector()`来定位多个 WebElement。

现在，让我们使用`find_element_by_id()`来找到输入框：

```py
searchBox = driver.find_element_by_id('search_query_top')
#searchBox = driver.find_element_by_xpath('//*[@id="search_query_top"]')
#searchBox = driver.find_element_by_css_selector('#search_query_top')
```

如前面的代码所示，`searchBox`可以使用任何方便的定位器来定位，这些定位器都提供了它们各自的参数。

获得的 WebElement 可以访问以下属性和一般方法，以及许多其他方法：

+   `get_attribute()`: 返回提供的键参数的属性值，例如`value`、`id`、`name`和`class`。

+   `tag_name`: 返回特定 WebElement 的 HTML 标签名称。

+   `text`: 返回 WebElement 的文本。

+   `clear()`: 这会清除 HTML 表单元素的文本。

+   `send_keys()`: 用于填充文本并提供键效果，例如按下`ENTER`、`BACKSPACE`和`DELETE`，可从`selenium.webdriver.common`模块中的`selenium.webdriver.common.keys`模块中获得，应用于 HTML 表单元素。

+   `click()`: 执行单击操作到 WebElement。用于 HTML 元素，如提交按钮。

在下面的代码中，我们将使用前面列出的`searchBox`中的函数和属性：

```py
print("Type :",type(searchBox))
<class 'selenium.webdriver.remote.webelement.WebElement'>

print("Attribute Value :",searchBox.get_attribute("value")) #is empty
Attribute Value *:* 

print("Attribute Class :",searchBox.get_attribute("class"))
Attribute Class : search_query form-control ac_input

print("Tag Name :",searchBox.tag_name)
Tag Name : input
```

让我们清除`searchBox`内的文本并输入要搜索的文本`Dress`。我们还需要提交位于`searchBox`右侧的按钮，并点击它以使用 WebElement 方法`click()`执行搜索：

```py
searchBox.clear() 
searchBox.send_keys("Dress")
submitButton = driver.find_element_by_name("submit_search")
submitButton.click()
```

浏览器将处理提交的文本`Dress`的搜索操作并加载结果页面。

现在搜索操作完成，为了验证成功的搜索，我们将使用以下代码提取有关产品数量和计数的信息：

```py
#find text or provided class name
resultsShowing = driver.find_element_by_class_name("product-count")
print("Results Showing: ",resultsShowing.text) 

Results Showing: Showing 1-7 of 7 items

#find results text using XPath
resultsFound = driver.find_element_by_xpath('//*[@id="center_column"]//span[@class="heading-counter"]')
print("Results Found: ",resultsFound.text)

Results Found: 7 results have been found.
```

通过找到的项目数量和产品数量，这传达了我们搜索过程的成功信息。现在，我们可以继续使用 XPath、CSS 选择器等查找产品：

```py
#Using XPath
products = driver.find_elements_by_xpath('//*[@id="center_column"]//a[@class="product-name"]')

#Using CSS Selector
#products = driver.find_elements_by_css_selector('ul.product_list li.ajax_block_product a.product-name')

foundProducts=[]
for product in products:
    foundProducts.append([product.text,product.get_attribute("href")])
```

从前面的代码中，对获得的`products`进行迭代，并将单个项目添加到 Python 列表`foundProducts`中。`product`是 WebElement 对象，换句话说，是`selenium.webdriver.remote.webelement.WebElement`，而属性是使用`text`和`get_attribute()`收集的：

```py
print(foundProducts) 

[['Printed Summer Dress',
'http://automationpractice.com/index.php?id_product=5&controller=product&search_query=Dress&results=7'],
['Printed Dress',
'http://automationpractice.com/index.php?id_product=4&controller=product&search_query=Dress&results=7'],
['Printed Summer Dress',
'http://automationpractice.com/index.php?id_product=6&controller=product&search_query=Dress&results=7'],
['Printed Chiffon Dress',
'http://automationpractice.com/index.php?id_product=7&controller=product&search_query=Dress&results=7'],['PrintedDress',
'http://automationpractice.com/index.php?id_product=3&controller=product&search_query=Dress&results=7'],
['Faded Short Sleeve T-shirts',
'http://automationpractice.com/index.php?id_product=1&controller=product&search_query=Dress&results=7'],['Blouse',
'http://automationpractice.com/index.php?id_product=2&controller=product&search_query=Dress&results=7']]
```

在本节中，我们探索了`selenium.webdriver`中用于处理浏览器、使用 HTML 表单、读取页面内容等的各种属性和方法。请访问[`selenium-python.readthedocs.io`](https://selenium-python.readthedocs.io)了解有关 Python Selenium 及其模块的更详细信息。在下一节中，我们将使用本节中使用的大部分方法来从网页中抓取信息。

# 使用 Selenium 进行网页抓取

Selenium 用于测试 Web 应用程序。它主要用于使用各种基于编程语言的库和浏览器驱动程序执行浏览器自动化。正如我们在前面的*探索 Selenium*部分中看到的，我们可以使用 Selenium 导航和定位页面中的元素，并执行爬取和抓取相关的活动。

让我们看一些使用 Selenium 从网页中抓取内容的示例。

# 示例 1 - 抓取产品信息

在这个例子中，我们将继续使用*探索 Selenium*部分获得的`foundProducts`的搜索结果。

我们将从`foundProducts`中找到的每个单独的产品链接中提取一些特定信息，列举如下：

+   `product_name`：产品名称

+   `product_price`：列出的价格

+   `image_url`：产品主要图片的 URL

+   `item_condition`：产品的状态

+   `product_description`：产品的简短描述

使用`driver.get()`加载`foundProducts`中的每个单独的产品链接：

```py
dataSet=[]
if len(foundProducts)>0:
   for foundProduct in foundProducts:
       driver.get(foundProduct[1])

       product_url = driver.current_url
       product_name = driver.find_element_by_xpath('//*[@id="center_column"]//h1[@itemprop="name"]').text
       short_description = driver.find_element_by_xpath('//*[@id="short_description_content"]').text
       product_price = driver.find_element_by_xpath('//*[@id="our_price_display"]').text
       image_url = driver.find_element_by_xpath('//*[@id="bigpic"]').get_attribute('src')
       condition = driver.find_element_by_xpath('//*[@id="product_condition"]/span').text
       dataSet.append([product_name,product_price,condition,short_description,image_url,product_url])

print(dataSet)
```

使用 XPath 获取要提取的目标字段或信息，并将其附加到`dataSet`。请参考[第三章](https://cdp.packtpub.com/hands_on_web_scraping_with_python/wp-admin/post.php?post=31&action=edit#post_26)中的*使用 Web 浏览器开发者工具访问 Web 内容*部分，*使用 LXML、XPath 和 CSS 选择器*。

从`dataSet`中获取的输出如下：

```py
[['Printed Summer Dress','$28.98','New','Long printed dress with thin adjustable straps. V-neckline and wiring under the bust with ruffles at the bottom of the dress.', 'http://automationpractice.com/img/p/1/2/12-large_default.jpg', 'http://automationpractice.com/index.php?id_product=5&controller=product&search_query=Dress&results=7'],
['Printed Dress','$50.99','New','Printed evening dress with straight sleeves with black .............,
['Blouse','$27.00','New','Short sleeved blouse with feminine draped sleeve detail.', 'http://automationpractice.com/img/p/7/7-large_default.jpg','http://automationpractice.com/index.php?id_product=2&controller=product&search_query=Dress&results=7']]
```

最后，使用`close()`和`quit()`保持系统资源空闲。此示例的完整代码如下：

```py
from selenium import webdriver
chrome_path='chromedriver' driver = webdriver.Chrome(executable_path=chrome_path)
driver.get('http://automationpractice.com')

searchBox = driver.find_element_by_id('search_query_top')
searchBox.clear()
searchBox.send_keys("Dress")
submitButton = driver.find_element_by_name("submit_search")
submitButton.click()

resultsShowing = driver.find_element_by_class_name("product-count")
resultsFound = driver.find_element_by_xpath('//*[@id="center_column"]//span[@class="heading-counter"]')

products = driver.find_elements_by_xpath('//*[@id="center_column"]//a[@class="product-name"]')
foundProducts=[]
for product in products:
    foundProducts.append([product.text,product.get_attribute("href")])

dataSet=[]
if len(foundProducts)>0:
   for foundProduct in foundProducts:
       driver.get(foundProduct[1])
       product_url = driver.current_url
       product_name = driver.find_element_by_xpath('//*[@id="center_column"]//h1[@itemprop="name"]').text
       short_description = driver.find_element_by_xpath('//*[@id="short_description_content"]').text
       product_price = driver.find_element_by_xpath('//*[@id="our_price_display"]').text
       image_url = driver.find_element_by_xpath('//*[@id="bigpic"]').get_attribute('src')
       condition = driver.find_element_by_xpath('//*[@id="product_condition"]/span').text
       dataSet.append([product_name,product_price,condition,short_description,image_url,product_url])

driver.close()
driver.quit()
```

在这个例子中，我们执行了基于 HTML `<form>`的操作，并从每个单独的页面中提取所需的细节。表单处理是在测试 Web 应用程序期间执行的主要任务之一。

# 示例 2 - 抓取书籍信息

在这个例子中，我们将自动化浏览器来处理主 URL 提供的类别和分页链接。我们有兴趣从[`books.toscrape.com/index.html`](http://books.toscrape.com/index.html)跨多个页面提取*食品和饮料*类别的详细信息。

类别中的单个页面包含产品（书籍）的列表，其中包含以下某些信息：

+   `title`：书籍的标题

+   `titleLarge`：列出的书籍标题（完整标题，作为`title`属性的值找到）

+   `price`：列出的书籍价格

+   `stock`：与列出的书籍相关的库存信息

+   `image`：书籍图片的 URL

+   `starRating`：评级（找到的星星数量）

+   `url`：列出每本书的 URL。

在第三章中还展示了一个类似的例子，*使用 LXML、XPath 和 CSS 选择器*中的*使用 LXML 进行网页抓取*部分，名称为*示例 2 - 使用 XPath 循环并从多个页面抓取数据*。在那里，我们使用了 Python 库`lxml`。

导入`selenium.webdriver`并设置 Chrome 驱动程序路径后，让我们开始加载[`books.toscrape.com/index.html`](http://books.toscrape.com/index.html)。当主页面加载时，我们将看到各种类别依次列出。

目标类别包含文本“食品和饮料”，可以使用`find_element_by_link_text()`找到（我们可以使用任何适用的`find_element...`方法来找到特定类别）。找到的元素进一步使用`click()`进行处理 - 即点击返回的元素。此操作将在浏览器中加载特定类别的 URL：

```py
driver.get('http://books.toscrape.com/index.html')

driver.find_element_by_link_text("Food and Drink").click()
print("Current Page URL: ", driver.current_url)
totalBooks = driver.find_element_by_xpath("//*[@id='default']//form/strong[1]")
print("Found: ", totalBooks.text)
```

为了处理在迭代过程中找到的多个页面，将从`selenium.common.exceptions`导入`NoSuchElementException`：

```py
from selenium.common.exceptions import NoSuchElementException
```

由于我们将使用分页按钮 next，`NoSuchElementException`将有助于处理如果没有找到进一步的 next 或页面的情况。

如下代码所示，分页选项 next 位于页面中，并使用`click()`操作进行处理。此操作将加载它包含的 URL 到浏览器中，并且迭代将继续直到在页面中找不到或找到 next，被代码中的`except`块捕获：

```py
try:
 #Check for Pagination with text 'next'  driver.find_element_by_link_text('next').click()
    continue except NoSuchElementException:
    page = False
```

此示例的完整代码如下所示：

```py
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
chrome_path = 'chromedriver' driver = webdriver.Chrome(executable_path=chrome_path)
driver.get('http://books.toscrape.com/index.html')

dataSet = []
driver.find_element_by_link_text("Food and Drink").click()
totalBooks = driver.find_element_by_xpath("//*[@id='default']//form/strong[1]")

page = True while page:
    listings = driver.find_elements_by_xpath("//*[@id='default']//ol/li[position()>0]")
    for listing in listings:
        url=listing.find_element_by_xpath(".//article[contains(@class,'product_pod')]/h3/a"). get_attribute('href')
        title=listing.find_element_by_xpath(".//article[contains(@class,'product_pod')]/h3/a").text
        titleLarge=listing.find_element_by_xpath(".//article[contains(@class,'product_pod')]/h3/a"). get_attribute('title')
        price=listing.find_element_by_xpath(".//article/div[2]/p[contains(@class,'price_color')]").text
        stock=listing.find_element_by_xpath(".//article/div[2]/p[2][contains(@class,'availability')]"). text
        image=listing.find_element_by_xpath(".//article/div[1][contains(@class,'image_container')]/a/img") .get_attribute('src')
        starRating=listing.find_element_by_xpath(".//article/p[contains(@class,'star-rating')]"). get_attribute('class')
        dataSet.append([titleLarge,title,price,stock,image,starRating.replace('star-rating ',''),url])

    try:
  driver.find_element_by_link_text('next').click()
        continue
 except NoSuchElementException:
        page = False 
driver.close()
driver.quit()
```

最后，在迭代完成后，`dataSet`将包含所有页面的列表数据，如下所示：

```py
[['Foolproof Preserving: A Guide to Small Batch Jams, Jellies, Pickles, Condiments, and More: A Foolproof Guide to Making Small Batch Jams, Jellies, Pickles, Condiments, and More', 'Foolproof Preserving: A Guide ...','£30.52','In stock', 'http://books.toscrape.com/media/cache/9f/59/9f59f01fa916a7bb8f0b28a4012179a4.jpg','Three','http://books.toscrape.com/catalogue/foolproof-preserving-a-guide-to-small-batch-jams-jellies-pickles-condiments-and-more-a-foolproof-guide-to-making-small-batch-jams-jellies-pickles-condiments-and-more_978/index.html'], ['The Pioneer Woman Cooks: Dinnertime: Comfort Classics, Freezer Food, 16-Minute Meals, and Other Delicious Ways to Solve Supper!', 'The Pioneer Woman Cooks: ...', '£56.41', 'In stock', 'http://books.toscrape.com/media/cache/b7/f4/b7f4843dbe062d44be1ffcfa16b2faa4.jpg', 'One', 'http://books.toscrape.com/catalogue/the-pioneer-woman-cooks-dinnertime-comfort-classics-freezer-food-16-minute-meals-and-other-delicious-ways-to-solve-supper_943/index.html'],................, 
['Hungry Girl Clean & Hungry: Easy All-Natural Recipes for Healthy Eating in the Real World', 'Hungry Girl Clean & ...', '£33.14', 'In stock', 'http://books.toscrape.com/media/cache/6f/c4/6fc450625cd672e871a6176f74909be2.jpg', 'Three', 'http://books.toscrape.com/catalogue/hungry-girl-clean-hungry-easy-all-natural-recipes-for-healthy-eating-in-the-real-world_171/index.html']]
```

在本节中，我们探索了来自`selenium.webdriver`的方法和属性，并将其用于网页抓取活动。

# 摘要

在本章中，我们学习了关于 Selenium 以及使用 Python 库进行浏览器自动化、网页内容抓取、基于浏览器的活动和 HTML `<form>` 处理。 Selenium 可以用于处理多种活动，这是 Selenium 相对于 Python 专用库（如`lxml`、`pyquery`、`bs4`和`scrapy`）的主要优势之一。

在下一章中，我们将学习更多关于使用正则表达式进行网页抓取的技术。

# 进一步阅读

+   SeleniumHQ: [`www.seleniumhq.org/`](https://www.seleniumhq.org/)

+   Selenium with Python: [`selenium-python.readthedocs.io/`](https://selenium-python.readthedocs.io/)

+   Python Selenium: [`pypi.python.org/pypi/selenium`](http://pypi.python.org/pypi/selenium)


# 第九章：使用正则表达式提取数据

如果您当前的 Python 设置中不存在这些库，请参考第二章，*Python 和 Web - 使用 urllib 和 Requests*，*设置事项*部分，了解有关其安装和设置的更多信息。到目前为止，我们已经学习了关于 Web 技术、数据查找技术以及如何使用 Python 库访问 Web 内容的知识。

**正则表达式**（**Regex**或**regex**）实际上是使用预定义命令和格式构建的模式，以匹配所需内容。在数据提取过程中，当没有特定的布局或标记模式可供选择时，正则表达式提供了很大的价值，并且可以与 XPath、CSS 选择器等其他技术一起应用。

复杂的网页内容和一般文本或字符格式的数据可能需要使用正则表达式来完成匹配和提取等活动，还包括函数替换、拆分等。

在本章中，我们将学习以下主题：

+   正则表达式概述

+   使用正则表达式提取数据

# 技术要求

本章需要一个 Web 浏览器（Google Chrome 或 Mozilla Firefox）。我们将使用以下 Python 库：

+   `请求`

+   `re`

+   `bs4`

如果您当前的 Python 设置中不存在这些库，请参考第二章，*Python 和 Web - 使用 urllib 和 Requests*，*设置事项*部分，了解有关其安装和设置的更多信息。

本章的代码文件可在本书的 GitHub 存储库中找到：[`github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python/tree/master/Chapter09`](https://github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python/tree/master/Chapter09)。

那些已经使用`re`的人可以参考*使用正则表达式提取数据*部分。

# 正则表达式概述

正则表达式用于匹配文本或字符串中找到的模式。正则表达式可以用于根据需要对文本或网页内容进行测试和查找模式。正则表达式包含各种定义模式和特殊符号的方法，例如*转义代码*，以应用一些预定义规则。有关正则表达式的更多信息，请参考*进一步阅读*部分。

有各种情况下，正则表达式可以非常有效和快速地获得所需的结果。正则表达式可以仅应用于内容（文本或网页源代码），并且可以用于针对不易使用 XPath、CSS 选择器、BS4*、*PyQuery 等提取的特定信息模式。

有时，可能会出现需要同时使用正则表达式和 XPath 或 CSS 选择器才能获得所需输出的情况。然后可以使用正则表达式对输出进行测试，以查找模式或清理和管理数据。代码编辑器、文档编写器和阅读器还提供了嵌入式基于正则表达式的实用工具。

正则表达式可以应用于任何包含正确或不正确格式的文本或字符字符串、HTML 源代码等。正则表达式可以用于各种应用，例如以下内容：

+   基于特定模式的内容

+   页面链接

+   图像标题和链接

+   链接内的文本

+   匹配和验证电子邮件地址

+   从地址字符串中匹配邮政编码或邮政编码

+   验证电话号码等

使用搜索、查找、拆分、替换、匹配和迭代等工具，无论是否有其他技术干扰，都可以适用。

在接下来的章节中，我们将使用`re` Python 模块并探索其方法，然后将其应用于正则表达式。

# 正则表达式和 Python

`re`是一个标准的 Python 库，用于处理正则表达式。每个默认的 Python 安装都包含`re`库。如果该库不存在，请参考第二章，*Python 和 Web - 使用 urllib 和 Requests**,* *设置事物*部分，了解如何设置它。

`>>>` 在代码中表示使用 Python IDE。它接受给定的代码或指令，并在下一行显示输出。

让我们开始通过 Python IDE 导入`re`并使用`dir()`函数列出其属性：

```py
>>> import re
>>> print(dir(re)) #listing features from re
```

以下是前面命令的输出：

```py
['A', 'ASCII', 'DEBUG', 'DOTALL', 'I', 'IGNORECASE', 'L', 'LOCALE', 'M', 'MULTILINE', 'S', 'Scanner', 'T', 'TEMPLATE', 'U', 'UNICODE', 'VERBOSE', 'X', '_MAXCACHE', '__all__', '__builtins__', '__cached__', '__doc__', '__file__', '__loader__', '__name__', '__package__', '__spec__', '__versio n__', '_alphanum_bytes', '_alphanum_str', '_cache', '_cache_repl', '_compile', '_compile_repl', '_expand', '_locale', '_pattern_type', '_pickle', '_subx', 'compile', 'copyreg', 'error', 'escape', 'findall', 'finditer', 'fullmatch', 'match', 'purge', 'search', 'split', 'sre_compile', 'sre_parse', 'sub', 'subn', 'sys', 'template']
```

从前面的输出中可以看出，在`re`中有各种可用的函数。我们将从内容提取的角度使用其中的一些函数，并通过使用以下示例来解释正则表达式的基础知识：

```py
>>> sentence = """Brief information about Jobs in Python. Programming and Scripting experience in some language (such as Python R, MATLAB, SAS, Mathematica, Java, C, C++, VB, JavaScript or FORTRAN) is expected. Participants should be comfortable with basic programming concepts like variables, loops, and functions."""
```

我们之前声明的`sentence`包含有关 Python 工作和工作描述的简要信息。我们将使用这个句子来解释基本的正则表达式功能。

`split()`函数将字符串分解并返回由*空格*字符默认分隔的单词列表。我们也可以使用`re.split()`来拆分字符串对象。在这种情况下，`split()`接受正则表达式模式来拆分句子，例如`re.split(r'\s+',sentence)`： 

```py
>>> splitSentence = sentence.split() #split sentence or re.split(r'\s',sentence) >>> print("Length of Sentence: ",len(sentence), '& splitSentence: ',len(splitSentence))
Length of Sentence: 297 & splitSentence: 42 >>> print(splitSentence) #List of words obtained using split() 
['Brief', 'information', 'about', 'Jobs', 'in', 'Python.', 'Programming', 'and', 'Scripting', 'experience', 'in', 'some', 'language', '(such', 'as', 'Python', 'R,', 'MATLAB,', 'SAS,', 'Mathematica,', 'Java,', 'C,', 'C++,', 'VB,', 'JavaScript', 'or', 'FORTRAN)', 'is', 'expected.', 'Participants', 'should', 'be', 'comfortable', 'with', 'basic', 'programming', 'concepts', 'like', 'variables,', 'loops,', 'and', 'functions.']
```

使用前面的代码获取并打印`sentence`的长度和 Python 的`splitSentence`列表对象的长度。这些元素和字符的计数将有助于比较从以下示例返回的答案：

```py
>>> matches = re.findall(r"([A-Z+]+)\,",sentence) #finding pattern with [A-Z+] and comma behind >>> print("Findall found total ",len(matches)," Matches >> ",matches) **Findall found total  6  Matches >>  ['R', 'MATLAB', 'SAS', 'C', 'C++', 'VB']** >>> matches = re.findall(r"([A-Z]+)\,",sentence) #finding pattern with [A-Z] and comma behind >>> print("Findall found total ",len(matches)," Matches >> ",matches) Findall found total 5 Matches >> ['R', 'MATLAB', 'SAS', 'C', 'VB']
```

`re.findall()`接受要搜索的模式和要查找的与提供的模式相关的内容。通常，模式可以直接作为参数提供给函数，并且作为*原始*字符串前面带有`r`，例如`r'([A-Z]+)'`，或包含*原始*字符串的变量。

在前面的代码中，我们可以看到类似的模式，提供了一些额外的字符，但它们的输出不同。以下是一些这些模式的一般解释：

+   `[A-Z]`：模式中的方括号匹配一组字符，并且区分大小写。在这里，它匹配从`A`到`Z`的字符，但不匹配`a`到`z`的字符。我们可以提供一组字符，例如`[A-Za-z0-9]`，它匹配从`A`到`Z`和`a`到`z`的任何字符，以及从`0`到`9`的数字字符。如果需要，可以在集合中传递其他字符，例如`[A-Z+]`；`+`字符可以与`A`到`Z`的字符一起存在，例如 C++或 C。

+   `()`: 模式中的圆括号包含匹配的值组。

+   `+`（用于重复）：在字符集之外找到时，它匹配模式的一个或多个出现。`[A-Z]+`将匹配至少一个或多个`A`到`Z`的字符组合，例如，前面代码中的`R`和`MATLAB`。还有一些用于指定重复或出现次数的其他字符，也称为正则表达式量词：

+   `*` 匹配零次或多次模式

+   `?` 匹配模式的零次或一次出现

+   `{m,n}` 分别匹配重复的最小`m`和最大`n`次数：

+   `{2,5}`：最少 2 次或最多 5 次

+   `{2,}`：最少 2 次或更多

+   `{,5}`：最多 5 次

+   `{3}`：3 次出现

+   `\,`（逗号）：在正则表达式中，除了`[A-Za-z0-9]`之外的字符通常被写为转义字符，以便提及特定的字符（`\,`代表逗号，`\.`代表句号，`\?`代表问号等）。

正则表达式量词也分为以下几类：

+   **贪婪量词**：这些量词尽可能多地匹配任何元素。

+   **懒惰或非贪婪量词**：这些量词尽可能少地匹配任何元素。通常，通过在贪婪量词后添加`?`将其转换为懒惰量词。

诸如 `([A-Z+]+)\,` 的模式匹配从 `A` 到 `Z` 和 `+` 中至少一个或多个字符，后跟`,`。在前面的代码中的`sentence`中，我们可以找到`R`、`MATLAB`、`SAS`、`Mathematica`、`Java`、`C`、`C++`、`VB`和`JavaScript`（还有`FORTRAN`），即名称后跟`,`（但不适用于`FORTRAN`的情况；这就是为什么它在提供的模式的输出中被排除的原因）。

在下面的代码中，我们试图匹配在`sentence`中找到的`FORTRAN`，并使用先前在代码中尝试的模式进行省略：

```py
>>> matches = re.findall(r"\s*([\sorA-Z+]+)\)",sentence) #r'\s*([A-Z]+)\)' matches 'FORTRAN' 
>>> print("Findall found total ",len(matches)," Matches >> ",matches)

Findall found total  1  Matches >>  ['or FORTRAN']

>>> fortran = matches[0] # 'or FORTRAN'
>>> if re.match(r'or',fortran): 
 fortran = re.sub(r'or\s*','',fortran) #substitute 'or ' with empty string >>> print(fortran)

FORTRAN

>>> if re.search(r'^F.*N$',fortran):  #using beginning and end of line searching pattern 
 print("True")
 True
```

如前面的代码块所示，Python 库`re`具有各种函数，如下所示：

+   `re.match()`: 这匹配提供的模式在字符串的开头，并返回匹配的对象。

+   `re.sub()`: 这会找到一个模式并用提供的字符串替换它。它类似于文本中的查找和替换。

+   `re.search()`: 这在字符串中匹配模式并返回找到的匹配对象。

+   `\s`: 这表示*空格*、*制表符*和*换行符*。在这里，`[\sorA-Z+]+\)`匹配一个或多个字符，包括`A-Z`、`o`、`r`、`\s`和`+`，后跟`\)`（右括号）。在正则表达式中还有一些其他转义代码，如下所示：

+   `\d`: 匹配数字

+   `\D`: 匹配非数字

+   `\s`: 匹配空白

+   `\S`: 匹配非空白

+   `\w`: 匹配字母数字字符

+   `\W`: 匹配非字母数字字符

+   `\b`: 匹配单词边界

+   `\B`: 匹配非单词边界

+   `^`: 这匹配字符串的开头。

注意：`r'[^a-z]'`（插入符号或`^`）在字符集内使用时起否定作用。这意味着*除了*或*排除*`[a-z]`。

+   `$`: 这匹配字符串的结尾。

+   `|`: 这在模式中实现逻辑表达式`OR`。例如，`r'a|b'`将匹配任何真实表达式，即`a`或`b`。

以下代码显示了一些这些正则表达式模式和`findall()`函数的使用，以及它们的输出：

```py
>>> matches  = re.findall(r'\s(MAT.*?)\,',sentence,flags=re.IGNORECASE)
>>> print("(MAT.*?)\,: ",matches)  #r'(?i)\s(MAT.*?)\,' can also be used
 (MAT.*?)\,: ['MATLAB', 'Mathematica']   >>> matches = re.findall(r'\s(MAT.*?)\,',sentence) #findall with 'MAT' case-sensitive
>>> print("(MAT.*?)\,: ",matches)
 (MAT.*?)\,: ['MATLAB']   >>> matches = re.findall(r'\s(C.*?)\,',sentence)
>>> print("\s(C.*?)\,: ",matches)
 \s(C.*?)\,: ['C', 'C++']
```

在前面的代码中找到了以下函数：

+   `re` 函数还支持可选的*flags* 参数。这些标志也有缩写形式（`i`代表`re.IGNORECASE`，`s`代表`re.DOTALL`，`M`代表`re.MULTILINE`）。它们可以通过在表达式开头包含它们来在模式中使用。例如，`r'(?i)\s(MAT.*?)\,`将返回[`MATLAB`, `Mathematica`]。以下是在代码中找到的一些其他`re`函数：

+   `re.IGNORECASE` : 忽略提供的模式中发现的大小写敏感性

+   `re.DOTALL` : 允许`.` (句号)匹配换行符，并且适用于包含多行的字符串

+   `re.MULTILINE` : 与多行字符串一起使用，并搜索包括换行符(`"\n"`)在内的模式

+   `.` 或句号: 这匹配任何单个字符，但不包括换行符(`"\n"`)。它通常与重复字符一起在模式中使用。句号或`.` 需要在字符串中匹配，并且应该使用`\.`：

```py
>>> matchesOne = re.split(r"\W+",sentence)  #split by word, \w (word characters, \W - nonword) >>> print("Regular Split '\W+' found total: ",len(matchesOne ),"\n",matchesOne)  Regular Split '\W+' found total: 43 
['Brief', 'information', 'about', 'Jobs', 'in', 'Python', 'Programming', 'and', 'Scripting', 'experience', 'in', 'some', 'language', 'such', 'as', 'Python', 'R', 'MATLAB', 'SAS', 'Mathematica', 'Java', 'C', 'C', 'VB', 'JavaScript', 'or', 'FORTRAN', 'is', 'expected', 'Participants', 'should', 'be', 'comfortable', 'with', 'basic', 'programming', 'concepts', 'like', 'variables', 'loops', 'and', 'functions', ''] >>> matchesTwo = re.split(r"\s",sentence) #split by space
>>> print("Regular Split '\s' found total: ",len(matchesTwo),"\n", matchesTwo) **Regular Split '\s' found total: 42** 
['Brief', 'information', 'about', 'Jobs', 'in', 'Python.', 'Programming', 'and', 'Scripting', 'experience', 'in', 'some', 'language', '(such', 'as', 'Python', 'R,', 'MATLAB,', 'SAS,', 'Mathematica,', 'Java,', 'C,', 'C++,', 'VB,', 'JavaScript', 'or', 'FORTRAN)', 'is', 'expected.', 'Participants', 'should', 'be', 'comfortable', 'with', 'basic', 'programming', 'concepts', 'like', 'variables,', 'loops,', 'and', 'functions.']
```

+   `re.split()`: 这根据模式拆分提供的内容并返回带有结果的列表。还有一个`split()`，它可以与字符串一起使用以使用默认或提供的字符进行分割。它的使用方式与本节中稍早的`splitSentence`类似。

建议您比较此部分中`matchesOne`和`matchesTwo`的结果**。**

在下面的代码中，我们尝试应用 datetime 属性中找到的值的正则表达式模式。定义的模式将被编译，然后用于在代码块中搜索：

```py
>>> timeDate= '''<time datetime="2019-02-11T18:00:00+00:00"></time> <time datetime="2018-02-11T13:59:00+00:00"></time> <time datetime="2019-02-06T13:44:00.000002+00:00"></time> <time datetime="2019-02-05T17:39:00.000001+00:00"></time> <time datetime="2019-02-04T12:53:00+00:00"></time>''' >>> pattern = r'(20\d+)([-]+)(0[1-9]|1[012])([-]+)(0[1-9]|[12][0-9]|3[01])' >>> recompiled = re.compile(pattern)  # <class '_sre.SRE_Pattern'>
>>> dateMatches = recompiled.search(timeDate)
```

+   `re.compile()`: 用于编译正则表达式模式并接收模式对象（`_sre.SRE_Pattern`）。接收到的对象可以与其他正则表达式功能一起使用。

可以通过使用`group()`方法单独探索组匹配，如下面的代码所示：

```py
>>> print("Group : ",dateMatches.group()) 
Group : 2019-02-11
 >>> print("Groups : ",dateMatches.groups())
Groups : ('2019', '-', '02', '-', '11')
 >>> print("Group 1 : ",dateMatches.group(1))
Group 1 : 2019
 >>> print("Group 5 : ",dateMatches.group(5))
Group 5 : 11
```

正如我们所看到的，尽管该模式已经针对多行 `timeDate` 进行了搜索，但结果是一个单独的分组；也可以使用索引返回单个分组。一个与 `re` 相关的匹配对象包含了 `groups()` 和 `group()` 函数；`groups(0)` 的结果与 `groups()` 相同。`groups()` 中的单个元素将需要从 `1` 开始的索引。

+   `re.finditer()`: 用于迭代在提供的内容中找到的模式或模式对象的结果匹配。它返回一个从 `re.match()` 中找到的匹配（`_sre.SRE_Match`）对象。

`re.match()` 返回一个包含在代码示例中使用的各种函数和属性的对象。这些如下：

+   `start()`: 返回与表达式匹配的起始字符索引

+   `end()`: 返回与表达式匹配的结束字符索引

+   `span()`: 返回匹配表达式的起始和结束字符索引

+   `lastindex`: 返回最后匹配表达式的索引

+   `groupdict()`: 返回匹配组字典与模式字符串和匹配值

+   `groups()`: 返回所有匹配的元素

+   `group()`: 返回一个单独的分组，并可以通过分组名称访问

+   `lastgroup`: 返回最后一个组的名称

```py
>>> for match in re.finditer(pattern, timeDate): # <class '_sre.SRE_Match'>
 #for match in re.finditer(recompiled, timeDate):
 s = match.start()
 e = match.end()
 l = match.lastindex
 g = match.groups()

 print('Found {} at {}:{}, groups{} lastindex:{}'.format(timeDate[s:e], s, e,g,l))

Found 2019-02-11 at 16:26, groups('2019', '-', '02', '-', '11') lastindex:5
Found 2018-02-11 at 67:77, groups('2018', '-', '02', '-', '11') lastindex:5
Found 2019-02-06 at 118:128, groups('2019', '-', '02', '-', '06') lastindex:5
Found 2019-02-05 at 176:186, groups('2019', '-', '02', '-', '05') lastindex:5
Found 2019-02-04 at 234:244, groups('2019', '-', '02', '-', '04') lastindex:5
```

模式也可以为它们所在的组指定字符串名称；例如，`r'(?P<year>[0-9]{4})'` 匹配 `year` 组。在正则表达式中使用基于组的模式可以帮助我们更准确地读取模式并管理输出；这意味着我们不必担心索引。

让我们考虑模式 `pDate`（实现 `group()`, `groupdict()`, `start()`, `end()`, `lastgroup`, 和 `lastindex`）与一个分组名称和代码，分别展示日期和时间的输出：

```py
>>> pDate = r'(?P<year>[0-9]{4})(?P<sep>[-])(?P<month>0[1-9]|1[012])-(?P<day>0[1-9]|[12][0-9]|3[01])' >>> recompiled = re.compile(pDate) #compiles the pattern >>> for match in re.finditer(recompiled,timeDate): #apply pattern on timeDate
 s = match.start()
 e = match.end()
 l = match.lastindex

 print("Group ALL or 0: ",match.groups(0)) #or match.groups() that is all
 print("Group Year: ",match.group('year')) #return year
 print("Group Month: ",match.group('month')) #return month
 print("Group Day: ",match.group('day')) #return day

 print("Group Delimiter: ",match.group('sep')) #return seperator
 print('Found {} at {}:{}, lastindex: {}'.format(timeDate[s:e], s, e,l))

 print('year :',match.groupdict()['year']) #accessing groupdict()
 print('day :',match.groupdict()['day'])

 print('lastgroup :',match.lastgroup) #lastgroup name
```

前面的代码将产生以下输出：

```py
Group ALL or 0: ('2019', '-', '02', '11')
Group Year: 2019
Group Month: 02
Group Day: 11
Group Delimiter: -
Found 2019-02-11 at 16:26, lastindex: 4
year : 2019
day : 11
lastgroup : day
```

以下代码显示了使用 `pTime`（实现 `span()`）：

```py
>>> pTime = r'(?P<hour>[0-9]{2})(?P<sep>[:])(?P<min>[0-9]{2}):(?P<sec_mil>[0-9.:+]+)'
>>> recompiled = re.compile(pTime)

>>> for match in re.finditer(recompiled,timeDate):
 print("Group String: ",match.group()) #groups
 print("Group ALL or 0: ",match.groups())

 print("Group Span: ",match.span()) #using span()
 print("Group Span 1: ",match.span(1))
 print("Group Span 4: ",match.span(4))

 print('hour :',match.groupdict()['hour']) #accessing groupdict()
 print('minute :',match.groupdict()['min'])
 print('second :',match.groupdict()['sec_mil'])

 print('lastgroup :',match.lastgroup) #lastgroup name
```

前面的代码将产生以下输出：

```py
Group String: 12:53:00+00:00
Group ALL or 0: ('12', ':', '53', '00+00:00')
Group Span: (245, 259)
Group Span 1: (245, 247)
Group Span 4: (251, 259)
hour : 12
minute : 53
second : 00+00:00
lastgroup : sec_mil
```

在本节中，我们已经介绍了正则表达式的一般概述和 `re` Python 库的特性，以及一些实际示例。请参考*进一步阅读*部分以获取有关正则表达式的更多信息。在下一节中，我们将应用正则表达式来从基于 web 的内容中提取数据。

# 使用正则表达式提取数据

现在我们已经介绍了基础知识并概述了正则表达式，我们将使用正则表达式以类似于使用 XPath、CSS 选择器、`pyquery`、`bs4` 等的方式批量抓取（提取）数据，通过选择在正则表达式、XPath、`pyquery` 等之间的实现来满足网页访问的要求和可行性以及内容的可用性。

并不总是要求内容应该是无结构的才能应用正则表达式并提取数据。正则表达式可以用于结构化和非结构化的网页内容，以提取所需的数据。在本节中，我们将探讨一些示例，同时使用正则表达式及其各种属性。

# 示例 1 - 提取基于 HTML 的内容

在这个例子中，我们将使用来自 `regexHTML.html` 文件的 HTML 内容，并应用正则表达式模式来提取以下信息：

+   HTML 元素

+   元素的属性（`key` 和 `values`）

+   元素的内容

这个例子将为您提供一个如何处理网页内容中存在的各种元素、值等以及如何应用正则表达式来提取内容的概述。我们将在接下来的代码中应用以下步骤来处理 HTML 和类似内容：

```py
<html>
<head>
   <title>Welcome to Web Scraping: Example</title>
   <style type="text/css">
        ....
   </style>
</head>
<body>
    <h1 style="color:orange;">Welcome to Web Scraping</h1>
     Links:
    <a href="https://www.google.com" style="color:red;">Google</a>   <a class="classOne" href="https://www.yahoo.com">Yahoo</a>   <a id="idOne" href="https://www.wikipedia.org" style="color:blue;">Wikipedia</a>
    <div>
        <p id="mainContent" class="content">
            <i>Paragraph contents</i>
            <img src="mylogo.png" id="pageLogo" class="logo"/>
        </p>
        <p class="content" id="subContent">
            <i style="color:red">Sub paragraph content</i>
            <h1 itemprop="subheading">Sub heading Content!</h1>
        </p>
    </div>
</body>
</html>
```

前面的代码是我们将要使用的 HTML 页面源代码。这里的内容是结构化的，我们可以用多种方式处理它。

在下面的代码中，我们将使用以下函数：

+   `read_file()`: 这将读取 HTML 文件并返回页面源代码以供进一步处理。

+   `applyPattern()`: 这个函数接受一个`pattern`参数，即用于查找内容的正则表达式模式，它使用`re.findall()`应用于 HTML 源代码，并打印诸如搜索元素列表和它们的计数之类的信息。

首先，让我们导入`re`和`bs4`：

```py
import re
from bs4 import BeautifulSoup

def read_file():
   ''' Read and return content from file (.html). '''  content = open("regexHTML.html", "r")
    pageSource = content.read()
    return pageSource

def applyPattern(pattern):
'''Applies regex pattern provided to Source and prints count and contents'''
    elements = re.findall(pattern, page) #apply pattern to source
    print("Pattern r'{}' ,Found total: {}".format(pattern,len(elements)))
    print(elements) #print all found tags
    return   if __name__ == "__main__":
    page = read_file() #read HTML file 
```

在这里，`page`是从 HTML 文件中使用`read_file()`读取的 HTML 页面源。我们还在前面的代码中导入了`BeautifulSoup`，以提取单独的 HTML 标签名称，并通过使用`soup.find_all()`和我们将应用的正则表达式模式来比较代码的实现和结果：

```py
soup = BeautifulSoup(page, 'lxml')
print([element.name for element in soup.find_all()])
['html', 'head', 'title', 'style', 'body', 'h1', 'a', 'a', 'a', 'div', 'p', 'i', 'img', 'p', 'i', 'h1']
```

为了找到`page`中存在的所有 HTML 标签，我们使用了`find_all()`方法，`soup`作为`BeautifulSoup`的对象，使用`lxml`解析器。

有关 Beautiful Soup 的更多信息，请访问第五章，*使用 Scrapy 和 Beautiful Soup 进行 Web 抓取*，*使用 Beautiful Soup 进行 Web 抓取*部分。

在这里，我们正在查找所有没有任何属性的 HTML 标签名称。`\w+`匹配任何一个或多个字符的单词：

```py
applyPattern(r'<(\w+)>') #Finding Elements without attributes 
Pattern r'<(\w+)>' ,Found total: 6
['html', 'head', 'title', 'body', 'div', 'i']
```

可以使用空格字符`\s`来查找所有不以`>`结尾或包含某些属性的 HTML 标签或元素：

```py
applyPattern(r'<(\w+)\s') #Finding Elements with attributes 
Pattern r'<(\w+)\s' ,Found total: 10
['style', 'h1', 'a', 'a', 'a', 'p', 'img', 'p', 'i', 'h1']
```

现在，通过结合所有这些模式，我们正在列出在页面源中找到的所有 HTML 标签。通过使用`soup.find_all()`和`name`属性，前面的代码也得到了相同的结果：

```py
applyPattern(r'<(\w+)\s?') #Finding all HTML element

Pattern r'<(\w+)\s?' ,Found total: 16
['html', 'head', 'title', 'style', 'body', 'h1', 'a', 'a', 'a', 'div', 'p', 'i', 'img', 'p', 'i', 'h1']
```

让我们找到 HTML 元素中的属性名称：

```py
applyPattern(r'<\w+\s+(.*?)=') #Finding attributes name Pattern r'<\w+\s+(.*?)=' ,Found total: 10
['type', 'style', 'href', 'class', 'id', 'id', 'src', 'class', 'style', 'itemprop']
```

正如我们所看到的，只列出了 10 个属性。在 HTML 源代码中，一些标签包含多个属性，比如`<a href="https://www.google.com" style="color:red;">Google</a>`，只有使用提供的模式找到了第一个属性。

让我们纠正这一点。我们可以使用`r'(\w+)='`模式选择紧跟着`=`字符的单词，这将导致返回页面源中找到的所有属性：

```py
applyPattern(r'(\w+)=') #Finding names of all attributes Pattern r'(\w+)=' ,Found total: 18
['type', 'style', 'href', 'style', 'class', 'href', 'id', 'href', 'style', 'id', 'class', 'src', 'id', 'class', 'class', 'id', 'style', 'itemprop']
```

同样，让我们找到我们找到的属性的所有值。以下代码列出了属性的值，并比较了我们之前列出的`18`个属性。只找到了`9`个值。使用的模式`r'=\"(\w+)\"'`只会找到单词字符。一些属性值包含非单词字符，比如`<a href="https://www.google.com" style="color:red;">`：

```py
applyPattern(r'=\"(\w+)\"')

Pattern r'=\"(\w+)\"' ,Found total: 9
['classOne', 'idOne', 'mainContent', 'content', 'pageLogo', 'logo', 'content', 'subContent', 'subheading']
```

通过使用我们分析的适当模式列出了完整的属性值。内容属性值还包含非单词字符，如`;`、`/`、`:`和`.`。在正则表达式中，我们可以单独包含这些字符，但这种方法可能并不适用于所有情况。

在这种情况下，包括`\w`和非空白字符`\S`的模式非常合适，即`r'=\"([\w\S]+)\"`：

```py
applyPattern(r'=\"([\w\S]+)\"')

Pattern r'=\"([\w\S]+)\"' ,Found total: 18
['text/css', 'color:orange;', 'https://www.google.com', 'color:red;', 'classOne', 'https://www.yahoo.com', 'idOne', 'https://www.wikipedia.org', 'color:blue;', 'mainContent', 'content', 'mylogo.png', 'pageLogo', 'logo', 'content', 'subContent', 'color:red', 'subheading']
```

最后，让我们收集在 HTML 标签的开头和结尾之间找到的所有文本：

```py
applyPattern(r'\>(.*)\<')
Pattern r'\>(.*)\<' ,Found total: 8
['Welcome to Web Scraping: Example', 'Welcome to Web Scraping', 'Google', 'Yahoo', 'Wikipedia', 'Paragraph contents', 'Sub paragraph content', 'Sub heading Content!']  
```

在对内容应用正则表达式时，必须进行内容类型和要提取的值的初步分析。这将有助于在一次尝试中获得所需的结果。

# 示例 2 - 提取经销商位置

在这个例子中，我们将从[`godfreysfeed.com/dealersandlocations.php`](http://godfreysfeed.com/dealersandlocations.php)提取内容。这个网站包含经销商位置信息，如下面的屏幕截图所示：

```py
import re
import requests
 def read_url(url):
'''
Handles URL Request and Response
Loads the URL provided using requests and returns the text of page source
'''
  pageSource = requests.get(url).text
    return pageSource

if __name__ == "__main__":
```

在本节和其他示例中，我们将使用`re`和`requests`库来检索页面源代码，即`pageSource`。在这里，我们将使用`read_url()`函数来实现。

页面包含 HTML`<form>`元素，以便我们可以根据输入的`zipcode`搜索经销商。还有一个带有标记的地理地图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/6a8edbca-0e35-4112-8341-44add5a180f2.png)

Godfreysfeed 经销商首页

您可以使用`zipcode`进行表单提交，也可以从地图中提取内容。

通过分析页面源，我们将发现没有包含经销商信息的 HTML 元素。实现 Regex 非常适合这种情况。在这里，经销商的信息是在 JavaScript 代码中找到的，其中包含`latLng`和`infoWindowContent`等变量，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/5026c2bb-c5ec-42a4-ad46-e7d3c9d53192.png)

Godfreysfeed 经销商页面源

我们现在将继续加载所需 URL 的页面源，并实现 Regex 来查找数据：

```py
dataSet=list() #collecting data extracted
sourceUrl = 'http://godfreysfeed.com/dealersandlocations.php' page = read_url(sourceUrl) #load sourceUrl and return the page source
```

通过从`read_url()`获取的页面源，让我们进行基本分析并构建一个模式来收集纬度和经度信息。我们需要两个不同的模式来分别获取经销商的地址和坐标值。从这两个模式的输出可以合并以获得最终结果：

```py
#Defining pattern matching latitude and longitude as found in page.
pLatLng= r'var latLng = new google.maps.LatLng\((?P<lat>.*)\,\s*(?P<lng>.*)\)\;'

#applying pattern to page source latlngs = re.findall(pLatLng,page) 
print("Findall found total *LatLngs:* ", len(latlngs))

#Print coordinates found
print(latlngs)
```

通过使用`pLatLng`模式，共找到了`55`个坐标值：

```py
Findall found total LatLngs: 55 
[('33.2509855','-84.2633946'),('31.0426107','-84.8821949'),('34.8761989','-83.9582412'),('32.43158','-81.749293'),('33.8192864','-83.4387722'),('34.2959968','-83.0062267'),
('32.6537561','-83.7596295'),('31.462497','-82.5866503'),('33.7340136','-82.7472304')
,................................................................., 
('32.5444125','-82.8945945'),('32.7302168','-82.7117232'),('34.0082425','-81.7729772'),
('34.6639864', '-82.5126743'),('31.525261','-83.06603'),('34.2068698','-83.4689814'),
('32.9765932','-84.98978'),('34.0412765','-83.2001394'),('33.3066615','-83.6976187'), 
('31.3441482','-83.3002373'),('30.02116','-82.329495'),('34.58403','-83.760829')]
```

现在我们已经得到了经销商的坐标，让我们找出经销商的名称、地址等信息：

```py
#Defining pattern to find dealer from page.
pDealers = r'infoWindowContent = infoWindowContent\+\s*\"(.*?)\"\;'

#applying dealers pattern to page source dealers = re.findall(pDealers, page)
print("Findall found total Address: ", len(dealers))

#Print dealers information found
print(dealers)
```

还有`55`个基于地址的信息，是通过使用`pDealers`模式找到的。请注意，经销商的内容是以 HTML 格式呈现的，需要进一步实现 Regex 以获取诸如`name`、`address`和`city`等个别标题：

```py
Findall found total Address: 55

["<strong><span style='color:#e5011c;'>Akins Feed & Seed</span></strong><br><strong>206 N Hill Street </strong><br><strong>Griffin, GA</strong><br><strong>30223</strong><br><br>", "<strong><span style='color:#e5011c;'>Alf&apos;s Farm and Garden</span></strong><br><strong>101 East 1st Street</strong><br><strong>Donalsonville, GA</strong><br><strong>39845</strong><br><br>", "<strong><span style='color:#e5011c;'>American Cowboy Shop</span></strong><br><strong>513 D Murphy Hwy</strong><br><strong>Blairsville, GA</strong><br><strong>30512</strong><br><br>",................................... ....................................,"<strong><span style='color:#e5011c;'>White Co. Farmers Exchange </span></strong><br><strong>951 S Main St</strong><br><strong>Cleveland, GA</strong><br><strong>30528 </strong><br><br>"]
```

现在我们已经得到了`latlngs`和`dealers`的结果，让我们收集经销商地址的各个部分。经销商的原始数据包含一些 HTML 标签，已被用于拆分和清理经销商的地址信息。由于`re.findall()`返回 Python 列表，索引也可以用于检索地址组件：

```py
d=0 #maintaining loop counter for dealer in dealers:
    dealerInfo = re.split(r'<br>',re.sub(r'<br><br>','',dealer))

    #extract individual item from dealerInfo
    name = re.findall(r'\'>(.*?)</span',dealerInfo[0])[0]
    address = re.findall(r'>(.*)<',dealerInfo[1])[0]
    city = re.findall(r'>(.*),\s*(.*)<',dealerInfo[2])[0][0]
    state = re.findall(r'>(.*),\s*(.*)<',dealerInfo[2])[0][1]
    zip = re.findall(r'>(.*)<',dealerInfo[3])[0]
    lat = latlngs[d][0]
    lng = latlngs[d][1]
    d+=1

    #appending items to dataset
  dataSet.append([name,address,city,state,zip,lat,lng])
 print(dataSet)  #[[name,address, city, state, zip, lat,lng],]
```

最后，`dataSet`将包含从`dealers`和`latlngs`中合并的单个经销商信息：

```py
[['Akins Feed & Seed', '206 N Hill Street', 'Griffin', 'GA', '30223', '33.2509855', '-84.2633946'], ['Alf&apos;s Farm and Garden', '101 East 1st Street', 'Donalsonville', 'GA', '39845', '31.0426107', '-84.8821949'],...................................., 
['Twisted Fitterz', '10329 Nashville Enigma Rd', 'Alapaha', 'GA', '31622', '31.3441482', '-83.3002373'], 
['Westside Feed II', '230 SE 7th Avenue', 'Lake Butler', 'FL', '32054', '30.02116', '-82.329495'],
['White Co. Farmers Exchange', '951 S Main St', 'Cleveland', 'GA', '30528', '34.58403', '-83.760829']]
```

在这个例子中，我们尝试使用不同的模式提取数据，并从提供的 URL 中检索了经销商的信息。

# 示例 3 - 提取 XML 内容

在这个例子中，我们将从`sitemap.xml`文件中提取内容，可以从**[`webscraping.com/sitemap.xml`](https://webscraping.com/sitemap.xml)**下载：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/060d674a-0e48-4325-b8a3-720edd7f4a0a.png)

来自 https://webscraping.com 的 sitemap.xml 文件

通过分析 XML 内容，我们可以看到不同类型的 URL 存在于子节点中，即`<loc>`。我们将从这些 URL 中提取以下内容：

+   博客 URL（包含`/blog/`字符串的 URL，如[`webscraping.com/blog/Why-Python/`](https://webscraping.com/blog/Why-Python/)）

+   从博客 URL 获取的标题（*Why-Python*）

+   类别 URL（包含`/category/`字符串的 URL，如[`webscraping.com/blog/category/beautifulsoup`](https://webscraping.com/blog/category/beautifulsoup)）

+   从类别 URL 获取的类别标题（*beautifulsoup*）

从代码中获取的博客标题和类别标题是从 URL 或实际可用的内容的表示中检索出来的。实际标题可能会有所不同。

首先，让我们导入`re` Python 库并读取文件内容，以及创建一些 Python 列表以收集相关数据：

```py
import re

filename = 'sitemap.xml' dataSetBlog = [] # collect Blog title information from URLs except 'category' dataSetBlogURL = [] # collects Blog URLs dataSetCategory = [] # collect Category title dataSetCategoryURL = [] # collect Category URLs   page = open(filename, 'r').read()
```

从 XML 内容，也就是`page`中，我们需要找到 URL 模式。代码中使用的`pattern`匹配并返回`<loc>`节点内的所有 URL。`urlPatterns`（`<class 'list'>`）是一个包含搜索 URL 的 Python 列表对象，可以迭代收集和处理所需的信息：

```py
#Pattern to be searched, found inside <loc>(.*)</loc>
pattern = r"loc>(.*)</loc" urlPatterns = re.findall(pattern, page) #finding pattern on page

for url in urlPatterns: #iterating individual url inside urlPatterns
```

现在，让我们匹配一个`url`，比如[`webscraping.com/blog/Google-App-Engine-limitations/`](https://webscraping.com/blog/Google-App-Engine-limitations/)，其中包含一个`blog`字符串，并将其附加到`dataSetBlogURL`。还有一些其他 URL，比如[`webscraping.com/blog/8/`](https://webscraping.com/blog/8/)，在我们提取`blogTitle`时将被忽略。

此外，任何作为文本等于`category`的`blogTitle`都将被忽略。`r'blog/([A-Za-z0-9\-]+)`模式匹配包含`-`字符的字母和数字值：

```py
if re.match(r'.*blog', url): #Blog related
    dataSetBlogURL.append(url)
 if re.match(r'[\w\-]', url):
        blogTitle = re.findall(r'blog/([A-Za-z0-9\-]+)', url)

        if len(blogTitle) > 0 and not re.match('(category)', blogTitle[0]):
            #blogTitle is a List, so index is applied.
            dataSetBlog.append(blogTitle[0]) 
```

以下是`dataSetBlogURL`的输出：

```py
print("Blogs URL: ", len(dataSetBlogURL))
print(dataSetBlogURL)

Blogs URL: 80
['https://webscraping.com/blog', 'https://webscraping.com/blog/10/', 
'https://webscraping.com/blog/11/', .......,
'https://webscraping.com/blog/category/screenshot', 'https://webscraping.com/blog/category/sitescraper', 'https://webscraping.com/blog/category/sqlite', 'https://webscraping.com/blog/category/user-agent', 'https://webscraping.com/blog/category/web2py', 'https://webscraping.com/blog/category/webkit', 'https://webscraping.com/blog/category/website/', 'https://webscraping.com/blog/category/xpath']
```

`dataSetBlog`将包含以下标题（URL 部分）。将`set()`方法应用于`dataSetBlog`时，将从`dataSetBlog`返回唯一元素。如下所示，`dataSetBlog`中没有重复的标题：

```py
print**("Blogs Title: ", len(dataSetBlog))
print("Unique Blog Count: ", len(set(dataSetBlog)))
print(dataSetBlog)
#print(set(dataSetBlog)) #returns unique element from List similar to dataSetBlog.

Blogs Title: 24
Unique Blog Count: 24
 ['Android-Apps-Update', 'Apple-Apps-Update', 'Automating-CAPTCHAs', 'Automating-webkit', 'Bitcoin', 'Client-Feedback', 'Fixed-fee-or-hourly', 'Google-Storage', 'Google-interview', 'How-to-use-proxies', 'I-love-AJAX', 'Image-efficiencies', 'Luminati', 'Reverse-Geocode', 'Services', 'Solving-CAPTCHA', 'Startup', 'UPC-Database-Update', 'User-agents', 'Web-Scrapping', 'What-is-CSV', 'What-is-web-scraping', 'Why-Python', 'Why-web']
```

现在，让我们通过使用`category`来提取与 URL 相关的信息。`r'.*category'`正则表达式模式匹配迭代中的`url`，并将其收集或附加到`datasetCategoryURL`。从与`r'category/([\w\s\-]+)`模式匹配的`url`中提取`categoryTitle`，并将其添加到`dataSetCategory`：

```py
if re.match(r'.*category', url): #Category Related
    dataSetCategoryURL.append(url)
    categoryTitle = re.findall(r'category/([\w\s\-]+)', url)
    dataSetCategory.append(categoryTitle[0])

print("Category URL Count: ", len(dataSetCategoryURL))
print(dataSetCategoryURL)
```

`dataSetCategoryURL`将产生以下值：

```py
Category URL Count: 43
['https://webscraping.com/blog/category/ajax', 'https://webscraping.com/blog/category/android/', 'https://webscraping.com/blog/category/big picture', 'https://webscraping.com/blog/category/business/', 'https://webscraping.com/blog/category/cache', 'https://webscraping.com/blog/category/captcha', ..................................., 'https://webscraping.com/blog/category/sitescraper', 'https://webscraping.com/blog/category/sqlite', 'https://webscraping.com/blog/category/user-agent', 'https://webscraping.com/blog/category/web2py', 'https://webscraping.com/blog/category/webkit', 'https://webscraping.com/blog/category/website/', 'https://webscraping.com/blog/category/xpath']
```

最后，以下输出显示了从`dataSetCategory`中检索到的标题，以及其计数：

```py
print("Category Title Count: ", len(dataSetCategory))
print("Unique Category Count: ", len(set(dataSetCategory)))
print(dataSetCategory)
#returns unique element from List similar to dataSetCategory.
#print(set(dataSetCategory)) 

Category Title Count: 43
Unique Category Count: 43 
['ajax', 'android', 'big picture', 'business', 'cache', 'captcha', 'chickenfoot', 'concurrent', 'cookies', 'crawling', 'database', 'efficiency', 'elance', 'example', 'flash', 'freelancing', 'gae', 'google', 'html', 'image', 'ip', 'ir', 'javascript', 'learn', 'linux', 'lxml', 'mobile', 'mobile apps', 'ocr', 'opensource', 'proxies', 'python', 'qt', 'regex', 'scrapy', 'screenshot', 'sitescraper', 'sqlite', 'user-agent', 'web2py', 'webkit', 'website', 'xpath']
```

从这些示例中，我们可以看到，通过使用正则表达式，我们可以编写针对来自网页、HTML 或 XML 等来源的特定数据的模式。

搜索、分割和迭代等正则表达式功能可以通过`re` Python 库中的各种函数来实现。尽管正则表达式可以应用于任何类型的内容，但首选非结构化内容。使用 XPath 和 CSS 选择器时，首选带有属性的结构化网页内容。

# 摘要

在本章中，我们学习了正则表达式及其在`re` Python 库中的实现。

到目前为止，我们已经了解了各种基于抓取的工具和技术。当涉及到提取任务时，正则表达式可以提供更多的灵活性，并且可以与其他工具一起使用。

在下一章中，我们将学习进一步的步骤和主题，这些对于学习环境可能是有益的，比如管理抓取的数据，可视化和分析，以及机器学习和数据挖掘的介绍，以及探索一些相关资源。

# 进一步阅读

+   正则表达式指南：[`docs.python.org/2/howto/regex.html`](https://docs.python.org/2/howto/regex.html)

+   正则表达式 - JavaScript：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions)

+   Python 正则表达式：[`developers.google.com/edu/python/regular-expressions`](https://developers.google.com/edu/python/regular-expressions)

+   在线正则表达式测试器和调试器：[`regex101.com/`](https://regex101.com/)

+   *正则表达式食谱：第二版，2012* 作者：Jan Goyvaerts 和 Steven Levithan

+   正则表达式参考：[`regexone.com/references/python`](https://regexone.com/references/python)

+   正则表达式 - 信息：[`www.regular-expressions.info/python.html`](http://www.regular-expressions.info/python.html)
