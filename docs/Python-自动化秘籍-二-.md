# Python 自动化秘籍（二）

> 原文：[`zh.annas-archive.org/md5/de38d8b70825b858336fa5194110e245`](https://zh.annas-archive.org/md5/de38d8b70825b858336fa5194110e245)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：构建您的第一个 Web 抓取应用程序

在本章中，我们将涵盖以下内容：

+   下载网页

+   解析 HTML

+   爬取网络

+   订阅源

+   访问 Web API

+   与表单交互

+   使用 Selenium 进行高级交互

+   访问受密码保护的页面

+   加速网络抓取

# 介绍

互联网和**WWW**（**万维网**）可能是当今最重要的信息来源。大部分信息可以通过 HTTP 协议检索。**HTTP**最初是为了共享超文本页面而发明的（因此称为**超文本传输协议**），这开创了 WWW。

这个操作非常熟悉，因为它是任何网络浏览器中发生的事情。但我们也可以以编程方式执行这些操作，自动检索和处理信息。Python 在标准库中包含了一个 HTTP 客户端，但是 fantastic `requests`模块使它变得非常容易。在本章中，我们将看到如何做到这一点。

# 下载网页

下载网页的基本能力涉及对 URL 发出 HTTP `GET`请求。这是任何网络浏览器的基本操作。让我们快速回顾一下这个操作的不同部分：

1.  使用 HTTP 协议。

1.  使用最常见的 HTTP 方法`GET`。我们将在*访问 Web API*配方中看到更多。

1.  URL 描述页面的完整地址，包括服务器和路径。

该请求将由服务器处理，并发送回一个响应。这个响应将包含一个**状态码**，通常是 200，如果一切顺利的话，以及一个包含结果的 body，通常是一个包含 HTML 页面的文本。

大部分由用于执行请求的 HTTP 客户端自动处理。在这个配方中，我们将看到如何发出简单的请求以获取网页。

HTTP 请求和响应也可以包含头部。头部包含额外的信息，如请求的总大小，内容的格式，请求的日期以及使用的浏览器或服务器。

# 准备工作

使用 fantastic `requests`模块，获取网页非常简单。安装模块：

```py
$ echo "requests==2.18.3" >> requirements.txt
$ source .venv/bin/activate
(.venv) $ pip install -r requirements.txt 
```

我们将下载页面在[`www.columbia.edu/~fdc/sample.html`](http://www.columbia.edu/~fdc/sample.html)，因为它是一个简单的 HTML 页面，很容易在文本模式下阅读。

# 如何做...

1.  导入`requests`模块：

```py
>>> import requests
```

1.  对 URL 发出请求，这将花费一两秒钟：

```py
>>> url = 'http://www.columbia.edu/~fdc/sample.html'
>>> response = requests.get(url)
```

1.  检查返回的对象状态码：

```py
>>> response.status_code
200
```

1.  检查结果的内容：

```py
>>> response.text
'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">\n<html>\n<head>\n
...
FULL BODY
...
<!-- close the <html> begun above -->\n'
```

1.  检查进行中和返回的头部：

```py
>>> response.request.headers
{'User-Agent': 'python-requests/2.18.4', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}
>>> response.headers
{'Date': 'Fri, 25 May 2018 21:51:47 GMT', 'Server': 'Apache', 'Last-Modified': 'Thu, 22 Apr 2004 15:52:25 GMT', 'Accept-Ranges': 'bytes', 'Vary': 'Accept-Encoding,User-Agent', 'Content-Encoding': 'gzip', 'Content-Length': '8664', 'Keep-Alive': 'timeout=15, max=85', 'Connection': 'Keep-Alive', 'Content-Type': 'text/html', 'Set-Cookie': 'BIGipServer~CUIT~www.columbia.edu-80-pool=1764244352.20480.0000; expires=Sat, 26-May-2018 03:51:47 GMT; path=/; Httponly'}
```

# 它是如何工作的...

`requests`的操作非常简单；在 URL 上执行操作，这种情况下是`GET`，返回一个可以分析的`result`对象。主要元素是`status_code`和 body 内容，可以呈现为`text`。

可以在`request`字段中检查完整的请求：

```py
>>> response.request
<PreparedRequest [GET]>
>>> response.request.url
'http://www.columbia.edu/~fdc/sample.html'
```

完整的请求文档可以在这里找到：[`docs.python-requests.org/en/master/`](http://docs.python-requests.org/en/master/)。在本章中，我们将展示更多功能。

# 还有更多...

所有 HTTP 状态码可以在这个网页上检查：[`httpstatuses.com/`](https://httpstatuses.com/)。它们也在`httplib`模块中以方便的常量名称进行描述，如`OK`，`NOT_FOUND`或`FORBIDDEN`。

最著名的错误状态码可能是 404，当 URL 未找到时会发生。通过执行`requests.get('http://www.columbia.edu/invalid')`来尝试。

请求可以使用**HTTPS**协议（**安全 HTTP**）。它是等效的，但确保请求和响应的内容是私有的。`requests`会自动处理它。

任何处理任何私人信息的网站都将使用 HTTPS 来确保信息没有泄漏。HTTP 容易受到窃听。尽可能使用 HTTPS。

# 另请参阅

+   在第一章的*让我们开始自动化之旅*中的*安装第三方包*配方中

+   *解析 HTML*配方

# 解析 HTML

下载原始文本或二进制文件是一个很好的起点，但是网页的主要语言是 HTML。

HTML 是一种结构化语言，定义文档的不同部分，如标题和段落。HTML 也是分层的，定义了子元素。将原始文本解析为结构化文档的能力基本上是能够从网页中自动提取信息的能力。例如，如果在特定的`class div`中或在标题`h3`标签后面包含一些文本，则该文本可能是相关的。

# 准备就绪

我们将使用优秀的 Beautiful Soup 模块将 HTML 文本解析为可以分析的内存对象。我们需要使用`beautifulsoup4`包来使用可用的最新 Python 3 版本。将包添加到您的`requirements.txt`并在虚拟环境中安装依赖项：

```py
$ echo "beautifulsoup4==4.6.0" >> requirements.txt
$ pip install -r requirements.txt
```

# 如何做...

1.  导入`BeautifulSoup`和`requests`：

```py
>>> import requests >>> from bs4 import BeautifulSoup
```

1.  设置要下载并检索的页面的 URL：

```py
>>> URL = 'http://www.columbia.edu/~fdc/sample.html'
>>> response = requests.get(URL)
>>> response
<Response [200]>
```

1.  解析下载的页面：

```py
>>> page = BeautifulSoup(response.text, 'html.parser')
```

1.  获取页面的标题。注意它与浏览器中显示的内容相同：

```py
>>> page.title
<title>Sample Web Page</title>
>>> page.title.string
'Sample Web Page'
```

1.  在页面中查找所有的`h3`元素，以确定现有的部分：

```py
>>> page.find_all('h3')
[<h3><a name="contents">CONTENTS</a></h3>, <h3><a name="basics">1\. Creating a Web Page</a></h3>, <h3><a name="syntax">2\. HTML Syntax</a></h3>, <h3><a name="chars">3\. Special Characters</a></h3>, <h3><a name="convert">4\. Converting Plain Text to HTML</a></h3>, <h3><a name="effects">5\. Effects</a></h3>, <h3><a name="lists">6\. Lists</a></h3>, <h3><a name="links">7\. Links</a></h3>, <h3><a name="tables">8\. Tables</a></h3>, <h3><a name="install">9\. Installing Your Web Page on the Internet</a></h3>, <h3><a name="more">10\. Where to go from here</a></h3>]
```

1.  提取部分链接上的文本。当达到下一个`<h3>`标签时停止：

```py
>>> link_section = page.find('a', attrs={'name': 'links'})
>>> section = []
>>> for element in link_section.next_elements:
...     if element.name == 'h3':
...         break
...     section.append(element.string or '')
...
>>> result = ''.join(section)
>>> result
'7\. Links\n\nLinks can be internal within a Web page (like to\nthe Table of ContentsTable of Contents at the top), or they\ncan be to external web pages or pictures on the same website, or they\ncan be to websites, pages, or pictures anywhere else in the world.\n\n\n\nHere is a link to the Kermit\nProject home pageKermit\nProject home page.\n\n\n\nHere is a link to Section 5Section 5 of this document.\n\n\n\nHere is a link to\nSection 4.0Section 4.0\nof the C-Kermit\nfor Unix Installation InstructionsC-Kermit\nfor Unix Installation Instructions.\n\n\n\nHere is a link to a picture:\nCLICK HERECLICK HERE to see it.\n\n\n'
```

注意没有 HTML 标记；这都是原始文本。

# 它是如何工作的...

第一步是下载页面。然后，可以像第 3 步那样解析原始文本。生成的`page`对象包含解析的信息。

`html.parser`解析器是默认的，但是对于特定操作可能会出现问题。例如，对于大页面，它可能会很慢，或者在渲染高度动态的网页时可能会出现问题。您可以使用其他解析器，例如`lxml`，它速度更快，或者`html5lib`，它将更接近浏览器的操作，包括 HTML5 产生的动态更改。它们是外部模块，需要添加到`requirements.txt`文件中。

`BeautifulSoup`允许我们搜索 HTML 元素。它可以使用`.find()`搜索第一个元素，或者使用`.find_all()`返回一个列表。在第 5 步中，它搜索了一个具有特定属性`name=link`的特定标签`<a>`。之后，它继续在`.next_elements`上迭代，直到找到下一个`h3`标签，标志着该部分的结束。

提取每个元素的文本，最后组合成单个文本。注意`or`，它避免存储`None`，当元素没有文本时返回。

HTML 非常灵活，可以有多种结构。本配方中介绍的情况是典型的，但是在划分部分方面的其他选项可能是将相关部分组合在一个大的`<div>`标签或其他元素内，甚至是原始文本。需要进行一些实验，直到找到从网页中提取重要部分的特定过程。不要害怕尝试！

# 还有更多...

正则表达式也可以用作`.find()`和`.find_all()`方法的输入。例如，此搜索使用`h2`和`h3`标签：

```py
>>> page.find_all(re.compile('^h(2|3)'))
[<h2>Sample Web Page</h2>, <h3><a name="contents">CONTENTS</a></h3>, <h3><a name="basics">1\. Creating a Web Page</a></h3>, <h3><a name="syntax">2\. HTML Syntax</a></h3>, <h3><a name="chars">3\. Special Characters</a></h3>, <h3><a name="convert">4\. Converting Plain Text to HTML</a></h3>, <h3><a name="effects">5\. Effects</a></h3>, <h3><a name="lists">6\. Lists</a></h3>, <h3><a name="links">7\. Links</a></h3>,
```

```py
<h3><a name="tables">8\. Tables</a></h3>, <h3><a name="install">9\. Installing Your Web Page on the Internet</a></h3>, <h3><a name="more">10\. Where to go from here</a></h3>]
```

另一个有用的 find 参数是包含`class_`参数的 CSS 类。这将在本书的后面显示。

完整的 Beautiful Soup 文档可以在这里找到：[`www.crummy.com/software/BeautifulSoup/bs4/doc/`](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)。

# 另请参阅

+   在第一章的*让我们开始自动化之旅*中的*安装第三方包*配方

+   在第一章的*让我们开始自动化之旅*中的*介绍正则表达式*配方

+   *下载网页*配方

# 爬取网页

考虑到超链接页面的性质，从已知位置开始并跟随链接到其他页面是在抓取网页时的重要工具。

为此，我们爬取页面寻找一个小短语，并打印包含它的任何段落。我们只会在属于同一网站的页面中搜索。即只有以 www.somesite.com 开头的 URL。我们不会跟踪外部网站的链接。

# 准备工作

这个食谱是基于介绍的概念构建的，因此它将下载和解析页面以搜索链接并继续下载。

在爬取网页时，记得在下载时设置限制。很容易爬取太多页面。任何查看维基百科的人都可以证实，互联网是潜在无限的。

我们将使用一个准备好的示例，该示例可在 GitHub 存储库中找到：[`github.com/PacktPublishing/Python-Automation-Cookbook/tree/master/Chapter03/test_site`](https://github.com/PacktPublishing/Python-Automation-Cookbook/tree/master/Chapter03/test_site)。下载整个站点并运行包含的脚本。

```py
$ python simple_delay_server.py
```

它在 URL`http://localhost:8000`中提供站点。您可以在浏览器上查看它。这是一个简单的博客，有三篇文章。大部分内容都不那么有趣，但我们添加了一些包含关键字`python`的段落。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/28ceb1d7-d5a3-47b8-b776-e6a0d1bf8bcb.png)

# 如何做到这一点...

1.  完整的脚本`crawling_web_step1.py`可以在 GitHub 的以下链接找到：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter03/crawling_web_step1.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter03/crawling_web_step1.py)。最相关的部分显示在这里：

```py
...

def process_link(source_link, text):
    logging.info(f'Extracting links from {source_link}')
    parsed_source = urlparse(source_link)
    result = requests.get(source_link)
    # Error handling. See GitHub for details
    ...
    page = BeautifulSoup(result.text, 'html.parser')
    search_text(source_link, page, text)
    return get_links(parsed_source, page)

def get_links(parsed_source, page):
    '''Retrieve the links on the page'''
    links = []
    for element in page.find_all('a'):
        link = element.get('href')
        # Validate is a valid link. See GitHub for details
        ...
        links.append(link)
    return links
```

1.  搜索对`python`的引用，返回包含它和段落的 URL 列表。请注意，由于损坏的链接，有一些错误：

```py
$ python crawling_web_step1.py https://localhost:8000/ -p python
Link http://localhost:8000/: --> A smaller article , that contains a reference to Python
Link http://localhost:8000/files/5eabef23f63024c20389c34b94dee593-1.html: --> A smaller article , that contains a reference to Python
Link http://localhost:8000/files/33714fc865e02aeda2dabb9a42a787b2-0.html: --> This is the actual bit with a python reference that we are interested in.
Link http://localhost:8000/files/archive-september-2018.html: --> A smaller article , that contains a reference to Python
Link http://localhost:8000/index.html: --> A smaller article , that contains a reference to Python
```

1.  另一个很好的搜索词是`crocodile`。试一下：

```py
$ python crawling_web_step1.py http://localhost:8000/ -p crocodile
```

# 它是如何工作的...

让我们看看脚本的每个组件：

1.  一个循环，遍历`main`函数中找到的所有链接：

请注意，有 10 页的检索限制，并且正在检查是否已经添加了要添加的任何新链接。

请注意这两件事是有限制的。我们不会下载相同的链接两次，我们会在某个时候停止。

1.  在`process_link`函数中下载和解析链接：

它下载文件，并检查状态是否正确，以跳过诸如损坏链接之类的错误。它还检查类型（如`Content-Type`中描述的）是否为 HTML 页面，以跳过 PDF 和其他格式。最后，它将原始 HTML 解析为`BeautifulSoup`对象。

它还使用`urlparse`解析源链接，以便在步骤 4 中跳过所有对外部来源的引用。`urlparse`将 URL 分解为其组成元素：

```py
>>> from urllib.parse import urlparse
>>> >>> urlparse('http://localhost:8000/files/b93bec5d9681df87e6e8d5703ed7cd81-2.html')
ParseResult(scheme='http', netloc='localhost:8000', path='/files/b93bec5d9681df87e6e8d5703ed7cd81-2.html', params='', query='', fragment='')
```

1.  在`search_text`函数中找到要搜索的文本：

它在解析的对象中搜索指定的文本。请注意，搜索是作为`regex`进行的，仅在文本中进行。它打印出结果的匹配项，包括`source_link`，引用找到匹配项的 URL：

```py
for element in page.find_all(text=re.compile(text)):
    print(f'Link {source_link}: --> {element}')
```

1.  **`get_links`**函数检索页面上的所有链接：

它在解析页面中搜索所有`<a>`元素，并检索`href`元素，但只有具有这些`href`元素并且是完全合格的 URL（以`http`开头）的元素。这将删除不是 URL 的链接，例如`'#'`链接，或者是页面内部的链接。

还进行了额外的检查，以检查它们是否与原始链接具有相同的来源，然后将它们注册为有效链接。`netloc`属性允许检测链接是否来自与步骤 2 中生成的解析 URL 相同的 URL 域。

我们不会跟踪指向不同地址的链接（例如[`www.google.com`](http://www.google.com)）。

最后，链接被返回，它们将被添加到步骤 1 中描述的循环中。

# 还有更多...

还可以进一步强制执行其他过滤器，例如丢弃所有以`.pdf`结尾的链接，这意味着它们是 PDF 文件：

```py
# In get_links
if link.endswith('pdf'):
  continue
```

还可以使用`Content-Type`来确定以不同方式解析返回的对象。例如，PDF 结果（`Content-Type: application/pdf`）将没有有效的`response.text`对象进行解析，但可以用其他方式解析。其他类型也是如此，例如 CSV 文件（`Content-Type: text/csv`）或可能需要解压缩的 ZIP 文件（`Content-Type: application/zip`）。我们将在后面看到如何处理这些。

# 另请参阅

+   *下载网页*食谱

+   *解析 HTML*食谱

# 订阅 Feed

RSS 可能是互联网上最大的“秘密”。虽然它的辉煌时刻似乎是在 2000 年代，现在它不再处于聚光灯下，但它可以轻松订阅网站。它存在于许多地方，非常有用。

在其核心，RSS 是一种呈现有序引用（通常是文章，但也包括其他元素，如播客剧集或 YouTube 出版物）和发布时间的方式。这使得很自然地知道自上次检查以来有哪些新文章，以及呈现一些关于它们的结构化数据，如标题和摘要。

在这个食谱中，我们将介绍`feedparser`模块，并确定如何从 RSS Feed 中获取数据。

**RSS**不是唯一可用的 Feed 格式。还有一种称为**Atom**的格式，但两者几乎是等效的。`feedparser`也能够解析它，因此两者可以不加区分地使用。

# 准备工作

我们需要将`feedparser`依赖项添加到我们的`requirements.txt`文件中并重新安装它：

```py
$ echo "feedparser==5.2.1" >> requirements.txt
$ pip install -r requirements.txt
```

几乎所有涉及出版物的页面上都可以找到 Feed URL，包括博客、新闻、播客等。有时很容易找到它们，但有时它们会隐藏得有点深。可以通过`feed`或`RSS`进行搜索。

大多数报纸和新闻机构都将它们的 RSS Feed 按主题划分。我们将使用**纽约时报**主页 Feed 作为示例，[`rss.nytimes.com/services/xml/rss/nyt/HomePage.xml`](http://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml)。主要 Feed 页面上还有更多可用的 Feed：[`archive.nytimes.com/www.nytimes.com/services/xml/rss/index.html`](https://archive.nytimes.com/www.nytimes.com/services/xml/rss/index.html?mcubz=0)。

请注意，Feed 可能受到使用条款和条件的约束。在纽约时报的情况下，它们在主要 Feed 页面的末尾有描述。

请注意，此 Feed 经常更改，这意味着链接的条目将与本书中的示例不同。

# 如何做...

1.  导入`feedparser`模块，以及`datetime`、`delorean`和`requests`：

```py
import feedparser
import datetime
import delorean
import requests
```

1.  解析 Feed（它将自动下载）并检查其上次更新时间。Feed 信息，如 Feed 的标题，可以在`feed`属性中获取：

```py
>>> rss = feedparser.parse('http://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml')
```

```py
>>> rss.updated
'Sat, 02 Jun 2018 19:50:35 GMT'
```

1.  获取新于六小时的条目：

```py
>>> time_limit = delorean.parse(rss.updated) - datetime.timedelta(hours=6)
>>> entries = [entry for entry in rss.entries if delorean.parse(entry.published) > time_limit]
```

1.  条目将比总条目少，因为返回的条目中有些条目的时间已经超过六个小时：

```py
>>> len(entries)
10
>>> len(rss.entries)
44
```

1.  检索条目的信息，如`title`。完整的条目 URL 可作为`link`获取。探索此特定 Feed 中的可用信息：

```py
>>> entries[5]['title']
'Loose Ends: How to Live to 108'
>>> entries[5]['link']
'https://www.nytimes.com/2018/06/02/opinion/sunday/how-to-live-to-108.html?partner=rss&emc=rss'
>>> requests.get(entries[5].link)
<Response [200]>
```

# 工作原理...

解析的`feed`对象包含条目的信息，以及有关 Feed 本身的一般信息，例如更新时间。`feed`信息可以在`feed`属性中找到：

```py
>>> rss.feed.title
'NYT > Home Page'
```

每个条目都像一个字典，因此很容易检索字段。它们也可以作为属性访问，但将它们视为键可以获取所有可用的字段：

```py
>>> entries[5].keys()
dict_keys(['title', 'title_detail', 'links', 'link', 'id', 'guidislink', 'media_content', 'summary', 'summary_detail', 'media_credit', 'credit', 'content', 'authors', 'author', 'author_detail', 'published', 'published_parsed', 'tags'])
```

处理 Feed 的基本策略是解析它们并浏览条目，快速检查它们是否有趣，例如通过检查*描述*或*摘要*。如果它们有趣，就使用“链接”字段下载整个页面。然后，为了避免重新检查条目，存储最新的发布日期，下次只检查更新的条目。

# 还有更多...

完整的`feedparser`文档可以在这里找到：[`pythonhosted.org/feedparser/`](https://pythonhosted.org/feedparser/)。

可用的信息可能因源而异。在纽约时报的例子中，有一个带有标签信息的`tag`字段，但这不是标准的。至少，条目将有一个标题，一个描述和一个链接。

RSS 订阅也是筛选自己的新闻来源的好方法。有很好的订阅阅读器。

# 另请参阅

+   第一章中的*安装第三方软件包*配方，*让我们开始我们的自动化之旅*

+   *下载网页*的配方

# 访问 Web API

通过 Web 可以创建丰富的接口，通过 HTTP 进行强大的交互。最常见的接口是使用 JSON 的 RESTful API。这些基于文本的接口易于理解和编程，并使用通用技术，**与语言无关**，这意味着它们可以在任何具有 HTTP`client`模块的编程语言中访问，当然包括 Python。

除了 JSON 之外，还使用了其他格式，例如 XML，但 JSON 是一种非常简单和可读的格式，非常适合转换为 Python 字典（以及其他语言的等价物）。JSON 目前是 RESTful API 中最常见的格式。在这里了解更多关于 JSON 的信息：[`www.json.org/`](https://www.json.org/)。

RESTful 的严格定义需要一些特征，但更非正式的定义可能是通过 URL 访问资源。这意味着 URL 代表特定的资源，例如报纸上的文章或房地产网站上的属性。然后可以通过 HTTP 方法（`GET`查看，`POST`创建，`PUT`/`PATCH`编辑和`DELETE`删除）来操作资源。

适当的 RESTful 接口需要具有某些特征，并且是创建接口的一种方式，不严格限于 HTTP 接口。您可以在这里阅读更多信息：[`codewords.recurse.com/issues/five/what-restful-actually-means`](https://codewords.recurse.com/issues/five/what-restful-actually-means)。

使用`requests`与它们非常容易，因为它包含本机 JSON 支持。

# 准备就绪

为了演示如何操作 RESTful API，我们将使用示例站点[`jsonplaceholder.typicode.com/`](https://jsonplaceholder.typicode.com/)。它模拟了帖子，评论和其他常见资源的常见情况。我们将使用帖子和评论。要使用的 URL 如下：

```py
# The collection of all posts
/posts
# A single post. X is the ID of the post
/posts/X
# The comments of post X
/posts/X/comments
```

网站为它们中的每一个返回了适当的结果。非常方便！

因为这是一个测试站点，数据不会被创建，但站点将返回所有正确的响应。

# 如何做...

1.  导入`requests`：

```py
>>> import requests
```

1.  获取所有帖子的列表并显示最新帖子：

```py
>>> result = requests.get('https://jsonplaceholder.typicode.com/posts')
>>> result
<Response [200]>
>>> result.json()
# List of 100 posts NOT DISPLAYED HERE
>>> result.json()[-1]
{'userId': 10, 'id': 100, 'title': 'at nam consequatur ea labore ea harum', 'body': 'cupiditate quo est a modi nesciunt soluta\nipsa voluptas error itaque dicta in\nautem qui minus magnam et distinctio eum\naccusamus ratione error aut'}
```

1.  创建一个新帖子。查看新创建资源的 URL。调用还返回资源：

```py
>>> new_post = {'userId': 10, 'title': 'a title', 'body': 'something something'}
>>> result = requests.post('https://jsonplaceholder.typicode.com/posts',
              json=new_post)
>>> result
<Response [201]>
>>> result.json()
{'userId': 10, 'title': 'a title', 'body': 'something something', 'id': 101}
>>> result.headers['Location']
'http://jsonplaceholder.typicode.com/posts/101'
```

注意，创建资源的`POST`请求返回 201，这是创建的适当状态。

1.  使用`GET`获取现有帖子：

```py
>>> result = requests.get('https://jsonplaceholder.typicode.com/posts/2')
>>> result
<Response [200]>
>>> result.json()
{'userId': 1, 'id': 2, 'title': 'qui est esse', 'body': 'est rerum tempore vitae\nsequi sint nihil reprehenderit dolor beatae ea dolores neque\nfugiat blanditiis voluptate porro vel nihil molestiae ut reiciendis\nqui aperiam non debitis possimus qui neque nisi nulla'}
```

1.  使用`PATCH`更新其值。检查返回的资源：

```py
>>> update = {'body': 'new body'}
>>> result = requests.patch('https://jsonplaceholder.typicode.com/posts/2', json=update)
>>> result
<Response [200]>
>>> result.json()
{'userId': 1, 'id': 2, 'title': 'qui est esse', 'body': 'new body'}
```

# 它是如何工作的...

通常访问两种资源。单个资源（`https://jsonplaceholder.typicode.com/posts/X`）和集合（`https://jsonplaceholder.typicode.com/posts`）：

+   集合接受`GET`以检索它们所有，并接受`POST`以创建新资源

+   单个元素接受`GET`以获取元素，`PUT`和`PATCH`以编辑，`DELETE`以删除它们

所有可用的 HTTP 方法都可以在`requests`中调用。在以前的配方中，我们使用了`.get()`，但`.post()`，`.patch()`，`.put()`和`.delete()`也可用。

返回的响应对象具有`.json()`方法，用于解码 JSON 结果。

同样，发送信息时，有一个`json`参数可用。这将字典编码为 JSON 并将其发送到服务器。数据需要遵循资源的格式，否则可能会引发错误。

`GET`和`DELETE`不需要数据，而`PATCH`、`PUT`和`POST`需要数据。

将返回所引用的资源，其 URL 在标头位置可用。这在创建新资源时非常有用，因为其 URL 事先是未知的。

`PATCH`和`PUT`之间的区别在于后者替换整个资源，而前者进行部分更新。

# 还有更多...

RESTful API 非常强大，但也具有巨大的可变性。请查看特定 API 的文档，了解其详细信息。

# 另请参阅

+   *下载网页*配方

+   第一章中的*安装第三方软件包*配方，*让我们开始我们的自动化之旅*

# 与表单交互

网页中常见的一个元素是表单。表单是将值发送到网页的一种方式，例如，在博客文章上创建新评论或提交购买。

浏览器呈现表单，以便您可以输入值并在按下提交或等效按钮后以单个操作发送它们。我们将在此配方中看到如何以编程方式创建此操作。

请注意，向网站发送数据通常比从网站接收数据更明智。例如，向网站发送自动评论非常符合**垃圾邮件**的定义。这意味着自动化和包含安全措施可能更加困难。请仔细检查您尝试实现的是否是有效的、符合道德的用例。

# 准备就绪

我们将针对测试服务器[`httpbin.org/forms/post`](https://httpbin.org/forms/post)进行操作，该服务器允许我们发送测试表单并返回提交的信息。

以下是一个订购比萨的示例表单：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/3fe93fc3-a5a2-450e-ba88-003566953c79.png)

您可以手动填写表单并查看它以 JSON 格式返回信息，包括浏览器使用等额外信息。

以下是生成的 Web 表单的前端：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/32f55d90-7967-4733-9b79-a3a6eca11557.png)

以下图像是生成的 Web 表单的后端：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/1f516fd0-d5de-484c-8875-9369cbe29b1b.png)

我们需要分析 HTML 以查看表单的接受数据。检查源代码，显示如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/a2f505fc-424b-47f5-a94f-93541d72e0b8.png)源代码

检查输入的名称，`custname`、`custtel`、`custemail`、`size`（单选按钮选项）、`topping`（多选复选框）、`delivery`（时间）和`comments`。

# 如何做...

1.  导入`requests`、`BeautifulSoup`和`re`模块：

```py
>>> import requests
>>> from bs4 import BeautifulSoup
>>> import re
```

1.  检索表单页面，解析它，并打印输入字段。检查发布 URL 是否为`/post`（而不是`/forms/post`）：

```py
>>> response = requests.get('https://httpbin.org/forms/post')
>>> page = BeautifulSoup(response.text)
>>> form = soup.find('form')
>>> {field.get('name') for field in form.find_all(re.compile('input|textarea'))}
{'delivery', 'topping', 'size', 'custemail', 'comments', 'custtel', 'custname'}
```

请注意，`textarea`是有效输入，也是在 HTML 格式中定义的。

1.  准备要发布的数据作为字典。检查值是否与表单中定义的相同：

```py
>>> data = {'custname': "Sean O'Connell", 'custtel': '123-456-789', 'custemail': 'sean@oconnell.ie', 'size': 'small', 'topping': ['bacon', 'onion'], 'delivery': '20:30', 'comments': ''}
```

1.  发布值并检查响应是否与浏览器中返回的相同：

```py
>>> response = requests.post('https://httpbin.org/post', data)
>>> response
<Response [200]>
>>> response.json()
{'args': {}, 'data': '', 'files': {}, 'form': {'comments': '', 'custemail': 'sean@oconnell.ie', 'custname': "Sean O'Connell", 'custtel': '123-456-789', 'delivery': '20:30', 'size': 'small', 'topping': ['bacon', 'onion']}, 'headers': {'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate', 'Connection': 'close', 'Content-Length':
```

```py
'140', 'Content-Type': 'application/x-www-form-urlencoded', 'Host': 'httpbin.org', 'User-Agent': 'python-requests/2.18.3'}, 'json': None, 'origin': '89.100.17.159', 'url': 'https://httpbin.org/post'}
```

# 它是如何工作的...

`requests`直接接受以正确方式发送数据。默认情况下，它以`application/x-www-form-urlencoded`格式发送`POST`数据。

将其与*访问 Web API*配方进行比较，其中数据是使用参数`json`以 JSON 格式明确发送的。这使得`Content-Type`为`application/json`而不是`application/x-www-form-urlencoded`。

这里的关键是尊重表单的格式和可能返回错误的可能值，通常是 400 错误。

# 还有更多...

除了遵循表单的格式和输入有效值之外，在处理表单时的主要问题是防止垃圾邮件和滥用行为的多种方式。

非常常见的限制是确保在提交表单之前下载了表单，以避免提交多个表单或**跨站点请求伪造**（**CSRF**）。

CSRF，意味着从一个页面对另一个页面发出恶意调用，利用您的浏览器已经经过身份验证，这是一个严重的问题。例如，进入一个利用您已经登录到银行页面执行操作的小狗网站。这是一个很好的描述：[`stackoverflow.com/a/33829607`](https://stackoverflow.com/a/33829607)。浏览器中的新技术默认情况下有助于解决这些问题。

要获取特定令牌，您需要首先下载表单，如配方中所示，获取 CSRF 令牌的值，并重新提交。请注意，令牌可以有不同的名称；这只是一个例子：

```py
>>> form.find(attrs={'name': 'token'}).get('value')
'ABCEDF12345'
```

# 另请参阅

+   *下载网页*的配方

+   *解析 HTML*的配方

# 使用 Selenium 进行高级交互

有时，除了真实的东西外，什么都行不通。 Selenium 是一个实现 Web 浏览器自动化的项目。它被构想为一种自动测试的方式，但也可以用于自动化与网站的交互。

Selenium 可以控制 Safari、Chrome、Firefox、Internet Explorer 或 Microsoft Edge，尽管它需要为每种情况安装特定的驱动程序。我们将使用 Chrome。

# 准备工作

我们需要为 Chrome 安装正确的驱动程序，称为`chromedriver`。它在这里可用：[`sites.google.com/a/chromium.org/chromedriver/`](https://sites.google.com/a/chromium.org/chromedriver/)。它适用于大多数平台。它还要求您已安装 Chrome：[`www.google.com/chrome/`](https://www.google.com/chrome/)。

将`selenium`模块添加到`requirements.txt`并安装它：

```py
$ echo "selenium==3.12.0" >> requirements.txt
$ pip install -r requirements.txt
```

# 如何做...

1.  导入 Selenium，启动浏览器，并加载表单页面。将打开一个反映操作的页面：

```py
>>> from selenium import webdriver
>>> browser = webdriver.Chrome()
>>> browser.get('https://httpbin.org/forms/post')
```

请注意，Chrome 中的横幅由自动化测试软件控制。

1.  在“客户名称”字段中添加一个值。请记住它被称为`custname`：

```py
>>> custname = browser.find_element_by_name("custname")
>>> custname.clear()
>>> custname.send_keys("Sean O'Connell")
```

表单将更新：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/13d8d74f-9f2e-4ef9-87e1-29deb1c70b95.png)

1.  选择披萨大小为`medium`：

```py
>>> for size_element in browser.find_elements_by_name("size"):
...     if size_element.get_attribute('value') == 'medium':
...         size_element.click()
...
>>>
```

这将改变披萨大小比例框。

1.  添加`bacon`和`cheese`：

```py
>>> for topping in browser.find_elements_by_name('topping'):
...     if topping.get_attribute('value') in ['bacon', 'cheese']:
...         topping.click()
...
>>>
```

最后，复选框将显示为已标记：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/789403c5-3c8f-4c14-b9c5-6318286ae9c1.png)

1.  提交表单。页面将提交，结果将显示：

```py
>>> browser.find_element_by_tag_name('form').submit()
```

表单将被提交，服务器的结果将显示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/b9063025-2521-4820-a446-90e9d89b4dbd.png)

1.  关闭浏览器：

```py
>>> browser.quit()
```

# 它是如何工作的...

*如何做...*部分的第 1 步显示了如何创建一个 Selenium 页面并转到特定的 URL。

Selenium 的工作方式与 Beautiful Soup 类似。选择适当的元素，然后操纵它。 Selenium 中的选择器的工作方式与 Beautiful Soup 中的选择器的工作方式类似，最常见的选择器是`find_element_by_id`、`find_element_by_class_name`、`find_element_by_name`、`find_element_by_tag_name`和`find_element_by_css_selector`。还有等效的`find_elements_by_X`，它们返回一个列表而不是第一个找到的元素（`find_elements_by_tag_name`、`find_elements_by_name`等）。当检查元素是否存在时，这也很有用。如果没有元素，`find_element`将引发错误，而`find_elements`将返回一个空列表。

可以通过`.get_attribute()`获取元素上的数据，用于 HTML 属性（例如表单元素上的值）或`.text`。

可以通过模拟发送按键输入文本来操作元素，方法是`.send_keys()`，点击是`.click()`，如果它们接受，可以使用`.submit()`进行提交。`.submit()`将在表单上搜索适当的提交，`.click()`将以与鼠标点击相同的方式选择/取消选择。

最后，第 6 步关闭浏览器。

# 还有更多...

这是完整的 Selenium 文档：[`selenium-python.readthedocs.io/`](http://selenium-python.readthedocs.io/)。

对于每个元素，都可以提取额外的信息，例如`.is_displayed()`或`.is_selected()`。可以使用`.find_element_by_link_text()`和`.find_element_by_partial_link_text()`来搜索文本。

有时，打开浏览器可能会不方便。另一种选择是以无头模式启动浏览器，并从那里操纵它，就像这样：

```py
>>> from selenium.webdriver.chrome.options import Options
>>> chrome_options = Options()
>>> chrome_options.add_argument("--headless")
>>> browser = webdriver.Chrome(chrome_options=chrome_options)
>>> browser.get('https://httpbin.org/forms/post')
```

页面不会显示。但是可以使用以下命令保存截图：

```py
>>> browser.save_screenshot('screenshot.png')
```

# 另请参阅

+   *解析 HTML*配方

+   *与表单交互*配方

# 访问受密码保护的页面

有时，网页对公众不开放，而是以某种方式受到保护。最基本的方面是使用基本的 HTTP 身份验证，它集成到几乎每个 Web 服务器中，并且是用户/密码模式。

# 准备就绪

我们可以在[`httpbin.org`](https://httpbin.org)中测试这种身份验证。

它有一个路径，`/basic-auth/{user}/{password}`，强制进行身份验证，用户和密码已声明。这对于理解身份验证的工作原理非常方便。

# 如何做...

1.  导入`requests`：

```py
>>> import requests
```

1.  使用错误的凭据对 URL 进行`GET`请求。注意，我们在 URL 上设置了凭据为`user`和`psswd`：

```py
>>> requests.get('https://httpbin.org/basic-auth/user/psswd', 
                 auth=('user', 'psswd'))
<Response [200]>
```

1.  使用错误的凭据返回 401 状态码（未经授权）：

```py
>>> requests.get('https://httpbin.org/basic-auth/user/psswd', 
                 auth=('user', 'wrong'))
<Response [401]>
```

1.  凭据也可以直接通过 URL 传递，在服务器之前用冒号和`@`符号分隔，就像这样：

```py
>>> requests.get('https://user:psswd@httpbin.org/basic-auth/user/psswd')
<Response [200]>
>>> requests.get('https://user:wrong@httpbin.org/basic-auth/user/psswd')
<Response [401]>
```

# 它的工作原理...

由于 HTTP 基本身份验证在各处都受支持，因此从“请求”获得支持非常容易。

*如何做...*部分的第 2 步和第 4 步显示了如何提供正确的密码。第 3 步显示了密码错误时会发生什么。

请记住始终使用 HTTPS，以确保密码的发送保密。如果使用 HTTP，密码将在网络上以明文发送。

# 还有更多...

将用户和密码添加到 URL 中也适用于浏览器。尝试直接访问页面，看到一个框显示要求输入用户名和密码：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/b0d91d6e-fa37-4084-82f1-d825d15441bc.png)用户凭据页面

在使用包含用户和密码的 URL 时，`https://user:psswd@httpbin.org/basic-auth/user/psswd`，对话框不会出现，它会自动进行身份验证。

如果您需要访问多个页面，可以在“请求”中创建一个会话，并将身份验证参数设置为避免在各处输入它们：

```py
>>> s = requests.Session()
>>> s.auth = ('user', 'psswd')
>>> s.get('https://httpbin.org/basic-auth/user/psswd')
<Response [200]>
```

# 另请参阅

+   *下载网页*配方

+   *访问 Web API*配方

# 加快网页抓取速度

从网页下载信息所花费的大部分时间通常是在等待。请求从我们的计算机发送到将处理它的任何服务器，直到响应被组成并返回到我们的计算机，我们无法做太多事情。

在书中执行配方时，您会注意到`requests`调用通常需要等待大约一两秒。但是计算机可以在等待时做其他事情，包括同时发出更多请求。在这个配方中，我们将看到如何并行下载页面列表并等待它们全部准备就绪。我们将使用一个故意缓慢的服务器来说明这一点。

# 准备就绪

我们将获得代码来爬取和搜索关键字，利用 Python 3 的`futures`功能同时下载多个页面。

`future`是表示值承诺的对象。这意味着在代码在后台执行时，您立即收到一个对象。只有在明确请求其`.result()`时，代码才会阻塞，直到获取它。

要生成一个`future`，你需要一个后台引擎，称为**executor**。一旦创建，`submit`一个函数和参数给它以检索一个`future`。结果的检索可以被延迟，直到需要，允许连续生成多个`futures`，并等待直到所有都完成，以并行执行它们，而不是创建一个，等待它完成，再创建另一个，依此类推。

有几种方法可以创建一个 executor；在这个示例中，我们将使用`ThreadPoolExecutor`，它将使用线程。

我们将以一个准备好的示例为例，该示例可在 GitHub 存储库中找到：[`github.com/PacktPublishing/Python-Automation-Cookbook/tree/master/Chapter03/test_site`](https://github.com/PacktPublishing/Python-Automation-Cookbook/tree/master/Chapter03/test_site)。下载整个站点并运行包含的脚本。

```py
$ python simple_delay_server.py -d 2
```

这是 URL 为`http://localhost:8000`的站点。你可以在浏览器上查看它。这是一个简单的博客，有三篇文章。大部分内容都不那么有趣，但我们添加了几段包含关键字`python`的段落。参数`-d 2`使服务器故意变慢，模拟一个糟糕的连接。

# 如何做...

1.  编写以下脚本`speed_up_step1.py`。完整的代码可以在 GitHub 的`Chapter03`目录下找到：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter03/speed_up_step1.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter03/speed_up_step1.py)。这里只列出了最相关的部分。它基于`crawling_web_step1.py`。

```py
...
def process_link(source_link, text):
    ...
    return source_link, get_links(parsed_source, page)
...

def main(base_url, to_search, workers):
    checked_links = set()
    to_check = [base_url]
    max_checks = 10

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        while to_check:
            futures = [executor.submit(process_link, url, to_search)
                       for url in to_check]
            to_check = []
            for data in concurrent.futures.as_completed(futures):
                link, new_links = data.result()

                checked_links.add(link)
                for link in new_links:
                    if link not in checked_links and link not in to_check:
                        to_check.append(link)

                max_checks -= 1
                if not max_checks:
                    return

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    ...
    parser.add_argument('-w', type=int, help='Number of workers',
                        default=4)
    args = parser.parse_args()

    main(args.u, args.p, args.w)
```

1.  请注意`main`函数中的差异。还添加了一个额外的参数（并发工作人员的数量），并且`process_link`函数现在返回源链接。

1.  运行`crawling_web_step1.py`脚本以获取时间基准。注意这里已经删除了输出以保持清晰：

```py
$ time python crawling_web_step1.py http://localhost:8000/
... REMOVED OUTPUT
real 0m12.221s
user 0m0.160s
sys 0m0.034s
```

1.  使用比原始版本慢的一个工作人员运行新脚本：

```py
$ time python speed_up_step1.py -w 1
... REMOVED OUTPUT
real 0m16.403s
user 0m0.181s
sys 0m0.068s
```

1.  增加工作人员的数量：

```py
$ time python speed_up_step1.py -w 2
... REMOVED OUTPUT
real 0m10.353s
user 0m0.199s
sys 0m0.068s
```

1.  增加更多的工作人员会减少时间。

```py
$ time python speed_up_step1.py -w 5
... REMOVED OUTPUT
real 0m6.234s
user 0m0.171s
sys 0m0.040s
```

# 它是如何工作的...

创建并发请求的主要引擎是主函数。请注意，代码的其余部分基本上没有改动（除了在`process_link`函数中返回源链接）。

这种变化在适应并发时实际上是相当常见的。并发任务需要返回所有相关的数据，因为它们不能依赖于有序的上下文。

这是处理并发引擎的代码的相关部分：

```py
with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
    while to_check:
        futures = [executor.submit(process_link, url, to_search)
                   for url in to_check]
        to_check = []
        for data in concurrent.futures.as_completed(futures):
            link, new_links = data.result()

            checked_links.add(link)
            for link in new_links:
                if link not in checked_links and link not in to_check:
                    to_check.append(link)

             max_checks -= 1
             if not max_checks:
                return
```

`with`上下文创建了一个指定数量的工作人员池。在内部，创建了一个包含所有要检索的 URL 的`futures`列表。`.as_completed()`函数返回已完成的`futures`，然后进行一些工作，处理获取到的新链接，并检查它们是否需要被添加到检索中。这个过程类似于*Crawling the web*示例中呈现的过程。

该过程会再次开始，直到检索到足够的链接或没有链接可检索为止。请注意，链接是批量检索的；第一次，处理基本链接并检索所有链接。在第二次迭代中，将请求所有这些链接。一旦它们都被下载，将处理一个新的批次。

处理并发请求时，请记住它们可以在两次执行之间改变顺序。如果一个请求花费的时间稍微多一点或少一点，那可能会影响检索信息的顺序。因为我们在下载 10 页后停止，这也意味着这 10 页可能是不同的。

# 还有更多...

Python 的完整`futures`文档可以在这里找到：[`docs.python.org/3/library/concurrent.futures.html`](https://docs.python.org/3/library/concurrent.futures.html)。

正如您在*如何做…*部分的第 4 和第 5 步中所看到的，正确确定工作人员的数量可能需要一些测试。一些数字可能会使过程变慢，因为管理增加了。不要害怕尝试！

在 Python 世界中，还有其他方法可以进行并发的 HTTP 请求。有一个原生请求模块，允许我们使用`futures`，名为`requests-futures`。它可以在这里找到：[`github.com/ross/requests-futures`](https://github.com/ross/requests-futures)。

另一种选择是使用异步编程。最近，这种工作方式引起了很多关注，因为在处理许多并发调用时可以非常高效，但编码的方式与传统方式不同，需要一些时间来适应。Python 包括`asyncio`模块来进行这种工作，还有一个名为`aiohttp`的好模块来处理 HTTP 请求。您可以在这里找到有关`aiohttp`的更多信息：[`aiohttp.readthedocs.io/en/stable/client_quickstart.html`](https://aiohttp.readthedocs.io/en/stable/client_quickstart.html)。

关于异步编程的良好介绍可以在这篇文章中找到：[`djangostars.com/blog/asynchronous-programming-in-python-asyncio/`](https://djangostars.com/blog/asynchronous-programming-in-python-asyncio/)。

# 另请参阅

+   *爬取网页*配方

+   *下载网页*配方


# 第四章：搜索和阅读本地文件

在本章中，我们将涵盖以下食谱：

+   爬取和搜索目录

+   阅读文本文件

+   处理编码

+   阅读 CSV 文件

+   阅读日志文件

+   阅读文件元数据

+   阅读图像

+   阅读 PDF 文件

+   阅读 Word 文档

+   扫描文档以查找关键字

# 介绍

在本章中，我们将处理读取文件的基本操作，从搜索和打开目录和子目录中的文件开始。然后，我们将描述一些最常见的文件类型以及如何读取它们，包括原始文本文件、PDF 和 Word 文档等格式。

最后一个食谱将把它们全部结合起来，展示如何在目录中递归搜索不同类型的文件中的单词。

# 爬取和搜索目录

在本食谱中，我们将学习如何*递归*扫描目录以获取其中包含的所有文件。文件可以是特定类型的，也可以是所有类型的。

# 准备工作

让我们从创建一个带有一些文件信息的测试目录开始：

```py
$ mkdir dir
$ touch dir/file1.txt
$ touch dir/file2.txt
$ mkdir dir/subdir
$ touch dir/subdir/file3.txt
$ touch dir/subdir/file4.txt
$ touch dir/subdir/file5.pdf
$ touch dir/file6.pdf
```

所有文件都将是空的；我们只会在本食谱中使用它们来发现它们。请注意，有四个文件的扩展名是`.txt`，另外两个文件的扩展名是`.pdf`。

这些文件也可以在 GitHub 存储库中找到：[`github.com/PacktPublishing/Python-Automation-Cookbook/tree/master/Chapter04/documents/dir`](https://github.com/PacktPublishing/Python-Automation-Cookbook/tree/master/Chapter04/documents/dir)。

进入创建的`dir`目录：

```py
$ cd dir
```

# 操作步骤...

1.  打印`dir`目录和子目录中的所有文件名：

```py
>>> import os
>>> for root, dirs, files in os.walk('.'):
...     for file in files:
...         print(file)
...
file1.txt
file2.txt
file6.pdf
file3.txt
file4.txt
file5.pdf
```

1.  打印文件的完整路径，与`root`连接：

```py
>>> for root, dirs, files in os.walk('.'):
...     for file in files:
...         full_file_path = os.path.join(root, file)
...         print(full_file_path)
...
./dir/file1.txt
./dir/file2.txt
./dir/file6.pdf
./dir/subdir/file3.txt
./dir/subdir/file4.txt
./dir/subdir/file5.pdf
```

1.  仅打印`.pdf`文件：

```py
>>> for root, dirs, files in os.walk('.'):
...     for file in files:
...         if file.endswith('.pdf'):
...             full_file_path = os.path.join(root, file)
...             print(full_file_path)
...
./dir/file6.pdf
./dir/subdir/file5.pdf
```

1.  仅打印包含偶数的文件：

```py
>>> import re
>>> for root, dirs, files in os.walk('.'):
...     for file in files:
...         if re.search(r'[13579]', file):
...             full_file_path = os.path.join(root, file)
...             print(full_file_path)
...
./dir/file1.txt
./dir/subdir/file3.txt
./dir/subdir/file5.pdf
```

# 工作原理...

`os.walk()`遍历整个目录和所有子目录，返回所有文件。它返回一个元组，其中包含特定目录、直接依赖的子目录和所有文件：

```py
>>> for root, dirs, files in os.walk('.'):
... print(root, dirs, files)
...
. ['dir'] []
./dir ['subdir'] ['file1.txt', 'file2.txt', 'file6.pdf']
./dir/subdir [] ['file3.txt', 'file4.txt', 'file5.pdf']
```

`os.path.join()`函数允许我们清晰地连接两个路径，比如基本路径和文件。

由于文件以纯字符串形式返回，因此可以进行任何类型的过滤，就像第 3 步那样。在第 4 步中，可以使用正则表达式的全部功能进行过滤。

在下一个食谱中，我们将处理文件的内容，而不仅仅是文件名。

# 还有更多...

返回的文件不会以任何方式打开或修改。此操作是只读的。文件可以像平常一样打开，并且可以像下面的食谱中描述的那样进行操作。

请注意，在遍历目录时更改目录的结构可能会影响结果。如果需要在工作时存储任何文件，例如复制或移动文件时，通常最好将其存储在不同的目录中。

`os.path`模块还有其他有趣的函数。除了`join()`之外，最有用的可能是：

+   `os.path.abspath()`，返回文件的绝对路径

+   `os.path.split()`，用于在目录和文件之间拆分路径：

```py
>>> os.path.split('/a/very/long/path/file.txt')
('/a/very/long/path', 'file.txt')
```

+   `os.path.exists()`，用于返回文件在文件系统上是否存在

有关`os.path`的完整文档可以在这里找到：[`docs.python.org/3/library/os.path.html`](https://docs.python.org/3/library/os.path.html)。另一个模块`pathlib`可以用于以面向对象的方式进行更高级别的访问：[`docs.python.org/3/library/pathlib.html`](https://docs.python.org/3/library/pathlib.html)。

如第 4 步所示，可以使用多种过滤方式。在第一章中展示的所有字符串操作，*让我们开始自动化之旅*都可以使用。

# 另请参阅

+   第一章中的*介绍正则表达式*食谱，*让我们开始自动化之旅*

+   *阅读文本文件*食谱

# 阅读文本文件

在搜索特定文件之后，我们可能会打开并阅读它。文本文件非常简单，但非常强大。它们以纯文本形式存储数据，而不是复杂的二进制格式。

Python 本身提供了对文本文件的支持，并且很容易将其视为一系列行。

# 准备工作

我们将阅读包含 Tim Peters 的*Python 之禅*的`zen_of_python.txt`文件，这是一系列很好地描述了 Python 设计原则的格言。它在 GitHub 存储库中可用：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/documents/zen_of_python.txt`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/documents/zen_of_python.txt)：

```py
Beautiful is better than ugly.
Explicit is better than implicit.
Simple is better than complex.
Complex is better than complicated.
Flat is better than nested.
Sparse is better than dense.
Readability counts.
Special cases aren't special enough to break the rules.
Although practicality beats purity.
Errors should never pass silently.
Unless explicitly silenced.
In the face of ambiguity, refuse the temptation to guess.
There should be one-- and preferably only one --obvious way to do it.
Although that way may not be obvious at first unless you're Dutch.
Now is better than never.
Although never is often better than *right* now.
If the implementation is hard to explain, it's a bad idea.
If the implementation is easy to explain, it may be a good idea.
Namespaces are one honking great idea -- let's do more of those!
```

*Python 之禅*在 PEP-20 中描述：[`www.python.org/dev/peps/pep-0020/`](https://www.python.org/dev/peps/pep-0020/)。

*Python 之禅*可以通过调用`import this`在任何 Python 解释器中显示。

# 如何做...

1.  打开并打印整个文件，逐行（结果不显示）：

```py
>>> with open('zen_of_python.txt') as file:
...     for line in file:
...         print(line)
...
[RESULT NOT DISPLAYED]
```

1.  打开文件并打印包含字符串`should`的任何行：

```py
>>> with open('zen_of_python.txt', 'r') as file:
...     for line in file:
...         if 'should' in line.lower():
...             print(line)
...
Errors should never pass silently.
There should be one-- and preferably only one --obvious way to do it.
```

1.  打开文件并打印包含单词`better`的第一行：

```py
>>> with open('zen_of_python.txt', 'rt') as file:
...     for line in file:
...         if 'better' in line.lower():
...             print(line)
...             break
...
Beautiful is better than ugly.
```

# 它是如何工作的...

要以文本模式打开文件，请使用`open()`函数。这将返回一个`file`对象，然后可以迭代返回每一行，如*如何做...*部分的步骤 1 所示。

`with`上下文管理器是处理文件的非常方便的方式，因为它在完成使用后会关闭它们（离开块）。即使出现异常，它也会这样做。

步骤 2 显示了如何迭代和过滤基于哪些行适用于我们的任务。这些行作为字符串返回，可以以多种方式进行过滤，如前面所述。

可能不需要读取整个文件，如步骤 3 所示。因为逐行迭代文件将在读取文件时进行，您可以随时停止，避免读取文件的其余部分。对于像我们的示例这样的小文件来说，这并不是很重要，但对于长文件来说，这可以减少内存使用和时间。

# 还有更多...

`with`上下文管理器是处理文件的首选方式，但不是唯一的方式。您也可以像这样手动打开和关闭它们：

```py
>>> file = open('zen_of_python')
>>> content = file.read()
>>> file.close()
```

请注意`.close()`方法，以确保文件已关闭并释放与打开文件相关的资源。`.read()`方法一次读取整个文件，而不是逐行读取。

`.read()`方法还接受以字节为单位的大小参数，限制读取的数据大小。例如，`file.read(1024)`将返回最多 1KB 的信息。下一次调用`.read()`将从那一点继续。

文件以特定模式打开。模式定义了读/写以及文本或二进制数据的组合。默认情况下，文件以只读和文本模式打开，描述为`'r'`（步骤 2）或`'rt'`（步骤 3）。

其他配方将探讨更多模式。

# 另请参阅

+   *爬取和搜索目录*配方

+   *处理编码*配方

# 处理编码

文本文件可以以不同的编码形式存在。近年来，情况有了很大改善，但在处理不同系统时仍然存在兼容性问题。

文件中的原始数据和 Python 中的字符串对象之间存在差异。字符串对象已从文件包含的任何编码转换为本机字符串。一旦以这种格式存在，可能需要以不同的编码进行存储。默认情况下，Python 使用操作系统定义的编码，在现代操作系统中为 UTF-8。这是一种高度兼容的编码，但您可能需要以不同的编码保存文件。

# 准备工作

我们在 GitHub 存储库中准备了两个文件，这两个文件以两种不同的编码存储字符串`20£`。一个是通常的 UTF8，另一个是 ISO 8859-1，另一种常见的编码。这些文件可以在 GitHub 的`Chapter04/documents`目录下找到，文件名分别是`example_iso.txt`和`example_utf8.txt`：

[`github.com/PacktPublishing/Python-Automation-Cookbook`](https://github.com/PacktPublishing/Python-Automation-Cookbook)

我们将使用 Beautiful Soup 模块，该模块在第三章中的*解析 HTML*食谱中介绍，*构建您的第一个网络爬虫应用程序*。

# 操作步骤...

1.  打开`example_utf8.txt`文件并显示其内容：

```py
>>> with open('example_utf8.txt') as file:
...     print(file.read())
...
20£
```

1.  尝试打开`example_iso.txt`文件，这将引发异常：

```py
>>> with open('example_iso.txt') as file:
... print(file.read())
...
Traceback (most recent call last):
  ...
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xa3 in position 2: invalid start byte
```

1.  以正确的编码打开`example_iso.txt`文件：

```py
>>> with open('example_iso.txt', 
              encoding='iso-8859-1') as file:
...     print(file.read())
...
20£
```

1.  打开`utf8`文件并将其内容保存在`iso-8859-1`文件中：

```py
>>> with open('example_utf8.txt') as file:
...     content = file.read()
>>> with open('example_output_iso.txt', 'w',
               encoding='iso-8859-1') as file:
...     file.write(content)
...
4
```

1.  最后，从新文件中以正确的格式读取，以确保它已正确保存：

```py
>>> with open('example_output_iso.txt', 
              encoding='iso-8859-1') as file:
...     print(file.read())
...
20£
```

# 工作原理...

*操作步骤...*部分的步骤 1 和 2 非常简单。在第 3 步中，我们添加了一个额外的参数`encoding`，以指定文件需要以与 UTF-8 不同的方式打开。

Python 可以直接接受很多标准编码。在这里检查所有标准编码及其别名：[`docs.python.org/3/library/codecs.html#standard-encodings`](https://docs.python.org/3/library/codecs.html#standard-encodings)。

在第 4 步中，我们创建一个新的 ISO-8859-1 文件，并像往常一样写入。注意`'w'`参数，它指定以文本模式打开文件进行写入。

步骤 5 是确认文件已正确保存。

# 还有更多...

这个食谱假设我们知道文件的编码。但有时我们不确定。Beautiful Soup，一个用于解析 HTML 的模块，可以尝试检测特定文件的编码。

自动检测文件的编码可能是不可能的，因为潜在的编码可能有无限多种。但我们将检查通常的编码，应该可以覆盖 90%的真实情况。只需记住，确切知道的最简单方法是询问创建文件的人。

为此，我们需要以`'rb'`参数以二进制格式打开文件进行读取，然后将二进制内容传递给 Beautiful Soup 的`UnicodeDammit`模块，如下所示：

```py
>>> from bs4 import UnicodeDammit
>>> with open('example_output_iso.txt', 'rb') as file:
...     content = file.read()
...
>>> suggestion = UnicodeDammit(content)
>>> suggestion.original_encoding
'iso-8859-1'
>>> suggestion.unicode_markup
'20£\n'
```

然后可以推断出编码。虽然`.unicode_markup`返回解码后的字符串，但最好只使用这个建议一次，然后以正确的编码打开文件进行自动化任务。

# 另请参阅

+   第一章中的*操作字符串*食谱，*让我们开始我们的自动化之旅*

+   第三章中的*解析 HTML*食谱，*构建您的第一个网络爬虫应用程序*

# 读取 CSV 文件

一些文本文件包含用逗号分隔的表格数据。这是一种方便的创建结构化数据的方式，而不是使用专有的、更复杂的格式，如 Excel 或其他格式。这些文件称为**逗号分隔值**，或**CSV**文件，大多数电子表格软件也可以导出到它。

# 准备工作

我们使用了这个页面描述的 10 部票房电影的数据制作了一个 CSV 文件：[`www.mrob.com/pub/film-video/topadj.html`](http://www.mrob.com/pub/film-video/topadj.html)。

我们将表格的前十个元素复制到电子表格程序（Numbers）中，并将文件导出为 CSV。该文件可以在 GitHub 存储库的`Chapter04/documents`目录中找到，文件名为`top_films.csv`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/167bb0f1-03c9-4a8f-80af-8faa051e79c5.png)

# 操作步骤...

1.  导入`csv`模块：

```py
>>> import csv
```

1.  打开文件，创建读取器，并迭代显示所有行的表格数据（仅显示了三行）：

```py
>>> with open('top_films.csv') as file:
...   data = csv.reader(file)
...   for row in data:
...       print(row)
...
['Rank', 'Admissions\n(millions)', 'Title (year) (studio)', 'Director(s)']
['1', '225.7', 'Gone With the Wind (1939)\xa0(MGM)', 'Victor Fleming, George Cukor, Sam Wood']
['2', '194.4', 'Star Wars (Ep. IV: A New Hope) (1977)\xa0(Fox)', 'George Lucas']
...
['10', '118.9', 'The Lion King (1994)\xa0(BV)', 'Roger Allers, Rob Minkoff']
```

1.  打开文件并使用`DictReader`来构造数据，包括标题：

```py
>>> with open('top_films.csv') as file:
...     data = csv.DictReader(file)
...     structured_data = [row for row in data]
...
>>> structured_data[0]
OrderedDict([('Rank', '1'), ('Admissions\n(millions)', '225.7'), ('Title (year) (studio)', 'Gone With the Wind (1939)\xa0(MGM)'), ('Director(s)', 'Victor Fleming, George Cukor, Sam Wood')])
```

1.  `structured_data`中的每个项目都是一个包含所有值的完整字典：

```py
>>> structured_data[0].keys()
odict_keys(['Rank', 'Admissions\n(millions)', 'Title (year) (studio)', 'Director(s)'])
>>> structured_data[0]['Rank']
'1'
>>> structured_data[0]['Director(s)']
'Victor Fleming, George Cukor, Sam Wood'
```

# 工作原理...

请注意，需要读取文件，并且我们使用`with`上下文管理器。这确保了文件在块结束时关闭。

如*如何做*部分的第 2 步所示，`csv.reader`类允许我们通过将它们细分为列表来结构化返回的代码行，遵循表格数据的格式。请注意，所有值都被描述为字符串。`csv.reader`无法理解第一行是否是标题。

为了更结构化地读取文件，在第 3 步中我们使用`csv.DictReader`，它默认将第一行读取为一个标题，定义后面描述的字段，然后将每一行转换为包含这些字段的字典。

有时，就像在这种情况下一样，文件中描述的字段名称可能有点冗长。不要害怕将字典翻译成更易管理的字段名称。

# 还有更多...

由于 CSV 是一个非常宽泛的解释，数据可以以几种方式存储。这在`csv`模块中表示为**方言**。例如，值可以由逗号、分号或制表符分隔。可以通过调用`csv.list_dialect`来显示默认接受的方言列表。

默认情况下，方言将是 Excel，这是最常见的方言。即使其他电子表格也通常会使用它。

但是，方言也可以通过`Sniffer`类从文件本身推断出来。`Sniffer`类分析文件的样本（或整个文件）并返回一个`dialect`对象，以允许以正确的方式进行读取。

请注意，文件是没有换行符打开的，因此不要对其进行任何假设：

```py
>>> with open('top_films.csv', newline='') as file:
...    dialect = csv.Sniffer().sniff(file.read())
```

然后可以在打开读取器时使用方言。再次注意`newline`，因为方言将正确地拆分行：

```py
>>> with open('top_films.csv', newline='') as file:
...     reader = csv.reader(file, dialect)
...     for row in reader:
...         print(row)
```

完整的`csv`模块文档可以在这里找到：[`docs.python.org/3.6/library/csv.html`](https://docs.python.org/3.6/library/csv.html)。

# 另请参阅

+   *处理编码*配方

+   *读取文本文件*配方

# 读取日志文件

另一种常见的结构化文本文件格式是**日志文件**。日志文件由一行行的日志组成，每行都有特定格式的文本。通常，每个日志都会有发生时间，因此文件是事件的有序集合。

# 准备工作

可以从 GitHub 存储库获取包含五个销售日志的`example_log.log`文件：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/documents/example_logs.log`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/documents/example_logs.log)。

格式如下：

```py
[<Timestamp in iso format>] - SALE - PRODUCT: <product id> - PRICE: $<price of the sale>
```

我们将使用`Chapter01/price_log.py`文件来将每个日志处理为一个对象。

# 如何做...

1.  导入`PriceLog`：

```py
>>> from price_log import PriceLog
```

1.  打开日志文件并解析所有日志：

```py
>>> with open('example_logs.log') as file:
...     logs = [PriceLog.parse(log) for log in file]
...
>>> len(logs)
5
>>> logs[0]
<PriceLog (Delorean(datetime=datetime.datetime(2018, 6, 17, 22, 11, 50, 268396), timezone='UTC'), 1489, 9.99)>
```

1.  确定所有销售的总收入：

```py
>>> total = sum(log.price for log in logs)
>>> total
Decimal('47.82')
```

1.  确定每个`product_id`已售出多少个单位：

```py
>>> from collections import Counter
>>> counter = Counter(log.product_id for log in logs)
>>> counter
Counter({1489: 2, 4508: 1, 8597: 1, 3086: 1})
```

1.  过滤日志，找到所有销售产品 ID 为`1489`的事件：

```py
>>> logs = []
>>> with open('example_logs.log') as file:
...     for log in file:
...         plog = PriceLog.parse(log)
...         if plog.product_id == 1489:
...             logs.append(plog)
...
>> len(logs)
2
>>> logs[0].product_id, logs[0].timestamp
(1489, Delorean(datetime=datetime.datetime(2018, 6, 17, 22, 11, 50, 268396), timezone='UTC'))
>>> logs[1].product_id, logs[1].timestamp
(1489, Delorean(datetime=datetime.datetime(2018, 6, 17, 22, 11, 50, 268468), timezone='UTC'))
```

# 工作原理...

由于每个日志都是单独的一行，我们逐个打开文件并解析每个日志。解析代码在`price_log.py`中可用。查看它以获取更多细节。

在*如何做*部分的第 2 步中，我们打开文件并处理每一行，以创建包含所有已处理日志的日志列表。然后，我们可以进行聚合操作，就像下一步一样。

第 3 步显示了如何聚合所有值，例如对文件日志中出售的所有商品的价格进行求和，以获得总收入。

第 4 步使用 Counter 来确定文件日志中每个项目的数量。这将返回一个类似字典的对象，其中包含要计数的值以及它们出现的次数。

过滤也可以逐行进行，就像第 5 步中所示的那样。这类似于本章中其他配方中的过滤。

# 还有更多...

请记住，一旦获得所需的所有数据，就可以立即停止处理文件。如果文件非常大，通常情况下是日志文件的情况，这可能是一个很好的策略。

Counter 是一个快速计算列表的好工具。有关更多详细信息，请参阅 Python 文档：[`docs.python.org/2/library/collections.html#counter-objects`](https://docs.python.org/2/library/collections.html#counter-objects)。您可以通过调用以下方式获取有序项目：

```py
>>> counter.most_common()
[(1489, 2), (4508, 1), (8597, 1), (3086, 1)]
```

# 另请参阅

+   第一章中的*使用第三方工具—parse*食谱，*让我们开始自动化之旅*

+   *读取文本文件*食谱

# 读取文件元数据

文件元数据是与特定文件相关的除数据本身之外的所有内容。这意味着参数，如文件的大小、创建日期或其权限。

浏览这些数据很重要，例如，要筛选早于某个日期的文件，或查找所有大于某个 KB 值的文件。在本食谱中，我们将看到如何在 Python 中访问文件元数据。

# 准备工作

我们将使用 GitHub 存储库中的`zen_of_python.txt`文件（[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/documents/zen_of_python.txt`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/documents/zen_of_python.txt)）。通过使用`ls`命令，您可以看到该文件有`856`字节，并且在此示例中，它是在 6 月 14 日创建的：

```py
$ ls -lrt zen_of_python.txt
-rw-r--r--@ 1 jaime staff 856 14 Jun 21:22 zen_of_python.txt
```

在您的计算机上，日期可能会有所不同，这取决于您下载代码的时间。

# 如何做…

1.  导入`os`和`datetime`：

```py
>>> import os
>>> from datetime import datetime
```

1.  检索`zen_of_python.txt`文件的统计信息：

```py
>>> stats = os.stat(('zen_of_python.txt')
>>> stats
os.stat_result(st_mode=33188, st_ino=15822537, st_dev=16777224, st_nlink=1, st_uid=501, st_gid=20, st_size=856, st_atime=1529461935, st_mtime=1529007749, st_ctime=1529007757)
```

1.  获取文件的大小，以字节为单位：

```py
>>> stats.st_size
856
```

1.  获取文件上次修改的时间：

```py
>>> datetime.fromtimestamp(stats.st_mtime)
datetime.datetime(2018, 6, 14, 21, 22, 29)
```

1.  获取文件上次访问的时间：

```py
>>> datetime.fromtimestamp(stats.st_atime)
datetime.datetime(2018, 6, 20, 3, 32, 15)
```

# 它是如何工作的…

`os.stats`返回一个表示文件系统中存储的元数据的 stats 对象。元数据包括：

+   文件的大小，以字节为单位，如*如何做…*部分中的步骤 3 所示，使用`st_size`

+   文件内容上次修改的时间，如步骤 4 所示，使用`st_mtime`

+   文件上次读取（访问）的时间，如步骤 5 所示，使用`st_atime`

时间以时间戳形式返回，因此在步骤 4 和 5 中，我们从时间戳创建一个`datetime`对象，以更好地访问数据。

所有这些值都可以用来过滤文件。

请注意，您无需使用`open()`打开文件以读取其元数据。检测文件是否在已知值之后已更改将比比较其内容更快，因此您可以利用这一点进行比较。

# 还有更多…

要逐个获取统计信息，还有`os.path`中可用的便利函数，其遵循模式`get<value>`：

```py
>>> os.path.getsize('zen_of_python.txt')
856
>>> os.path.getmtime('zen_of_python.txt')
1529531584.0
>>> os.path.getatime('zen_of_python.txt')
1529531669.0
```

该值以 UNIX 时间戳格式指定（自 1970 年 1 月 1 日以来的秒数）。

请注意，调用这三个函数的速度将比调用`os.stats`和处理结果要慢。此外，返回的`stats`可以被检查以检测可用的值。

该食谱中描述的数值适用于所有文件系统，但还有更多可以使用的数值。

例如，要获取文件的创建日期，可以在 MacOS 中使用`st_birthtime`参数，或在 Windows 中使用`st_mtime`。

`st_mtime`始终可用，但其含义在不同系统之间会有所不同。在 Unix 系统中，当内容被修改时，它会发生变化，因此它不是一个可靠的创建时间。

`os.stat`将遵循符号链接。如果要获取符号链接的统计信息，请使用`os.lstat()`。

查看所有可用统计信息的完整文档：[`docs.python.org/3.6/library/os.html#os.stat_result`](https://docs.python.org/3.6/library/os.html#os.stat_result)。

# 另请参阅

+   *读取文本文件*食谱

+   *读取图像*食谱

# 读取图像

可能最常见的非文本数据是图像数据。图像有自己一套特定的元数据，可以读取以筛选值或执行其他操作。

主要挑战是处理多种格式和不同的元数据定义。在本示例中，我们将展示如何从 JPEG 和 PNG 中获取信息，以及相同的信息如何以不同的方式编码。

# 准备工作

处理 Python 中图像的最佳通用工具可能是 Pillow。该模块允许您轻松读取最常见格式的文件，并对其进行操作。Pillow 最初是**PIL**（**Python Imaging Library**）的一个分支，几年前成为停滞不前的模块。

我们还将使用`xmltodict`模块将一些 XML 数据转换为更方便的字典。将这两个模块添加到`requirements.txt`中，并重新安装到虚拟环境中：

```py
$ echo "Pillow==5.1.0" >> requirements.txt
$ echo "xmltodict==0.11.0" >> requirements.txt
$ pip install -r requirements.txt
```

照片文件中的元数据信息是以**EXIF**（**Exchangeable Image File**）格式定义的。EXIF 是一种存储有关照片信息的标准，包括拍摄照片的相机、拍摄时间、GPS 位置、曝光、焦距、颜色信息等。

您可以在此处获取更多信息：[`www.slrphotographyguide.com/what-is-exif-metadata/`](https://www.slrphotographyguide.com/what-is-exif-metadata/)。所有信息都是可选的，但几乎所有数字相机和处理软件都会存储一些数据。由于隐私问题，其中的部分信息，如确切位置，可以被禁用。

以下图像将用于此示例，并可在 GiHub 存储库中下载（[`github.com/PacktPublishing/Python-Automation-Cookbook/tree/master/Chapter04/images`](https://github.com/PacktPublishing/Python-Automation-Cookbook/tree/master/Chapter04/images)）：

+   `photo-dublin-a1.jpg`

+   `photo-dublin-a2.png`

+   `photo-dublin-b.png`

其中两张照片，`photo-dublin-a1.jpg`和`photo-dublin-a2.png`，是同一张照片，但第一张是原始照片，而第二张经过了轻微的颜色变化和裁剪。请注意，一张是 JPEG 格式，另一张是 PNG 格式。另一张照片，`photo-dublin-b.png`，是一张不同的照片。这两张照片是在都柏林用同一部手机相机拍摄的，分别在两天拍摄。

虽然 Pillow 可以直接理解 JPG 文件存储的 EXIF 信息，但 PNG 文件存储 XMP 信息，这是一种更通用的标准，可以包含 EXIF 信息。

可以在此处获取有关 XMP 的更多信息：[`www.adobe.com/devnet/xmp.html`](https://www.adobe.com/devnet/xmp.html)。在很大程度上，它定义了一个相对易于阅读的 XML 树结构。

更进一步复杂化的是，XMP 是 RDF 的一个子集，RDF 是一种描述信息编码方式的标准。

如果 EFIX、XMP 和 RDF 听起来令人困惑，那是因为它们确实如此。最终，它们只是用来存储我们感兴趣的值的名称。我们可以使用 Python 内省工具检查名称的具体信息，确切地查看数据的结构以及我们要查找的参数名称。

由于 GPS 信息以不同的格式存储，我们在 GitHub 存储库中包含了一个名为`gps_conversion.py`的文件，位于此处：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/gps_conversion.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/gps_conversion.py)。其中包括`exif_to_decimal`和`rdf_to_decimal`函数，它们将两种格式转换为十进制以进行比较。

# 如何做...

1.  导入要在此示例中使用的模块和函数：

```py
>>> from PIL import Image
>>> from PIL.ExifTags import TAGS, GPSTAGS
>>> import xmltodict
>>> from gps_conversion import exif_to_decimal, rdf_to_decimal
```

1.  打开第一张照片：

```py
>>> image1 = Image.open('photo-dublin-a1.jpg')
```

1.  获取文件的宽度、高度和格式：

```py
>>> image1.height
3024
>>> image1.width
4032
>>> image1.format
'JPEG'
```

1.  检索图像的 EXIF 信息，并处理为方便的字典。显示相机、使用的镜头以及拍摄时间：

```py
>>> exif_info_1 = {TAGS.get(tag, tag): value 
                   for tag, value in image1._getexif().items()}
>>> exif_info_1['Model']
'iPhone X'
>>> exif_info_1['LensModel']
'iPhone X back dual camera 4mm f/1.8'
>>> exif_info_1['DateTimeOriginal']
'2018:04:21 12:07:55'
```

1.  打开第二张图像并获取 XMP 信息：

```py
>>> image2 = Image.open('photo-dublin-a2.png')
>>> image2.height
2630
>>> image2.width
3943
>>> image2.format
'PNG'
>>> xmp_info = xmltodict.parse(image2.info['XML:com.adobe.xmp'])
```

1.  获取包含我们正在寻找的所有值的 RDF 描述字段。检索模型（TIFF 值）、镜头模型（EXIF 值）和创建日期（XMP 值）。检查这些值是否与第 4 步中的相同，即使文件不同：

```py
>>> rdf_info_2 = xmp_info['x:xmpmeta']['rdf:RDF']['rdf:Description']
>>> rdf_info_2['tiff:Model']
'iPhone X'
>>> rdf_info_2['exifEX:LensModel']
'iPhone X back dual camera 4mm f/1.8'
>>> rdf_info_2['xmp:CreateDate']
'2018-04-21T12:07:55'
```

1.  获取两张图片中的 GPS 信息，转换为等效格式，并检查它们是否相同。请注意，分辨率不同，但它们匹配到第四位小数：

```py
>>> gps_info_1 = {GPSTAGS.get(tag, tag): value 
                  for tag, value in exif_info_1['GPSInfo'].items()}
>>> exif_to_decimal(gps_info_1)
('N53.34690555555556', 'W6.247797222222222')
>>> rdf_to_decimal(rdf_info_2)
('N53.346905', 'W6.247796666666667')
```

1.  打开第三张图片，获取创建日期和 GPS 信息，并检查它与另一张照片不匹配，尽管它很接近（第二和第三位小数不相同）：

```py
>>> image3 = Image.open('photo-dublin-b.png')
>>> xmp_info = xmltodict.parse(image3.info['XML:com.adobe.xmp'])
>>> rdf_info_3 = xmp_info['x:xmpmeta']['rdf:RDF']['rdf:Description']
>>> rdf_info_3['xmp:CreateDate']
'2018-03-08T18:16:57'
>>> rdf_to_decimal(rdf_info_3)
('N53.34984166666667', 'W6.260388333333333')
```

# 工作原理...

Pillow 能够解释大多数常见语言的文件，并将它们以 JPG 格式的图像打开，就像在*如何做…*部分的第 2 步中所示。

`Image`对象包含有关文件大小和格式的基本信息，并在第 3 步中显示。 `info`属性包含取决于格式的信息。

JPG 文件的 EXIF 元数据可以使用`._getexif()`方法进行解析，但随后需要正确翻译，因为它使用原始二进制定义。例如，数字 42,036 对应于`LensModel`属性。幸运的是，`PIL.ExifTags`模块中有所有标签的定义。我们在第 4 步中将字典翻译为可读标签，以获得更可读的字典。

第 5 步打开了 PNG 格式，其与大小相关的属性相同，但元数据存储在 XML/RDF 格式中，并且需要借助“xmltodict”进行解析。第 6 步展示了如何导航此元数据以提取与 JPG 格式中相同的信息。数据是相同的，因为这两个文件来自同一原始图片，即使图片不同。

`xmltodict`在尝试解析非 XML 格式的数据时会出现一些问题。请检查输入是否为有效的 XML。

第 7 步提取了两张图片的 GPS 信息，这些信息以不同的方式存储，并显示它们是相同的（尽管由于编码方式不同，精度也不同）。

第 8 步显示了不同照片的信息。

# 还有更多...

Pillow 还具有许多围绕修改图片的功能。很容易调整大小或对文件进行简单修改，例如旋转。您可以在这里找到完整的 Pillow 文档：[`pillow.readthedocs.io`](https://pillow.readthedocs.io)。

Pillow 允许对图像进行许多操作。不仅可以进行简单的操作，如调整大小或将一个格式转换为另一个格式，还可以进行诸如裁剪图像、应用颜色滤镜或生成动画 GIF 等操作。如果您对使用 Python 进行图像处理感兴趣，那么 Pillow 绝对值得一看。

食谱中的 GPS 坐标以 DMS（度，分，秒），DDM（度，十进制分钟）表示，并转换为 DD（十进制度）。您可以在这里找到有关不同 GPS 格式的更多信息：[`www.ubergizmo.com/how-to/read-gps-coordinates/`](http://www.ubergizmo.com/how-to/read-gps-coordinates/)。如果您感兴趣，还可以在那里找到如何搜索图片的确切位置。

阅读图像文件的更高级用法是尝试对其进行 OCR（光学字符识别）处理。这意味着自动检测图像中的文本并提取和处理它。开源模块`tesseract`允许您执行此操作，并且可以与 Python 和 Pillow 一起使用。

您需要在系统中安装`tesseract`（[`github.com/tesseract-ocr/tesseract/wiki`](https://github.com/tesseract-ocr/tesseract/wiki)），以及`pytesseract` Python 模块（使用`pip install pytesseract`）。您可以从 GitHub 存储库中下载一个带有清晰文本的文件，称为`photo-text.jpg`，网址为[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/images/photo-text.jpg`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/images/photo-text.jpg)。

```py
>>> from PIL import Image
>>> import pytesseract
>>> pytesseract.image_to_string(Image.open('photo-text.jpg'))
'Automate!'
```

如果图像中的文本不太清晰，或者与图像混合在一起，或者使用了独特的字体，OCR 可能会很困难。在 GitHub 存储库中提供了`photo-dublin-a-text.jpg`文件的示例（可在[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/images/photo-dublin-a-text.jpg`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/images/photo-dublin-a-text.jpg)找到），其中包含图片上的文本：

```py
>>> >>> pytesseract.image_to_string(Image.open('photo-dublin-a-text.jpg'))
'ﬂ\n\nAutomat'
```

有关 Tesseract 的更多信息，请访问以下链接：[`github.com/tesseract-ocr/tesseract`](https://github.com/tesseract-ocr/tesseract)

[`github.com/madmaze/pytesseract`](https://github.com/madmaze/pytesseract)

将文件正确导入 OCR 可能需要进行初始图像处理以获得更好的结果。图像处理超出了本书的目标范围，但您可以使用比 Pillow 更强大的 OpenCV。您可以处理一个文件，然后使用 Pillow 打开它：[`opencv-python-tutroals.readthedocs.io/en/latest/py_tutorials/py_tutorials.html`](http://opencv-python-tutroals.readthedocs.io/en/latest/py_tutorials/py_tutorials.html)。

# 另请参阅

+   阅读文本文件食谱

+   阅读文件元数据食谱

+   爬行和搜索目录食谱

# 阅读 PDF 文件

文档的常见格式是 PDF（便携式文档格式）。它起初是一种描述任何打印机文档的格式，因此 PDF 是一种确保文档将被打印为其显示的格式的格式，因此是保证一致性的绝佳方式。它已成为共享文档的强大标准，特别是只读文档。

# 做好准备

对于这个食谱，我们将使用`PyPDF2`模块。我们需要将其添加到我们的虚拟环境中：

```py
>>> echo "PyPDF2==1.26.0" >> requirements.txt
>>> pip install -r requirements.txt
```

在 GitHub 目录`Chapter03/documents`中，我们准备了两个文档，`document-1.pdf`和`document-2.pdf`，供本食谱使用。请注意，它们主要包含 Lorem Ipsum 文本，这只是占位文本。

Lorem Ipsum 文本通常用于设计，以显示文本而无需在设计之前创建内容。在这里了解更多：[`loremipsum.io/`](https://loremipsum.io/)。

它们都是相同的测试文档，但第二个只能使用密码打开。密码是`automate`。

# 如何做...

1.  导入模块：

```py
>>> from PyPDF2 import PdfFileReader
```

1.  打开`document-1.pdf`文件并创建一个 PDF 文档对象。请注意，文件需要一直处于打开状态以进行阅读：

```py
>>> file = open('document-1.pdf', 'rb')
>>> document = PdfFileReader(file)
```

1.  获取文档的页数，并检查它是否已加密：

```py
>>> document.numPages
3
>>> document.isEncrypted
False
```

1.  从文档信息中获取创建日期（2018 年 6 月 24 日 11:15:18），并发现它是使用 Mac 的`Quartz PDFContext`创建的：

```py
>>> document.documentInfo['/CreationDate']
"D:20180624111518Z00'00'"
>>> document.documentInfo['/Producer']
'Mac OS X 10.13.5 Quartz PDFContext'
```

1.  获取第一页，并阅读其上的文本：

```py
>>> document.pages[0].extractText()
'!A VERY IMPORTANT DOCUMENT \nBy James McCormac CEO Loose Seal Inc '
```

1.  对第二页执行相同的操作（此处已编辑）：

```py
>>> document.pages[1].extractText()
'"!This is an example of a test document that is stored in PDF format. It contains some \nsentences to describe what it is and the it has lore ipsum text.\n!"\nLorem ipsum dolor sit amet, consectetur adipiscing elit. ...$'
```

1.  关闭文件并打开`document-2.pdf`：

```py
>>> file.close()
>>> file = open('document-2.pdf', 'rb')
>>> document = PdfFileReader(file)
```

1.  检查文档是否已加密（需要密码），并在尝试访问其内容时引发错误：

```py
>>> document.isEncrypted
True
>>> document.numPages
...
PyPDF2.utils.PdfReadError: File has not been decrypted
```

1.  解密文件并访问其内容：

```py
>>> document.decrypt('automate')
1
>>> document.numPages
3
>>> document.pages[0].extractText()
'!A VERY IMPORTANT DOCUMENT \nBy James McCormac CEO Loose Seal Inc ' 
```

1.  关闭文件以进行清理：

```py
>>> file.close()
```

# 它是如何工作的...

一旦文档打开，如*如何做...*部分的步骤 1 和 2 所示，`document`对象将提供对文档的访问。

最有趣的属性是页面数量，可在 `.numPages` 中找到，以及每个页面，可在 `.pages` 中找到，可以像列表一样访问。

其他可访问的数据存储在 `.documentInfo` 中，其中存储了有关创建者和创建时间的元数据。

`.documentInfo` 中的信息是可选的，有时不是最新的。这在很大程度上取决于用于生成 PDF 的工具。

每个 `page` 对象都可以通过调用 `.extractText()` 来获取其文本，这将返回页面中包含的所有文本，就像步骤 5 和 6 中所做的那样。这种方法尝试提取所有文本，但它也有一些限制。对于结构良好的文本，例如我们的示例，它运行得相当好，生成的文本可以被干净地处理。处理多列文本或位于奇怪位置的文本可能会使处理变得复杂。

请注意，PDF 文件需要在整个操作期间保持打开状态，而不是使用 `with` 上下文运算符。离开 `with` 块后，文件将被关闭。

步骤 8 和 9 展示了如何处理加密文件。您可以使用 `.isEncrypted` 检测文件是否已加密，然后使用 `.decrypt` 方法解密文件，提供密码。

# 还有更多...

PDF 是一种非常灵活的格式，因此它非常标准，但这也意味着它可能很难解析和处理。

虽然大多数 PDF 文件包含文本信息，但并不罕见它们包含图像。例如，扫描文档经常会出现这种情况。这意味着信息被存储为图像的集合，而不是文本。这使得提取数据变得困难；我们最终不得不采用诸如 OCR 这样的方法来将图像解析为文本。

PyPDF2 没有提供处理图像的良好接口。您可能需要将 PDF 转换为一组图像，然后对其进行处理。大多数 PDF 阅读器都可以做到这一点，或者您可以使用命令行工具，如 `pdftooppm`（[`linux.die.net/man/1/pdftoppm`](https://linux.die.net/man/1/pdftoppm)）或 QPDF（参见下文）。有关 OCR 的想法，请参阅 *读取图像* 配方。

某些加密文件的加密方式可能无法被 PyPDF2 理解。它会生成 `NotImplementedError: only algorithm code 1 and 2 are supported`。如果发生这种情况，您需要在外部解密 PDF 并在解密后打开它。您可以使用 QPDF 创建一个无需密码的副本，方法如下：

```py
$ qpdf --decrypt --password=PASSWORD encrypted.pdf output-decrypted.pdf
```

完整的 QPDF 可在此处找到：[`qpdf.sourceforge.net/files/qpdf-manual.html`](http://qpdf.sourceforge.net/files/qpdf-manual.html)。QPDF 也可以在大多数软件包管理器中找到。

QPDF 能够进行大量的转换和深入分析 PDF。还有一个名为 `pikepdf` 的 Python 模块的绑定（[`pikepdf.readthedocs.io/en/stable/`](https://pikepdf.readthedocs.io/en/stable/)）。这个模块比 PyPDF2 更难使用，对于文本提取来说也不那么直接，但如果需要其他操作，比如从 PDF 中提取图像，它可能会很有用。

# 另请参阅

+   *读取文本文件* 配方

+   *爬取和搜索目录* 配方

# 阅读 Word 文档

Word 文档（`.docx`）是另一种常见的存储文本的文档类型。它们通常是使用 Microsoft Office 生成的，但其他工具也会生成兼容的文件。它们可能是最常见的用于共享需要可编辑的文件的格式，但也常用于分发文档。

在本配方中，我们将看到如何从 Word 文档中提取文本信息。

# 准备工作

我们将使用 `python-docx` 模块来读取和处理 Word 文档：

```py
>>> echo "python-docx==0.8.6" >> requirements.txt
>>> pip install -r requirements.txt
```

我们已经准备了一个测试文件，位于 GitHub 的 `Chapter04/documents` 目录中，名为 `document-1.docx`，我们将在本配方中使用它。请注意，该文档遵循了与配方 *读取 PDF 文件* 配方中的测试文档中描述的 Lorem Ipsun 模式相同。

# 如何做...

1.  导入 `python-docx`：

```py
>> import docx
```

1.  打开 `document-1.docx` 文件：

```py
>>> doc = docx.Document('document-1.docx')
```

1.  检查存储在`core_properties`中的一些元数据属性：

```py
>> doc.core_properties.title
'A very important document'
>>> doc.core_properties.keywords
'lorem ipsum'
>>> doc.core_properties.modified
datetime.datetime(2018, 6, 24, 15, 1, 7)
```

1.  检查段落的数量：

```py
>>> len(doc.paragraphs)
58
```

1.  遍历段落以检测包含文本的段落。请注意，并非所有文本都在此处显示：

```py
>>> for index, paragraph in enumerate(doc.paragraphs):
...     if paragraph.text:
...         print(index, paragraph.text)
...
30 A VERY IMPORTANT DOCUMENT
31 By James McCormac
32 CEO Loose Seal Inc
34
...
56 TITLE 2
57 ...
```

1.  获取段落`30`和`31`的文本，这对应于第一页的标题和副标题：

```py
>>> doc.paragraphs[30].text
'A VERY IMPORTANT DOCUMENT'
>>> doc.paragraphs[31].text
'By James McCormac'
```

1.  每个段落都有`runs`，这些是具有不同属性的文本部分。检查第一个文本段落和`run`是否为粗体，第二个是否为斜体：

```py
>>> doc.paragraphs[30].runs[0].italic
>>> doc.paragraphs[30].runs[0].bold
True
>>> doc.paragraphs[31].runs[0].bold
>>> doc.paragraphs[31].runs[0].italic
True
```

1.  在这个文档中，大多数段落只有一个`run`，但我们在第`48`段有一个不错的例子，其中包含不同的运行。显示其文本和不同的样式。例如，单词`Word`是粗体，`ipsum`是斜体：

```py
>>> [run.text for run in doc.paragraphs[48].runs]
['This is an example of a test document that is stored in ', 'Word', ' format', '. It contains some ', 'sentences', ' to describe what it is and it has ', 'lore', 'm', ' ipsum', ' text.']
>>> run1 = doc.paragraphs[48].runs[1]
>>> run1.text
'Word'
>>> run1.bold
True
>>> run2 = doc.paragraphs[48].runs[8]
>>> run2.text
' ipsum'
>>> run2.italic
True
```

# 它是如何工作的…

Word 文档最重要的特点是数据是以段落而不是页面结构化的。字体大小、行大小和其他考虑因素可能导致页面数量发生变化。

大多数段落通常也是空的，或者只包含换行符、制表符或其他空白字符。检查段落是否为空并跳过它是一个好主意。

在*如何做…*部分，第 2 步打开文件，第 3 步显示如何访问核心属性。这些属性在 Word 中被定义为文档元数据，例如作者或创建日期。

这些信息需要谨慎对待，因为许多生成 Word 文档的工具（但不包括 Microsoft Office）不一定会填充它。在使用该信息之前，请再次检查。

文档的段落可以被迭代，并以原始格式提取其文本，如第 6 步所示。这是不包括样式信息的信息，通常对于自动处理数据来说是最有用的。

如果需要样式信息，可以使用运行，如第 7 和第 8 步。每个段落可以包含一个或多个运行，这些运行是共享相同样式的较小单位。例如，如果一个句子是*Word1* word2 **word3**，将有三个运行，一个是斜体文本（Word1），另一个是下划线（word2），另一个是粗体（word3）。更甚者，可能会有包含空格的常规文本的中间运行，总共有 5 个运行。

样式可以通过属性进行单独检测，例如粗体、斜体或下划线。

运行的划分可能相当复杂。由于编辑器的工作方式，*半词*是很常见的，一个单词分成两个运行，有时具有相同的属性。不要依赖于运行的数量并分析内容。特别是在试图确保具有特定样式的部分是否分成两个或更多个运行时，请再次检查。一个很好的例子是第 8 步中的单词`lore` `m`（应该是`lorem`）。

请注意，由于 Word 文档由许多来源生成，许多属性可能未设置，因此需要工具决定使用哪些具体属性。例如，保留默认字体非常常见，这可能意味着字体信息为空。

# 还有更多...

可以在字体属性下找到更多样式信息，例如`small_caps`或大小：

```py
>>> run2.font.cs_italic
True
>>> run2.font.size
152400
>>> run2.font.small_caps
```

通常专注于原始文本，而不关注样式信息是正确的解析。但有时段落中的粗体单词会有特殊意义。它可能是标题或您正在寻找的结果。因为它被突出显示，很可能就是您要找的！在分析文档时请记住这一点。

你可以在这里找到整个`python-docx`文档：[`python-docx.readthedocs.io/en/latest/`](https://python-docx.readthedocs.io/en/latest/)。

# 另请参阅

+   *阅读文本文件*配方

+   *阅读 PDF 文件*配方

# 扫描文档以查找关键字

在这个配方中，我们将汇总前几个配方的所有课程，并在目录中搜索特定关键字的文件。这是本章其余配方的总结，包括一个搜索不同类型文件的脚本。

# 准备就绪

确保在`requirements.txt`文件中包含以下所有模块，并将它们安装到您的虚拟环境中：

```py
beautifulsoup4==4.6.0
Pillow==5.1.0
PyPDF2==1.26.0
python-docx==0.8.6
```

检查要搜索的目录是否有以下文件（所有文件都在 GitHub 的`Chapter04/documents`目录中可用）。请注意，`file5.pdf`和`file6.pdf`是`document-1.pdf`的副本，以简化。`file1.txt`到`file4.txt`是空文件：

```py
├── dir
│   ├── file1.txt
│   ├── file2.txt
│   ├── file6.pdf
│   └── subdir
│       ├── file3.txt
│       ├── file4.txt
│       └── file5.pdf
├── document-1.docx
├── document-1.pdf
├── document-2-1.pdf
├── document-2.pdf
├── example_iso.txt
├── example_output_iso.txt
├── example_utf8.txt
├── top_films.csv
└── zen_of_python.txt
```

我们准备了一个名为`scan.py`的脚本，它将在所有`.txt`、`.csv`、`.pdf`和`.docx`文件中搜索一个单词。该脚本可在 GitHub 存储库的`Chapter04`目录中找到。

# 如何做...

1.  有关如何使用`scan.py`脚本，请参考帮助`-h`：

```py
$ python scan.py -h
usage: scan.py [-h] [-w W]

optional arguments:
 -h, --help show this help message and exit
 -w W Word to search
```

1.  搜索单词`the`，它出现在大多数文件中：

```py
$ python scan.py -w the
>>> Word found in ./document-1.pdf
>>> Word found in ./top_films.csv
>>> Word found in ./zen_of_python.txt
>>> Word found in ./dir/file6.pdf
>>> Word found in ./dir/subdir/file5.pdf
```

1.  搜索单词`lorem`，只出现在 PDF 和 docx 文件中：

```py
$ python scan.py -w lorem
>>> Word found in ./document-1.docx
>>> Word found in ./document-1.pdf
>>> Word found in ./dir/file6.pdf
>>> Word found in ./dir/subdir/file5.pdf
```

1.  搜索单词`20£`，只出现在两个 ISO 文件中，使用不同的编码：

```py
$ python scan.py -w 20£
>>> Word found in ./example_iso.txt
>>> Word found in ./example_output_iso.txt
```

1.  搜索是不区分大小写的。搜索单词`BETTER`，只出现在`zen_of_python.txt`文件中：

```py
$ python scan.py -w BETTER
>>> Word found in ./zen_of_python.txt
```

# 它是如何工作的...

文件`scan.py`包含以下元素：

1.  解析输入参数并为命令行创建帮助的入口点。

1.  一个主要函数遍历目录并分析找到的每个文件。根据它们的扩展名，它决定是否有可用的函数来处理和搜索它。

1.  一个`EXTENSION`字典，将扩展名与搜索它们的函数配对。

1.  `search_txt`，`search_csv`，`search_pdf`和`search_docx`函数，用于处理和搜索每种文件所需的单词。

比较不区分大小写，因此搜索词转换为小写，在所有比较中，文本都转换为小写。

每个搜索函数都有自己的特点：

1.  `search_txt`首先打开文件以确定其编码，使用`UnicodeDammit`，然后逐行打开文件并读取。如果找到该单词，它会立即停止并返回成功。

1.  `search_csv`以 CSV 格式打开文件，并不仅逐行迭代，还逐列迭代。一旦找到该单词，它就会返回。

1.  `search_pdf`打开文件，如果文件被加密，则退出。如果没有加密，它会逐页提取文本并与单词进行比较。一旦找到匹配项，它就会立即返回。

1.  `search_docx`打开文件并遍历其所有段落以进行匹配。一旦找到匹配项，函数就会返回。

# 还有更多...

还有一些额外的想法可以实现：

+   可以添加更多的搜索函数。在本章中，我们浏览了日志文件和图像。

+   类似的结构也可以用于搜索文件并仅返回最后 10 个。

+   `search_csv`没有嗅探以检测方言。这也可以添加。

+   阅读是相当顺序的。应该可以并行读取文件，分析它们以获得更快的返回，但要注意，并行读取文件可能会导致排序问题，因为文件不总是以相同的顺序处理。

# 另请参阅

+   爬行和搜索目录的配方

+   阅读文本文件的配方

+   处理编码的配方

+   阅读 CSV 文件的配方

+   阅读 PDF 文件的配方

+   阅读 Word 文档的配方
