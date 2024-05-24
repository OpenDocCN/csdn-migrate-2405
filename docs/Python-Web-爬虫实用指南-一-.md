# Python Web 爬虫实用指南（一）

> 原文：[`zh.annas-archive.org/md5/AB12C428C180E19BF921ADFBD1CC8C3E`](https://zh.annas-archive.org/md5/AB12C428C180E19BF921ADFBD1CC8C3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

网页抓取是许多组织中使用的一种重要技术，用于从网页中抓取有价值的数据。网页抓取是为了从网站中提取和收集数据而进行的。网页抓取在模型开发中非常有用，这需要实时收集数据。它也适用于真实且与主题相关的数据，其中准确性是短期内所需的，而不是实施数据集。收集的数据存储在包括 JSON、CSV 和 XML 在内的文件中，也写入数据库以供以后使用，并作为数据集在线提供。本书将为您打开网页抓取技术和方法的大门，使用 Python 库和其他流行工具，如 Selenium。通过本书，您将学会如何高效地抓取不同的网站。

# 本书适合对象

这本书适用于 Python 程序员、数据分析师、网页抓取新手以及任何想要学习如何从头开始进行网页抓取的人。如果你想开始学习如何将网页抓取技术应用于各种网页，那么这本书就是你需要的！

# 本书内容

第一章，网页抓取基础知识，探讨了一些与 WWW 相关的核心技术和工具，这些技术和工具对网页抓取是必需的。

第二章，Python 和 Web-使用 URLlib 和 Requests，演示了 Python 库中可用的一些核心功能，如`requests`和`urllib`，并探索了各种格式和结构的页面内容。

第三章，使用 LXML、XPath 和 CSS 选择器，描述了使用 LXML 的各种示例，实现了处理元素和 ElementTree 的各种技术和库特性。

第四章，使用 pyquery 进行抓取-一个 Python 库，更详细地介绍了网页抓取技术和一些部署这些技术的新 Python 库。

第五章，使用 Scrapy 和 Beautiful Soup 进行网页抓取，检查了使用 Beautiful Soup 遍历网页文档的各个方面，同时还探索了一个专为使用蜘蛛进行爬行活动而构建的框架，换句话说，Scrapy。

第六章，处理安全网页，涵盖了许多常见的基本安全措施和技术，这些措施和技术经常遇到，并对网页抓取构成挑战。

第七章，使用基于 Web 的 API 进行数据提取，涵盖了 Python 编程语言以及如何与 Web API 交互以进行数据提取。

第八章，使用 Selenium 进行网页抓取，涵盖了 Selenium 以及如何使用它从网页中抓取数据。

第九章，使用正则表达式提取数据，更详细地介绍了使用正则表达式进行网页抓取技术。

第十章，下一步，介绍并探讨了使用文件进行数据管理，使用 pandas 和 matplotlib 进行分析和可视化的基本概念，同时还介绍了机器学习和数据挖掘，并探索了一些相关资源，这些资源对进一步学习和职业发展都有帮助。

# 充分利用本书

读者应该具有一定的 Python 编程语言工作知识。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在“搜索”框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python`](https://github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富书籍和视频目录的其他代码包，可以在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一份 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781789533392_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781789533392_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“`<p>`和`<h1>` HTML 元素包含与它们一起的一般文本信息（元素内容）。”

代码块设置如下：

```py
import requests
link="http://localhost:8080/~cache"

queries= {'id':'123456','display':'yes'}

addedheaders={'user-agent':''}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
import requests
link="http://localhost:8080/~cache"

queries= {'id':'123456','display':'yes'}

addedheaders={'user-agent':''}
```

任何命令行输入或输出都以以下方式编写：

```py
C:\> pip --version

pip 18.1 from c:\python37\lib\site-packages\pip (python 3.7)
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这样的方式出现在文本中。这是一个例子：“如果通过 Chrome 菜单访问开发者工具，请单击更多工具|开发者工具”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一部分：网络抓取简介

在本节中，您将获得有关网络抓取（抓取要求、数据重要性）、网页内容（模式和布局）、Python 编程和库（基础和高级）、以及数据管理技术（文件处理和数据库）的概述。

本节包括以下章节：

+   第一章，*网络抓取基础*


# 第一章：网络爬虫基础知识

在本章中，我们将学习和探讨与网络爬取和基于网络的技术相关的某些基本概念，假设您没有网络爬取的先验经验。

因此，让我们从以下一些问题开始：

+   为什么会出现对数据的不断增长需求？

+   我们将如何管理和满足来自“万维网”（WWW）资源的数据需求？

网络爬虫解决了这两个问题，因为它提供了各种工具和技术，可以用来提取数据或协助信息检索。无论是基于网络的结构化数据还是非结构化数据，我们都可以使用网络爬虫过程来提取数据，并将其用于研究、分析、个人收藏、信息提取、知识发现等多种目的。

我们将学习通用技术，用于从网络中查找数据，并在接下来的章节中使用 Python 编程语言深入探讨这些技术。

在本章中，我们将涵盖以下主题：

+   网络爬虫介绍

+   了解网络开发和技术

+   数据查找技术

# 网络爬虫介绍

爬取是从网络中提取、复制、筛选或收集数据的过程。从网络（通常称为网站、网页或与互联网相关的资源）中提取或提取数据通常被称为“网络爬取”。

网络爬虫是一种适用于特定需求的从网络中提取数据的过程。数据收集和分析，以及其在信息和决策制定中的参与，以及与研究相关的活动，使得爬取过程对所有类型的行业都很敏感。

互联网及其资源的普及每天都在引起信息领域的演变，这也导致了对原始数据的不断增长需求。数据是科学、技术和管理领域的基本需求。收集或组织的数据经过不同程度的逻辑处理，以获取信息并获得进一步的见解。

网络爬虫提供了用于根据个人或业务需求从网站收集数据的工具和技术，但需要考虑许多法律因素。

在执行爬取任务之前，有许多法律因素需要考虑。大多数网站包含诸如“隐私政策”、“关于我们”和“条款和条件”等页面，其中提供了法律条款、禁止内容政策和一般信息。在计划从网站进行任何爬取和抓取活动之前，开发者有道德责任遵守这些政策。

在本书的各章中，爬取和抓取两个术语通常可以互换使用。抓取，也称为蜘蛛，是用于浏览网站链接的过程，通常由搜索引擎用于索引目的，而爬取大多与从网站中提取内容相关。

# 了解网络开发和技术

网页不仅仅是一个文档容器。当今计算和网络技术的快速发展已经将网络转变为动态和实时的信息来源。

在我们这一端，我们（用户）使用网络浏览器（如 Google Chrome、Firefox Mozilla、Internet Explorer 和 Safari）来从网络中获取信息。网络浏览器为用户提供各种基于文档的功能，并包含对网页开发人员通常有用的应用级功能。

用户通过浏览器查看或浏览的网页不仅仅是单个文档。存在各种技术可用于开发网站或网页。网页是包含 HTML 标记块的文档。大多数情况下，它是由各种子块构建而成，这些子块作为依赖或独立组件来自各种相互关联的技术，包括 JavaScript 和 CSS。

对网页的一般概念和网页开发技术的理解，以及网页内部的技术，将在抓取过程中提供更多的灵活性和控制。很多时候，开发人员还可以使用反向工程技术。

反向工程是一种涉及分解和检查构建某些产品所需概念的活动。有关反向工程的更多信息，请参阅 GlobalSpec 文章*反向工程是如何工作的？*，网址为[`insights.globalspec.com/article/7367/how-does-reverse-engineering-work`](https://insights.globalspec.com/article/7367/how-does-reverse-engineering-work)。

在这里，我们将介绍和探讨一些可以帮助和指导我们进行数据提取过程的技术。

# HTTP

**超文本传输协议**（**HTTP**）是一种应用协议，用于在客户端和 Web 服务器之间传输资源，例如 HTML 文档。HTTP 是一种遵循客户端-服务器模型的无状态协议。客户端（Web 浏览器）和 Web 服务器使用 HTTP 请求和 HTTP 响应进行通信或交换信息：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/e8e73182-af3b-4420-b6e2-b1dd169524d6.png)

HTTP（客户端-服务器通信）

通过 HTTP 请求或 HTTP 方法，客户端或浏览器向服务器提交请求。有各种方法（也称为 HTTP 请求方法）可以提交请求，例如`GET`、`POST`和`PUT`：

+   `GET`：这是请求信息的常见方法。它被认为是一种安全方法，因为资源状态不会被改变。此外，它用于提供查询字符串，例如`http://www.test-domain.com/`，根据请求中发送的`id`和`display`参数从服务器请求信息。

+   `POST`：用于向服务器发出安全请求。所请求的资源状态*可以*被改变。发送到请求的 URL 的数据不会显示在 URL 中，而是与请求主体一起传输。它用于以安全的方式向服务器提交信息，例如登录和用户注册。

使用浏览器开发者工具显示的以下屏幕截图，可以显示请求方法以及其他与 HTTP 相关的信息：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/a520b2b7-8916-45e4-927c-eb41b01ff8ff.png)

一般的 HTTP 头（使用浏览器开发者工具访问）

我们将在第二章中更多地探讨 HTTP 方法，

*Python 和 Web-使用 urllib 和 Requests*，在*实现 HTTP 方法*部分。

**HTTP 头**在请求或响应过程中向客户端或服务器传递附加信息。头通常是客户端和服务器在通信过程中传输的信息的名称-值对，并且通常分为请求头和响应头：

+   请求头：这些是用于发出请求的头。在发出请求时，会向服务器提供诸如语言和编码请求 `-*`、引用者、cookie、与浏览器相关的信息等信息。以下屏幕截图显示了在向[`www.python.org`](https://www.python.org)发出请求时从浏览器开发者工具中获取的请求头：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/f8b43b0f-9120-4c2b-a5b2-f7fe47beae33.png)

请求头（使用浏览器开发者工具访问）

+   响应头：这些头包含有关服务器响应的信息。响应头通常包含有关响应的信息（包括大小、类型和日期）以及服务器状态。以下屏幕截图显示了在向[`www.python.org`](https://www.python.org)发出请求后从浏览器开发者工具中获取的响应头：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/2574079c-3df8-4486-9f0e-f156c6c06e6d.png)

响应头（使用浏览器开发者工具访问）

在之前的屏幕截图中看到的信息是在对[`www.python.org`](https://www.python.org)发出的请求期间捕获的。

在向服务器发出请求时，还可以提供所需的 HTTP 头部。通常可以使用 HTTP 头部信息来探索与请求 URL、请求方法、状态代码、请求头部、查询字符串参数、cookie、`POST`参数和服务器详细信息相关的信息。

通过**HTTP 响应**，服务器处理发送到它的请求，有时也处理指定的 HTTP 头部。当接收并处理请求时，它将其响应返回给浏览器。

响应包含状态代码，其含义可以使用开发者工具来查看，就像在之前的屏幕截图中看到的那样。以下列表包含一些状态代码以及一些简要信息：

+   200（OK，请求成功）

+   404（未找到；请求的资源找不到）

+   500（内部服务器错误）

+   204（无内容发送）

+   401（未经授权的请求已发送到服务器）

有关 HTTP、HTTP 响应和状态代码的更多信息，请参阅官方文档[`www.w3.org/Protocols/`](https://www.w3.org/Protocols/)和[`developer.mozilla.org/en-US/docs/Web/HTTP/Status`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)。

**HTTP cookie**是服务器发送给浏览器的数据。cookie 是网站在您的系统或计算机上生成和存储的数据。cookie 中的数据有助于识别用户对网站的 HTTP 请求。cookie 包含有关会话管理、用户偏好和用户行为的信息。

服务器根据存储在 cookie 中的信息来识别并与浏览器通信。cookie 中存储的数据帮助网站访问和传输某些保存的值，如会话 ID、过期日期和时间等，从而在 web 请求和响应之间提供快速交互：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/1b75aaec-97fa-4e42-9cec-0abf89697eff.png)

网站设置的 cookie（使用浏览器开发者工具访问）有关 cookie 的更多信息，请访问[`www.allaboutcookies.org/`](http://www.allaboutcookies.org/)的 AboutCookies 和[`www.allaboutcookies.org/`](http://www.allaboutcookies.org/)的 allaboutcookies。

通过**HTTP 代理**，代理服务器充当客户端和主要 web 服务器之间的中间服务器。网页浏览器发送的请求实际上是通过代理传递的，代理将服务器的响应返回给客户端。

代理通常用于监视/过滤、性能改进、翻译和互联网相关资源的安全性。代理也可以作为一种服务购买，也可以用来处理跨域资源。还有各种形式的代理实现，比如网页代理（可以用来绕过 IP 封锁）、CGI 代理和 DNS 代理。

通过使用`GET`请求传递的基于 cookie 的参数、HTML 表单相关的`POST`请求以及修改或调整头部，在网页抓取过程中管理代码（即脚本）和访问内容将至关重要。

有关 HTTP、头部、cookie 等的详细信息将在即将到来的*网络数据查找技术*部分中更详细地探讨。请访问 MDN web docs-HTTP ([`developer.mozilla.org/en-US/docs/Web/HTTP`](https://developer.mozilla.org/en-US/docs/Web/HTTP))获取有关 HTTP 的更详细信息。

# HTML

网站由包含文本、图像、样式表和脚本等内容的页面或文档组成。它们通常是用标记语言（如**超文本标记语言**（**HTML**）和**可扩展超文本标记语言**（**XHTML**））构建的。

HTML 通常被称为用于构建网页的标准标记语言。自上世纪 90 年代初以来，HTML 已经独立使用，也与基于服务器的脚本语言（如 PHP、ASP 和 JSP）一起使用。

XHTML 是 HTML 的高级和扩展版本，是用于 Web 文档的主要标记语言。XHTML 也比 HTML 更严格，从编码的角度来看，它是一个 XML 应用程序。

HTML 定义并包含网页的内容。可以在 HTML 页面中找到可以提取的数据，以及任何揭示信息的数据源，这些数据源位于预定义的指令集或标记元素**标签**内。HTML 标签通常是一个带有特定预定义属性的命名占位符。

# HTML 元素和属性

HTML 元素（也称为文档节点）是 Web 文档的构建块。HTML 元素由开始标签`<..>`和结束标签`</..>`以及其中的特定内容构成。HTML 元素也可以包含属性，通常定义为`attribute-name = attribute-value`，提供额外的信息给元素：

```py
<p>normal paragraph tags</p>
<h1>heading tags there are also h2, h3, h4, h5, h6</h1>
<a href="https://www.google.com">Click here for Google.com</a>
<img src="myphoto1.jpg" width="300" height="300" alt="Picture" />
<br />
```

前面的代码可以分解如下：

+   `<p>`和`<h1>` HTML 元素包含一般文本信息（元素内容）。

+   `<a>`定义了一个包含实际链接的`href`属性，当点击文本`点击这里前往 Google.com`时将被处理。链接指向[`www.google.com/`](https://www.google.com/)。

+   `<img>`图像标签也包含一些属性，比如`src`和`alt`，以及它们各自的值。`src`保存资源，即图像地址或图像 URL 作为值，而`alt`保存`<img>`的替代文本的值。

+   `<br />`代表 HTML 中的换行，没有属性或文本内容。它用于在文档的布局中插入新行。

HTML 元素也可以以树状结构嵌套，具有父子层次结构：

```py
<div>
   <p id="mainContent" class="content"> 
        <i> Paragraph contents </i>
        <img src="mylogo.png" id="pageLogo" class="logo"/>
        ….
    </p>
    <p class="content" id="subContent">
        <i style="color:red"> Sub paragraph content </i>
        <h1 itemprop="subheading">Sub heading Content! </h1>
        ….
    </p>
</div>
```

如前面的代码所示，在 HTML`<div>`块内找到了两个`<p>`子元素。两个子元素都带有特定的属性和各种子元素作为它们的内容。通常，HTML 文档是按照上述结构构建的。

# 全局属性

HTML 元素可以包含一些额外的信息，如键/值对。这些也被称为 HTML 元素属性。属性保存值并提供标识，或包含在许多方面有用的附加信息，比如在爬取活动中识别确切的网页元素和提取值或文本，遍历元素等。

有一些属性是通用的 HTML 元素属性，或者可以应用于所有 HTML 元素，如下所示。这些属性被标识为全局属性（[`developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes`](https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes)）：

+   `id`

+   `class`

+   `style`

+   `lang`

HTML 元素属性，如`id`和`class`，主要用于标识或格式化单个元素或元素组。这些属性也可以由 CSS 和其他脚本语言管理。

`id`属性值应该对应于它们所应用的元素是唯一的。`class`属性值通常与 CSS 一起使用，提供相同的状态格式选项，并且可以用于多个元素。

当与 CSS、遍历和解析技术一起使用时，通过在属性名称前面分别放置`#`和`.`来识别`id`和`class`等属性。

HTML 元素属性也可以通过脚本语言动态地覆盖或实现。

如下例所示，`itemprop`属性用于向元素添加属性，而`data-*`用于存储元素本身的本地数据：

```py
<div itemscope itemtype ="http://schema.org/Place">
    <h1 itemprop="univeristy">University of Helsinki</h1>
     <span>Subject:
         <span itemprop="subject1">Artificial Intelligence</span>   
    </span>
     <span itemprop="subject2">Data Science</span>
</div>

<img class="dept" src="logo.png" data-course-id="324" data-title="Predictive Aanalysis"  data-x="12345" data-y="54321" data-z="56743" onclick="schedule.load()">
</img>
```

当涉及到提取时，HTML 标签和属性是数据的主要来源。

请访问[`www.w3.org/html/`](https://www.w3.org/html/)和[`www.w3schools.com/html/`](https://www.w3schools.com/html/)了解更多关于 HTML 的信息。

在接下来的章节中，我们将使用不同的工具来探索这些属性。我们还将执行各种逻辑操作，并使用它们来提取内容。

# XML

**可扩展标记语言**（**XML**）是一种用于在互联网上传输数据的标记语言，具有一组规则，用于对可读和易于在机器和文档之间交换的文档进行编码。

XML 可以在各种格式和系统之间使用文本数据。XML 旨在携带可移植数据或未使用 HTML 标记预定义的标记中存储的数据。在 XML 文档中，标记是由文档开发人员或自动化程序创建的，用于描述它们携带的内容。

以下代码显示了一些示例 XML 内容。`<employees>`父节点有三个`<employee>`子节点，这些子节点又包含其他子节点`<firstName>`、`<lastName>`和`<gender>`：

```py
<employees>
    <employee>
        <firstName>Rahul</firstName>
        <lastName>Reddy</lastName>
        <gender>Male</gender>
    </employee>
    <employee>
        <firstName>Aasira</firstName>
        <lastName>Chapagain</lastName>
        <gender>Female</gender> 
    </employee>
    <employee>
        <firstName>Peter</firstName>
        <lastName>Lara</lastName>
        <gender>Male</gender>        
    </employee>
</employees>
```

XML 是一种使用 Unicode 字符集的开放标准。XML 用于在各种平台之间共享数据，并已被各种 Web 应用程序采用。许多网站使用 XML 数据，使用脚本语言实现其内容，并以 HTML 或其他文档格式呈现给最终用户查看。

还可以执行从 XML 文档中提取任务，以获取所需格式的内容，或者通过过滤数据需求来满足特定的需求。此外，还可以从某些网站获取幕后数据。

请访问[`www.w3.org/XML/`](https://www.w3.org/XML/)和[`www.w3schools.com/xml/`](https://www.w3schools.com/xml/)了解更多关于 XML 的信息。

# JavaScript

JavaScript 是一种编程语言，用于编写在浏览器中运行的 HTML 和 Web 应用程序。JavaScript 主要用于添加动态功能，并在网页内提供基于用户的交互。JavaScript、HTML 和 CSS 是最常用的 Web 技术之一，现在它们也与无头浏览器一起使用。JavaScript 引擎的客户端可用性也加强了它在应用程序测试和调试中的地位。

JavaScript 代码可以使用`<script>`添加到 HTML 中，也可以嵌入为文件。`<script>`包含具有 JavaScript 变量、运算符、函数、数组、循环、条件和事件的编程逻辑，目标是 HTML **文档对象模型**（**DOM**）：

```py
<!DOCTYPE html>
<html>
<head>
    <script>
        function placeTitle() {
            document.getElementById("innerDiv").innerHTML = "Welcome to WebScraping";
        }
    </script>
</head>
<body>
    <div>Press the button: <p id="innerDiv"></p></div>
    <br />
    <button id="btnTitle" name="btnTitle" type="submit" onclick="placeTitle()">
        Load Page Title!
    </button>
</body>
</html>
```

HTML DOM 是如何获取、更改、添加或删除 HTML 元素的标准。JavaScript HTML DOM，可以参考 W3Schools 的 URL[`www.w3schools.com/js/js_htmldom.asp`](https://www.w3schools.com/js/js_htmldom.asp)。

通过可访问的内部函数和编程功能对 HTML 内容、元素、属性值、CSS 和 HTML 事件进行动态操作，使 JavaScript 在 Web 开发中非常受欢迎。与 JavaScript 相关的许多基于 Web 的技术，包括 JSON、jQuery、AngularJS 和 AJAX 等。

jQuery 是一个 JavaScript 库，解决了浏览器之间的不兼容性，提供了处理 HTML DOM、事件和动画的 API 功能。

jQuery 因为为 Web 提供交互性以及使用 JavaScript 进行编码而在全球受到赞誉。与 JavaScript 框架相比，jQuery 轻量级，易于实现，并且具有简短和可读的编码方法。

有关 jQuery 的更多信息，请访问[`www.w3schools.com/jquery/`](https://www.w3schools.com/jquery/)和[`jquery.com/`](http://jquery.com/)。

**异步 JavaScript 和 XML**（**AJAX**）是一种 Web 开发技术，它在客户端使用一组 Web 技术来创建异步 Web 应用程序。JavaScript **XMLHttpRequest**（**XHR**）对象用于在网页上执行 AJAX，并在不刷新或重新加载页面的情况下加载页面内容。有关 AJAX 的更多信息，请访问 AJAX W3Schools（[`www.w3schools.com/js/js_ajax_intro.asp`](https://www.w3schools.com/js/js_ajax_intro.asp)）。

从抓取的角度来看，对 JavaScript 功能的基本概述将有助于理解页面的构建或操作，以及识别所使用的动态组件。

有关 JavaScript 的更多信息，请访问[`developer.mozilla.org/en-US/docs/Web/JavaScript`](https://developer.mozilla.org/en-US/docs/Web/JavaScript)和[`www.javascript.com/`](https://www.javascript.com/)。

# JSON

**JavaScript 对象表示法**（**JSON**）是一种用于从服务器传输数据到网页的格式。它与语言无关，并且由于其大小和可读性，在基于网络的数据交换操作中很受欢迎。

JSON 数据通常是一个名称/值对，被视为 JavaScript 对象，并遵循 JavaScript 操作。JSON 和 XML 经常被比较，因为它们都在各种 Web 资源之间携带和交换数据。JSON 的结构比 XML 更简单、可读、自我描述、易于理解和处理。对于使用 JavaScript、AJAX 或 RESTful 服务的 Web 应用程序，由于其快速和简便的操作，JSON 比 XML 更受青睐。

JSON 和 JavaScript 对象是可以互换的。JSON 不是一种标记语言，它不包含任何标签或属性。相反，它是一种仅限于文本的格式，可以通过服务器发送/访问，并且可以由任何编程语言管理。JSON 对象也可以表示为数组、字典和列表，如下面的代码所示：

```py
{"mymembers":[
 { "firstName":"Aasira", "lastName":"Chapagain","cityName":"Kathmandu"},
 { "firstName":"Rakshya", "lastName":"Dhungel","cityName":"New Delhi"},
 { "firstName":"Shiba", "lastName":"Paudel","cityName":"Biratnagar"},
 { "firstName":"Rahul", "lastName":"Reddy","cityName":"New Delhi"},
 { "firstName":"Peter", "lastName":"Lara","cityName":"Trinidad"}
]}
```

**JSON Lines**：这是一种类似 JSON 的格式，其中每条记录的每行都是有效的 JSON 值。它也被称为换行符分隔的 JSON，即用换行符（`\n`）分隔的单独的 JSON 记录。处理大量数据时，JSON Lines 格式非常有用。

由于易于数据模式和代码可读性，JSON 或 JSON Lines 格式的数据源比 XML 更受青睐，这也可以通过最少的编程工作来管理：

```py
 {"firstName":"Aasira", "lastName":"Chapagain","cityName":"Kathmandu"}
 {"firstName":"Rakshya", "lastName":"Dhungel","cityName":"New Delhi"}
 {"firstName":"Shiba", "lastName":"Paudel","cityName":"Biratnagar"}
 {"firstName":"Rahul", "lastName":"Reddy","cityName":"New Delhi"}
 {"firstName":"Peter", "lastName":"Lara","cityName":"Trinidad"}
```

从数据提取的角度来看，由于 JSON 格式的轻量和简单结构，网页使用 JSON 内容与其脚本技术结合，以添加动态功能。

有关 JSON 和 JSON Lines 的更多信息，请访问[`www.json.org/`](http://www.json.org/)，[`jsonlines.org/`](http://jsonlines.org/)和[`www.w3schools.com/js/js_json_intro.asp`](https://www.w3schools.com/js/js_json_intro.asp)。

# CSS

到目前为止，我们介绍的基于网络的技术涉及内容、内容绑定、内容开发和处理。**层叠样式表**（**CSS**）描述了 HTML 元素的显示属性和网页的外观。CSS 用于为 HTML 元素提供样式和所需的外观和呈现。

开发人员/设计人员可以使用 CSS 来控制网页文档的布局和呈现。CSS 可以应用于页面中的特定元素，也可以通过单独的文档进行嵌入。可以使用`<style>`标签来描述样式细节。

`<style>`标签可以包含针对块中重复和各种元素的详细信息。如下面的代码所示，存在多个`<a>`元素，并且还具有`class`和`id`全局属性：

```py
<html>
<head>
      <style>
        a{color:blue;}
        h1{color:black; text-decoration:underline;}
        #idOne{color:red;}
        .classOne{color:orange;}
      </style>
</head>
<body>
      <h1> Welcome to Web Scraping </h1>
      Links:
      <a href="https://www.google.com"> Google </a> 
      <a class='classOne' href="https://www.yahoo.com"> Yahoo </a> 
      <a id='idOne' href="https://www.wikipedia.org"> Wikipedia </a>
</body>
</html>
```

与 CSS 属性一起提供的属性，或者在前面的代码块中在`<style>`标签中进行了样式化的属性，将导致在此处看到的输出：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/b9327add-325f-4d48-8f4a-135dc4eeef4a.png)

HTML 输出（使用 CSS 进行样式化的元素）

CSS 属性也可以以内联结构出现在每个特定元素中。内联 CSS 属性会覆盖外部 CSS 样式。CSS 的`color`属性已经内联应用到元素中。这将覆盖`<style>`中定义的`color`值：

```py
  <h1 style ='color:orange;'> Welcome to Web Scraping </h1>
  Links:
  <a href="https://www.google.com" style ='color:red;'> Google </a> 
  <a class='classOne' href="https://www.yahoo.com"> Yahoo </a> 
  <a id='idOne' href="https://www.wikipedia.org" style ='color:blue;'> Wikipedia </a>
```

CSS 也可以使用外部样式表文件嵌入到 HTML 中：

```py
<link href="http://..../filename.css" rel="stylesheet" type="text/css">
```

尽管 CSS 用于 HTML 元素的外观，但 CSS 选择器（用于选择元素的模式）在抓取过程中经常起着重要作用。我们将在接下来的章节中详细探讨 CSS 选择器。

请访问[`www.w3.org/Style/CSS/`](https://www.w3.org/Style/CSS/)和[`www.`](https://www.w3schools.com/css/)[w3schools](https://www.w3schools.com/css/)[.com/css/](https://www.w3schools.com/css/)获取有关 CSS 的更详细信息。

# AngularJS

到目前为止，我们在本章中介绍了一些选定的与 Web 相关的技术。让我们通过介绍 AngularJS 来了解 Web 框架的概述。Web 框架涉及许多与 Web 相关的工具，并用于开发与采用最新方法的 Web 相关资源。

AngularJS（也被称为*Angular.js*或*Angular*）主要用于构建客户端 Web 应用程序。这是一个基于 JavaScript 的框架。AngularJS 是通过`<script>`标签添加到 HTML 中的，它将 HTML 属性扩展为指令，并将数据绑定为表达式。AngularJS 表达式用于将数据绑定到从静态或动态 JSON 资源中检索的 HTML 元素。AngularJS 指令以`ng-`为前缀。

AngularJS 与 HTML 一起用于动态内容开发。它提供了性能改进、测试环境、元素操作和数据绑定功能，并通过在文档、数据、平台和其他工具之间提供更加动态和灵活的环境，帮助构建基于**模型-视图-控制器**（**MVC**）框架的 Web 应用程序。

我们可以将外部 JavaScript 文件链接到我们的 HTML 文档中，如下所示：

```py
<!doctype html>
<html ng-app>
    <head>
        <script 
 src="https://ajax.googleapis.com/ajax/libs/angularjs/1.7.5/angular.min.js">
 </script>
    </head>
    <body>
        <div>
            <label> Place: </label>
            <input type="text" ng-model="place" placeholder="Visited place!">
            <label> Cost :</label>
            <input type="text" ng-model="price" placeholder="Ticket Price!">
            <br>
            <b>Wow! {{place}} for only {{price}}</b>
        </div>
    </body>
</html>
```

此外，我们可以将脚本和元素块一起包含在页面中，如下所示：

```py
<script>
     var app = angular.module('myContact', []);
     app.controller('myDiv', function($scope) {
         $scope.firstName = "Aasira";
         $scope.lastName = "Chapagain";
         $scope.college= "London Business School";
         $scope.subject= "Masters in Analytics and Management";
     });
</script>
<div ng-app="myContact" ng-controller="myDiv">
     First Name: <input type="text" ng-model="firstName"><br>
     Last Name: <input type="text" ng-model="lastName"><br>
     College Name: <input type="text" ng-model="college"><br>
     Subjects: <input type="text" ng-model="subject"><br>
     <br>
     Full Name: {{firstName + " " + lastName}}
     <br>
     Enrolled on {{college + " with " + subject}}
</div>
```

我们在这里提供的 AngularJS 及其工作方法的概述允许更灵活地追踪和遍历数据。

请访问 AngularJS（[`angularjs.org/`](https://angularjs.org/)和[`angular.io/`](https://angular.io/)）获取有关 AngularJS 的更详细信息。

前面讨论的技术是 Web 的一些核心组件；它们相互关联，相互依赖，以产生最终用户与之交互的网站或 Web 文档。在接下来的章节中，我们将识别脚本并进一步分析其中包含的代码。

在接下来的章节中，我们将探索 Web 内容，并寻找可以在 Web 页面内找到的数据，我们将在接下来的章节中使用 Python 编程语言提取这些数据。

# 网络数据查找技术

有各种技术可用于开发网站。使用 Web 浏览器向最终用户呈现的内容也可以存在于各种其他格式和模式中。

如前所述，动态生成或操作网页内容也是可能的。页面内容也可以包括使用 HTML 和相关技术呈现的静态内容，或者实时呈现和创建的内容。内容也可以使用第三方来源检索并呈现给最终用户。

# HTML 页面源代码

Web 浏览器用于基于客户端服务器的 GUI 交互，探索 Web 内容。浏览器地址栏提供了 Web 地址或 URL，并将请求的 URL 发送到服务器（主机），然后由浏览器接收响应，即加载。获取的响应或页面源代码可以进一步探索，并以原始格式搜索所需的内容。

用户可以自由选择他们的 Web 浏览器。我们将在大部分书中使用安装在 Windows **操作系统**（**OS**）上的 Google Chrome。

在抓取过程中，页面的 HTML 源将经常被打开和调查以获取所需的内容和资源。右键单击网页。然后会出现一个菜单，您可以在其中找到**查看页面源**选项。或者，按*Ctrl* + *U*。

# 案例 1

让我们通过以下步骤来看一个网页抓取的例子：

1.  在您选择的浏览器中打开[`www.google.com`](https://www.google.com)

1.  在搜索框中输入`Web Scraping`

1.  按*Enter*或点击页面上的谷歌搜索按钮

1.  您应该看到类似以下屏幕截图的内容：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/f1f50003-a26f-4f89-9631-da3c6f0965a7.png)

从谷歌搜索中获取网页抓取的搜索结果

谷歌已经为我们提供了我们所要求的搜索信息。这些信息以段落形式显示，还有许多链接。显示的信息是互动的、丰富多彩的，并且以维护的结构呈现，搜索内容采用了布局。

这是我们正在查看的前端内容。这些内容是根据我们与谷歌的互动动态提供给我们的。现在让我们查看一下提供给我们的原始内容。

1.  右键单击网页。然后会出现一个菜单，您可以在其中找到查看页面源的选项。或者，按*Ctrl* + *U*。在这里，将会打开一个新标签页，其中包含页面的 HTML 源代码。在浏览器的 URL 开头检查`view-source`：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/5e827c69-8c28-47f9-9b4d-43c0828f6864.png)

HTML 页面源：从谷歌搜索中获取网页抓取的搜索结果

我们现在正在访问上一个屏幕截图中显示的页面的 HTML 源代码。HTML 标签和 JavaScript 代码可以很容易地看到，但没有以正确的格式呈现。这些是浏览器呈现给我们的核心内容。

在页面源中搜索一些文本，在页面源中找到文本、链接和图片的位置。您将能够在 HTML 标签中找到页面源中的文本（但并不总是，我们将看到！）

网页开发可以使用各种技术和工具进行，正如我们在前面的部分中讨论的那样。浏览器显示的网页内容在探索其源代码时，可能并不总是存在于 HTML 标签中。内容也可能存在于脚本中，甚至在第三方链接上。这就是使得网页抓取经常具有挑战性的原因，因此需要存在于网页开发中的最新工具和技术。

# 案例 2

让我们探索另一个案例，使用我们在*案例 1*部分应用的浏览过程：

1.  在谷歌上搜索`2018 年美国最佳酒店`，并选择您喜欢的任何酒店名称。

1.  直接在谷歌中搜索酒店名称（或者您可以忽略前面的步骤）。例如，尝试`芝加哥半岛酒店`。

1.  谷歌将加载搜索酒店的详细信息以及地图和预订和评论部分。结果将类似于以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/64d47ab1-0606-484f-9f1c-f16c20086d7a.png)

芝加哥半岛酒店的谷歌搜索结果

1.  在左侧，您可以找到谷歌评论的链接。点击链接后，将会弹出一个新页面，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/6eb2771c-9ba2-492d-bae3-ac8f5f61d37b.png)

来自搜索页面的谷歌评论页面

1.  右键单击弹出的评论页面，选择查看页面源，或按*Ctrl* + *U*查看页面源。

尝试从页面源中找到用户的评论和回复文本。

# 开发者工具

开发者工具（或*DevTools*）现在嵌入在市面上大多数浏览器中。开发人员和最终用户都可以识别和定位在客户端-服务器通信期间使用的资源和搜索网页内容，或者在进行 HTTP 请求和响应时使用的资源。

DevTools 允许用户检查、创建、编辑和调试 HTML、CSS 和 JavaScript。它们还允许我们处理性能问题。它们有助于提取浏览器动态或安全呈现的数据。

DevTools 将用于大多数数据提取案例，以及类似于*页面源*部分中提到的*案例 2*。有关开发人员工具的更多信息，请探索这些链接：

+   Chrome DevTools ([`developers.google.com/web/tools/chrome-devtools/`](https://developers.google.com/web/tools/chrome-devtools/))

+   Firefox DevTools [(](https://developer.mozilla.org/son/docs/Tools)[`developer.mozilla.org/son/docs/Tools/`](https://developer.mozilla.org/son/docs/Tools)[)](https://developer.mozilla.org/son/docs/Tools)

在 Google Chrome 中，我们可以通过以下任一指示加载 DevTools：

+   只需按下*Ctrl* + *Shift* + *I*

+   另一个选项是右键单击页面，然后选择“检查”选项

+   或者，如果通过 Chrome 菜单访问开发者工具，请单击“更多工具”|“开发者工具”：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/23c63e2a-21ea-4cf7-b12d-7f57fca58987.png)

加载评论页面的 Chrome DevTools

上述屏幕截图显示了开发者工具面板：元素、控制台、网络、来源等。在我们的情况下，让我们从评论页面中找一些文本。按照这些步骤将允许我们找到它：

1.  在开发者工具中打开“网络”面板。

1.  选择“XHR”过滤器选项。（在“名称”面板下将找到列出的多个资源，如 HTML 文件、图像和 JSON 数据。）

1.  我们需要遍历“名称”窗格下的资源，寻找我们寻找的选择文本片段。（“响应”选项卡显示所选资源的内容。）

1.  找到以`reviewDialog?`开头的资源，其中包含搜索的文本。

这里概述的搜索评论文本的步骤是定位确切内容的最常用技术之一。当内容是动态获取的并且不在页面源中时，通常会遵循这些步骤。

开发者工具中有各种面板，与特定功能相关，用于提供给 Web 资源或进行分析，包括“来源”、“内存”、“性能”和“网络”。我们将探索在 Chrome DevTools 中找到的一些面板，如下所示：

在基于浏览器的 DevTools 中找到的面板的具体名称可能在所有浏览器中都不相同。

+   元素：显示所查看页面的 HTML 内容。用于查看和编辑 DOM 和 CSS，以及查找 CSS 选择器和 XPath。

HTML 元素显示或位于“元素”面板中，可能不会在页面源中找到。

+   控制台：用于运行和交互 JavaScript 代码，并查看日志消息：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/b32d8061-c74f-421f-b7ce-87a395d5b7fb.png)

Chrome DevTools 中的控制台面板

+   来源：用于导航页面，查看可用的脚本和文档来源。基于脚本的工具可用于任务，如脚本执行（即，恢复、暂停）、跳过函数调用、激活和停用断点，以及处理异常，如暂停异常（如果遇到）：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/18049d9e-2141-48e7-b88e-381fe583895f.png)

Chrome DevTools 的“来源”面板

+   网络：提供与 HTTP 请求和响应相关的资源，并显示加载页面时使用的网络资源。在网络功能选项中找到的资源，如记录数据到网络日志，捕获屏幕截图，过滤 Web 资源（JavaScript、图像、文档和 CSS），搜索 Web 资源，分组 Web 资源，也可用于调试任务：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/1161f4d4-ce23-4cfc-8b32-c5b200e418d2.png)

Chrome DevTools 网络面板

请求也可以按类型进行过滤：

+   **全部**：列出与网络相关的所有请求，包括文档请求、图像请求和字体和 CSS 请求。资源按加载顺序排列。

+   XHR：列出`XmlHttpRequest`对象，动态加载 AJAX 内容

+   JS：列出请求的脚本文件

+   CSS：列出请求的样式文件

+   Img：列出请求的图像文件

+   文档：列出请求的 HTML 或 Web 文档

+   其他：任何未列出的与请求相关的资源类型

对于先前列出的过滤选项，在 Name 面板中选择的资源有标签（标题、预览、响应、时间、Cookie）：

+   标题：加载特定请求的 HTTP 头数据。显示的信息包括请求 URL、请求方法、状态码、请求头、查询字符串参数和`POST`参数。

+   预览：加载响应的格式化预览。

+   响应：加载特定请求的响应。

+   时间：查看时间分解信息。

+   Cookie：加载 Name 面板中选择的资源的 cookie 信息。

从爬取的角度来看，DevTools Network 面板对于查找和分析 Web 资源非常有用。这些信息对于检索数据和选择处理这些资源的方法非常有用。

有关网络面板的更多信息，请访问[`developers.google.com/web/tools/chrome-devtools/network-performance/reference/`](https://developers.google.com/web/tools/chrome-devtools/network-performance/reference)和[`developer.mozilla.org/en-US/docs/Tools/Network_Monitor/`](https://developer.mozilla.org/en-US/docs/Tools/Network_Monitor)。网络面板提供了各种元素，下面将对其进行解释：

+   性能：可以记录屏幕截图页面和内存时间轴。获取的视觉信息用于优化网站速度，改善加载时间和分析运行时性能。在较早的 Chrome 版本中，性能面板提供的信息曾存在于一个名为时间轴的面板中：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/06c15469-51a3-4ce7-975f-3f26e8c6518e.png)

Chrome DevTools 中的性能面板

+   内存：在较早的 Chrome 版本中，这个面板也被称为面板配置文件。从这个面板获得的信息用于修复内存问题和跟踪内存泄漏。开发人员还使用性能和内存面板来分析整体网站性能。

+   应用程序：最终用户可以检查和管理所有加载的资源的存储，包括 cookie、会话、应用程序缓存、图像和数据库。

在探索 HTML 页面源代码和 DevTools 之后，我们现在大致知道可以在哪里探索或搜索数据。总的来说，爬取涉及从网页中提取数据，我们需要确定或定位携带我们想要提取的数据的资源。在进行数据探索和内容识别之前，计划和确定包含数据的页面 URL 或链接将是有益的。

用户可以选择任何 URL 进行爬取。指向单个页面的页面链接或 URL 也可能包含分页链接或将用户重定向到其他资源的链接。跨多个页面分布的内容需要通过识别页面 URL 来单独爬取。网站提供站点地图和`robots.txt`文件，其中包含用于爬取相关活动的链接和指令。

# 站点地图

`sitemap.xml`文件是一个包含与页面 URL 相关信息的 XML 文件。维护站点地图是通知搜索引擎网站包含的 URL 的简单方法。基于搜索引擎的脚本会爬取站点地图中的链接，并将找到的链接用于索引和各种用途，如搜索引擎优化（SEO）。

在站点地图中找到的 URL 通常包含额外的信息，如创建日期、修改日期、新 URL、已删除 URL 等。这些通常包含在 XML 标记中。在这种情况下，我们有`<sitemap>`和`<loc>`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/5ecbabfd-388d-4c18-ae7e-59ee938a15ea.png)

来自 https://www.samsclub.com/的站点地图内容

通过在 URL 中添加`sitemap.xml`来访问站点地图，例如，[`www.samsclub.com/sitemap.xml`](https://www.samsclub.com/sitemap.xml)。

并非所有网站都必须存在`sitemap.xml`。站点地图可能包含页面、产品、类别和内部站点地图文件的单独 URL，这些可以轻松地用于抓取目的，而不是从每个网站逐个探索网页链接并收集它们。

# robots.txt 文件

`robots.txt`，也称为机器人排除协议，是网站用于与自动脚本交换信息的基于 Web 的标准。一般来说，`robots.txt`包含有关网站上的 URL、页面和目录的指令，用于指导网页机器人（也称为**网络漫游者**、**爬虫**或**蜘蛛**）的行为，如允许、禁止、站点地图和爬行延迟。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/fec89d74-a850-4da6-bd74-76ad7df218d1.png)

来自 https://www.samsclub.com/的 robots.txt 文件

对于任何提供的网站地址或 URL，可以通过在 URL 中添加`robots.txt`来访问`robots.txt`文件，例如，`https://www.samsclub.com/robots.txt`或`https://www.test-domainname.com/robots.txt`。

如前面的屏幕截图所示（*来自 https://www.samsclub.com/的 robots.txt 文件*），在[`www.samsclub.com/robots.txt`](https://www.samsclub.com/robots.txt)中列出了允许、禁止和站点地图指令：

+   允许许可网页机器人访问它所携带的链接

+   Disallow 表示限制对给定资源的访问

+   User-agent: *表示列出的指令应由所有代理遵循

对于由网络爬虫和垃圾邮件发送者引起的访问违规，网站管理员可以采取以下步骤：

+   增强安全机制，限制对网站的未经授权访问

+   对被跟踪的 IP 地址施加阻止

+   采取必要的法律行动

网络爬虫应遵守文件中列出的指令，但对于正常的数据提取目的，除非爬行脚本妨碍网站流量，或者它们从网络中获取个人数据，否则不会施加限制。再次强调，并非每个网站都必须提供`robots.txt`文件。

有关指令和`robots.txt`的更多信息，请访问[`www.robotstxt.org/`](http://www.robotstxt.org/)。

# 总结

在本章中，我们探讨了一些与万维网相关的核心技术和工具，这些技术和工具对于网页抓取是必需的。

通过介绍 Web 开发工具来识别和探索内容，并寻找目标数据的页面 URL，是本章的主要重点。

在下一章中，我们将使用 Python 编程语言与网络进行交互，并探索主要的与网络相关的 Python 库，这些库将用于检查网络内容。

# 进一步阅读

+   AngularJS：[`www.angularjs.org`](https://www.angularjs.org), [`www.angular.io`](https://www.angular.io)

+   AJAX：[`api.jquery.com/jquery.ajax/`](http://api.jquery.com/jquery.ajax/), [`www.w3schools.com/js/js_ajax_intro.asp`](https://www.w3schools.com/js/js_ajax_intro.asp)

+   浏览器开发工具：[`developers.google.com/web/tools/chrome-devtools/`](https://developers.google.com/web/tools/chrome-devtools/), [`developer.mozilla.org/son/docs/Tools`](https://developer.mozilla.org/son/docs/Tools)

+   CSS：[`www.w3schools.com/css/`](https://www.w3schools.com/css/), [`www.w3.org/Style/CSS/`](https://www.w3.org/Style/CSS/)

+   Cookies：[`www.aboutcookies.org/`](https://www.aboutcookies.org/), [www.allaboutcookies.org](http://www.allaboutcookies.org/)

+   HTTP：[`www.w3.org/Protocols/`](https://www.w3.org/Protocols/), [`developer.mozilla.org/en-US/docs/Web/HTTP`](https://developer.mozilla.org/en-US/docs/Web/HTTP)

+   HTTP 方法：[`restfulapi.net/http-methods/`](https://restfulapi.net/http-methods/)

+   HTTP 标头的快速参考：[`jkorpela.fi/http.html`](http://jkorpela.fi/http.html)

+   面向开发人员的 Web 技术：[`developer.mozilla.org/en-US/docs/Web`](https://developer.mozilla.org/en-US/docs/Web)

+   标记系统和学术文本处理的未来：[`xml.coverpages.org/coombs.html`](http://xml.coverpages.org/coombs.html)

+   JSON Lines: [`jsonlines.org/`](http://jsonlines.org/)

+   jQuery: [`jquery.com/`](https://jquery.com/), [`www.w3schools.com/jquery/`](https://www.w3schools.com/jquery/)

+   JavaScript: [`developer.mozilla.org/en-US/docs/Web/JavaScript`](https://developer.mozilla.org/en-US/docs/Web/JavaScript), [`www.javascript.com/`](https://www.javascript.com/)

+   Robots Exclusion Protocol: [`www.robotstxt.org/`](http://www.robotstxt.org/)

+   逆向工程：[`insights.globalspec.com/article/7367/how-does-reverse-engineering-work`](https://insights.globalspec.com/article/7367/how-does-reverse-engineering-work)

+   站点地图：[`www.sitemaps.org/`](https://www.sitemaps.org/)

+   XML: [`www.w3schools.com/xml/`](https://www.w3schools.com/xml/), [`www.w3.org/XML/`](https://www.w3.org/XML/)


# 第二部分：开始网页抓取

在本节中，您将学习如何通过使用网页抓取和 Python 编程来规划、分析和处理来自目标网站的所需数据。将探讨有关有效工具和各种数据收集技术的信息。

本节包括以下章节：

+   第二章，Python 和 Web-使用 urllib 和 Requests

+   第三章，使用 LXML、XPath 和 CSS 选择器

+   第四章，使用 pyquery 进行网页抓取-一个 Python 库

+   第五章，使用 Scrapy 和 Beautiful Soup 进行网页抓取


# 第二章：Python 和 Web - 使用 urllib 和 Requests

从上一章，我们现在对 Web 抓取是什么，存在哪些核心开发技术以及我们可以计划在哪里或如何找到我们正在寻找的信息有了一个概念。

Web 抓取需要使用脚本或程序实施和部署的工具和技术。Python 编程语言包括一大批适用于与 Web 交互和抓取目的的库。在本章中，我们将使用 Python 与 Web 资源进行通信；我们还将探索并搜索要从 Web 中提取的内容。

本章还将详细介绍使用 Python 库，如`requests`和`urllib`。

特别是，我们将学习以下主题：

+   设置 Python 及其所需的库`requests`和`urllib`来加载 URL

+   `requests`和`urllib`的详细概述

+   实现 HTTP 方法（`GET`/`POST`）

我们假设您具有一些使用 Python 编程语言的基本经验。如果没有，请参考 W3schools 的 Python 教程（[`www.w3schools.com/python/default.asp`](https://www.w3schools.com/python/default.asp)）、Python 课程（[`python-course.eu/`](https://python-course.eu/)）或在 Google 上搜索*学习 Python 编程*。

# 技术要求

我们将使用已安装在 Windows 操作系统上的 Python 3.7.0。有很多选择的代码编辑器；选择一个方便使用并处理本章代码示例中使用的库的编辑器。我们将同时使用来自 JetBrains 的 PyCharm（社区版[`www.jetbrains.com/pycharm/download/download-thanks.html?platform=windows&code=PCC`](https://www.jetbrains.com/pycharm/download/download-thanks.html?platform=windows&code=PCC)）和 Python IDLE（[`www.python.org/downloads/`](https://www.python.org/downloads/)）。

要跟着本章进行，您需要安装以下应用程序：

+   Python 3.7.*或适合您操作系统的最新版本：[`www.python.org/downloads/`](https://www.python.org/downloads/)

+   `pip` Python 软件包管理：[`packaging.python.org/tutorials/installing-packages/`](https://packaging.python.org/tutorials/installing-packages/)

+   要么使用谷歌 Chrome，要么使用 Mozilla Firefox

+   JetBrains PyCharm 或 Visual Studio Code

本章所需的 Python 库如下：

+   `requests`

+   `urllib`

本章的代码文件可在 GitHub 上找到：[`github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python/tree/master/Chapter02`](https://github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python/tree/master/Chapter02)。

# 使用 Python 访问网络

Python 是一种用于编写各种类型应用程序的编程语言，从简单脚本到人工智能算法和 Web 框架。我们将使用 Python 编写脚本来从数据提取或抓取的角度访问我们感兴趣的 URL。

存在许多用于 HTTP 通信和与 Web 相关目的的 Python 库（包括`http`、`cookielib`、`urllib`、`requests`、`html`、`socket`、`json`、`xmlrpc`、`httplib2`和`urllib3`）。我们将探索并使用一些被程序员社区赞扬的用于 HTTP 访问或客户端-服务器通信的库。我们感兴趣使用的是`urllib`和`requests` Python 模块。这些库具有各种函数，可用于使用 Python 与 Web 通信并处理 HTTP 请求和响应。

为了立即开始一些编码任务并探索基于 Python 的模块，让我们在继续之前验证我们已经安装了所有想要的 Python 资源。

# 设置事物

假设 Python 已预先安装。如果没有，请访问[`www.python.org/downloads/`](https://www.python.org/downloads/)和[`www.python.org/download/other/`](https://www.python.org/download/other/)获取您操作系统的最新 Python 版本。关于一般设置和安装程序，请访问[`realpython.com/installing-python/`](https://realpython.com/installing-python/)了解如何在您选择的平台上安装 Python。我们将在这里使用 Windows 操作系统。

为了验证我们是否拥有所有所需的工具，请检查 Python 和`pip`是否已安装并且是否是最新版本。

`pip`包管理系统用于安装和管理用 Python 编写的软件包。有关安装 Python 软件包和`pip`的更多信息，请访问[`packaging.python.org/tutorials/installing-packages/`](https://packaging.python.org/tutorials/installing-packages/)。

我们将在 Windows 操作系统上使用 Python 3.7。按下 Windows + *R*打开运行框，输入`cmd`以获取命令行界面：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/c9e94300-8d7a-4f84-875d-c926ec32cce7.png)

在 Windows 操作系统上打开命令行界面

现在，转到您的根目录并键入以下命令：

```py
C:\> python –version
Python 3.7.0
```

上述命令将为我们提供当前系统上的 Python 版本。让我们获取一些关于我们正在使用的`pip`版本的信息。以下命令将显示当前的`pip`版本以及其位置：

```py
C:\> pip --version

pip 18.1 from c:\python37\lib\site-packages\pip (python 3.7)
```

在看到前面的响应后，我们很高兴继续进行。如果遇到“找不到应用程序”或“不被识别为内部或外部命令”的错误，则需要重新安装 Python 或检查安装过程中使用的正确驱动器。

始终建议检查系统和库的版本，并保持它们更新，除非需要特定版本。

要将`pip`更新到最新版本，请使用以下命令：

```py
C:\> python -m pip install --upgrade pip
```

您可以验证我们希望使用的库，即`requests`和`urllib`，可以从命令行或通过导入 Python IDE 并使用`help()`方法获取有关包的详细信息：

```py
C:\> pip install requests

Requirement already satisfied: requests in c:\python37\lib\site-packages (2.19.1)
```

如前面的代码所示，我们尝试安装`requests`，但命令返回“要求已满足”。`pip`命令在安装新库之前会检查系统上是否已存在安装。

在下面的代码块中，我们将使用 Python IDE 来导入`urllib`。我们将使用 Python 的内置`help()`方法查看其详细信息。

代码中的`>>>`符号表示使用 Python IDE；它接受代码或指令，并在下一行显示输出：

```py
>>> import urllib 
>>> help(urllib) #display documentation available for urllib

```

以下是输出：

```py
Help on package urllib:
NAME
 urllib
PACKAGE CONTENTS
 error
 parse
 request
 response
 robotparser
FILE
 c:\python37\lib\urllib\__init__.py
```

与之前的代码类似，让我们在 Python IDE 中导入`requests`：

```py
>>> import requests 
>>> requests.__version__ #display requests version 

'2.21.0'

>>> help(requests)   #display documentation available for requests

Help on package requests:
NAME
 requests
DESCRIPTION
 Requests HTTP Library
 ~~~~~~~~~~~~~~~~~~
 Requests is an HTTP library, written in Python, for human beings.
```

如果我们导入`urllib`或`requests`，并且这些库不存在，结果将会抛出错误：

```py
ModuleNotFoundError: No module named 'requests'
```

对于缺少的模块或在先前的情况下，首先安装模块；使用以下`pip`安装或升级。您可以按照以下方式从命令行安装它：

```py
C:\> pip install requests
```

您还可以使用`--upgrade`参数升级模块版本：

```py
C:\> pip install requests -–upgrade
```

# 加载 URL

现在我们已确认所需的库和系统要求，我们将继续加载 URL。在查找 URL 的内容时，还需要确认和验证已选择的所需内容的确切 URL。内容可以在单个网页上找到，也可以分布在多个页面上，并且可能并非始终是我们要寻找的 HTML 源。

我们将加载一些 URL 并使用一些任务来探索内容。

在使用 Python 脚本加载 URL 之前，还建议使用 Web 浏览器验证 URL 是否正常工作并包含我们正在寻找的详细信息。开发人员工具也可以用于类似的场景，如第一章中所讨论的*Web Scraping Fundamentals*的*Developer tools*部分。

**任务 1**：查看来自维基百科的最受欢迎网站列表相关的数据。我们将从页面源中识别*Site*、*Domain*和*Type*列中的数据。

我们将按照以下链接中的步骤来完成我们的任务（第三章将进行与数据提取相关的活动，*Using LXML, XPath and CSS Selectors*）：[`en.wikipedia.org/wiki/List_of_most_popular_websites`](https://en.wikipedia.org/wiki/List_of_most_popular_websites)。

搜索维基百科以获取我们正在寻找的信息。前面的链接可以在 Web 浏览器中轻松查看。内容以表格格式呈现（如下面的屏幕截图所示），因此可以通过重复使用选择、复制和粘贴操作，或者收集表格内的所有文本来收集数据。

然而，这样的操作不会导致我们感兴趣的内容以理想的格式显示，或者将需要在文本上执行额外的编辑和格式化任务才能实现所需的结果。我们也对从浏览器获取的页面源不感兴趣：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/ff896cba-9530-485c-bdd9-130ac843833d.png)

来自维基百科的页面，即 https://en.wikipedia.org/wiki/List_of_most_popular_websites

在确定包含我们需要的内容的链接后，让我们使用 Python 加载链接。我们正在请求链接，并希望看到由`urllib`和`requests`返回的响应：

1.  让我们使用`urllib`：

```py
>>> import urllib.request as req #import module request from urllib
>>> link = "https://en.wikipedia.org/wiki/List_of_most_popular_websites"
>>> response = req.urlopen(link)  #load the link using method urlopen()

>>> print(type(response))   #print type of response object
 <class 'http.client.HTTPResponse'>

>>> print(response.read()) #read response content
b'<!DOCTYPE html>\n<html class="client-nojs" lang="en" dir="ltr">\n<head>\n<meta charset="UTF-8"/>\n<title>List of most popular websites - Wikipedia</title>\n<script>…..,"wgCanonicalSpecialPageName":false,"wgNamespaceNumber":0,"wgPageName":"List_of_most_popular_websites","wgTitle":"List of most popular websites",……
```

`urllib.request`中的`urlopen()`函数已经传递了所选的 URL 或对 URL 进行的请求，并收到了`response`，即`HTTPResponse`。可以使用`read()`方法读取对请求的`response`。

2. 现在，让我们使用`requests`：

```py
>>> import requests
>>> link = "https://en.wikipedia.org/wiki/List_of_most_popular_websites"
>>> response = requests.get(link)

>>> print(type(response))
 <class 'requests.models.Response'>

>>> content = response.content #response content received
>>> print(content[0:150])  #print(content) printing first 150 character from content

b'<!DOCTYPE html>\n<html class="client-nojs" lang="en" dir="ltr">\n<head>\n<meta charset="UTF-8"/>\n<title>List of most popular websites - Wikipedia</title>'
```

在这里，我们使用`requests`模块来加载页面源，就像我们使用`urllib`一样。`requests`使用`get()`方法，该方法接受 URL 作为参数。对于这两个示例，也已经检查了`response`类型。

在前面的代码块中显示的输出已经被缩短。您可以在[`github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python`](https://github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python)找到此代码文件。

在上述示例中，页面内容或`response`对象包含了我们正在寻找的详细信息，即*Site*、*Domain*和*Type*列。

我们可以选择任何一个库来处理 HTTP 请求和响应。关于这两个 Python 库的详细信息和示例将在下一节*URL handling and operations with urllib and requests*中提供。

让我们看一下下面的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/6ea4c570-0bf3-4c2b-b970-a0978b106125.png)

使用 Python 库查看维基百科页面内容

进一步的活动，如处理和解析，可以应用于这样的内容，以提取所需的数据。有关进一步处理工具/技术和解析的更多详细信息可以在第三章、*Using LXML, XPath, and CSS Selectors*，第四章、*Scraping Using pyquery – a Python Library*和第五章、*Web Scraping Using Scrapy and Beautiful Soup*中找到。

**任务 2**：使用`urllib`和`requests`加载并保存来自[`www.samsclub.com/robots.txt`](https://www.samsclub.com/robots.txt)和[`www.samsclub.com/sitemap.xml`](https://www.samsclub.com/sitemap.xml)的页面内容。

通常，网站在其根路径中提供文件（有关这些文件的更多信息，请参阅第一章，*网络抓取基础知识*，*网络数据查找技术*部分）：

+   `robots.txt`：其中包含爬虫、网络代理等的信息

+   `sitemap.xml`：其中包含最近修改的文件、发布的文件等的链接

从*任务 1*中，我们能够加载 URL 并检索其内容。将内容保存到本地文件并使用文件处理概念将在此任务中实现。将内容保存到本地文件并处理内容，如解析和遍历等任务，可以非常快速，甚至可以减少网络资源：

1.  使用`urllib`加载并保存来自[`www.samsclub.com/robots.txt`](https://www.samsclub.com/robots.txt)的内容：

```py
>>> import urllib.request 

>>> urllib.request.urlretrieve('https://www.samsclub.com/robots.txt')
('C:\\Users\\*****\AppData\\Local\\Temp\\tmpjs_cktnc', <http.client.HTTPMessage object at 0x04029110>)

>>> urllib.request.urlretrieve(link,"testrobots.txt") #urlretrieve(url, filename=None)
('testrobots.txt', <http.client.HTTPMessage object at 0x04322DF0>)
```

`urlretrieve()`函数，即`urlretrieve(url, filename=None, reporthook=None, data=None)`，从`urllib.request`返回一个包含文件名和 HTTP 头的元组。如果没有给出路径，可以在`C:\\Users..Temp`目录中找到此文件；否则，文件将在当前工作目录中生成，文件名由`urlretrieve()`方法的第二个参数提供。在前面的代码中，这是`testrobots.txt`：

```py
>>> import urllib.request
>>> import os
>>> content = urllib.request.urlopen('https://www.samsclub.com/robots.txt').read() #reads robots.txt content from provided URL

>>> file = open(os.getcwd()+os.sep+"contents"+os.sep+"robots.txt","wb") #Creating a file robots.txt inside directory 'contents' that exist under current working directory (os.getcwd()) 

>>> file.write(content) #writing content to file robots.txt opened in line above. If the file doesn't exist inside directory 'contents', Python will throw exception "File not Found"

>>> file.close() #closes the file handle
```

在前面的代码中，我们正在读取 URL 并使用文件处理概念编写找到的内容。

1.  使用`requests`加载并保存来自[`www.samsclub.com/sitemap.xml`](https://www.samsclub.com/sitemap.xml)的内容：

```py
>>> link="https://www.samsclub.com/sitemap.xml"
>>> import requests
>>> content = requests.get(link).content
>>> content 

b'<?xml version="1.0" encoding="UTF-8"?>\n<sitemapindex >\n<sitemap><loc>https://www.samsclub.com/sitemap_categories.xml</loc></sitemap>\n<sitemap><loc>https://www.samsclub.com/sitemap_products_1.xml</loc></sitemap>\n<sitemap><loc>https://www.samsclub.com/sitemap_products_2.xml</loc></sitemap>\n<sitemap><loc>https://www.samsclub.com/sitemap_locators.xml</loc></sitemap>\n</sitemapindex>'

>>> file = open(os.getcwd()+os.sep+"contents"+os.sep+"sitemap.xml","wb") #Creating a file robots.txt inside directory 'contents' that exist under current working directory (os.getcwd()) 

>>> file.write(content) #writing content to file robots.txt opened in line above. If the file doesn't exist inside directory 'contents', Python will throw exception "File not Found"

>>> file.close() #closes the file handle
```

在这两种情况下，我们都能够从相应的 URL 中找到内容并将其保存到各自的文件和位置。前面的代码中的内容被发现为字节文字，例如`b'<!DOCTYPE …`或`b'<?xml`。页面内容也可以以文本格式检索，例如`requests.get(link).text`。

我们可以使用`decode()`方法将字节转换为字符串，使用`encode()`方法将字符串转换为字节，如下面的代码所示：

```py
>>> link="https://www.samsclub.com/sitemap.xml"
>>> import requests
>>> content = requests.get(link).text  #using 'text'
>>> content

'<?xml version="1.0" encoding="UTF-8"?>\n<sitemapindex >\n<sitemap><loc>https://www.samsclub.com/sitemap_categories.xml</loc></sitemap>\n<sitemap><loc>https://www.samsclub.com/sitemap_products_1.xml</loc></sitemap>\n<sitemap><loc>https://www.samsclub.com/sitemap_products_2.xml</loc></sitemap>\n<sitemap><loc>https://www.samsclub.com/sitemap_locators.xml</loc></sitemap>\n</sitemapindex>' >>> content = requests.get(link).content 
>>> content.decode() # decoding 'content' , decode('utf-8')

'<?xml version="1.0" encoding="UTF-8"?>\n<sitemapindex >\n<sitemap><loc>https://www.samsclub.com/sitemap_categories.xml</loc></sitemap>\n<sitemap><loc>https://www.samsclub.com/sitemap_products_1.xml</loc></sitemap>\n<sitemap><loc>https://www.samsclub.com/sitemap_products_2.xml</loc></sitemap>\n<sitemap><loc>https://www.samsclub.com/sitemap_locators.xml</loc></sitemap>\n</sitemapindex>'
```

在处理各种域和文档类型时，识别适当的字符集或`charset`是很重要的。要识别适当的`charset`编码类型，我们可以通过使用`content-type`或`charset`从页面源中寻求`<meta>`标签的帮助。

从页面源中识别带有`charset`属性的`<meta>`标签，如下面的屏幕截图所示（或`<meta http-equiv="content-type" content="text/html; charset=utf-8">`：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/a224b37e-d00d-44a2-a460-7fcb132b97eb.png)

从文档响应或页面源中识别字符集

此外，`<meta http-equiv="content-type" content="text/html; charset=utf-8">`的内容可以从响应头中获取，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/5b46e1f3-ee12-4967-8388-4b10b4f82ad1.png)通过浏览器 DevTools、Network 面板、Headers 选项卡和响应头识别字符集

使用 Python 代码，我们可以在 HTTP 头中找到`charset`：

```py
>>> import urllib.request
>>> someRequest = urllib.request.urlopen(URL) #load/Open the URL
>>> urllib.request.getheaders() #Lists all HTTP headers. 

>>> urllib.request.getheader("Content-Type") #return value of header 'Content-Type'

'text/html; charset=ISO-8859-1' or 'utf-8'
```

识别的`charset`将用于使用`requests.get(link).content.decode('utf-8')`进行编码和解码。

Python 3.0 使用*文本*和(二进制)*数据*的概念，而不是 Unicode 字符串和 8 位字符串。所有文本都是 Unicode；然而，*编码*的 Unicode 被表示为二进制数据。用于保存文本的类型是`str`([`docs.python.org/3/library/stdtypes.html#str`](https://docs.python.org/3/library/stdtypes.html#str))，用于保存数据的类型是 bytes([`docs.python.org/3/library/stdtypes.html#bytes`](https://docs.python.org/3/library/stdtypes.html#bytes))。有关 Python 3.0 的更多信息，请访问[`docs.python.org/3/whatsnew/3.0.html`](https://docs.python.org/3/whatsnew/3.0.html)。

在本节中，我们设置并验证了我们的技术要求，并探索了 URL 加载和内容查看。在下一节中，我们将探索 Python 库，找到一些有用的函数及其属性。

# 使用 urllib 和 requests 进行 URL 处理和操作

对于从网页中提取数据的主要动机，需要使用 URL。在我们迄今为止看到的示例中，我们注意到 Python 与其源或内容通信时使用了一些非常简单的 URL。网络爬虫过程通常需要使用来自不同域的不同格式或模式的 URL。

开发人员可能还会面临许多情况，需要对 URL 进行操作（更改、清理）以便快速方便地访问资源。URL 处理和操作用于设置、更改查询参数或清理不必要的参数。它还传递了所需的请求标头和适当值，并确定了适当的 HTTP 方法来进行请求。您将发现许多与 URL 相关的操作，这些操作可以使用浏览器 DevTools 或网络面板进行识别。

`urllib`和`requests` Python 库将贯穿本书使用，处理 URL 和基于网络的客户端-服务器通信。这些库提供了各种易于使用的函数和属性，我们将探索一些重要的函数和属性。

# urllib

`urllib`库是一个标准的 Python 包，它收集了几个模块，用于处理与 HTTP 相关的通信模型。`urllib`内部的模块经过特别设计，包含处理各种类型的客户端-服务器通信的函数和类。

类似命名的包也存在，如`urllib2`，一个可扩展的库，以及`urllib3`，一个功能强大的 HTTP 客户端，解决了 Python 标准库中缺少的功能。

处理 URL 请求和响应的两个最重要的`urllib`模块如下。我们将在本章和接下来的章节中使用这些模块：

+   `urllib.request`：用于打开和读取 URL 以及请求或访问网络资源（cookie、身份验证等）

+   `urllib.response`：该模块用于提供对生成的请求的响应

存在许多函数和公共属性来处理与 HTTP 请求相关的请求信息和处理响应数据，例如`urlopen()`、`urlretrieve()`、`getcode()`、`getheaders()`、`getheader()`、`geturl()`、`read()`、`readline()`等等。

我们可以使用 Python 内置的`dir()`函数来显示模块的内容，例如其类、函数和属性，如下面的代码所示：

```py
>>> import urllib.request
>>> dir(urllib.request) #list features available from urllib.request

['AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'AbstractHTTPHandler', 'BaseHandler', 'CacheFTPHandler', 'ContentTooShortError', 'DataHandler', 'FTPHandler', 'FancyURLopener', 'FileHandler', 'HTTPBasicAuthHandler', 'HTTPCookieProcessor',....'Request', 'URLError', 'URLopener',......'pathname2url', 'posixpath', 'proxy_bypass', 'proxy_bypass_environment', 'proxy_bypass_registry', 'quote', 're', 'request_host', 'socket', 'splitattr', 'splithost', 'splitpasswd', 'splitport', 'splitquery', 'splittag', 'splittype', 'splituser', 'splitvalue', 'ssl', 'string', 'sys', 'tempfile', 'thishost', 'time', 'to_bytes', 'unquote', 'unquote_to_bytes', 'unwrap', 'url2pathname', 'urlcleanup', 'urljoin', 'urlopen', 'urlparse', 'urlretrieve', 'urlsplit', 'urlunparse', 'warnings']
```

`urlopen()`函数接受 URL 或`urllib.request.Request`对象（如`requestObj`），并通过`urllib.response`的`read()`函数返回响应，如下面的代码所示：

```py
>>> import urllib.request
>>> link='https://www.google.com' [](https://www.google.com) 
>>> linkRequest = urllib.request.urlopen(link) #open link
>>> print(type(linkRequest)) #object type
 <class 'http.client.HTTPResponse'> [](https://www.google.com) 
>>> linkResponse = urllib.request.urlopen(link).read() #open link and read content
>>> print(type(linkResponse))
 <class 'bytes'>
 [](https://www.google.com) >>> requestObj = urllib.request.Request('https:/www.samsclub.com/robots.txt')
>>> print(type(requestObj)) #object type
 <class 'urllib.request.Request'>

>>> requestObjResponse = urllib.request.urlopen(requestObj).read()
>>> print(type(requestObjResponse))  #object type
 <class 'bytes'>
```

`linkRequest`和`requestObj`从`urlopen()`函数和类请求返回的对象类型是不同的。还创建了`linkResponse`和`requestObjResponse`对象，其中包含`urllib.response`的`read()`函数的信息。

通常，`urlopen()`用于从 URL 读取响应，而`urllib.request.Request`用于发送额外的参数，如`data`或`headers`，甚至指定 HTTP 方法并检索响应。可以如下使用：

`urllib.request.Request(url, data=None, headers={}, origin_req_host=None, unverifiable=False, method=None)`

`urllib.response`及其函数，如`read()`和`readline()`，与`urllib.request`对象一起使用。

如果所做的请求成功并从正确的 URL 收到响应，我们可以检查 HTTP 状态码，使用的 HTTP 方法，以及返回的 URL 来查看描述：

+   `getcode()` 返回 HTTP 状态码。如下面的代码所示，也可以使用 `code` 和 `status` 公共属性获得相同的结果：

```py
>>> linkRequest.getcode()  #can also be used as: linkRequest.code or linkRequest.status 

 200
```

+   `geturl()` 返回当前的 URL。有时很方便验证是否发生了任何重定向。`url` 属性可用于类似的目的：

```py
>>> linkRequest.geturl()   # can also be used as: linkRequest.url

 'https://www.google.com'
```

+   `_method` 返回一个 HTTP 方法；`GET` 是默认响应：

```py
>>> linkRequest._method 
'GET'
```

+   `getheaders()` 返回一个包含 HTTP 头的元组列表。如下面的代码所示，我们可以从输出中确定有关 cookie、内容类型、日期等的值：

```py
>>> linkRequest.getheaders()

[('Date','Sun, 30 Dec 2018 07:00:25 GMT'),('Expires', '-1'),('Cache-Control','private, max-age=0'),('Content-Type','text/html; charset=ISO-8859-1'),('P3P', 'CP="This is not a P3P policy! See g.co/p3phelp for more info."'),('Server', 'gws'),('X-XSS-Protection', '1; mode=block'),('X-Frame-Options','SAMEORIGIN'),('Set-Cookie', '1P_JAR=…..; expires=Tue, 29-Jan-2019 07:00:25 GMT; path=/; domain=.google.com'),('Set-Cookie 'NID=152=DANr9NtDzU_glKFRgVsOm2eJQpyLijpRav7OAAd97QXGX6WwYMC59dDPe.; expires=Mon, 01-Jul-2019 07:00:25 GMT; path=/; domain=.google.com; HttpOnly'),('Alt-Svc', 'quic=":443"; ma=2592000; v="44,43,39,35"'),('Accept-Ranges', 'none'),('Vary', 'Accept-Encoding'),('Connection', 'close')] 
```

+   当使用 `getheader()` 传递所需的头元素时，也可以检索单个基于请求的头，如下面的代码所示。在这里，我们可以看到我们可以获取 `Content-Type` 头的值。相同的结果也可以使用 `info()` 函数实现：

```py
>>> linkRequest.getheader("Content-Type") 

 'text/html; charset=ISO-8859-1'

>>> linkRequest.info()["content-type"]

 'text/html; charset=ISO-8859-1'
```

我们已经使用了代码块，并找到了与我们的请求和响应相关的输出。Web 浏览器还允许我们使用浏览器 DevTools（基于浏览器的开发人员工具）跟踪请求/响应相关的信息。

以下截图显示了网络面板和文档选项卡，其中包括头选项。其中包含各种部分，如常规、响应头和请求头。头选项中可以找到基本的请求和响应相关信息：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/b497f7dc-d4f4-4734-93d2-a91aa064ef87.png)

网络面板和文档选项卡显示了常规和请求头信息

`urllib.error` 处理 `urllib.request` 引发的异常。例如，`URLError` 和 `HTTPError` 可能会为请求引发异常。以下代码演示了 `urllib.error` 的使用：

异常处理处理编程中的错误处理和管理。使用异常处理的代码也被认为是一种有效的技术，并经常被推荐用于适应。

```py
>>> import urllib.request as request
>>> import urllib.error as error

>>> try:  #attempting an error case
 request.urlopen("https://www.python.ogr") #wrong URL is passed to urlopen()
 except error.URLError as e:
 print("Error Occurred: ",e.reason)

Error Occurred: [Errno 11001] getaddrinfo failed #output
```

`urllib.parse` 用于编码/解码请求（数据）或链接，添加/更新头，并分析、解析和操作 URL。解析的 URL 字符串或对象使用 `urllib.request` 处理。

此外，`urlencode()`、`urlparse()`、`urljoin()`、`urlsplit()`、`quote_plus()` 是 `urllib.parse` 中可用的一些重要函数，如下面的代码所示：

```py
>>> import urllib.parse as urlparse
>>> print(dir(urlparse)) #listing features from urlparse
```

我们得到以下输出：

```py

['DefragResult', 'DefragResultBytes', 'MAX_CACHE_SIZE', 'ParseResult', 'ParseResultBytes', 'Quoter', 'ResultBase', 'SplitResult', 'SplitResultBytes', .........'clear_cache', 'collections', 'namedtuple', 'non_hierarchical', 'parse_qs', 'parse_qsl', 'quote', 'quote_from_bytes', 'quote_plus', 're', 'scheme_chars', 'splitattr', 'splithost', 'splitnport', 'splitpasswd', 'splitport', 'splitquery', 'splittag', 'splittype', 'splituser', 'splitvalue', 'sys', 'to_bytes', 'unquote', 'unquote_plus', 'unquote_to_bytes', 'unwrap', 'urldefrag', 'urlencode', 'urljoin', 'urlparse', 'urlsplit', 'urlunparse', 'urlunsplit', 'uses_fragment', 'uses_netloc', 'uses_params', 'uses_query', 'uses_relative']
```

`urllib.parse` 中的 `urlsplit()` 函数将传递的 URL 拆分为 `namedtuple` 对象。元组中的每个名称标识 URL 的部分。这些部分可以分开并在其他变量中检索和根据需要使用。以下代码实现了 `urlsplit()` 用于 `amazonUrl`：

```py
>>> amazonUrl ='https://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3Dstripbooks-intl-ship&field-keywords=Packt+Books'

>>> print(urlparse.urlsplit(amazonUrl)) #split amazonURL
SplitResult(scheme='https', netloc='www.amazon.com', path='/s/ref=nb_sb_noss', query='url=search-alias%3Dstripbooks-intl-ship&field-keywords=Packt+Books', fragment='')

>>> print(urlparse.urlsplit(amazonUrl).query) #query-string from amazonURL
'url=search-alias%3Dstripbooks-intl-ship&field-keywords=Packt+Books'

>>> print(urlparse.urlsplit(amazonUrl).scheme) #return URL scheme
'https'
```

使用 `urllib.parse` 中的 `urlparse()` 函数会得到 `ParseResult` 对象。与 `urlsplit()` 相比，它在检索 URL 中的参数（`params` 和 `path`）方面有所不同。以下代码打印了从 `urlparse()` 中获取的对象：

```py
>>> print(urlparse.urlparse(amazonUrl)) #parsing components of amazonUrl

 ParseResult(scheme='https', netloc='www.amazon.com', path='/s/ref=nb_sb_noss', params='', query='url=search-alias%3Dstripbooks-intl-ship&field-keywords=Packt+Books', fragment='')
```

让我们确认 `urlparse()` 和 `urlsplit()` 之间的区别。创建的 `localUrl` 使用 `urlsplit()` 和 `urlparse()` 进行解析。`params` 仅在 `urlparse()` 中可用：

```py
import urllib.parse as urlparse
>>> localUrl= 'http://localhost/programming/books;2018?browse=yes&sort=ASC#footer'

>>> print(urlparse.urlsplit(localUrl))
SplitResult(scheme='http', netloc='localhost', path='/programming/books;2018', query='browse=yes&sort=ASC', fragment='footer')

>>> parseLink = urlparse.urlparse(localUrl)
ParseResult(scheme='http', netloc='localhost', path='/programming/books', params='2018', query='browse=yes&sort=ASC', fragment='footer')

>>> print(parseLink.path) #path without domain information
 '/programming/books'

>>> print(parseLink.params) #parameters 
 '2018'

>>> print(parseLink.fragment) #fragment information from URL
 'footer'
```

基本上，`urllib.request.Request` 接受数据和与头相关的信息，`headers` 可以使用 `add_header()` 赋值给一个对象；例如，`object.add_header('host','hostname')` 或 `object.add_header('referer','refererUrl')`。

为了请求 `data`，需要使用 `Query Information` 或 `URL arguments` 作为附加到所需 URL 的键值对信息。这样的 URL 通常使用 HTTP GET 方法处理。传递给请求对象的查询信息应使用 `urlencode()` 进行编码。

`urlencode()` 确保参数符合 W3C 标准并被服务器接受。`parse_qs()` 将百分比编码的查询字符串解析为 Python 字典。以下代码演示了使用 `urlencode()` 的示例：

```py
>>> import urllib.parse as urlparse
>>> data = {'param1': 'value1', 'param2': 'value2'}

>>> urlparse.urlencode(data)
 'param1=value1&param2=value2'

>>> urlparse.parse_qs(urlparse.urlencode(data))
 {'param1': ['value1'], 'param2': ['value2']}

>>> urlparse.urlencode(data).encode('utf-8')
 b'param1=value1&param2=value2'
```

在处理请求发送到服务器之前，您可能还需要对 URL 中的特殊字符进行编码：

请注意，`urllib.parse`包含`quote()`、`quote_plus()`和`unquote()`函数，这些函数允许无误的服务器请求：

+   `quote()`通常应用于 URL 路径（与`urlsplit()`或`urlparse()`一起列出）或在传递给`urlencode()`之前使用保留和特殊字符（由 RFC 3986 定义）进行查询，以确保服务器的可接受性。默认编码使用`UTF-8`进行。

+   `quote_plus()`还对特殊字符、空格和 URL 分隔符进行编码。

+   `unquote()`和`unquote_plus()`用于恢复使用`quote()`和`quote_plus()`应用的编码。

这些函数在以下代码中进行了演示：

```py
>>> import urllib.parse as urlparse
>>> url="http://localhost:8080/~cache/data file?id=1345322&display=yes&expiry=false"

>>> urlparse.quote(url) 
 'http%3A//localhost%3A8080/~cache/data%20file%3Fid%3D1345322%26display%3Dyes%26expiry%3Dfalse'

>>> urlparse.unquote(url)
 'http://localhost:8080/~cache/data file?id=1345322&display=yes&expiry=false'

>>> urlparse.quote_plus(url) 'http%3A%2F%2Flocalhost%3A8080%2F~cache%2Fdata+file%3Fid%3D1345322%26display%3Dyes%26expiry%3Dfalse' 

>>> urlparse.unquote_plus(url)
 'http://localhost:8080/~cache/data file?id=1345322&display=yes&expiry=false'
```

`urllib.parse`中的`urljoin()`函数有助于从提供的参数中获取 URL，如下面的代码所示：

```py
>>> import urllib.parse as urlparse

>>> urlparse.urljoin('http://localhost:8080/~cache/','data file') #creating URL
 'http://localhost:8080/~cache/data file'

>>> urlparse.urljoin('http://localhost:8080/~cache/data file/','id=1345322&display=yes')
 'http://localhost:8080/~cache/data file/id=1345322&display=yes'
```

`urllib.robotparser`，顾名思义，帮助解析`robots.txt`并识别基于代理的规则。有关`robots.txt`的更详细信息，请参阅第一章，*网络爬虫基础*，*网络数据查找技术*部分。

如下面的代码所示，`par`是`RobotFileParser`的对象，可以通过`set_url()`函数设置 URL。它还可以使用`read()`函数读取内容。诸如`can_fetch()`的函数可以返回对评估条件的布尔答案：

```py
>>> import urllib.robotparser as robot
>>> par = robot.RobotFileParser()
>>> par.set_url('https://www.samsclub.com/robots.txt') #setting robots URL
>>> par.read()  #reading URL content

>>> print(par)
User-agent: *
Allow: /sams/account/signin/createSession.jsp
Disallow: /cgi-bin/
Disallow: /sams/checkout/
Disallow: /sams/account/
Disallow: /sams/cart/
Disallow: /sams/eValues/clubInsiderOffers.jsp
Disallow: /friend
Allow: /sams/account/referal/

>>> par.can_fetch('*','https://www.samsclub.com/category') #verify if URL is 'Allow' to Crawlers 
True

>>> par.can_fetch('*','https://www.samsclub.com/friend')
False
```

正如我们所看到的，当使用`can_fetch()`函数传递`https://www.samsclub.com/friend`时，返回`False`，从而满足了`robots.txt`中找到的`Disallow: /friend`指令。同样，`https://www.samsclub.com/category`返回`True`，因为没有列出限制类别 URL 的指令。

然而，使用`urllib.request`存在一些限制。在使用`urlopen()`和`urlretrieve()`等函数时可能会出现基于连接的延迟。这些函数返回原始数据，需要在它们可以在爬取过程中使用之前转换为解析器所需的类型。

部署线程或线程在处理 HTTP 请求和响应时被认为是一种有效的技术。

# 请求

`requests` HTTP Python 库于 2011 年发布，是近年来开发人员中最著名的 HTTP 库之一。

*Requests 是一个优雅而简单的 Python HTTP 库，专为人类而建*。（来源：[`2.python-requests.org/en/master/`](https://2.python-requests.org/en/master/)）。

有关`requests`的更多信息，请访问[`docs.python-requests.org/en/master/`](http://docs.python-requests.org/en/master/)。

与 Python 中的其他 HTTP 库相比，`requests`在处理 HTTP 方面的功能能力得到了高度评价。它的一些功能如下：

+   简短、简单和可读的函数和属性

+   访问各种 HTTP 方法（GET、POST 等）

+   摆脱手动操作，如编码表单值

+   处理查询字符串

+   自定义标头

+   会话和 cookie 处理

+   处理 JSON 请求和内容

+   代理设置

+   部署编码和合规性

+   基于 API 的链接标头

+   原始套接字响应

+   超时等等...

我们将使用`requests`库并访问一些其属性。`requests`中的`get()`函数用于向提供的 URL 发送 GET HTTP 请求。返回的对象是`requests.model.Response`类型，如下面的代码所示：

```py
>>> import requests
>>> link="http://www.python-requests.org"
>>> r = requests.get(link)

>>> dir(r)
['__attrs__', '__bool__', '__class__'......'_content', '_content_consumed', '_next', 'apparent_encoding', 'close', 'connection', 'content', 'cookies', 'elapsed', 'encoding', 'headers', 'history', 'is_permanent_redirect', 'is_redirect', 'iter_content', 'iter_lines', 'json', 'links', 'next', 'ok', 'raise_for_status', 'raw', 'reason', 'request', 'status_code', 'text', 'url']

>>> print(type(r)) 
<class 'requests.models.Response'>
```

`requests`库还支持 HTTP 请求，如`PUT`、`POST`、`DELETE`、`HEAD`和`OPTIONS`，分别使用`put()`、`post()`、`delete()`、`head()`和`options()`方法。

以下是一些`requests`属性，以及对每个属性的简要解释：

+   `url`输出当前 URL

+   使用`status_code`找到 HTTP 状态代码

+   `history`用于跟踪重定向：

```py
>>> r.url #URL of response object`
 'http://www.python-requests.org/en/master/'

>>> r.status_code #status code
 200

>>> r.history #status code of history event
 [<Response [302]>]
```

我们还可以获取一些在使用开发人员工具时发现的细节，例如 HTTP 标头、编码等等：

+   `headers`返回与响应相关的 HTTP 标头

+   `requests.header`返回与请求相关的 HTTP 标头

+   `encoding`显示从内容中获取的`charset`：

```py
>>> r.headers #response headers with information about server, date.. 
{'Transfer-Encoding': 'chunked', 'Content-Type': 'text/html', 'Content-Encoding': 'gzip', 'Last-Modified': '....'Vary': 'Accept-Encoding', 'Server': 'nginx/1.14.0 (Ubuntu)', 'X-Cname-TryFiles': 'True', 'X-Served': 'Nginx', 'X-Deity': 'web02', 'Date': 'Tue, 01 Jan 2019 12:07:28 GMT'}

>>> r.headers['Content-Type'] #specific header Content-Type
 'text/html'

>>> r.request.headers  #Request headers 
{'User-Agent': 'python-requests/2.21.0', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}

>>> r.encoding  #response encoding
 'ISO-8859-1'
```

可以使用`content`以字节形式检索页面或响应内容，而`text`返回一个`str`字符串：

```py
>>> r.content[0:400]  #400 bytes characters

b'\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"\n ....... <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />\n <title>Requests: HTTP for Humans\xe2\x84\xa2 — Requests 2.21.0 documentation'

>>> r.text[0:400]  #sub string that is 400 string character from response

'\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"\n......\n <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />\n <title>Requests: HTTP for Humansâ\x84¢ — Requests 2.21.0 documentation'
```

此外，`requests`还通过在`get()`请求中使用`stream`参数返回服务器的`raw`套接字响应。我们可以使用`raw.read()`函数读取原始响应：

```py
>>> r = requests.get(link,stream=True) #raw response

>>> print(type(r.raw))   #type of raw response obtained
 <class 'urllib3.response.HTTPResponse'>

>>> r.raw.read(100)  #read first 100 character from raw response
 b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\xed}[o\xdcH\x96\xe6{\xfe\x8a\xa8\xd4\xb4%O\x8bL2/JI\x96\xb2Z\x96e[U\xbe\xa8-\xb9\xaa\x1b\x85^!\x92\x8c\xcc\xa4\xc5$Y\xbc(\x95\xae)\xa0\x1e\x06\x18\xcc\xf3\xce\xcb\x00\xbbX`\x16\xd8\xc7\xc5>\xed\xeb\x02\xfb3f_\x16\xf5\x0b\xf6'\xec9'\x82\x97\xbc\xc9\xb2+#g"
```

使用`raw`属性接收的原始响应是未经转换或自动解码的原始字符字节。

`requests`使用其内置解码器非常有效地处理 JSON 数据。正如我们所看到的，具有 JSON 内容的 URL 可以使用`requests`进行解析并根据需要使用：

```py
>>> import requests
>>> link = "https://feeds.citibikenyc.com/stations/stations.json"
>>> response = requests.get(link).json()

>>> for i in range(10): #read 10 stationName from JSON response.
 print('Station ',response['stationBeanList'][i]['stationName'])

Station W 52 St & 11 Ave
Station Franklin St & W Broadway
Station St James Pl & Pearl St
........
Station Clinton St & Joralemon St
Station Nassau St & Navy St
Station Hudson St & Reade St
```

请注意，`requests`使用`urllib3`进行会话和原始套接字响应。在撰写本文时，`requests`版本 2.21.0 可用。

爬取脚本可能使用任何提到的或可用的 HTTP 库来进行基于 Web 的通信。大多数情况下，来自多个库的函数和属性将使这个任务变得容易。在下一节中，我们将使用`requests`库来实现 HTTP（`GET`/`POST`）方法。

# 实现 HTTP 方法

通常，网页与用户或读者之间的基于 Web 的交互或通信是这样实现的：

+   用户或读者可以访问网页阅读或浏览呈现给他们的信息

+   用户或读者还可以通过 HTML 表单提交某些信息到网页，比如搜索、登录、用户注册、密码恢复等

在本节中，我们将使用`requests` Python 库来实现常见的 HTTP 方法（`GET`和`POST`），执行我们之前列出的基于 HTTP 的通信场景。

# GET

请求信息的一种命令方式是使用安全方法，因为资源状态不会被改变。`GET`参数，也称为查询字符串，在 URL 中是可见的。它们使用`?`附加到 URL，并以`key=value`对的形式可用。

通常，未指定任何 HTTP 方法的处理 URL 是正常的 GET 请求。使用 GET 发出的请求可以被缓存和书签标记。在进行`GET`请求时也有长度限制。以下是一些示例 URL：

+   [`www.test-domain.com`](http://www.test-domain.com)

+   [`www.test-domain.com/indexes/`](http://www.test-domain.com/indexes/)

+   [`www.test-domain.com/data file?id=1345322&display=yes`](http://www.test-domain.com/data%20file?id=1345322&display=yes)

在前面的部分，对正常的 URL（如`robots.txt`和`sitemap.xml`）进行了请求，这两个 URL 都使用了 HTTP `GET`方法。`requests`的`get()`函数接受 URL、参数和标头：

```py
import requests
link="http://localhost:8080/~cache"

queries= {'id':'123456','display':'yes'}

addedheaders={'user-agent':''}

#request made with parameters and headers
r = requests.get(link, params=queries, headers=addedheaders) 
print(r.url)
```

这是前面代码的输出：

```py
http://localhst:8080/~cache?id=123456+display=yes
```

# POST

这些被称为安全请求，这些请求是向源发出的。请求的资源状态可以被改变。发送到请求的 URL 的数据在 URL 中是不可见的；相反，它被传输到请求体中。使用`POST`发出的请求不会被缓存或书签标记，并且在长度方面没有限制。

在下面的示例中，使用了一个简单的 HTTP 请求和响应服务<q> (</q>来源：[`httpbin.org/`](http://httpbin.org/)) 来发出`POST`请求。

`pageUrl`接受要发布的数据，如`params`中定义的内容到`postUrl`。自定义标头被分配为`headers`。`requests`库的`post()`函数接受 URL、数据和标头，并以 JSON 格式返回响应：

```py
import requests pageUrl="http://httpbin.org/forms/post"
postUrl="http://httpbin.org/post"

params = {'custname':'Mr. ABC','custtel':'','custemail':'abc@somedomain.com','size':'small', 'topping':['cheese','mushroom'],'delivery':'13:00','comments':'None'} headers={ 'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8','Content-Type':'application/x-www-form-urlencoded', 'Referer':pageUrl }

#making POST request to postUrl with params and request headers, response will be read as JSON response = requests.post(postUrl,data=params,headers=headers).json()
print(response)
```

前面的代码将产生以下输出：

```py
{
'args': {}, 
'data': '', 
'files': {}, 
'form': {
'comments': 'None', 
'custemail': 'abc@somedomain.com',
'custname': 'Mr. ABC', 
'custtel': '',
'delivery': '13:00', 
'size': 'small', 
'topping': ['cheese', 'mushroom']
}, 
'headers': {    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8', 'Accept-Encoding': 'gzip, deflate', 
'Connection': 'close', 
'Content-Length': '130', 
'Content-Type': 'application/x-www-form-urlencoded', 
'Host': 'httpbin.org', 
'Referer': 'http://httpbin.org/forms/post', 
'User-Agent': 'python-requests/2.21.0'
}, 
'json': None, 'origin': '202.51.76.90', 
'url': 'http://httpbin.org/post'
}
```

对于我们尝试的`POST`请求，我们可以使用 DevTools Network 面板找到有关请求标头、响应标头、HTTP 状态和`POST`数据（参数）的详细信息，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/ade91570-74a7-4bc6-99e7-708ac1ddb71e.png)

在 DevTools 网络面板中提交的 POST 数据并作为表单数据找到总是有益的学习和检测通过浏览器和可用的 DevTools 进行的 URL 的请求和响应序列。

# 总结

在本章中，我们学习了如何使用 Python 库向网络资源发出请求并收集返回的响应。本章的主要目标是演示通过`urllib`和`requests` Python 库提供的核心功能，以及探索以各种格式找到的页面内容。

在下一章中，我们将学习并使用一些技术来识别和提取网页内容中的数据。

# 进一步阅读

+   urllib：[`docs.python.org/3/library/urllib.html`](https://docs.python.org/3/library/urllib.html)

+   请求：[`2.python-requests.org/en/master/`](https://2.python-requests.org/en/master/)

+   urllib3 [`urllib3.readthedocs.io/en/latest/index.html`](https://urllib3.readthedocs.io/en/latest/index.html)

+   HTTP 方法（GET/POST）：[`www.w3schools.com/tags/ref_httpmethods.asp`](https://www.w3schools.com/tags/ref_httpmethods.asp)

+   安装 Python 包：[`packaging.python.org/tutorials/installing-packages/`](https://packaging.python.org/tutorials/installing-packages/)

+   什么是 DevTools？[`developer.mozilla.org/en-US/docs/Learn/Common_questions/What_are_browser_developer_tools`](https://developer.mozilla.org/en-US/docs/Learn/Common_questions/What_are_browser_developer_tools)

+   HTTP 请求和响应服务：[`httpbin.org/`](http://httpbin.org/)


# 第三章：使用 LXML、XPath 和 CSS 选择器

到目前为止，我们已经了解了 Web 开发技术、数据查找技术以及使用 Python 编程语言访问 Web 内容。

基于 Web 的内容以一些预定义的文档表达式存在于部分或元素中。分析这些部分的模式是处理方便的抓取的主要任务。元素可以使用 XPath 和 CSS 选择器进行搜索和识别，这些选择器会根据抓取逻辑处理所需的内容。lxml 将用于处理标记文档中的元素。我们将使用基于浏览器的开发工具进行内容阅读和元素识别。

在本章中，我们将学习以下内容：

+   XPath 和 CSS 选择器简介

+   使用浏览器开发者工具

+   学习并使用 Python lxml 库进行抓取

# 技术要求

需要一个 Web 浏览器（Google Chrome 或 Mozilla Firefox），我们将使用以下 Python 库：

+   lxml

+   请求

如果当前 Python 设置中不存在上述库，可以参考上一章的*设置*部分进行设置或安装。

代码文件可在 GitHub 上找到：[`github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python/tree/master/Chapter03`](https://github.com/PacktPublishing/Hands-On-Web-Scraping-with-Python/tree/master/Chapter03)。

# XPath 和 CSS 选择器简介

在第一章的*了解 Web 开发和技术*部分，*Web 抓取基础*中，我们介绍了 XML 作为一个包含可在 Web 和文档相关技术中交换和分发的数据的文档。XML 包含用户定义的标签，也称为节点，它们以树状结构保存数据。

树状结构（也称为元素树）是大多数标记语言的基本模型，并经常被称为**文档对象模型**（**DOM**）。借助 DOM 及其定义的约定，我们可以访问、遍历和操作元素。

元素被结构化在一些父元素内部，这些父元素又位于它们自己的父元素内部，依此类推；这描述了标记语言最重要的特征，即父子关系。许多支持 XML 或标记语言的应用程序支持 DOM，甚至包含解析器来使用。

为了提取信息，有必要确定信息的确切位置。信息可能嵌套在树状结构内，并可能具有一些额外的属性来表示内容。XPath 和 CSS 选择器都用于沿着 DOM 导航并搜索文档中的所需元素或节点。

在接下来的部分中，我们将介绍 XPath 和 CSS 选择器，并使用它们来进行 Web 抓取，并使用支持的 Python 库。

# XPath

**XML Path**（**XPath**）语言是基于 XML 的技术（XML、XSLT 和 XQuery）的一部分，用于通过表达式导航 DOM 元素或在 XML（或 HTML）文档中定位节点。XPath 通常是标识文档中节点的路径。XPath 也是**W3C**（**万维网联盟**）的推荐（[`www.w3.org/TR/xpath/all/`](https://www.w3.org/TR/xpath/all/)）。

XPath 或 XPath 表达式也被识别为绝对和相对：

+   绝对路径是表示从根元素到所需元素的完整路径的表达式。它以`/html`开头，看起来像`/html/body/div[1]/div/div[1]/div/div[1]/div[2]/div[2]/div/span/b[1]`。单个元素通过其位置进行识别，并由索引号表示。

+   相对路径表示从某些选定的元素中选择的表达式到所需的元素。相对路径比绝对路径更短，更易读，并且看起来像`//*[@id="answer"]/div/span/b[@class="text"]`。相对路径通常优先于绝对路径，因为元素索引、属性、逻辑表达式等可以组合在一个表达式中。

使用 XPath 表达式，我们可以在元素之间进行层次导航并达到目标元素。XPath 也由各种编程语言实现，例如 JavaScript、Java、PHP、Python 和 C++。Web 应用程序和浏览器也内置了对 XPath 的支持。

可以使用各种内置函数来构建表达式，这些函数适用于各种数据类型。与一般数学相关的操作（+、-、*、/）、比较（<、>、=、!=、>=、<=）和组合运算符（`and`、`or`和`mod`）也可以用于构建表达式。XPath 也是 XML 技术（如 XQuery 和**eXtensible Stylesheet Language Transformations**（**XSLT**））的核心组成部分。

**XML 查询**（**XQuery**）是一种使用 XPath 表达式从 XML 文档中提取数据的查询语言。

XSLT 用于以更易读的格式呈现 XML。

让我们从`food.xml`文件中的 XML 内容中探索一些 XPath 表达式：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/84e3a184-9a6f-49a1-a378-0de23cc11d41.png)

XML 内容

在以下示例中，我们将使用 Code Beautify 的 XPath-Tester（[`codebeautify.org/Xpath-Tester`](https://codebeautify.org/Xpath-Tester)）。使用前面提供的 XML 源 URL 获取 XML 内容，并将其与 Code Beautify XPath-Tester 一起使用。

您可以使用[`codebeautify.org/Xpath-Tester`](https://codebeautify.org/Xpath-Tester)、[`www.freeformatter.com/xpath-tester.htm`](https://www.freeformatter.com/xpath-tester.html)或任何其他免费提供的 XPath 测试工具。

在 XML 文档中，一切都是一个节点，例如`menus`、`food`和`price`。XML 节点本身可以是一个元素（元素是具有开始和结束标记的类型或实体）。

前面的 XML 文档也可以被视为继承的元素块。父节点`menus`包含多个子节点`food`，这些子节点区分适当的值和适当的数据类型。如下截图所示，XPath 表达式`//food`显示了所选节点`food`的结果。节点选择还检索了父节点中的子节点，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/595692c6-3dd2-4fad-bd74-d17dd48e3a45.png)

XPath //food 的结果（使用 https://codebeautify.org/Xpath-Tester）

以下截图中的 XPath 表达式选择了所有父节点`food`中找到的子节点`price`。有六个可用的子`food`节点，每个节点都包含`price`、`name`、`description`、`feedback`和`rating`：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/b527b33b-10c7-46e0-ac56-29da6549590c.png)

XPath //food/price 的结果（使用 https://codebeautify.org/Xpath-Tester）

从前面测试的两个 XPath 可以看出，表达式几乎像文件系统（命令行或终端路径）一样创建，我们在各种操作系统中使用。XPath 表达式包含代码模式、函数和条件语句，并支持使用谓词。

谓词用于识别特定的节点或元素。谓词表达式使用方括号编写，类似于 Python 列表或数组表达式。

在前面的 XML 中给出的 XPath 表达式的简要解释列在以下表中：

| **XPath 表达式** | **描述** |
| --- | --- |
| `//` | 选择文档中的节点，无论它们位于何处 |
| `//*` | 选择文档中的所有元素 |
| `//food` | 选择元素`food` |
| `*` | 选择所有元素 |

| `//food/name &#124; //food/price` | 选择在`food`节点中找到的`name`和`price`元素：

```py
<name>Butter Milk with Vanilla</name>
 <name>Fish and Chips</name>
 <price>$5.50</price>
 <price>$2.99</price>
```

|

| `//food/name` | 选择`food`中的所有`name`元素：

```py
<name>Butter Milk with Vanilla</name>
 <name>Eggs and Bacon</name>
 <name>Orange Juice</name>
```

|

| `//food/name/text()` | 仅选择所有`food/name`元素的`text`：

```py
Butter Milk with Vanilla Orange Juice
```

|

| `//food/name &#124; //rating` | 选择文档中`food`和`rating`中找到的所有`name`元素：

```py
<name>Butter Milk with Vanilla</name>
 <name>Fish and Chips</name><rating>4.5</rating>
 <rating>4.9</rating>
```

|

| `//food[1]/name` | 选择第一个`food`节点的`name`元素：

```py
<name>Butter Milk with Vanilla</name>
```

|

| `//food[feedback<9]` | 选择满足谓词条件`feedback<9`的`food`节点及其所有元素：

```py
<food>
 <name>Butter Milk with Vanilla</name>
 <name>Egg Roll</name>
 <name>Eggs and Bacon</name>
 </food>
```

|

| `//food[feedback<9]/name` | 选择满足条件的`food`节点和`name`元素：

```py
<name>Butter Milk with Vanilla</name>
 <name>Egg Roll</name>
 <name>Eggs and Bacon</name>
```

|

| `//food[last()]/name` | 选择最后一个`food`节点的`name`元素：

```py
<name>Orange Juice</name>
```

|

| `//food[last()]/name/text()` | 选择最后一个`food`节点的`name`元素的`text`：

```py
Orange Juice
```

|

| `sum(//food/feedback)` | 提供所有`food`节点中反馈的总和：

```py
47.0
```

|

| `//food[rating>3 and rating<5]/name` | 选择满足谓词条件的`food`的`name`：

```py
<name>Egg Roll</name>
<name>Eggs and Bacon</name>
<name>Orange Juice</name>
```

|

| `//food/name[contains(.,"Juice")]` | 选择包含`Juice`字符串的`food`的`name`：

```py
<name>Orange Juice</name>
```

|

| `//food/description[starts-with(.,"Fresh")]/text()` | 选择以“新鲜”开头的描述节点的文本：

```py
Fresh egg rolls filled with ground chicken, ... cabbage
Fresh Orange juice served
```

|

| `//food/description[starts-with(.,"Fresh")]` | 选择以“新鲜”开头的`description`节点的`text`：

```py
<description>Fresh egg rolls filled with.. cabbage</description>
 <description>Fresh Orange juice served</description>
```

|

| `//food[position()<3]` | 根据其位置选择第一个和第二个食物：

```py
<food>
 <name>Butter Milk with Vanilla</name>
 <price>$3.99</price>
 ...
 <rating>5.0</rating>
 <feedback>10</feedback>
 </food>
```

|

XPath 谓词可以包含从`1`（而不是`0`）开始的数字索引和条件语句，例如`//food[1]`或`//food[last()]/price`。

现在我们已经使用各种 XPath 表达式测试了前面的 XML，让我们考虑一个带有一些属性的简单 XML。属性是用于标识给定节点或元素的某些参数的额外属性。单个元素可以包含唯一的属性集。在 XML 节点或 HTML 元素中找到的属性有助于识别具有其所包含值的唯一元素。正如我们在以下 XML 代码中所看到的，属性以`key=value`信息对的形式出现，例如`id="1491946008"`：

```py
<?xml version="1.0" encoding="UTF-8"?>
<books>
     <book id="1491946008" price='47.49'>
        <author>Luciano Ramalho</author>
         <title>
            Fluent Python: Clear, Concise, and Effective Programming
        </title>
     </book>
     <book id="1491939362" price='29.83'>
         <author>Allen B. Downey</author>
         <title>
 Think Python: How to Think Like a Computer Scientist
        </title>
     </book>
</books>
```

XPath 表达式通过在键名前面添加`@`字符来接受`key`属性。以下表中列出了使用属性的 XPath 的一些示例，并附有简要描述。

| **XPath** **表达式** | **描述** |
| --- | --- |

| `//book/@price` | 选择`book`的`price`属性：

```py
price="47.49"
price="29.83"
```

|

| `//book` | 选择`book`字段及其元素：

```py
<book id="1491946008" price="47.49">

<author>Luciano Ramalho</author>
 <title>Fluent Python: Clear, Concise, and Effective Programming
 Think Python: How to Think Like a Computer Scientist
 </title></book>
```

|

| `//book[@price>30]` | 选择`price`属性大于`30`的`book`中的所有元素：

```py
<book id="1491946008" price="47.49">
 <author>Luciano Ramalho</author>
 <title>Fluent Python: Clear, Concise, and Effective Programming </title> </book>
```

|

| `//book[@price<30]/title` | 选择`price`属性小于`30`的书籍的`title`：

```py
<title>Think Python: How to Think Like a Computer Scientist</title>
```

|

| `//book/@id` | 选择`id`属性及其值。`//@id`表达式也会产生相同的输出：

```py
id="1491946008"
 id="1491939362"
```

|

| `//book[@id=1491939362]/author` | 选择`id=1491939362`的`book`中的`author`：

```py
<author>Allen B. Downey</author>
```

|

我们已经尝试探索和学习了一些关于 XPath 和编写表达式以检索所需内容的基本特性。在*使用 lxml 进行爬虫-一个 Python 库*部分，我们将使用 Python 编程库进一步探索使用 XPath 部署代码来爬取提供的文档（XML 或 HTML），并学习使用浏览器工具生成或创建 XPath 表达式。有关 XPath 的更多信息，请参考*进一步阅读*部分中的链接。

# CSS 选择器

在第一章中，*网络爬虫基础*，在*了解网页开发和技术*部分，我们学习了 CSS 及其用于样式化 HTML 元素的用法，以及使用全局属性。 CSS 通常用于样式化 HTML，有各种方法可以将 CSS 应用于 HTML。

CSS 选择器（也称为 CSS 查询或 CSS 选择器查询）是 CSS 使用的定义模式，用于选择 HTML 元素，使用元素名称或全局属性（`ID`和`Class`）。 CSS 选择器如其名称所示，以各种方式选择或提供选择 HTML 元素的选项。

在下面的示例代码中，我们可以看到在`<body>`中找到的一些元素：

+   `<h1>`是一个元素和选择器。

+   `<p>`元素或选择器具有`class`属性和`header`样式类型。在选择`<p>`时，我们可以使用元素名称、属性名称或类型名称。

+   多个`<a>`在`<div>`中找到，但它们的`class`属性、`id`和`href`属性的值不同：

```py
<html>
<head>
    <title>CSS Selectors: Testing</title>
    <style>
        h1{color:black;}
        .header,.links{color: blue;}
        .plan{color: black;}
        #link{color: blue;}
    </style>
</head>
<body>
    <h1>Main Title</h1>
    <p class=”header”>Page Header</p>
    <div class="links">
         <a class="plan" href="*.pdf">Document Places</a>
         <a id="link" href="mailto:xyz@domain.com">Email Link1!</a>
         <a href="mailto:abc@domain.com">Email Link2!</a>    
    </div>
</body>
</html>
```

我们在前面的代码中识别出的可区分的模式可以用于单独或分组选择这些特定元素。在线上有许多 DOM 解析器，它们提供了与 CSS 查询相关的功能。其中一个，如下面的屏幕截图所示，是[`try.jsoup.org/`](https://try.jsoup.org/)：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/c543073e-d7dd-4219-a1ce-fa384b2f66b8.png)

从 https://try.jsoup.org/评估 CSS 查询 DOM 解析器将提供的 XML 或 HTML 转换为 DOM 对象或树类型的结构，从而便于访问和操作元素或树节点。有关 DOM 的更多详细信息，请访问[`dom.spec.whatwg.org/`](https://dom.spec.whatwg.org/)。

在 CSS 查询中，以下代码文本中列出的各种符号代表特定的特征，并且可以在 CSS 查询中使用：

+   全局`id`属性和`class`由`#`和`.`表示，如此查询所示：

+   `a#link`: `<a id="link" href="mailto:xyz@domain.com">Email Link1!</a>`

+   `a.plan`: `<a class="plan" href="*.pdf">Document Places</a>`

+   组合符（显示元素之间的关系）也被使用，例如`+`、`>`、`~`和空格字符，如此查询所示：

+   `h1 + p`: `<p class=”header”>Page Header</p>`

+   `div.links a.plan`: `<a class="plan" href="*.pdf">Document Places</a>`

+   诸如`^`、`*`、`$`之类的运算符用于定位和选择，如此查询所示：

+   `a[href$="pdf"]`: `<a class="plan" href="*.pdf">Document Places</a>`

+   `a[href^="mailto"]`: `<a id="link" href="mailto:xyz@domain.com">Email Link1!</a><a href="mailto:abc@domain.com">Email Link2!</a>`

这些符号在以下各节中并排使用和解释，参考前面 HTML 代码中各种类型的选择器。

# 元素选择器

元素选择器是从 HTML 中选择元素的基本选择器。通常，这些元素是 HTML 的基本标签。以下表格列出了此类别的一些选择器及其用法：

| **CSS 查询** | **描述** |
| --- | --- |
| `h1` | 选择`<h1>`元素 |
| `a` | 选择所有`<a>`元素 |
| `*` | 选择 HTML 代码中的所有元素 |
| `body *` | 选择`<body>`中的所有`<h1>`、`<p>`、`<div>`和`<a>`元素 |
| `div a` | 选择`<div>`中的所有`<a>`（使用空格字符之间） |
| `h1 + p` | 选择`<h1>`后面的直接`<p>`元素 |
| `h1 ~ p` | 选择`<h1>`之前的每个`<p>`元素 |
| `h1,p` | 选择所有`<h1>`和`<p>`元素 |
| `div > a` | 选择所有是`<div>`的直接子元素的`<a>`元素 |

# ID 和类选择器

ID 和类选择器是元素选择器的附加功能。我们可以找到具有`class`和`id`属性的 HTML 标签。这些也被称为全局属性。这些属性通常优先于其他属性，因为它们定义了结构和标识的标签。

有关全局属性的更多详细信息，请参阅第一章，*Web Scraping Fundamentals*，*全局属性*部分。以下表格列出了此类选择器的用法：

| **CSS 查询** | **描述** |
| --- | --- |
| `.header` | 选择具有`class=header`的元素 |
| `.plan` | 选择具有`class=plan`的`<a>` |
| `div.links` | 选择`class=plan`的`<div>` |
| `#link` | 选择具有`id=link`的元素 |
| `a#link` | 选择具有`id=link`的`<a>`元素 |
| `a.plan` | 选择具有`class=plan`的`<a>`元素 |

# 属性选择器

属性选择器用于定义具有可用属性的选择器。HTML 标签包含一个属性，该属性有助于识别具有该属性和其携带的值的特定元素。

以下表格列出了一些显示属性选择器用法的方式：

| **CSS 查询** | **描述** |
| --- | --- |

| `a[href*="domain"]` | 选择`<a>`元素，其`href`中包含`domain`子字符串：

```py
<a id="link" href="mailto:xyz@domain.com">Email Link1!</a> 
<a href="mailto:abc@domain.com">Email Link2!</a>
```

|

| `a[href^="mailto"]` | 选择以`href`属性的`mailto`子字符串开头的`<a>`元素：

```py
<a id="link" href="mailto:xyz@domain.com">Email Link1!</a> 
<a href="mailto:abc@domain.com">Email Link2!</a>
```

|

| `a[href$="pdf"]` | 选择`<a>`元素，其`href`属性末尾有`pdf`子字符串：

```py
<a class="plan" href="*.pdf"> Document Places </a>
```

|

| `[href~=do]` | 选择所有具有`href`属性并在值中匹配`do`的元素。以下两个`<a>`元素的`href`值中都包含`do`：

```py
<a id="link" href="mailto:xyz@domain.com">Email Link1!</a> 
<a href="mailto:abc@domain.com">Email Link2!</a>
```

|

| `[class]` | 选择所有具有`class`属性的元素或`<p>`、`<div>`和`<a>`：

```py
<p class='header'>Page Header</p>
<div class="links">
<a class="plan" href="*.pdf"> Document Places </a>
```

|

| `[class=plan]` | 选择`class=plan`的`<a>`：

```py
<a class="plan" href="*.pdf"> Document Places </a>
```

|

# 伪选择器

伪选择器是一组方便的选择，用于根据其位置识别或选择元素。

以下表格列出了这些类型选择器的一些用法及简要描述：

| **CSS 查询** | **描述** |
| --- | --- |

| `a:gt(0)` | 选择除了索引为`0`的所有`<a>`元素：

```py
<a id="link" href="mailto:xyz@domain.com">Email Link1!</a> <a href="mailto:abc@domain.com">Email Link2!</a> 
```

|

| `a:eq(2)` | 选择索引为`2`的`<a>`元素：

```py
<a href="mailto:abc@domain.com">
```

|

| `a:first-child` | 选择其父元素中是第一个子元素的每个`<a>`元素：

```py
<a class="plan" href="*.pdf">Document Places</a>
```

|

| `a:last-child` | 选择其父元素中是最后一个子元素的每个`<a>`元素：

```py
<a href="mailto:abc@domain.com">Email Link2!</a>
```

|

| `a:last-of-type` | 选择其父元素的最后一个`<a>`元素：

```py
<a href="mailto:abc@domain.com">Email Link2!</a>
```

|

| `:not(p)` | 选择除了`<p>`之外的所有元素。 |
| --- | --- |

| `a:nth-child(1)` | 选择其父元素中是第一个子元素的每个`<a>`元素：

```py
<a class="plan" href="*.pdf">Document Places</a>
```

|

| `a:nth-last-child(3)` | 选择其父元素中倒数第三个位置的每个`<a>`元素：

```py
<a class="plan" href="*.pdf">Document Places</a>
```

|

| `a:nth-of-type(3)` | 选择其父元素的每第三个`<a>`元素：

```py
<a href="mailto:abc@domain.com">Email Link2!</a>
```

|

| `a:nth-last-of-type(3)` | 选择其父元素中倒数第三个位置的每个`<a>`元素：

```py
<a class="plan" href="*.pdf">Document Places</a>
```

|

CSS 选择器被用作选择元素的方便替代方法，与绝对 XPath 相比，它们长度更短，并且在表达式中使用简单模式，易于阅读和管理。CSS 选择器可以转换为 XPath 表达式，但反之则不行。

还有许多在线工具可用，允许将 CSS 选择器查询转换为 XPath 表达式；其中一个是[`css-selector-to-xpath.appspot.com/`](https://css-selector-to-xpath.appspot.com/)，如下截图所示；我们不应总是信任可用的工具，应在应用于代码之前进行测试结果：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/c7f2e6a1-0110-4135-822c-97efabd35133.png)

CSS 选择器转 XPath 转换器

如前面的截图所述，CSS 选择器用于从数据提取的角度选择元素，并且可以在`Scraper`代码中使用，甚至可以在应用样式到所选元素的样式方面使用。

在本节中，我们学习了 XPath 和 CSS 选择器的最流行的与网络相关的模式查找技术。在下一节中，我们将探索基于浏览器的开发者工具（DevTools），并学习如何使用 DevTools 内部的功能。DevTools 可用于搜索、分析、识别和选择元素，并获取 XPath 表达式和 CSS 选择器。

# 使用 Web 浏览器开发者工具访问 Web 内容

在第一章中，*网络抓取基础知识*，在*数据查找技术*（从网络中获取数据）部分和*开发者工具（DevTools）*内部，我们介绍了基于浏览器的 DevTools 来定位内容和探索各种面板。DevTools 提供各种功能面板，为我们提供支持工具来管理相关资源。

在这个特定的部分，我们的目的将是特定地识别持有我们正在寻找的内容的特定元素。这种基于标识的信息，比如 XPath 表达式、CSS 查询，甚至是基于 DOM 的导航流，在编写`Scraper`时将会很有帮助。

我们将使用 Google Chrome 浏览网页。Chrome 内置了开发者工具，具有许多功能（用于元素识别、选择、DOM 导航等）。在接下来的部分，我们将探索并使用这些功能。

# HTML 元素和 DOM 导航

我们将使用[`books.toscrape.com/`](http://books.toscrape.com/)来自[`toscrape.com/`](http://toscrape.com/)。`toscrape`提供了与网页抓取相关的资源，供初学者和开发人员学习和实施`Scraper`。

让我们使用网页浏览器 Google Chrome 打开[`books.toscrape.com`](http://books.toscrape.com)的 URL，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/55b6f040-3c78-4824-857a-b759ba4254d6.png)books.toscrape.com 的检查视图

当页面内容成功加载后，我们可以右键单击页面并选择选项检查，或者按*Ctrl* + *Shift* + *I*来加载 DevTools。如果通过 Chrome 菜单访问，点击更多工具和开发者工具。浏览器应该看起来与前面的屏幕截图中的内容类似。

正如您在前面的屏幕截图中所看到的，在检查模式下，加载了以下内容：

+   面板元素默认位于左侧。

+   基于 CSS 样式的内容位于右侧。

+   我们注意到在左下角有 DOM 导航或元素路径，例如，`html.no-js body .... div.page_inner div.row`。

我们在第一章中已经对这些面板进行了基本概述，*Web Scraping Fundamentals*，在*Developer Tools*部分。随着开发者工具的加载，我们可以首先找到一个指针图标，这是用于从页面中选择元素的，如下图所示；这个元素选择器（检查器）可以使用*Ctrl* + *Shift* + *C*打开/关闭：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/5a5ec3a7-22fb-4e7e-bdf1-86827e38dd81.png)

检查栏上的元素选择器（检查器）

打开元素选择器后，我们可以在页面上移动鼠标。基本上，我们正在使用鼠标搜索我们指向的确切 HTML 元素：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/a9235959-772d-4060-b3f5-e1735651d65b.png)

在书籍图片上使用元素选择器

如前面的屏幕截图所示，该元素已被选中，当我们将鼠标移动到第一本书的图片上时，这个动作会导致以下结果：

+   `div.image_container`元素在页面中显示并被选中。

+   在元素面板源中，我们可以找到特定的 HTML 代码`<div class="image_container">`，也被突出显示。这些信息（书籍图片的位置）也可以通过右键单击+页面源或*Ctrl* + *U*，然后搜索特定内容来找到。

我们可以重复对我们希望抓取的 HTML 内容的各个部分执行相同的操作，就像以下示例中所示的那样：

+   列出的书籍价格位于`div.product_price`元素内。

+   星级评分位于`p.star-rating`内。

+   书名位于`*<*h3>`内，在`div.product_price`之前或在`p.star-rating`之后。

+   书籍详细链接位于`<a>`内，该链接存在于`<h3>`内。

+   从下面的屏幕截图中，也清楚地看到了先前列出的元素都位于`article.product_prod`内。此外，在下面的屏幕截图底部，我们可以确定 DOM 路径为`article.product_prod`：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/be32e5d0-f89c-4306-9df6-88b96ef47857.png)

检查模式下的元素选择

在前面的截图中找到的 DOM 导航在处理 XPath 表达式时可能会有所帮助，并且可以使用页面源代码验证内容，如果元素检查器显示的路径或元素实际存在于获取的页面源代码中。

DOM 元素、导航路径和使用元素检查器或选择器找到的元素应该进行交叉验证，以确保它们在页面源代码或网络面板中存在。

# 使用 DevTools 获取 XPath 和 CSS 选择器

在本节中，我们将收集所需元素的 XPath 表达式和 CSS 查询。与我们在前一节中探索页面检查和元素面板的方式类似，让我们继续以下步骤，获取所选元素的 XPath 表达式和 CSS 查询：

1.  选择元素选择器并获取元素代码

1.  右键单击鼠标获取元素代码

1.  从菜单中选择复制选项

1.  从子菜单选项中，选择复制 XPath 以获取所选元素的 XPath 表达式

1.  或选择 CSS 选择器（查询）的复制选择器

如下截图所示，我们选择单个图书项目的各个部分，并获取相应的 CSS 选择器或 XPath 表达式，访问菜单选项：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/7f53f2c4-ef0a-4b88-ba6d-56beb60c066f.png)

使用页面检查复制 XPath 和 CSS 选择器

以下是使用 DevTools 收集的一些 XPath 和 CSS 选择器，用于产品的可用项目，如图书标题和价格。

**使用 DevTools 获取 XPath 选择器**：

+   图书标题：`//*[@id="default"]/div/div/div/div/section/div[2]/ol/li[1]/article/h3/a`

+   价格：`//*[@id="default"]/div/div/div/div/section/div[2]/ol/li[1]/article/div[2]`

+   图片：`//*[@id="default"]/div/div/div/div/section/div[2]/ol/li[1]/article/div[1]`

+   库存信息：`//*[@id="default"]/div/div/div/div/section/div[2]/ol/li[1]/article/div[2]/p[2]`

+   星级评分：`//*[@id="default"]/div/div/div/div/section/div[2]/ol/li[1]/article/p`

**使用 DevTools 获取 CSS 查询选择器**：

+   图书标题：`#default > div > div > div > div > section > div:nth-child(2) > ol > li:nth-child(1) > article > h3 > a`

+   价格：`#default > div > div > div > div > section > div:nth-child(2) > ol > li:nth-child(1) > article > div.product_price`

+   图片：`#default > div > div > div > div > section > div:nth-child(2) > ol > li:nth-child(1) > article > div.image_container`

+   库存信息：`#default > div > div > div > div > section > div:nth-child(2) > ol > li:nth-child(1) > article > div.product_price > p.instock.availability`

+   星级评分：`#default > div > div > div > div > section > div:nth-child(2) > ol > li:nth-child(1) > article > p.star-rating`

同样，其他必要的 XPath 或 CSS 选择器也将根据需要收集。在收集和验证或清理（缩短）这些表达式和查询之后，使用 Python 编程应用爬虫逻辑来自动化数据收集。

同样，没有特定的方法可以避开前一节中讨论的步骤。XPath 或 CSS 选择器也可以通过显示 HTML 源代码或页面源代码来确定或形成；还有许多支持类似任务的基于浏览器的扩展。开发人员可以选择任何我们讨论过的处理 XPath 和 CSS 选择器的方法来感到舒适。

最近列出的基于浏览器的扩展之一，用于生成 Google Chrome 的 XPath 和 CSS 选择器是 ChroPath ([`autonomiq.io/chropath/`](https://autonomiq.io/chropath/)[)](https://autonomiq.io/chropath/)。建议自行练习和了解编写自定义表达式和查询。在处理大量信息源时，应使用扩展和其他类似应用程序。

在本节中，我们检查和探索了元素面板，用于元素识别和 DOM 导航：修改、删除元素、修改脚本等。元素面板中也存在相关选项。在接下来的部分中，我们将使用 Python 库`lxml`来编写`Scraper`，并使用 XPath 和 CSS 选择器从选择的网站收集数据。

# 使用 lxml，一个 Python 库

lxml 是一个 XML 工具包，具有丰富的库集来处理 XML 和 HTML。lxml 在 Python 中比其他基于 XML 的库更受青睐，因为它具有高速和有效的内存管理。它还包含各种其他功能，用于处理小型或大型 XML 文件。Python 程序员使用 lxml 来处理 XML 和 HTML 文档。有关 lxml 及其库支持的更详细信息，请访问[`lxml.de/.`](https://lxml.de/)

lxml 提供了对 XPath 和 XSLT 的本机支持，并构建在强大的 C 库`libxml2`和`libxslt`之上。它的库集通常与 XML 或 HTML 一起使用，用于访问 XPath、解析、验证、序列化、转换和扩展 ElementTree 的功能([`effbot.org/zone/element-index.htm#documentation`](http://effbot.org/zone/element-index.htm#documentation))。从 lxml 中解析、遍历 ElementTree、XPath 和类似 CSS 选择器的功能使其足够方便用于诸如网络抓取之类的任务。lxml 还用作 Python Beautiful Soup ([`www.crummy.com/software/BeautifulSoup/bs4/doc/`](https://www.crummy.com/software/BeautifulSoup/bs4/doc/))和 pandas ([`pandas.pydata.org/`](https://pandas.pydata.org/))中的解析引擎。

标记语言的元素，如 XML 和 HTML，具有开始和结束标记；标记也可以具有属性并包含其他元素。ElementTree 是一个加载 XML 文件为元素树的包装器。Python 内置库 ElementTree (etree) 用于搜索、解析元素和构建文档树。元素对象还具有与 Python 列表和字典相关的各种可访问属性。

XSLT 是一种将 XML 文档转换为 HTML、XHML、文本等的语言。XSLT 使用 XPath 在 XML 文档中导航。XSLT 是一种模板类型的结构，用于将 XML 文档转换为新文档。

lxml 库包含以下重要模块：

+   `lxml.etree` ([`lxml.de/api/lxml.etree-module.html`](https://lxml.de/api/lxml.etree-module.html))：解析和实现 ElementTree；支持 XPath、迭代等

+   `lxml.html` ([`lxml.de/api/lxml.html-module.html`](https://lxml.de/api/lxml.html-module.html))：解析 HTML，支持 XPath、CSSSelect、HTML 表单和表单提交

+   `lxml.cssselect` ([`lxml.de/api/lxml.cssselect-module.html`](https://lxml.de/api/lxml.cssselect-module.html))：将 CSS 选择器转换为 XPath 表达式；接受 CSS 选择器或 CSS 查询作为表达式

# 通过示例学习 lxml

lxml 具有大量的模块集，在本节中，我们将学习使用大部分功能的示例来探索 lxml，然后再进行抓取任务。这些示例旨在进行提取活动，而不是开发。

# 示例 1 - 从文件中读取 XML 并遍历其元素

在这个例子中，我们将读取`food.xml`文件中可用的 XML 内容。我们将使用 XML 内容：

```py
from lxml import etree
xml = open("food.xml","rb").read() #open and read XML file
```

从前面的代码中获得的 XML 响应需要使用`lxml.etree.XML()`进行解析和遍历。`XML()`函数解析 XML 文档并返回`menus`根节点，在这种情况下。有关`lxml.etree`的更详细信息，请参阅[`lxml.de/api/lxml.etree-module.html`](https://lxml.de/api/lxml.etree-module.html)：

```py
tree = etree.XML(xml) 
#tree = etree.fromstring(xml) #tree = etree.parse(xml) 
```

在前面的代码中找到的`fromstring()`和`parse()`函数也提供了内容给`lxml.etree`使用的默认或选择的解析器。

lxml 提供了多个解析器（XMLParser 和 HTMLParser），可以使用`>>> etree.get_default_parser()`来查找代码中使用的默认解析器。在前面的情况下，结果是`<lxml.etree.XMLParser>`。

让我们验证解析后得到的`tree`：

```py
print(tree)  
print(type(tree))   

<Element menus at 0x3aa1548>
<class 'lxml.etree._Element'>
```

前两个语句证实了`tree`是`lxml.etree._Element`类型的 XML 根元素。要遍历树中的所有元素，可以使用树迭代，这会按照它们被找到的顺序返回元素。

使用`iter()`函数执行树迭代。可以通过元素属性`tag`访问元素的标签名称；类似地，可以通过`text`属性访问元素的文本，如下所示：

```py
for element in tree.iter():
    print("%s - %s" % (element.tag, element.text))
```

前述树迭代将产生以下输出：

```py
menus - 
food - 

name - Butter Milk with Vanilla
price - $3.99
description - Rich tangy buttermilk with vanilla essence
rating - 5.0
feedback - 6
.............
food - 

name - Orange Juice
price - $2.99
description - Fresh Orange juice served
rating - 4.9
feedback - 10
```

我们也可以将子元素作为参数传递给树迭代器（`price`和`name`），以获取基于选定元素的响应。在通过`tree.iter()`传递子元素后，可以使用`element.tag`和`element.text`分别获取`Tag`和`Text`或`Content`子元素，如下所示：

```py
#iter through selected elements found in Tree
for element in tree.iter('price','name'):
 print("%s - %s" % (element.tag, element.text))

name - Butter Milk with Vanilla
price - $3.99
name - Fish and Chips
price - $4.99
...........
name - Eggs and Bacon
price - $5.50
name - Orange Juice
price - $2.99
```

还要注意的是，`food.xml`文件是以`rb`模式而不是`r`模式打开的。处理本地基于文件的内容和带有编码声明的文件时，比如`<?xml version="1.0" encoding="UTF-8"?>`，有可能会遇到错误，如`ValueError: Unicode strings with encoding declaration are not supported. Please use bytes input or XML fragments without declaration`。对内容进行编码/解码可能会解决这个问题，这也取决于文件模式。

要处理前述条件或从文件、HTTP URL 或 FTP 中读取内容，`parse()`是一个非常有效的方法。它使用默认解析器，除非指定了一个额外的参数。以下代码演示了`parse()`函数的使用，它被迭代以获取元素名称以获取其文本：

```py
from lxml import etree

#read and parse the file
tree = etree.parse("food.xml")

#iterate through 'name' and print text content
for element in tree.iter('name'):
    print(element.text)
```

前面的代码会产生以下输出：`Butter Milk with Vanilla`，`Fish and Chips`等，这些都是从`name`元素和`food.xml`文件中获取的。

```py
Butter Milk with Vanilla
Fish and Chips
Egg Roll
Pineapple Cake
Eggs and Bacon
Orange Juice
```

多个树元素也可以被迭代，如下所示：

```py
for element in tree.iter('name','rating','feedback'):
 print("{} - {}".format(element.tag, element.text))

name - Butter Milk with Vanilla
rating - 5.0
feedback - 6
name - Fish and Chips
rating - 5.0
...........
feedback - 4
name - Orange Juice
rating - 4.9
feedback - 10

```

# 示例 2 - 使用 lxml.html 读取 HTML 文档

在这个例子中，我们将使用`lxml.html`模块来遍历来自[`httpbin.org/forms/post`](http://httpbin.org/forms/post)的元素：

```py
from lxml import html
from urllib.request import urlopen

root = html.parse(urlopen('http://httpbin.org/forms/post')).getroot()
tree = html.parse(urlopen('http://httpbin.org/forms/post')) print(type(root)) #<class 'lxml.html.HtmlElement'> print(type(tree)) #<class 'lxml.etree._ElementTree'>
```

我们正在使用`lxml.html`中的`parse()`来加载给定 URL 的内容。`parse()`的作用类似于`lxml.etree`，但在这种情况下，得到的`root`是 HTML 类型。`getroot()`方法返回文档根。可以比较`root`和`tree`的对象类型，如前面的代码所示。在这个例子中，我们对`root`或 HTMLElement 感兴趣。解析为`root`的内容如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/59036331-0920-4468-84a4-9a59392938a4.png)

页面源代码：http://httpbin.org/forms/post

HTMLElement `root`具有各种属性，如下所示：

```py
print(dir(root)) 

[...'addnext', 'addprevious', 'append', 'attrib', 'base', 'base_url', 'body', 'clear', 'cssselect', 'drop_tag', 'drop_tree', 'extend', 'find', 'find_class', 'find_rel_links', 'findall', 'findtext', 'forms', 'get', 'get_element_by_id', 'getchildren', 'getiterator', 'getnext', 'getparent', 'getprevious', 'getroottree', 'head', 'index', 'insert', 'items', 'iter', 'iterancestors', 'iterchildren', 'iterdescendants', 'iterfind', 'iterlinks', 'itersiblings', 'itertext', 'keys', 'label', 'make_links_absolute', 'makeelement', 'nsmap', 'prefix', 'remove', 'replace', 'resolve_base_href', 'rewrite_links', 'set', 'sourceline', 'tag', 'tail', 'text', 'text_content', 'values', 'xpath']
```

让我们从`root`中找到`<p>`；可以使用`find()`来定位路径中的第一个元素。可以使用`text_content()`函数检索文本。`findtext()`函数也可以用于类似情况，如下所示：

```py
p = root.find('.//p') #find first <p> from root

print(p.text_content())  *# Customer name:*
print(root.findtext('.//p/label')) *#Customer name:* 
```

如下代码所示，`findall()`用于查找和遍历`root`中的所有元素：

```py
elemP = root.findall('.//p') #find all <p> element from root
for p in elemP  :
    print(p.text_content())
```

前面的代码列出了查找所有`p`标签的文本，如下所示：

```py
Customer name: 
Telephone: 
E-mail address: 
 Small 
 Medium 
 Large 
 Bacon 
 Extra Cheese 
 Onion 
 Mushroom 
Preferred delivery time: 
Delivery instructions: 
Submit order
```

HTMLElement `root`也支持 XPath 和 CSSSelect：

```py
print(root.xpath('//p/label/input/@value'))
print(root.xpath('//legend/text()')) 
```

这将产生以下输出：

```py
['small','medium','large','bacon','cheese','onion','mushroom']
['Pizza Size', 'Pizza Toppings'] 
```

CSSSelect 将 CSS 选择器转换为 XPath 表达式，并与相关对象一起使用：

```py
#print text_content() for label inside <p>
for e in root.cssselect('p label'):
    print(e.text_content())

Customer name: 
Telephone: 
E-mail address: 
 Small 
 ......
 Mushroom 
Preferred delivery time: 
Delivery instructions:

#print text_content for element <p> inside <form>
for e in root.cssselect('form > p'):
    print(e.text_content())

Customer name: 
Telephone: 
E-mail address: 
Preferred delivery time: 
Delivery instructions: 
Submit order
```

以下代码演示了 HTML `<form>`元素被探索其属性和属性。我们首先针对`root`中的`<form>`元素进行操作，即`<form method="post" action="/post">`：

```py
print(root.forms[0].action)  #http://httpbin.org/post
print(root.forms[0].keys())  #['method', 'action']
print(root.forms[0].items()) #[('method', 'post'), ('action', '/post')]
print(root.forms[0].method) # POST
```

从前面的代码中可以看到，输出显示为内联注释：

+   `action`返回`key`属性`action`的 URL 值。获得的 URL 实际上是一个将处理提交的信息或选择的选项的链接。

+   `items()`返回包含元素键和值的元组列表。

+   `keys()`返回元素键的列表。

+   `method` 返回属性`method`的值，即 HTTP 请求或 HTTP 方法。有关 HTTP 方法的更多信息，请参阅第一章，*Web Scraping Fundamentals*，*了解 Web 开发和技术*部分。

# 示例 3 - 读取和解析 HTML 以检索 HTML 表单类型元素属性

在这个例子中，我们将从[`httpbin.org/forms/post`](http://httpbin.org/forms/post)的 URL 中读取 HTML，其中包含基于 HTML 的表单元素。表单元素具有各种预定义属性，例如类型，值和名称，并且可以存在手动属性。在前面的示例中，我们尝试实现各种函数 - XPath 和 CSSSelect - 以从所需元素中检索内容。

在这里，我们将尝试收集在 HTML 表单元素中找到的属性及其值：

```py
from lxml import html
import requests
response = requests.get('http://httpbin.org/forms/post')

# build the DOM Tree
tree = html.fromstring(response.text)

for element in tree.iter('input'):
     print("Element: %s \n\tvalues(): %s \n\tattrib: %s \n\titems(): %s \n\tkeys(): %s"%
     (element.tag, element.values(),element.attrib,element.items(),element.keys()))
     print("\n")
```

在前面的代码中，对于给定的 URL 获得了`response.text`和一个`str`类型对象。`fromstring()`函数解析提供的字符串对象并返回根节点或 HTMLElement `tree`类型。

在这个例子中，我们正在迭代`input`元素或`<input...>`，并试图识别每个输入所拥有的属性。

前面的代码导致了以下输出：

```py
Element: input
     values(): ['custname']
     attrib: {'name': 'custname'}
     items(): [('name', 'custname')]
     keys(): ['name']
Element: input
     values(): ['tel', 'custtel']
     attrib: {'name': 'custtel', 'type': 'tel'}
     items(): [('type', 'tel'), ('name', 'custtel')]
     keys(): ['type', 'name']
.......
.......
Element: input
     values(): ['checkbox', 'topping', 'mushroom']
     attrib: {'name': 'topping', 'type': 'checkbox', 'value': 'mushroom'}
     items(): [('type', 'checkbox'), ('name', 'topping'), ('value', 'mushroom')]
     keys(): ['type', 'name', 'value']
Element: input
     values(): ['time', '11:00', '21:00', '900', 'delivery']
     attrib: {'max': '21:00', 'type': 'time', 'step': '900', 'min': '11:00', 'name': 'delivery'}
     items(): [('type', 'time'), ('min', '11:00'), ('max', '21:00'), ('step', '900'), ('name',     'delivery')]
     keys(): ['type', 'min', 'max', 'step', 'name']
```

在代码输出中，使用了一些与`<input>`元素一起使用的函数和属性。以下是示例中使用的一些代码及其解释：

+   `element.tag`：这 r

+   返回元素`tag`名称（例如，`input`）。

+   `element.values()`：HTML 表单元素的属性存在为`key:value`对。`value`属性包含特定元素的确切数据。`values()`返回`List`对象中所选元素的`value`属性。

+   `element.attrib`：`attrib`返回一个`Dict`类型对象（字典），其中包含`key:value`对。

+   `element.items()`：`items()`返回一个包含键和值的元组的`List`对象。

+   `element.keys()`：类似于

+   `items()`，`keys()` 返回`List`对象中的属性`key`。

通过前面的示例对 lxml 及其特性进行了概述，现在我们将执行一些网络抓取任务。

# 使用 lxml 进行网页抓取

在本节中，我们将利用迄今为止学到的大部分技术和概念，并实施一些抓取任务。

对于即将进行的任务，我们将首先选择所需的 URL。在这种情况下，它将是[`books.toscrape.com/`](http://books.toscrape.com/)，但是通过定位音乐类别，即[`books.toscrape.com/catalogue/category/books/music_14/index.html`](http://books.toscrape.com/catalogue/category/books/music_14/index.html)。有了选择的目标 URL，现在是时候探索网页并识别我们愿意提取的内容了。

我们希望收集每个页面中列出的每个个体项目（即`Article`元素）的标题，价格，可用性，`imageUrl`和评级等特定信息。我们将尝试使用 lxml 和 XPath 从单个和多个页面中抓取数据，以及使用 CSS 选择器。

关于元素识别，XPath，CSS 选择器和使用 DevTools，请参阅*使用 Web 浏览器开发人员工具访问 Web 内容*部分。

# 示例 1 - 使用 lxml.html.xpath 从单个页面提取选定的数据

在这个例子中，我们将使用 XPath 从提供的 URL 中收集信息并使用 lxml 特性。

在下面的代码中，`musicUrl`字符串对象包含一个指向页面的链接。`musicUrl`使用`parse()`函数进行解析，结果是`doc`和`lxml.etree.ElementTree`对象：

```py
import lxml.html
musicUrl= "http://books.toscrape.com/catalogue/category/books/music_14/index.html"
doc = lxml.html.parse(musicUrl)
```

现在我们有了一个可用的 ElementTree `doc`；我们将收集`musicUrl`页面上找到的标题和价格等字段的 XPath 表达式。有关生成 XPath 表达式，请参考*使用 DevTools 的 XPath 和 CSS 选择器*部分。

```py
#base element
articles = doc.xpath("//*[@id='default']/div/div/div/div/section/div[2]/ol/li[1]/article")[0]

#individual element inside base
title = articles.xpath("//h3/a/text()")
price = articles.xpath("//div[2]/p[contains(@class,'price_color')]/text()")
availability = articles.xpath("//div[2]/p[2][contains(@class,'availability')]/text()[normalize-space()]")
imageUrl = articles.xpath("//div[1][contains(@class,'image_container')]/a/img/@src")
starRating = articles.xpath("//p[contains(@class,'star-rating')]/@class")
```

上述`articles`的 XPath 包含了`<article>`内所有可用字段，例如`title`、`price`、`availability`、`imageUrl`和`starRating`。`articles`字段是一种具有子元素的父元素的表达式类型。此外，还声明了子元素的单独 XPath 表达式，例如`title`字段，即`title = articles.xpath("//h3/a/text()")`。我们可以注意到表达式中使用了`articles`。

还要注意，在子表达式中，元素属性或键名，如`class`或`src`也可以分别使用`@class`和`@src`。

现在，一旦设置了单独的表达式，我们就可以打印收集到的所有表达式的信息，并将其返回到 Python 列表中。收到的数据也已经使用`map()`、`replace()`和`strip()` Python 函数以及 Lambda 运算符进行了清理和格式化，如下面的代码所示：

```py
#cleaning and formatting 
stock = list(map(lambda stock:stock.strip(),availability))
images = list(map(lambda img:img.replace('../../../..','http://books.toscrape.com'),imageUrl))
rating = list(map(lambda rating:rating.replace('star-rating ',''),starRating))

print(title)
print(price)
print(stock)
print(images)
print(rating)
```

收集或提取的数据可能需要额外的清理任务，即删除不需要的字符、空格等。它可能还需要格式化或将数据转换为所需的格式，例如将字符串日期和时间转换为数值，等等。这两个操作有助于保持一些预定义或相同结构的数据。

上述代码的最终输出如下截图所示：

！[](assets/12cb33b8-3a35-4e8d-aa7e-64ccc854f962.png)

从所选页面获取各种数据的 Python 列表

从上述截图中可以看出，有一个针对目标数据的单独收集。以这种方式收集的数据可以合并到单个 Python 对象中，如下面的代码所示，也可以写入外部文件，例如 CSV 或 JSON，以进行进一步处理：

```py
#Merging all 
dataSet = zip(title,price,stock,images,rating)
print(list(dataSet))

[('Rip it Up and ...', '£35.02', 'In stock', 'http://books.toscrape.com/media/cache/81/c4/81c4a973364e17d01f217e1188253d5e.jpg', 'Five'), 
('Our Band Could Be ...', '£57.25', 'In stock', 'http://books.toscrape.com/media/cache/54/60/54607fe8945897cdcced0044103b10b6.jpg', 'Three'),
.........
......... 
('Old Records Never Die: ...', '£55.66', 'In stock', 'http://books.toscrape.com/media/cache/7e/94/7e947f3dd04f178175b85123829467a9.jpg', 'Two'), 
('Forever Rockers (The Rocker ...', '£28.80', 'In stock', 'http://books.toscrape.com/media/cache/7f/b0/7fb03a053c270000667a50dd8d594843.jpg', 'Three')]
```

上述代码中的`dataSet`是使用`zip()` Python 函数生成的。`zip()`收集所有提供的列表对象的单个索引，并将它们附加为元组。`dataSet`的最终输出对于每个`<article>`都有特定的值，就像前面的代码中所示的那样。

# 示例 2 - 使用 XPath 循环并从多个页面抓取数据

在示例 1 中，我们尝试了基于简单 XPath 的技术，用于单个页面上有限数量的结果的 URL。在这种情况下，我们将针对*食品和饮料*类别进行操作，即[`books.toscrape.com/catalogue/category/books/food-and-drink_33/index.html`](http://books.toscrape.com/catalogue/category/books/food-and-drink_33/index.html)，该类别的内容跨页面存在。在本例中将使用基于 XPath 的循环操作，这支持更有效地收集数据。

由于我们将处理多个页面，因此最好的做法是在浏览器中查找一些单独页面的 URL，以便在浏览列出的页面时找到这些 URL。大多数情况下，它可能包含一些模式，可以轻松解决难题，就像以下代码中使用的那样：

```py
import lxml.html
from lxml.etree import XPath

baseUrl = "http://books.toscrape.com/"

#Main URL
bookUrl = "http://books.toscrape.com/catalogue/category/books/food-and-drink_33/index.html"

#Page URL Pattern obtained (eg: page-1.html, page-2.html...)
pageUrl = "http://books.toscrape.com/catalogue/category/books/food-and-drink_33/page-"
```

`bookUrl`是我们感兴趣的主要 URL；它还包含下一页的页面链接，其中包含一个模式，如`pageUrl`中所找到的那样，例如`page-2.html`：

```py
dataSet = []
page=1
totalPages=1
while(page<=totalPages):
    print("Rows in Dataset: "+str(len(dataSet)))
    if(page==1):
        doc = lxml.html.parse(pageUrl+str(page)+".html").getroot()
        perPageArticles = doc.xpath("//*[@id=\"default\"]//form/strong[3]/text()")
        totalArticles = doc.xpath("//*[@id=\"default\"]//form/strong[1]/text()")
        totalPages = round(int(totalArticles[0])/int(perPageArticles[0]))
        print(str(totalArticles[0])+" Results, showing "+str(perPageArticles[0])+" Articles per page")
    else:
        doc = lxml.html.parse(pageUrl+str(page)+".html").getroot()

    #used to find page URL pattern
    nextPage = doc.xpath("//*[@id=\"default\"]//ul[contains(@class,'pager')]/li[2]/a/@href")
    if len(nextPage)>0: 
        print("Scraping Page "+str(page)+" of "+str(totalPages)+". NextPage > "+str(nextPage[0]))
    else:
        print("Scraping Page "+str(page)+" of "+str(totalPages))
```

定义了一个空的`dataSet`列表，用于保存跨页面找到的每篇文章的数据。

个人页面 URL 是通过将`pageUrl`与页面编号和`.html`连接而获得的。在从页面本身跟踪到的`totalArticles`和`perPageArticles`计算后找到`totalPages`。获得的`totalPages`将给出一个确切的循环计数，并且更容易应用于循环（`while`循环在代码中找到）：

```py
articles = XPath("//*[@id='default']//ol/li[position()>0]")

titlePath = XPath(".//article[contains(@class,'product_pod')]/h3/a/text()")
pricePath = XPath(".//article/div[2]/p[contains(@class,'price_color')]/text()")
stockPath = XPath(".//article/div[2]/p[2][contains(@class,'availability')]/text()[normalize-space()]")
imagePath = XPath(".//article/div[1][contains(@class,'image_container')]/a/img/@src")
starRating = XPath(".//article/p[contains(@class,'star-rating')]/@class")
```

正如我们在前面的代码中所看到的，`articles`是用于循环查找`<article>`字段内的各个元素的主要 XPath 表达式。该表达式应包含一个特定条件，可以满足以执行循环；在这种情况下，我们确定`<article>`字段存在于`<ol><li>`元素内部。

因此，我们可以使用`li[position()>0]`执行循环，该循环标识每个在`<ol>`中存在的`<li>`内找到的`<article>`字段，即`articles = XPath("//*[@id='default']//ol/li[position()>0]")`：

```py
#looping through 'articles' found in 'doc' i.e each <li><article> found in Page Source
for row in articles(doc): 
     title = titlePath(row)[0]
     price = pricePath(row)[0]
     availability = stockPath(row)[0].strip()
     image = imagePath(row)[0]
     rating = starRating(row)[0]

     #cleaning and formatting applied to image and rating
     dataSet.append([title,price,availability,image.replace('../../../..',baseUrl),rating.replace('star-rating','')])

page+=1 #updating Page Count for While loop

#Final Dataset with data from all pages. 
print(dataSet)
```

XPath 表达式的各个元素被定义为`titlePath`元素，`imagePath`元素等，以定位要获取的特定元素。最后，为文章设置的表达式被循环到每个页面获得的 HTMLElement 中，即`doc`元素，并收集每个`title`和`image`元素的第一次出现以及找到的其他元素。这些收集的数据被附加到`dataSet`字段中，作为经过清理和格式化的列表，其结果显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/059c3514-4cf0-4d47-ae5e-c51f3cba78f3.png)

带有分页信息和 dataSet 内容的输出

# 示例 3 - 使用 lxml.cssselect 从页面中抓取内容

CSS 选择器具有广泛的查询选项，如*XPath 和 CSS 选择器简介*部分所述，并且通常用作 XPath 的简单替代方法。在前面的两个示例中，我们探索了 XPath 以收集所需的信息。在这个例子中，我们将使用 lxml 中的`cssselect`从[`developer.ibm.com/announcements/category/data-science/?fa=date%3ADESC&fb=`](https://developer.ibm.com/announcements/category/data-science/?fa=date%3ADESC&fb=)上的单个页面收集相关数据。

要识别 CSS 查询，可以浏览页面源代码或使用 DevTools。有关使用 DevTools 的更多详细信息，请参阅*使用 DevTools 进行 XPath 和 CSS 选择器*部分。在这种情况下，我们正在使用 DevTools 识别和收集 CSS 查询，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/f06876ef-04f3-4456-aa83-13e9d499b882.png)

使用 DevTools 并从 https://developer.ibm.com/announcements 选择选择器

从上述截图中，我们可以看到，个别公告是由`a.ibm--card__block_link`在`div.ibm--card`内找到的块标识的，该块具有具有类的 HTML 元素，例如`ibm--card__body`和`ibm--card__type`。使用所描述的过程复制 CSS 选择器将分别为`a.ibm--card__block_link`和`div.ibm--card__body`生成以下列表：

+   `#content > div > div.code_main > div > div.cpt-content > div > div.bx--grid.no-pad.cpt--item__row > div:nth-child(1) > div:nth-child(1) > div > a`

+   `#content > div > div.code_main > div > div.cpt-content > div > div.bx--grid.no-pad.cpt--item__row > div:nth-child(1) > div:nth-child(1) > div > a > div.ibm--card__body`

让我们使用 Python 代码部署前面的概念，如下片段所示：

```py
from lxml import html
import requests
from lxml.cssselect import CSSSelector
url = 'https://developer.ibm.com/announcements/category/data-science/?fa=date%3ADESC&fb='
url_get = requests.get(url)
tree = html.document_fromstring(url_get.content)
```

所需的 Python 库和 URL 已声明，并且页面内容`url_get`已使用`lxml.html`进行解析。通过获得的`lxml.html.HTMLElement`，我们现在可以使用 XPath 或 CSS 选择器选择和导航到树中的所需元素：

```py
announcements=[]
articles = tree.cssselect('.ibm--card > a.ibm--card__block_link')

for article in articles:
    link = article.get('href')
    atype = article.cssselect('div.ibm--card__body > h5')[0].text.strip()
    adate = article.cssselect('div.ibm--card__body > h5 > .ibm--card__date')[0].text
    title = article.cssselect('div.ibm--card__body > h3.ibm--card__title')[0].text_content()
    excerpt= article.cssselect(' div.ibm--card__body > p.ibm--card__excerpt')[0].text
    category= article.cssselect('div.ibm--card__bottom > p.cpt-byline__categories span')

    #only two available on block: except '+'
    #announcements.append([link,atype,adate,title,excerpt,[category[0].text,category[1].text]])

    announcements.append([link,atype,adate,title,excerpt,[span.text for span in category if     span.text!='+']])

print(announcements)
```

`articles`是一个定义好的主要 CSS 查询，并且对在页面中找到的所有可用`articles`进行循环，作为`article`。每篇文章都有不同的元素，如类型、日期、标题、类别等。使用`text`、`text_content()`和`get()`来收集元素数据或属性。`cssselect`返回 Python 列表对象，因此使用索引，如`[0]`，来收集特定元素内容。

前面的代码中的`category`没有任何索引，因为它包含多个`<span>`元素，其值是使用列表推导技术提取的，同时附加或使用索引如注释中所示。代码获得的输出如下截图所示。尝试对数据进行了轻微的清理，但最终列表仍然包含获得的原始数据：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-web-scp-py/img/3cfdddb1-72ed-4663-8f8e-bce9310f1c49.png)

使用 lxml.cssselect 获取的列表公告的输出还要注意的是，使用 DevTools 复制或获取的 CSS 选择器查询在表达和长度上似乎与示例代码中的不同。DevTools 提供的查询包含从找到的所有选择的元素的父元素的详细信息和链接表达式。在代码中，我们只使用了特定元素的 CSS 查询。

# 总结

元素识别、基于 DOM 的导航、使用基于浏览器的开发者工具、部署数据提取技术以及对 XPath 和 CSS 选择器的概述，以及在 Python 库中使用 lxml，这些都是本章探讨的主要主题。

我们还通过使用 lxml 探索了各种示例，实现了不同的技术和库特性来处理元素和 ElementTree。最后，通过示例探讨了网页抓取技术，重点关注了在实际情况中可能出现的不同情况。

在下一章中，我们将学习更多关于网页抓取技术以及一些使用这些技术的新 Python 库。

# 进一步阅读

+   DOM：[`dom.spec.whatwg.org/`](https://dom.spec.whatwg.org/)

+   XPath：[`www.w3.org/TR/xpath/`](https://www.w3.org/TR/xpath/)，[`www.w3.org/TR/2017/REC-xpath-31-20170321/`](https://www.w3.org/TR/2017/REC-xpath-31-20170321/)

+   XML DOM：[`www.w3schools.com/xml/dom_intro.asp`](https://www.w3schools.com/xml/dom_intro.asp)

+   XPath 介绍：[`www.w3schools.com/xml/xpath_intro.asp`](https://www.w3schools.com/xml/xpath_intro.asp)

+   XPath 测试器：[`freeformatter.com/xpath-tester.html`](https://freeformatter.com/xpath-tester.html)，[`www.xpathtester.com/xslt`](http://www.xpathtester.com/xslt)，[`codebeautify.org/Xpath-Tester`](https://codebeautify.org/Xpath-Tester)

+   XPath 教程：[`doc.scrapy.org/en/xpath-tutorial/topics/xpath-tutorial.html`](https://doc.scrapy.org/en/xpath-tutorial/topics/xpath-tutorial.html)

+   CSS 选择器参考：[`www.w3schools.com/cssref/css_selectors.asp`](https://www.w3schools.com/cssref/css_selectors.asp)

+   CSS 伪类和元素：[`www.w3schools.com/css/css_pseudo_elements.asp`](https://www.w3schools.com/css/css_pseudo_elements.asp)

+   CSS 信息：[`www.css3.info/`](http://www.css3.info/)，[`developer.mozilla.org/en-US/docs/Web/CSS`](https://developer.mozilla.org/en-US/docs/Web/CSS)

+   CSS 查询解析器：[`try.jsoup.org/`](https://try.jsoup.org/)

+   CSS 选择器转换为 XPath：[`css-selector-to-xpath.appspot.com`](https://css-selector-to-xpath.appspot.com)

+   ElementTree 概述：[`effbot.org/zone/element-index.htm`](http://effbot.org/zone/element-index.htm)
