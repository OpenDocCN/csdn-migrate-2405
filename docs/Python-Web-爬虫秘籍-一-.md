# Python Web 爬虫秘籍（一）

> 原文：[`zh.annas-archive.org/md5/6ba628f13aabe820a089a16eaa190089`](https://zh.annas-archive.org/md5/6ba628f13aabe820a089a16eaa190089)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

互联网包含大量数据。这些数据既通过结构化 API 提供，也通过网站直接提供。虽然 API 中的数据高度结构化，但在网页中找到的信息通常是非结构化的，需要收集、提取和处理才能有价值。收集数据只是旅程的开始，因为这些数据还必须存储、挖掘，然后以增值形式向他人展示。

通过这本书，您将学习从网站收集各种信息所需的核心任务。我们将介绍如何收集数据，如何执行几种常见的数据操作（包括存储在本地和远程数据库中），如何执行常见的基于媒体的任务，如将图像和视频转换为缩略图，如何使用 NTLK 清理非结构化数据，如何检查几种数据挖掘和可视化工具，以及构建基于微服务的爬虫和 API 的核心技能，这些技能可以并且将在云上运行。

通过基于配方的方法，我们将学习独立的技术，以解决不仅仅是爬取，还包括数据操作和管理、数据挖掘、可视化、微服务、容器和云操作中涉及的特定任务。这些配方将以渐进和整体的方式建立技能，不仅教授如何执行爬取的基础知识，还将带您从爬取的结果到通过云向他人提供的服务。我们将使用 Python、容器和云生态系统中的常用工具构建一个实际的网络爬虫服务。

# 这本书适合谁

这本书适合那些想要学习使用爬取过程从网站提取数据以及如何使用各种数据管理工具和云服务的人。编码将需要基本的 Python 编程语言技能。

这本书还适合那些希望了解更大的工具生态系统，用于检索、存储和搜索数据，以及使用现代工具和 Python 库创建数据 API 和云服务的人。您可能还会使用 Docker 和 Amazon Web Services 在云上打包和部署爬虫。

# 本书涵盖内容

第一章，“开始爬取”，介绍了网页爬取的几个概念和工具。我们将研究如何安装并使用工具，如 requests、urllib、BeautifulSoup、Scrapy、PhantomJS 和 Selenium 进行基本任务。

第二章，“数据获取和提取”，基于对 HTML 结构的理解以及如何查找和提取嵌入式数据。我们将涵盖 DOM 中的许多概念以及如何使用 BeautifulSoup、XPath、LXML 和 CSS 选择器查找和提取数据。我们还简要介绍了 Unicode / UTF8 的工作。

第三章，“处理数据”，教你如何以多种格式加载和操作数据，然后如何将数据存储在各种数据存储中（S3、MySQL、PostgreSQL 和 ElasticSearch）。网页中的数据以各种格式表示，最常见的是 HTML、JSON、CSV 和 XML。我们还将研究使用消息队列系统，主要是 AWS SQS，来帮助构建强大的数据处理管道。

第四章，“处理图像、音频和其他资产”，研究了检索多媒体项目的方法，将它们存储在本地，并执行诸如 OCR、生成缩略图、制作网页截图、从视频中提取音频以及在 YouTube 播放列表中找到所有视频 URL 等多项任务。

第五章，*爬取-行为准则*，涵盖了与爬取的合法性有关的几个概念，以及进行礼貌爬取的实践。我们将研究处理 robots.txt 和站点地图的工具，以尊重网络主机对可接受行为的要求。我们还将研究爬行的几个方面的控制，比如使用延迟、包含爬行的深度和长度、使用用户代理以及实施缓存以防止重复请求。

第六章，*爬取挑战与解决方案*，涵盖了编写健壮爬虫时面临的许多挑战，以及如何处理许多情况。这些情况包括分页、重定向、登录表单、保持爬虫在同一域内、请求失败时重试以及处理验证码。

第七章，*文本整理和分析*，探讨了各种工具，比如使用 NLTK 进行自然语言处理，以及如何去除常见的噪音词和标点符号。我们经常需要处理网页的文本内容，以找到页面上作为文本一部分的信息，既不是结构化/嵌入式数据，也不是多媒体。这需要使用各种概念和工具来清理和理解文本。

第八章，*搜索、挖掘和可视化数据*，涵盖了在网上搜索数据、存储和组织数据，以及从已识别的关系中得出结果的几种方法。我们将看到如何理解维基百科贡献者的地理位置，找到 IMDB 上演员之间的关系，以及在 Stack Overflow 上找到与特定技术匹配的工作。

第九章，*创建一个简单的数据 API*，教会我们如何创建一个爬虫作为服务。我们将使用 Flask 为爬虫创建一个 REST API。我们将在这个 API 后面运行爬虫作为服务，并能够提交请求来爬取特定页面，以便从爬取和本地 ElasticSearch 实例中动态查询数据。

第十章，*使用 Docker 创建爬虫微服务*，通过将服务和 API 打包到 Docker 集群中，并通过消息队列系统（AWS SQS）分发请求，继续扩展我们的爬虫服务。我们还将介绍使用 Docker 集群工具来扩展和缩减爬虫实例。

第十一章，*使爬虫成为真正的服务*，通过充实上一章中创建的服务来结束，添加一个爬虫，汇集了之前介绍的各种概念。这个爬虫可以帮助分析 StackOverflow 上的职位发布，以找到并比较使用指定技术的雇主。该服务将收集帖子，并允许查询以找到并比较这些公司。

# 为了充分利用本书

本书中所需的主要工具是 Python 3 解释器。这些配方是使用 Anaconda Python 发行版的免费版本编写的，具体版本为 3.6.1。其他 Python 3 发行版应该也能很好地工作，但尚未经过测试。

配方中的代码通常需要使用各种 Python 库。这些都可以使用`pip`进行安装，并且可以使用`pip install`进行访问。在需要的地方，这些安装将在配方中详细说明。

有几个配方需要亚马逊 AWS 账户。AWS 账户在第一年可以免费使用免费层服务。配方不需要比免费层服务更多的东西。可以在[`portal.aws.amazon.com/billing/signup`](https://portal.aws.amazon.com/billing/signup)上创建一个新账户。

几个食谱将利用 Elasticsearch。GitHub 上有一个免费的开源版本，网址是[`github.com/elastic/elasticsearch`](https://github.com/elastic/elasticsearch)，该页面上有安装说明。Elastic.co 还提供了一个完全功能的版本（还带有 Kibana 和 Logstash），托管在云上，并提供为期 14 天的免费试用，网址是[`info.elastic.co`](http://info.elastic.co)（我们将使用）。还有一个 docker-compose 版本，具有所有 x-pack 功能，网址是[`github.com/elastic/stack-docker`](https://github.com/elastic/stack-docker)，所有这些都可以通过简单的`docker-compose up`命令启动。

最后，一些食谱使用 MySQL 和 PostgreSQL 作为数据库示例，以及这些数据库的几个常见客户端。对于这些食谱，这些都需要在本地安装。 MySQL Community Server 可在[`dev.mysql.com/downloads/mysql/`](https://dev.mysql.com/downloads/mysql/)上找到，而 PostgreSQL 可在[`www.postgresql.org/`](https://www.postgresql.org/)上找到。

我们还将研究创建和使用多个食谱的 docker 容器。 Docker CE 是免费的，可在[`www.docker.com/community-edition`](https://www.docker.com/community-edition)上获得。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，文件将直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址是[`github.com/PacktPublishing/Python-Web-Scraping-Cookbook`](https://github.com/PacktPublishing/Python-Web-Scraping-Cookbook)。我们还有其他代码包，来自我们丰富的书籍和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“这将循环遍历多达 20 个字符，并将它们放入`sw`索引中，文档类型为`people`”

代码块设置如下：

```py
from elasticsearch import Elasticsearch
import requests
import json

if __name__ == '__main__':
    es = Elasticsearch(
        [
```

任何命令行输入或输出都按如下方式编写：

```py
$ curl https://elastic:tduhdExunhEWPjSuH73O6yLS@7dc72d3327076cc4daf5528103c46a27.us-west-2.aws.found.io:9243
```

**粗体**：表示一个新术语、一个重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会出现在文本中。这是一个例子：“从管理面板中选择系统信息。”

警告或重要说明会出现在这样的地方。提示和技巧会出现在这样的地方。


# 第一章：开始爬取

在本章中，我们将涵盖以下主题：

+   设置 Python 开发环境

+   使用 Requests 和 Beautiful Soup 爬取 Python.org

+   使用 urllib3 和 Beautiful Soup 爬取 Python.org

+   使用 Scrapy 爬取 Python.org

+   使用 Selenium 和 PhantomJs 爬取 Python.org

# 介绍

网上可用的数据量在数量和形式上都在持续增长。企业需要这些数据来做决策，特别是随着需要大量数据进行训练的机器学习工具的爆炸式增长。很多数据可以通过应用程序编程接口获得，但同时也有很多有价值的数据仍然只能通过网页抓取获得。

本章将重点介绍设置爬取环境的几个基本原理，并使用行业工具进行基本数据请求。Python 是本书的首选编程语言，也是许多进行爬取系统构建的人的首选语言。它是一种易于使用的编程语言，拥有丰富的工具生态系统，适用于许多任务。如果您使用其他语言进行编程，您会发现很容易上手，也许永远不会回头！

# 设置 Python 开发环境

如果您以前没有使用过 Python，拥有一个可用的开发环境是很重要的。本书中的示例将全部使用 Python，并且是交互式示例的混合，但主要是作为脚本实现，由 Python 解释器解释。这个示例将向您展示如何使用`virtualenv`设置一个隔离的开发环境，并使用`pip`管理项目依赖。我们还会获取本书的代码并将其安装到 Python 虚拟环境中。

# 准备工作

我们将专门使用 Python 3.x，特别是在我的情况下是 3.6.1。虽然 Mac 和 Linux 通常已安装了 Python 2 版本，而 Windows 系统没有安装。因此很可能需要安装 Python 3。您可以在 www.python.org 找到 Python 安装程序的参考资料。

您可以使用`python --version`检查 Python 的版本

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/e9039d11-8e50-44c6-8204-3199ae5d7b1e.png)`pip`已经随 Python 3.x 一起安装，因此我们将省略其安装说明。此外，本书中的所有命令行示例都在 Mac 上运行。对于 Linux 用户，命令应该是相同的。在 Windows 上，有替代命令（如 dir 而不是 ls），但这些替代命令将不会被涵盖。

# 如何做...

我们将使用`pip`安装许多包。这些包将被安装到一个 Python 环境中。通常可能会与其他包存在版本冲突，因此在跟着本书的示例进行操作时，一个很好的做法是创建一个新的虚拟 Python 环境，确保我们将使用的包能够正常工作。

虚拟 Python 环境是用`virtualenv`工具管理的。可以用以下命令安装它：

```py
~ $ pip install virtualenv
Collecting virtualenv
 Using cached virtualenv-15.1.0-py2.py3-none-any.whl
Installing collected packages: virtualenv
Successfully installed virtualenv-15.1.0
```

现在我们可以使用`virtualenv`。但在那之前，让我们简要地看一下`pip`。这个命令从 PyPI 安装 Python 包，PyPI 是一个拥有成千上万个包的包存储库。我们刚刚看到了使用 pip 的 install 子命令，这可以确保一个包被安装。我们也可以用`pip list`来查看当前安装的所有包：

```py
~ $ pip list
alabaster (0.7.9)
amqp (1.4.9)
anaconda-client (1.6.0)
anaconda-navigator (1.5.3)
anaconda-project (0.4.1)
aniso8601 (1.3.0)
```

我截取了前几行，因为安装了很多包。对我来说，安装了 222 个包。

也可以使用`pip uninstall`命令卸载包。我留给您去尝试一下。

现在回到`virtualenv`。使用`virtualenv`非常简单。让我们用它来创建一个环境并安装来自 github 的代码。让我们一步步走过这些步骤：

1.  创建一个代表项目的目录并进入该目录。

```py
~ $ mkdir pywscb
~ $ cd pywscb
```

1.  初始化一个名为 env 的虚拟环境文件夹：

```py
pywscb $ virtualenv env
Using base prefix '/Users/michaelheydt/anaconda'
New python executable in /Users/michaelheydt/pywscb/env/bin/python
copying /Users/michaelheydt/anaconda/bin/python => /Users/michaelheydt/pywscb/env/bin/python
copying /Users/michaelheydt/anaconda/bin/../lib/libpython3.6m.dylib => /Users/michaelheydt/pywscb/env/lib/libpython3.6m.dylib
Installing setuptools, pip, wheel...done.
```

1.  这将创建一个 env 文件夹。让我们看看安装了什么。

```py
pywscb $ ls -la env
total 8
drwxr-xr-x 6  michaelheydt staff 204 Jan 18 15:38 .
drwxr-xr-x 3  michaelheydt staff 102 Jan 18 15:35 ..
drwxr-xr-x 16 michaelheydt staff 544 Jan 18 15:38 bin
drwxr-xr-x 3  michaelheydt staff 102 Jan 18 15:35 include
drwxr-xr-x 4  michaelheydt staff 136 Jan 18 15:38 lib
-rw-r--r-- 1  michaelheydt staff 60 Jan 18 15:38  pip-selfcheck.json
```

1.  现在我们激活虚拟环境。这个命令使用`env`文件夹中的内容来配置 Python。之后所有的 python 活动都是相对于这个虚拟环境的。

```py
pywscb $ source env/bin/activate
(env) pywscb $
```

1.  我们可以使用以下命令检查 python 是否确实使用了这个虚拟环境：

```py
(env) pywscb $ which python
/Users/michaelheydt/pywscb/env/bin/python
```

有了我们创建的虚拟环境，让我们克隆书籍的示例代码并看看它的结构。

```py
(env) pywscb $ git clone https://github.com/PacktBooks/PythonWebScrapingCookbook.git
 Cloning into 'PythonWebScrapingCookbook'...
 remote: Counting objects: 420, done.
 remote: Compressing objects: 100% (316/316), done.
 remote: Total 420 (delta 164), reused 344 (delta 88), pack-reused 0
 Receiving objects: 100% (420/420), 1.15 MiB | 250.00 KiB/s, done.
 Resolving deltas: 100% (164/164), done.
 Checking connectivity... done.
```

这创建了一个`PythonWebScrapingCookbook`目录。

```py
(env) pywscb $ ls -l
 total 0
 drwxr-xr-x 9 michaelheydt staff 306 Jan 18 16:21 PythonWebScrapingCookbook
 drwxr-xr-x 6 michaelheydt staff 204 Jan 18 15:38 env
```

让我们切换到它并检查内容。

```py
(env) PythonWebScrapingCookbook $ ls -l
 total 0
 drwxr-xr-x 15 michaelheydt staff 510 Jan 18 16:21 py
 drwxr-xr-x 14 michaelheydt staff 476 Jan 18 16:21 www
```

有两个目录。大部分 Python 代码都在`py`目录中。`www`包含一些我们将使用的网络内容，我们将使用本地 web 服务器不时地访问它。让我们看看`py`目录的内容：

```py
(env) py $ ls -l
 total 0
 drwxr-xr-x 9  michaelheydt staff 306 Jan 18 16:21 01
 drwxr-xr-x 25 michaelheydt staff 850 Jan 18 16:21 03
 drwxr-xr-x 21 michaelheydt staff 714 Jan 18 16:21 04
 drwxr-xr-x 10 michaelheydt staff 340 Jan 18 16:21 05
 drwxr-xr-x 14 michaelheydt staff 476 Jan 18 16:21 06
 drwxr-xr-x 25 michaelheydt staff 850 Jan 18 16:21 07
 drwxr-xr-x 14 michaelheydt staff 476 Jan 18 16:21 08
 drwxr-xr-x 7  michaelheydt staff 238 Jan 18 16:21 09
 drwxr-xr-x 7  michaelheydt staff 238 Jan 18 16:21 10
 drwxr-xr-x 9  michaelheydt staff 306 Jan 18 16:21 11
 drwxr-xr-x 8  michaelheydt staff 272 Jan 18 16:21 modules
```

每个章节的代码都在与章节匹配的编号文件夹中（第二章没有代码，因为它都是交互式 Python）。

请注意，有一个`modules`文件夹。本书中的一些食谱使用这些模块中的代码。确保你的 Python 路径指向这个文件夹。在 Mac 和 Linux 上，你可以在你的`.bash_profile`文件中设置这一点（在 Windows 上是在环境变量对话框中）：

```py
export PYTHONPATH="/users/michaelheydt/dropbox/packt/books/pywebscrcookbook/code/py/modules"
export PYTHONPATH
```

每个文件夹中的内容通常遵循与章节中食谱顺序相匹配的编号方案。以下是第六章文件夹的内容：

```py
(env) py $ ls -la 06
 total 96
 drwxr-xr-x 14 michaelheydt staff 476 Jan 18 16:21 .
 drwxr-xr-x 14 michaelheydt staff 476 Jan 18 16:26 ..
 -rw-r--r-- 1  michaelheydt staff 902 Jan 18 16:21  01_scrapy_retry.py
 -rw-r--r-- 1  michaelheydt staff 656 Jan 18 16:21  02_scrapy_redirects.py
 -rw-r--r-- 1  michaelheydt staff 1129 Jan 18 16:21 03_scrapy_pagination.py
 -rw-r--r-- 1  michaelheydt staff 488 Jan 18 16:21  04_press_and_wait.py
 -rw-r--r-- 1  michaelheydt staff 580 Jan 18 16:21  05_allowed_domains.py
 -rw-r--r-- 1  michaelheydt staff 826 Jan 18 16:21  06_scrapy_continuous.py
 -rw-r--r-- 1  michaelheydt staff 704 Jan 18 16:21  07_scrape_continuous_twitter.py
 -rw-r--r-- 1  michaelheydt staff 1409 Jan 18 16:21 08_limit_depth.py
 -rw-r--r-- 1  michaelheydt staff 526 Jan 18 16:21  09_limit_length.py
 -rw-r--r-- 1  michaelheydt staff 1537 Jan 18 16:21 10_forms_auth.py
 -rw-r--r-- 1  michaelheydt staff 597 Jan 18 16:21  11_file_cache.py
 -rw-r--r-- 1  michaelheydt staff 1279 Jan 18 16:21 12_parse_differently_based_on_rules.py
```

在食谱中，我会说明我们将使用`<章节目录>`/`<食谱文件名>`中的脚本。

恭喜，你现在已经配置了一个带有书籍代码的 Python 环境！

现在，如果你想退出 Python 虚拟环境，你可以使用以下命令退出：

```py
(env) py $ deactivate
 py $
```

检查一下 python，我们可以看到它已经切换回来了：

```py
py $ which python
 /Users/michaelheydt/anaconda/bin/python
```

我不会在本书的其余部分使用虚拟环境。当你看到命令提示时，它们将是以下形式之一"<目录> $"或者简单的"$"。

现在让我们开始爬取一些数据。

# 使用 Requests 和 Beautiful Soup 从 Python.org 上爬取数据

在这个食谱中，我们将安装 Requests 和 Beautiful Soup，并从 www.python.org 上爬取一些内容。我们将安装这两个库，并对它们有一些基本的了解。在随后的章节中，我们将深入研究它们。

# 准备好了...

在这个食谱中，我们将从[`www.python.org/events/pythonevents`](https://www.python.org/events/pythonevents)中爬取即将到来的 Python 事件。以下是`Python.org 事件页面`的一个示例（它经常更改，所以你的体验会有所不同）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/c4caf889-b8fa-4f5e-87dc-d6d78921bddb.png)

我们需要确保 Requests 和 Beautiful Soup 已安装。我们可以使用以下命令来安装：

```py
pywscb $ pip install requests
Downloading/unpacking requests
 Downloading requests-2.18.4-py2.py3-none-any.whl (88kB): 88kB downloaded
Downloading/unpacking certifi>=2017.4.17 (from requests)
 Downloading certifi-2018.1.18-py2.py3-none-any.whl (151kB): 151kB downloaded
Downloading/unpacking idna>=2.5,<2.7 (from requests)
 Downloading idna-2.6-py2.py3-none-any.whl (56kB): 56kB downloaded
Downloading/unpacking chardet>=3.0.2,<3.1.0 (from requests)
 Downloading chardet-3.0.4-py2.py3-none-any.whl (133kB): 133kB downloaded
Downloading/unpacking urllib3>=1.21.1,<1.23 (from requests)
 Downloading urllib3-1.22-py2.py3-none-any.whl (132kB): 132kB downloaded
Installing collected packages: requests, certifi, idna, chardet, urllib3
Successfully installed requests certifi idna chardet urllib3
Cleaning up...
pywscb $ pip install bs4
Downloading/unpacking bs4
 Downloading bs4-0.0.1.tar.gz
 Running setup.py (path:/Users/michaelheydt/pywscb/env/build/bs4/setup.py) egg_info for package bs4
```

# 如何做...

现在让我们去学习一下爬取一些事件。对于这个食谱，我们将开始使用交互式 python。

1.  用`ipython`命令启动它：

```py
$ ipython
Python 3.6.1 |Anaconda custom (x86_64)| (default, Mar 22 2017, 19:25:17)
Type "copyright", "credits" or "license" for more information.
IPython 5.1.0 -- An enhanced Interactive Python.
? -> Introduction and overview of IPython's features.
%quickref -> Quick reference.
help -> Python's own help system.
object? -> Details about 'object', use 'object??' for extra details.
In [1]:
```

1.  接下来导入 Requests

```py
In [1]: import requests
```

1.  我们现在使用 requests 来对以下 url 进行 GET HTTP 请求：[`www.python.org/events/python-events/`](https://www.python.org/events/python-events/)，通过进行`GET`请求：

```py
In [2]: url = 'https://www.python.org/events/python-events/'
In [3]: req = requests.get(url)
```

1.  这下载了页面内容，但它存储在我们的 requests 对象 req 中。我们可以使用`.text`属性检索内容。这打印了前 200 个字符。

```py
req.text[:200]
Out[4]: '<!doctype html>\n<!--[if lt IE 7]> <html class="no-js ie6 lt-ie7 lt-ie8 lt-ie9"> <![endif]-->\n<!--[if IE 7]> <html class="no-js ie7 lt-ie8 lt-ie9"> <![endif]-->\n<!--[if IE 8]> <h'
```

现在我们有了页面的原始 HTML。我们现在可以使用 beautiful soup 来解析 HTML 并检索事件数据。

1.  首先导入 Beautiful Soup

```py
In [5]: from bs4 import BeautifulSoup
```

1.  现在我们创建一个`BeautifulSoup`对象并传递 HTML。

```py
In [6]: soup = BeautifulSoup(req.text, 'lxml')
```

1.  现在我们告诉 Beautiful Soup 找到最近事件的主要`<ul>`标签，然后获取其下的所有`<li>`标签。

```py
In [7]: events = soup.find('ul', {'class': 'list-recent-events'}).findAll('li')
```

1.  最后，我们可以循环遍历每个`<li>`元素，提取事件详情，并将每个打印到控制台：

```py
In [13]: for event in events:
 ...: event_details = dict()
 ...: event_details['name'] = event_details['name'] = event.find('h3').find("a").text
 ...: event_details['location'] = event.find('span', {'class', 'event-location'}).text
 ...: event_details['time'] = event.find('time').text
 ...: print(event_details)
 ...:
{'name': 'PyCascades 2018', 'location': 'Granville Island Stage, 1585 Johnston St, Vancouver, BC V6H 3R9, Canada', 'time': '22 Jan. – 24 Jan. 2018'}
{'name': 'PyCon Cameroon 2018', 'location': 'Limbe, Cameroon', 'time': '24 Jan. – 29 Jan. 2018'}
{'name': 'FOSDEM 2018', 'location': 'ULB Campus du Solbosch, Av. F. D. Roosevelt 50, 1050 Bruxelles, Belgium', 'time': '03 Feb. – 05 Feb. 2018'}
{'name': 'PyCon Pune 2018', 'location': 'Pune, India', 'time': '08 Feb. – 12 Feb. 2018'}
{'name': 'PyCon Colombia 2018', 'location': 'Medellin, Colombia', 'time': '09 Feb. – 12 Feb. 2018'}
{'name': 'PyTennessee 2018', 'location': 'Nashville, TN, USA', 'time': '10 Feb. – 12 Feb. 2018'}
```

整个示例都在`01/01_events_with_requests.py`脚本文件中可用。以下是它的内容，它逐步汇总了我们刚刚做的所有内容：

```py
import requests
from bs4 import BeautifulSoup

def get_upcoming_events(url):
    req = requests.get(url)

    soup = BeautifulSoup(req.text, 'lxml')

    events = soup.find('ul', {'class': 'list-recent-events'}).findAll('li')

    for event in events:
        event_details = dict()
        event_details['name'] = event.find('h3').find("a").text
        event_details['location'] = event.find('span', {'class', 'event-location'}).text
        event_details['time'] = event.find('time').text
        print(event_details)

get_upcoming_events('https://www.python.org/events/python-events/')
```

你可以在终端中使用以下命令运行它：

```py
$ python 01_events_with_requests.py
{'name': 'PyCascades 2018', 'location': 'Granville Island Stage, 1585 Johnston St, Vancouver, BC V6H 3R9, Canada', 'time': '22 Jan. – 24 Jan. 2018'}
{'name': 'PyCon Cameroon 2018', 'location': 'Limbe, Cameroon', 'time': '24 Jan. – 29 Jan. 2018'}
{'name': 'FOSDEM 2018', 'location': 'ULB Campus du Solbosch, Av. F. D. Roosevelt 50, 1050 Bruxelles, Belgium', 'time': '03 Feb. – 05 Feb. 2018'}
{'name': 'PyCon Pune 2018', 'location': 'Pune, India', 'time': '08 Feb. – 12 Feb. 2018'}
{'name': 'PyCon Colombia 2018', 'location': 'Medellin, Colombia', 'time': '09 Feb. – 12 Feb. 2018'}
{'name': 'PyTennessee 2018', 'location': 'Nashville, TN, USA', 'time': '10 Feb. – 12 Feb. 2018'}
```

# 它的工作原理...

我们将在下一章节详细介绍 Requests 和 Beautiful Soup，但现在让我们总结一下关于它的一些关键点。关于 Requests 的一些重要点：

+   Requests 用于执行 HTTP 请求。我们用它来对事件页面的 URL 进行 GET 请求。

+   Requests 对象保存了请求的结果。不仅包括页面内容，还有很多其他关于结果的项目，比如 HTTP 状态码和头部信息。

+   Requests 仅用于获取页面，不进行解析。

我们使用 Beautiful Soup 来解析 HTML 和在 HTML 中查找内容。

要理解这是如何工作的，页面的内容具有以下 HTML 来开始“即将到来的事件”部分：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/9c3b8d5a-57e7-4cab-b868-b2362f805cc8.png)

我们利用 Beautiful Soup 的强大功能：

+   找到代表该部分的`<ul>`元素，通过查找具有值为`list-recent-events`的`class`属性的`<ul>`来找到。

+   从该对象中，我们找到所有`<li>`元素。

每个`<li>`标签代表一个不同的事件。我们遍历每一个，从子 HTML 标签中找到事件数据，制作一个字典：

+   名称从`<h3>`标签的子标签`<a>`中提取

+   位置是具有`event-location`类的`<span>`的文本内容

+   时间是从`<time>`标签的`datetime`属性中提取的。

# 使用 urllib3 和 Beautiful Soup 爬取 Python.org

在这个配方中，我们将使用 requests 替换为另一个库`urllib3`。这是另一个常见的用于从 URL 检索数据以及处理 URL 的各个部分和处理各种编码的库。

# 准备工作...

这个配方需要安装`urllib3`。所以用`pip`安装它：

```py
$ pip install urllib3
Collecting urllib3
 Using cached urllib3-1.22-py2.py3-none-any.whl
Installing collected packages: urllib3
Successfully installed urllib3-1.22
```

# 如何做...

该代码在`01/02_events_with_urllib3.py`中实现。代码如下：

```py
import urllib3
from bs4 import BeautifulSoup

def get_upcoming_events(url):
    req = urllib3.PoolManager()
    res = req.request('GET', url)

    soup = BeautifulSoup(res.data, 'html.parser')

    events = soup.find('ul', {'class': 'list-recent-events'}).findAll('li')

    for event in events:
        event_details = dict()
        event_details['name'] = event.find('h3').find("a").text
        event_details['location'] = event.find('span', {'class', 'event-location'}).text
        event_details['time'] = event.find('time').text
        print(event_details)

get_upcoming_events('https://www.python.org/events/python-events/')
```

使用 Python 解释器运行它。你将得到与前一个配方相同的输出。

# 它的工作原理

这个配方唯一的区别是我们如何获取资源：

```py
req = urllib3.PoolManager()
res = req.request('GET', url)
```

与`Requests`不同，`urllib3`不会自动应用头部编码。前面示例中代码片段能够工作的原因是因为 BS4 能够很好地处理编码。但你应该记住编码是爬取的一个重要部分。如果你决定使用自己的框架或其他库，请确保编码得到很好的处理。

# 还有更多...

Requests 和 urllib3 在功能方面非常相似。一般建议在进行 HTTP 请求时使用 Requests。以下代码示例说明了一些高级功能：

```py
import requests

# builds on top of urllib3's connection pooling
# session reuses the same TCP connection if 
# requests are made to the same host
# see https://en.wikipedia.org/wiki/HTTP_persistent_connection for details
session = requests.Session()

# You may pass in custom cookie
r = session.get('http://httpbin.org/get', cookies={'my-cookie': 'browser'})
print(r.text)
# '{"cookies": {"my-cookie": "test cookie"}}'

# Streaming is another nifty feature
# From http://docs.python-requests.org/en/master/user/advanced/#streaming-requests
# copyright belongs to reques.org
r = requests.get('http://httpbin.org/stream/20', stream=True) 
```

```py
for line in r.iter_lines():
  # filter out keep-alive new lines
  if line:
     decoded_line = line.decode('utf-8')
     print(json.loads(decoded_line))
```

# 使用 Scrapy 爬取 Python.org

**Scrapy**是一个非常流行的开源 Python 爬虫框架，用于提取数据。它最初是为了爬取而设计的，但它也发展成了一个强大的网络爬虫解决方案。

在我们之前的配方中，我们使用 Requests 和 urllib2 来获取数据，使用 Beautiful Soup 来提取数据。Scrapy 提供了所有这些功能以及许多其他内置模块和扩展。在使用 Python 进行爬取时，这也是我们的首选工具。

Scrapy 提供了一些强大的功能值得一提：

+   内置扩展，用于进行 HTTP 请求和处理压缩、认证、缓存、操作用户代理和 HTTP 头部

+   内置支持使用选择器语言（如 CSS 和 XPath）选择和提取数据，以及支持利用正则表达式选择内容和链接

+   编码支持以处理语言和非标准编码声明

+   灵活的 API，可以重用和编写自定义中间件和管道，提供了一种干净简单的方式来执行任务，比如自动下载资源（例如图片或媒体）并将数据存储在文件系统、S3、数据库等中

# 准备工作...

有几种方法可以使用 Scrapy 创建一个爬虫。一种是编程模式，我们在代码中创建爬虫和爬虫。还可以从模板或生成器配置一个 Scrapy 项目，然后使用`scrapy`命令从命令行运行爬虫。本书将遵循编程模式，因为它可以更有效地将代码放在一个文件中。这将有助于我们在使用 Scrapy 时组合特定的、有针对性的配方。

这并不一定是比使用命令行执行 Scrapy 爬虫更好的方式，只是这本书的设计决定。最终，这本书不是关于 Scrapy 的（有其他专门讲 Scrapy 的书），而是更多地阐述了在爬取时可能需要做的各种事情，以及在云端创建一个功能齐全的爬虫服务。

# 如何做...

这个配方的脚本是`01/03_events_with_scrapy.py`。以下是代码：

```py
import scrapy
from scrapy.crawler import CrawlerProcess

class PythonEventsSpider(scrapy.Spider):
    name = 'pythoneventsspider'    start_urls = ['https://www.python.org/events/python-events/',]
    found_events = []

    def parse(self, response):
        for event in response.xpath('//ul[contains(@class, "list-recent-events")]/li'):
            event_details = dict()
            event_details['name'] = event.xpath('h3[@class="event-title"]/a/text()').extract_first()
            event_details['location'] = event.xpath('p/span[@class="event-location"]/text()').extract_first()
            event_details['time'] = event.xpath('p/time/text()').extract_first()
            self.found_events.append(event_details)

if __name__ == "__main__":
    process = CrawlerProcess({ 'LOG_LEVEL': 'ERROR'})
    process.crawl(PythonEventsSpider)
    spider = next(iter(process.crawlers)).spider
    process.start()

    for event in spider.found_events: print(event)
```

以下是运行脚本并显示输出的过程：

```py
~ $ python 03_events_with_scrapy.py
{'name': 'PyCascades 2018', 'location': 'Granville Island Stage, 1585 Johnston St, Vancouver, BC V6H 3R9, Canada', 'time': '22 Jan. – 24 Jan. '}
{'name': 'PyCon Cameroon 2018', 'location': 'Limbe, Cameroon', 'time': '24 Jan. – 29 Jan. '}
{'name': 'FOSDEM 2018', 'location': 'ULB Campus du Solbosch, Av. F. D. Roosevelt 50, 1050 Bruxelles, Belgium', 'time': '03 Feb. – 05 Feb. '}
{'name': 'PyCon Pune 2018', 'location': 'Pune, India', 'time': '08 Feb. – 12 Feb. '}
{'name': 'PyCon Colombia 2018', 'location': 'Medellin, Colombia', 'time': '09 Feb. – 12 Feb. '}
{'name': 'PyTennessee 2018', 'location': 'Nashville, TN, USA', 'time': '10 Feb. – 12 Feb. '}
{'name': 'PyCon Pakistan', 'location': 'Lahore, Pakistan', 'time': '16 Dec. – 17 Dec. '}
{'name': 'PyCon Indonesia 2017', 'location': 'Surabaya, Indonesia', 'time': '09 Dec. – 10 Dec. '}
```

使用另一个工具得到相同的结果。让我们快速回顾一下它是如何工作的。

# 它是如何工作的

我们将在后面的章节中详细介绍 Scrapy，但让我们快速浏览一下这段代码，以了解它是如何完成这个爬取的。Scrapy 中的一切都围绕着创建**spider**。蜘蛛根据我们提供的规则在互联网上爬行。这个蜘蛛只处理一个单独的页面，所以它并不是一个真正的蜘蛛。但它展示了我们将在后面的 Scrapy 示例中使用的模式。

爬虫是通过一个类定义创建的，该类继承自 Scrapy 爬虫类之一。我们的类继承自`scrapy.Spider`类。

```py
class PythonEventsSpider(scrapy.Spider):
    name = 'pythoneventsspider'    start_urls = ['https://www.python.org/events/python-events/',]
```

每个爬虫都有一个`name`，还有一个或多个`start_urls`，告诉它从哪里开始爬行。

这个爬虫有一个字段来存储我们找到的所有事件：

```py
    found_events = []
```

然后，爬虫有一个名为 parse 的方法，它将被调用来处理爬虫收集到的每个页面。

```py
def parse(self, response):
        for event in response.xpath('//ul[contains(@class, "list-recent-events")]/li'):
            event_details = dict()
            event_details['name'] = event.xpath('h3[@class="event-title"]/a/text()').extract_first()
            event_details['location'] = event.xpath('p/span[@class="event-location"]/text()').extract_first()
            event_details['time'] = event.xpath('p/time/text()').extract_first()
            self.found_events.append(event_details)
```

这个方法的实现使用了 XPath 选择器来从页面中获取事件（XPath 是 Scrapy 中导航 HTML 的内置方法）。它构建了`event_details`字典对象，类似于其他示例，然后将其添加到`found_events`列表中。

剩下的代码执行了 Scrapy 爬虫的编程执行。

```py
    process = CrawlerProcess({ 'LOG_LEVEL': 'ERROR'})
    process.crawl(PythonEventsSpider)
    spider = next(iter(process.crawlers)).spider
    process.start()
```

它从创建一个 CrawlerProcess 开始，该过程执行实际的爬行和许多其他任务。我们传递了一个 ERROR 的 LOG_LEVEL 来防止大量的 Scrapy 输出。将其更改为 DEBUG 并重新运行以查看差异。

接下来，我们告诉爬虫进程使用我们的 Spider 实现。我们从爬虫中获取实际的蜘蛛对象，这样当爬取完成时我们就可以获取项目。然后我们通过调用`process.start()`来启动整个过程。

当爬取完成后，我们可以迭代并打印出找到的项目。

```py
    for event in spider.found_events: print(event)
```

这个例子并没有涉及到 Scrapy 的任何强大功能。我们将在本书的后面更深入地了解一些更高级的功能。

# 使用 Selenium 和 PhantomJS 来爬取 Python.org

这个配方将介绍 Selenium 和 PhantomJS，这两个框架与之前的配方中的框架非常不同。实际上，Selenium 和 PhantomJS 经常用于功能/验收测试。我们想展示这些工具，因为它们从爬取的角度提供了独特的好处。我们将在本书的后面看到一些，比如填写表单、按按钮和等待动态 JavaScript 被下载和执行的能力。

Selenium 本身是一个与编程语言无关的框架。它提供了许多编程语言绑定，如 Python、Java、C#和 PHP（等等）。该框架还提供了许多专注于测试的组件。其中三个常用的组件是：

+   用于录制和重放测试的 IDE

+   Webdriver 实际上启动了一个 Web 浏览器（如 Firefox、Chrome 或 Internet Explorer），通过发送命令并将结果发送到所选的浏览器来运行脚本

+   网格服务器在远程服务器上执行带有 Web 浏览器的测试。它可以并行运行多个测试用例。

# 准备工作

首先，我们需要安装 Selenium。我们可以使用我们信赖的`pip`来完成这个过程：

```py
~ $ pip install selenium
Collecting selenium
 Downloading selenium-3.8.1-py2.py3-none-any.whl (942kB)
 100% |████████████████████████████████| 952kB 236kB/s
Installing collected packages: selenium
Successfully installed selenium-3.8.1
```

这将安装 Python 的 Selenium 客户端驱动程序（语言绑定）。如果你将来想要了解更多信息，可以在[`github.com/SeleniumHQ/selenium/blob/master/py/docs/source/index.rst`](https://github.com/SeleniumHQ/selenium/blob/master/py/docs/source/index.rst)找到更多信息。

对于这个配方，我们还需要在目录中有 Firefox 的驱动程序（名为`geckodriver`）。这个文件是特定于操作系统的。我已经在文件夹中包含了 Mac 的文件。要获取其他版本，请访问[`github.com/mozilla/geckodriver/releases`](https://github.com/mozilla/geckodriver/releases)。

然而，当运行这个示例时，你可能会遇到以下错误：

```py
FileNotFoundError: [Errno 2] No such file or directory: 'geckodriver'
```

如果你这样做了，将 geckodriver 文件放在系统的 PATH 中，或者将`01`文件夹添加到你的路径中。哦，你还需要安装 Firefox。

最后，需要安装 PhantomJS。你可以在[`phantomjs.org/`](http://phantomjs.org/)下载并找到安装说明。

# 如何做...

这个配方的脚本是`01/04_events_with_selenium.py`。

1.  以下是代码：

```py
from selenium import webdriver

def get_upcoming_events(url):
    driver = webdriver.Firefox()
    driver.get(url)

    events = driver.find_elements_by_xpath('//ul[contains(@class, "list-recent-events")]/li')

    for event in events:
        event_details = dict()
        event_details['name'] = event.find_element_by_xpath('h3[@class="event-title"]/a').text
        event_details['location'] = event.find_element_by_xpath('p/span[@class="event-location"]').text
        event_details['time'] = event.find_element_by_xpath('p/time').text
        print(event_details)

    driver.close()

get_upcoming_events('https://www.python.org/events/python-events/')
```

1.  然后用 Python 运行脚本。你会看到熟悉的输出：

```py
~ $ python 04_events_with_selenium.py
{'name': 'PyCascades 2018', 'location': 'Granville Island Stage, 1585 Johnston St, Vancouver, BC V6H 3R9, Canada', 'time': '22 Jan. – 24 Jan.'}
{'name': 'PyCon Cameroon 2018', 'location': 'Limbe, Cameroon', 'time': '24 Jan. – 29 Jan.'}
{'name': 'FOSDEM 2018', 'location': 'ULB Campus du Solbosch, Av. F. D. Roosevelt 50, 1050 Bruxelles, Belgium', 'time': '03 Feb. – 05 Feb.'}
{'name': 'PyCon Pune 2018', 'location': 'Pune, India', 'time': '08 Feb. – 12 Feb.'}
{'name': 'PyCon Colombia 2018', 'location': 'Medellin, Colombia', 'time': '09 Feb. – 12 Feb.'}
{'name': 'PyTennessee 2018', 'location': 'Nashville, TN, USA', 'time': '10 Feb. – 12 Feb.'}
```

在这个过程中，Firefox 将弹出并打开页面。我们重用了之前的配方并采用了 Selenium。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/05feca6d-bf9f-4938-9cb7-1392310dc374.png)Firefox 弹出的窗口

# 它的工作原理

这个配方的主要区别在于以下代码：

```py
driver = webdriver.Firefox()
driver.get(url)
```

这个脚本获取了 Firefox 驱动程序，并使用它来获取指定 URL 的内容。这是通过启动 Firefox 并自动化它去到页面，然后 Firefox 将页面内容返回给我们的应用程序。这就是为什么 Firefox 弹出的原因。另一个区别是，为了找到东西，我们需要调用`find_element_by_xpath`来搜索结果的 HTML。

# 还有更多...

在许多方面，PhantomJS 与 Selenium 非常相似。它对各种 Web 标准有快速和本地支持，具有 DOM 处理、CSS 选择器、JSON、Canvas 和 SVG 等功能。它经常用于 Web 测试、页面自动化、屏幕捕捉和网络监控。

Selenium 和 PhantomJS 之间有一个关键区别：PhantomJS 是**无头**的，使用 WebKit。正如我们所看到的，Selenium 打开并自动化浏览器。如果我们处于一个连续集成或测试环境中，浏览器没有安装，我们也不希望打开成千上万个浏览器窗口或标签，那么这并不是很好。无头浏览器使得这一切更快更高效。

PhantomJS 的示例在`01/05_events_with_phantomjs.py`文件中。只有一行代码需要更改：

```py
driver = webdriver.PhantomJS('phantomjs')
```

运行脚本会产生与 Selenium/Firefox 示例类似的输出，但不会弹出浏览器，而且完成时间更短。


# 第二章：数据获取和提取

在本章中，我们将涵盖：

+   如何使用 BeautifulSoup 解析网站和导航 DOM

+   使用 Beautiful Soup 的查找方法搜索 DOM

+   使用 XPath 和 lxml 查询 DOM

+   使用 XPath 和 CSS 选择器查询数据

+   使用 Scrapy 选择器

+   以 Unicode / UTF-8 格式加载数据

# 介绍

有效抓取的关键方面是理解内容和数据如何存储在 Web 服务器上，识别要检索的数据，并理解工具如何支持此提取。在本章中，我们将讨论网站结构和 DOM，介绍使用 lxml、XPath 和 CSS 解析和查询网站的技术。我们还将看看如何处理其他语言和不同编码类型（如 Unicode）开发的网站。

最终，理解如何在 HTML 文档中查找和提取数据归结为理解 HTML 页面的结构，它在 DOM 中的表示，查询 DOM 以查找特定元素的过程，以及如何根据数据的表示方式指定要检索的元素。

# 如何使用 BeautifulSoup 解析网站和导航 DOM

当浏览器显示网页时，它会在一种称为**文档对象模型**（**DOM**）的表示中构建页面内容的模型。DOM 是页面整个内容的分层表示，以及结构信息、样式信息、脚本和其他内容的链接。

理解这种结构对于能够有效地从网页上抓取数据至关重要。我们将看一个示例网页，它的 DOM，并且检查如何使用 Beautiful Soup 导航 DOM。

# 准备就绪

我们将使用示例代码的`www`文件夹中包含的一个小型网站。要跟着做，请从`www`文件夹内启动一个 Web 服务器。可以使用 Python 3 来完成这个操作：

```py
www $ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

可以通过右键单击页面并选择检查来检查 Chrome 中的网页 DOM。这将打开 Chrome 开发者工具。在浏览器中打开`http://localhost:8080/planets.html`。在 Chrome 中，您可以右键单击并选择“检查”以打开开发者工具（其他浏览器也有类似的工具）。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/414227f7-dd30-4c7e-8bab-7fc02e136fcd.png)在页面上选择检查

这将打开开发者工具和检查器。DOM 可以在元素选项卡中检查。

以下显示了表中第一行的选择：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/f3dd4285-7e9b-4b96-a3c5-3f31e318b983.png)检查第一行

每一行行星都在一个`<tr>`元素内。这个元素及其相邻元素有几个特征，我们将检查它们，因为它们被设计为模拟常见的网页。

首先，这个元素有三个属性：`id`，`planet`和`name`。属性在抓取中通常很重要，因为它们通常用于识别和定位嵌入在 HTML 中的数据。

其次，`<tr>`元素有子元素，在这种情况下是五个`<td>`元素。我们经常需要查看特定元素的子元素，以找到所需的实际数据。

这个元素还有一个父元素`<tbody>`。还有兄弟元素，以及一组`<tr>`子元素。从任何行星，我们可以向上到父元素并找到其他行星。正如我们将看到的，我们可以使用各种工具中的各种构造，比如 Beautiful Soup 中的**find**函数系列，以及`XPath`查询，轻松地导航这些关系。

# 如何做...

这个配方以及本章中的大多数其他配方都将以 iPython 的交互方式呈现。但是每个配方的代码都可以在脚本文件中找到。这个配方的代码在`02/01_parsing_html_wtih_bs.py`中。您可以输入以下内容，或者从脚本文件中复制粘贴。

现在让我们通过 Beautiful Soup 解析 HTML。我们首先通过以下代码将此页面加载到`BeautifulSoup`对象中，该代码创建一个 BeautifulSoup 对象，使用 requests.get 加载页面内容，并将其加载到名为 soup 的变量中。

```py
In [1]: import requests
   ...: from bs4 import BeautifulSoup
   ...: html = requests.get("http://localhost:8080/planets.html").text
   ...: soup = BeautifulSoup(html, "lxml")
   ...:
```

通过将其转换为字符串，可以检索`soup`对象中的 HTML（大多数 BeautifulSoup 对象都具有此特性）。以下显示了文档中 HTML 的前 1000 个字符：

```py
In [2]: str(soup)[:1000]
Out[2]: '<html>\n<head>\n</head>\n<body>\n<div id="planets">\n<h1>Planetary data</h1>\n<div id="content">Here are some interesting facts about the planets in our solar system</div>\n<p></p>\n<table border="1" id="planetsTable">\n<tr id="planetHeader">\n<th>\n</th>\n<th>\r\n Name\r\n </th>\n<th>\r\n Mass (10²⁴kg)\r\n </th>\n<th>\r\n Diameter (km)\r\n </th>\n<th>\r\n How it got its Name\r\n </th>\n<th>\r\n More Info\r\n </th>\n</tr>\n<tr class="planet" id="planet1" name="Mercury">\n<td>\n<img src="img/mercury-150x150.png"/>\n</td>\n<td>\r\n Mercury\r\n </td>\n<td>\r\n 0.330\r\n </td>\n<td>\r\n 4879\r\n </td>\n<td>Named Mercurius by the Romans because it appears to move so swiftly.</td>\n<td>\n<a href="https://en.wikipedia.org/wiki/Mercury_(planet)">Wikipedia</a>\n</td>\n</tr>\n<tr class="p'
```

我们可以使用`soup`的属性来导航 DOM 中的元素。`soup`代表整个文档，我们可以通过链接标签名称来深入文档。以下导航到包含数据的`<table>`：

```py
In [3]: str(soup.html.body.div.table)[:200]
Out[3]: '<table border="1" id="planetsTable">\n<tr id="planetHeader">\n<th>\n</th>\n<th>\r\n Name\r\n </th>\n<th>\r\n Mass (10²⁴kg)\r\n </th>\n<th>\r\n '
```

以下是获取表格的第一个子`<tr>`：

```py
In [6]: soup.html.body.div.table.tr
Out[6]: <tr id="planetHeader">
<th>
</th>
<th>
                    Name
                </th>
<th>
                    Mass (10²⁴kg)
                </th>
<th>
                    Diameter (km)
                </th>
<th>
                    How it got its Name
                </th>
<th>
                    More Info
                </th>
</tr>
```

请注意，此类表示法仅检索该类型的第一个子节点。要找到更多，需要迭代所有子节点，我们将在下一步中进行，或者使用查找方法（下一个示例）。

每个节点都有子节点和后代。后代是给定节点下面的所有节点（甚至比直接子节点更深层次的节点），而子节点是第一级后代。以下是获取表格的子节点，实际上是一个`list_iterator`对象：

```py
In [4]: soup.html.body.div.table.children
Out[4]: <list_iterator at 0x10eb11cc0>
```

我们可以使用`for`循环或 Python 生成器来检查迭代器中的每个子元素。以下使用生成器来获取所有子节点，并将它们的 HTML 组成的前几个字符作为列表返回：

```py
In [5]: [str(c)[:45] for c in soup.html.body.div.table.children]
Out[5]:
['\n',
 '<tr id="planetHeader">\n<th>\n</th>\n<th>\r\n ',
 '\n',
 '<tr class="planet" id="planet1" name="Mercury',
 '\n',
 '<tr class="planet" id="planet2" name="Venus">',
 '\n',
 '<tr class="planet" id="planet3" name="Earth">',
 '\n',
 '<tr class="planet" id="planet4" name="Mars">\n',
 '\n',
 '<tr class="planet" id="planet5" name="Jupiter',
 '\n',
 '<tr class="planet" id="planet6" name="Saturn"',
 '\n',
 '<tr class="planet" id="planet7" name="Uranus"',
 '\n',
 '<tr class="planet" id="planet8" name="Neptune',
 '\n',
 '<tr class="planet" id="planet9" name="Pluto">',
 '\n']
```

最后，节点的父节点可以使用`.parent`属性找到：

```py
In [7]: str(soup.html.body.div.table.tr.parent)[:200]
Out[7]: '<table border="1" id="planetsTable">\n<tr id="planetHeader">\n<th>\n</th>\n<th>\r\n Name\r\n </th>\n<th>\r\n Mass (10²⁴kg)\r\n </th>\n<th>\r\n '
```

# 它是如何工作的

Beautiful Soup 将页面的 HTML 转换为其自己的内部表示。这个模型与浏览器创建的 DOM 具有相同的表示。但是 Beautiful Soup 还提供了许多强大的功能，用于导航 DOM 中的元素，例如我们在使用标签名称作为属性时所看到的。当我们知道 HTML 中的标签名称的固定路径时，这些功能非常适合查找东西。

# 还有更多...

这种导航 DOM 的方式相对不灵活，并且高度依赖于结构。可能随着网页由其创建者更新，结构会随时间改变。页面甚至可能看起来相同，但具有完全不同的结构，从而破坏您的抓取代码。

那么我们该如何处理呢？正如我们将看到的，有几种搜索元素的方法比定义显式路径要好得多。一般来说，我们可以使用 XPath 和 Beautiful Soup 的查找方法来做到这一点。我们将在本章后面的示例中检查这两种方法。

# 使用 Beautiful Soup 的查找方法搜索 DOM

我们可以使用 Beautiful Soup 的查找方法对 DOM 进行简单搜索。这些方法为我们提供了一个更灵活和强大的构造，用于查找不依赖于这些元素的层次结构的元素。在本示例中，我们将检查这些函数的几种常见用法，以定位 DOM 中的各种元素。

# 准备工作

如果您想将以下内容剪切并粘贴到 ipython 中，您可以在`02/02_bs4_find.py`中找到示例。

# 如何做...

我们将从一个新的 iPython 会话开始，并首先加载行星页面：

```py
In [1]: import requests
 ...: from bs4 import BeautifulSoup
 ...: html = requests.get("http://localhost:8080/planets.html").text
 ...: soup = BeautifulSoup(html, "lxml")
 ...:
```

在上一个示例中，为了访问表格中的所有`<tr>`，我们使用了链式属性语法来获取表格，然后需要获取子节点并对其进行迭代。这会有一个问题，因为子节点可能是除了`<tr>`之外的其他元素。获取`<tr>`子元素的更优选方法是使用`findAll`。

让我们首先找到`<table>`：

```py
In [4]: table = soup.find("table")
   ...: str(table)[:100]
   ...:
Out[4]: '<table border="1" id="planetsTable">\n<tr id="planetHeader">\n<th>\n</th>\n<th>\r\n Nam'
```

这告诉 soup 对象在文档中查找第一个`<table>`元素。从这个元素中，我们可以使用`findAll`找到所有属于该表格的`<tr>`元素的后代：

```py
In [8]: [str(tr)[:50] for tr in table.findAll("tr")]
Out[8]:
['<tr id="planetHeader">\n<th>\n</th>\n<th>\r\n ',
 '<tr class="planet" id="planet1" name="Mercury">\n<t',
 '<tr class="planet" id="planet2" name="Venus">\n<td>',
 '<tr class="planet" id="planet3" name="Earth">\n<td>',
 '<tr class="planet" id="planet4" name="Mars">\n<td>\n',
 '<tr class="planet" id="planet5" name="Jupiter">\n<t',
 '<tr class="planet" id="planet6" name="Saturn">\n<td',
 '<tr class="planet" id="planet7" name="Uranus">\n<td',
 '<tr class="planet" id="planet8" name="Neptune">\n<t',
 '<tr class="planet" id="planet9" name="Pluto">\n<td>']
```

请注意这些是后代而不是直接的子代。将查询更改为`"td"`以查看区别。没有直接的子代是`<td>`，但每行都有多个`<td>`元素。总共会找到 54 个`<td>`元素。

如果我们只想要包含行星数据的行，这里有一个小问题。表头也被包括在内。我们可以通过利用目标行的`id`属性来解决这个问题。以下代码找到了`id`值为`"planet3"`的行。

```py
In [14]: table.find("tr", {"id": "planet3"})
    ...:
Out[14]:
<tr class="planet" id="planet3" name="Earth">
<td>
<img src="img/earth-150x150.png"/>
</td>
<td>
                    Earth
                </td>
<td>
                    5.97
                </td>
<td>
                    12756
                </td>
<td>
                    The name Earth comes from the Indo-European base 'er,'which produced the Germanic noun 'ertho,' and ultimately German 'erde,'
                    Dutch 'aarde,' Scandinavian 'jord,' and English 'earth.' Related forms include Greek 'eraze,' meaning
                    'on the ground,' and Welsh 'erw,' meaning 'a piece of land.'
                </td>
<td>
<a href="https://en.wikipedia.org/wiki/Earth">Wikipedia</a>
</td>
</tr>
```

太棒了！我们利用了这个页面使用这个属性来表示具有实际数据的表行。

现在让我们再进一步，收集每个行星的质量，并将名称和质量放入字典中：

```py
In [18]: items = dict()
    ...: planet_rows = table.findAll("tr", {"class": "planet"})
    ...: for i in planet_rows:
    ...: tds = i.findAll("td")
    ...: items[tds[1].text.strip()] = tds[2].text.strip()
    ...:

In [19]: items
Out[19]:
{'Earth': '5.97',
 'Jupiter': '1898',
 'Mars': '0.642',
 'Mercury': '0.330',
 'Neptune': '102',
 'Pluto': '0.0146',
 'Saturn': '568',
 'Uranus': '86.8',
 'Venus': '4.87'}
```

就像这样，我们已经从页面中嵌入的内容中制作了一个很好的数据结构。

# 使用 XPath 和 lxml 查询 DOM

XPath 是一种用于从 XML 文档中选择节点的查询语言，对于进行网页抓取的任何人来说，它是必须学习的查询语言。XPath 相对于其他基于模型的工具，为其用户提供了许多好处：

+   可以轻松地浏览 DOM 树

+   比 CSS 选择器和正则表达式等其他选择器更复杂和强大

+   它有一个很棒的（200+）内置函数集，并且可以通过自定义函数进行扩展

+   它得到了解析库和抓取平台的广泛支持

XPath 包含七种数据模型（我们之前已经看到了其中一些）：

+   根节点（顶级父节点）

+   元素节点（`<a>`..`</a>`）

+   属性节点（`href="example.html"`）

+   文本节点（`"this is a text"`）

+   注释节点（`<!-- a comment -->`）

+   命名空间节点

+   处理指令节点

XPath 表达式可以返回不同的数据类型：

+   字符串

+   布尔值

+   数字

+   节点集（可能是最常见的情况）

（XPath）**轴**定义了相对于当前节点的节点集。XPath 中定义了总共 13 个轴，以便轻松搜索不同的节点部分，从当前上下文节点或根节点。

**lxml**是一个 Python 包装器，位于 libxml2 XML 解析库之上，后者是用 C 编写的。C 中的实现有助于使其比 Beautiful Soup 更快，但在某些计算机上安装起来也更困难。最新的安装说明可在以下网址找到：[`lxml.de/installation.html`](http://lxml.de/installation.html)。

lxml 支持 XPath，这使得管理复杂的 XML 和 HTML 文档变得相当容易。我们将研究使用 lxml 和 XPath 一起的几种技术，以及如何使用 lxml 和 XPath 来导航 DOM 并访问数据。

# 准备工作

这些片段的代码在`02/03_lxml_and_xpath.py`中，如果你想节省一些输入。我们将首先从`lxml`中导入`html`，以及`requests`，然后加载页面。

```py
In [1]: from lxml import html
   ...: import requests
   ...: page_html = requests.get("http://localhost:8080/planets.html").text
```

到这一点，lxml 应该已经作为其他安装的依赖项安装了。如果出现错误，请使用`pip install lxml`进行安装。

# 如何做...

我们要做的第一件事是将 HTML 加载到 lxml 的“etree”中。这是 lxml 对 DOM 的表示。

```py
in [2]: tree = html.fromstring(page_html)
```

`tree`变量现在是 DOM 的 lxml 表示，它对 HTML 内容进行了建模。现在让我们来看看如何使用它和 XPath 从文档中选择各种元素。

我们的第一个 XPath 示例将是查找所有在`<table>`元素下的`<tr>`元素。

```py
In [3]: [tr for tr in tree.xpath("/html/body/div/table/tr")]
Out[3]:
[<Element tr at 0x10cfd1408>,
 <Element tr at 0x10cfd12c8>,
 <Element tr at 0x10cfd1728>,
 <Element tr at 0x10cfd16d8>,
 <Element tr at 0x10cfd1458>,
 <Element tr at 0x10cfd1868>,
 <Element tr at 0x10cfd1318>,
 <Element tr at 0x10cfd14a8>,
 <Element tr at 0x10cfd10e8>,
 <Element tr at 0x10cfd1778>,
 <Element tr at 0x10cfd1638>]
```

这个 XPath 从文档的根部通过标签名称进行导航，直到`<tr>`元素。这个例子看起来类似于 Beautiful Soup 中的属性表示法，但最终它更加具有表现力。请注意结果中的一个区别。所有的`<tr>`元素都被返回了，而不仅仅是第一个。事实上，如果每个级别的标签都有多个项目可用，那么这个路径的搜索将在所有这些`<div>`上执行。

实际结果是一个`lxml`元素对象。以下使用`etree.tostring()`获取与元素相关的 HTML（尽管它们已经应用了编码）：

```py
In [4]: from lxml import etree
   ...: [etree.tostring(tr)[:50] for tr in tree.xpath("/html/body/div/table/tr")]
Out[4]:
[b'<tr id="planetHeader">
\n <th>&#',
 b'<tr id="planet1" class="planet" name="Mercury">&#1',
 b'<tr id="planet2" class="planet" name="Venus">
',
 b'<tr id="planet3" class="planet" name="Earth">
',
 b'<tr id="planet4" class="planet" name="Mars">
\n',
 b'<tr id="planet5" class="planet" name="Jupiter">&#1',
 b'<tr id="planet6" class="planet" name="Saturn">&#13',
 b'<tr id="planet7" class="planet" name="Uranus">&#13',
 b'<tr id="planet8" class="planet" name="Neptune">&#1',
 b'<tr id="planet9" class="planet" name="Pluto">
',
 b'<tr id="footerRow">
\n <td>
']
```

现在让我们看看如何使用 XPath 来选择只有行星的`<tr>`元素。

```py
In [5]: [etree.tostring(tr)[:50] for tr in tree.xpath("/html/body/div/table/tr[@class='planet']")]
Out[5]:
[b'<tr id="planet1" class="planet" name="Mercury">&#1',
 b'<tr id="planet2" class="planet" name="Venus">
',
 b'<tr id="planet3" class="planet" name="Earth">
',
 b'<tr id="planet4" class="planet" name="Mars">
\n',
 b'<tr id="planet5" class="planet" name="Jupiter">&#1',
 b'<tr id="planet6" class="planet" name="Saturn">&#13',
 b'<tr id="planet7" class="planet" name="Uranus">&#13',
 b'<tr id="planet8" class="planet" name="Neptune">&#1',
 b'<tr id="planet9" class="planet" name="Pluto">
']
```

在标签旁边使用`[]`表示我们要根据当前元素的某些条件进行选择。`@`表示我们要检查标签的属性，在这种情况下，我们要选择属性等于"planet"的标签。

还有另一个要指出的是查询中有 11 个`<tr>`行。如前所述，XPath 在每个级别上对所有找到的节点进行导航。这个文档中有两个表，都是不同`<div>`的子元素，都是`<body>`元素的子元素。具有`id="planetHeader"`的行来自我们想要的目标表，另一个具有`id="footerRow"`的行来自第二个表。

以前我们通过选择`class="row"`的`<tr>`来解决了这个问题，但还有其他值得简要提及的方法。首先，我们还可以使用`[]`来指定 XPath 的每个部分中的特定元素，就像它们是数组一样。看下面的例子：

```py
In [6]: [etree.tostring(tr)[:50] for tr in tree.xpath("/html/body/div[1]/table/tr")]
Out[6]:
[b'<tr id="planetHeader">
\n <th>&#',
 b'<tr id="planet1" class="planet" name="Mercury">&#1',
 b'<tr id="planet2" class="planet" name="Venus">
',
 b'<tr id="planet3" class="planet" name="Earth">
',
 b'<tr id="planet4" class="planet" name="Mars">
\n',
 b'<tr id="planet5" class="planet" name="Jupiter">&#1',
 b'<tr id="planet6" class="planet" name="Saturn">&#13',
 b'<tr id="planet7" class="planet" name="Uranus">&#13',
 b'<tr id="planet8" class="planet" name="Neptune">&#1',
 b'<tr id="planet9" class="planet" name="Pluto">
']
```

XPath 中的数组从 1 开始而不是 0（一个常见的错误来源）。这选择了第一个`<div>`。更改为`[2]`选择了第二个`<div>`，因此只选择了第二个`<table>`。

```py
In [7]: [etree.tostring(tr)[:50] for tr in tree.xpath("/html/body/div[2]/table/tr")]
Out[7]: [b'<tr id="footerRow">
\n <td>
']
```

这个文档中的第一个`<div>`也有一个 id 属性：

```py
  <div id="planets">  
```

这可以用来选择这个`<div>`：

```py
In [8]: [etree.tostring(tr)[:50] for tr in tree.xpath("/html/body/div[@id='planets']/table/tr")]
Out[8]:
[b'<tr id="planetHeader">
\n <th>&#',
 b'<tr id="planet1" class="planet" name="Mercury">&#1',
 b'<tr id="planet2" class="planet" name="Venus">
',
 b'<tr id="planet3" class="planet" name="Earth">
',
 b'<tr id="planet4" class="planet" name="Mars">
\n',
 b'<tr id="planet5" class="planet" name="Jupiter">&#1',
 b'<tr id="planet6" class="planet" name="Saturn">&#13',
 b'<tr id="planet7" class="planet" name="Uranus">&#13',
 b'<tr id="planet8" class="planet" name="Neptune">&#1',
 b'<tr id="planet9" class="planet" name="Pluto">
']
```

之前我们根据 class 属性的值选择了行星行。我们也可以排除行：

```py
In [9]: [etree.tostring(tr)[:50] for tr in tree.xpath("/html/body/div[@id='planets']/table/tr[@id!='planetHeader']")]
Out[9]:
[b'<tr id="planet1" class="planet" name="Mercury">&#1',
 b'<tr id="planet2" class="planet" name="Venus">
',
 b'<tr id="planet3" class="planet" name="Earth">
',
 b'<tr id="planet4" class="planet" name="Mars">
\n',
 b'<tr id="planet5" class="planet" name="Jupiter">&#1',
 b'<tr id="planet6" class="planet" name="Saturn">&#13',
 b'<tr id="planet7" class="planet" name="Uranus">&#13',
 b'<tr id="planet8" class="planet" name="Neptune">&#1',
 b'<tr id="planet9" class="planet" name="Pluto">
']
```

假设行星行没有属性（也没有标题行），那么我们可以通过位置来做到这一点，跳过第一行：

```py
In [10]: [etree.tostring(tr)[:50] for tr in tree.xpath("/html/body/div[@id='planets']/table/tr[position() > 1]")]
Out[10]:
[b'<tr id="planet1" class="planet" name="Mercury">&#1',
 b'<tr id="planet2" class="planet" name="Venus">
',
 b'<tr id="planet3" class="planet" name="Earth">
',
 b'<tr id="planet4" class="planet" name="Mars">
\n',
 b'<tr id="planet5" class="planet" name="Jupiter">&#1',
 b'<tr id="planet6" class="planet" name="Saturn">&#13',
 b'<tr id="planet7" class="planet" name="Uranus">&#13',
 b'<tr id="planet8" class="planet" name="Neptune">&#1',
 b'<tr id="planet9" class="planet" name="Pluto">
']
```

可以使用`parent::*`来导航到节点的父级：

```py
In [11]: [etree.tostring(tr)[:50] for tr in tree.xpath("/html/body/div/table/tr/parent::*")]
Out[11]:
[b'<table id="planetsTable" border="1">
\n ',
 b'<table id="footerTable">
\n <tr id="']
```

这返回了两个父级，因为这个 XPath 返回了两个表的行，所以找到了所有这些行的父级。`*`是一个通配符，代表任何名称的任何父级标签。在这种情况下，这两个父级都是表，但通常结果可以是任意数量的 HTML 元素类型。下面的结果相同，但如果两个父级是不同的 HTML 标签，那么它只会返回`<table>`元素。

```py
In [12]: [etree.tostring(tr)[:50] for tr in tree.xpath("/html/body/div/table/tr/parent::table")]
Out[12]:
[b'<table id="planetsTable" border="1">
\n ',
 b'<table id="footerTable">
\n <tr id="']
```

还可以通过位置或属性指定特定的父级。以下选择具有`id="footerTable"`的父级：

```py
In [13]: [etree.tostring(tr)[:50] for tr in tree.xpath("/html/body/div/table/tr/parent::table[@id='footerTable']")]
Out[13]: [b'<table id="footerTable">
\n <tr id="']
```

父级的快捷方式是`..`（`.`也表示当前节点）：

```py
In [14]: [etree.tostring(tr)[:50] for tr in tree.xpath("/html/body/div/table/tr/..")]
Out[14]:
[b'<table id="planetsTable" border="1">
\n ',
 b'<table id="footerTable">
\n <tr id="']
```

最后一个示例找到了地球的质量：

```py
In [15]: mass = tree.xpath("/html/body/div[1]/table/tr[@name='Earth']/td[3]/text()[1]")[0].strip()
    ...: mass
Out[15]: '5.97'
```

这个 XPath 的尾部`/td[3]/text()[1]`选择了行中的第三个`<td>`元素，然后选择了该元素的文本（这是元素中所有文本的数组），并选择了其中的第一个质量。

# 它是如何工作的

XPath 是**XSLT**（可扩展样式表语言转换）标准的一部分，提供了在 XML 文档中选择节点的能力。HTML 是 XML 的一种变体，因此 XPath 可以在 HTML 文档上工作（尽管 HTML 可能格式不正确，在这种情况下会破坏 XPath 解析）。

XPath 本身旨在模拟 XML 节点、属性和属性的结构。该语法提供了查找与表达式匹配的 XML 中的项目的方法。这可以包括匹配或逻辑比较 XML 文档中任何节点、属性、值或文本的任何部分。

XPath 表达式可以组合成非常复杂的路径在文档中。还可以根据相对位置导航文档，这在根据相对位置而不是 DOM 中的绝对位置找到数据时非常有帮助。

理解 XPath 对于知道如何解析 HTML 和执行网页抓取是至关重要的。正如我们将看到的，它是许多高级库的基础，并为其提供了实现，比如 lxml。

# 还有更多...

XPath 实际上是处理 XML 和 HTML 文档的一个了不起的工具。它在功能上非常丰富，我们仅仅触及了它在演示 HTML 文档中常见的一些示例的表面。

要了解更多，请访问以下链接：

+   [`www.w3schools.com/xml/xml_xpath.asp`](https://www.w3schools.com/xml/xml_xpath.asp)

+   [`www.w3.org/TR/xpath/`](https://www.w3.org/TR/xpath/)

# 使用 XPath 和 CSS 选择器查询数据

CSS 选择器是用于选择元素的模式，通常用于定义应该应用样式的元素。它们也可以与 lxml 一起用于选择 DOM 中的节点。CSS 选择器通常被广泛使用，因为它们比 XPath 更紧凑，并且通常在代码中更可重用。以下是可能使用的常见选择器的示例：

| **您要寻找的内容** | **示例** |
| --- | --- |
| 所有标签 | `*` |
| 特定标签（即`tr`） | `.planet` |
| 类名（即`"planet"`） | `tr.planet` |
| 具有`ID "planet3"`的标签 | `tr#planet3` |
| 表的子`tr` | `table tr` |
| 表的后代`tr` | `table tr` |
| 带有属性的标签（即带有`id="planet4"`的`tr`） | `a[id=Mars]` |

# 准备工作

让我们开始使用与上一个示例中使用的相同的启动代码来检查 CSS 选择器。这些代码片段也在`02/04_css_selectors.py`中。

```py
In [1]: from lxml import html
   ...: import requests
   ...: page_html = requests.get("http://localhost:8080/planets.html").text
   ...: tree = html.fromstring(page_html)
   ...:
```

# 如何做...

现在让我们开始使用 XPath 和 CSS 选择器。以下选择所有具有等于`"planet"`的类的`<tr>`元素：

```py
In [2]: [(v, v.xpath("@name")) for v in tree.cssselect('tr.planet')]
Out[2]:
[(<Element tr at 0x10d3a2278>, ['Mercury']),
 (<Element tr at 0x10c16ed18>, ['Venus']),
 (<Element tr at 0x10e445688>, ['Earth']),
 (<Element tr at 0x10e477228>, ['Mars']),
 (<Element tr at 0x10e477408>, ['Jupiter']),
 (<Element tr at 0x10e477458>, ['Saturn']),
 (<Element tr at 0x10e4774a8>, ['Uranus']),
 (<Element tr at 0x10e4774f8>, ['Neptune']),
 (<Element tr at 0x10e477548>, ['Pluto'])]
```

可以通过多种方式找到地球的数据。以下是基于`id`获取行的方法：

```py
In [3]: tr = tree.cssselect("tr#planet3")
   ...: tr[0], tr[0].xpath("./td[2]/text()")[0].strip()
   ...:
Out[3]: (<Element tr at 0x10e445688>, 'Earth')
```

以下示例使用具有特定值的属性：

```py
In [4]: tr = tree.cssselect("tr[name='Pluto']")
   ...: tr[0], tr[0].xpath("td[2]/text()")[0].strip()
   ...:
Out[5]: (<Element tr at 0x10e477548>, 'Pluto')
```

请注意，与 XPath 不同，不需要使用`@`符号来指定属性。

# 工作原理

lxml 将您提供的 CSS 选择器转换为 XPath，然后针对底层文档执行该 XPath 表达式。实质上，lxml 中的 CSS 选择器提供了一种简写 XPath 的方法，使得查找符合某些模式的节点比使用 XPath 更简单。

# 还有更多...

由于 CSS 选择器在底层使用 XPath，因此与直接使用 XPath 相比，使用它会增加一些开销。然而，这种差异几乎不成问题，因此在某些情况下，更容易只使用 cssselect。

可以在以下位置找到 CSS 选择器的完整描述：[`www.w3.org/TR/2011/REC-css3-selectors-20110929/`](https://www.w3.org/TR/2011/REC-css3-selectors-20110929/)

# 使用 Scrapy 选择器

Scrapy 是一个用于从网站提取数据的 Python 网络爬虫框架。它提供了许多强大的功能，用于浏览整个网站，例如跟踪链接的能力。它提供的一个功能是使用 DOM 在文档中查找数据，并且现在，相当熟悉的 XPath。

在这个示例中，我们将加载 StackOverflow 上当前问题的列表，然后使用 scrapy 选择器解析它。使用该选择器，我们将提取每个问题的文本。

# 准备工作

此示例的代码位于`02/05_scrapy_selectors.py`中。

# 如何做...

我们首先从`scrapy`中导入`Selector`，还有`requests`，以便我们可以检索页面：

```py
In [1]: from scrapy.selector import Selector
   ...: import requests
   ...:
```

接下来加载页面。在此示例中，我们将检索 StackOverflow 上最近的问题并提取它们的标题。我们可以使用以下查询来实现：

```py
In [2]: response = requests.get("http://stackoverflow.com/questions")
```

现在创建一个`Selector`并将其传递给响应对象：

```py
In [3]: selector = Selector(response)
   ...: selector
   ...:
Out[3]: <Selector xpath=None data='<html>\r\n\r\n <head>\r\n\r\n <title>N'>
```

检查此页面的内容，我们可以看到问题的 HTML 具有以下结构：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/d72e8df6-61f1-4395-a003-009279e30ddb.png)StackOverflow 问题的 HTML

使用选择器，我们可以使用 XPath 找到这些：

```py
In [4]: summaries = selector.xpath('//div[@class="summary"]/h3')
   ...: summaries[0:5]
   ...:
Out[4]:
[<Selector xpath='//div[@class="summary"]/h3' data='<h3><a href="/questions/48353091/how-to-'>,
 <Selector xpath='//div[@class="summary"]/h3' data='<h3><a href="/questions/48353090/move-fi'>,
 <Selector xpath='//div[@class="summary"]/h3' data='<h3><a href="/questions/48353089/java-la'>,
 <Selector xpath='//div[@class="summary"]/h3' data='<h3><a href="/questions/48353086/how-do-'>,
 <Selector xpath='//div[@class="summary"]/h3' data='<h3><a href="/questions/48353085/running'>]
```

现在我们进一步深入每个问题的标题。

```py
In [5]: [x.extract() for x in summaries.xpath('a[@class="question-hyperlink"]/text()')][:10]
Out[5]:
['How to convert stdout binary file to a data URL?',
 'Move first letter from sentence to the end',
 'Java launch program and interact with it programmatically',
 'How do I build vala from scratch',
 'Running Sql Script',
 'Mysql - Auto create, update, delete table 2 from table 1',
 'how to map meeting data corresponding calendar time in java',
 'Range of L*a* b* in Matlab',
 'set maximum and minimum number input box in js,html',
 'I created generic array and tried to store the value but it is showing ArrayStoreException']
```

# 工作原理

在底层，Scrapy 构建其选择器基于 lxml。它提供了一个较小且略微简单的 API，性能与 lxml 相似。

# 还有更多...

要了解有关 Scrapy 选择器的更多信息，请参见：[`doc.scrapy.org/en/latest/topics/selectors.html`](https://doc.scrapy.org/en/latest/topics/selectors.html)。

# 以 unicode / UTF-8 加载数据

文档的编码告诉应用程序如何将文档中的字符表示为文件中的字节。基本上，编码指定每个字符有多少位。在标准 ASCII 文档中，所有字符都是 8 位。HTML 文件通常以每个字符 8 位编码，但随着互联网的全球化，情况并非总是如此。许多 HTML 文档以 16 位字符编码，或者使用 8 位和 16 位字符的组合。

一种特别常见的 HTML 文档编码形式被称为 UTF-8。这是我们将要研究的编码形式。

# 准备工作

我们将从位于`http://localhost:8080/unicode.html`的本地 Web 服务器中读取名为`unicode.html`的文件。该文件采用 UTF-8 编码，并包含编码空间不同部分的几组字符。例如，页面在浏览器中如下所示：

浏览器中的页面

使用支持 UTF-8 的编辑器，我们可以看到西里尔字母在编辑器中是如何呈现的：

编辑器中的 HTML

示例的代码位于`02/06_unicode.py`中。

# 如何做...

我们将研究如何使用`urlopen`和`requests`来处理 UTF-8 中的 HTML。这两个库处理方式不同，让我们来看看。让我们开始导入`urllib`，加载页面并检查一些内容。

```py
In [8]: from urllib.request import urlopen
   ...: page = urlopen("http://localhost:8080/unicode.html")
   ...: content = page.read()
   ...: content[840:1280]
   ...:
Out[8]: b'><strong>Cyrillic</strong> &nbsp; U+0400 \xe2\x80\x93 U+04FF &nbsp; (1024\xe2\x80\x931279)</p>\n <table class="unicode">\n <tbody>\n <tr valign="top">\n <td width="50">&nbsp;</td>\n <td class="b" width="50">\xd0\x89</td>\n <td class="b" width="50">\xd0\xa9</td>\n <td class="b" width="50">\xd1\x89</td>\n <td class="b" width="50">\xd3\x83</td>\n </tr>\n </tbody>\n </table>\n\n '
```

请注意，西里尔字母是以多字节代码的形式读入的，使用\符号，例如`\xd0\x89`。

为了纠正这一点，我们可以使用 Python 的`str`语句将内容转换为 UTF-8 格式：

```py
In [9]: str(content, "utf-8")[837:1270]
Out[9]: '<strong>Cyrillic</strong> &nbsp; U+0400 – U+04FF &nbsp; (1024–1279)</p>\n <table class="unicode">\n <tbody>\n <tr valign="top">\n <td width="50">&nbsp;</td>\n <td class="b" width="50">Љ</td>\n <td class="b" width="50">Щ</td>\n <td class="b" width="50">щ</td>\n <td class="b" width="50">Ӄ</td>\n </tr>\n </tbody>\n </table>\n\n '
```

请注意，输出现在已经正确编码了字符。

我们可以通过使用`requests`来排除这一额外步骤。

```py
In [9]: import requests
   ...: response = requests.get("http://localhost:8080/unicode.html").text
   ...: response.text[837:1270]
   ...:
'<strong>Cyrillic</strong> &nbsp; U+0400 – U+04FF &nbsp; (1024–1279)</p>\n <table class="unicode">\n <tbody>\n <tr valign="top">\n <td width="50">&nbsp;</td>\n <td class="b" width="50">Љ</td>\n <td class="b" width="50">Щ</td>\n <td class="b" width="50">щ</td>\n <td class="b" width="50">Ӄ</td>\n </tr>\n </tbody>\n </table>\n\n '
```

# 它是如何工作的

在使用`urlopen`时，通过使用 str 语句并指定应将内容转换为 UTF-8 来明确执行了转换。对于`requests`，该库能够通过在文档中看到以下标记来确定 HTML 中的内容是以 UTF-8 格式编码的：

```py
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
```

# 还有更多...

互联网上有许多关于 Unicode 和 UTF-8 编码技术的资源。也许最好的是以下维基百科文章，其中有一个很好的摘要和描述编码技术的表格：[`en.wikipedia.org/wiki/UTF-8`](https://en.wikipedia.org/wiki/UTF-8)


# 第三章：处理数据

在本章中，我们将涵盖：

+   使用 CSV 和 JSON 数据

+   使用 AWS S3 存储数据

+   使用 MySQL 存储数据

+   使用 PostgreSQL 存储数据

+   使用 Elasticsearch 存储数据

+   如何使用 AWS SQS 构建健壮的 ETL 管道

# 介绍

在本章中，我们将介绍 JSON、CSV 和 XML 格式的数据使用。这将包括解析和将这些数据转换为其他格式的方法，包括将数据存储在关系数据库、Elasticsearch 等搜索引擎以及包括 AWS S3 在内的云存储中。我们还将讨论通过使用 AWS Simple Queue Service（SQS）等消息系统创建分布式和大规模的抓取任务。目标是既了解您可能检索和需要解析的各种数据形式，又了解可以存储您已抓取的数据的各种后端。最后，我们首次介绍了 Amazon Web Service（AWS）的一项服务。在本书结束时，我们将深入研究 AWS，并进行初步介绍。

# 使用 CSV 和 JSON 数据

从 HTML 页面中提取数据是使用上一章节中的技术完成的，主要是使用 XPath 通过各种工具和 Beautiful Soup。虽然我们主要关注 HTML，但 HTML 是 XML（可扩展标记语言）的一种变体。XML 曾经是在 Web 上表达数据的最流行形式之一，但其他形式已经变得流行，甚至超过了 XML。

您将看到的两种常见格式是 JSON（JavaScript 对象表示）和 CSV（逗号分隔值）。CSV 易于创建，是许多电子表格应用程序的常见形式，因此许多网站提供该格式的数据，或者您需要将抓取的数据转换为该格式以进行进一步存储或协作。由于 JSON 易于在 JavaScript（和 Python）等编程语言中使用，并且许多数据库现在支持它作为本机数据格式，因此 JSON 确实已成为首选格式。

在这个示例中，让我们来看看将抓取的数据转换为 CSV 和 JSON，以及将数据写入文件，以及从远程服务器读取这些数据文件。我们将研究 Python CSV 和 JSON 库。我们还将研究使用`pandas`进行这些技术。

这些示例中还隐含了将 XML 数据转换为 CSV 和 JSON 的过程，因此我们不会为这些示例专门设置一个部分。

# 准备工作

我们将使用行星数据页面，并将该数据转换为 CSV 和 JSON 文件。让我们从将行星数据从页面加载到 Python 字典对象列表中开始。以下代码（在（`03/get_planet_data.py`）中找到）提供了执行此任务的函数，该函数将在整个章节中重复使用：

```py
import requests
from bs4 import BeautifulSoup

def get_planet_data():
   html = requests.get("http://localhost:8080/planets.html").text
   soup = BeautifulSoup(html, "lxml")

   planet_trs = soup.html.body.div.table.findAll("tr", {"class": "planet"})

   def to_dict(tr):
      tds = tr.findAll("td")
      planet_data = dict()
      planet_data['Name'] = tds[1].text.strip()
      planet_data['Mass'] = tds[2].text.strip()
      planet_data['Radius'] = tds[3].text.strip()
      planet_data['Description'] = tds[4].text.strip()
      planet_data['MoreInfo'] = tds[5].findAll("a")[0]["href"].strip()
      return planet_data

   planets = [to_dict(tr) for tr in planet_trs]

   return planets

if __name__ == "__main__":
   print(get_planet_data())
```

运行脚本会产生以下输出（简要截断）：

```py
03 $python get_planet_data.py
[{'Name': 'Mercury', 'Mass': '0.330', 'Radius': '4879', 'Description': 'Named Mercurius by the Romans because it appears to move so swiftly.', 'MoreInfo': 'https://en.wikipedia.org/wiki/Mercury_(planet)'}, {'Name': 'Venus', 'Mass': '4.87', 'Radius': '12104', 'Description': 'Roman name for the goddess of love. This planet was considered to be the brightest and most beautiful planet or star in the\r\n heavens. Other civilizations have named it for their god or goddess of love/war.', 'MoreInfo': 'https://en.wikipedia.org/wiki/Venus'}, {'Name': 'Earth', 'Mass': '5.97', 'Radius': '12756', 'Description': "The name Earth comes from the Indo-European base 'er,'which produced the Germanic noun 'ertho,' and ultimately German 'erde,'\r\n Dutch 'aarde,' Scandinavian 'jord,' and English 'earth.' Related forms include Greek 'eraze,' meaning\r\n 'on the ground,' and Welsh 'erw,' meaning 'a piece of land.'", 'MoreInfo': 'https://en.wikipedia.org/wiki/Earth'}, {'Name': 'Mars', 'Mass': '0.642', 'Radius': '6792', 'Description': 'Named by the Romans for their god of war because of its red, bloodlike color. Other civilizations also named this planet\r\n from this attribute; for example, the Egyptians named it "Her Desher," meaning "the red one."', 'MoreInfo':
...
```

可能需要安装 csv、json 和 pandas。您可以使用以下三个命令来完成：

```py
pip install csv
pip install json
pip install pandas
```

# 如何做

我们将首先将行星数据转换为 CSV 文件。

1.  这将使用`csv`执行。以下代码将行星数据写入 CSV 文件（代码在`03/create_csv.py`中）：

```py
import csv
from get_planet_data import get_planet_data

planets = get_planet_data()

with open('../../www/planets.csv', 'w+', newline='') as csvFile:
    writer = csv.writer(csvFile)
    writer.writerow(['Name', 'Mass', 'Radius', 'Description', 'MoreInfo'])
for planet in planets:
        writer.writerow([planet['Name'], planet['Mass'],planet['Radius'], planet['Description'], planet['MoreInfo']])

```

1.  输出文件放入我们项目的 www 文件夹中。检查它，我们看到以下内容：

```py
Name,Mass,Radius,Description,MoreInfo
Mercury,0.330,4879,Named Mercurius by the Romans because it appears to move so swiftly.,https://en.wikipedia.org/wiki/Mercury_(planet)
Venus,4.87,12104,Roman name for the goddess of love. This planet was considered to be the brightest and most beautiful planet or star in the heavens. Other civilizations have named it for their god or goddess of love/war.,https://en.wikipedia.org/wiki/Venus
Earth,5.97,12756,"The name Earth comes from the Indo-European base 'er,'which produced the Germanic noun 'ertho,' and ultimately German 'erde,' Dutch 'aarde,' Scandinavian 'jord,' and English 'earth.' Related forms include Greek 'eraze,' meaning 'on the ground,' and Welsh 'erw,' meaning 'a piece of land.'",https://en.wikipedia.org/wiki/Earth
Mars,0.642,6792,"Named by the Romans for their god of war because of its red, bloodlike color. Other civilizations also named this planet from this attribute; for example, the Egyptians named it ""Her Desher,"" meaning ""the red one.""",https://en.wikipedia.org/wiki/Mars
Jupiter,1898,142984,The largest and most massive of the planets was named Zeus by the Greeks and Jupiter by the Romans; he was the most important deity in both pantheons.,https://en.wikipedia.org/wiki/Jupiter
Saturn,568,120536,"Roman name for the Greek Cronos, father of Zeus/Jupiter. Other civilizations have given different names to Saturn, which is the farthest planet from Earth that can be observed by the naked human eye. Most of its satellites were named for Titans who, according to Greek mythology, were brothers and sisters of Saturn.",https://en.wikipedia.org/wiki/Saturn
Uranus,86.8,51118,"Several astronomers, including Flamsteed and Le Monnier, had observed Uranus earlier but had recorded it as a fixed star. Herschel tried unsuccessfully to name his discovery ""Georgian Sidus"" after George III; the planet was named by Johann Bode in 1781 after the ancient Greek deity of the sky Uranus, the father of Kronos (Saturn) and grandfather of Zeus (Jupiter).",https://en.wikipedia.org/wiki/Uranus
Neptune,102,49528,"Neptune was ""predicted"" by John Couch Adams and Urbain Le Verrier who, independently, were able to account for the irregularities in the motion of Uranus by correctly predicting the orbital elements of a trans- Uranian body. Using the predicted parameters of Le Verrier (Adams never published his predictions), Johann Galle observed the planet in 1846\. Galle wanted to name the planet for Le Verrier, but that was not acceptable to the international astronomical community. Instead, this planet is named for the Roman god of the sea.",https://en.wikipedia.org/wiki/Neptune
Pluto,0.0146,2370,"Pluto was discovered at Lowell Observatory in Flagstaff, AZ during a systematic search for a trans-Neptune planet predicted by Percival Lowell and William H. Pickering. Named after the Roman god of the underworld who was able to render himself invisible.",https://en.wikipedia.org/wiki/Pluto
```

我们将这个文件写入 www 目录，以便我们可以通过我们的 Web 服务器下载它。

1.  现在可以在支持 CSV 内容的应用程序中使用这些数据，例如 Excel：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/a00f3815-56b8-4bfb-bcd7-e9dbd035caa9.png)在 Excel 中打开的文件

1.  还可以使用`csv`库从 Web 服务器读取 CSV 数据，并首先使用`requests`检索内容。以下代码在`03/read_csv_from_web.py`中：

```py
import requests
import csv

planets_data = requests.get("http://localhost:8080/planets.csv").text
planets = planets_data.split('\n')
reader = csv.reader(planets, delimiter=',', quotechar='"')
lines = [line for line in reader][:-1]
for line in lines: print(line)
```

以下是部分输出

```py
['Name', 'Mass', 'Radius', 'Description', 'MoreInfo']
['Mercury', '0.330', '4879', 'Named Mercurius by the Romans because it appears to move so swiftly.', 'https://en.wikipedia.org/wiki/Mercury_(planet)']
['Venus', '4.87', '12104', 'Roman name for the goddess of love. This planet was considered to be the brightest and most beautiful planet or star in the heavens. Other civilizations have named it for their god or goddess of love/war.', 'https://en.wikipedia.org/wiki/Venus']
['Earth', '5.97', '12756', "The name Earth comes from the Indo-European base 'er,'which produced the Germanic noun 'ertho,' and ultimately German 'erde,' Dutch 'aarde,' Scandinavian 'jord,' and English 'earth.' Related forms include Greek 'eraze,' meaning 'on the ground,' and Welsh 'erw,' meaning 'a piece of land.'", 'https://en.wikipedia.org/wiki/Earth']
```

有一点要指出的是，CSV 写入器留下了一个尾随空白，如果不处理，就会添加一个空列表项。这是通过切片行来处理的：以下语句返回除最后一行之外的所有行：

`lines = [line for line in reader][:-1]`

1.  这也可以很容易地使用 pandas 完成。以下从抓取的数据构造一个 DataFrame。代码在`03/create_df_planets.py`中：

```py
import pandas as pd
planets_df = pd.read_csv("http://localhost:8080/planets_pandas.csv", index_col='Name')
print(planets_df)
```

运行此命令将产生以下输出：

```py
                                               Description Mass Radius
Name 
Mercury Named Mercurius by the Romans because it appea...  0.330 4879
Venus   Roman name for the goddess of love. This plane...   4.87 12104
Earth   The name Earth comes from the Indo-European ba...   5.97 12756
Mars    Named by the Romans for their god of war becau...  0.642 6792
Jupiter The largest and most massive of the planets wa...   1898 142984
Saturn  Roman name for the Greek Cronos, father of Zeu...    568 120536
Uranus  Several astronomers, including Flamsteed and L...   86.8 51118
Neptune Neptune was "predicted" by John Couch Adams an...    102 49528
Pluto   Pluto was discovered at Lowell Observatory in ... 0.0146 2370
```

1.  `DataFrame`也可以通过简单调用`.to_csv()`保存到 CSV 文件中（代码在`03/save_csv_pandas.py`中）：

```py
import pandas as pd
from get_planet_data import get_planet_data

# construct a data from from the list planets = get_planet_data()
planets_df = pd.DataFrame(planets).set_index('Name')
planets_df.to_csv("../../www/planets_pandas.csv")
```

1.  可以使用`pd.read_csv()`非常轻松地从`URL`中读取 CSV 文件，无需其他库。您可以使用`03/read_csv_via_pandas.py`中的代码：

```py
import pandas as pd
planets_df = pd.read_csv("http://localhost:8080/planets_pandas.csv", index_col='Name')
print(planets_df)
```

1.  将数据转换为 JSON 也非常容易。使用 Python 可以使用 Python 的`json`库对 JSON 进行操作。该库可用于将 Python 对象转换为 JSON，也可以从 JSON 转换为 Python 对象。以下将行星列表转换为 JSON 并将其打印到控制台：将行星数据打印为 JSON（代码在`03/convert_to_json.py`中）：

```py
import json
from get_planet_data import get_planet_data
planets=get_planet_data()
print(json.dumps(planets, indent=4))
```

执行此脚本将产生以下输出（省略了部分输出）：

```py
[
    {
        "Name": "Mercury",
        "Mass": "0.330",
        "Radius": "4879",
        "Description": "Named Mercurius by the Romans because it appears to move so swiftly.",
        "MoreInfo": "https://en.wikipedia.org/wiki/Mercury_(planet)"
    },
    {
        "Name": "Venus",
        "Mass": "4.87",
        "Radius": "12104",
        "Description": "Roman name for the goddess of love. This planet was considered to be the brightest and most beautiful planet or star in the heavens. Other civilizations have named it for their god or goddess of love/war.",
        "MoreInfo": "https://en.wikipedia.org/wiki/Venus"
    },
```

1.  这也可以用于轻松地将 JSON 保存到文件（`03/save_as_json.py`）：

```py
import json
from get_planet_data import get_planet_data
planets=get_planet_data()
with open('../../www/planets.json', 'w+') as jsonFile:
   json.dump(planets, jsonFile, indent=4)
```

1.  使用`!head -n 13 ../../www/planets.json`检查输出，显示：

```py
[
    {
        "Name": "Mercury",
        "Mass": "0.330",
        "Radius": "4879",
        "Description": "Named Mercurius by the Romans because it appears to move so swiftly.",
        "MoreInfo": "https://en.wikipedia.org/wiki/Mercury_(planet)"
    },
    {
        "Name": "Venus",
        "Mass": "4.87",
        "Radius": "12104",
        "Description": "Roman name for the goddess of love. This planet was considered to be the brightest and most beautiful planet or star in the heavens. Other civilizations have named it for their god or goddess of love/war.",
```

1.  可以使用`requests`从 Web 服务器读取 JSON 并将其转换为 Python 对象（`03/read_http_json_requests.py`）：

```py
import requests
import json

planets_request = requests.get("http://localhost:8080/planets.json")
print(json.loads(planets_request.text))
```

1.  pandas 还提供了将 JSON 保存为 CSV 的功能（`03/save_json_pandas.py`）：

```py
import pandas as pd
from get_planet_data import get_planet_data

planets = get_planet_data()
planets_df = pd.DataFrame(planets).set_index('Name')
planets_df.reset_index().to_json("../../www/planets_pandas.json", orient='records')
```

不幸的是，目前还没有一种方法可以漂亮地打印从`.to_json()`输出的 JSON。还要注意使用`orient='records'`和使用`rest_index()`。这对于复制与使用 JSON 库示例写入的相同 JSON 结构是必要的。

1.  可以使用`.read_json()`将 JSON 读入 DataFrame，也可以从 HTTP 和文件中读取（`03/read_json_http_pandas.py`）：

```py
import pandas as pd
planets_df = pd.read_json("http://localhost:8080/planets_pandas.json").set_index('Name')
print(planets_df)
```

# 工作原理

`csv`和`json`库是 Python 的标准部分，提供了一种简单的方法来读取和写入这两种格式的数据。

在某些 Python 发行版中，pandas 并不是标准配置，您可能需要安装它。pandas 对 CSV 和 JSON 的功能也更高级，提供了许多强大的数据操作，还支持从远程服务器访问数据。

# 还有更多...

选择 csv、json 或 pandas 库由您决定，但我倾向于喜欢 pandas，并且我们将在整本书中更多地研究其在抓取中的使用，尽管我们不会深入研究其用法。

要深入了解 pandas，请查看`pandas.pydata.org`，或者阅读我在 Packt 出版的另一本书《Learning pandas, 2ed》。

有关 csv 库的更多信息，请参阅[`docs.python.org/3/library/csv.html`](https://docs.python.org/3/library/csv.html)

有关 json 库的更多信息，请参阅[`docs.python.org/3/library/json.html`](https://docs.python.org/3/library/json.html)

# 使用 AWS S3 存储数据

有许多情况下，我们只想将我们抓取的内容保存到本地副本以进行存档、备份或以后进行批量分析。我们还可能希望保存这些网站的媒体以供以后使用。我为广告合规公司构建了爬虫，我们会跟踪并下载网站上基于广告的媒体，以确保正确使用，并且以供以后分析、合规和转码。

这些类型系统所需的存储空间可能是巨大的，但随着云存储服务（如 AWS S3（简单存储服务））的出现，这比在您自己的 IT 部门中管理大型 SAN（存储区域网络）要容易得多，成本也更低。此外，S3 还可以自动将数据从热存储移动到冷存储，然后再移动到长期存储，例如冰川，这可以为您节省更多的钱。

我们不会深入研究所有这些细节，而只是看看如何将我们的`planets.html`文件存储到 S3 存储桶中。一旦您能做到这一点，您就可以保存任何您想要的内容。

# 准备就绪

要执行以下示例，您需要一个 AWS 账户，并且可以访问用于 Python 代码的密钥。它们将是您账户的唯一密钥。我们将使用`boto3`库来访问 S3。您可以使用`pip install boto3`来安装它。此外，您需要设置环境变量进行身份验证。它们看起来像下面这样：

`AWS_ACCESS_KEY_ID=AKIAIDCQ5PH3UMWKZEWA`

`AWS_SECRET_ACCESS_KEY=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`

这些可以在 AWS 门户的 IAM（身份访问管理）部分找到。

将这些密钥放在环境变量中是一个好习惯。在代码中使用它们可能会导致它们被盗。在编写本书时，我将它们硬编码并意外地将它们检入 GitHub。第二天早上，我醒来收到了来自 AWS 的关键消息，说我有成千上万台服务器在运行！GitHub 有爬虫在寻找这些密钥，它们会被找到并用于不正当目的。等我把它们全部关闭的时候，我的账单已经涨到了 6000 美元，全部是在一夜之间产生的。幸运的是，AWS 免除了这些费用！

# 如何做到这一点

我们不会解析`planets.html`文件中的数据，而只是使用 requests 从本地 web 服务器检索它：

1.  以下代码（在`03/S3.py`中找到）读取行星网页并将其存储在 S3 中：

```py
import requests
import boto3

data = requests.get("http://localhost:8080/planets.html").text

# create S3 client, use environment variables for keys s3 = boto3.client('s3')

# the bucket bucket_name = "planets-content"   # create bucket, set s3.create_bucket(Bucket=bucket_name, ACL='public-read')
s3.put_object(Bucket=bucket_name, Key='planet.html',
              Body=data, ACL="public-read")
```

1.  这个应用程序将给出类似以下的输出，这是 S3 信息，告诉您关于新项目的各种事实。

```py

{'ETag': '"3ada9dcd8933470221936534abbf7f3e"',
 'ResponseMetadata': {'HTTPHeaders': {'content-length': '0',
   'date': 'Sun, 27 Aug 2017 19:25:54 GMT',
   'etag': '"3ada9dcd8933470221936534abbf7f3e"',
   'server': 'AmazonS3',
   'x-amz-id-2': '57BkfScql637op1dIXqJ7TeTmMyjVPk07cAMNVqE7C8jKsb7nRO+0GSbkkLWUBWh81k+q2nMQnE=',
   'x-amz-request-id': 'D8446EDC6CBA4416'},
  'HTTPStatusCode': 200,
  'HostId': '57BkfScql637op1dIXqJ7TeTmMyjVPk07cAMNVqE7C8jKsb7nRO+0GSbkkLWUBWh81k+q2nMQnE=',
  'RequestId': 'D8446EDC6CBA4416',
  'RetryAttempts': 0}}
```

1.  这个输出告诉我们对象已成功创建在存储桶中。此时，您可以转到 S3 控制台并查看您的存储桶：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/29fbd119-7ee5-43eb-8b2f-9bc34998ff53.png)S3 中的存储桶

1.  在存储桶中，您将看到`planet.html`文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/49cc32c4-5ac3-4177-a397-35385afbcf4e.png)存储桶中的文件

1.  通过点击文件，您可以看到 S3 中文件的属性和 URL：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/6c5b035d-009f-4878-9806-034b4db8e500.png)S3 中文件的属性

# 它是如何工作的

boto3 库以 Pythonic 语法封装了 AWS S3 API。`.client()`调用与 AWS 进行身份验证，并为我们提供了一个用于与 S3 通信的对象。确保您的密钥在环境变量中，否则这将无法工作。

存储桶名称必须是全局唯一的。在撰写本文时，这个存储桶是可用的，但您可能需要更改名称。`.create_bucket()`调用创建存储桶并设置其 ACL。`put_object()`使用`boto3`上传管理器将抓取的数据上传到存储桶中的对象。

# 还有更多...

有很多细节需要学习来使用 S3。您可以在以下网址找到 API 文档：[`docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html`](http://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html)。Boto3 文档可以在以下网址找到：[`boto3.readthedocs.io/en/latest/`](https://boto3.readthedocs.io/en/latest/)。

虽然我们只保存了一个网页，但这个模型可以用来在 S3 中存储任何类型的基于文件的数据。

# 使用 MySQL 存储数据

MySQL 是一个免费的、开源的关系数据库管理系统（RDBMS）。在这个例子中，我们将从网站读取行星数据并将其存储到 MySQL 数据库中。

# 准备工作

您需要访问一个 MySQL 数据库。您可以在本地安装一个，也可以在云中安装，也可以在容器中安装。我正在使用本地安装的 MySQL 服务器，并且将`root`密码设置为`mypassword`。您还需要安装 MySQL python 库。您可以使用`pip install mysql-connector-python`来安装它。

1.  首先要做的是使用终端上的`mysql`命令连接到数据库：

```py
# mysql -uroot -pmypassword
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor. Commands end with ; or \g.
Your MySQL connection id is 4
Server version: 5.7.19 MySQL Community Server (GPL)

Copyright (c) 2000, 2017, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

1.  现在我们可以创建一个数据库，用来存储我们抓取的信息：

```py
mysql> create database scraping;
Query OK, 1 row affected (0.00 sec)
```

1.  现在使用新的数据库：

```py
mysql> use scraping;
Database changed
```

1.  并在数据库中创建一个行星表来存储我们的数据：

```py

mysql> CREATE TABLE `scraping`.`planets` (
 `id` INT NOT NULL AUTO_INCREMENT,
 `name` VARCHAR(45) NOT NULL,
 `mass` FLOAT NOT NULL,
 `radius` FLOAT NOT NULL,
 `description` VARCHAR(5000) NULL,
 PRIMARY KEY (`id`));
Query OK, 0 rows affected (0.02 sec)

```

现在我们准备好抓取数据并将其放入 MySQL 数据库中。

# 如何做到这一点

1.  以下代码（在`03/store_in_mysql.py`中找到）将读取行星数据并将其写入 MySQL：

```py
import mysql.connector
import get_planet_data
from mysql.connector import errorcode
from get_planet_data import get_planet_data

try:
    # open the database connection
    cnx = mysql.connector.connect(user='root', password='mypassword',
                                  host="127.0.0.1", database="scraping")

    insert_sql = ("INSERT INTO Planets (Name, Mass, Radius, Description) " +
                  "VALUES (%(Name)s, %(Mass)s, %(Radius)s, %(Description)s)")

    # get the planet data
    planet_data = get_planet_data()

    # loop through all planets executing INSERT for each with the cursor
    cursor = cnx.cursor()
    for planet in planet_data:
        print("Storing data for %s" % (planet["Name"]))
        cursor.execute(insert_sql, planet)

    # commit the new records
    cnx.commit()

    # close the cursor and connection
    cursor.close()
    cnx.close()

except mysql.connector.Error as err:
    if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
        print("Something is wrong with your user name or password")
    elif err.errno == errorcode.ER_BAD_DB_ERROR:
        print("Database does not exist")
    else:
        print(err)
else:
    cnx.close()
```

1.  这将产生以下输出：

```py
Storing data for Mercury
Storing data for Venus
Storing data for Earth
Storing data for Mars
Storing data for Jupiter
Storing data for Saturn
Storing data for Uranus
Storing data for Neptune
Storing data for Pluto
```

1.  使用 MySQL Workbench，我们可以看到记录已写入数据库（您也可以使用 mysql 命令行）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/c8a2c090-dce7-40f2-b0b3-0c6d72ff3885.png)使用 MySQL Workbench 显示的记录

1.  以下代码可用于检索数据（`03/read_from_mysql.py`）：

```py
import mysql.connector
from mysql.connector import errorcode

try:
  cnx = mysql.connector.connect(user='root', password='mypassword',
                  host="127.0.0.1", database="scraping")
  cursor = cnx.cursor(dictionary=False)

  cursor.execute("SELECT * FROM scraping.Planets")
  for row in cursor:
    print(row)

  # close the cursor and connection
  cursor.close()
  cnx.close()

except mysql.connector.Error as err:
  if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
    print("Something is wrong with your user name or password")
  elif err.errno == errorcode.ER_BAD_DB_ERROR:
    print("Database does not exist")
  else:
    print(err)
finally:
  cnx.close()

```

1.  这将产生以下输出：

```py
(1, 'Mercury', 0.33, 4879.0, 'Named Mercurius by the Romans because it appears to move so swiftly.', 'https://en.wikipedia.org/wiki/Mercury_(planet)')
(2, 'Venus', 4.87, 12104.0, 'Roman name for the goddess of love. This planet was considered to be the brightest and most beautiful planet or star in the heavens. Other civilizations have named it for their god or goddess of love/war.', 'https://en.wikipedia.org/wiki/Venus')
(3, 'Earth', 5.97, 12756.0, "The name Earth comes from the Indo-European base 'er,'which produced the Germanic noun 'ertho,' and ultimately German 'erde,' Dutch 'aarde,' Scandinavian 'jord,' and English 'earth.' Related forms include Greek 'eraze,' meaning 'on the ground,' and Welsh 'erw,' meaning 'a piece of land.'", 'https://en.wikipedia.org/wiki/Earth')
(4, 'Mars', 0.642, 6792.0, 'Named by the Romans for their god of war because of its red, bloodlike color. Other civilizations also named this planet from this attribute; for example, the Egyptians named it "Her Desher," meaning "the red one."', 'https://en.wikipedia.org/wiki/Mars')
(5, 'Jupiter', 1898.0, 142984.0, 'The largest and most massive of the planets was named Zeus by the Greeks and Jupiter by the Romans; he was the most important deity in both pantheons.', 'https://en.wikipedia.org/wiki/Jupiter')
(6, 'Saturn', 568.0, 120536.0, 'Roman name for the Greek Cronos, father of Zeus/Jupiter. Other civilizations have given different names to Saturn, which is the farthest planet from Earth that can be observed by the naked human eye. Most of its satellites were named for Titans who, according to Greek mythology, were brothers and sisters of Saturn.', 'https://en.wikipedia.org/wiki/Saturn')
(7, 'Uranus', 86.8, 51118.0, 'Several astronomers, including Flamsteed and Le Monnier, had observed Uranus earlier but had recorded it as a fixed star. Herschel tried unsuccessfully to name his discovery "Georgian Sidus" after George III; the planet was named by Johann Bode in 1781 after the ancient Greek deity of the sky Uranus, the father of Kronos (Saturn) and grandfather of Zeus (Jupiter).', 'https://en.wikipedia.org/wiki/Uranus')
(8, 'Neptune', 102.0, 49528.0, 'Neptune was "predicted" by John Couch Adams and Urbain Le Verrier who, independently, were able to account for the irregularities in the motion of Uranus by correctly predicting the orbital elements of a trans- Uranian body. Using the predicted parameters of Le Verrier (Adams never published his predictions), Johann Galle observed the planet in 1846\. Galle wanted to name the planet for Le Verrier, but that was not acceptable to the international astronomical community. Instead, this planet is named for the Roman god of the sea.', 'https://en.wikipedia.org/wiki/Neptune')
(9, 'Pluto', 0.0146, 2370.0, 'Pluto was discovered at Lowell Observatory in Flagstaff, AZ during a systematic search for a trans-Neptune planet predicted by Percival Lowell and William H. Pickering. Named after the Roman god of the underworld who was able to render himself invisible.', 'https://en.wikipedia.org/wiki/Pluto')
```

# 工作原理

使用`mysql.connector`访问 MySQL 数据库涉及使用库中的两个类：`connect`和`cursor`。`connect`类打开并管理与数据库服务器的连接。从该连接对象，我们可以创建一个光标对象。该光标用于使用 SQL 语句读取和写入数据。

在第一个例子中，我们使用光标将九条记录插入数据库。直到调用连接的`commit()`方法，这些记录才会被写入数据库。这将执行将所有行写入数据库的操作。

读取数据使用类似的模型，只是我们使用光标执行 SQL 查询（`SELECT`），并遍历检索到的行。由于我们是在读取而不是写入，因此无需在连接上调用`commit()`。

# 还有更多...

您可以从以下网址了解更多关于 MySQL 并安装它：`https://dev.mysql.com/doc/refman/5.7/en/installing.html`。有关 MySQL Workbench 的信息，请访问：`https://dev.mysql.com/doc/workbench/en/`。

# 使用 PostgreSQL 存储数据

在这个示例中，我们将我们的行星数据存储在 PostgreSQL 中。PostgreSQL 是一个开源的关系数据库管理系统（RDBMS）。它由一个全球志愿者团队开发，不受任何公司或其他私人实体控制，源代码可以免费获得。它具有许多独特的功能，如分层数据模型。

# 准备工作

首先确保您可以访问 PostgreSQL 数据实例。同样，您可以在本地安装一个，运行一个容器，或者在云中获取一个实例。

与 MySQL 一样，我们需要首先创建一个数据库。该过程与 MySQL 几乎相同，但命令和参数略有不同。

1.  从终端执行终端上的 psql 命令。这将带您进入 psql 命令处理器：

```py
# psql -U postgres psql (9.6.4) Type "help" for help. postgres=# 
```

1.  现在创建抓取数据库：

```py
postgres=# create database scraping;
CREATE DATABASE
postgres=#
```

1.  然后切换到新数据库：

```py
postgres=# \connect scraping You are now connected to database "scraping" as user "postgres". scraping=# 
```

1.  现在我们可以创建 Planets 表。我们首先需要创建一个序列表：

```py
scraping=# CREATE SEQUENCE public."Planets_id_seq" scraping-#  INCREMENT 1 scraping-#  START 1 scraping-#  MINVALUE 1 scraping-#  MAXVALUE 9223372036854775807 scraping-#  CACHE 1; CREATE SEQUENCE scraping=# ALTER SEQUENCE public."Planets_id_seq" scraping-#  OWNER TO postgres; ALTER SEQUENCE scraping=# 
```

1.  现在我们可以创建表：

```py
scraping=# CREATE TABLE public."Planets" scraping-# ( scraping(# id integer NOT NULL DEFAULT nextval('"Planets_id_seq"'::regclass), scraping(# name text COLLATE pg_catalog."default" NOT NULL, scraping(# mass double precision NOT NULL, scraping(# radius double precision NOT NULL, scraping(# description text COLLATE pg_catalog."default" NOT NULL, scraping(# moreinfo text COLLATE pg_catalog."default" NOT NULL, scraping(# CONSTRAINT "Planets_pkey" PRIMARY KEY (name) scraping(# ) scraping-# WITH ( scraping(# OIDS = FALSE scraping(# )
</span>scraping-# TABLESPACE pg_default; CREATE TABLE scraping=# scraping=# ALTER TABLE public."Planets" scraping-# OWNER to postgres; ALTER TABLE scraping=# \q
```

要从 Python 访问 PostgreSQL，我们将使用`psycopg2`库，因此请确保在 Python 环境中安装了它，使用`pip install psycopg2`。

我们现在准备好编写 Python 将行星数据存储在 PostgreSQL 中。

# 如何操作

我们按照以下步骤进行：

1.  以下代码将读取行星数据并将其写入数据库（代码在`03/save_in_postgres.py`中）：

```py
import psycopg2
from get_planet_data import get_planet_data

try:
  # connect to PostgreSQL
  conn = psycopg2.connect("dbname='scraping' host='localhost' user='postgres' password='mypassword'")

  # the SQL INSERT statement we will use
  insert_sql = ('INSERT INTO public."Planets"(name, mass, radius, description, moreinfo) ' +
          'VALUES (%(Name)s, %(Mass)s, %(Radius)s, %(Description)s, %(MoreInfo)s);')

  # open a cursor to access data
  cur = conn.cursor()

  # get the planets data and loop through each
  planet_data = get_planet_data()
  for planet in planet_data:
    # write each record
    cur.execute(insert_sql, planet)

  # commit the new records to the database
  conn.commit()
  cur.close()
  conn.close()

  print("Successfully wrote data to the database")

except Exception as ex:
  print(ex)

```

1.  如果成功，您将看到以下内容：

```py
Successfully wrote data to the database
```

1.  使用诸如 pgAdmin 之类的 GUI 工具，您可以检查数据库中的数据：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/e1060188-c3d3-4a2d-aaf4-4f9124294d9e.png)在 pgAdmin 中显示的记录

1.  可以使用以下 Python 代码查询数据（在`03/read_from_postgresql.py`中找到）：

```py
import psycopg2

try:
  conn = psycopg2.connect("dbname='scraping' host='localhost' user='postgres' password='mypassword'")

  cur = conn.cursor()
  cur.execute('SELECT * from public."Planets"')
  rows = cur.fetchall()
  print(rows)

  cur.close()
  conn.close()

except Exception as ex:
  print(ex)

```

1.  并导致以下输出（略有截断：

```py
(1, 'Mercury', 0.33, 4879.0, 'Named Mercurius by the Romans because it appears to move so swiftly.', 'https://en.wikipedia.org/wiki/Mercury_(planet)'), (2, 'Venus', 4.87, 12104.0, 'Roman name for the goddess of love. This planet was considered to be the brightest and most beautiful planet or star in the heavens. Other civilizations have named it for their god or goddess of love/war.', 'https://en.wikipedia.org/wiki/Venus'), (3, 'Earth', 5.97, 12756.0, "The name Earth comes from the Indo-European base 'er,'which produced the Germanic noun 'ertho,' and ultimately German 'erde,' Dutch 'aarde,' Scandinavian 'jord,' and English 'earth.' Related forms include Greek 'eraze,' meaning 'on the ground,' and Welsh 'erw,' meaning 'a piece of land.'", 'https://en.wikipedia.org/wiki/Earth'), (4, 'Mars', 0.642, 6792.0, 'Named by the Romans for their god of war because of its red, bloodlike color. Other civilizations also named this planet from this attribute; for example, the Egyptians named it 
```

# 工作原理

使用`psycopg2`库访问 PostgreSQL 数据库涉及使用库中的两个类：`connect`和`cursor`。`connect`类打开并管理与数据库服务器的连接。从该连接对象，我们可以创建一个`cursor`对象。该光标用于使用 SQL 语句读取和写入数据。

在第一个例子中，我们使用光标将九条记录插入数据库。直到调用连接的`commit()`方法，这些记录才会被写入数据库。这将执行将所有行写入数据库的操作。

读取数据使用类似的模型，只是我们使用游标执行 SQL 查询（`SELECT`），并遍历检索到的行。由于我们是在读取而不是写入，所以不需要在连接上调用`commit()`。

# 还有更多...

有关 PostgreSQL 的信息可在`https://www.postgresql.org/`找到。pgAdmin 可以在`https://www.pgadmin.org/`获得。`psycopg`的参考资料位于`http://initd.org/psycopg/docs/usage.html`

# 在 Elasticsearch 中存储数据

Elasticsearch 是基于 Lucene 的搜索引擎。它提供了一个分布式、多租户能力的全文搜索引擎，具有 HTTP Web 界面和无模式的 JSON 文档。它是一个非关系型数据库（通常称为 NoSQL），专注于存储文档而不是记录。这些文档可以是许多格式之一，其中之一对我们有用：JSON。这使得使用 Elasticsearch 非常简单，因为我们不需要将我们的数据转换为/从 JSON。我们将在本书的后面更多地使用 Elasticsearch

现在，让我们去将我们的行星数据存储在 Elasticsearch 中。

# 准备就绪

我们将访问一个本地安装的 Elasticsearch 服务器。为此，我们将使用`Elasticsearch-py`库从 Python 中进行操作。您很可能需要使用 pip 来安装它：`pip install elasticsearch`。

与 PostgreSQL 和 MySQL 不同，我们不需要提前在 Elasticsearch 中创建表。Elasticsearch 不关心结构化数据模式（尽管它确实有索引），因此我们不必经历这个过程。

# 如何做到

将数据写入 Elasticsearch 非常简单。以下 Python 代码使用我们的行星数据执行此任务（`03/write_to_elasticsearch.py`）：

```py
from elasticsearch import Elasticsearch
from get_planet_data import get_planet_data

# create an elastic search object
es = Elasticsearch()

# get the data
planet_data = get_planet_data()

for planet in planet_data:
  # insert each planet into elasticsearch server
  res = es.index(index='planets', doc_type='planets_info', body=planet)
  print (res)
```

执行此操作将产生以下输出：

```py
{'_index': 'planets', '_type': 'planets_info', '_id': 'AV4qIF3_T0Z2t9T850q6', '_version': 1, 'result': 'created', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': True}{'_index': 'planets', '_type': 'planets_info', '_id': 'AV4qIF5QT0Z2t9T850q7', '_version': 1, 'result': 'created', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': True}
{'_index': 'planets', '_type': 'planets_info', '_id': 'AV4qIF5XT0Z2t9T850q8', '_version': 1, 'result': 'created', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': True}
{'_index': 'planets', '_type': 'planets_info', '_id': 'AV4qIF5fT0Z2t9T850q9', '_version': 1, 'result': 'created', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': True}
{'_index': 'planets', '_type': 'planets_info', '_id': 'AV4qIF5mT0Z2t9T850q-', '_version': 1, 'result': 'created', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': True}
{'_index': 'planets', '_type': 'planets_info', '_id': 'AV4qIF5rT0Z2t9T850q_', '_version': 1, 'result': 'created', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': True}
{'_index': 'planets', '_type': 'planets_info', '_id': 'AV4qIF50T0Z2t9T850rA', '_version': 1, 'result': 'created', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': True}
{'_index': 'planets', '_type': 'planets_info', '_id': 'AV4qIF56T0Z2t9T850rB', '_version': 1, 'result': 'created', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': True}
{'_index': 'planets', '_type': 'planets_info', '_id': 'AV4qIF6AT0Z2t9T850rC', '_version': 1, 'result': 'created', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': True}
```

输出显示了每次插入的结果，为我们提供了 elasticsearch 分配给文档的`_id`等信息。

如果您也安装了 logstash 和 kibana，您可以在 Kibana 内部看到数据：

![Kibana 显示和索引

我们可以使用以下 Python 代码查询数据。此代码检索“planets”索引中的所有文档，并打印每个行星的名称、质量和半径（`03/read_from_elasticsearch.py`）：

```py
from elasticsearch import Elasticsearch

# create an elastic search object
es = Elasticsearch()

res = es.search(index="planets", body={"query": {"match_all": {}}})

```

```py
print("Got %d Hits:" % res['hits']['total'])
for hit in res['hits']['hits']:
 print("%(Name)s %(Mass)s: %(Radius)s" % hit["_source"])Got 9 Hits:
```

这将产生以下输出：

```py
Mercury 0.330: 4879
Mars 0.642: 6792
Venus 4.87: 12104
Saturn 568: 120536
Pluto 0.0146: 2370
Earth 5.97: 12756
Uranus 86.8: 51118
Jupiter 1898: 142984
Neptune 102: 49528
```

# 它是如何工作的

Elasticsearch 既是 NoSQL 数据库又是搜索引擎。您将文档提供给 Elasticsearch，它会解析文档中的数据并自动为该数据创建搜索索引。

在插入过程中，我们使用了`elasticsearch`库的`.index()`方法，并指定了一个名为“planets”的索引，一个文档类型`planets_info`，最后是文档的主体，即我们的行星 Python 对象。`elasticsearch`库将该对象转换为 JSON 并将其发送到 Elasticsearch 进行存储和索引。

索引参数用于通知 Elasticsearch 如何创建索引，它将用于索引和我们在查询时可以用来指定要搜索的一组文档。当我们执行查询时，我们指定了相同的索引“planets”并执行了一个匹配所有文档的查询。

# 还有更多...

您可以在`https://www.elastic.co/products/elasticsearch`找到有关 elasticsearch 的更多信息。有关 python API 的信息可以在`http://pyelasticsearch.readthedocs.io/en/latest/api/`找到

我们还将在本书的后面章节回到 Elasticsearch。

# 如何使用 AWS SQS 构建强大的 ETL 管道

爬取大量站点和数据可能是一个复杂和缓慢的过程。但它可以充分利用并行处理，无论是在本地使用多个处理器线程，还是使用消息队列系统将爬取请求分发给报告爬虫。在类似于提取、转换和加载流水线（ETL）的过程中，可能还需要多个步骤。这些流水线也可以很容易地使用消息队列架构与爬取相结合来构建。

使用消息队列架构给我们的流水线带来了两个优势：

+   健壮性

+   可伸缩性

处理变得健壮，因为如果处理单个消息失败，那么消息可以重新排队进行处理。因此，如果爬虫失败，我们可以重新启动它，而不会丢失对页面进行爬取的请求，或者消息队列系统将把请求传递给另一个爬虫。

它提供了可伸缩性，因为在同一系统或不同系统上可以监听队列上的多个爬虫。然后，可以在不同的核心或更重要的是不同的系统上同时处理多个消息。在基于云的爬虫中，您可以根据需要扩展爬虫实例的数量以处理更大的负载。

可以使用的常见消息队列系统包括：Kafka、RabbitMQ 和 Amazon SQS。我们的示例将利用 Amazon SQS，尽管 Kafka 和 RabbitMQ 都非常适合使用（我们将在本书的后面看到 RabbitMQ 的使用）。我们使用 SQS 来保持使用 AWS 基于云的服务的模式，就像我们在本章早些时候使用 S3 一样。

# 准备就绪

例如，我们将构建一个非常简单的 ETL 过程，该过程将读取主行星页面并将行星数据存储在 MySQL 中。它还将针对页面中的每个*更多信息*链接传递单个消息到队列中，其中 0 个或多个进程可以接收这些请求，并对这些链接执行进一步处理。

要从 Python 访问 SQS，我们将重新使用`boto3`库。

# 如何操作-将消息发布到 AWS 队列

`03/create_messages.py`文件包含了读取行星数据并将 URL 发布到 SQS 队列的代码：

```py
from urllib.request import urlopen
from bs4 import BeautifulSoup

import boto3
import botocore

# declare our keys (normally, don't hard code this)
access_key="AKIAIXFTCYO7FEL55TCQ"
access_secret_key="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"

# create sqs client
sqs = boto3.client('sqs', "us-west-2",
                   aws_access_key_id = access_key, 
                   aws_secret_access_key = access_secret_key)

# create / open the SQS queue
queue = sqs.create_queue(QueueName="PlanetMoreInfo")
print (queue)

# read and parse the planets HTML
html = urlopen("http://127.0.0.1:8080/pages/planets.html")
bsobj = BeautifulSoup(html, "lxml")

planets = []
planet_rows = bsobj.html.body.div.table.findAll("tr", {"class": "planet"})

for i in planet_rows:
  tds = i.findAll("td")

  # get the URL
  more_info_url = tds[5].findAll("a")[0]["href"].strip()

  # send the URL to the queue
  sqs.send_message(QueueUrl=queue["QueueUrl"],
           MessageBody=more_info_url)
  print("Sent %s to %s" % (more_info_url, queue["QueueUrl"]))
```

在终端中运行代码，您将看到类似以下的输出：

```py
{'QueueUrl': 'https://us-west-2.queue.amazonaws.com/414704166289/PlanetMoreInfo', 'ResponseMetadata': {'RequestId': '2aad7964-292a-5bf6-b838-2b7a5007af22', 'HTTPStatusCode': 200, 'HTTPHeaders': {'server': 'Server', 'date': 'Mon, 28 Aug 2017 20:02:53 GMT', 'content-type': 'text/xml', 'content-length': '336', 'connection': 'keep-alive', 'x-amzn-requestid': '2aad7964-292a-5bf6-b838-2b7a5007af22'}, 'RetryAttempts': 0}} Sent https://en.wikipedia.org/wiki/Mercury_(planet) to https://us-west-2.queue.amazonaws.com/414704166289/PlanetMoreInfo Sent https://en.wikipedia.org/wiki/Venus to https://us-west-2.queue.amazonaws.com/414704166289/PlanetMoreInfo Sent https://en.wikipedia.org/wiki/Earth to https://us-west-2.queue.amazonaws.com/414704166289/PlanetMoreInfo Sent https://en.wikipedia.org/wiki/Mars to https://us-west-2.queue.amazonaws.com/414704166289/PlanetMoreInfo Sent https://en.wikipedia.org/wiki/Jupiter to https://us-west-2.queue.amazonaws.com/414704166289/PlanetMoreInfo Sent https://en.wikipedia.org/wiki/Saturn to https://us-west-2.queue.amazonaws.com/414704166289/PlanetMoreInfo Sent https://en.wikipedia.org/wiki/Uranus to https://us-west-2.queue.amazonaws.com/414704166289/PlanetMoreInfo Sent https://en.wikipedia.org/wiki/Neptune to https://us-west-2.queue.amazonaws.com/414704166289/PlanetMoreInfo Sent https://en.wikipedia.org/wiki/Pluto to https://us-west-2.queue.amazonaws.com/414704166289/PlanetMoreInfo
```

现在进入 AWS SQS 控制台。您应该看到队列已经被创建，并且它包含 9 条消息：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/2ad3b7c1-9f39-4d02-ac61-d23619a9c409.png)SQS 中的队列

# 工作原理

该代码连接到给定帐户和 AWS 的 us-west-2 地区。然后，如果队列不存在，则创建队列。然后，对于源内容中的每个行星，程序发送一个消息，该消息包含该行星的*更多信息* URL。

此时，没有人在监听队列，因此消息将一直保留在那里，直到最终被读取或它们过期。每条消息的默认生存期为 4 天。

# 如何操作-读取和处理消息

要处理消息，请运行`03/process_messages.py`程序：

```py
import boto3
import botocore
import requests
from bs4 import BeautifulSoup

print("Starting")

# declare our keys (normally, don't hard code this)
access_key = "AKIAIXFTCYO7FEL55TCQ"
access_secret_key = "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"

# create sqs client
sqs = boto3.client('sqs', "us-west-2", 
          aws_access_key_id = access_key, 
          aws_secret_access_key = access_secret_key)

print("Created client")

# create / open the SQS queue
queue = sqs.create_queue(QueueName="PlanetMoreInfo")
queue_url = queue["QueueUrl"]
print ("Opened queue: %s" % queue_url)

while True:
  print ("Attempting to receive messages")
  response = sqs.receive_message(QueueUrl=queue_url,
                 MaxNumberOfMessages=1,
                 WaitTimeSeconds=1)
  if not 'Messages' in response:
    print ("No messages")
    continue

  message = response['Messages'][0]
  receipt_handle = message['ReceiptHandle']
  url = message['Body']

  # parse the page
  html = requests.get(url)
  bsobj = BeautifulSoup(html.text, "lxml")

  # now find the planet name and albedo info
  planet=bsobj.findAll("h1", {"id": "firstHeading"} )[0].text
  albedo_node = bsobj.findAll("a", {"href": "/wiki/Geometric_albedo"})[0]
  root_albedo = albedo_node.parent
  albedo = root_albedo.text.strip()

  # delete the message from the queue
  sqs.delete_message(
    QueueUrl=queue_url,
    ReceiptHandle=receipt_handle
  )

  # print the planets name and albedo info
  print("%s: %s" % (planet, albedo))
```

使用`python process_messages.py`运行脚本。您将看到类似以下的输出：

```py
Starting Created client Opened queue: https://us-west-2.queue.amazonaws.com/414704166289/PlanetMoreInfo Attempting to receive messages Jupiter: 0.343 (Bond) 0.52 (geom.)[3] Attempting to receive messages Mercury (planet): 0.142 (geom.)[10] Attempting to receive messages Uranus: 0.300 (Bond) 0.51 (geom.)[5] Attempting to receive messages Neptune: 0.290 (bond) 0.41 (geom.)[4] Attempting to receive messages Pluto: 0.49 to 0.66 (geometric, varies by 35%)[1][7] Attempting to receive messages Venus: 0.689 (geometric)[2] Attempting to receive messages Earth: 0.367 geometric[3] Attempting to receive messages Mars: 0.170 (geometric)[8] 0.25 (Bond)[7] Attempting to receive messages Saturn: 0.499 (geometric)[4] Attempting to receive messages No messages
```

# 工作原理

程序连接到 SQS 并打开队列。打开队列以进行读取也是使用`sqs.create_queue`完成的，如果队列已经存在，它将简单地返回队列。

然后，它进入一个循环调用`sqs.receive_message`，指定队列的 URL，每次读取消息的数量，以及如果没有消息可用时等待的最长时间（以秒为单位）。

如果读取了一条消息，将检索消息中的 URL，并使用爬取技术读取 URL 的页面并提取行星的名称和有关其反照率的信息。

请注意，我们会检索消息的接收处理。这是删除队列中的消息所必需的。如果我们不删除消息，它将在一段时间后重新出现在队列中。因此，如果我们的爬虫崩溃并且没有执行此确认，消息将由 SQS 再次提供给另一个爬虫进行处理（或者在其恢复正常时由相同的爬虫处理）。

# 还有更多...

您可以在以下网址找到有关 S3 的更多信息：`https://aws.amazon.com/s3/`。有关 API 详细信息的具体内容，请访问：`https://aws.amazon.com/documentation/s3/`。
