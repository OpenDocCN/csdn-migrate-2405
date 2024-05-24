# Learning Scrapy 中文版（二）



# 三、爬虫基础



本章非常重要，你可能需要读几遍，或是从中查找解决问题的方法。我们会从如何安装 Scrapy 讲起，然后在案例中讲解如何编写爬虫。开始之前，说几个注意事项。

因为我们马上要进入有趣的编程部分，使用本书中的代码段会十分重要。当你看到：

```py
$ echo hello world
hello world 
```

是要让你在终端中输入 echo hello world（忽略$），第二行是看到结果。

当你看到：

```py
>>> print 'hi'
hi 
```

是让你在 Python 或 Scrapy 界面进行输入（忽略>>>）。同样的，第二行是输出结果。

你还需要对文件进行编辑。编辑工具取决于你的电脑环境。如果你使用 Vagrant（强烈推荐），你可以是用 Notepad、Notepad++、Sublime Text、TextMate，Eclipse、或 PyCharm 等文本编辑器。如果你更熟悉 Linux/Unix，你可以用控制台自带的 vim 或 emacs。这两个编辑器功能强大，但是有一定的学习曲线。如果你是初学者，可以选择适合初学者的 nano 编辑器。

**安装 Scrapy**

Scrapy 的安装相对简单，但这还取决于读者的电脑环境。为了支持更多的人，本书安装和使用 Scrapy 的方法是用 Vagrant，它可以让你在 Linux 盒中使用所有的工具，而无关于操作系统。下面提供了 Vagrant 和一些常见操作系统的指导。

**MacOS**

为了轻松跟随本书学习，请参照后面的 Vagrant 说明。如果你想在 MacOS 中安装 Scrapy，只需控制台中输入：

```py
$ easy_install scrapy 
```

然后，所有事就可以交给电脑了。安装过程中，可能会向你询问密码或是否安装 Xcode，只需同意即可。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/f2e926516e84fdc690fdd4f8506d02c4.jpg)

**Windows**
在 Windows 中安装 Scrapy 要麻烦些。另外，在 Windows 安装本书中所有的软件也很麻烦。我们都为你想到了可能的问题。有 Virtualbox 的 Vagrant 可以在所有 64 位电脑上顺利运行。翻阅相关章节，只需几分钟就可以安装好。如果真要在 Windows 中安装，请参考本书网站[http://scrapybook.com/](https://link.jianshu.com?t=http://scrapybook.com/)上面的资料。

**Linux**
你可能会在多种 Linux 服务器上安装 Scrapy，步骤如下：

> 提示：确切的安装依赖变化很快。写作本书时，Scrapy 的版本是 1.0.3（翻译此书时是 1.4）。下面只是对不同服务器的建议方法。

**Ubuntu 或 Debian Linux**
为了在 Ubuntu（测试机是 Ubuntu 14.04 Trusty Tahr - 64 bit）或是其它使用 apt 的服务器上安装 Scrapy，可以使用下面三条命令：

```py
$ sudo apt-get update
$ sudo apt-get install python-pip python-lxml python-crypto python-
cssselect python-openssl python-w3lib python-twisted python-dev libxml2-
dev libxslt1-dev zlib1g-dev libffi-dev libssl-dev
$ sudo pip install scrapy 
```

这个方法需要进行编译，可能随时中断，但可以安装 PyPI 上最新版本的 Scrapy。如果想避开编译，安装不是最新版本的话，可以搜索“install Scrapy Ubuntu packages”，按照官方文档安装。

**Red Hat 或 CentOS Linux**
在使用 yum 的 Linux 上安装 Scrapy 也很简单（测试机是 Ubuntu 14.04 Trusty Tahr - 64 bit）。只需三条命令：

```py
sudo yum update
sudo yum -y install libxslt-devel pyOpenSSL python-lxml python-devel gcc
sudo easy_install scrapy 
```

**从 GitHub 安装**
按照前面的指导，就可以安装好 Scrapy 的依赖了。Scrapy 是纯 Python 写成的，如果你想编辑源代码或是测试最新版，可以从[https://github.com/scrapy/scrapy](https://link.jianshu.com?t=https://github.com/scrapy/scrapy)克隆最新版，只需命令行输入：

```py
$ git clonehttps://github.com/scrapy/scrapy.git
$ cd scrapy
$ python setup.py install 
```

我猜如果你是这类用户，就不需要我提醒安装 virtualenv 了。

**升级 Scrapy**
Scrapy 升级相当频繁。如果你需要升级 Scrapy，可以使用 pip、easy_install 或 aptitude：

```py
$ sudo pip install --upgrade Scrapy 
```

或

```py
$ sudo easy_install --upgrade scrapy 
```

如果你想降级或安装指定版本的 Scrapy，可以：

```py
$ sudo pip install Scrapy==1.0.0 
```

或

```py
$ sudo easy_install scrapy==1.0.0 
```

**Vagrant：本书案例的运行方法**
本书有的例子比较复杂，有的例子使用了许多东西。无论你是什么水平，都可以尝试运行所有例子。只需一句命令，就可以用 Vagrant 搭建操作环境。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/eece8269f19454392770d561634bf9ac.jpg)本书使用的系统

在 Vagrant 中，你的电脑被称作“主机”。Vagrant 在主机中创建一个虚拟机。这样就可以让我们忽略主机的软硬件，来运行案例了。

本书大多数章节使用了两个服务——开发机和网络机。我们在开发机中登录运行 Scrapy，在网络机中进行抓取。后面的章节会使用更多的服务，包括数据库和大数据处理引擎。

根据附录 A 安装必备，安装 Vagrant，直到安装好 git 和 Vagrant。打开命令行，输入以下命令获取本书的代码：

```py
$ git clone https://github.com/scalingexcellence/scrapybook.git
$ cd scrapybook 
```

打开 Vagrant：

```py
$ vagrant up --no-parallel 
```

第一次打开 Vagrant 会需要些时间，这取决于你的网络。第二次打开就会比较快。打开之后，登录你的虚拟机，通过：

```py
$ vagrant ssh 
```

代码已经从主机中复制到了开发机，现在可以在 book 的目录中看到：

```py
$ cd book
$ ls
$ ch03 ch04 ch05 ch07 ch08 ch09 ch10 ch11 ... 
```

可以打开几个窗口输入 vagrant ssh，这样就可以打开几个终端。输入 vagrant halt 可以关闭系统，vagrantstatus 可以检查状态。vagrant halt 不能关闭虚拟机。如果在 VirtualBox 中碰到问题，可以手动关闭，或是使用 vagrant global-status 查找 id，用`vagrant halt <ID>`暂停。大多数例子可以离线运行，这是 Vagrant 的一大优点。

安装好环境之后，就可以开始学习 Scrapy 了。

**UR<sup>2</sup>IM——基础抓取过程**
每个网站都是不同的，对每个网站进行额外的研究不可避免，碰到特别生僻的问题，也许还要用 Scrapy 的邮件列表咨询。寻求解答，去哪里找、怎么找，前提是要熟悉整个过程和相关术语。Scrapy 的基本过程，可以写成字母缩略语 UR<sup>2</sup>IM，见下图。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/dd3a65222b6041421aad22a758c3f894.jpg)

**The URL**
一切都从 URL 开始。你需要目标网站的 URL。我的例子是[https://www.gumtree.com/](https://link.jianshu.com?t=https://www.gumtree.com/)，Gumtree 分类网站。

例如，访问伦敦房地产首页[http://www.gumtree.com/flats-houses/london](https://link.jianshu.com?t=http://www.gumtree.com/flats-houses/london)，你就可以找到许多房子的 URL。右键复制链接地址，就可以复制 URL。其中一个 URL 可能是这样的：[https://www.gumtree.com/p/studios-bedsits-rent/split-level](https://link.jianshu.com?t=https://www.gumtree.com/p/studios-bedsits-rent/split-level)。但是，Gumtree 的网站变动之后，URL 的 XPath 表达式会失效。不添加用户头的话，Gumtree 也不会响应。这个留给以后再说，现在如果你想加载一个网页，你可以使用 Scrapy 终端，如下所示：

```py
scrapy shell -s USER_AGENT="Mozilla/5.0" <your url here  e.g. http://www.gumtree.com/p/studios-bedsits-rent/...> 
```

要进行调试，可以在 Scrapy 语句后面添加 –pdb，例如：

```py
scrapy shell --pdb https://gumtree.com 
```

我们不想让大家如此频繁的点击 Gumtree 网站，并且 Gumtree 网站上 URL 失效很快，不适合做例子。我们还希望大家能在离线的情况下，多多练习书中的例子。这就是为什么 Vagrant 开发环境内嵌了一个网络服务器，可以生成和 Gumtree 类似的网页。这些网页可能并不好看，但是从爬虫开发者的角度，是完全合格的。如果想在 Vagrant 上访问 Gumtree，可以在 Vagrant 开发机上访问[http://web:9312/](https://link.jianshu.com?t=http://web:9312/)，或是在浏览器中访问[http://localhost:9312/](https://link.jianshu.com?t=http://localhost:9312/)。

让我们在这个网页上尝试一下 Scrapy，在 Vagrant 开发机上输入：

```py
$ scrapy shell http://web:9312/properties/property_000000.html
...
[s] Available Scrapy objects:
[s]   crawler    <scrapy.crawler.Crawler object at 0x2d4fb10>
[s]   item       {}
[s]   request    <GET http:// web:9312/.../property_000000.html>
[s]   response   <200 http://web:9312/.../property_000000.html>
[s]   settings   <scrapy.settings.Settings object at 0x2d4fa90>
[s]   spider     <DefaultSpider 'default' at 0x3ea0bd0>
[s] Useful shortcuts:
[s]   shelp()           Shell help (print this help)
[s]   fetch(req_or_url) Fetch request (or URL) and update local...
[s]   view(response)    View response in a browser
>>> 
```

得到一些输出，加载页面之后，就进入了 Python（可以使用 Ctrl+D 退出）。

**请求和响应**
在前面的输出日志中，Scrapy 自动为我们做了一些工作。我们输入了一条地址，Scrapy 做了一个 GET 请求，并得到一个成功响应值 200。这说明网页信息已经成功加载，并可以使用了。如果要打印 reponse.body 的前 50 个字母，我们可以得到：

```py
>>> response.body[:50]
'<!DOCTYPE html>\n<html>\n<head>\n<meta charset="UTF-8"' 
```

这就是这个 Gumtree 网页的 HTML 文档。有时请求和响应会很复杂，第 5 章会对其进行讲解，现在只讲最简单的情况。

**抓取对象**
下一步是从响应文件中提取信息，输入到 Item。因为这是个 HTML 文档，我们用 XPath 来做。首先来看一下这个网页：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/c951459d1ce03f93b3da21f5f4151b52.jpg)

页面上的信息很多，但大多是关于版面的：logo、搜索框、按钮等等。从抓取的角度，它们不重要。我们关注的是，例如，列表的标题、地址、电话。它们都对应着 HTML 里的元素，我们要在 HTML 中定位，用上一章所学的提取出来。先从标题开始。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/3fb27959c356a0bda74846fc130e63b0.jpg)

在标题上右键点击，选择检查元素。在自动定位的 HTML 上再次右键点击，选择复制 XPath。Chrome 给的 XPath 总是很复杂，并且容易失效。我们要对其进行简化。我们只取最后面的 h1。这是因为从 SEO 的角度，每页 HTML 只有一个 h1 最好，事实上大多是网页只有一个 h1，所以不用担心重复。

> 提示：SEO 是搜索引擎优化的意思：通过对网页代码、内容、链接的优化，提升对搜索引擎的支持。

让我们看看 h1 标签行不行：

```py
>>> response.xpath('//h1/text()').extract()
[u'set unique family well'] 
```

很好，完全行得通。我在 h1 后面加上了 text()，表示只提取 h1 标签里的文字。没有添加 text()的话，就会这样：

```py
>>> response.xpath('//h1').extract()
[u'<h1 itemprop="name" class="space-mbs">set unique family well</h1>'] 
```

我们已经成功得到了 title，但是再仔细看看，还能发现更简便的方法。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/d61bdc3cd6cb5182af8cf8019178ae15.jpg)

Gumtree 为标签添加了属性，就是 itemprop=name。所以 XPath 可以简化为//*[@itemprop="name"][1]/text()。在 XPath 中，切记数组是从 1 开始的，所以这里[]里面是 1。

选择 itemprop="name"这个属性，是因为 Gumtree 用这个属性命名了许多其他的内容，比如“You may also like”，用数组序号提取会很方便。

接下来看价格。价格在 HTML 中的位置如下：

```py
<strong class="ad-price txt-xlarge txt-emphasis" itemprop="price">£334.39pw</strong> 
```

我们又看到了 itemprop="name"这个属性，XPath 表达式为//*[@itemprop="price"][1]/text()。验证一下：

```py
>>> response.xpath('//*[@itemprop="price"][1]/text()').extract()
[u'\xa3334.39pw'] 
```

注意 Unicode 字符（£符号）和价格 350.00pw。这说明要对数据进行清理。在这个例子中，我们用正则表达式提取数字和小数点。使用正则方法如下：

```py
>>> response.xpath('//*[@itemprop="price"][1]/text()').re('[.0-9]+')
[u'334.39'] 
```

提取房屋描述的文字、房屋的地址也很类似，如下：

```py
//*[@itemprop="description"][1]/text()
//*[@itemtype="http://schema.org/Place"][1]/text() 
```

相似的，抓取图片可以用//img[@itemprop="image"][1]/@src。注意这里没使用 text()，因为我们只想要图片的 URL。

假如这就是我们要提取的所有信息，整理如下：

| 目标 | XPath 表达式 |
| --- | --- |
| title | //*[@itemprop="name"][1]/text()
Example value: [u'set unique family well'] |
| Price | //*[@itemprop="price"][1]/text()
Example value (using re()):[u'334.39'] |
| description | //*[@itemprop="description"][1]/text()
Example value: [u'website court warehouse\r\npool...'] |
| Address | //*[@itemtype="[http://schema.org/Place](https://link.jianshu.com?t=http://schema.org/Place)"][1]/text()
Example value: [u'Angel, London'] |
| Image_URL | //*[@itemprop="image"][1]/@src
Example value: [u'img/i01.jpg'] |

这张表很重要，因为也许只要稍加改变表达式，就可以抓取其他页面。另外，如果要爬取数十个网站时，使用这样的表可以进行区分。

目前为止，使用的还只是 HTML 和 XPath，接下来用 Python 来做一个项目。

**一个 Scrapy 项目**
目前为止，我们只是在 Scrapy shell 中进行操作。学过前面的知识，现在开始一个 Scrapy 项目，Ctrl+D 退出 Scrapy shell。Scrapy shell 只是操作网页、XPath 表达式和 Scrapy 对象的工具，不要在上面浪费太多，因为只要一退出，写过的代码就会消失。我们创建一个名字是 properties 的项目：

```py
$ scrapy startproject properties
$ cd properties
$ tree
.
├── properties
│   ├── __init__.py
│   ├── items.py
│   ├── pipelines.py
│   ├── settings.py
│   └── spiders
│       └── __init__.py
└── scrapy.cfg
2 directories, 6 files 
```

先看看这个 Scrapy 项目的文件目录。文件夹内包含一个同名的文件夹，里面有三个文件 items.py, pipelines.py, 和 settings.py。还有一个子文件夹 spiders，里面现在是空的。后面的章节会详谈 settings、pipelines 和 scrapy.cfg 文件。

**定义 items**
用编辑器打开 items.py。里面已经有代码，我们要对其修改下。用之前的表里的内容重新定义 class PropertiesItem。

还要添加些后面会用到的内容。后面会深入讲解。这里要注意的是，声明一个字段，并不要求一定要填充。所以放心添加你认为需要的字段，后面还可以修改。

| 字段 | Python 表达式 |
| --- | --- |
| images | pipeline 根据 image_URL 会自动填充这里。后面详解。 |
| Location | 地理编码会填充这里。后面详解。 |

我们还会加入一些杂务字段，也许和现在的项目关系不大，但是我个人很感兴趣，以后或许能用到。你可以选择添加或不添加。观察一下这些项目，你就会明白，这些项目是怎么帮助我找到何地（server，url），何时（date），还有（爬虫）如何进行抓取的。它们可以帮助我取消项目，制定新的重复抓取，或忽略爬虫的错误。这里看不明白不要紧，后面会细讲。

| 杂务字段 | Python 表达式 |
| --- | --- |
| url | response.url
Example value: ‘[http://web.../property_000000.html'](https://link.jianshu.com?t=http://web.../property_000000.html') |
| project | self.settings.get('BOT_NAME')
Example value: 'properties' |
| spider | self.name
Example value: 'basic' |
| server | server socket.gethostname()
Example value: 'scrapyserver1' |
| date | datetime.datetime.now()
Example value: datetime.datetime(2015, 6, 25...) |

利用这个表修改 PropertiesItem 这个类。修改文件 properties/items.py 如下：

```py
from scrapy.item import Item, Field

class PropertiesItem(Item):
    # Primary fields
    title = Field()
    price = Field()
    description = Field()
    address = Field()
    image_URL = Field()

# Calculated fields
    images = Field()
    location = Field()

 # Housekeeping fields
    url = Field()
    project = Field()
    spider = Field()
    server = Field()
    date = Field() 
```

这是我们的第一段代码，要注意 Python 中是使用空格缩进的。每个字段名之前都有四个空格或是一个 tab。如果一行有四个空格，另一行有三个空格，就会报语法错误。如果一行是四个空格，另一行是一个 tab，也会报错。空格符指定了这些项目是在 PropertiesItem 下面的。其他语言有的用花括号{}，有的用 begin – end，Python 则使用空格。

**编写爬虫**
已经完成了一半。现在来写爬虫。一般的，每个网站，或一个大网站的一部分，只有一个爬虫。爬虫代码来成 UR<sup>2</sup>IM 流程。

当然，你可以用文本编辑器一句一句写爬虫，但更便捷的方法是用 scrapy genspider 命令，如下所示：

```py
$ scrapy genspider basic web 
```

使用模块中的模板“basic”创建了一个爬虫“basic”：

```py
 properties.spiders.basic 
```

一个爬虫文件 basic.py 就出现在目录 properties/spiders 中。刚才的命令是，生成一个名字是 basic 的默认文件，它的限制是在 web 上爬取 URL。我们可以取消这个限制。这个爬虫使用的是 basic 这个模板。你可以用 scrapy genspider –l 查看所有的模板，然后用参数–t 利用模板生成想要的爬虫，后面会介绍一个例子。

查看 properties/spiders/basic.py file 文件, 它的代码如下：

```py
import scrapy
class BasicSpider(scrapy.Spider):
    name = "basic"
    allowed_domains = ["web"]
start_URL = (
        'http://www.web/',
    )
    def parse(self, response):
        pass 
```

import 命令可以让我们使用 Scrapy 框架。然后定义了一个类 BasicSpider，继承自 scrapy.Spider。继承的意思是，虽然我们没写任何代码，这个类已经继承了 Scrapy 框架中的类 Spider 的许多特性。这允许我们只需写几行代码，就可以有一个功能完整的爬虫。然后我们看到了一些爬虫的参数，比如名字和抓取域字段名。最后，我们定义了一个空函数 parse()，它有两个参数 self 和 response。通过 self，可以使用爬虫一些有趣的功能。response 看起来很熟悉，它就是我们在 Scrapy shell 中见到的响应。

下面来开始编辑这个爬虫。start_URL 更改为在 Scrapy 命令行中使用过的 URL。然后用爬虫事先准备的 log()方法输出内容。修改后的 properties/spiders/basic.py 文件为：

```py
import scrapy
class BasicSpider(scrapy.Spider):
    name = "basic"
    allowed_domains = ["web"]
    start_URL = (
        'http://web:9312/properties/property_000000.html',
    )
    def parse(self, response):
        self.log("title: %s" % response.xpath(
            '//*[@itemprop="name"][1]/text()').extract())
        self.log("price: %s" % response.xpath(
            '//*[@itemprop="price"][1]/text()').re('[.0-9]+'))
        self.log("description: %s" % response.xpath(
        '//*[@itemprop="description"][1]/text()').extract())
        self.log("address: %s" % response.xpath(
            '//*[@itemtype="http://schema.org/'
            'Place"][1]/text()').extract())
        self.log("image_URL: %s" % response.xpath(
            '//*[@itemprop="image"][1]/@src').extract()) 
```

总算到了运行爬虫的时间！让爬虫运行的命令是 scrapy crawl 接上爬虫的名字：

```py
$ scrapy crawl basic
INFO: Scrapy 1.0.3 started (bot: properties)
...
INFO: Spider opened
DEBUG: Crawled (200) <GET http://...000.html>
DEBUG: title: [u'set unique family well']
DEBUG: price: [u'334.39']
DEBUG: description: [u'website...']
DEBUG: address: [u'Angel, London']
DEBUG: image_URL: [u'img/i01.jpg']
INFO: Closing spider (finished)
... 
```

成功了！不要被这么多行的命令吓到，后面我们再仔细说明。现在，我们可以看到使用这个简单的爬虫，所有的数据都用 XPath 得到了。

来看另一个命令，scrapy parse。它可以让我们选择最合适的爬虫来解析 URL。用—spider 命令可以设定爬虫：

```py
$ scrapy parse --spider=basic http://web:9312/properties/property_000001.html 
```

你可以看到输出的结果和前面的很像，但却是关于另一个房产的。

**填充一个项目**
接下来稍稍修改一下前面的代码。你会看到，尽管改动很小，却可以解锁许多新的功能。

首先，引入类 PropertiesItem。它位于 properties 目录中的 item.py 文件，因此在模块 properties.items 中。它的导入命令是：

```py
from properties.items import PropertiesItem 
```

然后我们要实例化，并进行返回。这很简单。在 parse()方法中，我们加入声明 item = PropertiesItem()，它产生了一个新项目，然后为它分配表达式：

```py
item['title'] = response.xpath('//*[@itemprop="name"][1]/text()').extract() 
```

最后，我们用 return item 返回项目。更新后的 properties/spiders/basic.py 文件如下：

```py
import scrapy
from properties.items import PropertiesItem
class BasicSpider(scrapy.Spider):
    name = "basic"
    allowed_domains = ["web"]
    start_URL = (
        'http://web:9312/properties/property_000000.html',
    )
    def parse(self, response):
        item = PropertiesItem()
        item['title'] = response.xpath(
            '//*[@itemprop="name"][1]/text()').extract()
        item['price'] = response.xpath(
            '//*[@itemprop="price"][1]/text()').re('[.0-9]+')
        item['description'] = response.xpath(
            '//*[@itemprop="description"][1]/text()').extract()
        item['address'] = response.xpath(
            '//*[@itemtype="http://schema.org/'
            'Place"][1]/text()').extract()
        item['image_URL'] = response.xpath(
            '//*[@itemprop="image"][1]/@src').extract()
        return item 
```

现在如果再次运行爬虫，你会注意到一个不大但很重要的改动。被抓取的值不再打印出来，没有“DEBUG：被抓取的值”了。你会看到：

```py
DEBUG: Scraped from <200  
http://...000.html>
  {'address': [u'Angel, London'],
   'description': [u'website ... offered'],
   'image_URL': [u'img/i01.jpg'],
   'price': [u'334.39'],
   'title': [u'set unique family well']} 
```

这是从这个页面抓取的 PropertiesItem。这很好，因为 Scrapy 就是围绕 Items 的概念构建的，这意味着我们可以用 pipelines 填充丰富项目，或是用“Feed export”导出保存到不同的格式和位置。

**保存到文件**
试运行下面：

```py
$ scrapy crawl basic -o items.json
$ cat items.json
[{"price": ["334.39"], "address": ["Angel, London"], "description": 
["website court ... offered"], "image_URL": ["img/i01.jpg"], 
"title": ["set unique family well"]}]
$ scrapy crawl basic -o items.jl
$ cat items.jl
{"price": ["334.39"], "address": ["Angel, London"], "description": 
["website court ... offered"], "image_URL": ["img/i01.jpg"], 
"title": ["set unique family well"]}
$ scrapy crawl basic -o items.csv
$ cat items.csv 
description,title,url,price,spider,image_URL...
"...offered",set unique family well,,334.39,,img/i01.jpg
$ scrapy crawl basic -o items.xml
$ cat items.xml 
<?xml version="1.0" encoding="utf-8"?>
<items><item><price><value>334.39</value></price>...</item></items> 
```

不用我们写任何代码，我们就可以用这些格式进行存储。Scrapy 可以自动识别输出文件的后缀名，并进行输出。这段代码中涵盖了一些常用的格式。CSV 和 XML 文件很流行，因为可以被 Excel 直接打开。JSON 文件很流行是因为它的开放性和与 JavaScript 的密切关系。JSON 和 JSON Line 格式的区别是.json 文件是在一个大数组中存储 JSON 对象。这意味着如果你有一个 1GB 的文件，你可能必须现在内存中存储，然后才能传给解析器。相对的，.jl 文件每行都有一个 JSON 对象，所以读取效率更高。

不在文件系统中存储生成的文件也很麻烦。利用下面例子的代码，你可以让 Scrapy 自动上传文件到 FTP 或亚马逊的 S3 bucket。

```py
$ scrapy crawl basic -o "ftp://user:pass@ftp.scrapybook.com/items.json "
$ scrapy crawl basic -o "s3://aws_key:aws_secret@scrapybook/items.json" 
```

注意，证书和 URL 必须按照主机和 S3 更新，才能顺利运行。

另一个要注意的是，如果你现在使用 scrapy parse，它会向你显示被抓取的项目和抓取中新的请求：

```py
$ scrapy parse --spider=basic http://web:9312/properties/property_000001.html
INFO: Scrapy 1.0.3 started (bot: properties)
...
INFO: Spider closed (finished)
>>> STATUS DEPTH LEVEL 1 <<<
# Scraped Items  ------------------------------------------------
[{'address': [u'Plaistow, London'],
  'description': [u'features'],
  'image_URL': [u'img/i02.jpg'],
  'price': [u'388.03'],
  'title': [u'belsize marylebone...deal']}]
# Requests  ------------------------------------------------
[] 
```

当出现意外结果时，scrapy parse 可以帮你进行 debug，你会更感叹它的强大。

**清洗——项目加载器和杂务字段**
恭喜你，你已经创建成功一个简单爬虫了！让我们让它看起来更专业些。

我们使用一个功能类，ItemLoader，以取代看起来杂乱的 extract()和 xpath()。我们的 parse()进行如下变化：

```py
def parse(self, response):
    l = ItemLoader(item=PropertiesItem(), response=response)
    l.add_xpath('title', '//*[@itemprop="name"][1]/text()')
    l.add_xpath('price', './/*[@itemprop="price"]'
           '[1]/text()', re='[,.0-9]+')
    l.add_xpath('description', '//*[@itemprop="description"]'
           '[1]/text()')
    l.add_xpath('address', '//*[@itemtype='
           '"http://schema.org/Place"][1]/text()')
    l.add_xpath('image_URL', '//*[@itemprop="image"][1]/@src')
    return l.load_item() 
```

是不是看起来好多了？事实上，它可不是看起来漂亮那么简单。它指出了我们现在要干什么，并且后面的加载项很清晰。这提高了代码的可维护性和自文档化。（自文档化，self-documenting，是说代码的可读性高，可以像文档文件一样阅读）

ItemLoaders 提供了许多有趣的方式整合数据、格式化数据、清理数据。它的更新很快，查阅文档可以更好的使用它，[http://doc.scrapy.org/en/latest/topics/loaders](https://link.jianshu.com?t=http://doc.scrapy.org/en/latest/topics/loaders)。通过不同的类处理器，ItemLoaders 从 XPath/CSS 表达式传参。处理器函数快速小巧。举一个 Join()的例子。//p 表达式会选取所有段落，这个处理函数可以在一个入口中将所有内容整合起来。另一个函数 MapCompose()，可以与 Python 函数或 Python 函数链结合，实现复杂的功能。例如，MapCompose(float)可以将字符串转化为数字，MapCompose(unicode.strip, unicode.title)可以去除多余的空格，并将单词首字母大写。让我们看几个处理函数的例子：

| 处理函数 | 功能 |
| --- | --- |
| Join() | 合并多个结果。 |
| MapCompose(unicode.strip) | 除去空格。 |
| MapCompose(unicode.strip, unicode.title) | 除去空格，单词首字母大写。 |
| MapCompose(float) | 将字符串转化为数字。 |
| MapCompose(lambda i: i.replace(',', ''), float) | 将字符串转化为数字，逗号替换为空格。 |
| MapCompose(lambda i: urlparse.urljoin(response.url, i)) | 使用 response.url 为开头，将相对 URL 转化为绝对 URL。 |

你可以使用 Python 编写处理函数，或是将它们串联起来。unicode.strip()和 unicode.title()分别用单一参数实现了单一功能。其它函数，如 replace()和 urljoin()需要多个参数，我们可以使用 Lambda 函数。这是一个匿名函数，可以不声明函数就调用参数：

```py
myFunction = lambda i: i.replace(',', '') 
```

可以取代下面的函数：

```py
def myFunction(i):
    return i.replace(',', '') 
```

使用 Lambda 函数，打包 replace()和 urljoin()，生成一个结果，只需一个参数即可。为了更清楚前面的表，来看几个实例。在 scrapy 命令行打开任何 URL，并尝试：

```py
 >>> from scrapy.loader.processors import MapCompose, Join
>>> Join()(['hi','John'])
u'hi John'
>>> MapCompose(unicode.strip)([u'  I',u' am\n'])
[u'I', u'am']
>>> MapCompose(unicode.strip, unicode.title)([u'nIce cODe'])
[u'Nice Code']
>>> MapCompose(float)(['3.14'])
[3.14]
>>> MapCompose(lambda i: i.replace(',', ''), float)(['1,400.23'])
[1400.23]
>>> import urlparse
>>> mc = MapCompose(lambda i: urlparse.urljoin('http://my.com/test/abc', i))
>>> mc(['example.html#check'])
['http://my.com/test/example.html#check']
>>> mc(['http://absolute/url#help'])
['http://absolute/url#help'] 
```

要记住，处理函数是对 XPath/CSS 结果进行后处理的的小巧函数。让我们来看几个我们爬虫中的处理函数是如何清洗结果的：

```py
def parse(self, response):
    l.add_xpath('title', '//*[@itemprop="name"][1]/text()',
                MapCompose(unicode.strip, unicode.title))
    l.add_xpath('price', './/*[@itemprop="price"][1]/text()',
                MapCompose(lambda i: i.replace(',', ''), float),
                re='[,.0-9]+')
    l.add_xpath('description', '//*[@itemprop="description"]'
                '[1]/text()', MapCompose(unicode.strip), Join())
    l.add_xpath('address',
               '//*[@itemtype="http://schema.org/Place"][1]/text()',
                MapCompose(unicode.strip))
    l.add_xpath('image_URL', '//*[@itemprop="image"][1]/@src',
                MapCompose(
                lambda i: urlparse.urljoin(response.url, i))) 
```

完整的列表在本章后面给出。如果你用 scrapy crawl basic 再运行的话，你可以得到干净的结果如下：

```py
'price': [334.39],
'title': [u'Set Unique Family Well'] 
```

最后，我们可以用 add_value()方法添加用 Python（不用 XPath/CSS 表达式）计算得到的值。我们用它设置我们的“杂务字段”，例如 URL、爬虫名、时间戳等等。我们直接使用前面杂务字段表里总结的表达式，如下：

```py
l.add_value('url', response.url)
l.add_value('project', self.settings.get('BOT_NAME'))
l.add_value('spider', self.name)
l.add_value('server', socket.gethostname())
l.add_value('date', datetime.datetime.now()) 
```

记得 import datetime 和 socket，以使用这些功能。

现在，我们的 Items 看起来就完美了。我知道你的第一感觉是，这可能太复杂了，值得吗？回答是肯定的，这是因为或多或少，想抓取网页信息并存到 items 里，这就是你要知道的全部。这段代码如果用其他语言来写，会非常难看，很快就不能维护了。用 Scrapy，只要 25 行简洁的代码，它明确指明了意图，你可以看清每行的意义，可以清晰的进行修改、再利用和维护。

你的另一个感觉可能是处理函数和 ItemLoaders 太花费精力。如果你是一名经验丰富的 Python 开发者，你已经会使用字符串操作、lambda 表达构造列表，再学习新的知识会觉得不舒服。然而，这只是对 ItemLoader 和其功能的简单介绍，如果你再深入学习一点，你就不会这么想了。ItemLoaders 和处理函数是专为有抓取需求的爬虫编写者、维护者开发的工具集。如果你想深入学习爬虫的话，它们是绝对值得学习的。

**创建协议**
协议有点像爬虫的单元测试。它们能让你快速知道错误。例如，假设你几周以前写了一个抓取器，它包含几个爬虫。你想快速检测今天是否还是正确的。协议位于评论中，就在函数名后面，协议的开头是@。看下面这个协议：

```py
def parse(self, response):
    """ This function parses a property page.
    @url http://web:9312/properties/property_000000.html
    @returns items 1
    @scrapes title price description address image_URL
    @scrapes url project spider server date
    """ 
```

这段代码是说，检查这个 URL，你可以在找到一个项目，它在那些字段有值。现在如果你运行 scrapy check，它会检查协议是否被满足：

```py
$ scrapy check basic
----------------------------------------------------------------
Ran 3 contracts in 1.640s
OK
如果 url 的字段是空的（被注释掉），你会得到一个描述性错误：
FAIL: [basic] parse (@scrapes post-hook)
------------------------------------------------------------------
ContractFail: 'url' field is missing 
```

当爬虫代码有错，或是 XPath 表达式过期，协议就可能失效。当然，协议不会特别详细，但是可以清楚的指出代码的错误所在。

综上所述，我们的第一个爬虫如下所示：

```py
from scrapy.loader.processors import MapCompose, Join
from scrapy.loader import ItemLoader
from properties.items import PropertiesItem
import datetime
import urlparse
import socket
import scrapy

class BasicSpider(scrapy.Spider):
    name = "basic"
    allowed_domains = ["web"]
    # Start on a property page
    start_URL = (
        'http://web:9312/properties/property_000000.html',
    )
    def parse(self, response):
        """ This function parses a property page.
        @url http://web:9312/properties/property_000000.html
        @returns items 1
        @scrapes title price description address image_URL
        @scrapes url project spider server date
        """
        # Create the loader using the response
        l = ItemLoader(item=PropertiesItem(), response=response)
        # Load fields using XPath expressions
        l.add_xpath('title', '//*[@itemprop="name"][1]/text()',
                    MapCompose(unicode.strip, unicode.title))
        l.add_xpath('price', './/*[@itemprop="price"][1]/text()',
                    MapCompose(lambda i: i.replace(',', ''),  
                    float),
                    re='[,.0-9]+')
        l.add_xpath('description', '//*[@itemprop="description"]'
                    '[1]/text()',
                    MapCompose(unicode.strip), Join())
        l.add_xpath('address',
                    '//*[@itemtype="http://schema.org/Place"]'
                    '[1]/text()',
                    MapCompose(unicode.strip))
        l.add_xpath('image_URL', '//*[@itemprop="image"]'
                    '[1]/@src', MapCompose(
                    lambda i: urlparse.urljoin(response.url, i)))
        # Housekeeping fields
        l.add_value('url', response.url)
        l.add_value('project', self.settings.get('BOT_NAME'))
        l.add_value('spider', self.name)
        l.add_value('server', socket.gethostname())
        l.add_value('date', datetime.datetime.now())
        return l.load_item() 
```

**提取更多的 URL**
到目前为止，在爬虫的 start_URL 中我们还是只加入了一条 URL。因为这是一个元组，我们可以向里面加入多个 URL，例如：

```py
start_URL = (
    'http://web:9312/properties/property_000000.html',
    'http://web:9312/properties/property_000001.html',
    'http://web:9312/properties/property_000002.html',
) 
```

不够好。我们可以用一个文件当做 URL 源文件：

```py
start_URL = [i.strip() for i in  
open('todo.URL.txt').readlines()] 
```

还是不够好，但行得通。更常见的，网站可能既有索引页也有列表页。例如，Gumtree 有索引页：[http://www.gumtree.com/flats-houses/london](https://link.jianshu.com?t=http://www.gumtree.com/flats-houses/london)：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/3042ffa57ba01da1ac876568bb9105a5.jpg)

一个典型的索引页包含许多列表页、一个分页系统，让你可以跳转到其它页面。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/ceca54f573034c4b91b841c74ebae33a.jpg)

因此，一个典型的爬虫在两个方向移动：

*   水平——从索引页到另一个索引页
*   垂直——从索引页面到列表页面提取项目

在本书中，我们称前者为水平抓取，因为它在同一层次（例如索引）上抓取页面；后者为垂直抓取，因为它从更高层次（例如索引）移动到一个较低的层次（例如列表）。

做起来要容易许多。我们只需要两个 XPath 表达式。第一个，我们右键点击 Next page 按钮，URL 位于 li 中，li 的类名含有 next。因此 XPath 表达式为//*[contains(@class,"next")]//@href。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/2b7a69c561da7bf153a3236ce53de008.jpg)

对于第二个表达式，我们在列表的标题上右键点击，选择检查元素：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/e3faf54a07915a60f1ddd3bcceeaf5b5.jpg)

这个 URL 有一个属性是 itemprop="url。因此，表达式确定为//*[@itemprop="url"]/@href。打开 scrapy 命令行进行确认：

```py
$ scrapy shell http://web:9312/properties/index_00000.html
>>> URL = response.xpath('//*[contains(@class,"next")]//@href').extract()
>>> URL
[u'index_00001.html']
>>> import urlparse
>>> [urlparse.urljoin(response.url, i) for i in URL]
[u'http://web:9312/scrapybook/properties/index_00001.html']
>>> URL = response.xpath('//*[@itemprop="url"]/@href').extract()
>>> URL
[u'property_000000.html', ... u'property_000029.html']
>>> len(URL)
30
>>> [urlparse.urljoin(response.url, i) for i in URL]
[u'http://..._000000.html', ... /property_000029.html'] 
```

很好，我们看到有了这两个表达式，就可以进行水平和垂直抓取 URL 了。

**使用爬虫进行二维抓取**
将前一个爬虫代码复制到新的爬虫 manual.py 中：

```py
$ ls
properties  scrapy.cfg
$ cp properties/spiders/basic.py properties/spiders/manual.py 
```

在 properties/spiders/manual.py 中，我们通过添加 from scrapy.http import Request 引入 Request，将爬虫的名字改为 manual，将 start_URL 改为索引首页，将 parse()重命名为 parse_item()。接下来写心得 parse()方法进行水平和垂直的抓取：

```py
def parse(self, response):
    # Get the next index URL and yield Requests
    next_selector = response.xpath('//*[contains(@class,'
                                   '"next")]//@href')
    for url in next_selector.extract():
        yield Request(urlparse.urljoin(response.url, url))

    # Get item URL and yield Requests
    item_selector = response.xpath('//*[@itemprop="url"]/@href')
    for url in item_selector.extract():
        yield Request(urlparse.urljoin(response.url, url),
                      callback=self.parse_item) 
```

> 提示：你可能注意到了 yield 声明。它和 return 很像，不同之处是 return 会退出循环，而 yield 不会。从功能上讲，前面的例子与下面很像
> 
> ```py
> next_requests = []
> for url in...
>    next_requests.append(Request(...))
> for url in...
>    next_requests.append(Request(...))
> return next_requests 
> ```
> 
> yield 可以大大提高 Python 编程的效率。

做好爬虫了。但如果让它运行起来的话，它将抓取 5 万张页面。为了避免时间太长，我们可以通过命令-s CLOSESPIDER_ITEMCOUNT=90（更多的设定见第 7 章），设定爬虫在一定数量（例如，90）之后停止运行。开始运行：

```py
$ scrapy crawl manual -s CLOSESPIDER_ITEMCOUNT=90
INFO: Scrapy 1.0.3 started (bot: properties)
...
DEBUG: Crawled (200) <...index_00000.html> (referer: None)
DEBUG: Crawled (200) <...property_000029.html> (referer: ...index_00000.html)
DEBUG: Scraped from <200 ...property_000029.html>
  {'address': [u'Clapham, London'],
   'date': [datetime.datetime(2015, 10, 4, 21, 25, 22, 801098)],
   'description': [u'situated camden facilities corner'],
   'image_URL': [u'http://web:93img/i10.jpg'],
   'price': [223.88],
   'project': ['properties'],
  'server': ['scrapyserver1'],
   'spider': ['manual'],
   'title': [u'Portered Mile'],
   'url': ['http://.../property_000029.html']}
DEBUG: Crawled (200) <...property_000028.html> (referer: ...index_00000.
html)
...
DEBUG: Crawled (200) <...index_00001.html> (referer: ...)
DEBUG: Crawled (200) <...property_000059.html> (referer: ...)
...
INFO: Dumping Scrapy stats: ...
   'downloader/request_count': 94, ...
   'item_scraped_count': 90, 
```

查看输出，你可以看到我们得到了水平和垂直两个方向的结果。首先读取了 index_00000.html, 然后产生了许多请求。执行请求的过程中，debug 信息指明了谁用 URL 发起了请求。例如，我们看到，property_000029.html, property_000028.html ... 和 index_00001.html 都有相同的 referer(即 index_00000.html)。然后，property_000059.html 和其它网页的 referer 是 index_00001，过程以此类推。

这个例子中，Scrapy 处理请求的机制是后进先出（LIFO），深度优先抓取。最后提交的请求先被执行。这个机制适用于大多数情况。例如，我们想先抓取完列表页再取下一个索引页。不然的话，我们必须消耗内存存储列表页的 URL。另外，许多时候你想用一个辅助的 Requests 执行一个请求，下一章有例子。你需要 Requests 越早完成越好，以便爬虫继续下面的工作。

我们可以通过设定 Request()参数修改默认的顺序，大于 0 时是高于默认的优先级，小于 0 时是低于默认的优先级。通常，Scrapy 会先执行高优先级的请求，但不会花费太多时间思考到底先执行哪一个具体的请求。在你的大多数爬虫中，你不会有超过一个或两个的请求等级。因为 URL 会被多重过滤，如果我们想向一个 URL 多次请求，我们可以设定参数 dont_filter Request()为 True。

**用 CrawlSpider 二维抓取**
如果你觉得这个二维抓取单调的话，说明你入门了。Scrapy 试图简化这些琐事，让编程更容易。完成之前结果的更好方法是使用 CrawlSpider，一个简化抓取的类。我们用 genspider 命令，设定一个-t 参数，用爬虫模板创建一个爬虫：

```py
$ scrapy genspider -t crawl easy web
Created spider 'crawl' using template 'crawl' in module:
  properties.spiders.easy 
```

现在 properties/spiders/easy.py 文件包含如下所示：

```py
...
class EasySpider(CrawlSpider):
    name = 'easy'
    allowed_domains = ['web']
    start_URL = ['http://www.web/']
    rules = (
        Rule(LinkExtractor(allow=r'Items/'),  
callback='parse_item', follow=True),
    )
    def parse_item(self, response):
        ... 
```

这段自动生成的代码和之前的很像，但是在类的定义中，这个爬虫从 CrawlSpider 定义的，而不是 Spider。CrawlSpider 提供了一个包含变量 rules 的 parse()方法，以完成之前我们手写的内容。

现在将 start_URL 设定为索引首页，并将 parse_item()方法替换。这次不再使用 parse()方法，而是将 rules 变成两个 rules，一个负责水平抓取，一个负责垂直抓取：

```py
rules = (
Rule(LinkExtractor(restrict_xpaths='//*[contains(@class,"next")]')),
Rule(LinkExtractor(restrict_xpaths='//*[@itemprop="url"]'),
         callback='parse_item')
) 
```

两个 XPath 表达式与之前相同，但没有了 a 与 href 的限制。正如它们的名字，LinkExtractor 专门抽取链接，默认就是寻找 a、href 属性。你可以设定 tags 和 attrs 自定义 LinkExtractor()。对比前面的请求方法 Requests(self.parse_item)，回调的字符串中含有回调方法的名字（例如，parse_item）。最后，除非设定 callback，一个 Rule 就会沿着抽取的 URL 扫描外链。设定 callback 之后，Rule 才能返回。如果你想让 Rule 跟随外链，你应该从 callback 方法 return/yield，或设定 Rule()的 follow 参数为 True。当你的列表页既有 Items 又有其它有用的导航链接时非常有用。

你现在可以运行这个爬虫，它的结果与之前相同，但简洁多了：

```py
$ scrapy crawl easy -s CLOSESPIDER_ITEMCOUNT=90 
```

**总结**
对所有学习 Scrapy 的人，本章也许是最重要的。你学习了爬虫的基本流程 UR<sup>2</sup>IM、如何自定义 Items、使用 ItemLoaders，XPath 表达式、利用处理函数加载 Items、如何 yield 请求。我们使用 Requests 水平抓取多个索引页、垂直抓取列表页。最后，我们学习了如何使用 CrawlSpider 和 Rules 简化代码。多度几遍本章以加深理解、创建自己的爬虫。

我们刚刚从一个网站提取了信息。它的重要性在哪呢？答案在下一章，我们只用几页就能制作一个移动 app，并用 Scrapy 填充数据。



# 四、从 Scrapy 到移动应用



有人问，移动 app 开发平台 Appery.io 和 Scrapy 有什么关系？眼见为实。在几年前，用 Excel 向别人展示数据才可以让人印象深刻。现在，除非你的受众分布很窄，他们彼此之间是非常不同的。接下来几页，你会看到一个快速构建的移动应用，一个最小可行产品。它可以向别人清楚的展示你抓取的数据的力量，为源网站搭建的生态系统带来回报。

我尽量让这个挖掘数据价值的例子简短。要是你自己就有一个使用数据的应用，你可以跳过本章。本章就是告诉你如何用现在最流行的方式，移动应用，让你的数据面向公众。

## 选择移动应用框架

使用适当的工具向移动应用导入数据是相当容易的。跨平台开发移动应用的框架很多，例如 PhoneGap、Appcelerator 和 Appcelerator 云服务、jQuery Mobile 和 Sencha Touch。

本章会使用 Appery.io，因为它可以让我们用 PhoneGap 和 jQuery Mobile 快速开发 iOS、Android、Windows Phone、HTML5 移动应用。我并不是要为 Appery.io 代言，我鼓励你自己去调研下它是否符合你的需求。Appery.io 是一个付费服务，但有 14 天的试用期。在我看来，即使是外行也可以用 Appery.io 快速创建一个应用。我选择它的原因是，它提供了移动和后端两个服务，所以我们不用配置数据库、写 REST APIs、或在服务器和移动端使用不同的语言。你将看到，我们根本不用写任何代码！我们会使用它的在线工具，你可以随时下载 app 作为 PhoneGap 项目，使用 PhoneGap 的全部特性。

使用 Appery.io，你需要连接网络。另外，因为它的网站可能会发生改变，如果和截图不同不要惊讶。

## 创建数据库和集合

第一步是注册 Appery.io，并选择试用。提供名字、Emai 密码之后，你的账户就创立了。登录 Appery.io 工作台，你就可以创建数据库和集合了：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/dd35728df5c30839b5964b6480646d56.jpg)

步骤如下：
1.点击 Databases 标签（1）。
2.然后点击绿色的 Create new database 按钮（2）。将新数据库命名为 scrapy（3）。
3.现在点击 Create 按钮（4）。自动打开 Scrapy 数据库工作台，在工作台上可以新建集合。

在 Appery.io 中，数据库是集合的整合。粗略的讲，一个应用使用一个数据库，这个数据库中有许多集合，例如用户、特性、信息等等。Appery.io 已经有了一个 Users 集合，用来存储用户名和密码（Appery.io 有许多内建的功能）。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/88723d286743d8da22778952f9627116.jpg)

让我们添加一个用户，用户名是 root，密码是 pass。显然，密码可以更复杂。在侧边栏点击 Users（1），然后点击+Row（2）添加 user/row。在弹出的界面中输入用户名和密码（3,4）。

再为 Scrapy 抓取的数据创建一个集合，命名为 properties。点击 Create new collection 绿色按钮（5），命名为 properties（6），点击 Add 按钮（7）。现在，我们需要自定义这个集合。点击+Col 添加列（8）。列有一些数据类型可以帮助确认值。大多数要填入的是字符串，除了价格是个数字。点击+Col（8）再添加几列，填入列的名字（9）、数据类型（10），然后点击 Create column 按钮（11）。重复五次这个步骤以创建下表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/df5b20e3354f1bb80dabbb039b564d3c.jpg)

创建好所有列之后，就可以导入数据了。

## **用 Scrapy 导入数据**

首先，我们需要 API key，在 Settings 中可以找到（1）。复制它（2），然后点击 Collections 标签返回集合（3）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/222e2c24a552ecd5d1761aa5e39d8f32.jpg)

现在，修改一下上一章的代码，以导入数据。我们把名字是 easy.py 的爬虫中的代码复制到名字是 tomobile.py 的爬虫中：

```py
$ ls
properties  scrapy.cfg
$ cat properties/spiders/tomobile.py
...
class ToMobileSpider(CrawlSpider):
    name = 'tomobile'
    allowed_domains = ["scrapybook.s3.amazonaws.com"]
    # Start on the first index page
    start_URL = (
        'http://scrapybook.s3.amazonaws.com/properties/'
        'index_00000.html',
    )
... 
```

你可能注意到了，我们没有使用网络服务器[http://web:9312](https://link.jianshu.com?t=http://web:9312)。我们用的是我托管在[http://scrapybook.s3.amazonaws.com](https://link.jianshu.com?t=http://scrapybook.s3.amazonaws.com)上的副本。使用它，我们的图片和 URL 所有人都可以访问，更易分享我们的 app。

我们使用 Appery.io pipline 导入数据。Scrapy 的 pipelines 是后处理的、简洁的、可以存储 items 的很小的 Python 类。第 8 章中会详细讲解两者。现在，你可以用 easy_install 或 pip 安装，但如果你用 Vagrant 开发机，因为已经都安装好了，你就不用再安装了：

```py
$ sudo easy_install -U scrapyapperyio 
```

或

```py
$ sudo pip install --upgrade scrapyapperyio 
```

这时，要在 Scrapy 的设置文件中添加 API key。更多关于设置的内容会在第 7 章中介绍。现在，我们只需在在 properties/settings.py 文件后面加入如下代码：

```py
ITEM_PIPELINES = {'scrapyapperyio.ApperyIoPipeline': 300}
APPERYIO_DB_ID = '<<Your API KEY here>>'
APPERYIO_USERNAME = 'root'
APPERYIO_PASSWORD = 'pass'
APPERYIO_COLLECTION_NAME = 'properties' 
```

别忘了将 APPERYIO_DB_ID 替换为 API key。还要确认你的设置有和 Appery.io 相同的用户名和密码。要进行向 Appery.io 注入数据，像之前一样用 Scrapy 抓取：

```py
$ scrapy crawl tomobile -s CLOSESPIDER_ITEMCOUNT=90
INFO: Scrapy 1.0.3 started (bot: properties)
...
INFO: Enabled item pipelines: ApperyIoPipeline
INFO: Spider opened
...
DEBUG: Crawled (200) <GET https://api.appery.io/rest/1/db/login?username=
root&password=pass>
...
DEBUG: Crawled (200) <POST https://api.appery.io/rest/1/db/collections/
properties>
...
INFO: Dumping Scrapy stats:
  {'downloader/response_count': 215,
   'item_scraped_count': 105,
  ...}
INFO: Spider closed (closespider_itemcount) 
```

输出的结果略有不用。你可以看到代码的前几行运行了 ApperyIoPipeline 的项目 pipeline；更显著的是，大概抓取了 100 个项目，有约 200 个请求/响应。这是因为 Appery.io pipeline 为写入每个项目，都额外的做了一次请求。这些请求也出现在日志中，带有 api.appery.io URL。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/93089add234f6c1753131ee13471cddd.jpg)

如果返回 Appery.io，我们可以 properties 集合（1）中填入了数据（2）。

## **创建移动应用**

创建移动应用有点繁琐。点击 Apps 标签（1），然后点击 Create new app（2）。将这个应用命名为 properties（3），再点击 Create 按钮（4）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/bcd58ae841c995c210286fa275d62b53.jpg)

## **创建数据库接入服务**

创建应用的选项很多。使用 Appery.io 应用编辑器可以编写复杂应用，但我们的应用力求简单。让我们的应用连接 Scrapy 数据库，点击 CREATE NEW 按钮（5），选择 Datebase Services（6）。弹出一个界面让我们选择连接的对象。我们选择 scrapy 数据库（7）。点击 properties 栏（8），选择 List（9）。这些操作可以让我们爬到的数据可用于数据库。最后点击 Import selected services 完成导入（10）。

设定用户界面
接下来创建 app 的界面。我们在 DESIGN 标签下工作：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/75388e78de96f31deddfc27db408549d.jpg)

在左侧栏中点开 Pages 文件夹（1），然后点击 startScreen（2）。UI 编辑器会打开一个页面，我们在上面添加空间。先修改标题。点击标题栏，在右侧的属性栏修改标题为 Scrapy App。同时，标题栏会更新。

然后，我们添加格栅组件。从左侧的控制板中拖动 Grid 组件（5）。这个组件有两行，而我们只要一行。选择这个格栅组件，选中的时候，它在路径中会变为灰色（6）。选中之后，在右侧的属性栏中编辑 Rows 为 1，然后点击 Apply（7,8）。现在，格栅就只有一行了。

最后，再向格栅中拖进一些组件。先在左边添加一个图片组件（9），然后在右侧添加一个链接（10）。最后，在链接下添加一个标签（11）。

排版结束。接下来将数据从数据库导入用户界面。

## **将数据映射到用户界面**

截止目前，我们只是在 DESIGN 标签下设置界面。为了连接数据和组件，我们切换到 DATA 标签（1）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/032006684c490d89771621b3a77ebf1e.jpg)

我们用 Service（2）作为数据源类型，它会自动选择我们之前建立的唯一可用数据。点击 Add 按钮（3）。点击 Add 之后，可以在下方看到一系列事件，例如 Before send 和 Success。点击 Success 后面的 Mapping 可以调用服务，我们现在对它进行设置。

打开 Mapping action editor，在上面进行连线。编辑器有两个部分。左边是服务的可用响应，右边是 UI 组件的属性。两边都有一个 Expand all，展开所有的项，以查看可用的。接下来按照下表，用从左到右拖动的方式完成五个映射（5）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/77f3dcef9e592fe114c63cb31f1d2cc4.jpg)

## **映射数据字段和用户组件**

前面列表中的数字可能在你的例子中是不同的，但是因为每种组件的类型都是唯一的，所以连线出错的可能性很小。通过映射，我们告诉 Appery.io 当数据库查询成功时载入数据。然后点击 Save and return（6）。

返回 DATA 标签。我们需要返回 UI 编辑器，点击 DESIGN 标签（7）。屏幕下方，你会看到 EVENTS 区域（8）被展开了。利用 EVENTS，我们让 Appery.io 响应 UI 时间。下面是最后一步，就是加载 UI 时调用服务取回数据。我们打开 startScreen 作为组件，事件的默认选项是 Load。然后选择 Invoke service 作为 action，然后用 Datasource 作为默认的 restservice1 选项（9）。点击 Save（10），保存这个移动应用。

## **测试、分享、生成 app**

现在准备测试 app。我们要做的是点击 UI 上方的 TEST 按钮（1）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/b16a0ca08503e2cbd489f942efd9d6e3.jpg)

这个应用直接在浏览器中运行。链接（2）是启动的，可以进行跳转。你可以设置分辨率和屏幕的横竖。你还可以点击 View on Phone，创建一个二维码，用手机扫描，然后在手机上看。你刚刚创建了一个链接，别人也可以在他们的浏览器中查看。

只需几次点击，我们就用一个移动应用展示了 Scrapy 抓取的数据。你可以在这个网页，[http://devcenter.appery.io/tutorials/](https://link.jianshu.com?t=http://devcenter.appery.io/tutorials/)学习[Appery.io](https://link.jianshu.com?t=http://Appery.io)教程，继续定制这个应用。当你准备好之后，可以点击 EXPORT 按钮输出这个 app：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/3d622f80c7a4867b75735175b5b1cc6e.jpg)

你可以输出文档到你喜爱的 IDE 继续开发，或是生成在各个平台都能运行的 app。

## **总结**

使用 Scrapy 和 Appery.io 两个工具，我们创建了一个爬虫、抓取了一个网站，并将数据存到数据库之中。我们还创建了 RESTful API 和一个简单的移动端应用。对于更高级的特点和进一步开发，你可以进一步探究这个平台，或将这个应用用于实际或科研。现在，用最少的代码，你就可以用一个小产品展示网络抓取的应用了。

鉴于这么短的开发时间，我们的 app 就有不错的效果。它有真实的数据，而不是 Lorem Ipsum 占字符，所有的链接运行良好。我们成功地制作了一个最小可行产品，它可以融合进源网站的生态，提高流量。

接下来学习在更加复杂的情况下，如何使用 Scrapy 爬虫提取信息。



# 五、快速构建爬虫



第 3 章中，我们学习了如何从网页提取信息并存储到 Items 中。大多数情况都可以用这一章的知识处理。本章，我们要进一步学习抓取流程 UR<sup>2</sup>IM 中两个 R，Request 和 Response。

## **一个具有登录功能的爬虫**

你常常需要从具有登录机制的网站抓取数据。多数时候，网站要你提供用户名和密码才能登录。我们的例子，你可以在[http://web:9312/dynamic](https://link.jianshu.com?t=http://web:9312/dynamic)或[http://localhost:9312/dynamic](https://link.jianshu.com?t=http://localhost:9312/dynamic)找到。用用户名“user”、密码“pass”登录之后，你会进入一个有三条房产链接的网页。现在的问题是，如何用 Scrapy 登录？

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/1ea173b84998e877daf15d3c48b61a8e.jpg)

让我们使用谷歌 Chrome 浏览器的开发者工具搞清楚登录的机制。首先，选择 Network 标签（1）。然后，填入用户名和密码，点击 Login（2）。如果用户名和密码是正确的，你会进入下一页。如果是错误的，会看到一个错误页。

一旦你点击了 Login，在开发者工具的 Network 标签栏中，你就会看到一个发往[http://localhost:9312/dynamic/login](https://link.jianshu.com?t=http://localhost:9312/dynamic/login)的请求 Request Method: POST。

> 提示：上一章的 GET 请求，通常用来获取静止数据，例如简单的网页和图片。POST 请求通常用来获取的数据，取决于我们发给服务器的数据，例如这个例子中的用户名和密码。

点击这个 POST 请求，你就可以看到发给服务器的数据，其中包括表单信息，表单信息中有你刚才输入的用户名和密码。所有数据都以文本的形式发给服务器。Chrome 开发者工具将它们整理好并展示出来。服务器的响应是 302 FOUND（5），然后将我们重定向到新页面：/dynamic/gated。只有登录成功时才会出现此页面。如果没有正确输入用户名和密码就前往[http://localhost:9312/dynamic/gated](https://link.jianshu.com?t=http://localhost:9312/dynamic/gated)，服务器会发现你作弊，并将你重定向到错误页面：[http://localhost:9312/dynamic/error](https://link.jianshu.com?t=http://localhost:9312/dynamic/error)。服务器怎么知道你和密码呢？如果你点击左侧的 gated（6），你会发现在 RequestHeaders（7）下有一个 Cookie（8）。

> 提示：HTTP cookie 是通常是一些服务器发送到浏览器的短文本或数字片段。反过来，在每一个后续请求中，浏览器把它发送回服务器，以确定你、用户和期限。这让你可以执行复杂的需要服务器端状态信息的操作，如你购物车中的商品或你的用户名和密码。

总结一下，单单一个操作，如登录，可能涉及多个服务器往返操作，包括 POST 请求和 HTTP 重定向。Scrapy 处理大多数这些操作是自动的，我们需要编写的代码很简单。
我们将第 3 章名为 easy 的爬虫重命名为 login，并修改里面名字的属性，如下：

```py
class LoginSpider(CrawlSpider):
    name = 'login' 
```

> 提示：本章的代码 github 的 ch05 目录中。这个例子位于 ch05/properties。

我们要在[http://localhost:9312/dynamic/login](https://link.jianshu.com?t=http://localhost:9312/dynamic/login)上面模拟一个 POST 请求登录。我们用 Scrapy 中的类 FormRequest 来做。这个类和第 3 章中的 Request 很像，但有一个额外的 formdata，用来传递参数。要使用这个类，首先必须要引入：

```py
from scrapy.http import FormRequest 
```

我们然后将 start_URL 替换为 start_requests()方法。这么做是因为在本例中，比起 URL，我们要做一些自定义的工作。更具体地，用下面的函数，我们创建并返回一个 FormRequest：

```py
# Start with a login request
def start_requests(self):
  return [
    FormRequest(
      "http://web:9312/dynamic/login",
      formdata={"user": "user", "pass": "pass"}
         )] 
```

就是这样。CrawlSpider 的默认 parse()方法，即 LoginSpider 的基本类，负责处理响应，并如第 3 章中使用 Rules 和 LinkExtractors。其余的代码很少，因为 Scrapy 负责了 cookies，当我们登录时，Scrapy 将 cookies 传递给后续请求，与浏览器的方式相同。还是用 scrapy crawl 运行：

```py
$ scrapy crawl login 
INFO: Scrapy 1.0.3 started (bot: properties)
...
DEBUG: Redirecting (302) to <GET .../gated> from <POST .../login >
DEBUG: Crawled (200) <GET .../data.php>
DEBUG: Crawled (200) <GET .../property_000001.html> (referer: .../data.
php)
DEBUG: Scraped from <200 .../property_000001.html>
  {'address': [u'Plaistow, London'],
   'date': [datetime.datetime(2015, 11, 25, 12, 7, 27, 120119)],
   'description': [u'features'],
   'image_URL': [u'http://web:93img/i02.jpg'],
...
INFO: Closing spider (finished)
INFO: Dumping Scrapy stats:
  {...
   'downloader/request_method_count/GET': 4,
   'downloader/request_method_count/POST': 1,
...
   'item_scraped_count': 3, 
```

我们注意到登录跳转从 dynamic/login 到 dynamic/gated，然后就可以像之前一样抓取项目。在统计中，我们看到一个 POST 请求和四个 GET 请求；一个是 dynamic/gated 首页，三个是房产网页。

> 提示：在本例中，我们不保护房产页，而是是这些网页的链接。代码在相反的情况下也是相同的。

如果我们使用了错误的用户名和密码，我们将重定向到一个没有 URL 的页面，进程并将在这里结束，如下所示：

```py
$ scrapy crawl login
INFO: Scrapy 1.0.3 started (bot: properties)
...
DEBUG: Redirecting (302) to <GET .../dynamic/error > from <POST .../
dynamic/login>
DEBUG: Crawled (200) <GET .../dynamic/error>
...
INFO: Spider closed (closespider_itemcount) 
```

这是一个简单的登录示例，演示了基本的登录机制。大多数网站可能有更复杂的机制，但 Scrapy 也处理的很好。例如一些网站在执行 POST 请求时，需要通过从表单页面到登录页面传递某种形式的变量以确定 cookies 的启用，让你使用大量用户名和密码暴力破解时变得困难。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/a518f94ae0a84e3c9e90c3d1f69d720a.jpg)

例如，如果你访问[http://localhost:9312/dynamic/nonce](https://link.jianshu.com?t=http://localhost:9312/dynamic/nonce)，你会看到一个和之前一样的网页，但如果你使用 Chrome 开发者工具，你会发现这个页面的表单有一个叫做 nonce 的隐藏字段。当你提交表单[http://localhost:9312/dynamic/nonce-login](https://link.jianshu.com?t=http://localhost:9312/dynamic/nonce-login)时，你必须既要提供正确的用户名密码，还要提交正确的浏览器发给你的 nonce 值。因为这个值是随机且只能使用一次，你很难猜到。这意味着，如果要成功登陆，必须要进行两次请求。你必须访问表单、登录页，然后传递数值。和以前一样，Scrapy 有内建的功能可以解决这个问题。

我们创建一个和之前相似的 NonceLoginSpider 爬虫。现在，在 start_requests()中，我们要向表单页返回一个简单的 Request，并通过设定 callback 为名字是 parse_welcome()的方法手动处理响应。在 parse_welcome()中，我们使用 FormRequest 对象中的 from_response()方法创建 FormRequest，并将原始表单中的字段和值导入 FormRequest。FormRequest.from_response()可以模拟提交表单。

> 提示：花时间看 from_response()的文档是十分值得的。他有许多有用的功能如 formname 和 formnumber，它可以帮助你当页面有多个表单时，选择特定的表单。

它最大的功能是，一字不差地包含了表单中所有的隐藏字段。我们只需使用 formdata 参数，填入 user 和 pass 字段，并返回 FormRequest。代码如下：

```py
# Start on the welcome page
def start_requests(self):
    return [
        Request(
            "http://web:9312/dynamic/nonce",
            callback=self.parse_welcome)
    ]
# Post welcome page's first form with the given user/pass
def parse_welcome(self, response):
    return FormRequest.from_response(
        response,
        formdata={"user": "user", "pass": "pass"}
    ) 
```

像之前一样运行爬虫：

```py
$ scrapy crawl noncelogin 
INFO: Scrapy 1.0.3 started (bot: properties)
...
DEBUG: Crawled (200) <GET .../dynamic/nonce>
DEBUG: Redirecting (302) to <GET .../dynamic/gated > from <POST .../
dynamic/login-nonce>
DEBUG: Crawled (200) <GET .../dynamic/gated>
...
INFO: Dumping Scrapy stats:
  {...
   'downloader/request_method_count/GET': 5,
   'downloader/request_method_count/POST': 1,
...
   'item_scraped_count': 3, 
```

我们看到第一个 GET 请求先到/dynamic/nonce，然后 POST，重定向到/dynamic/nonce-login 之后，之后像之前一样，访问了/dynamic/gated。登录过程结束。这个例子的登录含有两步。只要有足够的耐心，无论多少步的登录过程，都可以完成。

## **使用 JSON APIs 和 AJAX 页面的爬虫**

有时，你会发现网页的 HTML 找不到数据。例如，在[http://localhost:9312/static/](https://link.jianshu.com?t=http://localhost:9312/static/)页面上右键点击检查元素（1,2），你就可以在 DOM 树种看到所有 HTML 元素。或者，如果你使用 scrapy shell 或在 Chrome 中右键点击查看网页源代码（3,4），你会看到这个网页的 HTML 代码不包含任何和值有关的信息。数据都是从何而来呢？

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/4c057000299da480cf37619262e69166.jpg)

和以前一样，在开发者工具中打开 Network 标签（5）查看发生了什么。左侧列表中，可以看到所有的请求。在这个简单的页面中，只有三个请求：static/我们已经检查过了，jquery.min.js 是一个流行的 JavaScript 框架，api.json 看起来不同。如果我们点击它（6），然后在右侧点击 Preview 标签（7），我们可以看到它包含我们要找的信息。事实上，[http://localhost:9312/properties/api.json](https://link.jianshu.com?t=http://localhost:9312/properties/api.json)包含 IDs 和名字（8），如下所示：

```py
[{
    "id": 0,
    "title": "better set unique family well"
}, 
... {
    "id": 29,
    "title": "better portered mile"
}] 
```

这是一个很简单的 JSON API 例子。更复杂的 APIs 可能要求你登录，使用 POST 请求，或返回某种数据结结构。任何时候，JSON 都是最容易解析的格式，因为不需要 XPath 表达式就可以提取信息。

Python 提供了一个强大的 JSON 解析库。当我们 import json 时，我们可以使用 json.loads（response.body）解析 JSON，并转换成等价的 Python 对象，语句、列表和字典。

复制第 3 章中的 manual.py 文件。这是最好的方法，因为我们要根据 JSON 对象中的 IDs 手动创建 URL 和 Request。将这个文件重命名为 api.py，重命名类为 ApiSpider、名字是 api。新的 start_URL 变成：

```py
start_URL = (
    'http://web:9312/properties/api.json',
) 
```

如果你要做 POST 请求或更复杂的操作，你可以使用 start_requests()方法和前面几章介绍的方法。这里，Scrapy 会打开这个 URL 并使用 Response 作为参数调用 parse()方法。我们可以 import json，使用下面的代码解析 JSON：

```py
def parse(self, response):
    base_url = "http://web:9312/properties/"
    js = json.loads(response.body)
    for item in js:
        id = item["id"]
        url = base_url + "property_%06d.html" % id
        yield Request(url, callback=self.parse_item) 
```

这段代码使用了 json.loads（response.body）将响应 JSON 对象转换为 Python 列表，然后重复这个过程。对于列表中的每个项，我们设置一个 URL，它包含：base_url，property_%06d 和.html.base_url，.html.base_url 前面定义过的 URL 前缀。%06d 是一个非常有用的 Python 词，可以让我们结合多个 Python 变量形成一个新的字符串。在本例中，用 id 变量替换%06d。id 被当做数字（%d 的意思就是当做数字进行处理），并扩展成 6 个字符，位数不够时前面添加 0。如果 id 的值是 5，%06d 会被替换为 000005；id 是 34322 时，%06d 会被替换为 034322 替换。最后的结果是可用的 URL。和第 3 章中的 yield 一样，我们用 URL 做一个新的 Request 请求。运行爬虫：

```py
$ scrapy crawl api
INFO: Scrapy 1.0.3 started (bot: properties)
...
DEBUG: Crawled (200) <GET ...properties/api.json>
DEBUG: Crawled (200) <GET .../property_000029.html>
...
INFO: Closing spider (finished)
INFO: Dumping Scrapy stats:
...
   'downloader/request_count': 31, ...
   'item_scraped_count': 30, 
```

最后一共有 31 次请求，每个项目一次，api.json 一次。

## **在响应间传递参数**

许多时候，你想把 JSON APIs 中的信息存储到 Item 中。为了演示，在我们的例子中，对于一个项，JSON API 在返回它的名字时，在前面加上“better”。例如，如果一个项的名字时“Covent Garden”，API 会返回“Better Covent Garden”。我们要在 Items 中保存这些含有“bette”的名字。如何将数据从 parse()传递到 parse_item()中呢？

我们要做的就是在 parse()方法产生的 Request 中进行设置。然后，我们可以从 parse_item()的的 Response 中取回。Request 有一个名为 meta 的字典，在 Response 中可以直接访问。对于我们的例子，给字典设一个 title 值以存储从 JSON 对象的返回值：

```py
title = item["title"]
yield Request(url, meta={"title": title},callback=self.parse_item) 
```

在 parse_item()中，我们可以使用这个值，而不用 XPath 表达式：

```py
l.add_value('title', response.meta['title'],
      MapCompose(unicode.strip, unicode.title)) 
```

你会注意到，我们从调用 add_xpath()切换到 add_value()，因为对于这个字段不需要使用 XPath。我们现在运行爬虫，就可以在 PropertyItems 中看到 api.json 中的标题了。

## **一个加速 30 倍的项目爬虫**

当你学习使用一个框架时，这个框架越复杂，你用它做任何事都会很复杂。可能你觉得 Scrapy 也是这样。当你就要为 XPath 和其他方法变得抓狂时，不妨停下来思考一下：我现在抓取网页的方法是最简单的吗？

如果你可以从索引页中提取相同的信息，就可以避免抓取每一个列表页，这样就可以节省大量的工作。

> 提示：许多网站的索引页提供的项目数量是不同的。例如，一个网站可以通过调整一个参数，例如&show=50，给每个索引页面设置 10、 50 或 100 个列表项。如果是这样的话，将其设置为可用的最大值。

例如，对于我们的例子，我们需要的所有信息都存在于索引页中，包括标题、描述、价格和图片。这意味着我们抓取单个索引页，提取 30 个条目和下一个索引页的链接。通过抓取 100 个索引页，我们得到 3000 个项，但只有 100 个请求而不是 3000 个。

在真实的 Gumtree 网站上，索引页的描述比列表页的完整描述要短。这是可行的，或者是更推荐的。

> 提示：许多情况下，您不得不在数据质量与请求数量间进行折衷。很多网站都限制请求数量（后面章节详解），所以减少请求可能解决另一个棘手的问题。

在我们的例子中，如果我们查看一个索引页的 HTML，我们会发现，每个列表页有自己的节点，itemtype="[http://schema.org/Product](https://link.jianshu.com?t=http://schema.org/Product)"。节点有每个项的全部信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/3dc06d131102c89384248739e4544fca.jpg)

让我们在 Scrapy shell 中加载索引首页，并用 XPath 处理：

```py
$ scrapy shell http://web:9312/properties/index_00000.html
While within the Scrapy shell, let's try to select everything with the Product tag:
>>> p=response.xpath('//*[@itemtype="http://schema.org/Product"]')
>>> len(p)
30
>>> p
[<Selector xpath='//*[@itemtype="http://schema.org/Product"]' data=u'<li 
class="listing-maxi" itemscopeitemt'...] 
```

我们得到了一个包含 30 个 Selector 对象的表，每个都指向一个列表。Selector 对象和 Response 对象很像，我们可以用 XPath 表达式从它们指向的对象中提取信息。不同的是，表达式为有相关性的 XPath 表达式。相关性 XPath 表达式与我们之前见过的很像，不同之处是它们前面有一个点“.”。然我们看看如何用.//*[@itemprop="name"][1]/text()提取标题的：

```py
>>> selector = p[3]
>>> selector
<Selector xpath='//*[@itemtype="http://schema.org/Product"]' ... '>
>>> selector.xpath('.//*[@itemprop="name"][1]/text()').extract()
[u'l fun broadband clean people brompton european'] 
```

我们可以在 Selector 对象表中用 for 循环提取一个索引页的所有 30 个项目信息。还是从第 3 章中的 maunal.py 文件开始，重命名为 fast.py。重复使用大部分代码，修改 parse()和 parse_item()方法。更新的方法如下所示：

```py
def parse(self, response):
    # Get the next index URL and yield Requests
    next_sel = response.xpath('//*[contains(@class,"next")]//@href')
    for url in next_sel.extract():
        yield Request(urlparse.urljoin(response.url, url))
    # Iterate through products and create PropertiesItems
    selectors = response.xpath(
        '//*[@itemtype="http://schema.org/Product"]')
    for selector in selectors:
        yield self.parse_item(selector, response) 
```

第一部分中用于产生下一条索引请求的代码没有变动。不同的地方是第二部分，我们重复使用选择器调用 parse_item()方法，而不是用 yield 创建请求。这和原先使用的源代码很像：

```py
def parse_item(self, selector, response):
    # Create the loader using the selector
    l = ItemLoader(item=PropertiesItem(), selector=selector)
    # Load fields using XPath expressions
l.add_xpath('title', './/*[@itemprop="name"][1]/text()',
                MapCompose(unicode.strip, unicode.title))
    l.add_xpath('price', './/*[@itemprop="price"][1]/text()',
                MapCompose(lambda i: i.replace(',', ''), float),
                re='[,.0-9]+')
    l.add_xpath('description',
                './/*[@itemprop="description"][1]/text()',
                MapCompose(unicode.strip), Join())
    l.add_xpath('address',
                './/*[@itemtype="http://schema.org/Place"]'
                '[1]/*/text()',
                MapCompose(unicode.strip))
    make_url = lambda i: urlparse.urljoin(response.url, i)
    l.add_xpath('image_URL', './/*[@itemprop="image"][1]/@src',
                MapCompose(make_url))
    # Housekeeping fields
    l.add_xpath('url', './/*[@itemprop="url"][1]/@href',
                MapCompose(make_url))
    l.add_value('project', self.settings.get('BOT_NAME'))
    l.add_value('spider', self.name)
    l.add_value('server', socket.gethostname())
    l.add_value('date', datetime.datetime.now())
    return l.load_item() 
```

我们做出的变动是：

*   ItemLoader 现在使用 selector 作为源，不使用 Response。这么做可以让 ItemLoader 更便捷，可以让我们从特定的区域而不是整个页面抓取信息。
*   通过在前面添加“.”使 XPath 表达式变为相关 XPath。

> 提示：碰巧的是，在我们的例子中，XPath 表达式在索引页和介绍页中是相同的。不同的时候，你需要按照索引页修改 XPath 表达式。

*   在 response.url 给我们列表页的 URL 之前，我们必须自己编辑 Item 的 URL。然后，它才能返回我们抓取网页的 URL。我们必须用.//*[@itemprop="url"][1]/@href 提取 URL，然后将它用 MapCompose 转化为 URL 绝对路径。

这些小小大量的工作的改动可以节省大量的工作。现在，用以下命令运行爬虫：

```py
$ scrapy crawl fast -s CLOSESPIDER_PAGECOUNT=3
...
INFO: Dumping Scrapy stats:
   'downloader/request_count': 3, ...
   'item_scraped_count': 90,... 
```

就像之前说的，我们用三个请求，就抓取了 90 个项目。不从索引开始的话，就要用 93 个请求。

如果你想用 scrapy parse 来调试，你需要如下设置 spider 参数：

```py
$ scrapy parse --spider=fast http://web:9312/properties/index_00000.html
...
>>> STATUS DEPTH LEVEL 1 <<<
# Scraped Items  --------------------------------------------
[{'address': [u'Angel, London'],
... 30 items...
# Requests  ---------------------------------------------------
[<GET http://web:9312/properties/index_00001.html>] 
```

正如所料，parse()返回了 30 个 Items 和下一个索引页的请求。你还可以继续试验 scrapy parse，例如，设置—depth=2。

## **可以抓取 Excel 文件的爬虫**

大多数时候，你每抓取一个网站就使用一个爬虫，但如果要从多个网站抓取时，不同之处就是使用不同的 XPath 表达式。为每一个网站配置一个爬虫工作太大。能不能只使用一个爬虫呢？答案是可以。

新建一个项目抓取不同的东西。当前我们是在 ch05 的 properties 目录，向上一级：

```py
$ pwd
/root/book/ch05/properties
$ cd ..
$ pwd
/root/book/ch05 
```

新建一个项目，命名为 generic，再创建一个名为 fromcsv 的爬虫：

```py
$ scrapy startproject generic
$ cd generic
$ scrapy genspider fromcsv example.com 
```

新建一个.csv 文件，它是我们抓取的目标。我们可以用 Excel 表建这个文件。如下表所示，填入 URL 和 XPath 表达式，在爬虫的目录中（有 scrapy.cfg 的文件夹）保存为 todo.csv。保存格式是 csv：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/f528e5376d7d0dc3c4c5fed07ae87783.jpg)

一切正常的话，就可以在终端看见这个文件：

```py
$ cat todo.csv 
url,name,price
a.html,"//*[@id=""itemTitle""]/text()","//*[@id=""prcIsum""]/text()"
b.html,//h1/text(),//span/strong/text()
c.html,"//*[@id=""product-desc""]/span/text()" 
```

Python 中有 csv 文件的内建库。只需 import csv，就可以用后面的代码一行一行以 dict 的形式读取这个 csv 文件。在当前目录打开 Python 命令行，然后输入：

```py
$ pwd
/root/book/ch05/generic2
$ python
>>> import csv
>>> with open("todo.csv", "rU") as f:
        reader = csv.DictReader(f)
        for line in reader:
            print line 
```

文件的第一行会被自动作为 header，从而导出 dict 的键名。对于下面的每一行，我们得到一个包含数据的 dict。用 for 循环执行每一行。前面代码的结果如下：

```py
{'url': ' http://a.html', 'price': '//*[@id="prcIsum"]/text()', 'name': '//*[@id="itemTitle"]/text()'}
{'url': ' http://b.html', 'price': '//span/strong/text()', 'name': '//h1/text()'}
{'url': ' http://c.html', 'price': '', 'name': '//*[@id="product-desc"]/span/text()'} 
```

很好。现在编辑 generic/spiders/fromcsv.py 爬虫。我们使用.csv 文件中的 URL，并且不希望遇到域名限制的情况。因此第一件事是移除 start_URL 和 allowed_domains。然后再读.csv 文件。

因为从文件中读取的 URL 是我们事先不了解的，所以使用一个 start_requests()方法。对于每一行，我们都会创建 Request。我们还要从 request,meta 的 csv 存储字段名和 XPath，以便在我们的 parse()函数中使用。然后，我们使用 Item 和 ItemLoader 填充 Item 的字段。下面是所有代码：

```py
import csv
import scrapy
from scrapy.http import Request
from scrapy.loader import ItemLoader
from scrapy.item import Item, Field
class FromcsvSpider(scrapy.Spider):
    name = "fromcsv"
def start_requests(self):
    with open("todo.csv", "rU") as f:
        reader = csv.DictReader(f)
        for line in reader:
            request = Request(line.pop('url'))
            request.meta['fields'] = line
            yield request
def parse(self, response):
    item = Item()
    l = ItemLoader(item=item, response=response)
    for name, xpath in response.meta['fields'].iteritems():
        if xpath:
      item.fields[name] = Field()
            l.add_xpath(name, xpath)
    return l.load_item() 
```

运行爬虫，输出文件保存为 csv：

```py
$ scrapy crawl fromcsv -o out.csv
INFO: Scrapy 0.0.3 started (bot: generic)
...
DEBUG: Scraped from <200 a.html>
{'name': [u'My item'], 'price': [u'128']}
DEBUG: Scraped from <200 b.html>
{'name': [u'Getting interesting'], 'price': [u'300']}
DEBUG: Scraped from <200 c.html>
{'name': [u'Buy this now']}
...
INFO: Spider closed (finished)
$ cat out.csv 
price,name
128,My item
300,Getting interesting
,Buy this now 
```

有几点要注意。项目中没有定义一个整个项目的 Items，我们必须手动向 ItemLoader 提供一个：

```py
item = Item()
l = ItemLoader(item=item, response=response) 
```

我们还用 Item 的 fields 成员变量添加了动态字段。添加一个新的动态字段，并用 ItemLoader 填充，使用下面的方法：

```py
item.fields[name] = Field()
l.add_xpath(name, xpath) 
```

最后让代码再漂亮些。硬编码 todo.csv 不是很好。Scrapy 提供了一种便捷的向爬虫传递参数的方法。如果我们使用-a 参数，例如，-a variable=value，就创建了一个爬虫项，可以用 self.variable 取回。为了检查变量（没有的话，提供一个默认变量），我们使用 Python 的 getattr()方法：getattr(self, 'variable', 'default')。总之，原来的 with open…替换为：

```py
with open(getattr(self, "file", "todo.csv"), "rU") as f: 
```

现在，todo.csv 是默认文件，除非使用参数-a，用一个源文件覆盖它。如果还有一个文件，another_todo.csv，我们可以运行：

```py
$ scrapy crawl fromcsv -a file=another_todo.csv -o out.csv 
```

## **总结**

在本章中，我们进一步学习了 Scrapy 爬虫。我们使用 FormRequest 进行登录，用请求/响应中的 meta 传递变量，使用了相关的 XPath 表达式和 Selectors，使用.csv 文件作为数据源等等。

接下来在第 6 章学习在 Scrapinghub 云部署爬虫，在第 7 章学习关于 Scrapy 的设置。



# 六、Scrapinghub 部署



前面几章中，我们学习了如何编写爬虫。编写好爬虫之后，我们有两个选择。如果是做单次抓取，让爬虫在开发机上运行一段时间就行了。或者，我们往往需要周期性的进行抓取。我们可以用 Amazon、RackSpace 等服务商的云主机，但这需要一些设置、配置和维护。这时候就需要 Scrapinghub 了。

Scrapinghub 是 Scrapy 高级开发者托管在 Amazon 上面的云架构。这是一个付费服务，但提供免费使用。如果想短时间内让爬虫运行在专业、有维护的平台上，本章内容很适合你。

**注册、登录、创建项目**

第一步是在[http://scrapinghub.com/](https://link.jianshu.com?t=http://scrapinghub.com/)注册一个账户，只需电子邮件地址和密码。点击确认邮件的链接之后，就登录了。首先看到的是工作台，目前还没有任何项目，点击+Service 按钮（1）创建一个：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/627755bbe604653b1b4511f519dd72fd.jpg)

将项目命名为 properties（2），点击 Create 按钮（3）。然后点击链接 new（4）打开这个项目。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/0be351705e354fc3ff426b4ad82fa993.jpg)

项目的工作台是最重要的界面。左侧栏中可以看到一些标签。Jobs 和 Spiders 提供运行和爬虫的信息。Periodic Jobs 可以制定周期抓取。其它四项，现在对我们不重要。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/59f095e5cbf2f265b6ed489e69acc6d8.jpg)

进入 Settings（1）。和许多网站的设置不同，Scrapinghub 提供许多非常有用的设置项。

现在，先关注下 Scrapy Deploy（2）。

**部署爬虫并制定计划**

我们从开发机直接部署。将 Scrapy Deploy 页上的 url 复制到我们项目的 scrapy.cfg 中，替换原有的[depoly]部分。不必设置密码。我们用第 4 章中的 properties 爬虫作例子。我们使用这个爬虫的原因是，目标数据可以从网页访问，访问的方式和第 4 章中一样。开始之前，我们先恢复原有的 settings.py，去除和 Appery.io pipeline 有关的内容：

> 提示：代码位于目录 ch06。这个例子在 ch06/properties 中。

```py
$ pwd
/root/book/ch06/properties
$ ls
properties  scrapy.cfg
$ cat scrapy.cfg
...
[settings]
default = properties.settings
# Project: properties
[deploy]
url = http://dash.scrapinghub.com/api/scrapyd/
username = 180128bc7a0.....50e8290dbf3b0
password = 
project = 28814 
```

为了部署爬虫，我们使用 Scrapinghub 提供的 shub 工具，可以用 pip install shub 安装。我们的开发机中已经有了。我们 shub login 登录 Scrapinghub，如下所示：

```py
$ shub login
Insert your Scrapinghub API key : 180128bc7a0.....50e8290dbf3b0
Success. 
```

我们已经在 scrapy.cfg 文件中复制了 API key，我们还可以点击 Scrapinghub 右上角的用户名找到 API key。弄好 API key 之后，就可以使用 shub deploy 部署爬虫了：

```py
$ shub deploy
Packing version 1449092838
Deploying to project "28814"in {"status": "ok", "project": 28814,
"version":"1449092838", "spiders": 1}
Run your spiders at: https://dash.scrapinghub.com/p/28814/ 
```

Scrapy 打包了所有爬虫文件，并上传到了 Scrapinghub。我们可以看到两个新目录和一个文件，可以选择删除或不删除。

```py
$ ls
build project.egg-info properties scrapy.cfgsetup.py
$ rm -rf build project.egg-info setup.py 
```

现在，如果我们在 Scrapinghub 点击 Spiders 栏（1），我们可以看到上传的 tomobile 爬虫：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/3d77e53845bbbe8aecf937766b0a4c1c.jpg)

如果我们点击它（2），可以转到爬虫的工作台。里面的信息很多，但我们要做的是点击右上角的 Schedule 按钮（3），在弹出的界面中再点击 Schedule（4）。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/9f5e671eb0026ee905ac2f81e431ac36.jpg)

几秒钟之后，Running Jobs 栏会出现新的一行，再过一会儿，Requests 和 Items 的数量开始增加。

> 提示：你或许不会限制抓取速度。Scrapinghub 使用算法估算在不被封的情况下，你每秒的最大请求数。

运行一段时间后，勾选这个任务（6），点击 Stop（7）。

几秒之后，可以在 Completed Jobs 看到抓取结束。要查看抓取文件，可以点击文件数（8）。

**访问文件**
来到任务的工作台。这里，可以查看文件（9），确认它们是否合格。我们还可以用上面的条件过滤结果。当我们向下翻动时，更多的文件被加载进来。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/dee187c58910e8b10726b3ff29e15152.jpg)

如果有错的话，我们可以在 Items 的上方找到有用的关于 Requests 和 Log 的信息（10）。用上方的面包屑路径（11）可以返回爬虫或项目主页。当然，可以点击左上的 Items 按钮（12）下载文件，选择合适的选项（13），保存格式可以是 CSV、JSON 和 JSON Lines。

另一种访问文件的方法是通过 Scrapinghub 的 Items API。我们要做的是查看任务页或文件页的 URL。应该看起来和下面很像：
[https://dash.scrapinghub.com/p/28814/job/1/1/](https://link.jianshu.com?t=https://dash.scrapinghub.com/p/28814/job/1/1/)

在这个 URL 中，28814 是项目编号（scrapy.cfg 中也设置了它），第一个 1 是爬虫“tomobile”的 ID 编号，第二个 1 是任务编号。按顺序使用这三个数字，我们可以在控制台中用 curl 取回文件，请求发送到[https://storage.scrapinghub.com/items/](https://link.jianshu.com?t=https://storage.scrapinghub.com/items/)<project id>/<spider id>/<job id>，并使用用户名/API key 验证，如下所示：

```py
$ curl -u 180128bc7a0.....50e8290dbf3b0: https://storage.scrapinghub.com/items/28814/1/1
{"_type":"PropertiesItem","description":["same\r\nsmoking\r\nr...
{"_type":"PropertiesItem","description":["british bit keep eve...
... 
```

如果询问密码的话，可以不填。用程序取回文件的话，可以使用 Scrapinghub 当做数据存储后端。存储的时间取决于订阅套餐的时间（免费试用是七天）。

**制定周期抓取**

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/2c8b4f46f77072845c9d776c77a3f188.jpg)

只需要点击 Periodic Jobs 栏（1），点击 Add（2），设定爬虫（3），调整抓取频率（4），最后点击 Save（5）。

**总结**
本章中，我们首次接触了将 Scrapy 项目部署到 Scrapinghub。定时抓取数千条信息，并可以用 API 方便浏览和提取。后面的章节中，我们继续学习设置一个类似 Scrapinghub 的小型服务器。下一章先学习配置和管理。



# 七、配置和管理



我们已经学过了用 Scrapy 写一个抓取网络信息的简单爬虫是多么容易。通过进行设置，Scrapy 还有许多用途和功能。对于许多软件框架，用设置调节系统的运行，很让人头痛。对于 Scrapy，设置是最基础的知识，除了调节和配置，它还可以扩展框架的功能。这里只是补充官方 Scrapy 文档，让你可以尽快对设置有所了解，并找到能对你有用的东西。在做出修改时，还请查阅文档。

**使用 Scrapy 设置**
在 Scrapy 的设置中，你可以按照五个等级进行设置。第一级是默认设置，你不必进行修改，但是 scrapy/settings/default_settings.py 文件还是值得一读的。默认设置可以在命令级进行优化。一般来讲，除非你要插入自定义命令，否则不必修改。更经常的，我们只是修改自己项目的 settings.py 文件。这些设置只对当前项目管用。这么做很方便，因为当我们把项目部署到云主机时，可以连带设置文件一起打包，并且因为它是文件，可以用文字编辑器进行编辑。下一级是每个爬虫的设置。通过在爬虫中使用 custom_settings 属性，我们可以自定义每个爬虫的设置。例如，这可以让我们打开或关闭某个特定蜘蛛的 Pipelines。最后，要做最后的修改时，我们可以在命令行中使用-s 参数。我们做过这样的设置，例如-s CLOSESPIDER_PAGECOUNT=3，这可以限制爬虫的抓取范围。在这一级，我们可以设置 API、密码等等。不要在 settings.py 文件中保存这些设置，因为不想让它们在公共仓库中失效。

这一章，我们会学习一些非常重要且常用的设置。在任意项目中输入以下命令，可以了解设置都有多少类型：

```py
$ scrapy settings --get CONCURRENT_REQUESTS
16 
```

你得到的是默认值。修改这个项目的 settings.py 文件的 CONCURRENT_REQUESTS 的值，比如，14。上面命令行的结果也会变为 14，别忘了将设置改回去。在命令行中设置参数的话：

```py
$ scrapy settings --get CONCURRENT_REQUESTS -s CONCURRENT_REQUESTS=19
19 
```

这个结果暗示 scrapy crawl 和 scrapy settings 都是命令。每个命令都使用这样的方法加载设置。再举一个例子：

```py
$ scrapy shell -s CONCURRENT_REQUESTS=19
>>> settings.getint('CONCURRENT_REQUESTS')
19 
```

当你想确认设置文件中的值时，你就可以才用以上几种方法。下面详细学习 Scrapy 的设置。

**基本设置**
Scrapy 的设置太多，将其分类很有必要。我们从下图的基本设置开始，它可以让你明白重要的系统特性，你可能会频繁使用。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/7e375a5ce30a0f8de9d52a778f88435c.jpg)

**分析**
通过这些设置，可以调节 Scrapy 的性能、调试信息的日志、统计、远程登录设备。

**日志**
Scrapy 有不同的日志等级：DEBUG（最低），INFO，WARNING，ERROR，和 CRITICAL（最高）。除此之外，还有一个 SILENT 级，没有日志输出。Scrapy 的有用扩展之一是 Log Stats，它可以打印出每分钟抓取的文件数和页数。LOGSTATS_INTERVAL 设置日志频率，默认值是 60 秒。这个间隔偏长。我习惯于将其设置为 5 秒，因为许多运行都很短。LOG_FILE 设置将日志写入文件。除非进行设定，输出会一直持续到发生标准错误，将 LOG_ENABLED 设定为 False，就不会这样了。最后，通过设定 LOG_STDOUT 为 True，你可以让 Scrapy 在日志中记录所有的输出（比如 print）。

**统计**
STATS_DUMP 是默认开启的，当爬虫运行完毕时，它把统计收集器（Stats Collector）中的值转移到日志。设定 DOWNLOADER_STATS，可以决定是否记录统计信息。通过 DEPTH_STATS，可以设定是否记录网站抓取深度的信息。若要记录更详细的深度信息，将 DEPTH_STATS_VERBOSE 设定为 True。STATSMAILER_RCPTS 是一个当爬虫结束时，发送 email 的列表。你不用经常设置它，但有时调试时会用到它。

**远程登录**
Scrapy 包括一个内建的远程登录控制台，你可以在上面用 Python 控制 Scrapy。TELNETCONSOLE_ENABLED 是默认开启的，TELNETCONSOLE_PORT 决定连接端口。在发生冲突时，可以对其修改。

**案例 1——使用远程登录**
有时，你想查看 Scrapy 运行时的内部状态。让我们来看看如何用远程登录来做：

> 笔记：本章代码位于 ch07。这个例子位于 ch07/properties 文件夹中。

```py
$ pwd
/root/book/ch07/properties
$ ls
properties  scrapy.cfg
Start a crawl as follows:
$ scrapy crawl fast
...
[scrapy] DEBUG: Telnet console listening on 127.0.0.1:6023:6023 
```

这段信息是说远程登录被激活，监听端口是 6023。然后在另一台电脑，使用远程登录的命令连接：

```py
$ telnet localhost 6023
>>> 
```

现在，这台终端会给你一个在 Scrapy 中的 Python 控制台。你可以查看某些组件，例如用 engine 变量查看引擎，可以用 est()进行快速查看：

```py
>>> est()
Execution engine status
time()-engine.start_time                        : 5.73892092705
engine.has_capacity()                           : False
len(engine.downloader.active)                   : 8
...
len(engine.slot.inprogress)                     : 10
...
len(engine.scraper.slot.active)                 : 2 
```

我们在第 10 章中会继续学习里面的参数。接着输入以下命令：

```py
>>> import time
>>> time.sleep(1) # Don't do this! 
```

你会注意到，另一台电脑有一个短暂停。你还可以进行暂停、继续、停止爬虫。使用远程机器时，使用远程登录的功能非常有用：

```py
>>> engine.pause()
>>> engine.unpause()
>>> engine.stop()
Connection closed by foreign host. 
```

**性能**
第 10 章会详细介绍这些设置，这里只是一个概括。性能设定可以让你根据具体的工作调节爬虫的性能。CONCURRENT_REQUESTS 设置了并发请求的最大数。这是为了当你抓取很多不同的网站（域名/IPs）时，保护你的服务器性能。不是这样的话，你会发现 CONCURRENT_REQUESTS_PER_DOMAIN 和 CONCURRENT_REQUESTS_PER_IP 更多是限制性的。这两项分别通过限制每一个域名或 IP 地址的并发请求数，保护远程服务器。如果 CONCURRENT_REQUESTS_PER_IP 是非零的，CONCURRENT_REQUESTS_PER_DOMAIN 则被忽略。这些设置不是按照每秒。如果 CONCURRENT_REQUESTS = 16，请求平均消耗四分之一秒，最大极限则为每秒 16/0.25 = 64 次请求。CONCURRENT_ITEMS 设定每次请求并发处理的最大文件数。你可能会觉得这个设置没什么用，因为每个页面通常只有一个抓取项。它的默认值是 100。如果降低到，例如 10 或 1，你可能会觉得性能提升了，取决于每次请求抓取多少项和 pipelines 的复杂度。你还会注意到，当这个值是关于每次请求的，如果 CONCURRENT_REQUESTS = 16，CONCURRENT_ITEMS = 100 意味每秒有 1600 个文件同时要写入数据库。我一般把这个值设的比较小。

对于下载，DOWNLOADS_TIMEOUT 决定了取消请求前，下载器的等待时间。默认是 180 秒，这个时间太长，并发请求是 16 时，每秒的下载数是 5 页。我建议设为 10 秒。默认情况下，各个下载间的间隔是 0，以提高抓取速度。你可以设置 DOWNLOADS_DELAY 改变下载速度。有的网站会测量请求频率以判定是否是机器人行为。设定 DOWNLOADS_DELAY 的同时，还会有±50%的随机延迟。你可以设定 RANDOMIZE_DOWNLOAD_DELAY 为 False。

最后，若要使用更快的 DNS 查找，可以设定 DNSCACHE_ENABLED 打开内存 DNS 缓存。

**提早结束抓取**
Scrapy 的 CloseSpider 扩展可以在条件达成时，自动结束抓取。你可以用 CLOSESPIDER_TIMEOUT(in seconds)， CLOSESPIDER_ITEMCOUNT， CLOSESPIDER_PAGECOUNT，和 CLOSESPIDER_ERRORCOUNT 分别设置在一段时间、抓取一定数量的文件、发出一定数量请求、发生一定数量错误时，提前关闭爬虫。你会在运行爬虫时频繁地做出这类设置：

```py
$ scrapy crawl fast -s CLOSESPIDER_ITEMCOUNT=10
$ scrapy crawl fast -s CLOSESPIDER_PAGECOUNT=10
$ scrapy crawl fast -s CLOSESPIDER_TIMEOUT=10 
```

**HTTP 缓存和脱机工作**
Scrapy 的 HttpCacheMiddleware 中间件（默认关闭）提供了一个低级的 HTTP 请求响应缓存。如果打开的话，缓存会存储每次请求和对应的响应。通过设定 HTTPCACHE_POLICY 为 scrapy.contrib.httpcache.RFC2616Policy，我们可以使用一个更为复杂的、按照 RFC2616 遵循网站提示的缓存策略。打开这项功能，设定 HTTPCACHE_ENABLED 为 True，HTTPCACHE_DIR 指向一个磁盘路径（使用相对路径的话，会存在当前文件夹内）。

你可以为缓存文件指定数据库后端，通过设定 HTTPCACHE_STORAGE 为 scrapy.contrib.httpcache.DbmCacheStorage，还可以选择调整 HTTPCACHE_DBM_MODULE。（默认为 anydbm）还有其它微调缓存的设置，但按照默认设置就可以了。

**案例 2——用缓存离线工作**
运行以下代码：

```py
$ scrapy crawl fast -s LOG_LEVEL=INFO -s CLOSESPIDER_ITEMCOUNT=5000 
```

一分钟之后才结束。如果你无法联网，就无法进行任何抓取。用下面的代码再次进行抓取：

```py
$ scrapy crawl fast -s LOG_LEVEL=INFO -s CLOSESPIDER_ITEMCOUNT=5000 -s HTTPCACHE_ENABLED=1
...
INFO: Enabled downloader middlewares:...*HttpCacheMiddleware* 
```

你会看到启用了 HttpCacheMiddleware，如果你查看当前目录，会发现一个隐藏文件夹，如下所示：

```py
$ tree .scrapy | head
.scrapy
└── httpcache
    └── easy
        ├── 00
        │     ├── 002054968919f13763a7292c1907caf06d5a4810
        │     │     ├── meta
        │     │     ├── pickled_meta
        │     │     ├── request_body
        │     │     ├── request_headers
        │     │     ├── response_body
... 
```

当你再次运行不能联网的爬虫时，抓取稍少的文件，你会发现运行变快了：

```py
$ scrapy crawl fast -s LOG_LEVEL=INFO -s CLOSESPIDER_ITEMCOUNT=4500 -s 
HTTPCACHE_ENABLED=1 
```

抓取稍少的文件，是因为使用 CLOSESPIDER_ITEMCOUNT 结束爬虫时，爬虫实际上会多抓取几页，我们不想抓取不在缓存中的内容。清理缓存的话，只需删除缓存目录：

```py
$ rm -rf .scrapy 
```

**抓取方式**
Scrapy 允许你设置从哪一页开始爬。设置 DEPTH_LIMIT，可以设置最大深度，0 代表没有限制。根据深度，通过 DEPTH_PRIORITY，可以给请求设置优先级。将其设为正值，可以让你实现广度优先抓取，并在 LIFO 和 FIFO 间切换：

```py
DEPTH_PRIORITY = 1
SCHEDULER_DISK_QUEUE = 'scrapy.squeue.PickleFifoDiskQueue'
SCHEDULER_MEMORY_QUEUE = 'scrapy.squeue.FifoMemoryQueue' 
```

这个功能十分有用，例如，当你抓取一个新闻网站，先抓取离首页近的最近的新闻，然后再是其它页面。默认的 Scrapy 方式是顺着第一条新闻抓取到最深，然后再进行下一条。广度优先可以先抓取层级最高的新闻，再往深抓取，当设定 DEPTH_LIMIT 为 3 时，就可以让你快速查看最近的新闻。

有的网站在根目录中用一个网络标准文件 robots.txt 规定了爬虫的规则。当设定 ROBOTSTXT_OBEY 为 True 时，Scrapy 会参考这个文件。设定为 True 之后，记得调试的时候碰到意外的错误时，可能是这个原因。

CookiesMiddleware 负责所有 cookie 相关的操作，开启 session 跟踪的话，可以实现登录。如果你想进行秘密抓取，可以设置 COOKIES_ENABLED 为 False。使 cookies 无效减少了带宽，一定程度上可以加快抓取。相似的，REFERER_ENABLED 默认是 True，可使 RefererMiddleware 生效，用它填充 Referer headers。你可以用 DEFAULT_REQUEST_HEADERS 自定义 headers。你会发现当有些奇怪的网站要求特定的请求头时，这个特别有用。最后，自动生成的 settings.py 文件建议我们设定 USER_AGENT。默认也可以，但我们应该修改它，以便网站所有者可以联系我们。

**Feeds**
Feeds 可以让你导出用 Scrapy 抓取的数据到本地或到服务器。存储路径取决于 FEED_URI.FEED_URI，其中可能包括参数。例如 scrapy crawl fast -o "%(name)s_%(time)s.jl，可以自动将时间和名字填入到输出文件。如果你需要你个自定义参数，例如%(foo)s, feed 输出器希望在爬虫中提供一个叫做 foo 的属性。数据的存储，例如 S3、FTP 或本地，也是在 URI 中定义。例如，FEED_URI='[s3://mybucket/file.json'](https://link.jianshu.com?t=s3://mybucket/file.json')可以使用你的 Amazon 证书（AWS_ACCESS_KEY_ID 和 AWS_SECRET_ACCESS_KEY），将你的文件存储到 Amazon S3。存储的格式，JSON、JSON Lines、CSV 和 XML，取决于 FEED_FORMAT。如果没有指定的话，Scrapy 会根据 FEED_URI 的后缀猜测。你可以选择输出为空，通过设定 FEED_STORE_EMPTY 为 True。你还可以选择输出指定字段，通过设定 FEED_EXPORT_FIELDS。这对.csv 文件特别有用，可以固定 header 的列数。最后 FEED_URI_PARAMS 用于定义一个函数，对传递给 FEED_URI 的参数进行后处理。

**下载媒体文件**
Scrapy 可以用 Image Pipeline 下载媒体文件，它还可以将图片转换成不同的格式、生成面包屑路径、或根据图片大小进行过滤。

IMAGES_STORE 设置了图片存储的路径（选用相对路径的话，会存储在项目的根目录）。每个图片的 URL 存在各自的 image_URL 字段（它可以被 IMAGES_URL_FIELD 设置覆盖），下载下来的图片的文件名会存在一个新的 image 字段（它可以被 IMAGES_RESULT_FIELD 设置覆盖）。你可以通过 IMAGES_MIN_WIDTH 和 IMAGES_MIN_HEIGHT 筛选出小图片。IMAGES_EXPIRES 可以决定图片在缓存中存储的天数。IMAGES_THUMBS 可以设置一个或多个缩略图，还可以设置缩略图的大小。例如，你可以让 Scrapy 生成一个图标大小的缩略图或为每个图片生成一个中等的缩略图。

**其它媒体文件**
你可以使用 Files Pipelines 下载其它媒体文件。与图片相同 FILES_STORE 决定了存储地址，FILES_EXPIRES 决定存储时间。FILES_URL_FIELD 和 FILES_
RESULT_FIELD 的作用与之前图片的相似。文件和图片的 pipelines 可以同时工作。

**案例 3——下载图片**
为了使用图片功能，我们必须安装图片包，命令是 pip install image。我们的开发机已经安装好了。要启动 Image Pipeline，你需要编辑 settings.py 加入一些设置。首先在 ITEM_PIPELINES 添加 scrapy.pipelines.images.ImagesPipeline。然后，将 IMAGES_STORE 设为相对路径"images"，通过设置 IMAGES_THUMBS，添加缩略图的描述，如下所示：

```py
ITEM_PIPELINES = {
...
    'scrapy.pipelines.images.ImagesPipeline': 1,
}
IMAGES_STORE = 'images'
IMAGES_THUMBS = { 'small': (30, 30) } 
```

我们已经为 Item 安排了 image_URL 字段，然后如下运行：

```py
$ scrapy crawl fast -s CLOSESPIDER_ITEMCOUNT=90
...
DEBUG: Scraped from <200 http://http://web:9312/.../index_00003.html/
property_000001.html>{
   'image_URL': [u'http://web:93img/i02.jpg'],
   'images': [{'checksum': 'c5b29f4b223218e5b5beece79fe31510',
               'path': 'full/705a3112e67...a1f.jpg',
               'url': 'http://web:93img/i02.jpg'}],
...
$ tree images 
images
├── full
│   ├── 0abf072604df23b3be3ac51c9509999fa92ea311.jpg
│   ├── 1520131b5cc5f656bc683ddf5eab9b63e12c45b2.jpg
...
└── thumbs
    └── small
        ├── 0abf072604df23b3be3ac51c9509999fa92ea311.jpg
        ├── 1520131b5cc5f656bc683ddf5eab9b63e12c45b2.jpg
... 
```

我们看到图片成功下载下来，病生成了缩略图。Images 文件夹中存储了 jpg 文件。缩略图的路径可以很容易推测出来。删掉图片，可以使用命令 rm -rf images。

**亚马逊网络服务**
Scrapy 內建支持亚马逊服务。你可以将 AWS 的 access key 存储到 AWS_ACCESS_KEY_ID，将 secret key 存到 AWS_SECRET_ACCESS_KEY。这两个设置默认都是空的。使用方法如下：

*   当你用开头是 s3://（注意不是 http://）下载 URL 时
*   当你用 media pipelines 在 s3://路径存储文件或缩略图时
*   当你在 s3://目录存储输出文件时，不要在[settings.py](https://link.jianshu.com?t=http://settings.py)中存储这些设置，以免有一天这个文件要公开。

**使用代理和爬虫**
Scrapy 的 HttpProxyMiddleware 组件可以让你使用代理，它包括 http_proxy、https_proxy 和 no_proxy 环境变量。代理功能默认是开启的。

**案例 4——使用代理和 Crawlera 的智慧代理**
DynDNS 提供了一个免费检查你的 IP 地址的服务。使用 Scrapy shell，我们向 checkip.dyndns.org 发送一个请求，检查响应确定当前的 IP 地址：

```py
$ scrapy shell http://checkip.dyndns.org
>>> response.body
'<html><head><title>Current IP Check</title></head><body>Current IP 
Address: xxx.xxx.xxx.xxx</body></html>\r\n'
>>> exit() 
```

要使用代理请求，退出 shell，然后使用 export 命令设置一个新代理。你可以通过搜索 HMA 的公共代理列表（[http://proxylist.hidemyass.com/](https://link.jianshu.com?t=http://proxylist.hidemyass.com/)）测试一个免费代理。例如，假设我们选择一个代理 IP 是 10.10.1.1，端口是 80（替换成你的），如下运行：

```py
$ # First check if you already use a proxy
$ env | grep http_proxy
$ # We should have nothing. Now let's set a proxy
$ export http_proxy=http://10.10.1.1:80 
```

再次运行 Scrapy shell，你可以看到这次请求使用了不同的 IP。代理很慢，有时还会失败，这时可以选择另一个 IP。要关闭代理，可以退出 Scrapy shell，并使用 unset http_proxy。

Crawlera 是 Scrapinghub 的一个服务。除了使用一个大的 IP 池，它还能调整延迟并退出坏的请求，让连接变得快速稳定。这是爬虫工程师梦寐以求的产品。使用它，只需设置 http_proxy 的环境变量为：

```py
$ export http_proxy=myusername:mypassword@proxy.crawlera.com:8010 
```

除了 HTTP 代理，还可以通过它给 Scrapy 设计的中间件使用 Crawlera。

**更多的设置**
接下来看一些 Scrapy 不常用的设置和 Scrapy 的扩展设置，后者在后面的章节会详细介绍。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/804c12478e1f7170fc75e8c3b9174e58.jpg)

**和项目相关的设定**
这个小标题下，介绍和具体项目相关的设置，例如 BOT_NAME、SPIDER_MODULES 等等。最好在文档中查看一下，因为它们在某些具体情况下可以提高效率。但是通常来讲，Scrapy 的 startproject 和 genspider 命令的默认设置已经是合理的了，所以就不必另行设置了。和邮件相关的设置，例如 MAIL_FROM，可以让你配置 MailSender 类，它被用来发送统计数据（还可以查看 STATSMAILER_RCPTS）和内存使用（还可以查看 MEMUSAGE_NOTIFY_MAIL）。还有两个环境变量 SCRAPY_SETTINGS_MODULE 和 SCRAPY_PROJECT，它们可以让你微调 Scrapy 项目的整合，例如，整合一个 Django 项目。scrapy.cfg 还可以让你修改设置模块的名字。

**扩展 Scrapy 设置**
这些设定允许你扩展和修改 Scrapy 的几乎每个方面。最重要的就是 ITEM_PIPELINES。它允许你在项目中使用 Item Processing Pipelines。我们会在第 9 章中看到更多的例子。除了 pipelines，还可以用多种方式扩展 Scrapy，第 8 章总结了一些方式。COMMANDS_MODULE 允许我们设置自定义命令。例如，假设我们添加了一个 properties/hi.py 文件：

```py
from scrapy.commands import ScrapyCommand
class Command(ScrapyCommand):
    default_settings = {'LOG_ENABLED': False}
    def run(self, args, opts):
        print("hello") 
```

一旦我们在 settings.py 加入了 COMMANDS_MODULE='properties.hi'，就可以在 Scrapy 的 help 中运行 hi 查看。在命令行的 default_settings 中定义的设置会与项目的设置合并，但是与 settings.py 文件的优先级比起来，它的优先级偏低。

Scrapy 使用-_BASE 字典（例如，FEED_EXPORTERS_BASE）来存储不同扩展框架的默认值，然后我们可以在 settings.py 文件和命令行中设置 non-_BASE 版本进行切换（例如，FEED_EXPORTERS）。

最后，Scrapy 使用设置，例如 DOWNLOADER 或 SCHEDULER，保管系统基本组件的包和类的名。我们可以继承默认的下载器（scrapy.core.downloader.Downloader），加载一些方法，在 DOWNLOADER 设置中自定义我们的类。这可以让开发者试验新特性、简化自动检测，但是只推荐专业人士这么做。

**微调下载**
RETRY_*, REDIRECT_*和 METAREFRESH_*设置分别配置了 Retry、Redirect、Meta-Refresh 中间件。例如，REDIRECT_PRIORITY_ 设为 2，意味着每次有重定向时，都会在没有重定向请求之后，预约一个新的请求。REDIRECT_MAX_TIMES 设为 20 意味着，在 20 次重定向之后，下载器不会再进行重定向，并返回现有值。当你抓取一些有问题的网站时，知道这些设置是很有用的，但是默认设置在大多数情况下就能应付了。HTTPERROR_ALLOWED_CODES 和 URLLENGTH_LIMIT 也类似。

**自动限定扩展设置**
AUTOTHROTTLE_*设置可以自动限定扩展。看起来有用，但在实际中，我发现很难用它进行调节。它使用下载延迟，并根据加载和指向服务器，调节下载器的延迟。如果你不能确定 DOWNLOAD_DELAY（默认是 0）的值，这个模块会派上用场。

**内存使用扩展设置**
MEMUSAGE_*设置可以配置内存使用扩展。当超出内存上限时，它会关闭爬虫。在共享环境中这会很有用，因为抓取过程要尽量小心。更多时候，你会将 MEMUSAGE_LIMIT_MB 设为 0，将自动关闭爬虫的功能取消，只接收警告 email。这个扩展只在类 Unix 平台有。

MEMDEBUG_ENABLED 和 MEMDEBUG_NOTIFY 可以配置内存调试扩展，可以在爬虫关闭时实时打印出参考的个数。阅读用 trackref 调试内存泄漏的文档，更重要的，我建议抓取过程最好简短、分批次，并匹配服务器的能力。我认为，每批次最好一千个网页、不超过几分钟。

**登录和调试**
最后，还有一些登录和调试的设置。LOG_ENCODING，LOG_DATEFORMAT 和 LOG_FORMAT 可以让你微调登录的方式，当你使用登录管理，比如 Splunk、Logstash 和 Kibana 时，你会觉得它很好用。DUPEFILTER_DEBUG 和 COOKIES_DEBUG 可以帮助你调试相对复杂的状况，比如，当你的请求数比预期少，或丢失 session 时。

**总结**
通过阅读本章，你一定会赞叹比起以前手写的爬虫，Scrapy 的功能更具深度和广度。如果你想微调或扩展 Scrapy 的功能，可以有大量的方法，见下面几章。

