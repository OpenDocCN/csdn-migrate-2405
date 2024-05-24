# Learning Scrapy 中文版（一）



# 零、序言

* * *

序言
[第 1 章 Scrapy 介绍](https://www.jianshu.com/p/b807653e97bb)
[第 2 章 理解 HTML 和 XPath](https://www.jianshu.com/p/90c2c25f0c41)
[第 3 章 爬虫基础](https://www.jianshu.com/p/6ebb898841bc)
[第 4 章 从 Scrapy 到移动应用](https://www.jianshu.com/p/4156e757557f)
[第 5 章 快速构建爬虫](https://www.jianshu.com/p/9d1e00dc40e4)
[第 6 章 Scrapinghub 部署](https://www.jianshu.com/p/441fa74d7aad)
[第 7 章 配置和管理](https://www.jianshu.com/p/674de4eacf15)
[第 8 章 Scrapy 编程](https://www.jianshu.com/p/545d07702e7f)
[第 9 章 使用 Pipeline](https://www.jianshu.com/p/e0287e773d28)
[第 10 章 理解 Scrapy 的性能](https://www.jianshu.com/p/e9710002cb4e)
[第 11 章（完） Scrapyd 分布式抓取和实时分析](https://www.jianshu.com/p/cfca4b7e62f4)

* * *

## 作者简介

Dimitris Kouzis – Loukas 有超过 15 年的软件开发经历。同时他也参与到教学活动中，受众广泛。

他精通数个领域，包括数学、物理和微电子。对这些学科的理解帮助使他得到了提高，超越了软件的“实用方案”。他认为，好的解决方案应该像物理学一样确定，像纠错内存一样拥有健壮性，并且像数学原理一样具有通用性。

Dimitris 现在正在使用最新的数据中心技术，着手开发分布式、低延迟、高可用性的系统。他运用多个编程语言，但更偏爱 Python、C++和 Java。作为开源软硬件的坚定支持者，他希望对独立开发群体和整个人类做出贡献。

* * *

## 审稿人简介

Lazar Telebak 是一名网络开发自由从业者，专精于网络抓取和利用 Python 库和框架进行网页索引。

他的主要工作涉及自动化、网络抓取和数据导出，导出为 CSV、JSON、XML 和 TXT 等多种格式，或是导出到 MongoDB、SQLAlchemy 和 Postgres 等数据库。

他还会使用网络前端技术：HTML、CSS、JS 和 Jquery。

* * *

## 序言

让我大胆猜一下，下面两个故事肯定有一个说的是你。

你第一次碰到 Scrapy 是在搜索“Python 网络抓取”的时候。你瞟了一眼 Scrapy 想，“这个太复杂，我需要个简单的。”然后你就开始用 requests 写 Python 代码，在 BeautifulSoup 上碰到点麻烦，但最后成功了。这个程序有点慢，所以你让它昼夜不停的运行。重启了几次、忽略了一些坏链和非英文字符，早上的时候，大部分网页都存在你的硬盘里了。但是，因为一些未知的技术原因，你再也不想看这段代码了。下次你再抓取网络的时候，你直接登录 scrapy.org，这次 Scrapy 文档看起来合理多了，感觉不用费力就可以解决所有问题。并且，Scrapy 还能解决你没想到的问题。你再也不用以前的方法了。

或者，你是在做网络抓取调研时碰到的 Scrapy。你需要一个可靠快速的企业级工具，毫无疑问，就是只要轻轻一击就能进行网络抓取。这个工具不仅要简单，而且可以根据不同的数据源进行灵活的定制，提供多种的数据输出方式，可以自动 24/7 的可靠运行。比起要价很高的提供网络抓取服务的公司，你偏向于开源的解决方案。从一开始，Scrapy 就是当然的选择。

无论你是如何听说 Scrapy 的，我都热烈欢迎你翻开这本专门为 Scrapy 而写的书。Scrapy 是全世界网络抓取专家的秘密武器。在专家手中，Scrapy 节省了大量时间，表现出众，花费最少。如果你缺少经验，但想像这些专家一样，很可惜，Google 帮不上你什么忙。网上关于 Scrapy 的大部分信息不是过于简化无效，就是太过复杂。对每个想获得准确、可用、规范的 Scrapy 知识的人，这是本必备的书。希望这本书可以扩大 Scrapy 社区，让 Scrapy 被更多人采用。

## 本书的内容

第 1 章，Scrapy 介绍，向你介绍这本书和 Scrapy，使你对 Scrapy 框架和后面章节有清醒的认识。

第 2 章，理解 HTML 和 XPath，让爬虫初学者掌握基础的网页相关技术，以及后面会使用到的技术。

第 3 章，爬虫基础，我们会学习如何安装 Scrapy 和抓取网站。通过一步步搭建实例，让读者理解方法和背后的逻辑。学过这一章，你就可以抓取大部分简单站点了。

第 4 章，从 Scrapy 到移动应用，我们如何使用爬虫生成数据库和向移动应用提供数据支持。通过这一章，你会明白如何用网络抓取获益。

第 5 章，快速构建爬虫，介绍更多关于爬虫的特点，模拟登陆、更快抓取、使用 APIs、爬 URL 的方法。

第 6 章，Scrapinghub 部署，如何将爬虫部署到 Scrapinghub 云服务器，以尝试更快的可用性、简易部署和操作。

第 7 章，配置和管理，详细介绍利用 Scrapy 的配置文件对爬虫进行改进。

第 8 章，Scrapy 编程，使用底层 Twisted 引擎和 Scrapy 架构扩展爬虫功能。

第 9 章，如何使用 Pipelines，在不明显降低性能的条件下，举例实现 Scrapy 连接 MySQL、Elasticsearch、Redis、APIs 和应用。

第 10 章，理解 Scrapy 的性能，Scrapy 的工作机制，如何提高 Scrapy 的性能。

第 11 章，Scrapyd 分布式抓取和实时分析，最后一章介绍如何在多台服务器中使用 Scrapyd 以实现水平伸缩性，并将数据传送到 Apache Spark 进行实时分析。

* * *

序言
[第 1 章 Scrapy 介绍](https://www.jianshu.com/p/b807653e97bb)
[第 2 章 理解 HTML 和 XPath](https://www.jianshu.com/p/90c2c25f0c41)
[第 3 章 爬虫基础](https://www.jianshu.com/p/6ebb898841bc)
[第 4 章 从 Scrapy 到移动应用](https://www.jianshu.com/p/4156e757557f)
[第 5 章 快速构建爬虫](https://www.jianshu.com/p/9d1e00dc40e4)
[第 6 章 Scrapinghub 部署](https://www.jianshu.com/p/441fa74d7aad)
[第 7 章 配置和管理](https://www.jianshu.com/p/674de4eacf15)
[第 8 章 Scrapy 编程](https://www.jianshu.com/p/545d07702e7f)
[第 9 章 使用 Pipeline](https://www.jianshu.com/p/e0287e773d28)
[第 10 章 理解 Scrapy 的性能](https://www.jianshu.com/p/e9710002cb4e)
[第 11 章（完） Scrapyd 分布式抓取和实时分析](https://www.jianshu.com/p/cfca4b7e62f4)

* * *

本书第二版会在 2018 年三月份出版。第二版的目标是对应 Scrapy 1.4 版本。但那时，恐怕 Scrapy 又要升级了。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/bdae4bb89924cc713758709f968ad163.jpg)
新版内容增加了 100 页，达到了 365 页。
[https://www.packtpub.com/big-data-and-business-intelligence/learning-scrapy-second-edition](https://link.jianshu.com?t=https://www.packtpub.com/big-data-and-business-intelligence/learning-scrapy-second-edition)

# 九、使用 Pipelines



在上一章，我们学习了如何辨析 Scrapy 中间件。在本章中，我们通过实例学习编写 pipelines，包括使用 REST APIs、连接数据库、处理 CPU 密集型任务、与老技术结合。

我们在本章中会使用集中新的数据库，列在下图的右边：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/f216a658ebb14e51e8055873ff0a6fd9.jpg)

Vagrant 已经配置好了数据库，我们可以从开发机向其发送 ping，例如 ping es 或 ping mysql。让我们先来学习 REST APIs。

## 使用 REST APIs

REST 是用来一套创建网络服务的技术集合。它的主要优点是，比起 SOAP 和专有 web 服务，REST 更简单和轻量。软件开发者注意到了 web 服务的 CRUD（Create、Read、Update、Delete）和 HTTP 操作（GET、POST、PUT、DELETE）的相似性。它们还注意到传统 web 服务调用需要的信息可以再 URL 源进行压缩。例如，[http://api.mysite.com/customer/john](https://link.jianshu.com?t=http://api.mysite.com/customer/john)是一个 URL 源，它可以让我们分辨目标服务器，，更具体的，名字是 john 的服务器（行的主键）。它与其它技术结合时，比如安全认证、无状态服务、缓存、输出 XML 或 JSON 时，可以提供一个强大但简单的跨平台服务。REST 席卷软件行业并不奇怪。

Scrapy pipeline 的功能可以用 REST API 来做。接下来，我们来学习它。

## 使用 treq

treq 是一个 Python 包，它在 Twisted 应用中和 Python 的 requests 包相似。它可以让我们做出 GET、POST、和其它 HTTP 请求。可以使用 pip install treq 安装，开发机中已经安装好了。

比起 Scrapy 的 Request/crawler.engine.download() API，我们使用 treq，因为后者具有性能优势，详见第 10 章。

## 一个写入 Elasticsearch 的 pipeline

我们从一个向 ES 服务器（Elasticsearch）写入 Items 的爬虫开始。你可能觉得从 ES 开始，而不是 MySQL，有点奇怪，但实际上 ES 是最容易的。ES 可以是无模式的，意味着我们可以不用配置就使用它。treq 也足以应付需要。如果想使用更高级的 ES 功能，我们应该使用 txes2 和其它 Python/Twisted ES 包。

有了 Vagrant，我们已经有个一个运行的 ES 服务器。登录开发机，验证 ES 是否运行：

```py
$ curl http://es:9200
{
  "name" : "Living Brain",
  "cluster_name" : "elasticsearch",
  "version" : { ... },
  "tagline" : "You Know, for Search"
} 
```

在浏览器中登录[http://localhost:9200](https://link.jianshu.com?t=http://localhost:9200)也可以看到相同的结果。如果访问[http://localhost:9200/properties/property/_search](https://link.jianshu.com?t=http://localhost:9200/properties/property/_search)，我们可以看到一个响应，说 ES 已经进行了全局尝试，但是没有找到索引页。

> 笔记：在本章中，我们会在项集合中插入新的项，如果你想恢复原始状态的话，可以用下面的命令：
> 
> ```py
> $ curl -XDELETE http://es:9200/properties 
> ```

本章中的 pipeline 完整代码还有错误处理的功能，但我尽量让这里的代码简短，以突出重点。

> 提示：本章位于目录 ch09，这个例子位于 ch09/properties/properties/pipelines/es.py。

本质上，这个爬虫只有四行：

```py
@defer.inlineCallbacks
def process_item(self, item, spider):
    data = json.dumps(dict(item), ensure_ascii=False).encode("utf- 8")
    yield treq.post(self.es_url, data) 
```

前两行定义了一个标准 process_item()方法，它可以产生延迟项。（参考第 8 章）

第三行准备了插入的 data。ensure_ascii=False 可使结果压缩，并且没有跳过非 ASCII 字符。我们然后将 JSON 字符串转化为 JSON 标准的默认编码 UTF-8。

最后一行使用了 treq 的 post()方法，模拟一个 POST 请求，将我们的文档插入 ElasticSearch。es_url，例如[http://es:9200/properties/property](https://link.jianshu.com?t=http://es:9200/properties/property)存在[settings.py](https://link.jianshu.com?t=http://settings.py)文件中（ES_PIPELINE_URL 设置），它提供重要的信息，例如我们想要写入的 ES 的 IP 和端口（es:9200）、集合名（properties）和对象类型（property）。

为了是 pipeline 生效，我们要在 settings.py 中设置 ITEM_PIPELINES，并启动 ES_PIPELINE_URL 设置：

```py
ITEM_PIPELINES = {
    'properties.pipelines.tidyup.TidyUp': 100,
    'properties.pipelines.es.EsWriter': 800,
}
ES_PIPELINE_URL = 'http://es:9200/properties/property' 
```

这么做完之后，我们前往相应的目录：

```py
$ pwd
/root/book/ch09/properties
$ ls
properties  scrapy.cfg 
```

然后运行爬虫：

```py
$ scrapy crawl easy -s CLOSESPIDER_ITEMCOUNT=90
...
INFO: Enabled item pipelines: EsWriter...
INFO: Closing spider (closespider_itemcount)...
   'item_scraped_count': 106, 
```

如果现在访问[http://localhost:9200/properties/property/_search](https://link.jianshu.com?t=http://localhost:9200/properties/property/_search)，除了前 10 条结果，我们可以在响应的 hits/total 字段看到插入的文件数。我们还可以添加参数?size=100 以看到更多的结果。通过添加 q= URL 搜索中的参数，我们可以在全域或特定字段搜索关键词。相关性最强的结果会首先显示出来。例如，[http://localhost:9200/properties/property/_search?q=title:london](https://link.jianshu.com?t=http://localhost:9200/properties/property/_search?q=title:london)，可以让标题变为 London。对于更复杂的查询，可以在[https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html](https://link.jianshu.com?t=https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html)查询 ES 文档。

ES 不需要配置，因为它根据提供的第一个文件，进行模式（字段类型）自动检测的。通过访问[http://localhost:9200/properties/](https://link.jianshu.com?t=http://localhost:9200/properties/)，我们可以看到它自动检测的映射。

再次运行 crawl easy -s CLOSESPIDER_ITEMCOUNT=1000。因为 pipelines 的平均时间从 0.12 变为 0.15 秒，平均延迟从 0.78 变为 0.81 秒。吞吐量仍保持每秒约 25 项。

> 笔记：用 pipelines 向数据库插入 Items 是个好方法吗？答案是否定的。通常来讲，数据库更简单的方法以大量插入数据，我们应该使用这些方法大量批次插入数据，或抓取完毕之后进行后处理。我们会在最后一章看到这些方法。然后，还是有很多人使用 pipelines 向数据库插入文件，相应的就要使用 Twisted APIs。

## pipeline 使用 Google Geocoding API 进行地理编码

我们的房子有各自所在的区域，我们还想对它们进行地理编码，即找到相应的坐标（经度、纬度）。我们可以将坐标显示在地图上，或计算距离。建这样的数据库需要复杂的数据库、复杂的文本匹配，还有复杂的空间计算。使用 Google Geocoding API，我们可以避免这些。在浏览器中打开它，或使用 curl 取回以下 URL 的数据：

```py
$ curl "https://maps.googleapis.com/maps/api/geocode/json?sensor=false&ad
dress=london"
{
   "results" : [
         ...
         "formatted_address" : "London, UK",
         "geometry" : {
            ...
            "location" : {
               "lat" : 51.5073509,
               "lng" : -0.1277583
          },
            "location_type" : "APPROXIMATE",
            ...
   ],
   "status" : "OK"
} 
```

我们看到一个 JSON 对象，如果搜索一个 location，我们可以快速获取伦敦中心的坐标。如果继续搜索，我们可以看到相同文件中海油其它地点。第一个是相关度最高的。因此如果存在 results[0].geometry.location 的话，它就是我们要的结果。

可以用前面的方法（treq）使用 Google Geocoding API。只需要几行，我们就可以找到一个地址的坐标（目录 pipelines 中的 geo.py），如下所示：

```py
@defer.inlineCallbacks
def geocode(self, address):
   endpoint = 'http://web:9312/maps/api/geocode/json'
   parms = [('address', address), ('sensor', 'false')]
   response = yield treq.get(endpoint, params=parms)
   content = yield response.json()
   geo = content['results'][0]["geometry"]["location"]
   defer.returnValue({"lat": geo["lat"], "lon": geo["lng"]}) 
```

这个函数做出了一条 URL，但我们让它指向一个可以离线快速运行的假程序。你可以使用 endpoint = '[https://maps.googleapis.com/maps/api/geocode/json'](https://link.jianshu.com?t=https://maps.googleapis.com/maps/api/geocode/json')连接 Google 服务器，但要记住它对请求的限制很严格。address 和 sensor 的值是 URL 自动编码的，使用 treq 的方法 get()的参数 params。对于第二个 yield，即 response.json()，我们必须等待响应主题完全加载完毕对解析为 Python 对象。此时，我们就可以找到第一个结果的地理信息，格式设为 dict，使用 defer.returnValue()返回，它使用了 inlineCallbacks。如果发生错误，这个方法会扔出例外，Scrapy 会向我们报告。

通过使用 geocode()，process_item()变成了一行语句：

```py
item["location"] = yield self.geocode(item["address"][0]) 
```

设置让 pipeline 生效，将它添加到 ITEM_PIPELINES，并设定优先数值，该数值要小于 ES 的，以让 ES 获取坐标值：

```py
ITEM_PIPELINES = {
    ...
    'properties.pipelines.geo.GeoPipeline': 400, 
```

开启数据调试，然后运行：

```py
$ scrapy crawl easy -s CLOSESPIDER_ITEMCOUNT=90 -L DEBUG
...
{'address': [u'Greenwich, London'],
...
 'image_URL': [u'http://web:93img/i06.jpg'],
 'location': {'lat': 51.482577, 'lon': -0.007659},
 'price': [1030.0],
... 
```

我们现在可以看到 Items 里的 location 字段。如果使用真正的 Google API 的 URL 运行，会得到例外：

```py
File "pipelines/geo.py" in geocode (content['status'], address))
Exception: Unexpected status="OVER_QUERY_LIMIT" for  
address="*London" 
```

这是为了检查我们在完整代码中插入了地点，以确保 Geocoding API 响应的 status 字段有 OK 值。除非是 OK，否则我们取回的数据不会有设定好的格式，进而不能使用。对于这种情况，我们会得到 OVER_QUERY_LIMIT 状态，它指明我们在某处做错了。这个问题很重要，也很常见。应用 Scrapy 的高性能引擎，进行缓存、限制请求就很必要了。

我们可以在 Geocoder API 的文档，查看它的限制，“每 24 小时，免费用户可以进行 2500 次请求，每秒 5 次请求”。即使我们使用付费版本，仍有每秒 10 次请求的限制，所以这里的分析是有意义的。

> 笔记：后面的代码看起来可能有些复杂，复杂度还要取决于实际情况。在多线程环境中创建这样的组件，需要线程池和同步，这样代码就会变复杂。

这是一个简易的运用 Twisted 技术的限制引擎：

```py
class Throttler(object):
    def __init__(self, rate):
        self.queue = []
        self.looping_call = task.LoopingCall(self._allow_one)
        self.looping_call.start(1\. / float(rate))
    def stop(self):
        self.looping_call.stop()
    def throttle(self):
        d = defer.Deferred()
        self.queue.append(d)
        return d
    def _allow_one(self):
        if self.queue:
            self.queue.pop(0).callback(None) 
```

这可以让延迟项在一个列表中排队，逐个触发，调用 _allow_one()；_allow_one()检查队列是否为空，如果不是，它会调用第一个延迟项的 callback()。我们使用 Twisted 的 task.LoopingCall() API，周期性调用 _allow_one()。使用 Throttler 很容易。我们在 pipeline 的**init**初始化它，当爬虫停止时清空它：

```py
class GeoPipeline(object):
    def __init__(self, stats):
        self.throttler = Throttler(5)  # 5 Requests per second
    def close_spider(self, spider):
        self.throttler.stop() 
```

在使用限定源之前，我们的例子是在 process_item()中调用 geocode()，必须 yield 限制器的 throttle()方法：

```py
yield self.throttler.throttle()
item["location"] = yield self.geocode(item["address"][0]) 
```

对于第一个 yield，代码会暂停一下，一段时间之后，会继续运行。例如，当某时有 11 个延迟项时，限制是每秒 5 次请求，即时间为 11/5=2.2 秒之后，队列变空，代码会继续。

使用 Throttler，不再有错误，但是爬虫会变慢。我们看到示例中的房子只有几个不同的地址。这时使用缓存非常好。我们使用一个简单的 Python dict 来做，但这么可能会有竞争条件，这样会造成伪造的 API 请求。下面是一个没有此类问题的缓存方法，展示了 Python 和 Twisted 的特点：

```py
class DeferredCache(object):
    def __init__(self, key_not_found_callback):
        self.records = {}
        self.deferreds_waiting = {}
        self.key_not_found_callback = key_not_found_callback
    @defer.inlineCallbacks
    def find(self, key):
        rv = defer.Deferred()
        if key in self.deferreds_waiting:
            self.deferreds_waiting[key].append(rv)
        else:
            self.deferreds_waiting[key] = [rv]
            if not key in self.records:
                try:
                    value = yield self.key_not_found_callback(key)
                    self.records[key] = lambda d: d.callback(value)
                except Exception as e:
                    self.records[key] = lambda d: d.errback(e)
            action = self.records[key]
            for d in self.deferreds_waiting.pop(key):
                reactor.callFromThread(action, d)
        value = yield rv
        defer.returnValue(value) 
```

这个缓存看起来有些不同，它包含两个组件：

*   self.deferreds_waiting：这是一个延迟项的队列，等待给键赋值
*   self.records：这是键值对中出现过的 dict

在 find()方法的中间，如果没有在 self.records 找到一个键，我们会调用预先定义的 callback 函数，以取回丢失的值（yield self.key_not_found_callback(key)）。这个调回函数可能会扔出一个例外。如何在 Python 中压缩存储值或例外呢？因为 Python 是一种函数语言，根据是否有例外，我们在 self.records 中保存小函数（lambdas），调用 callback 或 errback。lambda 函数定义时，就将值或例外附着在上面。将变量附着在函数上称为闭包，闭包是函数语言最重要的特性之一。

> 笔记：缓存例外有点不常见，但它意味着首次查找 key 时，key_not_found_callback(key)返回了一个例外。当后续查找还找这个 key 时，就免去了调用，再次返回这个例外。

find()方法其余的部分提供了一个避免竞争条件的机制。如果查找某个键已经在进程中，会在 self.deferreds_waiting dict 中有记录。这时，我们不在向 key_not_found_callback()发起另一个调用，只是在延迟项的等待列表添加这个项。当 key_not_found_callback()返回时，键有了值，我们触发所有的等待这个键的延迟项。我们可以直接发起 action(d)，而不用 reactor.callFromThread()，但需要处理每个扔给下游的例外，我们必须创建不必要的很长的延迟项链。

使用这个缓存很容易。我们在**init**()对其初始化，设定调回函数为 API 调用。在 process_item()中，使用缓存查找的方法如下：

```py
def __init__(self, stats):
    self.cache = DeferredCache(self.cache_key_not_found_callback)
@defer.inlineCallbacks
def cache_key_not_found_callback(self, address):
    yield self.throttler.enqueue()
    value = yield self.geocode(address)
    defer.returnValue(value)
@defer.inlineCallbacks
def process_item(self, item, spider):
    item["location"] = yield self.cache.find(item["address"][0])
    defer.returnValue(item) 
```

> 提示：完整代码位于 ch09/properties/properties/pipelines/geo2.py。

为了使 pipeline 生效，我们使前一个方法无效，并添加当前的到 settings.py 的 ITEM_PIPELINES：

```py
ITEM_PIPELINES = {
    'properties.pipelines.tidyup.TidyUp': 100,
    'properties.pipelines.es.EsWriter': 800,
    # DISABLE 'properties.pipelines.geo.GeoPipeline': 400,
    'properties.pipelines.geo2.GeoPipeline': 400,
} 
```

运行爬虫，用如下代码：

```py
$ scrapy crawl easy -s CLOSESPIDER_ITEMCOUNT=1000
...
Scraped... 15.8 items/s, avg latency: 1.74 s and avg time in pipelines: 
0.94 s
Scraped... 32.2 items/s, avg latency: 1.76 s and avg time in pipelines: 
0.97 s
Scraped... 25.6 items/s, avg latency: 0.76 s and avg time in pipelines: 
0.14 s
...
: Dumping Scrapy stats:...
   'geo_pipeline/misses': 35,
   'item_scraped_count': 1019, 
```

当填充缓存时，我们看到抓取的延迟变高。缓存结束时，延迟降低。数据还显示有 35 个遗漏，正好是数据集中不同地点的数目。很明显，上例中一共有 1019 - 35= 984 次 API 请求。如果我们使用真正的 Google API，并提高每秒的 API 请求数，例如通过改变 Throttler(5)到 Throttler(10)，使从 5 提高到 10，我们可以将重试添加到 geo_pipeline/retries stat 记录中。如果有错误的话，例如，使用 API 找不到某个地点，会扔出一个例外，这会被 geo_pipeline/errors stat 记录。如果地点通过什么方式已经存在了，会在 geo_pipeline/already_set stat 中指明。最后，如果我们访问[http://localhost:9200/properties/property/_search](https://link.jianshu.com?t=http://localhost:9200/properties/property/_search)，以检查 ES 中的房子，我们可以看到包括地点的记录，例如{..."location": {"lat": 51.5269736, "lon": -0.0667204}...}。（运行前确保清空集合，去除旧的值）

## 在 Elasticsearch 进行地理索引

我们已经有了地点，我们可以将它们按距离排序。下面是一个 HTTP POST 请求，返回标题中包含 Angel 的房子，按照离点{51.54, -0.19}的距离进行排序：

```py
$ curl http://es:9200/properties/property/_search -d '{
    "query" : {"term" : { "title" : "angel" } },
    "sort": [{"_geo_distance": {
        "location":      {"lat":  51.54, "lon": -0.19},
        "order":         "asc",
        "unit":          "km", 
        "distance_type": "plane" 
}}]}' 
```

唯一的问题是如果我们运行它，我们会看到一个错误信息"failed to find mapper for [location] for geo distance based sort"。它指出，我们的 location 字段没有正确的空间计算的格式。为了设定正确的格式，我们要手动覆盖默认格式。首先，我们将自动检测的映射保存起来，将它作为起点：

```py
$ curl 'http://es:9200/properties/_mapping/property' > property.txt 
```

然后，我们如下所示编辑 property.txt：

```py
"location":{"properties":{"lat":{"type":"double"},"lon":{"type":"double"}}} 
```

我们将这行代码替换为：

```py
"location": {"type": "geo_point"} 
```

我们还在文件最后删除了{"properties":{"mappings": and two }}。文件现在就处理完了。我们现在可以删除旧的类型，并用下面的 schema 建立新的类型：

```py
$ curl -XDELETE 'http://es:9200/properties'
$ curl -XPUT 'http://es:9200/properties'
$ curl -XPUT 'http://es:9200/properties/_mapping/property' --data  
@property.txt 
```

我们现在可以用之前的命令，进行一个快速抓取，将结果按距离排序。我们的搜索返回的是房子的 JSONs 对象，其中包括一个额外的 sort 字段，显示房子离某个点的距离。

## 连接数据库与 Python 客户端

可以连接 Python Database API 2.0 的数据库有许多种，包括 MySQL、PostgreSQL、Oracle、Microsoft、SQL Server 和 SQLite。它们的驱动通常很复杂且进行过测试，为 Twisted 再进行适配会浪费很多时间。可以在 Twisted 应用中使用数据库客户端，例如，Scrapy 可以使用 twisted.enterprise.adbapi 库。我们使用 MySQL 作为例子，说明用法，原则也适用于其他数据库。

## 用 pipeline 写入 MySQL

MySQL 是一个好用又流行的数据库。我们来写一个 pipeline，来向其中写入文件。我们的虚拟环境中，已经有了一个 MySQL 实例。我们用 MySQL 命令行来做一些基本的管理操作，命令行工具已经在开发机中预先安装了：

```py
$ mysql -h mysql -uroot -ppass 
```

mysql>提示 MySQL 已经运行，我们可以建立一个简单的含有几个字段的数据表，如下所示：

```py
mysql> create database properties;
mysql> use properties
mysql> CREATE TABLE properties (
  url varchar(100) NOT NULL,
  title varchar(30),
  price DOUBLE,
  description varchar(30),
  PRIMARY KEY (url)
);
mysql> SELECT * FROM properties LIMIT 10;
Empty set (0.00 sec) 
```

很好，现在已经建好了一个包含几个字段的 MySQL 数据表，它的名字是 properties，可以开始写 pipeline 了。保持 MySQL 控制台打开，我们过一会儿会返回查看是否有差入值。输入 exit，就可以退出。

> 笔记：在这一部分中，我们会向 MySQL 数据库插入 properties。如果你想删除，使用以下命令：
> 
> ```py
> mysql> DELETE FROM properties; 
> ```

我们使用 MySQL 的 Python 客户端。我们还要安装一个叫做 dj-database-url 的小功能模块（它可以帮我们设置不同的 IP、端口、密码等等）。我们可以用 pip install dj-database-url MySQL-python，安装这两项。我们的开发机上已经安装好了。我们的 MySQL pipeline 很简单，如下所示：

```py
from twisted.enterprise import adbapi
...
class MysqlWriter(object):
    ...
    def __init__(self, mysql_url):
        conn_kwargs = MysqlWriter.parse_mysql_url(mysql_url)
        self.dbpool = adbapi.ConnectionPool('MySQLdb',
                                            charset='utf8',
                                            use_unicode=True,
                                            connect_timeout=5,
                                            **conn_kwargs)
    def close_spider(self, spider):
        self.dbpool.close()
    @defer.inlineCallbacks
    def process_item(self, item, spider):
        try:
            yield self.dbpool.runInteraction(self.do_replace, item)
        except:
            print traceback.format_exc()
        defer.returnValue(item)
    @staticmethod
    def do_replace(tx, item):
        sql = """REPLACE INTO properties (url, title, price, description) VALUES (%s,%s,%s,%s)"""
        args = (
            item["url"][0][:100],
            item["title"][0][:30],
            item["price"][0],
            item["description"][0].replace("\r\n", " ")[:30]
        )
        tx.execute(sql, args) 
```

> 提示：完整代码位于 ch09/properties/properties/pipelines/mysql.py。

本质上，这段代码的大部分都很普通。为了简洁而省略的代码将一条保存在 MYSQL_PIPELINE_URL、格式是[mysql://user:pass@ip/database](https://link.jianshu.com?t=mysql://user:pass@ip/database)的 URL，解析成了独立的参数。在爬虫的**init**()中，将它们传递到 adbapi.ConnectionPool()，它使用 adbapi 的底层结构，初始化 MySQL 连接池。第一个参数是我们想要引入的模块的名字。对于我们的 MySQL，它是 MySQLdb。我们为 MySQL 客户端另设了几个参数，以便正确处理 Unicode 和超时。每当 adbapi 打开新连接时，所有这些参数都要进入底层的 MySQLdb.connect()函数。爬虫关闭时，我们调用连接池的 close()方法。

我们的 process_item()方法包装了 dbpool.runInteraction()。这个方法给调回方法排队，会在当连接池中一个连接的 Transaction 对象变为可用时被调用。这个 Transaction 对象有一个和 DB-API 指针相似的 API。在我们的例子中，调回方法是 do_replace()，它定义在后面几行。@staticmethod 是说这个方法关联的是类而不是具体的类实例，因此，我们可以忽略通常的 self 参数。如果方法不使用成员的话，最好设其为静态，如果你忘了设为静态也不要紧。这个方法准备了一个 SQL 字符串、几个参数，并调用 Transaction 的 execute()函数，以进行插入。我们的 SQL 使用 REPLACE INTO，而不用更常见的 INSERT INTO，来替换键相同的项。这可以让我们的案例简化。如果我们相拥 SQL 返回数据，例如 SELECT 声明，我们使用 dbpool.runQuery()，我们可能还需要改变默认指针，方法是设置 adbapi.ConnectionPool()的参数 cursorclass 为 cursorclass=MySQLdb.cursors，这样取回数据更为简便。

使用这个 pipeline，我们要在 settings.py 的 ITEM_PIPELINES 添加它，还要设置一下 MYSQL_PIPELINE_URL：

```py
ITEM_PIPELINES = { ...
    'properties.pipelines.mysql.MysqlWriter': 700,
...
MYSQL_PIPELINE_URL = 'mysql://root:pass@mysql/properties' 
```

执行以下命令：

```py
scrapy crawl easy -s CLOSESPIDER_ITEMCOUNT=1000 
```

运行这条命令后，返回 MySQL 控制台，可以看到如下记录：

```py
mysql> SELECT COUNT(*) FROM properties;
+----------+
|     1006 |
+----------+
mysql> SELECT * FROM properties LIMIT 4;
+------------------+--------------------------+--------+-----------+
| url              | title                    | price  | description
+------------------+--------------------------+--------+-----------+
| http://...0.html | Set Unique Family Well   | 334.39 | website c
| http://...1.html | Belsize Marylebone Shopp | 388.03 | features                       
| http://...2.html | Bathroom Fully Jubilee S | 365.85 | vibrant own
| http://...3.html | Residential Brentford Ot | 238.71 | go court
+------------------+--------------------------+--------+-----------+
4 rows in set (0.00 sec) 
```

延迟和吞吐量的性能和之前相同。结果让人印象深刻。

## 使用 Twisted 特定客户端连接服务

目前为止，我们学习了如何用 treq 使用类 REST APIs。Scrapy 可以用 Twisted 特定客户端连接许多其它服务。例如，如果我们想连接 MongoDB，通过搜索“MongoDB Python”，我们可以找到 PyMongo，它是阻塞/同步的，除非我们使用 pipeline 处理阻塞操作中的线程，我们不能在 Twisted 中使用 PyMongo。如果我们搜索“MongoDB Twisted Python”，可以找到 txmongo，它可以完美适用于 Twisted 和 Scrapy。通常的，Twisted 客户端群体很小，但使用它比起自己写一个客户端还是要方便。下面，我们就使用这样一个 Twisted 特定客户端连接 Redis 键值对存储。

## 用 pipeline 读写 Redis

Google Geocoding API 是按照每个 IP 进行限制的。如果可以接入多个 IPs（例如，多台服务器），当一个地址已经被另一台机器做过地理编码，就要设法避免对发出重复的请求。如果一个地址之前已经被查阅过，也要避免再次查阅。我们不想浪费限制的额度。

> 笔记：与 API 商家联系，以确保这符合规定。你可能，必须每几分钟/小时，就要清空缓存记录，或者根本就不能缓存。

我们可以使用 Redis 键值缓存作为分布式 dict。Vagrant 环境中已经有了一个 Redis 实例，我们现在可以连接它，用 redis-cli 作一些基本操作：

```py
$ redis-cli -h redis
redis:6379> info keyspace
# Keyspace
redis:6379> set key value
OK
redis:6379> info keyspace
# Keyspace
db0:keys=1,expires=0,avg_ttl=0
redis:6379> FLUSHALL
OK
redis:6379> info keyspace
# Keyspace
redis:6379> exit 
```

通过搜索“Redis Twisted”，我们找到一个 txredisapi 库。它最大的不同是，它不仅是一个 Python 的同步封装，还是一个 Twisted 库，可以通过 reactor.connectTCP()，执行 Twisted 协议，连接 Redis。其它库也有类似用法，但是 txredisapi 对于 Twisted 效率更高。我们可以通过安装库 dj_redis_url 可以安装它，这个库通过 pip 可以解析 Redis 配置 URL（sudo pip install txredisapi dj_redis_url）。和以前一样，开发机中已经安装好了。

我们如下启动 RedisCache pipeline：

```py
from txredisapi import lazyConnectionPool
class RedisCache(object):
...
    def __init__(self, crawler, redis_url, redis_nm):
        self.redis_url = redis_url
        self.redis_nm = redis_nm
        args = RedisCache.parse_redis_url(redis_url)
        self.connection = lazyConnectionPool(connectTimeout=5,
                                             replyTimeout=5,
                                             **args)
        crawler.signals.connect(
                self.item_scraped,signal=signals.item_scraped) 
```

这个 pipeline 比较简单。为了连接 Redis 服务器，我们需要主机、端口等等，它们全都用 URL 格式存储。我们用 parse_redis_url()方法解析这个格式。使用命名空间做键的前缀很普遍，在我们的例子中，我们存储在 redis_nm。我们然后使用 txredisapi 的 lazyConnectionPool()打开一个数据库连接。

最后一行有一个有趣的函数。我们是想用 pipeline 封装 geo-pipeline。如果在 Redis 中没有某个值，我们不会设定这个值，geo-pipeline 会用 API 像之前一样将地址进行地理编码。完毕之后，我们必须要在 Redis 中缓存键值对，我们是通过连接 signals.item_scraped 信号来做的。我们定义的调回（即 item_scraped()方法，马上会讲）只有在最后才会被调用，那时，地址就设置好了。

> 提示：完整代码位于 ch09/properties/properties/pipelines/redis.py。

我们简化缓存，只寻找和存储每个 Item 的地址和地点。这对 Redis 来说是合理的，因为它通常是运行在单一服务器上的，这可以让它很快。如果不是这样的话，可以加入一个 dict 结构的缓存，它与我们在 geo-pipeline 中用到的相似。以下是我们如何处理入库的 Items：

```py
process incoming Items:
@defer.inlineCallbacks
def process_item(self, item, spider):
    address = item["address"][0]
    key = self.redis_nm + ":" + address
    value = yield self.connection.get(key)
    if value:
        item["location"] = json.loads(value)
    defer.returnValue(item) 
```

和预期的相同。我们得到了地址，给它添加前缀，然后使用 txredisapi connection 的 get()在 Redis 进行查找。我们将 JSON 编码的对象在 Redis 中保存成值。如果一个值设定了，我们就使用 JSON 解码，然后将其设为地点。

当一个 Item 到达 pipelines 的末端时，我们重新取得它，将其保存为 Redis 中的地点值。以下是我们的做法：

```py
 from txredisapi import ConnectionError
    def item_scraped(self, item, spider):
        try:
            location = item["location"]
            value = json.dumps(location, ensure_ascii=False)
        except KeyError:
            return
        address = item["address"][0]
        key = self.redis_nm + ":" + address
        quiet = lambda failure: failure.trap(ConnectionError)
        return self.connection.set(key, value).addErrback(quiet) 
```

如果我们找到了一个地点，我们就取得了地址，添加前缀，然后使用它作为 txredisapi 连接的 set()方法的键值对。set()方法没有使用@defer.inlineCallbacks，因为处理 signals.item_scraped 时，它不被支持。这意味着，我们不能对 connection.set()使用 yield，但是我们可以返回一个延迟项，Scrapy 可以在它后面排上其它信号对象。任何情况下，如果 Redis 的连接不能使用用 connection.set()，它就会抛出一个例外。在这个错误处理中，我们把传递的错误当做参数，我们让它 trap()任何 ConnectionError。这是 Twisted 的延迟 API 的优点之一。通过用 trap()捕获错误项，我们可以轻易忽略它们。

使这个 pipeline 生效，我们要做的是在 settings.py 的 ITEM_PIPELINES 中添加它，并提供一个 REDIS_PIPELINE_URL。必须要让它的优先级比 geo-pipeline 高，以免太晚就不能使用了：

```py
ITEM_PIPELINES = { ...
    'properties.pipelines.redis.RedisCache': 300,
    'properties.pipelines.geo.GeoPipeline': 400,
...
REDIS_PIPELINE_URL = 'redis://redis:6379' 
```

像之前一样运行。第一次运行时和以前很像，但随后的运行结果如下：

```py
$ scrapy crawl easy -s CLOSESPIDER_ITEMCOUNT=100
...
INFO: Enabled item pipelines: TidyUp, RedisCache, GeoPipeline, 
MysqlWriter, EsWriter
...
Scraped... 0.0 items/s, avg latency: 0.00 s, time in pipelines: 0.00 s
Scraped... 21.2 items/s, avg latency: 0.78 s, time in pipelines: 0.15 s
Scraped... 24.2 items/s, avg latency: 0.82 s, time in pipelines: 0.16 s
...
INFO: Dumping Scrapy stats: {...
   'geo_pipeline/already_set': 106,
   'item_scraped_count': 106, 
```

我们看到 GeoPipeline 和 RedisCache 都生效了，RedisCache 第一个输出。还注意到在统计中 geo_pipeline/already_set: 106。这是 GeoPipeline 发现的 Redis 缓存中填充的数目，它不调用 Google API。如果 Redis 缓存是空的，你会看到 Google API 处理了一些键。从性能上来讲，我们看到 GeoPipeline 引发的初始行为消失了。事实上，当我们开始使用内存，我们绕过了每秒只有 5 次请求的 API 限制。如果我们使用 Redis，应该考虑使用过期键，让系统周期刷新缓存数据。

## 连接 CPU 密集型、阻塞或旧方法

最后一部分讲连接非 Twisted 的工作。尽管异步程序的优点很多，并不是所有库都专门为 Twisted 和 Scrapy 写的。使用 Twisted 的线程池和 reactor.spawnProcess()方法，我们可以使用任何 Python 库和任何语言写的编码。

## pipeline 进行 CPU 密集型和阻塞操作

我们在第 8 章中强调，反应器适合简短非阻塞的任务。如果我们不得不要处理复杂和阻塞的任务，又该怎么做呢？Twisted 提供了线程池，有了它可以使用 reactor.callInThread() API 在分线程而不是主线程中执行慢操作。这意味着，反应器可以一直运行并对事件反馈，而不中断计算。但要记住，在线程池中运行并不安全，当你使用全局模式时，会有多线程的同步问题。让我们从一个简单的 pipeline 开始，逐渐做出完整的代码：

```py
class UsingBlocking(object):
    @defer.inlineCallbacks
    def process_item(self, item, spider):
        price = item["price"][0]
        out = defer.Deferred()
        reactor.callInThread(self._do_calculation, price, out)
    item["price"][0] = yield out
        defer.returnValue(item)
    def _do_calculation(self, price, out):
        new_price = price + 1
        time.sleep(0.10)
        reactor.callFromThread(out.callback, new_price) 
```

在前面的 pipeline 中，我们看到了一些基本用法。对于每个 Item，我们提取出价格，我们相用 _do_calucation()方法处理它。这个方法使用 time.sleep()，一个阻塞操作。我们用 reactor.callInThread()调用，让它在另一个线程中运行。显然，我们传递价格，我们还创建和传递了一个名为 out 的延迟项。当 _do_calucation()完成了计算，我们使用 out 调回值。下一步，我们执行延迟项，并未价格设新的值，最后返回 Item。

在 _do_calucation()中，有一个细微之处，价格增加了 1，进而睡了 100ms。这个时间很多，如果调用进反应器主线程，每秒就不能抓取 10 页了。通过在另一个线程中运行，就不会再有这个问题。任务会在线程池中排队，每次处理耗时 100ms。最后一步是触发调回。一般的，我们可以使用 out.callback(new_price)，但是因为我们现在是在另一个线程，这么做不安全。如果这么做的话，延迟项的代码会被从另一个线程调用，这样迟早会产生错误的数据。不这样做，转而使用 reactor.callFromThread()，它也可以将函数当做参数，将任意其余参数传递到函数。这个函数会排队并被调回主线程，主进程反过来会打开 process_item()对象 yield，并继续 Item 的操作。

如果我们用全局模式，例如计数器、滑动平均，又该怎么使用 _do_calucation()呢？例如，添加两个变量，beta 和 delta，如下所示：

```py
class UsingBlocking(object):
    def __init__(self):
        self.beta, self.delta = 0, 0
    ...
    def _do_calculation(self, price, out):
        self.beta += 1
        time.sleep(0.001)
self.delta += 1
        new_price = price + self.beta - self.delta + 1
        assert abs(new_price-price-1) < 0.01
        time.sleep(0.10)... 
```

这段代码是断言失败错误。这是因为如果一个线程在 self.beta 和 self.delta 间切换，另一个线程继续计算使用 beta/delta 计算价格，它会发现它们状态不一致（beta 大于 delta），因此，计算出错误的结果。短暂的睡眠可能会造成竞争条件。为了不发生这些状况，我们要使一个锁，例如 Python 的 threading.RLock()递归锁。使用它，可以确保没有两个线程在同一时间操作被保护代码：

```py
class UsingBlocking(object):
    def __init__(self):
        ...
        self.lock = threading.RLock()
    ...
    def _do_calculation(self, price, out):
        with self.lock:
            self.beta += 1
            ...
            new_price = price + self.beta - self.delta + 1
        assert abs(new_price-price-1) < 0.01 ... 
```

代码现在就正确了。记住，我们不需要保护整段代码，就足以处理全局模式。

> 提示：完整代码位于 ch09/properties/properties/pipelines/computation.py。

要使用这个 pipeline，我们需要把它添加到 settings.py 的 ITEM_PIPELINES 中。如下所示：

```py
ITEM_PIPELINES = { ...
    'properties.pipelines.computation.UsingBlocking': 500, 
```

像之前一样运行爬虫，pipeline 延迟达到了 100ms，但吞吐量没有发生变化，大概每秒 25 个 items。

## pipeline 使用二进制和脚本

最麻烦的借口当属独立可执行文件和脚本。打开需要几秒（例如，从数据库加载数据），但是后面处理数值的延迟很小。即便是这种情况，Twisted 也预料到了。我们可以使用 reactor.spawnProcess() API 和相关的 protocol.ProcessProtocol 来运行任何执行文件。让我们来看一个例子。脚本如下：

```py
#!/bin/bash
trap "" SIGINT
sleep 3
while read line
do
    # 4 per second
    sleep 0.25
    awk "BEGIN {print 1.20 * $line}"
done 
```

这是一个简单的 bash 脚本。它运行时，会使 Ctrl + C 无效。这是为了避免系统的一个奇怪的错误，将 Ctrl + C 增值到子流程并过早结束，导致 Scrapy 强制等待流程结果。在使 Ctrl + C 无效之后，它睡眠三秒，模拟启动时间。然后，它阅读输入的代码语句，等待 250ms，然后返回结果价格，价格的值乘以了 1.20，由 Linux 的 awk 命令计算而得。这段脚本的最大吞吐量为每秒 1/250ms=4 个 Items。用一个短 session 检测：

```py
$ properties/pipelines/legacy.sh 
12 <- If you type this quickly you will wait ~3 seconds to get results
14.40
13 <- For further numbers you will notice just a slight delay
15.60 
```

因为 Ctrl + C 失效了，我们用 Ctrl + D 必须结束 session。我们该如何让 Scrapy 使用这个脚本呢？再一次，我们从一个简化版开始：

```py
class CommandSlot(protocol.ProcessProtocol):
    def __init__(self, args):
      self._queue = []
        reactor.spawnProcess(self, args[0], args)
    def legacy_calculate(self, price):
        d = defer.Deferred()
        self._queue.append(d)
        self.transport.write("%f\n" % price)
        return d
    # Overriding from protocol.ProcessProtocol
    def outReceived(self, data):
        """Called when new output is received"""
        self._queue.pop(0).callback(float(data))
class Pricing(object):
    def __init__(self):
        self.slot = CommandSlot(['properties/pipelines/legacy.sh'])
    @defer.inlineCallbacks
    def process_item(self, item, spider):
        item["price"][0] = yield self.slot.legacy_calculate(item["price"][0])
       defer.returnValue(item) 
```

我们在这里找到了一个名为 CommandSlot 的 ProcessProtocol 和 Pricing 爬虫。在**init**()中，我们创建了新的 CommandSlot，它新建了一个空的队列，并用 reactor.spawnProcess()开启了一个新进程。它调用收发数据的 ProcessProtocol 作为第一个参数。在这个例子中，是 self 的原因是 spawnProcess()是被从类 protocol 调用的。第二个参数是可执行文件的名字，第三个参数 args，让二进制命令行参数成为字符串序列。

在 pipeline 的 process_item()中，我们用 CommandSlot 的 legacy_calculate()方法代表所有工作，CommandSlot 可以返回产生的延迟项。legacy_calculate()创建延迟项，将其排队，用 transport.write()将价格写入进程。ProcessProtocol 提供了 transport，可以让我们与进程沟通。无论何时我们从进程收到数据， outReceived()就会被调用。通过延迟项，进程依次执行，我们可以弹出最老的延迟项，用收到的值触发它。全过程就是这样。我们可以让这个 pipeline 生效，通过将它添加到 ITEM_PIPELINES：

```py
ITEM_PIPELINES = {...
    'properties.pipelines.legacy.Pricing': 600, 
```

如果运行的话，我们会看到性能很差。进程变成了瓶颈，限制了吞吐量。为了提高性能，我们需要修改 pipeline，允许多个进程并行运行，如下所示：

```py
class Pricing(object):
    def __init__(self):
        self.concurrency = 16
        args = ['properties/pipelines/legacy.sh']
        self.slots = [CommandSlot(args) 
                      for i in xrange(self.concurrency)]
        self.rr = 0
    @defer.inlineCallbacks
    def process_item(self, item, spider):
        slot = self.slots[self.rr]
        self.rr = (self.rr + 1) % self.concurrency
        item["price"][0] = yield
                         slot.legacy_calculate(item["price"][0])
        defer.returnValue(item) 
```

这无非是开启 16 个实例，将价格以轮转的方式发出。这个 pipeline 的吞吐量是每秒 16*4 = 64。我们可以用下面的爬虫进行验证：

```py
 $ scrapy crawl easy -s CLOSESPIDER_ITEMCOUNT=1000
...
Scraped... 0.0 items/s, avg latency: 0.00 s and avg time in pipelines: 
0.00 s
Scraped... 21.0 items/s, avg latency: 2.20 s and avg time in pipelines: 
1.48 s
Scraped... 24.2 items/s, avg latency: 1.16 s and avg time in pipelines: 
0.52 s 
```

延迟增加了 250 ms，但吞吐量仍然是每秒 25。
请记住前面的方法使用了 transport.write()让所有的价格在脚本 shell 中排队。这个可能对你的应用不适用，，尤其是当数据量很大时。Git 的完整代码让值和调回都进行了排队，不想脚本发送值，除非收到前一项的结果。这种方法可能看起来更友好，但是会增加代码复杂度。

## 总结

你刚刚学习了复杂的 Scrapy pipelines。目前为止，你应该就掌握了所有和 Twisted 编程相关的知识。并且你学会了如何在进程中执行复杂的功能，用 Item Processing Pipelines 存储 Items。我们看到了添加 pipelines 对延迟和吞吐量的影响。通常，延迟和吞吐量是成反比的。但是，这是在恒定并发数的前提下（例如，一定数量的线程）。在我们的例子中，我们一开始的并发数为 N=S*T=25*0.77≅19,添加 pipelines 之后，并发数为 N=25*3.33≅83，并没有引起性能的变化。这就是 Twisted 的强大之处！下面学习第 10 章，Scrapy 的性能。



# 十、理解 Scrapy 的性能



通常，很容易将性能理解错。对于 Scrapy，几乎一定会把它的性能理解错，因为这里有许多反直觉的地方。除非你对 Scrapy 的结构有清楚的了解，你会发现努力提升 Scrapy 的性能却收效甚微。这就是处理高性能、低延迟、高并发环境的复杂之处。对于优化瓶颈， Amdahl 定律仍然适用，但除非找到真正的瓶颈，吞吐量并不会增加。要想学习更多，可以看 Dr.Goldratt 的《目标》这本书，其中用比喻讲到了更多关于瓶延迟、吞吐量的知识。本章就是来帮你确认 Scrapy 配置的瓶颈所在，让你避免明显的错误。

请记住，本章相对较难，涉及到许多数学。但计算还算比较简单，并且有图表示意。如果你不喜欢数学，可以直接忽略公式，这样仍然可以搞明白 Scrapy 的性能是怎么回事。

## Scrapy 的引擎——一个直观的方法

并行系统看起来就像管道系统。在计算机科学中，我们使用队列符表示队列并处理元素（见图 1 的左边）。队列系统的基本定律是 Little 定律，它指明平衡状态下，队列系统中的总元素个数（N）等于吞吐量（T）乘以总排队/处理时间（S），即 N=T*S。另外两种形式，T=N/S 和 S=N/T 也十分有用。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/5c85890389f3d7bf4500a683fc3bd775.jpg)图 1 Little 定律、队列系统、管道

管道（图 1 的右边）在几何学上也有一个相似的定律。管道的体积（V）等于长度（L）乘以横截面积（A），即 V=L*A。

如果假设 L 代表处理时间 S（L≈S），体积代表总元素个数（V≈N），横截面积啊代表吞吐量（A≈T），Little 定律和体积公式就是相同的。

> 提示：这个类比合理吗？答案是基本合理。如果我们想象小液滴在管道中以匀速流过，那么 L≈S 就完全合理，因为管道越长，液滴流过的时间也越长。V≈N 也是合理的，因为管道越大，它能容下的液滴越多。但是，我们可以通过增大压力的方法，压入更多的液滴。A≈T 是真正的类比。在管道中，吞吐量是每秒流进/流出的液滴总数，被称为体积流速，在正常的情况下，它与 A^2 成正比。这是因为更宽的管道不仅意味更多的液体流出，还具有更快的速度，因为管壁之间的空间变大了。但对于这一章，我们可以忽略这一点，假设压力和速度是不变的，吞吐量只与横截面积成正比。

Little 定律与体积公式十分相似，所以管道模型直观上是正确的。再看看图 1 中的右半部。假设管道代表 Scrapy 的下载器。第一个十分细的管道，它的总体积/并发等级（N）=8 个并发请求。长度/延迟（S）对于一个高速网站，假设为 S=250ms。现在可以计算横街面积/吞吐量 T=N/S=8/0.25=32 请求/秒。

可以看到，延迟率是手远程服务器和网络延迟的影响，不受我们控制。我们可以控制的是下载器的并发等级（N），将 8 提升到 16 或 32，如图 1 所示。对于固定的管道长度（这也不受我们控制），我们只能增加横截面积来增加体积，即增加吞吐量。用 Little 定律来讲，并发如果是 16 个请求，就有 T=N/S=16/0.25=64 请求/秒，并发 32 个请求，就有 T=N/S=32/0.25=128 请求/秒。貌似如果并发数无限大，吞吐量也就无限大。在得出这个结论之前，我们还得考虑一下串联排队系统。

## 串联排队系统

当你将横截面积/吞吐量不同的管道连接起来时，直观上，人们会认为总系统会受限于最窄的管道（最小的吞吐量 T），见图 2。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/9e40644246ab8d4b1a7c0b45d685cb87.jpg)图 2 不同的串联排队系统

你还可以看到最窄的管道（即瓶颈）放在不同的地方，可以影响其他管道的填充程度。如果将填充程度类比为系统内存需求，瓶颈的摆放就十分重要了。最好能将填充程度达到最高，这样单位工作的花费最小。在 Scrapy 中，单位工作（抓取一个网页）大体包括下载器之前的一条 URL（几个字节）和下载器之后的 URL 和服务器响应。

> 提示：这就是为什么，Scrapy 把瓶颈放在下载器。

## 确认瓶颈

用管道系统的比喻，可以直观的确认瓶颈所在。查看图 2，你可以看到瓶颈之前都是满的，瓶颈之后就不是满的。

对于大多数系统，可以用系统的性能指标监测排队系统是否拥挤。通过检测 Scrapy 的队列，我们可以确定出瓶颈的所在，如果瓶颈不是在下载器的话，我们可以通过调整设置使下载器成为瓶颈。瓶颈没有得到优化，吞吐量就不会有优化。调整其它部分只会使系统变得更糟，很可能将瓶颈移到别处。所以在修改代码和配置之前，你必须找到瓶颈。你会发现在大多数情况下，包括本书中的例子，瓶颈的位置都和预想的不同。

## Scrapy 的性能模型

让我们回到 Scrapy，详细查看它的性能模型，见图 3。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/7a8d06d1a9fcaf81f2b7079592467ab9.jpg)图 3 Scrapy 的性能模型

Scrapy 包括以下部分：

*   **调度器**：大量的 Request 在这里排队，直到下载器处理它们。其中大部分是 URL，因此体积不大，也就是说即便有大量请求存在，也可以被下载器及时处理。
*   **阻塞器**：这是抓取器由后向前进行反馈的一个安全阀，如果进程中的响应大于 5MB，阻塞器就会暂停更多的请求进入下载器。这可能会造成性能的波动。
*   **下载器**：这是对 Scrapy 的性能最重要的组件。它用复杂的机制限制了并发数。它的延迟（管道长度）等于远程服务器的响应时间，加上网络/操作系统、Python/Twisted 的延迟。我们可以调节并发请求数，但是对其它延迟无能为力。下载器的能力受限于 CONCURRENT_REQUESTS*设置。
*   **爬虫**：这是抓取器将 Response 变为 Item 和其它 Request 的组件。只要我们遵循规则来写爬虫，通常它不是瓶颈。
*   **Item Pipelines**：这是抓取器的第二部分。我们的爬虫对每个 Request 可能产生几百个 Items，只有 CONCURRENT_ITEMS 会被并行处理。这一点很重要，因为，如果你用 pipelines 连接数据库，你可能无意地向数据库导入数据，pipelines 的默认值（100）就会看起来很少。

爬虫和 pipelines 的代码是异步的，会包含必要的延迟，但二者不会是瓶颈。爬虫和 pipelines 很少会做繁重的处理工作。如果是的话，服务器的 CPU 则是瓶颈。

## 使用远程登录控制组件

为了理解 Requests/Items 是如何在管道中流动的，我们现在还不能真正的测量流动。然而，我们可以检测在 Scrapy 的每个阶段，有多少个 Requests/Responses/Items。

通过 Scrapy 运行远程登录，我们就可以得到性能信息。我们可以在 6023 端口运行远程登录命令。然后，会在 Scrapy 中出现一个 Python 控制台。注意，如果在这里进行中断操作，比如 time.sleep()，就会暂停爬虫。通过内建的 est()函数，可以查看一些有趣的信息。其中一些或是非常专业的，或是可以从核心数据推导出来。本章后面会展示后者。下面运行一个例子。当我们运行一个爬虫时，我们在开发机打开第二台终端，在端口 6023 远程登录，然后运行 est()。

> 提示：本章代码位于目录 ch10。这个例子位于 ch10/speed。

在第一台终端，运行如下命令：

```py
$ pwd
/root/book/ch10/speed
$ ls
scrapy.cfg  speed
$ scrapy crawl speed -s SPEED_PIPELINE_ASYNC_DELAY=1
INFO: Scrapy 1.0.3 started (bot: speed)
... 
```

现在先不关注 scrapy crawl speed 和它的参数的意义，后面会详解。在第二台终端，运行如下代码：

```py
$ telnet localhost 6023
>>> est()
...
len(engine.downloader.active)                   : 16
...
len(engine.slot.scheduler.mqs)                  : 4475
...
len(engine.scraper.slot.active)                 : 115
engine.scraper.slot.active_size                 : 117760
engine.scraper.slot.itemproc_size               : 105 
```

然后在第二台终端按 Ctrl+D 退出远程登录，返回第一台终端按 Ctrl+C 停止抓取。

> 提示：我们现在忽略 dqs。如果你通过设置 JOBDIR 打开了持久支持，你会得到非零的 dqs（len(engine.slot.scheduler.dqs)），你应该将它添加到 mqs 的大小中。

让我们查看这个例子中的数据的意义。mqs 指出调度器中等待的项目很少（4475 个请求）。len(engine.downloader.active)指出下载器现在正在下载 16 个请求。这与我们在 CONCURRENT_REQUESTS 的设置相同。len(engine.scraper.slot.active)说明现在正有 115 个响应在抓取器中处理。 (engine.scraper.slot.active_size)告诉我们这些响应的大小是 115kb。除了响应，105 个 Items 正在 pipelines(engine.scraper.slot.itemproc_size)中处理，这说明还有 10 个在爬虫中。经过总结，我们看到瓶颈是下载器，在下载器之前有很长的任务队列（mqs），下载器在满负荷运转；下载器之后，工作量较高并有一定波动。

另一个可以查看信息的地方是 stats 对象，抓取之后打印的内容。我们可以以 dict 的形式访问它，只需通过 via stats.get_stats()远程登录，用 p()函数打印：

```py
$ p(stats.get_stats())
{'downloader/request_bytes': 558330,
...
 'item_scraped_count': 2485,
...} 
```

这里对我们最重要的是 item_scraped_count，它可以通过 stats.get_value ('item_scraped_count')之间访问。它告诉我们现在已经抓取了多少个 items，以及增长的速率，即吞吐量。

## 评分系统

我为本章写了一个简单的评分系统，它可以让我们评估在不同场景下的性能。它的代码有些复杂，你可以在 speed/spiders/speed.py 找到，但我们不会深入讲解它。

这个评分系统包括：

*   服务器上[http://localhost:9312/benchmark/](https://link.jianshu.com?t=http://localhost:9312/benchmark/)...的句柄（handlers）。我们可以控制这个假网站的结构（见图 4），通过调节 URL 参数/Scrapy 设置，控制网页加载的速度。不用在意细节，我们接下来会看许多例子。现在，先看一下[http://localhost:9312/benchmark/index?p=1](https://link.jianshu.com?t=http://localhost:9312/benchmark/index?p=1)和[http://localhost:9312/benchmark/id:3/rr:5/index?p=1](https://link.jianshu.com?t=http://localhost:9312/benchmark/id:3/rr:5/index?p=1)的不同。第一个网页在半秒内加载完毕，每页只含有一个 item，第二个网页加载用了五秒，每页有三个 items。我们还可以在网页上添加垃圾信息，降低加载速度。例如，查看[http://localhost:9312/benchmark/ds:100/detail?id0=0](https://link.jianshu.com?t=http://localhost:9312/benchmark/ds:100/detail?id0=0)。默认条件下（见 speed/[settings.py](https://link.jianshu.com?t=http://settings.py)），页面渲染用时 SPEED_T_RESPONSE = 0.125 秒，假网站有 SPEED_TOTAL_ITEMS = 5000 个 Items。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/675b9ba463c6c72def3541c2f7c3232c.jpg)图 4 评分服务器创建了一个结构可变的假网站

*   爬虫，SpeedSpider，模拟用几种方式取回被 SPEED_START_REQUESTS_STYLE 控制的 start_requests()，并给出一个 parse_item()方法。默认下，用 crawler.engine.crawl()方法将所有起始 URL 提供给调度器。
*   pipeline，DummyPipeline，模拟了一些处理过程。它可以引入四种不同的延迟类型。阻塞/计算/同步延迟(SPEED_PIPELINE_BLOCKING_DELAY—很差)，异步延迟(SPEED_PIPELINE_ASYNC_DELAY—不错)，使用远程 treq 库进行 API 调用(SPEED_PIPELINE_API_VIA_TREQ—不错)，和使用 Scrapy 的 crawler.engine.download()进行 API 调用(SPEED_PIPELINE_API_VIA_DOWNLOADER—不怎么好)。默认时，pipeline 不添加延迟。
*   settings.py 中的一组高性能设置。关闭任何可能使系统降速的项。因为只在本地服务器运行，我们还关闭了每个域的请求限制。
*   一个可以记录数据的扩展，和第 8 章中的类似。它每隔一段时间，就打印出核心数据。

在上一个例子，我们已经用过了这个系统，让我们重新做一次模拟，并使用 Linux 的计时器测量总共的执行时间。核心数据打印如下：

```py
$ time scrapy crawl speed
...
INFO:  s/edule  d/load  scrape  p/line    done       mem
INFO:        0       0       0       0       0         0
INFO:     4938      14      16       0      32     16384
INFO:     4831      16       6       0     147      6144
...
INFO:      119      16      16       0    4849     16384
INFO:        2      16      12       0    4970     12288
...
real  0m46.561s
Column          Metric
s/edule         len(engine.slot.scheduler.mqs)
d/load          len(engine.downloader.active)
scrape          len(engine.scraper.slot.active)
p/line          engine.scraper.slot.itemproc_size
done            stats.get_value('item_scraped_count')
mem             engine.scraper.slot.active_size 
```

结果这样显示出来效果很好。调度器中初始有 5000 条 URL，结束时 done 的列也有 5000 条。下载器全负荷下并发数是 16，与设置相同。抓取器主要是爬虫，因为 pipeline 是空的，它没有满负荷运转。它用 46 秒抓取了 5000 个 Items，并发数是 16，即每个请求的处理时间是 46*16/5000=147ms，而不是预想的 125ms，满足要求。

## 标准性能模型

当 Scrapy 正常运行且下载器为瓶颈时，就是 Scrapy 的标准性能模型。此时，调度器有一定数量的请求，下载器满负荷运行。抓取器负荷不满，并且加载的响应不会持续增加。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/78dd9bc4255fefa4eb235ce8ab8b2be1.jpg)图 5 标准性能模型和一些试验结果

三项设置负责控制下载器的性能： CONCURRENT_REQUESTS，CONCURRENT_REQUESTS_PER_DOMAIN 和 CONCURRENT_REQUESTS_PER_IP。第一个是宏观上的控制，无论任何时候，并发数都不能超过 CONCURRENT_REQUESTS。另外，如果是单域或几个域，CONCURRENT_REQUESTS_PER_DOMAIN 也可以限制活跃请求数。如果你设置了 CONCURRENT_REQUESTS_PER_IP，CONCURRENT_REQUESTS_PER_DOMAIN 就会被忽略，活跃请求数就是每个 IP 的请求数量。对于共享站点，比如，多个域名指向一个服务器，这可以帮助你降低服务器的载荷。

为了更简明的分析，现在把 per-IP 的限制关闭，即使 CONCURRENT_REQUESTS_PER_IP 为默认值（0），并设置 CONCURRENT_REQUESTS_PER_DOMAIN 为一个超大值（1000000）。这样就可以无视其它的设置，让下载器的并发数完全受 CONCURRENT_REQUESTS 控制。

我们希望吞吐量取决于下载网页的平均时间，包括远程服务器和我们系统（Linux、Twisted/Python）的延迟，t<sub>download</sub>=t<sub>response</sub>+t<sub>overhead</sub>。还可以加上启动和关闭的时间。这包括从取得响应到 Items 离开 pipeline 的时间，和取得第一个响应的时间，还有空缓存的内部损耗。

总之，如果你要完成 N 个请求，在爬虫正常的情况下，需要花费的时间是：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/7340a2fa5cc3db21133ee8eda503815c.jpg)

所幸的是，我们只需控制一部分参数就可以了。我们可以用一台更高效的服务器控制 t<sub>overhead</sub>，和 t<sub>start/stop</sub>，但是后者并不值得，因为每次运行只影响一次。除此之外，最值得关注的就是 CONCURRENT_REQUESTS，它取决于我们如何使用服务器。如果将其设置成一个很大的值，在某一时刻就会使服务器或我们电脑的 CPU 满负荷，这样响应就会不及时，t<sub>response</sub>会急剧升高，因为网站会阻塞、屏蔽进一步的访问，或者服务器会崩溃。

让我们验证一下这个理论。我们抓取 2000 个 items，t<sub>response</sub>∈{0.125s，0.25s，0.5s}，CONCURRENT_REQUESTS∈{8，16，32，64}：

```py
$ for delay in 0.125 0.25 0.50; do for concurrent in 8 16 32 64; do
    time scrapy crawl speed -s SPEED_TOTAL_ITEMS=2000 \
    -s CONCURRENT_REQUESTS=$concurrent -s SPEED_T_RESPONSE=$delay
  done; done 
```

在我的电脑上，我完成 2000 个请求的时间如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/24c454c4e09d2a378d28bf533b762e0c.jpg)

接下来复杂的数学推导，可以跳过。在图 5 中，可以看到一些结果。将上一个公式变形为 y=t<sub>overhead</sub>·x+ t<sub>start/stop</sub>，其中 x=N/CONCURRENT_REQUESTS， y=t<sub>job</sub>·x+t<sub>response</sub>。使用最小二乘法（LINEST Excel 函数）和前面的数据，可以计算出 t<sub>overhead</sub>=6ms，t<sub>start/stop</sub>=3.1s。toverhead 可以忽略，但是开始时间相对较长，最好是在数千条 URL 时长时间运行。因此，可以估算出吞吐量公式是：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/09fd06cb73c76b6b5e3bb03417997f78.jpg)

处理 N 个请求，我们可以估算 t<sub>job</sub>，然后可以直接求出 T。

## 解决性能问题

现在我们已经明白如何使 Scrapy 的性能最大化，让我们来看看如何解决实际问题。我们会通过探究症状、运行错误、讨论原因、修复问题，讨论几个实例。呈现的顺序是从系统性的问题到 Scrapy 的小技术问题，也就是说，更为常见的问题可能会排在后面。请阅读全部章节，再开始处理你自己的问题。

## 实例 1——CPU 满负荷

症状：当你提高并发数时，性能并没有提高。当你降低并发数，一切工作正常。下载器没有问题，但是每个请求花费时间太长。用 Unix/Linux 命令 ps 或 Windows 的任务管理器查看 CPU 的情况，CPU 的占用率非常高。

案例：假设你运行如下命令：

```py
$ for concurrent in 25 50 100 150 200; do
   time scrapy crawl speed -s SPEED_TOTAL_ITEMS=5000 \
    -s CONCURRENT_REQUESTS=$concurrent
  done 
```

求得抓取 5000 条 URL 的时间。预计时间是用之前推导的公式求出的，CPU 是用命令查看得到的（可以在另一台终端运行查看命令）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/745cb8623aaf6ec389c4cdcb025c9a3c.jpg)![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/8b13f3109d77546f0084b9a75c721f12.jpg)图 6 当并发数超出一定值时，性能变化趋缓。

在我们的试验中，我们没有进行任何处理工作，所以并发数可以很高。在实际中，很快就可以看到性能趋缓的情况发生。

讨论：Scrapy 使用的是单线程，当并发数很高时，CPU 可能会成为瓶颈。假设没有使用线程池，CPU 的使用率建议是 80-90%。可能你还会碰到其他系统性问题，比如带宽、内存、硬盘吞吐量，但是发生这些状况的可能性比较小，并且不属于系统管理，所以就不赘述了。

解决：假设你的代码已经是高效的。你可以通过在一台服务器上运行多个爬虫，使累积并发数超过 CONCURRENT_REQUESTS。这可以充分利用 CPU 的性能。如果还想提高并发数，你可以使用多台服务器（见 11 章），这样就可以使用更多的内存、带宽和硬盘吞吐量。检查 CPU 的使用情况是你的首要关切。

## 实例 2-阻塞代码

症状：系统的运行得十分奇怪。比起预期的速度，系统运行的十分缓慢。改变并发数，也没有效果。下载器几乎是空的（远小于并发数），抓取器的响应数很少。

案例：使用两个评分设置，SPEED_SPIDER_BLOCKING_DELAY 和 SPEED_PIPELINE_BLOCKING_DELAY（二者效果相同），使每个响应有 100ms 的阻塞延迟。在给定的并发数下，100 条 URL 大概要 2 到 3 秒，但结果总是 13 秒左右，并且不受并发数影响：

```py
for concurrent in 16 32 64; do
  time scrapy crawl speed -s SPEED_TOTAL_ITEMS=100 \
  -s CONCURRENT_REQUESTS=$concurrent -s SPEED_SPIDER_BLOCKING_DELAY=0.1
done 
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/d5efa5141e985c794906203a96d9241d.jpg)

讨论：任何阻塞代码都会是并发数无效，并使得 CONCURRENT_REQUESTS=1。公式：100URL*100ms(阻塞延迟)=10 秒+tstart/stop，完美解释了发生的状况。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/7fb52ea5be780e67a3bc6ee59ae0374e.jpg)图 7 阻塞代码使并发数无效化

无论阻塞代码位于 pipelines 还是爬虫，你都会看到抓取器满负荷，它之前和之后的部分都是空的。看起来这违背了我们之前讲的，但是由于我们并没有一个并行系统，pipeline 的规则此处并不适用。这个错误很容易犯（例如，使用了阻塞 APIs），然后就会出现之前的状况。相似的讨论也适用于计算复杂的代码。应该为每个代码使用多线程，如第 9 章所示，或在 Scrapy 的外部批次运行，第 11 章会看到例子。

解决：假设代码是继承而来的，你并不知道阻塞代码位于何处。没有 pipelines 系统也能运行的话，使 pipeline 无效，看系统能否正常运行。如果是的话，说明阻塞代码位于 pipelines。如果不是的话，逐一恢复 pipelines，看问题何时发生。如果必须所有组件都在运行，整个系统才能运行的话，给每个 pipeline 阶段添加日志消息（或者插入可以打印时间戳的伪 pipelines），就可以发现哪一步花费的时间最多。如果你想要一个长期可重复使用的解决方案，你可以用在每个 meta 字段添加时间戳的伪 pipelines 追踪请求。最后，连接 item_scraped 信号，打印出时间戳。一旦找到阻塞代码，将其转化为 Twisted/异步，或使用 Twisted 的线程池。要查看转化的效果，将 SPEED_PIPELINE_BLOCKING_DELAY 替换为 SPEED_PIPELINE_ASYNC_DELAY，然后再次运行。可以看到性能改进很大。

## 实例 3-下载器中有“垃圾”

症状：吞吐量比预期的低。下载器的请求数貌似比并发数多。

案例：模拟下载 1000 个网页，每个响应时间是 0.25 秒。当并发数是 16 时，根据公式，整个过程大概需要 19 秒。我们使用一个 pipeline，它使用 crawler.engine.download()向一个响应时间小于一秒的伪装 API 做另一个 HTTP 请求，。你可以在[http://localhost:9312/benchmark/ar:1/api?text=hello](https://link.jianshu.com?t=http://localhost:9312/benchmark/ar:1/api?text=hello)尝试。下面运行爬虫：

```py
$ time scrapy crawl speed -s SPEED_TOTAL_ITEMS=1000 -s SPEED_T_
RESPONSE=0.25 -s SPEED_API_T_RESPONSE=1 -s SPEED_PIPELINE_API_VIA_
DOWNLOADER=1
...
s/edule  d/load  scrape  p/line    done       mem
    968      32      32      32       0     32768
    952      16       0       0      32         0
    936      32      32      32      32     32768
...
real 0m55.151s 
```

很奇怪，不仅时间多花了三倍，并发数也比设置的数值 16 要大。下载器明显是瓶颈，因为它已经过载了。让我们重新运行爬虫，在另一台终端，远程登录 Scrapy。然后就可以查看下载器中运行的 Requests 是哪个：

```py
$ telnet localhost 6023
>>> engine.downloader.active
set([<POST http://web:9312/ar:1/ti:1000/rr:0.25/benchmark/api>,  ... ]) 
```

貌似下载器主要是在做 APIs 请求，而不是下载网页。

讨论：你可能希望没人使用 crawler.engine.download()，因为它看起来很复杂，但在 Scrapy 的 robots.txt 中间件和媒体 pipeline，它被使用了两次。因此，当人们需要处理网络 APIs 时，自然而然要使用它。使用它远比使用阻塞 APIs 要好，例如前面看过的流行的 Python 的 requests 包。比起理解 Twisted 和使用 treq，它使用起来也更简单。这个错误很难调试，所以让我们转而查看下载器中的请求。如果看到有 API 或媒体 URL 不是直接抓取的，就说明 pipelines 使用了 crawler.engine.download()进行了 HTTP 请求。我们的 ONCURRENT_REQUESTS 限制部队这些请求生效，所以下载器中的请求数总是超过设置的并发数。除非伪请求数小于 CONCURRENT_REQUESTS，下载器不会从调度器取得新的网页请求。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/4d56af7a260cf54e598382558d7c9e5d.jpg)图 8 伪 API 请求决定了性能

因此，当原始请求持续 1 秒（API 延迟）而不是 0.25 秒时（页面下载延迟），吞吐量自然会发生变化。这里容易让人迷惑的地方是，要是 API 的调用比网页请求还快，我们根本不会观察到性能的下降。

解决：我们可以使用 treq 而不是 crawler.engine.download()解决这个问题，你可以看到抓取器的性能大幅提高，这对 API 可能不是个好消息。我先将 CONCURRENT_REQUESTS 设置的很低，然后逐步提高，以确保不让 API 服务器过载。

下面是使用 treq 的例子：

```py
$ time scrapy crawl speed -s SPEED_TOTAL_ITEMS=1000 -s SPEED_T_
RESPONSE=0.25 -s SPEED_API_T_RESPONSE=1 -s SPEED_PIPELINE_API_VIA_TREQ=1
...
s/edule  d/load  scrape  p/line    done       mem
    936      16      48      32       0     49152
    887      16      65      64      32     66560
    823      16      65      52      96     66560
...
real 0m19.922s 
```

可以看到一个有趣的现象。pipeline (p/line)的 items 似乎比下载器(d/load)的还多。这并不是一个问题，弄清楚它是很有意思的。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/3ebf881419c810ad29b4c89ab7e7e060.jpg)图 9 使用长 pipelines 也符合要求

和预期一样，下载器中有 16 条请求。这意味着系统的吞吐量是 T = N/S = 16/0.25 = 64 请求/秒。done 这一列逐渐升高，可以确认这点。每条请求在下载器中耗时 0.25 秒，但它在 pipelines 中会耗时 1 秒，因为较慢的 API 请求。这意味着在 pipeline 中，平均的 N = T * S = 64 * 1 = 64 Items。这完全合理。这是说 pipelines 是瓶颈吗？不是，因为 pipelines 没有同时处理响应数量的限制。只要这个数字不持续增加，就没有问题。接下来会进一步讨论。

## 实例 4-大量响应造成溢出

症状：下载器几乎满负荷运转，一段时间后关闭。这种情况循环发生。抓取器的内存使用很高。

案例：设置和以前相同（使用 treq），但响应很高，有大约 120kB 的 HTML。可以看到，这次耗时 31 秒而不是 20 秒：

```py
$ time scrapy crawl speed -s SPEED_TOTAL_ITEMS=1000 -s SPEED_T_
RESPONSE=0.25 -s SPEED_API_T_RESPONSE=1 -s SPEED_PIPELINE_API_VIA_TREQ=1 
-s SPEED_DETAIL_EXTRA_SIZE=120000
s/edule  d/load  scrape  p/line    done       mem
    952      16      32      32       0   3842818
    917      16      35      35      32   4203080
    876      16      41      41      67   4923608
    840       4      48      43     108   5764224
    805       3      46      27     149   5524048
...
real  0m30.611s 
```

讨论：我们可能简单的认为延迟的原因是“需要更多的时间创建、传输、处理网页”，但这并不是真正的原因。对于响应的大小有一个强制性的限制，max_active_size = 5000000。每一个响应都和响应体的大小相同，至少为 1kB。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/eb416cfba996e61f7509e9a3150dc635.jpg)图 10 下载器中的请求数不规律变化，说明存在响应大小限制

这个限制可能是 Scrapy 最基本的机制，当存在慢爬虫和 pipelines 时，以保证性能。如果 pipelines 的吞吐量小于下载器的吞吐量，这个机制就会起作用。当 pipelines 的处理时间很长，即便是很小的响应也可能触发这个机制。下面是一个极端的例子，pipelines 非常长，80 秒后出现问题：

```py
$ time scrapy crawl speed -s SPEED_TOTAL_ITEMS=10000 -s SPEED_T_
RESPONSE=0.25 -s SPEED_PIPELINE_ASYNC_DELAY=85 
```

解决：对于这个问题，在底层结构上很难做什么。当你不再需要响应体的时候，可以立即清除它。这可能是在爬虫的后续清除响应体，但是这么做不会重置抓取器的计数器。你能做的是减少 pipelines 的处理时间，减少抓取器中的响应数量。用传统的优化方法就可以做到：检查交互中的 APIs 或数据库是否支持抓取器的吞吐量，估算下载器的能力，将 pipelines 进行后批次处理，或使用性能更强的服务器或分布式抓取。

## 实例 5-item 并发受限/过量造成溢出

症状：爬虫对每个响应产生多个 Items。吞吐量比预期的小，和之前的实例相似，也呈现出间歇性。

案例：我们有 1000 个请求，每一个会返回 100 个 items。响应时间是 0.25 秒，pipelines 处理时间是 3 秒。进行几次试验，CONCURRENT_ITEMS 的范围是 10 到 150：

```py
for concurrent_items in 10 20 50 100 150; do
time scrapy crawl speed -s SPEED_TOTAL_ITEMS=100000 -s  \
SPEED_T_RESPONSE=0.25 -s SPEED_ITEMS_PER_DETAIL=100 -s  \
SPEED_PIPELINE_ASYNC_DELAY=3 -s \
CONCURRENT_ITEMS=$concurrent_items
done
...
s/edule  d/load  scrape  p/line    done       mem
    952      16      32     180       0    243714
    920      16      64     640       0    487426
    888      16      96     960       0    731138
... 
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/4a8d58738384fdb0bcbb83111427410d.jpg)图 11 以 CONCURRENT_ITEMS 为参数的抓取时间函数

讨论：只有每个响应产生多个 Items 时才出现这种情况。这个案例的人为性太强，因为吞吐量达到了每秒 1300 个 Items。吞吐量这么高是因为稳定的低延迟、没进行处理、响应很小。这样的条件很少见。

我们首先观察到的是，以前 scrape 和 p/line 两列的数值是相同的，现在 p/line 显示的是 shows CONCURRENT_ITEMS * scrape。这是因为 scrape 显示 Reponses，而 p/line 显示 Items。

第二个是图 11 中像一个浴缸的函数。部分原因是纵坐标轴造成的。在左侧，有非常高延迟，因为达到了内存极限。右侧，并发数太大，CPU 使用率太高。取得最优化并不是那么重要，因为很容易向左或向右变动。

解决：很容易检测出这个例子中的两个错误。如果 CPU 使用率太高，就降低并发数。如果达到了 5MB 的响应限制，pipelines 就不能很好的衔接下载器的吞吐量，提高并发数就可以解决。如果不能解决问题，就查看一下前面的解决方案，并审视是否系统的其它部分可以支撑抓取器的吞吐量。

## 实例 6-下载器没有充分运行

症状：提高了 CONCURRENT_REQUESTS，但是下载器中的数量并没有提高，并且没有充分利用。调度器是空的。

案例：首先运行一个没有问题的例子。将响应时间设为 1 秒，这样可以简化计算，使下载器吞吐量 T = N/S = N/1 = CONCURRENT_REQUESTS。然后运行如下代码：

```py
$ time scrapy crawl speed -s SPEED_TOTAL_ITEMS=500 \
-s SPEED_T_RESPONSE=1 -s CONCURRENT_REQUESTS=64
  s/edule  d/load  scrape  p/line    done       mem
     436      64       0       0       0         0
...
real  0m10.99s 
```

下载器满状态运行（64 个请求），总时长为 11 秒，和 500 条 URL、每秒 64 请求的模型相符，S=N/T+tstart/stop=500/64+3.1=10.91 秒。
现在，再做相同的抓取，不再像之前从列表中提取 URL，这次使用 SPEED_START_REQUESTS_STYLE=UseIndex 从索引页提取 URL。这与其它章的方法是一样的。每个索引页有 20 条 URL：

```py
$ time scrapy crawl speed -s SPEED_TOTAL_ITEMS=500 \
-s SPEED_T_RESPONSE=1 -s CONCURRENT_REQUESTS=64 \
-s SPEED_START_REQUESTS_STYLE=UseIndex
s/edule  d/load  scrape  p/line    done       mem
       0       1       0       0       0         0
       0      21       0       0       0         0
       0      21       0       0      20         0
...
real 0m32.24s 
```

很明显，与之前的结果不同。下载器没有满负荷运行，吞吐量为 T=N/S-tstart/stop=500/(32.2-3.1)=17 请求/秒。

讨论：d/load 列可以确认下载器没有满负荷运行。这是因为没有足够的 URL 进入。抓取过程产生 URL 的速度慢于处理的速度。这时，每个索引页会产生 20 个 URL+下一个索引页。吞吐量不可能超过每秒 20 个请求，因为产生 URL 的速度没有这么快。

解决：如果每个索引页有至少两个下一个索引页的链接，呢么我们就可以加快产生 URL 的速度。如果可以找到能产生更多 URL（例如 50）的索引页面则会更好。通过模拟观察变化：

```py
$ for details in 10 20 30 40; do for nxtlinks in 1 2 3 4; do
time scrapy crawl speed -s SPEED_TOTAL_ITEMS=500 -s SPEED_T_RESPONSE=1 \
-s CONCURRENT_REQUESTS=64 -s SPEED_START_REQUESTS_STYLE=UseIndex \
-s SPEED_DETAILS_PER_INDEX_PAGE=$details \
-s SPEED_INDEX_POINTAHEAD=$nxtlinks
done; done 
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/fad9c1665058ab5cce0d755ba154ae0a.jpg)图 12 以每页能产生的链接数为参数的吞吐量函数

在图 12 中，我们可以看到吞吐量是如何随每页 URL 数和索引页链接数变化的。初始都是线性变化，直到到达系统限制。你可以改变爬虫的规则进行试验。如果使用 LIFO（默认项）规则，即先发出索引页请求最后收回，可以看到性能有小幅提高。你也可以将索引页的优先级设置为最高。两种方法都不会有太大的提高，但是你可以通过分别设置 SPEED_INDEX_RULE_LAST=1 和 SPEED_INDEX_HIGHER_PRIORITY=1，进行试验。请记住，这两种方法都会首先下载索引页（因为优先级高），因此会在调度器中产生大量 URL，这会提高对内存的要求。在完成索引页之前，输出的结果很少。索引页不多时推荐这种做法，有大量索引时不推荐这么做。

另一个简单但高效的方法是分享首页。这需要你使用至少两个首页 URL，并且它们之间距离最大。例如，如果首页有 100 页，你可以选择 1 和 51 作为起始。爬虫这样就可以将抓取下一页的速度提高一倍。相似的，对首页中的商品品牌或其他属性也可以这么做，将首页大致分为两个部分。你可以使用-s SPEED_INDEX_SHARDS 设置进行模拟：

```py
$ for details in 10 20 30 40; do for shards in 1 2 3 4; do
time scrapy crawl speed -s SPEED_TOTAL_ITEMS=500 -s SPEED_T_RESPONSE=1 \
-s CONCURRENT_REQUESTS=64 -s SPEED_START_REQUESTS_STYLE=UseIndex \
-s SPEED_DETAILS_PER_INDEX_PAGE=$details -s SPEED_INDEX_SHARDS=$shards
done; done 
```

这次的结果比之前的方法要好，并且更加简洁 。

## 解决问题的流程

总结一下，Scrapy 的设计初衷就是让下载器作为瓶颈。使 CONCURRENT_REQUESTS 从小开始，逐渐变大，直到发生以下的限制：

*   CPU 利用率 > 80-90%
*   源网站延迟急剧升高
*   抓取器的响应达到内存 5Mb 上限
    同时，进行如下操作：
*   始终保持调度器（mqs/dqs）中有一定数量的请求，避免下载器是空的
*   不使用阻塞代码或 CPU 密集型代码

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/3af65ddee0d38d3ae0dca08bff910b37.jpg)图 13 解决 Scrapy 性能问题的路线图

## 总结

在本章中，我们通过案例展示了 Scrapy 的架构是如何影响性能的。细节可能会在未来的 Scrapy 版本中变动，但是本章阐述的原理在相当长一段时间内可以帮助你理解以 Twisted、Netty Node.js 等为基础的异步框架。

谈到具体的 Scrapy 性能，有三个确定的答案：我不知道也不关心、我不知道但会查出原因，和我知道。本章已多次指出，“更多的服务器/内存/带宽”不能提高 Scrapy 的性能。唯一的方法是找到瓶颈并解决它。

在最后一章中，我们会学习如何进一步提高性能，不是使用一台服务器，而是在多台服务器上分布多个爬虫。



# 十一、Scrapyd 分布式抓取和实时分析

* * *

[序言](https://www.jianshu.com/p/6c9baeb60044)
[第 1 章 Scrapy 介绍](https://www.jianshu.com/p/b807653e97bb)
[第 2 章 理解 HTML 和 XPath](https://www.jianshu.com/p/90c2c25f0c41)
[第 3 章 爬虫基础](https://www.jianshu.com/p/6ebb898841bc)
[第 4 章 从 Scrapy 到移动应用](https://www.jianshu.com/p/4156e757557f)
[第 5 章 快速构建爬虫](https://www.jianshu.com/p/9d1e00dc40e4)
[第 6 章 Scrapinghub 部署](https://www.jianshu.com/p/441fa74d7aad)
[第 7 章 配置和管理](https://www.jianshu.com/p/674de4eacf15)
[第 8 章 Scrapy 编程](https://www.jianshu.com/p/545d07702e7f)
[第 9 章 使用 Pipeline](https://www.jianshu.com/p/e0287e773d28)
[第 10 章 理解 Scrapy 的性能](https://www.jianshu.com/p/e9710002cb4e)
第 11 章（完） Scrapyd 分布式抓取和实时分析

* * *

我们已经学了很多东西。我们先学习了两种基础的网络技术，HTML 和 XPath，然后我们学习了使用 Scrapy 抓取复杂的网站。接着，我们深入学习了 Scrapy 的设置，然后又进一步深入学习了 Scrapy 和 Python 的内部架构和 Twisted 引擎的异步特征。在上一章中，我们学习了 Scrapy 的性能和以及处理复杂的问题以提高性能。

在本章中，我将展示如何在多台服务器上进一步提高性能。我们会发现抓取通常是一个并行问题；因此，我们可以水平延展至多台服务器。为了这么做，我们会使用一个 Scrapy 中间件，我们还会使用 Scrapyd，一个用来管理远程服务器爬虫的应用。它可以让我们像第 6 章那样进行抓取。

我们最后用 Apache Spark 对提取的数据进行实时分析。Spark 一个非常流行的大数据处理框架。收集的数据越多、结果就变得越准确，我们使用 Spark Streaming API 展示结果。最后的结果展示了 Python 的强大和成熟，单单用 Python 的简明代码就全栈开发了从抓取到分析的全过程。

## 房子的标题如何影响价格？

我们要研究个问题是房子的标题和价格有什么关系。我们预计像“按摩浴缸”和“游泳池”可能和高价相关，而“打折”会和低价有关。将标题与地点结合，例如，可以根据地点和描述，实时判断哪个房子最划算。

我们想计算的就是特定名词对价格造成的偏移：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/c09b2eaecae9f3074be28b7b3c60d070.jpg)

例如，如果平均租金是$1000，我们观察到带有按摩浴缸的房子的平均价格是$1300，没有的价格是$995，因此按摩浴缸的偏移值为 shiftjacuzzi=(1300-995)/1000=30.5%。如果一个带有按摩浴缸的房子的价格直逼平均价格高 5%，那么它的价格就很划算。

因为名词效应会有累加，所以这个指标并不繁琐。例如，标题同时含有按摩浴缸和打折会有一个混合效果。我们收集分析的数据越多，估算就会越准确。稍后回到这个问题，接下来讲一个流媒体解决方案。

## Scrapyd

现在，我们来介绍 Scrapyd。Scrapyd 是一个应用，使用它，我们可以将爬虫附属到服务器上，并对抓取进行规划。我们来看看它的使用是多么容易，我们用第 3 章的代码，只做一点修改。

我们先来看 Scrapyd 的界面，在[http://localhost:6800/](https://link.jianshu.com?t=http://localhost:6800/)。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/ca2c833ca84b360b72d41389dd717d5f.jpg)Scrapyd 的界面

你可以看到，它有几个部分，有 Jobs、Items、Logs 和 Documentation。它还给出了如何规划抓取工作的 API 方法。

为了这么做，我们必须首先将爬虫部署到服务器上。第一步是修改 scrapy.cfg，如下所示：

```py
$ pwd
/root/book/ch03/properties
$ cat scrapy.cfg 
...
[settings]
default = properties.settings
[deploy]
url = http://localhost:6800/
project = properties 
```

我们要做的就是取消 url 的注释。默认的设置适合我们。现在，为了部署爬虫，我们使用 scrapyd-client 提供的工具 scrapyd-deploy。scrapyd-client 以前是 Scrapy 的一部分，但现在是一个独立的模块，可以用 pip install scrapyd-client 进行安装（开发机中已经安装了）：

```py
$ scrapyd-deploy 
Packing version 1450044699
Deploying to project "properties" in http://localhost:6800/addversion.
json
Server response (200):
{"status": "ok", "project": "properties", "version": "1450044699", 
"spiders": 3, "node_name": "dev"} 
```

部署好之后，就可以在 Scrapyd 的界面的 Available projects 看到。我们现在可以根据提示，在当前页提交一个任务：

```py
$ curl http://localhost:6800/schedule.json -d project=properties -d spider=easy
{"status": "ok", "jobid": " d4df...", "node_name": "dev"} 
```

如果我们返回 Jobs，我们可以使用 jobid schedule.json，它可以在之后用 cancel.json 取消任务：

```py
$ curl http://localhost:6800/cancel.json -d project=properties -d job=d4df...
{"status": "ok", "prevstate": "running", "node_name": "dev"} 
```

一定要取消进程，否则会浪费计算资源。

完毕之后，访问 Logs，我们可以看到日志，在 Items 我们可以看到抓取过的 items。这些数据会被周期清空以节省空间，所以一段时间后就会失效。

如果发生冲突或有其它理由的话，我们可以通过 http_port 修改端口，它是 Scrapyd 的诸多设置之一。最好阅读文档[http://scrapyd.readthedocs.org/](https://link.jianshu.com?t=http://scrapyd.readthedocs.org/)，多了解下。我们的部署必须要设置的是 max_proc。如果使用默认值 0，任务的并行数量最多可以是 CPU 核心的四位。因为我们可能会在虚拟机中运行多个 Scrapyd 服务器，我们将 max_proc 设为 4，可以允许 4 个任务同时进行。在真实环境中，使用默认值就可以。

## 分布式系统概述

设计这个系统对我是个挑战。我一开始添加了许多特性，导致复杂度升高，只有高性能的机器才能完成工作。然后，又不得不进行简化，既对硬件性能要求不那么高，也可以让本章的重点仍然是 Scrapy。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/7a88abe485a0b9077947f84aeb234310.jpg)

最后，系统中会包括我们的开发机和几台服务器。我们用开发机进行首页的水平抓取，提取几批 URL。然后用轮训机制将 URL 分发到 Scrapyd 的结点，并进行抓取。最后，通过 FTP 传递.jl 文件和 Items 到运行 Spark 的服务器上。我选择 FTP 和本地文件系统，而不是 HDFS 或 Apache Kafka，是因为 FTP 内存需求少，并且作为 FEED_URI 被 Scrapy 支持。请记住，只要简单设置 Scrapyd 和 Spark 的配置，我们就可以使用亚马逊 S3 存储这些文件，获得冗余度和可伸缩性等便利，而不用再使用其它技术。

> 笔记：FTP 的缺点之一是，上传过程可能会造成文件不完整。为了避免这点，一旦上传完成，我们便使用 Pure-FTPd 和调回脚本将文件上传到/root/items。

每过几秒，Spark 都读一下目录/root/items，读取任何新文件，取一个小批次进行分析。我们使用 Spark 是因为它支持 Python 作为编程语言，也支持流分析。到现在，我们使用的爬虫都比较短，实际中有的爬虫是 24 小时运行的，不断发出数据流并进行分析，数据越多，分析的结果越准确。我们就是要用 Spark 进行这样的演示。

> 笔记：除了 Spark 和 Scrapy，你还可以使用 MapReduce，Apache Storm 或其它框架。

在本章中，我们不向数据库中插入 items。我们在第 9 章中用的方法也可以在这里使用，但是性能很糟。很少有数据库喜欢每秒被 pipelines 写入几千个文件。如果想进行写入的话，应该用 Spark 专用的方法，即批次导入 Items。你可以修改我们 Spark 的例子，向任何数据库进行批次导入。

还有，这个系统的弹性很差。我们假设每个结点都是健康的，任何一个损坏的话，也不会对总系统造成影响。Spark 提供高可用性的弹性配置。Scrapy 不提供此类内建的功能，除了 Scrapyd 的“持续排队”功能，即当结点恢复时，可以继续失败的任务。这个功能不一定对你有用。如果弹性对你十分重要，你就得搭建一个监督系统和分布式排队方案（例如，基于 Kafka 或 RabbitMQ），可以重启失败的任务。

## 修改爬虫和中间件

为了搭建这个系统，我们要稍稍修改爬虫和中间件。更具体地，我们要做如下工作：

*   微调爬虫，使抓取索引页的速度达到最大
*   写一个中间件，可以将 URL 批次发送给 scrapyd 服务器。
*   使用相同的中间件，使系统启动时就可以将 URL 分批

我们尽量用简明的方式来完成这些工作。理想状态下，整个过程应该对底层的爬虫代码简洁易懂。这是一个底层层面的要求，通过破解爬虫达到相同目的不是好主意。

## 抓取共享首页

第一步是优化抓取首页的速度，速度越快越好。开始之前，先明确一下目的。假设爬虫的并发数是 16，源网站的延迟大概是 0.25 秒。这样，最大吞吐量是 16/0.25=64 页/秒。首页有 5000O 个子页，每个索引页有 30 个子页，那就有 1667 个索引页。预计下载整个首页需要，1667/64=26 秒。

将第 3 章中的爬虫重命名为 easy。我们将首先进行垂直抓取的 Rule（含有 callback='parse_item'的一项）注释掉，因为现在只想抓取索引页。

> 提示：本章的代码位于目录 ch11。

在进行优化之前，我们让 scrapy crawl 只抓取 10 个页面，结果如下：

```py
$ ls
properties  scrapy.cfg
$ pwd
/root/book/ch11/properties
$ time scrapy crawl easy -s CLOSESPIDER_PAGECOUNT=10
...
DEBUG: Crawled (200) <GET ...index_00000.html> (referer: None)
DEBUG: Crawled (200) <GET ...index_00001.html> (referer: ...index_00000.
html)
...
real  0m4.099s 
```

如果 10 个页面用时 4 秒，26 秒内是不可能完成 1700 个页面的。通过查看日志，我们看到每个索引页都来自前一个页面，也就是说，任何时候最多是在处理一个页面。实际上，并发数是 1。我们需要将其并行化，使达到并发数 16。我们将索引页相互共享，即 URL 互相连接，再加入一些其他的链接，以免爬虫中没有 URL。我们将首页分厂 20 个部分。实际上，任何大于 16 的数，都可以提速，但是一旦超过 20，速度反而会下降。我们用下面的方法计算每个部分的起始索引页：

```py
>>> map(lambda x: 1667 * x / 20, range(20))
[0, 83, 166, 250, 333, 416, 500, ...  1166, 1250, 1333, 1416, 1500, 1583] 
```

据此，设置 start_URL 如下：

```py
start_URL = ['http://web:9312/properties/index_%05d.html' % id
              for id in map(lambda x: 1667 * x / 20, range(20))] 
```

这可能会和你的情况不同，所以就不做美化了。将并发数(CONCURRENT_REQUESTS, CONCURRENT_REQUESTS_PER_DOMAIN)设为 16，再次运行爬虫，运行如下：

```py
$ time scrapy crawl easy -s CONCURRENT_REQUESTS=16 -s CONCURRENT_
REQUESTS_PER_DOMAIN=16
...
real  0m32.344s 
```

结果接近了我们的目标。下载速度是 1667 页面/32 秒=52 页面/秒，也就是说，每秒可以产生 52*30=1560 个子页面。我们现在可以注释掉垂直抓取的 Rule，将文件保存成一个爬虫。我们不需要进一步修改爬虫代码，而是用一个功能强大的中间件继续来做。如果只用开发机运行爬虫，假设可以像抓取索引页一样抓取子页，可以在 50000/52=16 分钟内完成抓取。

这里有两个要点。在学习完第 10 章之后，我们在做的都是工程项目。我们可以想方设法计算出系统确切的性能。第二点是，抓取索引页会产生子页，但实际的吞吐量不大。如果产生 URL 的速度快过 scrapyd 处理 URL 的速度，URL 就会在 scrapyd 排队。或者，如果产生 URL 的速度太慢，scrapyd 就会空闲。

## 批次抓取 URL

现在来处理子页面的 URL，并把它们分批，然后直接发送给 scrapyds，而不是继续抓取。

如果检查 Scrapy 的架构，我们可以明白这么做就是为了做一个中间件，它可以执行 process_spider_output()，在 Requests 到达下载器之前就可以进行处理或取消。我们限定中间件只支持 CrawlSpider 的爬虫，并且只支持简单的 GET 请求。如果要提高复杂度，例如，POST 或认证请求，我们必须开发更多的功能，以传递参数、头文件、每个批次进行重新登陆。

打开 Scrapy 的 GitHub，查看 SPIDER_MIDDLEWARES_BASE 设置，看看能否重利用哪个程序。Scrapy 1.0 有以下中间件：HttpErrorMiddleware、OffsiteMiddleware、RefererMiddleware、UrlLengthMiddleware 和 DepthMiddleware。我们看到 OffsiteMiddleware（只有 60 行）好像使我们需要的。它根据爬虫属性 allowed_domains 限定 URL。我们可以用相同的方法吗？不是丢弃 URL，我们转而将它们分批，发送给 scrapyds。我们确实可以这么做，部分代码如下：

```py
def __init__(self, crawler):
    settings = crawler.settings
    self._target = settings.getint('DISTRIBUTED_TARGET_RULE', -1)
    self._seen = set()
    self._URL = []
    self._batch_size = settings.getint('DISTRIBUTED_BATCH_SIZE', 1000)
    ...
def process_spider_output(self, response, result, spider):
    for x in result:
        if not isinstance(x, Request):
            yield x
        else:
            rule = x.meta.get('rule')
            if rule == self._target:
                self._add_to_batch(spider, x)
            else:
                yield x
def _add_to_batch(self, spider, request):
    url = request.url
    if not url in self._seen:
        self._seen.add(url)
        self._URL.append(url)
        if len(self._URL) >= self._batch_size:
            self._flush_URL(spider) 
```

process_spider_output()处理 Item 和 Request。我们只需要 Request，其它就不考虑了。如果查看 CrawlSpider 的源代码，我们看到将 Request/Response 映射到 Rule 的方式是用一个 meta dict 中的名为“rule”的整数字段。我们检查这个数字，如果它指向我们想要的 Rule（DISTRIBUTED_TARGET_RULE 设置），我们调用 _add_to_batch()，将它的 URL 添加到这个批次里面。我们然后取消这个 Request。我们接着产生出其他的请求，例如下一页的链接，不进行改动。The _add_to_batch()方法起到去重的作用。但是，我们前面描述的碎片化过程，意味着有的 URL 可能要提取两次。我们使用 _seen set 检测并去除重复项。然后将这些 URL 添加到 _URL 列表，如果它的大小超过了 _batch_size（根据 DISTRIBUTED_BATCH_SIZE 设置），就会调用 _flush_URL()。这个方法提供了一下功能：

```py
def __init__(self, crawler):
    ...
    self._targets = settings.get("DISTRIBUTED_TARGET_HOSTS")
    self._batch = 1
    self._project = settings.get('BOT_NAME')
    self._feed_uri = settings.get('DISTRIBUTED_TARGET_FEED_URL', None)
    self._scrapyd_submits_to_wait = []
def _flush_URL(self, spider):
    if not self._URL:
        return
    target = self._targets[(self._batch-1) % len(self._targets)]
    data = [
        ("project", self._project),
        ("spider", spider.name),
        ("setting", "FEED_URI=%s" % self._feed_uri),
        ("batch", str(self._batch)),
    ]
    json_URL = json.dumps(self._URL)
    data.append(("setting", "DISTRIBUTED_START_URL=%s" % json_URL))
    d = treq.post("http://%s/schedule.json" % target,
                  data=data, timeout=5, persistent=False)
    self._scrapyd_submits_to_wait.append(d)
    self._URL = []
    self._batch += 1 
```

首先，它使用了批次计数器（_batch）来决定发向哪个 scrapyd 服务器。可用服务器保存在 _targets（见 DISTRIBUTED_TARGET_HOSTS 设置）。我们然后向 scrapyd 的 schedule.json 做一个 POST 请求。这比之前用过的 curl 方法高级，因为它传递了经过仔细选择的参数。基于这些常熟，scrapyd 就规划了一次抓取，如下所示：

```py
scrapy crawl distr \
-s DISTRIBUTED_START_URL='[".../property_000000.html", ... ]' \
-s FEED_URI='ftp://anonymous@spark/%(batch)s_%(name)s_%(time)s.jl' \
-a batch=1 
```

除了项目和爬虫的名字，我们想爬虫传递了一个 FEED_URI 设置。它的值是从 DISTRIBUTED_TARGET_FEED_URL 得到的。

因为 Scrapy 支持 FTP，我们可以让 scrapyds 用一个匿名 FTP 将抓取的 Item 文件上传到 Spark 服务器。它的格式包括爬虫的名字（%(name)s 和时间（%(time)s）。如果只有这两项的话，那么同一时间创建出来的两个文件就会有冲突。为了避免覆盖，我们加入一个参数%(batch)。Scrapy 默认是不知道批次的，所以我们必须给设定一个值。scrapyd 的 schedule.json API 的特点之一是，每个不是设置的参数或已知的参数都被传递给了爬虫。默认时，爬虫的参数成为了爬虫的属性，然后在爬虫的属性中寻找未知的 FEED_URI 参数。因此，将一批参数传递给 schedule.json，我们就可以在 FEED_URI 中使用它，以避免冲突。

最后是将 DISTRIBUTED_START_URL 和这一批次的子页 URL 编译为 JSON，因为 JSON 是最简洁的文本格式。

> 笔记：用命令行将大量数据传递到 Scrapy 并不可取。如果你想将参数存储到数据库（例如 Redis），只传递给 Scrapy 一个 ID。这么做的话，需要小幅修改 _flush_URL()和 process_start_requests()。

我们用 treq.post()来做 POST 请求。Scrapyd 处理持续连接并不好，因此我们用 persistent=False 取消它。我们还设置了一个 5 秒的暂停。这个请求的的延迟项被保存在 _scrapyd_submits_to_wait 列表。要关闭这个函数，我们重置 _URL 列表，并加大当前的 _batch。

奇怪的是，关闭操作中会出现许多方法，如下所示：

```py
def __init__(self, crawler):
    ...
    crawler.signals.connect(self._closed, signal=signals.spider_
closed)
@defer.inlineCallbacks
def _closed(self, spider, reason, signal, sender):
    # Submit any remaining URL
    self._flush_URL(spider)
    yield defer.DeferredList(self._scrapyd_submits_to_wait) 
```

调用 _closed()可能是因为我们按下了 Ctrl + C 或因为抓取结束。两种情况下，我们不想失去任何最后批次的还未发送的 URL。这就是为什么在 _closed()中，第一件事是调用 _flush_URL(spider)加载最后的批次。第二个问题是，因为是非阻塞的，停止抓取时，[treq.post()](https://link.jianshu.com?t=http://treq.post())可能结束也可能没结束。为了避免丢失最后批次，我们要使用前面提到过的 scrapyd_submits_to_wait 列表，它包括所有的[treq.post()](https://link.jianshu.com?t=http://treq.post())延迟项。我们使用 defer.DeferredList()等待，直到全部完成。因为 _closed()使用了@defer.inlineCallbacks，当所有请求完成时，我们只 yield 它并继续。

总结一下，DISTRIBUTED_START_URL 设置中的批次 URL 会被发送到 scrapyds，scrapyds 上面运行着相同的爬虫。很明显，我们需要使用这个设置以启动 start_URL。

## 从 settings 启动 URL

中间件还提供了一个 process_start_requests()方法，使用它可以处理爬虫提供的 start_requests。检测是否设定了 DISTRIBUTED_START_URL，设定了的话，用 JSON 解码，并使用它的 URL 产生相关的请求。对于这些请求，我们设定 CrawlSpider 的 _response_downloaded()方法作为回调函数，再设定参数 meta['rule']，以让恰当的 Rule 处理响应。我们查看 Scrapy 的源码，找到 CrawlSpider 创建请求的方法，并依法而做：

```py
def __init__(self, crawler):
    ...
    self._start_URL = settings.get('DISTRIBUTED_START_URL', None)
    self.is_worker = self._start_URL is not None
def process_start_requests(self, start_requests, spider):
    if not self.is_worker:
        for x in start_requests:
            yield x
    else:
        for url in json.loads(self._start_URL):
            yield Request(url, spider._response_downloaded,
                          meta={'rule': self._target}) 
```

中间件就准备好了。我们在 settings.py 进行设置以启动它：

```py
SPIDER_MIDDLEWARES = {
    'properties.middlewares.Distributed': 100,
}
DISTRIBUTED_TARGET_RULE = 1
DISTRIBUTED_BATCH_SIZE = 2000
DISTRIBUTED_TARGET_FEED_URL = ("ftp://anonymous@spark/"
                               "%(batch)s_%(name)s_%(time)s.jl")
DISTRIBUTED_TARGET_HOSTS = [
    "scrapyd1:6800",
    "scrapyd2:6800",
    "scrapyd3:6800",
] 
```

有人可能认为 DISTRIBUTED_TARGET_RULE 不应该作为设置，因为它会使爬虫差异化。你可以认为这是个默认值，你可以在你的爬虫中使用属性 custom_settings 覆盖它，例如:

```py
custom_settings = {
    'DISTRIBUTED_TARGET_RULE': 3
} 
```

我们的例子并不需要这么做。我们可以做一个测试运行，只抓取一个页面：

```py
$ scrapy crawl distr -s \
DISTRIBUTED_START_URL='["http://web:9312/properties/property_000000.html"]' 
```

这个成功之后，我们进一步，抓取一个页面之后，用 FTP 将它传送到 Spark 服务器：

```py
scrapy crawl distr -s \
DISTRIBUTED_START_URL='["http://web:9312/properties/property_000000.html"]' \
-s FEED_URI='ftp://anonymous@spark/%(batch)s_%(name)s_%(time)s.jl' -a batch=12 
```

用 ssh 连接 Spark 服务器，你可以看到一个文件，例如/root/items 下的 12_distr_date_time.jl。
这个中间件的例子可以让你完成 scrapyd 的分布式抓取。你可以将它当做起点，进行改造。你可能要做如下修改：

*   爬虫的类型。除了 CrawlSpider，你必须让爬虫用恰当的 meta 标记分布式的请求，用惯用命名法执行调回。
*   向 scrapyds 传递 URL 的方式。你可能想限定域名，减少传递的量。例如，你只想传递 IDs。
*   你可以用分布式排队方案，让爬虫可以从失败恢复，让 scrapyds 执行更多的 URL 批次。
*   你可以动态扩展服务器的规模，以适应需求。

## 将项目部署到 scrapyd 服务器

为了将爬虫附属到三台 scrapyd 服务器上，我们必须将它们添加到 scrapy.cfg 文件。文件上的每个[deploy:target-name]定义了一个新的部署目标：

```py
$ pwd
/root/book/ch11/properties
$ cat scrapy.cfg
...
[deploy:scrapyd1]
url = http://scrapyd1:6800/
[deploy:scrapyd2]
url = http://scrapyd2:6800/
[deploy:scrapyd3]
url = http://scrapyd3:6800/ 
```

你可以用 scrapyd-deploy -l 查询可用的服务器：

```py
$ scrapyd-deploy -l
scrapyd1             http://scrapyd1:6800/
scrapyd2             http://scrapyd2:6800/
scrapyd3             http://scrapyd3:6800/ 
```

用 scrapyd-deploy <target name>进行部署：

```py
$ scrapyd-deploy scrapyd1
Packing version 1449991257
Deploying to project "properties" in http://scrapyd1:6800/addversion.json
Server response (200):
{"status": "ok", "project": "properties", "version": "1449991257", 
"spiders": 2, "node_name": "scrapyd1"} 
```

这个过程会产生一些新的目录和文件（build、project.egg-info、setup.py），可以删掉。其实，scrapyd-deploy 做的就是打包你的项目，并用 addversion.json，传递到目标服务器上。

之后，如果我们用 scrapyd-deploy –L 查询服务器，我们可以确认项目被成功部署了：

```py
$ scrapyd-deploy -L scrapyd1
properties 
```

我还用 touch 在项目的目录创建了三个空文件夹，scrapyd1-3。这样可以将 scrapyd 的名字传递给下面的文件，同时也是服务器的名字。然后可以用 bash loop 将其部署服务器： for i in scrapyd*; do scrapyd-deploy $i; done。

## 创建自定义监视命令

如果你想在多台 scrapyd 服务器上监视抓取的进程，你必须亲自编写程序。这是一个练习所学知识的好机会，写一个原生的 Scrapy 命令，scrapy monitor，用它监视一组 scrapyd 服务器。文件命名为[monitor.py](https://link.jianshu.com?t=http://monitor.py)，在[settings.py](https://link.jianshu.com?t=http://settings.py)中添加 COMMANDS_MODULE = 'properties.monitor'。快速查看 scrapyd 的文档，listjobs.json API 给我们提供了关于任务的信息。如果我们想找到给定目标的根 URL，我们可以断定，它只能是在 scrapyd-deploy 的代码中。如果查看[https://github.com/scrapy/scrapyd-client/blob/master/scrapyd-client/scrapyd-deploy](https://link.jianshu.com?t=https://github.com/scrapy/scrapyd-client/blob/master/scrapyd-client/scrapyd-deploy)，我们可以发现一个 _get_targets()函数（执行它不会添加许多值，所以略去了），它可以给出目标的名字和根 URL。我们现在就可以执行命令的第一部分了，如下所示：

```py
class Command(ScrapyCommand):
    requires_project = True
    def run(self, args, opts):
        self._to_monitor = {}
        for name, target in self._get_targets().iteritems():
            if name in args:
               project = self.settings.get('BOT_NAME')
                url = target['url'] + "listjobs.json?project=" + project
               self._to_monitor[name] = url
        l = task.LoopingCall(self._monitor)
        l.start(5)  # call every 5 seconds
        reactor.run() 
```

这段代码将名字和想要监视的 API 的终点提交给 dict _to_monitor。我们然后使用 task.LoopingCall()规划向 _monitor()方法发起递归调用。_monitor()使用 treq 和 deferred，我们使用@defer.inlineCallbacks 对它进行简化。方法如下（省略了一些错误处理和代码美化）：

```py
@defer.inlineCallbacks
def _monitor(self):
    all_deferreds = []
    for name, url in self._to_monitor.iteritems():
        d = treq.get(url, timeout=5, persistent=False)
        d.addBoth(lambda resp, name: (name, resp), name)
        all_deferreds.append(d)
    all_resp = yield defer.DeferredList(all_deferreds)
    for (success, (name, resp)) in all_resp:
        json_resp = yield resp.json()
        print "%-20s running: %d, finished: %d, pending: %d" %
              (name,  len(json_resp['running']),
              len(json_resp['finished']), len(json_resp['pending'])) 
```

这几行代码包括了目前我们学过的所有 Twisted 方法。我们使用 treq 调用 scrapyd 的 API 和 defer.DeferredList，立即处理所有的响应。当 all_resp 有了所有结果之后，我们重复这个过程，取回它们的 JSON 对象。treq Response'json()方法返回延迟项，而不是实际值，以与后续的实际值继续任务。我们最后打印出结果。JSON 响应的列表信息包括悬挂、运行中、结束的任务，我们打印出它的长度。

## 用 Apache Spark streaming 计算偏移值

我们的 Scrapy 系统现在就功能完备了。让我们来看看 Apache Spark 的使用。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/79e9a84d9e730b0f25ecf18fe9ac40bb.jpg)

让我来看如何执行。请记住这不是 Scrapy 代码，所以看起来会觉得陌生，但是是可以看懂的。你可以在 boostwords.py 文件找到这个应用，这个文件包括了复杂的测试代码，可以忽略。它的主要代码如下：

```py
# Monitor the files and give us a DStream of term-price pairs
raw_data = raw_data = ssc.textFileStream(args[1])
word_prices = preprocess(raw_data)
# Update the counters using Spark's updateStateByKey
running_word_prices = word_prices.updateStateByKey(update_state_
function)
# Calculate shifts out of the counters
shifts = running_word_prices.transform(to_shifts)
# Print the results
shifts.foreachRDD(print_shifts) 
```

Spark 使用 DStream 代表数据流。textFileStream()方法监督文件系统的一个目录，当检测到新文件时，就传出来。我们的 preprocess()函数将它们转化为 term/price 对。我们用 update_state_function()函数和 Spark 的 updateStateByKey()方法累加这些 term/price 对。我们最后通过运行 to_shifts()计算偏移值，并用 print_shifts()函数打印出极值。大多我们的函数修改不大，只是高效重塑了数例据。例外的是 shifts()函数：

```py
def to_shifts(word_prices):
    (sum0, cnt0) = word_prices.values().reduce(add_tuples)
    avg0 = sum0 / cnt0
    def calculate_shift((isum, icnt)):
        avg_with = isum / icnt
        avg_without = (sum0 - isum) / (cnt0 - icnt)
        return (avg_with - avg_without) / avg0
    return word_prices.mapValues(calculate_shift) 
```

这段代码完全是按照公式做的。尽管很简单，Spark 的 mapValues()可以让 calculate_shift 在 Spark 服务器上用最小开销高效运行。

## 进行分布式抓取

我进行四台终端进行抓取。我想让这部分尽量独立，所以我还提供了 vagrant ssh 命令，可以在终端使用。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/17b091193bc1c87eb51a0fe315cd236e.jpg)使用四台终端进行抓取

用终端 1 来检测集群的 CPU 和内存的使用。这可以确认和修复问题。设置方法如下：

```py
$ alias provider_id="vagrant global-status --prune | grep 'docker-
provider' | awk '{print \$1}'"
$ vagrant ssh $(provider_id)
$ docker ps --format "{{.Names}}" | xargs docker stats 
```

前两行可以让我们用 ssh 打开 docker provider VM。如果没有使用 VM，只在 docker Linux 运行，我们只需要最后一行。
终端 2 用作诊断，如下运行 scrapy monitor：

```py
$ vagrant ssh
$ cd book/ch11/properties
$ scrapy monitor scrapyd* 
```

使用 scrapyd*和空文件夹，空文件夹名字是 scrapy monitor，这会扩展到 scrapy monitor scrapyd1 scrapyd2 scrapyd3。

终端 3，是我们启动抓取的终端。除此之外，它基本是闲置的。开始一个新的抓取，我们操作如下：

```py
$ vagrant ssh
$ cd book/ch11/properties
$ for i in scrapyd*; do scrapyd-deploy $i; done
$ scrapy crawl distr 
```

最后两行很重要。首先，我们使用一个 for 循环和 scrapyd-deploy，将爬虫部署到服务器上。然后我们用 scrapy crawl distr 开始抓取。我们随时可以运行小的抓取，例如，scrapy crawl distr -s CLOSESPIDER_PAGECOUNT=100，来抓取 100 个索引页，它会产生大概 3000 个子页。
终端 4 用来连接 Spark 服务器，我们用它进行实时分析：

```py
$ vagrant ssh spark
$ pwd
/root
$ ls
book items
$ spark-submit book/ch11/boostwords.py items 
```

只有最后一行重要，它运行了 boostwords.py，将本地 items 目录传给了监视器。有时，我还使用 watch ls -1 items 来监视 item 文件。
到底哪个词对价格的影响最大呢？这个问题留给读者。

## 系统性能

系统的性能极大地依赖于硬件、CPU 的数量、虚拟机分配内存的大小。在真实情况下，我们可以进行水平扩展，使抓取提速。

理论最大吞吐量是 3 台服务器*4 个 CPU*16 并发数*4 页/秒=768 页/秒。
实际中，使用分配了 4G 内存、8CPU 的虚拟机的 Macbook Pro，2 分 40 秒内下载了 50000 条 URL，即 315 页/秒。在一台亚马逊 EC2 m4.large，它有 2 个 vCPUs、8G 内存，因为 CPU 频率低，用时 6 分 12 秒，即 134 页/秒。在一台台亚马逊 EC2 m4.4xlarge，它有 16 个 vCPUs、64G 内存，用时 1 分 44 秒，即 480 页/秒。在同一台机器上，我将 scrapyd 的数量提高到 6（修改 Vagrantfile、scrapy.cfg 和 settings.py），用时 1 分 15 秒，即 667 页/秒。在最后的例子中，网络服务器似乎是瓶颈。

实际和理论计算存在差距是合理的。我们的粗略计算中没有考虑许多小延迟。尽管我们声明了每个页有 250ms 的延迟，我们在前几章已经看到，实际延迟要更高，这是因为我们还有额外的 Twisted 和操作系统延迟。还有开发机向 scrapyds 传递 URL 的时间，FTP 向 Spark 传递 Items 的时间，还有 scrapyd 发现新文件和规划任务的时间（平均要 2.5 秒，根据 scrapyd 的 poll_interval 设置）。还没计算开发机和 scrapyd 的启动时间。如果不能确定可以提高吞吐量的话，我是不会试图改进这些延迟的。我的下一步是扩大抓取的规模，比如 500000 个页面、网络服务器的负载均衡，在扩大的过程中发现新的挑战。

## 要点

本章的要点是，如果要进行分布式抓取，一定要使用大小合适的批次。
取决于源网站的响应速度，你可能有数百、数千、上万个 URL。你希望它们越大越好（在几分钟的水平），这样就可以分摊启动的费用。另一方面，你也不希望它们太大，以免造成机器故障。在一个有容错的分布式系统中，你需要重试失败的批次，而且重试不要浪费太多时间。

## 总结

希望你能喜欢这本关于 Scrapy 的书。现在你对 Scrapy 应该已经有深入的了解了，并可以解决简单或复杂的问题了。你还学到了 Scrapy 复杂的结构，以及如何发挥出它的最大性能。通过抓取，你可以在应用中使用庞大的数据资源。我们已经看到了如何在移动应用中使用 Scrapy 抓取的数据并进行分析。希望你能用 Scrapy 做出更多强大的应用，为世界做出贡献。祝你好运！

* * *

[序言](https://www.jianshu.com/p/6c9baeb60044)
[第 1 章 Scrapy 介绍](https://www.jianshu.com/p/b807653e97bb)
[第 2 章 理解 HTML 和 XPath](https://www.jianshu.com/p/90c2c25f0c41)
[第 3 章 爬虫基础](https://www.jianshu.com/p/6ebb898841bc)
[第 4 章 从 Scrapy 到移动应用](https://www.jianshu.com/p/4156e757557f)
[第 5 章 快速构建爬虫](https://www.jianshu.com/p/9d1e00dc40e4)
[第 6 章 Scrapinghub 部署](https://www.jianshu.com/p/441fa74d7aad)
[第 7 章 配置和管理](https://www.jianshu.com/p/674de4eacf15)
[第 8 章 Scrapy 编程](https://www.jianshu.com/p/545d07702e7f)
[第 9 章 使用 Pipeline](https://www.jianshu.com/p/e0287e773d28)
[第 10 章 理解 Scrapy 的性能](https://www.jianshu.com/p/e9710002cb4e)
第 11 章（完） Scrapyd 分布式抓取和实时分析

* * *

# 一、Scrapy 介绍



本书作者使用的 Scrapy 版本是 1.0.3。感兴趣的话，还可以看看[Scrapy1.4 最新官方文档总结](https://www.jianshu.com/p/999f3809c98a)。

* * *

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/fed2d5ca4e621f908217b2060f542d55.jpg)
下载本书代码：[https://github.com/scalingexcellence/scrapybook](https://link.jianshu.com?t=https://github.com/scalingexcellence/scrapybook)。
下载本书 PDF（英文版）：[http://file.allitebooks.com/20160330/Learning%20Scrapy.pdf](https://link.jianshu.com?t=http://file.allitebooks.com/20160330/Learning%20Scrapy.pdf)

* * *

欢迎来到 Scrapy 之旅。通过这本书，我们希望你可以从只会一点或零基础的初学者，达到熟练使用这个强大的框架海量抓取网络和其他资源的水平。在本章里，我们会向你介绍 Scrapy，以及 Scrapy 能做什么。

## HelloScrapy

Scrapy 是一个健壮的抓取网络资源的框架。作为互联网使用者，你可能经常希望可以将网上的资源保存到 Excel 中（见第 3 章），以便离线时使用或进行计算。作为开发者，你可能经常希望将不同网站的资源整合起来，但你清楚这么做的复杂性。Scrapy 可以帮助你完成简单和复杂的数据提取。

Scrapy 是利用健壮高效的方式提取网络资源的多年经验开发的。使用 Scrapy，你只需进行一项设置，就可以抵过其它框架使用多个类、插件和配置。看一眼第 7 章，你就可以知道仅需几行代码就可以完成大量工作。

从开发者的角度，你会喜欢 Scrapy 的基于事件的架构（见第 8 章和第 9 章）。它可以让我们进行串联操作，清洗、形成、丰富数据，或存入数据库等等，同时不会有太大的性能损耗。从技术上说，基于事件的机制，Scrapy 可以让吞吐量摆脱延迟，同时开放数千个连接。举一个极端的例子，假设你要从一个网站提取列表，每页有 100 个列表项。Scrapy 可以轻松的同时处理 16 个请求，假设每个请求在一秒内完成，每秒就可以抓取 16 个页面。乘以每页的列表数，每秒就可以抓取 1600 个列表项。然后，你想将每个列表项写入一个高并发的云存储，每个要花 3 秒。为了支持每秒 16 个请求，必须要并行进行 4800 个写入请求（第 9 章你会看到更多类似的计算）。对于传统的多线程应用，这需要 4800 个线程，对你和操作系统都是个挑战。在 Scrapy 中，4800 个并发请求很平常，只要操作系统支持就行。更进一步，Scrapy 的内存要求和你要抓取的列表项的数据量相关，而对于多线程应用，每个线程的大小都和一个列表的大小相当。

简而言之，速度慢或不可预测的网站、数据库或远程 API 不会对 Scrapy 的性能造成影响，因为你可以进行并发请求，用单线程管理。相比于多线程应用，使用更简单的代码反而可以同时运行几个抓取器和其它应用，这样就可以降低费用。

## 喜爱 Scrapy 的其它理由

Scrapy 出现已经有五年多了，现在已经成熟稳定。除了前面提到的性能的优点，以下是 Scrapy 其它让人喜爱的理由：

*   Scrapy 可以读懂破损的 HTML

你可以在 Scrapy 上直接使用 BeautifulSoup 或 lxml，但 Scrapy 提供 Selector，一个相比 lxml 更高级的 XPath 解析器。它可以有效的处理破损的 HTML 代码和费解的编码。

*   社区

Scrapy 有一个活跃的社区。可以查看 Scrapy 的邮件列表[https://groups.google.com/forum/#!forum/scrapy-users](https://link.jianshu.com?t=https://groups.google.com/forum/#!forum/scrapy-users)和 Stack Overflow 上的数千个问题[http://stackoverflow.com/questions/tagged/scrapy](https://link.jianshu.com?t=http://stackoverflow.com/questions/tagged/scrapy)。多数问题在数分钟之内就会得到解答。[http://scrapy.org/community/](https://link.jianshu.com?t=http://scrapy.org/community/)有更多的社区资源。

*   由社区维护的组织清晰的代码

Scrapy 需要用标准的方式组织代码。你用 Python 来写爬虫和 pipelines，就可以自动使引擎的效率提高。如果你在网上搜索，你会发现许多人有使用 Scrapy 的经验。这意味着，可以方便地找人帮你维护或扩展代码。无论是谁加入你的团队，都不必经过学习曲线理解你特别的爬虫。

*   注重质量的更新

如果查看版本记录（[http://doc.scrapy.org/en/latest/news.html](https://link.jianshu.com?t=http://doc.scrapy.org/en/latest/news.html)），你会看到有不断的更新和稳定性/错误修正。

## 关于此书：目标和用法

对于此书，我们会用例子和真实的数据教你使用 Scrapy。大多数章节，要抓取的都是一个房屋租赁网站。我们选择它的原因是，它很有代表性，并可以进行一定的变化，同时也很简单。使用这个例子，可以让我们专注于 Scrapy。

我们会从抓取几百页开始，然后扩展到抓取 50000 页。在这个过程中，我们会教你如何用 Scrapy 连接 MySQL、Redis 和 Elasticsearch，使用 Google geocoding API 找到给定地点的坐标，向 Apach Spark 传入数据，预测影响价格的关键词。

你可能需要多读几遍本书。你可以粗略地浏览一遍，了解一下结构，然后仔细读一两章、进行学习和试验，然后再继续读。如果你对哪章熟悉的话，可以跳过。如果你熟悉 HTML 和 XPath 的话，就没必要在第 2 章浪费太多时间。某些章如第 8 章，既是示例也是参考，具有一定深度。它就需要你多读几遍，每章之间进行数周的练习。如果没有完全搞懂第 8 章的话，也可以读第 9 章的具体应用。后者可以帮你进一步理解概念。

我们已经尝试调整本书的结构，以让其既有趣也容易上手。但我们做不到用这本书教给你如何使用 Python。Python 的书有很多，但我建议你在学习的过程中尽量保持放松。Python 流行的原因之一是，它很简洁，可以像读英语一样读代码。对于 Python 初学者和专家，Scrapy 都是一个高级框架。你可以称它为“Scrapy 语言”。因此，我建议你直接从实例学习，如果你觉得 Python 语法有困难的话，再进行补充学习，可以是在线的 Python 教程或 Coursera 的初级课程。放心，就算不是 Python 专家，你也可以成为一个优秀的 Scrapy 开发者。

## 掌握自动抓取数据的重要性

对于许多人，对 Scrapy 这样的新技术有好奇心和满足感，就是学习的动力。学习这个框架的同时，我们可以从数据开发和社区，而不是代码，获得额外的好处。

## 开发高可靠高质量的应用 提供真实的开发进度表

为了开发新颖高质量的应用，我们需要真实和大量的数据，如果可能的话，最好在写代码之前就有数据。现在的软件开发都要实时处理海量的瑕疵数据，以获取知识和洞察力。当软件应用到海量数据时，错误和疏忽很难检测出来，就会造成后果严重的决策。例如，在进行人口统计时，很容易忽略一整个州，仅仅是因为这个州的名字太长，它的数据被丢弃了。通过细心的抓取，有高质量的、海量的真实数据，在开发和设计的过程中，就可以找到并修复 bug，然后才能做出正确的决策。

另一个例子，假设你想设计一个类似亚马逊的“如果你喜欢这个，你可能也喜欢那个”的推荐系统。如果在开始之前，你就能抓取手机真实的数据，你就可以快速知道一些问题，比如无效记录、打折商品、重复、无效字符、因为分布导致的性能问题。数据会强制你设计健壮的算法以处理被数千人抢购或无人问津的商品。相比较于数周开发之后却碰到现实问题，这两种方法可能最终会一致，但是在一开始就能对整个进程有所掌握，意义肯定是不同的。从数据开始，可以让软件的开发过程更为愉悦和有预测性。

## 快速开发最小化可行产品

海量真实数据对初创企业更为重要。你可能听说过“精益初创企业”，这是 Eric Ries 发明的词，用来描述高度不确定的企业发展阶段，尤其是技术初创企业。它的核心概念之一就是最小化可行产品（MVP），一个只包含有限功能的产品，快速开发并投放，以检测市场反应、验证商业假设。根据市场反应，初创企业可以选择追加投资，或选择其他更有希望的项目。

很容易忽略这个过程中的某些方面，这些方面和数据问题密切相关，用 Scrapy 可以解决数据问题。当我们让潜在用户尝试移动 App 时，例如，作为开发者或企业家，我们让用户来判断完成的 App 功能如何。这可能对非专家的用户有点困难。一个应用只展示“产品 1”、“产品 2”、“用户 433”，和另一个应用展示“Samsung UN55J6200 55-Inch TV”，用户“Richard S.”给它打了五星评价，并且有链接可以直接打开商品主页，这两个应用的差距是非常大的。很难让人们对 MVP 进行客观的评价，除非它使用的数据是真实可信的。

一些初创企业事后才想到数据，是因为考虑到采集数据很贵。事实上，我们通常都是打开表格、屏幕、手动输入数据，或者我们可以用 Scrapy 抓取几个网站，然后再开始写代码。第 4 章中，你可以看到如何快速创建一个移动 App 以使用数据。

## 网络抓取让你的应用快速成长 —— Google 不能使用表格

让我们来看看表格是如何影响一个产品的。假如谷歌的创始人创建了搜索引擎的第一个版本，但要求每个网站站长填入信息，并复制粘贴他们的每个网页的链接。他们然后接受谷歌的协议，让谷歌处理、存储、呈现内容，并进行收费。可以想象整个过程工作量巨大。即使市场有搜索引擎的需求，这个引擎也成为不了谷歌，因为它的成长太慢了。即使是最复杂的算法也不能抵消缺失数据。谷歌使用网络爬虫逐页抓取，填充数据库。站长完全不必做任何事。实际上，想屏蔽谷歌，还需要做一番努力。

让谷歌使用表格的主意有点搞笑，但是一个普通网站要用户填多少表呢？登录表单、列表表单、勾选表单等等。这些表单会如何遏制应用的市场扩张？如果你足够了解用户，你会知道他们还会使用其它什么网站，或许已经有了账户。例如，开发者可能有 Stack Overflow 和 GitHub 账户。经过用户同意，你能不能直接用这些账户就自动填入照片、介绍和最近的帖子呢？你能否对这些帖子做文本分析，根据结果设置网站的导航结构、推荐商品或服务呢？我希望你能看到将表格换为自动数据抓取可以更好的为用户服务，使网站快速成长。

## 发现并实践

抓取数据自然而然会让你发现和思考你和被抓取目标的关系。当你抓取一个数据源时，自然会有一些问题：我相信他们的数据吗？我相信提供数据的公司吗？我应该和它们正式商谈合作吗？我和他们有竞争吗？从其他渠道获得数据花费是多少？这些商业风险是必然存在的，但是抓取数据可以让我们更早的知道，进行应对。

你还想知道如何反馈给这些网站或社区？给他们免费流量，他们肯定很高兴。另一方面，如果你的应用不能提供价值，继续合作的可能就会变小，除非找到另外合作的方式。通过从各种渠道获得数据，你可以开发对现有生态更友好的产品，甚至打败旧产品。或者，老产品能帮助你扩张，例如，你的应用数据来自两个或三个不同的生态圈，每个生态圈都有十万名用户，结合起来，你的应用或许就能惠及三十万人。假如你的初创企业结合了摇滚乐和 T 恤印刷行业，就将两个生态圈结合了起来，你和这两个社区都可以得到扩张。

## 在充满爬虫的网络世界做守法公民

开发爬虫还有一些注意事项。不负责任的网络抓取让人不悦，有时甚至是犯罪。两个最重要的要避免的就是拒绝访问攻击（DoS）和侵犯著作权。

对于第一个，普通访问者每隔几秒才访问一个新页面。爬虫的话，每秒可能下载几十个页面。流量超过普通用户的十倍。这会让网站的拥有者不安。使用阻塞器降低流量，模仿普通用户。检测响应时间，如果看到响应时间增加，则降低抓取的强度。好消息是 Scrapy 提供了两个现成的方法（见第 7 章）。

对于著作权，可以查看网站的著作权信息，以确认什么可以抓取什么不能抓取。大多数站点允许你处理网站的信息，只要不复制并宣称是你的。一个好的方法是在你请求中使用一个 User-Agent 字段，告诉网站你是谁，你想用他们的数据做什么。Scrapy 请求默认使用你的 BOT_NAME 作为 User-Agent。如果这是一个 URL 或名字，可以直接指向你的应用，那么源网站的站长就可以访问你的站点，并知道你用他的数据做什么。另一个重要的地方，允许站长可以禁止爬虫访问网站的某个区域。Scrapy 提供了功能（RobotsTxtMiddleware），以尊重源网站列在 robots.txt 文件的意见（在[http://www.google.com/robots.txt](https://link.jianshu.com?t=http://www.google.com/robots.txt)可以看到一个例子）。最后，最好提供可以让站长提出拒绝抓取的方法。至少，可以让他们很容易地找到你，并提出交涉。

每个国家的法律不同，我无意给出法律上的建议。如果你觉得需要的话，请寻求专业的法律建议。这适用于整本书的内容。

## Scrapy 不是什么

最后，因为数据抓取和相关的名词定义很模糊，或相互使用，很容易误解 Scrapy。我这里解释一下，避免发生误解。

Scrapy 不是 Apache Nutch，即它不是一个原生的网络爬虫。如果 Scrapy 访问一个网站，它对网站一无所知，就不能抓取任何东西。Scrapy 是用来抓取结构化的信息，并需要手动设置 XPath 和 CSS 表达式。Apache Nutch 会取得一个原生网页并提取信息，例如关键词。它更适合某些应用，而不适合其它应用。

Scrapy 不是 Apache Solr、Elasticsearch 或 Lucene；换句话说，它和搜索引擎无关。Scrapy 不是用来给包含“爱因斯坦”的文档寻找参考。你可以使用 Scrapy 抓取的数据，并将它们插入到 Solr 或 Elasticsearch，如第 9 章所示，但这只是使用 Scrapy 的一种途径，而不是嵌入 Scrapy 的功能。

最后，Scrapy 不是类似 MySQL、MongoDB、Redis 的数据库。它不存储和索引数据。它只是提取数据。也就是说，你需要将 Scrapy 提取的数据插入到数据库中，可行的数据库有多种。虽然 Scrapy 不是数据库，它的结果可以方便地输出为文件，或不进行输出。

## 总结

在本章中，我们向你介绍了 Scrapy 以及它的作用，还有使用这本书的最优方法。通过开发与市场完美结合的高质量应用，我们还介绍了几种自动抓取数据能使你获益的方法。下一章会介绍两个极为重要的网络语言，HTML 和 XPath，我们在每个 Scrapy 项目中都会用到。



# 二、理解 HTML 和 XPath



为了从网页提取信息，了解网页的结构是非常必要的。我们会快速学习 HTML、HTML 的树结构和用来筛选网页信息的 XPath。

## HTML、DOM 树结构和 XPath

从这本书的角度，键入网址到看见网页的整个过程可以分成四步：

*   在浏览器中输入网址 URL。URL 的第一部分,也即域名（例如 gumtree.com），用来搜寻网络上的服务器。URL 和其他像 cookies 等数据形成了一个发送到服务器的请求 request。
*   服务器向浏览器发送 HTML。服务器也可能发送 XML 或 JSON 等其他格式，目前我们只关注 HTML。
*   HTML 在浏览器内部转化成树结构：文档对象模型（DOM）。
*   根据布局规范，树结构转化成屏幕上的真实页面。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/b25cb1ef4a9f8b77c22f189454c8d4e9.jpg)

研究下这四个步骤和树结构，可以帮助定位要抓取的文本和编写爬虫。

**URL**
URL 包括两部分：第一部分通过 DNS 定位服务器，例如当你在浏览器输入[https://mail.google.com/mail/u/0/#inbox](https://link.jianshu.com?t=https://mail.google.com/mail/u/0/#inbox)这个地址时，产生了一个[mail.google.com](https://link.jianshu.com?t=http://mail.google.com)的 DNS 请求，后者为你解析了一台服务器的 IP 地址，例如 173.194.71.83。也就是说，[https://mail.google.com/mail/u/0/#inbox](https://link.jianshu.com?t=https://mail.google.com/mail/u/0/#inbox)转换成了[https://173.194.71.83/mail/u/0/#inbox](https://link.jianshu.com?t=https://173.194.71.83/mail/u/0/#inbox)。

URL 其余的部分告诉服务器这个请求具体是关于什么的，可能是一张图片、一份文档或是触发一个动作，例如在服务器上发送一封邮件。

## HTML 文档

服务器读取 URL，了解用户请求，然后回复一个 HTML 文档。HTML 本质是一个文本文件，可以用 TextMate、Notepad、vi 或 Emacs 等软件打开。与大多数文本文件不同，HTML 严格遵循万维网联盟（World Wide Web Consortium）的规定格式。这个格式超出了本书的范畴，这里只看一个简单的 HTML 页面。如果你打开[http://example.com](https://link.jianshu.com?t=http://example.com)，点击查看源代码，就可以看到 HTML 代码，如下所示：

```py
<!doctype html>
<html>
  <head>
      <title>Example Domain</title>
      <meta charset="utf-8" />
      <meta http-equiv="Content-type"
              content="text/html; charset=utf-8" />
      <meta name="viewport" content="width=device-width,
              initial-scale=1" />
      <style type="text/css"> body { background-color: ... 
              } </style>
  <body>
      <div>
              <h1>Example Domain</h1>
              <p>This domain is established to be used for
                 illustrative examples examples in documents.
                 You may use this domain in examples without
                 prior coordination or asking for permission.</p>
              <p><a href="http://www.iana.org/domains/example">
                 More information...</a></p>
      </div>
  </body>
</html> 
```

为了便于阅读，我美化了这个 HTML 文档。你也可以把整篇文档放在一行里。对于 HTML，大多数情况下，空格和换行符不会造成什么影响。

尖括号里的字符称作标签，例如`<html>`或`<head>`。`<html>`是起始标签，`</html>`是结束标签。标签总是成对出现。某些网页没有结束标签，例如只用`<p>`标签分隔段落，浏览器对这种行为是容许的，会智能判断哪里该有结束标签`</p>`。
`<p>`与`</p>`之间的内容称作 HTML 的元素。元素之间可以嵌套元素，比如例子中的`<div>`标签，和第二个`<p>`标签，后者包含了一个`<a>`标签。

有些标签稍显复杂，例如<a href="http://www.iana.org/domains/example">，带有 URL 的 href 部分称作属性。
最后，许多标签元素包含有文本，例如`<h1>`标签中的 Example Domain。对我们而言，`<body>`标签之间的可见内容更为重要。头部标签`<head>`中指明了编码字符，由 Scrapy 对其处理，就不用我们浪费精力了。

## 树结构

不同的浏览器有不同的借以呈现网页的内部数据结构。但 DOM 树是跨平台且不依赖语言的，可以被几乎所有浏览器支持。

只需右键点击，选择查看元素，就可以在浏览器中查看网页的树结构。如果这项功能被禁止了，可以在选项的开发者工具中修改。

你看到的树结构和 HTML 很像，但不完全相同。无论原始 HTML 文件使用了多少空格和换行符，树结构看起来都会是一样的。你可以点击任意元素，或是改变属性，这样可以实时看到对 HTML 网页产生了什么变化。例如，如果你双击了一段文字，并修改了它，然后点击回车，屏幕上这段文字就会根据新的设置发生改变。在右边的方框中，在属性标签下面，你可以看到这个树结构的属性列表。在页面底部，你可以看到一个面包屑路径，指示着选中元素的所在位置。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/bc0283189f44b51f7d4b3e85059b1916.jpg)

重要的是记住，HTML 是文本，而树结构是浏览器内存中的一个对象，你可以通过程序查看、操作这个对象。在 Chrome 浏览器中，就是通过开发者工具查看。

## 浏览器中的页面

HTML 文本和树结构和我们平时在浏览器中看到的页面截然不同。这恰恰是 HTML 的成功之处。HTML 文件就是要具有可读性，可以区分网页的内容，但不是按照呈现在屏幕上的方式。这意味着，呈现 HTML 文档、进行美化都是浏览器的职责，无论是对于功能齐备的 Chrome、移动端浏览器、还是 Lynx 这样的文本浏览器。

也就是说，网页的发展对网页开发者和用户都提出了极大的开发网页方面的需求。CSS 就是这样被发明出来，用以服务 HTML 元素。对于 Scrapy，我们不涉及 CSS。

既然如此，树结构对呈现出来的网页有什么作用呢？答案就是盒模型。正如 DOM 树可以包含其它元素或是文字，同样的，盒模型里面也可以内嵌其它内容。所以，我们在屏幕上看到的网页是原始 HTML 的二维呈现。树结构是其中的一维，但它是隐藏的。例如，在下图中，我们看到三个 DOM 元素，一个`<div>`和两个内嵌的`<h1>`和`<p>`，出现在浏览器和 DOM 中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/ae065e2832210ba3d38deeccdb8c3d4c.jpg)

**用 XPath 选择 HTML 元素**
如果你以前接触过传统的软件工程，并不知道 XPath，你可能会担心，在 HTML 文档中查询某个信息，要进行复杂的字符串匹配、搜索标签、处理特殊字符、解析整个树结构等繁琐工作。对于 XPath，所有的这些都不是问题，你可以轻松提取元素、属性或是文字。

在 Chrome 中使用 XPath，在开发者工具中点击控制台标签，使用$x 功能。例如，在网页[http://example.com/](https://link.jianshu.com?t=http://example.com/)的控制台，输入$x('//h1')，就可以移动到`<h1>`元素，如截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/783e36acdaec98fbd4b2dd994b1c6a92.jpg)

你在控制台中看到的是一个包含所选元素的 JavaScript 数组。如果你将光标移动到这个数组上，你可以看到被选择的元素被高亮显示。这个功能很有用。

**XPath 表达式**
HTML 文档的层级结构的最高级是`<html>`标签，你可以使用元素名和斜杠线选择任意元素。例如，下面的表达式返回了[http://example.com/](https://link.jianshu.com?t=http://example.com/)上对应的内容：

```py
$x('/html')
  [ <html>...</html> ]
$x('/html/body')
  [ <body>...</body> ]
$x('/html/body/div')
  [ <div>...</div> ]
$x('/html/body/div/h1')
  [ <h1>Example Domain</h1> ]
$x('/html/body/div/p')
  [ <p>...</p>, <p>...</p> ]
$x('/html/body/div/p[1]')
  [ <p>...</p> ]
$x('/html/body/div/p[2]')
  [ <p>...</p> ] 
```

注意，`<p>`标签在`<div>`标签内有两个，所以会返回两个。你可以用 p[1]和 p[2]分别返回两个元素。

从抓取的角度，文档的标题或许是唯一让人感兴趣的，它位于文档的头部，可以用下面的额表达式找到：

```py
$x('//html/head/title')
  [ <title>Example Domain</title> ] 
```

对于大文档，你可能要写很长的 XPath 表达式，以获取所要的内容。为了避免这点，两个斜杠线//可以让你访问到所有的同名元素。例如，//p 可以选择所有的 p 元素，//a 可以选择所有的链接。

```py
$x('//p')
  [ <p>...</p>, <p>...</p> ]
$x('//a')
  [ <a href="http://www.iana.org/domains/example">More information...</a> ] 
```

//a 可以用在更多的地方。例如，如果要找到所有`<div>`标签的链接，你可以使用//div//a。如果 a 前面只有一个斜杠，//div/a 会返回空，因为在上面的例子中`<div>`标签下面没有`<a>`。

```py
$x('//div//a')
  [ <a href="http://www.iana.org/domains/example">More information...</a> ]
$x('//div/a')
  [ ] 
```

你也可以选择属性。[http://example.com/](https://link.jianshu.com?t=http://example.com/)上唯一的属性是链接 href，可以通过下面的方式找到：

```py
$x('//a/@href')
[href="http://www.iana.org/domains/example"] 
```

你也可以只通过 text( )函数选择文字：

```py
$x('//a/text()')
["More information..."] 
```

可以使用*标志选择某层下所有的元素，例如：

```py
$x('//div/*')
[<h1>Example Domain</h1>, <p>...</p>, <p>...</p>] 
```

寻找特定属性，例如@class、或属性有特定值时，你会发现 XPath 非常好用。例如，//a[@href]可以找到所有链接，//a[@href="[http://www.iana.org/domains/example](https://link.jianshu.com?t=http://www.iana.org/domains/example)"]则进行了指定的选择。
当属性值中包含特定字符串时，XPath 会极为方便。例如，

```py
$x('//a[@href]')
[<a href="http://www.iana.org/domains/example">More information...</a>]
$x('//a[@href="http://www.iana.org/domains/example"]')
[<a href="http://www.iana.org/domains/example">More information...</a>]
$x('//a[contains(@href, "iana")]')
[<a href="http://www.iana.org/domains/example">More information...</a>]
$x('//a[starts-with(@href, "http://www.")]')
[<a href="http://www.iana.org/domains/example">More information...</a>]
$x('//a[not(contains(@href, "abc"))]')
[ <a href="http://www.iana.org/domains/example">More information...</a>] 
```

在[http://www.w3schools.com/xsl/xsl_functions.asp](https://link.jianshu.com?t=http://www.w3schools.com/xsl/xsl_functions.asp)在线文档中你可以找到更多类似的函数，但并非都常用。

在 Scrapy 终端中可以使用同样的命令，在命令行中输入

```py
scrapy shell "http://example.com" 
```

终端会向你展示许多写爬虫时碰到的变量。其中最重要的是响应，在 HTML 中是 HtmlResponse，这个类可以让你在 Chrome 使用 xpath( )方法$x。下面是一些例子：

```py
response.xpath('/html').extract()
  [u'<html><head><title>...</body></html>']
response.xpath('/html/body/div/h1').extract()
  [u'<h1>Example Domain</h1>']
response.xpath('/html/body/div/p').extract()
  [u'<p>This domain ... permission.</p>', u'<p><a href="http://www.iana.org/domains/example">More information...</a></p>']
response.xpath('//html/head/title').extract()
  [u'<title>Example Domain</title>']
response.xpath('//a').extract()
  [u'<a href="http://www.iana.org/domains/example">More information...</a>']
response.xpath('//a/@href').extract()
  [u'http://www.iana.org/domains/example']
response.xpath('//a/text()').extract()
  [u'More information...']
response.xpath('//a[starts-with(@href, "http://www.")]').extract()
  [u'<a href="http://www.iana.org/domains/example">More information...</a>'] 
```

这意味着，你可用 Chrome 浏览器生成 XPath 表达式，以便在 Scrapy 爬虫中使用。

## 使用 Chrome 浏览器获得 XPath 表达式

Chrome 浏览器可以帮助我们获取 XPath 表达式这点确实对开发者非常友好。像之前演示的那样检查一个元素：右键选择一个元素，选择检查元素。开发者工具被打开，该元素在 HTML 的树结构中被高亮显示，可以在右键打开的菜单中选择 Copy XPath，表达式就复制到粘贴板中了。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/learn-scrapy/img/1a8e8e9983d33acbb25393490b2a68d2.jpg)

你可以在控制台中检测表达式：

```py
$x('/html/body/div/p[2]/a')
[<a href="http://www.iana.org/domains/example">More information...</a>] 
```

## 常见工作

下面展示一些 XPath 表达式的常见使用。先来看看在维基百科上是怎么使用的。维基百科的页面非常稳定，不会在短时间内改变排版。

*   取得 id 为 firstHeading 的 div 下的 span 的 text：

```py
//h1[@id="firstHeading"]/span/text() 
```

*   取得 id 为 toc 的 div 下的 ul 内的 URL：

```py
//div[@id="toc"]/ul//a/@href 
```

*   在任意 class 包含 ltr 和 class 包含 skin-vector 的元素之内，取得 h1 的 text，这两个字符串可能在同一 class 内，或不在。

```py
//*[contains(@class,"ltr") and contains(@class,"skin-vector")]//h1//text() 
```

实际应用中，你会在 XPath 中频繁地使用 class。在这几个例子中，你需要记住，因为 CSS 的板式原因，你会看到 HTML 的元素总会包含许多特定的 class 属性。这意味着，有的`<div>`的 class 是 link，其他导航栏的`<div>`的 class 就是 link active。后者是当前生效的链接，因此是可见或是用 CSS 特殊色高亮显示的。当抓取的时候，你通常是对含有某个属性的元素感兴趣的，就像之前的 link 和 link active。XPath 的 contains( )函数就可以帮你选择包含某一 class 的所有元素。

*   选择 class 属性是 infobox 的 table 的第一张图片的 URL：

```py
//table[@class="infobox"]//img[1]/@src 
```

*   选择 class 属性是 reflist 开头的 div 下面的所有 URL 链接：

```py
//div[starts-with(@class,"reflist")]//a/@href 
```

*   选择 div 下面的所有 URL 链接，并且这个 div 的下一个相邻元素的子元素包含文字 References：

```py
//*[text()="References"]/../following-sibling::div//a 
```

*   取得所有图片的 URL：

```py
//img/@src 
```

## 提前应对网页发生改变

爬取的目标常常位于远程服务器。这意味着，如果它的 HTML 发生了改变，XPath 表达式就无效了，我们就不得不回过头修改爬虫的程序。因为网页的改变一般就很少，爬虫的改动往往不会很大。然而，我们还是宁肯不要回头修改。一些基本原则可以帮助我们降低表达式失效的概率：

*   避免使用数组序号
    Chrome 常常会在表达式中加入许多常数

```py
//*[@id="myid"]/div/div/div[1]/div[2]/div/div[1]/div[1]/a/img 
```

如果 HTML 上有一个广告窗的话，就会改变文档的结构，这个表达式就会失效。解决的方法是，尽量找到离 img 标签近的元素，根据该元素的 id 或 class 属性，进行抓取，例如：

```py
//div[@class="thumbnail"]/a/img 
```

*   用 class 抓取效果不一定好
    使用 class 属性可以方便的定位要抓取的元素，但是因为 CSS 也要通过 class 修改页面的外观，所以 class 属性可能会发生改变，例如下面用到的 class：

```py
//div[@class="thumbnail"]/a/img 
```

过一段时间之后，可能会变成：

```py
//div[@class="preview green"]/a/img 
```

*   数据指向的 class 优于排版指向的 class
    在上一个例子中，使用 thumbnail 和 green 两个 class 都不好。thumbnail 比 green 好，但这两个都不如 departure-time。前面两个是用来排版的，departure-time 是有语义的，和 div 中的内容有关。所以，在排版发生改变的情况下，departure-time 发生改变的可能性会比较小。应该说，网站作者在开发中十分清楚，为内容设置有意义的、一致的标记，可以让开发过程收益。

*   id 通常是最可靠的
    只要 id 具有语义并且数据相关，id 通常是抓取时最好的选择。部分原因是，JavaScript 和外链锚点总是使用 id 获取文档中特定的部分。例如，下面的 XPath 非常可靠：

```py
//*[@id="more_info"]//text( ) 
```

相反的例子是，指向唯一参考的 id，对抓取没什么帮助，因为抓取总是希望能够获取具有某个特点的所有信息。例如：

```py
//[@id="order-F4982322"] 
```

这是一个非常差的 XPath 表达式。还要记住，尽管 id 最好要有某种特点，但在许多 HTML 文档中，id 都很杂乱无章。

**总结**
编程语言的不断进化，使得创建可靠的 XPath 表达式从 HTML 抓取信息变得越来越容易。在本章中，你学到了 HTML 和 XPath 的基本知识、如何利用 Chrome 自动获取 XPath 表达式。你还学会了如何手工写 XPath 表达式，并区分可靠和不够可靠的 XPath 表达式。第 3 章中，我们会用这些知识来写几个爬虫。

