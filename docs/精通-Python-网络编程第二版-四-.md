# 精通 Python 网络编程第二版（四）

> 原文：[`zh.annas-archive.org/md5/dda7e4d1dd78bc5577547014ce9b53d1`](https://zh.annas-archive.org/md5/dda7e4d1dd78bc5577547014ce9b53d1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：使用 Python 构建网络 Web 服务

在之前的章节中，我们是各种工具提供的 API 的消费者。在第三章中，*API 和意图驱动的网络*，我们看到我们可以使用`HTTP POST`方法到`http://<your router ip>/ins` URL 上的 NX-API，其中`CLI`命令嵌入在主体中，以远程执行 Cisco Nexus 设备上的命令；然后设备返回命令执行输出。在第八章中，*使用 Python 进行网络监控-第 2 部分*，我们使用`GET`方法来获取我们 sFlow-RT 的`http://<your host ip>:8008/version`上的版本，主体为空。这些交换是 RESTful Web 服务的例子。

根据维基百科（[`en.wikipedia.org/wiki/Representational_state_transfer`](https://en.wikipedia.org/wiki/Representational_state_transfer)）：

“表征状态转移（REST）或 RESTful Web 服务是提供互操作性的一种方式，用于互联网上的计算机系统。符合 REST 标准的 Web 服务允许请求系统使用一组统一和预定义的无状态操作来访问和操作 Web 资源的文本表示。”

如前所述，使用 HTTP 协议的 REST Web 服务只是网络上信息交换的许多方法之一；还存在其他形式的 Web 服务。然而，它是今天最常用的 Web 服务，具有相关的`GET`，`POST`，`PUT`和`DELETE`动词作为信息交换的预定义方式。

使用 RESTful 服务的优势之一是它可以让您隐藏用户对内部操作的了解，同时仍然为他们提供服务。例如，在 sFlow-RT 的情况下，如果我们要登录安装了我们软件的设备，我们需要更深入地了解工具，才能知道在哪里检查软件版本。然而，通过以 URL 的形式提供资源，软件将版本检查操作从请求者中抽象出来，使操作变得更简单。抽象还提供了一层安全性，因为现在可以根据需要仅打开端点。

作为网络宇宙的大师，RESTful Web 服务提供了许多显着的好处，我们可以享受，例如以下：

+   您可以将请求者与网络操作的内部细节分离。例如，我们可以提供一个 Web 服务来查询交换机版本，而无需请求者知道所需的确切 CLI 命令或 API 格式。

+   我们可以整合和定制符合我们网络需求的操作，例如升级所有顶部交换机的资源。

+   我们可以通过仅在需要时公开操作来提供更好的安全性。例如，我们可以为核心网络设备提供只读 URL（`GET`），并为访问级别交换机提供读写 URL（`GET` / `POST` / `PUT` / `DELETE`）。

在本章中，我们将使用最流行的 Python Web 框架之一**Flask**来为我们的网络创建自己的 REST Web 服务。在本章中，我们将学习以下内容：

+   比较 Python Web 框架

+   Flask 简介

+   静态网络内容的操作

+   涉及动态网络操作的操作

让我们开始看看可用的 Python Web 框架以及为什么我们选择了 Flask。

# 比较 Python Web 框架

Python 以其众多的 web 框架而闻名。在 PyCon 上有一个笑话，即你永远不能成为全职 Python 开发者而不使用任何 Python web 框架。甚至为 Django 举办了一年一度的会议，这是最受欢迎的 Python 框架之一，叫做 DjangoCon。每年都吸引数百名与会者。如果你在[`hotframeworks.com/languages/python`](https://hotframeworks.com/languages/python)上对 Python web 框架进行排序，你会发现在 Python 和 web 框架方面选择是不缺乏的。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/15528b62-5084-4ef6-936e-5f53f2f6faa0.png)Python web 框架排名

有这么多选择，我们应该选择哪个框架呢？显然，自己尝试所有的框架将非常耗时。关于哪个 web 框架更好的问题也是网页开发者之间的一个热门话题。如果你在任何论坛上问这个问题，比如 Quora，或者在 Reddit 上搜索，准备好接受一些充满个人意见的答案和激烈的辩论。

说到 Quora 和 Reddit，这里有一个有趣的事实：Quora 和 Reddit 都是用 Python 编写的。Reddit 使用 Pylons（[`www.reddit.com/wiki/faq#wiki_so_what_python_framework_do_you_use.3F`](https://www.reddit.com/wiki/faq#wiki_so_what_python_framework_do_you_use.3F.)），而 Quora 最初使用 Pylons，但用他们自己的内部代码替换了部分框架（[`www.quora.com/What-languages-and-frameworks-are-used-to-code-Quora`](https://www.quora.com/What-languages-and-frameworks-are-used-to-code-Quora)）。

当然，我对编程语言（Python！）和 web 框架（Flask！）有自己的偏见。在这一部分，我希望向你传达我选择一个而不是另一个的理由。让我们选择前面 HotFrameworks 列表中的前两个框架并进行比较：

+   **Django**：这个自称为“完美主义者与截止日期的 web 框架”是一个高级 Python web 框架，鼓励快速开发和清晰的实用设计（[`www.djangoproject.com/`](https://www.djangoproject.com/)）。它是一个大型框架，提供了预先构建的代码，提供了管理面板和内置内容管理。

+   **Flask**：这是一个基于 Werkzeug，Jinja2 和良好意图的 Python 微框架（[`flask.pocoo.org/`](http://flask.pocoo.org/)）。作为一个微框架，Flask 的目标是保持核心小，需要时易于扩展。微框架中的“微”并不意味着 Flask 功能不足，也不意味着它不能在生产环境中工作。

就我个人而言，我觉得 Django 有点难以扩展，大部分时间我只使用预先构建的代码的一小部分。Django 框架对事物应该如何完成有着强烈的意见；任何偏离这些意见的行为有时会让用户觉得他们在“与框架作斗争”。例如，如果你看一下 Django 数据库文档，你会注意到这个框架支持多种不同的 SQL 数据库。然而，它们都是 SQL 数据库的变体，比如 MySQL，PostgreSQL，SQLite 等。如果你想使用 NoSQL 数据库，比如 MongoDB 或 CouchDB 呢？这可能是可能的，但可能会让你自己摸索。成为一个有主见的框架当然不是坏事，这只是一个观点问题（无意冒犯）。

我非常喜欢保持核心代码简洁，并在需要时进行扩展的想法。文档中让 Flask 运行的初始示例只包含了八行代码，即使你没有任何经验，也很容易理解。由于 Flask 是以扩展为核心构建的，编写自己的扩展，比如装饰器，非常容易。尽管它是一个微框架，但 Flask 核心仍然包括必要的组件，比如开发服务器、调试器、与单元测试的集成、RESTful 请求分发等等，可以让你立即开始。正如你所看到的，除了 Django，Flask 是按某些标准来说第二受欢迎的 Python 框架。社区贡献、支持和快速发展带来的受欢迎程度有助于进一步扩大其影响力。

出于上述原因，我觉得 Flask 是我们在构建网络 Web 服务时的理想选择。

# Flask 和实验设置

在本章中，我们将使用`virtualenv`来隔离我们将要工作的环境。顾名思义，virtualenv 是一个创建虚拟环境的工具。它可以将不同项目所需的依赖项保存在不同的位置，同时保持全局 site-packages 的清洁。换句话说，当你在虚拟环境中安装 Flask 时，它只会安装在本地`virtualenv`项目目录中，而不是全局 site-packages。这使得将代码移植到其他地方变得非常容易。

很有可能在之前使用 Python 时，你已经接触过`virtualenv`，所以我们会快速地浏览一下这个过程。如果你还没有接触过，可以随意选择在线的优秀教程之一，比如[`docs.python-guide.org/en/latest/dev/virtualenvs/`](http://docs.python-guide.org/en/latest/dev/virtualenvs/)。

要使用，我们首先需要安装`virtualenv`。

```py
# Python 3
$ sudo apt-get install python3-venv
$ python3 -m venv venv

# Python 2
$ sudo apt-get install python-virtualenv
$ virtualenv venv-python2
```

下面的命令使用`venv`模块（`-m venv`）来获取一个带有完整 Python 解释器的`venv`文件夹。我们可以使用`source venv/bin/activate`和`deactivate`来进入和退出本地 Python 环境：

```py
$ source venv/bin/activate
(venv) $ python
$ which python
/home/echou/Master_Python_Networking_second_edition/Chapter09/venv/bin/python
$ python
Python 3.5.2 (default, Nov 23 2017, 16:37:01)
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>
>>> exit()
(venv) $ deactivate
```

在本章中，我们将安装相当多的 Python 包。为了让生活更轻松，我在书的 GitHub 存储库中包含了一个`requirements.txt`文件；我们可以使用它来安装所有必要的包（记得激活你的虚拟环境）。在过程结束时，你应该看到包被下载并成功安装：

```py
(venv) $ pip install -r requirements.txt
Collecting Flask==0.10.1 (from -r requirements.txt (line 1))
  Downloading https://files.pythonhosted.org/packages/db/9c/149ba60c47d107f85fe52564133348458f093dd5e6b57a5b60ab9ac517bb/Flask-0.10.1.tar.gz (544kB)
    100% |████████████████████████████████| 552kB 2.0MB/s
Collecting Flask-HTTPAuth==2.2.1 (from -r requirements.txt (line 2))
  Downloading https://files.pythonhosted.org/packages/13/f3/efc053c66a7231a5a38078a813aee06cd63ca90ab1b3e269b63edd5ff1b2/Flask-HTTPAuth-2.2.1.tar.gz
... <skip>
  Running setup.py install for Pygments ... done
  Running setup.py install for python-dateutil ... done
Successfully installed Flask-0.10.1 Flask-HTTPAuth-2.2.1 Flask-SQLAlchemy-1.0 Jinja2-2.7.3 MarkupSafe-0.23 Pygments-1.6 SQLAlchemy-0.9.6 Werkzeug-0.9.6 httpie-0.8.0 itsdangerous-0.24 python-dateutil-2.2 requests-2.3.0 six-1.11.0 
```

对于我们的网络拓扑，我们将使用一个简单的四节点网络，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/1647347c-bb46-4301-82d5-4cd6b61096bc.png) 实验拓扑

让我们在下一节中看一下 Flask。

请注意，从现在开始，我将假设你总是在虚拟环境中执行，并且已经安装了`requirements.txt`文件中的必要包。

# Flask 简介

像大多数流行的开源项目一样，Flask 有非常好的文档，可以在[`flask.pocoo.org/docs/0.10/`](http://flask.pocoo.org/docs/0.10/)找到。如果任何示例不清楚，你可以肯定会在项目文档中找到答案。

我还强烈推荐 Miguel Grinberg（[`blog.miguelgrinberg.com/`](https://blog.miguelgrinberg.com/)）关于 Flask 的工作。他的博客、书籍和视频培训让我对 Flask 有了很多了解。事实上，Miguel 的课程*使用 Flask 构建 Web API*启发了我写这一章。你可以在 GitHub 上查看他发布的代码：[`github.com/miguelgrinberg/oreilly-flask-apis-video`](https://github.com/miguelgrinberg/oreilly-flask-apis-video)。

我们的第一个 Flask 应用程序包含在一个单独的文件`chapter9_1.py`中：

```py
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_networkers():
    return 'Hello Networkers!'

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
```

这几乎总是 Flask 最初的设计模式。我们使用 Flask 类的实例作为应用程序模块包的第一个参数。在这种情况下，我们使用了一个单一模块；在自己操作时，输入您选择的名称，以指示它是作为应用程序启动还是作为模块导入。然后，我们使用路由装饰器告诉 Flask 哪个 URL 应该由`hello_networkers()`函数处理；在这种情况下，我们指定了根路径。我们以通常的名称结束文件（[`docs.python.org/3.5/library/__main__.html`](https://docs.python.org/3.5/library/__main__.html)）。我们只添加了主机和调试选项，允许更详细的输出，并允许我们监听主机的所有接口（默认情况下，它只监听回环）。我们可以使用开发服务器运行此应用程序：

```py
(venv) $ python chapter9_1.py
 * Running on http://0.0.0.0:5000/
 * Restarting with reloader
```

既然我们有一个运行的服务器，让我们用一个 HTTP 客户端测试服务器的响应。

# HTTPie 客户端

我们已经安装了 HTTPie ([`httpie.org/`](https://httpie.org/)) 作为从阅读`requirements.txt`文件安装的一部分。尽管本书是黑白文本打印的，所以这里看不到，但在您的安装中，您可以看到 HTTPie 对 HTTP 事务有更好的语法高亮。它还具有更直观的 RESTful HTTP 服务器命令行交互。我们可以用它来测试我们的第一个 Flask 应用程序（后续将有更多关于 HTTPie 的例子）：

```py
$ http GET http://172.16.1.173:5000/
HTTP/1.0 200 OK
Content-Length: 17
Content-Type: text/html; charset=utf-8
Date: Wed, 22 Mar 2017 17:37:12 GMT
Server: Werkzeug/0.9.6 Python/3.5.2

Hello Networkers!
```

或者，您也可以使用 curl 的`-i`开关来查看 HTTP 头：`curl -i http://172.16.1.173:5000/`。

我们将在本章中使用`HTTPie`作为我们的客户端；值得花一两分钟来看一下它的用法。我们将使用免费的网站 HTTP Bin ([`httpbin.org/`](https://httpbin.org/)) 来展示`HTTPie`的用法。`HTTPie`的用法遵循这种简单的模式：

```py
$ http [flags] [METHOD] URL [ITEM]
```

按照前面的模式，`GET`请求非常简单，就像我们在 Flask 开发服务器中看到的那样：

```py
$ http GET https://httpbin.org/user-agent
...
{
 "user-agent": "HTTPie/0.8.0"
}
```

JSON 是`HTTPie`的默认隐式内容类型。如果您的 HTTP 主体只包含字符串，则不需要进行其他操作。如果您需要应用非字符串 JSON 字段，请使用`:=`或其他文档化的特殊字符：

```py
$ http POST https://httpbin.org/post name=eric twitter=at_ericchou married:=true 
HTTP/1.1 200 OK
...
Content-Type: application/json
...
{
 "headers": {
...
 "User-Agent": "HTTPie/0.8.0"
 },
 "json": {
 "married": true,
 "name": "eric",
 "twitter": "at_ericchou"
 },
 ...
 "url": "https://httpbin.org/post"
}
```

正如您所看到的，`HTTPie`是传统 curl 语法的一个重大改进，使得测试 REST API 变得轻而易举。

更多的用法示例可在[`httpie.org/doc#usage`](https://httpie.org/doc#usage)找到。

回到我们的 Flask 程序，API 构建的一个重要部分是基于 URL 路由的流程。让我们更深入地看一下`app.route()`装饰器。

# URL 路由

我们添加了两个额外的函数，并将它们与`chapter9_2.py`中的适当的`app.route()`路由配对：

```py
$ cat chapter9_2.py
from flask import Flask
app = Flask(__name__)

@app.route('/')
def index():
    return 'You are at index()'

@app.route('/routers/')
def routers():
    return 'You are at routers()'

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
```

结果是不同的端点传递给不同的函数。我们可以通过两个`http`请求来验证这一点：

```py
# Server
$ python chapter9_2.py

# Client
$ http GET http://172.16.1.173:5000/
...

You are at index()

$ http GET http://172.16.1.173:5000/routers/
...

You are at routers()
```

当然，如果我们一直保持静态，路由将会非常有限。有办法将变量从 URL 传递给 Flask；我们将在接下来的部分看一个例子。

# URL 变量

如前所述，我们也可以将变量传递给 URL，就像在`chapter9_3.py`中讨论的例子中看到的那样：

```py
...
@app.route('/routers/<hostname>')
def router(hostname):
    return 'You are at %s' % hostname

@app.route('/routers/<hostname>/interface/<int:interface_number>')
def interface(hostname, interface_number):
    return 'You are at %s interface %d' % (hostname, interface_number)
...
```

请注意，在`/routers/<hostname>` URL 中，我们将`<hostname>`变量作为字符串传递；`<int:interface_number>`将指定该变量应该是一个整数：

```py
$ http GET http://172.16.1.173:5000/routers/host1
...
You are at host1

$ http GET http://172.16.1.173:5000/routers/host1/interface/1
...
You are at host1 interface 1

# Throws exception
$ http GET http://172.16.1.173:5000/routers/host1/interface/one
HTTP/1.0 404 NOT FOUND
...
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

转换器包括整数、浮点数和路径（它接受斜杠）。

除了匹配静态路由之外，我们还可以动态生成 URL。当我们事先不知道端点变量，或者端点基于其他条件，比如从数据库查询的值时，这是非常有用的。让我们看一个例子。

# URL 生成

在`chapter9_4.py`中，我们想要在代码中动态创建一个形式为`'/<hostname>/list_interfaces'`的 URL：

```py
from flask import Flask, url_for
...
@app.route('/<hostname>/list_interfaces')
def device(hostname):
    if hostname in routers:
        return 'Listing interfaces for %s' % hostname
    else:
        return 'Invalid hostname'

routers = ['r1', 'r2', 'r3']
for router in routers:
    with app.test_request_context():
        print(url_for('device', hostname=router))
...
```

执行后，您将得到一个漂亮而合乎逻辑的 URL，如下所示：

```py
(venv) $ python chapter9_4.py
/r1/list_interfaces
/r2/list_interfaces
/r3/list_interfaces
 * Running on http://0.0.0.0:5000/
 * Restarting with reloader 
```

目前，您可以将`app.text_request_context()`视为一个虚拟的`request`对象，这对于演示目的是必要的。如果您对本地上下文感兴趣，请随时查看[`werkzeug.pocoo.org/docs/0.14/local/`](http://werkzeug.pocoo.org/docs/0.14/local/)。

# jsonify 返回

Flask 中的另一个时间节省器是`jsonify()`返回，它包装了`json.dumps()`并将 JSON 输出转换为具有`application/json`作为 HTTP 标头中内容类型的`response`对象。我们可以稍微调整最后的脚本，就像我们将在`chapter9_5.py`中做的那样：

```py
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/routers/<hostname>/interface/<int:interface_number>')
def interface(hostname, interface_number):
    return jsonify(name=hostname, interface=interface_number)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
```

我们将看到返回的结果作为`JSON`对象，并带有适当的标头：

```py
$ http GET http://172.16.1.173:5000/routers/r1/interface/1
HTTP/1.0 200 OK
Content-Length: 36
Content-Type: application/json
...

{
 "interface": 1,
 "name": "r1"
}
```

在 Flask 中查看了 URL 路由和`jsonify()`返回后，我们现在准备为我们的网络构建 API。

# 网络资源 API

通常，您的网络由一旦投入生产就不经常更改的网络设备组成。例如，您将拥有核心设备、分发设备、脊柱、叶子、顶部交换机等。每个设备都有特定的特性和功能，您希望将这些信息存储在一个持久的位置，以便以后可以轻松检索。通常是通过将数据存储在数据库中来实现的。但是，您通常不希望将其他用户直接访问数据库；他们也不想学习所有复杂的 SQL 查询语言。对于这种情况，我们可以利用 Flask 和 Flask-SQLAlchemy 扩展。

您可以在[`flask-sqlalchemy.pocoo.org/2.1/`](http://flask-sqlalchemy.pocoo.org/2.1/)了解更多关于 Flask-SQLAlchemy 的信息。

# Flask-SQLAlchemy

当然，SQLAlchemy 和 Flask 扩展都是数据库抽象层和对象关系映射器。这是一种使用`Python`对象作为数据库的高级方式。为了简化事情，我们将使用 SQLite 作为数据库，它是一个充当独立 SQL 数据库的平面文件。我们将查看`chapter9_db_1.py`的内容，作为使用 Flask-SQLAlchemy 创建网络数据库并将表条目插入数据库的示例。

首先，我们将创建一个 Flask 应用程序，并加载 SQLAlchemy 的配置，比如数据库路径和名称，然后通过将应用程序传递给它来创建`SQLAlchemy`对象：

```py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Create Flask application, load configuration, and create
# the SQLAlchemy object
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network.db'
db = SQLAlchemy(app)
```

然后，我们可以创建一个`database`对象及其关联的主键和各种列：

```py
class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(120), index=True)
    vendor = db.Column(db.String(40))

    def __init__(self, hostname, vendor):
        self.hostname = hostname
        self.vendor = vendor

    def __repr__(self):
        return '<Device %r>' % self.hostname
```

我们可以调用`database`对象，创建条目，并将它们插入数据库表中。请记住，我们添加到会话中的任何内容都需要提交到数据库中才能永久保存：

```py
if __name__ == '__main__':
    db.create_all()
    r1 = Device('lax-dc1-core1', 'Juniper')
    r2 = Device('sfo-dc1-core1', 'Cisco')
    db.session.add(r1)
    db.session.add(r2)
    db.session.commit()
```

我们将运行 Python 脚本并检查数据库文件是否存在：

```py
$ python chapter9_db_1.py
$ ls network.db
network.db
```

我们可以使用交互式提示来检查数据库表条目：

```py
>>> from flask import Flask
>>> from flask_sqlalchemy import SQLAlchemy
>>>
>>> app = Flask(__name__)
>>> app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network.db'
>>> db = SQLAlchemy(app)
>>> from chapter9_db_1 import Device
>>> Device.query.all()
[<Device 'lax-dc1-core1'>, <Device 'sfo-dc1-core1'>]
>>> Device.query.filter_by(hostname='sfo-dc1-core1')
<flask_sqlalchemy.BaseQuery object at 0x7f1b4ae07eb8>
>>> Device.query.filter_by(hostname='sfo-dc1-core1').first()
<Device 'sfo-dc1-core1'>
```

我们也可以以相同的方式创建新条目：

```py
>>> r3 = Device('lax-dc1-core2', 'Juniper')
>>> db.session.add(r3)
>>> db.session.commit()
>>> Device.query.all()
[<Device 'lax-dc1-core1'>, <Device 'sfo-dc1-core1'>, <Device 'lax-dc1-core2'>]
```

# 网络内容 API

在我们深入代码之前，让我们花一点时间考虑我们要创建的 API。规划 API 通常更多是一种艺术而不是科学；这确实取决于您的情况和偏好。我建议的下一步绝不是正确的方式，但是现在，为了开始，跟着我走。

回想一下，在我们的图表中，我们有四个 Cisco IOSv 设备。假设其中两个，`iosv-1`和`iosv-2`，是网络角色的脊柱。另外两个设备，`iosv-3`和`iosv-4`，在我们的网络服务中作为叶子。这显然是任意选择，可以稍后修改，但重点是我们想要提供关于我们的网络设备的数据，并通过 API 公开它们。

为了简化事情，我们将创建两个 API：设备组 API 和单个设备 API：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/0cf9e61a-6b19-4746-b968-9ef5830d08ab.png)网络内容 API

第一个 API 将是我们的`http://172.16.1.173/devices/`端点，支持两种方法：`GET`和`POST`。`GET`请求将返回当前设备列表，而带有适当 JSON 主体的`POST`请求将创建设备。当然，您可以选择为创建和查询设置不同的端点，但在这个设计中，我们选择通过 HTTP 方法来区分这两种情况。

第二个 API 将特定于我们的设备，形式为`http://172.16.1.173/devices/<device id>`。带有`GET`请求的 API 将显示我们输入到数据库中的设备的详细信息。`PUT`请求将修改更新条目。请注意，我们使用`PUT`而不是`POST`。这是 HTTP API 使用的典型方式；当我们需要修改现有条目时，我们将使用`PUT`而不是`POST`。

到目前为止，您应该对您的 API 的外观有一个很好的想法。为了更好地可视化最终结果，我将快速跳转并展示最终结果，然后再看代码。

对`/devices/`API 的`POST`请求将允许您创建一个条目。在这种情况下，我想创建我们的网络设备，其属性包括主机名、回环 IP、管理 IP、角色、供应商和运行的操作系统：

```py
$ http POST http://172.16.1.173:5000/devices/ 'hostname'='iosv-1' 'loopback'='192.168.0.1' 'mgmt_ip'='172.16.1.225' 'role'='spine' 'vendor'='Cisco' 'os'='15.6'
HTTP/1.0 201 CREATED
Content-Length: 2
Content-Type: application/json
Date: Fri, 24 Mar 2017 01:45:15 GMT
Location: http://172.16.1.173:5000/devices/1
Server: Werkzeug/0.9.6 Python/3.5.2

{}
```

我可以重复前面的步骤来添加另外三个设备：

```py
$ http POST http://172.16.1.173:5000/devices/ 'hostname'='iosv-2' 'loopback'='192.168.0.2' 'mgmt_ip'='172.16.1.226' 'role'='spine' 'vendor'='Cisco' 'os'='15.6'
...
$ http POST http://172.16.1.173:5000/devices/ 'hostname'='iosv-3', 'loopback'='192.168.0.3' 'mgmt_ip'='172.16.1.227' 'role'='leaf' 'vendor'='Cisco' 'os'='15.6'
...
$ http POST http://172.16.1.173:5000/devices/ 'hostname'='iosv-4', 'loopback'='192.168.0.4' 'mgmt_ip'='172.16.1.228' 'role'='leaf' 'vendor'='Cisco' 'os'='15.6'
```

如果我们可以使用相同的 API 和`GET`请求，我们将能够看到我们创建的网络设备列表：

```py
$ http GET http://172.16.1.173:5000/devices/
HTTP/1.0 200 OK
Content-Length: 188
Content-Type: application/json
Date: Fri, 24 Mar 2017 01:53:15 GMT
Server: Werkzeug/0.9.6 Python/3.5.2

{
 "device": [
 "http://172.16.1.173:5000/devices/1",
 "http://172.16.1.173:5000/devices/2",
 "http://172.16.1.173:5000/devices/3",
 "http://172.16.1.173:5000/devices/4"
 ]
}
```

类似地，使用`GET`请求对`/devices/<id>`将返回与设备相关的特定信息：

```py
$ http GET http://172.16.1.173:5000/devices/1
HTTP/1.0 200 OK
Content-Length: 188
Content-Type: application/json
...
{
 "hostname": "iosv-1",
 "loopback": "192.168.0.1",
 "mgmt_ip": "172.16.1.225",
 "os": "15.6",
 "role": "spine",
 "self_url": "http://172.16.1.173:5000/devices/1",
 "vendor": "Cisco"
}
```

假设我们将`r1`操作系统从`15.6`降级到`14.6`。我们可以使用`PUT`请求来更新设备记录：

```py
$ http PUT http://172.16.1.173:5000/devices/1 'hostname'='iosv-1' 'loopback'='192.168.0.1' 'mgmt_ip'='172.16.1.225' 'role'='spine' 'vendor'='Cisco' 'os'='14.6'
HTTP/1.0 200 OK

# Verification
$ http GET http://172.16.1.173:5000/devices/1
...
{
 "hostname": "r1",
 "loopback": "192.168.0.1",
 "mgmt_ip": "172.16.1.225",
 "os": "14.6",
 "role": "spine",
 "self_url": "http://172.16.1.173:5000/devices/1",
 "vendor": "Cisco"
}
```

现在，让我们看一下`chapter9_6.py`中的代码，这些代码帮助创建了前面的 API。在我看来，很酷的是，所有这些 API 都是在单个文件中完成的，包括数据库交互。以后，当我们需要扩展现有的 API 时，我们总是可以将组件分离出来，比如为数据库类单独创建一个文件。

# 设备 API

`chapter9_6.py`文件以必要的导入开始。请注意，以下请求导入是来自客户端的`request`对象，而不是我们在之前章节中使用的 requests 包：

```py
from flask import Flask, url_for, jsonify, request
from flask_sqlalchemy import SQLAlchemy
# The following is deprecated but still used in some examples
# from flask.ext.sqlalchemy import SQLAlchemy
```

我们声明了一个`database`对象，其`id`为主键，`hostname`、`loopback`、`mgmt_ip`、`role`、`vendor`和`os`为字符串字段：

```py
class Device(db.Model):
    __tablename__ = 'devices'
  id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(64), unique=True)
    loopback = db.Column(db.String(120), unique=True)
    mgmt_ip = db.Column(db.String(120), unique=True)
    role = db.Column(db.String(64))
    vendor = db.Column(db.String(64))
    os = db.Column(db.String(64))
```

`get_url()`函数从`url_for()`函数返回一个 URL。请注意，调用的`get_device()`函数尚未在`'/devices/<int:id>'`路由下定义：

```py
def get_url(self):
    return url_for('get_device', id=self.id, _external=True)
```

`export_data()`和`import_data()`函数是彼此的镜像。一个用于从数据库获取信息到用户（`export_data()`），当我们使用`GET`方法时。另一个用于将用户的信息放入数据库（`import_data()`），当我们使用`POST`或`PUT`方法时：

```py
def export_data(self):
    return {
        'self_url': self.get_url(),
  'hostname': self.hostname,
  'loopback': self.loopback,
  'mgmt_ip': self.mgmt_ip,
  'role': self.role,
  'vendor': self.vendor,
  'os': self.os
    }

def import_data(self, data):
    try:
        self.hostname = data['hostname']
        self.loopback = data['loopback']
        self.mgmt_ip = data['mgmt_ip']
        self.role = data['role']
        self.vendor = data['vendor']
        self.os = data['os']
    except KeyError as e:
        raise ValidationError('Invalid device: missing ' + e.args[0])
    return self
```

有了`database`对象以及创建的导入和导出函数，设备操作的 URL 分发就变得简单了。`GET`请求将通过查询设备表中的所有条目返回设备列表，并返回每个条目的 URL。`POST`方法将使用全局`request`对象作为输入，使用`import_data()`函数，然后将设备添加到数据库并提交信息：

```py
@app.route('/devices/', methods=['GET'])
def get_devices():
    return jsonify({'device': [device.get_url() 
                              for device in Device.query.all()]})

@app.route('/devices/', methods=['POST'])
def new_device():
    device = Device()
    device.import_data(request.json)
    db.session.add(device)
    db.session.commit()
    return jsonify({}), 201, {'Location': device.get_url()}
```

如果您查看`POST`方法，返回的主体是一个空的 JSON 主体，状态码为`201`（已创建），以及额外的标头：

```py
HTTP/1.0 201 CREATED
Content-Length: 2
Content-Type: application/json
Date: ...
Location: http://172.16.1.173:5000/devices/4
Server: Werkzeug/0.9.6 Python/3.5.2
```

让我们来看一下查询和返回有关单个设备的信息的 API。

# 设备 ID API

单个设备的路由指定 ID 应该是一个整数，这可以作为我们对错误请求的第一道防线。这两个端点遵循与我们的`/devices/`端点相同的设计模式，我们在这里使用相同的`import`和`export`函数：

```py
@app.route('/devices/<int:id>', methods=['GET'])
def get_device(id):
    return jsonify(Device.query.get_or_404(id).export_data())

@app.route('/devices/<int:id>', methods=['PUT'])
def edit_device(id):
    device = Device.query.get_or_404(id)
    device.import_data(request.json)
    db.session.add(device)
    db.session.commit()
    return jsonify({})
```

注意`query_or_404()`方法；如果数据库查询对传入的 ID 返回负值，它提供了一个方便的方法来返回`404（未找到）`。这是一个相当优雅的方式来快速检查数据库查询。

最后，代码的最后部分创建数据库表并启动 Flask 开发服务器：

```py
if __name__ == '__main__':
    db.create_all()
    app.run(host='0.0.0.0', debug=True)
```

这是本书中较长的 Python 脚本之一，这就是为什么我们花了更多的时间详细解释它。该脚本提供了一种说明我们如何利用后端数据库来跟踪网络设备，并将它们仅作为 API 暴露给外部世界的方法，使用 Flask。

在下一节中，我们将看看如何使用 API 对单个设备或一组设备执行异步任务。

# 网络动态操作

我们的 API 现在可以提供关于网络的静态信息；我们可以将数据库中存储的任何内容返回给请求者。如果我们可以直接与我们的网络交互，比如查询设备信息或向设备推送配置更改，那将是很棒的。

我们将通过利用我们已经在第二章中看到的脚本，*低级网络设备交互*，来开始这个过程，通过 Pexpect 与设备进行交互。我们将稍微修改脚本，将其转换为一个我们可以在`chapter9_pexpect_1.py`中重复使用的函数：

```py
# We need to install pexpect for our virtual env
$ pip install pexpect

$ cat chapter9_pexpect_1.py
import pexpect

def show_version(device, prompt, ip, username, password):
 device_prompt = prompt
 child = pexpect.spawn('telnet ' + ip)
 child.expect('Username:')
 child.sendline(username)
 child.expect('Password:')
 child.sendline(password)
 child.expect(device_prompt)
 child.sendline('show version | i V')
 child.expect(device_prompt)
 result = child.before
 child.sendline('exit')
 return device, result
```

我们可以通过交互式提示来测试新的函数：

```py
$ pip3 install pexpect
$ python
>>> from chapter9_pexpect_1 import show_version
>>> print(show_version('iosv-1', 'iosv-1#', '172.16.1.225', 'cisco', 'cisco'))
('iosv-1', b'show version | i V\r\nCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(3)M2, RELEASE SOFTWARE (fc2)\r\n')
>>> 
```

确保您的 Pexpect 脚本在继续之前能够正常工作。以下代码假定您已经输入了前一节中的必要数据库信息。

我们可以在`chapter9_7.py`中添加一个新的 API 来查询设备版本：

```py
from chapter9_pexpect_1 import show_version
...
@app.route('/devices/<int:id>/version', methods=['GET'])
def get_device_version(id):
    device = Device.query.get_or_404(id)
    hostname = device.hostname
    ip = device.mgmt_ip
    prompt = hostname+"#"
  result = show_version(hostname, prompt, ip, 'cisco', 'cisco')
    return jsonify({"version": str(result)})
```

结果将返回给请求者：

```py
$ http GET http://172.16.1.173:5000/devices/4/version
HTTP/1.0 200 OK
Content-Length: 210
Content-Type: application/json
Date: Fri, 24 Mar 2017 17:05:13 GMT
Server: Werkzeug/0.9.6 Python/3.5.2

{
 "version": "('iosv-4', b'show version | i V\r\nCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)\r\nProcessor board ID 9U96V39A4Z12PCG4O6Y0Q\r\n')"
}
```

我们还可以添加另一个端点，允许我们根据它们的共同字段对多个设备执行批量操作。在下面的示例中，端点将在 URL 中获取`device_role`属性，并将其与相应的设备匹配：

```py
@app.route('/devices/<device_role>/version', methods=['GET'])
def get_role_version(device_role):
    device_id_list = [device.id for device in Device.query.all() if device.role == device_role]
    result = {}
    for id in device_id_list:
        device = Device.query.get_or_404(id)
        hostname = device.hostname
        ip = device.mgmt_ip
        prompt = hostname + "#"
  device_result = show_version(hostname, prompt, ip, 'cisco', 'cisco')
        result[hostname] = str(device_result)
    return jsonify(result)
```

当然，像在前面的代码中那样循环遍历所有的设备`Device.query.all()`是不高效的。在生产中，我们将使用一个专门针对设备角色的 SQL 查询。

当我们使用 REST API 时，可以同时查询所有的骨干和叶子设备：

```py
$ http GET http://172.16.1.173:5000/devices/spine/version
HTTP/1.0 200 OK
...
{
 "iosv-1": "('iosv-1', b'show version | i V\r\nCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)\r\n')",
 "iosv-2": "('iosv-2', b'show version | i V\r\nCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)\r\nProcessor board ID 9T7CB2J2V6F0DLWK7V48E\r\n')"
}

$ http GET http://172.16.1.173:5000/devices/leaf/version
HTTP/1.0 200 OK
...
{
 "iosv-3": "('iosv-3', b'show version | i V\r\nCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)\r\nProcessor board ID 9MGG8EA1E0V2PE2D8KDD7\r\n')",
 "iosv-4": "('iosv-4', b'show version | i V\r\nCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)\r\nProcessor board ID 9U96V39A4Z12PCG4O6Y0Q\r\n')"
}
```

正如所示，新的 API 端点实时查询设备，并将结果返回给请求者。当您可以保证在事务的超时值（默认为 30 秒）内获得操作的响应，或者如果您可以接受 HTTP 会话在操作完成之前超时，这种方法相对有效。解决超时问题的一种方法是异步执行任务。我们将在下一节中看看如何做到这一点。

# 异步操作

在我看来，异步操作是 Flask 的一个高级主题。幸运的是，Miguel Grinberg（[`blog.miguelgrinberg.com/`](https://blog.miguelgrinberg.com/)）是我非常喜欢的 Flask 工作的作者，他在博客和 GitHub 上提供了许多帖子和示例。对于异步操作，`chapter9_8.py`中的示例代码引用了 Miguel 在 GitHub 上的`Raspberry Pi`文件上的代码（[`github.com/miguelgrinberg/oreilly-flask-apis-video/blob/master/camera/camera.py`](https://github.com/miguelgrinberg/oreilly-flask-apis-video/blob/master/camera/camera.py)）来使用 background 装饰器。我们将开始导入一些额外的模块：

```py
from flask import Flask, url_for, jsonify, request,
    make_response, copy_current_request_context
...
import uuid
import functools
from threading import Thread
```

background 装饰器接受一个函数，并使用线程和 UUID 作为任务 ID 在后台运行它。它返回状态码`202` accepted 和新资源的位置，供请求者检查。我们将创建一个新的 URL 用于状态检查：

```py
@app.route('/status/<id>', methods=['GET'])
def get_task_status(id):   global background_tasks
    rv = background_tasks.get(id)
    if rv is None:
        return not_found(None)
   if isinstance(rv, Thread):
        return jsonify({}), 202, {'Location': url_for('get_task_status', id=id)}
   if app.config['AUTO_DELETE_BG_TASKS']:
        del background_tasks[id]
    return rv
```

一旦我们检索到资源，它就会被删除。这是通过在应用程序顶部将`app.config['AUTO_DELETE_BG_TASKS']`设置为`true`来完成的。我们将在我们的版本端点中添加这个装饰器，而不改变代码的其他部分，因为所有的复杂性都隐藏在装饰器中（这多酷啊！）：

```py
@app.route('/devices/<int:id>/version', methods=['GET'])
@**background** def get_device_version(id):
    device = Device.query.get_or_404(id)
...

@app.route('/devices/<device_role>/version', methods=['GET'])
@**background** def get_role_version(device_role):
    device_id_list = [device.id for device in Device.query.all() if device.role == device_role]
...
```

最终结果是一个两部分的过程。我们将为端点执行`GET`请求，并接收位置头：

```py
$ http GET http://172.16.1.173:5000/devices/spine/version
HTTP/1.0 202 ACCEPTED
Content-Length: 2
Content-Type: application/json
Date: <skip>
Location: http://172.16.1.173:5000/status/d02c3f58f4014e96a5dca075e1bb65d4
Server: Werkzeug/0.9.6 Python/3.5.2

{}
```

然后我们可以发出第二个请求以检索结果的位置：

```py
$ http GET http://172.16.1.173:5000/status/d02c3f58f4014e96a5dca075e1bb65d4
HTTP/1.0 200 OK
Content-Length: 370
Content-Type: application/json
Date: <skip>
Server: Werkzeug/0.9.6 Python/3.5.2

{
 "iosv-1": "('iosv-1', b'show version | i V\r\nCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)\r\n')",
 "iosv-2": "('iosv-2', b'show version | i V\r\nCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)\r\nProcessor board ID 9T7CB2J2V6F0DLWK7V48E\r\n')"
}
```

为了验证当资源尚未准备好时是否返回状态码`202`，我们将使用以下脚本`chapter9_request_1.py`立即向新资源发出请求：

```py
import requests, time

server = 'http://172.16.1.173:5000' endpoint = '/devices/1/version'   # First request to get the new resource r = requests.get(server+endpoint)
resource = r.headers['location']
print("Status: {} Resource: {}".format(r.status_code, resource))

# Second request to get the resource status r = requests.get(resource)
print("Immediate Status Query to Resource: " + str(r.status_code))

print("Sleep for 2 seconds")
time.sleep(2)
# Third request to get the resource status r = requests.get(resource)
print("Status after 2 seconds: " + str(r.status_code))
```

如您在结果中所见，当资源仍在后台运行时，状态码以`202`返回：

```py
$ python chapter9_request_1.py
Status: 202 Resource: http://172.16.1.173:5000/status/1de21f5235c94236a38abd5606680b92
Immediate Status Query to Resource: 202
Sleep for 2 seconds
Status after 2 seconds: 200
```

我们的 API 正在很好地进行中！因为我们的网络资源对我们很有价值，所以我们应该只允许授权人员访问 API。我们将在下一节为我们的 API 添加基本的安全措施。

# 安全

对于用户身份验证安全，我们将使用 Flask 的`httpauth`扩展，由 Miguel Grinberg 编写，以及 Werkzeug 中的密码函数。`httpauth`扩展应该已经作为`requirements.txt`安装的一部分。展示安全功能的新文件名为`chapter9_9.py`；我们将从几个模块导入开始：

```py
...
from werkzeug.security import generate_password_hash, check_password_hash
from flask.ext.httpauth import HTTPBasicAuth
...
```

我们将创建一个`HTTPBasicAuth`对象以及`用户数据库`对象。请注意，在用户创建过程中，我们将传递密码值；但是，我们只存储`password_hash`而不是密码本身。这确保我们不会为用户存储明文密码：

```py
auth = HTTPBasicAuth()

class User(db.Model):
    __tablename__ = 'users'
  id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
```

`auth`对象有一个`verify_password`装饰器，我们可以使用它，以及 Flask 的`g`全局上下文对象，该对象在请求开始时创建，用于密码验证。因为`g`是全局的，如果我们将用户保存到`g`变量中，它将在整个事务中存在：

```py
@auth.verify_password def verify_password(username, password):
    g.user = User.query.filter_by(username=username).first()
    if g.user is None:
        return False
 return g.user.verify_password(password)
```

有一个方便的`before_request`处理程序，可以在调用任何 API 端点之前使用。我们将结合`auth.login_required`装饰器和`before_request`处理程序，将其应用于所有 API 路由：

```py
@app.before_request @auth.login_required def before_request():
    pass 
```

最后，我们将使用`未经授权`错误处理程序返回`401`未经授权错误的`response`对象：

```py
@auth.error_handler def unauthorized():
    response = jsonify({'status': 401, 'error': 'unauthorized', 
 'message': 'please authenticate'})

    response.status_code = 401
  return response
```

在我们测试用户身份验证之前，我们需要在我们的数据库中创建用户：

```py
>>> from chapter9_9 import db, User
>>> db.create_all()
>>> u = User(username='eric')
>>> u.set_password('secret')
>>> db.session.add(u)
>>> db.session.commit()
>>> exit()
```

一旦启动 Flask 开发服务器，请尝试发出请求，就像我们之前做的那样。您应该看到，这次服务器将以`401`未经授权的错误拒绝请求：

```py
$ http GET http://172.16.1.173:5000/devices/
HTTP/1.0 401 UNAUTHORIZED
Content-Length: 81
Content-Type: application/json
Date: <skip>
Server: Werkzeug/0.9.6 Python/3.5.2
WWW-Authenticate: Basic realm="Authentication Required"

{
 "error": "unauthorized",
 "message": "please authenticate",
 "status": 401
}
```

现在我们需要为我们的请求提供身份验证头：

```py
$ http --auth eric:secret GET http://172.16.1.173:5000/devices/
HTTP/1.0 200 OK
Content-Length: 188
Content-Type: application/json
Date: <skip>
Server: Werkzeug/0.9.6 Python/3.5.2

{
 "device": [
 "http://172.16.1.173:5000/devices/1",
 "http://172.16.1.173:5000/devices/2",
 "http://172.16.1.173:5000/devices/3",
 "http://172.16.1.173:5000/devices/4"
 ]
}
```

现在我们已经为我们的网络设置了一个不错的 RESTful API。用户现在可以与 API 交互，而不是与网络设备。他们可以查询网络的静态内容，并为单个设备或一组设备执行任务。我们还添加了基本的安全措施，以确保只有我们创建的用户能够从我们的 API 中检索信息。很酷的是，这一切都在不到 250 行代码的单个文件中完成了（如果减去注释，不到 200 行）！

我们现在已经将底层供应商 API 从我们的网络中抽象出来，并用我们自己的 RESTful API 替换了它们。我们可以在后端自由使用所需的内容，比如 Pexpect，同时为我们的请求者提供统一的前端。

让我们看看 Flask 的其他资源，这样我们就可以继续构建我们的 API 框架。

# 其他资源

毫无疑问，Flask 是一个功能丰富的框架，功能和社区都在不断增长。在本章中，我们涵盖了许多主题，但我们仍然只是触及了框架的表面。除了 API，你还可以将 Flask 用于 Web 应用程序以及你的网站。我认为我们的网络 API 框架仍然有一些改进的空间：

+   将数据库和每个端点分开放在自己的文件中，以使代码更清晰，更易于故障排除。

+   从 SQLite 迁移到其他适用于生产的数据库。

+   使用基于令牌的身份验证，而不是为每个交易传递用户名和密码。实质上，我们将在初始身份验证时收到一个具有有限过期时间的令牌，并在之后的交易中使用该令牌，直到过期。

+   将 Flask API 应用程序部署在生产 Web 服务器后面，例如 Nginx，以及 Python WSGI 服务器用于生产环境。

+   使用自动化过程控制系统，如 Supervisor ([`supervisord.org/`](http://supervisord.org/))，来控制 Nginx 和 Python 脚本。

显然，推荐的改进选择会因公司而异。例如，数据库和 Web 服务器的选择可能会对公司的技术偏好以及其他团队的意见产生影响。如果 API 仅在内部使用，并且已经采取了其他形式的安全措施，那么使用基于令牌的身份验证可能并不必要。因此，出于这些原因，我想为您提供额外的链接作为额外资源，以便您选择继续使用前述任何项目。

以下是一些我认为在考虑设计模式、数据库选项和一般 Flask 功能时有用的链接：

+   Flask 设计模式的最佳实践: [`flask.pocoo.org/docs/0.10/patterns/`](http://flask.pocoo.org/docs/0.10/patterns/)

+   Flask API: [`flask.pocoo.org/docs/0.12/api/`](http://flask.pocoo.org/docs/0.12/api/)

+   部署选项: [`flask.pocoo.org/docs/0.12/deploying/`](http://flask.pocoo.org/docs/0.12/deploying/)

由于 Flask 的性质以及它依赖于其小核心之外的扩展，有时你可能会发现自己从一个文档跳到另一个文档。这可能令人沮丧，但好处是你只需要了解你正在使用的扩展，我觉得这在长远来看节省了时间。

# 摘要

在本章中，我们开始着手构建网络的 REST API。我们研究了不同流行的 Python Web 框架，即 Django 和 Flask，并对比了两者。选择 Flask，我们能够从小处着手，并通过使用 Flask 扩展来扩展功能。

在我们的实验室中，我们使用虚拟环境将 Flask 安装基础与全局 site-packages 分开。实验室网络由四个节点组成，其中两个被指定为脊柱路由器，另外两个被指定为叶子路由器。我们对 Flask 的基础知识进行了介绍，并使用简单的 HTTPie 客户端来测试我们的 API 设置。

在 Flask 的不同设置中，我们特别强调了 URL 分发以及 URL 变量，因为它们是请求者和我们的 API 系统之间的初始逻辑。我们研究了使用 Flask-SQLAlchemy 和 SQLite 来存储和返回静态网络元素。对于操作任务，我们还创建了 API 端点，同时调用其他程序，如 Pexpect，来完成配置任务。我们通过添加异步处理和用户身份验证来改进 API 的设置。在本章的最后，我们还查看了一些额外的资源链接，以便添加更多安全性和其他功能。

在第十章中，*AWS 云网络*，我们将转向使用**Amazon Web Services**（**AWS**）进行云网络的研究。


# 第十章：AWS 云网络

云计算是当今计算领域的主要趋势之一。公共云提供商已经改变了高科技行业，以及从零开始推出服务的含义。我们不再需要构建自己的基础设施；我们可以支付公共云提供商租用他们资源的一部分来满足我们的基础设施需求。如今，在任何技术会议或聚会上，我们很难找到一个没有了解、使用或构建基于云的服务的人。云计算已经到来，我们最好习惯与之一起工作。

云计算有几种服务模型，大致分为软件即服务（SaaS）（[`en.wikipedia.org/wiki/Software_as_a_service`](https://en.wikipedia.org/wiki/Software_as_a_service)）、平台即服务（PaaS）（[`en.wikipedia.org/wiki/Cloud_computing#Platform_as_a_service_(PaaS)`](https://en.wikipedia.org/wiki/Cloud_computing#Platform_as_a_service_(PaaS)）和基础设施即服务（IaaS）（[`en.wikipedia.org/wiki/Infrastructure_as_a_service`](https://en.wikipedia.org/wiki/Infrastructure_as_a_service)）。每种服务模型从用户的角度提供了不同的抽象级别。对我们来说，网络是基础设施即服务提供的一部分，也是本章的重点。

亚马逊云服务（AWS）是第一家提供 IaaS 公共云服务的公司，也是 2018 年市场份额方面的明显领导者。如果我们将“软件定义网络”（SDN）定义为一组软件服务共同创建网络结构 - IP 地址、访问列表、网络地址转换、路由器 - 我们可以说 AWS 是世界上最大的 SDN 实现。他们利用全球网络、数据中心和主机的大规模来提供令人惊叹的各种网络服务。

如果您有兴趣了解亚马逊的规模和网络，我强烈建议您观看 James Hamilton 在 2014 年 AWS re:Invent 的演讲：[`www.youtube.com/watch?v=JIQETrFC_SQ`](https://www.youtube.com/watch?v=JIQETrFC_SQ)。这是一个罕见的内部人员对 AWS 规模和创新的视角。

在本章中，我们将讨论 AWS 云服务提供的网络服务以及如何使用 Python 与它们一起工作：

+   AWS 设置和网络概述

+   虚拟私有云

+   直接连接和 VPN

+   网络扩展服务

+   其他 AWS 网络服务

# AWS 设置

如果您还没有 AWS 账户并希望跟随这些示例，请登录[`aws.amazon.com/`](https://aws.amazon.com/)并注册。这个过程非常简单明了；您需要一张信用卡和某种形式的验证。AWS 在免费套餐中提供了许多服务（[`aws.amazon.com/free/`](https://aws.amazon.com/free/)），在一定水平上可以免费使用一些最受欢迎的服务。

列出的一些服务在第一年是免费的，其他服务在一定限额内是免费的，没有时间限制。请查看 AWS 网站获取最新的优惠。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/c63f6039-b3d3-41b9-9654-c91aa3b51537.png)AWS 免费套餐

一旦您有了账户，您可以通过 AWS 控制台（[`console.aws.amazon.com/`](https://console.aws.amazon.com/)）登录并查看 AWS 提供的不同服务。控制台是我们可以配置所有服务并查看每月账单的地方。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/40bd402d-f546-4d6c-b4bc-157cff3d978a.png)AWS 控制台

# AWS CLI 和 Python SDK

我们也可以通过命令行界面管理 AWS 服务。AWS CLI 是一个可以通过 PIP 安装的 Python 包（[`docs.aws.amazon.com/cli/latest/userguide/installing.html`](https://docs.aws.amazon.com/cli/latest/userguide/installing.html)）。让我们在 Ubuntu 主机上安装它：

```py
$ sudo pip3 install awscli
$ aws --version
aws-cli/1.15.59 Python/3.5.2 Linux/4.15.0-30-generic botocore/1.10.58
```

安装了 AWS CLI 后，为了更轻松和更安全地访问，我们将创建一个用户并使用用户凭据配置 AWS CLI。让我们回到 AWS 控制台，选择 IAM 进行用户和访问管理：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/5fc1647e-cd89-424f-81af-e674415d622c.png) AWS IAM

我们可以在左侧面板上选择“用户”来创建用户：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/697ef15f-61f3-445d-a5ef-3f24332c0a84.png)

选择编程访问并将用户分配给默认管理员组：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/b6f17d3f-d822-41e8-a054-4089af2a9e9d.png)

最后一步将显示访问密钥 ID 和秘密访问密钥。将它们复制到文本文件中并保存在安全的地方：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/3a53eaff-674a-4c07-8d58-3e256e86bfab.png)

我们将通过终端中的`aws configure`完成 AWS CLI 身份验证凭据设置。我们将在接下来的部分中介绍 AWS 地区；现在我们将使用`us-east-1`，但随时可以返回并更改这个值：

```py
$ aws configure
AWS Access Key ID [None]: <key>
AWS Secret Access Key [None]: <secret>
Default region name [None]: us-east-1
Default output format [None]: json
```

我们还将安装 AWS Python SDK，Boto3 ([`boto3.readthedocs.io/en/latest/`](https://boto3.readthedocs.io/en/latest/))：

```py
$ sudo pip install boto3
$ sudo pip3 install boto3

# verification
$ python3
Python 3.5.2 (default, Nov 23 2017, 16:37:01)
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import boto3
>>> exit()
```

我们现在准备继续进行后续部分，从介绍 AWS 云网络服务开始。

# AWS 网络概述

当我们讨论 AWS 服务时，我们需要从地区和可用性区开始。它们对我们所有的服务都有重大影响。在撰写本书时，AWS 列出了 18 个地区、55 个可用性区和一个全球范围的本地地区。用 AWS 全球基础设施的话来说，([`aws.amazon.com/about-aws/global-infrastructure/`](https://aws.amazon.com/about-aws/global-infrastructure/))：

“AWS 云基础设施建立在地区和可用性区（AZ）周围。AWS 地区提供多个物理上分离和隔离的可用性区，这些区域通过低延迟、高吞吐量和高度冗余的网络连接在一起。”

AWS 提供的一些服务是全球性的，但大多数服务是基于地区的。对我们来说，这意味着我们应该在最接近我们预期用户的地区建立基础设施。这将减少服务对客户的延迟。如果我们的用户在美国东海岸，如果服务是基于地区的，我们应该选择`us-east-1`（北弗吉尼亚）或`us-east-2`（俄亥俄）作为我们的地区：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/8255a3ce-7fed-4297-aa14-49c62b673c65.png)AWS 地区

并非所有地区都对所有用户可用，例如，GovCloud 和中国地区默认情况下对美国用户不可用。您可以通过`aws ec2 describe-regions`列出对您可用的地区：

```py
$ aws ec2 describe-regions
{
 "Regions": 
 {
 "RegionName": "ap-south-1",
 "Endpoint": "ec2.ap-south-1.amazonaws.com"
 },
 {
 "RegionName": "eu-west-3",
 "Endpoint": "ec2.eu-west-3.amazonaws.com"
 },
...
```

所有地区都是完全独立的。大多数资源不会在地区之间复制。如果我们有多个地区，比如`US-East`和`US-West`，并且需要它们之间的冗余，我们将需要自己复制必要的资源。选择地区的方式是在控制台右上角：

![如果服务是基于地区的，例如 EC2，只有在选择正确的地区时，门户才会显示该服务。如果我们的 EC2 实例在`us-east-1`，而我们正在查看 us-west-1 门户，则不会显示任何 EC2 实例。我犯过这个错误几次，并且想知道我的所有实例都去哪了！在前面的 AWS 地区截图中，地区后面的数字代表每个地区的 AZ 数量。每个地区有多个可用性区。每个可用性区都是隔离的，但地区中的可用性区通过低延迟的光纤连接在一起：![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/9d72cf3c-5508-4524-966e-84554a9fa937.png)AWS 地区和可用性区

我们构建的许多资源都会在可用性区复制。AZ 的概念非常重要，它的约束对我们构建的网络服务非常重要。

AWS 独立地为每个账户将可用区映射到标识符。例如，我的可用区 us-eas-1a 可能与另一个账户的`us-east-1a`不同。

我们可以使用 AWS CLI 检查一个区域中的可用区：

```py
$ aws ec2 describe-availability-zones --region us-east-1
{
 "AvailabilityZones": [
 {
 "Messages": [],
 "RegionName": "us-east-1",
 "State": "available",
 "ZoneName": "us-east-1a"
 },
 {
 "Messages": [],
 "RegionName": "us-east-1",
 "State": "available",
 "ZoneName": "us-east-1b"
 },
...
```

为什么我们如此关心区域和可用区？正如我们将在接下来的几节中看到的，网络服务通常受区域和可用区的限制。例如，**虚拟私有云（VPC）**需要完全位于一个区域，每个子网需要完全位于一个可用区。另一方面，**NAT 网关**是与可用区相关的，因此如果我们需要冗余，就需要为每个可用区创建一个。我们将更详细地介绍这两项服务，但它们的用例在这里作为 AWS 网络服务提供的基础的例子。

**AWS 边缘位置**是**AWS CloudFront**内容传递网络的一部分，分布在 26 个国家的 59 个城市。这些边缘位置用于以低延迟分发内容，比整个数据中心的占地面积小。有时，人们会误将边缘位置的出现地点误认为是完整的 AWS 区域。如果占地面积仅列为边缘位置，那么 AWS 服务，如 EC2 或 S3，将不会提供。我们将在*AWS CloudFront*部分重新讨论边缘位置。

**AWS Transit Centers**是 AWS 网络中最少有文档记录的方面之一。它在 James Hamilton 的 2014 年**AWS re:Invent**主题演讲中提到（[`www.youtube.com/watch?v=JIQETrFC_SQ`](https://www.youtube.com/watch?v=JIQETrFC_SQ)），作为该区域不同可用区的聚合点。公平地说，我们不知道转换中心是否仍然存在并且在这些年后是否仍然起作用。然而，对于转换中心的位置以及它与我们将在本章后面看到的**AWS Direct Connect**服务的相关性，做出一个合理的猜测是公平的。

James Hamilton 是 AWS 的副总裁和杰出工程师之一，是 AWS 最有影响力的技术专家之一。如果有人在 AWS 网络方面具有权威性，那就是他。您可以在他的博客 Perspectives 上阅读更多关于他的愿景，网址为[`perspectives.mvdirona.com/`](https://perspectives.mvdirona.com/)。

在一个章节中不可能涵盖所有与 AWS 相关的服务。有一些与网络直接相关的相关服务我们没有空间来涵盖，但我们应该熟悉：

+   **身份和访问管理**（**IAM**）服务，[`aws.amazon.com/iam/`](https://aws.amazon.com/iam/)，是使我们能够安全地管理对 AWS 服务和资源的访问的服务。

+   **Amazon 资源名称**（**ARNs**），[`docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html`](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html)，在整个 AWS 中唯一标识 AWS 资源。当我们需要识别需要访问我们的 VPC 资源的服务时，这个资源名称是重要的，比如 DynamoDB 和 API Gateway。

+   **Amazon 弹性计算云**（**EC2**），[`aws.amazon.com/ec2/`](https://aws.amazon.com/ec2/)，是使我们能够通过 AWS 接口获取和配置计算能力，如 Linux 和 Windows 实例的服务。我们将在本章的示例中使用 EC2 实例。

为了学习的目的，我们将排除 AWS GovCloud（美国）和中国，它们都不使用 AWS 全球基础设施，并且有自己的限制。

这是对 AWS 网络概述的一个相对较长的介绍，但是非常重要。这些概念和术语将在本书的其余章节中被引用。在接下来的章节中，我们将看一下 AWS 网络中最重要的概念（在我看来）：虚拟私有云。

# 虚拟私有云

亚马逊虚拟私有云（Amazon VPC）使客户能够将 AWS 资源启动到专门为客户账户提供的虚拟网络中。这是一个真正可定制的网络，允许您定义自己的 IP 地址范围，添加和删除子网，创建路由，添加 VPN 网关，关联安全策略，将 EC2 实例连接到自己的数据中心等等。在 VPC 不可用的早期，AZ 中的所有 EC2 实例都在一个共享的单一平面网络上。客户将把他们的信息放在云中会有多舒服呢？我想不会很舒服。从 2007 年 EC2 推出到 2009 年 VPC 推出之前，VPC 功能是 AWS 最受欢迎的功能之一。

在 VPC 中离开您的 EC2 主机的数据包将被 Hypervisor 拦截。Hypervisor 将使用了解我们 VPC 结构的映射服务对其进行检查。离开您的 EC2 主机的数据包将使用 AWS 真实服务器的源和目的地地址进行封装。封装和映射服务允许 VPC 的灵活性，但也有一些 VPC 的限制（多播，嗅探）。毕竟，这是一个虚拟网络。

自 2013 年 12 月以来，所有 EC2 实例都是 VPC-only。如果我们使用启动向导创建 EC2 实例，它将自动放入具有虚拟互联网网关以进行公共访问的默认 VPC。在我看来，除了最基本的用例，所有情况都应该使用默认 VPC。对于大多数情况，我们需要定义我们的非默认自定义 VPC。

让我们在`us-east-1`使用 AWS 控制台创建以下 VPC：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/afa05231-3c87-47f3-a238-273e37860134.png)我们在美国东部的第一个 VPC

如果您还记得，VPC 是 AWS 区域绑定的，子网是基于可用性区域的。我们的第一个 VPC 将基于`us-east-1`；三个子网将分配给 1a、1b 和 1c 中的三个不同的可用性区域。

使用 AWS 控制台创建 VPC 和子网非常简单，AWS 在网上提供了许多很好的教程。我已经在 VPC 仪表板上列出了相关链接的步骤：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/c1fe117d-9253-45cb-bb5a-934f48d39aef.png)

前两个步骤是点对点的过程，大多数网络工程师甚至没有先前的经验也可以完成。默认情况下，VPC 只包含本地路由`10.0.0.0/16`。现在，我们将创建一个互联网网关并将其与 VPC 关联：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/4d402e8e-89ff-4a1d-82f2-9ac736fffdca.png)

然后，我们可以创建一个自定义路由表，其中包含指向互联网网关的默认路由。我们将把这个路由表与我们在`us-east-1a`的子网`10.0.0.0/24`关联，从而使其可以面向公众：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/04ccec30-9248-4b9d-8f58-ea68cbbcd6d8.png)路由表

让我们使用 Boto3 Python SDK 来查看我们创建了什么；我使用标签`mastering_python_networking_demo`作为 VPC 的标签，我们可以将其用作过滤器：

```py
$ cat Chapter10_1_query_vpc.py
#!/usr/bin/env python3

import json, boto3

region = 'us-east-1'
vpc_name = 'mastering_python_networking_demo'

ec2 = boto3.resource('ec2', region_name=region)
client = boto3.client('ec2')

filters = [{'Name':'tag:Name', 'Values':[vpc_name]}]

vpcs = list(ec2.vpcs.filter(Filters=filters))
for vpc in vpcs:
    response = client.describe_vpcs(
                 VpcIds=[vpc.id,]
                )
    print(json.dumps(response, sort_keys=True, indent=4))
```

此脚本将允许我们以编程方式查询我们创建的 VPC 的区域：

```py
$ python3 Chapter10_1_query_vpc.py
{
 "ResponseMetadata": {
 "HTTPHeaders": {
 "content-type": "text/xml;charset=UTF-8",
 ...
 },
 "HTTPStatusCode": 200,
 "RequestId": "48e19be5-01c1-469b-b6ff-9c45f2745483",
 "RetryAttempts": 0
 },
 "Vpcs": [
 {
 "CidrBlock": "10.0.0.0/16",
 "CidrBlockAssociationSet": [
 {
 "AssociationId": "...",
 "CidrBlock": "10.0.0.0/16",
 "CidrBlockState": {
 "State": "associated"
 }
 }
 ],
 "DhcpOptionsId": "dopt-....",
 "InstanceTenancy": "default",
 "IsDefault": false,
 "State": "available",
 "Tags": [
 {
 "Key": "Name",
 "Value": "mastering_python_networking_demo"
 }
 ],
 "VpcId": "vpc-...."
 }
 ]
}

```

Boto3 VPC API 文档可以在[`boto3.readthedocs.io/en/latest/reference/services/ec2.html#vpc`](https://boto3.readthedocs.io/en/latest/reference/services/ec2.html#vpc)找到。

您可能想知道 VPC 中的子网如何相互到达。在物理网络中，网络需要连接到路由器才能到达其本地网络之外。在 VPC 中也是如此，只是它是一个具有本地网络默认路由表的*隐式路由器*，在我们的示例中是`10.0.0.0/16`。当我们创建 VPC 时，将创建此隐式路由器。

# 路由表和路由目标

路由是网络工程中最重要的主题之一。值得更仔细地研究它。我们已经看到在创建 VPC 时有一个隐式路由器和主路由表。从上一个示例中，我们创建了一个互联网网关，一个默认路由指向互联网网关的自定义路由表，并将自定义路由表与子网关联。

路由目标的概念是 VPC 与传统网络有些不同的地方。总之：

+   每个 VPC 都有一个隐式路由器

+   每个 VPC 都有一个带有本地路由的主路由表

+   您可以创建自定义路由表

+   每个子网可以遵循自定义路由表或默认的主路由表

+   路由表路由目标可以是互联网网关、NAT 网关、VPC 对等连接等

我们可以使用 Boto3 查看自定义路由表和子网的关联：

```py
$ cat Chapter10_2_query_route_tables.py
#!/usr/bin/env python3

import json, boto3

region = 'us-east-1'
vpc_name = 'mastering_python_networking_demo'

ec2 = boto3.resource('ec2', region_name=region)
client = boto3.client('ec2')

response = client.describe_route_tables()
print(json.dumps(response['RouteTables'][0], sort_keys=True, indent=4))
```

我们只有一个自定义路由表：

```py
$ python3 Chapter10_2_query_route_tables.py
{
 "Associations": [
 {
 ....
 }
 ],
 "PropagatingVgws": [],
 "RouteTableId": "rtb-6bee5514",
 "Routes": [
 {
 "DestinationCidrBlock": "10.0.0.0/16",
 "GatewayId": "local",
 "Origin": "CreateRouteTable",
 "State": "active"
 },
 {
 "DestinationCidrBlock": "0.0.0.0/0",
 "GatewayId": "igw-...",
 "Origin": "CreateRoute",
 "State": "active"
 }
 ],
 "Tags": [
 {
 "Key": "Name",
 "Value": "public_internet_gateway"
 }
 ],
 "VpcId": "vpc-..."
}
```

通过点击左侧子网部分并按照屏幕上的指示进行操作，创建子网非常简单。对于我们的目的，我们将创建三个子网，`10.0.0.0/24`公共子网，`10.0.1.0/24`和`10.0.2.0/24`私有子网。

现在我们有一个带有三个子网的工作 VPC：一个公共子网和两个私有子网。到目前为止，我们已经使用 AWS CLI 和 Boto3 库与 AWS VPC 进行交互。让我们看看另一个自动化工具**CloudFormation**。

# 使用 CloudFormation 进行自动化

AWS CloudFomation ([`aws.amazon.com/cloudformation/`](https://aws.amazon.com/cloudformation/))，是我们可以使用文本文件描述和启动所需资源的一种方式。我们可以使用 CloudFormation 在`us-west-1`地区配置另一个 VPC：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/d37b0edc-2d29-4752-a72b-62c4184507a2.png)美国西部的 VPC

CloudFormation 模板可以是 YAML 或 JSON；我们将使用 YAML 来创建我们的第一个配置模板：

```py
$ cat Chapter10_3_cloud_formation.yml
AWSTemplateFormatVersion: '2010-09-09'
Description: Create VPC in us-west-1
Resources:
 myVPC:
 Type: AWS::EC2::VPC
 Properties:
 CidrBlock: '10.1.0.0/16'
 EnableDnsSupport: 'false'
 EnableDnsHostnames: 'false'
 Tags:
 - Key: Name
 Value: 'mastering_python_networking_demo_2'
```

我们可以通过 AWS CLI 执行模板。请注意，在我们的执行中指定了`us-west-1`地区：

```py
$ aws --region us-west-1 cloudformation create-stack --stack-name 'mpn-ch10-demo' --template-body file://Chapter10_3_cloud_formation.yml
{
 "StackId": "arn:aws:cloudformation:us-west-1:<skip>:stack/mpn-ch10-demo/<skip>"
}
```

我们可以通过 AWS CLI 验证状态：

```py
$ aws --region us-west-1 cloudformation describe-stacks --stack-name mpn-ch10-demo
{
 "Stacks": [
 {
 "CreationTime": "2018-07-18T18:45:25.690Z",
 "Description": "Create VPC in us-west-1",
 "DisableRollback": false,
 "StackName": "mpn-ch10-demo",
 "RollbackConfiguration": {},
 "StackStatus": "CREATE_COMPLETE",
 "NotificationARNs": [],
 "Tags": [],
 "EnableTerminationProtection": false,
 "StackId": "arn:aws:cloudformation:us-west-1<skip>"
 }
 ]
}
```

为了演示目的，最后一个 CloudFormation 模板创建了一个没有任何子网的 VPC。让我们删除该 VPC，并使用以下模板创建 VPC 和子网。请注意，在 VPC 创建之前我们将没有 VPC-id，因此我们将使用特殊变量来引用子网创建中的 VPC-id。这是我们可以用于其他资源的相同技术，比如路由表和互联网网关：

```py
$ cat Chapter10_4_cloud_formation_full.yml
AWSTemplateFormatVersion: '2010-09-09'
Description: Create subnet in us-west-1
Resources:
 myVPC:
 Type: AWS::EC2::VPC
 Properties:
 CidrBlock: '10.1.0.0/16'
 EnableDnsSupport: 'false'
 EnableDnsHostnames: 'false'
 Tags:
 - Key: Name
 Value: 'mastering_python_networking_demo_2'

 mySubnet:
 Type: AWS::EC2::Subnet
 Properties:
 VpcId: !Ref myVPC
 CidrBlock: '10.1.0.0/24'
 AvailabilityZone: 'us-west-1a'
 Tags:
 - Key: Name
 Value: 'mpn_demo_subnet_1'
```

我们可以执行并验证资源的创建如下：

```py
$ aws --region us-west-1 cloudformation create-stack --stack-name mpn-ch10-demo-2 --template-body file://Chapter10_4_cloud_formation_full.yml
{
 "StackId": "arn:aws:cloudformation:us-west-1:<skip>:stack/mpn-ch10-demo-2/<skip>"
}

$ aws --region us-west-1 cloudformation describe-stacks --stack-name mpn-ch10-demo-2
{
 "Stacks": [
 {
 "StackStatus": "CREATE_COMPLETE",
 ...
 "StackName": "mpn-ch10-demo-2",
 "DisableRollback": false
 }
 ]
}
```

我们还可以从 AWS 控制台验证 VPC 和子网信息。我们将首先从控制台验证 VPC：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/c08d36c4-58bc-4669-8468-0e1e363b3f7b.png)VPC 在 us-west-1

我们还可以查看子网：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/68f0b4e2-69b7-4e6c-a7ca-c5d6003ac4d3.png)us-west-1 的子网

现在我们在美国两个海岸有两个 VPC。它们目前的行为就像两个孤立的岛屿。这可能是您期望的操作状态，也可能不是。如果您希望 VPC 能够相互连接，我们可以使用 VPC 对等连接（[`docs.aws.amazon.com/AmazonVPC/latest/PeeringGuide/vpc-peering-basics.html`](https://docs.aws.amazon.com/AmazonVPC/latest/PeeringGuide/vpc-peering-basics.html)）来允许直接通信。

VPC 对等连接不限于同一帐户。只要请求被接受并且其他方面（安全性、路由、DNS 名称）得到处理，您就可以连接不同帐户的 VPC。

在接下来的部分，我们将看一下 VPC 安全组和网络访问控制列表。

# 安全组和网络 ACL

AWS 安全组和访问控制列表可以在 VPC 的安全部分找到：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/8ecdda0a-5132-499c-bd48-8b417eed3499.png)VPC 安全

安全组是一个有状态的虚拟防火墙，用于控制资源的入站和出站访问。大多数情况下，我们将使用安全组来限制对我们的 EC2 实例的公共访问。当前限制是每个 VPC 中有 500 个安全组。每个安全组最多可以包含 50 个入站和 50 个出站规则。您可以使用以下示例脚本创建一个安全组和两个简单的入站规则：

```py
$ cat Chapter10_5_security_group.py
#!/usr/bin/env python3

import boto3

ec2 = boto3.client('ec2')

response = ec2.describe_vpcs()
vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')

# Query for security group id
response = ec2.create_security_group(GroupName='mpn_security_group',
 Description='mpn_demo_sg',
 VpcId=vpc_id)
security_group_id = response['GroupId']
data = ec2.authorize_security_group_ingress(
 GroupId=security_group_id,
 IpPermissions=[
 {'IpProtocol': 'tcp',
 'FromPort': 80,
 'ToPort': 80,
 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
 {'IpProtocol': 'tcp',
 'FromPort': 22,
 'ToPort': 22,
 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
 ])
print('Ingress Successfully Set %s' % data)

# Describe security group
#response = ec2.describe_security_groups(GroupIds=[security_group_id])
print(security_group_id)
```

我们可以执行脚本并收到有关创建可与其他 AWS 资源关联的安全组的确认：

```py
$ python3 Chapter10_5_security_group.py
Ingress Successfully Set {'ResponseMetadata': {'RequestId': '<skip>', 'HTTPStatusCode': 200, 'HTTPHeaders': {'server': 'AmazonEC2', 'content-type': 'text/xml;charset=UTF-8', 'date': 'Wed, 18 Jul 2018 20:51:55 GMT', 'content-length': '259'}, 'RetryAttempts': 0}}
sg-<skip>
```

网络访问控制列表（ACL）是一个无状态的额外安全层。VPC 中的每个子网都与一个网络 ACL 相关联。由于 ACL 是无状态的，您需要指定入站和出站规则。

安全组和 ACL 之间的重要区别如下：

+   安全组在网络接口级别操作，而 ACL 在子网级别操作

+   对于安全组，我们只能指定允许规则，而 ACL 支持允许和拒绝规则

+   安全组是有状态的；返回流量会自动允许。返回流量需要在 ACL 中明确允许

让我们来看看 AWS 网络中最酷的功能之一，弹性 IP。当我最初了解弹性 IP 时，我对动态分配和重新分配 IP 地址的能力感到震惊。

# 弹性 IP

弹性 IP（EIP）是一种使用可以从互联网访问的公共 IPv4 地址的方式。它可以动态分配给 EC2 实例、网络接口或其他资源。弹性 IP 的一些特点如下：

+   弹性 IP 与账户关联，并且是特定于地区的。例如，`us-east-1`中的 EIP 只能与`us-east-1`中的资源关联。

+   您可以取消与资源的弹性 IP 关联，并将其重新关联到不同的资源。这种灵活性有时可以用于确保高可用性。例如，您可以通过将相同的 IP 地址从较小的 EC2 实例重新分配到较大的 EC2 实例来实现迁移。

+   弹性 IP 有与之相关的小额每小时费用。

您可以从门户请求弹性 IP。分配后，您可以将其与所需的资源关联：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/a40704c5-33fd-426b-b1be-f69f3075f380.png)弹性 IP 不幸的是，弹性 IP 在每个地区有默认限制，[`docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html`](https://docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html)。

在接下来的部分，我们将看看如何使用 NAT 网关允许私有子网与互联网通信。

# NAT 网关

为了允许我们的 EC2 公共子网中的主机从互联网访问，我们可以分配一个弹性 IP 并将其与 EC2 主机的网络接口关联。然而，在撰写本书时，每个 EC2-VPC 最多只能有五个弹性 IP 的限制([`docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_Limits.html#vpc-limits-eips`](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_Limits.html#vpc-limits-eips))。有时，当需要时，允许私有子网中的主机获得出站访问权限而不创建弹性 IP 和 EC2 主机之间的永久一对一映射会很好。

这就是 NAT 网关可以帮助的地方，它允许私有子网中的主机通过执行网络地址转换（NAT）临时获得出站访问权限。这个操作类似于我们通常在公司防火墙上执行的端口地址转换（PAT）。要使用 NAT 网关，我们可以执行以下步骤：

+   通过 AWS CLI、Boto3 库或 AWS 控制台在具有对互联网网关访问权限的子网中创建 NAT 网关。NAT 网关将需要分配一个弹性 IP。

+   将私有子网中的默认路由指向 NAT 网关。

+   NAT 网关将遵循默认路由到互联网网关以进行外部访问。

这个操作可以用下图来说明：

NAT 网关操作

NAT 网关通常围绕着 NAT 网关应该位于哪个子网的最常见问题之一。经验法则是要记住 NAT 网关需要公共访问。因此，它应该在具有公共互联网访问权限的子网中创建，并分配一个可用的弹性 IP：

NAT 网关创建

在接下来的部分中，我们将看一下如何将我们在 AWS 中闪亮的虚拟网络连接到我们的物理网络。

# 直接连接和 VPN

到目前为止，我们的 VPC 是驻留在 AWS 网络中的一个自包含网络。它是灵活和功能齐全的，但要访问 VPC 内部的资源，我们需要使用它们的面向互联网的服务，如 SSH 和 HTTPS。

在本节中，我们将看一下 AWS 允许我们从私人网络连接到 VPC 的两种方式：IPSec VPN 网关和直接连接。

# VPN 网关

将我们的本地网络连接到 VPC 的第一种方式是使用传统的 IPSec VPN 连接。我们需要一个可以与 AWS 的 VPN 设备建立 VPN 连接的公共可访问设备。客户网关需要支持基于路由的 IPSec VPN，其中 VPN 连接被视为可以在虚拟链路上运行路由协议的连接。目前，AWS 建议使用 BGP 交换路由。

在 VPC 端，我们可以遵循类似的路由表，可以将特定子网路由到**虚拟私有网关**目标：

VPC VPN 连接（来源：[`docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_VPN.html`](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_VPN.html)）

除了 IPSec VPN，我们还可以使用专用电路进行连接。

# 直接连接

我们看到的 IPSec VPN 连接是提供本地设备与 AWS 云资源连接的简单方法。然而，它遭受了 IPSec 在互联网上总是遭受的相同故障：它是不可靠的，我们对它几乎没有控制。性能监控很少，直到连接到我们可以控制的互联网部分才有**服务级别协议**（SLA）。

出于所有这些原因，任何生产级别的、使命关键的流量更有可能通过亚马逊提供的第二个选项，即 AWS 直接连接。AWS 直接连接允许客户使用专用虚拟电路将他们的数据中心和机房连接到他们的 AWS VPC。这个操作通常比较困难的部分通常是将我们的网络带到可以与 AWS 物理连接的地方，通常是在一个承载商酒店。您可以在这里找到 AWS 直接连接位置的列表：[`aws.amazon.com/directconnect/details/`](https://aws.amazon.com/directconnect/details/)。直接连接链接只是一个光纤补丁连接，您可以从特定的承载商酒店订购，将网络连接到网络端口并配置 dot1q 干线的连接。

还有越来越多的通过第三方承运商使用 MPLS 电路和聚合链路进行直接连接的连接选项。我发现并使用的最实惠的选择之一是 Equinix Cloud Exchange ([`www.equinix.com/services/interconnection-connectivity/cloud-exchange/`](https://www.equinix.com/services/interconnection-connectivity/cloud-exchange/))。通过使用 Equinix Cloud Exchange，我们可以利用相同的电路并以较低成本连接到不同的云提供商：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/966cabb6-fb23-4921-96f6-290e979d6c9f.png)Equinix Cloud Exchange（来源：[`www.equinix.com/services/interconnection-connectivity/cloud-exchange/`](https://www.equinix.com/services/interconnection-connectivity/cloud-exchange/)）

在接下来的部分，我们将看一下 AWS 提供的一些网络扩展服务。

# 网络扩展服务

在本节中，我们将看一下 AWS 提供的一些网络服务。许多服务没有直接的网络影响，比如 DNS 和内容分发网络。由于它们与网络和应用性能的密切关系，它们与我们的讨论相关。

# 弹性负载均衡

**弹性负载均衡**（**ELB**）允许来自互联网的流量自动分布到多个 EC2 实例。就像物理世界中的负载均衡器一样，这使我们能够在减少每台服务器负载的同时获得更好的冗余和容错。ELB 有两种类型：应用和网络负载均衡。

应用负载均衡器通过 HTTP 和 HTTPS 处理 Web 流量；网络负载均衡器在 TCP 层运行。如果您的应用程序在 HTTP 或 HTTPS 上运行，通常最好选择应用负载均衡器。否则，使用网络负载均衡器是一个不错的选择。

可以在[`aws.amazon.com/elasticloadbalancing/details/`](https://aws.amazon.com/elasticloadbalancing/details/)找到应用和网络负载均衡器的详细比较：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/af58c911-8764-46d9-a3e3-71e90df6e39b.png)弹性负载均衡器比较（来源：[`aws.amazon.com/elasticloadbalancing/details/`](https://aws.amazon.com/elasticloadbalancing/details/)）

弹性负载均衡器提供了一种在资源进入我们地区后平衡流量的方式。AWS Route53 DNS 服务允许在地区之间进行地理负载平衡。

# Route53 DNS 服务

我们都知道域名服务是什么；Route53 是 AWS 的 DNS 服务。Route53 是一个全功能的域名注册商，您可以直接从 AWS 购买和管理域名。关于网络服务，DNS 允许通过在地理区域之间以轮询方式服务域名来实现负载平衡。

在我们可以使用 DNS 进行负载平衡之前，我们需要以下项目：

+   每个预期的负载平衡地区中都有一个弹性负载均衡器。

+   注册的域名。我们不需要 Route53 作为域名注册商。

+   Route53 是该域的 DNS 服务。

然后我们可以在两个弹性负载均衡器之间的主动-主动环境中使用 Route 53 基于延迟的路由策略和健康检查。

# CloudFront CDN 服务

CloudFront 是亚马逊的**内容分发网络**（**CDN**），通过在物理上为客户提供更接近的内容，减少了内容交付的延迟。内容可以是静态网页内容、视频、应用程序、API，或者最近的 Lambda 函数。CloudFront 边缘位置包括现有的 AWS 区域，还有全球许多其他位置。CloudFront 的高级操作如下：

+   用户访问您的网站以获取一个或多个对象

+   DNS 将请求路由到距用户请求最近的 Amazon CloudFront 边缘位置

+   CloudFront 边缘位置将通过缓存提供内容或从源请求对象

AWS CloudFront 和 CDN 服务通常由应用程序开发人员或 DevOps 工程师处理。但是，了解它们的运作方式总是很好的。

# 其他 AWS 网络服务

还有许多其他 AWS 网络服务，我们没有空间来介绍。一些更重要的服务列在本节中：

+   **AWS Transit VPC** ([`aws.amazon.com/blogs/aws/aws-solution-transit-vpc/`](https://aws.amazon.com/blogs/aws/aws-solution-transit-vpc/))：这是一种连接多个虚拟私有云到一个作为中转中心的公共 VPC 的方式。这是一个相对较新的服务，但它可以最小化您需要设置和管理的连接。这也可以作为一个工具，当您需要在不同的 AWS 账户之间共享资源时。

+   **Amazon GuardDuty** ([`aws.amazon.com/guardduty/`](https://aws.amazon.com/guardduty/))：这是一个托管的威胁检测服务，持续监视恶意或未经授权的行为，以帮助保护我们的 AWS 工作负载。它监视 API 调用或潜在的未经授权的部署。

+   **AWS WAF**([`aws.amazon.com/waf/`](https://aws.amazon.com/waf/))：这是一个 Web 应用程序防火墙，可以帮助保护 Web 应用程序免受常见的攻击。我们可以定义定制的 Web 安全规则来允许或阻止 Web 流量。

+   **AWS Shield** ([`aws.amazon.com/shield/`](https://aws.amazon.com/shield/))：这是一个托管的**分布式拒绝服务**（**DDoS**）保护服务，可保护在 AWS 上运行的应用程序。基本级别的保护服务对所有客户免费；AWS Shield 的高级版本是一项收费服务。

# 总结

在本章中，我们深入了解了 AWS 云网络服务。我们讨论了 AWS 网络中区域、可用区、边缘位置和中转中心的定义。通过了解整体的 AWS 网络，这让我们对其他 AWS 网络服务的一些限制和内容有了一个很好的了解。在本章的整个过程中，我们使用了 AWS CLI、Python Boto3 库以及 CloudFormation 来自动化一些任务。

我们深入讨论了 AWS 虚拟私有云，包括路由表和路由目标的配置。关于安全组和网络 ACL 控制我们 VPC 的安全性的示例。我们还讨论了弹性 IP 和 NAT 网关，以允许外部访问。

连接 AWS VPC 到本地网络有两种方式：直接连接和 IPSec VPN。我们简要地介绍了每种方式以及使用它们的优势。在本章的最后，我们了解了 AWS 提供的网络扩展服务，包括弹性负载均衡、Route53 DNS 和 CloudFront。

在第十一章中，*使用 Git*，我们将更深入地了解我们一直在使用的版本控制系统：Git。


# 第十一章：使用 Git

我们已经使用 Python、Ansible 和许多其他工具在网络自动化的各个方面进行了工作。如果您一直在阅读本书的前九章的示例，我们已经使用了超过 150 个文件，其中包含超过 5300 行代码。对于可能主要使用命令行界面的网络工程师来说，这是相当不错的！有了我们的新一套脚本和工具，我们现在准备好去征服我们的网络任务了，对吗？嗯，我的同行网络忍者们，不要那么快。

我们面对的第一个任务是如何将代码文件保存在一个位置，以便我们和其他人可以检索和使用。理想情况下，这个位置应该是保存文件的最新版本的唯一位置。在初始发布之后，我们可能会在未来添加功能和修复错误，因此我们希望有一种方式来跟踪这些更改并保持最新版本可供下载。如果新的更改不起作用，我们希望回滚更改并反映文件历史中的差异。这将给我们一个关于代码文件演变的良好概念。

第二个问题是我们团队成员之间的协作过程。如果我们与其他网络工程师合作，我们将需要共同在文件上工作。这些文件可以是 Python 脚本、Ansible Playbook、Jinja2 模板、INI 风格的配置文件等等。关键是任何一种基于文本的文件都应该被多方输入跟踪，以便团队中的每个人都能看到。

第三个问题是责任制。一旦我们有了一个允许多方输入和更改的系统，我们需要用适当的记录来标记这些更改，以反映更改的所有者。记录还应包括更改的简要原因，以便审查历史的人能够理解更改的原因。

这些是版本控制（或源代码控制）系统试图解决的一些主要挑战。公平地说，版本控制可以存在于专用系统以外的形式。例如，如果我打开我的 Microsoft Word 程序，文件会不断保存自身，并且我可以回到过去查看更改或回滚到以前的版本。我们在这里关注的版本控制系统是具有主要目的跟踪软件更改的独立软件工具。

在软件工程中，有各种不同的源代码控制工具，既有专有的也有开源的。一些更受欢迎的开源版本控制系统包括 CVS、SVN、Mercurial 和 Git。在本章中，我们将专注于源代码控制系统**Git**，这是我们在本书中使用的许多`.software`软件包中下载的工具。我们将更深入地了解这个工具。Git 是许多大型开源项目的事实上的版本控制系统，包括 Python 和 Linux 内核。

截至 2017 年 2 月，CPython 开发过程已经转移到 GitHub。自 2015 年 1 月以来一直在进行中。有关更多信息，请查看[`www.python.org/dev/peps/pep-0512/`](https://www.python.org/dev/peps/pep-0512/)上的 PEP 512。

在我们深入了解 Git 的工作示例之前，让我们先来看看 Git 系统的历史和优势。

# Git 简介

Git 是由 Linux 内核的创造者 Linus Torvalds 于 2005 年 4 月创建的。他幽默地称这个工具为“来自地狱的信息管理者”。在 Linux 基金会的一次采访中，Linus 提到他觉得源代码控制管理在计算世界中几乎是最不有趣的事情。然而，在 Linux 内核开发社区和当时他们使用的专有系统 BitKeeper 之间发生分歧后，他还是创建了这个工具。

Git 这个名字代表什么？在英国俚语中，Git 是一个侮辱性词语，表示一个令人不愉快、恼人、幼稚的人。Linus 以他的幽默说他是一个自负的混蛋，所以他把所有的项目都以自己的名字命名。首先是 Linux，现在是 Git。然而，也有人建议这个名字是**全球信息跟踪器**（**GIT**）的缩写。你可以做出判断。

这个项目很快就成形了。在创建后大约十天（没错，你没看错），Linus 觉得 Git 的基本理念是正确的，开始用 Git 提交第一个 Linux 内核代码。其余的，就像他们说的那样，就成了历史。在创建十多年后，它仍然满足 Linux 内核项目的所有期望。尽管切换源代码控制系统存在固有的惯性，它已经成为许多其他开源项目的版本控制系统。在多年托管 Python 代码后，该项目于 2017 年 2 月在 GitHub 上切换到 Git。

# Git 的好处

像 Linux 内核和 Python 这样的大型分布式开源项目的成功托管，证明了 Git 的优势。这尤其重要，因为 Git 是一个相对较新的源代码控制工具，人们不倾向于切换到新工具，除非它比旧工具有显著的优势。让我们看看 Git 的一些好处：

+   **分布式开发**：Git 支持在私人仓库中进行并行、独立和同时的离线开发。与其他一些版本控制系统需要与中央仓库进行不断同步相比，这为开发人员提供了更大的灵活性。

+   **扩展以处理成千上万的开发人员**：许多开源项目的开发人员数量达到了成千上万。Git 支持可靠地集成他们的工作。

+   **性能**：Linus 决心确保 Git 快速高效。为了节省空间和传输时间，仅 Linux 内核代码的更新量就需要压缩和增量检查来使 Git 快速高效。

+   **责任和不可变性**：Git 强制在每次更改文件的提交时记录更改日志，以便对所有更改和更改原因进行跟踪。Git 中的数据对象在创建并放入数据库后无法修改，使它们不可变。这进一步强化了责任。

+   **原子事务**：确保仓库的完整性，不同但相关的更改要么一起执行，要么不执行。这将确保仓库不会处于部分更改或损坏的状态。

+   **完整的仓库**：每个仓库都有每个文件的所有历史修订版本的完整副本。

+   **自由，就像自由**：Git 工具的起源源于 Linux 内核的免费版本与 BitKeeper VCS 之间的分歧，因此这个工具有一个非常自由的使用许可证。

让我们来看看 Git 中使用的一些术语。

# Git 术语

以下是一些我们应该熟悉的 Git 术语：

+   **Ref**：以`refs`开头指向对象的名称。

+   **存储库**：包含项目所有信息、文件、元数据和历史记录的数据库。它包含了所有对象集合的`ref`。

+   **分支**：活跃的开发线。最近的提交是该分支的`tip`或`HEAD`。存储库可以有多个分支，但您的`工作树`或`工作目录`只能与一个分支关联。有时这被称为当前或`checked out`分支。

+   **检出**：将工作树的全部或部分更新到特定点的操作。

+   **提交**：Git 历史中的一个时间点，或者可以表示将新的快照存储到存储库中。

+   **合并**：将另一个分支的内容合并到当前分支的操作。例如，我正在将`development`分支与`master`分支合并。

+   **获取**：从远程存储库获取内容的操作。

+   **拉取**：获取并合并存储库的内容。

+   **标签**：存储库中某个时间点的标记。在第四章中，*Python 自动化框架- Ansible 基础*，我们看到标签用于指定发布点，`v2.5.0a1`。

这不是一个完整的列表；请参考 Git 术语表，[`git-scm.com/docs/gitglossary`](https://git-scm.com/docs/gitglossary)，了解更多术语及其定义。

# Git 和 GitHub

Git 和 GitHub 并不是同一回事。对于新手来说，这有时会让工程师感到困惑。Git 是一个版本控制系统，而 GitHub，[`github.com/`](https://github.com/)，是 Git 存储库的集中式托管服务。

因为 Git 是一个分散的系统，GitHub 存储了我们项目的存储库的副本，就像其他任何开发人员一样。通常，我们将 GitHub 存储库指定为项目的中央存储库，所有其他开发人员将其更改推送到该存储库，并从该存储库拉取更改。

GitHub 通过使用`fork`和`pull requests`机制，进一步将这个在分布式系统中的集中存储库的概念发扬光大。对于托管在 GitHub 上的项目，鼓励开发人员`fork`存储库，或者复制存储库，并在该复制品上工作作为他们的集中存储库。在做出更改后，他们可以向主项目发送`pull request`，项目维护人员可以审查更改，并在适当的情况下`commit`更改。GitHub 还除了命令行之外，还为存储库添加了 Web 界面；这使得 Git 更加用户友好。

# 设置 Git

到目前为止，我们只是使用 Git 从 GitHub 下载文件。在本节中，我们将进一步设置 Git 变量，以便开始提交我们的文件。我将在示例中使用相同的 Ubuntu 16.04 主机。安装过程有很好的文档记录；如果您使用的是不同版本的 Linux 或其他操作系统，快速搜索应该能找到正确的指令集。

如果您还没有这样做，请通过`apt`软件包管理工具安装 Git：

```py
$ sudo apt-get update
$ sudo apt-get install -y git
$ git --version
git version 2.7.4
```

安装了`git`之后，我们需要配置一些东西，以便我们的提交消息可以包含正确的信息：

```py
$ git config --global user.name "Your Name"
$ git config --global user.email "email@domain.com"
$ git config --list
user.name=Your Name
user.email=email@domain.com
```

或者，您可以修改`~/.gitconfig`文件中的信息：

```py
$ cat ~/.gitconfig
[user]
 name = Your Name
 email = email@domain.com
```

Git 中还有许多其他选项可以更改，但是名称和电子邮件是允许我们提交更改而不会收到警告的选项。个人而言，我喜欢使用 VIM，而不是默认的 Emac，作为我的文本编辑器来输入提交消息：

```py
(optional)
$ git config --global core.editor "vim"
$ git config --list
user.name=Your Name
user.email=email@domain.com
core.editor=vim
```

在我们继续使用 Git 之前，让我们先了解一下`gitignore`文件的概念。

# Gitignore

有时，有些文件您不希望 Git 检查到 GitHub 或其他存储库中。这样做的最简单方法是在`repository`文件夹中创建`.gitignore`；Git 将使用它来确定在进行提交之前应该忽略哪些文件。这个文件应该提交到存储库中，以便与其他用户共享忽略规则。

这个文件可以包括特定于语言的文件，例如，让我们排除 Python 的`Byte-compiled`文件：

```py
# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class
```

我们还可以包括特定于您的操作系统的文件：

```py
# OSX
# =========================

.DS_Store
.AppleDouble
.LSOverride
```

您可以在 GitHub 的帮助页面上了解更多关于`.gitignore`的信息：[`help.github.com/articles/ignoring-files/`](https://help.github.com/articles/ignoring-files/)。以下是一些其他参考资料：

+   Gitignore 手册：[`git-scm.com/docs/gitignore`](https://git-scm.com/docs/gitignore)

+   GitHub 的`.gitignore`模板集合：[`github.com/github/gitignore`](https://github.com/github/gitignore)

+   Python 语言`.gitignore`示例：[`github.com/github/gitignore/blob/master/Python.gitignore`](https://github.com/github/gitignore/blob/master/Python.gitignore)

+   本书存储库的`.gitignore`文件：[`github.com/PacktPublishing/Mastering-Python-Networking-Second-Edition/blob/master/.gitignore`](https://github.com/PacktPublishing/Mastering-Python-Networking-Second-Edition/blob/master/.gitignore)

我认为`.gitignore`文件应该与任何新存储库同时创建。这就是为什么这个概念尽早被引入的原因。我们将在下一节中看一些 Git 使用示例。

# Git 使用示例

大多数时候，当我们使用 Git 时，我们会使用命令行：

```py
$ git --help
usage: git [--version] [--help] [-C <path>] [-c name=value]
 [--exec-path[=<path>]] [--html-path] [--man-path] [--info-path]
 [-p | --paginate | --no-pager] [--no-replace-objects] [--bare]
 [--git-dir=<path>] [--work-tree=<path>] [--namespace=<name>]
 <command> [<args>]
```

我们将创建一个`repository`并在其中创建一个文件：

```py
$ mkdir TestRepo
$ cd TestRepo/
$ git init
Initialized empty Git repository in /home/echou/Master_Python_Networking_second_edition/Chapter11/TestRepo/.git/
$ echo "this is my test file" > myFile.txt
```

当使用 Git 初始化存储库时，会在目录中添加一个新的隐藏文件夹`.git`。它包含所有与 Git 相关的文件：

```py
$ ls -a
. .. .git myFile.txt

$ ls .git/
branches config description HEAD hooks info objects refs
```

Git 接收其配置的位置有几个层次结构。您可以使用`git config -l`命令来查看聚合配置：

```py
$ ls .git/config
.git/config

$ ls ~/.gitconfig
/home/echou/.gitconfig

$ git config -l
user.name=Eric Chou
user.email=<email>
core.editor=vim
core.repositoryformatversion=0
core.filemode=true
core.bare=false
core.logallrefupdates=true
```

当我们在存储库中创建一个文件时，它不会被跟踪。为了让`git`意识到这个文件，我们需要添加这个文件：

```py
$ git status
On branch master

Initial commit

Untracked files:
 (use "git add <file>..." to include in what will be committed)

 myFile.txt

nothing added to commit but untracked files present (use "git add" to track)

$ git add myFile.txt
$ git status
On branch master

Initial commit

Changes to be committed:
 (use "git rm --cached <file>..." to unstage)

 new file: myFile.txt
```

当您添加文件时，它处于暂存状态。为了使更改生效，我们需要提交更改：

```py
$ git commit -m "adding myFile.txt"
[master (root-commit) 5f579ab] adding myFile.txt
 1 file changed, 1 insertion(+)
 create mode 100644 myFile.txt

$ git status
On branch master
nothing to commit, working directory clean
```

在上一个示例中，我们在发出提交语句时使用了`-m`选项来提供提交消息。如果我们没有使用该选项，我们将被带到一个页面上来提供提交消息。在我们的情况下，我们配置了文本编辑器为 vim，因此我们将能够使用 vim 来编辑消息。

让我们对文件进行一些更改并提交它：

```py
$ vim myFile.txt
$ cat myFile.txt
this is the second iteration of my test file
$ git status
On branch master
Changes not staged for commit:
 (use "git add <file>..." to update what will be committed)
 (use "git checkout -- <file>..." to discard changes in working directory)

 modified: myFile.txt
$ git add myFile.txt
$ git commit -m "made modificaitons to myFile.txt"
[master a3dd3ea] made modificaitons to myFile.txt
 1 file changed, 1 insertion(+), 1 deletion(-)
```

`git commit`号是一个`SHA1 哈希`，这是一个重要的特性。如果我们在另一台计算机上按照相同的步骤操作，我们的`SHA1 哈希`值将是相同的。这就是 Git 知道这两个存储库在并行工作时是相同的方式。

我们可以使用`git log`来显示提交的历史记录。条目以相反的时间顺序显示；每个提交显示作者的姓名和电子邮件地址，日期，日志消息，以及提交的内部标识号：

```py
$ git log
commit a3dd3ea8e6eb15b57d1f390ce0d2c3a03f07a038
Author: Eric Chou <echou@yahoo.com>
Date: Fri Jul 20 09:58:24 2018 -0700

 made modificaitons to myFile.txt

commit 5f579ab1e9a3fae13aa7f1b8092055213157524d
Author: Eric Chou <echou@yahoo.com>
Date: Fri Jul 20 08:05:09 2018 -0700

 adding myFile.txt
```

我们还可以使用提交 ID 来显示更改的更多细节：

```py
$ git show a3dd3ea8e6eb15b57d1f390ce0d2c3a03f07a038
commit a3dd3ea8e6eb15b57d1f390ce0d2c3a03f07a038
Author: Eric Chou <echou@yahoo.com>
Date: Fri Jul 20 09:58:24 2018 -0700

 made modificaitons to myFile.txt

diff --git a/myFile.txt b/myFile.txt
index 6ccb42e..69e7d47 100644
--- a/myFile.txt
+++ b/myFile.txt
@@ -1 +1 @@
-this is my test file
+this is the second iteration of my test file
```

如果您需要撤消所做的更改，您可以选择`revert`和`reset`之间。`revert`将特定提交的所有文件更改回到它们在提交之前的状态：

```py
$ git revert a3dd3ea8e6eb15b57d1f390ce0d2c3a03f07a038
[master 9818f29] Revert "made modificaitons to myFile.txt"
 1 file changed, 1 insertion(+), 1 deletion(-)

# Check to verified the file content was before the second change. 
$ cat myFile.txt
this is my test file
```

`revert`命令将保留您撤消的提交并创建一个新的提交。您将能够看到到那一点的所有更改，包括撤消：

```py
$ git log
commit 9818f298f477fd880db6cb87112b50edc392f7fa
Author: Eric Chou <echou@yahoo.com>
Date: Fri Jul 20 13:11:30 2018 -0700

 Revert "made modificaitons to myFile.txt"

 This reverts commit a3dd3ea8e6eb15b57d1f390ce0d2c3a03f07a038.

 modified: reverted the change to myFile.txt

commit a3dd3ea8e6eb15b57d1f390ce0d2c3a03f07a038
Author: Eric Chou <echou@yahoo.com>
Date: Fri Jul 20 09:58:24 2018 -0700

 made modificaitons to myFile.txt

commit 5f579ab1e9a3fae13aa7f1b8092055213157524d
Author: Eric Chou <echou@yahoo.com>
Date: Fri Jul 20 08:05:09 2018 -0700

 adding myFile.txt
```

`reset`选项将将存储库的状态重置为旧版本，并丢弃其中的所有更改：

```py
$ git reset --hard a3dd3ea8e6eb15b57d1f390ce0d2c3a03f07a038
HEAD is now at a3dd3ea made modificaitons to myFile.txt

$ git log
commit a3dd3ea8e6eb15b57d1f390ce0d2c3a03f07a038
Author: Eric Chou <echou@yahoo.com>
Date: Fri Jul 20 09:58:24 2018 -0700

 made modificaitons to myFile.txt

commit 5f579ab1e9a3fae13aa7f1b8092055213157524d
Author: Eric Chou <echou@yahoo.com>
Date: Fri Jul 20 08:05:09 2018 -0700

 adding myFile.txt
```

就个人而言，我喜欢保留所有历史记录，包括我所做的任何回滚。因此，当我需要回滚更改时，我通常选择`revert`而不是`reset`。

`git`中的`分支`是存储库内的开发线。Git 允许在存储库内有许多分支和不同的开发线。默认情况下，我们有主分支。分支的原因有很多，但大多数代表单个客户发布或开发阶段，即`dev`分支。让我们在我们的存储库中创建一个`dev`分支：

```py
$ git branch dev
$ git branch
 dev
* master
```

要开始在分支上工作，我们需要`检出`该分支：

```py
$ git checkout dev
Switched to branch 'dev'
$ git branch
* dev
 master
```

让我们在`dev`分支中添加第二个文件：

```py
$ echo "my second file" > mySecondFile.txt
$ git add mySecondFile.txt
$ git commit -m "added mySecondFile.txt to dev branch"
[dev c983730] added mySecondFile.txt to dev branch
 1 file changed, 1 insertion(+)
 create mode 100644 mySecondFile.txt
```

我们可以回到`master`分支并验证两行开发是分开的：

```py
$ git branch
* dev
 master
$ git checkout master
Switched to branch 'master'
$ ls
myFile.txt
$ git checkout dev
Switched to branch 'dev'
$ ls
myFile.txt mySecondFile.txt
```

将`dev`分支中的内容写入`master`分支，我们需要将它们`合并`：

```py
$ git branch
* dev
 master
$ git checkout master
$ git merge dev master
Updating a3dd3ea..c983730
Fast-forward
 mySecondFile.txt | 1 +
 1 file changed, 1 insertion(+)
 create mode 100644 mySecondFile.txt
$ git branch
 dev
* master
$ ls
myFile.txt mySecondFile.txt
```

我们可以使用`git rm`来删除文件。让我们创建第三个文件并将其删除：

```py
$ touch myThirdFile.txt
$ git add myThirdFile.txt
$ git commit -m "adding myThirdFile.txt"
[master 2ec5f7d] adding myThirdFile.txt
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 myThirdFile.txt
$ ls
myFile.txt mySecondFile.txt myThirdFile.txt
$ git rm myThirdFile.txt
rm 'myThirdFile.txt'
$ git status
On branch master
Changes to be committed:
 (use "git reset HEAD <file>..." to unstage)

 deleted: myThirdFile.txt
$ git commit -m "deleted myThirdFile.txt"
[master bc078a9] deleted myThirdFile.txt
 1 file changed, 0 insertions(+), 0 deletions(-)
 delete mode 100644 myThirdFile.txt
```

我们将能够在日志中看到最后两次更改：

```py
$ git log
commit bc078a97e41d1614c1ba1f81f72acbcd95c0728c
Author: Eric Chou <echou@yahoo.com>
Date: Fri Jul 20 14:02:02 2018 -0700

 deleted myThirdFile.txt

commit 2ec5f7d1a734b2cc74343ce45075917b79cc7293
Author: Eric Chou <echou@yahoo.com>
Date: Fri Jul 20 14:01:18 2018 -0700

 adding myThirdFile.txt
```

我们已经了解了 Git 的大部分基本操作。让我们看看如何使用 GitHub 共享我们的存储库。

# GitHub 示例

在这个例子中，我们将使用 GitHub 作为同步我们的本地存储库并与其他用户共享的集中位置。

我们将在 GitHub 上创建一个存储库。默认情况下，GitHub 有一个免费的公共存储库；在我的情况下，我支付一个小额的月费来托管私人存储库。在创建时，您可以选择创建许可证和`.gitignore`文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/62b8ab5d-063e-438a-9705-88d7472f9f8f.png)

GitHub 私人存储库

存储库创建后，我们可以找到该存储库的 URL：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/f0203a9a-1927-4afc-9b44-492d918e31d4.png)

GitHub 存储库 URL

我们将使用此 URL 创建一个`远程`目标；我们将其命名为`gitHubRepo`：

```py
$ git remote add gitHubRepo https://github.com/ericchou1/TestRepo.git
$ git remote -v
gitHubRepo https://github.com/ericchou1/TestRepo.git (fetch)
gitHubRepo https://github.com/ericchou1/TestRepo.git (push)
```

由于我们选择在创建时创建`README.md`和`LICENSE`文件，远程存储库和当前存储库不同。如果我们将本地更改推送到 GitHub 存储库，将收到以下错误：

```py
$ git push gitHubRepo master
Username for 'https://github.com': echou@yahoo.com
Password for 'https://echou@yahoo.com@github.com':
To https://github.com/ericchou1/TestRepo.git
 ! [rejected] master -> master (fetch first)
```

我们将继续使用`git pull`从 GitHub 获取新文件：

```py
$ git pull gitHubRepo master
Username for 'https://github.com': <username>
Password for 'https://<username>@github.com':
From https://github.com/ericchou1/TestRepo
 * branch master -> FETCH_HEAD
Merge made by the 'recursive' strategy.
 .gitignore | 104 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 LICENSE | 21 +++++++++++++
 README.md | 2 ++
 3 files changed, 127 insertions(+)
 create mode 100644 .gitignore
 create mode 100644 LICENSE
 create mode 100644 README.md
```

现在我们将能够将内容`推送`到 GitHub：

```py
$ git push gitHubRepo master
Username for 'https://github.com': <username>
Password for 'https://<username>@github.com':
Counting objects: 15, done.
Compressing objects: 100% (9/9), done.
Writing objects: 100% (15/15), 1.51 KiB | 0 bytes/s, done.
Total 15 (delta 1), reused 0 (delta 0)
remote: Resolving deltas: 100% (1/1), done.
To https://github.com/ericchou1/TestRepo.git
 a001b81..0aa362a master -> master
```

我们可以在网页上验证 GitHub 存储库的内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/d7d01d22-b4a7-45e3-9230-faa30494b5af.png)

GitHub 存储库

现在另一个用户可以简单地制作存储库的副本，或`克隆`：

```py
[This is operated from another host]
$ cd /tmp
$ git clone https://github.com/ericchou1/TestRepo.git
Cloning into 'TestRepo'...
remote: Counting objects: 20, done.
remote: Compressing objects: 100% (13/13), done.
remote: Total 20 (delta 2), reused 15 (delta 1), pack-reused 0
Unpacking objects: 100% (20/20), done.
$ cd TestRepo/
$ ls
LICENSE myFile.txt
README.md mySecondFile.txt
```

这个复制的存储库将是我原始存储库的精确副本，包括所有提交历史：

```py
$ git log
commit 0aa362a47782e7714ca946ba852f395083116ce5 (HEAD -> master, origin/master, origin/HEAD)
Merge: bc078a9 a001b81
Author: Eric Chou <echou@yahoo.com>
Date: Fri Jul 20 14:18:58 2018 -0700

 Merge branch 'master' of https://github.com/ericchou1/TestRepo

commit a001b816bb75c63237cbc93067dffcc573c05aa2
Author: Eric Chou <ericchou1@users.noreply.github.com>
Date: Fri Jul 20 14:16:30 2018 -0700

 Initial commit
...
```

我还可以在存储库设置下邀请另一个人作为项目的合作者：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/49c734fa-c413-4bc2-98fe-b392520dec52.png)

存储库邀请

在下一个例子中，我们将看到如何分叉存储库并为我们不维护的存储库发起拉取请求。

# 通过拉取请求进行协作

如前所述，Git 支持开发人员之间的合作，用于单个项目。我们将看看当代码托管在 GitHub 上时是如何完成的。

在这种情况下，我将查看这本书的 GitHub 存储库。我将使用不同的 GitHub 句柄，所以我会以不同的用户身份出现。我将点击分叉按钮，在我的个人帐户中制作存储库的副本：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/5e9563c6-d5df-41b6-a780-797aa8e88afb.png)

Git 分叉底部

制作副本需要几秒钟：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/7c4ffe85-465d-4874-a9aa-12e02fa89634.png)

Git 正在进行分叉

分叉后，我们将在我们的个人帐户中拥有存储库的副本：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/6ec1babb-d96b-4b24-9dc5-e160acb2440f.png)

Git 分叉

我们可以按照之前使用过的相同步骤对文件进行一些修改。在这种情况下，我将对`README.md`文件进行一些更改。更改完成后，我可以点击“新拉取请求”按钮来创建一个拉取请求：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/080bb0d8-2ecc-4778-b9be-8753ed38db7b.png)

拉取请求

在发起拉取请求时，我们应尽可能填写尽可能多的信息，以提供更改的理由：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/87417bd2-789c-42f5-b5cc-d79e341451cd.png)

拉取请求详细信息

存储库维护者将收到拉取请求的通知；如果被接受，更改将传递到原始存储库：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/8cecc7d3-149e-4400-a506-7b4404e530bf.png)

拉取请求记录

GitHub 为与其他开发人员合作提供了一个出色的平台；这很快成为了许多大型开源项目的事实开发选择。在接下来的部分，让我们看看如何使用 Python 与 Git。

# 使用 Python 的 Git

有一些 Python 包可以与 Git 和 GitHub 一起使用。在本节中，我们将看一下 GitPython 和 PyGithub 库。

# GitPython

我们可以使用 GitPython 包[`gitpython.readthedocs.io/en/stable/index.html`](https://gitpython.readthedocs.io/en/stable/index.html)来处理我们的 Git 存储库。我们将安装该包并使用 Python shell 来构建一个`Repo`对象。从那里，我们可以列出存储库中的所有提交：

```py
$ sudo pip3 install gitpython
$ python3
>>> from git import Repo
>>> repo = Repo('/home/echou/Master_Python_Networking_second_edition/Chapter11/TestRepo')
>>> for commits in list(repo.iter_commits('master')):
... print(commits)
...
0aa362a47782e7714ca946ba852f395083116ce5
a001b816bb75c63237cbc93067dffcc573c05aa2
bc078a97e41d1614c1ba1f81f72acbcd95c0728c
2ec5f7d1a734b2cc74343ce45075917b79cc7293
c98373069f27d8b98d1ddacffe51b8fa7a30cf28
a3dd3ea8e6eb15b57d1f390ce0d2c3a03f07a038
5f579ab1e9a3fae13aa7f1b8092055213157524d

```

我们还可以查看索引条目：

```py
>>> for (path, stage), entry in index.entries.items():
... print(path, stage, entry)
...
mySecondFile.txt 0 100644 75d6370ae31008f683cf18ed086098d05bf0e4dc 0 mySecondFile.txt
LICENSE 0 100644 52feb16b34de141a7567e4d18164fe2400e9229a 0 LICENSE
myFile.txt 0 100644 69e7d4728965c885180315c0d4c206637b3f6bad 0 myFile.txt
.gitignore 0 100644 894a44cc066a027465cd26d634948d56d13af9af 0 .gitignore
README.md 0 100644 a29fe688a14d119c20790195a815d078976c3bc6 0 README.md
>>>
```

GitPython 与所有 Git 功能集成良好。但是它并不是最容易使用的。我们需要了解 Git 的术语和结构，以充分利用 GitPython。但是要记住，以防我们需要它用于其他项目。

# PyGitHub

让我们看看如何使用 PyGitHub 包[`pygithub.readthedocs.io/en/latest/`](http://pygithub.readthedocs.io/en/latest/)与 GitHub 存储库进行交互。该包是围绕 GitHub APIv3 的包装器[`developer.github.com/v3/`](https://developer.github.com/v3/)：

```py
$ sudo pip install pygithub
$ sudo pip3 install pygithub
```

让我们使用 Python shell 来打印用户当前的存储库：

```py
$ python3
>>> from github import Github
>>> g = Github("ericchou1", "<password>")
>>> for repo in g.get_user().get_repos():
...     print(repo.name)
...
ansible
...
-Hands-on-Network-Programming-with-Python
Mastering-Python-Networking
Mastering-Python-Networking-Second-Edition
>>>
```

为了更多的编程访问，我们还可以使用访问令牌创建更细粒度的控制。Github 允许令牌与所选权限关联：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/ee987cae-5c00-4fc8-a0d7-78299cbf0e9a.png)

GitHub 令牌生成

如果使用访问令牌作为认证机制，输出会有些不同：

```py
>>> from github import Github
>>> g = Github("<token>")
>>> for repo in g.get_user().get_repos():
...     print(repo)
...
Repository(full_name="oreillymedia/distributed_denial_of_service_ddos")
Repository(full_name="PacktPublishing/-Hands-on-Network-Programming-with-Python")
Repository(full_name="PacktPublishing/Mastering-Python-Networking")
Repository(full_name="PacktPublishing/Mastering-Python-Networking-Second-Edition")
...
```

现在我们熟悉了 Git、GitHub 和一些 Python 包，我们可以使用它们来处理技术。在接下来的部分，我们将看一些实际的例子。

# 自动化配置备份

在这个例子中，我们将使用 PyGithub 来备份包含我们路由器配置的目录。我们已经看到了如何使用 Python 或 Ansible 从我们的设备中检索信息；现在我们可以将它们检入 GitHub。

我们有一个子目录，名为`config`，其中包含我们的路由器配置的文本格式：

```py
$ ls configs/
iosv-1 iosv-2

$ cat configs/iosv-1
Building configuration...

Current configuration : 4573 bytes
!
! Last configuration change at 02:50:05 UTC Sat Jun 2 2018 by cisco
!
version 15.6
service timestamps debug datetime msec
...
```

我们可以使用以下脚本从我们的 GitHub 存储库中检索最新的索引，构建我们需要提交的内容，并自动提交配置：

```py
$ cat Chapter11_1.py
#!/usr/bin/env python3
# reference: https://stackoverflow.com/questions/38594717/how-do-i-push-new-files-to-github

from github import Github, InputGitTreeElement
import os

github_token = '<token>'
configs_dir = 'configs'
github_repo = 'TestRepo'

# Retrieve the list of files in configs directory
file_list = []
for dirpath, dirname, filenames in os.walk(configs_dir):
    for f in filenames:
        file_list.append(configs_dir + "/" + f)

g = Github(github_token)
repo = g.get_user().get_repo(github_repo)

commit_message = 'add configs'
master_ref = repo.get_git_ref('heads/master')
master_sha = master_ref.object.sha
base_tree = repo.get_git_tree(master_sha)

element_list = list()

for entry in file_list:
    with open(entry, 'r') as input_file:
        data = input_file.read()
    element = InputGitTreeElement(entry, '100644', 'blob', data)
    element_list.append(element)

# Create tree and commit
tree = repo.create_git_tree(element_list, base_tree)
parent = repo.get_git_commit(master_sha)
commit = repo.create_git_commit(commit_message, tree, [parent])
master_ref.edit(commit.sha)
```

我们可以在 GitHub 存储库中看到`configs`目录：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/bbc515e8-57e3-4942-87ce-cd5f36ba8662.png)

Configs 目录

提交历史显示了我们脚本的提交：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/74cb1602-7bad-4888-b920-78a54d3c3051.png)

提交历史

在*GitHub 示例*部分，我们看到了如何通过分叉存储库并发出拉取请求与其他开发人员合作。让我们看看如何进一步使用 Git 进行协作。

# 与 Git 协作

Git 是一种很棒的协作技术，而 GitHub 是一种非常有效的共同开发项目的方式。GitHub 为世界上任何有互联网访问权限的人提供了一个免费分享他们的想法和代码的地方。我们知道如何使用 Git 和一些基本的 GitHub 协作步骤，但是我们如何加入并为一个项目做出贡献呢？当然，我们想回馈给那些给予我们很多的开源项目，但是我们如何开始呢？

在本节中，我们将看一些关于使用 Git 和 GitHub 进行软件开发协作的要点：

+   **从小开始**：理解的最重要的事情之一是我们在团队中可以扮演的角色。我们可能擅长网络工程，但是 Python 开发水平一般。有很多事情我们可以做，不一定要成为高技能的开发者。不要害怕从小事做起，文档编写和测试是成为贡献者的好方法。

+   **学习生态系统**：对于任何项目，无论大小，都有一套已经建立的惯例和文化。我们都被 Python 的易于阅读的语法和初学者友好的文化所吸引；他们还有一个围绕这种意识形态的开发指南（[`devguide.python.org/`](https://devguide.python.org/)）。另一方面，Ansible 项目还有一个广泛的社区指南（[`docs.ansible.com/ansible/latest/community/index.html`](https://docs.ansible.com/ansible/latest/community/index.html)）。它包括行为准则、拉取请求流程、如何报告错误以及发布流程。阅读这些指南，了解感兴趣项目的生态系统。

+   **创建分支**：我犯了一个错误，分叉了一个项目并为主分支提出了拉取请求。主分支应该留给核心贡献者进行更改。我们应该为我们的贡献创建一个单独的分支，并允许在以后的某个日期合并该分支。

+   **保持分叉存储库同步**：一旦您分叉了一个项目，就没有规则强制克隆存储库与主存储库同步。我们应该定期执行`git pull`（获取代码并在本地合并）或`git fetch`（获取本地任何更改的代码）以确保我们拥有主存储库的最新副本。

+   **友善相处**：就像现实世界一样，虚拟世界也不容忍敌意。讨论问题时，要文明友好，即使意见不一致也是如此。

Git 和 GitHub 为任何有动力的个人提供了一种方式，使其易于在项目上进行协作，从而产生影响。我们都有能力为任何我们感兴趣的开源或私有项目做出贡献。

# 总结

在本章中，我们看了一下被称为 Git 的版本控制系统及其近亲 GitHub。Git 是由 Linus Torvolds 于 2005 年开发的，用于帮助开发 Linux 内核，后来被其他开源项目采用为源代码控制系统。Git 是一个快速、分布式和可扩展的系统。GitHub 提供了一个集中的位置在互联网上托管 Git 存储库，允许任何有互联网连接的人进行协作。

我们看了如何在命令行中使用 Git，以及它的各种操作，以及它们在 GitHub 中的应用。我们还研究了两个用于处理 Git 的流行 Python 库：GitPython 和 PyGitHub。我们以一个配置备份示例和关于项目协作的注释结束了本章。

在第十二章中，*使用 Jenkins 进行持续集成*，我们将看另一个流行的开源工具，用于持续集成和部署：Jenkins。
