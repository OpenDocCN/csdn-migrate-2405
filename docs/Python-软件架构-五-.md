# Python 软件架构（五）

> 原文：[`zh.annas-archive.org/md5/E8EC0BA674FAF6D2B8F974FE76F20D30`](https://zh.annas-archive.org/md5/E8EC0BA674FAF6D2B8F974FE76F20D30)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：Python - 架构模式

架构模式是软件模式体系中最高级别的模式。架构模式允许架构师指定应用程序的基本结构。为给定的软件问题选择的架构模式控制着其余的活动，例如所涉及系统的设计，系统不同部分之间的通信等等。

根据手头的问题，可以选择多种架构模式。不同的模式解决不同类或系列的问题，创造出自己的风格或架构类别。例如，某一类模式解决了客户端/服务器系统的架构，另一类模式帮助构建分布式系统，第三类模式帮助设计高度解耦的对等系统。

在本章中，我们将讨论并专注于 Python 世界中经常遇到的一些架构模式。我们在本章中的讨论模式将是采用一个众所周知的架构模式，并探索一个或两个实现它的流行软件应用程序或框架，或者它的变体。

在本章中，我们不会讨论大量的代码 - 代码的使用将仅限于那些绝对必要使用程序进行说明的模式。另一方面，大部分讨论将集中在架构细节，参与子系统，所选应用程序/框架实现的架构变化等方面。

我们可以研究任意数量的架构模式。在本章中，我们将重点关注 MVC 及其相关模式，事件驱动编程架构，微服务架构以及管道和过滤器。

在本章中，我们将涵盖以下主题：

+   介绍 MVC：

+   模型视图模板 - Django

+   Flask 微框架

+   事件驱动编程：

+   使用 select 的聊天服务器和客户端

+   事件驱动与并发编程

+   扭曲

扭曲聊天服务器和客户端

+   Eventlet

Eventlet 聊天服务器

+   Greenlets 和 gevent

Gevent 聊天服务器

+   微服务架构：

+   Python 中的微服务框架

+   微服务示例

+   微服务优势

+   管道和过滤器架构：

+   Python 中的管道和过滤器 - 示例

# 介绍 MVC

模型视图控制器或 MVC 是用于构建交互式应用程序的众所周知和流行的架构模式。MVC 将应用程序分为三个组件：模型，视图和控制器。

![介绍 MVC](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00489.jpeg)

模型-视图-控制器（MVC）架构

这三个组件执行以下职责：

+   **模型**：模型包含应用程序的核心数据和逻辑。

+   **视图**：视图形成应用程序向用户的输出。它们向用户显示信息。可以有同一数据的多个视图。

+   **控制器**：控制器接收和处理用户输入，如键盘点击或鼠标点击/移动，并将它们转换为对模型或视图的更改请求。

使用这三个组件分离关注避免了应用程序的数据和其表示之间的紧密耦合。它允许同一数据（模型）的多个表示（视图），可以根据通过控制器接收的用户输入进行计算和呈现。

MVC 模式允许以下交互：

1.  模型可以根据从控制器接收的输入更改其数据。

1.  更改的数据反映在视图上，这些视图订阅了模型的更改。

1.  控制器可以发送命令来更新模型的状态，例如在对文档进行更改时。控制器还可以发送命令来修改视图的呈现，而不对模型进行任何更改，例如放大图表或图表。

1.  MVC 模式隐含地包括一个变更传播机制，以通知其他依赖组件的变更。

1.  Python 世界中的许多 Web 应用程序实现了 MVC 或其变体。我们将在接下来的部分中看一些，即 Django 和 Flask。

## 模板视图（MTV） - Django

Django 项目是 Python 世界中最受欢迎的 Web 应用程序框架之一。Django 实现了类似 MVC 模式的东西，但有一些细微的差异。

Django（核心）组件架构如下图所示：

![Model Template View (MTV) – Django](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00490.jpeg)

Django 核心组件架构

Django 框架的核心组件如下：

+   对象关系映射器（ORM），充当数据模型（Python）和数据库（关系数据库管理系统）之间的中介 - 这可以被认为是模型层。

+   Python 中的一组回调函数，将数据呈现给特定 URL 的用户界面 - 这可以被认为是 VIEW 层。视图侧重于构建和转换内容，而不是实际呈现。

+   一组 HTML 模板，用于以不同的方式呈现内容。视图委托给特定模板，该模板负责数据的呈现方式。

+   基于正则表达式的 URL DISPATCHER，将服务器上的相对路径连接到特定视图及其变量参数。这可以被认为是一个基本的控制器。

+   在 Django 中，由于呈现是由 TEMPLATE 层执行的，而只有 VIEW 层执行内容映射，因此 Django 经常被描述为实现 Model Template View（MTV）框架。

+   Django 中的控制器并没有很好地定义 - 它可以被认为是整个框架本身 - 或者限于 URL DISPATCHER 层。

## Django admin - 自动化的模型中心视图

Django 框架最强大的组件之一是其自动管理员系统，它从 Django 模型中读取元数据，并生成快速的、以模型为中心的管理员视图，系统管理员可以通过简单的 HTML 表单查看和编辑数据模型。

为了说明，以下是一个描述将术语添加到网站作为“词汇”术语的 Django 模型的示例（词汇是描述与特定主题、文本或方言相关的词汇含义的列表或索引）：

```py
from django.db import models

class GlossaryTerm(models.Model):
    """ Model for describing a glossary word (term) """

    term = models.CharField(max_length=1024)
    meaning = models.CharField(max_length=1024)
    meaning_html = models.CharField('Meaning with HTML markup',
                    max_length=4096, null=True, blank=True)
    example = models.CharField(max_length=4096, null=True, blank=True)

    # can be a ManyToManyField?
    domains = models.CharField(max_length=128, null=True, blank=True)

    notes = models.CharField(max_length=2048, null=True, blank=True)
    url = models.CharField('URL', max_length=2048, null=True, blank=True)
    name = models.ForeignKey('GlossarySource', verbose_name='Source', blank=True)

    def __unicode__(self):
        return self.term

    class Meta:
        unique_together = ('term', 'meaning', 'url')
```

这与一个注册模型以获得自动化管理员视图的管理员系统相结合：

```py
from django.contrib import admin

admin.site.register(GlossaryTerm)
admin.site.register(GlossarySource)
```

以下是通过 Django admin 界面添加术语词汇的自动化管理员视图（HTML 表单）的图像：

![Django admin – automated model-centric views](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00491.jpeg)

Django 自动管理员视图（HTML 表单）用于添加词汇术语

快速观察告诉您 Django 管理员如何为模型中的不同数据字段生成正确的字段类型，并生成添加数据的表单。这是 Django 中的一个强大模式，允许您以几乎零编码工作量生成自动化的管理员视图以添加/编辑模型。

现在让我们来看另一个流行的 Python Web 应用程序框架，即 Flask。

## 灵活的微框架 - Flask

Flask 是一个微型 Web 框架，它使用了一种最小主义的哲学来构建 Web 应用程序。Flask 仅依赖于两个库：Werkzeug（[`werkzeug.pocoo.org/`](http://werkzeug.pocoo.org/)）WSGI 工具包和 Jinja2 模板框架。

Flask 通过装饰器提供了简单的 URL 路由。Flask 中的“微”一词表明框架的核心很小。对数据库、表单和其他功能的支持是由 Python 社区围绕 Flask 构建的多个扩展提供的。

因此，Flask 的核心可以被认为是一个 MTV 框架减去 M（视图模板），因为核心不实现对模型的支持。

以下是 Flask 组件架构的近似示意图：

![Flexible Microframework – Flask](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00492.jpeg)

Flask 组件的示意图

使用模板的简单 Flask 应用程序看起来是这样的：

```py
from flask import Flask
app = Flask(__name__)

@app.route('/')
def index():
    data = 'some data'
    return render_template('index.html', **locals())
```

我们可以在这里找到 MVC 模式的一些组件：

+   `@app.route`装饰器将浏览器的请求路由到`index`函数。应用程序路由器可以被视为控制器。

+   `index`函数返回数据，并使用模板进行渲染。`index`函数可以被视为生成视图或视图组件。

+   Flask 使用类似 Django 的模板来将内容与呈现分开。这可以被视为模板组件。

+   在 Flask 核心中没有特定的模型组件。但是，可以借助附加插件来添加模型组件。

+   Flask 使用插件架构来支持附加功能。例如，可以使用 Flask-SQLAlchemy 添加模型，使用 Flask-RESTful 支持 RESTful API，使用 Flask-marshmallow 进行序列化等。

# 事件驱动编程

事件驱动编程是一种系统架构范式，其中程序内部的逻辑流由事件驱动，例如用户操作、来自其他程序的消息或硬件（传感器）输入。

在事件驱动架构中，通常有一个主事件循环，它监听事件，然后在检测到事件时触发具有特定参数的回调函数。

在像 Linux 这样的现代操作系统中，对输入文件描述符（如套接字或已打开的文件）的事件的支持是通过系统调用（如`select`、`poll`和`epoll`）来实现的。

Python 通过其`select`模块提供了对这些系统调用的包装。使用`select`模块在 Python 中编写简单的事件驱动程序并不是很困难。

以下一组程序一起使用 Python 实现了基本的聊天服务器和客户端，利用了 select 模块的强大功能。

## 使用 select 模块进行 I/O 多路复用的聊天服务器和客户端

我们的聊天服务器使用`select`模块通过`select`系统调用来创建频道，客户端可以连接到这些频道并相互交谈。它处理输入准备好的事件（套接字）-如果事件是客户端连接到服务器，则连接并进行握手；如果事件是要从标准输入读取数据，则服务器读取数据，否则将从一个客户端接收到的数据传递给其他客户端。

这是我们的聊天服务器：

### 注意

由于聊天服务器的代码很大，我们只包含了主函数，即`serve`函数，显示服务器如何使用基于 select 的 I/O 多路复用。`serve`函数中的大量代码也已经被修剪，以保持打印的代码较小。

完整的源代码可以从本书的代码存档中下载，也可以从本书的网站上下载。

```py
# chatserver.py

import socket
import select
import signal
import sys
from communication import send, receive

class ChatServer(object):
    """ Simple chat server using select """

    def serve(self):
        inputs = [self.server,sys.stdin]
        self.outputs = []

        while True:

                inputready,outputready,exceptready = select.select(inputs, self.outputs, [])

            for s in inputready:

                if s == self.server:
                    # handle the server socket
                    client, address = self.server.accept()

                    # Read the login name
                    cname = receive(client).split('NAME: ')[1]

                    # Compute client name and send back
                    self.clients += 1
                    send(client, 'CLIENT: ' + str(address[0]))
                    inputs.append(client)

                    self.clientmap[client] = (address, cname)
                    self.outputs.append(client)

                elif s == sys.stdin:
                    # handle standard input – the server exits 
                    junk = sys.stdin.readline()
		  break
                else:
                    # handle all other sockets
                    try:
                        data = receive(s)
                        if data:
                            # Send as new client's message...
                            msg = '\n#[' + self.get_name(s) + ']>> ' + data
                            # Send data to all except ourselves
                            for o in self.outputs:
                                if o != s:
                                    send(o, msg)
                        else:
                            print('chatserver: %d hung up' % s.fileno())
                            self.clients -= 1
                            s.close()
                            inputs.remove(s)
                            self.outputs.remove(s)

                    except socket.error as e:
                        # Remove
                        inputs.remove(s)
                        self.outputs.remove(s)

        self.server.close()

if __name__ == "__main__":
    ChatServer().serve()
```

### 注意

通过发送一行空输入可以停止聊天服务器。

聊天客户端也使用`select`系统调用。它使用套接字连接到服务器，然后在套接字和标准输入上等待事件。如果事件来自标准输入，则读取数据。否则，它通过套接字将数据发送到服务器：

```py
# chatclient.py
import socket
import select
import sys
from communication import send, receive

class ChatClient(object):
    """ A simple command line chat client using select """

    def __init__(self, name, host='127.0.0.1', port=3490):
        self.name = name
        # Quit flag
        self.flag = False
        self.port = int(port)
        self.host = host
        # Initial prompt
        self.prompt='[' + '@'.join((name, socket.gethostname().split('.')[0])) + ']> '
        # Connect to server at port
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, self.port))
            print('Connected to chat server@%d' % self.port)
            # Send my name...
            send(self.sock,'NAME: ' + self.name) 
            data = receive(self.sock)
            # Contains client address, set it
            addr = data.split('CLIENT: ')[1]
            self.prompt = '[' + '@'.join((self.name, addr)) + ']> '
        except socket.error as e:
            print('Could not connect to chat server @%d' % self.port)
            sys.exit(1)

    def chat(self):
        """ Main chat method """

        while not self.flag:
            try:
                sys.stdout.write(self.prompt)
                sys.stdout.flush()

                # Wait for input from stdin & socket
                inputready, outputready,exceptrdy = select.select([0, self.sock], [],[])

                for i in inputready:
                    if i == 0:
                        data = sys.stdin.readline().strip()
                        if data: send(self.sock, data)
                    elif i == self.sock:
                        data = receive(self.sock)
                        if not data:
                            print('Shutting down.')
                            self.flag = True
                            break
                        else:
                            sys.stdout.write(data + '\n')
                            sys.stdout.flush()

            except KeyboardInterrupt:
                print('Interrupted.')
                self.sock.close()
                break

if __name__ == "__main__":
    if len(sys.argv)<3:
        sys.exit('Usage: %s chatid host portno' % sys.argv[0])

    client = ChatClient(sys.argv[1],sys.argv[2], int(sys.argv[3]))
    client.chat()
```

### 注意

聊天客户端可以通过在终端上按下*Ctrl* + *C*来停止。

为了通过套接字发送和接收数据，这两个脚本都使用了一个名为`communication`的第三方模块，该模块具有`send`和`receive`函数。该模块分别在`send`和`receive`函数中使用 pickle 对数据进行序列化和反序列化：

```py
# communication.py
import pickle
import socket
import struct

def send(channel, *args):
    """ Send a message to a channel """

    buf = pickle.dumps(args)
    value = socket.htonl(len(buf))
    size = struct.pack("L",value)
    channel.send(size)
    channel.send(buf)

def receive(channel):
    """ Receive a message from a channel """

    size = struct.calcsize("L")
    size = channel.recv(size)
    try:
        size = socket.ntohl(struct.unpack("L", size)[0])
    except struct.error as e:
        return ''

    buf = ""

    while len(buf) < size:
        buf = channel.recv(size - len(buf))

    return pickle.loads(buf)[0]
```

以下是服务器运行的一些图像，以及通过聊天服务器相互连接的两个客户端：

这是连接到聊天服务器的名为`andy`的客户端#1 的图像：

![使用 select 模块进行 I/O 多路复用的聊天服务器和客户端](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00493.jpeg)

聊天客户端#1 的聊天会话（客户端名称：andy）

同样，这是一个名为`betty`的客户端，它连接到聊天服务器并与`andy`进行交谈：

![使用 select 模块进行 I/O 多路复用的聊天服务器和客户端](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00494.jpeg)

聊天客户端#2 的聊天会话（客户端名称：betty）

程序的一些有趣点列举如下：

+   看看客户端是如何看到彼此的消息的。这是因为服务器将一个客户端发送的数据发送给所有其他连接的客户端。我们的聊天服务器使用井号`#`作为前缀来指示这条消息来自另一个客户端。

+   看看服务器是如何将客户端的连接和断开信息发送给所有其他客户端的。这通知了客户端另一个客户端何时连接到或从会话中断开。

+   服务器在客户端断开连接时会回显消息，表示客户端已经“挂断”：

### 注意

前面的聊天服务器和客户端示例是作者在 ASPN Cookbook 中的 Python 配方的一个小变化，网址为[`code.activestate.com/recipes/531824`](https://code.activestate.com/recipes/531824)。

像 Twisted、Eventlet 和 Gevent 这样的库将简单的基于 select 的多路复用提升到了下一个级别，以构建提供高级基于事件的编程例程的系统，通常基于类似于我们聊天服务器示例的核心事件循环的核心事件循环。

我们将在接下来的章节中讨论这些框架的架构。

## 事件驱动编程与并发编程

在前一节中我们看到的例子使用了异步事件的技术，正如我们在并发章节中看到的那样。这与真正的并发或并行编程是不同的。

事件编程库也使用了异步事件的技术。在其中只有一个执行线程，任务根据接收到的事件依次交错执行。

在下面的例子中，考虑通过三个线程或进程并行执行三个任务：

![事件驱动编程与并发编程](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00495.jpeg)

使用三个线程并行执行三个任务

与通过事件驱动编程执行任务时发生的情况形成对比，如下图所示：

![事件驱动编程与并发编程](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00496.jpeg)

在单个线程中异步执行三个任务

在异步模型中，只有一个单一的执行线程，任务以交错的方式执行。每个任务在异步处理服务器的事件循环中有自己的处理时间段，但在任何给定时间只有一个任务在执行。任务将控制权交还给循环，以便它可以在下一个时间片中安排一个不同的任务来执行当前正在执行的任务。正如我们在第五章中所看到的，“编写可扩展的应用程序”，这是一种协作式多任务处理。

## Twisted

Twisted 是一个事件驱动的网络引擎，支持多种协议，如 DNS、SMTP、POP3、IMAP 等。它还支持编写 SSH 客户端和服务器，并构建消息和 IRC 客户端和服务器。

Twisted 还提供了一组模式（风格）来编写常见的服务器和客户端，例如 Web 服务器/客户端（HTTP）、发布/订阅模式、消息客户端和服务器（SOAP/XML-RPC）等。

它使用了反应器设计模式，将来自多个来源的事件多路复用并分派给它们的事件处理程序在一个单线程中。

它接收来自多个并发客户端的消息、请求和连接，并使用事件处理程序顺序处理这些帖子，而无需并发线程或进程。

反应器伪代码大致如下：

```py
while True:
    timeout = time_until_next_timed_event()
    events = wait_for_events(timeout)
    events += timed_events_until(now())
    for event in events:
        event.process()
```

Twisted 使用回调来在事件发生时调用事件处理程序。为了处理特定事件，为该事件注册一个回调。回调可以用于常规处理，也可以用于管理异常（错误回调）。

与`asyncio`模块一样，Twisted 使用类似于 futures 的对象来包装任务执行的结果，其实际结果仍然不可用。在 Twisted 中，这些对象称为**Deferreds**。

延迟对象有一对回调链：一个用于处理结果（回调），另一个用于管理错误（errbacks）。当获得执行结果时，将创建一个延迟对象，并按照添加的顺序调用其回调和/或 errbacks。

以下是 Twisted 的架构图，显示了高级组件：

![Twisted](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00497.jpeg)

扭曲 - 核心组件

### Twisted - 一个简单的 Web 客户端

以下是使用 Twisted 的简单 Web HTTP 客户端的示例，获取给定 URL 并将其内容保存到特定文件名：

```py
# twisted_fetch_url.py
from twisted.internet import reactor
from twisted.web.client import getPage
import sys

def save_page(page, filename='content.html'):
    print type(page)
    open(filename,'w').write(page)
    print 'Length of data',len(page)
    print 'Data saved to',filename

def handle_error(error):
    print error

def finish_processing(value):
    print "Shutting down..."
    reactor.stop()

if __name__ == "__main__":
    url = sys.argv[1]
    deferred = getPage(url) 
    deferred.addCallbacks(save_page, handle_error)
    deferred.addBoth(finish_processing)

    reactor.run()
```

正如您在前面的代码中所看到的，`getPage`方法返回一个延迟对象，而不是 URL 的数据。对于延迟对象，我们添加了两个回调：一个用于处理数据（`save_page`函数），另一个用于处理错误（`handle_error`函数）。延迟的`addBoth`方法将一个函数添加为回调和 errback。

事件处理是通过运行反应器来启动的。在结束时调用`finish_processing`回调，停止反应器。由于事件处理程序是按添加顺序调用的，因此此函数只会在最后调用。

当反应器运行时，会发生以下事件：

+   页面被获取并创建了延迟。

+   回调按顺序在延迟上调用。首先调用`save_page`函数，将页面内容保存到`content.html`文件中。然后调用`handle_error`事件处理程序，打印任何错误字符串。

+   最后，调用`finish_processing`，停止反应器，事件处理结束，退出程序。

### 注意

在撰写本文时，Twisted 尚未适用于 Python3，因此前面的代码是针对 Python2 编写的。

+   当您运行代码时，您会看到产生以下输出：

```py
$ python2 twisted_fetch_url.py http://www.google.com
Length of data 13280
Data saved to content.html
Shutting down...
```

### 使用 Twisted 的聊天服务器

现在让我们看看如何在 Twisted 上编写一个简单的聊天服务器，类似于我们使用`select`模块的聊天服务器。

在 Twisted 中，服务器是通过实现协议和协议工厂来构建的。协议类通常继承自 Twisted 的`Protocol`类。

工厂只是作为协议对象的工厂模式的类。

使用这个，这是我们使用 Twisted 的聊天服务器：

```py
from twisted.internet import protocol, reactor

class Chat(protocol.Protocol):
    """ Chat protocol """

    transports = {}
    peers = {}

    def connectionMade(self):
        self._peer = self.transport.getPeer()
        print 'Connected',self._peer

    def connectionLost(self, reason):
        self._peer = self.transport.getPeer()
        # Find out and inform other clients
        user = self.peers.get((self._peer.host, self._peer.port))
        if user != None:
            self.broadcast('(User %s disconnected)\n' % user, user)
            print 'User %s disconnected from %s' % (user, self._peer)

    def broadcast(self, msg, user):
        """ Broadcast chat message to all connected users except 'user' """

        for key in self.transports.keys():
            if key != user:
                if msg != "<handshake>":
                    self.transports[key].write('#[' + user + "]>>> " + msg)
                else:
                    # Inform other clients of connection
                    self.transports[key].write('(User %s connected from %s)\n' % (user, self._peer))                

    def dataReceived(self, data):
        """ Callback when data is ready to be read from the socket """

        user, msg = data.split(":")
        print "Got data=>",msg,"from",user
        self.transports[user] = self.transport
        # Make an entry in the peers dictionary
        self.peers[(self._peer.host, self._peer.port)] = user
        self.broadcast(msg, user)

class ChatFactory(protocol.Factory):
    """ Chat protocol factory """

    def buildProtocol(self, addr):
        return Chat()

if __name__ == "__main__":
    reactor.listenTCP(3490, ChatFactory())
    reactor.run()
```

我们的聊天服务器比以前的更复杂，因为它执行以下附加步骤：

1.  它有一个单独的握手协议，使用特殊的`<handshake>`消息。

1.  当客户端连接时，会向其他客户端广播通知他们客户端的名称和连接详细信息。

1.  当客户端断开连接时，其他客户端会收到通知。

聊天客户端还使用 Twisted，并使用两个协议 - 分别是用于与服务器通信的`ChatClientProtocol`和用于从标准输入读取数据并将从服务器接收的数据回显到标准输出的`StdioClientProtocol`。

后一个协议还将前一个协议连接到其输入，以便将接收到的任何数据发送到服务器作为聊天消息。

看一下以下代码：

```py
import sys
import socket
from twisted.internet import stdio, reactor, protocol

class ChatProtocol(protocol.Protocol):
    """ Base protocol for chat """

    def __init__(self, client):
        self.output = None
        # Client name: E.g: andy
        self.client = client
        self.prompt='[' + '@'.join((self.client, socket.gethostname().split('.')[0])) + ']> '             

    def input_prompt(self):
        """ The input prefix for client """
        sys.stdout.write(self.prompt)
        sys.stdout.flush()

    def dataReceived(self, data):
        self.processData(data)

class ChatClientProtocol(ChatProtocol):
    """ Chat client protocol """

    def connectionMade(self):
        print 'Connection made'
        self.output.write(self.client + ":<handshake>")

    def processData(self, data):
        """ Process data received """

        if not len(data.strip()):
            return

        self.input_prompt()

        if self.output:
            # Send data in this form to server
            self.output.write(self.client + ":" + data)

class StdioClientProtocol(ChatProtocol):
    """ Protocol which reads data from input and echoes
    data to standard output """

    def connectionMade(self):
        # Create chat client protocol
        chat = ChatClientProtocol(client=sys.argv[1])
        chat.output = self.transport

        # Create stdio wrapper
        stdio_wrapper = stdio.StandardIO(chat)
        # Connect to output
        self.output = stdio_wrapper
        print "Connected to server"
        self.input_prompt()

    def input_prompt(self):
        # Since the output is directly connected
        # to stdout, use that to write.
        self.output.write(self.prompt)

    def processData(self, data):
        """ Process data received """

        if self.output:
            self.output.write('\n' + data)
            self.input_prompt()

class StdioClientFactory(protocol.ClientFactory):

    def buildProtocol(self, addr):
        return StdioClientProtocol(sys.argv[1])

def main():
    reactor.connectTCP("localhost", 3490, StdioClientFactory())
    reactor.run()

if __name__ == '__main__':
    main()

```

以下是两个客户端`andy`和`betty`使用这个聊天服务器和客户端进行通信的一些屏幕截图：

![使用 Twisted 的聊天服务器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00498.jpeg)

使用 Twisted 的聊天客户端 - 客户端＃1（andy）的会话

这是第二个会话，针对客户端 betty：

![使用 Twisted 的聊天服务器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00499.jpeg)

使用 Twisted 的聊天客户端 - 客户端＃2（betty）的会话

您可以通过交替查看屏幕截图来跟踪对话的流程。

请注意，服务器在用户 betty 连接和用户 andy 断开连接时发送的连接和断开连接消息。

## Eventlet

Eventlet 是 Python 世界中另一个知名的网络库，允许使用异步执行的概念编写事件驱动程序。

Eventlet 使用协程来执行这些任务，借助一组所谓的*绿色线程*，这些线程是轻量级的用户空间线程，执行协作式多任务。

Eventlet 使用一组绿色线程的抽象，`Greenpool`类，以执行其任务。

`Greenpool`类运行预定义的一组`Greenpool`线程（默认为`1000`），并提供不同方式将函数和可调用对象映射到线程的方法。

以下是使用 Eventlet 重写的多用户聊天服务器：

```py
# eventlet_chat.py

import eventlet
from eventlet.green import socket

participants = set()

def new_chat_channel(conn):
    """ New chat channel for a given connection """

    data = conn.recv(1024)
    user = ''

    while data:
        print("Chat:", data.strip())
        for p in participants:
            try:
                if p is not conn:
                    data = data.decode('utf-8')
                    user, msg = data.split(':')
                    if msg != '<handshake>':
                        data_s = '\n#[' + user + ']>>> says ' + msg
                    else:
                        data_s = '(User %s connected)\n' % user

                    p.send(bytearray(data_s, 'utf-8'))
            except socket.error as e:
                # ignore broken pipes, they just mean the participant
                # closed its connection already
                if e[0] != 32:
                    raise
        data = conn.recv(1024)

    participants.remove(conn)
    print("Participant %s left chat." % user)

if __name__ == "__main__":
    port = 3490
    try:
        print("ChatServer starting up on port", port)
        server = eventlet.listen(('0.0.0.0', port))

        while True:
            new_connection, address = server.accept()
            print("Participant joined chat.")
            participants.add(new_connection)
            print(eventlet.spawn(new_chat_channel,
                                 new_connection))

    except (KeyboardInterrupt, SystemExit):
        print("ChatServer exiting.")
```

### 注意

这个服务器可以与我们在之前示例中看到的 Twisted 聊天客户端一起使用，并且行为完全相同。因此，我们不会展示此服务器的运行示例。

Eventlet 库在内部使用`greenlets`，这是一个在 Python 运行时上提供绿色线程的包。我们将在下一节中看到 greenlet 和一个相关库 Gevent。

## Greenlets 和 Gevent

Greenlet 是一个在 Python 解释器之上提供绿色或微线程版本的包。它受 Stackless 的启发，Stackless 是支持称为 stacklets 的微线程的 CPython 的一个版本。然而，greenlets 能够在标准 CPython 运行时上运行。

Gevent 是一个 Python 网络库，提供在 C 语言编写的`libev`之上的高级同步 API。

Gevent 受到 gevent 的启发，但它具有更一致的 API 和更好的性能。

与 Eventlet 一样，gevent 对系统库进行了大量的猴子补丁，以提供协作式多任务支持。例如，gevent 自带自己的套接字，就像 Eventlet 一样。

与 Eventlet 不同，gevent 还需要程序员显式进行猴子补丁。它提供了在模块本身上执行此操作的方法。

话不多说，让我们看看使用 gevent 的多用户聊天服务器是什么样子的：

```py
# gevent_chat_server.py

import gevent
from gevent import monkey
from gevent import socket
from gevent.server import StreamServer

monkey.patch_all()

participants = set()

def new_chat_channel(conn, address):
    """ New chat channel for a given connection """

    participants.add(conn)
    data = conn.recv(1024)
    user = ''

    while data:
        print("Chat:", data.strip())
        for p in participants:
            try:
                if p is not conn:
                    data = data.decode('utf-8')
                    user, msg = data.split(':')
                    if msg != '<handshake>':
                        data_s = '\n#[' + user + ']>>> says ' + msg
                    else:
                        data_s = '(User %s connected)\n' % user

                    p.send(bytearray(data_s, 'utf-8'))                  
            except socket.error as e:
                # ignore broken pipes, they just mean the participant
                # closed its connection already
                if e[0] != 32:
                    raise
        data = conn.recv(1024)

    participants.remove(conn)
    print("Participant %s left chat." % user)

if __name__ == "__main__":
    port = 3490
    try:
        print("ChatServer starting up on port", port)
        server = StreamServer(('0.0.0.0', port), new_chat_channel)
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        print("ChatServer exiting.")
```

基于 gevent 的聊天服务器的代码几乎与使用 Eventlet 的代码相同。原因是它们都通过在建立新连接时将控制权交给回调函数的方式以非常相似的方式工作。在这两种情况下，回调函数的名称都是`new_chat_channel`，具有相同的功能，因此代码非常相似。

两者之间的区别如下：

+   gevent 提供了自己的 TCP 服务器类——`StreamingServer`，因此我们使用它来代替直接监听模块

+   在 gevent 服务器中，对于每个连接，都会调用`new_chat_channel`处理程序，因此参与者集合在那里进行管理

+   由于 gevent 服务器有自己的事件循环，因此无需创建用于监听传入连接的 while 循环，就像我们在 Eventlet 中所做的那样

这个示例与之前的示例完全相同，并且与 Twisted 聊天客户端一起使用。

# 微服务架构

微服务架构是开发单个应用程序的一种架构风格，将其作为一套小型独立服务运行，每个服务在自己的进程中运行，并通过轻量级机制进行通信，通常使用 HTTP 协议。

微服务是独立部署的组件，通常没有或者只有极少的中央管理或配置。

微服务可以被视为**面向服务的架构**（**SOA**）的特定实现风格，其中应用程序不是自上而下构建为单体应用程序，而是构建为相互交互的独立服务的动态组。

传统上，企业应用程序是以单块模式构建的，通常由这三个层组成：

1.  由 HTML 和 JavaScript 组成的客户端用户界面（UI）层。

1.  由业务逻辑组成的服务器端应用程序。

1.  数据库和数据访问层，保存业务数据。

另一方面，微服务架构将这一层拆分为多个服务。例如，业务逻辑不再在单个应用程序中，而是拆分为多个组件服务，它们的交互定义了应用程序内部的逻辑流程。这些服务可能查询单个数据库或独立的本地数据库，后者的配置更常见。

微服务架构中的数据通常以文档对象的形式进行处理和返回 - 通常以 JSON 编码。

以下示意图说明了单体架构与微服务架构的区别：

![微服务架构](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00500.jpeg)

单体架构（左）与微服务架构（右）

## Python 中的微服务框架

由于微服务更多地是一种哲学或架构风格，没有明确的软件框架类别可以说是它们的最佳选择。然而，人们仍然可以对框架应该具有的属性做出一些合理的预测，以便为在 Python 中构建 Web 应用程序的微服务架构选择一个好的框架。这些属性包括以下内容：

+   组件架构应该是灵活的。框架不应该在规定使系统的不同部分工作的组件选择方面变得死板。

+   框架的核心应该是轻量级的。这是有道理的，因为如果我们从头开始，比如说，微服务框架本身有很多依赖，软件在一开始就会感觉很沉重。这可能会导致部署、测试等方面出现问题。

+   框架应该支持零或最小化配置。微服务架构通常是自动配置的（零配置）或具有一组最小配置输入，这些输入在一个地方可用。通常，配置本身作为微服务可供其他服务查询，并使配置共享变得简单、一致和可扩展。

+   它应该非常容易将现有的业务逻辑，比如编码为类或函数的业务逻辑，转换为 HTTP 或 RCP 服务。这允许代码的重用和智能重构。

如果您遵循这些原则并在 Python 软件生态系统中寻找，您会发现一些 Web 应用程序框架符合要求，而另一些则不符合。

例如，Flask 及其单文件对应物 Bottle 由于其最小的占用空间、小的核心和简单的配置，是微服务框架的良好选择。

Pyramid 等框架也可以用于微服务架构，因为它促进了组件选择的灵活性，并避免了紧密集成。

像 Django 这样更复杂的 Web 框架由于正好相反的原因 - 组件的紧密垂直集成、在选择组件方面缺乏灵活性、复杂的配置等等，因此不适合作为微服务框架的选择。

另一个专门用于在 Python 中实现微服务的框架是 Nameko。Nameko 旨在测试应用程序，并提供对不同通信协议的支持，如 HTTP、RPC（通过 AMQP）- 发布-订阅系统和定时器服务。

我们不会详细介绍这些框架。另一方面，我们将看一下如何使用微服务来设计和构建一个真实的 Web 应用程序示例。

## 微服务示例 - 餐厅预订

让我们以一个 Python Web 应用程序的真实例子为例，尝试将其设计为一组微服务。

我们的应用是一个餐厅预订应用程序，帮助用户在靠近他们当前位置的餐厅预订特定时间的一定人数。假设预订只能在同一天进行。

应用程序需要执行以下操作：

1.  返回在用户想要进行预订的时间营业的餐厅列表。

1.  对于给定的餐厅，返回足够的元信息，如菜肴选择、评分、定价等，并允许用户根据其标准筛选酒店。

1.  一旦用户做出选择，允许他们为选定的餐厅预订一定数量的座位，预订时间。

这些要求中的每一个都足够细粒度，可以拥有自己的微服务。

因此，我们的应用程序将设计为以下一组微服务：

+   使用用户的位置，并返回一份营业中的餐厅列表，并支持在线预订 API 的服务。

+   第二个服务根据餐厅 ID 检索给定酒店的元数据。应用程序可以使用此元数据与用户的标准进行比较，以查看是否匹配。

+   第三个服务，根据餐厅 ID、用户信息、所需座位数和预订时间，使用预订 API 进行座位预订，并返回状态。

应用程序逻辑的核心部分现在适合这三个微服务。一旦它们被实现，调用这些服务并执行预订的管道将直接发生在应用程序逻辑中。

我们不会展示此应用程序的任何代码，因为那是一个独立的项目，但我们将向读者展示微服务的 API 和返回数据是什么样子的。

![微服务示例-餐厅预订](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00501.jpeg)

使用微服务的餐厅预订应用程序架构

微服务通常以 JSON 形式返回数据。例如，我们的第一个返回餐厅列表的服务将返回类似于以下内容的 JSON：

```py
GET /restaurants?geohash=tdr1y1g1zgzc

{
    "8f95e6ad-17a7-48a9-9f82-07972d2bc660": {
        "name": "Tandoor",
        "address": "Centenary building, #28, MG Road b-01"
        "hours": "12.00 – 23.30"
	},
  "4307a4b1-6f35-481b-915b-c57d2d625e93": {
        "name": "Karavalli",
        "address": "The Gateway Hotel, 66, Ground Floor"
        "hours": "12.30 – 01:00"
	},
   ...
} 
```

返回餐厅元数据的第二个服务，大多会返回类似于以下内容的 JSON：

```py
GET /restaurants/8f95e6ad-17a7-48a9-9f82-07972d2bc660

{

   "name": "Tandoor",
   "address": "Centenary building, #28, MG Road b-01"
   "hours": "12.00 – 23.30",
   "rating": 4.5,
   "cuisine": "north indian",
   "lunch buffet": "no",
   "dinner buffet": "no",
   "price": 800

} 
```

这是第三个互动，根据餐厅 ID 进行预订：

由于此服务需要用户提供预订信息，因此需要一个包含预订详细信息的 JSON 有效负载。因此，最好以 HTTP POST 调用进行。

```py
POST  /restaurants/reserve
```

在这种情况下，该服务将使用以下给定的有效负载作为 POST 数据：

```py
{
   "name": "Anand B Pillai",
   "phone": 9880078014,
   "time": "2017-04-14 20:40:00",
   "seats": 3,
   "id": "8f95e6ad-17a7-48a9-9f82-07972d2bc660"
} 

```

它将返回类似于以下内容的 JSON 作为响应：

```py
{
   "status": "confirmed",
   "code": "WJ7D2B",
   "time": "2017-04-14 20:40:00",
   "seats": 3
}
```

有了这样的设计，很容易在您选择的框架中实现应用程序，无论是 Flask、Bottle、Nameko 还是其他任何东西。

## 微服务-优势

那么使用微服务而不是单体应用程序有哪些优势呢？让我们看看其中一些重要的优势：

+   微服务通过将应用程序逻辑拆分为多个服务来增强关注点分离。这提高了内聚性，减少了耦合。由于业务逻辑不在一个地方，因此无需对系统进行自上而下的预先设计。相反，架构师可以专注于微服务和应用程序之间的相互作用和通信，让微服务的设计和架构通过重构逐步出现。

+   微服务改善了可测试性，因为现在逻辑的每个部分都可以作为独立的服务进行独立测试，因此很容易与其他部分隔离并进行测试。

+   团队可以围绕业务能力而不是应用程序或技术层的层次进行组织。由于每个微服务都包括逻辑、数据和部署，使用微服务的公司鼓励跨功能角色。这有助于构建更具敏捷性的组织。

+   微服务鼓励去中心化数据。通常，每个服务都将拥有自己的本地数据库或数据存储，而不是单体应用程序所偏爱的中央数据库。

+   微服务促进了持续交付和集成，以及快速部署。由于对业务逻辑的更改通常只需要对一个或几个服务进行小的更改，因此测试和重新部署通常可以在紧密的周期内完成，并且在大多数情况下可以完全自动化。

# 管道和过滤器架构

管道和过滤器是一种简单的架构风格，它连接了一些处理数据流的组件，每个组件通过**管道**连接到处理管道中的下一个组件。

管道和过滤器架构受到了 Unix 技术的启发，该技术通过 shell 上的管道将一个应用程序的输出连接到另一个应用程序的输入。

管道和过滤器架构由一个或多个数据源组成。数据源通过管道连接到数据过滤器。过滤器处理它们接收到的数据，并将它们传递给管道中的其他过滤器。最终的数据接收到一个**数据接收器**：

![管道和过滤器架构](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00502.jpeg)

管道和过滤器架构

管道和过滤器通常用于执行大量数据处理的应用程序，如数据分析、数据转换、元数据提取等。

过滤器可以在同一台机器上运行，并且它们使用实际的 Unix 管道或共享内存进行通信。然而，在大型系统中，这些通常在单独的机器上运行，管道不需要是实际的管道，而可以是任何类型的数据通道，如套接字、共享内存、队列等。

可以连接多个过滤器管道以执行复杂的数据处理和数据分段。

一个很好的使用这种架构的 Linux 应用程序的例子是`gstreamer`——这是一个多媒体处理库，可以对多媒体视频和音频执行多项任务，包括播放、录制、编辑和流式传输。

## Python 中的管道和过滤器

在 Python 中，我们在多进程模块中以最纯粹的形式遇到管道。多进程模块提供了管道作为一种从一个进程到另一个进程进行通信的方式。

创建一个父子连接对的管道。在连接的一侧写入的内容可以在另一侧读取，反之亦然。

这使我们能够构建非常简单的数据处理管道。

例如，在 Linux 上，可以通过以下一系列命令计算文件中的单词数：

```py
$ cat filename | wc -w

```

我们将使用多进程模块编写一个简单的程序，模拟这个管道：

```py
# pipe_words.py
from multiprocessing import Process, Pipe
import sys

def read(filename, conn):
    """ Read data from a file and send it to a pipe """

    conn.send(open(filename).read())

def words(conn):
    """ Read data from a connection and print number of words """

    data = conn.recv()
    print('Words',len(data.split()))

if __name__ == "__main__":
    parent, child = Pipe()
    p1 = Process(target=read, args=(sys.argv[1], child))
    p1.start()
    p2 = Process(target=words, args=(parent,))
    p2.start()
    p1.join();p2.join()
```

以下是工作流程的分析：

1.  创建了一个管道，并获得了两个连接。

1.  `read`函数作为一个进程执行，传递管道的一端（子进程）和要读取的文件名。

1.  该进程读取文件，将数据写入连接。

1.  `words`函数作为第二个进程执行，将管道的另一端传递给它。

1.  当此函数作为一个进程执行时，它从连接中读取数据，并打印单词的数量。

以下屏幕截图显示了相同文件上的 shell 命令和前面程序的输出：

![Python 中的管道和过滤器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00503.jpeg)

使用管道和其等效的 Python 程序的 shell 命令的输出

您不需要使用看起来像实际管道的对象来创建管道。另一方面，Python 中的生成器提供了一个很好的方式来创建一组可调用对象，它们相互调用，消耗和处理彼此的数据，产生数据处理的管道。

以下是与前一个示例相同的示例，重写为使用生成器，并且这次是处理文件夹中匹配特定模式的所有文件：

```py
# pipe_words_gen.py

# A simple data processing pipeline using generators
# to print count of words in files matching a pattern.
import os

def read(filenames):
    """ Generator that yields data from filenames as (filename, data) tuple """

    for filename in filenames:
        yield filename, open(filename).read()

def words(input):
    """ Generator that calculates words in its input """

    for filename, data in input:
        yield filename, len(data.split())

def filter(input, pattern):
    """ Filter input stream according to a pattern """

    for item in input:
        if item.endswith(pattern):
            yield item

if __name__ == "__main__":
    # Source
    stream1 = filter(os.listdir('.'), '.py')
    # Piped to next filter
    stream2 = read(stream1)
    # Piped to last filter (sink)
    stream3 = words(stream2)

    for item in stream3:
        print(item)
```

以下是输出的屏幕截图：

![Python 中的管道和过滤器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00504.jpeg)

使用生成器输出管道的输出，打印 Python 程序的单词计数

### 注意

可以使用以下命令验证类似于前面程序的输出：

```py
$ wc -w *.py

```

这是另一个程序，它使用另外两个数据过滤生成器来构建一个程序，该程序监视与特定模式匹配的文件并打印有关最近文件的信息，类似于 Linux 上的 watch 程序所做的事情：

```py
# pipe_recent_gen.py
# Using generators, print details of the most recently modified file
# matching a pattern.

import glob
import os
from time import sleep

def watch(pattern):
    """ Watch a folder for modified files matching a pattern """

    while True:
        files = glob.glob(pattern)
        # sort by modified time
        files = sorted(files, key=os.path.getmtime)
        recent = files[-1]
        yield recent        
        # Sleep a bit
        sleep(1)

def get(input):
    """ For a given file input, print its meta data """
    for item in input:
        data = os.popen("ls -lh " + item).read()
        # Clear screen
        os.system("clear")
        yield data

if __name__ == "__main__":
    import sys

    # Source + Filter #1
    stream1 = watch('*.' + sys.argv[1])

    while True:
        # Filter #2 + sink
        stream2 = get(stream1)
        print(stream2.__next__())
        sleep(2)
```

这个最后一个程序的细节应该对读者是不言自明的。

这是我们在控制台上程序的输出，监视 Python 源文件：

![Python 中的管道和过滤器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00505.jpeg)

监视最近修改的 Python 源文件的程序输出

如果我们创建一个空的 Python 源文件，比如`example.py`，两秒后输出会发生变化：

![Python 中的管道和过滤器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00506.jpeg)

监视程序更改的输出，始终显示最近修改的文件

使用生成器（协程）构建这样的管道的基本技术是将一个生成器的输出连接到下一个生成器的输入。通过在系列中连接许多这样的生成器，可以构建从简单到复杂的数据处理管道。

当然，除了这些之外，我们还可以使用许多技术来构建管道。一些常见的选择是使用队列连接的生产者-消费者任务，可以使用线程或进程。我们在可扩展性章节中看到了这方面的例子。

微服务还可以通过将一个微服务的输入连接到另一个微服务的输出来构建简单的处理管道。

在 Python 第三方软件生态系统中，有许多模块和框架可以让您构建复杂的数据管道。Celery 虽然是一个任务队列，但可以用于构建具有有限管道支持的简单批处理工作流。管道不是 Celery 的强项，但它对于链接任务具有有限的支持，可以用于此目的。

Luigi 是另一个强大的框架，专为需要管道和过滤器架构的复杂、长时间运行的批处理作业而编写。Luigi 具有内置的支持 Hadoop 作业的功能，因此它是构建数据分析管道的良好选择。

# 总结

在本章中，我们看了一些构建软件的常见架构模式。我们从模型视图控制器架构开始，并在 Django 和 Flask 中看了一些例子。您了解了 MVC 架构的组件，并了解到 Django 使用模板实现了 MVC 的变体。

我们以 Flask 作为一个微框架的例子，它通过使用插件架构实现了 Web 应用程序的最小占地面积，并可以添加额外的服务。

我们继续讨论事件驱动的编程架构，这是一种使用协程和事件的异步编程。我们从一个在 Python 中使用`select`模块的多用户聊天示例开始。然后，我们继续讨论更大的框架和库。

我们讨论了 Twisted 的架构和其组件。我们还讨论了 Eventlet 及其近亲 gevent。对于这些框架，我们看到了多用户聊天服务器的实现。

接下来，我们以微服务作为架构，通过将核心业务逻辑分割到多个服务中来构建可扩展的服务和部署。我们设计了一个使用微服务的餐厅预订应用程序的示例，并简要介绍了可以用于构建微服务的 Python Web 框架的情况。

在本章的最后，我们看到了使用管道和过滤器进行串行和可扩展数据处理的架构。我们使用 Python 中的多进程模块构建了一个实际管道的简单示例，模仿了 Unix 的管道命令。然后，我们看了使用生成器构建管道的技术，并看了一些例子。我们总结了构建管道和 Python 第三方软件生态系统中可用框架的技术。

这就是应用架构章节的结束。在下一章中，我们将讨论可部署性-即将软件部署到生产系统等环境的方面。


# 第九章：部署 Python 应用程序

将代码推送到生产环境通常是将应用程序从开发环境带给客户的最后一步。尽管这是一项重要的活动，但在软件架构师的检查表中往往被忽视。

假设如果系统在开发环境中运行良好，它也会在生产环境中忠实地运行是一个非常常见且致命的错误。首先，生产系统的配置通常与开发环境大不相同。在开发人员的环境中可以使用和理所当然的许多优化和调试，在生产设置中通常是不可用的。

部署到生产环境是一门艺术，而不是一门精确的科学。系统部署的复杂性取决于许多因素，例如系统开发的语言、运行时可移植性和性能、配置参数的数量、系统是在同质环境还是异质环境中部署、二进制依赖关系、部署的地理分布、部署自动化工具等等。

近年来，作为一种开源语言，Python 在为生产系统部署软件包提供的自动化和支持水平上已经成熟。凭借其丰富的内置和第三方支持工具，生产部署和保持部署系统最新的痛苦和麻烦已经减少。

在本章中，我们将简要讨论可部署系统和可部署性的概念。我们将花一些时间了解 Python 应用程序的部署，以及架构师可以添加到其工具库中的工具和流程，以便轻松部署和维护使用 Python 编写的生产系统运行的应用程序。我们还将探讨架构师可以采用的技术和最佳实践，以使其生产系统在没有频繁停机的情况下健康安全地运行。

本章我们将讨论的主题列表如下。

+   可部署性

+   影响可部署性的因素

+   软件部署架构的层次

+   Python 中的软件部署

+   打包 Python 代码

Pip

Virtualenv

Virtualenv 和 Pip

PyPI- Python 软件包索引

应用程序的打包和提交

PyPA

+   使用 Fabric 进行远程部署

+   使用 Ansible 进行远程部署

+   使用 Supervisor 管理远程守护程序

+   部署-模式和最佳实践

# 可部署性

软件系统的可部署性是指将其从开发环境部署到生产环境的便捷程度。它可以根据部署代码所需的工作量（以人时计）或部署代码所需的不同步骤的数量来衡量其复杂性。

常见的错误是假设在开发或暂存系统中运行良好的代码在生产系统中会以类似的方式运行。由于生产系统与开发系统相比具有截然不同的要求，这种情况并不经常发生。

## 影响可部署性的因素

以下是一些区分生产系统和开发系统的因素的简要介绍，这些因素通常会导致部署中出现意外问题，从而导致*生产陷阱*：

+   **优化和调试**：在开发系统中关闭代码优化是非常常见的。

如果您的代码在像 Python 这样的解释运行时中运行，通常会打开调试配置，这允许程序员在发生异常时生成大量的回溯。此外，通常会关闭任何 Python 解释器优化。

另一方面，在生产系统中，情况正好相反 - 优化被打开，调试被关闭。这通常需要额外的配置才能使代码以类似的方式工作。也有可能（虽然很少）在某些情况下，程序在优化后的行为与在未经优化时运行时的行为不同。

+   **依赖项和版本**：开发环境通常具有丰富的开发和支持库的安装，用于运行开发人员可能正在开发的多个应用程序。这些通常是开发人员经常使用的最新代码的依赖项。

生产系统，另一方面，需要使用预先编译的依赖项及其版本的列表进行精心准备。通常只指定成熟或稳定的版本用于在生产系统上部署是非常常见的。因此，如果开发人员依赖于下游依赖项的不稳定（alpha、beta 或发布候选）版本上可用的功能或错误修复，可能会发现 - 太迟了 - 该功能在生产中无法按预期工作。

另一个常见的问题是未记录的依赖项或需要从源代码编译的依赖项 - 这通常是首次部署时的问题。

+   **资源配置和访问权限**：开发系统和生产系统在本地和网络资源的级别、权限和访问细节上通常有所不同。开发系统可能有一个本地数据库，而生产系统往往会为应用程序和数据库系统使用单独的托管。开发系统可能使用标准配置文件，而在生产中，配置可能需要使用特定脚本专门为主机或环境生成。同样，在生产中，可能需要以较低的权限作为特定用户/组运行应用程序，而在开发中，通常会以 root 或超级用户身份运行程序。用户权限和配置上的差异可能影响资源访问，并可能导致软件在生产中失败，而在开发环境中正常运行。

+   **异构的生产环境**：代码通常是在通常是同质的开发环境中开发的。但通常需要在生产中部署到异构系统上。例如，软件可能在 Linux 上开发，但可能需要在 Windows 上进行客户部署。

部署的复杂性与环境的异质性成正比增加。在将此类代码带入生产之前，需要良好管理的分级和测试环境。此外，异构系统使依赖管理变得更加复杂，因为需要为每个目标系统架构维护一个单独的依赖项列表。

+   **安全性**：在开发和测试环境中，通常会对安全性方面给予宽容以节省时间并减少测试的配置复杂性。例如，在 Web 应用程序中，需要登录的路由可能会使用特殊的开发环境标志来禁用，以便快速编程和测试。

同样，在开发环境中使用的系统可能经常使用易于猜测的密码，例如数据库系统、Web 应用程序登录等，以便轻松进行常规回忆和使用。此外，可能会忽略基于角色的授权以便进行测试。

然而，在生产中安全性至关重要，因此这些方面需要相反的处理。需要强制执行需要登录的路由。应该使用强密码。需要强制执行基于角色的身份验证。这些通常会在生产中引起微妙的错误，即在开发环境中正常工作的功能在生产中失败。

由于这些以及其他类似的问题是在生产中部署代码的困扰，已经定义了标准的实践方法，以使运维从业者的生活变得稍微容易一些。大多数公司都遵循使用隔离环境来开发、测试和验证代码和应用程序，然后再将它们推送到生产的做法。让我们来看一下。

# 软件部署架构的层

为了避免在从开发到测试，再到生产的过程中出现复杂性，通常在应用程序部署到生产之前的每个阶段使用多层架构是很常见的。

让我们来看一下以下一些常见的部署层：

+   **开发/测试/阶段/生产**：这是传统的四层架构。

+   开发人员将他们的代码推送到开发环境，进行单元测试和开发人员测试。这个环境总是处于最新的代码状态。很多时候这个环境会被跳过，用开发人员的笔记本电脑上的本地设置替代。

+   然后，软件由测试工程师在测试环境中使用黑盒技术进行测试。他们也可能在这个环境上运行性能测试。这个环境在代码更新方面总是落后于开发环境。通常，内部发布、标签或**代码转储**用于将 QA 环境与开发环境同步。

+   阶段环境试图尽可能地模拟生产环境。这是*预生产*阶段，在这个环境中，软件在尽可能接近部署环境的环境中进行测试，以提前发现可能在生产中出现的问题。这个环境通常用于运行压力测试或负载测试。它还允许运维工程师测试他的部署自动化脚本、定时作业，并验证系统配置。

+   生产环境当然是最终的阶段，经过阶段测试的软件被推送和部署。许多部署通常使用相同的阶段/生产阶段，并且只是从一个切换到另一个。

+   **开发和测试/阶段/生产**：这是前一个层的变体，其中开发环境也兼具测试环境的双重职责。这种系统用于采用敏捷软件开发实践的公司，其中代码至少每周推送一次到生产环境，没有空间或时间来保留和管理一个单独的测试环境。当没有单独的开发环境时——即开发人员使用他们的笔记本电脑进行编程时——测试环境也是一个本地环境。

+   **开发和测试/阶段和生产**：在这种设置中，阶段和生产环境完全相同，使用多个服务器。一旦系统在阶段中经过测试和验证，它就会通过简单地切换主机被推送到生产环境——当前的生产系统切换到阶段，阶段切换到生产。

除此之外，还可以有更复杂的架构，其中使用一个单独的**集成**环境进行集成测试，一个**沙盒**环境用于测试实验性功能，等等。

使用分阶段系统对确保软件在类生产环境中经过充分测试和协调后再推送代码到生产环境是很重要的。

# Python 中的软件部署

正如前面提到的，Python 开发人员在 Python 提供的各种工具以及第三方生态系统中，可以轻松自动化地部署使用 Python 编写的应用程序和代码。

在这一部分，我们将简要地看一下其中一些工具。

## 打包 Python 代码

Python 内置支持为各种分发打包应用程序——源代码、二进制和特定的操作系统级打包。

在 Python 中打包源代码的主要方式是编写一个`setup.py`文件。然后可以借助内置的`distutils`库或更复杂、丰富的`setuptools`框架来打包源代码。

在我们开始了解 Python 打包的内部机制之前，让我们先熟悉一下几个相关的工具，即`pip`和`virtualenv`。

## Pip

Pip 是**Pip installs packages**的递归缩写。Pip 是 Python 中安装软件包的标准和建议工具。

在本书中我们一直看到 pip 在工作，但到目前为止，我们从未看到 pip 本身被安装过，对吧？

让我们在以下截图中看到这一点：

![Pip](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00507.jpeg)

下载并安装 Python3 的 pip

pip 安装脚本可在[`bootstrap.pypa.io/get-pip.py`](https://bootstrap.pypa.io/get-pip.py)找到。

这些步骤应该是不言自明的。

### 注意

在上面的例子中，已经有一个 pip 版本，所以这个操作是升级现有版本，而不是进行全新安装。我们可以通过使用`–version`选项来尝试程序来查看版本详细信息，如下所示：

看一下以下截图：

![Pip](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00508.jpeg)

打印当前 pip 版本（pip3）

看到 pip 清楚地打印出其版本号以及安装的目录位置，以及其所安装的 Python 版本。

### 注意

要区分 Python2 和 Python3 版本的 pip，记住为 Python3 安装的版本始终命名为`pip3`。Python2 版本是`pip2`，或者只是`pip`。

使用 pip 安装软件包，只需通过`install`命令提供软件包名称即可。例如，以下截图显示了使用`pip`安装`numpy`软件包：

![Pip](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00509.jpeg)

我们不会在这里进一步讨论使用 pip 的细节。相反，让我们来看看另一个与 pip 密切相关的工具，它用于安装 Python 软件。

## Virtualenv

Virtualenv 是一个允许开发人员为本地开发创建沙盒式 Python 环境的工具。假设您想要为同时开发的两个不同应用程序维护特定库或框架的两个不同版本。

如果要将所有内容安装到系统 Python 中，那么您一次只能保留一个版本。另一个选项是在不同的根文件夹中创建不同的系统 Python 安装——比如`/opt`而不是`/usr`。然而，这会带来额外的开销和路径管理方面的麻烦。而且，如果您希望在没有超级用户权限的共享主机上维护版本依赖关系，那么您将无法获得对这些文件夹的写入权限。

Virtualenv 解决了权限和版本问题。它创建一个带有自己的 Python 可执行标准库和安装程序（默认为 pip）的本地安装目录。

一旦开发人员激活了这样创建的虚拟环境，任何进一步的安装都会进入这个环境，而不是系统 Python 环境。

可以使用 pip 来安装 Virtualenv。

以下截图显示了使用`virtualenv`命令创建名为`appvenv`的虚拟环境，并激活该环境以及在环境中安装软件包。

### 注意

安装还会安装 pip、setuptools 和其他依赖项。

![Virtualenv](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00510.jpeg)

### 注意

看到`python`和`pip`命令指向虚拟环境内部的命令。`pip –version`命令清楚地显示了虚拟环境文件夹内`pip`的路径。

从 Python 3.3 开始，对虚拟环境的支持已经内置到 Python 安装中，通过新的`venv`库。

以下截图显示了在 Python 3.5 中使用该库安装虚拟环境，并在其中安装一些软件包。像往常一样，查看 Python 和 pip 可执行文件的路径：

![Virtualenv](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00511.jpeg)

### 注意

上述屏幕截图还显示了如何通过`pip`命令升级 pip 本身。

## Virtualenv 和 pip

一旦为您的应用程序设置了虚拟环境并安装了所需的软件包，最好生成依赖项及其版本。可以通过以下命令轻松完成：

```py
$ pip freeze

```

此命令要求 pip 输出所有已安装的 Python 软件包及其版本的列表。这可以保存到一个 requirements 文件中，并在服务器上进行镜像部署时进行设置复制：

![Virtualenv and pip](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00512.jpeg)

以下屏幕截图显示了通过 pip install 命令的`-r`选项在另一个虚拟环境中重新创建相同的设置，该选项接受此类文件作为输入：

![Virtualenv 和 pip](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00513.jpeg)

### 注意

我们的源虚拟环境是 Python2，目标是 Python3。但是，pip 能够无任何问题地从`requirements.txt`文件中安装依赖项。

## 可重定位的虚拟环境

从一个虚拟环境复制软件包依赖项到另一个虚拟环境的建议方法是执行冻结，并按照前一节中所示通过 pip 进行安装。例如，这是从开发环境中冻结 Python 软件包要求并成功地在生产服务器上重新创建的最常见方法。

还可以尝试使虚拟环境可重定位，以便可以将其存档并移动到兼容的系统。

![可重定位的虚拟环境](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00514.jpeg)

创建可重定位的虚拟环境

它是如何工作的：

1.  首先，通常创建虚拟环境。

1.  然后通过运行`virtualenv –relocatable lenv`来使其可重定位。

1.  这会将 setuptools 使用的一些路径更改为相对路径，并设置系统可重定位。

1.  这样的虚拟环境可以重定位到同一台机器上的另一个文件夹，或者重定位到*远程和相似的机器*上的文件夹。

### 注意

可重定位的虚拟环境并不保证在远程环境与机器环境不同时能正常工作。例如，如果您的远程机器是不同的架构，甚至使用另一种类型的 Linux 发行版进行打包，重定位将无法正常工作。这就是所谓的*相似的机器*。

## PyPI

我们了解到 Pip 是 Python 中进行软件包安装的标准化工具。只要存在，它就能够按名称选择任何软件包。正如我们在 requirements 文件的示例中看到的，它也能够按版本安装软件包。

但是 pip 从哪里获取软件包呢？

要回答这个问题，我们转向 Python 软件包索引，更常被称为 PyPI。

**Python 软件包索引（PyPI）**是官方的第三方 Python 软件包在 Web 上托管元数据的存储库。顾名思义，它是 Web 上 Python 软件包的索引，其元数据发布并在服务器上进行索引。PyPI 托管在 URL [`pypi.python.org`](http://pypi.python.org)。

PyPI 目前托管了接近一百万个软件包。这些软件包是使用 Python 的打包和分发工具 distutils 和 setuptools 提交到 PyPI 的，这些工具具有用于将软件包元数据发布到 PyPI 的钩子。许多软件包还在 PyPI 中托管实际软件包数据，尽管 PyPI 可以用于指向位于另一台服务器上 URL 的软件包数据。

当您使用 pip 安装软件包时，实际上是在 PyPI 上搜索软件包，并下载元数据。它使用元数据来查找软件包的下载 URL 和其他信息，例如进一步的下游依赖项，这些信息用于为您获取和安装软件包。

以下是 PyPI 的屏幕截图，显示了此时软件包的实际数量：

![PyPI](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00515.jpeg)

开发人员可以在 PyPI 网站上直接执行许多操作：

1.  使用电子邮件地址注册并登录网站。

1.  登录后，直接在网站上提交您的软件包。

1.  通过关键字搜索软件包。

1.  通过一些顶级*trove*分类器浏览软件包，例如主题、平台/操作系统、开发状态、许可证等。

现在我们已经熟悉了所有 Python 打包和安装工具及其关系，让我们尝试一个小例子，将一个简单的 Python 模块打包并提交到 PyPI。

## 软件包的打包和提交

请记住，我们曾经开发过一个 mandelbrot 程序，它使用 pymp 进行缩放，在第五章中，*编写可扩展的应用程序*。我们将以此作为一个开发软件包的示例程序，并使用`setup.py`文件将该应用程序提交到 PyPI。

我们将 mandelbrot 应用程序打包成一个主包，其中包含两个子包，如下所示：

+   `mandelbrot.simple`：包含 mandelbrot 基本实现的子包（子模块）

+   `mandelbrot`.mp：包含 mandelbrot 的 PyMP 实现的子包（子模块）

以下是我们软件包的文件夹结构：

![软件包的打包和提交](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00516.jpeg)

mandelbrot 软件包的文件夹布局

让我们快速分析一下我们将要打包的应用程序的文件夹结构：

+   顶级目录名为`mandelbrot`。它有一个`__init__.py`，一个`README`和一个`setup.py`文件。

+   该目录有两个子目录——`mp`和`simple`。

+   每个子文件夹都包括两个文件，即`__init__.py`和`mandelbrot.py`。这些子文件夹将形成我们的子模块，每个子模块包含 mandelbrot 集的相应实现。

### 注意

为了将 mandelbrot 模块安装为可执行脚本，代码已更改以向我们的每个`mandelbrot.py`模块添加`main`方法。

### `__init__.py`文件

`__init__.py`文件允许将 Python 应用程序中的文件夹转换为软件包。我们的文件夹结构有三个：第一个是顶级软件包`mandelbrot`，其余两个分别是每个子包`mandelbrot.simple`和`mandelbrot.mp`。

顶级`__init__.py`为空。其他两个有以下单行：

```py
from . import mandelbrot
```

### 注意

相对导入是为了确保子包导入本地的`mandelbrot.py`模块，而不是顶级`mandelbrot`软件包。

### `setup.py`文件

`setup.py`文件是整个软件包的中心点。让我们来看一下：

```py
from setuptools import setup, find_packages
setup(
    name = "mandelbrot",
    version = "0.1",
    author = "Anand B Pillai",
    author_email = "abpillai@gmail.com",
    description = ("A program for generating Mandelbrot fractal images"),
    license = "BSD",
    keywords = "fractal mandelbrot example chaos",
    url = "http://packages.python.org/mandelbrot",
    packages = find_packages(),
    long_description=open('README').read(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Scientific/Engineering :: Visualization",
        "License :: OSI Approved :: BSD License",
    ],
    install_requires = [
        'Pillow>=3.1.2',
        'pymp-pypi>=0.3.1'
        ],
    entry_points = {
        'console_scripts': [
            'mandelbrot = mandelbrot.simple.mandelbrot:main',
            'mandelbrot_mp = mandelbrot.mp.mandelbrot:main'
            ]
        }
)
```

`setup.py`文件的全面讨论超出了本章的范围，但请注意以下几个关键点：

+   `setup.py`文件允许作者创建许多软件包元数据，例如名称、作者名称、电子邮件、软件包关键字等。这些对于创建软件包元信息非常有用，一旦提交到 PyPI，就可以帮助人们搜索软件包。

+   该文件中的一个主要字段是`packages`，它是由此`setup.py`文件创建的软件包（和子软件包）的列表。我们使用 setuptools 模块提供的`find_packages`辅助函数来实现这一点。

+   我们在`install-requires`键中提供了安装要求，以 PIP 格式逐个列出依赖项。

+   `entry_points`键用于配置此软件包安装的控制台脚本（可执行程序）。让我们看其中一个：

```py
mandelbrot = mandelbrot.simple.mandelbrot:main
```

这告诉包资源加载器加载名为`mandelbrot.simple.mandelbrot`的模块，并在调用脚本`mandelbrot`时执行其函数`main`。

### 安装软件包

现在可以使用以下命令安装软件包：

```py
$ python setup.py install

```

安装的以下截图显示了一些初始步骤：

![安装软件包](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00517.jpeg)

### 注意

我们已将此软件包安装到名为`env3`的虚拟环境中。

### 将软件包提交到 PyPI

Python 中的`setup.py`文件加上 setuptools/distutils 生态系统不仅可以用于安装和打包代码，还可以用于将代码提交到 Python 软件包索引。

将软件包注册到 PyPI 非常容易。只有以下两个要求：

+   具有适当`setup.py`文件的软件包。

+   PyPI 网站上的一个帐户。

现在，我们将通过以下步骤将我们的新 mandelbrot 软件包提交到 PyPI：

1.  首先，需要在家目录中创建一个名为`.pypirc`的文件，其中包含一些细节，主要是 PyPI 帐户的身份验证细节。

这是作者的`.pypirc`文件，其中密码被隐藏：

![将软件包提交到 PyPI](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00518.jpeg)

1.  完成此操作后，注册就像运行`setup.py`并使用`register`命令一样简单：

```py
$ python setup.py register

```

下一张截图显示了控制台上实际命令的执行情况：

![将软件包提交到 PyPI](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00519.jpeg)

然而，这最后一步只是通过提交其元数据注册了软件包。在此步骤中并未提交软件包数据，如源代码数据。

1.  要将源代码提交到 PyPI，应运行以下命令：

```py
$ python setup.py sdist upload

```

![将软件包提交到 PyPI](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00520.jpeg)

这是我们在 PyPI 服务器上的新软件包的视图：

![将软件包提交到 PyPI](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00521.jpeg)

现在，通过 pip 安装软件包，完成了软件开发的循环：首先是打包、部署，然后是安装。

## PyPA

**Python Packaging Authority**（**PyPA**）是一群维护 Python 打包标准和相关应用程序的 Python 开发人员的工作组。PyPA 在[`www.pypa.io/`](https://www.pypa.io/)上有他们的网站，并在 GitHub 上维护应用程序[`github.com/pypa/`](https://github.com/pypa/)。

以下表格列出了由 PyPA 维护的项目。您已经看到了其中一些，比如 pip、virtualenv 和 setuptools；其他可能是新的：

| 项目 | 描述 |
| --- | --- |
| setuptools | 对 Python distutils 的增强集合 |
| virtualenv | 用于创建沙盒 Python 环境的工具 |
| pip | 用于安装 Python 软件包的工具 |
| packaging | pip 和 setuptools 使用的核心 Python 打包实用程序 |
| wheel | 用于创建 wheel 分发的 setuptools 扩展，它是 Python eggs（ZIP 文件）的替代方案，并在 PEP 427 中指定 |
| twine | 用于创建 wheel 分发的`setup.py`上传的安全替代品 |
| warehouse | 新的 PyPI 应用程序，可以在[`pypi.org`](https://pypi.org)上查看 |
| distlib | 一个实现与 Python 代码打包和分发相关功能的低级库 |
| bandersnatch | 用于镜像 PyPI 内容的 PyPI 镜像客户端 |

有兴趣的开发人员可以访问 PyPA 网站，并注册其中一个项目，并通过访问 PyPA 的 github 存储库，以进行测试、提交补丁等方面的贡献。

## 使用 Fabric 进行远程部署

Fabric 是一个用 Python 编写的命令行工具和库，它通过一组对 SSH 协议的良好定义的包装器来自动化服务器上的远程部署。它在幕后使用`ssh-wrapper`库`paramiko`。

Fabric 仅适用于 Python 2.x 版本。但是，有一个名为 Fabric3 的分支，可以同时适用于 Python 2.x 和 3.x 版本。

使用 fabric 时，devops 用户通常将远程系统管理员命令部署为名为`fabfile.py`的 Python 函数。

当远程系统已经配置了用户机器的 ssh 公钥时，Fabric 的工作效果最佳，因此无需提供用户名和密码。

以下是在服务器上进行远程部署的示例。在这种情况下，我们正在将我们的 mandelbrot 应用程序安装到远程服务器上。

fabfile 如下所示。请注意，它是为 Python3 编写的：

```py
from fabric.api import run

def remote_install(application):

    print ('Installing',application)
    run('sudo pip install ' + application)
```

以下是一个在远程服务器上安装并运行的示例：

![使用 Fabric 进行远程部署](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00522.jpeg)

Devops 工程师和系统管理员可以使用预定义的 fabfiles 集合来自动化不同的系统和应用程序部署任务，跨多个服务器。

### 注意

虽然 Fabric 是用 Python 编写的，但可以用于自动化任何类型的远程服务器管理和配置任务。

## 使用 Ansible 进行远程部署

Ansible 是用 Python 编写的配置管理和部署工具。Ansible 可以被视为在 SSH 上使用脚本的包装器，支持通过易于管理的单元（称为*playbooks*）组装的任务进行编排，将一组主机映射到一组角色。

Ansible 使用“facts”，这是它在运行任务之前收集的系统和环境信息。它使用这些 facts 来检查是否有任何需要在运行任务之前改变任何状态的情况。

这使得 Ansible 任务可以安全地在服务器上以重复的方式运行。良好编写的 ansible 任务是*幂等*的，对远程系统几乎没有副作用。

Ansible 是用 Python 编写的，可以使用 pip 安装。

它使用自己的主机文件，即`/etc/ansible/hosts`，来保存其运行任务的主机信息。

典型的 ansible 主机文件可能如下所示，

```py
[local]
127.0.0.1

[webkaffe]
139.162.58.8
```

以下是一个名为`dependencies.yaml`的 Ansible playbook 的片段，它在名为*webkaffe*的远程主机上通过 pip 安装了一些 Python 包。

```py
---
- hosts: webkaffe
  tasks:
    - name: Pip - Install Python Dependencies
      pip:
          name="{{ python_packages_to_install | join(' ') }}"

      vars:
          python_packages_to_install:
          - Flask
          - Bottle
          - bokeh
```

这是在使用 ansible-playbook 命令行运行此 playbook 的图像。

![使用 Ansible 进行远程部署](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00520.jpeg)

Ansible 是管理远程依赖项的一种简单有效的方式，由于其幂等 playbooks，比 Fabric 更适合执行任务。

## 使用 Supervisor 管理远程守护进程

Supervisor 是一个客户端/服务器系统，对于控制 Unix 和类 Unix 系统上的进程非常有用。它主要由一个名为**supervisord**的服务器守护进程和一个与服务器交互的命令行客户端**supervisorctl**组成。

Supervisor 还带有一个基本的 Web 服务器，可以通过端口 9001 访问。可以通过此界面查看运行进程的状态，并通过此界面启动/停止它们。Supervisor 不在任何版本的 Windows 上运行。

Supervisor 是一个使用 Python 编写的应用程序，因此可以通过 pip 安装。它仅在 Python 2.x 版本上运行。

通过 supervisor 管理的应用程序应该通过 supervisor 守护程序的配置文件进行配置。默认情况下，这些文件位于`/etc/supervisor.d/conf`文件夹中。

然而，也可以通过将其安装到虚拟环境中并将配置保留在虚拟环境中来在本地运行 Supervisor。事实上，这是运行多个管理特定于虚拟环境的进程的常见方式。

我们不会详细介绍或举例使用 Supervisor，但以下是使用 Supervisor 与传统方法（如系统`rc.d`脚本）相比的一些好处：

+   通过使用客户端/服务器系统来解耦进程创建/管理和进程控制。`supervisor.d`文件通过子进程管理进程。用户可以通过客户端 supervisorctl 获取进程状态信息。此外，大多数传统的 rc.d 进程需要 root 或 sudo 访问权限，而 supervisor 进程可以通过系统的普通用户通过客户端或 Web UI 进行控制。

+   由于 supervisord 通过子进程启动进程，可以配置它们在崩溃时自动重新启动。相比依赖 PID 文件，更容易获得子进程的更准确状态。

+   监管者支持进程组，允许用户按优先级顺序定义进程。进程可以作为一组按特定顺序启动和停止。当应用程序中的进程之间存在时间依赖性时，这允许实现精细的进程控制。（进程 B 需要 A 正在运行，C 需要 B 正在运行，依此类推。）

我们将在本章中完成讨论，概述常见的部署模式，架构师可以选择以解决可部署性的常见问题。

# 部署-模式和最佳实践

有不同的部署方法或模式可用于解决停机时间、减少部署风险以及无缝开发和部署软件的问题。

+   持续部署：持续部署是一种部署模型，其中软件随时可以准备上线。只有在包括开发、测试和暂存在内的各个层次不断集成的情况下，才能实现持续交付。在持续部署模型中，一天内可以发生多次生产部署，并且可以通过部署管道自动完成。由于不断部署增量更改，持续部署模式最小化了部署风险。在敏捷软件开发公司，这也有助于客户通过几乎在开发和测试结束后立即在生产中看到实时代码来直接跟踪进展。还有一个额外的优势，即更快地获得用户反馈，从而允许更快地对代码和功能进行迭代。

+   蓝绿部署：我们已经在第五章中讨论过这个问题。蓝绿部署保持两个生产环境，彼此非常相似。在某个时刻，一个环境是活跃的（蓝色）。您将新的部署更改准备到另一个环境（绿色），一旦测试并准备好上线，切换系统——绿色变为活跃，蓝色变为备份。蓝绿部署大大降低了部署风险，因为对于新部署出现的任何问题，您只需要切换路由器或负载均衡器到新环境。通常，在典型的蓝绿系统中，一个系统是生产（活跃）的，另一个是暂存的，您可以在它们之间切换角色。

+   金丝雀发布：如果您想在将软件更改部署给所有客户的整个受众之前，先在用户的子集上测试这些更改，您可以使用这种方法。在金丝雀发布中，更改首先针对一小部分用户进行推出。一个简单的方法是狗食，首先将更改内部推出给员工。另一种方法是测试版，邀请一组特定的受众来测试您的早期功能。其他涉及的方法包括根据地理位置、人口统计和个人资料选择用户。金丝雀发布除了使公司免受对糟糕管理的功能的突然用户反应之外，还可以以递增方式管理负载和容量扩展。例如，如果某个特定功能变得受欢迎，并且开始将比以前多 100 倍的用户驱动到您的服务器，传统的部署可能会导致服务器故障和可用性问题，而不是使用金丝雀发布进行逐步部署。地理路由是一种技术，可以用来选择用户的子集，如果您不想进行复杂的用户分析和分析。这是将负载发送到部署在特定地理位置或数据中心的节点，而不是其他节点。金丝雀发布也与增量部署或分阶段部署的概念相关。

+   **桶测试（A/B 测试）**：这是一种在生产中部署两个不同版本的应用程序或网页来测试哪个版本更受欢迎和/或更具吸引力的技术。在生产中，你的一部分受众看到应用程序（或页面）的 A 版本——控制或基本版本——另一部分看到 B 版本或修改（变体）版本。通常，这是一个 50-50 的分割，尽管与金丝雀发布一样，用户配置文件、地理位置或其他复杂模型可以被使用。用户体验和参与度是通过分析仪表板收集的，然后确定更改是否有积极、消极或中性的响应。

+   **诱发混乱**：这是一种故意引入错误或禁用生产部署系统的一部分来测试其对故障的弹性和/或可用性的技术。

生产服务器存在漂移问题——除非你使用持续部署或类似的方法进行同步，否则，生产服务器通常会偏离标准配置。测试系统的一种方法是去故意禁用生产系统的一部分——例如，通过禁用负载均衡器配置中随机 50%的节点，然后观察系统的其余部分的表现。

寻找和清除未使用代码的类似方法是去注入随机的秘密部分配置，使用一个你怀疑是多余且不再需要的 API。然后观察应用在生产环境中的表现。如果一个随机的秘密会导致 API 失败，那么如果应用的某个部分仍然使用依赖的代码，它将在生产中失败。否则，这表明代码可以安全地移除。

Netflix 有一个名为**混沌猴**的工具，它会自动在生产系统中引入故障，然后衡量影响。

诱发混乱允许 DevOps 工程师和架构师了解系统的弱点，了解正在经历配置漂移的系统，并找到并清除应用程序中不必要或未使用的部分。

# 总结

这一章是关于将你的 Python 代码部署到生产环境。我们看了影响系统可部署性的不同因素。我们继续讨论了部署架构中的层次，比如传统的四层和三层、两层架构，包括开发、测试、暂存/QA 和生产层的组合。

然后我们讨论了打包 Python 代码的细节。我们详细讨论了 pip 和 virtualenv 这两个工具。我们看了 pip 和 virtualenv 如何一起工作，以及如何使用 pip 安装一组要求，并使用它设置类似的虚拟环境。我们还简要介绍了可重定位的虚拟环境。

然后我们讨论了 PyPI——Python 包索引，它在网络上托管 Python 第三方包。然后我们通过一个详细的例子讨论了如何使用 setuptools 和`setup.py`文件设置 Python 包。在这种情况下，我们使用 mandelbrot 应用程序作为例子。

我们通过展示如何使用元数据将包注册到 PyPI，并且如何上传包括代码在内的包数据来结束了这次讨论。我们还简要介绍了 PyPA，即 Python Packaging Authority 及其项目。

之后，我们讨论了两个工具——都是用 Python 开发的——Fabric 用于远程自动部署，Supervisor 用于 Unix 系统上的远程进程管理。我们以概述常见的部署模式结束了这一章，这些模式可以用来解决部署问题。

在本书的最后一章中，我们讨论了一系列调试代码的技术，以找出潜在的问题。


# 第十章：调试技术

调试程序通常会像编写程序一样困难，有时甚至更困难。很多时候，程序员似乎会花费大量的时间寻找那个难以捉摸的错误，其原因可能正盯着他们，却不显露出来。

许多开发人员，甚至是优秀的开发人员，发现故障排除是一门困难的艺术。大多数情况下，程序员在简单的方法，如适当放置的打印语句和策略性注释的代码等方法无法解决问题时，就会求助于复杂的调试技术。

Python 在调试代码时会带来自己的一套问题。作为一种动态类型的语言，由于程序员假设类型是某种类型（当它实际上是其他类型），类型相关的异常在 Python 中是非常常见的。名称错误和属性错误也属于类似的范畴。

在本章中，我们将专注于软件的这一少讨论的方面。

这是一个按主题分类的列表，我们将在本章中遇到的内容：

+   最大子数组问题：

+   “打印”的力量

+   分析和重写

+   计时和优化代码

+   简单的调试技巧和技术：

+   单词搜索程序

+   单词搜索程序-调试步骤 1

+   单词搜索程序-调试步骤 2

+   单词搜索程序-最终代码

+   跳过代码块

+   停止执行

+   外部依赖-使用包装器

+   用返回值/数据替换函数（模拟）

+   将数据保存到/从文件加载为缓存

+   将数据保存到/从内存加载为缓存

+   返回随机/模拟数据

生成随机患者数据

+   日志记录作为调试技术：

+   简单的应用程序日志记录

+   高级日志记录-记录器对象

高级日志记录-自定义格式和记录器

高级日志记录-写入 syslog

+   调试工具-使用调试器：

+   与 pdb 一起进行调试会话

+   Pdb-类似工具

iPdb

Pdb++

+   高级调试-跟踪：

+   跟踪模块

+   lptrace 程序

+   使用 strace 进行系统调用跟踪

好的，让我们调试一下！

# 最大子数组问题

首先，让我们看一个有趣的问题。在这个问题中，目标是找到一个混合负数和正数的整数数组（序列）的最大连续子数组。

例如，假设我们有以下数组：

```py
>>> a  = [-5, 20, -10, 30, 15]
```

通过快速扫描很明显，最大和的子数组是`[20, -10, 30, 15]`，得到和`55`。

让我们说，作为第一步，你写下了这段代码：

```py
import itertools

# max_subarray: v1
def max_subarray(sequence):
    """ Find sub-sequence in sequence having maximum sum """

    sums = []

    for i in range(len(sequence)):
        # Create all sub-sequences in given size
        for sub_seq in itertools.combinations(sequence, i):
            # Append sum
            sums.append(sum(sub_seq))

    return max(sums)
```

现在让我们试一下：

```py
>>>  max_subarray([-5, 20, -10, 30, 15])
65

```

这个输出看起来显然是错误的，因为在数组中手动添加任何子数组似乎都不会产生大于 55 的数字。我们需要调试代码。

## “打印”的力量

为了调试前面的例子，一个简单而策略性放置的**“打印”**语句就可以解决问题。让我们在内部的`for`循环中打印出子序列：

函数修改如下：

# max_subarray：v1

```py
def max_subarray(sequence):
    """ Find sub-sequence in sequence having maximum sum """

    sums = []
    for i in range(len(sequence)):
        for sub_seq in itertools.combinations(sequence, i):
            sub_seq_sum = sum(sub_seq)
            print(sub_seq,'=>',sub_seq_sum)
            sums.append(sub_seq_sum)

    return max(sums)
```

现在代码执行并打印出这个输出：

```py
>>> max_subarray([-5, 20, -10, 30, 15])
((), '=>', 0)
((-5,), '=>', -5)
((20,), '=>', 20)
((-10,), '=>', -10)
((30,), '=>', 30)
((15,), '=>', 15)
((-5, 20), '=>', 15)
((-5, -10), '=>', -15)
((-5, 30), '=>', 25)
((-5, 15), '=>', 10)
((20, -10), '=>', 10)
((20, 30), '=>', 50)
((20, 15), '=>', 35)
((-10, 30), '=>', 20)
((-10, 15), '=>', 5)
((30, 15), '=>', 45)
((-5, 20, -10), '=>', 5)
((-5, 20, 30), '=>', 45)
((-5, 20, 15), '=>', 30)
((-5, -10, 30), '=>', 15)
((-5, -10, 15), '=>', 0)
((-5, 30, 15), '=>', 40)
((20, -10, 30), '=>', 40)
((20, -10, 15), '=>', 25)
((20, 30, 15), '=>', 65)
((-10, 30, 15), '=>', 35)
((-5, 20, -10, 30), '=>', 35)
((-5, 20, -10, 15), '=>', 20)
((-5, 20, 30, 15), '=>', 60)
((-5, -10, 30, 15), '=>', 30)
((20, -10, 30, 15), '=>', 55)
65

```

通过查看打印语句的输出，问题现在变得清晰了。

有一个子数组`[20, 30, 15]`（在前面的输出中用粗体标出），产生和*65*。然而，这不是一个有效的子数组，因为元素在原始数组中不是连续的。

显然，程序是错误的，需要修复。

## 分析和重写

快速分析告诉我们，使用`itertools.combinations`在这里是罪魁祸首。我们使用它作为一种快速从数组中生成所有不同长度的子数组的方法，但是使用组合*不*尊重项目的顺序，并生成*所有*组合，产生不连续的子数组。

显然，我们需要重写这个。这是重写的第一次尝试：

# max_subarray：v2

```py
def max_subarray(sequence):
    """ Find sub-sequence in sequence having maximum sum """

    sums = []

    for i in range(len(sequence)):
        for j in range(i+1, len(sequence)):
            sub_seq = sequence[i:j]
            sub_seq_sum = sum(sub_seq)
            print(sub_seq,'=>',sub_seq_sum)
            sums.append(sum(sub_seq))

    return max(sums)
```

现在输出如下：

```py
>>> max_subarray([-5, 20, -10, 30, 15])
([-5], '=>', -5)
([-5, 20], '=>', 15)
([-5, 20, -10], '=>', 5)
([-5, 20, -10, 30], '=>', 35)
([20], '=>', 20)
([20, -10], '=>', 10)
([20, -10, 30], '=>', 40)
([-10], '=>', -10)
([-10, 30], '=>', 20)
([30], '=>', 30)
40
```

答案再次不正确，因为它给出了次优解*40*，而不是正确的解答*55*。再次，打印语句挺身而出，因为它清楚地告诉我们，主数组本身没有被考虑进去-我们有一个*偏移一个*的错误。

### 注意

在编程中，当用于迭代序列（数组）的数组索引比正确值要少一个或多一个时，就会出现一个偏差或一次性错误。这经常出现在序列的索引从零开始的语言中，比如 C/C++、Java 或 Python。

在这种情况下，*off-by-one*错误在这一行中：

```py
    "sub_seq = sequence[i:j]"
```

正确的代码应该是这样的：

```py
    "sub_seq = sequence[i:j+1]"
```

有了这个修复，我们的代码产生了预期的输出：

# max_subarray: v2

```py
def max_subarray(sequence):
    """ Find sub-sequence in sequence having maximum sum """

    sums = []

    for i in range(len(sequence)):
        for j in range(i+1, len(sequence)):
            sub_seq = sequence[i:j+1]
            sub_seq_sum = sum(sub_seq)
          print(sub_seq,'=>',sub_seq_sum)
            sums.append(sub_seq_sum)

    return max(sums)
```

以下是输出：

```py
>>> max_subarray([-5, 20, -10, 30, 15])
([-5, 20], '=>', 15)
([-5, 20, -10], '=>', 5)
([-5, 20, -10, 30], '=>', 35)
([-5, 20, -10, 30, 15], '=>', 50)
([20, -10], '=>', 10)
([20, -10, 30], '=>', 40)
([20, -10, 30, 15], '=>', 55)
([-10, 30], '=>', 20)
([-10, 30, 15], '=>', 35)
([30, 15], '=>', 45)
55
```

让我们在这一点上假设您认为代码已经完成。

您将代码传递给审阅人员，他们提到您的代码，尽管被称为`max_subarray`，但实际上忘记了返回子数组本身，而只返回了总和。还有反馈说您不需要维护一个总和数组。

您结合这些反馈，生成了修复了这两个问题的代码版本 3.0：

# max_subarray: v3

```py
def max_subarray(sequence):
    """ Find sub-sequence in sequence having maximum sum """

    # Trackers for max sum and max sub-array
    max_sum, max_sub = 0, []

    for i in range(len(sequence)):
        for j in range(i+1, len(sequence)):
            sub_seq = sequence[i:j+1]
            sum_s = sum(sub_seq)
            if sum_s > max_sum:
                # If current sum > max sum so far, replace the values
                max_sum, max_sub = sum_s, sub_seq

    return max_sum, max_sub

>>>  max_subarray([-5, 20, -10, 30, 15])
(55, [20, -10, 30, 15])
```

注意，我们在最后一个版本中删除了打印语句，因为逻辑已经正确，所以不需要调试。

一切正常。

## 计时和优化代码

如果您稍微分析一下代码，您会发现代码对整个序列进行了两次遍历，一次外部遍历，一次内部遍历。因此，如果序列包含*n*个项目，代码将执行*n*n*次遍历。

我们从第四章中知道，*良好的性能是值得的！*，关于性能，这样一段代码的性能是*O(n2)*。我们可以使用简单的`上下文管理器`和`with`运算符来测量代码的实际运行时间。

我们的上下文管理器如下：

```py
import time
from contextlib import contextmanager

@contextmanager
def timer():
    """ Measure real-time execution of a block of code """

    try:
        start = time.time()
        yield
    finally:
        end = (time.time() - start)*1000
        print 'time taken=> %.2f ms' % end
```

让我们修改代码，创建一个不同大小的随机数数组来测量所花费的时间。我们将为此编写一个函数：

```py
import random

def num_array(size):
    """ Return a list of numbers in a fixed random range
    of given size """

    nums = []
    for i in range(size):
        nums.append(random.randrange(-25, 30))
    return nums
```

让我们测试各种大小的数组的逻辑，从 100 开始：

```py
>>> with timer():
... max_subarray(num_array(100))
... (121, [7, 10, -17, 3, 21, 26, -2, 5, 14, 2, -19, -18, 23, 12, 8, -12, -23, 28, -16, -19, -3, 14, 16, -25, 26, -16, 4, 12, -23, 26, 22, 12, 23])
time taken=> 16.45 ms
```

对于一个大小为 1000 的数组，代码将如下：

```py
>>> with timer():
... max_subarray(num_array(100))
... (121, [7, 10, -17, 3, 21, 26, -2, 5, 14, 2, -19, -18, 23, 12, 8, -12, -23, 28, -16, -19, -3, 14, 16, -25, 26, -16, 4, 12, -23, 26, 22, 12, 23])
time taken=> 16.45 ms
```

所以大约需要 3.3 秒。

可以证明，对于输入大小为 10000，代码运行大约需要 2 到 3 小时。

有没有一种方法可以优化代码？是的，有一个*O(n)*版本的相同代码，看起来像这样：

```py
def max_subarray(sequence):
    """ Maximum subarray – optimized version """

    max_ending_here = max_so_far = 0

    for x in sequence:
        max_ending_here = max(0, max_ending_here + x)
        max_so_far = max(max_so_far, max_ending_here)

    return max_so_far
```

有了这个版本，所花费的时间要好得多：

```py
>>> with timer():
... max_subarray(num_array(100))
... 240
time taken=> 0.77 ms
```

对于一个大小为 1000 的数组，所花费的时间如下：

```py
>>> with timer():
... max_subarray(num_array(1000))
... 2272
time taken=> 6.05 ms
```

对于一个大小为 10000 的数组，时间大约为 44 毫秒：

```py
>>> with timer():
... max_subarray(num_array(10000))
... 19362
time taken=> 43.89 ms
```

# 简单的调试技巧和技术

我们在前面的示例中看到了简单的`print`语句的威力。类似的其他简单技术也可以用来调试程序，而无需使用调试器。

调试可以被认为是一个逐步排除的过程，直到程序员找到真相——错误的原因。它基本上涉及以下步骤：

+   分析代码，并得出一组可能的假设（原因），可能是错误的来源。

+   逐个测试每个假设，使用适当的调试技术。

+   在测试的每一步，您要么找到了错误的原因——因为测试成功告诉您问题出在您正在测试的特定原因；要么测试失败，您继续测试下一个假设。

+   重复上一步，直到找到原因或放弃当前一组可能的假设。然后重新开始整个循环，直到（希望）找到原因。

## 单词搜索程序

在本节中，我们将逐个使用示例来看一些简单的调试技巧。我们将从一个单词搜索程序的示例开始，该程序在文件列表中查找包含特定单词的行，并将这些行附加并返回到一个列表中。

以下是单词搜索程序的代码清单：

```py
import os
import glob

def grep_word(word, filenames):
    """ Open the given files and look for a specific word.
    Append lines containing word to a list and
    return it """

    lines, words = [], []

    for filename in filenames:
        print('Processing',filename)
        lines += open(filename).readlines()

    word = word.lower()
    for line in lines:
        if word in line.lower():
            lines.append(line.strip())

    # Now sort the list according to length of lines
    return sorted(words, key=len)
```

您可能已经注意到前面的代码中有一个细微的错误——它附加到了错误的列表上。它从列表“lines”中读取，并附加到同一个列表，这将导致列表无限增长；当遇到包含给定单词的一行时，程序将进入无限循环。

让我们在当前目录上运行程序：

```py
>>> parse_filename('lines', glob.glob('*.py'))
(hangs)
```

在任何一天，你可能会很容易地找到这个 bug。在糟糕的一天，你可能会卡在这里一段时间，没有注意到正在读取的列表是被追加的。

以下是你可以做的一些事情：

+   由于代码挂起并且有两个循环，找出导致问题的循环。为了做到这一点，可以在两个循环之间放置一个打印语句，或者放置一个`sys.exit`函数，这将导致解释器在那一点退出。

+   开发人员可能会忽略打印语句，特别是如果代码中有很多其他打印语句，但`sys.exit`当然不会被忽略。

## 单词搜索程序-调试步骤 1

代码重写如下，插入了一个特定的`sys.exit(…)`调用在两个循环之间：

```py
import os
import glob

def grep_word(word, filenames):
    """ Open the given files and look for a specific word.
    Append lines containing word to a list and
    return it """

    lines, words = [], []

    for filename in filenames:
        print('Processing',filename)
        lines += open(filename).readlines()

    sys.exit('Exiting after first loop')

    word = word.lower()
    for line in lines:
        if word in line.lower():
            lines.append(line.strip())

    # Now sort the list according to length of lines
    return sorted(words, key=len)
```

第二次尝试时，我们得到了这个输出：

```py
>>> grep_word('lines', glob.glob('*.py'))
Exiting after first loop
```

现在很明显问题不在第一个循环中。现在你可以继续调试第二个循环（我们假设你完全不知道错误的变量使用方式，所以你正在通过调试的方式艰难地找出问题）。

## 单词搜索程序-调试步骤 2

每当你怀疑循环内的一段代码可能导致 bug 时，有一些调试技巧可以帮助你确认这一点。这些包括以下内容：

+   在代码块之前放置一个策略性的`continue`。如果问题消失了，那么你已经确认了特定的代码块或下一个代码块是问题所在。你可以继续移动你的`continue`语句，直到找到引起问题的具体代码块。

+   让 Python 跳过代码块，通过在其前面加上`if 0:`。如果代码块是一行代码或几行代码，这将更有用。

+   如果循环内有大量的代码，并且循环执行多次，打印语句可能不会对你有太大帮助，因为会打印出大量的数据，很难筛选和扫描找出问题所在。

在这种情况下，我们将使用第一个技巧来找出问题。以下是修改后的代码：

```py
def grep_word(word, filenames):
    """ Open the given files and look for a specific word.
    Append lines containing word to a list and
    return it """

    lines, words = [], []

    for filename in filenames:
        print('Processing',filename)
        lines += open(filename).readlines()

    # Debugging steps
    # 1\. sys.exit
    # sys.exit('Exiting after first loop')

    word = word.lower()
    for line in lines:
        if word in line.lower():
            words.append(line.strip())
            continue

    # Now sort the list according to length of lines
    return sorted(words, key=len)

>>> grep_word('lines', glob.glob('*.py'))
[]
```

现在代码执行了，很明显问题出在处理步骤中。希望从那里只需一步就能找出 bug，因为程序员终于通过调试过程找到了引起问题的代码行。

## 单词搜索程序-最终代码

我们花了一些时间通过前几节中记录的一些调试步骤来解决程序中的问题。通过这些步骤，我们假设的程序员能够找到代码中的问题并解决它。

以下是修复了 bug 的最终代码：

```py
def grep_word(word, filenames):
    """ Open the given files and look for a specific word.
    Append lines containing word to a list and
    return it """

    lines, words = [], []

    for filename in filenames:
        print('Processing',filename)
        lines += open(filename).readlines()

    word = word.lower()
    for line in lines:
        if word in line.lower():
            words.append(line.strip())

    # Now sort the list according to length of lines
    return sorted(words, key=len)
```

输出如下：

```py
>>> grep_word('lines', glob.glob('*.py'))
['for line in lines:', 'lines, words = [], []', 
  '#lines.append(line.strip())', 
  'lines += open(filename).readlines()',
  'Append lines containing word to a list and', 
  'and return list of lines containing the word.', 
  '# Now sort the list according to length of lines', 
  "print('Lines => ', grep_word('lines', glob.glob('*.py')))"]
```

让我们总结一下我们在本节中学到的简单调试技巧，并看一些相关的技巧和方法。

## 跳过代码块

在调试期间，程序员可以跳过他们怀疑会导致 bug 的代码块。如果代码块在循环内，可以通过`continue`语句跳过执行。我们已经看到了一个例子。

如果代码块在循环之外，可以通过使用`if 0`，并将怀疑的代码移动到依赖块中来完成：

```py
if 0:# Suspected code block
     perform_suspect_operation1(args1, args2, ...)
     perform_suspect_operation2(…)
```

如果 bug 在此之后消失了，那么你可以确定问题出在怀疑的代码块中。

这个技巧有其自身的不足之处，因为它需要将大块的代码缩进到右侧，一旦调试完成，就应该将其重新缩进。因此，不建议用于超过 5-6 行代码的任何情况。

## 停止执行

如果你正在进行紧张的编程工作，并且正在尝试找出一个难以捉摸的 bug，已经尝试了打印语句、使用调试器和其他方法，一个相当激进但通常非常有用的方法是在怀疑的代码路径之前或之后停止执行，使用函数`sys.exit`表达式。

`sys.exit(<strategic message>)`会使程序立即停止，因此程序员*不会错过*它。在以下情况下，这通常非常有用：

+   一段复杂的代码存在一个难以捉摸的 bug，取决于特定的输入值或范围，导致一个被捕获并忽略的异常，但后来导致程序出现问题。

+   在这种情况下，检查特定值或范围，然后通过`sys.exit`在异常处理程序中使用正确的消息退出代码，将允许你找出问题的根源。程序员然后可以决定通过纠正输入或变量处理代码来解决问题。

在编写并发程序时，资源锁定的错误使用或其他问题可能会使跟踪死锁、竞争条件等 bug 变得困难。由于通过调试器调试多线程或多进程程序非常困难，一个简单的技巧是在怀疑的函数中放置`sys.exit`，在实现正确的异常处理代码后。

+   当你的代码存在严重的内存泄漏或无限循环时，随着时间的推移，调试变得困难，你无法找出问题的根源。将`sys.exit(<message>)`这一行代码从一行移到下一行，直到确定问题，可以作为最后的手段。

## 外部依赖-使用包装器

在你怀疑问题不在你的函数内部，而是在你从代码中调用的函数中时，可以使用这种方法。

由于该函数不在你的控制范围之内，你可以尝试用你可以控制的模块中的包装器函数替换它。

例如，以下是用于处理串行 JSON 数据的通用代码。假设程序员发现处理某些数据的 bug（可能具有某个键值对），并怀疑外部 API 是 bug 的来源。bug 可能是 API 超时、返回损坏的响应，或在最坏的情况下导致崩溃：

```py
import external_api
def process_data(data):
    """ Process data using external API """

    # Clean up data—local function
    data = clean_up(data)
    # Drop duplicates from data—local function
    data = drop_duplicates(data)

    # Process line by line JSON
    for json_elem in data:
        # Bug ?
        external_api.process(json_elem)
```

验证的一种方法是对特定范围或数据的 API 进行*虚拟*，在这种情况下，可以通过创建以下包装器函数来实现：

```py
def process(json_data, skey='suspect_key',svalue='suspect_value'):
    """ Fake the external API except for the suspect key & value """

    # Assume each JSON element maps to a Python dictionary

    for json_elem in json_data:
        skip = False

        for key in json_elem:
            if key == skey:
                if json_elem[key] == svalue:
                    # Suspect key,value combination - dont process
                    # this JSON element
                    skip = True
                    break

        # Pass on to the API
        if not skip:
            external_api.process(json_elem)

def process_data(data):
    """ Process data using external API """

    # Clean up data—local function
    data = clean_up(data)
    # Drop duplicates from data—local function
    data = drop_duplicates(data)

    # Process line by line JSON using local wrapper
    process(data)
```

如果你的怀疑是正确的，这将导致问题消失。然后你可以将其用作测试代码，并与外部 API 的利益相关者沟通，以解决问题，或编写代码确保在发送到 API 的数据中跳过问题的键值对。

## 用返回值/数据替换函数（模拟）

在现代 Web 应用程序编程中，你的程序中从来不会离开阻塞 I/O 调用太远。这可能是一个简单的 URL 请求，稍微复杂的外部 API 请求，或者可能是一个昂贵的数据库查询，这些调用可能是 bug 的来源。

你可能会遇到以下情况之一：

+   这样的调用返回数据可能是问题的原因

+   调用本身是问题的原因，比如 I/O 或网络错误、超时或资源争用

当你遇到昂贵 I/O 的问题时，复制它们通常会成为一个问题。这是因为以下原因：

+   I/O 调用需要时间，因此调试会浪费大量时间，无法专注于真正的问题。

+   后续调用可能无法重复出现问题，因为外部请求可能每次返回略有不同的数据

+   如果你使用的是外部付费 API，调用实际上可能会花费你的钱，因此你不能在调试和测试上花费大量这样的调用

在这些情况下非常有用的一种常见技术是保存这些 API/函数的返回数据，然后通过使用它们的返回数据来替换函数/API 本身来模拟函数。这是一种类似于模拟测试的方法，但是它是在调试的上下文中使用的。

让我们看一个 API 的示例，它根据企业地址返回网站上的*商家列表*，包括名称、街道地址、城市等详细信息。代码如下：

```py
import config

search_api = 'http://api.%(site)s/listings/search'

def get_api_key(site):
    """ Return API key for a site """

    # Assumes the configuration is available via a config module
    return config.get_key(site)

def api_search(address, site='yellowpages.com'):
    """ API to search for a given business address
    on a site and return results """

    req_params = {}
    req_params.update({
        'key': get_api_key(site),
        'term': address['name'],
        'searchloc': '{0}, {1}, {1}'.format(address['street'],
                                            address['city'],
                                            address['state'])})
    return requests.post(search_api % locals(),
                         params=req_params)

def parse_listings(addresses, sites):
    """ Given a list of addresses, fetch their listings
    for a given set of sites, process them """

    for site in sites:
        for address in addresses:
            listing = api_search(address, site)
            # Process the listing
            process_listing(listing, site)

def process_listings(listing, site):
    """ Process a listing and analzye it """

     # Some heavy computational code
     # whose details we are not interested.
```

### 注意

该代码做出了一些假设，其中之一是每个站点都具有相同的 API URL 和参数。请注意，这仅用于说明目的。实际上，每个站点的 API 格式都会有很大不同，包括其 URL 和接受的参数。

请注意，在这段代码的最后，实际工作是在`process_listings`函数中完成的，由于示例是说明性的，因此未显示代码。

假设您正在尝试调试此函数。但是，由于 API 调用的延迟或错误，您发现自己在获取列表本身方面浪费了大量宝贵的时间。您可以使用哪些技术来避免这种依赖？以下是一些您可以做的事情：

+   不要通过 API 获取列表，而是将它们保存到文件、数据库或内存存储中，并按需加载

+   通过缓存或记忆模式缓存`api_search`函数的返回值，以便在第一次调用后，进一步调用从内存返回数据

+   模拟数据，并返回具有与原始数据相同特征的随机数据

我们将依次查看这些内容。

### 将数据保存到/从文件中加载作为缓存

在这种技术中，您使用输入数据的唯一键构造文件名。如果磁盘上存在匹配的文件，则打开该文件并返回数据，否则进行调用并写入数据。可以通过使用*文件缓存*装饰器来实现，如下面的代码所示：

```py
import hashlib
import json
import os

def unique_key(address, site):
    """ Return a unique key for the given arguments """

    return hashlib.md5(''.join((address['name'],
                               address['street'],
                               address['city'],
                               site)).encode('utf-8')).hexdigest()

def filecache(func):
    """ A file caching decorator """

    def wrapper(*args, **kwargs):
        # Construct a unique cache filename
        filename = unique_key(args[0], args[1]) + '.data'

        if os.path.isfile(filename):
            print('=>from file<=')
            # Return cached data from file
            return json.load(open(filename))

        # Else compute and write into file
        result = func(*args, **kwargs)
        json.dump(result, open(filename,'w'))

        return result

    return wrapper

@filecache
def api_search(address, site='yellowpages.com'):
    """ API to search for a given business address
    on a site and return results """

    req_params = {}
    req_params.update({
        'key': get_api_key(site),
        'term': address['name'],
        'searchloc': '{0}, {1}, {1}'.format(address['street'],
                                            address['city'],
                                            address['state'])})
    return requests.post(search_api % locals(),
                         params=req_params)
```

以下是这段代码的工作原理：

1.  `api_search`函数被装饰为`filecache`。

1.  `filecache`使用`unique_key`作为计算存储 API 调用结果的唯一文件名的函数。在这种情况下，`unique_key`函数使用业务名称、街道和城市的组合的哈希值，以及查询的站点来构建唯一值。

1.  第一次调用函数时，数据通过 API 获取并存储在文件中。在进一步调用期间，数据直接从文件返回。

这在大多数情况下效果相当不错。大多数数据只加载一次，再次调用时从文件缓存返回。然而，这会遇到“陈旧数据”的问题，因为一旦文件创建，数据总是从中返回。与此同时，服务器上的数据可能已经发生了变化。

这可以通过使用内存键值存储解决，并将数据保存在内存中，而不是在磁盘上的文件中。可以使用著名的键值存储，如**Memcached**、**MongoDB**或**Redis**来实现这一目的。在下面的示例中，我们将向您展示如何使用 Redis 将`filecache`装饰器替换为*memorycache*装饰器。

### 将数据保存到/从内存中加载作为缓存

在这种技术中，使用输入参数的唯一值构造唯一的内存缓存键。如果通过使用键查询在缓存存储中找到缓存，则从存储中返回其值；否则进行调用并写入缓存。为了确保数据不会太陈旧，使用了固定的**生存时间**（**TTL**）。我们使用 Redis 作为缓存存储引擎：

```py
from redis import StrictRedis

def memoize(func, ttl=86400):
    """ A memory caching decorator """

    # Local redis as in-memory cache
    cache = StrictRedis(host='localhost', port=6379)

    def wrapper(*args, **kwargs):
        # Construct a unique key

        key = unique_key(args[0], args[1])
        # Check if its in redis
        cached_data = cache.get(key)
        if cached_data != None:
             print('=>from cache<=')
             return json.loads(cached_data)
         # Else calculate and store while putting a TTL
         result = func(*args, **kwargs)
         cache.set(key, json.dumps(result), ttl)

         return result

    return wrapper
```

### 注意

请注意，我们正在重用先前代码示例中的`unique_key`的定义。

在代码的其余部分中唯一变化的是我们用`memoize`替换了`filecache`装饰器：

```py
@memoize    
def api_search(address, site='yellowpages.com'):
    """ API to search for a given business address
    on a site and return results """

    req_params = {}
    req_params.update({
        'key': get_api_key(site),
        'term': address['name'],
        'searchloc': '{0}, {1}, {1}'.format(address['street'],
                                            address['city'],
                                            address['state'])})
    return requests.post(search_api % locals(),
                         params=req_params)
```

这个版本相对于之前的版本的优势如下：

+   缓存存储在内存中。不会创建额外的文件。

+   缓存是使用 TTL 创建的，超过 TTL 后会过期。因此，陈旧数据的问题被规避了。TTL 是可定制的，在这个例子中默认为一天（86400 秒）。

还有一些模拟外部 API 调用和类似依赖的技术。以下是其中一些：

+   在 Python 中使用`StringIO`对象读取/写入数据，而不是使用文件。例如，`filecache`或`memoize`装饰器可以很容易地修改为使用`StringIO`对象。

+   使用可变默认参数，如字典或列表，作为缓存并将结果写入其中。由于 Python 中的可变参数在重复调用后保持其状态，因此它实际上可以作为内存缓存。

+   通过编辑系统主机文件，为外部 API 替换为对本地机器上的服务的调用（`127.0.0.1` IP 地址）添加一个主机条目，并将其 IP 设置为`127.0.0.1`。对 localhost 的调用总是可以返回标准（预设）响应。

例如，在 Linux 和其他 POSIX 系统上，可以在`/etc/hosts`文件中添加以下行：

```py
# Only for testing—comment out after that!
127.0.0.1 api.website.com
```

### 注意

请注意，只要记得在测试后注释掉这些行，这种技术就是一种非常有用和巧妙的方法！

### 返回随机/模拟数据

另一种技术，主要用于性能测试和调试，是使用*相似但不同*于原始数据的数据来提供函数。

例如，假设您正在开发一个应用程序，该应用程序与特定保险计划（例如美国的 Medicare/Medicaid，印度的 ESI）下的患者/医生数据一起工作，以分析并找出常见疾病、政府支出前 10 位的健康问题等模式。

假设您的应用程序预计一次从数据库加载和分析成千上万行患者数据，并且在高峰负载下预计扩展到 100-200 万行。您想要调试应用程序，并找出在这种负载下的性能特征，但是您没有任何真实数据，因为数据还处于收集阶段。

在这种情况下，生成和返回模拟数据的库或函数非常有用。在本节中，我们将使用第三方 Python 库来实现这一点。

#### 生成随机患者数据

假设，对于一个患者，我们需要以下基本字段：

+   姓名

+   年龄

+   性别

+   健康问题

+   医生的姓名

+   血型

+   有无保险

+   最后一次就医日期

Python 中的`schematics`库提供了一种使用简单类型生成这些数据结构的方法，然后可以对其进行验证、转换和模拟。

`schematics`是一个可通过以下命令使用`pip`安装的库：

```py
$ pip install schematics

```

要生成只有姓名和年龄的人的模型，只需在`schematics`中编写一个类即可：

```py
from schematics import Model
from schematics.types import StringType, DecimalType

class Person(Model):
    name = StringType()
    age = DecimalType()
```

生成模拟数据时，返回一个模拟对象，并使用此对象创建一个*primitive*：

```py
>>> Person.get_mock_object().to_primitive()
{'age': u'12', 'name': u'Y7bnqRt'}
>>> Person.get_mock_object().to_primitive()
{'age': u'1', 'name': u'xyrh40EO3'}

```

可以使用 Schematics 创建自定义类型。例如，对于*Patient*模型，假设我们只对 18-80 岁的年龄组感兴趣，因此需要返回该范围内的年龄数据。

以下自定义类型为我们做到了这一点：

```py
from schematics.types import IntType

class AgeType(IntType):
    """ An age type for schematics """

    def __init__(self, **kwargs):
        kwargs['default'] = 18
        IntType.__init__(self, **kwargs)

    def to_primitive(self, value, context=None):
        return random.randrange(18, 80)
```

此外，由于 Schematics 库返回的姓名只是随机字符串，还有改进的空间。以下的`NameType`类通过返回包含元音和辅音巧妙混合的姓名来改进：

```py
import string
import random

class NameType(StringType):
    """ A schematics custom name type """

    vowels='aeiou'
    consonants = ''.join(set(string.ascii_lowercase) - set(vowels))

    def __init__(self, **kwargs):
        kwargs['default'] = ''
        StringType.__init__(self, **kwargs)

   def get_name(self):
        """ A random name generator which generates
        names by clever placing of vowels and consontants """

        items = ['']*4

        items[0] = random.choice(self.consonants)
        items[2] = random.choice(self.consonants)

        for i in (1, 3):
            items[i] = random.choice(self.vowels)            

        return ''.join(items).capitalize()

    def to_primitive(self, value, context=None):
        return self.get_name()
```

将这两种新类型结合起来后，我们的`Person`类在返回模拟数据时看起来更好：

```py
class Person(Model):
    name = NameType()
    age = AgeType()
```

```py
>>> Person.get_mock_object().to_primitive()
{'age': 36, 'name': 'Qixi'}
>>> Person.get_mock_object().to_primitive()
{'age': 58, 'name': 'Ziru'}
>>> Person.get_mock_object().to_primitive()
{'age': 32, 'name': 'Zanu'}

```

以类似的方式，很容易提出一组自定义类型和标准类型，以满足*Patient*模型所需的所有字段：

```py
class GenderType(BaseType):
    """A gender type for schematics """

    def __init__(self, **kwargs):
        kwargs['choices'] = ['male','female']
        kwargs['default'] = 'male'
        BaseType.__init__(self, **kwargs)

class ConditionType(StringType):
    """ A gender type for a health condition """

    def __init__(self, **kwargs):
        kwargs['default'] = 'cardiac'
        StringType.__init__(self, **kwargs)     

    def to_primitive(self, value, context=None):
        return random.choice(('cardiac',
                              'respiratory',
                              'nasal',
                              'gynec',
                              'urinal',
                              'lungs',
                              'thyroid',
                              'tumour'))

import itertools

class BloodGroupType(StringType):
    """ A blood group type for schematics  """

    def __init__(self, **kwargs):
        kwargs['default'] = 'AB+'
        StringType.__init__(self, **kwargs)

    def to_primitive(self, value, context=None):
        return ''.join(random.choice(list(itertools.product(['AB','A','O','B'],['+','-']))))    
```

现在，将所有这些与一些标准类型和默认值结合到一个*Patient*模型中，我们得到以下代码：

```py
class Patient(Model):
    """ A model class for patients """

    name = NameType()
    age = AgeType()
    gender = GenderType()
    condition = ConditionType()
    doctor = NameType()
    blood_group = BloodGroupType()
    insured = BooleanType(default=True)
    last_visit = DateTimeType(default='2000-01-01T13:30:30')
```

现在，创建任意大小的随机数据就像在*Patient*类上调用`get_mock_object`方法一样简单：

```py
patients = map(lambda x: Patient.get_mock_object().to_primitive(), range(n))

```

例如，要创建 10,000 个随机患者数据，我们可以使用以下方法：

```py
>>> patients = map(lambda x: Patient.get_mock_object().to_primitive(), range(1000))

```

这些数据可以作为模拟数据输入到处理函数中，直到真实数据可用为止。

### 注意

注意：Python 中的 Faker 库也可用于生成各种假数据，如姓名、地址、URI、随机文本等。

现在让我们从这些简单的技巧和技术转移到更复杂的内容，主要是配置应用程序中的日志记录。

# 作为调试技术的日志记录

Python 自带了对日志记录的标准库支持，通过名为`logging`的模块。虽然可以使用打印语句作为快速和简陋的调试工具，但现实生活中的调试大多需要系统或应用程序生成一些日志。日志记录是有用的，因为有以下原因：

+   日志通常保存在特定的日志文件中，通常带有时间戳，并在服务器上保留一段时间，直到它们被轮换出去。这使得即使程序员在发生问题一段时间后进行调试，调试也变得容易。

+   可以在不同级别进行日志记录，从基本的 INFO 到冗长的 DEBUG 级别，改变应用程序输出的信息量。这使程序员能够在不同级别的日志记录中进行调试，提取他们想要的信息，并找出问题所在。

+   可以编写自定义记录器，可以将日志记录到各种输出。在最基本的情况下，日志记录是写入日志文件的，但也可以编写将日志记录到套接字、HTTP 流、数据库等的记录器。

## 简单的应用程序日志记录

在 Python 中配置简单的日志记录相当容易，如下所示：

```py
>>> import logging
>>> logging.warning('I will be back!')
WARNING:root:I will be back!

>>> logging.info('Hello World')
>>>

```

执行前面的代码不会发生任何事情，因为默认情况下，`logging`被配置为**WARNING**级别。但是，很容易配置日志以更改其级别。

以下代码将日志记录更改为以`info`级别记录，并添加一个目标文件来保存日志：

```py
>>> logging.basicConfig(filename='application.log', level=logging.DEBUG)
>>> logging.info('Hello World')

```

如果我们检查`application.log`文件，我们会发现它包含以下行：

```py
INFO:root:Hello World

```

为了在日志行中添加时间戳，我们需要配置日志格式。可以按以下方式完成：

```py
>>> logging.basicConfig(format='%(asctime)s %(message)s')

```

结合起来，我们得到最终的日志配置如下：

```py
>>> logging.basicConfig(format='%(asctime)s %(message)s', filename='application.log', level=logging.DEBUG)
>>> logging.info('Hello World!')

```

现在，`application.log`的内容看起来像下面这样：

```py
INFO:root:Hello World
2016-12-26 19:10:37,236 Hello World!

```

日志支持变量参数，用于向作为第一个参数提供的模板字符串提供参数。

逗号分隔的参数的直接日志记录不起作用。例如：

```py
>>> import logging
>>> logging.basicConfig(level=logging.DEBUG)
>>> x,y=10,20
>>> logging.info('Addition of',x,'and',y,'produces',x+y)
--- Logging error ---
Traceback (most recent call last):
 **File "/usr/lib/python3.5/logging/__init__.py", line 980, in emit
 **msg = self.format(record)
 **File "/usr/lib/python3.5/logging/__init__.py", line 830, in format
 **return fmt.format(record)
 **File "/usr/lib/python3.5/logging/__init__.py", line 567, in format
 **record.message = record.getMessage()
 **File "/usr/lib/python3.5/logging/__init__.py", line 330, in getMessage
 **msg = msg % self.args
TypeError: not all arguments converted during string formatting
Call stack:
 **File "<stdin>", line 1, in <module>
Message: 'Addition of'
Arguments: (10, 'and', 20, 'produces', 30)

```

但是，我们可以使用以下方法：

```py
>>> logging.info('Addition of %s and %s produces %s',x,y,x+y)
INFO:root:Addition of 10 and 20 produces 30

```

之前的例子运行得很好。

## 高级日志记录-记录器对象

直接使用`logging`模块进行日志记录在大多数简单情况下都可以工作。但是，为了从`logging`模块中获得最大的价值，我们应该使用记录器对象。它还允许我们执行许多自定义操作，比如自定义格式化程序、自定义处理程序等。

让我们编写一个返回这样一个自定义记录器的函数。它接受应用程序名称、日志级别和另外两个选项-日志文件名和是否打开控制台日志记录：

```py
import logging
def create_logger(app_name, logfilename=None, 
                             level=logging.INFO, console=False):

    """ Build and return a custom logger. Accepts the application name,
    log filename, loglevel and console logging toggle """

    log=logging.getLogger(app_name)
    log.setLevel(logging.DEBUG)
    # Add file handler
    if logfilename != None:
        log.addHandler(logging.FileHandler(logfilename))

    if console:
        log.addHandler(logging.StreamHandler())

    # Add formatter
    for handle in log.handlers:
        formatter = logging.Formatter('%(asctime)s : %(levelname)-8s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        handle.setFormatter(formatter)

    return log
```

让我们检查一下这个函数：

1.  不直接使用`logging`，而是使用`logging.getLogger`工厂函数创建一个`logger`对象。

1.  默认情况下，`logger`对象是无用的，因为它没有配置任何处理程序。处理程序是流包装器，负责将日志记录到特定流，如控制台、文件、套接字等。

1.  在这个记录器对象上进行配置，比如设置级别（通过`setLevel`方法）和添加处理程序，比如用于记录到文件的`FileHandler`和用于记录到控制台的`StreamHandler`。

1.  日志消息的格式化是在处理程序上完成的，而不是在记录器对象本身上完成的。我们使用`YY-mm-dd HH:MM:SS`的日期格式作为时间戳的标准格式。

让我们看看它的运行情况：

```py
>>> log=create_logger('myapp',logfilename='app.log', console=True)
>>> log
<logging.Logger object at 0x7fc09afa55c0>
>>> log.info('Started application')
2016-12-26 19:38:12 : INFO     - Started application
>>> log.info('Initializing objects...')
2016-12-26 19:38:25 : INFO     - Initializing objects…

```

在同一目录中检查 app.log 文件会发现以下内容：

```py
2016-12-26 19:38:12 : INFO    —Started application
2016-12-26 19:38:25 : INFO    —Initializing objects…

```

### 高级日志记录-自定义格式和记录器

我们看了如何根据我们的要求创建和配置记录器对象。有时，需要超越并在日志行中打印额外的数据，这有助于调试。

在调试应用程序中经常出现的一个常见问题，特别是那些对性能至关重要的应用程序，就是找出每个函数或方法需要多少时间。尽管可以通过使用性能分析器对应用程序进行性能分析等方法来找出这一点，并且通过使用之前讨论过的一些技术，如计时器上下文管理器，很多时候，可以编写一个自定义记录器来实现这一点。

假设您的应用程序是一个业务列表 API 服务器，响应类似于我们在前一节中讨论的列表 API 请求。当它启动时，需要初始化一些对象并从数据库加载一些数据。

假设作为性能优化的一部分，您已经调整了这些例程，并希望记录这些例程需要多少时间。我们将看看是否可以编写一个自定义记录器来为我们完成这项工作：

```py
import logging
import time
from functools import partial

class LoggerWrapper(object):
    """ A wrapper class for logger objects with
    calculation of time spent in each step """

    def __init__(self, app_name, filename=None, 
                       level=logging.INFO, console=False):
        self.log = logging.getLogger(app_name)
        self.log.setLevel(level)

        # Add handlers
        if console:
            self.log.addHandler(logging.StreamHandler())

        if filename != None:
            self.log.addHandler(logging.FileHandler(filename))

        # Set formatting
        for handle in self.log.handlers:

          formatter = logging.Formatter('%(asctime)s [%(timespent)s]: %(levelname)-8s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')                                   
             handle.setFormatter(formatter)

        for name in ('debug','info','warning','error','critical'):
            # Creating convenient wrappers by using functools
            func = partial(self._dolog, name)
            # Set on this class as methods
            setattr(self, name, func)

        # Mark timestamp
        self._markt = time.time()

    def _calc_time(self):
        """ Calculate time spent so far """

        tnow = time.time()
        tdiff = int(round(tnow - self._markt))

        hr, rem = divmod(tdiff, 3600)
        mins, sec = divmod(rem, 60)
        # Reset mark
        self._markt = tnow
        return '%.2d:%.2d:%.2d' % (hr, mins, sec)

    def _dolog(self, levelname, msg, *args, **kwargs):
        """ Generic method for logging at different levels """

        logfunc = getattr(self.log, levelname)
        return logfunc(msg, *args, extra={'timespent': self._calc_time()})         
```

我们已经构建了一个名为`LoggerWrapper`的自定义类。让我们分析一下代码并看看它的作用：

1.  这个类的`__init__`方法与之前编写的`create_logger`函数非常相似。它接受相同的参数，构造处理程序对象，并配置`logger`。但是，这一次，`logger`对象是外部`LoggerWrapper`实例的一部分。

1.  格式化程序接受一个名为`timespent`的额外变量模板。

1.  似乎没有定义直接的日志记录方法。但是，使用部分函数技术，我们在不同级别的日志记录中包装`_dolog`方法，并将它们动态地设置为类的`logging`方法，使用`setattr`。

1.  `_dolog`方法通过使用标记时间戳来计算每个例程中花费的时间——第一次初始化，然后在每次调用时重置。花费的时间使用一个名为 extra 的字典参数发送到日志记录方法。

让我们看看应用程序如何使用这个记录器包装器来测量关键例程中花费的时间。以下是一个假设使用 Flask Web 应用程序的示例：

```py
    # Application code
    log=LoggerWrapper('myapp', filename='myapp.log',console=True)

    app = Flask(__name__)
    log.info("Starting application...")
    log.info("Initializing objects.")
    init()
    log.info("Initialization complete.")
    log.info("Loading configuration and data …")
    load_objects()
    log.info('Loading complete. Listening for connections …')
    mainloop()
```

请注意，花费的时间在时间戳之后的方括号内记录。

假设最后的代码产生了以下输出：

```py
2016-12-26 20:08:28 [00:00:00]: INFO    —Starting application...
2016-12-26 20:08:28 [00:00:00]: INFO     - Initializing objects.
2016-12-26 20:08:42 [00:00:14]: INFO     - Initialization complete.
2016-12-26 20:08:42 [00:00:00]: INFO     - Loading configuration and data ...
2016-12-26 20:10:37 [00:01:55]: INFO     - Loading complete. Listening for connections

```

从日志行可以明显看出，初始化花费了 14 秒，而配置和数据的加载花费了 1 分 55 秒。

通过添加类似的日志行，您可以快速而相当准确地估计应用程序关键部分的时间。保存在日志文件中，另一个额外的优势是您不需要特别计算和保存它在其他地方。

### 注意

使用这个自定义记录器，请注意，显示为给定日志行花费的时间是在前一行例程中花费的时间。

### 高级日志记录——写入 syslog

像 Linux 和 Mac OS X 这样的 POSIX 系统有一个系统日志文件，应用程序可以写入。通常，该文件存在为`/var/log/syslog`。让我们看看如何配置 Python 日志记录以写入系统日志文件。

您需要做的主要更改是向记录器对象添加系统日志处理程序，如下所示：

```py
log.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))
```

让我们修改我们的`create_logger`函数，使其能够写入`syslog`，并查看完整的代码运行情况：

```py
import logging
import logging.handlers

def create_logger(app_name, logfilename=None, level=logging.INFO, 
                             console=False, syslog=False):
    """ Build and return a custom logger. Accepts the application name,
    log filename, loglevel and console logging toggle and syslog toggle """

    log=logging.getLogger(app_name)
    log.setLevel(logging.DEBUG)
    # Add file handler
    if logfilename != None:
        log.addHandler(logging.FileHandler(logfilename))

    if syslog:
        log.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))

    if console:
        log.addHandler(logging.StreamHandler())

    # Add formatter
    for handle in log.handlers:
        formatter = logging.Formatter('%(asctime)s : %(levelname)-8s - %(message)s',  datefmt='%Y-%m-%d %H:%M:%S')
        handle.setFormatter(formatter)                             

    return log
```

现在让我们尝试创建一个记录器，同时记录到`syslog`：

```py
>>> create_logger('myapp',console=True, syslog=True)
>>> log.info('Myapp - starting up…')
```

让我们检查 syslog，看看它是否真的被记录了下来：

```py
$ tail -3 /var/log/syslog
Dec 26 20:39:54 ubuntu-pro-book kernel: [36696.308437] psmouse serio1: TouchPad at isa0060/serio1/input0 - driver resynced.
Dec 26 20:44:39 ubuntu-pro-book 2016-12-26 20:44:39 : INFO     - Myapp - starting up...
Dec 26 20:45:01 ubuntu-pro-book CRON[11522]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)

```

输出显示它确实做到了。

# 调试工具——使用调试器

大多数程序员倾向于将*调试*视为他们应该使用调试器进行的事情。在本章中，我们迄今为止已经看到，调试不仅仅是一门精确的科学，而且是一门艺术，可以使用许多技巧和技术来完成，而不是直接跳到调试器。然而，迟早，我们期望在本章中遇到调试器——现在就是时候了！

Python 调试器，或者称为 pdb，是 Python 运行时的一部分。

可以在从头开始运行脚本时调用 Pdb，如下所示：

```py
$ python3 -m pdb script.py

```

然而，程序员通常调用 pdb 的最常见方式是在代码中想要进入调试器的地方插入以下行：

```py
import pdb; pdb.set_trace()
```

让我们使用这个，并尝试调试本章第一个示例的一个实例，也就是最大子数组的和。我们将调试代码的`O(n)`版本作为示例：

```py
def max_subarray(sequence):
    """ Maximum subarray - optimized version """

    max_ending_here = max_so_far = 0
    for x in sequence:
        # Enter the debugger
        import pdb; pdb.set_trace()
        max_ending_here = max(0, max_ending_here + x)
        max_so_far = max(max_so_far, max_ending_here)

    return max_so_far
```

## 使用 pdb 进行调试会话

在程序运行后立即进入调试器的第一个循环中：

```py
>>> max_subarray([20, -5, -10, 30, 10])
> /home/user/programs/maxsubarray.py(8)max_subarray()
-> max_ending_here = max(0, max_ending_here + x)
-> for x in sequence:
(Pdb) max_so_far
20

```

您可以使用(*s*)来停止执行。Pdb 将执行当前行，并停止：

```py
> /home/user/programs/maxsubarray.py(7)max_subarray()
-> max_ending_here = max(0, max_ending_here + x)

```

您可以通过简单地输入变量名称并按[*Enter*]来检查变量：

```py
(Pdb) max_so_far
20

```

可以使用(*w*)或 where 打印当前堆栈跟踪。箭头(→)表示当前堆栈帧：

```py
(Pdb) w

<stdin>(1)<module>()
> /home/user/programs/maxsubarray.py(7)max_subarray()
-> max_ending_here = max(0, max_ending_here + x)

```

可以使用(*c*)或 continue 继续执行，直到下一个断点：

```py
> /home/user/programs/maxsubarray.py(6)max_subarray()
-> for x in sequence:
(Pdb) max_so_far
20
(Pdb) c
> /home/user/programs/maxsubarray.py(6)max_subarray()
-> for x in sequence:
(Pdb) max_so_far
20
(Pdb) c
> /home/user/programs/maxsubarray.py(6)max_subarray()
-> for x in sequence:
(Pdb) max_so_far
35
(Pdb) max_ending_here
35

```

在前面的代码中，我们继续了`for`循环的三次迭代，直到最大值从 20 变为 35。让我们检查一下我们在序列中的位置：

```py
(Pdb) x
30

```

我们还有一个项目要在列表中完成，即最后一个项目。让我们使用(*l*)或`list`命令来检查此时的源代码：

```py
(Pdb) l
  1     
  2     def max_subarray(sequence):
  3         """ Maximum subarray - optimized version """
  4     
  5         max_ending_here = max_so_far = 0
  6  ->     for x in sequence:
  7             max_ending_here = max(0, max_ending_here + x)
  8             max_so_far = max(max_so_far, max_ending_here)
  9             import pdb; pdb.set_trace()
 10     
 11         return max_so_far
```

可以使用(*u*)或`up`和(*d*)或*down*命令在堆栈帧上下移动：

```py
(Pdb) up
> <stdin>(1)<module>()
(Pdb) up
*** Oldest frame
(Pdb) list
[EOF]
(Pdb) d
> /home/user/programs/maxsubarray.py(6)max_subarray()
-> for x in sequence:

```

现在让我们从函数中返回：

```py
(Pdb) r
> /home/user/programs/maxsubarray.py(6)max_subarray()
-> for x in sequence:
(Pdb) r
--Return--
> /home/user/programs/maxsubarray.py(11)max_subarray()->45
-> return max_so_far

```

函数的返回值是*45*。

Pdb 有很多其他命令，不仅限于我们在这里介绍的内容。但是，我们不打算让本次会话成为一个完整的 pdb 教程。有兴趣的程序员可以参考网络上的文档以了解更多信息。

## Pdb-类似的工具

Python 社区已经构建了许多有用的工具，这些工具是在 pdb 的基础上构建的，但添加了更多有用的功能、开发者的易用性，或者两者兼而有之。

### iPdb

iPdb 是启用 iPython 的 pdb。它导出函数以访问 iPython 调试器。它还具有制表完成、语法高亮和更好的回溯和内省方法。

iPdb 可以通过 pip 安装。

以下屏幕截图显示了使用 iPdb 进行调试会话，与之前使用 pdb 相同的功能。注意**iPdb**提供的语法高亮：

![iPdb](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00523.jpeg)

iPdb 在操作中，显示语法高亮

还要注意，iPdb 提供了比 pdb 更完整的堆栈跟踪：

![iPdb](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00524.jpeg)

iPdb 在操作中，显示比 pdb 更完整的堆栈跟踪

请注意，iPdb 使用 iPython 作为默认运行时，而不是 Python。

### Pdb++

Pdb++是 pdb 的一个替代品，具有类似于 iPdb 的功能，但它适用于默认的 Python 运行时，而不需要 iPython。Pdb++也可以通过 pip 安装。

安装 pdb++后，它将接管所有导入 pdb 的地方，因此根本不需要更改代码。

Pdb++进行智能命令解析。例如，如果变量名与标准 Pdb 命令冲突，pdb 将优先显示变量内容而不是命令。Pdb++能够智能地解决这个问题。

以下是显示 Pdb++在操作中的屏幕截图，包括语法高亮、制表完成和智能命令解析：

![Pdb++](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00525.jpeg)

Pdb++在操作中-请注意智能命令解析，其中变量 c 被正确解释

# 高级调试-跟踪

从一开始跟踪程序的执行通常可以作为一种高级调试技术。跟踪允许开发人员跟踪程序执行，找到调用者/被调用者关系，并找出程序运行期间执行的所有函数。

## 跟踪模块

Python 自带了一个默认的`trace`模块作为其标准库的一部分。

trace 模块接受`-trace`、`--count`或`-listfuncs`选项之一。第一个选项跟踪并打印所有源行的执行情况。第二个选项生成一个文件的注释列表，显示语句执行的次数。后者简单地显示程序运行期间执行的所有函数。

以下是使用`trace`模块的`-trace`选项调用子数组问题的屏幕截图：

![trace 模块](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00526.jpeg)

通过使用其-trace 选项，可以使用 trace 模块跟踪程序执行。

正如您所看到的，*trace*模块跟踪了整个程序执行过程，逐行打印代码行。由于大部分代码都是`for`循环，您实际上会看到循环中的代码行被打印出循环执行的次数（五次）。

`-trackcalls`选项跟踪并打印调用者和被调用函数之间的关系。

trace 模块还有许多其他选项，例如跟踪调用、生成带注释的文件列表、报告等。我们不会对这些进行详尽的讨论，因为读者可以参考 Web 上有关此模块的文档以获取更多信息。

## lptrace 程序

在调试服务器并尝试在生产环境中查找性能或其他问题时，程序员需要的通常不是由*trace*模块提供的 Python 系统或堆栈跟踪，而是实时附加到进程并查看正在执行哪些函数。

### 注意

lptrace 可以使用 pip 安装。请注意，它不适用于**Python3**。

`lptrace`包允许您执行此操作。它不是提供要运行的脚本，而是通过其进程 ID 附加到正在运行 Python 程序的现有进程，例如运行服务器、应用程序等。

在下面的屏幕截图中，您可以看到* lptrace *调试我们在第八章中开发的 Twisted 聊天服务器，*架构模式- Pythonic 方法*实时。会话显示了客户端 andy 连接时的活动：

![lptrace 程序](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00527.jpeg)

lptrace 命令调试 Twisted 中的聊天服务器

有很多日志行，但您可以观察到一些 Twisted 协议的众所周知的方法被记录，例如客户端连接时的**connectionMade**。还可以看到接受来自客户端的连接的 Socket 调用，例如*accept*。

## 使用 strace 进行系统调用跟踪

`Strace`是一个 Linux 命令，允许用户跟踪运行程序调用的系统调用和信号。它不仅适用于 Python，还可以用于调试任何程序。Strace 可以与 lptrace 结合使用，以便就其系统调用进行故障排除。

`Strace`与*lptrace*类似，可以附加到正在运行的进程。它也可以被调用以从命令行运行进程，但在附加到服务器等进程时更有用。

例如，此屏幕截图显示了附加到我们的聊天服务器时的 strace 输出：

![使用 strace 进行系统调用跟踪](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00528.jpeg)

附加到 Twisted 聊天服务器的 strace 命令

*strace*命令证实了服务器正在等待**epoll**句柄以接收连接的`lptrace`命令的结论。

这是客户端连接时发生的情况：

![使用 strace 进行系统调用跟踪](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00529.jpeg)

strace 命令显示客户端连接到 Twisted 聊天服务器的系统调用

Strace 是一个非常强大的工具，可以与特定于运行时的工具（例如 Python 的 lptrace）结合使用，以便在生产环境中进行高级调试。

# 总结

在本章中，我们学习了使用 Python 的不同调试技术。我们从简单的*print*语句开始，然后使用*continue*语句在循环中进行简单的调试技巧，以及在代码块之间 strategically placed `sys.exit` 调用等。

然后，我们详细讨论了一些调试技术，特别是模拟和随机化数据。讨论了文件缓存和 Redis 等内存数据库的技术，并提供了示例。

使用 Python schematics 库的示例显示了在医疗保健领域的假设应用程序中生成随机数据。

接下来的部分是关于日志记录及其作为调试技术的使用。我们讨论了使用*logging*模块进行简单日志记录，使用`logger`对象进行高级日志记录，并通过创建具有自定义格式的日志记录函数内部所花费时间的记录器包装器来结束讨论。我们还学习了一个写入 syslog 的示例。

本章的结尾专门讨论了调试工具。您学习了 pdb，Python 调试器的基本命令，并快速了解了提供更好体验的类似工具，即 iPdb 和 Pdb++。我们在本章结束时简要讨论了诸如 lptrace 和 Linux 上无处不在的*strace*程序之类的跟踪工具。

这就是本章和本书的结论。
