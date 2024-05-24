# 精通 Python 并发（三）

> 原文：[`zh.annas-archive.org/md5/9D7D3F09D4C6183257545C104A0CAC2A`](https://zh.annas-archive.org/md5/9D7D3F09D4C6183257545C104A0CAC2A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：使用 asyncio 构建通信渠道

通信渠道是计算机科学领域中应用并发性的重要组成部分。在本章中，我们将介绍传输的基本理论，这些理论是由`asyncio`模块提供的类，以便抽象各种形式的通信渠道。我们还将介绍 Python 中简单回显服务器-客户端逻辑的实现，以进一步说明`asyncio`和通信系统中并发性的使用。这个例子的代码将成为本书后面出现的一个高级例子的基础。

本章将涵盖以下主题：

+   通信渠道的基础知识以及将异步编程应用于它们

+   如何使用`asyncio`和`aiohttp`在 Python 中构建异步服务器

+   如何异步地向多个服务器发出请求，并处理异步文件的读取和写入

# 技术要求

以下是本章的先决条件列表：

+   确保您的计算机上已安装 Python 3

+   确保您的计算机上已安装 Telnet

+   确保您已经在您的 Python 3 发行版中安装了 Python 模块`aiohttp`

+   在[`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python)下载 GitHub 存储库

+   在本章中，我们将使用名为`Chapter11`的子文件夹

+   查看以下视频以查看代码的实际操作：[`bit.ly/2FMwKL8`](http://bit.ly/2FMwKL8)

# 通信渠道的生态系统

通信渠道用于表示不同系统之间的物理接线连接和促进计算机网络的逻辑数据通信。在本章中，我们只关注后者，因为这是与计算相关的问题，更与异步编程的概念相关。在本节中，我们将讨论通信渠道的一般结构，以及该结构中与异步编程特别相关的两个特定元素。

# 通信协议层

大多数通过通信渠道进行的数据传输过程都是通过**开放系统互连**（**OSI**）模型协议层来实现的。OSI 模型规定了系统间通信过程中的主要层和主题。

以下图表显示了 OSI 模型的一般结构：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/8ddd0769-bc8d-4cf0-95ab-05baf817c9aa.png)

OSI 模型结构

如前图所示，数据传输过程中有七个主要的通信层，具有不同程度的计算级别。我们不会详细介绍每个层的目的和具体功能，但重要的是您要理解媒体和主机层背后的一般思想。

底层的三个层包含与通信渠道的底层操作相当相关的操作。物理和数据链路层的操作包括编码方案、访问方案、低级错误检测和纠正、位同步等。这些操作用于在传输数据之前实现和指定数据的处理和准备逻辑。另一方面，网络层处理从一个系统（例如服务器）到另一个系统（例如客户端）的数据包转发，通过确定接收者的地址和数据传输路径。

另一方面，顶层处理高级数据通信和操作。在这些层中，我们将专注于传输层，因为它直接被`asyncio`模块用于实现通信渠道。这一层通常被视为媒体层和主机层（例如客户端和服务器）之间的概念性过渡，负责在不同系统之间的端到端连接中发送数据。此外，由于数据包（由网络层准备）可能在传输过程中由于网络错误而丢失或损坏，传输层还负责通过错误检测代码中的方法检测这些错误。

其他主机层实现处理、解释和提供来自另一个系统发送的数据的机制。在从传输层接收数据后，会话层处理身份验证、授权和会话恢复过程。表示层然后将相同的数据进行翻译并重新组织成可解释的表示形式。最后，应用层以用户友好的格式显示数据。

# 通信渠道的异步编程

鉴于异步编程的性质，编程模型可以提供与有效促进通信渠道的过程相辅相成的功能，这并不奇怪。以 HTTP 通信为例，服务器可以异步处理多个客户端；当它在等待特定客户端发出 HTTP 请求时，它可以切换到另一个客户端并处理该客户端的请求。同样，如果客户端需要向多个服务器发出 HTTP 请求，并且必须等待某些服务器的大型响应，它可以处理更轻量级的响应，这些响应已经被处理并首先发送回客户端。以下图表显示了服务器和客户端在 HTTP 请求中如何异步地相互交互：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/d3a27a5c-2ea2-4165-ad7b-83439d70ec22.png)

异步交错的 HTTP 请求

# 在 asyncio 中的传输和协议

`asyncio`模块提供了许多不同的传输类。实质上，这些类是在前一节讨论的传输层功能的实现。您已经知道传输层在通信渠道中发挥着重要作用；因此，传输类给`asyncio`（因此也给开发人员）更多控制权，以实现我们自己的通信渠道的过程。

`asyncio`模块将传输的抽象与异步程序的实现结合在一起。特别是，尽管传输是通信渠道的核心元素，但为了利用传输类和其他相关的通信渠道工具，我们需要初始化和调用事件循环，这是`asyncio.AbstractEventLoop`类的一个实例。事件循环本身将创建传输并管理低级通信过程。

重要的是要注意，在`asyncio`中建立的通信渠道中，`transport`对象始终与`asyncio.Protocol`类的实例相关联。正如其名称所示，`Protocol`类指定了通信渠道使用的基础协议；对于与另一个系统建立的每个连接，将创建此类的新协议对象。在与`transport`对象密切合作时，协议对象可以从`transport`对象调用各种方法；这是我们可以实现通信渠道的具体内部工作的地方。

因此，通常在构建连接通道时，我们需要专注于实现`asyncio.Protocol`子类及其方法。换句话说，我们使用`asyncio.Protocol`作为父类来派生一个满足通信通道需求的子类。为此，我们在自定义协议子类中覆盖`asyncio.Protocol`基类中的以下方法：

+   `Protocol.connection_made(transport)`: 每当来自另一个系统的连接建立时，将自动调用此方法。`transport`参数保存与连接相关联的`transport`对象。同样，每个`transport`都需要与协议配对；我们通常将此`transport`对象作为特定协议对象的属性存储在`connection_made()`方法中。

+   `Protocol.data_received(data)`: 每当我们连接的系统发送其数据时，将自动调用此方法。请注意，`data`参数中保存的发送信息通常以字节表示，因此在进一步处理`data`之前应使用 Python 的`encode()`函数。

接下来，让我们考虑来自`asyncio`传输类的重要方法。所有传输类都继承自一个名为`asyncio.BaseTransport`的父传输类，对于该类，我们有以下常用方法：

+   `BaseTransport.get_extra_info()`: 此方法返回调用的`transport`对象的额外通道特定信息，正如其名称所示。结果可以包括有关与该传输相关联的套接字、管道和子进程的信息。在本章后面，我们将调用`BaseTransport.get_extra_info('peername')`，以获取传输的远程地址。

+   `BaseTransport.close()`: 此方法用于关闭调用的`transport`对象，之后不同系统之间的连接将被停止。传输的相应协议将自动调用其`connection_lost()`方法。

在许多传输类的实现中，我们将专注于`asyncio.WriteTransport`类，它再次继承自`BaseTransport`类的方法，并且还实现了其他用于实现仅写传输功能的方法。在这里，我们将使用`WriteTransport.write()`方法，该方法将写入我们希望通过`transport`对象与另一个系统通信的数据。作为`asyncio`模块的一部分，此方法不是阻塞函数；相反，它以异步方式缓冲并发送已写入的数据。

# `asyncio`服务器客户端的大局观

您已经了解到异步编程，特别是`asyncio`，可以显著改善通信通道的执行。您还看到了在实现异步通信通道时需要使用的特定方法。在我们深入研究 Python 中的一个工作示例之前，让我们简要讨论一下我们试图实现的大局观，或者换句话说，我们程序的一般结构。

正如前面提到的，我们需要实现`asyncio.Protocol`的子类来指定通信通道的基本组织。同样，在每个异步程序的核心都有一个事件循环，因此我们还需要在协议类的上下文之外创建一个服务器，并在程序的事件循环中启动该服务器。这个过程将设置整个服务器的异步架构，并且可以通过`asyncio.create_server()`方法来完成，我们将在接下来的示例中进行讨论。

最后，我们将使用`AbstractEventLoop.run_forever()`方法永久运行我们异步程序的事件循环。与实际的服务器类似，我们希望保持服务器运行，直到遇到问题，然后我们将优雅地关闭服务器。以下图表说明了整个过程：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/5a5d7c16-ff13-4ee0-9eb3-9a55389b7bdb.png)

通信通道中的异步程序结构

# Python 示例

现在，让我们看一个具体的 Python 示例，实现了一个促进异步通信的服务器。从 GitHub 页面（[`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python)）下载本书的代码，并转到`Chapter11`文件夹。

# 启动服务器

在`Chapter11/example1.py`文件中，让我们来看一下`EchoServerClientProtocol`类，如下所示：

```py
# Chapter11/example1.py

import asyncio

class EchoServerClientProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def data_received(self, data):
        message = data.decode()
        print('Data received: {!r}'.format(message))
```

在这里，我们的`EchoServerClientProtocol`类是`asyncio.Protocol`的子类。正如我们之前讨论的那样，在这个类的内部，我们需要实现`connection_made(transport)`和`data_received(data)`方法。在`connection_made()`方法中，我们简单地通过`get_extra_info()`方法（使用`'peername'`参数）获取连接系统的地址，打印出带有该信息的消息，并最终将`transport`对象存储在类的属性中。为了在`data_received()`方法中打印出类似的消息，我们再次使用`decode()`方法从字节数据中获取一个字符串对象。

让我们继续看一下我们脚本的主程序，如下所示：

```py
# Chapter11/example1.py

loop = asyncio.get_event_loop()
coro = loop.create_server(EchoServerClientProtocol, '127.0.0.1', 8888)
server = loop.run_until_complete(coro)

# Serve requests until Ctrl+C is pressed
print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
```

我们使用熟悉的`asyncio.get_event_loop()`函数为我们的异步程序创建一个事件循环。然后，我们通过让该事件循环调用`create_server()`方法来为我们的通信创建一个服务器；这个方法接受`asyncio.Protocol`类的子类、服务器的地址（在本例中是本地主机：`127.0.0.1`）以及该地址的端口（通常为`8888`）。

请注意，这个方法并不会创建服务器本身；它只会异步地启动创建服务器的过程，并返回一个完成该过程的协程。因此，我们需要将该方法返回的协程存储在一个变量中（在我们的例子中是`coro`），并让我们的事件循环运行该协程。在使用服务器对象的`sockets`属性打印出一条消息之后，我们将事件循环永远运行，以保持服务器运行，除非出现`KeyboardInterrupt`异常。

最后，在我们的程序结束时，我们将处理脚本的清理部分，即优雅地关闭服务器。这通常是通过让服务器对象调用`close()`方法（启动服务器关闭过程）并使用事件循环在服务器对象上运行`wait_closed()`方法来完成的，以确保服务器正确关闭。最后，我们关闭事件循环。

# 安装 Telnet

在运行我们的示例 Python 程序之前，我们必须安装 Telnet 程序，以便正确模拟客户端和服务器之间的连接通道。Telnet 是一个提供终端命令的程序，用于促进双向交互式的文本通信协议。如果您的计算机上已经安装了 Telnet，只需跳过下一节；否则，请在本节中找到适合您系统的信息。

在 Windows 系统中，Telnet 已经安装，但可能未启用。要启用它，您可以使用“打开或关闭 Windows 功能”窗口，并确保 Telnet 客户端框被选中，或者运行以下命令：

```py
dism /online /Enable-Feature /FeatureName:TelnetClient
```

Linux 系统通常预装了 Telnet，因此如果您拥有 Linux 系统，只需继续下一节。

在 macOS 系统中，Telnet 可能已经安装在您的计算机上。如果没有，您需要通过软件包管理软件 Homebrew 进行安装，如下所示：

```py
brew install telnet
```

请注意，macOS 系统确实有一个预安装的 Telnet 替代品，称为 Netcat。如果您不希望在 macOS 计算机上安装 Telnet，只需在以下示例中使用`nc`命令而不是`telnet`，即可实现相同的效果。

# 模拟连接通道

运行以下服务器示例有多个步骤。首先，我们需要运行脚本以启动服务器，从中您将获得以下输出：

```py
> python example1.py
Serving on ('127.0.0.1', 8888)
```

请注意，程序将一直运行，直到您调用*Ctrl* + *C*键组合。在一个终端（这是我们的服务器终端）中仍在运行程序的情况下，打开另一个终端并连接到指定端口（`8888`）的服务器（`127.0.0.1`）；这将作为我们的客户端终端：

```py
telnet 127.0.0.1 8888
```

现在，您将在服务器和客户端终端中看到一些变化。很可能，您的客户端终端将有以下输出：

```py
> telnet 127.0.0.1 8888
Trying 127.0.0.1...
Connected to localhost.
```

这是 Telnet 程序的界面，它表示我们已成功连接到本地服务器。更有趣的输出在我们的服务器终端上，它将类似于以下内容：

```py
> python example1.py
Serving on ('127.0.0.1', 8888)
Connection from ('127.0.0.1', 60332)
```

请记住，这是我们在`EchoServerClientProtocol`类中实现的信息消息，具体在`connection_made()`方法中。同样，当服务器与新客户端之间建立连接时，将自动调用此方法，以启动通信。从输出消息中，我们知道客户端正在从服务器`127.0.0.1`的端口`60332`发出请求（与运行服务器相同，因为它们都是本地的）。

我们在`EchoServerClientProtocol`类中实现的另一个功能是在`data_received()`方法中。具体来说，我们打印从客户端发送的解码数据。要模拟这种类型的通信，只需在客户端终端中输入一条消息，然后按*Return*（对于 Windows，按*Enter*）键。您将不会在客户端终端输出中看到任何更改，但服务器终端应该打印出一条消息，如我们协议类的`data_received()`方法中指定的那样。

例如，当我从客户端终端发送消息`Hello, World!`时，以下是我的服务器终端输出：

```py
> python example1.py
Serving on ('127.0.0.1', 8888)
Connection from ('127.0.0.1', 60332)
Data received: 'Hello, World!\r\n'
```

`\r`和`\n`字符只是消息字符串中包含的返回字符。使用我们当前的协议，您可以向服务器发送多条消息，甚至可以让多个客户端向服务器发送消息。要实现这一点，只需打开另一个终端并再次连接到本地服务器。您将从服务器终端看到，不同的客户端（来自不同的端口）已连接到服务器，而服务器与旧客户端的原始通信仍在维持。这是异步编程实现的另一个结果，允许多个客户端与同一服务器无缝通信，而无需使用线程或多进程。

# 将消息发送回客户端

因此，在我们当前的示例中，我们能够使我们的异步服务器接收、读取和处理来自客户端的消息。但是，为了使我们的通信渠道有用，我们还希望从服务器向客户端发送消息。在本节中，我们将更新我们的服务器到一个回显服务器，根据定义，它将发送从特定客户端接收到的任何和所有数据回到客户端。

为此，我们将使用`asyncio.WriteTransport`类的`write()`方法。请查看`EchoServerClientProtocol`类的`data_received()`方法中的`Chapter11/example2.py`文件，如下所示：

```py
# Chapter11/example2.py

import asyncio

class EchoServerClientProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def data_received(self, data):
        message = data.decode()
        print('Data received: {!r}'.format(message))

        self.transport.write(('Echoed back: {}'.format(message)).encode())

loop = asyncio.get_event_loop()
coro = loop.create_server(EchoServerClientProtocol, '127.0.0.1', 8888)
server = loop.run_until_complete(coro)

# Serve requests until Ctrl+C is pressed
print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
```

在从`transport`对象接收数据并将其打印出来后，我们向`transport`对象写入相应的消息，该消息将返回给原始客户端。通过运行`Chapter11/example2.py`脚本，并模拟上一个例子中使用 Telnet 或 Netcat 实现的相同通信，您会发现在客户端终端输入消息后，客户端会收到服务器的回显消息。在启动通信通道并输入`Hello, World!`消息后，以下是我的输出：

```py
> telnet 127.0.0.1 8888
Trying 127.0.0.1...
Connected to localhost.
Hello, World!
Echoed back: Hello, World!
```

本质上，这个例子说明了通过自定义的`asyncio.Protocol`类，我们可以实现双向通信通道的能力。在运行服务器时，我们可以获取从连接到服务器的各个客户端发送的数据，处理数据，最终将所需的结果发送回适当的客户端。

# 关闭传输

有时，我们会希望强制关闭通信通道中的传输。例如，即使使用异步编程和其他形式的并发，您的服务器可能会因来自多个客户端的不断通信而不堪重负。另一方面，当服务器达到最大容量时，完全处理一些发送的请求并明确拒绝其余请求是不可取的。

因此，我们可以在服务器上为每个连接指定在成功通信后关闭连接，而不是为每个连接保持通信开放。我们将通过使用`BaseTransport.close()`方法来强制关闭调用的`transport`对象，从而停止服务器和特定客户端之间的连接。同样，我们将修改`Chapter11/example3.py`中`EchoServerClientProtocol`类的`data_received()`方法如下：

```py
# Chapter11/example3.py

import asyncio

class EchoServerClientProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def data_received(self, data):
        message = data.decode()
        print('Data received: {!r}'.format(message))

        self.transport.write(('Echoed back: {}'.format(message)).encode())

        print('Close the client socket')
        self.transport.close()

loop = asyncio.get_event_loop()
coro = loop.create_server(EchoServerClientProtocol, '127.0.0.1', 8888)
server = loop.run_until_complete(coro)

# Serve requests until Ctrl+C is pressed
print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
```

运行脚本，尝试连接到指定的服务器，并输入一些消息，以查看我们实现的更改。使用我们当前的设置，客户端连接并向服务器发送消息后，将收到回显消息，并且其与服务器的连接将被关闭。以下是我在使用当前协议模拟此过程后获得的输出（同样来自 Telnet 程序的界面）：

```py
> telnet 127.0.0.1 8888
Trying 127.0.0.1...
Connected to localhost.
Hello, World!
Echoed back: Hello, World!
Connection closed by foreign host.
```

# 使用 aiohttp 进行客户端通信

在之前的章节中，我们涵盖了使用`asyncio`模块实现异步通信通道的示例，主要是从通信过程的服务器端的角度。换句话说，我们一直在考虑处理和处理来自外部系统的请求。然而，这只是方程式的一面，我们还有客户端通信的另一面要探索。在本节中，我们将讨论应用异步编程来向服务器发出请求。

正如您可能已经猜到的那样，这个过程的最终目标是通过异步向这些系统发出请求，有效地从外部系统中收集数据。我们将重新讨论网络爬虫的概念，即自动化对各种网站进行 HTTP 请求并从其 HTML 源代码中提取特定信息的过程。如果您尚未阅读第五章，*并发网络请求*，我强烈建议在继续本节之前阅读该章，因为该章涵盖了网络爬虫的基本思想和其他相关重要概念。

在本节中，您还将了解另一个支持异步编程选项的模块：`aiohttp`（代表**异步 I/O HTTP**）。该模块提供了简化 HTTP 通信过程的高级功能，并且与`asyncio`模块无缝配合，以便进行异步编程。

# 安装 aiohttp 和 aiofiles

`aiohttp`模块不会预装在您的 Python 发行版中；然而，类似于其他包，您可以通过使用`pip`或`conda`命令轻松安装该模块。我们还将安装另一个模块`aiofiles`，它可以促进异步文件写入。如果您使用`pip`作为您的包管理器，只需运行以下命令：

```py
pip install aiohttp
pip install aiofiles
```

如果您想使用 Anaconda，请运行以下命令：

```py
conda install aiohttp
conda install aiofiles
```

始终要确认您已成功安装了一个包，打开您的 Python 解释器并尝试导入模块。在这种情况下，运行以下代码：

```py
>>> import aiohttp
>>> import aiofiles
```

如果包已成功安装，将不会出现错误消息。

# 获取网站的 HTML 代码

首先，让我们看一下如何使用`aiohttp`从单个网站发出请求并获取 HTML 源代码。请注意，即使只有一个任务（一个网站），我们的应用程序仍然是异步的，并且异步程序的结构仍然需要实现。现在，导航到`Chapter11/example4.py`文件，如下所示：

```py
# Chapter11/example4.py

import aiohttp
import asyncio

async def get_html(session, url):
    async with session.get(url, ssl=False) as res:
        return await res.text()

async def main():
    async with aiohttp.ClientSession() as session:
        html = await get_html(session, 'http://packtpub.com')
        print(html)

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```

首先考虑`main()`协程。我们在上下文管理器中初始化了一个`aiohttp.ClientSession`类的实例；请注意，我们还在这个声明前面加上了`async`关键字，因为整个上下文块本身也将被视为一个协程。在这个块内部，我们调用并等待`get_html()`协程进行处理和返回。

将注意力转向`get_html()`协程，我们可以看到它接受一个会话对象和一个要从中提取 HTML 源代码的网站的 URL。在这个函数内部，我们另外使用了一个异步上下文管理器，用于发出`GET`请求并将来自服务器的响应存储到`res`变量中。最后，我们返回存储在响应中的 HTML 源代码；由于响应是从`aiohttp.ClientSession`类返回的对象，其方法是异步函数，因此在调用`text()`函数时需要指定`await`关键字。

当您运行程序时，将打印出 Packt 网站的整个 HTML 源代码。例如，以下是我的输出的一部分：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/a5fb1256-d1a8-42fd-981b-6fe29204e1e1.png)

来自 aiohttp 的 HTML 源代码

# 异步写文件

大多数情况下，我们希望通过向多个网站发出请求来收集数据，并且简单地打印出响应的 HTML 代码是不合适的（出于许多原因）；相反，我们希望将返回的 HTML 代码写入输出文件。实质上，这个过程是异步下载，也是流行的下载管理器的底层架构中实现的。为此，我们将使用`aiofiles`模块，结合`aiohttp`和`asyncio`。

导航到`Chapter11/example5.py`文件。首先，我们将看一下`download_html()`协程，如下所示：

```py
# Chapter11/example5.py

async def download_html(session, url):
    async with session.get(url, ssl=False) as res:
        filename = f'output/{os.path.basename(url)}.html'

        async with aiofiles.open(filename, 'wb') as f:
            while True:
                chunk = await res.content.read(1024)
                if not chunk:
                    break
                await f.write(chunk)

        return await res.release()
```

这是上一个示例中`get_html()`协程的更新版本。现在，我们不再使用`aiohttp.ClientSession`实例来发出`GET`请求并打印返回的 HTML 代码，而是使用`aiofiles`模块将 HTML 代码写入文件。例如，为了便于异步文件写入，我们使用`aiofiles`的异步`open()`函数来在上下文管理器中读取文件。此外，我们使用`read()`函数以异步方式按块读取返回的 HTML，使用响应对象的`content`属性；这意味着在读取当前响应的`1024`字节后，执行流将被释放回事件循环，并且将发生任务切换事件。

这个示例的`main()`协程和主程序与我们上一个示例中的相对相同：

```py
async def main(url):
    async with aiohttp.ClientSession() as session:
        await download_html(session, url)

urls = [
    'http://packtpub.com',
    'http://python.org',
    'http://docs.python.org/3/library/asyncio',
    'http://aiohttp.readthedocs.io',
    'http://google.com'
]

loop = asyncio.get_event_loop()
loop.run_until_complete(
    asyncio.gather(*(main(url) for url in urls))
)
```

`main()`协程接收一个 URL，并将其传递给`download_html()`协程，同时传入一个`aiohttp.ClientSession`实例。最后，在我们的主程序中，我们创建一个事件循环，并将指定的 URL 列表中的每个项目传递给`main()`协程。运行程序后，输出应该类似于以下内容，尽管运行程序所需的时间可能会有所不同：

```py
> python3 example5.py
Took 0.72 seconds.
```

此外，在`Chapter11`文件夹内会有一个名为`output`的子文件夹，其中将填充我们 URL 列表中每个网站的下载 HTML 代码。同样，这些文件是通过`aiofiles`模块的功能异步创建和写入的，这是我们之前讨论过的。如您所见，为了比较这个程序及其对应的同步版本的速度，我们还在跟踪整个程序运行所需的时间。

现在，转到`Chapter11/example6.py`文件。这个脚本包含了我们当前程序的同步版本的代码。具体来说，它按顺序对各个网站进行 HTTP `GET`请求，并且文件写入的过程也是按顺序实现的。这个脚本产生了以下输出：

```py
> python3 example6.py
Took 1.47 seconds.
```

尽管它达到了相同的结果（下载 HTML 代码并将其写入文件），但我们的顺序程序花费的时间明显比其异步对应版本多得多。

# 总结

数据传输过程中有七个主要的通信层，具有不同程度的计算级别。媒体层包含与通信通道的底层过程交互的相当低级别的操作，而主机层处理高级数据通信和操作。在这七个层中，传输层通常被视为媒体层和主机层之间的概念性过渡，负责在不同系统之间的端到端连接中发送数据。异步编程可以提供补充有效促进通信通道的过程的功能。

在服务器方面，`asyncio`模块将传输的抽象与异步程序的实现结合在一起。具体来说，通过其`BaseTransport`和`BaseProtocol`类，`asyncio`提供了不同的方式来定制通信通道的底层架构。与`aiohttp`模块一起，`asyncio`在客户端通信过程中提供了效率和灵活性。`aiofiles`模块可以与其他两个异步编程模块一起使用，还可以帮助促进异步文件读取和写入。

我们现在已经探讨了并发编程中最重要的三个主题：线程、多进程和异步编程。我们已经展示了它们如何应用于各种编程问题，并在速度上提供了显著的改进。在本书的下一章中，我们将开始讨论并发编程对开发人员和程序员常见的问题，从死锁开始。

# 问题

+   什么是通信通道？它与异步编程有什么联系？

+   OSI 模型协议层有哪两个主要部分？它们各自的目的是什么？

+   传输层是什么？它对通信通道为什么至关重要？

+   `asyncio`如何促进服务器端通信通道的实现？

+   `asyncio`如何促进客户端通信通道的实现？

+   `aiofiles`是什么？

# 进一步阅读

有关更多信息，您可以参考以下链接：

+   *IoT 系统和通信通道*（[bridgera.com/iot-communication-channels/](https://bridgera.com/iot-communication-channels/)），作者：Bridgera

+   *用 Python 自动化无聊的事情：面向完全初学者的实用编程*，No Starch Press，Al. Sweigart

+   *传输和协议*（[docs.python.org/3/library/asyncio-protocol](https://docs.python.org/3/library/asyncio-protocol.html)），Python 文档


# 第十二章：死锁

死锁是并发问题中最常见的问题之一。在本章中，我们将讨论并发编程中死锁的理论原因。我们将涵盖并发中的一个经典同步问题，称为哲学家就餐问题，作为死锁的现实例子。我们还将在 Python 中演示死锁的实际实现。我们将讨论解决该问题的几种方法。本章还将涵盖与死锁相关的活锁概念，这是并发编程中相对常见的问题。

本章将涵盖以下主题：

+   死锁的概念，以及如何在 Python 中模拟它

+   死锁的常见解决方案，以及如何在 Python 中实现它们

+   活锁的概念，以及它与死锁的关系

# 技术要求

以下是本章的先决条件列表：

+   确保您的计算机上安装了 Python 3

+   在[`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python)下载 GitHub 存储库

+   在本章中，我们将使用名为**`Chapter12`**的子文件夹进行工作

+   查看以下视频以查看代码的实际操作：[`bit.ly/2r2WKaU`](http://bit.ly/2r2WKaU)

# 死锁的概念

在计算机科学领域，死锁指的是并发编程中的一种特定情况，即程序无法取得进展并且陷入当前状态。在大多数情况下，这种现象是由于不同锁对象之间的协调不足或处理不当（用于线程同步目的）。在本节中，我们将讨论一个被称为哲学家就餐问题的思想实验，以阐明死锁及其原因的概念；从那里，您将学习如何在 Python 并发程序中模拟该问题。

# 哲学家就餐问题

哲学家就餐问题最初是由 Edgar Dijkstra（正如您在**第一章**中学到的那样，*并发和并行编程的高级介绍*是并发编程的领先先驱）在 1965 年首次提出的。该问题最初使用不同的技术术语（计算机系统中的资源争用）进行演示，并且后来由 Tony Hoare 重新表述，他是一位英国计算机科学家，也是快速排序算法的发明者。问题陈述如下。

五位哲学家围坐在一张桌子旁，每个人面前都有一碗食物。在这五碗食物之间放着五把叉子，所以每个哲学家左边和右边都有一把叉子。这个设置由以下图表演示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/4d3213aa-ee0f-4d22-a967-af295e8e34b5.png)

哲学家就餐问题的插图

每位沉默的哲学家都要在思考和进餐之间交替。每位哲学家需要周围的两把叉子才能够拿起自己碗里的食物，而且一把叉子不能被两个或更多不同的哲学家共享。当一个哲学家吃完一定量的食物后，他们需要把两把叉子放回原来的位置。在这一点上，那位哲学家周围的哲学家将能够使用那些叉子。

由于哲学家们是沉默的，无法相互交流，因此他们没有方法让彼此知道他们需要叉子来吃饭。换句话说，哲学家吃饭的唯一方法是已经有两把叉子可供他们使用。这个问题的问题是设计一组指令，使哲学家能够有效地在进餐和思考之间切换，以便每个哲学家都能得到足够的食物。

现在，解决这个问题的一个潜在方法可能是以下一组指令：

1.  哲学家必须思考，直到他们左边的叉子可用。当这种情况发生时，哲学家就要拿起它。

1.  哲学家必须思考，直到他们右边的叉子可用。当这种情况发生时，哲学家就要拿起它。

1.  如果一个哲学家手里拿着两个叉子，他们会从面前的碗里吃一定量的食物，然后以下情况将适用：

+   之后，哲学家必须把右边的叉子放回原来的位置

+   之后，哲学家必须把左边的叉子放回原来的位置。

1.  过程从第一个项目重复。

很明显，这一系列指令如何导致无法取得进展的情况；也就是说，如果一开始所有哲学家都同时开始执行他们的指令。由于一开始所有叉子都在桌子上，因此附近的哲学家可以拿起叉子执行第一个指令（拿起左边的叉子）。

现在，经过这一步，每个哲学家都会用左手拿着一个叉子，桌子上不会剩下叉子。由于没有哲学家手里同时拿着两个叉子，他们无法开始吃饭。此外，他们得到的指令集规定，只有在哲学家吃了一定量的食物后，才能把叉子放在桌子上。这意味着只要哲学家没有吃饭，他们就不会放下手里的叉子。

因此，每个哲学家只用左手拿着一个叉子，无法开始吃饭或放下手里的叉子。哲学家能吃饭的唯一时机是邻座的哲学家放下叉子，而这只有在他们自己能吃饭的情况下才可能发生；这造成了一个永无止境的条件循环，无法满足。这种情况本质上就是死锁的特性，系统中的所有元素都被困在原地，无法取得进展。

# 并发系统中的死锁

考虑到餐桌哲学家问题的例子，让我们考虑死锁的正式概念以及相关的理论。给定一个具有多个线程或进程的并发程序，如果一个进程（或线程）正在等待另一个进程持有并使用的资源，而另一个进程又在等待另一个进程持有的资源，那么执行流程就会陷入死锁。换句话说，进程在等待只有在执行完成后才能释放的资源时，无法继续执行其指令；因此，这些进程无法改变其执行状态。

死锁还由并发程序需要同时具备的条件来定义。这些条件最初由计算机科学家 Edward G. Coffman, Jr.提出，因此被称为 Coffman 条件。这些条件如下：

+   至少有一个资源必须处于不可共享的状态。这意味着资源被一个单独的进程（或线程）持有，其他人无法访问；资源只能被单个进程（或线程）在任何给定时间内访问和持有。这种情况也被称为互斥。

+   存在一个同时访问资源并等待其他进程（或线程）持有的进程（或线程）。换句话说，这个进程（或线程）需要访问两个资源才能执行其指令，其中一个已经持有，另一个则需要等待其他进程（或线程）释放。这种情况称为持有和等待。

+   资源只能由持有它们的进程（或线程）释放，如果有特定的指令要求进程（或线程）这样做。这就是说，除非进程（或线程）自愿主动释放资源，否则该资源将保持在不可共享的状态。这就是无抢占条件。

+   最终的条件称为循环等待。正如名称所示，该条件指定存在一组进程（或线程），使得该组中的第一个进程（或线程）处于等待状态，等待第二个进程（或线程）释放资源，而第二个进程（或线程）又需要等待第三个进程（或线程）；最后，该组中的最后一个进程（或线程）等待第一个进程。

让我们快速看一个死锁的基本例子。考虑一个并发程序，其中有两个不同的进程（进程**A**和进程**B**），以及两个不同的资源（资源**R1**和资源**R2**），如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/e440b909-cfa2-4257-9c5c-6ab2a8eb71e2.png)

样本死锁图

这两个资源都不能在不同的进程之间共享，并且每个进程都需要访问这两个资源来执行其指令。以进程**A**为例。它已经持有资源**R1**，但它还需要**R2**来继续执行。然而，**R2**无法被进程**A**获取，因为它被进程**B**持有。因此，进程**A**无法继续。进程**B**也是一样，它持有**R2**，并且需要**R1**来继续。而**R1**又被进程**A**持有。

# Python 模拟

在本节中，我们将在一个实际的 Python 程序中实现前面的情况。具体来说，我们将有两个锁（我们将它们称为锁 A 和锁 B），以及两个分开的线程与锁交互（线程 A 和线程 B）。在我们的程序中，我们将设置这样一种情况：线程 A 已经获取了锁 A，并且正在等待获取锁 B，而锁 B 已经被线程 B 获取，并且正在等待锁 A 被释放。

如果您已经从 GitHub 页面下载了本书的代码，请转到`Chapter12`文件夹。让我们考虑`Chapter12/example1.py`文件，如下所示：

```py
# Chapter12/example1.py

import threading
import time

def thread_a():
    print('Thread A is starting...')

    print('Thread A waiting to acquire lock A.')
    lock_a.acquire()
    print('Thread A has acquired lock A, performing some calculation...')
    time.sleep(2)

    print('Thread A waiting to acquire lock B.')
    lock_b.acquire()
    print('Thread A has acquired lock B, performing some calculation...')
    time.sleep(2)

    print('Thread A releasing both locks.')
    lock_a.release()
    lock_b.release()

def thread_b():
    print('Thread B is starting...')

    print('Thread B waiting to acquire lock B.')
    lock_b.acquire()
    print('Thread B has acquired lock B, performing some calculation...')
    time.sleep(5)

    print('Thread B waiting to acquire lock A.')
    lock_a.acquire()
    print('Thread B has acquired lock A, performing some calculation...')
    time.sleep(5)

    print('Thread B releasing both locks.')
    lock_b.release()
    lock_a.release()

lock_a = threading.Lock()
lock_b = threading.Lock()

thread1 = threading.Thread(target=thread_a)
thread2 = threading.Thread(target=thread_b)

thread1.start()
thread2.start()

thread1.join()
thread2.join()

print('Finished.')
```

在这个脚本中，`thread_a()`和`thread_b()`函数分别指定了我们的线程 A 和线程 B。在我们的主程序中，我们还有两个`threading.Lock`对象：锁 A 和锁 B。线程指令的一般结构如下：

1.  启动线程

1.  尝试获取与线程名称相同的锁（线程 A 将尝试获取锁 A，线程 B 将尝试获取锁 B）

1.  执行一些计算

1.  尝试获取另一个锁（线程 A 将尝试获取锁 B，线程 B 将尝试获取锁 A）

1.  执行一些其他计算

1.  释放两个锁

1.  结束线程

请注意，我们使用`time.sleep()`函数来模拟一些计算正在进行的动作。

首先，我们几乎同时启动线程 A 和线程 B，在主程序中。考虑到线程指令集的结构，我们可以看到此时两个线程将被启动；线程 A 将尝试获取锁 A，并且会成功，因为此时锁 A 仍然可用。线程 B 和锁 B 也是一样。然后两个线程将继续进行一些计算。

让我们考虑一下我们程序的当前状态：锁 A 已被线程 A 获取，锁 B 已被线程 B 获取。在它们各自的计算过程完成后，线程 A 将尝试获取锁 B，线程 B 将尝试获取锁 A。我们很容易看出这是我们死锁情况的开始：由于锁 B 已经被线程 B 持有，并且无法被线程 A 获取，出于同样的原因，线程 B 也无法获取锁 A。

现在，两个线程将无限等待，以获取它们各自的第二个锁。然而，锁能够被释放的唯一方式是线程继续执行指令并在最后释放它所持有的所有锁。因此，我们的程序将在这一点上被卡住，不会再有进展。

以下图表进一步说明了死锁是如何按顺序展开的。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/bd657a2f-bc26-424b-a3ef-06c0bd441ffa.png)

死锁序列图

现在，让我们看看我们创建的死锁是如何发生的。运行脚本，你应该会得到以下输出：

```py
> python example1.py
Thread A is starting...
Thread A waiting to acquire lock A.
Thread B is starting...
Thread A has acquired lock A, performing some calculation...
Thread B waiting to acquire lock B.
Thread B has acquired lock B, performing some calculation...
Thread A waiting to acquire lock B.
Thread B waiting to acquire lock A.
```

正如我们讨论过的，由于每个线程都试图获取另一个线程当前持有的锁，而锁能够被释放的唯一方式是线程继续执行。这就是死锁，你的程序将无限挂起，永远无法到达程序最后一行的最终打印语句。

# 死锁情况的方法

正如我们所见，死锁会导致我们的并发程序陷入无限挂起，这在任何情况下都是不可取的。在本节中，我们将讨论预防死锁发生的潜在方法。直觉上，每种方法都旨在消除程序中的四个 Coffman 条件之一，以防止死锁发生。

# 实现资源之间的排名

从哲学家就餐问题和我们的 Python 示例中，我们可以看到四个 Coffman 条件中的最后一个条件，循环等待，是死锁问题的核心。它指定了并发程序中不同进程（或线程）等待其他进程（或线程）持有的资源的循环方式。仔细观察后，我们可以看到这种条件的根本原因是进程（或线程）访问资源的顺序（或缺乏顺序）。

在哲学家就餐问题中，每个哲学家都被指示首先拿起左边的叉子，而在我们的 Python 示例中，线程总是在执行任何计算之前尝试获取同名的锁。正如你所见，当哲学家们想同时开始就餐时，他们会拿起各自左边的叉子，并陷入无限等待；同样，当两个线程同时开始执行时，它们将获取各自的锁，然后再次无限等待另一个锁。

我们可以从中得出的结论是，如果进程（或线程）不是任意地访问资源，而是按照预定的静态顺序访问它们，那么它们获取和等待资源的循环性质将被消除。因此，对于我们的两把锁 Python 示例，我们将要求两个线程以相同的顺序尝试获取锁。例如，现在两个线程将首先尝试获取锁 A，进行一些计算，然后尝试获取锁 B，进行进一步的计算，最后释放两个线程。

这个改变是在`Chapter12/example2.py`文件中实现的，如下所示：

```py
# Chapter12/example2.py

import threading
import time

def thread_a():
    print('Thread A is starting...')

    print('Thread A waiting to acquire lock A.')
    lock_a.acquire()
    print('Thread A has acquired lock A, performing some calculation...')
    time.sleep(2)

    print('Thread A waiting to acquire lock B.')
    lock_b.acquire()
    print('Thread A has acquired lock B, performing some calculation...')
    time.sleep(2)

    print('Thread A releasing both locks.')
    lock_a.release()
    lock_b.release()

def thread_b():
    print('Thread B is starting...')

    print('Thread B waiting to acquire lock A.')
    lock_a.acquire()
    print('Thread B has acquired lock A, performing some calculation...')
    time.sleep(5)

    print('Thread B waiting to acquire lock B.')
    lock_b.acquire()
    print('Thread B has acquired lock B, performing some calculation...')
    time.sleep(5)

    print('Thread B releasing both locks.')
    lock_b.release()
    lock_a.release()

lock_a = threading.Lock()
lock_b = threading.Lock()

thread1 = threading.Thread(target=thread_a)
thread2 = threading.Thread(target=thread_b)

thread1.start()
thread2.start()

thread1.join()
thread2.join()

print('Finished.')
```

这个版本的脚本现在能够完成执行，并应该产生以下输出：

```py
> python3 example2.py
Thread A is starting...
Thread A waiting to acquire lock A.
Thread A has acquired lock A, performing some calculation...
Thread B is starting...
Thread B waiting to acquire lock A.
Thread A waiting to acquire lock B.
Thread A has acquired lock B, performing some calculation...
Thread A releasing both locks.
Thread B has acquired lock A, performing some calculation...
Thread B waiting to acquire lock B.
Thread B has acquired lock B, performing some calculation...
Thread B releasing both locks.
Finished.
```

这种方法有效地消除了我们两把锁示例中的死锁问题，但它对哲学家就餐问题的解决方案有多大的影响呢？为了回答这个问题，让我们尝试自己在 Python 中模拟问题和解决方案。`Chapter12/example3.py`文件包含了 Python 中哲学家就餐问题的实现，如下所示：

```py
# Chapter12/example3.py

import threading

# The philosopher thread
def philosopher(left, right):
    while True:
        with left:
             with right:
                 print(f'Philosopher at {threading.currentThread()} 
                       is eating.')

# The chopsticks
N_FORKS = 5
forks = [threading.Lock() for n in range(N_FORKS)]

# Create all of the philosophers
phils = [threading.Thread(
    target=philosopher,
    args=(forks[n], forks[(n + 1) % N_FORKS])
) for n in range(N_FORKS)]

# Run all of the philosophers
for p in phils:
    p.start()
```

在这里，我们有`philospher()`函数作为我们单独线程的基本逻辑。它接受两个`Threading.Lock`对象，并模拟先前讨论的吃饭过程，使用两个上下文管理器。在我们的主程序中，我们创建了一个名为`forks`的五个锁对象的列表，以及一个名为`phils`的五个线程的列表，规定第一个线程将获取第一个和第二个锁，第二个线程将获取第二个和第三个锁，依此类推；第五个线程将按顺序获取第五个和第一个锁。最后，我们同时启动所有五个线程。

运行脚本，可以很容易地观察到死锁几乎立即发生。以下是我的输出，直到程序无限挂起：

```py
> python3 example3.py
Philosopher at <Thread(Thread-1, started 123145445048320)> is eating.
Philosopher at <Thread(Thread-1, started 123145445048320)> is eating.
Philosopher at <Thread(Thread-1, started 123145445048320)> is eating.
Philosopher at <Thread(Thread-1, started 123145445048320)> is eating.
Philosopher at <Thread(Thread-1, started 123145445048320)> is eating.
Philosopher at <Thread(Thread-1, started 123145445048320)> is eating.
Philosopher at <Thread(Thread-3, started 123145455558656)> is eating.
Philosopher at <Thread(Thread-1, started 123145445048320)> is eating.
Philosopher at <Thread(Thread-3, started 123145455558656)> is eating.
Philosopher at <Thread(Thread-3, started 123145455558656)> is eating.
Philosopher at <Thread(Thread-3, started 123145455558656)> is eating.
Philosopher at <Thread(Thread-3, started 123145455558656)> is eating.
Philosopher at <Thread(Thread-5, started 123145466068992)> is eating.
Philosopher at <Thread(Thread-3, started 123145455558656)> is eating.
Philosopher at <Thread(Thread-3, started 123145455558656)> is eating.
```

接下来自然而然的问题是：我们如何在`philosopher()`函数中实现获取锁的顺序？我们将使用 Python 中内置的`id()`函数，该函数返回参数的唯一常量标识作为排序锁对象的键。我们还将实现一个自定义上下文管理器，以便将这个排序逻辑分离到一个单独的类中。请转到`Chapter12/example4.py`查看具体实现。

```py
# Chapter12/example4.py

class acquire(object):
    def __init__(self, *locks):
        self.locks = sorted(locks, key=lambda x: id(x))

    def __enter__(self):
        for lock in self.locks:
            lock.acquire()

    def __exit__(self, ty, val, tb):
        for lock in reversed(self.locks):
            lock.release()
        return False

# The philosopher thread
def philosopher(left, right):
    while True:
        with acquire(left,right):
             print(f'Philosopher at {threading.currentThread()} 
                   is eating.')
```

在主程序保持不变的情况下，这个脚本将产生一个输出，显示排序的解决方案可以有效解决哲学家就餐问题。

然而，当这种方法应用于某些特定情况时，会出现问题。牢记并发的高级思想，我们知道在将并发应用于程序时的主要目标之一是提高速度。让我们回到我们的两锁示例，检查实现资源排序后程序的执行时间。看一下`Chapter12/example5.py`文件；它只是实现了排序（或有序）锁定的两锁程序，结合了一个计时器，用于跟踪两个线程完成执行所需的时间。

运行脚本后，你的输出应该类似于以下内容：

```py
> python3 example5.py
Thread A is starting...
Thread A waiting to acquire lock A.
Thread B is starting...
Thread A has acquired lock A, performing some calculation...
Thread B waiting to acquire lock A.
Thread A waiting to acquire lock B.
Thread A has acquired lock B, performing some calculation...
Thread A releasing both locks.
Thread B has acquired lock A, performing some calculation...
Thread B waiting to acquire lock B.
Thread B has acquired lock B, performing some calculation...
Thread B releasing both locks.
Took 14.01 seconds.
Finished.
```

你可以看到两个线程的组合执行大约需要 14 秒。然而，如果我们仔细看两个线程的具体指令，除了与锁交互外，线程 A 需要大约 4 秒来进行计算（通过两个`time.sleep(2)`命令模拟），而线程 B 需要大约 10 秒（两个`time.sleep(5)`命令）。

这是否意味着我们的程序花费的时间与我们按顺序执行两个线程时一样长？我们将用`Chapter12/example6.py`文件测试这个理论，在这个文件中，我们规定每个线程应该在主程序中依次执行它的指令：

```py
# Chapter12/example6.py

lock_a = threading.Lock()
lock_b = threading.Lock()

thread1 = threading.Thread(target=thread_a)
thread2 = threading.Thread(target=thread_b)

start = timer()

thread1.start()
thread1.join()

thread2.start()
thread2.join()

print('Took %.2f seconds.' % (timer() - start))
print('Finished.')
```

运行这个脚本，你会发现我们的两锁程序的顺序版本将花费与并发版本相同的时间。

```py
> python3 example6.py
Thread A is starting...
Thread A waiting to acquire lock A.
Thread A has acquired lock A, performing some calculation...
Thread A waiting to acquire lock B.
Thread A has acquired lock B, performing some calculation...
Thread A releasing both locks.
Thread B is starting...
Thread B waiting to acquire lock A.
Thread B has acquired lock A, performing some calculation...
Thread B waiting to acquire lock B.
Thread B has acquired lock B, performing some calculation...
Thread B releasing both locks.
Took 14.01 seconds.
Finished.
```

这个有趣的现象是我们在程序中对锁的严格要求的直接结果。换句话说，由于每个线程都必须获取两个锁才能完成执行，每个锁在任何给定时间内都不能被多个线程获取，最后，需要按特定顺序获取锁，并且单个线程的执行不能同时发生。如果我们回过头来检查`Chapter12/example5.py`文件产生的输出，很明显可以看到线程 B 在线程 A 在执行结束时释放两个锁后无法开始计算。

因此，很直观地得出结论，如果在并发程序的资源上放置了足够多的锁，它将在执行上变得完全顺序化，并且结合并发编程功能的开销，它的速度甚至会比程序的纯顺序版本更糟糕。然而，在餐桌哲学家问题中（在 Python 中模拟），我们没有看到锁所创建的这种顺序性。这是因为在两线程问题中，两个锁足以使程序执行顺序化，而五个锁不足以使餐桌哲学家问题执行顺序化。

我们将在《第十四章》*竞争条件*中探讨这种现象的另一个实例。

# 忽略锁并共享资源

锁无疑是同步任务中的重要工具，在并发编程中也是如此。然而，如果锁的使用导致不良情况，比如死锁，那么我们很自然地会探索在并发程序中简单地不使用锁的选项。通过忽略锁，我们程序的资源有效地在并发程序中的不同进程/线程之间可以共享，从而消除了 Coffman 条件中的第一个条件：互斥。

这种解决死锁问题的方法可能很容易实现；让我们尝试前面的两个例子。在两锁示例中，我们简单地删除了指定与线程函数和主程序中的锁对象的任何交互的代码。换句话说，我们不再使用锁定机制。`Chapter12/example7.py` 文件包含了这种方法的实现，如下所示：

```py
# Chapter12/example7.py

import threading
import time
from timeit import default_timer as timer

def thread_a():
    print('Thread A is starting...')

    print('Thread A is performing some calculation...')
    time.sleep(2)

    print('Thread A is performing some calculation...')
    time.sleep(2)

def thread_b():
    print('Thread B is starting...')

    print('Thread B is performing some calculation...')
    time.sleep(5)

    print('Thread B is performing some calculation...')
    time.sleep(5)

thread1 = threading.Thread(target=thread_a)
thread2 = threading.Thread(target=thread_b)

start = timer()

thread1.start()
thread2.start()

thread1.join()
thread2.join()

print('Took %.2f seconds.' % (timer() - start))

print('Finished.')
```

运行脚本，你的输出应该类似于以下内容：

```py
> python3 example7.py
Thread A is starting...
Thread A is performing some calculation...
Thread B is starting...
Thread B is performing some calculation...
Thread A is performing some calculation...
Thread B is performing some calculation...
Took 10.00 seconds.
Finished.
```

很明显，由于我们不使用锁来限制对任何计算过程的访问，两个线程的执行现在已经完全独立于彼此，因此线程完全并行运行。因此，我们也获得了更好的速度：由于线程并行运行，整个程序所花费的总时间与两个线程中较长任务所花费的时间相同（换句话说，线程 B，10 秒）。

那么餐桌哲学家问题呢？似乎我们也可以得出结论，没有锁（叉子）的情况下，问题可以很容易地解决。由于资源（食物）对于每个哲学家都是独特的（换句话说，没有哲学家应该吃另一个哲学家的食物），因此每个哲学家都可以在不担心其他人的情况下继续执行。通过忽略锁，每个哲学家可以并行执行，类似于我们在两锁示例中看到的情况。

然而，这样做意味着我们完全误解了问题。我们知道锁被利用来让进程和线程可以以系统化、协调的方式访问程序中的共享资源，以避免对数据的错误处理。因此，在并发程序中移除任何锁定机制意味着共享资源的可能性，这些资源现在不受访问限制，被以不协调的方式操纵（因此，变得损坏）的可能性显著增加。

因此，通过忽略锁，我们很可能需要完全重新设计和重构我们的并发程序。如果共享资源仍然需要以有组织的方式访问和操作，就需要实现其他同步方法。我们的进程和线程的逻辑可能需要改变以适当地与这种新的同步方法进行交互，执行时间可能会受到程序结构变化的负面影响，还可能会出现其他潜在的同步问题。

# 关于锁的额外说明

虽然在我们的程序中取消锁定机制以消除死锁的方法可能会引发一些问题和关注，但它确实为我们揭示了 Python 中锁对象的一个新点：在访问给定资源时，一个并发程序的元素完全可以绕过锁。换句话说，锁对象只有在进程/线程实际获取锁对象时，才能阻止不同的进程/线程访问和操作共享资源。

因此，锁实际上并没有锁定任何东西。它们只是标志，帮助指示在给定时间是否应该访问资源；如果一个指令不清晰甚至恶意的进程/线程试图在没有检查锁对象存在的情况下访问该资源，它很可能可以轻松地做到这一点。换句话说，锁根本不与它们应该锁定的资源相关联，它们绝对不会阻止进程/线程访问这些资源。

因此，简单地使用锁来设计和实现安全的、动态的并发数据结构是低效的。为了实现这一点，我们需要在锁和它们对应的资源之间添加更多具体的链接，或者完全利用不同的同步工具（例如原子消息队列）。

# 关于死锁解决方案的结论

您已经看到了解决死锁问题的两种最常见方法。每种方法都解决了四个 Coffman 条件中的一个，虽然两种方法在我们的示例中都（在某种程度上）成功地防止了死锁的发生，但每种方法都引发了不同的额外问题和关注。因此，真正理解您的并发程序的性质非常重要，以便知道这两种方法中的哪一种是适用的，如果有的话。

也有可能，一些程序通过死锁向我们展示出不适合并发的特性；有些程序最好是按顺序执行，如果强制并发可能会变得更糟。正如我们所讨论的，虽然并发在我们应用程序的许多领域中提供了显著的改进，但有些领域本质上不适合并发编程的应用。在死锁的情况下，开发人员应该准备考虑设计并发程序的不同方法，并且在一个并发方法不起作用时不要犹豫地实现另一种方法。

# 活锁的概念

活锁的概念与死锁有关；有些人甚至认为它是死锁的另一种版本。在活锁的情况下，并发程序中的进程（或线程）能够切换它们的状态；事实上，它们不断地切换状态。然而，它们只是无限地来回切换，没有任何进展。现在我们将考虑一个实际的活锁场景。

假设一对夫妇在一起吃晚餐。他们只有一个叉子可以共用，所以在任何给定的时间只有一个人可以吃。此外，夫妇之间非常彬彬有礼，所以即使其中一位饥饿想吃饭，如果另一位也饥饿，他们会把叉子放在桌子上。这个规定是创建这个问题的活锁的核心：当夫妇两个都饥饿时，每个人都会等待另一个先吃饭，从而创建一个无限循环，每个人都在想要吃饭和等待另一位先吃饭之间切换。

让我们在 Python 中模拟这个问题。转到`Chapter12/example8.py`，看一下`Spouse`类：

```py
# Chapter12/example8.py

class Spouse(threading.Thread):

    def __init__(self, name, partner):
        threading.Thread.__init__(self)
        self.name = name
        self.partner = partner
        self.hungry = True

    def run(self):
        while self.hungry:
            print('%s is hungry and wants to eat.' % self.name)

            if self.partner.hungry:
                print('%s is waiting for their partner to eat first...' 
                      % self.name)
            else:
                with fork:
                    print('%s has stared eating.' % self.name)
                    time.sleep(5)

                    print('%s is now full.' % self.name)
                    self.hungry = False
```

这个类继承自`threading.Thread`类，并实现了我们之前讨论的逻辑。它接受一个`Spouse`实例的名称和另一个`Spouse`对象作为其伴侣；初始化时，`Spouse`对象也总是饥饿的（`hungry`属性始终设置为`True`）。类中的`run()`函数指定了线程启动时的逻辑：只要`Spouse`对象的`hungry`属性设置为`True`，对象将尝试使用叉子（一个锁对象）进食。但是，它总是检查其伴侣的`hungry`属性是否也设置为`True`，在这种情况下，它将不会继续获取锁，而是等待其伴侣这样做。

在我们的主程序中，首先将叉子创建为一个锁对象；然后，我们创建两个`Spouse`线程对象，它们分别是彼此的`partner`属性。最后，我们启动两个线程，并运行程序直到两个线程都执行完毕：

```py
# Chapter12/example8.py

fork = threading.Lock()

partner1 = Spouse('Wife', None)
partner2 = Spouse('Husband', partner1)
partner1.partner = partner2

partner1.start()
partner2.start()

partner1.join()
partner2.join()

print('Finished.')
```

运行脚本，您会看到，正如我们讨论的那样，每个线程都会进入一个无限循环，不断地在想要吃饭和等待伴侣吃饭之间切换；程序将永远运行，直到 Python 被中断。以下代码显示了我得到的输出的前几行：

```py
> python3 example8.py
Wife is hungry and wants to eat.
Wife is waiting for their partner to eat first...
Husband is hungry and wants to eat.
Wife is hungry and wants to eat.
Husband is waiting for their partner to eat first...
Wife is waiting for their partner to eat first...
Husband is hungry and wants to eat.
Wife is hungry and wants to eat.
Husband is waiting for their partner to eat first...
Wife is waiting for their partner to eat first...
Husband is hungry and wants to eat.
Wife is hungry and wants to eat.
Husband is waiting for their partner to eat first...
...
```

# 总结

在计算机科学领域，死锁是指并发编程中的一种特定情况，即没有任何进展并且程序被锁定在当前状态。在大多数情况下，这种现象是由于不同锁对象之间缺乏或处理不当的协调引起的，可以用餐厅哲学家问题来说明。

预防死锁发生的潜在方法包括对锁对象施加顺序和通过忽略锁对象共享不可共享的资源。每种解决方案都解决了四个 Coffman 条件中的一个，虽然这两种解决方案都可以成功地防止死锁，但每种解决方案都会引发不同的额外问题和关注点。

与死锁概念相关的是活锁。在活锁情况下，并发程序中的进程（或线程）能够切换它们的状态，但它们只是无休止地来回切换，没有任何进展。在下一章中，我们将讨论并发编程中的另一个常见问题：饥饿。

# 问题

+   什么会导致死锁情况，为什么这是不可取的？

+   餐厅哲学家问题与死锁问题有什么关系？

+   什么是四个 Coffman 条件？

+   资源排序如何解决死锁问题？在实施这一方法时可能会出现哪些其他问题？

+   忽略锁如何解决死锁问题？在实施这一方法时可能会出现哪些其他问题？

+   活锁与死锁有什么关系？

# 进一步阅读

有关更多信息，您可以参考以下链接：

+   *使用 Python 进行并行编程*，作者 Jan. Palach，Packt Publishing Ltd，2014

+   *Python 并行编程食谱*，作者 Giancarlo Zaccone，Packt Publishing Ltd，2015

+   *Python 线程死锁避免*（[dabeaz.blogspot.com/2009/11/python-thread-deadlock-avoidance_20](http://dabeaz.blogspot.com/2009/11/python-thread-deadlock-avoidance_20.html)）


# 第十三章：饥饿

在本章中，我们将讨论并发编程中饥饿的概念及其潜在原因。我们将涵盖一些读者-写者问题，这些问题是饥饿的主要例子，并且我们将在示例 Python 代码中模拟它们。本章还将涵盖死锁和饥饿之间的关系，以及饥饿的一些潜在解决方案。

本章将涵盖以下主题：

+   饥饿背后的基本思想、其根本原因和一些更相关的概念

+   读者-写者问题的详细分析，用于说明并发系统中饥饿的复杂性

# 技术要求

本章的先决条件如下：

+   确保您的计算机上安装了 Python 3

+   在 [`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python) 下载 GitHub 存储库

+   在本章中，我们将使用名为`Chapter13`的子文件夹进行工作

+   查看以下视频以查看代码示例： [`bit.ly/2r3caw8`](http://bit.ly/2r3caw8)

# 饥饿的概念

**饥饿**是并发系统中的一个问题，其中一个进程（或线程）无法获得必要的资源以继续执行，因此无法取得任何进展。在本节中，我们将探讨饥饿情况的特征，分析饥饿的最常见原因，并最后考虑一个示例程序，说明饥饿的情况。

# 什么是饥饿？

并发程序通常会在其执行过程中实现不同进程之间的某种排序。例如，考虑一个具有三个独立进程的程序，如下所示：

+   一个负责处理非常紧急的指令，一旦必要的资源可用就需要立即运行

+   另一个进程负责其他重要的执行，这些执行不像第一个进程中的任务那样重要

+   最后一个处理杂项、非常不频繁的任务

此外，这三个进程需要利用相同的资源来执行各自的指令。

直观地，我们有充分理由实施一个规范，允许第一个进程具有最高的执行优先级和资源访问权限，然后是第二个进程，最后是优先级最低的最后一个进程。然而，想象一下，前两个进程（优先级较高）运行得如此频繁，以至于第三个进程无法执行其指令；每当第三个进程需要运行时，它都会检查资源是否可用，并发现其他优先级更高的进程正在使用它们。

这是一个饥饿的情况：第三个进程没有机会执行，因此，该进程无法取得任何进展。在典型的并发程序中，很常见有多于三个不同优先级的进程，然而情况基本相似：一些进程获得更多运行的机会，因此它们不断执行。其他进程优先级较低，无法访问必要的资源来执行。

# 调度

在接下来的几个小节中，我们将讨论导致饥饿情况的潜在原因。大多数情况下，一组调度指令的协调不佳是饥饿的主要原因。例如，处理三个独立任务的相当天真的算法可能会在前两个任务之间实现不断的通信和交互。

这种设置导致算法的执行流程仅在第一和第二个任务之间切换，而第三个任务发现自己处于空闲状态，无法在执行中取得任何进展；在这种情况下，因为它被剥夺了 CPU 的执行流程。直观地，我们可以确定问题的根源在于算法允许前两个任务始终主导 CPU，因此有效地阻止了任何其他任务也利用 CPU。一个良好调度算法的特征是能够平均和适当地分配执行流程和资源。

如前所述，许多并发系统和程序实现了特定的优先级顺序，以进程和线程的执行为基础。这种有序调度的实现很可能会导致低优先级的进程和线程饥饿，并且可能导致一种称为**优先级倒置**的情况。

假设在您的并发程序中，您有最高优先级的进程 A，中等优先级的进程 B，最后是最低优先级的进程 C；进程 C 很可能会陷入饥饿的情况。此外，如果优先级进程 A 的执行取决于已经处于饥饿状态的进程 C 的完成，那么即使在并发程序中给予了最高优先级，进程 A 也可能永远无法完成其执行。

以下图表进一步说明了优先级倒置的概念：一个从时间**t2**到**t3**运行的高优先级任务需要访问一些资源，而这些资源正在被低优先级任务利用：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/d4c74468-db4a-4a70-88a1-84de39731b88.png)

优先级倒置的图表

再次强调，结合饥饿和优先级倒置可能导致即使高优先级任务也无法执行它们的指令的情况。

# 饥饿的原因

考虑到设计调度算法的复杂性，让我们讨论饥饿的具体原因。我们在前面的部分描述的情况表明了饥饿情况的一些潜在原因。然而，饥饿可能来自多种来源，如下所示：

+   高优先级的进程（或线程）主导着 CPU 的执行流程，因此，低优先级的进程（或线程）没有机会执行它们自己的指令。

+   高优先级的进程（或线程）主导着不可共享资源的使用，因此，低优先级的进程（或线程）没有机会执行它们自己的指令。这种情况类似于第一种情况，但是涉及访问资源的优先级，而不是执行本身的优先级。

+   低优先级的进程（或线程）正在等待资源来执行它们的指令，但是一旦资源变得可用，具有更高优先级的其他进程（或线程）立即获得访问权限，因此低优先级的进程（或线程）将无限等待。

还有其他导致饥饿的原因，但前述是最常见的根本原因。

# 饥饿与死锁的关系

有趣的是，死锁情况也可能导致饥饿，因为饥饿的定义表明，如果有一个进程（或线程）由于无法获得必要的进程而无法取得任何进展，那么该进程（或线程）正在经历饥饿。

回想一下我们的死锁示例，餐桌哲学家问题，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/7477edae-1949-42f9-a756-dbc4ecb6fd28.png)

餐桌哲学家问题的插图

当死锁发生时，没有哲学家可以获得执行他们指令所需的资源（每个哲学家需要两把叉子才能开始吃饭）。处于死锁状态的每个哲学家也处于饥饿状态。

# 读者-写者问题

读者-写者问题是计算机科学领域中经典和最复杂的例子之一，它展示了并发程序中可能出现的问题。通过分析读者-写者问题的不同变体，我们将更多地了解饥饿问题及其常见原因。我们还将在 Python 中模拟这个问题，以便更深入地理解这个问题。

# 问题陈述

在读者-写者问题中，首先，我们有一个共享资源，大多数情况下是一个文本文件。不同的线程与该文本文件交互；每个线程都是读者或写者。**读者**是一个简单地访问共享资源（文本文件）并读取其中包含的数据的线程，而**写者**是一个访问并可能改变文本文件内容的线程。

我们知道写者和读者不能同时访问共享资源，因为如果一个线程正在向文件写入数据，其他线程就不应该访问文件以从中读取任何数据。因此，读者-写者问题的目标是找到一种正确和高效的方式来设计和协调这些读者和写者线程的调度。成功实现这个目标不仅意味着整个程序以最优化的方式执行，而且所有线程都有足够的机会执行它们的指令，不会发生饥饿。此外，需要适当地处理共享资源（文本文件），以便不会损坏数据。

以下图表进一步说明了读者-写者问题的设置：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/6d69fd3c-9f98-4006-9a5a-f3a165eaaab6.png)

读者-写者问题的图表

# 第一个读者-写者问题

正如我们所提到的，这个问题要求我们提出一个调度算法，以便读者和写者可以适当和高效地访问文本文件，而不会错误处理/损坏其中包含的数据。对这个问题的一个天真的解决方案是对文本文件施加锁定，使其成为一个不可共享的资源；这意味着在任何给定时间只有一个线程（无论是读者还是写者）可以访问（并可能操纵）文本文件。

然而，这种方法只是等同于一个顺序程序：如果共享资源一次只能被一个线程使用，不同线程之间的处理时间就不能重叠，实际上，执行变成了顺序的。因此，这不是一个最佳解决方案，因为它没有充分利用并发编程。

关于读者线程的一个见解可以导致对这个问题更优化的解决方案：由于读者只是读取文本文件中的数据而不改变它，可以允许多个读者同时访问文本文件。实际上，即使有多个读者同时从文本文件中获取数据，数据也不会以任何方式改变，因此数据的一致性和准确性得到了维护。

按照这种方法，我们将实现一个规范，其中如果共享资源正在被另一个读者打开进行读取，那么不会让任何读者等待。具体来说，除了对共享资源的锁定，我们还将有一个计数器，用于记录当前正在访问资源的读者数量。如果在程序的任何时刻，该计数器从零增加到一（换句话说，至少有一个读者开始访问资源），我们将锁定资源，使写者无法访问；同样，每当计数器减少到零（换句话说，没有读者请求访问资源），我们将释放对资源的锁定，以便写者可以访问它。

这个规范对读者来说是高效的，因为一旦第一个读者访问了资源并对其进行了锁定，就没有写者可以访问它，而后续的读者在最后一个读者完成对资源的阅读之前不必重新对其进行锁定。

让我们尝试在 Python 中实现这个解决方案。如果你已经从 GitHub 页面下载了本书的代码，请前往`Chapter13`文件夹。让我们看一下`Chapter13/example1.py`文件；具体来说，是`writer()`和`reader()`函数，如下所示：

```py
# Chapter13/example1.py

def writer():
    global text

    while True:
        with resource:
            print(f'Writing being done by 
                   {threading.current_thread().name}.')
            text += f'Writing was done by 
                    {threading.current_thread().name}. '

def reader():
    global rcount

    while True:
        with rcounter:
            rcount += 1
            if rcount == 1:
                resource.acquire()

        print(f'Reading being done by 
               {threading.current_thread().name}:')
        print(text)

        with rcounter:
            rcount -= 1
            if rcount == 0:
                resource.release()
```

在前面的脚本中，`writer()`函数由`threading.Thread`实例（换句话说，一个单独的线程）调用，指定了我们之前讨论的写者线程的逻辑：访问共享资源（在本例中是全局变量`text`，它只是一个 Python 字符串）并向资源写入一些数据。请注意，我们将所有指令放在一个`while`循环中，以模拟应用程序的不断性质（写者和读者不断尝试访问共享资源）。

我们还可以在`reader()`函数中看到读者逻辑。在请求访问共享资源之前，每个读者都会增加一个当前活动并试图访问资源的读者数量的计数器。类似地，在从文件中读取数据后，每个读者都需要减少读者的数量。在这个过程中，如果一个读者是第一个访问文件的读者（换句话说，当计数器为 1 时），它将对文件进行锁定，以便没有写者可以访问它；相反，当一个读者是最后一个读者读取文件时，它必须释放该锁。

关于读者计数器的处理，你可能已经注意到我们在增加/减少计数器变量（`rcount`）时使用了一个名为`rcounter`的锁对象。这是一种方法，用来避免计数器变量的竞争条件，这是另一个常见的并发相关问题；具体来说，没有锁定，多个线程可以同时访问和修改计数器变量，但确保数据的完整性的唯一方法是按顺序处理这个计数器变量。我们将在下一章更详细地讨论竞争条件（以及用于避免它们的实践）。

回到我们当前的脚本，在主程序中，我们将设置`text`变量，读者计数器和两个锁对象（分别用于读者计数器和共享资源）。我们还初始化并启动了三个读者线程和两个写者线程，如下所示：

```py
# Chapter13/example1.py

text = 'This is some text. '
rcount = 0

rcounter = threading.Lock()
resource = threading.Lock()

threads = [threading.Thread(target=reader) for i in range(3)] + [threading.Thread(target=writer) for i in range(2)]

for thread in threads:
    thread.start()
```

重要的是要注意，由于读者和写者线程的指令都包裹在`while`循环中，因此当启动脚本时，它将无限运行。在产生足够的输出以观察程序的一般行为后，应在大约 3-4 秒后取消 Python 执行。

在运行脚本后，以下代码显示了我获得的输出的前几行：

```py
> python3 example1.py
Reading being done by Thread-1:
This is some text. 
Reading being done by Thread-2:
Reading being done by Thread-1:
This is some text. 
This is some text. 
Reading being done by Thread-2:
Reading being done by Thread-1:
This is some text. 
This is some text. 
Reading being done by Thread-3:
Reading being done by Thread-1:
This is some text. 
This is some text. 
...
```

正如你所看到的，在前面的输出中有一个特定的模式：所有访问共享资源的线程都是读者。实际上，在我整个输出中，没有写者能够访问文件，因此`text`变量只包含初始字符串`This is some text.`，并且没有以任何方式进行修改。你获得的输出也应该具有相同的模式（共享资源未被修改）。

在这种情况下，写者们正在经历饥饿，因为他们都无法访问和使用资源。这是我们调度算法的直接结果；由于允许多个读者同时访问文本文件，如果有多个读者频繁访问文本文件，将会创建一个连续的读者流通过文本文件，不给写者尝试访问文件留下空间。

这种调度算法无意中给了读者优先于写者，因此被称为**读者优先**。因此，这种设计是不可取的。

# 第二个读者-写者问题

第一个方法的问题在于，当一个读者正在访问文本文件并且一个写者正在等待文件被解锁时，如果另一个读者开始执行并且想要访问文件，它将优先于已经等待的写者。此外，如果越来越多的读者继续请求访问文件，写者将无限等待，这就是我们在第一个代码示例中观察到的情况。

为了解决这个问题，我们将实现规范，即一旦写者请求访问文件，就不应该有读者能够插队并在该写者之前访问文件。为此，我们将在程序中添加一个额外的锁对象，以指定是否有写者正在等待文件，因此是否读者线程可以尝试读取文件；我们将称这个锁为`read_try`。

与第一个读者总是锁定文本文件不同，我们现在将等待访问文件的多个写者中的第一个写者锁定`read_try`，以便没有读者可以再次在它之前请求访问的那些写者之前插队。正如我们在读者方面讨论的那样，由于我们正在跟踪等待文本文件的写者数量，我们需要在程序中实现写者数量及其相应的锁的计数器。

`Chapter13/example2.py`文件包含了此实现的代码，如下所示：

```py
# Chapter13/example2.py

import threading

def writer():
    global text
    global wcount

    while True:
        with wcounter:
            wcount += 1
            if wcount == 1:
                read_try.acquire()

        with resource:
            print(f'Writing being done by 
                  {threading.current_thread().name}.')
            text += f'Writing was done by 
                  {threading.current_thread().name}. '

        with wcounter:
            wcount -= 1
            if wcount == 0:
                read_try.release()

def reader():
    global rcount

    while True:
        with read_try:
            with rcounter:
                rcount += 1
                if rcount == 1:
                    resource.acquire()

            print(f'Reading being done by 
                  {threading.current_thread().name}:')
            print(text)

            with rcounter:
                rcount -= 1
                if rcount == 0:
                    resource.release()

text = 'This is some text. '
wcount = 0
rcount = 0

wcounter = threading.Lock()
rcounter = threading.Lock()
resource = threading.Lock()
read_try = threading.Lock()

threads = [threading.Thread(target=reader) for i in range(3)] + 
           [threading.Thread(target=writer) for i in range(2)]

for thread in threads:
    thread.start()
```

与我们对问题的第一个解决方案相比，主程序保持相对不变（除了初始化`read_try`锁、`wcount`计数器及其锁`wcounter`之外），但在我们的`writer()`函数中，一旦有至少一个写者等待访问文件，我们就会锁定`read_try`；当最后一个写者完成执行时，它将释放锁，以便任何等待文件的读者现在可以访问它。

再次，为了查看程序产生的输出，我们将让它运行 3-4 秒，然后取消执行，因为程序否则将永远运行。以下是我通过此脚本获得的输出：

```py
> python3 example2.py
Reading being done by Thread-1:
This is some text. 
Reading being done by Thread-1:
This is some text. 
Writing being done by Thread-4.
Writing being done by Thread-5.
Writing being done by Thread-4.
Writing being done by Thread-4.
Writing being done by Thread-4.
Writing being done by Thread-5.
Writing being done by Thread-4.
...
```

可以观察到，虽然一些读者能够访问文本文件（由我的输出的前四行表示），但一旦写者获得对共享资源的访问权，就再也没有读者能够访问它了。我的输出的其余部分包括有关写入指令的消息：`Writing being done by`等等。与我们在读者-写者问题的第一个解决方案中看到的情况相反，这个解决方案给了写者优先权，因此读者被饿死。因此，这被称为**写者优先**。

写者优先于读者的优先级是由于只有第一个和最后一个写者必须分别获取和释放`read_try`锁，而每个想要访问文本文件的读者都必须单独与该锁对象交互。一旦`read_try`被写者锁定，没有读者甚至可以尝试执行其指令，更不用说尝试访问文本文件了。

有些情况下，如果读者在写者之前初始化并执行（例如，在我们的程序中，读者是前三个元素，写者是线程列表中的最后两个），则一些读者可以访问文本文件。然而，一旦写者能够在执行期间访问文件并获取`read_try`锁，读者很可能会饿死。

这种解决方案也不理想，因为它在我们的程序中给了写者线程更高的优先级。

# 第三个读者-写者问题

你已经看到我们尝试实现的两种解决方案都可能导致饥饿，因为没有给予不同线程相等的优先级；一种可能会使写入者饿死，另一种可能会使读者饿死。这两种方法之间的平衡可能会给我们一个实现，使读者和写者之间具有相等的优先级，从而解决饥饿问题。

回想一下：在我们的第二种方法中，我们在读者尝试访问文本文件时放置了一个锁，要求一旦写者开始等待文件，就不会使其饿死。在这个解决方案中，我们将实现一个锁，该锁也利用这种逻辑，但然后应用于读者和写者。然后，所有线程将受到锁的约束，因此在不同线程之间将实现相等的优先级。

具体来说，这是一个锁，指定在特定时刻是否允许线程访问文本文件；我们将其称为**服务锁**。每个写者或读者在执行任何指令之前都必须尝试获取此服务锁。写者在获得此服务锁后，还将尝试获取资源锁，并立即释放服务锁。然后，写者将执行其写入逻辑，并最终在执行结束时释放资源锁。

让我们看一下`Chapter13/example3.py`文件中我们在 Python 中的实现的`writer()`函数，如下所示：

```py
# Chapter13/example3.py

def writer():
    global text

    while True:
        with service:
            resource.acquire()

        print(f'Writing being done by 
              {threading.current_thread().name}.')
        text += f'Writing was done by 
              {threading.current_thread().name}. '

        resource.release()
```

另一方面，读者也需要首先获取服务锁。由于我们仍然允许多个读者同时访问资源，我们正在实现读者计数器及其相应的锁。

读者将获取服务锁和计数器锁，增加读者计数器（可能锁定资源），然后依次释放服务锁和计数器锁。现在，它将实际从文本文件中读取数据，最后，它将减少读者计数器，并在那时是最后一个读者访问文件时，可能释放资源锁。

`reader()`函数包含以下规范：

```py
# Chapter13/example3.py

def reader():
    global rcount

    while True:
        with service:
            rcounter.acquire()
            rcount += 1
            if rcount == 1:
                resource.acquire()
        rcounter.release()

        print(f'Reading being done by 
              {threading.current_thread().name}:')
        #print(text)

        with rcounter:
            rcount -= 1
            if rcount == 0:
                resource.release()
```

最后，在我们的主程序中，我们初始化文本字符串、读者计数器、所有必要的锁以及读者和写者线程，如下所示：

```py
# Chapter13/example3.py

text = 'This is some text. '
rcount = 0

rcounter = threading.Lock()
resource = threading.Lock()
service = threading.Lock()

threads = [threading.Thread(target=reader) for i in range(3)] + [threading.Thread(target=writer) for i in range(2)]

for thread in threads:
    thread.start()
```

请注意，我们正在对`reader()`函数中打印文本文件当前内容的代码进行注释，以便后续输出更易读。运行程序 3-4 秒，然后取消。以下输出是我在我的个人电脑上获得的：

```py
> python3 example3.py
Reading being done by Thread-3:
Writing being done by Thread-4.
Reading being done by Thread-1:
Writing being done by Thread-5.
Reading being done by Thread-2:
Reading being done by Thread-3:
Writing being done by Thread-4.
...
```

我们当前输出的模式是，读者和写者能够合作和高效地访问共享资源；所有读者和写者都在执行其指令，没有线程被这个调度算法饿死。

请注意，当您在并发程序中处理读者-写者问题时，您不必重新发明我们刚刚讨论的方法。PyPI 实际上有一个名为`readerwriterlock`的外部库，其中包含了 Python 中三种方法的实现，以及对超时的支持。访问[`pypi.org/project/readerwriterlock/`](https://pypi.org/project/readerwriterlock/)了解更多关于该库及其文档的信息。

# 饥饿的解决方案

通过分析不同的读者-写者问题的方法，您已经看到解决饥饿的关键：由于如果某些线程在访问共享资源时没有得到高优先级，它们将会被饿死，因此在所有线程的执行中实施公平性将防止饥饿的发生。在这种情况下，公平性并不要求程序放弃对不同线程施加的任何顺序或优先级；但为了实施公平性，程序需要确保所有线程有足够的机会执行它们的指令。

牢记这个想法，我们可以通过实施以下方法之一（或组合）来解决饥饿问题：

+   **增加低优先级线程的优先级**：就像我们在读者-写者问题的第二种方法中对写者线程和第三种方法中对读者线程所做的那样，优先考虑那些本来没有机会访问共享资源的线程，可以成功地消除饥饿。

+   **先进先出线程队列**：为了确保一个线程在另一个线程之前开始等待共享资源，可以跟踪请求访问的线程，并将其保存在先进先出队列中。

+   **其他方法**：还可以实施几种方法来平衡不同线程的选择频率。例如，一个优先级队列也会逐渐增加等待时间较长的线程的优先级，或者如果一个线程能够多次访问共享资源，它将被给予较低的优先级，依此类推。

解决并发程序中的饥饿问题可能是一个相当复杂和涉及深入理解调度算法的过程，结合对进程和线程如何与共享资源交互的理解在这个过程中是必要的。正如您在读者-写者问题的示例中所看到的，解决饥饿问题可能需要多种实现和不同方法的修订，才能得到一个好的解决方案。

# 总结

饥饿是并发系统中的一个问题，其中一个进程（或线程）无法获得必要的资源来继续执行，因此无法取得任何进展。大多数情况下，调度指令的不良协调是饥饿的主要原因；死锁情况也会导致饥饿。

读者-写者问题是计算机科学领域中经典和最复杂的例子之一，它说明了并发程序中可能出现的问题。通过分析不同的读者-写者问题的方法，您已经了解到如何使用不同的调度算法解决饥饿问题。公平性是一个良好调度算法的重要元素，通过确保优先级在不同进程和线程之间适当分配，可以消除饥饿。

在下一章中，我们将讨论并发编程的三个常见问题中的最后一个：竞争条件。我们将涵盖竞争条件的基本基础和原因，相关概念，以及竞争条件与其他并发相关问题的联系。

# 问题

+   什么是饥饿，为什么在并发程序中是不可取的？

+   饥饿的根本原因是什么？可以从根本原因中产生的饥饿的常见高级原因是什么？

+   死锁和饥饿之间有什么联系？

+   什么是读者-写者问题？

+   读者-写者问题的第一种方法是什么？为什么在那种情况下会出现饥饿？

+   读者-写者问题的第二种方法是什么？为什么在那种情况下会出现饥饿？

+   读者-写者问题的第三种方法是什么？为什么它成功地解决了饥饿问题？

+   饥饿的一些常见解决方案是什么？

# 进一步阅读

+   《使用 Python 进行并行编程》，作者 Jan Palach，Packt Publishing Ltd，2014

+   《Python 并行编程食谱》，作者 Giancarlo Zaccone，Packt Publishing Ltd，2015

+   《饥饿和公平》（tutorials.jenkov.com/java-concurrency/starvation-and-fairness），作者 Jakob Jenkov

+   《读者-写者问题的更快公平解决方案》，V.Popov 和 O.Mazonka


# 第十四章：竞争条件

在本章中，我们将讨论竞争条件的概念及其在并发环境中的潜在原因。还将介绍关键部分的定义，这是与竞争条件和并发编程密切相关的概念。我们将使用 Python 中的一些示例代码来模拟竞争条件以及常用的解决方法。最后，将讨论通常处理竞争条件的现实应用程序。

本章将涵盖以下主题：

+   竞争条件的基本概念，以及它在并发应用程序中的发生方式，以及关键部分的定义

+   Python 中竞争条件的模拟以及如何实现竞争条件解决方案

+   通常与竞争条件交互和处理的现实计算机科学概念

# 技术要求

以下是本章所需的先决条件列表：

+   确保您的计算机上安装了 Python 3

+   在[`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python)下载 GitHub 存储库。

+   在本章中，我们将使用名为`Chapter14`的子文件夹进行工作

+   查看以下视频以查看代码的实际操作：[`bit.ly/2AdYWRj`](http://bit.ly/2AdYWRj)

# 竞争条件的概念

竞争条件通常被定义为系统输出不确定并且取决于调度算法和任务调度和执行顺序的现象。当数据在此过程中被错误处理和损坏时，竞争条件就成为系统中的一个错误。鉴于这个问题的性质，竞争条件在强调调度和协调独立任务的并发系统中很常见。

竞争条件可能发生在电子硬件系统和软件应用程序中；在本章中，我们将只讨论软件开发环境中的竞争条件，具体来说是并发软件应用程序。本节将涵盖竞争条件的理论基础及其根本原因以及关键部分的概念。

# 关键部分

关键部分指示并发应用程序中由多个进程或线程访问的共享资源，这可能导致意外甚至错误的行为。我们已经看到有多种方法来保护这些资源中包含的数据的完整性，我们称这些受保护的部分为**关键部分**。

可以想象，当这些关键部分中的数据在并发或并行交互和更改时，可能会被错误处理或损坏。当与之交互的线程和进程协调不当并且调度不当时，这一点尤其明显。因此，逻辑结论是不允许多个代理同时进入关键部分。我们称这个概念为**互斥**。

我们将在下一小节中讨论关键部分与竞争条件的原因之间的关系。

# 竞争条件是如何发生的

让我们考虑一个简单的并发程序，以便了解什么会导致竞争条件。假设程序有一个共享资源和两个单独的线程（线程 1 和线程 2），它们将访问并与该资源交互。具体而言，共享资源是一个数字，并且根据它们各自的执行指令，每个线程都要读取该数字，将其增加 1，最后更新共享资源的值为增加后的数字。

假设共享数字最初为 2，然后线程 1 访问和交互该数字；共享资源随后变为 3。在线程 1 成功更改并退出资源后，线程 2 开始执行其指令，并且共享资源即数字被更新为 4。在整个过程中，数字最初为 2，递增了两次（每次由一个单独的线程），并在结束时保持了一个值为 4。在这种情况下，共享数字没有被错误处理和损坏。

现在想象一种情况，即在开始时共享数字仍为 2，但两个线程同时访问该数字。现在，每个线程都从共享资源中读取数字 2，分别将数字 2 递增为 3，然后将数字 3 写回共享资源。尽管共享资源被线程访问和交互了两次，但在进程结束时它只保持了一个值为 3。

这是并发程序中发生竞争条件的一个例子：因为第二个访问共享资源的线程在第一个线程完成执行之前（换句话说，在将新值写入共享资源之前）就已经这样做，第二个线程未能获取更新的资源值。这导致在第二个线程写入资源时，第一个线程处理和更新的值被覆盖。在两个线程执行结束时，共享资源实际上只被第二个线程更新了。

下面的图表进一步说明了正确数据处理过程和竞争条件情况之间的对比：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/cba8d804-7fd7-4729-95db-a8ca8f5647e6.png)

处理共享数据不当

直觉上，我们可以看到竞争条件可能导致数据的处理和损坏。在前面的例子中，我们可以看到只有两个单独的线程访问一个共同的资源就可能发生竞争条件，导致共享资源被错误地更新，并在程序结束时保持了一个错误的值。我们知道大多数现实生活中的并发应用程序包含了更多的线程和进程以及更多的共享资源，而与共享资源交互的线程/进程越多，竞争条件发生的可能性就越大。

# 在 Python 中模拟竞争条件

在讨论我们可以实施的解决竞争条件问题的解决方案之前，让我们尝试在 Python 中模拟这个问题。如果您已经从 GitHub 页面下载了本书的代码，请继续导航到`Chapter14`文件夹。让我们看一下`Chapter14/example1.py`文件，特别是`update()`函数，如下所示：

```py
# Chapter14/example1.py

import random
import time

def update():
    global counter

    current_counter = counter # reading in shared resource
    time.sleep(random.randint(0, 1)) # simulating heavy calculations
    counter = current_counter + 1 # updating shared resource
```

前面的`update()`函数的目标是递增一个名为`counter`的全局变量，并且它将被我们脚本中的一个单独的线程调用。在函数内部，我们正在与一个共享资源交互——在这种情况下是`counter`。然后我们将`counter`的值赋给另一个本地变量，称为`current_counter`（这是为了模拟从更复杂的数据结构中读取共享资源的过程）。

接下来，我们将使用`time.sleep()`方法暂停函数的执行。程序暂停的时间长度是通过函数调用`random.randint(0, 1)`伪随机选择的，因此程序要么暂停一秒，要么根本不暂停。最后，我们将新计算出的`current_counter`值（即它的一次递增）赋给原始共享资源（`counter`变量）。

现在，我们可以继续我们的主程序：

```py
# Chapter14/example1.py

import threading

counter = 0

threads = [threading.Thread(target=update) for i in range(20)]

for thread in threads:
    thread.start()
for thread in threads:
    thread.join()

print(f'Final counter: {counter}.')
print('Finished.')
```

在这里，我们正在使用一组`threading.Thread`对象初始化`counter`全局变量，以便并发执行`update()`函数；我们初始化了二十个线程对象，以便共享计数器增加二十次。在启动和加入所有线程后，我们最终可以打印出我们共享的`counter`变量的最终值。

理论上，一个设计良好的并发程序将成功地总共增加共享计数器二十次，而且，由于其原始值为`0`，计数器的最终值应该在程序结束时为`20`。然而，当您运行此脚本时，您得到的`counter`变量很可能不会保持最终值为`20`。以下是我自己运行脚本后得到的输出：

```py
> python3 example1.py
Final counter: 9.
Finished.
```

这个输出表明计数器只成功增加了九次。这是我们并发程序存在的竞争条件的直接结果。当一个特定的线程花时间从共享资源中读取和处理数据（具体来说，使用`time.sleep()`方法一秒钟），另一个线程读取`counter`变量的当前值，此时该值尚未被第一个线程更新，因为它尚未完成执行。

有趣的是，如果一个线程不花时间处理数据（换句话说，当`random.randint()`方法选择`0`时），共享资源的值可能会及时更新，以便下一个线程读取和处理它。这种现象可以通过程序的不同运行中计数器的最终值的变化来说明。例如，以下是我在运行脚本三次后得到的输出。第一次运行的输出如下：

```py
> python3 example1.py
Final counter: 9.
Finished.
```

第二次运行的输出如下：

```py
> python3 example1.py
Final counter: 12.
Finished.
```

第三次运行的输出如下：

```py
> python3 example1.py
Final counter: 5.
Finished.
```

再次，计数器的最终值取决于花一秒暂停的线程数和根本不暂停的线程数。由于这两个数字又取决于`random.randint()`方法，计数器的最终值在程序的不同运行之间会发生变化。我们的程序仍然存在竞争条件，除非我们可以确保计数器的最终值始终为`20`（计数器总共成功增加二十次）。

# 锁作为解决竞争条件的解决方案

在这一部分，我们将讨论竞争条件最常见的解决方案：锁。直觉上，由于我们观察到的竞争条件是在多个线程或进程同时访问和写入共享资源时出现的，解决竞争条件的关键思想是隔离不同线程/进程的执行，特别是在与共享资源交互时。具体来说，我们需要确保一个线程/进程只能在任何其他与资源交互的线程/进程完成其与该资源的交互后才能访问共享资源。

# 锁的有效性

使用锁，我们可以将并发程序中的共享资源转换为临界区，保证其数据的完整性得到保护。临界区保证了共享资源的互斥访问，并且不能被多个进程或线程同时访问；这将防止受保护的数据由于竞争条件而被更新或改变。

在下图中，**线程 B**被互斥锁（mutex）阻止访问共享资源——名为`var`的临界区，因为**线程 A**已经在访问资源：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/d4e4feb0-9ba3-46f0-89c3-3b4125b58095.png)

锁防止对临界区的同时访问

现在，我们将指定，在并发程序中，为了访问临界区，线程或进程需要获取与临界区相关联的锁对象；同样，该线程或进程在离开临界区时也需要释放该锁。这样的设置将有效地防止对临界区的多次访问，因此也将防止竞争条件。以下图表说明了多个线程与多个临界区交互的执行流程，并且实现了锁的设置：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/5b3de2b6-dac3-43e0-a00f-4c30702a0763.png)

多线程中的锁和临界区

如图表所示，线程**T1**和**T2**都与其各自的执行指令中的三个临界区**CS1**、**CS2**和**CS3**进行交互。在这里，**T1**和**T2**几乎同时尝试访问**CS1**，由于**CS1**受到锁**L1**的保护，因此只有**T1**能够获取锁**L1**，因此可以访问/与临界区交互，而**T2**必须等待**T1**退出临界区并释放锁后才能访问该区域。同样，对于临界区**CS2**和**CS3**，尽管两个线程同时需要访问临界区，但只有一个可以处理，而另一个必须等待获取与临界区相关联的锁。

# Python 中的实现

现在，让我们实现前面示例中的规范，以解决竞争条件的问题。转到`Chapter14/example2.py`文件，并考虑我们已更正的`update()`函数，如下所示：

```py
# Chapter14/example2.py

import random
import time

def update():
    global counter

    with count_lock:
        current_counter = counter # reading in shared resource
        time.sleep(random.randint(0, 1)) # simulating heavy calculations
        counter = current_counter + 1
```

您可以看到，线程在`update()`函数中指定的所有执行指令都在名为`count_lock`的锁对象的上下文管理器下。因此，每次调用线程运行该函数时，都必须首先获取锁对象，然后才能执行任何指令。在我们的主程序中，除了我们已经拥有的内容，我们只需创建锁对象，如下所示：

```py
# Chapter14/example2.py

import threading

counter = 0
count_lock = threading.Lock()

threads = [threading.Thread(target=update) for i in range(20)]

for thread in threads:
    thread.start()
for thread in threads:
    thread.join()

print(f'Final counter: {counter}.')
print('Finished.')
```

运行程序，您的输出应该类似于以下内容：

```py
> python3 example2.py
Final counter: 20.
Finished.
```

您可以看到，计数器成功增加了二十次，并且在程序结束时保持了正确的值。此外，无论脚本执行多少次，计数器的最终值始终为**20**。这是在并发程序中使用锁来实现临界区的优势。

# 锁的缺点

在第十二章中，*死锁*，我们介绍了一个有趣的现象，即使用锁可能会导致不良结果。具体来说，我们发现，在并发程序中实现了足够多的锁后，整个程序可能会变成顺序执行。让我们用当前的程序来分析这个概念。考虑`Chapter14/example3.py`文件，如下所示：

```py
# ch14/example3.py

import threading
import random; random.seed(0)
import time

def update(pause_period):
    global counter

    with count_lock:
        current_counter = counter # reading in shared resource
        time.sleep(pause_period) # simulating heavy calculations
        counter = current_counter + 1 # updating shared resource

pause_periods = [random.randint(0, 1) for i in range(20)]

###########################################################################

counter = 0
count_lock = threading.Lock()

start = time.perf_counter()
for i in range(20):
    update(pause_periods[i])

print('--Sequential version--')
print(f'Final counter: {counter}.')
print(f'Took {time.perf_counter() - start : .2f} seconds.')

###########################################################################

counter = 0

threads = [threading.Thread(target=update, args=(pause_periods[i],)) for i in range(20)]

start = time.perf_counter()
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()

print('--Concurrent version--')
print(f'Final counter: {counter}.')
print(f'Took {time.perf_counter() - start : .2f} seconds.')

###########################################################################

print('Finished.')
```

# 将并发程序变为顺序执行

该脚本的目标是比较当前并发程序与其顺序版本的速度。在这里，我们仍然使用相同的带有锁的`update()`函数，并且我们将它连续运行二十次，既顺序执行又并发执行，就像我们之前做的那样。我们还创建了一个确定的暂停时间列表，以便这些时间段在模拟顺序版本和模拟并发版本时保持一致（因此，`update()`函数现在需要接受一个参数，指定每次调用时的暂停时间）：

```py
pause_periods = [random.randint(0, 1) for i in range(20)]
```

在程序的下一步中，我们只需在`for`循环中调用`update()`函数，进行二十次迭代，并跟踪循环完成所需的时间。请注意，即使这是为了模拟程序的顺序版本，`update()`函数仍然需要在此之前创建锁对象，因此我们在这里进行初始化：

```py
counter = 0
count_lock = threading.Lock()

start = time.perf_counter()
for i in range(20):
    update(pause_periods[i])

print('--Sequential version--')
print(f'Final counter: {counter}.')
print(f'Took {time.perf_counter() - start : .2f} seconds.')
```

最后一步是重置计数器并运行我们已经实现的程序的并发版本。同样，我们需要在初始化运行`update()`函数的每个线程时传入相应的暂停时间。我们还要跟踪并发程序运行所需的时间：

```py
counter = 0

threads = [threading.Thread(target=update, args=(pause_periods[i],)) for i in range(20)]

start = time.perf_counter()
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()

print('--Concurrent version--')
print(f'Final counter: {counter}.')
print(f'Took {time.perf_counter() - start : .2f} seconds.')
```

现在，在您运行脚本之后，您会观察到我们的程序的顺序版本和并发版本都花费了相同的时间来运行。具体来说，我得到的输出是：在这种情况下，它们都花费了大约 12 秒。您的程序实际花费的时间可能不同，但两个版本的速度应该是相等的。

```py
> python3 example3.py
--Sequential version--
Final counter: 20.
Took 12.03 seconds.
--Concurrent version--
Final counter: 20.
Took 12.03 seconds.
Finished.
```

因此，我们的并发程序所花费的时间与其顺序版本一样多，这否定了在程序中实现并发的最大目的之一：提高速度。但为什么具有相同指令和元素集的并发和传统顺序应用程序也具有相同的速度？并发程序是否总是比顺序程序产生更快的速度？

回想一下，在我们的程序中，临界区由一个锁对象保护，没有多个线程可以同时访问它。由于程序的所有执行（对计数器进行 20 次递增）都取决于一个线程访问临界区，因此在临界区放置锁对象意味着在给定时间内只有一个线程可以执行。根据这个规范，任何两个线程的执行都不会重叠，这种并发实现无法获得额外的速度。

这是我们在分析死锁问题时遇到的现象：如果在并发程序中放置了足够多的锁，那么该程序将变得完全顺序化。这就是为什么锁有时不是并发编程问题的理想解决方案的原因。然而，只有当并发程序的所有执行都依赖于与临界区交互时，才会出现这种情况。大多数情况下，读取和操作共享资源的数据只是整个程序的一部分，因此并发仍然可以为我们的程序提供预期的额外速度。

# 锁不会锁任何东西

锁的另一个方面是它们实际上并没有锁住任何东西。锁对象与特定共享资源的交互线程和进程也需要与锁进行交互。换句话说，如果这些线程和进程选择在访问和更改共享资源之前不检查锁，那么锁对象本身就无法阻止它们这样做。

在我们的示例中，您已经看到，为了实现锁对象的获取/释放过程，线程或进程的指令将被锁上下文管理器包裹；这个规范取决于线程/进程执行逻辑的实现，而不是资源。这是因为我们看到的锁对象与它们所应保护的资源没有任何连接。因此，如果线程/进程执行逻辑不需要与共享资源相关联的锁对象进行任何交互，那么该线程或进程可以简单地访问资源而无需困难，可能导致数据的错误操作和损坏。

这不仅适用于在单个并发程序中拥有多个线程和进程的范围。假设我们有一个由多个组件组成的并发系统，所有这些组件都相互作用并操作跨系统共享的资源的数据，并且这个资源与一个锁对象相关联；由此可见，如果其中任何一个组件未能与该锁进行交互，它可以简单地绕过锁实施的保护并访问共享资源。更重要的是，锁的这种特性也对并发程序的安全性有着重要的影响。如果一个外部的恶意代理连接到系统（比如，一个恶意客户端与服务器进行交互）并且意图破坏跨系统共享的数据，那么该代理可以被指示简单地忽略锁对象并以侵入的方式访问数据。

锁不锁任何东西的观点是由雷蒙德·赫廷格（Raymond Hettinger）提出的，他是 Python 核心开发人员，负责实现 Python 并发编程中的各种元素。有人认为仅使用锁对象并不能保证并发数据结构和系统的安全实现。锁需要与它们要保护的资源具体关联起来，没有任何东西应该能够在未先获取与之相关联的锁的情况下访问资源。或者，其他并发同步工具，比如原子消息队列，可以提供解决这个问题的方案。

# 现实生活中的竞争条件

现在你已经了解了竞争条件的概念，它们在并发系统中是如何引起的，以及如何有效地防止它们。在本节中，我们将提供一个关于竞争条件如何在计算机科学的各个子领域中发生的总体观点。具体来说，我们将讨论安全、文件管理和网络的主题。

# 安全

并发编程对系统安全性可能会产生重大影响。回想一下，读取和更改资源数据的过程之间会出现竞争条件；在认证系统中出现竞争条件可能会导致在检查代理的凭据和代理可以利用资源之间数据的损坏。这个问题也被称为**检查时间到使用时间**（TOCTTOU）漏洞，这无疑对安全系统有害。

在处理竞争条件时对共享资源的粗心保护可以为外部代理提供访问那些被认为受到保护的资源的机会。然后这些代理可以改变资源的数据以创建**权限提升**（简单来说，给自己更多非法访问更多共享资源的权限），或者他们可以简单地破坏数据，导致整个系统发生故障。

有趣的是，竞争条件也可以用于实现计算机安全。由于竞争条件是由多个线程/进程对共享资源的不协调访问导致的，竞争条件发生的规范是相当随机的。例如，在我们自己的 Python 示例中，你看到在模拟竞争条件时，计数器的最终值在程序的不同执行之间变化；这部分是因为情况的不可预测性，其中多个线程正在运行并访问共享资源。（我说部分是因为随机性也是由我们在每次执行程序时生成的随机暂停期间导致的。）因此，有时会故意引发竞争条件，并且在竞争条件发生时获得的信息可以用于生成安全流程的数字指纹——这些信息同样是相当随机的，因此对安全目的而言具有价值。

# 操作系统

在操作系统中的文件和内存管理的背景下，竞争条件可能会发生，当两个单独的程序尝试访问相同的资源，如内存空间。想象一种情况，两个来自不同程序的进程已经运行了相当长的时间，尽管它们最初在内存空间方面是分开初始化的，但足够的数据已经积累，一个进程的执行堆栈现在与另一个进程的执行堆栈发生了冲突。这可能导致两个进程共享相同的内存空间部分，并最终导致不可预测的后果。

竞争条件复杂性的另一个方面是由 Unix 版本 7 操作系统中的`mkdir`命令所说明的。通常，`mkdir`命令用于在 Unix 操作系统中创建新目录；这是通过调用`mknod`命令创建实际目录和`chown`命令指定该目录的所有者来完成的。因为有两个单独的命令需要运行，并且第一个命令完成和第二个命令调用之间存在明确的间隙，这可能导致竞争条件。

在两个命令之间的间隙期间，如果有人可以删除`mknod`命令创建的新目录，并将引用链接到另一个文件，当运行`chown`命令时，该文件的所有权将被更改。通过利用这个漏洞，某人理论上可以更改操作系统中任何文件的所有权，以便某人可以创建一个新目录。以下图表进一步说明了这种利用：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/66861344-20e7-4db5-9f43-57592c8b370b.png)

`mkdir`竞争条件的图表

# 网络

在网络中，竞争条件可以以在网络中为多个用户提供独特特权的形式出现。具体来说，假设给定服务器应该只有一个用户具有管理员特权。如果两个用户，都有资格成为服务器管理员，同时请求访问这些特权，那么两者都有可能获得该访问权限。这是因为在服务器接收到两个用户请求时，两个用户都还没有被授予管理员特权，服务器认为管理员特权仍然可以分配。

这种形式的竞争条件在网络高度优化以进行并行处理时（例如，非阻塞套接字），而没有仔细考虑网络共享资源时是非常常见的。

# 总结

竞争条件被定义为系统输出不确定的现象，取决于调度算法和任务调度和执行的顺序。临界区指示并发应用程序中由多个进程或线程访问的共享资源，这可能导致意外甚至错误的行为。当两个或多个线程/进程同时访问和更改共享资源时，就会发生竞争条件，导致数据处理不当和损坏。竞争条件在现实生活应用中也有重要影响，如安全性、操作系统和网络。

由于我们观察到的竞争条件是在多个线程或进程同时访问和写入共享资源时出现的，解决竞争条件的关键思想是隔离不同线程/进程的执行，特别是在与共享资源交互时。使用锁，我们可以将并发程序中的共享资源转换为临界区，其数据的完整性得到保护。然而，使用锁也有许多缺点：在并发程序中实现了足够多的锁，整个程序可能变成顺序执行；锁并不真正锁定任何东西。

在下一章中，我们将考虑 Python 并发编程中最大的问题之一：臭名昭著的**全局解释器锁（GIL）**。您将了解 GIL 背后的基本思想，它的目的，以及如何在并发 Python 应用程序中有效地使用它。

# 问题

+   什么是临界区？

+   什么是竞争条件，为什么在并发程序中是不可取的？

+   竞争条件的根本原因是什么？

+   锁如何解决竞争条件的问题？

+   为什么锁有时在并发程序中是不可取的？

+   在现实生活系统和应用中，竞争条件的重要性是什么？

# 进一步阅读

欲了解更多信息，您可以参考以下链接：

+   *使用 Python 进行并行编程*，作者 Jan Palach，Packt Publishing Ltd，2014

+   *Python 并行编程食谱*，作者 Giancarlo Zaccone，Packt Publishing Ltd，2015

+   *竞争条件和临界区*（[tutorials.jenkov.com/java-concurrency/race-conditions-and-critical-sections](http://tutorials.jenkov.com/java-concurrency/race-conditions-and-critical-sections.html)），作者 Jakob Jenkov

+   *竞争条件、文件和安全漏洞；或乌龟和野兔的重现*，作者 Matt Bishop，技术报告 CSE-95-98（1995）

+   *计算机和信息安全，第十一章，软件缺陷和恶意软件 1 插图*（[slideplayer.com/slide/10319860/](https://slideplayer.com/slide/10319860/)）


# 第十五章：全局解释器锁

Python 并发编程中的主要参与者之一是全局解释器锁（GIL）。在本章中，我们将介绍 GIL 的定义和目的，以及它对并发 Python 应用程序的影响。还将讨论 GIL 对 Python 并发系统造成的问题以及其实施引起的争议。最后，我们将提到一些关于 Python 程序员和开发人员应该如何思考和与 GIL 交互的想法。

本章将涵盖以下主题：

+   对 GIL 的简要介绍：它是如何产生的，以及它引起的问题

+   在 Python 中消除/修复 GIL 的努力

+   如何有效地处理 Python 并发程序中的 GIL

# 技术要求

以下是本章的先决条件列表：

+   确保您的计算机上已安装 Python 3

+   在[`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python)下载 GitHub 存储库

+   在本章中，我们将使用名为`Chapter15`的子文件夹进行工作

+   查看以下视频以查看代码的实际操作：[`bit.ly/2DFDYhC`](http://bit.ly/2DFDYhC)

# 全局解释器锁简介

GIL 在 Python 并发编程社区中非常受欢迎。设计为一种锁，它只允许一个线程在任何给定时间访问和控制 Python 解释器，Python 中的 GIL 通常被称为臭名昭著的 GIL，它阻止多线程程序达到其完全优化的速度。在本节中，我们将讨论 GIL 背后的概念及其目标：为什么它被设计和实施，以及它如何影响 Python 中的多线程编程。

# Python 中内存管理的分析

在我们深入讨论 GIL 及其影响之前，让我们考虑 Python 核心开发人员在 Python 早期遇到的问题，以及这些问题引发了对 GIL 的需求。具体来说，在内存空间中管理对象方面，Python 编程与其他流行语言的编程存在显着差异。

例如，在编程语言 C++中，变量实际上是内存空间中将写入值的位置。这种设置导致了一个事实，即当非指针变量被赋予特定值时，编程语言将有效地将该特定值复制到内存位置（即变量）。此外，当一个变量被赋予另一个变量（不是指针）时，后者的内存位置将被复制到前者的内存位置；在赋值后，这两个变量之间将不再保持任何连接。

另一方面，Python 将变量视为简单的名称，而变量的实际值则隔离在内存空间的另一个区域。当一个值被赋给一个变量时，变量实际上被赋予了对该值在内存空间中位置的引用（即使引用这个术语并不像 C++中的引用那样使用）。因此，Python 中的内存管理与我们在 C++中看到的将值放入内存空间的模型根本不同。

这意味着当执行赋值指令时，Python 只是与引用交互并将它们切换，而不是实际的值本身。此外，出于这个原因，多个变量可以被同一个值引用，并且一个变量所做的更改将在所有其他相关变量中反映出来。

让我们分析 Python 中的这个特性。如果您已经从 GitHub 页面下载了本书的代码，请转到`Chapter15`文件夹。让我们看一下`Chapter15/example1.py`文件，如下所示：

```py
# Chapter15/example1.py

import sys

print(f'Reference count when direct-referencing: {sys.getrefcount([7])}.')

a = [7]
print(f'Reference count when referenced once: {sys.getrefcount(a)}.')

b = a
print(f'Reference count when referenced twice: {sys.getrefcount(a)}.')

###########################################################################

a[0] = 8
print(f'Variable a after a is changed: {a}.')
print(f'Variable b after a is changed: {b}.')

print('Finished.')
```

在这个例子中，我们正在管理值`[7]`（一个元素的列表：整数`7`）。我们提到 Python 中的值是独立于变量存储的，Python 中的值管理只是将变量引用到适当的值。Python 中的`sys.getrefcount()`方法接受一个对象并返回与该对象关联的值的所有引用的计数。在这里，我们调用`sys.getrefcount()`三次：在实际值`[7]`上；分配给值的变量`a`；最后，分配给变量`a`的变量`b`。

此外，我们正在探讨通过使用与之引用的变量来改变值的过程，以及与该值相关联的所有变量的结果值。具体来说，我们通过变量`a`来改变列表的第一个元素，并打印出`a`和`b`的值。运行脚本，你的输出应该类似于以下内容：

```py
> python3 example1.py
Reference count when direct-referencing: 1.
Reference count when referenced once: 2.
Reference count when referenced twice: 3.
Variable a after a is changed: [8].
Variable b after a is changed: [8].
Finished.
```

正如你所看到的，这个输出与我们讨论的一致：对于第一个`sys.getrefcount()`函数调用，值`[7]`只有一个引用计数，当我们直接引用它时创建；当我们将列表分配给变量`a`时，该值有两个引用，因为`a`现在与该值相关联；最后，当`a`分配给`b`时，`[7]`还被`b`引用，引用计数现在是三。

在程序的第二部分输出中，我们可以看到，当我们改变变量`a`引用的值时，`[7]`被改变了，而不是变量`a`。结果，引用与`a`相同的变量`b`的值也被改变了。

下图说明了这个过程。在 Python 程序中，变量（`a`和`b`）只是简单地引用实际值（对象），两个变量之间的赋值语句（例如，`a = b`）指示 Python 让这两个变量引用相同的对象（而不是将实际值复制到另一个内存位置，就像在 C++中一样）：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/0f95f237-7e49-418b-96b9-5824aacab7af.png)

Python 引用方案的图示

# GIL 解决的问题

牢记 Python 对内存和变量管理的实现，我们可以看到 Python 中对给定值的引用在程序中不断变化，因此跟踪值的引用计数非常重要。

现在，应用你在第十四章中学到的*竞争条件*，你应该知道在 Python 并发程序中，这个引用计数是一个需要保护免受竞争条件影响的共享资源。换句话说，这个引用计数是一个关键部分，如果处理不慎，将导致对特定值引用的变量数量的错误解释。这将导致内存泄漏，使 Python 程序显着低效，并且甚至可能释放实际上被一些变量引用的内存，永久丢失该值。

正如你在上一章中学到的，确保不会发生关于特定共享资源的竞争条件的解决方案是在该资源上放置一个锁，从而在并发程序中最多允许一个线程访问该资源。我们还讨论了，如果在并发程序中放置了足够多的锁，那么该程序将变得完全顺序化，并且通过实现并发性将不会获得额外的速度。

GIL 是对前面两个问题的解决方案，是 Python 整个执行过程中的一个单一锁。任何想要执行的 Python 指令（CPU 密集型任务）必须首先获取 GIL，以防止任何引用计数的竞争条件发生。

在 Python 语言开发的早期，也提出了其他解决这个问题的方案，但 GIL 是迄今为止最有效和最简单实现的。由于 GIL 是 Python 整个执行过程的轻量级全局锁，因此不需要实现其他锁来保证其他关键部分的完整性，从而将 Python 程序的性能开销降到最低。

# GIL 引发的问题

直观地说，由于锁保护了 Python 中的所有 CPU 绑定任务，因此并发程序将无法完全实现多线程。GIL 有效地阻止了 CPU 绑定任务在多个线程之间并行执行。为了理解 GIL 这一特性的影响，让我们来看一个 Python 中的例子；转到`Chapter15/example2.py`。

```py
# Chapter15/example2.py

import time
import threading

COUNT = 50000000

def countdown(n):
    while n > 0:
        n -= 1

###########################################################################

start = time.time()
countdown(COUNT)

print('Sequential program finished.')
print(f'Took {time.time() - start : .2f} seconds.')

###########################################################################

thread1 = threading.Thread(target=countdown, args=(COUNT // 2,))
thread2 = threading.Thread(target=countdown, args=(COUNT // 2,))

start = time.time()
thread1.start()
thread2.start()
thread1.join()
thread2.join()

print('Concurrent program finished.')
print(f'Took {time.time() - start : .2f} seconds.')
```

在这个例子中，我们比较了在 Python 中顺序执行和并发执行（通过多线程）一个特定程序的速度。具体来说，我们有一个名为`countdown()`的函数，模拟了一个重型 CPU 绑定任务，它接受一个数字`n`，并将其递减直到变为零或负数。然后，我们将`countdown()`在 5000 万上顺序执行一次。最后，我们将该函数分别在两个线程中调用，每个线程上执行 2500 万次，这正好是 5000 万的一半；这是程序的多线程版本。我们还记录了 Python 运行顺序程序和多线程程序所需的时间。

理论上，程序的多线程版本应该比顺序版本快一半，因为任务实际上被分成两半并且通过我们创建的两个线程并行运行。然而，程序产生的输出表明了相反的情况。通过运行脚本，我得到了以下输出：

```py
> python3 example2.py
Sequential program finished.
Took 2.80 seconds.
Concurrent program finished.
Took 2.74 seconds.
```

与我们预测的相反，倒计时的并发版本几乎与顺序版本一样长；多线程对我们的程序并没有提供任何显著的加速。这是由于 GIL 保护 CPU 绑定任务的直接影响，多个线程不被允许同时运行。有时，多线程程序甚至可能比其顺序对应物更长时间才能完成执行，因为还有获取和释放 GIL 的开销。

这无疑是多线程和 Python 中的并发编程的一个重大问题，因为只要程序包含 CPU 绑定指令，这些指令实际上会在程序的执行中是顺序的。然而，不是 CPU 绑定的指令发生在 GIL 之外，因此不受 GIL 的影响（例如 I/O 绑定指令）。

# 从 Python 中潜在删除 GIL

您已经了解到，GIL 对我们在 Python 中编写的多线程程序产生了重大限制，特别是对于那些包含 CPU 绑定任务的程序。因此，许多 Python 开发人员开始对 GIL 持负面看法，术语“臭名昭著的 GIL”开始变得流行；毫不奇怪，一些人甚至主张从 Python 语言中完全删除 GIL。

事实上，一些知名的 Python 用户曾多次尝试去除 GIL。然而，GIL 在语言的实现中根深蒂固，而大多数不支持多线程的库和包的执行都严重依赖于 GIL，因此去除 GIL 实际上会引发 Python 程序的错误以及向后不兼容性问题。一些 Python 开发人员和研究人员曾试图完全省略 Python 执行中的 GIL，结果大多数现有的 C 扩展都无法正常工作，因为它们严重依赖于 GIL 的功能。

现在有其他可行的解决方案来解决我们讨论过的问题；换句话说，GIL 在任何情况下都是可以替代的。然而，大多数这些解决方案包含如此复杂的指令，以至于它们实际上会降低顺序和 I/O 受限程序的性能，而这些程序并不受 GIL 的影响。因此，这些解决方案将减慢单线程或多线程 I/O 程序的速度，而这些程序实际上占现有 Python 应用程序的很大比例。有趣的是，Python 的创始人 Guido van Rossum 在他的文章《移除 GIL 并不容易》中也对这个话题发表了评论：

我只会欢迎一组补丁进入 Py3k，只要单线程程序的性能（以及多线程但 I/O 受限的程序）不会下降。

不幸的是，没有任何提出的 GIL 替代方案实现了这一要求。GIL 仍然是 Python 语言的一个重要部分。

# 如何处理 GIL

有几种方法可以处理你的 Python 应用程序中的 GIL，将在下文中讨论。

# 实施多进程，而不是多线程

这可能是规避 GIL 并在并发程序中实现最佳速度的最流行和最简单的方法。由于 GIL 只阻止多个线程同时执行 CPU 受限任务，因此在系统的多个核心上执行的进程，每个进程都有自己的内存空间，完全不受 GIL 的影响。

具体来说，考虑前面的倒计时示例，让我们比较一下当它是顺序的、多线程的和多进程的时候，那个 CPU 受限程序的性能。导航到`Chapter15/example3.py`文件；程序的第一部分与我们之前看到的是相同的，但在最后，我们添加了一个从 5000 万开始倒计时的多进程解决方案的实现，使用了两个独立的进程：

```py
# Chapter15/example3.py

import time
import threading
from multiprocessing import Pool

COUNT = 50000000

def countdown(n):
    while n > 0:
        n -= 1

if __name__ == '__main__':

    #######################################################################
    # Sequential

    start = time.time()
    countdown(COUNT)

    print('Sequential program finished.')
    print(f'Took {time.time() - start : .2f} seconds.')
    print()

    #######################################################################
    # Multithreading

    thread1 = threading.Thread(target=countdown, args=(COUNT // 2,))
    thread2 = threading.Thread(target=countdown, args=(COUNT // 2,))

    start = time.time()
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()

    print('Multithreading program finished.')
    print(f'Took {time.time() - start : .2f} seconds.')
    print()

    #######################################################################
    # Multiprocessing

    pool = Pool(processes=2)
    start = time.time()
    pool.apply_async(countdown, args=(COUNT//2,))
    pool.apply_async(countdown, args=(COUNT//2,))
    pool.close()
    pool.join()

    print('Multiprocessing program finished.')
    print(f'Took {time.time() - start : .2f} seconds.')
```

运行程序后，我的输出如下：

```py
> python3 example3.py
Sequential program finished.
Took 2.95 seconds.

Multithreading program finished.
Took 2.69 seconds.

Multiprocessing program finished.
Took 1.54 seconds.
```

顺序和多线程版本的程序之间仍然存在微小的速度差异。然而，多进程版本能够将执行速度减少了近一半；正如前几章讨论的那样；由于进程相当沉重，多进程指令包含了显著的开销，这就是为什么多进程程序的速度并不完全是顺序程序的一半的原因。

# 利用本地扩展规避 GIL

有一些用 C/C++编写的 Python 本地扩展，因此能够避免 GIL 设置的限制；一个例子是最流行的 Python 科学计算包 NumPy。在这些扩展中，可以进行 GIL 的手动释放，以便执行可以简单地绕过锁。然而，这些释放需要谨慎实施，并在执行返回到主 Python 执行之前伴随着 GIL 的重新断言。

# 利用不同的 Python 解释器

GIL 只存在于 CPython 中，这是迄今为止最常用的语言解释器，它是用 C 构建的。然而，Python 还有其他解释器，比如 Jython（用 Java 编写）和 IronPython（用 C++编写），可以用来避免 GIL 及其对多线程程序的影响。请记住，这些解释器并不像 CPython 那样广泛使用，一些包和库可能与其中一个或两个不兼容。

# 总结

虽然 Python 中的 GIL 为语言中的一个更难的问题提供了一个简单而直观的解决方案，但它也提出了一些自己的问题，涉及在 Python 程序中运行多个线程以处理 CPU 受限任务的能力。已经有多次尝试从 Python 的主要实现中删除 GIL，但没有一次能够在保持处理非 CPU 受限任务的有效性的同时实现它。

在 Python 中，有多种方法可供选择，以提供处理 GIL 的选项。总的来说，虽然它在 Python 编程社区中声名显赫，但 GIL 只影响 Python 生态系统的一部分，并且可以被视为一种必要的恶，因为它对于从语言中移除来说太重要了。Python 开发人员应该学会与 GIL 共存，并在并发程序中绕过它。

在最后四章中，我们讨论了 Python 中并发编程中最著名和常见的一些问题。在本书的最后一节中，我们将研究 Python 提供的一些更高级的并发功能。在下一章中，您将了解无锁和基于锁的并发数据结构的设计。

# 问题

+   Python 和 C++之间的内存管理有哪些区别？

+   GIL 为 Python 解决了什么问题？

+   GIL 为 Python 带来了什么问题？

+   在 Python 程序中规避 GIL 的一些方法是什么？

# 进一步阅读

欲了解更多信息，您可以参考以下链接：

+   《Python 全局解释器锁（GIL）是什么？》（[realpython.com/python-gil/](https://realpython.com/python-gil/)），Abhinav Ajitsaria

+   《Python GIL 可视化》（[dabeaz.blogspot.com/2010/01/python-gil-visualized](http://dabeaz.blogspot.com/2010/01/python-gil-visualized.html)），Dave Beazley

+   《Python 中的复制操作》（[pythontic.com/modules/copy/introduction](https://pythontic.com/modules/copy/introduction)）

+   《移除 GIL 并不容易》（[www.artima.com/weblogs/viewpost.jsp?thread=214235](https://www.artima.com/weblogs/viewpost.jsp?thread=214235)），Guido Van Rossum

+   《使用 Python 进行并行编程》，Jan Palach，Packt Publishing Ltd，2014

+   《在 Python 中学习并发：构建高效、健壮和并发的应用程序》，Elliot Forbes（2017）
