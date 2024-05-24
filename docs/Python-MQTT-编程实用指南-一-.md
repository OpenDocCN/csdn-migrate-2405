# Python MQTT 编程实用指南（一）

> 原文：[`zh.annas-archive.org/md5/948E1F407C9BFCC597B979028EF5EE22`](https://zh.annas-archive.org/md5/948E1F407C9BFCC597B979028EF5EE22)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

MQTT 是首选的物联网发布-订阅轻量级消息传递协议。Python 绝对是最流行的编程语言之一。它是开源的，多平台的，您可以使用它开发任何类型的应用程序。如果您开发物联网、Web 应用程序、移动应用程序或这些解决方案的组合，您必须学习 MQTT 及其轻量级消息传递系统的工作原理。Python 和 MQTT 的结合使得开发能够与传感器、不同设备和其他应用程序进行通信的强大应用程序成为可能。当然，在使用该协议时，考虑安全性是非常重要的。

大多数情况下，当您使用现代 Python 3.6 编写的复杂物联网解决方案时，您将使用可能使用不同操作系统的不同物联网板。MQTT 有自己的特定词汇和不同的工作模式。学习 MQTT 是具有挑战性的，因为它包含太多需要真实示例才能易于理解的抽象概念。

本书将使您深入了解最新版本的 MQTT 协议：3.1.1。您将学习如何使用最新的 Mosquitto MQTT 服务器、命令行工具和 GUI 工具，以便了解 MQTT 的一切工作原理以及该协议为您的项目提供的可能性。您将学习安全最佳实践，并将其用于 Mosquitto MQTT 服务器。

然后，您将使用 Python 3.6 进行许多真实示例。您将通过与 Eclipse Paho MQTT 客户端库交换 MQTT 消息来控制车辆、处理命令、与执行器交互和监视冲浪比赛。您还将使用基于云的实时 MQTT 提供程序进行工作。

您将能够在各种现代物联网板上运行示例，例如 Raspberry Pi 3 Model B+、Qualcomm DragonBoard 410c、BeagleBone Black、MinnowBoard Turbot Quad-Core、LattePanda 2G 和 UP Core 4GB。但是，任何支持 Python 3.6 的其他板都可以运行这些示例。

# 本书适合对象

本书面向希望开发能够与其他应用程序和设备交互的 Python 开发人员，例如物联网板、传感器和执行器。

# 本书涵盖内容

第一章，*安装 MQTT 3.1.1 Mosquitto 服务器*，开始我们的旅程，使用首选的物联网发布-订阅轻量级消息传递协议在不同的物联网解决方案中，结合移动应用程序和 Web 应用程序。我们将学习 MQTT 及其轻量级消息传递系统的工作原理。我们将了解 MQTT 的谜题：客户端、服务器（以前称为代理）和连接。我们将学习在 Linux、macOS 和 Windows 上安装 MQTT 3.1.1 Mosquitto 服务器的程序。我们将学习在云上（Azure、AWS 和其他云提供商）运行 Mosquitto 服务器的特殊注意事项。

第二章，*使用命令行和 GUI 工具学习 MQTT 的工作原理*，教我们如何使用命令行和 GUI 工具详细了解 MQTT 的工作原理。我们将学习 MQTT 的基础知识，MQTT 的特定词汇和其工作模式。我们将使用不同的实用工具和图表来理解与 MQTT 相关的最重要的概念。我们将在编写 Python 代码与 MQTT 协议一起工作之前，了解一切必须知道的内容。我们将使用不同的服务质量级别，并分析和比较它们的开销。

第三章，*保护 MQTT 3.1.1 Mosquitto 服务器*，着重介绍如何保护 MQTT 3.1.1 Mosquitto 服务器。我们将进行所有必要的配置，以使用数字证书加密 MQTT 客户端和服务器之间发送的所有数据。我们将使用 TLS，并学习如何为每个 MQTT 客户端使用客户端证书。我们还将学习如何强制所需的 TLS 协议版本。

第四章，*使用 Python 和 MQTT 消息编写控制车辆的代码*，侧重于使用加密连接（TLS 1.2）通过 MQTT 消息控制车辆的 Python 3.x 代码。我们将编写能够在不同流行的 IoT 平台上运行的代码，例如树莓派 3 板。我们将了解如何利用我们对 MQTT 协议的了解来构建基于需求的解决方案。我们将学习如何使用最新版本的 Eclipse Paho MQTT Python 客户端库。

第五章，*测试和改进我们的 Python 车辆控制解决方案*，概述了如何使用 MQTT 消息和 Python 代码来处理我们的车辆控制解决方案。我们将学习如何使用 Python 代码处理接收到的 MQTT 消息中的命令。我们将编写 Python 代码来组成和发送带有命令的 MQTT 消息。我们将使用阻塞和线程化的网络循环，并理解它们之间的区别。最后，我们将利用遗嘱功能。

第六章，*使用基于云的实时 MQTT 提供程序和 Python 监控冲浪比赛*，介绍了如何编写 Python 代码，使用 PubNub 基于云的实时 MQTT 提供程序与 Mosquitto MQTT 服务器结合，监控冲浪比赛。我们将通过分析需求从头开始构建一个解决方案，并编写 Python 代码，该代码将在连接到冲浪板上的多个传感器的防水 IoT 板上运行。我们将定义主题和命令，并与基于云的 MQTT 服务器一起使用，结合了前几章中使用的 Mosquitto MQTT 服务器。

附录，*解决方案*，每章的*测试你的知识*部分的正确答案都包含在附录中。

# 为了充分利用本书

您需要对 Python 3.6.x 和 IoT 板有基本的了解。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择支持选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-MQTT-Programming-with-Python`](https://github.com/PacktPublishing/Hands-On-MQTT-Programming-with-Python)。如果代码有更新，将在现有的 GitHub 存储库中更新。

我们还有其他代码包，来自我们丰富的书籍和视频目录，可以在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/HandsOnMQTTProgrammingwithPython_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/HandsOnMQTTProgrammingwithPython_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```py
@staticmethod
    def on_subscribe(client, userdata, mid, granted_qos):
        print("I've subscribed with QoS: {}".format(
            granted_qos[0]))
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```py
 time.sleep(0.5) 
       client.disconnect() 
       client.loop_stop() 
```

任何命令行输入或输出都以以下方式书写：

```py
 sudo apt-add-repository ppa:mosquitto-dev/mosquitto-ppa
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。例如："从管理面板中选择系统信息。"

警告或重要提示会以这种方式出现。技巧和窍门会以这种方式出现。


# 第一章：安装 MQTT 3.1.1 Mosquitto 服务器

在本章中，我们将开始使用首选的物联网发布-订阅轻量级消息传递协议，在不同的物联网解决方案中与移动应用和 Web 应用程序相结合。我们将学习 MQTT 及其轻量级消息系统的工作原理。

我们将理解 MQTT 谜题：客户端、服务器（以前称为经纪人）和连接。我们将学习在 Linux、macOS 和 Windows 上安装 MQTT 3.1.1 Mosquitto 服务器的程序。我们将学习在云中运行 Mosquitto 服务器（Azure、AWS 和其他云提供商）的特殊注意事项。我们将了解以下内容：

+   理解 MQTT 协议的便利场景

+   使用发布-订阅模式

+   使用消息过滤

+   理解 MQTT 谜题：客户端、服务器和连接

+   在 Linux 上安装 Mosquitto 服务器

+   在 macOS 上安装 Mosquitto 服务器

+   在 Windows 上安装 Mosquitto 服务器

+   在云中运行 Mosquitto 服务器的注意事项

# 理解 MQTT 协议的便利场景

想象一下，我们有数十个不同的设备必须在它们之间交换数据。这些设备必须从其他设备请求数据，接收请求的设备必须用所需的数据做出响应。请求数据的设备必须处理来自响应所需数据的设备的数据。

这些设备是物联网（IoT）板，上面连接了数十个传感器。我们有以下不同处理能力的物联网板：

+   Raspberry Pi 3 Model B+

+   Qualcomm DragonBoard 410c

+   Udoo Neo

+   BeagleBone Black

+   Phytec phyBoard-i.MX7-Zeta

+   e-con Systems eSOMiMX6-micro

+   MinnowBoard Turbot Quad-Core

每个这些板都必须能够发送和接收数据。此外，我们希望 Web 应用程序能够发送和接收数据。我们希望能够在互联网上实时发送和接收数据，并且可能会遇到一些网络问题：我们的无线网络有些不可靠，而且有些高延迟的环境。一些设备功耗低，许多设备由电池供电，它们的资源有限。此外，我们必须小心网络带宽的使用，因为一些设备使用按流量计费的连接。

按流量计费的连接是指每月有限的数据使用量的网络连接。如果超出此数据量，将额外收费。

我们可以使用 HTTP 请求并构建发布-订阅模型来在不同设备之间交换数据。然而，有一个专门设计的协议比 HTTP 1.1 和 HTTP/2 协议更轻。MQ Telemetry Transport（MQTT）更适合于许多设备在互联网上实时交换数据并且需要消耗尽可能少的网络带宽的场景。当涉及不可靠的网络和连接不稳定时，该协议比 HTTP 1.1 和 HTTP/2 更有效。

MQTT 协议是一种机器对机器（M2M）和物联网连接协议。MQTT 是一种轻量级的消息传递协议，使用基于服务器的发布-订阅机制，并在 TCP/IP（传输控制协议/互联网协议）之上运行。以下图表显示了 MQTT 协议在 TCP/IP 堆栈之上的情况：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/2b55d99a-0dfd-49d7-8893-68b40101356c.png)MQTT 最流行的版本是 3.1.1 和 3.1。在本书中，我们将使用 MQTT 3.1.1。每当我们提到 MQTT 时，我们指的是 MQTT 3.1.1，这是协议的最新版本。MQTT 3.1.1 规范已经由 OASIS 联盟标准化。此外，MQTT 3.1.1 在 2016 年成为 ISO 标准（ISO/IEC 20922）。

MQTT 比 HTTP 1.1 和 HTTP/2 协议更轻，因此在需要以发布-订阅模式实时发送和接收数据时，同时需要最小的占用空间时，它是一个非常有趣的选择。MQTT 在物联网、M2M 和嵌入式项目中非常受欢迎，但也在需要可靠消息传递和高效消息分发的 Web 应用和移动应用中占据一席之地。总之，MQTT 适用于以下需要数据交换的应用领域：

+   资产跟踪和管理

+   汽车远程监控

+   化学检测

+   环境和交通监测

+   现场力量自动化

+   火灾和气体测试

+   家庭自动化

+   **车载信息娱乐**（**IVI**）

+   医疗

+   消息传递

+   **销售点**（**POS**）自助服务亭

+   铁路

+   **射频识别**（**RFID**）

+   **监控和数据采集**（**SCADA**）

+   老虎机

总之，MQTT 旨在支持物联网、M2M、嵌入式和移动应用中的以下典型挑战：

+   轻量化，使得能够在没有巨大开销的情况下传输大量数据

+   在大量数据中分发最小的数据包

+   支持异步、双向、低延迟推送消息的事件驱动范式

+   轻松地从一个客户端向多个客户端发出数据

+   使得能够在事件发生时监听事件（面向事件的架构）

+   支持始终连接和有时连接的模式

+   在不可靠的网络上发布信息，并在脆弱的连接上提供可靠的传递

+   非常适合使用电池供电的设备或需要低功耗

+   提供响应性，使得能够实现信息的准实时传递

+   为所有数据提供安全性和隐私

+   能够提供必要的可扩展性，将数据分发给数十万客户端

# 使用发布-订阅模式工作

在深入研究 MQTT 之前，我们必须了解发布-订阅模式，也称为发布-订阅模式。在发布-订阅模式中，发布消息的客户端与接收消息的其他客户端或客户端解耦。客户端不知道其他客户端的存在。客户端可以发布特定类型的消息，只有对该特定类型的消息感兴趣的客户端才会接收到发布的消息。

发布-订阅模式需要一个*服务器*，也称为**代理**。所有客户端都与服务器建立连接。通过服务器发送消息的客户端称为**发布者**。服务器过滤传入的消息，并将其分发给对该类型接收消息感兴趣的客户端。向服务器注册对特定类型消息感兴趣的客户端称为**订阅者**。因此，发布者和订阅者都与服务器建立连接。

通过简单的图表很容易理解事物是如何工作的。以下图表显示了一个发布者和两个订阅者连接到服务器：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/987de943-ac68-4a91-af30-20bcdb0cca5b.png)

连接有高度传感器的**树莓派 3 型 B+**板是一个发布者，它与服务器建立连接。**BeagleBone Black**板和**Udoo Neo**板是两个订阅者，它们与服务器建立连接。

**BeagleBone Black**板向服务器指示要订阅属于**传感器/无人机 01/高度**主题的所有消息。**Udoo Neo**板也向服务器指示相同的内容。因此，两个板都订阅了**传感器/无人机 01/高度**主题。

*主题*是一个命名的逻辑通道，也称为通道或主题。服务器只会向订阅了特定主题的订阅者发送消息。

**Raspberry Pi 3 Model B+**板发布了一个有效负载为**100 英尺**，主题为**sensors/drone01/altitude**的消息。这个板，也就是发布者，向服务器发送了发布请求。

消息的数据称为**有效负载**。消息包括它所属的主题和有效负载。

服务器将消息分发给订阅了**sensors/drone01/altitude**主题的两个客户端：**BeagleBone Black**和**Udoo Neo**板。

发布者和订阅者在空间上是解耦的，因为它们彼此不知道。发布者和订阅者不必同时运行。发布者可以发布一条消息，订阅者可以稍后接收。此外，发布操作与接收操作不是同步的。

发布者请求服务器发布一条消息，已订阅适当主题的不同客户端可以在不同时间接收消息。发布者可以将消息作为异步操作发送，以避免在服务器接收消息之前被阻塞。但是，也可以将消息作为同步操作发送到服务器，并且仅在操作成功后继续执行。在大多数情况下，我们将希望利用异步操作。

一个需要向数百个客户端发送消息的出版商可以通过向服务器进行单次发布操作来完成。服务器负责将发布的消息发送给所有已订阅适当主题的客户端。由于发布者和订阅者是解耦的，因此发布者不知道是否有任何订阅者会收听它即将发送的消息。因此，有时需要使订阅者也成为发布者，并发布一条消息，表明它已收到并处理了一条消息。具体要求取决于我们正在构建的解决方案的类型。MQTT 提供了许多功能，使我们在分析的许多场景中更轻松。我们将在整本书中使用这些不同的功能。

# 使用消息过滤

服务器必须确保订阅者只接收他们感兴趣的消息。在发布-订阅模式中，可以根据不同的标准过滤消息。我们将专注于分析*基于主题*的过滤，也称为基于主题的过滤。

考虑到每条消息都属于一个主题。当发布者请求服务器发布一条消息时，它必须同时指定主题和消息。服务器接收消息并将其传递给所有已订阅消息所属主题的订阅者。

服务器不需要检查消息的有效负载以将其传递给相应的订阅者；它只需要检查已到达的每条消息的主题，并在发布给相应订阅者之前进行过滤。

订阅者可以订阅多个主题。在这种情况下，服务器必须确保订阅者接收属于其订阅的所有主题的消息。通过另一个简单的图表，很容易理解事情是如何工作的。

以下图表显示了两个尚未发布任何消息的未来发布者，一个服务器和两个连接到服务器的订阅者：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/289669b0-5c2b-4519-9e17-0b795fb48fcd.png)

一个**Raspberry Pi 3 Model B+**板上连接了一个高度传感器，另一个**Raspberry Pi 3**板上连接了一个温度传感器，它们将成为两个发布者。一个**BeagleBone Black**板和一个**Udoo Neo**板是两个订阅者，它们与服务器建立连接。

**BeagleBone Black**板告诉服务器它想订阅属于**sensors/drone01/altitude**主题的所有消息。**Udoo Neo**板告诉服务器它想订阅属于以下两个主题之一的所有消息：**sensors/drone01/altitude**和**sensors/drone40/temperature**。因此，**Udoo Neo**板订阅了两个主题，而**BeagleBone Black**板只订阅了一个主题。

下图显示了两个发布者连接并通过服务器发布不同主题的消息后会发生什么：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/eebaf448-c739-4e3b-a6fc-c9ca3002a393.png)

**Raspberry Pi 3 Model B+**板发布了一个以**120 英尺**为有效载荷和**sensors/drone01/altitude**为主题的消息。即发布者的板发送发布请求到服务器。服务器将消息分发给订阅了**sensors/drone01/altitude**主题的两个客户端：**BeagleBone Black**和**Udoo Neo**板。

**Raspberry Pi 3**板发布了一个以**75 F**为有效载荷和**sensors/drone40/temperature**为主题的消息。即发布者的板发送发布请求到服务器。服务器将消息分发给唯一订阅了**sensors/drone40/temperature**主题的客户端：**Udoo Neo**板。因此，**Udoo Neo**板从服务器接收了两条消息，一条属于**sensors/drone01/altitude**主题，另一条属于**sensors/drone40/temperature**主题。

下图显示了当一个发布者通过服务器发布消息到一个主题，而这个主题只有一个订阅者时会发生什么：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/08bb62ae-cc96-4a44-8dfa-3bd68cbc61c3.png)

**Raspberry Pi 3**板发布了一个以**76 F**为有效载荷和**sensors/drone40/temperature**为主题的消息。即发布者的板发送发布请求到服务器。服务器将消息分发给唯一订阅了**sensors/drone40/temperature**主题的客户端：**Udoo Neo**板。

# 理解 MQTT 谜题-客户端、服务器和连接

在低于 3.1.1 版本的 MQTT 协议中，MQTT 服务器被称为 MQTT 代理。从 MQTT 3.1.1 开始，MQTT 代理被重命名为 MQTT 服务器，因此我们将称其为服务器。然而，我们必须考虑到 MQTT 服务器、工具和客户端库的文档可能会使用旧的 MQTT 代理名称来指代服务器。MQTT 服务器也被称为消息代理。

MQTT 服务器使用先前解释的基于主题的过滤器来过滤和分发消息给适当的订阅者。有许多 MQTT 服务器实现提供了通过提供自定义插件来提供额外的消息过滤功能。但是，我们将专注于作为 MQTT 协议要求一部分的功能。

如前所述，在 MQTT 中，发布者和订阅者是完全解耦的。发布者和订阅者都是仅与 MQTT 服务器建立连接的 MQTT 客户端。一个 MQTT 客户端可以同时是发布者和订阅者，也就是说，客户端可以向特定主题发布消息，同时接收订阅了的主题的消息。

各种流行的编程语言和平台都有 MQTT 客户端库可用。在选择 MQTT 客户端库时，我们必须考虑的最重要的事情之一是它们支持的 MQTT 功能列表以及我们解决方案所需的功能。有时，我们可以在特定编程语言和平台之间选择多个库，其中一些可能不实现所有功能。在本书中，我们将使用支持各种平台的现代 Python 版本的最完整的库。

任何具有 TCP/IP 协议栈并能够使用 MQTT 库的设备都可以成为 MQTT 客户端，即发布者、订阅者，或者既是发布者又是订阅者。MQTT 库使设备能够在 TCP/IP 协议栈上与 MQTT 通信，并与特定类型的 MQTT 服务器进行交互。例如，以下设备都可以成为 MQTT 客户端，除其他设备外：

+   一个 Arduino 板

+   一个树莓派 3 Model B+板

+   一个 BeagleBone Black 板

+   一个 Udoo Neo 板

+   一个 iPhone

+   一个 iPad

+   一个安卓平板电脑

+   一个安卓智能手机

+   运行 Windows 的笔记本电脑

+   运行 Linux 的服务器

+   运行 macOS 的 MacBook

许多 MQTT 服务器适用于最流行的平台，包括 Linux、Windows 和 macOS。其中许多是可以作为 MQTT 服务器工作并提供额外功能的服务器。MQTT 服务器可能只实现 MQTT 功能的子集，并可能具有特定的限制。因此，在选择 MQTT 服务器之前，检查我们解决方案中所需的所有功能非常重要。与其他中间件一样，我们有开源版本、免费版本和付费版本。因此，我们还必须确保根据我们的预算和特定需求选择适当的 MQTT 服务器。

在本书中，我们将使用 Eclipse Mosquitto MQTT 服务器（[`www.mosquitto.org`](http://www.mosquitto.org)）。Mosquitto 是一个开源的 MQTT 服务器，具有 EPL/EDL 许可证，与 MQTT 版本 3.1.1 和 3.1 兼容。我们可以利用我们学到的一切与其他 MQTT 服务器一起工作，比如**Erlang MQTT Broker**（**EMQ**），也称为 Emqttd（[`www.emqtt.io`](http://www.emqtt.io)），以及 HiveMQ（[`hivemq.com`](http://hivemq.com)），等等。此外，我们可能会利用我们的知识与基于云的 MQTT 服务器一起工作，比如 CloudMQTT（[`www.cloudmqtt.com`](http://www.cloudmqtt.com)）或 PubNub MQTT 桥接器（[`pubnub.com`](http://pubnub.com)）。我们还将专门与基于云的 MQTT 提供商一起工作。

MQTT 服务器是我们之前分析的发布-订阅模型的中心枢纽。MQTT 服务器负责对将能够成为发布者和/或订阅者的 MQTT 客户端进行身份验证和授权。因此，MQTT 客户端必须做的第一件事就是与 MQTT 服务器建立连接。

为了建立连接，MQTT 客户端必须向 MQTT 服务器发送一个带有有效载荷的`CONNECT`控制数据包，该有效载荷必须包括启动连接和进行身份验证和授权所需的所有必要信息。MQTT 服务器将检查`CONNECT`数据包，执行身份验证和授权，并向客户端发送一个`CONNACK`控制数据包的响应，我们将在理解`CONNECT`控制数据包后详细分析。如果 MQTT 客户端发送了无效的`CONNECT`控制数据包，服务器将自动关闭连接。

以下图显示了 MQTT 客户端与 MQTT 服务器之间建立连接的交互：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/38f3b9e7-aa98-49a9-8f4f-1eea5545a86f.png)

在 MQTT 客户端和 MQTT 服务器之间建立成功连接后，服务器将保持连接开放，直到客户端失去连接或向服务器发送`DISCONNECT`控制数据包以关闭连接。

`CONNECT`控制数据包的有效载荷必须包括以下字段的值，以及包含在控制数据包中的特殊标志字节的位。我们希望理解这些字段和标志的含义，因为当我们使用 Python 中的 MQTT 工具和 MQTT 客户端库时，我们将能够指定它们的值：

+   `ClientId`：客户端标识符，也称为客户端 ID，是一个字符串，用于标识连接到 MQTT 服务器的每个 MQTT 客户端。连接到 MQTT 服务器的每个客户端必须具有唯一的`ClientId`，服务器使用它来标识与客户端和服务器之间的 MQTT 会话相关的状态。如果客户端将空值指定为`ClientId`，MQTT 服务器必须生成一个唯一的`ClientId`来标识客户端。但是，此行为取决于为`CleanSession`字段指定的值。

+   `CleanSession`：清理会话标志是一个布尔值，指定 MQTT 客户端从 MQTT 服务器断开连接然后重新连接后会发生什么。如果`CleanSession`设置为`1`或`True`，客户端向 MQTT 服务器指示会话只会持续到网络连接保持活跃。MQTT 客户端从 MQTT 服务器断开连接后，与会话相关的任何信息都会被丢弃。同一 MQTT 客户端重新连接到 MQTT 服务器时，不会使用上一个会话的数据，而会创建一个新的清理会话。如果`CleanSession`设置为`0`或`False`，我们将使用持久会话。在这种情况下，MQTT 服务器会存储 MQTT 客户端的所有订阅，当 MQTT 客户端断开连接时，MQTT 服务器会存储与订阅匹配的特定服务质量级别的所有消息。这样，当同一 MQTT 客户端与 MQTT 服务器建立新连接时，MQTT 客户端将拥有相同的订阅，并接收在失去连接时无法接收的所有消息。我们将在后面的第二章中深入探讨消息的服务质量级别及其与清理会话标志或持久会话选项的关系。

当清理会话标志设置为`0`或`False`时，客户端向服务器指示它需要一个持久会话。我们只需要记住，清理会话是持久会话的相反。

+   `UserName`：如果客户端想要指定一个用户名来请求 MQTT 服务器的认证和授权，它必须将`UserName`标志设置为`1`或`True`，并为`UserName`字段指定一个值。

+   `Password`：如果客户端想要指定一个密码来请求 MQTT 服务器的认证和授权，它必须将`Password`标志设置为`1`或`True`，并为`Password`字段指定一个值。

我们将专门为 MQTT 安全性撰写一整章，因此我们只提及`CONNECT`控制数据包中包含的字段和标志。

+   `ProtocolLevel`：协议级别值指示 MQTT 客户端请求 MQTT 服务器使用的 MQTT 协议版本。请记住，我们将始终使用 MQTT 版本 3.1.1。

+   `KeepAlive`：`KeepAlive`是以秒为单位表示的时间间隔。如果`KeepAlive`的值不等于`0`，MQTT 客户端承诺在指定的`KeepAlive`时间内向服务器发送控制数据包。如果 MQTT 客户端不必发送任何控制数据包，它必须向 MQTT 服务器发送一个`PINGREQ`控制数据包，以告知 MQTT 服务器客户端连接仍然活跃。MQTT 服务器会用`PINGRESP`响应控制数据包回应 MQTT 客户端，以告知 MQTT 客户端与 MQTT 服务器的连接仍然活跃。当缺少这些控制数据包时，连接将被关闭。如果`KeepAlive`的值为`0`，则保持活动机制将被关闭。

+   Will，WillQoS，WillRetain，WillTopic 和 WillMessage：这些标志和字段允许 MQTT 客户端利用 MQTT 的遗嘱功能。如果 MQTT 客户端将 Will 标志设置为 1 或 True，则指定它希望 MQTT 服务器存储与会话关联的遗嘱消息。WillQoS 标志指定了遗嘱消息的期望服务质量，而 WillRetain 标志指示发布此消息时是否必须保留。如果 MQTT 客户端将 Will 标志设置为 1 或 True，则必须在 WillTopic 和 WillMessage 字段中指定 Will 消息的主题和消息。如果 MQTT 客户端断开连接或与 MQTT 服务器失去连接，MQTT 服务器将使用 WillTopic 字段中指定的主题以所选的服务质量发布 WillMessage 字段中指定的消息。我们将稍后详细分析此功能。

MQTT 服务器将处理有效的 CONNECT 控制数据包，并将以 CONNACK 控制数据包作出响应。此控制数据包将包括标头中包含的以下标志的值。我们希望了解这些标志的含义，因为在使用 MQTT 工具和 MQTT 客户端库时，我们将能够检索它们的值：

+   SessionPresent: 如果 MQTT 服务器收到了一个将 CleanSession 标志设置为 1 或 True 的连接请求，SessionPresent 标志的值将为 0 或 False，因为不会重用任何存储的会话。如果连接请求中的 CleanSession 标志设置为 0 或 False，MQTT 服务器将使用持久会话，并且如果服务器从先前的连接中为客户端检索到持久会话，则 SessionPresent 标志的值将为 1 或 True。否则，SessionPresent 将为 0 或 False。想要使用持久会话的 MQTT 客户端可以使用此标志的值来确定是否必须请求订阅所需主题，或者订阅是否已从持久会话中恢复。

+   ReturnCode: 如果授权和认证通过，并且连接成功建立，ReturnCode 的值将为 0。否则，返回代码将不同于 0，客户端和服务器之间的网络连接将被关闭。以下表格显示了 ReturnCode 的可能值及其含义：

| ReturnCode 值 | 描述 |
| --- | --- |
| 0 | 连接被接受 |
| 1 | 由于 MQTT 服务器不支持 MQTT 客户端在 CONNECT 控制数据包中请求的 MQTT 协议版本，连接被拒绝 |
| 2 | 由于指定的 ClientId（客户端标识符）已被拒绝，连接被拒绝 |
| 3 | 由于网络连接已建立但 MQTT 服务不可用，连接被拒绝 |
| 4 | 由于用户名或密码数值格式不正确，连接被拒绝 |
| 5 | 由于授权失败，连接被拒绝 |

# 在 Linux 上安装 Mosquitto 服务器

现在，我们将学习在最流行的操作系统上安装 Mosquitto 服务器所需的步骤：Linux，macOS 和 Windows。

使用最新版本的 Mosquitto 非常重要，以确保解决了先前版本中发现的许多安全漏洞。例如，Mosquitto 1.4.15 解决了影响版本 1.0 至 1.4.14（含）的两个重要安全漏洞。

首先，我们将从 Linux 开始；具体来说，我们将使用 Ubuntu Linux。如果您想使用其他 Linux 发行版，您可以在 Mosquitto 下载部分找到有关安装过程的详细信息：[`mosquitto.org/download`](http://mosquitto.org/download)。

按照以下步骤在 Ubuntu Linux 上安装 Mosquitto 服务器；请注意，您需要 root 权限：

1.  打开终端窗口或使用安全 shell 访问 Ubuntu，并运行以下命令以添加 Mosquitto 存储库：

```py
 sudo apt-add-repository ppa:mosquitto-dev/mosquitto-ppa 
```

您将看到类似于下面的输出（临时文件名将不同）：

```py
 gpg: keyring `/tmp/tmpi5yrsz7i/secring.gpg' created
 gpg: keyring `/tmp/tmpi5yrsz7i/pubring.gpg' created
 gpg: requesting key 262C4500 from hkp server keyserver.ubuntu.com
 gpg: /tmp/tmpi5yrsz7i/trustdb.gpg: trustdb created
 gpg: key 262C4500: public key "Launchpad mosquitto" imported
 gpg: Total number processed: 1
 gpg: imported: 1 (RSA: 1)
 OK
```

1.  运行以下命令以更新最近添加的 Mosquitto 存储库中的软件包：

```py
 sudo apt-get update
```

您将看到类似于下面的输出。请注意，下面的行显示了作为 Windows Azure 虚拟机运行的 Ubuntu 服务器的输出，因此输出将类似：

```py
 Hit:1 http://azure.archive.ubuntu.com/ubuntu xenial InRelease
      Get:2 http://azure.archive.ubuntu.com/ubuntu xenial-updates       
      InRelease [102 kB]
      Get:3 http://azure.archive.ubuntu.com/ubuntu xenial-backports 
      InRelease [102 kB]

      ...

      Get:32 http://security.ubuntu.com/ubuntu xenial-security/universe        
      Translation-en [121 kB]
      Get:33 http://security.ubuntu.com/ubuntu xenial-
      security/multiverse amd64 Packages [3,208 B]
      Fetched 12.8 MB in 2s (4,809 kB/s)
      Reading package lists... Done
```

1.  现在，运行以下命令以安装 Mosquitto 服务器的软件包：

```py
 sudo apt-get install mosquitto
```

您将看到类似于下面的输出。

1.  输入`Y`并按*Enter*回答问题，完成安装过程：

```py
 Building dependency tree
      Reading state information... Done
      The following additional packages will be installed:
        libev4 libuv1 libwebsockets7
      The following NEW packages will be installed:
        libev4 libuv1 libwebsockets7 mosquitto
      0 upgraded, 4 newly installed, 0 to remove and 29 not upgraded.
      Need to get 280 kB of archives.
      After this operation, 724 kB of additional disk space will be 
      used.
      Do you want to continue? [Y/n] Y
```

1.  最后几行应包括一行，其中说`Setting up mosquitto`，后面跟着版本号，如下所示：

```py
 Setting up libuv1:amd64 (1.8.0-1) ...
 Setting up libev4 (1:4.22-1) ...
 Setting up libwebsockets7:amd64 (1.7.1-1) ...
 Setting up mosquitto (1.4.15-0mosquitto1~xenial1) ...
 Processing triggers for libc-bin (2.23-0ubuntu10) ...
 Processing triggers for systemd (229-4ubuntu21.1) ...
 Processing triggers for ureadahead (0.100.0-19) ...
```

1.  现在，运行以下命令以安装 Mosquitto 客户端软件包，这将允许我们运行命令以发布消息到主题和订阅主题过滤器：

```py
 sudo apt-get install mosquitto-clients
```

您将看到类似于下面的输出。

1.  输入`Y`并按*Enter*回答问题，完成安装过程：

```py
 Reading package lists... Done
 Building dependency tree
 Reading state information... Done
 The following additional packages will be installed:
 libc-ares2 libmosquitto1
 The following NEW packages will be installed:
 libc-ares2 libmosquitto1 mosquitto-clients
 0 upgraded, 3 newly installed, 0 to remove and 29 not upgraded.
 Need to get 144 kB of archives.
 After this operation, 336 kB of additional disk space will be   
      used.
 Do you want to continue? [Y/n] Y
```

最后几行应包括一行，其中说`Setting up mosquitto-clients`，后面跟着版本号，如下所示：

```py
 Setting up libmosquitto1:amd64 (1.4.15-0mosquitto1~xenial1) ...
      Setting up mosquitto-clients (1.4.15-0mosquitto1~xenial1) ...
      Processing triggers for libc-bin (2.23-0ubuntu10) ... 
```

1.  最后，运行以下命令来检查最近安装的`mosquitto`服务的状态：

```py
 sudo service mosquitto status
```

输出的前几行应类似于以下行，显示`active (running)`状态。`CGroup`后面的详细信息指示启动服务的命令行。`-c`选项后跟`/etc/mosquitto/mosquitto.conf`指定 Mosquitto 正在使用此配置文件：

```py
mosquitto.service - LSB: mosquitto MQTT v3.1 message broker
 Loaded: loaded (/etc/init.d/mosquitto; bad; vendor preset: enabled)
 Active: active (running) since Sun 2018-03-18 19:58:15 UTC; 3min 8s ago
 Docs: man:systemd-sysv-generator(8)
 CGroup: /system.slice/mosquitto.service
 └─15126 /usr/sbin/mosquitto -c /etc/mosquitto/mosquitto.conf
```

您还可以运行以下命令来检查 Mosquitto MQTT 服务器是否在默认端口`1883`上监听：

```py
netstat -an | grep 1883
```

以下行显示了上一个命令的结果，指示 Mosquitto MQTT 服务器已在端口`1883`上打开了 IPv4 和 IPv6 监听套接字：

```py
tcp 0 0 0.0.0.0:1883 0.0.0.0:* LISTEN

tcp6 0 0 :::1883 :::* LISTEN 
```

# 在 macOS 上安装 Mosquitto 服务器

按照以下步骤在 macOS 上安装 Mosquitto 服务器，即 macOS Sierra 之前的 OS X：

1.  如果您尚未安装 Homebrew，请打开终端窗口并运行 Homebrew 主页上指定的命令[`brew.sh`](http://brew.sh)，以安装 macOS 的这个流行软件包管理器。以下命令将完成工作。但是，最好检查 Homebrew 主页并查看所有始终更新为最新 macOS 版本的详细说明。如果您已经安装了 Homebrew，请转到下一步：

```py
 /usr/bin/ruby -e "$(curl -fsSL      
    https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

1.  打开终端窗口并运行以下命令以请求 Homebrew 安装 Mosquitto：

```py
 brew install mosquitto
```

请注意，在某些情况下，Homebrew 可能需要在您安装 Mosquitto 之前在计算机上安装其他软件。如果需要安装其他软件，例如 Xcode 命令行工具，Homebrew 将为您提供必要的说明。

1.  以下行显示了在终端中显示的最后消息，指示 Homebrew 已安装 Mosquitto 并启动 MQTT 服务器的说明：

```py
 ==> Installing dependencies for mosquitto: c-ares, openssl, 
 libev, libuv, libevent, libwebsockets
 ==> Installing mosquitto dependency: c-ares
 ==> Caveats
 A CA file has been bootstrapped using certificates from the 
 SystemRoots
 keychain. To add additional certificates (e.g. the certificates 
 added in the System keychain), place .pem files in
 /usr/local/etc/openssl/certs and run
 /usr/local/opt/openssl/bin/c_rehash

 This formula is keg-only, which means it was not symlinked into 
 /usr/local, because Apple has deprecated use of OpenSSL in favor 
 of its own TLS and crypto libraries. If you need to have this 
 software first in your PATH run:
 echo 'export PATH="/usr/local/opt/openssl/bin:$PATH"' >> 
 ~/.bash_profile

 For compilers to find this software you may need to set:
 LDFLAGS: -L/usr/local/opt/openssl/lib
 CPPFLAGS: -I/usr/local/opt/openssl/include

 ==> Installing mosquitto
 ==> Downloading https://homebrew.bintray.com/bottles/mosquitto- 
 1.4.14_2.el_capit
 ##################################################
 #####################100.0%
 ==> Pouring mosquitto-1.4.14_2.el_capitan.bottle.tar.gz
 ==> Caveats
 mosquitto has been installed with a default configuration file.
 You can make changes to the configuration by editing:
 /usr/local/etc/mosquitto/mosquitto.conf

 To have launchd start mosquitto now and restart at login:
 brew services start mosquitto

 Or, if you don't want/need a background service you can just run:
 mosquitto -c /usr/local/etc/mosquitto/mosquitto.conf
```

1.  Mosquitto 安装完成后，在新的终端窗口中运行以下命令以使用默认配置文件启动 Mosquitto。 `-c`选项后跟`/usr/local/etc/mosquitto/mosquitto.conf`指定我们要使用此配置文件：

```py
 /usr/local/sbin/mosquitto -c       
     /usr/local/etc/mosquitto/mosquitto.conf
```

在运行上一个命令后，以下是输出结果：

```py
 1521488973: mosquitto version 1.4.14 (build date 2017-10-22 
 16:34:20+0100) starting
 1521488973: Config loaded from 
 /usr/local/etc/mosquitto/mosquitto.conf.
 1521488973: Opening ipv4 listen socket on port 1883.
 1521488973: Opening ipv6 listen socket on port 1883.
```

最后几行指示 Mosquitto MQTT 服务器已在默认 TCP 端口`1883`上打开了 IPv4 和 IPv6 监听套接字。保持终端窗口打开，因为我们需要在本地计算机上运行 Mosquitto 以使用下面的示例。

# 在 Windows 上安装 Mosquitto 服务器

按照以下步骤在 Windows 上安装 Mosquitto 服务器。请注意，您需要 Windows Vista 或更高版本（Windows 7、8、8.1、10 或更高版本）。这些说明也适用于 Windows Server 2008、2012、2016 或更高版本：

1.  在 Mosquitto 下载网页上下载提供本机构建的可执行文件，该网页列出了二进制安装和 Windows 下的文件：[`mosquitto.org/download`](http://mosquitto.org/download)。对于 Mosquitto 1.4.15，文件名为`mosquitto-1.4.15-install-win32.exe`。您必须单击或点击文件名，然后将被重定向到 Eclipse 存储库，其中包括默认推荐的许多镜像选项，您可以从中下载可执行文件。

1.  运行先前下载的可执行文件，mosquitto 设置向导将显示其欢迎对话框。单击“下一步>”继续。设置向导将显示您必须安装的依赖项：OpenSSL 和 pthreads。对话框将显示您可以使用的链接来下载和运行这两个要求的安装程序，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/2e12e15c-544b-484b-8719-da419fa7c04d.png)

1.  如果您在 Windows 上没有安装 Win32 OpenSSL v1.0.2j Light，请转到 Win32 OpenSSL 网页，[`slproweb.com/products/Win32OpenSSL.html`](http://slproweb.com/products/Win32OpenSSL.html)，并下载`Win32 OpenSSL v1.1.0g Light`文件。不要下载 Win64 版本，因为您需要 Win32 版本才能使 Mosquitto 具有其依赖项。如果您已经安装了 Win32 OpenSSL v1.1.0g Light，请转到第 7 步。对于 Win32 OpenSSL v1.1.0g Light，文件名为`Win32OpenSSL_Light-1_1_0g.exe`。运行下载的可执行文件，OpenSSL Light（32 位）将显示其欢迎对话框。单击“下一步>”继续。

1.  设置向导将显示许可协议。阅读并选择“我接受协议”，然后单击“下一步>”。如果您不想使用默认文件夹，请选择要安装 OpenSSL Light（32 位）的文件夹。请记住您指定的文件夹，因为您稍后需要从此文件夹复制一些 DLL 文件。默认文件夹为`C:\OpenSSL-Win32`。

1.  单击“下一步>”继续，如有必要，指定不同的开始菜单文件夹，然后单击“下一步>”。选择 OpenSSL 二进制文件（/bin）目录作为“复制 OpenSSL DLLs”的所需选项。这样，安装将把 DLL 复制到先前指定文件夹内的`bin`子文件夹中，默认为`C:\OpenSSL-Win32\bin`。

1.  单击“下一步>”继续。查看所选的安装选项，然后单击“安装”以完成 OpenSSL Light（32 位）的安装。最后，考虑向 Win32 OpenSSL 项目捐赠，然后单击“完成”退出设置。

1.  在 Web 浏览器中转到以下地址：ftp://sources.redhat.com/pub/pthreads-win32/dll-latest/dll/x86。浏览器将显示此 FTP 目录的许多文件。右键单击**pthreadVC2.dll**，然后将文件保存在您的`Downloads`文件夹中。稍后您需要将此 DLL 复制到 Mosquitto 安装文件夹中。

1.  现在，返回到 Mosquitto 设置窗口，单击“下一步>”继续。默认情况下，Mosquitto 将安装文件和 Mosquitto 服务。保留默认组件以安装所选内容，然后单击“下一步>”继续。

1.  如果您不想使用默认文件夹，请选择要安装 Mosquitto 的文件夹。请记住您指定的文件夹，因为您稍后需要将一些 DLL 文件复制到此文件夹。默认文件夹为`C:\Program Files (x86)\mosquitto`。单击“安装”以完成安装。请注意，mosquitto 设置向导可能会显示与缺少 DLL 相关的错误。我们将在接下来的步骤中解决此问题。安装完成后，单击“完成”关闭 mosquitto 设置向导。

1.  打开文件资源管理器窗口，转到您安装 OpenSSL Light（32 位）的文件夹中的`bin`子文件夹，默认情况下为`C:\OpenSSL-Win32\bin`。

1.  复制以下四个 DLL 文件：`libcrypto-1_1.dll`、`libeay32.dll`、`ssleay32.dll`和`libssl-1_1.dll`。现在，转到您安装 Mosquitto 的文件夹，并将这四个 DLL 粘贴进去。默认情况下，Mosquitto 安装文件夹是`C:\Program Files (x86)\mosquitto`。您需要提供管理员权限才能将 DLL 粘贴到默认文件夹中。

1.  打开文件资源管理器窗口，转到您的下载文件夹。复制您在先前步骤中下载的 pthreads DLL，`pthreadVC2.dll`。现在，转到您安装 Mosquitto 的文件夹，并将此 DLL 粘贴进去。您需要提供管理员权限才能将 DLL 粘贴到默认的 Mosquitto 安装文件夹中。

1.  现在，所有依赖项都包含在 Mosquitto 安装文件夹中，需要再次运行安装程序以使 Mosquitto 设置配置 Windows 服务。再次运行先前下载的 Mosquitto 安装可执行文件。对于 Mosquitto 1.4.15，文件名是`mosquito-1.4.15-install-win32.exe`。确保指定与您复制 DLL 的文件夹相同的安装文件夹，并激活`Service`组件。点击**下一步**多次，然后点击**安装**以完成 Windows 服务的配置。安装完成后，点击完成以关闭 Mosquitto 设置向导。

1.  在 Windows 中打开服务应用程序，并搜索服务名称为**Mosquitto Broker**的服务。右键单击服务名称，然后选择**启动**。状态将变为**运行**。默认情况下，服务配置为其**启动类型**设置为**自动**。如果您不想自动启动 Mosquitto Broker 服务，请将**启动类型**更改为**手动**。在 Windows 计算机上使用 Mosquitto 之前，您必须重复手动启动服务的步骤。请注意，服务的描述为 MQTT v3.1 代理，如下图所示。该描述已过时，因为该服务提供了一个与 MQTT 3.1 兼容的 MQTT 3.1.1 服务器。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/99ddba70-39f6-4886-9c6f-3e195f5724b0.png)

打开 Windows PowerShell 或命令提示符窗口，并运行以下命令以检查 Mosquitto MQTT 服务器是否在默认 TCP 端口`1883`上监听：

```py
 netstat -an | findstr 1883
```

以下行显示了先前命令的结果，表明 Mosquitto MQTT 服务器已在端口`1883`上打开了 IPv4 和 IPv6 监听套接字：

```py
 TCP 0.0.0.0:1883 0.0.0.0:0 LISTENING
 TCP [::]:1883 [::]:0 LISTENING
```

# 在云中运行 Mosquitto 服务器时需要考虑的事项

我们已经在 Linux、macOS 和 Windows 上使用了 Mosquitto 服务器的默认配置。Mosquitto 服务器将使用 TCP 端口`1883`。如果您想从其他设备或计算机与 Mosquitto 服务器交互，您必须确保运行在您计算机上的防火墙对该端口号有适当的配置。

当您在云中的 Linux 或 Windows 虚拟机上运行 Mosquitto 服务器时，您还必须确保虚拟机网络过滤器对入站和出站流量都有适当的配置，以允许端口`1883`上的入站和出站流量。您必须授权端口`1883`上的入站和出站流量。

# 测试您的知识

让我们看看您是否能正确回答以下问题：

1.  MQTT 运行在以下之上：

1.  MQIP 协议

1.  TCP/IP 协议

1.  物联网协议

1.  MQTT 消息的数据称为：

1.  有效载荷

1.  数据包

1.  上传

1.  在 MQTT 3.1.1 版本中，代理被命名为：

1.  MQTT 代理

1.  MQTT 客户端

1.  MQTT 服务器

1.  Mosquitto 是：

1.  仅在 Windows Azure 上可用的基于云的 MQTT 服务器

1.  仅在亚马逊网络服务上可用的基于云的 MQTT 服务器

1.  与 MQTT 版本 3.1.1 和 3.1 兼容的开源 MQTT 服务器

1.  Mosquitto 服务器使用的默认 TCP 端口是：

1.  `22`

1.  `1883`

1.  `9000`

正确答案包含在附录的*Solutions*部分中。

# 总结

在本章中，我们开始了解 MQTT 协议。我们了解了该协议的便利场景，发布-订阅模式的细节以及消息过滤。我们学习了与 MQTT 相关的基本概念，并了解了不同的组件：客户端、服务器或代理和连接。

我们学会了在 Linux、macOS 和 Windows 上安装 Mosquitto 服务器。我们使用了默认配置，因为这样可以让我们在使用 Mosquitto 的同时了解其内部工作原理。然后，我们将保护服务器。这样，我们就可以更容易地开始使用 Python 客户端库来发布 MQTT 消息和订阅 MQTT 主题过滤器。

现在我们的环境已经准备好开始使用尚未安全保护的 Mosquitto 服务器进行工作，我们将使用命令行和图形界面工具来详细了解 MQTT 的工作原理。我们将学习 MQTT 的基础知识，MQTT 的特定词汇以及其工作模式，这些都是我们将在第二章中讨论的主题，*使用命令行和图形界面工具来学习 MQTT 的工作原理*。


# 第二章：使用命令行和 GUI 工具学习 MQTT 的工作原理

在本章中，我们将使用命令行和 GUI 工具详细了解 MQTT 3.1.1 的工作原理。我们将学习 MQTT 的基础知识，MQTT 的特定词汇以及其工作模式。我们将使用不同的实用程序和图表来了解与 MQTT 相关的最重要的概念。在编写 Python 代码与 MQTT 协议一起工作之前，我们将了解我们需要知道的一切。我们将使用不同的服务质量（QoS）级别，并分析和比较它们的开销。我们将了解以下内容：

+   使用命令行工具订阅主题

+   使用 GUI 工具订阅主题

+   使用命令行工具发布消息

+   使用 GUI 工具发布消息

+   使用 GUI 工具取消订阅主题

+   学习主题的最佳实践

+   理解 MQTT 通配符

+   了解不同的服务质量级别

+   使用至少一次传递（QoS 级别 1）工作

+   使用恰好一次传递（QoS 级别 2）工作

+   理解不同服务质量级别的开销

# 使用命令行工具订阅主题

无人机是一种与许多传感器和执行器进行交互的物联网设备，包括与发动机、螺旋桨和伺服电机连接的数字电子调速器。无人机也被称为**无人驾驶飞行器**（**UAV**），但我们肯定会称其为无人机。假设我们必须监视许多无人机。具体来说，我们必须显示它们的高度和每个伺服电机的速度。并非所有无人机都具有相同数量的发动机、螺旋桨和伺服电机。我们必须监视以下类型的无人机：

| **名称** | **螺旋桨数量** |
| --- | --- |
| 四旋翼 | `4` |
| 六旋翼 | `6` |
| 八旋翼 | `8` |

每架飞行器将每 2 秒发布一次其高度到以下主题：`sensors/dronename/altitude`，其中`dronename`必须替换为分配给每架飞行器的名称。例如，名为`octocopter01`的飞行器将其高度值发布到`sensors/octocopter01/altitude`主题，名为`quadcopter20`的飞行器将使用`sensors/quadcopter20/altitude`主题。

此外，每架飞行器将每 2 秒发布一次其每个转子的速度到以下主题：`sensors/dronename/speed/rotor/rotornumber`，其中`dronename`必须替换为分配给每架飞行器的名称，`rotornumber`必须替换为将要发布速度的转子编号。例如，名为`octocopter01`的飞行器将其转子编号`1`的速度值发布到`sensors/octocopter01/speed/rotor/1`主题。

我们将使用 Mosquitto 中包含的`mosquitto_sub`命令行实用程序生成一个简单的 MQTT 客户端，该客户端订阅主题并打印接收到的所有消息。在 macOS 或 Linux 中打开终端，或在 Windows 中打开命令提示符，转到 Mosquitto 安装的目录，并运行以下命令：

```py
mosquitto_sub -V mqttv311 -t sensors/octocopter01/altitude -d
```

如果您想使用 Windows PowerShell 而不是命令提示符，您将不得不在`mosquitto_sub`之前添加`.\`作为前缀。

上述命令将创建一个 MQTT 客户端，该客户端将与本地 MQTT 服务器建立连接，然后将使客户端订阅在`-t`选项之后指定的主题：`sensors/octocopter01/altitude`。当客户端建立连接时，我们指定要使用的 MQTT 协议的版本为`-V mqttv311`。这样，我们告诉 MQTT 服务器我们要使用 MQTT 版本 3.11。我们指定`-d`选项以启用调试消息，这将使我们能够了解底层发生了什么。稍后我们将分析连接和订阅的其他选项。

终端或命令提示符窗口将显示类似以下行的调试消息。请注意，生成的`ClientId`将与`Client mosqsub|17040-LAPTOP-5D`之后显示的不同：

```py
Client mosqsub|17040-LAPTOP-5D sending CONNECT
Client mosqsub|17040-LAPTOP-5D received CONNACK
Client mosqsub|17040-LAPTOP-5D sending SUBSCRIBE (Mid: 1, Topic: sensors/octocopter01/altitude, QoS: 0)
Client mosqsub|17040-LAPTOP-5D received SUBACK
Subscribed (mid: 1): 0
```

终端或命令提示符窗口将显示从 MQTT 服务器到 MQTT 客户端的到达的消息。保持窗口打开。您将看到客户端向 MQTT 服务器发送`PINGREQ`数据包，并从 MQTT 服务器接收`PINQRESP`数据包。以下行显示了这些数据包的消息示例：

```py
Client mosqsub|17040-LAPTOP-5D sending PINGREQ
Client mosqsub|17040-LAPTOP-5D received PINGRESP
```

# 使用 GUI 工具订阅主题

MQTT.fx 是使用 JavaFX 实现的 GUI 实用程序，适用于 Windows、Linux 和 macOS。该工具允许我们连接到 MQTT 服务器，订阅主题过滤器，查看接收到的消息，并向主题发布消息。您可以从此实用程序的主网页的下载部分下载适合您操作系统的版本：[`www.mqttfx.org`](http://www.mqttfx.org)。

现在，我们将使用 MQTT.fx GUI 实用程序生成另一个订阅相同主题`sensors/octocopter01/altitude`并显示所有接收到的消息的 MQTT 客户端。我们将使用 MQTT.fx 版本 1.6.0。按照以下步骤：

1.  启动 MQTT.fx，在位于左上角的下拉菜单中选择本地 mosquitto，并单击该下拉菜单右侧和连接按钮左侧的配置图标。MQTT.fx 将显示带有名为本地 mosquitto 的连接配置文件的不同选项的编辑连接配置文件对话框。当我们学习 MQTT 客户端发送到 MQTT 服务器以建立连接的数据时，我们分析了许多这些选项。

1.  确保按下“General”按钮，并确保取消激活“MQTT 版本使用默认”复选框。确保在“MQTT 版本”下拉菜单中选择 3.1.1。这样，我们告诉 MQTT 服务器我们要使用 MQTT 版本 3.11。注意，客户端 ID 文本框指定了 MQTT_FX_Client。这是 MQTT.fx 将发送到 MQTT 服务器（Mosquitto）的`CONNECT`控制数据包中的`ClientId`值。以下屏幕截图显示了所选选项的对话框：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/a4b11c12-4981-4425-9cb3-08a384726ce2.png)

1.  单击“确定”，然后单击“连接”按钮。MQTT.fx 将与本地 Mosquitto 服务器建立连接。请注意，连接按钮已禁用，断开连接按钮已启用，因为客户端已连接到 MQTT 服务器。

1.  单击“订阅”，并在“订阅”按钮左侧的下拉菜单中输入`sensors/octocopter01/altitude`。然后，单击“订阅”按钮。MQTT.fx 将在左侧显示一个新面板，显示我们已订阅的主题，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/21f54e53-245a-4d99-abf6-d0bcd2f5d256.png)

如果您不想使用 MQTT.fx 实用程序，可以运行另一个`mosquitto_sub`命令，生成另一个订阅主题并打印接收到的所有消息的 MQTT 客户端。您只需要在 macOS 或 Linux 中打开另一个终端，或者在 Windows 中打开另一个命令提示符，转到安装 Mosquitto 的目录，并再次运行以下命令。在这种情况下，不需要指定此处给出的`-d`选项：

```py
mosquitto_sub -V mqttv311 -t sensors/octocopter01/altitude
```

现在，我们有两个订阅相同主题`sensors/octocopter01/altitude`的 MQTT 客户端。现在，我们将了解客户端订阅主题时发生的情况。

MQTT 客户端向 MQTT 服务器发送一个带有标识符（`PacketId`）的`SUBSCRIBE`数据包，并在有效载荷中包含一个或多个主题过滤器及其所需的服务质量级别。

**服务质量**被称为**QoS**。

因此，单个`SUBSCRIBE`数据包可以要求 MQTT 服务器订阅客户端到多个主题。`SUBSCRIBE`数据包必须至少包括一个主题过滤器和一个 QoS 对，以符合协议。

在我们请求订阅的两种情况下，我们使用特定的主题名称作为主题过滤器的值，因此我们要求 MQTT 服务器订阅单个主题。稍后我们将学习主题过滤器中通配符的使用。

我们使用了默认选项，因此请求的服务质量是默认级别 0。我们稍后将深入研究 QoS 级别。现在，我们将专注于最简单的订阅情况。如果 QoS 级别等于 0，则`PacketId`字段的值将为 0。如果 QoS 级别等于 1 或 2，则数据包标识符将具有一个数字值，以标识数据包并使其能够识别与此数据包相关的响应。

MQTT 服务器将处理有效的`SUBSCRIBE`数据包，并将用`SUBACK`数据包做出响应，该数据包指示订阅确认并确认了`SUBSCRIBE`数据包的接收和处理。 `SUBACK`数据包将在标头中包括与在`SUBSCRIBE`数据包中收到的`PacketId`相同的数据包标识符（`PacketId`）。 `SUBACK`数据包将包括每对主题过滤器和在`SUBSCRIBE`数据包中收到的所需 QoS 级别的返回代码。返回代码的数量将与`SUBSCRIBE`数据包中包含的主题过滤器的数量相匹配。以下表显示了这些返回代码的可能值。前三个返回代码表示成功订阅，每个值都指定了根据请求的 QoS 和 MQTT 服务器授予请求的 QoS 的可能性来交付的最大 QoS：

| **ReturnCode value** | **Description** |
| --- | --- |
| `0` | 成功订阅，最大 QoS 为 0 |
| `1` | 成功订阅，最大 QoS 为 1 |
| `2` | 成功订阅，最大 QoS 为 2 |
| `128` | 订阅失败 |

如果订阅成功，MQTT 服务器将开始将与订阅中指定的主题过滤器匹配的每条发布的消息以指定的 QoS 发送到 MQTT 客户端。

以下图表显示了 MQTT 客户端与 MQTT 服务器之间订阅一个或多个主题过滤器的交互：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/62ac841c-d673-4f39-9f9e-1e5b93dd0866.png)

# 使用命令行工具发布消息

我们将使用 Mosquitto 中包含的`mosquitto_pub`命令行实用程序生成一个简单的 MQTT 客户端，该客户端将向主题发布一条消息。在 macOS 或 Linux 中打开终端，或在 Windows 中打开命令提示符，转到安装 Mosquitto 的目录，并运行以下命令：

```py
mosquitto_pub -V mqttv311 -t sensors/octocopter01/altitude -m  "25 f" -d
```

上述命令将创建一个 MQTT 客户端，该客户端将与本地 MQTT 服务器建立连接，然后使客户端发布一条消息到`-t`选项后指定的主题：`sensors/octocopter01/altitude`。我们在`-m`选项后指定消息的有效载荷：`"25 f"`。当客户端建立连接时，我们指定要使用的 MQTT 协议的版本为`-V mqttv311`。这样，我们告诉 MQTT 服务器我们要使用 MQTT 版本 3.11。我们指定`-d`选项以启用调试消息，这将使我们能够了解底层发生了什么。稍后我们将分析连接和发布的其他选项。

终端或命令提示符窗口将显示类似以下行的调试消息。请注意，生成的`ClientId`将与`Client mosqpub|17912-LAPTOP-5D`后显示的不同。发布消息后，客户端将断开连接：

```py
Client mosqpub|17912-LAPTOP-5D sending CONNECT
Client mosqpub|17912-LAPTOP-5D received CONNACK
Client mosqpub|17912-LAPTOP-5D sending PUBLISH (d0, q0, r0, m1, 'sensors/octocopter01/altitude', ... (4 bytes))
Client mosqpub|17912-LAPTOP-5D sending DISCONNECT
```

# 使用 GUI 工具发布消息

现在，我们将使用 MQTT.fx GUI 实用程序生成另一个 MQTT 客户端，该客户端将发布另一条消息到相同的主题“sensors/octocopter01/altitude”。按照以下步骤进行：

1.  转到您建立连接并订阅主题的 MQTT.fx 窗口。

1.  单击“Publish”，并在发布按钮左侧的下拉菜单中输入`sensors/octocopter01/altitude`。

1.  在发布按钮下的文本框中输入以下文本：`32 f`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/755c6b63-1d41-4e44-baf3-f76cd78e484f.png)

1.  然后，单击发布按钮。 MQTT.fx 将发布输入的文本到指定的主题。

如果您不想使用 MQTT.fx 实用程序，可以运行另一个`mosquitto_pub`命令，以生成另一个发布消息到主题的 MQTT 客户端。您只需在 macOS 或 Linux 中打开另一个终端，或在 Windows 中打开另一个命令提示符，转到 Mosquitto 安装的目录，并运行以下命令：

```py
mosquitto_pub -V mqttv311 -t sensors/octocopter01/altitude -m "32 f"
```

现在，返回到您执行`mosquitto_sub`命令并订阅`sensors/octocopter01/atitude`主题的终端或命令提示符窗口。您将看到类似以下内容的行：

```py
Client mosqsub|3476-LAPTOP-5DO received PUBLISH (d0, q0, r0, m0, 'sensors/octocopter01/altitude', ... (4 bytes))
25 f
Client mosqsub|3476-LAPTOP-5DO received PUBLISH (d0, q0, r0, m0, 'sensors/octocopter01/altitude', ... (4 bytes))
32 f
```

如果我们清除以 Client 前缀开头的调试消息，我们将只看到接下来的两行。这些行显示了我们订阅`sensors/octocopter01/altitude`主题后收到的两条消息的有效负载：

```py
25 f
32 f
```

转到 MQTT.fx 窗口，单击订阅。您将在窗口左侧的面板中看到用于订阅的主题过滤器标题右侧的 2。MQTT.fx 告诉您，您已在`sensors/octocopter01/altitude`主题中收到两条消息。单击此面板，MQTT.fx 将在面板右侧显示所有收到的消息。 MQTT.fx 将在每条消息的右侧显示一个数字，以指定自订阅主题过滤器以来的消息编号。单击每条消息，MQTT.fx 将显示消息的 QoS 级别（0），接收日期和时间，以及消息的默认纯文本格式的有效负载。以下屏幕截图显示了订阅者由 MQTT.fx 生成的已收到的第二条消息的有效负载：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/041085e3-85c0-4701-9743-929abf57a7f8.png)

我们创建了两个发布者，每个发布者都向相同的主题`sensors/octocopter01/altitude`发布了一条消息。此主题的两个订阅者都收到了这两条消息。现在，我们将了解当客户端向主题发布消息时发生了什么。

已经建立连接的 MQTT 客户端向 MQTT 服务器发送一个包含以下字段和标志的`PUBLISH`数据包的标头。我们需要理解这些字段和标志的含义，因为当我们使用 MQTT 工具和 Python 中的 MQTT 客户端库时，我们将能够指定其中一些值：

+   `PacketId`：如果 QoS 级别等于 0，则此字段的值将为 0 或不存在。如果 QoS 级别等于 1 或 2，则数据包标识符将具有一个数字值，用于标识数据包并使其能够识别与此数据包相关的响应。

+   `Dup`：如果 QoS 级别等于 0，则此字段的值将为 0。如果 QoS 级别等于 1 或 2，则 MQTT 客户端库或 MQTT 服务器可以在订阅者未确认第一条消息时重新发送先前由客户端发布的消息。每当尝试重新发送已经发布的消息时，Dup 标志的值必须为 1 或`True`。

+   `QoS`：指定消息的 QoS 级别。我们将深入研究消息的服务质量级别，以及它们与许多其他标志的关系。到目前为止，我们一直在使用 QoS 级别 0。

+   `Retain`：如果此标志的值设置为`1`或`True`，MQTT 服务器将使用指定的 QoS 级别存储消息。每当新的 MQTT 客户端订阅与存储或保留消息的主题匹配的主题过滤器时，将向新订阅者发送此主题的最后存储的消息。如果此标志的值设置为`0`或`False`，MQTT 服务器将不会存储消息，并且不会替换具有相同主题的保留消息。

+   `TopicName`：要发布消息的主题名称的字符串。主题名称具有层次结构，斜杠(`/`)用作分隔符。在我们的示例中，`TopicName`的值是`"sensors/octocopter01/altitude"`。我们稍后将分析主题名称的最佳实践。

有效载荷包含 MQTT 客户端希望 MQTT 服务器发布的实际消息。MQTT 是数据无关的，因此我们可以发送任何二进制数据，我们不受 JSON 或 XML 等所施加的限制。当然，如果愿意，我们可以使用这些或其他方式来组织有效载荷。在我们的示例中，我们发送了一个包含表示海拔的数字，后跟一个空格和一个表示单位为`feet`的`"f"`的字符串。

MQTT 服务器将读取有效的`PUBLISH`数据包，并且只会对大于 0 的 QoS 级别做出响应。如果 QoS 级别为 0，则 MQTT 服务器不会做出响应。MQTT 服务器将识别所有订阅主题与消息指定的主题名称匹配的订阅者，并将消息发布给这些客户端。

以下图表显示了 MQTT 客户端与 MQTT 服务器之间以 QoS 级别 0 发布消息的交互：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/a27b8136-4eda-4a7e-8a36-375ac322adaf.png)

其他 QoS 级别具有不同的流程，发布者和 MQTT 服务器之间有额外的交互，并增加了我们稍后将分析的开销。

# 使用 GUI 工具取消订阅主题

每当我们不希望订阅者接收更多与一个或多个主题过滤器匹配的目标主题名称的消息时，订阅者可以向 MQTT 服务器发送取消订阅到主题过滤器列表的请求。显然，取消订阅主题过滤器与订阅主题过滤器相反。我们将使用 MQTT.fx GUI 实用程序从`sensors/octocopter01/altitude`主题中取消订阅 MQTT 客户端。按照以下步骤：

1.  转到您建立连接并订阅主题的 MQTT.fx 窗口。

1.  单击“订阅”。

1.  单击窗口左侧显示`sensors/octocopter01/altitude`主题名称的面板。然后，单击此面板中的“取消订阅”按钮。以下屏幕截图显示了此按钮：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/53c9f43c-2184-4463-9e55-7f9182472def.png)

1.  MQTT.fx 将取消订阅客户端的`sensors/octocopter01/altitude`主题，因此客户端将不会接收发布到`sensors/octocopter01/altitude`主题的任何新消息。

现在，我们将使用 MQTT.fx GUI 实用程序使 MQTT 客户端向`sensors/octocopter01/altitude`发布另一条消息。按照以下步骤：

1.  转到您建立连接并订阅主题的 MQTT.fx 窗口。

1.  单击“发布”并在“发布”按钮左侧的下拉菜单中输入`sensors/octocopter01/altitude`。

1.  然后，单击“发布”按钮。MQTT.fx 将向指定的主题发布输入的文本。

1.  在发布按钮下方的文本框中输入以下文本：`37 f`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/dd889680-10a8-4ad5-a871-1632586b5db3.png)

如果您不想使用 MQTT.fx 实用程序，您可以运行`mosquitto_pub`命令生成另一个 MQTT 客户端，以向主题发布消息。您只需要在 macOS 或 Linux 中打开另一个终端，或者在 Windows 中打开另一个命令提示符，转到 Mosquitto 安装的目录，并运行以下命令：

```py
mosquitto_pub -V mqttv311 -t sensors/octocopter01/altitude -m "37 f"
```

现在，返回到 MQTT.fx 窗口，点击订阅以检查已接收的消息。在我们发布新消息到`sensors/octocopter01/altitude`主题之前，客户端已经取消订阅了该主题，因此最近发布的带有负载`"37 f"`的消息没有显示出来。

返回到您执行`mosquitto_sub`命令并订阅`sensors/octocopter01/atitude`主题的终端或命令提示符窗口。您将看到类似以下的行：

```py
Client mosqsub|3476-LAPTOP-5DO received PUBLISH (d0, q0, r0, m0, 'sensors/octocopter01/altitude', ... (4 bytes))
37 f
```

该客户端仍然订阅`sensors/octocopter01/altitude`主题，因此它接收到了负载为`"37 f"`的消息。

MQTT 客户端向 MQTT 服务器发送一个带有头部中的数据包标识符（`PacketId`）和负载中的一个或多个主题过滤器的`UNSUBSCRIBE`数据包。与`SUBSCRIBE`数据包的主要区别在于，对于每个主题过滤器并不需要包括 QoS 等级，因为 MQTT 客户端只是想要取消订阅。

当 MQTT 客户端取消订阅一个或多个主题过滤器后，MQTT 服务器仍然保持连接打开；与`UNSUBSCRIBE`数据包中指定的主题过滤器不匹配的主题过滤器的订阅将继续工作。

因此，一个`UNSUBSCRIBE`数据包可以要求 MQTT 服务器取消订阅客户端的多个主题。`UNSUBSCRIBE`数据包必须至少包括一个主题过滤器的负载，以符合协议。

在前面的例子中，我们要求 MQTT 服务器取消订阅时，我们使用了特定的主题名称作为主题过滤器的值，因此我们请求 MQTT 服务器取消订阅单个主题。如前所述，我们将在后面学习主题过滤器中通配符的使用。

数据包标识符将具有一个数字值，用于标识数据包并使其能够识别与此`UNSUBSCRIBE`数据包相关的响应。MQTT 服务器将处理有效的`UNSUBSCRIBE`数据包，并将以`UNSUBACK`数据包作出响应，该数据包表示取消订阅的确认，并确认了`UNSUBSCRIBE`数据包的接收和处理。`UNSUBACK`数据包将在头部中包含与`UNSUBSCRIBE`数据包中接收到的相同的数据包标识符（`PacketId`）。

MQTT 服务器将删除`UNSUBSCRIBE`数据包的负载中指定的特定客户端的订阅列表中完全匹配的任何主题过滤器。主题过滤器匹配必须是精确的才能被删除。在 MQTT 服务器从客户端的订阅列表中删除主题过滤器后，服务器将停止向客户端添加要发布的新消息。只有已经以 QoS 等级为 1 或 2 开始传递到客户端的消息将被发布到客户端。此外，服务器可能会发布已经缓冲以分发给订阅者的现有消息。

以下图表显示了 MQTT 客户端与 MQTT 服务器在取消订阅一个或多个主题过滤器时的交互：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/5dedc49e-0158-46ca-b64f-07262736f3ce.png)

# 学习主题的最佳实践

我们已经知道 MQTT 允许我们在主题上发布消息。发布者必须始终指定要发布消息的主题名称。理解 MQTT 中主题名称的最简单方法是将它们视为文件系统中的路径。

如果我们需要保存数十个文件，这些文件包含有关不同类型传感器的信息，用于各种无人机，我们可以创建一个目录层次结构来组织我们将保存的所有文件。我们可以创建一个名为`sensors`的目录，然后为每个无人机创建一个子目录，比如`octocopter01`，最后再创建一个传感器名称的子目录，比如`altitude`。在 macOS 或 Linux 中的路径将是`sensors/octocopter01/altitude`，因为这些操作系统使用正斜杠(`/`)作为分隔符。在 Windows 中，路径将是`sensors\drone\altitude`，因为这个操作系统使用反斜杠(`\`)作为分隔符。

然后，我们将保存有关名为`octocopter01`的无人机的高度传感器信息的文件在创建的路径中。我们可以考虑发布消息到一个路径，使用与我们用于组织文件路径的相同机制来安排主题中的消息。

与目录或文件夹不同，主题具有主题级别，具体是主题级别的层次结构，并且斜杠(`/`)被用作分隔符，即主题级别分隔符。如果我们将`sensors/octocopter01/altitude`用作主题名称，`sensors`是第一个主题级别，`octocopter01`是第二个主题级别，`altitude`是第三个主题级别。

主题名称区分大小写，因此`sensors/octocopter01/altitude`与`sensors/Octocopter01/altitude`、`Sensors/octocopter01/altitude`和`Sensors/Octocopter01/Altitude`是不同的。实际上，这四个字符串将被视为四个单独的主题名称。我们必须确保为主题名称选择一个大小写方案，并将其用于所有主题名称和主题过滤器。

我们可以在主题名称中使用任何 UTF-8 字符，除了我们稍后将分析的两个通配符字符：加号(`+`)和井号(`#`)。因此，我们必须避免在主题名称中使用`+`和`#`。然而，限制字符集以避免客户端库出现意外问题是一个好的做法。例如，我们可以避免使用重音符号和在英语中不常见的字符，就像我们在构建 URL 时所做的那样。虽然可以使用这些字符，但在使用它们时可能会遇到问题。

我们应该避免创建以美元符号(`$`)开头的主题，因为许多 MQTT 服务器会在以`$`开头的主题中发布与服务器相关的统计数据。具体来说，第一个主题级别是`$SYS`。

在发送消息到不同主题名称时，我们必须保持一致性，就像我们在不同路径中保存文件时一样。例如，如果我们想要发布名为`hexacopter20`的无人机的高度，我们将使用`sensors/hexacopter20/altitude`。我们必须使用与为`octocopter01`相同目标使用的相同主题级别，只需将无人机名称从`octocopter01`更改为`hexacopter20`。使用不同结构或不一致大小写的主题将是一个非常糟糕的做法，比如`altitude/sensors/hexacopter20`或`Sensors/Hexacopter20/Altitude`。我们必须考虑到我们可以通过使用主题过滤器订阅多个主题，因此创建主题名称非常重要。

# 了解 MQTT 通配符

当我们分析订阅操作时，我们了解到 MQTT 客户端可以订阅一个或多个主题过滤器。如果我们将主题名称指定为主题过滤器，我们将只订阅一个单一主题。我们可以利用以下两个通配符来创建订阅与过滤器匹配的所有主题的主题过滤器：

+   **加号**(`+`)：这是一个单级通配符，匹配特定主题级别的任何名称。我们可以在主题过滤器中使用这个通配符，代替指定主题级别的名称。

+   **井号** (`#`)：这是一个多级通配符，我们只能在主题过滤器的末尾使用它，作为最后一级，并且它匹配任何主题，其第一级与`#`符号左侧指定的主题级别相同。

例如，如果我们想接收所有无人机海拔相关的消息，我们可以使用`+`单级通配符，而不是特定的无人机名称。我们可以使用以下主题过滤器：`sensors/+/altitude`。

如果我们发布消息到以下主题，使用`sensors/+/altitude`主题过滤器的订阅者将会收到所有这些消息：

+   `sensors/octocopter01/altitude`

+   `sensors/hexacopter20/altitude`

+   `sensors/superdrone01/altitude`

+   `sensors/thegreatestdrone/altitude`

使用`sensors/+/altitude`主题过滤器的订阅者将不会收到发送到以下任何主题的消息，因为它们不匹配主题过滤器：

+   `sensors/octocopter01/speed/rotor/1`

+   `sensors/superdrone01/speed/rotor/2`

+   `sensors/superdrone01/remainingbattery`

如果我们想接收所有名为`octocopter01`的无人机所有传感器相关的消息，我们可以在无人机名称后使用`#`多级通配符和斜杠(`/`)。我们可以使用以下主题过滤器：`sensors/octocopter01/#`。

如果我们发布消息到以下主题，使用`sensors/octocopter01/#`主题过滤器的订阅者将会收到所有这些消息：

+   `sensors/octocopter01/altitude`

+   `sensors/octocopter01/speed/rotor/1`

+   `sensors/octocopter01/speed/rotor/2`

+   `sensors/octocopter01/speed/rotor/3`

+   `sensors/octocopter01/speed/rotor/4`

+   `sensors/octocopter01/remainingbattery`

我们使用了多级通配符，因此，无论`sensors/octocopter01/`后面有多少额外的主题级别，我们都会收到所有这些消息。

使用`sensors/octocopter01/#`主题过滤器的订阅者将不会收到发送到以下任何主题的消息，因为它们不匹配主题过滤器。以下任何主题都没有`sensors/octocopter01/`作为前缀，因此它们不匹配主题过滤器：

+   `sensors/hexacopter02/altitude`

+   `sensors/superdrone01/altitude`

+   `sensors/thegreatestdrone/altitude`

+   `sensors/drone02/speed/rotor/1`

+   `sensors/superdrone02/speed/rotor/2`

+   `sensors/superdrone02/remainingbattery`

显然，当我们使用通配符时，必须小心，因为我们可能会使用单个主题过滤器订阅大量主题。我们必须避免订阅对客户端不感兴趣的主题，以避免浪费不必要的带宽和服务器资源。

稍后我们将在订阅中使用这些通配符，以分析不同的 QoS 级别如何与 MQTT 一起工作。

# 学习不同的 QoS 级别

现在我们了解了连接、订阅和发布如何与主题名称和带通配符的主题过滤器结合使用，我们可以深入了解 QoS 级别。到目前为止，我们已经分析了订阅和发布如何使用 QoS 级别等于 0。现在，我们将了解这个数字的含义，以及当我们使用其他可用的发布和订阅 QoS 级别时，事情是如何工作的。

记住，发布涉及从 MQTT 客户端到 MQTT 服务器的发布，然后从服务器到订阅的客户端。非常重要的是要理解，我们可以使用一个 QoS 级别进行发布，使用另一个 QoS 级别进行订阅。因此，发布过程中有一个 QoS 级别，用于发布者和 MQTT 服务器之间的过程，另一个 QoS 级别用于 MQTT 服务器和订阅者之间的发布过程。我们将使用发送者和接收者来识别参与不同 QoS 级别消息传递的各方。在发布者和 MQTT 服务器之间的发布过程中，发布者将是发送者，MQTT 服务器将是接收者。在 MQTT 服务器和订阅者之间的发布过程中，发送者将是 MQTT 服务器，接收者将是订阅者。

根据 QoS 级别，在 MQTT 协议中，发送方和接收方之间关于实际传递消息的保证的含义有所不同。QoS 级别是关于发送方和接收方之间消息保证的协议。这些保证可能包括消息到达的次数以及重复的可能性（或不可能性）。MQTT 支持以下三种可能的 QoS 级别：

+   **0，至多一次交付**：此 QoS 级别提供与基础 TCP 协议相同的保证。消息不会被接收方或目的地确认。发送方只是将消息发送到目的地，然后什么都不会发生。发送方既不存储也不安排任何可能未能到达目的地的消息的新交付。这个 QoS 级别的主要优势是与其他 QoS 级别相比，它具有最低的开销。

+   **1，至少一次交付**：此 QoS 级别向目的地添加了一个必须接收消息的确认要求。因此，QoS 级别 1 提供了消息至少一次传递给订阅者的保证。这个 QoS 级别的一个关键缺点是它可能会产生重复，也就是说，同一条消息可能会被发送多次到同一个目的地。发送方将消息存储，直到它收到订阅者的确认。如果发送方在特定时间内没有收到确认，它将再次向接收方发布消息。最终的接收方必须具有必要的逻辑来检测重复，如果它们不应该被处理两次的话。

+   **2，仅一次交付**：此 QoS 级别提供了消息仅一次传递到目的地的保证。与其他 QoS 级别相比，QoS 级别 2 具有最高的开销。此 QoS 级别需要发送方和接收方之间的两个流。使用 QoS 级别 2 发布的消息在发送方确信它已被目的地成功接收一次后被视为成功传递。

有时，我们只希望以最少的带宽使用交付消息，我们有一个非常可靠的网络，如果由于某种原因丢失了一些消息，也无所谓。在这种情况下，QoS 级别 0 是合适的选择。

在其他情况下，消息非常重要，因为它们代表了控制物联网设备的命令，网络不可靠，我们必须确保消息到达目的地。此外，重复的命令可能会产生大问题，因为我们不希望物联网设备处理特定命令两次。在这种情况下，QoS 级别 2 将是合适的选择。

如果发布者使用比订阅者指定的 QoS 级别更高的 QoS 级别，MQTT 服务器将不得不将 QoS 级别降级到特定订阅者使用的最低级别，当它从 MQTT 服务器向该订阅者发布消息时。例如，如果我们使用 QoS 级别 2 从发布者向 MQTT 服务器发布消息，但一个订阅者在订阅时请求了 QoS 级别 1，那么从 MQTT 服务器到该订阅者的发布将使用 QoS 级别 1。

# 使用至少一次交付（QoS 级别 1）

首先，我们将使用通配符订阅具有 QoS 级别 1 的主题过滤器，然后我们将向与 QoS 级别 1 匹配的主题名称发布一条消息。这样，我们将分析发布和订阅如何使用 QoS 级别 1。

我们将使用 Mosquitto 中包含的`mosquitto_sub`命令行实用程序生成一个简单的 MQTT 客户端，该客户端订阅具有 QoS 级别 1 的主题过滤器，并打印它接收到的所有消息。在 macOS 或 Linux 中打开终端，或在 Windows 中打开命令提示符，转到安装 Mosquitto 的目录，并运行以下命令：

```py
mosquitto_sub -V mqttv311 -t sensors/+/altitude -q 1 -d
```

上述命令将创建一个 MQTT 客户端，该客户端将与本地 MQTT 服务器建立连接，然后将使客户端订阅在`-t`选项之后指定的主题过滤器：`sensors/+/altitude`。我们指定要使用 QoS 级别 1 来订阅`-q 1`选项指定的主题过滤器。我们指定`-d`选项以启用调试消息，这将使我们能够了解底层发生的事情以及与使用 QoS 级别 0 发布消息时的差异。

终端或命令提示窗口将显示类似以下行的调试消息。请注意，生成的`ClientId`将与`Client mosqsub|16736-LAPTOP-5D`之后显示的不同。请注意，`QoS: 1`表示使用 QoS 级别 1 进行订阅：

```py
Client mosqsub|16736-LAPTOP-5D sending CONNECT
Client mosqsub|16736-LAPTOP-5D received CONNACK
Client mosqsub|16736-LAPTOP-5D sending SUBSCRIBE (Mid: 1, Topic: sensors/+/altitude, QoS: 1)
Client mosqsub|16736-LAPTOP-5D received SUBACK
Subscribed (mid: 1): 1
```

我们将使用 Mosquitto 中包含的`mosquitto_pub`命令行实用程序生成一个简单的 MQTT 客户端，该客户端将以 QoS 级别 1 发布消息到主题，而不是我们之前发布消息时使用的 QoS 级别 0。在 macOS 或 Linux 中打开终端，或在 Windows 中打开命令提示符，转到安装 Mosquitto 的目录，并运行以下命令：

```py
mosquitto_pub -V mqttv311 -t sensors/hexacopter02/altitude -m  "75 f" -q 1 -d
```

上述命令将创建一个 MQTT 客户端，该客户端将与本地 MQTT 服务器建立连接，然后将使客户端发布一条消息到`-t`选项之后指定的主题：`sensors/hexacopter02/altitude`。我们在`-m`选项之后指定消息的有效载荷：`"75 f"`。我们指定要使用 QoS 级别 1 来发布消息，使用`-q 1`选项。我们指定 X 选项以启用调试消息，这将使我们能够了解底层发生的事情以及与使用 QoS 级别 0 发布消息时的差异。

终端或命令提示窗口将显示类似以下行的调试消息。请注意，生成的`ClientId`将与`Client mosqpub|19544-LAPTOP-5D`之后显示的不同。发布消息后，客户端将断开连接：

```py
Client mosqpub|19544-LAPTOP-5D sending CONNECT
Client mosqpub|19544-LAPTOP-5D received CONNACK
Client mosqpub|19544-LAPTOP-5D sending PUBLISH (d0, q1, r0, m1, 'sensors/drone02/altitude', ... (4 bytes))
Client mosqpub|19544-LAPTOP-5D received PUBACK (Mid: 1)
Client mosqpub|19544-LAPTOP-5D sending DISCONNECT
```

上述行显示，生成的 MQTT 客户端向 MQTT 服务器发送`PUBLISH`数据包，然后从服务器接收`PUBACK`数据包。

现在，回到您执行`mosquitto_sub`命令并订阅`sensors/+/atitude`主题过滤器的终端或命令提示窗口。您将看到类似以下行的内容：

```py
Client mosqsub|16736-LAPTOP-5D received PUBLISH (d0, q1, r0, m1, 'sensors/drone02/altitude', ... (4 bytes))
Client mosqsub|16736-LAPTOP-5D sending PUBACK (Mid: 1)
75 f
```

上述行显示，生成的 MQTT 客户端，即订阅者，从 MQTT 服务器接收了`PUBLISH`数据包，然后向服务器发送了`PUBACK`数据包以确认消息。如果我们清除以`Client`前缀开头的调试消息，我们将只看到最后一行，显示我们订阅`sensors/+/altitude`主题过滤器后收到的消息的有效载荷：`75 f`。

已经建立连接的 MQTT 客户端，即发布者，向 MQTT 服务器发送了一个`PUBLISH`数据包，其中包含我们已经描述的标头，QoS 设置为 1，并包括一个`PacketId`数值，该数值对于此客户端是唯一的。此时，发布者将`PacketId`标识的`PUBLISH`数据包视为未确认的`PUBLISH`数据包。

MQTT 服务器读取有效的`PUBLISH`数据包，并使用与`PUBLISH`数据包相同的`PacketId`值向发布者发送`PUBACK`数据包。一旦发布者收到`PUBACK`数据包，它将丢弃消息，MQTT 服务器负责将其发布给适当的订阅者。

以下图表显示了发布者与 MQTT 服务器之间以 QoS 级别 1 发布消息的交互：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/6851968e-ccf4-41d2-bfde-a17bcfce7fbb.png)

MQTT 服务器可以在向发布者发送`PUBACK`数据包之前开始向适当的订阅者发布消息。因此，当发布者从 MQTT 服务器接收到`PUBACK`数据包时，并不意味着所有订阅者都已收到消息。理解这个`PUBACK`数据包的含义非常重要。

对于每个需要发布消息的订阅者，MQTT 服务器将发送一个`PUBLISH`数据包，订阅者必须通过向 MQTT 服务器发送一个`PUBACK`数据包来确认收到消息。下图显示了当使用 QoS 级别为 1 发布消息时，MQTT 服务器与订阅者之间的交互：

如果应用程序能够容忍重复，并且我们必须确保消息至少到达订阅者一次，QoS 级别 1 是一个很好的选择。如果没有办法处理重复，我们必须使用 QoS 级别 2。

# 使用仅一次传递（QoS 级别 2）

首先，我们将使用通配符订阅一个带有 QoS 级别 2 的主题过滤器，然后我们将向与 QoS 级别 2 匹配的主题发布一条消息。这样，我们将分析发布和订阅在 QoS 级别 2 下的工作方式。

我们将使用 Mosquitto 中包含的`mosquitto_sub`命令行实用程序生成一个简单的 MQTT 客户端，该客户端订阅带有 QoS 级别 1 的主题过滤器，并打印接收到的所有消息。在 macOS 或 Linux 中打开终端，或在 Windows 中打开命令提示符，转到安装 Mosquitto 的目录，并运行以下命令：

```py
mosquitto_sub -V mqttv311 -t sensors/quadcopter30/# -q 2 -d
```

上述命令将创建一个 MQTT 客户端，该客户端将与本地 MQTT 服务器建立连接，然后将客户端订阅到`-t`选项后指定的主题过滤器：`sensors/quadcopter30/#`。我们指定要使用`-q 2`选项订阅带有 QoS 级别 2 的主题过滤器。我们指定`-d`选项以启用调试消息，以便我们了解底层发生了什么以及与使用 QoS 级别 0 和 1 发布消息时的区别。

终端或命令提示符窗口将显示类似以下行的调试消息。请注意，生成的`ClientId`将与`Client mosqsub|8876-LAPTOP-5DO`后显示的不同。请注意，`QoS: 2`表示使用 QoS 级别 2 进行订阅：![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/d3cef734-2f01-424f-a46a-2d978f06f1b6.png)

```py
Client mosqsub|8876-LAPTOP-5DO sending CONNECT
Client mosqsub|8876-LAPTOP-5DO received CONNACK
Client mosqsub|8876-LAPTOP-5DO sending SUBSCRIBE (Mid: 1, Topic: sensors/quadcopter30/#, QoS: 2)
Client mosqsub|8876-LAPTOP-5DO received SUBACK
Subscribed (mid: 1): 2
```

我们将使用 Mosquitto 中包含的`mosquitto_pub`命令行实用程序生成一个简单的 MQTT 客户端，该客户端将向具有 QoS 级别 2 的主题发布消息，而不是我们之前发布消息时使用的 QoS 级别 0 和 1。在 macOS 或 Linux 中打开终端，或在 Windows 中打开命令提示符，转到安装 Mosquitto 的目录，并运行以下命令：

```py
mosquitto_pub -V mqttv311 -t sensors/quadcopter30/speed/rotor/1 -m  "123 f" -q 2 -d
```

上述命令将创建一个 MQTT 客户端，该客户端将与本地 MQTT 服务器建立连接，然后将客户端发布一条消息到`-t`选项后指定的主题：`sensors/quadcopter30/speed/rotor/1`。我们在`-m`选项后指定消息的有效载荷：`"123 f"`。我们指定要使用`-q 2`选项发布消息的 QoS 级别 2。我们指定`-d`选项以启用调试消息，以便我们了解底层发生了什么以及与使用 QoS 级别 0 和 1 发布消息时的区别。

终端或命令提示符窗口将显示类似以下行的调试消息。请注意，生成的`ClientId`将与`Client mosqpub|14652-LAPTOP-5D`后显示的不同。发布消息后，客户端将断开连接：

```py
Client mosqpub|14652-LAPTOP-5D sending CONNECT
Client mosqpub|14652-LAPTOP-5D received CONNACK
Client mosqpub|14652-LAPTOP-5D sending PUBLISH (d0, q2, r0, m1, 'sensors/quadcopter30/speed/rotor/1', ... (5 bytes))
Client mosqpub|14652-LAPTOP-5D received PUBREC (Mid: 1)
Client mosqpub|14652-LAPTOP-5D sending PUBREL (Mid: 1)
Client mosqpub|14652-LAPTOP-5D received PUBCOMP (Mid: 1)
Client mosqpub|14652-LAPTOP-5D sending DISCONNECT
```

上述行显示生成的 MQTT 客户端（即发布者）与 MQTT 服务器的数据包交换如下：

1.  发布者向 MQTT 服务器发送一个`PUBLISH`数据包

1.  发布者从 MQTT 服务器接收到一个`PUBREC`数据包

1.  发布者向 MQTT 服务器发送了`PUBREL`数据包

1.  发布者从 MQTT 服务器接收了`PUBCOMP`数据包

现在，回到您执行`mosquitto_sub`命令并订阅`sensors/quadcopter30/#`主题过滤器的终端或命令提示符窗口。您将看到类似以下行的行：

```py
Client mosqsub|8876-LAPTOP-5DO received PUBLISH (d0, q2, r0, m1, 'sensors/quadcopter30/speed/rotor/1', ... (5 bytes))
Client mosqsub|8876-LAPTOP-5DO sending PUBREC (Mid: 1)
Client mosqsub|8876-LAPTOP-5DO received PUBREL (Mid: 1)
123 f
Client mosqsub|8876-LAPTOP-5DO sending PUBCOMP (Mid: 1)
```

前面的行显示了生成的 MQTT 客户端，即订阅者，与 MQTT 服务器进行的数据包交换：

1.  订阅者从 MQTT 服务器接收了`PUBLISH`数据包

1.  订阅者向 MQTT 服务器发送了`PUBREC`数据包

1.  订阅者从 MQTT 服务器接收了`PUBREL`数据包

1.  订阅者在成功接收有效载荷为消息的消息后向 MQTT 服务器发送了`PUBCOMP`数据包

如果我们清除以`Client`前缀开头的调试消息，我们将只看到最后一行，它显示了我们订阅`sensors/quadcopter30/#`主题过滤器收到的消息的有效载荷：`123 f`。

已经建立连接的 MQTT 客户端，即发布者，发送了带有我们已经描述的标头的`PUBLISH`数据包到 MQTT 服务器，QoS 设置为 2，并包括一个对于此客户端将是唯一的`PacketId`数值。此时，发布者将把带有`PacketId`的`PUBLISH`数据包视为未被确认的`PUBLISH`数据包。

MQTT 服务器读取有效的`PUBLISH`数据包，并将用相同的`PacketId`值向发布者发送`PUBREC`数据包作为响应`PUBLISH`数据包。`PUBREC`数据包表示 MQTT 服务器接受了消息的所有权。一旦发布者收到`PUBREC`数据包，它会丢弃消息，并存储与消息相关的`PacketId`和`PUBREC`数据包。

出版商将`PUBREL`数据包发送到 MQTT 服务器，作为对收到的`PUBREC`数据包的响应。直到它收到与 MQTT 服务器相关的`PacketId`的`PUBCOMP`数据包，这个`PUBREL`数据包将被视为未被确认。最后，MQTT 服务器向发布者发送带有`PacketId`的`PUBCOMP`数据包，此时，发布者和 MQTT 服务器都确信消息已成功传递。

以下图表显示了发布者和 MQTT 服务器之间以 QoS 级别 2 发布消息的交互：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/ff3b4070-f57c-41b0-b046-625e2c94725b.png)

对于每个具有 QoS 级别 2 的订阅者，消息必须被发布到 MQTT 服务器，MQTT 服务器将发送一个`PUBLISH`数据包，并且我们已经分析过的与发布者和 MQTT 服务器之间的相同数据包交换将在 MQTT 服务器和订阅者之间发生。但是，在这种情况下，MQTT 服务器将作为发布者并启动流程。以下图表显示了在使用 QoS 级别 2 发布消息时 MQTT 服务器和订阅者之间的交互：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/0c238fff-d56d-4284-8ace-46b6a5931f12.png)如果应用程序无法容忍重复，并且我们必须确保消息只到达订阅者一次，那么 QoS 级别 2 是合适的选择。然而，魔法是有代价的：我们必须考虑到 QoS 级别 2 与其他 QoS 级别相比具有最高的开销。

# 了解不同服务质量级别的开销

以下图表总结了 MQTT 客户端和 MQTT 服务器之间交换的不同数据包，以发布具有 QoS 级别 0、1 和 2 的消息。通过这种方式，我们可以轻松识别随着 QoS 级别的增加而增加的开销：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/23bb3359-59a3-41e5-87ef-5521855c37f1.png)非常重要的是要考虑 QoS 级别 2 所需的额外开销，并且只在真正必要时使用它。

# 测试你的知识

让我们看看你是否能正确回答以下问题：

1.  MQTT 的 QoS 级别 0 表示：

1.  确切一次传递

1.  至多一次传递

1.  至少一次交付

1.  MQTT 的 QoS 级别 1 意味着：

1.  恰好一次交付

1.  至多一次交付

1.  至少一次交付

1.  MQTT 的 QoS 级别 2 意味着：

1.  恰好一次交付

1.  至多一次交付

1.  至少一次交付

1.  如果应用程序无法容忍重复，并且我们必须确保消息仅一次到达订阅者，那么适当的选择是：

1.  QoS 级别 0

1.  QoS 级别 1

1.  QoS 级别 2

1.  哪个 QoS 级别的开销最高：

1.  QoS 级别 0

1.  QoS 级别 1

1.  QoS 级别 2

正确答案包含在[附录]（d9cf708f-f027-4bfa-a2d2-9fd3653165d9.xhtml）中，*解决方案*。

# 摘要

在本章中，我们使用不同的工具与我们在[第一章]（d20ae00b-2bb7-4d81-b3eb-5c47215bce1f.xhtml）中安装的 Mosquitto MQTT 3.1.1 服务器进行交互，*安装 MQTT 3.1.1 Mosquitto 服务器*。我们使用了一个未经保护的 MQTT 服务器，以便轻松理解 MQTT 客户端与 MQTT 服务器之间的交互。

我们通过命令行和 GUI 工具订阅了主题。然后，我们以 QoS 级别 0 发布消息，并从主题中取消订阅。我们学习了与主题相关的最佳实践；以及单级和多级通配符。我们详细研究了 MQTT 支持的不同服务质量级别，以及在何时使用每个级别是适当的。我们分析了它们的优点和缺点。

现在我们了解了 MQTT 3.1.1 基础知识的工作原理，我们将学习如何保护 MQTT 服务器并遵循与安全相关的最佳实践，这些是我们将在[第三章]（89bdce8f-72bc-4fda-82a0-5cab33fa4bd8.xhtml）中讨论的主题，*保护 MQTT 3.1.1 Mosquitto 服务器*。


# 第三章：保护 MQTT 3.1.1 Mosquitto 服务器

在本章中，我们将保护 MQTT 3.1.1 Mosquitto 服务器。我们将进行所有必要的配置，以使用数字证书加密 MQTT 客户端和服务器之间发送的所有数据。我们将使用 TLS，并学习如何为每个 MQTT 客户端使用客户端证书。我们还将学习如何强制所需的 TLS 协议版本。我们将了解以下内容：

+   保护 Mosquitto 服务器的重要性

+   生成用于与 Mosquitto 使用 TLS 的私有证书颁发机构

+   为 Mosquitto 服务器创建证书

+   在 Mosquitto 中配置 TLS 传输安全性

+   使用命令行工具测试 MQTT TLS 配置

+   使用 GUI 工具测试 MQTT TLS 配置

+   为每个 MQTT 客户端创建证书

+   在 Mosquitto 中配置 TLS 客户端证书认证

+   使用命令行工具测试 MQTT TLS 客户端认证

+   使用 GUI 工具测试 MQTT TLS 配置

+   强制 TLS 协议版本为特定数字

# 理解保护 Mosquitto 服务器的重要性

物联网应用程序的安全性是一个非常重要的话题，值得有很多专门的书籍来讨论。每个解决方案都有自己的安全要求，当开发解决方案的每个组件时，考虑所有这些要求非常重要。

如果我们使用 MQTT 发布既不机密也不关键的值，我们唯一关心的可能是控制每个主题的最大订阅者数量，以确保消息始终可用。这样，我们可以防止 MQTT 服务器无法向大量订阅者传递消息。

然而，大多数情况下，我们不会在一个可以无限制地与整个世界共享数据并且不需要关心数据机密性和完整性以及数据可用性的解决方案上工作。想象一下，我们正在开发一个允许用户控制一个巨大的八旋翼无人机的解决方案。如果无人机飞错了方向，我们可能会对真实的人造成伤害。我们不能允许任何未知的发布者能够向允许我们控制八旋翼的主题发送消息。我们必须确保正确的人在控制八旋翼，并且作为消息的一部分发送的命令不能被中间的入侵者更改；也就是说，我们需要数据完整性。

不同级别的安全性都是有代价的；也就是说，总是会有额外的开销。因此，我们应该始终保持平衡，以避免可能使整个解决方案不可行和无法使用的开销。每当我们增加更多的安全性时，我们将需要额外的带宽，并且我们将在客户端和服务器中增加处理开销。我们必须考虑到，一些在现代智能手机上可以无问题运行的加密算法并不适合处理能力受限的物联网板。有时，安全要求可能会迫使我们使用特定的硬件，比如更强大的物联网板。在购买解决方案的所有硬件之前，我们绝对必须考虑安全性。

我们必须考虑的另一件重要事情是，许多安全级别需要维护任务，在某些情况下可能是不可行的，或者在其他情况下可能非常难以实现。例如，如果我们决定为每个将成为 MQTT 服务器客户端的设备使用证书，我们将不得不为每个设备生成和分发证书。我们必须访问设备的文件系统，将新文件复制到其中。如果我们必须使证书无效，就需要为受影响的设备提供新的证书。考虑一种情况，所有设备分布在难以访问的不同位置；我们必须有一种机制来远程访问设备，并能够为其提供新的证书。这项任务还需要安全性，因为我们不希望任何人都能访问设备的文件系统。因此，一旦我们开始分析所有安全要求和可能必要的维护任务，事情可能变得非常复杂。

每个 MQTT 服务器或代理实现都可以提供特定的安全功能。我们将使用 Mosquitto 开箱即用提供的一些功能。特定的安全要求可能会使我们决定使用特定的 MQTT 服务器或代理实现。

当我们使用 Mosquitto 时，我们可以在以下级别实施安全性：

+   **网络**：我们可以使用 VPN（虚拟专用网络）在互联网上扩展私有网络。

+   **传输**：MQTT 使用 TCP 作为传输协议，因此默认情况下通信不加密。**TLS**（传输层安全）通常被称为 TLS/SSL，因为**SSL**（安全套接字层）是其前身。我们可以使用 TLS 来保护和加密 MQTT 客户端和 MQTT 服务器之间的通信。使用 TLS 与 MQTT 有时被称为 MQTTS。TLS 允许我们同时提供隐私和数据完整性。我们可以使用 TLS 客户端证书来提供身份验证。

+   **应用**：在这个级别，我们可以利用 MQTT 中包含的功能来提供应用级别的身份验证和授权。我们可以使用`ClientId`（客户端标识符）来标识每个客户端，并将其与用户名和密码身份验证结合使用。我们可以在这个级别添加额外的安全机制。例如，我们可以加密消息有效载荷和/或添加完整性检查以确保数据完整性。但是，主题仍将是未加密的，因此 TLS 是确保一切都加密的唯一方法。我们可以使用插件来提供更复杂的身份验证和授权机制。我们可以授予或拒绝每个用户的权限，以控制他们可以订阅哪些主题以及他们可以向哪些主题发布消息。

大多数流行的 MQTT 实现都支持 TLS。但是，在选择适合您解决方案的 MQTT 服务器之前，请确保您检查其功能。

我们不会涵盖所有安全主题，因为这将需要一个或多个专门致力于这些主题的整本书。相反，我们将首先专注于传输级别安全中最常用的功能，然后再转向应用级别安全。VPN 的使用超出了本书的全局范围。但是，您必须根据您的特定需求考虑其使用。我们将在示例中使用 Mosquitto，但您可以为任何其他决定使用的 MQTT 服务器遵循许多类似的程序。我们将学到的一切对于任何其他提供与我们将与 Mosquitto 一起使用的相同安全功能支持的 MQTT 服务器都将是有用的。

# 使用 Mosquitto 生成私有证书颁发机构以使用 TLS

到目前为止，我们一直在使用其默认配置的 Mosquitto 服务器，它在端口`1883`上监听，并使用纯 TCP 作为传输协议。每个 MQTT 客户端和 MQTT 服务器之间发送的数据都没有加密。订阅者或发布者没有任何限制。如果我们打开防火墙端口并在路由器中重定向端口，或者为运行 MQTT 服务器的基于云的虚拟机配置端口安全性，任何具有 MQTT 服务器的 IP 地址或主机名的 MQTT 客户端都可以发布到任何主题并订阅任何主题。

在我们的示例中第二章中，*使用命令行和 GUI 工具学习 MQTT 的工作原理*，我们没有对允许连接到端口 1883 的传入连接进行任何更改，因此我们没有将我们的 Mosquitto 服务器开放到互联网。

我们希望在我们的开发环境中使用 TLS 与 MQTT 和 Mosquitto。这样，我们将确保我们可以信任 MQTT 服务器，因为我们相信它是它所说的那样，我们的数据将是私密的，因为它将被加密，它将具有完整性，因为它不会被篡改。如果您有*HTTP*协议的经验，您会意识到我们所做的转变与我们从使用*HTTP*转移到*HTTPS*时所做的转变是一样的。

网站从主要的证书颁发机构购买证书。如果我们想为服务器使用购买的证书，我们就不需要生成自己的证书。事实上，当我们有一个公开的 MQTT 服务器并且转移到生产环境时，这是最方便的选择。

在这种情况下，我们将使用免费的 OpenSSL 实用程序为服务器生成必要的证书，以便在我们的开发环境中启用 TLS 与 Mosquitto。非常重要的是要注意，我们不会生成一个生产就绪的配置，我们专注于一个安全的开发环境，它将模拟一个安全的生产环境。

OpenSSL 已经安装在 macOS 和大多数现代 Linux 发行版中。在 Windows 中，我们已经将 OpenSSL 安装为 Mosquitto 的先决条件之一。使用 OpenSSL 实用程序需要一本完整的书，因此我们将专注于使用最常见的选项生成我们需要的证书。如果您有特定的安全需求，请确保您探索使用 OpenSSL 实现您的目标所需的选项。

具体来说，我们将生成一个使用 X.509 **PKI**（公钥基础设施的缩写）标准的 X.509 数字证书。这个数字证书允许我们确认特定的公钥属于证书中包含的主体。有一个发行证书的身份，它的详细信息也包含在证书中。

数字证书仅在特定期限内有效，因此我们必须考虑数字证书某一天会过期，我们将不得不提供新的证书来替换过期的证书。根据我们使用的特定 X.509 版本，证书有特定的数据要求。根据版本和我们用来生成证书的选项，我们可能需要提供特定的数据。

我们将运行命令来生成不同的 X.509 数字证书，并提供将包含在证书中的所有必要细节。我们将在创建证书时了解证书将具有的所有数据。

我们将创建我们自己的私有证书颁发机构，也称为 CA。我们将创建一个根证书，然后我们将生成服务器密钥。

检查您安装 OpenSSL 的目录或文件夹。

在 macOS 上，OpenSSL 安装在`/usr/bin/openssl`中。但是，这是一个旧版本，需要在运行命令之前安装一个新版本。可以使用`homebrew`软件包管理器安装新版本，并且您将能够在另一个目录中运行新版本。例如，使用`homebrew`安装的版本 1.0.2n 的路径将在`/usr/local/Cellar/openssl/1.0.2n/bin/openssl`中。确保您不使用默认的旧版本。

在 Windows 中，我们安装为 Mosquitto 先决条件的 OpenSSL 版本，在[第二章](https://cdp.packtpub.com/hands_on_mqtt_programming_with_python/wp-admin/post.php?post=26&action=edit#post_25)中，*使用命令行和 GUI 工具学习 MQTT 工作*，默认的`C:\OpenSSL-Win32\bin`文件夹中有`openssl.exe`可执行文件。如果您使用 Windows，可以使用命令提示符或 Windows PowerShell。

在任何操作系统中，使用下一个以`openssl`开头的命令中适当的 OpenSSL 版本的完整路径。

创建一个名为`mosquitto_certificates`的新目录，并更改此目录的必要权限，以确保您只能访问其内容。

在 macOS 或 Linux 中打开终端，或者在 Windows 中打开命令提示符，并转到之前创建的`mosquitto_certificates`目录。运行以下命令来创建一个 2,048 位的根密钥，并将其保存在`ca.key`文件中：

```py
openssl genrsa -out ca.key 2048
```

以下行显示了上一个命令生成的示例输出：

```py
Generating RSA private key, 2048 bit long modulus
......+++
.............+++
e is 65537 (0x010001)
```

上一个命令将在`ca.key`文件中生成私有根密钥。确保您保持此文件私密，因为任何拥有此文件的人都将能够生成证书。也可以使用`openssl`的其他选项来保护此文件的密码。但是，如前所述，我们将遵循使用 TLS 的必要步骤，您可以探索与 OpenSSL 和证书相关的其他选项。

转到 macOS 或 Linux 中的终端，或者在 Windows 中的命令提示符中。运行以下命令以自签名根证书。下一个命令使用先前创建的 2,048 位私钥保存在`ca.key`文件中，并生成一个带有自签名 X.509 数字证书的`ca.crt`文件。该命令使自签名证书在`3650`天内有效。该值在`-days`选项之后指定：

```py
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt
```

在这种情况下，我们指定了`-sha256`选项来使用 SHA-256 哈希函数。如果我们想要增加安全性，我们可以在所有使用`-sha256`的情况下使用`-sha512`选项。这样，我们将使用 SHA-512 哈希函数。然而，我们必须考虑到 SHA-512 可能不适合某些功耗受限的物联网设备。

在输入上述命令后，OpenSSL 会要求输入将被合并到证书中的信息。您必须输入信息并按*Enter*。如果您不想输入特定信息，只需输入一个点(`.`)并按*Enter*。可以将所有值作为`openssl`命令的参数传递，但这样做会使我们难以理解我们正在做什么。事实上，也可以使用更少的调用`openssl`命令来执行前面的任务。但是，我们运行了更多的步骤来理解我们正在做什么。

以下行显示了示例输出和带有示例答案的问题。请记住，我们正在生成我们的私有证书颁发机构：

```py
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:NEW YORK CITY
Locality Name (eg, city) []:NEW YORK
Organization Name (eg, company) [Internet Widgits Pty Ltd]:MOSQUITTO CERTIFICATE AUTHORITY
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:MOSQUITTO CERTIFICATE AUTHORITY
Email Address []:mosquittoca@example.com
```

运行以下命令以显示最近生成的证书颁发机构证书文件的数据和详细信息：

```py
Certificate:
 Data:
 Version: 3 (0x2)
 Serial Number:
 96:f6:f6:36:ad:63:b2:1f
 Signature Algorithm: sha256WithRSAEncryption
 Issuer: C = US, ST = NEW YORK, L = NEW YORK, O = MOSQUITTO 
        CERTIFICATE AUTHORITY, CN = MOSQUITTO CERTIFICATE AUTHORITY, 
        emailAddress = mosquittoca@example.com
 Validity
 Not Before: Mar 22 15:43:23 2018 GMT
 Not After : Mar 19 15:43:23 2028 GMT
 Subject: C = US, ST = NEW YORK, L = NEW YORK, O = MOSQUITTO 
            CERTIFICATE AUTHORITY, CN = MOSQUITTO CERTIFICATE 
            AUTHORITY, emailAddress = mosquittoca@example.com
 Subject Public Key Info:
 Public Key Algorithm: rsaEncryption
 Public-Key: (2048 bit)
 Modulus:
 00:c0:45:aa:43:d4:76:e7:dc:58:9b:19:85:5d:35:
 54:2f:58:61:72:6a:42:81:f9:64:1b:51:18:e1:95:
 ba:50:99:56:c5:9a:c2:fe:07:8e:26:12:47:a6:be:
 8b:ce:23:bf:4e:5a:ea:ab:2e:51:99:0f:23:ea:38:
 68:f3:80:16:5d:5f:51:cf:ce:ee:c9:e9:3a:34:ac:
 ee:24:a6:50:31:59:c5:db:75:b3:33:0e:96:31:23:
 1b:9c:6f:2f:96:1f:6d:cc:5c:4e:20:10:9e:f2:4e:
 a9:f6:31:83:54:11:b6:af:86:0e:e0:af:69:a5:b3:
 f2:5a:b5:da:b6:64:73:87:86:bb:e0:be:b3:10:9f:
 ef:91:8f:e5:68:8c:ab:38:75:8d:e1:33:bc:fb:00:
 d8:d6:d2:d3:6e:e3:a0:3f:08:b6:9e:d6:da:94:ad:
 61:74:90:6c:71:98:88:e8:e1:2b:2d:b1:18:bb:6d:
 b8:65:43:cf:ac:79:ab:a7:a4:3b:65:a8:8a:6f:be:
 c1:66:71:d6:9c:2d:d5:0e:81:13:69:23:65:fa:d3:
 cb:79:e5:75:ea:a2:22:72:c7:e4:f7:5c:be:e7:64:
 9b:54:17:dd:ca:43:7f:93:be:b6:39:20:e7:f1:21:
 0f:a7:e6:24:99:57:9b:02:1b:6d:e4:e5:ee:ad:76:
 2f:69
 Exponent: 65537 (0x10001)
 X509v3 extensions:
 X509v3 Subject Key Identifier:
 F7:C7:9E:9D:D9:F2:9D:38:2F:7C:A6:8F:C5:07:56:57:48:7D:07:35
 X509v3 Authority Key Identifier: keyid:F7:C7:9E:9D:D9:F2:9D:38:2F:7C:A6:8F:C5:07:56:57:48:7D:07:35
 X509v3 Basic Constraints: critical
 CA:TRUE
 Signature Algorithm: sha256WithRSAEncryption
 a2:64:5d:7b:f4:85:81:f7:d0:30:8b:8d:7c:83:83:63:2c:4e:
 a8:56:fb:fc:f0:4f:d4:d8:9c:cd:ac:c7:e9:bc:4b:b5:87:9e:
 02:0b:9f:e0:4b:a3:da:3f:84:b4:1c:e3:42:d4:9f:4e:c0:29:
 f7:ae:18:d3:2d:bf:93:e2:2b:5c:d9:9a:82:53:d8:6a:fb:c8:
 47:9f:02:d4:05:11:e9:8f:2a:54:09:c4:a4:f1:00:eb:35:1d:
 6b:e9:55:3b:4b:a6:27:d0:52:cf:86:c1:03:32:ce:22:41:55:
 32:1e:93:4f:6b:a5:b5:19:9e:8c:a7:de:91:2b:2c:c6:95:a9:
 b6:44:18:e7:40:23:38:87:5d:89:b6:25:d7:32:60:28:0b:41:
 5b:6e:46:20:bf:36:9d:ba:26:6d:63:71:0f:fd:c3:e3:0d:6b:
 b6:84:34:06:ea:67:7c:4e:2e:df:fe:b6:ec:48:f5:7b:b5:06:
 c5:ad:6f:3e:0c:25:2b:a3:9d:49:f7:d4:b7:69:9e:3e:ca:f8:
 65:f2:77:ae:50:63:2b:48:e0:72:93:a7:60:99:b7:40:52:ab:
 6f:00:78:89:ad:92:82:93:e3:30:ab:ac:24:e7:82:7f:51:c7:
 2d:e7:e1:2d:3f:4d:c1:5c:27:15:d9:bc:81:7b:00:a0:75:07:
 99:ee:78:70
```

在运行上述命令之后，我们将在`mqtt_certificates`目录中有以下两个文件：

+   `ca.key`：证书颁发机构密钥

+   `ca.crt`：证书颁发机构证书文件

证书颁发机构证书文件采用**PEM**（即**隐私增强邮件**）格式。我们必须记住这种格式，因为一些 MQTT 工具将要求我们指定证书是否采用 PEM 格式。在此选项中输入错误的值将不允许 MQTT 客户端与使用 PEM 格式证书的 MQTT 服务器建立连接。

# 为 Mosquitto 服务器创建证书

现在我们有了一个私有证书颁发机构，我们可以为 Mosquitto 服务器创建证书，也就是为将运行 MQTT 服务器的计算机创建证书。

首先，我们必须生成一个新的私钥，该私钥将与我们为自己的私有证书颁发机构生成的私钥不同。

转到 macOS 或 Linux 中的终端，或者 Windows 中的命令提示符。运行以下命令以创建一个 2048 位密钥并将其保存在`server.key`文件中：

```py
openssl genrsa -out server.key 2048
```

以下行显示了由上一个命令生成的示例输出：

```py
Generating RSA private key, 2048 bit long modulus
..................................................................................................+++
..............................................................................................................................+++
e is 65537 (0x010001)
```

上一个命令将在`server.key`文件中生成私钥。返回到 macOS 或 Linux 中的终端，或者 Windows 中的命令提示符。运行以下命令以生成证书签名请求。下一个命令使用先前创建的 2048 位私钥保存在`server.key`文件中，并生成`server.csr`文件：

```py
openssl req -new -key server.key -out server.csr
```

输入上述命令后，OpenSSL 会要求输入将纳入证书中的信息。您必须输入信息并按*Enter*。如果您不想输入特定信息，只需输入一个点（`.`）并按*Enter*。在这种情况下，最重要的值是通用名称。在此字段中，输入运行 Mosquitto 服务器的计算机的 IPv4 或 IPv6 地址，而不是下一行中显示的`192.168.1.1`值。以下行显示了示例输出和示例答案的问题。不要忘记输入通用名称的适当值：

```py
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:FLORIDA
Locality Name (eg, city) []:ORLANDO
Organization Name (eg, company) [Internet Widgits Pty Ltd]:MQTT 3.1.1 SERVER
Organizational Unit Name (eg, section) []:MQTT
Common Name (e.g. server FQDN or YOUR name) []:192.168.1.1
Email Address []:mosquittoserver@example.com

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:Mosquitto MQTT Server
```

转到 macOS 或 Linux 中的终端，或者 Windows 中的命令提示符。运行以下命令以签署先前创建的证书签名请求，即`server.csr`文件。下一个命令还使用了我们之前生成的自签名 X.509 数字证书的证书颁发机构和私钥：`ca.crt`和`ca.key`文件。

该命令生成了一个带有 Mosquitto 服务器签名的 X.509 数字证书的`server.crt`文件。该命令使签名证书有效期为 3650 天。该值在`-days`选项之后指定：

```py
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650 -sha256
```

与我们为证书颁发机构创建自签名 X.509 数字证书时一样，我们还指定了`-sha256`选项，以便为 Mosquitto 服务器证书使用 SHA-256 哈希函数。如果您想要使用 SHA-512 哈希函数以增加安全性，可以使用`-sha512`选项代替`-sha256`。

以下行显示了由上一个命令生成的示例输出。在`subject`之后显示的值将在您的配置中有所不同，因为您在生成证书签名请求时输入了自己的值，这些值保存在`server.csr`文件中：

```py
Signature ok
subject=C = US, ST = FLORIDA, L = ORLANDO, O = MQTT 3.1.1 SERVER, OU = MQTT, CN = 192.168.1.1, emailAddress = mosquittoserver@example.com
Getting CA Private Key
```

运行以下命令以显示生成的服务器证书文件的数据和详细信息：

```py
openssl x509 -in server.crt -noout -text
```

以下行显示了显示有关签名算法、颁发者、有效性、主题和签名算法的详细信息的示例输出：

```py
Certificate:
 Data:
 Version: 1 (0x0)
 Serial Number:
 a1:fa:a7:26:53:da:24:0b
 Signature Algorithm: sha256WithRSAEncryption
 Issuer: C = US, ST = NEW YORK, L = NEW YORK, O = MOSQUITTO     
        CERTIFICATE AUTHORITY, CN = MOSQUITTO CERTIFICATE AUTHORITY, 
        emailAddress = mosquittoca@example.com
 Validity
 Not Before: Mar 22 18:20:01 2018 GMT
 Not After : Mar 19 18:20:01 2028 GMT
 Subject: C = US, ST = FLORIDA, L = ORLANDO, O = MQTT 3.1.1 
        SERVER, OU = MQTT, CN = 192.168.1.1, emailAddress = 
        mosquittoserver@example.com
 Subject Public Key Info:
 Public Key Algorithm: rsaEncryption
 Public-Key: (2048 bit)
 Modulus:
 00:f5:8b:3e:76:0a:ab:65:d2:ee:3e:47:6e:dc:be:
 74:7e:96:5c:93:25:45:54:a4:97:bc:4d:34:3b:ed:
 33:89:39:f4:df:8b:cd:9f:63:fa:4d:d4:01:c8:a5:
 0b:4f:c7:0d:35:a0:9a:20:4f:66:be:0e:4e:f7:1a:
 bc:4a:86:a7:1f:69:30:36:01:2f:93:e6:ff:8f:ca:
 1f:d0:58:fa:37:e0:90:5f:f8:06:7c:2c:1c:c7:21:
 c8:b4:12:d4:b7:b1:4e:5e:6d:41:68:f3:dd:03:33:
 f5:d5:e3:de:37:08:c4:5f:8c:db:21:a2:d7:20:12:
 f2:a4:81:20:3d:e4:d7:af:81:32:82:31:a2:2b:fd:
 02:c2:ee:a0:fa:53:1b:ca:2d:43:b3:7e:b7:b8:12:
 9c:3e:26:66:cd:90:34:ba:aa:6b:ad:e4:eb:0d:15:
 cf:0b:ce:f6:b1:07:1f:7c:33:05:11:4b:57:6c:48:
 0d:f8:e5:f3:d3:f0:88:92:53:ec:3e:04:d7:fc:81:
 75:5e:ef:01:56:f1:66:fe:a4:34:9b:13:8a:b6:5d:
 cc:8f:72:11:0e:9c:c9:65:71:e3:dd:0e:5a:b7:9d:
 8f:18:3e:09:62:52:5f:fa:a5:96:4d:2b:35:23:26:
 ca:74:5d:f9:04:64:f1:f8:f6:f6:7a:d7:31:4c:b7:
 e8:53
 Exponent: 65537 (0x10001)
 Signature Algorithm: sha256WithRSAEncryption
 9c:2f:b5:f9:fa:06:9f:a3:1e:a3:38:94:a7:aa:4c:11:e9:30:
 2e:4b:cf:16:a3:c6:46:ad:e5:3b:d9:43:f0:41:37:62:93:94:
 72:56:1a:dd:27:50:f7:89:2f:4b:56:55:59:d6:da:2e:8f:0a:
 d8:1e:dd:41:0e:1c:36:1b:eb:8d:32:2c:24:ef:58:93:18:e1:
 fc:ce:71:f6:b2:ed:84:5e:06:52:b8:f1:87:f3:13:ca:b9:41:
 3f:a2:1d:a0:52:5d:52:37:6c:2b:8c:28:ab:7f:7d:ed:fc:07:
 9f:60:8b:ad:3d:48:17:95:fe:20:b8:96:87:44:9a:32:b8:9c:
 a8:d7:3c:cf:98:ba:a4:5c:c9:6e:0c:10:ee:45:3a:23:4a:e8:
 34:28:63:c4:8e:6e:1b:d9:a0:1b:e5:cc:33:69:ae:6f:e1:bb:
 99:df:04:fa:c9:bd:8c:c5:c7:e9:a9:fd:f2:dc:2c:b3:a9:7c:
 8a:ef:bf:66:f6:09:01:9a:0e:8f:27:a4:a1:45:f7:90:d2:bb:
 6d:4f:12:46:56:29:85:cd:c8:d6:d7:d3:60:e4:d1:27:a3:88:
 52:41:6a:7d:b2:06:8e:10:ec:ae:b5:7e:58:3e:ae:33:7c:f7:
 3a:21:a6:ae:61:5f:4d:c8:44:86:48:3d:c4:32:f2:db:05:e9:
 c9:f1:0c:be
```

运行上述命令后，我们将在`mqtt_certificates`目录中有以下三个文件：

+   `server.key`：服务器密钥

+   `server.csr`：服务器证书签名请求

+   `server.crt`：服务器证书文件

服务器证书文件采用 PEM 格式，证书颁发机构证书文件也是如此。

# 在 Mosquitto 中配置 TLS 传输安全

现在，我们将配置 Mosquitto 使用 TLS 传输安全，并与不同客户端进行加密通信。请注意，我们尚未为客户端生成证书，因此我们不会使用客户端证书进行身份验证。这样，任何拥有`ca.crt`文件的客户端都将能够与 Mosquitto 服务器建立通信。

转到 Mosquitto 安装目录，并创建一个名为`certificates`的新子目录。在 Windows 中，您需要管理员权限才能访问默认安装文件夹。

从`mqtt_certificates`目录中复制以下文件（我们在其中保存了证书颁发机构证书和服务器证书）到我们最近在 Mosquitto 安装目录中创建的`certificates`子目录：

+   `ca.crt`

+   `server.crt`

+   `server.key`

如果您在 macOS 或 Linux 的终端窗口中运行 Mosquitto 服务器，请按下*Ctrl* + *C*来停止它。在 Windows 中，使用*Services*应用程序停止适当的服务。如果您在 Linux 中运行 Mosquitto 服务器，请运行以下命令停止服务：

```py
sudo service mosquitto stop
```

转到 Mosquitto 安装目录，并使用您喜欢的文本编辑器打开`mosquitto.conf`配置文件。默认情况下，此文件的所有行都被注释掉，即以井号(`#`)开头。每个设置的默认值已指示，并包括适当的注释。这样，我们很容易知道所有默认值。设置按不同部分组织。

在对其进行更改之前，最好先备份现有的`mosquitto.conf`配置文件。每当我们对`mosquitto.conf`进行更改时，如果出现问题，能够轻松回滚到先前的配置是一个好主意。

在 macOS 或 Linux 中，在配置文件的末尾添加以下行，并确保将`/usr/local/etc/mosquitto/certificates`替换为我们在`Mosquitto`安装文件夹中创建的`certificates`目录的完整路径：

```py
# MQTT over TLS
listener 8883
cafile /usr/local/etc/mosquitto/certificates/ca.crt
certfile /usr/local/etc/mosquitto/certificates/server.crt
keyfile /usr/local/etc/mosquitto/certificates/server.key
```

在 Windows 中，在配置文件的末尾添加以下行，并确保将`C:\Program Files (x86)\mosquitto\certificates`替换为我们在`Mosquitto`安装文件夹中创建的`certificates`目录的完整路径。请注意，当您运行文本编辑器打开文件时，您将需要管理员权限；也就是说，您将需要以管理员身份运行文本编辑器：

```py
# MQTT over TLS
listener 8883
cafile C:\Program Files (x86)\mosquitto\certificates\ca.crt
certfile C:\Program Files (x86)\mosquitto\certificates\server.crt
keyfile C:\Program Files (x86)\mosquitto\certificates\server.key
```

我们为监听器选项指定了`8883`值，以使 Mosquitto 在 TCP 端口号`8883`上监听传入的网络连接。此端口是具有 TLS 的 MQTT 的默认端口号。

`cafile`选项指定提供 PEM 编码证书颁发机构证书文件`ca.crt`的完整路径。

`certfile`选项指定提供 PEM 编码服务器证书`server.crt`的完整路径。

最后，`keyfile`选项指定提供 PEM 编码服务器密钥文件`server.key`的完整路径。

保存更改到`mosquitto.conf`配置文件，并使用我们在上一章中学到的相同机制再次启动 Mosquitto，以在端口`8883`而不是`1883`上监听 Mosquitto 服务器。

# 使用命令行工具测试 MQTT TLS 配置

我们将使用 Mosquitto 中包含的`mosquitto_sub`命令行实用程序尝试生成一个简单的 MQTT 客户端，该客户端订阅一个主题并打印其接收到的所有消息。我们将使用默认配置，尝试使用默认的`1883`端口与 Mosquitto 服务器建立通信，而不指定证书颁发机构证书。在 macOS 或 Linux 中打开终端，或在 Windows 中打开命令提示符，转到 Mosquitto 安装的目录，并运行以下命令：

```py
mosquitto_sub -V mqttv311 -t sensors/octocopter01/altitude -d
```

`mosquitto_sub`实用程序将显示以下错误。Mosquitto 服务器不再接受端口`1883`上的任何连接。请注意，错误消息可能因平台而异：

```py
Error: No connection could be made because the target machine actively refused it.
```

使用`-p`选项运行以下命令，后跟我们要使用的端口号：`8883`。这样，我们将尝试连接到端口`8883`，而不是默认端口`1883`：

```py
mosquitto_sub -V mqttv311 -p 8883 -t sensors/octocopter01/altitude -d
```

`mosquitto_sub`实用程序将显示调试消息，指示它正在向 MQTT 服务器发送`CONNECT`数据包。但是，连接将永远不会建立，因为潜在的 MQTT 客户端未提供所需的证书颁发机构。按下*Ctrl* + *C*停止实用程序尝试连接。以下行显示了上一个命令生成的示例输出：

```py
Client mosqsub|14064-LAPTOP-5D sending CONNECT
Client mosqsub|14064-LAPTOP-5D sending CONNECT
Client mosqsub|14064-LAPTOP-5D sending CONNECT
Client mosqsub|14064-LAPTOP-5D sending CONNECT
Client mosqsub|14064-LAPTOP-5D sending CONNECT
Client mosqsub|14064-LAPTOP-5D sending CONNECT
```

以下命令使用`-h`选项，后跟 MQTT 服务器主机。在这种情况下，我们指定运行 Mosquitto MQTT 服务器的计算机的 IPv4 地址：`192.168.1.1`。请注意，此值必须与我们在生成`server.csr`文件时指定为通用名称字段中的 IPv4 或 IPv6 地址相匹配，即服务器证书签名请求。如果您在通用名称字段中使用主机名作为值，而不是 IPv4 或 IPv6 地址，则必须使用相同的主机名。如果`-h`选项指定的值与通用名称字段中指示的值不匹配，则 Mosquitto 服务器将拒绝客户端。因此，请确保您在下一行中用适当的值替换`192.168.1.1`。此外，该命令在`--cafile`选项之后指定证书颁发机构证书文件，并指示我们要使用端口`8883`。您只需将`ca.crt`替换为您在`mqtt_certificates`目录中创建的`ca.crt`文件的完整路径。例如，在 Windows 中可能是`C:\mqtt_certificates\ca.crt`，在 macOS 或 Linux 中可能是`/Users/gaston/mqtt_certificates/ca.crt`。`mosquitto_sub`实用程序将创建一个与 Mosquitto 建立加密连接的 MQTT 订阅者：

```py
mosquitto_sub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt -t sensors/octocopter01/altitude -d
```

如果您为`-h`选项指定的值与您在生成`server.csr`文件时指定的通用名称字段中的值不匹配，则将看到以下错误消息作为上一个命令的结果：

```py
Client mosqsub|14064-LAPTOP-5D sending CONNECT
Error: A TLS error occurred.
```

如果命令生成了上一个错误消息，请确保查看生成`server.csr`文件的先前步骤。确保不要将`localhost`用作`-h`选项的值。

使用类似的语法，我们将使用 Mosquitto 中包含的`mosquitto_pub`命令行实用程序生成一个简单的 MQTT 客户端，该客户端将发布消息到一个主题，并使用加密连接。在 macOS 或 Linux 中打开终端，或在 Windows 中打开命令提示符，转到安装 Mosquitto 的目录，并运行以下命令。

请记住在下一行中用适当的值替换`192.168.1.1`。此外，请用`mqtt_certificates`目录中创建的`ca.crt`文件的完整路径替换`ca.crt`：

```py
mosquitto_pub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt -t sensors/octocopter01/altitude -m "123 f" -d
```

在命令发布消息后，您将在使用`mosquitto_sub`命令订阅`sensors/octocopter01/altitude`主题的窗口中看到该消息。

# 使用 GUI 工具测试 MQTT TLS 配置

现在，我们将使用 MQTT.fx GUI 实用程序生成另一个 MQTT 客户端，该客户端使用加密连接将消息发布到相同的主题：`sensors/octocopter01/altitude`。我们必须更改连接选项以启用 TLS 并指定证书颁发机构证书文件。请按照以下步骤操作：

1.  启动 MQTT.fx，在左上角的下拉菜单中选择本地 mosquitto，并单击此下拉菜单右侧和连接按钮左侧的配置图标。MQTT.fx 将显示带有不同连接配置文件选项的编辑连接配置文件对话框，名为本地 mosquitto。

1.  转到经纪人地址文本框，并输入我们在生成`server.csr`文件时指定为通用名称字段值的 IPv4 或 IPv6 地址，即服务器证书签名请求。如果您在通用名称字段中使用的是主机名而不是 IPv4 或 IPv6 地址，您将需要使用相同的主机名。如果经纪人地址中指定的值与通用名称字段中指示的值不匹配，Mosquitto 服务器将拒绝客户端。

1.  转到经纪人端口文本框，并输入 8883。

1.  单击 SSL/TLS 按钮。

1.  激活启用 SSL/TLS 复选框。

1.  激活 CA 证书文件单选按钮。

1.  在 CA 证书文件文本框中输入或选择您在 CA 证书文件夹中创建的`ca.crt`文件的完整路径，然后单击确定。以下屏幕截图显示了所选选项的对话框：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/83c21b8b-589b-446b-8a24-067dc32e5e6e.png)

1.  单击连接按钮。MQTT.fx 将与本地 Mosquitto 服务器建立加密连接。请注意，连接按钮已禁用，断开按钮已启用，因为客户端已连接到 Mosquitto 服务器。

1.  点击订阅并在订阅按钮左侧的下拉菜单中输入`sensors/octocopter01/altitude`。然后，点击订阅按钮。MQTT.fx 将在左侧显示一个新面板，显示我们已订阅的主题。

1.  单击发布，并在发布按钮左侧的下拉菜单中输入`sensors/octocopter01/altitude`。

1.  在发布按钮下方的文本框中输入以下文本：`250 f`。

1.  然后，单击发布按钮。MQTT.fx 将发布输入的文本到指定的主题。

1.  点击订阅，您将看到已发布的消息。

通过我们对 Mosquitto 服务器所做的配置更改，任何具有证书颁发机构证书文件（即我们生成的`ca.crt`文件）的客户端都将能够与 Mosquitto 建立连接，订阅和发布主题。 MQTT 客户端和 MQTT 服务器之间发送的数据是加密的。在此配置中，我们不需要 MQTT 客户端提供证书进行身份验证。但是，请不要忘记我们正在为开发环境进行配置。我们不应该在生产 Mosquitto 服务器上使用自签名证书。

还有另一个非常受欢迎的 GUI 实用程序，我们可以使用它来生成可以订阅主题和发布主题的 MQTT 客户端：MQTT-spy。该实用程序是开源的，可以在安装了 Java 8 或更高版本的任何计算机上运行。您可以在此处找到有关 MQTT-spy 的更多信息：[`github.com/eclipse/paho.mqtt-spy`](https://github.com/eclipse/paho.mqtt-spy)。使用证书颁发机构证书文件与 MQTT 服务器建立连接的选项与我们为 MQTT.fx 分析的选项类似。但是，如果您还想使用此实用程序，最好详细分析这些选项。

现在，我们将使用 MQTT-spy GUI 实用程序生成另一个使用加密连接发布消息到相同主题`sensors/octocopter01/altitude`的 MQTT 客户端。按照以下步骤：

1.  启动 MQTT-spy。

1.  选择连接 | 新连接。连接列表对话框将出现。

1.  单击连接选项卡，并在协议版本下拉菜单中选择 MQTT 3.1.1。我们希望使用 MQTT 版本 3.1.1。

1.  转到服务器 URI(s)文本框，并输入我们在生成`server.csr`文件时指定为通用名称字段值的 IPv4 或 IPv6 地址，即服务器证书签名请求。如果您在通用名称字段中使用的是主机名而不是 IPv4 或 IPv6 地址，您将需要使用相同的主机名。如果经纪人地址中指定的值与通用名称字段中指示的值不匹配，Mosquitto 服务器将拒绝由 MQTT-spy 实用程序生成的客户端。

1.  点击安全选项卡，在用户认证选项卡下方的 TLS 选项卡中。

1.  在 TLS/SSL 模式下拉菜单中选择 CA 证书。

1.  在协议下拉菜单中选择 TLSv1.2。

1.  输入或选择在`mqtt_certificates`文件夹中创建的`ca.crt`文件的完整路径，然后点击打开连接。以下屏幕截图显示了具有所选选项的对话框：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/d728a805-2bdb-4628-9282-39da7dab785e.png)

1.  MQTT-spy 将关闭对话框，并显示一个具有绿色背景的新选项卡，连接名称已在连接列表对话框的左侧突出显示并被选中。确保点击新连接的选项卡。

1.  在主题下拉菜单中输入`sensors/octocopter01/altitude`。

1.  在数据文本框中输入以下文本：`178 f`。以下屏幕截图显示了新连接的选项卡以及在不同控件中输入的数据：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/6bef46e1-b6bf-40f3-8807-db4264417e38.png)

1.  点击发布按钮。MQTT-spy 将向指定主题发布输入的文本，您将能够在 MQTT.fx 订阅者和`mosquitto-sub`订阅者中看到消息。

# 为每个 MQTT 客户端创建证书

现在，我们希望要求每个 MQTT 客户端提供有效的证书以建立与 MQTT 服务器的连接。这样，只有拥有有效证书的客户端才能发布或订阅主题。我们将使用先前创建的私有证书颁发机构来为认证创建客户端证书。

我们将为我们的本地计算机生成一个样本证书，该证书将充当客户端。我们可以按照相同的步骤为我们想要连接到 Mosquitto 服务器的其他设备生成额外的证书。我们只需要为文件使用不同的名称，并在相应的选项中使用不同的设备名称。

我们必须使用与生成服务器证书相同的证书颁发机构证书来生成客户端证书。如前所述，对于生产环境，我们不应该使用自签名证书。这个过程对于开发环境是有用的。

首先，我们必须生成一个新的私钥，该私钥将与我们为自己的私有证书颁发机构和服务器证书生成的私钥不同。

转到 macOS 或 Linux 中的终端，或者 Windows 中的命令提示符。运行以下命令以创建一个 2,048 位的密钥，并将其保存在`board001.key`文件中。要为其他设备重复此过程，请将`board001`替换为标识将使用该证书的设备的任何其他名称。在所有使用`board001`的不同文件名和值的以下命令中都要这样做：

```py
openssl genrsa -out board001.key 2048
```

以下行显示了上一个命令生成的示例输出：

```py
Generating RSA private key, 2048 bit long modulus
..........................................................................................+++
.....................................+++
e is 65537 (0x10001)
```

上一个命令将在`board001.key`文件中生成私钥。

返回到 macOS 或 Linux 中的终端，或者 Windows 中的命令提示符。运行以下命令以生成证书签名请求，也称为 CSR。下一个命令使用先前创建的 2,048 位私钥，保存在`board001.key`文件中，并生成一个`board001.csr`文件：

```py
openssl req -new -key board001.key -out board001.csr
```

在输入上一个命令后，OpenSSL 会要求输入将被合并到证书中的信息。您必须输入信息并按*Enter*。如果您不想输入特定信息，只需输入一个点（.）并按*Enter*。在这种情况下，最重要的值是通用名称。在此字段中输入设备名称：

```py
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:US 
State or Province Name (full name) [Some-State]:CALIFORNIA
Locality Name (eg, city) []:SANTA MONICA
Organization Name (eg, company) [Internet Widgits Pty Ltd]:MQTT BOARD 001
Organizational Unit Name (eg, section) []:MQTT BOARD 001
Common Name (e.g. server FQDN or YOUR name) []:MQTT BOARD 001
Email Address []:mttboard001@example.com

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:.
An optional company name []:.
```

转到 macOS 或 Linux 中的终端，或者转到 Windows 中的命令提示符。运行以下命令以签署先前创建的证书签名请求，即`board001.csr`文件。下一个命令还使用我们之前生成的自签名 X.509 数字证书用于证书颁发机构和其私钥：`ca.crt`和`ca.key`文件。该命令生成一个带有 MQTT 客户端签名的 X.509 数字证书的`board001.crt`文件。该命令使签名证书在 3,650 天内有效，这是在`-days`选项之后指定的值。`-addTrust clientAuth`选项表示我们要使用证书来验证客户端：

```py
openssl x509 -req -in board001.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out board001.crt -days 3650 -sha256 -addtrust clientAuth
```

以下行显示了先前命令生成的示例输出。在您的配置中，主题后显示的值将不同，因为在生成保存在`board001.csr`文件中的证书签名请求时，您输入了自己的值：

```py
Signature ok
subject=/C=US/ST=CALIFORNIA/L=SANTA MONICA/O=MQTT BOARD 001/OU=MQTT BOARD 001/CN=MQTT BOARD 001/emailAddress=mttboard001@example.com
Getting CA Private Key
```

运行以下命令以显示生成的服务器证书文件的数据和详细信息：

```py
openssl x509 -in board001.crt -noout -text
```

以下行显示了显示有关签名算法、发行者、有效性和主题的详细信息的示例输出：

```py
Certificate:
 Data:
 Version: 1 (0x0)
 Serial Number:
 dd:34:7a:3c:a6:cd:c1:94
 Signature Algorithm: sha256WithRSAEncryption
 Issuer: C=US, ST=CALIFORNIA, L=SAN FRANCISCO, O=CERTIFICATE 
 AUTHORITY, CN=CERTIFICATE 
 AUTHORITY/emailAddress=CERTIFICATE@EXAMPLE.COM
 Validity
 Not Before: Mar 23 22:10:05 2018 GMT
 Not After : Mar 20 22:10:05 2028 GMT
 Subject: C=US, ST=CALIFORNIA, L=SANTA MONICA, O=MQTT BOARD 001, 
 OU=MQTT BOARD 001, CN=MQTT BOARD 
 001/emailAddress=mttboard001@example.com
 Subject Public Key Info:
 Public Key Algorithm: rsaEncryption
 RSA Public Key: (2048 bit)
 Modulus (2048 bit):
 00:d0:9c:dd:9f:3e:db:3f:15:9c:23:40:12:5f:4e:
 56:2a:30:34:df:88:51:d7:ca:61:bb:99:b5:ab:b4:
 a6:61:e9:f1:ed:2e:c3:61:7a:f2:0b:70:5b:24:7a:
 12:3f:cb:5d:76:f7:10:b2:08:24:94:31:0d:80:35:
 78:2c:19:70:8b:c0:fe:c1:cb:b2:13:5e:9a:d3:68:
 5d:4d:78:47:5a:a3:d5:63:cd:3c:2f:8b:b1:48:4d:
 12:11:0b:02:17:f3:4c:56:91:67:9f:98:3d:90:1f:
 47:09:c0:1b:3a:04:09:2f:b9:fe:f1:e9:df:38:35:
 f8:12:ee:59:96:b1:ca:57:90:53:19:2b:4f:d3:45:
 9e:f2:6a:09:95:46:f9:68:6b:c6:4e:89:33:78:4f:
 0f:5b:2f:d3:00:d0:12:d7:ca:92:df:f4:86:6e:22:
 9d:63:a2:f7:de:09:f4:8c:02:ad:03:9c:13:7b:b4:
 9e:03:d6:99:f4:c0:3f:3f:c3:31:52:12:f1:66:cd:
 22:5d:48:fb:7f:ca:ac:84:cf:24:c5:c4:85:af:61:
 de:59:84:a8:e0:fd:ce:44:5d:f2:85:c0:5d:f2:c5:
 ec:71:04:2c:83:94:cd:71:a1:14:1b:f7:e4:1b:b4:
 2f:12:70:cb:b7:17:9e:db:c9:23:d1:56:bd:f5:02:
 c8:3b
 Exponent: 65537 (0x10001)

 Signature Algorithm: sha256WithRSAEncryption
 55:6a:69:0f:3a:e5:6f:d4:16:0a:4f:67:46:ec:36:ea:a4:54:
 db:04:86:e9:48:ed:0e:83:52:56:75:65:f0:85:34:32:75:0a:
 0a:15:13:73:21:a4:a9:9c:89:b4:73:15:06:2a:b3:e8:ab:7b:
 f4:16:37:17:a9:0e:eb:74:1d:78:c8:df:5e:5f:41:af:53:ca:
 a1:94:d8:d2:f5:87:a5:a9:8a:6a:d1:0e:e0:b7:30:92:d2:94:
 98:65:4c:bf:f9:a7:60:f8:c2:df:7c:4e:28:3c:02:f0:d4:a8:
 f7:16:d5:38:88:43:e4:c4:2e:02:72:ee:4b:6f:cd:2a:d7:3b:
 c4:e8:f4:7d:0e:3b:9b:5b:20:00:69:75:76:ce:79:a1:ed:25:
 f7:f1:3c:96:f8:7d:35:dd:5c:f8:4d:d2:04:32:bb:41:b2:3d:
 1a:5d:f6:63:ff:63:48:ec:85:c2:b3:9c:02:d3:ad:17:59:46:
 3e:10:6f:82:2f:d8:ef:6c:a5:42:3f:55:74:bb:f6:17:59:a0:
 39:e5:16:55:a3:f9:5a:b5:04:c0:61:2a:55:32:56:c2:12:0a:
 2c:c8:8a:23:b1:60:d5:a3:93:f3:a0:e4:e0:a8:98:3b:e1:83:
 ea:43:06:bc:d0:96:0b:c2:0b:95:6b:ce:39:02:7f:19:01:ea:
 47:83:25:c5
 Trusted Uses:
 TLS Web Client Authentication
 No Rejected Uses.
```

运行上述命令后，我们将在证书目录中有以下三个新文件：

+   `board001.key`: 客户端密钥

+   `board001.csr`：客户端证书签名请求

+   `board001.crt`：客户端证书文件

客户端证书文件以 PEM 格式存储，证书颁发机构证书文件和服务器证书文件也是如此。

我们将不得不向任何要连接到 Mosquitto 服务器的设备提供以下三个文件：

+   `ca.crt`

+   `board001.crt`

+   `board001.key`

永远不要向必须与 MQTT 服务器建立连接的设备提供额外的文件。您不希望设备能够生成额外的证书。您只希望它们使用有效的证书进行身份验证。

`openssl`实用程序允许我们使用附加的命令行选项为许多参数提供值。因此，可以自动化许多先前的步骤，以便更容易生成多个设备证书。

# 在 Mosquitto 中配置 TLS 客户端证书认证

现在，我们将配置 Mosquitto 以使用 TLS 客户端证书认证。这样，任何客户端都将需要`ca.crt`文件和客户端证书，例如最近生成的`board001.crt`文件，才能与 Mosquitto 服务器建立通信。

如果您在 macOS 或 Linux 的终端窗口中运行 Mosquitto 服务器，请按*Ctrl* + *C*停止它。在 Windows 中，请停止适当的服务。

转到 Mosquitto 安装目录并打开`mosquitto.conf`配置文件。

在 macOS、Linux 或 Windows 中，在配置文件的末尾添加以下行：

```py
require_certificate true
```

我们为`require_certificate`选项指定了`true`值，以使 Mosquitto 要求任何请求与 Mosquitto 建立连接的客户端都需要有效的客户端证书。

保存更改到`mosquitto.conf`配置文件并重新启动 Mosquitto。我们将使用 Mosquitto 中包含的`mosquitto_sub`命令行实用程序生成一个简单的 MQTT 客户端，该客户端订阅主题过滤器并打印其接收到的所有消息。

# 使用命令行工具测试 MQTT TLS 客户端认证

现在，我们将使用 Mosquitto 命令行工具来测试客户端认证配置。

以下命令指定证书颁发机构证书文件、客户端证书和客户端密钥。您必须用证书目录中创建的这些文件的完整路径替换`ca.crt`，`board001.crt`和`board001.key`。但是，最好将这些文件复制到一个新目录，就好像我们正在处理的文件只能供希望与 Mosquitto 建立连接的设备使用。与以前的命令一样，此命令使用`-h`选项，后面跟着 MQTT 服务器主机。在这种情况下，我们指定运行 Mosquitto MQTT 服务器的计算机的 IPv4 地址：`192.168.1.1`。请注意，此值必须与我们在生成`server.csr`文件时指定为值的 IPv4 或 IPv6 地址相匹配，即服务器证书签名请求的`Common Name`字段。如果您在`Common Name`字段中使用主机名作为值，而不是 IPv4 或 IPv6 地址，您将不得不使用相同的主机名。`mosquitto_sub`实用程序将创建一个 MQTT 订阅者，将与 Mosquitto 建立加密连接，并提供客户端证书和客户端密钥以进行身份验证：

```py
mosquitto_sub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt --cert board001.crt --key board001.key -t sensors/+/altitude -d
```

使用类似的语法，我们将使用 Mosquitto 中包含的`mosquitto_pub`命令行实用程序生成一个简单的 MQTT 客户端，该客户端将向与先前指定的主题过滤器匹配的主题发布消息，使用加密连接和客户端身份验证。在 macOS 或 Linux 中打开终端，或者在 Windows 中打开命令提示符，转到安装 Mosquitto 的目录，并运行以下命令。记得用`ca.crt`，`board001.crt`和`board001.key`替换`mqtt_certificates`目录中创建的这些文件的完整路径。此外，用我们在生成`server.csr`文件时指定为值的 IPv4 或 IPv6 地址替换 192.168.1.1，即服务器证书签名请求的`Common Name`字段。如果您在`Common Name`字段中使用主机名作为值，而不是 IPv4 或 IPv6 地址，您将不得不使用相同的主机名：

```py
mosquitto_pub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt --cert board001.crt --key board001.key -t sensors/quadcopter12/altitude -m "361 f" -d
```

有时，需要使客户端证书失效。Mosquitto 允许我们指定一个 PEM 编码的证书吊销列表文件。我们必须在 Mosquitto 配置文件的`crlfile`选项的值中指定此文件的路径。

# 使用 GUI 工具测试 MQTT TLS 配置

现在，我们将使用 MQTT.fx GUI 实用程序生成另一个 MQTT 客户端，该客户端使用加密连接和 TLS 客户端身份验证来发布消息到与我们用于订阅的主题过滤器匹配的主题`sensors/hexacopter25/altitude`。我们必须对启用 TLS 时使用的连接选项进行更改。我们必须指定客户端证书和客户端密钥文件。按照以下步骤操作：

1.  启动 MQTT.fx，并在连接到 Mosquitto MQTT 服务器时单击断开连接。

1.  在左上角的下拉菜单中选择本地 mosquitto，并单击该下拉菜单右侧和连接按钮左侧的配置图标。MQTT.fx 将显示带有不同连接配置选项的编辑连接配置对话框，名称为本地 mosquitto。

1.  转到 Broker Address 文本框，并输入我们在生成`server.csr`文件时指定为值的 IPv4 或 IPv6 地址，即服务器证书签名请求的`Common Name`字段。如果您在`Common Name`字段中使用主机名作为值，而不是 IPv4 或 IPv6 地址，您将不得不使用相同的主机名。如果 Broker Address 中指定的值与`Common Name`字段中指示的值不匹配，Mosquitto 服务器将拒绝客户端。

1.  单击 SSL/TLS 按钮。

1.  确保启用 SSL/TLS 复选框已激活。

1.  激活自签名证书单选按钮。

1.  在 CA 文件文本框中输入或选择您在`mqtt_certificates`文件夹中创建的`ca.crt`文件的完整路径。

1.  在客户端证书文件文本框中输入或选择您在`mqtt_ertificates`文件夹中创建的`board001.crt`文件的完整路径。

1.  在客户端密钥文件文本框中输入或选择您在`mqtt_certificates`文件夹中创建的`board001.key`文件的完整路径。

1.  确保激活 PEM 格式复选框。以下屏幕截图显示了具有所选选项和不同文本框的示例值的对话框：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/3093410b-c541-47f5-8e6d-0bc2abce3334.png)

1.  单击确定。然后，单击连接按钮。MQTT.fx 将使用我们指定的证书和密钥文件与本地 Mosquitto 服务器建立加密连接。请注意，连接按钮被禁用，断开按钮被启用，因为客户端已连接到 Mosquitto 服务器。

1.  单击订阅并在订阅按钮左侧的下拉菜单中输入`sensors/+/altitude`。然后，单击订阅按钮。MQTT.fx 将在左侧显示一个新面板，其中包含我们已订阅的主题过滤器。

1.  单击发布并在发布按钮左侧的下拉菜单中输入`sensors/hexacopter25/altitude`。

1.  在发布按钮下的文本框中输入以下文本：`1153 f`。

1.  然后，单击发布按钮。MQTT.fx 将向指定的主题发布输入的文本。

1.  单击订阅，您将看到发布的消息，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/fcca001d-30a8-45c5-922b-61374483c7a3.png)

现在，我们将使用 MQTT-spy GUI 实用程序生成另一个 MQTT 客户端，该客户端使用加密连接发布消息到另一个与`sensors/+/altitude`主题过滤器匹配的主题：`sensors/quadcopter500/altitude`。按照以下步骤：

1.  启动 MQTT-spy。

1.  如果您已经在运行 MQTT-spy 或保存了以前的设置，请选择连接|新连接或连接|管理连接。连接列表对话框将出现。

1.  单击连接选项卡，确保在协议版本下拉菜单中选择了 MQTT 3.1.1。

1.  转到服务器 URI(s)文本框，并输入我们在生成`server.csr`文件时指定为值的 IPv4 或 IPv6 地址，即通用名称字段。如果您在通用名称字段中使用主机名作为值，而不是 IPv4 或 IPv6 地址，则必须使用相同的主机名。如果在经纪人地址中指定的值与通用名称字段中指示的值不匹配，则 Mosquitto 服务器将拒绝 MQTT-spy 实用程序生成的客户端。

1.  单击安全选项卡，然后单击用户 auth.选项卡下方的 TLS 选项卡。

1.  在 TLS/SSL 模式下拉菜单中选择 CA 证书和客户端证书/密钥。

1.  在协议下拉菜单中选择 TLSv1.2。

1.  在 CA 证书文件文本框中输入或选择您在`mqtt_certificates`文件夹中创建的`ca.crt`文件的完整路径。

1.  在客户端证书文件文本框中输入或选择您在`mqtt_ertificates`文件夹中创建的`board001.crt`文件的完整路径。

1.  在客户端密钥文件文本框中输入或选择您在`mqtt_certificates`文件夹中创建的`board001.key`文件的完整路径。

1.  激活 PEM 格式中的客户端密钥复选框。最后，单击打开连接或关闭并重新打开现有连接。以下屏幕截图显示了具有所选选项和文本框示例值的对话框：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/d1b1f37c-11cd-44e3-a5ee-168bbcfbb383.png)

1.  MQTT-spy 将关闭对话框，并显示一个具有绿色背景和在连接列表对话框中出现的连接名称的新选项卡。确保单击新连接的选项卡。

1.  在主题下拉菜单中输入`sensors/quadcopter500/altitude`。

1.  在“数据”文本框中输入以下文本：`1417 f`。

1.  单击“发布”按钮。 MQTT-spy 将输入的文本发布到指定的主题，您将能够在 MQTT.fx 订阅者和`mosquitto-sub`订阅者中看到消息。

任何安全配置都会发生的情况，如果根据先前的说明未激活任何复选框，MQTT 客户端将无法与 Mosquitto 建立连接。请记住证书使用 PEM 格式。

# 将 TLS 协议版本强制为特定数字

使用最高可能的 TLS 协议版本是一个好习惯。默认情况下，Mosquitto 服务器接受 TLS 1.0、1.1 和 1.2。如果所有客户端都能够使用 Mosquitto 支持的最高 TLS 协议版本，我们应该强制 Mosquitto 仅使用最高版本。这样，我们可以确保不会受到先前 TLS 版本的攻击。

现在，我们将在配置文件中进行必要的更改以强制使用 TLS 1.2。如果您在 macOS 或 Linux 的终端窗口中运行 Mosquitto 服务器，请按*Ctrl *+ *C*停止它。在 Windows 中，停止适当的服务。

转到 Mosquitto 安装目录并打开`mosquitto.conf`配置文件。

在 macOS、Linux 或 Windows 中，在配置文件的末尾添加以下行：

```py
tls_version tlsv1.2
```

我们为`tls_version`选项指定了`tlsv1.2`值，以便 Mosquitto 仅使用 TLS 1.2。任何使用先前 TLS 版本的客户端将无法与 Mosquitto 服务器建立连接。

保存更改到`mosquitto.conf`配置文件并重新启动 Mosquitto。我们在 MQTT.fx 和 MQTT-spy GUI 实用程序中配置连接时指定了 TLS 版本；具体来说，我们为客户端指定了 TLS 1.2 作为期望的 TLS 版本，因此不需要额外的更改。我们必须在`mosquitto_sub`和`mosquitto_pub`命令行实用程序中使用`--tls-version tlsv1.2`选项。

在 macOS 或 Linux 中打开终端，或在 Windows 中打开命令提示符，转到 Mosquitto 安装的目录，并运行以下命令。记得使用`ca.crt`，`device.001`和`device.key`文件的完整路径。此外，将`192.168.1.1`替换为我们在生成`server.csr`文件时指定为“通用名称”字段值的 IPv4 或 IPv6 地址，即服务器证书签名请求。如果您在“通用名称”字段中使用主机名而不是 IPv4 或 IPv6 地址作为值，则必须使用相同的主机名：

```py
mosquitto_pub -h 192.168.1.1 --tls-version tlsv1.2 -V mqttv311 -p 8883 --cafile ca.crt -t sensors/octocopter01/altitude -m "1025 f" -d
```

上一个命令指定了使用 TLS 1.2，因此 MQTT 客户端可以与 Mosquitto 服务器建立连接并发布消息。如果我们指定不同的 TLS 版本，`mosquitto_pub`命令将无法连接到 Mosquitto 服务器。

# 测试您的知识

让我们看看您是否能正确回答以下问题：

1.  MQTT 上 TLS 的默认端口号是多少：

1.  `1883`

1.  `5883`

1.  `8883`

1.  以下哪个实用程序允许我们生成 X.509 数字证书：

1.  OpenX509

1.  TLS4Devs

1.  OpenSSL

1.  当我们使用 MQTT 上的 TLS 时：

1.  与没有 TLS 的 MQTT 上 TCP 相比，存在带宽和处理开销

1.  与没有 TLS 的 MQTT 上 TCP 相比，只有一点带宽开销，但没有处理开销

1.  与没有 TLS 的 MQTT 上 TCP 相比，没有开销

1.  以下哪项可以用来保护和加密 MQTT 客户端和 MQTT 服务器之间的通信：

1.  TCPS

1.  TLS

1.  HTTPS

1.  如果我们在 Mosquitto 配置文件（`mosquitto.conf`）的`require_certificate`选项中指定`true`作为值：

1.  想要连接到 MQTT 服务器的客户端将需要一个客户端证书

1.  想要连接到 MQTT 服务器的客户端不需要客户端证书

1.  想要连接到 MQTT 服务器的客户端可以提供一个可选的客户端证书

正确答案包括在附录中的*Solutions*中。

# 总结

在本章中，我们生成了一个私有证书颁发机构、一个服务器证书和客户端证书，以实现 Mosquitto 的 TLS 传输安全和 TLS 客户端认证。MQTT 客户端和 MQTT 服务器之间的通信是加密的。

我们与 OpenSSL 合作为我们的开发环境生成自签名数字证书。我们使用 MQTT.fx，MQTT-spy 和 Mosquitto 命令行工具测试了 MQTT TLS 配置。我们强制 Mosquitto 仅使用特定的 TLS 版本。

与 MQTT 服务器和 Mosquitto 相关的许多其他安全主题。我们将在接下来的章节中处理其中一些，届时我们将开发将使用 Python 与 MQTT 的应用程序。

现在我们了解了如何加密 MQTT 客户端和 Mosquitto 服务器之间的通信，我们将了解 MQTT 库，并编写 Python 代码来通过加密连接传递 MQTT 消息来控制车辆，这是我们将在第四章中讨论的主题，*使用 Python 和 MQTT 消息编写控制车辆的代码*。
