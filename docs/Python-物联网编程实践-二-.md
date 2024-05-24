# Python 物联网编程实践（二）

> 原文：[`zh.annas-archive.org/md5/7FABA31DD38F615362E1254C67CC152E`](https://zh.annas-archive.org/md5/7FABA31DD38F615362E1254C67CC152E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 MQTT，Python 和 Mosquitto MQTT 代理进行网络连接

在上一章中，我们使用 RESTful API 和 Web Socket 方法创建了两个 Python 服务器和相应的网页。在本章中，我们将涵盖另一种在物联网世界中常见的网络拓扑，称为**MQTT**或**消息队列遥测传输**。

我们将首先设置您的开发环境，并在树莓派上安装 Mosquitto MQTT 代理服务。然后，我们将使用 Mosquitto 附带的命令行工具学习 MQTT 的特性，以帮助您单独理解核心概念。之后，我们将进行一个使用 MQTT 作为其消息传输层的 Python 物联网应用程序，是的，它将完全关于 LED 的控制！

我们将在本章中涵盖以下主题：

+   安装 Mosquitto MQTT 代理

+   通过示例学习 MQTT

+   介绍 Python Paho-MQTT 客户端库

+   使用 Python 和 MQTT 控制 LED

+   构建基于 Web 的 MQTT 客户端

# 技术要求

要执行本章的练习，您需要以下内容：

+   树莓派 4 型 B 型号

+   Raspbian OS Buster（带桌面和推荐软件）

+   至少 Python 版本 3.5

这些要求是本书中代码示例的基础。可以合理地期望代码示例应该可以在树莓派 3 型 B 型或不同版本的 Raspbian OS 上无需修改地运行，只要您的 Python 版本是 3.5 或更高。

您可以在以下 URL 的 GitHub 存储库的`chapter04`文件夹中找到本章的源代码：[`github.com/PacktPublishing/Practical-Python-Programming-for-IoT`](https://github.com/PacktPublishing/Practical-Python-Programming-for-IoT)

您需要在终端中执行以下命令，以设置虚拟环境并安装本章代码所需的 Python 库：

```py
$ cd chapter04              # Change into this chapter's folder
$ python3 -m venv venv      # Create Python Virtual Environment
$ source venv/bin/activate  # Activate Python Virtual Environment
(venv) $ pip install pip --upgrade        # Upgrade pip
(venv) $ pip install -r requirements.txt  # Install dependent packages
```

从`requirements.txt`中安装以下依赖项：

+   **GPIOZero**：GPIOZero GPIO 库（[`pypi.org/project/gpiozero`](https://pypi.org/project/gpiozero)）

+   **PiGPIO**：PiGPIO GPIO 库（[`pypi.org/project/pigpio`](https://pypi.org/project/pigpio)）

+   **Paho-MQTT** **客户端**：Paho-MQTT 客户端库（[`pypi.org/project/paho-mqtt`](https://pypi.org/project/paho-mqtt)）

我们将使用我们在第二章中创建的面包板电路进行工作，*使用 Python 和物联网入门*，*图 2.7*。

# 安装 Mosquitto MQTT 代理

**MQTT**，或**消息队列遥测传输**，是一种专门针对物联网应用的轻量级和简单的消息传输协议。虽然树莓派足够强大，可以利用更复杂的消息传输协议，但如果您将其用作分布式物联网解决方案的一部分，很可能会遇到 MQTT；因此，学习它非常重要。此外，它的简单性和开放性使其易于学习和使用。

我们将使用一个名为*Mosquitto*的流行开源 MQTT 代理来进行 MQTT 的介绍，并将其安装在您的树莓派上。

本章涵盖的示例是使用 Mosquitto 代理和客户端版本 1.5.7 执行的，这是 MQTT 协议版本 3.1.1 兼容的。只要它们是 MQTT 协议版本 3.1.x 兼容的，代理或客户端工具的不同版本都将适用。

要安装 Mosquitto MQTT 代理服务和客户端工具，请按照以下步骤进行：

1.  打开一个新的终端窗口并执行以下`apt-get`命令。这必须使用`sudo`执行：

```py
$ sudo apt-get --yes install mosquitto mosquitto-clients
... truncated ...
```

1.  要确保 Mosquitto MQTT 代理服务已启动，请在终端中运行以下命令：

```py
$ sudo systemctl start mosquitto
```

1.  使用以下`service`命令检查 Mosquitto 服务是否已启动。我们期望在终端上看到`active (running)`文本打印出来：

```py
$ systemctl status mosquitto
... truncated ...
 Active: active (running)
... truncated ...
```

1.  我们可以使用`mosquitto -h`命令检查 Mosquitto 和 MQTT 协议版本。 在这里，我们看到 Mosquitto 代理使用的是 MQTT 版本 3.1.1：

```py
$ mosquitto -h
mosquitto version 1.5.7
mosquitto is an MQTT v3.1.1 broker.
... truncated ...
```

1.  接下来，我们将配置 Mosquitto，以便它可以提供网页并处理 Web 套接字请求。 当我们在本章后面构建网页客户端时，我们将使用这些功能。

在`chapter4`文件夹中，有一个名为`mosquitto_pyiot.conf`的文件，这里部分复制了该文件。 此文件中有一行我们需要检查的内容：

```py
# File: chapter04/mosquitto_pyiot.conf
... truncated...
http_dir /home/pi/pyiot/chapter04/mosquitto_www
```

对于本章的练习，您需要更新最后一行的`http_dir`设置，使其成为树莓派上`chapter04/mosquitto_www`文件夹的绝对路径。 如果您在第一章*，设置您的开发环境*中克隆 GitHub 存储库时使用了建议的文件夹`/home/pi/pyiot`，那么先前列出的路径是正确的。

1.  接下来，我们使用以下`cp`命令将`mosquitto_pyiot.conf`中的配置复制到适当的文件夹中，以便 Mosquitto 可以加载它：

```py
$ sudo cp mosquitto_pyiot.conf /etc/mosquitto/conf.d/
```

1.  现在我们重新启动 Mosquitto 服务以加载我们的配置：

```py
$ sudo systemctl restart mosquitto 
```

1.  要检查配置是否有效，请在树莓派上的 Web 浏览器中访问`http://localhost:8083` URL，您应该看到类似以下截图的页面：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/525e2257-5a0c-4b58-a62a-8b11eb2f467e.png)

图 4.1 - Mosquitto MQTT 代理提供的网页

这是本章后面我们将要做的事情的线索！ 目前，虽然您可以移动滑块，但它*不会*改变 LED 的亮度，因为我们没有运行 Python 端的代码。 我们将在本章后面逐步介绍。

如果您在启动 Mosquitto MQTT 代理时遇到问题，请尝试以下操作：

+   在终端中执行`sudo mosquitto -v -c /etc/mosquitto/mosquitto.conf`。 这将在前台启动 Mosquitto，并且任何启动或配置错误都将显示在您的终端上。

+   阅读`mosquitto_pyiot.conf`文件中的故障排除注释以获取其他建议。

Mosquitto 安装后的默认配置创建了一个*未加密*和*未经身份验证*的 MQTT 代理服务。 Mosquitto 文档包含有关其配置以及如何启用身份验证和加密的详细信息。 您将在本章末尾的*进一步阅读*部分找到链接。

现在我们已经安装并运行了 Mosquitto，我们可以探索 MQTT 概念并执行示例以看到它们在实践中的应用。

# 通过示例学习 MQTT

MQTT 是基于代理的*发布*和*订阅*消息协议（经常被简化为*pub/sub*），而 MQTT *代理*（就像我们在上一节中安装的 Mosquitto MQTT 代理）是实现 MQTT 协议的服务器。 通过使用基于 MQTT 的架构，您的应用程序可以基本上将所有复杂的消息处理和路由逻辑交给代理，以便它们可以保持专注于解决方案。

MQTT 客户端（例如，您的 Python 程序和我们即将使用的命令行工具）与代理创建订阅并*订阅*它们感兴趣的消息主题。 客户端*发布*消息到主题，然后代理负责所有消息路由和传递保证。 任何客户端都可以扮演订阅者、发布者或两者的角色。

*图 4.2*展示了涉及泵、水箱和控制器应用程序的简单概念 MQTT 系统：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/09bd86dd-a43b-4ff7-917c-c0be54738043.png)

图 4.2 - MQTT 示例

以下是系统组件的高级描述：

+   将*水位传感器 MQTT 客户端*视为连接到水箱中的水位传感器的软件。 在我们的 MQTT 示例中，此客户端扮演*发布者*的角色。 它定期发送（即*发布*）关于水箱装满了多少水的消息到 MQTT 代理。

+   将* Pump MQTT 客户端*视为能够打开或关闭水泵的软件驱动程序。在我们的示例中，此客户端扮演*发布者*和*订阅者*的角色：

+   作为*订阅者*，它可以接收一条消息（通过*订阅*）指示它打开或关闭水泵。

+   作为*发布者*，它可以发送一条消息，指示水泵是打开并抽水还是关闭。

+   将*Controller MQTT 客户端*视为所有控制逻辑所在的应用程序。此客户端还扮演*发布者*和*订阅者*的角色：

+   作为*发布者*，此客户端可以发送一条消息，告诉水泵打开或关闭。

+   作为*订阅者*，此客户端可以从水箱水位传感器和水泵接收消息。

举例来说，*Controller MQTT 客户端*应用程序可以配置为在水箱水位低于 50％时打开水泵，并在水位达到 100％时关闭水泵。此控制器应用程序还可以包括一个仪表板用户界面，显示水箱的当前水位以及指示水泵是否打开或关闭的状态灯。

关于我们的 MQTT 系统需要注意的一点是，每个客户端都不知道其他客户端，客户端只连接到 MQTT 代理并与之交互，然后代理将消息适当地路由到客户端。这通过使用消息*主题*来实现，我们将在标题为*探索 MQTT 主题和通配符*的部分中进行介绍。

可以理解为什么水泵需要接收消息来告诉它打开或关闭，但是水泵还需要发送消息来说明它是打开还是关闭吗？如果您对此感到困惑，这就是原因。MQTT 消息是发送并忘记的，这意味着客户端不会收到它发布的消息的应用级响应。因此，在我们的示例中，虽然控制器客户端可以发布一条消息要求水泵打开，但如果水泵不发布其状态，控制器就无法知道水泵是否真的打开了。

在实践中，每次水泵打开或关闭时，水泵都会发布其开/关状态。这将允许控制器的仪表板及时更新水泵的状态指示器。此外，水泵还会定期发布其状态（就像水位传感器一样），而不依赖于其接收到的任何请求来打开或关闭。这样，控制器应用程序可以监视水泵的连接和可用性，并检测水泵是否脱机。

目前，如果您能理解前面示例中提出的基本思想，那么您就已经在更深入地理解本章其余部分将关注的核心 MQTT 概念的道路上了。到我们完成时，您将对如何使用和设计基于 MQTT 的应用程序有一个基本的端到端理解。

我们将从学习如何发布和订阅消息开始。

## 发布和订阅 MQTT 消息

让我们通过以下步骤来发送（即发布）和接收（即订阅）使用 MQTT 的消息：

1.  在终端中运行以下命令。`mosquitto_sub`（Mosquitto 订阅）是一个命令行工具，用于*订阅*消息：

```py
# Terminal #1 (Subscriber)
$ mosquitto_sub -v -h localhost -t 'pyiot'
```

选项如下：

+   +   `-v`（-详细信息）：详细信息是为了在终端上打印消息*主题*和*消息*负载。

+   `-h`（-主机）：localhost 是我们要连接的代理的主机；这里是我们刚刚安装的代理。使用的默认端口是 1883。

+   `-t`（-主题）：`pyiot`是我们要订阅和监听的主题。

在本章中，我们将需要两个或三个终端会话来进行示例。代码块的第一行将指示您需要在哪个终端中运行命令；例如，在前面的代码块中是**终端＃1**，在下面的代码块中是**终端＃2**。

1.  打开第二个终端并运行以下命令。`mosquitto_pub`（Mosquitto 发布）是一个命令行工具，用于*发布*消息：

```py
# Terminal #2 (Publisher)
$ mosquitto_pub -h localhost -t 'pyiot' -m 'hello!' 
```

让我们看看选项：

+   +   `-h`和`-t`的含义与前面的订阅命令相同。

+   `-m 'hello!'`（-message）是我们想要发布的消息。在 MQTT 中，消息是简单的字符串——如果你想知道 JSON，它只需要被序列化/反序列化为字符串。

1.  在**终端#1**上，我们看到主题和消息`hello!`被打印出来：

```py
# Terminal #1 (Subscriber)
$ mosquitto_sub -v -h localhost -t 'pyiot'
pyiot hello!
```

最后一行的格式是<*topic>* <*message payload>*。

因为我们使用了`-v`选项来订阅`mosquitto_sub`，所以`hello!`消息之前有主题名`pyiot`。如果没有`-v`选项，如果我们订阅多个主题，我们无法确定消息属于哪个主题。

现在，我们已经学会了如何使用简单主题发布和订阅消息。但是有没有办法更好地组织这些消息呢？继续阅读。

## 探索 MQTT 主题和通配符

MQTT *主题* 用于以分层格式对消息进行分类或分组。我们已经在我们之前的命令行示例中使用主题，但是以非分层的方式。另一方面，通配符是订阅者用来创建灵活的主题匹配模式的特殊字符。

以下是来自具有传感器的假设建筑的一些分层主题示例。层次结构由`/`字符分隔：

+   `level1/lounge/temperature/sensor1`

+   `level1/lounge/temperature/sensor2`

+   `level1/lounge/lighting/sensor1`

+   `level2/bedroom1/temperature/sensor1`

+   `level2/bedroom1/lighting/sensor1`

在 MQTT 代理上没有必要预先创建主题。使用*默认*代理配置（我们正在使用），您只需随意发布和订阅主题。

当 Mosquitto 代理配置为使用身份验证时，有可能根据客户端 ID 和/或用户名和密码限制对主题的访问。

消息*必须*发布到*特定*主题，如`pyiot`，而订阅可以通过使用通配符字符`+`和`#`订阅到特定主题或一系列主题：

+   `+`用于匹配层次结构的单个元素。

+   `#` 用于匹配层次结构中的*所有*剩余元素（它只能在主题查询的末尾）。

对主题和通配符的订阅最好通过示例来解释。使用上述假设的建筑和传感器，考虑以下表中的示例：

| 我们想要订阅... | 通配符主题 | 主题匹配 |
| --- | --- | --- |
| 到处的**温度**传感器 | `+/+/**temperature**/+` |

+   `level1/lounge/**temperature**/sensor1`

+   `level1/lounge/**temperature**/sensor2`

+   `level2/bedroom1/**temperature**/sensor1`

|

| 所有地方的**灯**传感器 | `+/+/**lighting**/+` |
| --- | --- |

+   `level1/lounge/**lighting**/sensor1`

+   `level2/bedroom1/**lighting**/sensor1`

|

| **level 2** 上的每个传感器 | `**level2**/+/+/+` |
| --- | --- |

+   `**level2**/bedroom1/temperature/sensor1`

+   `**level2**/bedroom1/lighting/sensor1`

|

| **level 2** 上的每个传感器（一个更简单的方法，其中`#`匹配每个剩余的子级） | `**level2**/#` |
| --- | --- |

+   **level2**/bedroom1/temperature/sensor1

+   `**level2**/bedroom1/lighting/sensor1`

|

| 到处只有**sensor1** | `+/+/+/**sensor1**` |
| --- | --- |

+   `level1/lounge/temperature/**sensor1**`

+   `level1/lounge/lighting/**sensor1**`

+   `**level2**/bedroom1/temperature/**sensor1**`

+   `level2/bedroom1/lighting/**sensor1**`

|

| 到处只有**sensor1**（一个更简单的方法，其中`#`匹配每个剩余的子级） | `#/**sensor1**` | 无效，因为#只能在主题查询的末尾 |
| --- | --- | --- |
| 每个主题 | `#` | 匹配所有内容 |
| 代理信息 | `$SYS/#` | 这是一个特殊的保留主题，代理在其中发布信息和运行时统计信息。 |

表 1 - MQTT 通配符主题示例

从前面的示例中可以明显看出，您需要在设计应用程序的主题层次结构时小心，以便使用通配符订阅多个主题是一致的、逻辑的和简单的。

如果您使用`mosquitto_sub`订阅使用`+`或`#`通配符，请记住使用`-v`（--verbose）选项，以便主题名称打印在输出中，例如`mosquitto_sub -h localhost -v -t '#'`。

在命令行上尝试一些示例，通过混合和匹配前面的主题和通配符来感受主题和通配符的工作原理。以下是一个示例的步骤，其中`mosquitto_sub`订阅了所有从根主题下两级的父主题为*temperature*的子主题：

1.  在一个终端中，启动一个订阅通配符主题的订阅者：

```py
# Terminal #1 (Subscriber)
mosquitto_sub -h localhost -v -t '+/+/temperature/+'
```

1.  使用*表 1 - MQTT 通配符主题示例*中的主题，以下是两个`mosquitto_pub`命令，将发布的消息将被**终端#1**中的`mosquitto_sub`命令接收：

```py
# Terminal #2 (Publisher)
$ mosquitto_pub -h localhost -t 'level1/lounge/temperature/sensor1' -m '20'
$ mosquitto_pub -h localhost -t 'level2/bedroom1/temperature/sensor1' -m '22'
```

我们刚刚看到如何使用通配符字符`+`和`*`订阅主题层次结构。使用主题和通配符一起是一个设计决策，您需要根据数据流动的需求以及您设想客户端应用程序发布和订阅的方式在每个项目级别上做出的。在设计一致而灵活的基于通配符的主题层次结构方面投入的时间将有助于帮助您构建更简单和可重用的客户端代码和应用程序。

接下来，我们将学习有关消息服务质量的所有内容，以及这如何影响您通过 MQTT Broker 发送的消息。

## 将服务质量应用于消息

MQTT 为*单个消息传递*提供了三个**服务质量**（**QoS**）级别 - 我强调*单个消息传递*，因为 QoS 级别适用于单个消息的传递，而不适用于主题。随着您逐步学习示例，这一点将变得更加清晰。

作为开发人员，您规定消息的 QoS，而代理负责确保消息传递符合 QoS。以下是您可以应用于消息的 QoS 以及它们对传递的含义：

| **QoS 级别** | **含义** | **传递的消息数量** |
| --- | --- | --- |
| 级别 0 | 该消息将被传递最多一次，但也可能根本不传递。 | 0 或 1 |
| 级别 1 | 该消息将至少传递一次，但可能更多。 | 1 或更多 |
| 级别 2 | 该消息将被传递一次。 | 1 |

表 2 - 消息 QoS 级别

您可能会问：级别 0 和 1 似乎有点随机，那么为什么不总是使用级别 2 呢？答案是*资源*。让我们看看为什么...

与较低级别的 QoS 消息相比，代理和客户端将消耗更多的资源来处理较高级别的 QoS 消息 - 例如，代理将需要更多的时间和内存来存储和处理消息，而代理和客户端在确认确认和连接握手时消耗更多的时间和网络带宽。

对于许多用例，包括本章后续的示例，我们将注意不到 QoS 级别 1 和 2 之间的区别，我们也无法实际演示它们（级别 0 由于一个很好的原因被省略，我们稍后将在消息保留和持久连接时看到）。然而，设想一个分布式物联网系统，其中成千上万的传感器每分钟发布成千上万条消息，现在围绕 QoS 设计开始变得更有意义。

QoS 级别适用于消息订阅和消息发布，当你第一次思考时，这可能看起来有点奇怪。例如，一个客户端可以以 QoS 1 发布消息到一个主题，而另一个客户端可以以 QoS 2 订阅该主题（我知道我说 QoS 与消息有关，而不是与主题有关，但在这里，它与通过主题流动的消息有关）。这条消息的 QoS 是 1 还是 2？对于订阅者来说，是 1——让我们找出原因。

订阅客户端选择它想要接收的消息的最高 QoS，但可能会得到更低的 QoS。因此，实际上，这意味着客户端接收的交付 QoS 被降级为发布或订阅的最低 QoS。

以下是一些供您思考的示例：

| 发布者发送消息 | 订阅者订阅 | 订阅者获取的内容 |
| --- | --- | --- |
| QoS 2 | QoS 0 | 传递符合 QoS 0 的消息（订阅者获取消息 0 次或 1 次） |
| QoS 2 | QoS 2 | 传递符合 QoS 2 的消息（订阅者获取消息一次） |
| QoS 0 | QoS 1 | 传递符合 QoS 0 的消息（订阅者获取消息 0 次或 1 次） |
| QoS 1 | QoS 2 | 传递符合 QoS 1 的消息（订阅者获取消息 1 次或多次） |
| QoS 2 | QoS 1 | 传递符合 QoS 1 的消息（订阅者获取消息 1 次或多次） |

表 3 - 发布者和订阅者 QoS 示例

从这些示例中可以得出的结论是，在实践中，设计或集成物联网解决方案时，您需要了解主题两侧的发布者和订阅者使用的 QoS——QoS 不能在任一侧单独解释。

以下是播放 QoS 场景并实时查看客户端-代理交互的步骤：

1.  在终端中，运行以下命令启动订阅者：

```py
# Terminal 1 (Subscriber)
$ mosquitto_sub -d -v -q 2 -h localhost -t 'pyiot'
```

1.  在第二个终端中，运行以下命令发布消息：

```py
# Terminal 2 (Publisher)
$ mosquitto_pub -d -q 1 -h localhost -t 'pyiot' -m 'hello!'
```

在这里，我们再次在**终端＃1**上订阅，并在**终端＃2**上发布。以下是与`mosquitto_sub`和`mosquitto_pub`一起使用的新选项：

+   +   `-d`：打开调试消息

+   `-q <level>`：QoS 级别

启用调试（`-d`）后，尝试在任一侧更改`-q`参数（为 0、1 或 2）并发布新消息。

1.  观察**终端＃1**和**终端＃2**中记录的消息。

在**终端＃1**和**终端＃2**中将出现一些调试消息，您将观察到订阅端发生的 QoS 降级（寻找`q0`，`q1`或`q2`），而在双方，您还将注意到不同的调试消息，具体取决于客户端和代理执行握手和交换确认时指定的 QoS：

```py
# Terminal 1 (Subscriber)
$ mosquitto_sub -d -v -q 2 -h localhost -t 'pyiot' # (1)
Client mosqsub|25112-rpi4 sending CONNECT
Client mosqsub|25112-rpi4 received CONNACK (0)
Client mosqsub|25112-rpi4 sending SUBSCRIBE (Mid: 1, Topic: pyiot, QoS: 2) # (2)
Client mosqsub|25112-rpi4 received SUBACK
Subscribed (mid: 1): 2
Client mosqsub|25112-rpi4 received PUBLISH (d0, q1, r0, m1, 'pyiot', ... (6 bytes)) # (3)
Client mosqsub|25112-rpi4 sending PUBACK (Mid: 1)
pyiot hello!
```

以下是**终端＃1**上订阅者的调试输出。请注意以下内容：

+   +   在第 1 行，我们使用 QoS 2（`-q 2`）进行订阅。这在调试输出中反映为`QoS：2`，在第 2 行。

+   在第 3 行，我们看到了 QoS 的降级。接收到的消息是 QoS 1（`q1`），这是消息在**终端＃1**中发布的 QoS。

QoS 是较复杂的 MQTT 概念之一。如果您想更深入地了解 QoS 级别以及发布者、订阅者和代理之间进行的低级通信，您将在*进一步阅读*部分找到链接。

现在我们已经介绍了消息 QoS 级别，接下来我们将了解两个 MQTT 功能，确保离线客户端可以在重新上线时接收以前的消息。我们还将看到 QoS 级别如何影响这些功能。

## 保留消息以供以后传递

MQTT 代理可以被指示保留发布到主题的消息。消息保留有两种类型，称为保留消息和持久连接：

+   保留消息是指代理保留在主题上发布的最后一条消息。这也通常被称为最后已知的好消息，任何订阅主题的客户端都会自动获取此消息。

+   **持久连接**也涉及保留消息，但在不同的上下文中。如果客户端告诉代理它想要一个*持久连接*，那么代理将在客户端离线时保留 QoS 1 和 2 的消息。

除非特别配置，Mosquitto *不会*在服务器重新启动时保留消息或连接。要在重新启动时保留此信息，Mosquitto 配置文件必须包含条目`persistence true`。树莓派上 Mosquitto 的默认安装应该包括此条目，但是，为了确保它也包含在我们之前安装的`mosquitto_pyiot.conf`中。请参阅官方 Mosquitto 文档以获取有关持久性的更多信息和配置参数。您将在本章末尾的*进一步阅读*部分找到链接。

接下来，我们将学习保留消息并在随后的部分中涵盖持久连接。

### 发布保留消息

发布者可以要求代理保留一个消息作为主题的*最后已知的良好*消息。任何新连接的订阅者将立即收到这个最后保留的消息。

让我们通过一个示例来演示保留消息：

1.  运行以下命令，注意我们从**终端#2**开始，这个示例中是发布者：

```py
# Terminal 2 (Publisher)
$ mosquitto_pub -r -q 2 -h localhost -t 'pyiot' -m 'hello, I have been retained!'
```

已添加了一个新选项，`-r`（--retain），告诉代理应该为该主题保留此消息。

一个主题只能存在一个保留的消息。如果使用`-r`选项发布另一条消息，则先前保留的消息将被替换。

1.  在另一个终端中启动一个订阅者，然后立即您将收到保留的消息：

```py
# Terminal 1 (Subscriber)
$ mosquitto_sub -v -q 2 -h localhost -t 'pyiot'
pyiot hello, I have been retained!
```

1.  在**终端#1**中按下*Ctrl* + *C*来终止`mosquitto_sub`。

1.  再次使用与*步骤 2*相同的命令启动`mosquitto_sub`，然后您将在**终端#1**中再次收到保留的消息。

您仍然可以发布普通消息（即*不*使用`-r`选项），但是，新连接的订阅者将接收到使用`-r`选项指示的最后保留的消息。

1.  我们的最后一个命令显示了如何清除先前保留的消息：

```py
# Terminal 2 (Publisher)
$ mosquitto_pub -r -q 2 -h localhost -t 'pyiot' -m ''
```

在这里，我们正在发布（使用`-r`）一个带有`-m ''`的空消息。请注意，我们可以使用`-n`作为`-m ''`的替代方法来指示空消息。保留空消息的效果实际上是清除保留的消息。

当您向主题发送空消息以删除保留的消息时，当前订阅该主题的任何客户端（包括具有持久连接的离线客户端-请参阅下一节）都将收到空消息，因此您的应用代码必须适当地测试和处理空消息。

现在您了解并知道如何使用保留消息，我们现在可以探索 MQTT 中可用的另一种消息保留类型，称为*持久连接*。

### 创建持久连接

订阅主题的客户端可以要求代理在其离线时保留或排队消息。在 MQTT 术语中，这被称为*持久连接*。为了使持久连接和传递工作，订阅客户端需要以特定的方式进行配置和订阅，如下所示：

+   当客户端连接时，*必须*向代理提供唯一的客户端 ID。

+   客户端*必须*使用 QoS 1 或 2（级别 1 和 2 保证传递，但级别 0 不保证）进行订阅。

+   客户端只有在使用 QoS 1 或 2 进行发布的消息时才能得到保证。

最后两点涉及了一个示例，其中了解主题的发布和订阅双方的 QoS 对于物联网应用程序设计非常重要。

MQTT 代理可以在代理重新启动时保留消息，树莓派上 Mosquitto 的默认配置也可以这样做。

让我们通过一个示例来演示：

1.  启动订阅者，然后立即使用*Ctrl* + *C*终止它，使其处于离线状态：

```py
# Terminal #1 (Subscriber)
$ mosquitto_sub -q 1 -h localhost -t 'pyiot' -c -i myClientId123
$ # MAKE SURE YOU PRESS CONTROL+C TO TERMINATE mosquitto_sub
```

使用的新选项如下：

+   +   `-i <client id>`（-id <client id>）是一个唯一的客户端 ID（这是代理识别客户端的方式）。

+   `-c`（--disable-clean-session）指示代理保留订阅主题上到达的任何 QoS 1 和 2 消息，即使客户端断开连接（即*保留*消息）。

措辞有点反向，但通过使用`-c`选项启动订阅者，我们已要求代理通过在连接时不清除任何存储的消息来为我们的客户端创建一个*持久连接*。

如果您使用通配符订阅一系列主题（例如，`pyiot/#`），并请求持久连接，那么通配符层次结构中所有主题的所有消息都将保留给您的客户端。

1.  发布一些消息（当**终端#1**中的订阅者仍然离线时）：

```py
# Terminal #2 (Publisher)
$ mosquitto_pub -q 2 -h localhost -t 'pyiot' -m 'hello 1'
$ mosquitto_pub -q 2 -h localhost -t 'pyiot' -m 'hello 2'
$ mosquitto_pub -q 2 -h localhost -t 'pyiot' -m 'hello 3
```

1.  将**终端#1**中的订阅者重新连接，我们将看到在*步骤 2*中发布的消息被传送：

```py
# Terminal 1 (Subscriber)
$ mosquitto_sub -v -q 1 -h localhost -t 'pyiot' -c -i myClientId123
pyiot hello 1
pyiot hello 2
pyiot hello 3
```

再次尝试*步骤 1*至*3*，只是这次在*步骤 1*和*3*中的订阅者中省略`-c`选项，您会注意到没有消息被保留。此外，当您在有保留消息等待传送时*不使用*`-c`标志连接时，那么所有保留消息都将被清除（这是您想要清除客户端的保留消息的方法）。

如果您在单个主题上同时使用*保留消息*（即最后已知的良好消息）和*持久连接*，并重新连接离线订阅者，您将*收到保留消息两次*—一次是*保留消息*，而第二次是来自*持久连接*的消息。

在围绕 MQTT 构建解决方案时，您对保留消息和持久连接的了解将对设计具有弹性和可靠性的系统至关重要，特别是在需要处理离线客户端的情况下。保留（最后已知的良好）消息非常适合在客户端重新上线时初始化客户端，而持久连接将帮助您为任何必须能够消费其订阅的每条消息的离线客户端保留和传送消息。

干得好！我们已经涵盖了很多内容，实际上您现在已经了解了构建基于 MQTT 的物联网解决方案时将使用的大多数核心 MQTT 功能。我们要了解的最后一个功能是称为*Will*。

## 用 Will 说再见

我们探索的最后一个 MQTT 功能是称为 Will。客户端（发布者或订阅者）可以向代理注册一个特殊的*Will*消息，以便如果客户端死机并突然断开与代理的连接（例如，它失去了网络连接或其电池耗尽），代理将代表客户端发送*Will*消息，通知订阅者设备的消亡。

Will 只是一个消息和主题组合，类似于我们之前使用的。

让我们看看 Will 的作用，为此，我们将需要三个终端：

1.  打开一个终端，并使用以下命令启动一个订阅者：

```py
# Terminal #1 (Subscriber with Will)
$ mosquitto_sub -h localhost -t 'pyiot' --will-topic 'pyiot' --will-payload 'Good Bye' --will-qos 2 --will-retain
```

新的选项如下：

+   +   `--will-payload`：这是 Will 消息。

+   `--will-topic`：这是 Will 消息将要发布的主题。在这里，我们使用与我们订阅的相同主题，但也可以是不同的主题。

+   `--will-qos`：这是 Will 消息的 QoS。

+   `--will-retain`：如果存在此选项，那么如果客户端突然断开连接，Will 消息将被代理保留为 Will 主题的*保留（最后已知的良好）消息*。

1.  使用以下命令在第二个终端中启动一个订阅者：

```py
# Terminal #2 (Subscriber listening to Will topic).
$ mosquitto_sub -h localhost -t 'pyiot'
```

1.  在第三个终端中，使用以下命令发布一条消息：

```py
# Terminal #3 (Publisher)
$ mosquitto_pub -h localhost -t 'pyiot' -m 'hello'
```

1.  一旦在**终端#3**上执行*步骤 3*中的`mosquitto_pub`命令，您应该会在**终端#1**和**#2**上都看到`hello`被打印出来。

1.  在**终端#1**中，按下*Ctrl* + *C*来终止向代理注册 Will 的订阅者。*Ctrl* + *C*被视为与代理的非优雅或突然断开连接。

1.  在**终端#2**中，我们将看到遗嘱的“再见”消息：

```py
# Terminal #2 (Subscriber listening to Will topic).
$ mosquitto_sub -h localhost -t 'pyiot'
'Good Bye'
```

好的，那么优雅地断开连接呢，订阅者如何正确地关闭与代理的连接？我们可以使用`mosquitto_sub`的`-C`选项来演示这一点。

1.  使用以下命令重新启动**终端#1**中的订阅者：

```py
# Terminal #1 (Subscriber with Will)
$ mosquitto_sub -h localhost -t 'pyiot' --will-topic 'pyiot' --will-payload 'Good Bye, Again' --will-qos 2 --will-retain -C 2
```

新的`-C <count>`选项告诉`mosquitto_sub`在接收到指定数量的消息后断开（优雅地）并退出。

您会立即注意到打印的“再见”消息。这是因为我们之前在**终端#1**中指定了`--retain-will`选项。此选项使遗嘱消息成为主题的保留或最后已知的好消息，因此新连接的客户端将接收此消息。

1.  在**终端#3**中，发布一条新消息，**终端#1**中的订阅者将退出。请注意，在**终端#3**中，不会收到遗嘱消息“再见，再见”。这是因为我们的**终端#1**订阅者因为`-C`选项而优雅地与代理断开连接，并且如果您想知道`-C 2`中的`2`，则保留的遗嘱消息被计为第一条消息。

干得好！如果您已经完成了前面的每个 MQTT 示例，那么您已经涵盖了 MQTT 和 Mosquitto 代理的核心概念和用法。请记住，所有这些原则都适用于任何 MQTT 代理或客户端，因为 MQTT 是一个开放标准。

到目前为止，我们已经了解了消息订阅和发布，以及如何使用主题对消息进行分离，以及如何利用 QoS、消息保留、持久连接和遗嘱来控制消息的管理和传递。单单这些知识就为您提供了构建复杂和有弹性的分布式物联网系统的基础，使用 MQTT。

我将给您留下一个最后的提示（当我开始使用 MQTT 时，这个提示几次让我困惑）。

如果您的实时、保留或排队的持久连接消息似乎消失在黑洞中，请检查订阅和发布客户端的 QoS 级别。要监视所有消息，请启动一个命令行订阅者，使用 QoS 2，监听`#`主题，并启用详细和调试选项，例如`mosquitto_sub -q 2 -v -d -h localhost -t '#'`。

我们现在已经完成了 MQTT 示例部分的所有示例，并学会了如何从命令行与 MQTT 代理进行交互。接下来，我想简要提一下公共代理服务。之后，我们将进入代码，看看如何利用 Python 与 MQTT。

## 使用 MQTT 代理服务

互联网上有几家 MQTT 代理服务提供商，您可以使用它们创建基于 MQTT 的消息传递应用程序，如果您不想托管自己的 MQTT 代理。许多还提供免费的公共 MQTT 代理，供您用于测试和快速概念验证，但请记住它们是免费和公共的，因此不要发布任何敏感信息！

如果您在使用免费公共代理服务时遇到挫折、断开连接或意外行为，请使用本地代理测试和验证您的应用程序。您无法可靠地了解或验证开放公共代理的流量拥塞、主题使用或配置细节以及这可能如何影响您的应用程序。

以下是一些免费的公共代理，您可以尝试。只需将前面示例中的`-h`*localhost*选项替换为代理的地址。访问以下页面以获取更多信息和说明：

+   [`test.mosquitto.org`](https://test.mosquitto.org/)

+   [`broker.mqtt-dashboard.com`](http://broker.mqtt-dashboard.com/)

+   [`ot.eclipse.org/getting-started`](https://iot.eclipse.org/getting-started/#sandboxes)

在接下来的部分，我们将提升一个级别。最后，我们将进入 MQTT 的 Python 部分！请放心，我们刚刚讨论的一切在您开发使用 MQTT 的物联网应用程序时将非常宝贵，因为我们讨论的命令行工具和示例将成为您的 MQTT 开发和调试工具包的重要组成部分。我们将应用我们已经学到的核心 MQTT 概念，只是这次使用 Python 和 Paho-MQTT 客户端库。

# 介绍 Python Paho-MQTT 客户端库

在我们进入 Python 代码之前，我们首先需要一个 Python 的 MQTT 客户端库。在本章的*技术要求*部分开始时，我们安装了 Paho-MQTT 客户端库，它是`requirements.txt`的一部分。

如果您是 MQTT 的新手，并且还没有阅读前面的*通过示例学习 MQTT*部分，我建议现在停下来先阅读它，以便您对接下来的 Python 示例中将使用的 MQTT 概念和术语有所了解。

Paho-MQTT 客户端库来自 Eclipse 基金会，该基金会还维护 Mosquitto MQTT 代理。在*进一步阅读*部分，您将找到指向官方*Paho-MQTT 客户端库 API*文档的链接。在完成本章后，如果您希望加深对该库及其功能的理解，我建议阅读官方文档和其中的示例。

Python Paho-MQTT 库有三个核心模块：

+   **客户端**：这为您在 Python 应用程序中完全管理 MQTT 的生命周期。

+   **发布者**：这是一个用于消息发布的辅助模块。

+   **订阅者**：这是一个用于消息订阅的辅助模块。

客户端模块非常适合创建更复杂和长时间运行的物联网应用程序，而发布者和订阅者辅助模块适用于短暂的应用程序和不需要完全生命周期管理的情况。

以下 Python 示例将连接到我们之前在*安装 Mosquitto MQTT 代理*部分安装的本地 Mosquitto MQTT 代理。

我们将使用 Paho 客户端模块，以便我们可以创建一个更完整的 MQTT 示例。然而，一旦您能够理解并跟随客户端模块，使用辅助模块创建替代方案将变得轻而易举。

作为提醒，我们将使用我们在第二章*Python 和物联网入门*，*图 2.7*中创建的面包板电路。

现在我们对 Paho-MQTT 库有了基本的了解，接下来我们将简要回顾 Python 程序和配套的网页客户端的功能，并看到 Paho-MQTT 的实际应用。

# 使用 Python 和 MQTT 控制 LED

在*安装 Mosquitto MQTT 代理*部分中，我们通过访问`http://localhost:8083` URL 来测试安装，这给了我们一个带有滑块的网页。然而，当时我们无法改变 LED 的亮度。当您移动滑块时，网页会向 Mosquitto 代理发布 MQTT 消息，但没有程序接收消息来改变 LED 的亮度。

在本节中，我们将看到 Python 代码订阅名为`led`的主题并处理滑块生成的消息。我们将首先运行 Python 代码，并确保我们可以改变 LED 的亮度。

## 运行 LED MQTT 示例

您将在`chapter04/mqtt_led.py`文件中找到代码。在继续之前，请先查看此文件，以便对其内容有一个整体的了解，然后按照以下步骤操作：

1.  使用以下命令在终端中运行程序：

```py
# Terminal #1
(venv) $ python mqtt_led.py
INFO:main:Listening for messages on topic 'led'. Press Control + C to exit.
INFO:main:Connected to MQTT Broker
```

1.  现在，打开第二个终端窗口并尝试以下操作，LED 应该会亮起（请确保 JSON 字符串格式正确）：

```py
# Terminal #2
$ mosquitto_pub -q 2 -h localhost -t 'led' -r -m '{"level": "100"}'
```

1.  您是否注意到在*步骤 2*中使用了`-r`(`--retain`)选项？终止并重新启动`mqtt_led.py`，并观察**终端#1**中的日志输出和 LED。您应该注意到在启动时，`mqtt_led.py`从主题的*保留消息*接收 LED 的亮度值，并相应地初始化 LED 的亮度。

1.  接下来，访问`http://localhost:8083`的 URL，并确保 LED 在您移动滑块时改变亮度。

保持网页打开，并再次尝试*步骤 2*中的命令。观察滑块的变化——它将与您指定的新级别值保持同步。

1.  接下来，让我们看看持久连接是如何工作的。再次终止`mqtt_led.py`并执行以下操作：

+   在网页上，随机移动滑块大约 5 秒钟。当您移动滑块时，消息将被发布到`led`主题的代理中。当`mqtt_led.py`重新连接时，它们将被排队等待传递。

+   重新启动`mqtt_led.py`并观察终端和 LED。您会注意到终端上有大量的消息，并且 LED 会闪烁，因为排队的消息被`mqtt_led.py`接收和处理。

默认情况下，Mosquitto 配置为每个使用持久连接的客户端排队 100 条消息。客户端由其客户端 ID 标识，您在连接到代理时提供该 ID。

现在我们已经与`mqtt_led.py`进行了交互并看到它的运行情况，让我们来看看它的代码。

## 理解代码

当我们讨论在`chapter04/mqtt_led.py`中找到的代码时，特别注意代码如何连接到 MQTT 代理并管理连接生命周期。此外，当我们讨论代码如何接收和处理消息时，试着将代码工作流程与我们在上一小节中用于发布消息的命令行示例联系起来。

一旦您了解了我们的 Python 代码以及它如何与我们的 MQTT 代理集成，您将拥有一个端到端的工作参考解决方案，围绕 MQTT 消息构建，您可以根据自己的需求和项目进行调整。

我们将从导入开始。通常情况下，我们将跳过我们在之前章节中已经涵盖过的任何常见代码，包括日志设置和**GPIOZero**相关的代码。

### 导入

我们在这个例子中唯一新的导入是 Paho-MQTT 客户端：

```py
import paho.mqtt.client as mqtt  # (1)
```

在第 1 行，我们导入 Paho-MQTT `client`类，并给它起了别名`mqtt`。如前所述，这是一个客户端类，它将允许我们在 Python 中创建一个完整的生命周期 MQTT 客户端。

接下来，我们将考虑全局变量。

### 全局变量

在第 2 行的`BROKER_HOST`和`BROKER_POST`变量是指我们本地安装的 Mosquitto MQTT 代理。端口`1883`是标准默认的 MQTT 端口：

```py
# Global Variables ...  BROKER_HOST = "localhost"   # (2) BROKER_PORT = 1883 CLIENT_ID = "LEDClient" # (3) TOPIC = "led" # (4) client = None # MQTT client instance. See init_mqtt()   # (5) ...
```

在第 3 行，我们定义了`CLIENT_ID`，这将是我们用来标识我们的程序与 Mosquitto MQTT 代理连接的唯一客户端标识符。我们*必须*向代理提供一个唯一的 ID，以便我们可以使用*持久连接*。

在第 4 行，我们定义了我们的程序将订阅的 MQTT 主题，而在第 5 行，`client`变量是一个占位符，将被分配 Paho-MQTT 客户端实例，我们很快就会看到。

### set_led_level(data)方法

`set_led_level(data)`在第 6 行是我们与 GPIOZero 集成以改变 LED 亮度的地方，方法类似于我们在第三章中涵盖的相应方法，*使用 Flask 进行 RESTful API 和 Web 套接字的网络*，因此我们不会再次在这里涵盖内部情况：

```py
def set_led_level(data):  # (6)
   ...
```

数据参数预期是一个 Python 字典，格式为`{ "level": 50 }`，其中整数介于 0 和 100 之间，表示亮度百分比。

接下来，我们有 MQTT 的回调函数。我们将从审查`on_connect()`和`on_disconnect()`开始。

### on_connect()和 on_disconnect() MQTT 回调方法

`on_connect()`和`on_disconnect()`回调处理程序是使用 Paho `client`类提供的完整生命周期的示例。我们将在覆盖`init_mqtt()`方法时看到如何实例化 Paho `client`实例并注册这些回调。

在以下代码块的第 7 行，`on_connect()`感兴趣的参数是`client`，它是对 Paho `client`类的引用，以及`result_code`，它是描述连接结果的整数。我们在第 8 行看到`result_code`用于测试连接的成功。注意`connack_string()`方法，它用于连接失败时将`result_code`转换为可读的字符串。

当我们谈论 MQTT *client*并在以下代码块的第 7 行看到`client`参数时，请记住这是我们 Python 代码的客户端连接*到代理*，而不是指客户端程序，比如网页。这个客户端参数在意义上与我们在*第三章中为 Flask-SocketIO Web Socket 服务器使用回调处理程序时看到的客户端参数非常不同。

供参考，`user_data`参数可用于在 Paho 客户端的回调方法之间传递私有数据，而`flags`是一个包含 MQTT 代理的响应和配置提示的 Python 字典：

```py
def on_connect(client, user_data, flags, result_code): # (7)     if connection_result_code == 0:                    # (8)
  logger.info("Connected to MQTT Broker")
    else:
  logger.error("Failed to connect to MQTT Broker: " + 
                     mqtt.connack_string(result_code))

    client.subscribe(TOPIC, qos=2)                     # (9)
```

在第 9 行，我们看到 Paho `client`实例方法`subscribe()`，用于使用我们之前定义的全局变量`TOPIC`订阅`led`主题。我们还告诉代理我们的订阅是 QoS 级别 2。

总是在`on_connect()`处理程序中订阅主题。这样，如果客户端失去与代理的连接，它可以在重新连接时重新建立订阅。

接下来，在以下的第 10 行，我们有`on_disconnect()`处理程序，我们只是记录任何断开连接。方法参数的含义与`on_connect()`处理程序相同：

```py
def on_disconnect(client, user_data, result_code):  # (10)
    logger.error("Disconnected from MQTT Broker")
```

我们现在将转到处理我们在`on_connect()`中订阅的`led`主题的回调方法，位于第 9 行。

### on_message() MQTT 回调方法

在第 11 行的`on_message()`处理程序在我们的程序接收到订阅主题的新消息时被调用。消息通过`msg`参数可用，它是`MQTTMessage`的一个实例。

在第 12 行，我们访问`msg`的`payload`属性并将其解码为字符串。我们期望我们的数据是一个 JSON 字符串（例如，`{ "level": 100 }`），所以我们使用`json.loads()`将字符串解析为 Python 字典，并将结果赋给`data`。如果消息负载不是有效的 JSON，我们捕获异常并记录错误：

```py
def on_message(client, userdata, msg):                    # (11)   data = None  try:                                                  
  data = json.loads(msg.payload.decode("UTF-8"))    # (12)
    except json.JSONDecodeError as e:
        logger.error("JSON Decode Error: " 
                   + msg.payload.decode("UTF-8"))

    if msg.topic == TOPIC:                                # (13)   set_led_level(data)                               # (14)
    else:
        logger.error("Unhandled message topic {} 
                 with payload " + str(msg.topic, msg.payload)))
```

在第 13 行使用`msg`的`topic`属性，我们检查它是否与我们预期的`led`主题匹配，在我们的情况下，它会匹配，因为我们的程序只订阅这个特定的主题。然而，这提供了一个参考点，关于在订阅多个主题的程序中执行条件逻辑和路由的位置和方式。

最后，在第 14 行，我们将解析的消息传递给`set_led_level()`方法，正如讨论的那样，这会改变 LED 的亮度。

接下来，我们将学习如何创建和配置 Paho 客户端。

### init_mqtt()方法

我们在第 15 行看到 Paho-MQTT `client`实例被创建并分配给全局`client`变量。这个对象的引用是`client`参数，我们之前在`on_connect()`、`on_disconnect()`和`on_message()`方法中看到过。

`client_id`参数设置为我们之前在`CLIENT_ID`中定义的客户端名称，而`clean_session=False`告诉代理在连接时*不要清除*我们的客户端的任何存储消息。正如我们在命令行示例中讨论的那样，这是说我们希望建立持久连接，因此当我们的客户端离线时，发布到`led`主题的任何消息都会为我们的客户端存储。

```py
def init_mqtt():
    global client   client = mqtt.Client(                                       # (15)
  client_id=CLIENT_ID,
        clean_session=False)

    # Route Paho logging to Python logging.   client.enable_logger()                                      # (16)   # Setup callbacks  client.on_connect = on_connect                              # (17)
  client.on_disconnect = on_disconnect
    client.on_message = on_message

    # Connect to Broker.
  client.connect(BROKER_HOST, BROKER_PORT)                    # (18)
```

需要注意的一个重要点是在第 16 行。我们的程序使用标准的 Python 日志包，因此我们需要调用`client.enable_logger()`来确保我们获得任何 Paho-MQTT 客户端日志消息。如果缺少这个调用，可能会导致有用的诊断信息未被记录。

最后，在第 18 行，我们连接到 Mosquitto MQTT 代理。一旦连接建立，就会调用我们的`on_connect()`处理程序。

接下来，我们将看到我们的程序是如何启动的。

### 主入口点

在初始化 LED 和客户端实例之后，我们进入了程序的主入口点。

我们在第 19 行注册了一个信号处理程序，以捕获*Ctrl* + *C*组合键。`signal_handler`方法（未显示）简单地关闭我们的 LED 并从代理中优雅地断开连接：

```py
# Initialise Module init_led()
init_mqtt()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)    # (19)   logger.info("Listening for messages on topic '" 
       + TOPIC + "'. Press Control + C to exit.")

    client.loop_start()                             # (20)
  signal.pause()
```

在第 20 行，调用`client.loop_start()`是允许我们的客户端启动、连接到代理并接收消息的方法。

您是否注意到 LED 程序是无状态的？我们没有在代码或磁盘中存储或持久化任何 LED 级别。我们的程序所做的就是订阅代理上的一个主题，并使用 GPIOZero 改变 LED 的亮度。我们通过依赖 MQTT 的保留消息（也称为*最后已知的好消息*）功能，将所有状态管理交给了 MQTT 代理。

我们现在已经完成了与 LED 和 MQTT 代理互动的 Python 代码的探索。我们学会了如何使用 Python Paho-MQTT 库连接到 MQTT 代理并订阅 MQTT 主题。当我们收到订阅主题上的消息时，我们看到了如何处理它们，并根据消息负载改变 LED 的亮度级别。

我们介绍的 Python 和 Paho-MQTT 框架和示例将为您自己的基于 MQTT 的物联网项目提供一个坚实的起点。

接下来，我们将查看一个使用 MQTT 和 Web 套接字的 Web 客户端。这个 Web 客户端将连接到我们的 Mosquitto MQTT 代理并发布消息以控制我们的 LED。

# 构建基于 Web 的 MQTT 客户端

在第三章中，*使用 Flask 进行 RESTful API 和 Web 套接字网络*，我们介绍了一个使用 Web 套接字的代码示例，其中包括一个 HTML 文件和 JavaScript Web 客户端。在本节中，我们还将查看使用 HTML 和 JavaScript 构建的基于 Web 套接字的 Web 客户端。然而，这一次，我们将利用 Mosquitto MQTT 代理提供的内置 Web 套接字功能以及兼容的 JavaScript Paho-JavaScript Web 套接字库（您将在*进一步阅读*部分找到此库的链接）。

作为对比，在第三章中，*使用 Flask 进行 RESTful API 和 Web 套接字网络*，我们使用 Flask-SocketIO 在 Python 中自己创建了 Web 套接字服务器，而我们的 Web 客户端使用了 Socket.io JavaScript Web 套接字库。

我们之前与即将探索的 Web 客户端进行了互动，以控制我们的 LED，位于*安装 Mosquitto MQTT 代理*的第 7 步。您可能希望快速查看*第 7 步*，以重新熟悉 Web 客户端以及如何在 Web 浏览器中访问它。

您将在`chapter04/mosquitto_www/index.html`文件中找到 Web 页面客户端的代码。请在继续之前查看此文件。

## 理解代码

虽然我们在此示例中使用的 JavaScript 库不同，但您会发现 JavsScript 代码的一般结构和用法与我们在第三章中看到的基于`socket.io`的 Web 客户端的代码类似，*使用 Flask 进行 RESTful API 和 Web 套接字的网络*。像往常一样，我们将从导入开始。

### 导入

我们的 Web 客户端在第 1 行导入了 Paho-MQTT JavaScript 客户端库：

```py
<title>MQTT Web Socket Example</title>
<script src="./jquery.min.js"></script>
<script src="./paho-mqtt.js"></script> <!-- (1) --> 
```

`paho-mqtt.js`也可以在`chapter04/mosquitto_www`文件夹中找到。

Paho-MQTT JavaScript 库的官方文档页面位于[`www.eclipse.org/paho/clients/js`](https://www.eclipse.org/paho/clients/js)，而其官方 GitHub 页面位于[`github.com/eclipse/paho.mqtt.javascript`](https://github.com/eclipse/paho.mqtt.javascript)。

当您进一步探索 Paho-MQTT JavaScript API 时，请从其 GitHub 网站开始，并注意其中提到的任何重大更改。已知文档页面包含不反映最新 GitHub 代码库的代码片段。

接下来，我们遇到了全局变量。

### 全局变量

在第 2 行，我们初始化了一个`Client_ID`常量，用于标识我们的 JavaScript 客户端与代理的连接。

每个 Paho JavaScript MQTT 客户端*必须*在连接到代理时具有唯一的*主机名、端口*和*客户端 ID*组合。为了确保我们可以在单台计算机上运行多个网页进行测试和演示，我们使用随机数为每个网页创建一个准唯一的客户端 ID：

```py
<script type="text/javascript" charset="utf-8">
    messagePubCount = 0;
    const CLIENT_ID = String(Math.floor(Math.random() * 10e16)) // (2)
    const TOPIC   = "led";                                      // (3)
```

在第 3 行，我们使用`led`定义了`TOPIC`常量，这是我们将要订阅和发布的 MQTT 主题的名称。接下来，我们创建我们的客户端实例。

### Paho JavaScript MQTT 客户端

在第 4 行，我们创建了我们的 Paho-MQTT 客户端实例并将其分配给`client`变量。

`Paho.MQTT.Client()`的参数是代理的主机名和端口。我们通过 Mosquitto 提供此网页，因此代理的主机和端口将与网页相同：

```py
const client = new Paho.Client(location.hostname,        // (4)
                               Number(location.port),
                               CLIENT_ID); 
```

您可能已经注意到在`http://localhost:8083`的 URL 中，端口是`8083`，而在 Python 中我们使用的是端口`1883`：

+   端口`1883`是代理上的 MQTT 协议端口。我们的 Python 程序直接连接到代理的这个端口。

+   我们之前将端口`8083`配置为 Mosquitto 代理上的 Web 套接字端口。Web 页面可以使用 HTTP 和 Web 套接字协议，而不是 MQTT。

这提出了一个重要的观点。虽然我们在 JavaScript 代码的上下文中使用 MQTT 这个术语，但我们实际上是使用 Web 套接字来代理 MQTT 的想法与代理来回传递。

当我们谈到 MQTT *client*并在第 4 行创建了`client`实例时，请记住这是我们 JavaScript 代码的客户端连接*到代理*。

接下来，我们将看到如何连接到代理并注册`onConnect`处理程序函数。

### 连接到代理

我们在第 5 行定义了`onConnectionSuccess()`处理程序，这将在我们的`client`成功连接到代理后调用。当我们成功连接时，我们将更新网页以反映成功的连接并启用滑块控件：

```py
onConnectionSuccess = function(data) {         // (5)
    console.log("Connected to MQTT Broker");
    $("#connected").html("Yes");
    $("input[type=range].brightnessLevel")
          .attr("disabled", null);

    client.subscribe(TOPIC);                   // (6)
};

client.connect({                               // (7)
   onSuccess: onConnectionSuccess,
   reconnect: true
 });       
```

接下来，在第 6 行，我们订阅了`led`主题。在第 7 行，我们连接到了代理。请注意，我们将`onConnectionSuccess`函数注册为`onSuccess`选项。

请记住，与 Python 示例类似，总是订阅主题

`onSuccess`处理程序。这样，如果客户端失去与代理的连接，它可以在重新连接时重新建立订阅。

我们还指定了`reconnect: true`选项，这样我们的客户端在失去连接时将自动重新连接到代理。

已经观察到，JavaScript Paho-MQTT 客户端在失去连接后可能需要一分钟才能重新连接，所以请耐心等待。这与 Python Paho-MQTT 客户端形成对比，后者几乎可以立即重新连接。

接下来，我们有另外两个处理程序需要审查。

### onConnectionLost 和 onMessageArrived 处理程序方法

在以下代码中，第（8）行和（9）行，我们看到如何使用 Paho-MQTT 的`client`实例注册`onConnectionLost`和`onMessageArrived`处理程序：

```py
client.onConnectionLost = function onConnectionLost(data) {    // (8)
  ...
}

client.onMessageArrived = function onMessageArrived(message) { // (9)
   ...
}
```

这两个函数在原则上类似于之前第三章中 socket.io 示例中的相应函数，即它们基于它们各自的`data`和`message`参数中的数据更新滑块和网页文本。

接下来，我们有我们的文档准备函数。

### JQuery 文档准备函数

最后，在第（10）行，我们遇到了文档准备函数，其中我们初始化了我们的网页内容并注册了滑块的事件监听器：

```py
$(document).ready(function() {                                   // (10)
    $("#clientId").html(CLIENT_ID);

    // Event listener for Slider value changes.
    $("input[type=range].brightnessLevel").on('input', function() {
        level = $(this).val();

        payload = {
            "level": level
         };

        // Publish LED brightness.
        var message = new Paho.Message(                         // (11)
           JSON.stringify(payload)
        );

        message.destinationName = TOPIC;                        // (12)
        message.qos = 2;
        message.retained = true;                                // (13)
        client.send(message);
    });
});
```

在第（11）行的滑块事件处理程序中，我们看到了如何创建一个 MQTT 消息。请注意`JSON.stringify(payload)`的使用。`Paho.Message`构造函数期望一个`String`参数，而不是一个`Object`，因此我们必须将 payload 变量（它是一个`Object`）转换为字符串。

从第（12）行开始，我们将消息发布主题设置为`led`，并在标记其 QoS 级别为 2 之前，使用`message.destinationName = TOPIC`。

接下来，在第（13）行，通过`message.retained = true`，我们指示希望保留此消息，以便它会自动传递给订阅`led`主题的新客户端。保留此消息是使`mqtt_led.py`能够在重新启动时重新初始化 LED 的先前亮度。

干得好！我们现在已经涵盖了简单基于 MQTT 的应用程序的 Python 和 JavaScript 两方面。

# 总结

在这一章中，我们探讨并实践了 MQTT 的核心概念。在您的树莓派上安装和配置 Mosquitto MQTT 代理之后，我们直接开始学习了一系列命令行示例。我们学习了如何发布和订阅 MQTT 消息，如何理解主题构建和名称层次结构，以及如何将 QoS 级别附加到消息上。

我们还涵盖了 MQTT 代理提供的两种机制，即持久连接和保留消息，用于存储消息以供以后传递。我们通过探索一种称为*Will*的特殊消息和主题类型来结束了我们对 MQTT 概念的讲解，其中客户端可以向代理注册一条消息，在客户端突然失去连接时自动发布到主题。

接下来，我们回顾并讲解了一个使用 Paho Python MQTT 库订阅 MQTT 主题并根据接收到的消息控制 LED 亮度的 Python 程序。然后我们讲解了一个使用 Paho JavaScript MQTT 库构建的网页，该网页发布了 Python 程序消费的消息。

您现在已经掌握了 MQTT 的工作知识，并且有一个可以用于自己的物联网应用的实用代码框架。这是我们在之前章节中探讨过的其他网络方法和代码框架的补充，例如 dweet.io 服务、Flask-RESTful 和 Flask-SocketIO。您用于项目的方法取决于您要创建什么，当然还取决于您个人的偏好。对于较大的项目和需要与外部系统集成的项目，您可能需要同时利用多种方法，甚至需要研究和探索其他技术。我毫不怀疑，到目前为止我们所涵盖的其他网络方法的学习和理解将对您理解遇到的其他方法有所帮助。

在下一章《将 Python 连接到物理世界》中，我们将探讨一系列与将树莓派连接到世界的主题相关的话题。我们将介绍流行的 Python GPIO 库选项，以及 GPIOZero 和 PiGPIO，并研究与树莓派一起使用的不同类型的电子接口选项和配置。我们还有一个全面的练习，我们将向您的树莓派添加一个模数转换器，并使用它创建一个程序来探索 PWM 技术和概念。

# 问题

最后，这里有一些问题供您测试对本章材料的了解。您将在书的*评估*部分找到答案：

1.  什么是 MQTT？

1.  您保留的 MQTT 消息从未被传递。您应该检查什么？

1.  在什么条件下，MQTT 代理会发布*遗嘱*消息？

1.  您选择使用 MQTT 作为物联网应用程序的消息传递层，并且必须确保消息被发送和接收。所需的最低 QoS 级别是多少？

1.  您使用 MQTT 开发了一个应用程序，并使用 Mosquitto 代理，但现在您需要使用不同的代理。这对您的代码库和部署配置意味着什么？

1.  在代码中的哪个位置（提示：哪个处理程序方法）应该订阅 MQTT 主题，以及为什么？

# 进一步阅读

在本章中，我们从操作层面介绍了 MQTT 的基础知识。如果您想从协议和数据层面了解更多关于 MQTT 的知识，HiveMQ（一个 MQTT 代理和服务提供商）在[`www.hivemq.com/blog/mqtt-essentials-part-1-introducing-mqtt`](https://www.hivemq.com/blog/mqtt-essentials-part-1-introducing-mqtt/)上提供了一系列关于 MQTT 协议的精彩 11 部分系列文章。

Mosquitto MQTT 代理和客户端工具的主页位于以下 URL：

+   Mosquitto MQTT 代理：[`mosquitto.org`](https://mosquitto.org)

我们在本章中使用的 Paho-MQTT 库的文档和 API 参考资料可在以下 URL 找到：

+   Paho-MQTT Python 库：[`www.eclipse.org/paho/clients/python`](https://www.eclipse.org/paho/clients/python/)

+   Paho-MQTT JavaScript 库：[`www.eclipse.org/paho/clients/js`](https://www.eclipse.org/paho/clients/js)

除了 MQTT，HTTP RESTful API 和 Web Sockets 之外，还有一些专为受限设备设计的补充通信协议，称为 CoRA 和 MQTT-NS。 Eclipse Foundation 在[`www.eclipse.org/community/eclipse_newsletter/2014/february/article2.php`](https://www.eclipse.org/community/eclipse_newsletter/2014/february/article2.php)上提供了这些协议的摘要。


# 第二部分：与物理世界互动的实用电子学

在本节中，我们将探讨与使用树莓派的*P1 引脚*连接物理世界的相关概念，这是主板上的一组大引脚，我们通常称之为*GPIO 引脚*。 

本质上，这一部分是软件世界和电子世界之间的桥梁。我们的目标是涵盖您需要了解的核心术语和实际概念，以便开始与简单和复杂的电子设备进行接口。到本节结束时，您将具备进一步探索和研究将电子设备与树莓派接口的挑战的知识，并能够根据您的用例和兴趣进行明智决策并进行有针对性的研究。

本节包括以下章节：

+   第五章，*将您的树莓派连接到物理世界*

+   第六章，*软件工程师的电子学 101*


# 第五章：将您的 Raspberry Pi 连接到物理世界

在本章中，我们将探讨与将您的 Raspberry Pi 连接到物理世界相关的硬件和软件概念。我们将介绍由 GPIO 库使用的流行编号方案，以引用您的 Raspberry Pi 上的 GPIO 引脚，并概述流行的 GPIO 库，除了我们在之前章节中使用的 GPIOZero 和 PiGPIO 库。正如我们将会了解的那样，理解 GPIO 编号方案对于确保您理解 GPIO 库如何与 GPIO 引脚一起工作至关重要。

在我们完成对 Raspberry Pi 的许多不同方式进行电子接口的概念概述和讨论之前，我们的旅程还将包括对两个重要的电子概念-**脉宽调制**（**PWM**）和模数转换的详细练习和实际演示。

我们将在本章中涵盖以下主题：

+   理解 Raspberry Pi 引脚编号

+   探索流行的 Python GPIO 库

+   探索 Raspberry Pi 的电子接口选项

+   与模数转换器进行接口

# 技术要求

要执行本章的练习，您需要以下物品：

+   Raspberry Pi 4 Model B

+   Raspbian OS Buster（带桌面和推荐软件）

+   至少 Python 版本 3.5

这些要求是本书中代码示例的基础。可以合理地期望，只要您的 Python 版本是 3.5 或更高，代码示例应该可以在 Raspberry Pi 3 Model B 或 Raspbian OS 的不同版本上无需修改即可运行。

您可以在 GitHub 存储库的以下 URL 中的`chapter05`文件夹中找到本章的源代码：[`github.com/PacktPublishing/Practical-Python-Programming-for-IoT`](https://github.com/PacktPublishing/Practical-Python-Programming-for-IoT)

您需要在终端中执行以下命令来设置虚拟环境并安装本章代码所需的 Python 库：

```py
$ cd chapter05              # Change into this chapter's folder
$ python3 -m venv venv      # Create Python Virtual Environment
$ source venv/bin/activate  # Activate Python Virtual Environment
(venv) $ pip install pip --upgrade        # Upgrade pip
(venv) $ pip install -r requirements.txt  # Install dependent packages
```

以下依赖项是从`requirements.txt`中安装的：

+   **GPIOZero**：GPIOZero GPIO 库（[`pypi.org/project/gpiozero`](https://pypi.org/project/gpiozero)）

+   **PiGPIO**：PiGPIO GPIO 库（[`pypi.org/project/pigpio`](https://pypi.org/project/pigpio)）

+   **RPi.GPIO**：RPi.GPIO 库（[`sourceforge.net/p/raspberry-gpio-python/wiki/Home`](https://sourceforge.net/p/raspberry-gpio-python/wiki/Home)）

+   **ADS1X15**：ADS11x5 ADC 库（[`pypi.org/project/adafruit-circuitpython-ads1x15`](https://pypi.org/project/adafruit-circuitpython-ads1x15)）

除了前述的安装，我们在本章的练习中还需要一些物理电子组件：

+   1 x 5 mm 红色 LED

+   1 x 200 Ω电阻器-其色带将是红色，黑色，棕色，然后是金色或银色

+   1 x ADS1115 ADC 拆分模块（例如，[`www.adafruit.com/product/1085`](https://www.adafruit.com/product/1085)）

+   2 x 10 kΩ电位器（范围在 10K 到 100K 之间的任何值都适用）

+   一个面包板

+   母对母和母对公跳线（也称为杜邦线）

# 理解 Raspberry Pi 引脚编号

到目前为止，您可能已经注意到您的 Raspberry Pi 上有很多引脚突出！自第二章 *使用 Python 和物联网入门*以及所有后续章节中，我们已经通过引用它们来引用这些引脚，例如*GPIO 引脚 23*，但这是什么意思？是时候我们更详细地了解这一点了。

有三种常见的方式可以引用 Raspberry Pi 的 GPIO 引脚，如*图 5.1*所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/012865d7-2318-4b7a-b5af-2f3b06f7e29a.png)

图 5.1 - GPIO 引脚编号方案

在之前的所有章节中，我们一直从 PiGPIO 的角度讨论 GPIO 引脚，它使用**Broadcom**或**BCM**编号方案。BCM 是 Python GPIO 库中最常用的方案，我们将很快讨论的 GPIO 库都专门或默认使用 BCM。然而，了解其他方案的存在是有用的，因为它将有助于阅读或调试您在互联网和其他资源上遇到的代码片段。

GPIO 和引脚这两个术语在识别引脚时可能会被宽泛使用。您需要解释诸如*GPIO 23*或*引脚 23*之类的用语，考虑到它所使用的上下文和方案。

让我们探索这些替代方案，如*图 5.1*所示：

+   **Broadcom/BCM 编号**：这指的是树莓派中 Broadcom 芯片的 GPIO 编号。使用 BCM 编号时，当我们说*GPIO 23*时，我们指的是在 BCM 引脚图中标记为*GPIO 23*。这是我们在本书中使用的方案，用于 GPIOZero 和 PiGPIO 示例。

+   **物理/板/P1 标头**：在这种编号方案中，使用 P1 标头的物理引脚编号，例如，BCM GPIO 23 = 物理引脚 16。

+   **WiringPi**：这是一个名为 WiringPi 的流行的 C GPIO 库，引入了自己的引脚映射方案。由于 WiringPi 的成熟度（有一个 Python 端口），您会不时遇到这个方案——继续我们的例子，BCM GPIO 23 = 物理引脚 16 = WiringPi 引脚 4。

还有其他用于引用引脚和接口的方法和命名，需要注意的包括以下内容：

+   **虚拟文件系统**：在`/sys`上挂载了一个虚拟文件系统，用于一般 GPIO 访问，`/dev/*i2c`用于 I2C，`/dev/*spi*`用于 SPI，`/sys/bus/w1/devices/*`用于 1-wire 设备。

+   **替代引脚功能**：*图 5.1*中的前面的 BCM 图表列出了 GPIO 引脚编号，以及括号中的 PWM0、I2C0 和 SPI0 等替代引脚功能。这些代表了引脚可以执行的基本数字 I/O 之外的替代角色。

+   **总线/通道编号**：对于 SPI 和 I2C 接口以及硬件 PWM，库通常会使用总线或通道编号。例如，我们可以使用 BCM GPIO 18 作为通用数字输入和输出，或者我们可以在其备用功能模式下将其用作 PWM 通道 0 的硬件 PWM 输出。

[pinout.xyz](https://pinout.xyz)网站是一个探索引脚命名、替代功能和方案映射的好资源。

现在您已经了解了在树莓派上引用 GPIO 引脚可以使用的不同方案。虽然 BCM 方案往往是基于 Python 的 GPIO 库中最常见和通用的方案，但绝对不能假设一个 GPIO 库、代码示例，甚至是您正在使用的面包板布局或原理图图使用 BCM 方案来引用 GPIO 引脚。代码中使用的方案与用于将电子设备连接到树莓派的 GPIO 引脚的方案之间的不匹配是导致电路无法工作的常见错误。

我经常看到人们（我自己也这样做过！）在他们的电路与他们在网上找到的代码示例不匹配时，责怪他们的接线或认为电子元件必须是有故障的。作为诊断的第一步，请检查代码使用的引脚编号方案是否与您用来连接树莓派的 GPIO 引脚的方案相匹配。

现在我们了解了不同 GPIO 编号方案的使用和重要性，让我们继续并审查流行的 Python GPIO 库。

# 探索流行的 Python GPIO 库

如果你和我一样，当你第一次开始使用树莓派时，你可能只是想控制*东西*。如今，对于许多开发人员来说，使用树莓派进行物理计算的第一步将是通过官方树莓派网站和 GPIOZero 库。然而，当你玩弄按钮、LED 和电机等简单电子设备一段时间后，你可能会想要进行更复杂的接口。如果你已经迈出了这一步，或者即将迈出这一步，你可能会发现自己处于 GPIO 库和选项的令人困惑的世界。本节旨在通过介绍更受欢迎的选项来帮助你在这条道路上导航。

我在[`10xiot.com/gpio-comp-table`](https://10xiot.com/gpio-comp-table)上维护了一个 Python GPIO 库的摘要和比较表（包括以下部分未列出的其他库）。

我们将从 GPIOZero 开始对 GPIO 库进行概述。

## 审查 GPIOZero-初学者的简单接口

GPIOZero 库的重点是简单性，使其成为初学者进入物理计算和接口电子设备的无忧库。它通过抽象化底层技术复杂性来实现易用性，并允许您编写处理*设备*和*外围设备*（如 LED、按钮和常见传感器）的代码，而不是编写直接管理引脚的低级别代码。

从技术上讲，GPIOZero 实际上并不是一个完整的 GPIO 库，它是围绕其他用于执行实际 GPIO grunt 工作的 GPIO 库的简化包装器。在第二章中，*使用 Python 和 IoT 入门*，我们看到了在 GPIOZero 和 PiGPIO 中的一个按钮和 LED 示例，说明了这一点。

以下是 GPIOZero 的主要亮点：

+   **描述**：为初学者设计的高级 GPIO 库

+   **优点**：易于学习和使用，具有出色的文档和许多示例

+   **缺点**：在简单的电子接口之外的用途上有限

+   **网站**：[`gpiozero.readthedocs.io`](https://gpiozero.readthedocs.io/)

接下来，我们将审查 RPi.GPIO，一个流行的低级 GPIO 库。

## 审查 RPi.GPIO-初学者的低级 GPIO

我们之前提到，GPIOZero 的本质是编写处理设备和组件的代码。而 RPi.GPIO 采用了一种不同且更经典的方法，我们编写的代码直接与 GPIO 引脚进行交互和管理。RPi.GPIO 是树莓派和电子学的流行低级介绍，因此您会发现许多使用它的示例在互联网上。

GPIOZero 文档中有一个关于 RPi.GPIO 的很好的部分，其中它解释了在 GPIOZero 和 RPi.GPIO 中等效的代码示例。这是一个很好的资源，可以开始学习更低级别的引脚级编程概念。

还有一个名为 RPIO 的库，它被创建为 RPi.GPIO 的性能替代品。RPIO 目前没有维护，并且不适用于树莓派 3 或 4 型号。

以下是 RPI.GPIO 的主要亮点：

+   **描述**：轻量级低级 GPIO

+   **优点**：成熟的库，在互联网上可以找到许多代码示例

+   **缺点**：轻量级意味着它不是面向性能的库，没有硬件辅助的 PWM

+   **网站**：[`pypi.python.org/pypi/RPi.GPIO`](https://pypi.python.org/pypi/RPi.GPIO)

接下来，我们将看一看另一个用于控制复杂设备的高级库。

## 审查 Circuit Python 和 Blinka-用于复杂设备的接口

Blinka 是 Circuit Python（[circuitpython.org](http://circuitpython.org/)）的 Python 兼容层，这是专为微控制器设计的 Python 版本。它由电子公司 Adafruit 创建和支持，该公司分发许多电子扩展板和小工具。Adafruit 为其许多产品系列提供高质量的 Circuit Python 驱动程序，基本上延续了 GPIOZero 易用性的理念，适用于更复杂的设备。

在本章的后面，我们将使用 Blinka 和 Circuit Python 驱动程序库来为我们的 Raspberry Pi 添加模拟到数字功能，以使用 ADS1115 ADC 扩展模块。

以下是 Blinka 的主要亮点：

+   **摘要**：用于控制复杂设备的高级库

+   **优点**：无论您的经验水平如何，都可以轻松使用支持的设备

+   **缺点**：对于基本 IO，它使用 RPi.GPIO，因此具有相同的基本限制

+   **网站**：[`pypi.org/project/Adafruit-Blinka`](https://pypi.org/project/Adafruit-Blinka/)

接下来，我们将介绍 Pi.GPIO，一个功能强大的低级 GPIO 库。

## 回顾 PiGPIO - 低级 GPIO 库

在功能和性能方面，PiGPIO 被认为是树莓派最完整的 GPIO 库选项之一。其核心是用 C 实现的，并且有一个官方的 Python 端口可用。

从架构上讲，PiGPIO 由两部分组成：

+   **pigpiod 守护程序服务**提供对底层 PiGPIO C 库的套接字和管道访问。

+   **PiGPIO 客户端库**使用套接字或管道与 pigpiod 服务进行交互。正是这种设计使得 PiGPIO 可以通过网络实现远程 GPIO 功能。

以下是 PiGPIO 的主要亮点：

+   **描述**：高级低级 GPIO 库

+   **优点**：提供了许多功能

+   **缺点**：需要额外的设置；简单的文档假设了对底层概念的了解

+   **网站（Python 端口）**：[`abyz.me.uk/rpi/pigpio/python.html`](http://abyz.me.uk/rpi/pigpio/python.html)

在我们继续下一个库之前，我想提醒您一个这个库独有且非常有用的功能 - 远程 GPIO。

### 使用 PiGPIO（和 GPIOZero）探索远程 GPIO

一旦您在树莓派上启动了 pigpiod 服务（在*第一章 设置您的开发环境*中介绍），有两种方法可以使您的代码远程运行，通过远程，我的意思是您的程序代码可以在任何计算机上运行（不仅仅是树莓派），并控制远程树莓派的 GPIO。

**方法 1**：此方法涉及将远程树莓派的 IP 或主机地址传递给 PiGPIO 构造函数。使用这种方法，您还可以通过创建额外的`pigpio.pi()`实例来与多个树莓派 GPIO 进行接口。例如，在以下示例中，对`pi`实例调用的任何方法将在运行 pigpiod 服务的`192.168.0.4`主机上执行：

```py
# Python Code.
pi = pigpio.pi('192.168.0.4', 8888) # Remote host and port (8888 is default if omitted)
```

**方法 2**：第二种方法涉及在计算机上设置环境变量并运行您的 Python 代码（您的 Python 代码只需要使用默认的 PiGPIO 构造函数，`pi = pigpio.pi()`）：

```py
# In Terminal
(venv) $ PIGPIO_ADDR="192.168.0.4" PIGPIO_PORT=8888 python my_script.py
```

远程 GPIO 可以成为一个很好的开发辅助工具，但会增加代码与 GPIO 引脚交互的延迟，因为数据通过网络传输。这意味着它可能不适用于非开发版本。例如，按钮按下可能感觉不够灵敏，对于需要快速定时的用例，远程 GPIO 可能不切实际。

您可能还记得第二章 *使用 Python 和物联网入门*中提到，GPIOZero 可以使用 PiGPIO *引脚工厂*，当这样做时，GPIOZero 自动获得免费的远程 GPIO 功能！

最后，因为这是 PiGPIO 库的一个独特特性，如果我们想要远程 GPIO 功能，所有的代码都必须使用这个库。如果你安装第三方 Python 库来驱动一个电子设备，并且它使用（例如）RPi.GPIO，这个设备就不支持远程 GPIO。

接下来，我们将看一下两个常见的用于 I2C 和 SPI 通信的低级库。

## 审查 SPIDev 和 SMBus - 专用的 SPI 和 I2C 库

当使用 I2C 和 SPI 设备时，你将会遇到 SPIDev 和 SMBus 库（或类似的替代品）。SPIDev 是一个用于 SPI 通信的流行的低级 Python 库，而 SMBus2 是一个用于 I2C 和 SMBus 通信的流行的低级 Python 库。这两个库不是通用库，不能用于基本的数字 IO 引脚控制。

当开始时，你不太可能直接使用这些 I2C 或 SPI 库。相反，你将使用更高级的 Python 库来处理 SPI 或 I2C 设备，而这些库在底层会使用这些低级库来与物理设备进行通信。

以下是 SPIDev 和 SMBus2 的主要亮点：

+   **描述**：这些是用于 SPI 和 I2C 接口的低级库。

+   **优点**：使用低级库可以完全控制 SPI 或 I2C 设备。许多高级便利包只暴露最常用的功能。

+   **缺点**：利用这些低级库需要你解释和理解如何使用低级数据协议和位操作技术与电子设备进行接口。

+   **SPIDev 网站**：[`pypi.org/project/spidev`](https://pypi.org/project/spidev/)

+   **SMBus2 网站**：[`pypi.org/project/smbus2`](https://pypi.org/project/smbus2/)

为了完成关于 GPIO 库的部分，让我简要讨论一下为什么这本书主要基于 PiGPIO 库。

## 为什么 PiGPIO？

你可能会想知道，为什么在所有的选择中，我选择在这本书中主要使用 PiGPIO。作为这本书的读者，我假设你在编程和技术概念方面有很好的基础，并且使用和学习 PiGPIO 这样的库不会超出你的能力范围。如果你打算在 Python 中构建更复杂的物联网项目，并超越 GPIOZero 和 RPi.GPIO 提供的基础知识，PiGPIO 是一个全面的库。

你会发现 PiGPIO 的 API 和文档被分为初学者、中级和高级部分，因此在实践和学习过程中，你可以根据自己的经验水平和需求混合使用库的 API。

我们已经完成了对几种流行的 GPIO 库的探索，并审查了它们的基本架构和设计。接下来，我们将把注意力转向通过其他方法连接和控制树莓派上的电子设备。

# 探索树莓派的电子接口选项

我们刚刚涵盖了 GPIO 的软件部分，现在我们将把注意力转向电子方面。树莓派提供了许多标准的接口方式，可以连接简单和复杂的电子设备。通常，你的电子元件和模块的选择将决定你需要使用哪种接口技术，有时你可能会有选择的余地。

无论你是否有选择，你对不同选项的了解将帮助你理解电路及其相应代码背后的原因，并帮助你诊断和解决可能遇到的任何问题。

在接下来的部分中，我们将探索概念，然后进行实际练习。我们将从数字 IO 开始。

## 理解数字 IO

树莓派的每个 GPIO 引脚都可以执行数字输入和输出。数字简单地意味着某物要么完全开启，要么完全关闭——没有中间状态。在之前的章节中，我们一直在处理简单的数字 IO：

+   我们的 LED 要么是开启的，要么是关闭的。

+   我们的按钮要么被按下（开启），要么未被按下（关闭）。

您将遇到几个可互换使用的术语来描述数字状态，包括以下内容：

+   开 = 高 = 真 = 1

+   关闭 = 低 = 假 = 0

数字 IO 是一种基本 IO 形式。模拟 IO 是另一种，因此我们将在下面探讨它。

## 理解模拟 IO

而数字处理完全开启和关闭状态，模拟处理程度——开启、关闭或介于两者之间。想象一下你家里的窗户。在数字世界中，它可以完全打开（数字高）或完全关闭（数字低）；然而，在现实中，它是模拟的，我们可以将其打开到完全关闭和完全打开之间的某个位置，例如，打开四分之一。

模拟电子元件的简单和常见示例包括以下内容：

+   **电位器（也称为旋钮）**：这是一个产生一系列电阻值的旋钮或滑块。现实世界的例子包括音量控制和加热器恒温控制。

+   **光敏电阻（LDR）**：这些是用于测量光照水平的电子元件，您会在自动夜灯中找到它们。

+   **热敏电阻**：这些是用于测量温度的电子元件，您可能会在加热器、冰箱或任何需要测量温度的地方找到它们。

树莓派没有模拟 IO 功能，因此我们需要使用外部电子设备，称为**模数转换器**（**ADC**）来读取模拟输入，这将是本章后面一个实际示例的核心重点，标题为*与模数转换器进行接口*。

要输出模拟信号，我们有两个选择——要么使用**数模转换器**（**DAC**），要么使用称为 PWM 的数字技术从数字输出产生类似模拟的信号。我们不会在本书中涵盖 DAC，但是我们将深入探讨 PWM，接下来我们将进行。

## 理解**脉宽调制**

**脉宽调制**或**PWM**是一种通过快速脉冲引脚的开和关来产生介于完全开启（高电平）和完全关闭（低电平）之间的平均电压的技术。通过这种方式，它有点像从数字引脚提供伪模拟输出，并且用于各种控制应用，例如改变 LED 的亮度、电机速度控制和舵机角度控制。

PWM 由两个主要特征定义：

+   **占空比**：引脚高电平的时间百分比

+   **频率**：占空比重复的时间周期

如*图 5.2*所示（对于固定频率），50%的占空比意味着引脚高电平占一半时间，低电平占一半时间，而 25%的占空比意味着引脚只有 25%的时间是高电平。虽然没有画出来，0%的占空比意味着引脚高电平占 0%的时间（始终低电平），因此实际上是关闭的，而 100%的占空比则始终是高电平：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/ab7ce801-b7f3-4099-b5e8-8c760b93da32.png)

图 5.2 - PWM 占空比上述图表摘自[`en.wikipedia.org/wiki/File:Duty_Cycle_Examples.png`](https://en.wikipedia.org/wiki/File:Duty_Cycle_Examples.png)，作者为 Thewrightstuff。它属于 CC BY-SA 4.0：[`creativecommons.org/licenses/by-sa/4.0/deed.en`](https://creativecommons.org/licenses/by-sa/4.0/deed.en)。

在树莓派上使用 PWM 很容易，尽管有其他方法可以创建 PWM 信号，我们将在下面看到。

### 创建 PWM 信号

不同的 GPIO 库以不同的方式生成 PWM 信号。三种常见的技术如下：

+   **软件 PWM**：PWM 信号的频率和占空比定时由代码生成，并且可以在任何 GPIO 引脚上使用。这是创建 PWM 信号的最不准确的方法，因为定时可能会受到繁忙的树莓派 CPU 的不利影响。

+   **硬件定时 PWM**：使用 DMA 和 PWM/PCM 硬件外设进行 PWM 定时。它非常精确，并且适用于任何 GPIO 引脚。

+   **硬件 PWM**：硬件 PWM 完全通过硬件提供，并且是创建 PWM 信号的最准确的方法。树莓派有两个专用的硬件 PWM 通道，通过 GPIO 引脚 18 和 12 标记为 PWM0，通过 GPIO 引脚 13 和 19 标记为 PWM1（参见*图 5.1*）。

仅仅连接到 GPIO 12、13、18 或 19 并不能获得硬件 PWM。这些 GPIO 是 BCM GPIO，其*替代*功能列出了 PWM。如果要使用硬件 PWM，必须满足两个基本要求。首先，您使用的 GPIO 库必须支持硬件 PWM。其次，您必须正确使用库及其硬件 PWM 功能，这将在库的 API 文档中详细说明。共享相同硬件 PWM 通道的引脚将获得相同的占空比和频率，因此虽然有四个硬件 PWM 引脚，但只有两个唯一的 PWM 信号。

要使用哪种 PWM 技术将始终取决于您要构建的内容以及 PWM 信号需要多精确。有时，您将直接控制您的项目使用的 GPIO 库（因此 PWM 技术），而其他时候——特别是在使用第三方更高级的 Python 库时——您将被迫使用库开发人员使用的任何 PWM 技术。

一般规则是，当我控制 GPIO 库选择时，尽可能避免使用软件 PWM。如果我使用 PiGPIO 进行开发，那么我更倾向于使用硬件定时 PWM，因为我可以在任何 GPIO 引脚上使用它。

关于我们之前介绍的 GPIO 库，它们对 PWM 的支持如下：

+   **GPIOZero**：继承自其引脚工厂实现的 PWM 方法

+   **RPi.GPIO**：仅支持软件 PWM

+   **PiGPIO**：硬件定时 PWM 和硬件 PWM

+   **Blinka**：仅支持硬件 PWM

您可以连接外部硬件 PWM 模块到您的树莓派（通常通过 I2C），这将给您更多的硬件 PWM 输出。

现在我们已经看到了 PWM 信号可以被创建的三种方式，接下来我们将看 SPI、I2C 和 1-wire 接口。

## 理解 SPI、I2C 和 1-wire 接口

**串行外围接口电路**（**SPI**）、**I2C**和 1-wire 是标准化的通信接口和协议，允许非平凡的电子设备进行通信。这些协议可以直接通过一些操作和数学运算来使用，也可以通过使用更高级的 Python 驱动程序模块间接地与电子外围设备一起工作，后者对于一般用途更为常见。

通过这些协议工作的设备的示例包括以下内容：

+   模数转换器（SPI 或 I2C）

+   LED 灯带和 LCD 显示器（SPI 或 I2C）

+   环境传感器，如温度传感器（1-wire）

本章稍后我们将更详细地探讨 I2C，当我们连接模数转换器到树莓派时。

最后，我们有串行通信和 UART。

## 理解串行/UART 协议

**通用异步收发器**（**UART**）是一种已经存在很长时间并且在 USB 普及之前广泛使用的串行通信协议。UART 实际上是指用于实现串行协议的电子硬件，尽管它也可以在纯软件中实现。

今天，SPI 或 I2C 往往优先于 UART。GPS 接收器是串行通信仍然普遍存在的一个常见例子。如果您曾经将 Arduino 连接到 PC 进行烧录或调试，那么设备使用的是串行通信协议，Arduino 中存在 UART 硬件。

我们现在已经学会了许多标准的方法，可以用来将电子设备与树莓派进行接口连接，包括模拟和数字电子、PWM、I2C 和 SPI 等线路协议以及串行通信。随着我们在本书中的继续，我们将开始看到许多这些接口选项的实际应用，并了解哪种类型的接口适用于哪种类型的电子设备。

接下来，我们将通过向树莓派添加模数转换器来看一下本章我们已经涵盖的一些概念。

# 与模数转换器进行接口连接

恭喜您走到了这一步。我猜想您在阅读了这么多之后迫不及待地想要开始编写一些代码了！

现在我们将改变步调，并应用我们刚刚学到的知识，向您的树莓派添加一个 ADS1115 模数转换器。一个典型的 ADS1115 分立模块的示例如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/20b42eaa-eff1-41af-88a7-f50d944fa1a6.png)

图 5.3 - ADS1115 分立模块

ADC 是一个非常方便的附加功能，因为这样就可以让您接触到模拟元件和设备的世界，否则这些设备是无法与树莓派一起使用的。

作为这个实际练习的一部分，我们将连接两个电位器（也称为电位器）到 ADS1115，并在 Python 中读取它们的值。我们将使用这些值来通过改变其占空比和频率来创建 PWM 信号。我们将通过观察它如何影响 LED 以及波形在一个名为 PiScope 的程序中如何变化来看到改变这些参数的效果，这是 PiGPIO 系列实用程序的一部分。

我们将在第六章 *软件工程师的电子学 101*中更详细地讨论电位器。

为了进行以下练习，请记住我们需要本章开头列出的电子元件，包括 ADS1115 分立模块。ADS1115 是一种常见且功能强大的模数转换器，它使用 I2C 连接到其主设备（在我们的案例中是树莓派）。

以下是我们从其数据表中提取的 ADS1115 的核心规格，这些规格是我们练习所需的：

+   **工作电压**：2 至 5 伏特（所以我们知道它将与树莓派的 3.3 伏逻辑兼容）

+   **接口**：I2C

+   **默认 I2C 地址**：0x48

ADS1115 上的端子如下：

+   **Vcc & GND**：设备的电源。

+   **SCL**：时钟信号，用于同步主从之间的通信。

+   **SDA**：数据信号，用于在树莓派和 ADS1115 之间发送数据。

+   **ADDR**：如果需要，此端子可用于更改默认地址。

+   **ALTR**：高级用途的警报信号（我们不需要这个）。

+   **A0** - **A3**：模拟输入通道（我们将把电位器连接到 A0 和 A1）。

在继续之前，请确保您的树莓派上已启用 I2C 接口。我们在第一章 *设置您的开发环境*中介绍了启用接口（包括 I2C）的步骤。

首先，让我们从在面包板上构建我们需要的电路开始。

## 构建 ADS1115 ADC 电路

让我们为本章的练习建立我们的面包板电路。我们将分步构建我们的电路，首先放置核心元件，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/815f2ede-d682-4275-8433-f9546e74b8f7.png)

图 5.4 - 面包板 ADC 电路（3 部分之一）面包板上离散元件和导线的整体布置和放置并不是特别重要。然而，元件和导线之间创建的连接非常重要！如果您需要关于面包板、它们的工作原理以及最重要的是孔如何电气连接的复习，请参阅第二章 *Python 和物联网入门*。

以下是如何在面包板上布置组件的方法。以下步骤编号与*图 5.4*中编号的黑色圆圈相匹配：

1.  将 ADS1115 放在面包板上。

1.  将电位器 VR1 放在面包板上。所示的电位器是全尺寸电位器。如果您有不同尺寸的电位器，它们的引脚配置可能跨越较少的面包板孔。

1.  将电位器 VR2 放在面包板上。

1.  将电阻放在面包板上。

1.  将 LED 放在面包板上，注意确保其阴极腿与电阻共享同一行（在 D29 和 E29 孔上说明）。

接下来，我们将按照以下方式连接 ADS1115：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/a18ec6ce-48fb-4da8-b93e-af0d064f7f56.png)图 5.5 - 面包板 ADC 电路（第二部分）

以下是要遵循的步骤。这次，以下步骤编号与*图 5.5*中编号的黑色圆圈相匹配：

1.  将树莓派的+3.3 伏引脚连接到面包板的正电源轨。

1.  将 ADS1115 上的 VDD 端子连接到面包板的正电源轨。

1.  将 ADS1115 上的 GND 端子连接到面包板的负电源轨。

1.  将树莓派的 GND 引脚连接到面包板的负电源轨。

1.  将树莓派上的 SCL 引脚连接到 ADS1115 上的 SCL 端子。

1.  将树莓派上的 SDA 引脚连接到 ADS1115 上的 SDA 端子。

最后，我们将 LED、电阻和电位器连接起来，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/0bfe52c2-e0ed-4643-b94a-e9b175cc0a46.png)图 5.6 - 面包板 ADC 电路（第三部分） 

以下是要遵循的步骤。这次，以下步骤编号与*图 5.6*中编号的黑色圆圈相匹配：

1.  将 ADS1115 上的 A0 端子连接到电位器 VR1 的中间腿。

1.  将 ADS1115 上的 A1 端子连接到电位器 VR2 的中间腿。

1.  将电位器 VR1 的上腿连接到面包板的负电源轨。

1.  将电位器 VR1 的下腿连接到面包板的正电源轨。

1.  将电位器 VR2 的上腿连接到面包板的负电源轨。

1.  将电位器 VR2 的下腿连接到面包板的正电源轨。

1.  将电阻的上腿连接到面包板的负电源轨。

1.  将 LED 的阳极腿连接到树莓派的 BCM GPIO 12 / PWM 0 上。

干得好！您现在已经完成了这个电路。供您参考，*图 5.7*显示了描述面包板电路的语义图。

作为提醒，我们在第二章中介绍了如何阅读语义图的示例，*Python 和物联网入门*。

我鼓励您在参考面包板布局时围绕这个语义图进行追踪，以了解图表上的线条和标签如何与面包板上的组件和导线相关联。投资时间来理解成对的原理图和面包板电路如何相互关联将有助于增强您直接从原理图创建面包板布局的能力：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/95c0a63b-bd3b-46c6-9483-926af6fb94d3.png)

图 5.7 - ADC 电路语义图

电路完成后，让我们检查一下树莓派是否能够看到 ADS1115。

## 确保 ADS1115 已连接到您的树莓派

I2C 设备通过唯一地址（即我们的树莓派）标识其主设备，并且 ADS1115 的默认地址为 0x48。由于 I2C 设备是有地址的，多个设备可以共享树莓派上的相同 I2C 通道（引脚）。

如果有多个设备共享相同地址，您可以更改大多数 IC2 设备上的 I2C 设备。这是 ADS1115 上的 ADDR 端子的目的，您可以在 ADS1115 数据表中找到其使用说明。

Raspbian OS 包含`i2cdetect`实用程序，用于查询树莓派的 I2C 接口以查找连接的设备。在终端中运行以下命令：

```py
$ i2cdetect -y 1
```

`-y`选项假设我们对任何提示都回答是。`1`是 I2C 总线号。在树莓派 3 或 4 上始终是`1`。我们期望看到这样的输出：

```py
     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
 00:          -- -- -- -- -- -- -- -- -- -- -- -- --
 10: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
 20: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
 30: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
 40: -- -- -- -- -- -- -- -- 48 -- -- -- -- -- -- --
 50: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
 60: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
 70: -- -- -- -- -- -- -- --
```

我们看到`48`（十六进制地址）表明我们的树莓派已经检测到了 ADS1115。如果您没有得到这个结果，请检查您的接线，并确保 I2C 已经按照第一章中描述的方式启用。

现在我们已经验证了我们的 ADS1115 对我们的树莓派是可见的，让我们继续读取两个电位器作为模拟输入。

## 使用 ADS1115 读取模拟输入

现在我们已经将我们的 ADS1115 连接到我们的树莓派，是时候学习如何使用它来读取模拟值，特别是我们两个电位器产生的模拟值。我们很快将使用这些模拟值来产生 PWM 信号，进而控制 LED 的亮度。

我们即将涵盖的代码可以在文件`chapter05/analog_input_ads1115.py`中找到。请在继续之前查看此文件。

1.  在终端中运行程序：

```py
(venv) $ python analog_input_ads1115.py
```

1.  您应该收到类似以下内容的输出流（您的值和伏特数将不同）：

```py
 Frequency Pot (A0) value=3 volts=0.000 Duty Cycle Pot (A1) value= 9286 volts=1.193
 Frequency Pot (A0) value=3 volts=0.000 Duty Cycle Pot (A1) value= 9286 volts=1.193
 ...truncated...
```

1.  转动两个电位器并观察输出的变化-具体来说，您会注意到报告的值和伏特数会发生变化。值和电压将在以下范围内：

+   +   值范围在 0 到 26294 之间（或附近）

+   电压范围在 0 到 3.3 伏特（或附近）

输出将如下所示：

```py
 Frequency Pot (A0) value=3 volts=0.000 Duty Cycle Pot (A1) value= 9286 volts=1.193
 Frequency Pot (A0) value=4 volts=0.001 Duty Cycle Pot (A1) value=26299 volts=3.288
 ...truncated...
```

正如我们将在第六章中讨论的那样，*软件工程师的电子学 101*，模拟输入是关于读取电压的，就我们这里而言，电压在 0 伏特/GND（我们的参考电压）和+3.3 伏特之间。整数值是 ADS1115 的原始输出，它的最大值取决于 ADS1115 IC 的配置方式（我们使用默认配置）。电压值是根据 ADS1115 配置的数学计算得出的。如果您感兴趣，所有细节都在 ADS1115 数据表和库源代码中。

在高级 ADC 库的表面下，许多低级设置会影响 ADC 芯片的工作方式（只需查看其数据表）。不同的库作者可能以不同的方式实现这些设置，或者使用不同的默认设置。实际上，这意味着相同 ADC 的两个库可能输出不同的原始值（有些库甚至可能不会向程序员提供这个值）。因此，永远不要假设预期的原始输出值是什么，而是依靠电压测量，这总是真相的来源。

当您调整两个电位器时，如果确切的范围末端与 0 和 3.3 伏特不完全匹配，或者值随机地微微抖动，不要担心。当我们处理模拟电子时，这种模糊的结果是预期的。

接下来，我们将检查代码。

### 理解代码

现在我们已经看到了 ADS1115 ADC 的基本操作，是时候看一下相应的代码，了解我们如何在 Python 中查询 ADS1115 以获取模拟读数。我们下面学到的内容将为本书的*第三部分*中我们将看到的模拟接口程序奠定基础。

我们将从导入开始我们的代码漫步。

#### 导入

我们可以用两种方法在树莓派上使用 ADS1115 与 Python：

+   阅读 ADS1115 数据表，并使用较低级别的 I2C，如 SMBus 来实现设备使用的数据协议。

+   找到一个现成的 Python 库，通过 PyPi 可以使用`pip`安装。

有几个现成的 Python 模块可用于与 ADS1115 一起使用。我们使用了通过`requirement.txt`在本章开始时安装的 Adafruit Binka ADS11x5 ADC 库：

```py
import board                                      # (1)
import busio
import adafruit_ads1x15.ads1115 as ADS
from adafruit_ads1x15.analog_in import AnalogIn
```

从第 1 行开始，我们看到了来自 Circuit Python（Blinka）的`board`和`busio`导入，而以`adafruit`开头的最后两个导入来自 Adafruit ADS11x5 ADC 库，并用于配置 ADS1115 模块并读取其模拟输入，我们将在下面看到。

#### ADS1115 设置和配置

在以下代码块的第 2 行，我们使用`busio`导入来创建一个与 Circuit Python/Blika 的 I2C 接口。`board.SLC`和`board.SDA`参数表示我们正在使用树莓派上的专用 I2C 通道（GPIO 2 和 3 的替代功能）：

```py
# Create the I2C bus & ADS object.
i2c = busio.I2C(board.SCL, board.SDA)      # (2)
ads = ADS.ADS1115(i2c)
```

接下来，我们使用预配置的 I2C 接口创建`ADS.ADS1115`的实例，并将其分配给`ads`变量。从此刻起，在代码中，当我们与 ADS1115 模块交互时，我们将使用这个实例。

接下来，让我们考虑全局变量。

#### 全局变量

在以下代码片段的第 3 行，我们从几个准常量开始，定义了我们希望通过模拟输入接收的最大和最小电压。当您之前运行代码时，您的端电压范围可能并不完全是 0 和 3.3 伏特。这种情况是可以预期的，并且可能会使程序感觉像电位器无法达到其旋转的端点。`A_IN_EDGE_ADJ`的值用于在代码中进行补偿。我们将在下一节重新访问这个变量：

```py
A_IN_EDGE_ADJ = 0.002                     # (3)
MIN_A_IN_VOLTS = 0 + A_IN_EDGE_ADJ
MAX_A_IN_VOLTS = 3.3 - A_IN_EDGE_ADJ
```

接下来，从第 4 行开始，我们创建了两个与连接到我们的电位器的 ADS1115 的`A0`和`A1`输入相关的`AnalogIn`实例。通过这些变量，我们确定用户旋转了我们的频率和占空比电位器的程度：

```py
frequency_ch = AnalogIn(ads, ADS.P0)  #ADS.P0 --> A0    # (4)
duty_cycle_ch = AnalogIn(ads, ADS.P1) #ADS.P1 --> A1
```

接下来，我们来到程序的入口点，我们将在这里读取我们的模拟输入。

#### 程序入口点

我们的程序不断循环，读取每个电位器的模拟输入值，并将格式化输出打印到终端。

在第 5 行，我们看到如何使用`frequency_ch.value`访问频率电位器的整数值，并使用`frequency_ch.voltage`访问电压值：

```py
if __name__ == '__main__':
   try:
       while True: 
           output = ("Frequency Pot (A0) value={:>5} volts={:>5.3f} "
                     "Duty Cycle Pot (A1) value={:>5} volts={:>5.3f}")
           output = output.format(frequency_ch.value,          # (5)
                                  frequency_ch.voltage,
                                  duty_cycle_ch.value,
                                  duty_cycle_ch.voltage)
           print(output)
           sleep(0.05)
   except KeyboardInterrupt:
       i2c.deinit()                                            # (6)
```

最后，请注意程序被包裹在一个 try/except 块中，以捕获*Ctrl* + *C*，以便我们可以使用`i2c.deinit()`进行清理。

现在我们已经看到如何使用 ADS1115 读取模拟输入，接下来，我们将集成 LED。

## 使用 PWM 控制 LED

现在我们将 LED 添加到代码中，只是我们将以与之前章节不同的方式进行。此练习中 LED 的目的是为了直观地看到改变 PWM 的占空比和频率特性的效果。我们将使用两个电位器的模拟输入来定义 PWM 的占空比和频率。

本节讨论的代码扩展了我们刚刚在`chapter05/analog_input_ads1115.py`中涵盖的模拟代码示例，以使用 PiGPIO 创建硬件 PWM 信号。

本书提供了另外两个源代码文件，分别使用 PiGPIO 实现硬件定时 PWM 和使用 RPi.GPIO 实现软件 PWM：

+   `chapter05/pwm_hardware_timed.py`

+   `chapter05/pwm_software.py`

他们的整体代码类似，不同之处在于用于调用 PWM 的方法和输入参数。我们将在接下来的部分再次访问这些文件，*可视化软件和硬件定时 PWM*。

我们即将讨论的代码可以在`chapter05/pwm_hardware.py`文件中找到。请在继续之前查看此文件：

1.  在终端中运行程序并观察输出：

```py
(venv) $ python pwm_hardware.py
Frequency 0Hz Duty Cycle 0%
... truncated ...
Frequency 58Hz Duty Cycle 0%
Frequency 59Hz Duty Cycle 0%
... truncated ...
```

1.  调整电位器，直到频率读取为 60 赫兹，占空比读取为 0%。LED 不应点亮。LED 未点亮是因为占空比为 0%，因此 GPIO 12（PWM0）始终为低电平。非常缓慢地转动占空比电位器以增加占空比，并观察 LED 缓慢增加亮度。在 100%的占空比下，GPIO 12（PWM0）始终为高电平 100%的时间，LED 处于全亮状态。

如果您发现终端上打印的占空比在 Pot 移动范围的任一端都没有达到 0%或 100%，请尝试增加代码中`A_IN_EDGE_ADJ`的值（首先尝试+0.02）。如果您在频率范围和刻度上遇到类似问题，也可以调整此参数。

1.  旋转占空比刻度，直到它显示小于 100%（例如 98%），然后调整频率刻度。LED 以这个频率闪烁。当你将频率降低到零时，LED 会闪烁得更慢。对于大多数人来说，在大约 50-60 赫兹时，LED 会闪烁得如此之快，以至于它看起来就像是一直开着。请记住，如果占空比为 0%或 100%，频率刻度不起作用！这是因为在占空比的任一端，PWM 信号完全关闭或打开——它不是脉冲，因此频率没有意义。

让我们来检查一下让这个工作的代码。

### 理解代码

这个示例使用了 PiGPIO 提供的硬件 PWM 功能。与我们之前的示例相同，ADS1115 相关的代码也是一样的，所以我们不会在这里再次介绍它。我们将首先看看额外的全局变量。

#### 全局变量

在以下代码块的第 1 行和第 2 行，我们定义了两个变量，用于最小和最大占空比和频率值。这些值来自 PiGPIO `hardware_PWM()`方法的 API 文档，我们很快就会看到它们的使用：

```py
MIN_DUTY_CYCLE = 0            # (1)
MAX_DUTY_CYCLE = 1000000
MIN_FREQ = 0                  # (2)
MAX_FREQ = 60 *# max 125000000*
```

我们已经将`MAX_FREQ`限制为 60 赫兹，以便我们的肉眼可以观察 LED 的效果。

接下来，我们有一个自定义函数来映射值范围。

#### 范围映射函数

在第 3 行，我们有一个名为`map_value()`的函数：

```py
def map_value(in_v, in_min, in_max, out_min, out_max):           # (3)
    *"""Helper method to map an input value (v_in)
       between alternative max/min ranges."""* v = (in_v - in_min) * (out_max - out_min) / (in_max - in_min) + out_min
    if v < out_min: v = out_min elifv > out_max: v = out_max
    return v
```

这种方法的目的是将一个输入值范围映射到另一个值范围。例如，我们使用这个函数将模拟输入电压范围 0-3.3 伏特映射到 0-60 的频率范围。在处理模拟输入时，您经常会使用这样的值映射函数，将原始模拟输入值映射为代码中更有意义的值。

接下来，我们准备创建 PWM 信号。

#### 生成 PWM 信号

下一个代码片段位于主`while`循环中。

在第 4 行和第 5 行，我们从频率和占空比 Pots 中读取电压值，然后使用`map_value()`函数将 0-3.3 伏特的电压范围转换为我们在全局变量中定义的所需频率和占空比范围。请注意，我们还将占空比格式化为百分比值以供显示：

```py
frequency = int(map_value(frequency_ch.voltage,                # (4)
                          MIN_A_IN_VOLTS, MAX_A_IN_VOLTS,
                          MIN_FREQ, MAX_FREQ))
 duty_cycle = int(map_value(duty_cycle_ch.voltage,              # (5)
                           MIN_A_IN_VOLTS, MAX_A_IN_VOLTS,
                           MIN_DUTY_CYCLE, MAX_DUTY_CYCLE))

duty_cycle_percent = int((duty_cycle/MAX_DUTY_CYCLE) * 100)
 pi.hardware_PWM(LED_GPIO_PIN, frequency, duty_cycle)           # (6)
```

在第 6 行，我们使用`pi.hardware_PWM()`来使用树莓派的 PWM 硬件在 LED 引脚上生成 PWM 信号。

现在我们已经看到了改变 LED 频率和占空比的效果，我们将进行一个练习，使用逻辑分析仪来可视化 PWM 信号。

## 使用 PiScope 进行 PWM 的可视化探索

让我们进行一个练习，看看逻辑分析仪中的 PWM 波形，逻辑分析仪是一种用于可视化电子信号的设备。尽管 PWM 背后的一般原理在技术上很简单，但在刚开始学习时，通过可视化 PWM 信号的外观和观察其随着占空比和频率的变化而发生的变化，可以帮助学习。

PiGPIO 包含一个我们可以用于此目的的软件逻辑分析仪。现在，我需要指出的是，这是一个基本的软件逻辑分析仪，绝对不能与专业设备相比，但是对于我们的示例和教育来说，它将非常有效，并且不会花费我们任何费用。

让我们下载、安装并运行 PiScope。以下是要遵循的步骤：

1.  首先，我们必须安装 PiScope。运行以下命令来下载、编译和安装 PiScope：

```py
# Download and install piscope
$ cd ~
$ wget abyz.me.uk/rpi/pigpio/piscope.tar
$ tar xvf piscope.tar
$ cd PISCOPE
$ make hf
$ make install
```

1.  使用以下命令运行 PiScope：

```py
$ piscope
```

我建议在启动 PiScope 并进行此练习之前关闭任何资源密集型应用程序。由于我通过菜单关闭了一些 GPIO，所以下面的屏幕截图并不像您的默认情况下那样显示所有 GPIO。**如果您也关闭了显示器上的 GPIO，请记住保留 SDA（GPIO 2）和/或 SCL（GPIO 3）以进行此练习，因为这会为 PiScope 创建一个连续的输入信号，使显示器保持时间运动。如果没有这个连续的输入，PiScope 会在没有信号输入时暂停显示，因此我们的示例将在占空比或频率为 0 时暂停显示，这将使演示感觉笨拙。

1.  确保`chapter05/pwm_hardware.py`程序在终端中运行。

1.  慢慢地转动占空比和频率旋钮，并观察第 12 行上 PWM 信号的变化。保持我们的频率范围非常低（例如 0 到 60 赫兹）意味着我们可以在 PiScope 逻辑分析仪中轻松观察 PWM 信号：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/a962eccd-2d44-444e-ae1c-51a64831fcb1.png)

图 5.8 - 10 赫兹下的 25%占空比

上面的屏幕截图显示了 10 赫兹下的 25%占空比。如果您检查屏幕截图中的最后一行，您会注意到 GPIO 12 在单个周期中高电平占 25%，低电平占 75%。

下面的屏幕截图显示了 10 赫兹下的 75%占空比。如果您检查屏幕截图中的最后一行，您会注意到 GPIO 12 在单个周期中高电平占 75%，低电平占 25%：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/dc005bb3-581d-4361-a5dd-c1ae77287bfa.png)

图 5.9 - 10 赫兹下的 75%占空比

我们现在已经通过 PiScope 看到了 PWM 信号波形的可视化，PiScope 是 PiGPIO 开发者提供的免费基本软件逻辑分析仪。我们将 PWM 信号可视化的主要目的是为了提供一个视觉辅助工具，帮助您理解 PWM 及其占空比和频率特性。

实际上，当您刚开始并与基本电子集成时，您可能不需要逻辑分析仪，甚至不需要可视化信号。然而，随着您的知识的提升以及在电子集成问题的调试上的需求，我希望这个对逻辑分析仪的基本介绍能够帮助您，并指引您进一步探索的方向。

接下来，我们将指向演示替代 PWM 技术的 Python 源文件。

## 可视化软件和硬件定时 PWM

我们之前章节的代码示例，*使用 PWM 控制 LED*和*使用 PiScope 进行 PWM 可视化*，都是使用树莓派的 PWM 硬件创建 PWM 信号。本章的代码以及下表中列出的替代实现演示了硬件定时和软件生成的 PWM 信号的使用。您可能还记得我们在*创建 PWM 信号*部分讨论过这些替代方案：

| 文件 | 详情 |
| --- | --- |
| `pwm_hardware.py` | 这是使用 PiGPIO 的硬件 PWM（这是本章中看到的代码）。您必须使用 PWM 硬件 GPIO 引脚 12、13、18 或 19。 |
| `pwm_hardware_timed.py` | 这是使用 PiGPIO 的硬件定时 PWM。这将适用于任何 GPIO 引脚。 |
| `pwm_software.py` | 这是使用 RPi.GPIO 的软件 PWM（PiGPIO 不提供软件 PWM）。这将适用于任何 GPIO 引脚。 |

从功能上讲，这些示例是相同的，它们将改变 LED 的亮度，我预测您会发现硬件和软件 PWM 的表现相似。当您转动频率旋钮时，LED 和 PiScope 的变化会感觉平滑，而硬件定时 PWM 会感觉有些生硬。这是因为硬件定时频率（在 PiGPIO 中）必须是 18 个预定值中的一个，因此当您调整旋钮时，频率的变化不是逐渐的和线性的，而是跳到/从下一个预定义的频率。您将在`pwm_hardware-timed.py`中的数组中看到这些预定义的频率。

正如之前提到的，软件 PWM 是产生 PWM 信号的最不可靠的方法，因为如果您的树莓派 CPU 变得繁忙，它容易失真。

您可以尝试使用以下步骤创建和可视化 PWM 失真：

1.  运行`pwm_software.py`并将占空比设置为高（例如 98%），频率为 60 赫兹。不要使用 100%的占空比，因为这是一个完全开启的状态，你会看到一个水平线，而不是重复的方波形。

1.  在您的树莓派上启动一个资源密集型程序，比如尝试关闭并重新启动 Chrome 浏览器。

1.  如果您仔细观察 LED，您可能会注意到 PWM 信号在某些时候会闪烁。或者，您可以在 PiScope 中观察到波形失真，如下截图中的箭头所示。当信号失真时，您会注意到条的宽度不均匀：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/0401f0ad-c4ee-4350-8fe5-84a947ed2ee2.png)

图 5.10 - PWM 信号中的失真，50%占空比，50 赫兹

干得好。您刚刚完成了一个详细的实际练习，使用 ADS1115 扩展了您的树莓派，以便您还可以将其与模拟电子设备进行接口。在此过程中，您还学会了如何使用 Python 产生 PWM 信号，看到了这个信号对 LED 的影响，并用 PiScope 进行了可视化观察。

# 摘要

做得好，因为肯定有很多东西需要我们理解！回顾一下，我们探讨了用于引用 GPIO 引脚的常见编号方案，并回顾了 Python 的流行 GPIO 库。我们还研究了用于将电子设备连接到树莓派的各种接口方法，并进行了一个实际练习，向您的树莓派添加 ADC，并使用它来通过 LED 和 PiScope 逻辑分析仪进行可视化探索 PWM 概念。

您对我们在本章中探讨和实验的基本概念的理解将有助于您理解树莓派如何与电子元件和设备进行接口，并让您第一手地了解我们如何与模拟元件（例如我们的电位计）和复杂设备（即我们的 ADS1115）进行交互。在本书的其余部分，我们将使用和建立许多这些基本原理。

本章主要关注软件库和代码。然而，在下一章《软件工程师的电子学 101》中，我们将把注意力转向电子概念和用于将电子设备与树莓派进行接口的常见电路。

# 问题

在我们结束时，这里有一系列问题供您测试对本章材料的了解。您将在书的*评估*部分找到答案：

1.  哪种串行通信接口允许设备进行级联连接？

1.  您有一个 I2C 设备，但不知道它的地址。您该如何找到它？

1.  您第一次开始使用一个新的 GPIO Python 库，但似乎无法使任何 GPIO 引脚工作。您需要检查什么？

1.  您正在 Windows 上使用 PiGPIO 和远程 GPIO 驱动远程树莓派。现在，您尝试安装一个第三方设备驱动程序库，但在 Windows 下安装失败，但您发现它在树莓派上成功安装了。可能的问题是什么？

1.  真或假：树莓派上有 3.3 伏和 5 伏的引脚，因此在使用 GPIO 引脚时可以使用任一电压？

1.  您创建了一个使用舵机的机器人。在简单测试期间，一切都很正常。然而，现在您完成了，您注意到舵机会随机抽搐。为什么？

1.  当机器人的舵机移动时，您会注意到显示器上出现了一个闪电图标，或者显示器变黑了。这可能是为什么？

# 进一步阅读

GPIOZero 网站提供了一系列示例，展示了使用 GPIOZero 和 RPi.GPIO 的功能等效示例。这是一个很好的入门资源，可以帮助理解更低级别的 GPIO 编程概念和技术：

+   [`gpiozero.readthedocs.io/en/stable/migrating_from_rpigpio.html`](https://gpiozero.readthedocs.io/en/stable/migrating_from_rpigpio.html)

以下链接包含了有关本章讨论的接口和概念的额外材料：

+   SPI 接口：[`en.wikipedia.org/wiki/Serial_Peripheral_Interface`](https://en.wikipedia.org/wiki/Serial_Peripheral_Interface)

+   I2C 接口：[`en.wikipedia.org/wiki/I%C2%B2C`](https://en.wikipedia.org/wiki/I%C2%B2C)

+   1-wire 接口：[`en.wikipedia.org/wiki/1-Wire`](https://en.wikipedia.org/wiki/1-Wire)

+   PWM：[`en.wikipedia.org/wiki/Pulse-width_modulation`](https://en.wikipedia.org/wiki/Pulse-width_modulation)

+   电位器：[`en.wikipedia.org/wiki/Potentiometer`](https://en.wikipedia.org/wiki/Potentiometer)

+   ADS1115 数据表：[`www.ti.com/lit/gpn/ads1115`](http://www.ti.com/lit/gpn/ads1115)


# 第六章：软件工程师的电子学 101

到目前为止，本书大部分内容都集中在软件上。在本章中，我们将转而关注电子学。我们将通过学习基本的电子概念来学习如何将基本的电子传感器和执行器与您的 Raspberry Pi 进行接口。本章中学到的内容将为我们在第三部分“物联网游乐场”中讨论的许多电路奠定基础。

我们将首先介绍您在处理电子学时所需的基本车间工具，并提供实用的建议，以帮助您购买电子元件。接下来，我们将为您提供指南，以帮助您在使用物理 GPIO 引脚时保护您的 Raspberry Pi 不受损害。我们还将讨论电子元件常见的故障方式，以帮助您诊断不工作的电路。

然后我们将进入电子学！在这里，我们将研究两个重要的电子定律——欧姆定律和基尔霍夫定律，并通过一个实际示例来解释为什么我们在早期章节中使用 200Ω电阻器来配合我们的 LED 电路（如果您需要关于此 LED 电路的复习，请参见第二章，*使用 Python 和物联网入门*）。

接下来，我们将探讨数字和模拟电子学，并讨论用于将它们与您的 Raspberry Pi 集成的核心电路和思想。我们将通过学习逻辑电平转换来结束本章，这是一种实用的技术，用于接口操作不同电压的电子设备。

本章将涵盖以下主题：

+   装备您的车间

+   保护您的 Raspberry Pi

+   电子元件故障的三种方式

+   用于 GPIO 控制的电子接口原理

+   探索数字电子学

+   探索模拟电子学

+   理解逻辑电平转换

# 技术要求

要执行本章的练习，您将需要以下内容：

+   Raspberry Pi 4 Model B

+   Raspbian OS Buster（带桌面和推荐软件）

+   最低 Python 版本 3.5

这些要求是本书中代码示例的基础。只要您的 Python 版本为 3.5 或更高，代码示例应该可以在不需要修改 Raspberry Pi 3 Model B 或使用不同版本的 Raspbian OS 的情况下工作。

您可以在本书的 GitHub 存储库的`chapter06`文件夹中找到本章的源代码：[`github.com/PacktPublishing/Practical-Python-Programming-for-IoT`](https://github.com/PacktPublishing/Practical-Python-Programming-for-IoT)。

您需要在终端中执行以下命令来设置虚拟环境并安装本章所需的 Python 库：

```py
$ cd chapter06              # Change into this chapter's folder
$ python3 -m venv venv      # Create Python Virtual Environment
$ source venv/bin/activate  # Activate Python Virtual Environment
(venv) $ pip install pip --upgrade        # Upgrade pip
(venv) $ pip install -r requirements.txt  # Install dependent packages
```

以下依赖项从`requirements.txt`中安装：

+   **PiGPIO**：PiGPIO GPIO 库（[`pypi.org/project/pigpio`](https://pypi.org/project/pigpio)）

本章所需的硬件组件如下：

+   数字万用表。

+   红色 LED（供参考的数据表-[`www.alldatasheet.com/datasheet-pdf/pdf/41462/SANYO/SLP-9131C-81.html`](https://www.alldatasheet.com/datasheet-pdf/pdf/41462/SANYO/SLP-9131C-81.html); 点击 PDF 选项）。

+   瞬时**按钮开关**（**SPST**）。

+   200Ω、1kΩ、2kΩ和 51kΩ电阻器。

+   10kΩ电位器

+   4 通道基于 MOSFET 的逻辑电平转换器模块。示例请参见*图 6.12*（左侧模块）。

# 装备您的车间

拥有正确的工具和设备对于帮助您组装、构建、测试和诊断电子电路非常重要。以下是您在深入电子学并创建本书中所示电路的过程中需要的基本设备（除了电子元件）：

+   **焊接铁**：您将需要一个焊接铁（和焊料）来进行一些零散的工作，比如将排针连接到扩展板上或将导线焊接到元件上，以便它们可以插入您的面包板。

+   **焊料**：寻找一种通用的 60/40（60%锡和 40%铅）树脂芯焊料，直径约为 0.5 毫米至 0.7 毫米。

+   **吸锡器/真空吸**：我们都会犯错误，所以这个设备可以帮助您从接头中去除焊料并撤消您的焊接工作。

+   **湿海绵或抹布**：始终保持焊接铁头的清洁，去除积聚的焊料 - 干净的铁头有助于清洁焊接。

+   **剥线器和剪刀**：为您的电子工作保留一套剪线器和剥线器。来自其他用途的切割刀刃中的芯片和毛刺会降低其性能。

+   **数字万用表（DMM）**：入门级的 DMM 适用于一般工作，并将包括一系列标准功能，如电压、电流和电阻测量。

+   **面包板**：我强烈建议购买两个全尺寸的面包板并将它们连接在一起，以获得更多的面包板空间。这将使得与面包板和元件一起工作更容易。

+   **杜邦（跳线）电缆**：这些是与面包板一起使用的电缆。它们有各种类型：公-公、公-母和母-母。您将需要它们的混合。

+   **松散的排针**：这些对于连接杜邦线并使不适合面包板的元件适合面包板非常有用。

+   **外部电源供应**：这样您就可以从树莓派外部为电路供电。对于本书的目的，至少您将需要一个可以提供 3.3 和 5 伏的面包板电源。

+   **树莓派外壳**：确保您的树莓派有一个外壳。一个没有外壳的树莓派下面的所有裸露的电子元件都是一场等待发生的事故。

+   **GPIO 引脚扩展头**：这使得与树莓派和面包板一起工作更容易。

如果您还没有上述设备，请在 eBay 和 Banggood 等网站上寻找*焊接铁套件*和*面包板入门套件*。这些套件通常捆绑了许多列出的项目。

这个清单显示了我们需要的基本工具，但是实际的电子设备和小工具呢？我们接下来会看到。

## 购买电子模块和元件

本书中使用的所有组件和模块的目录都包含在*附录*中。在本节中，我想提供一些一般的提示和指导，以帮助您在购买电子元件时提供帮助，以防您之前没有做过太多这方面的工作。我们将从一些购买松散元件时的提示开始。

### 购买松散的元件

当购买电阻器、LED、按钮、晶体管、二极管和其他元件（我们将在本书的*第三部分*，*物联网游乐场 - 与物理世界互动的实际示例*中探讨）等松散的元件时，有一些指导原则将帮助您，如下所示：

+   从*附录*中获取列出的特定组件值和零件号。购买许多备件，因为在学习使用它们时可能会损坏组件。

+   如果您从 eBay 或 Banggood 等网站购买，请仔细查看物品的详细信息，并最好放大零件的图像并检查所示的零件号。永远不要仅仅依靠列表的标题。许多卖家在标题中添加各种术语以进行搜索优化，这些术语不一定与实际出售的物品相关。

+   在 eBay 和 Banggood 等网站上搜索诸如*电子入门套件*之类的术语。您可能可以一次性购买一组松散的元件。

这些观点在购买传感器和模块时也适用，我们将在下一节中讨论。

### 购买开源硬件模块

我相信你们都知道开源软件，但也有开源硬件。这是一些电子硬件制造商公开发布设计和原理图，以便任何人都可以制造（和销售）这些硬件。您会发现许多来自不同供应商的分立模块（例如我们在第五章中使用的 ADS1115 模块，“将您的树莓派连接到物理世界”），它们具有不同的（或没有）品牌。不同的供应商也可能以不同的颜色制造他们的模块，虽然较少见，但物理布局也可能不同。

模块的*核心*或*心脏* - 尤其是更简单的模块 - 通常是一个单一的**集成电路**（**IC**或芯片）。只要核心 IC 和 I/O 引脚相似，通常可以安全地假设板子将以相同的方式运行。

SparkFun（[`www.sparkfun.com/`](https://www.sparkfun.com/)）和 Adafruit（[`adafruit.com/`](http://adafruit.com/)）是两家生产开源硬件的公司，许多其他公司都在克隆他们的产品。当您从这些公司购买产品时，您将获得一个很大的优势，通常他们的产品包括代码示例、教程和使用产品的技巧，并且产品质量很好。是的，您可能需要支付更多的钱，但在刚开始和尤其是对于更复杂的电子产品来说，这样的投资可以节省您大量的时间。便宜的克隆品常常出现故障 - 因此您需要购买两个或更多来规避风险。

我们现在已经介绍了一些建议和技巧，以帮助您装备您的车间并购买电子元件。拥有合适的工具并学会使用它们（特别是焊接，如果这是一项新技能，需要练习）对于使您的电子之旅顺利和高效至关重要。有时，购买散装元件可能会令人困惑，有时也容易出错，特别是在规格或标签上的细微差异可能会产生重大的实际影响的地方，因此如果您不确定，请勤勉地仔细检查并核对您购买的东西。最后，如*附录*中建议的，购买备用元件。如果一个元件损坏，您需要寻找或等待替换品到货，突然中断您的学习过程是不好玩的！

接下来，我们将讨论一些指南，以帮助您在将电子设备与树莓派连接时保持安全。

# 保护您的树莓派

在本节中，我们将介绍一些指南和建议，以帮助您在将电子设备与树莓派连接时保持安全。通过谨慎和勤勉的方法，这些指南将帮助您最大程度地减少对树莓派或电子元件造成损坏的潜在风险。

如果一些与电子相关的点，如电压和电流，目前还不清楚，不要担心。我们将在本章和本书的*第三部分*“物联网游乐场 - 与物理世界互动的实际示例”中涉及这些概念，因此会有更多的上下文：

+   *永远*不要向任何输入 GPIO 引脚施加超过 3.3 伏特的电压。更高的电压可能会造成损坏。

+   *永远*不要从任何单个输出 GPIO 引脚使用超过 8 毫安（它们可以处理高达〜16 毫安，但默认情况下，保持在 8 毫安以确保可靠的 GPIO 操作）。作为一个经验法则，除非您知道自己在做什么，否则不要为除 LED 和分立模块以外的任何东西供电。在第七章中，“打开和关闭东西”，我们将看看可以用来开关更高电流和电压负载的电路。

+   *永远不要*在多个 GPIO 引脚上使用超过合计 50 毫安的电流。

+   *永远*不要在配置为输入的 GPIO 引脚上使用超过 0.5 毫安。

+   在连接或断开连接到树莓派或进行任何更改之前，*始终*断开电路的电源。

+   在连接、断开或处理电路之前，*一定要*停止与 GPIO 引脚交互的所有运行程序。

+   在给电路供电之前，*一定要*仔细检查你的布线。

+   *永远不要*在电路中替换随机的元件值-它们不具有原理图中显示的正确和预期值。

+   如果你在树莓派的显示器上看到闪电图标，或者当运行程序时显示器变黑，那就是树莓派告诉你你的电路从树莓派吸取了太多的电力。

+   *永远不要*直接连接和使用感应负载和机械设备，比如使用 GPIO 引脚的电机、继电器或磁铁的螺线管。它们可能会吸取太多电流，并引起所谓的*EMF* *flyback*现象，这可能会损坏周围的电子设备，包括你的树莓派。

你为树莓派准备的电源最好是 3 安培（15 瓦）。许多手机充电器的额定功率低于这个值，它们的使用是看到闪电图标（或空白显示）的常见原因。

在处理电子设备时，有时候元件会受损或失效。让我们简要地看一下这种情况可能发生的方式。

# 电子元件失效的三种方式

在处理电子设备时，与软件不同。在软件世界中，我们可以更改代码、破坏代码、调试代码和修复代码，而且可以多次进行这些操作而没有真正的伤害。我们还可以自由备份和恢复状态和数据。在处理电子设备时，我们没有这种奢侈。我们处在物理世界，如果某样东西受损了，那就是最终的！

包括树莓派在内的元件和电路可能因连接不正确、过度供电、供电或输出过多电压、过热，甚至对组件进行错误处理而受损或失效，甚至物理上断裂或被你的身体静电损坏。

当元件失效时，可能会以几种不同的方式失效：

+   它会在一股烟雾中失败，熔化，或以其他方式显示出受损的物理迹象。

+   它悄然失败，没有任何视觉指示失败。

+   它虽然受损，但基本上还是按预期的方式工作，但在将来的某个时候，它会在没有警告的情况下悄然失效。

以物理标志失败是我们想要的结果，因为很明显是什么失败了，需要被替换。这也给了我们一个起点，我们可以开始诊断我们的电路。无声失败和延迟失败是痛苦和耗时的，特别是在开始时。

以下是一些帮助你在开始时构建和调试故障电路的提示：

+   在连接电源之前，始终要仔细检查电路。

+   备有备用零件。如果你有已知的好零件可以替换到电路中，那么诊断和测试电路就会更容易。

+   如果你认为某样东西受损了，那么立即丢弃它。你不需要有故障的零件和好的零件混在一起，特别是当没有明显的损坏迹象时。

接下来，我们将讨论核心电子原理，这些原理决定了电路中为什么以及如何选择元件，并通过我们的 LED 电路来说明这些概念。

# GPIO 控制的电子接口原则

虽然这本书不是一本电子理论的书，但有一些核心原则是重要的，因为它们影响电路设计以及它们与你的树莓派的接口。本节的目标是向你介绍为什么电路以某种方式设计以及这与 GPIO 接口有关的基本理解。掌握了这些基本知识，我希望它能激励你更深入地探索核心思想和原则。你会在本章末尾的*进一步阅读*部分找到建议的资源。

我们将从电子原理开始，这可能是所有电气原理中最基本的两个原理 - *欧姆定律*和*功率*。

## 欧姆定律和功率

欧姆定律是一个基本的电子原理，解释了*电压*、*电阻*和*电流*之间的关系。连同*功率*原理，这些是解释为什么在电路中选择某些值的核心基本原理。

欧姆定律表示为以下方程：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/da753273-432f-4c95-a698-57330ac312ff.png)

在这里，*V*是以伏特为单位的电压，*I*（大写 i）是以安培为单位的电流，*R*是以欧姯为单位的电阻，通常用希腊字母Ω表示。

另一方面，功率表示为以下方程：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/33f905b8-998d-4365-b9c8-5f3f4ded0781.png)

在这里，*P*是以瓦特为单位的功率，*I*（大写 i）是以安培为单位的电流（与欧姆定律中相同），*R*是以欧姯为单位的电阻（与欧姆定律中相同）。

这些方程的重要原则是，您不能改变电子电路中的单个参数而不影响另一个参数。这意味着组件被选择和排列在电路中，以确保电压、电流和功率适当地比例分配给各个组件和电路的整体运行。

如果您是电子世界的新手，这些内容不会立即理解，不要灰心！这需要时间和实践。除了欧姆定律，我们还有基尔霍夫定律，下面我们将讨论它。

## 基尔霍夫电路定律

基尔霍夫的电压和电流定律是电路遵循的两个定律。它们是电气工程中的两个基本定律，陈述如下：

+   环路中所有电压的代数和必须等于零。

+   进入和退出节点的所有电流的代数和必须等于零。

这就是我们将要讨论的这些定律的深度。我在这里提到这些定律，因为电压定律是我们将在下一节中看到的定律，当我们计算为什么在本书的早期章节中为 LED 电路使用了 200 欧姆电阻时。

到目前为止，我们已经简要介绍了三个重要的电气原理或定律 - 欧姆定律、功率和基尔霍夫电路定律。现在是时候将这些原理付诸实践了。我们将通过一项练习来解释为什么我们在 LED 电路中一直使用 200Ω串联电阻。

## 为什么我们在 LED 电路中使用 200 欧姆电阻？

到目前为止，在本书中，我们的电子学大部分都围绕 LED 发展。我这样做是有充分理由的。LED（和电阻）是易于使用的组件，并为学习欧姆定律、功率和基尔霍夫电压定律等概念提供了基本的构建模块。掌握 LED 电路的基础知识和背后的计算，您将很快掌握更复杂的组件和电路。

让我们更深入地了解 LED，并探索其数据属性，并看看欧姆定律、功率和基尔霍夫电压定律的应用。通过一系列示例，我们将通过一个过程解释为什么在本书中之前看到的 LED 电路中使用了 200 欧姆电阻。

以下是一个基本的 LED 电路，类似于我们在本书中迄今为止使用的电路。如果您需要恢复这个电路，请回顾第二章，*开始使用 Python 和物联网*：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/1bcb5727-5cc2-4a11-95be-13ed36b9463d.png)

图 6.1 - LED 和电阻电路

我们一直在使用*典型*的 5 毫米*红色*LED。我在这里提取了它的*典型*技术规格的一部分。强调*典型*和*红色*的区别是因为 LED 的规格会有所不同，取决于它们的颜色、最大亮度、物理尺寸和制造商。即使是同一批次的 LED 也会有所不同。

以下是与我们参考的红色 LED 数据表相关的一些核心规格：

+   **正向电压降（VF）在 1.7 到 2.8 伏特之间**，典型降为 2.1 伏特。这是 LED 需要照亮的电压。如果电路中的电压不足以点亮 LED，LED 将不会点亮。如果超过所需电压，那没关系-LED 将只取所需的电压。

+   **最大连续正向电流（IF）为 25 毫安**。这是 LED 达到最大亮度所需的安全电流，当 LED 一直开启时，对于一些 LED 来说，这可能太亮了。提供更少的电流意味着 LED 会更暗，而提供更多的电流可能会损坏 LED。对于我们的 LED 和数据表，当脉冲 LED（例如使用 PWM）时，最大电流可以达到（IFP）100 毫安。

功率呢？LED 是根据电压和电流工作的组件。如果你看一下功率方程（![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/93621e39-5a1d-4a11-af90-32775ea48b95.png)），你会发现功率是电压（V）和电流（I）的函数。只要你在 LED 的电流额定范围内工作，你就在其功率容限范围内。

如果你没有 LED 的匹配数据表（在小批量推入时很常见），可以使用 2 伏特的电压降和 20 毫安的参考电流进行计算。你也可以使用数字万用表设置为二极管设置来测量 LED 的正向电压。

让我们继续看看我们如何得出 R1 电阻的值。

### 计算电阻值

在前面的电路图中，我们有以下参数：

+   供电电压为 3.3 伏特

+   LED 典型正向电压为 2.1 伏特

+   LED 电流为 20 毫安（数据表中提到了电压降的毫安测试条件）

以下是计算电阻值的过程：

1.  我们的电阻（标记为 R1）需要降低 1.2 伏特，这是我们之前简要提到的柯希霍夫电压定律的一个简单应用；即*回路中所有电压的代数和必须等于零*。因此，如果我们的源电压是+3.3 伏特，LED 降低 2.1 伏特，那么电阻必须降低 1.2 伏特。这意味着我们得到以下方程：

+3.3V + -2.1V + -1.2V = 0V

1.  我们可以代数地排列欧姆定律，得到以下结果：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/da82fc27-418f-4857-ad67-ea7fea45deca.png)

1.  使用这个公式，我们计算出了我们电阻的值：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/7465557d-5bc1-476c-89a2-10dfb6a16074.png)

= 60Ω（因此，前面电路中的电阻 R1 为 60Ω）

但这不是 200Ω。到目前为止，我们的例子是一个简单的 LED 和电阻电路，连接到 3.3 伏特的电源，而不是树莓派。还有更多要考虑的，因为我们需要尊重树莓派 GPIO 引脚的电流限制，接下来我们将做到这一点。

### **考虑树莓派的电流限制**

我们可以安全使用的与配置为输出的 GPIO 引脚的最大电流为 16 毫安。然而，GPIO 引脚有一个可配置的方面，这意味着，默认情况下，我们不应该使用超过每个 GPIO 8 毫安。这个限制可以配置，使其达到 16 毫安，但这超出了我们的范围。理想情况下，我们希望在需要更多电流时向外部电路移动，而不是不断提高引脚的电流。我们将在第七章中学习如何做到这一点，*打开和关闭*。

虽然我们希望将单个 GPIO 输出引脚限制在 8 毫安，但我们不应该超过多个 GPIO 引脚的总和约 50 毫安。当涉及到 GPIO 输入引脚时，我们应该将电流限制在 0.5 毫安，以确保在连接外部输入设备或组件时安全操作。将输入 GPIO 引脚直接连接到树莓派的+3.3V 或 GND 引脚是可以的，因为测得的电流约为 70 微安（我们将在第七章中学习如何使用万用表测量电流，*打开和关闭*）。

让我们修改我们的计算并继续这个过程：

1.  如果我们将电流限制在 8 毫安，我们可以使用之前的方程得出 R1 的值：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/e2e2b068-4f07-4f4c-80a9-ca52582b2475.png)

R1 = 150Ω

1.  电阻器的额定值从来不会是精确的。它们有一个值的公差，如果我们的物理电阻器小于 150Ω，根据欧姆定律，我们会增加电路中的电流并超过 8 毫安的限制。

因此，我们将选择一个稍高一点的值。这可能就是使用经验法则，比如选择一个比 150Ω高两个标准电阻值，或者将 150Ω乘以我们电阻器的公差，然后选择下一个最高的标准值。让我们使用后一种方法，假设我们电阻器的公差是±20%（顺便说一句，这将是一个非常低质量的电阻器。5%和 10%更常见）：

150Ω x 1.2 = 180Ω

180Ω恰好是一个标准的电阻值，所以我们可以使用它，但是我没有（经常会发现在计算后你也没有你想要的确切电阻值！）。然而，我有一些 200Ω的电阻器，所以我会使用其中一个。

对于原型设计和修补，从 180Ω到约 1kΩ的任何电阻器都足以满足我们电路的需求。只要记住，随着电阻器值的增加，电流会受到限制，所以 LED 会变得更暗。

但是电阻器上的功率和功率额定值呢？我们将在下面计算。

### 计算电阻器的功率耗散

我们面包板中使用的通用电阻器通常额定为 1/8 瓦特、1/4 瓦特或 1/2 瓦特。如果向电阻器提供过多的功率，它将烧毁并冒出一股难闻的气味。

当我们有一个 3.3 伏的电源时，这是我们计算 200Ω电阻器的功耗的方法：

1.  电阻器的功率可以用以下公式计算。注意，电压*V*是电阻器两端的电压降，单位是伏特，而*R*是欧姆的电阻：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/3ad95b98-ca5a-4f81-afee-c78f93abe671.png)

1.  因此，当我们在公式中替换我们电阻器的电压降和电阻值时，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/da8b9153-8294-4f0c-be8c-6689e8f2f2cc.png)

= 0.0072 瓦特，或 7.2 毫瓦（或 mW）

1.  我们的功率值为 7.2 毫瓦，甚至低于 0.25 瓦特的电阻器，因此 1/8 瓦特或更高的电阻器在我们的电路中是安全的，不会烧毁。

如果你觉得功率方程看起来与你之前看到的不同，你是对的。这是重新编写的功率方程，使用电压和电阻。这是一个方便的图表，我相信你在电子学学习过程中会看到的，它以不同的方式表达了欧姆定律和功率：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/aae01c1f-bdce-4e6c-b6d5-7e8a6ab760c7.png)

图 6.2 - 欧姆定律功率轮

我给你留下一个关于 LED 的最后提示，以及一些思考。

改变 LED 的亮度是由电流决定的。数据表中的 25 毫安值是驱动 LED 到最大亮度的最大连续安全电流。更少的电流也可以，只是意味着 LED 会变得更暗。

等一下 - 在第五章中，*将您的树莓派连接到物理世界*，我们使用了 PWM，这是一种伪模拟*电压*，用于改变 LED 的亮度。暂停一下，思考一下……发生了什么？这只是欧姆定律的一个应用。在我们的电路中，我们的电阻器固定在 200Ω。因此，通过改变电压，我们也改变了电流，从而改变了 LED 的亮度。

您认为呢？请放心，这是本书中数学的复杂程度。但我鼓励您重复这些练习，直到您对这个过程感到舒适。理解电子基础知识（以及相关的计算）是一个爱好者只是通过试错猜测组件直到电路工作的区别，和一个真正可以构建所需内容的工程师之间的区别。

接下来，我们将探讨与数字电子相关的核心概念。

# 探索数字电子

数字 I/O 基本上意味着检测或使 GPIO 引脚为高电平或低电平。在本节中，我们将探讨核心概念，并看一些数字 I/O 操作的示例。然后，我们将讨论这与您的树莓派以及您将与之接口的任何数字电子元件的关系。我们将通过查看和操作数字输出来开始或数字 I/O 之旅。

## 数字输出

简单来说，对于我们的树莓派来说，当我们将 GPIO 引脚设为高电平时，其电压测量值为~3.3 伏特，当我们将其设为低电平时，测量值为~0 伏特。

让我们用万用表观察一下：

不同的万用表可能有不同的连接和标记，与这里所示的万用表不同。如果您不确定如何设置测量电压，请参阅您的万用表手册。

1.  将您的万用表设置为电压设置，并将其连接到 GPIO 21 和 GND，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/12e7ad52-5289-4058-9954-c943702ddb46.png)

图 6.3 - 将万用表连接到 GPIO 引脚

1.  运行以下代码，您可以在`chapter06/digital_output_test.py`文件中找到。您会注意到仪表在大约 0 伏和大约 3.3 伏之间切换。我说“大约”，因为在电子设备中没有什么是完美或精确的；总是有公差。以下是代码的概要：

```py
# ... truncated ...
GPIO_PIN = 21
pi = pigpio.pi()
pi.set_mode(GPIO_PIN, pigpio.OUTPUT)           # (1)

try:
    while True:                                # (2)
        # Alternate between HIGH and LOW
        state = pi.read(GPIO_PIN); # 1 or 0
        new_state = (int)(not state) # 1 or 0
        pi.write(GPIO_PIN, new_state);
        print("GPIO {} is {}".format(GPIO_PIN, new_state))
        sleep(3)
# ... truncated ...
```

在第 1 行，我们将 GPIO 21 配置为输出引脚，而在第 2 行，我们启动了一个`while`循环，该循环在每个状态转换之间有 3 秒的延迟，将 GPIO 21 的状态在高和低之间交替变换（即 0 和 1）。

您可能已经注意到，我们树莓派上的数字输出就是这么简单 - 高电平或低电平。现在，让我们考虑数字输入。

## 数字输入

通常，当我们考虑数字输入和 3.3 伏特设备的电压时，比如树莓派，我们认为将引脚连接到地（0 伏特）以使其低电平，或者连接到 3.3 伏特以使其高电平。在大多数应用中，这确实是我们努力做的事情。但实际上，这个故事还有更多内容，因为 GPIO 引脚不仅仅在两个离散的电压水平上工作。相反，它们在定义输入引脚为高和低的一系列电压范围内工作。这适用于树莓派和具有 GPIO 的类似计算机、微控制器、集成电路和分线板。

考虑以下图表，显示了 0 到 3.3 伏特之间的电压连续体，以及标有“低、悬空”和“高”的三个突出区域：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/51462758-4c5a-44eb-b85c-16db3d1e61c6.png)

图 6.4 - 数字输入触发电压

这幅插图告诉我们，如果我们在 2.0 伏特和 3.3 伏特之间施加电压，那么输入引脚将被读取为数字高电平。或者，如果我们在 0.8 伏特和 0 伏特之间施加电压，引脚将被读取为数字低电平。超出这些范围的任何电压都是危险区域，您很可能会损坏您的树莓派。虽然您可能不会意外地向引脚施加负电压，但很可能会意外地向引脚施加超过 3.3 伏特的电压，因为通常会使用 5 伏特的数字电路。

那么，中间的灰色区域呢？我们是数字高电平还是数字低电平？答案是我们不知道，也永远无法可靠地知道。在这个范围内，引脚被称为“悬空”。

让我们看看悬空引脚的影响。我们将在面包板上创建以下电路：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/b950eaef-573a-4442-bdd5-a0eed9d133ac.png)

图 6.5 - 按钮电路

以下是此步骤。这里的步骤编号与前面图中显示的带有编号的黑色圆圈相匹配：

1.  将按钮放在面包板上。

1.  将按钮的一端连接到树莓派上的 GND 引脚。在图中，我们将按钮的下部腿（显示在 E4 孔处）连接到 GND 引脚。

1.  最后，将按钮的另一端（在图中，这是最上面的腿，显示在 E2 孔处）连接到树莓派上的 GPIO 21。

现在您的电路已经建立完成，让我们测试电路并看看会发生什么：

1.  运行以下代码，可以在`chapter06/digital_input_test.py`文件中找到：

```py
# ... truncated...
GPIO_PIN = 21
pi = pigpio.pi()
pi.set_mode(GPIO_PIN, pigpio.INPUT)   # (1)
# ... truncated...

try:
   while True:                        # (2)
   state = pi.read(GPIO_PIN)
   print("GPIO {} is {}".format(GPIO_PIN, state))
   sleep(0.02)

except KeyboardInterrupt:
   print("Bye")
   pi.stop() # PiGPIO cleanup.
```

此代码在第 1 行上将 GPIO21 配置为输入。在第 2 行上，使用`while`循环，我们快速读取 GPIO 引脚的值（1 或 0）并将其打印到终端。

1.  用手指触摸面包板上的导线，以及开关周围的任何裸露的金属触点。导线和触点就像天线一样捕捉电气噪音，您应该看到终端输出在高（1）和低（0）之间波动 - 这是一个*浮动*引脚。这也说明了一个常见的误解，即配置为输入并且未连接任何东西的 GPIO 引脚默认总是低电平。

如果您最初的想法是“哇！我可以创建一个触摸开关”，那么抱歉；您会感到失望 - 这并不可靠，至少没有额外的电子设备。

接下来，我们将看两种常见的避免浮动引脚的方法。

## 使用上拉和下拉电阻

当引脚未连接到任何东西时，它被称为浮动。如前面的示例所示，它在周围*漂移*，从其他附近的组件、连接到它的导线和来自您自己的电荷中捕捉电气噪音。

再次参考前面的图表，当按钮*按下*时，电路完成，GPIO 21 连接到地，因此我们可以确定引脚为低电平。正如我们刚才看到的，当按钮*未*按下时，GPIO 21 是浮动的 - 由于外部噪音，它可以在高电平和低电平之间波动。

这需要纠正，我们可以用电阻或代码来解决这个问题。

### 电阻解决方案

如果我们在电路中添加一个外部电阻，如下图所示，那么我们将引入所谓的*上拉电阻*，它的作用是*拉*（意思是连接）GPIO 引脚 21 *上拉*（意思是连接到正电压）到 3.3 伏：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/1be002af-489f-4fcb-9955-9f780f5a9604.png)

图 6.6 - 带上拉电阻的按钮电路

以下是在面包板上创建此电路的步骤。这里的步骤编号与前面图中显示的带有编号的黑色圆圈相匹配：

1.  将按钮放在面包板上。

1.  在面包板上放置一个电阻（值在 50kΩ到 65kΩ之间）。电阻的一端与按钮的上部位置的腿共用同一行（显示在孔 B5 处）。电阻的另一端放在一个空行上。

1.  将电阻的另一端连接到树莓派上的 3.3 伏引脚。

1.  将按钮的下部腿连接到树莓派上的 GND 引脚。

1.  最后，将按钮的上部腿和电阻的下部腿共用的行（显示在 D5 孔处）连接到树莓派上的 GPIO 21。

现在您已经创建了电路，这里是它的简要描述：

+   当按钮*未* *按下*时，电阻将 GPIO 21 *上拉*到 3.3 伏引脚。电流沿着这条路径流动，引脚将被读取为保证的数字高电平。

+   当按钮*按下*时，连接 GPIO 21 到地的电路段被创建。由于在这条路径中流动的电流更多，因为它的电阻更小（接近零），所以 GPIO 引脚连接到地，因此会读取为低电平。

在`chapter06/digital_input_test.py`中运行相同的代码，只是这一次，当你触摸电线时，输出*不应该*波动。

如果你的电路不工作，而且你的接线是正确的，尝试将你的按钮在面包板上旋转 90 度。

为什么在前面的图中使用 50kΩ到 65kΩ的电阻？继续阅读-当我们看一个基于代码的替代方案时，我们将会找出原因。

### 代码解决方案

我们可以通过告诉我们的树莓派激活并连接一个嵌入式上拉电阻到 GPIO 21 来在代码中解决我们的浮动引脚问题，根据树莓派的文档，这个电阻将在 50kΩ-65kΩ的范围内，这就是为什么我们在前面的图中规定了这个范围。

下图显示了一个类似于前图所示的电路，但在外部电路中没有物理电阻。我在树莓派图中添加了一个电阻，以说明树莓派的电路中确实有一个物理电阻，尽管我们看不到它：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/574a6411-caa5-4a6c-b37c-46b7a03f0d9c.png)

图 6.7 - 使用嵌入式上拉电阻的按钮电路

让我们在代码中启用一个上拉电阻并测试这个电路。以下是你需要遵循的步骤：

1.  这个例子使用了之前在*图 6.5*中显示的按钮电路。在继续之前，请在面包板上重新创建这个电路。

1.  接下来，编辑`chapter06/digital_input_test.py`文件，启用内部上拉电阻，如下所示：

```py
#pi.set_pull_up_down(GPIO_PIN, pigpio.PUD_OFF) <<< COMMENT OUT THIS LINE
pi.set_pull_up_down(GPIO_PIN, pigpio.PUD_UP)   <<< ENABLE THIS LINE
```

1.  再次运行`chapter06/digital_input_test.py`文件。当你按下按钮时，你应该看到终端上的高/低（0/1）值在改变；然而，触摸按钮的电线或终端不应该引起任何干扰。

当阅读前面的代码并观察终端输出时，如果终端在按钮*未* *按下*时打印`1`，在按钮*按下*时打印`0`（即按钮按下=引脚低）在编程意义上似乎有点前后颠倒，那么你是对的...也是错的。这是因为你是以程序员的身份看待电路。我故意这样做是因为这是你经常会看到的配置。这被称为*主动低*，这意味着当引脚低时按钮是活动的（按下）。

相反的电阻设置也是可能的，同样有效。也就是说，你可以设计一个将 GPIO 21 默认接地的电路，这样我们就使用了一个*下拉*电阻，无论是物理电阻还是在代码中激活的嵌入式电阻。在这种情况下，当按钮被按下时，引脚读取 1（高），在代码中可能会更舒服！

作为练习，尝试更改电路和代码，使其默认为下拉。

在阅读数字输入电路时，你需要结合伴随的代码来阅读电路，或者考虑你将要编写的代码。忽视上拉或下拉电阻的使用可能是看似简单的数字输入电路不工作的基础。

现在我们明白了我们可以有物理和代码激活的上拉和下拉电阻，我们可以说一个方法比另一个更好吗？简短的答案是，有时候...外部电阻确实有优势。

外部上拉或下拉电阻的优势在于它们始终存在。代码激活的上拉和下拉只有在满足两个条件时才存在：

+   你的树莓派已经开机。

+   你已经运行了激活上拉或下拉的代码。在此之前，引脚是浮动的！我们将在第七章中看到一个应用，*打开和关闭设备*。

这并不是说代码激活的上拉和下拉电阻是次优的，只是意味着当您的树莓派关闭或您没有运行代码时，您需要考虑漂移引脚对电路的影响。

我们现在已经介绍了数字输入和输出的基础知识，这在许多方面是电子接口的支柱。我们还了解到，数字输入并不仅仅是高电平或低电平状态，实际上阈值电压水平确定了树莓派的数字高电平或数字低电平的电压水平。除此之外，我们还了解到在处理数字输入时，有必要适当地使用上拉或下拉电阻，以使输入电路可靠和可预测 - 也就是说，它不会*漂移*。

当设计可预测的数字输入电路时，您对数字 I/O 的理解将对您有所帮助（漂移引脚和缺失或错误使用的上拉或下拉电阻在刚开始时是常见的错误来源！）。此外，当您与非树莓派设备和电子设备集成时，您对数字高/低电压水平的理解将是有价值的。我们将在本章后面再次提到这个数字电压主题，在*逻辑电平转换*部分。

现在，让我们从数字电子学转向模拟电子学。

# 探索模拟电子学

正如我们在前一节中看到的，数字 I/O 完全取决于电压确定的离散高电平或低电平。另一方面，模拟 I/O 完全取决于电压的程度。在本节中，我们将探讨一些核心概念，并查看模拟 I/O 的操作示例。

## 模拟输出

在第五章中，*将您的树莓派连接到物理世界*，我们讨论了通过在数字输出引脚上使用 PWM，我们可以创建伪模拟输出或可变输出电压的外观。此外，我们还在第三章中看到了 PWM 的使用，*使用 Flask 进行 RESTful API 和 Web 套接字网络*，当时我们使用了这个概念来控制 LED 的亮度。

在这一部分，我们将通过一个简短的练习进一步探讨 PWM 的基本概念。我们的示例与之前进行数字输出的示例类似，只是这一次，我们使用 PWM 在 GPIO 引脚上产生可变电压。以下是我们需要遵循的步骤：

1.  将您的万用表连接到您的树莓派上，就像我们在*图 6.3*中为数字输出所做的那样。

1.  运行以下代码，您可以在`chapter06/analog_pwm_output_test.py`文件中找到。

1.  当代码运行时，您的万用表将步进到一系列不同的电压。虽然不会像终端屏幕输出所示的那样精确，但应该足够接近以说明意图：

```py
(venv) $ analog_pwm_output_test.py
Duty Cycle 0%, estimated voltage 0.0 volts
Duty Cycle 25%, estimated voltage 0.825 volts
Duty Cycle 50%, estimated voltage 1.65 volts
Duty Cycle 75%, estimated voltage 2.475 volts
Duty Cycle 100%, estimated voltage 3.3 volts
```

让我们来看一下代码，部分代码如下。

它使用了 PiGPIO 的硬件定时 PWM，在第 1 行进行配置，同时在第 2 行定义了一组占空比百分比。这些是我们的代码将在第 3 行中步进的占空比值。在第 4 行，我们设置了 GPIO 21 的占空比，然后休眠 5 秒，这样您就可以在终端和您的万用表上读取值：

```py
# ... truncated ...
pi.set_PWM_frequency(GPIO_PIN, 8000)                       # (1)

duty_cycle_percentages = [0, 25, 50, 75, 100]              # (2)
max_voltage = 3.3

try:
    while True:                                  
       for duty_cycle_pc in duty_cycle_percentages:        # (3)
           duty_cycle = int(255 * duty_cycle_pc / 100)
           estimated_voltage = max_voltage * duty_cycle_pc / 100
           print("Duty Cycle {}%, estimated voltage {} volts"
                 .format(duty_cycle_pc, estimated_voltage))
           pi.set_PWM_dutycycle(GPIO_PIN, duty_cycle)      # (4)
           sleep(5)

# ... truncated ...
```

如果您需要从您的树莓派提供更真实的模拟输出，那么您可能会喜欢探索如何使用**数字模拟转换器**（**DAC**）。它们通常通过 I2C 或 SPI 进行接口，您将通过类似于 ADS1115 ADC 的驱动程序库来控制它们，只是您将输出可变电压而不是读取电压。

现在我们已经讨论了模拟输出，并看到了如何使用 PWM 创建一个简单的示例，接下来，我们将看看模拟电子学的输入端。

## 模拟输入

在第五章中，*将您的树莓派连接到物理世界*，我们学习了如何使用 ADS1115 ADC 扩展模块，模拟输入就是测量预定义范围内的电压，对于我们的目的来说，范围在 0 伏特到 3.3 伏特之间。在数字 I/O 中，我们会说在引脚上测量到 0 伏特意味着低，3.3 伏特意味着高，但在模拟 I/O 中，这方面没有高低的概念。

许多简单的模拟元件和传感器都是根据它们测量的内容来改变它们的电阻。例如，光敏电阻器（LDR）的电阻会随着它检测到的光的变化而变化。然而，模拟输入是关于测量电压的。为了将变化的电阻转换为变化的电压，我们使用电压分压器电路。

### 电压分压器

以下图显示了一个简单的两电阻器电压分压器电路。本例中，我们的电阻值是固定的，以说明基本原理。请注意，我们在本例中使用了 5 伏特。我们之所以这样做的原因很快就会揭晓，当我们讨论逻辑电平转换时：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/7dd2315e-73d9-4629-9dc4-b5f0c8d364cb.png)

图 6.8 - 测量电压跨电压分压器

电子学和电阻器的原理是，电压会按照它们的电阻值成比例地*降低*在串联电阻器上。在前述电路中，R1 的值是 R2 的两倍，所以它降低的电压是 R2 的两倍。以下是基本公式，应用于前述电路（实际上是再次应用了基尔霍夫定律和欧姆定律）：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/0e2f9821-4be4-43c2-b7f7-69f20c5b7d59.png)

V[out] = 5 伏特 x 2000Ω / (1000Ω + 2000Ω)

V[out] = 3.33333 伏特

我们将在*第三部分*中看到电压分压器的应用，*物联网游乐场-与物理世界互动的实际示例*，但现在，为了看到这个原理在实践中的应用并帮助巩固概念，将数字万用表放在前图中标记的点之间，以验证测量的电压是否接近所示的值；即在 R1（前图中的 A 和 B 点）之间测量约 1.6 伏特，在 R2（前图中的 B 和 C 点）之间测量约 3.3 伏特。在前述方程中，R2（B 和 C 点）之间的测量是*V[out]*。

那么电阻值的选择呢？对于电压分压器，电阻值选择最重要的部分是它们相对比例的选择，以便按照我们想要的方式分压电压。除此之外，还涉及到电流流动和电阻器功率额定值 - 再次，这些是欧姆定律和功率的应用。

还记得第五章中的电位器吗？它们实际上是电压分压器！我们将中间的拨片连接到 ADS1115 的 AIN1 和 AIN2 上，当您转动电位器上的拨片时，您所做的就是改变 A 和 B 端子之间相对于中心拨片的电阻，从而产生由 ADS1115 读取的可变电压。

以下图显示了电位器与语义图的关系。A、B 和 C 点与前述电路中指示的点是可比较的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/68d00ad0-aa4c-463b-90ff-9b0822d87f4d.png)

图 6.9 - 电位器是电压分压器

让我们进行一个实验，看看电位器如何作为电压分压器，创建如下电路：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/2ee99f40-bed5-423c-bf22-83242cdb9fa5.png)

图 6.10 - 电位器电路

以下是要遵循的第一组步骤。这里的步骤编号与前图中显示的带编号的黑色圆圈相匹配：

1.  将 10kΩ电位器放在面包板上。您会注意到我已经标记了 A、B 和 C 三个端子，以便它们与*图 6.9*中显示的标签相匹配。

1.  将外部电位器（标有 A）的端子连接到树莓派上的 3.3 伏针脚。在这个电路中，我们只使用树莓派作为电源。如果需要，您也可以使用外部电源或电池。

1.  将电位器的另一个外部端子（标有 C）连接到树莓派的 GND 针脚。

1.  将万用表的电压测量引线连接到电位器的中间端子（标有 B）。

1.  将万用表的*com*端子连接到 GND（在我们的示例中，与标有 C 的电位器端子共用）。

1.  打开您的万用表并选择电压模式。

现在，打开万用表，转动电位器的旋钮，观察万用表上的电压读数在 0 伏特和 3.3 伏特之间的变化。

这就结束了我们对*模拟电子学*的介绍。我们进行了一个简单的练习，用万用表演示和可视化了 PWM 如何产生可变的输出电压。我们还学习了*电压分压器*，它们的工作原理，以及它们为何是任何模拟输入电路的关键部分。最后，我们再次回顾了*电位器*，并看看它们如何作为可变的*电压分压器*。

这些模拟概念虽然相对简短和简单，但是是每个电子工程师（无论您是专业人士还是业余爱好者）都需要理解的两个核心原则。这些概念，特别是*电压分压器*，将在接下来的章节中出现在许多电路中（我们将与 ADS1115 模数转换器一起使用它们），因此，请尝试使用前面的示例和原则来确保您掌握了基础知识！

接下来，我们将讨论逻辑电平转换，并看看电压分压器的另一个实际应用，这次是在*数字输入*空间中。

# 理解逻辑电平转换

有时候您需要从树莓派的 3.3 伏特 GPIO 引脚与 5 伏特设备进行接口。这种接口可能是为了 GPIO 输入、输出或双向 I/O。用于在逻辑电平电压之间转换的技术称为*逻辑电平转换*或*逻辑电平转移*。

有各种技术可以用来转移电压，我们将在本节中介绍其中两种比较常见的技术。一种是使用电压分压电路，我们在上一节中讨论过，而另一种是使用专用的逻辑电平转移模块。我们逻辑电平转换的第一个示例将是查看一种基于电阻的解决方案，称为*电压分压器*。

## 电压分压器作为逻辑电平转换器

由适当选择的电阻构成的电压分压电路可以用于*从 5 伏特降低*到 3.3 伏特，使您可以将来自设备的 5 伏特输出用作输入到您的 3.3 伏特树莓派针脚。

为了让您清楚地理解和学习，在本节中，我们处理的是*数字*电子学，特别是数字输入和数字输入电路中*电压分压器*的应用。请确保在完成本章后，您对*电压分压器*在模拟和数字电路中的基本实际差异和应用感到满意。

以下图表是我们之前在*图 6.8*中看到的相同示例，只是这次是在不同的上下文中绘制的；也就是说，显示了如何将 5 伏特输入*降低*到 3.3 伏特：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/dd2d81a7-dbe1-401a-a73e-aa369d824529.png)

图 6.11 - 使用电压分压器作为逻辑电平转移

电压分压器不能将电压从 3.3 伏特升高到 5 伏特。然而，回想一下我们在数字输入和*图 6.4*中的讨论，我们解释了输入引脚只要电压>= ~2.0 伏特就会读取数字高。同样的规则通常也适用于 5 伏特电路-只要输入电压>= ~2.0 伏特（3.3 伏特就是），5 伏特逻辑将会注册为逻辑高。数字低也是同样的道理，当电压<= ~0.8 伏特时。

通常情况下是这样，尽管您需要检查所涉及的 5 伏特设备的详细信息和数据表。它可能明确提到最低电压，或者可能只是提到它将使用 3.3 伏特逻辑。如果没有明显的迹象表明设备支持 3.3 伏特逻辑，您可以使用 3.3 伏特自行测试。这样做是安全的，因为 3.3 伏特小于 5 伏特，这意味着没有损坏的风险。最坏的情况下，它只是不起作用或者工作不可靠，这种情况下，您可以使用专用的逻辑电平转换器。我们将在下面讨论这个问题。

## 逻辑电平转换器 IC 和模块

电压分压电路的替代方案是专用的逻辑电平转换器。它们以 IC（芯片）形式和面包板友好的断路模块形式出现。因为它们基本上是即插即用的，所以不需要进行数学计算，并且它们包括多个通道，可以同时转换多个 I/O 流。

以下图片显示了典型的 4 通道（左侧）和 8 通道（右侧）逻辑电平转换断路模块。左侧的 4 通道是使用 MOSFET 构建的，而右侧的 8 通道使用了 TXB0108 IC。请注意，虽然我们将在第七章中介绍 MOSFET，*打开和关闭物品*，但我们的重点将是使用 MOSFET 作为开关，而不是逻辑电平转换应用。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/fc1a8a21-b675-491f-ad9c-85a51c3f9269.png)

图 6.12 - 逻辑电平转换器断路模块

逻辑电平转换器模块也有两个部分-低电压端和高电压端。关于树莓派，我们将其 3.3 伏特引脚和 GPIO 连接到低电压端，然后将另一个更高电压的电路（例如 5 伏特电路）连接到高电压端。

接下来的示例将基于类似于之前图片中的 4 通道 MOSFET 模块，它有 LV 和 HV 端子，以及两个 GND 端子。如果您使用不同的模块，您可能需要查阅其数据表，并根据示例调整接线。

让我们看看电平转换的实际操作。我们将通过构建一个电路并测量电压来实现这一点。在*数字输出*部分中，我们直接将万用表连接到树莓派的 GPIO 引脚上，并观察到当 GPIO 为高时，万用表读取~3.3 伏特。这一次，我们将把我们的万用表连接到逻辑电平转换器的 HV 端，并观察到当 GPIO 引脚为高时，万用表读取~5 伏特。

我们将从构建我们的电路开始，这将分为两部分：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/ea1c6f54-806a-491b-adb1-f7c7fff02672.png)

图 6.13 - 可视化 3.3 伏特到 5 伏特电平转换（1/2）

以下是要遵循的第一组步骤，其中我们放置了连接逻辑电平转换器低电压端的组件。这里的步骤编号与前图中显示的编号黑色圆圈相匹配：

1.  将您的逻辑电平转换器放在面包板上。

1.  将逻辑电平转换器的 LV（低电压）端连接到左侧电源轨道的正极。我们将这个轨道称为*低电压轨道*，因为它将连接到我们供电电压中较低的那一侧（即 3.3 伏特）。LV 端是逻辑电平转换器的低电压端电源输入端子。

1.  将*低电压轨道*的正极连接到树莓派上的 3.3 伏特电源引脚。

1.  将逻辑电平转换器低电压侧的 GND 端子连接到*低电压轨道*的负电源。

1.  将*低电压轨道*的负电源连接到树莓派上的 GND 引脚。

1.  最后，将逻辑电平转换器的 A1 端口连接到树莓派上的 GPIO 21。

接下来，我们将连接逻辑电平转换器的高电压侧并连接我们的万用表：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/3cba66db-ca8d-4f09-b510-609e190d5049.png)

图 6.14 - 可视化 3.3 伏特到 5 伏特电平转换（第二部分）

以下是要遵循的第二组步骤。这里的步骤编号与前图中显示的编号黑色圆圈相匹配：

1.  将右侧电源轨道上的正电源连接到树莓派的 5 伏特引脚。我们将称这条轨道为*高电压轨道*，因为它将连接到我们供电电压中较高的那个（即 5 伏特）。HV 端子是逻辑电平转换器的高电压侧电源输入端子。

1.  将*高电压轨道*的负电源连接到*低电压轨道*的负电源。你可能还记得所有 GND 连接在电路中是共用的。如果你需要关于这个概念的复习，请回顾第二章中的*引入地面连接和符号*部分。

1.  将逻辑电平转换器的 HV 端子连接到*高电压轨道*的正电源。

1.  将逻辑电平转换器高电压侧的 GND 端子连接到*高电压轨道*的负电源。

1.  将你的万用表的*电压*测量端子连接到逻辑电平转换器的 B1 端口。

1.  将你的万用表的*com*端子连接到*高电压轨道*的负电源。

1.  最后，将你的万用表设置为电压模式。

现在我们已经搭建好了电路，让我们运行一个 Python 程序，并确认当 GPIO 21 为高电平时，我们的万用表读取到了~5 伏特。以下是我们需要做的：

1.  运行`chapter06/digital_output_test.py`文件中的代码 - 这是我们之前在*数字输出*部分使用的相同代码。

1.  在低电压侧，我们的树莓派在通道 1 端口 A1 上的 GPIO 21 之间脉冲低（0 伏特）和高（3.3 伏特），而在高电压侧，我们的万用表连接到通道 1 端口 B1，将在 0 伏特和~5 伏特之间交替，说明了 3.3 伏特逻辑电平高到 5 伏特逻辑电平高的转变。

反向场景也是可能的；也就是说，如果你在高电压侧应用了 5 伏特输入，它将被转换成 3.3 伏特在低电压侧，这可以安全地被 3.3 伏特的树莓派 GPIO 引脚读取。

构建这个反向场景是一个你可能想要自己尝试的练习 - 你已经有了核心知识、代码和电路来实现这一点；你只需要把它全部连接起来！我鼓励你尝试一下，并为了帮助你开始，这里有一些提示：

+   在你的面包板上放置一个按钮和上拉电阻，并将其连接到逻辑电平转换器高电压侧的 B1 端口。这个电路（在原理上）与你之前在*图 6.6*中看到的是相同的，只是现在的电源是 5 伏特，GPIO 引脚现在是 B1 端口。

+   要测试你的电路，你可以使用我们之前使用的相同的数字输入代码，可以在`chapter06/digital_input_test.py`文件中找到。

+   如果你遇到困难，需要参考面包板布局，或者希望检查你的电路搭建，你可以在`chapter06/logic_level_input_breadboard.png`文件中找到一个面包板布局。

当使用逻辑电平转换器 IC、分立模块或电压分压器作为电平转换器时，始终在连接到外部电路或树莓派之前用万用表测试输入/输出电压。这个检查将确保你已经正确连接了转换器，并且电压已经按照你的意图进行了转换。

让我们通过比较我们所看到的两种方法来结束我们对电平转换的讨论。

## 比较电压分压器和逻辑电平转换器

一个方法比另一个更好吗？这取决于情况，尽管我会说一个专用的转换器总是比基本的电压分压器更出色，而且它们在面包板上使用起来更方便。电压分压器更便宜，但只能在一个方向上工作（你需要两个电压分压器电路来执行双向 I/O）。它们还具有相对较高的电阻，这意味着在可变电阻改变和可测电压改变之间会发生实际的延迟。这种延迟足以使简单的电压分压器在高低状态之间快速切换的电路中变得不切实际。一个专用的逻辑电平转换器克服了这些限制，而且它们是多通道、双向、更快和更高效的。

# 总结

本章以对你在进一步学习电子学和我们将在*第三部分*中涵盖的电路中所需的基本工具和设备的快速概述开始（我们将在下一章开始）。然后，我们提出了一些建议，以帮助您在连接电子设备到树莓派的 GPIO 引脚时保持安全，以及在购买元件时的一些建议。

然后，我们探讨了欧姆定律（和非常简要地基尔霍夫定律），然后通过原因和计算来解释为什么我们的 LED 电路使用了 200 欧姆的电阻。我们通过查看数字电路的电子特性来跟进这个例子，其中我们探讨了逻辑电压电平、悬空引脚和上拉和下拉电阻。然后，我们查看了模拟电路，并通过一个电压分压器电路的例子来进行了工作。我们通过查看逻辑电平转换来结束了本章，并介绍了如何将 5 伏逻辑设备与 3.3 伏逻辑设备（如您的树莓派）进行接口。

本章的目标是向您介绍支撑基本电子学和特别是与树莓派等设备的电子接口的基本电子原理。我还努力解释了这些原理背后的基本*为什么*，以及它们如何影响为电路选择哪些元件。有了这些信息，您现在应该能够更好地理解如何构建与您的树莓派配合工作的简单电路。

此外，您可以利用这一理解作为进一步发展和提高您的电子技能的起点。在*进一步阅读*部分，您会找到一些有用的电子网站的链接，而且在我们继续*第三部分* *物联网游乐场*时，我们会看到这些原则的许多应用。

当你准备好开始时，我会在下一章见到你——这也是*第三部分* *物联网游乐场*的开始——在那里我们将探索不同的开关方法。

# 问题

随着我们的结束，这里有一些问题供你测试对本章材料的了解。你会在书的*评估*部分找到答案：

1.  你有一个需要 200Ω电阻的电路，但你只有一个 330Ω的电阻可用。使用这个值安全吗？

1.  你在电路中用一个更高阻值的电阻代替，但电路却无法工作。根据欧姆定律，可能出了什么问题？

1.  您使用欧姆定律计算了电路的合适电阻值，但当您给电路加电时，电阻开始变色并冒烟。为什么？

1.  假设 GPIO 21 通过 Python 配置为输入引脚，并且通过一根导线直接连接到+3.3 伏引脚，`pi.read(21)`会返回什么值？

1.  你设置了一个按钮，当按下时，它将 GPIO 21 连接到 GND 引脚。当按钮*没有*被按下时，你会注意到你的程序表现不稳定，并且似乎接收到了一个幻象按钮按下。问题可能是什么？

1.  你想将一个输出引脚在 5 伏特操作的设备安全地连接到树莓派的 GPIO 输入引脚。你可以如何安全地做到这一点？

1.  真或假 - 电阻器电压分压电路可以用于将 3.3 伏特输入转换为 5 伏特，以用于 5 伏特逻辑输入设备。

# 进一步阅读

以下两个网站是电子制造商，它们都提供了广泛的入门到中级教程。它们侧重于电子学的实际方面，不会向你灌输太多理论。在它们的网站上搜索*Raspberry Pi*试试：

+   [`learn.adafruit.com`](https://learn.adafruit.com/)

+   [`learn.sparkfun.com`](https://learn.sparkfun.com/)

关于本章涵盖的概念，以下是上述网站上的一些具体链接：

+   关于 LED 的一切：[`learn.sparkfun.com/tutorials/light-emitting-diodes-leds`](https://learn.sparkfun.com/tutorials/light-emitting-diodes-leds)

+   欧姆定律、功率和基尔霍夫定律入门：[`learn.sparkfun.com/tutorials/voltage-current-resistance-and-ohms-law`](https://learn.sparkfun.com/tutorials/voltage-current-resistance-and-ohms-law)

+   电压分压器：[`learn.sparkfun.com/tutorials/voltage-dividers`](https://learn.sparkfun.com/tutorials/voltage-dividers)

+   上拉/下拉电阻：[`learn.sparkfun.com/tutorials/pull-up-resistors/all`](https://learn.sparkfun.com/tutorials/pull-up-resistors/all)

+   电阻和色码：[`learn.sparkfun.com/tutorials/resistors`](https://learn.sparkfun.com/tutorials/resistors)

如果你想深入了解，以下两个网站是优秀的（并且免费）资源，涵盖了电子基础和理论的各种主题：

+   [`www.allaboutcircuits.com`](https://www.allaboutcircuits.com/textbook/)

+   [`www.electronics-tutorials.ws`](https://www.electronics-tutorials.ws/)

我建议花一些时间在这些网站上浏览一下，了解它们包含的内容。这样，如果你在这本书中遇到想进一步探索的电子术语、元件或概念，你就会知道从哪里开始调查。以下是两个开始探索的链接：

+   [`www.electronics-tutorials.ws/category/dccircuits`](https://www.electronics-tutorials.ws/category/dccircuits)（直流电路理论）

+   [`www.allaboutcircuits.com/textbook/direct-current`](https://www.allaboutcircuits.com/textbook/direct-current/)（直流电路理论）

如果你浏览这些网站的索引，你会发现包括欧姆定律、功率、基尔霍夫定律、电压分压器以及数字和模拟电子学在内的部分。
