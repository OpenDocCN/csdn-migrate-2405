# 精通 Python 网络编程第二版（一）

> 原文：[`zh.annas-archive.org/md5/dda7e4d1dd78bc5577547014ce9b53d1`](https://zh.annas-archive.org/md5/dda7e4d1dd78bc5577547014ce9b53d1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

正如查尔斯·狄更斯在《双城记》中写道，“这是最好的时代，也是最坏的时代，这是智慧的时代，也是愚蠢的时代。”他看似矛盾的话语完美地描述了变革和过渡时期的混乱和情绪。毫无疑问，我们正在经历网络工程领域的快速变化。随着软件开发在网络的各个方面变得更加集成，传统的命令行界面和垂直集成的网络堆栈方法不再是管理今天网络的最佳方式。对于网络工程师来说，我们所看到的变化充满了兴奋和机遇，但对于那些需要快速适应和跟上的人来说，也是具有挑战性的。本书旨在通过提供一个实用指南来帮助网络专业人士缓解过渡，解决如何从传统平台发展到基于软件驱动实践的问题。

在这本书中，我们使用 Python 作为首选的编程语言，以掌握网络工程任务。Python 是一种易于学习的高级编程语言，可以有效地补充网络工程师的创造力和问题解决能力，以简化日常操作。Python 正在成为许多大型网络的一个组成部分，通过这本书，我希望与您分享我所学到的经验。

自第一版出版以来，我已经与许多读者进行了有趣而有意义的交流。第一版书的成功让我感到谦卑，并且我对所得到的反馈非常重视。在第二版中，我尝试使示例和技术更加相关。特别是，传统的 OpenFlow SDN 章节被一些网络 DevOps 工具所取代。我真诚地希望新的内容对你有所帮助。

变革的时代为技术进步提供了巨大的机遇。本书中的概念和工具在我的职业生涯中帮助了我很多，我希望它们也能对你有同样的帮助。

# 这本书适合谁

这本书非常适合已经管理网络设备组并希望扩展他们对使用 Python 和其他工具克服网络挑战的知识的 IT 专业人员和运维工程师。建议具有网络和 Python 的基本知识。

# 本书涵盖内容

第一章，*TCP/IP 协议套件和 Python 回顾*，回顾了构成当今互联网通信的基本技术，从 OSI 和客户端-服务器模型到 TCP、UDP 和 IP 协议套件。本章将回顾 Python 语言的基础知识，如类型、运算符、循环、函数和包。

第二章，*低级网络设备交互*，使用实际示例说明如何使用 Python 在网络设备上执行命令。它还将讨论在自动化中仅具有 CLI 界面的挑战。本章将使用 Pexpect 和 Paramiko 库进行示例。

第三章，*API 和意图驱动的网络*，讨论了支持**应用程序编程接口**（**API**）和其他高级交互方法的新型网络设备。它还说明了允许在关注网络工程师意图的同时抽象低级任务的工具。本章将使用 Cisco NX-API、Juniper PyEZ 和 Arista Pyeapi 的讨论和示例。

第四章，《Python 自动化框架- Ansible 基础》，讨论了 Ansible 的基础知识，这是一个基于 Python 的开源自动化框架。Ansible 比 API 更进一步，专注于声明性任务意图。在本章中，我们将介绍使用 Ansible 的优势、其高级架构，并展示一些与思科、Juniper 和 Arista 设备一起使用 Ansible 的实际示例。

第五章，《Python 自动化框架-进阶》，在前一章的基础上，涵盖了更高级的 Ansible 主题。我们将介绍条件、循环、模板、变量、Ansible Vault 和角色。还将介绍编写自定义模块的基础知识。

第六章，《Python 网络安全》，介绍了几种 Python 工具，帮助您保护网络。将讨论使用 Scapy 进行安全测试，使用 Ansible 快速实施访问列表，以及使用 Python 进行网络取证分析。

第七章，《Python 网络监控-第 1 部分》，涵盖了使用各种工具监控网络。本章包含了一些使用 SNMP 和 PySNMP 进行查询以获取设备信息的示例。还将展示 Matplotlib 和 Pygal 示例来绘制结果。本章将以使用 Python 脚本作为输入源的 Cacti 示例结束。

第八章，《Python 网络监控-第 2 部分》，涵盖了更多的网络监控工具。本章将从使用 Graphviz 根据 LLDP 信息绘制网络开始。我们将继续使用推送式网络监控的示例，使用 Netflow 和其他技术。我们将使用 Python 解码流数据包和 ntop 来可视化结果。还将概述 Elasticsearch 以及如何用于网络监控。

第九章，《使用 Python 构建网络 Web 服务》，向您展示如何使用 Python Flask Web 框架为网络自动化创建自己的 API。网络 API 提供了诸如将请求者与网络细节抽象化、整合和定制操作以及通过限制可用操作的暴露来提供更好的安全性等好处。

第十章，《AWS 云网络》，展示了如何使用 AWS 构建一个功能齐全且具有弹性的虚拟网络。我们将介绍诸如 CloudFormation、VPC 路由表、访问列表、弹性 IP、NAT 网关、Direct Connect 等虚拟私有云技术以及其他相关主题。

第十一章，《使用 Git 工作》，我们将说明如何利用 Git 进行协作和代码版本控制。本章将使用 Git 进行网络操作的实际示例。

第十二章，《Jenkins 持续集成》，使用 Jenkins 自动创建操作流水线，可以节省时间并提高可靠性。

第十三章，《网络的测试驱动开发》，解释了如何使用 Python 的 unittest 和 PyTest 创建简单的测试来验证我们的代码。我们还将看到编写用于验证可达性、网络延迟、安全性和网络事务的网络测试的示例。我们还将看到如何将这些测试集成到 Jenkins 等持续集成工具中。

# 为了充分利用本书

为了充分利用本书，建议具备一些基本的网络操作知识和 Python 知识。大多数章节可以任意顺序阅读，但第四章和第五章必须按顺序阅读。除了书的开头介绍的基本软件和硬件工具外，每个章节还会介绍与该章节相关的新工具。

强烈建议按照自己的网络实验室中显示的示例进行跟踪和练习。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  登录或注册网址为[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在“搜索”框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Mastering-Python-Networking-Second-Edition`](https://github.com/PacktPublishing/Mastering-Python-Networking-Second-Edition)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在此处下载：[`www.packtpub.com/sites/default/files/downloads/MasteringPythonNetworkingSecondEdition_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/MasteringPythonNetworkingSecondEdition_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如：“自动配置还生成了`vty`访问，用于 telnet 和 SSH。”

代码块设置如下：

```py
# This is a comment
print("hello world")
```

任何命令行输入或输出都按照以下格式编写：

```py
$ python
Python 2.7.12 (default, Dec 4 2017, 14:50:18)
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> exit()
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。例如：“在‘拓扑设计’选项中，我将‘管理网络’选项设置为‘共享平面网络’，以便在虚拟路由器上使用 VMnet2 作为管理网络。”

警告或重要提示会以这种形式出现。提示和技巧会以这种形式出现。


# 第一章：TCP/IP 协议套件和 Python 的回顾

欢迎来到网络工程的新时代。18 年前，也就是在千禧年之交，我开始担任网络工程师时，这个角色与其他技术角色有着明显的不同。网络工程师主要具有领域特定的知识，用于管理和操作局域网和广域网，偶尔会涉足系统管理，但没有写代码或理解编程概念的期望。现在情况已经不同了。多年来，DevOps 和软件定义网络（SDN）运动等因素显著地模糊了网络工程师、系统工程师和开发人员之间的界限。

您拿起这本书的事实表明您可能已经是网络 DevOps 的采用者，或者您正在考虑走这条路。也许您已经作为网络工程师工作了多年，就像我一样，想知道 Python 编程语言的热度是怎么回事。或者您可能已经精通 Python，但想知道它在网络工程中的应用。如果您属于这些人群，或者只是对网络工程领域中的 Python 感到好奇，我相信这本书适合您：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/dce15e34-48e7-47b4-91ef-fb54268aa5f0.png)Python 和网络工程的交集

已经有很多深入探讨网络工程和 Python 主题的书籍。我不打算在本书中重复他们的努力。相反，本书假设您有一些管理网络的实际经验，以及对网络协议和 Python 语言的基本理解。您不需要成为 Python 或网络工程的专家，但应该发现本章中的概念构成了一个概括性的回顾。本章的其余部分应该设定了对先前知识的期望水平，以便从本书中获得最大的收获。如果您想复习本章的内容，有很多免费或低成本的资源可以帮助您迅速掌握。我建议使用免费的可汗学院（[`www.khanacademy.org/)`](https://www.khanacademy.org/)和 Python 教程：[`www.python.org/.`](https://www.python.org/)

本章将快速介绍相关的网络主题。根据我在这个领域工作的经验，一个典型的网络工程师或开发人员可能不记得确切的 TCP 状态机来完成他们的日常任务（我知道我不记得），但他们会熟悉 OSI 模型的基础知识、TCP 和 UDP 的操作、不同的 IP 头字段以及其他基本概念。

我们还将对 Python 语言进行高层次的概述；对于那些不是每天都用 Python 编码的读者来说，这足够让他们在本书的其余部分有所准备。

具体来说，我们将涵盖以下主题：

+   互联网概述

+   OSI 和客户端-服务器模型

+   TCP、UDP 和 IP 协议套件

+   Python 语法、类型、运算符和循环

+   使用函数、类和包扩展 Python

当然，本章中提供的信息并不是详尽无遗的；请查看参考资料以获取更多信息。

# 互联网概述

什么是互联网？这个看似简单的问题可能会因你的背景而得到不同的答案。互联网对不同的人意味着不同的东西；年轻人、老年人、学生、教师、商人、诗人，都可能对这个问题给出不同的答案。

对于网络工程师来说，互联网是一个全球计算机网络，由一系列互联网络连接大大小小的网络。换句话说，它是一个没有集中所有者的网络。以您的家庭网络为例。它可能由家用以太网交换机和无线接入点组成，将您的智能手机、平板电脑、计算机和电视连接在一起，以便设备之间进行通信。这就是您的**局域网**（**LAN**）。当您的家庭网络需要与外部世界通信时，它会将信息从您的 LAN 传递到一个更大的网络，通常称为**互联网服务提供商**（**ISP**）。您的 ISP 通常由边缘节点组成，这些节点将流量聚合到其核心网络中。核心网络的功能是通过更高速的网络连接这些边缘网络。在特定的边缘节点，您的 ISP 连接到其他 ISP，以适当地将您的流量传递到目的地。从目的地返回到您的家用计算机、平板电脑或智能手机的路径可能会或可能不会沿着同样的路径穿过所有这些网络返回到您的设备，而源和目的地保持不变。

让我们来看看构成这个网络之网的组件。

# 服务器、主机和网络组件

**主机**是网络上的终端节点，与其他节点进行通信。在今天的世界中，主机可以是传统计算机，也可以是您的智能手机、平板电脑或电视。随着**物联网**（**IoT**）的兴起，主机的广义定义可以扩展到包括 IP 摄像机、电视机顶盒以及我们在农业、农场、汽车等领域使用的越来越多类型的传感器。随着连接到互联网的主机数量的激增，所有这些主机都需要被寻址、路由和管理。对适当的网络需求从未如此迫切。

我们在互联网上大部分时间都是在请求服务。这可能是查看网页，发送或接收电子邮件，传输文件等。这些服务是由**服务器**提供的。顾名思义，服务器为多个节点提供服务，并且通常具有更高级别的硬件规格。在某种程度上，服务器是网络上提供额外功能的特殊超级节点。我们将在客户端-服务器模型部分稍后讨论服务器。

如果您将服务器和主机视为城市和城镇，**网络组件**就是连接它们的道路和高速公路。事实上，在描述跨越全球传输不断增加的比特和字节的网络组件时，信息高速公路这个术语就会浮现在脑海中。在我们稍后将要看到的 OSI 模型中，这些网络组件是第一到第三层设备。它们是第二和第三层的路由器和交换机，用于指导流量，以及第一层的传输设备，如光纤电缆、同轴电缆、双绞铜线和一些 DWDM 设备，等等。

总的来说，主机、服务器和网络组件构成了我们今天所知的互联网。

# 数据中心的崛起

在上一节中，我们看到了服务器、主机和网络组件在互联网中扮演的不同角色。由于服务器需要更高的硬件容量，它们通常被放在一个中央位置，以便更有效地进行管理。我们经常将这些位置称为数据中心。

# 企业数据中心

在典型的企业中，公司通常需要内部工具，如电子邮件、文档存储、销售跟踪、订购、人力资源工具和知识共享内部网。这些服务转化为文件和邮件服务器、数据库服务器和 Web 服务器。与用户计算机不同，这些通常是需要大量电力、冷却和网络连接的高端计算机。硬件的副产品也是它们产生的噪音量。它们通常被放置在企业的中心位置，称为主配线架（MDF），以提供必要的电力供应、电力冗余、冷却和网络连接。

为了连接到 MDF，用户的流量通常会在距离用户更近的位置进行聚合，有时被称为中间分配框架（IDF），然后再捆绑并连接到 MDF。 IDF-MDF 的分布通常遵循企业建筑或校园的物理布局。例如，每个楼层可以包括一个 IDF，它会聚合到另一楼层的 MDF。如果企业由多栋建筑组成，可以通过将建筑的流量组合起来，然后连接到企业数据中心来进一步进行聚合。

企业数据中心通常遵循三层网络设计。这些层是接入层、分发层和核心层。接入层类似于每个用户连接的端口，IDF 可以被视为分发层，而核心层包括与 MDF 和企业数据中心的连接。当然，这是企业网络的概括，因为其中一些网络将不会遵循相同的模型。

# 云数据中心

随着云计算和软件或基础设施即服务的兴起，云提供商建立的数据中心规模庞大。由于它们所容纳的服务器数量，它们通常对电力、冷却、网络速度和供电需求远远高于任何企业数据中心。即使在云提供商数据中心工作多年后，每次我访问云提供商数据中心时，我仍然对它们的规模感到惊讶。事实上，云数据中心如此庞大且耗电量巨大，它们通常建在靠近发电厂的地方，以获得最便宜的电力费率，而在输电过程中不会损失太多效率。它们的冷却需求如此之大，有些被迫在建造数据中心时寻求创意，选择建在通常气候寒冷的地方，这样他们就可以在需要时打开门窗，保持服务器以安全温度运行。任何搜索引擎都可以给出一些惊人的数字，涉及为亚马逊、微软、谷歌和 Facebook 等公司建造和管理云数据中心的科学：

犹他数据中心（来源：https://en.wikipedia.org/wiki/Utah_Data_Center）

在云提供商的规模下，它们需要提供的服务通常不具备成本效益，或者无法合理地容纳在单个服务器中。它们分布在一群服务器之间，有时跨越许多不同的机架，以提供冗余和灵活性给服务所有者。延迟和冗余要求对网络施加了巨大的压力。互连的数量相当于网络设备的爆炸性增长；这意味着这些网络设备需要被装架、配置和管理的次数。典型的网络设计是多级 CLOS 网络：

CLOS 网络

在某种程度上，云数据中心是网络自动化成为速度和可靠性的必要性的地方。如果我们按照传统的方式通过终端和命令行界面管理网络设备，所需的工程小时数将不允许服务在合理的时间内可用。更不用说人类的重复是容易出错、低效和工程人才的可怕浪费。

云数据中心是我多年前开始使用 Python 进行网络自动化的地方，自那以后我就再也没有回头过。

# 边缘数据中心

如果我们在数据中心级别有足够的计算能力，为什么还要将任何东西放在数据中心之外呢？来自世界各地的客户的所有连接都可以路由回提供服务的数据中心服务器，我们就可以结束一天了，对吗？当然，答案取决于用例。将请求和会话从客户端一直路由到大型数据中心的最大限制是传输中引入的延迟。换句话说，大延迟是网络成为瓶颈的地方。延迟数字永远不会为零：即使光在真空中传播得很快，物理传输也需要时间。在现实世界中，当数据包穿过多个网络时，有时还穿过海底电缆、慢速卫星链路、3G 或 4G 蜂窝链路或 Wi-Fi 连接时，延迟会比真空中的光要高得多。

解决方案？减少终端用户穿越的网络数量。尽可能与用户在用户进入您的网络的边缘处紧密连接，并在边缘位置放置足够的资源来提供服务。让我们花一分钟想象一下，您正在构建下一代视频流媒体服务。为了提高顾客对流畅播放的满意度，您会希望将视频服务器尽可能靠近客户，要么在客户的 ISP 内部，要么非常靠近客户的 ISP。此外，视频服务器农场的上游不仅连接到一个或两个 ISP，而是连接到我可以连接的所有 ISP，以减少跳数。所有连接都将具有所需的带宽，以在高峰时段减少延迟。这种需求催生了大型 ISP 和内容提供商的对等交换边缘数据中心。即使网络设备的数量不像云数据中心那样多，它们也可以从网络自动化中受益，因为网络自动化带来了增加的可靠性、安全性和可见性。

我们将在本书的后面章节中涵盖安全性和可见性。

# OSI 模型

没有网络书籍是完整的，没有先讨论**开放系统互连**（**OSI**）模型。该模型是一个概念模型，将电信功能组件化为不同的层。该模型定义了七个层，每个层都独立地位于另一个层的顶部，只要它们遵循定义的结构和特征。例如，在网络层，IP 可以位于不同类型的数据链路层的顶部，如以太网或帧中继。OSI 参考模型是将不同和多样的技术规范化为一组人们可以达成一致的共同语言的好方法。这大大减少了在各自层上工作的各方的范围，并允许他们深入研究特定任务，而不用太担心兼容性。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/762c9bbe-cd1f-4546-a2a7-2725a7caa3e9.png)OSI 模型

OSI 模型最初是在 20 世纪 70 年代后期进行研究的，后来由**国际标准化组织**（**ISO**）和现在被称为**国际电信联盟**（**ITU-T**）的**电信标准化部门**联合出版。它被广泛接受，并在引入电信新主题时通常被引用。

在 OSI 模型开发的同时期，互联网正在形成。原始设计者使用的参考模型通常被称为 TCP/IP 模型。传输控制协议（TCP）和互联网协议（IP）是最初包含在设计中的协议套件。这在某种程度上类似于 OSI 模型，因为它们将端到端数据通信分为抽象层。不同的是，该模型将 OSI 模型中的第 5 至 7 层合并为应用层，而物理层和数据链路层合并为链路层。

互联网协议套件

OSI 和 TCP/IP 模型都对提供端到端数据通信的标准很有用。然而，大部分时间我们将更多地参考 TCP/IP 模型，因为互联网就是建立在这个模型上的。当我们讨论即将到来的章节中的 Web 框架时，我们将指定 OSI 模型。

# 客户端-服务器模型

参考模型展示了数据在两个节点之间进行通信的标准方式。当然，到现在为止，我们都知道，并非所有节点都是平等的。即使在 DARPA 网络的早期，也有工作站节点，也有目的是向其他节点提供内容的节点。这些服务器节点通常具有更高的硬件规格，并由工程师更密切地管理。由于这些节点向其他节点提供资源和服务，它们通常被称为服务器。服务器通常处于空闲状态，等待客户端发起对其资源的请求。这种由客户端请求的分布式资源模型被称为客户端-服务器模型。

为什么这很重要？如果你仔细想一想，客户端-服务器模型凸显了网络的重要性。没有它，网络互连的需求其实并不是很大。正是客户端向服务器传输比特和字节的需求，突显了网络工程的重要性。当然，我们都知道，最大的网络——互联网，一直在改变我们所有人的生活，并持续不断地这样做。

你可能会问，每个节点如何确定每次需要相互通信时的时间、速度、源和目的地？这就引出了网络协议。

# 网络协议套件

在计算机网络的早期，协议是专有的，并由设计连接方法的公司严格控制。如果您在主机中使用 Novell 的 IPX/SPX 协议，您将无法与苹果的 AppleTalk 主机进行通信，反之亦然。这些专有协议套件通常与 OSI 参考模型具有类似的层，并遵循客户端-服务器通信方法。它们通常在局域网（LAN）中运行良好，这些局域网是封闭的，无需与外部世界通信。当流量需要移动到本地局域网之外时，通常会使用互联网设备，如路由器，来将一个协议转换为另一个协议。例如，路由器连接 AppleTalk 网络到基于 IP 的网络。翻译通常不完美，但由于在早期大部分通信发生在局域网内，这是可以接受的。

然而，随着对局域网之外的互联网通信需求的增加，标准化网络协议套件的需求变得更加迫切。专有协议最终让位于 TCP、UDP 和 IP 的标准化协议套件，这极大地增强了一个网络与另一个网络进行通信的能力。互联网，所有网络中最伟大的网络，依赖这些协议来正常运行。在接下来的几节中，我们将看一下每个协议套件。

# 传输控制协议

**传输控制协议**（**TCP**）是今天互联网上使用的主要协议之一。如果您打开过网页或发送过电子邮件，您就已经接触过 TCP 协议。该协议位于 OSI 模型的第 4 层，负责以可靠和经过错误检查的方式在两个节点之间传递数据段。TCP 由一个包括源端口、目的端口、序列号、确认号、控制标志和校验和在内的 160 位标头组成：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/c505f800-db13-46d6-b706-c5c3bf1f94e8.png)TCP 标头

# TCP 的功能和特性

TCP 使用数据报套接字或端口来建立主机之间的通信。称为**Internet Assigned Numbers Authority**（**IANA**）的标准机构指定了知名端口，以指示特定服务，例如端口`80`用于 HTTP（web），端口`25`用于 SMTP（邮件）。在客户端-服务器模型中，服务器通常在这些知名端口之一上监听，以便接收来自客户端的通信请求。TCP 连接由操作系统通过表示连接的本地端点的套接字来管理。

协议操作由一个状态机组成，其中状态机需要跟踪何时正在监听传入连接，以及在通信会话期间释放资源。每个 TCP 连接都经历一系列状态，如`Listen`，`SYN-SENT`，`SYN-RECEIVED`，`ESTABLISHED`，`FIN-WAIT`，`CLOSE-WAIT`，`CLOSING`，`LAST-ACK`，`TIME-WAIT`和`CLOSED`。

# TCP 消息和数据传输

TCP 和**用户数据报协议**（**UDP**）之间最大的区别是，TCP 以有序和可靠的方式传输数据。操作保证传递通常被称为 TCP 是一种面向连接的协议。它通过首先建立三次握手来同步发送方和接收方之间的序列号`SYN`，`SYN-ACK`和`ACK`来实现这一点。

确认用于跟踪对话中的后续段。最后，在对话结束时，一方将发送一个`FIN`消息，另一方将`ACK`这个`FIN`消息，并发送自己的`FIN`消息。`FIN`发起方然后将`ACK`收到的`FIN`消息。

正如许多我们曾经排查过 TCP 连接的人所能告诉你的那样，这个操作可能会变得非常复杂。大多数情况下，这个操作只是在后台默默地进行。

关于 TCP 协议可以写一整本书；事实上，已经有许多优秀的书籍写就了这个协议。

由于本节是一个快速概述，如果感兴趣，可以使用 TCP/IP 指南（[`www.tcpipguide.com/`](http://www.tcpipguide.com/)）这个优秀的免费资源来深入了解这个主题。

# 用户数据报协议

**用户数据报协议**（**UDP**）也是互联网协议套件的核心成员之一。与 TCP 一样，它在 OSI 模型的第 4 层上运行，负责在应用程序和 IP 层之间传递数据段。与 TCP 不同的是，UDP 的标头只有 64 位，其中只包括源端口、目的端口、长度和校验和。轻量级的标头使其非常适合那些更喜欢快速数据传递而不需要在两个主机之间建立会话或需要可靠数据传递的应用程序。也许在今天快速的互联网连接下很难想象，但在 X.21 和帧中继链路的早期，额外的标头对传输速度产生了很大影响。尽管速度差异同样重要，但与 TCP 一样，不必维护各种状态也节省了两个端点的计算机资源：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/3ef8b6dc-c13e-4091-b48b-a9f5a882a35a.png)UDP 标头

您可能会想为什么在现代时代还要使用 UDP；考虑到可靠传输的缺乏，我们难道不希望所有连接都是可靠且无错误的吗？如果考虑多媒体视频流或 Skype 通话，这些应用程序受益于轻量级标头，因为应用程序只是希望尽快传递数据报。您还可以考虑基于 UDP 协议的快速 DNS 查找过程。当您在浏览器中输入的地址被转换为计算机可理解的地址时，用户将受益于轻量级过程，因为这必须在您从您喜爱的网站接收到第一个比特之前发生。

再次强调，本节对 UDP 的主题并不充分，鼓励读者通过各种资源探索该主题，如果您对学习更多关于 UDP 感兴趣的话。

# 互联网协议

正如网络工程师所说，他们活在**互联网协议**（IP）层，这是 OSI 模型的第 3 层。**IP**的工作是在终端节点之间进行寻址和路由等。IP 的寻址可能是它最重要的工作。地址空间分为两部分：网络部分和主机部分。子网掩码用于指示网络地址中的网络部分和主机部分，通过将网络部分与 1 匹配，主机部分与 0 匹配。IPv4 和后来的 IPv6 都以点分表示法表示地址，例如`192.168.0.1`。子网掩码可以以点分表示法（`255.255.255.0`）或使用斜杠表示应考虑的网络位数（/24）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/86dd4756-3682-4a2d-89e9-5e8cd3eeae43.png)IPv4 头部

IPv6 头部是 IPv4 的 IP 头部的下一代，具有固定部分和各种扩展标头：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/04eb0dd0-5fb9-4c7b-8dbf-deac8eb97cdb.png)IPv6 固定头部

固定头部中的**下一个标头**字段可以指示后续携带附加信息的扩展标头。扩展标头可以包括路由和分段信息。尽管协议设计者希望从 IPv4 转移到 IPv6，但今天的互联网仍然主要使用 IPv4 进行寻址，部分服务提供商网络内部使用 IPv6 进行寻址。

# IP NAT 和安全

**网络地址转换**（**NAT**）通常用于将一系列私有 IPv4 地址转换为公共可路由的 IPv4 地址。但它也可以意味着 IPv4 到 IPv6 之间的转换，例如在运营商边缘使用 IPv6 内部网络需要转换为 IPv4 时。有时也出于安全原因使用 NAT6 到 6。

安全是一个持续的过程，整合了网络的所有方面，包括自动化和 Python。本书旨在使用 Python 帮助您管理网络；安全将作为本书后续章节的一部分进行讨论，例如使用 SSHv2 替代 telnet。我们还将探讨如何使用 Python 和其他工具来获得网络的可见性。

# IP 路由概念

在我看来，IP 路由是指让两个端点之间的中间设备根据 IP 头部传输数据包。对于所有通过互联网进行的通信，数据包将通过各种中间设备传输。如前所述，中间设备包括路由器、交换机、光学设备和其他不会检查网络和传输层以外内容的设备。用一种道路旅行的类比来说，你可能会从加利福尼亚州的圣迭戈市到华盛顿州的西雅图市旅行。IP 源地址类似于圣迭戈，目的地 IP 地址可以被视为西雅图。在你的旅行中，你会经过许多不同的中间地点，比如洛杉矶、旧金山和波特兰；这些可以被视为源地址和目的地之间的路由器和交换机。

为什么这很重要？在某种程度上，这本书是关于管理和优化这些中间设备。在跨越多个美式橄榄球场大小的超大数据中心时代，高效、灵活、可靠和具有成本效益的网络管理方式成为公司的竞争优势的重要点。在未来的章节中，我们将深入探讨如何使用 Python 编程有效地管理网络。

# Python 语言概述

简而言之，这本书是关于如何使用 Python 使我们的网络工程生活更轻松。但是 Python 是什么，为什么它是许多 DevOps 工程师的首选语言呢？用 Python 基金会执行摘要的话来说：

“Python 是一种解释型、面向对象的高级编程语言，具有动态语义。它的高级内置数据结构，结合动态类型和动态绑定，使其非常适合快速应用程序开发，以及作为脚本或粘合语言来连接现有组件。Python 的简单、易学的语法强调可读性，因此降低了程序维护的成本。”

如果你对编程还比较陌生，前面提到的面向对象、动态语义可能对你来说意义不大。但我认为我们都可以同意，对于快速应用程序开发来说，简单易学的语法听起来是一件好事。作为一种解释型语言，Python 意味着不需要编译过程，因此编写、测试和编辑 Python 程序的时间大大缩短。对于简单的脚本，如果你的脚本出错，通常只需要一个`print`语句就可以调试出问题所在。使用解释器还意味着 Python 很容易移植到不同类型的操作系统，比如 Windows 和 Linux，一个在一个操作系统上编写的 Python 程序可以在另一个操作系统上使用。

面向对象的特性鼓励通过将大型程序分解为简单可重用的对象来实现代码重用，以及其他可重用的格式，如函数、模块和包。事实上，所有的 Python 文件都是可以被重用或导入到另一个 Python 程序中的模块。这使得工程师之间可以轻松共享程序，并鼓励代码重用。Python 还有一个“电池包含在内”的口号，这意味着对于常见的任务，你不需要下载任何额外的包。为了在不使代码过于臃肿的情况下实现这一点，当你安装 Python 解释器时，一组标准库会被安装。对于常见的任务，比如正则表达式、数学函数和 JSON 解码，你只需要使用`import`语句，解释器就会将这些函数移入你的程序中。这是我认为 Python 语言的一个杀手功能。

最后，Python 代码可以从几行代码的相对小型脚本开始，并逐渐发展成一个完整的生产系统，对于网络工程师来说非常方便。正如我们许多人所知，网络通常是在没有总体规划的情况下有机地发展的。一种可以随着网络规模增长的语言是非常宝贵的。您可能会惊讶地看到，许多前沿公司（使用 Python 的组织）正在使用被许多人认为是脚本语言的语言来开发完整的生产系统。

如果您曾经在需要在不同的供应商平台上工作时不得不切换，比如 Cisco IOS 和 Juniper Junos，您就知道在尝试完成相同任务时切换语法和用法是多么痛苦。由于 Python 足够灵活，可以用于大型和小型程序，因此没有这种上下文切换，因为它只是 Python。

在本章的其余部分，我们将对 Python 语言进行高层次的介绍，以便稍作复习。如果您已经熟悉基础知识，可以快速浏览或跳过本章的其余部分。

# Python 版本

许多读者已经意识到，Python 在过去几年中一直在从 Python 2 过渡到 Python 3。 Python 3 于 2008 年发布，已经有 10 多年的历史，最近发布了 3.7 版本。不幸的是，Python 3 与 Python 2 不兼容。在撰写本书第二版时，即 2018 年中期，Python 社区基本上已经转向 Python 3。最新的 Python 2.x 版本 2.7 是在 2010 年中期发布的，已经有 6 年多的历史了。幸运的是，两个版本可以在同一台机器上共存。我个人在命令提示符中输入 Python 时使用 Python 2 作为默认解释器，需要使用 Python 3 时则使用 Python 3。关于调用 Python 解释器的更多信息将在下一节中给出，但这里有一个在 Ubuntu Linux 机器上调用 Python 2 和 Python 3 的示例：

```py
$ python
Python 2.7.12 (default, Dec 4 2017, 14:50:18)
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> exit() 
```

```py
$ python3
Python 3.5.2 (default, Nov 23 2017, 16:37:01)
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> exit() 
```

随着 2.7 版本的终止生命周期，大多数 Python 框架现在支持 Python 3。Python 3 还有许多很好的特性，比如异步 I/O，在需要优化我们的代码时可以利用这些特性。本书的代码示例将使用 Python 3，除非另有说明。我们还将尽量在适用时指出 Python 2 和 Python 3 之间的区别。

如果特定的库或框架更适合 Python 2，比如 Ansible（请参阅以下信息），我们将指出并使用 Python 2。

在撰写本文时，Ansible 2.5 及以上版本支持 Python 3。在 2.5 之前，Python 3 支持被视为技术预览。鉴于相对较新的支持性，许多社区模块仍然需要迁移到 Python 3。有关 Ansible 和 Python 3 的更多信息，请参阅[`docs.ansible.com/ansible/2.5/dev_guide/developing_python_3.html`](https://docs.ansible.com/ansible/2.5/dev_guide/developing_python_3.html)。

# 操作系统

如前所述，Python 是跨平台的。Python 程序可以在 Windows、Mac 和 Linux 上运行。实际上，在需要确保跨平台兼容性时需要注意一些细节，比如在 Windows 文件名中反斜杠的微妙差异。由于本书是为 DevOps、系统和网络工程师编写的，Linux 是预期受众的首选平台，特别是在生产环境中。本书中的代码将在 Linux Ubuntu 16.06 LTS 机器上进行测试。我也会尽力确保代码在 Windows 和 MacOS 平台上运行相同。

如果您对操作系统的详细信息感兴趣，它们如下：

```py
$ uname -a
Linux packt-network-python 4.13.0-45-generic #50~16.04.1-Ubuntu SMP Wed May 30 11:18:27 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux 
```

# 运行 Python 程序

Python 程序由解释器执行，这意味着代码通过解释器传递给底层操作系统执行，并显示结果。Python 开发社区有几种不同的解释器实现，例如 IronPython 和 Jython。在本书中，我们将使用今天最常用的 Python 解释器，即 CPython。在本书中提到 Python 时，我们指的是 CPython，除非另有说明。

您可以使用 Python 的交互式提示符来使用 Python 的一种方式。当您想要快速测试一段 Python 代码或概念而不写整个程序时，这是很有用的。通常只需输入`Python`关键字即可：

```py
Python 3.5.2 (default, Nov 17 2016, 17:05:23)
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for 
more information.
>>> print("hello world")
hello world
>>>
```

在 Python 3 中，`print`语句是一个函数；因此，它需要括号。在 Python 2 中，您可以省略括号。

交互模式是 Python 最有用的功能之一。在交互式 shell 中，您可以输入任何有效的语句或语句序列，并立即得到结果。我通常用它来探索我不熟悉的功能或库。谈论即时满足！

在 Windows 上，如果没有收到 Python shell 提示符，则可能没有将程序添加到系统搜索路径中。最新的 Windows Python 安装程序提供了一个复选框，用于将 Python 添加到系统路径中；确保已经选中。或者您可以通过转到环境设置手动将程序添加到路径中。

然而，运行 Python 程序的更常见的方法是保存您的 Python 文件，并在之后通过解释器运行它。这将使您免于在交互式 shell 中一遍又一遍地输入相同的语句。Python 文件只是通常以`.py`扩展名保存的普通文本文件。在*Nix 世界中，您还可以在顶部添加**shebang**（`#!`）行，以指定将用于运行文件的解释器。`#`字符可用于指定不会被解释器执行的注释。以下文件`helloworld.py`包含以下语句：

```py
# This is a comment
print("hello world") 
```

可以按照以下方式执行：

```py
$ python helloworld.py
hello world
$
```

# Python 内置类型

Python 在解释器中内置了几种标准类型：

+   **None**：`Null`对象

+   **数值**：`int`、`long`、`float`、`complex`和`bool`（带有`True`或`False`值的`int`子类）

+   **序列**：`str`、list、tuple 和 range

+   **映射**：`dict`

+   **集合**：`set`和`frozenset`

# None 类型

`None`类型表示没有值的对象。在不明确返回任何内容的函数中返回`None`类型。`None`类型也用于函数参数，如果调用者没有传入实际值，则会出错。

# 数值

Python 数值对象基本上是数字。除了布尔值外，`int`、`long`、`float`和`complex`这些数值类型都是有符号的，这意味着它们可以是正数或负数。布尔值是整数的一个子类，可以是两个值之一：`True`为`1`，`False`为`0`。其余的数值类型是通过它们能够准确表示数字的方式来区分的；例如，`int`是具有有限范围的整数，而`long`是具有无限范围的整数。浮点数是使用机器上的双精度表示（64 位）的数字。

# 序列

序列是具有非负整数索引的对象的有序集合。在本节和接下来的几节中，我们将使用交互式解释器来说明不同的类型。请随时在您自己的计算机上输入。

有时人们会感到惊讶，`string`实际上是一个序列类型。但是如果你仔细看，字符串是一系列字符组合在一起。字符串可以用单引号、双引号或三引号括起来。请注意，在以下示例中，引号必须匹配，三引号允许字符串跨越不同的行：

```py
>>> a = "networking is fun"
>>> b = 'DevOps is fun too'
>>> c = """what about coding?
... super fun!"""
>>>
```

另外两种常用的序列类型是列表和元组。列表是任意对象的序列。列表可以通过将对象括在方括号中创建。就像字符串一样，列表由从零开始的非零整数索引。通过引用索引号检索列表的值：

```py
>>> vendors = ["Cisco", "Arista", "Juniper"]
>>> vendors[0]
'Cisco'
>>> vendors[1]
'Arista'
>>> vendors[2]
'Juniper'
```

元组类似于列表，通过括号括起的值创建。与列表一样，可以通过引用其索引号来检索元组中的值。与列表不同的是，创建后不能修改值：

```py
>>> datacenters = ("SJC1", "LAX1", "SFO1")
>>> datacenters[0]
'SJC1'
>>> datacenters[1]
'LAX1'
>>> datacenters[2]
'SFO1' 
```

所有序列类型都有一些共同的操作，例如按索引返回元素以及切片：

```py
>>> a
'networking is fun'
>>> a[1]
'e'
>>> vendors
['Cisco', 'Arista', 'Juniper']
>>> vendors[1]
'Arista'
>>> datacenters
('SJC1', 'LAX1', 'SFO1')
>>> datacenters[1]
'LAX1'
>>>
>>> a[0:2]
'ne'
>>> vendors[0:2]
['Cisco', 'Arista']
>>> datacenters[0:2]
('SJC1', 'LAX1')
>>>
```

记住索引从`0`开始。因此，`1`的索引实际上是序列中的第二个元素。

还有一些常见的函数可以应用于序列类型，例如检查元素数量和最小值和最大值：

```py
>>> len(a)
17
>>> len(vendors)
3
>>> len(datacenters)
3
>>>
>>> b = [1, 2, 3, 4, 5]
>>> min(b)
1
>>> max(b)
5
```

毫不奇怪，还有各种方法仅适用于字符串。值得注意的是，这些方法不会修改基础字符串数据本身，并始终返回一个新的字符串。如果您想使用新值，您需要捕获返回值并将其分配给不同的变量：

```py
>>> a
'networking is fun'
>>> a.capitalize()
'Networking is fun'
>>> a.upper()
'NETWORKING IS FUN'
>>> a
'networking is fun'
>>> b = a.upper()
>>> b
'NETWORKING IS FUN'
>>> a.split()
['networking', 'is', 'fun']
>>> a
'networking is fun'
>>> b = a.split()
>>> b
['networking', 'is', 'fun']
>>>
```

以下是列表的一些常用方法。在将多个项目放在一起并逐个迭代它们方面，列表是一种非常有用的结构。例如，我们可以制作一个数据中心脊柱交换机的列表，并通过逐个迭代它们来应用相同的访问列表。由于列表的值可以在创建后修改（与元组不同），因此我们还可以在程序中扩展和对比现有列表：

```py
>>> routers = ['r1', 'r2', 'r3', 'r4', 'r5']
>>> routers.append('r6')
>>> routers
['r1', 'r2', 'r3', 'r4', 'r5', 'r6']
>>> routers.insert(2, 'r100')
>>> routers
['r1', 'r2', 'r100', 'r3', 'r4', 'r5', 'r6']
>>> routers.pop(1)
'r2'
>>> routers
['r1', 'r100', 'r3', 'r4', 'r5', 'r6']
```

# 映射

Python 提供了一种映射类型，称为**字典**。字典是我认为的穷人的数据库，因为它包含可以由键索引的对象。在其他语言中，这通常被称为关联数组或哈希表。如果您在其他语言中使用过类似字典的对象，您将知道这是一种强大的类型，因为您可以使用可读的键引用对象。对于试图维护和排除代码的可怜家伙来说，这个键将更有意义。几个月后，您编写代码并在凌晨 2 点排除故障时，这个家伙可能就是您。字典值中的对象也可以是另一种数据类型，比如列表。您可以用大括号创建一个字典：

```py
>>> datacenter1 = {'spines': ['r1', 'r2', 'r3', 'r4']}
>>> datacenter1['leafs'] = ['l1', 'l2', 'l3', 'l4']
>>> datacenter1
{'leafs': ['l1', 'l2', 'l3', 'l4'], 'spines': ['r1',  
'r2', 'r3', 'r4']}
>>> datacenter1['spines']
['r1', 'r2', 'r3', 'r4']
>>> datacenter1['leafs']
['l1', 'l2', 'l3', 'l4']
```

# 集合

**集合**用于包含无序的对象集合。与列表和元组不同，集合是无序的，不能通过数字索引。但是有一个特点使集合成为有用的：集合的元素永远不会重复。想象一下，您有一个需要放入访问列表中的 IP 列表。这个 IP 列表中唯一的问题是它们充满了重复项。现在，想象一下，您需要使用多少行代码来循环遍历 IP 列表，逐个筛选出唯一的项。然而，内置的集合类型只需要一行代码就可以消除重复的条目。老实说，我并不经常使用集合，但是当我需要它时，我总是非常感激它的存在。一旦创建了集合，它们可以使用并集、交集和差集进行比较：

```py
>>> a = "hello"
>>> set(a)
{'h', 'l', 'o', 'e'}
>>> b = set([1, 1, 2, 2, 3, 3, 4, 4])
>>> b
{1, 2, 3, 4}
>>> b.add(5)
>>> b
{1, 2, 3, 4, 5}
>>> b.update(['a', 'a', 'b', 'b'])
>>> b
{1, 2, 3, 4, 5, 'b', 'a'}
>>> a = set([1, 2, 3, 4, 5])
>>> b = set([4, 5, 6, 7, 8])
>>> a.intersection(b)
{4, 5}
>>> a.union(b)
{1, 2, 3, 4, 5, 6, 7, 8}
>>> 1 *
{1, 2, 3}
>>>
```

# Python 运算符

Python 有一些数字运算符，你会期望的；请注意截断除法（`//`，也称为**地板除法**）将结果截断为整数和浮点数，并返回整数值。取模（`%`）运算符返回除法中的余数值：

```py
>>> 1 + 2
3
>>> 2 - 1
1
>>> 1 * 5
5
>>> 5 / 1
5.0
>>> 5 // 2
2
>>> 5 % 2
1
```

还有比较运算符。请注意，双等号用于比较，单等号用于变量赋值：

```py
>>> a = 1
>>> b = 2
>>> a == b
False
>>> a > b
False
>>> a < b
True
>>> a <= b
True 
```

我们还可以使用两个常见的成员运算符来查看对象是否在序列类型中：

```py
>>> a = 'hello world'
>>> 'h' in a
True
>>> 'z' in a
False
>>> 'h' not in a
False
>>> 'z' not in a
True
```

# Python 控制流工具

`if`、`else`和`elif`语句控制条件代码的执行。正如你所期望的，条件语句的格式如下：

```py
if expression:
  do something
elif expression:
  do something if the expression meets
elif expression:
  do something if the expression meets
...
else:
  statement
```

这是一个简单的例子：

```py
>>> a = 10
>>> if a > 1:
...   print("a is larger than 1")
... elif a < 1:
...   print("a is smaller than 1")
... else:
...   print("a is equal to 1")
...
a is larger than 1
>>>
```

`while`循环将继续执行，直到条件为`false`，所以如果你不想继续执行（并且崩溃你的进程），请小心：

```py
while expression:
  do something
```

```py
>>> a = 10
>>> b = 1
>>> while b < a:
...   print(b)
...   b += 1
...
1
2
3
4
5
6
7
8
9
```

`for`循环适用于任何支持迭代的对象；这意味着所有内置的序列类型，如列表、元组和字符串，都可以在`for`循环中使用。下面`for`循环中的字母`i`是一个迭代变量，所以你通常可以在代码的上下文中选择一个有意义的东西：

```py
for i in sequence:
  do something
```

```py
>>> a = [100, 200, 300, 400]
>>> for number in a:
...   print(number)
...
100
200
300
400
```

你还可以创建自己的对象，支持迭代器协议，并能够为这个对象使用`for`循环。

构建这样一个对象超出了本章的范围，但这是有用的知识；你可以在[`docs.python.org/3/c-api/iter.html`](https://docs.python.org/3/c-api/iter.html)上阅读更多关于它的内容。

# Python 函数

大多数情况下，当你发现自己在复制和粘贴一些代码片段时，你应该将它们分解成一个自包含的函数块。这种做法可以实现更好的模块化，更容易维护，并允许代码重用。Python 函数是使用`def`关键字定义的，后面跟着函数名和函数参数。函数的主体由要执行的 Python 语句组成。在函数的末尾，你可以选择向函数调用者返回一个值，或者默认情况下，如果你没有指定返回值，它将返回`None`对象：

```py
def name(parameter1, parameter2):
  statements
  return value
```

在接下来的章节中，我们将看到更多的函数示例，所以这里是一个快速的例子：

```py
>>> def subtract(a, b):
...   c = a - b
...   return c
...
>>> result = subtract(10, 5)
>>> result
5
>>>
```

# Python 类

Python 是一种**面向对象编程**（**OOP**）语言。Python 创建对象的方式是使用`class`关键字。Python 对象通常是函数（方法）、变量和属性（属性）的集合。一旦类被定义，你就可以创建这样一个类的实例。类作为后续实例的蓝图。

OOP 的主题超出了本章的范围，所以这里是一个`router`对象定义的简单例子：

```py
>>> class router(object):
...   def __init__(self, name, interface_number,
vendor):
...     self.name = name
...     self.interface_number = interface_number
...     self.vendor = vendor
...
>>>
```

一旦定义，你就可以创建任意数量的该类的实例：

```py
>>> r1 = router("SFO1-R1", 64, "Cisco")
>>> r1.name
'SFO1-R1'
>>> r1.interface_number
64
>>> r1.vendor
'Cisco'
>>>
>>> r2 = router("LAX-R2", 32, "Juniper")
>>> r2.name
'LAX-R2'
>>> r2.interface_number
32
>>> r2.vendor
'Juniper'
>>>
```

当然，Python 对象和 OOP 还有很多内容。我们将在以后的章节中看到更多的例子。

# Python 模块和包

任何 Python 源文件都可以用作模块，你在该源文件中定义的任何函数和类都可以被重用。要加载代码，引用模块的文件需要使用`import`关键字。当文件被导入时会发生三件事：

1.  文件为源文件中定义的对象创建了一个新的命名空间

1.  调用者执行模块中包含的所有代码

1.  文件在调用者内创建一个指向被导入模块的名称。名称与模块的名称匹配

还记得你在交互式 shell 中定义的`subtract()`函数吗？为了重用这个函数，我们可以把它放到一个名为`subtract.py`的文件中：

```py
def subtract(a, b):
  c = a - b
  return c
```

在`subtract.py`的同一目录中的文件中，你可以启动 Python 解释器并导入这个函数：

```py
Python 2.7.12 (default, Nov 19 2016, 06:48:10)
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for  
more information.
>>> import subtract
>>> result = subtract.subtract(10, 5)
>>> result
5
```

这是因为默认情况下，Python 首先会在当前目录中搜索可用的模块。如果你在不同的目录中，你可以使用`sys`模块和`sys.path`手动添加搜索路径位置。还记得我们之前提到的标准库吗？你猜对了，那些只是作为模块使用的 Python 文件。

包允许将一组模块组合在一起。这进一步将 Python 模块组织成更具命名空间保护的可重用性。包是通过创建一个希望用作命名空间的名称的目录来定义的，然后可以将模块源文件放在该目录下。为了让 Python 将其识别为 Python 包，只需在该目录中创建一个`__init__.py`文件。在与`subtract.py`文件相同的示例中，如果你创建一个名为`math_stuff`的目录并创建一个`__init__.py`文件：

```py
echou@pythonicNeteng:~/Master_Python_Networking/
Chapter1$ mkdir math_stuff
echou@pythonicNeteng:~/Master_Python_Networking/
Chapter1$ touch math_stuff/__init__.py
echou@pythonicNeteng:~/Master_Python_Networking/
Chapter1$ tree .
.
├── helloworld.py
└── math_stuff
 ├── __init__.py
 └── subtract.py

1 directory, 3 files
echou@pythonicNeteng:~/Master_Python_Networking/
Chapter1$
```

现在你将引用模块时需要包括包名：

```py
>>> from math_stuff.subtract import subtract
>>> result = subtract(10, 5)
>>> result
5
>>>
```

正如你所看到的，模块和包是组织大型代码文件并使共享 Python 代码变得更加容易的好方法。

# 总结

在本章中，我们介绍了 OSI 模型并回顾了网络协议套件，如 TCP、UDP 和 IP。它们作为处理任意两个主机之间的寻址和通信协商的层。这些协议在设计时考虑了可扩展性，并且基本上没有从其原始设计中改变。考虑到互联网的爆炸性增长，这是相当了不起的成就。

我们还快速回顾了 Python 语言，包括内置类型、运算符、控制流、函数、类、模块和包。Python 是一种功能强大、适合生产的语言，同时也很容易阅读。这使得 Python 成为网络自动化的理想选择。网络工程师可以利用 Python 从简单的脚本开始，逐渐转向其他高级特性。

在第二章中，*低级网络设备交互*，我们将开始学习如何使用 Python 与网络设备进行编程交互。


# 第二章：低级网络设备交互

在第一章中，*TCP/IP 协议套件和 Python 概述*，我们研究了网络通信协议背后的理论和规范。我们还快速浏览了 Python 语言。在本章中，我们将开始深入探讨使用 Python 管理网络设备的不同方式，特别是我们如何使用 Python 与传统网络路由器和交换机进行程序通信。

我所说的传统网络路由器和交换机是什么意思？虽然很难想象今天出现的任何网络设备都没有用于程序通信的**应用程序接口**（**API**），但众所周知，许多在以前部署的网络设备中并不包含 API 接口。这些设备的管理方式是通过使用终端程序的**命令行接口**（**CLI**），最初是为了人类工程师而开发的。管理依赖于工程师对设备返回的数据的解释以采取适当的行动。随着网络设备数量和网络复杂性的增加，手动逐个管理它们变得越来越困难。

Python 有两个很棒的库可以帮助完成这些任务，Pexpect 和 Paramiko，以及从它们衍生出的其他库。本章将首先介绍 Pexpect，然后以 Paramiko 的示例进行讲解。一旦你了解了 Paramiko 的基础知识，就很容易扩展到 Netmiko 等更多的库。值得一提的是，Ansible（在第四章中介绍，*Python 自动化框架- Ansible 基础*，以及第五章中介绍，*Python 自动化框架-进阶*）在其网络模块中大量依赖 Paramiko。在本章中，我们将讨论以下主题：

+   命令行界面的挑战

+   构建虚拟实验室

+   Python Pexpect 库

+   Python Paramiko 库

+   Pexpect 和 Paramiko 的缺点

让我们开始吧！

# 命令行界面的挑战

在 2014 年的 Interop 博览会上，*BigSwitch Networks*的首席执行官道格拉斯·默里展示了以下幻灯片，以说明在 1993 年至 2013 年间**数据中心网络**（**DCN**）发生了什么变化：

数据中心网络变化（来源：[`www.bigswitch.com/sites/default/files/presentations/murraydouglasstartuphotseatpanel.pdf`](https://www.bigswitch.com/sites/default/files/presentations/murraydouglasstartuphotseatpanel.pdf)）

他的观点很明显：在这 20 年里，我们管理网络设备的方式几乎没有什么变化。虽然他在展示这张幻灯片时可能对现任供应商持有负面偏见，但他的观点是很有道理的。在他看来，20 年来管理路由器和交换机唯一改变的是协议从不太安全的 Telnet 变为更安全的 SSH。

正是在 2014 年左右，我们开始看到行业达成共识，即远离手动、人为驱动的 CLI，转向自动化、以计算机为中心的 API。毫无疑问，当我们进行网络设计、启动初步概念验证和首次部署拓扑时，我们仍需要直接与设备进行通信。然而，一旦我们超越了初始部署，要求是要始终可靠地进行相同的更改，使其无误，并且一遍又一遍地重复，而不让工程师分心或感到疲倦。这个要求听起来就像是计算机和我们最喜爱的语言 Python 的理想工作。

回到幻灯片，主要挑战在于路由器和管理员之间的交互。路由器将输出一系列信息，并期望管理员根据工程师对输出的解释输入一系列手动命令。例如，你必须输入`enable`才能进入特权模式，并在收到带有`#`符号的返回提示后，你再输入`configure terminal`以进入配置模式。同样的过程可以进一步扩展到接口配置模式和路由协议配置模式。这与计算机驱动的程序思维形成鲜明对比。当计算机想要完成单个任务时，比如在接口上放置 IP 地址，它希望一次性将所有信息结构化地提供给路由器，并且期望路由器给出一个`yes`或`no`的答复来指示任务的成功或失败。

Pexpect 和 Paramiko 都实现了这个解决方案，即将交互过程视为子进程，并监视进程与目标设备之间的交互。根据返回的值，父进程将决定随后的操作（如果有的话）。

# 构建虚拟实验室

在我们深入研究这些软件包之前，让我们来看看组建一个实验室以便学习的选项。正如古语所说，“熟能生巧”：我们需要一个隔离的沙盒来安全地犯错误，尝试新的做事方式，并重复一些步骤以加强在第一次尝试时不清楚的概念。安装 Python 和管理主机所需的软件包很容易，但那些我们想要模拟的路由器和交换机呢？

要组建一个网络实验室，我们基本上有两个选项，每个选项都有其优势和劣势：

+   **物理设备**：这个选项包括可以看到和触摸的物理设备。如果你足够幸运，你可能能够组建一个与你的生产环境完全相同的实验室。

+   **优势**：从实验室到生产的过渡更容易，易于经理和同事理解并触摸设备。简而言之，由于熟悉度高，对物理设备的舒适度非常高。

+   **劣势**：为实验室使用而支付设备相对昂贵。设备需要工程师花费时间来安装，并且一旦构建完成后就不太灵活。

+   **虚拟设备**：这些是实际网络设备的仿真或模拟。它们可以是供应商提供的，也可以是开源社区提供的。

+   **优势**：虚拟设备更容易设置，成本相对较低，并且可以快速更改拓扑结构。

+   **劣势**：它们通常是其物理对应物的缩减版本。有时虚拟设备和物理设备之间存在功能差距。

当然，决定使用虚拟实验室还是物理实验室是一个个人决定，需要在成本、实施的便利性和实验室与生产之间的差距之间进行权衡。在我工作过的一些环境中，当进行初步概念验证时使用虚拟实验室，而在接近最终设计时使用物理实验室。

在我看来，随着越来越多的供应商决定生产虚拟设备，虚拟实验室是学习环境中的正确选择。虚拟设备的功能差距相对较小，并且有专门的文档，特别是当虚拟实例由供应商提供时。与购买物理设备相比，虚拟设备的成本相对较低。使用虚拟设备构建的时间更快，因为它们通常只是软件程序。

对于这本书，我将使用物理和虚拟设备的组合来进行概念演示，更偏向于虚拟设备。对于我们将看到的示例，差异应该是透明的。如果虚拟和物理设备在我们的目标方面有任何已知的差异，我会确保列出它们。

在虚拟实验室方面，除了来自各种供应商的镜像，我还在使用一款来自 Cisco 的程序**Virtual Internet Routing Lab**（**VIRL**）[`learningnetworkstore.cisco.com/virtual-internet-routing-lab-virl/cisco-personal-edition-pe-20-nodes-virl-20`](https://learningnetworkstore.cisco.com/virtual-internet-routing-lab-virl/cisco-personal-edition-pe-20-nodes-virl-20)。

我想指出，读者完全可以选择是否使用这个程序。但强烈建议读者有一些实验室设备来跟随本书中的示例。

# 思科 VIRL

我记得当我第一次开始准备我的**思科认证网络专家**（**CCIE**）实验考试时，我从 eBay 购买了一些二手思科设备来学习。即使打折，每台路由器和交换机也要花费数百美元，所以为了省钱，我购买了一些上世纪 80 年代的非常过时的思科路由器（在您喜欢的搜索引擎中搜索思科 AGS 路由器，会让您大笑一番），它们明显缺乏功能和性能，即使是对实验室标准来说。尽管当我打开它们时（它们的声音很大），它们给家人带来了有趣的对话，但组装物理设备并不好玩。它们又重又笨重，连接所有的电缆很麻烦，为了引入链路故障，我会直接拔掉一根电缆。

快进几年。**Dynamip**被创建，我爱上了它创建不同网络场景的简易性。当我尝试学习一个新概念时，这尤其重要。您只需要来自 Cisco 的 IOS 镜像，一些精心构建的拓扑文件，就可以轻松构建一个虚拟网络，以便测试您的知识。我有一个完整的网络拓扑文件夹，预先保存的配置和不同版本的镜像，根据场景的需要。GNS3 前端的添加使整个设置具有美丽的 GUI 外观。使用 GNS3，您可以轻松地点击和拖放您的链接和设备；您甚至可以直接从 GNS3 设计面板打印出网络拓扑图给您的经理。唯一缺少的是该工具没有得到供应商的官方认可，因此缺乏可信度。

2015 年，Cisco 社区决定通过发布 Cisco VIRL 来满足这一需求。如果您有一台符合要求的服务器，并且愿意支付所需的年度许可证费用，这是我首选的开发和尝试大部分 Python 代码的方法，无论是为这本书还是我的自己的生产使用。

截至 2017 年 1 月 1 日，只有 20 节点个人版许可证可供购买，价格为每年 199.99 美元。

在我看来，即使需要花费一些金钱，VIRL 平台相对于其他替代方案有一些优势：

+   **易用性**：所有 IOSv、IOS-XRv、CSR100v、NX-OSv 和 ASAv 的镜像都包含在一个单独的下载中。

+   **官方**（**有点**）：尽管支持是由社区驱动的，但它在 Cisco 内部被广泛使用。由于其受欢迎程度，错误得到快速修复，新功能得到仔细记录，并且有用的知识在其用户之间广泛分享。

+   云迁移路径：当您的仿真超出您拥有的硬件能力时，比如 Cisco dCloud（[`dcloud.cisco.com/`](https://dcloud.cisco.com/)）、Packet 上的 VIRL（[`virl.cisco.com/cloud/`](http://virl.cisco.com/cloud/)）和 Cisco DevNet（[`developer.cisco.com/`](https://developer.cisco.com/)）时，该项目提供了一个逻辑的迁移路径。这是一个有时被忽视的重要特性。

+   链接和控制平面模拟：该工具可以模拟真实世界链路特性的每个链路的延迟、抖动和数据包丢失。还有一个用于外部路由注入的控制平面流量生成器。

+   **其他**：该工具提供了一些不错的功能，比如 VM Maestro 拓扑设计和模拟控制，AutoNetkit 用于自动生成配置，以及用户工作空间管理（如果服务器是共享的）。还有一些开源项目，比如 virlutils（[`github.com/CiscoDevNet/virlutils`](https://github.com/CiscoDevNet/virlutils)），由社区积极开发，以增强该工具的可用性。

在本书中，我们不会使用 VIRL 中的所有功能。但由于这是一个相对较新的工具，值得您考虑，如果您决定使用这个工具，我想提供一些我使用过的设置。

再次强调拥有一个实验室的重要性，但不一定需要是思科 VIRL 实验室。本书中提供的代码示例应该适用于任何实验室设备，只要它们运行相同的软件类型和版本。

# VIRL 提示

VIRL 网站（[`virl.cisco.com/`](http://virl.cisco.com/)）提供了大量的指导、准备和文档。我还发现 VIRL 用户社区通常能够提供快速准确的帮助。我不会重复这两个地方已经提供的信息；然而，这里是我在本书中用于实验室的一些设置：

1.  VIRL 使用两个虚拟以太网接口进行连接。第一个接口设置为主机机器的互联网连接的 NAT，第二个用于本地管理接口的连接（在下面的示例中为 VMnet2）。我使用一个具有类似网络设置的单独的虚拟机来运行我的 Python 代码，第一个主要以太网用于互联网连接，第二个以太网连接到 Vmnet2，用于实验室设备管理网络：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/c82cd2d1-cdde-4f81-bc77-ae9d8fa0975c.png)

1.  VMnet2 是一个自定义网络，用于将 Ubuntu 主机与 VIRL 虚拟机连接：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/85f2152f-11e7-4be2-918e-d6153657d2be.png)

1.  在拓扑设计选项中，我将管理网络选项设置为共享平面网络，以便在虚拟路由器上使用 VMnet2 作为管理网络：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/02656522-3921-4e03-a513-4d10675cd081.png)

1.  在节点配置下，您可以选择静态配置管理 IP 的选项。我尝试静态设置管理 IP 地址，而不是让软件动态分配它们。这可以更确定地访问： 

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/ef2611d4-2e65-4fde-93d2-89b164515c8c.png)

# 思科 DevNet 和 dCloud

思科提供了另外两种非常好的、并且在撰写本文时是免费的方法，用于使用各种思科设备进行网络自动化实践。这两种工具都需要**思科连接在线（CCO）**登录。它们都非常好，尤其是价格方面（它们是免费的！）。我很难想象这些在线工具会长时间保持免费；我相信，这些工具在某个时候将需要收费或者被纳入需要收费的更大计划中。然而，在它们免费提供的时候我们可以利用它们。

第一个工具是思科 DevNet ([`developer.cisco.com/`](https://developer.cisco.com/)) 实验室，其中包括引导式学习轨迹、完整文档和远程实验室等多种好处。一些实验室是一直开放的，而另一些需要预订。实验室的可用性将取决于使用情况。如果你没有自己的实验室，这是一个很好的选择。在我使用 DevNet 的经验中，一些文档和链接已经过时，但可以很容易地获取到最新版本。在软件开发这样一个快速变化的领域，这是可以预料的。无论你是否有一个本地运行的 VIRL 主机，DevNet 都是一个你应该充分利用的工具：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/687289f1-0881-4d40-a9f9-b46cb69a31bb.png)

思科的另一个在线实验室选择是[`dcloud.cisco.com/`](https://dcloud.cisco.com/)。你可以把 dCloud 看作是在其他人的服务器上运行 VIRL，而不必管理或支付这些资源。看起来思科把 dCloud 既当作一个独立的产品，又当作 VIRL 的扩展。例如，在你无法在本地运行超过几个 IOX-XR 或 NX-OS 实例的情况下，你可以使用 dCloud 来扩展你的本地实验室。这是一个相对较新的工具，但绝对值得一试：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/9013d0ba-57bd-48e0-8d65-8278953469b5.png)

# GNS3

这本书和其他用途我使用了一些其他虚拟实验室。其中一个是[GNS3](https://gns3.com/)工具：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/90c418fe-1abc-4b39-9bc3-38e5104ea653.png)

正如本章前面提到的，GNS3 是我们很多人用来准备认证考试和实验练习的工具。这个工具从最初的 Dynamips 的简单前端发展成了一个可行的商业产品。思科制造的工具，比如 VIRL、DevNet 和 dCloud，只包含思科技术。尽管它们提供了虚拟实验室设备与外部世界通信的方式，但并不像直接在模拟环境中拥有多供应商虚拟化设备那样简单。GNS3 是供应商中立的，可以在实验室中直接包含多供应商虚拟化平台。这通常是通过克隆镜像（比如 Arista vEOS）或者通过其他虚拟化程序直接启动网络设备镜像（比如 Juniper Olive 仿真）来实现的。有人可能会认为 GNS3 没有思科 VIRL 项目那样的广度和深度，但由于它可以运行不同版本的思科技术，所以在需要将其他供应商技术纳入实验室时，我经常使用它。

另一个得到很多好评的多供应商网络仿真环境是**Emulated Virtual Environment Next Generation (EVE-NG)**，[`www.eve-ng.net/`](http://www.eve-ng.net/)。我个人对这个工具没有太多经验，但我在这个行业的许多同事和朋友都在他们的网络实验室中使用它。

还有其他虚拟化平台，比如 Arista vEOS ([`eos.arista.com/tag/veos/`](https://eos.arista.com/tag/veos/))、Juniper vMX ([`www.juniper.net/us/en/products-services/routing/mx-series/vmx/`](http://www.juniper.net/us/en/products-services/routing/mx-series/vmx/))和 vSRX ([`www.juniper.net/us/en/products-services/security/srx-series/vsrx/`](http://www.juniper.net/us/en/products-services/security/srx-series/vsrx/))，你可以在测试中作为独立的虚拟设备使用。它们是测试特定平台功能的绝佳补充工具，比如平台上 API 版本的差异。它们通常作为付费产品在公共云提供商市场上提供，以便更容易地访问。它们通常提供与它们的物理对应产品相同的功能。

# Python Pexpect 库

Pexpect 是一个纯 Python 模块，用于生成子应用程序、控制它们并响应其输出中的预期模式。Pexpect 的工作原理类似于 Don Libes 的 Expect。Pexpect 允许您的脚本生成一个子应用程序并控制它，就像一个人在键入命令一样。Pexpect，Read the Docs: [`pexpect.readthedocs.io/en/stable/index.html`](https://pexpect.readthedocs.io/en/stable/index.html)

让我们来看看 Python Pexpect 库。与 Don Libe 的原始 Tcl Expect 模块类似，Pexpect 启动或生成另一个进程并监视它以控制交互。Expect 工具最初是为了自动化诸如 FTP、Telnet 和 rlogin 之类的交互式进程而开发的，后来扩展到包括网络自动化。与原始 Expect 不同，Pexpect 完全由 Python 编写，不需要编译 TCL 或 C 扩展。这使我们能够在我们的代码中使用熟悉的 Python 语法和其丰富的标准库。

# Pexpect 安装

由于这是我们要安装的第一个软件包，我们将同时安装`pip`工具和`pexpect`软件包。该过程非常简单：

```py
sudo apt-get install python-pip #Python2
sudo apt-get install python3-pip
sudo pip3 install pexpect
sudo pip install pexpect #Python2
```

我正在使用`pip3`来安装 Python 3 包，同时使用`pip`在 Python 2 环境中安装包。

快速测试一下确保软件包可用：

```py
>>> import pexpect
>>> dir(pexpect)
['EOF', 'ExceptionPexpect', 'Expecter', 'PY3', 
 'TIMEOUT', '__all__', '__builtins__', '__cached__', 
 '__doc__', '__file__', '__loader__', '__name__', 
 '__package__', '__path__', '__revision__', 
 '__spec__', '__version__', 'exceptions', 'expect', 
 'is_executable_file', 'pty_spawn', 'run', 'runu', 
 'searcher_re', 'searcher_string', 'spawn', 
 'spawnbase', 'spawnu', 'split_command_line', 'sys',
 'utils', 'which']
>>> 
```

# Pexpect 概述

对于我们的第一个实验，我们将构建一个简单的网络，其中有两个相连的 IOSv 设备：

！[](assets/8ae3d89a-e435-42d3-bab2-6835055f9cae.png)实验拓扑

每个设备都将在`192.16.0.x/24`范围内拥有一个环回地址，管理 IP 将在`172.16.1.x/24`范围内。VIRL 拓扑文件包含在适应书籍可下载文件中。您可以将拓扑导入到您自己的 VIRL 软件中。如果您没有 VIRL，您也可以通过使用文本编辑器打开拓扑文件来查看必要的信息。该文件只是一个 XML 文件，每个节点的信息都在`node`元素下：

！[](assets/15ca7c31-52f3-4c40-a953-ea2b7a79cb45.png)实验节点信息

设备准备就绪后，让我们看看如果您要 Telnet 到设备中，您将如何与路由器进行交互：

```py
echou@ubuntu:~$ telnet 172.16.1.20
Trying 172.16.1.20...
Connected to 172.16.1.20.
Escape character is '^]'.
<skip>
User Access Verification

Username: cisco
Password:
```

我使用 VIRL AutoNetkit 自动生成路由器的初始配置，生成了默认用户名`cisco`和密码`cisco`。请注意，由于配置中分配的特权，用户已经处于特权模式下：

```py
iosv-1#sh run | i cisco
enable password cisco
username cisco privilege 15 secret 5 $1$Wiwq$7xt2oE0P9ThdxFS02trFw.
 password cisco
 password cisco
iosv-1#
```

自动配置还为 Telnet 和 SSH 生成了`vty`访问：

```py
line vty 0 4
 exec-timeout 720 0
 password cisco
 login local
 transport input telnet ssh
```

让我们看一个使用 Python 交互式 shell 的 Pexpect 示例：

```py
Python 3.5.2 (default, Nov 17 2016, 17:05:23)
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pexpect
>>> child = pexpect.spawn('telnet 172.16.1.20')
>>> child.expect('Username')
0
>>> child.sendline('cisco')
6
>>> child.expect('Password')
0
>>> child.sendline('cisco')
6
>>> child.expect('iosv-1#')
0
>>> child.sendline('show version | i V')
19
>>> child.expect('iosv-1#')
0
>>> child.before
b'show version | i VrnCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)rnProcessor board ID 9MM4BI7B0DSWK40KV1IIRrn'
>>> child.sendline('exit')
5
>>> exit()
```

从 Pexpect 版本 4.0 开始，您可以在 Windows 平台上运行 Pexpect。但是，正如 Pexpect 文档中所指出的，目前应该将在 Windows 上运行 Pexpect 视为实验性的。

在上一个交互式示例中，Pexpect 生成了一个子进程并以交互方式监视它。示例中显示了两个重要的方法，`expect()`和`sendline()`。`expect()`行指示 Pexpect 进程寻找的字符串，作为返回的字符串被视为完成的指示器。这是预期的模式。在我们的示例中，当返回主机名提示（`iosv-1#`）时，我们知道路由器已经向我们发送了所有信息。`sendline()`方法指示应将哪些单词作为命令发送到远程设备。还有一个名为`send()`的方法，但`sendline()`包括一个换行符，类似于在上一个 telnet 会话中按下*Enter*键。从路由器的角度来看，这就像有人从终端键入文本一样。换句话说，我们正在欺骗路由器，让它们认为它们正在与人类进行交互，而实际上它们正在与计算机进行通信。

`before`和`after`属性将设置为子应用程序打印的文本。`before`属性将设置为子应用程序打印的文本，直到预期的模式。`after`字符串将包含由预期模式匹配的文本。在我们的情况下，`before`文本将设置为两个预期匹配（`iosv-1#`）之间的输出，包括`show version`命令。`after`文本是路由器主机名提示符：

```py
>>> child.sendline('show version | i V')
19
>>> child.expect('iosv-1#')
0
>>> child.before
b'show version | i VrnCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)rnProcessor board ID 9MM4BI7B0DSWK40KV1IIRrn'
>>> child.after
b'iosv-1#'
```

如果您期望错误的术语会发生什么？例如，如果在生成子应用程序后输入`username`而不是`Username`，那么 Pexpect 进程将从子进程中寻找一个`username`字符串。在这种情况下，Pexpect 进程将会挂起，因为路由器永远不会返回`username`这个词。会话最终会超时，或者您可以通过*Ctrl* + *C*手动退出。

`expect()`方法等待子应用程序返回给定的字符串，因此在前面的示例中，如果您想要适应小写和大写的`u`，您可以使用以下术语：

```py
>>> child.expect('[Uu]sername')
```

方括号作为`or`操作，告诉子应用程序期望小写或大写的`u`后跟字符串`sername`。我们告诉进程的是我们将接受`Username`或`username`作为预期字符串。

有关 Python 正则表达式的更多信息，请访问[`docs.python.org/3.5/library/re.html`](https://docs.python.org/3.5/library/re.html)。

`expect()`方法也可以包含一个选项列表，而不仅仅是一个单独的字符串；这些选项本身也可以是正则表达式。回到前面的示例，您可以使用以下选项列表来适应两种不同的可能字符串：

```py
>>> child.expect(['Username', 'username'])
```

一般来说，当您可以在正则表达式中适应不同的主机名时，使用单个`expect`字符串的正则表达式，而如果您需要捕获路由器完全不同的响应，例如密码拒绝，那么使用可能的选项。例如，如果您对登录使用了几个不同的密码，您希望捕获`％Login invalid`以及设备提示。

Pexpect 正则表达式和 Python 正则表达式之间的一个重要区别是，Pexpect 匹配是非贪婪的，这意味着在使用特殊字符时，它们将尽可能少地匹配。因为 Pexpect 在流上执行正则表达式，所以您不能向前查看，因为生成流的子进程可能尚未完成。这意味着特殊的美元符号字符`$`通常匹配行尾是无用的，因为`.+`总是不会返回任何字符，而`.*`模式将尽可能少地匹配。一般来说，记住这一点，并尽可能具体地匹配`expect`字符串。

让我们考虑以下情景：

```py
>>> child.sendline('show run | i hostname')
22
>>> child.expect('iosv-1')
0
>>> child.before
b'show run | i hostnamernhostname '
>>>
```

嗯...这里有点不对劲。与之前的终端输出进行比较；您期望的输出应该是`hostname iosv-1`：

```py
iosv-1#show run | i hostname
hostname iosv-1
iosv-1#
```

仔细查看预期的字符串将会揭示错误。在这种情况下，我们忘记了在`iosv-1`主机名后面加上`#`号。因此，子应用程序将返回字符串的第二部分视为预期字符串：

```py
>>> child.sendline('show run | i hostname')
22
>>> child.expect('iosv-1#')
0
>>> child.before
b'show run | i hostnamernhostname iosv-1rn'
>>>
```

通过几个示例后，您可以看到 Pexpect 的使用模式。用户可以规划 Pexpect 进程和子应用程序之间的交互序列。通过一些 Python 变量和循环，我们可以开始构建一个有用的程序，帮助我们收集信息并对网络设备进行更改。

# 我们的第一个 Pexpect 程序

我们的第一个程序`chapter2_1.py`扩展了上一节的内容，并添加了一些额外的代码：

```py
     #!/usr/bin/python3

     import pexpect

     devices = {'iosv-1': {'prompt': 'iosv-1#', 'ip': '172.16.1.20'}, 'iosv-2': {'prompt': 'iosv-2#', 'ip': '172.16.1.21'}}
     username = 'cisco'
     password = 'cisco'

     for device in devices.keys():
         device_prompt = devices[device]['prompt']
         child = pexpect.spawn('telnet ' + devices[device]['ip'])
         child.expect('Username:')
         child.sendline(username)
         child.expect('Password:')
         child.sendline(password)
         child.expect(device_prompt)
         child.sendline('show version | i V')
         child.expect(device_prompt)
         print(child.before)
         child.sendline('exit')
```

我们在第 5 行使用了嵌套字典：

```py
       devices = {'iosv-1': {'prompt': 'iosv-1#', 'ip': 
      '172.16.1.20'}, 'iosv-2': {'prompt': 'iosv-2#', 
      'ip': '172.16.1.21'}}
```

嵌套字典允许我们使用适当的 IP 地址和提示符号引用相同的设备（例如`iosv-1`）。然后我们可以在循环后面使用这些值进行`expect()`方法。

输出在屏幕上打印出每个设备的`show version | i V`输出：

```py
 $ python3 chapter2_1.py
 b'show version | i VrnCisco IOS Software, IOSv
 Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, 
 RELEASE SOFTWARE (fc2)rnProcessor board ID 
 9MM4BI7B0DSWK40KV1IIRrn'
 b'show version | i VrnCisco IOS Software, IOSv 
 Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T,
 RELEASE SOFTWARE (fc2)rn'
```

# 更多 Pexpect 功能

在本节中，我们将看看更多 Pexpect 功能，这些功能在某些情况下可能会派上用场。

如果您的远程设备链接速度慢或快，默认的`expect()`方法超时时间为 30 秒，可以通过`timeout`参数增加或减少：

```py
>>> child.expect('Username', timeout=5)
```

您可以选择使用`interact()`方法将命令传递回用户。当您只想自动化初始任务的某些部分时，这是很有用的：

```py
>>> child.sendline('show version | i V')
19
>>> child.expect('iosv-1#')
0
>>> child.before
b'show version | i VrnCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)rnProcessor board ID 9MM4BI7B0DSWK40KV1IIRrn'
>>> child.interact()
iosv-1#show run | i hostname
hostname iosv-1
iosv-1#exit
Connection closed by foreign host.
>>>
```

通过以字符串格式打印`child.spawn`对象，您可以获得有关该对象的大量信息：

```py
>>> str(child)
"<pexpect.pty_spawn.spawn object at 0x7fb01e29dba8>ncommand: /usr/bin/telnetnargs: ['/usr/bin/telnet', '172.16.1.20']nsearcher: Nonenbuffer (last 100 chars): b''nbefore (last 100 chars): b'NTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)rnProcessor board ID 9MM4BI7B0DSWK40KV1IIRrn'nafter: b'iosv-1#'nmatch: <_sre.SRE_Match object; span=(164, 171), match=b'iosv-1#'>nmatch_index: 0nexitstatus: 1nflag_eof: Falsenpid: 2807nchild_fd: 5nclosed: Falsentimeout: 30ndelimiter: <class 'pexpect.exceptions.EOF'>nlogfile: Nonenlogfile_read: Nonenlogfile_send: Nonenmaxread: 2000nignorecase: Falsensearchwindowsize: Nonendelaybeforesend: 0.05ndelayafterclose: 0.1ndelayafterterminate: 0.1"
>>>
```

Pexpect 最有用的调试工具是将输出记录在文件中：

```py
>>> child = pexpect.spawn('telnet 172.16.1.20')
>>> child.logfile = open('debug', 'wb')
```

使用`child.logfile = open('debug', 'w')`来代替 Python 2。Python 3 默认使用字节字符串。有关 Pexpect 功能的更多信息，请查看[`pexpect.readthedocs.io/en/stable/api/index.html`](https://pexpect.readthedocs.io/en/stable/api/index.html)。

# Pexpect 和 SSH

如果您尝试使用先前的 Telnet 示例并将其插入 SSH 会话，您可能会对体验感到非常沮丧。您始终必须在会话中包含用户名，回答`ssh`新密钥问题，以及更多琐碎的任务。有许多方法可以使 SSH 会话工作，但幸运的是，Pexpect 有一个名为`pxssh`的子类，专门用于建立 SSH 连接。该类添加了登录、注销和处理`ssh`登录过程中不同情况的各种棘手事务的方法。这些过程大多数情况下是相同的，除了`login()`和`logout()`：

```py
>>> from pexpect import pxssh
>>> child = pxssh.pxssh()
>>> child.login('172.16.1.20', 'cisco', 'cisco', auto_prompt_reset=False)
True
>>> child.sendline('show version | i V')
19
>>> child.expect('iosv-1#')
0
>>> child.before
b'show version | i VrnCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)rnProcessor board ID 9MM4BI7B0DSWK40KV1IIRrn'
>>> child.logout()
>>>
```

注意`login()`方法中的`auto_prompt_reset=False`参数。默认情况下，`pxssh`使用 Shell 提示来同步输出。但由于它在大多数 bash 或 CSH 中使用 PS1 选项，它们将在 Cisco 或其他网络设备上出错。

# 为 Pexpect 整合各种功能

作为最后一步，让我们将到目前为止学到的关于 Pexpect 的一切放入脚本中。将代码放入脚本中可以更容易地在生产环境中使用，并且更容易与同事共享。我们将编写第二个脚本`chapter2_2.py`。

您可以从书的 GitHub 存储库[`github.com/PacktPublishing/Mastering-Python-Networking-second-edition`](https://github.com/PacktPublishing/Mastering-Python-Networking-second-edition)下载脚本，以及查看由脚本生成的输出作为命令的结果。参考以下代码：

```py
  #!/usr/bin/python3

  import getpass
  from pexpect import pxssh

  devices = {'iosv-1': {'prompt': 'iosv-1#', 'ip': '172.16.1.20'},
  'iosv-2': {'prompt': 'iosv-2#', 'ip': '172.16.1.21'}}
  commands = ['term length 0', 'show version', 'show run']

  username = input('Username: ')
  password = getpass.getpass('Password: ')

  # Starts the loop for devices
  for device in devices.keys():
      outputFileName = device + '_output.txt'
      device_prompt = devices[device]['prompt']
      child = pxssh.pxssh()
      child.login(devices[device]['ip'], username.strip(), password.strip(), auto_promp t_reset=False)
      # Starts the loop for commands and write to output
      with open(outputFileName, 'wb') as f:
          for command in commands:
              child.sendline(command)
              child.expect(device_prompt)
              f.write(child.before)

      child.logout()
```

该脚本从我们的第一个 Pexpect 程序进一步扩展，具有以下附加功能：

+   它使用 SSH 而不是 Telnet

+   通过将命令转换为列表（第 8 行）并循环执行命令（从第 20 行开始），它支持多个命令而不仅仅是一个命令

+   它提示用户输入用户名和密码，而不是在脚本中硬编码它们

+   它将输出写入两个文件，`iosv-1_output.txt`和`ios-2_output.txt`，以便进一步分析

对于 Python 2，使用`raw_input()`而不是`input()`来进行用户名提示。此外，使用`w`而不是`wb`作为文件模式。

# Python Paramiko 库

Paramiko 是 SSHv2 协议的 Python 实现。就像 Pexpect 的`pxssh`子类一样，Paramiko 简化了主机和远程设备之间的 SSHv2 交互。与`pxssh`不同，Paramiko 仅专注于 SSHv2，不支持 Telnet。它还提供客户端和服务器操作。

Paramiko 是高级自动化框架 Ansible 用于其网络模块的低级 SSH 客户端。我们将在后面的章节中介绍 Ansible。让我们来看看 Paramiko 库。

# Paramiko 的安装

使用 Python `pip`安装 Paramiko 非常简单。但是，它对 cryptography 库有严格的依赖。该库为 SSH 协议提供了基于 C 的低级加密算法。

Windows、Mac 和其他 Linux 版本的安装说明可以在[`cryptography.io/en/latest/installation/`](https://cryptography.io/en/latest/installation/)找到。

我们将在接下来的输出中展示 Ubuntu 16.04 虚拟机上 Paramiko 的安装。以下输出显示了安装步骤，以及 Paramiko 成功导入 Python 交互提示符。

如果您使用的是 Python 2，请按照以下步骤。我们将尝试在交互提示符中导入库，以确保库可以使用：

```py
sudo apt-get install build-essential libssl-dev libffi-dev python-dev
sudo pip install cryptography
sudo pip install paramiko
$ python
Python 2.7.12 (default, Nov 19 2016, 06:48:10)
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import paramiko
>>> exit()
```

如果您使用的是 Python 3，请参考以下命令行安装依赖项。安装后，我们将导入库以确保它已正确安装：

```py
sudo apt-get install build-essential libssl-dev libffi-dev python3-dev
sudo pip3 install cryptography
sudo pip3 install paramiko
$ python3
Python 3.5.2 (default, Nov 17 2016, 17:05:23)
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import paramiko
>>>
```

# Paramiko 概述

让我们来看一个使用 Python 3 交互式 shell 的快速 Paramiko 示例：

```py
>>> import paramiko, time
>>> connection = paramiko.SSHClient()
>>> connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
>>> connection.connect('172.16.1.20', username='cisco', password='cisco', look_for_keys=False, allow_agent=False)
>>> new_connection = connection.invoke_shell()
>>> output = new_connection.recv(5000)
>>> print(output)
b"rn**************************************************************************rn* IOSv is strictly limited to use for evaluation, demonstration and IOS *rn* education. IOSv is provided as-is and is not supported by Cisco's *rn* Technical Advisory Center. Any use or disclosure, in whole or in part, *rn* of the IOSv Software or Documentation to any third party for any *rn* purposes is expressly prohibited except as otherwise authorized by *rn* Cisco in writing. *rn**************************************************************************rniosv-1#"
>>> new_connection.send("show version | i Vn")
19
>>> time.sleep(3)
>>> output = new_connection.recv(5000)
>>> print(output)
b'show version | i VrnCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)rnProcessor board ID 9MM4BI7B0DSWK40KV1IIRrniosv-1#'
>>> new_connection.close()
>>>
```

`time.sleep()`函数插入时间延迟，以确保所有输出都被捕获。这在网络连接较慢或设备繁忙时特别有用。这个命令不是必需的，但根据您的情况，建议使用。

即使您是第一次看到 Paramiko 操作，Python 及其清晰的语法意味着您可以对程序尝试做什么有一个相当好的猜测：

```py
>>> import paramiko
>>> connection = paramiko.SSHClient()
>>> connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
>>> connection.connect('172.16.1.20', username='cisco', password='cisco', look_for_keys=False, allow_agent=False)
```

前四行创建了 Paramiko 的`SSHClient`类的实例。下一行设置了客户端在 SSH 服务器的主机名（在本例中为`iosv-1`）不在系统主机密钥或应用程序密钥中时应使用的策略。在我们的情况下，我们将自动将密钥添加到应用程序的`HostKeys`对象中。此时，如果您登录路由器，您将看到 Paramiko 的额外登录会话：

```py
iosv-1#who
 Line User Host(s) Idle Location
*578 vty 0 cisco idle 00:00:00 172.16.1.1
 579 vty 1 cisco idle 00:01:30 172.16.1.173
Interface User Mode Idle Peer Address
iosv-1#
```

接下来的几行调用连接的新交互式 shell，并重复发送命令和检索输出的模式。最后，我们关闭连接。

一些之前使用过 Paramiko 的读者可能对`exec_command()`方法比调用 shell 更熟悉。为什么我们需要调用交互式 shell 而不是直接使用`exec_command()`呢？不幸的是，在 Cisco IOS 上，`exec_command()`只允许一个命令。考虑以下使用`exec_command()`进行连接的示例：

```py
>>> connection.connect('172.16.1.20', username='cisco', password='cisco', look_for_keys=False, allow_agent=False)
>>> stdin, stdout, stderr = connection.exec_command('show version | i V')
>>> stdout.read()
b'Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)rnProcessor board ID 9MM4BI7B0DSWK40KV1IIRrn'
>>> 
```

一切都很顺利；但是，如果您查看 Cisco 设备上的会话数量，您会注意到连接被 Cisco 设备中断，而您并没有关闭连接：

```py
iosv-1#who
 Line User Host(s) Idle Location
*578 vty 0 cisco idle 00:00:00 172.16.1.1
Interface User Mode Idle Peer Address
iosv-1#
```

因为 SSH 会话不再活动，如果您想向远程设备发送更多命令，`exec_command()`将返回错误：

```py
>>> stdin, stdout, stderr = connection.exec_command('show version | i V')
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
 File "/usr/local/lib/python3.5/dist-packages/paramiko/client.py", line 435, in exec_command
 chan = self._transport.open_session(timeout=timeout)
 File "/usr/local/lib/python3.5/dist-packages/paramiko/transport.py", line 711, in open_session
 timeout=timeout)
 File "/usr/local/lib/python3.5/dist-packages/paramiko/transport.py", line 795, in open_channel
 raise SSHException('SSH session not active')
paramiko.ssh_exception.SSHException: SSH session not active
>>>
```

Kirk Byers 的 Netmiko 库是一个开源的 Python 库，简化了对网络设备的 SSH 管理。要了解更多信息，请查看这篇文章[`pynet.twb-tech.com/blog/automation/netmiko.html`](https://pynet.twb-tech.com/blog/automation/netmiko.html)，以及源代码[`github.com/ktbyers/netmiko`](https://github.com/ktbyers/netmiko)。

如果您不清除接收到的缓冲区，会发生什么？输出将继续填充缓冲区并覆盖它：

```py
>>> new_connection.send("show version | i Vn")
19
>>> new_connection.send("show version | i Vn")
19
>>> new_connection.send("show version | i Vn")
19
>>> new_connection.recv(5000)
b'show version | i VrnCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)rnProcessor board ID 9MM4BI7B0DSWK40KV1IIRrniosv-1#show version | i VrnCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)rnProcessor board ID 9MM4BI7B0DSWK40KV1IIRrniosv-1#show version | i VrnCisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)rnProcessor board ID 9MM4BI7B0DSWK40KV1IIRrniosv-1#'
>>>
```

为了保持确定性输出的一致性，我们将在每次执行命令时从缓冲区中检索输出。

# 我们的第一个 Paramiko 程序

我们的第一个程序将使用与我们组合的 Pexpect 程序相同的一般结构。我们将循环遍历设备和命令列表，同时使用 Paramiko 而不是 Pexpect。这将使我们很好地比较 Paramiko 和 Pexpect 之间的差异。

如果您还没有这样做，您可以从书的 GitHub 存储库[`github.com/PacktPublishing/Mastering-Python-Networking-second-edition`](https://github.com/PacktPublishing/Mastering-Python-Networking)下载代码`chapter2_3.py`。我将在这里列出显著的区别：

```py
devices = {'iosv-1': {'ip': '172.16.1.20'}, 'iosv-2': {'ip': '172.16.1.21'}}
```

我们不再需要使用 Paramiko 来匹配设备提示；因此，设备字典可以简化：

```py
commands = ['show version', 'show run']
```

Paramiko 中没有 sendline 的等价物；相反，我们需要在每个命令中手动包含换行符：

```py
def clear_buffer(connection):
    if connection.recv_ready():
        return connection.recv(max_buffer)
```

我们包含了一个新的方法来清除发送命令的缓冲区，比如`terminal length 0`或`enable`，因为我们不需要这些命令的输出。我们只是想清除缓冲区并进入执行提示符。这个函数稍后将在循环中使用，比如脚本的第 25 行：

```py
output = clear_buffer(new_connection)
```

程序的其余部分应该是相当容易理解的，类似于我们在本章中看到的内容。我想指出的最后一件事是，由于这是一个交互式程序，我们在远程设备上放置了一些缓冲区，并等待命令在远程设备上完成后再检索输出。

```py
time.sleep(2)
```

在清除缓冲区之后，在执行命令之间，我们将等待两秒。这将给设备足够的时间来响应，如果它很忙的话。

# 更多 Paramiko 功能

我们将在本书的后面部分再次看到 Paramiko，当我们讨论 Ansible 时，Paramiko 是许多网络模块的基础传输。在本节中，我们将看一下 Paramiko 的一些其他功能。

# Paramiko 用于服务器

Paramiko 也可以用于通过 SSHv2 管理服务器。让我们看一个使用 Paramiko 管理服务器的例子。我们将使用基于密钥的身份验证进行 SSHv2 会话。

在这个例子中，我使用了与目标服务器相同的虚拟机上的另一个 Ubuntu 虚拟机。您也可以使用 VIRL 模拟器上的服务器或者公共云提供商之一的实例，比如亚马逊 AWS EC2。

我们将为 Paramiko 主机生成一个公私钥对：

```py
ssh-keygen -t rsa
```

这个命令默认会生成一个名为`id_rsa.pub`的公钥，作为用户主目录`~/.ssh`下的公钥，以及一个名为`id_rsa`的私钥。对待私钥的注意力应与您不想与任何其他人分享的私人密码一样。您可以将公钥视为标识您身份的名片。使用私钥和公钥，消息将在本地由您的私钥加密，然后由远程主机使用公钥解密。我们应该将公钥复制到远程主机。在生产环境中，我们可以通过使用 USB 驱动器进行离线复制；在我们的实验室中，我们可以简单地将公钥复制到远程主机的`~/.ssh/authorized_keys`文件中。打开远程服务器的终端窗口，这样您就可以粘贴公钥。

使用 Paramiko 将`~/.ssh/id_rsa`的内容复制到您的管理主机上：

```py
<Management Host with Pramiko>$ cat ~/.ssh/id_rsa.pub
ssh-rsa <your public key> echou@pythonicNeteng
```

然后，将其粘贴到远程主机的`user`目录下；在这种情况下，我在双方都使用`echou`：

```py
<Remote Host>$ vim ~/.ssh/authorized_keys
ssh-rsa <your public key> echou@pythonicNeteng
```

您现在可以使用 Paramiko 来管理远程主机。请注意，在这个例子中，我们将使用私钥进行身份验证，以及`exec_command()`方法来发送命令：

```py
Python 3.5.2 (default, Nov 17 2016, 17:05:23)
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import paramiko
>>> key = paramiko.RSAKey.from_private_key_file('/home/echou/.ssh/id_rsa')
>>> client = paramiko.SSHClient()
>>> client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
>>> client.connect('192.168.199.182', username='echou', pkey=key)
>>> stdin, stdout, stderr = client.exec_command('ls -l')
>>> stdout.read()
b'total 44ndrwxr-xr-x 2 echou echou 4096 Jan 7 10:14 Desktopndrwxr-xr-x 2 echou echou 4096 Jan 7 10:14 Documentsndrwxr-xr-x 2 echou echou 4096 Jan 7 10:14 Downloadsn-rw-r--r-- 1 echou echou 8980 Jan 7 10:03 examples.desktopndrwxr-xr-x 2 echou echou 4096 Jan 7 10:14 Musicndrwxr-xr-x 2 echou echou 4096 Jan 7 10:14 Picturesndrwxr-xr-x 2 echou echou 4096 Jan 7 10:14 Publicndrwxr-xr-x 2 echou echou 4096 Jan 7 10:14 Templatesndrwxr-xr-x 2 echou echou 4096 Jan 7 10:14 Videosn'
>>> stdin, stdout, stderr = client.exec_command('pwd')
>>> stdout.read()
b'/home/echoun'
>>> client.close()
>>>
```

请注意，在服务器示例中，我们不需要创建交互式会话来执行多个命令。您现在可以关闭远程主机的 SSHv2 配置中基于密码的身份验证，以实现更安全的基于密钥的身份验证，并启用自动化。一些网络设备，如 Cumulus 和 Vyatta 交换机，也支持基于密钥的身份验证。

# 为 Paramiko 整合各种功能

我们几乎已经到了本章的结尾。在这最后一节中，让我们使 Paramiko 程序更具重用性。我们现有脚本的一个缺点是：每次我们想要添加或删除主机，或者每当我们需要更改要在远程主机上执行的命令时，我们都需要打开脚本。这是因为主机和命令信息都是静态输入到脚本中的。硬编码主机和命令更容易出错。此外，如果你要把脚本传给同事，他们可能不太愿意在 Python、Paramiko 或 Linux 中工作。

通过将主机和命令文件都作为脚本的参数读入，我们可以消除一些这些顾虑。用户（包括未来的你）可以在需要更改主机或命令时简单地修改这些文本文件。

我们已经在名为`chapter2_4.py`的脚本中引入了更改。

我们没有将命令硬编码，而是将命令分成一个单独的`commands.txt`文件。到目前为止，我们一直在使用 show 命令；在这个例子中，我们将进行配置更改。特别是，我们将日志缓冲区大小更改为`30000`字节：

```py
$ cat commands.txt
config t
logging buffered 30000
end
copy run start
```

设备的信息被写入`devices.json`文件。我们选择 JSON 格式来存储设备信息，因为 JSON 数据类型可以很容易地转换为 Python 字典数据类型：

```py
$ cat devices.json
{
 "iosv-1": {"ip": "172.16.1.20"},
 "iosv-2": {"ip": "172.16.1.21"}
}
```

在脚本中，我们做出了以下更改：

```py
  with open('devices.json', 'r') as f:
      devices = json.load(f)

  with open('commands.txt', 'r') as f:
      commands = [line for line in f.readlines()]
```

以下是脚本执行的简化输出：

```py
$ python3 chapter2_4.py
Username: cisco
Password:
b'terminal length 0rniosv-2#config trnEnter configuration commands, one per line. End with CNTL/Z.rniosv-2(config)#'
b'logging buffered 30000rniosv-2(config)#'
...
```

快速检查确保更改已经在`running-config`和`startup-config`中生效：

```py
iosv-1#sh run | i logging
logging buffered 30000
iosv-1#sh start | i logging
logging buffered 30000
```

```py
iosv-2#sh run | i logging
logging buffered 30000
iosv-2#sh start | i logging
logging buffered 30000

```

# 展望未来

就自动化网络使用 Python 而言，本章我们已经取得了相当大的进步。然而，我们使用的方法感觉有点像自动化的变通方法。我们试图欺骗远程设备，让它们认为它们在与另一端的人类进行交互。

# 与其他工具相比，Pexpect 和 Paramiko 的缺点

到目前为止，我们的方法最大的缺点是远程设备没有返回结构化数据。它们返回的数据适合在终端上显示并由人类解释，而不是由计算机程序。人眼可以轻松解释空格，而计算机只能看到回车符。

我们将在接下来的章节中看到更好的方法。作为第三章 *API 和意图驱动的网络*的序曲，让我们讨论幂等性的概念。

# 网络设备交互的幂等性

**幂等性**一词在不同的语境中有不同的含义。但在本书的语境中，该术语意味着当客户端对远程设备进行相同的调用时，结果应始终相同。我相信我们都同意这一点。想象一种情况，每次执行相同的脚本时，你都会得到不同的结果。我觉得那种情况非常可怕。如果是这种情况，你怎么能相信你的脚本呢？这将使我们的自动化工作变得毫无意义，因为我们需要准备处理不同的返回结果。

由于 Pexpect 和 Paramiko 正在交互式地发送一系列命令，非幂等交互的机会更高。回到需要从返回结果中筛选有用元素的事实，差异的风险更高。在我们编写脚本和脚本执行 100 次之间，远程端的某些内容可能已经发生了变化。例如，如果供应商在发布之间更改了屏幕输出，而我们没有更新脚本，脚本可能会出错。

如果我们需要依赖脚本进行生产，我们需要尽可能使脚本具有幂等性。

# 糟糕的自动化会加速糟糕的事情发生

糟糕的自动化会让你更快地刺瞎自己的眼睛，就是这么简单。计算机在执行任务时比我们人类工程师快得多。如果我们用相同的操作程序由人类和脚本执行，脚本会比人类更快地完成，有时甚至没有在程序之间建立良好的反馈循环的好处。互联网上充满了当有人按下*Enter*键后立即后悔的恐怖故事。

我们需要确保糟糕的自动化脚本搞砸事情的机会尽可能小。我们都会犯错；在进行任何生产工作之前仔细测试您的脚本和小的影响范围是确保您能在错误发生之前捕捉到它的关键。

# 总结

在本章中，我们介绍了与网络设备直接通信的低级方式。如果没有一种以编程方式与网络设备通信并对其进行更改的方法，就不可能实现自动化。我们看了 Python 中的两个库，它们允许我们管理本来应该由 CLI 管理的设备。虽然有用，但很容易看出这个过程可能有些脆弱。这主要是因为所涉及的网络设备本来是为人类而不是计算机管理而设计的。

在第三章中，*API 和意图驱动的网络*，我们将看看支持 API 和意图驱动网络的网络设备。


# 第三章：API 和意图驱动的网络

在第二章中，*低级网络设备交互*，我们看了一下使用 Pexpect 和 Paramiko 与网络设备进行交互的方法。这两个工具都使用了一个模拟用户在终端前输入命令的持久会话。这在一定程度上是有效的。很容易发送命令以在设备上执行并捕获输出。然而，当输出超过几行字符时，计算机程序很难解释输出。Pexpect 和 Paramiko 返回的输出是一系列字符，是为人类阅读而设计的。输出的结构包括了人类友好的行和空格，但对计算机程序来说很难理解。

为了让我们的计算机程序自动化执行我们想要执行的许多任务，我们需要解释返回的结果，并根据返回的结果采取后续行动。当我们无法准确和可预测地解释返回的结果时，我们无法有信心执行下一个命令。

幸运的是，这个问题已经被互联网社区解决了。想象一下当计算机和人类都在阅读网页时的区别。人类看到的是浏览器解释的单词、图片和空格；计算机看到的是原始的 HTML 代码、Unicode 字符和二进制文件。当一个网站需要成为另一个计算机的网络服务时会发生什么？同样的网络资源需要同时适应人类客户和其他计算机程序。这个问题听起来是不是很熟悉？答案就是**应用程序接口**（**API**）。需要注意的是，根据维基百科的说法，API 是一个概念，而不是特定的技术或框架。

在计算机编程中，**应用程序编程接口**（**API**）是一组子程序定义、协议和用于构建应用软件的工具。一般来说，它是各种软件组件之间清晰定义的通信方法集。一个好的 API 通过提供所有构建块，使得开发计算机程序更容易，然后由程序员组合在一起。

在我们的用例中，清晰定义的通信方法集将在我们的 Python 程序和目标设备之间。我们的网络设备 API 提供了一个独立的接口供计算机程序使用。确切的 API 实现是特定于供应商的。一个供应商可能更喜欢 XML 而不是 JSON，有些可能提供 HTTPS 作为底层传输协议，而其他供应商可能提供 Python 库作为包装器。尽管存在差异，API 的概念仍然是相同的：它是一种为其他计算机程序优化的独立通信方法。

在本章中，我们将讨论以下主题：

+   将基础设施视为代码、意图驱动的网络和数据建模

+   思科 NX-API 和面向应用的基础设施

+   Juniper NETCONF 和 PyEZ

+   Arista eAPI 和 PyEAPI

# 基础设施即代码

在一个完美的世界里，设计和管理网络的网络工程师和架构师应该关注网络应该实现的目标，而不是设备级别的交互。在我作为当地 ISP 的实习生的第一份工作中，我兴奋地安装了一个路由器在客户现场，打开了他们的分段帧中继链路（还记得那些吗？）。我应该怎么做？我问道。我拿到了一个打开帧中继链路的标准操作流程。我去了客户现场，盲目地输入命令，看着绿灯闪烁，然后高兴地收拾行李，为自己的工作感到自豪。尽管第一份工作很令人兴奋，但我并没有完全理解我在做什么。我只是在按照指示行事，没有考虑我输入的命令的影响。如果灯是红色而不是绿色，我该如何排除故障？我想我会打电话回办公室求助（泪水可选）。

当然，网络工程不是关于在设备上输入命令，而是建立一种允许服务尽可能顺畅地从一点传递到另一点的方式。我们必须使用的命令和我们必须解释的输出只是达到目的的手段。换句话说，我们应该专注于网络的意图。我们想要网络实现的目标比我们用来让设备做我们想让它做的命令语法更重要。如果我们进一步提取描述我们意图的代码行的想法，我们可以潜在地将我们整个基础设施描述为特定状态。基础设施将在代码行中描述，并有必要的软件或框架强制执行该状态。

# 基于意图驱动的网络

自从这本书第一版出版以来，“基于意图的网络”这个术语在主要网络供应商选择将其用于描述其下一代设备后得到了更多的使用。在我看来，“基于意图驱动的网络”是定义网络应该处于的状态，并有软件代码来强制执行该状态的想法。举个例子，如果我的目标是阻止端口 80 被外部访问，那么我应该将这个作为网络意图声明。底层软件将负责知道配置和应用必要的访问控制列表的语法在边界路由器上实现这个目标。当然，“基于意图驱动的网络”是一个没有明确实现的想法。但这个想法很简单明了，我在此要主张我们应该更多地关注网络的意图，并摆脱设备级别的交互。

在使用 API 时，我认为这让我们更接近基于意图驱动的网络的状态。简而言之，因为我们抽象了在目标设备上执行的特定命令的层，我们关注的是我们的意图，而不是具体的命令。例如，回到我们的“阻止端口 80”的访问控制列表的例子，我们可能在思科上使用访问控制列表和访问组，而在 Juniper 上使用过滤列表。然而，在使用 API 时，我们的程序可以开始询问执行者的意图，同时掩盖他们正在与何种物理设备交流。我们甚至可以使用更高级的声明性框架，比如 Ansible，我们将在第四章中介绍，即《Python 自动化框架- Ansible 基础》。但现在，让我们专注于网络 API。

# 屏幕抓取与 API 结构化输出

想象一个常见的情景，我们需要登录到网络设备，并确保设备上的所有接口都处于 up/up 状态（状态和协议都显示为`up`）。对于人类网络工程师来说，登录到 Cisco NX-OS 设备，通过终端发出`show IP interface brief`命令就足够简单，可以轻松地从输出中看出哪个接口是 up 的：

```py
 nx-osv-2# show ip int brief
    IP Interface Status for VRF "default"(1)
    Interface IP Address Interface Status
    Lo0 192.168.0.2 protocol-up/link-up/admin-up
    Eth2/1 10.0.0.6 protocol-up/link-up/admin-up
    nx-osv-2#
```

换行符、空格和列标题的第一行很容易从人眼中区分出来。事实上，它们是为了帮助我们对齐，比如说，从第一行到第二行和第三行的每个接口的 IP 地址。如果我们把自己放在计算机的位置上，所有这些空格和换行只会让我们远离真正重要的输出，那就是：哪些接口处于 up/up 状态？为了说明这一点，我们可以看一下相同操作的 Paramiko 输出：

```py
 >>> new_connection.send('sh ip int briefn')
    16
    >>> output = new_connection.recv(5000)
    >>> print(output)
    b'sh ip int briefrrnIP Interface Status for VRF 
    "default"(1)rnInterface IP Address Interface 
    StatusrnLo0 192.168.0.2 protocol-up/link-up/admin-up 
    rnEth2/1 10.0.0.6 protocol-up/link-up/admin-up rnrnx-
    osv-2# '
    >>>
```

如果我们要解析出这些数据，我会以伪代码的方式进行如下操作（简化了我将要编写的代码的表示方式）：

1.  通过换行符分割每一行。

1.  我可能不需要包含`show ip interface brief`执行命令的第一行。目前，我认为我不需要它。

1.  删除第二行直到 VRF 的所有内容，并将其保存在一个变量中，因为我们想知道输出显示的是哪个 VRF。

1.  对于其余的行，因为我们不知道有多少个接口，我们将使用正则表达式语句来搜索行是否以可能的接口开头，比如`lo`表示环回接口，`Eth`表示以太网接口。

1.  我们需要通过空格将这行分成三个部分，每个部分包括接口名称、IP 地址，然后是接口状态。

1.  然后进一步使用斜杠(`/`)分割接口状态，以获取协议、链路和管理状态。

哇，这需要大量的工作，而人类一眼就能看出来！你可能能够优化代码和行数，但总的来说，当我们需要屏幕抓取一些结构不太清晰的东西时，这就是我们需要做的。这种方法有许多缺点，但我能看到的一些更大的问题列在下面：

+   **可扩展性**：我们花了很多时间来仔细解析每个命令的输出。很难想象我们如何能够对我们通常运行的数百个命令进行这样的操作。

+   **可预测性**：实际上并没有保证输出在不同软件版本之间保持不变。如果输出稍有变化，可能会使我们辛苦收集的信息变得毫无用处。

+   **供应商和软件锁定**：也许最大的问题是，一旦我们花费了所有这些时间来解析特定供应商和软件版本（在本例中为 Cisco NX-OS）的输出，我们需要重复这个过程来选择下一个供应商。我不知道你怎么看，但如果我要评估一个新的供应商，如果我不得不重新编写所有的屏幕抓取代码，那么新的供应商就处于严重的入门劣势。

让我们将其与相同`show IP interface brief`命令的 NX-API 调用输出进行比较。我们将在本章后面详细介绍如何从设备中获取此输出，但这里重要的是将以下输出与先前的屏幕抓取输出进行比较：

```py
    {
     "ins_api":{
     "outputs":{
     "output":{
     "body":{
     "TABLE_intf":[
       {
       "ROW_intf":{
       "admin-state":"up",
       "intf-name":"Lo0",
       "iod":84,
       "ip-disabled":"FALSE",
       "link-state":"up",
       "prefix":"192.168.0.2",
       "proto-state":"up"
       }
       },
     {
     "ROW_intf":{
     "admin-state":"up",
     "intf-name":"Eth2/1",
     "iod":36,
     "ip-disabled":"FALSE",
     "link-state":"up",
     "prefix":"10.0.0.6",
     "proto-state":"up"
     }
     }
     ],
      "TABLE_vrf":[
      {
     "ROW_vrf":{
     "vrf-name-out":"default"
     }
     },
     {
     "ROW_vrf":{
     "vrf-name-out":"default"
     }
     }
     ]
     },
     "code":"200",
     "input":"show ip int brief",
     "msg":"Success"
     }
     },
     "sid":"eoc",
     "type":"cli_show",
     "version":"1.2"
     }
    }
```

NX-API 可以返回 XML 或 JSON 格式的输出，这是我们正在查看的 JSON 输出。您可以立即看到输出是结构化的，并且可以直接映射到 Python 字典数据结构。无需解析-您只需选择键并检索与键关联的值。您还可以从输出中看到各种元数据，例如命令的成功或失败。如果命令失败，将显示一条消息，告诉发送者失败的原因。您不再需要跟踪已发出的命令，因为它已在“输入”字段中返回给您。输出中还有其他有用的元数据，例如 NX-API 版本。

这种类型的交换使供应商和运营商的生活更加轻松。对于供应商来说，他们可以轻松地传输配置和状态信息。当需要公开额外数据时，他们可以使用相同的数据结构添加额外字段。对于运营商来说，他们可以轻松地摄取信息并围绕它构建基础设施。一般认为自动化是非常需要的，也是一件好事。问题通常集中在自动化的格式和结构上。正如您将在本章后面看到的，API 的伞下有许多竞争技术。仅在传输方面，我们有 REST API、NETCONF 和 RESTCONF 等。最终，整体市场可能会决定未来的最终数据格式。与此同时，我们每个人都可以形成自己的观点，并帮助推动行业向前发展。

# 基础设施的数据建模

根据维基百科（[`en.wikipedia.org/wiki/Data_model`](https://en.wikipedia.org/wiki/Data_model)）的定义，数据模型的定义如下：

数据模型是一个抽象模型，它组织数据元素并规范它们之间以及与现实世界实体属性的关系。例如，数据模型可以指定代表汽车的数据元素由许多其他元素组成，这些元素反过来代表汽车的颜色和大小，并定义其所有者。

数据建模过程可以用以下图表来说明：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/2c817be7-d41c-47bd-929a-130e1a63fd87.png)数据建模过程

当应用于网络时，我们可以将这个概念应用为描述我们的网络的抽象模型，无论是数据中心、校园还是全球广域网。如果我们仔细观察物理数据中心，可以将层 2 以太网交换机视为包含 MAC 地址映射到每个端口的设备。我们的交换机数据模型描述了 MAC 地址应该如何保存在表中，其中包括键、附加特性（考虑 VLAN 和私有 VLAN）等。同样，我们可以超越设备，将整个数据中心映射到一个模型中。我们可以从每个接入、分发和核心层中的设备数量开始，它们是如何连接的，以及它们在生产环境中应该如何行为。例如，如果我们有一个 fat-tree 网络，每个脊柱路由器应该有多少链接，它们应该包含多少路由，每个前缀应该有多少下一跳？这些特性可以以一种格式映射出来，可以与我们应该始终检查的理想状态进行对比。

**另一种下一代**（**YANG**）是一种相对新的网络数据建模语言，正在受到关注（尽管一般的看法是，一些 IETF 工作组确实有幽默感）。它首次在 2010 年的 RFC 6020 中发布，并且自那时以来在供应商和运营商中得到了广泛的应用。在撰写本文时，对 YANG 的支持在供应商和平台之间差异很大。因此，生产中的适应率相对较低。但是，这是一项值得关注的技术。

# 思科 API 和 ACI

思科系统是网络领域的 800 磅大猩猩，在网络自动化的趋势中没有落后。在推动网络自动化的过程中，他们进行了各种内部开发、产品增强、合作伙伴关系，以及许多外部收购。然而，由于产品线涵盖路由器、交换机、防火墙、服务器（统一计算）、无线、协作软件和硬件以及分析软件等，要知道从哪里开始是很困难的。

由于这本书侧重于 Python 和网络，我们将把这一部分范围限定在主要的网络产品上。特别是，我们将涵盖以下内容：

+   NX-API 的 Nexus 产品自动化

+   思科 NETCONF 和 YANG 示例

+   数据中心的思科应用中心基础设施

+   企业级思科应用中心基础设施

对于这里的 NX-API 和 NETCONF 示例，我们可以使用思科 DevNet 始终开启的实验室设备，或者在本地运行思科 VIRL。由于 ACI 是一个独立的产品，并且在以下 ACI 示例中与物理交换机一起许可使用，我建议使用 DevNet 实验室来了解这些工具。如果你是那些有自己的私人 ACI 实验室可以使用的幸运工程师之一，请随意在相关示例中使用它。

我们将使用与第二章中相同的实验拓扑，*低级网络设备交互*，只有一个设备运行 nx-osv 除外：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/f905b772-b032-4d3a-b935-4d5cdd6b0faf.png) 实验室拓扑

让我们来看看 NX-API。

# 思科 NX-API

Nexus 是思科的主要数据中心交换机产品线。NX-API ([`www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/6-x/programmability/guide/b_Cisco_Nexus_9000_Ser`](http://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/6-x/programmability/guide/b_Cisco_Nexus_9000_Series_NX-OS_Programmability_Guide/b_Cisco_Nexus_9000_Series_NX-OS_Programmability_Guide_chapter_011.html)[ies_NX-OS_Programmability_Guide/b_Cisco_Nexus_9000_Series_NX-OS_Programmability_Guide_chapter_011.html](http://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/6-x/programmability/guide/b_Cisco_Nexus_9000_Series_NX-OS_Programmability_Guide/b_Cisco_Nexus_9000_Series_NX-OS_Programmability_Guide_chapter_011.html))允许工程师通过各种传输方式与交换机进行交互，包括 SSH、HTTP 和 HTTPS。

# 实验室软件安装和设备准备

以下是我们将安装的 Ubuntu 软件包。你可能已经安装了一些软件包，比如`pip`和`git`：

```py
$ sudo apt-get install -y python3-dev libxml2-dev libxslt1-dev libffi-dev libssl-dev zlib1g-dev python3-pip git python3-requests
```

如果你使用的是 Python 2，使用以下软件包代替：`sudo apt-get install -y python-dev libxml2-dev libxslt1-dev libffi-dev libssl-dev zlib1g-dev python-pip git python-requests`。

`ncclient` ([`github.com/ncclient/ncclient`](https://github.com/ncclient/ncclient))库是一个用于 NETCONF 客户端的 Python 库。我们将从 GitHub 存储库中安装它，以便安装最新版本：

```py
$ git clone https://github.com/ncclient/ncclient
$ cd ncclient/
$ sudo python3 setup.py install
$ sudo python setup.py install #for Python 2
```

Nexus 设备上的 NX-API 默认关闭，因此我们需要打开它。我们可以使用已经创建的用户（如果你使用的是 VIRL 自动配置），或者为 NETCONF 过程创建一个新用户：

```py
feature nxapi
username cisco password 5 $1$Nk7ZkwH0$fyiRmMMfIheqE3BqvcL0C1 role network-operator
username cisco role network-admin
username cisco passphrase lifetime 99999 warntime 14 gracetime 3
```

对于我们的实验室，我们将同时打开 HTTP 和沙盒配置，因为它们在生产中应该关闭：

```py
nx-osv-2(config)# nxapi http port 80
nx-osv-2(config)# nxapi sandbox
```

我们现在准备看我们的第一个 NX-API 示例。

# NX-API 示例

NX-API 沙盒是一个很好的方式来玩各种命令、数据格式，甚至可以直接从网页上复制 Python 脚本。在最后一步，我们为了学习目的打开了它。在生产中应该关闭它。让我们打开一个网页浏览器，看看基于我们已经熟悉的 CLI 命令的各种消息格式、请求和响应。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/3d7aec04-66a7-4ecb-95c2-f19b17fd399a.png)

在下面的例子中，我选择了`JSON-RPC`和`CLI`命令类型来执行`show version`命令：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/48fbd88d-cc73-4a69-aa66-fff954aaa457.png)

如果你对消息格式的支持性不确定，或者对你想在代码中检索的值的响应数据字段键有疑问，沙盒会派上用场。

在我们的第一个例子中，我们只是连接到 Nexus 设备，并在连接时打印出交换的能力：

```py
    #!/usr/bin/env python3
    from ncclient import manager
    conn = manager.connect(
            host='172.16.1.90',
            port=22,
            username='cisco',
            password='cisco',
            hostkey_verify=False,
            device_params={'name': 'nexus'},
            look_for_keys=False)
    for value in conn.server_capabilities:
        print(value)
    conn.close_session()
```

主机、端口、用户名和密码的连接参数都很容易理解。设备参数指定了客户端连接的设备类型。当使用 ncclient 库时，在 Juniper NETCONF 部分会看到不同的响应。`hostkey_verify`绕过了 SSH 的`known_host`要求；如果不绕过，主机需要列在`~/.ssh/known_hosts`文件中。`look_for_keys`选项禁用了公钥私钥认证，而是使用用户名和密码进行认证。

如果你在 Python 3 和 Paramiko 中遇到问题，请随时使用 Python 2。希望在你阅读本节时，这个问题已经得到解决。

输出将显示这个版本的 NX-OS 支持的 XML 和 NETCONF 特性：

```py
$ python cisco_nxapi_1.py
urn:ietf:params:netconf:capability:writable-running:1.0
urn:ietf:params:netconf:capability:rollback-on-error:1.0
urn:ietf:params:netconf:capability:validate:1.0
urn:ietf:params:netconf:capability:url:1.0?scheme=file
urn:ietf:params:netconf:base:1.0
urn:ietf:params:netconf:capability:candidate:1.0
urn:ietf:params:netconf:capability:confirmed-commit:1.0
urn:ietf:params:xml:ns:netconf:base:1.0
```

使用 ncclient 和通过 SSH 的 NETCONF 非常好，因为它让我们更接近本地实现和语法。我们将在本书的后面使用相同的库。对于 NX-API，处理 HTTPS 和 JSON-RPC 可能更容易。在 NX-API 开发者沙箱的早期截图中，如果你注意到，在请求框中，有一个标有 Python 的框。如果你点击它，你将能够获得一个基于请求库自动生成的 Python 脚本。

以下脚本使用了一个名为`requests`的外部 Python 库。`requests`是一个非常流行的、自称为人类的 HTTP 库，被亚马逊、谷歌、NSA 等公司使用。你可以在官方网站上找到更多关于它的信息。

对于`show version`的例子，以下 Python 脚本是自动生成的。我将输出粘贴在这里，没有进行任何修改：

```py
    """
     NX-API-BOT 
    """
    import requests
    import json

    """
    Modify these please
    """
    url='http://YOURIP/ins'
    switchuser='USERID'
    switchpassword='PASSWORD'

    myheaders={'content-type':'application/json-rpc'}
    payload=[
      {
        "jsonrpc": "2.0",
        "method": "cli",
        "params": {
          "cmd": "show version",
          "version": 1.2
        },
        "id": 1
      }
    ]
    response = requests.post(url,data=json.dumps(payload), 
    headers=myheaders,auth=(switchuser,switchpassword)).json()
```

在`cisco_nxapi_2.py`脚本中，你会看到我只修改了前面文件的 URL、用户名和密码。输出被解析为只包括软件版本。以下是输出：

```py
$ python3 cisco_nxapi_2.py
7.2(0)D1(1) [build 7.2(0)ZD(0.120)]
```

使用这种方法的最好之处在于，相同的总体语法结构既适用于配置命令，也适用于显示命令。这在`cisco_nxapi_3.py`文件中有所体现。对于多行配置，你可以使用 ID 字段来指定操作的顺序。在`cisco_nxapi_4.py`中，列出了用于更改接口 Ethernet 2/12 的描述的有效负载：

```py
      {
        "jsonrpc": "2.0",
        "method": "cli",
        "params": {
          "cmd": "interface ethernet 2/12",
          "version": 1.2
        },
        "id": 1
      },
      {
        "jsonrpc": "2.0",
        "method": "cli",
        "params": {
          "cmd": "description foo-bar",
          "version": 1.2
        },
        "id": 2
      },
      {
        "jsonrpc": "2.0",
        "method": "cli",
        "params": {
          "cmd": "end",
          "version": 1.2
        },
        "id": 3
      },
      {
        "jsonrpc": "2.0",
        "method": "cli",
        "params": {
          "cmd": "copy run start",
          "version": 1.2
        },
        "id": 4
      }
    ]
```

我们可以通过查看 Nexus 设备的运行配置来验证前面配置脚本的结果：

```py
hostname nx-osv-1-new
...
interface Ethernet2/12
description foo-bar
shutdown
no switchport
mac-address 0000.0000.002f 
```

在接下来的部分，我们将看一些关于 Cisco NETCONF 和 YANG 模型的例子。

# Cisco 和 YANG 模型

在本章的前面，我们探讨了使用数据建模语言 YANG 来表达网络的可能性。让我们通过例子再深入了解一下。

首先，我们应该知道 YANG 模型只定义了通过 NETCONF 协议发送的数据类型，而不规定数据应该是什么。其次，值得指出的是 NETCONF 存在作为一个独立的协议，正如我们在 NX-API 部分看到的那样。YANG 作为相对较新的技术，在各个供应商和产品线之间的支持性不够稳定。例如，如果我们对运行 IOS-XE 的 Cisco 1000v 运行相同的能力交换脚本，我们会看到这样的结果：

```py
 urn:cisco:params:xml:ns:yang:cisco-virtual-service?module=cisco-
 virtual-service&revision=2015-04-09
 http://tail-f.com/ns/mibs/SNMP-NOTIFICATION-MIB/200210140000Z?
 module=SNMP-NOTIFICATION-MIB&revision=2002-10-14
 urn:ietf:params:xml:ns:yang:iana-crypt-hash?module=iana-crypt-
 hash&revision=2014-04-04&features=crypt-hash-sha-512,crypt-hash-
 sha-256,crypt-hash-md5
 urn:ietf:params:xml:ns:yang:smiv2:TUNNEL-MIB?module=TUNNEL-
 MIB&revision=2005-05-16
 urn:ietf:params:xml:ns:yang:smiv2:CISCO-IP-URPF-MIB?module=CISCO-
 IP-URPF-MIB&revision=2011-12-29
 urn:ietf:params:xml:ns:yang:smiv2:ENTITY-STATE-MIB?module=ENTITY-
 STATE-MIB&revision=2005-11-22
 urn:ietf:params:xml:ns:yang:smiv2:IANAifType-MIB?module=IANAifType-
 MIB&revision=2006-03-31
 <omitted>
```

将此与我们在 NX-OS 中看到的输出进行比较。显然，IOS-XE 对 YANG 模型功能的支持要比 NX-OS 多。在整个行业范围内，当支持时，网络数据建模显然是可以跨设备使用的，这对于网络自动化是有益的。然而，鉴于供应商和产品的支持不均衡，我认为它还不够成熟，不能完全用于生产网络。对于本书，我包含了一个名为`cisco_yang_1.py`的脚本，演示了如何使用 YANG 过滤器`urn:ietf:params:xml:ns:yang:ietf-interfaces`来解析 NETCONF XML 输出的起点。

您可以在 YANG GitHub 项目页面上检查最新的供应商支持（[`github.com/YangModels/yang/tree/master/vendor`](https://github.com/YangModels/yang/tree/master/vendor)）。

# Cisco ACI

Cisco **Application Centric Infrastructure**（**ACI**）旨在为所有网络组件提供集中化的方法。在数据中心环境中，这意味着集中控制器知道并管理着脊柱、叶子和机架顶部交换机，以及所有网络服务功能。这可以通过 GUI、CLI 或 API 来实现。有人可能会认为 ACI 是思科对更广泛的基于控制器的软件定义网络的回应。

对于 ACI 而言，有点令人困惑的是 ACI 和 APIC-EM 之间的区别。简而言之，ACI 专注于数据中心操作，而 APIC-EM 专注于企业模块。两者都提供了对网络组件的集中视图和控制，但每个都有自己的重点和工具集。例如，很少见到任何主要数据中心部署面向客户的无线基础设施，但无线网络是当今企业的重要组成部分。另一个例子是网络安全的不同方法。虽然安全在任何网络中都很重要，但在数据中心环境中，许多安全策略被推送到服务器的边缘节点以实现可伸缩性。在企业安全中，策略在网络设备和服务器之间有一定的共享。

与 NETCONF RPC 不同，ACI API 遵循 REST 模型，使用 HTTP 动词（`GET`，`POST`，`DELETE`）来指定所需的操作。

我们可以查看`cisco_apic_em_1.py`文件，这是 Cisco 示例代码`lab2-1-get-network-device-list.py`的修改版本（[`github.com/CiscoDevNet/apicem-1.3-LL-sample-codes/blob/master/basic-labs/lab2-1-get-network-device-list.py`](https://github.com/CiscoDevNet/apicem-1.3-LL-sample-codes/blob/master/basic-labs/lab2-1-get-network-device-list.py)）。

在以下部分列出了没有注释和空格的缩写版本。

名为`getTicket()`的第一个函数在控制器上使用 HTTPS `POST`，路径为`/api/v1/ticket`，在标头中嵌入用户名和密码。此函数将返回仅在有限时间内有效的票证的解析响应：

```py
  def getTicket():
      url = "https://" + controller + "/api/v1/ticket"
      payload = {"username":"usernae","password":"password"}
      header = {"content-type": "application/json"}
      response= requests.post(url,data=json.dumps(payload), headers=header, verify=False)
      r_json=response.json()
      ticket = r_json["response"]["serviceTicket"]
      return ticket
```

然后，第二个函数调用另一个名为`/api/v1/network-devices`的路径，并在标头中嵌入新获取的票证，然后解析结果：

```py
url = "https://" + controller + "/api/v1/network-device"
header = {"content-type": "application/json", "X-Auth-Token":ticket}
```

这是 API 交互的一个常见工作流程。客户端将在第一个请求中使用服务器进行身份验证，并接收一个基于时间的令牌。此令牌将在后续请求中使用，并将作为身份验证的证明。

输出显示了原始 JSON 响应输出以及解析后的表格。执行针对 DevNet 实验室控制器的部分输出如下所示：

```py
    Network Devices =
    {
     "version": "1.0",
     "response": [
     {
     "reachabilityStatus": "Unreachable",
     "id": "8dbd8068-1091-4cde-8cf5-d1b58dc5c9c7",
     "platformId": "WS-C2960C-8PC-L",
    <omitted>
     "lineCardId": null,
     "family": "Wireless Controller",
     "interfaceCount": "12",
     "upTime": "497 days, 2:27:52.95"
     }
    ]
    }
    8dbd8068-1091-4cde-8cf5-d1b58dc5c9c7 Cisco Catalyst 2960-C Series
     Switches
    cd6d9b24-839b-4d58-adfe-3fdf781e1782 Cisco 3500I Series Unified
    Access Points
    <omitted>
    55450140-de19-47b5-ae80-bfd741b23fd9 Cisco 4400 Series Integrated 
    Services Routers
    ae19cd21-1b26-4f58-8ccd-d265deabb6c3 Cisco 5500 Series Wireless LAN 
    Controllers
```

正如您所看到的，我们只查询了一个控制器设备，但我们能够高层次地查看控制器所知道的所有网络设备。在我们的输出中，Catalyst 2960-C 交换机，3500 接入点，4400 ISR 路由器和 5500 无线控制器都可以进一步探索。当然，缺点是 ACI 控制器目前只支持 Cisco 设备。

# Juniper 网络的 Python API

Juniper 网络一直是服务提供商群体中的最爱。如果我们退一步看看服务提供商垂直领域，自动化网络设备将是他们需求清单的首要任务。在云规模数据中心出现之前，服务提供商是拥有最多网络设备的人。一个典型的企业网络可能在公司总部有几个冗余的互联网连接，还有一些以枢纽-辐射方式连接回总部，使用服务提供商的私有 MPLS 网络。对于服务提供商来说，他们需要构建、配置、管理和排除连接和底层网络的问题。他们通过销售带宽以及增值的托管服务来赚钱。对于服务提供商来说，投资于自动化以使用最少的工程小时数来保持网络运行是合理的。在他们的用例中，网络自动化是他们竞争优势的关键。

在我看来，服务提供商网络的需求与云数据中心相比的一个区别是，传统上，服务提供商将更多的服务聚合到单个设备中。一个很好的例子是**多协议标签交换**（**MPLS**），几乎所有主要的服务提供商都提供，但在企业或数据中心网络中很少使用。正如 Juniper 非常成功地发现了这一需求，并且在满足服务提供商自动化需求方面表现出色。让我们来看一下 Juniper 的一些自动化 API。

# Juniper 和 NETCONF

**网络配置协议**（**NETCONF**）是一个 IETF 标准，最早于 2006 年发布为[RFC 4741](https://tools.ietf.org/html/rfc4741)，后来修订为[RFC 6241](https://tools.ietf.org/html/rfc6241)。Juniper 网络对这两个 RFC 标准做出了重大贡献。事实上，Juniper 是 RFC 4741 的唯一作者。Juniper 设备完全支持 NETCONF 是合情合理的，并且它作为大多数自动化工具和框架的基础层。NETCONF 的一些主要特点包括以下内容：

1.  它使用**可扩展标记语言**（**XML**）进行数据编码。

1.  它使用**远程过程调用**（**RPC**），因此在使用 HTTP(s)作为传输方式时，URL 端点是相同的，而所需的操作在请求的正文中指定。

1.  它在概念上是基于自上而下的层。这些层包括内容、操作、消息和传输：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/46006bbf-bde4-4219-b26e-451e09a7d384.png)NETCONF 模型

Juniper 网络在其技术库中提供了一个广泛的 NETCONF XML 管理协议开发者指南（[`www.juniper.net/techpubs/en_US/junos13.2/information-products/pathway-pages/netconf-guide/netconf.html#overview`](https://www.juniper.net/techpubs/en_US/junos13.2/information-products/pathway-pages/netconf-guide/netconf.html#overview)）。让我们来看一下它的用法。

# 设备准备

为了开始使用 NETCONF，让我们创建一个单独的用户，并打开所需的服务：

```py
 set system login user netconf uid 2001
 set system login user netconf class super-user
 set system login user netconf authentication encrypted-password
 "$1$0EkA.XVf$cm80A0GC2dgSWJIYWv7Pt1"
 set system services ssh
 set system services telnet
 set system services netconf ssh port 830
```

对于 Juniper 设备实验室，我正在使用一个名为**Juniper Olive**的较旧、不受支持的平台。它仅用于实验目的。您可以使用您喜欢的搜索引擎找出一些关于 Juniper Olive 的有趣事实和历史。

在 Juniper 设备上，您可以随时查看配置，无论是在一个平面文件中还是在 XML 格式中。当您需要指定一条命令来进行配置更改时，`flat`文件非常方便：

```py
 netconf@foo> show configuration | display set
 set version 12.1R1.9
 set system host-name foo
 set system domain-name bar
 <omitted>
```

在某些情况下，当您需要查看配置的 XML 结构时，XML 格式非常方便：

```py
 netconf@foo> show configuration | display xml
 <rpc-reply >
 <configuration junos:commit-seconds="1485561328" junos:commit-
 localtime="2017-01-27 23:55:28 UTC" junos:commit-user="netconf">
 <version>12.1R1.9</version>
 <system>
 <host-name>foo</host-name>
 <domain-name>bar</domain-name>
```

我们已经在 Cisco 部分安装了必要的 Linux 库和 ncclient Python 库。如果您还没有这样做，请参考该部分并安装必要的软件包。

我们现在准备好查看我们的第一个 Juniper NETCONF 示例。

# Juniper NETCONF 示例

我们将使用一个非常简单的示例来执行`show version`。我们将把这个文件命名为`junos_netconf_1.py`：

```py
  #!/usr/bin/env python3

  from ncclient import manager

  conn = manager.connect(
      host='192.168.24.252',
      port='830',
      username='netconf',
      password='juniper!',
      timeout=10,
      device_params={'name':'junos'},
      hostkey_verify=False)

  result = conn.command('show version', format='text')
  print(result)
  conn.close_session()
```

脚本中的所有字段应该都很容易理解，除了`device_params`。从 ncclient 0.4.1 开始，添加了设备处理程序，用于指定不同的供应商或平台。例如，名称可以是 juniper、CSR、Nexus 或 Huawei。我们还添加了`hostkey_verify=False`，因为我们使用的是 Juniper 设备的自签名证书。

返回的输出是用 XML 编码的`rpc-reply`，其中包含一个`output`元素：

```py
    <rpc-reply message-id="urn:uuid:7d9280eb-1384-45fe-be48-
    b7cd14ccf2b7">
    <output>
    Hostname: foo
 Model: olive
 JUNOS Base OS boot [12.1R1.9]
 JUNOS Base OS Software Suite [12.1R1.9]
 <omitted>
 JUNOS Runtime Software Suite [12.1R1.9]
 JUNOS Routing Software Suite [12.1R1.9]
    </output>
    </rpc-reply>
```

我们可以解析 XML 输出以仅包括输出文本：

```py
      print(result.xpath('output')[0].text)
```

在`junos_netconf_2.py`中，我们将对设备进行配置更改。我们将从一些新的导入开始，用于构建新的 XML 元素和连接管理器对象：

```py
      #!/usr/bin/env python3

      from ncclient import manager
      from ncclient.xml_ import new_ele, sub_ele

      conn = manager.connect(host='192.168.24.252', port='830', 
    username='netconf' , password='juniper!', timeout=10, 
    device_params={'name':'junos'}, hostkey_v erify=False)
```

我们将锁定配置并进行配置更改：

```py
      # lock configuration and make configuration changes
      conn.lock()

      # build configuration
      config = new_ele('system')
      sub_ele(config, 'host-name').text = 'master'
      sub_ele(config, 'domain-name').text = 'python'
```

在构建配置部分，我们创建一个`system`元素，其中包含`host-name`和`domain-name`子元素。如果你想知道层次结构，你可以从 XML 显示中看到`system`的节点结构是`host-name`和`domain-name`的父节点：

```py
     <system>
        <host-name>foo</host-name>
        <domain-name>bar</domain-name>
    ...
    </system>
```

配置构建完成后，脚本将推送配置并提交配置更改。这些是 Juniper 配置更改的正常最佳实践步骤（锁定、配置、解锁、提交）：

```py
      # send, validate, and commit config
      conn.load_configuration(config=config)
      conn.validate()
      commit_config = conn.commit()
      print(commit_config.tostring)

      # unlock config
      conn.unlock()

      # close session
      conn.close_session()
```

总的来说，NETCONF 步骤与 CLI 步骤非常相似。请查看`junos_netconf_3.py`脚本，以获取更多可重用的代码。以下示例将步骤示例与一些 Python 函数结合起来：

```py
# make a connection object
def connect(host, port, user, password):
    connection = manager.connect(host=host, port=port, username=user,
            password=password, timeout=10, device_params={'name':'junos'},
            hostkey_verify=False)
    return connection

# execute show commands
def show_cmds(conn, cmd):
    result = conn.command(cmd, format='text')
    return result

# push out configuration
def config_cmds(conn, config):
    conn.lock()
    conn.load_configuration(config=config)
    commit_config = conn.commit()
    return commit_config.tostring
```

这个文件可以自行执行，也可以被导入到其他 Python 脚本中使用。

Juniper 还提供了一个名为 PyEZ 的 Python 库，可用于其设备。我们将在下一节中看一些使用该库的示例。

# 开发人员的 Juniper PyEZ

**PyEZ**是一个高级的 Python 实现，与现有的 Python 代码更好地集成。通过使用 Python API，您可以执行常见的操作和配置任务，而无需对 Junos CLI 有深入的了解。

Juniper 在其技术库的[`www.juniper.net/techpubs/en_US/junos-pyez1.0/information-products/pathway-pages/junos-pyez-developer-guide.html#configuration`](https://www.juniper.net/techpubs/en_US/junos-pyez1.0/information-products/pathway-pages/junos-pyez-developer-guide.html#configuration)上维护了一份全面的 Junos PyEZ 开发人员指南。如果您有兴趣使用 PyEZ，我强烈建议至少浏览一下指南中的各个主题。

# 安装和准备

每个操作系统的安装说明都可以在*安装 Junos PyEZ* ([`www.juniper.net/techpubs/en_US/junos-pyez1.0/topics/task/installation/junos-pyez-server-installing.html`](https://www.juniper.net/techpubs/en_US/junos-pyez1.0/topics/task/installation/junos-pyez-server-installing.html))页面上找到。我们将展示 Ubuntu 16.04 的安装说明。

以下是一些依赖包，其中许多应该已经在主机上运行之前的示例中了：

```py
$ sudo apt-get install -y python3-pip python3-dev libxml2-dev libxslt1-dev libssl-dev libffi-dev
```

`PyEZ`包可以通过 pip 安装。在这里，我已经为 Python 3 和 Python 2 都安装了：

```py
$ sudo pip3 install junos-eznc
$ sudo pip install junos-eznc
```

在 Juniper 设备上，NETCONF 需要配置为 PyEZ 的基础 XML API：

```py
set system services netconf ssh port 830
```

对于用户认证，我们可以使用密码认证或 SSH 密钥对。创建本地用户很简单：

```py
set system login user netconf uid 2001
set system login user netconf class super-user
set system login user netconf authentication encrypted-password "$1$0EkA.XVf$cm80A0GC2dgSWJIYWv7Pt1"
```

对于`ssh`密钥认证，首先在主机上生成密钥对：

```py
$ ssh-keygen -t rsa
```

默认情况下，公钥将被称为`id_rsa.pub`，位于`~/.ssh/`目录下，而私钥将被命名为`id_rsa`，位于相同的目录下。将私钥视为永远不共享的密码。公钥可以自由分发。在我们的用例中，我们将把公钥移动到`/tmp`目录，并启用 Python 3 HTTP 服务器模块以创建可访问的 URL：

```py
$ mv ~/.ssh/id_rsa.pub /tmp
$ cd /tmp
$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 ...
```

对于 Python 2，请改用`python -m SimpleHTTPServer`。

从 Juniper 设备中，我们可以通过从 Python 3 web 服务器下载公钥来创建用户并关联公钥：

```py
netconf@foo# set system login user echou class super-user authentication load-key-file http://192.168.24.164:8000/id_rsa.pub
/var/home/netconf/...transferring.file........100% of 394 B 2482 kBps
```

现在，如果我们尝试使用管理站的私钥进行 ssh，用户将自动进行身份验证：

```py
$ ssh -i ~/.ssh/id_rsa 192.168.24.252
--- JUNOS 12.1R1.9 built 2012-03-24 12:52:33 UTC
echou@foo>
```

让我们确保两种身份验证方法都可以与 PyEZ 一起使用。让我们尝试用户名和密码组合：

```py
Python 3.5.2 (default, Nov 17 2016, 17:05:23)
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from jnpr.junos import Device
>>> dev = Device(host='192.168.24.252', user='netconf', password='juniper!')
>>> dev.open()
Device(192.168.24.252)
>>> dev.facts
{'serialnumber': '', 'personality': 'UNKNOWN', 'model': 'olive', 'ifd_style': 'CLASSIC', '2RE': False, 'HOME': '/var/home/juniper', 'version_info': junos.version_info(major=(12, 1), type=R, minor=1, build=9), 'switch_style': 'NONE', 'fqdn': 'foo.bar', 'hostname': 'foo', 'version': '12.1R1.9', 'domain': 'bar', 'vc_capable': False}
>>> dev.close()
```

我们也可以尝试使用 SSH 密钥身份验证：

```py
>>> from jnpr.junos import Device
>>> dev1 = Device(host='192.168.24.252', user='echou', ssh_private_key_file='/home/echou/.ssh/id_rsa')
>>> dev1.open()
Device(192.168.24.252)
>>> dev1.facts
{'HOME': '/var/home/echou', 'model': 'olive', 'hostname': 'foo', 'switch_style': 'NONE', 'personality': 'UNKNOWN', '2RE': False, 'domain': 'bar', 'vc_capable': False, 'version': '12.1R1.9', 'serialnumber': '', 'fqdn': 'foo.bar', 'ifd_style': 'CLASSIC', 'version_info': junos.version_info(major=(12, 1), type=R, minor=1, build=9)}
>>> dev1.close()
```

太好了！我们现在准备好查看一些 PyEZ 的示例了。

# PyEZ 示例

在之前的交互提示中，我们已经看到设备连接时，对象会自动检索有关设备的一些事实。在我们的第一个示例`junos_pyez_1.py`中，我们连接到设备并执行了`show interface em1`的 RPC 调用：

```py
      #!/usr/bin/env python3
      from jnpr.junos import Device
      import xml.etree.ElementTree as ET
      import pprint

      dev = Device(host='192.168.24.252', user='juniper', passwd='juniper!')

      try:
          dev.open()
      except Exception as err:
          print(err)
          sys.exit(1)

      result = 
    dev.rpc.get_interface_information(interface_name='em1', terse=True)
      pprint.pprint(ET.tostring(result))

      dev.close()
```

设备类具有一个包含所有操作命令的`rpc`属性。这非常棒，因为我们在 CLI 和 API 中可以做的事情之间没有差距。问题在于我们需要找出`xml rpc`元素标签。在我们的第一个示例中，我们如何知道`show interface em1`等同于`get_interface_information`？我们有三种方法可以找出这些信息：

1.  我们可以参考*Junos XML API 操作开发人员参考*

1.  我们可以使用 CLI 显示 XML RPC 等效，并用下划线（`_`）替换单词之间的破折号（`-`）

1.  我们还可以通过使用 PyEZ 库来进行编程

我通常使用第二个选项直接获取输出：

```py
 netconf@foo> show interfaces em1 | display xml rpc
 <rpc-reply >
 <rpc>
 <get-interface-information>
 <interface-name>em1</interface-name>
 </get-interface-information>
 </rpc>
 <cli>
 <banner></banner>
 </cli>
 </rpc-reply>
```

以下是使用 PyEZ 进行编程的示例（第三个选项）：

```py
 >>> dev1.display_xml_rpc('show interfaces em1', format='text')
 '<get-interface-information>n <interface-name>em1</interface-
 name>n</get-interface-information>n'
```

当然，我们还需要进行配置更改。在`junos_pyez_2.py`配置示例中，我们将从 PyEZ 导入一个额外的`Config()`方法：

```py
      #!/usr/bin/env python3
      from jnpr.junos import Device
      from jnpr.junos.utils.config import Config
```

我们将利用相同的块连接到设备：

```py
      dev = Device(host='192.168.24.252', user='juniper', 
    passwd='juniper!')

      try:
          dev.open()
      except Exception as err:
          print(err)
          sys.exit(1)
```

`new Config()`方法将加载 XML 数据并进行配置更改：

```py
      config_change = """
      <system>
        <host-name>master</host-name>
        <domain-name>python</domain-name>
      </system>
      """

      cu = Config(dev)
      cu.lock()
      cu.load(config_change)
      cu.commit()
      cu.unlock()

      dev.close()
```

PyEZ 示例设计简单。希望它们能展示您如何利用 PyEZ 满足 Junos 自动化需求的方式。

# Arista Python API

**Arista Networks**一直专注于大型数据中心网络。在其公司简介页面（[`www.arista.com/en/company/company-overview`](https://www.arista.com/en/company/company-overview)）中，如下所述：

“Arista Networks 成立的目的是开创并提供面向大型数据中心存储和计算环境的软件驱动云网络解决方案。”

请注意，该声明特别指出了**大型数据中心**，我们已经知道这些数据中心充斥着服务器、数据库和网络设备。自动化一直是 Arista 的主要特点之一是有道理的。事实上，他们的操作系统背后有一个 Linux 支撑，允许许多附加功能，如 Linux 命令和内置的 Python 解释器。

与其他供应商一样，您可以直接通过 eAPI 与 Arista 设备交互，或者您可以选择利用他们的`Python`库。我们将看到两者的示例。我们还将在后面的章节中看到 Arista 与 Ansible 框架的集成。

# Arista eAPI 管理

几年前，Arista 的 eAPI 首次在 EOS 4.12 中引入。它通过 HTTP 或 HTTPS 传输一系列显示或配置命令，并以 JSON 形式回应。一个重要的区别是它是**远程过程调用**（**RPC**）和**JSON-RPC**，而不是纯粹通过 HTTP 或 HTTPS 提供的 RESTFul API。对于我们的意图和目的，不同之处在于我们使用相同的 HTTP 方法（`POST`）向相同的 URL 端点发出请求。我们不是使用 HTTP 动词（`GET`，`POST`，`PUT`，`DELETE`）来表达我们的动作，而是简单地在请求的正文中说明我们的意图动作。在 eAPI 的情况下，我们将为我们的意图指定一个`method`键和一个`runCmds`值。

在以下示例中，我使用运行 EOS 4.16 的物理 Arista 交换机。

# eAPI 准备

Arista 设备上的 eAPI 代理默认处于禁用状态，因此我们需要在设备上启用它才能使用：

```py
arista1(config)#management api http-commands
arista1(config-mgmt-api-http-cmds)#no shut
arista1(config-mgmt-api-http-cmds)#protocol https port 443
arista1(config-mgmt-api-http-cmds)#no protocol http
arista1(config-mgmt-api-http-cmds)#vrf management
```

如您所见，我们已关闭 HTTP 服务器，而是仅使用 HTTPS 作为传输。从几个 EOS 版本前开始，默认情况下，管理接口位于名为**management**的 VRF 中。在我的拓扑中，我通过管理接口访问设备；因此，我已指定了 eAPI 管理的 VRF。您可以通过"show management api http-commands"命令检查 API 管理状态：

```py
arista1#sh management api http-commands
Enabled: Yes
HTTPS server: running, set to use port 443
HTTP server: shutdown, set to use port 80
Local HTTP server: shutdown, no authentication, set to use port 8080
Unix Socket server: shutdown, no authentication
VRF: management
Hits: 64
Last hit: 33 seconds ago
Bytes in: 8250
Bytes out: 29862
Requests: 23
Commands: 42
Duration: 7.086 seconds
SSL Profile: none
QoS DSCP: 0
 User Requests Bytes in Bytes out Last hit
----------- -------------- -------------- --------------- --------------
 admin 23 8250 29862 33 seconds ago

URLs
-----------------------------------------
Management1 : https://192.168.199.158:443

arista1#
```

启用代理后，您将能够通过访问设备的 IP 地址来访问 eAPI 的探索页面。如果您已更改访问的默认端口，只需在末尾添加即可。认证与交换机上的认证方法绑定。我们将使用设备上本地配置的用户名和密码。默认情况下，将使用自签名证书：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/3df6e19b-b674-427d-8fd8-e2b40dbfae9a.png)Arista EOS explorer

您将进入一个探索页面，在那里您可以输入 CLI 命令并获得请求正文的良好输出。例如，如果我想查看如何为`show version`制作请求正文，这就是我将从探索器中看到的输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/8579af8e-eb72-4dc3-baab-1ab7d8c937be.png)Arista EOS explorer viewer

概述链接将带您进入示例用途和背景信息，而命令文档将作为 show 命令的参考点。每个命令引用都将包含返回值字段名称、类型和简要描述。Arista 的在线参考脚本使用 jsonrpclib ([`github.com/joshmarshall/jsonrpclib/`](https://github.com/joshmarshall/jsonrpclib/))，这是我们将使用的。然而，截至撰写本书时，它依赖于 Python 2.6+，尚未移植到 Python 3；因此，我们将在这些示例中使用 Python 2.7。

在您阅读本书时，可能会有更新的状态。请阅读 GitHub 拉取请求 ([`github.com/joshmarshall/jsonrpclib/issues/38`](https://github.com/joshmarshall/jsonrpclib/issues/38)) 和 GitHub README ([`github.com/joshmarshall/jsonrpclib/`](https://github.com/joshmarshall/jsonrpclib/)) 以获取最新状态。

安装很简单，使用`easy_install`或`pip`：

```py
$ sudo easy_install jsonrpclib
$ sudo pip install jsonrpclib
```

# eAPI 示例

然后，我们可以编写一个名为`eapi_1.py`的简单程序来查看响应文本：

```py
      #!/usr/bin/python2

      from __future__ import print_function
      from jsonrpclib import Server
      import ssl

      ssl._create_default_https_context = ssl._create_unverified_context

      switch = Server("https://admin:arista@192.168.199.158/command-api")

      response = switch.runCmds( 1, [ "show version" ] )
      print('Serial Number: ' + response[0]['serialNumber'])
```

请注意，由于这是 Python 2，在脚本中，我使用了`from __future__ import print_function`以便未来迁移更容易。与`ssl`相关的行适用于 Python 版本 > 2.7.9。更多信息，请参阅[`www.python.org/dev/peps/pep-0476/`](https://www.python.org/dev/peps/pep-0476/)。

这是我从先前的`runCms()`方法收到的响应：

```py
 [{u'memTotal': 3978148, u'internalVersion': u'4.16.6M-
 3205780.4166M', u'serialNumber': u'<omitted>', u'systemMacAddress':
 u'<omitted>', u'bootupTimestamp': 1465964219.71, u'memFree': 
 277832, u'version': u'4.16.6M', u'modelName': u'DCS-7050QX-32-F', 
 u'isIntlVersion': False, u'internalBuildId': u'373dbd3c-60a7-4736-
 8d9e-bf5e7d207689', u'hardwareRevision': u'00.00', u'architecture': 
 u'i386'}]
```

如您所见，结果是包含一个字典项的列表。如果我们需要获取序列号，我们可以简单地引用项目编号和键：

```py
     print('Serial Number: ' + response[0]['serialNumber'])
```

输出将仅包含序列号：

```py
$ python eapi_1.py
Serial Number: <omitted>
```

为了更熟悉命令参考，请点击 eAPI 页面上的命令文档链接，并将您的输出与文档中 show version 的输出进行比较。

如前所述，与 REST 不同，JSON-RPC 客户端使用相同的 URL 端点来调用服务器资源。您可以从前面的示例中看到，`runCmds()`方法包含一系列命令。对于配置命令的执行，您可以遵循相同的框架，并通过一系列命令配置设备。

这是一个名为`eapi_2.py`的配置命令示例。在我们的示例中，我们编写了一个函数，该函数将交换机对象和命令列表作为属性：

```py
      #!/usr/bin/python2

      from __future__ import print_function
      from jsonrpclib import Server
      import ssl, pprint

      ssl._create_default_https_context = ssl._create_unverified_context

      # Run Arista commands thru eAPI
      def runAristaCommands(switch_object, list_of_commands):
          response = switch_object.runCmds(1, list_of_commands)
          return response

      switch = Server("https://admin:arista@192.168.199.158/command-
    api")

      commands = ["enable", "configure", "interface ethernet 1/3", 
    "switchport acc ess vlan 100", "end", "write memory"]

     response = runAristaCommands(switch, commands)
     pprint.pprint(response)

```

这是命令执行的输出：

```py
$ python2 eapi_2.py
[{}, {}, {}, {}, {}, {u'messages': [u'Copy completed successfully.']}]
```

现在，快速检查`switch`以验证命令的执行：

```py
arista1#sh run int eth 1/3
interface Ethernet1/3
    switchport access vlan 100
arista1# 
```

总的来说，eAPI 非常简单直接，易于使用。大多数编程语言都有类似于`jsonrpclib`的库，它们抽象了 JSON-RPC 的内部。通过几个命令，您就可以开始将 Arista EOS 自动化集成到您的网络中。

# Arista Pyeapi 库

Python 客户端 Pyeapi（[`pyeapi.readthedocs.io/en/master/index.html`](http://pyeapi.readthedocs.io/en/master/index.html)）库是一个原生的 Python 库，包装了 eAPI。它提供了一组绑定来配置 Arista EOS 节点。为什么我们需要 Pyeapi，当我们已经有 eAPI 了呢？在 Python 环境中选择 Pyeapi 还是 eAPI 主要是一个判断调用。

然而，如果你处于非 Python 环境中，eAPI 可能是一个不错的选择。从我们的例子中可以看出，eAPI 的唯一要求是一个支持 JSON-RPC 的客户端。因此，它与大多数编程语言兼容。当我刚开始进入这个领域时，Perl 是脚本和网络自动化的主导语言。仍然有许多企业依赖 Perl 脚本作为他们的主要自动化工具。如果你处于一个公司已经投入大量资源且代码基础是另一种语言而不是 Python 的情况下，使用支持 JSON-RPC 的 eAPI 可能是一个不错的选择。

然而，对于那些更喜欢用 Python 编程的人来说，一个原生的`Python`库意味着在编写我们的代码时更自然。它确实使得扩展 Python 程序以支持 EOS 节点更容易。它也使得更容易跟上 Python 的最新变化。例如，我们可以使用 Python 3 与 Pyeapi！

在撰写本书时，Python 3（3.4+）支持正式是一个正在进行中的工作，如文档中所述（[`pyeapi.readthedocs.io/en/master/requirements.html`](http://pyeapi.readthedocs.io/en/master/requirements.html)）。请查看文档以获取更多详细信息。

# Pyeapi 安装

使用 pip 进行安装非常简单：

```py
$ sudo pip install pyeapi
$ sudo pip3 install pyeapi
```

请注意，pip 还将安装 netaddr 库，因为它是 Pyeapi 的规定要求的一部分（[`pyeapi.readthedocs.io/en/master/requirements.html`](http://pyeapi.readthedocs.io/en/master/requirements.html)）。

默认情况下，Pyeapi 客户端将在您的主目录中查找一个 INI 风格的隐藏文件（前面带有一个句点）称为`eapi.conf`。您可以通过指定`eapi.conf`文件路径来覆盖这种行为，但通常最好将连接凭据与脚本本身分开。您可以查看 Arista Pyeapi 文档（[`pyeapi.readthedocs.io/en/master/configfile.html#configfile`](http://pyeapi.readthedocs.io/en/master/configfile.html#configfile)）以获取文件中包含的字段。这是我在实验室中使用的文件：

```py
cat ~/.eapi.conf
[connection:Arista1]
host: 192.168.199.158
username: admin
password: arista
transport: https
```

第一行`[connection:Arista1]`包含了我们将在 Pyeapi 连接中使用的名称；其余字段应该是相当容易理解的。您可以将文件锁定为只读，供用户使用此文件：

```py
$ chmod 400 ~/.eapi.conf
$ ls -l ~/.eapi.conf
-r-------- 1 echou echou 94 Jan 27 18:15 /home/echou/.eapi.conf
```

# Pyeapi 示例

现在，我们准备好查看用法了。让我们通过在交互式 Python shell 中创建一个对象来连接到 EOS 节点：

```py
Python 3.5.2 (default, Nov 17 2016, 17:05:23)
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pyeapi
>>> arista1 = pyeapi.connect_to('Arista1')
```

我们可以执行 show 命令到节点并接收输出：

```py
>>> import pprint
>>> pprint.pprint(arista1.enable('show hostname'))
[{'command': 'show hostname',
 'encoding': 'json',
 'result': {'fqdn': 'arista1', 'hostname': 'arista1'}}]
```

配置字段可以是单个命令，也可以是使用`config()`方法的命令列表：

```py
>>> arista1.config('hostname arista1-new')
[{}]
>>> pprint.pprint(arista1.enable('show hostname'))
[{'command': 'show hostname',
 'encoding': 'json',
 'result': {'fqdn': 'arista1-new', 'hostname': 'arista1-new'}}]
>>> arista1.config(['interface ethernet 1/3', 'description my_link'])
[{}, {}]
```

请注意，命令缩写（`show run`与`show running-config`）和一些扩展将不起作用：

```py
>>> pprint.pprint(arista1.enable('show run'))
Traceback (most recent call last):
...
 File "/usr/local/lib/python3.5/dist-packages/pyeapi/eapilib.py", line 396, in send
 raise CommandError(code, msg, command_error=err, output=out)
pyeapi.eapilib.CommandError: Error [1002]: CLI command 2 of 2 'show run' failed: invalid command [incomplete token (at token 1: 'run')]
>>>
>>> pprint.pprint(arista1.enable('show running-config interface ethernet 1/3'))
Traceback (most recent call last):
...
pyeapi.eapilib.CommandError: Error [1002]: CLI command 2 of 2 'show running-config interface ethernet 1/3' failed: invalid command [incomplete token (at token 2: 'interface')]
```

然而，您总是可以捕获结果并获得所需的值：

```py
>>> result = arista1.enable('show running-config')
>>> pprint.pprint(result[0]['result']['cmds']['interface Ethernet1/3'])
{'cmds': {'description my_link': None, 'switchport access vlan 100': None}, 'comments': []}
```

到目前为止，我们一直在使用 eAPI 进行 show 和配置命令。Pyeapi 提供了各种 API 来使生活更轻松。在下面的示例中，我们将连接到节点，调用 VLAN API，并开始对设备的 VLAN 参数进行操作。让我们来看一下：

```py
>>> import pyeapi
>>> node = pyeapi.connect_to('Arista1')
>>> vlans = node.api('vlans')
>>> type(vlans)
<class 'pyeapi.api.vlans.Vlans'>
>>> dir(vlans)
[...'command_builder', 'config', 'configure', 'configure_interface', 'configure_vlan', 'create', 'default', 'delete', 'error', 'get', 'get_block', 'getall', 'items', 'keys', 'node', 'remove_trunk_group', 'set_name', 'set_state', 'set_trunk_groups', 'values']
>>> vlans.getall()
{'1': {'vlan_id': '1', 'trunk_groups': [], 'state': 'active', 'name': 'default'}}
>>> vlans.get(1)
{'vlan_id': 1, 'trunk_groups': [], 'state': 'active', 'name': 'default'}
>>> vlans.create(10)
True
>>> vlans.getall()
{'1': {'vlan_id': '1', 'trunk_groups': [], 'state': 'active', 'name': 'default'}, '10': {'vlan_id': '10', 'trunk_groups': [], 'state': 'active', 'name': 'VLAN0010'}}
>>> vlans.set_name(10, 'my_vlan_10')
True
```

让我们验证一下设备上是否创建了 VLAN 10：

```py
arista1#sh vlan
VLAN Name Status Ports
----- -------------------------------- --------- -------------------------------
1 default active
10 my_vlan_10 active
```

正如你所看到的，EOS 对象上的 Python 本机 API 确实是 Pyeapi 在 eAPI 之上的优势所在。它将底层属性抽象成设备对象，使代码更清晰、更易读。

要获取不断增加的 Pyeapi API 的完整列表，请查阅官方文档（[`pyeapi.readthedocs.io/en/master/api_modules/_list_of_modules.html`](http://pyeapi.readthedocs.io/en/master/api_modules/_list_of_modules.html)）。

总结本章，让我们假设我们重复了前面的步骤足够多次，以至于我们想写另一个 Python 类来节省一些工作。`pyeapi_1.py`脚本如下所示：

```py
      #!/usr/bin/env python3

      import pyeapi

      class my_switch():

          def __init__(self, config_file_location, device):
               # loads the config file
               pyeapi.client.load_config(config_file_location)
               self.node = pyeapi.connect_to(device)
               self.hostname = self.node.enable('show hostname')[0]
    ['result']['host name']
              self.running_config = self.node.enable('show running-
    config')

           def create_vlan(self, vlan_number, vlan_name):
               vlans = self.node.api('vlans')
               vlans.create(vlan_number)
               vlans.set_name(vlan_number, vlan_name) 
```

从脚本中可以看出，我们自动连接到节点并在连接时设置主机名和`running_config`。我们还创建了一个使用`VLAN` API 创建 VLAN 的类方法。让我们在交互式 shell 中尝试运行脚本：

```py
Python 3.5.2 (default, Nov 17 2016, 17:05:23)
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pyeapi_1
>>> s1 = pyeapi_1.my_switch('/tmp/.eapi.conf', 'Arista1')
>>> s1.hostname
'arista1'
>>> s1.running_config
[{'encoding': 'json', 'result': {'cmds': {'interface Ethernet27': {'cmds': {}, 'comments': []}, 'ip routing': None, 'interface face Ethernet29': {'cmds': {}, 'comments': []}, 'interface Ethernet26': {'cmds': {}, 'comments': []}, 'interface Ethernet24/4': h.': 
<omitted>
'interface Ethernet3/1': {'cmds': {}, 'comments': []}}, 'comments': [], 'header': ['! device: arista1 (DCS-7050QX-32, EOS-4.16.6M)n!n']}, 'command': 'show running-config'}]
>>> s1.create_vlan(11, 'my_vlan_11')
>>> s1.node.api('vlans').getall()
{'11': {'name': 'my_vlan_11', 'vlan_id': '11', 'trunk_groups': [], 'state': 'active'}, '10': {'name': 'my_vlan_10', 'vlan_id': '10', 'trunk_groups': [], 'state': 'active'}, '1': {'name': 'default', 'vlan_id': '1', 'trunk_groups': [], 'state': 'active'}}
>>>
```

# 供应商中立库

有几个优秀的供应商中立库，比如 Netmiko（[`github.com/ktbyers/netmiko`](https://github.com/ktbyers/netmiko)）和 NAPALM（[`github.com/napalm-automation/napalm`](https://github.com/napalm-automation/napalm)）。因为这些库并非来自设备供应商，它们有时会慢一步来支持最新的平台或功能。然而，由于这些库是供应商中立的，如果你不喜欢为你的工具绑定供应商，那么这些库是一个不错的选择。使用这些库的另一个好处是它们通常是开源的，所以你可以为新功能和错误修复做出贡献。

另一方面，由于这些库是由社区支持的，如果你需要依赖他人来修复错误或实现新功能，它们可能并不是理想的选择。如果你有一个相对较小的团队，仍然需要遵守工具的某些服务级保证，你可能最好使用供应商支持的库。

# 总结

在本章中，我们看了一些从思科、Juniper 和 Arista 管理网络设备的各种方法。我们既看了与 NETCONF 和 REST 等直接通信，也使用了供应商提供的库，比如 PyEZ 和 Pyeapi。这些都是不同的抽象层，旨在提供一种无需人工干预就能编程管理网络设备的方式。

在第四章中，*Python 自动化框架- Ansible 基础*，我们将看一下一个更高级的供应商中立抽象框架，称为**Ansible**。Ansible 是一个用 Python 编写的开源通用自动化工具。它可以用于自动化服务器、网络设备、负载均衡器等等。当然，对于我们的目的，我们将专注于使用这个自动化框架来管理网络设备。
