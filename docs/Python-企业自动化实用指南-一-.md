# Python 企业自动化实用指南（一）

> 原文：[`zh.annas-archive.org/md5/0bfb2f4dbc80a06d99550674abb53d0d`](https://zh.annas-archive.org/md5/0bfb2f4dbc80a06d99550674abb53d0d)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书首先介绍了建立 Python 环境以执行自动化任务的设置，以及您将使用的模块、库和工具。

我们将使用简单的 Python 程序和 Ansible 探索网络自动化任务的示例。接下来，我们将带您了解如何使用 Python Fabric 自动化管理任务，您将学习执行服务器配置和管理以及系统管理任务，如用户管理、数据库管理和进程管理。随着您在本书中的进展，您将使用 Python 脚本自动化多个测试服务，并使用 Python 在虚拟机和云基础架构上执行自动化任务。在最后几章中，您将涵盖基于 Python 的攻击性安全工具，并学习如何自动化您的安全任务。

通过本书，您将掌握使用 Python 自动化多个系统管理任务的技能。

您可以访问作者的博客，链接如下：[`basimaly.wordpress.com/.`](https://basimaly.wordpress.com/)

# 这本书是为谁准备的

*使用 Python 进行企业自动化*适用于寻找 Puppet 和 Chef 等主要自动化框架替代方案的系统管理员和 DevOps 工程师。需要具备 Python 和 Linux shell 脚本的基本编程知识。

# 这本书涵盖了什么

第一章，*设置 Python 环境*，探讨了如何下载和安装 Python 解释器以及名为*JetBrains PyCharm*的 Python 集成开发环境。该 IDE 提供智能自动完成、智能代码分析、强大的重构，并与 Git、virtualenv、Vagrant 和 Docker 集成。这将帮助您编写专业和健壮的 Python 代码。

第二章，*自动化中使用的常见库*，介绍了今天可用的用于自动化的 Python 库，并根据它们的用途（系统、网络和云）进行分类，并提供简单的介绍。随着您在本书中的进展，您将发现自己深入研究每一个库，并了解它们的用途。

第三章，*设置您的网络实验室环境*，讨论了网络自动化的优点以及网络运营商如何使用它来自动化当前的设备。我们将探讨今天用于自动化来自思科、Juniper 和 Arista 的网络节点的流行库。本章介绍了如何构建一个网络实验室来应用 Python 脚本。我们将使用一个名为 EVE-NG 的开源网络仿真工具。

第四章，*使用 Python 管理网络设备*，深入介绍了通过 telnet 和 SSH 连接使用 netmiko、paramiko 和 telnetlib 管理网络设备。我们将学习如何编写 Python 代码来访问交换机和路由器，并在终端上执行命令，然后返回输出。我们还将学习如何利用不同的 Python 技术来备份和推送配置。本章以当今现代网络环境中使用的一些用例结束。

第五章，*从网络设备中提取有用数据*，解释了如何使用 Python 内部的不同工具和技术从返回的输出中提取有用数据并对其进行操作。此外，我们将使用一个名为*CiscoConfParse*的特殊库来审计配置。然后，我们将学习如何可视化数据，使用 matplotlib 生成吸引人的图表和报告。

第六章《使用 Python 和 Jinja2 生成配置文件》解释了如何为拥有数百个网络节点的站点生成通用配置。我们将学习如何编写模板，并使用 Jinja2 模板语言生成黄金配置。

第七章《Python 脚本的并行执行》涵盖了如何并行实例化和执行 Python 代码。只要不相互依赖，这将使我们能够更快地完成自动化工作流程。

第八章《准备实验室环境》涵盖了实验室环境的安装过程和准备工作。我们将在不同的虚拟化器上安装我们的自动化服务器，无论是在 CentOS 还是 Ubuntu 上。然后我们将学习如何使用 Cobbler 自动安装操作系统。

第九章《使用 Subprocess 模块》解释了如何从 Python 脚本直接发送命令到操作系统 shell 并调查返回的输出。

第十章《使用 Fabric 运行系统管理任务》介绍了 Fabric，这是一个用于通过 SSH 执行系统管理任务的 Python 库。它也用于大规模应用部署。我们将学习如何利用和发挥这个库来在远程服务器上执行任务。

第十一章《生成系统报告》、《管理用户和系统监控》解释了从系统收集数据并生成定期报告对于任何系统管理员来说都是一项重要任务，自动化这项任务将帮助您及早发现问题并为其提供解决方案。在本章中，我们将看到一些经过验证的自动化从服务器收集数据并生成正式报告的方法。我们将学习如何使用 Python 和 Ansible 管理新用户和现有用户。此外，我们还将深入研究系统 KPI 的监控和日志分析。您还可以安排监控脚本定期运行，并将结果发送到您的邮箱。

第十二章《与数据库交互》指出，如果你是数据库管理员或数据库开发人员，那么 Python 提供了许多库和模块，涵盖了管理和操作流行的 DBMS（如 MySQL、Postgress 和 Oracle）。在本章中，我们将学习如何使用 Python 连接器与 DBMS 进行交互。

第十三章《系统管理的 Ansible》探讨了配置管理软件中最强大的工具之一。当涉及系统管理时，Ansible 非常强大，可以确保配置在数百甚至数千台服务器上同时精确复制。

第十四章《创建和管理 VMWare 虚拟机》解释了如何在 VMWare 虚拟化器上自动创建 VM。我们将探索使用 VMWare 官方绑定库在 ESXi 上创建和管理虚拟机的不同方法。

第十五章《与 Openstack API 交互》解释了在创建私有云时，OpenStack 在私有 IaaS 方面非常受欢迎。我们将使用 Python 模块，如 requests，创建 REST 调用并与 OpenStack 服务（如 nova、cinder 和 neutron）进行交互，并在 OpenStack 上创建所需的资源。在本章后期，我们将使用 Ansible playbooks 执行相同的工作流程。

第十六章，*使用 Python 和 Boto3 自动化 AWS*，介绍了如何使用官方的 Amazon 绑定（BOTO3）自动化常见的 AWS 服务，如 EC2 和 S3，它提供了一个易于使用的 API 来访问服务。

第十七章，*使用 SCAPY 框架*，介绍了 SCAPY，这是一个强大的 Python 工具，用于构建和制作数据包，然后将其发送到网络上。您可以构建任何类型的网络流并将其发送到网络上。它还可以帮助您捕获网络数据包并将其重放到网络上。

第十八章，*使用 Python 构建网络扫描器*，提供了使用 Python 构建网络扫描器的完整示例。您可以扫描完整的子网以查找不同的协议和端口，并为每个扫描的主机生成报告。然后，我们将学习如何通过 Git 与开源社区（GitHub）共享代码。

# 为了充分利用本书

读者应该熟悉 Python 编程语言的基本编程范式，并且应该具有 Linux 和 Linux shell 脚本的基本知识。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Enterprise-Automation-with-Python`](https://github.com/PacktPublishing/Hands-On-Enterprise-Automation-with-Python)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富的图书和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/HandsOnEnterpriseAutomationwithPython_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/HandsOnEnterpriseAutomationwithPython_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码字词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子："一些大型软件包，如`matplotlib`或`django`，其中包含数百个模块，开发人员通常将相关模块分类到子目录中。"

代码块设置如下：

```py
from netmiko import ConnectHandler
from devices import R1,SW1,SW2,SW3,SW4

nodes = [R1,SW1,SW2,SW3,SW4]   for device in nodes:
  net_connect = ConnectHandler(**device)
  output = net_connect.send_command("show run")
  print output
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```py
hostname {{hostname}}
```

任何命令行输入或输出都将按照以下方式编写：

```py
pip install jinja2 
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：

"从下载页面选择您的平台，然后选择 x86 或 x64 版本。"

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：设置我们的 Python 环境

在这一章中，我们将简要介绍 Python 编程语言以及当前版本之间的区别。Python 有两个活跃版本，并且在开发过程中选择使用哪一个是很重要的。在这一章中，我们将下载并安装 Python 二进制文件到操作系统中。

在本章结束时，我们将安装全球专业开发人员使用的最先进的**集成开发环境**（**IDE**）之一：PyCharm。PyCharm 提供智能代码完成、代码检查、实时错误突出显示和快速修复、自动代码重构以及丰富的导航功能，我们将在本书中编写和开发 Python 代码时进行介绍。

本章将涵盖以下主题：

+   Python 简介

+   安装 PyCharm IDE

+   探索一些巧妙的 PyCharm 功能

# Python 简介

Python 是一种提供友好语法的高级编程语言；它易于学习和使用，无论是初学者还是专家程序员。

Python 最初是由 Guido van Rossum 于 1991 年开发的；它依赖于 C、C++和其他 Unix shell 工具的混合。Python 被称为通用编程语言，并且今天它被用于许多领域，如软件开发、Web 开发、网络自动化、系统管理和科学领域。由于其大量可供下载的模块，涵盖了许多领域，Python 可以将开发时间缩短到最低。

Python 语法设计得易读；它与英语有些相似，而代码本身的构造也很美。Python 核心开发人员提供了 20 条信息规则，称为 Python 之禅，这些规则影响了 Python 语言的设计；其中大部分涉及构建清洁、有组织和易读的代码。以下是其中一些规则：

美好优于丑陋。

显式优于隐式。

简单优于复杂。

复杂优于复杂。

您可以在[`www.python.org/dev/peps/pep-0020/`](https://www.python.org/dev/peps/pep-0020/)上阅读更多关于 Python 之禅的内容。

# Python 版本

Python 有两个主要版本：Python 2.x 和 Python 3.x。这两个版本之间有细微的差异；最明显的是它们的`print`函数对多个字符串的处理方式。此外，所有新功能只会添加到 3.x，而 2.x 将在完全退役之前接收安全更新。这不会是一个简单的迁移，因为许多应用程序都是基于 Python 2.x 构建的。

# 为什么有两个活跃版本？

我将引用官方 Python 网站上的原因：

<q class="calibre21">"Guido van Rossum（Python 语言的原始创造者）决定彻底清理 Python 2.x，不像对 2.x 范围内的新版本那样考虑向后兼容性。最重大的改进是更好的 Unicode 支持（默认情况下所有文本字符串都是 Unicode），以及更合理的字节/Unicode 分离。</q> <q class="calibre21">"此外，核心语言的几个方面（如 print 和 exec 作为语句，整数使用地板除法）已经调整为更容易让新手学习，并且更一致于语言的其他部分，并且已经删除了旧的不必要的东西（例如，所有类现在都是新式的，“range()”返回一个内存高效的可迭代对象，而不是像 2.x 中的列表那样）。</q>

您可以在[`wiki.python.org/moin/Python2orPython3`](https://wiki.python.org/moin/Python2orPython3)上阅读更多关于这个主题的内容。

# 您是否应该只学习 Python 3？

这取决于*.*学习 Python 3 将使您的代码具有未来性，并且您将使用开发人员提供的最新功能。但是，请注意，一些第三方模块和框架不支持 Python 3，并且在不久的将来将继续如此，直到他们完全将他们的库移植到 Python 3。

另外，请注意，一些网络供应商（如思科）对 Python 3.x 提供有限支持，因为大多数所需功能已经在 Python 2.x 版本中涵盖。例如，以下是思科设备支持的 Python 版本；您将看到所有设备都支持 2.x，而不支持 3.x：

！[](../images/00005.jpeg)来源：[`developer.cisco.com/site/python/`](https://developer.cisco.com/site/python/)

# 这是否意味着我不能编写在 Python 2 和 Python 3 上运行的代码？

不，当然可以在 Python 2.x 中编写代码并使其与两个版本兼容，但您需要首先导入一些库，例如`__future__`模块，使其向后兼容。此模块包含一些函数，可以调整 Python 2.x 的行为，并使其与 Python 3.x 完全相同。看一下以下示例，以了解两个版本之间的区别：

```py
#python 2 only print "Welcome to Enterprise Automation" 
```

以下代码适用于 Python 2 和 3：

```py
# python 2 and 3  print("Welcome to Enterprise Automation")
```

现在，如果您需要打印多个字符串，Python 2 的语法将如下所示：

```py
# python 2, multiple strings print "welcome", "to", "Enterprise", "Automation"   # python 3, multiple strings print ("welcome", "to", "Enterprise", "Automation")
```

如果您尝试在 Python 2 中使用括号打印多个字符串，它将将其解释为元组，这是错误的。因此，我们将在代码开头导入`__future__`模块，以防止该行为并指示 Python 打印多个字符串。

输出将如下所示：

！[](../images/00006.jpeg)

# Python 安装

无论您选择使用流行的 Python 版本（2.x）还是使用 Python 3.x 构建未来的代码，您都需要从官方网站下载 Python 二进制文件并在操作系统中安装它们。 Python 支持不同的平台（Windows，Mac，Linux，Raspberry PI 等）：

1.  转到[`www.python.org/downloads/`](https://www.python.org/downloads/)并选择最新的 2.x 或 3.x 版本：

！[](../images/00007.jpeg)

1.  从下载页面选择您的平台，以及 x86 或 x64 版本：

！[](../images/00008.jpeg)

1.  像往常一样安装软件包。在安装过程中选择将 python 添加到路径选项很重要，以便从命令行访问 Python（在 Windows 的情况下）。否则，Windows 将无法识别 Python 命令并将抛出错误：

！[](../images/00009.jpeg)

1.  通过在操作系统中打开命令行或终端并键入`python`来验证安装是否完成。这应该访问 Python 控制台并提供 Python 已成功安装在您的系统上的验证：

！[](../images/00010.jpeg)

# 安装 PyCharm IDE

PyCharm 是一个完整的 IDE，被世界各地的许多开发人员用来编写和开发 Python 代码。这个 IDE 是由 Jetbrains 公司开发的，提供丰富的代码分析和完成，语法高亮，单元测试，代码覆盖率，错误发现和其他 Python 代码操作。

此外，PyCharm 专业版支持 Python Web 框架，如 Django，web2py 和 Flask，以及与 Docker 和 vagrant 的集成。它与多个版本控制系统（如 Git（和 GitHub），CVS 和 subversion）提供了惊人的集成。

在接下来的几个步骤中，我们将安装 PyCharm 社区版：

1.  转到 PyCharm 下载页面（[`www.jetbrains.com/pycharm/download/`](https://www.jetbrains.com/pycharm/download/)）并选择您的平台。此外，选择下载 Community Edition（永久免费）或 Professional Edition（Community 版本完全适用于运行本书中的代码）：

！[](../images/00011.jpeg)

1.  像往常一样安装软件，但确保选择以下选项：

+   32 位或 64 位的启动器（取决于您的操作系统）。

+   创建关联（这将使 PyCharm 成为 Python 文件的默认应用程序）。

+   下载并安装 JetBrains 的 JRE x86：

！[](../images/00012.jpeg)

1.  等待 PyCharm 从互联网下载附加包并安装它，然后选择运行 PyCharm 社区版：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00013.jpeg)

1.  由于这是一个新的安装，我们不会从中导入任何设置

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00014.jpeg)

1.  选择所需的 UI 主题（默认或*darcula*，用于暗模式）。您可以安装一些附加插件，例如 Markdown 和 BashSupport，这将使 PyCharm 识别和支持这些语言。完成后，单击开始使用 PyCharm：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00015.jpeg)

# 在 PyCharm 中设置 Python 项目

在 PyCharm 中，一个 Python 项目是你开发的 Python 文件的集合，以及内置的或从第三方安装的 Python 模块。在开始开发代码之前，您需要创建一个新项目并将其保存到计算机内的特定位置。此外，您需要为该项目选择默认解释器。默认情况下，PyCharm 将扫描系统上的默认位置并搜索 Python 解释器。另一个选项是使用 Python `virtualenv` 创建一个完全隔离的环境。`virtualenv`的基本问题是其包依赖性。假设您正在处理多个不同的 Python 项目，其中一个项目需要特定版本的*x*包。另一方面，另一个项目需要完全不同版本的相同包。请注意，所有安装的 Python 包都放在`/usr/lib/python2.7/site-packages`中，您无法存储相同包的不同版本。`virtualenv`将通过创建一个具有自己的安装目录和自己的包的环境来解决此问题；每次您在这两个项目中的任何一个上工作时，PyCharm（借助`virtualenv`的帮助）将激活相应的环境，以避免包之间的任何冲突。

按照以下步骤设置项目：

1.  选择创建新项目：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00016.jpeg)

1.  选择项目设置：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00017.jpeg)

1.  1.  选择项目类型；在我们的情况下，它将是纯 Python*.*

1.  在本地硬盘上选择项目的位置。

1.  选择项目解释器。要么使用默认目录中现有的 Python 安装，要么创建一个专门与该项目绑定的新虚拟环境。

1.  单击 Create*.*

1.  在项目内创建一个新的 Python 文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00018.jpeg)

+   1.  右键单击项目名称，然后选择 New。

1.  从菜单中选择 Python 文件，然后选择文件名。

打开一个新的空白文件，您可以直接在其中编写 Python 代码。例如，尝试导入`__future__`模块，PyCharm 将自动打开一个弹出窗口，显示所有可能的补全，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00019.jpeg)

1.  运行您的代码：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00020.jpeg)

+   1.  输入您希望运行的代码。

1.  选择编辑配置以配置 Python 文件的运行时设置。

1.  配置运行文件的新 Python 设置：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00021.jpeg)

1.  1.  单击+号添加新配置，然后选择 Python。

1.  选择配置名称。

1.  选择项目内的脚本路径。

1.  单击确定。

1.  运行代码：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00022.jpeg)

1.  1.  单击配置名称旁边的播放按钮。

1.  PyCharm 将执行配置中指定的文件中的代码，并将输出返回到终端。

# 探索一些巧妙的 PyCharm 功能

在本节中，我们将探讨 PyCharm 的一些特性。PyCharm 拥有大量的内置工具，包括集成调试器和测试运行器、Python 分析器、内置终端、与主要版本控制系统的集成和内置数据库工具、远程开发能力与远程解释器、集成 SSH 终端，以及与 Docker 和 Vagrant 的集成。有关其他功能的列表，请查看官方网站（[`www.jetbrains.com/pycharm/features/`](https://www.jetbrains.com/pycharm/features/)）。

# 代码调试

代码调试是一个过程，可以帮助您了解错误的原因，通过为代码提供输入并逐行查看代码的执行情况，以及最终的评估结果。Python 语言包含一些调试工具，从简单的`print`函数、assert 命令到代码的完整单元测试。PyCharm 提供了一种简单的调试代码和查看评估值的方法。

要在 PyCharm 中调试代码（比如，一个带有`if`子句的嵌套`for`循环），您需要在希望 PyCharm 停止程序执行的行上设置断点。当 PyCharm 到达这一行时，它将暂停程序并转储内存以查看每个变量的内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00023.jpeg)

请注意，在第一次迭代时，每个变量的值都会被打印在其旁边：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00024.jpeg)

此外，您还可以右键单击断点，并为任何变量添加特定条件。如果变量评估为特定值，那么将打印日志消息：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00025.jpeg)

# 代码重构

重构代码是更改代码中特定变量名称结构的过程。例如，您可能为变量选择一个名称，并在由多个源文件组成的项目中使用它，然后决定将变量重命名为更具描述性的名称。PyCharm 提供了许多重构技术，以确保代码可以更新而不会破坏操作。

PyCharm 执行以下操作：

+   重构本身

+   扫描项目中的每个文件，并确保变量的引用已更新

+   如果某些内容无法自动更新，它将给出警告并打开一个菜单，让您决定如何处理

+   在重构代码之前保存代码，以便以后可以恢复

让我们来看一个例子。假设我们的项目中有三个 Python 文件，分别为`refactor_1.py`、`refactor_2.py`和`refactor_3.py`。第一个文件包含`important_funtion(x)`，它也在`refactor_2.py`和`refactor_3.py`中使用。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00026.jpeg)

将以下代码复制到`refactor_1.py`文件中：

```py
def important_function(x):
  print(x)
```

将以下代码复制到`refactor_2.py`文件中：

```py
from refactor_1 import important_function
important_function(2)
```

将以下代码复制到`refactor_3.py`文件中：

```py
from refactor_1 import important_function
important_function(10)
```

要进行重构，您需要右键单击方法本身，选择重构 | 重命名，并输入方法的新名称：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00027.jpeg)

请注意，IDE 底部会打开一个窗口，列出此函数的所有引用，每个引用的当前值，以及重构后将受影响的文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00028.jpeg)

如果选择执行重构，所有引用将使用新名称进行更新，您的代码将不会被破坏。

# 从 GUI 安装包

PyCharm 可以用来使用 GUI 为现有的解释器（或`virtualenv`）安装包。此外，您可以查看所有已安装包的列表，以及它们是否有可用的升级版本。

首先，您需要转到文件 | 设置 | 项目 | 项目解释器：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00029.jpeg)

如前面的截图所示，PyCharm 提供了已安装包及其当前版本的列表。您可以点击+号将新包添加到项目解释器中，然后在搜索框中输入包的缩写：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00030.jpeg)

您应该看到一个可用软件包的列表，其中包含每个软件包的名称和描述。此外，您可以指定要安装在您的解释器上的特定版本。一旦您点击安装软件包，PyCharm 将在您的系统上执行一个`pip`命令（可能会要求您权限）；然后，它将下载软件包到安装目录并执行`setup.py`文件。

# 总结

在本章中，您学习了 Python 2 和 Python 3 之间的区别，以及如何根据您的需求决定使用哪种版本。此外，您还学习了如何安装 Python 解释器，以及如何使用 PyCharm 作为高级编辑器来编写和管理代码的生命周期。

在下一章中，我们将讨论 Python 软件包结构和自动化中常用的 Python 软件包。


# 第二章：自动化中常用的库

本章将带您了解 Python 包的结构以及今天用于自动化系统和网络基础设施的常见库。有一个不断增长的 Python 包列表，涵盖了网络自动化、系统管理以及管理公共和私有云的功能。

此外，重要的是要理解如何访问模块源代码，以及 Python 包中的小部分如何相互关联，这样我们就可以修改代码，添加或删除功能，并再次与社区分享代码。

本章将涵盖以下主题：

+   理解 Python 包

+   常见的 Python 库

+   访问模块源代码

# 理解 Python 包

Python 核心代码实际上是小而简单的。大部分功能都是通过添加第三方包和模块来实现的。

模块是一个包含函数、语句和类的 Python 文件，将在您的代码中使用。首先要做的是`import`模块，然后开始使用它的函数。

另一方面，一个**包**会收集相关的模块并将它们放在一个层次结构中。一些大型包，如`matplotlib`或`django`，其中包含数百个模块，开发人员通常会将相关的模块分类到子目录中。例如，`netmiko`包包含多个子目录，每个子目录包含连接到不同供应商的网络设备的模块：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00031.jpeg)

这样做可以让包的维护者灵活地向每个模块添加或删除功能，而不会破坏全局包的操作。

# 包搜索路径

通常情况下，Python 会在一些特定的系统路径中搜索模块。您可以通过导入`sys`模块并打印`sys.path`来打印这些路径。这实际上会返回`PYTHONPATH`环境变量和操作系统中的字符串；请注意结果只是一个普通的 Python 列表。您可以使用列表函数（如`insert()`）添加更多路径到搜索范围。

然而，最好是将包安装在默认搜索路径中，这样当与其他开发人员共享代码时，代码不会出错：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00032.jpeg)

一个简单的包结构，只有一个模块，会是这样的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00033.jpeg)

每个包中的`__init__`文件（在全局目录或子目录中）会告诉 Python 解释器这个目录是一个 Python 包，每个以`.py`结尾的文件都是一个模块文件，可以在你的代码中导入。`init`文件的第二个功能是一旦导入包，就执行其中的任何代码。然而，大多数开发人员会将其留空，只是用它来标记目录为 Python 包。

# 常见的 Python 库

在接下来的章节中，我们将探讨用于网络、系统和云自动化的常见 Python 库。

# 网络 Python 库

如今的网络环境中包含来自许多供应商的多个设备，每个设备扮演不同的角色。设计和自动化网络设备的框架对于网络工程师来说至关重要，可以自动执行重复的任务，提高他们通常完成工作的方式，同时减少人为错误。大型企业和服务提供商通常倾向于设计一个能够自动执行不同网络任务并提高网络弹性和灵活性的工作流程。这个工作流程包含一系列相关的任务，共同形成一个流程或工作流程，当网络需要变更时将被执行。

网络自动化框架可以在无需人工干预的情况下执行一些任务：

+   问题的根本原因分析

+   检查和更新设备操作系统

+   发现节点之间的拓扑和关系

+   安全审计和合规性报告

+   根据应用程序需求从网络设备安装和撤销路由

+   管理设备配置和回滚

以下是用于自动化网络设备的一些 Python 库：

| **网络库** | **描述** | **链接** |
| --- | --- | --- |
| Netmiko | 一个支持 SSH 和 Telnet 的多供应商库，用于在网络设备上执行命令。支持的供应商包括 Cisco、Arista、Juniper、HP、Ciena 和许多其他供应商。 | [`github.com/ktbyers/netmiko`](https://github.com/ktbyers/netmiko) |
| NAPALM | 一个 Python 库，作为官方供应商 API 的包装器工作。它提供了连接到多个供应商设备并从中提取信息的抽象方法，同时以结构化格式返回输出。这可以很容易地被软件处理。 | [`github.com/napalm-automation/napalm`](https://github.com/napalm-automation/napalm) |
| PyEZ | 用于管理和自动化 Juniper 设备的 Python 库。它可以从 Python 客户端对设备执行 CRUD 操作。此外，它可以检索有关设备的信息，如管理 IP、序列号和版本。返回的输出将以 JSON 或 XML 格式呈现。 | [`github.com/Juniper/py-junos-eznc`](https://github.com/Juniper/py-junos-eznc) |
| infoblox-client | 用于基于 REST 称为 WAPI 与 infoblox NIOS 进行交互的 Python 客户端。 | [`github.com/infobloxopen/infoblox-client`](https://github.com/infobloxopen/infoblox-client) |
| NX-API | 一个 Cisco Nexus（仅限某些平台）系列 API，通过 HTTP 和 HTTPS 公开 CLI。您可以在提供的沙箱门户中输入 show 命令，它将被转换为对设备的 API 调用，并以 JSON 和 XML 格式返回输出。 | [`developer.cisco.com/docs/nx-os/#!working-with-nx-api-cli`](https://developer.cisco.com/docs/nx-os/#!working-with-nx-api-cli) |
| pyeapi | 一个 Python 库，作为 Arista EOS eAPI 的包装器，用于配置 Arista EOS 设备。该库支持通过 HTTP 和 HTTPs 进行 eAPI 调用。 | [`github.com/arista-eosplus/pyeapi`](https://github.com/arista-eosplus/pyeapi) |
| netaddr | 用于处理 IPv4、IPv6 和第 2 层地址（MAC 地址）的 Python 库。它可以迭代、切片、排序和总结 IP 块。 | [`github.com/drkjam/netaddr`](https://github.com/drkjam/netaddr) |
| ciscoconfparse | 一个能够解析 Cisco IOS 风格配置并以结构化格式返回输出的 Python 库。该库还支持基于大括号分隔的配置的设备配置，如 Juniper 和 F5。 | [`github.com/mpenning/ciscoconfparse`](https://github.com/mpenning/ciscoconfparse) |
| NSoT | 用于跟踪网络设备库存和元数据的数据库。它提供了一个基于 Python Django 的前端 GUI。后端基于 SQLite 数据库存储数据。此外，它提供了使用 pynsot 绑定的库存的 API 接口。 | [`github.com/dropbox/nsot`](https://github.com/dropbox/nsot) |
| Nornir | 一个基于 Python 的新的自动化框架，可以直接从 Python 代码中使用，无需自定义**DSL**（**领域特定语言**）。Python 代码称为 runbook，包含一组可以针对存储在库存中的设备运行的任务（还支持 Ansible 库存格式）。任务可以利用其他库（如 NAPALM）来获取信息或配置设备。 | [`github.com/nornir-automation/nornir`](https://github.com/nornir-automation/nornir) |

# 系统和云 Python 库

以下是一些可用于系统和云管理的 Python 软件包。像**Amazon Web Services**（**AWS**）和 Google 这样的公共云提供商倾向于以开放和标准的方式访问其资源，以便与组织的 DevOps 模型轻松集成。像持续集成、测试和部署这样的阶段需要对基础设施（虚拟化或裸金属服务器）进行*持续*访问，以完成代码生命周期。这无法手动完成，需要自动化：

| **库** | **描述** | **链接** |
| --- | --- | --- |
| ConfigParser | 用于解析和处理 INI 文件的 Python 标准库。 | [`github.com/python/cpython/blob/master/Lib/configparser.py`](https://github.com/python/cpython/blob/master/Lib/configparser.py) |
| Paramiko | Paramiko 是 SSHv2 协议的 Python（2.7、3.4+）实现，提供客户端和服务器功能。 | [`github.com/paramiko/paramiko`](https://github.com/paramiko/paramiko) |
| Pandas | 提供高性能、易于使用的数据结构和数据分析工具的库。 | [`github.com/pandas-dev/pandas`](https://github.com/pandas-dev/pandas) |
| `boto3` | 官方 Python 接口，用于管理不同的 AWS 操作，例如创建 EC2 实例和 S3 存储。 | [`github.com/boto/boto3`](https://github.com/boto/boto3) |
| `google-api-python-client` | Google Cloud Platform 的官方 API 客户端库。 | [`github.com/google/google-api-python-client`](https://github.com/google/google-api-python-client) |
| `pyVmomi` | 来自 VMWare 的官方 Python SDK，用于管理 ESXi 和 vCenter。 | [`github.com/vmware/pyvmomi`](https://github.com/vmware/pyvmomi) |
| PyMYSQL | 用于与 MySQL DBMS 一起工作的纯 Python MySQL 驱动程序。 | [`github.com/PyMySQL/PyMySQL`](https://github.com/PyMySQL/PyMySQL) |
| Psycopg | 适用于 Python 的 PostgresSQL 适配器，符合 DP-API 2.0 标准。 | [`initd.org/psycopg/`](http://initd.org/psycopg/) |
| Django | 基于 Python 的高级开源 Web 框架。该框架遵循**MVT**（**Model, View, and Template**）架构设计，用于构建 Web 应用程序，无需进行 Web 开发和常见安全错误。 | [`www.djangoproject.com/`](https://www.djangoproject.com/) |
| Fabric | 用于在基于 SSH 的远程设备上执行命令和软件部署的简单 Python 工具。 | [`github.com/fabric/fabric`](https://github.com/fabric/fabric) |
| SCAPY | 一个出色的基于 Python 的数据包操作工具，能够处理各种协议，并可以使用任意组合的网络层构建数据包；它还可以将它们发送到网络上。 | [`github.com/secdev/scapy`](https://github.com/secdev/scapy) |
| Selenium | 用于自动化 Web 浏览器任务和 Web 验收测试的 Python 库。该库与 Firefox、Chrome 和 Internet Explorer 的 Selenium Webdriver 一起工作，以在 Web 浏览器上运行测试。 | [`pypi.org/project/selenium/`](https://pypi.org/project/selenium/) |

您可以在以下链接找到更多按不同领域分类的 Python 软件包：[`github.com/vinta/awesome-python`](https://github.com/vinta/awesome-python)。

# 访问模块源代码

您可以以两种方式访问您使用的任何模块的源代码。首先，转到[github.com](https://github.com/)上的`module`页面，查看所有文件、发布、提交和问题，就像下面的截图一样。我通过`netmiko`模块的维护者具有对所有共享代码的读取权限，并可以查看完整的提交列表和文件内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00034.jpeg)

第二种方法是使用`pip`或 PyCharm GUI 将包本身安装到 Python 站点包目录中。`pip`实际上的操作是到 GitHub 下载模块内容并运行`setup.py`来安装和注册模块。你可以看到模块文件，但这次你对所有文件都有完全的读写权限，可以更改原始代码。例如，以下代码利用`netmiko`库连接到思科设备并在其上执行`show arp`命令：

```py
from netmiko import ConnectHandler

device = {"device_type": "cisco_ios",
  "ip": "10.10.88.110",
  "username": "admin",
  "password": "access123"}   net_connect = ConnectHandler(**device) output = net_connect.send_command("show arp")
```

如果我想看 netmiko 源代码，我可以去安装 netmiko 库的 site-packages 并列出所有文件*或*我可以在 PyCharm 中使用*Ctrl*和左键单击模块名称。这将在新标签中打开源代码：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00035.jpeg)

# 可视化 Python 代码

你是否想知道 Python 自定义模块或类是如何制造的？开发人员如何编写 Python 代码并将其粘合在一起以创建这个漂亮而惊人的*x*模块？底层发生了什么？

文档是一个很好的开始，当然，我们都知道它通常不会随着每一步或开发人员添加的每一个细节而更新。

例如，我们都知道由 Kirk Byers 创建和维护的强大的 netmiko 库（[`github.com/ktbyers/netmiko`](https://github.com/ktbyers/netmiko)），它利用了另一个名为 Paramiko 的流行 SSH 库（[`www.paramiko.org/`](http://www.paramiko.org/)）。但我们不了解细节以及这些类之间的关系。如果你需要了解 netmiko（或任何其他库）背后的魔力，以便处理请求并返回结果，请按照以下步骤（需要 PyCharm 专业版）。

PyCharm 中的代码可视化和检查不受 PyCharm 社区版支持，只有专业版支持。

以下是你需要遵循的步骤：

1.  转到 Python 库位置文件夹中的 netmiko 模块源代码（通常在 Windows 上为`C:\Python27\Lib\site-packages`或在 Linux 上为`/usr/local/lib/pyhon2.7/dist-packages`）并从 PyCharm 中打开文件。

1.  右键单击地址栏中出现的模块名称，选择 Diagram | Show Diagram。从弹出窗口中选择 Python 类图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00036.jpeg)

1.  PyCharm 将开始在`netmiko`模块中的所有类和文件之间构建依赖树，然后在同一个窗口中显示它。请注意，这个过程可能需要一些时间，具体取决于你的计算机内存。此外，最好将图表保存为外部图像以查看：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00037.jpeg)

根据生成的图表，你可以看到 Netmiko 支持许多供应商，如 HP Comware，entrasys，Cisco ASA，Force10，Arista，Avaya 等，所有这些类都继承自`netmiko.cisco_base_connection.CicsoSSHConnection`父类（我认为这是因为它们使用与思科相同的 SSH 风格）。这又继承自另一个名为`netmiko.cisco_base_connection.BaseConnection`的大父类。

此外，你可以看到 Juniper 有自己的类（`netmiko.juniper.juniper_ssh.JuniperSSH`），它直接连接到大父类。最后，我们连接到 Python 中所有父类的父类：`Object`类（记住最终在 Python 中的一切都是对象）。

你可以找到很多有趣的东西，比如*SCP 传输*类和*SNMP*类，每个类都会列出用于初始化该类的方法和参数。

因此，`ConnectHandler`方法主要用于检查供应商类中的`device_type`可用性，并根据返回的数据使用相应的 SSH 类：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00038.jpeg)

可视化代码的另一种方法是查看代码执行期间实际命中的模块和函数。这称为分析，它允许你在运行时检查函数。

首先，您需要像往常一样编写您的代码，然后右键单击空白处，选择“profile”而不是像平常一样运行代码：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00039.jpeg)

等待代码执行。这次，PyCharm 将检查从您的代码调用的每个文件，并为执行生成*调用图*，这样您就可以轻松地知道使用了哪些文件和函数，并计算每个文件的执行时间：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00040.jpeg)

正如您在上一个图表中所看到的，我们在`profile_code.py`中的代码（图表底部）将调用`ConnectHandler()`函数，而后者将执行`__init__.py`，并且执行将继续。在图表的左侧，您可以看到在代码执行期间触及的所有文件。

# 摘要

在本章中，我们探讨了 Python 提供的一些最受欢迎的网络、系统和云包。此外，我们学习了如何访问模块源代码，并将其可视化，以更好地理解内部代码。我们查看了代码运行时的调用流程。在下一章中，我们将开始构建实验环境，并将我们的代码应用于其中。


# 第三章：设置网络实验室环境

我们现在已经有了如何编写和开发 Python 脚本的基本概念，这是创建程序的基本组成部分。我们现在将继续了解为什么自动化是当今网络中一个重要的话题，然后我们将使用一种流行的软件之一，名为 EVE-NG，来构建我们的网络自动化实验室，这有助于我们虚拟化网络设备。

在本章中，我们将涵盖以下主题：

+   何时以及为什么自动化网络

+   屏幕抓取与 API 自动化

+   为什么要使用 Python 进行网络自动化

+   网络自动化的未来

+   实验室设置

+   准备工作：安装 EVE-NG

+   构建企业网络拓扑

# 技术要求

在本章中，我们将介绍 EVE-NG 的安装步骤以及如何创建我们的实验室环境。安装将在 VMware Workstation、VMware ESXi 和最后的 Red Hat KVM 上进行，因此您应该熟悉虚拟化概念，并在实验室设置之前已经运行其中一个 hypervisor。

# 何时以及为什么自动化网络

网络自动化正在全球范围内增加。然而，了解何时以及为什么自动化您的网络是非常重要的。例如，如果您是几个网络设备（三四个交换机）的管理员，并且不经常在它们上执行许多任务，那么您可能不需要对它们进行全面自动化。实际上，编写和开发脚本以及测试和故障排除所需的时间可能大于手动执行简单任务所需的时间。另一方面，如果您负责一个包含多供应商平台的大型企业网络，并且经常执行重复任务，那么强烈建议您编写脚本来自动化。

# 我们为什么需要自动化？

今天网络自动化的重要性有几个原因：

+   **降低成本**：使用自动化解决方案（无论是内部开发还是从供应商购买）将减少网络操作复杂性以及配置、操作网络设备所需的时间

+   **业务连续性**：自动化将减少当前基础设施上服务创建过程中的人为错误，从而使企业能够缩短服务的**上市时间**（**TTM**）

+   **业务敏捷性**：大多数网络任务都是重复的，通过自动化，您将提高生产力并推动业务创新

+   **相关性**：建立稳固的自动化工作流程使网络和系统管理员能够更快地进行根本原因分析，并增加通过将多个事件相关联来解决问题的可能性

# 屏幕抓取与 API 自动化

长期以来，CLI 是管理和操作网络设备的唯一访问方法。运营商和管理员过去通常使用 SSH 和 Telnet 来访问网络终端进行配置和故障排除。Python 或任何编程语言在与设备通信时有两种方法。第一种是像以前一样使用 SSH 或 Telnet 获取信息，然后处理它。这种方法称为**屏幕抓取**，需要能够与设备建立连接并直接在终端上执行命令的库，以及其他库来处理返回的信息，以提取有用的数据。这种方法通常需要了解其他解析语言，如正则表达式，以匹配输出的数据模式并从中提取有用的数据。

第二种方法称为**应用程序可编程接口**（**API**），这种方法完全依赖于使用 REST 或 SOAP 协议向设备发送结构化请求，并返回输出，也以结构化格式编码为 JSON 或 XML。与第一种方法相比，这种方法中处理返回数据所需的时间相当短；但是，API 需要在网络设备上进行额外的配置以支持它。

# 为什么要使用 Python 进行网络自动化？

Python 是当今一个非常结构良好且易于使用的编程语言，面向技术、Web 和互联网开发、数据挖掘和可视化、桌面 GUI、分析、游戏开发和自动化测试的许多领域；这就是为什么它被称为*通用目的语言*。

因此，选择 Python 有三个原因：

+   易读性和易用性：当你使用 Python 进行开发时，实际上是在用英语写作。Python 内部的许多关键字和程序流都被设计成可读的语句。此外，Python 不需要`;`或花括号来开始和结束代码块，这使得 Python 具有较低的学习曲线。最后，Python 有一些可选的规则，称为 PEP 8，告诉 Python 开发人员如何格式化他们的程序以获得可读的代码。

你可以配置 PyCharm 来遵循这些规则，并通过转到设置|检查|PEP 8 编码风格违规来检查你的代码是否违反了这些规则：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00041.jpeg)

+   **库**：这是 Python 的真正力量：库和包。Python 在许多领域拥有广泛的库。任何 Python 开发人员都可以轻松开发一个 Python 库并将其上传到网上，以便其他开发人员使用。库被上传到一个名为 PyPI 的网站（[`pypi.Python.org/pypi`](https://pypi.python.org/pypi)），并链接到一个 GitHub 存储库。当你想要将库下载到你的电脑上时，你可以使用一个叫做`pip`的工具连接到 PyPI 并将其下载到本地。诸如思科、Juniper 和 Arista 等网络供应商开发了库来方便访问他们的平台。大多数供应商都在努力使他们的库易于使用，并且需要最少的安装和配置步骤来从设备中检索有用的信息。

+   **强大**：Python 试图最小化达到最终结果所需的步骤数量。例如，要使用 Java 打印 hello world，你将需要这个代码块：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00042.jpeg)

然而，在 Python 中，整个代码块都写在一行中以打印它，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00043.jpeg)

将所有这些原因结合在一起，使 Python 成为自动化的事实标准，也是供应商在自动化网络设备时的首选。

# 网络自动化的未来

在很长一段时间里，网络自动化只意味着使用编程语言（如 Perl、TcL 或 Python）开发脚本，以便在不同的网络平台上执行任务。这种方法被称为**脚本驱动的网络自动化**。但随着网络变得更加复杂和服务导向，需要并开始出现新类型的自动化，例如以下内容：

+   **软件定义的网络自动化**：网络设备只有一个转发平面，而控制平面是使用外部软件（称为**SDN 控制器**）实现和创建的。这种方法的好处是任何网络变化都将有一个单一的联系点，并且 SDN 控制器可以接受来自其他软件（如外部门户）的变更请求，通过良好实现的北向接口。

+   **高级编排**：这种方法需要一个称为编排器的软件，它与 SDN 控制器集成，并使用抽象服务的语言（如 YANG）创建网络服务模型，该模型将在其上运行的底层设备中运行。此外，编排器可以与**虚拟基础设施管理器**（**VIM**）（如 OpenStack 和 vCenter）集成，以便管理虚拟机作为网络服务建模的一部分。

+   **基于策略的网络**：在这种类型的自动化中，您描述了网络中所需的内容，系统具有所有详细信息，以便找出如何在底层设备中实现它。这使软件工程师和开发人员能够在网络中实施更改，并在声明性策略中描述其应用程序的需求。

# 网络实验室设置

现在，我们将开始在一个名为 EVE-NG 的流行平台上构建我们的网络实验室。当然，您可以使用物理节点来实现拓扑，但虚拟化环境为我们提供了一个隔离和沙箱环境，可以测试许多不同的配置，还可以灵活地添加/删除节点到/从拓扑中。此外，我们可以对我们的配置进行多个快照，因此可以随时恢复到任何场景。

EVE-NG（以前称为 UNetLab）是网络仿真中最受欢迎的选择之一。它支持来自不同供应商的各种虚拟化节点。还有另一个选择，即 GNS3，但正如我们将在本章和下一章中看到的那样，EVE-NG 提供了许多功能，使其成为网络建模的一个坚实选择。

EVE-NG 有三个版本：社区版、专业版和学习中心。我们将使用社区版，因为它包含了我们在本书中需要的所有功能。

# 准备就绪-安装 EVE-NG

EVE-NG 社区版有两个选项，OVA 和 ISO。第一个选项是使用 OVA，它为您提供了所需的最少安装步骤，前提是您已经拥有 VMware Player/Workstation/Fusion，或 VMware ESXi，或 Red Hat KVM。第二个选项是在没有虚拟化程序的裸机服务器上直接安装它，这次使用 Ubuntu 16.06 LTS 操作系统：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00044.jpeg)

然而，ISO 选项需要一些 Linux 高级技能来准备机器本身，并将安装存储库导入操作系统。

Oracle VirtualBox 不支持 EVE-NG 所需的硬件加速，因此最好在 VMware 或 KVM 中安装它。

首先，前往[`www.eve-ng.net/index.php/downloads/eve-ng`](http://www.eve-ng.net/index.php/downloads/eve-ng)下载最新版本的 EVE-NG，然后将其导入到您的虚拟化程序中。我为创建的机器分配了 8 GB 内存和四个 vCPU，但您可以为其添加更多资源。在下一节中，我们将看到如何将下载的镜像导入到虚拟化程序并配置每个镜像。

# 在 VMware Workstation 上安装

在接下来的步骤中，我们将把下载的 EVE-NG OVA 镜像导入到 VMware Workstation 中。基于 OVA 的镜像包含描述虚拟机的文件，如硬盘、CPU 和 RAM 值。导入后，您可以修改这些数字：

1.  打开 VMware Workstation，从“文件”中选择“打开”以导入 OVA。

1.  完成导入过程后，右键单击新创建的机器，选择“编辑设置”。

1.  将处理器数量增加到 4 个，内存分配为 8 GB（同样，如果您有资源，可以添加更多，但此设置对于我们的实验足够了）。

1.  确保启用虚拟化 Intel VT-x/EPT 或 AMD-V/RVI 复选框。此选项指示 VMware Workstation 将虚拟化标志传递给客户操作系统（嵌套虚拟化）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00045.jpeg)

此外，建议通过向现有硬盘添加额外空间来扩展硬盘，以便有足够的空间来托管来自供应商的多个镜像：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00046.jpeg)

扩展磁盘后，将出现一条消息，指示操作已成功完成，并且您需要按照一些程序在客户操作系统中将新空间与旧空间合并。幸运的是，我们不需要这样做，因为 EVE-NG 将在系统启动期间将硬盘中发现的任何新空间与旧空间合并：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00047.jpeg)

# 在 VMware ESXi 上安装

VMware ESXi 是直接在系统上运行的一种类型 1 虚拟化程序的良好示例。有时它们被称为裸机虚拟化程序，并且与类型 2 虚拟化程序（如 VMware Workstation/Fusion 或 VirtualBox）相比，它们提供了许多功能：

1.  打开 vSphere 客户端并连接到您的 ESXi 服务器

1.  从“文件”菜单中，选择“部署 OVF 模板”

1.  输入下载的 OVA 镜像的路径并单击“下一步”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00048.jpeg)

1.  接受虚拟化程序建议的所有默认设置，直到您到达最终页面“准备完成”，然后单击“完成”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00049.jpeg)

ESXi 将开始在虚拟化程序上部署镜像，稍后您可以更改其设置并为其添加更多资源，就像我们之前在 VMware Workstation 中所做的那样。

# 在 Red Hat KVM 上安装

您需要将下载的 OVA 镜像转换为 KVM 支持的 QCOW2 格式。按照以下步骤将一种格式转换为另一种格式。我们将需要一个名为`qemu-img`的特殊实用程序，该实用程序可在`qemu-utils`软件包内找到：

1.  解压下载的 OVA 文件以提取 VMDK 文件（镜像的硬盘）：

```py
tar -xvf EVE\ Community\ Edition.ova
EVE Community Edition.ovf
EVE Community Edition.vmdk
```

1.  安装`qemu-utils`工具：

```py
sudo apt-get install qemu-utils
```

1.  现在，将 VMDK 转换为 QCOW2。转换可能需要几分钟才能完成：

```py
qemu-img convert -O qcow2 EVE\ Community\ Edition.vmdk eve-ng.qcow
```

最后，我们有自己的准备好在 Red Hat KVM 中托管的`qcow2`文件。打开 KVM 控制台，并从菜单中选择“导入现有磁盘映像”选项：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00050.jpeg)

然后，选择转换图像的路径并单击“前进”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00051.jpeg)

# 访问 EVE-NG

在将镜像导入虚拟化程序并启动它后，您将被要求提供一些信息以完成安装。首先，您将看到 EVE 标志，表示机器已成功导入虚拟化程序，并准备启动引导阶段：

1.  提供将用于 SSH 连接到 EVE 机器的 root 密码。默认情况下，它将是`eve`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00052.gif)

1.  提供将在 Linux 内用作名称的主机名：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00053.gif)

1.  为机器提供一个域名：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00054.gif)

1.  选择使用静态方法配置网络。这将确保即使在机器重启后，给定的 IP 地址也将是持久的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00055.gif)

1.  最后，提供一个从您的网络可达的范围内的静态 IP 地址。此 IP 将用于 SSH 到 EVE 并将供应商镜像上传到存储库：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00056.gif)

要访问 EVE-NG GUI，您需要打开浏览器并转到`http://<server_ip>`。请注意，`server_IP`是我们在安装步骤中使用的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00057.jpeg)GUI 的默认用户名是`admin`，密码是`eve`，而 SSH 的默认用户名是`root`，密码是在安装步骤中提供的。

# 安装 EVE-NG 客户端包

EVE-NG 附带的客户端包允许我们选择在 telnet 或 SSH 到设备时使用哪个应用程序（PuTTY 或 SecureCRT），并设置 Wireshark 以在链接之间进行远程数据包捕获。此外，它还便于在基于 RDP 和 VNC 的镜像上工作。首先，您需要从[`eve-ng.net/index.php/downloads/windows-client-side-pack`](http://eve-ng.net/index.php/downloads/windows-client-side-pack)下载客户端包到您的 PC，然后将文件提取到`C:\Program Files\EVE-NG`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00058.gif)

提取的文件包含许多用 Windows 批处理脚本（`.bat`）编写的脚本，用于配置将用于访问 EVE-NG 的机器。您将找到配置默认 Telnet/SSH 客户端的脚本和另一个用于 Wireshark 和 VNC 的脚本。软件源也可在文件夹内找到：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00059.jpeg)如果您使用 Ubuntu 或 Fedora 等 Linux 桌面，则可以使用 GitHub 上的这个优秀项目来获取客户端包：[`github.com/SmartFinn/eve-ng-integration`](https://github.com/SmartFinn/eve-ng-integration)。

# 将网络图像加载到 EVE-NG 中

从供应商获得的所有网络图像都应上传到`/opt/unetlab/addons/qemu`。EVE-NG 支持基于 QEMU 的图像和动态图像，还支持 iOL（iOS On Linux）。

当您从供应商那里获得图像时，您应该在`/opt/unetlab/addons/qemu`内创建一个目录，并将图像上传到该目录；然后，您应该执行此脚本来修复上传图像的权限：

```py
/opt/unetlab/wrappers/unl_wrapper -a fixpermission
```

# 构建企业网络拓扑

在我们的基本实验室设置中，我们将模拟一个具有四个交换机和一个充当外部网络网关的路由器的企业网络。以下是将用于每个节点的 IP 模式：

| **节点名称** | **IP** |
| --- | --- |
| GW | `10.10.88.110` |
| Switch1 | `10.10.88.111` |
| Switch2 | `10.10.88.112` |
| Switch3 | `10.10.88.113` |
| Switch4 | `10.10.88.114` |

我们的 Python 脚本（或 Ansible 剧本）将托管在连接到每个设备的管理的外部 Windows PC 上。

# 添加新节点

我们将首先选择已经上传到 EVE 的 IOSv 图像，并将四个交换机添加到拓扑。右键单击拓扑中的任何空白处，并从下拉菜单中选择添加新对象，选择添加节点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00060.jpeg)

您应该看到两个蓝色的 Cisco 图像，表示它们已成功添加到 EVE-NG 库中的可用图像，并映射到相应的模板。选择 Cisco vIOS L2 以添加 Cisco 交换机：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00061.jpeg)

增加要添加的节点数到 4，然后点击确定：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00062.jpeg)

现在，您将看到四个交换机添加到拓扑；再次重复此操作并添加路由器，但这次选择 Cisco vIOS：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00063.jpeg)

# 连接节点

现在，开始连接节点，当节点离线时，重复每个节点，直到您完成连接拓扑内的所有节点；然后，开始实验：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00064.gif)

在将 IP 地址和一些自定义形状添加到拓扑后的最终视图如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00065.jpeg)

现在，我们的拓扑已经准备就绪，并且应该加载基本配置。我使用以下片段作为启用 SSH 和 telnet 的任何 Cisco-IOS 设备的配置基础，并配置了用于访问的用户名。请注意，有一些参数被`{{ }}`包围。我们将在下一章讨论它们，当我们使用 Jinja2 模板生成一个黄金配置时，但现在，分别用`hostname`和每个设备的管理 IP 地址替换它们：

```py
hostname {{hostname}}
int gig0/0
  no shutdown
  ip address {{mgmt_ip}} 255.255.255.0

aaa new-model
aaa session-id unique
aaa authentication login default local
aaa authorization exec default local none 

enable password access123
username admin password access123
no ip domain-lookup

lldp run

ip domain-name EnterpriseAutomation.net
ip ssh version 2
ip scp server enable
crypto key generate rsa general-keys modulus 1024

```

# 总结

在本章中，我们了解了当今可用的不同类型的网络自动化，以及为什么我们选择 Python 作为网络自动化中的主要工具。此外，我们学习了如何在不同的 hypervisor 和平台上安装 EVE-NG，如何提供初始配置，以及如何将我们的网络图像添加到图像目录中。然后，我们添加了不同的节点并将它们连接在一起，以创建我们的网络企业实验室。

在下一章中，我们将开始构建我们的 Python 脚本，使用不同的 Python 库（如 telnetlib、Netmiko、Paramiko 和 Pexpect）自动化拓扑中的不同任务。


# 第四章：使用 Python 管理网络设备

现在我们对如何在不同操作系统中使用和安装 Python 以及如何使用 EVE-NG 构建网络拓扑有了相当的了解。在本章中，我们将发现如何利用今天用于自动化各种网络任务的许多网络自动化库。Python 可以在许多层面与网络设备进行交互。

首先，它可以通过套接字编程和 `socket` 模块处理低级层，这些模块作为运行 Python 的操作系统和网络设备之间的低级网络接口。此外，Python 模块通过 telnet、SSH 和 API 提供更高级的交互。在本章中，我们将深入探讨如何使用 Python 建立远程连接并使用 telnet 和 SSH 模块在远程设备上执行命令。

以下主题将被涵盖：

+   使用 Python 进行 telnet 到设备

+   Python 和 SSH

+   使用 `netaddr` 处理 IP 地址和网络

+   网络自动化示例用例

# 技术要求

以下工具应安装并在您的环境中可用：

+   Python 2.7.1x

+   PyCharm 社区版或专业版

+   EVE-NG 拓扑；请参阅第三章，*设置网络实验室环境*，了解如何安装和配置模拟器

您可以在以下 GitHub URL 找到本章中开发的完整脚本：[`github.com/TheNetworker/EnterpriseAutomation.git`](https://github.com/TheNetworker/EnterpriseAutomation.git)。

# Python 和 SSH

与 telnet 不同，SSH 提供了一个安全的通道，用于在客户端和服务器之间交换数据。在客户端和设备之间创建的隧道使用不同的安全机制进行加密，使得任何人都很难解密通信。对于需要安全管理网络节点的网络工程师来说，SSH 协议是首选。

Python 可以使用 SSH 协议与网络设备通信，利用一个名为 **Paramiko** 的流行库，该库支持认证、密钥处理（DSA、RSA、ECDSA 和 ED25519）以及其他 SSH 功能，如 `proxy` 命令和 SFTP。

# Paramiko 模块

Python 中最广泛使用的 SSH 模块称为 `Paramiko`，正如 GitHub 官方页面所说，Paramiko 的名称是 "paranoid" 和 "friend" 这两个世界的组合。该模块本身是使用 Python 编写和开发的，尽管一些核心功能如加密依赖于 C 语言。您可以在官方 GitHub 链接中了解更多有关贡献者和模块历史的信息：[`github.com/paramiko/paramiko`](https://github.com/paramiko/paramiko)。

# 模块安装

打开 Windows cmd 或 Linux shell 并执行以下命令，从 PyPI 下载最新的 `paramiko` 模块。它将下载附加的依赖包，如 `cyrptography`、`ipaddress` 和 `six`，并在您的计算机上安装它们：

```py
pip install paramiko
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00066.jpeg)

您可以通过进入 Python shell 并导入 `paramiko` 模块来验证安装是否成功，如下面的屏幕截图所示。Python 应该成功导入它而不打印任何错误：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00067.jpeg)

# SSH 到网络设备

与每个 Python 模块一样，我们首先需要将其导入到我们的 Python 脚本中，然后我们将通过继承 `SSHClient()` 来创建一个 SSH 客户端。之后，我们将配置 Paramiko 自动添加任何未知的主机密钥并信任您和服务器之间的连接。然后，我们将使用 `connect` 函数并提供远程主机凭据：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   import paramiko
import time
Channel = paramiko.SSHClient()  Channel.set_missing_host_key_policy(paramiko.AutoAddPolicy()) Channel.connect(hostname="10.10.88.112", username='admin', password='access123', look_for_keys=False,allow_agent=False)   shell = Channel.invoke_shell()  
```

`AutoAddPolicy()` 是可以在 `set_missing_host_key_policy()` 函数内使用的策略之一。在实验室环境中，它是首选且可接受的。然而，在生产环境中，我们应该使用更严格的策略，比如 `WarningPolicy()` 或 `RejectPolicy()`。

最后，`invoke_shell()`将启动与我们的 SSH 服务器的交互式 shell 会话。您可以向其提供附加参数，如终端类型、宽度和高度。

Paramiko 连接参数：

+   `Look_For_Keys`：默认为`True`，它将强制 Paramiko 使用密钥对身份验证，用户使用私钥和公钥对来对网络设备进行身份验证。在我们的情况下，我们将其设置为`False`，因为我们将使用密码身份验证。

+   `allow_agent paramiko`：它可以连接到本地 SSH 代理操作系统。这在使用密钥时是必要的；在这种情况下，由于使用登录/密码进行身份验证，我们将禁用它。

最后一步是向设备终端发送一系列命令，如`show ip int b`和`show arp`，并将输出返回到我们的 Python shell：

```py
shell.send("enable\n") shell.send("access123\n") shell.send("terminal length 0\n") shell.send("show ip int b\n") shell.send("show arp \n") time.sleep(2) print shell.recv(5000)  Channel.close()
```

脚本输出为：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00068.jpeg)当您需要在远程设备上执行需要很长时间的命令时，最好使用`time.sleep()`来强制 Python 等待一段时间，直到设备生成输出并将其发送回 Python。否则，Python 可能会向用户返回空白输出。

# Netmiko 模块

`netmiko`模块是 paramiko 的增强版本，专门针对网络设备。虽然 paramiko 旨在处理对设备的 SSH 连接，并检查设备是服务器、打印机还是网络设备，但 Netmiko 是专为网络设备设计的，并更有效地处理 SSH 连接。此外，Netmiko 支持广泛的供应商和平台。

Netmiko 被认为是 paramiko 的包装器，并通过许多附加增强功能扩展了其功能，例如直接访问供应商启用模式，读取配置文件并将其推送到设备，登录期间禁用分页，并在每个命令后默认发送回车符`"\n"`。

# 供应商支持

Netmiko 支持许多供应商，并定期向受支持的列表中添加新供应商。以下是受支持的供应商列表，分为三组：定期测试，有限测试和实验性。您可以在模块 GitHub 页面上找到列表[`github.com/ktbyers/netmiko#supports`](https://github.com/ktbyers/netmiko#supports)。

以下截图显示了定期测试类别下受支持供应商的数量：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00069.jpeg)

以下截图显示了有限测试类别下受支持供应商的数量：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00070.jpeg)

以下截图显示了实验类别下受支持供应商的数量：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00071.jpeg)

# 安装和验证

要安装`netmiko`，打开 Windows cmd 或 Linux shell，并执行以下命令从 PyPI 获取最新包：

```py
pip install netmiko
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00072.jpeg)

然后从 Python shell 导入 netmiko，以确保模块已正确安装到 Python site-packages 中：

```py
$python
>>>import netmiko
```

# 使用 netmiko 进行 SSH

现在是时候利用 netmiko 并看到它在 SSH 到网络设备并执行命令时的强大功能。默认情况下，netmiko 在会话建立期间在后台处理许多操作，例如添加未知的 SSH 密钥主机，设置终端类型、宽度和高度，并在需要时访问启用模式，然后通过运行特定于供应商的命令来禁用分页。您需要首先以字典格式定义设备，并提供五个强制键：

```py
R1 = {
  'device_type': 'cisco_ios',
  'ip': '10.10.88.110',
  'username': 'admin',
  'password': 'access123',
  'secret': 'access123',  }
```

第一个参数是`device_type`，用于定义平台供应商，以便执行正确的命令。然后，我们需要 SSH 的`ip`地址。如果已经通过 DNS 解析了设备主机名，这个参数可以是设备主机名，或者只是 IP 地址。然后我们提供`username`，`password`，和`secret`中的启用模式密码。请注意，您可以使用`getpass()`模块隐藏密码，并且只在脚本执行期间提示密码。

虽然变量内的键的顺序并不重要，但键的名称应与前面的示例中提供的完全相同，以便 netmiko 正确解析字典并开始建立与设备的连接。

接下来，我们将从 netmiko 模块中导入`ConnectHandler`函数，并给它定义的字典以开始连接。由于我们所有的设备都配置了启用模式密码，我们需要通过提供`.enable()`来访问启用模式到创建的连接。我们将使用`.send_command()`在路由器终端上执行命令，该命令将执行命令并将设备输出返回到变量中：

```py
from netmiko import ConnectHandler
connection = ConnectHandler(**R1)  connection.enable()  output = connection.send_command("show ip int b") print output
```

脚本输出为：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00073.jpeg)

请注意输出已经从设备提示和我们在设备上执行的命令中清除。默认情况下，Netmiko 会替换它们并生成一个经过清理的输出，可以通过正则表达式进行处理，我们将在下一章中看到。

如果您需要禁用此行为，并希望在返回的输出中看到设备提示和执行的命令，则需要为`.send_command()`函数提供额外的标志：

```py
output = connection.send_command("show ip int b",strip_command=False,strip_prompt=False) 
```

`strip_command=False`和`strip_prompt=False`标志告诉 netmiko 保留提示和命令，不要替换它们。它们默认为`True`，如果需要，可以切换它们：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00074.jpeg)

# 使用 netmiko 配置设备

Netmiko 可以用于通过 SSH 配置远程设备。它通过使用`.config`方法访问配置模式，然后应用以`list`格式给出的配置来实现这一点。列表本身可以在 Python 脚本中提供，也可以从文件中读取，然后使用`readlines()`方法转换为列表：

```py
from netmiko import ConnectHandler

SW2 = {
  'device_type': 'cisco_ios',
  'ip': '10.10.88.112',
  'username': 'admin',
  'password': 'access123',
  'secret': 'access123', }   core_sw_config = ["int range gig0/1 - 2","switchport trunk encapsulation dot1q",
  "switchport mode trunk","switchport trunk allowed vlan 1,2"]     print "########## Connecting to Device {0} ############".format(SW2['ip']) net_connect = ConnectHandler(**SW2) net_connect.enable()    print "***** Sending Configuration to Device *****" net_connect.send_config_set(core_sw_config) 
```

在上一个脚本中，我们做了与之前连接到 SW2 并进入启用模式相同的事情，但这次我们利用了另一个 netmiko 方法，称为`send_config_set()`，它以列表格式接收配置并访问设备配置模式并开始应用。我们有一个简单的配置，修改了`gig0/1`和`gig0/2`，并对它们应用了干线配置。您可以通过在设备上运行`show run`命令来检查命令是否成功执行；您应该会得到类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00075.jpeg)

# netmiko 中的异常处理

当设计 Python 脚本时，我们假设设备正在运行，并且用户已经提供了正确的凭据，这并不总是情况。有时 Python 和远程设备之间存在网络连接问题，或者用户输入了错误的凭据。通常，如果发生这种情况，Python 会抛出异常并退出，这并不是最佳解决方案。

netmiko 中的异常处理模块`netmiko.ssh_exception`提供了一些可以处理这种情况的异常类。第一个是`AuthenticationException`，将捕获远程设备中的身份验证错误。第二个类是`NetMikoTimeoutException`，将捕获 netmiko 和设备之间的超时或任何连接问题。我们需要做的是用 try-except 子句包装我们的 ConnectHandler()方法，并捕获超时和身份验证异常：

```py

from netmiko import ConnectHandler
from netmiko.ssh_exception import AuthenticationException, NetMikoTimeoutException

device = {
  'device_type': 'cisco_ios',
  'ip': '10.10.88.112',
  'username': 'admin',
  'password': 'access123',
  'secret': 'access123', }     print "########## Connecting to Device {0} ############".format(device['ip']) try:
  net_connect = ConnectHandler(**device)
  net_connect.enable()    print "***** show ip configuration of Device *****"
  output = net_connect.send_command("show ip int b")
  print output

    net_connect.disconnect()   except NetMikoTimeoutException:
  print "=========== SOMETHING WRONG HAPPEN WITH {0} ============".format(device['ip'])   except AuthenticationException:
  print "========= Authentication Failed with {0} ============".format(device['ip'])   except Exception as unknown_error:
  print "============ SOMETHING UNKNOWN HAPPEN WITH {0} ============"
```

# 设备自动检测

Netmiko 提供了一种可以猜测设备类型并检测它的机制。它使用 SNMP 发现 OID 和在远程控制台上执行几个 show 命令的组合来检测路由器操作系统和类型，基于输出字符串。然后 netmiko 将加载适当的驱动程序到`ConnectHandler()`类中：

```py
#!/usr/local/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"     from netmiko import SSHDetect, Netmiko

device = {
  'device_type': 'autodetect',
  'host': '10.10.88.110',
  'username': 'admin',
  'password': "access123", }   detect_device = SSHDetect(**device) device_type = detect_device.autodetect() print(device_type)  print(detect_device.potential_matches)    device['device_type'] = device_type
connection = Netmiko(**device)
```

在上一个脚本中：

+   设备字典中的`device_type`将是`autodetect`，这将告诉`netmiko`等待并不加载驱动程序，直到 netmiko 猜测到它。

+   然后我们指示 netmiko 使用`SSHDetect()`类执行设备检测。该类将使用 SSH 连接到设备，并执行一些发现命令来定义操作系统类型。返回的结果将是一个字典，并且最佳匹配将使用`autodetect()`函数分配给`device_type`变量。

+   您可以通过打印`potential_matches`来查看所有匹配的结果。

+   现在我们可以更新设备字典并为其分配新的`device_type`。

# 使用 Python 中的 telnet 协议

Telnet 是 TCP/IP 协议栈中可用的最古老的协议之一。它主要用于在服务器和客户端之间建立的连接上交换数据。它在服务器上使用 TCP 端口`23`来监听来自客户端的传入连接。

在我们的情况下，我们将创建一个充当 telnet 客户端的 Python 脚本，拓扑中的其他路由器和交换机将充当 telnet 服务器。Python 自带了一个名为`telnetlib`的库，因此我们不需要安装它。

通过从`telnetlib`模块中可用的`Telnet()`类实例化客户端对象后，我们可以使用`telnetlib`中可用的两个重要函数，即`read_until()`（用于读取输出）和`write()`（用于在远程设备上写入）。这两个函数用于与创建的通道进行交互，无论是写入还是读取返回的输出。

另外，重要的是要注意，使用`read_until()`读取通道将清除缓冲区，并且数据将不可用于进一步的读取。因此，如果您读取重要数据并且稍后将对其进行处理和处理，那么您需要在继续脚本之前将其保存为变量。

Telnet 数据以明文格式发送，因此您的凭据和密码可能会被执行中间人攻击的任何人捕获和查看。一些服务提供商和企业仍然使用它，并将其与 VPN 和 radius/tacacs 协议集成，以提供轻量级和安全的访问。

按照以下步骤来理解整个脚本：

1.  我们将在 Python 脚本中导入`telnetlib`模块，并将用户名和密码定义为变量，如下面的代码片段所示：

```py
import telnetlib
username = "admin" password = "access123" enable_password = "access123"
```

1.  我们将定义一个变量，用于与远程主机建立连接。请注意，在建立连接期间我们不会提供用户名或密码；我们只会提供远程主机的 IP 地址：

```py
cnx = telnetlib.Telnet(host="10.10.88.110") #here we're telnet to Gateway 
```

1.  现在我们将通过从通道返回的输出中读取`Username:`关键字并搜索来为 telnet 连接提供用户名。然后我们写入我们的管理员用户名。当我们需要输入 telnet 密码和启用密码时，也是使用相同的过程：

```py
cnx.read_until("Username:") cnx.write(username + "\n") cnx.read_until("Password:") cnx.write(password + "\n") cnx.read_until(">") cnx.write("en" + "\n") cnx.read_until("Password:") cnx.write(enable_password + "\n")  
```

重要的是要提供在建立 telnet 连接或连接时出现在控制台中的确切关键字，否则连接将进入无限循环。然后 Python 脚本将因错误而超时。

1.  最后，我们将在通道上写入`show ip interface brief`命令，并读取直到路由器提示`#`以获取输出。这应该可以让我们获取路由器中的接口配置：

```py
cnx.read_until("#") cnx.write("show ip int b" + "\n") output = cnx.read_until("#") print output
```

完整的脚本如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00076.jpeg)

脚本输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00077.jpeg)

请注意，输出包含执行的命令`show ip int b`，并且路由器提示“R1＃”被返回并打印在`stdout`中。我们可以使用内置的字符串函数如`replace()`来清除它们的输出：

```py
cleaned_output = output.replace("show ip int b","").replace("R1#","")
print cleaned_output 
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00078.jpeg)

正如您注意到的，我们在脚本中以明文形式提供了密码和启用密码，这被认为是一个安全问题。在 Python 脚本中硬编码这些值也不是一个好的做法。稍后在下一节中，我们将隐藏密码并设计一个机制，仅在脚本运行时提供凭据。

此外，如果您想要执行跨多个页面的命令输出，比如`show running config`，那么您需要先发送`terminal length 0`来禁用分页，然后再连接到设备并发送命令。

# 使用 telnetlib 推送配置

在前一节中，我们通过执行`show ip int brief`来简化`telnetlib`的操作。现在我们需要利用它来将 VLAN 配置推送到拓扑中的四个交换机。我们可以使用 python 的`range()`函数创建一个 VLAN 列表，并迭代它以将 VLAN ID 推送到当前交换机。请注意，我们将交换机 IP 地址定义为列表中的一个项目，这个列表将是我们外部的`for`循环。此外，我将使用另一个内置模块称为`getpass`来隐藏控制台中的密码，并且只在脚本运行时提供它：

```py
#!/usr/bin/python import telnetlib
import getpass
import time

switch_ips = ["10.10.88.111", "10.10.88.112", "10.10.88.113", "10.10.88.114"] username = raw_input("Please Enter your username:") password = getpass.getpass("Please Enter your Password:") enable_password = getpass.getpass("Please Enter your Enable Password:")   for sw_ip in switch_ips:
  print "\n#################### Working on Device " + sw_ip + " ####################"
  connection = telnetlib.Telnet(host=sw_ip.strip())
  connection.read_until("Username:")
  connection.write(username + "\n")
  connection.read_until("Password:")
  connection.write(password + "\n")
  connection.read_until(">")
  connection.write("enable" + "\n")
  connection.read_until("Password:")
  connection.write(enable_password + "\n")
  connection.read_until("#")
  connection.write("config terminal" + "\n") # now i'm in config mode
  vlans = range(300,400)
  for vlan_id in vlans:
  print "\n********* Adding VLAN " + str(vlan_id) + "**********"
  connection.read_until("#")
  connection.write("vlan " + str(vlan_id) + "\n")
  time.sleep(1)
  connection.write("exit" + "\n")
  connection.read_until("#")
  connection.close()
```

在我们最外层的`for`循环中，我们正在迭代设备，然后在每次迭代（每个设备）中，我们从 300 到 400 生成一个 vlan 范围，并将它们推送到当前设备。

脚本输出为：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00079.jpeg)

此外，您还可以检查交换机控制台本身的输出（输出已省略）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00080.jpeg)

# 使用 netaddr 处理 IP 地址和网络

处理和操作 IP 地址是网络工程师最重要的任务之一。Python 开发人员提供了一个了不起的库，可以理解 IP 地址并对其进行操作，称为`netaddr`。例如，假设您开发了一个应用程序，其中的一部分是获取`129.183.1.55/21`的网络和广播地址。您可以通过模块内部的两个内置方法`network`和`broadcast`轻松实现：

```py
net.network
129.183.0.
net.broadcast
129.183.0.0
```

总的来说，netaddr 提供以下功能的支持：

**第 3 层地址：**

+   IPv4 和 IPv6 地址、子网、掩码、前缀

+   迭代、切片、排序、总结和分类 IP 网络

+   处理各种范围格式（CIDR、任意范围和通配符、nmap）

+   基于集合的操作（并集、交集等）在 IP 地址和子网上

+   解析各种不同格式和符号

+   查找 IANA IP 块信息

+   生成 DNS 反向查找

+   超网和子网

**第 2 层地址：**

+   表示和操作 MAC 地址和 EUI-64 标识符

+   查找 IEEE 组织信息（OUI、IAB）

+   生成派生的 IPv6 地址

# Netaddr 安装

netaddr 模块可以使用 pip 安装，如下所示：

```py
pip install netaddr
```

作为成功安装模块的验证，您可以在安装后打开 PyCharm 或 Python 控制台，并导入模块。如果没有产生错误，则模块安装成功：

```py
python
>>>import netaddr
```

# 探索 netaddr 方法

`netaddr`模块提供了两种重要的方法来定义 IP 地址并对其进行操作。第一个称为`IPAddress()`，用于定义具有默认子网掩码的单个类 IP 地址。第二种方法是`IPNetwork()`，用于定义具有 CIDR 的无类别 IP 地址。

这两种方法都将 IP 地址作为字符串，并返回该字符串的 IP 地址或 IP 网络对象。可以对返回的对象执行许多操作。例如，我们可以检查 IP 地址是单播、多播、环回、私有、公共，甚至是有效还是无效。上述操作的输出要么是`True`，要么是`False`，可以在 Python 的`if`条件中使用。

此外，该模块支持比较操作，如`==`、`<`和`>`来比较两个 IP 地址，生成子网，还可以检索给定 IP 地址或子网所属的超网列表。最后，`netaddr`模块可以生成一个完整的有效主机列表（不包括网络 IP 和网络广播）：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"  from netaddr import IPNetwork,IPAddress
def check_ip_address(ipaddr):
  ip_attributes = []
  ipaddress = IPAddress(ipaddr)    if ipaddress.is_private():
  ip_attributes.append("IP Address is Private")   else:
  ip_attributes.append("IP Address is public")   if ipaddress.is_unicast():
  ip_attributes.append("IP Address is unicast")
  elif ipaddress.is_multicast():
  ip_attributes.append("IP Address is multicast")   if ipaddress.is_loopback():
  ip_attributes.append("IP Address is loopback")    return "\n".join(ip_attributes)   def operate_on_ip_network(ipnet):    net_attributes = []
  net = IPNetwork(ipnet)   net_attributes.append("Network IP Address is " + str(net.network) + " and Netowrk Mask is " + str(net.netmask))    net_attributes.append("The Broadcast is " + str(net.broadcast) )   net_attributes.append("IP Version is " + str(net.version) )
  net_attributes.append("Information known about this network is " + str(net.info) )   net_attributes.append("The IPv6 representation is " + str(net.ipv6()))   net_attributes.append("The Network size is " + str(net.size))   net_attributes.append("Generating a list of ip addresses inside the subnet")   for ip in net:
  net_attributes.append("\t" + str(ip))   return "\n".join(net_attributes)  
ipaddr = raw_input("Please Enter the IP Address: ") print check_ip_address(ipaddr)    ipnet = raw_input("Please Enter the IP Network: ") print operate_on_ip_network(ipnet) 
```

前面的脚本首先使用`raw_input()`函数从用户那里请求 IP 地址和 IP 网络，然后将调用两个用户方法`check_ip_address()`和`operate_on_ip_network()`，并将输入的值传递给它们。第一个函数`check_ip_address()`将检查输入的 IP 地址并尝试生成有关 IP 地址属性的报告，例如它是单播 IP、多播、私有还是环回，并将输出返回给用户。

第二个函数`operate_on_ip_network()`接受 IP 网络并生成网络 ID、子网掩码、广播、版本、已知有关此网络的信息、IPv6 表示，最后生成此子网中的所有 IP 地址。

重要的是要注意，`net.info`仅对公共 IP 地址有效，而不适用于私有 IP 地址。

请注意，在使用它们之前，我们需要从`netaddr`模块导入`IP Network`和`IP Address`。

脚本输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00081.jpeg)

# 示例用例

随着我们的网络变得越来越大，并开始包含来自不同供应商的许多设备，我们需要创建模块化的 Python 脚本来自动化其中的各种任务。在接下来的几节中，我们将探讨三种用例，这些用例可以用来从我们的网络中收集不同的信息，并降低故障排除所需的时间，或者至少将网络配置恢复到其上次已知的良好状态。这将使网络工程师更专注于完成他们的工作，并为企业提供处理网络故障和恢复的自动化工作流程。

# 备份设备配置

备份设备配置是任何网络工程师的最重要任务之一。在这种用例中，我们将设计一个示例 Python 脚本，可用于不同的供应商和平台，以备份设备配置。我们将利用`netmiko`库来执行此任务。

结果文件应该以设备 IP 地址格式化，以便以后轻松访问或引用。例如，SW1 备份操作的结果文件应为`dev_10.10.88.111_.cfg`。

# 构建 Python 脚本

我们将首先定义我们的交换机。我们希望将它们的配置备份为文本文件，并提供由逗号分隔的凭据和访问详细信息。这将使我们能够在 Python 脚本中使用`split()`函数获取数据，并在`ConnectHandler`函数中使用它。此外，该文件可以轻松地从 Microsoft Excel 表或任何数据库中导出和导入。

文件结构如下：

`<device_ipaddress>,<username>,<password>,<enable_password>,<vendor>`

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00082.jpeg)

现在我们将通过导入文件并使用`with open`子句来开始构建我们的 Python 脚本。我们使用文件上的`readlines()`将每一行作为列表中的一个项目。我们将创建一个`for`循环来遍历每一行，并使用`split()`函数来通过逗号分隔访问详细信息并将它们分配给变量：

```py
from netmiko import ConnectHandler
from datetime import datetime

with open("/media/bassim/DATA/GoogleDrive/Packt/EnterpriseAutomationProject/Chapter5_Using_Python_to_manage_network_devices/UC1_devices.txt") as devices_file:    devices = devices_file.readlines()   for line in devices:
    line = line.strip("\n")
  ipaddr = line.split(",")[0]
  username = line.split(",")[1]
  password = line.split(",")[2]
  enable_password = line.split(",")[3]    vendor = line.split(",")[4]    if vendor.lower() == "cisco":
  device_type = "cisco_ios"
  backup_command = "show running-config"    elif vendor.lower() == "juniper":
  device_type = "juniper"
  backup_command = "show configuration | display set"   
```

由于我们需要创建一个模块化和多供应商的脚本，我们需要在每一行中使用`if`子句检查供应商，并为当前设备分配正确的`device_type`和`backup_command`。

接下来，我们现在准备使用`netmiko`模块中可用的`.send_command()`方法建立与设备的 SSH 连接并在其上执行备份命令：

```py

print str(datetime.now()) + " Connecting to device {}" .format(ipaddr)   net_connect = ConnectHandler(device_type=device_type,
  ip=ipaddr,
  username=username,
  password=password,
  secret=enable_password) net_connect.enable() running_config = net_connect.send_command(backup_command)   print str(datetime.now()) + " Saving config from device {}" .format(ipaddr)   f = open( "dev_" + ipaddr + "_.cfg", "w") f.write(running_config) f.close() print "=============================================="
```

在最后几个语句中，我们打开了一个文件进行写入，并使其名称包含从我们的文本文件中收集的`ipaddr`变量。

脚本输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00083.jpeg)

另外，请注意备份配置文件是在项目主目录中创建的，其名称包含每个设备的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00084.jpeg)您可以在 Linux 服务器上设计一个简单的 cron 作业，或在 Windows 服务器上安排一个作业，在特定时间运行先前的 Python 脚本。例如，脚本可以每天午夜运行一次，并将配置存储在`latest`目录中，以便团队以后可以参考。

# 创建您自己的访问终端

在 Python 中，以及一般的编程中，您就是供应商！您可以创建任何代码组合和程序，以满足您的需求。在第二个用例中，我们将创建我们自己的终端，通过`telnetlib`访问路由器。通过在终端中写入几个单词，它将被翻译成在网络设备中执行的多个命令并返回输出，这些输出可以只打印在标准输出中，也可以保存在文件中：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   import telnetlib

connection = telnetlib.Telnet(host="10.10.88.110") connection.read_until("Username:") connection.write("admin" + "\n") connection.read_until("Password:") connection.write("access123" + "\n") connection.read_until(">") connection.write("en" + "\n") connection.read_until("Password:") connection.write("access123" + "\n") connection.read_until("#") connection.write("terminal length 0" + "\n") connection.read_until("#") while True:
  command = raw_input("#:")
  if "health" in command.lower():
  commands = ["show ip int b",
  "show ip route",
  "show clock",
  "show banner motd"
  ]    elif "discover" in command.lower():
  commands = ["show arp",
  "show version | i uptime",
  "show inventory",   ]
  else:
  commands = [command]
  for cmd in commands:
  connection.write(cmd + "\n")
  output = connection.read_until("#")
  print output
        print "==================="  
```

首先，我们建立一个 telnet 连接到路由器，并输入用户访问详细信息，直到达到启用模式。然后，我们创建一个始终为`true`的无限`while`循环，并使用内置函数`raw_input()`来期望用户输入命令。当用户输入任何命令时，脚本将捕获它并直接执行到网络设备。

然而，如果用户输入了`health`或`discover`关键字，那么我们的终端将足够智能，以执行一系列命令来反映所需的操作。这在网络故障排除的情况下应该非常有用，您可以扩展它以进行任何日常操作。想象一下，您需要在两台路由器之间排除 OSPF 邻居关系问题。您只需要打开您自己的终端 Python 脚本，您已经教给它了一些用于故障排除所需的命令，并写入类似于`tshoot_ospf`的内容。一旦您的脚本看到这个魔术关键字，它将启动一系列多个命令，打印 OSPF 邻居关系状态、MTU 接口、在 OSPF 下广告的网络等，直到找到问题为止。

**脚本输出：**

通过在提示符中写入`health`来尝试我们脚本中的第一个命令：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00085.jpeg)

正如您所看到的，脚本返回了在设备中执行的多个命令的输出。

现在尝试第二个支持的命令，`discover`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00086.jpeg)

这次脚本返回了发现命令的输出。在后面的章节中，我们可以解析返回的输出并从中提取有用的信息。

# 从 Excel 表中读取数据

网络和 IT 工程师总是使用 Excel 表来存储有关基础设施的信息，如 IP 地址、设备供应商和凭据。Python 支持从 Excel 表中读取信息并处理它，以便您以后在脚本中使用。

在这个用例中，我们将使用**Excel Read**（**xlrd**）模块来读取包含我们基础设施的主机名、IP、用户名、密码、启用密码和供应商信息的`UC3_devices.xlsx`文件，并使用这些信息来提供`netmiko`模块。

Excel 表将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00087.jpeg)

首先，我们需要安装`xlrd`模块，使用`pip`，因为我们将使用它来读取 Microsoft Excel 表：

```py
pip install xlrd
```

XLRD 模块读取 Excel 工作簿并将行和列转换为矩阵。例如，如果您需要获取左侧的第一项，那么您将需要访问 row[0][0]。右侧的下一个项将是 row[0][1]，依此类推。

此外，当 xlrd 读取工作表时，它将通过每次读取一行来增加一个名为`nrows`（行数）的特殊计数器。类似地，它将通过每次读取列来增加`ncols`（列数），因此您可以通过这两个参数知道矩阵的大小：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00088.jpeg)

您可以使用`open_workbook()`函数提供`xlrd`的文件路径。然后，您可以通过使用`sheet_by_index()`或`sheet_by_name()`函数访问包含数据的工作表。对于我们的用例，我们的数据存储在第一个工作表（索引=0）中，并且文件路径存储在章节名称下。然后，我们将遍历工作表中的行，并使用`row()`函数访问特定行。返回的输出是一个列表，我们可以使用索引访问其中的任何项。

Python 脚本：

```py
__author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   from netmiko import ConnectHandler
from netmiko.ssh_exception import AuthenticationException, NetMikoTimeoutException
import xlrd
from pprint import pprint

workbook = xlrd.open_workbook(r"/media/bassim/DATA/GoogleDrive/Packt/EnterpriseAutomationProject/Chapter4_Using_Python_to_manage_network_devices/UC3_devices.xlsx")   sheet = workbook.sheet_by_index(0)   for index in range(1, sheet.nrows):
  hostname = sheet.row(index)[0].value
    ipaddr = sheet.row(index)[1].value
    username = sheet.row(index)[2].value
    password = sheet.row(index)[3].value
    enable_password = sheet.row(index)[4].value
    vendor = sheet.row(index)[5].value

    device = {
  'device_type': vendor,
  'ip': ipaddr,
  'username': username,
  'password': password,
  'secret': enable_password,    }
  # pprint(device)    print "########## Connecting to Device {0} ############".format(device['ip'])
  try:
  net_connect = ConnectHandler(**device)
  net_connect.enable()    print "***** show ip configuration of Device *****"
  output = net_connect.send_command("show ip int b")
  print output

        net_connect.disconnect()    except NetMikoTimeoutException:
  print "=======SOMETHING WRONG HAPPEN WITH {0}=======".format(device['ip'])    except AuthenticationException:
  print "=======Authentication Failed with {0}=======".format(device['ip'])   
```

```py
  except Exception as unknown_error:
  print "=======SOMETHING UNKNOWN HAPPEN WITH {0}======="   
```

# 更多用例

Netmiko 可以用于实现许多网络自动化用例。它可以用于在升级期间从远程设备上传、下载文件，从 Jinja2 模板加载配置，访问终端服务器，访问终端设备等等。您可以在[`github.com/ktbyers/pynet/tree/master/presentations/dfwcug/examples`](https://github.com/ktbyers/pynet/tree/master/presentations/dfwcug/examples)找到一些有用的用例列表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00089.jpeg)

# 摘要

在本章中，我们开始了我们的 Python 网络自动化实践之旅。我们探索了 Python 中可用的不同工具，以建立与 telnet 和 SSH 远程节点的连接，并在其上执行命令。此外，我们学习了如何使用`netaddr`模块处理 IP 地址和网络子网。最后，我们通过两个实际用例加强了我们的知识。

在下一章中，我们将处理返回的输出并开始从中提取有用的信息。


# 第五章：从网络设备中提取有用数据

在上一章中，我们已经看到了如何使用不同的方法和协议访问网络设备，然后在远程设备上执行命令，将输出返回到 Python。现在，是时候从这个输出中提取一些有用的数据了。

在本章中，您将学习如何使用 Python 中的不同工具和库从返回的输出中提取有用的数据，并使用正则表达式对其进行操作。此外，我们将使用一个名为`CiscoConfParse`的特殊库来审计配置，然后学习如何使用`matplotlib`库可视化数据，生成视觉上吸引人的图形和报告。

在本章中，我们将涵盖以下主题：

+   理解解析器

+   正则表达式简介

+   使用`Ciscoconfparse`进行配置审计

+   使用`matplotlib`可视化返回的数据

# 技术要求

您的环境中应安装并可用以下工具：

+   Python 2.7.1x

+   PyCharm 社区版或专业版

+   EVE-NG 实验室

您可以在以下 GitHub URL 找到本章开发的完整脚本：

[`github.com/TheNetworker/EnterpriseAutomation.git`](https://github.com/TheNetworker/EnterpriseAutomation.git)

# 理解解析器

在上一章中，我们探讨了访问网络设备、执行命令并将输出返回到终端的不同方式。现在我们需要处理返回的输出，并从中提取一些有用的信息。请注意，从 Python 的角度来看，输出只是一个多行字符串，Python 不区分 IP 地址、接口名称或节点主机名，因为它们都是字符串。因此，第一步是设计和开发我们自己的解析器，使用 Python 根据返回的输出中的重要信息对项目进行分类和区分。

之后，您可以处理解析后的数据，并生成有助于可视化的图形，甚至将它们存储到持久的外部存储或数据库中。

# 正则表达式简介

正则表达式是一种语言，用于通过跟随整个字符串的模式来匹配特定的字符串出现。当找到匹配时，将返回匹配的字符串，并将其保存在 Python 格式的结构中，如`tuple`、`list`或`dictionary`。以下表总结了正则表达式中最常见的模式：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00090.jpeg)

此外，正则表达式中的一个重要规则是您可以编写自己的正则表达式，并用括号`()`括起来，这称为捕获组，它可以帮助您保存重要数据，以便稍后使用捕获组编号引用它：

```py
line = '30 acd3.b2c6.aac9 FastEthernet0/1' 
match = re.search('(\d+) +([0-9a-f.]+) +(\S+)', line)
print match.group(1)
print match.group(2)
```

PyCharm 将自动对写成正则表达式的字符串进行着色，并可以帮助您在将其应用于数据之前检查正则表达式的有效性。请确保在设置中启用了 Check RegExp 意图，如下所示：![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00091.jpeg)

# 在 Python 中创建正则表达式

您可以使用 Python 中的`re`模块构建正则表达式，该模块已经与 Python 安装一起原生地提供。该模块内部有几种方法，如`search()`、`sub()`、`split()`、`compile()`和`findall()`，它们将以正则表达式对象的形式返回结果。以下是每个函数的用法总结：

| **函数名称** | **用法** |
| --- | --- |
| `search()` | 搜索和匹配模式的第一个出现。 |
| `findall()` | 搜索和匹配模式的所有出现，并将结果作为列表返回。 |
| `Finditer()` | 搜索和匹配模式的所有出现，并将结果作为迭代器返回。 |
| `compile()` | 将正则表达式编译为具有各种操作方法的模式对象，例如搜索模式匹配或执行字符串替换。如果您在脚本中多次使用相同的正则表达式模式，这将非常有用。 |
| `sub()` | 用于用另一个字符串替换匹配的模式。 |
| `split()` | 用于在匹配模式上拆分并创建列表。 |

正则表达式很难阅读；因此，让我们从简单的开始，看一些最基本级别的简单正则表达式。

使用`re`模块的第一步是在 Python 代码中导入它

```py
import re
```

我们将开始探索`re`模块中最常见的函数，即`search()`，然后我们将探索`findall()`。当您需要在字符串中找到一个匹配项，或者当您编写正则表达式模式来匹配整个输出并需要使用`groups()`方法来获取结果时，`search()`函数是合适的，正如我们将在接下来的例子中看到的。

`re.search()`函数的语法如下：

```py
match = re.search('regex pattern', 'string')
```

第一个参数`'regex pattern'`是为了匹配`'string'`中的特定出现而开发的正则表达式。当找到匹配项时，`search()`函数将返回一个特殊的匹配对象，否则将返回`None`。请注意，`search()`将仅返回模式的第一个匹配项，并将忽略其余的匹配项。让我们看一些在 Python 中使用`re`模块的例子：

**示例 1：搜索特定 IP 地址**

```py
import re
intf_ip = 'Gi0/0/0.911            10.200.101.242   YES NVRAM  up                    up' match = re.search('10.200.101.242', intf_ip)    if match:
  print match.group()
```

在这个例子中，我们可以看到以下内容：

+   `re`模块被导入到我们的 Python 脚本中。

+   我们有一个字符串，对应于接口详细信息，并包含名称、IP 地址和状态。这个字符串可以在脚本中硬编码，也可以使用 Netmiko 库从网络设备中生成。

+   我们将这个字符串传递给`search()`函数，以及我们的正则表达式，即 IP 地址。

+   然后，脚本检查前一个操作是否返回了`match`对象；如果是，则会打印出来。

测试匹配的最基本方法是通过`re.match`函数，就像我们在前面的例子中所做的那样。`match`函数接受一个正则表达式模式和一个字符串值。

请注意，我们只在`intf_ip`参数内搜索特定的字符串，而不是每个 IP 地址模式。

**示例 1 输出**

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00092.jpeg)

**示例 2：匹配 IP 地址模式**

```py
import re
intf_ip = '''Gi0/0/0.705            10.103.17.5      YES NVRAM  up                    up Gi0/0/0.900            86.121.75.31  YES NVRAM  up                    up Gi0/0/0.911            10.200.101.242   YES NVRAM  up                    up Gi0/0/0.7000           unassigned      YES unset  up                    up ''' match = re.search("\d+\.\d+\.\d+\.\d+", intf_ip)   if match:
  print match.group()
```

在这个例子中，我们可以看到以下内容：

+   `re`模块被导入到我们的 Python 脚本中。

+   我们有一个多行字符串，对应于接口详细信息，并包含名称、IP 地址和状态。

+   我们将这个字符串传递给`search()`函数，以及我们的正则表达式，即使用`\d+`匹配一个或多个数字，以及`\.`匹配点的出现。

+   然后，脚本检查前一个操作是否返回了`match`对象；如果是，则会打印出来。否则，将返回`None`对象。

**示例 2 输出**

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00093.jpeg)

请注意，`search()`函数只返回模式的第一个匹配项，而不是所有匹配项。

**示例 3：使用** **groups()正则表达式**

如果您有一个长输出，并且需要从中提取多个字符串，那么您可以用`()`括起提取的值，并在其中编写您的正则表达式。这称为**捕获组**，用于捕获长字符串中的特定模式，如下面的代码片段所示：

```py
import re
log_msg = 'Dec 20 12:11:47.417: %LINK-3-UPDOWN: Interface GigabitEthernet0/0/4, changed state to down' match = re.search("(\w+\s\d+\s\S+):\s(\S+): Interface (\S+), changed state to (\S+)", log_msg) if match:
  print match.groups() 
```

在这个例子中，我们可以看到以下内容：

+   `re`模块被导入到我们的 Python 脚本中。

+   我们有一个字符串，对应于路由器中发生的事件，并存储在日志中。

+   我们将这个字符串传递给`search()`函数，以及我们的正则表达式。请注意，我们将时间戳、事件类型、接口名称和捕获组的新状态都括起来，并在其中编写我们的正则表达式。

+   然后，脚本检查前一个操作是否返回了匹配对象；如果是，则会打印出来，但这次我们使用了`groups()`而不是`group()`，因为我们正在捕获多个字符串。

**示例 3 输出**

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00094.jpeg)

请注意，返回的数据是一个名为**tuple**的结构化格式。我们可以稍后使用此输出来触发事件，并且例如在冗余接口上启动恢复过程。

我们可以增强我们之前的代码，并使用`Named`组来为每个捕获组命名，以便稍后引用或用于创建字典。在这种情况下，我们在正则表达式前面加上了`?P<"NAME">`，就像下一个示例（GitHub 存储库中的**示例 4**）中一样：**示例 4：命名组**![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00095.jpeg)

**示例 5-1：使用 re.search()搜索多行**

假设我们的输出中有多行，并且我们需要针对正则表达式模式检查所有这些行。请记住，`search()`函数在找到第一个模式匹配时退出。在这种情况下，我们有两种解决方案。第一种是通过在`"\n"`上拆分整个字符串将每行输入到搜索函数中，第二种解决方案是使用`findall()`函数。让我们探讨这两种解决方案：

```py

import re

show_ip_int_br_full = """ GigabitEthernet0/0/0        110.110.110.1   YES NVRAM  up                    up GigabitEthernet0/0/1        107.107.107.1   YES NVRAM  up                    up GigabitEthernet0/0/2        108.108.108.1   YES NVRAM  up                    up GigabitEthernet0/0/3        109.109.109.1   YES NVRAM  up                    up GigabitEthernet0/0/4   unassigned      YES NVRAM  up                    up GigabitEthernet0/0/5             10.131.71.1     YES NVRAM  up                    up GigabitEthernet0/0/6          10.37.102.225   YES NVRAM  up                    up GigabitEthernet0/1/0            unassigned      YES unset  up                    up GigabitEthernet0/1/1           57.234.66.28   YES manual up                    up GigabitEthernet0/1/2           10.10.99.70   YES manual up                    up GigabitEthernet0/1/3           unassigned      YES manual deleted               down GigabitEthernet0/1/4           192.168.200.1   YES manual up                    up GigabitEthernet0/1/5   unassigned      YES manual down                  down GigabitEthernet0/1/6         10.20.20.1      YES manual down                  down GigabitEthernet0/2/0         10.30.40.1      YES manual down                  down GigabitEthernet0/2/1         57.20.20.1      YES manual down                  down  """ for line in show_ip_int_br_full.split("\n"):
  match = re.search(r"(?P<interface>\w+\d\/\d\/\d)\s+(?P<ip>\d+.\d+.\d+.\d+)", line)
  if match:
  intf_ip = match.groupdict()
  if intf_ip["ip"].startswith("57"):
  print "Subnet is configured on " + intf_ip["interface"] + " and ip is " + intf_ip["ip"]
```

上面的脚本将拆分`show ip interface brief`输出并搜索特定模式，即接口名称和配置在其上的 IP 地址。根据匹配的数据，脚本将继续检查每个 IP 地址并使用`start with 57`进行验证，然后脚本将打印相应的接口和完整的 IP 地址。

**示例 5-1 输出**

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00096.jpeg)如果您只搜索第一次出现，可以优化脚本，并且只需在找到第一个匹配项时中断外部`for`循环，但请注意，第二个匹配项将无法找到或打印。

**示例 5-2：使用 re.findall()搜索多行**

`findall()`函数在提供的字符串中搜索所有不重叠的匹配项，并返回与正则表达式模式匹配的字符串列表（与`search`函数不同，后者返回`match`对象），如果没有捕获组，则返回。如果您用捕获组括起您的正则表达式，那么`findall()`将返回一个元组列表。在下面的脚本中，我们有相同的多行输出，并且我们将使用`findall()`方法来获取所有配置了以 57 开头的 IP 地址的接口：

```py
import re
from pprint import pprint
show_ip_int_br_full = """ GigabitEthernet0/0/0        110.110.110.1   YES NVRAM  up                    up GigabitEthernet0/0/1        107.107.107.1   YES NVRAM  up                    up GigabitEthernet0/0/2        108.108.108.1   YES NVRAM  up                    up GigabitEthernet0/0/3        109.109.109.1   YES NVRAM  up                    up GigabitEthernet0/0/4   unassigned      YES NVRAM  up                    up GigabitEthernet0/0/5             10.131.71.1     YES NVRAM  up                    up GigabitEthernet0/0/6          10.37.102.225   YES NVRAM  up                    up GigabitEthernet0/1/0            unassigned      YES unset  up                    up GigabitEthernet0/1/1           57.234.66.28   YES manual up                    up GigabitEthernet0/1/2           10.10.99.70   YES manual up                    up GigabitEthernet0/1/3           unassigned      YES manual deleted               down GigabitEthernet0/1/4           192.168.200.1   YES manual up                    up GigabitEthernet0/1/5   unassigned      YES manual down                  down GigabitEthernet0/1/6         10.20.20.1      YES manual down                  down GigabitEthernet0/2/0         10.30.40.1      YES manual down                  down GigabitEthernet0/2/1         57.20.20.1      YES manual down                  down """    intf_ip = re.findall(r"(?P<interface>\w+\d\/\d\/\d)\s+(?P<ip>57.\d+.\d+.\d+)", show_ip_int_br_full) pprint(intf_ip) 
```

**示例 5-2 输出**：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00097.jpeg)

请注意，这一次我们不必编写`for`循环来检查每行是否符合正则表达式模式。这将在`findall()`方法中自动完成。

# 使用 CiscoConfParse 进行配置审计

在网络配置上应用正则表达式以从输出中获取特定信息需要我们编写一些复杂的表达式来解决一些复杂的用例。在某些情况下，您只需要检索一些配置或修改现有配置而不深入编写正则表达式，这就是`CiscoConfParse`库诞生的原因（[`github.com/mpenning/ciscoconfparse`](https://github.com/mpenning/ciscoconfparse)）。

# CiscoConfParse 库

正如官方 GitHub 页面所说，该库检查了一个类似 iOS 风格的配置，并将其分解成一组链接的父/子关系。您可以对这些关系执行复杂的查询：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00098.jpeg)来源：[`github.com/mpenning/ciscoconfparse`](https://github.com/mpenning/ciscoconfparse)

因此，配置的第一行被视为父级，而后续行被视为父级的子级。`CiscoConfparse`库将父级和子级之间的关系构建成一个对象，因此最终用户可以轻松地检索特定父级的配置，而无需编写复杂的表达式。

非常重要的是，您的配置文件格式良好，以便在父级和子级之间建立正确的关系。

如果需要向文件中注入配置，也适用相同的概念。该库将搜索给定的父级，并将配置插入其下方，并保存到新文件中。这在您需要对多个文件运行配置审计作业并确保它们都具有一致的配置时非常有用。

# 支持的供应商

作为一个经验法则，任何具有制表符分隔配置的文件都可以被`CiscoConfParse`解析，并且它将构建父子关系。

以下是支持的供应商列表：

+   Cisco IOS，Cisco Nexus，Cisco IOS-XR，Cisco IOS-XE，Aironet OS，Cisco ASA，Cisco CatOS

+   Arista EOS

+   Brocade

+   HP 交换机

+   Force10 交换机

+   Dell PowerConnect 交换机

+   Extreme Networks

+   Enterasys

+   ScreenOS

另外，从 1.2.4 版本开始，`CiscoConfParse`可以处理花括号分隔的配置，这意味着它可以处理以下供应商：

+   Juniper Network 的 Junos OS

+   Palo Alto Networks 防火墙配置

+   F5 Networks 配置

# CiscoConfParse 安装

`CiscoConfParse`可以通过在 Windows 命令行或 Linux shell 上使用`pip`来安装：

```py
pip install ciscoconfparse
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00099.jpeg)

请注意，还安装了一些其他依赖项，例如`ipaddr`，`dnsPython`和`colorama`，这些依赖项被`CiscoConfParse`使用。

# 使用 CiscoConfParse

我们将要处理的第一个示例是从名为`Cisco_Config.txt`的文件中提取关闭接口的示例 Cisco 配置。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00100.jpeg)

在这个例子中，我们可以看到以下内容：

+   从`CiscoConfParse`模块中，我们导入了`CiscoConfParse`类。同时，我们导入了`pprint`模块，以便以可读格式打印输出以适应 Python 控制台输出。

+   然后，我们将`config`文件的完整路径提供给`CiscoConfParse`类。

+   最后一步是使用内置函数之一，例如`find_parents_w_child()`，并提供两个参数。第一个是父级规范，它搜索以`interface`关键字开头的任何内容，而子规范具有`shutdown`关键字。

正如您所看到的，在三个简单的步骤中，我们能够获取所有具有关闭关键字的接口，并以结构化列表输出。

**示例 1 输出**

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00101.jpeg)

**示例 2：检查特定功能的存在**

第二个示例将检查配置文件中是否存在路由器关键字，以指示路由协议（例如`ospf`或`bgp`）是否已启用。如果模块找到它，则结果将为`True`。否则，将为`False`。这可以通过模块内的内置函数`has_line_with()`来实现：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00102.jpeg)

这种方法可以用于设计`if`语句内的条件，我们将在下一个和最后一个示例中看到。

**示例 2 输出**

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00103.jpeg)

**示例 3：从父级打印特定子项**：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00104.jpeg)

在这个例子中，我们可以看到以下内容：

+   从`CiscoConfParse`模块中，我们导入了`CiscoConfParse`类。同时，我们导入了`pprint`模块，以便以可读格式打印输出以适应 Python 控制台输出。

+   然后，我们将`config`文件的完整路径提供给`CiscoConfParse`类。

+   我们使用了一个内置函数，例如`find_all_children()`，并且只提供了父级。这将指示`CiscoConfParse`类列出此父级下的所有配置行。

+   最后，我们遍历返回的输出（记住，它是一个列表），并检查字符串中是否存在网络关键字。如果是，则将其附加到网络列表中，并在最后打印出来。

**示例 3 输出：**

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00105.jpeg)

`CiscoConfParse`模块中还有许多其他可用的函数，可用于轻松从配置文件中提取数据并以结构化格式返回输出。以下是其他函数的列表：

+   `find_lineage`

+   查找行()

+   查找所有子级()

+   查找块()

+   查找有子级的父级()

+   查找有父级的子级()

+   查找没有子级的父级()

+   查找没有父级的子级()

# 使用 matplotLib 可视化返回的数据

俗话说，“一图胜千言”。可以从网络中提取大量信息，如接口状态、接口计数器、路由器更新、丢包、流量量等。将这些数据可视化并放入图表中将帮助您看到网络的整体情况。Python 有一个名为**matplotlib**的优秀库（[`matplotlib.org/`](https://matplotlib.org/)），用于生成图表并对其进行自定义。

Matplotlib 能够创建大多数类型的图表，如折线图、散点图、条形图、饼图、堆叠图、3D 图和地理地图图表。

# Matplotlib 安装

我们将首先使用`pip`从 PYpI 安装库。请注意，除了 matplotlib 之外，还将安装一些其他包，如`numpy`和`six`：

```py
pip install matplotlib
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00106.jpeg)

现在，尝试导入`matplotlib`，如果没有打印错误，则成功导入模块：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00107.jpeg)

# Matplotlib 实践

我们将从简单的示例开始，以探索 matplotlib 的功能。我们通常做的第一件事是将`matplotlib`导入到我们的 Python 脚本中：

```py
import matplotlib.pyplot as plt
```

请注意，我们将`pyplot`导入为一个简短的名称`plt`，以便在我们的脚本中使用。现在，我们将在其中使用`plot()`方法来绘制我们的数据，其中包括两个列表。第一个列表表示*x*轴的值，而第二个列表表示*y*轴的值：

```py
plt.plot([0, 1, 2, 3, 4], [0, 10, 20, 30, 40])
```

现在，这些值被放入了图表中。

最后一步是使用`show()`方法将该图表显示为窗口：

```py
plt.show()
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00108.jpeg)在 Ubuntu 中，您可能需要安装`Python-tk`才能查看图表。使用`apt install Python-tk`。

生成的图表将显示代表 x 轴和 y 轴输入值的线。在窗口中，您可以执行以下操作：

+   使用十字图标移动图表

+   调整图表大小

+   使用缩放图标放大特定区域

+   使用主页图标重置到原始视图

+   使用保存图标保存图表

您可以通过为图表添加标题和两个轴的标签来自定义生成的图表。此外，如果图表上有多条线，还可以添加解释每条线含义的图例：

```py
import matplotlib.pyplot as plt
plt.plot([0, 1, 2, 3, 4], [0, 10, 20, 30, 40]) plt.xlabel("numbers") plt.ylabel("numbers multiplied by ten") plt.title("Generated Graph\nCheck it out") plt.show()
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00109.jpeg)请注意，我们通常不会在 Python 脚本中硬编码绘制的值，而是会从网络外部获取这些值，这将在下一个示例中看到。

此外，您可以在同一图表上绘制多个数据集。您可以添加另一个代表先前图表数据的列表，`matplotlib`将绘制它。此外，您可以添加标签以区分图表上的数据集。这些标签的图例将使用`legend()`函数打印在图表上：

```py
import matplotlib.pyplot as plt
plt.plot([0, 1, 2, 3, 4], [0, 10, 20, 30, 40], label="First Line")
plt.plot([5, 6, 7, 8, 9], [50, 60, 70, 80, 90], label="Second Line") plt.xlabel("numbers") plt.ylabel("numbers multiplied by ten") plt.title("Generated Graph\nCheck it out") plt.legend() plt.show()
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00110.jpeg)

# 使用 matplotlib 可视化 SNMP

在这个用例中，我们将利用`pysnmp`模块向路由器发送 SNMP `GET`请求，检索特定接口的输入和输出流量速率，并使用`matplotlib`库对输出进行可视化。使用的 OID 是`.1.3.6.1.4.1.9.2.2.1.1.6`和`.1.3.6.1.4.1.9.2.2.1.1.8`，分别表示输入和输出速率：

```py
from pysnmp.entity.rfc3413.oneliner import cmdgen
import time
import matplotlib.pyplot as plt    cmdGen = cmdgen.CommandGenerator()   snmp_community = cmdgen.CommunityData('public') snmp_ip = cmdgen.UdpTransportTarget(('10.10.88.110', 161)) snmp_oids = [".1.3.6.1.4.1.9.2.2.1.1.6.3",".1.3.6.1.4.1.9.2.2.1.1.8.3"]   slots = 0 input_rates = [] output_rates = [] while slots <= 50:
  errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(snmp_community, snmp_ip, *snmp_oids)    input_rate = str(varBinds[0]).split("=")[1].strip()
  output_rate = str(varBinds[1]).split("=")[1].strip()    input_rates.append(input_rate)
  output_rates.append(output_rate)    time.sleep(6)
  slots = slots + 1
  print slots

time_range = range(0, slots)   print input_rates
print output_rates
# plt.figure() plt.plot(time_range, input_rates, label="input rate") plt.plot(time_range, output_rates, label="output rate") plt.xlabel("time slot") plt.ylabel("Traffic Measured in bps") plt.title("Interface gig0/0/2 Traffic") 
```

```py
plt.legend() plt.show()
```

在这个例子中，我们可以看到以下内容：

+   我们从`pysnmp`模块导入了`cmdgen`，用于为路由器创建 SNMP `GET`命令。我们还导入了`matplotlib`模块。

+   然后，我们使用`cmdgen`来定义 Python 和路由器之间的传输通道属性，并提供 SNMP 社区。

+   `pysnmp`将开始使用提供的 OID 发送 SNMP GET 请求，并将输出和错误（如果有）返回到`errorIndication`、`errorStatus`、`errorIndex`和`varBinds`。我们对`varBinds`感兴趣，因为它包含输入和输出流量速率的实际值。

+   注意，`varBinds` 的形式将是 `<oid> = <value>`，因此我们只提取了值，并将其添加到之前创建的相应列表中。

+   这个操作将在 6 秒的间隔内重复 100 次，以收集有用的数据。

+   最后，我们将收集到的数据提供给从 `matplotlib` 导入的 `plt`，并通过提供 `xlabel`、`ylabel`、标题和 `legends` 来自定义图表：

**脚本输出**：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00111.jpeg)

# 总结

在本章中，我们学习了如何在 Python 中使用不同的工具和技术从返回的输出中提取有用的数据并对其进行操作。此外，我们使用了一个名为 `CiscoConfParse` 的特殊库来审计配置，并学习了如何可视化数据以生成吸引人的图表和报告。

在下一章中，我们将学习如何编写模板并使用它来使用 Jinja2 模板语言生成配置。


# 第六章：使用 Python 和 Jinja2 生成配置

本章介绍了 YAML 格式，用于表示数据并从 Jinja2 语言创建的黄金模板生成配置。我们将在 Ansible 和 Python 中使用这两个概念来创建我们配置的数据模型存储。

在本章中，我们将涵盖以下主题：

+   什么是 YAML？

+   使用 Jinja2 构建黄金配置模板

# 什么是 YAML？

**YAML Ain’t Markup Language**（**YAML**）通常被称为数据序列化语言。它旨在是人类可读的，并将数据组织成结构化格式。编程语言可以理解 YAML 文件的内容（通常具有`.yml`或`.yaml`扩展名），并将其映射到内置数据类型。例如，当您在 Python 脚本中使用`.yaml`文件时，它将自动将内容转换为字典`{}`或列表`[]`，因此您可以对其进行处理和迭代。

YAML 规则有助于构建可读文件，因此了解它们以编写有效和格式良好的 YAML 文件非常重要。

# YAML 文件格式

在开发 YAML 文件时需要遵循一些规则。YAML 使用缩进（类似于 Python），它建立了项目之间的关系：

1.  因此，编写 YAML 文件的第一个规则是使缩进保持一致，使用空格或制表符，并且不要混合使用它们。

1.  第二条规则是在创建具有键和值的字典时使用冒号`:`（有时称为`yaml`中的关联数组）。冒号左侧的项目是键，而冒号右侧的项目是值。

1.  第三条规则是在列表中使用破折号`"-"`来分组项目。您可以在 YAML 文件中混合使用字典和列表，以有效地描述您的数据。左侧作为字典键，右侧作为字典值。您可以创建任意数量的级别以获得结构化数据：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00112.jpeg)

让我们举个例子并应用这些规则：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00113.jpeg)

有很多事情要看。首先，文件有一个顶级，`my_datacenter`，它作为顶级键，其值由它之后的所有缩进行组成，即`GW`，`switch1`和`switch2`。这些项目也作为键，并在其中有值，即`eve_port`，`device_template`，`hostname`，`mgmt_int`，`mgmt_ip`和`mgmt_subnet`，它们同时作为第 3 级键和第 2 级值。

另一件事要注意的是`enabled_ports`，它是一个键，但具有作为列表的值。我们知道这一点，因为下一级缩进是一个破折号。

请注意，所有接口都是同级元素，因为它们具有相同级别的缩进。

最后，不需要在字符串周围使用单引号或双引号。当我们将文件加载到 Python 中时，Python 会自动执行这些操作，并且还将根据缩进确定每个项目的数据类型和位置。

现在，让我们开发一个 Python 脚本，读取这个 YAML 文件，并使用`yaml`模块将其转换为字典和列表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00114.jpeg)

在这个例子中，我们可以看到以下内容：

+   我们在 Python 脚本中导入了`yaml`模块，以处理 YAML 文件。此外，我们导入了`pprint`函数，以显示嵌套字典和列表的层次结构。

+   然后，我们使用`with`子句和`open（）`函数打开了`yaml_example.yml`文件作为`yaml_file`。

+   最后，我们使用`load（）`函数将文件加载到`yaml_data`变量中。在这个阶段，Python 解释器将分析`yaml`文件的内容并建立项目之间的关系，然后将它们转换为标准数据类型。输出可以使用`pprint（）`函数在控制台上显示。

**脚本输出**

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00115.jpeg)

现在，使用标准 Python 方法访问任何信息都相当容易。例如，您可以通过使用`my_datacenter`后跟`switch1`键来访问`switch1`配置，如以下代码片段所示：

```py
pprint(yaml_data['my_datacenter']['switch1'])

{'device_template': 'vIOSL2_Template',
 'eve_port': 32769,
 'hostname': 'SW1',
 'mgmt_intf': 'gig0/0',
 'mgmt_ip': '10.10.88.111',
 'mgmt_subnet': '255.255.255.0'}    
```

此外，您可以使用简单的`for`循环迭代键，并打印任何级别的值：

```py
for device in yaml_data['my_datacenter']:
    print device

GW
switch2
switch1
```

作为最佳实践，建议您保持键名一致，仅在描述数据时更改值。例如，`hostname`，`mgmt_intf`和`mgmt_ip`项目在所有具有相同名称的设备上都存在，而它们在`.yaml`文件中的值不同。

# 文本编辑器提示

正确的缩进对于 YAML 数据非常重要。建议使用高级文本编辑器，如 Sublime Text 或 Notepad++，因为它们具有将制表符转换为特定数量的空格的选项。同时，您可以选择特定的制表符缩进大小为 2 或 4。因此，每当您点击*Tab*按钮时，您的编辑器将将制表符转换为静态数量的空格。最后，您可以选择在每个缩进处显示垂直线，以确保行缩进相同。

请注意，Microsoft Windows Notepad 没有此选项，这可能会导致 YAML 文件的格式错误。

以下是一个名为 Sublime Text 的高级编辑器的示例，可以配置为使用上述选项：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00116.jpeg)

屏幕截图显示了垂直线指南，确保当您点击 Tab 时，兄弟项目处于相同的缩进级别和空格数。

# 使用 Jinja2 构建黄金配置

大多数网络工程师都有一个文本文件，用作特定设备配置的模板。该文件包含许多值的网络配置部分。当网络工程师想要配置新设备或更改其配置时，他们基本上会用另一个文件中的特定值替换此文件中的特定值，以生成新的配置。

在本书的后面，我们将使用 Python 和 Ansible，使用 Jinja2 模板语言([`jinja.pocoo.org`](http://jinja.pocoo.org))高效地自动化此过程。 Jinja2 开发的核心概念和驱动程序是在特定网络/系统配置的所有模板文件中具有统一的语法，并将数据与实际配置分离。这使我们能够多次使用相同的模板，但使用不同的数据集。此外，正如 Jinja2 网页所示，它具有一些独特的功能，使其脱颖而出，与其他模板语言不同。

以下是官方网站上提到的一些功能：

+   强大的自动 HTML 转义系统，用于跨站点脚本预防。

+   高性能，使用即时编译到 Python 字节码。Jinja2 将在首次加载时将您的模板源代码转换为 Python 字节码，以获得最佳的运行时性能。

+   可选的提前编译。

+   易于调试，具有将模板编译和运行时错误集成到标准 Python 回溯系统的调试系统。

+   可配置的语法：例如，您可以重新配置 Jinja2 以更好地适应输出格式，例如 LaTeX 或 JavaScript。

+   模板设计帮助程序：Jinja2 附带了一系列有用的小助手，可帮助解决模板中的常见任务，例如将项目序列分成多列。

另一个重要的 Jinja 功能是*模板继承*，我们可以创建一个*基础/父模板*，为我们的系统或所有设备的 Day 0 初始配置定义基本结构。此初始配置将是基本配置，并包含通用部分，例如用户名、管理子网、默认路由和 SNMP 社区。其他*子模板*扩展基础模板并继承它。

在本章中，术语 Jinja 和 Jinja2 可以互换使用。

在我们深入研究 Jinja2 语言提供的更多功能之前，让我们先来看几个构建模板的例子：

1.  首先，我们需要确保 Jinja2 已经安装在您的系统中，使用以下命令：

```py
pip install jinja2 
```

该软件包将从 PyPi 下载，然后将安装在站点软件包中。

1.  现在，打开你喜欢的文本编辑器，并编写以下模板，它代表了一个简单的 Day 0（初始）配置，用于配置设备主机名、一些`aaa`参数、每个交换机上应存在的默认 VLAN 以及 IP 地址的管理：

```py
hostname {{ hostname }}

aaa new-model aaa session-id unique aaa authentication login default local aaa authorization exec default local none vtp mode transparent vlan 10,20,30,40,50,60,70,80,90,100,200   int {{ mgmt_intf }}
no switchport no shut ip address {{ mgmt_ip }} {{ mgmt_subnet }}
```

一些文本编辑器（如 Sublime Text 和 Notepad++）支持 Jinja2，并可以为您提供语法高亮和自动补全，无论是通过本地支持还是通过扩展。

请注意，在上一个模板中，变量是用双大括号`{{  }}`写的。因此，当 Python 脚本加载模板时，它将用所需的值替换这些变量：

```py
#!/usr/bin/python   from jinja2 import Template
template = Template(''' hostname {{hostname}}   aaa new-model aaa session-id unique aaa authentication login default local aaa authorization exec default local none vtp mode transparent vlan 10,20,30,40,50,60,70,80,90,100,200   int {{mgmt_intf}}
 no switchport no shut ip address {{mgmt_ip}} {{mgmt_subnet}} ''')   sw1 = {'hostname': 'switch1', 'mgmt_intf': 'gig0/0', 'mgmt_ip': '10.10.88.111', 'mgmt_subnet': '255.255.255.0'} print(template.render(sw1))
```

在这个例子中，我们可以看到以下内容：

+   首先，我们导入了`jinja2`模块中的`Template`类。这个类将验证和解析 Jinja2 文件。

+   然后，我们定义了一个变量`sw1`，它是一个带有与模板内变量名称相等的键的字典。字典值将是渲染模板的数据。

+   最后，我们在模板中使用了`render()`方法，该方法以`sw1`作为输入，将 Jinja2 模板与渲染值连接起来，并打印配置。

**脚本输出**

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00117.jpeg)

现在，让我们改进我们的脚本，使用 YAML 来渲染模板，而不是在字典中硬编码值。这个概念很简单：我们将在 YAML 文件中建模我们实验室的`day0`配置，然后使用`yaml.load()`将该文件加载到我们的 Python 脚本中，并使用输出来填充 Jinja2 模板，从而生成每个设备的`day0`配置文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00118.jpeg)

首先，我们将扩展上次开发的 YAML 文件，并在保持每个节点层次结构不变的情况下，向其中添加其他设备：

```py
--- dc1:
 GW: eve_port: 32773
  device_template: vIOSL3_Template
  hostname: R1
  mgmt_intf: gig0/0
  mgmt_ip: 10.10.88.110
  mgmt_subnet: 255.255.255.0      switch1:
 eve_port: 32769
  device_template: vIOSL2_Template
  hostname: SW1
  mgmt_intf: gig0/0
  mgmt_ip: 10.10.88.111
  mgmt_subnet: 255.255.255.0    switch2:
 eve_port: 32770
  device_template: vIOSL2_Template
  hostname: SW2
  mgmt_intf: gig0/0
  mgmt_ip: 10.10.88.112
  mgmt_subnet: 255.255.255.0    switch3:
 eve_port: 32769
  device_template: vIOSL2_Template
  hostname: SW3
  mgmt_intf: gig0/0
  mgmt_ip: 10.10.88.113
  mgmt_subnet: 255.255.255.0    switch4:
 eve_port: 32770
  device_template: vIOSL2_Template
  hostname: SW4
  mgmt_intf: gig0/0
  mgmt_ip: 10.10.88.114
  mgmt_subnet: 255.255.255.0 
```

**以下是 Python 脚本：**

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   import yaml
from jinja2 import Template

with open('/media/bassim/DATA/GoogleDrive/Packt/EnterpriseAutomationProject/Chapter6_Configuration_generator_with_python_and_jinja2/network_dc.yml', 'r') as yaml_file:
  yaml_data = yaml.load(yaml_file)   router_day0_template = Template(""" hostname {{hostname}} int {{mgmt_intf}}
 no shutdown ip add {{mgmt_ip}} {{mgmt_subnet}}   lldp run   ip domain-name EnterpriseAutomation.net ip ssh version 2 ip scp server enable crypto key generate rsa general-keys modulus 1024   snmp-server community public RW snmp-server trap link ietf snmp-server enable traps snmp linkdown linkup snmp-server enable traps syslog snmp-server manager   logging history debugging logging snmp-trap emergencies logging snmp-trap alerts logging snmp-trap critical logging snmp-trap errors logging snmp-trap warnings logging snmp-trap notifications logging snmp-trap informational logging snmp-trap debugging   """)     switch_day0_template = Template(""" hostname {{hostname}}   aaa new-model aaa session-id unique aaa authentication login default local aaa authorization exec default local none vtp mode transparent vlan 10,20,30,40,50,60,70,80,90,100,200   int {{mgmt_intf}}
 no switchport no shut ip address {{mgmt_ip}} {{mgmt_subnet}}   snmp-server community public RW snmp-server trap link ietf snmp-server enable traps snmp linkdown linkup snmp-server enable traps syslog snmp-server manager   logging history debugging logging snmp-trap emergencies logging snmp-trap alerts logging snmp-trap critical logging snmp-trap errors logging snmp-trap warnings logging snmp-trap notifications logging snmp-trap informational logging snmp-trap debugging   """)   for device,config in yaml_data['dc1'].iteritems():
  if config['device_template'] == "vIOSL2_Template":
  device_template = switch_day0_template
    elif config['device_template'] == "vIOSL3_Template":
  device_template = router_day0_template

    print("rendering now device {0}" .format(device))
  Day0_device_config = device_template.render(config)    print Day0_device_config
    print "=" * 30 
```

在这个例子中，我们可以看到以下内容：

+   我们像往常一样导入了`yaml`和`Jinja2`模块

+   然后，我们指示脚本将`yaml`文件加载到`yaml_data`变量中，这将把它转换为一系列字典和列表

+   分别定义了路由器和交换机配置的两个模板，分别为`router_day0_template`和`switch_day0_template`

+   `for`循环将遍历`dc1`的设备，并检查`device_template`，然后为每个设备渲染配置

**脚本输出**

以下是路由器配置（输出已省略）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00119.jpeg)

以下是交换机 1 的配置（输出已省略）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00120.jpeg)

# 从文件系统中读取模板

Python 开发人员的一种常见方法是将静态的、硬编码的值和模板移出 Python 脚本，只保留脚本内的逻辑。这种方法可以使您的程序更加清晰和可扩展，同时允许其他团队成员通过更改输入来获得期望的输出，而对 Python 了解不多的人也可以使用这种方法。Jinja2 也不例外。您可以使用 Jinja2 模块中的`FileSystemLoader()`类从操作系统目录中加载模板。我们将修改我们的代码，将`router_day0_template`和`switch_day0_template`的内容从脚本中移到文本文件中，然后将它们加载到我们的脚本中。

**Python 代码**

```py
import yaml
from jinja2 import FileSystemLoader, Environment

with open('/media/bassim/DATA/GoogleDrive/Packt/EnterpriseAutomationProject/Chapter6_Configuration_generator_with_python_and_jinja2/network_dc.yml', 'r') as yaml_file:
  yaml_data = yaml.load(yaml_file)     template_dir = "/media/bassim/DATA/GoogleDrive/Packt/EnterpriseAutomationProject/Chapter6_Configuration_generator_with_python_and_jinja2"   template_env = Environment(loader=FileSystemLoader(template_dir),
  trim_blocks=True,
  lstrip_blocks= True
  )     for device,config in yaml_data['dc1'].iteritems():
  if config['device_template'] == "vIOSL2_Template":
  device_template = template_env.get_template("switch_day1_template.j2")
  elif config['device_template'] == "vIOSL3_Template":
  device_template = template_env.get_template("router_day1_template.j2")    print("rendering now device {0}" .format(device))
  Day0_device_config = device_template.render(config)    print Day0_device_config
    print "=" * 30 
```

在这个例子中，我们不再像之前那样从 Jinja2 模块中加载`Template()`类，而是导入`Environment()`和`FileSystemLoader()`，它们用于通过提供`template_dir`从特定操作系统目录中读取 Jinja2 文件，其中存储了我们的模板。然后，我们将使用创建的`template_env`对象，以及`get_template()`方法，获取模板名称并使用配置渲染它。

确保您的模板文件以`.j2`扩展名结尾。这将使 PyCharm 将文件中的文本识别为 Jinja2 模板，从而提供语法高亮和更好的代码完成。

# 使用 Jinja2 循环和条件

Jinja2 中的循环和条件用于增强我们的模板并为其添加更多功能。我们将首先了解如何在模板中添加`for`循环，以便迭代从 YAML 传递的值。例如，我们可能需要在每个接口下添加交换机配置，比如使用交换机端口模式并配置 VLAN ID，这将在访问端口下配置，或者在干线端口的情况下配置允许的 VLAN 范围。

另一方面，我们可能需要在路由器上启用一些接口并为其添加自定义配置，比如 MTU、速度和双工。因此，我们将使用`for`循环。

请注意，我们的脚本逻辑的一部分现在将从 Python 移动到 Jinja2 模板中。Python 脚本将只是从操作系统外部或通过脚本内部的`Template()`类读取模板，然后使用来自 YAML 文件的解析值渲染模板。

Jinja2 中`for`循环的基本结构如下：

```py
{% for key, value in var1.iteritems() %}
configuration snippets
{% endfor %}
```

请注意使用`{% %}`来定义 Jinja2 文件中的逻辑。

此外，`iteritems()`具有与迭代 Python 字典相同的功能，即迭代键和值对。循环将为`var1`字典中的每个元素返回键和值。

此外，我们可以有一个`if`条件来验证特定条件，如果条件为真，则配置片段将被添加到渲染文件中。基本的`if`结构如下所示：

```py
{% if enabled_ports %}
configuration snippet goes here and added to template if the condition is true
{% endif %}
```

现在，我们将修改描述数据中心设备的`.yaml`文件，并为每个设备添加接口配置和已启用的端口：

```py
--- dc1:
 GW: eve_port: 32773
  device_template: vIOSL3_Template
  hostname: R1
  mgmt_intf: gig0/0
  mgmt_ip: 10.10.88.110
  mgmt_subnet: 255.255.255.0
  enabled_ports:
  - gig0/0
  - gig0/1
  - gig0/2    switch1:
 eve_port: 32769
  device_template: vIOSL2_Template
  hostname: SW1
  mgmt_intf: gig0/0
  mgmt_ip: 10.10.88.111
  mgmt_subnet: 255.255.255.0
  interfaces:
 gig0/1: vlan: [1,10,20,200]
  description: TO_DSW2_1
  mode: trunk   gig0/2:
 vlan: [1,10,20,200]
  description: TO_DSW2_2
  mode: trunk   gig0/3:
 vlan: [1,10,20,200]
  description: TO_ASW3
  mode: trunk   gig1/0:
 vlan: [1,10,20,200]
  description: TO_ASW4
  mode: trunk
  enabled_ports:
  - gig0/0
  - gig1/1    switch2:
 eve_port: 32770
  device_template: vIOSL2_Template
  hostname: SW2
  mgmt_intf: gig0/0
  mgmt_ip: 10.10.88.112
  mgmt_subnet: 255.255.255.0
  interfaces:
 gig0/1: vlan: [1,10,20,200]
  description: TO_DSW1_1
  mode: trunk   gig0/2:
 vlan: [1,10,20,200]
  description: TO_DSW1_2
  mode: trunk
  gig0/3:
 vlan: [1,10,20,200]
  description: TO_ASW3
  mode: trunk   gig1/0:
 vlan: [1,10,20,200]
  description: TO_ASW4
  mode: trunk
  enabled_ports:
  - gig0/0
  - gig1/1    switch3:
 eve_port: 32769
  device_template: vIOSL2_Template
  hostname: SW3
  mgmt_intf: gig0/0
  mgmt_ip: 10.10.88.113
  mgmt_subnet: 255.255.255.0
  interfaces:
 gig0/1: vlan: [1,10,20,200]
  description: TO_DSW1
  mode: trunk   gig0/2:
 vlan: [1,10,20,200]
  description: TO_DSW2
  mode: trunk   gig1/0:
 vlan: 10
  description: TO_Client1
  mode: access   gig1/1:
 vlan: 20
  description: TO_Client2
  mode: access
  enabled_ports:
  - gig0/0    switch4:
 eve_port: 32770
  device_template: vIOSL2_Template
  hostname: SW4
  mgmt_intf: gig0/0
  mgmt_ip: 10.10.88.114
  mgmt_subnet: 255.255.255.0
  interfaces:
 gig0/1: vlan: [1,10,20,200]
  description: TO_DSW2
  mode: trunk   gig0/2:
 vlan: [1,10,20,200]
  description: TO_DSW1
  mode: trunk   gig1/0:
 vlan: 10
  description: TO_Client1
  mode: access   gig1/1:
 vlan: 20
  description: TO_Client2
  mode: access
  enabled_ports:
  - gig0/0
```

请注意，我们将交换机端口分类为干线端口或访问端口，并为每个端口添加 VLAN。

根据`yaml`文件，以交换机端口访问模式进入的数据包将被标记为 VLAN。在干线端口模式下，只有数据包的 VLAN ID 属于配置列表，才允许数据包进入。

现在，我们将为设备 Day 1（运行）配置创建两个额外的模板。第一个模板将是`router_day1_template`，第二个将是`switch_day1_template`，它们都将继承之前开发的相应 day0 模板：

**router_day1_template:**

```py
{% include 'router_day0_template.j2' %}   {% if enabled_ports %}
 {% for port in enabled_ports %} interface {{ port }}
    no switchport
 no shutdown mtu 1520 duplex auto speed auto  {% endfor %}   {% endif %}
```

**switch_day1_template:**

```py

{% include 'switch_day0_template.j2' %}   {% if enabled_ports %}
 {% for port in enabled_ports %} interface {{ port }}
    no switchport
 no shutdown mtu 1520 duplex auto speed auto    {% endfor %} {% endif %}   {% if interfaces %}
 {% for intf,intf_config in interfaces.items() %} interface {{ intf }}
 description "{{intf_config['description']}}"
 no shutdown duplex full  {% if intf_config['mode'] %}   {% if intf_config['mode'] == "access" %}
  switchport mode {{intf_config['mode']}}
 switchport access vlan {{intf_config['vlan']}}
   {% elif intf_config['mode'] == "trunk" %}
  switchport {{intf_config['mode']}} encapsulation dot1q
 switchport mode trunk switchport trunk allowed vlan {{intf_config['vlan']|join(',')}}
   {% endif %}
 {% endif %}
 {% endfor %} {% endif %} 
```

请注意使用`{% include <template_name.j2> %}`标签，它指的是设备的 day0 模板。

此模板将首先被渲染并填充来自 YAML 的传递值，然后填充下一个部分。

Jinja2 语言继承了许多写作风格和特性，来自 Python 语言。虽然在开发模板和插入标签时不是强制遵循缩进规则，但作者更喜欢在可读的 Jinja2 模板中使用缩进。

**脚本输出:**

```py
rendering now device GW
hostname R1
int gig0/0
  no shutdown
  ip add 10.10.88.110 255.255.255.0
lldp run
ip domain-name EnterpriseAutomation.net
ip ssh version 2
ip scp server enable
crypto key generate rsa general-keys modulus 1024
snmp-server community public RW
snmp-server trap link ietf
snmp-server enable traps snmp linkdown linkup
snmp-server enable traps syslog
snmp-server manager
logging history debugging
logging snmp-trap emergencies
logging snmp-trap alerts
logging snmp-trap critical
logging snmp-trap errors
logging snmp-trap warnings
logging snmp-trap notifications
logging snmp-trap informational
logging snmp-trap debugging
interface gig0/0
    no switchport
    no shutdown
    mtu 1520
    duplex auto
    speed auto
interface gig0/1
    no switchport
    no shutdown
    mtu 1520
    duplex auto
    speed auto
interface gig0/2
    no switchport
    no shutdown
    mtu 1520
    duplex auto
    speed auto
==============================
rendering now device switch1
hostname SW1
aaa new-model
aaa session-id unique
aaa authentication login default local
aaa authorization exec default local none
vtp mode transparent
vlan 10,20,30,40,50,60,70,80,90,100,200
int gig0/0
 no switchport
 no shut
 ip address 10.10.88.111 255.255.255.0
snmp-server community public RW
snmp-server trap link ietf
snmp-server enable traps snmp linkdown linkup
snmp-server enable traps syslog
snmp-server manager
logging history debugging
logging snmp-trap emergencies
logging snmp-trap alerts
logging snmp-trap critical
logging snmp-trap errors
logging snmp-trap warnings
logging snmp-trap notifications
logging snmp-trap informational
logging snmp-trap debugging
interface gig0/0
    no switchport
    no shutdown
    mtu 1520
    duplex auto
    speed auto
interface gig1/1
    no switchport
    no shutdown
    mtu 1520
    duplex auto
    speed auto
interface gig0/2
 description "TO_DSW2_2"
 no shutdown
 duplex full
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 1,10,20,200
interface gig0/3
 description "TO_ASW3"
 no shutdown
 duplex full
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 1,10,20,200
interface gig0/1
 description "TO_DSW2_1"
 no shutdown
 duplex full
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 1,10,20,200
interface gig1/0
 description "TO_ASW4"
 no shutdown
 duplex full
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 1,10,20,200
==============================

<switch2 output omitted>

==============================
rendering now device switch3
hostname SW3
aaa new-model
aaa session-id unique
aaa authentication login default local
aaa authorization exec default local none
vtp mode transparent
vlan 10,20,30,40,50,60,70,80,90,100,200
int gig0/0
 no switchport
 no shut
 ip address 10.10.88.113 255.255.255.0
snmp-server community public RW
snmp-server trap link ietf
snmp-server enable traps snmp linkdown linkup
snmp-server enable traps syslog
snmp-server manager
logging history debugging
logging snmp-trap emergencies
logging snmp-trap alerts
logging snmp-trap critical
logging snmp-trap errors
logging snmp-trap warnings
logging snmp-trap notifications
logging snmp-trap informational
logging snmp-trap debugging
interface gig0/0
    no switchport
    no shutdown
    mtu 1520
    duplex auto
    speed auto
interface gig0/2
 description "TO_DSW2"
 no shutdown
 duplex full
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 1,10,20,200
interface gig1/1
 description "TO_Client2"
 no shutdown
 duplex full
 switchport mode access
 switchport access vlan 20
interface gig1/0
 description "TO_Client1"
 no shutdown
 duplex full
 switchport mode access
 switchport access vlan 10
interface gig0/1
 description "TO_DSW1"
 no shutdown
 duplex full
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 1,10,20,200
==============================
<switch4 output omitted>
```

# 总结

在本章中，我们学习了 YAML 及其格式以及如何使用文本编辑器。我们还了解了 Jinja2 及其配置。然后，我们探讨了在 Jinja2 中使用循环和条件的方法。

在下一章中，我们将学习如何使用多进程同时实例化和执行 Python 代码。
