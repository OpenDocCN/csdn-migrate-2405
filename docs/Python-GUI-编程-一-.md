# Python GUI 编程（一）

> 原文：[`zh.annas-archive.org/md5/9d5f7126bd532a80dd6a9dce44175aaa`](https://zh.annas-archive.org/md5/9d5f7126bd532a80dd6a9dce44175aaa)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

响应式图形用户界面（GUI）帮助您与应用程序交互，提高用户体验，并增强应用程序的效率。使用 Python，您将可以访问精心设计的 GUI 框架，可以用来构建与众不同的交互式 GUI。

本学习路径首先介绍了 Tkinter 和 PyQt，然后引导您通过应用程序开发过程。随着您通过添加更多小部件扩展您的 GUI，您将使用增强其功能的网络、数据库和图形库。您还将学习如何连接到外部数据库和网络资源，测试您的代码，并使用异步编程来最大化性能。在后面的章节中，您将了解如何使用 Tkinter 和 Qt5 的跨平台功能来保持跨平台兼容性。您将能够模仿平台本地的外观和感觉，并构建可在流行的计算平台上部署的可执行文件。

在学习路径结束时，您将具备设计和构建高端 GUI 应用程序的技能和信心，可以解决现实世界中的问题。

本学习路径包括以下 Packt 产品的内容：

+   *Python GUI Programming with Tkinter* by Alan D. Moore

+   *Qt5 Python GUI Programming Cookbook* by B. M. Harwani

# 本书适合对象

如果您是一名中级 Python 程序员，希望通过使用 PyQT 和 Tkinter 在 Python 中编写强大的 GUI 来增强您的编码技能，那么这对您来说是一个理想的学习路径。对 Python 语言的深入理解是理解本书中解释的概念的必要条件。

# 本书涵盖的内容

*第一章*，*Tkinter 简介*，向您介绍了 Tkinter 库的基础知识，并带您创建一个 Hello World 应用程序。它还将向您介绍 IDLE 作为 Tkinter 应用程序的示例。

*第二章*，*使用 Tkinter 设计 GUI 应用程序*，介绍了将一组用户需求转化为我们可以实现的设计过程。

*第三章*，*使用 Tkinter 和 ttk 小部件创建基本表单*，向您展示如何创建一个基本的数据输入表单，将数据追加到 CSV 文件中。

*第四章*，*使用验证和自动化减少用户错误*，演示了如何自动填充和验证我们表单输入中的数据。

*第五章*，*规划我们应用程序的扩展*，让您了解如何将一个小脚本分解为多个文件，并构建一个可以导入的 Python 模块。它还包含一些关于如何管理更大代码库的一般建议。

*第六章*，*使用 Menu 和 Tkinter 对话框创建菜单*，概述了使用 Tkinter 创建主菜单。它还将展示使用几种内置对话框类型来实现常见菜单功能。

*第七章*，*使用 Treeview 导航记录*，详细介绍了使用 Tkinter Treeview 构建记录导航系统，并将我们的应用程序从仅追加转换为具有完整读取、写入和更新功能。

*第八章*，*使用样式和主题改善外观*，告诉您如何更改应用程序的颜色、字体和小部件样式，以及如何使用它们使您的应用程序更易用。

*第九章*，*使用 unittest 创建自动化测试*，讨论了如何使用自动化单元测试和集成测试来验证您的代码。

第十章《使用 SQL 改进数据存储》带您了解如何将我们的应用程序从 CSV 平面文件转换为 SQL 数据存储。您将学习有关 SQL 和关系数据模型的所有知识。

第十一章《连接到云》介绍了如何使用云服务，如 Web 服务和 FTP 来下载和上传数据。

第十二章《使用 Canvas 小部件可视化数据》教会您如何使用 Tkinter 的 Canvas 小部件来创建可视化和动画。

第十三章《使用 Qt 组件创建用户界面》教会您如何使用 Qt Designer 的某些基本小部件，以及如何显示欢迎消息和用户名。您将学会使用单选按钮从几个选项中选择一个选项，并通过复选框选择多个选项。

第十四章《事件处理-信号和槽》介绍了如何在任何小部件上发生特定事件时执行特定任务，以及如何从一个行编辑小部件复制和粘贴文本到另一个小部件，转换数据类型并制作一个小型计算器，以及使用微调框、滚动条和滑块。您还将学会使用列表小部件执行多个任务。

第十五章《理解面向对象编程概念》讨论了面向对象编程概念，如如何在 GUI 应用程序中使用类、单继承、多级继承和多重继承。

第十六章《理解对话框》探讨了使用特定对话框，每个对话框用于获取不同类型的信息。您还将学会使用输入对话框从用户那里获取输入。

第十七章《理解布局》解释了如何通过使用水平布局、垂直布局和不同布局来水平、垂直地排列小部件，以及如何使用表单布局在两列布局中排列小部件。

第十八章《网络和管理大型文档》演示了如何制作一个小型浏览器，建立客户端和服务器之间的连接，创建一个可停靠和可浮动的登录表单，并使用 MDI 管理多个文档。此外，您还将学会使用选项卡小部件在各个部分显示信息，以及如何创建一个自定义菜单栏，在选择特定菜单项时调用不同的图形工具。

第十九章《数据库处理》概述了如何管理 SQLite 数据库以保存未来使用的信息。利用所学知识，您将学会制作一个登录表单，检查用户的电子邮件地址和密码是否正确。

第二十章《使用图形》解释了如何在应用程序中显示特定的图形。您还将学习如何创建自己的工具栏，其中包含可用于绘制不同图形的特定工具。

第二十一章《实现动画》介绍了如何显示 2D 图形图像，使球在点击按钮时向下移动，制作一个弹跳的球，以及根据指定曲线使球动画化。

第二十二章《使用 Google 地图》展示了如何使用 Google API 显示位置和其他信息。您将学会根据输入的经度和纬度值计算两个位置之间的距离，并在 Google 地图上显示位置。

# 为了充分利用本书

本书期望您了解 Python 3 的基础知识。您应该知道如何使用内置类型和函数编写和运行简单脚本，如何定义自己的函数和类，以及如何从标准库导入模块。

您可以在 Windows、macOS、Linux 甚至 BSD 上使用本书。确保您已安装 Python 3 和 Tcl/Tk，并且有一个您熟悉的编辑环境（我们建议使用 IDLE，因为它与 Python 捆绑在一起并使用 Tkinter）。在后面的章节中，您需要访问互联网，以便安装 Python 软件包和 PostgreSQL 数据库。

要在 Android 设备上运行 Python 脚本，您需要在 Android 设备上安装 QPython。要使用 Kivy 库将 Python 脚本打包成 Android 的 APK，您需要安装 Kivy、Virtual Box 和 Buildozer 打包程序。同样，要在 iOS 设备上运行 Python 脚本，您需要一台 macOS 机器和一些库工具，包括 Cython。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在“搜索”框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹。

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Python-GUI-Programming-A-Complete-Reference-Guide`](https://github.com/PacktPublishing/Python-GUI-Programming-A-Complete-Reference-Guide)[.](https://github.com/TrainingByPackt/Spring-Boot-2-Fundamentals)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。请查看！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“确定每个数据字段的适当`input`小部件。”

代码块设置如下：

```py
def has_five_or_less_chars(string):
    return len(string) <= 5

    wrapped_function = root.register(has_five_or_less_chars)
    vcmd = (wrapped_function, '%P')
    five_char_input = ttk.Entry(root, validate='key', validatecommand=vcmd)
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都以如下形式书写：

```py
pip install --user psycopg2-binary
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“安装后，启动 pgAdmin，并通过选择 Object | Create | Login/Group Role 来为自己创建一个新的管理员用户。”

警告或重要说明会出现在这样。提示和技巧会出现在这样。


# 第一章：Tkinter 简介

欢迎，Python 程序员！如果您已经掌握了 Python 的基础知识，并希望开始设计强大的 GUI 应用程序，那么这本书就是为您准备的。

到目前为止，您无疑已经体验到了 Python 的强大和简单。也许您已经编写了 Web 服务，进行了数据分析，或者管理了服务器。也许您已经编写了游戏，自动化了例行任务，或者只是在代码中玩耍。但现在，您已经准备好去应对 GUI 了。

在如此强调网络、移动和服务器端编程的今天，开发简单的桌面 GUI 应用程序似乎越来越像是一门失传的艺术；许多经验丰富的开发人员从未学会创建这样的应用程序。真是一种悲剧！桌面计算机在工作和家庭计算中仍然发挥着至关重要的作用，能够为这个无处不在的平台构建简单、功能性的应用程序的能力应该成为每个软件开发人员工具箱的一部分。幸运的是，对于 Python 程序员来说，由于 Tkinter，这种能力完全可以实现。

在本章中，您将涵盖以下主题：

+   发现 Tkinter——一个快速、有趣、易学的 GUI 库，直接内置在 Python 标准库中

+   了解 IDLE——一个使用 Tkinter 编写并与 Python 捆绑在一起的编辑器和开发环境

+   创建两个`Hello World`应用程序，以学习编写 Tkinter GUI 的基础知识

# 介绍 Tkinter 和 Tk

Tk 的小部件库起源于“工具命令语言”（Tcl）编程语言。Tcl 和 Tk 是由约翰·奥斯特曼（John Ousterman）在 20 世纪 80 年代末担任伯克利大学教授时创建的，作为一种更简单的方式来编写在大学中使用的工程工具。由于其速度和相对简单性，Tcl/Tk 在学术、工程和 Unix 程序员中迅速流行起来。与 Python 本身一样，Tcl/Tk 最初是在 Unix 平台上诞生的，后来才迁移到 macOS 和 Windows。Tk 的实际意图和 Unix 根源仍然影响着它的设计，与其他工具包相比，它的简单性仍然是一个主要优势。

Tkinter 是 Python 对 Tk GUI 库的接口，自 1994 年以来一直是 Python 标准库的一部分，随着 Python 1.1 版本的发布，它成为了 Python 的事实标准 GUI 库。Tkinter 的文档以及进一步学习的链接可以在标准库文档中找到：[`docs.python.org/3/library/tkinter.html`](https://docs.python.org/3/library/tkinter.html)。

# 选择 Tkinter

想要构建 GUI 的 Python 程序员有几种工具包选择；不幸的是，Tkinter 经常被诋毁或被忽视为传统选项。公平地说，它并不是一种时髦的技术，无法用时髦的流行词和光辉的炒作来描述。然而，Tkinter 不仅适用于各种应用程序，而且具有以下无法忽视的优势：

+   它在标准库中：除了少数例外，Tkinter 在 Python 可用的任何地方都可以使用。无需安装`pip`，创建虚拟环境，编译二进制文件或搜索网络安装包。对于需要快速完成的简单项目来说，这是一个明显的优势。

+   它是稳定的：虽然 Tkinter 的开发并没有停止，但它是缓慢而渐进的。API 已经稳定多年，主要变化是额外的功能和错误修复。您的 Tkinter 代码可能会在未来数十年内保持不变。

+   它只是一个 GUI 工具包：与一些其他 GUI 库不同，Tkinter 没有自己的线程库、网络堆栈或文件系统 API。它依赖于常规的 Python 库来实现这些功能，因此非常适合将 GUI 应用于现有的 Python 代码。

+   它简单而直接：Tkinter 是直接、老派的面向对象的 GUI 设计。要使用 Tkinter，您不必学习数百个小部件类、标记或模板语言、新的编程范式、客户端-服务器技术或不同的编程语言。

当然，Tkinter 并非完美。它还具有以下缺点：

+   **外观和感觉**：它经常因其外观和感觉而受到批评，这些外观和感觉仍带有一些 1990 年代 Unix 世界的痕迹。在过去几年中，由于 Tk 本身的更新和主题化小部件库的添加，这方面已经有了很大改进。我们将在本书中学习如何修复或避免 Tkinter 更古老的默认设置。

+   **复杂的小部件**：它还缺少更复杂的小部件，比如富文本或 HTML 渲染小部件。正如我们将在本书中看到的，Tkinter 使我们能够通过定制和组合其简单小部件来创建复杂的小部件。

Tkinter 可能不是游戏用户界面或时尚商业应用的正确选择；但是，对于数据驱动的应用程序、简单实用程序、配置对话框和其他业务逻辑应用程序，Tkinter 提供了所需的一切以及更多。

# 安装 Tkinter

Tkinter 包含在 Python 标准库中，适用于 Windows 和 macOS 发行版。这意味着，如果您在这些平台上安装了 Python，您无需执行任何操作来安装 Tkinter。

但是，我们将专注于本书中的 Python 3.x；因此，您需要确保已安装了这个版本。

# 在 Windows 上安装 Python 3

您可以通过以下步骤从[python.org](https://www.python.org/)网站获取 Windows 的 Python 3 安装程序：

1.  转到[`www.python.org/downloads/windows`](http://www.python.org)。

1.  选择最新的 Python 3 版本。在撰写本文时，最新版本为 3.6.4，3.7 版本预计将在发布时推出。

1.  在文件部分，选择适合您系统架构的 Windows 可执行安装程序（32 位 Windows 选择 x86，64 位 Windows 选择 x86_64）。

1.  启动下载的安装程序。

1.  单击“自定义安装”。确保 tcl/tk 和 IDLE 选项已被选中（默认情况下应该是这样）。

1.  按照所有默认设置继续安装程序。

# 在 macOS 上安装 Python 3

截至目前，macOS 内置 Python 2 和 Tcl/Tk 8.5。但是，Python 2 计划在 2020 年停用，本书中的代码将无法与其一起使用，因此 macOS 用户需要安装 Python 3 才能跟随本书学习。

让我们按照以下步骤在 macOS 上安装 Python3：

1.  转到[`www.python.org/downloads/mac-osx/`](http://www.python.org)。

1.  选择最新的 Python 3 版本。在撰写本文时，最新版本为 3.6.4，但在出版时应该会有 3.7 版本。

1.  在文件部分，选择并下载`macOS 64 位/32 位安装程序`**。**

1.  启动您下载的`.pkg`文件，并按照安装向导的步骤进行操作，选择默认设置。

目前在 macOS 上没有推荐的升级到 Tcl/Tk 8.6 的方法，尽管如果您愿意，可以使用第三方工具来完成。我们的大部分代码将与 8.5 兼容，不过当某些内容仅适用于 8.6 时会特别提到。

# 在 Linux 上安装 Python 3 和 Tkinter

大多数 Linux 发行版都包括 Python 2 和 Python 3，但 Tkinter 并不总是捆绑在其中或默认安装。

要查看 Tkinter 是否已安装，请打开终端并尝试以下命令：

```py
python3 -m tkinter
```

这将打开一个简单的窗口，显示有关 Tkinter 的一些信息。如果您收到`ModuleNotFoundError`，则需要使用软件包管理器为 Python 3 安装您发行版的 Tkinter 包。在大多数主要发行版中，包括 Debian、Ubuntu、Fedora 和 openSUSE，这个包被称为`python3-tk`。

# 介绍 IDLE

IDLE 是一个集成开发环境，随 Windows 和 macOS Python 发行版捆绑提供（在大多数 Linux 发行版中通常也可以找到，通常称为 IDLE 或 IDLE3）。IDLE 使用 Tkinter 用 Python 编写，它不仅为 Python 提供了一个编辑环境，还是 Tkinter 的一个很好的示例。因此，虽然许多 Python 编码人员可能不认为 IDLE 的基本功能集是专业级的，而且您可能已经有了首选的 Python 代码编写环境，但我鼓励您在阅读本书时花一些时间使用 IDLE。

让我们熟悉 IDLE 的两种主要模式：**shell**模式和**editor**模式。

# 使用 IDLE 的 shell 模式

当您启动 IDLE 时，您将开始进入 shell 模式，这只是一个类似于在终端窗口中键入`python`时获得的 Python **Read-Evaluate-Print-Loop**（**REPL**）。

查看下面的屏幕截图中的 shell 模式：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/589e283e-d8fa-4c1a-93b3-ffec82450966.png)

IDLE 的 shell 具有一些很好的功能，这些功能在命令行 REPL 中无法获得，如语法高亮和制表符补全。REPL 对 Python 开发过程至关重要，因为它使您能够实时测试代码并检查类和 API，而无需编写完整的脚本。我们将在后面的章节中使用 shell 模式来探索模块的特性和行为。如果您没有打开 shell 窗口，可以通过单击“开始”，然后选择“运行”，并搜索 Python shell 来打开一个。

# 使用 IDLE 的编辑器模式

编辑器模式用于创建 Python 脚本文件，稍后可以运行。当本书告诉您创建一个新文件时，这是您将使用的模式。要在编辑器模式中打开新文件，只需在菜单中导航到 File | New File，或者在键盘上按下*Ctrl* + *N*。

以下是一个可以开始输入脚本的窗口：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/16738154-6cfd-4030-a682-8da92f4125dd.png)

您可以通过在编辑模式下按下*F5*而无需离开 IDLE 来运行脚本；输出将显示在一个 shell 窗口中。

# IDLE 作为 Tkinter 示例

在我们开始使用 Tkinter 编码之前，让我们快速看一下您可以通过检查 IDLE 的一些 UI 来做些什么。导航到主菜单中的 Options | Configure IDLE，打开 IDLE 的配置设置，您可以在那里更改 IDLE 的字体、颜色和主题、键盘快捷键和默认行为，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/0084883d-16d3-4c43-8b4d-ff027d48fd5f.png)

考虑一些构成此用户界面的组件：

+   有下拉列表和单选按钮，允许您在不同选项之间进行选择

+   有许多按钮，您可以单击以执行操作

+   有一个文本窗口可以显示多彩的文本

+   有包含组件组的标记帧

这些组件中的每一个都被称为**widget**；我们将在本书中遇到这些小部件以及更多内容，并学习如何像这里使用它们。然而，我们将从更简单的东西开始。

# 创建一个 Tkinter Hello World

通过执行以下步骤学习 Tkinter 的基础知识，创建一个简单的`Hello World` Tkinter 脚本：

1.  在 IDLE 或您喜欢的编辑器中创建一个新文件，输入以下代码，并将其保存为`hello_tkinter.py`：

```py
"""Hello World application for Tkinter"""

from tkinter import *
from tkinter.ttk import *

root = Tk()
label = Label(root, text="Hello World")
label.pack()
root.mainloop()
```

1.  通过按下*F5*在 IDLE 中运行此命令，或者在终端中键入以下命令：

```py
python3 hello_tkinter.py
```

您应该看到一个非常小的窗口弹出，其中显示了“Hello World”文本，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/c8342aa6-557d-416b-8058-e13fa2af884c.png)

1.  关闭窗口并返回到编辑器屏幕。让我们分解这段代码并谈谈它的作用：

+   `from tkinter import *`：这将 Tkinter 库导入全局命名空间。这不是最佳实践，因为它会填充您的命名空间，您可能会意外覆盖很多类，但对于非常小的脚本来说还可以。

+   `from tkinter.ttk import *`: 这导入了`ttk`或**主题**Tk 部件库。我们将在整本书中使用这个库，因为它添加了许多有用的部件，并改善了现有部件的外观。由于我们在这里进行了星号导入，我们的 Tk 部件将被更好看的`ttk`部件替换（例如，我们的`Label`对象）。

+   `root = Tk()`: 这将创建我们的根或主应用程序对象。这代表应用程序的主要顶层窗口和主执行线程，因此每个应用程序应该有且只有一个 Tk 的实例。

+   `label = Label(root, text="Hello World")`: 这将创建一个新的`Label`对象。顾名思义，`Label`对象只是用于显示文本（或图像）的部件。仔细看这一行，我们可以看到以下内容：

+   我们传递给`Label()`的第一个参数是`parent`或主部件。Tkinter 部件按层次结构排列，从根窗口开始，每个部件都包含在另一个部件中。每次创建部件时，第一个参数将是包含新部件的部件对象。在这种情况下，我们将`Label`对象放在主应用程序窗口上。

+   第二个参数是一个关键字参数，指定要显示在`Label`对象上的文本。

+   我们将新的`Label`实例存储在一个名为`label`的变量中，以便以后可以对其进行更多操作。

+   `label.pack()`: 这将新的标签部件放在其`parent`部件上。在这种情况下，我们使用`pack()`方法，这是您可以使用的三种**几何管理器**方法中最简单的一种。我们将在以后的章节中更详细地了解这些内容。

+   `root.mainloop()`: 这最后一行启动我们的主事件循环。这个循环负责处理所有事件——按键、鼠标点击等等——并且会一直运行直到程序退出。这通常是任何 Tkinter 脚本的最后一行，因为它之后的任何代码都不会在主窗口关闭之前运行。

花点时间玩弄一下这个脚本，在`root.mainloop()`调用之前添加更多的部件。你可以添加更多的`Label`对象，或者尝试`Button`（创建一个可点击的按钮）或`Entry`（创建一个文本输入字段）。就像`Label`一样，这些部件都是用`parent`对象（使用`root`）和`text`参数初始化的。不要忘记调用`pack()`将你的部件添加到窗口中。

你也可以尝试注释掉`ttk`导入，看看小部件外观是否有所不同。根据你的操作系统，外观可能会有所不同。

# 创建一个更好的 Hello World Tkinter

像我们刚才做的那样创建 GUI 对于非常小的脚本来说还可以，但更可扩展的方法是子类化 Tkinter 部件，以创建我们将随后组装成一个完成的应用程序的组件部件。

**子类化**只是一种基于现有类创建新类的方法，只添加或更改新类中不同的部分。我们将在本书中广泛使用子类化来扩展 Tkinter 部件的功能。

让我们构建一个更健壮的`Hello World`脚本，演示一些我们将在本书的其余部分中使用的模式。看一下以下步骤：

1.  创建一个名为`better_hello_tkinter.py`的文件，并以以下行开始：

```py
"""A better Hello World for Tkinter"""
import tkinter as tk
from tkinter import ttk
```

这一次，我们不使用星号导入；相反，我们将保持 Tkinter 和`ttk`对象在它们自己的命名空间中。这样可以避免全局命名空间被混乱，消除潜在的错误源。

星号导入（`from module import *`）在 Python 教程和示例代码中经常见到，但在生产代码中应该避免使用。Python 模块可以包含任意数量的类、函数或变量；当你进行星号导入时，你会导入所有这些内容，这可能导致一个导入覆盖从另一个模块导入的对象。如果你发现一个模块名在重复输入时很麻烦，可以将其别名为一个简短的名称，就像我们对 Tkinter 所做的那样。

1.  接下来，我们创建一个名为`HelloView`的新类，如下所示：

```py
class HelloView(tk.Frame):
    """A friendly little module"""

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
```

我们的类是从`Tkinter.Frame`继承的。`Frame`类是一个通用的 Tk 小部件，通常用作其他小部件的容器。我们可以向`Frame`类添加任意数量的小部件，然后将整个内容视为单个小部件。这比在单个主窗口上单独放置每个按钮、标签和输入要简单得多。构造函数的首要任务是调用`super().__init__()`。`super()`函数为我们提供了对超类的引用（在本例中是我们继承的类，即`tk.Frame`）。通过调用超类构造函数并传递`*args`和`**kwargs`，我们的新`HelloWidget`类可以接受`Frame`可以接受的任何参数。

在较旧的 Python 版本中，`super()`必须使用子类的名称和对当前实例的引用来调用，例如`super(MyChildClass, self)`。Python 3 允许您无需参数调用它，但您可能会遇到使用旧调用的代码。

1.  接下来，我们将创建两个 Tkinter 变量对象来存储名称和问候语字符串，如下所示：

```py
        self.name = tk.StringVar()
        self.hello_string = tk.StringVar()
        self.hello_string.set("Hello World")
```

Tkinter 有一系列变量类型，包括`StringVar`、`IntVar`、`DoubleVar`和`BooleanVar`。您可能会想知道为什么我们要使用这些，当 Python 已经为所有这些（以及更多！）提供了完全良好的数据类型。Tkinter 变量不仅仅是数据的容器：它们具有常规 Python 变量缺乏的特殊功能，例如自动传播对所有引用它们的小部件的更改或在它们更改时触发事件的能力。在这里，我们将它们用作一种访问小部件中的数据的方式，而无需保留或传递对小部件本身的引用。

注意，将值设置为 Tkinter 变量需要使用`set()`方法，而不是直接赋值。同样，检索数据需要使用`get()`方法。在这里，我们将`hello_string`的值设置为`Hello World`。我们通过创建`Label`对象和`Entry`来开始构建我们的视图，如下所示：

```py
        name_label = ttk.Label(self, text="Name:")
        name_entry = ttk.Entry(self, textvariable=self.name)
```

`Label()`的调用看起来很熟悉，但`Entry`对象获得了一个新的参数：`textvariable`。通过将 Tkinter `StringVar`变量传递给此参数，`Entry`框的内容将绑定到该变量，我们可以在不需要引用小部件的情况下访问它。每当用户在`Entry`对象中输入文本时，`self.name`将立即在出现的任何地方更新。

1.  现在，让我们创建`Button`，如下所示：

```py
        ch_button = ttk.Button(self, text="Change", 
            command=self.on_change)
```

在上述代码中，我们再次有一个新的参数`command`，它接受对 Python 函数或方法的引用。我们通过这种方式传递的函数或方法称为回调，正如你所期望的那样，当单击按钮时将调用此回调。这是将函数绑定到小部件的最简单方法；稍后，我们将学习一种更灵活的方法，允许我们将各种按键、鼠标点击和其他小部件事件绑定到函数或方法调用。

确保此时不要实际调用回调函数——它应该是`self.on_change`，而不是`self.on_change()`。回调函数应该是对函数或方法的引用，而不是它的输出。

1.  让我们创建另一个`Label`，如下所示，这次用于显示我们的文本：

```py
        hello_label = ttk.Label(self, textvariable=self.hello_string,
            font=("TkDefaultFont", 64), wraplength=600)
```

在这里，我们将另一个`StringVar`变量`self.hello_string`传递给`textvariable`参数；在标签上，`textvariable`变量决定了将显示什么。通过这样做，我们可以通过简单地更改`self.hello_string`来更改标签上的文本。我们还将使用`font`参数设置一个更大的字体，该参数采用格式为`(font_name, font_size)`的元组。

您可以在这里输入任何字体名称，但它必须安装在系统上才能工作。Tk 有一些内置的别名，可以映射到每个平台上合理的字体，例如这里使用的`TkDefaultFont`。我们将在第八章“使用样式和主题改善外观”中学习更多关于在 Tkinter 中使用字体的知识。

`wraplength`参数指定文本在换行到下一行之前可以有多宽。我们希望当文本达到窗口边缘时换行；默认情况下，标签文本不会换行，因此会在窗口边缘被截断。通过将换行长度设置为 600 像素，我们的文本将在屏幕宽度处换行。

1.  到目前为止，我们已经创建了小部件，但尚未放置在`HelloView`上。让我们安排我们的小部件如下：

```py
        name_label.grid(row=0, column=0, sticky=tk.W)
        name_entry.grid(row=0, column=1, sticky=(tk.W + tk.E))
                ch_button.grid(row=0, column=2, sticky=tk.E)
                hello_label.grid(row=1, column=0, columnspan=3)
```

在这种情况下，我们使用`grid()`几何管理器添加我们的小部件，而不是之前使用的`pack()`几何管理器。顾名思义，`grid()`允许我们使用行和列在它们的`parent`对象上定位小部件，就像电子表格或 HTML 表格一样。我们的前三个小部件在第 0 行的三列中排列，而`hello_label`将在第二行（第 1 行）。`sticky`参数采用基本方向（`N`、`S`、`E`或`W`—您可以使用字符串或 Tkinter 常量），指定内容必须粘附到单元格的哪一侧。您可以将这些加在一起，以将小部件粘附到多个侧面；例如，通过将`name_entry`小部件粘附到东侧和西侧，它将拉伸以填满整个列的宽度。`grid()`调用`hello_label`使用`columnspan`参数。正如您可能期望的那样，这会导致小部件跨越三个网格列。由于我们的第一行为网格布局建立了三列，如果我们希望这个小部件填满应用程序的宽度，我们需要跨越所有三列。最后，我们将通过调整网格配置来完成`__init__()`方法：

```py
        self.columnconfigure(1, weight=1)
```

在上述代码中，`columnconfigure()`方法用于更改小部件的网格列。在这里，我们告诉它要比其他列更加重视第 1 列（第二列）。通过这样做，网格的第二列（我们的输入所在的位置）将水平扩展并压缩周围的列到它们的最小宽度。还有一个`rowconfigure()`方法，用于对网格行进行类似的更改。

1.  在完成`HelloModule`类之前，我们必须创建`ch_button`的回调，如下所示：

```py
def on_change(self):
    if self.name.get().strip():
        self.hello_string.set("Hello " + self.name.get())
    else:
        self.hello_string.set("Hello World")
```

要获取文本输入的值，我们调用其文本变量的`get()`方法。如果这个变量包含任何字符（请注意我们去除了空格），我们将设置我们的问候文本来问候输入的名字；否则，我们将只是问候整个世界。

通过使用`StringVar`对象，我们不必直接与小部件交互。这使我们不必在我们的类中保留大量小部件引用，但更重要的是，我们的变量可以从任意数量的来源更新或更新到任意数量的目的地，而无需明确编写代码来执行此操作。

1.  创建了`HelloView`后，我们转到实际的应用程序类，如下所示：

```py
class MyApplication(tk.Tk):
    """Hello World Main Application"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("Hello Tkinter")
        self.geometry("800x600")
        self.resizable(width=False, height=False)
```

这次，我们对`Tk`进行了子类化，它将代表我们的主要应用程序对象。在 Tkinter 世界中，是否这样做是最佳实践存在一些争议。由于应用程序中只能有一个`Tk`对象，如果我们将来想要多个`MyApplication`对象，这可能会在某种程度上造成问题；对于简单的单窗口应用程序，这是完全可以的。

1.  与我们的模块一样，我们调用`super().__init__()`并传递任何参数。请注意，这次我们不需要一个`parent`小部件，因为`Tk`对象是根窗口，没有`parent`。然后有以下三个调用来配置我们的应用程序窗口：

+   `self.title()`: 这个调用设置窗口标题，通常出现在任务列表和/或我们的 OS 环境中的窗口栏中。

+   `self.geometry()`: 此调用以像素为单位设置窗口的大小，格式为`x * y`（宽度 x 高度）。

+   `self.resizable()`: 此调用设置程序窗口是否可以调整大小。我们在这里禁用调整大小，宽度和高度都禁用。

1.  我们通过将视图添加到主窗口来完成我们的应用程序类，如下所示：

```py
        HelloView(self).grid(sticky=(tk.E + tk.W + tk.N + tk.S))
        self.columnconfigure(0, weight=1)
```

请注意，我们在一行代码中创建和放置`HelloView`。我们在不需要保留对小部件的引用的情况下这样做，但由于`grid()`不返回值，如果您想在代码中稍后访问小部件，则必须坚持使用两个语句的版本。

因为我们希望视图填充应用程序窗口，我们的`grid()`调用将其固定在单元格的所有边上，我们的`columnconfigure()`调用会导致第一列扩展。请注意，我们省略了`row`和`column`参数，没有它们，`grid()`将简单地使用下一个可用行的第一列（在本例中为`0`，`0`）。

1.  定义了我们的类之后，我们将开始实际执行代码，如下所示：

```py
if __name__ == '__main__':
    app = MyApplication()
    app.mainloop()
```

在 Python 中，`if __name__ == '__main__':`是一个常见的习语，用于检查脚本是否直接运行，例如当我们在终端上键入`python3 better_hello_world.py`时。如果我们将此文件作为模块导入到另一个 Python 脚本中，此检查将为 false，并且之后的代码将不会运行。在此检查下方放置程序的主执行代码是一个良好的做法，这样您可以在更大的应用程序中安全地重用您的类和函数。

请记住，`MyApplication`是`Tk`的子类，因此它充当根窗口。我们只需要创建它，然后启动它的主循环。看一下以下的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/2687700f-7aa1-434a-be4e-0aeaf4ec4d4f.png)

对于`Hello World`应用程序来说，这显然是过度的，但它演示了使用子类将我们的应用程序分成模块的用法，这将大大简化我们构建更大程序时的布局和代码组织。

# 摘要

现在您已经安装了 Python 3，学会了使用 IDLE，品尝了 Tkinter 的简单性和强大性，并且已经看到了如何开始为更复杂的应用程序进行结构化，现在是时候开始编写一个真正的应用程序了。

在下一章中，您将开始在 ABQ AgriLabs 的新工作，并面临一个需要用您的编程技能和 Tkinter 解决的问题。您将学习如何分解这个问题，制定程序规范，并设计一个用户友好的应用程序，这将成为解决方案的一部分。


# 第二章：使用 Tkinter 设计 GUI 应用程序

软件应用程序的开发分为三个重复阶段：理解问题、设计解决方案和实施解决方案。这些阶段在应用程序的整个生命周期中重复，不断完善和改进，直到它变得最佳或过时。

在本章中，我们将学习以下主题：

+   介绍和分析工作场所中需要软件解决方案的场景

+   记录解决方案的要求

+   为实施解决方案的软件设计一个设计

# ABQ AgriLabs 的问题

恭喜！你的 Python 技能让你在 ABQ AgriLabs 找到了一份出色的数据分析师工作。到目前为止，你的工作相当简单：整理并对每天从实验室数据录入人员那里收到的 CSV 文件进行简单的数据分析。

然而，有一个问题。你沮丧地注意到实验室的 CSV 文件质量非常不一致。数据缺失，错别字丛生，而且文件经常需要重新输入，耗费大量时间。实验室主任也注意到了这一点，并且知道你是一位技艺高超的 Python 程序员，她认为你可能能够提供帮助。

你被委托编写一个解决方案，允许数据录入人员将实验室数据输入到 CSV 文件中，减少错误。你的应用程序需要简单，并且尽量减少错误的可能性。

# 评估问题

电子表格通常是需要跟踪数据的计算机用户的第一站。它们的表格布局和计算功能似乎使它们成为完成任务的理想选择。然而，随着数据集的增长和多个用户的添加，电子表格的缺点变得明显：它们不能强制数据完整性，它们的表格布局在处理稀疏或模糊数据的长行时可能会造成视觉混乱，如果用户不小心的话，他们可以轻松地删除或覆盖数据。

为了改善这种情况，你建议实现一个简单的 GUI 数据输入表单，将数据以我们需要的格式追加到 CSV 文件中。表单可以在多种方式上帮助改善数据完整性：

+   只允许输入正确类型的数据（例如，只允许在数字字段中输入数字）

+   限制选择只能是有效的选项

+   自动填充当前日期、时间等信息

+   验证输入的数据是否在预期范围内或与预期模式匹配

+   确保所有数据都已填写

通过实施这样的表单，我们可以大大减少数据录入人员输入的错误数量。

# 收集有关问题的信息

要构建数据输入表单应用程序，你需要收集关于它需要完成的任务的详细信息。幸运的是，你已经知道了等式的输出部分：你需要一个包含每个实验室地块上植物生长和每个地块的环境条件数据的 CSV 文件。你每天都在使用这些文件，所以你对字段布局非常熟悉。

然而，你并不知道关于数据或输入过程的一切；你需要与其他相关人员交谈，以获取更多信息。

首先，你需要更详细地了解正在记录的数据。这并不总是那么容易。软件在处理数据时需要绝对的、黑白分明的规则；而人们往往倾向于以一般性的方式思考他们的数据，并且通常在没有一些提示的情况下不考虑限制或边缘情况的确切细节。

作为程序员，你的工作是提出问题，以获取你所需要的信息。

你决定应该从实验室技术人员开始，了解他们正在收集的数据。你提出了以下问题：

+   每个字段的可接受值是什么？是否有任何字段受限于一组值？

+   每个数字字段代表什么单位？

+   数字字段是否真的只是数字字段？它们是否会需要字母或符号？

+   每个数字字段的可接受范围是多少？

+   你是如何记录数据的，需要多长时间？

数据不是唯一的考虑因素。如果我们正在制作一个帮助减少用户错误的程序，我们还必须了解这些用户以及他们的工作方式。在这个应用程序的情况下，我们的用户将是数据录入人员。我们需要向他们询问关于他们的需求和工作流程的问题，以了解如何为他们创建一个良好运行的应用程序。

我们列出了以下问题清单：

+   你输入的数据是以什么格式？

+   数据是何时接收并且多快被输入？最晚可能是什么时候输入？

+   是否有字段可以自动填充？用户是否能够覆盖自动值？

+   用户的整体技术能力如何？

+   你喜欢当前解决方案的什么？你不喜欢什么？

+   用户是否有视觉或手动障碍需要考虑？

最后，我们需要了解与操作我们的应用程序相关的技术——用于完成任务的计算机、网络、服务器和平台。

你决定添加以下问题，当你与数据录入人员会面时，你将自己评估：

+   数据录入使用什么样的计算机？

+   它运行在什么平台上？

+   它有多快或多强大？

+   这些系统上是否有 Python 可用？

+   有哪些 Python 库可用？

# 你发现了什么

你首先写下你知道的关于 ABQ 的基本信息：

+   你的 ABQ 设施有五个温室，每个温室都有不同的气候，标记为 A、B、C、D 和 E

+   每个温室有 20 个地块（标记为 1 到 20）

+   目前有四个种子样本，每个都用一个六位字符标签编码

+   每个样本的每个地块都种植了 20 颗种子，以及自己的环境传感器单元

# 正在收集的数据的信息

你与实验室技术人员的交谈揭示了很多关于数据的信息。每天四次，分别在 8:00、12:00、16:00 和 20:00，每个技术人员检查一两个实验室的地块。他们使用纸质表格记录每个地块的值，将所有值记录到小数点后两位。这通常需要每个实验室 30 到 40 分钟，整个过程通常需要 90 分钟。

每个地块都有一个环境传感器，用于检测地块的光线、温度和湿度。不幸的是，这些设备容易出现故障，单位上的`设备` `故障`指示灯会亮起。技术人员记录这个灯是否亮起，因为它会使环境数据无效。

最后，技术人员告诉你有关单位和字段的可接受范围，你记录在以下图表中：

| **字段** | **数据类型** | **备注** |
| --- | --- | --- |
| `日期` | `日期` | 数据收集日期。几乎总是当前日期 |
| `时间` | `时间` | 测量期间的开始时间。8:00、12:00、16:00 或 20:00 之一 |
| `实验室` | `字符` | 实验室 ID，将是 A 到 E |
| `技术人员` | `文本` | 记录数据的技术人员的姓名 |
| `地块` | `整数` | 地块 ID，从 1 到 20 |
| `种子样本` | `文本` | 种子样本的 ID 字符串。始终是包含数字 0 到 9 和大写字母 A 到 Z 的六位字符代码 |
| `故障` | `布尔` | 如果环境设备注册了故障，则为真，否则为假 |
| `湿度` | `小数` | 每立方米的绝对湿度，大约在 0.5 到 52.0 之间 |
| `光线` | `小数` | 地块中心的阳光量，单位为千勒克斯，介于 0 和 100 之间 |
| `温度` | `小数` | 摄氏度，不应低于 4 或高于 40 |
| `开花` | `整数` | 地块上的花朵数量必须是 0 或更多，但不太可能接近 1000 |
| `水果` | `整数` | 地块上的水果数量必须是 0 或更多，但不太可能接近 1000 |
| `植物` | `整数` | 生长植物的数量，介于 0 和 20 之间。 |
| `最大高度` | `小数` | 植物的最大高度（厘米）。至少为 0，不太可能接近 1,000。 |
| `中位高度` | `小数` | 样地内植物的中位高度（厘米）。至少为 0，不太可能接近 1,000 |
| `最小高度` | `小数` | 植物的最小高度（厘米）。至少为 0，不太可能接近 1,000 |
| `备注` | `长文本` | 关于植物、数据、仪器等的其他观察。 |

# 应用程序用户的信息

您与数据录入人员的会话为您提供了关于他们的工作流程、要求和技术的有用信息。

实验室技术人员在完成后交接他们的纸质表格。数据通常会立即输入，并且通常在交接当天就会完成。

技术人员目前正在使用 Debian Linux 工作站上的 LibreOffice 进行数据输入。使用复制和粘贴，他们可以批量填写重复数据，如日期、时间和技术人员。LibreOffice 的自动完成功能在文本字段中通常很有帮助，但有时会在数字字段中导致意外的数据错误。

正在使用的工作站已经使用了几年，但性能仍然良好。您有机会查看它，并发现 Python 和 Tkinter 已经安装。

总共有四名数据录入员，但一次只有一名工作；在采访这些员工时，您了解到其中一名员工有红绿色盲，另一名员工由于 RSI 问题难以使用鼠标。所有员工都具有合理的计算机素养。

# 记录规格要求

现在，您已经收集了关于应用程序的数据，是时候撰写一份**规格说明**了。软件规格说明可以从非常正式的、包括时间估计和截止日期的合同文件，到程序员打算构建的简单描述集合。规格说明的目的是为项目中的所有参与者提供开发人员将创建的参考点。它详细说明了要解决的问题、所需的功能以及程序应该做什么和不应该做什么的范围。

您的情景相当非正式，您的应用程序很简单，因此在这种情况下您不需要详细的正式规格说明。然而，对您所知道的基本描述将确保您、您的老板和用户都在同一页面上。

# 简要规格说明的内容

我们将从以下项目的概述开始撰写我们需要的内容：

+   **描述**：这是描述应用程序的主要目的、功能和目标的一两句话。将其视为程序的使命宣言。

+   **所需功能**：这一部分是程序需要具备的最基本功能的具体列表。它可以包括硬性要求，如详细的输出和输入格式，以及软性要求——无法量化实现的目标，但程序应该努力实现（例如，“尽量减少用户错误”）。

+   **不需要的功能**：这一部分是程序不需要执行的功能的列表；它存在的目的是澄清软件的范围，并确保没有人对应用程序期望不合理的事情。

+   **限制**：这是程序必须在其中运行的技术和人为约束的列表。

+   **数据字典**：这是应用程序将处理的数据字段及其参数的详细列表。这些内容可能会变得非常冗长，但在应用程序扩展和数据在其他上下文中被利用时，它们是关键的参考。

# 编写 ABQ 数据录入程序规格说明

您可以在您喜欢的文字处理器中编写规格说明，但理想情况下，规格说明应该是代码的一部分；它需要与代码一起保存，并与应用程序的任何更改同步。因此，我们将使用**reStructuredText**标记语言在我们的文本编辑器中编写它。

对于 Python 文档，reStructuredText 或 reST 是官方的标记语言。Python 社区鼓励使用 reST 来记录 Python 项目，并且 Python 社区中使用的许多打包和发布工具都期望 reST 格式。我们将在第五章“规划我们应用程序的扩展”中更深入地介绍 reST，但您可以在[`docutils.sourceforge.net/rst.html`](http://docutils.sourceforge.net/rst.html)找到官方文档。

让我们开始逐个部分编写我们的规范：

1.  以应用程序的名称和简短描述开始规范。这应该包含程序目的的摘要，如下： 

```py
======================================
 ABQ Data Entry Program specification
======================================

Description
-----------
The program is being created to minimize data entry errors for laboratory measurements.
```

1.  现在，让我们列出要求。请记住，硬性要求是客观可实现的目标——输入和输出要求、必须进行的计算、必须存在的功能，而我们的软性要求是主观或尽力而为的目标。浏览上一节的发现，并考虑哪些需求属于哪种需求。

您应该得出类似以下的结论：

```py

Functionality Required
----------------------

The program must:

* allow all relevant, valid data to be entered, as per the field chart
* append entered data to a CSV file
  - The CSV file must have a filename
    of abq_data_record_CURRENTDATE.csv, where 
    CURRENTDATE is the date of the checks in 
    ISO format (Year-month-day)
  - The CSV file must have all the fields as per the chart
* enforce correct datatypes per field

The program should try, whenever possible, to:

* enforce reasonable limits on data entered
* Auto-fill data
* Suggest likely correct values
* Provide a smooth and efficient workflow
```

1.  接下来，我们将通过`Functionality Not Required`部分限制程序的范围。请记住，目前这只是一个输入表单；编辑或删除将在电子表格应用程序中处理。我们将明确如下：

```py
Functionality Not Required
--------------------------

The program does not need to:

* Allow editing of data. This can be done in LibreOffice if necessary.
* Allow deletion of data.
```

1.  对于`Limitations`部分，请记住我们有一些具有身体限制的用户，还有硬件和操作系统的限制。添加如下：

```py
Limitations
-----------

The program must:

* Be efficiently operable by keyboard-only users.
* Be accessible to color blind users.
* Run on Debian Linux.
* Run acceptably on a low-end PC.
```

1.  最后，数据字典，这本质上是我们之前制作的表格，但我们将分解范围、数据类型和单位以供快速参考，如下：

```py
+------------+----------+------+--------------+---------------------+
|Field       | Datatype | Units| Range        |Descripton           |
+============+==========+======+==============+=====================+
|Date        |Date      |      |              |Date of record       |
+------------+----------+------+--------------+---------------------+
|Time        |Time      |      |8, 12, 16, 20 |Time period          |
+------------+----------+------+--------------+---------------------+
|Lab         |String    |      | A - E        |Lab ID               |
+------------+----------+------+--------------+---------------------+
|Technician  |String    |      |              |Technician name      |
+------------+----------+------+--------------+---------------------+
|Plot        |Int       |      | 1 - 20       |Plot ID              |
+------------+----------+------+--------------+---------------------+
|Seed        |String    |      |              |Seed sample ID       |
|sample      |          |      |              |                     |
+------------+----------+------+--------------+---------------------+
|Fault       |Bool      |      |              |Fault on sensor      |
+------------+----------+------+--------------+---------------------+
|Light       |Decimal   |klx   | 0 - 100      |Light at plot        |
+------------+----------+------+--------------+---------------------+
|Humidity    |Decimal   |g/m³  | 0.5 - 52.0   |Abs humidity at plot |
+------------+----------+------+--------------+---------------------+
|Temperature |Decimal   |°C    | 4 - 40       |Temperature at plot  |
+------------+----------+------+--------------+---------------------+
|Blossoms    |Int       |      | 0 - 1000     |# blossoms in plot   |
+------------+----------+------+--------------+---------------------+
|Fruit       |Int       |      | 0 - 1000     |# fruits in plot     |
+------------+----------+------+--------------+---------------------+
|Plants      |Int       |      | 0 - 20       |# plants in plot     |
+------------+----------+------+--------------+---------------------+
|Max height  |Decimal   |cm    | 0 - 1000     |Ht of tallest plant  |
+------------+----------+------+--------------+---------------------+
|Min height  |Decimal   |cm    | 0 - 1000     |Ht of shortest plant |
+------------+----------+------+--------------+---------------------+
|Median      |Decimal   |cm    | 0 - 1000     |Median ht of plants  |
|height      |          |      |              |                     |
+------------+----------+------+--------------+---------------------+
|Notes       |String    |      |              |Miscellaneous notes  |
+------------+----------+------+--------------+---------------------+
```

这就是我们目前的规范！随着我们发现新的需求，规范很可能会增长、改变或发展复杂性。

# 设计应用程序

有了我们手头的规范和清晰的要求，现在是时候开始设计我们的解决方案了。我们将从表单 GUI 组件本身开始。

| `ttk.Combobox` | 带有可选文本输入的下拉列表 | 在几个值之间进行选择以及文本输入 |

1.  确定每个数据字段的适当`input`小部件

1.  将相关项目分组以创建组织感

1.  在表单上将我们的小部件分组布局

# 探索 Tkinter 输入小部件

与所有工具包一样，Tkinter 为不同类型的数据提供了各种`input`小部件。然而，`ttk`提供了额外的小部件类型，并增强了 Tkinter 的一些（但不是全部！）原生小部件。以下表格提供了关于哪些小部件最适合不同类型的数据输入的建议：

| **小部件** | **描述** | **用于** |
| --- | --- | --- |
| `ttk.Entry` | 基本文本输入 | 单行字符串 |
| `ttk.Spinbox` | 具有增量/减量箭头的文本输入 | 数字 |
| `Tkinter.Listbox` | 带有选择列表的框 | 在几个值之间进行选择 |
| `Tkinter.OptionMenu` | 带有选择列表的下拉列表 | 在几个值之间进行选择 |
| 我们将按照以下三个步骤为我们的表单创建一个基本设计： |
| `ttk.Checkbutton` | 带标签的复选框 | 布尔值 |
| `ttk.Radiobutton` | 类似复选框，但只能选择一组中的一个 | 在一组小部件中选择 |
| `Tkiner.Text` | 多行文本输入框 | 长、多行字符串 |
| `Tkinter.Scale` | 鼠标操作滑块 | 有界数值数据 |

让我们考虑哪些小部件适合需要输入的数据：

+   有几个`Decimal`字段，其中许多具有明确的边界范围，包括`Min height`，`Max height`，`Median height`，`Humidity`，`Temperature`和`Light`。您可以使用`Scale`小部件进行操作，但对于精确的数据输入来说并不是很合适，因为它需要仔细的定位才能获得精确的值。它也是鼠标操作的，这违反了您的规范要求。相反，对于这些字段，请使用`Spinbox`小部件。

+   还有一些`Int`字段，例如`植物`，`花朵`和`水果`。同样，`Spinbox`小部件是正确的选择。

+   有一些字段具有一组可能值—`时间`和`实验室`。`Radiobutton`或`Listbox`小部件可能适用于这些字段，但两者都占用大量空间，并且不太友好，因为它们需要使用箭头键进行选择。还有`OptionMenu`，但它也只能使用鼠标或箭头键。对于这些字段，应使用`Combobox`小部件。

+   图表是一个棘手的情况。乍一看，它看起来像一个`Int`字段，但仔细想想。图表也可以用字母、符号或名称来标识。数字只是一组易于分配任意标识符的值。`图表 ID`，就像`实验室 ID`一样，是一组受限制的值；因此，在这里使用`Combobox`小部件更合理。

+   `注释`字段是多行文本，因此在这里使用`Text`小部件是合适的。

+   有一个`Boolean`字段，`故障`。它可以使用`Radiobutton`或`Combobox`来处理，但`Checkbutton`是最佳选择—它紧凑且相对键盘友好。

+   其余行都是简单的单行字符字段。我们将使用`Entry`来处理这些字段。

+   您可能会对`日期`字段感到困惑。Tkinter 没有专门用于日期的小部件；因此，我们暂时将在这里使用通用的`Entry`小部件。

我们的最终分析将如下所示：

| **字段** | **小部件类型** |
| --- | --- |
| `花朵` | `ttk.Spinbox` |
| `日期` | `ttk.Entry` |
| `故障` | `ttk.Checkbutton` |
| `水果` | `ttk.Spinbox` |
| `湿度` | `ttk.Spinbox` |
| `实验室` | `ttk.Combobox` |
| `光线` | `ttk.Spinbox` |
| `最大高度` | `ttk.Spinbox` |
| `中位高度` | `ttk.Spinbox` |
| `最小高度` | `ttk.Spinbox` |
| `注释` | `Tkinter.Text` |
| `植物` | `ttk.Spinbox` |
| `图表` | `ttk.Combobox` |
| `种子样本` | `ttk.Entry` |
| `技术人员` | `ttk.Entry` |
| `温度` | `ttk.Spinbox` |
| `时间` | `ttk.Combobox` |

# 对我们的字段进行分组

人们在没有特定顺序的大量输入面前往往会感到困惑。通过将输入表单分成相关字段的集合，您可以为用户做出很大的帮助。当然，这假设您的数据具有相关字段的集合，不是吗？

在查看了您的字段后，您确定了以下相关组：

+   `日期`，`实验室`，`图表`，`种子样本`，`技术人员`和`时间`字段是关于记录本身的标识数据或元数据。您可以将它们组合在一个标题下，如`记录信息`。

+   `花朵`，`水果`，三个`高度`字段和`植物`字段都是与`图表`字段中的植物有关的测量值。您可以将它们组合在一起，称为`植物数据`。

+   `湿度`，`光线`，`温度`和`设备故障`字段都是来自环境传感器的信息。您可以将它们组合为`环境数据`。

+   `注释`字段可能与任何事物有关，因此它属于自己的类别。

在 Tkinter 中对前面的字段进行分组，我们可以在每组字段之间插入标签，但值得探索将小部件组合在一起的各种选项：

| **小部件** | **描述** |
| --- | --- |
| `ttk.LabelFrame` | 带有标签文本和可选边框的框架 |
| `ttk.NoteBook` | 允许多个页面的选项卡小部件 |
| `Tkinter.PanedWindow` | 允许在水平或垂直排列中有多个可调整大小的框架 |

我们不希望我们的表单跨多个页面，用户也不需要调整各个部分的大小，但`LabelFrame`小部件非常适合我们的需求。

# 布置表单

到目前为止，我们知道我们有 17 个输入，分组如下：

+   `记录信息`下的六个字段

+   `环境数据`下的四个字段

+   `植物数据`下的六个字段

+   一个大的`注释`字段

我们希望使用`LabelFrame`来对前面的输入进行分组。

请注意，前三个部分中的两个有三个小部件。这表明我们可以将它们排列在一个三个项目横向的网格中。我们应该如何对每个组内的字段进行排序？

字段的排序似乎是一个微不足道的事项，但对于用户来说，它可能在可用性上产生重大影响。必须在表单中随意跳转以匹配其工作流程的用户更有可能出错。

正如您所了解的，数据是由实验室技术人员填写的纸质表格输入的。您已经获得了表格的副本，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/5c9481da-4be5-4b0d-ae11-c269df173e16.png)

看起来项目大多按照我们的记录分组的方式进行分组，因此我们将使用此表单上的顺序来对我们的字段进行排序。这样，数据输入员就可以直接通过表单，而不必在屏幕上来回跳动。

在设计新应用程序以替换现有工作流程的某个部分时，了解和尊重该工作流程是很重要的。虽然我们必须调整工作流程以实际改进它，但我们不希望使某人的工作变得更加困难，只是为了使我们正在处理的部分更简单。

我们设计中的最后一个考虑是标签与字段的相对位置。在 UI 设计社区中，关于标签的最佳放置位置存在很多争论，但共识是以下两种选项中的一种最佳：

+   字段上方的标签

+   字段左侧的标签

您可以尝试绘制两者，看看哪个更适合您，但对于此应用程序，字段上方的标签可能会更好，原因如下：

+   由于字段和标签都是矩形形状，我们的表单将通过将它们堆叠在一起更加紧凑。

+   这样做起来要容易得多，因为我们不必找到适用于所有标签的标签宽度，而不会使它们与字段之间的距离太远

唯一的例外是复选框字段；复选框通常标记在小部件的右侧。

花点时间用纸和铅笔或绘图程序制作一个表单的草图。您的表单应如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/b492e61c-f61f-4088-882b-c2e5aec87a18.png)

# 布局应用程序

设计好您的表单后，现在是考虑应用程序 GUI 的其余部分的时候了：

+   您需要一个保存按钮来触发输入数据的存储

+   有时，我们可能需要向用户提供状态信息；应用程序通常有一个状态栏，用于显示这些类型的消息

+   最后，最好有一个标题来指示表单是什么

将以下内容添加到我们的草图中，我们得到了以下截图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/35e3cd90-956d-490f-9e44-a3ca0524ceb4.png)

看起来不错！这绝对是一个我们可以在 Tkinter 中实现的表单。您的最后一步是向用户和主管展示这些设计，以获取任何反馈或批准。

尽量让利益相关者参与到应用程序设计过程中。这样可以减少您以后不得不回头重新设计应用程序的可能性。

# 总结

在这一章中，您已经完成了应用程序开发的前两个阶段：了解问题和设计解决方案。您学会了如何通过采访用户和检查数据和要求来开发应用程序规范，为用户创建最佳的表单布局，并了解了 Tkinter 中可用的小部件，用于处理不同类型的输入数据。最重要的是，您学会了开发应用程序不是从编码开始，而是从研究和规划开始。

在下一章中，您将使用 Tkinter 和 Python 创建您设计的基本实现。我们将熟悉创建表单所需的 Tkinter 小部件，构建表单，并将表单放置在应用程序中。我们还将学习如何使我们的表单触发回调操作，并发现如何构建我们的代码以确保效率和一致性。


# 第三章：使用 Tkinter 和 ttk 小部件创建基本表单

好消息！您的设计已经得到主管的审查和批准。现在是时候开始实施了！

在本章中，您将涵盖以下主题：

+   根据设计评估您的技术选择

+   了解我们选择的 Tkinter 和`ttk`小部件

+   实现和测试表单和应用程序

让我们开始编码吧！

# 评估我们的技术选择

我们对设计的第一次实现将是一个非常简单的应用程序，它提供了规范的核心功能和很少的其他功能。这被称为**最小可行产品**或**MVP**。一旦我们建立了 MVP，我们将更好地了解如何将其发展成最终产品。

在我们开始之前，让我们花点时间评估我们的技术选择。

# 选择技术

当然，我们将使用 Python 和 Tkinter 构建这个表单。然而，值得问一下，Tkinter 是否真的是应用程序的良好技术选择。在选择用于实现此表单的 GUI 工具包时，我们需要考虑以下几点：

+   **您目前的专业知识和技能**：您的专业是 Python，但在创建 GUI 方面经验不足。为了最快的交付时间，您需要一个能够很好地与 Python 配合使用并且不难学习的选项。您还希望选择一些已经建立并且稳定的东西，因为您没有时间跟上工具包的新发展。Tkinter 在这里适用。

+   **目标平台**：您将在 Windows PC 上开发应用程序，但它需要在 Debian Linux 上运行，因此 GUI 的选择应该是跨平台的。它将在一台又老又慢的计算机上运行，因此您的程序需要节约资源。Tkinter 在这里也适用。

+   **应用功能**：您的应用程序需要能够显示基本表单字段，验证输入的数据，并将其写入 CSV。Tkinter 可以处理这些前端要求，Python 可以轻松处理 CSV 文件。

鉴于 Python 的可用选项，Tkinter 是一个不错的选择。它学习曲线短，轻量级，在您的开发和目标平台上都很容易获得，并且包含了表单所需的功能。

Python 还有其他用于 GUI 开发的选项，包括**PyQT**、**Kivy**和**wxPython**。与 Tkinter 相比，它们各自有不同的优势和劣势，但如果发现 Tkinter 不适合某个项目，其中一个可能是更好的选择。

# 探索 Tkinter 小部件

当我们设计应用程序时，我们挑选了一个小部件类，它最接近我们需要的每个字段。这些是`Entry`、`Spinbox`、`Combobox`、`Checkbutton`和`Text`小部件。我们还确定我们需要`Button`和`LabelFrame`小部件来实现应用程序布局。在我们开始编写我们的类之前，让我们来看看这些小部件。

我们的一些小部件在 Tkinter 中，另一些在`ttk`主题小部件集中，还有一些在两个库中都有。我们更喜欢`ttk`版本，因为它们在各个平台上看起来更好。请注意我们从哪个库导入每个小部件。

# 输入小部件

`ttk.Entry`小部件是一个基本的、单行字符输入，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/93ab1723-3880-43fe-8866-779aeb33dd64.png)

您可以通过执行以下代码来创建一个输入：

```py
my_entry = ttk.Entry(parent, textvariable=my_text_var)
```

在上述代码中，`ttk.Entry`的常用参数如下：

+   `parent`：此参数为输入设置了`parent`小部件。

+   `textvariable`：这是一个 Tkinter `StringVar`变量，其值将绑定到此`input`小部件。

+   `show`：此参数确定在您输入框中键入时将显示哪个字符。默认情况下，它是您键入的字符，但这可以被替换（例如，对于密码输入，您可以指定`*`或点来代替显示）。

+   `Entry`：像所有的`ttk`小部件一样，此小部件支持额外的格式和样式选项。

在所有上述参数中，使用`textvariable`参数是可选的；没有它，我们可以使用其`get()`方法提取`Entry`小部件中的值。然而，将变量绑定到我们的`input`小部件具有一些优势。首先，我们不必保留或传递对小部件本身的引用。这将使得在后面的章节中更容易将我们的软件重新组织为单独的模块。此外，对输入值的更改会自动传播到变量，反之亦然。

# Spinbox 小部件

`ttk.Spinbox`小部件向常规`Entry`小部件添加了增量和减量按钮，使其适用于数字数据。

在 Python 3.7 之前，`Spinbox`只在 Tkinter 中可用，而不是在`ttk`中。如果您使用的是 Python 3.6 或更早版本，请改用`Tkinter.Spinbox`小部件。示例代码使用了 Tkinter 版本以确保兼容性。

创建`Spinbox`小部件如下：

```py
my_spinbox = tk.Spinbox(
    parent,
    from_=0.5,
    to=52.0,
    increment=.01,
    textvariable=my_double_var)
```

如前面的代码所示，`Spinbox`小部件需要一些额外的构造函数参数来控制增量和减量按钮的行为，如下所示：

+   **`from_`**：此参数确定箭头递减到的最低值。需要添加下划线，因为`from`是 Python 关键字；在 Tcl/`Tk`中只是`from`。

+   **`to`**：此参数确定箭头递增到的最高值。

+   **`increment`**：此参数表示箭头递增或递减的数量。

+   **`values`**：此参数接受一个可以通过递增的字符串或数字值列表。

请注意，如果使用了`from_`和`to`，则两者都是必需的；也就是说，您不能只指定一个下限，这样做将导致异常或奇怪的行为。

查看以下截图中的`Spinbox`小部件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/0af19ce1-0ba8-4436-9c18-41fe6f315936.png)

`Spinbox`小部件不仅仅是用于数字，尽管这主要是我们将要使用它的方式。它也可以接受一个字符串列表，可以使用箭头按钮进行选择。因为它可以用于字符串或数字，所以`textvariable`参数接受`StringVar`、`IntVar`或`DoubleVar`数据类型。

请注意，这些参数都不限制可以输入到`Spinbox`小部件中的内容。它只不过是一个带有按钮的`Entry`小部件，您不仅可以输入有效范围之外的值，还可以输入字母和符号。这样做可能会导致异常，如果您已将小部件绑定到非字符串变量。

# Combobox 小部件

`ttk.Combobox`参数是一个`Entry`小部件，它添加了一个下拉选择菜单。要填充下拉菜单，只需传入一个带有用户可以选择的字符串列表的`values`参数。

您可以执行以下代码来创建一个`Combobox`小部件：

```py
combobox = ttk.Combobox(
    parent, textvariable=my_string_var,
    values=["Option 1", "Option 2", "Option 3"])
```

上述代码将生成以下小部件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/2b06ad94-ddbd-45f4-8a00-fa095da6b4d9.png)如果您习惯于 HTML 的`<SELECT>`小部件或其他工具包中的下拉小部件，`ttk.Combobox`小部件可能对您来说有些陌生。它实际上是一个带有下拉菜单以选择一些预设字符串的`Entry`小部件。就像`Spinbox`小部件一样，它不限制可以输入的值。

# Checkbutton 小部件

`ttk.Checkbutton`小部件是一个带有标签的复选框，用于输入布尔数据。与`Spinbox`和`Combobox`不同，它不是从`Entry`小部件派生的，其参数如下所示：

+   `text`：此参数设置小部件的标签。

+   `variable`：此参数是`BooleanVar`，绑定了复选框的选中状态。

+   `textvariable`：与基于`Entry`的小部件不同，此参数可用于将变量绑定到小部件的标签文本。您不会经常使用它，但您应该知道它存在，以防您错误地将变量分配给它。

您可以执行以下代码来创建一个`Checkbutton`小部件：

```py
my_checkbutton = ttk.Checkbutton(
    parent, text="Check to make this option True",
    variable=my_boolean_var)
```

`Checkbox`小部件显示为一个带有标签的可点击框，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/8a97f210-253f-438e-afb5-b7f49e04fed9.png)

# 文本小部件

`Text`小部件不仅仅是一个多行`Entry`小部件。它具有强大的标记系统，允许您实现多彩的文本，超链接样式的可点击文本等。与其他小部件不同，它不能绑定到 Tkinter 的`StringVar`，因此设置或检索其内容需要通过其`get()`、`insert()`和`delete()`方法来完成。

在使用这些方法进行读取或修改时，您需要传入一个或两个**索引**值来选择您要操作的字符或字符范围。这些索引值是字符串，可以采用以下任何格式：

+   由点分隔的行号和字符号。行号从 1 开始，字符从 0 开始，因此第一行上的第一个字符是`1.0`，而第四行上的第十二个字符将是`4.11`。

+   `end`字符串或 Tkinter 常量`END`，表示字段的结束。

+   一个数字索引加上单词`linestart`、`lineend`、`wordstart`和`wordend`中的一个，表示相对于数字索引的行或单词的开始或结束。例如，`6.2 wordstart`将是包含第六行第三个字符的单词的开始；`2.0 lineend`将是第二行的结束。

+   前述任何一个，加上加号或减号运算符，以及一定数量的字符或行。例如，`2.5 wordend - 1 chars`将是第二行第六个字符所在的单词结束前的字符。

以下示例显示了使用`Text`小部件的基础知识：

```py
# create the widget.  Make sure to save a reference.
mytext = tk.Text(parent)

# insert a string at the beginning
mytext.insert('1.0', "I love my text widget!")

# insert a string into the current text
mytext.insert('1.2', 'REALLY ')

# get the whole string
mytext.get('1.0', tk.END)

# delete the last character.
# Note that there is always a newline character
# at the end of the input, so we backup 2 chars.
mytext.delete('end - 2 chars')
```

运行上述代码，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/52c2e54d-1453-4eee-99a0-70c08c082001.png)

在这个表单中的`Notes`字段中，我们只需要一个简单的多行`Entry`；所以，我们现在只会使用`Text`小部件的最基本功能。

# 按钮小部件

`ttk.Button`小部件也应该很熟悉。它只是一个可以用鼠标或空格键单击的简单按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/83d80f01-f102-4d59-878d-c674bf8a3d54.png)

就像`Checkbutton`小部件一样，此小部件使用`text`和`textvariable`配置选项来控制按钮上的标签。`Button`对象不接受`variable`，但它们确实接受`command`参数，该参数指定单击按钮时要运行的 Python 函数。

以下示例显示了`Button`对象的使用：

```py
tvar = tk.StringVar()
def swaptext():
    if tvar.get() == 'Hi':
        tvar.set('There')
    else:
        tvar.set('Hi')

my_button = ttk.Button(parent, textvariable=tvar, command=swaptext)
```

# LabelFrame 小部件

我们选择了`ttk.LabelFrame`小部件来对我们的应用程序中的字段进行分组。顾名思义，它是一个带有标签的`Frame`（通常带有一个框）。`LabelFrame`小部件在构造函数中接受一个`text`参数，用于设置标签，该标签位于框架的左上角。

Tkinter 和`ttk`包含许多其他小部件，其中一些我们将在本书的后面遇到。Python 还附带了一个名为`tix`的小部件库，其中包含几十个小部件。但是，`tix`已经非常过时，我们不会在本书中涵盖它。不过，您应该知道它的存在。

# 实现应用程序

要启动我们的应用程序脚本，请创建一个名为`ABQ data entry`的文件夹，并在其中创建一个名为`data_entry_app.py`的文件。

我们将从以下样板代码开始：

```py
import tkinter as tk
from tkinter import ttk

# Start coding here

class Application(tk.Tk):
    """Application root window"""

if __name__ == "__main__":
    app = Application()
    app.mainloop()
```

运行此脚本应该会给您一个空白的 Tk 窗口。

# 使用 LabelInput 类节省一些时间

我们表单上的每个`input`小部件都有一个与之关联的标签。在一个小应用程序中，我们可以分别创建标签和输入，然后将每个标签添加到`parent`框架中，如下所示：

```py
form = Frame()
label = Label(form, text='Name')
name_input = Entry(form)
label.grid(row=0, column=0)
name_input.grid(row=1, column=0)
```

这样做很好，你可以为你的应用程序这样做，但它也会创建大量乏味、重复的代码，并且移动输入意味着改变两倍的代码。由于`label`和`input`小部件是一起的，创建一个小的包装类来包含它们并建立一些通用默认值会很聪明。

在编码时，要注意包含大量重复代码的部分。您通常可以将此代码抽象为类、函数或循环。这样做不仅可以节省您的输入，还可以确保一致性，并减少您需要维护的代码总量。

让我们看看以下步骤：

1.  我们将这个类称为`LabelInput`，并在我们的代码顶部定义它，就在`Start coding here`注释下面：

```py
"""Start coding here"""
class LabelInput(tk.Frame):
    """A widget containing a label and input together."""

    def __init__(self, parent, label='', input_class=ttk.Entry,
         input_var=None, input_args=None, label_args=None,
         **kwargs):
        super().__init__(parent, **kwargs)
        input_args = input_args or {}
        label_args = label_args or {}
        self.variable = input_var
```

1.  我们将基于`Tkinter.Frame`类，就像我们在`HelloWidget`中所做的一样。我们的构造函数接受以下参数：

+   `parent`：这个参数是对`parent`小部件的引用；我们创建的所有小部件都将以此作为第一个参数。

+   `label`：这是小部件标签部分的文本。

+   `input_class`：这是我们想要创建的小部件类。它应该是一个实际的可调用类对象，而不是一个字符串。如果留空，将使用`ttk.Entry`。

+   `input_var`：这是一个 Tkinter 变量，用于分配输入。这是可选的，因为有些小部件不使用变量。

+   `input_args`：这是`input`构造函数的任何额外参数的可选字典。

+   `label_args`：这是`label`构造函数的任何额外参数的可选字典。

+   `**kwargs`：最后，我们在`**kwargs`中捕获任何额外的关键字参数。这些将传递给`Frame`构造函数。

1.  在构造函数中，我们首先调用`super().__init__()`，并传入`parent`和额外的关键字参数。然后，我们确保`input_args`和`label_args`都是字典，并将我们的输入变量保存为`self.variable`的引用。

不要诱使使用空字典（`{}`）作为方法关键字参数的默认值。如果这样做，当方法定义被评估时会创建一个字典，并被类中的所有对象共享。这会对您的代码产生一些非常奇怪的影响！接受的做法是对于可变类型如字典和列表，传递`None`，然后在方法体中用空容器替换`None`。

1.  我们希望能够使用任何类型的`input`小部件，并在我们的类中适当处理它；不幸的是，正如我们之前学到的那样，不同小部件类的构造函数参数和行为之间存在一些小差异，比如`Combobox`和`Checkbutton`使用它们的`textvariable`参数的方式。目前，我们只需要区分`Button`和`Checkbutton`等按钮小部件处理变量和标签文本的方式。为了处理这个问题，我们将添加以下代码：

```py
        if input_class in (ttk.Checkbutton, ttk.Button, 
        ttk.Radiobutton):
            input_args["text"] = label
            input_args["variable"] = input_var
        else:
            self.label = ttk.Label(self, text=label, **label_args)
            self.label.grid(row=0, column=0, sticky=(tk.W + tk.E))
            input_args["textvariable"] = input_var
```

1.  对于按钮类型的小部件，我们以不同的方式执行以下任务：

+   我们不是添加一个标签，而是设置`text`参数。所有按钮都使用这个参数来添加一个`label`到小部件中。

+   我们将变量分配给`variable`，而不是分配给`textvariable`。

1.  对于其他`input`类，我们设置`textvariable`并创建一个`Label`小部件，将其添加到`LabelInput`类的第一行。

1.  现在我们需要创建`input`类，如下所示：

```py
        self.input = input_class(self, **input_args)
        self.input.grid(row=1, column=0, sticky=(tk.W + tk.E))
```

1.  这很简单：我们用扩展为关键字参数的`input_args`字典调用传递给构造函数的`input_class`类。然后，我们将其添加到第`1`行的网格中。

1.  最后，我们配置`grid`布局，将我们的单列扩展到整个小部件，如下所示：

```py
        self.columnconfigure(0, weight=1)
```

1.  当创建自定义小部件时，我们可以做的一件好事是为其几何管理器方法添加默认值，这将节省我们大量的编码。例如，我们将希望所有的`LabelInput`对象填充它们所放置的整个网格单元。我们可以通过覆盖方法将`sticky=(tk.W + tk.E)`添加为默认值，而不是在每个`LabelInput.grid()`调用中添加它：

```py
    def grid(self, sticky=(tk.E + tk.W), **kwargs):
        super().grid(sticky=sticky, **kwargs)
```

通过将其定义为默认参数，我们仍然可以像往常一样覆盖它。所有`input`小部件都有一个`get()`方法，返回它们当前的值。为了节省一些重复的输入，我们将在`LabelInput`类中实现一个`get()`方法，它将简单地将请求传递给输入或其变量。接下来添加这个方法：

```py
    def get(self):
        try:
            if self.variable:
                return self.variable.get()
            elif type(self.input) == tk.Text:
                return self.input.get('1.0', tk.END)
            else:
                return self.input.get()
        except (TypeError, tk.TclError):
            # happens when numeric fields are empty.
            return ''
```

我们在这里使用`try`块，因为在某些条件下，例如当数字字段为空时（空字符串无法转换为数字值），Tkinter 变量将抛出异常，如果调用`get()`。在这种情况下，我们将简单地从表单中返回一个空值。此外，我们需要以不同的方式处理`tk.Text`小部件，因为它们需要一个范围来检索文本。我们总是希望从这个表单中获取所有文本，所以我们在这里指定。作为`get()`的补充，我们将实现一个`set()`方法，将请求传递给变量或小部件，如下所示：

```py
    def set(self, value, *args, **kwargs):
        if type(self.variable) == tk.BooleanVar:
                self.variable.set(bool(value))
        elif self.variable:
                self.variable.set(value, *args, **kwargs)
        elif type(self.input) in (ttk.Checkbutton, 
        ttk.Radiobutton):
            if value:
                self.input.select()
            else:
                self.input.deselect()
        elif type(self.input) == tk.Text:
            self.input.delete('1.0', tk.END)
            self.input.insert('1.0', value)
        else: # input must be an Entry-type widget with no variable
            self.input.delete(0, tk.END)
            self.input.insert(0, value)
```

`.set()`方法抽象了各种 Tkinter 小部件设置其值的差异：

+   如果我们有一个`BooleanVar`类的变量，将`value`转换为`bool`并设置它。`BooleanVar.set()`只接受`bool`，而不是其他假值或真值。这确保我们的变量只获得实际的布尔值。

+   如果我们有任何其他类型的变量，只需将`value`传递给其`.set()`方法。

+   如果我们没有变量，并且是一个按钮样式的类，我们使用`.select()`和`.deselect()`方法来根据变量的真值选择和取消选择按钮。

+   如果它是一个`tk.Text`类，我们可以使用它的`.delete`和`.insert`方法。

+   否则，我们使用`input`的`.delete`和`.insert`方法，这些方法适用于`Entry`、`Spinbox`和`Combobox`类。我们必须将这个与`tk.Text`输入分开，因为索引值的工作方式不同。

这可能并不涵盖每种可能的`input`小部件，但它涵盖了我们计划使用的以及我们以后可能需要的一些。虽然构建`LabelInput`类需要很多工作，但我们将看到现在定义表单要简单得多。

# 构建表单

我们不直接在主应用程序窗口上构建我们的表单，而是将我们的表单构建为自己的对象。最初，这样做可以更容易地维护一个良好的布局，而在将来，这将使我们更容易扩展我们的应用程序。让我们执行以下步骤来构建我们的表单：

1.  一旦再次子类化`Tkinter.Frame`来构建这个模块。在`LabelInput`类定义之后，开始一个新的类，如下所示：

```py
class DataRecordForm(tk.Frame):
    """The input form for our widgets"""

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
```

这应该现在很熟悉了。我们子类化`Frame`，定义我们的构造函数，并调用`super().__init__()`来初始化底层的`Frame`对象。

1.  现在我们将创建一个结构来保存表单中所有`input`小部件的引用，如下所示：

```py
        # A dict to keep track of input widgets
        self.inputs = {}
```

在创建`input`小部件时，我们将在字典中存储对它们的引用，使用字段名作为键。这将使我们以后更容易检索所有的值。

# 添加 LabelFrame 和其他小部件

我们的表单被分成了带有标签和框的各个部分。对于每个部分，我们将创建一个`LabelFrame`小部件，并开始向其中添加我们的`LabelInput`小部件，执行以下步骤：

1.  让我们从执行以下代码开始记录信息框架：

```py
        recordinfo = tk.LabelFrame(self, text="Record Information")
```

记住，`LabelFrame`的`text`参数定义了标签的文本。这个小部件将作为记录信息组中所有输入的`parent`小部件传递。

1.  现在，我们将添加`input`小部件的第一行，如下所示：

```py
        self.inputs['Date'] = LabelInput(recordinfo, "Date",
            input_var=tk.StringVar())
        self.inputs['Date'].grid(row=0, column=0)

        self.inputs['Time'] = LabelInput(recordinfo, "Time",
            input_class=ttk.Combobox, input_var=tk.StringVar(),
            input_args={"values": ["8:00", "12:00", "16:00", "20:00"]})
        self.inputs['Time'].grid(row=0, column=1)

        self.inputs['Technician'] = LabelInput(recordinfo, 
        "Technician",
            input_var=tk.StringVar())
        self.inputs['Technician'].grid(row=0, column=2)
```

1.  `Date`和`Technician`输入是简单的文本输入；我们只需要将`parent`，`label`和`input`变量传递给我们的`LabelInput`构造函数。对于`Time`输入，我们指定一个可能值的列表，这些值将用于初始化`Combobox`小部件。

1.  让我们按照以下方式处理第 2 行：

```py
        # line 2
        self.inputs['Lab'] = LabelInput(recordinfo, "Lab",
            input_class=ttk.Combobox, input_var=tk.StringVar(),
            input_args={"values": ["A", "B", "C", "D", "E"]})
        self.inputs['Lab'].grid(row=1, column=0)

       self.inputs['Plot'] = LabelInput(recordinfo, "Plot",
            input_class=ttk.Combobox, input_var=tk.IntVar(),
           input_args={"values": list(range(1, 21))})
        self.inputs['Plot'].grid(row=1, column=1)

        self.inputs['Seed sample'] = LabelInput(
            recordinfo, "Seed sample", input_var=tk.StringVar())
        self.inputs['Seed sample'].grid(row=1, column=2)

        recordinfo.grid(row=0, column=0, sticky=tk.W + tk.E)
```

1.  这里，我们有两个`Combobox`小部件和另一个`Entry`。这些创建方式与第 1 行中的方式类似。`Plot`的值只需要是 1 到 20 的数字列表；我们可以使用 Python 内置的`range()`函数创建它。完成记录信息后，我们通过调用`grid()`将其`LabelFrame`添加到表单小部件。其余字段以基本相同的方式定义。例如，我们的环境数据将如下所示：

```py
        # Environment Data
        environmentinfo = tk.LabelFrame(self, text="Environment Data")
        self.inputs['Humidity'] = LabelInput(
            environmentinfo, "Humidity (g/m³)",
            input_class=tk.Spinbox, input_var=tk.DoubleVar(),
            input_args={"from_": 0.5, "to": 52.0, "increment": .01})
        self.inputs['Humidity'].grid(row=0, column=0)
```

1.  在这里，我们添加了我们的第一个`Spinbox`小部件，指定了有效范围和增量；您可以以相同的方式添加`Light`和`Temperature`输入。请注意，我们的`grid()`坐标已经从`0, 0`重新开始；这是因为我们正在开始一个新的父对象，所以坐标重新开始。

所有这些嵌套的网格可能会让人困惑。请记住，每当在小部件上调用`.grid()`时，坐标都是相对于小部件父级的左上角。父级的坐标是相对于其父级的，依此类推，直到根窗口。

这一部分还包括唯一的`Checkbutton`小部件：

```py
        self.inputs['Equipment Fault'] = LabelInput(
            environmentinfo, "Equipment Fault",
            input_class=ttk.Checkbutton,
            input_var=tk.BooleanVar())
        self.inputs['Equipment Fault'].grid(
            row=1, column=0, columnspan=3)
```

1.  对于`Checkbutton`，没有真正的参数可用，尽管请注意我们使用`BooleanVar`来存储其值。现在，我们继续进行植物数据部分：

```py
        plantinfo = tk.LabelFrame(self, text="Plant Data")

        self.inputs['Plants'] = LabelInput(
            plantinfo, "Plants",
            input_class=tk.Spinbox,
            input_var=tk.IntVar(),
            input_args={"from_": 0, "to": 20})
        self.inputs['Plants'].grid(row=0, column=0)

        self.inputs['Blossoms'] = LabelInput(
            plantinfo, "Blossoms",
            input_class=tk.Spinbox,
            input_var=tk.IntVar(),
            input_args={"from_": 0, "to": 1000})
        self.inputs['Blossoms'].grid(row=0, column=1)
```

请注意，与我们的十进制`Spinboxes`不同，我们没有为整数字段设置增量；这是因为它默认为`1.0`，这正是我们想要的整数字段。

1.  尽管从技术上讲`Blossoms`没有最大值，但我们也使用`1000`作为最大值；我们的`Lab` `Technicians`向我们保证它永远不会接近 1000。由于`Spinbox`需要`to`和`from_`，如果我们使用其中一个，我们将使用这个值。

您还可以指定字符串`infinity`或`-infinity`作为值。这些可以转换为`float`值，其行为是适当的。

1.  `Fruit`字段和三个`Height`字段将与这些基本相同。继续创建它们，确保遵循适当的`input_args`值和`input_var`类型的数据字典。通过添加以下注释完成我们的表单字段：

```py
# Notes section
self.inputs['Notes'] = LabelInput(
    self, "Notes",
    input_class=tk.Text,
    input_args={"width": 75, "height": 10}
)
self.inputs['Notes'].grid(sticky="w", row=3, column=0)
```

1.  这里不需要`LabelFrame`，因此我们只需将注释的`LabelInput`框直接添加到表单中。`Text`小部件采用`width`和`height`参数来指定框的大小。我们将为注释输入提供一个非常大的尺寸。

# 从我们的表单中检索数据

现在我们已经完成了表单，我们需要一种方法来从中检索数据，以便应用程序对其进行处理。我们将创建一个返回表单数据字典的方法，并且与我们的`LabelInput`对象一样，遵循 Tkinter 的约定将其命名为`get()`。

在你的表单类中添加以下方法：

```py
    def get(self):
        data = {}
        for key, widget in self.inputs.items():
            data[key] = widget.get()
        return data
```

代码很简单：我们遍历包含我们的`LabelInput`对象的实例的`inputs`对象，并通过对每个变量调用`get()`来构建一个新字典。

这段代码展示了可迭代对象和一致命名方案的强大之处。如果我们将输入存储为表单的离散属性，或者忽略了规范化`get()`方法，我们的代码将不够优雅。

# 重置我们的表单

我们的表单类几乎完成了，但还需要一个方法。在每次保存表单后，我们需要将其重置为空字段；因此，让我们通过执行以下步骤添加一个方法来实现：

1.  将此方法添加到表单类的末尾：

```py
    def reset(self):
        for widget in self.inputs.values():
            widget.set('')
```

1.  与我们的`get()`方法一样，我们正在遍历`input`字典并将每个`widget`设置为空值。

1.  为了确保我们的应用程序行为一致，我们应该在应用程序加载后立即调用`reset()`，清除我们可能不想要的任何`Tk`默认设置。

1.  回到`__init__()`的最后一行，并添加以下代码行：

```py
        self.reset()
```

# 构建我们的应用程序类

让我们看看构建我们的应用程序类的以下步骤：

1.  在`Application`类文档字符串（读作`Application root window`的行）下面移动，并开始为`Application`编写一个`__init__()`方法，如下所示：

```py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.title("ABQ Data Entry Application")
        self.resizable(width=False, height=False)
```

1.  再次调用`super().__init__()`，传递任何参数或关键字参数。

请注意，我们这里没有传入`parent`小部件，因为`Application`是根窗口。

1.  我们调用`.title()`来设置我们应用程序的标题字符串；这不是必需的，但它肯定会帮助运行多个应用程序的用户快速在他们的桌面环境中找到我们的应用程序。

1.  我们还通过调用`self.resizable`禁止窗口的调整大小。这也不是严格必要的，但它使我们暂时更容易控制我们的布局。让我们开始添加我们的应用程序组件，如下所示：

```py
        ttk.Label(
            self,
            text="ABQ Data Entry Application",
            font=("TkDefaultFont", 16)
        ).grid(row=0)
```

1.  应用程序将从顶部开始，显示一个`Label`对象，以比正常字体大的字体显示应用程序的名称。请注意，我们这里没有指定`column`；我们的主应用程序布局只有一列，所以没有必要严格指定`column`，因为它默认为`0`。接下来，我们将添加我们的`DataRecordForm`如下：

```py
        self.recordform = DataRecordForm(self)
        self.recordform.grid(row=1, padx=10)
```

1.  我们使用`padx`参数向左和向右添加了 10 像素的填充。这只是在表单的边缘周围添加了一些空白，使其更易读。

1.  接下来，让我们添加保存按钮，如下所示：

```py
        self.savebutton = ttk.Button(self, text="Save", 
        command=self.on_save)
        self.savebutton.grid(sticky=tk.E, row=2, padx=10)
```

1.  我们给按钮一个`command`值为`self.on_save`；我们还没有编写该方法，所以在运行代码之前我们需要这样做。

当编写用于 GUI 事件的方法或函数时，惯例是使用格式`on_EVENTNAME`，其中`EVENTNAME`是描述触发它的事件的字符串。我们也可以将此方法命名为`on_save_button_click()`，但目前`on_save()`就足够了。

1.  最后，让我们添加状态栏，如下所示：

```py
        # status bar
        self.status = tk.StringVar()
        self.statusbar = ttk.Label(self, textvariable=self.status)
        self.statusbar.grid(sticky=(tk.W + tk.E), row=3, padx=10)
```

1.  我们首先创建一个名为`self.status`的字符串变量，并将其用作`ttk.Label`的`textvariable`。我们的应用程序只需要在类内部调用`self.status.set()`来更新状态。通过将状态栏添加到应用程序小部件的底部，我们的 GUI 完成了。

# 保存到 CSV

当用户点击保存时，需要发生以下一系列事件：

1.  打开一个名为`abq_data_record_CURRENTDATE.csv`的文件

1.  如果文件不存在，它将被创建，并且字段标题将被写入第一行

1.  数据字典从`DataEntryForm`中检索

1.  数据被格式化为 CSV 行并附加到文件

1.  表单被清除，并通知用户记录已保存

我们将需要一些其他 Python 库来帮助我们完成这个任务：

1.  首先，我们需要一个用于我们文件名的日期字符串。Python 的`datetime`库可以帮助我们。

1.  接下来，我们需要能够检查文件是否存在。Python 的`os`库有一个用于此的函数。

1.  最后，我们需要能够写入 CSV 文件。Python 在标准库中有一个 CSV 库，这里非常适用。

让我们看看以下步骤：

1.  回到文件顶部，并在 Tkinter 导入之前添加以下导入：

```py
from datetime import datetime
import os
import csv
```

1.  现在，回到`Application`类，并开始`on_save()`方法，如下所示：

```py
   def on_save(self):
        datestring = datetime.today().strftime("%Y-%m-%d")
        filename = "abq_data_record_{}.csv".format(datestring)
        newfile = not os.path.exists(filename)
```

1.  我们要做的第一件事是创建我们的日期字符串。`datetime.today()`方法返回当前日期的午夜`datetime`；然后我们使用`strftime()`将其格式化为年-月-日的 ISO 日期字符串（使用数字 01 到 12 表示月份）。这将被插入到我们规范的文件名模板中，并保存为`filename`。

1.  接下来，我们需要确定文件是否已经存在；`os.path.exists()`将返回一个布尔值，指示文件是否存在；我们对这个值取反，并将其存储为`newfile`。

1.  现在，让我们从`DataEntryForm`获取数据：

```py
        data = self.recordform.get()
```

1.  获得数据后，我们需要打开文件并将数据写入其中。添加以下代码：

```py
        with open(filename, 'a') as fh:
            csvwriter = csv.DictWriter(fh, fieldnames=data.keys())
            if newfile:
                csvwriter.writeheader()
            csvwriter.writerow(data)
```

`with open(filename, 'a') as fh:`语句以追加模式打开我们生成的文件名，并为我们提供一个名为`fh`的文件句柄。追加模式意味着我们不能读取或编辑文件中的任何现有行，只能添加到文件的末尾，这正是我们想要的。

`with`关键字与**上下文管理器**对象一起使用，我们调用`open()`返回的就是这样的对象。上下文管理器是特殊的对象，它定义了在`with`块之前和之后要运行的代码。通过使用这种方法打开文件，它们将在块结束时自动正确关闭。

1.  接下来，我们使用文件句柄创建一个`csv.DictWriter`对象。这个对象将允许我们将数据字典写入 CSV 文件，将字典键与 CSV 的标题行标签匹配。这对我们来说比默认的 CSV 写入对象更好，后者每次都需要正确顺序的字段。

1.  要配置这一点，我们首先必须将`fieldnames`参数传递给`DictWriter`构造函数。我们的字段名称是从表单中获取的`data`字典的键。如果我们正在处理一个新文件，我们需要将这些字段名称写入第一行，我们通过调用`DictWriter.writeheader()`来实现。

1.  最后，我们使用`DictWriter`对象的`.writerow()`方法将我们的`data`字典写入新行。在代码块的末尾，文件会自动关闭和保存。

# 完成和测试

此时，您应该能够运行应用程序，输入数据，并将其保存到 CSV 文件中。试试看！您应该会看到类似以下截图的东西：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/9708ab24-6d9f-4276-935b-454f6110dc31.png)

也许您注意到的第一件事是，单击保存没有明显的效果。表单保持填充状态，没有任何指示已经完成了什么。我们应该修复这个问题。

我们将执行以下两件事来帮助这里：

1.  首先，在我们的状态栏中放置一个通知，说明记录已保存以及本次会话已保存多少条记录。对于第一部分，将以下代码行添加到`Application`构造函数的末尾，如下所示：

```py
        self.records_saved = 0
```

1.  其次，在保存后清除表单，以便可以开始下一个记录。然后将以下代码行添加到`on_save()`方法的末尾，如下所示：

```py
        self.records_saved += 1
        self.status.set(
            "{} records saved this session".format(self.records_saved))
```

这段代码设置了一个计数器变量，用于跟踪自应用程序启动以来保存的记录数。

1.  保存文件后，我们增加值，然后设置我们的状态以指示已保存多少条记录。用户将能够看到这个数字增加，并知道他们的按钮点击已经做了一些事情。

1.  接下来，我们将在保存后重置表单。将以下代码追加到`Application.on_save()`的末尾，如下所示：

```py
        self.recordform.reset()
```

这将清空表单，并准备好下一个记录的输入。

1.  现在，再次运行应用程序。它应该清除并在保存记录时给出状态指示。

# 摘要

嗯，我们在这一章取得了长足的进步！您将您的设计从规范和一些图纸转化为一个运行的应用程序，它已经涵盖了您需要的基本功能。您学会了如何使用基本的 Tkinter 和`ttk`小部件，并创建自定义小部件，以节省大量重复的工作。

在下一章中，我们将解决`input`小部件的问题。我们将学习如何自定义`input`小部件的行为，防止错误的按键，并验证数据，以确保它在我们规范中规定的容差范围内。在此过程中，我们将深入研究 Python 类，并学习更多高效和优雅的代码技巧。


# 第四章：通过验证和自动化减少用户错误

我们的表单有效，主管和数据输入人员都对表单设计感到满意，但我们还没有准备好投入生产！我们的表单还没有履行承诺的任务，即防止或阻止用户错误。数字框仍然允许字母，组合框不限于给定的选择，日期必须手动填写。在本章中，我们将涵盖以下主题：

+   决定验证用户输入的最佳方法

+   学习如何使用 Tkinter 的验证系统

+   为我们的表单创建自定义小部件，验证输入的数据

+   在我们的表单中适当的情况下自动化默认值

让我们开始吧！

# 验证用户输入

乍一看，Tkinter 的输入小部件选择似乎有点令人失望。它没有给我们一个真正的数字输入，只允许数字，也没有一个真正的下拉选择器，只允许从下拉列表中选择项目。我们没有日期输入、电子邮件输入或其他特殊格式的输入小部件。

但这些弱点可以成为优势。因为这些小部件什么都不假设，我们可以使它们以适合我们特定需求的方式行为，而不是以可能或可能不会最佳地工作的通用方式。例如，字母在数字输入中可能看起来不合适，但它们呢？在 Python 中，诸如`NaN`和`Infinity`之类的字符串是有效的浮点值；拥有一个既可以增加数字又可以处理这些字符串值的框在某些应用中可能非常有用。

我们将学习如何根据需要调整我们的小部件，但在学习如何控制这种行为之前，让我们考虑一下我们想要做什么。

# 防止数据错误的策略

对于小部件如何响应用户尝试输入错误数据，没有通用答案。各种图形工具包中的验证逻辑可能大不相同；当输入错误数据时，输入小部件可能会验证用户输入如下：

+   防止无效的按键注册

+   接受输入，但在提交表单时返回错误或错误列表

+   当用户离开输入字段时显示错误，可能会禁用表单提交，直到它被纠正

+   将用户锁定在输入字段中，直到输入有效数据

+   使用最佳猜测算法悄悄地纠正错误的数据

数据输入表单中的正确行为（每天由甚至可能根本不看它的用户填写数百次）可能与仪器控制面板（值绝对必须正确以避免灾难）或在线用户注册表单（用户以前从未见过的情况下填写一次）不同。我们需要向自己和用户询问哪种行为将最大程度地减少错误。

与数据输入人员讨论后，您得出以下一组指南：

+   尽可能忽略无意义的按键（例如数字字段中的字母）

+   空字段应该注册一个错误（所有字段都是必填的），但`Notes`除外

+   包含错误数据的字段应以某种可见的方式标记，并描述问题

+   如果存在错误字段，则应禁用表单提交

让我们在继续之前，将以下要求添加到我们的规范中。在“必要功能”部分，更新硬性要求如下：

```py
The program must:
...
* have inputs that:
  - ignore meaningless keystrokes
  - require a value for all fields, except Notes
  - get marked with an error if the value is invalid on focusout
* prevent saving the record when errors are present

```

那么，我们如何实现这一点呢？

# Tkinter 中的验证

Tkinter 的验证系统是工具包中不太直观的部分之一。它依赖于以下三个配置选项，我们可以将其传递到任何输入小部件中：

+   `validate`：此选项确定哪种类型的事件将触发验证回调

+   `validatecommand`：此选项接受将确定数据是否有效的命令

+   `invalidcommand`：此选项接受一个命令，如果`validatecommand`返回`False`，则运行该命令

这似乎很简单，但有一些意想不到的曲线。

我们可以传递给`validate`的值如下：

| **验证字符串** | **触发时** |
| --- | --- |
| `none` | 它是关闭验证的无 |
| `focusin` | 用户输入或选择小部件 |
| `unfocus` | 用户离开小部件 |
| `focus` | `focusin`或`focusout` |
| `key` | 用户在小部件中输入文本 |
| `all` | `focusin`，`focusout`和`key` |

`validatecommand`参数是事情变得棘手的地方。您可能会认为这需要 Python 函数或方法的名称，但事实并非如此。相反，我们需要给它一个包含对 Tcl/`Tk`函数的引用的元组，并且可以选择一些**替换代码**，这些代码指定我们要传递到函数中的触发事件的信息。

我们如何获得对 Tcl/`Tk`函数的引用？幸运的是，这并不太难；我们只需将 Python 可调用对象传递给任何 Tkinter 小部件的`.register（）`方法。这将返回一个字符串，我们可以在`validatecommand`中使用。

当然，除非我们传入要验证的数据，否则验证函数没有什么用。为此，我们向我们的`validatecommand`元组添加一个或多个替换代码。

这些代码如下：

| **代码** | **传递的值** |
| --- | --- |
| “％d” | 指示正在尝试的操作的代码：`0`表示`delete`，`1`表示插入，`-1`表示其他事件。请注意，这是作为字符串而不是整数传递的。 |
| “％P” | 更改后字段将具有的建议值（仅限键事件）。 |
| “％s” | 字段中当前的值（仅限键事件）。 |
| “％i” | 在键事件上插入或删除的文本的索引（从`0`开始），或在非键事件上为`-1`。请注意，这是作为字符串而不是整数传递的。 |
| “％S” | 对于插入或删除，正在插入或删除的文本（仅限键事件）。 |
| “％v” | 小部件的“验证”值。 |
| “％V” | 触发验证的事件：`focusin`，`focusout`，`key`或`forced`（表示文本变量已更改）。 |
| “％W” | Tcl/`Tk`中小部件的名称，作为字符串。 |

`invalidcommand`选项的工作方式完全相同，需要使用`.register（）`方法和替换代码。

要查看这些内容是什么样子，请考虑以下代码，用于仅接受五个字符的`Entry`小部件：

```py
def has_five_or_less_chars(string):
    return len(string) <= 5

wrapped_function = root.register(has_five_or_less_chars)
vcmd = (wrapped_function, '%P')
five_char_input = ttk.Entry(root, validate='key', validatecommand=vcmd)
```

在这里，我们创建了一个简单的函数，它只返回字符串的长度是否小于或等于五个字符。然后，我们使用“register（）”方法将此函数注册到`Tk`，将其引用字符串保存为`wrapped_function`。接下来，我们使用引用字符串和“'％P'”替换代码构建我们的`validatecommand`元组，该替换代码表示建议的值（如果接受键事件，则输入将具有的值）。

您可以传入任意数量的替换代码，并且可以按任何顺序，只要您的函数是写入接受这些参数的。最后，我们将创建我们的`Entry`小部件，将验证类型设置为`key`，并传入我们的验证命令元组。

请注意，在这种情况下，我们没有定义`invalidcommand`方法；当通过按键触发验证时，从`validate`命令返回`False`将导致忽略按键。当通过焦点或其他事件类型触发验证时，情况并非如此；在这种情况下，没有定义默认行为，需要`invalidcommand`方法。

考虑以下`FiveCharEntry`的替代基于类的版本，它允许您输入任意数量的文本，但在离开字段时会截断您的文本：

```py
class FiveCharEntry2(ttk.Entry):
    """An Entry that truncates to five characters on exit."""

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.config(
            validate='focusout',
            validatecommand=(self.register(self._validate), '%P'),
            invalidcommand=(self.register(self._on_invalid),)
        )

    def _validate(self, proposed_value):
        return len(proposed_value) <= 5

    def _on_invalid(self):
        self.delete(5, tk.END)
```

这一次，我们通过对`Entry`进行子类化并在方法中定义我们的验证逻辑来实现验证，而不是在外部函数中。这简化了我们在验证方法中访问小部件。

`_validate()`和`_on_invalid()`开头的下划线表示这些是内部方法，只能在类内部访问。虽然这并不是必要的，而且 Python 并不会将其与普通方法区别对待，但它让其他程序员知道这些方法是供内部使用的，不应该在类外部调用。

我们还将`validate`参数更改为`focusout`，并添加了一个`_on_invalid()`方法，该方法将使用`Entry`小部件的`delete()`方法截断值。每当小部件失去焦点时，将调用`_validate()`方法并传入输入的文本。如果失败，将调用`_on_invalid()`，导致内容被截断。

# 创建一个 DateEntry 小部件

让我们尝试创建一个验证版本的`Date`字段。我们将创建一个`DateEntry`小部件，它可以阻止大多数错误的按键，并在`focusout`时检查日期的有效性。如果日期无效，我们将以某种方式标记该字段并显示错误。让我们执行以下步骤来完成相同的操作：

1.  打开一个名为`DateEntry.py`的新文件，并从以下代码开始：

```py
from datetime import datetime

class DateEntry(ttk.Entry):
    """An Entry for ISO-style dates (Year-month-day)"""

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.config(
            validate='all',
            validatecommand=(
                self.register(self._validate),
                '%S', '%i', '%V', '%d'
            ),
        invalidcommand=(self.register(self._on_invalid), '%V')
    )
    self.error = tk.StringVar()
```

1.  由于我们需要在验证方法中使用`datetime`，所以我们在这里导入它。

1.  我们对`ttk.Entry`进行子类化，然后在构造方法中开始调用`super().__init__()`，就像往常一样。

1.  接下来，我们使用`self.config()`来更改小部件的配置。你可能会想知道为什么我们没有将这些参数传递给`super().__init__()`调用；原因是直到底层的`Entry`小部件被初始化之后，`self.register()`方法才存在。

1.  我们注册以下两种方法：`self._validate`和`self._on_invalid`，我们将很快编写：

+   `_validate()`：这个方法将获取插入的文本（`%S`），插入的索引（`%i`），事件类型（`%V`）和执行的操作（`%d`）。

+   `_on_invalid()`：这个方法只会获取事件类型。由于我们希望在按键和`focusout`时进行验证，所以我们将`validate`设置为`all`。我们的验证方法可以通过查看事件类型（`%V`）来确定正在发生的事件。

1.  最后，我们创建`StringVar`来保存我们的错误文本；这将在类外部访问，所以我们不在其名称中使用前导下划线。

1.  我们创建的下一个方法是`_toggle_error()`，如下所示：

```py
def _toggle_error(self, error=''):
    self.error.set(error)
    if error:
        self.config(foreground='red')
    else:
        self.config(foreground='black')
```

1.  我们使用这种方法来在出现错误的情况下整合小部件的行为。它首先将我们的`error`变量设置为提供的字符串。如果字符串不为空，我们会打开错误标记（在这种情况下，将文本变为红色）；如果为空，我们会关闭错误标记。`_validate()`方法如下：

```py
    def _validate(self, char, index, event, action):

        # reset error state
        self._toggle_error()
        valid = True

        # ISO dates, YYYY-MM-DD, only need digits and hyphens
        if event == 'key':
            if action == '0':  # A delete event should always validate
                valid = True
            elif index in ('0', '1', '2', '3',
                           '5', '6', '8', '9'):
                valid = char.isdigit()
            elif index in ('4', '7'):
                valid = char == '-'
            else:
                valid = False
```

1.  我们要做的第一件事是切换关闭我们的错误状态，并将`valid`标志设置为`True`。我们的输入将是“无罪直到被证明有罪”。

1.  然后，我们将查看按键事件。`if action == '0':`告诉我们用户是否尝试删除字符。我们总是希望允许这样做，以便用户可以编辑字段。

ISO 日期的基本格式是：四位数字，一个破折号，两位数字，一个破折号，和两位数字。我们可以通过检查插入的字符是否与我们在插入的`index`位置的期望相匹配来测试用户是否遵循这种格式。例如，`index in ('0', '1', '2', '3', '5', '6', '8', '9')`将告诉我们插入的字符是否是需要数字的位置之一，如果是，我们检查该字符是否是数字。索引为`4`或`7`应该是一个破折号。任何其他按键都是无效的。

尽管你可能期望它们是整数，但 Tkinter 将动作代码传递为字符串并将其索引化。在编写比较时要记住这一点。

虽然这是一个对于正确日期的幼稚的启发式方法，因为它允许完全无意义的日期，比如`0000-97-46`，或者看起来正确但仍然错误的日期，比如`2000-02-29`，但至少它强制执行了基本格式并消除了大量无效的按键。一个完全准确的部分日期分析器是一个单独的项目，所以现在这样做就可以了。

在`focusout`上检查我们的日期是否正确更简单，也更可靠，如下所示：

```py
        elif event == 'focusout':
            try:
                datetime.strptime(self.get(), '%Y-%m-%d')
            except ValueError:
                valid = False
        return valid
```

由于我们在这一点上可以访问用户打算输入的最终值，我们可以使用`datetime.strptime()`来尝试使用格式`%Y-%m-%d`将字符串转换为 Python 的`datetime`。如果失败，我们就知道日期是无效的。

结束方法时，我们返回我们的`valid`标志。

验证方法必须始终返回一个布尔值。如果由于某种原因，您的验证方法没有返回值（或返回`None`），您的验证将在没有任何错误的情况下悄悄中断。请务必确保您的方法始终返回一个布尔值，特别是如果您使用多个`return`语句。

正如您之前看到的，对于无效的按键，只需返回`False`并阻止插入字符就足够了，但对于焦点事件上的错误，我们需要以某种方式做出响应。

看一下以下代码中的`_on_invalid()`方法：

```py
    def _on_invalid(self, event):
        if event != 'key':
            self._toggle_error('Not a valid date')
```

我们只将事件类型传递给这个方法，我们将使用它来忽略按键事件（它们已经被默认行为充分处理）。对于任何其他事件类型，我们将使用我们的`_toggle_error()`方法来显示错误。

要测试我们的`DateEntry`类，请将以下测试代码添加到文件的底部：

```py
if __name__ == '__main__':
    root = tk.Tk()
    entry = DateEntry(root)
    entry.pack()
    tk.Label(textvariable=entry.error).pack()

    # add this so we can unfocus the DateEntry
    tk.Entry(root).pack()
    root.mainloop()
```

保存文件并运行它以尝试新的`DateEntry`类。尝试输入各种错误的日期或无效的按键，并看看会发生什么。

# 在我们的表单中实现验证小部件

现在您知道如何验证您的小部件，您有很多工作要做！我们有 16 个输入小部件，您将不得不为所有这些编写代码，以获得我们需要的行为。在这个过程中，您需要确保小部件对错误的响应是一致的，并向应用程序提供一致的 API。

如果这听起来像是你想无限期推迟的事情，我不怪你。也许有一种方法可以减少我们需要编写的代码量。

# 利用多重继承的力量

到目前为止，我们已经了解到 Python 允许我们通过子类化创建新的类，从超类继承特性，并只添加或更改新类的不同之处。Python 还支持**多重继承**，其中子类可以从多个超类继承。我们可以利用这个特性来为我们带来好处，创建所谓的**混合**类。

混合类只包含我们想要能够与其他类混合以组成新类的特定功能集。

看一下以下示例代码：

```py
class Displayer():

    def display(self, message):
        print(message)

class LoggerMixin():

    def log(self, message, filename='logfile.txt'):
        with open(filename, 'a') as fh:
            fh.write(message)

    def display(self, message):
        super().display(message)
        self.log(message)

class MySubClass(LoggerMixin, Displayer):

    def log(self, message):
        super().log(message, filename='subclasslog.txt')

subclass = MySubClass()
subclass.display("This string will be shown and logged in subclasslog.txt.")
```

我们实现了一个名为`Displayer`的基本类，其中包含一个`display()`方法，用于打印消息。然后，我们创建了一个名为`LoggerMixin`的混合类，它添加了一个`log()`方法来将消息写入文本文件，并覆盖了`display()`方法以调用`log()`。最后，我们通过同时继承`LoggerMixin`和`Displayer`来创建一个子类。子类然后覆盖了`log()`方法并设置了不同的文件名。

当我们创建一个使用多重继承的类时，我们指定的最右边的类称为**基类**，混合类应该在它之前指定。对于混合类与任何其他类没有特殊的语法，但要注意混合类的`display()`方法中使用`super()`。从技术上讲，`LoggerMixin`继承自 Python 内置的`object`类，该类没有`display()`方法。那么，我们如何在这里调用`super().display()`呢？

在多重继承的情况下，`super()`做的事情比仅仅代表超类要复杂一些。它使用一种叫做**方法解析顺序**的东西来查找继承链，并确定定义我们调用的方法的最近的类。因此，当我们调用`MySubclass.display()`时，会发生一系列的方法解析，如下所示：

+   `MySubClass.display()`被解析为`LoggerMixin.display()`。

+   `LoggerMixin.display()`调用`super().display()`，解析为`Displayer.display()`。

+   它还调用`self.log()`。在这种情况下，`self`是一个`MySubClass`实例，所以它解析为`MySubClass.log()`。

+   `MySubClass.log()`调用`super().log()`，解析回`LoggerMixin.log()`。

如果这看起来令人困惑，只需记住`self.method()`将首先在当前类中查找`method()`，然后按照从左到右的继承类列表查找方法。`super().method()`也会这样做，只是它会跳过当前类。

类的方法解析顺序存储在它的`__mro__`属性中；如果你在 Python shell 或调试器中遇到继承方法的问题，你可以检查这个方法。

请注意，`LoggerMixin`不能单独使用：它只在与具有`display()`方法的类结合时起作用。这就是为什么它是一个 mixin 类，因为它的目的是混合到其他类中以增强它们。

# 一个验证 mixin 类

让我们运用我们对多重继承的知识来构建一个 mixin，通过执行以下步骤来给我们一些样板验证逻辑：

1.  打开`data_entry_app.py`并在`Application`类定义之前开始这个类：

```py
class ValidatedMixin:
    """Adds a validation functionality to an input widget"""

    def __init__(self, *args, error_var=None, **kwargs):
        self.error = error_var or tk.StringVar()
        super().__init__(*args, **kwargs)

```

1.  我们像往常一样开始这节课，尽管这次我们不会再继承任何东西。构造函数还有一个额外的参数叫做`error_var`。这将允许我们传入一个变量来用于错误消息；如果我们不这样做，类会创建自己的变量。调用`super().__init__()`将导致我们混合的基类执行它的构造函数。

1.  接下来，我们进行验证，如下所示：

```py
        vcmd = self.register(self._validate)
        invcmd = self.register(self._invalid)

        self.config(
            validate='all',
            validatecommand=(vcmd, '%P', '%s', '%S', '%V', '%i', '%d'),
            invalidcommand=(invcmd, '%P', '%s', '%S', '%V', '%i', '%d')
        )
```

1.  我们在这里设置了我们的`validate`和`invalid`方法。我们将继续传入所有的替换代码（除了`'%w'`，因为在类上下文中它几乎没有用）。我们对所有条件进行验证，所以我们可以捕获焦点和按键事件。

1.  现在，我们将定义我们的错误条件处理程序：

```py
    def _toggle_error(self, on=False):
        self.config(foreground=('red' if on else 'black'))
```

1.  如果有错误，这将只是将文本颜色更改为红色，否则更改为黑色。我们不在这个函数中设置错误，因为我们将希望在验证方法中设置实际的错误文本，如下所示：

```py
  def _validate(self, proposed, current, char, event, index, 
  action):
        self._toggle_error(False)
        self.error.set('')
        valid = True
        if event == 'focusout':
            valid = self._focusout_validate(event=event)
        elif event == 'key':
            valid = self._key_validate(proposed=proposed,
                current=current, char=char, event=event,
                index=index, action=action)
        return valid

    def _focusout_validate(self, **kwargs):
        return True

    def _key_validate(self, **kwargs):
        return True 
```

我们的`_validate()`方法只处理一些设置工作，比如关闭错误和清除错误消息。然后，它运行一个特定于事件的验证方法，取决于传入的事件类型。我们现在只关心`key`和`focusout`事件，所以任何其他事件都会返回`True`。

请注意，我们使用关键字调用各个方法；当我们创建我们的子类时，我们将覆盖这些方法。通过使用关键字参数，我们覆盖的函数只需指定所需的关键字或从`**kwargs`中提取单个参数，而不必按正确的顺序获取所有参数。还要注意，所有参数都传递给`_key_validate()`，但只有`event`传递给`_focusout_validate()`。焦点事件对于其他参数都没有有用的返回值，所以将它们传递下去没有意义。

1.  这里的最终想法是，我们的子类只需要覆盖我们关心的小部件的验证方法或方法。如果我们不覆盖它们，它们就会返回`True`，所以验证通过。现在，我们需要处理一个无效的事件：

```py
   def _invalid(self, proposed, current, char, event, index, 
   action):
        if event == 'focusout':
            self._focusout_invalid(event=event)
        elif event == 'key':
            self._key_invalid(proposed=proposed,
                current=current, char=char, event=event,
                index=index, action=action)

    def _focusout_invalid(self, **kwargs):
        self._toggle_error(True)

    def _key_invalid(self, **kwargs):
        pass

```

1.  我们对这些方法采取相同的方法。不像验证方法，我们的无效数据处理程序不需要返回任何内容。对于无效的键，默认情况下我们什么也不做，对于`focusout`上的无效数据，我们切换错误状态。

1.  按键验证只在输入键的情况下才有意义，但有时我们可能希望手动运行`focusout`检查，因为它有效地检查完全输入的值。因此，我们将实现以下方法：

```py
   def trigger_focusout_validation(self):
        valid = self._validate('', '', '', 'focusout', '', '')
        if not valid:
            self._focusout_invalid(event='focusout')
        return valid
```

1.  我们只是复制了`focusout`事件发生时发生的逻辑：运行验证函数，如果失败，则运行无效处理程序。这就是我们对`ValidatedMixin`所需的全部内容，所以让我们开始将其应用于一些小部件，看看它是如何工作的。

# 构建我们的小部件

让我们仔细考虑我们需要使用新的`ValidatedMixin`类实现哪些类，如下所示：

+   除了`Notes`之外，我们所有的字段都是必需的，因此我们需要一个基本的`Entry`小部件，如果没有输入，则会注册错误。

+   我们有一个`Date`字段，因此我们需要一个强制有效日期字符串的`Entry`小部件。

+   我们有一些用于十进制或整数输入的`Spinbox`小部件。我们需要确保这些只接受有效的数字字符串。

+   我们有一些`Combobox`小部件的行为不太符合我们的期望。

让我们开始吧！

# 需要数据

我们所有的字段都是必需的，所以让我们从一个需要数据的基本`Entry`小部件开始。我们可以将这些用于字段：`Technician`和`Seed sample`。

在`ValidatedMixin`类下添加以下代码：

```py
class RequiredEntry(ValidatedMixin, ttk.Entry):

    def _focusout_validate(self, event):
        valid = True
        if not self.get():
            valid = False
            self.error.set('A value is required')
        return valid
```

这里没有按键验证要做，所以我们只需要创建`_focusout_validate()`。如果输入的值为空，我们只需设置一个错误字符串并返回`False`。

就是这样了！

# 日期小部件

现在，让我们将 mixin 类应用于之前制作的`DateEntry`类，保持相同的验证算法如下：

```py
class DateEntry(ValidatedMixin, ttk.Entry):

    def _key_validate(self, action, index, char, **kwargs):
        valid = True

        if action == '0':
            valid = True
        elif index in ('0', '1', '2', '3', '5', '6', '8', '9'):
            valid = char.isdigit()
        elif index in ('4', '7'):
            valid = char == '-'
        else:
            valid = False
        return valid

    def _focusout_validate(self, event):
        valid = True
        if not self.get():
            self.error.set('A value is required')
            valid = False
        try:
            datetime.strptime(self.get(), '%Y-%m-%d')
        except ValueError:
            self.error.set('Invalid date')
            valid = False
        return valid
```

同样，非常简单，我们只需要指定验证逻辑。我们还添加了来自我们的`RequiredEntry`类的逻辑，因为`Date`值是必需的。

让我们继续进行一些更复杂的工作。

# 更好的 Combobox 小部件

不同工具包中的下拉式小部件在鼠标操作时表现相当一致，但对按键的响应有所不同，如下所示：

+   有些什么都不做

+   有些需要使用箭头键来选择项目

+   有些移动到按下任意键开始的第一个条目，并在后续按键开始的条目之间循环

+   有些会缩小列表以匹配所键入的内容

我们需要考虑我们的`Combobox`小部件应该具有什么行为。由于我们的用户习惯于使用键盘进行数据输入，有些人使用鼠标有困难，小部件需要与键盘配合使用。让他们重复按键来选择选项也不是很直观。与数据输入人员讨论后，您决定采用以下行为：

+   如果建议的文本与任何条目都不匹配，它将被忽略。

+   当建议的文本与单个条目匹配时，小部件将设置为该值

+   删除或退格会清除整个框

在`DateEntry`代码下添加此代码：

```py
class ValidatedCombobox(ValidatedMixin, ttk.Combobox):

    def _key_validate(self, proposed, action, **kwargs):
        valid = True
        # if the user tries to delete, just clear the field
        if action == '0':
            self.set('')
            return True
```

`_key_validate()`方法首先设置一个`valid`标志，并快速检查是否是删除操作。如果是，我们将值设置为空字符串并返回`True`。

现在，我们将添加逻辑来匹配建议的文本与我们的值：

```py
       # get our values list
        values = self.cget('values')
        # Do a case-insensitive match against the entered text
        matching = [
            x for x in values
            if x.lower().startswith(proposed.lower())
        ]
        if len(matching) == 0:
            valid = False
        elif len(matching) == 1:
            self.set(matching[0])
            self.icursor(tk.END)
            valid = False
        return valid
```

使用其`.cget()`方法检索小部件值列表的副本。然后，我们使用列表推导来将此列表减少到仅与建议的文本匹配的条目，对列表项和建议的文本的值调用`lower()`，以便我们的匹配不区分大小写。

每个 Tkinter 小部件都支持`.cget()`方法。它可以用来按名称检索小部件的任何配置值。

如果匹配列表的长度为`0`，我们拒绝按键。如果为`1`，我们找到了匹配，所以我们将变量设置为该值。如果是其他任何值，我们需要让用户继续输入。作为最后的修饰，如果找到匹配，我们将使用`.icursor()`方法将光标发送到字段的末尾。这并不是严格必要的，但比将光标留在文本中间看起来更好。现在，我们将添加`focusout`验证器，如下所示：

```py
    def _focusout_validate(self, **kwargs):
        valid = True
        if not self.get():
            valid = False
            self.error.set('A value is required')
        return valid
```

这里我们不需要做太多，因为关键验证方法确保唯一可能的值是空字段或值列表中的项目，但由于所有字段都需要有一个值，我们将从`RequiredEntry`复制验证。

这就处理了我们的`Combobox`小部件。接下来，我们将处理`Spinbox`小部件。

# 范围限制的 Spinbox 小部件

数字输入似乎不应该太复杂，但有许多微妙之处需要解决，以使其牢固。除了将字段限制为有效的数字值之外，您还希望将`from`、`to`和`increment`参数分别强制为输入的最小、最大和精度。

算法需要实现以下规则：

+   删除始终允许

+   数字始终允许

+   如果`from`小于`0`，则允许减号作为第一个字符

+   如果`increment`有小数部分，则允许一个点

+   如果建议的值大于`to`值，则忽略按键

+   如果建议的值需要比`increment`更高的精度，则忽略按键

+   在`focusout`时，确保值是有效的数字字符串

+   同样在`focusout`时，确保值大于`from`值

看一下以下步骤：

1.  以下是我们将如何编码，关于前面的规则：

```py
class ValidatedSpinbox(ValidatedMixin, tk.Spinbox):

    def __init__(self, *args, min_var=None, max_var=None,
                 focus_update_var=None, from_='-Infinity',    
                 to='Infinity', **kwargs):
        super().__init__(*args, from_=from_, to=to, **kwargs)
        self.resolution = Decimal(str(kwargs.get('increment',  
        '1.0')))
        self.precision = (
            self.resolution
            .normalize()
```

```py
            .as_tuple()
            .exponent
        )
```

1.  我们将首先重写`__init__()`方法，以便我们可以指定一些默认值，并从构造函数参数中获取`increment`值以进行处理。

1.  `Spinbox`参数可以作为浮点数、整数或字符串传递。无论如何传递，Tkinter 都会将它们转换为浮点数。确定浮点数的精度是有问题的，因为浮点误差的原因，所以我们希望在它变成浮点数之前将其转换为 Python `Decimal`。

浮点数尝试以二进制形式表示十进制数。打开 Python shell 并输入`1.2 / .2`。您可能会惊讶地发现答案是`5.999999999999999`而不是`6`。这被称为**浮点误差**，几乎在每种编程语言中都是计算错误的来源。Python 为我们提供了`Decimal`类，它接受一个数字字符串并以一种使数学运算免受浮点误差的方式存储它。

1.  在我们使用`Decimal`之前，我们需要导入它。在文件顶部的导入中添加以下代码：

```py
from decimal import Decimal, InvalidOperation
```

1.  `InvalidOperation`是当`Decimal`得到一个它无法解释的字符串时抛出的异常。我们稍后会用到它。

请注意，在将其传递给`Decimal`之前，我们将`increment`转换为`str`。理想情况下，我们应该将`increment`作为字符串传递，以确保它将被正确解释，但以防我们因某种原因需要传递一个浮点数，`str`将首先进行一些明智的四舍五入。

1.  我们还为`to`和`from_`设置了默认值：`-Infinity`和`Infinity`。`float`和`Decimal`都会愉快地接受这些值，并将它们视为您期望的那样处理。`Tkinter.Spinbox`的默认`to`和`from_`值为`0`；如果它们保留在那里，Tkinter 会将其视为无限制，但如果我们指定一个而不是另一个，这就会产生问题。

1.  我们提取`resolution`值的`precision`作为最小有效小数位的指数。我们将在验证类中使用这个值。

1.  我们的构造函数已经确定，所以让我们编写验证方法。关键验证方法有点棘手，所以我们将一步一步地走过它。首先，我们开始这个方法：

```py
    def _key_validate(self, char, index, current,
                      proposed, action, **kwargs):
        valid = True
        min_val = self.cget('from')
        max_val = self.cget('to')
        no_negative = min_val >= 0
        no_decimal = self.precision >= 0
```

1.  首先，我们检索`from`和`to`值，然后分配标志变量以指示是否应允许负数和小数，如下所示：

```py
        if action == '0':
            return True
```

删除应该总是有效的，所以如果是删除，返回`True`。

我们在这里打破了不要多次返回的准则，因为只有一个`return`的相同逻辑会嵌套得非常深。在尝试编写可读性好、易于维护的代码时，有时不得不选择两害相权取其轻。

1.  接下来，我们测试按键是否是有效字符，如下所示：

```py
      # First, filter out obviously invalid keystrokes
        if any([
                (char not in ('-1234567890.')),
                (char == '-' and (no_negative or index != '0')),
                (char == '.' and (no_decimal or '.' in current))
        ]):
            return False
```

有效字符是数字加上`-`和`.`。减号只在索引`0`处有效，点只能出现一次。其他任何字符都返回`False`。

内置的`any`函数接受一个表达式列表，并在列表中的任何一个表达式为真时返回`True`。还有一个`all`函数，如果所有表达式都为真，则返回`True`。这些函数允许您压缩一长串布尔表达式。

在这一点上，我们几乎可以保证有一个有效的`Decimal`字符串，但还不够；我们可能只有`-`、`.`或`-.`字符。

1.  以下是有效的部分条目，因此我们只需为它们返回`True`：

```py
        # At this point, proposed is either '-', '.', '-.',
        # or a valid Decimal string
        if proposed in '-.':
            return True
```

1.  此时，建议的文本只能是有效的`Decimal`字符串，因此我们将从中制作一个`Decimal`并进行更多的测试：

```py
        # Proposed is a valid Decimal string
        # convert to Decimal and check more:
        proposed = Decimal(proposed)
        proposed_precision = proposed.as_tuple().exponent

        if any([
            (proposed > max_val),
            (proposed_precision < self.precision)
        ]):
            return False

        return valid
```

1.  我们最后两个测试检查建议的文本是否大于我们的最大值，或者比我们指定的“增量”具有更多的精度（我们在这里使用`<`运算符的原因是因为“精度”给出为小数位的负值）。如果还没有返回任何内容，我们将返回`valid`值作为保障。我们的`focusout`验证器要简单得多，如下所示：

```py
    def _focusout_validate(self, **kwargs):
        valid = True
        value = self.get()
        min_val = self.cget('from')

        try:
            value = Decimal(value)
        except InvalidOperation:
            self.error.set('Invalid number string: {}'.format(value))
            return False

        if value < min_val:
            self.error.set('Value is too low (min {})'.format(min_val))
            valid = False
        return valid
```

1.  有了整个预期值，我们只需要确保它是有效的`Decimal`字符串并且大于最小值。

有了这个，我们的`ValidatedSpinbox`已经准备就绪。

# 动态调整 Spinbox 范围

我们的`ValidatedSpinbox`方法似乎对我们的大多数字段都足够了。但是考虑一下`Height`字段。`Mini height`值大于`Max height`值或`Median height`值不在它们之间是没有意义的。有没有办法将这种相互依赖的行为融入到我们的类中？

我们可以！为此，我们将依赖 Tkinter 变量的**跟踪**功能。跟踪本质上是对变量的`.get()`和`.set()`方法的钩子，允许您在读取或更改变量时触发任何 Python 函数或方法。

语法如下：

```py
sv = tk.StringVar()
sv.trace('w', some_function_or_method)
```

`.trace()`的第一个参数表示我们要跟踪的事件。这里，`w`表示写（`.set()`），`r`表示读（`.get()`），`u`表示未定义的变量或删除变量。

我们的策略是允许可选的`min_var`和`max_var`变量进入`ValidatedSpinbox`方法，并在这些变量上设置一个跟踪，以便在更改此变量时更新`ValidatedSpinbox`方法的最小或最大值。我们还将有一个`focus_update_var`变量，它将在`focusout`时间更新为`Spinbox`小部件值。

让我们看看以下步骤：

1.  首先，我们将更新我们的`ValidatedSpinbox`构造函数如下：

```py
    def __init__(self, *args, min_var=None, max_var=None,
        focus_update_var=None, from_='-Infinity', to='Infinity', 
    **kwargs
    ):
        super().__init__(*args, from_=from_, to=to, **kwargs)
        self.resolution = Decimal(str(kwargs.get('increment', '1.0')))
        self.precision = (
            self.resolution
            .normalize()
            .as_tuple()
            .exponent
        )
        # there should always be a variable,
        # or some of our code will fail
        self.variable = kwargs.get('textvariable') or tk.DoubleVar()

        if min_var:
            self.min_var = min_var
            self.min_var.trace('w', self._set_minimum)
        if max_var:
            self.max_var = max_var
            self.max_var.trace('w', self._set_maximum)
        self.focus_update_var = focus_update_var
        self.bind('<FocusOut>', self._set_focus_update_var)
```

1.  首先，请注意我们已经添加了一行来将变量存储在`self.variable`中，如果程序没有明确传入变量，我们将创建一个变量。我们需要编写的一些代码将取决于文本变量的存在，因此我们将强制执行这一点，以防万一。

1.  如果我们传入`min_var`或`max_var`参数，该值将被存储，并配置一个跟踪。`trace()`方法指向一个适当命名的方法。

1.  我们还存储了对`focus_update_var`参数的引用，并将`<FocusOut>`事件绑定到一个方法，该方法将用于更新它。

`bind()`方法可以在任何 Tkinter 小部件上调用，它用于将小部件事件连接到 Python 可调用函数。事件可以是按键、鼠标移动或点击、焦点事件、窗口管理事件等等。

1.  现在，我们需要为我们的`trace()`和`bind()`命令添加回调方法。首先从`_set_focus_update_var()`开始，如下所示：

```py
def _set_focus_update_var(self, event):
        value = self.get()
        if self.focus_update_var and not self.error.get():
            self.focus_update_var.set(value)
```

这个方法只是简单地获取小部件的当前值，并且如果实例中存在`focus_update_var`参数，则将其设置为相同的值。请注意，如果小部件当前存在错误，我们不会设置值。将值更新为无效值是没有意义的。

当 Tkinter 调用`bind`回调时，它传递一个包含有关触发回调的事件的信息的事件对象。即使您不打算使用这些信息，您的函数或方法也需要能够接受此参数。

1.  现在，让我们创建设置最小值的回调，如下所示：

```py
    def _set_minimum(self, *args):
        current = self.get()
        try:
            new_min = self.min_var.get()
            self.config(from_=new_min)
        except (tk.TclError, ValueError):
            pass
        if not current:
            self.delete(0, tk.END)
        else:
            self.variable.set(current)
        self.trigger_focusout_validation()
```

1.  我们要做的第一件事是检索当前值。`Tkinter.Spinbox`在更改`to`或`from`值时有稍微让人讨厌的行为，将太低的值移动到`from`值，将太高的值移动到`to`值。这种悄悄的自动校正可能会逃过我们用户的注意，导致坏数据被保存。我们希望的是将值留在范围之外，并将其标记为错误；因此，为了解决 Tkinter 的问题，我们将保存当前值，更改配置，然后将原始值放回字段中。

1.  保存当前值后，我们尝试获取`min_var`的值，并从中设置我们的小部件的`from_`值。这里可能会出现几种问题，例如控制我们的最小和最大变量的字段中有空白或无效值，所有这些都应该引发`tk.TclError`或`ValueError`。在任何一种情况下，我们都不会做任何事情。

通常情况下，只是消除异常是一个坏主意；然而，在这种情况下，如果变量有问题，我们无法合理地做任何事情，除了忽略它。

1.  现在，我们只需要将我们保存的当前值写回字段。如果为空，我们只需删除字段；否则，我们设置输入的变量。该方法以调用`trigger_focusout_validation()`方法结束，以重新检查字段中的值与新最小值的匹配情况。

1.  `_set_maximum()`方法将与此方法相同，只是它将使用`max_var`来更新`to`值。您可以自己编写它，或者查看本书附带的示例代码。

1.  我们需要对我们的`ValidatedSpinbox`类进行最后一个更改。由于我们的最大值可能在输入后更改，并且我们依赖于我们的`focusout`验证来检测它，我们需要添加一些条件来检查最大值。

1.  我们需要将这个添加到`_focusout_validate()`方法中：

```py
        max_val = self.cget('to')
        if value > max_val:
            self.error.set('Value is too high (max {})'.format(max_val))
```

1.  在`return`语句之前添加这些行以检查最大值并根据需要设置错误。

# 更新我们的表单

现在我们所有的小部件都已经制作好了，是时候通过执行以下步骤让表单使用它们了：

1.  向下滚动到`DataRecordForm`类构造函数，并且我们将逐行更新我们的小部件。第 1 行非常简单：

```py
        self.inputs['Date'] = LabelInput(
            recordinfo, "Date",
            input_class=DateEntry,
            input_var=tk.StringVar())
        self.inputs['Date'].grid(row=0, column=0)
        self.inputs['Time'] = LabelInput(
            recordinfo, "Time",
            input_class=ValidatedCombobox,
            input_var=tk.StringVar(),
            input_args={"values": ["8:00", "12:00", "16:00", "20:00"]})
        self.inputs['Time'].grid(row=0, column=1)
        self.inputs['Technician'] = LabelInput(
            recordinfo, "Technician",
            input_class=RequiredEntry,
            input_var=tk.StringVar())
        self.inputs['Technician'].grid(row=0, column=2)
```

1.  将`LabelInput`中的`input_class`值替换为我们的新类就像交换一样简单。继续运行你的应用程序并尝试小部件。尝试一些不同的有效和无效日期，并查看`Combobox`小部件的工作方式（`RequiredEntry`在这一点上不会有太多作用，因为唯一可见的指示是红色文本，如果为空，就没有文本标记为红色；我们稍后会解决这个问题）。现在，转到第 2 行，首先添加`Lab`小部件，如下所示：

```py
        self.inputs['Lab'] = LabelInput(
            recordinfo, "Lab",
            input_class=ValidatedCombobox,
            input_var=tk.StringVar(),
            input_args={"values": ["A", "B", "C", "D", "E"]})
```

1.  接下来，添加`Plot`小部件，如下所示：

```py
        self.inputs['Plot'] = LabelInput(
            recordinfo, "Plot",
            input_class=ValidatedCombobox,
            input_var=tk.IntVar(),
            input_args={"values": list(range(1, 21))})
```

再次相当简单，但如果您运行它，您会发现`Plot`存在问题。事实证明，当值为整数时，我们的`ValidatedComobox`方法无法正常工作，因为用户键入的字符始终是字符串（即使它们是数字）；我们无法比较字符串和整数。

1.  如果您考虑一下，`Plot`实际上不应该是一个整数值。是的，这些值在技术上是整数，但正如我们在第三章*使用 Tkinter 和 ttk 小部件创建基本表单*中决定的那样，它们也可以是字母或符号；您不会在一个图表号上进行数学运算。因此，我们将更改`Plot`以使用`StringVar`变量，并将小部件的值也更改为字符串。更改`Plot`小部件的创建如下所示：

```py
       self.inputs['Plot'] = LabelInput(
            recordinfo, "Plot",
            input_class=ValidatedCombobox,
            input_var=tk.StringVar(),
            input_args={"values": [str(x) for x in range(1, 21)]})
```

1.  在这里，我们只是将`input_var`更改为`StringVar`，并使用列表推导将每个`values`项转换为字符串。现在，`Plot`的工作正常了。

1.  继续通过表单，用新验证的版本替换默认的`ttk`小部件。对于`Spinbox`小部件，请确保将`to`、`from_`和`increment`值作为字符串而不是整数传递。例如，`Humidity`小部件应该如下所示：

```py
        self.inputs['Humidity'] = LabelInput(
            environmentinfo, "Humidity (g/m³)",
            input_class=ValidatedSpinbox,
            input_var=tk.DoubleVar(),
            input_args={"from_": '0.5', "to": '52.0', "increment": 
            '.01'})
```

1.  当我们到达`Height`框时，是时候测试我们的`min_var`和`max_var`功能了。首先，我们需要设置变量来存储最小和最大高度，如下所示：

```py
        # Height data
        # create variables to be updated for min/max height
        # they can be referenced for min/max variables
        min_height_var = tk.DoubleVar(value='-infinity')
        max_height_var = tk.DoubleVar(value='infinity')
```

我们创建两个新的`DoubleVar`对象来保存当前的最小和最大高度，将它们设置为无限值。这确保一开始实际上没有最小或最大高度。

请注意，我们的小部件直到它们实际更改才会受到这些值的影响，因此它们不会使传入的原始`to`和`from_`值无效。

1.  现在，我们创建`Min Height`小部件，如下所示：

```py
        self.inputs['Min Height'] = LabelInput(
            plantinfo, "Min Height (cm)",
            input_class=ValidatedSpinbox,
            input_var=tk.DoubleVar(),
            input_args={
                "from_": '0', "to": '1000', "increment": '.01',
                "max_var": max_height_var, "focus_update_var": 
                 min_height_var})
```

1.  我们将使用`max_height_var`在此处设置最大值，确保我们的最小值永远不会超过最大值，并将`focus_update_var`设置为`min_height_var`的值，以便在更改此字段时它将被更新。现在，`Max Height`小部件如下所示：

```py
        self.inputs['Max Height'] = LabelInput(
            plantinfo, "Max Height (cm)",
            input_class=ValidatedSpinbox,
            input_var=tk.DoubleVar(),
            input_args={
                "from_": 0, "to": 1000, "increment": .01,
                "min_var": min_height_var, "focus_update_var":  
                max_height_var})
```

1.  这一次，我们使用我们的`min_height_var`变量来设置小部件的最小值，并从小部件的当前值更新`max_height_var`。最后，`Median Height`字段如下所示：

```py
        self.inputs['Median Height'] = LabelInput(
            plantinfo, "Median Height (cm)",
            input_class=ValidatedSpinbox,
            input_var=tk.DoubleVar(),
            input_args={
                "from_": 0, "to": 1000, "increment": .01,
                "min_var": min_height_var, "max_var": max_height_var})
```

1.  在这里，我们分别从`min_height_var`和`max_height_var`变量设置字段的最小和最大值。我们不会更新任何来自`Median Height`字段的变量，尽管我们可以在这里添加额外的变量和代码，以确保`Min Height`不会超过它，或者`Max Height`不会低于它。在大多数情况下，如果用户按顺序输入数据，`Median Height`就不重要了。

1.  您可能会想知道为什么我们不直接使用`Min Height`和`Max Height`中的`input_var`变量来保存这些值。如果您尝试这样做，您会发现原因：`input_var`会随着您的输入而更新，这意味着您的部分值立即成为新的最大值或最小值。我们宁愿等到用户提交值后再分配这个值，因此我们创建了一个只在`focusout`时更新的单独变量。

# 显示错误

如果您运行应用程序，您可能会注意到，虽然`focusout`错误的字段变红，但我们无法看到实际的错误。我们需要通过执行以下步骤来解决这个问题：

1.  找到您的`LabelInput`类，并将以下代码添加到构造方法的末尾：

```py
        self.error = getattr(self.input, 'error', tk.StringVar())
        self.error_label = ttk.Label(self, textvariable=self.error)
        self.error_label.grid(row=2, column=0, sticky=(tk.W + tk.E))
```

1.  在这里，我们检查我们的输入是否有错误变量，如果没有，我们就创建一个。我们将它保存为`self.error`的引用，然后创建一个带有错误的`textvariable`的`Label`。

1.  最后，我们将这个放在输入小部件下面。

1.  现在，当您尝试应用程序时，您应该能够看到字段错误。

# 防止表单在出现错误时提交

阻止错误进入 CSV 文件的最后一步是，如果表单存在已知错误，则停止应用程序保存。让我们执行以下步骤来做到这一点：

1.  实施这一步的第一步是为`Application`对象（负责保存数据）提供一种从`DataRecordForm`对象检索错误状态的方法。

1.  在`DataRecordForm`类的末尾，添加以下方法：

```py
    def get_errors(self):
        """Get a list of field errors in the form"""

        errors = {}
        for key, widget in self.inputs.items():
            if hasattr(widget.input, 'trigger_focusout_validation'):
                widget.input.trigger_focusout_validation()
            if widget.error.get():
                errors[key] = widget.error.get()

        return errors
```

1.  与我们处理数据的方式类似，我们只需循环遍历`LabelFrame`小部件。我们寻找具有`trigger_focusout_validation`方法的输入，并调用它，以确保所有值都已经被检查。然后，如果小部件的`error`变量有任何值，我们将其添加到一个`errors`字典中。这样，我们可以检索每个字段的字段名称和错误的字典。

1.  现在，我们需要将此行为添加到`Application`类的保存逻辑中。

1.  在`on_save()`的开头添加以下代码，在`docstring`下面：

```py
        # Check for errors first

        errors = self.recordform.get_errors()
        if errors:
            self.status.set(
                "Cannot save, error in fields: {}"
                .format(', '.join(errors.keys()))
            )
            return False
```

这个逻辑很简单：获取错误，如果我们找到任何错误，就在状态区域警告用户并从函数返回（因此不保存任何内容）。

1.  启动应用程序并尝试保存一个空白表单。您应该在所有字段中收到错误消息，并在底部收到一个消息，告诉您哪些字段有错误。

# 自动化输入

防止用户输入错误数据是帮助用户输入更好数据的一种方式；另一种方法是自动化。利用我们对表单可能如何填写的理解，我们可以插入对于某些字段非常可能是正确的值。

请记住第二章中提到的，*使用 Tkinter 设计 GUI 应用程序*，表单几乎总是在填写当天录入，并且按顺序从`Plot` 1 到`Plot` 20 依次填写。还要记住，`Date`，`Lab`和`Technician`的值对每个填写的表单保持不变。让我们为我们的用户自动化这个过程。

# 插入日期

插入当前日期是一个简单的开始地方。这个地方是在`DataRecordForm.reset()`方法中，该方法设置了输入新记录的表单。

按照以下方式更新该方法：

```py
    def reset(self):
        """Resets the form entries"""

        # clear all values
        for widget in self.inputs.values():
            widget.set('')

        current_date = datetime.today().strftime('%Y-%m-%d')
        self.inputs['Date'].set(current_date)
```

就像我们在`Application.save()`方法中所做的那样，我们从`datetime.today()`获取当前日期并将其格式化为 ISO 日期。然后，我们将`Date`小部件的输入设置为该值。

# 自动化 Lab，Time 和 Technician

稍微复杂一些的是我们对`Lab`，`Time`和`Technician`的处理。让我们按照以下逻辑进行审查：

1.  在清除数据之前，保存`Lab`，`Time`和`Technician`的值。

1.  如果`Plot`小于最后一个值（`20`），我们将在清除所有字段后将这些值放回，然后增加到下一个`Plot`值。

1.  如果`Plot`是最后一个值或没有值，则将这些字段留空。代码如下：

```py
   def reset(self):
        """Resets the form entries"""

        # gather the values to keep for each lab
        lab = self.inputs['Lab'].get()
        time = self.inputs['Time'].get()
        technician = self.inputs['Technician'].get()
        plot = self.inputs['Plot'].get()
        plot_values = self.inputs['Plot'].input.cget('values')

        # clear all values
        for widget in self.inputs.values():
            widget.set('')

        current_date = datetime.today().strftime('%Y-%m-%d')
        self.inputs['Date'].set(current_date)
        self.inputs['Time'].input.focus()

        # check if we need to put our values back, then do it.
        if plot not in ('', plot_values[-1]):
            self.inputs['Lab'].set(lab)
            self.inputs['Time'].set(time)
            self.inputs['Technician'].set(technician)
            next_plot_index = plot_values.index(plot) + 1
            self.inputs['Plot'].set(plot_values[next_plot_index])
            self.inputs['Seed sample'].input.focus()
```

因为`Plot`看起来像一个整数，可能会诱人像增加一个整数一样增加它，但最好将其视为非整数。我们使用值列表的索引。

1.  最后一个微调，表单的焦点始终从第一个字段开始，但这意味着用户必须通过已经填写的字段进行标签。如果下一个空输入从一开始就聚焦，那将是很好的。Tkinter 输入有一个`focus()`方法，它可以给它们键盘焦点。根据我们填写的字段，这要么是`Time`，要么是`Seed sample`。在设置`Date`值的下一行下面，添加以下代码行：

```py
self.inputs['Time'].input.focus()
```

1.  在设置`Plot`值的行下面，在条件块内，添加以下代码行：

```py
self.inputs['Seed sample'].input.focus()
```

我们的表单现在已经准备好与用户进行试运行。在这一点上，它绝对比 CSV 输入有所改进，并将帮助数据输入快速完成这些表单。

# 总结

应用程序已经取得了长足的进步。在本章中，我们学习了 Tkinter 验证，创建了一个验证混合类，并用它来创建`Entry`，`Combobox`和`Spinbox`小部件的验证版本。我们在按键和焦点事件上验证了不同类型的数据，并创建了根据相关字段的值动态更新其约束的字段。

在下一章中，我们将准备我们的代码基础以便扩展，并学习如何组织一个大型应用程序以便更容易维护。更具体地说，我们将学习 MVC 模式以及如何将我们的代码结构化为多个文件，以便更简单地进行维护。我们还将更多地了解 RST 和版本控制软件。
