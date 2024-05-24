# 精通 Python GUI 编程（一）

> 原文：[`zh.annas-archive.org/md5/0baee48435c6a8dfb31a15ece9441408`](https://zh.annas-archive.org/md5/0baee48435c6a8dfb31a15ece9441408)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在一个时代，**应用程序开发人员**几乎总是意味着**网络应用程序开发人员**的时代，构建桌面 GUI 应用程序似乎有可能变成一种古雅而晦涩的艺术。然而，在每一个讨论编程的论坛、邮件列表和聊天服务中，我发现年轻的 Python 编程人员渴望深入研究 GUI 工具包，以便开始构建任何普通人都可以轻松识别为应用程序的软件。对于这些学习者一直推荐的一个 GUI 库，也可以说是 Python 最令人兴奋和最完整的工具包，就是 PyQt。

尽管 PyQt 很受欢迎，但学习 PyQt 的资源相对较少。那些希望学习它的人必须严重依赖过时的书籍、C++文档、零散的博客或在邮件列表或 Stack Overflow 帖子中找到的代码片段。显然，Python 程序员需要一本现代的 PyQt 教程和参考书，而这本书旨在填补这一需求。

我的第一本书《使用 Tkinter 进行 Python GUI 编程》专注于使用 Tkinter 进行应用程序开发的基础知识，涵盖了诸如界面设计、单元测试、程序架构和打包等核心主题。在这本书中，我希望超越基础知识，不仅教你如何构建数据驱动的业务表单（许多工具包都可以生成，许多其他书籍都可以教你编写），而且探索 PyQt 提供的更令人兴奋和独特的可能性：多媒体、动画、3D 图形、图像处理、网络、多线程等。当然，这本书也不会忽视业务方面的内容，包括数据输入表单、SQL 数据库和图表。

写技术书籍的作者有两种。第一种是绝对的专家，具有不可动摇的权威和对所讨论主题的百科全书式知识，能够凭借深刻的理解力提供完美地满足学习者最迫切需求的解释。

第二种作者是一个普通人，具有对基础知识的合理熟悉度，愿意研究未知的内容，最重要的是，他们有顽强的决心，确保印刷出版的每一种陈述都是完整和正确的真相。这种作者必须准备好在写作过程中停下来，测试解释器或代码编辑器中的声明；花费数小时阅读文档、邮件列表线程、代码注释和 IRC 日志，以追求更正确的理解；当新的事实揭示了他们最初的假设存在错误时，删除和重写大部分工作。

当有人要求我写一本关于 PyQt5 的书时，我不能声称自己是第一种作者（现在也不行）；虽然我在工作中和开源世界中开发和维护了几个 PyQt 应用程序，但我对 PyQt 的理解很少超出我自己代码的简单需求。因此，我立志成为第二种类型的作者，致力于勤奋学习和费力地将可用信息的混乱大量筛选和提炼成一篇文章，以指导有抱负的 GUI 程序员掌握 PyQt。

作为五个孩子的自豪父亲，其中一些孩子对编程有着萌芽（如果不是蓬勃）的兴趣，我在过去的六个月里努力写了一本书，如果他们希望学习这些技能，我可以自信和认真地放在他们面前。亲爱的读者，我希望你在这本书中感受到我的父母对你的成长和进步的热情，我们一起攻克这个主题。

# 这本书是为谁写的

本书适用于希望深入了解 PyQt 应用程序框架并学习如何制作强大 GUI 应用程序的中级 Python 程序员。假设读者了解 Python 语法、特性和习惯用法，如函数、类和常见标准库工具。还假设读者有一个可以舒适地编写和执行 Python 代码的环境。

本书不假设读者具有任何 GUI 开发、其他 GUI 工具包或其他版本的 PyQt 的先前知识。

# 本书涵盖内容

第一章《PyQt 入门》，向您介绍了 Qt 和 PyQt 库。您将学习如何设置系统以编写 PyQt 应用程序，并介绍 Qt Designer。您还将编写传统的`Hello World`应用程序，并开发 PyQt 应用程序的基本模板。

第二章《使用 QtWidgets 构建表单》，向您展示了制作 PyQt GUI 的基础知识。您将了解最常见的输入和显示小部件，学会使用布局来排列它们，并学会验证用户输入。您将应用这些技能来开发日历 GUI。

第三章《使用信号和槽处理事件》，专注于 PyQt 的事件处理和对象通信系统。您将学习如何使用此系统使应用程序响应用户输入，以及如何创建自定义信号和槽。您将通过完成日历应用程序来应用这些技能。

第四章《使用 QMainWindow 构建应用程序》，向您介绍了`QMainWindow`类，它是本书其余部分应用程序的基础。您还将探索 PyQt 的标准对话框类和`QSettings`模块，用于保存应用程序的配置。

第五章《使用模型视图类创建数据接口》，专注于 Qt 的模型视图类。您将学习模型视图设计原则，探索`QtWidgets`中的模型视图类，并在开发 CSV 编辑器时练习您的知识。

第六章《美化 Qt 应用程序》，探讨了 PyQt 小部件的样式能力。您将通过自定义字体、图像和图标为 GUI 应用程序增添趣味。您将学会使用样式对象和 Qt 样式表自定义颜色。最后，我们将学习如何对样式属性进行基本动画。

第七章《使用 QtMultimedia 处理音视频》，探索了 Qt 的多媒体功能。您将学习如何在各个平台上无缝播放和录制音频和视频。

第八章《使用 QtNetwork 进行网络通信》，专注于使用`QtNetwork`库进行简单的网络通信。您将学习如何通过原始套接字进行通信，包括**传输控制协议**（**TCP**）和**用户数据报协议**（**UDP**），以及学习如何使用 HTTP 传输和接收文件和数据。

第九章《使用 QtSQL 探索 SQL》，向您介绍了 SQL 数据库编程的世界。您将学习 SQL 的基础知识和 SQLite 数据库。然后，您将学习您的 PyQt 应用程序如何使用`QtSQL`库来使用原始 SQL 命令或 Qt 的 SQL 模型视图类访问数据。

第十章《使用 QTimer 和 QThread 进行多线程》，介绍了多线程和异步编程的世界。您将学习如何使用定时器延迟事件循环中的任务，并学习如何使用`QThread`将进程推入单独的执行线程。您还将学习如何使用`QThreadPool`进行高并发编程。

《第十一章》，*使用 QTextDocument 创建丰富文本*，探索了 Qt 中的丰富文本和文档准备。你将了解 Qt 的丰富文本标记语言，并学习如何使用`QTextDocument`以编程方式构建文档。你还将学习如何使用 Qt 的打印库，轻松实现跨平台的文档打印。

《第十二章》，*使用 Qpainter 创建 2D 图形*，深入探讨了 Qt 中的二维图形。你将学习如何加载和编辑图像，创建自定义小部件。你还将了解使用 Qt 图形系统进行绘制和动画，并创建一个街机风格的游戏。

《第十三章》，*使用 QtOpenGL 创建 3D 图形*，向你介绍了 OpenGL 的 3D 图形。你将学习现代 OpenGL 编程的基础知识，以及如何使用 PyQt 小部件来显示和与 OpenGL 图形进行交互。

《第十四章》，*使用 QtCharts 嵌入数据图表*，探索了 Qt 内置的图表功能。你将学习如何创建静态和动画图表，以及如何自定义图表的颜色、字体和样式。

《第十五章》，*PyQt 树莓派*，着重介绍了在树莓派计算机上使用 PyQt。你将学习如何在 Raspbian Linux 上设置 PyQt，以及如何将 PyQt 的强大功能与树莓派的 GPIO 引脚结合起来，创建与真实电路交互的 GUI 应用程序。

《第十六章》，*使用 QtWebEngine 进行网页浏览*，探讨了 PyQt 的基于 Chromium 的网页浏览器模块。你将在构建自己的多标签网页浏览器时探索这个模块的功能。

《第十七章》，*为软件分发做准备*，讨论了准备代码进行共享和分发的各种方法。我们将研究最佳的项目布局，使用`setuptools`为其他 Python 用户打包源代码，以及使用 PyInstaller 构建独立可执行文件。

《附录 A》，*问题的答案*，包含了每章末尾问题的答案或建议。

《附录 B》，*将 Raspbian 9 升级到 Raspbian 10*，解释了如何将树莓派设备从 Raspbian 9 升级到 Raspbian 10，供那些在正式发布 Raspbian 10 之前尝试跟随本书的读者参考。

# 为了充分利用本书

读者应该精通 Python 语言，特别是 Python 3。你应该至少在基本层面上理解如何使用类和面向对象编程。如果你对 C++有一定的了解，可能会有所帮助，因为大部分可用的 Qt 文档都是针对这种语言的。

你应该有一台安装了 Python 3.7 的 Windows、macOS 或 Linux 系统的计算机，并且可以根据需要安装其他软件。你应该有一个你熟悉的代码编辑器和命令行 shell。最后，你应该能够接入互联网。

本书的每一章都包含一个或多个示例应用。尽管这些示例可以下载，但鼓励你跟着操作，手动创建这些应用程序，以便看到应用程序在中间阶段的形成过程。

每一章还包含一系列问题或建议的项目，以巩固你对主题的知识，并提供了一些资源供进一步学习。如果你在解决这些问题和阅读提供的材料时能够运用你的头脑和创造力，你将能够充分利用每一章。

本书中包含的代码是根据开源 MIT 许可发布的，允许您根据自己的需要重复使用代码，前提是您保留了包含的版权声明。鼓励您使用、修改、改进和重新发布这些程序。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便将文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的以下工具解压或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781789612905_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781789612905_ColorImages.pdf)。

# 代码实例

访问以下链接查看代码运行的视频：[`bit.ly/2M3QVrl`](http://bit.ly/2M3QVrl)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“HTML 文档是按层次结构构建的，最外层的标签通常是`<html>`。”

代码块设置如下：

```py
<table border=2>
      <thead>
        <tr bgcolor='grey'><th>System</th><th>Graphics</th><th>Sound</th></tr>
      </thead>
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
<table border=2>
      <thead>
        <tr bgcolor='grey'><th>System</th><th>Graphics</th><th>Sound</th></tr>
      </thead>
```

任何命令行输入或输出都以以下方式编写：

```py
$ python game_lobby.py
Font is Totally Nonexistent Font Family XYZ
Actual font used is Bitstream Vera Sans
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这样的方式出现在文本中。这是一个例子：“从管理面板中选择系统信息。”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一部分：深入了解 PyQt

在本节中，您将探索 PyQt 的核心功能。在本节结束时，您应该能够熟悉 PyQt 应用程序编写中涉及的基本设计工作流程和编码习惯，并且对构建简单的 PyQt 界面有信心。

本节包括以下章节：

+   第一章，*PyQt 入门*

+   第二章，*使用 QtWidgets 构建表单*

+   第三章，*使用信号和槽处理事件*

+   第四章，*使用 QMainWindow 构建应用*

+   第五章，*使用模型-视图类创建数据接口*

+   第六章，*美化 Qt 应用*


# 第一章：开始使用 PyQt

欢迎，Python 程序员！

Python 是一个用于系统管理、数据分析、Web 服务和命令行程序的优秀语言；很可能您已经在其中至少一个领域发现了 Python 的用处。然而，构建出用户可以轻松识别为程序的 GUI 驱动应用程序确实令人满意，这种技能应该是任何优秀软件开发人员的工具箱中的一部分。在本书中，您将学习如何使用 Python 和 Qt 框架开发令人惊叹的应用程序-从简单的数据输入表单到强大的多媒体工具。

我们将从以下主题开始介绍这些强大的技术：

+   介绍 Qt 和 PyQt

+   创建`Hello Qt`-我们的第一个窗口

+   创建 PyQt 应用程序模板

+   介绍 Qt Designer

# 技术要求

对于本章和本书的大部分内容，您将需要以下内容：

+   一台运行**Microsoft Windows**，**Apple macOS**或 64 位**GNU/Linux**的 PC。

+   **Python 3**，可从[`www.python.org`](http://www.python.org)获取。本书中的代码需要 Python 3.7 或更高版本。

+   **PyQt 5.12**，您可以使用以下命令从 Python 软件包索引中安装：

```py
$ pip install --user PyQt5
```

+   Linux 用户也可以从其发行版的软件包存储库中安装 PyQt5。

+   **Qt Designer 4.9**是一款来自[`www.qt.io`](https://www.qt.io)的所见即所得的 GUI 构建工具。有关安装说明，请参阅以下部分。

+   来自[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter01`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter01)的**示例代码**[.](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter01)

查看以下视频以查看代码的运行情况：[`bit.ly/2M5OUeg`](http://bit.ly/2M5OUeg)

# 安装 Qt Designer

在 Windows 或 macOS 上，Qt Designer 是 Qt 公司的 Qt Creator IDE 的一部分。这是一个免费的 IDE，您可以用来编码，尽管在撰写本文时，它主要面向 C++，对 Python 的支持还很初级。无论您是否在 Qt Creator 中编写代码，都可以使用 Qt Designer 组件。

您可以从[`download.qt.io/official_releases/qtcreator/4.9/4.9.0/`](https://download.qt.io/official_releases/qtcreator/4.9/4.9.0/)下载 Qt Creator 的安装程序。

尽管 Qt 公司为 Linux 提供了类似的独立 Qt 安装程序，但大多数 Linux 用户更倾向于使用其发行版存储库中的软件包。一些发行版提供 Qt Designer 作为独立应用程序，而其他发行版则将其包含在其 Qt Creator 软件包中。

此表显示了在几个主要发行版中安装 Qt Designer 的软件包：

| 发行版 | 软件包名称 |
| --- | --- |
| Ubuntu，Debian，Mint | `qttools5-dev-tools` |
| Fedora，CentOS，Red Hat，SUSE | `qt-creator` |
| Arch，Manjaro，Antergos | `qt5-tools` |

# 介绍 Qt 和 PyQt

Qt 是一个为 C++设计的跨平台应用程序框架。它有商业和开源许可证（**通用公共许可证**（**GPL**）v3 和**较宽松的通用公共许可证**（**LGPL**）v3），被广泛应用于开源项目，如 KDE Plasma 和 Oracle VirtualBox，商业软件如 Adobe Photoshop Elements 和 Autodesk Maya，甚至是 LG 和 Panasonic 等公司产品中的嵌入式软件。Qt 目前由 Qt 公司（[`www.qt.io`](https://www.qt.io)）拥有和维护。

在本书中，我们将使用 Qt 5.12 的开源版本。如果您使用的是 Windows、macOS 或主要的 Linux 发行版，您不需要显式安装 Qt；当您安装 PyQt5 时，它将自动安装。

Qt 的官方发音是**cute**，尽管许多人说**Q T**。

# PyQt5

PyQt 是一个允许 Qt 框架在 Python 代码中使用的 Python 库。它是由 Riverbank Computing 在 GPL 许可下开发的，尽管商业许可证可以用于购买想要开发专有应用程序的人。（请注意，这是与 Qt 许可证分开的许可证。）它目前支持 Windows、Linux、UNIX、Android、macOS 和 iOS。

PyQt 的绑定是由一个名为**SIP**的工具自动生成的，因此，在很大程度上，使用 PyQt 就像在 Python 中使用 Qt 本身一样。换句话说，类、方法和其他对象在用法上都是相同的，除了语言语法。

Qt 公司最近发布了**Qt for Python**（也称为**PySide2**），他们自己的 Python Qt5 库，遵循 LGPL 条款。 Qt for Python 在功能上等同于 PyQt5，代码可以在它们之间进行很少的更改。本书将涵盖 PyQt5，但您学到的知识可以轻松应用于 Qt for Python，如果您需要一个 LGPL 库。

# 使用 Qt 和 PyQt

Qt 不仅仅是一个 GUI 库；它是一个应用程序框架。它包含数十个模块，数千个类。它有用于包装日期、时间、URL 或颜色值等简单数据类型的类。它有 GUI 组件，如按钮、文本输入或对话框。它有用于硬件接口，如相机或移动传感器的接口。它有一个网络库、一个线程库和一个数据库库。如果说什么，Qt 真的是第二个标准库！

Qt 是用 C++编写的，并且围绕 C++程序员的需求进行设计；它与 Python 很好地配合，但 Python 程序员可能会发现它的一些概念起初有些陌生。

例如，Qt 对象通常希望使用包装在 Qt 类中的数据。一个期望颜色值的方法不会接受字符串或 RGB 值的元组；它需要一个`QColor`对象。一个返回大小的方法不会返回`(width, height)`元组；它会返回一个`QSize`对象。PyQt 通过自动在 Qt 对象和 Python 标准库类型之间转换一些常见数据类型（例如字符串、列表、日期和时间）来减轻这种情况；然而，Python 标准库中没有与 Qt 类对应的数百个 Qt 类。

Qt 在很大程度上依赖于称为**enums**或**flags**的命名常量来表示选项设置或配置值。例如，如果您想要在最小化、浮动或最大化之间切换窗口的状态，您需要传递一个在`QtCore.Qt.WindowState`枚举中找到的常量给窗口。

在 Qt 对象上设置或检索值需要使用**访问器**方法，有时也称为设置器和获取器方法，而不是直接访问属性。

对于 Python 程序员来说，Qt 似乎有一种近乎狂热的执着于定义类和常量，你会花费很多时间在早期搜索文档以定位需要配置对象的项目。不要绝望！您很快就会适应 Qt 的工作方式。

# 理解 Qt 的文档

Qt 是一个庞大而复杂的库，没有任何印刷书籍能够详细记录其中的大部分内容。因此，学会如何访问和理解在线文档非常重要。对于 Python 程序员来说，这是一个小挑战。

Qt 本身拥有详细和优秀的文档，记录了所有 Qt 模块和类，包括示例代码和关于使用 Qt 进行编码的高级教程。然而，这些文档都是针对 C++开发的；所有示例代码都是 C++，并且没有指示 Python 的方法或解决问题的方法何时有所不同。

PyQt 的文档要少得多。它只涵盖了与 Python 相关的差异，并缺乏全面的类参考、示例代码和教程，这些都是 Qt 文档的亮点。对于任何使用 PyQt 的人来说，这是必读的，但它并不完整。

随着 Qt for Python 的发布，正在努力将 Qt 的 C++文档移植到 Python，网址为[`doc-snapshots.qt.io/qtforpython/`](https://doc-snapshots.qt.io/qtforpython/)。完成后，这也将成为 PyQt 程序员的宝贵资源。不过，在撰写本文时，这一努力还远未完成；无论如何，PyQt 和 Qt for Python 之间存在细微差异，这可能使这些文档既有帮助又令人困惑。

如果您对 C++语法有一些基本的了解，将 Qt 文档精神翻译成 Python 并不太困难，尽管在许多情况下可能会令人困惑。本书的目标之一是弥合那些对 C++不太熟悉的人的差距。

# 核心 Qt 模块

在本书的前六章中，我们将主要使用三个 Qt 模块：

+   `QtCore`包含低级数据包装类、实用函数和非 GUI 核心功能

+   `QtGui`包含特定于 GUI 的数据包装类和实用程序

+   `QtWidgets`定义了 GUI 小部件、布局和其他高级 GUI 组件

这三个模块将在我们编写的任何 PyQt 程序中使用。本书后面，我们将探索其他用于图形、网络、Web 渲染、多媒体和其他高级功能的模块。

# 创建 Hello Qt-我们的第一个窗口

现在您已经了解了 Qt5 和 PyQt5，是时候深入了解并进行一些编码了。确保一切都已安装好，打开您喜爱的 Python 编辑器或 IDE，让我们开始吧！

在您的编辑器中创建一个`hello_world.py`文件，并输入以下内容：

```py
from PyQt5 import QtWidgets
```

我们首先导入`QtWidgets`模块。该模块包含 Qt 中大部分的小部件类，以及一些其他重要的用于 GUI 创建的组件。对于这样一个简单的应用程序，我们不需要`QtGui`或`QtCore`。

接下来，我们需要创建一个`QApplication`对象，如下所示：

```py
app = QtWidgets.QApplication([])
```

`QApplication`对象表示我们运行应用程序的状态，必须在创建任何其他 Qt 小部件之前创建。`QApplication`应该接收一个传递给我们脚本的命令行参数列表，但在这里我们只是传递了一个空列表。

现在，让我们创建我们的第一个小部件：

```py
window = QtWidgets.QWidget(windowTitle='Hello Qt')
```

在 GUI 工具包术语中，**小部件**指的是 GUI 的可见组件，如按钮、标签、文本输入或空面板。在 Qt 中，最通用的小部件是`QWidget`对象，它只是一个空白窗口或面板。在创建此小部件时，我们将其`windowTitle`设置为`'Hello Qt'`。`windowTitle`就是所谓的**属性**。所有 Qt 对象和小部件都有属性，用于配置小部件的不同方面。在这种情况下，`windowTitle`是程序窗口的名称，并显示在窗口装饰、任务栏或停靠栏等其他地方，取决于您的操作系统和桌面环境。

与大多数 Python 库不同，Qt 属性和方法使用**驼峰命名法**而不是**蛇形命名法**。

用于配置 Qt 对象的属性可以通过将它们作为构造函数参数传递或使用适当的 setter 方法进行设置。通常，这只是`set`加上属性的名称，所以我们可以这样写：

```py
window = QtWidgets.QWidget()
window.setWindowTitle('Hello Qt')
```

属性也可以使用 getter 方法进行检索，这只是属性名称：

```py
print(window.windowTitle())
```

创建小部件后，我们可以通过调用`show()`使其显示，如下所示：

```py
window.show()
```

调用`show()`会自动使`window`成为自己的顶级窗口。在第二章中，*使用 Qt 小部件构建表单*，您将看到如何将小部件放置在其他小部件内，但是对于这个程序，我们只需要一个顶级小部件。

最后一行是对`app.exec()`的调用，如下所示：

```py
app.exec()
```

`app.exec()`开始`QApplication`对象的**事件循环**。事件循环将一直运行，直到应用程序退出，处理我们与 GUI 的用户交互。请注意，`app`对象从不引用`window`，`window`也不引用`app`对象。这些对象在后台自动连接；您只需确保在创建任何`QWidget`对象之前存在一个`QApplication`对象。

保存`hello_world.py`文件并从编辑器或命令行运行脚本，就像这样：

```py
python hello_world.py
```

当您运行此代码时，您应该会看到一个空白窗口，其标题文本为`Hello Qt`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/6ccffe2a-ed42-4818-b83f-433e4fb47c03.png)

这不是一个非常激动人心的应用程序，但它确实展示了任何 PyQt 应用程序的基本工作流程：

1.  创建一个`QApplication`对象

1.  创建我们的主应用程序窗口

1.  显示我们的主应用程序窗口

1.  调用`QApplication.exec()`来启动事件循环

如果您在 Python 的**Read-Eval-Print-Loop**（**REPL**）中尝试使用 PyQt，请通过传入一个包含单个空字符串的列表来创建`QApplication`对象，就像这样：`QtWidgets.QApplication([''])`；否则，Qt 会崩溃。此外，在 REPL 中不需要调用`QApplication.exec()`，这要归功于一些特殊的 PyQt 魔法。

# 创建一个 PyQt 应用程序模板

`hello_world.py`演示了在屏幕上显示 Qt 窗口的最低限度的代码，但它过于简单，无法作为更复杂应用程序的模型。在本书中，我们将创建许多 PyQt 应用程序，因此为了简化事情，我们将组成一个基本的应用程序模板。未来的章节将参考这个模板，所以确保按照指定的方式创建它。

打开一个名为`qt_template.py`的新文件，并添加这些导入：

```py
import sys
from PyQt5 import QtWidgets as qtw
from PyQt5 import QtGui as qtg
from PyQt5 import QtCore as qtc
```

我们将从导入`sys`开始，这样我们就可以向`QApplication`传递一个实际的脚本参数列表；然后我们将导入我们的三个主要 Qt 模块。为了节省一些输入，同时避免星号导入，我们将它们别名为缩写名称。我们将在整本书中一贯使用这些别名。

星号导入（也称为**通配符导入**），例如`from PyQt5.QtWidgets import *`，在教程中很方便，但在实践中最好避免使用。这样做会使您的命名空间充满了数百个类、函数和常量，其中任何一个您可能会意外地用变量名覆盖。避免星号导入还将帮助您了解哪些模块包含哪些常用类。

接下来，我们将创建一个`MainWindow`类，如下所示：

```py
class MainWindow(qtw.QWidget):

    def __init__(self):
        """MainWindow constructor"""
        super().__init__()
        # Main UI code goes here

        # End main UI code
        self.show()
```

为了创建我们的`MainWindow`类，我们对`QWidget`进行子类化，然后重写构造方法。每当我们在未来的章节中使用这个模板时，请在注释行之间开始添加您的代码，除非另有指示。

对 PyQt 类进行子类化是一种构建 GUI 的好方法。它允许我们定制和扩展 Qt 强大的窗口部件类，而无需重新发明轮子。在许多情况下，子类化是利用某些类或完成某些自定义的唯一方法。

我们的构造函数以调用`self.show()`结束，因此我们的`MainWindow`将负责显示自己。

始终记得在子类的构造函数中调用`super().__init__()`，特别是在 Qt 类中。不这样做意味着父类没有得到正确设置，肯定会导致非常令人沮丧的错误。

我们将用主要的代码执行完成我们的模板：

```py
if __name__ == '__main__':
    app = qtw.QApplication(sys.argv)
    mw = MainWindow()
    sys.exit(app.exec())
```

在这段代码中，我们将创建我们的`QApplication`对象，制作我们的`MainWindow`对象，然后调用`QApplication.exec()`。虽然这并不是严格必要的，但最好的做法是在全局范围内创建`QApplication`对象（在任何函数或类的外部）。这确保了应用程序退出时所有 Qt 对象都能得到正确关闭和清理。

注意我们将`sys.argv`传递给`QApplication()`；Qt 有几个默认的命令行参数，可以用于调试或更改样式和主题。如果你传入`sys.argv`，这些参数将由`QApplication`构造函数处理。

还要注意，我们在调用`sys.exit`时调用了`app.exec()`；这是一个小技巧，使得`app.exec()`的退出代码传递给`sys.exit()`，这样如果底层的 Qt 实例由于某种原因崩溃，我们就可以向操作系统传递适当的退出代码。

最后，注意我们在这个检查中包装了这个块：

```py
if __name__ == '__main__':
```

如果你以前从未见过这个，这是一个常见的 Python 习语，意思是：只有在直接调用这个脚本时才运行这段代码。通过将我们的主要执行放在这个块中，我们可以想象将这个文件导入到另一个 Python 脚本中，并能够重用我们的`MainWindow`类，而不运行这个块中的任何代码。

如果你运行你的模板代码，你应该会看到一个空白的应用程序窗口。在接下来的章节中，我们将用各种小部件和功能来填充这个窗口。

# 介绍 Qt Designer

在我们结束对 Qt 的介绍之前，让我们看看 Qt 公司提供的一个免费工具，可以帮助我们创建 PyQt 应用程序——Qt Designer。

Qt Designer 是一个用于 Qt 的图形 WYSIWYG GUI 设计师。使用 Qt Designer，你可以将 GUI 组件拖放到应用程序中并配置它们，而无需编写任何代码。虽然它确实是一个可选工具，但你可能会发现它对于原型设计很有用，或者比手工编写大型和复杂的 GUI 更可取。虽然本书中的大部分代码将是手工编写的，但我们将在第二章《使用 Qt 小部件构建表单》和第三章《使用信号和槽处理事件》中介绍在 PyQt 中使用 Qt Designer。

# 使用 Qt Designer

让我们花点时间熟悉如何启动和使用 Qt Designer：

1.  启动 Qt Creator

1.  选择文件|新建文件或项目

1.  在文件和类下，选择 Qt

1.  选择 Qt Designer 表单

1.  在选择模板表单下，选择小部件，然后点击下一步

1.  给你的表单取一个名字，然后点击下一步

1.  点击完成

你应该会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/76412061-910f-4543-a6b3-353931588943.png)

如果你在 Linux 上将 Qt Designer 作为独立应用程序安装，可以使用`designer`命令启动它，或者从程序菜单中选择它。你不需要之前的步骤。

花几分钟时间来测试 Qt Designer：

+   从左侧窗格拖动一些小部件到基本小部件上

+   如果你愿意，可以调整小部件的大小，或者选择一个小部件并在右下角的窗格中查看它的属性

+   当你做了几次更改后，选择工具|表单编辑器|预览，或者按*Alt* + *Shift* + *R*，来预览你的 GUI。

在第二章《使用 Qt 小部件构建表单》中，我们将详细介绍如何使用 Qt Designer 构建 GUI 界面；现在，你可以在[`doc.qt.io/qt-5/qtdesigner-manual.html`](https://doc.qt.io/qt-5/qtdesigner-manual.html)的手册中找到更多关于 Qt Designer 的信息。

# 总结

在本章中，你了解了 Qt 应用程序框架和 PyQt 对 Qt 的 Python 绑定。我们编写了一个`Hello World`应用程序，并创建了一个构建更大的 Qt 应用程序的模板。最后，我们安装并初步了解了 Qt Designer，这个 GUI 编辑器。

在第二章《使用 Qt 小部件构建表单》中，我们将熟悉一些基本的 Qt 小部件，并学习如何调整和排列它们在用户界面中。然后，你将通过代码和 Qt Designer 设计一个日历应用程序来应用这些知识。

# 问题

尝试这些问题来测试你从本章学到的知识：

1.  Qt 是用 C++编写的，这是一种与 Python 非常不同的语言。这两种语言之间有哪些主要区别？在使用 Python 中的 Qt 时，这些区别可能会如何体现？

1.  GUI 由小部件组成。在计算机上打开一些 GUI 应用程序，并尝试识别尽可能多的小部件。

1.  以下程序崩溃了。找出原因，并修复它以显示一个窗口：

```py
    from PyQt5.QtWidgets import *

    app = QWidget()
    app.show()
    QApplication().exec()
```

1.  `QWidget`类有一个名为`statusTip`的属性。以下哪些最有可能是该属性的访问方法的名称？

1.  `getStatusTip()`和`setStatusTip()`

1.  `statusTip()`和`setStatusTip()`

1.  `get_statusTip()`和`change_statusTip()`

1.  `QDate`是用于封装日历日期的类。你期望在三个主要的 Qt 模块中的哪一个找到它？

1.  `QFont`是定义屏幕字体的类。你期望在三个主要的 Qt 模块中的哪一个找到它？

1.  你能使用 Qt Designer 重新创建`hello_world.py`吗？确保设置`windowTitle`。

# 进一步阅读

查看以下资源，了解有关 Qt、PyQt 和 Qt Designer 的更多信息：

+   [`pyqt.sourceforge.net/Docs/PyQt5/`](http://pyqt.sourceforge.net/Docs/PyQt5/)上的**PyQt 手册**是了解 PyQt 独特方面的方便资源

+   [`doc.qt.io/qt-5/qtmodules.html`](https://doc.qt.io/qt-5/qtmodules.html)上的**Qt 模块列表**提供了 Qt 中可用模块的概述

+   请查看[`doc.qt.io/qt-5/qapplication.html#QApplication`](https://doc.qt.io/qt-5/qapplication.html#QApplication)上的**QApplication**文档，列出了`QApplication`对象解析的所有命令行开关

+   [`doc.qt.io/qt-5/qwidget.html`](https://doc.qt.io/qt-5/qwidget.html)上的**QWidget**文档显示了`QWidget`对象中可用的属性和方法

+   [`doc.qt.io/qt-5/qtdesigner-manual.html`](https://doc.qt.io/qt-5/qtdesigner-manual.html)上的**Qt Designer 手册**将帮助您探索 Qt Designer 的全部功能

+   如果你想了解更多关于 C++的信息，请查看 Packt 提供的这些内容[`www.packtpub.com/tech/C-plus-plus`](https://www.packtpub.com/tech/C-plus-plus)


# 第二章：使用 QtWidgets 构建表单

应用程序开发的第一步之一是原型设计应用程序的 GUI。有了各种各样的现成小部件，PyQt 使这变得非常容易。最重要的是，当我们完成后，我们可以直接将我们的原型代码移植到实际应用程序中。

在这一章中，我们将通过以下主题熟悉基本的表单设计：

+   创建基本的 QtWidgets 小部件

+   放置和排列小部件

+   验证小部件

+   构建一个日历应用程序的 GUI

# 技术要求

要完成本章，您需要从第一章 *PyQt 入门*中获取所有内容，以及来自[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter02`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter02)的示例代码。

查看以下视频以查看代码的实际效果：[`bit.ly/2M2R26r`](http://bit.ly/2M2R26r)

# 创建基本的 QtWidgets 小部件

`QtWidgets`模块包含数十个小部件，有些简单和标准，有些复杂和独特。在本节中，我们将介绍八种最常见的小部件及其基本用法。

在开始本节之前，从第一章 *PyQt 入门*中复制您的应用程序模板，并将其保存到名为`widget_demo.py`的文件中。当我们逐个示例进行时，您可以将它们添加到您的`MainWindow.__init__()`方法中，以查看这些对象的工作方式。

# QWidget

`QWidget`是所有其他小部件的父类，因此它拥有的任何属性和方法也将在任何其他小部件中可用。单独使用时，`QWidget`对象可以作为其他小部件的容器，填充空白区域，或作为顶层窗口的基类。

创建小部件就像这样简单：

```py
        # inside MainWindow.__init__()
        subwidget = qtw.QWidget(self)
```

请注意我们将`self`作为参数传递。如果我们正在创建一个小部件以放置在或在另一个小部件类中使用，就像我们在这里做的那样，将父小部件的引用作为第一个参数传递是一个好主意。指定父小部件将确保在父小部件被销毁和清理时，子小部件也被销毁，并限制其可见性在父小部件内部。

正如您在第一章中学到的，*PyQt 入门*，PyQt 也允许我们为任何小部件的属性指定值。

例如，我们可以使用`toolTip`属性来设置此小部件的工具提示文本（当鼠标悬停在小部件上时将弹出）：

```py
        subwidget = qtw.QWidget(self, toolTip='This is my widget')
```

阅读`QWidget`的 C++文档（位于[`doc.qt.io/qt-5/qwidget.html`](https://doc.qt.io/qt-5/qwidget.html)）并注意类的属性。请注意，每个属性都有指定的数据类型。在这种情况下，`toolTip`需要`QString`。每当需要`QString`时，我们可以使用常规 Unicode 字符串，因为 PyQt 会为我们进行转换。然而，对于更奇特的数据类型，如`QSize`或`QColor`，我们需要创建适当的对象。请注意，这些转换是在后台进行的，因为 Qt 对数据类型并不宽容。

例如，这段代码会导致错误：

```py
        subwidget = qtw.QWidget(self, toolTip=b'This is my widget')
```

这将导致`TypeError`，因为 PyQt 不会将`bytes`对象转换为`QString`。因此，请确保检查小部件属性或方法调用所需的数据类型，并使用兼容的类型。

# QWidget 作为顶层窗口

当创建一个没有父级的`QWidget`并调用它的`show()`方法时，它就成为了一个顶层窗口。当我们将其用作顶层窗口时，例如我们在`MainWindow`实例中所做的那样，我们可以设置一些特定于窗口的属性。其中一些显示在下表中：

| 属性 | 参数类型 | 描述 |
| --- | --- | --- |
| `windowTitle` | 字符串 | 窗口的标题。 |
| `windowIcon` | `QIcon` | 窗口的图标。 |
| `modal` | 布尔值 | 窗口是否为模态。 |
| `cursor` | `Qt.CursorShape` | 当小部件悬停时使用的光标。 |
| `windowFlags` | `Qt.WindowFlags` | 操作系统应如何处理窗口（对话框、工具提示、弹出窗口）。 |

`cursor`的参数类型是枚举的一个例子。枚举只是一系列命名的值，Qt 在属性受限于一组描述性值的任何地方定义枚举。`windowFlags`的参数是标志的一个例子。标志类似于枚举，不同之处在于它们可以组合（使用管道运算符`|`），以便传递多个标志。

在这种情况下，枚举和标志都是`Qt`命名空间的一部分，位于`QtCore`模块中。因此，例如，要在小部件悬停时将光标设置为箭头光标，您需要找到`Qt`中引用箭头光标的正确常量，并将小部件的`cursor`属性设置为该值。要在窗口上设置标志，指示操作系统它是`sheet`和`popup`窗口，您需要找到`Qt`中表示这些窗口标志的常量，用管道组合它们，并将其作为`windowFlags`的值传递。

创建这样一个`QWidget`窗口可能是这样的：

```py
window = qtw.QWidget(cursor=qtc.Qt.ArrowCursor)
window.setWindowFlags(qtc.Qt.Sheet|qtc.Qt.Popup)
```

在本书的其余部分学习配置 Qt 小部件时，我们将遇到更多的标志和枚举。

# QLabel

`QLabel`是一个配置为显示简单文本和图像的`QWidget`对象。

创建一个看起来像这样的：

```py
        label = qtw.QLabel('Hello Widgets!', self)
```

注意这次指定的父窗口小部件是第二个参数，而第一个参数是标签的文本。

这里显示了一些常用的`QLabel`属性：

| 属性 | 参数 | 描述 |
| --- | --- | --- |
| `text` | string | 标签上显示的文本。 |
| `margin` | 整数 | 文本周围的空间（以像素为单位）。 |
| `indent` | 整数 | 文本缩进的空间（以像素为单位）。 |
| `wordWrap` | 布尔值 | 是否换行。 |
| `textFormat` | `Qt.TextFormat` | 强制纯文本或富文本，或自动检测。 |
| `pixmap` | `QPixmap` | 要显示的图像而不是文本。 |

标签的文本存储在其`text`属性中，因此可以使用相关的访问器方法来访问或更改，如下所示：

```py
        label.setText("Hi There, Widgets!")
        print(label.text())
```

`QLabel`可以显示纯文本、富文本或图像。Qt 中的富文本使用类似 HTML 的语法；默认情况下，标签将自动检测您的字符串是否包含任何格式标记，并相应地显示适当类型的文本。例如，如果我们想要使我们的标签加粗并在文本周围添加边距，我们可以这样做：

```py
        label = qtw.QLabel('<b>Hello Widgets!</b>', self, margin=10)
```

我们将在第六章 *Qt 应用程序样式*和第十一章 *使用 QTextDocument 创建富文本*中学习更多关于使用图像、富文本和字体的知识。

# QLineEdit

`QLineEdit`类是一个单行文本输入小部件，您可能经常在数据输入或登录表单中使用。`QLineEdit`可以不带参数调用，只带有父窗口小部件，或者将默认字符串值作为第一个参数，如下所示：

```py
        line_edit = qtw.QLineEdit('default value', self)
```

还有许多我们可以传递的属性：

| 属性 | 参数 | 描述 |
| --- | --- | --- |
| `text` | string | 盒子的内容。 |
| `readOnly` | 布尔值 | 字段是否可编辑。 |
| `clearButtonEnabled` | 布尔值 | 是否添加清除按钮。 |
| `placeholderText` | string | 字段为空时显示的文本。 |
| `maxLength` | 整数 | 可输入的最大字符数。 |
| `echoMode` | `QLineEdit.EchoMode` | 切换文本输入时显示方式（例如用于密码输入）。 |

让我们给我们的行编辑小部件添加一些属性：

```py
        line_edit = qtw.QLineEdit(
            'default value',
            self,
            placeholderText='Type here',
            clearButtonEnabled=True,
            maxLength=20
        )
```

这将用默认文本'默认值'填充小部件。当字段为空或有一个清除字段的小`X`按钮时，它将显示一个占位符字符串'在此输入'。它还限制了可以输入的字符数为`20`。

# QPushButton 和其他按钮

`QPushButton`是一个简单的可点击按钮小部件。与`QLabel`和`QLineEdit`一样，它可以通过第一个参数调用，该参数指定按钮上的文本，如下所示：

```py
        button = qtw.QPushButton("Push Me", self)
```

我们可以在`QPushButton`上设置的一些更有用的属性包括以下内容：

| 属性 | 参数 | 描述 |
| --- | --- | --- |
| `checkable` | 布尔值 | 按钮是否在按下时保持开启状态。 |
| `checked` | 布尔值 | 对于`checkable`按钮，按钮是否被选中。 |
| `icon` | `QIcon` | 要显示在按钮上的图标图像。 |
| `shortcut` | `QKeySequence` | 一个激活按钮的键盘快捷键。 |

`checkable`和`checked`属性允许我们将此按钮用作反映开/关状态的切换按钮，而不仅仅是执行操作的单击按钮。所有这些属性都来自`QPushButton`类的父类`QAbstractButton`。这也是其他几个按钮类的父类，列在这里：

| 类 | 描述 |
| --- | --- |
| `QCheckBox` | 复选框可以是开/关的布尔值，也可以是开/部分开/关的三态值。 |
| `QRadioButton` | 类似复选框，但在具有相同父级的按钮中只能选中一个按钮。 |
| `QToolButton` | 用于工具栏小部件的特殊按钮。 |

尽管每个按钮都有一些独特的特性，但在核心功能方面，这些按钮在我们创建和配置它们的方式上是相同的。

让我们将我们的按钮设置为可选中，默认选中，并给它一个快捷键：

```py
        button = qtw.QPushButton(
            "Push Me",
            self,
            checkable=True,
            checked=True,
            shortcut=qtg.QKeySequence('Ctrl+p')
        )
```

请注意，`shortcut`选项要求我们传入一个`QKeySequence`，它是`QtGui`模块的一部分。这是一个很好的例子，说明属性参数通常需要包装在某种实用类中。`QKeySequence`封装了一个键组合，这里是*Ctrl*键（或 macOS 上的*command*键）和*P*。

键序列可以指定为字符串，例如前面的示例，也可以使用`QtCOre.Qt`模块中的枚举值。例如，我们可以将前面的示例写为`QKeySequence(qtc.Qt.CTRL + qtc.Qt.Key_P)`。

# QComboBox

**combobox**，也称为下拉或选择小部件，是一个在点击时呈现选项列表的小部件，其中必须选择一个选项。`QCombobox`可以通过将其`editable`属性设置为`True`来允许文本输入自定义答案。

让我们创建一个`QCombobox`对象，如下所示：

```py
        combobox = qtw.QComboBox(self)
```

现在，我们的`combobox`菜单中没有项目。`QCombobox`在构造函数中不提供使用选项初始化小部件的方法；相反，我们必须创建小部件，然后使用`addItem()`或`insertItem()`方法来填充其菜单选项，如下所示：

```py
        combobox.addItem('Lemon', 1)
        combobox.addItem('Peach', 'Ohh I like Peaches!')
        combobox.addItem('Strawberry', qtw.QWidget)
        combobox.insertItem(1, 'Radish', 2)
```

`addItem()`方法接受标签和数据值的字符串。正如你所看到的，这个值可以是任何东西——整数，字符串，Python 类。可以使用`QCombobox`对象的`currentData()`方法检索当前选定项目的值。通常最好——尽管不是必需的——使所有项目的值都是相同类型的。

`addItem()`将始终将项目附加到菜单的末尾；要在之前插入它们，使用`insertItem()`方法。它的工作方式完全相同，只是它接受一个索引（整数值）作为第一个参数。项目将插入到列表中的该索引处。如果我们想节省时间，不需要为我们的项目设置`data`属性，我们也可以使用`addItems()`或`insertItems()`传递一个选项列表。

`QComboBox`的一些其他重要属性包括以下内容：

| 属性 | 参数 | 描述 |
| --- | --- | --- |
| `currentData` | （任何） | 当前选定项目的数据对象。 |
| `currentIndex` | 整数 | 当前选定项目的索引。 |
| `currentText` | string | 当前选定项目的文本。 |
| `editable` | 布尔值 | `combobox`是否允许文本输入。 |
| `insertPolicy` | `QComboBox.InsertPolicy` | 输入的项目应该插入列表中的位置。 |

`currentData`的数据类型是`QVariant`，这是 Qt 的一个特殊类，用作任何类型数据的容器。在 C++中更有用，因为它们为多种数据类型可能有用的情况提供了一种绕过静态类型的方法。PyQt 会自动将`QVariant`对象转换为最合适的 Python 类型，因此我们很少需要直接使用这种类型。

让我们更新我们的`combobox`，以便我们可以将项目添加到下拉列表的顶部：

```py
        combobox = qtw.QComboBox(
            self,
            editable=True,
            insertPolicy=qtw.QComboBox.InsertAtTop
        )
```

现在这个`combobox`将允许输入任何文本；文本将被添加到列表框的顶部。新项目的`data`属性将为`None`，因此这实际上只适用于我们仅使用可见字符串的情况。

# QSpinBox

一般来说，旋转框是一个带有箭头按钮的文本输入，旨在*旋转*一组递增值。`QSpinbox`专门用于处理整数或离散值（例如下拉框）。

一些有用的`QSpinBox`属性包括以下内容：

| 属性 | 参数 | 描述 |
| --- | --- | --- |
| `value` | 整数 | 当前旋转框值，作为整数。 |
| `cleanText` | string | 当前旋转框值，作为字符串（不包括前缀和后缀）。 |
| `maximum` | 整数 | 方框的最大整数值。 |
| `minimum` | 整数 | 方框的最小值。 |
| `prefix` | string | 要添加到显示值的字符串。 |
| `suffix` | string | 要附加到显示值的字符串。 |
| `singleStep` | 整数 | 当使用箭头时增加或减少值的数量。 |
| `wrapping` | 布尔值 | 当使用箭头时是否从范围的一端包装到另一端。 |

让我们在脚本中创建一个`QSpinBox`对象，就像这样：

```py
        spinbox = qtw.QSpinBox(
            self,
            value=12,
            maximum=100,
            minimum=10,
            prefix='$',
            suffix=' + Tax',
            singleStep=5
        )
```

这个旋转框从值`12`开始，并允许输入从`10`到`100`的整数，以`$<value> + Tax`的格式显示。请注意，框的非整数部分不可编辑。还要注意，虽然增量和减量箭头移动`5`，但我们可以输入不是`5`的倍数的值。

`QSpinBox`将自动忽略非数字的按键，或者会使值超出可接受范围。如果输入了一个太低的值，当焦点从`spinbox`移开时，它将被自动更正为有效值；例如，如果您在前面的框中输入了`9`并单击了它，它将被自动更正为`90`。

`QDoubleSpinBox`与`QSpinBox`相同，但设计用于十进制或浮点数。

要将`QSpinBox`用于离散文本值而不是整数，您需要对其进行子类化并重写其验证方法。我们将在*验证小部件*部分中进行。

# QDateTimeEdit

旋转框的近亲是`QDateTimeEdit`，专门用于输入日期时间值。默认情况下，它显示为一个旋转框，允许用户通过每个日期时间值字段进行制表，并使用箭头递增/递减它。该小部件还可以配置为使用日历弹出窗口。

更有用的属性包括以下内容：

| 属性 | 参数 | 描述 |
| --- | --- | --- |
| `date` | `QDate`或`datetime.date` | 日期值。 |
| `time` | `QTime`或`datetime.time` | 时间值。 |
| `dateTime` | `QDateTime`或`datetime.datetime` | 组合的日期时间值。 |
| `maximumDate`，`minimumDate` | `QDate`或`datetime.date` | 可输入的最大和最小日期。 |
| `maximumTime`，`minimumTime` | `QTime`或`datetime.time` | 可输入的最大和最小时间。 |
| `maximumDateTime`，`minimumDateTime` | `QDateTime`或`datetime.datetime` | 可输入的最大和最小日期时间。 |
| `calendarPopup` | 布尔值 | 是否显示日历弹出窗口或像旋转框一样行为。 |
| `displayFormat` | string | 日期时间应如何格式化。 |

让我们像这样创建我们的日期时间框：

```py
       datetimebox = qtw.QDateTimeEdit(
            self,
            date=qtc.QDate.currentDate(),
            time=qtc.QTime(12, 30),
            calendarPopup=True,
            maximumDate=qtc.QDate(2030, 1, 1),
            maximumTime=qtc.QTime(17, 0),
            displayFormat='yyyy-MM-dd HH:mm'
        )
```

这个日期时间小部件将使用以下属性创建：

+   当前日期将设置为 12:30

+   当焦点集中时，它将显示日历弹出窗口

+   它将禁止在 2030 年 1 月 1 日之后的日期

+   它将禁止在最大日期后的 17:00（下午 5 点）之后的时间

+   它将以年-月-日小时-分钟的格式显示日期时间

请注意，`maximumTime`和`minimumTime`只影响`maximumDate`和`minimumDate`的值，分别。因此，即使我们指定了 17:00 的最大时间，只要在 2030 年 1 月 1 日之前，您也可以输入 18:00。相同的概念也适用于最小日期和时间。

日期时间的显示格式是使用包含每个项目的特定替换代码的字符串设置的。这里列出了一些常见的代码：

| 代码 | 意义 |
| --- | --- |
| `d` | 月份中的日期。 |
| `M` | 月份编号。 |
| `yy` | 两位数年份。 |
| `yyyy` | 四位数年份。 |
| `h` | 小时。 |
| `m` | 分钟。 |
| `s` | 秒。 |
| `A` | 上午/下午，如果使用，小时将切换到 12 小时制。 |

日，月，小时，分钟和秒都默认省略前导零。要获得前导零，只需将字母加倍（例如，`dd`表示带有前导零的日期）。代码的完整列表可以在[`doc.qt.io/qt-5/qdatetime.html`](https://doc.qt.io/qt-5/qdatetime.html)找到。

请注意，所有时间、日期和日期时间都可以接受来自 Python 标准库的`datetime`模块以及 Qt 类型的对象。因此，我们的框也可以这样创建：

```py
        import datetime
        datetimebox = qtw.QDateTimeEdit(
            self,
            date=datetime.date.today(),
            time=datetime.time(12, 30),
            calendarPopup=True,
            maximumDate=datetime.date(2020, 1, 1),
            minimumTime=datetime.time(8, 0),
            maximumTime=datetime.time(17, 0),
            displayFormat='yyyy-MM-dd HH:mm'
        )
```

你选择使用哪一个取决于个人偏好或情境要求。例如，如果您正在使用其他 Python 模块，`datetime`标准库对象可能更兼容。如果您只需要为小部件设置默认值，`QDateTime`可能更方便，因为您可能已经导入了`QtCore`。

如果您需要更多对日期和时间输入的控制，或者只是想将它们拆分开来，Qt 有`QTimeEdit`和`QDateEdit`小部件。它们就像这个小部件一样，只是分别处理时间和日期。

# QTextEdit

虽然`QLineEdit`用于单行字符串，但`QTextEdit`为我们提供了输入多行文本的能力。`QTextEdit`不仅仅是一个简单的纯文本输入，它是一个完整的所见即所得编辑器，可以配置为支持富文本和图像。

这里显示了`QTextEdit`的一些更有用的属性：

| 属性 | 参数 | 描述 |
| --- | --- | --- |
| `plainText` | 字符串 | 框的内容，纯文本格式。 |
| `html` | 字符串 | 框的内容，富文本格式。 |
| `acceptRichText` | 布尔值 | 框是否允许富文本。 |
| `lineWrapColumnOrWidth` | 整数 | 文本将换行的像素或列。 |
| `lineWrapMode` | `QTextEdit.LineWrapMode` | 行换行模式使用列还是像素。 |
| `overwriteMode` | 布尔值 | 是否激活覆盖模式；`False`表示插入模式。 |
| `placeholderText` | 字符串 | 字段为空时显示的文本。 |
| `readOnly` | 布尔值 | 字段是否只读。 |

让我们创建一个文本编辑器，如下所示：

```py
        textedit = qtw.QTextEdit(
            self,
            acceptRichText=False,
            lineWrapMode=qtw.QTextEdit.FixedColumnWidth,
            lineWrapColumnOrWidth=25,
            placeholderText='Enter your text here'
            )
```

这将创建一个纯文本编辑器，每行只允许输入`25`个字符，当为空时显示短语`'在此输入您的文本'`。

我们将在第十一章中深入了解`QTextEdit`和富文本文档，*使用 QTextDocument 创建富文本*。

# 放置和排列小部件

到目前为止，我们已经创建了许多小部件，但如果运行程序，您将看不到它们。虽然我们的小部件都属于父窗口，但它们还没有放置在上面。在本节中，我们将学习如何在应用程序窗口中排列我们的小部件，并将它们设置为适当的大小。

# 布局类

布局对象定义了子小部件在父小部件上的排列方式。Qt 提供了各种布局类，每个类都有适合不同情况的布局策略。

使用布局类的工作流程如下：

1.  从适当的布局类创建布局对象

1.  使用`setLayout()`方法将布局对象分配给父小部件的`layout`属性

1.  使用布局的`addWidget()`方法向布局添加小部件

您还可以使用`addLayout()`方法将布局添加到布局中，以创建更复杂的小部件排列。让我们来看看 Qt 提供的一些基本布局类。

# QHBoxLayout 和 QVBoxLayout

`QHBoxLayout`和`QVBoxLayout`都是从`QBoxLayout`派生出来的，这是一个非常基本的布局引擎，它简单地将父对象分成水平或垂直框，并按顺序放置小部件。`QHBoxLayout`是水平定向的，小部件按添加顺序从左到右放置。`QVBoxLayout`是垂直定向的，小部件按添加顺序从上到下放置。

让我们在`MainWindow`小部件上尝试`QVBoxLayout`：

```py
        layout = qtw.QVBoxLayout()
        self.setLayout(layout)
```

一旦布局对象存在，我们可以使用`addWidget()`方法开始向其中添加小部件：

```py
        layout.addWidget(label)
        layout.addWidget(line_edit)
```

如您所见，如果运行程序，小部件将逐行添加。如果我们想要将多个小部件添加到一行中，我们可以像这样在布局中嵌套一个布局：

```py
        sublayout = qtw.QHBoxLayout()
        layout.addLayout(sublayout)

        sublayout.addWidget(button)
        sublayout.addWidget(combobox)
```

在这里，我们在主垂直布局的下一个单元格中添加了一个水平布局，然后在子布局中插入了三个更多的小部件。这三个小部件在主布局的一行中并排显示。大多数应用程序布局可以通过简单地嵌套框布局来完成。

# QGridLayout

嵌套框布局涵盖了很多内容，但在某些情况下，您可能希望以统一的行和列排列小部件。这就是`QGridLayout`派上用场的地方。顾名思义，它允许您以表格结构放置小部件。

像这样创建一个网格布局对象：

```py
        grid_layout = qtw.QGridLayout()
        layout.addLayout(grid_layout)
```

向`QGridLayout`添加小部件类似于`QBoxLayout`类的方法，但还需要传递坐标：

```py
        grid_layout.addWidget(spinbox, 0, 0)
        grid_layout.addWidget(datetimebox, 0, 1)
        grid_layout.addWidget(textedit, 1, 0, 2, 2)
```

这是`QGridLayout.addWidget()`的参数，顺序如下：

1.  要添加的小部件

1.  行号（垂直坐标），从`0`开始

1.  列号（水平坐标），从`0`开始

1.  行跨度，或者小部件将包含的行数（可选）

1.  列跨度，或者小部件将包含的列数（可选）

因此，我们的`spinbox`小部件放置在第`0`行，第`0`列，即左上角；我们的`datetimebox`放置在第`0`行，第`1`列，即右上角；我们的`textedit`放置在第`1`行，第`0`列，并且跨越了两行两列。

请记住，网格布局保持所有列的宽度一致，所有行的高度一致。因此，如果您将一个非常宽的小部件放在第`2`行，第`1`列，所有行中位于第`1`列的小部件都会相应地被拉伸。如果希望每个单元格独立拉伸，请改用嵌套框布局。

# QFormLayout

在创建数据输入表单时，通常会在标签旁边放置标签。Qt 为这种情况提供了一个方便的两列网格布局，称为`QFormLayout`。

让我们向我们的 GUI 添加一个表单布局：

```py
        form_layout = qtw.QFormLayout()
        layout.addLayout(form_layout)
```

使用`addRow()`方法可以轻松添加小部件：

```py
        form_layout.addRow('Item 1', qtw.QLineEdit(self))
        form_layout.addRow('Item 2', qtw.QLineEdit(self))
        form_layout.addRow(qtw.QLabel('<b>This is a label-only row</b>'))
```

这个方便的方法接受一个字符串和一个小部件，并自动为字符串创建`QLabel`小部件。如果只传递一个小部件（如`QLabel`），该小部件跨越两列。这对于标题或部分标签非常有用。

`QFormLayout`不仅仅是对`QGridLayout`的方便，它还在跨不同平台使用时自动提供成语化的行为。例如，在 Windows 上使用时，标签是左对齐的；在 macOS 上使用时，标签是右对齐的，符合平台的设计指南。此外，当在窄屏幕上查看（如移动设备），布局会自动折叠为单列，标签位于输入框上方。在任何需要两列表单的情况下使用这种布局是非常值得的。

# 控制小部件大小

如果您按照当前的设置运行我们的演示并将其扩展以填满屏幕，您会注意到主布局的每个单元格都会均匀拉伸以填满屏幕，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/2b113c24-8f5f-4608-a786-8a0e4d6b40bd.png)

这并不理想。顶部的标签实际上不需要扩展，并且底部有很多空间被浪费。据推测，如果用户要扩展此窗口，他们会这样做以获得更多的输入小部件空间，就像我们的`QTextEdit`。我们需要为 GUI 提供一些关于如何调整小部件的大小以及在窗口从其默认大小扩展或收缩时如何调整它们的指导。

在任何工具包中，控制小部件的大小可能会有些令人困惑，但 Qt 的方法可能尤其令人困惑，因此让我们一步一步来。

我们可以简单地使用其`setFixedSize()`方法为任何小部件设置固定大小，就像这样：

```py
        # Fix at 150 pixels wide by 40 pixels high
        label.setFixedSize(150, 40)
```

`setFixedSize`仅接受像素值，并且设置为固定大小的小部件在任何情况下都不能改变这些像素大小。以这种方式调整小部件的大小的问题在于它没有考虑不同字体、不同文本大小或应用程序窗口的大小或布局发生变化的可能性，这可能导致小部件对其内容太小或过大。我们可以通过设置`minimumSize`和`maximumSize`使其稍微灵活一些，就像这样：

```py
        # setting minimum and maximum sizes
        line_edit.setMinimumSize(150, 15)
        line_edit.setMaximumSize(500, 50)
```

如果您运行此代码并调整窗口大小，您会注意到`line_edit`在窗口扩展和收缩时具有更大的灵活性。但是，请注意，小部件不会收缩到其`minimumSize`以下，但即使有空间可用，它也不一定会使用其`maximumSize`。

因此，这仍然远非理想。与其关心每个小部件消耗多少像素，我们更希望它根据其内容和在界面中的角色合理而灵活地调整大小。Qt 正是使用*大小提示*和*大小策略*的概念来实现这一点。

大小提示是小部件的建议大小，并由小部件的`sizeHint()`方法返回。此大小可能基于各种动态因素；例如，`QLabel`小部件的`sizeHint()`值取决于其包含的文本的长度和换行。由于它是一个方法而不是属性，因此为小部件设置自定义`sizeHint()`需要您对小部件进行子类化并重新实现该方法。幸运的是，这并不是我们经常需要做的事情。

大小策略定义了小部件在调整大小请求时如何响应其大小提示。这是作为小部件的`sizePolicy`属性设置的。大小策略在`QtWidgets.QSizePolicy.Policy`枚举中定义，并使用`setSizePolicy`访问器方法分别为小部件的水平和垂直尺寸设置。可用的策略在此处列出：

| 策略 | 描述 |
| --- | --- |
| 固定 | 永远不要增长或缩小。 |
| 最小 | 不要小于`sizeHint`。扩展并不有用。 |
| 最大 | 不要大于`sizeHint`，如果有必要则缩小。 |
| 首选 | 尝试是`sizeHint`，但如果有必要则缩小。扩展并不有用。这是默认值。 |
| 扩展 | 尝试是`sizeHint`，如果有必要则缩小，但尽可能扩展。 |
| 最小扩展 | 不要小于`sizeHint`，但尽可能扩展。 |
| 忽略 | 完全忘记`sizeHint`，尽可能占用更多空间。 |

因此，例如，如果我们希望 SpinBox 保持固定宽度，以便旁边的小部件可以扩展，我们将这样做：

```py
      spinbox.setSizePolicy(qtw.QSizePolicy.Fixed,qtw.QSizePolicy.Preferred)
```

或者，如果我们希望我们的`textedit`小部件尽可能填满屏幕，但永远不要缩小到其`sizeHint()`值以下，我们应该像这样设置其策略：

```py
        textedit.setSizePolicy(
            qtw.QSizePolicy.MinimumExpanding,
            qtw.QSizePolicy.MinimumExpanding
        )
```

当您有深度嵌套的布局时，调整小部件的大小可能有些不可预测；有时覆盖`sizeHint()`会很方便。在 Python 中，可以使用 Lambda 函数快速实现这一点，就像这样：

```py
        textedit.sizeHint = lambda : qtc.QSize(500, 500)
```

请注意，`sizeHint()`必须返回`QtCore.QSize`对象，而不仅仅是整数元组。

在使用框布局时，控制小部件大小的最后一种方法是在将小部件添加到布局时设置一个`stretch`因子。拉伸是`addWidget()`的可选第二个参数，它定义了每个小部件的比较拉伸。

这个例子展示了`stretch`因子的使用：

```py
        stretch_layout = qtw.QHBoxLayout()
        layout.addLayout(stretch_layout)
        stretch_layout.addWidget(qtw.QLineEdit('Short'), 1)
        stretch_layout.addWidget(qtw.QLineEdit('Long'), 2)
```

`stretch`只适用于`QHBoxLayout`和`QVBoxLayout`类。

在这个例子中，我们添加了一个拉伸因子为`1`的行编辑，和一个拉伸因子为`2`的第二个。当你运行这个程序时，你会发现第二个行编辑的长度大约是第一个的两倍。

请记住，拉伸不会覆盖大小提示或大小策略，因此根据这些因素，拉伸比例可能不会完全按照指定的方式进行。

# 容器小部件

我们已经看到我们可以使用`QWidget`作为其他小部件的容器。Qt 还为我们提供了一些专门设计用于包含其他小部件的特殊小部件。我们将看看其中的两个：`QTabWidget`和`QGroupBox`。

# QTabWidget

`QTabWidget`，有时在其他工具包中被称为**笔记本小部件**，允许我们通过选项卡选择多个*页面*。它们非常适用于将复杂的界面分解为更容易用户接受的较小块。

使用`QTabWidget`的工作流程如下：

1.  创建`QTabWidget`对象

1.  在`QWidget`或其他小部件类上构建一个 UI 页面

1.  使用`QTabWidget.addTab()`方法将页面添加到选项卡小部件

让我们试试吧；首先，创建选项卡小部件：

```py
        tab_widget = qtw.QTabWidget()
        layout.addWidget(tab_widget)
```

接下来，让我们将我们在*放置和排列小部件*部分下构建的`grid_layout`移动到一个容器小部件下：

```py
        container = qtw.QWidget(self)
        grid_layout = qtw.QGridLayout()
        # comment out this line:
        #layout.addLayout(grid_layout)
        container.setLayout(grid_layout)
```

最后，让我们将我们的`container`小部件添加到一个新的选项卡中：

```py
        tab_widget.addTab(container, 'Tab the first')
```

`addTab()`的第二个参数是选项卡上将显示的标题文本。可以通过多次调用`addTab()`来添加更多的选项卡，就像这样：

```py
        tab_widget.addTab(subwidget, 'Tab the second')
```

`insertTab()`方法也可以用于在末尾以外的其他位置添加新的选项卡。

`QTabWidget`有一些我们可以自定义的属性，列在这里：

| 属性 | 参数 | 描述 |
| --- | --- | --- |
| `movable` | 布尔值 | 选项卡是否可以重新排序。默认值为`False`。 |
| `tabBarAutoHide` | 布尔值 | 当只有一个选项卡时，选项卡栏是隐藏还是显示。 |
| `tabPosition` | `QTabWidget.TabPosition` | 选项卡出现在小部件的哪一侧。默认值为 North（顶部）。 |
| `tabShape` | `QTabWidget.TabShape` | 选项卡的形状。可以是圆角或三角形。 |
| `tabsClosable` | 布尔值 | 是否在选项卡上显示一个关闭按钮。 |
| `useScrollButtons` | 布尔值 | 是否在有许多选项卡时使用滚动按钮或展开。 |

让我们修改我们的`QTabWidget`，使其在小部件的左侧具有可移动的三角形选项卡：

```py
        tab_widget = qtw.QTabWidget(
            movable=True,
            tabPosition=qtw.QTabWidget.West,
            tabShape=qtw.QTabWidget.Triangular
        )
```

`QStackedWidget`类似于选项卡小部件，只是它不包含用于切换页面的内置机制。如果您想要构建自己的选项卡切换机制，您可能会发现它很有用。

# QGroupBox

`QGroupBox`提供了一个带有标签的面板，并且（取决于平台样式）有边框。它对于在表单上将相关的输入分组在一起非常有用。我们创建`QGroupBox`的方式与创建`QWidget`容器的方式相同，只是它可以有一个边框和一个框的标题，例如：

```py
        groupbox = qtw.QGroupBox('Buttons')
        groupbox.setLayout(qtw.QHBoxLayout())
        groupbox.layout().addWidget(qtw.QPushButton('OK'))
        groupbox.layout().addWidget(qtw.QPushButton('Cancel'))
        layout.addWidget(groupbox)
```

在这里，我们创建了一个带有`Buttons`标题的分组框。我们给它一个水平布局，并添加了两个按钮小部件。

请注意，在这个例子中，我们没有像以前那样给布局一个自己的句柄，而是创建了一个匿名的`QHBoxLayout`，然后使用小部件的`layout()`访问器方法来检索一个引用，以便添加小部件。在某些情况下，您可能更喜欢这种方法。

分组框相当简单，但它确实有一些有趣的属性：

| 属性 | 参数 | 描述 |
| --- | --- | --- |
| `title` | 字符串 | 标题文本。 |
| `checkable` | 布尔值 | groupbox 是否有一个复选框来启用/禁用它的内容。 |
| `checked` | 布尔值 | 一个可勾选的 groupbox 是否被勾选（启用）。 |
| `alignment` | `QtCore.Qt.Alignment` | 标题文本的对齐方式。 |
| `flat` | 布尔值 | 盒子是平的还是有框架。 |

`checkable`和`checked`属性非常有用，用于希望用户能够禁用表单的整个部分的情况（例如，如果与运输地址相同，则禁用订单表单的帐单地址部分）。

让我们重新配置我们的`groupbox`，如下所示：

```py
        groupbox = qtw.QGroupBox(
            'Buttons',
            checkable=True,
            checked=True,
            alignment=qtc.Qt.AlignHCenter,
            flat=True
        )
```

请注意，现在按钮可以通过简单的复选框切换禁用，并且框架的外观不同。

如果您只想要一个有边框的小部件，而没有标签或复选框功能，`QFrame`类可能是一个更好的选择。

# 验证小部件

尽管 Qt 提供了各种现成的输入小部件，例如日期和数字，但有时我们可能会发现需要一个具有非常特定约束的小部件。这些输入约束可以使用`QValidator`类创建。

工作流程如下：

1.  通过子类化`QtGui.QValidator`创建自定义验证器类

1.  用我们的验证逻辑覆盖`validate()`方法

1.  将我们自定义类的一个实例分配给小部件的`validator`属性

一旦分配给可编辑小部件，`validate()`方法将在用户更新小部件的值时被调用（例如，在`QLineEdit`中的每次按键），并确定输入是否被接受。

# 创建 IPv4 输入小部件

为了演示小部件验证，让我们创建一个验证**互联网协议版本 4**（**IPv4**）地址的小部件。IPv4 地址必须是 4 个整数，每个整数在`0`和`255`之间，并且每个数字之间有一个点。

让我们首先创建我们的验证器类。在`MainWindow`类之前添加这个类：

```py
class IPv4Validator(qtg.QValidator):
    """Enforce entry of IPv4 Addresses"""
```

接下来，我们需要重写这个类的`validate()`方法。`validate()`接收两个信息：一个包含建议输入的字符串和输入发生的索引。它将返回一个指示输入是`可接受`、`中间`还是`无效`的值。如果输入是可接受或中间的，它将被接受。如果无效，它将被拒绝。

用于指示输入状态的值是`QtValidator.Acceptable`、`QtValidator.Intermediate`或`QtValidator.Invalid`。

在 Qt 文档中，我们被告知验证器类应该只返回状态常量。然而，在 PyQt 中，实际上需要返回一个包含状态、字符串和位置的元组。不幸的是，这似乎没有很好的记录，如果您忘记了这一点，错误就不直观。

让我们开始构建我们的 IPv4 验证逻辑如下：

1.  在点字符上拆分字符串：

```py
            def validate(self, string, index):
                octets = string.split('.')
```

1.  如果有超过`4`个段，该值无效：

```py
            if len(octets) > 4:
                state = qtg.QValidator.Invalid
```

1.  如果任何填充的段不是数字字符串，则该值无效：

```py
            elif not all([x.isdigit() for x in octets if x != '']):
                state = qtg.QValidator.Invalid
```

1.  如果不是每个填充的段都可以转换为 0 到 255 之间的整数，则该值无效：

```py
            elif not all([0 <= int(x) <= 255 for x in octets if x != '']):
                state = qtg.QValidator.Invalid
```

1.  如果我们已经进行了这些检查，该值要么是中间的，要么是有效的。如果段少于四个，它是中间的：

```py
            elif len(octets) < 4:
                state = qtg.QValidator.Intermediate
```

1.  如果有任何空段，该值是中间的：

```py
            elif any([x == '' for x in octets]):
                state = qtg.QValidator.Intermediate
```

1.  如果值通过了所有这些测试，它是可接受的。我们可以返回我们的元组：

```py
            else:
                state = qtg.QValidator.Acceptable
            return (state, string, index)
```

要使用此验证器，我们只需要创建一个实例并将其分配给一个小部件：

```py
        # set the default text to a valid value
        line_edit.setText('0.0.0.0')
        line_edit.setValidator(IPv4Validator())
```

如果您现在运行演示，您会看到行编辑现在限制您输入有效的 IPv4 地址。

# 使用 QSpinBox 进行离散值

正如您在*创建基本 QtWidgets 小部件*部分中学到的，`QSpinBox`可以用于离散的字符串值列表，就像组合框一样。`QSpinBox`有一个内置的`validate()`方法，它的工作方式就像`QValidator`类的方法一样，用于限制小部件的输入。要使旋转框使用离散字符串列表，我们需要对`QSpinBox`进行子类化，并覆盖`validate()`和另外两个方法，`valueFromText()`和`textFromValue()`。

让我们创建一个自定义的旋转框类，用于从列表中选择项目；在`MainWindow`类之前，输入以下内容：

```py
class ChoiceSpinBox(qtw.QSpinBox):
    """A spinbox for selecting choices."""

    def __init__(self, choices, *args, **kwargs):
        self.choices = choices
        super().__init__(
            *args,
            maximum=len(self.choices) - 1,
            minimum=0,
            **kwargs
        )
```

我们正在对`qtw.QSpinBox`进行子类化，并覆盖构造函数，以便我们可以传入一个选择列表或元组，将其存储为`self.choices`。然后我们调用`QSpinBox`构造函数；请注意，我们设置了`maximum`和`minimum`，以便它们不能设置在我们选择的范围之外。我们还传递了任何额外的位置或关键字参数，以便我们可以利用所有其他`QSpinBox`属性设置。

接下来，让我们重新实现`valueFromText()`，如下所示：

```py
    def valueFromText(self, text):
        return self.choices.index(text)
```

这个方法的目的是能够返回一个整数索引值，给定一个与显示的选择项匹配的字符串。我们只是返回传入的任何字符串的列表索引。

接下来，我们需要重新实现补充方法`textFromValue()`：

```py
    def textFromValue(self, value):
        try:
            return self.choices[value]
        except IndexError:
            return '!Error!'
```

这个方法的目的是将整数索引值转换为匹配选择的文本。在这种情况下，我们只是返回给定索引处的字符串。如果以某种方式小部件传递了超出范围的值，我们将返回`!Error!`作为字符串。由于此方法用于确定在设置特定值时框中显示的内容，如果以某种方式值超出范围，这将清楚地显示错误条件。

最后，我们需要处理`validate()`。就像我们的`QValidator`类一样，我们需要创建一个方法，该方法接受建议的输入和编辑索引，并返回一个包含验证状态、字符串值和索引的元组。

我们将像这样编写它：

```py
    def validate(self, string, index):
        if string in self.choices:
            state = qtg.QValidator.Acceptable
        elif any([v.startswith(string) for v in self.choices]):
            state = qtg.QValidator.Intermediate
        else:
            state = qtg.QValidator.Invalid
        return (state, string, index)
```

在我们的方法中，如果输入字符串在`self.choices`中找到，我们将返回`Acceptable`，如果任何选择项以输入字符串开头（包括空字符串），我们将返回`Intermediate`，在任何其他情况下我们将返回`Invalid`。

有了这个类创建，我们可以在我们的`MainWindow`类中创建一个小部件：

```py
        ratingbox = ChoiceSpinBox(
            ['bad', 'average', 'good', 'awesome'],
            self
        )
        sublayout.addWidget(ratingbox)
```

`QComboBox`对象和具有文本选项的`QSpinBox`对象之间的一个重要区别是，旋转框项目缺少`data`属性。只能返回文本或索引。最适合用于诸如月份、星期几或其他可转换为整数值的顺序列表。

# 构建一个日历应用程序 GUI

现在是时候将我们所学到的知识付诸实践，实际构建一个简单的功能性 GUI。我们的目标是构建一个简单的日历应用程序，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/e7ff923c-5442-4c41-ba36-c81f7435b740.png)

我们的界面还不能正常工作；现在，我们只关注如何创建和布局组件，就像屏幕截图中显示的那样。我们将以两种方式实现这一点：一次只使用代码，第二次使用 Qt Designer。

这两种方法都是有效的，而且都可以正常工作，尽管您会看到，每种方法都有优点和缺点。

# 在代码中构建 GUI

通过复制第一章中的应用程序模板，创建一个名为`calendar_form.py`的新文件，*PyQt 入门*。

然后我们将配置我们的主窗口；在`MainWindow`构造函数中，从这段代码开始：

```py
        self.setWindowTitle("My Calendar App")
        self.resize(800, 600)
```

这段代码将设置我们窗口的标题为适当的内容，并设置窗口的固定大小为 800 x 600。请注意，这只是初始大小，用户可以调整窗体的大小。

# 创建小部件

现在，让我们创建所有的小部件：

```py
        self.calendar = qtw.QCalendarWidget()
        self.event_list = qtw.QListWidget()
        self.event_title = qtw.QLineEdit()
        self.event_category = qtw.QComboBox()
        self.event_time = qtw.QTimeEdit(qtc.QTime(8, 0))
        self.allday_check = qtw.QCheckBox('All Day')
        self.event_detail = qtw.QTextEdit()
        self.add_button = qtw.QPushButton('Add/Update')
        self.del_button = qtw.QPushButton('Delete')
```

这些都是我们在 GUI 中将要使用的所有小部件。其中大部分我们已经介绍过了，但有两个新的：`QCalendarWidget`和`QListWidget`。

`QCalendarWidget`正是您所期望的：一个完全交互式的日历，可用于查看和选择日期。虽然它有许多可以配置的属性，但对于我们的需求，默认配置就可以了。我们将使用它来允许用户选择要查看和编辑的日期。

`QListWidget`用于显示、选择和编辑列表中的项目。我们将使用它来显示保存在特定日期的事件列表。

在我们继续之前，我们需要使用一些项目配置我们的`event_category`组合框以进行选择。以下是此框的计划：

+   当没有选择时，将其读为“选择类别…”作为占位符

+   包括一个名为`New…`的选项，也许允许用户输入新类别。

+   默认情况下包括一些常见类别，例如`工作`、`会议`和`医生`

为此，请添加以下内容：

```py
        # Add event categories
        self.event_category.addItems(
            ['Select category…', 'New…', 'Work',
             'Meeting', 'Doctor', 'Family']
            )
        # disable the first category item
        self.event_category.model().item(0).setEnabled(False)
```

`QComboBox`实际上没有占位符文本，因此我们在这里使用了一个技巧来模拟它。我们像往常一样使用`addItems()`方法添加了我们的组合框项目。接下来，我们使用`model()`方法检索其数据模型，该方法返回一个`QStandardItemModel`实例。数据模型保存组合框中所有项目的列表。我们可以使用模型的`item()`方法来访问给定索引（在本例中为`0`）处的实际数据项，并使用其`setEnabled()`方法来禁用它。

简而言之，我们通过禁用组合框中的第一个条目来模拟占位符文本。

我们将在第五章中了解更多关于小部件数据模型的知识，*使用模型视图类创建数据接口*。

# 构建布局

我们的表单将需要一些嵌套布局才能将所有内容放置到正确的位置。让我们分解我们提议的设计，并确定如何创建此布局：

+   应用程序分为左侧的日历和右侧的表单。这表明主要布局使用`QHBoxLayout`。

+   右侧的表单是一个垂直堆叠的组件，表明我们应该使用`QVBoxLayout`在右侧排列事物。

+   右下角的事件表单可以大致布局在网格中，因此我们可以在那里使用`QGridLayout`。

我们将首先创建主布局，然后添加日历：

```py
        main_layout = qtw.QHBoxLayout()
        self.setLayout(main_layout)
        main_layout.addWidget(self.calendar)
```

我们希望日历小部件填充布局中的任何额外空间，因此我们将根据需要设置其大小策略：

```py
        self.calendar.setSizePolicy(
            qtw.QSizePolicy.Expanding,
            qtw.QSizePolicy.Expanding
        )
```

现在，在右侧创建垂直布局，并添加标签和事件列表：

```py
        right_layout = qtw.QVBoxLayout()
        main_layout.addLayout(right_layout)
        right_layout.addWidget(qtw.QLabel('Events on Date'))
        right_layout.addWidget(self.event_list)
```

如果有更多的垂直空间，我们希望事件列表填满所有可用的空间。因此，让我们将其大小策略设置如下：

```py
        self.event_list.setSizePolicy(
            qtw.QSizePolicy.Expanding,
            qtw.QSizePolicy.Expanding
        )
```

GUI 的下一部分是事件表单及其标签。我们可以在这里使用另一个标签，但设计建议这些表单字段在此标题下分组在一起，因此`QGroupBox`更合适。

因此，让我们创建一个带有`QGridLayout`的组框来容纳我们的事件表单：

```py
        event_form = qtw.QGroupBox('Event')
        right_layout.addWidget(event_form)
        event_form_layout = qtw.QGridLayout()
        event_form.setLayout(event_form_layout)
```

最后，我们需要将剩余的小部件添加到网格布局中：

```py
        event_form_layout.addWidget(self.event_title, 1, 1, 1, 3)
        event_form_layout.addWidget(self.event_category, 2, 1)
        event_form_layout.addWidget(self.event_time, 2, 2,)
        event_form_layout.addWidget(self.allday_check, 2, 3)
        event_form_layout.addWidget(self.event_detail, 3, 1, 1, 3)
        event_form_layout.addWidget(self.add_button, 4, 2)
        event_form_layout.addWidget(self.del_button, 4, 3)
```

我们将网格分为三列，并使用可选的列跨度参数将我们的标题和详细字段跨越所有三列。

现在我们完成了！此时，您可以运行脚本并查看您完成的表单。当然，它目前还没有做任何事情，但这是我们第三章的主题，*使用信号和槽处理事件*。

# 在 Qt Designer 中构建 GUI

让我们尝试构建相同的 GUI，但这次我们将使用 Qt Designer 构建它。

# 第一步

首先，按照第一章中描述的方式启动 Qt Designer，然后基于小部件创建一个新表单，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/eda1e482-5f33-4176-a699-f3da3c3f43a7.png)

现在，单击小部件，我们将使用右侧的属性面板配置其属性：

1.  将对象名称更改为`MainWindow`

1.  在**几何**下，将宽度更改为`800`，高度更改为`600`

1.  将窗口标题更改为`我的日历应用程序`

接下来，我们将开始添加小部件。在左侧的小部件框中滚动查找**日历小部件**，然后将其拖放到主窗口上。选择日历并编辑其属性：

1.  将名称更改为`calendar`

1.  将水平和垂直大小策略更改为`扩展`

要设置我们的主要布局，右键单击主窗口（不是日历），然后选择布局|**水平布局**。这将在主窗口小部件中添加一个`QHBoxLayout`。请注意，直到至少有一个小部件放在主窗口上，您才能这样做，这就是为什么我们首先添加了日历小部件。

# 构建右侧面板

现在，我们将为表单的右侧添加垂直布局。将一个垂直布局拖到日历小部件的右侧。然后将一个标签小部件拖到垂直布局中。确保标签在层次结构中列为垂直布局的子对象，而不是同级对象：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/ba44242d-5956-4cd8-9e1a-492662eec464.png)

如果您在将小部件拖放到未展开的布局上遇到问题，您也可以将其拖放到**对象检查器**面板中的层次结构中。

双击标签上的文本，将其更改为日期上的事件。

接下来，将一个列表小部件拖到垂直布局中，使其出现在标签下面。将其重命名为`event_list`，并检查其属性，确保其大小策略设置为`扩展`。

# 构建事件表单

在小部件框中找到组框，并将其拖到列表小部件下面。双击文本，并将其更改为`事件`。

将一个行编辑器拖到组框上，确保它显示为组框对象检查器中的子对象。将对象名称更改为`event_title`。

现在，右键单击组框，选择布局，然后选择**在网格中布局**。这将在组框中创建一个网格布局。

将一个组合框拖到下一行。将一个时间编辑器拖到其右侧，然后将一个复选框拖到其右侧。将它们分别命名为`event_category`，`event_time`和`allday_check`。双击复选框文本，并将其更改为`全天`。

要向组合框添加选项，右键单击框并选择**编辑项目**。这将打开一个对话框，我们可以在其中输入我们的项目，所以点击+按钮添加`选择类别…`，就像第一个一样，然后`新建…`，然后一些随机类别（如`工作`，`医生`，`会议`）。

不幸的是，我们无法在 Qt Designer 中禁用第一项。当我们在应用程序中使用我们的表单时，我们将在第三章中讨论如何处理这个问题，*使用信号和槽处理事件*。

注意，添加这三个小部件会将行编辑器推到右侧。我们需要修复该小部件的列跨度。单击行编辑器，抓住右边缘的手柄，将其向右拖动，直到它扩展到组框的宽度。

现在，抓住一个文本编辑器，将其拖到其他小部件下面。注意它被挤压到第一列，所以就像行编辑一样，将其向右拖动，直到填满整个宽度。将文本编辑器重命名为`event_detail`。

最后，将两个按钮小部件拖到表单底部。确保将它们拖到第二列和第三列，留下第一列为空。将它们重命名为`add_button`和`del_button`，将文本分别更改为`添加/更新`和`删除`。

# 预览表单

将表单保存为`calendar_form.ui`，然后按下*Ctrl* + *R*进行预览。您应该看到一个完全功能的表单，就像原始截图中显示的那样。要实际使用这个文件，我们需要将其转换为 Python 代码并将其导入到实际的脚本中。在我们对表单进行一些额外修改之后，我们将在第三章中进行讨论，*使用信号和槽处理事件*。

# 总结

在本章中，我们介绍了 Qt 中一些最受欢迎的小部件类。您学会了如何创建它们，自定义它们，并将它们添加到表单中。我们讨论了各种控制小部件大小的方法，并练习了在 Python 代码和 Qt Designer 所见即所得应用程序中构建简单应用程序表单的方法。

在下一章中，我们将学习如何使这个表单真正做一些事情，同时探索 Qt 的核心通信和事件处理系统。保持你的日历表单方便，因为我们将对它进行更多修改，并从中制作一个功能应用程序。

# 问题

尝试这些问题来测试你从本章学到的知识：

1.  你会如何创建一个全屏、没有窗口框架，并使用沙漏光标的`QWidget`？

1.  你被要求为计算机库存数据库设计一个数据输入表单。为以下字段选择最好的小部件使用：

+   **计算机制造商**：你公司购买的八个品牌之一

+   **处理器速度**：CPU 速度，以 GHz 为单位

+   **内存量**：内存量，以 MB 为单位

+   **主机名**：计算机的主机名

+   **视频制作**：视频硬件是 Nvidia、AMD 还是 Intel

+   **OEM 许可证**：计算机是否使用原始设备制造商（OEM）许可证

1.  数据输入表单包括一个需要`XX-999-9999X`格式的`库存编号`字段，其中`X`是从`A`到`Z`的大写字母，不包括`O`和`I`，`9`是从`0`到`9`的数字。你能创建一个验证器类来验证这个输入吗？

1.  看看下面的计算器表单——可能使用了哪些布局来创建它？

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/1b7c100d-6694-48e8-8bc0-e15dc8c0aba7.png)

1.  参考前面的计算器表单，当表单被调整大小时，你会如何使按钮网格占用任何额外的空间？

1.  计算器表单中最顶层的小部件是一个`QLCDNumber`小部件。你能找到关于这个小部件的 Qt 文档吗？它有哪些独特的属性？你什么时候会使用它？

1.  从你的模板代码开始，在代码中构建计算器表单。

1.  在 Qt Designer 中构建计算器表单。

# 进一步阅读

查看以下资源，了解本章涉及的主题的更多信息：

+   `QWidget`属性文档列出了所有`QWidget`的属性，这些属性被所有子类继承，网址为[`doc.qt.io/qt-5/qwidget.html#properties`](https://doc.qt.io/qt-5/qwidget.html#properties)

+   `Qt`命名空间文档列出了 Qt 中使用的许多全局枚举，网址为[`doc.qt.io/qt-5/qt.html#WindowState-enum`](https://doc.qt.io/qt-5/qt.html#WindowState-enum)

+   Qt 布局管理教程提供了有关布局和大小调整的详细信息，网址为[`doc.qt.io/qt-5/layout.html`](https://doc.qt.io/qt-5/layout.html)

+   `QDateTime`文档提供了有关在 Qt 中处理日期和时间的更多信息，网址为[`doc.qt.io/qt-5/qdatetime.html`](https://doc.qt.io/qt-5/qdatetime.html)

+   有关`QCalendarWidget`的更多信息可以在[`doc.qt.io/qt-5/qcalendarwidget.html`](https://doc.qt.io/qt-5/qcalendarwidget.html)找到。


# 第三章：使用信号和插槽处理事件

将小部件组合成一个漂亮的表单是设计应用程序的一个很好的第一步，但是为了 GUI 能够发挥作用，它需要连接到实际执行操作的代码。为了在 PyQt 中实现这一点，我们需要了解 Qt 最重要的功能之一，**信号和插槽**。

在本章中，我们将涵盖以下主题：

+   信号和插槽基础

+   创建自定义信号和插槽

+   自动化我们的日历表单

# 技术要求

除了第一章中列出的基本要求外，*使用 PyQt 入门*，您还需要来自第二章*使用 QtWidgets 构建全面表单*的日历表单代码和 Qt Designer 文件。您可能还希望从我们的 GitHub 存储库[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter03`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter03)下载示例代码。

查看以下视频，看看代码是如何运行的：[`bit.ly/2M5OFQo`](http://bit.ly/2M5OFQo)

# 信号和插槽基础

**信号**是对象的特殊属性，可以在对应的**事件**类型中发出。事件可以是用户操作、超时或异步方法调用的完成等。

**插槽**是可以接收信号并对其做出响应的对象方法。我们连接信号到插槽，以配置应用程序对事件的响应。

所有从`QObject`继承的类（这包括 Qt 中的大多数类，包括所有`QWidget`类）都可以发送和接收信号。每个不同的类都有适合该类功能的一组信号和插槽。

例如，`QPushButton`有一个`clicked`信号，每当用户点击按钮时就会发出。`QWidget`类有一个`close()`插槽，如果它是顶级窗口，就会导致它关闭。我们可以这样连接两者：

```py
self.quitbutton = qtw.QPushButton('Quit')
self.quitbutton.clicked.connect(self.close)
self.layout().addWidget(self.quitbutton)
```

如果您将此代码复制到我们的应用程序模板中并运行它，您会发现单击“退出”按钮会关闭窗口并结束程序。在 PyQt5 中连接信号到插槽的语法是`object1.signalName.connect(object2.slotName)`。

您还可以在创建对象时通过将插槽作为关键字参数传递给信号来进行连接。例如，前面的代码可以重写如下：

```py
self.quitbutton = qtw.QPushButton('Quit', clicked=self.close)
self.layout().addWidget(self.quitbutton)
```

C++和旧版本的 PyQt 使用非常不同的信号和插槽语法，它使用`SIGNAL()`和`SLOT()`包装函数。这些在 PyQt5 中不存在，所以如果您在遵循旧教程或非 Python 文档，请记住这一点。

信号还可以携带数据，插槽可以接收。例如，`QLineEdit`有一个`textChanged`信号，随信号发送进小部件的文本一起。该行编辑还有一个接受字符串参数的`setText()`插槽。我们可以这样连接它们：

```py
self.entry1 = qtw.QLineEdit()
self.entry2 = qtw.QLineEdit()
self.layout().addWidget(self.entry1)
self.layout().addWidget(self.entry2)
self.entry1.textChanged.connect(self.entry2.setText)
```

在这个例子中，我们将`entry1`的`textChanged`信号连接到`entry2`的`setText()`插槽。这意味着每当`entry1`中的文本发生变化时，它将用输入的文本信号`entry2`；`entry2`将把自己的文本设置为接收到的字符串，导致它镜像`entry1`中输入的任何内容。

在 PyQt5 中，插槽不必是官方的 Qt 插槽方法；它可以是任何 Python 可调用对象，比如自定义方法或内置函数。例如，让我们将`entry2`小部件的`textChanged`连接到老式的`print()`：

```py
self.entry2.textChanged.connect(print)
```

现在，您会发现对`entry2`的每次更改都会打印到控制台。`textChanged`信号基本上每次触发时都会调用`print()`，并传入信号携带的文本。

信号甚至可以连接到其他信号，例如：

```py
self.entry1.editingFinished.connect(lambda: print('editing finished'))
self.entry2.returnPressed.connect(self.entry1.editingFinished)
```

我们已经将`entry2`小部件的`returnPressed`信号（每当用户在小部件上按下*return*/*Enter*时发出）连接到`entry1`小部件的`editingFinished`信号，而`editingFinished`信号又连接到一个打印消息的`lambda`函数。当你连接一个信号到另一个信号时，事件和数据会从一个信号传递到下一个信号。最终结果是在`entry2`上触发`returnPressed`会导致`entry1`发出`editingFinished`，然后运行`lambda`函数。

# 信号和槽连接的限制

尽管 PyQt 允许我们将信号连接到任何 Python 可调用对象，但有一些规则和限制需要牢记。与 Python 不同，C++是一种**静态类型**语言，这意味着变量和函数参数必须给定一个类型（`string`、`integer`、`float`或许多其他类型），并且存储在变量中或传递给该函数的任何值必须具有匹配的类型。这被称为**类型安全**。

原生的 Qt 信号和槽是类型安全的。例如，假设我们尝试将行编辑的`textChanged`信号连接到按钮的`clicked`信号，如下所示：

```py
self.entry1.textChanged.connect(self.quitbutton.clicked)
```

这是行不通的，因为`textChanged`发出一个字符串，而`clicked`发出（并且因此期望接收）一个布尔值。如果你运行这个，你会得到这样的错误：

```py
QObject::connect: Incompatible sender/receiver arguments
        QLineEdit::textChanged(QString) --> QPushButton::clicked(bool)
Traceback (most recent call last):
  File "signal_slots_demo.py", line 57, in <module>
    mw = MainWindow()
  File "signal_slots_demo.py", line 32, in __init__
    self.entry1.textChanged.connect(self.quitbutton.clicked)
TypeError: connect() failed between textChanged(QString) and clicked()
```

槽可以有多个实现，每个实现都有自己的**签名**，允许相同的槽接受不同的参数类型。这被称为**重载**槽。只要我们的信号签名与任何重载的槽匹配，我们就可以建立连接，Qt 会确定我们连接到哪一个。

当连接到一个是 Python 函数的槽时，我们不必担心参数类型，因为 Python 是**动态类型**的（尽管我们需要确保我们的 Python 代码对传递给它的任何对象都做正确的事情）。然而，与对 Python 函数的任何调用一样，我们确实需要确保传入足够的参数来满足函数签名。

例如，让我们向`MainWindow`类添加一个方法，如下所示：

```py
def needs_args(self, arg1, arg2, arg3):
        pass
```

这个实例方法需要三个参数（`self`会自动传递）。让我们尝试将按钮的`clicked`信号连接到它：

```py
self.badbutton = qtw.QPushButton("Bad")
self.layout().addWidget(self.badbutton)
self.badbutton.clicked.connect(self.needs_args)
```

这段代码本身并不反对连接，但当你点击按钮时，程序会崩溃并显示以下错误：

```py
TypeError: needs_args() missing 2 required positional arguments: 'arg2' and 'arg3'
Aborted (core dumped)
```

由于`clicked`信号只发送一个参数，函数调用是不完整的，会抛出异常。可以通过将`arg2`和`arg3`变成关键字参数（添加默认值），或者创建一个以其他方式填充它们的包装函数来解决这个问题。

顺便说一句，槽接收的参数比信号发送的参数少的情况并不是问题。Qt 只是从信号中丢弃额外的数据。

因此，例如，将`clicked`连接到一个没有参数的方法是没有问题的，如下所示：

```py
        # inside __init__()
        self.goodbutton = qtw.QPushButton("Good")
        self.layout().addWidget(self.goodbutton)
        self.goodbutton.clicked.connect(self.no_args)
        # ...

    def no_args(self):
        print('I need no arguments')
```

# 创建自定义信号和槽

为按钮点击和文本更改设置回调是信号和槽的常见和非常明显的用法，但这实际上只是开始。在本质上，信号和槽机制可以被看作是应用程序中任何两个对象进行通信的一种方式，同时保持**松散耦合**。

松散耦合是指保持两个对象彼此需要了解的信息量最少。这是设计大型复杂应用程序时必须保留的重要特性，因为它隔离了代码并防止意外的破坏。相反的是紧密耦合，其中一个对象的代码严重依赖于另一个对象的内部结构。

为了充分利用这一功能，我们需要学习如何创建自己的自定义信号和槽。

# 使用自定义信号在窗口之间共享数据

假设您有一个弹出表单窗口的程序。当用户完成填写表单并提交时，我们需要将输入的数据传回主应用程序类进行处理。我们可以采用几种方法来解决这个问题；例如，主应用程序可以监视弹出窗口的**提交**按钮的单击事件，然后在销毁对话框之前从其字段中获取数据。但这种方法要求主窗体了解弹出对话框的所有部件，而且任何对弹出窗口的重构都可能破坏主应用程序窗口中的代码。

让我们尝试使用信号和槽的不同方法。从第一章中打开我们应用程序模板的新副本，*PyQt 入门*，并开始一个名为`FormWindow`的新类，就像这样：

```py
class FormWindow(qtw.QWidget):

    submitted = qtc.pyqtSignal(str)
```

在这个类中我们定义的第一件事是一个名为`submitted`的自定义信号。要定义自定义信号，我们需要调用`QtCore.pyqtSignal()`函数。`pyqtSignal()`的参数是我们的信号将携带的数据类型，在这种情况下是`str`。我们可以在这里使用 Python `type`对象，或者命名 C++数据类型的字符串（例如`'QString'`）。

现在让我们通过定义`__init__()`方法来构建表单，如下所示：

```py
    def __init__(self):
        super().__init__()
        self.setLayout(qtw.QVBoxLayout())

        self.edit = qtw.QLineEdit()
        self.submit = qtw.QPushButton('Submit', clicked=self.onSubmit)

        self.layout().addWidget(self.edit)
        self.layout().addWidget(self.submit)
```

在这里，我们定义了一个用于数据输入的`QLineEdit`和一个用于提交表单的`QPushButton`。按钮单击信号绑定到一个名为`onSubmit`的方法，我们将在下面定义：

```py
    def onSubmit(self):
        self.submitted.emit(self.edit.text())
        self.close()
```

在这个方法中，我们调用`submitted`信号的`emit()`方法，传入`QLineEdit`的内容。这意味着任何连接的槽都将使用从`self.edit.text()`检索到的字符串进行调用。

发射信号后，我们关闭`FormWindow`。

在我们的`MainWindow`构造函数中，让我们构建一个使用它的应用程序：

```py
    def __init__(self):
        super().__init__()
        self.setLayout(qtw.QVBoxLayout())

        self.label = qtw.QLabel('Click "change" to change this text.')
        self.change = qtw.QPushButton("Change", clicked=self.onChange)
        self.layout().addWidget(self.label)
        self.layout().addWidget(self.change)
        self.show()
```

在这里，我们创建了一个`QLabel`和一个`QPushButton`，并将它们添加到垂直布局中。单击按钮时，按钮调用一个名为`onChange()`的方法。

`onChange()`方法看起来像这样：

```py
    def onChange(self):
        self.formwindow = FormWindow()
        self.formwindow.submitted.connect(self.label.setText)
        self.formwindow.show()
```

这个方法创建了一个`FormWindow`的实例。然后将我们的自定义信号`FormWindow.submitted`绑定到标签的`setText`槽；`setText`接受一个字符串作为参数，而我们的信号发送一个字符串。

如果您运行此应用程序，您会看到当您提交弹出窗口表单时，标签中的文本确实会更改。

这种设计的美妙之处在于`FormWindow`不需要知道任何关于`MainWindow`的东西，而`MainWindow`只需要知道`FormWindow`有一个`submitted`信号，该信号发射输入的字符串。只要相同的信号发射相同的数据，我们可以轻松修改任一类的结构和内部，而不会对另一类造成问题。

`QtCore`还包含一个`pyqtSlot()`函数，我们可以将其用作装饰器，表示 Python 函数或方法旨在作为槽使用。

例如，我们可以装饰我们的`MainWindow.onChange()`方法来声明它为一个槽：

```py
    @qtc.pyqtSlot()
    def onChange(self):
        # ...
```

这纯粹是可选的，因为我们可以使用任何 Python 可调用对象作为槽，尽管这确实给了我们强制类型安全的能力。例如，如果我们希望要求`onChange()`始终接收一个字符串，我们可以这样装饰它：

```py
    @qtc.pyqtSlot(str)
    def onChange(self):
        # ...
```

如果您这样做并运行程序，您会看到我们尝试连接`clicked`信号会失败：

```py
Traceback (most recent call last):
  File "form_window.py", line 47, in <module>
    mw = MainWindow()
  File "form_window.py", line 31, in __init__
    self.change = qtw.QPushButton("Change", clicked=self.onChange)
TypeError: decorated slot has no signature compatible with clicked(bool)
```

除了强制类型安全外，将方法声明为槽还会减少其内存使用量，并提供一点速度上的改进。因此，虽然这完全是可选的，但对于只会被用作槽的方法来说，这可能值得做。

# 信号和槽的重载

就像 C++信号和槽可以被重载以接受不同的参数签名一样，我们也可以重载我们自定义的 PyQt 信号和槽。例如，假设如果在我们的弹出窗口中输入了一个有效的整数字符串，我们希望将其作为字符串和整数发射出去。

为了做到这一点，我们首先必须重新定义我们的信号：

```py
    submitted = qtc.pyqtSignal([str], [int, str])
```

我们不仅传入单个变量类型，而是传入两个变量类型的列表。每个列表代表一个信号签名的参数列表。因此，我们在这里注册了两个信号：一个只发送字符串，一个发送整数和字符串。

在`FormWindow.onSubmit()`中，我们现在可以检查行编辑中的文本，并使用适当的签名发送信号：

```py
    def onSubmit(self):
        if self.edit.text().isdigit():
            text = self.edit.text()
            self.submitted[int, str].emit(int(text), text)
        else:
            self.submitted[str].emit(self.edit.text())
        self.close()
```

在这里，我们测试`self.edit`中的文本，以查看它是否是有效的数字字符串。如果是，我们将其转换为`int`，并使用整数和文本版本的文本发出`submitted`信号。选择签名的语法是在信号名称后跟一个包含参数类型列表的方括号。

回到主窗口，我们将定义两种新方法来处理这些信号：

```py
    @qtc.pyqtSlot(str)
    def onSubmittedStr(self, string):
        self.label.setText(string)

    @qtc.pyqtSlot(int, str)
    def onSubmittedIntStr(self, integer, string):
        text = f'The string {string} becomes the number {integer}'
        self.label.setText(text)
```

我们已经创建了两个插槽——一个接受字符串，另一个接受整数和字符串。现在我们可以将`FormWindow`中的两个信号连接到适当的插槽，如下所示：

```py
    def onChange(self):
        self.formwindow = FormWindow()
        self.formwindow.submitted[str].connect(self.onSubmittedStr)
        self.formwindow.submitted[int, str].connect(self.onSubmittedIntStr)
```

运行脚本，您会发现输入一串数字会打印与字母数字字符串不同的消息。

# 自动化我们的日历表单

要了解信号和插槽在实际应用程序中的使用方式，让我们拿我们在第二章 *使用 QtWidgets 构建表单*中构建的日历表单，并将其转换为一个可工作的日历应用程序。为此，我们需要进行以下更改：

+   应用程序需要一种方法来存储我们输入的事件。

+   全天复选框应在选中时禁用时间输入。

+   在日历上选择一天应该用当天的事件填充事件列表。

+   在事件列表中选择一个事件应该用事件的详细信息填充表单。

+   单击“添加/更新”应该更新保存的事件详细信息，如果选择了事件，或者如果没有选择事件，则添加一个新事件。

+   单击删除应该删除所选事件。

+   如果没有选择事件，删除应该被禁用。

+   选择“新建…”作为类别应该打开一个对话框，允许我们输入一个新的类别。如果我们选择输入一个，它应该被选中。

我们将首先使用我们手工编码的表单进行这一过程，然后讨论如何使用 Qt Designer 文件解决同样的问题。

# 使用我们手工编码的表单

要开始，请将您的`calendar_form.py`文件从第二章 *使用 QtWidgets 构建表单*复制到一个名为`calendar_app.py`的新文件中，并在编辑器中打开它。我们将开始编辑我们的`MainWindow`类，并将其完善为一个完整的应用程序。

为了处理存储事件，我们将在`MainWindow`中创建一个`dict`属性，如下所示：

```py
class MainWindow(qtw.QWidget):

    events = {}
```

我们不打算将数据持久化到磁盘，尽管如果您愿意，您当然可以添加这样的功能。`dict`中的每个项目将使用`date`对象作为其键，并包含一个包含该日期上所有事件详细信息的`dict`对象列表。数据的布局将看起来像这样：

```py
    events = {
        QDate:  {
            'title': "String title of event",
            'category': "String category of event",
            'time': QTime() or None if "all day",
            'detail':  "String details of event"
        }
    }
```

接下来，让我们深入研究表单自动化。最简单的更改是在单击“全天”复选框时禁用时间输入，因为这种自动化只需要处理内置信号和插槽。

在`__init__()`方法中，我们将添加这段代码：

```py
        self.allday_check.toggled.connect(self.event_time.setDisabled)
```

`QCheckBox.toggled`信号在复选框切换开或关时发出，并发送一个布尔值，指示复选框是（更改后）未选中（`False`）还是选中（`True`）。这与`setDisabled`很好地连接在一起，它将在`True`时禁用小部件，在`False`时启用它。

# 创建和连接我们的回调方法

我们需要的其余自动化不适用于内置的 Qt 插槽，因此在连接更多信号之前，我们需要创建一些将用于实现插槽的方法。我们将把所有这些方法创建为`MainWindow`类的方法。

在开始处理回调之前，我们将创建一个实用方法来清除表单，这是几个回调方法将需要的。它看起来像这样：

```py
    def clear_form(self):
        self.event_title.clear()
        self.event_category.setCurrentIndex(0)
        self.event_time.setTime(qtc.QTime(8, 0))
        self.allday_check.setChecked(False)
        self.event_detail.setPlainText('')
```

基本上，这个方法会遍历我们表单中的字段，并将它们全部设置为默认值。不幸的是，这需要为每个小部件调用不同的方法，所以我们必须把它全部写出来。

现在让我们来看看回调方法。

# populate_list()方法

第一个实际的回调方法是`populate_list()`，它如下所示：

```py
    def populate_list(self):
        self.event_list.clear()
        self.clear_form()
        date = self.calendar.selectedDate()
        for event in self.events.get(date, []):
            time = (
                event['time'].toString('hh:mm')
                if event['time']
                else 'All Day'
            )
            self.event_list.addItem(f"{time}: {event['title']}")
```

这将在日历选择更改时调用，并且其工作是使用该天的事件重新填充`event_list`小部件。它首先清空列表和表单。然后，它使用其`selectedDate()`方法从日历小部件中检索所选日期。

然后，我们循环遍历所选日期的`self.events`字典的事件列表，构建一个包含时间和事件标题的字符串，并将其添加到`event_list`小部件中。请注意，我们的事件时间是一个`QTime`对象，因此要将其用作字符串，我们需要使用它的`toString()`方法进行转换。

有关如何将时间值格式化为字符串的详细信息，请参阅[`doc.qt.io/qt-5/qtime.html`](https://doc.qt.io/qt-5/qtime.html)中的`QTime`文档。

为了连接这个方法，在`__init__()`中，我们添加了这段代码：

```py
        self.calendar.selectionChanged.connect(self.populate_list)
```

`selectionChanged`信号在日历上选择新日期时发出。它不发送任何数据，因此我们的回调函数不需要任何数据。

# populate_form()方法

接下来的回调是`populate_form()`，当选择事件时将调用它并填充事件详细信息表单。它开始如下：

```py
    def populate_form(self):
        self.clear_form()
        date = self.calendar.selectedDate()
        event_number = self.event_list.currentRow()
        if event_number == -1:
            return
```

在这里，我们首先清空表单，然后从日历中检索所选日期，并从事件列表中检索所选事件。当没有选择事件时，`QListWidget.currentRow()`返回值为`-1`；在这种情况下，我们将只是返回，使表单保持空白。

方法的其余部分如下：

```py
        event_data = self.events.get(date)[event_number]

        self.event_category.setCurrentText(event_data['category'])
        if event_data['time'] is None:
            self.allday_check.setChecked(True)
        else:
            self.event_time.setTime(event_data['time'])
        self.event_title.setText(event_data['title'])
        self.event_detail.setPlainText(event_data['detail'])
```

由于列表小部件上显示的项目与`events`字典中存储的顺序相同，因此我们可以使用所选项目的行号来从所选日期的列表中检索事件。

一旦数据被检索，我们只需要将每个小部件设置为保存的值。

回到`__init__()`中，我们将连接槽如下：

```py
        self.event_list.itemSelectionChanged.connect(
            self.populate_form
        )
```

`QListWidget`在选择新项目时发出`itemSelectionChanged`。它不发送任何数据，因此我们的回调函数也不需要任何数据。

# save_event()方法

`save_event()`回调将在单击添加/更新按钮时调用。它开始如下：

```py
    def save_event(self):
        event = {
            'category': self.event_category.currentText(),
            'time': (
                None
                if self.allday_check.isChecked()
                else self.event_time.time()
                ),
            'title': self.event_title.text(),
            'detail': self.event_detail.toPlainText()
            }
```

在这段代码中，我们现在调用访问器方法来从小部件中检索值，并将它们分配给事件字典的适当键。

接下来，我们将检索所选日期的当前事件列表，并确定这是添加还是更新：

```py
        date = self.calendar.selectedDate()
        event_list = self.events.get(date, [])
        event_number = self.event_list.currentRow()

        if event_number == -1:
            event_list.append(event)
        else:
            event_list[event_number] = event
```

请记住，如果没有选择项目，`QListWidget.currentRow()`会返回`-1`。在这种情况下，我们希望将新事件追加到列表中。否则，我们将所选事件替换为我们的新事件字典：

```py
        event_list.sort(key=lambda x: x['time'] or qtc.QTime(0, 0))
        self.events[date] = event_list
        self.populate_list()
```

为了完成这个方法，我们将使用时间值对列表进行排序。请记住，我们对全天事件使用`None`，因此它们将首先通过在排序中用`QTime`的 0:00 替换它们来进行排序。

排序后，我们用新排序的列表替换当前日期的事件列表，并用新列表重新填充`QListWidget`。

我们将通过在`__init__()`中添加以下代码来连接`add_button`小部件的`clicked`事件：

```py
        self.add_button.clicked.connect(self.save_event)
```

# delete_event()方法

`delete_event`方法将在单击删除按钮时调用，它如下所示：

```py
    def delete_event(self):
        date = self.calendar.selectedDate()
        row = self.event_list.currentRow()
        del(self.events[date][row])
        self.event_list.setCurrentRow(-1)
        self.clear_form()
        self.populate_list()
```

再次，我们检索当前日期和当前选择的行，并使用它们来定位我们想要删除的`self.events`中的事件。在从列表中删除项目后，我们通过将`currentRow`设置为`-1`来将列表小部件设置为无选择。然后，我们清空表单并填充列表小部件。

请注意，我们不需要检查当前选择的行是否为`-1`，因为我们计划在没有选择行时禁用删除按钮。

这个回调很容易连接到`__init__()`中的`del_button`：

```py
        self.del_button.clicked.connect(self.delete_event)
```

# 检查`_delete _btn()`方法

我们的最后一个回调是最简单的，它看起来像这样：

```py
    def check_delete_btn(self):
        self.del_button.setDisabled(
            self.event_list.currentRow() == -1)
```

这个方法只是检查当前事件列表小部件中是否没有事件被选中，并相应地启用或禁用删除按钮。

回到`__init__()`，让我们连接到这个回调：

```py
        self.event_list.itemSelectionChanged.connect(
            self.check_delete_btn)
        self.check_delete_btn()
```

我们将这个回调连接到`itemSelectionChanged`信号。请注意，我们已经将该信号连接到另一个插槽。信号可以连接到任意数量的插槽而不会出现问题。我们还直接调用该方法，以便`del_button`一开始就被禁用。

# 构建我们的新类别弹出表单

我们应用程序中的最后一个功能是能够向组合框添加新类别。我们需要实现的基本工作流程是：

1.  当用户更改事件类别时，检查他们是否选择了“新…”

1.  如果是这样，打开一个新窗口中的表单，让他们输入一个类别

1.  当表单提交时，发出新类别的名称

1.  当发出该信号时，向组合框添加一个新类别并选择它

1.  如果用户选择不输入新类别，则将组合框默认为“选择类别…”

让我们从实现我们的弹出表单开始。这将与我们在本章前面讨论过的表单示例一样，它看起来像这样：

```py
class CategoryWindow(qtw.QWidget):

    submitted = qtc.pyqtSignal(str)

    def __init__(self):
        super().__init__(None, modal=True)
        self.setLayout(qtw.QVBoxLayout())
        self.layout().addWidget(
            qtw.QLabel('Please enter a new catgory name:'))
        self.category_entry = qtw.QLineEdit()
        self.layout().addWidget(self.category_entry)
        self.submit_btn = qtw.QPushButton(
            'Submit',
            clicked=self.onSubmit)
        self.layout().addWidget(self.submit_btn)
        self.cancel_btn = qtw.QPushButton(
            'Cancel',
            clicked=self.close
            )
        self.layout().addWidget(self.cancel_btn)
        self.show()

    @qtc.pyqtSlot()
    def onSubmit(self):
        if self.category_entry.text():
            self.submitted.emit(self.category_entry.text())
        self.close()
```

这个类与我们的`FormWindow`类相同，只是增加了一个标签和一个取消按钮。当点击`cancel_btn`小部件时，将调用窗口的`close()`方法，导致窗口关闭而不发出任何信号。

回到`MainWindow`，让我们实现一个方法，向组合框添加一个新类别：

```py
    def add_category(self, category):
        self.event_category.addItem(category)
        self.event_category.setCurrentText(category)
```

这种方法非常简单；它只是接收一个类别文本，将其添加到组合框的末尾，并将组合框选择设置为新类别。

现在我们需要编写一个方法，每当选择“新…”时，它将创建我们弹出表单的一个实例：

```py
    def on_category_change(self, text):
        if text == 'New…':
            dialog = CategoryWindow()
            dialog.submitted.connect(self.add_category)
            self.event_category.setCurrentIndex(0)
```

这种方法接受已更改类别的`text`值，并检查它是否为“新…”。如果是，我们创建我们的`CategoryWindow`对象，并将其`submitted`信号连接到我们的`add_category()`方法。然后，我们将当前索引设置为`0`，这是我们的“选择类别…”选项。

现在，当`CategoryWindow`显示时，用户要么点击取消，窗口将关闭并且组合框将被设置为“选择类别…”，就像`on_category_change()`留下的那样，要么用户将输入一个类别并点击提交，这样`CategoryWindow`将发出一个带有新类别的`submitted`信号。`add_category()`方法将接收到新类别，将其添加，并将组合框设置为它。

我们的日历应用现在已经完成；启动它并试试吧！

# 使用 Qt Designer .ui 文件

现在让我们回过头来使用我们在第二章中创建的 Qt Designer 文件，*使用 QtWidgets 构建表单*。这将需要一种完全不同的方法，但最终产品将是一样的。

要完成本节的工作，您需要第二章中的`calendar_form.ui`文件，*使用 QtWidgets 构建表单*，以及第二个`.ui`文件用于类别窗口。您可以自己练习构建这个表单，也可以使用本章示例代码中包含的表单。如果选择自己构建，请确保将每个对象命名为我们在上一节的代码中所做的那样。

# 在 Qt Designer 中连接插槽

Qt Designer 对于连接信号和插槽到我们的 GUI 的能力有限。对于 Python 开发人员，它主要只能用于在同一窗口中的小部件之间连接内置的 Qt 信号到内置的 Qt 插槽。连接信号到 Python 可调用对象或自定义的 PyQt 信号实际上是不可能的。

在日历 GUI 中，我们确实有一个原生的 Qt 信号-槽连接示例——`allday_check`小部件连接到`event_time`小部件。让我们看看如何在 Qt Designer 中连接这些：

1.  在 Qt Designer 中打开`calendar_form.ui`文件

1.  在屏幕右下角找到 Signal/Slot Editor 面板

1.  点击+图标添加一个新的连接

1.  在 Sender 下，打开弹出菜单，选择`allday_check`

1.  在 Signal 下，选择 toggled(bool)

1.  对于 Receiver，选择`event_time`

1.  最后，对于 Slot，选择 setDisabled(bool)

生成的条目应该是这样的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/f8145b67-f651-4977-9b7f-6e0c23b01bf5.png)

如果你正在构建自己的`category_window.ui`文件，请确保你还将取消按钮的`clicked`信号连接到类别窗口的`closed`槽。

# 将.ui 文件转换为 Python

如果你在文本编辑器中打开你的`calendar_form.ui`文件，你会看到它既不是 Python 也不是 C++，而是你设计的 GUI 的 XML 表示。PyQt 为我们提供了几种选择，可以在 Python 应用程序中使用`.ui`文件。

第一种方法是使用 PyQt 附带的`pyuic5`工具将 XML 转换为 Python。在存放`.ui`文件的目录中打开命令行窗口，运行以下命令：

```py
$ pyuic5 calendar_form.ui
```

这将生成一个名为`calendar_form.py`的文件。如果你在代码编辑器中打开这个文件，你会看到它包含一个`Ui_MainWindow`类的单个类定义，如下所示：

```py
class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(799, 600)
        # ... etc
```

注意这个类既不是`QWidget`的子类，也不是`QObject`的子类。这个类本身不会显示我们构建的窗口。相反，这个类将在另一个小部件内部构建我们设计的 GUI，我们必须用代码创建它。

为了做到这一点，我们将这个类导入到另一个脚本中，创建一个`QWidget`作为容器，并将`setupUi()`方法与我们的小部件容器作为参数一起调用。

不要试图编辑或添加代码到生成的 Python 文件中。如果你想使用 Qt Designer 更新你的 GUI，当你生成新文件时，你会丢失所有的编辑。把生成的代码当作第三方库来对待。

首先，从第一章，*PyQt 入门*中复制 PyQt 应用程序模板到存放`calendar_form.py`的目录，并将其命名为`calendar_app.py`。

在文件顶部像这样导入`Ui_MainWindow`类：

```py
from calendar_form import Ui_MainWindow
```

我们可以以几种方式使用这个类，但最干净的方法是通过将它作为`MainWindow`的第二个父类进行**多重继承**。

更新`MainWindow`类定义如下：

```py
class MainWindow(qtw.QWidget, Ui_MainWindow):
```

注意我们窗口的基类（第一个父类）仍然是`QWidget`。这个基类需要与我们最初设计表单时选择的基类匹配（参见第二章，*使用 QtWidgets 构建表单*）。

现在，在构造函数内部，我们可以调用`setupUi`，像这样：

```py
    def __init__(self):
        super().__init__()
        self.setupUi(self)
```

如果你在这一点运行应用程序，你会看到日历 GUI 都在那里，包括我们在`allday_check`和`event_time`之间的连接。然后，你可以将其余的连接和修改添加到`MainWindow`构造函数中，如下所示：

```py
        # disable the first category item
        self.event_category.model().item(0).setEnabled(False)
        # Populate the event list when the calendar is clicked
        self.calendar.selectionChanged.connect(self.populate_list)
        # Populate the event form when an item is selected
        self.event_list.itemSelectionChanged.connect(
            self.populate_form)
        # Save event when save is hit
        self.add_button.clicked.connect(self.save_event)
        # connect delete button
        self.del_button.clicked.connect(self.delete_event)
        # Enable 'delete' only when an event is selected
        self.event_list.itemSelectionChanged.connect(
            self.check_delete_btn)
        self.check_delete_btn()
        # check for selection of "new…" for category
        self.event_category.currentTextChanged.connect(
            self.on_category_change)
```

这个类的回调方法与我们在代码中定义的方法是相同的。继续把它们复制到`MainWindow`类中。

使用`pyuic5`创建的`Ui_`类的另一种方法是将其实例化为容器小部件的属性。我们将尝试在类别窗口中使用这个方法；在文件顶部添加这个类：

```py
class CategoryWindow(qtw.QWidget):

    submitted = qtc.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.ui = Ui_CategoryWindow()
        self.ui.setupUi(self)
        self.show()
```

在将`Ui_CategoryWindow`对象创建为`CategoryWindow`的属性之后，我们调用它的`setupUi()`方法来在`CategoryWindow`上构建 GUI。然而，我们所有对小部件的引用现在都在`self.ui`命名空间下。因此，例如，`category_entry`不是`self.category_entry`，而是`self.ui.category_entry`。虽然这种方法稍微冗长，但如果你正在构建一个特别复杂的类，它可能有助于避免名称冲突。

# 自动信号和插槽连接

再次查看由`pyuic5`生成的`Ui_`类，并注意`setupUi`中的最后一行代码：

```py
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
```

`connectSlotsByName()`是一种方法，它将通过将信号与以`on_object_name_signal()`格式命名的方法进行匹配来自动连接信号和插槽，其中`object_name`与`PyQt`对象的`objectName`属性匹配，`signal`是其内置信号之一的名称。

例如，在我们的`CategoryWindow`中，我们希望创建一个回调，当单击`submit_btn`时运行（如果您制作了自己的`.ui`文件，请确保您将提交按钮命名为`submit_btn`）。如果我们将回调命名为`on_submit_btn_clicked()`，那么这将自动发生。

代码如下：

```py
    @qtc.pyqtSlot()
    def on_submit_btn_clicked(self):
        if self.ui.category_entry.text():
            self.submitted.emit(self.ui.category_entry.text())
        self.close()
```

如果我们使名称匹配，我们就不必在任何地方显式调用`connect()`；回调将自动连接。

您也可以在手工编码的 GUI 中使用`connectSlotsByName()`；您只需要显式设置每个小部件的`objectName`属性，以便该方法有东西与名称匹配。仅仅变量名是行不通的。

# 在不进行转换的情况下使用.ui 文件

如果您不介意在运行时进行一些转换开销，实际上可以通过使用 PyQt 的`uic`库（`pyuic5`基于此库）在程序内部动态转换您的`.ui`文件，从而避免手动转换这一步。

让我们尝试使用我们的`MainWindow` GUI。首先将您对`Ui_MainWindow`的导入注释掉，并导入`uic`，如下所示：

```py
#from calendar_form import Ui_MainWindow
from PyQt5 import uic
```

然后，在您的`MainWindow`类定义之前，调用`uic.loadUiType()`，如下所示：

```py
MW_Ui, MW_Base = uic.loadUiType('calendar_form.ui')
```

`loadUiType()`接受一个`.ui`文件的路径，并返回一个包含生成的 UI 类和其基于的 Qt 基类（在本例中为`QWidget`）的元组。

然后，我们可以将这些用作我们的`MainWindow`类的父类，如下所示：

```py
class MainWindow(MW_Base, MW_Ui):
```

这种方法的缺点是额外的转换时间，但带来了更简单的构建和更少的文件维护。这是在早期开发阶段采取的一个很好的方法，当时您可能经常在 GUI 设计上进行迭代。

# 摘要

在本章中，您学习了 Qt 的对象间通信功能，即信号和插槽。您学会了如何使用它们来自动化表单行为，将功能连接到用户事件，并在应用程序的不同窗口之间进行通信。

在下一章中，我们将学习`QMainWindow`，这是一个简化常见应用程序组件构建的类。您将学会如何快速创建菜单、工具栏和对话框，以及如何保存设置。

# 问题

尝试这些问题来测试您对本章的了解：

1.  查看下表，并确定哪些连接实际上可以进行，哪些会导致错误。您可能需要在文档中查找这些信号和插槽的签名：

| # | 信号 | 插槽 |
| --- | --- | --- |
| 1 | `QPushButton.clicked` | `QLineEdit.clear` |
| 2 | `QComboBox.currentIndexChanged` | `QListWidget.scrollToItem` |
| 3 | `QLineEdit.returnPressed` | `QCalendarWidget.setGridVisible` |
| 4 | `QLineEdit.textChanged` | `QTextEdit.scrollToAnchor` |

1.  在信号对象上，`emit()`方法在信号被绑定（即连接到插槽）之前是不存在的。重写我们第一个`calendar_app.py`文件中的`CategoryWindow.onSubmit()`方法，以防`submitted`未绑定的可能性。

1.  您在 Qt 文档中找到一个对象，该对象的插槽需要`QString`作为参数。您能连接发送 Python 的`str`的自定义信号吗？

1.  您在 Qt 文档中找到一个对象，该对象的插槽需要`QVariant`作为参数。您可以将哪些内置的 Python 类型发送到这个插槽？

1.  您正在尝试创建一个对话框窗口，该窗口需要时间，并在用户完成编辑值时发出。您正在尝试使用自动插槽连接，但您的代码没有做任何事情。确定缺少了什么：

```py
    class TimeForm(qtw.QWidget):

        submitted = qtc.pyqtSignal(qtc.QTime)

        def __init__(self):
        super().__init__()
        self.setLayout(qtw.QHBoxLayout())
        self.time_inp = qtw.QTimeEdit(self)
        self.layout().addWidget(self.time_inp)

        def on_time_inp_editingFinished(self):
        self.submitted.emit(self.time_inp.time())
        self.destroy()
```

1.  你在 Qt Designer 中为一个计算器应用程序创建了一个`.ui`文件，现在你试图让它在代码中工作，但是它不起作用。在下面的源代码中你做错了什么？

```py
    from calculator_form import Ui_Calculator

    class Calculator(qtw.QWidget):
        def __init__(self):
            self.ui = Ui_Calculator(self)
            self.ui.setupGUI(self.ui)
            self.show()
```

1.  你正在尝试创建一个新的按钮类，当点击时会发出一个整数值；不幸的是，当你点击按钮时什么也不会发生。看看下面的代码，试着让它工作起来：

```py
    class IntegerValueButton(qtw.QPushButton):

        clicked = qtc.pyqtSignal(int)

        def __init__(self, value, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.value = value
            self.clicked.connect(
                lambda: self.clicked.emit(self.value))
```

# 进一步阅读

查看以下资源以获取更多信息：

+   PyQt 关于信号和槽支持的文档可以在这里找到：[`pyqt.sourceforge.net/Docs/PyQt5/signals_slots.html`](http://pyqt.sourceforge.net/Docs/PyQt5/signals_slots.html)

+   PyQt 关于使用 Qt Designer 的文档可以在这里找到：[`pyqt.sourceforge.net/Docs/PyQt5/designer.html`](http://pyqt.sourceforge.net/Docs/PyQt5/designer.html)
