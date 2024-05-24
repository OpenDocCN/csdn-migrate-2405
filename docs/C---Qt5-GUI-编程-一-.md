# C++ Qt5 GUI 编程（一）

> 原文：[`annas-archive.org/md5/63069ff6b9b588d5c75e8d5b8dbfb5ed`](https://annas-archive.org/md5/63069ff6b9b588d5c75e8d5b8dbfb5ed)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Qt 5 是 Qt 的最新版本，它使您能够为多个目标开发具有复杂用户界面的应用程序。它为您提供了更快速、更智能的方式来创建现代 UI 和多平台应用程序。本书将教您如何设计和构建功能齐全、吸引人和用户友好的图形用户界面。

通过本书，您将成功学习高端 GUI 应用程序，并能够构建更多功能强大的跨平台应用程序。

# 本书适合对象

本书适合希望构建基于 GUI 的应用程序的开发人员和程序员。需要基本的 C++知识，了解 Qt 的基础知识会有所帮助。

# 充分利用本书

为了成功执行本书中的所有代码和指令，您需要以下内容：

+   基本的 PC/笔记本电脑

+   工作的互联网连接

+   Qt 5.10

+   MariaDB 10.2（或 MySQL Connector）

+   Filezilla Server 0.9

我们将在每一章中处理安装过程和详细信息。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中为本书下载示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，文件将直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/Windows 7-Zip

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-GUI-Programming-with-CPP-and-Qt5`](https://github.com/PacktPublishing/Hands-On-GUI-Programming-with-CPP-and-Qt5)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在此处下载：[`www.packtpub.com/sites/default/files/downloads/HandsOnGUIProgrammingwithCPPandQt5_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/HandsOnGUIProgrammingwithCPPandQt5_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。这是一个例子：“我们在`MainWindow`构造函数中调用`test()`函数。”

代码块设置如下：

```cpp
void MainWindow::test() 
{ 
   int amount = 100; 
   amount -= 10; 
   qDebug() << "You have obtained" << amount << "apples!"; 
} 
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目以粗体设置：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 
   test(); 
} 
```

任何命令行输入或输出都以以下方式编写：

```cpp
********* Start testing of MainWindow ********* 
Config: Using QtTest library 5.9.1, Qt 5.9.1 (i386-little_endian-ilp32 shared (dynamic) debug build; by GCC 5.3.0) 
PASS   : MainWindow::initTestCase() 
PASS   : MainWindow::_q_showIfNotHidden() 
PASS   : MainWindow::testString() 
PASS   : MainWindow::testGui() 
PASS   : MainWindow::cleanupTestCase() 
Totals: 5 passed, 0 failed, 0 skipped, 0 blacklisted, 880ms 
********* Finished testing of MainWindow ********* 
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这样的方式出现在文本中。这是一个例子：“第三个选项是切换书签，它允许您为自己设置书签。”

警告或重要说明会以这种方式出现。

提示和技巧会以这种方式出现。


# 第一章：介绍 Qt

Qt（发音为可爱）自从首次发布以来，已经被软件工程师和开发人员使用了二十多年，用于创建跨平台应用程序。经过多次所有权变更和大量的重大代码改进，Qt 变得更加功能丰富，支持的平台也比以前更多。Qt 不仅在桌面应用程序开发方面表现出色，而且在移动和嵌入式系统开发方面也非常出色。

在本章中，我们将涵盖以下主题：

+   什么是 Qt？

+   为什么使用 Qt？

+   在 Qt 中使用工具

+   下载和安装 Qt

+   建立工作环境

+   运行我们的第一个`Hello World`Qt 程序

在本章中，我们将更多地了解 Qt 的历史。然后，我们将继续使用 Qt 的最新版本构建我们的第一个示例程序，该版本是 Qt 5 版。为了方便我们的读者，我们将在整本书中简称为 Qt。

# 什么是 Qt？

目前，Qt 的最新版本（本书撰写时）是版本 5.10。这个版本包含了许多新功能以及成千上万的错误修复，使 Qt 成为软件开发人员和系统工程师的强大稳定的开发工具包。Qt 有一个庞大的 SDK（软件开发工具包），包含了各种工具和库，帮助开发人员完成工作，而不用太担心特定平台的技术问题。Qt 在幕后处理所有混乱的集成和兼容性问题，这样你就不必处理它们。这不仅提高了效率，还降低了开发成本，特别是当您尝试开发迎合更广泛用户群的跨平台应用程序时。

Qt 有两种许可证：

+   第一种是开源许可证，免费，但只有在您的项目/产品符合其条款和条件时才免费。例如，如果您对 Qt 的源代码进行了任何更改，您有义务将这些更改提交给 Qt 开发人员。不这样做可能会导致严重的法律问题，因此您可能希望选择第二个选项。

+   第二种许可证是商业许可证，它给予您对专有 Qt 源代码修改的全部权利，并保持您的应用程序私有。但当然，这些特权是需要付费的。

如果你刚开始学习 Qt，不要被这些术语吓倒，因为你肯定不会修改 Qt 库的源代码，也不会重新编译它，至少现在不会。

有关 Qt 许可的更多信息，请访问[`www.qt.io/licensing-comparison.`](https://www.qt.io/licensing-comparison)

# 为什么使用 Qt？

不难看出为什么 Qt 有机会在市场上击败所有其他现有的 SDK；首先是跨平台兼容性。几乎找不到其他开发工具包支持这么多平台而不需要为每个平台编写不同的代码。通过消除这些额外的步骤，程序员可以专注于开发他们的应用程序，而不需要担心每个平台特定功能的实现。此外，您的代码将看起来干净，没有所有的`#ifdef`宏和需要为不同平台加载不同的依赖项。

Qt 通常使用 C++，这是一种生成小型高效代码的编译语言。它也有很好的文档，并遵循一套非常一致的命名约定，这减少了开发人员的学习曲线。

请注意，Qt 确实包含一小部分仅适用于特定平台的功能。但是，这些功能很少，通常用于特殊用例，例如仅在移动平台上工作的 Qt 传感器，仅在桌面上工作的 Qt Web Engine，仅适用于 Android 和 Linux 的 Qt NFC 等。这些都是一些非常特定的功能，只存在于支持它们的特定平台上。除此之外，通常所有平台都支持常见功能。

# Qt Designer

Qt Designer 通常由开发人员用于设计桌面应用程序的 GUI，而 Qt Quick Designer 通常用于移动和嵌入式平台。话虽如此，两种格式在桌面和移动格式上都可以正常运行，唯一的区别是外观和所使用的语言类型。

Qt Designer 保存的 GUI 文件具有`.ui`扩展名，保存为 XML 格式。该文件存储了 GUI 设计人员放置的每个小部件的属性，例如位置、大小、边距、工具提示、布局方向等。它还在文件内部保存了信号和槽事件名称，以便在后期轻松连接代码。该格式不支持编码，仅适用于 Qt C++项目，即基于小部件的应用程序项目。

# Qt Quick Designer

另一方面，Qt Quick Designer 以`.ui.qml`和`.qml`格式保存 GUI 文件。从技术概念和开发方法来看，Qt Quick 是一种非常不同的 GUI 系统，我们将在第十四章《Qt Quick 和 QML》中进行介绍。Qt Quick Designer 保存其数据的格式不是 XML，而是一种类似 JavaScript 的声明性语言称为**QML**。QML 不仅允许设计人员以类似于 CSS（层叠样式表）的方式自定义他们的 GUI，还允许程序员在 QML 文件中编写功能性 JavaScript。正如我们之前提到的，`.ui.qml`是仅用于视觉装饰的文件格式，而`.qml`包含应用程序逻辑。

如果您正在使用 Qt Quick 编写简单的程序，您根本不需要接触任何 C++编码。这对 Web 开发人员来说尤其受欢迎，因为他们可以立即开始使用 Qt Quick 开发自己的应用程序，无需经历陡峭的学习曲线；一切对他们来说都是如此熟悉。对于更复杂的软件，您甚至可以在 QML 中链接 C++函数，反之亦然。同样，如果您对 Qt Quick 和 QML 想了解更多信息，请转到第十四章《QtQuick 和 QML》。

由于 Qt Creator 本身也是用 Qt 库编写的，因此它也是完全跨平台的。因此，您可以在不同的开发环境中使用相同的一组工具，并为您的团队开发统一的工作流程，从而提高效率和节约成本。

除此之外，Qt 还配备了许多不同的模块和插件，涵盖了您项目所需的各种功能。通常情况下，您无需寻找其他外部库或依赖项并尝试自行实现它们。Qt 的抽象层使后端实现对用户不可见，并导致统一的编码风格和语法。如果您尝试自行组合一堆外部依赖项，您会发现每个库都有其独特的编码风格。在同一项目中混合所有不同的编码风格会非常混乱，除非您制作自己的抽象层，这是一项非常耗时的任务。由于 Qt 已经包含了大多数（如果不是全部）您需要创建功能丰富的应用程序的模块，因此您无需自行实现。

有关 Qt 附带的模块的更多信息，请访问：[`doc.qt.io/qt-5/qtmodules.html`](http://doc.qt.io/qt-5/qtmodules.html)。

也就是说，还有许多第三方库可以扩展 Qt，以实现 Qt 本身不支持的功能，例如专注于游戏开发或为特定用户群设计的其他功能的库。

# 下载和安装 Qt

不浪费任何时间，让我们开始安装吧！要获取开源 Qt 的免费安装程序，首先转到他们的网站[`www.qt.io`](https://www.qt.io)。在那里，寻找一个名为 Download Qt 的按钮（如果他们已经更新了网站，网站可能看起来不同）。请注意，您可能正在下载商业 Qt 的免费试用版，在 30 天后将无法使用。确保您下载的是开源版本的 Qt。此外，您可能需要为您的平台选择正确的安装程序，因为 Qt 有许多不同的安装程序，适用于不同的操作系统 Windows、macOS 和 Linux。

您可能会想知道为什么安装程序的大小如此之小-只有大约 19 MB。这是因为统一的在线安装程序实际上不包含任何 Qt 软件包，而是一个下载客户端，它可以帮助您下载所有相关文件，并在下载完成后将它们安装到您的计算机上。一旦您下载了在线安装程序，请双击它，您将看到一个类似于这样的界面（以下示例在 Windows 系统上运行）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/2887b5c2-45ea-457d-94bf-1dcd96367148.png)

单击“下一步”按钮，将出现一个 DRM（数字版权管理）页面，并要求您使用 Qt 帐户登录。如果您没有帐户，您也可以在同一页面上创建您的帐户：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/8da1ff97-e940-4f55-9e78-b9c1c17dfcce.png)

一旦您登录，您将看到一条消息，上面写着您的 Qt 帐户在此主机平台上没有有效的商业许可证。不用担心，只需单击“下一步”按钮即可继续。

接下来，您将被要求指定安装路径。默认路径通常就可以了，但您可以根据需要将其更改为任何其他路径。此外，您可以选择保留与 Qt Creator 关联这些常见文件类型的选项，或者如果不需要，也可以手动取消选中。

之后，您将看到一系列复选框，您可以使用这些复选框选择要安装到计算机上的 Qt 版本。通常，对于新用户，默认选项就足够了。如果您不需要某些选项，例如对 Android 上的 Qt 的支持，您可以在此处取消选择它们，以减小下载的大小。如果需要，您随时可以使用维护工具返回并添加或删除 Qt 组件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/02db9bda-c373-4b0e-957c-9dc316133d55.png)

接下来，您将看到许可协议。勾选第一个选项，即我已阅读并同意许可协议中包含的条款，然后单击“下一步”按钮。确保您确实阅读了许可协议中规定的条款和条件！

最后，安装程序将要求您输入一个名称，以创建 Qt 的开始菜单快捷方式。完成后，只需单击“下一步”，然后单击“安装”。下载过程将根据您的互联网速度花费几分钟到几个小时不等。一旦所有文件都已下载，安装程序将自动继续将文件安装到您刚刚在之前的步骤中设置的安装路径。

# 设置工作环境

既然您已经安装了最新版本的 Qt，让我们启动 Qt Creator，并开始通过创建我们的第一个项目来进行实验！您应该能够在桌面上或开始菜单的某个位置找到 Qt Creator 的快捷方式图标。

让我们看看设置环境的步骤：

1.  当您首次启动 Qt Creator 时，您应该会看到以下界面：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/78301c1b-8a25-4575-a4ea-b46880946909.png)

1.  在开始创建第一个项目之前，您可能需要调整一些设置。转到顶部菜单，选择“工具”|“选项”。屏幕上将弹出一个类似于此的窗口：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/6a5dc3a3-954d-439e-8d96-c396f90317b6.png)

1.  窗口左侧有许多不同的类别可供选择。每个类别代表一组选项，您可以设置以自定义 Qt Creator 的外观和操作方式。您可能不想触碰设置，但最好先了解它们。您可能想要更改的第一个设置之一是语言选项，该选项位于环境类别中。Qt Creator 为我们提供了在不同语言之间切换的选项。虽然它不支持所有语言，但大多数流行的语言都可用，例如英语、法语、德语、日语、中文、俄语等。选择所需的语言后，单击应用并重新启动 Qt Creator。您必须重新启动 Qt Creator 才能看到更改。

1.  您可能需要的下一个设置是缩进设置。默认情况下，Qt 使用空格缩进，每当您在键盘上按“Tab”键时，将向您的脚本添加四个空格。像我这样的一些人更喜欢制表符缩进。您可以在 C++类别中更改缩进设置。

请注意，如果您要为 Qt 项目的源代码做出贡献，则需要使用空格缩进，而不是制表符，这是 Qt 项目的编码标准和样式。

1.  在 C++类别下，您可以找到一个名为“复制”的按钮，位于右上方的“编辑”按钮旁边。单击它，将弹出一个新窗口。

1.  输入您自己的代码样式名称，因为您无法编辑默认的内置编码样式。创建自己的设置后，单击“编辑”按钮。现在您可以在“常规”选项卡下看到实际的“制表符和缩进”设置：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/86b23382-3d24-4f3a-8b10-e8642f5a3a21.png)

1.  请注意，即使在“文本编辑器”类别中有一个名为“制表符和缩进”的设置，我认为这是一个旧设置，在 Qt Creator 中已不再起作用。界面上还有一条注释，写着代码缩进是在 C++和 Qt Quick 设置中配置的。这可能的原因是，由于 Qt Creator 现在同时支持 C++项目和 QML 项目，Qt 开发人员可能觉得有必要将设置分开，因此旧设置不再有效。我相当肯定，文本编辑器中的这一部分将在不久的将来被弃用。

1.  接下来，在“构建和运行”类别下，您将看到一个名为“工具包”的选项卡。

1.  这是您可以为每个平台设置编译设置的地方。从下一个截图中可以看出，我的 Qt 不支持在 MSVC（Microsoft Visual Studio Compiler）下进行桌面构建，因为我从未在计算机上安装 Visual Studio。相反，我的 Qt 只支持在 MinGW（Minimal GNU for Windows）编译器下进行桌面构建。从此窗口，您可以检查并查看您的 Qt 是否支持您项目所需的平台和编译器，并在必要时进行更改。但是现在，我们将保持不变。要了解有关*工具包*是什么以及如何配置构建设置的更多信息，请转到第十五章，*跨平台开发*： 

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/96a3210e-7871-4d1e-bbe1-f31ed021db05.png)

1.  最后，我们可以将我们的项目链接到版本控制类别中的版本控制服务器。

1.  版本控制允许您或您的团队将代码更改提交到集中系统，以便每个团队成员都可以获取相同的代码，而无需手动传递文件。当您在一个大团队中工作时，手动跟踪代码更改非常困难，甚至更难合并不同程序员完成的代码。版本控制系统旨在解决这些问题。Qt 支持不同类型的版本控制系统，如 Git、SVN、Mercurial、Perforce 等。尽管这是一个非常有用的功能，特别是在团队中工作时，但我们现在不需要为其进行配置：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/8faf6c93-fcab-4c20-b1e6-b9c70cba4b3e.png)

# 运行我们的第一个 Hello World Qt 程序

Hello World 程序是一个非常简单的程序，它只是显示一个输出，上面写着`Hello, World!`（或者其他内容，不一定是这个），以显示 SDK 正常工作。我们不需要编写很长的代码来生成`Hello World`程序，我们可以只使用最少和最基本的代码来完成。实际上，在 Qt 中我们不需要编写任何代码，因为它会在您第一次创建项目时生成代码！

让我们按照以下步骤开始我们的项目：

1.  要在 Qt 中创建新项目，请单击 Qt Creator 欢迎屏幕上的“新项目”按钮。或者，您也可以转到顶部菜单，选择“文件”|“新文件或项目”。

1.  之后，您将看到一个窗口，让您为项目或文件选择模板。在这个演示中，我们将选择 Qt Widgets Application：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/61467706-8fad-4cfb-be1b-a27dce3aae57.png)

1.  之后，设置您的项目名称和项目目录。您还可以勾选“用作默认项目位置”，这样下次在 Qt 中创建新项目时就可以自动获得相同的路径。

1.  接下来，Qt Creator 将要求您为项目选择一个或多个工具包。在这个演示中，我们将选择使用 MinGW 编译器的桌面 Qt。不用担心，因为您可以在开发过程中随时添加或删除项目中的工具包：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/f117e1ba-50ee-481b-ab1b-52bdb4a9f7d1.png)

1.  之后，您将看到一个页面，上面写着“类信息”。这基本上是您为基本窗口设置类名的地方，但我们不打算更改任何内容，所以只需点击“下一步”按钮继续：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/4955e578-162a-477d-9739-1e799f4c42bd.png)

1.  最后，它会要求您将项目链接到您的版本控制服务器。如果您以前没有在 Qt 中添加过任何内容，可以单击“Configure”按钮，它将带您进入我在本章前一节中向您展示的设置对话框。

1.  但是，在这个演示中，我们将保持设置为<None>并按下“Finish”按钮。然后，Qt Creator 将继续生成项目所需的文件。一两秒后，Qt Creator 将自动切换到编辑模式，您应该能够在项目面板下看到它为您创建的文件。您可以通过在 Qt Creator 中双击它们来打开任何文件，并且它们将显示在右侧的编辑器中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/cb27c62e-5ab5-4690-b775-70a353b84b85.png)

1.  在开始编译项目之前，让我们在项目面板的`Forms`目录下打开`mainwindow.ui`文件。不要太担心用户界面，因为我们将在下一章中介绍它。我们需要做的是在右侧窗口的中心点击并拖动“Display Widgets”类别下的“Label”图标，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/60c3a7ec-dbe6-4832-a1b5-0b36788c4e76.png)

1.  之后，双击`Text Label`小部件并将文本更改为`Hello World!`。完成后，按下键盘上的*Enter*按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/6d7f068a-eca4-4c99-9253-8f31e8ccfed0.png)

1.  最后一步是按下位于左下角的运行按钮，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/a071be71-b7fd-4cf3-92b0-ee7e0fd16d28.png)

1.  通常情况下，我们会先构建程序，然后运行程序，但是 Qt Creator 足够聪明，可以自行构建它。然而，构建和运行应用程序分开仍然是一个好习惯。经过几秒钟的编译，...哇！你已经使用 Qt 创建了你的第一个`Hello World`程序！

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/6823e337-e451-4170-898a-cd7ef9504c04.png)

# 摘要

诸如 Qt Creator 之类的工具的存在使得为开发人员设计应用程序的用户界面成为一项简单而有趣的工作。我们不再需要编写大量的代码来创建单个按钮，或者更改一大堆代码来调整文本标签的位置，因为当我们设计我们的 GUI 时，Qt Designer 会为我们生成那些代码。Qt 已经将所见即所得的哲学应用到了工作流程中，并为我们提供了完成工作所需的所有便利和效率。

在下一章中，我们将学习 Qt Creator 的方方面面，并开始使用 Qt 设计我们的第一个 GUI！


# 第二章：Qt 小部件和样式表

使用 Qt 进行软件开发的一个优势是，使用 Qt 提供的工具非常容易设计程序的**图形用户界面**（**GUI**）。在本书中，我们将尝试创建一个涉及 Qt 许多不同组件和模块的单一项目。我们将在每一章中逐步介绍项目的每个部分，这样您最终将能够掌握整个 Qt 框架，并同时完成演示项目，这对于您的作品集来说是一个非常有价值的项目。您可以在[`github.com/PacktPublishing/Hands-On-GUI-Programming-with-C-QT5`](https://github.com/PacktPublishing/Hands-On-GUI-Programming-with-C-QT5)找到所有源代码。

在本章中，我们将涵盖以下主题：

+   Qt Designer 简介

+   基本 Qt 小部件

+   Qt 样式表

在本章中，我们将深入探讨 Qt 在设计时如何为我们提供优雅的 GUI。在本章开头，您将了解 Qt 提供的小部件类型及其功能。之后，我们将逐步进行一系列步骤，并使用 Qt 设计我们的第一个表单应用程序。

# Qt Designer 简介

Qt 中有两种类型的 GUI 应用程序，即 Qt Quick 应用程序和 Qt Widgets 应用程序。在本书中，我们将主要涵盖后者，因为这是为桌面应用程序设计 GUI 的标准方式，而 Qt Quick 更广泛地用于移动和嵌入式系统：

1.  我们需要做的第一件事是打开 Qt Creator 并创建一个新项目。您可以通过转到“文件”|“新文件或项目”，或者点击欢迎屏幕上的“新项目”按钮来完成：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/9d6b9538-0ada-4bb2-89f9-17caebfb9a74.png)

1.  在那之后，将弹出一个新窗口，询问您要创建的项目类型。在“应用程序”类别下选择“Qt Widgets 应用程序”，然后点击“选择...”，接着，为您的项目创建一个名称（我选择了`Chapter2`），并通过点击“浏览...”按钮选择项目目录：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/4e7a8d84-01bf-4955-845d-8aa6561f1888.png)

1.  接下来，您将被要求为您的项目选择一个工具包。如果您在 Windows 系统上运行，并且已安装了 Microsoft Visual Studio，则可以选择具有 MSVC 编译器的相关工具包；否则，选择运行 MinGW 编译器的工具包。Qt 通常预装了 MinGW 编译器，因此您无需单独下载它。如果您在 Linux 系统上运行，那么您将看到 GCC 工具包，如果您在 macOS 上运行，那么您将看到 Clang 工具包。要了解更多关于*工具包和构建设置*的信息，请查看第十五章，*跨平台开发*：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/27f4cfa6-475e-4f42-b565-9b1032f053dc.png)

1.  在那之后，新项目向导将要求您命名主窗口类。我们将使用默认设置，然后点击“下一步”按钮继续：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/807a7eff-6385-4e4b-bb7f-152a098a229e.png)

1.  最后，您将被要求将您的版本控制工具链接到您的项目。通过将版本控制工具链接到您的项目，您将能够将代码的每个修订版本保存在远程服务器上，并跟踪对项目所做的所有更改。如果您是在团队中工作，这将特别有用。然而，在本教程中，我们将不使用任何版本控制，所以让我们继续点击“完成”按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/de7bb5f9-296f-4f14-9e74-3585be29dc2d.png)

1.  完成后，Qt Creator 将打开您的新项目，您将能够在左上角看到您的项目目录显示，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/36036ee1-58f6-4813-92e1-f96125abb552.png)

1.  现在，通过双击项目目录面板上的`mainwindow.ui`来打开它。然后，Qt Creator 将切换到另一种模式，称为 Qt Designer，这实质上是一个用于为程序设计基于小部件的 GUI 的工具。一旦激活 Qt Designer，您将在左侧面板上看到可用的小部件列表，并且在右侧设计 GUI 的位置。在开始学习如何设计我们自己的 UI 之前，让我们花点时间熟悉一下 Qt Designer 的界面：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/0e7c7455-3546-4bdd-ad91-6e405747afe6.png)

以下数字代表前面截图中显示的 UI：

1.  菜单栏：菜单栏是您找到 Qt Creator 的所有基本功能的地方，例如创建新项目，保存文件，更改编译器设置等。

1.  小部件框：小部件框有点像工具箱，其中显示了 Qt Designer 提供的所有不同小部件，并准备好供使用。您可以从小部件框直接将任何小部件拖放到表单编辑器的画布上，它们将出现在您的程序中。

1.  模式选择器：模式选择器是您可以通过单击编辑或设计按钮快速轻松地在源代码编辑或 UI 设计之间切换的地方。您还可以通过单击位于模式选择器面板上的相应按钮轻松导航到调试器和分析器工具。

1.  构建快捷键：这里显示了三个不同的快捷按钮——构建、运行和调试。您可以通过按下这里的按钮轻松构建和测试运行应用程序，而不是在菜单栏上这样做。

1.  表单编辑器：这是您应用创意并设计应用程序 UI 的地方。您可以从小部件框中拖放任何小部件到表单编辑器的画布上，以使其出现在您的程序中。

1.  表单工具栏：表单工具栏是您可以快速选择要编辑的不同表单的地方。您可以通过单击位于小部件框上方的下拉框并选择要在 Qt Designer 中打开的 UI 文件来切换到不同的表单。还有一些按钮，允许您在表单编辑器和 UI 布局之间切换不同的模式。

1.  对象检查器：这是当前`.ui`文件中所有小部件以分层方式列出的地方。小部件按照其与其他小部件的父子关系在树状列表中排列。通过在表单编辑器中移动它来轻松重新排列小部件的层次结构。

1.  属性编辑器：当您从对象检查器窗口（或表单编辑器窗口）中选择一个小部件时，该特定小部件的属性将显示在属性编辑器上。您可以在这里更改任何属性，结果将立即显示在表单编辑器上。

1.  动作编辑器和信号与槽编辑器：动作编辑器和信号与槽编辑器都位于此窗口中。您可以使用动作编辑器创建与菜单栏和工具栏按钮相关联的动作。信号和槽编辑器是您

1.  输出窗格：输出窗格是您在测试应用程序时查找问题或调试信息的地方。它由几个窗口组成，显示不同的信息，例如问题、搜索结果、应用程序输出等。

简而言之，Qt 提供了一个名为 Qt Creator 的多合一编辑器。Qt Creator 与 Qt 附带的几种不同工具紧密配合，例如脚本编辑器、编译器、调试器、分析器和 UI 编辑器。您在上面的截图中看到的 UI 编辑器称为 Qt Designer。Qt Designer 是设计师设计其程序 UI 的完美工具，而无需编写任何代码。这是因为 Qt Designer 采用了所见即所得的方法，通过提供最终结果的准确视觉表示，意味着您在 Qt Designer 中设计的任何内容在编译和运行程序时都会完全相同。请注意，Qt 附带的每个工具实际上都可以单独运行，但如果您是初学者或只是做一个简单的项目，建议只使用 Qt Creator，它将所有这些工具连接在一个界面中。

# 基本的 Qt 小部件

现在，我们将看一下 Qt Designer 中默认的小部件集。实际上，您可以自己创建自定义小部件，但这是本书范围之外的高级主题。让我们来看看小部件框中列出的第一和第二类别——布局和间隔：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/b0c9740b-923c-42a5-8f99-7becc72dd3f7.png)

布局和间隔实际上并不是您可以直接观察到的东西，但它们可以影响小部件的位置和方向：

1.  垂直布局：垂直布局小部件以垂直列从上到下布置小部件。

1.  水平布局：水平布局小部件以水平行从左到右（或从右到左的从右到左语言）布置小部件。

1.  网格布局：网格布局小部件以二维网格布局放置小部件。每个小部件可以占据多个单元格。

1.  表单布局：表单布局小部件以两列字段样式放置小部件。正如其名称所示，这种类型的布局最适合输入小部件的表单。

Qt 提供的布局对于创建高质量的应用程序非常重要，而且非常强大。Qt 程序通常不使用固定位置来布置元素，因为布局允许对话框和窗口以合理的方式动态调整大小，同时处理不同语言中本地化的文本长度。如果您在 Qt 程序中不使用布局，其 UI 在不同计算机或设备上可能会看起来非常不同，这在大多数情况下会导致不愉快的用户体验。

接下来，让我们看看间隔小部件。间隔是一个不可见的小部件，它沿特定方向推动小部件，直到达到布局容器的限制。间隔必须在布局内使用，否则它们将不会产生任何效果。

有两种类型的间隔，即水平间隔和垂直间隔：

1.  水平间隔：水平间隔小部件是一个占据布局内空间并将布局内其他小部件推动沿水平空间移动的小部件。

1.  垂直间隔：垂直间隔与水平间隔类似，只是它将小部件沿垂直空间推动。

在没有实际使用它们的情况下，很难想象布局和间隔是如何工作的。不用担心，我们马上就会尝试它。Qt Designer 最强大的功能之一是您可以在每次更改后无需更改和编译代码即可实验和测试布局。

除了布局和间隔之外，还有几个类别，包括按钮、项目视图、容器、输入小部件和显示小部件。我不会解释它们中的每一个，因为它们的名称基本上是不言自明的。您也可以将小部件拖放到表单编辑器中以查看其功能。让我们来试一试：

1.  从小部件框中将“推按钮”小部件拖放到表单编辑器中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/b08ee4fd-99be-4cc4-b9ea-05ff5ebcc182.png)

1.  然后，选择新添加的“推送按钮”小部件，你会看到与该特定小部件相关的所有信息现在都显示在属性编辑器面板上：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/0e37a02f-3c9f-4105-8f8e-c9c5adc6a2c9.png)

1.  你可以在 C++代码中以编程方式更改小部件的属性，如外观、焦点策略、工具提示等。有些属性也可以直接在表单编辑器中进行编辑。让我们双击“推送按钮”并更改按钮的文本，然后通过拖动其边缘来调整按钮的大小：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/66b379d7-9073-4de9-9ac0-4c67809f03e4.png)

1.  完成后，让我们在表单编辑器中拖放一个水平布局。然后，将“推送按钮”拖放到新添加的布局中。你会看到按钮自动适应到布局中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/46d70ffd-ef5a-40d5-886e-3d909a82504b.png)

1.  默认情况下，主窗口不具有任何布局效果，因此小部件将保持在它们最初放置的位置，即使窗口被调整大小，这看起来并不好。要为主窗口添加布局效果，在表单编辑器中右键单击窗口，选择“布局”，最后选择“垂直布局”。现在你会看到我们之前添加的水平布局小部件现在自动扩展以适应整个窗口。这是 Qt 中布局的正确行为：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/7df2925b-fe74-48f6-9624-923afa4de14b.png)

1.  接下来，我们可以玩一下间隔器，看看它有什么效果。我们将在包含“推送按钮”的布局顶部拖放一个垂直间隔器，然后在其布局内的按钮两侧放置两个水平间隔器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/b786e4c5-9668-4c30-ac42-3ad74bade19c.png)

间隔器将推动它们两端的所有小部件并占据空间。在这个例子中，“提交”按钮将始终保持在窗口底部并保持其中间位置，无论窗口的大小如何。这使得 GUI 在不同的屏幕尺寸上看起来很好。

自从我们在窗口中添加了间隔器以后，我们的“推送按钮”被挤压到了最小尺寸。通过将其`minimumSize`属性设置为 120 x 40 来放大按钮，你会看到按钮现在显得更大了：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/10f7a183-c62d-4c25-bf11-16e2e9784767.png)

1.  之后，让我们在“推送按钮”的布局上方添加一个表单布局，并在其下方添加一个垂直间隔器。现在你会看到表单布局非常窄，因为它被我们之前放置在主窗口上的垂直间隔器挤压，这可能会在你想要将小部件拖放到表单布局中时造成麻烦。为了解决这个问题，暂时将`layoutTopMargin`属性设置为`20`或更高：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/190414c4-4b1b-4b30-b24c-940dc11f5e7e.png)

1.  然后，在表单布局的左侧拖放两个标签，右侧拖放两个行编辑。双击标签，将它们的显示文本分别更改为“用户名：”和“密码：”。完成后，将表单布局的`layoutTopMargin`属性设置回`0`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/80a44e78-2571-458f-b9db-adbae4d956fa.png)

目前，GUI 看起来非常棒，但是表单布局现在占据了中间的所有空间，这在主窗口最大化时并不是很愉快。为了保持表单紧凑，我们将执行以下一些有点棘手的步骤：

1.  首先，在表单上方拖放一个水平布局，并将其`layoutTopMargin`和`layoutBottomMargin`设置为`20`，以便稍后放置在其中的小部件不会离“提交”按钮太近。接下来，将之前放置在表单布局中的整个表单布局拖放到水平布局中。然后，在表单的两侧放置水平间隔器以使其保持居中。以下截图说明了这些步骤：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e87bdb1a-9eab-4ffc-bad2-59b8bf8a76af.png)

1.  之后，我们可以在进入下一部分之前对 GUI 进行进一步调整，使其看起来整洁。首先，将两个行编辑小部件的`minimumSize`属性设置为 150 x 25。然后，将表单布局的`layoutLeftMargin`、`layoutRightMargin`、`layoutTopMargin`和`layoutBottomMargin`属性设置为`25`。我们这样做的原因是我们将在下一部分中为表单布局添加轮廓。

1.  由于“提交”按钮现在与表单布局的距离太远，让我们将水平布局的`layoutBottomMargin`属性设置为`0`，以将表单布局设置为`0`。这将使“提交”按钮稍微上移并靠近表单布局。之后，我们将调整“提交”按钮的大小，使其与表单布局对齐。让我们将“提交”按钮的`minimumSize`属性设置为 260 x 35，然后我们完成了！：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/cc448268-3595-446c-a1cb-1fb416824a36.png)

您还可以通过转到“工具”|“表单编辑器”|“预览”来预览 GUI，而无需构建程序。Qt Designer 是一种非常方便的工具，可以在不陡峭的学习曲线的情况下为 Qt 程序设计时尚的 GUI。在接下来的部分中，我们将学习如何使用 Qt 样式表自定义小部件的外观。

# Qt 样式表

Qt 的小部件应用程序使用了一个名为 Qt 样式表的样式系统，它类似于 Web 技术的样式系统——**CSS**（**层叠样式表**）。您只需要编写小部件的样式描述，Qt 将相应地呈现它。Qt 样式表的语法与 CSS 几乎相同。

Qt 样式表受 CSS 的启发，因此它们非常相似：

+   Qt 样式表：

```cpp
QLineEdit { color: blue; background-color: black; } 
```

+   CSS：

```cpp
h1 { color: blue; background-color: black; } 
```

在上面的示例中，Qt 样式表和 CSS 都包含了一个声明块和一个选择器。每个声明由属性和值组成，它们之间用冒号分隔。

您可以通过两种方法更改小部件的样式表——直接使用 C++代码或使用属性编辑器。如果您使用 C++代码，可以调用`QObject::setStyleSheet()`函数，如下所示：

```cpp
myButton->setStyleSheet("background-color: green"); 
```

上述代码将我们的按钮小部件的背景颜色更改为绿色。您也可以通过在 Qt Designer 中将相同的声明写入小部件的`styleSheet`属性中来实现相同的结果：

```cpp
QPushButton#myButton { background-color: green } 
```

关于 Qt 样式表的语法和属性的更多信息，请参考以下链接：[`doc.qt.io/qt-5/stylesheet-reference.html`](http://doc.qt.io/qt-5/stylesheet-reference.html)

让我们继续我们的项目，并将自定义 Qt 样式表应用到我们的 GUI 上！

1.  首先，右键单击“提交”按钮，然后选择“更改样式表...”将弹出一个窗口供您编辑小部件的样式表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/26ee01cd-38ad-4ec7-a8d5-907c466e4c39.png)

1.  然后，将以下内容添加到样式表编辑器窗口中：

```cpp
border: 1px solid rgb(24, 103, 155); 
border-radius: 5px; 
background-color: rgb(124, 203, 255); 
color: white;
```

1.  完成后，单击“确定”按钮，您应该能够看到“提交”按钮的外观发生了变化：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e14883aa-10c4-4615-93c4-30d02a0923c4.png)

我们之前使用的样式表基本上是不言自明的。它使按钮的边框变为深蓝色，并使用 RGB 值设置边框颜色。然后，它还将按钮应用了圆角效果，并将其背景颜色更改为浅蓝色。最后，“提交”文本也已更改为白色。

1.  接下来，我们想要将自定义样式表应用到表单布局上。但是，您会注意到右键单击它时没有“更改样式表...”选项。这是因为布局不具备该属性。为了对表单布局应用样式，我们必须首先将其转换为 QWidget 或 QFrame 对象。为此，请右键单击表单布局，然后选择“转换为 | QFrame”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/3634c2e1-b183-4dd3-ab0e-845d8041d60c.png)

1.  完成后，您会注意到它现在具有`styleSheet`属性，因此我们现在可以自定义其外观。让我们右键单击它，然后选择“Change styleSheet...”打开样式表编辑器窗口。然后，插入以下脚本：

```cpp
#formFrame { 
border: 1px solid rgb(24, 103, 155); 
border-radius: 5px; 
background-color: white; } 
```

单词`formFrame`指的是小部件的`objectName`属性，它必须与小部件的确切名称匹配，否则样式将不会应用于它。我们为这个例子定义小部件名称的原因（这是我们在上一个例子中没有做的）是因为如果我们不指定小部件名称，样式也将应用于其所有子级。您可以尝试从前面的脚本中删除`#formFrame {}`，然后看看会发生什么——现在，即使标签和行编辑也有边框线，这不是我们打算做的。GUI 现在看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/120838d2-fa4d-46c0-8ef9-fd47c956e19b.png)

1.  最后，我们想要一个漂亮的背景，我们可以通过附加背景图像来实现这一点。为此，我们首先需要将图像导入到 Qt 的资源系统中。转到“文件”|“新建文件或项目...”，然后在“文件和类别”类别下选择 Qt。之后，选择 Qt 资源文件并单击“选择...”按钮。Qt 资源系统是一种存储二进制文件的平台无关机制，这些文件存储在应用程序的可执行文件中。您可以基本上将所有这些重要文件存储在这里，例如图标图像或语言文件，直接通过使用 Qt 资源文件将这些重要文件直接嵌入到编译过程中的程序中。

1.  然后，在按下“下一步”按钮之前，键入文件名并设置其位置，然后点击“完成”按钮。现在，您将看到一个新的资源文件被创建，我命名为`resource.qrc`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/50822283-7c7e-4793-8d0b-b8aecd132fbd.png)

1.  用 Qt Creator 打开`resource.qrc`，然后选择“添加”|“添加前缀”。之后，键入您喜欢的前缀，例如`/images`。完成后，再次选择“添加”，这次选择“添加文件”。添加样本项目提供的图像文件`login_bg.png`。然后，保存`resource.qrc`，右键单击图像，选择“复制资源路径到剪贴板”。之后，关闭`resource.qrc`，再次打开`mainwindow.ui`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/6dd73f49-ae5b-4203-b622-73a4a5516060.png)

1.  我们需要做的下一件事是右键单击“Object Inspector”中的`centralWidget`对象，然后选择“Change styleSheet...”，然后插入以下脚本：

```cpp
#centralWidget { 
border-image: url(:/images/login_bg.png); }
```

1.  在`url()`中的文本可以通过按*Ctrl* + *V*（或粘贴）插入，因为在上一步中选择“复制资源路径到剪贴板”时已将其复制到剪贴板。最终结果如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/7234cdb9-3537-4851-94f0-2f498ad43a0e.png)

请确保您还构建和运行应用程序，然后检查最终结果是否与预期相同。还有很多东西可以调整，以使其看起来真正专业，但到目前为止，它看起来相当不错！

# 摘要

Qt Designer 真正改变了我们设计程序 GUI 的方式。它不仅包括所有常见的小部件，还有像布局和间隔这样方便的东西，这使我们的程序在不同类型的监视器和屏幕尺寸上运行得非常好。还要注意，我们已成功创建了一个具有漂亮用户界面的工作应用程序，而没有编写一行 C++代码！

本章中我们学到的只是 Qt 的冰山一角，因为还有许多功能我们尚未涵盖！在下一章中加入我们，学习如何使我们的程序真正功能强大！


# 第三章：数据库连接

在上一章中，我们学习了如何从头开始创建一个登录页面。然而，它还没有功能，因为登录页面还没有连接到数据库。在本章中，您将学习如何将您的 Qt 应用程序连接到验证登录凭据的 MySQL（或 MariaDB）数据库。

在本章中，我们将涵盖以下主题：

+   介绍 MySQL 数据库系统

+   设置 MySQL 数据库

+   SQL 命令

+   Qt 中的数据库连接

+   功能性登录页面

我们将逐步学习本章内容，以发现 Qt 提供的强大功能，使您的应用程序可以直接连接到数据库，而无需任何额外的第三方依赖。数据库查询本身是一个庞大的主题，但我们将能够通过示例和实际方法从头开始学习最基本的命令。

Qt 支持多种不同类型的数据库系统：

+   MySQL（或 MariaDB）

+   SQLite（版本 2 和 3）

+   IBM DB2

+   Oracle

+   ODBC

+   PostgreSQL

+   Sybase Adaptive Server

其中最受欢迎的两种是 MySQL 和 SQLite。SQLite 数据库通常用于离线，并且不需要任何设置，因为它使用磁盘文件格式来存储数据。因此，在本章中，我们将学习如何设置 MySQL 数据库系统，并同时学习如何将我们的 Qt 应用程序连接到 MySQL 数据库。用于连接到 MySQL 数据库的 C++代码可以在不进行太多修改的情况下重用于连接到其他数据库系统。

# 介绍 MySQL 数据库系统

**MySQL**是一种基于关系模型的开源数据库管理系统，这是现代数据库系统用于存储各种信息的最常用方法。

与一些其他传统模型（如对象数据库系统或分层数据库系统）不同，关系模型已被证明更加用户友好，并且在其他模型之外表现出色。这就是为什么我们今天看到的大多数现代数据库系统大多使用这种方法的原因。

MySQL 最初由一家名为**MySQL AB**的瑞典公司开发，其名称是公司联合创始人的女儿*My*和**Structured Query Language**的缩写*SQL*的组合。

与 Qt 类似，MySQL 在其历史上也曾被多个不同的人拥有。最引人注目的收购发生在 2008 年，**Sun Microsystems**以 10 亿美元收购了 MySQL AB。一年后的 2009 年，**Oracle Corporation**收购了 Sun Microsystems，因此 MySQL 直到今天仍归 Oracle 所有。尽管 MySQL 多次易手，但它仍然是一款开源软件，允许用户更改代码以适应其自身目的。

由于其开源性质，还有其他从 MySQL 项目派生/分叉出来的数据库系统，如**MariaDB**、**Percona Server**等。然而，这些替代方案与 MySQL 并不完全兼容，因为它们已经修改了以适应自己的需求，因此在这些系统中有些命令可能会有所不同。

根据**Stack Overflow**在 2017 年进行的一项调查，MySQL 是 Web 开发人员中使用最广泛的数据库系统，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/ea013fb4-46cf-44fc-ac35-1968cc90e84f.png)

调查结果表明，您在本章中学到的内容不仅可以应用于 Qt 项目，还可以应用于 Web、移动应用程序和其他类型的应用程序。

此外，MySQL 及其变体被大公司和项目组使用，如 Facebook、YouTube、Twitter、NASA、Wordpress、Drupal、Airbnb、Spotify 等。这意味着在开发过程中遇到任何技术问题时，您可以轻松获得答案。

有关 MySQL 的更多信息，请访问：

[`www.mysql.com`](https://www.mysql.com)

# 设置 MySQL 数据库

设置 MySQL 数据库有许多不同的方法。这实际上取决于您正在运行的平台类型，无论是 Windows、Linux、Mac 还是其他类型的操作系统；它还将取决于您的数据库用途——无论是用于开发和测试，还是用于大规模生产服务器。

对于大规模服务（如社交媒体），最好的方法是从源代码编译 MySQL，因为这样的项目需要大量的优化、配置，有时需要定制，以处理大量用户和流量。

但是，如果您只是进行正常使用，可以直接下载预编译的二进制文件，因为默认配置对此非常足够。您可以从官方网站或下载安装包安装独立的 MySQL 安装程序，该安装程序还包括 MySQL 以外的几个其他软件。

在本章中，我们将使用一个名为**XAMPP**的软件包，这是一个由**Apache Friends**开发的 Web 服务器堆栈软件包。该软件包包括**Apache**，**MariaDB**，**PHP**和其他可选服务，您可以在安装过程中添加。以前，MySQL 是该软件包的一部分，但从 5.5.30 和 5.6.14 版本开始，它已经被**MariaDB**替换。MariaDB 几乎与 MySQL 相同，除了涉及高级功能的命令，这些功能我们在本书中不会使用。

我们使用 XAMPP 的原因是它有一个控制面板，可以轻松启动和停止服务，而无需使用命令提示符，并且可以轻松访问配置文件，而无需自己深入安装目录。对于涉及频繁测试的应用程序开发来说，它非常快速和高效。但是，不建议在生产服务器上使用 XAMPP，因为一些安全功能已经被默认禁用。

或者，您也可以通过其他类似的软件包安装 MySQL，如**AppServ**，**AMPPS**，**LAMP**（仅限 Linux），**WAMP**（仅限 Windows），**Zend****Server**等。

现在，让我们学习如何安装 XAMPP：

1.  首先，访问他们的网站[`www.apachefriends.org`](https://www.apachefriends.org)，并点击屏幕底部的一个下载按钮，显示您当前操作系统的图标：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/d5053fc7-76bd-47ad-bf75-a82f1f8758db.png)

1.  一旦您点击下载按钮，下载过程应该在几秒钟内自动开始，并且一旦完成，它应该继续安装程序。在安装过程开始之前，请确保包括 Apache 和 MySQL/MariaDB。

1.  安装 XAMPP 后，从开始菜单或桌面快捷方式启动控制面板。之后，您可能会注意到没有发生任何事情。这是因为 XAMPP 控制面板默认隐藏在任务栏中。您可以通过右键单击它并在弹出菜单中选择显示/隐藏选项来显示控制面板窗口。以下屏幕截图显示了 Windows 机器上的情况。对于 Linux，菜单可能看起来略有不同，但总体上非常相似。对于 macOS，您必须从启动台或从 dock 启动 XAMPP：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/2a3b8dac-a0be-4737-9347-82c56c7345a1.png)

1.  一旦您点击显示/隐藏选项，您最终将在屏幕上看到控制面板窗口。如果再次点击显示/隐藏选项，窗口将被隐藏起来：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/4984acd2-2086-41b0-bbcd-962dc8e2a416.png)

1.  他们的控制面板乍一看就很容易理解。在左侧，您可以看到 XAMPP 中可用服务的名称，在右侧，您将看到指示启动、配置、日志等按钮。由于某种原因，XAMPP 显示 MySQL 作为模块名称，但实际上它正在运行 MariaDB。不用担心；由于 MariaDB 是 MySQL 的一个分支，两者基本上工作方式相同。

1.  在本章中，我们只需要 Apache 和 MySQL（MariaDB），所以让我们点击这些服务的启动按钮。一两秒后，您会看到启动按钮现在标记为停止，这意味着服务已经启动！：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/ac835466-9711-40f6-b924-8cecf413aeff.png)

1.  要验证这一点，让我们打开浏览器，输入`localhost`作为网站地址。如果您看到类似以下图像的东西，这意味着 Apache Web 服务器已成功启动！：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/3b8247ee-f9db-4a17-a1a8-ccc18d7147e4.png)

1.  Apache 在这里非常重要，因为我们将使用它来使用名为**phpMyAdmin**的基于 Web 的管理工具来配置数据库。phpMyAdmin 是用 PHP 脚本语言编写的 MySQL 管理工具，因此得名。尽管它最初是为 MySQL 设计的，但它对 MariaDB 也非常有效。

1.  要访问 phpMyAdmin 控制面板，请在浏览器上输入`localhost/phpmyadmin`。之后，您应该会看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/5b480b92-1af6-46ae-8bf8-e0a965c6b8a0.png)

1.  在页面的左侧，您将看到导航面板，它允许您访问 MariaDB 数据库中可用的不同数据库。页面的右侧是各种工具，让您查看表格，编辑表格，运行 SQL 命令，将数据导出到电子表格，设置权限等等。

1.  默认情况下，您只能在右侧的设置面板上修改数据库的常规设置。在能够修改特定数据库的设置之前，您必须在左侧的导航面板上选择一个数据库。

1.  数据库就像一个您可以在其中存储日志的文件柜。每本日志称为一个表，每个表包含数据，这些数据像电子表格一样排序。当您想从 MariaDB 获取数据时，您必须在获取数据之前指定要访问的文件柜（数据库）和日志（表）。希望这能让您更好地理解 MariaDB 和其他类似的数据库系统背后的概念。

1.  现在，让我们开始创建我们的第一个数据库！要这样做，您可以点击导航面板上方的数据库名称上方的新建按钮，或者点击菜单顶部的数据库按钮。这两个按钮都会带您到数据库页面，您应该能够在菜单按钮下方看到这个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/14b5f1e8-da81-4fc8-a2ab-32ea8391e601.png)

1.  之后，让我们创建我们的第一个数据库！输入您想要创建的数据库名称，然后点击创建按钮。数据库创建后，您将被重定向到结构页面，该页面将列出此数据库中包含的所有表。默认情况下，您新创建的数据库不包含任何表，因此您将看到一行文本，其中说没有在数据库中找到表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e4aa4deb-6437-4a98-98f9-f8ea2582bf7c.png)

1.  猜猜我们接下来要做什么？正确，我们将创建我们的第一个表！首先，让我们插入您想要创建的表的名称。由于在本章后面我们将做一个登录页面，让我们将我们的表命名为`user`。我们将保留默认的列数，然后点击 Go。

1.  之后，您将被重定向到另一个页面，其中包含许多列的输入字段供您填写。每一列代表一个数据结构，它将在创建后添加到您的表中。

1.  第一件需要添加到表结构中的是一个 ID，它将在每次插入新数据时自动增加。然后，添加一个时间戳列来指示数据插入的日期和时间，这对于调试很有用。最后，我们将添加一个用户名列和密码列用于登录验证。如果您不确定如何操作，请参考以下图片。确保您遵循图片中被圈出的设置：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/75358cae-706a-4724-bf52-f7e4b844bfff.png)

1.  结构的类型非常重要，必须根据其预期目的进行设置。例如，id 列必须设置为 INT（整数），因为它必须是一个完整的数字，而用户名和密码必须设置为 VARCHAR 或其他类似的数据类型（CHAR、TEXT 等），以便正确保存数据。

1.  另一方面，时间戳必须设置为时间戳类型，并且必须将默认值设置为 CURRENT_TIMESTAMP，这将通知 MariaDB 在数据插入时自动生成当前时间戳。

1.  请注意，ID 列的索引设置必须设置为 PRIMARY，并确保 A_I（自动增量）复选框被选中。当您选中 A_I 复选框时，将出现一个添加索引窗口。您可以保持默认设置，然后点击 Go 按钮完成步骤并开始创建表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/edd187b5-7f50-47b4-9f89-d5caee38de4c.png)

1.  创建新表后，您应该能够看到类似以下图片的内容。您仍然可以随时通过单击更改按钮来编辑结构设置；您还可以通过单击列右侧的删除按钮来删除任何列。请注意，删除列也将删除属于该列的所有现有数据，此操作无法撤消：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/6342b9cf-6219-4036-92a8-e4ed95cf1a96.png)

1.  尽管我们通常会通过程序或网页向数据库添加数据，但我们也可以直接在 phpMyAdmin 上添加数据以进行测试。要使用 phpMyAdmin 添加数据，首先必须创建一个数据库和表，这是我们在前面的步骤中已经完成的。然后，点击菜单顶部的插入按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/bf34412c-d063-4f91-8f52-053dd8ee6768.png)

1.  之后，您会看到一个表单出现，它类似于我们之前创建的数据结构：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/480a40bc-f234-468d-9184-1e3e5b45e03c.png)

1.  您可以简单地忽略 ID 和时间戳的值，因为当您保存数据时它们将自动生成。在这种情况下，只需要填写用户名和密码。为了测试，让我们将`test`作为用户名，`123456`作为密码。然后，点击 Go 按钮保存数据。

请注意，您不应该以人类可读的格式保存密码在您的实际生产服务器上。在将密码传递到数据库之前，您必须使用加密哈希函数（如 SHA-512、RIPEEMD-512、BLAKE2b 等）对密码进行加密。这将确保密码在数据库被攻破时不被黑客读取。我们将在本章末尾讨论这个话题。

现在我们已经完成了数据库的设置并插入了我们的第一个测试数据，让我们继续学习一些 SQL 命令！

# SQL 命令

大多数流行的关系数据库管理系统，如 MySQL、MariaDB、Oracle SQL、Microsoft SQL 等，都使用一种称为 SQL（结构化查询语言）的声明性语言来与数据库交互。SQL 最初是由 IBM 工程师在 20 世纪 70 年代开发的，但后来又被 Oracle Corporation 和其他当时新兴的技术公司进一步增强。

如今，SQL 已成为**美国国家标准学会**（**ANSI**）和**国际标准化组织**（**ISO**）的标准。SQL 语言自那时起已被许多不同的数据库系统采用，并成为现代时代最流行的数据库语言之一。

在本节中，我们将学习一些基本的 SQL 命令，您可以使用这些命令与您的 MariaDB 数据库进行交互，特别是用于从数据库中获取、保存、修改和删除数据。这些基本命令也可以用于其他类型的基于 SQL 的数据库系统，以及在 ANSI 和 ISO 标准下。只是，一些更高级/定制的功能在不同系统中可能有所不同，因此在使用这些高级功能之前，请确保阅读系统手册。

好的，让我们开始吧！

# SELECT

大多数 SQL 语句都是单词简短且不言自明的。例如，此语句用于从特定表中选择一个或多个列，并获取来自所述列的数据。让我们来看看一些使用`SELECT`语句的示例命令。

以下命令检索`user`表中所有列的所有数据：

```cpp
SELECT * FROM user;
```

以下命令仅从用户表中检索`username`列：

```cpp
SELECT username FROM user;
```

以下命令检索`user`表中`id`等于`1`的`username`和`password`列：

```cpp
SELECT username, password FROM user WHERE id = 1;
```

您可以使用 phpMyAdmin 自行尝试这些命令。要执行此操作，请单击 phpMyAdmin 菜单顶部的 SQL 按钮。之后，您可以在下面的文本字段中输入命令，然后单击 Go 以执行查询：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/7a345815-c3c1-45bb-93aa-affbbcaee5fa.png)

要了解有关`SELECT`语句的更多信息，请参阅以下链接：

[`dev.mysql.com/doc/refman/5.7/en/select.html`](https://dev.mysql.com/doc/refman/5.7/en/select.html)

# INSERT

接下来，`INSERT`语句用于将新数据保存到数据库表中。例如：

```cpp
INSERT INTO user (username, password) VALUES ("test2", "123456");
```

上述 SQL 命令将`username`和`password`数据插入`user`表中。还有一些其他语句可以与`INSERT`一起使用，例如`LOW_PRIORITY`，`DELAYED`，`HIGH_PRIORITY`等。

请参考以下链接以了解更多关于这些选项的信息：

[`dev.mysql.com/doc/refman/5.7/en/insert.html`](https://dev.mysql.com/doc/refman/5.7/en/insert.html)

# UPDATE

`UPDATE`语句修改数据库中的现有数据。您必须为`UPDATE`命令指定条件，否则它将修改表中的每一条数据，这不是我们期望的行为。尝试以下命令，它将更改第一个用户的`username`和`password`：

```cpp
UPDATE user SET username = "test1", password = "1234321" WHERE id = 1;
```

但是，如果 ID 为`1`的用户不存在，该命令将失败。如果您提供的`username`和`password`数据与数据库中存储的数据完全匹配（没有变化），该命令还将返回状态`0 行受影响`。有关`UPDATE`语句的更多信息，请参阅以下链接：

[`dev.mysql.com/doc/refman/5.7/en/update.html`](https://dev.mysql.com/doc/refman/5.7/en/update.html)

# DELETE

`DELETE`语句从数据库的特定表中删除数据。例如，以下命令从`user`表中删除 ID 为`1`的数据：

```cpp
DELETE FROM user WHERE id = 1;
```

尽管您可以使用此语句删除不需要的数据，但不建议从数据库中删除任何数据，因为该操作无法撤消。最好在表中添加另一列，称为状态，并使用该列指示数据是否应显示。例如，如果用户在前端应用程序中删除数据，请将该数据的状态设置为（假设）`1`而不是`0`。然后，当您想要在前端显示数据时，仅显示携带`status`为`0`的数据：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/7858c675-a8f2-41dd-8112-e762d1c1b0a8.png)

这样，任何意外删除的数据都可以轻松恢复。如果您只计划使用 true 或 false，也可以使用 BOOLEAN 类型。我通常使用 TINYINT，以防将来需要第三或第四状态。有关`DELETE`语句的更多信息，您可以参考以下链接：

[`dev.mysql.com/doc/refman/5.7/en/delete.html`](https://dev.mysql.com/doc/refman/5.7/en/delete.html)

# 连接

使用关系数据库管理系统的优势在于，可以轻松地将来自不同表的数据连接在一起，并以单个批量返回给用户。这极大地提高了开发人员的生产力，因为它在设计复杂的数据库结构时提供了流动性和灵活性。

MariaDB/MySQL 中有许多类型的 JOIN 语句—INNER JOIN、FULL OUTER JOIN、LEFT JOIN 和 RIGHT JOIN。这些不同的 JOIN 语句在执行时表现不同，您可以在以下图像中看到：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/12b3d2f1-150c-48c3-b1d5-07f2d459d007.png)

大多数情况下，我们将使用 INNER JOIN 语句，因为它只返回两个表中具有匹配值的数据，因此只返回所需的少量数据。JOIN 命令比其他命令复杂得多，因为您需要首先设计可连接的表。在开始测试 JOIN 命令之前，让我们创建另一个表以实现这一点。我们将称这个新表为 department：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/02429334-d381-4597-82cc-d533541239a6.png)

之后，添加两个部门，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e22b95e9-823e-4da3-8983-435a77825095.png)

然后，转到用户表，在结构页面，滚动到底部，查找所示的表单，然后单击“Go”按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/ca934b9d-4c81-40e2-8830-f1ee803de1a0.png)

添加一个名为 deptID（代表部门 ID）的新列，并将其数据类型设置为`int`（整数）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/50b28f30-fb37-402b-9748-76115be1cd2c.png)

完成后，设置几个测试用户，并将他们的 deptID 分别设置为`1`或`2`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/fc9743b9-80f9-45b3-b8f5-3c2dc3db7af2.png)

请注意，我在这里还添加了状态列，以检查用户是否已被删除。完成后，让我们尝试运行一个示例命令！：

```cpp
SELECT my_user.username, department.name FROM (SELECT * FROM user WHERE deptID = 1) AS my_user INNER JOIN department ON department.id = my_user.deptID AND my_user.status = 0 
```

乍一看，这看起来相当复杂，但如果您将其分成几个部分，实际上并不复杂。我们将从`()`括号内的命令开始，其中我们要求 MariaDB/MySQL 选择`deptID = 1`的`user`表中的所有列：

```cpp
SELECT * FROM user WHERE deptID = 1 
```

之后，将其包含在`()`括号中，并将整个命令命名为`my_user`。之后，您可以开始使用`INNER JOIN`语句将用户表（现在称为`my_user`）与部门表进行连接。在这里，我们还添加了一些条件来查找数据，例如部门表的 ID 必须与`my_user`的`deptID`匹配，并且`my_user`的状态值必须为`0`，表示数据仍然有效，未标记为已移除：

```cpp
(SELECT * FROM user WHERE deptID = 1) AS my_user INNER JOIN department ON department.id = my_user.deptID AND my_user.status = 0 
```

最后，在前面添加以下代码以完成 SQL 命令：

```cpp
SELECT my_user.username, department.name FROM  
```

让我们尝试上述命令，看看结果是否符合您的预期。

只要表通过匹配列相互连接，您就可以使用此方法连接无限数量的表。

要了解有关**JOIN**语句的更多信息，请访问以下链接：

[`dev.mysql.com/doc/refman/5.7/en/join.html`](https://dev.mysql.com/doc/refman/5.7/en/join.html)

在本章中，我们还没有涵盖的许多其他 SQL 语句，但我们已经涵盖的基本上就是您开始所需的全部内容。

在我们进入下一部分之前，我们必须为应用程序创建一个访问 MariaDB/MySQL 数据库的用户帐户。首先，转到 phpMyAdmin 的主页，然后单击顶部菜单上的用户帐户：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e7591330-3f91-4f6c-9fe3-7cee39a65a11.png)

然后，转到底部，查找名为“添加用户帐户”的链接：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/bf188b4e-ac18-4800-b4a4-f484bef7e05c.png)

一旦您进入“添加用户帐户”页面，请在登录信息表单中输入用户名和密码信息。确保主机名设置为本地：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/ab7d52be-0aba-4723-b40c-a90718e74ce5.png)

然后，向下滚动并设置用户的全局权限。在数据部分启用选项就足够了，但不要启用其他选项，因为一旦您的服务器被入侵，它可能会给黑客修改数据库结构的权限。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/d3803205-cff4-4c72-ae76-9da02eba99a0.png)

创建用户帐户后，请按照以下步骤允许新创建的用户访问名为 test 的数据库（或您选择的任何其他表名）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/89c0aee6-4bd7-430d-b521-4abf695e9ba9.png)

点击“Go”按钮后，您现在已经赋予了用户帐户访问数据库的权限！在下一节中，我们将学习如何将我们的 Qt 应用程序连接到数据库。

# Qt 中的数据库连接

现在我们已经学会了如何设置一个功能齐全的 MySQL/MariaDB 数据库系统，让我们再进一步，了解 Qt 中的数据库连接模块！

在我们继续处理上一章的登录页面之前，让我们首先开始一个新的 Qt 项目，这样可以更容易地演示与数据库连接相关的功能，而不会被其他东西分散注意力。这次，我们将选择名为 Qt 控制台应用程序的终端样式应用程序，因为我们不真的需要任何 GUI 来进行演示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/b62b379e-c4f9-4152-9670-799387f56f43.png)

创建新项目后，您应该只在项目中看到两个文件，即[project_name].pro 和 main.cpp：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/f74bcfc6-d1f9-463d-8fc1-25c4a112d9a6.png)

您需要做的第一件事是打开您的项目文件（`.pro`），在我的情况下是 DatabaseConnection.pro，并在第一行的末尾添加`sql`关键字，如下所示：

```cpp
QT += core sql 
```

就这么简单，我们已经成功地将`sql`模块导入到了我们的 Qt 项目中！然后，打开`main.cpp`，您应该看到一个非常简单的脚本，其中只包含八行代码。这基本上是您创建一个空控制台应用程序所需的全部内容：

```cpp
#include <QCoreApplication> 
int main(int argc, char *argv[]) 
{ 
   QCoreApplication a(argc, argv); 
   return a.exec(); 
} 
```

为了连接到我们的数据库，我们必须首先将相关的头文件导入到`main.cpp`中，如下所示：

```cpp
#include <QCoreApplication> 
#include <QtSql> 
#include <QSqlDatabase> 
#include <QSqlQuery> 
#include <QDebug> 
int main(int argc, char *argv[]) 
{ 
   QCoreApplication a(argc, argv); 
   return a.exec(); 
} 
```

没有这些头文件，我们将无法使用 Qt 的`sql`模块提供的函数，这些函数是我们之前导入的。此外，我们还添加了`QDebug`头文件，以便我们可以轻松地在控制台显示上打印出任何文本（类似于 C++标准库提供的`std::cout`函数）。

接下来，我们将向`main.cpp`文件添加一些代码。在`return a.exec()`之前添加以下突出显示的代码：

```cpp
int main(int argc, char *argv[]) 
{ 
   QCoreApplication a(argc, argv); 
   QSqlDatabase db = QSqlDatabase::addDatabase("QMYSQL"); 
   db.setHostName("127.0.0.1"); 
   db.setPort(3306); 
   db.setDatabaseName("test"); 
   db.setUserName("testuser"); 
   db.setPassword("testpass"); 
   if (db.open()) 
   { 
         qDebug() << "Connected!"; 
   } 
   else 
   { 
         qDebug() << "Failed to connect."; 
         return 0; 
   } 
   return a.exec(); 
} 
```

请注意，数据库名称、用户名和密码可能与您在数据库中设置的不同，请在编译项目之前确保它们是正确的。

完成后，让我们点击“运行”按钮，看看会发生什么！：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/61992a63-5c9a-4319-95a0-50e25a5ee0ad.png)

如果您看到以下错误，请不要担心：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/1b176a50-7762-48d9-8b8f-a1db1165c9b8.png)

这只是因为您必须将 MariaDB Connector（或者如果您正在运行 MySQL，则是 MySQL Connector）安装到您的计算机上，并将 DLL 文件复制到 Qt 安装路径。请确保 DLL 文件与服务器的数据库库匹配。您可以打开 phpMyAdmin 的主页，查看它当前使用的库。

出于某种原因，尽管我正在运行带有 MariaDB 的 XAMPP，但这里的库名称显示为 libmysql 而不是 libmariadb，因此我不得不安装 MySQL Connector：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/3b99df22-27e4-4703-92fb-9982f7e896eb.png)

如果您使用的是 MariaDB，请在以下链接下载 MariaDB Connector：

[`downloads.mariadb.org/connector-c`](https://downloads.mariadb.org/connector-c) 如果您使用的是 MySQL（或者遇到了我遇到的相同问题），请访问另一个链接并下载 MySQL 连接器：

[`dev.mysql.com/downloads/connector/cpp/`](https://dev.mysql.com/downloads/connector/cpp/)

在您下载了 MariaDB 连接器之后，请在您的计算机上安装它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/3766d4f4-d470-4bc6-8d6f-239d81751bcf.png)

上面的截图显示了 Windows 机器的安装过程。如果您使用 Linux，您必须为您的 Linux 发行版下载正确的软件包。如果您使用 Debian、Ubuntu 或其变体之一，请下载 Debian 和 Ubuntu 软件包。如果您使用 Red Hat、Fedora、CentOS 或其变体之一，请下载 Red Hat、Fedora 和 CentOS 软件包。这些软件包的安装是自动的，所以您可以放心。但是，如果您没有使用这些系统之一，您将需要下载符合您系统要求的下载页面上列出的一个 gzipped tar 文件。

有关在 Linux 上安装 MariaDB 二进制 tarballs 的更多信息，请参阅以下链接：

[`mariadb.com/kb/en/library/installing-mariadb-binary-tarballs/`](https://mariadb.com/kb/en/library/installing-mariadb-binary-tarballs/)

至于 macOS，您需要使用一个名为**Homebrew**的软件包管理器来安装 MariaDB 服务器。

有关更多信息，请查看以下链接：

[`mariadb.com/kb/en/library/installing-mariadb-on-macos-using-homebrew/`](https://mariadb.com/kb/en/library/installing-mariadb-on-macos-using-homebrew/)

安装完成后，转到其安装目录并查找 DLL 文件（MariaDB 的`libmariadb.dll`或 MySQL 的`libmysql.dll`）。对于 Linux 和 macOS，而不是 DLL，它是`libmariadb.so`或`libmysql.so`。

然后，将文件复制到应用程序的构建目录（与应用程序的可执行文件相同的文件夹）。之后，尝试再次运行您的应用程序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/b0d5c6d5-4a32-43f6-9050-27f519df0800.png)

如果您仍然收到`连接失败`的消息，但没有`QMYSQL driver not loaded`的消息，请检查您的 XAMPP 控制面板，并确保您的数据库服务正在运行；还要确保您在代码中输入的数据库名称、用户名和密码都是正确的信息。

接下来，我们可以开始尝试使用 SQL 命令！在`return a.exec()`之前添加以下代码：

```cpp
QString command = "SELECT name FROM department"; 
QSqlQuery query(db); 
if (query.exec(command)) 
{ 
   while(query.next()) 
   { 
         QString name = query.value("name").toString(); 
         qDebug() << name; 
   } 
} 
```

上述代码将命令文本发送到数据库，并同步等待来自服务器的结果返回。之后，使用`while`循环遍历每个结果并将其转换为字符串格式。然后，在控制台窗口上显示结果。如果一切顺利，您应该会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/1de75368-744f-4875-8829-37ac18d64e11.png)

让我们尝试一些更复杂的东西：

```cpp
QString command = "SELECT my_user.username, department.name AS deptname FROM (SELECT * FROM user WHERE status = 0) AS my_user INNER JOIN department ON department.id = my_user.deptID"; 
QSqlQuery query(db); 
if (query.exec(command)) 
{ 
   while(query.next()) 
   { 
         QString username = query.value("username").toString(); 
         QString department = query.value("deptname").toString(); 
         qDebug() << username << department; 
   } 
} 
```

这一次，我们使用**INNER JOIN**来合并两个表以选择`username`和`department`名称。为了避免关于名为`name`的变量的混淆，使用`AS`语句将其重命名为`deptname`。之后，在控制台窗口上显示`username`和`department`名称：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/8b7da1e9-561b-44b2-b239-72c4041f0ccd.png)

我们暂时完成了。让我们继续下一节，学习如何使我们的登录页面功能正常！

# 创建我们的功能性登录页面

既然我们已经学会了如何将我们的 Qt 应用程序连接到 MariaDB/MySQL 数据库系统，现在是时候继续在登录页面上继续工作了！在上一章中，我们学会了如何设置登录页面的 GUI。但是，它作为登录页面完全没有任何功能，因为它没有连接到数据库并验证登录凭据。因此，我们将学习如何通过赋予 Qt 的`sql`模块来实现这一点。

只是为了回顾一下——这就是登录界面的样子：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/cb136c81-3dfb-4e7b-83f5-61bb09344f75.png)

现在我们需要做的第一件事是为这个登录页面中重要的小部件命名，包括用户名输入、密码输入和提交按钮。您可以通过选择小部件并在属性编辑器中查找属性来设置这些属性：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/b729735b-5cfb-437d-9b48-f45a85d46314.png)

然后，将密码输入的 echoMode 设置为 Password。这个设置将通过用点替换密码来在视觉上隐藏密码：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/5a5a484f-a746-4be7-8841-08707e28016e.png)

之后，右键单击提交按钮，选择转到槽... 一个窗口将弹出并询问您要使用哪个信号。选择 clicked()，然后点击确定：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/aaf55004-4f8c-47b6-ba33-6aa31b5480b3.png)

一个名为`on_loginButton_clicked()`的新函数将自动添加到`MainWindow`类中。当用户按下提交按钮时，这个函数将被 Qt 触发，因此你只需要在这里编写代码来提交`username`和`password`以进行登录验证。信号和槽机制是 Qt 提供的一项特殊功能，用于对象之间的通信。当一个小部件发出信号时，另一个小部件将收到通知，并将继续运行特定的函数，该函数旨在对特定信号做出反应。

让我们来看看代码。

首先，在项目（.pro）文件中添加`sql`关键字：

`QT += core gui`

**sql**

然后，继续在`mainwindow.cpp`中添加相关的头文件：

```cpp
#ifndef MAINWINDOW_H 
#define MAINWINDOW_H 

#include <QMainWindow> 

#include <QtSql> 
#include <QSqlDatabase> 
#include <QSqlQuery> 
#include <QDebug> 
#include <QMessageBox> 
```

然后，回到`mainwindow.cpp`，在`on_loginButton_clicked()`函数中添加以下代码：

```cpp
void MainWindow::on_loginButton_clicked() 
{ 
   QString username = ui->userInput->text(); 
   QString password = ui->passwordInput->text(); 
   qDebug() << username << password; 
} 
```

现在，点击运行按钮，等待应用程序启动。然后，输入任意随机的`username`和`password`，然后点击提交按钮。您现在应该在 Qt Creator 的应用程序输出窗口中看到您的`username`和`password`被显示出来。

接下来，我们将把之前编写的 SQL 集成代码复制到`mainwindow.cpp`中：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 

   db = QSqlDatabase::addDatabase("QMYSQL"); 
   db.setHostName("127.0.0.1"); 
   db.setPort(3306); 
   db.setDatabaseName("test"); 
   db.setUserName("testuser"); 
   db.setPassword("testpass"); 

   if (db.open()) 
   { 
         qDebug() << "Connected!"; 
   } 
   else 
   { 
         qDebug() << "Failed to connect."; 
   } 
}
```

请注意，我在数据库名称、用户名和密码中使用了一些随机文本。请确保在这里输入正确的详细信息，并确保它们与您在数据库系统中设置的内容匹配。

我们对前面的代码做了一个小改动，就是我们只需要在`mainwindow.cpp`中调用`db = QSqlDatabase::addDatabase("QMYSQL")`，而不需要类名，因为声明`QSqlDatabase db`现在已经被移到了`mainwindow.h`中：

```cpp
private: 
   Ui::MainWindow *ui; 
 QSqlDatabase db; 
```

最后，我们添加了将`username`和`password`信息与 SQL 命令结合的代码，并将整个内容发送到数据库进行执行。如果有与登录信息匹配的结果，那么意味着登录成功，否则，意味着登录失败：

```cpp
void MainWindow::on_loginButton_clicked() 
{ 
   QString username = ui->userInput->text(); 
   QString password = ui->passwordInput->text(); 

   qDebug() << username << password; 

   QString command = "SELECT * FROM user WHERE username = '" + username 
   + "' AND password = '" + password + "' AND status = 0"; 
   QSqlQuery query(db); 
   if (query.exec(command)) 
   { 
         if (query.size() > 0) 
         { 
               QMessageBox::information(this, "Login success.", "You 
               have successfully logged in!"); 
         } 
         else 
         { 
               QMessageBox::information(this, "Login failed.", "Login 
               failed. Please try again..."); 
         } 
   } 
} 
```

再次点击运行按钮，看看当您点击提交按钮时会发生什么：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/a486dbd1-070a-42c9-9c64-9b6f274b0987.png)

万岁！登录页面现在已经完全可用！

# 摘要

在本章中，我们学习了如何设置数据库系统并使我们的 Qt 应用程序连接到它。在下一章中，我们将学习如何使用强大的 Qt 框架绘制图表和图表。


# 第四章：图表和图形

在上一章中，我们学习了如何使用 Qt 的`sql`模块从数据库中检索数据。有许多方法可以向用户呈现这些数据，例如以表格或图表的形式显示。在本章中，我们将学习如何进行后者——使用 Qt 的图表模块以不同类型的图表和图形呈现数据。

在本章中，我们将涵盖以下主题：

+   Qt 中的图表和图形类型

+   图表和图形实现

+   创建仪表板页面

自 Qt 5.7 以来，以前只有商业用户才能使用的几个模块已经免费提供给所有开源软件包用户，其中包括 Qt Charts 模块。因此，对于那些没有商业许可证的大多数 Qt 用户来说，这被认为是一个非常新的模块。

请注意，与大多数可在 LGPLv3 许可下使用的 Qt 模块不同，Qt Chart 模块是根据 GPLv3 许可提供的。与 LGPLv3 不同，GPLv3 许可要求您发布应用程序的源代码，同时您的应用程序也必须在 GPLv3 下获得许可。这意味着您不允许将 Qt Chart 与您的应用程序进行静态链接。它还阻止了该模块在专有软件中的使用。

要了解有关 GNU 许可的更多信息，请访问以下链接：[`www.gnu.org/licenses/gpl-faq.html.`](https://www.gnu.org/licenses/gpl-faq.html)

让我们开始吧！

# Qt 中的图表和图形类型

Qt 支持最常用的图表，并且甚至允许开发人员自定义它们的外观和感觉，以便可以用于许多不同的目的。Qt Charts 模块提供以下图表类型：

+   线性和样条线图

+   条形图

+   饼图

+   极坐标图

+   区域和散点图

+   箱形图

+   蜡烛图

# 线性和样条线图

第一种类型的图表是**线性和样条线图**。这些图表通常呈现为一系列通过线连接的点/标记。在线图中，点通过直线连接以显示变量随时间变化的情况。另一方面，样条线图与线图非常相似，只是点是通过样条线/曲线连接而不是直线：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/629caf81-65dc-4ade-bca7-c83446b9563a.png)

# 条形图

**条形图**是除线图和饼图之外最常用的图表之一。条形图与线图非常相似，只是它不沿轴连接数据。相反，条形图使用单独的矩形形状来显示其数据，其中其高度由数据的值决定。这意味着数值越高，矩形形状就会变得越高：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/da0e850e-1370-4f92-9b2f-59d6ff87010f.png)

# 饼图

**饼图**，顾名思义，是一种看起来像饼的图表类型。饼图以饼片的形式呈现数据。每个饼片的大小将由其值的整体百分比决定，与其余数据相比。因此，饼图通常用于显示分数、比率、百分比或一组数据的份额：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/bef47cfa-ec84-4d74-9a31-7fccac977da3.jpg)

有时，饼图也可以以甜甜圈形式显示（也称为甜甜圈图）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/21decb70-9994-4aa5-9201-0d617a5577f0.png)

# 极坐标图

**极坐标图**以圆形图表的形式呈现数据，其中数据的放置基于角度和距离中心的距离，这意味着数据值越高，点距离图表中心就越远。您可以在极坐标图中显示多种类型的图表，如线性、样条线、区域和散点图来可视化数据：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/12341292-4158-439e-a319-746511e60aab.png)

如果您是游戏玩家，您应该已经注意到在一些视频游戏中使用了这种类型的图表来显示游戏角色的属性：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/388b962c-afac-421e-afe0-076d47706e35.png)

# 区域和散点图

**面积图**将数据显示为面积或形状，以指示体积。通常用于比较两个或多个数据集之间的差异。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/fb091f5c-a7aa-4329-9faf-40f1f7e1ead0.png)

**散点图**，另一方面，用于显示一组数据点，并显示两个或多个数据集之间的非线性关系。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e2ce41e1-47a7-4fdf-832a-df1bc9b62b47.png)

# 箱线图

**箱线图**将数据呈现为四分位数，并延伸出显示值的变异性的须。箱子可能有垂直延伸的线，称为*须*。这些线表示四分位数之外的变异性，任何超出这些线或须的点都被视为异常值。箱线图最常用于统计分析，比如股票市场分析：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/bd88e23e-128d-4f49-828e-6e548e6f83ce.png)

# 蜡烛图

**蜡烛图**在视觉上与箱线图非常相似，只是用于表示开盘和收盘价之间的差异，同时通过不同的颜色显示值的方向（增加或减少）。如果特定数据的值保持不变，矩形形状将根本不会显示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/1b4c98ab-bbee-4f7f-8168-c054e28be15d.png)

有关 Qt 支持的不同类型图表的更多信息，请访问以下链接：[`doc.qt.io/qt-5/qtcharts-overview.html.`](https://doc.qt.io/qt-5/qtcharts-overview.html)

Qt 支持大多数你项目中需要的图表类型。在 Qt 中实现这些图表也非常容易。让我们看看如何做到！

# 实现图表和图形

Qt 通过将复杂的绘图算法放在不同的抽象层后面，使得绘制不同类型的图表变得容易，并为我们提供了一组类和函数，可以用来轻松创建这些图表，而不需要知道绘图算法在幕后是如何工作的。这些类和函数都包含在 Qt 的图表模块中。

让我们创建一个新的 Qt Widgets 应用程序项目，并尝试在 Qt 中创建我们的第一个图表。

创建新项目后，打开项目文件（.pro）并将`charts`模块添加到项目中，如下所示：

```cpp
QT += core gui charts 
```

然后，打开`mainwindow.h`并添加以下内容以包含使用`charts`模块所需的头文件：

```cpp
#include <QtCharts> 
#include <QChartView> 
#include <QBarSet> 
#include <QBarSeries> 
```

`QtCharts`和`QtChartView`头文件对于 Qt 的`charts`模块都是必不可少的。你必须包含它们两个才能让任何类型的图表正常工作。另外两个头文件，即`QBarSet`和`QBarSeries`，在这里被使用是因为我们将创建一个条形图。根据你想创建的图表类型不同，项目中包含的头文件也会有所不同。

接下来，打开`mainwindow.ui`并将垂直布局或水平布局拖到中央窗口部件。然后，选择中央窗口部件，点击水平布局或垂直布局。布局方向并不是特别重要，因为我们这里只会创建一个图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/4e4f032b-86fb-4548-a497-f60076f9a6d3.png)

之后，右键单击刚刚拖到中央窗口部件的布局部件，选择转换为 | QFrame。这将把布局部件更改为 QFrame 部件，同时保持其布局属性。如果从 Widget Box 创建 QFrame，它将没有我们需要的布局属性。这一步很重要，这样我们才能将其设置为稍后图表的父级：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/9ef83d89-2839-43c4-9537-cb34557dddec.png)

现在打开`mainwindow.cpp`并添加以下代码：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 

   QBarSet *set0 = new QBarSet("Jane"); 
   QBarSet *set1 = new QBarSet("John"); 
   QBarSet *set2 = new QBarSet("Axel"); 
   QBarSet *set3 = new QBarSet("Mary"); 
   QBarSet *set4 = new QBarSet("Samantha"); 

   *set0 << 10 << 20 << 30 << 40 << 50 << 60; 
   *set1 << 50 << 70 << 40 << 45 << 80 << 70; 
   *set2 << 30 << 50 << 80 << 13 << 80 << 50; 
   *set3 << 50 << 60 << 70 << 30 << 40 << 25; 
   *set4 << 90 << 70 << 50 << 30 << 16 << 42; 

   QBarSeries *series = new QBarSeries(); 
   series->append(set0); 
   series->append(set1); 
   series->append(set2); 
   series->append(set3); 
   series->append(set4); 
} 
```

上面的代码初始化了将显示在条形图中的所有类别。然后，我们还为每个类别添加了六个不同的数据项，这些数据项稍后将以条形/矩形形式表示。

`QBarSet`类表示条形图中的一组条形。它将几个条形组合成一个条形集，然后可以加标签。另一方面，`QBarSeries`表示按类别分组的一系列条形。换句话说，颜色相同的条形属于同一系列。

接下来，初始化`QChart`对象并将系列添加到其中。我们还设置了图表的标题并启用了动画：

```cpp
QChart *chart = new QChart(); 
chart->addSeries(series); 
chart->setTitle("Student Performance"); 
chart->setAnimationOptions(QChart::SeriesAnimations); 
```

之后，我们创建了一个条形图类别轴，并将其应用于条形图的*x*轴。我们使用了一个`QStringList`变量，类似于数组，但专门用于存储字符串。然后，`QBarCategoryAxis`将获取字符串列表并填充到*x*轴上：

```cpp
QStringList categories; 
categories << "Jan" << "Feb" << "Mar" << "Apr" << "May" << "Jun"; 
QBarCategoryAxis *axis = new QBarCategoryAxis(); 
axis->append(categories); 
chart->createDefaultAxes(); 
chart->setAxisX(axis, series); 
```

然后，我们为 Qt 创建一个图表视图来渲染条形图，并将其设置为主窗口中框架小部件的子级；否则，它将无法在主窗口上渲染：

```cpp
QChartView *chartView = new QChartView(chart); 
chartView->setParent(ui->verticalFrame); 
```

在 Qt Creator 中点击运行按钮，你应该会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/ca8c434b-348e-442c-83fc-d763be3e71c3.png)

接下来，让我们做一个饼图；这真的很容易。首先，我们包括`QPieSeries`和`QPieSlice`，而不是`QBarSet`和`QBarSeries`：

```cpp
#include <QPieSeries> 
#include <QPieSlice> 
```

然后，创建一个`QPieSeries`对象，并设置每个数据的名称和值。之后，将其中一个切片设置为不同的视觉样式，并使其脱颖而出。然后，创建一个`QChart`对象，并将其与我们创建的`QPieSeries`对象链接起来：

```cpp
QPieSeries *series = new QPieSeries(); 
series->append("Jane", 10); 
series->append("Joe", 20); 
series->append("Andy", 30); 
series->append("Barbara", 40); 
series->append("Jason", 50); 

QPieSlice *slice = series->slices().at(1); 
slice->setExploded(); // Explode this chart 
slice->setLabelVisible(); // Make label visible 
slice->setPen(QPen(Qt::darkGreen, 2)); // Set line color 
slice->setBrush(Qt::green); // Set slice color 

QChart *chart = new QChart(); 
chart->addSeries(series); 
chart->setTitle("Students Performance"); 
```

最后，创建`QChartView`对象，并将其与我们刚刚创建的`QChart`对象链接起来。然后，将其设置为框架小部件的子级，我们就可以开始了！

```cpp
QChartView *chartView = new QChartView(chart);
chartView->setParent(ui->verticalFrame);
```

现在按下运行按钮，你应该能看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/a5355056-5e99-4777-804c-117005d6848d.png)

有关如何在 Qt 中创建不同图表的更多示例，请查看以下链接的示例代码：[`doc.qt.io/qt-5/qtcharts-examples.html`](https://doc.qt.io/qt-5/qtcharts-examples.html)。

现在我们已经看到使用 Qt 创建图表和图形是很容易的，让我们扩展前几章开始的项目，并为其创建一个仪表板！

# 创建仪表板页面

在上一章中，我们创建了一个功能性的登录页面，允许用户使用他们的用户名和密码登录。接下来我们需要做的是创建仪表板页面，用户成功登录后将自动跳转到该页面。

仪表板页面通常用作用户快速了解其公司、业务、项目、资产和/或其他统计数据的概览。以下图片展示了仪表板页面可能的外观：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/00d8ae97-eb16-42e8-87b2-e6fc98288a8a.jpg)

正如你所看到的，仪表板页面使用了相当多的图表和图形，因为这是在不让用户感到不知所措的情况下显示大量数据的最佳方式。此外，图表和图形可以让用户轻松了解整体情况，而无需深入细节。

让我们打开之前的项目并打开`mainwindow.ui`文件。用户界面应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/d94821f7-5f65-4794-824b-f819318c9b22.png)

正如你所看到的，我们现在已经有了登录页面，但我们还需要添加另一个页面作为仪表板。为了让多个页面在同一个程序中共存，并能够随时在不同页面之间切换，Qt 为我们提供了一种叫做**QStackedWidget**的东西。

堆叠窗口就像一本书，你可以不断添加更多页面，但一次只显示一页。每一页都是完全不同的 GUI，因此不会干扰堆叠窗口中的其他页面。

由于之前的登录页面并不是为堆叠窗口而设计的，我们需要对其进行一些调整。首先，从小部件框中将堆叠窗口拖放到应用程序的中央小部件下，然后，我们需要将之前在中央小部件下的所有内容移动到堆叠窗口的第一页中，我们将其重命名为 loginPage：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/4e44e2d8-9594-4cea-88c6-970b2e7fb0b7.png)

接下来，将中央窗口部件的所有布局设置为`0`，这样它就完全没有边距，就像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/4870550e-3423-44cc-9e59-782f31959dd6.png)

在那之后，我们必须将中央窗口部件的样式表属性中的代码剪切，并粘贴到登录页面的样式表属性中。换句话说，背景图片、按钮样式和其他视觉设置现在只应用于登录页面。

完成后，切换页面时，你应该会得到两个完全不同的 GUI（仪表板页面目前为空）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/8c047da2-209c-4102-94c5-ac0e8ec76c60.png)

接下来，将网格布局拖放到仪表板页面，并将布局垂直应用到仪表板页面：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/ed2ed650-4139-46e9-99f8-f2375414f6f1.png)

在那之后，将六个垂直布局拖放到网格布局中，就像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/cc848c1e-1aa3-4a26-a6e1-966834507a66.png)

然后，选择我们刚刚添加到网格布局中的每个垂直布局，并将其转换为 QFrame：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/d5761610-be0c-4854-a859-603a27326ffc.png)

就像我们在图表实现示例中所做的那样，我们必须将布局转换为`QFrame`（或`QWidget`），以便我们可以将图表附加到它作为子对象。如果你直接从部件框中拖动`QFrame`并且不使用变形，那么`QFrame`对象就没有布局属性，因此图表可能无法调整大小以适应`QFrame`的几何形状。此外，将这些`QFrame`对象命名为`chart1`到`chart6`，因为我们将在接下来的步骤中需要它们。完成后，让我们继续编写代码。

首先，打开你的项目（`.pro`）文件，并添加`charts`模块，就像我们在本章的早期示例中所做的那样。然后，打开`mainwindow.h`并包含所有所需的头文件。这一次，我们还包括了用于创建折线图的`QLineSeries`头文件：

```cpp
#include <QtCharts> 
#include <QChartView> 

#include <QBarSet> 
#include <QBarSeries> 

#include <QPieSeries> 
#include <QPieSlice> 

#include <QLineSeries> 
```

在那之后，声明图表的指针，就像这样：

```cpp
QChartView *chartViewBar; 
QChartView *chartViewPie; 
QChartView *chartViewLine; 
```

然后，我们将添加创建柱状图的代码。这是我们之前在图表实现示例中创建的相同的柱状图，只是现在它附加到名为`chart1`的`QFrame`对象上，并在渲染时设置为启用*抗锯齿*。抗锯齿功能可以消除所有图表的锯齿状边缘，从而使渲染看起来更加平滑：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 

   ////////BAR CHART///////////// 
   QBarSet *set0 = new QBarSet("Jane"); 
   QBarSet *set1 = new QBarSet("John"); 
   QBarSet *set2 = new QBarSet("Axel"); 
   QBarSet *set3 = new QBarSet("Mary"); 
   QBarSet *set4 = new QBarSet("Samantha"); 

   *set0 << 10 << 20 << 30 << 40 << 50 << 60; 
   *set1 << 50 << 70 << 40 << 45 << 80 << 70; 
   *set2 << 30 << 50 << 80 << 13 << 80 << 50; 
   *set3 << 50 << 60 << 70 << 30 << 40 << 25; 
   *set4 << 90 << 70 << 50 << 30 << 16 << 42; 

   QBarSeries *seriesBar = new QBarSeries(); 
   seriesBar->append(set0); 
   seriesBar->append(set1); 
   seriesBar->append(set2); 
   seriesBar->append(set3); 
   seriesBar->append(set4); 

   QChart *chartBar = new QChart(); 
   chartBar->addSeries(seriesBar); 
   chartBar->setTitle("Students Performance"); 
   chartBar->setAnimationOptions(QChart::SeriesAnimations); 

   QStringList categories; 
   categories << "Jan" << "Feb" << "Mar" << "Apr" << "May" << "Jun"; 
   QBarCategoryAxis *axis = new QBarCategoryAxis(); 
   axis->append(categories); 
   chartBar->createDefaultAxes(); 
   chartBar->setAxisX(axis, seriesBar); 

   chartViewBar = new QChartView(chartBar); 
   chartViewBar->setRenderHint(QPainter::Antialiasing); 
   chartViewBar->setParent(ui->chart1); 
} 
```

接下来，我们还要添加饼图的代码。同样，这是来自先前示例的相同饼图：

```cpp
QPieSeries *seriesPie = new QPieSeries(); 
seriesPie->append("Jane", 10); 
seriesPie->append("Joe", 20); 
seriesPie->append("Andy", 30); 
seriesPie->append("Barbara", 40); 
seriesPie->append("Jason", 50); 

QPieSlice *slice = seriesPie->slices().at(1); 
slice->setExploded(); 
slice->setLabelVisible(); 
slice->setPen(QPen(Qt::darkGreen, 2)); 
slice->setBrush(Qt::green); 

QChart *chartPie = new QChart(); 
chartPie->addSeries(seriesPie); 
chartPie->setTitle("Students Performance"); 

chartViewPie = new QChartView(chartPie); 
chartViewPie->setRenderHint(QPainter::Antialiasing); 
chartViewPie->setParent(ui->chart2); 
```

最后，我们还向仪表板添加了一个折线图，这是新的内容。代码非常简单，非常类似于饼图：

```cpp
QLineSeries *seriesLine = new QLineSeries(); 
seriesLine->append(0, 6); 
seriesLine->append(2, 4); 
seriesLine->append(3, 8); 
seriesLine->append(7, 4); 
seriesLine->append(10, 5); 
seriesLine->append(11, 10); 
seriesLine->append(13, 3); 
seriesLine->append(17, 6); 
seriesLine->append(18, 3); 
seriesLine->append(20, 2); 

QChart *chartLine = new QChart(); 
chartLine->addSeries(seriesLine); 
chartLine->createDefaultAxes(); 
chartLine->setTitle("Students Performance"); 

chartViewLine = new QChartView(chartLine); 
chartViewLine->setRenderHint(QPainter::Antialiasing); 
chartViewLine->setParent(ui->chart3); 
```

完成后，我们必须为主窗口类添加一个 resize-event 槽，并在主窗口调整大小时使图表跟随其各自父级的大小。首先，进入`mainwindow.h`并添加事件处理程序声明：

```cpp
protected: 
   void resizeEvent(QResizeEvent* event); 
```

然后，打开`mainwindow.cpp`并添加以下代码：

```cpp
void MainWindow::resizeEvent(QResizeEvent* event) 
{ 
   QMainWindow::resizeEvent(event); 

   chartViewBar->resize(chartViewBar->parentWidget()->size()); 
   chartViewPie->resize(chartViewPie->parentWidget()->size()); 
   chartViewLine->resize(chartViewLine->parentWidget()->size()); 
} 
```

请注意，必须首先调用`QMainWindow::resizeEvent(event)`，以便在调用自定义方法之前触发默认行为。`resizeEvent()`是 Qt 提供的许多事件处理程序之一，用于对其事件做出反应，例如鼠标事件、窗口事件、绘制事件等。与信号和槽机制不同，你需要替换事件处理程序的虚函数，以使其在调用事件时执行你想要的操作。

如果我们现在构建并运行项目，应该会得到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/2a440a24-0d6a-4d47-b54b-a50aee5eaffc.png)

看起来相当整洁，不是吗！然而，为了简单起见，也为了不让读者感到困惑，图表都是硬编码的，并且没有使用来自数据库的任何数据。如果你打算使用来自数据库的数据，在程序启动时不要进行任何 SQL 查询，因为如果你加载的数据非常大，或者你的服务器非常慢，这将使你的程序冻结。

最好的方法是只在从登录页面切换到仪表板页面（或切换到任何其他页面时）加载数据，以便加载时间对用户不太明显。要做到这一点，右键单击堆叠窗口，然后选择转到槽。然后，选择 currentChanged(int)并单击确定。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/531baa65-d083-4a70-a57c-aeff6def670a.png)

之后，Qt 会自动创建一个新的槽函数。当堆叠窗口在页面之间切换时，此函数将自动调用。您可以通过检查`arg1`变量来查看它当前切换到的页面。如果目标页面是堆叠窗口中的第一页，则`arg1`的值将为`0`，如果目标是第二页，则为`1`，依此类推。

只有在堆叠窗口显示仪表板页面时，才能提交 SQL 查询，这是第二页（`arg1`等于`1`）：

```cpp
void MainWindow::on_stackedWidget_currentChanged(int arg1) 
{ 
   if (arg1 == 1) 
   { 
      // Do it here 
   } 
} 
```

哎呀！这一章内容真是太多了！希望这一章能帮助您了解如何为您的项目创建一个美丽而丰富的页面。

# 摘要

Qt 中的图表模块是功能和视觉美学的结合。它不仅易于实现，而且无需编写非常长的代码来显示图表，而且还可以根据您的视觉要求进行定制。我们真的需要感谢 Qt 开发人员开放了这个模块，并允许非商业用户免费使用它！

在本章中，我们学习了如何使用 Qt 图表模块创建一个真正漂亮的仪表板，并在其上显示不同类型的图表。在接下来的章节中，我们将学习如何使用视图部件、对话框和文件选择对话框。


# 第五章：项目视图和对话框

在上一章中，我们学习了如何使用不同类型的图表显示数据。图表是向用户在屏幕上呈现信息的许多方式之一。对于您的应用程序来说，向用户呈现重要信息非常重要，这样他们就可以准确地了解应用程序的情况——无论数据是否已成功保存，或者应用程序正在等待用户的输入，或者用户应该注意的警告/错误消息等等——这些都非常重要，以确保您的应用程序的用户友好性和可用性。

在本章中，我们将涵盖以下主题：

+   使用项目视图部件

+   使用对话框

+   使用文件选择对话框

+   图像缩放和裁剪

Qt 为我们提供了许多类型的部件和对话框，我们可以轻松使用它们来向用户显示重要信息。让我们看看这些部件是什么！

# 使用项目视图部件

除了使用不同类型的图表显示数据外，我们还可以使用不同类型的项目视图来显示这些数据。项目视图部件通过在垂直轴上呈现数据来将数据可视化呈现。

二维项目视图，通常称为**表视图**，在垂直和水平方向上显示数据。这使它能够在紧凑的空间内显示大量数据，并使用户能够快速轻松地搜索项目。

在项目视图中显示数据有两种方法。最常见的方法是使用**模型-视图架构**，它使用三个不同的组件，模型、视图和委托，从数据源检索数据并在项目视图中显示它。这些组件都利用 Qt 提供的**信号-槽架构**来相互通信：

+   模型的信号通知视图有关数据源保存的数据的更改

+   视图的信号提供有关用户与正在显示的项目的交互的信息

+   委托的信号在编辑期间用于告诉模型和视图有关编辑器状态的信息

另一种方法是手动方式，程序员必须告诉 Qt 哪些数据放在哪一列和行。与模型-视图相比，这种方法要简单得多，但在性能上要慢得多。然而，对于少量数据，性能问题可以忽略不计，这是一个很好的方法。

如果您打开 Qt Designer，您将看到两种不同的项目视图部件类别，即项目视图（基于模型）和项目部件（基于项目）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/6f63f909-cc29-4299-baf3-b34e7655cf7d.png)

尽管它们看起来可能相同，但实际上这两个类别中的部件工作方式非常不同。在本章中，我们将学习如何使用后一类别，因为它更直观、易于理解，并且可以作为前一类别的先决知识。

在项目部件（基于项目）类别下有三种不同的部件，称为列表部件、树部件和表部件。每个项目部件以不同的方式显示数据。选择适合您需求的部件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/a50b4415-472d-4c74-b1e1-f735f0a5bd21.png)

正如您从前面的图表中所看到的，**列表部件**以一维列表显示其项目，而**表部件**以二维表格显示其项目。尽管**树部件**几乎与**列表部件**类似，但其项目以分层结构显示，其中每个项目下可以递归地有多个子项目。一个很好的例子是我们操作系统中的文件系统，它使用树部件显示目录结构。

为了说明这些区别，让我们创建一个新的 Qt Widgets 应用程序项目，并自己试一试。

# 创建我们的 Qt Widgets 应用程序

创建项目后，打开`mainwindow.ui`并将三种不同的项目小部件拖到主窗口中。之后，选择主窗口并点击位于顶部的垂直布局按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e0e15392-5def-4f64-accd-075c8e6d2778.png)

然后，双击列表小部件，将弹出一个新窗口。在这里，您可以通过单击+图标向列表小部件添加一些虚拟项目，或者通过选择列表中的项目并单击-图标来删除它们。单击“确定”按钮将最终结果应用于小部件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/4a126e2c-2059-4faf-a325-fafa3b81ce9d.png)

您可以对树形小部件执行相同的操作。它几乎与列表小部件相同，只是您可以向项目添加子项目，递归地。您还可以向树形小部件添加列并命名这些列：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/486ef112-0666-4f94-a753-eac1472c352e.png)

最后，双击表格小部件以打开编辑表格小部件窗口。与其他两个项目视图不同，表格小部件是一个二维项目视图，这意味着您可以像电子表格一样向其添加列和行。可以通过在“列”或“行”选项卡中设置所需的名称来为每列和行加标签：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/c3e07ba3-fb5c-4017-90db-caf9edae65e1.png)

通过使用 Qt Designer，了解小部件的工作原理非常容易。只需将小部件拖放到窗口中并调整其设置，然后构建并运行项目以查看结果。

在这种情况下，我们已经演示了三种不同的项目视图小部件之间的区别，而不需要编写一行代码：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/cb94f990-0b6d-435e-8bea-c09205c56bf3.png)

# 使我们的列表小部件功能化

然而，为了使小部件在应用程序中完全可用，仍然需要编写代码。让我们学习如何使用 C++代码向我们的项目视图小部件添加项目！

首先，打开`mainwindow.cpp`并在`ui->setupui(this)`之后的类构造函数中编写以下代码：

```cpp
ui->listWidget->addItem("My Test Item"); 
```

就这么简单，您已成功向列表小部件添加了一个项目！

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/2f54393e-6a48-42c9-90c3-0d36ae463ad2.png)

还有另一种方法可以向列表小部件添加项目。但在此之前，我们必须向`mainwindow.h`添加以下头文件：

```cpp
#ifndef MAINWINDOW_H 
#define MAINWINDOW_H 

#include <QMainWindow> 
#include <QDebug> 
#include <QListWidgetItem> 
```

`QDebug`头文件用于打印调试消息，`QListWidgetItem`头文件用于声明列表小部件的项目对象。接下来，打开`mainwindow.cpp`并添加以下代码：

```cpp
QListWidgetItem* listItem = new QListWidgetItem; 
listItem->setText("My Second Item"); 
listItem->setData(100, 1000); 
ui->listWidget->addItem(listItem); 
```

前面的代码与前一个一行代码相同。不同的是，这次我向项目添加了额外的数据。`setData()`函数接受两个输入变量——第一个变量是项目的数据角色，指示 Qt 应如何处理它。如果放入与`Qt::ItemDataRole`枚举器匹配的值，数据将影响显示、装饰、工具提示等，这可能会改变其外观。

在我的情况下，我只是简单地设置了一个与`Qt::ItemDataRole`中的任何枚举器都不匹配的数字，以便我可以将其存储为以后使用的隐藏数据。要检索数据，您只需调用`data()`并插入与您刚刚设置的数字匹配的数字：

```cpp
qDebug() << listItem->data(100); 
```

构建并运行项目；您应该能够看到新项目现在已添加到列表小部件中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/bf13b2e0-4637-4f30-a7c4-2c79b541baad.png)

有关`Qt::ItemDataRole`枚举器的更多信息，请查看以下链接：[`doc.qt.io/qt-5/qt.html#ItemDataRole-enum`](http://doc.qt.io/qt-5/qt.html#ItemDataRole-enum)

如前所述，可以将隐藏数据附加到列表项目以供以后使用。例如，您可以使用列表小部件显示准备由用户购买的产品列表。每个项目都可以附加其产品 ID，以便当用户选择该项目并将其放入购物车时，您的系统可以自动识别已添加到购物车的产品 ID 作为数据角色存储。 

在上面的例子中，我在我的列表项中存储了自定义数据`1000`，并将其数据角色设置为`100`，这与任何`Qt::ItemDataRole`枚举器都不匹配。这样，数据就不会显示给用户，因此只能通过 C++代码检索。

# 向树部件添加功能

接下来，让我们转到树部件。实际上，它与列表部件并没有太大的不同。让我们看一下以下代码：

```cpp
QTreeWidgetItem* treeItem = new QTreeWidgetItem; 
treeItem->setText(0, "My Test Item"); 
ui->treeWidget->addTopLevelItem(treeItem); 
```

它与列表部件几乎相同，只是我们必须在`setText()`函数中设置列 ID。这是因为树部件介于列表部件和表部件之间——它可以有多个列，但不能有任何行。

树部件与其他视图部件最明显的区别是，所有的项都可以递归地包含子项。让我们看一下以下代码，看看我们如何向树部件中的现有项添加子项：

```cpp
QTreeWidgetItem* treeItem2 = new QTreeWidgetItem; 
treeItem2->setText(0, "My Test Subitem"); 
treeItem->addChild(treeItem2); 
```

就是这么简单！最终结果看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/3580d596-4c97-4c34-9699-f54ddf816393.png)

# 最后，我们的表部件

接下来，让我们对表部件做同样的操作。从技术上讲，当列和行被创建时，表部件中的项已经存在并被保留。我们需要做的是创建一个新项，并用特定列和行的（当前为空的）项替换它，这就是为什么函数名叫做`setItem()`，而不是列表部件使用的`addItem()`。

让我们看一下代码：

```cpp
QTableWidgetItem* tableItem = new QTableWidgetItem; 
tableItem->setText("Testing1"); 
ui->tableWidget->setItem(0, 0, tableItem); 

QTableWidgetItem* tableItem2 = new QTableWidgetItem; 
tableItem2->setText("Testing2"); 
ui->tableWidget->setItem(1, 2, tableItem2); 
```

从代码中可以看出，我在两个不同的位置添加了两个数据部分，这将转化为以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/05cecb5e-908c-4668-8afa-dde23dae413d.png)

就是这样！使用 Qt 中的项视图来显示数据是如此简单和容易。如果你正在寻找与项视图相关的更多示例，请访问以下链接：[`doc.qt.io/qt-5/examples-itemviews.html`](http://doc.qt.io/qt-5/examples-itemviews.html)

# 使用对话框

创建用户友好的应用程序的一个非常重要的方面是，在发生某个事件（有意或无意）时，能够显示关于应用程序状态的重要信息。为了显示这样的信息，我们需要一个外部窗口，用户可以在确认信息后将其关闭。

Qt 具有这个功能，它全部驻留在`QMessageBox`类中。在 Qt 中，你可以使用几种类型的消息框；最基本的一种只需要一行代码，就像这样：

```cpp
QMessageBox::information(this, "Alert", "Just to let you know, something happened!"); 
```

对于这个函数，你需要提供三个参数。第一个是消息框的父窗口，我们已经将其设置为主窗口。第二个参数是窗口标题，第三个参数是我们想要传递给用户的消息。上述代码将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/2b92e3f2-4363-46db-aa12-afc721e665e8.png)

这里显示的外观是在 Windows 系统上运行的。在不同的操作系统（Linux、macOS 等）上，外观可能会有所不同。正如你所看到的，对话框甚至带有文本之前的图标。你可以使用几种类型的图标，比如信息、警告和严重。以下代码向你展示了调用带有图标的不同消息框的代码：

```cpp
QMessageBox::question(this, "Alert", "Just to let you know, something happened!"); 
QMessageBox::warning(this, "Alert", "Just to let you know, something happened!"); 
QMessageBox::information(this, "Alert", "Just to let you know, something happened!"); 
QMessageBox::critical(this, "Alert", "Just to let you know, something happened!"); 
```

上述代码产生以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/84024277-2f97-4651-b89e-b3a4e9528f8a.png)

如果你不需要任何图标，只需调用`QMessageBox::about()`函数。你还可以通过从 Qt 提供的标准按钮列表中选择来设置你想要的按钮，例如：

```cpp
QMessageBox::question(this, "Serious Question", "Am I an awesome guy?", QMessageBox::Ignore, QMessageBox::Yes); 
```

上述代码将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e95537ee-6b14-4da6-9e38-af1eaaf6fda3.png)

由于这些是 Qt 提供的内置函数，用于轻松创建消息框，它不会给开发人员完全自定义消息框的自由。但是，Qt 允许您使用另一种方法手动创建消息框，这种方法比内置方法更可定制。这需要更多的代码行，但编写起来仍然相当简单：

```cpp
QMessageBox msgBox; 
msgBox.setWindowTitle("Alert"); 
msgBox.setText("Just to let you know, something happened!"); 
msgBox.exec(); 
```

上述代码将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/f79a9076-7112-4fa4-bed4-5bc3b9bc5628.png)

“看起来完全一样”，你告诉我。那么添加我们自己的图标和自定义按钮呢？这没有问题：

```cpp
QMessageBox msgBox; 
msgBox.setWindowTitle("Serious Question"); 
msgBox.setText("Am I an awesome guy?"); 
msgBox.addButton("Seriously Yes!", QMessageBox::YesRole); 
msgBox.addButton("Well no thanks", QMessageBox::NoRole); 
msgBox.setIcon(QMessageBox::Question); 
msgBox.exec(); 
```

上述代码产生以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/04e2e8f6-5139-4bfb-aced-564cedaf5d2d.png)

在上面的代码示例中，我已经加载了 Qt 提供的问题图标，但如果您打算这样做，您也可以从资源文件中加载自己的图标：

```cpp
QMessageBox msgBox; 
msgBox.setWindowTitle("Serious Question"); 
msgBox.setText("Am I an awesome guy?"); 
msgBox.addButton("Seriously Yes!", QMessageBox::YesRole); 
msgBox.addButton("Well no thanks", QMessageBox::NoRole); 
QPixmap myIcon(":/images/icon.png"); 
msgBox.setIconPixmap(myIcon); 
msgBox.exec(); 
```

现在构建并运行项目，您应该能够看到这个奇妙的消息框：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/ce170a25-75c4-448e-ab26-b82691eda029.png)

一旦您了解了如何创建自己的消息框，让我们继续学习消息框附带的事件系统。

当用户被呈现具有多个不同选择的消息框时，他/她会期望在按下不同按钮时应用程序有不同的反应。

例如，当消息框弹出并询问用户是否希望退出程序时，按钮“是”应该使程序终止，而“否”按钮将不起作用。

Qt 的`QMessageBox`类为我们提供了一个简单的解决方案来检查按钮事件。当消息框被创建时，Qt 将等待用户选择他们的选择；然后，它将返回被触发的按钮。通过检查哪个按钮被点击，开发人员可以继续触发相关事件。让我们看一下示例代码：

```cpp
if (QMessageBox::question(this, "Question", "Some random question. Yes or no?") == QMessageBox::Yes) 
{ 
   QMessageBox::warning(this, "Yes", "You have pressed Yes!"); 
} 
else 
{ 
   QMessageBox::warning(this, "No", "You have pressed No!"); 
} 
```

上述代码将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/4ec73206-502c-4051-aa2a-ba175f839f16.png)

如果您更喜欢手动创建消息框，检查按钮事件的代码会稍微长一些：

```cpp
QMessageBox msgBox; 
msgBox.setWindowTitle("Serious Question"); 
msgBox.setText("Am I an awesome guy?"); 
QPushButton* yesButton = msgBox.addButton("Seriously Yes!", QMessageBox::YesRole); 
QPushButton* noButton = msgBox.addButton("Well no thanks", QMessageBox::NoRole); 
msgBox.setIcon(QMessageBox::Question); 
msgBox.exec(); 

if (msgBox.clickedButton() == (QAbstractButton*) yesButton) 
{ 
   QMessageBox::warning(this, "Yes", "Oh thanks! :)"); 
} 
else if (msgBox.clickedButton() == (QAbstractButton*) noButton) 
{ 
   QMessageBox::warning(this, "No", "Oh why... :("); 
} 
```

尽管代码稍微长一些，但基本概念基本相同——被点击的按钮始终可以被开发人员检索以触发适当的操作。然而，这次，Qt 直接检查按钮指针，而不是检查枚举器，因为前面的代码没有使用`QMessageBox`类的内置标准按钮。

构建项目，您应该能够获得以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/9c49eca5-6076-4609-9e1c-e3f2e7a1a762.png)

有关对话框的更多信息，请访问以下链接的 API 文档：[`doc.qt.io/qt-5/qdialog.html`](http://doc.qt.io/qt-5/qdialog.html)

# 创建文件选择对话框

既然我们已经讨论了消息框的主题，让我们也了解一下另一种类型的对话框——文件选择对话框。文件选择对话框也非常有用，特别是如果您的应用程序经常处理文件。要求用户输入他们想要打开的文件的绝对路径是非常不愉快的，因此文件选择对话框在这种情况下非常方便。

Qt 为我们提供了一个内置的文件选择对话框，看起来与我们在操作系统中看到的一样，因此，对用户来说并不陌生。文件选择对话框本质上只做一件事——让用户选择他们想要的文件或文件夹，并返回所选文件或文件夹的路径；就这些。实际上，它不负责打开文件和读取其内容。

让我们看看如何触发文件选择对话框。首先，打开`mainwindow.h`并添加以下头文件：

```cpp
#ifndef MAINWINDOW_H 
#define MAINWINDOW_H 

#include <QMainWindow> 
#include <QFileDialog> 
#include <QDebug> 
```

接下来，打开`mainwindow.cpp`并插入以下代码：

```cpp
QString fileName = QFileDialog::getOpenFileName(this); 
qDebug() << fileName; 
```

就是这么简单！现在构建并运行项目，您应该会得到这个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/cb0d3f1e-1e61-4d02-b280-9a4935ead609.png)

如果用户选择了文件并按下打开，`fileName` 变量将填充为所选文件的绝对路径。如果用户单击取消按钮，`fileName` 变量将为空字符串。

文件选择对话框在初始化步骤中还包含几个可以设置的选项。例如：

```cpp
QString fileName = QFileDialog::getOpenFileName(this, "Your title", QDir::currentPath(), "All files (*.*) ;; Document files (*.doc *.rtf);; PNG files (*.png)"); 
qDebug() << fileName; 
```

在前面的代码中，我们设置了三件事，它们如下：

+   文件选择对话框的窗口标题

+   对话框创建时用户看到的默认路径

+   文件类型过滤

文件类型过滤在您只允许用户选择特定类型的文件时非常方便（例如，仅允许 JPEG 图像文件），并隐藏其他文件。除了 `getOpenFileName()`，您还可以使用 `getSaveFileName()`，它将允许用户指定尚不存在的文件名。

有关文件选择对话框的更多信息，请访问以下链接的 API 文档：[`doc.qt.io/qt-5/qfiledialog.html`](http://doc.qt.io/qt-5/qfiledialog.html)

# 图像缩放和裁剪

由于我们在上一节中学习了文件选择对话框，我想这次我们应该学习一些有趣的东西！

首先，让我们创建一个新的 Qt Widgets 应用程序。然后，打开 `mainwindow.ui` 并创建以下用户界面：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/867c3332-9f87-40c0-933b-05190c15dd8e.png)

让我们将这个用户界面分解成三个部分：

+   顶部—图像预览：

+   首先，在窗口中添加一个水平布局。

+   然后，将一个标签小部件添加到我们刚刚添加的水平布局中，然后将文本属性设置为 `empty`。将标签的 minimumSize 和 maximumSize 属性都设置为 150x150。最后，在 QFrame 类别下设置 frameShape 属性为 Box。

+   在标签的两侧添加两个水平间隔器，使其居中。

+   中部—用于调整的滑块：

+   在窗口中添加一个表单布局，放在我们在步骤 1 中刚刚添加的水平布局下方。

+   将三个标签添加到表单布局中，并将它们的文本属性分别设置为 `比例：`、`水平：` 和 `垂直：`。

+   将三个水平滑块添加到表单布局中。将最小属性设置为 `1`，最大属性设置为 `100`。然后，将 pageStep 属性设置为 `1`。

+   将比例滑块的值属性设置为 `100`。

+   底部—浏览按钮和保存按钮：

+   在窗口中添加一个水平布局，放在我们在步骤 2 中添加的表单布局下方。

+   将两个按钮添加到水平布局中，并将它们的文本属性分别设置为 `浏览` 和 `保存`。

+   +   最后，从中央小部件中删除菜单栏、工具栏和状态栏。

现在我们已经创建了用户界面，让我们开始编码吧！首先，打开 `mainwindow.h` 并添加以下头文件：

```cpp
#ifndef MAINWINDOW_H 
#define MAINWINDOW_H 

#include <QMainWindow> 
#include <QMessageBox> 
#include <QFileDialog> 
#include <QPainter> 
```

然后，将以下变量添加到 `mainwindow.h`：

```cpp
private: 
   Ui::MainWindow *ui; 
   bool canDraw; 
   QPixmap* pix; 
   QSize imageSize; 
   QSize drawSize; 
   QPoint drawPos; 
```

然后，返回到 `mainwindow.ui`，右键单击浏览按钮，然后选择转到槽。然后，一个窗口将弹出并要求您选择一个信号。选择位于列表顶部的 `clicked()` 信号，然后按下 OK 按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e63f85a0-57c5-4097-a3aa-ddba2adc9e17.png)

在您的源文件中将自动添加一个新的 `slot` 函数。现在，添加以下代码以在单击浏览按钮时打开文件选择对话框。对话框仅列出 JPEG 图像并隐藏其他文件：

```cpp
void MainWindow::on_browseButton_clicked() 
{ 
   QString fileName = QFileDialog::getOpenFileName(this, tr("Open   
   Image"), QDir::currentPath(), tr("Image Files (*.jpg *.jpeg)")); 

   if (!fileName.isEmpty()) 
   { 
         QPixmap* newPix = new QPixmap(fileName); 

         if (!newPix->isNull()) 
         { 
               if (newPix->width() < 150 || newPix->height() < 150) 
               { 
                     QMessageBox::warning(this, tr("Invalid Size"), 
                     tr("Image size too small. Please use an image  
                     larger than 150x150.")); 
                     return; 
               } 

               pix = newPix; 
               imageSize = pix->size(); 
               drawSize = pix->size(); 

               canDraw = true; 

         } 
         else 
         { 
               canDraw = false; 

               QMessageBox::warning(this, tr("Invalid Image"), 
               tr("Invalid or corrupted file. Please try again with  
               another image file.")); 
         } 
   } 
} 
```

如您所见，代码检查用户是否选择了任何图像。如果选择了图像，它会再次检查图像分辨率是否至少为 150 x 150。如果没有问题，我们将保存图像的像素映射到名为 `pix` 的指针中，然后将图像大小保存到 `imageSize` 变量中，并将初始绘图大小保存到 `drawSize` 变量中。最后，我们将 `canDraw` 变量设置为 `true`。

之后，再次打开 `mainwindow.h` 并声明以下两个函数：

```cpp
public: 
   explicit MainWindow(QWidget *parent = 0); 
   ~MainWindow(); 
   virtual void paintEvent(QPaintEvent *event); 
   void paintImage(QString fileName, int x, int y); 
```

第一个函数`paintEvent()`是一个虚函数，每当 Qt 需要刷新用户界面时（例如当主窗口被调整大小时），它就会自动调用。我们将重写这个函数，并将新加载的图像绘制到图像预览部件上。在这种情况下，我们将在`paintEvent()`虚函数中调用`paintImage()`函数：

```cpp
void MainWindow::paintEvent(QPaintEvent *event) 
{ 
   if (canDraw) 
   { 
         paintImage("", ui->productImage->pos().x(), ui->productImage-
         >pos().y()); 
   } 
} 
```

之后，我们将在`mainwindow.cpp`中编写`paintImage()`函数：

```cpp
void MainWindow::paintImage(QString fileName, int x, int y) 
{ 
   QPainter painter; 
   QImage saveImage(150, 150, QImage::Format_RGB16); 

   if (!fileName.isEmpty()) 
   { 
         painter.begin(&saveImage); 
   } 
   else 
   { 
         painter.begin(this); 
   } 

   if (!pix->isNull()) 
   { 
         painter.setClipRect(x, y, 150, 150); 
         painter.fillRect(QRect(x, y, 150, 150), Qt::SolidPattern); 
         painter.drawPixmap(x - drawPos.x(), y - drawPos.y(), 
         drawSize.width(), drawSize.height(), *pix); 
   } 

   painter.end(); 

   if (fileName != "") 
   { 
         saveImage.save(fileName); 
         QMessageBox::information(this, "Success", "Image has been 
         successfully saved!"); 
   } 
} 
```

此函数有两个作用——如果我们不设置`fileName`变量，它将继续在图像预览部件上绘制图像，否则，它将根据图像预览部件的尺寸裁剪图像，并根据`fileName`变量将其保存到磁盘上。

当单击保存按钮时，我们将再次调用此函数。这次，我们将设置`fileName`变量为所需的目录路径和文件名，以便`QPainter`类可以正确保存图像：

```cpp
void MainWindow::on_saveButton_clicked() 
{ 
   if (canDraw) 
   { 
         if (!pix->isNull()) 
         { 
               // Save new pic from painter 
               paintImage(QCoreApplication::applicationDirPath() + 
               "/image.jpg", 0, 0); 
         } 
   } 
} 
```

最后，右键单击三个滑块中的每一个，然后选择“转到槽”。然后，选择`valueChanged(int)`并单击“确定”。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/b605edff-3b8d-4ce0-9661-b08ae23bbb5d.png)

之后，我们将编写从上一步骤中得到的`slot`函数的代码：

```cpp
void MainWindow::on_scaleSlider_valueChanged(int value) 
{ 
   drawSize = imageSize * value / 100; 
   update(); 
} 

void MainWindow::on_leftSlider_valueChanged(int value) 
{ 
   drawPos.setX(value * drawSize.width() / 100 * 0.5); 
   update(); 
} 

void MainWindow::on_topSlider_valueChanged(int value) 
{ 
   drawPos.setY(value * drawSize.height() / 100 * 0.5); 
   update(); 
} 
```

比例滑块基本上是供用户在图像预览部件内调整所需比例的。左侧滑块是供用户水平移动图像的，而顶部滑块是供用户垂直移动图像的。通过组合这三个不同的滑块，用户可以在将图像上传到服务器之前，或者用于其他目的之前，调整和裁剪图像以满足他们的喜好。

如果您现在构建并运行项目，您应该能够获得以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/2b7d67e4-2cc1-434a-87b7-8e09130c019a.png)

您可以单击“浏览”按钮选择要加载的 JPG 图像文件。之后，图像应该会出现在预览区域。然后，您可以移动滑块来调整裁剪大小。一旦您对结果满意，点击“保存”按钮将图像保存在当前目录中。

如果您想详细了解，请查看本书附带的示例代码。您可以在以下 GitHub 页面找到源代码：[`github.com/PacktPublishing/Hands-On-GUI-Programming-with-C-QT5`](https://github.com/PacktPublishing/Hands-On-GUI-Programming-with-C-QT5)

# 摘要

**输入和输出（I/O）**是现代计算机软件的本质。Qt 允许我们以许多直观和引人入胜的方式显示我们的数据给最终用户。除此之外，Qt 提供的事件系统使得作为程序员的我们的生活变得更加轻松，因为它倾向于通过强大的信号和槽机制自动捕获用户输入，并触发自定义行为。没有 Qt，我们将很难想出如何重新发明这个老生常谈的轮子，并最终可能会创建一个不太用户友好的产品。

在本章中，我们学习了如何利用 Qt 提供的出色功能——视图部件、对话框和文件选择对话框，用于向用户显示重要信息。此外，我们还通过一个有趣的小项目学习了如何使用 Qt 部件对用户输入进行缩放和裁剪图像。在下一章中，我们将尝试更高级（也更有趣）的内容，即使用 Qt 创建我们自己的网络浏览器！
