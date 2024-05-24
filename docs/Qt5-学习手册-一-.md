# Qt5 学习手册（一）

> 原文：[`annas-archive.org/md5/9fdbc9f976587acda3d186af05c73879`](https://annas-archive.org/md5/9fdbc9f976587acda3d186af05c73879)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Qt 是一个成熟而强大的框架，可在多种平台上交付复杂的应用程序。它在嵌入式设备中被广泛使用，包括电视、卫星机顶盒、医疗设备、汽车仪表板等。它在 Linux 世界中也有丰富的历史，KDE 和 Sailfish OS 广泛使用它，许多应用程序也是使用 Qt 开发的。在过去几年中，它在移动领域也取得了巨大进展。然而，在 Microsoft Windows 和 Apple macOS X 世界中，C#/.NET 和 Objective-C/Cocoa 的主导地位意味着 Qt 经常被忽视。

本书旨在展示 Qt 框架的强大和灵活性，并展示如何编写应用程序一次并将其部署到多个操作系统的桌面。读者将从头开始构建一个完整的现实世界**业务线**（**LOB**）解决方案，包括独立的库、用户界面和单元测试项目。

我们将使用 QML 构建现代和响应式的用户界面，并将其连接到丰富的 C++类。我们将使用 QMake 控制项目配置和输出的每个方面，包括平台检测和条件表达式。我们将构建“自我意识”的数据实体，它们可以将自己序列化到 JSON 并从中反序列化。我们将在数据库中持久化这些数据实体，并学习如何查找和更新它们。我们将访问互联网并消费 RSS 源。最后，我们将生成一个安装包，以便将我们的应用部署到其他机器上。

这是一套涵盖大多数 LOB 应用程序核心要求的基本技术，将使读者能够从空白页面到已部署应用程序的进程。

# 本书的受众

本书面向寻找在 Microsoft Windows、Apple Mac OS X 和 Linux 桌面平台上创建现代和响应式应用程序的强大而灵活的框架的应用程序开发人员。虽然专注于桌面应用程序开发，但所讨论的技术在移动开发中也大多适用。

# 充分利用本书

读者应该熟悉 C++，但不需要先前了解 Qt 或 QML。在 Mac OS X 上，您需要安装 XCode 并至少启动一次。在 Windows 上，您可以选择安装 Visual Studio 以便使用 MSVC 编译器。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的以下工具解压或提取文件夹：

+   Windows 需要 WinRAR/7-Zip

+   Mac 需要 Zipeg/iZip/UnRarX

+   Linux 需要 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Learn-Qt-5`](https://github.com/PacktPublishing/Learn-Qt-5)。我们还有其他书籍和视频的代码包可供下载，网址为**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。请查看！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“在`cm-ui/ui/views`中创建`SplashView.qml`文件”。

代码块设置如下：

```cpp
<RCC>
    <qresource prefix="/views">
        <file alias="MasterView">views/MasterView.qml</file>
    </qresource>
    <qresource prefix="/">
        <file>views/SplashView.qml</file>
        <file>views/DashboardView.qml</file>
        <file>views/CreateClientView.qml</file>
        <file>views/EditClientView.qml</file>
        <file>views/FindClientView.qml</file>
    </qresource>
</RCC>
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cpp
QT += sql network
```

任何命令行输入或输出都以以下方式书写：

```cpp
$ <Qt Installation Path> \Tools \QtInstallerFramework \3.0\ bin\ binarycreator.exe -c config\config.xml -p packages ClientManagementInstaller.exe
```

**粗体**：表示一个新术语，一个重要词，或者你在屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“用 Client Management 替换 Hello World 标题，并在 Window 的正文中插入一个 Text 组件”。

警告或重要说明会出现在这样的地方。

提示和技巧会出现在这样的地方。

# 第一章：Hello Qt

Qt 是一个成熟而强大的框架，可在多种平台上交付复杂的应用程序。它被广泛应用于嵌入式设备，包括电视、卫星机顶盒、医疗设备、汽车仪表板等。它在 Linux 世界中也有丰富的历史，KDE 和 Sailfish OS 广泛使用它，许多应用程序也是使用 Qt 开发的。在过去几年中，它在移动领域也取得了巨大进展。然而，在 Microsoft Windows 和 Apple Mac OS X 世界中，C#/.NET 和 Objective-C/Cocoa 的主导地位意味着 Qt 经常被忽视。

本书旨在演示 Qt 框架的强大和灵活性，并展示如何编写应用程序一次并部署到多个操作系统桌面上。我们将从头开始构建一个完整的现实世界的**业务线**（**LOB**）解决方案，包括独立的库、用户界面和单元测试项目。

我们将介绍如何使用 QML 构建现代、响应式的用户界面，并将其与丰富的 C++类连接起来。我们将使用 QMake 控制项目配置和输出的每个方面，包括平台检测和条件表达式。我们将构建“自我意识”的数据实体，可以将自己序列化到 JSON 并从中反序列化。我们将在数据库中持久化这些数据实体，并学习如何查找和更新它们。我们将访问互联网并消费 RSS 源。最后，我们将生成一个安装包，以便将我们的应用程序部署到其他机器上。

在这一章中，我们将安装和配置 Qt 框架以及相关的**集成开发环境**（**IDE**）Qt Creator。我们将创建一个简单的草稿应用程序，我们将在本书的其余部分中使用它来演示各种技术。我们将涵盖以下主题：

+   安装 Qt

+   维护你的安装

+   Qt Creator

+   草稿项目

+   qmake

# 安装 Qt

让我们首先访问 Qt 网站[`www.qt.io`](https://www.qt.io/)：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/c940d042-dd21-4b22-98cd-da7573f1eab4.png)

网站布局经常变化，但你要找的是下载桌面和移动端的 Qt 开源版本：

1.  从顶级菜单中选择产品，然后选择 IDE 和工具

1.  点击免费开始

1.  选择桌面和移动应用程序

1.  点击获取你的开源软件包

如果你继续在这些个人项目之外使用 Qt，请确保阅读 Qt 网站上提供的许可信息（[`www.qt.io/licensing/`](https://www.qt.io/licensing/)）。如果你的项目范围需要或者你想要访问官方 Qt 支持和与 Qt 公司的紧密战略关系的好处，升级到商业 Qt 许可证。

该网站将检测你的操作系统并建议一个推荐的下载：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/8bef27df-df7a-4602-8eea-60800d22aa90.png)

在 Windows 上，你将被推荐使用在线安装程序`*.exe`文件，而在 Linux 上，你将被提供一个`*.run`文件，如果你使用 Mac OS X，则会提供一个`.dmg`文件。在所有情况下，下载并启动安装程序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/a3f707e8-b55d-47bf-a6f0-28bdd400b734.png)

在 Linux 上，一旦下载完成，你可能需要首先转到`*.run`文件并将其标记为可执行，以便能够启动它。要做到这一点，右键单击文件管理器中的文件，然后单击属性。单击权限选项卡，选中“允许作为程序执行文件”的复选框。

在初始的欢迎对话框之后，你首先看到的是注册或使用 Qt 账户登录的选项。如果你愿意，可以随意创建一个，但现在我们将继续跳过：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/8e5c2903-df00-4369-aa2f-5a626363549f.png)

然后会要求你选择要安装的组件。

你的第一个决定是你想要哪个版本的 Qt 框架。你可以同时安装多个版本。让我们选择最新和最好的（写作时的 Qt 5.10），并取消选择所有旧版本。

接下来，展开所选版本，你会看到一个次要的选项列表。所有描述为“Qt 5.9.x 预构建组件...”的选项都被称为**工具包**。工具包本质上是一组工具，使你能够使用特定的编译器/链接器构建你的应用程序，并在特定的目标架构上运行它。每个工具包都带有专门为该特定工具集编译的 Qt 框架二进制文件以及必要的支持文件。请注意，工具包不包含所引用的编译器；你需要提前安装它们。在 Windows 上的一个例外是 MinGW（包括 Windows 的 GCC），你可以选择通过底部的工具组件列表安装。

在 Windows 上，我们将选择 MinGW 5.3.0 32 位工具包，还有来自工具部分的 MinGW 5.3.0 开发环境。在我的（64 位）机器上，我已经安装了 Microsoft Visual Studio 2017，所以我们还会选择 MSVC 2017 64 位工具包，以帮助在本书后面演示一些技术。在 Linux 上，我们选择 GCC 64 位，而在 Mac OS 上，我们选择 macOS 64 位（使用 Clang 编译器）。请注意，在 Mac OS 上，你必须安装 XCode，并且最好至少启动一次 XCode，让它有机会完成初始化和配置。

随意暂停，安装任何其他 IDE 或编译器，然后回来选择相匹配的工具包。你选择哪个并不太重要——本书中介绍的技术适用于任何工具包，只是结果可能略有不同。请注意，你所看到的可用工具包将取决于你的操作系统和芯片组；例如，如果你使用的是 32 位机器，就不会提供 64 位工具包。

在工具包下面是一些可选的 Qt API（如 Qt Charts），在本书涉及的主题中我们不需要，但如果你想探索它们的功能，可以随意添加。请注意，它们可能与核心 Qt 框架有不同的许可协议。

无论工具包和 API，你会注意到在工具部分，Qt Creator 是默认安装的 IDE，这也是我们在本书中将要使用的 IDE。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/f3fb9cc7-a583-4c20-89f5-b50d4bb5d82f.png)

完成选择后，点击下一步和更新开始安装。

通常最好将安装位置保持默认以保持机器的一致性，但随意选择任何你想要安装的位置。

# 维护你的安装

安装后，你可以通过位于你安装 Qt 的目录中的`维护工具`应用程序来更新、添加和删除组件（甚至整个 Qt 安装）。

启动这个工具基本上和我们第一次安装 Qt 时的体验是一样的。添加或移除组件选项是你想要添加之前可能不需要的项目，包括工具包甚至是全新的框架发布。除非你主动取消选择，已经安装在系统上的组件不会受到影响。

# Qt Creator

虽然 Qt Creator 的详细概述超出了本书的范围（Qt Creator 手册可以通过帮助模式访问，如此处所述），但在我们开始第一个项目之前，快速浏览一下是值得的，所以启动新安装的应用程序，我们来看一下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/82d23d25-1147-4106-9889-b59acce6dfcb.png)

在左上角（1）是应用程序的不同区域或模式：

+   欢迎模式是 Qt Creator 启动时的默认模式，是创建或打开项目的起点。有一套广泛的示例，帮助展示框架的各种功能，以及一些教程视频的选择。

+   编辑模式是您将花费绝大部分时间的地方，用于编辑各种基于文本的文件。

+   设计仅在打开 UI 文件时可访问，并且是用于视图的所见即所得编辑器。虽然对 UX 设计和基本布局工作很有用，但它可能会很快变得令人沮丧，因此我们将在编辑模式下进行所有 QML 工作。以这种方式工作有助于理解 QML（因为你必须编写它），并且还具有编辑器不添加不需要的代码的优势。

+   调试模式用于调试应用程序，超出了本书的范围。

+   项目模式是管理项目配置的地方，包括构建设置。在此处进行的更改将反映在`*.pro.user`文件中。

+   帮助模式带您进入 Qt Creator 手册和 Qt 库参考。

在识别的 Qt 符号上按下*F1*将自动打开该符号的上下文相关帮助。

在下面，我们有构建/运行工具（2）：

+   Kit/Build 让您选择您的工具包并设置构建模式

+   运行构建并在不进行调试的情况下运行应用程序

+   开始调试构建并使用调试器运行应用程序（请注意，您必须在所选工具包中安装和配置调试器才能使用此功能）

+   构建项目构建应用程序而不运行它

在底部（3），我们有一个搜索框，然后是几个输出窗口：

问题显示任何警告或错误。对于与您的代码相关的编译器错误，双击该项将导航到相关的源代码。

+   搜索结果让您在各种范围内查找文本的出现。*Ctrl *+ *F*会带出一个快速搜索，然后从那里选择*高级…*也会带出搜索结果控制台。

+   应用程序输出是控制台窗口；所有来自应用程序代码的输出，如`std::`cout 和 Qt 的等效`qDebug()`，以及 Qt 框架的某些消息都会显示在这里。

+   编译输出包含来自构建过程的输出，从 qmake 到编译和链接。

+   调试器控制台包含我们在本书中不会涉及的调试信息。

+   常规消息包含其他杂项输出，其中最有用的是来自`*.pro`文件的 qmake 解析，我们稍后会看到。

搜索框真的是一个隐藏的宝石，可以帮助您避免点击无尽的文件和文件夹，试图找到您要找的东西。您可以在框中开始输入要查找的文件名，然后会出现一个带有所有匹配文件的过滤列表。只需单击您想要的文件，它就会在编辑器中打开。不仅如此，您还可以应用大量的过滤器。单击光标放在空的搜索框中，它会显示一个可用过滤器的列表。例如，过滤器`m`会搜索 C++方法。所以，假设您记得写了一个名为`SomeAmazingFunction()`的方法，但不记得它在哪里，只需转到搜索框，开始输入`m Some`，它就会出现在过滤列表中。

在编辑模式下，布局会略有变化，并且会出现一些新的窗格。最初它们将是空的，但一旦打开项目，它们将类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/022cfbf8-e903-4cfd-8fbc-8f674707d226.png)

在导航栏旁边是项目资源管理器，您可以使用它来浏览解决方案的文件和文件夹。下面的窗格是您当前打开的所有文档的列表。右侧的较大区域是编辑器窗格，您可以在其中编写代码和编辑文档。

在项目资源管理器中双击文件通常会在编辑器窗格中打开它并将其添加到打开的文档列表中。单击打开文档列表中的文档将在编辑器窗格中激活它，而单击文件名右侧的小 x 将关闭它。

窗格可以更改以显示不同的信息，调整大小，分割，关闭，并可能使用标题中的按钮过滤或与编辑器同步。尝试一下，看看它们能做什么。

正如你所期望的，现代 IDE 的外观和感觉是非常可定制的。选择工具 > 选项…来查看可用的选项。我通常编辑以下内容：

+   环境 > 接口 > 主题 > 平面

+   `文本编辑器 > 字体和颜色 > 颜色方案 > 我自己的方案`

+   `文本编辑器 > 完成 > 用括号包围文本选择 > 关闭`

+   `文本编辑器 > 完成 > 用引号包围文本选择 > 关闭`

+   `C++ > 代码风格 > 当前设置 > 复制…然后编辑…`

+   `编辑代码风格 > 指针和引用 > 绑定到类型名称 > 打开（其他选项关闭）`

玩弄一下，把东西弄得你喜欢。

# 草稿项目

为了演示 Qt 项目可以有多简单，并给我们一个编程沙盒来玩耍，我们将创建一个简单的草稿项目。对于这个项目，我们甚至不会使用 IDE 来为我们做，这样你就可以真正看到项目是如何建立起来的。

首先，我们需要创建一个根文件夹来存储所有的 Qt 项目。在 Windows 上，我使用`c:\projects\qt`，而在 Linux 和 Mac OS 上我使用`~/projects/qt`。在任何你喜欢的地方创建这个文件夹。

请注意，文件同步工具（OneDrive，DropBox 等）有时会导致项目文件夹出现问题，因此请将项目文件保存在常规的未同步文件夹中，并使用远程存储库进行版本控制以进行备份和共享。

在本书的其余部分，我会宽松地将这个文件夹称为`<Qt 项目>`或类似的。我们也倾向于使用 Unix 风格的/分隔符来表示文件路径，而不是 Windows 风格的反斜杠`\`。因此，对于使用 Windows 的读者，`<Qt 项目>/scratchpad/amazing/code`等同于`c:\projects\qt\scratchpad\amazing\code`。Qt 也倾向于使用这种约定。

同样，本书中大部分截图将来自 Windows，因此 Linux/Mac 用户应将任何关于`c:\projects\qt`的引用解释为`~/projects/qt`。

在我们的 Qt 项目文件夹中，创建一个名为 scratchpad 的新文件夹并进入其中。创建一个名为`scratchpad.pro`的新纯文本文件，记得删除操作系统可能想要为你添加的任何`.txt`扩展名。

接下来，只需双击该文件，它将在 Qt Creator 中打开：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/0e9f2d91-6e96-4760-b1d0-0537f9cc23e5.png)

在这里，Qt Creator 问我们如何配置我们的项目，即在构建和运行代码时我们想要使用哪些工具包。选择一个或多个可用的工具包，然后点击配置项目。您可以随后轻松添加和删除工具包，所以不用担心选择哪个。

如果你切换回到`文件系统`，你会看到 Qt Creator 已经为我们创建了一个名为`scratchpad.pro.user`的新文件。这只是一个包含配置信息的 XML 文件。如果你删除这个文件并再次打开`.pro`文件，你将被提示再次配置项目。正如它的名字所暗示的那样，配置设置与本地用户有关，所以通常如果你加载了别人创建的项目，你也需要通过配置项目步骤。

成功配置项目后，您将看到项目已经打开，即使是一个完全空的`.pro`文件。这就是一个项目可以变得多么简单！

回到`文件系统`，创建以下纯文本文件：

+   `main.cpp`

+   `main.qml`

+   `qml.qrc`

我将逐个查看这些文件，解释它们的目的，并很快添加它们的内容。在现实世界的项目中，我们当然会使用 IDE 为我们创建文件。事实上，当我们创建主解决方案文件时，这正是我们要做的。然而，以这种方式做的目的是向您展示，归根结底，项目只是一堆文本文件。永远不要害怕手动创建和编辑文件。许多现代 IDE 可能会通过一个又一个的菜单和永无止境的选项窗口使人困惑和复杂化。Qt Creator 可能会错过其他 IDE 的一些高级功能，但它非常简洁和直观。

创建了这些文件后，在项目窗格中双击 `scratchpad.pro` 文件，我们将开始编辑我们的新项目。

# qmake

我们的项目（`.pro`）文件由一个名为 **qmake** 的实用程序解析，它生成驱动应用程序构建的 `Makefiles`。我们定义了我们想要的项目输出类型，包括哪些源文件以及依赖关系等等。我们现在将在项目文件中简单地设置变量来实现这些。

将以下内容添加到 `scratchpad.pro`：

```cpp
TEMPLATE = app

QT += qml quick

CONFIG += c++14
SOURCES += main.cpp
RESOURCES += qml.qrc
```

让我们依次浏览每一行：

```cpp
TEMPLATE = app
```

`TEMPLATE` 告诉 qmake 这是什么类型的项目。在我们的情况下，它是一个可执行应用程序，由 `app` 表示。我们感兴趣的其他值是用于构建库二进制文件的 `lib` 和用于多项目解决方案的 `subdirs`。请注意，我们使用 `=` 运算符设置变量：

```cpp
QT += qml quick
```

Qt 是一个模块化框架，允许您只引入您需要的部分。`QT` 标志指定我们想要使用的 Qt 模块。*core* 和 *gui* 模块默认包含在内。请注意，我们使用 `+=` 将附加值追加到期望列表的变量中：

```cpp
CONFIG += c++14
```

`CONFIG` 允许您添加项目配置和编译器选项。在这种情况下，我们指定要使用 C++14 特性。请注意，如果您使用的编译器不支持这些语言特性标志，它们将不起作用。

```cpp
SOURCES += main.cpp
```

`SOURCES` 是我们想要包含在项目中的所有 `*.cpp` 源文件的列表。在这里，我们添加了我们的空 `main.cpp` 文件，我们将在其中实现我们的 `main()` 函数。我们目前还没有，但当我们有时，我们的头文件将使用 `HEADERS` 变量指定：

```cpp
RESOURCES += qml.qrc 
```

`RESOURCES` 是项目中包含的所有资源集合文件（`*.qrc`）的列表。资源集合文件用于管理应用程序资源，如图像和字体，但对我们来说最关键的是我们的 QML 文件。

更新项目文件后，保存更改。

每当您保存对 `*.pro` 文件的更改时，qmake 将解析该文件。如果一切顺利，您将在 Qt Creator 的右下角获得一个小绿条。红色条表示某种问题，通常是语法错误。进程的任何输出都将写入“常规消息”窗口，以帮助您诊断和解决问题。空格将被忽略，所以不用担心完全匹配空行。

要让 qmake 重新审视您的项目并生成新的 `Makefiles`，请在项目窗格中右键单击您的项目，然后选择“运行 qmake”。这可能有点乏味，但在构建和运行应用程序之前手动运行 qmake 是一个好习惯。我发现某些类型的代码更改可能会“悄悄地”通过，当您运行应用程序时，它们似乎没有产生任何效果。如果您看到应用程序忽略了您刚刚进行的更改，请在每个项目上运行 qmake 并重试。如果出现虚假的链接器错误，也是同样的情况。

您会看到我们的其他文件现在神奇地出现在项目窗格中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/f3dcc2a3-3a5b-49db-a081-fb4626bb65b4.png)

双击 `main.cpp` 进行编辑，我们将写入我们的第一行代码：

```cpp
#include <QGuiApplication>
#include <QQmlApplicationEngine>

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QQmlApplicationEngine engine;

    engine.load(QUrl(QStringLiteral("qrc:/main.qml")));

    return app.exec();
}
```

我们在这里所做的就是实例化一个 Qt GUI 应用程序对象，并要求它加载我们的`main.qml`文件。这非常简短和简单，因为 Qt 框架为我们做了所有复杂的底层工作。我们不必担心平台检测或管理窗口句柄或 OpenGL。

可能最有用的事情之一是学会将光标放在 Qt 对象中，然后按下*F1*将打开该类型的帮助。对于 Qt 对象上的方法和属性也是如此。在帮助文件中查看`QGuiApplication`和`QQmlApplicationEngine`是关于什么的。

要编辑项目中的下一个文件`qml.qrc`，您需要右键单击并选择要打开它的编辑器。默认是资源编辑器。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/b6bd98fb-9f91-45f0-aa54-13a13af39bf2.png)

我个人不喜欢这个编辑器。我觉得它并没有比纯文本编辑更容易，也不是特别直观。关闭它，选择`以纯文本编辑器打开`。

添加以下内容：

```cpp
<RCC>
    <qresource prefix="/">
        <file>main.qml</file>
    </qresource>
</RCC>
```

回到`main.cpp`，我们要求 Qt 加载`qrc:/main.qml`文件。这基本上可以解释为“在具有前缀`/`和名称`main.qml`的`qrc`文件中查找文件”。现在在我们的`qrc`文件中，我们创建了一个具有前缀属性`/`的`qresource`元素。在这个元素内部，我们有一个资源集合（尽管只有一个），它的名称是`main.qml`。将`qrc`文件视为一个可移植的文件系统。请注意，资源文件相对于引用它们的`.qrc`文件而言。在这种情况下，我们的`main.qml`文件与我们的`qml.qrc`文件在同一个文件夹中。例如，如果它在名为`views`的子文件夹中，那么`qml.qrc`中的行将是这样的：

```cpp
<file>views/main.qml</file>
```

同样，在`main.cpp`中的字符串将是`qrc:/views/main.qml`。

保存这些更改后，您将看到我们空的`main.qml`文件出现在项目窗格中`qml.qrc`文件的子文件夹中。双击该文件进行编辑，我们将完成我们的项目：

```cpp
import QtQuick 2.9
import QtQuick.Window 2.3

Window {
    visible: true
    width: 1024
    height: 768
    title: qsTr("Scratchpad")
    color: "#ffffff"

    Text {
        id: message
        anchors.centerIn: parent
        font.pixelSize: 44
        text: qsTr("Hello Qt Scratchpad!")
        color: "#008000"
    }
}
```

我们将在第二章中详细介绍 QML，*项目结构*，但简而言之，这个文件代表了应用程序启动时向用户呈现的屏幕或视图。

导入行类似于 C++中的`#include`语句，不过不是包含单个头文件，而是导入整个模块。在这种情况下，我们希望使用基本的 QtQuick 模块来访问所有核心的 QML 类型，还有 QtQuick 窗口模块来访问`Window`组件。模块是有版本的，通常情况下，你会想要使用你所使用的 Qt 版本的最新版本。当前的版本号可以在 Qt 文档中找到。请注意，尽管在输入版本号时会有代码补全，但有时呈现的选项并不反映最新可用的版本。

正如其名称所示，`Window`元素为我们提供了一个顶级窗口，在其中我们的所有其他内容将被呈现。我们给它一个大小为 1024 x 765 像素，一个标题为“scratchpad”，以及一个白色的背景颜色，用十六进制 RGB 值表示。

在该组件中（QML 是一种分层标记语言），我们使用`Text`组件添加了一个欢迎消息。我们将文本居中显示在屏幕上，并设置了字体大小和颜色，但除此之外，在这个阶段我们不关心花哨的格式或其他任何东西，所以这就是我们会做的复杂程度。我们稍后会更详细地介绍这个，所以如果看起来有点陌生，不要担心。

就是这样。要构建和运行我们令人惊叹的新应用程序，首先使用左下角的监视器图标选择您想要的工具包和构建配置：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/75cffd4f-352a-47a0-acb8-cce893e02890.png)

接下来，在项目窗格中右键单击项目名称，然后选择运行 qmake。完成后，使用绿色播放图标运行应用程序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/257dd773-1abf-41e5-96f5-53ecb8906aea.png)

# 总结

在本章中，我们下载、安装和配置了 Qt。我们快速浏览了 Qt Creator IDE，尝试了它的选项，并了解了如何使用它编辑各种文件。我们对 qmake 有了初步了解，并看到了创建项目是多么简单，从而使事情变得不再神秘。最后，我们从头开始构建了我们的处女作品（弱笑话打算），并在屏幕上得到了必不可少的“Hello World”消息。

在第二章 *项目结构*中，我们将在这些基础上建立，并设置我们的主要解决方案。


# 第二章：项目结构

在本章中，我们将创建一个新的多项目解决方案，这将是我们示例应用程序的基础。我们将应用模型视图控制器模式，将用户界面和业务逻辑分离。我们还将介绍 Qt 的单元测试框架—QtTest，并演示如何将其集成到我们的解决方案中。我们将在本章中涵盖以下内容：

+   项目、MVC 和单元测试

+   创建库项目

+   创建单元测试项目

+   创建用户界面项目

+   掌握 MVC

+   QObject 基类

+   QML

+   控制项目输出

# 项目、MVC 和单元测试

我们在上一章中构建的草稿应用是一个 Qt 项目，由一个`.pro`文件表示。在商业环境中，技术解决方案通常作为公司倡议的一部分开发，这些倡议通常也被称为**项目**。为了尽量减少混淆（和项目出现的次数！），我们将使用项目来表示由`.pro`文件定义的 Qt 项目，倡议一词用来指代商业意义上的项目。

我们将要开展的倡议是一个通用的客户管理系统。它将是一个可以调整和重新用于多个应用程序的东西—供应商管理客户、卫生服务管理患者等。它将执行现实世界**业务线**（**LOB**）应用程序中一遍又一遍发现的常见任务，主要是添加、编辑和删除数据。

我们的草稿应用完全封装在一个项目中。对于较小的应用程序，这是完全可行的。然而，对于较大的代码库，特别是涉及多个开发人员的情况，通常最好将事情分解成更易管理的部分。

我们将使用超轻量级的**模型视图控制**（**MVC**）架构模式的实现。如果你之前没有接触过 MVC，它主要用于将业务逻辑与用户界面解耦。用户界面（视图）向一个类似于交换机的类（控制器）传达命令，以检索数据并执行所需的操作。控制器反过来将数据、逻辑和规则的责任委托给数据对象（模型）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/39853104-b5e4-4dc3-985b-febae3c11f56.png)

关键是**视图**知道**控制器**和**模型**，因为它需要向**控制器**发送命令并显示**模型**中保存的数据。**控制器**知道**模型**，因为它需要将工作委托给它，但它不知道**视图**。模型对**控制器**或**视图**一无所知。

在商业环境中以这种方式设计应用程序的一个关键好处是，专门的用户体验专家可以在视图上工作，而程序员可以在业务逻辑上工作。第二个好处是，因为业务逻辑层对 UI 一无所知，所以你可以添加、编辑，甚至完全替换用户界面而不影响逻辑层。一个很好的用例是为桌面应用程序拥有“全功能”UI，为移动设备拥有一个伴侣“半功能”UI，两者都可以使用相同的业务逻辑。考虑到所有这些，我们将把我们的 UI 和业务逻辑物理上分开成两个项目。

我们还将研究如何将自动化单元测试集成到我们的解决方案中。单元测试和**测试驱动开发**（**TDD**）在最近变得非常流行，当在商业环境中开发应用程序时，你很可能会被要求在编写代码时编写单元测试。如果没有，你应该提议这样做，因为它具有很大的价值。如果你以前没有进行过单元测试，不要担心；它非常简单，我们将在本书的后面更详细地讨论它。

最后，我们需要一种方法来将这些子项目聚合在一起，以便我们不必单独打开它们。我们将通过一个伞解决方案项目来实现这一点，该项目除了将其他项目绑在一起外，什么也不做。这就是我们将布置我们的项目的方式：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/83ae32f5-c0eb-43b2-8d40-d977d7fb3a9c.png)

# 项目创建

在上一章中，我们看到了通过创建一些文本文件来设置新项目是多么容易。但是，我们将使用 Qt Creator 创建我们的新解决方案。我们将使用新项目向导来引导我们创建一个顶级解决方案和一个单个子项目。

从顶部菜单中，选择文件>新文件或项目，然后选择项目>其他项目>Subdirs 项目，然后单击“选择...”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/ab5a4f70-f441-44b3-bcc1-118ee4ccb301.png)

Subdirs Project 是我们需要的顶级解决方案项目的模板。将其命名为`cm`，并在我们的`qt`项目文件夹中创建：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/466aba05-c61f-436c-82d6-203ad4fe6731.png)

在 Kit Selection 窗格中，选中我们安装的 Desktop Qt 5.10.0 MinGW 32 位套件。如果您已安装其他套件，可以随意选择要尝试的其他套件，但这并非必需。然后单击“下一步”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/16fccb2b-40e0-484c-a43a-7e926efe6c68.png)

如前所述，版本控制超出了本书的范围，因此在项目管理窗格中，从“添加到版本控制”下拉菜单中选择“无”。然后单击“完成并添加子项目”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/04cabdf6-7274-4e07-a775-ee9320205a4a.png)

我们将把用户界面项目作为第一个子项目添加。向导遵循的步骤与我们刚刚遵循的步骤更多或更少相同，因此执行以下操作：

1.  选择项目>应用程序>Qt Quick 应用程序-空，并单击“选择...”

1.  在项目位置对话框中，将其命名为`cm-ui`（用于客户端管理-用户界面），将位置保留为我们的新`cm`文件夹，然后单击“下一步”。

1.  在定义构建系统对话框中，选择构建系统 qmake，然后单击“下一步”。

1.  在定义项目详细信息对话框中，保留默认的最小 Qt 版本 QT 5.9 和未选中使用 Qt 虚拟键盘框，然后单击“下一步”。

1.  在 Kit Selection 对话框中，选择桌面 Qt 5.10.0 MinGW 32 位套件以及您希望尝试的其他套件，然后单击“下一步”。

1.  最后，在项目管理对话框中，跳过版本控制（将其保留为<无>）并单击“完成”。

我们的顶级解决方案和 UI 项目现在已经启动，所以让我们按照以下步骤添加其他子项目。接下来添加业务逻辑项目，如下所示：

1.  在“项目”窗格中，右键单击顶级`cm`文件夹，然后选择“新建子项目...”。

1.  选择项目>库> C++库，并单击“选择...”。

1.  在介绍和项目位置对话框中，选择共享库作为类型，将其命名为`cm-lib`，在`<Qt Projects>/cm`中创建它，然后单击“下一步”。

1.  在选择所需模块对话框中，只接受 QtCore 的默认设置，然后单击“下一步”。

1.  在**类信息**对话框中，我们有机会创建一个新类来帮助我们入门。给出类名`Client`，使用`client.h`头文件和`client.cpp`源文件，然后单击“下一步”。

1.  最后，在项目管理对话框中，跳过版本控制（将其保留为<无>）并单击“完成”。

最后，我们将重复这个过程来创建我们的单元测试项目：

1.  新子项目....

1.  项目>其他项目>Qt 单元测试。

1.  项目名称`cm-tests`。

1.  包括 QtCore 和 QtTest。

1.  创建`ClientTests`测试类，其中包括`testCase1`测试槽和`client-tests.cpp`文件名。将类型设置为测试，并检查生成初始化和清理代码。

1.  跳过版本控制并完成。

我们刚刚经历了很多对话框，但现在我们已经将骨架解决方案放置好了。您的项目文件夹应该如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/6a2a887e-58db-4347-8bf2-67aefbd91625.png)

现在让我们依次查看每个项目，并在开始添加内容之前进行一些调整。

# cm-lib

首先，前往文件资源管理器，在`cm-lib`下创建一个名为`source`的新子文件夹；将`cm-lib_global.h`移动到其中。在`source`中创建另一个名为`models`的子文件夹，并将`Client`类文件都移动到其中。

接下来，在 Qt Creator 中，打开`cm-lib.pro`并编辑如下：

```cpp
QT -= gui
TARGET = cm-lib
TEMPLATE = lib
CONFIG += c++14
DEFINES += CMLIB_LIBRARY
INCLUDEPATH += source

SOURCES += source/models/client.cpp

HEADERS += source/cm-lib_global.h \
    source/models/client.h
```

由于这是一个库项目，我们不需要加载默认的 GUI 模块，因此我们使用`QT`变量将其排除。`TARGET`变量是我们希望给我们的二进制输出的名称（例如`cm-lib.dll`）。这是可选的，如果未提供，将默认为项目名称，但我们将明确指定。接下来，与我们在草稿应用程序中看到的`app`模板不同，这次我们使用`lib`来创建一个库。我们通过`CONFIG`变量添加了 c++14 特性。

`cm-lib_global.h`文件是一个有用的预处理器样板，我们可以用它来导出我们的共享库符号，您很快就会看到它的用途。我们在`DEFINES`变量中使用`CMLIB_LIBRARY`标志来触发此导出。

最后，我们稍微重写了`SOURCES`和`HEADERS`变量列表，以考虑在我们移动了一些东西之后的新文件位置，并且我们将源文件夹（这是我们所有代码的所在地）添加到`INCLUDEPATH`中，这样当我们使用`#include`语句时就可以搜索到路径。

在项目窗格中右键单击`cm-lib`文件夹，选择运行 qmake。完成后，再次右键单击并选择**重新构建**。一切应该都是绿色和愉快的。

# cm-tests

创建新的`source/models`子文件夹，并将`client-tests.cpp`移动到那里。切换回 Qt Creator 并编辑`cm-tests.pro`：

```cpp
QT += testlib
QT -= gui
TARGET = client-tests
TEMPLATE = app

CONFIG += c++14 
CONFIG += console 
CONFIG -= app_bundle

INCLUDEPATH += source 

SOURCES += source/models/client-tests.cpp
```

这基本上与`cm-lib`的方法相同，唯一的区别是我们想要一个控制台应用程序而不是一个库。我们不需要 GUI 模块，但我们将添加`testlib`模块以获取 Qt 测试功能的访问权限。

目前这个子项目还没有太多内容，但您应该能够成功运行 qmake 并重新构建。

# cm-ui

这次创建两个子文件夹：`source`和`views`。将`main.cpp`移动到`source`中，将`main.qml`移动到`views`中。将`qml.qrc`重命名为`views.qrc`，并编辑`cm-ui.pro`：

```cpp
QT += qml quick

TEMPLATE = app

CONFIG += c++14 

INCLUDEPATH += source 

SOURCES += source/main.cpp 

RESOURCES += views.qrc 

# Additional import path used to resolve QML modules in Qt Creator's code model 
QML_IMPORT_PATH = $$PWD
```

我们的 UI 是用 QML 编写的，需要`qml`和`quick`模块，所以我们添加了这些。我们编辑`RESOURCES`变量以获取我们重命名的资源文件，并编辑`QML_IMPORT_PATH`变量，我们将在进入自定义 QML 模块时详细介绍。

接下来，编辑`views.qrc`以考虑我们已将`main.qml`文件移动到`views`文件夹中。记得右键单击并选择“使用其他应用程序打开”>“纯文本编辑器”：

```cpp
<RCC>
    <qresource prefix="/">
        <file>views/main.qml</file>
    </qresource>
</RCC>
```

最后，我们还需要编辑`main.cpp`中的一行以考虑文件移动：

```cpp
engine.load(QUrl(QStringLiteral("qrc:/views/main.qml")));
```

现在，您应该能够运行 qmake 并重新构建`cm-ui`项目。在运行之前，让我们快速看一下构建配置按钮，因为现在我们有多个项目打开了：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/dff629a5-d049-416c-a917-5f3dccd1f080.png)

请注意，现在除了工具链和构建选项之外，我们还必须选择要运行的可执行文件。确保选择了`cm-ui`，然后运行应用程序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/c87febe8-c33b-44c7-bafc-7e60d634a23e.png)

确实是世界你好。这是相当令人失望的东西，但我们已经成功地构建和运行了一个多项目解决方案，这是一个很好的开始。当您无法再忍受更多乐趣时，请关闭应用程序！

# MVC 的掌握

现在我们的解决方案结构已经就位，我们将开始 MVC 实现。正如您将看到的那样，它非常简单，非常容易设置。

首先，展开`cm-ui > Resources > views.qrc > / > views`，右键单击`main.qml`，选择重命名，将文件重命名为`MasterView.qml`。如果收到有关项目编辑的消息，请选择“是”以继续：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/e30af2b8-81b4-4c6f-9ac3-df51ea1e6ecc.png)

如果您收到错误消息，文件仍将在项目窗格中显示为`main.qml`，但文件在文件系统中已被重命名。

接下来，编辑`views.qrc`（右键单击它，然后选择使用纯文本编辑器打开）。将内容替换为以下内容：

```cpp
<RCC>
    <qresource prefix="/views">
        <file alias="MasterView.qml">views/MasterView.qml</file>
    </qresource>
</RCC>
```

如果您还记得我们如何在`main.cpp`中加载这个 QML 文件，语法是`qrc:<prefix><filename>`。我们以前有一个`/`前缀和一个`views/main.qml`相对文件名。这给了我们`qrc:/views/main.qml`。

`/`的前缀并不是非常描述性的。随着您添加更多的 QML 文件，将它们组织成具有有意义前缀的块会非常有帮助。拥有无结构的资源块也会使项目面板变得混乱，导航起来更加困难，就像您刚才在`views.qrc > / > views`中看到的那样。因此，第一步是将前缀从`/`重命名为`/views`。

然而，使用`/views`作为前缀和`views/main.qml`作为相对文件名，我们的 URL 现在是`qrc:/views/views/main.qml`。

这比以前更糟糕了，在`views.qrc`中我们仍然有一个深层的文件夹结构。幸运的是，我们可以为我们的文件添加一个*别名*来解决这两个问题。您可以使用资源的别名来代替相对路径，因此如果我们分配一个`main.qml`的别名，我们可以用`main.qml`来替换`views/main.qml`，得到`qrc:/views/main.qml`。

这是简洁和描述性的，我们的项目面板也更整洁了。

因此，回到我们更新后的`views.qrc`版本，我们只是将文件名从`main.qml`更新为`MasterView.qml`，与我们执行的文件重命名一致，并且我们还提供了一个快捷别名，这样我们就不必两次指定 views。

现在我们需要更新`main.cpp`中的代码以反映这些更改：

```cpp
engine.load(QUrl(QStringLiteral("qrc:/views/MasterView.qml")));
```

您应该能够运行 qmake，并构建和运行以验证没有出现问题。

接下来，我们将创建一个`MasterController`类，因此右键单击`cm-lib`项目，然后选择添加新内容… > C++ > C++类 > 选择…：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/2b36133d-dd2e-4811-9167-1b302283441b.png)

使用“浏览…”按钮创建`source/controllers`子文件夹。

通过选择 QObject 作为基类并包含它，Qt Creator 将为我们编写一些样板代码。您随后可以自己添加它，所以不要觉得这是创建新类的必要部分。

一旦您跳过了版本控制并创建了类，声明和定义如下。我们的`MasterController`目前还没有做任何特别激动人心的事情，我们只是在做基础工作。

这是`master-controller.h`：

```cpp
#ifndef MASTERCONTROLLER_H
#define MASTERCONTROLLER_H
#include <QObject>

#include <cm-lib_global.h>
namespace cm {
namespace controllers {
class CMLIBSHARED_EXPORT MasterController : public QObject
{
    Q_OBJECT
public:
    explicit MasterController(QObject* parent = nullptr);
};

}}

#endif
```

我们真正添加到 Qt Creator 默认实现的只是`CMLIBSHARED_EXPORT`宏，Qt Creator 在`cm-lib_global.h`中为我们编写的，以处理我们的共享库导出，并将类放在一个命名空间中。

我总是将项目名称作为根命名空间，然后是反映源目录中类文件物理位置的其他命名空间，所以在这种情况下，我使用`cm::controllers`，因为该类位于`source/controllers`目录中。

这是`master-controller.cpp`：

```cpp
#include "master-controller.h"

namespace cm {
namespace controllers {
MasterController::MasterController(QObject* parent)
    : QObject(parent)
{
}

}}

```

在实现文件中，我使用了一个略微不正统的风格——大多数人只是在`.cpp`文件的顶部添加`using namespace cm::controllers;`。我经常喜欢将代码放在命名空间的范围内，因为在 IDE 中可以折叠它。通过重复最内层的命名空间范围（在这个例子中是*controllers*），您可以将代码分解成可折叠的区域，就像在 C#中一样，这有助于在更大的文件中进行导航，因为您可以折叠您不感兴趣的部分。这在功能上没有任何区别，所以使用您喜欢的风格。

# QObject

那么，我们继承的这个古怪的**QObject**是什么东西？它是所有 Qt 对象的基类，并且它为我们提供了一些强大的功能。

QObjects 将自己组织成对象层次结构，*parent*对象承担其*child*对象的所有权，这意味着我们不必太担心内存管理。例如，如果我们有一个从 QObject 派生的 Client 类的实例，它是从 QObject 派生的 Address 的父类，那么当客户端被销毁时，地址会自动被销毁。

QObjects 携带元数据，允许一定程度的类型检查，并且是与 QML 交互的支柱。它们还可以通过事件订阅机制相互通信，其中事件被发射为*signals*，订阅的代理被称为*slots*。

现在您需要记住的是，对于您编写的任何自定义类，如果您希望在 UI 中与之交互，请确保它派生自 QObject。每当您从 QObject 派生时，请确保在做任何其他事情之前始终向您的类添加神奇的 Q_OBJECT 宏。它注入了一堆超级复杂的样板代码，您不需要理解就可以有效地使用 QObjects。

我们现在需要引用一个子项目（`cm-lib`中的`MasterController`）中的代码到另一个子项目（`cm-ui`）中。我们首先需要能够访问我们的`#include`语句的声明。编辑`cm-ui.pro`中的`INCLUDEPATH`变量如下：

```cpp
INCLUDEPATH += source \
    ../cm-lib/source
```

`\`符号是“继续到下一行”的指示符，因此您可以将一个变量设置为跨越多行的多个值。就像控制台命令一样，‘..’表示向上遍历一个级别，所以这里我们从本地文件夹（`cm-ui`）中跳出，然后进入`cm-lib`文件夹以获取其源代码。您需要小心，项目文件夹保持相对位置不变，否则这将无法工作。

紧接着，我们将告诉我们的 UI 项目在哪里找到我们的库项目的实现（已编译的二进制文件）。如果您查看与顶级`cm`项目文件夹并排的文件系统，您会看到一个或多个构建文件夹，例如，build-cm-Desktop_Qt_5_9_0_MinGW_32bit-Debug。每个文件夹在为给定的工具包和配置运行 qmake 时创建，并在构建时填充输出。

接下来，导航到与您正在使用的工具包和配置相关的文件夹，您会发现一个带有另一个配置文件夹的 cm-lib 文件夹。复制这个文件路径；例如，我正在使用 MinGW 32 位工具包进行调试配置，所以我的路径是`<Qt Projects>/build-cm-Desktop_Qt_5_10_0_MinGW_32bit-Debug/cm-lib/debug`。

在那个文件夹中，您会找到与您的操作系统相关的已编译二进制文件，例如，在 Windows 上是`cm-lib.dll`。这是我们希望我们的`cm-ui`项目引用的`cm-lib`库实现的文件夹。为了设置这一点，将以下语句添加到`cm-ui.pro`中：

```cpp
LIBS += -L$$PWD/../../build-cm-Desktop_Qt_5_10_0_MinGW_32bit-Debug/cm-lib/debug -lcm-lib
```

`LIBS`是用于向项目添加引用库的变量。`-L`前缀表示目录，而`-l`表示库文件。使用这种语法允许我们忽略文件扩展名（`.a`，`.o`，`.lib`）和前缀（lib...），这些可能因操作系统而异，让 qmake 自行解决。我们使用特殊的`$$`符号来访问`PWD`变量的值，该变量包含当前项目的工作目录（在这种情况下是`cm/cm-ui`的完整路径）。然后，我们从该位置向上两个目录，使用`../..`来到 Qt 项目文件夹。然后，我们再次向下钻取到我们知道`cm-lib`二进制文件构建的位置。

现在，这个写起来很痛苦，丑陋得要命，一旦我们切换工具包或配置，它就会崩溃，但我们稍后会回来整理所有这些。项目引用都已连接好，我们可以前往`cm-ui`中的`main.cpp`。

为了能够在 QML 中使用给定的类，我们需要在创建 QML 应用程序引擎之前在`main()`中注册它。首先，包括`MasterController`：

```cpp
#include <controllers/master-controller.h>
```

然后，在实例化`QGuiApplication`之后但在声明`QQmlApplicationEngine`之前，添加以下行：

```cpp
qmlRegisterType<cm::controllers::MasterController>("CM", 1, 0, "MasterController");
```

我们在这里所做的是将类型注册到 QML 引擎中。请注意，模板参数必须使用所有命名空间进行完全限定。我们将类型的元数据添加到一个名为 CM 的模块中，版本号为 1.0，并且我们希望在 QML 标记中将此类型称为`MasterController`。

然后，我们实例化`MasterController`的一个实例，并将其注入到根 QML 上下文中：

```cpp
cm::controllers::MasterController masterController;

QQmlApplicationEngine engine;
engine.rootContext()->setContextProperty("masterController", &masterController);
engine.load(QUrl(QStringLiteral("qrc:/views/MasterView")));
```

请注意，在加载 QML 文件之前，您需要设置上下文属性，并且还需要添加以下标头：

```cpp
#include <QQmlContext>
```

因此，我们已经创建了一个控制器，将其注册到了 QML 引擎中，并且一切就绪。现在呢？让我们开始我们的第一段 QML。

# QML

**Qt 建模语言**（**QML**）是一种用于用户界面布局的分层声明性语言，其语法类似于**JavaScript 对象表示法**（**JSON**）。它可以通过 Qt 的元对象系统绑定到 C++对象，并且还支持内联 JavaScript。它很像 HTML 或 XAML，但没有 XML 的繁琐。如果你更喜欢 JSON 而不是 XML，这只能是一件好事！

继续打开`MasterView.qml`，我们将看到发生了什么。

您将看到的第一件事是一对`import`语句。它们类似于 C++中的`#include`语句，它们引入了我们想要在视图中使用的功能部分。它们可以是打包和版本化的模块，如 QtQuick 2.9，也可以是指向本地内容的相对路径。

接下来，QML 层次结构从一个 Window 对象开始。对象的范围由随后的{}表示，因此括号内的所有内容都是对象的属性或子对象。

属性遵循 JSON 属性语法，形式为 key: value。一个显着的区别是，除非您提供字符串文字作为值，否则不需要引号。在这里，我们将窗口对象的`visible`属性设置为`true`，窗口的大小设置为 640 x 480 像素，并在标题栏中显示 Hello World。

让我们更改标题并添加一个简单的消息。将 Hello World 的标题更改为 Client Management，并在窗口的正文中插入一个 Text 组件：

```cpp
Window {
    visible: true
    width: 640
    height: 480
    title: qsTr("Client Management")

    Text {
        text: "Welcome to the Client Management system!"
    }
}
```

保存您的更改，并运行 qmake 并运行应用程序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/8a1da88e-5508-40df-b5f6-20da69d33968.png)

让我们让`MasterController`开始发挥作用，而不是在 UI 中硬编码我们的欢迎消息，我们将从我们的控制器动态获取它。

编辑`master-controller.h`，并添加一个名为`welcomeMessage`的新的`QString`类型的公共属性，并将其设置为初始值：

```cpp
QString welcomeMessage = "This is MasterController to Major Tom";
```

你还需要`#include <QString>`。

为了能够从 QML 访问此成员，我们需要配置一个新的属性。在 Q_OBJECT 宏之后但在第一个公共访问修饰符之前，添加以下内容：

```cpp
Q_PROPERTY( QString ui_welcomeMessage MEMBER welcomeMessage CONSTANT )
```

在这里，我们正在创建一个新的`QString`类型的属性，QML 可以访问。QML 将把属性称为`ui_welcomeMessage`，在调用时，将获取（或设置）`MEMBER`变量中称为`welcomeMessage`的值。我们明确地设置了变量的值，并且不会更改它，因此它将保持`CONSTANT`。

您可以简单地将属性命名为`welcomeMessage`，而不是`ui_welcomeMessage`。我个人偏好于明确地为仅用于 UI 消耗的事物添加 ui_ 前缀，以将其与成员变量和方法区分开。做适合您的事情。

返回`MasterView.qml`，我们将使用这个属性。将`Text`组件的`text`属性更改为以下内容：

```cpp
text: masterController.ui_welcomeMessage
```

注意 QML 编辑器如何识别`masterController`，甚至为其提供代码完成。现在，QML 不再显示字符串文字作为消息，而是访问我们在`main()`中注入到根上下文中的`MasterController`实例的`ui_welcomeMessage`属性，这将进而获取`welcomeMessage`成员变量的值。

构建和运行，现在您应该能够看到来自`MasterController`的消息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/fe3e204d-88f4-4203-9859-f16bde93e547.png)

我们现在有了一个让 QML 调用 C++代码并获取我们想要提供的任何数据和业务逻辑的工作机制。在这里，需要注意的一点是我们的`MasterController`对`MasterView`的存在一无所知，这是 MVC 模式的关键部分。

# 项目输出

为了让我们的`cm-ui`项目知道在哪里找到`cm-lib`的实现，我们在项目文件中使用了`LIBS`变量。这是一个相当丑陋的文件夹名，但只有一行，一切都运行得很完美，所以很容易就会让事情保持原样。然而，期待着当我们准备好为测试或者生产制作我们的第一个构建时。我们编写了一些非常聪明的代码，一切都构建和运行得很好。我们将配置从 Debug 切换到 Release 然后...一切都垮掉了。问题在于我们在项目文件中硬编码了库路径，以便在`Debug`文件夹中查找。切换到不同的套件或另一个操作系统，问题会更糟，因为使用不同的编译器会导致二进制兼容性问题。

让我们设定一些目标：

+   摆脱笨重的`build-cm…`文件夹

+   将所有编译后的二进制输出聚合到一个共同的文件夹`cm/binaries`

+   将所有临时构建工件隐藏在它们自己的文件夹`cm/<project>/build`

+   为不同的编译器和架构创建单独的构建和二进制文件夹

+   自动检测这些编译器和架构

那么，这些有趣的长文件夹名字首先是从哪里来的呢？在 Qt Creator 中，点击导航栏中的项目模式图标。在左侧的构建和运行部分，选择桌面 Qt 5.9.0 MinGW 32 位 > 构建。在这里，您将看到此解决方案中 MinGW 套件的构建设置，并在影子构建复选框下，您将认出长的构建目录。

我们需要保持影子构建的启用，因为这使我们能够对不同的套件执行构建到替代位置的能力。我们将在`.pro`文件中控制我们构建的确切输出，但我们仍然需要在这里指定一个构建目录，以使 Qt Creator 保持愉快。输入<Qt Projects>/shadow-builds。使用窗格顶部的下拉菜单重复此设置，为每个构建配置(Debug/Release/Profile)和您正在使用的所有套件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/09a8328e-26ef-439f-8546-7eb661821236.png)

在您的文件系统中，删除任何旧的`build-cm…`文件夹。右键单击解决方案文件夹并运行 qmake。qmake 完成后，您应该看到`cm-lib`，`cm-tests`和`cm-ui`文件夹已经在<Qt Projects>/shadow-builds 中创建，并且长的`build-cm…`文件夹没有重新出现。

动态设置任何相对路径的第一步是知道您当前所在的路径。我们已经在 qmake 中看到了`$$PWD`的作用，以获取项目工作目录。为了帮助我们可视化正在发生的事情，让我们介绍我们的第一个 qmake 函数——`message()`。

在`cm.pro`中添加以下行——放在文件的任何位置都可以：

```cpp
message(cm project dir: $${PWD})
```

在`cm-lib.pro`中添加以下行：

```cpp
message(cm-lib project dir: $${PWD})
```

`message()`是 qmake 支持的测试函数，它将提供的字符串参数输出到控制台。请注意，您不需要用双引号括起文本。当您保存更改时，您将看到解决方案项目和库项目的**项目工作目录**（**PWD**）被记录到 General Messages 控制台中：

`Project MESSAGE: cm project dir: C:/projects/qt/cm`

`Project MESSAGE: cm-lib project dir: C:/projects/qt/cm/cm-lib`

qmake 实际上会对`.pro`文件进行多次处理，因此每当您使用`message()`时，您可能会在控制台中看到相同的输出多次。您可以使用`message()`与作用域一起来过滤掉大部分重复的内容——`!build_pass:message(Here is my message)`。这可以防止在构建过程中调用`message()`方法。

如果我们回顾 Qt Creator 对于影子构建的默认行为，我们会发现其目的是允许多个构建并存。这是通过构建包含工具包、平台和构建配置的不同文件夹名称来实现的：

`build-cm-solution-Desktop_Qt_5_10_0_MinGW_32bit-Debug`

仅通过查看文件夹名称，您就可以看出其中的内容是使用 Qt 5.10.0 为 Desktop MinGW 32 位工具包在调试模式下构建的**cm**项目。我们现在将以更清晰和更灵活的方式重新实施这种方法。

我们将更喜欢一个分层结构，包括`操作系统 > 编译器 > 处理器架构 > 构建配置`文件夹，而不是将信息连接成一个很长的文件夹名称。

首先硬编码此路径，然后再进行自动化。编辑`cm-lib.pro`并添加以下内容：

```cpp
DESTDIR = $$PWD/../binaries/windows/gcc/x86/debug
message(cm-lib output dir: $${DESTDIR})
```

这是为了反映我们正在使用 MinGW 32 位工具包在 Windows 上以调试模式构建。如果您使用不同的操作系统，请将*Windows*替换为*osx*或*Linux*。我们在 General Messages 控制台中添加了另一个`message()`调用以输出此目标目录。请记住，`$$PWD`提取正在处理的`.pro`文件（在本例中为`cm-lib.pro`）的工作目录，因此这给了我们`<Qt Projects>/cm/cm-lib`。

右键单击`cm-lib`项目，运行 qmake 并构建。确保选择了 MinGW 工具包以及调试模式。

在文件系统中导航到`<Qt Projects>/cm/binaries/<OS>/gcc/x86/debug`，您将看到我们的库二进制文件，而不会有构建工件的混乱。这是一个很好的第一步，但是如果您现在将构建配置更改为 Release 或切换工具包，目标目录将保持不变，这不是我们想要的。

我们即将实施的技术将在我们的三个项目中使用，因此我们不必在所有的`.pro`文件中重复配置，让我们将配置提取到一个共享文件中并进行包含。

在根目录`cm`文件夹中，创建两个名为`qmake-target-platform.pri`和`qmake-destination-path.pri`的新空文本文件。在`cm-lib.pro`，`cm-tests.pro`和`cm-ui.pro`中添加以下行：

```cpp
include(../qmake-target-platform.pri)
include(../qmake-destination-path.pri)
```

在`*.pro`文件的顶部附近添加这些行。只要它们在设置`DESTDIR`变量之前，确切的顺序并不太重要。

编辑`qmake-target-platform.pri`如下：

```cpp
win32 {
    CONFIG += PLATFORM_WIN
    message(PLATFORM_WIN)
    win32-g++ {
        CONFIG += COMPILER_GCC
        message(COMPILER_GCC)
    }
    win32-msvc2017 {
        CONFIG += COMPILER_MSVC2017
        message(COMPILER_MSVC2017)
        win32-msvc2017:QMAKE_TARGET.arch = x86_64
    }
}

linux {
    CONFIG += PLATFORM_LINUX
    message(PLATFORM_LINUX)
    # Make QMAKE_TARGET arch available for Linux
    !contains(QT_ARCH, x86_64){
        QMAKE_TARGET.arch = x86
    } else {
        QMAKE_TARGET.arch = x86_64
    }
    linux-g++{
        CONFIG += COMPILER_GCC
        message(COMPILER_GCC)
    }
}

macx {
    CONFIG += PLATFORM_OSX
    message(PLATFORM_OSX)
    macx-clang {
        CONFIG += COMPILER_CLANG
        message(COMPILER_CLANG)
        QMAKE_TARGET.arch = x86_64
    }
    macx-clang-32{
        CONFIG += COMPILER_CLANG
        message(COMPILER_CLANG)
        QMAKE_TARGET.arch = x86
    }
}

contains(QMAKE_TARGET.arch, x86_64) {
    CONFIG += PROCESSOR_x64
    message(PROCESSOR_x64)
} else {
    CONFIG += PROCESSOR_x86
    message(PROCESSOR_x86)
}
CONFIG(debug, release|debug) {
    CONFIG += BUILD_DEBUG
    message(BUILD_DEBUG)
} else {
    CONFIG += BUILD_RELEASE
    message(BUILD_RELEASE)
}
```

在这里，我们利用了 qmake 的平台检测功能，将个性化标志注入`CONFIG`变量中。在每个操作系统上，不同的平台变量变得可用。例如，在 Windows 上，存在`win32`变量，Linux 由`linux`表示，Mac OS X 由`macx`表示。我们可以使用这些平台变量与花括号一起充当 if 语句：

```cpp
win32 {
    # This block will execute on Windows only…
}
```

我们可以考虑不同的平台变量组合，以确定当前选择的套件正在使用的编译器和处理器架构，然后向`CONFIG`添加开发人员友好的标志，以便稍后在我们的`.pro`文件中使用。请记住，我们正在尝试构建一个构建路径——`操作系统 > 编译器 > 处理器架构 > 构建配置`。

当你保存这些更改时，你应该会在通用消息控制台中看到类似以下的标志：

```cpp
Project MESSAGE: PLATFORM_WIN
Project MESSAGE: COMPILER_GCC
Project MESSAGE: PROCESSOR_x86
Project MESSAGE: BUILD_DEBUG
```

尝试切换套件或更改构建配置，你应该会看到不同的输出。当我将套件切换到 Visual Studio 2017 64 位的 Release 模式时，我现在得到了这个结果：

```cpp
Project MESSAGE: PLATFORM_WIN
Project MESSAGE: COMPILER_MSVC2017
Project MESSAGE: PROCESSOR_x64
Project MESSAGE: BUILD_RELEASE
```

在使用 MinGW 64 位套件的 Linux 机器上，我得到了这个结果：

```cpp
Project MESSAGE: PLATFORM_LINUX
Project MESSAGE: COMPILER_GCC
Project MESSAGE: PROCESSOR_x64
Project MESSAGE: BUILD_DEBUG
```

在使用 Clang 64 位的 Mac 上，我得到了以下结果：

```cpp
Project MESSAGE: PLATFORM_OSX
Project MESSAGE: COMPILER_CLANG
Project MESSAGE: PROCESSOR_x64
Project MESSAGE: BUILD_DEBUG
```

为了使其在 Windows 上工作，我不得不做一个假设，因为`QMAKE_TARGET.arch`在 MSVC2017 上没有正确检测到，所以我假设如果编译器是 MSVC2017，那么它必须是 x64，因为没有 32 位套件可用。

现在所有的平台检测都已完成，我们可以动态构建目标路径。编辑`qmake-destination-path.pri`：

```cpp
platform_path = unknown-platform
compiler_path = unknown-compiler
processor_path = unknown-processor
build_path = unknown-build

PLATFORM_WIN {
    platform_path = windows
}
PLATFORM_OSX {
    platform_path = osx
}
PLATFORM_LINUX {
    platform_path = linux
}

COMPILER_GCC {
    compiler_path = gcc
}
COMPILER_MSVC2017 {
    compiler_path = msvc2017
}
COMPILER_CLANG {
    compiler_path = clang
}

PROCESSOR_x64 {
    processor_path = x64
}
PROCESSOR_x86 {
    processor_path = x86
}

BUILD_DEBUG {
    build_path = debug
} else {
    build_path = release
}

DESTINATION_PATH = $$platform_path/$$compiler_path/$$processor_path/$$build_path
message(Dest path: $${DESTINATION_PATH})
```

在这里，我们创建了四个新变量——*platform_path*、*compiler_path*、*processor_path*和*build_path*——并为它们都分配了默认值。然后我们使用了在前一个文件中创建的`CONFIG`标志，并构建了我们的文件夹层次结构，将其存储在我们自己的变量`DESTINATION_PATH`中。例如，如果我们检测到操作系统是 Windows，我们会将`PLATFORM_WIN`标志添加到`CONFIG`中，从而将`platform_path`设置为`windows`。在 Windows 上切换套件和配置，我现在得到了这些消息：

```cpp
Dest path: windows/gcc/x86/debug
```

或者，我得到了这个结果：

```cpp
Dest path: windows/msvc2017/x64/release
```

在 Linux 上，我得到了以下结果：

```cpp
Dest path: linux/gcc/x64/debug
```

在 Mac OS 上，我得到了这个结果：

```cpp
Dest path: osx/clang/x64/debug
```

你可以将这些平台检测和目标路径创建技巧结合在一个文件中，但通过将它们分开，你可以在项目文件的其他地方使用这些标志。无论如何，我们现在正在根据我们的构建环境动态创建路径，并将其存储在一个变量中以供以后使用。

接下来要做的事情是将这个`DESTINATION_PATH`变量插入到我们的项目文件中。在这里，我们还可以使用相同的机制来构建我们的构建产物，通过添加几行代码。将以下内容添加到所有三个`*.pro`文件中，替换`cm-lib.pro`中已有的`DESTDIR`语句：

```cpp
DESTDIR = $$PWD/../binaries/$$DESTINATION_PATH
OBJECTS_DIR = $$PWD/build/$$DESTINATION_PATH/.obj
MOC_DIR = $$PWD/build/$$DESTINATION_PATH/.moc
RCC_DIR = $$PWD/build/$$DESTINATION_PATH/.qrc
UI_DIR = $$PWD/build/$$DESTINATION_PATH/.ui
```

临时构建产物现在将放置在构建文件夹内的离散目录中。

最后，我们可以解决最初导致我们来到这里的问题。在`cm-tests`和`cm-ui`中，我们现在可以使用我们新的动态目标路径设置`LIBS`变量：

```cpp
LIBS += -L$$PWD/../binaries/$$DESTINATION_PATH -lcm-lib
```

你现在可以右键单击`cm`项目，运行 qmake，并构建以自动构建所有三个子项目。所有的输出将被发送到正确的位置，库二进制文件可以很容易地被其他项目找到。你可以切换套件和配置，而不必担心引用错误的库。

# 总结

在本章中，我们将我们的项目创建技能提升到了一个新的水平，我们的解决方案现在开始成形。我们实现了 MVC 模式，并弥合了 UI 和业务逻辑项目之间的差距。我们尝试了我们的第一点 QML，并研究了 Qt 框架的基石 QObject。

我们移除了所有那些难看的`build-cm…`文件夹，展示了我们的 qmake 技巧，并控制了所有文件的位置。所有的二进制文件现在都放在`cm/binaries`文件夹中，按平台、编译器、处理器架构和构建配置进行组织。所有不需要的临时构建产物现在都被隐藏起来。我们可以自由切换套件和构建配置，并且我们的输出会自动重定向到正确的位置。

在第三章中，*用户界面*，我们将设计我们的 UI，并深入了解更多的 QML。


# 第三章：用户界面

在本章中，我们将更详细地了解 QML 并勾勒出我们的用户界面布局。我们将为所有屏幕创建占位视图，并实现一个在它们之间导航的框架。我们还将讨论这些视图中的内容，特别是如何以灵活和响应的方式锚定和调整元素的大小。我们将涵盖以下主题：

+   用户界面设计

+   创建视图

+   StackView 组件

+   锚定元素

+   调整元素大小

+   在视图之间导航

# UX

如果您曾经使用过其他声明性 UI 技术，如 HTML 和 XAML，它们通常采用父/子方法来处理 UI，即存在一个父视图或根视图，其中包含全局功能，例如顶级导航。然后有动态内容或子视图，根据需要切换并呈现上下文相关的命令。

我们将采用相同的方法，将我们的 MasterView 作为 UI 的根。我们将添加一个全局导航栏和一个内容窗格，我们可以根据需要添加和删除内容。子视图将可选择地呈现命令栏以执行操作，例如将记录保存到数据库。

让我们看看我们的基本布局目标：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/9f05c5d3-5098-498d-8980-8d761e081b46.png)

导航栏（**1**）将一直存在，并包含按钮，这些按钮将引导用户进入应用程序中的关键区域。默认情况下，该栏将很窄，并且与按钮相关的命令将由图标表示；然而，按下切换按钮将展开该栏，以显示每个按钮的附带描述文本。

内容窗格（**2**）将是一堆子视图。通过在内容窗格中替换子视图来导航到应用程序的不同区域。例如，如果我们在导航栏上添加一个新客户按钮并按下它，我们将把**新客户视图**推送到内容框架堆栈上。

命令栏（**3**）是一个可选元素，将用于向用户呈现更多的命令按钮。与导航栏的关键区别在于，这些命令将与当前视图相关，与上下文相关。例如，当创建新客户时，我们将需要一个保存按钮，但当我们搜索客户时，保存按钮就没有意义。每个子视图将可选择地呈现自己的命令栏。命令将由图标呈现，并在下面有一个简短的描述。 

现在让我们规划屏幕的流程，或者我们称之为视图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/88cb4886-bef2-4acf-8fec-17b997c55f39.png)

# 创建视图

在**cm-ui**中，右键单击`views.qrc`，然后选择添加新项…. 选择 Qt > QML 文件，然后单击选择…：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/ccb03d0d-cb3b-4bd8-ae67-41aa6e02c9c6.png)

在`cm-ui/ui/views`中创建`SplashView.qml`文件。重复此过程，直到创建了以下所有视图为止：

| **文件** | **目的** |
| --- | --- |
| `SplashView.qml` | 在加载 UI 时显示的占位视图。 |
| `DashboardView.qml` | 中央的“主页”视图。 |
| `CreateClientView.qml` | 用于输入新客户详细信息的视图。 |
| `EditClientView.qml` | 用于阅读/更新现有客户详细信息的视图。 |
| `FindClientView.qml` | 用于搜索现有客户的视图。 |

像之前一样在纯文本编辑器中编辑`views.qrc`。您会看到我们的新视图已经添加到了一个新的`qresource`块中，并且具有以下默认前缀：

```cpp
<RCC>
    <qresource prefix="/views">
        <file alias="MasterView">views/MasterView.qml</file>
    </qresource>
    <qresource prefix="/">
        <file>views/SplashView.qml</file>
        <file>views/DashboardView.qml</file>
        <file>views/CreateClientView.qml</file>
        <file>views/EditClientView.qml</file>
        <file>views/FindClientView.qml</file>
    </qresource>
</RCC>
```

还要注意，项目导航器有点混乱：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/6a8cda8d-a97a-4137-9b5e-b475274183ae.png)

将所有新文件移动到`“/views”`前缀块中，并删除`“/”`块。为每个新文件添加别名：

```cpp
<RCC>
    <qresource prefix="/views">
        <file alias="MasterView.qml">views/MasterView.qml</file>
        <file alias="SplashView.qml">views/SplashView.qml</file>
        <file alias="DashboardView.qml">views/DashboardView.qml</file>
        <file alias="CreateClientView.qml">views/CreateClientView.qml</file>
        <file alias="EditClientView.qml">views/EditClientView.qml</file>
        <file alias="CreateAppointmentView.qml">views/CreateAppointmentView.qml</file>
        <file alias="FindClientView.qml">views/FindClientView.qml</file>
    </qresource>
</RCC>
```

一旦保存了这些更改，您应该看到导航器变得整洁了：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/e95063e4-88c2-4ce9-8d72-943414f8359e.png)

# StackView

我们的子视图将通过**StackView**组件呈现，它提供了一个基于堆栈的导航模型，并内置了历史记录。当要显示新视图（在这种情况下，视图几乎可以是任何 QML）时，它们被推送到堆栈上，并且可以从堆栈中弹出，以返回到上一个视图。我们不需要使用历史记录功能，但它们是一个非常有用的功能。

要访问组件，我们首先需要引用该模块，因此在**MasterView**中添加导入：

```cpp
import QtQuick.Controls 2.2
```

完成后，让我们用`StackView`替换包含欢迎消息的**Text**元素：

```cpp
StackView {
    id: contentFrame
    initialItem: "qrc:/views/SplashView.qml"
}
```

我们为组件分配一个唯一标识符`contentFrame`，这样我们就可以在 QML 的其他地方引用它，并指定我们要默认加载的子视图——新的`SplashView`。

接下来，编辑`SplashView`。将`QtQuick`模块版本更新为 2.9，以便与**MasterView**匹配（如果没有明确说明，对所有后续的 QML 文件都要这样做）。这并不是严格必要的，但避免视图之间的不一致是一个好习惯。Qt 的次要版本发布通常不会有太多破坏性的变化，但是在两个引用不同版本 QtQuick 的视图上运行相同的代码可能会表现出不同的行为，这可能会引起问题。

现在我们对这个视图所做的就是让一个矩形的宽度为 400 像素，高度为 200 像素，具有“充满活力”的背景颜色，这样我们就可以看到它已经加载了：

```cpp
import QtQuick 2.9

Rectangle {
    width: 400
    height: 200
    color: "#f4c842"
}
```

颜色可以使用十六进制 RGB 值或命名的 SVG 颜色来指定，就像我们在这里做的一样。我通常觉得十六进制更容易，因为我永远记不住颜色的名称！

如果你将鼠标悬停在 Qt Creator 中的十六进制字符串上，你会得到一个非常有用的小弹出颜色样本。

现在运行应用程序，你会看到欢迎消息不再显示，取而代之的是一个绚丽的橙黄色矩形，这就是我们的**SplashView**。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/95abb8ea-4155-403a-85f6-5cd98845a7d4.png)

# 锚点

我们美妙的新**SplashView**有一个小问题，那就是它实际上并没有填满窗口。当然，我们可以将 400 x 200 的尺寸改为 1024 x 768，这样它就与**MasterView**匹配了，但是如果用户调整窗口大小会发生什么呢？现代 UI 都是响应式设计——动态内容可以适应呈现的显示器，因此为只适用于一个平台的硬编码属性并不理想。幸运的是，锚点来拯救我们了。

让我们利用我们可靠的旧**scratchpad**项目，看看锚点是如何运作的。

右键单击`qml.qrc`，在`scratchpad`文件夹中的`main.qml`文件旁边添加一个新的`AnchorsDemo.qml` QML 文件。不要担心子文件夹、`.qrc`前缀、别名或任何其他东西。

进入`main.cpp`，加载我们的新文件，而不是`main.qml`：

```cpp
engine.load(QUrl(QStringLiteral("qrc:/AnchorsDemo.qml")));
```

接下来，将以下代码粘贴到`AnchorsDemo`中：

```cpp
import QtQuick 2.9
import QtQuick.Window 2.2

Window {
    visible: true
    width: 1024
    height: 768
    title: qsTr("Scratchpad")
    color: "#ffffff"
    Rectangle {
        id: paleYellowBackground
        anchors.fill: parent
        color: "#cece9e"
    }
    Rectangle {
        id: blackRectangleInTheCentre
        width: 120
        height: 120
        anchors.centerIn: parent
        color: "#000000"
    }
    Rectangle {
        id: greenRectangleInTheCentre
        width: 100
        height: 100
        anchors.centerIn: parent
        anchors.verticalCenterOffset: 20
        color: "#008000"
    }
    Rectangle {
        id: redRectangleTopLeftCorner
        width: 100
        height: 100
        anchors {
            top: parent.top
            left: parent.left
        }
        color: "#800000"
    }
    Rectangle {
        id: blueRectangleTopLeftCorner
        width: 100
        height: 100
        anchors{
            top: redRectangleTopLeftCorner.bottom
            left: parent.left
        }
        color: "#000080"
    }
    Rectangle {
        id: purpleRectangleTopLeftCorner
        width: 100
        height: 100
        anchors{
            top: blueRectangleTopLeftCorner.bottom
            left: parent.left
            leftMargin: 20
        }
        color: "#800080"
    }
    Rectangle {
        id: turquoiseRectangleBottomRightCorner
        width: 100
        height: 100
        anchors{
            bottom: parent.bottom
            right: parent.right
            margins: 20
        }
        color: "#008080"
    }
}
```

构建和运行应用程序，你会看到这个相当令人困惑的景象：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/d9a0d9a2-5955-42c5-9096-0b79882dc347.png)

这一切乍一看可能有点令人困惑，如果你的颜色感知不够理想，我很抱歉，但我们所做的只是用不同的锚点值绘制一系列花哨的彩色矩形。让我们逐个矩形地走一遍，看看发生了什么：

```cpp
Rectangle {
    id: paleYellowBackground
    anchors.fill: parent
    color: "#cece9e"
}
```

我们的第一个矩形是沉闷的黄褐色背景；`anchors.fill: parent`告诉矩形填充其父级，无论大小如何。任何给定的 QML 组件的父级是包含它的 QML 组件——在层次结构中的下一个级别。在这种情况下，它是**Window**元素。**Window**元素是 1024 x 768 像素，所以矩形就是这么大。请注意，我们不需要为矩形指定宽度和高度属性，因为它们是从锚点中推断出来的。

这正是我们想要的**SplashView**的行为，但在我们回到主项目之前，让我们看看锚点的一些其他功能：

```cpp
Rectangle {
    id: blackRectangleInTheCentre
    width: 120
    height: 120
    anchors.centerIn: parent
    color: "#000000"
}
Rectangle {
    id: greenRectangleInTheCentre
    width: 100
    height: 100
    anchors.centerIn: parent
    anchors.verticalCenterOffset: 20
    color: "#008000"
}
```

我们将一起看接下来的两个矩形。首先是一个边长为 120 像素的黑色矩形；`anchors.centerIn: parent`将其定位在其父元素的中心。我们必须指定**width**和**height**，因为我们只是定位它，而不是调整大小。

接下来，我们有一个稍小一点的绿色矩形，也是在其父元素中居中。然后我们使用`anchors.verticalCenterOffset`属性将其向下移动 20 像素。用于定位的*x*，*y*坐标系统的根（0, 0）位于屏幕的左上角；`verticalCenterOffset`会增加 y 坐标。正数会将项目向下移动，负数会将项目向上移动。它的姐妹属性`horizontalCenterOffset`用于*x*轴的调整。

这里要注意的最后一件事是，矩形重叠，显示的是绿色矩形，黑色矩形被推到后面并被遮挡。同样，我们所有的小矩形都在大背景矩形的前面。QML 以自上而下的方式呈现，因此当根元素（**Window**）被绘制时，其子元素会从文件顶部到底部依次处理。因此，文件底部的项目将呈现在文件顶部的项目前面。如果你先把墙涂成白色，然后再涂成黑色，墙会变成黑色，因为那是最后涂的（呈现的）：

```cpp
Rectangle {
    id: redRectangleTopLeftCorner
    width: 100
    height: 100
    anchors {
        top: parent.top
        left: parent.left
    }
    color: "#800000"
}
```

接下来，我们画一个红色矩形，而不是一次性定位或调整整个矩形，我们只是锚定某些边。我们将其**top**边的锚点与其父元素（**Window**）的**top**边的锚点对齐。我们将其**left**边锚定到其父元素的**left**边。因此，它变成了与左上角“连接”起来。

我们必须输入以下内容：

```cpp
anchors.top: parent.top
anchors.left: parent.left
```

这里还有一个有用的语法糖，我们可以去掉重复的部分，并在花括号内设置`anchors`组的子属性：

```cpp
anchors {
    top: parent.top
    left: parent.left
}
```

接下来是蓝色矩形：

```cpp
Rectangle {
    id: blueRectangleTopLeftCorner
    width: 100
    height: 100
    anchors{
        top: redRectangleTopLeftCorner.bottom
        left: parent.left
    }
    color: "#000080"
}
```

这遵循相同的模式，不过这次我们不仅仅附加到其父元素，还要锚定到一个兄弟元素（红色矩形），我们可以通过`id`属性引用它：

```cpp
Rectangle {
    id: purpleRectangleTopLeftCorner
    width: 100
    height: 100
    anchors{
        top: blueRectangleTopLeftCorner.bottom
        left: parent.left
        leftMargin: 20
    }
    color: "#800080"
}
```

紫色矩形锚定在蓝色矩形的底部和窗口的左侧，但这里我们引入了第一个边距。每一边都有自己的边距，在这种情况下，我们使用`leftMargin`来给我们一个从左锚点的偏移，就像我们之前在`verticalCenterOffset`中看到的一样：

```cpp
Rectangle {
    id: turquoiseRectangleBottomRightCorner
    width: 100
    height: 100
    anchors{
        bottom: parent.bottom
        right: parent.right
        margins: 20
    }
    color: "#008080"
}
```

最后，我们的青绿色矩形利用了屏幕右侧的一些空白空间，并演示了如何使用`margins`属性同时设置四个边的边距。

请注意，所有这些绑定都是动态的。尝试调整窗口大小，所有的矩形都会自动适应。锚点是响应式 UI 设计的好工具。

让我们回到我们的`cm-ui`项目中的`SplashView`，并应用我们刚学到的知识。用更动态的`anchors.fill`属性替换固定的**width**和**height**属性：

```cpp
Rectangle {
    anchors.fill: parent
    color: "#f4c842"
}
```

现在，`SplashView`将填充其父元素。构建并运行，你会发现，我们原本期望的可爱多彩的矩形已经完全消失了。让我们看看为什么会这样。

# 大小

我们的矩形将填满其父元素，因此矩形的大小完全取决于其父元素的大小。沿着 QML 层次结构向上走，包含矩形的组件是**MasterView**中的`StackView`元素：

```cpp
StackView {
    id: contentFrame
    initialItem: Qt.resolvedUrl("qrc:/views/SplashView.qml")
}
```

通常，QML 组件足够聪明，可以根据它们的子元素自行调整尺寸。以前，我们将矩形设置为固定尺寸的 400 x 200。`StackView`可以查看并说：“我需要包含一个尺寸为 400 x 200 的**Rectangle**，所以我也会把自己做成 400 x 200。简单！”我们总是可以通过它的**width**和**height**属性来覆盖它，并将其设置为其他尺寸，但它可以计算出它想要的尺寸。

回到`scratchpad`，创建一个新的`SizingDemo.qml`视图，并编辑`main.cpp`以在启动时加载它，就像我们在`AnchorsDemo`中所做的那样。编辑`SizingDemo`如下：

```cpp
import QtQuick 2.9
import QtQuick.Window 2.2

Window {
    visible: true
    width: 1024
    height: 768
    title: qsTr("Scratchpad")
    color: "#ffffff"
    Column {
        id: columnWithText
        Text {
            id: text1
            text: "Text 1"
        }
        Text {
            id: text2
            text: "Text 2"
            width: 300
            height: 20
        }
        Text {
            id: text3
            text: "Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3"
        }
        Text {
            id: text4
            text: "Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4"
            width: 300
        }
        Text {
            id: text5
            text: "Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5"
            width: 300
            wrapMode: Text.Wrap
        }
    }
    Column {
        id: columnWithRectangle
        Rectangle {
            id: rectangle
            anchors.fill: parent
        }
    }
    Component.onCompleted: {
        console.log("Text1 - implicitWidth:" + text1.implicitWidth + " implicitHeight:" + text1.implicitHeight + " width:" + text1.width + " height:" + text1.height)
        console.log("Text2 - implicitWidth:" + text2.implicitWidth + " implicitHeight:" + text2.implicitHeight + " width:" + text2.width + " height:" + text2.height)
        console.log("Text3 - implicitWidth:" + text3.implicitWidth + " implicitHeight:" + text3.implicitHeight + " width:" + text3.width + " height:" + text3.height)
        console.log("Text4 - implicitWidth:" + text4.implicitWidth + " implicitHeight:" + text4.implicitHeight + " width:" + text4.width + " height:" + text4.height)
        console.log("Text5 - implicitWidth:" + text5.implicitWidth + " implicitHeight:" + text5.implicitHeight + " width:" + text5.width + " height:" + text5.height)
        console.log("ColumnWithText - implicitWidth:" + columnWithText.implicitWidth + " implicitHeight:" + columnWithText.implicitHeight + " width:" + columnWithText.width + " height:" + columnWithText.height)
        console.log("Rectangle - implicitWidth:" + rectangle.implicitWidth + " implicitHeight:" + rectangle.implicitHeight + " width:" + rectangle.width + " height:" + rectangle.height)
        console.log("ColumnWithRectangle - implicitWidth:" + columnWithRectangle.implicitWidth + " implicitHeight:" + columnWithRectangle.implicitHeight + " width:" + columnWithRectangle.width + " height:" + columnWithRectangle.height)
    }
}
```

运行这个，你会得到另一个充满无意义的屏幕：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/464111c3-4326-4a22-bf0e-9c51aed169f8.png)

对我们来说，更有趣的是控制台输出的内容：

`qml: Text1 - implicitWidth:30 implicitHeight:13 width:30 height:13`

`qml: Text2 - implicitWidth:30 implicitHeight:13 width:300 height:20`

`qml: Text3 - implicitWidth:1218 implicitHeight:13 width:1218 height:13`

`qml: Text4 - implicitWidth:1218 implicitHeight:13 width:300 height:13`

`qml: Text5 - implicitWidth:1218 implicitHeight:65 width:300 height:65`

`qml: ColumnWithText - implicitWidth:1218 implicitHeight:124 width:1218 height:124`

`qml: Rectangle - implicitWidth:0 implicitHeight:0 width:0 height:0`

`qml: ColumnWithRectangle - implicitWidth:0 implicitHeight:0 width:0 height:0`

那么，发生了什么？我们创建了两个**Column**元素，这是不可见的布局组件，可以垂直排列它们的子元素。我们用各种**Text**元素填充了第一个列，并在第二个列中添加了一个**Rectangle**。视图底部是一个 JavaScript 函数，当**Window**组件完成（即加载完成）时将执行。函数所做的就是写出视图上各个元素的`implicitWidth`、`implicitHeight`、`width`和`height`属性。

让我们逐个浏览元素和相应的控制台行：

```cpp
Text {
    id: text1
    text: "Text 1"
}
```

`qml: Text1 - implicitWidth:30 implicitHeight:13 width:30 height:13`

这个文本元素包含了一小段文本，我们没有指定任何尺寸。它的`implicitWidth`和`implicitHeight`属性是基于其内容所需的尺寸。它的`width`和`height`属性是元素实际的尺寸。在这种情况下，它会根据自己的需求调整尺寸，因为我们没有另外指定，所以它的`width`/`height`与`implicitWidth`/`implicitHeight`相同：

```cpp
Text {
    id: text2
    text: "Text 2"
    width: 300
    height: 20
}
```

`qml: Text2 - implicitWidth:30 implicitHeight:13 width:300 height:20`

对于`text2`，隐式尺寸与`text1`相同，因为内容几乎相同。然而，这次，我们明确告诉它宽度为 300，高度为 20。控制台告诉我们，元素按照指示进行，并且确实是那个尺寸：

```cpp
Text {
    id: text3
    text: "Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3 Text 3"
}
```

`qml: Text3 - implicitWidth:1218 implicitHeight:13 width:1218 height:13`

`text3`采取了与`text1`相同的不干涉方式，但内容是一段更长的文本。这次，`implicitWidth`要大得多，因为它需要适应长文本的空间。请注意，这实际上比窗口还要宽，文本被截断了。同样，我们没有另外指示，所以它自行调整尺寸：

```cpp
Text {
    id: text4
    text: "Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4 Text 4"
    width: 300
}
```

`qml: Text4 - implicitWidth:1218 implicitHeight:13 width:300 height:13`

`text4`有相同的冗长文本块，但这次我们告诉它我们想要的宽度。你会注意到，即使元素只有 300 像素宽，文本也能在整个窗口上都可见。内容溢出了容器的边界。你可以将`clip`属性设置为`true`来防止这种情况，但我们在这里并不太关心：

```cpp
Text {
    id: text5
    text: "Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 
    5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5   
    Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 
    5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5 Text 5"
    width: 300
    wrapMode: Text.Wrap
}
```

`qml: Text5 - implicitWidth:1218 implicitHeight:65 width:300 height:65`

`text5`重复了相同的长文本块，并将宽度限制为 300，但这次，我们通过将`wrapMode`属性设置为`Text.Wrap`来使事情更有条理。通过这个设置，启用的行为更像是你从一个文本块中期望的——它填满了可用的宽度，然后换行到下一行。元素的`implicitHeight`和因此`height`已增加以容纳内容。然而，请注意，`implicitHeight`仍然与之前相同；这仍然是控件希望的宽度，以便根据我们定义的约束来容纳其所有内容，而我们没有定义高度约束。

然后我们打印出包含所有这些文本的列的属性：

`qml: ColumnWithText - implicitWidth:1218 implicitHeight:124 width:1218 height:124`

需要注意的重要一点是，列能够计算出需要多宽和多高才能容纳所有子元素。

接下来，我们遇到了在`SplashView`中遇到的问题：

```cpp
Column {
    id: columnWithRectangle
    Rectangle {
        id: rectangle
        anchors.fill: parent
    }
}
```

在这里，我们遇到了一个鸡生蛋蛋生鸡的情况。`Column`试图计算出容纳其子元素所需的大小，因此它查看了`Rectangle`。`Rectangle`没有显式的大小信息，也没有自己的子元素，它只是设置为填充其父元素`Column`。两个元素都无法确定自己应该有多大，因此它们都默认为 0x0，这使它们变得不可见。

`qml: Rectangle - implicitWidth:0 implicitHeight:0 width:0 height:0`

`qml: ColumnWithRectangle - implicitWidth:0 implicitHeight:0 width:0 height:0`

多年来，元素的大小调整可能是我在 QML 中遇到的最困扰的问题。作为一般指导方针，如果您编写了一些 QML 但无法在屏幕上看到它呈现，那可能是一个大小问题。我通常发现，当调试时，给每个元素一个任意的固定**宽度**和**高度**是一个好的开始，然后逐个使尺寸动态化，直到重新创建问题。

有了这个知识，让我们回到`MasterView`并解决之前的问题。

将`anchors.fill: parent`添加到`StackView`组件：

```cpp
StackView {
    id: contentFrame
    anchors.fill: parent
    initialItem: Qt.resolvedUrl("qrc:/views/SplashView.qml")
}
```

`StackView`现在将填充其父级**Window**，我们已经明确给定了固定大小为 1024 x 768。再次运行应用程序，现在您应该有一个可爱的橙黄色的`SplashView`，它填满了屏幕，并且在调整窗口大小时可以愉快地调整大小：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/39e7344e-d964-43d5-ad69-841e8612c143.png)

# 导航

让我们快速在我们的`SplashView`中添加一个内容：

```cpp
Rectangle {
    anchors.fill: parent
    color: "#f4c842"
    Text {
        anchors.centerIn: parent
        text: "Splash View"
    }
}
```

这只是将视图的名称添加到屏幕上，因此当我们开始在视图之间移动时，我们知道我们正在查看哪一个。完成后，将`SplashView`的内容复制到所有其他新视图中，并更新每个视图中的文本以反映视图的名称，例如，在`DashboardView`中，文本可以说“Dashboard View”。

我们想要进行的第一次导航是当`MasterView`加载完成并且我们准备好进行操作时，加载`DashboardView`。我们可以使用我们刚刚看到的 QML 组件插槽之一`Component.onCompleted()`来实现这一点。

在`MasterView`中的根`Window`组件中添加以下行：

```cpp
Component.onCompleted: contentFrame.replace("qrc:/views/DashboardView.qml");
```

现在构建和运行时，一旦`MasterView`加载完成，它就会将子视图切换到`DashboardView`。这可能发生得如此之快，以至于您甚至不再看到`SplashView`，但它仍然存在。如果您的应用程序需要进行大量初始化，并且无法使用非阻塞 UI，那么拥有这样的启动视图是非常好的。这是一个方便的地方，可以放置公司标志和“Reticulating splines...”加载消息。是的，这是一个模拟人生的参考！

StackView 就像是你的网络浏览器中的历史记录。如果你访问[www.google.com](http://www.google.com)，然后访问[www.packtpub.com](http://www.packtpub.com)，你就是在将[www.packtpub.com](http://www.packtpub.com) *推送*到堆栈上。如果你在浏览器上点击返回，你就会回到[www.google.com](http://www.google.com)。这个历史记录可以包含多个页面（或视图），你可以通过它们向后和向前导航。有时你不需要历史记录，有时你甚至不希望用户能够返回。我们调用的`replace()`方法，正如其名称所示，会将一个新视图推送到堆栈上，并清除任何历史记录，这样你就无法返回。

在`Component.onCompleted`槽中，我们已经看到了如何直接从 QML 中导航到视图的示例。我们可以使用这种方法来进行应用程序的所有导航。例如，我们可以添加一个按钮，让用户创建一个新的客户，当点击时，直接将`CreateClientView`推送到堆栈上，如下所示：

```cpp
Button {
    onClicked: contentFrame.replace("qrc:/views/CreateClientView.qml")
}
```

对于 UX 设计或简单的 UI 重型应用程序，这是一个完全有效的方法。问题在于你的 QML 视图和组件变得非常紧密地耦合，而业务逻辑层对用户的操作一无所知。很多时候，移动到应用程序的新屏幕并不像只是显示一个新视图那么简单。你可能需要更新状态机，设置一些模型，或者清除前一个视图中的一些数据。通过将所有的导航请求都通过我们的**MasterController**中转站，我们解耦了我们的组件，并获得了业务逻辑拦截点，以便执行任何必要的操作，并验证请求是否合适。

我们将通过从业务逻辑层发出信号并让我们的**MasterView**对其做出响应并执行过渡来请求导航到这些视图。我们不会在**MasterController**中添加这些功能，而是将导航的责任委托给`cm-lib`中的一个新控制器，因此在`cm/cm-lib/source/controllers`中创建一个名为`navigation-controller.h`的新头文件（没有实际的实现，所以我们不需要一个`.cpp`文件），并添加以下代码：

```cpp
#ifndef NAVIGATIONCONTROLLER_H
#define NAVIGATIONCONTROLLER_H

#include <QObject>

#include <cm-lib_global.h>
#include <models/client.h>

namespace cm {
namespace controllers {

class CMLIBSHARED_EXPORT NavigationController : public QObject
{
    Q_OBJECT

public:
    explicit NavigationController(QObject* _parent = nullptr)
        : QObject(_parent)
    {}

signals:
    void goCreateClientView();
    void goDashboardView();
    void goEditClientView(cm::models::Client* client);
    void goFindClientView();
};

}
}
#endif
```

我们创建了一个最小的类，它继承自`QObject`，并为我们的新视图实现了一个信号。请注意，我们不需要导航到**MasterView**或**SplashView**，因此没有相应的信号。当我们导航到`EditClientView`时，我们需要通知 UI 我们想要编辑哪个**Client**，因此我们将其作为参数传递。从业务逻辑代码的任何地方调用这些方法会向外界发出一个请求，说“我想去某个视图，请”。然后由 UI 层的**MasterView**来监视这些请求并做出相应的响应。请注意，业务逻辑层仍然对 UI 实现一无所知。如果没有人响应这个信号，也没关系；这不是双向通信。

每当你从`QObject`继承时，一定要记住`Q_OBJECT`宏，还有一个接受`QObject`父对象的重载构造函数。由于我们希望在这个项目之外（在 UI 项目中）使用这个类，我们还必须记住 CMLIBSHARED_EXPORT 宏。

我们在这里稍微展望了一下，并假设我们的 Client 类将在`cm::models`命名空间中，但 Qt 在我们创建项目时为我们添加的默认`Client`类并不在这个命名空间中，所以在继续之前让我们先修复这个问题。

**client.h**：

```cpp
#ifndef CLIENT_H
#define CLIENT_H

#include "cm-lib_global.h"

namespace cm {
namespace models {

class CMLIBSHARED_EXPORT Client
{
public:
    Client();
};

}}

#endif
```

`client.cpp`：

```cpp
#include "client.h"

namespace cm {
namespace models {

Client::Client()
{
}

}}
```

我们需要能够创建一个 NavigationController 的实例，并让我们的 UI 与它交互。出于单元测试的原因，将对象创建隐藏在某种对象工厂接口后面是一个很好的做法，但在这个阶段我们不关心这个，所以我们将简单地在**MasterController**中创建对象。让我们趁机在**MasterController**中添加私有实现（PImpl）习惯用法。如果你以前没有接触过 PImpl，它只是一种将所有私有实现细节从头文件中移出并放入定义中的技术。这有助于保持头文件尽可能短和干净，只包含对公共 API 的消费者必要的包含。将声明和实现替换为以下内容：

`master-controller.h`：

```cpp
#ifndef MASTERCONTROLLER_H
#define MASTERCONTROLLER_H

#include <QObject>
#include <QScopedPointer>
#include <QString>

#include <cm-lib_global.h>
#include <controllers/navigation-controller.h>

namespace cm {
namespace controllers {

class CMLIBSHARED_EXPORT MasterController : public QObject
{
    Q_OBJECT
    Q_PROPERTY( QString ui_welcomeMessage READ welcomeMessage CONSTANT )
    Q_PROPERTY( cm::controllers::NavigationController* ui_navigationController READ navigationController CONSTANT )

public:
    explicit MasterController(QObject* parent = nullptr);
    ~MasterController();

    NavigationController* navigationController();
    const QString& welcomeMessage() const;

private:
    class Implementation;
    QScopedPointer<Implementation> implementation;
};

}}
#endif
```

`master-controller.cpp`：

```cpp
#include "master-controller.h"

namespace cm {
namespace controllers {

class MasterController::Implementation
{
public:
    Implementation(MasterController* _masterController)
        : masterController(_masterController)
    {
        navigationController = new NavigationController(masterController);
    }

    MasterController* masterController{nullptr};
    NavigationController* navigationController{nullptr};
    QString welcomeMessage = "This is MasterController to Major Tom";
};

MasterController::MasterController(QObject* parent)
    : QObject(parent)
{
    implementation.reset(new Implementation(this));
}

MasterController::~MasterController()
{
}

NavigationController* MasterController::navigationController()
{
    return implementation->navigationController;
}

const QString& MasterController::welcomeMessage() const
{
    return implementation->welcomeMessage;
}

}}
```

你可能已经注意到，对于 NavigationController 的访问器方法，我们没有指定 cm::controllers 命名空间，但对于`Q_PROPERTY`我们做了。这是因为属性是由 UI QML 访问的，它不在`cm`命名空间的范围内执行，所以我们必须明确指定完全限定的名称。作为一个一般的经验法则，对于 QML 直接交互的任何东西，包括信号和插槽中的参数，都要明确指定命名空间。

接下来，我们需要在**cm-ui**项目中使用`main.cpp`注册新的`NavigationController`类，所以在现有的**MasterController**旁边添加以下注册：

```cpp
qmlRegisterType<cm::controllers::NavigationController>("CM", 1, 0, "NavigationController");
```

我们现在准备好让**MasterView**对这些导航信号做出反应。在`StackView`之前添加以下元素：

```cpp
Connections {
    target: masterController.ui_navigationController
    onGoCreateClientView: contentFrame.replace("qrc:/views/CreateClientView.qml")
    onGoDashboardView: contentFrame.replace("qrc:/views/DashboardView.qml")
    onGoEditClientView: contentFrame.replace("qrc:/views/EditClientView.qml", {selectedClient: client})
    onGoFindClientView: contentFrame.replace("qrc:/views/FindClientView.qml")
}
```

我们正在创建一个连接组件，绑定到我们的新**NavigationController**实例，它对我们添加的每个 go 信号做出反应，并通过`contentFrame`导航到相关视图，使用我们之前用于移动到仪表板的`replace()`方法。因此，每当**NavigationController**上触发`goCreateClientView()`信号时，我们的`Connections`组件上的`onGoCreateClientView()`插槽将被调用，并且`CreateClientView`将加载到名为`contentFrame`的**StackView**中。在`onGoEditClientView`的情况下，从信号传递了一个`client`参数，我们将该对象传递给一个名为`selectedClient`的属性，稍后我们将在视图中添加该属性。

在 QML 组件中，一些信号和插槽是自动生成并连接的，遵循约定。插槽的命名方式是`on[CapitalisedNameOfRelatedSignal]`。例如，如果有一个名为`mySplendidSignal()`的信号，那么相应的插槽将被命名为`onMySplendidSignal`。这些约定适用于我们的`NavigationController`和`Connections`组件。

接下来，让我们在**MasterView**中添加一个导航栏，带有一些占位按钮，以便我们可以尝试这些信号。

添加一个`Rectangle`来形成我们条的背景：

```cpp
Rectangle {
    id: navigationBar
    anchors {
        top: parent.top
        bottom: parent.bottom
        left: parent.left
    }
    width: 100
    color: "#000000"
}
```

这会在视图的左侧绘制一个宽度为 100 像素的黑色条。

我们还需要调整我们的`StackView`，以便为我们的条留出一些空间。我们不是填充其父级，而是将其四个边的三个边锚定到其父级，但将左侧与我们的条的右侧连接起来：

```cpp
StackView {
    id: contentFrame
    anchors {
        top: parent.top
        bottom: parent.bottom
        right: parent.right
        left: navigationBar.right
    }
    initialItem: Qt.resolvedUrl("qrc:/views/SplashView.qml")
}
```

现在，让我们在我们的导航`Rectangle`中添加一些按钮：

```cpp
 Rectangle {
    id: navigationBar
    …

    Column {
        Button {
            text: "Dashboard"
            onClicked: masterController.ui_navigationController.goDashboardView()
        }
        Button {
            text: "New Client"
            onClicked: masterController.ui_navigationController.goCreateClientView()
        }
        Button {
            text: "Find Client"
            onClicked: masterController.ui_navigationController.goFindClientView()
        }
    }

}
```

我们使用`Column`组件来为我们布局按钮，而不是必须单独将按钮锚定到彼此。每个按钮显示一些文本，当点击时，调用**NavigationController**上的一个信号。我们的`Connection`组件对信号做出反应，并为我们执行视图转换：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/aad6160f-75eb-4122-a0f4-1b1e6e5790dd.png)

太棒了，我们有一个功能完善的导航框架！然而，当你点击导航按钮时，导航栏会短暂消失然后再次出现。我们的**应用输出**控制台中也出现了“冲突的锚点”消息，这表明我们做了一些不太对的事情。在继续之前，让我们解决这些问题。

# 解决冲突

导航栏的问题很简单。如前所述，QML 的结构是分层的。这体现在元素的渲染方式上——首先出现的子元素首先被渲染。在我们的情况下，我们先绘制导航栏，然后再绘制内容框架。当**StackView**组件加载新内容时，默认情况下会应用花哨的过渡效果，使其看起来很漂亮。这些过渡效果可能导致内容移出控件的边界并覆盖在其下方的任何内容上。有几种方法可以解决这个问题。

首先，我们可以重新排列组件的渲染顺序，并将导航栏放在内容框架之后。这将在`StackView`的顶部绘制导航栏，而不管它的情况如何。第二个选项，也是我们将实现的选项，就是简单地设置**StackView**的`clip`属性：

```cpp
clip: true
```

这会裁剪任何超出控件边界的内容，并且不会渲染它。

下一个问题有点更加深奥。正如我们讨论过的，QML 开发过去几年中我遇到的最令人困惑的问题之一是组件的大小。我们使用的一些组件，比如**Rectangle**，本质上是视觉元素。如果它们的大小没有被定义，要么是直接使用`width/height`属性，要么是间接使用**anchors**，那么它们就不会被渲染。其他元素，比如**Connections**，根本不是视觉元素，大小属性是多余的。布局元素，比如**Column**，可能在一个轴上有固定的大小，但在另一个轴上是动态的。

大多数组件共同的一点是它们都继承自**Item**，而**Item**又直接继承自**QtObject**，它只是一个普通的**QObject**。就像 C++端的 Qt 框架为普通的**QObject**实现了很多默认行为一样，QML 组件通常为我们可以在这里利用的**Item**组件实现了默认行为。

在我们的子视图中，我们使用**Rectangle**作为根对象。这是有道理的，因为我们想要显示一个固定大小和颜色的矩形。然而，这对**StackView**造成了问题，因为它不知道自己应该有多大。为了提供这些信息，我们尝试将其锚定到其父级（**StackView**），但这又会引发自己的问题，与我们切换视图时**StackView**正在执行的过渡效果发生冲突。

我们摆脱这个困境的方法是，将子视图的根改为普通的**Item**。**StackView**组件具有处理**Item**组件的内部逻辑，并且会自动调整大小。然后，我们的**Rectangle**组件就成为了已经自动调整大小的**Item**组件的子组件，我们可以将其锚定到这个组件上：

```cpp
Item {
    Rectangle {
        ...
    }
}
```

这有点令人困惑，感觉像巫术一样，但这里的要点是，在你的自定义 QML 中，将**Item**作为根元素通常是一个好主意。继续在所有子视图中以这种方式添加根**Item**组件（但不包括**MasterView**）。

再次运行应用程序，现在你应该有流畅的过渡效果，并且控制台中没有警告消息。

# 总结

我们已经建立了一个灵活的、解耦的导航机制，并成功地在不同的视图之间进行了过渡。我们已经建立了导航栏的基本结构，并且在本章开头设计的工作内容窗格中工作。

让 UI 调用业务逻辑层发出信号，然后 UI 对此做出反应，可能看起来有点绕弯，但这种业务逻辑信号/UI 插槽设计带来了好处。它使 UI 模块化，因为视图不需要相互了解。它将导航逻辑保留在业务逻辑层，并使该层能够请求 UI 将用户导航到特定视图，而无需了解 UI 或视图本身的任何信息。关键是，它还为我们提供了拦截点，因此当用户请求导航到特定视图时，我们可以处理它并执行任何我们需要的额外处理，比如状态管理或清理。

在第四章*“样式”*中，我们将介绍共享样式组件，以及在完成动态命令栏的 UI 设计之前，介绍 QML 模块和图标。
