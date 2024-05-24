# C++ Qt6 跨平台开发（一）

> 原文：[`zh.annas-archive.org/md5/E50463D8611423ACF3F047AAA5FD4529`](https://zh.annas-archive.org/md5/E50463D8611423ACF3F047AAA5FD4529)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Qt 是一个跨平台应用程序开发框架，旨在为桌面、嵌入式和移动平台创建出色的软件应用程序和令人惊叹的用户界面。它为开发人员提供了一套出色的工具，用于设计和构建出色的应用程序，而无需担心平台依赖性。

在本书中，我们将专注于 Qt 6，这是 Qt 框架的最新版本。本书将帮助您创建用户友好且功能性的图形用户界面。您还将通过提供外观和感觉在不同平台上保持一致的更美观的应用程序，获得与竞争对手的优势。

想要构建跨平台应用程序并拥有交互式 GUI 的开发人员将能够通过这本实用指南将他们的知识付诸实践。本书提供了一种实践方法来实现概念和相关机制，让您的应用程序可以立即投入运行。您还将获得关键概念的解释，并通过示例获得完整的学习体验。

您将首先探索不同平台上的 Qt 框架。您将学习如何在不同平台上配置 Qt，了解不同的 Qt 模块，学习核心概念，以及了解它们如何用于构建高效的 GUI 应用程序。您将能够在不同平台上构建、运行、测试和部署应用程序。您还将学习如何自定义应用程序的外观和感觉，并开发一个支持翻译的应用程序。除了学习完整的应用程序过程，本书还将帮助您识别瓶颈，并了解如何解决这些问题以增强应用程序的性能。

通过本书的学习，您将能够在不同平台上构建和部署自己的 Qt 应用程序。

# 这本书适合谁

本书旨在面向希望构建基于 GUI 的应用程序的开发人员和程序员。它也适用于之前使用过 C++编码的软件工程师。入门门槛并不高，所以如果你了解基本的 C++和面向对象编程的概念，那么你就可以踏上这段旅程。

此外，本书还可以帮助中级 Qt 开发人员，他们希望在其他平台上构建和部署应用程序。希望开始学习 Qt 编程的工作专业人士或学生，以及对 Qt 新手程序员，都会发现本书很有用。

# 本书涵盖内容

*第一章*，*介绍 Qt 6*，将向您介绍 Qt，并描述如何在计算机上设置 Qt。通过本章的学习，读者将能够从源代码构建 Qt，并在他们选择的平台上开始学习。

*第二章*，*介绍 Qt Creator*，向您介绍了 Qt Creator 集成开发环境及其用户界面。本章还将教您如何在 Qt Creator 中创建和管理项目。您将学习如何使用 Qt Creator 开发一个简单的“Hello World”应用程序，并了解不同的快捷键和实用技巧。

*第三章*，*使用 Qt Widgets 进行 GUI 设计*，探讨了 Qt Widgets 模块。在这里，您将学习创建 GUI 所需的各种小部件。您还将了解布局、Qt Designer，并学习如何创建自定义控件。本章将帮助您使用 Qt 开发您的第一个 GUI 应用程序。

*第四章*，*Qt Quick 和 QML*，介绍了 Qt Quick 和 QML 的基础知识，Qt Quick Controls，Qt Quick Designer，Qt Quick Layouts 和基本的 QML 脚本。在本章中，您将学习如何使用 Qt Quick 控件以及如何将 C++代码与 QML 集成。通过本章的学习，您将能够使用 QML 创建具有流畅用户界面的现代应用程序。

*第五章*, *跨平台开发*，探讨了使用 Qt 进行跨平台开发。您将了解 Qt Creator 中的不同设置。在本章中，您将能够在您喜爱的桌面和移动平台上运行示例应用程序。

*第六章*, *信号和槽*，深入介绍了信号和槽机制。您将能够在不同的 C++类之间以及在 C++和 QML 之间进行通信。您还将了解事件、事件过滤器和事件循环。

*第七章*, *模型视图编程*，介绍了 Qt 中的模型/视图架构及其核心概念。在这里，您将能够编写自定义模型和委托。您可以使用这些内容在基于 Qt Widget 或 Qt Quick 的 GUI 应用程序上显示所需的信息。

*第八章*, *图形和动画*，介绍了 2D 图形和动画的概念。您将学习如何使用绘图 API 在屏幕上绘制不同的形状。我们还将讨论使用 Qt 的图形视图框架和场景图表示图形数据的可能性。本章将指导您创建引人注目的用户界面动画。本章还涉及状态机框架。

*第九章*, *测试和调试*，探讨了 Qt 应用程序的不同调试技术。您将在本章中了解单元测试和 Qt 测试框架。我们还将讨论如何在 Qt 测试中使用 Google 测试框架，并了解可用的 Qt 工具和 GUI 特定的测试技术。

*第十章*, *部署 Qt 应用程序*，讨论了软件部署的重要性。您将学习如何在各种平台上部署 Qt 应用程序，包括桌面和移动平台。您将了解可用的部署工具和创建安装程序包的步骤。

*第十一章*, *国际化*，介绍了国际化。Qt 提供了优秀的支持，可以将 Qt Widgets 和 Qt Quick 应用程序翻译成本地语言。在本章中，您将学习如何制作支持多语言的应用程序。您还将了解内置工具和制作翻译感知应用程序的各种考虑因素。

*第十二章*, *性能考虑*，介绍了性能优化技术以及如何在 Qt 编程环境中应用这些技术。在这里，我们将讨论不同的性能分析工具，以诊断性能问题，特别集中在 Windows 上可用的工具。在本章中，您将学习如何使用 QML Profiler 对性能进行分析并对代码进行基准测试。本章还将帮助您编写高性能优化的 QML 代码。

# 为了充分利用本书

我们将只使用开源软件，因此您不需要购买任何许可证。随着我们逐渐进行每一章，我们将介绍安装程序和详细信息。要安装所需的软件，您需要一个功能齐全的互联网连接和台式电脑或笔记本电脑。除此之外，在开始本书之前，没有特定的软件要求。

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/B16231_Preface_Table.jpg)

**重要提示**

对于 Android 设置，您将需要以下内容：

OpenJDK 8 (JDK-8.0.275.1)

Android SDK 4.0

NDK r21 (21.3.6528147)

Clang 工具链

Android OpenSSL

如果您使用本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库访问代码（链接在下一节中提供）。这样做将有助于避免与复制和粘贴代码相关的潜在错误。

所有代码示例都是在 Windows 平台上使用 Qt 6 进行测试的。如果您使用 Qt 5，可能会出现失败。但是，它们也应该适用于将来的版本发布。请确保您安装到计算机上的版本至少是 Qt 6.0.0 或更高版本，以便代码与本书兼容。

# 下载示例代码文件

您可以从 GitHub 上下载本书的示例代码文件，网址为[`github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp`](https://github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp)。此外，您还可以在上述 GitHub 链接中找到一些具有 C++17 特性的额外示例。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在此处下载：`static.packt-cdn.com/downloads/9781800204584_ColorImages.pdf`。

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。例如："通常，`exec()` 方法用于显示对话框。"

代码块设置如下：

```cpp

    QMessageBox messageBox;
    messageBox.setText("This is a simple QMessageBox.");
    messageBox.exec(); 
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cpp

    QMessageBox messageBox;
    messageBox.setText("This is a simple QMessageBox.");
    messageBox.exec(); 
```

任何命令行输入或输出都以以下形式书写：

```cpp
> lrelease *.ts
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单中的单词或对话框中的单词会以此形式出现在文本中。例如："最后一步是构建并运行应用程序。在 Qt Creator 中点击**运行**按钮。"

提示或重要说明

会显示为这样。


# 第一部分：基础知识

在本节中，您将学习框架的基础知识和演变，以及如何在不同平台上安装 Qt。在本节中，您将了解 Qt 的演变。然后，我们将继续使用最新版本的 Qt，即 Qt 6，构建我们的第一个示例程序。您将学习使用 Qt Creator 集成开发环境。本节将向您介绍 Qt Widgets、Qt Designer 和创建自定义控件。您将学习样式表、QSS 文件和主题。本节还将向您介绍 Qt Quick 和 QML。

本节包括以下章节：

+   *第一章*, *Qt 6 简介*

+   *第二章*, *Qt Creator 简介*

+   *第三章*, *使用 Qt Widgets 进行 GUI 设计*

+   *第四章*, *Qt Quick 和 QML*


# 第一章：介绍 Qt 6

**Qt**（发音为*cute*，而不是*que-tee*）是一个跨平台应用程序开发框架，旨在为桌面、嵌入式和移动平台创建具有统一**用户界面**（**UI**）的优秀软件应用程序。它为开发人员提供了一套强大的工具，设计和构建出色的应用程序，而无需担心平台依赖性。在本章中，您将学习有关该框架的基础知识、其历史以及如何在不同平台上安装 Qt。您将了解 Qt 是什么，以及为什么使用它是有益的。在本章结束时，您将能够安装 Qt 并在您选择的平台上开始使用。

在本章中，我们将涵盖以下主要主题：

+   介绍 Qt

+   使用 Qt 的原因

+   下载和安装 Qt

+   从源代码构建 Qt 6

# 技术要求

要开始使用，您应该有一台运行 Windows、Linux 或 macOS 的台式机或笔记本电脑。请使用更新的 Windows 10 或 Ubuntu 20.04 **长期支持**（**LTS**）。或者，使用最新版本的 macOS（高于 macOS 10.14），如 macOS Catalina。

为了使您的**集成开发环境**（**IDE**）运行顺畅，您的系统应至少配备英特尔酷睿 i5 处理器，以及至少 4**GB**的**随机存取存储器**（**RAM**）。

您需要有一个活动的互联网连接来下载和安装 Qt。作为先决条件，您还应该熟悉 C++，因为 Qt 需要 C++编程知识。

# 介绍 Qt

Qt 是一个用于桌面、嵌入式和移动平台的跨平台软件开发框架。它遵循*少写代码，创造更多，随处部署*的理念。它支持 Windows、Linux、macOS、VxWorks、QNX、Android、iOS 等平台。该软件还支持来自 NXP、Renesas 和 STMicroelectronics 的多个**微控制器单元**（**MCUs**），这些单元在裸机或 FreeRTOS 上运行。

Qt 诞生的初衷是为了提供统一的**图形用户界面**（**GUI**），在不同平台上具有相同的外观、感觉和功能。Qt 通过提供一个框架来编写代码一次，并确保它在其他平台上以最少或没有修改的方式运行来实现这一目标。它不是一种编程语言，而是用 C++编写的框架。Qt 框架和工具在开源和商业许可下都有双重许可。

Qt 使用模块化方法将相关功能组合在一起。Qt Essentials 是所有平台上 Qt 的基础。这些模块是通用的，对大多数基于 Qt 的应用程序都很有用。基本模块可供开源使用。Qt Essentials 模块的示例包括 Qt Core、Qt GUI、Qt QML、Qt Widgets 等。还有一些特定用途的附加模块，提供特定功能并带有特定的许可义务。附加模块的示例包括 Qt 3D、Qt Bluetooth、Qt Charts、Qt Data Visualization 等。此外，还有增值模块，如 Qt Automotive Suite、Qt for Device Creation 和 Qt for MCUs 等，可在商业许可下使用。

要了解更多关于不同 Qt 模块的信息，请访问[`doc.qt.io/qt-6/qtmodules.html`](https://doc.qt.io/qt-6/qtmodules.html)。

Qt 于 1995 年发布供公众使用。自那时以来，有许多改进和重大变化。Qt 6 是 Qt 的新主要版本。它的主要目标是为 2020 年及以后的要求做好准备，删除过时的模块，并更易于维护。基于这一重点，Qt 6 中存在着一些架构变化，可能会破坏与早期版本的某些程度的向后兼容性。

Qt 6 中的一些基本修改如下：

+   引入强类型

+   JavaScript 作为**Qt 建模语言**（**QML**）的可选功能

+   删除 QML 版本

+   在 QObject 和 QML 之间删除重复的数据结构

+   避免创建运行时数据结构

+   将 QML 编译成高效的 C++和本机代码

+   支持隐藏实现细节

+   更好地集成工具

既然我们已经介绍了基础知识，让我们来看看使用 Qt 的主要原因…

# 使用 Qt 的原因

Qt 是一个模块化的跨平台应用程序开发框架。关于 Qt 最大的误解是很多人认为它是一个 GUI 框架。然而，Qt 远不止是一个 GUI 框架。它不仅包括一个 GUI 模块，还包括一组模块，使应用程序开发更快速、更容易在各种平台上扩展。使用 Qt 的最大好处是它能够为各种平台提供可移植性。以下是使用 Qt 的一些优势：

+   您可以为您的客户创建令人难以置信的用户体验，并通过 Qt 提升您的公司品牌。

+   跨平台开发既节省时间又节省金钱。您可以使用相同的代码库针对多个平台进行开发。

+   Qt 以使 C++易于使用和访问而闻名。使用 Qt，开发人员可以轻松创建具有流畅 UI 的高性能、可扩展的应用程序。

+   由于开源模型，该框架是未来的保障，同时拥有一个伟大的生态系统。

+   它进一步支持不同的编程语言，是一个非常灵活和可靠的框架。因此，有很多大公司如 Adobe、微软、三星、AMD、惠普、飞利浦和 MathWorks 都在他们的应用程序中使用 Qt。许多开源项目如 VLC（以前称为 VideoLAN 客户端）、Open Broadcaster Software（OBS）和 WPS Office（其中 WPS 代表 Writer、Presentation 和 Spreadsheets）也是基于 Qt 构建的。

Qt 的核心价值如下所述：

+   跨平台性质

+   高度可扩展

+   非常易于使用

+   内置世界一流的应用程序编程接口（API）、工具和文档

+   可维护、稳定和兼容

+   庞大的用户社区

无论您是业余爱好者、学生还是为公司工作，Qt 都提供了很大的灵活性，可以根据您的需求使用其模块。许多大学正在将 Qt 作为他们的课程科目之一。因此，Qt 是程序员开始构建具有现成功能的新应用程序的绝佳选择。让我们从在您的计算机上下载并安装 Qt 6 开始。

# 下载和安装 Qt

有多种方式可以在您的系统上安装 Qt 框架和工具。您可以从 Qt 网站下载在线或离线安装程序，也可以自己构建源代码包。Qt 建议首次安装使用在线安装程序，以及使用 Qt Maintenance Tool 进行后续安装的修改。

安装程序允许您下载和安装以下组件：

+   Qt 库

+   Qt Creator IDE

+   文档和示例

+   Qt 源代码

+   附加模块

在线安装程序允许您根据所选择的许可证选择 Qt 的开源或商业版本、工具和附加模块进行安装。在线安装程序不包含 Qt 组件，但它是一个下载客户端，用于下载所有相关文件。下载完成后，您可以进行安装。您需要一个 Qt 帐户来下载和安装 Qt。商业 Qt 的评估版本为您提供免费试用期访问权限，包括所有商业套餐和官方 Qt 支持。安装程序要求您使用 Qt 帐户登录。如果您没有 Qt 帐户，可以在安装过程中注册。安装程序从 Qt 服务器获取附加到帐户的许可证，并根据您的许可证列出模块。如果您是 Qt 的新手，我们建议您从开源版本开始。

离线安装程序是一个特定于平台的软件包，其中包含了平台相关的所有 Qt 模块和附加组件。由于官方政策的变化，自 Qt 5.15 起不再提供开源离线安装程序。如果您有商业许可证，那么您可以在安装过程中提供凭据。您可以在您的**Qt 帐户**Web 门户中找到您的许可密钥。

您可以从以下链接下载：

+   **开源**：[`www.qt.io/download-open-source`](https://www.qt.io/download-open-source)

+   **商业**：[`www.qt.io/download`](https://www.qt.io/download)

+   **离线**：[`www.qt.io/offline-installers`](https://www.qt.io/offline-installers)

重要提示

Qt 公司为用户提供了双重许可选项。作为初学者，您可以从开源许可证开始探索 Qt。如果您为公司工作，那么请与您的经理或**信息技术**（**IT**）或法律团队讨论获取商业许可证或了解法律义务。您可以在[`www.qt.io/licensing/`](https://www.qt.io/licensing/)了解有关 Qt 许可的更多信息。

## 下载 Qt

让我们开始将 Qt 下载到您的计算机上，步骤如下：

1.  首先，访问[`www.qt.io/download`](https://www.qt.io/download)下载页面。

1.  单击右上角的“下载。尝试。购买。”按钮。您将在此处看到不同的下载选项。

1.  如果您想尝试商业版本，请单击“尝试 Qt”部分。如果您已经有 Qt 帐户，那么您可以在“现有客户”部分登录帐户。

1.  考虑到您是 Qt 的新手，我们将从开源版本开始。单击“转到开源”按钮，如下截图所示：![图 1.1 - Qt 网站下载选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_1.1_B16231.jpg)

图 1.1 - Qt 网站下载选项

1.  在下一个屏幕上，您将找到“下载 Qt 在线安装程序”按钮。单击它以继续到下载链接。

1.  网页将自动从浏览器中检测到底层平台详细信息，并向您显示“下载”文件夹。

接下来，让我们从 Windows 平台上的安装过程开始。

## 在 Windows 上安装 Qt

现在，让我们在 Windows 上开始安装过程！请按照以下步骤进行：

1.  您将在下载文件夹中找到一个名为`qt-unified-windows-x86-%VERSION%-online.exe`的文件。双击可执行文件，您将看到一个“欢迎”屏幕。

1.  单击“下一步”按钮，将出现凭据屏幕，要求您使用 Qt 帐户登录。如果您没有帐户，那么您可以在同一页上注册，如下截图所示：![图 1.2 - 安装程序的登录屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_1.2_B16231.jpg)

图 1.2 - 安装程序的登录屏幕

1.  在下一个屏幕上，您将看到与开源使用义务协议相关的选项。如果您使用商业许可证进行安装，您将不会看到此屏幕。单击第一个复选框，表示**我已阅读并批准使用开源 Qt 的义务**，并承认您不会将 Qt 用于商业目的。确保您阅读了协议中提到的条款和条件！然后，单击“下一步”按钮。

1.  下一个屏幕将为您提供与在 Qt Creator 中跟踪和共享匿名数据相关的选项。您可以根据自己的喜好允许或禁用这些选项。然后，单击“下一步”按钮，以继续到下一个屏幕。

1.  在下一个屏幕上，您可以指定安装路径。您可以继续使用默认路径，或者如果默认驱动器上没有足够的空间，可以更改为任何其他路径。您还可以选择是否要通过选择底部的复选框选项将常见文件类型与 Qt Creator 关联起来。单击“下一步”按钮。

1.  接下来，您将看到一个列表，您可以在其中选择要在系统上安装的 Qt 版本。您可以简单地使用默认选项。如果您不需要某些组件，则可以取消选择它们以减小下载的大小。您随时可以使用**维护工具**更新 Qt 组件。要完成安装过程，请点击**下一步**按钮。组件选择屏幕如下所示：![图 1.3 - 安装程序的组件选择屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_1.3_B16231.jpg)

图 1.3 - 安装程序的组件选择屏幕

1.  在下一个屏幕上，您将看到许可协议。点击第一个单选按钮，上面写着**我已阅读并同意许可协议中包含的条款**。再次确保您阅读了许可协议中提到的条款和条件，然后点击**下一步**按钮。

1.  在下一个屏幕上，您可以在 Windows 上创建**开始**菜单快捷方式。此屏幕将不适用于其他平台。完成后，点击**下一步**按钮。

1.  现在，Qt 已经准备好在您的系统中安装。确保您有可用的互联网连接和数据余额。点击**安装**按钮开始安装。下载过程将根据您的互联网速度而花费时间。一旦所需文件下载完成，安装程序将自动将它们安装在先前选择的路径中。

1.  安装完成后，安装程序将为**维护工具**创建一个条目，以后将帮助您对库进行更改。点击**下一步**按钮进入安装程序的最后一个屏幕。

1.  为了完成安装过程，点击**完成**按钮。如果您留下了**启动 Qt Creator**复选框选中，则 Qt Creator 将被启动。我们将在下一章中更详细地讨论这个问题。现在，Qt 已经准备好在您的 Windows 机器上使用。点击**完成**按钮退出向导。

## 在 Linux 上安装 Qt

现在，让我们在最新的**LTS 版本 Linux**上安装 Qt 框架，例如 Ubuntu 20.04、CentOS 8.1 或 openSUSE 15.1。我们将专注于最受欢迎的 Linux 发行版 Ubuntu。您可以按照之前提到的相同步骤从 Qt 网站下载在线安装程序。

在 Ubuntu 上，您将获得一个安装程序文件，例如`qt-unified-linux-x64-%VERSION%-online.run`，其中`%VERSION%`是最新版本，例如：`qt-unified-linux-x86-4.0.1-1-online.run`。

1.  在执行下载的文件之前，您可能需要给予写入权限。要做到这一点，打开终端并运行以下命令：

```cpp
$ chmod +x qt-unified-linux-x64-%VERSION%-online.run
```

1.  您可以通过双击下载的安装程序文件来开始安装过程。安装需要超级用户访问权限。在安装过程中，您可能需要在授权对话框中输入密码。您也可以从终端运行安装程序，如下所示：

```cpp
$ ./qt-unified-linux-x64-%VERSION%-online.run
```

1.  您将看到与 Windows 平台相似的屏幕。除了**操作系统**（**OS**）特定的标题栏更改外，所有屏幕在 Ubuntu 或类似的 Linux 版本中的安装过程中保持不变。

在撰写本书时，由于各自的维护者已经退出，Qt 6 在 Ubuntu 或 Debian 上没有可用的软件包。因此，您可能无法从终端获取 Qt 6 软件包。

## 在 macOS 上安装 Qt

如果您是 macOS 用户，您也可以按照之前讨论的方式进行安装。您可以按照之前提到的相同步骤从 Qt 网站下载在线安装程序。

您将获得一个安装程序文件，例如`qt-unified-mac-x64-%VERSION%-online.dmg`，其中`%VERSION%`是最新版本（例如`qt-unified-mac-x64-4.0.1-1-online.dmg`）。

Qt 依赖于 Xcode。要在 Mac 上安装 Qt，您需要在计算机上安装 Xcode，否则它将拒绝安装。如果您是苹果开发人员，则您的 Mac 可能已安装 Xcode。如果您的计算机上没有安装 Xcode，则可以继续安装 Xcode 的**命令行工具**而不是 Xcode。这将节省计算机上的时间和存储空间。

1.  首先，在终端上键入以下命令：

```cpp
$ xcode-select --install    
```

1.  如果终端显示以下输出，则您的系统已准备好进行下一步操作：

```cpp
xcode-select: error: command line tools are already installed, use
"Software Update" to install updates
```

1.  下一步是安装 Qt 框架。双击安装程序文件以启动安装界面。

1.  如果安装程序仍然抱怨 Xcode 未安装，则继续单击**确定**直到消息永久消失。记住安装路径。安装完成后，您就可以在计算机上使用 Qt 了。

在 macOS 上有关 Qt 的进一步说明可以在以下链接找到：

[`doc.qt.io/qt-6/macos.html`](https://doc.qt.io/qt-6/macos.html)

## 更新或删除 Qt

安装 Qt 后，您可以使用安装目录下的**维护工具**修改组件，包括更新、添加和删除组件。对于所有桌面平台，目录结构保持不变。安装目录包含文件夹和文件，如下屏幕截图所示（在 Windows 上）：

![图 1.4 - 安装文件夹中的维护工具](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_1.4_B16231.jpg)

图 1.4 - 安装文件夹中的维护工具

让我们开始维护过程！您可以使用**维护工具**添加、删除和更新模块。请按照以下步骤进行：

1.  单击`MaintenanceTool.exe`可执行文件以启动维护界面。单击**下一步**按钮，将出现凭据屏幕，要求您使用 Qt 帐户登录。登录详细信息将从上次登录会话中预填。您可以单击**下一步**以添加或更新组件，或选择**仅卸载**复选框以从系统中删除 Qt。以下屏幕截图显示了凭据屏幕的外观：![图 1.5 - 维护工具的欢迎屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_1.5_B16231.jpg)

图 1.5 - 维护工具的欢迎屏幕

1.  登录后，工具将向您提供添加、删除或更新组件的选项，如下屏幕截图所示。单击**下一步**按钮继续：![图 1.6 - 维护工具的设置屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_1.6_B16231.jpg)

图 1.6 - 维护工具的设置屏幕

1.  在下一个屏幕上，您可以从最新版本或存档版本中选择新组件。您可以单击**筛选器**按钮根据需要筛选版本。您还可以从组件列表中添加新的特定于平台的组件，例如 Android。如果组件已存在并取消选中它，则在更新期间将从桌面中删除它。选择组件后，单击**下一步**按钮。以下屏幕截图显示了组件选择屏幕的外观：![图 1.7 - 组件选择屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_1.7_B16231.jpg)

图 1.7 - 组件选择屏幕

1.  然后您将遇到更新屏幕。此屏幕将告诉您安装需要多少存储空间。如果存储空间不足，则可以返回并删除一些现有组件。单击**更新**按钮开始该过程，如下屏幕截图所示：![图 1.8 - 维护工具的准备更新屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_1.8_B16231.jpg)

图 1.8 - 维护工具的准备更新屏幕

1.  您可以通过单击**取消**按钮中止更新安装过程。Qt 会在中止安装过程之前警告您并要求确认，如下截图所示。一旦过程中止，单击**下一步**按钮退出向导：![图 1.9 – 取消对话框](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_1.9_B16231.jpg)

图 1.9 – 取消对话框

1.  再次启动**维护工具**，以从最新版本更新现有组件。您可以单击**退出**按钮退出**维护工具**。请等待安装程序从远程存储库获取元信息。单击**下一步**按钮查看可用组件。更新选项如下截图所示：![图 1.10 – 维护工具中的更新选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_1.10_B16231.jpg)

图 1.10 – 维护工具中的更新选项

1.  接下来，您可以从复选框中选择要更新的组件。您可以选择全部更新，也可以选择性更新。安装程序将显示更新所需的存储空间，如下截图所示。单击**下一步**进入更新屏幕并开始更新。然后，在下一个屏幕上，单击**更新**按钮下载更新包：![图 1.11 – 可用于更新的组件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_1.11_B16231.jpg)

图 1.11 – 可用于更新的组件

1.  安装完成后，安装程序会为维护工具创建条目，以帮助您稍后对库进行更改。如下截图所示。单击**下一步**按钮进入安装程序的最后一个屏幕：![图 1.12 – 维护工具中的更新完成屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_1.12_B16231.jpg)

图 1.12 – 维护工具中的更新完成屏幕

1.  在最后一个屏幕上，您将看到**重新启动**和**完成**按钮。单击**完成**按钮退出 Qt 向导。

1.  同样，您可以重新启动或启动**维护工具**，并选择**删除所有组件**单选按钮。单击**下一步**按钮开始卸载过程，如下截图所示：

![图 1.13 – 维护工具中的删除选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_1.13_B16231.jpg)

图 1.13 – 维护工具中的删除选项

请注意，单击**卸载**按钮后，所有 Qt 组件将从系统中删除；如果您想再次使用它们，您将需要重新安装 Qt。如果您不打算从系统中删除 Qt 组件，请单击**取消**，如下截图所示。如果您打算删除现有版本并使用更新版本的 Qt，则选择**添加或删除组件**选项，如前所述。这将删除旧的 Qt 模块并释放磁盘空间：

![图 1.14 – 维护工具中的卸载屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_1.14_B16231.jpg)

图 1.14 – 维护工具中的卸载屏幕

在本节中，我们了解了通过维护工具修改现有的 Qt 安装。现在，让我们学习如何从源代码构建和安装 Qt。

# 从源代码构建 Qt 6

如果您想自己构建框架和工具，或者尝试最新的未发布代码，那么您可以**从源代码构建 Qt**。如果您要从源代码开发特定的 Qt 版本，那么可以从官方发布链接下载 Qt 6 源代码，如下所示：[`download.qt.io/official_releases/qt/6.0/`](https://download.qt.io/official_releases/qt/6.0/).

如果您是商业客户，那么可以从 Qt 帐户门户下载**源代码包**。平台特定的构建说明将在接下来的小节中讨论。

您还可以从 GitHub 存储库克隆，并检出所需的分支。在撰写本书时，Qt 6 分支仍位于 Qt 5 超级模块内。您可以从以下链接克隆存储库：`git://code.qt.io/qt/qt5.git`。

`qt5.git`存储库可能会在未来更名为`qt.git`以便维护。请参考`QTQAINFRA-4200` Qt 票。有关如何从 Git 构建 Qt 的详细说明，请访问以下链接：[`wiki.qt.io/Building_Qt_6_from_Git`](https://wiki.qt.io/Building_Qt_6_from_Git)。

确保在您的机器上安装最新版本的 Git、Perl 和 Python。在进入下一节的特定于平台的说明之前，请确保有一个可用的 C++编译器。

## 在 Windows 上从源代码安装 Qt

要在 Windows 上从源代码安装 Qt 6，请按照以下步骤进行：

1.  首先，从 Git 或之前提到的开源下载链接下载源代码。您将得到一个压缩文件，名称为`qt-everywhere-src--%VERSION%.zip`，其中`%VERSION%`是最新版本（例如`qt-everywhere-src-6.0.3.zip`）。请注意，后缀如`-everywhere-src-`可能会在未来被移除。

1.  下载源代码存档后，将其解压缩到所需的目录，例如`C:\Qt6\src`。

1.  在下一步中，使用支持的编译器和所需的构建工具配置构建环境。

1.  然后，将`CMake`、`ninja`、`Perl`和`Python`的相应安装目录添加到您的`PATH`环境变量中。

1.  下一步是构建 Qt 库。要为您的机器配置 Qt 库，请在源目录中运行`configure.bat`脚本。

1.  在此步骤中，通过在命令提示符中输入以下命令来构建 Qt：

```cpp
>cmake --build . –parallel
```

1.  接下来，在命令提示符中输入以下命令以在您的机器上安装 Qt：

```cpp
>cmake --install .
```

您的 Windows 机器现在已经准备好使用 Qt。

要了解更多关于配置选项的信息，请访问以下链接：

[`doc.qt.io/qt-6/configure-options.html`](https://doc.qt.io/qt-6/configure-options.html)

详细的构建说明可以在以下链接找到：

[`doc.qt.io/qt-6/windows-building.html`](https://doc.qt.io/qt-6/windows-building.html)

## 在 Linux 上从源代码安装 Qt

要在 Linux 发行版上构建源包，请在终端上运行以下一组指令：

1.  首先，从 Git 或之前提到的开源下载链接下载源代码。您将得到一个压缩文件，名称为`qt-everywhere-src--%VERSION%.tar.xz`，其中`%VERSION%`是最新版本（例如`qt-everywhere-src-6.0.3.tar.xz`）。请注意，后缀如`-everywhere-src-`可能会在未来被移除。

1.  下载源代码存档后，解压缩存档并解压到所需的目录，例如`/qt6`，如下面的代码片段所示：

```cpp
$ cd /qt6
$ tar xvf qt-everywhere-opensource-src-%VERSION%.tar.xz 
$ cd /qt6/qt-everywhere-opensource-src-%VERSION%
```

1.  要为您的机器配置 Qt 库，请在源目录中运行`./configure`脚本，如下面的代码片段所示：

```cpp
$ ./configure
```

1.  要创建库并编译所有示例、工具和教程，请输入以下命令：

```cpp
$ cmake --build . --parallel
$ cmake --install .
```

1.  下一步是设置环境变量。在`.profile`（如果您的 shell 是`bash`、`ksh`、`zsh`或`sh`），添加以下代码行：

```cpp
PATH=/usr/local/Qt-%VERSION%/bin:$PATH
export PATH
```

在`.login`（如果您的 shell 是`csh`或`tcsh`），添加以下代码行：

```cpp
setenv PATH /usr/local/Qt-%VERSION%/bin:$PATH
```

如果您使用不同的 shell，请相应修改您的环境变量。Qt 现在已经准备好在您的 Linux 机器上使用。

Linux/X11 的详细构建说明可以在以下链接找到：

[`doc.qt.io/qt-6/linux-building.html`](https://doc.qt.io/qt-6/linux-building.html)

## 在 macOS 上从源代码安装 Qt

Qt 依赖于**Xcode**。要在 Mac 上安装 Qt，您需要在您的机器上安装 Xcode。如果您的机器上没有安装 Xcode，则可以继续安装 Xcode 的**命令行工具**：

1.  首先，在终端上输入以下命令：

```cpp
$ xcode-select --install    
```

1.  如果终端显示以下输出，则您的系统已准备好进行下一步：

```cpp
xcode-select: error: command line tools are already installed, use
"Software Update" to install updates
```

1.  要构建源包，请在终端上运行以下一组指令：

```cpp
$ cd /qt6
$ tar xvf qt-everywhere-opensource-src-%VERSION%.tar          
$ cd /qt6/qt-everywhere-opensource-src-%VERSION%
```

1.  要为您的 Mac 配置 Qt 库，请在源目录中运行`./configure`脚本，如下面的代码片段所示：

```cpp
$ ./configure  
```

1.  创建库，请运行`make`命令，如下所示：

```cpp
$ make
```

1.  如果`-prefix`在构建目录之外，则输入以下行以安装库：

```cpp
$ sudo make -j1 install
```

1.  下一步是设置环境变量。在`.profile`（如果您的 shell 是`bash`），添加以下代码行：

```cpp
PATH=/usr/local/Qt-%VERSION%/bin:$PATH
export PATH
```

在`.login`（如果您的 shell 是`csh`或`tcsh`），添加以下代码行：

```cpp
setenv PATH /usr/local/Qt-%VERSION%/bin:$PATH
```

您的计算机现在已准备好进行 Qt 编程。

macOS 的详细构建说明可以在这里找到：

[`doc.qt.io/qt-6/macos-building.html`](https://doc.qt.io/qt-6/macos-building.html)

在本节中，我们学习了如何在您喜爱的平台上从源代码安装 Qt。现在，让我们总结一下我们的学习。

# 摘要

本章介绍了 Qt 框架的基础知识以及它的用途。在这里，我们讨论了 Qt 的历史、不同的模块以及使用 Qt 的优势。我们还了解了不同的安装方法和许可义务，为不同的桌面平台上的 Qt 提供了逐步安装过程。现在，您的计算机已准备好探索 Qt。

在下一章中，我们将讨论 Qt Creator IDE。您将了解 IDE 的用户界面、不同的配置以及如何将其用于 Qt 项目。


# 第二章：Qt Creator 简介

**Qt Creator**是 Qt 自己的**集成开发环境**（**IDE**），用于跨平台应用程序开发。在本章中，您将学习 Qt Creator IDE 的基础知识，以及 IDE 的**用户界面**（**UI**）。我们还将看看如何在 Qt Creator 中创建和管理项目。Qt 的这个模块涵盖了使用 Qt Creator 开发简单 Qt 应用程序的内容，包括开发人员的快捷方式和实用技巧。

更具体地说，我们将涵盖以下主要主题：

+   Qt Creator 基础知识

+   配置 IDE 和管理项目

+   用户界面

+   编写一个示例应用程序

+   高级选项

Qt Creator 可以通过许多有用的工具和示例使您更轻松地学习 Qt。您只需要最少的 IDE 知识即可开始。在本章结束时，您将熟悉 Qt Creator 的使用。您还将能够在您喜爱的桌面平台上构建和运行您的第一个 Qt 应用程序，并了解 IDE 中可用的高级选项，您将能够根据自己的喜好进行自定义。

# 技术要求

本章的技术要求与*第一章**，Qt 6 简介*相同。您将需要最新的 Qt 版本，即 Qt 6.0.0 MinGW 64 位，Qt Creator 4.13.0 或更高版本，以及 Windows 10、Ubuntu 20.04 LTS 或最新版本的 macOS（至少高于 macOS 10.13），如 macOS Catalina。Qt 支持较早版本的操作系统，如 Windows 8.1 或 Ubuntu 18.04。但是，我们建议您升级到首选操作系统的最新版本，以确保顺畅运行。在本章中，我们使用了来自 Windows 10 平台的屏幕截图。

# 探索 Qt Creator UI

Qt Creator 是由 Qt 公司生产的 IDE。它集成了多个工具，包括代码编辑器、**图形用户界面**（**GUI**）设计器、编译器、调试器、Qt Designer、Qt Quick Designer 和 Qt Assistant 等。

Qt Designer 帮助设计基于小部件的 GUI，而 Qt Quick Designer 提供了一个 UI，可以在设计模式下创建和编辑基于 QML 的 GUI。Qt Assistant 是一个集成的文档查看器，可以通过按下*F1*键打开与给定 Qt 类或函数相关的内容。

让我们开始启动 Qt Creator。二进制文件可以在`Qt\Tools\QtCreator\bin`中找到。您将看到一个类似于*图 2.1*所示的屏幕：

![图 2.1 – Qt Creator 界面](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.1_B16231.jpg)

图 2.1 – Qt Creator 界面

您可以在 UI 中看到以下 GUI 部分：

1.  **IDE 菜单栏**：为用户提供了一个标准的窗口位置，以找到大多数应用程序特定功能。这些功能包括创建项目、打开和关闭文件、开发工具、分析选项、帮助内容以及退出程序的方法。

1.  **模式选择器**：此部分根据活动任务提供不同的模式。**欢迎**按钮提供打开示例、教程、最近的会话和项目的选项。**编辑**按钮打开代码窗口，并帮助导航项目。**设计**按钮根据 UI 文件的类型打开 Qt Designer 或 Qt Quick Designer。**调试**提供分析应用程序的选项。**项目**按钮帮助管理项目设置，**帮助**按钮用于浏览帮助内容。

1.  **套件选择器**：这有助于选择活动项目配置并更改套件设置。

1.  运行按钮：构建完成后，此按钮运行活动项目。

1.  **调试按钮**：这有助于使用调试器调试活动项目。

1.  构建按钮：用于构建活动项目。

1.  **定位器**：用于从任何打开的项目中打开文件。

1.  **输出窗格**：包括几个窗口，用于显示项目信息，如编译和应用程序输出。它还显示构建问题、控制台消息以及测试和搜索结果。

1.  **进度指示器**：此控件显示与运行任务相关的进度。

当您第一次启动 Qt Creator 时，您还可以从菜单栏中的**帮助** | **UI Tour**选项启动交互式 UI 导览，如*图 2.2*所示：

![图 2.2 – Qt Creator UI 导览菜单选择](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.2_B16231.jpg)

图 2.2 – Qt Creator UI 导览菜单选择

注意

如果按下*Alt*键，您将看到菜单标题中的下划线助记符字母。按下相应的键打开相应的上下文菜单。

在本节中，我们学习了 IDE 中的各个部分。在下一节中，我们将使用 Qt Creator IDE 构建一个简单的 Qt 应用程序。

# 构建一个简单的 Qt 应用程序

让我们从一个简单的*Hello World*项目开始。*Hello World*程序是一个非常简单的程序，显示**Hello World!**并检查 SDK 配置是否没有错误。这些项目使用最基本、非常简洁的代码。对于这个项目，我们将使用 Qt Creator 创建的项目骨架。

按照以下步骤构建您的第一个 Qt 应用程序：

1.  要在 Qt 中创建一个新项目，请单击菜单栏上的**文件**菜单选项，或按下*Ctrl* + *N*。或者，您也可以单击欢迎屏幕上的**+ 新建**按钮来创建一个新项目，如*图 2.3*所示：![图 2.3 – 新项目界面](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.3_B16231.jpg)

图 2.3 – 新项目界面

1.  接下来，您可以选择项目的模板。您可以创建不同类型的应用程序，包括控制台应用程序或 GUI 应用程序。您还可以创建非 Qt 项目以及库项目。在右上角的部分，您将看到一个下拉菜单，用于过滤特定于所需目标平台的模板。选择**Qt Widgets 应用程序**模板，然后单击**选择...**按钮：![图 2.4 – 项目模板界面](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.4_B16231.jpg)

图 2.4 – 项目模板界面

1.  在下一步中，您将被要求选择项目名称和项目位置。您可以通过单击**浏览...**按钮导航到所需的项目位置。然后单击**下一步**按钮，进入下一个屏幕：![图 2.5 – 新项目位置屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.5_B16231.jpg)

图 2.5 – 新项目位置屏幕

1.  您现在可以选择构建系统。默认情况下，将选择 Qt 自己的构建系统**qmake**。我们将在*第六章*中更多地讨论 qmake，*信号和槽*。点击**下一步**按钮，进入下一个屏幕：![图 2.6 – 构建系统选择屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.6_B16231.jpg)

图 2.6 – 构建系统选择屏幕

1.  接下来，您可以指定类信息和要自动生成项目骨架的基类。如果您需要一个带有`MainWindow`功能的桌面应用程序，比如`menubar`、`toolbar`和`statusbar`，那么在*第三章**,* *使用 Qt Widgets 进行 GUI 设计*中选择`QMainWindow`。点击**下一步**按钮，进入下一个屏幕：![图 2.7 – 源代码骨架生成屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.7_B16231.jpg)

图 2.7 – 源代码骨架生成屏幕

1.  在下一步中，您可以指定翻译的语言。Qt Creator 带有*Qt Linguist*工具，允许您将应用程序翻译成不同的语言。您现在可以跳过这一步。我们将在*第十一章*中讨论**国际化**（**i18n**），*国际化*。点击**下一步**按钮，进入下一个屏幕：![图 2.8 – 翻译文件创建屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.8_B16231.jpg)

图 2.8 - 创建翻译文件屏幕

1.  在下一步中，您可以选择一个套件来构建和运行您的项目。要构建和运行项目，至少必须激活并可选择一个套件。如果您期望的套件显示为灰色，则可能存在一些套件配置问题。当您为目标平台安装 Qt 时，通常会自动配置开发目标的构建和运行设置。单击复选框以选择其中一个桌面套件，例如**Desktop Qt 6.0.0 MinGW 64 位**。单击**下一步**按钮以继续到下一个屏幕：![图 2.9 - 套件选择屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.9_B16231.jpg)

图 2.9 - 套件选择屏幕

1.  版本控制允许您或您的团队将代码更改提交到集中系统，以便每个团队成员都可以获取相同的代码，而无需手动传递文件。您可以将项目添加到安装在您的计算机上的版本控制系统中。Qt 在 Qt Creator IDE 中支持多个版本控制系统。您可以通过选择**<None>**来跳过此项目的版本控制。单击**完成**按钮以完成项目创建：![图 2.10 - 项目管理屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.10_B16231.jpg)

图 2.10 - 项目管理屏幕

1.  现在您将在编辑器窗口的左侧看到生成的文件。单击任何文件以在编码窗口中打开它，这是 Qt Creator 中最常用的组件。代码编辑器用于**编辑**模式。您可以在此窗口中编写、编辑、重构和美化代码。您还可以修改字体、字体大小、颜色和缩进。我们将在本章后面的*理解* *高级选项*部分中了解更多信息：![图 2.11 - 生成的文件和代码编辑器窗口](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.11_B16231.jpg)

图 2.11 - 生成的文件和代码编辑器窗口

1.  现在您可以在项目文件夹中看到一个`.pro`文件。在当前项目中，`HelloWorld.pro`文件是项目文件。这包含了 qmake 构建应用程序所需的所有信息。此文件在项目创建期间自动生成，并以结构化方式包含相关详细信息。您可以在此文件中指定文件、资源和目标平台。如果对`.pro`文件内容进行任何修改，则需要再次运行 qmake，如*图 2.12*所示。让我们跳过修改此项目的内容：![图 2.12 - 项目文件的内容](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.12_B16231.jpg)

图 2.12 - 项目文件的内容

1.  您可以在编辑器窗口的左侧找到一个带有`.ui`扩展名的表单文件。双击打开`mainwindow.ui`文件。在这里，您可以看到文件在不同的界面下打开：Qt Designer。您可以看到模式选择面板已切换到**设计**模式。我们将在下一章中更多地讨论 Qt Designer。

1.  现在，将**Label**控件从**显示小部件**类别下拖动到右侧表单的中心，如*图 2.13*所示。

1.  接下来，双击您拖动的项目，并键入`Hello World!`。按下键盘上的*Enter*键或单击控件外的任何位置以保存文本：![图 2.13 - 设计师屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.13_B16231.jpg)

图 2.13 - 设计师屏幕

1.  最后一步是按下套件选择按钮下方的**运行**按钮。读者点击**运行**按钮后，项目将自动构建。Qt Creator 足够智能，可以确定需要先构建项目。您可以分别构建和运行应用程序。编译几秒钟后，您将看到一个带有文本“Hello World!”的窗口：

![图 2.14 - 示例 GUI 应用程序的显示输出](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.14_B16231.jpg)

图 2.14 - 示例 GUI 应用程序的显示输出

恭喜，您已经创建了您的第一个基于 Qt 的 GUI 应用程序！现在让我们探索 Qt Creator 中提供的不同高级选项。

# 理解高级选项

安装 Qt Creator 时，它会以默认配置安装。您可以自定义 IDE 并配置其外观或设置您喜欢的编码风格。

转到顶部菜单栏，单击**工具**选项，然后选择**选项...**。您将看到左侧边栏上可用类别的列表。每个类别都提供一组选项来自定义 Qt Creator。作为初学者，您可能根本不需要更改设置，但让我们熟悉一下可用的不同选项。我们将从管理工具包开始。

## 管理工具包

Qt Creator 可以自动检测已安装的 Qt 版本和可用的编译器。它将用于构建和运行项目的配置分组，以使它们跨平台兼容。这组配置被存储为一个工具包。每个工具包包含一组描述环境的参数，例如目标平台、编译器和 Qt 版本。

首先点击左侧边栏中的**Kits**选项。这将自动检测并列出可用的工具包，如*图 2.15*所示。如果任何工具包显示为黄色或红色警告标记，则表示配置中存在故障。在这种情况下，您可能需要选择正确的编译器和 Qt 版本。您还可以通过单击**添加**按钮来创建自定义工具包。如果要使用新工具包，则不要忘记单击**应用**按钮。我们将继续使用默认的桌面配置，如下所示：

![图 2.15 - Kits 配置屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.15_B16231.jpg)

图 2.15 - Kits 配置屏幕

现在让我们继续到**Kits**部分下的**Qt 版本**选项卡。

## Qt 版本

在此选项卡中，您可以看到系统上可用的 Qt 版本。理想情况下，版本会自动检测到。如果没有检测到，然后单击**添加...**按钮并浏览到 qmake 的路径以添加所需的 Qt 版本。Qt 使用其发布的定义编号方案。例如，Qt 6.0.0 表示 Qt 6.0 的第一个补丁版本，6 表示主要 Qt 版本。每个版本都对可接受的更改量有限制，以确保稳定的 API。Qt 试图在版本之间保持兼容性。但是，由于主要版本中的代码清理和架构更改，这并不总是可能：

![图 2.16 - 可用的 Qt 版本](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.16_B16231.jpg)

图 2.16 - 可用的 Qt 版本

重要提示

Qt 软件版本使用`主要.次要.补丁`的版本格式。主要版本可能会破坏二进制和源代码的向后兼容性，尽管可能会保持源代码兼容性。次要版本具有二进制和源代码的向后兼容性。补丁版本对二进制和源代码都具有向后和向前兼容性。

我们不会讨论**Kits**部分下的所有选项卡，因为其他选项卡需要对编译器、调试器和构建系统有所了解。如果您是一名经验丰富的开发人员，可以探索选项卡并根据需要进行更改。让我们继续到左侧边栏中的**环境**类别。

## 环境

此选项允许用户选择他们喜欢的语言和主题。默认情况下，Qt Creator 使用系统语言。它不支持许多语言，但大多数流行的语言都可用。如果您切换到不同的语言，然后单击**应用**按钮并重新启动 Qt Creator 以查看更改。请注意，这些**环境**选项与构建环境不同。您将看到一个类似于*图 2.17*的界面，如下所示：

![图 2.17 - 环境设置选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.17_B16231.jpg)

图 2.17 - 环境设置选项

你还会看到一个复选框，上面写着**启用高 DPI 缩放**。Qt Creator 在不同的操作系统上处理高**每英寸点数**（**DPI**）缩放的方式不同，具体如下：

+   在 Windows 上，Qt Creator 会检测默认的缩放因子并相应地使用它。

+   在 Linux 上，Qt Creator 将是否启用高 DPI 缩放的决定留给用户。这是因为有许多 Linux 发行版和窗口系统。

+   在 macOS 上，Qt Creator 强制 Qt 使用系统缩放因子进行 Qt Creator 缩放。

要覆盖默认方法，你可以切换复选框选项并点击**应用**按钮。更改将在重新启动 IDE 后生效。现在让我们来看看**键盘**选项卡。

## 键盘快捷键

**键盘**部分允许用户探索现有的键盘快捷键并创建新的快捷键。Qt Creator 有许多内置的键盘快捷键，对开发人员非常有用。如果你喜欢的快捷键缺失，你也可以创建自己的快捷键。你还可以为在列表中不出现的功能指定自己的键盘快捷键，比如在文本编辑器中选择单词或行。

一些日常开发中常用的快捷键列举如下：

![图 2.18 - 一些常用的键盘快捷键](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.18_B16231.jpg)

图 2.18 - 一些常用的键盘快捷键

快捷键按类别分组。要在列表中找到一个键盘快捷键，输入一个函数名或快捷键在`new`中：

图 2.19 - 键盘快捷选项

](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.19_B16231.jpg)

图 2.19 - 键盘快捷选项

前面的屏幕截图显示了关键字`new`的可用快捷键列表。你可以看到*Ctrl* + *N*用于创建新文件或项目。你也可以导入或导出`.kms`格式的键盘映射方案文件。

重要提示

内置的 Qt 快捷键比我们在这里讨论的要多得多。你可以在以下文章中了解更多关于快捷键的信息：

[`doc.qt.io/qtcreator/creator-keyboard-shortcuts.html`](https://doc.qt.io/qtcreator/creator-keyboard-shortcuts.html)

[`wiki.qt.io/Qt_Creator_Keyboard_Shortcuts`](https://wiki.qt.io/Qt_Creator_Keyboard_Shortcuts)

[`shortcutworld.com/Qt-Creator/win/Qt-Creator_Shortcuts`](https://shortcutworld.com/Qt-Creator/win/Qt-Creator_Shortcuts)

Qt Creator 的键盘快捷键和窗口管理器快捷键之间可能会发生冲突。在这种情况下，窗口管理器快捷键将覆盖 Qt Creator 快捷键。你也可以在窗口管理器中配置键盘快捷键。如果这受到限制，那么你可以改变 Qt Creator 的快捷键。现在，让我们继续下一个侧边栏类别。

## 文本编辑器

左侧边栏中的下一个类别是**文本编辑器**。在这里，你可以在第一个选项卡中选择颜色方案、字体和字体大小。下一个选项卡列出了**文本编辑器**中的不同行为。正如你在*图 2.20*中所看到的，Qt 在键盘上使用空格缩进来代替*Tab*键：

图 2.20 - 文本编辑器行为选项卡

](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.20_B16231.jpg)

图 2.20 - 文本编辑器行为选项卡

一些开发人员更喜欢制表符缩进而不是空格缩进。你可以在**C++**和**Qt Quick**设置中更改缩进行为。由于有专门的设置作为不同的侧边栏类别，所以**文本编辑器**中的这一部分在未来的版本中可能会被弃用。

你可以在**文件编码**组中找到当前文件的文件编码。要修改文件编码，从下拉菜单中选择**新编码**。要用新编码查看文件，点击**应用**按钮。

我们不会讨论所有侧边栏类别，因为那些都是非常高级的选项。一旦你学会了基础知识，你可以在以后探索它们。在下一节中，我们将讨论管理编码窗口。

## 分割编码窗口

您可以将编码窗口拆分并在同一屏幕或外部屏幕上查看多个文件。您可以以多种不同的方式同时查看多个文件（这些选项在菜单栏的**窗口**选项下可用）：

![图 2.21– 展示拆分屏幕选项的截图](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.21_B16231.jpg)

图 2.21– 展示拆分屏幕选项的截图

现在让我们讨论拆分编码窗口和删除拆分窗口的各种方法：

+   要将编码窗口分割为上下视图，请按*Ctrl* + *E*，然后按*2*，或在菜单栏中选择**窗口**选项，然后单击**拆分**选项。这将在当前活动窗口下方创建一个额外的编码窗口。

+   要将编码窗口分割为相邻视图，请选择**并排拆分**或按*Ctrl* + *E*，然后按*3*。并排拆分会在当前活动编码窗口的右侧创建视图。

+   要在独立窗口中打开编码窗口，请按*Ctrl* + *E*，然后按*4*，或选择**在新窗口中打开**。您可以将窗口拖到外部监视器上以方便使用。

+   要在拆分视图和独立编辑器窗口之间移动，请选择**下一个拆分**或按*Ctrl* + *E*，然后按*O*。

+   要删除拆分视图，请单击要删除的窗口，然后选择**删除当前拆分**，或按*Ctrl* + *E*，然后按*0*。

+   要删除所有拆分编码窗口，请选择**删除所有拆分**或按*Ctrl* + *E*，然后按*1*。

在本节中，您了解了如何拆分编码编辑器窗口。这在编码时同时引用多个代码文件时非常有用。在下一节中，我们将讨论 IDE 菜单栏中的**构建**菜单。

## 构建选项

在菜单栏中，您可以看到**构建**选项。如果单击该选项，那么您将看到各种构建选项，如*图 2.22*所示。在这里，您可以构建、重新构建或清理您的项目。在复杂的项目中，您可能有多个子项目。您可以单独构建子项目以减少总体构建时间：

![图 2.22 – 构建菜单选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.22_B16231.jpg)

图 2.22 – 构建菜单选项

Qt Creator 项目向导允许您在创建新项目时选择构建系统，包括 qmake、CMake 和 Qbs。它使开发人员可以自由地将 Qt Creator 用作代码编辑器，并控制构建项目时使用的步骤或命令。默认情况下，qmake 已安装并配置为您的新项目。您可以在以下链接了解有关使用其他构建系统的更多信息：[`doc.qt.io/qtcreator/creator-project-other.html`](https://doc.qt.io/qtcreator/creator-project-other.html)。

现在让我们讨论在哪里以及如何查找框架的文档。

## Qt Assistant

Qt Creator 还包括一个名为 Qt Assistant 的内置文档查看器。这真的很方便，因为你可以通过简单地将鼠标悬停在源代码中的类名上并按下*F1*键来查找某个 Qt 类或函数的解释。然后 Qt Assistant 将被打开，并显示与该 Qt 类或函数相关的文档。

![图 2.23 – 集成帮助界面](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_2.23_B16231.jpg)

图 2.23 – 集成帮助界面

Qt Assistant 还支持交互式帮助，并使您能够为 Qt 应用程序创建帮助文档。

注意

在 Windows 平台上，Qt Assistant 作为 Qt Creator 菜单栏上的一个菜单选项。在 Linux 发行版上，您可以打开终端，输入`assistant`，然后按*Enter*。在 macOS 上，它安装在`/Developer/Applications/Qt`目录中。

在本节中，我们了解了 Qt Assistant 和帮助文档。现在，让我们总结一下本章的要点。

# 总结

本章介绍了 Qt Creator IDE 的基本原理以及它可以用于什么。Qt Creator 是一个带有一套强大工具的集成开发环境。它帮助您轻松地为多个平台创建出色的 GUI 应用程序。开发人员不需要编写冗长的代码来创建一个简单的按钮，也不需要改变大量的代码来对齐文本标签 - 当我们设计 GUI 时，Qt Designer 会自动生成代码。我们只需点击几下就创建了一个 GUI 应用程序，并且还学习了 IDE 中各种高级选项，包括如何管理工具包和快捷键。内置的 Qt 助手提供了有用的示例，并可以帮助我们编写自己的文档。

在下一章中，我们将讨论使用 Qt 小部件进行 GUI 设计。在这里，您将学习不同的小部件，如何创建自己的 GUI 元素，以及如何创建自定义的 GUI 应用程序。


# 第三章：使用 Qt 小部件进行 GUI 设计

Qt 小部件是一个模块，提供了一组用于构建经典 UI 的用户界面（UI）元素。在本章中，您将介绍 Qt 小部件模块，并了解基本小部件。我们将看看小部件是什么，以及可用于创建图形 UI（GUI）的各种小部件。除此之外，您还将通过 Qt Designer 介绍布局，并学习如何创建自定义控件。我们将仔细研究 Qt 在设计时如何为我们提供时尚的 GUI。在本章开始时，您将了解 Qt 提供的小部件类型及其功能。之后，我们将逐步进行一系列步骤，并使用 Qt 设计我们的第一个表单应用程序。然后，您将了解样式表、Qt 样式表（QSS 文件）和主题。

本章将涵盖以下主要主题：

+   介绍 Qt 小部件

+   使用 Qt Designer 创建 UI

+   管理布局

+   创建自定义小部件

+   创建 Qt 样式表和自定义主题

+   探索自定义样式

+   使用小部件、窗口和对话框

在本章结束时，您将了解 GUI 元素及其相应的 C++类的基础知识，如何在不编写一行代码的情况下创建自己的 UI，以及如何使用样式表自定义 UI 的外观和感觉。

# 技术要求

本章的技术要求包括 Qt 6.0.0 MinGW 64 位，Qt Creator 4.14.0 和 Windows 10/Ubuntu 20.04/macOS 10.14。本章中使用的所有代码都可以从以下 GitHub 链接下载：[`github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter03`](https://github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter03)。

注意

本章中使用的屏幕截图来自 Windows 环境。您将在您的机器上基于底层平台看到类似的屏幕。

# 介绍 Qt 小部件

小部件是 GUI 的基本元素。它也被称为`QObject`。`QWidget`是一个基本小部件，是所有 UI 小部件的基类。它包含描述小部件所需的大多数属性，以及几何、颜色、鼠标、键盘行为、工具提示等属性。让我们在下图中看一下`QWidget`的继承层次结构：

![图 3.1 – QWidget 类层次结构](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.1_B16231.jpg)

图 3.1 – QWidget 类层次结构

大多数 Qt 小部件的名称都是不言自明的，并且很容易识别，因为它们以*Q*开头。以下是其中一些：

+   `QPushButton`用于命令应用程序执行特定操作。

+   `QCheckBox`允许用户进行二进制选择。

+   `QRadioButton`允许用户从一组互斥选项中只做出一个选择。

+   `QFrame`显示一个框架。

+   `QLabel`用于显示文本或图像。

+   `QLineEdit`允许用户输入和编辑单行纯文本。

+   `QTabWidget`用于在选项卡堆栈中显示与每个选项卡相关的页面。

使用 Qt 小部件的优势之一是其父子系统。从`QObject`继承的任何对象都具有父子关系。这种关系使开发人员的许多事情变得方便，例如以下内容：

+   当小部件被销毁时，由于父子关系层次结构，所有子项也会被销毁。这可以避免内存泄漏。

+   您可以使用`findChild()`和`findChildren()`找到给定`QWidget`类的子项。

+   `QWidget`中的子小部件会自动出现在父小部件内部。

典型的 C++程序在主函数返回时终止，但在 GUI 应用程序中我们不能这样做，否则应用程序将无法使用。因此，我们需要 GUI 一直存在，直到用户关闭窗口。为了实现这一点，程序应该在发生这种情况之前一直运行。GUI 应用程序等待用户输入事件。

让我们使用`QLabel`来显示一个简单 GUI 程序的文本，如下所示：

```cpp
#include <QApplication>
#include <QLabel>
int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QLabel myLabel;
    myLabel.setText("Hello World!");
    myLabel.show();
    return app.exec();
}
```

请记住将以下行添加到`helloworld.pro`文件中以启用 Qt Widgets 模块：

`QT += widgets`

在对`.pro`文件进行更改后，您需要运行`qmake`。如果您正在使用命令行，则继续执行以下命令：

```cpp
>qmake
>make
```

现在，点击**Run**按钮来构建和运行应用程序。很快您将看到一个显示**Hello World!**的 UI，如下截图所示：

![图 3.2 - 简单的 GUI 应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.2_B16231.jpg)

图 3.2 - 简单的 GUI 应用程序

您也可以在 Windows 命令行中运行应用程序，如下所示：

```cpp
>helloworld.exe
```

您可以在 Linux 发行版的命令行中运行应用程序，如下所示：

```cpp
$./helloworld
```

在命令行模式下，如果库未在应用程序路径中找到，您可能会看到一些错误对话框。您可以将 Qt 库和插件文件复制到二进制文件夹中以解决此问题。为了避免这些问题，我们将坚持使用 Qt Creator 来构建和运行我们的示例程序。

在这一部分，我们学习了如何使用 Qt Widgets 模块创建一个简单的 GUI。在下一节中，我们将探索可用的小部件，并使用 Qt Designer 创建 UI。

# 使用 Qt Designer 创建 UI

在我们开始学习如何设计自己的 UI 之前，让我们熟悉一下 Qt Designer 的界面。以下截图显示了**Qt Designer**的不同部分。在设计我们的 UI 时，我们将逐渐了解这些部分：

![图 3.3 - Qt Designer UI](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.3_B16231.jpg)

图 3.3 - Qt Designer UI

Qt Widgets 模块带有现成的小部件。所有这些小部件都可以在**Widget Box**部分找到。Qt 提供了通过拖放方法创建 UI 的选项。让我们通过简单地从**Widget Box**区域拖动它们并将它们放入**Form Editor**区域来探索这些小部件。您可以通过抓取一个项目，然后在预定区域上按下并释放鼠标或触控板来执行此操作。在项目到达**Form Editor**区域之前，请不要释放鼠标或触控板。

以下截图显示了**Widget Box**部分提供的不同类型的小部件。我们已经将几个现成的小部件，如**Label**、**Push Button**、**Radio Button**、**Check Box**、**Combo Box**、**Progress Bar**和**Line Edit**添加到**Form Editor**区域。这些小部件是非常常用的小部件。您可以在**Property Editor**中探索特定于小部件的属性：

![图 3.4 - 不同类型的 GUI 小部件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.4_B16231.jpg)

图 3.4 - 不同类型的 GUI 小部件

您可以通过在**Form**菜单下选择**Preview…**选项来预览您的 UI，如下截图所示，或者您可以按下*Ctrl* + *R*。您将看到一个带有 UI 预览的窗口：

![图 3.5 - 预览您的自定义 UI](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.5_B16231.jpg)

图 3.5 - 预览您的自定义 UI

您可以通过在**Form**菜单下选择**View C++ Code…**选项来查找 UI 的创建的 C++代码，如下截图所示。您将看到一个显示生成代码的窗口。您可以在创建动态 UI 时重用该代码：

![图 3.6 - 查看相应的 C++代码的选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.6_B16231.jpg)

图 3.6 - 查看相应的 C++代码的选项

在本节中，我们熟悉了 Qt Designer UI。您还可以在`.ui`文件中找到相同的界面。在下一节中，您将学习不同类型的布局以及如何使用它们。

# 管理布局

Qt 提供了一组方便的布局管理类，以自动安排另一个小部件中的子小部件，以确保 UI 保持可用。`QLayout`类是所有布局管理器的基类。您还可以通过重新实现`setGeometry()`、`sizeHint()`、`addItem()`、`itemAt()`、`takeAt()`和`minimumSize()`函数来创建自己的布局管理器。请注意，一旦布局管理器被删除，布局管理也将停止。

以下列表提供了主要布局类的简要描述：

+   `QVBoxLayout`将小部件垂直排列。

+   `QHBoxLayout`将小部件水平排列。

+   `QGridLayout`以网格形式布置小部件。

+   `QFormLayout`管理输入小部件及其关联标签的表单。

+   `QStackedLayout`提供了一个小部件堆栈，一次只有一个小部件可见。

`QLayout`通过从`QObject`和`QLayoutItem`继承来使用多重继承。`QLayout`的子类包括`QBoxLayout`、`QGridLayout`、`QFormLayout`和`QStackedLayout`。`QVBoxLayout`和`QHBoxLayout`是从`QBoxLayout`继承的，并添加了方向信息。

让我们使用 Qt Designer 模块来布置一些`QPushButtons`。

## QVBoxLayout

在`QVBoxLayout`类中，小部件垂直排列，并且它们在布局中从上到下对齐。此时，您可以做以下事情：

1.  将四个按钮拖放到**表单编辑器**上。

1.  重命名按钮并按下键盘上的*Ctrl*键选择按钮。

1.  在**表单**工具栏中，单击垂直布局按钮。您可以通过悬停在工具栏按钮上找到这个按钮，该按钮上写着**垂直布局**。

您可以在以下屏幕截图中看到按钮垂直排列在从上到下的方式：

![图 3.7 – 使用 QVBoxLayout 进行布局管理](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.7_B16231.jpg)

图 3.7 – 使用 QVBoxLayout 进行布局管理

您还可以通过 C++代码动态添加垂直布局，如下面的代码片段所示：

```cpp
    QWidget *widget = new QWidget;
    QPushButton *pushBtn1 = new QPushButton("Push Button 
                                            1");
    QPushButton *pushBtn2 = new QPushButton("Push Button 
                                            2");
    QPushButton *pushBtn3 = new QPushButton("Push Button 
                                            3");
    QPushButton *pushBtn4 = new QPushButton("Push Button 
                                            4");
    QVBoxLayout *verticalLayout = new QVBoxLayout(widget);
    verticalLayout->addWidget(pushBtn1);
    verticalLayout->addWidget(pushBtn2);
    verticalLayout->addWidget(pushBtn3);
    verticalLayout->addWidget(pushBtn4);
    widget->show ();
```

该程序演示了如何使用垂直布局对象。请注意，`QWidget`实例`widget`将成为应用程序的主窗口。在这里，布局直接设置为顶级布局。添加到`addWidget()`方法的第一个按钮占据布局的顶部，而最后一个按钮占据布局的底部。`addWidget()`方法将一个小部件添加到布局的末尾，带有拉伸因子和对齐方式。

如果您在构造函数中没有设置父窗口，那么您将不得不稍后使用`QWidget::setLayout()`来安装布局并将其重新设置为`widget`实例的父对象。

接下来，我们将看看`QHBoxLayout`类。

## QHBoxLayout

在`QHBoxLayout`类中，小部件水平排列，并且它们从左到右对齐。

现在我们可以做以下事情：

1.  将四个按钮拖放到**表单编辑器**上。

1.  重命名按钮并按下键盘上的*Ctrl*键选择按钮。

1.  在**表单**工具栏中，单击水平布局按钮。您可以通过悬停在工具栏按钮上找到这个按钮，该按钮上写着**水平布局**。

您可以在此屏幕截图中看到按钮水平排列在左到右的方式：

![图 3.8 – 使用 QHBoxLayout 进行布局管理](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.8_B16231.jpg)

图 3.8 – 使用 QHBoxLayout 进行布局管理

您还可以通过 C++代码动态添加水平布局，如下面的代码片段所示：

```cpp
    QWidget *widget = new QWidget;
    QPushButton *pushBtn1 = new QPushButton("Push 
                                           Button 1");
    QPushButton *pushBtn2 = new QPushButton("Push 
                                           Button 2");
    QPushButton *pushBtn3 = new QPushButton("Push 
                                           Button 3");
    QPushButton *pushBtn4 = new QPushButton("Push 
                                           Button 4");
    QHBoxLayout *horizontalLayout = new QHBoxLayout(
                                        widget);
    horizontalLayout->addWidget(pushBtn1);
    horizontalLayout->addWidget(pushBtn2);
    horizontalLayout->addWidget(pushBtn3);
    horizontalLayout->addWidget(pushBtn4);
    widget->show ();
```

上面的示例演示了如何使用水平布局对象。与垂直布局示例类似，`QWidget`实例将成为应用程序的主窗口。在这种情况下，布局直接设置为顶级布局。默认情况下，添加到`addWidget()`方法的第一个按钮占据布局的最左侧，而最后一个按钮占据布局的最右侧。您可以使用`setDirection()`方法在将小部件添加到布局时更改增长方向。

在下一节中，我们将看一下`QGridLayout`类。

## QGridLayout

在`QGridLayout`类中，通过指定行数和列数将小部件排列成网格。它类似于具有行和列的网格结构，并且小部件被插入为项目。

在这里，我们应该执行以下操作：

1.  将四个按钮拖放到**表单编辑器**中。

1.  重命名按钮并按下键盘上的*Ctrl*键选择按钮。

1.  在**表单**工具栏中，单击网格布局按钮。您可以在工具栏按钮上悬停，找到标有**以网格形式布局**的按钮。

您可以在以下截图中看到按钮以网格形式排列：

![图 3.9 - 使用 QGridLayout 进行布局管理](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.9_B16231.jpg)

图 3.9 - 使用 QGridLayout 进行布局管理

您还可以通过 C++代码动态添加网格布局，如下段代码所示：

```cpp
    QWidget *widget = new QWidget;
    QPushButton *pushBtn1 = new QPushButton(
                               "Push Button 1");
    QPushButton *pushBtn2 = new QPushButton(
                               "Push Button 2");
    QPushButton *pushBtn3 = new QPushButton(
                               "Push Button 3");
    QPushButton *pushBtn4 = new QPushButton(
                               "Push Button 4");
    QGridLayout *gridLayout = new QGridLayout(widget);
    gridLayout->addWidget(pushBtn1);
    gridLayout->addWidget(pushBtn2);
    gridLayout->addWidget(pushBtn3);
    gridLayout->addWidget(pushBtn4);
    widget->show();
```

上述代码段解释了如何使用网格布局对象。布局概念与前几节中的相同。您可以从 Qt 文档中探索`QFormLayout`和`QStackedLayout`布局。让我们继续下一节，了解如何创建自定义小部件并将其导出到 Qt 设计师模块。

# 创建自定义小部件

Qt 提供了现成的基本`QLabel`作为我们的第一个自定义小部件。自定义小部件集合可以有多个自定义小部件。

按照以下步骤构建您的第一个 Qt 自定义小部件库：

1.  要在 Qt 中创建新的自定义小部件项目，请单击菜单栏上的**文件菜单**选项或按下*Ctrl* + *N*。或者，您也可以单击**欢迎**屏幕上的**新建项目**按钮。选择**其他项目**模板，然后选择**Qt 自定义设计师小部件**，如下截图所示：![图 3.10 - 创建自定义小部件库项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.10_B16231.jpg)

图 3.10 - 创建自定义小部件库项目

1.  在下一步中，您将被要求选择项目名称和项目位置。单击`MyWidgets`以导航到所需的项目位置。然后，单击**下一步**按钮，进入下一个屏幕。以下截图说明了这一步骤：![图 3.11 - 创建自定义控件库项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.11_B16231.jpg)

图 3.11 - 创建自定义控件库项目

1.  在下一步中，您可以从一组套件中选择一个套件来构建和运行您的项目。要构建和运行项目，至少一个套件必须处于活动状态且可选择。选择默认的**桌面 Qt 6.0.0 MinGW 64 位**套件。单击**下一步**按钮，进入下一个屏幕。以下截图说明了这一步骤：![图 3.12 - 套件选择屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.12_B16231.jpg)

图 3.12 - 套件选择屏幕

1.  在这一步中，您可以定义自定义小部件类名称和继承详细信息。让我们使用类名`MyLabel`创建自己的自定义标签。单击**下一步**按钮，进入下一个屏幕。以下截图说明了这一步骤：![图 3.13 - 从现有小部件屏幕创建自定义小部件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.13_B16231.jpg)

图 3.13 - 从现有小部件屏幕创建自定义小部件

1.  在下一步中，您可以添加更多自定义小部件以创建一个小部件集合。让我们使用类名`MyFrame`创建自己的自定义框架。您可以在**描述**选项卡中添加更多信息，或者稍后进行修改。选中**小部件是一个容器**的复选框，以将框架用作容器。单击**下一步**按钮，进入下一个屏幕。以下截图说明了这一步骤：![图 3.14 - 创建自定义小部件容器](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.14_B16231.jpg)

图 3.14 - 创建自定义小部件容器

1.  在这一步中，您可以指定集合类名称和插件信息，以自动生成项目骨架。让我们将集合类命名为`MyWidgetCollection`。单击**下一步**按钮，进入下一个屏幕。以下截图说明了这一步骤：![图 3.15 - 指定插件和集合类信息的选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.15_B16231.jpg)

图 3.15 - 指定插件和集合类信息的选项

1.  下一步是将您的自定义小部件项目添加到已安装的版本控制系统中。您可以跳过此项目的版本控制。单击**完成**按钮以使用生成的文件创建项目。以下截图说明了这一步骤：![图 3.16 - 项目管理屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.16_B16231.jpg)

图 3.16 - 项目管理屏幕

1.  展开`mylabel.h`文件。我们将修改内容以扩展功能。在自定义小部件类名之前添加`QDESIGNER_WIDGET_EXPORT`宏，以确保在插入宏后将类正确导出到`#include <QtDesigner>`头文件中。以下截图说明了这一步骤：![图 3.17 - 修改创建的骨架中的自定义小部件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.17_B16231.jpg)

图 3.17 - 修改创建的骨架中的自定义小部件

重要提示

在一些平台上，构建系统可能会删除 Qt Designer 模块创建新小部件所需的符号，使它们无法使用。使用`QDESIGNER_WIDGET_EXPORT`宏可以确保这些符号在这些平台上被保留。这在创建跨平台库时非常重要。其他平台没有副作用。

1.  现在，打开`mylabelplugin.h`文件。您会发现插件类是从一个名为`QDesignerCustomWidgetInterface`的新类继承而来。这个类允许 Qt Designer 访问和创建自定义小部件。请注意，为了避免弃用警告，您必须按照以下方式更新头文件：

`#include <QtUiPlugin/QDesignerCustomWidgetInterface>`

1.  在`mylabelplugin.h`中会自动生成几个函数。不要删除这些函数。您可以在`name()`、`group()`和`icon()`函数中指定在 Qt Designer 模块中显示的值。请注意，如果在`icon()`中没有指定图标路径，那么 Qt Designer 将使用默认的 Qt 图标。`group()`函数在以下代码片段中说明：

```cpp
QString MyFramePlugin::group() const
{
    return QLatin1String("My Containers");
}
```

1.  您可以在以下代码片段中看到，`isContainer()`在`MyLabel`中返回`false`，在`MyFrame`中返回`true`，因为`MyLabel`不设计用来容纳其他小部件。Qt Designer 调用`createWidget()`来获取`MyLabel`或`MyFrame`的实例：

```cpp
bool MyFramePlugin::isContainer() const
{
    return true;
}
```

1.  要创建具有定义几何形状或其他属性的小部件，您可以在`domXML()`方法中指定这些属性。该函数返回`MyLabel`宽度为`100` `16`像素，如下所示：

```cpp
QString MyLabelPlugin::domXml() const
{
    return "<ui language=\"c++\" 
             displayname=\"MyLabel\">\n"
            " <widget class=\"MyLabel\" 
               name=\"myLabel\">\n"
            "  <property name=\"geometry\">\n"
            "   <rect>\n"
            "    <x>0</x>\n"
            "    <y>0</y>\n"
            "    <width>100</width>\n"
            "    <height>16</height>\n"
            "   </rect>\n"
            "  </property>\n"
            "  <property name=\"text\">\n"
            "   <string>MyLabel</string>\n"
            "  </property>\n"
            " </widget>\n"
            "</ui>\n";
}
```

1.  现在，让我们来看看`MyWidgets.pro`文件。它包含了`qmake`构建自定义小部件集合库所需的所有信息。您可以在以下代码片段中看到，该项目是一个库类型，并配置为用作插件：

```cpp
CONFIG      += plugin debug_and_release
CONFIG      += c++17
TARGET      = $$qtLibraryTarget(
              mywidgetcollectionplugin)
TEMPLATE    = lib
HEADERS     = mylabelplugin.h myframeplugin.h mywidgetcollection.h
SOURCES     = mylabelplugin.cpp myframeplugin.cpp \ 
                        mywidgetcollection.cpp
RESOURCES   = icons.qrc
LIBS        += -L. 
greaterThan(QT_MAJOR_VERSION, 4) {
    QT += designer
} else {
    CONFIG += designer
}
target.path = $$[QT_INSTALL_PLUGINS]/designer
INSTALLS    += target
include(mylabel.pri)
include(myframe.pri)
```

1.  我们已经完成了自定义小部件创建过程。让我们运行`qmake`并在`inside release`文件夹中构建库。在 Windows 平台上，您可以手动将创建的`mywidgetcollectionplugin.dll`插件库复制到`D:\Qt\6.0.0\mingw81_64\plugins\designer`路径。这个路径和扩展名在不同的操作系统上会有所不同：![图 3.18 - 生成自定义小部件库的选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.18_B16231.jpg)

图 3.18 - 生成自定义小部件库的选项

1.  我们已经创建了我们的自定义插件。现在，关闭插件项目，然后单击`D:\Qt\6.0.0\mingw81_64\bin`中的`designer.exe`文件。您可以在**自定义小部件**部分下看到`MyFrame`，如下面的屏幕截图所示。单击**创建**按钮或使用小部件模板。您还可以通过进行特定于平台的修改来将自己的表单注册为模板。让我们使用 Qt Designer 提供的小部件模板：![图 3.19–新表单屏幕中的自定义容器](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.19_B16231.jpg)

图 3.19–新表单屏幕中的自定义容器

1.  您可以在左侧的**小部件框**部分看到我们的自定义小部件，位于底部。将**MyLabel**小部件拖到表单中。您可以在**属性编辑器**下找到创建的属性，例如**multiLine**和**fontCase**以及**QLabel**属性，如下面的屏幕截图所示：

![图 3.20–在 Qt Designer 中可用的导出小部件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.20_B16231.jpg)

图 3.20–在 Qt Designer 中可用的导出小部件

您还可以在以下 Qt 文档链接中找到详细的带有示例的说明：

[`doc.qt.io/qt-6/designer-creating-custom-widgets.html`](https://doc.qt.io/qt-6/designer-creating-custom-widgets.html)

恭喜！您已成功创建了具有新属性的自定义小部件。您可以通过组合多个小部件来创建复杂的自定义小部件。在下一节中，您将学习如何自定义小部件的外观和感觉。

# 创建 Qt 样式表和自定义主题

在上一节中，我们创建了我们的自定义小部件，但是小部件仍然具有本机外观。Qt 提供了几种自定义 UI 外观和感觉的方法。用大括号`{}`分隔，并用分号分隔。

让我们看一下简单的`QPushButton`样式表语法，如下所示：

`QPushButton { color: green; background-color: rgb (193, 255, 216);}`

您还可以通过在 Qt Designer 中使用样式表编辑器来改变小部件的外观和感觉，方法如下：

1.  打开 Qt Designer 模块并创建一个新表单。将一个按钮拖放到表单上。

1.  然后，右键单击按钮或表单中的任何位置以获取上下文菜单。

1.  接下来，单击**更改样式表…**选项，如下面的屏幕截图所示：![图 3.21–使用 Qt Designer 添加样式表](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.21_B16231.jpg)

图 3.21–使用 Qt Designer 添加样式表

1.  我们使用了以下样式表来创建之前的外观和感觉。您还可以在**属性编辑器**中从`QWidget`属性中更改样式表：

```cpp
QPushButton {
    background-color: rgb(193, 255, 216);
    border-width: 2px;
    border-radius: 6;
    border-color: lime;
    border-style: solid;
    padding: 2px;
    min-height: 2.5ex;
    min-width: 10ex;
}
QPushButton:hover {
    background-color: rgb(170, 255, 127);
}
QPushButton:pressed {
    background-color: rgb(170, 255, 127);
    font: bold;
}
```

在上面的示例中，只有`Push Button`将获得样式表中描述的样式，而所有其他小部件将具有本机样式。您还可以为每个按钮创建不同的样式，并通过在样式表中提及它们的对象名称来将样式应用于相应的按钮，方法如下：

`QPushButton#pushButtonID`

重要提示

要了解更多关于样式表及其用法的信息，请阅读以下链接中的文档：

[`doc.qt.io/qt-6/stylesheet-reference.html`](https://doc.qt.io/qt-6/stylesheet-reference.html)

[`doc.qt.io/qt-6/stylesheet-syntax.html`](https://doc.qt.io/qt-6/stylesheet-syntax.html)

[`doc.qt.io/qt-6/stylesheet-customizing.html`](https://doc.qt.io/qt-6/stylesheet-customizing.html)

## 使用 QSS 文件

您可以将所有样式表代码组合在一个定义的`.qss`文件中。这有助于确保在所有屏幕中应用程序的外观和感觉保持一致。QSS 文件类似于`.css`文件，其中包含 GUI 元素的外观和感觉的定义，如颜色、背景颜色、字体和鼠标交互行为。它们可以使用任何文本编辑器创建和编辑。您可以创建一个新的样式表文件，使用`.qss`文件扩展名，然后将其添加到资源文件（`.qrc`）中。您可能并非所有项目都有`.ui`文件。GUI 控件可以通过代码动态创建。您可以将样式表应用于小部件或整个应用程序，如下面的代码片段所示。这是我们为自定义小部件或表单执行的方式：

```cpp
MyWidget::MyWidget(QWidget *parent)
    : QWidget(parent)
{
    setStyleSheet("QWidget { background-color: green }");
}
```

这是我们为整个应用程序应用的方式：

```cpp
#include "mywidget.h"
#include <QApplication>
#include <QFile>
int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QFile file(":/qss/default.qss");
    file.open(QFile::ReadOnly);
    QString styleSheet = QLatin1String(file.readAll());
    app.setStyleSheet(styleSheet);
    Widget mywidget;
    mywidget.show();
    return app.exec();
}
```

上述程序演示了如何为整个 Qt GUI 应用程序使用样式表文件。您需要将`.qss`文件添加到资源中。使用`QFile`打开`.qss`文件，并将自定义的 QSS 规则作为参数传递给`QApplication`对象上的`setStyleSheet()`方法。您会看到所有屏幕都应用了样式表。

在本节中，您了解了使用样式表自定义应用程序外观和感觉的方法，但还有更多改变应用程序外观和感觉的方法。这些方法取决于您的项目需求。在下一节中，您将了解自定义样式。

# 探索自定义样式

Qt 提供了几个`QStyle`子类，模拟 Qt 支持的不同平台的样式。这些样式可以在 Qt GUI 模块中轻松获得。您可以构建自己的`QStyle`来渲染 Qt 小部件，以确保它们的外观和感觉与本机小部件一致。

在 Unix 发行版上，您可以通过运行以下命令为您的应用程序获取 Windows 风格的用户界面：

```cpp
$./helloworld -style windows
```

您可以使用`QWidget::setStyle()`方法为单个小部件设置样式。

## 创建自定义样式

您可以通过创建自定义样式来自定义 GUI 的外观和感觉。有两种不同的方法可以创建自定义样式。在静态方法中，您可以子类化`QStyle`类并重新实现虚拟函数以提供所需的行为，或者从头开始重写`QStyle`类。通常使用`QCommonStyle`作为基类，而不是`QStyle`。在动态方法中，您可以子类化`QProxyStyle`并在运行时修改系统样式的行为。您还可以使用`QStyle`函数（如`drawPrimitive()`，`drawItemText()`和`drawControl()`）开发样式感知的自定义小部件。

这部分是一个高级的 Qt 主题。您需要深入了解 Qt 才能创建自己的样式插件。如果您是初学者，可以跳过本节。您可以在以下链接的 Qt 文档中了解有关 QStyle 类和自定义样式的信息：

[`doc.qt.io/qt-6/qstyle.html`](https://doc.qt.io/qt-6/qstyle.html)

## 使用自定义样式

在 Qt 应用程序中应用自定义样式有几种方法。最简单的方法是在创建`QApplication`对象之前调用`QApplication::setStyle()`静态函数，如下所示：

```cpp
#include "customstyle.h"
int main(int argc, char *argv[])
{
    QApplication::setStyle(new CustomStyle);
    QApplication app(argc, argv);
    Widget helloworld;
    helloworld.show();
    return app.exec();
}
```

您还可以将自定义样式作为命令行参数应用，方法如下：

```cpp
>./customstyledemo -style customstyle
```

自定义样式可能难以实现，但可能更快速和更灵活。QSS 易于学习和实现，但性能可能会受到影响，特别是在应用程序启动时，因为 QSS 解析可能需要时间。您可以选择适合您或您的组织的方法。我们已经学会了如何自定义 GUI。现在，让我们在本章的最后一节中了解小部件、窗口和对话框是什么。

# 使用小部件、窗口和对话框

小部件是可以显示在屏幕上的 GUI 元素。这可能包括标签、按钮、列表视图、窗口、对话框等。所有小部件在屏幕上向用户显示某些信息，并且大多数允许用户通过键盘或鼠标进行交互。

窗口是一个没有父窗口的顶级小部件。通常，窗口具有标题栏和边框，除非指定了任何窗口标志。窗口样式和某些策略由底层窗口系统确定。Qt 中一些常见的窗口类包括`QMainWindow`、`QMessageBox`和`QDialog`。主窗口通常遵循桌面应用程序的预定义布局，包括菜单栏、工具栏、中央小部件区域和状态栏。`QMainWindow`即使只是一个占位符，也需要一个中央小部件。主窗口中的其他组件可以被移除。*图 3.22*说明了`QMainWindow`的布局结构。我们通常调用`show()`方法来显示一个小部件或主窗口。

`QMenuBar`位于`QMainWindow`的顶部。您可以添加诸如`QMenuBar`之类的菜单选项，还有`QToolBar`。`QDockWidget`提供了一个可以停靠在`QMainWindow`内或作为顶级窗口浮动的小部件。中央小部件是主要的视图区域，您可以在其中添加您的表单或子小部件。使用子小部件创建自己的视图区域，然后调用`setCentralWidget()`：

![图 3.22 – QMainWindow 布局](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_3.22_B16231.jpg)

图 3.22 – QMainWindow 布局

重要提示

`QMainWindow`不应与`QWindow`混淆。`QWindow`是一个方便的类，表示底层窗口系统中的窗口。通常，应用程序使用`QWidget`或`QMainWindow`来构建 UI。但是，如果您希望保持最小的依赖关系，也可以直接渲染到`QWindow`。

对话框是用于提供通知或接收用户输入的临时窗口，通常具有`QMessageBox`是一种用于显示信息和警报或向用户提问的对话框类型。通常使用`exec()`方法来显示对话框。对话框显示为模态对话框，在用户关闭它之前是阻塞的。可以使用以下代码片段创建一个简单的消息框：

```cpp

    QMessageBox messageBox;
    messageBox.setText("This is a simple QMessageBox.");
    messageBox.exec(); 
```

重点是所有这些都是小部件。窗口是顶级小部件，对话框是一种特殊类型的窗口。

# 总结

本章介绍了 Qt Widgets 模块的基础知识以及如何创建自定义 UI。在这里，您学会了如何使用 Qt Designer 设计和构建 GUI。传统的桌面应用程序通常使用 Qt Designer 构建。诸如自定义小部件插件之类的功能允许您在 Qt Designer 中创建和使用自己的小部件集合。我们还讨论了使用样式表和样式自定义应用程序的外观和感觉，以及查看小部件、窗口和对话框之间的用途和区别。现在，您可以使用自己的自定义小部件创建具有扩展功能的 GUI 应用程序，并为桌面应用程序创建自己的主题。

在下一章中，我们将讨论`QtQuick`和 QML。在这里，您将学习关于`QtQuick`控件、Qt Quick Designer 以及如何构建自定义 QML 应用程序。我们还将讨论使用 Qt Quick 而不是小部件进行 GUI 设计的另一种选择。


# 第四章：Qt Quick 和 QML

Qt 由两个不同的模块组成，用于开发**图形用户界面**（**GUI**）应用程序。第一种方法是使用 Qt Widgets 和 C++，我们在上一章中学习过。第二种方法是使用 Qt Quick Controls 和**Qt 建模语言**（**QML**），我们将在本章中介绍。

在本章中，您将学习如何使用 Qt Quick Controls 和 QML 脚本语言。您将学习如何使用 Qt Quick 布局和定位器，并创建一个响应式 GUI 应用程序。您将学习如何将后端 C++代码与前端 QML 集成。您将学习 Qt Quick 和 QML 的基础知识，以及如何开发触摸友好和视觉导向的 Qt 应用程序。您还将学习有关鼠标和触摸事件的知识，以及如何开发一个触摸感知的应用程序。

在本章中，我们将涵盖以下主要主题：

+   开始使用 QML 和 Qt Quick

+   理解 Qt Quick Controls

+   创建一个简单的 Qt Quick 应用程序

+   使用 Qt Quick Designer 设计**用户界面**（**UI**）

+   QML 中的定位器和布局

+   将 QML 与 C++集成

+   将 QML 与**JavaScript**（**JS**）集成

+   处理鼠标和触摸事件

在本章结束时，您将了解 QML 的基础知识，与 C++的集成，以及如何创建自己的流畅 UI。

# 技术要求

本章的技术要求包括在最新的桌面平台上安装 Qt 6.0.0 和 Qt Creator 4.14.0 的最低版本，如 Windows 10，Ubuntu 20.04 或 macOS 10.14。

本章中使用的所有代码都可以从以下 GitHub 链接下载：[`github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter04`](https://github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter04)。

重要提示

本章使用的屏幕截图来自 Windows 平台。您将在您的机器上看到基于底层平台的类似屏幕。

# 开始使用 QML 和 Qt Quick

QML 是一种 UI 标记语言。它是 Qt 框架的一部分，是一种声明性语言。它使得构建流畅且触摸友好的 UI 成为可能，并随着触摸屏移动设备的发展而出现。它被创建为高度动态的，开发人员可以轻松地使用最少的编码创建流畅的 UI。Qt QML 模块实现了 QML 架构，并提供了一个开发应用程序的框架。它定义和实现了语言和基础设施，并提供了**应用程序编程接口**（**API**）来将 QML 语言与 JS 和 C++集成。

Qt Quick 为 QML 提供了一系列类型和功能的库。它包括交互类型、可视类型、动画、模型、视图和图形效果。它用于触摸输入、流畅动画和用户体验至关重要的移动应用程序。Qt QML 模块为 QML 应用程序提供了语言和基础设施，而 Qt Quick 模块提供了许多可视元素、动画和许多其他模块，用于开发面向触摸和视觉吸引力的应用程序。您可以使用 QML 和 Qt Quick Controls 而不是 Qt Widgets 来设计 UI。Qt Quick 支持多个平台，如 Windows、Linux、Mac、iOS 和 Android。您可以在 C++中创建自定义类，并将其移植到 Qt Quick 以扩展其功能。此外，该语言与 C++和 JS 的集成非常顺畅。

## 理解 QML 类型系统

让我们熟悉**QML 类型系统**和各种 QML 类型。QML 文件中的类型可以来自各种来源。在 QML 文件中使用的不同类型在这里概述：

+   QML 本身提供的基本类型，如`int`，`bool`，`real`和`list`

+   JS 类型，如`var`，`Date`和`Array`

+   QML 对象类型，如`Item`，`Rectangle`，`Image`和`Component`

+   通过 QML 模块由 C++注册的类型，如`BackendLogic`

+   作为 QML 文件提供的类型，例如`MyPushButton`

基本类型可以包含诸如`int`或`bool`类型的简单值。除了本机基本类型外，Qt Quick 模块还提供了其他基本类型。QML 引擎还支持 JS 对象和数组。任何标准 JS 类型都可以使用通用的`var`类型创建和存储。请注意，`variant`类型已经过时，只存在于支持旧应用程序的情况下。QML 对象类型是可以创建 QML 对象的类型。可以通过创建定义类型的`.qml`文件来定义自定义 QML 对象类型。QML 对象类型可以具有属性、方法、信号等。

要在您的 QML 文件中使用基本的 QML 类型，请使用以下代码行导入`QtQml`模块：`import QtQml`

`Item`是 Qt Quick 中所有可视元素的基本类型。Qt Quick 中的所有可视项都是从`Item`继承的，它是一个可以用作容器的透明可视元素。Qt Quick 提供`Rectangle`作为绘制矩形的可视类型，并提供`Image`类型来显示图像。`Item`为可视元素提供了一组通用属性。我们将在整本书中探索这些类型的用法。

您可以在以下链接了解更多关于 QML 类型的信息：

[`doc.qt.io/qt-6/qmltypes.html`](https://doc.qt.io/qt-6/qmltypes.html)

在本节中，我们学习了 QML 和 Qt Quick 的基础知识。在下一节中，我们将讨论 Qt Quick Controls。

# 了解 Qt Quick Controls

**Qt Quick Controls**提供了一组 UI 元素，可用于使用 Qt Quick 构建流畅的 UI。为了避免与**小部件**产生歧义，我们将使用术语**控件**来表示 UI 元素。**Qt Quick Controls 1**最初设计用于支持桌面平台。随着移动设备和嵌入式系统的发展，该模块需要进行更改以满足性能期望。因此，**Qt Quick Controls 2**诞生了，并进一步增强了对移动平台的支持。自 Qt 5.11 起，Qt Quick Controls 1 已被弃用，并已从 Qt 6.0 中删除。Qt Quick Controls 2 现在简称为 Qt Quick Controls。

可以在您的`.qml`文件中使用以下`import`语句导入 QML 类型：

`import QtQuick.Controls`

重要提示

在 Qt 6 中，QML 导入和版本控制系统发生了一些变化。版本号现在是可选的。如果导入模块时没有指定版本号，则会自动导入模块的最新版本。如果只导入模块的主要版本号，则会导入指定主要版本和最新次要版本的模块。Qt 6 引入了`import <module> auto`。这确保了导入的模块和导入模块具有相同的版本号。

有关 Qt 6 中 Qt Quick Controls 的更改，请访问以下链接：

[`doc.qt.io/qt-6/qtquickcontrols-changes-qt6.html`](https://doc.qt.io/qt-6/qtquickcontrols-changes-qt6.html)

Qt Quick Controls 提供了用于创建 UI 的 QML 类型。这里提供了 Qt Quick Controls 的示例：

+   `ApplicationWindow`：带有标题和页脚支持的样式化顶层窗口

+   `BusyIndicator`：指示后台活动，例如内容正在加载时

+   `Button`：可单击以执行命令或回答问题的推按钮

+   `CheckBox`：可以切换打开或关闭的复选框

+   `ComboBox`：用于选择选项的组合按钮和弹出列表

+   `拨号`：旋转以设置值的圆形拨号

+   `对话框`：带有标准按钮和标题的弹出对话框

+   `标签`：带有继承字体的样式文本标签

+   `Popup`：类似弹出式 UI 控件的基本类型

+   `ProgressBar`：指示操作进度

+   `RadioButton`：可以切换打开或关闭的互斥单选按钮

+   滚动条：垂直或水平交互式滚动条

+   `ScrollView`：可滚动视图

+   `Slider`：用于通过沿轨道滑动手柄来选择值

+   `SpinBox`：允许用户从一组预设值中进行选择

+   `Switch`：可以切换打开或关闭的按钮

+   `TextArea`：多行文本输入区域

+   `TextField`：单行文本输入字段

+   `ToolTip`：为任何控件提供工具提示

+   `Tumbler`：可旋转的可选择项目的轮子

要为 qmake 构建配置 Qt Quick Controls 模块，请将以下行添加到项目的`.pro`文件中：

`QT += quickcontrols2`

在本节中，我们了解了 Qt Quick 提供的不同类型的 UI 元素。在下一节中，我们将讨论 Qt Quick 提供的不同样式以及如何应用它们。

## Qt Quick Controls 的样式

Qt Quick Controls 带有一套标准样式。它们在这里列出：

+   基本

+   **融合**

+   **想象**

+   **材料**

+   **通用**

在 Qt Quick Controls 中有两种应用样式的方式，如下：

+   编译时间

+   运行时

您可以通过导入相应的样式模块来应用编译时样式，如下所示：

`import QtQuick.Controls.Universal`

您可以通过以下方法之一应用运行时样式：

![图 4.1-运行时应用样式的不同方法](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.1_B16231.jpg)

图 4.1-运行时应用样式的不同方法

在本节中，我们了解了 Qt Quick 中提供的样式。在下一节中，我们将创建我们的第一个 Qt Quick GUI 应用程序。

# 创建一个简单的 Qt Quick 应用程序

让我们使用 Qt 6 创建我们的第一个 Qt Quick 应用程序。Hello World 程序是一个非常简单的程序，显示`Hello World!`。该项目使用最少的——和最基本的——代码。对于这个项目，我们将使用 Qt Creator 创建的**项目骨架**。所以，让我们开始吧！按照以下步骤进行：

1.  要创建一个新的 Qt Quick 应用程序，请单击菜单栏上的**文件菜单**选项或按下*Ctrl* + *N*。或者，您也可以单击欢迎屏幕上的**新建项目**按钮。然后，将弹出一个窗口供您选择项目模板。选择**Qt Quick Application - Empty**并单击**选择...**按钮，如下截图所示：![图 4.2-新的 Qt Quick 应用程序向导](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.2_B16231.jpg)

图 4.2-新的 Qt Quick 应用程序向导

1.  在下一步中，您将被要求选择项目名称和项目位置。您可以通过单击`SimpleQtQuickApp`导航到所需的项目位置。然后，单击**下一步**按钮继续到下一个屏幕，如下截图所示：![图 4.3-项目位置选择屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.3_B16231.jpg)

图 4.3-项目位置选择屏幕

1.  在下一步中，您可以从一组工具包中选择一个工具包来构建和运行您的项目。要构建和运行项目，至少必须激活并可选择一个工具包。选择默认的**Desktop Qt 6.0.0 MinGW 64 位**工具包。单击**下一步**按钮继续到下一个屏幕。可以在以下截图中看到：![图 4.4-工具包选择屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.4_B16231.jpg)

图 4.4-工具包选择屏幕

1.  下一步是将您的 Qt Quick 项目添加到已安装的**版本控制系统**（**VCS**）中。您可以跳过此项目的版本控制。单击**完成**按钮以创建带有生成文件的项目，如下截图所示：![图 4.5-项目管理屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.5_B16231.jpg)

图 4.5-项目管理屏幕

1.  创建项目后，Qt Creator 将自动打开项目中的一个文件，名为`main.qml`。您将看到一种与您平常的 C/C++项目非常不同的脚本类型，如下截图所示：![图 4.6-显示 main.qml 文件的代码编辑器屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.6_B16231.jpg)

```cpp
#include <QGuiApplication>
#include <QQmlApplicationEngine>
int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QQmlApplicationEngine engine;
    const QUrl url(QStringLiteral("qrc:/main.qml"));
    engine.load(url);
    return app.exec();
}
```

您也可以使用`QQuickView`类，它提供了一个用于显示 Qt Quick UI 的窗口。这种方法有点老了。`QQmlApplicationEngine`具有方便的 QML 中央应用功能，而`QQuickView`通常是从 C++控制的。以下代码片段显示了如何使用`QQuickView`来加载`.qml`文件：

```cpp
#include <QGuiApplication>
#include <QQuickView>
int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QQuickView view;
    view.setResizeMode(
        QQuickView::SizeRootObjectToView);
    view.setSource(QUrl("qrc:/main.qml"));
    view.show();
    return app.exec();
}
```

`QQuickView`不支持将`Window`作为根项。如果您想要从 QML 创建您的根窗口，那么选择`QQmlApplicationEngine`。在使用`QQuickView`时，您可以直接使用任何 Qt Quick 元素，如下面的代码片段所示：

```cpp
import QtQuick
Item  {
    width: 400
    height: 400
    Text {
          anchors.centerIn: parent
          text: "Hello World!"
    }
}
```

1.  接下来，您可以通过点击位于**集成开发环境**（**IDE**）左下角的绿色箭头按钮来构建和运行 Qt Quick 项目，如下截图所示：![图 4.7 – Qt Creator 中的构建和运行选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.7_B16231.jpg)

图 4.7 – Qt Creator 中的构建和运行选项

1.  现在，点击**运行**按钮来构建和运行应用程序。很快，您将会看到一个带有**Hello World!**的 UI，如下截图所示：

![图 4.8 – Hello World UI 的输出](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.8_B16231.jpg)

图 4.8 – Hello World UI 的输出

您可以在 Windows 的命令行中运行应用程序，如下所示：

```cpp
>SimpleQtQuickApp.exe
```

您也可以在 Linux 发行版的命令行中运行应用程序，如下所示：

```cpp
$./SimpleQtQuickApp
```

在命令行模式下，如果在应用程序路径中找不到库文件，您可能会看到一些错误对话框。您可以将 Qt 库和插件文件复制到二进制文件夹中以解决这个问题。为了避免这些问题，我们将坚持使用 Qt Creator 来构建和运行我们的示例程序。您可以通过转到项目界面并根据您的偏好选择一个工具包来在不同的工具包之间切换。请记住，在对`.pro`文件进行更改后，您需要运行`qmake`。如果您正在使用命令行，则继续执行以下命令：

```cpp
>qmake
>make
```

您还可以创建一个带有 QML 入口点的 Qt Quick 2 UI 项目，而不使用任何 C++代码。要使用它，您需要设置一个 QML 运行时环境，比如`qmlscene`。Qt Creator 使用`.qmlproject`来处理仅包含 QML 的项目：

1.  创建一个 Qt Quick 2 UI 项目，从新项目模板屏幕中选择**Qt Quick 2 UI Prototype**，如下截图所示：![图 4.9 – Qt Quick UI Prototype 向导](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.9_B16231.jpg)

图 4.9 – Qt Quick UI Prototype 向导

1.  继续点击`QtQuickUIPrototype.qmlproject`和`QtQuickUIPrototype.qml`这两个由 Qt Creator 生成的文件。

1.  让我们修改`QtQuickUIPrototype.qml`的内容，添加一个`Text`元素并显示`Hello World!`，如下截图所示：![图 4.10 – Qt Quick UI Prototype 项目的示例内容](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.10_B16231.jpg)

图 4.10 – Qt Quick UI Prototype 项目的示例内容

1.  现在，点击**运行**按钮来构建和运行应用程序。很快，您将会看到一个带有**Hello World!**的 UI。

您也可以在命令行中运行应用程序，如下所示：

```cpp
>qmlscene QtQuickUIPrototype.qml
```

您可能需要在命令行中提到`qmlscene`和`qml`文件路径。只有在原型设计时才使用这个。您不能用这个来创建一个完整的应用程序。考虑使用 Qt Quick 应用程序项目来创建一个完整的应用程序。

在本节中，我们学习了如何使用 Qt Quick 模块创建一个简单的 GUI。在下一节中，我们将学习如何使用 Qt Quick Designer UI 设计自定义 UI。

# 使用 Qt Quick Designer 设计 UI

在本节中，您将学习如何使用 Qt Quick Designer 设计您的 UI。与 Qt Widgets 中的`.ui`文件类似，您也可以在 QML 中创建一个 UI 文件。该文件具有`.ui.qml`文件扩展名。有两种类型的 QML 文件：一种是`.qml`扩展名，另一种是`.ui.qml`扩展名。QML 引擎将其视为标准的`.qml`文件，但禁止其中的逻辑实现。它为多个`.qml`文件创建了可重用的 UI 定义。通过分离 UI 定义和逻辑实现，增强了 QML 代码的可维护性。

在开始学习如何设计自己的 UI 之前，让我们熟悉一下 Qt Quick Designer 的界面。以下截图显示了 Qt Quick Designer 的不同部分。在设计我们的 UI 时，我们将逐渐了解这些部分：

![图 4.11 - Qt Quick Designer 界面的各个部分](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.11_B16231.jpg)

图 4.11 - Qt Quick Designer 界面的各个部分

Qt Quick Designer 的界面包括以下主要部分：

+   **导航器**：将当前 QML 文件中的项目列为树结构。这类似于我们在上一章中学习的 Qt Designer 中的**对象操作器**窗口。

+   **控件库**：此窗口显示了 QML 中所有可用的 Qt Quick 控件。您可以将控件拖放到画布窗口中，以修改您的 UI。

+   **资源**：显示了可以用于 UI 设计的所有资源的列表。

+   **导入浏览器**：**导入浏览器**便于将不同的 QML 模块导入到当前 QML 文件中，以为您的 QML 项目添加新功能。您还可以创建自己的自定义 QML 模块，并从这里导入。

+   **文本编辑器**：有六个工具按钮，每个按钮都用于特定操作，如复制和粘贴。

+   **属性编辑器**：类似于 Qt Designer 中的属性编辑器。Qt Quick Designer 中的**属性**部分显示了所选项目的属性。您还可以在**文本编辑器**中更改项目的属性。

+   **表单编辑器**：**表单编辑器**是一个画布，您可以在其中为 Qt Quick 应用程序设计 UI。

+   **状态编辑器**：此窗口列出了 QML 项目中的不同状态，并描述了它们的 UI 定义和行为。

+   **连接编辑器**：此部分类似于 Qt Designer 中的**信号/槽编辑器**。在这里，您可以为您的 QML 组件定义信号和槽机制。

您现在已经熟悉了 Qt Quick Designer UI。让我们创建一个 Qt Quick UI 文件，并探索 Qt Quick 控件，如下所示：

1.  要创建一个 Qt Quick UI，选择`ui.qml`文件扩展名。默认情况下，Qt Creator 将打开 Qt Quick Designer。您可以通过单击左侧面板上的**编辑**按钮切换到代码编辑模式：![图 4.12 - QtQuick UI 文件向导](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.12_B16231.jpg)

图 4.12 - QtQuick UI 文件向导

1.  让我们向`Item`、`Rectangle`、`Image`、`Text`等添加一些 QML 元素。`Item`是一个可以用作容器的透明 UI 元素：![图 4.13 - Qt Quick Designer 显示基本的 QML 类型](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.13_B16231.jpg)

图 4.13 - Qt Quick Designer 显示基本的 QML 类型

1.  默认情况下，库只包含一些基本的 QML 类型。您可以通过 QML `QtQuick.Controls`包将 Qt Quick 模块导入到 Qt Quick Designer 中，如下一张截图所示：![图 4.14 - Qt Quick Designer 显示了 QML 模块导入选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.14_B16231.jpg)

图 4.14 - Qt Quick Designer 显示了 QML 模块导入选项

1.  一旦导入模块，您就可以在库中看到一个带有**Qt Quick - Controls 2**的部分，如下一张截图所示：

![图 4.15 - Qt Quick Designer 显示 Qt Quick 控件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.15_B16231.jpg)

图 4.15 - Qt Quick Designer 显示 Qt Quick 控件

在本节中，我们熟悉了 Qt Quick Designer 的界面。在下一节中，您将学习不同的定位器和布局。

# QML 中的位置器和布局

在 QML 中有不同的定位项目的方法。您可以通过提及*x*和*y*坐标或使用锚点、位置器或布局手动定位控件。让我们讨论如何通过上述方法定位控件。

## 手动定位

通过设置相应的*x*和*y*属性，可以将控件定位在特定的*x*和*y*坐标上。根据视觉坐标系统规则，这将使控件相对于其父级的左上角定位。

以下代码片段显示了如何将`Rectangle`项目放置在位置(`50,50`)处：

```cpp
import QtQuick
Rectangle {
    // Manually positioned at 50,50
    x: 50 // x position
    y: 50 // y position
    width: 100; height: 80
    color: "blue"
}
```

当您运行上述代码时，您将看到一个蓝色矩形被创建在(`50,50`)位置。更改`x`和`y`值，您将看到位置相对于左上角如何改变。Qt 允许您在一行中用分号分隔写入多个属性。您可以在同一行中用分号分隔写入`x`和`y`位置。

在本节中，您学习了如何通过指定其坐标来定位可视项。在下一节中，我们将讨论锚点的使用。

## 使用锚点定位

Qt Quick 提供了一种将控件锚定到另一个控件的方法。每个项目有七条不可见的锚线：`left`、`right`、`top`、`bottom`、`baseline`、`horizontalCenter`和`verticalCenter`。您可以为每个边设置边距或不同的边距。如果特定项目有多个锚点，那么它们可以被分组。

让我们看下面的例子：

```cpp
import QtQuick
import QtQuick.Window
Window {
    width: 400; height: 400
    visible: true
    title: qsTr("Anchoring Demo")
    Rectangle {
        id: blueRect
        anchors {
            left: parent.left; leftMargin:10
            right: parent.right; rightMargin: 40
            top: parent.top; topMargin: 50
            bottom: parent.bottom; bottomMargin: 100
        }
        color: "blue"
        Rectangle {
            id: redRect
            anchors.centerIn: blueRect
            color:"red"
            width: 150; height: 100
        }
    }
}
```

如果您运行此示例，您将在输出窗口中看到一个红色矩形，它位于蓝色矩形内部，具有不同的边距，如下所示：

![图 4.16 - 锚定在窗口内部定位控件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.16_B16231.jpg)

图 4.16 - 锚定在窗口内部定位控件

在本节中，您学习了如何使用锚点定位可视项。在下一节中，我们将讨论位置器的使用。

## 位置器

**Positioners**是在声明性 UI 中管理可视元素位置的容器。Positioners 的行为方式类似于**Qt widgets**中的布局管理器。

一组标准的位置器在基本的 Qt Quick 元素集中提供。它们概述如下：

+   **Column**将其子项放置在列中。

+   **Row**将其子项放置在一行中。

+   **Grid**将其子项放置在网格中。

+   **Flow**将其子项放置在页面上的单词中。

让我们看看如何在 Qt Quick Designer 中使用它们。首先，创建三个具有不同颜色的**Rectangle**项目，然后将它们放置在一个**Row**元素内，如下截图所示：

![图 4.17 - 位置器内的矩形](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.17_B16231.jpg)

图 4.17 - 位置器内的矩形

您还可以编写代码来定位位置器内的控件。如果使用 Qt Quick Designer，Qt Creator 会自动生成代码。生成的代码可以通过**Form Editor**旁边的**Text Editor**选项卡查看和修改。代码如下所示：

```cpp
Row {
    id: row     
    Rectangle {
        id: yellowRect
        width: 150; height: 100
        color: "yellow"
        border.color: "black"
    }
    Rectangle {
        id: redRect
        width: 150; height: 100
        color: "red"
        border.color: "black"
    }
    Rectangle {
        id: greenRect
        width: 150; height: 100
        color: "green"
        border.color: "black"
    }
}
```

在本节中，我们学习了不同的位置器。在下一节中，我们将讨论重复器和模型的使用，以及位置器。

## Repeater

**Repeater**使用提供的模型创建多个可视元素，以及用于与位置器一起使用的模板元素，并使用模型中的数据。重复器放置在位置器内，并创建遵循定义的位置器排列的可视元素。当有许多类似的项目时，使用重复器的位置器在规则布局中排列时更容易维护。

让我们使用`Repeater`创建一个排列在一行中的五个矩形，如下所示：

```cpp
import QtQuick
import QtQuick.Window
Window {
    width: 400; height: 200
    visible: true
    title: qsTr("Repeater Demo")
    Row {
        anchors.centerIn: parent
        spacing: 10
        Repeater {
            model: 5
            Rectangle {
                width: 60; height: 40
                border{ width: 1; color: "black";}
                color: "green"
            }
        }
    }
}
```

当您运行上述示例时，您将看到五个矩形排列在一行中，如下所示：

![图 4.18 - 位置器内的矩形](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.18_B16231.jpg)

图 4.18 - 位置器内的矩形

在本节中，我们了解了使用位置器和重复器。在下一节中，我们将深入了解 Qt Quick 布局。

## Qt Quick 布局

Qt Quick 布局是一组 QML 类型，可用于在 UI 中排列可视元素。Qt Quick 布局可以调整其子元素的大小，因此它们用于可调整大小的 UI。位置器和布局之间的基本区别在于布局可以在窗口调整大小时调整其子元素。

可以通过以下`import`语句将 Qt Quick 布局导入到您的 QML 文件中：

`import QtQuick.Layouts`

这里有五种不同类型的 QML 布局，如下所述：

+   `RowLayout`：按行排列元素。它类似于`GridLayout`，但只有一行。

+   `ColumnLayout`：按列排列元素。它类似于`GridLayout`，但只有一列。

+   `GridLayout`：允许在网格中动态排列元素。

+   `Layout`：为推送到`ColumnLayout`、`RowLayout`或`GridLayout`布局类型的项目提供附加属性。

+   `StackLayout`：以堆栈方式排列元素，一次只有一个元素可见。

让我们看一下以下`RowLayout`示例：

```cpp
import QtQuick
import QtQuick.Window
import QtQuick.Layouts
Window {
    width: 640; height: 480
    visible: true
    title: qsTr("Layout Demo")
    RowLayout {
        id: layout
        anchors.fill: parent
        spacing: 6
        Rectangle {
            color: 'yellow'
            Layout.fillWidth: true
            Layout.minimumWidth: 50
            Layout.preferredWidth: 150
            Layout.maximumWidth: 200
            Layout.minimumHeight: 100
            Layout.margins: 10
        }
        Rectangle {
            color: 'red'
            Layout.fillWidth: true
            Layout.minimumWidth: 50
            Layout.preferredWidth: 100
            Layout.preferredHeight: 80
            Layout.margins: 10
        }
    }
}
```

请注意，`Row`类型是位置器，而`RowLayout`类型是布局。何时使用它们主要取决于您的目标，与往常一样。让我们继续下一节，看看如何将 QML 与 C++集成。

# 将 QML 与 C++集成

QML 应用程序通常需要在 C++中处理更高级和性能密集型的任务。这样做的最常见和最快速的方法是将 C++类暴露给 QML 运行时，前提是 C++实现派生自`QObject`。

QML 可以很容易地与 C++代码集成。可以从 C++加载和操作 QML 对象。QML 与 Qt 的元对象系统集成允许从 QML 调用 C++功能。这有助于构建混合应用程序，其中混合了 C++、QML 和 JS。要将 C++数据、属性或方法暴露给 QML，它应该派生自`QObject`类。这是可能的，因为所有 QML 对象类型都是使用`QObject`派生类实现的，允许 QML 引擎通过 Qt 元对象系统加载和检查对象。

您可以以以下方式将 QML 与 C++集成：

+   使用上下文属性将 C++对象嵌入到 QML 中

+   向 QML 引擎注册类型

+   创建 QML 扩展插件

让我们在以下各节中逐一讨论每种方法。

重要提示

要快速确定哪种集成方法适合您的项目，请查看 Qt 文档中以下链接中的流程图：

[`doc.qt.io/qt-6/qtqml-cppintegration-overview.html`](https://doc.qt.io/qt-6/qtqml-cppintegration-overview.html)

## 使用上下文属性将 C++对象嵌入到 QML 中

您可以使用上下文属性将 C++对象暴露到 QML 环境中。上下文属性适用于简单的应用程序。它们将您的对象导出为全局对象。上下文在由 QML 引擎实例化后暴露给 QML 环境。

让我们看一下以下示例，在这个示例中，我们已将`radius`导出到 QML 环境。您也可以以类似的方式导出 C++模型：

```cpp
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("radius", 50);
    const QUrl url(QStringLiteral("qrc:/main.qml"));
    engine.load(url);
    return app.exec();
}
```

您可以直接在 QML 文件中使用导出的值，如下所示：

```cpp
import QtQuick
import QtQuick.Window
Window {
    width: 640; height: 480
    visible: true
    title: qsTr("QML CPP integration")
    Text {
        anchors.centerIn: parent
        text: "C++ Context Property Value: "+ radius
    }
}
```

您还可以在 QML 环境中注册您的 C++类并实例化它。让我们在下一节中学习如何实现这一点。

## 使用 QML 引擎注册 C++类

注册 QML 类型允许开发人员从 QML 环境中控制 C++对象的生命周期。这不能通过上下文属性实现，也不会填充全局命名空间。不过，所有类型都需要首先注册，并且在应用程序启动时需要链接所有库，这在大多数情况下并不是真正的问题。

这些方法可以是公共槽或使用`Q_INVOKABLE`标记的公共方法。现在，让我们将 C++类导入到 QML 文件中。看一下以下 C++类：

```cpp
#ifndef BACKENDLOGIC_H
#define BACKENDLOGIC_H
#include <QObject>
class BackendLogic : public QObject
{
    Q_OBJECT
public:
    explicit BackendLogic(QObject *parent = nullptr) { 
             Q_UNUSED(parent);}
    Q_INVOKABLE int getData() {return mValue; }
private:
    int mValue = 100;
};
#endif // BACKENDLOGIC_H
```

您需要在`main.cpp`文件中使用`qmlRegisterType()`将 C++类注册为模块，如下所示：

```cpp
qmlRegisterType<BackendLogic>("backend.logic", 1, 0,"BackendLogic");
```

任何派生自`Qobject`的 C++类都可以注册为 QML 对象类型。一旦一个类被注册到 QML 类型系统中，该类就可以像任何其他 QML 类型一样使用。现在，C++类已准备好在您的`.qml`文件中实例化。您需要导入模块并创建一个对象，如下面的代码片段所示：

```cpp
import QtQuick
import QtQuick.Window
import backend.logic
Window {
    width: 640; height: 480
    visible: true
    title: qsTr("QML CPP integration")
    BackendLogic {
        id: backend
    }
    Text {
        anchors.centerIn: parent
        text: "From Backend Logic : "+ backend.getData()
    }
}
```

当您运行上述程序时，您会看到程序正在从后端 C++类中获取数据并在 UI 中显示。

您还可以使用`qmlRegisterSingletonType()`将 C++类公开为 QML 单例。通过使用 QML 单例，您可以防止全局命名空间中的重复对象。让我们跳过这部分，因为它需要对设计模式有所了解。详细的文档可以在以下链接找到：

[`doc.qt.io/qt-6/qqmlengine.html#qmlRegisterSingletonType`](https://doc.qt.io/qt-6/qqmlengine.html#qmlRegisterSingletonType%20)

在 Qt 6 中，您可以通过使用`QML_ELEMENT`宏实现 C++集成。该宏将声明封闭类型作为 QML 中可用，使用其类或命名空间名称作为 QML 元素名称。要在 C++头文件中使用此宏，您将需要包含`qml.h`头文件，如`#include <QtQml>`。

让我们看一下以下示例：

```cpp
#ifndef USINGELEMENT_H
#define USINGELEMENT_H
#include <QObject>
#include <QtQml>
class UsingElements : public QObject
{
    Q_OBJECT
    QML_ELEMENT
public:
    explicit UsingElements(QObject *parent = nullptr) { 
              Q_UNUSED(parent);}
    Q_INVOKABLE int readValue() {return mValue; }
private:
    int mValue = 500;
};
#endif // USINGELEMENT_H
```

在`.pro`文件中，您需要将`qmltypes`选项添加到`CONFIG`变量，并且需要提到`QML_IMPORT_NAME`和`QML_IMPORT_MAJOR_VERSION`，如下面的代码片段所示：

```cpp
CONFIG += qmltypes
QML_IMPORT_NAME = backend.element
QML_IMPORT_MAJOR_VERSION = 1
```

您的 C++类现在已准备好在您的`.qml`文件中实例化。您需要导入模块并创建一个对象，如下面的代码片段所示：

```cpp
import QtQuick
import QtQuick.Window
import backend.element
Window {
    width: 640; height: 480
    visible: true
    title: qsTr("QML CPP integration")
    UsingElements {
        id: backendElement
    }
    Text {
        anchors.centerIn: parent
        text: "From Backend Element : "+ 
              backendElement.readValue()
    }
}
```

在本节中，您学习了如何将您的 C++类导出到 QML 环境中，并从 QML 访问其函数。在这个例子中，数据只有在调用方法时才被检索。您还可以通过添加带有`NOTIFY`信号的`Q_PROPERTY()`宏在 C++内部更改数据时得到通知。在使用之前，您需要了解信号和槽机制。因此，我们将跳过这部分，并在*第六章*中进一步讨论*信号和槽*。在下一节中，我们将讨论如何创建一个 QML 扩展插件。

## 创建 QML 扩展插件

QML 扩展插件提供了与 C++集成的最灵活的方式。它允许您在插件中注册类型，在第一个 QML 文件调用导入标识符时加载该插件。您可以在项目之间使用插件，这在构建复杂项目时非常方便。

Qt Creator 有一个向导可以创建`QqmlExtensionPlugin`，并且应该实现`registerTypes()`函数。需要使用`Q_PLUGIN_METADATA`宏来标识插件为 QML 扩展插件：

![图 4.19 - Qt Quick 2 QML 扩展插件向导](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_4.19_B16231.jpg)

图 4.19 - Qt Quick 2 QML 扩展插件向导

这一部分是一个高级的 Qt 主题。您需要深入了解 Qt 才能创建自己的 QML 扩展插件。如果您是初学者，可以跳过本节，但您可以在以下链接的 Qt 文档中了解更多关于 QML 扩展插件的信息：

[`doc.qt.io/qt-6/qtqml-modules-cppplugins.html`](https://doc.qt.io/qt-6/qtqml-modules-cppplugins.html)

让我们继续下一节，了解如何在 C++类中调用 QML 方法。

## 在 C++类中调用 QML 方法

所有 QML 方法都暴露给元对象系统，并可以使用`QMetaObject::invokeMethod()`从 C++中调用。您可以在冒号字符后指定参数和返回值的类型，如下一个代码片段所示。当您想要将 C++中的信号连接到 QML 定义的特定签名的方法时，这可能很有用。如果省略类型，则 C++签名将使用`QVariant`。

让我们看一个调用 QML 方法的应用程序，使用`QMetaObject::invokeMethod()`。

在 QML 文件中，让我们添加一个名为`qmlMethod()`的方法，如下所示：

```cpp
import QtQuick
Item {
    function qmlMethod(msg: string) : string {
        console.log("Received message:", msg)
        return "Success"
    }
    Component.onCompleted: {
        console.log("Component created successfully.")
    }
}
```

在`main.cpp`文件中，按照以下代码片段调用`QMetaObject::invokeMethod()`：

```cpp
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlComponent>
int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QQmlApplicationEngine engine;
    QQmlComponent component(&engine, 
                            "qrc:/CustomItem.qml");
    QObject *myObject = component.create();
    QString retValue = "";
    QString msg = "Message from C++";
    QMetaObject::invokeMethod(myObject, "qmlMethod",
                              Q_RETURN_ARG(QString, 
                              retValue),
                              Q_ARG(QString, msg));
    qDebug() << "QML method returned:" << retValue;
    delete myObject;
    return app.exec();
}
```

请注意，必须指定参数和返回类型。基本类型和对象类型都允许作为类型名称。如果类型在 QML 类型系统中未提及，则在调用`QMetaObject::invokeMethod`时，您必须使用`Q_RETURN_ARG()`和`Q_ARG()`声明`QVariant`作为类型。或者，如果您不需要任何返回值，可以只用两个参数调用`invokeMethod()`，如下所示：

`QMetaObject::invokeMethod(myObject, "qmlMethod");`

在本节中，您学会了从 QML 方法中接收数据。在下一节中，您将学习如何在 C++中访问 QML 对象指针。

## 将 QML 对象指针暴露给 C++

有时，您可能希望通过 C++修改 QML 对象的属性，例如修改控件的文本、更改控件的可见性或更改自定义属性。QML 引擎允许您将 QML 对象注册为 C++类型，从而自动公开 QML 对象的属性。

让我们看一个示例，我们将一个 QML 对象导出到 C++环境中：

```cpp
#ifndef CUSTOMOBJECT_H
#define CUSTOMOBJECT_H
#include <QObject>
#include <QVariant>
class CustomObject : public QObject
{
    Q_OBJECT
public:
    explicit CustomObject(QObject *parent = nullptr);
    Q_INVOKABLE void setObject(QObject* object)
    {
        object->setProperty("text", QVariant("Clicked!"));
    }
};
#endif // CUSTOMOBJECT_H
```

在 QML 文件中，您需要创建`C++`类的实例并调用`C++`方法。如下面的代码片段所示，在`C++`类内部操作属性：

```cpp
import QtQuick
import QtQuick.Window
import QtQuick.Controls
import MyCustomObject
Window {
    width: 640; height: 480;
    visible: true
    title: qsTr("QML Object in C++")
    CustomObject{
        id: customObject
    }
    Button {
        id: button
        anchors.centerIn: parent
        text: qsTr("Click Me!")
        onClicked: {
            customObject.setObject(button);
        }
    }
}
```

重要说明

Qt QML 模块提供了几个用于注册不可实例化类型的宏。`QML_ANONYMOUS`注册一个不可实例化且无法从 QML 引用的 C++类型。`QML_INTERFACE`注册一个现有的 Qt 接口类型。该类型无法从 QML 实例化，并且您不能使用它声明 QML 属性。`QML_UNCREATABLE`注册一个命名的不可实例化的 C++类型，但应该作为 QML 类型系统中的类型可识别。`QML_SINGLETON`注册一个可以从 QML 导入的单例类型。

恭喜！您已经学会了如何集成 QML 和 C++。在下一节中，我们将讨论如何在 QML 中使用 JS。

# 将 QML 与 JS 集成

QML 与 JS 有很好的集成，并使用类似**JavaScript 对象表示**（**JSON**）的语法，允许定义表达式和方法作为 JS 函数。它还允许开发人员导入 JS 文件并使用现有功能。QML 引擎提供了一个 JS 环境，与 Web 浏览器提供的 JS 环境相比有一些限制。Qt Quick 应用程序的逻辑可以在 JS 中定义。JS 代码可以内联编写在 QML 文件中，也可以编写在单独的 JS 文件中。

让我们看看如何在 QML 文档中使用内联 JS。下面的示例演示了`btnClicked()`内联 JS 函数。当单击`Button`控件时，将调用该方法：

```cpp
import QtQuick
import QtQuick.Window
import QtQuick.Controls
Window {
    width: 640; height: 480;
    visible: true
    title: qsTr("QML JS integration")
    function btnClicked(controlName) {
        controlName.text = "JS called!"
    }
    Column  {
        anchors.centerIn: parent
        Button {
            text:"Call JS!"
            onClicked: btnClicked(displayText)
        }
        Text {
            id: displayText
        }
    }
}
```

前面的示例展示了如何将 JS 代码与 QML 集成。我们使用了`btnClicked()`内联 JS 函数。当您运行应用程序时，将收到一条消息，上面写着**JS called!**。

如果您的逻辑非常复杂或在多个 QML 文档中使用，则使用单独的 JS 文件。您可以按如下方式导入 JS 文件：

`import "<JavaScriptFile>" as <Identifier>`

例如，您可以运行以下代码行：

`import "constants.js" as Constants`

在前面的示例中，我们将`constants.js`导入到 QML 环境中。`Constants`是我们 JS 文件的标识符。

您还可以创建一个共享的 JS 库。您只需在 JS 文件的开头包含以下代码行：

`.pragma library`

重要提示

如果脚本是单个表达式，则建议将其内联写入。如果脚本有几行长，则使用块。如果脚本超过几行长或被不同对象需要，则创建一个函数并根据需要调用它。对于长脚本，创建一个 JS 文件并在 QML 文件中导入它。避免使用`Qt.include()`，因为它已被弃用，并将在未来的 Qt 版本中删除。

要了解有关在 QML 中导入 JS 的更多信息，请阅读以下文档：

[`doc.qt.io/qt-6/qtqml-javascript-imports.html`](https://doc.qt.io/qt-6/qtqml-javascript-imports.html)

在本节中，您学习了如何将 JS 与 QML 集成。在下一节中，我们将讨论如何在 QML 中导入目录。

## 在 QML 中导入目录

您可以直接在另一个 QML 文件中导入包含 QML 文件的本地目录，而无需添加资源。您可以使用目录的绝对或相对文件系统路径来实现这一点，为 QML 类型提供了一种方便的方式，将其排列为可重用的目录在文件系统上。

目录导入的常见形式如下所示：

`import "<DirectoryPath>" [as <Qualifier>]`

例如，如果您的目录名称是`customqmlelements`，那么您可以按如下方式导入它：

`import "../customqmlelements"`

还可以将目录作为限定的本地命名空间导入，如下面的代码片段所示：

`import "../customqmlelements" as CustomQMLElements`

您还可以按以下方式从资源路径导入文件：

`import "qrc:/qml/customqmlelements"`

您还可以从远程服务器导入一个包含 QML 文件的目录。有两种不同类型的`qmldir`文件：QML 目录列表文件和 QML 模块定义文件。在这里，我们讨论的是使用`qmldir` QML 目录列表文件。可以使用`qmldir`文件导入目录。为了避免恶意代码，您必须小心处理网络文件。

以下文档提供了有关`qmldir` QML 目录列表文件的更多信息：

[`doc.qt.io/qt-6/qtqml-syntax-directoryimports.html`](https://doc.qt.io/qt-6/qtqml-syntax-directoryimports.html)

您可以在以下链接了解有关不同类型的`qmldir`文件的更多信息：

[`doc.qt.io/qt-6/qtqml-modules-qmldir.html`](https://doc.qt.io/qt-6/qtqml-modules-qmldir.html)

在本节中，您学习了如何在 QML 中导入目录。在下一节中，我们将讨论如何在 QML 中处理鼠标和触摸事件。

# 处理鼠标和触摸事件

QML 通过输入处理程序提供了对鼠标和触摸事件的出色支持，这些处理程序让 QML 应用程序处理鼠标和触摸事件。QML 类型，如`MouseArea`、`MultiPointTouchArea`和`TapHandler`用于检测鼠标和触摸事件。我们将在下一节中查看这些 QML 类型。

## MouseArea

`MouseArea`是一个不可见的项目，用于与可见项目（如`Item`或`Rectangle`）一起，以便为该项目提供鼠标和触摸处理事件。`MouseArea`在`Item`的定义区域内接收鼠标事件。您可以通过使用`anchors.fill`属性将`MouseArea`锚定到其父级区域来定义此区域。如果将 visible 属性设置为`false`，则鼠标区域对鼠标事件变得透明。

让我们看看如何在以下示例中使用`MouseArea`：

```cpp
import QtQuick
import QtQuick.Window
Window {
    width: 640; height: 480
    visible: true
    title: qsTr("Mouse Area Demo")
    Rectangle {
        anchors.centerIn: parent
        width: 100; height: 100
        color: "green"
        MouseArea {
            anchors.fill: parent
            onClicked: { parent.color = 'red' }
        }
    }
}
```

在前面的例子中，您可以看到只有`rectangle`区域收到了鼠标事件。窗口的其他部分没有收到鼠标事件。您可以根据鼠标事件执行相应的操作。`MouseArea`还提供了方便的信号，可以提供有关鼠标事件的信息，如鼠标悬停、鼠标按下、按住、鼠标退出和鼠标释放事件。编写相应的信号处理程序，并尝试使用`entered()`、`exited()`、`pressed()`和`released()`信号。您还可以检测按下了哪个鼠标按钮，并执行相应的操作。

## MultiPointTouchArea

`MultiPointTouchArea` QML 类型使多点触摸屏幕上的多个触摸点处理成为可能。与`MouseArea`一样，`MultiPointTouchArea`是一个不可见的项。您可以跟踪多个触摸点并相应地处理手势。当禁用时，触摸区域对触摸和鼠标事件都变得透明。在`MultiPointTouchArea`类型中，鼠标事件被处理为单个触摸点。您可以将`mouseEnabled`属性设置为`false`以停止处理鼠标事件。

让我们看一下以下示例，其中有两个矩形跟随我们的触摸点：

```cpp
import QtQuick
import QtQuick.Window
Window {
    width: 640; height: 480
    visible: true
    title: qsTr("Multitouch Example")
    MultiPointTouchArea {
        anchors.fill: parent
        touchPoints: [
            TouchPoint { id: tp1 },
            TouchPoint { id: tp2 }
        ]
    }
    Rectangle {
        width: 100; height: 100
        color: "blue"
        x: tp1.x; y: tp1.y
    }
    Rectangle {
        width: 100; height: 100
        color: "red"
        x: tp2.x; y: tp2.y
    }
}
```

在`MultiPointTouchArea`类型中，`TouchPoint`定义了一个触摸点。它包含有关触摸点的详细信息，如压力、当前位置和区域。现在，在您的移动设备上运行应用程序并进行验证！

在本节中，您了解了使用`MouseArea`和`MultiPointTouchArea`来处理鼠标和触摸事件。让我们在下一节中了解`TapHandler`。

## TapHandler

`TapHandler`是鼠标点击事件和触摸屏上的轻拍事件的处理程序。您可以使用`TapHandler`来对轻拍和触摸手势做出反应，并允许您同时处理多个嵌套项中的事件。有效轻拍手势的识别取决于`gesturePolicy`。`gesturePolicy`的默认值是`TapHandler.DragThreshold`，其中事件点不得显着移动。如果将`gesturePolicy`设置为`TapHandler.WithinBounds`，则`TapHandler`独占按下事件，但一旦事件点离开父项的边界，就会释放独占。同样，如果将`gesturePolicy`设置为`TapHandler.ReleaseWithinBounds`，则`TapHandler`独占按下事件，并保持独占直到释放，以便检测此手势。

让我们创建一个`TapHandler`类型，以识别不同的鼠标按钮事件和触笔轻拍，如下所示：

```cpp
import QtQuick
import QtQuick.Window
Window {
    width: 640; height: 480
    visible: true
    title: qsTr("Hello World")
    Item {
        anchors.fill:parent
        TapHandler {
            acceptedButtons: Qt.LeftButton
            onTapped: console.log("Left Button Clicked!")
        }
        TapHandler {
            acceptedButtons: Qt.MiddleButton
            onTapped: console.log("Middle Button Clicked!")
        }
        TapHandler {
            acceptedButtons: Qt.RightButton
            onTapped: console.log("Right Button Clicked!")
        }
        TapHandler {
             acceptedDevices: PointerDevice.Stylus
             onTapped: console.log("Stylus Tap!")
         }
    }
}
```

您可以使用`MouseArea`。输入处理程序使得形成复杂的触摸交互变得更简单，这是使用`MouseArea`或`TouchArea`难以实现的。

Qt 提供了一些现成的控件来处理通用手势，如捏合、轻扫和滑动。`PinchArea`是一个方便的 QML 类型，用于处理简单的捏合手势。它是一个不可见项，与另一个可见项一起使用。`Flickable`是另一个方便的 QML 类型，提供了一个用于轻扫手势的表面。探索相关文档和示例，以了解更多关于这些 QML 元素的信息。

让我们在下一节中看看`SwipeView`。

## SwipeView

`SwipeView`用于通过侧向滑动导航页面。它使用基于滑动的导航模型，并提供了一种简化的水平分页滚动方式。您可以在底部添加页面指示器以显示当前活动页面。

让我们看一个简单的例子，如下所示：

```cpp
import QtQuick
import QtQuick.Window
import QtQuick.Controls
Window {
    width: 640; height: 480
    visible: true
    title: qsTr("Swipe Demo")
    SwipeView {
        id: swipeView
        currentIndex: 0
        anchors.fill: parent
        Rectangle { id: page1; color: "red" }
        Rectangle { id: page2; color: "green"}
        Rectangle { id: page3; color: "blue" }   
    }     
    PageIndicator {
        id: pageIndicator
        count: swipeView.count
        currentIndex: swipeView.currentIndex
        anchors {
            bottom: swipeView.bottom
            horizontalCenter: parent.horizontalCenter
        }
    }
}
```

如您所见，我们只需向`SwipeView`添加子项。您可以将`SwipeView`当前索引设置为`PageIndicator`当前索引。`SwipeView`是导航模型之一，还包括`StackView`和`Drawer`。您可以探索这些 QML 类型，以在移动设备上体验手势。

在本节中，您了解了使用各种 QML 类型来处理鼠标、触摸和手势事件。接下来，我们将总结本章学到的内容。

# 总结

本章解释了 Qt Quick 模块的基础知识以及如何创建自定义 UI。您学会了如何使用 Qt Quick Designer 设计和构建 GUI，并了解了 Qt Quick Controls 以及如何构建自定义 Qt Quick 应用程序。您还学会了如何将 QML 与 C++和 JS 集成。现在您应该了解 Qt Widgets 和 Qt Quick 之间的相似之处和不同之处，并能够为您的项目选择最合适的框架。在本章中，我们学习了 Qt Quick 以及如何使用 QML 创建应用程序。您还学会了如何将 QML 与 JS 集成，并了解了鼠标和触摸事件。

在下一章中，我们将讨论使用 Qt Creator 进行跨平台开发。您将学习在 Windows、Linux、Android 和 macOS 操作系统（OSes）上配置和构建应用程序。我们将学习如何将我们的 Qt 应用程序移植到不同的平台，而不会遇到太多挑战。让我们开始吧！
