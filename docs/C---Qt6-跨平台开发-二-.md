# C++ Qt6 跨平台开发（二）

> 原文：[`zh.annas-archive.org/md5/E50463D8611423ACF3F047AAA5FD4529`](https://zh.annas-archive.org/md5/E50463D8611423ACF3F047AAA5FD4529)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二部分：跨平台开发

本节将向您介绍跨平台开发。跨平台开发的理念是软件应用在多个平台上运行良好，而不需要进行重大的代码更改。这样可以节省在移植和维护代码库方面的时间。这符合 Qt 的理念：“少写代码，创造更多，到处部署”。在本节中，您将了解 Qt Creator IDE 及其用法，以及如何在不同平台上开发和运行相同的应用程序。

本节包括以下章节：

+   *第五章*, *跨平台开发*


# 第五章：跨平台开发

自其最初发布以来，Qt 以其跨平台能力而闻名——这是创建该框架的主要愿景。您可以在 Windows、Linux 和 macOS 等喜爱的桌面平台上使用 Qt Creator，并使用相同的代码库或稍作修改创建流畅、现代、触摸友好的**图形用户界面**（**GUI**）和桌面、移动或嵌入式应用程序。您可以轻松修改您的代码并将其部署到目标平台上。Qt 具有几个内置工具，可分析您的应用程序及其在各种支持的平台上的性能。此外，与其他跨平台框架不同，它易于使用，并且具有直观的**用户界面**（**UI**）。

在本章中，您将学习跨平台开发的基本知识以及如何在不同平台上构建应用程序。有了这些，您将能够在您喜爱的桌面和移动平台上运行示例应用程序。

在本章中，我们将涵盖以下主要主题：

+   了解跨平台开发

+   了解编译器

+   使用`qmake`构建

+   Qt 项目（`.pro`）文件

+   了解构建设置

+   特定于平台的设置

+   在 Microsoft Visual Studio 中使用 Qt

+   在 Linux 上运行 Qt 应用程序

+   在 macOS 和 iOS 上运行 Qt 应用程序

+   其他 Qt 支持的平台

+   从 Qt 5 迁移到 Qt 6

本章结束时，您将了解 Qt 项目文件、基本设置以及如何在移动设备上运行 Qt 应用程序。让我们开始吧！

# 技术要求

本章的技术要求包括在最新的桌面平台（如 Windows 10、Ubuntu 20.04 或 macOS 10.14）上安装 Qt 6.0.0 和 Qt Creator 4.14.0 的最低版本。

本章中使用的所有代码都可以从以下 GitHub 链接下载：

[`github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter05/HelloWorld`](https://github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter05/HelloWorld)

重要说明

本章中使用的屏幕截图是在 Windows 平台上拍摄的。您将在您的机器上看到基于底层平台的类似屏幕。

# 了解跨平台开发

市场上有几种跨平台框架可供选择，但由于其成熟度和可用的社区支持，Qt 是更好的选择。对于传统的 C++开发人员来说，很容易适应 Qt 并开发高质量的应用程序。Qt 框架允许开发人员开发与多个平台兼容的应用程序，如 Windows、Linux、macOS、**QNX**（最初称为**Quick Unix** [**Qunix**]）、iOS 和 Android。它通过一次编码和随处部署的理念，促进更快的应用程序开发和更好的代码质量。Qt 在内部处理特定于平台的实现，并且还能让您在微控制器驱动的设备上构建令人印象深刻的超轻量级应用程序。

要使用 Qt 开发嵌入式平台的应用程序，您将需要商业许可证来使用**Qt for Device Creation**。Qt 还支持一些**微控制器单元**（**MCU**）平台，如瑞萨、STM32 和 NXP。在撰写本书时，Qt for MCUs 1.8 已推出，提供了具有较小内存占用的超轻量级模块。

使用 Qt 框架进行跨平台开发的一些优势列在这里：

+   降低开发成本的成本效益

+   更好的代码可重用性

+   便利性

+   更快的**上市时间**（**TTM**）

+   更广泛的市场覆盖

+   提供接近本机体验

+   性能优越

也有一些缺点，比如：

+   无法使用特定于平台的功能和访问所有平台的**应用程序编程接口**（**API**）

+   本地和非本地组件之间的通信挑战

+   特定设备功能和硬件兼容性挑战

+   延迟的平台更新

在本节中，您对 Qt 的跨平台特性有了基本了解，并了解了跨平台开发的利弊。在您可以在任何平台上运行应用程序之前，您需要一个编译器来为目标平台编译应用程序。在下一节中，我们将了解 Qt 框架支持的编译器。

# 了解编译器

在本节中，您将学习什么是编译器，以及如何在跨平台开发中使用它。编译器是一种软件，它将您的程序转换为计算机可以读取和执行的机器代码或低级指令。这些低级机器指令因平台而异。您可以使用不同的编译器（如**GNU 编译器集合**（**GCC**））编译 Qt 应用程序，或者使用供应商提供的编译器。在 Qt Creator 中，您可以在**Kits**选项卡下找到一个支持的编译器，以及在特定平台（如 Windows、Linux 或 macOS）上构建应用程序所需的其他基本工具。并非所有支持的编译器都包含在 Qt 安装程序中，但您可以在推荐的工具包中自动列出最常用的编译器。Qt 可能会停止支持某些工具包配置，或者用最新版本替换它们。

目前，Qt 支持以下编译器：

+   GCC

+   **Windows 的极简 GNU**（**MinGW**）

+   **Microsoft Visual C++**（**MSVC**）

+   **低级虚拟机**（**LLVM**）

+   **英特尔 C++编译器**（**ICC**）

+   `clang-cl`

+   Nim

+   QCC

此外，**Qt Creator 裸机设备**插件提供以下编译器的支持：

+   **IAR 嵌入式工作台**（**IAREW**）

+   KEIL

+   **小型设备 C 编译器**（**SDCC**）

除了上述编译器，Qt 在构建 Qt 项目时还使用特定的内置编译器。这些列在这里：

+   `moc`)

+   `uic`)

+   `rcc`)

您可以使用上述编译器构建目标平台的应用程序，或者添加自定义编译器配置。在下一节中，您将学习如何创建自定义编译器配置。

## 添加自定义编译器

要添加 Qt Creator 未自动检测到或不可用的编译器，请使用**自定义**选项。您可以指定编译器和工具链路径到相应的目录，并进行相应的配置。

要添加自定义编译器配置，请按照以下步骤操作：

1.  要在 Qt 中创建新的编译器配置，请单击菜单栏上的**工具**菜单，然后从左侧窗格中选择**Kits**选项卡。

1.  然后，单击**编译器**选项卡，并从**添加**下拉菜单中选择**自定义**。您将在上下文菜单中看到**C**和**C++**选项。根据您的需求选择类型。您可以在以下截图中看到这个概述：![图 5.1-自定义编译器选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.1_B16231.jpg)

图 5.1-自定义编译器选项

1.  在下一步中，使用自定义名称填写**名称**字段。

1.  接下来，在**编译器路径**字段中，选择编译器所在目录的路径。

1.  接下来，指定`make`工具的位置。

1.  在下一步中，在**ABI**字段中指定**应用程序二进制接口**（**ABI**）版本。

您可以在以下截图中看到这个概述：

![图 5.2-自定义编译器所需字段](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.2_B16231.jpg)

图 5.2-自定义编译器所需字段

1.  接下来，您可以在`MACRO[=value]`中指定默认所需的宏。

1.  在下一步中，在**头文件路径**字段中指定编译器检查头文件的路径。

1.  接下来，在`C++11`支持中。

1.  在下一步中，在**Qt mkspecs**字段中指定`mkspecs`（一组编译规则）的位置。

1.  接下来，在**错误解析器**字段中，选择合适的错误解析器。

1.  单击**应用**按钮以保存配置。

在本节中，您了解了支持的编译器以及如何在 Qt Creator 中创建新的编译器配置，但是要构建和运行项目，我们需要比编译器更多的工具。Qt 提供了`qmake`作为我们方便使用的内置构建工具。在下一节中，我们将讨论`qmake`是什么。

# 使用 qmake 构建

`Makefile`并构建可执行程序和库。`qmake`是 Qt 提供的一个构建工具，可简化跨多个平台的开发项目的构建过程。它将每个项目文件中的信息扩展到一个`Makefile`中，以执行必要的编译和链接命令。它也可以用于非 Qt 项目。`qmake`根据项目文件中的信息生成一个`Makefile`，并包含支持 Qt 开发的附加功能，自动包括`moc`和`uic`的构建规则。`qmake`还可以创建 Microsoft Visual Studio 项目，而无需开发人员更改项目文件。

作为一个社区驱动的框架，Qt 对开发者非常灵活，并且给予他们选择最合适的工具来进行项目开发的自由，而不是强迫他们使用自己的构建系统。Qt 支持以下类型的构建系统：

+   `qmake`

+   CMake

+   Qbs

+   Meson

+   Incredibuild

您可以从 Qt Creator UI 或命令行中运行`qmake`。每次对项目文件进行更改时，都应该运行`qmake`。以下是从命令行运行`qmake`的语法：

```cpp
>qmake [mode] [options] files
```

`qmake`提供了两种不同的操作模式。在默认模式下，`qmake`使用项目文件中的信息生成`Makefile`，但它也可以生成项目文件。模式如下所示：

+   `-makefile`

+   `-project`

在`qmake`中，将生成一个用于构建项目的`Makefile`。运行`qmake`以 Makefile 模式的语法如下所示：

```cpp
>qmake -makefile [options] files
```

在项目模式下，`qmake`将生成一个项目文件。运行`qmake`的语法如下所示：

```cpp
>qmake -project [options] files
```

如果您将 Visual Studio 作为`qmake`项目，`qmake`可以创建一个包含开发环境所需的所有基本信息的 Visual Studio 项目。它可以递归生成子目录中的`.vcproj`文件和主目录中的`.sln`文件，使用以下命令：

```cpp
>qmake -tp vc -r
```

例如，您可以通过运行以下命令为您的`HelloWorld`项目生成一个 Visual Studio 项目：

```cpp
>qmake -tp vc HelloWorld.pro
```

请注意，每次修改项目文件时，都需要运行`qmake`以生成更新的 Visual Studio 项目。

您可以在以下链接找到有关`qmake`的更多详细信息：

[`doc.qt.io/qt-6/qmake-manual.html`](https://doc.qt.io/qt-6/qmake-manual.html)

大多数`qmake`项目文件使用`name = value`和`name += value`定义的列表定义项目中使用的源文件和头文件，但`qmake`中还有其他高级功能，使用其他运算符、函数、平台范围和条件来创建跨平台应用程序。有关`qmake`语言的更多详细信息，请访问以下链接：[`doc.qt.io/qt-6/qmake-language.html`](https://doc.qt.io/qt-6/qmake-language.html)。

Qt 团队在 Qt 6 中付出了很多努力，使其具有未来的可扩展性，通过使用广泛采用的流行构建工具**CMake**。已经实施了一些变化，通过使用**Conan**作为一些附加组件的包管理器，使 Qt 更加模块化。在 Qt 6 中，一些 Qt 模块不再作为 Qt 在线安装程序中的二进制包可用，而是作为 Conan 配方可用。您可以在以下链接了解有关构建系统更改以及将 CMake 作为默认构建工具的更多信息：[`doc.qt.io/qt-6/qt6-buildsystem.html`](https://doc.qt.io/qt-6/qt6-buildsystem.html)。

重要提示

在 Qt 5 中，构建系统是基于`qmake`构建的，但在 Qt 6 中，CMake 是构建 Qt 源代码的构建系统。这种变化只影响想要从源代码构建 Qt 的开发人员。您仍然可以使用`qmake`作为 Qt 应用程序的构建工具。

在本节中，您了解了`qmake`。我们将跳过高级的`qmake`主题，以便自行探索。在下一节中，我们将讨论 Qt 项目文件，这些文件由`qmake`解析。

# Qt 项目（.pro）文件

在早期示例中由 Qt Creator 创建的`.pro`文件实际上是 Qt 项目文件。`.pro`文件包含`qmake`构建应用程序、库或插件所需的所有信息。项目文件支持简单和复杂的构建系统。简单的项目文件可以使用直接的声明，定义标准变量以指示项目中使用的源文件和头文件。复杂的项目可能使用多个流结构来优化构建过程。项目文件包含一系列声明，用于指定资源，例如指向项目所需的源文件和头文件的链接、项目所需的库、不同平台的自定义构建过程等。

Qt 项目文件有几个部分，并使用某些预定义的`qmake`变量。让我们看一下我们早期的`HelloWorld`示例`.pro`文件：

```cpp
QT       += core gui
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
CONFIG += c++17
# You can make your code fail to compile if it uses 
# deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    
# disables all the APIs deprecated before Qt 6.0.0
SOURCES += \
    main.cpp \
    widget.cpp
HEADERS += \
    widget.h
FORMS += \
    widget.ui
# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
```

项目文件只是告诉`qmake`项目中所需的 Qt 模块，以及可执行程序的名称。它还链接到需要包含在项目中的头文件、源文件、表单文件和资源文件。所有这些信息对于`qmake`创建配置文件和构建应用程序至关重要。对于更复杂的项目，您可能需要为不同的操作系统不同地配置项目文件。

以下列表描述了最常用的变量，并描述了它们的目的：

+   `QT`：项目中使用的 Qt 模块列表

+   `CONFIG`：一般项目配置选项

+   `DESTDIR`：可执行文件或二进制文件将放置在其中的目录

+   `FORMS`：要由 UI 编译器（`uic`）处理的 UI 文件列表

+   `HEADERS`：构建项目时使用的头文件（`.h`）文件名列表

+   `RESOURCES`：要包含在最终项目中的资源（`.qrc`）文件列表

+   `SOURCES`：在构建项目时要使用的源代码（`.cpp`）文件列表

+   `TEMPLATE`：用于项目的模板

您可以向项目添加不同的 Qt 模块、配置和定义。让我们看看如何做到这一点。要添加额外的模块，只需在`QT +=`之后添加模块关键字，如下所示：

`QT += core gui sql`

您还可以在前面添加条件，以确定何时向项目添加特定模块，如下所示：

`greaterThan(QT_MAJOR_VERSION, 4): QT += widgets`

您还可以向项目添加配置设置。例如，如果要在编译项目时指定`c++17`规范，则将以下行添加到您的`.pro`文件中：

`CONFIG += c++17`

您可以向项目文件添加注释，以井号（`#`）开头，构建系统将忽略相应的文本行。现在，让我们看一下`TEMPLATE`变量。这确定构建过程的输出是应用程序、库还是插件。有不同的变量可用于概述`qmake`将生成的文件类型。这些列在下面：

+   `app`用于构建应用程序。

+   `lib`用于构建库。

+   `aux`用于构建空内容。如果不需要调用编译器来创建目标（例如，因为项目是用解释语言编写的），则使用此选项。

+   `subdirs`用于使用`SUBDIRS`变量指定的子目录。每个子目录必须包含自己的项目文件。

+   `vcapp`用于创建用于构建应用程序的 Visual Studio 项目文件。

+   `vclib`用于创建一个 Visual Studio 项目文件，以构建库。

+   `vcsubdirs`用于创建一个 Visual Studio 解决方案文件，以在子目录中构建项目。

Qt 项目文件有时需要依赖于`include`功能。在 Qt 项目文件中，您还可以定义两个重要的变量：`INCLUDEPATH`和`DEPENDPATH`。您可以使用`SUBDIRS`变量来编译一组依赖库或模块。

现在，让我们讨论一下`.pri`文件是什么。

## 了解`.pro`和`.pri`文件之间的区别

您可以创建一个`.pri`文件来包含复杂项目中的项目文件。这样可以提高可读性并将不同模块分隔开。`.pri`文件通常被称为`qmake`包含文件，其格式与`.pro`文件类似。主要区别在于使用意图；`.pro`文件是我们期望直接在其上运行`qmake`的文件，而`.pri`文件是由`.pro`文件包含的。您可以将常见配置，如源文件、头文件、`.ui`文件和`.qrc`文件添加到`.pri`文件中，并根据项目需求从多个`.pro`文件中包含它们。

您可以在`.pro`文件中包含一个`.pri`文件，如下所示：

`include($$PWD/common.pri)`

在本节中，您了解了 Qt 项目文件是什么，以及其中使用的不同变量。在下一节中，我们将讨论不同的构建设置。

# 了解构建设置

在编译或构建项目之前，编译器需要某些细节，这些细节称为构建设置。这是编译过程中非常重要的一部分。在本节中，您将了解构建设置以及如何以正确的方式配置它们。您可以为同一个项目拥有多个构建配置。通常，Qt Creator 会自动创建调试、发布和配置文件构建配置。调试构建包含用于调试应用程序的额外调试符号，而发布版本是一个经过优化的版本，不包含这样的符号。通常，开发人员使用调试配置进行测试，使用发布配置创建最终的二进制文件。配置文件构建是一个经过优化的发布构建，附带单独的调试信息，最适合于分析应用程序。

构建设置可以在**项目**模式中指定。如果 IDE 中没有打开项目，则可能会发现**项目**按钮被禁用。您可以通过单击**添加**下拉按钮，然后选择要添加的配置类型来添加新的构建配置。选项可能取决于为项目选择的构建系统。您可以根据需要添加多个构建配置。您可以单击**克隆…**按钮，以基于当前构建配置添加一个构建配置，或单击**重命名…**按钮来重命名当前选定的构建配置。单击**删除**按钮来删除一个构建配置。

您可以在以下截图中看到这个概述：

![图 5.3 - 构建设置和 Qt Quick 编译器选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.3_B16231.jpg)

图 5.3 - 构建设置和 Qt Quick 编译器选项

通常，Qt Creator 在与源目录不同的目录中构建项目，称为影子构建。这样可以将为每个构建和运行工具生成的文件分隔开。如果您只想使用单个工具包构建和运行，则可以取消选择**影子构建**复选框。Qt Creator 项目向导创建了一个可以编译使用**Qt 资源系统**的 Qt Quick 项目。要使用默认设置，请选择**保持默认**。要编译 Qt Quick 代码，请在**Qt Quick 编译器**字段中选择**启用**，如*图 5.3*所示。

您可以在以下链接中了解有关不同构建配置的更多信息：

[`doc.qt.io/qtcreator/creator-build-settings.html`](https://doc.qt.io/qtcreator/creator-build-settings.html)

在本节中，我们讨论了构建设置。在构建跨平台应用程序时，向项目文件添加特定于平台的配置非常重要。在下一节中，我们将学习有关特定于平台的设置。

# 特定于平台的设置

您可以为不同的平台定义不同的配置，因为并非每种配置都适用于所有用例。例如，如果您想为不同的操作系统包含不同的头文件路径，您可以将以下代码行添加到您的`.pro`文件中：

```cpp
win32: INCLUDEPATH += "C:/mylibs/windows_headers"
unix:INCLUDEPATH += "/home/user/linux_headers"
```

在上述代码片段中，我们添加了一些特定于 Windows 和特定于 Linux 的头文件。您还可以像这样在 C++中放置配置，例如`if`语句：

```cpp
win32 {
    SOURCES += windows_code.cpp
}
```

上述代码仅适用于 Windows 平台，这就是为什么我们在前面加了一个`win32`关键字。如果您的目标平台是基于 Linux 的，那么您可以添加一个`unix`关键字来添加特定于 Linux 的配置。

要在 Windows 平台上为应用程序设置自定义图标，您应该将以下代码行添加到您的项目（`.pro`）文件中：

`RC_ICONS = myapplication.ico`

要在 macOS 上为应用程序设置自定义图标，您应该将以下代码行添加到您的项目（`.pro`）文件中：

`ICON = myapplication.icns`

请注意，Windows 和 macOS 的图标格式不同。对于 Linux 发行版，制作每种风格的桌面条目有不同的方法。

在本节中，我们讨论了一些特定于平台的设置。在下一节中，我们将学习如何在 Qt VS 工具中使用 Visual Studio。

# 在 Microsoft Visual Studio 中使用 Qt

一些开发人员选择 Visual Studio 作为他们首选的 IDE。因此，如果您喜欢的 IDE 是 Visual Studio，那么您可以将 Qt VS 工具与 Microsoft Visual Studio 集成。这将允许您在标准的 Windows 开发环境中使用，而无需担心与 Qt 相关的构建步骤或工具。您可以直接从 Microsoft Visual Studio 安装和更新 Qt VS 工具。

您可以从 Visual Studio Marketplace 找到相应版本的 Qt Visual Studio 工具。对于 Visual Studio 2019，您可以从以下链接下载该工具：[`marketplace.visualstudio.com/items?itemName=TheQtCompany.QtVisualStudioTools2019`](https://marketplace.visualstudio.com/items?itemName=TheQtCompany.QtVisualStudioTools2019)。您还可以从以下 Qt 下载链接下载`VS`插件：[`download.qt.io/official_releases/vsaddin/`](https://download.qt.io/official_releases/vsaddin/)。

这些是 Qt VS 工具的一些重要功能：

+   创建新项目和类的向导

+   `moc`、`uic`和`rcc`编译器的自动构建设置

+   导入和导出`.pro`和`.pri`文件

+   将 Qt VS 工具项目自动转换为`qmake`项目

+   集成 Qt 资源管理

+   能够创建 Qt 翻译文件并与**Qt Linguist**集成

+   集成**Qt Designer**

+   集成 Qt 文档

+   用于 Qt 数据类型的调试扩展

要开始在 Visual Studio 环境中使用这些功能，您必须设置 Qt 版本。从`.pro`文件中选择适当的版本与`qmake`或从 Visual Studio 中的`.vcproj`文件构建您的项目。由于 Visual Studio 用于特定于 Windows 的开发，建议将 Qt Creator 用作跨平台开发的 IDE。

如果您没有`.vcproj`文件，那么您可以通过命令行或通过 VS 工具从`.pro`文件生成一个。我们已经在*使用 qmake 构建*部分讨论了命令行指令。您还可以通过使用`.vcproj`文件将您的`.pro`文件转换为`.vcproj`文件，该文件仅包含特定于 Windows 的设置。

在本节中，我们讨论了`VS`插件。在下一节中，我们将学习如何在 Linux 上运行一个示例应用程序。我们将跳过在 Windows 上构建和运行 Qt 应用程序的讨论，因为我们已经在前几章中讨论过这个问题。

# 在 Linux 上运行 Qt 应用程序

在 Linux 上构建和运行 Qt 应用程序与在 Windows 上运行类似，但 Linux 有许多发行版，因此很难构建一个完美运行在所有 Linux 变体上的应用程序。在大多数发行版中，应用程序将会顺利运行。我们将以 Ubuntu 20.04 作为目标平台。当你在 Ubuntu 上安装 Qt 时，它会自动检测套件和配置。你也可以配置一个带有适当编译器和 Qt 版本的套件，如下截图所示：

![图 5.4 - Ubuntu 上的桌面套件配置](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.4_B16231.jpg)

图 5.4 - Ubuntu 上的桌面套件配置

让我们在 Ubuntu 上运行我们的`HelloWorld`示例。点击左侧窗格上的**运行**按钮。一个显示**Hello World!**的 UI 将立即出现，如下截图所示：

![图 5.5 - Ubuntu 上运行的应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.5_B16231.jpg)

图 5.5 - Ubuntu 上运行的应用程序

你也可以从命令行运行应用程序，如下面的代码片段所示：

```cpp
$./HelloWorld
```

在本节中，我们讨论了如何在 Linux 发行版上运行我们的应用程序。在下一节中，我们将学习如何在 macOS 和 iOS 上运行 Qt 应用程序。

# 在 macOS 和 iOS 上运行 Qt 应用程序

我们已经在前几章讨论了如何在 Windows 和 Linux 平台上构建和运行应用程序。让我们继续学习如何在 macOS 和 iOS 等平台上运行我们的应用程序。要在 macOS 和 iOS 上构建 Qt 应用程序，你需要从 App Store 下载 Xcode。Xcode 是 macOS 的 IDE，包括一套用于在 macOS 和 iOS 中开发应用程序的软件开发工具。如果你已经安装了 Xcode，Qt Creator 将检测到其存在并自动检测到合适的套件。至于套件选择，Qt for macOS 支持 Android、`clang` 64 位、iOS 和 iOS 模拟器的套件。

你可以在下面的截图中看到 macOS 上的桌面套件配置示例：

图 5.6 - macOS 上的桌面套件配置

](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.6_B16231.jpg)

图 5.6 - macOS 上的桌面套件配置

如果你不想使用自动检测的调试器，你也可以在**调试器**选项卡中手动添加调试器，如下截图所示：

![图 5.7 - macOS 上的调试器选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.7_B16231.jpg)

图 5.7 - macOS 上的调试器选项

在 macOS 上运行应用程序与在 Windows 上运行类似。只需点击**运行**按钮，你将立即看到应用程序运行。

移动平台与 Windows、Linux 和 macOS 等桌面平台同等重要。让我们探讨如何设置运行 iOS 应用程序的环境。

## 为 iOS 配置 Qt Creator

在 iOS 上运行 Qt 应用程序非常简单。你可以连接你的 iOS 设备，并从设备选择列表中选择合适的设备类型。你可以从**套件**选择屏幕中选择**设备类型**。你也可以在 iOS 模拟器上运行应用程序，如下截图所示：

![图 5.8 - macOS 上的 iOS 模拟器选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.8_B16231.jpg)

图 5.8 - macOS 上的 iOS 模拟器选项

配置好套件后，只需将 iPhone 连接上并点击**运行**按钮。你可以在下面的截图中看到一个示例输出：

图 5.9 - Qt Creator 在 iPhone 上运行应用程序

](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.9_B16231.jpg)

图 5.9 - Qt Creator 在 iPhone 上运行应用程序

在 iOS 平台上构建和运行应用程序相对容易。然而，分发应用程序并不容易，因为 App Store 是一个非常封闭的生态系统。你需要一个 Apple ID，并且需要在分发应用程序给用户之前登录你的 iOS 应用程序。你无法避开这些步骤，但现在让我们跳过部署部分。 

你可以在以下链接了解更多关于 App Store 提交的信息：

[`developer.apple.com/app-store/submissions`](https://developer.apple.com/app-store/submissions)

在本节中，我们学习了如何在 macOS 和 iOS 上运行应用程序。在下一节中，我们将学习如何为 Android 平台配置和构建应用程序。

## 为 Android 配置 Qt Creator

Android 是当今最流行的移动平台，因此开发人员希望为 Android 构建应用程序。尽管 Android 是基于 Linux 的操作系统，但它与其他 Linux 发行版非常不同。为了使用它，您必须配置 Qt Creator 并安装某些软件包。

为了使 Qt Creator 配置 Android 顺利运行，请使用 OpenJDK 8，带有 clang 工具链的 NDK r21。您可以从`ANDROID_SDK_ROOT\cmdline-tools\latest\bin`运行 sdkmanager，并使用必要的参数配置所需的依赖项。

您可以在以下链接中了解有关 Android 特定要求和说明的更多信息：

[`doc.qt.io/qt-6/android-getting-started.html`](https://doc.qt.io/qt-6/android-getting-started.html)

让我们开始按照以下步骤配置您的机器以用于 Android：

1.  要在 Android 上构建 Qt 应用程序，您必须在开发 PC 上安装 Android**软件开发工具包**（**SDK**），Android**本机开发工具包**（**NDK**），**Java 开发工具包**（**JDK**）和 OpenSSL，无论您的桌面平台如何。您将在每个相应字段旁边找到带有地球图标或**下载**按钮的下载选项，以从各自软件包的页面下载。

1.  安装所有必需的软件包后，重新启动 Qt Creator。Qt Creator 应该能够自动检测构建和平台工具。

1.  但是，您可能需要进一步配置以修复**Android**设置中的错误。您可能会发现 SDK 管理器、平台 SDK 和必要的软件包缺失，如下截图所示：![图 5.10 - Android 设置屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.10_B16231.jpg)

图 5.10 - Android 设置屏幕

1.  在**Android 设置**下选择正确的 SDK 和 NDK 路径。点击**应用**按钮以保存更改。

1.  点击**SDK 管理器**选项卡，然后点击**更新已安装**按钮。您可能会看到一个消息框，提示您安装缺少的软件包，如下截图所示。点击**是**按钮来安装这些软件包：![图 5.11 - 显示缺少 Android 软件包的信息消息](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.11_B16231.jpg)

图 5.11 - 显示缺少 Android 软件包的信息消息

1.  您可能会收到另一条消息，警告 Android SDK 更改，列出缺少的基本软件包，如下截图所示。点击**确定**按钮：![图 5.12 - 关于缺少 Android 软件包的警告](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.12_B16231.jpg)

图 5.12 - 关于缺少 Android 软件包的警告

1.  点击`--verbose`，然后点击**确定**按钮。您可以在以下截图中看到概述：![图 5.13 - Android SDK 管理器工具](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.13_B16231.jpg)

图 5.13 - Android SDK 管理器工具

1.  一旦问题解决，您将看到所有 Android 设置已经正确配置，如下截图所示：![图 5.14 - Qt Creator 中正确的 Android 配置](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.14_B16231.jpg)

图 5.14 - 在 Qt Creator 中正确的 Android 配置

1.  如果问题仍未解决，或者您想安装特定平台，您可以输入适当的命令，如下截图所示。您还可以从命令行安装所需的软件包。Qt 将自动检测 SDK 位置中可用的构建工具和平台：![图 5.15 - Android SDK 管理器工具](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.15_B16231.jpg)

图 5.15 - Android SDK 管理器工具

1.  一旦 Android 设置正确配置，您可以看到 Android kit 已准备好进行开发，如下面的截图所示：![图 5.16 - 正确配置的 Android kit](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.16_B16231.jpg)

图 5.16 - 正确配置的 Android kit

1.  从**Kit**选择选项中选择一个 Android kit，如下面的截图所示：![图 5.17 - Android Kit 选择选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.17_B16231.jpg)

图 5.17 - Android Kit 选择选项

1.  在这一步中，您可以选择目标 Android 版本，并通过 Qt Creator 创建`AndroidManifest.xml`文件来配置您的 Android 应用程序。您可以设置包名称、版本代码、SDK 版本、应用程序图标、权限等。设置如下截图所示：![图 5.18 - 构建设置中的 Android 清单选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_5.18_B16231.jpg)

图 5.18 - 构建设置中的 Android 清单选项

1.  您的计算机现在已准备好进行 Android 开发。但是，您的 Android 硬件需要启用开发者选项，或者使用 Android 模拟器。要启用**Developer**模式，转到**Settings**，点击**System**，然后点击**About phone**。

1.  然后，点击**Software info**，找到构建号。不断点击**Builder number**，直到看到**Developer**模式已激活。可能需要点击七次才能激活**Developer**模式。现在，返回到**Settings**面板，您现在将找到**Developer**选项。

1.  您的 Android 设备已准备好运行 Android 应用程序。单击**Run**按钮，然后从**Compatible device**列表屏幕中选择设备。

1.  接下来，点击`build`文件夹中生成的`.apk`文件。

恭喜！您已成功开发了 Android 应用程序。与 iOS 不同，Android 是一个开放系统。您可以将`.apk`文件复制或分发到运行相同 Android 版本的其他 Android 设备上，然后安装它。但是，如果您想在 Google Play 商店上分发您的应用程序，那么您将需要注册为 Google Play 开发者并签署包。

在本节中，我们学习了如何配置和构建 Android 平台。在下一节中，我们将讨论在本书编写时 Qt 6 支持的其他平台。

# 其他 Qt 支持的平台

Qt 5 支持广泛的平台，从桌面和移动平台到嵌入式和 Web 平台。Qt 6 尚未支持 Qt 5 中支持的所有平台，但随着 Qt 6 的成熟，这些平台将逐渐得到支持。目前，在商业许可下，Qt 6 的最新版本仅支持嵌入式 Linux。您可能需要等一段时间才能将应用程序移植到不同的嵌入式平台上的 Qt 6。否则，如果您想立即迁移到 Qt 6 以适用于您喜爱的嵌入式平台，您必须从源代码构建并进行必要的修改。

以下链接提供了 Qt 6.2 中嵌入式 Linux 支持的快照：[`doc-snapshots.qt.io/qt6-dev/embedded-linux.html`](https://doc-snapshots.qt.io/qt6-dev/embedded-linux.html)。随着 Qt 迈向下一个版本，此链接可能会更新。

Qt 还为商业许可下的嵌入式 Linux 系统提供了**Boot to Qt**软件堆栈。这是一个轻量级的、经过 Qt 优化的完整软件堆栈，安装在目标系统上。Boot to Qt 软件堆栈使用传统的嵌入式 Linux 内核，设计有 Poky 和 Yocto 软件包。

在以下链接中了解更多关于 Boot to Qt 的信息：

[`doc.qt.io/QtForDeviceCreation/b2qt-index.html`](https://doc.qt.io/QtForDeviceCreation/b2qt-index.html)

**Qt for WebAssembly** 允许您为 Web 平台构建 Qt 应用程序。它不一定需要任何客户端安装，并节省服务器资源。它是一个平台插件，可以让您构建可以嵌入到网页中的 Qt 应用程序。在 Qt 6 中，尚未向开源开发人员提供此插件。商业许可证持有人可能会提前获得使用此插件的权限。

您可以在以下链接上了解有关 **Qt for WebAssembly** 插件的更多信息：

[`wiki.qt.io/Qt_for_WebAssembly`](https://wiki.qt.io/Qt_for_WebAssembly)

在本节中，我们了解了 Qt 6 支持的其他平台。在下一节中，我们将讨论如何将应用程序从 Qt 5 迁移到 Qt 6。

# 从 Qt 5 迁移到 Qt 6

**Qt 6** 是 Qt 框架的重大变化，因此它会破坏一些向后兼容性。因此，在升级到 Qt 6 之前，请确保您的 Qt 5 应用程序已更新到 Qt 5.15。从 Qt 5.15 迁移到 Qt 6 将更容易，需要的更改最少。但是，在 Qt 5.15 中标记为已弃用或过时的 API 在 Qt 6.0 中可能已被移除。

Qt 5 和 Qt 6 中的 CMake API 在语义上几乎是相同的。因此，Qt 5.15 引入了无版本目标和命令，允许编写完全独立于 Qt 版本的 CMake 代码。无版本导入目标对于需要同时进行 Qt 5 和 Qt 6 编译的项目非常有用。不建议默认使用它们，因为缺少目标属性。您可以在以下链接上阅读更多信息：[`doc.qt.io/qt-6/cmake-qt5-and-qt6-compatibility.html`](https://doc.qt.io/qt-6/cmake-qt5-and-qt6-compatibility.html)。

在 Qt 6 中，一些类和模块已被移除，但这些类和模块在 `Qt5Compat` 中保留以便于迁移。除了构建系统的更改之外，您可能需要修复过时类的包含指令，例如，Qt6 中的类如 `QLinkedList`、`QRegExp` 和 `QTextCodec` 都被新类替换。但为了便于迁移，您需要将 `core5compat` 添加到您的 `.pro` 文件中，如下所示：

`QT += core5compat`

关于绘图机制也有一些变化。如果您使用了 OpenGL 风格的 `qsb` 工具，您的着色器代码应该编译成 **Standard Portable Intermediate Representation-Vulkan** (**SPIR-V**) 格式。我们将在 *第八章* 中详细讨论图形和动画。更多细节可以在以下链接找到：[`doc.qt.io/qt-6/qtshadertools-index.html`](https://doc.qt.io/qt-6/qtshadertools-index.html)。

`QtGraphicalEffects` 也有一些变化，已从 Qt 6 中移除，并将以不同的许可证提供。Qt Quick MultiEffect 可在 Qt Marketplace 上获得，并提供更好的性能。您还可以考虑将 QML 中的早期信号连接更新为使用 JavaScript 函数声明，如以下代码片段所示：

```cpp
Connections {
    target: targetElement
    function onSignalName() {//Do Something}
}
```

Qt 状态机模块在很大程度上与 Qt 5 版本兼容，因此您应该能够继续在其项目上工作，而不需要或只需要进行轻微的更改。要使用状态机模块的类，请将以下代码添加到您的 Qt 项目（`.pro`）文件中：

```cpp
QT += statemachine
```

要在 QML 文件中导入状态机模块，请使用以下 `import` 语句：

`import QtQml.StateMachine`

Qt 提供了详细的迁移指南。如果您希望将 Qt 5 应用程序迁移到 Qt 6，请查看以下文档：

[`doc.qt.io/qt-6/portingguide.html`](https://doc.qt.io/qt-6/portingguide.html)

[`www.qt.io/blog/porting-from-qt-5-to-qt-6-using-qt5compat-library`](https://www.qt.io/blog/porting-from-qt-5-to-qt-6-using-qt5compat-library)

[`doc.qt.io/qt-6/porting-to-qt6-using-clazy.html`](https://doc.qt.io/qt-6/porting-to-qt6-using-clazy.html)

在本节中，您学习了如何将您的应用程序从 Qt 5 迁移到 Qt 6。在下一节中，我们将总结本章学到的内容。

# 总结

本章介绍了使用 Qt Creator 进行跨平台开发。您了解了各种编译器、构建工具以及构建和特定平台的设置。在本章中，您学会了在桌面和移动平台上配置和构建应用程序，以及如何在 iPhone 和 Android 设备上运行应用程序。我们讨论了如何在不太多的挑战下将您的 Qt 项目移植到不同的平台。

在下一章中，您将学习有关信号和槽机制、Qt 元对象系统和事件处理的知识。让我们继续吧！


# 第三部分：高级编程、调试和部署

在本节中，您将学习高级编程和开发方法。您将学习在各种平台上调试、测试和部署 Qt 应用程序。您还将学习国际化以及如何构建高性能应用程序。

在本节中，有以下章节：

+   第六章，信号和槽

+   第七章，模型视图编程

+   第八章，图形和动画

+   第九章，测试和调试

+   第十章，部署 Qt 应用程序

+   第十一章，国际化

+   第十二章，性能考虑


# 第六章：信号和槽

在之前的章节中，我们学习了如何使用 Qt Widgets 和 Qt Quick 创建 GUI 应用程序。但是为了使我们的应用程序可用，我们需要添加一个通信机制。**信号**和**槽**机制是 Qt 的一个独特特性，使其与其他框架不同。信号和槽是通过 Qt 的元对象系统实现的。

在本章中，您将深入了解信号和槽以及它们的内部工作原理。您将能够从不同的类中接收通知并采取相应的行动。

在本章中，我们将讨论以下主题：

+   理解 Qt 信号和槽

+   Qt 信号和槽的工作机制

+   了解 Qt 的属性系统

+   理解信号和处理程序事件系统

+   理解事件和事件循环

+   使用事件过滤器管理事件

+   拖放

通过本章结束时，您将能够在 C++类与 QML 之间以及 QML 组件之间进行通信。

# 技术要求

本章的技术要求包括在最新的桌面平台上安装 Qt（6.0.0）和 Qt Creator（4.14.0）的最低版本，例如 Windows 10、Ubuntu 20.04 或 macOS 10.14。

本章中的所有代码都可以从以下 GitHub 链接下载：

[`github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter06`](https://github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter06)

重要提示

本章中的屏幕截图是在 Windows 机器上拍摄的。您将在您的机器上看到基于底层平台的类似屏幕。

# 理解 Qt 信号和槽

在 GUI 编程中，当用户对任何 UI 元素执行任何操作时，另一个元素应该得到更新，或者应该执行某个特定的任务。为了实现这一点，我们需要对象之间的通信。例如，如果用户点击**标题**栏上的**关闭**按钮，预期窗口会关闭。不同的框架使用不同的方法来实现这种通信。**回调**是最常用的方法之一。回调是作为参数传递给另一个函数的函数。回调可能有多个缺点，并且可能在确保回调参数的类型正确性方面出现复杂性。

在 Qt 框架中，我们有一个称为信号和槽的回调技术的替代方法。信号是传递的消息，用于传达对象状态已更改。这个信号可能携带有关已发生更改的信息。槽是在特定信号的响应中调用的特殊函数。由于槽是函数，它们包含执行某个动作的逻辑。Qt Widgets 有许多预定义的信号，但您始终可以扩展您的类并向其添加自己的信号。同样，您也可以添加自己的槽来处理预期的信号。信号和槽使得实现观察者模式变得容易，同时避免样板代码。

为了能够通信，您必须连接相应的信号和槽。让我们了解信号和槽连接的连接机制和语法。

## 理解语法

要将信号连接到槽，我们可以使用`QObject::connect()`。这是一个线程安全的函数。标准语法如下：

```cpp
QMetaObject::Connection QObject::connect(
       const QObject *senderObject, const char *signalName, 
       const QObject *receiverObject, const char *slotName, 
       Qt::ConnectionType type = Qt::AutoConnection)
```

在前面的连接中，第一个参数是发送方对象，而下一个参数是发送方的信号。第三个参数是接收方对象，而第四个是槽方法。最后一个参数是可选的，描述要建立的连接类型。它确定通知是立即传递给槽还是排队等待。在 Qt 6 中可以建立六种不同类型的连接。让我们来看看连接类型：

+   使用`Qt::DirectConnection`；否则，使用`Qt::QueuedConnection`。

+   **Qt::DirectConnection**：在这种情况下，信号和槽都位于同一线程中。信号发射后立即调用槽。

+   **Qt::QueuedConnection**：在这种情况下，槽位于另一个线程中。一旦控制返回到接收者线程的事件循环，就会调用槽。

+   `Qt::QueuedConnection`，除了发出信号的线程会阻塞，直到槽返回。如果发送者和接收者在同一线程中，则不能使用此连接以避免死锁。

+   `按位或`。这用于避免重复连接。如果连接已经存在，则连接将失败。

+   `Qt::BlockingQueuedConnection`以避免死锁。您正在向同一线程发送事件，然后锁定线程，等待事件被处理。由于线程被阻塞，事件将永远不会被处理，线程将永远被阻塞，导致死锁。如果知道自己在做什么，请使用此连接类型。在使用此连接类型之前，必须了解两个线程的实现细节。

有几种连接信号和槽的方法。在指定信号和槽函数时，必须使用`SIGNAL()`和`SLOT()`宏。最常用的语法如下：

```cpp
QObject::connect(this, SIGNAL(signalName()), 
                 this, SLOT(slotName()));
```

这是自 Qt 诞生以来就存在的原始语法。但是，它的实现已经多次更改。新功能已添加，而不会破坏基本的**应用程序编程接口**（**API**）。建议使用新的函数指针语法，如下所示：

```cpp
connect(sender, &MyClass::signalName, this, 
        &MyClass::slotName);
```

这两种语法各有优缺点。您可以在以下链接中了解有关**基于字符串**和**基于函数对象**连接之间的区别的更多信息：

[`doc.qt.io/qt-6/signalsandslots-syntaxes.html`](https://doc.qt.io/qt-6/signalsandslots-syntaxes.html)

如果连接失败，则前面的语句返回`false`。您还可以按如下方式连接到函数对象或 C++11 lambda：

```cpp
connect(sender, &MyClass::signalName, this, [=]()
        { sender->doSomething(); });
```

您可以检查返回值以验证信号是否成功连接到槽。如果签名不兼容，或者信号和槽缺失，连接可能会失败。

重要说明

`Qt::UniqueConnection`不适用于 lambda、非成员函数和函数对象；它只能用于连接到成员函数。

信号和槽的签名可能包含参数，并且这些参数可能具有默认值。如果信号的参数至少与槽的参数一样多，并且相应参数的类型之间存在可能的隐式转换，则可以将信号连接到槽。让我们看一下具有不同参数数量的可行连接：

```cpp
connect(sender, SIGNAL(signalName(int)), this, 
        SLOT(slotName(int)));
connect(sender, SIGNAL(signalName(int)), this, 
        SLOT(slotName()));
connect(sender, SIGNAL(signalName()), this, 
        SLOT(slotName()));
```

但是，以下情况将无法正常工作，因为槽的参数比信号的参数多：

```cpp
connect(sender, SIGNAL(signalName()), this, 
        SLOT(slotName(int)));
```

您建立的每个连接都会发射一个信号，因此重复的连接会发射两个信号。您可以使用`disconnect()`来断开连接。

您还可以将 Qt 与第三方信号/槽机制一起使用。如果要在同一项目中使用两种机制，则将以下配置添加到 Qt 项目（`.pro`）文件中：

```cpp
 CONFIG += no_keywords
```

让我们创建一个简单的信号和槽连接的示例。

## 声明信号和槽

要创建信号和槽，必须在自定义类中声明信号和槽。类的头文件将如下所示：

```cpp
#ifndef MYCLASS_H
#define MYCLASS_H
#include <QObject>
class MyClass : public QObject
{
    Q_OBJECT
public:
    explicit MyClass(QObject *parent = nullptr);
signals:
    void signalName();
public slots:
    void slotName();
};
#endif // MYCLASS_H
```

如您所见，我们已向类添加了`Q_OBJECT`以便于信号和槽机制。您可以在头文件中使用`signals`关键字声明信号，如前面的代码片段所示。类似地，可以使用`slots`关键字声明槽。信号和槽都可以带有参数。在此示例中，我们使用相同的对象作为发送者和接收者，以使解释更简单。在大多数情况下，信号和槽将位于不同的类中。

接下来，我们将讨论如何将信号连接到槽。

## 将信号连接到槽

之前，我们声明了一个自定义信号和槽。现在，让我们看看如何连接它们。您可以在`MyClass`内定义信号和槽的连接，并发出信号，如下所示：

```cpp
#include "myclass.h"
#include <QDebug>
MyClass::MyClass(QObject *parent) : QObject(parent)
{
    QObject::connect(this, SIGNAL(signalName()), 
               this, SLOT(slotName()));
    emit signalName();
}
void MyClass::slotName()
{
    qDebug()<< "Slot called!";
}
```

在连接后需要发出信号以调用槽。在前面的例子中，我们使用了信号和槽声明的传统方式。您可以将连接替换为最新的语法，如下所示：

```cpp
connect(this, &MyClass::signalName, this, 
        &MyClass::slotName);
```

不仅可以将一个信号连接到一个槽，还可以连接多个槽和信号。同样，许多信号可以连接到一个槽。我们将在下一节中学习如何做到这一点。

## 将单个信号连接到多个槽

您可以将相同的信号连接到多个槽。这些槽将按照连接的顺序依次调用。假设一个名为`signalX()`的信号连接到名为`slotA()`、`slotB()`和`slotC()`的三个槽。当发出`signalA()`时，所有三个槽都将被调用。

让我们来看看传统的连接方式：

```cpp
    QObject::connect(this, SIGNAL(signalX()),this, 
                     SLOT(slotA()));
    QObject::connect(this, SIGNAL(signalX()),this, 
                     SLOT(slotB()));
    QObject::connect(this, SIGNAL(signalX()),this, 
                     SLOT(slotC()));
```

您还可以按照新的语法创建连接，如下所示：

```cpp
connect(this, &MyClass:: signalX, this, &MyClass:: slotA);
connect(this, &MyClass:: signalX, this, &MyClass:: slotB);
connect(this, &MyClass:: signalX, this, &MyClass:: slotC);
```

在下一节中，我们将学习如何将多个信号连接到单个槽。

## 将多个信号连接到单个槽

在前面的部分中，您学习了如何在单个信号和多个槽之间创建连接。现在，让我们看一下以下代码，以了解如何将多个信号连接到单个槽：

```cpp
    QObject::connect(this, SIGNAL(signalX()),this, 
                     SLOT(slotX()));
    QObject::connect(this, SIGNAL(signalY()),this, 
                     SLOT(slotX()));
    QObject::connect(this, SIGNAL(signalZ()),this, 
                     SLOT(slotX()));
```

在这里，我们使用了三个不同的信号，分别是`signalX()`、`signalY()`和`signalZ()`，但是只定义了一个名为`slotX()`的槽。当任何一个这些信号被发出时，都会调用该槽。

在下一节中，我们将学习如何将一个信号连接到另一个信号。

## 连接一个信号到另一个信号

有时，您可能需要转发一个信号，而不是直接连接到一个槽。您可以按照以下方式将一个信号连接到另一个信号：

```cpp
connect(sender, SIGNAL(signalA()),forwarder, 
        SIGNAL(signalB())));
```

您还可以按照新的语法创建连接，如下所示：

```cpp
connect(sender,&ClassName::signalA,forwarder,&ClassName::
        signalB);
```

在前面的行中，我们已经将`signalA()`连接到`signalB()`。因此，当发出`signalA()`时，`signalB()`也将被发出，并且连接到`signalB()`的相应槽将被调用。假设我们的 GUI 中有一个按钮，并且我们希望将按钮点击转发为不同的信号。以下代码片段显示了如何转发信号：

```cpp
#include <QWidget>
class QPushButton;
class MyClass : public QWidget
{
    Q_OBJECT
public:
    MyClass(QWidget *parent = nullptr);
    ~MyClass();
signals:
     void signalName();
 private:
     QPushButton *myButton;
};
MyClass::MyClass(QWidget *parent)
    : QWidget(parent)
{
    myButton = new QPushButton(this);
    connect(myButton, &QPushButton::clicked,
            this, &MyClass::signalName);
} 
```

在前面的例子中，我们将按钮点击信号转发到我们的自定义信号。我们可以调用连接到自定义信号的槽，就像之前讨论的那样。

在本节中，我们学习了如何进行连接以及如何使用信号和槽。现在，你可以在不同的类之间进行通信并共享信息。在下一节中，我们将学习信号和槽背后的工作机制。

# Qt 信号和槽的工作机制

在前面的部分中，我们学习了信号和槽的语法以及如何连接它们。现在，我们将了解它是如何工作的。

在创建连接时，Qt 会查找信号和槽的索引。Qt 使用查找字符串表来找到相应的索引。然后，创建一个`QObjectPrivate::Connection`对象并将其添加到内部链接列表中。由于一个信号可以连接到多个槽，每个信号可以有一个连接的槽列表。每个连接包含接收者的名称和槽的索引。每个对象都有一个连接向量，与`QObjectPrivate::Connection`的链接列表中的每个信号相关联。

以下图示了`ConnectionList`如何在发件人和接收者对象之间创建连接：

![图 6.1 - 发件人和接收者之间连接机制的说明](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_6.1_B16231.jpg)

图 6.1 - 发件人和接收者之间连接机制的说明

`ConnectionList`是一个包含与对象之间所有连接的单向链表。`signalVector`包含给定信号的连接列表。每个`Connection`也是*senders*链表的一部分。使用链表是因为它们允许更快地添加和删除对象。每个对象还有一个反向连接列表，用于自动删除对象。有关详细的内部实现，请查看最新的`qobject_p.h`。

在*woboq*网站上有很多关于信号和槽工作原理的文章。您还可以在 woboq 网站上探索 Qt 源代码。如果需要更多信息，请访问以下链接：

[`woboq.com/blog/how-qt-signals-slots-work.html`](https://woboq.com/blog/how-qt-signals-slots-work.html)。

现在，让我们了解一下 Qt 的元对象系统。

## Qt 的元对象系统

**Qt 的元对象系统**是信号和槽机制背后的核心机制。它提供了诸如对象间通信、动态属性系统和运行时类型信息等功能。

元对象系统是通过三部分机制实现的。这些机制如下：

+   QObject

+   Q_OBJECT 宏

+   元对象编译器

`QObject`类是所有 Qt 对象的基类。它是一个非常强大的机制，可以促进信号和槽机制。`QObject`类为可以利用元对象系统的对象提供了一个基类。`QObject`派生类在对象树中排列，从而在类之间创建了父子关系。当您创建一个`QObject`派生类，并将另一个`QObject`派生类作为父类时，该对象将自动添加到父类的`children()`列表中。父类将拥有该对象。GUI 编程需要运行时效率和高度的灵活性。Qt 通过将 C++的速度与 Qt 对象模型的灵活性相结合来实现这一点。Qt 通过基于从 QObject 继承的标准 C++技术来提供所需的功能。

您可以在以下链接了解有关 Qt 对象模型的更多信息：

[`doc.qt.io/qt-6/object.html`](https://doc.qt.io/qt-6/object.html)。

`Q_OBJECT`宏出现在类声明的私有部分。它用于启用 Qt 元对象系统提供的信号、槽和其他服务。

`QObject`派生类用于实现元对象特性。它提供了在运行时检查对象的能力。默认情况下，C++不支持内省。因此，Qt 创建了`moc`。这是一个处理 Qt 的 C++扩展的代码生成程序。该工具读取 C++头文件，如果找到`Q_OBJECT`宏，那么它会创建另一个包含元对象代码的 C++源文件。生成的文件包含了内省所需的代码。这两个文件被编译和链接在一起。除了为对象之间的通信提供信号和槽机制之外，元对象代码还提供了几个额外的功能，可以找到类名和继承详情，并且还可以帮助在运行时设置属性。Qt 的`moc`提供了一种超越编译语言功能的清晰方式。

您可以使用`qobject_cast()`在`QObject`派生类上执行类型转换。`qobject_cast()`函数类似于标准的 C++ `dynamic_cast()`。优点是它不需要`QObject`，但如果您不添加`Q_OBJECT`宏，那么信号和槽以及其他元对象系统功能将不可用。没有元代码的`QObject`派生类等同于包含元对象代码的最近祖先。还有一个更轻量级的`Q_OBJECT`宏的版本，称为`Q_GADGET`，可以用于利用`QMetaObject`提供的一些功能。使用`Q_GADGET`的类没有信号或槽。

我们在这里看到了一些新关键字，如`Q_OBJECT`、`signals`、`slots`、`emit`、`SIGNAL`和`SLOT`。这些被称为 C++的 Qt 扩展。它们是非常简单的宏，旨在被`moc`看到，定义在`qobjectdefs.h`中。其中，`emit`是一个空的宏，不会被`moc`解析。它只是为了给开发人员提供提示。

您可以在[`doc.qt.io/qt-6/why-moc.html`](https://doc.qt.io/qt-6/why-moc.html)了解为什么 Qt 使用`moc`来处理信号和槽。

在本节中，我们了解了 Qt 的元对象系统。在下一节中，我们将讨论`moc`生成的代码并讨论一些底层实现。

## MOC 生成的代码

在本节中，我们将看一下 Qt6 中由`moc`生成的代码。当您构建之前的信号和槽示例时，您会在构建目录下看到生成的文件：`moc_myclass.cpp`和`moc_predefs.h`。让我们用文本编辑器打开`moc_myclass.cpp`文件：

```cpp
#include <memory>
#include "../../SignalSlotDemo/myclass.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'myclass.h' doesn't include 
        <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.0.2\. 
        It"
#error "cannot be used with the include files from this 
        version of Qt."
#error "(The moc has changed too much.)"
#endif
```

您可以在文件顶部找到有关 Qt 元对象编译器版本的信息。请注意，对此文件所做的所有更改将在重新编译项目时丢失。因此，请不要修改此文件中的任何内容。我们正在查看该文件以了解工作机制。

让我们看一下`QMetaObject`的整数数据。您可以看到有两列；第一列是计数，而第二列是数组中的索引：

```cpp
static const uint qt_meta_data_MyClass[] = {
 // content:
       9,       // revision
       0,       // classname
       0,    0, // classinfo
       2,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount
 // signals: name, argc, parameters, tag, flags, initial 
 // metatype offsets
       1,    0,   26,    2, 0x06,    0 /* Public */,
 // slots: name, argc, parameters, tag, flags, initial 
 // metatype offsets
       3,    0,   27,    2, 0x0a,    1 /* Public */,
 // signals: parameters
    QMetaType::Void,
 // slots: parameters
    QMetaType::Void,
       0        // eod
};
```

在这种情况下，我们有一个方法，方法的描述从索引 14 开始。您可以在`signalCount`中找到可用信号的数量。对于每个函数，`moc`还保存每个参数的返回类型、它们的类型和它们的索引到名称。在每个元对象中，方法被赋予一个索引，从 0 开始。它们按信号、然后是槽，然后是其他函数排列。这些索引是相对索引，不包括父对象的索引。

当您进一步查看代码时，您会发现`MyClass::metaObject()`函数。这个函数返回动态元对象的`QObject::d_ptr->dynamicMetaObject()`。`metaObject()`函数通常返回类的`staticMetaObject`：

```cpp
const QMetaObject *MyClass::metaObject() const
{
    return QObject::d_ptr->metaObject 
? QObject::d_ptr->dynamicMetaObject() 
: &staticMetaObject;
}
```

当传入的字符串数据匹配当前类时，必须将此指针转换为 void 指针并传递给外部世界。如果不是当前类，则调用父类的`qt_metacast()`来继续查询：

```cpp
void *MyClass::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, 
                qt_meta_stringdata_MyClass.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}
```

Qt 的元对象系统使用`qt_metacall()`函数来访问特定`QObject`对象的元信息。当我们发出一个信号时，会调用`qt_metacall()`，然后调用真实的信号函数：

```cpp
int MyClass::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 2)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 2;
    } else if (_c == QMetaObject::
               RegisterMethodArgumentMetaType) {
        if (_id < 2)
            *reinterpret_cast<QMetaType *>(_a[0]) = 
                                           QMetaType();
        _id -= 2;
    }
    return _id;
}
```

当您调用一个信号时，它调用了`moc`生成的代码，内部调用了`QMetaObject::activate()`，如下面的代码片段所示。然后，`QMetaObject::activate()`查看内部数据结构，以了解连接到该信号的槽。

您可以在`qobject.cpp`中找到此函数的详细实现：

```cpp
void MyClass::signalName()
{
    QMetaObject::activate(this, &staticMetaObject, 0, 
                          nullptr);
}
```

通过这样做，您可以探索完整生成的代码并进一步查看符号。现在，让我们看一下`moc`生成的代码，其中调用了槽。槽是通过`qt_static_metacall`函数中的索引来调用的，如下所示：

```cpp
void MyClass::qt_static_metacall(QObject *_o, 
    QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<MyClass *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->signalName(); break;
        case 1: _t->slotName(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (MyClass::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == 
                static_cast<_t>(&MyClass::signalName)) {
                *result = 0;
                return;
            }
        }
    }
    (void)_a;
}
```

参数的数组指针的格式与信号相同。`_a[0]`没有被触及，因为这里的一切都返回 void：

```cpp
bool QObject::isSignalConnected(const QMetaMethod &signal) const
```

这将返回`true`，如果信号连接到至少一个接收器；否则，它将返回`false`。

当对象被销毁时，`QObjectPrivate::senders`列表被迭代，并且所有`Connection::receiver`被设置为`0`。此外，`Connection::receiver->connectionLists->dirty`被设置为`true`。还要迭代每个`QObjectPrivate::connectionLists`以删除发送者列表中的**连接**。

在本节中，我们浏览了一些`moc`生成的代码部分，并了解了信号和槽背后的工作机制。在下一节中，我们将学习 Qt 的属性系统。

# 了解 Qt 的属性系统

Qt 的属性系统类似于其他一些编译器供应商。但是它提供了跨平台的优势，并且可以与 Qt 在不同平台上支持的标准编译器一起使用。要添加一个属性，您必须将`Q_PROPERTY()`宏添加到`QObject`派生类中。这个属性就像一个类数据成员，但它提供了通过元对象系统可用的额外功能。一个简单的语法如下所示：

```cpp
Q_PROPERTY(type variableName READ getterFunction 
           WRITE setterFunction  NOTIFY signalName)
```

在上面的语法中，我们使用了一些最常见的参数。但是语法支持更多的参数。您可以通过阅读 Qt 文档了解更多信息。让我们看一下下面使用`MEMBER`参数的代码片段：

```cpp
     Q_PROPERTY(QString text MEMBER m_text NOTIFY 
                textChanged)
signals:
     void textChanged(const QString &newText);
private:
     QString m_text;
```

在上面的代码片段中，我们使用`MEMBER`关键字将一个成员变量导出为 Qt 属性。这里的类型是`QString`，`NOTIFY`信号用于实现 QML 属性绑定。

现在，让我们探讨如何使用元对象系统读取和写入属性。

## 使用元对象系统读取和写入属性

让我们创建一个名为`MyClass`的类，它是`QWidget`的子类。让我们在其私有部分添加`Q_OBJECT`宏以启用属性系统。在这个例子中，我们想在`MyClass`中创建一个属性来跟踪版本的值。属性的名称将是`version`，其类型将是`QString`，它在`MyClass`中定义。让我们看一下下面的代码片段：

```cpp
class MyClass : public QWidget
{
    Q_OBJECT
    Q_PROPERTY(QString version READ version WRITE 
               setVersion NOTIFY versionChanged)
public:
    MyClass(QWidget *parent = nullptr);
    ~MyClass();
    void setVersion(QString version)
    {
        m_version = version;
        emit versionChanged(version);
    }
    QString version() const { return m_version; }
    signals:
        void versionChanged(QString version);
    private:
       QString m_version;
};
```

要获得属性更改通知，您必须在更改`version`值后发出`versionChanged()`。

让我们看一下上面示例的`main.cpp`文件：

```cpp
int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MyClass myClass;
    myClass.setVersion("v1.0");
    myClass.show();
    return a.exec();
}
```

在上面的代码片段中，通过调用`setVersion()`来设置属性。您可以看到每次更改版本时都会发出`versionChanged()`信号。

您还可以使用`QObject::property()`读取属性，并使用`QObject::setProperty()`写入属性。您还可以使用`QObject::property()`查询动态属性，类似于编译时的`Q_PROPERTY()`声明。

您也可以这样设置属性：

```cpp
QObject *object = &myClass;
object->setProperty("version", "v1.0");
```

在本节中，我们讨论了属性系统。在下一节中，我们将学习 Qt Designer 中的信号和槽。

# 在 Qt Designer 中使用信号和槽

如果您使用 Qt Widgets 模块，那么可以使用 Qt Designer 在表单中编辑信号和槽连接。Qt 默认小部件带有许多信号和槽。让我们看看如何在 Qt Designer 中实现信号和槽而不编写任何代码。

您可以将**Dial**控件和**Slider**控件拖放到表单上。您可以通过底部选项卡上的**信号和槽编辑器**添加连接，如下面的截图所示：

![图 6.2 - 使用 Qt Designer 创建信号和槽连接](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_6.2_B16231.jpg)

图 6.2 - 使用 Qt Designer 创建信号和槽连接

或者，您可以按下*F4*或从顶部工具栏中选择**编辑信号/槽**按钮。然后，您可以选择控件并通过将连接拖动到接收器来创建连接。如果您为自定义类定义了自定义信号或槽，它们将自动显示在**信号和槽编辑器**中。但是，大多数开发人员更喜欢在 C++源文件中定义连接。

在本节中，我们讨论了使用 Qt Designer 在 Qt Widgets 中实现信号和槽。现在，让我们看一下在 QML 中如何处理信号。

# 了解 QML 中的信号和处理程序事件系统

之前，我们学习了如何在 C++源文件中连接信号和槽，并在 Qt Widgets 模块中使用它们。现在，让我们看看如何在 QML 中进行通信。QML 具有类似信号和槽的信号和处理程序机制。在 QML 文档中，信号是一个事件，通过信号处理程序响应信号。与 C++中的槽一样，当在 QML 中发射信号时，将调用信号处理程序。在 Qt 术语中，该方法是连接到信号的槽；在 QML 中定义的所有方法都被创建为 Qt 槽。因此，在 QML 中没有单独的槽声明。信号是来自对象的通知，表明发生了某个事件。您可以在 JavaScript 或方法内放置逻辑以响应信号。

让我们看看如何编写信号处理程序。您可以按如下方式声明信号处理程序：

```cpp
onSignalName : {
//Logic
}
```

这里，`signalName`是信号的名称。在编写处理程序时，信号的名称的第一个字母应大写。因此，这里的信号处理程序被命名为`onSignalName`。信号和信号处理程序应该在同一个对象内定义。信号处理程序内的逻辑是一段 JavaScript 代码块。

例如，当用户在鼠标区域内点击时，将发射`clicked()`信号。要处理`clicked()`信号，我们必须添加`onClicked:{...}`信号处理程序。

信号处理程序是由 QML 引擎在关联信号被发射时调用的简单函数。当您向 QML 对象添加信号时，Qt 会自动向对象定义中添加相应的信号处理程序。

让我们首先在 QML 文档中添加一个自定义信号。

## 在 QML 中添加信号

要在 QML 类中添加信号，必须使用`signal`关键字。定义新信号的语法如下：

```cpp
signal <name>[([<type> <parameter name>[...]])]
```

以下是一个示例：

```cpp
signal composeMessage(string message)
```

信号可以带参数也可以不带参数。如果没有为信号声明参数，则可以省略`()`括号。您可以通过调用它作为函数来发射信号：

```cpp
Rectangle {
    id: mailBox
    signal composeMessage(string message)
    anchors.fill: parent
    Button {
        id:sendButton
        anchors.centerIn: parent
        width: 100
        height: 50
        text: "Send"
        onClicked:  mailBox.composeMessage("Hello World!")
    }
    onComposeMessage: {
        console.log("Message Received",message)
    }
}
```

在前面的示例中，我们在 QML 文件中添加了一个自定义信号`composeMessage()`。我们使用了相应的信号处理程序`onComposeMessage()`。然后，我们添加了一个按钮，当点击按钮时会发射`composeMessage()`信号。当您运行此示例时，您将看到在点击按钮时信号处理程序会自动调用。

在本节中，您学习了如何声明信号以及如何实现相应的信号处理程序。在下一节中，我们将把信号连接到函数。

## 将信号连接到函数

您可以将信号连接到 QML 文档中定义的任何函数。您可以使用`connect()`将信号连接到函数或另一个信号。当信号连接到函数时，每当信号被发射时，该函数将自动调用。这种机制使得信号可以被函数而不是信号处理程序接收。

在以下代码片段中，使用`connect()`函数将`composeMessage()`信号连接到`transmitMessage()`函数：

```cpp
Rectangle {
    id: mailBox
    signal composeMessage(string message)
    anchors.fill: parent
    Text {
        id: textElement
        anchors {
            top:  parent.top
            left: parent.left
            right:parent.right
        }
        width: 100
        height:50
        text: ""
        horizontalAlignment: Text.AlignHCenter
    }
    Component.onCompleted: {
        mailBox.composeMessage.connect(transmitMessage)
        mailBox.composeMessage("Hello World!")
    }
    function transmitMessage(message) {
        console.log("Received message: " + message)
        textElement.text = message
    }
}
```

在 QML 中，信号处理是使用以下语法实现的：

```cpp
sender.signalName.connect(receiver.slotName)
```

您还可以使用`disconnect()`函数来删除连接。您可以这样断开连接：

```cpp
sender.signalName.disconnect(receiver.slotName)
```

现在，让我们探讨如何在 QML 中转发信号。

## 将信号连接到另一个信号

您可以在 QML 中将信号连接到另一个信号。您可以使用`connect()`函数实现这一点。

让我们通过以下示例来探讨如何做到这一点：

```cpp
Rectangle {
    id: mailBox
    signal forwardButtonClick()
    anchors.fill: parent
    Button {
        id:sendButton
        anchors.centerIn: parent
        width: 100
        height: 50
        text: "Send"
    }
    onForwardButtonClick: {
        console.log("Fordwarded Button Click Signal!")
    }
    Component.onCompleted: {
        sendButton.clicked.connect(forwardButtonClick)
    }
}
```

在前面的示例中，我们将`clicked()`信号连接到`forwardButtonClick()`信号。您可以在`onForwardButtonClick()`信号处理程序内部的根级别实现必要的逻辑。您还可以从按钮点击处理程序中发射信号，如下所示：

```cpp
onClicked: {
    mailBox.forwardButtonClick()
}
```

在本节中，我们讨论了如何连接两个信号并处理它们。在下一节中，我们将讨论如何使用信号和槽在 C++类和 QML 之间进行通信。

## 定义属性属性并理解属性绑定

之前，我们学习了如何通过注册类的`Q_PROPERTY`来定义 C++中的类型，然后将其注册到 QML 类型系统中。在 QML 文档中也可以创建自定义属性。属性绑定是 QML 的核心特性，允许我们创建各种对象属性之间的关系。您可以使用以下语法在 QML 文档中声明属性：

```cpp
[default] property <propertyType> <propertyName> : <value>
```

通过这种方式，您可以将特定参数暴露给外部对象，或更有效地维护内部状态。让我们看一下以下属性声明：

```cpp
property string version: "v1.0"
```

当您声明自定义属性时，Qt 会隐式创建该属性的属性更改信号。相关的信号处理程序是`on<PropertyName>Changed`，其中`<PropertyName>`是属性的名称，首字母大写。对于先前声明的属性，相关的信号处理程序是`onVersionChanged`，如下所示：

```cpp
onVersionChanged:{…}
```

如果属性被分配了静态值，那么它将保持不变，直到显式分配新值。要动态更新这些值，您应该在 QML 文档中使用属性绑定。我们之前使用了简单的属性绑定，如下面的代码片段所示：

```cpp
width: parent.width
```

然而，我们可以将其与后端 C++类暴露的属性结合使用，如下所示：

```cpp
property string version: myClass.version
```

在上一行中，`myClass`是已在 QML 引擎中注册的后端 C++对象。在这种情况下，每当从 C++端发出`versionChanged()`变化信号时，QML 的`version`属性会自动更新。

接下来，我们将讨论如何在 C++和 QML 之间集成信号和槽。

## 在 C++和 QML 之间集成信号和槽

在 C++中，要与 QML 层交互，可以使用信号、槽和`Q_INVOKABLE`函数。您还可以使用`Q_PROPERTY`宏创建属性。要响应来自对象的信号，可以使用`Connections` QML 类型。当 C++文件中的属性发生变化时，`Q_PROPERTY`会自动更新值。如果属性与任何 QML 属性绑定，它将自动更新 QML 中的属性值。在这种情况下，信号槽机制会自动建立。

让我们看一下以下示例，它使用了上述的机制：

```cpp
class CPPBackend : public QObject
{
    Q_OBJECT
    Q_PROPERTY(int counter READ counter WRITE setCounter 
               NOTIFY counterChanged)
public:
    explicit CPPBackend(QObject *parent = nullptr);
     Q_INVOKABLE  void receiveFromQml();
    int counter() const;
    void setCounter(int counter);
signals:
    void sendToQml(int);
    void counterChanged(int counter);
private:
    int m_counter = 0;
};
```

在上面的代码中，我们声明了基于 Q_PROPERTY 的通知。当发出`counterChanged()`信号时，我们可以获取新的`counter`值。然而，我们使用了`receiveFromQml()`函数作为`Q_INVOKABLE`函数，这样我们就可以直接在 QML 文档中调用它。我们正在发出`sendToQml()`，这在`main.qml`中进行处理：

```cpp
void CPPBackend::setCounter(int counter)
{
    if (m_counter == counter)
        return;
    m_counter = counter;
    emit counterChanged(m_counter);
}
void CPPBackend::receiveFromQml()
{
    // We increase the counter and send a signal with new 
    // value
    ++m_counter;
    emit sendToQml(m_counter);
}
```

现在，让我们看一下 QML 的实现：

```cpp
Window {
    width: 640
    height: 480
    visible: true
    title: qsTr("C++ QML Signals & Slots Demo")
    property int count: cppBackend.counter
    onCountChanged:{
        console.log("property is notified. Updated value 
                    is:",count)
    }
    Connections {
        target: cppBackend
        onSendToQml: {
            labelCount.text ="Fetched value is " 
                              +cppBackend.counter
        }
    }
    Row{
        anchors.centerIn: parent
        spacing: 20
        Text {
            id: labelCount
            text: "Fetched value is " + cppBackend.counter
        }
        Button {
            text: qsTr("Fetch")
            width: 100 ;height: 20
            onClicked: {
                cppBackend.receiveFromQml()
            }
        }
    }
}
```

在上面的示例中，我们使用`Connections`来连接到 C++信号。在按钮点击时，我们调用`receiveFromQml()` C++函数，在那里我们发出信号。我们还声明了`count`属性，它也监听`counterChanged()`。我们在相关的信号处理程序`onCountChanged`中处理数据；也就是说，我们也可以根据通知更新`labelCount`数据：

![图 6.3 - 在这个例子中使用的机制](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_6.3_B16231.jpg)

图 6.3 - 在这个例子中使用的机制

上图说明了此示例中的通信机制。为了解释的目的，我们在同一个示例中保留了多种方法，以解释 C++和 QML 之间的通信机制。

在本节中，您通过示例学习了信号和槽机制。在下一节中，我们将学习 Qt 中的事件和事件循环。

# 理解事件和事件循环

Qt 是一个基于事件的系统，所有 GUI 应用程序都是事件驱动的。在事件驱动的应用程序中，通常有一个主循环，它监听事件，然后在检测到其中一个事件时触发回调函数。事件可以是自发的或合成的。自发事件来自外部环境。合成事件是应用程序生成的自定义事件。在 Qt 中，事件是表示已发生的事情的通知。Qt 事件是值类型，派生自`QEvent`，为每个事件提供了类型枚举。在 Qt 应用程序内部产生的所有事件都封装在从`QEvent`类继承的对象中。所有`QObject`派生类都可以重写`QObject::event()`函数，以处理其实例所针对的事件。事件可以来自应用程序内部和外部。

当事件发生时，Qt 通过构造适当的`QEvent`子类实例来产生一个事件对象，然后通过调用其`event()`函数将其传递给特定的`QObject`实例。与信号和槽机制不同，信号连接的槽通常会立即执行，事件必须等待其轮次，直到事件循环分发所有先前到达的事件。您必须根据您的预期实现选择正确的机制。以下图表说明了事件在事件驱动应用程序中是如何创建和管理的：

![图 6.4 - 使用事件循环的事件驱动应用程序的说明](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_6.4_B16231.jpg)

图 6.4 - 使用事件循环的事件驱动应用程序的说明

我们可以通过调用`QCoreApplication::exec()`进入 Qt 的主事件循环。应用程序会一直运行，直到调用`QCoreApplication::exit()`或`QCoreApplication::quit()`，这将终止循环。`QCoreApplication`可以在 GUI 线程中处理每个事件并将事件转发给 QObjects。请注意，事件不会立即传递；相反，它们会排队在事件队列中，并稍后依次处理。事件调度程序循环遍历此队列，将它们转换为`QEvent`对象，然后将事件分派到目标`QObject`。

简化的事件循环调度器可能如下所示：

```cpp
while(true) 
{
  dispatchEventsFromQueue();
  waitForEvents();
}
```

与事件循环相关的一些重要 Qt 类如下：

+   `event`队列。

+   `event`循环。

+   非 GUI 应用程序的`event`循环。

+   GUI 应用程序的`event`循环。

+   **QThread**用于创建自定义线程和管理线程。

+   **QSocketNotifier**用于监视文件描述符上的活动。

+   `event`循环。

您可以在 Qt 文档中了解这些类。以下链接提供了有关事件系统的更深入了解：

[`wiki.qt.io/Threads_Events_QObjects`](https://wiki.qt.io/Threads_Events_QObjects)。

在本节中，我们讨论了事件和 Qt 的事件循环。在下一节中，我们将学习如何使用事件过滤器过滤事件。

# 使用事件过滤器管理事件

在本节中，您将学习如何管理事件，如何过滤特定事件并执行任务。您可以通过重新实现事件处理程序和安装事件过滤器来实现事件过滤。您可以通过对感兴趣的小部件进行子类化并重新实现该事件处理程序来重新定义事件处理程序应该执行的操作。

Qt 提供了五种不同的事件处理方法，如下所示：

+   重新实现特定事件处理程序，如`paintEvent()`

+   重新实现`QObject::event()`函数

+   在`QObject`实例上安装事件过滤器

+   在`QApplication`实例上安装事件过滤器

+   子类化`QApplication`并重新实现`notify()`

以下代码处理了自定义小部件上的鼠标左键单击，同时将所有其他按钮点击传递给基类`QWidget`：

```cpp
void MyClass::mousePressEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton) 
    {
        // Handle left mouse button here
    } 
    else 
    {
        QWidget::mousePressEvent(event);
    }
}
```

在前面的示例中，我们仅过滤了左键按下事件。您可以在相应的块内添加所需的操作。以下图示了高级事件处理机制：

![图 6.5 - 事件过滤器机制的说明](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_6.5_B16231.jpg)

图 6.5 - 事件过滤器机制的说明

事件过滤器可以安装在应用程序实例或本地对象上。如果事件过滤器安装在`QCoreApplication`对象中，则所有事件将通过此事件过滤器。如果它安装在派生自`QObject`的类中，则发送到该对象的事件将通过事件过滤器。有时，可能没有适合特定操作的 Qt 事件类型。在这种情况下，可以通过从`QEvent`创建子类来创建自定义事件。您可以重新实现`QObject::event()`以过滤所需的事件，如下所示：

```cpp
#include <QWidget>
#include <QEvent>
class MyCustomEvent : public QEvent
{
public:
    static const QEvent::Type MyEvent 
                 = QEvent::Type(QEvent::User + 1);
};
class MyClass : public QWidget
{
    Q_OBJECT
public:
    MyClass(QWidget *parent = nullptr);
    ~MyClass();
protected:
    bool event(QEvent *event);
}; 
```

在这里，我们创建了一个名为`MyCustomEvent`的自定义事件类，并创建了一个自定义类型。

现在，让我们通过重新实现`event()`来过滤这些事件：

```cpp
bool MyClass::event(QEvent *event)
{
    if (event->type() == QEvent::KeyPress)
    {
        QKeyEvent *keyEvent= static_cast<QKeyEvent 
                                         *>(event);
        if (keyEvent->key() == Qt::Key_Enter)
        {
            // Handle Enter event event
            return true;
        }
    }
    else if (event->type() == MyCustomEvent::MyEvent)
    {
        MyCustomEvent *myEvent = static_cast<MyCustomEvent 
                                 *>(event);
        // Handle custom event
        return true;
    }
    return QWidget::event(event);
}
```

如您所见，我们已将其他事件传递给`QWidget::event()`以进行进一步处理。如果要阻止事件进一步传播，则`return true`；否则，`return false`。

事件过滤器是一个接收发送到对象的所有事件的对象。过滤器可以停止事件或将其转发给对象。如果对象已被安装为监视对象的事件过滤器，则它会筛选事件。还可以使用事件过滤器监视另一个对象的事件并执行必要的任务。以下示例显示了如何使用*事件过滤器*方法重新实现最常用的事件之一 - 按键事件。

让我们看一下以下代码片段：

```cpp
#include <QMainWindow>
class QTextEdit;
class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
protected:
    bool eventFilter(QObject *obj, QEvent *event) override;
private:
    QTextEdit *textEdit;
};
```

在前面的代码中，我们创建了一个名为`MainWindow`的类，并重写了`eventFilter()`。让我们使用`installEventFilter()`在`textEdit`上安装过滤器。您可以在一个对象上安装多个事件过滤器。但是，如果在单个对象上安装了多个事件过滤器，则最后安装的过滤器将首先被激活。您还可以通过调用`removeEventFilter()`来移除事件过滤器：

```cpp
#include "mainwindow.h"
#include <QTextEdit>
#include <QKeyEvent>
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    textEdit = new QTextEdit;
    setCentralWidget(textEdit);
    textEdit->installEventFilter(this);
}
```

在前面的代码中，我们在`textEdit`对象上安装了一个`eventFilter`。现在，让我们看一下`eventFilter()`函数：

```cpp
bool MainWindow::eventFilter(QObject *monitoredObj, QEvent *event)
{
    if (monitoredObj == textEdit)
    {
        if (event->type() == QEvent::KeyPress)
        {
            QKeyEvent *keyEvent = static_cast<QKeyEvent*>
                                  (event);
            qDebug() << "Key Press detected: " << 
                                          keyEvent->text();
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        return QMainWindow::eventFilter(monitoredObj, 
                                        event);
    }
}
```

在这里，`textEdit`是被监视的对象。每次按键时，如果`textEdit`处于焦点状态，则会捕获事件。由于可能有更多的子对象和`QMainWindow`可能需要事件，不要忘记将未处理的事件传递给基类以进行进一步的事件处理。

重要提示

在`eventFilter()`函数中消耗了事件后，确保`return true`。如果接收对象被删除并且`return false`，那么可能导致应用程序崩溃。

您还可以将信号和槽机制与事件结合使用。您可以通过过滤事件并发出与该事件对应的信号来实现这一点。希望您已经了解了 Qt 中的事件处理机制。现在，让我们来看看拖放。

# 拖放

在本节中，我们将学习**拖放**（**DnD**）。在 GUI 应用程序中，DnD 是一种指向设备手势，用户通过*抓取*虚拟对象然后*释放*到另一个虚拟对象来选择虚拟对象。拖放操作在用户进行被识别为开始拖动操作的手势时开始。

让我们讨论如何使用 Qt 小部件实现拖放。

## Qt 小部件中的拖放

在基于 Qt Widgets 的 GUI 应用程序中，使用拖放时，用户从特定的小部件开始拖动，并将被拖动的对象放到另一个小部件上。这要求我们重新实现几个函数并处理相应的事件。需要重新实现的最常见函数如下：

```cpp
void dragEnterEvent(QDragEnterEvent *event) override;
void dragMoveEvent(QDragMoveEvent *event) override;
void dropEvent(QDropEvent *event) override;
void mousePressEvent(QMouseEvent *event) override;
```

一旦您重新实现了上述函数，可以使用以下语句在目标小部件上启用放置：

```cpp
setAcceptDrops(true);
```

要开始拖动，创建一个`QDrag`对象，并传递一个指向开始拖动的小部件的指针。拖放操作由`QDrag`对象处理。此操作要求附加数据描述为**多用途互联网邮件扩展**（**MIME**）类型。

```cpp
QMimeData *mimeData = new QMimeData;
mimeData->setData("text/csv", csvData);
QDrag *dragObject = new QDrag(event->widget());
dragObject->setMimeData(mimeData);
dragObject->exec();
```

上面的代码显示了如何创建一个拖动对象并设置自定义 MIME 类型。在这里，我们使用`text/csv`作为 MIME 类型。您可以使用拖放操作提供多种类型的 MIME 编码数据。

要拦截拖放事件，可以重新实现`dragEnterEvent()`。当拖动正在进行并且鼠标进入小部件时，将调用此事件处理程序。

您可以在 Qt Creator 的示例部分中找到几个相关示例。由于 Qt 小部件在当今并不十分流行，我们将跳过使用小部件进行拖放的示例。在下一节中，我们将讨论 QML 中的拖放。

## 在 QML 中进行拖放

在前面的部分中，我们讨论了使用小部件进行拖放。由于 QML 用于创建现代和触摸友好的应用程序，拖放是一个非常重要的功能。Qt 提供了几种方便的 QML 类型来实现拖放。在内部，相应的事件处理方式是相似的。这些函数在`QQuickItem`类中声明。

例如，`dragEnterEvent()`也在`QQuickItem`中可用，用于拦截拖放事件，如下所述：

```cpp
void QQuickItem::dragEnterEvent(QDragEnterEvent *event)
```

让我们讨论如何使用可用的 QML 类型来实现这一点。使用`Drag`附加属性，任何`Item`都可以在 QML 场景中成为拖放事件的源。`DropArea`是一个可以在其上拖动项目时接收事件的不可见项目。当项目上存在拖动操作时，对其位置进行的任何更改都将生成一个拖动事件，该事件将发送到任何相交的`DropArea`。`DragEvent` QML 类型提供有关拖动事件的信息。

以下代码片段显示了在 QML 中进行简单拖放操作：

```cpp
Rectangle {
    id: dragItem
    property point beginDrag
    property bool caught: false
    x: 125; y: 275
    z: mouseArea.drag.active ||  mouseArea.pressed ? 2 : 1
    width: 50; height: 50
    color: "red"
    Drag.active: mouseArea.drag.active
    Drag.hotSpot.x: 10 ; Drag.hotSpot.y: 10
    MouseArea {
    id: mouseArea
    anchors.fill: parent
    drag.target: parent
    onPressed: dragItem.beginDrag = Qt.point(dragItem.x, 
                                             dragItem.y)
    onReleased: {
          if(!dragItem.caught) {
          dragItem.x = dragItem.beginDrag.x
          dragItem.y = dragItem.beginDrag.y
      }
    }
  }
}
```

在上面的代码中，我们创建了一个 ID 为`dragItem`的可拖动项。它包含一个`MouseArea`来捕获鼠标按下事件。拖动不仅限于鼠标拖动。任何可以生成拖动事件的东西都可以触发拖动操作。可以通过调用`Drag.cancel()`或将`Drag.active`状态设置为`false`来取消拖动。

通过调用`Drag.drop()`可以完成放置操作。让我们添加一个`DropArea`：

```cpp
Rectangle {
    x: parent.width/2
    width: parent.width/2 ; height:parent.height
    color: "lightblue"
    DropArea {
    anchors.fill: parent
    onEntered: drag.source.caught = true
    onExited: drag.source.caught = false
    }
}
```

在上面的代码片段中，我们使用浅蓝色矩形将其区分为屏幕上的`DropArea`。当`dragItem`进入`DropArea`区域时，我们捕获它。当`dragItem`离开`DropArea`区域时，放置操作被禁用。因此，当放置不成功时，项目将返回到其原始位置。

在本节中，我们了解了拖放操作及其相应的事件。我们讨论了如何在 Qt Widgets 模块以及在 QML 中实现它们。现在，让我们总结一下本章学到的内容。

# 摘要

在本章中，我们了解了 Qt 中信号和槽的核心概念。我们讨论了连接信号和槽的不同方式。我们还学习了如何将一个信号连接到多个槽，以及多个信号连接到单个槽。然后，我们看了如何在 Qt 小部件中使用它们，以及在 QML 中使用它们，以及信号和槽连接背后的机制。之后，您学会了如何使用信号和槽在 C++和 QML 之间进行通信。

本章还讨论了 Qt 中的事件和事件循环。我们探讨了如何使用事件而不是信号槽机制。在这之后，我们创建了一个带有自定义事件处理程序的示例程序，以捕获事件并对其进行过滤。

在了解了事件之后，我们实现了一个简单的拖放示例。现在，您可以在类之间、在 C++和 QML 之间进行通信，并根据事件实现必要的操作。

在下一章中，我们将学习关于模型视图编程以及如何创建自定义模型。


# 第七章：模型视图编程

模型/视图编程用于在 Qt 中处理数据集时将数据与视图分离。**模型/视图（M/V）**架构区分了功能，使开发人员可以以多种方式修改和呈现**用户界面（UI）**上的信息。我们将讨论架构的每个组件，Qt 提供的相关便利类，以及如何使用实际示例。在本章中，我们将讨论模型视图模式并了解基本核心概念。

在本章中，我们将讨论以下主题：

+   M/V 架构的基本原理

+   使用模型和视图

+   创建自定义模型和委托

+   在 Qt 小部件中使用 M/V 显示信息

+   在 QML 中使用 M/V 显示信息

+   使用 C++模型与 QML

在本章结束时，您将能够创建数据模型并在自定义 UI 上显示信息。您将能够编写自定义模型和委托。您还将学会通过 Qt 小部件和 QML 在 UI 中表示信息。

# 技术要求

本章的技术要求包括在最新的桌面平台之一（如 Windows 10、Ubuntu 20.04 或 macOS 10.14）上安装 Qt 6.0.0 和 Qt Creator 4.14.0 的最低版本。

本章中使用的所有代码都可以从以下 GitHub 链接下载：[`github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter07`](https://github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter07)。

重要提示

本章中使用的屏幕截图是在 Windows 平台上获取的。您将在您的机器上基于底层平台看到类似的屏幕。

# 理解 M/V 架构

传统上，在构建 UI 时经常使用**模型-视图-控制器（MVC）**设计模式。顾名思义，它由三个术语组成：模型、视图和控制器。**模型**是具有动态数据结构和逻辑的独立组件，**视图**是视觉元素，**控制器**决定 UI 如何响应用户输入。在 MVC 出现之前，开发人员通常将这些组件放在一起。虽然开发人员希望将控制器与其他组件分离，但并不总是可能。MVC 设计将组件解耦以增加灵活性和重用。以下图示了传统 MVC 模式的组件：

![图 7.1 – 传统 MVC 设计模式](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_7.1_B16231.jpg)

图 7.1 – 传统 MVC 设计模式

在 MVC 模式中，用户看到视图并与控制器交互。控制器将数据发送到模型，模型更新视图。如果视图和控制器组件合并，则会得到 M/V 架构。它提供了更灵活的架构。它基于相同的原则，但使实现变得更简单。修改后的架构允许我们在多个不同的视图中显示相同的数据。开发人员可以实现新类型的视图而不更改底层数据结构。为了将这种灵活性带入我们对用户输入的处理中，Qt 引入了**委托**的概念。视图接收通过委托更新的数据，而不是通过控制器。它有两个主要目的：

+   为了帮助视图呈现每个值

+   为了帮助视图在用户想要进行一些更改时

因此，在某种程度上，控制器已与视图合并，并且视图还通过委托执行了一些控制器的工作。拥有委托的好处在于它提供了渲染和修改数据元素的手段。

让我们通过图表了解 M/V 的实现和其组件：

![图 7.2 – Qt 模型-视图-委托框架](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_7.2_B16231.jpg)

图 7.2 - Qt 模型-视图-委托框架

如*图 7.2*所示，M/V 组件分为**模型**、**视图**和**委托**三个部分。**模型**与数据库交互，并作为架构其他组件的接口。通信的目的由数据源和模型的实现确定。**视图**获取称为**模型索引**的数据项的引用。视图可以通过使用这个模型索引从数据模型中检索单个数据项。在标准视图中，委托渲染数据项。当数据项被修改时，**委托**使用模型索引通知模型。

*图 7.3*说明了模型如何向视图提供数据，并在单个委托上显示：

![图 7.3 - 模型-视图-委托实现示意图](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_7.3_B16231.jpg)

图 7.3 - 模型-视图-委托实现示意图

Qt 框架提供了一组标准类，实现了 M/V 架构，用于管理数据与用户视图之间的关系。通过解耦功能，该架构提供了灵活性，可以定制数据的呈现方式，并允许将广泛的数据源与视图结合起来。

模型、视图和委托使用**信号和槽机制**进行通信。模型发出信号通知数据源中发生的数据更改。当用户与视图交互时，视图发出信号通知用户操作。委托发出信号通知模型和视图有关编辑状态的变化。

现在，您已经了解了 M/V 架构的基础知识。接下来的部分将解释如何在 Qt 中使用 M/V 模式。我们将从 Qt 框架提供的标准类开始，然后讨论在 Qt 部件中使用 M/V。您将学习如何根据 M/V 架构创建新组件。让我们开始吧！

## 模型

M/V 消除了标准部件可能出现的数据一致性挑战。它使得可以更容易地为相同数据使用多个视图，因为一个模型可以传递给多个视图。Qt 提供了几个 M/V 实现的抽象类，具有共同的接口和特定的功能实现。您可以对抽象类进行子类化，并添加其他组件期望的功能。在 M/V 实现中，模型提供了供视图和委托访问数据的标准接口。

Qt 提供了一些现成的模型类，如`QStandardItemModel`、`QFileSystemModel`和`QSqlTableModel`。`QAbstractItemModel`是 Qt 定义的标准接口。`QAbstractItemModel`的子类表示分层结构中的数据。*图 7.4*说明了模型类的层次结构：

![图 7.4 - Qt 中模型类的层次结构](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_7.4_B16231.jpg)

图 7.4 - Qt 中模型类的层次结构

视图使用这种方法访问模型中的单个数据项，但在呈现信息给用户的方式上并没有受到限制。通过模型传递的数据可以保存在数据结构或数据库中，也可以是其他应用程序组件。所有的项模型都是基于`QAbstractItemModel`类的。

*图 7.5*显示了不同类型的模型中数据的排列方式：

![图 7.5 - 不同类型的模型和数据排列方式](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_7.5_B16231.jpg)

图 7.5 - 不同类型的模型和数据排列方式

数据通过模型以表格形式表示，以行和列的形式表示，或者使用数据的分层表示。在 M/V 模式中，小部件不会在单元格后面存储数据。它们直接使用数据。您可能需要创建一个包装器，使您的数据与`QAbstractItemModel`接口兼容。视图使用此接口来读取和写入数据。任何从`QAbstractItemModel`派生的类都称为模型。它提供了一个处理以列表、表格和树形式表示数据的视图的接口。要为列表或类似表格的数据结构实现自定义模型，可以从`QAbstractListModel`和`QAbstractTableModel`派生以使用可用的功能。子类提供了适用于特定列表和表格的模型。

Qt 框架提供了两种标准类型的模型。它们如下：

+   `QStandardItemModel`

+   `QFileSystemModel`

`QStandardItemModel`是一个多用途模型，可以存储自定义数据。每个元素都指代一个项目。它可以用于显示列表、表格和树形视图所需的各种数据结构。它提供了一种传统的基于项目的处理模型。`QStandardItem`提供了在`QStandardItemModel`中使用的项目。

`QFileSystemModel`是一个保持目录内容信息的模型。它简单地表示本地文件系统上的文件和目录，并不保存任何数据项。它提供了一个现成的模型，用于创建一个示例应用程序，并且可以使用模型索引来操作数据。现在，让我们讨论一下委托是什么。

## 委托

委托提供对视图中显示的项目呈现的控制。M/V 模式与 MVC 模式不同，它没有一个完全不同的组件来处理用户交互。视图主要负责将模型数据显示给用户，并允许用户与其交互。为了增加用户操作的灵活性，委托处理这些交互。它赋予了某些小部件作为模型中可编辑项目的编辑器。委托用于提供交互功能并渲染视图中的单个字段。`QAbstractItemDelegate`类定义了管理委托的基本接口。Qt 提供了一些现成的委托类，可用于与内置小部件一起使用以修改特定的数据类型。

为了更好地理解，我们将看一下 Qt 框架中委托类的层次结构（见*图 7.6*）：

![图 7.6 - Qt 框架中委托类的层次结构](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_7.6_B16231.jpg)

图 7.6 - Qt 框架中委托类的层次结构

正如我们在前面的图表中所看到的，`QAbstractItemDelegate`是委托的抽象基类。`QStyledItemDelegate`提供了默认的委托实现。Qt 的标准视图将其用作默认委托。用于在视图中绘制和创建编辑器的其他选项是`QStyledItemDelegate`和`QItemDelegate`。您可以使用`QItemDelegate`来自定义项目的显示特性和编辑器小部件。这两个类之间的区别在于，与`QItemDelegate`不同，`QStyledItemDelegate`使用当前样式来绘制其项目。`QStyledItemDelegate`可以处理最常见的数据类型，如`int`和`QString`。在创建新委托或使用 Qt 样式表时，建议从`QStyledItemDelegate`派生子类。通过编写自定义委托，您可以使用自定义数据类型或自定义渲染。

在本节中，我们讨论了不同类型的模型和委托。让我们讨论一下 Qt Widgets 提供的视图类。

## Qt Widgets 中的视图

有几个便利类是从标准 View 类派生出来实现 M/V 模式的。这些便利类的示例包括`QListWidget`、`QTableWidget`和`QTreeWidget`。根据 Qt 文档，这些类比 View 类更不灵活，不能用于随机模型。根据项目要求，您必须选择适合实现 M/V 模式的小部件类。

如果您想使用基于项目的界面并利用 M/V 模式，建议使用以下 View 类与`QStandardItemModel`一起使用：

+   `QListView`显示项目列表。

+   `QTableView`在表格中显示模型数据。

+   `QTreeView`以分层列表显示模型数据项。

Qt 框架中 View 类的层次结构如下：

![图 7.7 - Qt 框架中 View 类的层次结构](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_7.7_B16231.jpg)

图 7.7 - Qt 框架中 View 类的层次结构

`QAbstractItemView`是上述类的抽象基类。尽管这些类提供了可直接使用的实现，但这些类可以派生为具有专门视图，最适合用于`QFileSystemModel`的视图是`QListView`和`QTreeView`。每个视图都必须与模型相关联。Qt 提供了几个预定义的模型。如果现成的模型不符合您的标准，您可以添加自定义模型。

与 View 类不同（类名以`View`结尾），便利小部件（类名以`Widget`结尾）不需要由模型支持，可以直接使用。使用便利小部件的主要优势是，它们需要的工作量最少。

让我们看看 Qt Widgets 模块中的不同 View 类以及可以与它们一起使用的现成模型：

![图 7.8 - 在 M/V 模式中用作 View 的不同类型的 Qt 小部件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_7.8_B16231.jpg)

图 7.8 - 在 M/V 模式中用作 View 的不同类型的 Qt 小部件

委托用于在`QListView`、`QTableView`或`QTreeView`中显示单个字段数据。当用户开始与项目交互时，委托提供一个编辑器小部件进行编辑。

您可以在以下链接找到上述类的比较概述，并了解相应小部件的用途：

[`doc.qt.io/qt-6/modelview.html`](https://doc.qt.io/qt-6/modelview.html)

在本节中，您了解了 M/V 架构并熟悉了所使用的术语。让我们使用 Qt Widgets 创建一个简单的 GUI 应用程序来实现 M/V。

# 使用 M/V 模式创建一个简单的 Qt Widgets 应用程序

现在是时候使用*Qt Widgets*创建一个简单的示例了。本节中的示例演示了如何将预定义的`QFileSystemModel`与内置的`QListView`和`QTreeView`小部件关联使用。当双击视图时，委托会自动处理。

按照以下步骤创建一个实现 M/V 模式的简单应用程序：

1.  使用 Qt Creator 创建一个新项目，从项目创建向导中选择**Qt Widgets**模板。它将生成一个带有预定义项目骨架的项目。

1.  创建应用程序骨架后，打开`.ui`表单并将`QListView`和`QTreeView`添加到表单中。您可以添加两个标签以区分视图，如下所示：![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_7.9_B16231.jpg)

图 7.9 - 使用 Qt Designer 创建一个带有 QListView 和 QTreeView 的 UI

1.  打开`mainwindow.cpp`文件并添加以下内容：

```cpp
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileSystemModel>
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    QFileSystemModel *model = new QFileSystemModel;
    model->setRootPath(QDir::currentPath());
    ui->treeView->setModel(model);
    ui->treeView->setRootIndex(
        model->index(QDir::currentPath()));
    ui->listView->setModel(model);
    ui->listView->setRootIndex(
        model->index(QDir::currentPath()));
}
```

在前面的 C++实现中，我们使用了预定义的`QFileSystemModel`作为 View 的模型。

1.  接下来，点击左侧窗格中的**运行**按钮。一旦您点击**运行**按钮，您将看到一个窗口，如*图 7.10*所示：

](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_7.10_B16231.jpg)

图 7.10 - 显示 QListView 和 QTreeView 的示例应用程序的输出

1.  让我们修改现有的应用程序，使用从`QAbstractItemModel`派生的自定义模型。在以下示例中，我们创建了一个简单的`ContactListModel`自定义类，它是从`QAbstractItemModel`派生的：

```cpp
void ContactListModel::addContact(QAbstractItemModel *model, 
const QString &name,const QString &phoneno, const QString &emailid)
{
    model->insertRow(0);
    model->setData(model->index(0, 0), name);
    model->setData(model->index(0, 1), phoneno);
    model->setData(model->index(0, 2), emailid);
}
QAbstractItemModel* ContactListModel::
        getContactListModel()
{
    QStandardItemModel *model = new 
        QStandardItemModel(0, 3, this);
    model->setHeaderData(0,Qt::Horizontal, 
                         QObject::tr("Name"));
    model->setHeaderData(1,Qt::Horizontal, 
                         QObject::tr("Phone No"));
    model->setHeaderData(2,Qt::Horizontal, 
                         QObject::tr("Email ID"));
    addContact(model,"John","+1 
               1234567890","john@abc.com");
    addContact(model,"Michael","+44 
               213243546","michael@abc.com");
    addContact(model,"Robert","+61 
               5678912345","robert@xyz.com");
    addContact(model,"Kayla","+91 
               9876554321","kayla@xyz.com");
    return model;
}
```

1.  接下来，修改 UI 表单以实现`QTableView`，并将联系人列表模型设置为以下代码段所示：

```cpp
ContactListModel *contactModel = new ContactListModel;
ui->tableView->setModel(
               contactModel->getContactListModel());
ui->tableView->horizontalHeader()->setStretchLastSection(true);
```

1.  您可以将`QStringListModel`添加到`QListView`中以使用简单的列表模型：

```cpp
    QStringListModel *model = new QStringListModel(this);
    QStringList List;
    List << "Item 1" << "Item 2" << "Item 3" <<"Item 4";
    model->setStringList(List);
    ui->listView->setModel(model);
```

1.  接下来，点击左侧窗格中的**运行**按钮。一旦您点击**运行**按钮，您将看到一个窗口，如*图 7.11*所示：

![图 7.11 - 使用自定义模型在 QListView 和 QTableView 中的应用程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_7.11_B16231.jpg)

图 7.11 - 使用自定义模型在 QListView 和 QTableView 中的应用程序输出

恭喜！您已经学会了如何在 Qt 小部件项目中使用 M/V。

重要提示

要了解更多关于方便类的实现，例如`QTableWidget`或`QtTreeWidget`，请在 Qt Creator 欢迎屏幕和本章的源代码中探索相关示例。

您还可以创建自己的自定义委托类。要创建自定义委托，您需要对`QAbstractItemDelegate`或任何方便类（如`QStyledItemDelegate`或`QItemDelegate`）进行子类化。自定义委托类可能如下面的代码片段所示：

```cpp
class CustomDelegate: public QStyledItemDelegate
{
  Q_OBJECT
public:
  CustomDelegate(QObject* parent = nullptr);
  void paint(QPainter* painter, 
             const QStylestyleOptionViewItem& styleOption,
             const QModelIndex& modelIndex) const override;
  QSize sizeHint(const QStylestyleOptionViewItem& styleOption,
                 const QModelIndex& modelIndex) const override;
  void setModelData(QWidget* editor, QAbstractItemModel* model,
                    const QModelIndex& modelIndex)                     const override;
  QWidget *createEditor(QWidget* parent, 
                  const QStylestyleOptionViewItem& styleOption,
                  const QModelIndex & modelIndex)                   const override;
  void setEditorData(QWidget* editor, 
                    const QModelIndex& modelIndex)                     const override;
  void updateEditorGeometry(QWidget* editor, 
                  const QStylestyleOptionViewItem& styleOption, 
                  const QModelIndex& modelIndex)                   const override;
};
```

您必须重写虚拟方法，并根据项目需求添加相应的逻辑。您可以在以下链接了解有关自定义委托和示例的更多信息：

[`doc.qt.io/qt-6/model-View-programming.html`](https://doc.qt.io/qt-6/model-View-programming.html)

在本节中，我们学习了如何创建使用 M/V 模式的 GUI 应用程序。在下一节中，我们将讨论它在 QML 中的实现方式。

# 了解 QML 中的模型和视图

与 Qt 小部件一样，Qt Quick 也实现了模型、视图和委托来显示数据。该实现将数据的可视化模块化，使开发人员能够管理数据。您可以通过最小的更改来将一个视图更改为另一个视图。

要可视化数据，将视图的`model`属性绑定到模型，将`delegate`属性绑定到组件或其他兼容类型。

让我们讨论在 Qt Quick 应用程序中实现 M/V 模式的可用 QML 类型。

## Qt Quick 中的视图

视图是显示数据的容器，用于项目集合。这些容器功能丰富，可以根据特定的样式或行为要求进行定制。

在 Qt Quick 图形类型的基本集中提供了一组标准视图：

+   `ListView`：以水平或垂直列表方式布置项目

+   `GridView`：以网格方式布置项目

+   `TableView`：以表格形式布置项目

+   `PathView`：在路径上布置项目

`ListView`、`GridView`和`TableView`继承自`Flickable` QML 类型。`PathView`继承自`Item`。`TreeView` QML 类型已经过时。让我们看一下这些 QML 类型的继承关系：

![图 7.12 - Qt Quick 中视图类的层次结构](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_7.12_B16231.jpg)

图 7.12 - Qt Quick 中视图类的层次结构

每种 QML 类型的属性和行为都不同。它们根据 GUI 需求使用。如果您想了解更多关于 QML 类型的信息，可以参考它们各自的文档。让我们在下一节中探索 Qt Quick 中的模型。

## Qt Quick 中的模型

Qt 提供了几种方便的 QML 类型来实现 M/V 模式。这些模块提供了非常简单的模型，而无需在 C++中创建自定义模型类。这些方便类的示例包括`ListModel`、`TableModel`和`XmlListModel`。

`QtQml.Models` 模块提供以下用于定义数据模型的 QML 类型：

+   `ListModel` 定义了一个自由形式的列表数据源。

+   `ListElement` 定义了 `ListModel` 中的数据项。

+   `DelegateModel` 封装了一个模型和委托。

+   `DelegateModelGroup` 封装了一组经过筛选的可视数据项目。

+   `ItemSelectionModel` 继承自 `QItemSelectionModel`，它跟踪视图的选定项目。

+   `ObjectModel` 定义了一组要用作模型的项目。

+   `Instantiator` 动态实例化对象。

+   `Package` 描述了一组命名的项目。

要在您的 Qt Quick 应用程序中使用上述 QML 类型，请使用以下行导入模块：

`import QtQml.Models`

让我们讨论在 Qt Quick 中可用的现成模型。`ListModel` 是包含包含数据角色的 `ListElement` 定义的简单容器。它与 `ListView` 一起使用。`Qt.labs.qmlmodels` 提供了用于模型的实验性 QML 类型。这些模型可用于快速原型设计和显示非常简单的数据。`TableModel` 类型将 JavaScript/JSON 对象作为表模型的数据进行存储，并与 `TableView` 一起使用。您可以通过以下方式导入这些实验性类型：

`import Qt.labs.qmlmodels`

如果您想从 XML 数据创建模型，那么可以使用 `XmlListModel`。它可以与 `ListView`、`PathView` 和 `GridView` 等视图一起使用作为模型。要使用此模型，您必须按照以下方式导入模块：

`import QtQuick.XmlListModel`

您可以使用 `ListModel` 和 `XmlListModel` 与 `TableView` 一起创建 `TableView` 中的一列。要处理多行和多列，您可以使用 `TableModel` 或者通过子类化 `QAbstractItemModel` 创建自定义的 C++ 模型。

您还可以使用 `Repeater` 与 Models。整数可以用作定义项目数量的模型。在这种情况下，模型没有任何数据角色。让我们创建一个简单的示例，使用 `ListView` 和 `Text` 项目作为委托组件：

```cpp
import QtQuick
import QtQuick.Window
Window {
    width: 640
    height: 480
    visible: true
    title: qsTr("Simple M/V Demo")
    ListView {
        anchors.fill: parent
        model: 10
        delegate: itemDelegate
    }
    Component {
        id: itemDelegate
        Text { text: "  Item :  " + index }
    }
} 
```

在前面的示例中，我们使用了 `Text` 作为委托，而没有使用组件。

现在，让我们探讨如何将 `ListModel` 与 `ListView` 一起使用。`ListModel` 是在 QML 中指定的一组简单的类型层次结构。可用的角色由 `ListElement` 属性指定。让我们使用 `ListModel` 与 `ListView` 创建一个简单的应用程序。

假设您想创建一个简单的通讯录应用程序。您可能需要一些用于联系人的字段。在以下代码片段中，我们使用了一个包含一些联系人的姓名、电话号码和电子邮件地址的 `ListModel`：

```cpp
ListModel {
    id: contactListModel
    ListElement {
        name: "John" ; phone: "+1 1234567890" ; 
        email: "john@abc.com"
    }
    ListElement {
        name: "Michael" ; phone: "+44 213243546" ; 
        email: "michael@abc.com"
    }
    ListElement {
        name: "Robert" ; phone: "+61 5678912345" ; 
        email: "robert@xyz.com"
    }
    ListElement {
        name: "Kayla" ; phone: "+91 9876554321" ; 
        email: "kayla@xyz.com"
    }
}
```

我们现在已经创建了模型。接下来，我们必须使用委托来显示它。因此，让我们修改之前创建的委托组件，使用三个 `Text` 元素。根据您的需求，您可以创建具有图标、文本或自定义类型的复杂委托类型。您可以添加一个突出显示的项目，并根据焦点更新背景。您需要为视图提供一个委托，以在列表中直观地表示一个项目：

```cpp
Component {
    id: contactDelegate
    Row {
        id: contact
        spacing: 20
        Text { text: " Name: " + name; }
        Text { text: " Phone no: " + phone }
        Text { text: " Email ID: " + email }
    }
}
ListView {
    anchors.fill: parent
    model: contactListModel
    delegate: contactDelegate
}
```

在前面的示例中，我们使用了 `ListElement` 与 `ListModel`。视图根据委托定义的模板显示每个项目。可以通过 `index` 属性或项目的属性访问模型中的项目。

您可以在以下链接中了解有关不同类型的模型以及如何操作模型数据的更多信息：

[`doc.qt.io/qt-6/qtquick-modelviewsdata-modelview.html`](https://doc.qt.io/qt-6/qtquick-modelviewsdata-modelview.html)

在本节中，您了解了 QML 中的 M/V。您可以尝试使用自定义模型和委托，并创建个性化的视图。看一看您手机上的电话簿或最近的通话列表，并尝试实现它。在下一节中，您将学习如何将 QML 前端与 C++ 模型集成。

# 使用 C++ 模型与 QML

到目前为止，我们已经讨论了如何在 Qt Widgets 和 QML 中使用模型和视图。但在大多数现代应用程序中，您将需要在 C++中编写模型，并在 QML 中编写前端。Qt 允许我们在 C++中定义模型，然后在 QML 中访问它们。这对于将现有的 C++数据模型或其他复杂数据集暴露给 QML 非常方便。对于复杂的逻辑操作，原生 C++始终是正确的选择。它可以优于使用 JavaScript 编写的 QML 中的逻辑。

有许多原因您应该创建一个 C++模型。C++是类型安全的，并且编译为对象代码。它增加了应用程序的稳定性并减少了错误的数量。它灵活，并且可以提供比 QML 类型更多的功能。您可以与现有代码或使用 C++编写的第三方库集成。

您可以使用以下类定义 C++模型：

+   `QStringList`

+   `QVariantList`

+   `QObjectList`

+   `QAbstractItemModel`

前三个类有助于暴露更简单的数据集。`QAbstractItemModel`提供了一个更灵活的解决方案来创建复杂的模型。`QStringList`包含`QString`实例的列表，并通过`modelData`角色提供列表的内容。类似地，`QVariantList`包含`QVariant`类型的列表，并通过`modelData`角色提供列表的内容。如果`QVariantList`发生变化，则必须重置模型。`QObjectList`嵌入了一个`QObject*`列表，该列表提供了列表中对象的属性作为角色。`QObject*`可以作为`modelData`属性访问。为了方便起见，可以直接在委托的上下文中访问对象的属性。

Qt 还提供了处理 SQL 数据模型的 C++类，例如`QSqlQueryModel`、`QSqlTableModel`和`QSqlRelationalTableModel`。`QSqlQueryModel`提供了基于 SQL 查询的只读模型。这些类减少了运行 SQL 查询以进行基本的 SQL 操作（如插入、创建或更新）的需要。这些类是从`QAbstractTableModel`派生的，使得在 View 类中轻松呈现来自数据库的数据变得容易。

您可以通过访问以下链接了解有关不同类型的 C++模型的更多信息：

[`doc.qt.io/qt-6/qtquick-modelviewsdata-cppmodels.html`](https://doc.qt.io/qt-6/qtquick-modelviewsdata-cppmodels.html)

在本节中，我们讨论了 C++模型以及为什么要使用它们。现在，您可以从 C++后端获取数据，并在 QML 中开发的 UI 中呈现它。在下一节中，我们将使用上述概念创建一个简单的 Qt Quick 应用程序，并解释如何在 QML 中使用它们。

# 使用 Qt Quick 创建一个简单的 M/V 应用程序

在前面的部分中，我们讨论了 Qt 的模型-视图-委托框架。您学会了如何创建自定义模型和委托，以及如何使用 C++模型。但您一定想知道如何与我们的 QML 前端集成。在本节中，我们将创建一个 C++模型并将其暴露给 QML 引擎。我们还将讨论如何将自定义模型注册为 QML 类型。

让我们创建一个应用程序，从 C++代码中获取模型并在基于 Qt Quick 的应用程序中显示它：

```cpp
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QStringListModel>
int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QQmlApplicationEngine engine;
    QStringList stringList;
    stringList << "Item 1" << "Item 2" << "Item 3" 
               <<"Item 4";
    engine.rootContext()->setContextProperty("myModel", 
        QVariant::fromValue(stringList));
    const QUrl url(QStringLiteral("qrc:/main.qml"));
    engine.load(url);
    return app.exec();
}
```

在上面的代码片段中，我们创建了一个基于`QStringList`的简单模型。字符串列表包含四个不同的字符串。我们使用`setContextProperty()`将模型暴露给 QML 引擎。现在，让我们在 QML 文件中使用该模型：

```cpp
import QtQuick
import QtQuick.Window
Window {
    width: 640
    height: 480
    visible: true
    title: qsTr("QML CPP M/V Demo")
    ListView {
        id: listview
        width: 120
        height: 200
        model: myModel
        delegate: Text { text: modelData }
    }
}
```

上面的示例使用`QQmlContext::setContextProperty()`在 QML 组件中直接设置模型值。另一种方法是将 C++模型类注册为 QML 类型，如下所示：

`qmlRegisterType<MyModel>("MyModel",1,0,"MyModel");`

上述行将允许直接在 QML 文件中将模型类创建为 QML 类型。第一个字段是 C++类名，然后是所需的包名称，然后是版本号，最后一个参数是 QML 中的类型名称。您可以使用以下行将其导入到 QML 文件中：

`Import MyModel 1.0`

让我们在我们的 QML 文件中创建一个`MyModel`的实例，如下所示：

```cpp
MyModel {
    id: myModel
}
ListView {
    width: 120
    height: 200
    model: myModel
    delegate: Text { text: modelData }
} 
```

您还可以使用`setInitialProperties()`在`QQuickView`中使用模型，如下面的代码所示：

```cpp
QQuickView view;
view.setResizeMode(QQuickView::SizeRootObjectToView);
view.setInitialProperties({
                  {"myModel",QVariant::fromValue(myModel)}});
view.setSource(QUrl("qrc:/main.qml"));
view.show();
```

在前面的代码片段中，我们使用了`QQuickView`来创建一个 UI，并将自定义的 C++模型传递给了 QML 环境。

在本节中，我们学习了如何将简单的 C++模型与 QML 集成。您可以添加信号和属性来扩展自定义类的功能。接下来，让我们总结一下本章的学习成果。

# 总结

在本章中，我们深入了解了 Qt 中的 Model-View-Delegate 模式的核心概念。我们解释了它与传统 MVC 模式的不同之处。我们讨论了在 Qt 中使用 M/V 的不同方式以及 Qt 中提供的便利类。我们学习了如何在 Qt Widgets 和 Qt Quick 中应用 M/V 概念。我们讨论了如何将 C++模型集成到 QML 视图中。我们还创建了一些示例，并在我们的 Qt 应用程序中实现了这些概念。您现在可以创建自己的模型、委托和视图。我希望您已经理解了这个框架的重要性，以及使用它满足您需求的充分理由。

在*第八章*，*图形和动画*中，我们将学习关于图形框架以及如何将动画添加到您的 Qt Quick 项目。
