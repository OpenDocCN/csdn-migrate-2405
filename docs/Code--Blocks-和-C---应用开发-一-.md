# Code::Blocks 和 C++ 应用开发（一）

> 原文：[`zh.annas-archive.org/md5/D136533EB1CB1D754CE9EE199A478703`](https://zh.annas-archive.org/md5/D136533EB1CB1D754CE9EE199A478703)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

《使用 Code::Blocks 进行 C++开发》是一本简洁实用的应用程序开发指南，使用 C++和 Code::Blocks。本书为您提供了多个示例和逐步指南，以便开始，然后逐渐发展到使用 C++进行复杂的应用程序开发。它还巧妙地使用教程来详细说明 Code::Blocks 的特性。本书涵盖了 Code::Blocks 版本 12.11。然而，教程将适用于更新的版本。

# 本书涵盖内容

第一章，“使用 Code::Blocks 入门”，将帮助我们在 Windows 和 Linux 上安装 Code::Blocks。

第二章，“使用 Code::Blocks 进行应用程序开发”，将帮助我们开发一个简单的应用程序，以项目的形式开发应用程序，使用项目的外部库，以及工作区的概念。

第三章，“使用 Code::Blocks 进行应用程序调试”，解释了 Code::Blocks 提供的与调试器相关的功能，以及调试单个和多个应用程序。

第四章，“使用 Code::Blocks 进行 Windows 应用开发”，描述了如何使用 Code::Blocks 为 Windows 操作系统开发应用程序。我们还将学习如何使用 wxWidgets 以及如何将其用于开发跨平台应用程序。

第五章，“编程作业”，解释了如何使用 Code::Blocks 从头开始开发应用程序。我们将查看一个已完成的应用程序，对其进行分析，然后使用 Code::Blocks 进行开发。

附录讨论了 Code::Blocks 的一些高级功能。我们还将在本章中了解有关文档生成、导出源文件等内容。

# 你需要什么

学习和遵循本书示例所需的软件如下：

+   Code::Blocks 版本 12.11。

+   wxWidgets 版本 2.9.5

+   conio2 库

本书提供了 wxWidgets 库和 conio2 库的编译副本，以方便您使用。

# 这本书适合谁

本书的目标读者是 C/C++开发人员。需要具备 C/C++编译器的先验知识。本书适合想要学习 Code::Blocks 和使用它进行 C++应用开发的开发人员。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下：“我们可以通过使用`include`指令包含其他上下文。”

代码块设置如下：

```cpp
#include <iostream>

int main() {
  std::cout << "Hello World!" << std::endl;
  return 0;
}
```

任何命令行输入或输出都以以下方式编写：

```cpp
g++ -o app4.exe –g –O2 main.cpp

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，如菜单或对话框中的单词，会以这样的方式出现在文本中：“点击**下一步**按钮会将您移至下一个屏幕”。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：开始使用 Code::Blocks

在编写本书时，Code::Blocks—12.11 是最新的稳定版本。此版本配备了 Windows 的 GCC 4.7.1 编译器。我们将在本书中使用此版本进行 C++开发。在本章中，我们将下载 Code::Blocks，安装并了解更多信息。

# 为什么选择 Code::Blocks？

在我们继续了解**Code::Blocks**之前，让我们了解为什么我们应该使用 Code::Blocks 而不是其他 IDE。

+   这是一个跨平台集成开发环境（IDE）。它支持 Windows、Linux 和 Mac 操作系统。

+   它完全支持所有支持的平台上的 GCC 编译器和 GNU 调试器。

+   它支持多种其他编译器在多个平台上的各种程度。

+   它是可编写脚本和可扩展的。它带有几个插件，扩展了其核心功能。

+   它对资源要求较低，不需要强大的计算机来运行。

+   最后，它是免费和开源的。

# 在 Windows 上安装 Code::Blocks

本书的主要重点将放在 Windows 平台上。但是，我们将尽可能涉及其他平台。官方 Code::Blocks 二进制文件可从[www.codeblocks.org](http://www.codeblocks.org)下载。执行以下步骤以成功安装 Code::Blocks：

1.  在 Windows 平台上安装，从[`www.codeblocks.org/downloads/26`](http://www.codeblocks.org/downloads/26)下载`codeblocks-12.11mingw-setup.exe`文件，或从 sourceforge 镜像[`sourceforge.net/projects/codeblocks/files/Binaries/12.11/Windows/codeblocks-12.11mingw-setup.exe/download`](http://sourceforge.net/projects/codeblocks/files/Binaries/12.11/Windows/codeblocks-12.11mingw-setup.exe/download)下载，并将其保存在一个文件夹中。

1.  双击此文件并运行。您将看到以下屏幕：![在 Windows 上安装 Code::Blocks](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_01.jpg)

1.  如下截图所示，单击“**下一步**”按钮继续。将呈现许可证文本。Code::Blocks 应用程序根据 GNU GPLv3 许可证获得许可，而 Code::Blocks SDK 根据 GNU LGPLv3 获得许可。您可以在此网址了解有关这些许可证的更多信息-[`www.gnu.org/licenses/licenses.html`](https://www.gnu.org/licenses/licenses.html)。![在 Windows 上安装 Code::Blocks](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_02.jpg)

1.  单击**我同意**接受许可协议。在下面的截图中将呈现组件选择页面：![在 Windows 上安装 Code::Blocks](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_03.jpg)

1.  您可以选择以下任何选项：

+   **默认安装**：这是默认安装选项。这将安装 Code::Block 的核心组件和核心插件。

+   **Contrib 插件**：插件是扩展 Code::Block 功能的小程序。选择此选项以安装由其他几个开发人员贡献的插件。

+   **C::B 共享配置**：此实用程序可以复制所有/部分配置文件。

+   **MinGW 编译器套件**：此选项将为 Windows 安装 GCC 4.7.1。

1.  选择**完整安装**，然后单击**下一步**按钮继续。如下截图所示，安装程序现在将提示选择安装目录：![在 Windows 上安装 Code::Blocks](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_04.jpg)

1.  您可以将其安装到默认安装目录。否则选择**目标文件夹**，然后单击**安装**按钮。安装程序现在将继续安装。![在 Windows 上安装 Code::Blocks](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_05.jpg)

1.  如下截图所示，Code::Blocks 现在将提示我们在安装完成后运行它：![在 Windows 上安装 Code::Blocks](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_06.jpg)

1.  在这里单击**否**按钮，然后单击**下一步**按钮。安装现在将完成：![在 Windows 上安装 Code::Blocks](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_07.jpg)

1.  单击**完成**按钮以完成安装。桌面上将创建一个快捷方式。

这完成了我们在 Windows 上的 Code::Blocks 安装。

# 在 Linux 上安装 Code::Blocks

Code::Blocks 可在众多 Linux 发行版上运行。在本节中，我们将学习在 CentOS Linux 上安装 Code::Blocks。CentOS 是一个基于 Red Hat Enterprise Linux 的 Linux 发行版，是一个免费提供的企业级 Linux 发行版。执行以下步骤在 Linux 操作系统上安装 Code::Blocks：

1.  导航到 **设置** | **管理** | **添加/删除软件** 菜单选项。在搜索框中输入 `wxGTK` 并按 *Enter* 键。截至目前，wxGTK-2.8.12 是最新的稳定版本的 wxWidgets。选择它，然后点击 **应用** 按钮来通过软件包管理器安装 `wxGTK` 软件包，如下截图所示。![在 Linux 上安装 Code::Blocks](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_14.jpg)

1.  从此 URL（[`www.codeblocks.org/downloads/26`](http://www.codeblocks.org/downloads/26)）下载 **CentOS 6** 的软件包。

通过在 shell 中输入以下命令来解压 `.tar.bz2` 文件：

```cpp
tar xvjf codeblocks-12.11-1.el6.i686.tar.bz2

```

1.  右键单击 `codeblocks-12.11-1.el6.i686.rpm` 文件，如下截图所示，选择 **使用软件包安装器打开** 选项。![在 Linux 上安装 Code::Blocks](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_15.jpg)

1.  将显示以下窗口。点击 **安装** 按钮开始安装，如下截图所示：![在 Linux 上安装 Code::Blocks](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_16.jpg)

1.  如果您是从用户帐户安装的，可能会要求输入 root 密码。输入 root 密码，然后点击 **验证** 按钮。Code::Blocks 现在将被安装。

1.  重复步骤 4 到 6 来安装其他 rpm 文件。

我们现在已经学会在 Windows 和 Linux 平台上安装 Code::Blocks。我们现在准备进行 C++ 开发。在这之前，我们将学习 Code::Blocks 的用户界面。

# 首次运行

在 Windows 平台上，导航到 **开始** | **所有程序** | **CodeBlocks** | **CodeBlocks** 菜单选项来启动 Code::Blocks。或者，您也可以双击桌面上显示的快捷方式来启动 Code::Blocks，如下截图所示：

![首次运行](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_08.jpg)

在 Linux 上，导航到 **应用程序** | **编程** | **Code::Blocks IDE** 菜单选项来运行 Code::Blocks。请注意，在本书的后续章节中，我们将主要限制讨论到 Windows 平台。然而，Code::Blocks 的使用和 C++ 开发（除了特定于平台的领域）在两个平台上保持一致。

Code::Blocks 现在会要求用户选择默认编译器。Code::Blocks 支持多个编译器，因此能够检测到其他编译器的存在。下面的截图显示了 Code::Blocks 已经检测到 GNU GCC 编译器（它是与安装程序捆绑在一起并已安装的）。点击它选择，然后点击 **设置为默认按钮**，如下截图所示：

![首次运行](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_09.jpg)

不要担心前面截图中标记为红色的项目。红色线条表示 Code::Blocks 无法检测到特定编译器的存在。

最后，点击 **确定** 按钮继续加载 Code::Blocks。加载完成后，Code::Blocks 窗口将显示出来。

下面的截图显示了 Code::Blocks 的主窗口。标注部分突出显示了不同的用户界面（UI）组件：

![首次运行](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_10.jpg)

现在，让我们更多地了解不同的用户界面组件：

+   **菜单栏和工具栏**：所有 Code::Blocks 命令都可以通过菜单栏访问。另一方面，工具栏提供了对常用命令的快速访问。

+   **起始页和代码编辑器**：启动页是 Code::Blocks 启动时的默认页面。其中包含一些有用的链接和最近的项目和文件历史记录。代码编辑器是用于编辑 C++（和其他语言）源文件的文本容器。这些编辑器提供语法高亮功能，可以用不同颜色突出显示关键字。

+   **管理窗格**：此窗口显示所有打开的文件（包括源文件、项目文件和工作空间文件）。其他插件也使用此窗格提供额外功能。在前面的屏幕截图中，**文件管理器**插件提供类似 Windows 资源管理器的功能，**代码完成**插件提供当前打开源文件的详细信息。

+   **日志窗口**：显示来自不同工具（例如编译器、调试器、文档解析器等）的日志消息。其他插件也使用此组件。

+   **状态栏**：此组件显示 Code::Blocks 的各种状态信息，例如文件路径、文件编码、行号等。

# 重要工具栏简介

工具栏提供了对 Code::Blocks 不同功能的更便捷访问。在几个工具栏中，以下几个最重要。

## 主工具栏

主工具栏包含核心组件命令。从左到右依次为新建文件、打开文件、保存、全部保存、撤销、重做、剪切、复制、粘贴、查找和替换按钮。

![主工具栏](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_11.jpg)

## 编译器工具栏

编译器工具栏包含常用的与编译器相关的命令。从左到右依次为构建、运行、构建并运行、重新构建、停止构建、构建目标按钮。C++源代码的编译也称为构建，本书将沿用此术语。

![编译器工具栏](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_12.jpg)

## 调试器工具栏

调试器工具栏包含常用的与调试器相关的命令。从左到右依次为调试/继续、运行到光标、下一行、步入、步出、下一条指令、步入指令、中断调试器、停止调试器、调试窗口和各种信息按钮。

![调试器工具栏](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_01_13.jpg)

# 摘要

在本章中，我们学习了如何下载和安装 Code::Blocks。我们还了解了不同的界面元素。在下一章中，我们将开始使用 Code::Blocks 进行 C++编码。


# 第二章：使用 Code::Blocks 进行应用程序开发

在本章中，我们将学习使用 Code::Blocks 进行 C++应用程序开发。我们将从一个简单的 Hello World 应用程序开始。随后将介绍项目和工作空间的概念。

# 使用 Code::Blocks 创建你的第一个应用程序

让我们编写一个简单的 Hello World 应用程序，它基本上会在控制台上打印出“Hello World”。启动 Code::Blocks 并如下屏幕截图所示，单击主工具栏中的新按钮，然后单击**文件**菜单选项。以下屏幕截图表示相同的内容：

![使用 Code::Blocks 创建你的第一个应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_01.jpg)

在下一个窗口中单击**C/C++源文件**选项，然后单击**Go**按钮。将会出现一个向导。在向导的第一页上单击**下一步**按钮。在下一个窗口中选择**C++**选项，然后单击**下一步**按钮。在下一个窗口中选择文件路径和名称，然后单击**完成**按钮以完成向导。

然后在编辑器中输入以下代码：

```cpp
#include <iostream>

int main() {
  std::cout << "Hello World!" << std::endl;
  return 0;
}
```

如果文件末尾没有空行，Code::Blocks 会自动添加一个空行，这是 Code::Blocks 的特性。GCC 期望源代码末尾有一个空行，如果缺少空行，它会发出警告。因此，你可能会注意到 Code::Blocks 会自动添加一个空行。

在编辑器窗口中输入代码后，Code::Blocks 将看起来类似于以下屏幕截图。

![使用 Code::Blocks 创建你的第一个应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_02.jpg)

现在单击主工具栏中的保存按钮以保存此文件（转到**文件** | **保存**）。或者可以使用*Ctrl* + *S*组合键来保存文件。我们可以看到 Code::Blocks 已经对代码应用了语法高亮，并且使代码更易读。

现在单击编译器工具栏中的构建按钮，或者按下*Ctrl* + *F9*组合键进行编译。如果一切顺利，Code::Blocks 将看起来类似于之前的屏幕截图。现在单击编译器工具栏中的运行按钮。Code::Blocks 现在将运行程序。如下屏幕截图所示，我们的第一个程序已经成功运行：

![使用 Code::Blocks 创建你的第一个应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_03.jpg)

前一个屏幕截图显示程序执行已经完成，并且正在等待用户输入以关闭窗口。这是 Code::Blocks 的一个特性，它在执行完成后停止，以允许用户研究程序输出。

我们的第一个任务已经成功。然而，这种方法有几个缺点。

+   在编译单个文件时，Code::Blocks 会应用全局编译器/链接器标志。

+   Code::Blocks 纯粹作为文本编辑器（想象记事本）使用，大多数功能无法用于编译单个文件。

此外，管理由单独文件组成的大型项目是繁琐的。因此，**项目**的概念已经发展。在下一节中，我们将更多地了解 Code::Blocks 中的项目。

# Code::Blocks 中的项目

项目是 Code::Blocks 中的一个重要概念。项目可以被描述为一组源文件和构建目标。

![Code::Blocks 中的项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_27.jpg)

构建目标可以被定义为每个源文件的标签或标记，其中包含单独的构建（编译器、链接器和资源编译器）选项。每个构建目标包含一组构建选项，在项目编译时，Code::Blocks 会选择当前活动的目标。然后使用该构建目标的构建选项编译该目标的所有文件。

![Code::Blocks 中的项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_28.jpg)

一个项目需要至少一个目标和一个源文件来进行编译。源文件可以是所有目标的一部分，也可以是没有目标的一部分。构建目标可以依赖于其他目标，这有助于维护不同源文件之间的关系。我们将在下一节中更详细地解释构建目标的重要性。

但在此之前，让我们创建一个项目并开发一个应用程序。执行以下步骤：

1.  单击主工具栏上的新按钮，然后单击**项目**菜单选项。将显示向导，如下截图所示。现在选择**控制台应用程序**，然后单击**Go**按钮：![Code::Blocks 中的项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_04.jpg)

1.  在向导的第一页上单击**下一步**按钮。然后选择**C++**，并单击**下一步**按钮，如下截图所示：![Code::Blocks 中的项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_05.jpg)

1.  如下截图所示，输入**项目标题**（应用程序名称）为`App1`，并选择一个文件夹来创建`App1`项目。现在，单击**下一步**按钮继续。![Code::Blocks 中的项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_06.jpg)

1.  单击**完成**按钮，如下截图所示，**控制台应用程序**窗口将生成默认代码：![Code::Blocks 中的项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_07.jpg)

下面的截图显示了已填充新创建项目文件的**管理**窗口。双击树上的`main.cpp`项目以打开 Code::Blocks 编辑器。

![Code::Blocks 中的项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_08.jpg)

让我们用以下代码替换默认代码：

```cpp
#include <iostream>

class HelloWorld {
public:
  HelloWorld() {}
  ~HelloWorld() {}

  void Print() {
    std::cout << "Hello World!" << std::endl;
  }
};

int main()
{
  HelloWorld hello;
  hello.Print();
  return 0;
}
```

我们用 C++类替换了之前的`HelloWorld`代码，以实现打印“Hello World!”文本的相同目标。

C++类是特定的数据类型，可以定义为一组数据结构和操作这些数据结构的成员函数的集合。所有成员函数和基类默认为`private`。类可以包含重载运算符，允许与特定类相关的自定义操作。

类也可以使用`struct`关键字定义。但是，如果使用`struct`关键字定义类，则所有成员，即函数和基类，默认为`public`。

让我们分析我们的代码。我们定义了一个名为`HelloWorld`的类。我们还定义了一个`构造函数`函数`HelloWorld()`和一个`析构函数`函数`~HelloWorld()`。我们有一个名为`Print()`的公共可访问函数，用于打印出`"Hello World!"`文本。在`main()`函数中，我们创建了一个名为`hello`的`HelloWorld`类的对象，然后我们用它来调用`Print()`函数。

按下*F9*键构建并运行此项目。一个控制台窗口将弹出显示“Hello World!”文本。

# 多文件项目

在本节中，我们将学习由多个文件组成的 C++应用程序开发。我们将开发一个名为`Vector`的类，它实现了一个动态数组。这个类类似于**标准模板库**（**STL**）提供的`std::vector`类，并且与 STL 类相比具有非常有限的功能集。

创建一个新项目并命名为`App2`。转到**文件** | **新建** | **文件…**菜单选项，然后选择**C/C++头文件**选项，并按照向导将新文件添加到`App2`项目中。在`App2`下的新文件中添加以下代码，并将其命名为`vector.h`文件：

```cpp
#ifndef __VECTOR_H__
#define __VECTOR_H__

#ifndef DATA_TYPE
#define DATA_TYPE double
#endif

class Vector {
public:
    Vector(size_t size = 2);
    virtual ~Vector();

    size_t GetCount() const;

    bool Set(size_t id, DATA_TYPE data);
    DATA_TYPE operator[] (size_t id);

private:
    DATA_TYPE* m_data;
    size_t     m_size;
};

#endif //__VECTOR_H__
```

头文件`vector.h`声明了`Vector`类结构。我们有一个预处理器宏`DATA_TYPE`，定义了这个类所持有的数据类型。我们有一个构造函数（带有默认参数）和一个析构函数。这些函数将分配和释放一个指向元素数组的指针`m_data`。一个成员变量`m_size`将用于保存数组的大小，这将帮助我们进行边界检查。

有几个成员函数操作成员变量。`GetCount()`函数返回数组大小，`Set()`函数为数组中的元素赋值。运算符`[]`已被重载以访问数组数据。

`Vector`类已在`vector.cpp`文件中实现。创建并将此新文件添加到`App2`项目中，然后将以下代码复制到其中：

```cpp
#include <cstring>
#include "vector.h"

Vector::Vector(size_t size)
    : m_size(size)
{
    m_data = new DATA_TYPE[m_size];
    ::memset(m_data, 0, m_size * sizeof(DATA_TYPE));
}

Vector::~Vector() {
    if (m_data) {
        delete [] m_data;
        m_data = 0;
    }
}

size_t Vector::GetCount() const {
    return m_size;
}

bool Vector::Set(size_t id, DATA_TYPE data) {
    if (id < m_size) {
        m_data[id] = data;
        return true;
    }
    return false;
}

DATA_TYPE Vector::operator[](size_t id) {
    if (id < m_size) {
        return *(m_data + id);
    }

    return 0;
}
```

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，直接将文件发送到您的邮箱。

`m_size(size)`这一行定义了一个初始化列表，其中成员变量按照它们被声明的顺序进行初始化。我们使用 new 运算符来分配一个由用户给定大小的数组。`memset()`函数用零初始化该数组。在析构函数中，内部数组被检查是否为空指针，然后用`delete []`关键字进行解除分配，并分配一个空指针。

### 注意

空指针具有一个值（通常为`0`），用于指示它不指向任何有效对象。对空指针的任何操作都将导致分段错误或访问违例。在这种情况下，应用程序将立即崩溃。C++ 11 定义了一个单独的`nullptr`常量来定义空指针。

有两个成员函数`Set()`和`GetCount()`，它们操作内部数组。

最后，用以下代码替换`main.cpp`文件中的代码。它创建了一个`Vector`类的对象，并随后使用它：

```cpp
#include <iostream>
#include "vector.h"

int main() {
    Vector vec(4);
    vec.Set(0, 10); // Set first item = 10
    vec.Set(2, 55); // Set first item = 55
    std::cout << "Number of elements = " << vec.GetCount() << std::endl;
    std::cout << "vec[1] = " << vec[1] << std::endl;
    std::cout << "vec[2] = " << vec[2] << std::endl;
    return 0;
}
```

现在，**管理**窗口将类似于以下截图：

![具有多个文件的项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_09.jpg)

我们将定义一个预处理器定义，以确保**Vector**类被编译为整数数组。导航到**项目** | **构建选项...**菜单选项，将呈现**项目构建选项**窗口：

![具有多个文件的项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_10.jpg)

由于我们打算在整个项目中应用这些设置，因此在该窗口中单击项目树的根。现在，单击**编译器设置** | **#defines**选项卡，并根据前面的截图添加该行。然后，单击**确定**按钮关闭该对话框。现在编译并运行此项目。这将产生以下截图中的结果：

![具有多个文件的项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_11.jpg)

在我们的代码中，我们有一个预处理宏`DATA_TYPE`，它定义了这个类所持有的数据类型。如果我们打算将其用作`double`数组，我们必须重新编译此应用程序。

请注意，预处理宏通过简单的文本替换工作，替换过程中不执行任何类型检查。如果使用不正确，这可能会在程序中引入其他错误。

在本节中，我们学习了使用多个文件进行应用程序开发，调整编译器选项。

# 调试与发布目标

我们注意到在`App1`和`App2`中，每个项目中有两个构建目标，即**debug**和**release**。在本节中，我们将更多地了解它。

Code::Blocks 在项目创建时定义了两个默认构建目标——调试和发布。

正如其名称所示，调试目标适用于应用程序调试。适当的编译器选项被添加以在编译后生成调试符号。它还禁用了所有程序优化。

我们可以在以下截图中找到（导航到**项目** | **构建选项...**菜单选项）**Debug**目标具有一个编译器选项**生成调试符号**。这指示编译器生成调试符号，从而允许应用程序调试：

![调试与发布目标](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_13.jpg)

一个**发布**目标禁用了调试符号的生成。它还定义了适当的编译器选项来优化程序。因此，这适用于用于生产的代码。以下截图显示了发布目标中的典型编译器标志。

![调试与发布目标](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_14.jpg)

这两个目标非常重要，因为使用启用了编译器优化标志的程序进行调试是困难的。强烈建议在调试目标中编译程序时禁用所有优化。

为了理解这个问题，我们将使用以下代码片段，然后编译和调试它。请注意，我们将使用命令行工具来避免 Code::Blocks UI 对任何错误消息的抽象：

```cpp
#include <iostream>

int add (int a, int b) {
    return (a + b);
}

int main() {
    std::cout << "2 + 3 = " << add(2, 3) << std::endl;
    return 0;
}
```

现在以调试模式编译它：

```cpp
g++ -o app4.exe –g main.cpp

```

我们将使用 GNU 调试器`gdb`来调试和理解执行流程。启动`gdb`并按照以下步骤操作：

```cpp
gdb --quiet app4.exe
Reading symbols from Z:\app4.exe...done.
(gdb) b main.cpp:4
Breakpoint 1 at 0x401945: file main.cpp, line 4.
(gdb) b main.cpp:9
Breakpoint 2 at 0x4019ae: file main.cpp, line 9.
(gdb) r
Starting program: Z:\app4.exe
[New Thread 6036.0x6ac]

Breakpoint 1, add (a=2, b=3) at main.cpp:4
4      return (a + b);
(gdb) c
Continuing.
2 + 3 = 5

Breakpoint 2, _fu0___ZSt4cout () at main.cpp:9
9      return 0;
(gdb) c
Continuing.
[Inferior 1 (process 6036) exited normally]

```

我们要求`gdb`将`app4.exe`加载到内存中。然后我们要求`gdb`设置两个**断点**，通过发出命令`b`并指定行号。我们要求`gdb`运行程序。根据断点的指示，执行在每个断点处暂停。随后，程序在没有任何错误的情况下完成。

让我们看看在打开优化时会发生什么。我们将编译它为：

```cpp
g++ -o app4.exe –g –O2 main.cpp

```

现在再次按照之前的步骤调试此应用程序：

```cpp
gdb --quiet app4.exe
Reading symbols from Z:\app4.exe...done.
(gdb) b main.cpp:4
Breakpoint 1 at 0x401574: file main.cpp, line 4.
(gdb) b main.cpp:9
Breakpoint 2 at 0x402883: main.cpp:9\. (2 locations)
(gdb) r
Starting program: Z:\app4.exe
[New Thread 6084.0x1270]

Breakpoint 2, _GLOBAL__sub_I__Z3addii () at main.cpp:10
10   }
(gdb) c
Continuing.
2 + 3 = 5

Breakpoint 2, _fu0___ZSt4cout () at main.cpp:10
10   }
(gdb) c
Continuing.
[Inferior 1 (process 6084) exited normally]

```

从前面的输出可以看出，编译器优化了我们的源代码，并对代码进行了许多更改。函数`add()`似乎已经被内联扩展了。结果是，在执行过程中，`main.cpp`文件的`return (a + b)`行上的断点永远不会被触发。

这是优化对调试过程的一个副作用。Code::Blocks 创建了两个默认目标，以避免类似情况。强烈建议在项目开发中遵循这一点。

# 带有外部库的项目

在本节中，我们将开发一个使用外部库的应用程序。外部库几乎在任何语言编写的项目中都会被使用。它们允许代码重用，从而加快项目周期。我们将学习如何在 Code::Blocks 项目中配置外部库。

我们已经将`Hello World!`文本打印到控制台。如何在彩色打印文本？我们可以使用一个名为`conio2`的库（[`conio.sourceforge.net/`](http://conio.sourceforge.net/)）来打印彩色文本并进行其他文本操作。书中提供了`conio2`库的编译副本。考虑以下示例代码：

```cpp
#include <cstring>
#include "conio2.h"

int main() {
    int screenWidth = 0;
    const char* msg = "Hello World!\n\n";
    struct text_info textInfo;
    inittextinfo();
    gettextinfo(&textInfo);
    screenWidth  = textInfo.screenwidth;
    textcolor(YELLOW);
    textbackground(RED);
    cputsxy( (screenWidth - strlen(msg))/2 , textInfo.cury, const_cast<char*>(msg) );
    textcolor(WHITE); // Restore original colours
    textbackground(BLACK);
    return 0;
}
```

在这个例子中，我们在第二行包含了`conio2.h`文件。这将向我们的应用程序公开`conio2`库中的预定义函数。我们在`main()`函数内定义了几个变量，即`screenWidth`、`msg`和`textInfo`。然后，我们使用`gettextinfo()`函数检索了当前控制台文本设置。

在下一行中，我们将当前屏幕宽度保存到`screenWidth`变量中。随后，我们分配了`YELLOW`前景色和`RED`背景色。我们使用`cputsxy()`函数打印所需的文本。然后我们在随后的两行中恢复了文本颜色。

为了设置外部库，导航到**项目** | **构建选项...**菜单选项，并点击**搜索目录**选项卡，如下面的屏幕截图所示：

![带有外部库的项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_23.jpg)

将`conio2\include`路径（相对于项目路径）添加到上一个屏幕截图中显示的位置。如果`conio2`库安装在其他位置，也可以使用完整路径。这将指示编译器在代码中引用的任何头文件中也搜索此目录。

接下来，点击**链接器**选项卡，如下面的屏幕截图所示，添加`conio2\lib`相对路径，如下面的屏幕截图所示。这将指示链接器在此路径中搜索静态库。

![带有外部库的项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_24.jpg)

点击**链接器设置**选项卡，并按照下面的屏幕截图添加`libconio.a`：

![带有外部库的项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_25.jpg)

完成这一步后，我们的应用程序已准备好进行编译。现在编译并运行它。我们将看到以下输出：

![带有外部库的项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_26.jpg)

我们的应用程序现在正在使用外部 C/C++库。我们可以以类似的方式使用其他外部库来开发我们的应用程序。

# 工作区

在 Code::Blocks 中，工作区是项目的集合。工作区充当项目的容器，并且还维护项目之间的依赖关系。因此，如果项目 2 依赖于项目 1，那么在编译项目 1 之前将编译项目 2。

考虑以下片段。通过导航到**文件** | **新建** | **项目...**并选择**静态库**向导来创建一个名为`libcalc`的静态库项目。

然后用以下代码替换项目的`main.c`文件的代码：

```cpp
int mult(int a, int b)
{
    return (a * b);
}
```

接下来创建一个名为`App6`的控制台项目，然后用以下代码替换其`main.cpp`文件：

```cpp
#include <iostream>

extern "C" int mult(int a, int b);

int main() {
    std::cout << "2 * 3 = " << mult(2, 3);
    return 0;
}
```

**管理**窗口现在显示了一个工作区中的两个项目。工作区在以下截图中已重命名为`App6`：

![工作区](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_21.jpg)

通过导航到**文件** | **另存工作区为...**菜单选项来保存此工作区。右键单击项目树中的**App6**项目，然后单击屏幕截图菜单选项。接下来单击**项目的依赖项**按钮。将呈现以下窗口：

![工作区](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_02_22.jpg)

单击**关闭**按钮关闭此窗口，然后单击**确定**按钮关闭**项目/目标选项**窗口。现在`App6`依赖于`libcalc`项目。

现在导航到**项目** | **构建选项...**菜单选项，并在**链接器设置**选项卡的**链接库**中添加`..\libcalc\libcalc.a`。

要编译这两个项目，请导航到**构建** | **构建工作区**菜单选项。Code::Blocks 现在将构建`App6`，并处理其依赖项目。

现在很明显，我们可以使用工作区来管理大型项目中的子项目。

# 摘要

在本章中，我们学会了在 Code::Blocks 中创建项目。我们了解了构建目标的重要性。我们还学会了在我们的项目中使用外部库。最后，我们学会了创建和使用工作区。

通过这个，我们结束了对 Code::Blocks 中项目的介绍。我们将在下一章讨论调试。


# 第三章：Code::Blocks 应用程序调试

调试是应用程序开发中的一个重要步骤。它也是 IDE 的一个重要部分，Code::Blocks 也不例外。它提供了一系列功能，使应用程序调试变得更加容易。

在本章中，我们将学习使用 Code::Blocks 进行应用程序调试。我们将从一个简单的应用程序开始，展示 Code::Blocks 的各种功能。

# Code::Blocks 中的调试简介

Code::Blocks 支持两种调试器：

+   **GNU 调试器**，通常称为 **GDB**

+   微软 **控制台调试器** 或 **CDB**

Code::Blocks 安装程序将 GDB 与 GCC 编译器捆绑在一起。CDB 可以与 Windows **软件开发工具包**（**SDK**）的安装一起下载和安装。

### 注意

Windows SDK 是微软为 Windows 平台提供的一套工具集。它包括编译器、头文件、库、调试器、示例、文档和开发 .NET Framework 应用程序所需的工具。

CDB 可以从以下链接下载和安装：

[`msdn.microsoft.com/en-us/library/windows/hardware/gg463009.aspx`](http://msdn.microsoft.com/en-us/library/windows/hardware/gg463009.aspx)

本章我们将重点介绍 GDB。在 Code::Blocks 中，调试器相关功能可通过**调试**菜单进行访问，如下面的屏幕截图所示。调试器工具栏也提供了常用功能的快速访问。

![Code::Blocks 中的调试简介](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_01.jpg)

我们可以通过导航到**调试** | **调试窗口**菜单选项来访问几个与调试器相关的窗口。下面的屏幕截图显示了可用的菜单选项。

![Code::Blocks 中的调试简介](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_02.jpg)

我们可以从**调试** | **信息**中获取有关运行进程的更多信息，然后点击适当的菜单选项。下面的屏幕截图显示了可用的菜单选项：

![Code::Blocks 中的调试简介](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_03.jpg)

可以通过导航到**设置** | **调试器**菜单选项来访问调试器设置。下面的屏幕截图显示了调试器设置对话框：

![Code::Blocks 中的调试简介](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_04.jpg)

在左侧的树中选择**默认**，将会显示更多与调试器相关的选项，如下面的屏幕截图所示：

![Code::Blocks 中的调试简介](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_05.jpg)

选择前面屏幕截图中显示的**评估光标下的表达式**选项。该选项将在光标移动到变量上时提供包含详细信息的工具提示。

# 首次应用程序调试

让我们创建一个名为 `App7` 的新控制台项目，并将`main.cpp`文件中的代码替换为以下代码：

```cpp
#include <iostream>

int main() {
    const double pi = 3.1415926535897932384626433832795;
    double radius   = 20.0;
    double perimeter= 0.0;
    perimeter = 2 * pi * radius;
    std::cout << "Perimeter = " << perimeter << std::endl;
    return 0;
}
```

确保在编译工具栏中选择了**调试**目标，然后点击编译按钮进行编译。`App7` 将被编译以进行调试。

在我们要求 GDB 进行调试之前，我们必须为其创建断点。在编辑器窗口中输入代码后，Code::Blocks 将看起来类似于下面的屏幕截图。

![首次应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_06.jpg)

要设置断点，将光标移动到编辑器窗口左侧，靠近指示的行号。现在光标将变成右倾斜的光标。暂停鼠标并左键单击。断点将被设置在那里，并将以红色圆圈表示。下面的屏幕截图显示了在行号 `4` 处设置了一个断点。

![首次应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_07.jpg)

接下来按照相同的方法，在行号 5、6 和 9 处创建断点。编辑器窗口现在看起来类似于下面的屏幕截图： 

![首次应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_08.jpg)

所有断点现在都在编辑器窗口中以可视方式指示。

现在我们可以通过点击调试器工具栏中的**调试/继续**按钮来开始调试。也可以使用 *F8* 键开始调试。可能会出现下面的窗口：

![首次应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_10.jpg)

这突显了 Code::Blocks 的默认布局已经改变，因为**调试器日志**窗口已经获得了焦点（参考前面的截图）。选择“**不再打扰我**”复选框，然后单击“**否**”按钮停止它。它不会再出现。现在让我们来看看整个 IDE。

在以下截图中，执行已经在第`4`行停止，光标已经变成了黄色的三角形。这表示调试器已经在那个位置停止执行。当我们继续调试时，调试器日志窗口也将被更新。

![第一个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_11.jpg)

在继续调试之前，我们先看一下 Code::Blocks 的调试器相关功能。可以通过导航到**调试** | **调试窗口** | **CPU 寄存器**菜单选项来检查**CPU 寄存器**。寄存器是嵌入在处理器硬件中的一个小型但高速的缓冲区。

![第一个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_12.jpg)

现在导航到**调试** | **调试窗口** | **反汇编**菜单选项；这可以用来显示当前 C++代码的汇编语言表示。以下截图显示了**反汇编**窗口，并指示了执行停止的位置。单击“**混合模式**”复选框将叠加 C++代码和相应的汇编语言代码：

![第一个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_13.jpg)

这种汇编语言风格被称为**AT&T**风格。我们可以通过导航到**设置** | **调试器** | **GDB/调试器** | **默认**菜单选项，并在**选择反汇编风格**（仅限 GDB）组合框中选择**Intel**选项，来切换到**Intel**风格的汇编语言。现在关闭先前打开的反汇编对话框，然后重新打开它。它现在将以 Intel 风格显示反汇编，如下面的截图所示。请注意，AT&T 或 Intel 风格的选择取决于开发人员的偏好。它对调试过程没有影响。

![第一个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_14.jpg)

可以通过导航到**调试** | **调试窗口** | **运行线程**菜单选项来检查当前运行的线程。这个应用程序是单线程的，因此在以下截图中我们发现只有一个线程在运行：

![第一个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_15.jpg)

可以通过导航到**调试** | **信息** | **当前堆栈帧**菜单选项来检查堆栈帧。调用堆栈是一个存储有关当前运行函数的信息的数据结构。以下截图显示了当前进程的堆栈帧信息：

![第一个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_16.jpg)

### 注意

调用堆栈是一个根据（**后进先出**）原则工作的数据结构，用于存储有关活动子例程或程序的信息。堆栈帧是调用堆栈的一部分，用于存储单个子例程或函数的信息（局部变量、返回地址和函数参数）。

在 Windows 平台上运行应用程序时，会加载几个**动态链接库**（**DLL**）或动态库到内存中。DLL 提供的函数可以被其他应用程序访问，而不需要在使用它的应用程序中包含函数代码的副本。加载的库可以通过导航到**调试** | **信息** | **加载的库**菜单选项来检查。

以下截图显示了我们应用程序的加载库：

![第一个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_17.jpg)

DLL 名称旁边的星号表示它们的源代码是否可以进行调试。我们发现它们都不允许调试。

在我们介绍了几个与调试器相关的窗口之后，我们将继续进行调试。我们还将学习如何在变量上设置监视。单击“**继续**”按钮，调试器将在第`5`行停止。在编辑器窗口中右键单击`radius`变量，然后选择“监视'radius'”菜单选项。

![第一个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_18.jpg)

这将在变量`radius`上创建一个监视。监视可以定义为调试器在应用程序执行期间跟踪变量的指令。现在将打开一个带有被监视变量的单独窗口，如下面的屏幕截图所示。观察窗口也可以通过**调试** | **调试窗口** | **监视**菜单选项打开：

![第一个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_19.jpg)

如果我们再次点击**继续**按钮，应用程序的执行将前进到下一行。这将更新我们应用程序中`radius`变量的内容。观察窗口也将更新其内容，显示`radius`变量的当前值，如下面的屏幕截图所示：

![第一个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_20.jpg)

在这一步，我们将学习另一种称为**数据断点**的断点类型。在编辑器窗口中右键单击第`5`行的`radius`变量，然后单击**为'radius'添加数据断点**菜单选项：

![第一个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_21.jpg)

选择如下屏幕截图中的**读取或写入时中断**选项，然后单击**确定**按钮。通过这样做，我们指示 GDB 在每次读取或写入`radius`变量时暂停执行。

![第一个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_22.jpg)

现在将创建一个数据断点。但是数据断点在编辑器窗口中不会以可视方式显示。可以通过导航到**调试** | **调试窗口** | **断点**菜单选项，从**断点**窗口验证。下面屏幕截图中的最后一行显示已设置了数据断点。

![第一个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_23.jpg)

单击调试工具栏中的**继续**按钮，或按*F8*键，执行将继续。由于我们在上一步中设置的数据断点，它现在将在第`7`行停止。在这一行读取变量`radius`，`gdb`已经停止执行，因为数据断点条件已经满足。

![第一个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_24.jpg)

单击**继续**按钮以继续应用程序的执行，随后它将停在第`9`行。如果我们继续点击**继续**按钮，应用程序的执行将由于我们之前设置的数据断点而多次停止。这是正常的，为了立即停止执行，单击调试工具栏中的**停止**按钮，或按*Shift* + *F8*键停止执行。

这完成了我们对使用 Code::Blocks 进行应用程序调试的介绍。

# 多个应用程序调试

现实生活中的项目规模庞大，可能包含多个子项目。IDE 允许跨多个项目调试大型应用程序是至关重要的。使用 Code::Blocks，我们可以轻松实现这一点。

为了学习多个应用程序的调试，我们将创建两个项目——第一个项目是一个 DLL 项目，第二个项目是一个依赖于第一个 DLL 项目的控制台项目。然后将这两个项目保存在名为`App8`的同一工作区下。

转到**文件** | **新建** | **项目** | **动态链接库**菜单选项以创建一个 DLL 项目。将此项目命名为`libobject`。现在重命名`libobject`项目文件。我们将`main.h`文件重命名为`dllmain.h`，将`main.cpp`文件重命名为`dllmain.cpp`文件。要执行此操作，请关闭所有打开的编辑器文件，然后在项目树中右键单击文件名，如下面的屏幕截图所示：

![多个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_26.jpg)

在下面的屏幕截图中的对话框中输入新的文件名：

![多个应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_27.jpg)

这将避免文件名的歧义。现在用以下代码替换`dllmain.h`文件中的代码。

```cpp
#ifndef __DLLMAIN_H__
#define __DLLMAIN_H__

/*  To use this exported function of dll, include this header
 *  in your project.
 */

#ifdef BUILD_DLL
    #define DLL_IMP_EXPORT __declspec(dllexport)
#else
    #define DLL_IMP_EXPORT __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C"
{
#endif
    void DLL_IMP_EXPORT SayHello(void);
#ifdef __cplusplus
}
#endif

class base {
public:
    void Set(int width, int height) {
        m_width  = width;
        m_height = height;
    }
    virtual int Area() = 0;
protected:
    int m_width, m_height;
};

class DLL_IMP_EXPORT Rectangle : public base {
public:
    int Area();
};

class DLL_IMP_EXPORT Triangle : public base {
public:
    int Area();
};

#endif // __DLLMAIN_H__
```

在 Windows 上，DLL 需要特殊的修饰才能从动态链接库中导出。这个修饰语句在导出时会发生变化，并且在导入时也会发生变化。修饰`__declspec(dllexport)`用于从 DLL 中导出函数，`__declspec(dllimport)`用于从另一个 DLL 中导入函数。修饰指示链接器导出或导入一个带有或不带有名称修饰的变量/函数/对象名称。预处理器定义`DLL_IMP_EXPORT`用于指示编译器函数或类是被导出还是被导入。

C++允许函数/方法重载。这是通过在生成的代码中引入名称修饰来实现的。名称修饰是一个过程，其中函数名根据函数参数、返回类型和其他参数转换为唯一的名称。名称修饰是与编译器相关的，因此任何用 C++编写的 DLL 都不能直接与另一个编译器一起使用。

C++默认引入了所有函数的名称修饰。我们可以使用`extern "C"`关键字来停止名称修饰，并且正在使用它来停止导出的`SayHello()`函数的名称修饰。通过停止名称修饰，我们可以使用在一个编译器中编写并编译的 DLL 与另一个编译器一起使用。

我们定义了一个名为`base`的类，这个`base`类有一个成员函数`Set()`，它设置了两个内部变量。还有一个名为`Area()`的纯虚函数，必须在派生类中重新定义。**纯虚函数**是在基类中没有被实现的函数。如果在任何应用程序中调用了纯虚函数，可能会导致崩溃。

然而，这个`base`类没有用`DLL_IMP_EXPORT`修饰。这意味着它不会被导出到 DLL 中，也没有外部应用程序可以使用这个类。

为了使用`base`类的特性，我们将创建两个派生类。类`Rectangle`和`Triangle`，它们都是从`base`类公开派生的。我们在这里使用了类的继承。这些类被声明为`DLL_IMP_EXPORT`。因此，这两个类将被导出到生成的 DLL 中。

现在用以下代码替换`libobject`项目的`dllmain.cpp`文件中的代码：

```cpp
#include <windows.h>
#include <iostream>

#include "dllmain.h"

void SayHello(void) {
    std::cout << "Hello World!" << std::endl;
}

int Rectangle::Area() {
    return (m_width * m_height);
}

int Triangle::Area() {
    return (m_width * m_height / 2);
}

extern "C" DLL_IMP_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH: // attach to process
            // return FALSE to fail DLL load
            break;
        case DLL_PROCESS_DETACH: // detach from process
            break;
        case DLL_THREAD_ATTACH: // attach to thread
            break;
        case DLL_THREAD_DETACH: // detach from thread
            break;
    }
    return TRUE; // successful
}
```

`dllmain.cpp`文件中的代码主要定义了所有公开导出函数的代码。有一个`DllMain()`函数。它可以用于对 DLL 进行任何初始化或去初始化。

接下来创建一个名为`App8`的控制台应用程序。现在将工作区重命名为`App8`，并将工作区保存为`App8`。这个控制台应用程序将使用`libobject.dll`中定义的函数。用以下代码替换`App8`的`main.cpp`文件中的代码：

```cpp
#include <iostream>

#include "dllmain.h"

int main() {
    Rectangle rect;
    rect.Set(10, 20);
    Triangle  trigl;
    trigl.Set(5, 6);
    std::cout << "Rectangle(10, 20).Area() = " << rect.Area() << std::endl;
    std::cout << "Triangle(5, 6).Area() = " << trigl.Area() << std::endl;
    return 0;
}
```

接下来，我们需要准备我们的`App8`项目来使用这个 DLL。为此，转到**项目** | **构建选项**菜单选项。在项目树中选择`App8`，然后点击**搜索目录**选项卡。然后在**编译器**选项卡中添加`..\libobject`目录到列表中。这指示编译器在该目录中搜索头文件：

![多应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_28.jpg)

我们还需要指向链接器所在的目录，该目录存放了`libobject.dll`文件的导入库。为此，选择**调试**目标，点击**搜索目录**选项卡。然后点击**链接器**选项卡，将`..\libobject\bin\Debug`文件夹添加到列表中：

![多应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_29.jpg)

我们必须指示链接器查找`libobject.dll`文件中找到的符号引用。为此，点击**链接器设置**选项卡，并将`libobject.a`添加到**链接库**列表中。

![多应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_30.jpg)

我们将在这一步设置项目依赖关系。转到**项目** | **属性...**菜单选项，然后点击**项目依赖关系...**按钮。点击`libobject`，然后点击**关闭**按钮。最后点击**确定**按钮关闭**项目/目标**选项窗口。这完成了`App8`控制台应用程序的准备工作。

![多应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_31.jpg)

现在转到**构建** | **构建工作区**菜单选项。这将首先构建`libobject`项目，然后编译`App8`。

为了学习调试多个项目，我们将在以下行号设置断点：

+   `dllmain.cpp`文件中的第 11、15、19 行，`libobject`项目

+   `main.cpp`文件中的第 7、9、10、12 行，`App8`项目

断点可以从以下截图中显示的**断点**窗口中进行验证：

![多应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_32.jpg)

请注意，DLL 不能作为独立进程运行，需要主机应用程序将其加载到内存中。为了调试 DLL，我们必须调试加载和运行它的主机应用程序。或者，我们可以通过导航到**项目** | **设置程序参数...**菜单选项来指定一个主机应用程序（在我们的例子中是`App8.exe`）进行调试。

我们将使用第一种方法，让我们的主机应用程序加载`libobject.dll`，然后使用它来调试`libobject.dll`和`App8.exe`文件。确保在项目树中激活了`App8`项目，然后在调试器工具栏中点击调试/继续按钮：

![多应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_34.jpg)

在上述截图中，执行已经停在`dllmain.cpp`文件的第 19 行。每当`DllMain()`被导出时，它都成为任何 DLL 加载/卸载过程中被调用的第一个函数。因此，执行会在那里停止。

以下截图中的加载的库窗口确认了`libobject.dll`已经加载到内存中，并且这个库可以进行调试：

![多应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_33.jpg)

点击**继续**按钮继续。执行现在将在`main.cpp`文件的第`7`行暂停。

![多应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_35.jpg)

再次点击**继续**按钮两次。执行将停在`main.cpp`文件的第`10`行，如下截图所示：

![多应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_36.jpg)

再次点击**继续**按钮，执行将停在`dllmain.cpp`文件的第`11`行。

调试器现在正在调试`libobject`项目的源文件，这是一个独立的项目。如果光标悬停在`m_height`变量上，调试器将评估这个变量并显示它的值。

![多应用程序调试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415_03_37.jpg)

很明显，我们可以同时调试 DLL 项目和控制台应用程序项目。较大的项目可以使用类似的方法进行调试。通过这个例子，我们结束了多应用程序调试会话。点击**停止**按钮停止调试。

# 总结

在本章中，我们学习了使用 GNU GDB 调试器在 Code::Blocks 中进行应用程序调试。我们学习了 Code::Blocks 提供的各种与调试相关的工具。随后，我们学习了调试单个和多个应用程序。

在下一章中，我们将讨论 Windows 的应用程序开发。


# 第四章：使用 Code::Blocks 进行 Windows 应用程序开发

在之前的章节中，我们的应用程序开发重点是基于控制台的应用程序。这也被称为纯文本应用程序，因为基于控制台的应用程序只能显示文本和 ASCII 艺术。然而，在本章中，我们的重点将放在 Windows 应用程序开发上。

Windows 是世界上使用最广泛的操作系统之一。Code::Blocks 可以用于开发 Windows、Linux 或 Mac 的应用程序。考虑到 Windows 平台的流行，我们将把重点限制在 Windows 平台上。

Windows 应用程序也被称为 GUI（图形用户界面）应用程序。用户与应用程序的交互是通过鼠标和键盘完成的。记事本应用程序是 Windows 操作系统捆绑的 GUI 应用程序的一个例子。以下截图显示了记事本应用程序：

![使用 Code::Blocks 进行 Windows 应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_01.jpg)

Code::Blocks 随附了所有用于 Windows 应用程序开发的工具。让我们开发一个应用程序并学习它。

# 第一个 Windows 应用程序

遵循 Hello World 应用程序的传统，我们将创建我们的第一个 Windows 应用程序。要做到这一点，请执行以下步骤：

1.  转到**文件** | **新建** | **项目...**菜单选项。选择**Win32 GUI 项目**选项，如下截图所示，然后单击**Go**按钮：![第一个 Windows 应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_03.jpg)

1.  在向导的第一页上单击**下一步**按钮，如下截图所示。选择**基于框架**选项，然后单击**下一步**按钮。基于对话框的应用程序不能包含菜单栏或工具栏。因此，我们选择了基于框架的应用程序。![第一个 Windows 应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_04.jpg)

1.  将`App9`作为项目标题输入，并选择创建项目的文件夹。现在单击**下一步**按钮，然后单击**完成**按钮以完成向导。

1.  在`main.cpp`文件中用以下代码替换代码：

```cpp
#include <windows.h>

int WINAPI WinMain(HINSTANCE thisInstance,
                   HINSTANCE prevInstance,
                   LPSTR     commandLine,
                   int       cmdShow
                   )
{
    MessageBox(NULL, "Hello World!", "Title", MB_OK | MB_ICONINFORMATION);
    return 0;
}
```

1.  现在在编译器工具栏中单击构建图标。在编译器工具栏中单击运行按钮。我们的`App9`窗口将类似于以下截图：![第一个 Windows 应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_07.jpg)

1.  恭喜！我们已成功编译了我们的第一个 Windows 应用程序。

让我们理解我们为这个应用程序编写的代码。我们在代码开头包含了`windows.h`文件。这个文件必须包含在所有 Windows 应用程序中，因为它包含了 Windows 的相关函数声明。随后我们有一个名为`WinMain()`的函数，这是 Windows 应用程序的**入口点**。入口点是在应用程序启动时调用的第一个函数。

`WinMain()`函数接受四个参数——当前实例的句柄，先前实例的句柄，命令行字符串指针，以及控制应用程序应如何显示的窗口显示状态。

我们调用`MessageBox()`函数来显示一个消息框。它接受四个参数——父窗口的句柄（在我们的情况下为`NULL`或没有），消息文本，对话框标题，以及控制要显示的按钮和图标的标志的组合。在我们的情况下，我们使用了`MB_OK`和`MB_ICONINFORMATION`的组合，这指示`MessageBox()`函数分别显示一个**OK**按钮和一个信息图标。

但为什么我们为 GUI 应用程序获取了一个控制台？答案是，默认情况下，Code::Blocks 将调试目标创建为控制台应用程序。我们可以通过导航到**项目** | **属性...**菜单选项，然后单击**构建目标**选项卡来确认这一点。参考以下截图：

![第一个 Windows 应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_08.jpg)

这种方法的优点是可以将调试输出打印到控制台，以便更容易进行调试。可以通过在**类型：**组合框中将应用程序类型更改为**GUI 应用程序**来禁用此功能，如下截图所示：

![第一个 Windows 应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_09.jpg)

这将停止启动控制台窗口。

## Windows 应用和 Unicode

Unicode 是一种用于编码、存储和表示世界大多数语言文本的标准。C++的`char`数据类型大小为 1 字节。它只能表示英语中可用的文本。要在 Windows 应用程序中启用 Unicode 支持，我们必须使用一个称为`wchar_t`的特殊数据类型，其大小为 2 字节。让我们用印地语说 Hello World。为此，我们将用以下代码替换以前的`MessageBox（）`代码：

```cpp
MessageBox(NULL, TEXT("holaao valD-"), TEXT("Title"), MB_OK | MB_ICONINFORMATION);
```

Code::Blocks 编辑器窗口将类似于以下屏幕截图。编辑器字体大小已更改为 16 点，以便使用 Devnagiri 脚本：

![Windows App and Unicode](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_41.jpg)

我们已经用`TEXT（）`宏装饰了印地语文本。当定义了`UNICODE`或`_UNICODE`预处理器定义时，此宏用于将 Unicode 字符串转换为`wchar_t*`。当未启用 Unicode 支持时，它返回`char*`。

接下来，我们将定义以下预处理器定义。转到**项目** | **构建选项…**菜单选项。然后在左侧的树中选择`App9`，然后单击**编译器设置**，然后单击**#defines**选项卡。

![Windows App and Unicode](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_10.jpg)

将`UNICODE`和`_UNICODE`添加到文本控件中，然后单击**确定**按钮。单击编译器工具栏中的构建按钮，然后单击运行按钮。现在`App9`将以印地语显示 Hello World，如下面的屏幕截图所示：

![Windows App and Unicode](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_11.jpg)

请注意，我们将在所有后续应用程序中启用 Unicode 支持。

# 事件驱动的 Windows 应用程序

Windows 应用程序是**事件驱动**应用程序。事件可以是应用程序的外部或内部输入。事件驱动应用程序运行一个消息循环，该循环解析传入的事件，然后调用与该事件对应的适当函数。由**Win32 GUI 项目**向导生成的 Code::Blocks 默认代码生成了一个事件驱动应用程序的样板代码。

为了理解事件驱动编程，我们将使用以下示例来学习和理解。我们将使用本示例的本机 Win32 API。Win32 API 是几个工具包的基础。因此，我们应该了解它以便了解其他工具包。

让我们创建另一个名为`App10`的 GUI 应用程序。用以下代码替换向导生成的代码。还要按照前面示例中的步骤启用 Unicode 支持。由于代码片段很大，我们将分步理解并粘贴到编辑器窗口中。

以下代码片段显示了头文件声明、全局变量声明和回调函数声明：

```cpp
#include <windows.h>
#define ID_BTN_CLICK_ME 100
// This function is called by the Windows function DispatchMessage()
LRESULT CALLBACK WindowProcedure (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

// Make the class name into a global variable
TCHAR szClassName[ ] = TEXT("CodeBlocksWindowsApp");
```

在以下代码片段中，我们将定义`WinMain（）`函数。我们将在`WinMain（）`函数内定义`WNDCLASSEX`结构的对象。此结构需要几个输入。通过`wincl.lpfnWndProc`，我们已经将回调函数`WindowProcedure（）`分配给了`wincl`对象。这指示应用程序调用该函数进行事件处理。最后，`wincl`对象将使用`RegisterClassEx（）`函数注册。一旦对象成功注册，我们就可以使用`CreateWindowEx（）`函数创建该类的窗口。

我们将使用`ShowWindow（）`函数显示新创建的窗口。窗口显示后，我们将使用`GetMessage（）`函数在`while`循环内运行事件处理循环。所有传入的事件都将通过`DispatchMessage（）`函数发送到`WindowProcedure（）`函数。

```cpp
int WINAPI WinMain (HINSTANCE hThisInstance,
                    HINSTANCE hPrevInstance,
                    LPSTR lpszArgument,
                    int nCmdShow)
{
    HWND hwnd;    // This is the handle for our window
    MSG messages; // Here messages to the application are saved
    WNDCLASSEX wincl; //Data structure for the windowclass

    // The Window structure
    wincl.hInstance = hThisInstance;
    wincl.lpszClassName = szClassName;
    wincl.lpfnWndProc = WindowProcedure;  // Callback function
    wincl.style = CS_DBLCLKS; // Catch double-clicks
    wincl.cbSize = sizeof (WNDCLASSEX);

    // Use default icon and mouse-pointer
    wincl.hIcon = LoadIcon (NULL, IDI_APPLICATION);
    wincl.hIconSm = LoadIcon (NULL, IDI_APPLICATION);
    wincl.hCursor = LoadCursor (NULL, IDC_ARROW);
    wincl.lpszMenuName = NULL;  /* No menu */
    wincl.cbClsExtra = 0;  // No extra bytes after the window class
    wincl.cbWndExtra = 0;  // structure or the window instance
    // Use Windows's default colour as the background of the window
    wincl.hbrBackground = (HBRUSH) COLOR_BACKGROUND;

    // Register the window class, and if it fails quit the program
    if (!RegisterClassEx (&wincl))
        return 0;

    // The class is registered, let's create the window
    hwnd = CreateWindowEx (
           0,            // Extended possibilites for variation
           szClassName,         // Classname
           TEXT("App for Windows"), // Title Text
           WS_OVERLAPPEDWINDOW, // default window
           CW_USEDEFAULT,  // Windows decides the position
           CW_USEDEFAULT,  // where the window ends up on the screen
           300,            // The programs width
           250,            // and height in pixels
           HWND_DESKTOP,   // The window is a child-window to desktop
           NULL,           // No menu
           hThisInstance,  // Program Instance handler
           NULL            // No Window Creation data
           );

    // Make the window visible on the screen
    ShowWindow (hwnd, nCmdShow);

    // Run the message loop. It will run until GetMessage() returns 0
    while (GetMessage (&messages, NULL, 0, 0))
    {
        // Translate virtual-key messages into character messages
        TranslateMessage(&messages);
        // Send message to WindowProcedure
        DispatchMessage(&messages);
    }

    // Return value of PostQuitMessage()
    return messages.wParam;
}
```

当窗口正在创建时，Windows 操作系统会发送`WM_CREATE`事件。然后，我们将使用`CreateWindow（）`函数创建一个按钮。

我们将通过在`WindowProcedure（）`函数中处理`WM_COMMAND`事件来处理按钮按下。然后，每当单击此按钮时，我们将显示一个消息框。

最后，我们将处理`WM_DESTROY`事件，每当窗口被销毁时都会发出该事件。`PostQuitMessage()`函数将发布值为`0`的返回值，发出`WM_QUIT`事件到消息队列。

```cpp
LRESULT CALLBACK WindowProcedure (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{switch (message) // handle the messages
    {
        case WM_CREATE:
            CreateWindow(TEXT("button"), TEXT("Click Me!"),                     WS_VISIBLE | WS_CHILD, 20, 50, 80, 25, hwnd, (HMENU) ID_BTN_CLICK_ME, NULL, NULL);
            break;
        case WM_COMMAND:
            if (LOWORD(wParam) == ID_BTN_CLICK_ME) {
                MessageBox(hwnd, TEXT("Hello World!"),             TEXT("Information"), MB_OK | MB_ICONINFORMATION);
            }
            break;
        case WM_DESTROY:
            PostQuitMessage (0); // send a WM_QUIT to the message queue
            break;
        default:  // for messages that we don't deal with
            return DefWindowProc (hwnd, message, wParam, lParam);
    }

    return 0;
}
```

这完成了我们的 Windows 应用程序。按下*F9*键（构建和运行工具栏中的构建和运行图标的替代方法）来构建和运行此应用程序。将呈现以下截图：

![事件驱动的 Windows 应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_42.jpg)

Win32 API 的优势：

+   生成的可执行文件大小更小

+   由于开销较少，生成的代码速度更快

Win32 API 的缺点：

+   由于需要编写更多的代码，开发时间更长

+   开发人员可以使用最小的一组 GUI 控件（例如文本框、按钮等）

为了解决这个问题，开发了 GUI 工具包。GUI 工具包简化了开发过程，允许代码重用和更小的代码库。它还包含复杂的 GUI 控件（例如，富文本控件、HTML 控件等）。

# wxWidgets GUI toolkit

GUI 工具包是一组头文件和库，使开发人员更容易开发 GUI。市场上有几种 GUI 工具包可用，以下是其中的一些：

+   **Microsoft Foundation Class**（**MFC**）：这是一组作为 Win32 API 包装器的类。它随商业版本的 Visual Studio 捆绑提供。MFC 是专有的，需要 Visual Studio 许可证才能使用。MFC 应用程序具有本地外观和感觉。

+   **Qt**（发音为“cute”）：这是由**Digia**开发的开源跨平台 GUI 工具包。Qt 根据商业和 GPL/LGPL 许可证提供。它可在包括 Windows、Linux、Mac 等在内的广泛平台上使用。Qt 绘制的 GUI 是自定义绘制的 UI，可能与平台上的标准应用程序不同。

+   **wxWidgets**：这是另一个开源的跨平台 GUI 工具包，根据 wxWindows 许可证（基于 LGPL 但限制较少）许可。它生成的 UI 具有本地外观和感觉，因为它使用平台标准的 UI 元素。

由于其更简单的许可模型、本地外观和感觉以及跨平台开发能力，本书将专注于 wxWidgets 工具包。本书假定读者已将编译后的 wxWidgets 提取到`Z:\wxWidgets`文件夹中。

为了理解 Win32 API 和 wxWidgets 之间的相似之处，我们将使用 wxWidgets 重新创建`App9`的功能。

1.  转到**文件** | **新建** | **项目…**菜单选项。然后选择**wxWidgets 项目**向导。

1.  接下来单击**Go**按钮，然后在下一个窗口中单击**下一步**按钮。在向导页面中选择**wxWidgets 2.9.x（SVN 版本）**选项，然后单击**下一步**按钮，如下截图所示：![wxWidgets GUI toolkit](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_14.jpg)

1.  将`App11`输入为项目标题，然后单击**下一步**按钮。单击**下一步**按钮跳过项目详细信息页面。

1.  选择**基于框架**的应用程序类型，如下截图所示。基于框架的应用程序可以拥有菜单、工具栏，适用于大型应用程序。将**首选 GUI 生成器**选项保留为**无**，因为我们将自己编写 GUI 代码。![wxWidgets GUI toolkit](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_16.jpg)

1.  在下面的窗口中，`$(#wx`)是一个全局变量，指向 wxWidgets 安装目录。或者，可以在此处输入我们的情况下的 wxWidgets 的完整路径，即`Z:\wxWidgets`：![wxWidgets GUI toolkit](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_17.jpg)

1.  如果此全局变量在此时未定义，将弹出以下窗口。如果全局变量已经定义，则不会弹出。![wxWidgets GUI toolkit](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_18.jpg)

1.  根据上一个截图完成文本框的内容，然后单击**关闭**按钮。然后连续单击两次**下一步**按钮。

1.  在下面的截图中，勾选**启用 Unicode**选项以启用 Unicode 支持，然后单击**下一步**按钮。在下一页中单击**完成**按钮以关闭此向导。向导将生成必要的代码并设置一个使用 wxWidgets 工具包开发应用程序的项目。![wxWidgets GUI toolkit](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_19.jpg)

1.  用以下代码替换`App11Main.h`文件中的代码：

```cpp
#ifndef APP11MAIN_H
#define APP11MAIN_H

#include <wx/wx.h>
#include <wx/sizer.h>
#include <wx/button.h>

class App11Frame: public wxFrame {
    public:
        App11Frame(wxFrame *frame, const wxString& title);
        ~App11Frame();
    private:
        static const long idBtnClickMe;
        wxBoxSizer* m_boxSizerMain;
        wxButton* m_btnClickMe;
        void OnClickMe(wxCommandEvent& event);
        void OnClose(wxCloseEvent& event);
        DECLARE_EVENT_TABLE()
};
```

`App11Frame`类是从`wxFrame`类派生而来的。`wxFrame`类表示一个基本窗口。成员变量`m_btnClickMe`已经被定义用来创建和存储按钮，`idBtnClick`将存储它的 ID 以进行事件处理。我们放置了一个`DECLARE_EVENT_TABLE()`函数宏来创建与该类相关的事件处理的样板代码。

1.  接下来用以下代码替换`App11Main.cpp`文件中的代码：

```cpp
#include "App11Main.h"
const long App11Frame::idBtnClickMe = ::wxNewId();

BEGIN_EVENT_TABLE(App11Frame, wxFrame)
    EVT_BUTTON(idBtnClickMe, App11Frame::OnClickMe)
    EVT_CLOSE(App11Frame::OnClose)
END_EVENT_TABLE()

App11Frame::App11Frame(wxFrame *frame, const wxString& title)
    : wxFrame(frame, -1, title)
{
    this->SetSizeHints(wxDefaultSize, wxDefaultSize);
    m_boxSizerMain = new wxBoxSizer(wxHORIZONTAL);
    m_btnClickMe = new wxButton(this, idBtnClickMe, _T("Click Me!"),
                                wxDefaultPosition, wxDefaultSize, 0);
    m_boxSizerMain->Add(m_btnClickMe, 0, wxALL, 5);
    this->SetSizer(m_boxSizerMain);
    this->Layout();
}

App11Frame::~App11Frame() {
}

void App11Frame::OnClose(wxCloseEvent &event) {
    Destroy();
}

void App11Frame::OnClickMe(wxCommandEvent& event) {
    wxMessageBox(_T("Hello World!"), _T("Information"), wxOK | wxICON_INFORMATION, this);
}
```

使用`BEGIN_EVENT_TABLE()`和`END_EVENT_TABLE()`宏布置了一个事件表。这定义了回调函数与相应事件的关系。`OnClickMe()`函数已连接到按钮按下事件。每当用户按下**Click Me!**按钮时，它将显示一条消息。

当应用程序关闭时，`OnClose()`函数将被调用。它调用了一个`Destroy()`函数来启动应用程序关闭。

1.  现在用以下代码替换`App11App.h`文件中的代码：

```cpp
#ifndef APP11APP_H
#define APP11APP_H

#include <wx/app.h>

class App11App : public wxApp
{
    public:
        virtual bool OnInit();
};

#endif // APP11APP_H
```

在前面的文件中，我们从`wxApp`派生了一个`App11App`类。在这个类中实现了一个虚函数`OnInit()`。

1.  接下来在`App11App.cpp`文件中输入以下代码：

```cpp
#include "App11App.h"
#include "App11Main.h"

IMPLEMENT_APP(App11App);

bool App11App::OnInit() {
    App11Frame* frame = new App11Frame(0L, _("wxWidgets Application Template"));
    #ifdef __WXMSW__
    frame->SetIcon(wxICON(aaaa)); // To Set App Icon
    #endif
    frame->Show();

    return true;
}
```

在`OnInit()`函数的实现中，一个名为`frame`的对象是从`App11Frame`类派生出来的。资源文件仅在 Windows 平台上可用。因此，它已被包含在预处理器宏`__WXMSW__`中，并随后在第 12 行启动了应用程序。

1.  将`resource.rc`文件中的代码保持不变。

1.  按下*F9*按钮进行编译和运行。将启动以下窗口。我们发现我们的应用程序现在运行正常：

![wxWidgets GUI toolkit](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_43.jpg)

之前我们提到了 wxWidgets 的跨平台开发能力。让我们将这种能力付诸实践。我们将在 Linux 平台上编译`App11`源码而不做任何更改。在这个例子中，我们使用**CentOS 6** Linux。

为了在 Linux 平台上编译，我们将使用一个`Makefile`。请记住，我们也可以使用 Code::Blocks wxWidgets 项目向导来生成一个针对 Linux 平台的项目。但是在我看来，开发人员应该熟悉`Make`工具。

Make 是一个构建工具，可以根据一个名为`Makefile`的文本文件中的一组规则将任意数量的源文件编译成二进制文件。Make 有效地处理构建依赖关系，对于一个大型项目，Make 只会编译自上次构建以来发生变化的相关文件。这样可以节省时间，也可以消除整个构建过程中的任何人为错误。

执行以下步骤：

1.  将以下代码粘贴到一个文件中，并将其保存为文件名`Makefile`：

```cpp
CPP=g++
CXXFLAGS=-c $(shell wx-config --cflags)
LDFLAGS=$(shell wx-config --libs)
SOURCES=App11Main.cpp App11App.cpp

App11: App11Main.o App11App.o
  $(CPP) $(LDFLAGS) App11Main.o App11App.o -o App11

App11Main.o:
  $(CPP) $(CXXFLAGS) App11Main.cpp

App11App.o:
  $(CPP) $(CXXFLAGS) App11App.cpp

clean:
  rm -rf *.o App11
```

在这个文件中，前四行定义了几个变量。`CPP`变量定义了 C++编译器二进制文件，`CXXFLAGS`存储了通过运行脚本`wx-config`为`wxWidgets`项目提供的必要编译器标志。wxWidgets 项目提供了一个名为`wx-config`的 shell 脚本，可以用来确定编译器和链接器标志。

`LDFLAGS`存储了用于生成可执行二进制文件的必要链接器标志。`SOURCES`变量定义了要编译的源文件。请注意，我们不再使用`resource.rc`文件，因为在 Linux 平台上不存在资源编译器。

`App11：`行定义了一个名为`App11`的 make 目标，其中包括两个子目标`App11Main.o`和`App11App.o`。在接下来的一行中定义了一个 shell 命令，该命令指示在所有子目标成功构建后要执行的命令。随后，这两个目标也以类似的方式定义。

`clean`目标执行一个命令来删除所有对象文件和我们的可执行二进制文件。

1.  在 Linux shell 提示符下发出以下命令来编译我们的应用程序：

```cpp
[biplab@centos App11]$ make

```

1.  要运行我们的应用程序，请使用以下命令：

```cpp
[biplab@centos App11]$ ./App11

```

1.  将显示以下窗口：![wxWidgets GUI 工具包](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_44.jpg)

我们发现我们的应用程序现在在 Linux 平台上完美运行。它的行为与我们想要的完全一样。我们没有对我们为 Windows 平台编写的代码进行任何更改。但是我们的 GUI 工具包已经将我们的代码内部映射到适用于 Linux 平台的适当函数。这对开发人员来说是一个巨大的优势，因为面向多个平台变得更加容易。

# 使用 wxSmith 进行快速应用程序开发

在过去的几节中，我们已经了解了 Windows 平台的应用程序开发。但是我们所有的代码都是手写的。我们还注意到，即使对于一个简单的 GUI，我们也必须编写几行代码。

那么，我们能做些什么呢？自动生成 GUI 代码怎么样？听起来有趣！Code::Blocks 带有一个名为**wxSmith**的插件，它可以根据用户在可视化编辑器中生成的 GUI 生成基于 wxWidgets 工具包的 C++代码。我们将通过另一个示例来学习这个功能。

1.  创建一个新的 wxWidgets 项目。这次我们将给它取一个有意义的名字。在下面的窗口中，将项目标题输入为`MyNotePad`。

1.  在接下来的页面中，将**wxSmith**选择为**首选 GUI 生成器**。此选项配置 wxWidgets 项目以使用 wxSmith GUI 生成器。参考以下截图：![使用 wxSmith 进行快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_23.jpg)

1.  项目生成完成后，将显示以下文件窗口：![使用 wxSmith 进行快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/Image1.jpg)

1.  前面的窗口有以下三个主要组件：

+   wxSmith 窗口：此窗口显示可编辑的 UI 元素

+   资源树：此窗口提供了项目的整体视图，显示了该特定项目的 GUI 元素的层次结构

+   属性窗口：此窗口显示了 wxSmith 窗口中当前选定对象的属性

1.  点击资源树中显示的`MyNotePadFrame`项目，然后点击属性窗口中的**Title**属性。在文本框中输入`MyNotePad`。这将把我们的应用程序标题设置为`MyNotePad`。![使用 wxSmith 进行快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_26.jpg)

1.  现在我们将向我们的应用程序添加一个`wxTextCtrl`控件。这将向我们的应用程序添加一个文本框。在下方的工具栏上点击`wxTextCtrl`控件按钮。立即在 wxSmith 窗口内显示的**MyNotePadFrame**窗口将被选中。![使用 wxSmith 进行快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_27.jpg)

1.  点击它，这个文本控件将被添加到其中。wxSmith 窗口将看起来类似于以下截图：![使用 wxSmith 进行快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_28.jpg)

1.  在属性窗口中更改以下属性：

+   文本属性：它是一个空字符串。此属性存储文本控件中的文本

+   变量名属性：将其更改为`TextCtrlNotePad`。此属性将用于命名`wxTextCtrl`类的对象。

+   **标识符**属性`ID_TEXTCTRL_NOTEPAD`：它将被分配一个唯一的整数，然后将用于为其分配事件处理程序和事件类型。

1.  在属性窗口中向下滚动并点击**Style**属性。点击**wxTE_MULTILINE**属性进行选择。这将使文本控件显示多行文本。![使用 wxSmith 进行快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_29.jpg)

1.  在下一步中，我们将编辑菜单栏。双击菜单栏图标（如下截图所示）：![使用 wxSmith 进行快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_30.jpg)

1.  菜单栏编辑器窗口将弹出。在左侧的菜单树中选择“退出”菜单选项，然后点击“新建”按钮：![使用 wxSmith 进行快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_31.jpg)

1.  单击**^**按钮将新菜单项移动到**退出**菜单选项之上。如下屏幕截图所示，可以使用以下四个按钮重新排列菜单树中的菜单项：![wxSmith 快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/Image2.jpg)

1.  现在在菜单树中选择新菜单选项，并在右侧更改以下属性：

+   ID 属性：将其更改为`idFileOpen`。此属性将被定义为一个唯一的整数，并将用于将其分配给事件处理程序和事件类型。

+   标签属性：将此属性更改为`&Open`。此文本定义了菜单标签，`&O`文本将定义加速键。只要此菜单选项可见，就可以通过按下*O*按钮选择并单击此菜单。

+   加速器属性：将此属性更改为`Ctrl+O`。此属性为此菜单选项定义了一个键盘加速器。键盘加速器是一组唯一的按键组合，无论菜单项的可见性如何，都将生成此菜单选项的单击事件。

+   帮助属性：将其更改为“打开文件...”文本。每当鼠标光标或键盘选择此选项时，将在状态栏中显示此文本。

![wxSmith 快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_33.jpg)

1.  单击**确定**按钮关闭此窗口。我们现在已经向现有菜单栏添加了一个菜单选项。在我们添加代码以使用此菜单选项打开文件之前，我们需要添加一个文件打开保存控件。

1.  单击**对话框**选项卡，然后单击**wxFileDialog**控件按钮。这将向`MyNotePadFrame`类添加一个标准的文件打开和保存对话框。![wxSmith 快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_34.jpg)

1.  在属性窗口中更改以下属性：

+   将**通配符**更改为`*.txt`。这将将过滤文本设置为具有`.txt`扩展名的文件。

+   将**变量名**更改为`NotePadFileDialog`。这将用于创建`wxFileDialog`类的对象，该对象表示标准的打开或保存对话框。

![wxSmith 快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_35.jpg)

1.  现在我们准备添加代码到新添加的菜单选项。单击资源树中的**&Open**项目，然后单击属性窗口中的**{}**按钮。单击下拉框，选择如下屏幕截图中的**--添加新处理程序--**菜单选项：![wxSmith 快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_36.jpg)

1.  在对话框中输入`OnFileOpen`文本，然后单击**确定**按钮，如下屏幕截图所示：![wxSmith 快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_37.jpg)

1.  代码编辑器窗口将打开。将以下代码添加到`MyNotePadFrame::OnFileOpen()`函数中。

```cpp
int result;
wxTextFile textFile;
wxString fileContent;

result = NotePadFileDialog->ShowModal();
if (result == wxID_OK) {
  if (textFile.Open(NotePadFileDialog->GetPath())) {
    for (size_t i = 0; i < textFile.GetLineCount(); i++) {
      fileContent << textFile.GetLine(i) << _T("\r\n");
    }
    textFile.Close();
    TextCtrlNotePad->SetLabel(fileContent);
  }
}
```

让我们解释前面的代码。我们在开头定义了一对变量。我们使用`ShowModal()`函数显示文件打开对话框，此对话框的结果将存储在`result`变量中。下一行检查我们是否收到了`wxID_OK`值，这表示用户已选择了一个文件。

我们使用`Open()`函数打开文本文件，并使用从对话框中接收的文件名。如果文件打开成功，那么我们将创建一个循环逐行读取所有行。`fileContent`变量附加从文件中读取的行，然后附加一个新行（在 Windows 上为`\r\n`）到此字符串。当我们完成读取所有行时，打开的文本文件将使用`Close()`函数关闭。

最后，我们将存储在`fileContent`变量中的文本存储到我们的主文本控件中。

我们还需要包含一个额外的头文件，以便使用`wxTextFile`类。在`MyNotePadMain.cpp`文件的`#include <wx/msgdlg.h>`行之后添加以下行：

```cpp
#include <wx/textfile.h>

```

1.  现在我们准备编译我们的小记事本应用程序。按下*F9*键进行构建和运行。我们的应用程序将类似于以下屏幕截图：![wxSmith 快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_38.jpg)

1.  转到**文件** | **打开**菜单选项，将打开以下对话框：![wxSmith 快速应用程序开发](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_39.jpg)

1.  单击**Open**按钮，我们的应用程序现在将打开所选的文本文件，如下面的屏幕截图所示：![Rapid app development with wxSmith](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_04_40.jpg)

我们的应用程序现在可以工作了！我们在 Code::Blocks 的帮助下编写了大部分与 GUI 相关的代码。唯一手动编写的代码是我们插入的用于打开文本文件的代码。Code::Blocks 提供了一个出色的跨平台和快速应用程序开发平台。我们可以使用这种方法轻松地在 Code::Blocks 中开发 GUI 应用程序。

## 练习

在上一节中，我们学习并开发了我们自己的记事本应用程序。但是，我们的应用程序仅限于打开文件。在这个练习中，我们将扩展我们的应用程序以保存文本文件。

我们将执行以下步骤：

1.  在`&Open`菜单选项后的文件菜单中添加一个菜单项`&Save`，使用`Ctrl+S`作为键盘加速器，`idFileSave`作为 ID，`Saves a file...`作为帮助文本。

1.  为此菜单选项添加事件处理程序，并添加事件处理程序函数`OnFileSave()`。

1.  最后，将以下代码添加到`MyNotePadFrame::OnFileSave()`函数中：

```cpp
int result;

result = NotePadFileDialog->ShowModal();
if (result == wxID_OK) {
  if (!TextCtrlNotePad->SaveFile(NotePadFileDialog->GetPath())) {
    wxMessageBox(_T("Couldn't save ") + NotePadFileDialog->GetPath(),
        _T("Error"), wxOK | wxICON_ERROR);
  }
}
```

这段代码类似于我们为`OnFileOpen()`函数编写的代码。我们使用`wxTextCtrl::FileSave()`函数在第 5 行保存我们的文件。第 6 行的代码确保在无法写入文件时显示错误消息。

我把它留给你来按照之前的步骤并完成这个练习。您可以参考附带的 MyNotePad 应用程序源代码来完成此练习。

# 总结

在本章中，我们学习了使用 Win32 api 和 Code::Blocks 在 Windows 上开发应用程序。然后，我们专注于 GUI 工具包，并使用 wxWidgets 工具包在 Windows 和 Linux 上开发了我们的第一个应用程序。

Code::Blocks 还具有快速应用程序开发工具包，我们使用它来开发我们自己的记事本应用程序。

在下一章中，我们将选择一个应用程序，并学习如何从头开始规划和开发它。


# 第五章：编程作业

我们在之前的章节中学习了 Code:Blocks 和 Windows 应用程序开发。在本章中，我们将运用这些知识，并作为练习从头开始开发一个应用程序。我们将首先查看最终的应用程序，然后从零开始开发它。我们将使用之前章节中学到的工具，您可以在需要时参考。

# 开发 MyPaint - 一个图像查看器

我们将在本章练习中开发一个图像查看器应用程序。我们的图像查看器应用程序应具有以下功能：

+   它应该能够打开`.jpeg`、`.png`和`.bmp`文件

+   它应该允许用户以 10%的间隔放大和缩小加载的图像

+   缩放范围应在 10%到 200%之间

+   大多数命令应该分配键盘快捷键

+   应该有工具栏以提供对常用功能的访问

+   应用程序应该使用 Code::Blocks 的 wxSmith 插件开发

+   应用程序将使用 wxWidgets 工具包

我们的应用程序应该看起来像下面的屏幕截图。下面的屏幕截图显示我们的图像查看器应用程序已经打开了`Koala.jpg`文件（Windows 7 标准壁纸集的一部分），并将缩放级别设置为 60%。

![开发 MyPaint - 一个图像查看器](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_05_01.jpg)

看起来很有趣，不是吗？让我们开始练习并解决它。我们将分两步进行。

1.  了解我们的图像查看器应用程序的结构。

1.  使用 Code::Blocks 开始应用程序开发。

# 练习应用程序的解剖结构

我们的图像查看器应用程序使用多个 C++类来打开、显示和控制图像的显示。以下屏幕截图突出显示了负责用户交互的主要类：

![练习应用程序的解剖结构](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_05_02.jpg)

让我们更多地了解以下项目列表中列出的类：

+   `wxFrame`类：此类表示主窗口。所有其他可视元素都显示在此类内部。

+   `wxMenuBar`类：此类在我们的应用程序中显示菜单栏。

+   `wxToolBar`类：此类在我们的应用程序中显示工具栏。

+   `wxScrolledWindow`类：此类用于显示图像。此类创建一个可调整大小的窗口以匹配窗口大小。

+   `wxStatusBar`类：此类在应用程序底部显示状态栏。我们将使用它来显示菜单项帮助和其他信息。

下图显示了类的树形结构及其与`wxFrame`派生类的关系：

![练习应用程序的解剖结构](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_05_11.jpg)

在上图中，`wxMenuBar`、`wxToolBar`和`wxStatusBar`是派生类，并直接添加到`wxFrame`派生类中。

而对于`wxScrolledWindow`派生类，我们需要几个额外的类。我们有两个中间类，`wxBoxSizer`和`wxGridSizer`，用于`wxScrolledWindow`派生类。这些类被称为布局类，帮助在父窗口内布局子窗口。请注意，布局类对用户不可见。

wxWidgets 提供了一个类来通过`wxImage`类加载、操作多种图像格式。这个类是我们应用程序的引擎。`wxScrolledWindow`类使用它来加载和操作图像文件。`wxPaintDC`是`wxScrolledWindow`用来将加载的图像文件绘制到自身上的类。

通过这个对我们应用程序结构的介绍，我们将继续开发我们的应用程序。

# 练习问题的解决方案

让我们通过以下步骤逐步解决它：

1.  创建一个新的`wxWidgets`项目，并将项目名称设置为`MyPaint`。选择**wxSmith**作为**首选 GUI 生成器**。

1.  在如下屏幕截图所示的**管理**窗格中单击**wxFrame**：![练习问题的解决方案](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_05_02A.jpg)

1.  将`Title`属性设置为`MyPaint`。

1.  单击**布局**选项卡，然后单击如下屏幕截图所示的 wxBoxSizer 按钮。然后单击 wxSmith 窗口内显示的框架：![练习问题的解决方案](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_05_03.jpg)

1.  接下来，以类似的方式将 wxGridSizer 添加到新添加的 wxBoxSizer 中。参考以下截图以获取 wxGridSizer 按钮。添加 wxGridSizer 后，将**Cols**属性设置为`1`。![练习问题的解决方案](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_05_04.jpg)

1.  单击**标准**选项卡，并根据以下截图将 wxScrolledWindow 添加到 wxGridSizer 中：![练习问题的解决方案](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_05_05.jpg)

1.  为 wxScrolledWindow 设置以下属性：

+   **变量名**设置为`MyPaintWindow`

+   将最小宽度设置为`640`，最小高度设置为`480`

+   **边框宽度**设置为 5。

1.  在此步骤中，**管理**窗格应类似于以下截图：![练习问题的解决方案](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_05_06.jpg)

1.  单击**对话框**选项卡，然后单击 wxFileDialog 按钮。根据项目符号列表设置以下属性：

+   **消息**设置为`选择文件`

+   **通配符**设置为`*.bmp;*.jpg;*.png`

+   **变量名**设置为`MyPaintFileDialog`

1.  单击**管理**窗格中的**工具**，然后单击 wxStatusBar 项目。设置以下属性：

+   **变量名**设置为`StatusBarMain`

+   **字段**设置为`2`

+   在**字段 1**中，将**宽度**设置为`5`

+   在**字段 2**中，将**宽度**设置为`10`。

1.  接下来打开**菜单栏编辑器**，并根据下一个截图添加菜单项：

| 菜单项 | ID | 标签 | 加速键 | 帮助项目 |
| --- | --- | --- | --- | --- |
| **&文件** &#124; **&打开图像** | `idFileOpen` | `&打开图像` | `Ctrl + O` | `打开图像文件...` |
| **&查看** &#124; **放大** | `idViewZoomIn` | `放大` | `Ctrl++` | `放大 10%` |
| **&查看** &#124; **缩小** | `idViewZoomOut` | `缩小` | `Ctrl+-` | `缩小 10%` |

最终的菜单栏编辑器窗口应类似于以下截图：

![练习问题的解决方案](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_05_07.jpg)

1.  现在我们将向我们的应用程序添加一个 wxToolBar。如下截图所示，单击**工具**选项卡，然后单击 wxToolBar 按钮，将 wxToolBar 添加到我们的应用程序中。![练习问题的解决方案](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_05_08.jpg)

1.  双击 wxSmith 窗口中的 wxToolBar 图标，并添加以下项目。

| 标签 | 选项 | 位图 | 工具提示/帮助文本 |
| --- | --- | --- | --- |
| **打开图像...** | **正常** | 来自 wxArtProvider 的图像—wxART_FILE_OPEN | `打开图像文件` |
| – | 分隔符 | – | – |
| **放大** | **正常** | 项目文件夹中的`zoom_in.png`文件 | `放大 10%` |
| **缩小** | **正常** | 项目文件夹中的`zoom_out.png`文件 | `缩小 10%` |

最终的**ToolBar 编辑器**窗口将类似于以下截图。

![练习问题的解决方案](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_05_09.jpg)

我们已经完成了大多数 GUI 元素的添加。我们需要编写代码来完成我们的应用程序。在这之前，请注意 wxSmith 生成的代码保留在匹配的`//(*`和`//*)`块内。不要在此块内编写代码，因为 wxSmith 将在重新生成代码时删除此块内的任何自定义代码。

1.  在`MyPaintFrame.h`文件中的`MyPaintFrame`类声明内添加以下代码作为私有成员变量和函数。

```cpp
    wxImage* m_Image; //  To store loaded image
    double m_zoomFactor; // To store current zoom factor
    void RefreshPaintWindow(void); // To paint image
```

1.  在`MyPaintFrame()`构造函数内添加以下代码。我们将创建一个新的图像类并将其分配给`m_Image`变量。我们将使用`SetScrollbars()`和`ShowScrollbars()`函数来分配与滚动条相关的属性。我们将分配初始缩放因子为 100%，并使用`wxInitAllImageHandlers()`函数来初始化我们应用程序的图像处理引擎。最后，我们将使用`SetStatusText()`函数来设置状态栏文本。

```cpp
    m_Image = new wxImage(640, 480);
    MyPaintWindow->SetScrollbars(10, 10, 10, 10);
    MyPaintWindow->ShowScrollbars(wxSHOW_SB_ALWAYS, wxSHOW_SB_ALWAYS);
    m_zoomFactor = 1.0;
    wxInitAllImageHandlers();
    StatusBarMain->SetStatusText(_T("Ready!"), 0);
    wxString msg;
    msg.Printf(_T("%d %%"), static_cast<int>(m_zoomFactor*100));
    StatusBarMain->SetStatusText(msg, 1);
```

1.  单击资源树，导航到**&文件** | **&打开图像**菜单选项。转到**事件**选项卡（由**{}**标识），单击**EVT_MENU**旁边的下拉菜单，然后选择**---添加新处理程序---**菜单选项。输入`OnFileOpen`作为事件处理程序的名称。然后在`MyPaintFrame::OnFileOpen()`函数内输入以下代码：

```cpp
    int result;

    result = MyPaintFileDialog->ShowModal();
    if (result == wxID_OK) {
        m_Image->LoadFile(MyPaintFileDialog->GetPath());
        m_zoomFactor = 1.0;
        RefreshPaintWindow();
    }
```

1.  接下来，通过导航到**&View** | **放大**和**&View** | **缩小**菜单选项，将`OnViewZoomIn`和`OnViewZoomOut`事件处理程序函数添加到**放大**和**缩小**。请参考已完成的练习，了解要添加到每个处理程序的代码。

1.  从资源树中选择**MyPaintWindow**，单击**事件**选项卡。将`OnMyPaintWindowPaint`事件处理程序添加到**EVT_PAINT**，并粘贴以下代码。此代码在`wxScrolledWindow`上绘制加载的图像：

```cpp
    wxPaintDC paintDC(MyPaintWindow);
    wxRect rect;
    const wxBitmap bitmap(m_Image->Scale(m_Image->GetWidth() * m_zoomFactor,
                                         m_Image->GetHeight()* m_zoomFactor));

    rect.SetSize(m_Image->GetSize() * m_zoomFactor);
    MyPaintWindow->SetVirtualSize(m_Image->GetSize() * m_zoomFactor);

    if ( (rect.GetWidth() < MyPaintWindow->GetVirtualSize().GetWidth()) ||
        (rect.GetHeight() < MyPaintWindow->GetVirtualSize().GetHeight()) ) {
        rect = rect.CenterIn(MyPaintWindow->GetVirtualSize());
    }

    MyPaintWindow->DoPrepareDC(paintDC);
    paintDC.DrawBitmap(bitmap, rect.GetTopLeft());
```

1.  将`OnResize`事件处理程序添加到**MyPaintWindow**，并添加以下代码行：

```cpp
    RefreshPaintWindow();
```

1.  接下来，将`RefreshPaintWindow()`函数添加到`MyPaintFrame`类中，并在该函数内添加以下代码：

```cpp
    wxString msg;

    MyPaintWindow->ClearBackground();
    MyPaintWindow->Refresh();
    msg.Printf(_T("%d %%"), static_cast<int>(m_zoomFactor*100));
    StatusBarMain->SetStatusText(msg, 1);
```

1.  现在我们将为工具栏按钮添加代码。在资源树中选择**项目：打开图像...**项目，转到**事件**选项卡。将现有的`OnFileOpen`事件处理程序添加到**EVT_TOOL**。这将把现有的`OnFileOpen()`函数连接到这个工具栏按钮。因此，单击此工具栏按钮将模拟导航到**文件** | **打开**菜单选项。

1.  按照以前的步骤，将**放大**和**缩小**工具栏按钮连接到分别的`OnViewZoomIn`和`OnViewZoomOut`事件处理程序。

1.  我们的应用程序现在已经完成。按下*F9*键进行构建和运行。成功构建后，应用程序将运行，并且我们将看到应用程序窗口。现在打开任何图像文件，并在您新编写的应用程序中享受查看它。我们的应用程序现在将如下截图所示：![练习问题的解决方案](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_05_10.jpg)

# 总结

在这个练习中，我们计划并编写了自己的图像查看器应用程序。我们使用了 Code::Blocks 的 RAD 功能来编写我们的应用程序，并发现我们可以在短时间内从头开始编写一个应用程序。

我们结束了关于使用 C++和 Code::Blocks 进行应用程序开发的书籍。C++是一个广阔的主题。Code::Blocks 也有许多功能。不可能突出它们的每一个方面。我希望通过这本书，我已经能够阐明使用 C++和 Code::Blocks 进行应用程序开发。我也相信这本书也表明了使用 C++和 Code::Blocks 进行应用程序开发可以是有趣和令人兴奋的。


# 附录 A：附录

本附录侧重于 Code::Blocks 的功能集。除了代码编辑、管理和构建之外，Code::Blocks 还有许多其他功能。它可以被脚本化以扩展 Code::Blocks 的功能。它有插件可以生成代码文档。它还能够以不同格式导出代码，如富文本格式、便携式文档格式等。它还可以管理代码片段以简化开发过程。我们将在接下来的几节中讨论它们。

# 脚本化 Code::Blocks

Code::Blocks 使用**Squirrel**语言进行脚本编写。Squirrel 语言是一种高级、面向对象、轻量级的编程语言。Squirrel 语法类似于 C/C++编程语言。

Code::Blocks 通过脚本公开了大量 API。因此，Code::Blocks 的许多方面都可以通过脚本进行扩展。

有关脚本参考，请参考以下网址的文档：

+   **脚本命令**：[`wiki.codeblocks.org/index.php?title=Scripting_commands`](http://wiki.codeblocks.org/index.php?title=Scripting_commands)

+   **API 绑定**：[`wiki.codeblocks.org/index.php?title=Script_bindin`](http://wiki.codeblocks.org/index.php?title=Script_bindin)

# 文档生成

对于任何项目，代码文档都非常重要。它建立了编写的代码的概述，解释了其用法，并帮助开发人员理解代码。Code::Blocks 允许从 IDE 本身生成代码文档。

**Doxygen**是从带注释的 C++文件创建文档的标准工具。Code::Blocks 带有一个名为**DoxyBlocks**的插件，它与外部安装的 doxygen 工具创建了一个接口。

我们首先需要下载并安装 doxygen 工具。随后我们可以使用 DoxyBlocks 插件生成文档。执行以下步骤：

1.  从以下网址下载 doxygen - [`www.stack.nl/~dimitri/doxygen/download.html`](http://www.stack.nl/~dimitri/doxygen/download.html)。还要下载`doxygen-x.x.x-setup.exe`文件。双击该文件进行安装。

1.  我们需要将 DoxyBlocks 插件与 doxygen 工具连接起来。转到**DoxyBlocks** | **打开首选项...**菜单选项。将显示以下截图：![文档生成](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_06_01.jpg)

1.  单击**常规**选项卡。然后单击**Path To doxygen**选项旁边的**浏览**按钮，并设置路径为`C:\Program Files\doxygen\bin\doxygen.exe`。

1.  接下来创建一个新的 C++控制台项目，并将以下代码添加到向导生成的`main.cpp`文件中：

```cpp
class A {
    public:
        A() {};
        ~A() {};
        virtual int CallMe(int a) = 0;
};

class B : public A {
    public:
        B() {};
        ~B() {};
        int CallMe(int a) {
            return a;
        }
};

int main() {
    return 0;
}
```

1.  导航到**DoxyBlocks** | **提取文档**菜单选项，或按下*Ctrl* + *Alt* + *E*键组合。Code::Blocks 现在将在`doxygen`文件夹内生成项目文档。

1.  转到**DoxyBlocks** | **运行 HTML**菜单选项，或按下*Ctrl* + *Alt* + *H*键组合，以在 Web 浏览器中打开新创建的文档。

我们还可以添加有关函数、类等的详细描述，以创建详细的文档。

1.  将光标移动到`B::CallMe()`函数的开头，然后单击**DoxyBlocks | /** Block comment**菜单选项，或按下*Ctrl* + *Alt* + *B*键组合。Code::Blocks 将分析函数参数，并插入适合 doxygen 工具的默认注释块。调整注释块，我们的代码将类似于以下代码片段：

```cpp
        ~B() {};
        /** \brief Virtual function CallMe() is defined here
         *
         * \param a int
         * \return int
         *
         */
        int CallMe(int a) {
```

1.  按下*Ctrl* + *Alt* + *E*键组合重新生成文档，并使用*Ctrl* + *Alt* + *H*键组合在 Web 浏览器中打开它。`B::CallMe()`的文档将类似于以下截图：![文档生成](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_06_02.jpg)

我们还可以定制 DoxyBlocks 插件选项，以使用 doxygen 的高级功能。

# 代码片段管理

Code::Blocks 允许开发人员存储和检索经常使用的代码片段。在我们之前的示例中，我们使用了 DoxyBlocks 插件来注释适用于生成文档的块。但是我们也可以将空模板保存为代码片段，并在需要时重复使用它。

1.  转到**视图** | **代码片段**菜单选项，以显示**CodeSnippets**窗口。

1.  右键单击树中的`codesnippets`，然后选择**添加子类别**菜单选项。

1.  将其命名为`doxygen`。右键单击此**doxygen**类别，然后单击**添加片段**菜单选项。

1.  将`块注释`输入为**标签**，并将以下代码输入为片段文本：

```cpp
\** \brief
  *
  */
```

1.  单击**确定**按钮以保存此片段。**CodeSnippets**窗口将类似于以下屏幕截图：![管理代码片段](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_06_03.jpg)

1.  现在单击 Code::Blocks 编辑器窗口中的任何位置，右键单击此片段，然后选择**应用**菜单选项。此片段现在将粘贴到编辑器窗口中。

我们可以将代码、书签、文本文件添加为代码片段。代码片段不是特定于项目的，并且适用于所有项目。

# 项目使用外部工具

Code::Blocks 允许用户为任何项目使用外部工具。想象一下，我们想要使用 doxygen 工具来生成文档，而不使用 DoxyBlocks 插件。我们可以将 doxygen 添加为外部工具，然后根据需要使用它。

1.  转到**工具** | **配置工具…**菜单选项以添加新工具。将打开以下窗口：![项目使用外部工具](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_06_04.jpg)

1.  单击**添加**按钮以添加新工具。将打开以下窗口：![项目使用外部工具](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-appdev-cdblk/img/3415OS_06_05.jpg)

1.  输入以下详细信息：

+   将**名称**属性设置为`doxygen`。此值将用于在**工具**菜单下创建一个新的菜单项

+   将**可执行文件**属性设置为`C:\Program Files\doxygen\bin\doxygen.exe`

+   将**参数**属性设置为`${PROJECT_DIR}doxygen\doxyfile`

+   将**工作目录**属性设置为`${PROJECT_DIR}doxygen\`

1.  单击**确定**按钮关闭此窗口，然后单击**确定**按钮关闭**用户定义的工具**窗口。将在**工具**菜单选项下创建一个菜单项。

1.  导航到**工具** | **doxygen**菜单选项，doxygen 工具将在控制台窗口内启动。当完成后，按任意键关闭此控制台窗口。

我们可以以类似的方式使用任何其他工具。

# 以不同格式导出源代码

Code::Blocks 允许用户将源代码导出为 HTML、RTF、ODF 或 PDF 格式。执行以下步骤以以不同格式导出源代码：

1.  要将文件导出为 PDF 格式，请转到**文件** | **导出** | **作为 PDF…**菜单选项。

1.  在下一个对话框中输入文件名和路径。单击**保存**按钮继续。

1.  Code::Block 将提示确认在导出的源代码中包含行号。选择**是**或**否**选项，将导出特定的源文件。
