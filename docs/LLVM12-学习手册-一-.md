# LLVM12 学习手册（一）

> 原文：[`zh.annas-archive.org/md5/96A20F7680F39BBAA9B437BF26B65FE2`](https://zh.annas-archive.org/md5/96A20F7680F39BBAA9B437BF26B65FE2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

构建编译器是一项复杂而迷人的任务。LLVM 项目为您的编译器提供了可重用的组件。LLVM 核心库实现了世界一流的优化代码生成器，为所有流行的 CPU 架构转换了与源语言无关的中间表示的机器代码。许多编程语言的编译器已经利用了 LLVM 技术。

本书教会您如何实现自己的编译器，以及如何使用 LLVM 来实现。您将学习编译器的前端如何将源代码转换为抽象语法树，以及如何从中生成中间表示（IR）。通过向编译器添加优化管道，您可以将 IR 编译为高性能的机器代码。

LLVM 框架可以通过多种方式进行扩展，您将学习如何向 LLVM 添加新的 pass、新的机器指令，甚至是一个全新的后端。高级主题，如为不同的 CPU 架构进行编译，以及使用自己的插件和检查器扩展 clang 和 clang 静态分析器也会被涵盖。本书采用实用的方法，包含大量示例源代码，使得在自己的项目中应用所学知识变得容易。

# 本书适合对象

本书适用于编译器开发人员、爱好者和工程师，他们对 LLVM 还不熟悉，有兴趣了解 LLVM 框架。对于希望使用基于编译器的工具进行代码分析和改进的 C++软件工程师，以及希望更多了解 LLVM 基础知识的 LLVM 库的普通用户也很有用。理解本书所涵盖概念需要具备中级水平的 C++编程经验。

# 本书涵盖内容

[*第一章*]，*安装 LLVM*，解释了如何设置和使用开发环境。在本章结束时，您将已经编译了 LLVM 库，并学会了如何自定义构建过程。

[*第二章*]，*LLVM 源码之旅*，介绍了各种 LLVM 项目，并讨论了所有项目共享的常见目录布局。您将使用 LLVM 核心库创建您的第一个项目，并为不同的 CPU 架构进行编译。

[*第三章*]，*编译器的结构*，为您概述了编译器的组件。在本章结束时，您将已经实现了生成 LLVM IR 的第一个编译器。

[*第四章*]，*将源文件转换为抽象语法树*，详细教您如何实现编译器的前端。您将为一种小型编程语言创建自己的前端，最终构建一个抽象语法树。

[*第五章*]，*IR 生成基础*，向您展示如何从抽象语法树生成 LLVM IR。在本章结束时，您将已经实现了一个示例语言的编译器，生成汇编文本或目标代码文件作为结果。

[*第六章*]，*高级语言结构的 IR 生成*，说明了如何将高级编程语言中常见的源语言特性转换为 LLVM IR。您将学习如何翻译聚合数据类型，实现类继承和虚函数的各种选项，以及如何遵守系统的应用二进制接口。

[*第七章*]，*高级 IR 生成*，向您展示如何为源语言中的异常处理语句生成 LLVM IR。您还将学习如何为基于类型的别名分析添加元数据，以及如何向生成的 LLVM IR 添加调试信息，并扩展您的编译器生成的元数据。

*第八章*，*优化 IR*，解释了 LLVM pass 管理器。您将实现自己的 pass，作为 LLVM 的一部分和作为插件，并学习如何将新 pass 添加到优化 pass 管道中。

*第九章*，*指令选择*，展示了 LLVM 如何将 IR 降低为机器指令。您将学习 LLVM 中如何定义指令，并向 LLVM 添加一个新的机器指令，以便指令选择考虑新指令。

*第十章*，*JIT 编译*，讨论了如何使用 LLVM 实现**即时**（**JIT**）编译器。在本章结束时，您将以两种不同的方式为 LLVM IR 实现自己的 JIT 编译器。

*第十一章*，*使用 LLVM 工具进行调试*，探讨了 LLVM 的各种库和组件的细节，这有助于您识别应用程序中的错误。您将使用 sanitizer 来识别缓冲区溢出和其他错误。使用 libFuzzer 库，您将测试具有随机数据输入的函数，XRay 将帮助您找到性能瓶颈。您将使用 clang 静态分析器在源代码级别识别错误，并了解您可以向分析器添加自己的检查器。您还将学习如何使用自己的插件扩展 clang。

*第十二章*，*创建自己的后端*，解释了如何向 LLVM 添加新的后端。您将实现所有必要的类，并在本章结束时将 LLVM IR 编译为另一种 CPU 架构。

# 为了充分利用本书

*您需要一台运行 Linux、Windows、macOS 或 FreeBSD 的计算机，并为操作系统安装了开发工具链。请参阅所需工具的表格。所有工具都应该在您的 shell 的搜索路径中。*

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-llvm12/img/B15647_Preface_table_1.1.jpg)

要查看*第九章*中的 DAG 可视化，*指令选择*，您必须安装来自[`graphviz.org/`](https://graphviz.org/)的 Graphviz 软件。默认情况下，生成的图像是 PDF 格式，您需要一个 PDF 查看器来显示它。

要创建*第十一章*中的火焰图，*使用 LLVM 工具进行调试*，您需要从[`github.com/brendangregg/FlameGraph`](https://github.com/brendangregg/FlameGraph)安装脚本。要运行脚本，您还需要安装最新版本的 Perl，并且要查看图形，您需要一个能够显示 SVG 文件的 Web 浏览器，所有现代浏览器都可以。要查看同一章节中的 Chrome Trace Viewer 可视化，您需要安装 Chrome 浏览器。

**如果您使用本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库（链接在下一节中提供）访问代码。这样做将有助于避免与复制和粘贴代码相关的任何潜在错误。**

# 下载示例代码文件

您可以从 GitHub 上的[`github.com/PacktPublishing/Learn-LLVM-12`](https://github.com/PacktPublishing/Learn-LLVM-12)下载本书的示例代码文件。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。看一看吧！

# 代码实例

本书的代码实例视频可在[`bit.ly/3nllhED`](https://bit.ly/3nllhED)上观看

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在此处下载：[`static.packt-cdn.com/downloads/9781839213502_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781839213502_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。例如：“您可以在代码中观察到定义了一个量子电路操作，并定义了一个名为`numOnes`的变量。”

代码块设置如下：

```cpp
#include "llvm/IR/IRPrintingPasses.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/ToolOutputFile.h"
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cpp
  switch (Kind) {
// Many more cases
  case m88k:           return "m88k";
  }
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如：“从**管理**面板中选择**系统信息**。”

提示或重要说明

看起来像这样。


# 第一部分：使用 LLVM 进行编译器构建的基础

在本节中，您将学习如何自己编译 LLVM，以及如何根据自己的需求定制构建。您将了解 LLVM 项目的组织方式，并将创建您的第一个利用 LLVM 的项目。您还将学习如何为不同的 CPU 架构编译 LLVM 和使用 LLVM 进行应用程序的编译。最后，您将在创建一个小型编译器的过程中探索编译器的整体结构。

本节包括以下章节：

+   *第一章*, *安装 LLVM*

+   *第二章*, *浏览 LLVM 源码*

+   *第三章*, *编译器的结构*


# 第一章：安装 LLVM

要了解如何使用 LLVM，最好从源代码编译 LLVM 开始。LLVM 是一个综合项目，其 GitHub 存储库包含属于 LLVM 的所有项目的源代码。每个 LLVM 项目都在存储库的顶级目录中。除了克隆存储库外，您的系统还必须安装构建系统所需的所有工具。

在本章中，您将了解以下主题：

+   准备先决条件，将向您展示如何设置构建系统。

+   使用 CMake 构建，将介绍如何使用 CMake 和 Ninja 编译和安装 LLVM 核心库和 Clang。

+   定制构建过程，将讨论我们可以影响构建过程的各种方式。

# 准备先决条件

要使用 LLVM，您的开发系统必须运行常见的操作系统，如 Linux，FreeBSD，macOS 或 Windows。启用调试符号构建 LLVM 和 Clang 很容易需要数十 GB 的磁盘空间，因此请确保您的系统有足够的磁盘空间可用-在这种情况下，您应该有 30GB 的可用空间。

所需的磁盘空间严重依赖于所选择的构建选项。例如，仅在发布模式下构建 LLVM 核心库，同时仅针对一个平台，大约需要 2GB 的可用磁盘空间，这是所需的最低限度。为了减少编译时间，快速的 CPU（例如 2.5GHz 时钟速度的四核 CPU）和快速的 SSD 也会有所帮助。

甚至可以在树莓派等小型设备上构建 LLVM-只是需要花费很长时间。我在一台配有 Intel 四核 CPU，时钟速度为 2.7GHz，40GB RAM 和 2.5TB SSD 磁盘空间的笔记本电脑上开发了本书中的示例。这个系统非常适合手头的开发任务。

您的开发系统必须安装一些先决条件软件。让我们回顾一下这些软件包的最低要求版本。

注意

Linux 发行版通常包含可以使用的更新版本。版本号适用于 LLVM 12。LLVM 的较新版本可能需要这里提到的软件包的更新版本。

要从**GitHub**检出源代码，您需要**git** ([`git-scm.com/`](https://git-scm.com/))。没有特定版本的要求。GitHub 帮助页面建议至少使用版本 1.17.10。

LLVM 项目使用**CMake** ([`cmake.org/`](https://cmake.org/)) 作为构建文件生成器。至少需要版本 3.13.4。CMake 可以为各种构建系统生成构建文件。在本书中，使用**Ninja** ([`ninja-build.org/`](https://ninja-build.org/))，因为它快速且在所有平台上都可用。建议使用最新版本 1.9.0。

显然，您还需要一个**C/C++编译器**。LLVM 项目是用现代 C++编写的，基于 C++14 标准。需要符合的编译器和标准库。已知以下编译器与 LLVM 12 兼容：

+   gcc 5.1.0 或更高版本

+   Clang 3.5 或更高版本

+   Apple Clang 6.0 或更高版本

+   Visual Studio 2017 或更高版本

请注意，随着 LLVM 项目的进一步发展，编译器的要求很可能会发生变化。在撰写本文时，有讨论要使用 C++17 并放弃对 Visual Studio 2017 的支持。一般来说，您应该使用系统中可用的最新编译器版本。

**Python** ([`python.org/`](https://python.org/)) 用于生成构建文件和运行测试套件。它应至少是 3.6 版本。

尽管本书未涉及，但您可能有理由需要使用 Make 而不是 Ninja。在这种情况下，您需要在每个命令中使用`make`和本书中描述的场景。

要安装先决条件软件，最简单的方法是使用操作系统的软件包管理器。在接下来的部分中，将显示安装最受欢迎操作系统的软件所需输入的命令。

## Ubuntu

Ubuntu 20.04 使用 APT 软件包管理器。大多数基本实用程序已经安装好了；只有开发工具缺失。要一次安装所有软件包，请键入以下内容：

```cpp
$ sudo apt install –y gcc g++ git cmake ninja-build
```

## Fedora 和 RedHat

Fedora 33 和 RedHat Enterprise Linux 8.3 的软件包管理器称为**DNF**。与 Ubuntu 一样，大多数基本实用程序已经安装好了。要一次安装所有软件包，请键入以下内容：

```cpp
$ sudo dnf install –y gcc gcc-c++ git cmake ninja-build
```

## FreeBSD

在 FreeBSD 12 或更高版本上，必须使用 PKG 软件包管理器。FreeBSD 与基于 Linux 的系统不同，它更喜欢使用 Clang 编译器。要一次安装所有软件包，请键入以下内容：

```cpp
$ sudo pkg install –y clang git cmake ninja
```

## OS X

在 OS X 上进行开发时，最好从 Apple 商店安装**Xcode**。虽然本书中没有使用 XCode IDE，但它带有所需的 C/C++编译器和支持工具。要安装其他工具，可以使用 Homebrew 软件包管理器（https://brew.sh/）。要一次安装所有软件包，请键入以下内容：

```cpp
$ brew install git cmake ninja
```

## Windows

与 OS X 一样，Windows 没有软件包管理器。安装所有软件的最简单方法是使用**Chocolately**（[`chocolatey.org/`](https://chocolatey.org/)）软件包管理器。要一次安装所有软件包，请键入以下内容：

```cpp
$ choco install visualstudio2019buildtools cmake ninja git\
  gzip bzip2 gnuwin32-coreutils.install
```

请注意，这只安装了来自`package visualstudio2019community`而不是`visualstudio2019buildtools`的构建工具。Visual Studio 2019 安装的一部分是 x64 Native Tools Command Prompt for VS 2019。使用此命令提示时，编译器会自动添加到搜索路径中。

## 配置 Git

LLVM 项目使用 Git 进行版本控制。如果您以前没有使用过 Git，则应该在继续之前对 Git 进行一些基本配置；也就是说，设置用户名和电子邮件地址。如果您提交更改，这两个信息都会被使用。在以下命令中，将`Jane`替换为您的姓名，`jane@email.org`替换为您的电子邮件：

```cpp
$ git config --global user.email "jane@email.org"
$ git config --global user.name "Jane"
```

默认情况下，Git 使用**vi**编辑器进行提交消息。如果您希望使用其他编辑器，则可以以类似的方式更改配置。要使用**nano**编辑器，请键入以下内容：

```cpp
$ git config --global core.editor nano
```

有关 git 的更多信息，请参阅 Packt Publishing 的*Git Version Control Cookbook - Second Edition*（[`www.packtpub.com/product/git-version-control-cookbook/9781782168454`](https://www.packtpub.com/product/git-version-control-cookbook/9781782168454)）。

# 使用 CMake 构建

准备好构建工具后，您现在可以从 GitHub 检出所有 LLVM 项目。执行此操作的命令在所有平台上基本相同。但是，在 Windows 上，建议关闭行结束的自动翻译。

让我们分三部分回顾这个过程：克隆存储库，创建构建目录和生成构建系统文件。

## 克隆存储库

在所有非 Windows 平台上，键入以下命令以克隆存储库：

```cpp
$ git clone https://github.com/llvm/llvm-project.git
```

在 Windows 上，您必须添加选项以禁用自动翻译行结束。在这里，键入以下内容：

```cpp
$ git clone --config core.autocrlf=false\  https://github.com/llvm/llvm-project.git
```

这个`git`命令将最新的源代码从 GitHub 克隆到名为`llvm-project`的本地目录中。现在，使用以下命令将当前目录更改为新的`llvm-project`目录：

```cpp
$ cd llvm-project
```

在目录中包含了所有 LLVM 项目，每个项目都在自己的目录中。值得注意的是，LLVM 核心库位于`llvm`子目录中。LLVM 项目使用分支进行后续发布的开发（“release/12.x”）和标记（“llvmorg-12.0.0”）来标记特定的发布。使用前面的`clone`命令，您可以获得当前的开发状态。本书使用 LLVM 12。要检出 LLVM 12 的第一个发布版本，请键入以下内容：

```cpp
$ git checkout -b llvmorg-12.0.0
```

有了这个，你已经克隆了整个存储库并检出了一个标签。这是最灵活的方法。

Git 还允许你只克隆一个分支或一个标签（包括历史记录）。使用`git clone --branch llvmorg-12.0.0 https://github.com/llvm/llvm-project`，你检出了与之前相同的标签，但只克隆了该标签的历史记录。通过额外的`--depth=1`选项，你可以防止克隆历史记录。这样可以节省时间和空间，但显然会限制你在本地可以做什么。

下一步是创建一个构建目录。

## 创建一个构建目录

与许多其他项目不同，LLVM 不支持内联构建，需要一个单独的`build`目录。这可以很容易地在`llvm-project`目录内创建。使用以下命令切换到此目录：

```cpp
$ cd llvm-project
```

然后，为简单起见，创建一个名为`build`的构建目录。在这里，Unix 和 Windows 系统的命令不同。在类 Unix 系统上，你应该使用以下命令：

```cpp
$ mkdir build
```

在 Windows 上，你应该使用以下命令：

```cpp
$ md build
```

然后，切换到`build`目录：

```cpp
$ cd build
```

现在，你已经准备好在这个目录中使用 CMake 工具创建构建系统文件。

## 生成构建系统文件

要生成使用 Ninja 编译 LLVM 和 Clang 的构建系统文件，请运行以下命令：

```cpp
$ cmake –G Ninja -DLLVM_ENABLE_PROJECTS=clang ../llvm
```

提示

在 Windows 上，反斜杠字符`\`是目录名称分隔符。在 Windows 上，CMake 会自动将 Unix 分隔符`/`转换为 Windows 分隔符。

`-G`选项告诉 CMake 为哪个系统生成构建文件。最常用的选项如下：

+   `Ninja`：对于 Ninja 构建系统

+   `Unix Makefiles`：对于 GNU Make

+   `Visual Studio 15 VS2017`和`Visual Studio 16 VS2019`：对于 Visual Studio 和 MS Build

+   `Xcode`：对于 XCode 项目

生成过程可以通过使用`-D`选项设置各种变量来进行影响。通常，它们以`CMAKE_`（如果由 CMake 定义）或`LLVM_`（如果由 LLVM 定义）为前缀。通过设置`LLVM_ENABLE_PROJECTS=clang`变量，CMake 会生成 Clang 的构建文件，除了 LLVM。命令的最后一部分告诉 CMake 在哪里找到 LLVM 核心库源代码。关于这一点，我们将在下一节详细介绍。

一旦构建文件生成，LLVM 和 Clang 可以使用以下命令编译：

```cpp
$ ninja
```

根据硬件资源的不同，这个命令需要花费 15 分钟（具有大量 CPU 核心和内存以及快速存储的服务器）到几个小时（双核 Windows 笔记本，内存有限）不等。默认情况下，Ninja 利用所有可用的 CPU 核心。这对于编译速度很好，但可能会阻止其他任务运行。例如，在基于 Windows 的笔记本上，几乎不可能在 Ninja 运行时上网冲浪。幸运的是，你可以使用`-j`选项限制资源使用。

假设你有四个 CPU 核心可用，而 Ninja 只应该使用两个（因为你有并行任务要运行）。在这里，你应该使用以下命令进行编译：

```cpp
$ ninja –j2
```

一旦编译完成，最佳实践是运行测试套件，以检查一切是否按预期工作：

```cpp
$ ninja check-all
```

这个命令的运行时间因可用的硬件资源而变化很大。Ninja `check-all`目标运行所有测试用例。为包含测试用例的每个目录生成目标。使用`check-llvm`而不是`check-all`运行 LLVM 测试但不运行 Clang 测试；`check-llvm-codegen`只运行 LLVM 的`CodeGen`目录中的测试（即`llvm/test/CodeGen`目录）。

你也可以进行快速手动检查。你将使用的 LLVM 应用程序之一是`-version`选项，它显示它的 LLVM 版本，它的主机 CPU 以及所有支持的架构：

```cpp
$ bin/llc -version
```

如果您在编译 LLVM 时遇到问题，应该查阅*Getting Started with the LLVM System*文档的*Common Problems*部分（[`llvm.org/docs/GettingStarted.html#common-problems`](https://llvm.org/docs/GettingStarted.html#common-problems)）以解决常见问题。

最后，安装二进制文件：

```cpp
$ ninja install
```

在类 Unix 系统上，安装目录为`/usr/local`。在 Windows 上，使用`C:\Program Files\LLVM`。当然可以更改。下一节将解释如何更改。

# 自定义构建过程

CMake 系统使用`CMakeLists.txt`文件中的项目描述。顶层文件位于`llvm`目录中；即`llvm/CMakeLists.txt`。其他目录也包含`CMakeLists.txt`文件，在构建文件生成期间递归包含。

根据项目描述中提供的信息，CMake 检查已安装的编译器，检测库和符号，并创建构建系统文件，例如`build.ninja`或`Makefile`（取决于选择的生成器）。还可以定义可重用的模块，例如检测 LLVM 是否已安装的函数。这些脚本放置在特殊的`cmake`目录（`llvm/cmake`），在生成过程中会自动搜索。

构建过程可以通过定义 CMake 变量进行自定义。使用`-D`命令行选项设置变量的值。这些变量在 CMake 脚本中使用。CMake 本身定义的变量几乎总是以`CMAKE_`为前缀，并且这些变量可以在所有项目中使用。LLVM 定义的变量以`LLVM_`为前缀，但只能在项目定义中包括 LLVM 使用时使用。

## CMake 定义的变量

一些变量使用环境变量的值进行初始化。最显著的是`CC`和`CXX`，它们定义了用于构建的 C 和 C++编译器。CMake 会尝试自动定位 C 和 C++编译器，使用当前的 shell 搜索路径。它会选择找到的第一个编译器。如果安装了多个编译器，例如 gcc 和 Clang 或不同版本的 Clang，则这可能不是您要用于构建 LLVM 的编译器。

假设您想将`clang9`用作 C 编译器，将`clang++9`用作 C++编译器。在 Unix shell 中，可以按以下方式调用 CMake：

```cpp
$ CC=clang9 CXX=clang++9 cmake ../llvm
```

这将设置`cmake`调用时环境变量的值。如果需要，您可以为编译器可执行文件指定绝对路径。

`CC`是`CMAKE_C_COMPILER` CMake 变量的默认值，而`CXX`是`CMAKE_CXX_COMPILER` CMake 变量的默认值。您可以直接设置 CMake 变量，而不是使用环境变量。这相当于前面的调用：

```cpp
$ cmake –DCMAKE_C_COMPILER=clang9\
  -DCMAKE_CXX_COMPILER=clang++9 ../llvm
```

CMake 定义的其他有用变量如下：

+   `CMAKE_INSTALL_PREFIX`：安装期间添加到每个路径前面的路径前缀。Unix 上默认为`/usr/local`，Windows 上为`C:\Program Files\<Project>`。要在`/opt/llvm`目录中安装 LLVM，必须指定`-DCMAKE_INSTALL_PREFIX=/opt/llvm`。二进制文件将被复制到`/opt/llvm/bin`，库文件将被复制到`/opt/llvm/lib`，依此类推。

+   `CMAKE_BUILD_TYPE`：不同类型的构建需要不同的设置。例如，调试构建需要指定生成调试符号的选项，并且通常链接到系统库的调试版本。相比之下，发布构建使用优化标志，并链接到库的生产版本。此变量仅用于只能处理一种构建类型的构建系统，例如 Ninja 或 Make。对于 IDE 构建系统，会生成所有变体，您必须使用 IDE 的机制在构建类型之间切换。一些可能的值如下：

`DEBUG`：带有调试符号的构建

`RELEASE`：用于速度优化的构建

`RELWITHDEBINFO`：带有调试符号的发布版本

`MINSIZEREL`：针对大小进行优化的构建

默认的构建类型是`DEBUG`。要为发布构建生成构建文件，必须指定`-DCMAKE_BUILD_TYPE=RELEASE`。

+   `CMAKE_C_FLAGS`和`CMAKE_CXX_FLAGS`：这些是在编译 C 和 C++源文件时使用的额外标志。初始值取自`CFLAGS`和`CXXFLAGS`环境变量，可以用作替代。

+   `CMAKE_MODULE_PATH`：指定要在 CMake 模块中搜索的附加目录。指定的目录将在默认目录之前搜索。该值是一个用分号分隔的目录列表。

+   `PYTHON_EXECUTABLE`：如果找不到 Python 解释器，或者如果安装了多个版本并选择了错误的版本，则可以将此变量设置为 Python 二进制文件的路径。只有在包含 CMake 的 Python 模块时，此变量才会生效（这是 LLVM 的情况）。

CMake 为变量提供了内置帮助。`--help-variable var`选项会打印`var`变量的帮助信息。例如，您可以输入以下内容以获取`CMAKE_BUILD_TYPE`的帮助：

```cpp
$ cmake --help-variable CMAKE_BUILD_TYPE
```

您还可以使用以下命令列出所有变量：

```cpp
$ cmake --help-variablelist
```

此列表非常长。您可能希望将输出导入`more`或类似的程序。

## LLVM 定义的变量

LLVM 定义的变量与 CMake 定义的变量的工作方式相同，只是没有内置帮助。最有用的变量如下：

+   `LLVM_TARGETS_TO_BUILD`：LLVM 支持不同 CPU 架构的代码生成。默认情况下，会构建所有这些目标。使用此变量指定要构建的目标列表，用分号分隔。当前的目标有`AArch64`、`AMDGPU`、`ARM`、`BPF`、`Hexagon`、`Lanai`、`Mips`、`MSP430`、`NVPTX`、`PowerPC`、`RISCV`、`Sparc`、`SystemZ`、`WebAssembly`、`X86`和`XCore`。`all`可以用作所有目标的简写。名称区分大小写。要仅启用 PowerPC 和 System Z 目标，必须指定`-DLLVM_TARGETS_TO_BUILD="PowerPC;SystemZ"`。

+   `LLVM_ENABLE_PROJECTS`：这是要构建的项目列表，用分号分隔。项目的源代码必须与`llvm`目录处于同一级别（并排布局）。当前列表包括`clang`、`clang-tools-extra`、`compiler-rt`、`debuginfo-tests`、`lib`、`libclc`、`libcxx`、`libcxxabi`、`libunwind`、`lld`、`lldb`、`llgo`、`mlir`、`openmp`、`parallel-libs`、`polly`和`pstl`。`all`可以用作此列表中所有项目的简写。要与 LLVM 一起构建 Clang 和 llgo，必须指定`-DLLVM_ENABLE_PROJECT="clang;llgo"`。

+   `LLVM_ENABLE_ASSERTIONS`：如果设置为`ON`，则启用断言检查。这些检查有助于发现错误，在开发过程中非常有用。对于`DEBUG`构建，默认值为`ON`，否则为`OFF`。要打开断言检查（例如，对于`RELEASE`构建），必须指定`–DLLVM_ENABLE_ASSERTIONS=ON`。

+   `LLVM_ENABLE_EXPENSIVE_CHECKS`：这将启用一些可能会显著减慢编译速度或消耗大量内存的昂贵检查。默认值为`OFF`。要打开这些检查，必须指定`-DLLVM_ENABLE_EXPENSIVE_CHECKS=ON`。

+   `LLVM_APPEND_VC_REV`：LLVM 工具（如`llc`）显示它们所基于的 LLVM 版本，以及其他信息（如果提供了`--version`命令行选项）。此版本信息基于`LLVM_REVISION` C 宏。默认情况下，版本信息不仅包括 LLVM 版本，还包括最新提交的 Git 哈希。如果您正在跟踪主分支的开发，这很方便，因为它清楚地指出了工具所基于的 Git 提交。如果不需要这个信息，则可以使用`–DLLVM_APPEND_VC_REV=OFF`关闭。

+   `LLVM_ENABLE_THREADS`：如果检测到线程库（通常是 pthread 库），LLVM 会自动包含线程支持。此外，在这种情况下，LLVM 假定编译器支持`-DLLVM_ENABLE_THREADS=OFF`。

+   `LLVM_ENABLE_EH`：LLVM 项目不使用 C++异常处理，因此默认情况下关闭异常支持。此设置可能与您的项目链接的其他库不兼容。如果需要，可以通过指定`–DLLVM_ENABLE_EH=ON`来启用异常支持。

+   `LLVM_ENABLE_RTTI`：LVM 使用了一个轻量级的、自建的运行时类型信息系统。默认情况下，生成 C++ RTTI 是关闭的。与异常处理支持一样，这可能与其他库不兼容。要打开 C++ RTTI 的生成，必须指定`–DLLVM_ENABLE_RTTI=ON`。

+   `LLVM_ENABLE_WARNINGS`：编译 LLVM 应尽可能不生成警告消息。因此，默认情况下打印警告消息的选项是打开的。要关闭它，必须指定`–DLLVM_ENABLE_WARNINGS=OFF`。

+   `LLVM_ENABLE_PEDANTIC`：LLVM 源代码应符合 C/C++语言标准；因此，默认情况下启用源代码的严格检查。如果可能，还会禁用特定于编译器的扩展。要取消此设置，必须指定`–DLLVM_ENABLE_PEDANTIC=OFF`。

+   `LLVM_ENABLE_WERROR`：如果设置为`ON`，则所有警告都被视为错误-一旦发现警告，编译就会中止。它有助于找到源代码中所有剩余的警告。默认情况下，它是关闭的。要打开它，必须指定`–DLLVM_ENABLE_WERROR=ON`。

+   `LLVM_OPTIMIZED_TABLEGEN`：通常，tablegen 工具与 LLVM 的其他部分使用相同的选项构建。同时，tablegen 用于生成代码生成器的大部分代码。因此，在调试构建中，tablegen 的速度要慢得多，从而显著增加了编译时间。如果将此选项设置为`ON`，则即使在调试构建中，tablegen 也将使用优化进行编译，可能会减少编译时间。默认为`OFF`。要打开它，必须指定`–DLLVM_OPTIMIZED_TABLEGEN=ON`。

+   `LLVM_USE_SPLIT_DWARF`：如果构建编译器是 gcc 或 Clang，则打开此选项将指示编译器将 DWARF 调试信息生成到单独的文件中。对象文件的减小尺寸显著减少了调试构建的链接时间。默认为`OFF`。要打开它，必须指定`-LLVM_USE_SPLIT_DWARF=ON`。

LLVM 定义了许多更多的 CMake 变量。您可以在 LLVM CMake 文档中找到完整的列表([`releases.llvm.org/12.0.0/docs/CMake.html#llvm-specific-variables`](https://releases.llvm.org/12.0.0/docs/CMake.html#llvm-specific-variables))。前面的列表只包含您可能需要的变量。

# 总结

在本章中，您准备好了开发机器来编译 LLVM。您克隆了 LLVM GitHub 存储库，并编译了自己的 LLVM 和 Clang 版本。构建过程可以使用 CMake 变量进行自定义。您还了解了有用的变量以及如何更改它们。掌握了这些知识，您可以根据自己的需求调整 LLVM。

在下一章中，我们将更仔细地查看 LLVM 单一存储库的内容。您将了解其中包含哪些项目以及这些项目的结构。然后，您将使用这些信息来使用 LLVM 库创建自己的项目。最后，您将学习如何为不同的 CPU 架构编译 LLVM。


# 第二章：LLVM 源代码导览

LLVM 单一存储库包含`llvm-project`根目录下的所有项目。所有项目都遵循统一的源代码布局。要有效地使用 LLVM，了解可用内容以及其位置是很重要的。在本章中，您将了解以下内容：

+   LLVM 单一存储库的内容，涵盖了最重要的顶级项目

+   LLVM 项目的布局，展示了所有项目使用的通用源代码布局

+   如何使用 LLVM 库创建自己的项目，涵盖了在自己的项目中使用 LLVM 的所有方式

+   如何针对不同的 CPU 架构，展示交叉编译到另一个系统所需的步骤

# 技术要求

本章的代码文件可在[`github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter02/tinylang`](https://github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter02/tinylang)找到

您可以在[`bit.ly/3nllhED`](https://bit.ly/3nllhED)找到代码演示视频

# LLVM 单一存储库的内容

在*第一章*中，*安装 LLVM*，您克隆了 LLVM 单一存储库。该存储库包含所有 LLVM 顶级项目。它们可以分为以下几类：

+   LLVM 核心库和附加内容

+   编译器和工具

+   运行时库

在接下来的章节中，我们将更详细地了解这些组。

## LLVM 核心库和附加内容

LLVM 核心库位于`llvm`目录中。该项目提供了一组为知名 CPU 进行优化和代码生成的库。它还提供了基于这些库的工具。LLVM 静态编译器`llc`接受 LLVM `llvm-objdump`和`llvm-dwarfdump`文件，让您检查目标文件，以及像`llvm-ar`这样的工具让您从一组目标文件创建存档文件。它还包括帮助开发 LLVM 本身的工具。例如，`bugpoint`工具有助于找到 LLVM 内部崩溃的最小测试用例。`llvm-mc`是机器码播放器：该工具汇编和反汇编机器指令，并输出编码，这在添加新指令时非常有帮助。

LLVM 核心库是用 C++编写的。此外，还提供了 C 接口和 Go、Ocaml 和 Python 的绑定。

位于`polly`目录中的 Polly 项目为 LLVM 增加了另一组优化。它基于一种称为**多面体模型**的数学表示。采用这种方法，可以进行诸如为缓存局部性优化的循环等复杂优化。

`mlir`目录。

## 编译器和工具

LLVM 项目中包含一个名为 clang（[`clang.llvm.org/`](http://clang.llvm.org/)）的完整的 C/C++/Objective-C/Object-C++编译器。源代码位于`clang`目录中。它提供了一组库，用于从 C、C++、Objective-C 和 Objective-C++源文件中进行词法分析、语法分析、语义分析和生成 LLVM IR。小工具`clang`是基于这些库的编译器驱动程序。另一个有用的工具是`clang-format`，它可以根据用户提供的规则格式化 C/C++源文件和源代码片段。

Clang 旨在与 GCC（GNU C/C++编译器）和 CL（Microsoft C/C++编译器）兼容。

`clang-tools-extra`项目提供了 C/C++的其他工具，位于同名目录中。其中最值得注意的是`clang-tidy`，它是用于 C/C++的 Lint 风格检查器。`clang-tidy`使用 clang 库解析源代码并进行静态分析。该工具可以捕获比编译器更多的潜在错误，但运行时开销更大。

Llgo 是 Go 编程语言的编译器，位于`llgo`目录中。它是用 Go 编写的，并使用 LLVM 核心库的 Go 绑定与 LLVM 进行接口。Llgo 旨在与参考编译器（https://golang.org/）兼容，但目前唯一支持的目标是 64 位 x86 Linux。该项目似乎没有维护，并可能在将来被移除。

编译器创建的目标文件必须与运行时库链接在一起形成可执行文件。这是`lld`（[`lld.llvm.org/`](http://lld.llvm.org/)）的工作，LLVM 链接器位于`lld`目录中。该链接器支持 ELF、COFF、Mach-O 和 WebAssembly 格式。

没有调试器的编译器工具集是不完整的！LLVM 调试器称为`lldb`（[`lldb.llvm.org/`](http://lldb.llvm.org/)），位于同名目录中。其界面类似于 GDB，GNU 调试器，并且该工具可以直接支持 C、C++和 Objective-C。调试器是可扩展的，因此可以轻松添加对其他编程语言的支持。

## 运行时库

除了编译器，完整的编程语言支持还需要运行时库。所有列出的项目都位于顶级目录中，与同名目录中的目录相同：

+   `compiler-rt`项目提供了与编程语言无关的支持库。它包括通用函数，例如 32 位 i386 的 64 位除法，各种消毒剂，模糊库和分析库。

+   `libunwind`库基于 DWARF 标准提供了用于堆栈展开的辅助函数。这通常用于实现诸如 C++之类的语言的异常处理。该库是用 C 编写的，函数与特定的异常处理模型无关。

+   `libcxxabi`库在`libunwind`的基础上实现了 C++异常处理，并为其提供了标准的 C++函数。

+   最后，`libcxx`是 C++标准库的实现，包括 iostreams 和 STL。此外，`pstl`项目提供了 STL 算法的并行版本。

+   `libclc`是 OpenCL 的运行时库。OpenCL 是用于异构并行计算的标准，有助于将计算任务移动到图形卡上。

+   `libc`旨在提供完整的 C 库。该项目仍处于早期阶段。

+   `openmp`项目提供了对 OpenMP API 的支持。OpenMP 有助于多线程编程，并且可以根据源代码中的注释来并行化循环。

尽管这是一个很长的项目列表，但好消息是所有项目的结构都类似。我们将在下一节中查看通用目录布局。

# LLVM 项目的布局

所有 LLVM 项目都遵循相同的目录布局理念。为了理解这个理念，让我们将 LLVM 与**GCC**，**GNU 编译器集**进行比较。几十年来，GCC 为几乎您能想象到的每个系统提供了成熟的编译器。但是，除了编译器，没有利用代码的工具。原因是它不是为重用而设计的。这与 LLVM 不同。

每个功能都有明确定义的 API，并放在自己的库中。clang 项目（除其他外）有一个库，用于将 C/C++源文件词法分析为标记流。解析器库将此标记流转换为抽象语法树（也由库支持）。语义分析、代码生成甚至编译器驱动程序都作为库提供。著名的`clang`工具只是针对这些库链接的一个小应用程序。

优势是显而易见的：当您想要构建一个需要 C++文件的**抽象语法树**（**AST**）的工具时，您可以重用这些库的功能来构建 AST。不需要语义分析和代码生成，也不需要链接到这些库。这个原则被所有 LLVM 项目遵循，包括核心库！

每个项目都有类似的组织结构。因为 CMake 用于构建文件生成，每个项目都有一个`CMakeLists.txt`文件，描述了项目的构建过程。如果需要额外的 CMake 模块或支持文件，则它们存储在`cmake`子目录中，模块放置在`cmake/modules`中。

库和工具大多是用 C++编写的。源文件放在`lib`目录下，头文件放在`include`目录下。因为一个项目通常由多个库组成，在`lib`目录中为每个库都有一个目录。如果需要，这个过程会重复。例如，在`llvm/lib`目录中有`Target`目录，其中包含特定目标的降低代码。除了一些源文件外，每个目标都有一个子目录，这些子目录再次编译成库。每个目录都有一个`CMakeLists.txt`文件，描述了如何构建库以及哪些子目录还包含源代码。

`include`目录有一个额外的级别。为了使包含文件的名称唯一，路径名包括项目名称，这是`include`下的第一个子目录。只有在这个文件夹中，才会重复来自`lib`目录的结构。

应用程序的源代码位于`tools`和`utils`目录中。`utils`目录中是在编译或测试期间使用的内部应用程序。它们通常不是用户安装的一部分。`tools`目录包含面向最终用户的应用程序。在这两个目录中，每个应用程序都有自己的子目录。与`lib`目录一样，每个包含源代码的子目录都有一个`CMakeLists.txt`文件。

正确的代码生成对于编译器是*必不可少*的。这只能通过一个良好的测试套件来实现。`unittest`目录包含使用*Google Test*框架的单元测试。这主要用于单个函数和无法以其他方式进行测试的独立功能。`test`目录中是 LIT 测试。这些测试使用`llvm-lit`实用程序来执行测试。`llvm-lit`扫描文件以执行 shell 命令。文件包含用作测试输入的源代码，例如 LLVM IR。文件中嵌入了由`llvm-lit`执行的编译命令。然后验证此步骤的输出，通常借助`FileCheck`实用程序的帮助。这个实用程序从一个文件中读取检查语句，并将它们与另一个文件进行匹配。LIT 测试本身位于`test`目录下的子目录中，大致遵循`lib`目录的结构。

文档（通常作为`docs`目录。如果项目提供示例，则它们在`examples`目录中。

根据项目的需求，也可以有其他目录。最值得注意的是，一些提供运行时库的项目将源代码放在`src`目录中，并使用`lib`目录进行库导出定义。compiler-rt 和 libclc 项目包含与体系结构相关的代码。这总是放在以目标体系结构命名的子目录中（例如`i386`或`ptx`）。

总之，提供示例库并具有驱动程序工具的项目的一般布局如下：

![图 2.1-一般项目目录布局](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-llvm12/img/B15647_02_01.jpg)

图 2.1-一般项目目录布局

我们自己的项目也将遵循这种组织结构。

# 使用 LLVM 库创建您自己的项目

根据前一节的信息，现在可以使用 LLVM 库创建自己的项目。以下部分介绍了一个名为`tinylang`的小语言。在这里定义了这样一个项目的结构。尽管本节中的工具只是一个**Hello, world**应用程序，但其结构具有实现真实编译器所需的所有部分。

## 创建目录结构

第一个问题是是否应该将`tinylang`项目与 LLVM 一起构建（如 clang），还是应该是一个独立的项目，只是使用 LLVM 库。在前一种情况下，还需要决定在哪里创建项目。

首先假设`tinylang`应与 LLVM 一起构建。有不同的选项可供放置项目。第一个解决方案是在`llvm-projects`目录内创建项目的子目录。此目录中的所有项目都将作为构建 LLVM 的一部分进行捕获和构建。在创建并排项目布局之前，这是构建例如 clang 的标准方式。

第二个选项是将`tinylang`项目放在顶级目录中。因为它不是官方的 LLVM 项目，所以 CMake 脚本不知道它。在运行`cmake`时，您需要指定`–DLLVM_ENABLE_PROJECTS=tinylang`以将项目包含在构建中。

第三个选项是将项目目录放在`llvm-project`目录之外的其他位置。当然，您需要告诉 CMake 这个位置。例如，如果位置是`/src/tinylang`，则需要指定`–DLLVM_ENABLE_PROJECTS=tinylang –DLLVM_EXTERNAL_TINYLANG_SOURCE_DIR=/src/tinylang`。

如果要将项目构建为独立项目，则需要找到 LLVM 库。这是在稍后讨论的`CMakeLists.txt`文件中完成的。

在了解可能的选项之后，哪一个是最好的？将您的项目作为 LLVM 源树的一部分是有点不灵活的，因为大小。只要您不打算将项目添加到顶级项目列表中，我建议使用单独的目录。您可以在 GitHub 或类似服务上维护您的项目，而不必担心如何与 LLVM 项目同步。并且如前所示，您仍然可以与其他 LLVM 项目一起构建。

让我们创建一个非常简单的库和应用程序的项目。第一步是创建目录布局。选择一个对您方便的位置。在接下来的步骤中，我假设它与您克隆`llvm-project`目录的相同目录中。使用`mkdir`（Unix）或`md`（Windows）创建以下目录：

![图 2.2- 项目所需的目录](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-llvm12/img/B15647_02_02.jpg)

图 2.2- 项目所需的目录

接下来，我们将在这些目录中放置构建描述和源文件。

## 添加 CMake 文件

您应该从上一节中认识到基本结构。在`tinylang`目录中，创建一个名为`CMakeLists.txt`的文件，并执行以下步骤：

1.  文件开始时调用`cmake_minimum_required()`来声明所需的 CMake 的最小版本。这与*第一章*中的版本相同，*安装 LLVM*：

```cpp
Cmake_minimum_required(VERSION 3.13.4)
```

1.  下一个语句是`if()`。如果条件为真，则将构建项目，并且需要一些额外的设置。条件使用两个变量，`CMAKE_SOURCE_DIR`和`CMAKE_CURRENT_SOURCE_DIR`。`CMAKE_SOURCE_DIR`变量是在`cmake`命令行上给出的顶层源目录。正如我们在关于目录布局的讨论中看到的，每个具有源文件的目录都有一个`CMakeLists.txt`文件。CMake 当前处理的`CMakeLists.txt`文件的目录记录在`CMAKE_CURRENT_SOURCE_DIR`变量中。如果两个变量具有相同的字符串值，则将构建项目。否则，`CMAKE_SOURCE_DIR`将是`llvm`目录：

```cpp
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
```

独立设置很简单。每个 CMake 项目都需要一个名称。在这里，我们将其设置为`Tinylang`：

```cpp
  project(Tinylang)
```

1.  LLVM 软件包已被搜索，找到的 LLVM 目录被添加到 CMake 模块路径中：

```cpp
  find_package(LLVM REQUIRED HINTS     "${LLVM_CMAKE_PATH}")
  list(APPEND CMAKE_MODULE_PATH ${LLVM_DIR})
```

1.  然后，包含了 LLVM 提供的另外三个 CMake 模块。第一个仅在使用 Visual Studio 作为构建编译器时需要，并设置正确的运行时库以进行链接。另外两个模块添加了 LLVM 使用的宏，并根据提供的选项配置了构建：

```cpp
  include(ChooseMSVCCRT)
  include(AddLLVM)
  include(HandleLLVMOptions)
```

1.  接下来，LLVM 的头文件路径被添加到包含搜索路径中。添加了两个目录。从构建目录中添加了`include`目录，因为自动生成的文件保存在这里。另一个`include`目录是源目录内的目录：

```cpp
  include_directories("${LLVM_BINARY_DIR}/include"                      "${LLVM_INCLUDE_DIR}")
```

1.  使用`link_directories()`，将 LLVM 库的路径添加到链接器中：

```cpp
  link_directories("${LLVM_LIBRARY_DIR}")
```

1.  最后，设置一个标志以表示项目是独立构建的：

```cpp
  set(TINYLANG_BUILT_STANDALONE 1)
endif()
```

1.  现在进行常见的设置。将`cmake/modules`目录添加到 CMake 模块搜索路径中。这样可以稍后添加我们自己的 CMake 模块：

```cpp
list(APPEND CMAKE_MODULE_PATH   "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")
```

1.  接下来，我们检查用户是否正在进行外部构建。与 LLVM 一样，我们要求用户为构建项目使用单独的目录：

```cpp
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR AND NOT     MSVC_IDE)
  message(FATAL_ERROR "In-source builds are not     allowed.")
endif()
```

1.  `tinylang`的版本号被写入一个生成的文件中，使用`configure_file()`命令。版本号取自`TINYLANG_VERSION_STRING`变量。`configure_file()`命令读取一个输入文件，用当前值替换 CMake 变量，并写入一个输出文件。请注意，输入文件是从源目录读取的，并写入构建目录：

```cpp
set(TINYLANG_VERSION_STRING "0.1")
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/tinylang/Basic/Version.inc.in
  ${CMAKE_CURRENT_BINARY_DIR}/include/tinylang/Basic/Version.inc)
```

1.  接下来，包含另一个 CMake 模块。`AddTinylang`模块具有一些辅助功能：

```cpp
include(AddTinylang)
```

1.  接下来是另一个`include_directories()`语句。这将我们自己的`include`目录添加到搜索路径的开头。与独立构建一样，添加了两个目录：

```cpp
include_directories(BEFORE
  ${CMAKE_CURRENT_BINARY_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  )
```

1.  在文件末尾，将`lib`和`tools`目录声明为 CMake 查找`CMakeLists.txt`文件的其他目录。这是连接目录的基本机制。此示例应用程序只在`lib`和`tools`目录下有源文件，因此不需要其他内容。更复杂的项目将添加更多目录，例如用于单元测试的目录：

```cpp
add_subdirectory(lib)
add_subdirectory(tools)
```

这是您项目的主要描述。

`AddTinylang.cmake`辅助模块放置在`cmake/modules`目录中。它具有以下内容：

```cpp
macro(add_tinylang_subdirectory name)
  add_llvm_subdirectory(TINYLANG TOOL ${name})
endmacro()
macro(add_tinylang_library name)
  if(BUILD_SHARED_LIBS)
    set(LIBTYPE SHARED)
  else()
    set(LIBTYPE STATIC)
  endif()
  llvm_add_library(${name} ${LIBTYPE} ${ARGN})
  if(TARGET ${name})
    target_link_libraries(${name} INTERFACE 
      ${LLVM_COMMON_LIBS})
    install(TARGETS ${name}
      COMPONENT ${name}
      LIBRARY DESTINATION lib${LLVM_LIBDIR_SUFFIX}
      ARCHIVE DESTINATION lib${LLVM_LIBDIR_SUFFIX}
      RUNTIME DESTINATION bin)
  else()
    add_custom_target(${name})
  endif()
endmacro()
macro(add_tinylang_executable name)
  add_llvm_executable(${name} ${ARGN} )
endmacro()
macro(add_tinylang_tool name)
  add_tinylang_executable(${name} ${ARGN})
  install(TARGETS ${name}
    RUNTIME DESTINATION bin
    COMPONENT ${name})
endmacro()
```

随着模块的包含，`add_tinylang_subdirectory()`、`add_tinylang_library()`、`add_tinylang_executable()`和`add_tinylang_tool()`函数可供使用。基本上，这些函数是 LLVM 提供的等效函数（在`AddLLVM`模块中）的包装器。`add_tinylang_subdirectory()`添加一个新的源目录以便在构建中包含。此外，还添加了一个新的 CMake 选项。通过此选项，用户可以控制是否应该编译该目录的内容。使用`add_tinylang_library()`定义一个也被安装的库。`add_tinylang_executable()`定义一个可执行文件，`add_tinylang_tool()`定义一个也被安装的可执行文件。

在`lib`目录中，即使没有源文件，也需要一个`CMakeLists.txt`文件。它必须包括该项目库的源目录。打开您喜欢的文本编辑器，并将以下内容保存到文件中：

```cpp
add_subdirectory(Basic)
```

一个大型项目会创建多个库，并且源文件会放在`lib`的子目录中。每个这些目录都必须在`CMakeLists.txt`文件中添加。我们的小项目只有一个名为`Basic`的库，所以只需要一行。

`Basic`库只有一个源文件`Version.cpp`。该目录中的`CMakeLists.txt`文件同样简单：

```cpp
add_tinylang_library(tinylangBasic
  Version.cpp
  )
```

定义了一个名为`tinylangBasic`的新库，并将编译的`Version.cpp`添加到该库中。LLVM 选项控制这是一个共享库还是静态库。默认情况下，将创建一个静态库。

在`tools`目录中重复相同的步骤。该文件夹中的`CMakeLists.txt`文件几乎与`lib`目录中的一样简单：

```cpp
create_subdirectory_options(TINYLANG TOOL)
add_tinylang_subdirectory(driver)
```

首先，定义一个 CMake 选项，用于控制是否编译此目录的内容。然后添加唯一的子目录`driver`，这次使用我们自己模块的函数。同样，这使我们能够控制是否包括此目录在编译中。

`driver`目录包含应用程序`Driver.cpp`的源代码。此目录中的`CMakeLists.txt`文件包含编译和链接此应用程序的所有步骤：

```cpp
set(LLVM_LINK_COMPONENTS
  Support
  )
add_tinylang_tool(tinylang
  Driver.cpp
  )
target_link_libraries(tinylang
  PRIVATE
  tinylangBasic
  )
```

首先，将`LLVM_LINK_COMPONENTS`变量设置为我们需要将我们的工具链接到的 LLVM 组件列表。LLVM 组件是一个或多个库的集合。显然，这取决于工具的实现功能。在这里，我们只需要`Support`组件。

使用`add_tinylang_tool()`定义一个新的可安装应用程序。名称为`tinylang`，唯一的源文件是`Driver.cpp`。要链接到我们自己的库，必须使用`target_link_libraries()`指定它们。这里只需要`tinylangBasic`。

现在，CMake 系统所需的文件已经就位。接下来，我们将添加源文件。

## 添加 C++源文件

让我们从`include/tinylang/Basic`目录开始。首先，创建`Version.inc.in`模板文件，其中包含配置的版本号：

```cpp
#define TINYLANG_VERSION_STRING "@TINYLANG_VERSION_STRING@"
```

`@`符号表示`TINYLANG_VERSION_STRING`是一个 CMake 变量，应该用其内容替换。

`Version.h`头文件只声明一个函数来检索版本字符串：

```cpp
#ifndef TINYLANG_BASIC_VERSION_H
#define TINYLANG_BASIC_VERSION_H
#include "tinylang/Basic/Version.inc"
#include <string>
namespace tinylang {
std::string getTinylangVersion();
}
#endif
```

此函数的实现在`lib/Basic/Version.cpp`文件中。它同样简单：

```cpp
#include "tinylang/Basic/Version.h"
std::string tinylang::getTinylangVersion() {
  return TINYLANG_VERSION_STRING;
}
```

最后，在`tools/driver/Driver.cpp`文件中有应用程序源代码：

```cpp
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/raw_ostream.h"
#include "tinylang/Basic/Version.h"
int main(int argc_, const char **argv_) {
  llvm::InitLLVM X(argc_, argv_);
  llvm::outs() << "Hello, I am Tinylang "               << tinylang::getTinylangVersion()
               << "\n";
}
```

尽管只是一个友好的工具，但源代码使用了典型的 LLVM 功能。`llvm::InitLLVM()`调用进行了一些基本的初始化。在 Windows 上，参数被转换为 Unicode，以便统一处理命令行解析。并且在应用程序崩溃的情况下（希望不太可能发生），会安装一个漂亮的打印堆栈跟踪处理程序。它输出调用层次结构，从发生崩溃的函数开始。要查看真实的函数名称而不是十六进制地址，必须存在调试符号。

LLVM 不使用 C++标准库的`iostream`类。它带有自己的实现。`llvm::outs()`是输出流，在这里用于向用户发送友好的消息。

## 编译 tinylang 应用程序

现在，第一个应用程序的所有文件都就位，可以编译该应用程序。简而言之，您应该有以下目录和文件：

![图 2.3 - tinylang 项目的所有目录和文件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-llvm12/img/B15647_02_03.jpg)

图 2.3 - tinylang 项目的所有目录和文件

如前所述，有几种构建`tinylang`的方法。以下是如何将`tinylang`作为 LLVM 的一部分构建：

1.  使用以下命令切换到构建目录：

```cpp
$ cd build
```

1.  然后，按以下方式运行 CMake：

```cpp
-G Ninja). The build type is set to Release, thus producing optimized binaries (-DCMAKE_BUILD_TYPE=Release). Tinylang is built as an external project alongside LLVM (-DLLVM_EXTERNAL_PROJECTS=tinylang) and the source is found in a directory parallel to the build directory (-DLLVM_EXTERNAL_TINYLANG_SOURCE_DIR=../tinylang). A target directory for the build binaries is also given (-DCMAKE_INSTALL_PREFIX=../llvm-12). As the last parameter, the path of the LLVM project directory is specified (../llvm-project/llvm).
```

1.  现在，构建并安装所有内容：

```cpp
$ ninja
$ ninja install
```

1.  构建和安装后，`../llvm-12`目录包含 LLVM 和`tinylang`二进制文件。请检查您是否可以运行该应用程序：

```cpp
$ ../llvm-12/bin/tinylang
```

1.  您应该看到友好的消息。还请检查是否安装了 Basic 库：

```cpp
libtinylangBasic.a file.
```

与 LLVM 一起构建在您密切关注 LLVM 开发并希望尽快了解 API 更改时非常有用。在*第一章*中，*安装 LLVM*，我们检出了 LLVM 的特定版本。因此，我们看不到 LLVM 源代码的任何更改。

在这种情况下，构建 LLVM 一次并使用编译版本的 LLVM 编译`tinylang`作为独立项目是有意义的。以下是如何做到这一点：

1.  重新开始，进入`build`目录：

```cpp
$ cd build
```

这次，只使用 CMake 构建 LLVM：

```cpp
$ cmake -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=../llvm-12 \
  ../llvm-project/llvm
```

1.  将此与前面的 CMake 命令进行比较：缺少指向`tinylang`的参数；其他一切都是相同的。

1.  使用 Ninja 构建和安装 LLVM：

```cpp
$ ninja
$ ninja install
```

1.  现在您在`llvm-12`目录中安装了 LLVM。接下来，将构建`tinylang`项目。由于它是一个独立的构建，需要一个新的`build`目录。保留 LLVM 构建目录如下：

```cpp
$ cd ..
```

1.  现在创建一个新的`build-tinylang`目录。在 Unix 上，您使用以下命令：

```cpp
$ mkdir build-tinylang
```

在 Windows 上，您将使用以下命令：

```cpp
$ md build-tinylang
```

1.  使用以下命令进入新目录，无论是在哪个操作系统上：

```cpp
$ cd build-tinylang
```

1.  现在运行 CMake 为`tinylang`创建构建文件。唯一的特殊之处在于如何发现 LLVM，因为 CMake 不知道我们安装 LLVM 的位置。解决方案是使用`LLVMConfig.cmake`文件的路径来指定`LLVM_DIR`变量。命令如下：

```cpp
$ cmake -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR=../llvm-12/lib/cmake/llvm \
  -DCMAKE_INSTALL_PREFIX=../tinylang ../tinylang/
```

1.  安装目录现在也是分开的。像往常一样，使用以下命令构建和安装：

```cpp
$ ninja
$ ninja install
```

1.  命令完成后，您应该运行`../tinylang/bin/tinylang`应用程序，以检查应用程序是否正常工作。

### 包含 LLVM 的另一种方法

如果您不想为您的项目使用 CMake，那么您需要找出包含文件和库的位置，链接的库，使用了哪种构建模式等等。这些信息由`llvm-config`工具提供，该工具位于 LLVM 安装的`bin`目录中。假设该目录包含在您的 shell 搜索路径中，您运行`$ llvm-config`来查看所有选项。

例如，要使 LLVM 库链接到`support`组件（在前面的示例中使用），您运行以下命令：

```cpp
$ llvm-config –libs support
```

输出是一行库名称，包括编译器的链接选项，例如`-lLLVMSupport –lLLVMDemangle`。显然，这个工具可以很容易地与您选择的构建系统集成。

使用本节中显示的项目布局，您拥有一个适用于大型项目（如编译器）的结构。下一节奠定了另一个基础：如何为不同的目标架构进行交叉编译。

# 针对不同的 CPU 架构

今天，许多小型计算机，如树莓派，正在使用，并且资源有限。在这样的计算机上运行编译器通常是不可能的，或者运行时间太长。因此，编译器的一个常见要求是为不同的 CPU 架构生成代码。创建可执行文件的整个过程称为交叉编译。在上一节中，您创建了一个基于 LLVM 库的小型示例应用程序。现在我们将采用这个应用程序，并为不同的目标进行编译。

在交叉编译中，涉及两个系统：编译器在主机系统上运行，并为目标系统生成代码。为了表示这些系统，所谓的`x86_64-pc-win32`用于运行在 64 位 X86 CPU 上的 Windows 系统。CPU 架构是`x86_64`，`pc`是一个通用的供应商，`win32`是操作系统。这些部分由连字符连接。在 ARMv8 CPU 上运行 Linux 系统使用`aarch64-unknown-linux-gnu`作为三重。`aarch64`是 CPU 架构。操作系统是`linux`，运行`gnu`环境。对于基于 Linux 的系统，没有真正的供应商，因此这一部分是`unknown`。对于特定目的未知或不重要的部分通常被省略：三重`aarch64-linux-gnu`描述了相同的 Linux 系统。

假设您的开发机器在 X86 64 位 CPU 上运行 Linux，并且您希望交叉编译到运行 Linux 的 ARMv8 CPU 系统。主机三重是`x86_64-linux-gnu`，目标三重是`aarch64-linux-gnu`。不同的系统具有不同的特征。您的应用程序必须以可移植的方式编写，否则您将会受到失败的惊吓。常见的陷阱如下：

+   **字节序**：存储在内存中的多字节值的顺序可能不同。

+   `int`可能不足以容纳指针。

+   `long double`可以使用 64 位（ARM）、80 位（X86）或 128 位（ARMv8）。PowerPC 系统可能使用`long double`的双倍精度算术，通过使用两个 64 位`double`值的组合来获得更高的精度。

如果你不注意这些要点，那么你的应用程序在目标平台上可能会表现出令人惊讶的行为，甚至在你的主机系统上运行完美。LLVM 库在不同平台上进行了测试，也包含了对上述问题的可移植解决方案。

进行交叉编译，你需要以下工具：

+   为目标生成代码的编译器

+   一个能够为目标生成二进制文件的链接器

+   目标的头文件和库

Ubuntu 和 Debian 发行版有支持交叉编译的软件包。在下面的设置中，我们利用了这一点。`gcc`和`g++`编译器，`ld`链接器和库都可以作为预编译的二进制文件，生成 ARMv8 代码和可执行文件。要安装所有这些软件包，输入以下命令：

```cpp
$ sudo apt install gcc-8-aarch64-linux-gnu \
  g++-8-aarch64-linux-gnu binutils-aarch64-linux-gnu \
  libstdc++-8-dev-arm64-cross
```

新文件安装在`/usr/aarch64-linux-gnu`目录下。这个目录是目标系统的（逻辑）根目录。它包含通常的`bin`、`lib`和`include`目录。交叉编译器（`aarch64-linux-gnu-gcc-8`和`aarch64-linux-gnu-g++-8`）知道这个目录。

在其他系统上进行交叉编译

如果你的发行版没有所需的工具链，那么你可以从源代码构建它。gcc 和 g++编译器必须配置为为目标系统生成代码，binutils 工具需要处理目标系统的文件。此外，C 和 C++库需要使用这个工具链进行编译。这些步骤因使用的操作系统和主机和目标架构而异。在网上，你可以找到指令，如果你搜索`gcc 交叉编译<架构>`。

准备工作完成后，你几乎可以开始交叉编译示例应用程序（包括 LLVM 库），只是还有一个小细节。LLVM 使用*第一章*中构建的`llvm-tblgen`，或者你可以只编译这个工具。假设你在包含 GitHub 存储库克隆的目录中，输入以下命令：

```cpp
$ mkdir build-host
$ cd build-host
$ cmake -G Ninja \
  -DLLVM_TARGETS_TO_BUILD="X86" \
  -DLLVM_ENABLE_ASSERTIONS=ON \
  -DCMAKE_BUILD_TYPE=Release \
  ../llvm-project/llvm
$ ninja llvm-tblgen
$ cd ..
```

这些步骤现在应该很熟悉了。创建一个构建目录并进入。CMake 命令只为 X86 目标创建 LLVM 构建文件。为了节省空间和时间，进行了一个发布构建，但启用了断言以捕获可能的错误。只有`llvm-tblgen`工具是用 Ninja 编译的。

有了`llvm-tblgen`工具，现在你可以开始交叉编译了。CMake 命令行非常长，所以你可能想把命令存储在一个脚本文件中。与以前的构建不同的是，需要提供更多的信息：

```cpp
$ mkdir build-target
$ cd build-target
$ cmake -G Ninja \
  -DCMAKE_CROSSCOMPILING=True \
  -DLLVM_TABLEGEN=../build-host/bin/llvm-tblgen \
  -DLLVM_DEFAULT_TARGET_TRIPLE=aarch64-linux-gnu \
  -DLLVM_TARGET_ARCH=AArch64 \
  -DLLVM_TARGETS_TO_BUILD=AArch64 \
  -DLLVM_ENABLE_ASSERTIONS=ON \
  -DLLVM_EXTERNAL_PROJECTS=tinylang \
  -DLLVM_EXTERNAL_TINYLANG_SOURCE_DIR=../tinylang \
  -DCMAKE_INSTALL_PREFIX=../target-tinylang \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc-8 \
  -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++-8 \
  ../llvm-project/llvm
$ ninja
```

再次创建一个构建目录并进入。一些 CMake 参数以前没有使用过，需要一些解释：

+   `CMAKE_CROSSCOMPILING`设置为`ON`告诉 CMake 我们正在进行交叉编译。

+   `LLVM_TABLEGEN`指定要使用的`llvm-tblgen`工具的路径。这是之前构建的那个。

+   `LLVM_DEFAULT_TARGET_TRIPLE`是目标架构的三元组。

+   `LLVM_TARGET_ARCH`用于**即时**（**JIT**）代码生成。它默认为主机的架构。对于交叉编译，这必须设置为目标架构。

+   `LLVM_TARGETS_TO_BUILD`是 LLVM 应该包括代码生成器的目标列表。列表至少应该包括目标架构。

+   `CMAKE_C_COMPILER`和`CMAKE_CXX_COMPILER`指定用于构建的 C 和 C++编译器。交叉编译器的二进制文件以目标三元组为前缀，并且 CMake 不会自动找到它们。

使用其他参数，请求启用断言的发布构建，并将我们的 tinylang 应用程序作为 LLVM 的一部分构建（如前一节所示）。编译过程完成后，您可以使用 `file` 命令检查您是否真的为 ARMv8 创建了一个二进制文件。运行 `$ file bin/tinylang` 并检查输出是否表明它是针对 ARM aarch64 架构的 ELF 64 位对象。

使用 clang 进行交叉编译

由于 LLVM 为不同的架构生成代码，使用 clang 进行交叉编译似乎是显而易见的。这里的障碍是 LLVM 并未提供所有所需的部分；例如，缺少 C 库。因此，您必须使用 LLVM 和 GNU 工具的混合，并且作为结果，您需要向 CMake 提供更多关于您正在使用的环境的信息。至少，您需要为 clang 和 clang++ 指定以下选项：`--target=<target-triple>`（启用为不同目标生成代码）、`--sysroot=<path>`（目标根目录的路径；参见前文）、`I`（头文件的搜索路径）和 `–L`（库的搜索路径）。在 CMake 运行期间，将编译一个小应用程序，如果您的设置有问题，CMake 将会报错。这一步足以检查您是否有一个可用的环境。常见问题包括选择错误的头文件、由于不同的库名称导致的链接失败，以及错误的搜索路径。

交叉编译非常复杂。有了本节的说明，您将能够为您选择的目标架构交叉编译您的应用程序。

# 总结

在本章中，您了解了 LLVM 仓库中的项目以及常用的布局。您为自己的小应用程序复制了这个结构，为更复杂的应用程序奠定了基础。作为编译器构建的至高学科，您还学会了如何为另一个目标架构交叉编译您的应用程序。

在下一章中，将概述示例语言 `tinylang`。您将了解编译器必须执行的任务以及 LLVM 库支持的位置。


# 第三章：编译器的结构

编译器技术是计算机科学中一个深入研究的领域。它的高级任务是将源语言翻译成机器码。通常，这个任务分为两部分：前端和后端。前端主要处理源语言，而后端负责生成机器码。

在本章中，我们将涵盖以下主题：

+   编译器的构建模块，您将了解到编译器中通常找到的组件。

+   算术表达式语言，将为您介绍一个示例语言。您将学习语法如何用于定义语言。

+   词法分析，将讨论如何为语言实现词法分析器。

+   语法分析，涵盖如何从语法构建解析器。

+   语义分析，您将学习如何实现语义检查。

+   使用 LLVM 后端进行代码生成，将讨论如何与 LLVM 后端进行接口，以及如何将所有阶段连接在一起创建完整的编译器。

# 技术要求

本章的代码文件可在以下链接找到：[`github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter03/calc`](https://github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter03/calc)

您可以在以下链接找到代码的操作视频：[`bit.ly/3nllhED`](https://bit.ly/3nllhED)

# 编译器的构建模块

自从上个世纪中期计算机问世以来，很快就显而易见，比汇编语言更抽象的语言对编程是有用的。早在 1957 年，Fortran 就是第一种可用的高级编程语言。从那时起，成千上万种编程语言被开发出来。事实证明，所有编译器都必须解决相同的任务，并且编译器的实现最好根据这些任务进行结构化。

在最高级别上，编译器由两部分组成：前端和后端。前端负责特定于语言的任务。它读取源文件并计算其语义分析表示，通常是带注释的**抽象语法树**（**AST**）。后端从前端的结果创建优化的机器码。前端和后端之间有区分的动机是可重用性。假设前端和后端之间的接口定义良好。在这里，您可以将 C 和 Modula-2 前端连接到相同的后端。或者，如果您有一个用于 X86 的后端和一个用于 Sparc 的后端，那么您可以将 C++前端连接到两者。

前端和后端有特定的结构。前端通常执行以下任务：

1.  词法分析器读取源文件并生成标记流。

1.  解析器从标记流创建 AST。

1.  语义分析器向 AST 添加语义信息。

1.  代码生成器从 AST 生成**中间表示**（**IR**）。

中间表示是后端的接口。后端执行以下任务：

1.  后端对 IR 进行与目标无关的优化。

1.  然后，它为 IR 代码选择指令。

1.  然后，它对指令执行与目标相关的优化。

1.  最后，它会发出汇编代码或目标文件。

当然，这些说明仅在概念层面上。实现方式各不相同。LLVM 核心库定义了一个中间表示作为后端的标准接口。其他工具可以使用带注释的 AST。C 预处理器是一种独立的语言。它可以作为一个独立的应用程序实现，输出预处理的 C 源代码，或者作为词法分析器和解析器之间的附加组件。在某些情况下，AST 不必显式构造。如果要实现的语言不太复杂，那么将解析器和语义分析器结合起来，然后在解析过程中生成代码是一种常见的方法。即使程序设计语言的特定实现没有明确命名这些组件，也要记住这些任务仍然必须完成。

在接下来的章节中，我们将为一个表达式语言构建一个编译器，该编译器可以从输入中生成 LLVM IR。LLVM 静态编译器`llc`代表后端，然后可以用于将 IR 编译成目标代码。一切都始于定义语言。

# 算术表达式语言

算术表达式是每种编程语言的一部分。这里有一个名为**calc**的算术表达式计算语言的示例。calc 表达式被编译成一个应用程序，用于计算以下表达式：

```cpp
with a, b: a * (4 + b)
```

表达式中使用的变量必须使用`with`关键字声明。这个程序被编译成一个应用程序，该应用程序要求用户输入`a`和`b`变量的值，并打印结果。

示例总是受欢迎的，但作为编译器编写者，你需要比这更彻底的规范来进行实现和测试。编程语言的语法的载体是其语法。

## 用于指定编程语言语法的形式化方法

语言的元素，如关键字、标识符、字符串、数字和运算符，被称为**标记**。从这个意义上说，程序是一系列标记的序列，语法规定了哪些序列是有效的。

通常，语法是用**扩展的巴科斯-瑙尔范式（EBNF）**编写的。语法的一个规则是它有左侧和右侧。左侧只是一个称为**非终结符**的单个符号。规则的右侧由非终结符、标记和用于替代和重复的元符号组成。让我们来看看 calc 语言的语法：

```cpp
calc : ("with" ident ("," ident)* ":")? expr ;
expr : term (( "+" | "-" ) term)* ;
term : factor (( "*" | "/") factor)* ;
factor : ident | number | "(" expr ")" ;
ident : ([a-zAZ])+ ;
number : ([0-9])+ ;
```

在第一行中，`calc`是一个非终结符。如果没有另外说明，那么语法的第一个非终结符是起始符号。冒号`:`是规则左侧和右侧的分隔符。`"with"`、`,`和`":"`是代表这个字符串的标记。括号用于分组。一个组可以是可选的或重复的。括号后面的问号`?`表示一个可选组。星号`*`表示零次或多次重复，加号`+`表示一次或多次重复。`ident`和`expr`是非终结符。对于每一个，都存在另一个规则。分号`;`标记了规则的结束。第二行中的竖线`|`表示一个替代。最后，最后两行中的方括号`[]`表示一个字符类。有效的字符写在方括号内。例如，`[a-zA-Z]`字符类匹配大写或小写字母，`([a-zA-Z])+`匹配一个或多个这些字母。这对应于一个正则表达式。

## 语法如何帮助编译器编写者

这样的语法可能看起来像一个理论上的玩具，但对于编译器编写者来说是有价值的。首先，定义了所有的标记，这是创建词法分析器所需的。语法的规则可以被转换成解析器。当然，如果对解析器是否正确工作有疑问，那么语法就是一个很好的规范。

然而，语法并没有定义编程语言的所有方面。语法的含义 - 语义 - 也必须被定义。为此目的开发了形式化方法，但通常是以纯文本的方式指定的，类似于语言首次引入时的情况。

掌握了这些知识，接下来的两节将向您展示词法分析如何将输入转换为标记序列，以及如何在 C++中对语法进行编码以进行语法分析。

# 词法分析

正如我们在上一节的示例中看到的，编程语言由许多元素组成，如关键字、标识符、数字、运算符等。词法分析的任务是接受文本输入并从中创建一个标记序列。calc 语言由`with`、`:`、`+`、`-`、`*`、`/`、`(`和`)`标记以及`([a-zA-Z])+`（标识符）和`([0-9])+`（数字）正则表达式组成。我们为每个标记分配一个唯一的数字，以便更容易地处理它们。

## 手写词法分析器

词法分析器的实现通常称为`Lexer`。让我们创建一个名为`Lexer.h`的头文件，并开始定义`Token`。它以通常的头文件保护和所需的头文件开始：

```cpp
#ifndef LEXER_H
#define LEXER_H
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/MemoryBuffer.h"
```

`llvm::MemoryBuffer`类提供对填充有文件内容的内存块的只读访问。在请求时，会在缓冲区的末尾添加一个尾随的零字符（`'\x00'`）。我们使用这个特性来在不检查每次访问时缓冲区的长度的情况下读取缓冲区。`llvm::StringRef`类封装了指向 C 字符串及其长度的指针。由于长度被存储，字符串不需要像普通的 C 字符串那样以零字符（`'\x00'`）结尾。这允许`StringRef`的实例指向由`MemoryBuffer`管理的内存。让我们更详细地看一下这个：

1.  首先，`Token`类包含了先前提到的唯一标记数字的枚举定义：

```cpp
class Lexer;
class Token {
  friend class Lexer;
public:
  enum TokenKind : unsigned short {
    eoi, unknown, ident, number, comma, colon, plus, 
    minus, star, slash, l_paren, r_paren, KW_with
  };
```

除了为每个标记定义一个成员之外，我们还添加了两个额外的值：`eoi`和`unknown`。`eoi`代表结束输入，`unknown`用于在词法级别出现错误的情况下；例如，`#`不是语言的标记，因此会被映射为`unknown`。

1.  除了枚举之外，该类还有一个成员`Text`，它指向标记文本的开头。它使用了之前提到的`StringRef`类：

```cpp
private:
  TokenKind Kind;
  llvm::StringRef Text;
public:
  TokenKind getKind() const { return Kind; }
  llvm::StringRef getText() const { return Text; }
```

这对于语义处理很有用，因为知道标识符的名称是很有用的。

1.  `is()`和`isOneOf()`方法用于测试标记是否属于某种类型。`isOneOf()`方法使用可变模板，允许可变数量的参数：

```cpp
  bool is(TokenKind K) const { return Kind == K; }
  bool isOneOf(TokenKind K1, TokenKind K2) const {
    return is(K1) || is(K2);
  }
  template <typename... Ts>
  bool isOneOf(TokenKind K1, TokenKind K2, Ts... Ks) const {
    return is(K1) || isOneOf(K2, Ks...);
  }
};
```

1.  `Lexer`类本身具有类似的简单接口，并在头文件中紧随其后：

```cpp
class Lexer {
  const char *BufferStart;
  const char *BufferPtr;
public:
  Lexer(const llvm::StringRef &Buffer) {
    BufferStart = Buffer.begin();
    BufferPtr = BufferStart;
  }
  void next(Token &token);
private:
  void formToken(Token &Result, const char *TokEnd,
                 Token::TokenKind Kind);
};
#endif
```

除了构造函数之外，公共接口只包含`next()`方法，它返回下一个标记。该方法的行为类似于迭代器，总是前进到下一个可用的标记。该类的唯一成员是指向输入开头和下一个未处理字符的指针。假定缓冲区以终止`0`（类似于 C 字符串）结束。

1.  让我们在`Lexer.cpp`文件中实现`Lexer`类。它以一些辅助函数开始，以帮助对字符进行分类：

```cpp
#include "Lexer.h"
namespace charinfo {
LLVM_READNONE inline bool isWhitespace(char c) {
  return c == ' ' || c == '\t' || c == '\f' ||         c == '\v' ||
         c == '\r' || c == '\n';
}
LLVM_READNONE inline bool isDigit(char c) {
  return c >= '0' && c <= '9';
}
LLVM_READNONE inline bool isLetter(char c) {
  return (c >= 'a' && c <= 'z') ||         (c >= 'A' && c <= 'Z');
}
}
```

这些函数用于使条件更易读。

注意

我们不使用`<cctype>`标准库头文件提供的函数有两个原因。首先，这些函数根据环境中定义的区域设置而改变行为。例如，如果区域设置是德语区域设置，则德语变音符可以被分类为字母。这通常不是编译器所希望的。其次，由于这些函数的参数类型为`int`，我们必须从`char`类型转换。这种转换的结果取决于`char`是作为有符号类型还是无符号类型处理，这会导致可移植性问题。

1.  根据上一节中的语法，我们知道语言的所有标记。但是语法并没有定义应该忽略的字符。例如，空格或换行符只会添加空白并经常被忽略。`next()`方法首先忽略这些字符：

```cpp
void Lexer::next(Token &token) {
  while (*BufferPtr &&         charinfo::isWhitespace(*BufferPtr)) {
    ++BufferPtr;
  }
```

1.  接下来，确保仍有字符需要处理：

```cpp
  if (!*BufferPtr) {
    token.Kind = Token::eoi;
    return;
  }
```

至少有一个字符需要处理。

1.  因此，我们首先检查字符是小写还是大写。在这种情况下，标记要么是标识符，要么是`with`关键字，因为标识符的正则表达式也匹配关键字。常见的解决方案是收集正则表达式匹配的字符，并检查字符串是否恰好是关键字：

```cpp
  if (charinfo::isLetter(*BufferPtr)) {
    const char *end = BufferPtr + 1;
    while (charinfo::isLetter(*end))
      ++end;
    llvm::StringRef Name(BufferPtr, end - BufferPtr);
    Token::TokenKind kind =
        Name == "with" ? Token::KW_with : Token::ident;
    formToken(token, end, kind);
    return;
  }
```

私有的`formToken()`方法用于填充标记。

1.  接下来，我们检查是否为数字。以下代码与先前显示的代码非常相似：

```cpp
  else if (charinfo::isDigit(*BufferPtr)) {
    const char *end = BufferPtr + 1;
    while (charinfo::isDigit(*end))
      ++end;
    formToken(token, end, Token::number);
    return;
  }
```

1.  现在，只剩下由固定字符串定义的标记。这很容易用`switch`来实现。由于所有这些标记只有一个字符，所以使用`CASE`预处理宏来减少输入：

```cpp
  else {
    switch (*BufferPtr) {
#define CASE(ch, tok) \
case ch: formToken(token, BufferPtr + 1, tok); break
CASE('+', Token::plus);
CASE('-', Token::minus);
CASE('*', Token::star);
CASE('/', Token::slash);
CASE('(', Token::Token::l_paren);
CASE(')', Token::Token::r_paren);
CASE(':', Token::Token::colon);
CASE(',', Token::Token::comma);
#undef CASE
```

1.  最后，我们需要检查是否有意外的字符：

```cpp
    default:
      formToken(token, BufferPtr + 1, Token::unknown);
    }
    return;
  }
}
```

只有私有的辅助方法`formToken()`还缺失。

1.  这个私有的辅助方法填充了`Token`实例的成员并更新了指向下一个未处理字符的指针：

```cpp
void Lexer::formToken(Token &Tok, const char *TokEnd,
                      Token::TokenKind Kind) {
  Tok.Kind = Kind;
  Tok.Text = llvm::StringRef(BufferPtr, TokEnd -                              BufferPtr);
  BufferPtr = TokEnd;
}
```

在下一节中，我们将看一下如何构建用于语法分析的解析器。

# 语法分析

语法分析由我们将在下一步实现的解析器完成。它的基础是前几节的语法和词法分析器。解析过程的结果是一种称为**抽象语法树**（**AST**）的动态数据结构。AST 是输入的非常简洁的表示形式，并且非常适合语义分析。首先，我们将实现解析器。之后，我们将看一下 AST。

## 手写解析器

解析器的接口在`Parser.h`头文件中定义。它以一些`include`语句开始：

```cpp
#ifndef PARSER_H
#define PARSER_H
#include "AST.h"
#include "Lexer.h"
#include "llvm/Support/raw_ostream.h"
```

`AST.h`头文件声明了 AST 的接口，并将在稍后显示。LLVM 的编码指南禁止使用`<iostream>`库，因此必须包含等效的 LLVM 功能的头文件。需要发出错误消息。让我们更详细地看一下这个：

1.  首先，`Parser`类声明了一些私有成员：

```cpp
class Parser {
  Lexer &Lex;
  Token Tok;
  bool HasError;
```

`Lex`和`Tok`是前一节中的类的实例。`Tok`存储下一个标记（向前看），而`Lex`用于从输入中检索下一个标记。`HasError`标志指示是否检测到错误。

1.  有几种方法处理标记：

```cpp
  void error() {
    llvm::errs() << "Unexpected: " << Tok.getText()
                 << "\n";
    HasError = true;
  }
  void advance() { Lex.next(Tok); }
  bool expect(Token::TokenKind Kind) {
    if (Tok.getKind() != Kind) {
      error();
      return true;
    }
    return false;
  }
  bool consume(Token::TokenKind Kind) {
    if (expect(Kind))
      return true;
    advance();
    return false;
  }
```

`advance()`从词法分析器中检索下一个标记。`expect()`测试向前看是否是预期的类型，如果不是则发出错误消息。最后，`consume()`如果向前看是预期的类型，则检索下一个标记。如果发出错误消息，则将`HasError`标志设置为 true。

1.  对于语法中的每个非终结符，声明了一个解析规则的方法：

```cpp
  AST *parseCalc();
  Expr *parseExpr();
  Expr *parseTerm();
  Expr *parseFactor();
```

注意

`ident`和`number`没有方法。这些规则只返回标记，并由相应的标记替换。

1.  以下是公共接口。构造函数初始化所有成员并从词法分析器中检索第一个标记：

```cpp
public:
  Parser(Lexer &Lex) : Lex(Lex), HasError(false) {
    advance();
  }
```

1.  需要一个函数来获取错误标志的值：

```cpp
  bool hasError() { return HasError; }
```

1.  最后，`parse()`方法是解析的主要入口点：

```cpp
  AST *parse();
};
#endif
```

在下一节中，我们将学习如何实现解析器。

### 解析器实现

让我们深入了解解析器的实现：

1.  解析器的实现可以在`Parser.cpp`文件中找到，并以`parse()`方法开始：

```cpp
#include "Parser.h"
AST *Parser::parse() {
  AST *Res = parseCalc();
  expect(Token::eoi);
  return Res;
}
```

`parse()`方法的主要目的是整个输入已被消耗。您还记得第一节中解析示例添加了一个特殊符号来表示输入的结束吗？我们将在这里检查这一点。

1.  `parseCalc()`方法实现了相应的规则。让我们回顾一下第一节的规则：

```cpp
calc : ("with" ident ("," ident)* ":")? expr ;
```

1.  该方法开始声明一些局部变量：

```cpp
AST *Parser::parseCalc() {
  Expr *E;
  llvm::SmallVector<llvm::StringRef, 8> Vars;
```

1.  首先要做出的决定是是否必须解析可选组。该组以`with`标记开始，因此我们将标记与此值进行比较：

```cpp
  if (Tok.is(Token::KW_with)) {
    advance();
```

1.  接下来，我们期望一个标识符：

```cpp
    if (expect(Token::ident))
      goto _error;
    Vars.push_back(Tok.getText());
    advance();
```

如果有一个标识符，那么我们将其保存在`Vars`向量中。否则，这是一个语法错误，需要单独处理。

1.  语法中现在跟随一个重复组，它解析更多的标识符，用逗号分隔：

```cpp
    while (Tok.is(Token::comma)) {
      advance();
      if (expect(Token::ident))
        goto _error;
      Vars.push_back(Tok.getText());
      advance();
    }
```

这一点现在对你来说应该不足为奇了。重复组以`the`标记开始。标记的测试成为`while`循环的条件，实现零次或多次重复。循环内的标识符被视为之前处理的方式。

1.  最后，可选组需要在末尾加上冒号：

```cpp
    if (consume(Token::colon))
      goto _error;
  }
```

1.  现在，必须解析`expr`规则：

```cpp
  E = parseExpr();
```

1.  通过这个调用，规则已经成功解析。我们收集的信息现在用于创建这个规则的 AST 节点：

```cpp
  if (Vars.empty()) return E;
  else return new WithDecl(Vars, E);
```

现在，只有错误处理代码还缺失。检测语法错误很容易，但从中恢复却令人惊讶地复杂。在这里，必须使用一种称为**恐慌模式**的简单方法。

在恐慌模式中，从标记流中删除标记，直到找到解析器可以继续工作的标记为止。大多数编程语言都有表示结束的符号；例如，在 C++中，我们可以使用`;`（语句的结束）或`}`（块的结束）。这些标记是寻找的好候选者。

另一方面，错误可能是我们正在寻找的符号丢失了。在这种情况下，可能会在解析器继续之前删除很多标记。这并不像听起来那么糟糕。今天，编译器的速度更重要。在出现错误时，开发人员查看第一个错误消息，修复它，然后重新启动编译器。这与使用穿孔卡完全不同，那时尽可能多地获得错误消息非常重要，因为下一次运行编译器只能在第二天进行。

### 错误处理

不是使用一些任意的标记，而是使用另一组标记。对于每个非终端，都有一组可以在规则中跟随这个非终端的标记。让我们来看一下：

1.  在`calc`的情况下，只有输入的结尾跟随这个非终端。它的实现是微不足道的：

```cpp
_error:
  while (!Tok.is(Token::eoi))
    advance();
  return nullptr;
}
```

1.  其他解析方法的构造方式类似。`parseExpr()`是对`expr`规则的翻译：

```cpp
Expr *Parser::parseExpr() {
  Expr *Left = parseTerm();
  while (Tok.isOneOf(Token::plus, Token::minus)) {
    BinaryOp::Operator Op =
       Tok.is(Token::plus) ? BinaryOp::Plus :
                             BinaryOp::Minus;
    advance();
    Expr *Right = parseTerm();
    Left = new BinaryOp(Op, Left, Right);
  }
  return Left;
}
```

规则内的重复组被翻译成了`while`循环。请注意`isOneOf()`方法的使用简化了对多个标记的检查。

1.  `term`规则的编码看起来是一样的：

```cpp
Expr *Parser::parseTerm() {
  Expr *Left = parseFactor();
  while (Tok.isOneOf(Token::star, Token::slash)) {
    BinaryOp::Operator Op =
        Tok.is(Token::star) ? BinaryOp::Mul : 
                              BinaryOp::Div;
    advance();
    Expr *Right = parseFactor();
    Left = new BinaryOp(Op, Left, Right);
  }
  return Left;
}
```

这个方法与`parseExpr()`非常相似，你可能会想将它们合并成一个。在语法中，可以有一个处理乘法和加法运算符的规则。使用两个规则而不是一个的优势在于运算符的优先级与数学计算顺序很匹配。如果合并这两个规则，那么你需要在其他地方找出评估顺序。

1.  最后，你需要实现`factor`规则：

```cpp
Expr *Parser::parseFactor() {
  Expr *Res = nullptr;
  switch (Tok.getKind()) {
  case Token::number:
    Res = new Factor(Factor::Number, Tok.getText());
    advance(); break;
```

与使用一系列`if`和`else if`语句不同，这里似乎更适合使用`switch`语句，因为每个备选方案都以一个标记开始。一般来说，你应该考虑使用哪种翻译模式。如果以后需要更改解析方法，那么如果不是每个方法都有不同的实现语法规则的方式，那就是一个优势。

1.  如果使用`switch`语句，那么错误处理发生在`default`情况下：

```cpp
  case Token::ident:
    Res = new Factor(Factor::Ident, Tok.getText());
    advance(); break;
  case Token::l_paren:
    advance();
    Res = parseExpr();
    if (!consume(Token::r_paren)) break;
  default:
    if (!Res) error();
```

我们在这里防止发出错误消息，因为会出现错误。

1.  如果括号表达式中有语法错误，那么会发出错误消息。保护措施防止发出第二个错误消息：

```cpp
    while (!Tok.isOneOf(Token::r_paren, Token::star,
                        Token::plus, Token::minus,
                        Token::slash, Token::eoi))
      advance();
  }
  return Res;
}
```

这很容易，不是吗？一旦你记住了使用的模式，根据语法规则编写解析器几乎是乏味的。这种类型的解析器称为**递归下降解析器**。

递归下降解析器无法从所有语法构造出来

语法必须满足一定条件才能适合构造递归下降解析器。这类语法称为 LL(1)。事实上，大多数你可以在互联网上找到的语法都不属于这类语法。大多数关于编译器构造理论的书都解释了这个原因。这个主题的经典书籍是所谓的“龙书”，即 Aho、Lam、Sethi 和 Ullman 的*编译器原理、技术和工具*。

## 抽象语法树

解析过程的结果是一个`;`，表示单个语句的结束。当然，这对解析器很重要。一旦我们将语句转换为内存表示，分号就不再重要，可以被丢弃。

如果你看一下例子表达式语言的第一个规则，那么很明显`with`关键字，逗号`,`和冒号`:`对程序的含义并不重要。重要的是声明的变量列表，这些变量可以在表达式中使用。结果是只需要几个类来记录信息：`Factor`保存数字或标识符，`BinaryOp`保存算术运算符和表达式的左右两侧，`WithDecl`保存声明的变量列表和表达式。`AST`和`Expr`仅用于创建一个公共类层次结构。

除了从解析输入中获得的信息外，还要在使用`AST.h`头文件时进行树遍历。让我们来看一下：

1.  它以访问者接口开始：

```cpp
#ifndef AST_H
#define AST_H
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
class AST;
class Expr;
class Factor;
class BinaryOp;
class WithDecl;
class ASTVisitor {
public:
  virtual void visit(AST &){};
  virtual void visit(Expr &){};
  virtual void visit(Factor &) = 0;
  virtual void visit(BinaryOp &) = 0;
  virtual void visit(WithDecl &) = 0;
};
```

访问者模式需要知道它必须访问的每个类。因为每个类也引用了访问者，我们在文件顶部声明所有类。请注意，`AST`和`Expr`的`visit()`方法具有默认实现，什么也不做。

1.  `AST`类是层次结构的根：

```cpp
class AST {
public:
  virtual ~AST() {}
  virtual void accept(ASTVisitor &V) = 0;
};
```

1.  同样，`Expr`是与表达式相关的`AST`类的根：

```cpp
class Expr : public AST {
public:
  Expr() {}
};
```

1.  `Factor`类存储数字或变量的名称：

```cpp
class Factor : public Expr {
public:
  enum ValueKind { Ident, Number };
private:
  ValueKind Kind;
  llvm::StringRef Val;
public:
  Factor(ValueKind Kind, llvm::StringRef Val)
      : Kind(Kind), Val(Val) {}
  ValueKind getKind() { return Kind; }
  llvm::StringRef getVal() { return Val; }
  virtual void accept(ASTVisitor &V) override {
    V.visit(*this);
  }
};
```

在这个例子中，数字和变量几乎被处理得一样，因此我们决定只创建一个 AST 节点类来表示它们。`Kind`成员告诉我们实例代表这两种情况中的哪一种。在更复杂的语言中，通常希望有不同的 AST 类，比如`NumberLiteral`类用于数字，`VariableAccess`类用于引用变量。

1.  `BinaryOp`类保存了评估表达式所需的数据：

```cpp
class BinaryOp : public Expr {
public:
  enum Operator { Plus, Minus, Mul, Div };
private:
  Expr *Left;
  Expr *Right;
  Operator Op;
public:
  BinaryOp(Operator Op, Expr *L, Expr *R)
      : Op(Op), Left(L), Right(R) {}
  Expr *getLeft() { return Left; }
  Expr *getRight() { return Right; }
  Operator getOperator() { return Op; }
  virtual void accept(ASTVisitor &V) override {
    V.visit(*this);
  }
};
```

与解析器相比，`BinaryOp`类在乘法和加法运算符之间没有区别。运算符的优先级隐含在树结构中。

1.  最后，`WithDecl`存储了声明的变量和表达式：

```cpp
class WithDecl : public AST {
  using VarVector =                   llvm::SmallVector<llvm::StringRef, 8>;
  VarVector Vars;
  Expr *E;
public:
  WithDecl(llvm::SmallVector<llvm::StringRef, 8> Vars,
           Expr *E)
      : Vars(Vars), E(E) {}
  VarVector::const_iterator begin()                                 { return Vars.begin(); }
  VarVector::const_iterator end() { return Vars.end(); }
  Expr *getExpr() { return E; }
  virtual void accept(ASTVisitor &V) override {
    V.visit(*this);
  }
};
#endif
```

AST 在解析过程中构建。语义分析检查树是否符合语言的含义（例如，使用的变量是否已声明），并可能增强树。之后，树被用于代码生成。

# 语义分析

语义分析器遍历 AST 并检查语言的各种语义规则；例如，变量必须在使用前声明，或者表达式中的变量类型必须兼容。如果语义分析器发现可以改进的情况，还可以打印警告。对于示例表达语言，语义分析器必须检查每个使用的变量是否已声明，因为语言要求如此。可能的扩展（这里不会实现）是在未使用的情况下打印警告消息。

语义分析器实现在 `Sema` 类中，语义分析由 `semantic()` 方法执行。以下是完整的 `Sema.h` 头文件：

```cpp
#ifndef SEMA_H
#define SEMA_H
#include "AST.h"
#include "Lexer.h"
class Sema {
public:
  bool semantic(AST *Tree);
};
#endif
```

实现在 `Sema.cpp` 文件中。有趣的部分是语义分析，它使用访问者来实现。基本思想是每个声明的变量名都存储在一个集合中。在创建集合时，我们可以检查每个名称是否唯一，然后稍后检查名称是否在集合中：

```cpp
#include "Sema.h"
#include "llvm/ADT/StringSet.h"
namespace {
class DeclCheck : public ASTVisitor {
  llvm::StringSet<> Scope;
  bool HasError;
  enum ErrorType { Twice, Not };
  void error(ErrorType ET, llvm::StringRef V) {
    llvm::errs() << "Variable " << V << " "
                 << (ET == Twice ? "already" : "not")
                 << " declared\n";
    HasError = true;
  }
public:
  DeclCheck() : HasError(false) {}
  bool hasError() { return HasError; }
```

与 `Parser` 类一样，使用标志来指示是否发生错误。名称存储在名为 `Scope` 的集合中。在包含变量名的 `Factor` 节点中，我们检查变量名是否在集合中：

```cpp
  virtual void visit(Factor &Node) override {
    if (Node.getKind() == Factor::Ident) {
      if (Scope.find(Node.getVal()) == Scope.end())
        error(Not, Node.getVal());
    }
  };
```

对于 `BinaryOp` 节点，我们只需要检查两侧是否存在并已被访问：

```cpp
  virtual void visit(BinaryOp &Node) override {
    if (Node.getLeft())
      Node.getLeft()->accept(*this);
    else
      HasError = true;
    if (Node.getRight())
      Node.getRight()->accept(*this);
    else
      HasError = true;
  };
```

在 `WithDecl` 节点中，集合被填充，并开始对表达式的遍历：

```cpp
  virtual void visit(WithDecl &Node) override {
    for (auto I = Node.begin(), E = Node.end(); I != E;
         ++I) {
      if (!Scope.insert(*I).second)
        error(Twice, *I);
    }
    if (Node.getExpr())
      Node.getExpr()->accept(*this);
    else
      HasError = true;
  };
};
}
```

`semantic()` 方法只是开始树遍历并返回错误标志：

```cpp
bool Sema::semantic(AST *Tree) {
  if (!Tree)
    return false;
  DeclCheck Check;
  Tree->accept(Check);
  return Check.hasError();
}
```

如果需要，这里可以做更多的工作。还可以打印警告消息，如果声明的变量未被使用。我们留给您来实现。如果语义分析没有错误完成，那么我们可以从 AST 生成 LLVM IR。我们将在下一节中进行这个操作。

# 使用 LLVM 后端生成代码

后端的任务是从模块的 **IR** 创建优化的机器代码。IR 是后端的接口，可以使用 C++ 接口或文本形式创建。同样，IR 是从 AST 生成的。

## LLVM IR 的文本表示

在尝试生成 LLVM IR 之前，我们需要了解我们想要生成什么。对于示例表达语言，高级计划如下：

1.  询问用户每个变量的值。

1.  计算表达式的值。

1.  打印结果。

要求用户为变量提供一个值并打印结果，使用了两个库函数 `calc_read()` 和 `calc_write()`。对于 `with a: 3*a` 表达式，生成的 IR 如下：

1.  库函数必须像 C 语言一样声明。语法也类似于 C 语言。函数名前的类型是返回类型。括号中的类型是参数类型。声明可以出现在文件的任何位置：

```cpp
declare i32 @calc_read(i8*)
declare void @calc_write(i32)
```

1.  `calc_read()` 函数以变量名作为参数。以下结构定义了一个常量，保存了 `a` 和在 C 语言中用作字符串终结符的空字节：

```cpp
@a.str = private constant [2 x i8] c"a\00"
```

1.  它跟在 `main()` 函数后面。参数的名称被省略，因为它们没有被使用。与 C 语言一样，函数的主体用大括号括起来：

```cpp
define i32 @main(i32, i8**) {
```

1.  每个基本块必须有一个标签。因为这是函数的第一个基本块，我们将其命名为 `entry`：

```cpp
entry:
```

1.  调用 `calc_read()` 函数来读取 `a` 变量的值。嵌套的 `getelemenptr` 指令执行索引计算以计算字符串常量的第一个元素的指针。函数的结果被赋值给未命名的 `%2` 变量：

```cpp
  %2 = call i32 @calc_read(i8* getelementptr inbounds
                 ([2 x i8], [2 x i8]* @a.str, i32 0, i32 0))
```

1.  接下来，变量乘以 `3`：

```cpp
  %3 = mul nsw i32 3, %2
```

1.  结果通过调用 `calc_write()` 函数打印到控制台：

```cpp
  call void @calc_write(i32 %3)
```

1.  最后，`main()` 函数返回 `0` 表示执行成功：

```cpp
  ret i32 0
}
```

LLVM IR 中的每个值都是有类型的，`i32`表示 32 位整数类型，`i8*`表示指向字节的指针。IR 代码非常可读（也许除了`getelementptr`操作之外，在*第五章**，IR 生成基础*中将详细解释）。现在清楚了 IR 的样子，让我们从 AST 生成它。

## 从 AST 生成 IR。

在`CodeGen.h`头文件中提供的接口非常小：

```cpp
#ifndef CODEGEN_H
#define CODEGEN_H
#include "AST.h"
class CodeGen
{
public:
 void compile(AST *Tree);
};
#endif
```

因为 AST 包含了语义分析阶段的信息，基本思想是使用访问者遍历 AST。`CodeGen.cpp`文件的实现如下：

1.  所需的包含在文件顶部：

```cpp
#include "CodeGen.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/Support/raw_ostream.h"
```

1.  LLVM 库的命名空间用于名称查找：

```cpp
using namespace llvm;
```

1.  首先，在访问者中声明了一些私有成员。LLVM 中，每个编译单元都由`Module`类表示，访问者有一个指向模块调用`M`的指针。为了方便生成 IR，使用了`Builder`（`IRBuilder<>`类型）。LLVM 有一个类层次结构来表示 IR 中的类型。您可以在 LLVM 上下文中查找基本类型的实例，比如`i32`。这些基本类型经常被使用。为了避免重复查找，我们缓存所需的类型实例，可以是`VoidTy`、`Int32Ty`、`Int8PtrTy`、`Int8PtrPtrTy`或`Int32Zero`。`V`是当前计算的值，通过树遍历更新。最后，`nameMap`将变量名映射到`calc_read()`函数返回的值：

```cpp
namespace {
class ToIRVisitor : public ASTVisitor {
  Module *M;
  IRBuilder<> Builder;
  Type *VoidTy;
  Type *Int32Ty;
  Type *Int8PtrTy;
  Type *Int8PtrPtrTy;
  Constant *Int32Zero;
  Value *V;
  StringMap<Value *> nameMap;
```

1.  构造函数初始化了所有成员：

```cpp
public:
  ToIRVisitor(Module *M) : M(M), Builder(M->getContext()) 
  {
    VoidTy = Type::getVoidTy(M->getContext());
    Int32Ty = Type::getInt32Ty(M->getContext());
    Int8PtrTy = Type::getInt8PtrTy(M->getContext());
    Int8PtrPtrTy = Int8PtrTy->getPointerTo();
    Int32Zero = ConstantInt::get(Int32Ty, 0, true);
  }
```

1.  对于每个函数，必须创建一个`FunctionType`实例。在 C++术语中，这是一个函数原型。函数本身是用`Function`实例定义的。首先，`run()`方法在 LLVM IR 中定义了`main()`函数：

```cpp
  void run(AST *Tree) {
    FunctionType *MainFty = FunctionType::get(
        Int32Ty, {Int32Ty, Int8PtrPtrTy}, false);
    Function *MainFn = Function::Create(
        MainFty, GlobalValue::ExternalLinkage,
        "main", M);
```

1.  然后，使用`entry`标签创建`BB`基本块，并将其附加到 IR 构建器：

```cpp
    BasicBlock *BB = BasicBlock::Create(M->getContext(),
                                        "entry", MainFn);
    Builder.SetInsertPoint(BB);
```

1.  准备工作完成后，树遍历可以开始：

```cpp
    Tree->accept(*this);
```

1.  树遍历后，通过调用`calc_write()`函数打印计算出的值。再次，必须创建函数原型（`FunctionType`的实例）。唯一的参数是当前值`V`：

```cpp
    FunctionType *CalcWriteFnTy =
        FunctionType::get(VoidTy, {Int32Ty}, false);
    Function *CalcWriteFn = Function::Create(
        CalcWriteFnTy, GlobalValue::ExternalLinkage,
        "calc_write", M);
    Builder.CreateCall(CalcWriteFnTy, CalcWriteFn, {V});
```

1.  生成完成后，从`main()`函数返回`0`：

```cpp
    Builder.CreateRet(Int32Zero);
  }
```

1.  `WithDecl`节点保存了声明变量的名称。首先，必须为`calc_read()`函数创建函数原型：

```cpp
  virtual void visit(WithDecl &Node) override {
    FunctionType *ReadFty =
        FunctionType::get(Int32Ty, {Int8PtrTy}, false);
    Function *ReadFn = Function::Create(
        ReadFty, GlobalValue::ExternalLinkage, 
        "calc_read", M);
```

1.  该方法循环遍历变量名：

```cpp
    for (auto I = Node.begin(), E = Node.end(); I != E;
         ++I) {
```

1.  为每个变量创建一个带有变量名的字符串：

```cpp
      StringRef Var = *I;
      Constant *StrText = ConstantDataArray::getString(
          M->getContext(), Var);
      GlobalVariable *Str = new GlobalVariable(
          *M, StrText->getType(),
          /*isConstant=*/true, 
          GlobalValue::PrivateLinkage,
          StrText, Twine(Var).concat(".str"));
```

1.  然后，创建调用`calc_read()`函数的 IR 代码。将在上一步中创建的字符串作为参数传递：

```cpp
      Value *Ptr = Builder.CreateInBoundsGEP(
          Str, {Int32Zero, Int32Zero}, "ptr");
      CallInst *Call =
          Builder.CreateCall(ReadFty, ReadFn, {Ptr});
```

1.  返回的值存储在`mapNames`映射中以供以后使用：

```cpp
      nameMap[Var] = Call;
    }
```

1.  树遍历继续进行，表达式如下：

```cpp
    Node.getExpr()->accept(*this);
  };
```

1.  `Factor`节点可以是变量名或数字。对于变量名，在`mapNames`映射中查找值。对于数字，将值转换为整数并转换为常量值：

```cpp
  virtual void visit(Factor &Node) override {
    if (Node.getKind() == Factor::Ident) {
      V = nameMap[Node.getVal()];
    } else {
      int intval;
      Node.getVal().getAsInteger(10, intval);
      V = ConstantInt::get(Int32Ty, intval, true);
    }
  };
```

1.  最后，对于`BinaryOp`节点，必须使用正确的计算操作：

```cpp
  virtual void visit(BinaryOp &Node) override {
    Node.getLeft()->accept(*this);
    Value *Left = V;
    Node.getRight()->accept(*this);
    Value *Right = V;
    switch (Node.getOperator()) {
    case BinaryOp::Plus:
      V = Builder.CreateNSWAdd(Left, Right); break;
    case BinaryOp::Minus:
      V = Builder.CreateNSWSub(Left, Right); break;
    case BinaryOp::Mul:
      V = Builder.CreateNSWMul(Left, Right); break;
    case BinaryOp::Div:
      V = Builder.CreateSDiv(Left, Right); break;
    }
  };
};
}
```

1.  这样，访问者类就完成了。`compile()`方法创建全局上下文和模块，运行树遍历，并将生成的 IR 转储到控制台：

```cpp
void CodeGen::compile(AST *Tree) {
  LLVMContext Ctx;
  Module *M = new Module("calc.expr", Ctx);
  ToIRVisitor ToIR(M);
  ToIR.run(Tree);
  M->print(outs(), nullptr);
}
```

通过这样，我们已经实现了编译器的前端，从读取源代码到生成 IR。当然，所有这些组件必须在用户输入上一起工作，这是编译器驱动程序的任务。我们还需要实现运行时所需的函数。我们将在下一节中涵盖这两个方面。

## 缺失的部分 - 驱动程序和运行时库

前几节的所有阶段都由`Calc.cpp`驱动程序连接在一起，我们将在这里实现。此时，声明了输入表达式的参数，初始化了 LLVM，并调用了前几节的所有阶段。让我们来看一下：

1.  首先，必须包含所需的头文件：

```cpp
#include "CodeGen.h"
#include "Parser.h"
#include "Sema.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/raw_ostream.h"
```

1.  LLVM 有自己的命令行选项声明系统。您只需要为每个需要的选项声明一个静态变量。这样做，选项就会在全局命令行解析器中注册。这种方法的优势在于每个组件都可以在需要时添加命令行选项。我们必须为输入表达式声明一个选项：

```cpp
static llvm::cl::opt<std::string>
    Input(llvm::cl::Positional,
          llvm::cl::desc("<input expression>"),
          llvm::cl::init(""));
```

1.  在`main()`函数内，初始化了 LLVM 库。您需要调用`ParseCommandLineOptions`来处理命令行上的选项。这也处理打印帮助信息。在出现错误的情况下，此方法会退出应用程序：

```cpp
int main(int argc, const char **argv) {
  llvm::InitLLVM X(argc, argv);
  llvm::cl::ParseCommandLineOptions(
      argc, argv, "calc - the expression compiler\n");
```

1.  接下来，我们调用词法分析器和语法分析器。在语法分析之后，我们检查是否发生了错误。如果是这种情况，那么我们以一个返回代码退出编译器，表示失败：

```cpp
  Lexer Lex(Input);
  Parser Parser(Lex);
  AST *Tree = Parser.parse();
  if (!Tree || Parser.hasError()) {
    llvm::errs() << "Syntax errors occured\n";
    return 1;
  }
```

1.  如果有语义错误，我们也会这样做。

```cpp
  Sema Semantic;
  if (Semantic.semantic(Tree)) {
    llvm::errs() << "Semantic errors occured\n";
    return 1;
  }
```

1.  最后，在驱动程序中，调用了代码生成器：

```cpp
  CodeGen CodeGenerator;
  CodeGenerator.compile(Tree);
  return 0;
}
```

有了这个，我们已经成功地为用户输入创建了 IR 代码。我们将对象代码生成委托给 LLVM 静态编译器`llc`，因此这完成了我们的编译器的实现。我们必须将所有组件链接在一起，以创建`calc`应用程序。

运行时库由一个名为`rtcalc.c`的单个文件组成。它包含了用 C 编写的`calc_read()`和`calc_write()`函数的实现：

```cpp
#include <stdio.h>
#include <stdlib.h>
void calc_write(int v)
{
  printf("The result is: %d\n", v);
}
```

`calc_write()`只是将结果值写入终端：

```cpp
int calc_read(char *s)
{
  char buf[64];
  int val;
  printf("Enter a value for %s: ", s);
  fgets(buf, sizeof(buf), stdin);
  if (EOF == sscanf(buf, "%d", &val))
  {
    printf("Value %s is invalid\n", buf);
    exit(1);
  }
  return val;
}
```

`calc_read()`从终端读取一个整数。没有任何限制阻止用户输入字母或其他字符，因此我们必须仔细检查输入。如果输入不是数字，我们就退出应用程序。一个更复杂的方法是让用户意识到问题，并再次要求输入一个数字。

现在，我们可以尝试我们的编译器。`calc`应用程序从表达式创建 IR。LLVM 静态编译器`llc`将 IR 编译为一个目标文件。然后，您可以使用您喜欢的 C 编译器链接到小型运行时库。在 Unix 上，您可以输入以下内容：

```cpp
$ calc "with a: a*3" | llc –filetype=obj –o=expr.o
$ clang –o expr expr.o rtcalc.c
$ expr
Enter a value for a: 4
The result is: 12
```

在 Windows 上，您很可能会使用`cl`编译器：

```cpp
$ calc "with a: a*3" | llc –filetype=obj –o=expr.obj
$ cl expr.obj rtcalc.c
$ expr
Enter a value for a: 4
The result is: 12
```

有了这个，您已经创建了您的第一个基于 LLVM 的编译器！请花一些时间玩弄各种表达式。还要检查乘法运算符在加法运算符之前进行评估，并且使用括号会改变评估顺序，这是我们从基本计算器中期望的。

# 总结

在本章中，您了解了编译器的典型组件。一个算术表达式语言被用来向您介绍编程语言的语法。然后，您学会了如何为这种语言开发典型的前端组件：词法分析器、语法分析器、语义分析器和代码生成器。代码生成器只产生了 LLVM IR，LLVM 静态编译器`llc`用它来创建目标文件。最后，您开发了您的第一个基于 LLVM 的编译器！

在下一章中，您将加深这些知识，以构建一个编程语言的前端。
