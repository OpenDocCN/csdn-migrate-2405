# 面向 C++ 的现代 CMake 教程（预览）（一）

> 原文：[`zh.annas-archive.org/md5/125f0c03ca93490db2ba97b08bc69e99`](https://zh.annas-archive.org/md5/125f0c03ca93490db2ba97b08bc69e99)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第一章：使用 CMake 的第一步

将源代码转化为可工作的应用程序有一种神奇的感觉。不仅仅是效果本身：一个我们设计和赋予生命的工作机制，还有这个过程，将想法付诸实践的行为本身。

作为程序员，我们在这个循环中工作：设计-编码-测试。我们构思变更，用编译器理解的语言表达它们，并检查它们是否按预期工作。为了从我们的源代码创建一个高质量的应用程序，我们需要仔细执行重复且容易出错的任务：调用正确的命令，检查语法，链接二进制文件，运行测试，报告问题等等。

始终记住每一步都需要努力。相反，我们希望专注于实际的编码工作，并将其他所有事情委托给自动化工具。理想情况下，这个过程会在我们修改代码后立即通过一个按钮启动。它应该是智能、快速、可扩展的，并且在不同的操作系统和环境中以相同的方式工作。它应该得到多个 IDE 的支持，也应该得到持续集成管道的支持，这些管道在代码提交到共享存储库后测试我们的软件。

CMake 是满足许多此类需求的答案，但它需要一些工作来正确配置和使用。这不是因为 CMake 过于复杂，而是因为我们在这里处理的主题本身就很复杂。别担心，我们将非常系统地进行整个学习过程，很快你就会成为构建大师。

我知道你急于开始，开始编写你自己的 CMake 项目，我赞赏你的态度。既然你的项目将主要面向用户（包括你自己），那么理解那个视角也很重要。

让我们从成为 CMake 高级用户开始。我们将介绍一些基础知识：这个工具是什么，它在原理上是如何工作的，以及如何安装它。然后我们将深入探讨命令行和操作模式。最后，我们将总结项目中不同文件的用途，并简要介绍在没有项目的情况下使用 CMake。

在本章中，我们将涵盖以下主要主题：

+   理解基础知识

+   在不同平台上安装 CMake

+   掌握命令行

+   浏览项目文件

+   发现脚本和模块

## 技术要求

您可以在 GitHub 上找到本章中的代码文件，地址是[`github.com/PacktPublishing/Modern-CMake-for-Cpp`](https://github.com/PacktPublishing/Modern-CMake-for-Cpp)

## 理解基础知识

C++源代码的编译过程看起来相当直接。当我们处理一个小程序，比如经典的`hello.cpp`时：

#### 第一章/01-hello/hello.cpp

```cpp
#include <iostream>
int main() {
  std::cout << "Hello World!" << std::endl;
  return 0;
}
```

要获得可执行文件，我们只需运行一个命令。我们使用文件名作为参数调用编译器：

```cpp
$ g++ hello.cpp -o a.out
```

我们的代码是正确的，所以编译器会默默地生成一个可执行的二进制文件，我们的机器可以理解。我们可以通过调用它的名称来运行它：

```cpp
$ ./a.out
Hello World!
$
```

然而，随着我们的项目增长，我们很快意识到将所有内容保存在一个文件中是根本不可能的。干净的代码实践建议文件应该保持小巧，并组织得井井有条。手动编译每个文件将是一个繁琐且脆弱的过程。一定有更好的方法。

### CMake 是什么？

假设我们通过编写一个脚本来实现自动化构建，该脚本会遍历我们的项目树并编译所有内容。为了避免不必要的编译，我们的脚本会检测自上次以来源文件是否被修改过。现在我们希望有一个方便的方法来管理传递给每个文件编译器的参数——最好基于可配置的标准。我们的脚本还应该知道如何将所有编译过的文件链接成一个二进制文件，或者更好的是：构建整个解决方案，这些解决方案可以被重复使用，并作为模块整合到更大的项目中。

我们添加的功能越多——我们就会得到一个功能齐全的解决方案。软件构建是一个非常多样化的过程，可以跨越多个不同的方面：

+   编译可执行文件和库

+   管理依赖项

+   测试

+   安装

+   打包

+   生成文档

+   再测试一些

开发一个真正模块化且强大的适用于各种用途的 C++构建应用程序需要很长时间。确实如此。Kitware 的 Bill Hoffman 在 20 多年前实现了 CMake 的第一个版本。正如你已经猜到的——它非常成功，拥有许多功能和社区支持。今天，CMake 正在积极开发中，并已成为 C 和 C++程序员的行业标准。

在自动化方式下构建代码的问题比 CMake 要古老得多，所以自然有很多选择：Make、Autotools、SCons、Ninja、Premake 等等。但为什么 CMake 占据上风？

关于 CMake，我发现（当然，主观上）一些真正重要的事情：

+   它专注于支持现代编译器和工具链

+   CMake 确实是跨平台的——它支持为 Windows、Linux、macOS 和 Cygwin 构建

+   它为流行的 IDE 生成项目文件：Microsoft Visual Studio、Xcode、Eclipse CDT，并且它是其他 IDE（如 CLion）的项目模型

+   CMake 在适当的抽象级别上运行——它允许将文件分组为可重用的目标和项目

+   有大量的项目是使用 CMake 构建的，并提供了一种简单的方法将它们包含在你的项目中

+   CMake 将测试、打包和安装视为构建过程的固有部分

+   旧的、不常用的功能会被弃用，以保持 CMake 的精简

CMake 提供了这种统一的、简化的体验：在你的 IDE 中构建，从命令行构建，以及（真正重要的是）在后续阶段也是如此。你的 CI/CD 管道可以轻松地使用相同的 CMake 配置，并使用单一标准构建项目，即使上述所有环境都不同。

### 它是如何工作的？

你可能会得到这样的印象：CMake 是一个从一端读取源代码，从另一端生成二进制文件的工具——虽然在原则上这是正确的，但这并不是全部情况。

CMake 本身不能构建任何东西——它依赖于系统中的其他工具来执行实际的编译、链接和其他任务。将其视为构建过程的指挥者：它知道需要完成哪些步骤，最终目标是什么，以及如何找到合适的工人和材料来完成工作。

这个过程有三个阶段：

+   配置

+   生成

+   构建

#### 配置阶段

这个阶段是关于阅读存储在名为**源树**的目录中的项目细节，并为生成阶段准备一个输出目录**构建树**。

CMake 首先创建一个空的构建树，并收集有关其工作环境的全部细节——架构、可用的编译器、链接器、归档器，并检查是否可以正确编译一个简单的测试程序。

接下来，解析并执行`CMakeLists.txt`项目配置文件（是的，CMake 项目使用 CMake 自己的编程语言进行配置）。这个文件是 CMake 项目的基础（稍后可以添加源文件）。它告诉 CMake 项目的结构、目标和依赖关系：库和其他 CMake 包。在此过程中，CMake 在构建树中存储收集的信息：系统细节、项目配置、日志和用于下一步的临时文件。特别是，创建了一个`CMakeCache.txt`文件来存储更稳定的变量（如编译器和其他工具的路径），并在下一次配置时节省时间。

#### 生成阶段

在阅读项目配置后，CMake 将**为它工作的确切环境生成一个构建系统**。构建系统只不过是为其他构建工具定制的配置文件（例如，GNU Make 的 Makefile 或 Ninja 和 Visual Studio 的 IDE 项目文件）。在这个阶段，CMake 仍然可以通过评估**生成器表达式**来对构建配置进行一些最后的调整。

> **注意**
> 
> 生成阶段是在配置阶段之后执行的（除非你通过 cmake-gui 特别要求 CMake 不这样做）。因此，当我们提到生成阶段时，我们指的是两者。

#### 构建阶段

为了生成我们项目中指定的最终制品，我们必须运行适当的**构建工具**。这可以通过直接调用、通过 IDE 或使用 CMake 命令来实现。这些构建工具将反过来执行步骤，使用编译器、链接器、静态和动态分析工具、测试框架、报告工具以及你能想到的其他一切来生成**目标**。

这种解决方案的美妙之处在于，它能够为每个平台按需生成构建系统，且只需单一配置（相同的项目文件）。

![图 1.1：CMake 阶段](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/mdn-cmk-cpp/img/file0.png)

**图 1.1：CMake 阶段**

记得我们在第一节中的`hello.cpp`应用程序吗？CMake 使得构建它变得非常容易。我们所需要的只是旁边的源代码和两个简单的命令：`cmake -B buildtree`和`cmake --build buildtree`

#### chapter01/01-hello/CMakeLists.txt：CMake 语言中的 Hello world

```cpp
cmake_minimum_required(VERSION 3.20)
project(Hello)
add_executable(Hello hello.cpp)
```

以下是来自 Docker 化 Linux 系统的输出（我们将在下一节讨论 Docker）：

```cpp
root@5f81fe44c9bd:/home/root/chapter01/01-hello# cmake -B buildtree .
-- The C compiler identification is GNU 9.3.0
-- The CXX compiler identification is GNU 9.3.0
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Detecting C compile features
-- Detecting C compile features - done
-- Check for working CXX compiler: /usr/bin/c++
-- Check for working CXX compiler: /usr/bin/c++ -- works
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Configuring done
-- Generating done
-- Build files have been written to: /home/root/chapter01/01-hello/buildtree
root@5f81fe44c9bd:/home/root/chapter01/01-hello# cmake --build buildtree/
Scanning dependencies of target Hello
[ 50%] Building CXX object CMakeFiles/Hello.dir/hello.cpp.o
[100%] Linking CXX executable Hello
[100%] Built target Hello
```

剩下的就是运行它：

```cpp
root@68c249f65ce2:~# ./buildtree/Hello
Hello World!
```

我已经生成了一个存储在`buildtree`目录中的构建系统，然后执行了构建阶段，并生成了一个最终的可执行二进制文件。

现在，当您知道最终结果的样子时，我相信您一定有很多问题：这个过程的前提条件是什么？这些命令是什么意思？为什么我们需要两个？如何编写自己的项目文件？不用担心——这些问题将在接下来的页面上得到解答。

> **获取帮助**
> 
> 本书将为您提供与当前版本 CMake（截至今天：3.20）最相关的最重要信息。为了给您提供最佳建议，我特意避免了任何已弃用且不再推荐的功能。我强烈建议使用至少 3.15 版本，该版本被认为是“现代 CMake”。如果您需要更多信息，可以在线找到最新的完整文档：[`cmake.org/cmake/help/`](https://cmake.org/cmake/help/)。

## 在不同平台上安装 CMake

CMake 是一个跨平台的开源软件，用 C++编写。这意味着您当然可以自己编译它，但大多数情况下您不需要这样做，因为可以从官方网页下载预编译的二进制文件：[`cmake.org/download/`](https://cmake.org/download/)

基于 Unix 的系统提供了可以直接从命令行安装的软件包。

> **注意**
> 
> 请记住，CMake 不自带编译器，所以如果你的系统上没有任何安装，你需要自行提供。确保将它们可执行文件的路径添加到`PATH`环境变量中，以便 CMake 能够找到它们。
> 
> 为了避免在学习本书时解决工具和依赖问题，我建议选择第一种安装方法——Docker。

### Docker

Docker（[`www.docker.com/`](https://www.docker.com/)）是一个跨平台的工具，提供操作系统级别的虚拟化，允许应用程序以称为容器的完整包形式进行交付。这些是自给自足的包，包含所有库、依赖项和工具。Docker 在其轻量级环境中执行容器，这些环境彼此隔离。

这个概念使得共享整个工具链变得极其方便，这些工具链是为特定过程配置好的，随时可以使用。我无法强调当你不必担心微小的环境差异时，事情变得多么容易。

Docker 平台有一个公共的容器镜像仓库[`registry.hub.docker.com/`](https://registry.hub.docker.com/)，提供了数百万个随时可用的镜像。

为了您的方便，我已经发布了两个 docker 仓库：

+   `swidzinski/cmake:toolchain` - 包含构建 CMake 所需精选工具和依赖项

+   `swidzinski/cmake:examples` - 包含上述工具链以及本书中的所有项目和示例

第一种选择是为那些只想获得一个干净的镜像，准备构建自己项目的读者准备的，而第二种选择是为那些希望通过实践示例来练习的读者准备的，我们将在章节中逐步介绍。

按照 Docker 文档中的说明安装 Docker[`docs.docker.com/get-docker/`](https://docs.docker.com/get-docker/)，并在终端中执行以下命令以下载镜像并启动容器：

```cpp
$ docker pull swidzinski/cmake:examples
$ docker run -it swidzinski/cmake:examples
root@b55e271a85b2:/home/root#
```

所有示例都将位于`/home/root/chapter-<N>/<M>-<title>`目录中。

### Windows

在 Windows 上安装很简单——下载适用于 32 位或 64 位的版本。您可以选择适用于 Windows Installer 的便携式 zip 或 msi 软件包。

使用 zip 软件包，您将不得不将 CMake bin 目录添加到`PATH`环境变量中，以便能够在任何目录中使用它，而不会出现此类错误：

```cpp
'cmake' is not recognized as an internal or external command, operable program or batch file.
```

如果您偏好便利性——使用 msi 安装程序。

![图 1.2：安装向导可以为您设置 PATH 环境变量。](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/mdn-cmk-cpp/img/file1.jpg)

图 1.2：安装向导可以为您设置 PATH 环境变量。

正如我之前提到的——这是一个开源软件，所以你可以自己构建 CMake，但是——你首先必须在你的系统上获得一个二进制版本的 CMake。如果你有自己的构建工具，为什么要使用其他的呢，对吧？这种情况是由 CMake 贡献者用来生成新版本的。

在 Windows 上，我们还需要一个构建工具来完成 CMake 启动的构建过程。一个很好的通用选择是 Visual Studio，可以从微软网站的免费社区版下载：[`visualstudio.microsoft.com/downloads/`](https://visualstudio.microsoft.com/downloads/)

### Linux

在 Linux 上获取 CMake 与获取任何其他流行软件包完全相同。只需使用命令行上的软件包管理器即可。软件包通常会保持更新，版本相当新，但如果你需要最新版本，可以从网站下载安装脚本。

#### 适用于 Linux x86_64 的脚本

```cpp
$ wget -O - https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0-linux-x86_64.sh | bash
```

#### 适用于 Linux aarch64 的脚本

```cpp
$ wget -O - https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0-Linux-aarch64.sh | bash
```

#### 适用于 Debian / Ubuntu 的软件包

```cpp
$ sudo apt-get install cmake
```

#### 适用于 Redhat 的软件包

```cpp
$ yum install cmake
```

### MacOS

这个平台也得到了 CMake 开发者的强烈支持。最受欢迎的安装方式是通过 MacPorts：

```cpp
$ sudo port install cmake
```

或者，您可以使用 Homebrew：

```cpp
$ brew install cmake
```

### 从源代码构建

如果其他方法都失败了，或者你处于特殊平台，可以从官方网站下载源代码并自行编译：

```cpp
$ wget https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0.tar.gz
$ tar xzf cmake-3.20.0.tar.gz
$ cd cmake-3.20.0
$ ./bootstrap
$ make
$ make install
```

从源代码构建会稍微慢一些，步骤也更多，但这样能确保你使用的是 CMake 的最新版本。这在与 Linux 上可用的软件包进行比较时尤为明显：系统版本越旧，获得的更新就越少。

既然我们已经安装好了 CMake，现在让我们学习如何使用它！

## 掌握命令行

本书的大部分内容将教你如何为用户准备 CMake 项目。为了满足他们的需求，我们需要深入了解用户在不同情况下如何与 CMake 交互。这将使你能够测试项目文件并确保它们正常工作。

CMake 是一套工具，由五个可执行文件组成：

+   `cmake` – 配置、生成和构建项目的主可执行文件

+   `ctest` – 用于运行和报告测试结果的测试驱动程序

+   `cpack` – 用于生成安装程序和源包的打包程序

+   `cmake-gui` – 基于图形的 cmake 包装器

+   `ccmake` – 基于控制台的 cmake 图形界面包装器

### CMake

这个二进制文件提供了几种操作模式（也称为动作）：

+   生成项目构建系统

+   构建项目

+   安装项目

+   运行脚本

+   运行命令行工具

+   获取帮助

#### 生成项目构建系统

这是构建我们项目的第一步。以下是执行 CMake 构建操作的几种方式：

#### 生成模式的语法

```cpp
cmake [<options>] -S <path-to-source> -B <path-to-build>
cmake [<options>] <path-to-source>
cmake [<options>] <path-to-existing-build>
```

我们将在接下来的章节中讨论选项，现在让我们专注于选择正确的命令形式。CMake 的一个重要特性是外部构建，即在指定的目录中生成构件。与 GNU Make 等工具不同，这保持了源目录的清洁，没有与构建相关的文件，并避免了在我们的版本控制系统中添加不必要的文件或忽略指令。这就是为什么最好使用第一种生成模式，并通过`-B`指定生成的构建系统目录和通过`-S`指定源树路径，如下所示：

```cpp
cmake -S ./project -B ./build
```

上述操作将在`./build`目录中生成构建系统（如果该目录不存在则创建它），源代码位于`./project`目录中。

我们可以跳过其中一个参数，`cmake`会“猜测”我们打算使用当前目录，但要小心——跳过两个参数会导致内部构建，那会很混乱。

> **不推荐**
> 
> 不要使用第二种或第三种命令形式：`$ cmake <directory>`，因为它可能会产生混乱的内部构建（我们将在第三章学习如何阻止这种情况）。正如语法片段中所暗示的，如果`<directory>`中已经存在之前的构建，相同的命令会有不同的行为：它将使用缓存的源路径并从那里重新构建。由于我们经常从终端命令历史中调用相同的命令，我们可能会在这里遇到麻烦：在使用这种形式之前，请始终检查你的 shell 是否正在正确的目录中工作。

##### 示例

在当前目录中构建，但从上一级目录获取源代码（`-S`是可选的）：

```cpp
cmake -S ..
```

在`./build`目录中构建，并使用当前目录的源代码：

```cpp
cmake -B build
```

##### 选项：生成器

如概要所示，在生成步骤期间可以指定几个选项。选择和配置生成器决定了将使用我们系统上的哪个构建工具进行构建，构建文件将是什么样子，以及构建树的结构将是什么。

那么，你应该关心吗？幸运的是，答案通常是“不”。CMake 确实支持许多平台上的多种本地构建系统，但除非你同时安装了几个，否则 CMake 会为你正确选择。这可以通过`CMAKE_GENERATOR`环境变量或通过在命令行上直接指定生成器来覆盖，如下所示：

```cpp
cmake -G <generator-name> <path-to-source>
```

一些生成器（如 Visual Studio）支持更深入的工具集（编译器）和平台（编译器或 SDK）的规范。这些也有相应的环境变量，它们覆盖默认值：`CMAKE_GENERATOR_TOOLSET`和`CMAKE_GENERATOR_PLATFORM`。我们直接如下指定它们：

```cpp
cmake -G <generator-name> 
      -T <toolset-spec> -A <platform-name>
      <path-to-source>
```

通常，Windows 用户希望为其喜爱的 IDE 生成构建系统，而在 Linux 和 macOS 上，使用 Unix Makefiles 或 Ninja 生成器非常常见。

要检查系统上可用的生成器，请使用：

```cpp
cmake --help
```

在帮助打印输出的末尾，你将看到一个完整的列表，如下所示：

#### 在 Windows 10 上有许多可用的生成器

```cpp
The following generators are available on this platform:
Visual Studio 16 2019
Visual Studio 15 2017 [arch]
Visual Studio 14 2015 [arch]
Visual Studio 12 2013 [arch]
Visual Studio 11 2012 [arch]
Visual Studio 10 2010 [arch]
Visual Studio 9 2008 [arch]
Borland Makefiles
NMake Makefiles
NMake Makefiles JOM
MSYS Makefiles
MinGW Makefiles
Green Hills MULTI
Unix Makefiles
Ninja
Ninja Multi-Config
Watcom Wmake
CodeBlocks - MinGW Makefiles
CodeBlocks - NMake Makefiles
CodeBlocks - NMake Makefiles JOM
CodeBlocks - Ninja
CodeBlocks - Unix Makefiles
CodeLite - MinGW Makefiles
CodeLite - NMake Makefiles
CodeLite - Ninja
CodeLite - Unix Makefiles
Eclipse CDT4 - NMake Makefiles
Eclipse CDT4 - MinGW Makefiles
Eclipse CDT4 - Ninja
Eclipse CDT4 - Unix Makefiles
Kate - MinGW Makefiles
Kate - NMake Makefiles
Kate - Ninja
Kate - Unix Makefiles
Sublime Text 2 - MinGW Makefiles
Sublime Text 2 - NMake Makefiles
Sublime Text 2 - Ninja
Sublime Text 2 - Unix Makefiles 
```

##### 选项：缓存

CMake 在配置阶段查询系统以获取各种信息，这些信息被缓存在构建树目录中的`CMakeCache.txt`中。有几个选项允许更方便地管理该文件。

首先，我们可以**预填充缓存信息**：

```cpp
cmake -C <initial-cache-script> <path-to-source>
```

我们可以提供一个 CMake 脚本的路径，该脚本包含（仅）一个`set()`命令列表，以指定将用于初始化空构建树的变量。

**初始化和修改**现有缓存变量的另一种方法（当创建文件只是为了设置其中几个时，这有点过分）。你可以在命令行上像这样设置它们：

```cpp
cmake -D <var>[:<type>]=<value> <path-to-source>
```

`:<type>`部分是可选的（它被 GUI 使用），使用`BOOL`、`FILEPATH`、`PATH`、`STRING`、`INTERNAL`之一。如果你省略类型，它将被设置为现有变量的类型，否则为`UNITIALIZED`。

一个特别重要的变量包含构建的类型：调试、发布等。许多 CMake 项目会多次读取它，以决定消息的详细程度、调试信息的可用性以及构建产物的优化级别。

对于单配置生成器（如 Makefile 和 Ninja），你需要在配置阶段使用`CMAKE_BUILD_TYPE`变量指定它，并为每种配置类型生成一个单独的构建树：`Debug`、`Release`、`MinSizeRel`或`RelWithDebInfo`。

这里有一个例子：

```cpp
cmake -S . -B build -D CMAKE_BUILD_TYPE=Release
```

多配置生成器在构建阶段配置。

我们可以使用-L 选项**列出缓存**变量：

```cpp
cmake -L[A][H] <path-to-source>
```

这样的列表将包含未标记为`ADVANCED`的缓存变量，我们可以通过添加`A`修饰符来更改这一点。如果我们对阅读每个变量的帮助感兴趣，我们可以添加`H`修饰符。

令人惊讶的是，使用`-D`选项手动添加的自定义变量将不可见，除非您指定一种受支持的类型。

**删除**一个或多个变量可以使用以下选项完成：

```cpp
cmake -U <globbing_expr> <path-to-source>
```

通配符表达式支持通配符`*`和任意字符`?`符号。使用时要小心，因为您可能会破坏某些内容。

可以多次重复使用`-U`和`-D`选项。

##### 选项：调试和跟踪

CMake 可以通过多种选项运行，使其能够深入其内部并检查不同的设置。要**获取一般信息**关于变量、命令、宏和其他设置，请运行：

```cpp
cmake --system-information [file]
```

可选的文件参数允许您将输出存储在文件中。在构建树目录中运行它将打印有关缓存变量和来自日志文件的构建消息的额外信息。

在我们的项目中，我们将使用`message()`命令来报告构建过程的详细信息。CMake**根据当前日志级别（默认为`STATUS`）过滤这些日志输出**。以下行指定我们感兴趣的日志级别：

```cpp
cmake --log-level=<level>
```

其中`level`可以是以下任意一个：`ERROR`、`WARNING`、`NOTICE`、`STATUS`、`VERBOSE`、`DEBUG`和`TRACE`。您可以在`CMAKE_MESSAGE_LOG_LEVEL`缓存变量中永久指定此设置。

另一个有趣选项允许我们**显示日志上下文**，每个`message()`调用。为了调试非常复杂的项目，使用`CMAKE_MESSAGE_CONTEXT`变量作为堆栈，并在进入更窄的上下文时将其推入，并在离开时将其弹出。如果我们启用显示日志上下文，如下所示：

```cpp
cmake --log-context <path-to-source>
```

然后，我们的消息将装饰有当前的`CMAKE_MESSAGE_CONTEXT`，如下所示：

```cpp
[some.context.example] Debug message.
```

我们将在下一章详细讨论日志记录。

如果其他所有方法都失败了，我们需要使用重型武器 - 总有**跟踪模式**。它将打印每个命令及其调用的文件名和确切行号以及其参数。启用它如下所示：

```cpp
cmake --trace
```

##### 选项：预设

如您所见 - 用户可以指定许多选项来从您的项目生成构建树。在构建树路径、生成器、缓存和环境变量之间 - 很容易感到困惑或遗漏某些内容。开发人员可以简化用户与项目交互的方式，并提供一个`CMakePresets.json`文件，指定一些默认值。请在本章的*浏览项目文件*部分了解更多信息。

要列出可用的预设，请执行：

```cpp
cmake --list-presets
```

您可以像这样使用其中一个可用预设。

```cpp
cmake --preset=<preset>
```

这些值覆盖系统默认值和环境，但同时 - 可以用命令行中明确传递的任何参数覆盖。

![图 1.3：预设如何覆盖 CmakeCache.txt 和系统环境变量](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/mdn-cmk-cpp/img/file2.jpg)

图 1.3：预设如何覆盖 CmakeCache.txt 和系统环境变量

#### 构建项目

生成我们的构建树后，我们准备好进入下一个阶段：**运行构建工具**。CMake 不仅知道如何为许多不同的构建工具生成输入文件，还可以使用我们项目特定的参数为你运行它们。

> **不推荐**
> 
> 许多在线资源建议在生成阶段之后直接调用 GNU Make：`make`。这是 Linux 和 MacOS 的默认生成器，通常情况下它是有效的。然而，我们更倾向于本节描述的方法，因为它与生成器无关，并且支持所有平台。这样我们就不需要担心我们应用程序的每个用户的具体环境。

#### 构建模式的语法

```cpp
cmake --build <dir> [<options>] [-- <build-tool-options>]
```

在大多数情况下，只需提供最基本的信息就足以成功构建：

```cpp
cmake --build <dir>
```

CMake 需要知道我们生成的构建树的位置。这与我们在生成步骤中使用`-B`参数传递的路径相同。

通过提供一些选项，CMake 允许指定适用于每个构建工具的关键构建参数。如果你需要为所选的本地构建工具提供特殊参数，请在命令末尾的`--`标记之后传递它们：

```cpp
cmake --build <dir> -- <build-tool-options>
```

##### 选项：并行构建

许多构建工具默认会使用多个并发进程来利用现代处理器，并并行编译你的源代码。构建工具了解项目依赖关系的结构，因此它们可以同时处理那些依赖关系已满足的步骤，以节省用户的时间。

如果你在强大的机器上构建（或者为了调试而强制单线程构建），你可能想要覆盖该设置，只需**指定作业数量**，使用以下任一选项：

```cpp
cmake --build <dir> --parallel [<number-of-jobs>]
cmake --build <dir> -j [<number-of-jobs>]
```

另一种方法是使用`CMAKE_BUILD_PARALLEL_LEVEL`环境变量来设置它。通常，我们可以使用上述选项来覆盖该变量。

##### 选项：目标

我们将在本书的第二部分更多地讨论目标。现在，我们只能说每个项目都是由一个或多个称为目标的部分组成的。通常，我们想要构建所有目标，但有时我们可能对跳过某些目标感兴趣，或者**明确构建一个故意从正常构建中排除的目标**。我们可以这样做：

```cpp
cmake --build <dir> --target <tgt>..., -t <tgt>...
```

如你所见，我们可以通过冒号指定多个目标。

一个通常不会被构建的目标是`clean`。它将删除构建目录中的所有工件。调用它的方法是：

```cpp
cmake --build <dir> -t clean
```

CMake 还提供了一个方便的别名，如果你想要**先清理然后进行正常构建**：

```cpp
cmake --build <dir> --clean-first
```

##### 选项：多配置生成器

我们已经对生成器有了一些了解。它们有不同的形式和大小。有些生成器提供的功能比其他生成器更多，其中之一就是能够在单个构建树中构建`Debug`和`Release`构建类型。

支持此功能的生成器有 Ninja Multi-Config、XCode 和 Visual Studio。其他所有生成器都是单配置生成器，需要为此目的单独的构建树。

选择`Debug`、`Release`、`MinSizeRel`或`RelWithDebInfo`中的一个，并这样指定：

```cpp
cmake --build <dir> --config <cfg>
```

否则，CMake 将使用`Debug`作为默认值。

##### 选项：调试

当出现问题时，首先要检查的是输出消息。然而，经验丰富的开发者知道，始终打印所有细节会令人困惑，因此他们通常默认隐藏这些细节。当我们需要窥视引擎盖下时，我们可以要求更详细的日志，告诉 CMake 要详细：

```cpp
cmake --build <dir> --verbose
cmake --build <dir> -v
```

通过设置`CMAKE_VERBOSE_MAKEFILE`缓存变量也可以达到同样的效果。

#### 安装一个项目

当构建工件时，用户可以将它们安装到系统中。这通常意味着将文件复制到正确的目录，安装库，或从 CMake 脚本运行一些自定义安装逻辑。

#### 安装模式的语法

```cpp
cmake --install <dir> [<options>]
```

与其他操作模式一样，CMake 需要生成构建树的路径：

```cpp
cmake --install <dir>
```

##### 选项：多配置生成器

就像在构建阶段一样，我们可以指定我们希望为安装使用的构建类型（更多细节请参见“构建项目”）。可用类型为`Debug`、`Release`、`MinSizeRel`或`RelWithDebInfo`。签名如下：

```cpp
cmake --install <dir> --config <cfg>
```

##### 选项：组件

作为开发者，您可能希望将项目拆分为可以独立安装的组件。我们将在*第十一章*中详细讨论组件的概念，现在让我们假设它们代表了解决方案的不同部分。这可能是：“应用程序”、“文档”和“额外工具”。

要安装单个组件，请使用此选项：

```cpp
cmake --install <dir> --component <comp>
```

##### 选项：权限

如果在类 Unix 平台上进行安装，可以使用以下选项指定安装目录的默认权限，使用此格式：`u=rwx,g=rx,o=rx`

```cpp
cmake --install <dir> 
      --default-directory-permissions <permissions>
```

##### 选项：安装目录

我们可以在项目配置中指定的安装路径前加上我们选择的任何前缀（例如，当我们对某些目录的写入权限有限时）。路径`/usr/local`以前缀`/home/user`变为`/home/user/usr/local`。此选项的签名是：

```cpp
cmake --install <dir> --prefix <prefix>
```

请注意，这在 Windows 上不起作用，因为该平台上的路径通常以驱动器字母开头。

##### 选项：调试

与构建阶段类似，我们也可以选择查看安装阶段的详细输出。使用以下任何一种：

```cpp
cmake --build <dir> --verbose
cmake --build <dir> -v
```

如果设置了`VERBOSE`环境变量，也可以达到同样的效果。

#### 运行脚本

CMake 项目使用 CMake 的定制语言进行配置。它是跨平台的，非常强大，而且已经存在。为什么不将其用于其他任务呢？当然，您可以编写独立的脚本（我们将在本章末尾讨论这一点）。

CMake 可以这样运行：

#### 运行脚本模式的语法

```cpp
cmake [{-D <var>=<value>}...] -P <cmake-script-file> 
      [-- <unparsed-options>...]
```

运行这样的脚本不会运行任何配置或生成阶段，也不会影响缓存。有两种方法可以将值传递给此脚本：

+   通过使用`-D`选项定义的变量

+   通过可以在`--`标记后传递的参数。

    CMake 将为传递给脚本的所有参数（包括`--`标记）创建`CMAKE_ARGV<n>`变量。

#### 运行命令行工具

在极少数情况下，我们可能需要以平台无关的方式运行单个命令，例如复制文件或计算校验和。并非所有平台都是平等创建的，因此并非所有命令在每个系统上都可用，或者它们具有不同的名称。

CMake 提供了一种在跨平台上以相同方式执行最常见操作的模式：

#### 运行命令行工具模式的语法

```cpp
cmake -E <command> [<options>]
```

由于这种模式的使用相当有限，我们不会深入讨论它们。如果您对细节感兴趣，我建议调用`cmake -E`来列出所有可用的命令。只是为了窥见一斑，CMake 3.20 支持以下命令：

`capabilities`, `cat`, `chdir`, `compare_files`, `copy`, `copy_directory`, `copy_if_different`, `echo`, `echo_append`, `env`, `environment`, `make_directory`, `md5sum`, `sha1sum`, `sha224sum`, `sha256sum`, `sha384sum`, `sha512sum`, `remove`, `remove_directory`, `rename`, `rm`, `server`, `sleep`, `tar`, `time`, `touch`, `touch_nocreate`, `create_symlink`, `create_hardlink`, `true`, `false`

如果您想要使用的命令缺失，或者您需要更复杂的行为，可以考虑将其包装在脚本中，并在`-P`模式下运行。

#### 获取帮助

不出所料，CMake 通过其命令行提供了广泛的可用帮助。

#### 帮助模式的语法

```cpp
cmake --help[-<topic>]
```

### CTest

自动化测试对于生成和维护高质量代码非常重要。这就是为什么我们专门用*第八章*来讨论这个主题，并在那里深入探讨 CTest 的使用。它是可用的命令行工具之一，所以现在让我们简要介绍一下。

CTest 是关于将 CMake 包装在更高层次的抽象中，其中构建只是我们软件开发过程中的一个步骤。CMake 可以为我们执行的其他任务包括：更新、运行各种测试、向外部仪表板报告项目状态以及运行用 CMake 语言编写的脚本。

最重要的是，CTest 标准化了使用 CMake 构建的解决方案的**运行测试和报告**。作为用户，您不需要知道项目使用的是哪种测试框架，或者如何运行它。CTest 提供了一个方便的外观，用于列出、过滤、洗牌、重试和时间限制测试运行。如果需要构建，它还可以为您调用 CMake。

为已构建的项目运行测试的最简单方法是在生成的构建树中调用`ctest`：

```cpp
$ ctest
Test project C:/Users/rapha/Desktop/CMake/build
Guessing configuration Debug
    Start 1: SystemInformationNew
1/1 Test #1: SystemInformationNew .........   Passed 3.19 sec
100% tests passed, 0 tests failed out of 1
Total Test time (real) =   3.24 sec 
```

### CPack

在我们构建并测试了我们的精彩软件之后，我们准备与世界分享它。在极少数情况下，高级用户完全满意于源代码，这就是他们想要的。然而，世界上绝大多数人使用预编译的二进制文件，因为它们方便、节省时间以及许多其他原因。

CMake 不会让你陷入困境 - 它自带了所有必要的组件。CPack 正是为此目的而构建的，用于 **为不同平台创建包**：压缩档案、可执行安装程序、向导、NuGet 包、MacOS 捆绑包、DMG 包、RPM 等等。

CPack 的工作方式与 CMake 非常相似：它使用 CMake 语言进行配置，并且有许多包生成器可供选择（不要将它们与 CMake 构建系统生成器混淆）。我们将在 *第十一章* 中详细介绍，因为这是一个相当庞大的工具，用于 CMake 项目的最后阶段。

### CMake-GUI

CMake for Windows 附带了一个 GUI 版本，用于配置先前准备好的项目的构建过程。对于 Unix-like 平台，有一个使用 QT 库构建的版本。Ubuntu 在 `cmake-qt-gui` 包中提供了它。

要访问 CMake-GUI，请运行 `cmake-gui` 可执行文件。

![图 1.4：CMake GUI：使用 Visual Studio 2019 生成器的构建系统配置阶段](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/mdn-cmk-cpp/img/file3.jpg)

图 1.4：CMake GUI：使用 Visual Studio 2019 生成器的构建系统配置阶段

GUI 应用程序实际上是为你的应用程序用户提供的便利工具，因为那里的选项相当有限。对于不熟悉命令行并更喜欢基于窗口的界面的用户来说，它可能会有所帮助。

> **不推荐**
> 
> 我绝对推荐 GUI 给追求便利的终端用户，但作为程序员，我避免引入任何手动、阻塞的步骤，这些步骤每次构建程序时都需要点击表单。这对于持续集成管道中的构建自动化尤其重要。这些工具需要无头应用程序，因此可以在没有用户交互的情况下完全执行构建。

### CCMake

`ccmake` 可执行文件是 CMake 在 Unix-like 平台上的 `curses` 接口（在 Windows 上不可用）。它不是 CMake 包的一部分，因此用户必须单独安装它。

命令适用于 Debian/Ubuntu 系统：

```cpp
$ sudo apt-get install cmake-curses-gui
```

项目配置设置可以通过这个 GUI 进行交互式指定。当程序运行时，终端底部会提供简短的说明。

#### 语法 CCMake 命令

```cpp
ccmake [<options>]
ccmake {<path-to-source> | <path-to-existing-build>}
```

CCMake 使用与 `cmake` 相同的选项集。

![图 1.5：ccmake 中的配置阶段](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/mdn-cmk-cpp/img/file4.jpg)

图 1.5：ccmake 中的配置阶段

与图形化 GUI 一样，这种模式相当有限，旨在供经验较少的用户使用。如果你使用的是 Unix 机器，我建议你快速浏览一下，然后更快地继续前进。

## 浏览项目文件

CMake 使用相当多的文件来管理其项目。在我们开始修改这些文件的内容之前，让我们对每个文件的作用有一个大致的了解。这不仅是一种良好的实践，而且随机文件中的更改很容易丢失。您知道，即使文件包含 CMake 语言命令 - 也不能确定它是为开发人员编辑的。有些文件是生成的，供后续工具使用，在那里所做的工作可能会在某个阶段被覆盖。其他文件是为高级用户准备的，以调整您的项目以满足他们的个人需求。最后，有一些临时文件在特定上下文中提供有价值的信息。本节还将告诉您哪些文件应该在版本控制系统的忽略文件中。

### 源代码树

这是您的项目将存在的目录（也称为**项目根目录**）。它包含所有 C++源文件和 CMake 项目文件。

以下是关键要点：

+   需要在顶层目录中提供一个`CMakeLists.txt`配置文件

+   应该使用版本控制系统（或 VCS）如 git 来管理它。

+   您可以通过`cmake`命令的`-S`参数提供此目录的路径。

+   避免硬编码任何绝对路径到它 - 您的用户可能将其存储在其他地方。

### 构建树

CMake 使用此目录来存储在构建过程中生成的所有内容：项目产物、临时配置、缓存、构建日志以及您的本地构建工具将创建的任何内容。此目录的其他名称包括：**构建根目录**和**二进制树**。

关键要点：

+   您的二进制文件将在此处创建：可执行文件和库，以及用于最终链接的对象文件和存档。

+   不要将此目录添加到您的 VCS 中 - 它是特定于您的系统的。如果您决定将其放在源代码树中 - 请确保将其添加到 VCS 忽略文件中。

+   CMake 推荐**源码外构建**，即在所有源文件之外的目录中生成构建产物的构建方式。这样我们可以避免在我们的项目源代码树中污染临时、系统特定的文件（或**源码内构建**）。

+   使用`-B`参数指定，或者在提供源代码路径的情况下作为`cmake`命令的最后一个参数：`cmake -S ../project ./`

+   `建议项目提供一个安装步骤，将最终产物放置在系统中的正确位置，以便可以删除用于构建的所有临时文件。`

### 列出文件

包含 CMake 语言的文件称为 Listfiles，可以通过调用`include()`和`find_package()`，或间接使用`add_subdirectory()`来相互包含。

+   CMake 并不强制这些名称的一致性，但它们通常具有`.cmake`扩展名。

+   非常重要的命名例外是一个名为`CMakeLists.txt`的文件，这是在配置步骤中首先执行的文件，并且需要在源代码树的顶部。

+   CMake 遍历源树并包含不同的列表文件时，会设置以下变量：`CMAKE_CURRENT_LIST_DIR`，`CMAKE_CURRENT_LIST_FILE`，`CMAKE_PARENT_LIST_FILE`，`CMAKE_CURRENT_LIST_LINE`

### CMakeLists.txt

CMake 项目使用`CMakeLists.txt`列表文件进行配置。您需要在源树的根目录中至少提供一个。这种顶级文件是 CMake 配置步骤中第一个被执行的文件，并且应至少包含两个命令：

+   `cmake_minimum_required(VERSION <x.xx>)` 设置预期的 CMake 版本（并隐式告诉 CMake 应用哪些策略来处理遗留行为）。

+   `project(<name> <OPTIONS>)` 用于命名项目（稍后在`PROJECT_NAME`变量中可用），并指定配置它的选项（我们将在下一章中更多地讨论这一点）。

随着您的软件增长，您可能希望将其划分为可以单独配置和推理的小单元。CMake 通过子目录的概念支持这一点，以及它们自己的`CMakeLists.txt`文件。您的项目结构可能与此示例类似：

```cpp
CMakeLists.txt
api/CMakeLists.txt
api/api.h
api/api.cpp
```

然后可以使用一个非常简单的`CMakeLists.txt`将所有内容整合在一起：

#### CMakeLists.txt

```cpp
cmake_minimum_required(VERSION 3.20)
project(app)
message("Top level CMakeLists.txt")
add_subdirectory(api)
```

项目的主要方面在顶级文件中涵盖：管理依赖项、声明要求、环境检测等。在此文件中，我们还将有一个`add_subdirectory(api)`命令，以包含来自`api`目录的另一个`CMakeListst.txt`，以执行我们应用程序 API 部分的具体步骤。

### CMakeCache.txt

缓存变量将从`listfiles`生成，并在首次运行配置阶段时存储在`CMakeCache.txt`中。此文件位于构建树的根目录中，并且具有相当简单的格式：

```cpp
# This is the CMakeCache file.
# For build in directory: c:/Users/rapha/Desktop/CMake/empty_project/build
# It was generated by CMake: C:/Program Files/CMake/bin/cmake.exe
# You can edit this file to change values found and used by cmake.
# If you do want to change a value, simply edit, save, and exit the editor.
# The syntax for the file is as follows:
# KEY:TYPE=VALUE
# KEY is the name of a variable in the cache.
# TYPE is a hint to GUIs for the type of VALUE, DO NOT EDIT TYPE!.
# VALUE is the current value for the KEY.
########################
# EXTERNAL cache entries
########################
//Flags used by the CXX compiler during DEBUG builds.
CMAKE_CXX_FLAGS_DEBUG:STRING=/MDd /Zi /Ob0 /Od /RTC1
// ... more variables here ...
########################
# INTERNAL cache entries
########################
//Minor version of cmake used to create the current loaded cache
CMAKE_CACHE_MINOR_VERSION:INTERNAL=19
// ... more variables here ...
```

从标题中的注释可以看出 - 这种格式相当直观。`EXTERNAL`部分中的缓存条目旨在供用户修改，而`INTERNAL`部分由 CMake 管理，不建议手动更改它们。

关键要点：

+   您可以手动管理此文件，通过调用`cmake`（参见*掌握命令行*部分中的*选项：缓存*），或通过`ccmake`/`cmake-gui`。

+   通过删除此文件，您可以将项目重置为默认配置 - 它将从列表文件中重新生成。

+   缓存变量可以从列表文件中读取和写入。有时变量引用评估有点复杂 - 关于这一点将在下一章中详细介绍。

### 配置文件包

CMake 生态系统的大部分是项目可以依赖的外部包。它们允许开发人员以无缝、跨平台的方式使用库和工具。支持 CMake 的包应提供配置文件，以便 CMake 知道如何使用它们。

我们将在*第十一章*中学习编写这些文件。同时，这里有一些有趣的细节：

+   配置文件包含有关如何使用库二进制文件、头文件和辅助工具的信息。有时它们会公开 CMake 宏供您在项目中使用。

+   使用`find_package()`命令来包含包。

+   CMake 描述包的文件被命名为`<PackageName>-config.cmake`和`<PackageName>Config.cmake`。

+   在使用包时，可以指定所需的包版本。CMake 将在关联的`<Config>Version.cmake`文件中检查这一点。

+   配置文件由支持 CMake 生态系统的包供应商提供。如果供应商没有提供这样的配置文件，可以用 Find 模块替换。

+   CMake 提供了一个包注册表，用于存储系统范围和每个用户的包。

### cmake_install.cmake, CTestTestfile.cmake, CPackConfig.cmake

这些文件是在生成步骤中由`cmake`可执行文件在构建树中生成的。因此，不应手动编辑它们。CMake 使用它们作为`cmake`安装操作、CTest 和 CPack 的配置。如果你正在进行源内构建（不推荐），那么可能是个好主意将它们添加到 VCS 忽略文件中。

### CMakePresets.json, CMakeUserPresets.json

当需要对缓存变量、选定的生成器、构建树路径等事项进行具体配置时，项目的配置可能会变得相当繁琐。尤其是在我们有多种构建项目的方式时。这时预设就派上用场了。

用户可以通过图形界面选择预设，或者使用命令行来`--list-presets`并使用`--preset=<preset>`选项为构建系统选择一个预设。你会在本章的*精通命令行*部分找到更多详细信息。

预设以相同的 JSON 格式存储在两个文件中：

+   `CMakePresets.json`旨在供项目作者提供官方预设

+   `CMakeUserPresets.json`专为那些希望根据自己的喜好定制项目配置的用户而设（将其添加到你的 VCS 忽略文件中）

预设是项目文件，因此它们的解释属于这里。但它们在项目中不是必需的，只有在完成初始设置后它们才变得有用，所以如果需要，可以自由跳到下一部分，稍后再回到这里。

#### chapter-01/02-presets/CMakePresets.json

```cpp
{
  "version": 1,
  "cmakeMinimumRequired": {
    "major": 3, "minor": 19, "patch": 3
  },
  "configurePresets": [ ],
  "vendor": {
    "vendor-one.com/ExampleIDE/1.0": {
      "buildQuickly": false
    }
  }
}
```

`CmakePresets.json`指定了以下根字段：

+   `version` - 必需，始终为`1`

+   `cmakeMinimumRequired` - 可选，指定 CMake 版本，具有三个字段的对象：`major`, `minor`, `patch`

+   `vendor` - 可选映射，包含供应商特定选项的外部工具，如 IDE，键值为供应商域名和斜杠分隔的路径。CMake 实际上忽略了这个字段。

+   `configurePresets` - 可选数组，包含可用的预设。

让我们向我们的`configurePresets`数组添加两个预设：

#### chapter-01/02-presets/CMakePresets.json : my-preset

```cpp
{
  "name": "my-preset",
  "displayName": "Custom Preset",
  "description": "Custom build - Ninja",
  "generator": "Ninja",
  "binaryDir": "${sourceDir}/build/ninja",
  "cacheVariables": {
    "FIRST_CACHE_VARIABLE": {
      "type": "BOOL", "value": "OFF"
    },
    "SECOND_CACHE_VARIABLE": "Ninjas rock"
  },
  "environment": {
    "MY_ENVIRONMENT_VARIABLE": "Test",
    "PATH": "$env{HOME}/ninja/bin:$penv{PATH}"
  },
  "vendor": {
    "vendor-one.com/ExampleIDE/1.0": {
      "buildQuickly": true
    }
  }
},
```

该文件支持树状结构，其中子预设从多个父预设继承属性。这意味着我们可以创建上述预设的副本，并且只覆盖我们需要的字段。下面是一个子预设可能的样子：

#### chapter-01/02-presets/CMakePresets.json : my-preset-multi

```cpp
{
  "name": "my-preset-multi",
  "inherits": "my-preset",
  "displayName": "Custom Ninja Multi-Config",
  "description": "Custom build - Ninja Multi",
  "generator": "Ninja Multi-Config"
}
```

> **注意**
> 
> CMake 文档仅将少数字段标记为明确必需。然而，还有一些其他标记为可选的字段，这些字段必须在预设中提供，或者从其父级继承。

预设定义为具有以下字段的地图：

+   `name` - **必需**字符串，用于标识预设。它必须是机器友好的，并且在两个文件中都是唯一的。

+   `hidden` - 可选的布尔值，用于从 GUI 和命令行列表中隐藏预设。这样的预设可以是另一个预设的父级，并且不需要提供除其名称之外的任何内容。

+   `displayName` - 可选的人类友好名称字符串

+   `description` - 可选字符串，用于描述预设

+   `inherits` - 可选字符串或预设名称数组，用于继承自其他预设。在发生冲突时，将优先使用较早预设的值，并且每个预设都可以自由覆盖任何继承的字段。此外，`CMakeUserPresets.json` 可以继承项目预设，但不能反向继承。

+   `vendor` - 可选的供应商特定值映射，遵循与根级别 `vendor` 字段相同的约定。

+   `generator` - **必需或继承**字符串，指定用于预设的生成器。

+   `architecture`、`toolset` - 可选字段，用于配置支持这些字段的生成器。每个字段可以简单地是一个字符串或一个具有 `value` 和 `strategy` 字段的对象，其中 `strategy` 可以是 `set` 或 `external`。配置为 `set` 的策略将设置值，并在生成器不支持该字段时产生错误。配置为 `external` 意味着该字段值是为外部 IDE 设置的，CMake 应该忽略它。

+   `binaryDir` - **必需或继承**字符串，提供构建树目录的路径（绝对路径或相对于源树的路径）。支持宏扩展。

+   `cacheVariables` - 可选的缓存变量映射，其中键表示变量名称。接受的值为：`null`、`"TRUE"`、`"FALSE"`、字符串值或具有可选 `type` 和必需 `value` 字段的对象。`value` 可以是字符串值、`"TRUE"` 或 `"FALSE"`。

    缓存变量继承采用联合操作，除非值被指定为 `null` - 在这种情况下，它保持未设置状态。字符串值支持宏扩展。

+   `environment` - 可选的环境变量映射，其中键表示变量名称。接受的值为：`null` 或字符串值。

    环境变量继承采用联合操作，除非值被指定为 `null` - 在这种情况下，它保持未设置状态。字符串值支持宏扩展，并且变量可以以任何顺序引用彼此，只要不存在循环引用。

以下宏被识别并进行评估：

+   `${sourceDir}` - 源树的路径

+   `${sourceParentDir}` - 源树父目录的路径

+   `${sourceDirName}` - `${sourceDir}` 的最后一个文件名组件，例如，对于 `/home/rafal/project`，它将是 `project`

+   `${presetName}` - 预设名称字段的值

+   `${generator}` - 预设的生成器字段值

+   `${dollar}` - 字面美元符号（$）

+   `$env{<variable-name>}` - 环境变量宏。如果定义了预设，它将返回变量的值，否则 - 从父环境返回值。请记住，预设中的变量名是区分大小写的（与 Windows 环境不同）。

+   `$penv{<variable-name>}` - 与$env 类似，但总是从父环境返回值。这允许解决预设环境变量中不允许的循环引用问题。

+   `$vendor{<macro-name>}` - 允许供应商插入自己的宏。

### 忽略 Git 中的文件

有许多版本控制系统，其中最流行的是 Git。每当我们开始一个新项目时，最好确保我们只将需要的文件检入到仓库中。如果我们只是将一些生成的、用户和临时文件添加到`.gitignore`文件中，项目卫生更容易维护。这样 - git 在构建新提交时会自动跳过它们。以下是我在项目中使用的文件：

#### chapter-01/01-hello/.gitignore

```cpp
# If you put build tree in the source tree add it like so:
build_debug/
build_release/
# Generated and user files
**/CMakeCache.txt
**/CMakeUserPresets.json
**/CTestTestfile.cmake
**/CPackConfig.cmake
**/cmake_install.cmake
**/install_manifest.txt
**/compile_commands.json
```

在项目中使用上述文件将为您、其他贡献者和用户提供更大的灵活性。

项目文件的未知领域现已绘制出来。有了这张地图，您很快就能编写自己的 listfiles、配置缓存、预设等。在启航于项目编写的广阔海洋之前 - 让我们看看还可以用 CMake 创建哪些其他类型的自包含单元。

## 发现脚本和模块

CMake 的工作主要集中在构建项目上，生产出的工件被其他系统消耗：CI/CD 管道、测试平台和部署到机器或工件存储库。然而，CMake 还启用了另外两个概念，您可以用其语言创建：脚本和模块。让我们更仔细地看看。

### 脚本

为了配置项目构建，CMake 提供了一个与平台无关的编程语言。它带有许多有用的命令。您可以使用这个工具编写随项目一起提供的脚本或完全独立的脚本。

将其视为跨平台工作的统一方式：不必在 Linux 上使用 bash 脚本，在 Windows 上使用批处理或 powershell 脚本 - 您可以有一个版本。当然，您可以引入外部工具，如 python、perl 或 ruby 脚本，但这又是另一个依赖项，增加了 C/C++项目的复杂性。是的，有时这是唯一能完成工作的方法，但大多数情况下，我们可以用更简单的方法来解决问题。

我们已经从“掌握命令行”部分知道，我们可以使用`-P`选项执行脚本：`cmake -P script.cmake`，但是提供给脚本文件的实际要求是什么？并不多：脚本可以像您喜欢的那样复杂或是一个空文件，但是建议在脚本的开头调用`cmake_minimum_required()`命令，以给 CMake 提示它应该对具有遗留行为的命令应用哪些策略。

#### chapter-01/03-script/script.cmake

```cpp
# An example of a script
cmake_minimum_required(VERSION 3.20.0)
message("Hello world")
file(WRITE Hello.txt "I am writing to a file")
```

在运行脚本时，CMake 不会执行任何常规阶段（配置、生成），也不会使用缓存。由于脚本中没有源/构建树的概念，通常持有这些路径引用的变量将包含当前工作目录：`CMAKE_BINARY_DIR`、`CMAKE_SOURCE_DIR`、`CMAKE_CURRENT_BINARY_DIR`和`CMAKE_CURRENT_SOURCE_DIR`。

愉快的脚本编写。

### 实用模块

CMake 项目可以使用外部模块来增强其功能。模块是用 CMake 语言编写的，包含宏定义、变量和执行各种功能的命令。它们从相当复杂的脚本（`CPack`和`CTest`也提供它们的模块！）到相当简单的脚本，如`AddFileDependencies`或`TestBigEndian`。

CMake 发行版附带了近 90 个不同的实用模块。如果这还不够，你可以通过浏览这样的精选列表从互联网上下载更多：[`github.com/onqtam/awesome-cmake`](https://github.com/onqtam/awesome-cmake)，或者从头开始编写一个模块。

要使用实用模块，我们需要调用一个`include(<MODULE>)`命令。这里有一个简单的项目示例展示了这一操作：

#### chapter-01/04-module/CMakeLists.txt

```cpp
cmake_minimum_required(VERSION 3.20.0)
project(ModuleExample)
include (TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
 message("BIG_ENDIAN")
else()
 message("LITTLE_ENDIAN")
endif()
```

我们将学习哪些模块可用，因为它们与当前主题相关。如果你好奇，可以在这里找到捆绑模块的完整列表：[`cmake.org/cmake/help/latest/manual/cmake-modules.7.html`](https://cmake.org/cmake/help/latest/manual/cmake-modules.7.html)。

### 查找模块

在关于*包配置文件*的部分中，我提到了 CMake 有一个机制来查找属于不支持 CMake 且不提供 CMake 配置文件（或没有）的外部依赖的文件。这就是查找模块的作用。CMake 提供了超过 150 个模块，用于在系统中定位不同的包。与实用模块一样，网上有更多的查找模块可用，并且作为最后的手段，你可以编写自己的查找模块。

你可以通过调用`find_package()`命令并提供相关包的名称来使用它们。这样的查找模块将进行一场小小的捉迷藏游戏，检查软件所在的所有已知位置。然后，它定义变量（在模块手册中指定），允许构建针对该依赖项。

例如，`FindCURL`模块正在搜索流行的*客户端 URL*库，并定义以下变量：`CURL_FOUND`、`CURL_INCLUDE_DIRS`、`CURL_LIBRARIES`、`CURL_VERSION_STRING`。

*第七章*深入介绍了查找模块。

## 总结

现在你已经了解了 CMake 是什么以及它是如何工作的：CMake 工具家族的关键组件是什么，以及如何在各种系统上安装它们。作为一个真正的资深用户，你了解通过命令行运行 CMake 的所有方式：生成构建系统、构建项目、安装、运行脚本、命令行工具和打印帮助。你知道 CTest、CPack 和 GUI 应用程序。这将帮助你以正确的视角创建项目：为用户和其他开发者。你还学习了构成项目的要素：目录、listfiles、配置、预设和辅助文件，以及在你的 VCS 中应该忽略什么。最后，你偷偷瞥见了其他非项目文件：独立脚本和模块。

接下来是对 CMake 编程语言的深入探讨。它将允许你编写自己的 listfiles，并为你打开编写第一个脚本、项目和模块的大门。

## 进一步阅读

如需更多信息，您可以参考以下链接：

+   官方 CMake 网页及其文档：[`cmake.org/`](https://cmake.org/)

+   单配置生成器：[`cgold.readthedocs.io/en/latest/glossary/single-config.html`](https://cgold.readthedocs.io/en/latest/glossary/single-config.html)

+   CMake GUI 中阶段的分离：[`stackoverflow.com/questions/39401003/why-there-are-two-buttons-in-gui-configure-and-generate-when-cli-does-all-in-one`](https://stackoverflow.com/questions/39401003/why-there-are-two-buttons-in-gui-configure-and-generate-when-cli-does-all-in-one)


# 第二章：CMake 语言

编写 CMake 语言有点棘手。当你第一次阅读列表文件时——你可能会觉得那里的语言如此简单，以至于不需要任何特殊的培训或准备。这种方法往往转化为实际尝试引入更改和实验代码，而不彻底理解它是如何工作的。我们，程序员通常非常忙碌，并且非常热衷于通过实践学习、猜测等方式来解决这些问题。解决技术问题的这种“技术”被称为*巫毒编程*。

CMake 提供了这种不幸的简单性，它创造了一种一切都是理所当然的错觉。在我们完成了小的添加、修复、hack 或“快速修复”之后——我们意识到有些事情并不完全正常。花在调试上的时间往往比实际更好地研究主题要长。幸运的是，这不是我们的命运——因为在我们面前的章节涵盖了大部分这种关键知识。

我们不仅将理解 CMake 语言的基本构建块：注释、命令、变量和控制结构，还将结合一些关于干净、现代 CMake 的背景信息。你会发现：CMake 让你处于一个独特的地位：一方面，你扮演着构建工程师的角色。你需要理解编译器、平台以及它们之间的所有复杂性。另一方面：你是一名开发者——你在编写生成构建系统的代码。编写好的代码是困难的，需要在多个层面上同时思考：它应该有效、易于阅读、易于推理、扩展和维护。这正是我们在这里要讨论的内容。

最后，我们将介绍一些最有用和最常见的命令。那些不经常使用的命令，你会在*附录*中找到（完整的字符串、列表和文件操作命令参考）。

在本章中，我们将涵盖以下主要主题：

+   CMake 语法基础

+   使用变量

+   使用列表

+   理解控制结构

+   有用的命令

## 技术要求

你可以在 GitHub 上找到本章中出现的代码文件，地址是[`github.com/PacktPublishing/Modern-CMake-for-Cpp`](https://github.com/PacktPublishing/Modern-CMake-for-Cpp)

## CMake 语法基础

编写 CMake 代码非常类似于编写任何其他命令式语言：从上到下、从左到右执行行，偶尔进入一个包含的文件或调用的函数。根据模式（参见*第一章 - 命令行*），执行从源树的根文件（`CMakeLists.txt`）或作为`cmake`参数传递的`.cmake`脚本文件开始。

正如我们在上一章中讨论的，脚本支持大多数 CMake 语言（项目相关功能除外）。因此，它们非常适合早期练习语法本身，这就是我们在这里使用它们的原因。在熟悉编写基本列表文件后 - 我们将开始准备实际的项目文件（在下一章）。提醒一下 - 脚本可以通过以下命令行运行：

`cmake -P script.cmake`

> **注意**
> 
> CMake 支持 7 位 ASCII 文本文件，以便在所有平台上实现可移植性。您可以使用`\n`或`\r\n`行结束符。CMake 3.0 以上版本支持带有可选字节顺序标记的 UTF-8，CMake 3.2 以上版本支持 UTF-16。

CMake 列表文件中的所有内容要么是命令调用，要么是注释。

### 注释

（注释有两种类型：单行注释和括号（多行）注释，就像在 C++中一样。但与 C++不同的是，括号注释可以嵌套。让我展示一下语法：

```cpp
# single-line comments start with a hash sign "#"
# they can be placed on an empty line
message("Hi"); # or after a command like here.
#[=[ 
bracket comment
  #[[
    nested bracket comment
  #]]
#]=]
```

多行注释因其符号而得名，它们以一个开方括号、任意数量的等号和另一个括号开始：`[=[`。要关闭方括号注释，**请使用相同数量的**等号，并反向括号，如下所示：`]=]`。

在开方括号标记前加上`#`是可选的，并允许通过在方括号注释的第一行添加另一个`#`来快速取消注释多行注释，如下所示：

```cpp
##[=[ this is a single-line comment now
no longer commented
  #[[
    still, a nested comment
  #]]
#]=] this is a single-line comment now
```

这是一个巧妙的技巧，但在我们的 CMake 文件中何时以及如何使用注释？由于编写列表文件本质上是在编程，因此将最佳编码实践引入它们也是一个好主意。遵循这些实践的代码通常被称为“干净” - 这是多年来由软件开发大师如罗伯特·C·马丁、马丁·福勒和其他许多作者创造的术语。被认为是有帮助和有害的常常存在很大争议，正如你所猜测的 - 注释作为主题出现不止一次。

一切都应根据具体情况进行判断，但普遍认同的指导原则是，好的注释至少提供以下一项：

+   **信息**，解开复杂性，如正则表达式模式或格式化字符串

+   **意图**，从实现或接口中不明显

+   **澄清**，解释无法轻易重构或更改的概念

+   **后果警告**，特别是在可能破坏其他事物的代码周围

+   **强调**，强调难以用代码表达的想法的重要性

+   **法律条款**。一种必要的恶，通常不是程序员的领域

如果可以，避免注释，用更好的命名、重构或更正代码来代替。如果可能，避免以下类型的注释：

+   **强制性**，添加以完整性，但不是真正重要

+   **冗余**，重复代码中已经清楚写明的内容

+   **误导性**，过时或不正确，因为它们没有跟随代码变化

+   **日志**，记录更改的内容和时间（使用版本控制系统进行此操作）

+   **分隔符**，标记部分或以其他方式

不带注释编写优雅的代码是困难的，但它能提升读者的体验。由于我们花在阅读上的时间比写作多 - 我们应该坚持编写可读性强的代码，而不是快速编写的代码。我建议查看本章末尾的*进一步阅读*部分，以获取有关清洁代码的一些好参考资料。如果你对注释特别感兴趣 - 你会在我的许多 YouTube 视频中找到一个深入探讨这个主题的链接。

### 命令调用

是时候采取行动了！调用命令是 CMake listfiles 的基础。要执行命令，你必须提供其名称和括号，在其中你可以包含一个空格分隔的**命令参数**列表。

![图 2.1：命令示例](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/mdn-cmk-cpp/img/file5.png)

图 2.1：命令示例

命令名称不区分大小写，但 CMake 社区有一个约定，即在名称中使用`snake_case`（小写字母单词用下划线连接）。你还可以定义自己的命令 - 我们将在本章的*控制结构*部分介绍这一点。

与 C++相比，特别引人注目的是**CMake 中的命令调用不是表达式**。你不能将另一个命令作为参数提供给被调用的命令，因为*所有内容*在括号内都被解释为该命令的参数。

更令人愤怒的是，CMake 命令在调用结束时不需要分号。这可能是因为源文件的每一行可以包含**一个命令调用**，后面可以跟一个可选的单行注释。或者，整行必须是括号注释的一部分。所以，这些是唯一允许的格式：

```cpp
command(argument1 "argument2" argument3) # comment
[[ 
multiline comment ]] 
```

在括号注释后放置命令是不允许的：

```cpp
[[ bracket 
]] command()
```

删除注释、空格和空行后 - 我们得到一个命令调用列表。这创造了一个有趣的视角：CMake 语法真的很简单，但这就足够了吗？我们如何处理变量？或者如何控制执行流程？

CMake 提供了上述命令以及更多。为了使事情变得更容易，我们将随着我们通过不同的主题介绍相关的命令，它们可以分为三个类别：

+   脚本命令始终可用，它们改变命令处理器的状

+   项目命令在项目中可用，它们操作项目状态和构建目标

+   CTest 命令在 CTest 脚本中可用，它们管理测试

本章将介绍最常用的脚本命令（因为它们在项目中也非常有用）。项目和 CTest 命令将在后续章节中讨论，因为我们将介绍构建目标的概念（*第三章，设置你的第一个 CMake 项目*）和测试框架（*第八章，测试框架*）。

实际上，每个命令都依赖于语言的其他元素来发挥作用：变量、条件语句，最重要的是：命令行参数。让我们看看应该如何使用它们。

### 命令参数

许多命令需要以空格分隔的参数来参数化它们的行为。正如您在图 2.1 中看到的，参数周围的引号有些奇怪。一些参数有引号，而其他参数没有 - 这是怎么回事？

在底层，CMake 唯一识别的类型是字符串。这就是为什么每个命令都期望为其参数提供零个或多个字符串。但是，普通的静态字符串并不是很有用，特别是当我们不能嵌套命令调用时。这就是参数发挥作用的地方：CMake 将对每个参数求值为静态字符串，然后将它们传递给命令。求值意味着字符串插值，或者简单地说：用另一个值替换字符串的部分。这可能意味着替换*转义序列*，扩展**变量引用**（也称为变量插值）和解包列表。

根据上下文，我们可能希望根据需要启用这种求值，为此，CMake 提供了三种类型的参数：

+   括号参数

+   引号参数

+   未引用的参数

每种类型都提供不同级别的求值，并且有一些小的怪癖。

#### 括号参数

括号参数不会被求值，因为它们用于**原样传递多行字符串**，作为命令的单个参数。这意味着它将包含制表符和换行符等空白字符。

这些参数的结构与注释完全相同：以`[=[`打开并以`]=]`闭合，其中等号在标记中的数量必须匹配（跳过等号也可以）。与注释的唯一区别是 - 您不能嵌套括起来的参数。

这是使用`message()`命令的此类参数的示例，该命令在屏幕上打印所有传递的参数：

#### chapter02/01-arguments/bracket.cmake

```cpp
message([[multiline
bracket
argument
]])
message([==[
  because we used two equal-signs "=="
  following is still a single argument:
  { "petsArray" = [["mouse","cat"],["dog"]] }
]==])
```

在上面的示例中，我们可以看到不同形式的括号参数。第一个跳过等号。请注意，将闭合标签放在单独的行中在输出中显示为空行：

```cpp
$ cmake -P chapter02/01-arguments/bracket.cmake
multiline
bracket
argument
  because we used two equal-signs "=="
  following is still a single argument:
  { "petsArray" = [["mouse","cat"],["dog"]] }
```

第二种形式在我们传递包含双括号`]]`（突出显示）的文本时很有用，因此它们不会被解释为参数的闭合。

这种括号参数的使用有限 - 通常用于包含较长的文本块。在大多数情况下，我们需要更动态的内容，如引号参数。

#### 引号参数

第二种参数类似于常规的*C++字符串*：它们将多个字符（包括空格）组合在一起，并将扩展*转义序列*。与*C++字符串*一样，它们以双引号字符`"`打开和关闭，要使用文字引号，必须用反斜杠转义它：`\"`。其他广为人知的转义序列也得到支持：`\\`表示文字反斜杠，`\t`是制表符，`\n`是换行符，`\r`是回车符。

这与*C++字符串*的相似之处到此为止。相比之下，加引号的参数可以跨越多行，并且它们会插值变量引用。可以将它们视为内置了*C*中的`sprintf`或*C++20*中的`std::format`。要在参数中插入变量引用，请将变量名包裹在如下标记中：`${name}`。我们将在*变量*部分详细讨论变量引用。

让我们尝试这些参数的实际应用：

#### 第二章/01-参数/quoted.cmake

```cpp
message("1\. escape sequence: \" \n in a quoted argument")
message("2\. multi...
line")
message("3\. and a variable reference: ${CMAKE_VERSION}")
```

你能猜出上述脚本的输出会有多少行吗？

```cpp
$ cmake -P chapter02/01-arguments/quoted.cmake
1\. escape sequence: "
 in a quoted argument
2\. multi...
line
3\. and a variable reference: 3.16.3
```

没错 - 我们有一个转义的引号字符、转义的换行符和一个文字换行符 - 它们都将被打印在输出中。我们还访问了一个内置变量`CMAKE_VERSION`，我们可以看到它在最后一行正确地插值了。

#### 未加引号的参数

最后一种参数类型在编程世界中确实有点罕见。我们已经习惯了字符串必须以某种方式分隔：使用单引号、双引号或反引号。CMake 偏离了这一惯例，引入了未加引号的参数。有人可能会争辩说，省略定界符更容易阅读，就像跳过分号一样。这是真的吗？我会让你形成自己的观点。

未加引号的参数同时评估*转义序列*和变量引用。但是要小心分号`;`：它在这里被视为分隔符。CMake 会将包含它的参数分割成多个参数。如果需要使用它，请用反斜杠转义它（`\;`）。这就是 CMake 管理列表的方式。我将在*列表*部分详细解释这一点。

你可能会发现这些参数是最令人困惑的工作，所以这里有一些视觉帮助来澄清这些参数是如何划分的：

![图 2.2：转义序列使得单独的标记被解释为单个参数](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/mdn-cmk-cpp/img/file6.png)

图 2.2：转义序列使得单独的标记被解释为单个参数

> **问题**
> 
> 为什么一个值作为单个参数传递还是多个参数传递会有所不同？
> 
> 一些 CMake 命令会逐个消耗参数。如果你的参数意外地被分隔开，你将会得到难以调试的错误。

未加引号的参数不能包含未转义的引号`"`, 井号`#`和反斜杠`\`。如果这些规则还不够：括号`()`只有在其形成正确、匹配的配对时才被允许。也就是说：你必须从一个开括号开始，并在结束命令参数列表之前将其闭合。

让我们来看看上述所有规则的示例：

#### 第二章/01-参数/unquoted.cmake

```cpp
message(a\ single\ argument)
message(two arguments)
message(three;separated;arguments)
message(${CMAKE_VERSION})  # a variable reference
message(()()())            # matching parentheses 
```

上述的输出会是什么？

```cpp
$ cmake -P chapter02/01-arguments/unquoted.cmake
a single argument
twoarguments
threeseparatedarguments
3.16.3
()()() 
```

即使是像`message()`这样简单的命令，对于分隔的未加引号的参数也非常挑剔：

+   在**单个参数**中的空格在明确转义时被正确打印

+   然而**twoarguments**和**threeseparatearguments**被“粘合”在一起 - 因为`message()`本身不会添加任何空格。

既然我们了解了如何处理 CMake 参数的复杂性和特殊性——我们准备好探讨下一个有趣的课题：在 CMake 中处理各种变量。

## 处理变量

CMake 中的变量是一个出人意料的复杂主题。不仅存在三种类别的变量：普通、缓存和环境变量，而且它们还存在于不同的作用域中，有着特定的规则来决定一个作用域如何影响另一个作用域。对这些规则的糟糕理解往往是错误和头痛的来源。我建议你仔细研究这一部分，并确保在继续之前你已经掌握了所有概念。

让我们从关于 CMake 变量的关键事实开始：

+   变量名是区分大小写的，并且几乎可以使用任何字符构建。

+   所有变量在内部都存储为字符串，即使某些命令可以将它们解释为其他类型的值（甚至是列表！）。

+   基本的变量操作命令是`set()`和`unset()`，但还有其他命令可以影响变量，如`string()`和`list()`。

要设置一个变量，我们只需调用`set()`，提供其名称和值：

#### chapter02/02-variables/set.cmake

```cpp
set(MyString1 "Text1")
set([[My String2]] "Text2")
set("My String 3" "Text3")
message(${MyString1})
message(${My\ String2})
message(${My\ String\ 3})
```

如你所见，使用括号和引号参数允许变量名中包含空格。然而，在引用时，我们必须用反斜杠`\`转义空格。因此，建议在变量名中仅使用字母数字字符、`-`和`_`。

还要避免使用以`CMAKE_`、`_CMAKE_`、下划线`_`开头的保留名称（大写、小写或混合大小写），后跟任何 CMake 命令的名称。

> **注意**
> 
> `set()`命令接受变量的纯文本名称作为第一个参数，但`message()`使用包裹在`${}`语法中的变量引用。如果我们向`set()`命令提供包裹在`${}`语法中的变量会发生什么？为了回答这个问题，我们需要更好地理解变量引用。

要取消设置一个变量，我们可以使用`unset()`，如下所示：`unset(MyString1)`。

### 变量引用

在*命令参数*部分，我已简要提及了引用——因为它们对于带引号和不带引号的参数都会被评估。我们了解到，要创建对已定义变量的引用，我们需要使用这样的语法：`message(${MyString1})`。

在评估时，CMake 将遍历作用域栈（我稍后会解释），并用值或空字符串替换`${MyString1}`（如果没有找到变量，则不会报告错误）。这个过程称为变量评估、展开或插值。

这种插值是以由内而外的方式进行的，这意味着两件事：

+   首先，如果遇到这样的引用：`${MyOuter${MyInner}}`，CMake 会尝试先评估`MyInner`，而不是寻找名为`MyOuter${MyInner}`的变量。

+   其次：如果`MyInner`变量成功展开——CMake 将重复展开过程，直到没有进一步的展开是可能的。

让我们考虑以下变量的一个例子：

+   `MyInner` 的值为 `Hello`

+   `MyOuter` 的值为 `${My`

当我们调用命令：`message("${MyOuter}Inner} World")`时，我们将收到的输出是`Hello World,`，这是因为`${MyOuter}`被替换为字面值`${My`，它与顶层的`Inner}`结合，创建了另一个变量引用：`${MyInner}`。

CMake 将完全执行这种扩展，然后将生成的值作为参数传递给命令。这就是为什么当我们调用`set(${MyInner} "Hi")`时，我们实际上并没有改变`MyInner`变量，而是改变了`Hello`变量。CMake 将`${MyInner}`扩展为`Hello`，并将该字符串作为第一个参数传递给`set()`命令以及新值`Hi`。这种情况往往不是我们想要的。

变量引用在涉及变量类别时的工作方式有点特殊，但总的来说：

+   `${}`语法用于引用普通*或缓存变量*

+   `$ENV{}`语法用于引用环境变量

+   `$CACHE{}`语法用于引用缓存变量

没错，使用`${}`你可能从一个类别或另一个类别获取值，我将在*Scope*部分解释这一点。但首先让我们介绍其他类别的变量，这样我们就能清楚地了解它们是什么。

> **注意**
> 
> 请记住，你可以通过命令行在`--`标记后传递参数给脚本。
> 
> 值将位于`CMAKE_ARGV<n>`中，传递的参数数量位于`CMAKE_ARGC`中。

### 使用环境变量

这是最不复杂的变量类别。CMake 对用于启动`cmake`进程的环境中的变量进行复制，并将它们在一个单一的全局范围内提供。要引用这些变量，请使用`$ENV{<name>}`语法。

CMake 还允许你`set()`和`unset()`这些变量，但这些更改只会对运行中的`cmake`进程的本地副本生效，而不是实际的系统环境，这些更改对后续的构建或测试运行是不可见的。

要修改或创建变量，请使用`set(ENV{<variable>} <value>)`命令，如下所示：

```cpp
set(ENV{CXX} "clang++")
```

要清除环境变量，请使用`unset(ENV{<variable>})`，如下所示：

```cpp
unset(ENV{VERBOSE})
```

有一些环境变量会影响 CMake 的行为，控制构建和 CTest。CXX 是其中之一 - 它指定用于编译 C++文件的可执行文件。我们将在它们变得相关时介绍它们。完整的列表可在文档中找到：

[`cmake.org/cmake/help/latest/manual/cmake-env-variables.7.html`](https://cmake.org/cmake/help/latest/manual/cmake-env-variables.7.html)

如果你使用环境变量作为命令的参数，这些值将在生成构建系统时被插值。这意味着它们将被烘焙到构建树中，并且在构建阶段更改环境不会有任何影响。

以以下项目文件为例：

#### 章节 02/03-环境/CMakeLists.txt

```cpp
cmake_minimum_required(VERSION 3.20.0)
project(Environment)
message("generated with " $ENV{myenv})
add_custom_target(EchoEnv ALL COMMAND echo "myenv in build is" $ENV{myenv})
```

上述项目有两个步骤：它将在配置期间打印`myenv`环境变量，并通过`add_custom_target()`添加一个构建步骤，该步骤在构建过程中回显同一变量。我们可以通过一个使用配置阶段和构建阶段不同值的 bash 脚本来测试会发生什么：

#### 第二章/03-环境/build.sh

```cpp
#!/bin/bash
export myenv=first
echo myenv is now $myenv
cmake -B build .
cd build
export myenv=second
echo myenv is now $myenv
cmake --build .
```

运行上述命令可以清楚地看到，配置期间设置的值在生成的构建系统中得以保留：

```cpp
$ ./build.sh | grep -v "\-\-"
myenv is now first
generated with first
myenv is now second
Scanning dependencies of target EchoEnv
myenv in build is first
Built target EchoEnv
```

### 使用缓存变量

我们首次提到缓存变量是在讨论`cmake`的命令行选项时，在第一章中。本质上，它们是存储在构建树中的`CMakeCache.txt`文件中的持久化变量。它们包含在项目配置阶段收集的信息——既来自系统（编译器、链接器、工具的路径；以及其他），也来自用户通过 GUI。缓存变量在脚本中不可用（因为没有`CMakeCache.txt`），它们只存在于项目中。

缓存变量可以使用`$CACHE{<name>}`语法引用。

要设置缓存变量，请使用带有以下语法的`set()`：

`set(<variable> <value> CACHE <type> <docstring> [FORCE])`

如您所见，与普通变量的`set()`相比，有一些新的必需参数，还引入了一些第一个关键字：`CACHE`和`FORCE`。

将`CACHE`指定为`set()`的参数意味着我们打算更改配置阶段提供的内容，并要求提供变量`<type>`和`docstring`。这是因为这些变量可由用户配置，GUI 需要知道如何显示它们。接受的类型包括：

+   `BOOL` - 布尔 ON/OFF 值。GUI 将显示一个复选框。

+   `FILEPATH` - 磁盘上的文件路径。GUI 将打开一个文件对话框。

+   `PATH` - 磁盘上的目录路径。GUI 将打开一个目录对话框。

+   `STRING` - 一行文本。如果设置了`STRINGS`缓存条目属性（可以使用`set_property()`完成），GUI 将提供一个文本字段或一个下拉选择。

+   `INTERNAL` - 一行文本。GUI 会跳过内部条目。它们可用于在多次运行之间持久存储变量。使用此类型意味着 FORCE。

`<doctring>`只是一个标签，GUI 将在字段旁边显示该标签，以向用户提供有关此设置的更多详细信息。即使是`INTERNAL`类型，这也是必需的。

设置缓存变量在一定程度上遵循环境变量的规则：值仅在 CMake 当前执行期间被覆盖。请看这个例子：

```cpp
set(FOO "BAR" CACHE STRING "interesting value")
```

上述调用如果没有在缓存中存在变量，则没有永久效果。但是，如果缓存中不存在值或指定了可选的`FORCE`参数，则该值将被持久化：

```cpp
set(FOO "BAR" CACHE STRING "interesting value" FORCE)
```

设置缓存变量有一些不明显的含义。即：任何同名的普通变量都将被移除。我们将在下一节中找出原因。

提醒一下，缓存变量也可以从命令行管理，请查看第一章中的相应部分。

### 如何在 CMake 中正确使用变量作用域

变量作用域可能是整个概念中最难的部分。也许是因为我们习惯了在支持命名空间和作用域操作符的更高级语言中事物是如何完成的。CMake 没有这些机制，所以它以自己有点特定的方式处理这个问题。

为了澄清：变量作用域作为一个通用概念，旨在分离不同的抽象层次，以便当用户定义的函数被调用时 - 在该函数中设置的变量是局部的。这些局部变量即使与全局变量名称完全相同，也不会影响全局作用域。如果需要，函数应该具有对全局变量的读/写访问权限。这种变量（或作用域）的分离必须在多个层次上工作 - 当一个函数调用另一个函数时，适用相同的分离规则。

CMake 支持两种作用域：

+   **函数作用域**：当使用 `function()` 定义的自定义函数被执行时

+   **目录作用域**：当从 `add_subdirectory()` 命令执行嵌套目录中的 `CMakeLists.txt` 列表文件时

我们将在本书后面介绍上述命令，首先我们需要了解变量作用域的概念是如何实现的。当创建嵌套作用域时，CMake 只是用当前作用域中所有变量的副本填充它。后续命令将影响这些副本。但是，一旦嵌套作用域完成 - 所有副本都会被删除，原始的父作用域会被恢复。

让我们考虑以下场景：

+   父作用域将变量 `VAR` 设置为 `ONE`

+   嵌套作用域开始，`VAR` 被打印到控制台

+   `VAR` 被设置为 `TWO`，`VAR` 被打印到控制台

+   嵌套作用域结束，`VAR` 被打印到控制台

控制台的输出将如下所示：`ONE`，`TWO`，`ONE`。这是因为复制变量 `VAR` 在嵌套作用域结束后被丢弃。

CMake 中作用域的工作方式具有有趣的含义，这在其他语言中并不常见。如果在嵌套作用域中执行时 `unset()` 一个在父作用域中创建的变量 - 它将在嵌套作用域中消失。当嵌套作用域完成时 - 变量将恢复到其先前的值。

这使我们了解了变量引用的行为，以及 `${}` 语法。每当我们尝试访问普通变量时，CMake 将访问当前作用域的变量，如果定义了具有该名称的变量 - 它将返回其值。到目前为止，一切都很好。然而，当 CMake 找不到具有该名称的变量（它不存在，或者被 `unset()`）** - 它将访问缓存变量并在找到匹配项时返回其值**。

这是一个可能的陷阱，如果我们有一个嵌套作用域调用 `unset()`。取决于我们在哪里引用该变量：在内层还是外层作用域，我们将访问缓存或原始值。

但是，如果我们真的需要在调用的父作用域中改变变量，该怎么办？CMake 有一个 `PARENT_SCOPE` 标志，你可以将其添加到 `set()` 和 `unset()` 命令的末尾：

```cpp
set(MyVariable "New Value" PARENT_SCOPE)
unset(MyVariable PARENT_SCOPE) 
```

这种解决方法有些局限，因为它不允许访问超过一个层级的变量。另一个值得注意的是，使用 `PARENT_SCOPE` 并不会改变当前作用域中的变量。

让我们看看变量作用域在实践中是如何工作的，并考虑以下示例：

#### chapter02/04-scope/CMakeLists.txt

```cpp
function(Inner)
  message("  > Inner: ${V}")
  set(V 3)
  message("  < Inner: ${V}")
endfunction()
function(Outer)
  message(" > Outer: ${V}")
  set(V 2)
  Inner()
  message(" < Outer: ${V}")
endfunction()
set(V 1)
message("> Global: ${V}")
Outer()
message("< Global: ${V}")
```

我们将全局变量 `V` 设置为 `1`，然后调用 `Outer` 函数，将 `V` 设置为 `2`，调用 `Inner` 函数并将 `V` 设置为 `3`。在每一步之后，我们将变量打印到控制台：

```cpp
> Global: 1
 > Outer: 1
  > Inner: 2
  < Inner: 3
 < Outer: 2
< Global: 1
```

正如我们之前解释的：当我们深入函数时——变量值被复制到嵌套的作用域，但当我们退出作用域时——它们的原始值被恢复。

如果我们改变 `Inner` 函数的 `set()` 命令，使其在父作用域中操作：`set(V 3 PARENT_SCOPE)`，输出会是什么？

```cpp
> Global: 1
 > Outer: 1
  > Inner: 2
  < Inner: 2
 < Outer: 3
< Global: 1
```

我们影响了 `Outer` 函数的作用域，但没有影响 `Inner` 作用域或全局作用域！

CMake 文档还提到，CMake 脚本在单个目录作用域中绑定变量（这有点多余，因为实际上创建目录作用域的命令 `add_subdirectory()` 不允许在脚本中使用）。

由于所有变量都存储为字符串，CMake 必须采用更具创意的方法来处理更复杂的数据结构，如列表。

## 使用列表

为了存储一个列表，CMake 会将所有元素拼接成一个以分号为分隔符的字符串，如下所示：`a;list;of;5;elements`。你可以在元素中使用反斜杠来转义分号，例如：`a\;single\;element`。

我们可以使用 `set()` 命令创建一个列表：`set(myList a list of five elements)`。由于列表的存储方式，以下命令将产生完全相同的效果：

+   `set(myList "a;list;of;five;elements")`

+   `set(myList a list "of;five;elements")`

CMake 自动在未加引号的参数中解包列表。像这样传递一个未加引号的 `myList` 引用：`message("the list is:" ${myList})` 会导致 `message()` 命令接收 6 个参数：`"the list is:", "a", "list", "of", "five", "elements"`。当然，输出将不会在参数之间打印任何额外的空格：

```cpp
the list is:alistoffiveelements
```

如你所见——这是一个非常简单的机制，应该谨慎对待。

CMake 提供了一个 `list()` 命令，它提供了多种子命令来读取、搜索、修改和排序列表。这里是一个简短的总结：

```cpp
list(LENGTH <list> <out-var>)
list(GET <list> <element index> [<index> ...] <out-var>)
list(JOIN <list> <glue> <out-var>)
list(SUBLIST <list> <begin> <length> <out-var>)
list(FIND <list> <value> <out-var>)
list(APPEND <list> [<element>...])
list(FILTER <list> {INCLUDE | EXCLUDE} REGEX <regex>)
list(INSERT <list> <index> [<element>...])
list(POP_BACK <list> [<out-var>...])
list(POP_FRONT <list> [<out-var>...])
list(PREPEND <list> [<element>...])
list(REMOVE_ITEM <list> <value>...)
list(REMOVE_AT <list> <index>...)
list(REMOVE_DUPLICATES <list>)
list(TRANSFORM <list> <ACTION> [...])
list(REVERSE <list>)
list(SORT <list> [...])
```

大多数情况下，我们在项目中并不真正需要使用列表。然而，如果你发现自己处于那种罕见的情况，这个概念会带来便利——你会在*附录*中找到关于 `list()` 命令的更深入参考。

现在我们知道如何处理各种列表和变量——让我们将注意力转移到执行流程的控制上，并学习 CMake 中可用的控制结构。

## 理解控制结构

（没有控制结构的 CMake 语言是不完整的！就像其他一切一样，它们以命令的形式提供，并分为三类：条件块、循环和命令定义。控制结构在脚本中执行，并在项目构建系统生成期间执行。）

### （条件块）

（CMake 中唯一支持的条件块是简单的`if()`。每个这样的块都必须用`endif()`命令关闭，并且可以有任意数量的`elseif()`命令和一个可选的`else()`命令，顺序如下：）

```cpp
if(<condition>)
  <commands>
elseif(<condition>) # optional block, can be repeated
  <commands>
else()              # optional block
  <commands>
endif()
```

（就像许多其他命令式语言一样，if-块控制将执行哪些命令集：）

+   （如果`if()`命令中指定的`<条件>`满足，则将执行第一个代码段。）

+   （否则，CMake 将执行属于该块中第一个满足其`<条件>`的`elseif()`命令的代码段中的命令。）

+   （如果没有任何此类命令，CMake 将检查是否提供了`else()`命令，并执行该代码段中的任何命令。）

+   （如果上述条件都不满足，执行将继续在`endif()`之后。）

（提供的`<条件>`根据非常简单的语法进行评估。）

#### （条件语法）

`if()`、`elseif()`和`while()`命令同样适用相同的语法。

##### （逻辑运算）

（`if()`条件支持`NOT`、`AND`和`OR`逻辑运算符，如下所示：）

+   （`NOT <条件>`）

+   `<条件> AND <条件>`

+   `<条件> OR <条件>`

（此外，可以使用匹配的括号对`()`嵌套条件。像所有体面的语言一样，CMake 尊重评估顺序，并从最内层的括号开始：）

+   `(<条件>) AND ((<条件>) OR (<条件>))`

##### （字符串和变量的评估）

（由于历史原因（因为变量引用`${}`语法并不总是存在），CMake 将尝试将未加引号的参数评估为变量引用。换句话说：在条件中使用简单的变量名`VAR`等于写`${VAR}`。这里有一个例子供你考虑，还有一个陷阱：）

```cpp
set(VAR1 FALSE)
set(VAR2 "VAR1")
if(${VAR2})
```

（`if()`条件在这里以一种有些复杂的方式工作：首先，它将`${VAR2}`评估为`VAR1`，这是一个已识别的变量，然后又评估为`FALSE`字符串。**只有当字符串等于以下任何常量时，它们才被认为是布尔真**（比较时不区分大小写）：）

（`ON`、`Y`、`YES`、`TRUE`）

+   （非零数字）

（这使我们得出结论，上述示例中的条件将被评估为假。）

（然而，这里有一个问题：对于一个未加引号的参数，其名称是一个包含值如`BAR`的变量，这个条件的评估结果会是什么？）

```cpp
set(FOO BAR)
if(FOO)
```

根据我们目前所说的，这将是假的，因为字符串`BAR`不符合布尔值真的标准。不幸的是，情况并非如此，因为**CMake 在未加引号的变量引用方面做出了例外**。是的，显式的`if("BAR")`将被视为布尔值假，但由于该值存储在变量中。但是，CMake 只有在以下常量之一时才会将`if(FOO)`评估为假（比较不区分大小写）：

+   `OFF`, `NO`, `FALSE`, `N`, `IGNORE`, `NOTFOUND`

以`-NOTFOUND`结尾的字符串

+   空字符串

+   零

因此，简单地询问未定义的变量将被评估为**假**：

```cpp
if (FOO)
```

但是，事先定义变量会改变情况，条件将被评估为**真**：

```cpp
set(FOO "FOO")
if (FOO)
```

> **注意**
> 
> 如果你认为未加引号的参数的行为令人困惑，请将变量引用包裹在引号中：`if ("${FOO}")`。这将导致在传递给`if()`命令之前对参数进行评估，行为将与字符串的评估一致。

换句话说，CMake 假设用户是在询问变量是否已定义（且不是显式假）。幸运的是，我们可以明确检查这一事实（而不必担心内部值）：

```cpp
if(DEFINED <name>)
if(DEFINED CACHE{<name>})
if(DEFINED ENV{<name>})
```

##### 比较值

比较操作支持以下操作符：

`EQUAL`, `LESS`, `LESS_EQUAL`, `GREATER`, `GREATER_EQUAL`

它们可以用来比较数值，如下所示：

```cpp
if (1 LESS 2) 
```

> **注意**
> 
> CMake 的文档指出，如果其中一个操作数不是数字，则值将为假。但实际实验表明，以数字开头的字符串比较可以正确工作：`if (20 EQUALS "20 GB")`

通过在任何操作符前添加`VERSION_`前缀，按照`major[.minor[.patch[.tweak]]]`格式比较软件版本：

```cpp
if (1.3.4 VERSION_LESS_EQUAL 1.4)
```

省略的组件被视为零，非整数版本组件将比较的字符串截断到该点。

对于字典序字符串比较，我们需要在操作符前加上`STR`前缀（注意没有下划线）：

```cpp
if ("A" STREQUAL "${B}")
```

正如我们经常发现的那样，这还不够，幸运的是，CMake 还支持 POSIX 正则表达式匹配（文档暗示 ERE 风味，但没有提到字符类支持）。使用`MATCHES`操作符，如下所示：

`<VARIABLE|STRING> MATCHES <regex>`

任何匹配的组都捕获在 CMAKE_MATCH_<n>变量中。

##### 简单检查

我们之前已经提到过一种简单的检查`DEFINED`，但还有其他一些检查，如果满足简单条件，则直接返回真。

我们可以检查：

+   值在列表中：`<VARIABLE|STRING> IN_LIST <VARIABLE>`

+   可用于调用的命令：`COMMAND <command-name>`

+   CMake 政策存在：`POLICY <policy-id>`（在*第三章*中介绍）

+   使用`add_test()`添加了 CTest 测试：`TEST <test-name>`

+   如果构建目标已定义：`TARGET <target-name>`

-   我们将在*第四章，使用目标工作*中介绍构建目标，现在我们只能说，目标是在项目中使用`add_executable()`，`add_library()`或`add_custom_target()`命令创建的构建过程的逻辑单元，该命令已经被调用。

##### -   检查文件系统

-   CMake 提供了许多处理文件的方法。我们很少需要直接操作它们，我们更愿意使用更高层次的方法。本书将在*附录*中提供文件相关命令的简短参考。但大多数情况下，只需要以下操作符（只有对于完整路径，行为才是明确定义的）：

+   -   检查文件或目录是否存在：`EXISTS <path-to-file-or-directory>`它解析符号链接（如果符号链接的目标存在，则返回 true）。

+   -   检查哪个文件更新：`<file1> IS_NEWER_THAN <file2>`如果 file1 比 file2 更新（或相等），或者两个文件中有一个不存在，则返回 true。

+   -   检查路径是否为目录：`IS_DIRECTORY path-to-directory`

-   检查路径是否为符号链接：`IS_SYMLINK file-name`

检查路径是否为绝对路径：`IS_ABSOLUTE path`

### -   循环

CMake 中的循环相当直接，我们可以使用`while()`或`foreach()`来重复执行同一组命令。这两个命令都支持循环控制机制：

+   -   `break()`停止执行剩余的块并从封闭的循环中退出。

+   `continue()` 停止当前迭代的执行，并从下一次迭代的顶部开始。

#### -   While

-   循环块以`while()`命令打开，以`endwhile()`命令关闭。只要`while()`中提供的`<condition>`为 true，就会执行任何封闭的命令。表述条件的语法与`if()`命令相同。

```cpp
while(<condition>)
  <commands>
endwhile()
```

-   您可能已经猜到，通过一些额外的变量，while 循环可以替换 for 循环。实际上，使用`forach()`循环来做这件事要容易得多 - 让我们来看看。

#### -   Foreach

-   Foreach 块有几种变体，它们为每个值执行封闭的命令。与其他块一样，它有打开和关闭命令：`foreach()`和`endforeach()`。

-   最简单的 foreach 形式旨在提供 C++风格的 for 循环：

```cpp
foreach(<loop_var> RANGE <max>)
  <commands>
endforeach()
```

-   CMake 将从 0 迭代到`<max>`（包括）。如果我们需要更多控制，我们可以使用第二种变体，提供`<min>`，`<max>`和可选的`<step>`。所有参数必须是正整数。此外，`<min>`必须小于`<max>`。

```cpp
foreach(<loop_var> RANGE <min> <max> [<step>])
```

-   然而，`foreach()`在处理列表时才真正展现其能力：

```cpp
foreach(<loop_variable> IN [LISTS <lists>] [ITEMS <items>])
```

-   CMake 将从所有提供的`<lists>`后面跟着所有明确声明的`<items>`中取出项目，并将它们存储在`<loop variable>`中，为每个项目逐一执行`<commands>`。您可以选择只提供列表，只提供项目，或两者都提供：

#### chapter02/06-loops/foreach.cmake

```cpp
set(MY_LIST 1 2 3)
foreach(VAR IN LISTS MY_LIST ITEMS e f)
  message(${VAR})
endforeach()
```

-   这将打印

```cpp
1
2
3
e
f
```

-   或者使用简短版本（跳过`IN`）以获得相同的结果：

```cpp
foreach(VAR 1 2 3 e f)
```

-   自版本 3.17 起，`foreach()`已经学会了如何`ZIP_LISTS`：

```cpp
foreach(<loop_var>... IN ZIP_LISTS <lists>)
```

压缩列表意味着简单地遍历多个列表并对具有相同索引的相应项进行操作。让我们看一个例子：

#### 章节 02/06-循环/foreach.cmake

```cpp
set(L1 "one;two;three;four")
set(L2 "1;2;3;4;5")
foreach(num IN ZIP_LISTS L1 L2)
    message("num_0=${num_0}, num_1=${num_1}")
endforeach()
```

CMake 将创建`num_<N>`变量，每个提供的列表一个，它将用每个列表的项填充它们。你可以传递多个`<loop_var>`（每个列表一个） - 每个列表将使用一个单独的变量来存储其项：

```cpp
foreach(word num IN ZIP_LISTS L1 L2)
    message("word=${word}, num=${num}")
```

如果列表之间的项数不同 - CMake 不会为较短的列表定义变量。

这就是关于循环的所有内容。

### 命令定义

定义自己的命令有两种方法：使用`macro()`或`function()`命令。解释它们之间差异的最简单方法是将它们与 C 风格的预处理器宏和实际的 C++函数进行比较：

+   `macro()`更像是一个查找和替换指令，而不是像`function()`那样具有自己的调用堆栈入口的实际子程序调用。这意味着在宏中调用`return()`将返回到比函数调用高一级的调用语句（如果我们在顶层作用域中，可能会终止执行）。

+   只有`function()`为局部变量创建一个单独的作用域。`macro()`在调用作用域中工作 - 这可能导致令人困惑的结果。我们将在下一节讨论细节。

两种方法都接受参数，你可以在命令块内命名和引用这些参数。此外，CMake 允许你使用以下引用访问传递给命令调用的参数：

+   `${ARGC}` - 参数计数

+   `${ARGV}` - 所有参数的列表

+   `${ARG0}`，`${ARG1}`，`${ARG2}`… - 特定索引处的参数值

+   `${ARGN}` - 传递给最后一个预期参数之后的参数列表

访问超出`ARGC`边界的数字参数索引是未定义的行为。

如果你决定使用命名参数定义命令 - 每次调用都必须传递所有参数，否则将无效。

#### 宏

定义宏类似于任何其他块：

```cpp
macro(<name> [<argument>…])
  <commands>
endmacro()
```

在如此声明之后，我们可以通过调用其名称（函数调用不区分大小写）来执行我们的宏。

以下示例解释了宏中变量作用域的所有问题：

#### 章节 02/08-定义/macro.cmake

```cpp
macro(MyMacro myVar)
  set(myVar "new value")
  message("argument: ${myVar}")
endmacro()
set(myVar "first value")
message("myVar is now: ${myVar}")
MyMacro("called value")
message("myVar is now: ${myVar}")
```

这是该脚本的输出：

```cpp
$ cmake -P chapter02/08-definitions/macro.cmake
myVar is now: first value
argument: called value
myVar is now: new value
```

发生了什么？尽管明确地将`myVar`设置为`new value` - 但它并没有影响`message("argument: ${myVar}")`的输出！这是因为传递给宏的参数不被视为真正的变量，而是被视为常量的查找和替换指令。

另一方面 - 全局作用域中的变量`myVar`从`first value`更改为`new value`。这种行为被称为副作用，被认为是不良实践，因为很难判断哪些变量可能会受到这种宏的影响，而无需阅读它。

我建议尽可能使用函数。这很可能会为你节省很多头疼的问题。

#### 函数

要声明命令作为函数，请遵循此语法：

```cpp
function(<name> [<argument>…])
  <commands>
endfunction()
```

函数需要一个名称，并且可以选择性地接受一组必需的参数。如前所述——函数打开自己的作用域。您可以调用`set()`并提供函数的一个命名参数，更改将是局部的（除非指定了`PARENT_SCOPE`，正如我们在*变量：作用域*部分讨论的那样）。

函数遵循调用堆栈的规则，允许使用`return()`命令返回到调用作用域。

CMake 为每个函数设置以下变量（自版本 3.17 起可用）：

+   `CMAKE_CURRENT_FUNCTION`

+   `CMAKE_CURRENT_FUNCTION_LIST_DIR`

+   `CMAKE_CURRENT_FUNCTION_LIST_FILE`

+   `CMAKE_CURRENT_FUNCTION_LIST_LINE`

让我们来看看实际中的函数：

#### chapter02/08-definitions/function.cmake

```cpp
function(MyFunction FirstArg)
  message("Function: ${CMAKE_CURRENT_FUNCTION}")
  message("File: ${CMAKE_CURRENT_FUNCTION_LIST_FILE}")
  message("FirstArg: ${FirstArg}")
  set(FirstArg "new value")
  message("FirstArg again: ${FirstArg}")
  message("ARGV0: ${ARGV0} ARGV1: ${ARGV1} ARGC: ${ARGC}")
endfunction()
set(FirstArg "first value")
MyFunction("Value1" "Value2")
message("FirstArg in global scope: ${FirstArg}")
```

打印出以下输出：

```cpp
Function: MyFunction
File: /home/root/chapter02/08-definitions/function.cmake
FirstArg: Value1
FirstArg again: new value
ARGV0: Value1 ARGV1: Value2 ARGC: 2
FirstArg in global scope: first value
```

如您所见，函数的一般语法和概念与宏非常相似，但这次——它确实有效。

#### CMake 中的过程范式

让我们想象一下，如果我们想像编写 C++程序那样编写 CMake 代码。我们将有一个`CMakeLists.txt`列表文件，它将调用三个已定义的命令，这些命令可能调用它们自己的已定义命令。

![图 2.3：过程调用图](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/mdn-cmk-cpp/img/file7.png)

图 2.3：过程调用图

在 CMake 中以这种过程式风格编写代码存在一些问题：您需要提前提供计划使用的命令定义。CMake 解析器不会接受其他方式。您的代码可能看起来像这样：

```cpp
cmake_minimum_required(...)
project(Procedural)
function(pull_shared_protobuf)
function(setup_first_target)
function(calculate_version)
function(setup_second_target)
function(setup_tests)
setup_first_target()
setup_second_target()
setup_tests()
```

真是噩梦！一切都颠倒了！这段代码非常难以阅读，因为最微小的细节都位于文件的顶部。结构良好的代码首先列出最一般的步骤，然后提供更详细的子程序，并将最详细的步骤推到文件的末尾。

有解决这个问题的方法：将命令定义移动到其他文件，跨目录划分作用域。但也有一个简单而优雅的方法：在文件顶部声明一个入口点宏，并在文件的最后调用它：

```cpp
macro(main)
function(...) # key steps
function(...) # details
function(...) # fine details
main()
```

采用这种方法，我们的代码是按照逐渐缩小的作用域编写的，而且由于我们实际上直到最后才调用`main()`宏——CMake 不会抱怨执行未定义的命令！

最后一个问题仍然存在：为什么要使用宏而不是推荐的功能？在这种情况下，拥有对全局变量的不受限制的访问是很好的，而且由于我们没有向主函数传递任何参数——我们不必担心通常的注意事项。

您可以在`chapter-02/09-procedural/CMakeLists.txt`列表文件中找到这个概念的一个简单示例。

#### 关于命名的一点说明

命名在软件开发中是出了名的难，但仍然非常重要，以维护易于阅读和理解的解决方案。当涉及到 CMake 脚本和项目时，所有干净代码的规则都适用，就像它们适用于正常的软件开发解决方案一样：

+   遵循一致的命名风格（`snake_case`是 CMake 社区接受的规范）。

+   使用简短但有意义的名称（避免使用`func()`、`f()`等）。

+   避免在命名中使用双关语和机智。

+   使用可发音的、可搜索的名称，不需要心理映射。

既然我们已经知道如何正确调用命令并使用正确的语法，那么让我们找出哪些命令将是最有益的开始。

## 有用的命令

CMake 提供了许多脚本命令，允许你使用变量和环境。其中一些在*附录*中得到了广泛介绍：`list()`、`string()`、`file()`（为了避免在我们通往项目的路上拖慢我们）。其他的，如`find_...()`更适合在讨论管理依赖关系的章节中。在本节中，我们将简要介绍脚本中最有用的命令。

### message()

我们已经知道并喜欢我们可靠的`message()`命令，它将文本打印到标准输出。然而，它远不止于此。通过提供一个`MODE`参数，你可以自定义输出的样式，并且在出现错误时停止代码的执行：`message(<MODE> "text")`。

识别的模式：

+   `FATAL_ERROR` - 停止处理和生成。

+   `SEND_ERROR` - 继续处理，但跳过生成。

+   `WARNING` - 继续处理

+   `AUTHOR_WARNING` - CMake 警告（开发中），继续处理。

+   `DEPRECATION` - 如果启用了变量`CMAKE_ERROR_DEPRECATED`或`CMAKE_WARN_DEPRECATED`，则相应地工作。

+   `NOTICE` 或（无）- 消息打印到 stderr 以吸引用户的注意。

+   `STATUS`

+   `VERBOSE`

+   `DEBUG`

+   `TRACE`

以下示例在第一个消息后停止执行：

#### chapter02/10-useful/message_error.cmake

```cpp
message(FATAL_ERROR "Stop processing")
message("Won't print this.")
```

消息将根据当前的日志级别（默认为`STATUS`）打印。我们在上一章的*选项：调试与跟踪*部分讨论了如何更改它。然后我承诺会讨论使用`CMAKE_MESSAGE_CONTEXT`进行调试 - 让我们开始吧。从那时起，我们获得了这个难题的三个重要部分：列表、作用域和函数。

当我们启用命令行标志`cmake --log-context`时，我们的消息将用点分隔的上下文装饰，该上下文存储在`CMAKE_MESSAGE_CONTEXT`列表中。考虑以下示例：

#### chapter02/10-useful/message_context.cmake

```cpp
function(foo)
  list(APPEND CMAKE_MESSAGE_CONTEXT "foo")
  message("foo message")
endfunction()
list(APPEND CMAKE_MESSAGE_CONTEXT "top")
message("Before `foo`")
foo()
message("After `foo`")
```

上述脚本的输出将如下所示：

```cpp
$ cmake -P message_context.cmake --log-context
[top] Before `foo`
[top.foo] foo message
[top] After `foo`
```

函数的初始作用域是从父作用域复制的（父作用域已经在列表中有一个项：`top`）。`foo`中的第一个命令向`CMAKE_MESSAGE_CONTEXT`添加了一个新项，其名称为`foo`。消息被打印出来，函数作用域结束，丢弃了本地复制的变量，以及之前的（没有`foo`）作用域被恢复。

这种方法在非常复杂的项目中，有许多嵌套函数时非常有用。希望你永远不需要它，但我认为这是一个很好的例子，说明了函数作用域在实践中是如何工作的。

`message()`的另一个很酷的技巧是向`CMAKE_MESSAGE_INDENT`列表添加缩进（与`CMAKE_MESSAGE_CONTEXT`完全相同）：

```cpp
list(APPEND CMAKE_MESSAGE_INDENT "  ")
```

我们的脚本输出看起来会更清晰一些：

```cpp
Before `foo`
  foo message
After `foo`
```

由于 CMake 没有提供任何真正的带有断点或其他工具的调试器，因此能够生成清晰的日志消息在事情没有完全按计划进行时非常有用。

### include()

我们可以将我们的 CMake 代码分成单独的文件，以保持事物的有序和…嗯，分开。然后我们可以通过调用`include()`从我们的父列表文件中引用它们，如下所示：

```cpp
include(<file|module> [OPTIONAL] [RESULT_VARIABLE <var>])
```

如果我们提供了一个带有`.cmake`扩展名的文件名（路径），CMake 将尝试打开并执行它。请注意，不会创建嵌套的、独立的范围，因此该文件中对变量所做的任何更改都会影响调用范围。

CMake 会在文件不存在的情况下抛出错误，除非我们指定它是`OPTIONAL`。如果我们需要知道包含是否成功，我们可以提供一个`RESULT_VARIABLE`关键字和一个变量名。如果成功，它将被填充为包含文件的完整路径，或者在失败时填充为`NOTFOUND`。

在脚本模式下运行时，任何相对路径都将从当前工作目录解析。要强制在相对于脚本本身的位置搜索，请提供一个绝对路径：

```cpp
include("${CMAKE_CURRENT_LIST_DIR}/<filename>.cmake") 
```

如果我们不提供路径，而是提供一个模块的名称（不带`.cmake`或其他后缀），CMake 将尝试找到该模块并包含它。CMake 会在`CMAKE_MODULE_PATH`中搜索名为`<module>.cmake`的文件，然后在 CMake 模块目录中搜索。

### include_guard()

当我们包含具有副作用的文件时，我们可能希望限制它们只被包含一次。这时`include_guard([DIRECTORY|GLOBAL])`就派上用场了。

在包含的文件顶部放置`include_guard()`。当 CMake 第一次遇到它时，它会在当前范围内记录这一事实。如果文件再次被包含（可能是因为我们不控制项目中的所有文件），它将不会被进一步处理。

如果我们想防止在彼此不嵌套的范围内包含，我们应该提供`DIRECTORY`或`GLOBAL`参数。顾名思义，`DIRECTORY`保护将适用于当前目录及其下，而`GLOBAL`适用于整个构建。

### file()

为了给你一个关于 CMake 脚本可以做什么的提示，让我们快速看一下文件操作命令的最有用变体：

```cpp
file(READ <filename> <out-var> [...])
file({WRITE | APPEND} <filename> <content>...)
file(DOWNLOAD <url> [<file>] [...])
```

简而言之，`file()`命令将允许你以系统独立的方式读取、写入、传输文件，处理文件系统、文件锁、路径和存档；所有这些都在系统独立的方式下进行。详情请参阅*附录*。

### execute_process()

有时你将需要求助于系统中可用的工具（毕竟 CMake 主要是一个构建系统生成器）。CMake 为此提供了一个命令：你可以使用`execute_process()`来运行其他进程并收集它们的输出。这个命令非常适合脚本，也可以在项目配置阶段使用。这里是一般形式：

```cpp
execute_process(COMMAND <cmd1> [<arguments>]… [OPTIONS])
```

CMake 将使用操作系统的 API 来创建一个子进程（因此像`&&`、`||`和`>`这样的 shell 操作符将不起作用）。然而，你仍然可以通过多次提供`COMMAND <cmd> <arguments>`参数来链接命令并将一个命令的输出传递给另一个。

你可以选择使用`TIMEOUT <seconds>`来终止进程，如果它在限定时间内未完成任务，并根据需要设置`WORKING_DIRECTORY <directory>`。

所有任务的退出代码可以通过提供`RESULTS_VARIABLE <variable>`参数来收集到一个列表中。如果你只对最后一个执行的命令的结果感兴趣，请使用单数形式：`RESULT_VARIABLE <variable>`。

为了收集输出，CMake 提供了两个参数：`OUTPUT_VARIABLE`和`ERROR_VARIABLE`，使用方式类似。如果你想要合并`stdout`和`stderr`，可以使用同一个变量作为这两个参数。

记住，当你为其他用户编写项目时，你应该确保你计划使用的命令在你声称支持的平台上可用。

## 总结

本章打开了使用 CMake 进行实际编程的大门——你现在能够编写出色的、信息丰富的注释；调用内置命令，并理解如何正确地向它们提供各种参数。仅凭这些知识，就能帮助你理解在其他项目中可能见到的 CMake listfiles 的略显奇特的语法。

接下来，我们介绍了 CMake 中的变量：如何引用、设置和取消普通、缓存和环境变量。我们深入探讨了目录和函数作用域的工作原理，以及嵌套作用域的问题（及其解决方法）。

我们还介绍了列表和控制结构。我们讨论了条件的语法、逻辑操作、未加引号的参数的评估、字符串和变量。我们学会了如何比较值、进行简单检查以及检查系统中文件的状态。这使我们能够编写条件块和 while 循环。说到 while 循环，我们也掌握了 foreach 的语法。

我相信，知道如何使用宏和函数语句定义自己的命令将帮助你编写更简洁的代码，并以更过程化的风格编写。我们还分享了一些关于如何更好地组织我们的代码和想出更具可读性的名称的提示。

最后，我们正式介绍了 message()及其多个日志级别。我们还研究了如何划分和包含 listfiles，并发现了一些其他有用的命令。我确信，有了这些材料，我们已准备好迎接下一章，并编写我们的第一个 CMake 项目。

## 进一步阅读

你可以参考以下内容以获取更多信息：

+   [《代码整洁之道：程序员的敏捷软件工艺手册》](https://amzn.to/3cm69DD)（Robert C. Martin）

+   [重构：改善现有代码的设计](https://amzn.to/3cmWk8o)（Martin Fowler）

+   [你的代码中哪些注释是好的？](https://youtu.be/4t9bpo0THb8)（Rafał Świdzinski）

+   StackOverflow - CMake 语法设置和使用变量：[`stackoverflow.com/questions/31037882/whats-the-cmake-syntax-to-set-and-use-variables`](https://stackoverflow.com/questions/31037882/whats-the-cmake-syntax-to-set-and-use-variables)
