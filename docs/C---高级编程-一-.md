# C++ 高级编程（一）

> 原文：[`annas-archive.org/md5/5f35e0213d2f32c832c0e92fd16884c1`](https://annas-archive.org/md5/5f35e0213d2f32c832c0e92fd16884c1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

## 关于

本节简要介绍了作者、本书的内容、开始所需的技术技能以及完成所有包含的活动和练习所需的硬件和软件要求。

## 关于本书

C++是最广泛使用的编程语言之一，应用于各种领域，从游戏到图形用户界面（GUI）编程，甚至操作系统。如果您希望扩展职业机会，掌握 C++的高级特性至关重要。

该书从高级 C++概念开始，帮助您解析复杂的 C++类型系统，并了解编译的各个阶段如何将源代码转换为目标代码。然后，您将学习如何识别需要使用的工具，以控制执行流程，捕获数据并传递数据。通过创建小模型，您甚至会发现如何使用高级 lambda 和捕获，并在 C++中表达常见的 API 设计模式。随着后续章节的学习，您将探索通过学习内存对齐、缓存访问以及程序运行所需的时间来优化代码的方法。最后一章将帮助您通过了解现代 CPU 分支预测以及如何使您的代码对缓存友好来最大化性能。

通过本书，您将发展出与其他 C++程序员不同的编程技能。

### 关于作者

加齐汗·阿兰库斯（Gazihan Alankus）在华盛顿大学获得计算机科学博士学位。目前，他是土耳其伊兹密尔经济大学的助理教授。他在游戏开发、移动应用开发和人机交互方面进行教学和研究。他是 Dart 的 Google 开发专家，并与他在 2019 年创立的公司 Gbot 的学生一起开发 Flutter 应用程序。

奥莉娜·利津娜（Olena Lizina）是一名拥有 5 年 C++开发经验的软件开发人员。她具有为国际产品公司开发用于监控和管理远程计算机的系统的实际知识，该系统有大量用户。在过去的 4 年中，她一直在国际外包公司为知名汽车公司的汽车项目工作。她参与了不同项目的复杂和高性能应用程序的开发，如 HMI（人机界面）、导航以及与传感器工作的应用程序。

拉克什·马内（Rakesh Mane）在软件行业拥有 18 年的经验。他曾与来自印度、美国和新加坡的熟练程序员合作。他主要使用 C++、Python、shell 脚本和数据库进行工作。在业余时间，他喜欢听音乐和旅行。此外，他喜欢使用软件工具和代码玩耍、实验和破坏东西。

维韦克·纳加拉贾（Vivek Nagarajan）是一名自学成才的程序员，他在上世纪 80 年代开始使用 8 位系统。他曾参与大量软件项目，并拥有 14 年的 C++专业经验。此外，他还在多年间使用了各种语言和框架。他是一名业余举重运动员、DIY 爱好者和摩托车赛手。他目前是一名独立软件顾问。

布赖恩·普莱斯（Brian Price）在各种语言、项目和行业中拥有 30 多年的工作经验，其中包括 20 多年的 C++经验。他曾参与电站模拟器、SCADA 系统和医疗设备的开发。他目前正在为下一代医疗设备开发 C++、CMake 和 Python 软件。他喜欢用各种语言解决难题和欧拉项目。

### 学习目标

通过本书，您将能够：

+   深入了解 C++的解剖和工作流程

+   研究在 C++中编码的不同方法的优缺点

+   测试、运行和调试您的程序

+   将目标文件链接为动态库

+   使用模板、SFINAE、constexpr if 表达式和可变模板

+   应用最佳实践进行资源管理

### 观众

如果您已经使用 C++但想要学习如何充分利用这种语言，特别是对于大型项目，那么这本书适合您。必须具备对编程的一般理解，并且必须具备使用编辑器在项目目录中生成代码文件的知识。还建议具备一些使用强类型语言（如 C 和 C++）的经验。

### 方法

这本快节奏的书旨在通过描述性图形和具有挑战性的练习快速教授您概念。该书将包含“标注”，其中包括关键要点和最常见的陷阱，以保持您的兴趣，同时将主题分解为可管理的部分。

### 硬件要求

为了获得最佳的学生体验，我们建议以下硬件配置：

+   任何具有 Windows、Linux 或 macOS 的入门级 PC/Mac 都足够

+   处理器：双核或等效

+   内存：4 GB RAM（建议 8 GB）

+   存储：35 GB 的可用空间

### 软件要求

您还需要提前安装以下软件：

+   操作系统：Windows 7 SP1 32/64 位，Windows 8.1 32/64 位，或 Windows 10 32/64 位，Ubuntu 14.04 或更高版本，或 macOS Sierra 或更高版本

+   浏览器：Google Chrome 或 Mozilla Firefox

### 安装和设置

在开始阅读本书之前，您需要安装本书中使用的以下库。您将在此处找到安装这些库的步骤。

**安装 CMake**

我们将使用 CMake 版本 3.12.1 或更高版本。我们有两种安装选项。

选项 1：

如果您使用的是 Ubuntu 18.10，可以使用以下命令全局安装 CMake：

```cpp
sudo apt install cmake
```

当您运行以下命令时：

```cpp
cmake –version
```

您应该看到以下输出：

```cpp
cmake version 3.12.1
CMake suite maintained and supported by Kitware (kitware.com/cmake).
```

如果您在此处看到的版本低于 3.12.1（例如 3.10），则应按照以下说明在本地安装 CMake。

选项 2：

如果您使用的是较旧的 Linux 版本，则可能会获得低于 3.12.1 的 CMake 版本。然后，您需要在本地安装它。使用以下命令：

```cpp
wget \
https://github.com/Kitware/CMake/releases/download/v3.15.1/cmake-3.15.1-Linux-x86_64.sh
sh cmake-3.15.1-Linux-x86_64.sh
```

当您看到软件许可证时，请输入*y*并按*Enter*。当询问安装位置时，请输入*y*并再次按 Enter。这应该将其安装到系统中的一个新文件夹中。

现在，我们将将该文件夹添加到我们的路径中。输入以下内容。请注意，第一行有点太长，而且在本文档中换行。您应该将其写成一行，如下所示：

```cpp
echo "export PATH=\"$HOME/cmake-3.15.1-Linux-x86_64/bin:$PATH\"" >> .bash_profile
source .profile
```

现在，当您输入以下内容时：

```cpp
cmake –version
```

您应该看到以下输出：

```cpp
cmake version 3.15.1
CMake suite maintained and supported by Kitware (kitware.com/cmake).
```

在撰写本文时，3.15.1 是当前最新版本。由于它比 3.12.1 更新，这对我们的目的足够了。

**安装 Git**

通过输入以下内容来测试当前安装情况：

```cpp
git --version
```

您应该看到以下行：

```cpp
git version 2.17.1
```

如果您看到以下行，则需要安装`git`：

```cpp
command 'git' not found
```

以下是如何在 Ubuntu 中安装`git`：

```cpp
sudo apt install git
```

**安装 g++**

通过输入以下内容来测试当前安装情况：

```cpp
g++ --version
```

您应该看到以下输出：

```cpp
g++ (Ubuntu 7.4.0-1ubuntu1~18.04) 7.4.0
Copyright (C) 2017 Free Software Foundation, Inc.
This is free software; see the source for copying conditions. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```

如果尚未安装，请输入以下代码进行安装：

```cpp
sudo apt install g++
```

**安装 Ninja**

通过输入以下内容来测试当前安装情况：

```cpp
ninja --version
```

您应该看到以下输出：

```cpp
1.8.2
```

如果尚未安装，请输入以下代码进行安装：

```cpp
sudo apt install ninja-build
```

**安装 Eclipse CDT 和 cmake4eclipse**

有多种安装 Eclipse CDT 的方法。为了获得最新的稳定版本，我们将使用官方安装程序。转到此网站并下载 Linux 安装程序：[`www.eclipse.org/downloads/packages/installer`](https://www.eclipse.org/downloads/packages/installer)。

按照那里的说明并安装**Eclipse IDE for C/C++ Developers**。安装完成后，运行 Eclipse 可执行文件。如果您没有更改默认配置，在终端中输入以下命令将运行它：

```cpp
~/eclipse/cpp-2019-03/eclipse/eclipse
```

您将选择一个工作区文件夹，然后将在主 Eclipse 窗口中看到一个**欢迎**选项卡。

现在，我们将安装`cmake4eclipse`。一个简单的方法是访问该网站，并将**安装**图标拖到 Eclipse 窗口中：[`github.com/15knots/cmake4eclipse#installation`](https://github.com/15knots/cmake4eclipse#installation)。它会要求您重新启动 Eclipse，之后您就可以修改 CMake 项目以在 Eclipse 中使用了。

**安装 GoogleTest**

我们将在系统中安装`GoogleTest`，这也将安装其他依赖于它的软件包。写入以下命令：

```cpp
sudo apt install libgtest-dev google-mock
```

这个命令安装了`GoogleTest`的包含文件和源文件。现在，我们需要构建已安装的源文件以创建`GoogleTest`库。运行以下命令来完成这个步骤：

```cpp
cd /usr/src/gtest
sudo cmake CMakeLists.txt
sudo make
sudo cp *.a /usr/lib
```

### 安装代码包

将该课程的代码包复制到`C:/Code`文件夹中。

### 附加资源

本书的代码包也托管在 GitHub 上，网址为[`github.com/TrainingByPackt/Advanced-CPlusPlus`](https://github.com/TrainingByPackt/Advanced-CPlusPlus)。

我们还有其他代码包来自我们丰富的图书和视频目录，可以在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。去看看吧！


# 第一章：可移植 C++软件的解剖学

## 学习目标

在本章结束时，您将能够：

+   建立代码构建测试流程

+   描述编译的各个阶段

+   解密复杂的 C++类型系统

+   配置具有单元测试的项目

+   将源代码转换为目标代码

+   编写可读的代码并调试它

在本章中，我们将学习建立贯穿全书使用的代码构建测试模型，编写优美的代码并进行单元测试。

## 介绍

C++是最古老和最流行的语言之一，您可以使用它来编写高效的代码。它既像 C 一样“接近底层”，又具有高级的面向对象特性，就像 Java 一样。作为一种高效的低级语言，C++是效率至关重要的领域的首选语言，例如游戏、模拟和嵌入式系统。同时，作为一种具有高级特性的面向对象语言，例如泛型、引用和无数其他特性，使其适用于由多人开发和维护的大型项目。

几乎任何编程经验都涉及组织您的代码库并使用他人编写的库。C++也不例外。除非您的程序很简单，否则您将把代码分发到多个文件中，并且需要组织这些文件，您将使用各种库来完成任务，通常比您的代码更有效和更可靠。不使用任何第三方库的 C++项目是不代表大多数项目的边缘情况，大多数项目都使用许多库。这些项目及其库预期在不同的硬件架构和操作系统上工作。因此，如果您要使用 C++开发任何有意义的东西，花时间进行项目设置并了解用于管理依赖关系的工具是很重要的。

大多数现代和流行的高级语言都有标准工具来维护项目、构建项目并处理其库依赖关系。其中许多都有托管库和工具的存储库，可以自动下载并使用这些库。例如，Python 有`pip`，它负责下载和使用程序员想要使用的库的适当版本。同样，JavaScript 有`npm`，Java 有`maven`，Dart 有`pub`，C#有`NuGet`。在这些语言中，您列出要使用的库的名称和版本，工具会自动下载并使用兼容版本的库。这些语言受益于程序在受控环境中构建和运行，其中满足一定级别的硬件和软件要求。另一方面，C++预期在各种上下文中使用，具有不同的架构，包括非常原始的硬件。因此，当涉及构建程序和执行依赖管理时，C++程序员受到的关注较少。

## 管理 C++项目

在 C++世界中，我们有几种工具可帮助管理项目源代码及其依赖关系。例如，`pkg-config`、`Autotools`、`make`和`CMake`是社区中最值得注意的工具。与其他高级语言的工具相比，这些工具使用起来要复杂得多。`CMake`已成为管理 C++项目及其依赖关系的事实标准。与`make`相比，它更具有主观性，并且被接受为大多数集成开发环境（IDE）的直接项目格式。

虽然`CMake`有助于管理项目及其依赖关系，但体验仍远远不及高级语言，其中您列出要使用的库及其版本，其他一切都会为您处理。使用 CMake，您仍需负责在开发环境中正确安装库，并且您需要使用每个库的兼容版本。在流行的 Linux 发行版中，有广泛的软件包管理器，您可以轻松安装大多数流行库的二进制版本。然而，有时您可能需要自行编译和安装库。这是 C++开发者体验的一部分，您将通过学习更多关于您选择的开发平台的开发平台来了解。在这里，我们将更专注于如何正确设置我们的 CMake 项目，包括理解和解决与库相关的问题。

### 代码构建测试运行循环

为了以坚实的基础展开讨论，我们将立即从一个实际示例开始。我们将从一个 C++代码基础模板开始，您可以将其用作自己项目的起点。我们将看到如何使用 CMake 在命令行上构建和编译它。我们还将为 C/C++开发人员设置 Eclipse IDE，并导入我们的 CMake 项目。使用 IDE 将为我们提供便利设施，以便轻松创建源代码，并使我们能够逐行调试我们的程序，查看程序执行过程中到底发生了什么，并以明智的方式纠正错误，而不是靠试错和迷信。

### 构建一个 CMake 项目

C++项目的事实标准是使用 CMake 来组织和构建项目。在这里，我们将使用一个基本的模板项目作为起点。以下是一个示例模板的文件夹结构：

![图 1.1：示例模板的文件夹结构](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_01.jpg)

###### 图 1.1：示例模板的文件夹结构

在上图中，`git`版本控制系统。这些被忽略的文件包括构建过程的输出，这些文件是在本地创建的，不应在计算机之间共享。

不同平台的`make`文件中的文件。

使用 CMake 构建项目是一个两步过程。首先，我们让 CMake 生成平台相关的配置文件，用于本地构建系统编译和构建项目。然后，我们将使用生成的文件来构建项目。CMake 可以为平台生成配置文件的构建系统包括`UNIX` `Makefiles`、`Ninja` `build files`、`NMake` `Makefiles`和`MinGW` `Makefiles`。选择取决于所使用的平台、这些工具的可用性和个人偏好。`UNIX` `Makefiles`是`Unix`和`Linux`的事实标准，而`NMake`是其`Windows`和`Visual Studio`的对应物。另一方面，`MinGW`是`Windows`中的`Unix`-like 环境，也在使用`Makefiles`。`Ninja`是一个现代的构建系统，与其他构建系统相比速度异常快，同时支持多平台，我们选择在这里使用。此外，除了这些命令行构建系统，我们还可以为`Visual Studio`、`XCode`、`Eclipse CDT`等生成 IDE 项目，并在 IDE 中构建我们的项目。因此，`CMake`是一个元工具，将为另一个实际构建项目的系统创建配置文件。在下一节中，我们将解决一个练习，其中我们将使用`CMake`生成`Ninja` `build files`。

### 练习 1：使用 CMake 生成 Ninja 构建文件

在这个练习中，我们将使用`CMake`生成`Ninja build files`，用于构建 C++项目。我们将首先从`git`存储库下载我们的源代码，然后使用 CMake 和 Ninja 来构建它。这个练习的目的是使用 CMake 生成 Ninja 构建文件，构建项目，然后运行它们。

#### 注意

GitHub 仓库的链接可以在这里找到：[`github.com/TrainingByPackt/Advanced-CPlusPlus/tree/master/Lesson1/Exercise01/project`](https://github.com/TrainingByPackt/Advanced-CPlusPlus/tree/master/Lesson1/Exercise01/project)。

执行以下步骤完成练习：

1.  在终端窗口中，输入以下命令，将`CxxTemplate`仓库从 GitHub 下载到本地系统：

```cpp
git clone https://github.com/TrainingByPackt/Advanced-CPlusPlus/tree/master/Lesson1/Exercise01/project
```

上一个命令的输出类似于以下内容：

![图 1.2：从 GitHub 检出示例项目](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_02.jpg)

###### 图 1.2：从 GitHub 检出示例项目

现在你已经在`CxxTemplate`文件夹中有了源代码。

1.  通过在终端中输入以下命令，进入`CxxTemplate`文件夹：

```cpp
cd CxxTemplate
```

1.  现在你可以通过在终端中输入以下命令来列出项目中的所有文件：

```cpp
find .
```

1.  在`CxxTemplate`文件夹中使用`cmake`命令生成我们的 Ninja 构建文件。为此，输入以下命令：

```cpp
cmake -Bbuild -H. -GNinja
```

上一个命令的输出如下：

![图 1.3：生成 Ninja 构建文件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_03.jpg)

###### 图 1.3：生成 Ninja 构建文件

让我们解释一下上一个命令的部分。使用`-Bbuild`，我们告诉 CMake 使用`build`文件夹来生成构建产物。由于这个文件夹不存在，CMake 会创建它。使用`-H.`，我们告诉 CMake 使用当前文件夹作为源。通过使用单独的`build`文件夹，我们将保持我们的源文件干净，所有的构建产物都将存放在`build`文件夹中，这得益于我们的`.gitignore`文件而被 Git 忽略。使用`-GNinja`，我们告诉 CMake 使用 Ninja 构建系统。

1.  运行以下命令来列出项目文件并检查在`build`文件夹中创建的文件：

```cpp
ls
ls build
```

上一个命令将在终端中显示以下输出：

![图 1.4：构建文件夹中的文件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_04.jpg)

###### 图 1.4：构建文件夹中的文件

很明显，上一个文件将存在于构建文件夹中。上一个输出中的**build.ninja**和**rules.ninja**是 Ninja 构建文件，实际上可以在这个平台上构建我们的项目。

#### 注意

通过使用 CMake，我们不必编写 Ninja 构建文件，并避免了对 Unix 平台的提交。相反，我们有一个可以为其他平台生成低级构建文件的元构建系统，比如 UNIX/Linux、MinGW 和 Nmake。

1.  现在，进入`build`文件夹，并通过在终端中输入以下命令来构建我们的项目：

```cpp
cd build
ninja
```

你应该看到最终输出如下：

![图 1.5：使用 ninja 构建](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_05.jpg)

###### 图 1.5：使用 ninja 构建

1.  在`CxxTemplate`可执行文件中键入`ls`或不键入：

```cpp
ls
```

上一个命令在终端中产生以下输出：

![图 1.6：运行 ninja 后构建文件夹中的文件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_06.jpg)

###### 图 1.6：运行 ninja 后构建文件夹中的文件

在上一个图中，你可以看到`CxxTemplate`可执行文件已经生成。

1.  在终端中，输入以下命令来运行`CxxTemplate`可执行文件：

```cpp
./CxxTemplate
```

终端中的上一个命令将提供以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_07.jpg)

###### 图 1.7：运行可执行文件

`src/CxxTemplate.cpp`文件中的以下行负责写入上一个输出：

```cpp
std::cout << "Hello CMake." << std::endl;
```

现在你已经成功在 Linux 中构建了一个 CMake 项目。Ninja 和 CMake 在一起工作得很好。你只需要运行一次 CMake，Ninja 就会检测是否需要再次调用 CMake，并会自动为你调用。例如，即使你向`CMakeLists.txt`文件中添加新的源文件，你只需要在终端中输入`ninja`命令，它就会自动运行 CMake 来更新 Ninja 构建文件。现在你已经了解了如何在 Linux 中构建 CMake 项目，在下一节中，我们将看看如何将 CMake 项目导入 Eclipse CDT。

## 将 CMake 项目导入 Eclipse CDT

Ninja 构建文件对于在 Linux 中构建我们的项目非常有用。但是，CMake 项目是可移植的，并且也可以与其他构建系统和 IDE 一起使用。许多 IDE 接受 CMake 作为其配置文件，并在您修改和构建项目时提供无缝体验。在本节中，我们将讨论如何将 CMake 项目导入 Eclipse CDT，这是一款流行的跨平台 C/C++ IDE。

使用 Eclipse CDT 与 CMake 有多种方法。CMake 提供的默认方法是单向生成 IDE 项目。在这里，您只需创建一次 IDE 项目，对 IDE 项目进行的任何修改都不会改变原始的 CMake 项目。如果您将项目作为 CMake 项目进行管理，并且只在 Eclipse CDT 中进行一次性构建，则这很有用。但是，如果您想在 Eclipse CDT 中进行开发，则不是理想的方法。

使用 Eclipse CDT 与 CMake 的另一种方法是使用自定义的`cmake4eclipse`插件。使用此插件时，您不会放弃您的`CMakeLists.txt`文件并单向切换到 Eclipse CDT 的项目管理器。相反，您将继续通过`CMakeLists.txt`文件管理项目，该文件将继续是项目的主要配置文件。Eclipse CDT 会积极与您的`CMakeLists.txt`文件合作构建项目。您可以在`CMakeLists.txt`中添加或删除源文件并进行其他更改，`cmake4eclipse`插件会在每次构建时将这些更改应用于 Eclipse CDT 项目。您将拥有良好的 IDE 体验，同时保持您的 CMake 项目处于最新状态。这种方法的好处是您始终可以停止使用 Eclipse CDT，并使用您的`CMakeLists.txt`文件切换到另一个构建系统（如 Ninja）。我们将在以下练习中使用这种第二种方法。

### 练习 2：将 CMake 文件导入 Eclipse CDT

在上一个练习中，您开发了一个 CMake 项目，并希望开始使用 Eclipse CDT IDE 来编辑和构建该项目。在本练习中，我们将使用`cmake4eclipse`插件将我们的 CMake 项目导入 Eclipse CDT IDE。执行以下步骤完成练习：

1.  打开 Eclipse CDT。

1.  在当前项目的位置（包含`CMakeLists.txt`文件和**src**文件夹的文件夹）中创建一个新的 C++项目。转到**文件** | **新建** | **项目**。将出现一个类似以下截图的**新建项目**对话框：![图 1.8：新建项目对话框](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_08.jpg)

###### 图 1.8：新建项目对话框

1.  选择**C++项目**选项，然后点击**下一步**按钮。将出现一个类似以下截图的**C++项目**对话框：![图 1.9：C++项目对话框](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_09.jpg)

###### 图 1.9：C++项目对话框

1.  接受一切，包括切换到 C/C++视角，然后点击**完成**。

1.  点击左上角的**还原**按钮查看新创建的项目：![图 1.10：还原按钮](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_10.jpg)

###### 图 1.10：还原按钮

1.  点击**CxxTemplate**项目。转到**项目** | **属性**，然后在左侧窗格下选择**C/C++构建**下的**工具链编辑器**，将**当前构建器**设置为**CMake Builder (portable)**。然后，点击**应用并关闭**按钮：![图 1.11：项目属性](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_11.jpg)

###### 图 1.11：项目属性

1.  然后，选择**项目** | **构建全部**菜单项来构建项目：![图 1.12：构建项目](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_12.jpg)

###### 图 1.12：构建项目

1.  在接下来的`make all`中实际构建我们的项目：![图 1.13：构建输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_13.jpg)

###### 图 1.13：构建输出

1.  如果在之前的步骤中没有出现任何错误，您可以使用菜单项**运行** | **运行**来运行项目。如果给出了一些选项，请选择**本地 C/C++应用程序**和**CxxTemplate**作为可执行文件：![图 1.14：运行项目](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_14.jpg)

###### 图 1.14：运行项目

1.  当运行时，你会在**控制台**窗格中看到程序的输出如下：

![图 1.15：项目的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_15.jpg)

###### 图 1.15：项目的输出

你已经成功地使用 Eclipse CDT 构建和运行了一个 CMake 项目。在下一个练习中，我们将通过添加新的源文件和新类来频繁地更改我们的项目。

### 练习 3：向 CMake 和 Eclipse CDT 添加新的源文件

随着 C++项目的不断扩大，你会倾向于向其中添加新的源文件，以满足预期的要求。在这个练习中，我们将向我们的项目中添加一个新的`.cpp`和`.h`文件对，并看看 CMake 和 Eclipse CDT 如何处理这些更改。我们将使用新类向项目中添加这些文件，但你也可以使用任何其他文本编辑器创建它们。执行以下步骤将新的源文件添加到 CMake 和 Eclipse CDT 中：

1.  首先，打开我们一直在使用的项目。在左侧的**项目资源管理器**窗格中，展开根条目**CxxTemplate**，你会看到我们项目的文件和文件夹。右键单击**src**文件夹，从弹出菜单中选择**新建** | **类**：![图 1.16：创建一个新类](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_16.jpg)

###### 图 1.16：创建一个新类

1.  在打开的对话框中，为类名输入**ANewClass**。当你点击**完成**按钮时，你会看到**src**文件夹下生成了**ANewClass.cpp**和**ANewClass.h**文件。

1.  现在，让我们在`ANewClass`类中写一些代码，并从`ANewClass.cpp`中访问它，并更改文件的开头以匹配以下内容，然后保存文件：

```cpp
#include "ANewClass.h"
#include <iostream>
void ANewClass::run() {
    std::cout << "Hello from ANewClass." << std::endl;
}
```

你会看到 Eclipse 用`ANewClass.h`文件警告我们。这些警告是由 IDE 中的分析器实现的，非常有用，因为它们可以在你输入代码时帮助你修复代码，而无需运行编译器。

1.  打开`ANewClass.h`文件，添加以下代码，并保存文件：

```cpp
public:
    void run(); // we added this line
    ANewClass();
```

你应该看到`.cpp`文件中的错误消失了。如果没有消失，可能是因为你可能忘记保存其中一个文件。你应该养成按*Ctrl + S*保存当前文件的习惯，或者按*Shift + Ctrl + S*保存你编辑过的所有文件。

1.  现在，让我们从我们的另一个类`CxxTemplate.cpp`中使用这个类。打开该文件，进行以下修改，并保存文件。在这里，我们首先导入头文件，在`CxxApplication`的构造函数中，我们向控制台打印文本。然后，我们创建了`ANewClass`的一个新实例，并调用了它的`run`方法：

```cpp
#include "CxxTemplate.h"
#include "ANewClass.h"
#include <string>
...
CxxApplication::CxxApplication( int argc, char *argv[] ) {
  std::cout << "Hello CMake." << std::endl;
  ::ANewClass anew;
  anew.run();
}
```

#### 注意

这个文件的完整代码可以在这里找到：[`github.com/TrainingByPackt/Advanced-CPlusPlus/blob/master/Lesson1/Exercise03/src/CxxTemplate.cpp`](https://github.com/TrainingByPackt/Advanced-CPlusPlus/blob/master/Lesson1/Exercise03/src/CxxTemplate.cpp)。

1.  尝试通过点击`CMakeLists.txt`文件来构建项目，进行以下修改，并保存文件：

```cpp
add_executable(CxxTemplate
  src/CxxTemplate.cpp  
  src/ANewClass.cpp
)
```

尝试再次构建项目。这次你不应该看到任何错误。

1.  使用**运行** | **运行**菜单选项运行项目。你应该在终端中看到以下输出：

![图 1.18：程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_18.jpg)

###### 图 1.18：程序输出

你修改了一个 CMake 项目，向其中添加了新文件，并成功地运行了它。请注意，我们在`src`文件夹中创建了文件，并让`CMakeLists.txt`文件知道了 CPP 文件。如果你不使用 Eclipse，你可以继续使用通常的 CMake 构建命令，你的程序将成功运行。到目前为止，我们已经从 GitHub 检出了示例代码，并且用纯 CMake 和 Eclipse IDE 构建了它。我们还向 CMake 项目中添加了一个新类，并在 Eclipse IDE 中重新构建了它。现在你知道如何构建和修改 CMake 项目了。在下一节中，我们将进行一个活动，向项目添加一个新的源文件-头文件对。

### 活动 1：向项目添加新的源文件-头文件对

在开发 C++项目时，随着项目的增长，您会向其中添加新的源文件。您可能出于各种原因想要添加新的源文件。例如，假设您正在开发一个会计应用程序，在其中需要在多个地方计算利率，并且您希望创建一个单独的文件中的函数，以便在整个项目中重用它。为了保持简单，在这里我们将创建一个简单的求和函数。在这个活动中，我们将向项目添加一个新的源文件和头文件对。执行以下步骤完成该活动：

1.  在 Eclipse IDE 中打开我们在之前练习中创建的项目。

1.  将`SumFunc.cpp`和`SumFunc.h`文件对添加到项目中。

1.  创建一个名为`sum`的简单函数，它返回两个整数的和。

1.  从`CxxTemplate`类构造函数中调用该函数。

1.  在 Eclipse 中构建并运行项目。

预期输出应该类似于以下内容：

![图 1.19：最终输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_19.jpg)

###### 图 1.19：最终输出

#### 注意

此活动的解决方案可在第 620 页找到。

在接下来的部分中，我们将讨论如何为我们的项目编写单元测试。将项目分成许多类和函数，并让它们一起工作以实现期望的目标是很常见的。您必须使用单元测试来管理这些类和函数的行为，以确保它们以预期的方式运行。

## 单元测试

单元测试在编程中是一个重要的部分。基本上，单元测试是使用我们的类在各种场景下进行测试的小程序，预期结果是在我们的项目中的一个并行文件层次结构中，不会最终出现在实际的可执行文件中，而是在开发过程中由我们单独执行，以确保我们的代码以预期的方式运行。我们应该为我们的 C++程序编写单元测试，以确保它们在每次更改后都能按照预期的方式运行。

### 为单元测试做准备

有几个 C++测试框架可以与 CMake 一起使用。我们将使用**Google Test**，它比其他选项有几个优点。在下一个练习中，我们将准备我们的项目以便使用 Google Test 进行单元测试。

### 练习 4：为单元测试准备我们的项目

我们已经安装了 Google Test，但我们的项目还没有设置好以使用 Google Test 进行单元测试。除了安装之外，在我们的 CMake 项目中还需要进行一些设置才能进行 Google Test 单元测试。按照以下步骤执行此练习：

1.  打开 Eclipse CDT，并选择我们一直在使用的 CxxTemplate 项目。

1.  创建一个名为**tests**的新文件夹，因为我们将在那里执行所有的测试。

1.  编辑我们的基本`CMakeLists.txt`文件，以允许在`GTest`包中进行测试，该包为 CMake 带来了`GoogleTest`功能。我们将在此之后添加我们的新行：

```cpp
find_package(GTest)
if(GTEST_FOUND)
set(Gtest_FOUND TRUE)
endif()
if(GTest_FOUND)
include(GoogleTest)
endif()
# add these two lines below
enable_testing()
add_subdirectory(tests)
```

这就是我们需要添加到我们主要的`CMakeLists.txt`文件中的所有内容。

1.  在我们主要的`CMakeLists.txt`文件中的`add_subdirectory(tests)`行内创建另一个`CMakeLists.txt`文件。这个`tests/CMakeLists.txt`文件将管理测试源代码。

1.  在`tests/CMakeLists.txt`文件中添加以下代码：

```cpp
include(GoogleTest)
add_executable(tests CanTest.cpp)
target_link_libraries(tests GTest::GTest)
gtest_discover_tests(tests)
```

让我们逐行解析这段代码。第一行引入了 Google Test 功能。第二行创建了`tests`可执行文件，其中将包括所有我们的测试源文件。在这种情况下，我们只有一个`CanTest.cpp`文件，它将验证测试是否有效。之后，我们将`GTest`库链接到`tests`可执行文件。最后一行标识了`tests`可执行文件中的所有单独测试，并将它们添加到`CMake`作为一个测试。这样，各种测试工具将能够告诉我们哪些单独的测试失败了，哪些通过了。

1.  创建一个`tests/CanTest.cpp`文件。添加这段代码来简单验证测试是否运行，而不实际测试我们实际项目中的任何内容：

```cpp
#include "gtest/gtest.h"
namespace {
class CanTest: public ::testing::Test {};
TEST_F(CanTest, CanReallyTest) {
  EXPECT_EQ(0, 0);
}
}  
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
```

`TEST_F`行是一个单独的测试。现在，`EXPECT_EQ(0, 0)`正在测试零是否等于零，如果我们实际运行测试，它将始终成功。稍后，我们将在这里添加我们自己类的结果，以便对各种值进行测试。现在我们的项目中已经具备了 Google Test 的必要设置。接下来，我们将构建和运行这些测试。

### 构建、运行和编写单元测试

现在，我们将讨论如何构建、运行和编写单元测试。到目前为止，我们所拥有的示例是一个简单的虚拟测试，已准备好进行构建和运行。稍后，我们将添加更有意义的测试，并查看通过和失败测试的输出。在接下来的练习中，我们将为上一个练习中创建的项目构建、运行和编写单元测试。

### 练习 5：构建和运行测试

到目前为止，您已经创建了一个设置好的`GoogleTest`的项目，但没有构建或运行我们创建的测试。在这个练习中，我们将构建和运行我们创建的测试。由于我们使用`add_subdirectory`添加了我们的`tests`文件夹，构建项目将自动构建测试。运行测试将需要更多的努力。执行以下步骤完成练习：

1.  在 Eclipse CDT 中打开我们的 CMake 项目。

1.  构建测试，只需像以前一样构建项目即可。以下是在 Eclipse 中进行完整构建后再次构建项目的输出，使用**Project** | **Build All**：![图 1.20：构建操作及其输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_20.jpg)

###### 图 1.20：构建操作及其输出

1.  如果您没有看到此输出，则可能是因为您的控制台处于错误的视图中。您可以按照以下图示进行更正：![图 1.21：查看正确的控制台输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_21.jpg)

###### 图 1.21：查看正确的控制台输出

![图 1.22：查看正确的控制台输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_22.jpg)

###### 图 1.22：查看正确的控制台输出

如您所见，我们的项目现在有两个可执行目标。它们都位于`build`文件夹中，与任何其他构建产物一样。它们的位置分别是`build/Debug/CxxTemplate`和`build/Debug/tests/tests`。由于它们是可执行文件，我们可以直接运行它们。

1.  我们之前运行了`CxxTemplate`，现在不会看到任何额外的输出。通过在项目文件夹中输入以下命令，我们可以运行其他可执行文件：

```cpp
./build/Debug/tests/tests
```

前面的代码在终端中生成了以下输出：

![图 1.23：运行测试可执行文件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_23.jpg)

###### 图 1.23：运行测试可执行文件

这是我们的`tests`可执行文件的简单输出。如果您想查看测试是否通过，您可以简单地运行它。但是，测试远不止于此。

1.  您可以通过使用`ctest`命令之一来运行测试。在项目文件夹中的终端中输入以下命令。我们进入`tests`可执行文件所在的文件夹，运行`ctest`，然后返回：

```cpp
cd build/Debug/tests
ctest
cd ../../..
```

以下是您将看到的输出：

![图 1.24：运行 ctest](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_24.jpg)

###### 图 1.24：运行 ctest

#### 注意

`ctest`命令可以使用多种选项运行您的`tests`可执行文件，包括自动将测试结果提交到在线仪表板的功能。在这里，我们将简单地运行`ctest`命令；其更多功能留给感兴趣的读者作为练习。您可以输入`ctest --help`或访问在线文档以了解更多关于`ctest`的信息，网址为[`cmake.org/cmake/help/latest/manual/ctest.1.html#`](https://cmake.org/cmake/help/latest/manual/ctest.1.html#)。

1.  另一种运行测试的方法是在 Eclipse 中以漂亮的图形报告格式运行它们。为此，我们将创建一个测试感知的运行配置。在 Eclipse 中，单击**Run** | **Run Configurations…**，在左侧右键单击**C/C++ Unit**，然后选择**New Configuration**。

1.  将名称从**CxxTemplate Debug**更改为**CxxTemplate Tests**如下所示：![图 1.25：更改运行配置的名称](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_25.jpg)

###### 图 1.25：更改运行配置的名称

1.  在**C/C++ Application**下，选择**Search Project**选项：![图 1.26：运行配置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_26.jpg)

###### 图 1.26：运行配置

1.  在新对话框中选择**tests**：![图 1.27：创建测试运行配置并选择测试可执行文件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_27.jpg)

###### 图 1.27：创建测试运行配置并选择测试可执行文件

1.  接下来，转到**C/C++ Testing**选项卡，并在下拉菜单中选择**Google Tests Runner**。点击对话框底部的**Apply**，然后点击第一次运行的测试的**Run**选项：![图 1.28：运行配置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_28.jpg)

###### 图 1.28：运行配置

1.  在即将进行的运行中，您可以单击工具栏中播放按钮旁边的下拉菜单，或选择**Run** | **Run History**来选择**CxxTemplate Tests**：

![图 1.29：完成运行配置设置并选择要运行的配置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_29.jpg)

###### 图 1.29：完成运行配置设置并选择要运行的配置

结果将类似于以下截图：

![图 1.30：单元测试的运行结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_30.jpg)

###### 图 1.30：单元测试的运行结果

这是一个很好的报告，包含了所有测试的条目，现在只有一个。如果您不想离开 IDE，您可能会更喜欢这个。此外，当您有许多测试时，此界面可以帮助您有效地对其进行过滤。现在，您已经构建并运行了使用 Google Test 编写的测试。您以几种不同的方式运行了它们，包括直接执行测试，使用`ctest`和使用 Eclipse CDT。在下一节中，我们将解决一个练习，其中我们将实际测试我们代码的功能。

### 练习 6：测试代码功能

您已经运行了简单的测试，但现在您想编写有意义的测试来测试功能。在初始活动中，我们创建了`SumFunc.cpp`，其中包含`sum`函数。现在，在这个练习中，我们将为该文件编写一个测试。在这个测试中，我们将使用`sum`函数来添加两个数字，并验证结果是否正确。让我们回顾一下之前包含`sum`函数的以下文件的内容：

+   `src/SumFunc.h`：

```cpp
#ifndef SRC_SUMFUNC_H_
#define SRC_SUMFUNC_H_
int sum(int a, int b);
#endif /* SRC_SUMFUNC_H_ */
```

+   `src/SumFunc.cpp`：

```cpp
#include "SumFunc.h"
#include <iostream>
int sum(int a, int b) {
  return a + b;
}
```

+   `CMakeLists.txt`的相关行：

```cpp
add_executable(CxxTemplate
  src/CxxTemplate.cpp  
  src/ANewClass.cpp
  src/SumFunc.cpp
)
```

另外，让我们回顾一下我们的`CantTest.cpp`文件，它包含了我们单元测试的`main()`函数：

```cpp
#include "gtest/gtest.h"
namespace {
class CanTest: public ::testing::Test {};
TEST_F(CanTest, CanReallyTest) {
  EXPECT_EQ(0, 0);
}
}  
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
```

执行以下步骤完成练习：

1.  在 Eclipse CDT 中打开我们的 CMake 项目。

1.  添加一个新的测试源文件（`tests/SumFuncTest.cpp`），内容如下：

```cpp
#include "gtest/gtest.h"
#include "../src/SumFunc.h"
namespace {
  class SumFuncTest: public ::testing::Test {};
  TEST_F(SumFuncTest, CanSumCorrectly) {
    EXPECT_EQ(7, sum(3, 4));
  }
}
```

请注意，这里没有`main()`函数，因为`CanTest.cpp`有一个，它们将被链接在一起。其次，请注意，这包括`SumFunc.h`，它在测试中使用了`sum(3, 4)`。这是我们在测试中使用项目代码的方式。

1.  在`tests/CMakeLists.txt`文件中进行以下更改以构建测试：

```cpp
include(GoogleTest)
add_executable(tests CanTest.cpp SumFuncTest.cpp ../src/SumFunc.cpp) # added files here
target_link_libraries(tests GTest::GTest)
gtest_discover_tests(tests)
```

请注意，我们将测试（`SumFuncTest.cpp`）和它测试的代码（`../src/SumFunc.cpp`）都添加到可执行文件中，因为我们的测试代码正在使用实际项目中的代码。

1.  构建项目并像以前一样运行测试。您应该看到以下报告：![图 1.31：运行测试后的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_31.jpg)

###### 图 1.31：运行测试后的输出

我们可以将这样的测试添加到我们的项目中，所有这些测试都将显示在屏幕上，就像前面的截图所示的那样。

1.  现在，让我们添加一个实际失败的测试。在`tests/SumFuncTest.cpp`文件中，进行以下更改：

```cpp
TEST_F(SumFuncTest, CanSumCorrectly) {
  EXPECT_EQ(7, sum(3, 4));
}
// add this test
TEST_F(SumFuncTest, CanSumAbsoluteValues) {
  EXPECT_EQ(6, sum(3, -3));
}
```

请注意，此测试假定输入的绝对值被求和，这是不正确的。这次调用的结果是`0`，但在这个例子中预期是`6`。这是我们在项目中必须做的唯一更改，以添加这个测试。

1.  现在，构建项目并运行测试。您应该会看到这个报告：![图 1.32：构建报告](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_32.jpg)

###### 图 1.32：构建报告

如前图所示，前两个测试通过了，最后一个测试失败了。当我们看到这个输出时，有两种选择：要么我们的项目代码有问题，要么测试有问题。在这种情况下，我们的测试有问题。这是因为我们的`6`等于`sum(3, -3)`。这是因为我们假设我们的函数对提供的整数的绝对值求和。然而，事实并非如此。我们的函数只是简单地添加给定的数字，无论它们是正数还是负数。因此，这个测试有一个错误的假设，所以失败了。

1.  让我们改变测试并修复它。修改测试，使我们期望`-3`和`3`的和为`0`。重命名测试以反映这个测试实际上做了什么：

```cpp
TEST_F(SumFuncTest, CanSumCorrectly) {
  EXPECT_EQ(7, sum(3, 4));
}
// change this part
TEST_F(SumFuncTest, CanUseNegativeValues) {
  EXPECT_EQ(0, sum(3, -3));
}
```

1.  现在运行它，并观察报告中所有测试是否都通过了：

![图 1.33：测试执行成功](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_33.jpg)

###### 图 1.33：测试执行成功

最后，我们已经在系统和项目中使用 CMake 设置了 Google Test。我们还使用 Google Test 编写、构建和运行了单元测试，无论是在终端还是在 Eclipse 中。理想情况下，您应该为每个类编写单元测试，并覆盖每种可能的用法。您还应该在每次重大更改后运行测试，并确保不会破坏现有代码。在下一节中，我们将执行一个添加新类及其测试的活动。

### 活动 2：添加新类及其测试

在开发 C++项目时，随着项目的增长，我们会向其中添加新的源文件。我们还会为它们编写测试，以确保它们正常工作。在这个活动中，我们将添加一个模拟`1D`线性运动的新类。该类将具有`position`和`velocity`的 double 字段。它还将有一个`advanceTimeBy()`方法，接收一个 double `dt`参数，根据`velocity`的值修改`position`。对于 double 值，请使用`EXPECT_DOUBLE_EQ`而不是`EXPECT_EQ`。在这个活动中，我们将向项目中添加一个新类及其测试。按照以下步骤执行此活动：

1.  在 Eclipse IDE 中打开我们创建的项目。

1.  将`LinearMotion1D.cpp`和`LinearMotion1D.h`文件对添加到包含`LinearMotion1D`类的项目中。在这个类中，创建两个 double 字段：`position`和`velocity`。另外，创建一个`advanceTimeBy(double dt)`函数来修改`position`。

1.  在`tests/LinearMotion1DTest.cpp`文件中为此编写测试。编写两个代表两个不同方向运动的测试。

1.  在 Eclipse IDE 中构建并运行它。

1.  验证测试是否通过。

最终的测试结果应该类似于以下内容：

![图 1.34：最终测试结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_34.jpg)

###### 图 1.34：最终测试结果

#### 注意

这个活动的解决方案可以在第 622 页找到。

在 C++开发中，添加新类及其测试是一项非常常见的任务。我们出于各种原因创建类。有时，我们有一个很好的软件设计计划，我们创建它所需的类。其他时候，当一个类变得过大和单一时，我们以有意义的方式将一些责任分离到另一个类中。使这项任务变得实际是很重要的，以防止拖延和最终得到庞大的单一类。在接下来的部分中，我们将讨论编译和链接阶段发生了什么。这将让我们更好地了解 C++程序底层发生了什么。

## 理解编译、链接和目标文件内容

使用 C++的主要原因之一是效率。C++使我们能够控制内存管理，这就是为什么理解对象在内存中的布局很重要的原因。此外，C++源文件和库被编译为目标硬件的对象文件，并进行链接。通常，C++程序员必须处理链接器问题，这就是为什么理解编译步骤并能够调查对象文件很重要的原因。另一方面，大型项目是由团队在长时间内开发和维护的，这就是为什么创建清晰易懂的代码很重要的原因。与任何其他软件一样，C++项目中会出现错误，需要通过观察程序行为来仔细识别、分析和解决。因此，学习如何调试 C++代码也很重要。在接下来的部分中，我们将学习如何创建高效、与其他代码协作良好且易于维护的代码。

### 编译和链接步骤

C++项目是一组源代码文件和项目配置文件，用于组织源文件和库依赖关系。在编译步骤中，这些源文件首先被转换为对象文件。在链接步骤中，这些对象文件被链接在一起，形成项目的最终输出可执行文件。项目使用的库也在这一步中被链接。

在即将进行的练习中，我们将使用现有项目来观察编译和链接阶段。然后，我们将手动重新创建它们以更详细地查看这个过程。

### 练习 7：识别构建步骤

您一直在构建项目而没有调查构建操作的详细信息。在这个练习中，我们将调查我们项目的构建步骤的详细信息。执行以下操作完成练习：

1.  打开终端。

1.  通过输入以下命令导航到`build`文件夹，其中我们的`Makefile`文件位于其中：

```cpp
cd build/Debug
```

1.  使用以下命令清理项目并以`VERBOSE`模式运行构建：

```cpp
make clean 
make VERBOSE=1 all
```

您将在终端中获得构建过程的详细输出，可能会显得有点拥挤：

![图 1.35：构建过程第 1 部分](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_35.jpg)

###### 图 1.35：构建过程第 1 部分

![图 1.36：构建过程第 2 部分](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_36.jpg)

###### 图 1.36：构建过程第 2 部分

![图 1.37：完整的构建输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_37.jpg)

###### 图 1.37：完整的构建输出

以下是此输出中的一些行。以下行是与主可执行文件的编译和链接相关的重要行：

```cpp
/usr/bin/c++    -g   -pthread -std=gnu++1z -o CMakeFiles/CxxTemplate.dir/src/CxxTemplate.cpp.o -c /home/username/Packt/Cpp2019/CxxTemplate/src/CxxTemplate.cpp
/usr/bin/c++    -g   -pthread -std=gnu++1z -o CMakeFiles/CxxTemplate.dir/src/ANewClass.cpp.o -c /home/username/Packt/Cpp2019/CxxTemplate/src/ANewClass.cpp
/usr/bin/c++    -g   -pthread -std=gnu++1z -o CMakeFiles/CxxTemplate.dir/src/SumFunc.cpp.o -c /home/username/Packt/Cpp2019/CxxTemplate/src/SumFunc.cpp
/usr/bin/c++    -g   -pthread -std=gnu++1z -o CMakeFiles/CxxTemplate.dir/src/LinearMotion1D.cpp.o -c /home/username/Packt/Cpp2019/CxxTemplate/src/LinearMotion1D.cpp
/usr/bin/c++  -g   CMakeFiles/CxxTemplate.dir/src/CxxTemplate.cpp.o CMakeFiles/CxxTemplate.dir/src/ANewClass.cpp.o CMakeFiles/CxxTemplate.dir/src/SumFunc.cpp.o CMakeFiles/CxxTemplate.dir/src/LinearMotion1D.cpp.o  -o CxxTemplate -pthread 
```

1.  这里的`c++`命令只是`g++`编译器的符号链接。要查看它实际上是一系列符号链接，输入以下命令：

```cpp
namei /usr/bin/c++
```

您将看到以下输出：

![图 1.38：/usr/bin/c++的符号链接链](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_38.jpg)

###### 图 1.38：/usr/bin/c++的符号链接链

因此，在我们的讨论中，我们将交替使用`c++`和`g++`。在我们之前引用的构建输出中，前四行是编译每个`.cpp`源文件并创建相应的`.o`对象文件。最后一行是将这些对象文件链接在一起以创建`CxxTemplate`可执行文件。以下图形形象地展示了这个过程：

![图 1.39：C++项目的执行阶段](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_39.jpg)

###### 图 1.39：C++项目的执行阶段

如前面的图所示，作为目标的一部分添加到 CMake 中的 CPP 文件以及它们包含的头文件被编译为对象文件，然后将它们链接在一起以创建目标可执行文件。

1.  为了进一步了解这个过程，让我们自己执行编译步骤。在终端中，转到项目文件夹并使用以下命令创建一个名为`mybuild`的新文件夹：

```cpp
cd ~/CxxTemplate
mkdir mybuild
```

1.  然后，运行以下命令将 CPP 源文件编译为对象文件：

```cpp
/usr/bin/c++ src/CxxTemplate.cpp -o mybuild/CxxTemplate.o -c 
/usr/bin/c++ src/ANewClass.cpp -o mybuild/ANewClass.o -c 
/usr/bin/c++ src/SumFunc.cpp -o mybuild/SumFunc.o -c 
/usr/bin/c++ src/LinearMotion1D.cpp -o mybuild/LinearMotion1D.o -c 
```

1.  进入`mybuild`目录，并使用以下命令查看其中的内容：

```cpp
cd mybuild
ls 
```

我们看到了预期的以下输出。这些是我们的目标文件：

![图 1.40：已编译的目标文件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_40.jpg)

###### 图 1.40：已编译的目标文件

1.  在下一步中，将目标文件链接在一起形成我们的可执行文件。输入以下命令：

```cpp
/usr/bin/c++  CxxTemplate.o ANewClass.o SumFunc.o LinearMotion1D.o  -o CxxTemplate 
```

1.  现在，通过输入以下命令，让我们在文件列表中看到我们的可执行文件：

```cpp
ls 
```

这显示了以下图中的新`CxxTemplate`文件：

![图 1.41：链接可执行文件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_41.jpg)

###### 图 1.41：链接可执行文件

1.  现在，通过输入以下命令运行我们的可执行文件：

```cpp
./CxxTemplate
```

然后看看我们之前的输出：

![图 1.42：可执行文件输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_42.jpg)

###### 图 1.42：可执行文件输出

现在您已经检查了构建过程的细节，并自己重新创建了它们，在下一节中，让我们探索链接过程。

### 链接步骤

在本节中，让我们看一下两个源文件之间的联系以及它们如何最终出现在同一个可执行文件中。看看以下图中的**sum**函数：

![图 1.43：链接过程](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_43.jpg)

###### 图 1.43：链接过程

**sum**函数的主体在**SumFunc.cpp**中定义。它在**SumFunc.h**中有一个前向声明。这样，想要使用**sum**函数的源文件可以了解其签名。一旦它们知道了它的签名，它们就可以调用它，并相信在运行时将会有实际的函数定义，而实际上并没有与**SumFunc.cpp**交互。

编译后，调用**sum**函数的**CxxTemplate.cpp**将该调用传递到其目标文件中。但它不知道函数定义在哪里。**SumFunc.cpp**的目标文件具有该定义，但与**CxxTemplate.o**无关。

在链接步骤中，链接器将**CxxTemplate.o**中的调用与**SumFunc.o**中的定义进行匹配。结果，可执行文件中的调用正常工作。如果链接器找不到**sum**函数的定义，它将产生链接器错误。

链接器找到了`无法解析符号`错误。

这使我们经历了构建过程的两个阶段：`编译`和`链接`。请注意，与手动编译源文件时相比，我们使用了相当简单的命令。随时输入`man g++`以查看所有选项。稍后，我们将讨论链接以及符号是如何解析的。我们还讨论了链接步骤可能出现的问题。在下一节中，我们将学习有关目标文件的知识。

### 深入挖掘：查看目标文件

为了使链接步骤能够正常工作，我们需要使所有符号引用与符号定义匹配。大多数情况下，我们可以通过查看源文件来分析解决方案将如何解析。有时，在复杂情况下，我们可能难以理解为什么符号未能解析。在这种情况下，查看目标文件的内容以调查引用和定义可能有助于解决问题。除了链接器错误外，了解目标文件的内容以及链接工作的一般原理对于 C++程序员来说是有用的。了解底层发生的事情可能有助于程序员更好地理解整个过程。

当我们的源代码编译为目标文件时，我们的语句和表达式将转换为汇编代码，这是 CPU 理解的低级语言。汇编中的每条指令都包含一个操作，后跟寄存器，这些寄存器是 CPU 的寄存器。有指令用于将数据加载到寄存器中并从寄存器中加载数据，并对寄存器中的值进行操作。Linux 中的`objdump`命令可帮助我们查看这些目标文件的内容。

#### 注意

我们将利用 Compiler Explorer，这是一个很好用的在线工具，您可以在左侧窗口上编写代码，在右侧可以看到编译后的汇编代码。这是 Compiler Explorer 的链接：[`godbolt.org`](https://godbolt.org)。

### 练习 8：探索编译代码

在这个练习中，我们将使用 Compiler Explorer 编译一些简单的 C++代码，其中我们定义并调用一个函数。我们将调查编译后的汇编代码，以了解名称是如何解析和调用是如何进行的。这将让我们更好地理解发生了什么以及我们的代码在可执行格式中是如何工作的。执行以下步骤完成练习：

1.  在`call sum(int, int)`行中添加以下代码可以实现您的预期：它调用前面的`sum`函数并将参数放入一些寄存器中。这里的重要一点是，函数是通过它们的名称和参数类型按顺序标识的。链接器会寻找具有这个签名的适当函数。请注意，返回值不是签名的一部分。

1.  禁用`_Z`，数字告诉我们函数名的长度，以便正确解释后面的字母。在函数名之后，我们有`v`表示没有参数，`i`表示一个`int`参数。您可以更改这些函数签名以查看其他可能的类型。

1.  现在，让我们看看类是如何编译的。将以下代码添加到**Compiler Explorer**的现有代码下：

```cpp
class MyClass {
private:
    int a = 5;
    int myPrivateFunc(int i) {
        a = 4;
        return i + a;
    }
public:
    int b = 6;
    int myFunc(){ 
        return sum(1, myPrivateFunc(b));
    }
};
MyClass myObject;
int main() {
    myObject.myFunc();
}
```

这是这些添加行的编译版本：

![图 1.46：编译版本](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_46.jpg)

###### 图 1.46：编译版本

您可能会惊讶地发现编译代码中没有类定义。这些方法类似于全局函数，但有一个变化：它们的混淆名称包含类名，并将对象实例作为参数接收。创建实例只是为类的字段分配空间。

在链接器阶段，这些混淆的函数名用于将调用者与被调用者匹配。对于找不到被调用者的调用者，我们会得到链接器错误。大多数链接器错误可以通过仔细检查源代码来解决。然而，在某些情况下，使用`objdump`查看目标文件内容可以帮助找到问题的根源。

## 调试 C++代码

在开发 C++项目时，您可能会遇到不同级别的问题：

+   首先，您可能会收到编译器错误。这可能是因为您在语法上犯了错误，或者选择了错误的类型等。编译器是您必须跨越的第一个障碍，它会捕捉到您可能犯的一些错误。

+   第二个障碍是链接器。在那里，一个常见的错误是使用声明但实际上未定义的内容。当您使用错误的库头文件时，这种情况经常发生——头文件宣传了某个不存在于任何源文件或库中的签名。一旦您也通过了链接器的障碍，您的程序就准备好执行了。

+   现在，下一个要跨越的障碍是避免任何运行时错误。您的代码可能已经编译和链接成功，但可能会出现一些不起作用的情况，比如解引用空指针或除以零。

要查找和修复运行时错误，您必须以某种方式与正在运行的应用程序进行交互和监视。一个经常使用的技术是向代码中添加`print`语句，并监视它生成的日志，希望将应用程序行为与日志相关联，以确定代码中存在问题的区域。虽然这对某些情况有效，但有时您需要更仔细地查看执行情况。

调试器是一个更好的工具来解决运行时错误。调试器可以让你逐行运行代码，继续运行并在你想要的行上暂停，调查内存的值，并在错误上暂停，等等。这让你可以在程序运行时观察内存的具体情况，并确定导致不良行为的代码行。

`gdb`是一个经典的命令行调试器，可以调试 C++程序。然而，它可能难以使用，因为调试本质上是一项视觉任务——你希望能够同时查看代码行、变量值和程序的输出。幸运的是，Eclipse CDT 包含了一个易于使用的可视化调试器。

### 练习 9：使用 Eclipse CDT 进行调试

你之前只是简单地运行项目并查看输出。现在你想要学习如何详细调试你的代码。在这个练习中，我们将探索 Eclipse CDT 的调试能力。按照以下步骤完成练习：

1.  在 Eclipse CDT 中打开 CMake 项目。

1.  为了确保我们有一个现有的运行配置，点击**运行** | **运行配置**。在那里，你应该在**C/C++应用程序**下看到一个**CxxTemplate**条目。

#### 注意

由于我们之前运行了项目，它应该在那里。如果没有，请返回并重新创建。

1.  关闭对话框以继续。

1.  要启动调试器，找到看起来像昆虫（虫子）的工具栏条目，并点击旁边的下拉菜单。选择`main()`函数，它在代码视图中央显示为绿色高亮和箭头。在左侧，我们看到正在运行的线程，其中只有一个。在右侧，我们看到在这个上下文中可访问的变量。在底部，我们看到 Eclipse 在后台使用的**gdb**输出来实际调试可执行文件。现在，我们的主函数没有太多需要调试的地方。

1.  点击`libc-start.c`库，它是`main`函数的调用者。当完成后，你可以关闭它并切换到你的源文件。当你不再看到红色停止按钮时，你就知道程序执行结束了。

1.  通过添加以下代码编辑我们的`main`函数：

```cpp
int i = 1, t = 0;
do {
  t += i++;
} while (i <= 3);
std::cout << t << std::endl;
```

后增量运算符与偶尔的`do-while`循环对一些人来说可能是一个难题。这是因为我们试图在脑海中执行算法。然而，我们的调试器完全能够逐步运行它，并显示在执行过程中到底发生了什么。

1.  在添加了上述代码后开始调试。点击工具栏上**调试**按钮旁边的下拉菜单，选择**CxxTemplate**。按下*F6*几次来逐步执行代码。它会显示变量的变化以及将要执行的代码行：![图 1.48：跳过代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_48.jpg)

###### 图 1.48：跳过代码

1.  在执行每行代码后看到变量的变化，可以更清楚地理解算法。按下*F6*，注意在执行`t += i++;`这行代码后的值：![图 1.49：变量状态随时间变化](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_49.jpg)

###### 图 1.49：变量状态随时间变化

前面的输出清楚地解释了值是如何变化的，以及为什么最后打印出`6`。

1.  探索调试器的其他功能。虽然变量视图很有用，但你也可以悬停在任何变量上并浏览它的值：![图 1.50：调试器的视图选项](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_50.jpg)

###### 图 1.50：调试器的视图选项

此外，**表达式**视图帮助你计算那些从浏览的值中不清楚的东西。

1.  在右侧点击**表达式**，然后点击**添加**按钮：![图 1.51：添加表达式](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_51.jpg)

###### 图 1.51：添加表达式

1.  输入**t+i**并按*Enter*。现在你可以在表达式列表中看到总和：![图 1.52：带有新表达式的表达式视图](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_52.jpg)

###### 图 1.52：带有新表达式的表达式视图

您可以在工具栏中按下红色方块，或选择**运行** | **终止**随时停止调试。另一个功能是断点，它告诉调试器每当它到达带有断点的行时暂停。到目前为止，我们一直在逐行执行我们的代码，这在一个大型项目中可能非常耗时。相反，通常您希望继续执行，直到到达您感兴趣的代码。

1.  现在，不是逐行进行，而是在进行打印的行中添加一个断点。为此，请双击此行行号左侧的区域。在下图中，点表示断点：![图 1.53：使用断点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_53.jpg)

###### 图 1.53：使用断点

1.  现在启动调试器。通常情况下，它将开始暂停。现在选择**运行** | **恢复**或单击工具栏按钮。它将运行循环的三次执行，并在我们的断点处暂停。这样，我们通过跳过我们不调查的代码来节省时间：![图 1.54：使用调试器](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_54.jpg)

###### 图 1.54：使用调试器

1.  当我们处理添加的循环时，我们忽略了创建`app`对象的行。**步过**命令跳过了这行。但是，我们也有选择进入这行中的构造函数调用的选项。为此，我们将使用**运行** | **步入**或相应的工具栏按钮。

1.  停止调试器，然后再次启动。单击**步过**以转到创建应用程序的行：![图 1.55：使用调试器 - 步过选项](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_55.jpg)

###### 图 1.55：使用调试器 - 步过选项

1.  如果我们再次步过，高亮显示的是下一行将执行的行。相反，按下步入按钮。这将带我们进入构造函数调用：

![图 1.56：使用调试器 - 步入选项](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14508_01_56.jpg)

###### 图 1.56：使用调试器 - 步入选项

这是一个方便的功能，可以更深入地了解函数，而不仅仅是跳过它。还要注意左侧调试视图中的调用堆栈。您可以随时单击较低的条目以再次查看调用者的上下文。

这是对 Eclipse CDT 调试器的简要介绍，它在内部使用 GDB 为您提供可视化调试体验。在尝试更好地理解运行时错误并纠正导致这些错误的错误时，您可能会发现调试非常有用。

## 编写可读的代码

虽然可视化调试器非常有用，可以识别和消除运行时错误或意外的程序行为，但更好的做法是编写更不太可能出现问题的代码。其中一种方法是努力编写更易读和理解的代码。然后，在代码中找问题更像是识别英语句子之间的矛盾，而不是解决神秘的谜题。当您以一种易于理解的方式编写代码时，您的错误通常在制造时就会显现出来，并且在您回来解决滑过的问题时更容易发现。

经历了一些令人不愉快的维护经验后，你意识到你编写的程序的主要目的不是让计算机按照你的意愿去做，而是告诉读者程序运行时计算机将会做什么。这通常意味着你需要输入更多的内容，而集成开发环境可以帮助你。这也可能意味着你有时会编写在执行时间或内存使用方面不是最优的代码。如果这与你所学的知识相悖，考虑到你可能在以微不足道的效率换取错误的风险。在我们拥有的庞大处理能力和内存的情况下，你可能会使你的代码变得不必要地晦涩，可能会在追求效率的虚无之中产生错误。在接下来的章节中，我们将列出一些经验法则，这些法则可能会帮助你编写更易读的代码。

### 缩进和格式化

C++代码，就像许多其他编程语言一样，由程序块组成。一个函数有一组语句组成它的主体作为一个块。循环的块语句将在迭代中执行。如果给定条件为真，则`if`语句的块将执行，相应的`else`语句的块将在条件为假时执行。

花括号，或者对于单语句块的缺失，通知计算机，而缩进形式的空白则通知人类读者关于块结构。缺乏缩进或者误导性的缩进会使读者非常难以理解代码的结构。因此，我们应该努力保持我们的代码缩进良好。考虑以下两个代码块：

```cpp
// Block 1
if (result == 2) 
firstFunction();
secondFunction();
// Block 2
if (result == 2) 
  firstFunction();
secondFunction();
```

虽然从执行的角度来看它们是相同的，但在第二个示例中更清楚地表明`firstFunction()`只有在`result`是`2`的情况下才会被执行。现在考虑以下代码：

```cpp
if (result == 2) 
  firstFunction();
  secondFunction();
```

这只是误导。如果读者不小心，他们可能会很容易地假设`secondFunction()`只有在`result`是`2`的情况下才会被执行。然而，从执行的角度来看，这段代码与前两个示例是相同的。

如果你觉得纠正缩进在减慢你的速度，你可以使用编辑器的格式化工具来帮助你。在 Eclipse 中，你可以选择一段代码并使用**源码** | **纠正缩进**来修复该选择的缩进，或者使用**源码** | **格式化**来修复代码的其他格式问题。

除了缩进之外，其他格式规则，比如将花括号放在正确的行上，在二元运算符周围插入空格，以及在每个逗号后插入一个空格，也是非常重要的格式规则，你应该遵守这些规则，以保持你的代码格式良好，易于阅读。

在 Eclipse 中，你可以在**窗口** | **首选项** | **C/C++** | **代码样式** | **格式化程序**中为每个工作空间设置格式化规则，或者在**项目** | **属性** | **C/C++常规** | **格式化程序**中为每个项目设置格式化规则。你可以选择行业标准样式，比如 K&R 或 GNU，或者修改它们并创建自己的样式。当你使用**源码** | **格式化**来格式化你的代码时，这变得尤为重要。例如，如果你选择使用空格进行缩进，但 Eclipse 的格式化规则设置为制表符，你的代码将成为制表符和空格的混合体。

### 使用有意义的标识符名称

在我们的代码中，我们使用标识符来命名许多项目——变量、函数、类名、类型等等。对于计算机来说，这些标识符只是一系列字符，用于区分它们。然而，对于读者来说，它们更重要。标识符应该完全且明确地描述它所代表的项目。同时，它不应该过长。此外，它应该遵守正在使用的样式标准。

考虑以下代码：

```cpp
studentsFile File = runFileCheck("students.dat");
bool flag = File.check();
if (flag) {
    int Count_Names = 0;
    while (File.CheckNextElement() == true) {
        Count_Names += 1;
    }
    std::cout << Count_Names << std::endl;
}
```

虽然这是一段完全有效的 C++代码，但它很难阅读。让我们列出它的问题。首先，让我们看看标识符的风格问题。`studentsFile`类名以小写字母开头，而应该是大写字母。`File`变量应该以小写字母开头。`Count_Names`变量应该以小写字母开头，而且不应该有下划线。`CheckNextElement`方法应该以小写字母开头。虽然这些规则可能看起来是武断的，但在命名上保持一致会携带关于名称的额外信息——当你看到一个以大写字母开头的单词时，你立刻明白它必须是一个类名。此外，拥有不遵守使用标准的名称只会分散注意力。

现在，让我们超越风格，检查名称本身。第一个有问题的名称是`runFileCheck`函数。方法是返回值的动作：它的名称应该清楚地解释它的作用以及它的返回值。 “Check”是一个过度使用的词，在大多数情况下都太模糊了。是的，我们检查了，它在那里——那么我们接下来该怎么办呢？在这种情况下，似乎我们实际上读取了文件并创建了一个`File`对象。在这种情况下，`runFileCheck`应该改为`readFile`。这清楚地解释了正在进行的操作，返回值是你所期望的。如果你想对返回值更具体，`readAsFile`可能是另一种选择。同样，`check`方法太模糊了，应该改为`exists`。`CheckNextElement`方法也太模糊了，应该改为`nextElementExists`。

另一个过度使用的模糊词是`flag`，通常用于布尔变量。名称暗示了一个开/关的情况，但并没有提示其值的含义。在这种情况下，它的`true`值表示文件存在，`false`值表示文件不存在。命名布尔变量的技巧是设计一个问题或语句，当变量的值为`true`时是正确的。在这个例子中，`fileExists`和`doesFileExist`是两个不错的选择。

我们下一个命名不当的变量是`Count_Names`，或者正确的大写形式`countNames`。这对于整数来说是一个糟糕的名称，因为名称并没有暗示一个数字，而是暗示导致一个数字的动作。相反，诸如`numNames`或`nameCount`这样的标识符会清楚地传达内部数字的含义。

### 保持算法清晰简单

当我们阅读代码时，所采取的步骤和流程应该是有意义的。间接进行的事情——函数的副产品，为了效率而一起执行的多个操作等等——这些都会让读者难以理解你的代码。例如，让我们看看以下代码：

```cpp
int *input = getInputArray();
int length = getInputArrayLength();
int sum = 0;
int minVal = 0;
for (int i = 0; i < length; ++i) {
  sum += input[i];
  if (i == 0 || minVal > input[i]) {
    minVal = input[i];
  }
  if (input[i] < 0) {
    input[i] *= -1;
  }
}
```

在这里，我们有一个在循环中处理的数组。乍一看，很难确定循环到底在做什么。变量名帮助我们理解正在发生的事情，但我们必须在脑海中运行算法，以确保这些名称所宣传的确实发生在这里。在这个循环中进行了三种不同的操作。首先，我们找到所有元素的总和。其次，我们找到数组中的最小元素。第三，我们在这些操作之后取每个元素的绝对值。

现在考虑这个替代版本：

```cpp
int *input = getInputArray();
int length = getInputArrayLength();
int sum = 0;
for (int i = 0; i < length; ++i) {
  sum += input[i];
}
int minVal = 0;
for (int i = 0; i < length; ++i) {
  if (i == 0 || minVal > input[i]) {
    minVal = input[i];
  }
}
for (int i = 0; i < length; ++i) {
  if (input[i] < 0) {
    input[i] *= -1;
  }
}
```

现在一切都清晰多了。第一个循环找到输入的总和，第二个循环找到最小的元素，第三个循环找到每个元素的绝对值。虽然现在更清晰、更易理解，但你可能会觉得自己在做三个循环，因此浪费了 CPU 资源。创造更高效的代码的动力可能会促使你合并这些循环。请注意，这里的效率提升微乎其微；你的程序的时间复杂度仍然是 O(n)。

在创建代码时，可读性和效率是经常竞争的两个约束条件。如果你想开发可读性强、易于维护的代码，你应该始终优先考虑可读性。然后，你应该努力开发同样高效的代码。否则，可读性低的代码可能难以维护，甚至可能存在难以识别和修复的错误。当你的程序产生错误结果或者添加新功能的成本变得太高时，程序的高效性就变得无关紧要了。

### 练习 10：使代码更易读

以下代码存在样式和缩进问题。空格使用不一致，缩进不正确。此外，关于单语句`if`块是否使用大括号的决定也不一致。以下代码存在缩进、格式、命名和清晰度方面的问题：

```cpp
//a is the input array and Len is its length
void arrayPlay(int *a, int Len) { 
    int S = 0;
    int M = 0;
    int Lim_value = 100;
    bool flag = true;
    for (int i = 0; i < Len; ++i) {
    S += a[i];
        if (i == 0 || M > a[i]) {
        M = a[i];
        }
        if (a[i] >= Lim_value) {            flag = true;
            }
            if (a[i] < 0) {
            a[i] *= 2;
        }
    }
}
```

让我们解决这些问题，使其符合常见的 C++代码风格。执行以下步骤完成这个练习：

1.  打开 Eclipse CDT。

1.  创建一个新的`a`，其长度为`Len`。对这些更好的命名应该是`input`和`inputLength`。

1.  让我们首先做出这个改变，将`a`重命名为`input`。如果你正在使用 Eclipse，你可以选择`Len`并将其重命名为`inputLength`。

1.  更新后的代码将如下所示。请注意，由于参数名是不言自明的，我们不再需要注释：

```cpp
void arrayPlay(int *input, int inputLength) {
    int S = 0;
    int M = 0;
    int Lim_value = 100;
    bool flag = true;
    for (int i = 0; i < inputLength; ++i) {
        S += input[i];
        if (i == 0 || M > input[i]) {
            M = input[i];
        }
        if (input[i] >= Lim_value) {
            flag = true;
        }
        if (input[i] < 0) {
            input[i] *= 2;
        }
    }
}
```

1.  在循环之前我们定义了一些其他变量。让我们试着理解它们。它似乎只是将每个元素添加到`S`中。因此，`S`必须是`sum`。另一方面，`M`似乎是最小的元素——让我们称它为`smallest`。

1.  `Lim_value`似乎是一个阈值，我们只是想知道它是否被越过。让我们将其重命名为`topThreshold`。如果越过了这个阈值，`flag`变量被设置为 true。让我们将其重命名为`isTopThresholdCrossed`。在这些更改后，代码的状态如下所示：**重构** | **重命名**：

```cpp
void arrayPlay(int *input, int inputLength) {
    int sum = 0;
    int smallest = 0;
    int topThreshold = 100;
    bool isTopThresholdCrossed = true;
    for (int i = 0; i < inputLength; ++i) {
        sum += input[i];
        if (i == 0 || smallest > input[i]) {
            smallest = input[i];
        }
        if (input[i] >= topThreshold) {
            isTopThresholdCrossed = true;
        }
        if (input[i] < 0) {
            input[i] *= 2;
        }
    }
}
```

现在，让我们看看如何使这段代码更简单、更易理解。前面的代码正在做这些事情：计算输入元素的总和，找到最小的元素，确定是否越过了顶部阈值，并将每个元素乘以 2。

1.  由于所有这些都是在同一个循环中完成的，现在算法不太清晰。修复这个问题，将其分为四个独立的循环：

```cpp
void arrayPlay(int *input, int inputLength) {
    // find the sum of the input
    int sum = 0;
    for (int i = 0; i < inputLength; ++i) {
        sum += input[i];
    }
    // find the smallest element
    int smallest = 0;
    for (int i = 0; i < inputLength; ++i) {
        if (i == 0 || smallest > input[i]) {
            smallest = input[i];
        }
    }
    // determine whether top threshold is crossed
    int topThreshold = 100;
    bool isTopThresholdCrossed = true;
    for (int i = 0; i < inputLength; ++i) {
        if (input[i] >= topThreshold) {
            isTopThresholdCrossed = true;
        }
    }
    // multiply each element by 2
    for (int i = 0; i < inputLength; ++i) {
        if (input[i] < 0) {
            input[i] *= 2;
        }
    }
}
```

现在代码清晰多了。虽然很容易理解每个块在做什么，但我们还添加了注释以使其更清晰。在这一部分，我们更好地理解了我们的代码是如何转换为可执行文件的。然后，我们讨论了识别和解决可能的代码错误的方法。我们最后讨论了如何编写可读性更强、更不容易出现问题的代码。在下一部分，我们将解决一个活动，我们将使代码更易读。

### 活动 3：使代码更易读

你可能有一些难以阅读并且包含错误的代码，要么是因为你匆忙写成的，要么是因为你从别人那里收到的。你想改变代码以消除其中的错误并使其更易读。我们有一段需要改进的代码。逐步改进它并使用调试器解决问题。执行以下步骤来实施这个活动：

1.  下面是`SpeedCalculator`类的源代码。将这两个文件添加到你的项目中。

1.  在你的`main()`函数中创建这个类的一个实例，并调用它的`run()`方法。

1.  修复代码中的风格和命名问题。

1.  简化代码以使其更易理解。

1.  运行代码并观察运行时的问题。

1.  使用调试器来解决问题。

这是**SpeedCalculator.cpp**和**SpeedCalculator.h**的代码，你将把它们添加到你的项目中。你将修改它们作为这个活动的一部分：

```cpp
// SpeedCalculator.h
#ifndef SRC_SPEEDCALCULATOR_H_
#define SRC_SPEEDCALCULATOR_H_
class SpeedCalculator {
private:
    int numEntries;
    double *positions;
    double *timesInSeconds;
    double *speeds;
public:
    void initializeData(int numEntries);
    void calculateAndPrintSpeedData();
};
#endif /* SRC_SPEEDCALCULATOR_H_ */

//SpeedCalculator.cpp
#include "SpeedCalculator.h"
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <cassert>
void SpeedCalculator::initializeData(int numEntries) {
    this->numEntries = numEntries;
    positions = new double[numEntries];
    timesInSeconds = new double[numEntries];
    srand(time(NULL));
    timesInSeconds[0] = 0.0;
    positions[0] = 0.0;
    for (int i = 0; i < numEntries; ++i) {
    positions[i] = positions[i-1] + (rand()%500);
    timesInSeconds[i] = timesInSeconds[i-1] + ((rand()%10) + 1);
    }
}
void SpeedCalculator::calculateAndPrintSpeedData() {
    double maxSpeed = 0;
    double minSpeed = 0;
    double speedLimit = 100;
    double limitCrossDuration = 0;
    for (int i = 0; i < numEntries; ++i) {
        double dt = timesInSeconds[i+1] - timesInSeconds[i];
        assert (dt > 0);
        double speed = (positions[i+1] - positions[i]) / dt;
            if (maxSpeed < speed) {
                maxSpeed = speed;
            }
            if (minSpeed > speed) {
                minSpeed = speed;
            }
        if (speed > speedLimit) {
            limitCrossDuration += dt;
        }
        speeds[i] = speed;
    }
    std::cout << "Max speed: " << maxSpeed << std::endl;
        std::cout << "Min speed: " << minSpeed << std::endl;
        std::cout << "Total duration: " << 
timesInSeconds[numEntries - 1] - timesInSeconds[0] << " seconds" << std::endl;
    std::cout << "Crossed the speed limit for " << limitCrossDuration << " seconds"<< std::endl;
    delete[] speeds;
}
```

#### 注意

这个活动的解决方案可以在第 626 页找到。

## 总结

在本章中，我们学习了如何创建可移植和可维护的 C++项目。我们首先学习了如何创建 CMake 项目以及如何将它们导入到 Eclipse CDT，从而使我们可以选择使用命令行或者 IDE。本章的其余部分侧重于消除项目中的各种问题。首先，我们学习了如何向项目添加单元测试，以及如何使用它们来确保我们的代码按预期工作。然后，我们讨论了代码经历的编译和链接步骤，并观察了目标文件的内容，以更好地理解可执行文件。接着，我们学习了如何在 IDE 中以可视化方式调试我们的代码，以消除运行时错误。我们用一些经验法则结束了这个讨论，这些法则有助于创建可读、易懂和可维护的代码。这些方法将在你的 C++之旅中派上用场。在下一章中，我们将更多地了解 C++的类型系统和模板。


# 第二章：禁止鸭子 - 类型和推断

## 学习目标

通过本章结束时，您将能够：

+   实现自己的类，使其行为类似于内置类型

+   实现控制编译器创建的函数的类（零规则/五规则）

+   使用 auto 变量开发函数，就像你一直做的那样

+   通过使用强类型编写更安全的代码来实现类和函数

本章将为您提供对 C++类型系统的良好基础，并使您能够编写适用于该系统的自己的类型。

## 引言

C++是一种强类型、静态类型的语言。编译器使用与使用的变量相关的类型信息以及它们所用的上下文来检测和防止某些类别的编程错误。这意味着每个对象都有一个类型，而且该类型永远不会改变。相比之下，Python 和 PHP 等动态类型语言将类型检查推迟到运行时（也称为后期绑定），变量的类型可能在应用程序执行过程中发生变化。这些语言使用鸭子测试而不是变量类型 - 也就是说，“如果它走起来像鸭子，叫起来像鸭子，那么它一定是鸭子。”C++等静态类型语言依赖于类型来确定变量是否可以用于特定目的，而动态类型语言依赖于某些方法和属性的存在来确定其适用性。

C++最初被描述为“带类的 C”。这是什么意思？基本上，C 提供了一组内置的基本类型 - int、float、char 等 - 以及这些项的指针和数组。您可以使用 struct 将这些聚合成相关项的数据结构。C++将此扩展到类，以便您可以完全定义自己的类型，包括可以用来操作它们的运算符，从而使它们成为语言中的一等公民。自其谦卑的开始以来，C++已经发展成为不仅仅是“带类的 C”，因为它现在可以表达面向对象范式（封装、多态、抽象和继承）、函数范式和泛型编程（模板）。

在本书中，我们将重点关注 C++支持面向对象范式的含义。随着您作为开发人员的经验增长，并且接触到像 Clojure、Haskell、Lisp 和其他函数式语言，它们将帮助您编写健壮的 C++代码。动态类型语言如 Python、PHP 和 Ruby 已经影响了我们编写 C++代码的方式。随着 C++17 的到来，引入了`std::variant`类 - 一个在编译时保存我们选择的任何类型，并且在动态语言中的变量类似。

在上一章中，我们学习了如何使用 CMake 创建可移植和可维护的 C++项目。我们学习了如何在项目中加入单元测试，以帮助编写正确的代码，并在出现问题时进行调试。我们了解了工具链如何将我们的代码通过一系列程序流水线处理，以生成可执行文件。最后，我们总结了一些经验法则，帮助我们创建可读性强、理解性好、易于维护的代码。

在本章中，我们将快速浏览 C++类型系统，声明和使用我们自己的类型。

## C++类型

作为一种强类型和静态类型的语言，C++提供了几种基本类型，并能够根据需要定义自己的类型，以解决手头的问题。本节将首先介绍基本类型，初始化它们，声明变量，并将类型与之关联。然后我们将探讨如何声明和定义新类型。

### C++基本类型

C++包括几种*基本类型*或*内置类型*。C++标准定义了每种类型在内存中的最小大小和它们的相对大小。编译器识别这些基本类型，并具有内置规则来定义可以对它们执行哪些操作和不能执行哪些操作。还有关于类型之间的隐式转换的规则；例如，从 int 类型到 float 类型的转换。

#### 注意

有关所有内置类型的简要描述，请参阅[`en.cppreference.com/w/cpp/language/types`](https://en.cppreference.com/w/cpp/language/types)中的**基本类型**部分。

### C++文字量

C++文字量用于告诉编译器您希望在声明变量或对其进行赋值时与变量关联的值。前一节中的每种内置类型都有与之关联的文字量形式。

#### 注意

有关每种类型的文字量的简要描述，请参阅[`en.cppreference.com/w/cpp/language/expressions`](https://en.cppreference.com/w/cpp/language/expressions)中的**文字量**部分。

## 指定类型 - 变量

由于 C++是一种静态类型语言，在声明变量时需要指定变量的类型。当声明函数时，需要指定返回类型和传递给它的参数的类型。在声明变量时，有两种选择可以指定类型：

+   **显式**：您作为程序员正在明确指定类型。

+   **隐式**（使用 auto）：您告诉编译器查看用于初始化变量的值并确定其类型。这被称为（auto）**类型推导**。

标量变量的声明一般形式如下之一：

```cpp
type-specifier var;                       // 1\. Default-initialized variable
type-specifier var = init-value;          // 2\. Assignment initialized variable
type-specifier var{init-value};           // 3\. Brace-initialize variable
```

`type-specifier`指示您希望将`var`变量与之关联的类型（基本类型或用户定义类型）。所有三种形式都会导致编译器分配一些存储空间来保存值，并且将来对`var`的所有引用都将引用该位置。`init-value`用于初始化存储位置。默认初始化对内置类型无效，并将根据函数重载解析调用用户定义类型的构造函数来初始化存储。

编译器必须知道要分配多少内存，并提供一个运算符来确定类型或变量有多大 - `sizeof`。

根据我们的声明，编译器将在计算机的内存中留出空间来存储变量引用的数据项。考虑以下声明：

```cpp
int value = 42;     // declare value to be an integer and initialize to 42
short a_value{64};  // declare a_value to be a short integer and initialize
                    //    to 64
int bad_idea;       // declare bad_idea to be an integer and DO NOT 
                    // initialize it. Use of this variable before setting
                    // it is UNDEFINED BEHAVIOUR.
float pi = 3.1415F; // declare pi to be a single precision floating point
                    // number and initialize it to pi.
double e{2.71828};  // declare e to be a double precision floating point
                    // number and initialize it to natural number e.
auto title = "Sir Robin of Loxley"; // Let the compiler determine the type
```

如果这些是在函数范围内声明的，那么编译器会从所谓的堆栈中为它们分配内存。这可能看起来像以下的内存布局：

![图 2A.1：变量的内存布局](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_01.jpg)

###### 图 2A.1：变量的内存布局

编译器将按照我们声明变量的顺序分配内存。未使用的内存是因为编译器分配内存，以便基本类型通常是原子访问的，并且为了效率而对齐到适当的内存边界。请注意，`title`是`const char *`类型，是`const`。**"Sir Robin of Loxley"**字符串将存储在程序加载时初始化的内存的不同部分。我们将在后面讨论程序内存。

标量声明语法的轻微修改给我们提供了声明值数组的语法：

```cpp
type-specifier ary[count];                          // 1\. Default-initialized 
type-specifier ary[count] = {comma-separated list}; // 2\. Assignment initialized 
type-specifier ary[count]{comma-separated list};    // 3\. Brace-initialized
```

这可以用于多维数组，如下所示：

```cpp
type-specifier ary2d[countX][countY]; 
type-specifier ary3d[countX][countY][countZ];
// etc...
```

请注意，前述声明中的`count`、`countX`和其他项目在编译时必须评估为常量，否则将导致错误。此外，逗号分隔的初始化列表中的项目数必须小于或等于`count`，否则将再次出现编译错误。在下一节中，我们将在练习中应用到目前为止学到的概念。

#### 注意

在本章的任何实际操作之前，下载本书的 GitHub 存储库（[`github.com/TrainingByPackt/Advanced-CPlusPlus`](https://github.com/TrainingByPackt/Advanced-CPlusPlus)），并在 Eclipse 中导入 Lesson 2A 文件夹，以便您可以查看每个练习和活动的代码。

### 练习 1：声明变量和探索大小

这个练习将为本章的所有练习设置，并让您熟悉声明和初始化内置类型的变量。您还将介绍`auto 声明`，`数组`和`sizeof`。让我们开始吧：

1.  打开 Eclipse（在*第一章* *可移植 C++软件的解剖*中使用），如果出现启动窗口，请点击启动。

1.  转到**File**，在**New** **►**下选择**Project…**，然后转到选择 C++ Project（而不是 C/C++ Project）。

1.  点击**Next >**，清除**Use default location**复选框，并输入**Lesson2A**作为**Project name**。

1.  选择**Empty Project**作为**Project Type**。然后，点击**Browse…**并导航到包含 Lesson2A 示例的文件夹。

1.  点击**打开**以选择文件夹并关闭对话框。

1.  点击**Next >**，**Next >**，然后点击**Finish**。

1.  为了帮助您进行练习，我们将配置工作区在构建之前自动保存文件。转到**Window**，选择**Preferences**。在**General**下，打开**Workspace**并选择**Build**。

1.  勾选**Save automatically before build**框，然后点击**Apply and Close**。

1.  就像*第一章* *可移植 C++软件的解剖*一样，这是一个基于 CMake 的项目，所以我们需要更改当前的构建器。在**Project**资源管理器中点击**Lesson2A**，然后在**Project**菜单下点击**Properties**。在左侧窗格中选择 C/C++ Build 下的 Tool Chain Editor，并将 Current builder 设置为 Cmake Build（portable）。

1.  点击**Apply and Close**。然后，选择**Project** | **Build All**菜单项来构建所有练习。默认情况下，屏幕底部的控制台将显示**CMake Console [Lesson2A]**：![图 2A.2：CMake 控制台输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_02.jpg)

###### 图 2A.2：CMake 控制台输出

1.  在控制台的右上角，点击**Display Selected Console**按钮，然后从列表中选择**CDT Global Build Console**：![图 2A.3：选择不同的控制台](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_03.jpg)

###### 图 2A.3：选择不同的控制台

这将显示构建的结果 - 应该显示 0 个错误和 3 个警告：

![图 2A.4：构建过程控制台输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_04.jpg)

###### 图 2A.4：构建过程控制台输出

1.  由于构建成功，我们希望运行 Exercise1。在窗口顶部，点击下拉列表，选择**No Launch Configurations**：![图 2A.5：启动配置菜单](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_05.jpg)

###### 图 2A.5：启动配置菜单

1.  点击**New Launch Configuration…**。保持默认设置，然后点击**Next >**。

1.  将**Name**更改为**Exercise1**，然后点击**Search Project**：![图 2A.6：Exercise1 启动配置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_06.jpg)

###### 图 2A.6：Exercise1 启动配置

1.  从 Binaries 窗口中显示的程序列表中，点击**Exercise1**，然后点击**OK**。

1.  点击**Finish**。这将导致 exercise1 显示在启动配置下拉框中：![图 2A.7：更改启动配置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_07.jpg)

###### 图 2A.7：更改启动配置

1.  要运行**Exercise1**，点击**Run**按钮。Exercise1 将在控制台中执行并显示其输出：![图 2A.8：exercise1 的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_08.jpg)

###### 图 2A.8：exercise1 的输出

该程序没有任何价值 - 它只输出系统中各种类型的大小。但这表明程序是有效的并且可以编译。请注意，您系统的数字可能会有所不同（特别是 sizeof（title）的值）。

1.  在“项目资源管理器”中，展开“Lesson2A”，然后展开“Exercise01”，双击“Exercise1.cpp”以在编辑器中打开此练习的文件：

```cpp
int main(int argc, char**argv)
{
    std::cout << "\n\n------ Exercise 1 ------\n";
    int value = 42;     // declare value to be an integer & initialize to 42
    short a_value{64};  // declare a_value to be a short integer & 
                        // initialize to 64
    int bad_idea;       // declare bad_idea to be an integer and DO NOT 
                        // initialize it. Use of this variable before 
                        // setting it is UNDEFINED BEHAVIOUR.
    float pi = 3.1415F; // declare pi to be a single precision floating 
                        // point number and initialize it to pi.

    double e{2.71828};  // declare e to be a double precision floating point
                        // number and initialize it to natural number e.
    auto title = "Sir Robin of Loxley"; 
                        // Let the compiler determine the type
    int ary[15]{};      // array of 15 integers - zero initialized
    // double pi = 3.14159;  // step 24 - remove comment at front
    // auto speed;           // step 25 - remove comment at front
    // value = "Hello world";// step 26 - remove comment at front
    // title = 123456789;    // step 27 - remove comment at front
    // short sh_int{32768};  // step 28 - remove comment at front
    std::cout << "sizeof(int) = " << sizeof(int) << "\n";
    std::cout << "sizeof(short) = " << sizeof(short) << "\n";
    std::cout << "sizeof(float) = " << sizeof(float) << "\n";
    std::cout << "sizeof(double) = " << sizeof(double) << "\n";
    std::cout << "sizeof(title) = " << sizeof(title) << "\n";
    std::cout << "sizeof(ary) = " << sizeof(ary)
              << " = " << sizeof(ary)/sizeof(ary[0]) 
              << " * " << sizeof(ary[0]) << "\n";
    std::cout << "Complete.\n";
    return 0;
}
```

关于前面的程序，需要注意的一点是，主函数的第一条语句实际上是可执行语句，而不是声明。 C++允许您几乎可以在任何地方声明变量。 它的前身 C 最初要求所有变量必须在任何可执行语句之前声明。

#### 最佳实践

尽可能靠近将要使用的位置声明变量并初始化它。

1.  在编辑器中，通过删除行开头的分隔符（//）取消注释标记为“步骤 24”的行：

```cpp
double pi = 3.14159;  // step 24 - remove comment at front    
// auto speed;           // step 25 - remove comment at front
// value = "Hello world";// step 26 - remove comment at front
// title = 123456789;    // step 27 - remove comment at front
// short sh_int{32768};  // step 28 - remove comment at front
```

1.  再次单击“运行”按钮。 这将导致再次构建程序。 这一次，构建将失败，并显示错误：![图 2A.9：工作区中的错误对话框](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_09.jpg)

###### 图 2A.9：工作区中的错误对话框

1.  单击“取消”关闭对话框。 如果未显示“CDT 构建控制台[Lesson2A]”，则将其选择为活动控制台：![图 2A.10：重复声明错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_10.jpg)

###### 图 2A.10：重复声明错误

这一次，构建失败，因为我们尝试重新定义变量 pi 的类型。 编译器提供了有关我们需要查找以修复错误的位置的有用信息。

1.  将注释分隔符恢复到行的开头。 在编辑器中，通过删除行开头的分隔符（//）取消注释标记为“步骤 25”的行：

```cpp
// double pi = 3.14159;  // step 24 - remove comment at front    
auto speed;           // step 25 - remove comment at front
// value = "Hello world";// step 26 - remove comment at front
// title = 123456789;    // step 27 - remove comment at front
// short sh_int{32768};  // step 28 - remove comment at front
```

1.  再次单击“运行”按钮。 当“工作区中的错误”对话框出现时，单击“取消”：![图 2A.11：自动声明错误-无初始化](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_11.jpg)

###### 图 2A.11：自动声明错误-无初始化

再次构建失败，但这次我们没有给编译器足够的信息来推断速度的类型-自动类型的变量必须初始化。

1.  将注释分隔符恢复到行的开头。 在编辑器中，通过删除注释起始分隔符（//）取消注释标记为“步骤 26”的行：

```cpp
// double pi = 3.14159;  // step 24 - remove comment at front    
// auto speed;           // step 25 - remove comment at front
value = "Hello world";// step 26 - remove comment at front
// title = 123456789;    // step 27 - remove comment at front
// short sh_int{32768};  // step 28 - remove comment at front
```

1.  单击“值”。

1.  将注释分隔符恢复到行的开头。 在编辑器中，通过删除行开头的分隔符（//）取消注释标记为“步骤 27”的行：

```cpp
// double pi = 3.14159;  // step 24 - remove comment at front    
// auto speed;           // step 25 - remove comment at front
// value = "Hello world";// step 26 - remove comment at front
title = 123456789;    // step 27 - remove comment at front
// short sh_int{32768};  // step 28 - remove comment at front
```

1.  单击`int`，以标题，这是一个`const char*`。 这里非常重要的一点是，`title`是用`auto`类型声明的。 编译器生成的错误消息告诉我们，`title`被推断为`const char*`类型。

1.  将注释分隔符恢复到行的开头。 在编辑器中，通过删除行开头的分隔符（//）取消注释标记为“步骤 28”的行：

```cpp
// double pi = 3.14159;  // step 24 - remove comment at front    
// auto speed;           // step 25 - remove comment at front
// value = "Hello world";// step 26 - remove comment at front
// title = 123456789;    // step 27 - remove comment at front
short sh_int{32768};  // step 28 - remove comment at front
```

1.  单击`sh_int`与（`short`类型。 短占用两个字节的内存，被认为是 16 位的有符号数量。 这意味着可以存储在短中的值的范围是`-2^(16-1)`到`2^(16-1)-1`，或**-32768**到**32767**。

1.  将值从`short`更改。

1.  将值从`short`更改。

1.  将注释分隔符恢复到行的开头。 在编辑器中，尝试使用任何基本类型及其相关文字来探索变量声明，然后尽可能多地单击“运行”按钮。 检查“构建控制台”的输出是否有任何错误消息，因为这可能会帮助您找到错误。

在这个练习中，我们学习了如何设置 Eclipse 开发，实现变量声明，并解决声明中的问题。

## 指定类型-函数

现在我们可以声明一个变量为某种类型，我们需要对这些变量做些什么。 在 C++中，我们通过调用函数来做事情。 函数是一系列语句，产生结果。 结果可能是数学计算（例如，指数）然后发送到文件或写入终端。

函数允许我们将解决方案分解为更易于管理和理解的语句序列。当我们编写这些打包的语句时，我们可以在合适的地方重复使用它们。如果我们需要根据上下文使其以不同方式运行，那么我们会传入一个参数。如果它返回一个结果，那么函数需要一个返回类型。

由于 C++是一种强类型语言，我们需要指定与我们实现的函数相关的类型 - 函数返回的值的类型（包括无返回）以及传递给它的参数的类型（如果有的话）。

以下是一个典型的 hello world 程序：

```cpp
#include <iostream>
void hello_world()
{
  std::cout << "Hello world\n"; 
}
int main(int argc, char** argv)
{
  std::cout << "Starting program\n";
  hello_world();
  std::cout << "Exiting program\n";
  return 0;
}
```

在上面的例子中声明了两个函数 - `hello_world()`和`main()`。`main()`函数是每个 C++程序的入口点，并返回一个传递给主机系统的`int`值。它被称为退出代码。

从返回类型的声明到开括号（{）之间的所有内容都被称为**函数原型**。它定义了三件事，即返回类型、函数的名称和参数的数量和类型。

对于第一个函数，返回类型是`void` - 也就是说，它不返回任何值；它的名称是`hello_world`，不需要参数：

![图 2A.15：不带参数并且不返回任何内容的函数声明](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_15.jpg)

###### 图 2A.15：不带参数并且不返回任何内容的函数声明

第二个函数返回一个`int`值，名称为`main`，并带有两个参数。这些参数分别是`argc`和`argv`，类型分别为`int`和`char`类型的*指针的指针*：

![图 2A.16：带有两个参数并返回 int 的函数声明](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_16.jpg)

###### 图 2A.16：带有两个参数并返回 int 的函数声明

函数原型之后的所有内容都被称为**函数体**。函数体包含变量声明和要执行的语句。

函数在使用之前必须声明 - 也就是说，编译器需要知道它的参数和返回类型。如果函数在调用它的文件中定义在它之后，那么可以通过在使用之前提供函数的前向声明来解决这个问题。

通过在调用之前的文件中放置以分号终止的函数原型来进行前向声明。对于`hello_world()`，可以这样做：

```cpp
void hello_world();
```

对于主函数，可以这样做：

```cpp
int main(int, char**);
```

函数原型不需要参数的名称，只需要类型。但是，为了帮助函数的用户，保留参数是个好主意。

在 C++中，函数的定义可以在一个文件中，需要从另一个文件中调用。那么，第二个文件如何知道它希望调用的函数的原型？这是通过将前向声明放入一个名为头文件的单独文件中并在第二个文件中包含它来实现的。

### 练习 2：声明函数

在这个练习中，我们将测试编译器在遇到函数调用时需要了解的内容，并实现一个前向声明来解析未知的函数。让我们开始吧。

1.  在 Eclipse 中打开**Lesson2A**项目，然后在**Project Explorer**中展开**Lesson2A**，然后展开**Exercise02**，双击**Exercise2.cpp**以在编辑器中打开此练习的文件。

1.  单击**Launch Configuration**下拉菜单，选择**New Launch Configuration…**。

1.  将**Exercise2**配置为以名称**Exercise2**运行。完成后，它将成为当前选择的启动配置。

1.  单击**Run**按钮。练习 2 将运行并产生以下输出：![图 2A.17：exercise2 程序的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_17.jpg)

###### 图 2A.17：exercise2 程序的输出

1.  进入编辑器，通过将`gcd`函数移动到`main`之后来更改代码。它应该如下所示：

```cpp
int main(int argc, char**argv)
{
    std::cout << "\n\n------ Exercise 2 ------\n";
    std::cout << "The greatest common divisor of 44 and 121 is " << gcd(44, 121) << "\n";
    std::cout << "Complete.\n";
    return 0;
}
int gcd(int x, int y)
{
    while(y!=0)
    {
        auto c{x%y};
        x = y;
        y = c;
    }
    return x;
}
```

1.  点击`gcd()`函数。在需要调用它的时候，它对该函数没有任何了解，即使它在相同的文件中定义，但是在调用之后。

1.  在编辑器中，将前向声明放在主函数定义之前。同时在末尾添加一个分号（;）：

```cpp
int gcd(int x, int y);
```

1.  再次点击**运行**按钮。这次，程序编译并恢复原始输出。

在这个练习中，我们学习了如何提前声明函数并解决编译器错误，这些错误发生在使用函数之前未声明的情况下。

在早期的 C 编译器版本中，这是可以接受的。程序会假定函数存在并返回一个 int。函数的参数可以从调用中推断出来。然而，在现代 C++中并非如此，因为您必须在使用之前声明函数、类、变量等。在下一节中，我们将学习指针类型。

### 指针类型

由于 C 语言的起源，即编写高效的系统并直接访问硬件，C++允许您将变量声明为指针类型。其格式如下：

```cpp
type-specifier* pvar = &var;
```

这与以前一样，只有两个不同之处：

+   使用特殊声明符星号（`*`）指示名为 pvar 的变量指向内存中的位置或地址。

+   它使用特殊运算符和号（`&`）进行初始化，在这种情况下告诉编译器返回`var`变量的地址。

由于 C 是一种高级语言，但具有低级访问权限，指针允许用户直接访问内存，这在我们希望向硬件提供输入/输出并控制硬件时非常有帮助。指针的另一个用途是允许函数访问共同的数据项，并在调用函数时消除大量数据的复制需求，因为它默认为按值传递。要访问指针指向的值，使用特殊运算符星号（`*`）来**解引用**位置：

```cpp
int five = 5;                // declare five and initialize it
int *pvalue = &five;         // declare pvalue as pointer to int and have it
                            // point to the location of five
*pvalue = 6;                // Assign 6 into the location five.
```

下图显示了编译器分配内存的方式。`pvalue`需要内存来存储指针，而`five`需要内存来存储整数值 5：

![图 2A.19：指针变量的内存布局](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_19.jpg)

###### 图 2A.19：指针变量的内存布局

当通过指针访问用户定义的类型时，还有第二个特殊运算符（->）用于解引用成员变量和函数。在现代 C++中，这些指针被称为**原始指针**，它们的使用方式发生了显著变化。在 C 和 C++中使用指针一直是程序员面临的挑战，它们的错误使用是许多问题的根源，最常见的是资源泄漏。资源泄漏是指程序获取了资源（内存、文件句柄或其他系统资源）供其使用，但在使用完毕后未释放。这些资源泄漏可能导致性能问题、程序失败，甚至系统崩溃。在现代 C++中使用原始指针来管理资源的所有权现已被弃用，因为智能指针在 C++11 中出现。智能指针（在 STL 中实现为类）现在执行所需的清理工作，以成为主机系统中的良好组成部分。关于这一点将在*第三章*，*能与应该之间的距离-对象、指针和继承*中进行更多介绍。

在上面的代码中，当声明`pvalue`时，编译器只分配内存来存储它将引用的内存的地址。与其他变量一样，您应始终确保在使用指针之前对其进行初始化，因为对未初始化的指针进行解引用会导致未定义的行为。存储指针的内存量取决于编译器设计的系统以及处理器支持的位数。但是，无论它们指向什么类型，所有指针的大小都将相同。

指针也可以传递给函数。这允许函数访问指向的数据并可能修改它。考虑以下 swap 的实现：

```cpp
void swap(int* data1, int* data2)
{
    int temp{*data1};         // Initialize temp from value pointed to by data1
    *data1 = *data2;          // Copy data pointed to by data2 into location 
                              // pointed to by data1
    *data2 = temp;            // Store the temporarily cached value from temp
                              // into the location pointed to by data2
}
```

这展示了如何将指针声明为函数的参数，如何使用解引用运算符`*`从指针获取值，以及如何通过解引用运算符设置值。

以下示例使用 new 运算符从主机系统中分配内存，并使用 delete 运算符将其释放回主机系统：

```cpp
char* name = new char[20];    // Allocate 20 chars worth of memory and assign it
                              // to name.
  Do something with name
delete [] name;
```

在上面的代码中，第一行使用 new 运算符的数组分配形式创建了一个包含 20 个字符的数组。它向主机系统发出调用，为我们分配 20 * sizeof(char)字节的内存。分配多少内存取决于主机系统，但保证至少为 20 * sizeof(char)字节。如果无法分配所需的内存，则会发生以下两种情况之一：

+   它会抛出一个异常

+   它将返回`nullptr`。这是 C++11 中引入的特殊文字。早期，C++使用 0 或 NULL 表示无效指针。C++11 也将其作为强类型值。

在大多数系统上，第一个结果将是结果，并且您需要处理异常。第二个结果可能来自两种情况——调用 new 的 nothrow 变体，即`new(std::nothrow) int [250]`，或者在嵌入式系统上，异常处理的开销不够确定。

最后，请注意，delete 的调用使用了 delete 运算符的数组形式，即带有方括号[]。重要的是确保与 new 和 delete 运算符一起使用相同的形式。当 new 用于用户定义的类型（将在下一节中讨论）时，它不仅仅是分配内存：

```cpp
MyClass* object = new MyClass;
```

在上面的代码中，对 new 的调用分配了足够的内存来存储 MyClass，如果成功，它会继续调用构造函数来初始化数据：

```cpp
MyClass* objects = new MyClass[12];
```

在上面的代码中，对 new 的调用分配了足够的内存来存储 12 个 MyClass 的副本，如果成功，它会继续调用构造函数 12 次来初始化每个对象的数据。

请注意，在上面代码片段中声明的`object`和`objects`，`objects`应该是指向 MyClass 数组的指针，但实际上它是 MyClass 实例的指针。`objects`指向 MyClass 数组中的第一个实例。

考虑以下代码摘录：

```cpp
void printMyClasses(MyClass* objects, size_t number)
{
  for( auto i{0U} ; i<number ; i++ ) { 
    std::cout << objects[i] << "\n";
  }
}
void process()
{
    MyClass objects[12];

    // Do something with objects
    printMyClasses(objects, sizeof(objects)/sizeof(MyClass));
}
```

在 process()函数中，`objects`是"包含 12 个 MyClass 项的数组"类型，但当它传递给`printMyClasses()`时，它被（由编译器）转换为"指向 MyClass 的指针"类型。这是有意设计的（从 C 继承而来），并且被称为`printMyClasses()`如下：

```cpp
void printMyClasses(MyClass objects[12], size_t number)
```

这仍然会受到数组衰减的影响，因为编译器将参数对象更改为 MyClass*；在这种情况下，它不保留维度信息。数组衰减是我们需要将数字传递给`printMyClasses()`函数的原因：这样我们就知道数组中有多少项。C++提供了两种处理数组衰减的机制：

+   使用迭代器将范围传递到方法中。STL 容器（参见*第 2B 章*中的*C++预打包模板*部分，*不允许鸭子-模板和推断*）提供`begin()`和`end()`方法，以便我们可以获得允许算法遍历数组或其部分的迭代器。

#### 注意

对于 C++20，ISO 标准委员会正在考虑包含一种称为 Ranges 的概念，它将允许同时捕获起始和结束迭代器的对象。

+   使用模板（参见*第 2B 章，不允许鸭子-模板和推断*中的*非类型模板参数*部分）。

### 练习 3：声明和使用指针

在这个练习中，我们将实现接受指针和数组作为参数并比较它们的行为，同时考虑数组衰减的函数。让我们开始吧：

1.  在 Eclipse 中打开**Lesson2A**项目，然后在项目资源管理器中展开**Lesson2A**，然后**Exercise03**，双击**Exercise3.cpp**以在编辑器中打开此练习的文件。

1.  点击**Launch Configuration**下拉菜单，选择**New Launch Configuration…**。配置**Exercise3**以运行名称**Exercise3**。完成后，它将成为当前选择的 Launch Configuration。

1.  点击**Run**按钮。练习 3 将运行并产生以下输出：![图 2A.20：练习 3 输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_20.jpg)

###### 图 2A.20：练习 3 输出

1.  在编辑器中的某个地方插入一行空行，然后点击**Run**按钮。（通过更改文件，它将强制构建系统重新编译**Exercise3.cpp**。）

1.  如果我们现在看`print_array_size2()`是`int*`类型，并且由警告说明`sizeof`将返回'int*'的大小所证实：![图 2A.22：练习 3 部分输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_22.jpg)

###### 图 2A.22：练习 3 部分输出

`sizeof(ary)/sizeof(arg[0])`的计算应返回数组中的元素数。`elements in (ary) = 10`是从 main 函数生成的，ary 声明为`ary[10]`，所以是正确的。在---print_array_size2---横幅下的`elements in (ary) = 2`显示了数组衰减的问题，以及为什么编译器生成了警告。为什么值是 2？在测试 PC 上，指针占用 8 字节（64 位），而 int 只占用 4 字节，所以我们得到 8/4 = 2。

1.  在编辑器中，找到 main()中声明 ary 的行，并将其更改为以下内容：

```cpp
int ary[15]{};
```

1.  点击`int ary[15]`会导致错误或至少警告，因为参数原型不匹配。正如我们之前所述，编译器将参数视为`int* ary`，因此函数也可以声明如下：

```cpp
void print_array_size2(int* ary)
```

1.  在编辑器中，将`print_array_size2`的名称全部更改为`print_array_size`。点击`int* ary`和`int ary[10]`。这是确认，当作为函数参数使用时，`int ary[10]`生成的结果与声明`int*` ary 时相同。

1.  将文件恢复到其原始状态。

1.  在`main()`函数中，找到带有`Step 11`注释的行，并删除该行开头的注释。点击`title`以使其为`const char*`，p 的类型为`char*`。const 很重要。p 指针允许我们更改其指向的值。

1.  看一下以下行：

```cpp
p = title; 
```

将其更改为以下内容：

```cpp
title = p;
```

1.  点击**Run**按钮。这次，它构建并正确运行。将非 const 指针分配给 const 指针是可以的。

在这个练习中，我们学到了当将数组传递到函数中时，需要小心处理数组，因为关键信息（数组的大小）将在调用中丢失。

## 创建用户类型

C++的伟大之处在于您可以使用**struct**、**class**、**enum**或**union**创建自己的类型，编译器将在整个代码中将其视为基本类型。在本节中，我们将探讨创建自己的类型以及我们需要编写的方法来操纵它，以及编译器将为我们创建的一些方法。

### 枚举

最简单的用户定义类型是枚举。C++11 对枚举进行了改进，使它们更加类型安全，因此我们必须考虑两种不同的声明语法。在看如何声明它们之前，让我们弄清楚为什么需要它们。考虑以下代码：

```cpp
int check_file(const char* name)
{
  FILE* fptr{fopen(name,"r")};
  if ( fptr == nullptr)
    return -1;
  char buffer[120];
  auto numberRead = fread(buffer, 1, 30, fptr);
  fclose(fptr);
  if (numberRead != 30)
    return -2;
  if(is_valid(buffer))
    return -3;
  return 0;
}
```

这是许多 C 库函数的典型特征，其中返回状态代码，您需要主页知道它们的含义。在前述代码中，`-1`、`-2`、`-3`和`0`被称为**魔术数字**。您需要阅读代码以了解每个数字的含义。现在，考虑以下版本的代码：

```cpp
FileCheckStatus check_file(const char* name)
{
  FILE* fptr{fopen(name,"r")};
  if ( fptr == nullptr)
    return FileCheckStatus::NotFound;
  char buffer[30];
  auto numberRead = fread(buffer, 1, 30, fptr);
  fclose(fptr);
  if (numberRead != 30)
    return FileCheckStatus::IncorrectSize;
  if(is_valid(buffer))
    return FileCheckStatus::InvalidContents;
  return FileCheckStatus::Good;
}
```

这使用枚举类来传达结果并将含义附加到值的名称上。函数的用户现在可以使用枚举，因为代码更容易理解和使用。因此，魔术数字（与状态相关）已被替换为具有描述性标题的枚举值。让我们通过以下代码片段了解`FileCheckStatus`的声明：

```cpp
enum FileCheckStatus             // Old-style enum declaration
{
  Good,                         // = 0 - Value defaults to 0
  NotFound,                     // = 1 - Value set to one more than previous
  IncorrectSize,                // = 2 - Value set to one more than previous
  InvalidContents,              // = 3 - Value set to one more than previous
};
```

如果我们想使用魔术数字的值，那么我们会这样声明它们：

```cpp
enum FileCheckStatus             // Old-style enum declaration
{
  Good = 0, 
  NotFound = -1,
  IncorrectSize = -2,
  InvalidContents = -3,
};
```

或者，通过改变顺序，我们可以设置第一个值，编译器会完成其余部分：

```cpp
enum FileCheckStatus             // Old-style enum declaration
{
  InvalidContents = -3,          // Force to -3
  IncorrectSize,                 // set to -2(=-3+1)
  NotFound,                      // Set to -1(=-2+1)
  Good,                          // Set to  0(=-1+1)
};
```

前述函数也可以写成如下形式：

```cpp
FileCheckStatus check_file(const char* name)
{
  FILE* fptr{fopen(name,"r")};
  if ( fptr == nullptr)
    return NotFound;
  char buffer[30];
  auto numberRead = fread(buffer, 1, 30, fptr);
  fclose(fptr);
  if (numberRead != 30)
    return IncorrectSize;
  if(is_valid(buffer))
    return InvalidContents;
  return Good;
}
```

请注意，代码中缺少作用域指令`FileCheckStatus::`，但它仍将编译并工作。这引发了作用域的问题，我们将在*第 2B 章*的*可见性、生命周期和访问*部分中详细讨论。现在，知道每种类型和变量都有一个作用域，旧式枚举的问题在于它们的枚举器被添加到与枚举相同的作用域中。假设我们有两个枚举定义如下：

```cpp
enum Result 
{
    Pass,
    Fail,
    Unknown,
};
enum Option
{
    Keep,
    Discard,
    Pass,
    Play
};
```

现在我们有一个问题，`Pass`枚举器被定义两次并具有两个不同的值。旧式枚举还允许我们编写有效的编译器，但显然毫无意义的代码，例如以下代码：

```cpp
Option option{Keep};
Result result{Unknown};
if (option == result)
{
    // Do something
}
```

由于我们试图开发清晰明了的代码，易于理解，将结果与选项进行比较是没有意义的。问题在于编译器会隐式将值转换为整数，从而能够进行比较。

C++11 引入了一个被称为**枚举类**或**作用域枚举**的新概念。前述代码的作用域枚举定义如下：

```cpp
enum class Result 
{
    Pass,
    Fail,
    Unknown,
};
enum class Option
{
    Keep,
    Discard,
    Pass,
    Play
};
```

这意味着前述代码将不再编译：

```cpp
Option option{Keep};          // error: must use scope specifier Option::Keep
Result result{Unknown};       // error: must use scope specifier Result::Unknown
if (option == result)         // error: can no longer compare the different types
{
    // Do something
}
```

正如其名称所示，**作用域枚举**将枚举器放置在枚举名称的作用域内。此外，作用域枚举将不再被隐式转换为整数（因此 if 语句将无法编译通过）。您仍然可以将枚举器转换为整数，但需要进行类型转换：

```cpp
int value = static_cast<int>(Option::Play);
```

### 练习 4：枚举-新旧学校

在这个练习中，我们将实现一个程序，使用枚举来表示预定义的值，并确定当它们更改为作用域枚举时所需的后续更改。让我们开始吧：

1.  在 Eclipse 中打开**Lesson2A**项目，然后在**Project Explorer**中展开**Lesson2A**，然后展开**Exercise04**，双击**Exercise4.cpp**以在编辑器中打开此练习的文件。

1.  单击**启动配置**下拉菜单，然后选择**新建启动配置…**。配置**Exercise4**以使用名称**Exercise4**运行。

1.  完成后，它将成为当前选择的启动配置。

1.  单击**运行**按钮。练习 4 将运行并产生以下输出：![图 2A.25：练习 4 输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_25.jpg)

###### 图 2A.25：练习 4 输出

1.  检查编辑器中的代码。目前，我们可以比较苹果和橙子。在`printOrange()`的定义处，将参数更改为`Orange`：

```cpp
void printOrange(Orange orange)
```

1.  单击**运行**按钮。当出现工作区中的错误对话框时，单击**取消**：![图 2A.26：无法转换错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_26.jpg)

###### 图 2A.26：无法转换错误

通过更改参数类型，我们迫使编译器强制执行传递给函数的值的类型。

1.  通过在初始调用中传递`orange` `enum`变量并在第二次调用中传递`apple`变量，两次调用`printOrange()`函数：

```cpp
printOrange(orange);
printOrange(apple);
```

这表明编译器会将橙色和苹果隐式转换为`int`，以便调用该函数。还要注意关于比较`Apple`和`Orange`的警告。

1.  通过采用 int 参数并将`orange` `enum`的定义更改为以下内容来恢复`printOrange()`函数：

```cpp
enum class Orange;
```

1.  单击**运行**按钮。当出现工作区中的错误对话框时，单击**取消**：![图 2A.27：作用域枚举更改的多个错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_27.jpg)

###### 图 2A.27：作用域枚举更改的多个错误

1.  找到此构建的第一个错误：![图 2A.28：第一个作用域枚举错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_28.jpg)

###### 图 2A.28：第一个作用域枚举错误

1.  关于作用域枚举的第一件事是，当您引用枚举器时，它们必须具有作用域限定符。因此，在编辑器中，转到并更改此行如下：

```cpp
Orange orange{Orange::Hamlin};
```

1.  单击`Orange`类型。因为这涉及基于模板的类（我们稍后会讨论），错误消息变得非常冗长。花一分钟时间查看从此错误到下一个错误（红线）出现的所有消息。它向您展示了编译器试图做什么以能够编译该行。

1.  更改指定的行以读取如下内容：

```cpp
std::cout << "orange = " << static_cast<int>(orange) << "\n";
```

1.  单击`Orange::`作用域限定符。

1.  留给你的练习是使用`orange`作为作用域枚举重新编译文件。

在这个练习中，我们发现作用域枚举改进了 C++的强类型检查，如果我们希望将它们用作整数值，那么我们需要对它们进行转换，而非作用域枚举则会隐式转换。

#### 故障排除编译器错误

从前面的练习中可以看出，编译器可以从一个错误生成大量的错误和警告消息。这就是为什么建议找到第一个错误并首先修复它。在 IDE 中开发或使用着色错误的构建系统可以使这更容易。

### 结构和类

枚举是用户定义类型中的第一个，但它们并没有真正扩展语言，以便我们可以以适当的抽象级别表达问题的解决方案。然而，结构和类允许我们捕获和组合数据，然后关联方法以一致和有意义的方式来操作这些数据。

如果我们考虑两个矩阵的乘法，*A（m x n）*和*B（n x p）*，其结果是矩阵*C（m x p）*，那么 C 的第 i 行和第 j 列的方程如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_31.jpg)

###### 图 2A.31：第 i 行和第 j 列的方程

如果我们每次都必须这样写来乘两个矩阵，我们最终会得到许多嵌套的 for 循环。但是，如果我们可以将矩阵抽象成一个类，那么我们可以像表达两个整数或两个浮点数的乘法一样来表达它：

```cpp
Matrix a;
Matrix b;
// Code to initialize the matrices
auto c = a * b;
```

这就是面向对象设计的美妙之处 - 数据封装和概念的抽象被解释在这样一个层次上，以至于我们可以轻松理解程序试图实现的目标，而不会陷入细节。一旦我们确定矩阵乘法被正确实现，那么我们就可以自由地专注于以更高层次解决我们的问题。

接下来的讨论涉及类，但同样适用于结构体，大部分适用于联合体。在学习如何定义和使用类之后，我们将概述类、结构体和联合体之间的区别。

### 分数类

为了向您展示如何定义和使用类，我们将致力于开发`Fraction`类来实现有理数。一旦定义，我们可以像使用任何其他内置类型一样使用`Fraction`（加法、减法、乘法、除法），而不必担心细节 - 这就是抽象。现在我们只需在更高的抽象层次上思考和推理分数。

`Fraction`类将执行以下操作：

+   包含两个整数成员变量，`m_numerator`和`m_denominator`

+   提供方法来复制自身，分配给自身，相乘，相除，相加和相减

+   提供一种方法写入输出流

为了实现上述目标，我们有以下定义：

![图 2A.32：操作的定义](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_32.jpg)

###### 图 2A.32：操作的定义

此外，我们执行的操作将需要将分数归一化为最低项。为此，分子和分母都要除以它们的最大公约数（GCD）。

### 构造函数、初始化和析构函数

类定义在 C++代码中表达的是用于在内存中创建对象并通过它们的方法操作对象的模式。我们需要做的第一件事是告诉编译器我们希望声明一个新类型 - 一个类。要声明`Fraction`类，我们从以下开始：

```cpp
class Fraction
{
};
```

我们将这放在一个头文件**Fraction.h**中，因为我们希望在代码的其他地方重用这个类规范。

我们需要做的下一件事是引入要存储在类中的数据，在这种情况下是`m_numerator`和`m_denominator`。这两者都是 int 类型：

```cpp
class Fraction
{
  int m_numerator;
  int m_denominator;
};
```

我们现在已经声明了要存储的数据，并为它们赋予了任何熟悉数学的人都能理解的名称，以了解每个成员变量存储的内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_33.jpg)

###### 图 2A.33：分数的公式

由于这是一个类，默认情况下，声明的任何项目都被假定为`private`。这意味着没有外部实体可以访问这些变量。正是这种隐藏（使数据私有，以及某些方法）使得 C++中的封装成为可能。C++有三种类访问修饰符：

+   **public**：这意味着成员（变量或函数）可以从类外部的任何地方访问。

+   **private**：这意味着成员（变量或函数）无法从类外部访问。事实上，甚至无法查看。私有变量和函数只能从类内部或通过友元方法或类访问。私有成员（变量和函数）由公共函数使用以实现所需的功能。

+   **protected**：这是私有和公共之间的交叉。从类外部来看，变量或函数是私有的。但是，对于从声明受保护成员的类派生的任何类，它们被视为公共的。

在我们定义类的这一点上，这并不是很有用。让我们将声明更改为以下内容：

```cpp
class Fraction
{
public:
  int m_numerator;
  int m_denominator;
};
```

通过这样做，我们可以访问内部变量。`Fraction number;`变量声明将导致编译器执行两件事：

+   分配足够的内存来容纳数据项（取决于类型，这可能涉及填充，即包括或添加未使用的内存以对齐成员以实现最有效的访问）。`sizeof`运算符可以告诉我们为我们的类分配了多少内存。

+   通过调用**默认构造函数**来初始化数据项。

这些步骤与编译器为内置类型执行的步骤相同，即步骤 2 什么也不做，导致未初始化的变量。但是默认构造函数是什么？它做什么？

首先，默认构造函数是一个特殊成员函数。它是许多可能构造函数中的一个，其中三个被视为特殊成员函数。构造函数可以声明零个、一个或多个参数，就像任何其他函数一样，但它们不指定返回类型。构造函数的特殊目的是将所有成员变量初始化，将对象置于一个明确定义的状态。如果成员变量本身是一个类，那么可能不需要指定如何初始化变量。如果成员变量是内置类型，那么我们需要为它们提供初始值。

### 类特殊成员函数

当我们定义一个新类型（结构体或类）时，编译器会为我们创建多达六个（6）个特殊成员函数：

+   `Fraction::Fraction()`): 当没有提供参数时调用（例如在前面的部分中）。这可以通过构造函数没有参数列表或为所有参数定义默认值来实现，例如`Fraction(int numerator=0, denominator=1)`。编译器提供了一个`implicit` `inline`默认构造函数，执行成员变量的默认初始化 - 对于内置类型，这意味着什么也不做。

+   `Fraction::~Fraction()`): 这是一个特殊成员函数，当对象的生命周期结束时调用。它的目的是释放对象在其生命周期中分配和保留的任何资源。编译器提供了一个`public` `inline`成员函数，调用成员变量的析构函数。

+   `Fraction::Fraction(const Fraction&)`): 这是另一个构造函数，其中第一个参数是`Fraction&`的形式，没有其他参数，或者其余参数具有默认值。第一个参数的形式是`Fraction&`、`const Fraction&`、`volatile Fraction&`或`const volatile Fraction&`。我们将在后面处理`const`，但在本书中不处理`volatile`。编译器提供了一个`non-explicit` `public` `inline`成员函数，通常形式为`Fraction::Fraction(const Fraction&)`，按初始化顺序复制每个成员变量。

+   `Fraction& Fraction::operator=(Fraction&)`): 这是一个成员函数，名称为`operator=`，第一个参数可以是值，也可以是类的任何引用类型，在这种情况下是`Fraction`、`Fraction&`、`const Fraction&`、`volatile Fraction&`或`const volatile Fraction&`。编译器提供了一个`public` `inline`成员函数，通常形式为`Fraction::Fraction(const Fraction&)`，按初始化顺序复制每个成员变量。

+   `Fraction::Fraction(Fraction&&)`): 这是 C++11 中引入的一种新类型的构造函数，第一个参数是`Fraction&&`的形式，没有其他参数，或者其余参数具有默认值。第一个参数的形式是`Fraction&&`、`const Fraction&&`、`volatile Fraction&&`或`const volatile Fraction&&`。编译器提供了一个`non-explicit` `public` `inline`成员函数，通常形式为`Fraction::Fraction(Fraction&&)`，按初始化顺序移动每个成员变量。

+   `Fraction& Fraction::operator=(Fraction&&)`): 这是 C++11 中引入的一种新类型的赋值运算符，是一个名为`operator=`的成员函数，第一个参数是允许移动构造函数的任何形式之一。编译器提供了一个`public` `inline`成员函数，通常采用`Fraction::Fraction(Fraction&&)`的形式，按初始化顺序复制每个成员变量。

除了默认构造函数外，这些函数处理了该类拥有的资源的管理-即如何复制/移动它们以及如何处理它们。另一方面，默认构造函数更像是接受值的任何其他构造函数-它只初始化资源。

我们可以声明任何这些特殊函数，强制它们被默认（即，让编译器生成默认版本），或者强制它们不被创建。关于这些特殊函数在其他特殊函数存在时何时自动生成也有一些规则。前四个函数在概念上相对直接，但是两个“移动”特殊成员函数需要额外的解释。我们将在第三章“可以和应该之间的距离-对象、指针和继承”中详细讨论移动语义，但现在它基本上就是它所指示的意思-将某物从一个对象移动到另一个对象。

### 隐式构造函数与显式构造函数

前面的描述讨论了编译器生成隐式或非显式构造函数。如果存在可以用一个参数调用的构造函数，例如复制构造函数或移动构造函数，默认情况下，编译器可以在必要时调用它，以便将其从一种类型转换为另一种类型，从而允许对表达式、函数调用或赋值进行编码。这并不总是期望的行为，我们可能希望阻止隐式转换，并确保如果我们类的用户真的希望进行转换，那么他们必须在程序中写出来。为了实现这一点，我们可以在构造函数的声明前加上`explicit`关键字，如下所示：

```cpp
explicit Fraction(int numerator, int denominator = 1);
```

`explicit`关键字也可以应用于其他运算符，编译器可能会用它进行类型转换。

### 类特殊成员函数-编译器生成规则

首先，如果我们声明了任何其他形式的构造函数-默认、复制、移动或用户定义的构造函数，就不会生成`Default Constructor`。其他特殊成员函数都不会影响它的生成。

其次，如果声明了析构函数，则不会生成`Destructor`。其他特殊成员函数都不会影响它的生成。

其他四个特殊函数的生成取决于析构函数或其他特殊函数的声明的存在，如下表所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_34.jpg)

###### 图 2A.34：特殊成员函数生成规则

### 默认和删除特殊成员函数

在 C++11 之前，如果我们想要阻止使用复制构造函数或复制赋值成员函数，那么我们必须将函数声明为私有，并且不提供函数的定义：

```cpp
class Fraction
{
public:
  Fraction();
private:
  Fraction(const Fraction&);
  Fraction& operator=(const Fraction&);
};
```

通过这种方式，我们确保如果有人试图从类外部访问复制构造函数或复制赋值，那么编译器将生成一个错误，说明该函数不可访问。这仍然声明了这些函数，并且它们可以从类内部访问。这是一种有效的方法，但并不完美，以防止使用这些特殊成员函数。

但是自 C++11 引入了两种新的声明形式，允许我们覆盖编译器的默认行为，如前述规则所定义。

首先，我们可以通过使用`= delete`后缀来声明方法，强制编译器不生成该方法，如下所示：

```cpp
Fraction(const Fraction&) = delete;
```

#### 注意

如果参数没有被使用，我们可以省略参数的名称。对于任何函数或成员函数都是如此。实际上，根据编译器设置的警告级别，它甚至可能会生成一个警告，表明参数没有被使用。

或者，我们可以通过使用`= default`后缀来强制编译器生成特殊成员函数的默认实现，就像这样：

```cpp
Fraction(const Fraction&) = default;
```

如果这只是函数的声明，那么我们也可以省略参数的名称。尽管如此，良好的实践规定我们应该命名参数以指示其用途。这样，我们类的用户就不需要查看调用函数的实现。

#### 注意

使用默认后缀声明特殊成员函数被视为用户定义的成员函数，用于上述规则的目的。

### 三五法则和零法则

正如我们之前讨论过的，除了默认构造函数之外，特殊成员函数处理了管理该类拥有的资源的语义 - 即如何复制/移动它们以及如何处理它们。这导致了 C++社区内关于处理特殊函数的两个“规则”。

在 C++11 之前，有“三法则”，它涉及复制构造函数、复制赋值运算符和析构函数。基本上它表明我们需要实现其中一个方法，因为封装资源的管理是非平凡的。

随着 C++11 中移动构造函数和移动赋值运算符的引入，这个规则扩展为“五法则”。规则的本质没有发生变化。简单地说，特殊成员函数的数量增加到了五个。记住编译器生成规则，确保所有五个特殊方法都被实现（或通过= default 强制），这是一个额外的原因，如果编译器无法访问移动语义函数，它将尝试使用复制语义函数，这可能不是所期望的。

#### 注意

有关更多详细信息，请参阅 C.ctor：C++核心指南中的构造函数、赋值和析构函数部分，网址为：[`isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines`](http://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)。

### 构造函数 - 初始化对象

构造函数的主要任务是将对象置于稳定状态，以便通过其成员函数对对象执行的任何操作都会产生一致的定义行为。虽然前面的陈述对于复制和移动构造函数是正确的，但它们通过不同的语义（从另一个对象复制或移动）来实现这一点。

我们有四种不同的机制可以控制对象的初始状态。C++对于在这种情况下使用哪种初始化有很多规则。我们不会详细讨论 C++标准的默认初始化、零初始化、值初始化、常量初始化等等。只需知道最好的方法是明确地初始化您的变量。

第一种，也是最不受欢迎的初始化机制是在构造函数的主体中为成员变量赋值，就像这样：

```cpp
Fraction::Fraction()
{
  this->m_numerator = 0;
  this->m_denominator = 1;
}
Fraction::Fraction(int numerator, int denominator)
{
  m_numerator = numerator;
  m_denominator = denominator;
}
```

清楚地知道了用于初始化变量的值。严格来说，这不是类的初始化 - 根据标准，当构造函数的主体被调用时，初始化才算完成。这在这个类中很容易维护。对于有多个构造函数和许多成员变量的较大类，这可能是一个维护问题。如果更改一个构造函数，您将需要更改它们所有。它还有一个问题，如果成员变量是引用类型（我们稍后会讨论），那么它就不能在构造函数的主体中完成。

默认构造函数使用`this`指针。每个成员函数，包括构造函数和析构函数，都带有一个隐式参数（即使它从未声明过）- `this`指针。`this`指向对象的当前实例。`->`操作符是另一个解引用操作符，在这种情况下是简写，即`*(this).m_numerator`。使用`this->`是可选的，可以省略。其他语言，如 Python，要求声明和使用隐式指针/引用（Python 中的约定是称为*self*）。

**第二**种机制是使用成员初始化列表，其在使用中有一个警告。对于我们的 Fraction 类，我们有以下内容：

```cpp
Fraction::Fraction() : m_numerator(0), m_denominator(1)
{
}
Fraction::Fraction(int numerator, int denominator) :
  m_numerator(numerator), m_denominator(denominator)
{
}
```

冒号:后面和左花括号{前面的代码部分（`m_numerator(0), m_denominator(1)`和`m_numerator(numerator), m_denominator(denominator)`）是成员初始化列表。我们可以在成员初始化列表中初始化引用类型。

#### 成员初始化列表顺序

无论您在成员初始化列表中放置成员的顺序如何，编译器都将按照它们在类中声明的顺序初始化成员。

**第三**种和**推荐**的初始化是 C++11 中引入的默认成员初始化。我们在变量声明时使用赋值或大括号初始化器定义默认初始值：

```cpp
class Fraction
{
public:
  int m_numerator = 0;     // equals initializer
  int m_denominator{1};    // brace initializer
};
```

如果构造函数没有定义成员变量的初始值，则将使用此默认值来初始化变量。这样做的好处是确保所有构造函数产生相同的初始化，除非它们在构造函数的定义中被明确修改。

C++11 还引入了第四种初始化样式，称为构造函数委托。它是成员初始化列表的修改，其中不是列出成员变量及其初始值，而是调用另一个构造函数。以下示例是人为的，您不会以这种方式编写类，但它显示了构造函数委托的语法：

```cpp
Fraction::Fraction(int numerator) : m_numerator(numerator), m_denominator(1)
{
}
Fraction::Fraction(int numerator, int denominator) : Fraction(numerator)
{
  auto factor = std::gcd(numerator, denominator);
  m_numerator /= factor;
  m_denominator = denominator / factor;
}
```

您从具有两个参数的构造函数中调用单参数构造函数。

### 练习 5：声明和初始化分数

在这个练习中，我们将使用不同的技术实现类成员初始化，包括构造函数委托。让我们开始吧：

1.  在 Eclipse 中打开**Lesson2A**项目，然后在**Project Explorer**中展开**Lesson2A**，然后展开**Exercise05**，双击**Exercise5.cpp**以在编辑器中打开此练习的文件。

1.  单击**启动配置**下拉菜单，然后选择**新启动配置…**。将**Exercise5**配置为以名称 Exercise5 运行。

1.  完成后，它将成为当前选择的启动配置。

1.  单击**运行**按钮。**练习 5**将运行并产生类似以下输出：![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_35.jpg)

###### 图 2A.35：练习 5 典型输出

报告的分数值来自以任何方式初始化成员变量。如果再次运行，您很可能会得到不同的分数。

1.  点击**运行**按钮几次。您会看到分数发生变化。

1.  在编辑器中，将构造函数更改为如下所示：

```cpp
Fraction() : m_numerator{0}, m_denominator{1}
{
}
```

1.  单击**运行**按钮并观察输出：![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_36.jpg)

###### 图 2A.36：修改后的练习 5 输出

这次，分数值由我们在成员初始化列表中指定的值定义。 

1.  在编辑器中，添加以下两个`构造函数`：

```cpp
Fraction(int numerator) : m_numerator(numerator), m_denominator(1)
{
}
Fraction(int numerator, int denominator) : Fraction(numerator)
{
  auto factor = std::gcd(numerator, denominator);
  m_numerator /= factor;
  m_denominator = denominator / factor;
}
```

1.  在主函数中，更改`fraction`的声明以包括初始化：

```cpp
Fraction fraction{3,2};
```

1.  点击**运行**按钮并观察输出：![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_37.jpg)

###### 图 2A.37：构造函数委托示例

在这个练习中，我们使用成员初始化列表和构造函数委托实现了成员变量的初始化。*我们将在练习 7 中返回到分数，为分数类添加运算符。*

### 值与引用和常量

到目前为止，我们只处理了值类型，也就是变量保存了对象的值。指针保存了我们感兴趣的值（即对象的地址）（或 nullptr）。但这可能导致效率低下和资源管理问题。我们将在这里讨论如何解决效率低下的问题，但在*第三章*，*可以和应该之间的距离-对象、指针和继承*中解决资源管理问题。

考虑以下问题..我们有一个 10×10 的双精度矩阵，我们希望为其编写一个反转函数。该类声明如下：

```cpp
class Matrix10x10
{
private:
  double m_data[10][10];
};
```

如果我们要取`sizeof(Matrix10x10)`，我们会得到`sizeof(double)` x 10 x 10 = 800 字节。现在，如果我们要为此实现一个矩阵反转函数，其签名可能如下所示：

```cpp
Matrix10x10 invert(Matrix10x10 lhs);
Matrix10x10 mat;
// set up mat
Matrix10x10 inv = invert(mat);
```

首先，这意味着编译器需要将`mat`持有的值传递给`invert()`函数，并将 800 字节复制到堆栈上。然后函数执行其需要执行的操作来反转矩阵（L-U 分解、计算行列式-无论实现者选择的方法是什么），然后将 800 字节的结果复制回`inv`变量。在堆栈上传递大量值从来都不是一个好主意，原因有两个：

+   堆栈是主机操作系统给我们程序的有限资源。

+   在系统中复制大量值是低效的。

这种方法被称为按值传递。也就是说，我们希望处理的项目的值被复制到函数中。

在 C（和 C++）中，通过使用指针来解决这个限制。上面的代码可能变成下面这样：

```cpp
void invert(Matrix10x10* src, Matrix10x10* inv);
Matrix10x10 mat;
Matrix10x10 inv;
// set up mat
invert(&mat, &inv);
```

在这里，我们只是传递了 src 和 target 的地址作为两个指针的逆结果（这是少量字节）。不幸的是，这导致函数内部的代码在每次使用`src`或`inv`时都必须使用解引用操作符（`*`），使得代码更难阅读。此外，指针的使用导致了许多问题。

C++引入了一个更好的方法-变量别名或引用。引用类型是用和号（`&`）操作符声明的。因此，我们可以将 invert 方法声明如下：

```cpp
void invert(Matrix10x10& src, Matrix10x10& inv);
Matrix10x10 mat;
Matrix10x10 inv;
// set up mat
invert(mat, inv);
```

请注意，调用该方法不需要特殊的操作符来传递引用。从编译器的角度来看，引用仍然是一个带有一个限制的指针-它不能保存 nullptr。从程序员的角度来看，引用允许我们在不必担心在正确的位置使用解引用操作符的情况下推理我们的代码。这被称为**按引用传递**。

我们看到引用被传递给了复制构造函数和复制赋值方法。当用于它们的移动等价物时，引用的类型被称为**右值引用运算符**，将在*第三章*，*可以和应该之间的距离-对象、指针和继承*中解释。

`按值传递`的一个优点是我们不能无意中修改传递给方法的变量的值。现在，如果我们`按引用传递`，我们就不能再保证我们调用的方法不会修改原始变量。为了解决这个问题，我们可以将 invert 方法的签名更改为如下所示：

```cpp
void invert(const Matrix10x10& src, Matrix10x10& inv);
```

const 关键字告诉编译器，在处理`invert()`函数的定义时，将值引用到`src`的任何部分都是非法的。如果该方法尝试修改 src，编译器将生成一个错误。

在指定类型-变量部分，我们发现`auto title`的声明导致`title`是`const char *`类型。现在，我们可以解释`const`部分了。

`title`变量是**指向常量字符的指针**。换句话说，我们不能改变指向的内存中存储的数据的值。因此，我们不能执行以下操作：

```cpp
*title = 's';
```

这是因为编译器将生成与更改常量值相关的错误。然而，我们可以改变指针中存储的值。我们可以执行以下操作：

```cpp
title = "Maid Marian";
```

我们现在已经介绍了引用作为函数参数类型的用法，但它们也可以用作成员变量而不是指针。引用和指针之间有区别：

引用必须引用实际对象（没有 nullptr 的等价物）。一旦初始化，引用就不能被改变（这意味着引用必须要么是默认成员初始化的，要么出现在成员初始化列表中）。对象必须存在，只要对它的引用存在（如果对象可以在引用被销毁之前被销毁，那么如果尝试访问对象就有潜在的未定义行为）。

### 练习 6：声明和使用引用类型

在这个练习中，我们将声明和使用引用类型，以使代码更高效、更易读。让我们开始吧：

1.  在 Eclipse 中打开**Lesson2A**项目，然后在**Project Explorer**中展开**Lesson2A**，然后展开**Exercise06**，双击**Exercise6.cpp**以在编辑器中打开此练习的文件。

1.  点击**Launch Configuration**下拉菜单，选择**New Launch Configuration…**。配置**Exercise6**以使用名称 Exercise6 运行。

1.  完成后，它将成为当前选择的启动配置。

1.  点击`rvalue`变量允许我们操纵（读取和写入）存储在`value`变量中的数据。我们有一个对`value`变量的引用`rvalue`。我们还可以看到`swap()`函数交换了`a`和`b`变量中存储的值。

1.  在编辑器中，更改 swap 函数的函数定义：

```cpp
void swap(const int& lhs, const int& rhs)
```

1.  点击**Run**按钮。当出现工作区中的错误对话框时，点击**Cancel**。编译器报告的第一个错误如下所示：

![图 2A.39：赋值时的只读错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_39.jpg)

###### 图 2A.39：赋值时的只读错误

通过将参数从`int& lhs`更改为`const int& lhs`，我们告诉编译器在此函数内部参数不应该被改变。因为我们在函数中对 lhs 进行了赋值，所以编译器生成了关于 lhs 为只读的错误并终止了程序。

### 实现标准运算符

要像内置类一样使用分数，我们需要使它们能够使用标准数学运算符（`+，-，*，/`）及其赋值对应物（`+=，-=，*=，/=`）。如果您不熟悉赋值运算符，请考虑以下两个表达式 - 它们产生相同的输出：

```cpp
a = a + b;
a += b;
```

为 Fraction 声明这两个运算符的语法如下：

```cpp
// member function declarations
Fraction& operator+=(const Fraction& rhs);
Fraction operator+(const Fraction& rhs) const;
// normal function declaration of operator+
Fraction operator+(const Fraction& lhs, const Fraction& rhs);
```

因为`operator+=`方法修改了左侧变量的内容（将 a 添加到 b 然后再次存储在 a 中），建议将其实现为成员变量。在这种情况下，由于我们没有创建新值，我们可以直接返回对现有 lhs 的引用。

另一方面，`operator+`方法不应修改 lhs 或 rhs 并返回一个新对象。实现者可以自由地将其实现为成员函数或自由函数。在前面的代码中都展示了这两种方法，但只应存在一种。关于成员函数实现的有趣之处在于声明末尾的 const 关键字。这告诉编译器，当调用这个成员函数时，它不会修改对象的内部状态。虽然这两种方法都是有效的，但如果可能的话，`operator+`应该作为一个普通函数实现，而不是类的一部分。

相同的方法也可以用于其他运算符`-（减法）`，`*（乘法）`和`/（除法）`。前面的方法实现了标准数学运算符的语义，并使我们的类型像内置类型一样工作。

### 实现输出流操作符（<<）

C++将输入/输出（I/O）抽象为标准库中的流类层次结构（我们将在*第 2B 章*，*不允许鸭子 - 模板和推断*中讨论）。在*练习 5*，*声明和初始化分数*中，我们看到我们可以将分数插入到输出流中，如下所示：

```cpp
std::cout << "fraction = " << fraction.getNumerator() << "/" 
                           << fraction.getDenominator() << "\n";
```

到目前为止，对于我们的分数类，我们已经通过使用`getNumerator()`和`getDenominator()`方法从外部访问数据值来写出了分子和分母的值，但有更好的方法。作为使我们的类在 C++中成为一等公民的一部分，在合适的情况下，我们应该重载 I/O 运算符。在本章中，我们只会看输出运算符<<，也称为插入运算符。这样，我们可以用更清晰的版本替换以前的代码：

```cpp
std::cout << "fraction = " << fraction << "\n";
```

我们可以将运算符重载为友元函数或普通函数（如果类提供我们需要插入的数据的 getter 函数）。对于我们的目的，我们将其定义为普通函数：

```cpp
inline std::ostream& operator<< (std::ostream &out, const Fraction &rhs)
{
    out << rhs.getNumerator() << " / " << rhs.getDenominator();
    return out;
}
```

### 我们的代码结构

在我们深入练习之前，我们需要讨论一下我们的类的各个部分放在哪里 - 声明和定义。声明是我们的类的蓝图，指示它需要什么数据存储和将实现的方法。定义是每个方法的实际实现细节。

在 Java 和 C#等语言中，声明和定义是一样的，它们必须存在于一个文件（Java）或跨多个文件（C#部分类）中。在 C++中，取决于类和您希望向其他类公开多少，声明必须出现在头文件中（可以在其他文件中`#include`使用），定义可以出现在三个地方之一 - 内联在定义中，在相同文件中的`inline`定义，或在单独的实现文件中。

头文件通常以.hpp 扩展名命名，而实现文件通常是`*.cpp`或`*.cxx`之一。实现文件也称为**翻译单元**。通过将函数定义为内联，我们允许编译器以函数可能甚至不存在于最终程序中的方式优化代码 - 它已经将我们放入函数中的步骤替换为我们从中调用函数的位置。

### 练习 7：为分数类添加运算符

在这个练习中，我们的目标是使用单元测试在我们的分数类中实现运算符功能。这使我们的分数类成为一个真正的类型。让我们开始吧：

1.  在 Eclipse 中打开**Lesson2A**项目，然后在**项目资源管理器**中展开**Lesson2A**，然后**Exercise07**，双击**Exercise7.cpp**以在编辑器中打开此练习的文件。

1.  单击**启动配置**下拉菜单，然后选择**新启动配置…**。配置 Exercise7 以使用名称 Exercise7 运行。

1.  完成后，它将成为当前选择的启动配置。

1.  我们还需要配置一个单元测试。在 Eclipse 中，单击名为**运行** | **运行配置…**的菜单项，在左侧右键单击**C/C++单元**，然后选择**新配置**。

1.  将名称从`Lesson2A Debug`更改为`Exercise7 Tests`。

1.  在**C/C++应用程序**下，选择**搜索项目**选项，并在新对话框中选择**tests**。

1.  接下来，转到**C/C++测试**选项卡，并在下拉菜单中选择**Google 测试运行器**。点击对话框底部的**应用**，然后点击我们第一次运行的测试选项：![图 2A.40：失败的测试 - 乘法](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_40.jpg)

###### 图 2A.40：失败的测试 - 乘法

1.  打开`operator*=`函数。更新它的代码如下：

```cpp
Fraction& Fraction::operator*=(const Fraction& rhs)
{
  Fraction tmp(m_numerator*rhs.m_numerator, m_denominator*rhs.m_denominator);
  *this = tmp;
  return *this;
}
```

1.  点击**运行**按钮重新运行测试。这次，所有的测试都通过了：![图 2A.41：通过测试](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_41.jpg)

###### 图 2A.41：通过测试

1.  在 IDE 中打开`operator*=()`，同时测试其他的`operator*()`。修复`operator*=()`如何修复`operator*()`？如果在编辑器中打开 Fraction.hpp，你会发现`operator*()`函数是通过调用`operator*=()`来实现的，也就是说，它被标记为内联函数，是一个普通函数而不是成员函数。一般来说，当重载这些运算符时，修改调用它的对象的函数是成员函数，而生成新值的函数是调用成员函数的普通函数。

1.  在编辑器中打开**Fraction.hpp**，并将文件顶部的行更改为以下内容：

```cpp
#define EXERCISE7_STEP  11
```

1.  点击**AddFractions**和**AddFractions2**：![图 2A.42：额外的失败测试](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_42.jpg)

###### 图 2A.42：额外的失败测试

1.  在**Function.cpp**文件中找到`operator+=`函数。

1.  对函数进行必要的更改，然后点击实现`operator*=()`。

1.  在编辑器中打开**Fraction.hpp**，并将文件顶部的行更改为以下内容：

```cpp
#define EXERCISE7_STEP  15
```

1.  点击**SubtractFractions**和**SubtractFractions2**。

1.  在 Function.cpp 文件中找到`operator-=`函数。

1.  对函数进行必要的更改，然后点击**运行**按钮，直到测试通过。

1.  在编辑器中打开**Fraction.hpp**，并将文件顶部的行更改为以下内容：

```cpp
#define EXERCISE7_STEP  19
```

1.  点击**运行**按钮重新运行测试 - 这次，我们添加了两个失败的测试 - **DivideFractions**和**DivideFractions2**。

1.  在**Function.cpp**文件中找到`operator/=`函数。

1.  对函数进行必要的更改，然后点击**运行**按钮，直到测试通过。

1.  在编辑器中打开**Fraction.hpp**，并将文件顶部的行更改为以下内容：

```cpp
#define EXERCISE7_STEP  23
```

1.  点击**插入运算符**。

1.  在 Function.hpp 文件中找到`operator<<`函数。

1.  对函数进行必要的更改，然后点击**运行**按钮，直到测试通过。

1.  从**启动配置**中选择**Exercise7**，然后点击**运行**按钮。这将产生以下输出：

![图 2A.43：功能性分数类](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_43.jpg)

###### 图 2A.43：功能性分数类

这完成了我们对`Fraction`类的实现。当我们考虑*第三章*中的异常时，我们将再次返回它，*可以和应该之间的距离 - 对象、指针和继承*，这样我们就可以处理分数中的非法值（分母为 0）。

### 函数重载

C++支持一种称为函数重载的特性，即两个或多个函数具有相同的名称，但它们的参数列表不同。参数的数量可以相同，但至少一个参数类型必须不同。或者，它们可以具有不同数量的参数。因此，多个函数的函数原型是不同的。但是，两个函数不能具有相同的函数名称、相同的参数类型和不同的返回类型。以下是一个重载的示例：

```cpp
std::ostream& print(std::ostream& os, int value) {
   os << value << " is an int\n";
   return os;
}
std::ostream& print(std::ostream& os, float value) {
   os << value << " is a single precision float\n";
   return os;
}
std::ostream& print(std::ostream& os, double value) {
   os << value << " is a double precision float \n";
   return os;
}
// The next function causes the compiler to generate an error
// as it only differs by return type.
void print(std::ostream& os, double value) {
   os << value << " is a double precision float!\n";
}
```

到目前为止，`Fraction`上的多个构造函数和重载的算术运算符都是编译器在遇到这些函数时必须引用的重载函数的示例。考虑以下代码：

```cpp
int main(int argc, char** argv) {
   print(42);
}
```

当编译器遇到`print(42)`这一行时，它需要确定调用先前定义的函数中的哪一个，因此执行以下过程（大大简化）：

![图 2A.44：函数重载解析（简化）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_44.jpg)

###### 图 2A.44：函数重载解析（简化）

C++标准定义了编译器根据如何操作（即转换）参数来确定最佳候选函数的规则。如果不需要转换，则该函数是最佳匹配。

### 类，结构体和联合

当您定义一个类并且不指定访问修饰符（public，protected，private）时，默认情况下所有成员都将是 private 的：

```cpp
class Fraction
{
  Fraction() {};            // All of these are private
  int m_numerator;
  int m_denominator;
};
```

当您定义一个结构体并且不指定访问修饰符（public，protected，private）时，默认情况下所有成员都将是 public 的：

```cpp
struct Fraction
{
  Fraction() {};            // All of these are public
  int m_numerator;
  int m_denominator;
};
```

还有另一个区别，我们将在解释继承和多态性之后进行讨论。联合是一种与结构体和类不同但又相同的数据构造类型。联合是一种特殊类型的结构声明，其中所有成员占用相同的内存，并且在给定时间只有一个成员是有效的。`union`声明的一个示例如下：

```cpp
union variant
{
  int m_ivalue;
  float m_fvalue;
  double m_dvalue;
};
```

当您定义一个联合并且不指定访问修饰符（public，protected，private）时，默认情况下所有成员都将是 public 的。

联合的主要问题是没有内在的方法来知道在任何给定时间哪个值是有效的。这通过定义所谓的*标记联合*来解决 - 即一个包含联合和一个枚举的结构，用于标识它是有效值。联合还有其他限制（例如，只有一个成员可以有默认成员初始化程序）。我们不会在本书中深入探讨联合。

### 活动 1：图形处理

在现代计算环境中，矩阵被广泛用于解决各种问题 - 解决同时方程，分析电力网格或电路，对图形渲染对象进行操作，并提供机器学习的实现。在图形世界中，无论是二维（2D）还是三维（3D），您希望对对象执行的所有操作都可以通过矩阵乘法来完成。您的团队被要求开发点，变换矩阵的表示以及您可能希望对它们执行的操作。按照以下步骤来实现这一点：

1.  从**Lesson2A/Activity01**文件夹加载准备好的项目。

1.  创建一个名为**Point3d**的类，可以默认构造为原点，或使用三个或四个值的初始化列表（数据直接存储在类中）来构造。

1.  创建一个名为**Matrix3d**的类，可以默认构造为单位矩阵，或使用嵌套初始化列表来提供所有值（数据直接存储在类中）来构造。

1.  在`operator()`上，以便它接受（`index`）参数以返回`x(0)`，`y(1)`，`z(2)`和`w(3)`处的值。

1.  在`operator()`上接受（`row, col`）参数，以便返回该值。

1.  添加单元测试以验证所有上述功能。

1.  在**Matrix3d**类中添加`operator*=(const Matrix3d&)`和`operator==(const Matrix3d&)`，以及它们的单元测试。

1.  添加用于将两个**Matrix3d**对象相乘以及将**Matrix3d**对象乘以**Point3d**对象的自由函数，并进行单元测试。

1.  添加用于创建平移，缩放和旋转矩阵（围绕 x，y，z 轴）及其单元测试的独立方法。

在实现上述步骤之后，预期输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_45.jpg)

###### 图 2A.45：成功运行活动程序

在本次活动中，我们不会担心索引超出范围的可能性。我们将在*第三章*“能与应该之间的距离-对象、指针和继承”中讨论这个问题。单位矩阵是一个方阵（在我们的例子中是 4x4），对角线上的所有值都设置为 1，其他值都为 0。

在处理 3D 图形时，我们使用增广矩阵来表示点（顶点）和变换，以便所有的变换（平移、缩放、旋转）都可以通过乘法来实现。

一个`n × m`矩阵是一个包含 n 行 m 个数字的数组。例如，一个`2 x 3`矩阵可能如下所示：

![图 2A.46：2x3 矩阵](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_46.jpg)

###### 图 2A.46：2x3 矩阵

三维空间中的顶点可以表示为一个三元组（x，y，z）。然而，我们用另一个坐标`w（对于顶点为 1，对于方向为 0）`来增强它，使其成为一个四元组（x，y，z，1）。我们不使用元组，而是将其放在一个`4 x 1`矩阵中，如下所示：

![图 2A.47：4x1 矩阵](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_47.jpg)

###### 图 2A.47：4x1 矩阵

如果我们将`4 x 1`矩阵（点）乘以`4 x 4`矩阵（变换），我们可以操纵这个点。如果`Ti`表示一个变换，那么我们可以将变换相乘，以实现对点的某种操纵。

![图 2A.48：乘法变换](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_48.jpg)

###### 图 2A.48：乘法变换

要将一个转换矩阵相乘，`A x P = B`，我们需要做以下操作：

![图 2A.49：乘法变换矩阵](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_49.jpg)

###### 图 2A.49：乘法变换矩阵

我们也可以这样表达：

![图 2A.50：乘法变换表达式](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_50.jpg)

###### 图 2A.50：乘法变换表达式

同样，两个`4 x 4`矩阵也可以相乘，`AxB=C`：

![图 2A.51：4x4 矩阵乘法表达式：](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_51.jpg)

###### 图 2A.51：4x4 矩阵乘法表达式：

变换的矩阵如下：

![图 2A.52：变换矩阵列表](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02A_52.jpg)

###### 图 2A.52：变换矩阵列表

#### 注意

本次活动的解决方案可以在第 635 页找到。

## 总结

在本章中，我们学习了 C++中的类型。首先，我们介绍了内置类型，然后学习了如何创建行为类似于内置类型的自定义类型。我们学习了如何声明和初始化变量，了解了编译器从源代码生成的内容，变量的存储位置，链接器如何将其组合，以及在计算机内存中的样子。我们学习了一些关于 C++的部落智慧，比如零规则和五规则。这些构成了 C++的基本组成部分。在下一章中，我们将学习如何使用 C++模板创建函数和类，并探索模板类型推导的更多内容。
