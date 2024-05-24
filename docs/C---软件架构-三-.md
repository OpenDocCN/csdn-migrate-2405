# C++ 软件架构（三）

> 原文：[`zh.annas-archive.org/md5/FF4E2693BC25818CA0990A2CB63D13B8`](https://zh.annas-archive.org/md5/FF4E2693BC25818CA0990A2CB63D13B8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：构建和打包

作为架构师，您需要了解构建过程的所有要素。本章将解释构建过程的所有要素。从编译器标志到自动化脚本等，我们将指导您到每个可能的模块、服务和构件都被版本化并存储在一个中央位置，准备部署。我们将主要关注 CMake。

在本章中，您将了解以下内容：

+   您应该考虑使用哪些编译器标志

+   如何基于现代 CMake 创建构建系统

+   如何构建可重用的组件

+   如何在 CMake 中清洁地使用外部代码

+   如何使用 CPack 创建 DEB 和 RPM 软件包，以及 NSIS 安装程序

+   如何使用 Conan 软件包管理器来安装您的依赖项并创建您自己的软件包

阅读完本章后，您将了解如何编写最先进的代码来构建和打包您的项目。

# 技术要求

要复制本章中的示例，您应安装最新版本的**GCC**和**Clang**，**CMake 3.15**或更高版本，**Conan**和**Boost 1.69**。

本章的源代码片段可以在[`github.com/PacktPublishing/Software-Architecture-with-Cpp/tree/master/Chapter07`](https://github.com/PacktPublishing/Software-Architecture-with-Cpp/tree/master/Chapter07)找到。

# 充分利用编译器

编译器是每个程序员工作室中最重要的工具之一。这就是为什么充分了解它们可以在许多不同的场合帮助您的原因。在本节中，我们将描述一些有效使用它们的技巧。这只是冰山一角，因为整本书都可以写关于这些工具及其广泛的可用标志、优化、功能和其他具体内容。GCC 甚至有一个关于编译器书籍的维基页面！您可以在本章末尾的*进一步阅读*部分找到它。

## 使用多个编译器

在构建过程中应考虑的一件事是使用多个编译器而不仅仅是一个，原因是它带来的几个好处。其中之一是它们可以检测代码中的不同问题。例如，MSVC 默认启用了符号检查。使用多个编译器可以帮助您解决将来可能遇到的潜在可移植性问题，特别是当决定在不同操作系统上编译代码时，例如从 Linux 迁移到 Windows 或反之。为了使这样的努力不花费任何成本，您应该努力编写可移植的、符合 ISO C++标准的代码。**Clang**的一个好处是它比 GCC 更注重符合 C++标准。如果您使用**MSVC**，请尝试添加`/permissive-`选项（自 Visual Studio 17 起可用；对于使用版本 15.5+创建的项目，默认启用）。对于**GCC**，在为代码选择 C++标准时，尽量不要使用 GNU 变体（例如，更喜欢`-std=c++17`而不是`-std=gnu++17`）。如果性能是您的目标，能够使用多种编译器构建软件还将使您能够选择为特定用例提供最快二进制文件的编译器。

无论您选择哪个编译器进行发布构建，都应考虑在开发中使用 Clang。它可以在 macOS、Linux 和 Windows 上运行，支持与 GCC 相同的一组标志，并旨在提供最快的构建时间和简洁的编译错误。

如果您使用 CMake，有两种常见的方法可以添加另一个编译器。一种是在调用 CMake 时传递适当的编译器，如下所示：

```cpp
mkdir build-release-gcc
cd build-release-gcc
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=/usr/bin/gcc -DCMAKE_CXX_COMPILER=/usr/bin/g++ 
```

也可以在调用 CMake 之前设置 CC 和 CXX，但这些变量并非在所有平台上都受到尊重（例如 macOS）。

另一种方法是使用工具链文件。如果你只需要使用不同的编译器，这可能有点过度，但当你想要交叉编译时，这是一个常用的解决方案。要使用工具链文件，你应该将其作为 CMake 参数传递：`-DCMAKE_TOOLCHAIN_FILE=toolchain.cmake`。

## 减少构建时间

每年，程序员们花费无数时间等待他们的构建完成。减少构建时间是提高整个团队生产力的简单方法，所以让我们讨论一下几种方法来做到这一点。

### 使用一个快速编译器

有时使构建更快的最简单方法之一是升级你的编译器。例如，通过将 Clang 升级到 7.0.0，你可以减少高达 30%的构建时间，使用**预编译头**（**PCH**）文件。自 Clang 9 以来，它已经获得了`-ftime-trace`选项，它可以为你提供有关它处理的所有文件的编译时间的信息。其他编译器也有类似的开关：比如查看 GCC 的`-ftime-report`或 MSVC 的`/Bt`和`/d2cgsummary`。通常情况下，通过切换编译器可以获得更快的编译速度，这在你的开发机器上尤其有用；例如，Clang 通常比 GCC 更快地编译代码。

一旦你有了一个快速的编译器，让我们看看它需要编译什么。

### 重新思考模板

编译过程的不同部分需要不同的时间来完成。这对于编译时构造尤为重要。Odin Holmes 的一个实习生 Chiel Douwes 基于对各种模板操作的编译时成本进行基准测试，创造了所谓的 Chiel 规则。这个规则以及其他基于类型的模板元编程技巧可以在 Odin Holmes 的*基于类型的模板元编程并没有死*讲座中看到。从最快到最慢，它们如下：

+   查找一个记忆化类型（例如，一个模板实例化）

+   向别名调用添加一个参数

+   添加一个参数到一个类型

+   调用一个别名

+   实例化一个类型

+   实例化一个函数模板

+   使用**SFINAE**（**替换失败不是错误**）

为了证明这个规则，考虑以下代码：

```cpp
template<bool>
 struct conditional {
     template<typename T, typename F>
     using type = F;
 };

 template<>
 struct conditional<true> {
     template<typename T, typename F>
     using type = T;
 };

 template<bool B, typename T, typename F>
 using conditional_t = conditional<B>::template type<T, F>;
```

它定义了一个`conditional`模板别名，它存储一个类型，如果条件`B`为真，则解析为`T`，否则解析为`F`。编写这样一个实用程序的传统方式如下：

```cpp
template<bool B, class T, class F>
 struct conditional {
     using type = T;
 };

 template<class T, class F>
 struct conditional<false, T, F> {
     using type = F;
 };

 template<bool B, class T, class F>
 using conditional_t = conditional<B,T,F>::type;
```

然而，这第二种方法比第一种编译速度慢，因为它依赖于创建模板实例而不是类型别名。

现在让我们看看你可以使用哪些工具及其特性来保持编译时间低。

### 利用工具

一个常见的技术，可以使你的构建更快，就是使用**单一编译单元构建**，或者**统一构建**。它不会加速每个项目，但如果你的头文件中有大量代码，这可能值得一试。统一构建通过将所有`.cpp`文件包含在一个翻译单元中来工作。另一个类似的想法是使用预编译头文件。像 CMake 的 Cotire 这样的插件将为你处理这两种技术。CMake 3.16 还增加了对统一构建的本机支持，你可以通过为一个目标启用它，`set_target_properties(<target> PROPERTIES UNITY_BUILD ON`，或者通过将`CMAKE_UNITY_BUILD`设置为`true`来全局启用。如果你只想要 PCHs，你可能需要查看 CMake 3.16 的`target_precompile_headers`。

如果你觉得你在 C++文件中包含了太多内容，考虑使用一个名为**include-what-you-use**的工具来整理它们。更倾向于前向声明类型和函数而不是包含头文件也可以在减少编译时间方面走得更远。

如果您的项目链接需要很长时间，也有一些应对方法。使用不同的链接器，例如 LLVM 的 LLD 或 GNU 的 Gold，可以帮助很多，特别是因为它们允许多线程链接。如果您负担不起使用不同的链接器，您可以尝试使用诸如`-fvisibility-hidden`或`-fvisibility-inlines-hidden`等标志，并在源代码中仅标记您希望在共享库中可见的函数。这样，链接器将有更少的工作要做。如果您正在使用链接时优化，尝试仅对性能关键的构建进行优化：计划进行性能分析和用于生产的构建。否则，您可能只会浪费开发人员的时间。

如果您正在使用 CMake 并且没有绑定到特定的生成器（例如，CLion 需要使用`Code::Blocks`生成器），您可以用更快的生成器替换默认的 Make 生成器。**Ninja**是一个很好的选择，因为它是专门用于减少构建时间而创建的。要使用它，只需在调用 CMake 时传递`-G Ninja`。

还有两个很棒的工具，肯定会给您带来帮助。其中一个是**Ccache**。它是一个运行其 C 和 C++编译输出缓存的工具。如果您尝试两次构建相同的东西，它将从缓存中获取结果，而不是运行编译。它保留统计信息，如缓存命中和未命中，可以记住在编译特定文件时应发出的警告，并具有许多配置选项，可以存储在`~/.ccache/ccache.conf`文件中。要获取其统计信息，只需运行`ccache --show-stats`。

第二个工具是**IceCC**（或 Icecream）。这是 distcc 的一个分支，本质上是一个工具，可以在多台主机上分发您的构建。使用 IceCC，更容易使用自定义工具链。它在每台主机上运行 iceccd 守护程序和一个管理整个集群的 icecc-scheduler 服务。调度程序与 distcc 不同，它确保仅使用每台机器上的空闲周期，因此您不会过载其他人的工作站。

要在 CMake 构建中同时使用 IceCC 和 Ccache，只需在 CMake 调用中添加`-DCMAKE_C_COMPILER_LAUNCHER="ccache;icecc" -DCMAKE_CXX_COMPILER_LAUNCHER="ccache;icecc"`。如果您在 Windows 上编译，您可以使用 clcache 和 Incredibuild，或者寻找其他替代方案，而不是最后两个工具。

现在您知道如何快速构建，让我们继续另一个重要的主题。

## 查找潜在的代码问题

即使最快的构建也不值得，如果你的代码有错误。有数十个标志可以警告您代码中的潜在问题。本节将尝试回答您应该考虑启用哪些标志。

首先，让我们从一个略有不同的问题开始：如何避免收到来自其他库代码的问题警告。收到无法真正修复的问题警告是没有用的。幸运的是，有编译器开关可以禁用此类警告。例如，在 GCC 中，您有两种类型的`include`文件：常规文件（使用`-I`传递）和系统文件（使用`-isystem`传递）。如果您使用后者指定一个目录，您将不会收到它包含的头文件的警告。MSVC 有一个等效于`-isystem`的选项：`/external:I`。此外，它还有其他用于处理外部包含的标志，例如`/external:anglebrackets`，告诉编译器将使用尖括号包含的所有文件视为外部文件，从而禁用对它们的警告。您可以为外部文件指定警告级别。您还可以保留由您的代码引起的模板实例化产生的警告，使用`/external:templates-`。如果您正在寻找一种将`include`路径标记为系统/外部路径的便携方式，并且正在使用 CMake，您可以在`target_include_directories`指令中添加`SYSTEM`关键字。

谈到可移植性，如果您想符合 C++标准（您应该这样做），请考虑为 GCC 或 Clang 的编译选项添加-pedantic，或者为 MSVC 添加/permissive-选项。这样，您将得到关于您可能正在使用的每个非标准扩展的信息。如果您使用 CMake，请为每个目标添加以下行，set_target_properties(<target> PROPERTIES CXX_EXTENSIONS OFF)，以禁用特定于编译器的扩展。

如果您正在使用 MSVC，请努力使用/W4 编译代码，因为它启用了大部分重要的警告。对于 GCC 和 Clang，请尝试使用-Wall -Wextra -Wconversion -Wsign-conversion。第一个尽管名字是这样，但只启用了一些常见的警告。然而，第二个添加了另一堆警告。第三个基于 Scott Meyers 的一本名为《Effective C++》的好书中的建议（这是一组很好的警告，但请检查它是否对您的需求太吵闹）。最后两个是关于类型转换和符号转换的。所有这些标志一起创建了一个理智的安全网，但您当然可以寻找更多要启用的标志。Clang 有一个-Weverything 标志。尝试定期使用它运行构建，以发现可能值得在您的代码库中启用的新的潜在警告。您可能会对使用此标志获得多少消息感到惊讶，尽管启用一些警告标志可能不值得麻烦。MSVC 的替代方案名为/Wall。看一下以下表格，看看之前未启用的其他一些有趣的选项：

GCC/Clang:

| Flag | 意义 |
| --- | --- |
| -Wduplicated-cond | 当在 if 和 else-if 块中使用相同条件时发出警告。 |
| -Wduplicated-branches | 如果两个分支包含相同的源代码，则发出警告。 |
| -Wlogical-op | 当逻辑操作中的操作数相同时发出警告，并且应使用位操作符时发出警告。 |
| -Wnon-virtual-dtor | 当一个类有虚函数但没有虚析构函数时发出警告。 |
| -Wnull-dereference | 警告空指针解引用。此检查可能在未经优化的构建中处于非活动状态。 |
| -Wuseless-cast | 当转换为相同类型时发出警告。 |
| -Wshadow | 一系列关于声明遮蔽其他先前声明的警告。 |

MSVC:

| Flag | 意义 |
| --- | --- |
| /w44640 | 警告非线程安全的静态成员初始化。 |

最后值得一提的是一个问题：是否使用-Werror（或 MSVC 上的/WX）？这实际上取决于您的个人偏好，因为发出错误而不是警告有其利弊。好的一面是，您不会让任何已启用的警告溜走。您的 CI 构建将失败，您的代码将无法编译。在运行多线程构建时，您不会在快速通过的编译消息中丢失任何警告。然而，也有一些坏处。如果编译器启用了任何新的警告或只是检测到更多问题，您将无法升级编译器。对于依赖项也是一样，它们可能会废弃一些提供的函数。如果您的代码被项目的其他部分使用，您将无法废弃其中的任何内容。幸运的是，您总是可以使用混合解决方案：努力使用-Werror 进行编译，但在需要执行它所禁止的操作时将其禁用。这需要纪律，因为如果有任何新的警告滑入，您可能会很难消除它们。

## 使用以编译器为中心的工具

现在，编译器允许您做的事情比几年前多得多。这归功于 LLVM 和 Clang 的引入。通过提供 API 和模块化架构，使得诸如消毒剂、自动重构或代码完成引擎等工具得以蓬勃发展。您应该考虑利用这个编译器基础设施所提供的优势。使用 clang-format 确保代码库中的所有代码符合给定的标准。考虑使用 pre-commit 工具添加预提交挂钩，在提交之前重新格式化新代码。您还可以将 Python 和 CMake 格式化程序添加到其中。使用 clang-tidy 对代码进行静态分析——这是一个实际理解您的代码而不仅仅是推理的工具。这个工具可以为您执行大量不同的检查，所以一定要根据您的特定需求自定义列表和选项。您还可以在启用消毒剂的情况下每晚或每周运行软件测试。这样，您可以检测线程问题、未定义行为、内存访问、管理问题等。如果您的发布版本禁用了断言，使用调试版本运行测试也可能有价值。

如果您认为还可以做更多，您可以考虑使用 Clang 的基础设施编写自己的代码重构。如果您想看看如何创建一个基于 LLVM 的工具，已经有了一个`clang-rename`工具。对于 clang-tidy 的额外检查和修复也不难创建，它们可以为您节省数小时的手动劳动。

您可以将许多工具整合到您的构建过程中。现在让我们讨论这个过程的核心：构建系统。

# 摘要构建过程

在本节中，我们将深入研究 CMake 脚本，这是全球 C++项目中使用的事实标准构建系统生成器。

## 介绍 CMake

CMake 是构建系统生成器而不是构建系统本身意味着什么？简单地说，CMake 可以用来生成各种类型的构建系统。您可以使用它来生成 Visual Studio 项目、Makefile 项目、基于 Ninja 的项目、Sublime、Eclipse 和其他一些项目。

CMake 还配备了一系列其他工具，如用于执行测试的 CTest 和用于打包和创建安装程序的 CPack。CMake 本身也允许导出和安装目标。

CMake 的生成器可以是单配置的，比如 Make 或 NMAKE，也可以是多配置的，比如 Visual Studio。对于单配置的生成器，在首次在文件夹中运行生成时，应传递`CMAKE_BUILD_TYPE`标志。例如，要配置调试构建，您可以运行`cmake <project_directory> -DCMAKE_BUILD_TYPE=Debug`。其他预定义的配置有`Release`、`RelWithDebInfo`（带有调试符号的发布）和`MinSizeRel`（最小二进制大小的发布优化）。为了保持源目录清洁，始终创建一个单独的构建文件夹，并从那里运行 CMake 生成。

虽然可以添加自己的构建类型，但您真的应该尽量避免这样做，因为这会使一些 IDE 的使用变得更加困难，而且不具有可扩展性。一个更好的选择是使用`option`。

CMake 文件可以以两种风格编写：一种是基于变量的过时风格，另一种是基于目标的现代 CMake 风格。我们这里只关注后者。尽量遏制通过全局变量设置事物，因为这会在您想要重用目标时引起问题。

### 创建 CMake 项目

每个 CMake 项目的顶层`CMakeLists.txt`文件中应包含以下行：

```cpp
cmake_minimum_required(VERSION 3.15...3.19)

project(
   Customer
   VERSION 0.0.1
   LANGUAGES CXX)
```

设置最低和最大支持的版本很重要，因为它会影响 CMake 的行为，通过设置策略。如果需要，您也可以手动设置它们。

我们项目的定义指定了它的名称、版本（将用于填充一些变量）和 CMake 将用于构建项目的编程语言（这将填充更多变量并找到所需的工具）。

一个典型的 C++项目有以下目录：

+   `cmake`：用于 CMake 脚本

+   `include`：用于公共头文件，通常带有一个项目名称的子文件夹

+   `src`：用于源文件和私有头文件

+   `test`：用于测试

你可以使用 CMake 目录来存储你的自定义 CMake 模块。为了方便从这个目录访问脚本，你可以将它添加到 CMake 的`include()`搜索路径中，就像这样：

```cpp
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake"
```

在包含 CMake 模块时，你可以省略`.cmake`后缀。这意味着`include(CommonCompileFlags.cmake)`等同于`include(CommonCompileFlags)`。

### 区分 CMake 目录变量

在 CMake 中浏览目录有一个常见的陷阱，不是每个人都意识到。在编写 CMake 脚本时，尝试区分以下内置变量：

+   `PROJECT_SOURCE_DIR`：`project`命令最后一次从 CMake 脚本中调用的目录。

+   `PROJECT_BINARY_DIR`：与前一个相同，但用于构建目录树。

+   `CMAKE_SOURCE_DIR`：顶层源目录（这可能是另一个项目，只是将我们作为依赖项/子目录添加进来）。

+   `CMAKE_BINARY_DIR`：与`CMAKE_SOURCE_DIR`相同，但用于构建目录树。

+   `CMAKE_CURRENT_SOURCE_DIR`：对应于当前处理的`CMakeLists.txt`文件的源目录。

+   `CMAKE_CURRENT_BINARY_DIR`：与`CMAKE_CURRENT_SOURCE_DIR`匹配的二进制（构建）目录。

+   `CMAKE_CURRENT_LIST_DIR`：`CMAKE_CURRENT_LIST_FILE`的目录。如果当前的 CMake 脚本是从另一个脚本中包含的（对于被包含的 CMake 模块来说很常见），它可能与当前源目录不同。

搞清楚了这一点，现在让我们开始浏览这些目录。

在你的顶层`CMakeLists.txt`文件中，你可能想要调用`add_subdirectory(src)`，这样 CMake 将处理那个目录。

### 指定 CMake 目标

在`src`目录中，你应该有另一个`CMakeLists.txt`文件，这次可能定义了一个或两个目标。让我们为我们之前在书中提到的多米尼加展会系统添加一个客户微服务的可执行文件：

```cpp
add_executable(customer main.cpp)
```

源文件可以像前面的代码行那样指定，也可以稍后使用`target_sources`添加。

一个常见的 CMake 反模式是使用通配符来指定源文件。使用它们的一个很大的缺点是，CMake 不会知道文件是否被添加，直到重新运行生成。这样做的一个常见后果是，如果你从存储库中拉取更改然后简单地构建，你可能会错过编译和运行新的单元测试或其他代码。即使你使用了`CONFIGURE_DEPENDS`和通配符，构建时间也会变长，因为通配符必须作为每次构建的一部分进行检查。此外，该标志可能无法可靠地与所有生成器一起使用。即使 CMake 的作者也不鼓励使用它，而是更倾向于明确声明源文件。

好的，我们定义了我们的源代码。现在让我们指定我们的目标需要编译器支持 C++17：

```cpp
target_compile_features(customer PRIVATE cxx_std_17)
```

`PRIVATE`关键字指定这是一个内部要求，即只对这个特定目标可见，而不对依赖于它的任何目标可见。如果你正在编写一个提供用户 C++17 API 的库，你可以使用`INTERFACE`关键字。要同时指定接口和内部要求，你可以使用`PUBLIC`关键字。当使用者链接到我们的目标时，CMake 将自动要求它也支持 C++17。如果你正在编写一个不被构建的目标（即一个仅包含头文件的库或一个导入的目标），通常使用`INTERFACE`关键字就足够了。

你还应该注意，指定我们的目标要使用 C++17 特性并不强制执行 C++标准或禁止编译器扩展。要这样做，你应该调用以下命令：

```cpp
set_target_properties(customer PROPERTIES
     CXX_STANDARD 17
     CXX_STANDARD_REQUIRED YES
     CXX_EXTENSIONS NO
 )
```

如果你想要一组编译器标志传递给每个目标，你可以将它们存储在一个变量中，并在想要创建一个具有这些标志设置为`INTERFACE`的目标时调用以下命令，并且没有任何源并且使用这个目标在`target_link_libraries`中：

```cpp
target_compile_options(customer PRIVATE ${BASE_COMPILE_FLAGS})
```

该命令会自动传播包含目录、选项、宏和其他属性，而不仅仅是添加链接器标志。说到链接，让我们创建一个库，我们将与之链接：

```cpp
add_library(libcustomer lib.cpp)
add_library(domifair::libcustomer ALIAS libcustomer)
set_target_properties(libcustomer PROPERTIES OUTPUT_NAME customer)
# ...
target_link_libraries(customer PRIVATE libcustomer)
```

`add_library`可用于创建静态、共享、对象和接口（考虑头文件）库，以及定义任何导入的库。

它的**`ALIAS`**版本创建了一个命名空间目标，有助于调试许多 CMake 问题，是一种推荐的现代 CMake 实践。

因为我们已经给我们的目标添加了`lib`前缀，所以我们将输出名称设置为**`libcustomer.a`**而不是`liblibcustomer.a`。

最后，我们将我们的可执行文件与添加的库链接起来。尽量始终为`target_link_libraries`命令指定`PUBLIC`、`PRIVATE`或`INTERFACE`关键字，因为这对于 CMake 有效地管理目标依赖关系的传递性至关重要。

### 指定输出目录

一旦您使用`cmake --build .`等命令构建代码，您可能想知道在哪里找到构建产物。默认情况下，CMake 会将它们创建在与它们定义的源目录匹配的目录中。例如，如果您有一个带有`add_executable`指令的`src/CMakeLists.txt`文件，那么二进制文件将默认放在构建目录的`src`子目录中。我们可以使用以下代码来覆盖这一点：

```cpp
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin) 
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
```

这样，二进制文件和 DLL 文件将放在项目构建目录的`bin`子目录中，而静态和共享 Linux 库将放在`lib`子目录中。

## 使用生成器表达式

以一种既支持单配置生成器又支持多配置生成器的方式设置编译标志可能会很棘手，因为 CMake 在配置时间执行`if`语句和许多其他结构，而不是在构建/安装时间执行。

这意味着以下是 CMake 的反模式：

```cpp
if(CMAKE_BUILD_TYPE STREQUAL Release)
   target_compile_definitions(libcustomer PRIVATE RUN_FAST)
endif()
```

相反，生成器表达式是实现相同目标的正确方式，因为它们在稍后的时间被处理。让我们看一个实际使用它们的例子。假设您想为您的`Release`配置添加一个预处理器定义，您可以编写以下内容：

```cpp
target_compile_definitions(libcustomer PRIVATE "$<$<CONFIG:Release>:RUN_FAST>")
```

这将仅在构建所选的配置时解析为`RUN_FAST`。对于其他配置，它将解析为空值。它适用于单配置和多配置生成器。然而，这并不是生成器表达式的唯一用例。

在构建期间由我们的项目使用时，我们的目标的某些方面可能会有所不同，并且在安装目标时由其他项目使用时也会有所不同。一个很好的例子是**包含目录**。在 CMake 中处理这个问题的常见方法如下：

```cpp
target_include_directories(
   libcustomer PUBLIC $<INSTALL_INTERFACE:include>
                      $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)
```

在这种情况下，我们有两个生成器表达式。第一个告诉我们，当安装时，可以在`include`目录中找到包含文件，相对于安装前缀（安装的根目录）。如果我们不安装，这个表达式将变为空。这就是为什么我们有另一个用于构建的表达式。这将解析为上次使用`project()`找到的目录的`include`子目录。

不要在模块之外的路径上使用`target_include_directories`。如果这样做，您就是**偷**别人的头文件，而不是明确声明库/目标依赖关系。这是 CMake 的反模式。

CMake 定义了许多生成器表达式，您可以使用这些表达式来查询编译器和平台，以及目标（例如完整名称、对象文件列表、任何属性值等）。除此之外，还有运行布尔操作、if 语句、字符串比较等表达式。

现在，举一个更复杂的例子，假设您想要有一组编译标志，您可以在所有目标上使用，并且这些标志取决于所使用的编译器，您可以定义如下：

```cpp
list(
   APPEND
   BASE_COMPILE_FLAGS
   "$<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:-Wall;-Wextra;-pedantic;-Werror>"
   "$<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>")
```

如果编译器是 Clang 或 AppleClang 或 GCC，则会附加一组标志，如果使用的是 MSVC，则会附加另一组标志。请注意，我们使用分号分隔标志，因为这是 CMake 在列表中分隔元素的方式。

现在让我们看看如何为我们的项目添加外部代码供其使用。

# 使用外部模块

有几种方法可以获取您所依赖的外部项目。例如，您可以将它们添加为 Conan 依赖项，使用 CMake 的`find_package`来查找操作系统提供的版本或以其他方式安装的版本，或者自行获取和编译依赖项。

本节的关键信息是：如果可以的话，应该使用 Conan。这样，您将最终使用与您的项目及其依赖项要求相匹配的依赖项版本。

如果您的目标是支持多个平台，甚至是同一发行版的多个版本，使用 Conan 或自行编译都是可行的方法。这样，无论您在哪个操作系统上编译，都将使用相同的依赖项版本。

让我们讨论一下 CMake 本身提供的几种抓取依赖项的方法，然后转而使用名为 Conan 的多平台包管理器。

## 获取依赖项

使用 CMake 内置的`FetchContent`模块从源代码准备依赖项的一种可能的方法是。它将为您下载依赖项，然后像常规目标一样构建它们。

该功能在 CMake 3.11 中推出。它是`ExternalProject`模块的替代品，后者有许多缺陷。其中之一是它在构建时克隆了外部存储库，因此 CMake 无法理解外部项目定义的目标，以及它们的依赖关系。这使得许多项目不得不手动定义这些外部目标的`include`目录和库路径，并完全忽略它们所需的接口编译标志和依赖关系。`FetchContent`没有这样的问题，因此建议您使用它。

在展示如何使用之前，您必须知道`FetchContent`和`ExternalProject`（以及使用 Git 子模块和类似方法）都有一个重要的缺陷。如果您有许多依赖项使用同一个第三方库，您可能最终会得到同一项目的多个版本，例如几个版本的 Boost。使用 Conan 等包管理器可以帮助您避免这种问题。

举个例子，让我们演示如何使用上述的`FetchContent`功能将**GTest**集成到您的项目中。首先，创建一个`FetchGTest.cmake`文件，并将其放在我们源代码树中的`cmake`目录中。我们的`FetchGTest`脚本将定义如下：

```cpp
include(FetchContent)

 FetchContent_Declare(
   googletest
   GIT_REPOSITORY https://github.com/google/googletest.git
   GIT_TAG dcc92d0ab6c4ce022162a23566d44f673251eee4)

 FetchContent_GetProperties(googletest)
 if(NOT googletest_POPULATED)
   FetchContent_Populate(googletest)
   add_subdirectory(${googletest_SOURCE_DIR} ${googletest_BINARY_DIR}
                    EXCLUDE_FROM_ALL)
 endif()

 message(STATUS "GTest binaries are present at ${googletest_BINARY_DIR}")

```

首先，我们包含内置的`FetchContent`模块。一旦加载了该模块，我们就可以使用`FetchContent_Declare`来声明依赖项。现在，让我们命名我们的依赖项，并指定 CMake 将克隆的存储库以及它将检出的修订版本。

现在，我们可以读取我们外部库的属性并填充（即检出）它（如果尚未完成）。一旦我们有了源代码，我们可以使用`add_subdirectory`来处理它们。`EXCLUDE_FROM_ALL`选项将告诉 CMake 在运行诸如`make all`这样的命令时，如果其他目标不需要它们，就不要构建这些目标。在成功处理目录后，我们的脚本将打印一条消息，指示 GTests 库在构建后将位于哪个目录中。

如果您不喜欢将依赖项与项目一起构建，也许下一种集成依赖项的方式更适合您。

## 使用查找脚本

假设你的依赖项在主机的某个地方可用，你可以调用`find_package`来尝试搜索它。如果你的依赖项提供了配置或目标文件（稍后会详细介绍），那么只需编写这一个简单的命令就足够了。当然，前提是依赖项已经在你的机器上可用。如果没有，你需要在运行 CMake 之前安装它们。

要创建前面的文件，你的依赖项需要使用 CMake，但这并不总是情况。那么，你该如何处理那些不使用 CMake 的库呢？如果这个库很受欢迎，很可能已经有人为你创建了一个查找脚本。版本早于 1.70 的 Boost 库就是这种方法的一个常见例子。CMake 自带一个`FindBoost`模块，你可以通过运行`find_package(Boost)`来执行它。

要使用前面的模块找到 Boost，你首先需要在系统上安装它。之后，在你的 CMake 列表中，你应该设置任何你认为合理的选项。例如，要使用动态和多线程 Boost 库，而不是静态链接到 C++运行时，指定如下：

```cpp
set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
```

然后，你需要实际搜索库，如下所示：

```cpp
find_package(Boost 1.69 EXACT REQUIRED COMPONENTS Beast)
```

在这里，我们指定我们只想使用 Beast，这是 Boost 的一部分，一个很棒的网络库。一旦找到，你可以将它链接到你的目标，如下所示：

```cpp
target_link_libraries(MyTarget PUBLIC Boost::Beast)
```

现在你知道如何正确使用查找脚本了，让我们学习如何自己编写一个。

## 编写查找脚本

如果你的依赖项既没有提供配置和目标文件，也没有人为其编写查找模块，你总是可以自己编写这样的模块。

这不是你经常做的事情，所以我们会尽量简要地介绍一下这个主题。如果你想深入了解，你还应该阅读官方 CMake 文档中的指南（在*进一步阅读*部分中链接），或者查看 CMake 安装的一些查找模块（通常在 Unix 系统的`/usr/share/cmake-3.17/Modules`等目录中）。为简单起见，我们假设你只想找到你的依赖项的一个配置，但也可以分别找到`Release`和`Debug`二进制文件。这将导致设置不同的目标和相关变量。

脚本名称决定了你将传递给`find_package`的参数；例如，如果你希望最终得到`find_package(Foo)`，那么你的脚本应该命名为`FindFoo.cmake`。

良好的做法是从一个`reStructuredText`部分开始编写脚本，描述你的脚本实际要做什么，它将设置哪些变量等等。这样的描述示例可能如下：

```cpp
 #.rst:
 # FindMyDep
 # ----------
 #
 # Find my favourite external dependency (MyDep).
 #
 # Imported targets
 # ^^^^^^^^^^^^^^^^
 #
 # This module defines the following :prop_tgt:`IMPORTED` target:
 #
 # ``MyDep::MyDep``
 #   The MyDep library, if found.
 #
```

通常，你还会想描述一下你的脚本将设置的变量：

```cpp
 # Result variables
 # ^^^^^^^^^^^^^^^^
 #
 # This module will set the following variables in your project:
 #
 # ``MyDep_FOUND``
 #   whether MyDep was found or not
 # ``MyDep_VERSION_STRING``
 #   the found version of MyDep
```

如果`MyDep`本身有任何依赖项，现在就是找到它们的时候了：

```cpp
find_package(Boost REQUIRED)
```

现在我们可以开始搜索库了。一个常见的方法是使用`pkg-config`：

```cpp
find_package(PkgConfig)
pkg_check_modules(PC_MyDep QUIET MyDep)
```

如果`pkg-config`有关于我们的依赖项的信息，它将设置一些我们可以用来找到它的变量。

一个好主意可能是让我们的脚本用户设置一个变量，指向库的位置。按照 CMake 的约定，它应该被命名为`MyDep_ROOT_DIR`。用户可以通过在构建目录中调用`-DMyDep_ROOT_DIR=some/path`来提供这个变量给 CMake，修改`CMakeCache.txt`中的变量，或者使用`ccmake`或`cmake-gui`程序。

现在，我们可以使用前面提到的路径实际搜索我们的依赖项的头文件和库：

```cpp
find_path(MyDep_INCLUDE_DIR
   NAMES MyDep.h
   PATHS "${MyDep_ROOT_DIR}/include" "${PC_MyDep_INCLUDE_DIRS}"
   PATH_SUFFIXES MyDep
 )

 find_library(MyDep_LIBRARY
   NAMES mydep
   PATHS "${MyDep_ROOT_DIR}/lib" "${PC_MyDep_LIBRARY_DIRS}"
 )
```

然后，我们还需要设置找到的版本，就像我们在脚本头部承诺的那样。要使用从`pkg-config`找到的版本，我们可以编写如下内容：

```cpp
set(MyDep_VERSION ${PC_MyDep_VERSION})
```

或者，我们可以手动从头文件的内容、库路径的组件或使用其他任何方法中提取版本。完成后，让我们利用 CMake 的内置脚本来决定库是否成功找到，同时处理`find_package`调用的所有可能参数：

```cpp
include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(MyDep
         FOUND_VAR MyDep_FOUND
         REQUIRED_VARS
         MyDep_LIBRARY
         MyDep_INCLUDE_DIR
         VERSION_VAR MyDep_VERSION
         )
```

由于我们决定提供一个目标而不仅仅是一堆变量，现在是定义它的时候了：

```cpp
if(MyDep_FOUND AND NOT TARGET MyDep::MyDep)
     add_library(MyDep::MyDep UNKNOWN IMPORTED)
     set_target_properties(MyDep::MyDep PROPERTIES
             IMPORTED_LOCATION "${MyDep_LIBRARY}"
             INTERFACE_COMPILE_OPTIONS "${PC_MyDep_CFLAGS_OTHER}"
             INTERFACE_INCLUDE_DIRECTORIES "${MyDep_INCLUDE_DIR}"
             INTERFACE_LINK_LIBRARIES Boost::boost
             )
endif()
```

最后，让我们隐藏我们内部使用的变量，以免让不想处理它们的用户看到：

```cpp
mark_as_advanced(
 MyDep_INCLUDE_DIR
 MyDep_LIBRARY
 )
```

现在，我们有了一个完整的查找模块，我们可以按以下方式使用它：

```cpp
find_package(MyDep REQUIRED)
target_link_libraries(MyTarget PRIVATE MyDep::MyDep)
```

这就是您可以自己编写查找模块的方法。

不要为您自己的包编写`Find\*.cmake`模块。这些模块是为不支持 CMake 的包而设计的。相反，编写一个`Config\*.cmake`模块（如本章后面所述）。

现在让我们展示如何使用一个合适的包管理器，而不是自己来处理繁重的工作。

## 使用 Conan 包管理器

Conan 是一个开源的、去中心化的本地包管理器。它支持多个平台和编译器。它还可以与多个构建系统集成。

如果某个包在您的环境中尚未构建，Conan 将在您的计算机上处理构建它，而不是下载已构建的版本。构建完成后，您可以将其上传到公共存储库、您自己的`conan_server`实例，或者 Artifactory 服务器。

### 准备 Conan 配置文件

如果这是您第一次运行 Conan，它将根据您的环境创建一个默认配置文件。您可能希望通过创建新配置文件或更新默认配置文件来修改其中的一些设置。假设我们正在使用 Linux，并且希望使用 GCC 9.x 编译所有内容，我们可以运行以下命令：

```cpp
 conan profile new hosacpp
 conan profile update settings.compiler=gcc hosacpp
 conan profile update settings.compiler.libcxx=libstdc++11 hosacpp
 conan profile update settings.compiler.version=10 hosacpp
 conan profile update settings.arch=x86_64 hosacpp
 conan profile update settings.os=Linux hosacpp
```

如果我们的依赖来自于默认存储库之外的其他存储库，我们可以使用`conan remote add <repo> <repo_url>`来添加它们。例如，您可能希望使用这个来配置您公司的存储库。

现在我们已经设置好了 Conan，让我们展示如何使用 Conan 获取我们的依赖，并将所有这些集成到我们的 CMake 脚本中。

### 指定 Conan 依赖

我们的项目依赖于 C++ REST SDK。为了告诉 Conan 这一点，我们需要创建一个名为`conanfile.txt`的文件。在我们的情况下，它将包含以下内容：

```cpp
 [requires]
 cpprestsdk/2.10.18

 [generators]
 CMakeDeps
```

您可以在这里指定尽可能多的依赖。每个依赖可以有一个固定的版本、一系列固定版本，或者像**latest**这样的标签。在`@`符号之后，您可以找到拥有该包的公司以及允许您选择特定变体的通道（通常是稳定和测试）。

**生成器**部分是您指定要使用的构建系统的地方。对于 CMake 项目，您应该使用`CMakeDeps`。您还可以生成许多其他生成器，包括用于生成编译器参数、CMake 工具链文件、Python 虚拟环境等等。

在我们的情况下，我们没有指定任何其他选项，但您可以轻松添加此部分，并为您的包和它们的依赖项配置变量。例如，要将我们的依赖项编译为静态库，我们可以编写以下内容：

```cpp
 [options]
 cpprestsdk:shared=False
```

一旦我们放置了`conanfile.txt`，让我们告诉 Conan 使用它。

### 安装 Conan 依赖

要在 CMake 代码中使用我们的 Conan 包，我们必须先安装它们。在 Conan 中，这意味着下载源代码并构建它们，或者下载预构建的二进制文件，并创建我们将在 CMake 中使用的配置文件。在我们创建了构建目录后，让 Conan 在我们之后处理这些，我们应该`cd`进入它，然后简单地运行以下命令：

```cpp
conan install path/to/directory/containing/conanfile.txt --build=missing -s build_type=Release -pr=hosacpp
```

默认情况下，Conan 希望下载所有依赖项作为预构建的二进制文件。如果服务器没有预构建它们，Conan 将构建它们，而不是像我们传递了`--build=missing`标志那样退出。我们告诉它抓取使用与我们配置文件中相同的编译器和环境构建的发布版本。您可以通过简单地使用`build_type`设置为其他 CMake 构建类型的另一个命令来为多个构建类型安装软件包。如果需要，这可以帮助您快速切换。如果要使用默认配置文件（Conan 可以自动检测到的配置文件），只需不传递`-pr`标志。

如果我们计划使用的 CMake 生成器没有在`conanfile.txt`中指定，我们可以将其附加到前面的命令中。例如，要使用`compiler_args`生成器，我们应该附加`--generator compiler_args`。稍后，您可以通过将`@conanbuildinfo.args`传递给编译器调用来使用它生成的内容。

### 使用 CMake 中的 Conan 目标

一旦 Conan 完成下载、构建和配置我们的依赖关系，我们需要告诉 CMake 使用它们。

如果您正在使用带有`CMakeDeps`生成器的 Conan，请确保指定`CMAKE_BUILD_TYPE`值。否则，CMake 将无法使用 Conan 配置的软件包。例如调用（从您运行 Conan 的相同目录）可能如下所示：

```cpp
cmake path/to/directory/containing/CMakeLists.txt -DCMAKE_BUILD_TYPE=Release
```

这样，我们将以发布模式构建我们的项目；我们必须使用 Conan 安装的类型之一。要找到我们的依赖关系，我们可以使用 CMake 的`find_package`：

```cpp
list(APPEND CMAKE_PREFIX_PATH "${CMAKE_BINARY_DIR}")
find_package(cpprestsdk CONFIG REQUIRED)
```

首先，我们将根构建目录添加到 CMake 将尝试在其中查找软件包配置文件的路径中。然后，我们找到 Conan 生成的软件包配置文件。

要将 Conan 定义的目标作为我们目标的依赖项传递，最好使用命名空间目标名称：

```cpp
 target_link_libraries(libcustomer PUBLIC cpprestsdk::cpprest)
```

这样，当找不到包时，我们将在 CMake 的配置期间收到错误。如果没有别名，我们在尝试链接时会收到错误。

现在我们已经按照我们想要的方式编译和链接了我们的目标，是时候进行测试了。

## 添加测试

CMake 有自己的测试驱动程序，名为`CTest`。很容易从您的`CMakeLists`中添加新的测试套件，无论是自己还是使用测试框架提供的许多集成。在本书的后面，我们将深入讨论测试，但首先让我们展示如何快速而干净地基于 GoogleTest 或 GTest 测试框架添加单元测试。

通常，要在 CMake 中定义您的测试，您会想要编写以下内容：

```cpp
 if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
   include(CTest)
   if(BUILD_TESTING)
     add_subdirectory(test)
   endif()
 endif()
```

前面的片段将首先检查我们是否是正在构建的主项目。通常，您只想为您的项目运行测试，并且甚至不想为您使用的任何第三方组件构建测试。这就是为什么项目名称是`checked`。

如果我们要运行我们的测试，我们包括`CTest`模块。这将加载 CTest 提供的整个测试基础设施，定义其附加目标，并调用一个名为`enable_testing`的 CMake 函数，该函数将在其他事项中启用`BUILD_TESTING`标志。此标志是缓存的，因此您可以通过在生成构建系统时简单地传递`-DBUILD_TESTING=OFF`参数来禁用所有测试来构建您的项目。

所有这些缓存变量实际上都存储在名为`CMakeCache.txt`的文本文件中，位于您的构建目录中。随意修改那里的变量以更改 CMake 的操作；直到您删除该文件，它才不会覆盖那里的设置。您可以使用`ccmake`、`cmake-gui`，或者手动进行修改。

如果`BUILD_TESTING`为 true，我们只需处理我们测试目录中的`CMakeLists.txt`文件。可能看起来像这样：

```cpp
 include(FetchGTest)
 include(GoogleTest)

 add_subdirectory(customer)
```

第一个 include 调用了我们之前描述的提供 GTest 的脚本。在获取了 GTest 之后，我们当前的`CMakeLists.txt`通过调用`include(GoogleTest)`加载了 GoogleTest CMake 模块中定义的一些辅助函数。这将使我们更容易地将我们的测试集成到 CTest 中。最后，让我们告诉 CMake 进入一个包含一些测试的目录，通过调用`add_subdirectory(customer)`。

`test/customer/CMakeLists.txt`文件将简单地添加一个使用我们预定义的标志编译的带有测试的可执行文件，并链接到被测试的模块和 GTest。然后，我们调用 CTest 辅助函数来发现已定义的测试。所有这些只是四行 CMake 代码：

```cpp
 add_executable(unittests unit.cpp)
 target_compile_options(unittests PRIVATE ${BASE_COMPILE_FLAGS})
 target_link_libraries(unittests PRIVATE domifair::libcustomer gtest_main)
 gtest_discover_tests(unittests)
```

大功告成！

现在，您可以通过简单地转到`build`目录并调用以下命令来构建和执行您的测试：

```cpp
 cmake --build . --target unittests
 ctest # or cmake --build . --target test
```

您可以为 CTest 传递一个`-j`标志。它的工作方式与 Make 或 Ninja 调用相同-并行化测试执行。如果您想要一个更短的构建命令，只需运行您的构建系统，也就是通过调用`make`。

在脚本中，通常最好使用命令的较长形式；这将使您的脚本独立于所使用的构建系统。

一旦您的测试通过了，现在我们可以考虑向更广泛的受众提供它们。

# 重用优质代码

CMake 具有内置的实用程序，当涉及到分发构建结果时，这些实用程序可以走得更远。本节将描述安装和导出实用程序以及它们之间的区别。后续章节将向您展示如何使用 CPack 打包您的代码，以及如何使用 Conan 进行打包。

安装和导出对于微服务本身并不那么重要，但如果您要为其他人提供库以供重用，这将非常有用。

## 安装

如果您编写或使用过 Makefiles，您很可能在某个时候调用了`make install`，并看到项目的交付成果被安装在操作系统目录或您选择的其他目录中。如果您正在使用`make`与 CMake，使用本节的步骤将使您能够以相同的方式安装交付成果。如果没有，您仍然可以调用安装目标。除此之外，在这两种情况下，您将有一个简单的方法来利用 CPack 来创建基于您的安装命令的软件包。

如果您在 Linux 上，预设一些基于操作系统约定的安装目录可能是一个不错的主意，通过调用以下命令：

```cpp
include(GNUInstallDirs)
```

这将使安装程序使用由`bin`、`lib`和其他类似目录组成的目录结构。这些目录也可以使用一些 CMake 变量手动设置。

创建安装目标包括一些更多的步骤。首先，首要的是定义我们要安装的目标，这在我们的情况下将是以下内容：

```cpp
install(
   TARGETS libcustomer customer
   EXPORT CustomerTargets
   LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
   ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
   RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
```

这告诉 CMake 使用我们在本章前面定义的库和可执行文件作为`CustomerTargets`公开，使用我们之前设置的目录。

如果您计划将您的库的不同配置安装到不同的文件夹中，您可以使用前面命令的几次调用，就像这样：

```cpp
 install(TARGETS libcustomer customer
         CONFIGURATIONS Debug
         # destinations for other components go here...
         RUNTIME DESTINATION Debug/bin)
 install(TARGETS libcustomer customer
         CONFIGURATIONS Release
         # destinations for other components go here...
         RUNTIME DESTINATION Release/bin)
```

您可以注意到我们为可执行文件和库指定了目录，但没有包含文件。我们需要在另一个命令中提供它们，就像这样：

```cpp
 install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/
         DESTINATION include)
```

这意味着顶层包含目录的内容将被安装在安装根目录下的包含目录中。第一个路径后面的斜杠修复了一些路径问题，所以请注意使用它。

所以，我们有了一组目标；现在我们需要生成一个文件，另一个 CMake 项目可以读取以了解我们的目标。可以通过以下方式完成：

```cpp
 install(
     EXPORT CustomerTargets
     FILE CustomerTargets.cmake
     NAMESPACE domifair::
     DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Customer)
```

此命令将获取我们的目标集并创建一个`CustomerTargets.cmake`文件，其中将包含有关我们的目标及其要求的所有信息。我们的每个目标都将使用命名空间进行前缀处理；例如，`customer`将变成`domifair::customer`。生成的文件将安装在我们安装树中库文件夹的子目录中。

为了允许依赖项目使用 CMake 的`find_package`命令找到我们的目标，我们需要提供一个`CustomerConfig.cmake`文件。如果您的目标没有任何依赖项，您可以直接将前面的目标导出到该文件中，而不是`targets`文件。否则，您应该编写自己的配置文件，其中将包括前面的`targets`文件。

在我们的情况下，我们想要重用一些 CMake 变量，因此我们需要创建一个模板，并使用`configure_file`命令来填充它：

```cpp
  configure_file(${PROJECT_SOURCE_DIR}/cmake/CustomerConfig.cmake.in
                  CustomerConfig.cmake @ONLY)
```

我们的`CustomerConfig.cmake.in`文件将首先处理我们的依赖项：

```cpp
 include(CMakeFindDependencyMacro)

 find_dependency(cpprestsdk 2.10.18 REQUIRED)
```

`find_dependency`宏是`find_package`的包装器，旨在在配置文件中使用。尽管我们依赖 Conan 在`conanfile.txt`中定义的 C++ REST SDK 2.10.18，但在这里我们需要再次指定依赖关系。我们的软件包可以在另一台机器上使用，因此我们要求我们的依赖项也在那里安装。如果您想在目标机器上使用 Conan，可以按以下方式安装 C++ REST SDK：

```cpp
conan install cpprestsdk/2.10.18
```

处理完依赖项后，我们的配置文件模板将包括我们之前创建的`targets`文件：

```cpp
if(NOT TARGET domifair::@PROJECT_NAME@)
   include("${CMAKE_CURRENT_LIST_DIR}/@PROJECT_NAME@Targets.cmake")
endif()
```

当`configure_file`执行时，它将用项目中定义的`${VARIABLES}`的内容替换所有这些`@VARIABLES@`。这样，基于我们的`CustomerConfig.cmake.in`文件模板，CMake 将创建一个`CustomerConfig.cmake`文件。

在使用`find_package`查找依赖项时，通常需要指定要查找的软件包的版本。为了在我们的软件包中支持这一点，我们必须创建一个`CustomerConfigVersion.cmake`文件。CMake 为我们提供了一个辅助函数，可以为我们创建此文件。让我们按照以下方式使用它：

```cpp
 include(CMakePackageConfigHelpers)
 write_basic_package_version_file(
   CustomerConfigVersion.cmake
   VERSION ${PACKAGE_VERSION}
   COMPATIBILITY AnyNewerVersion)
```

`PACKAGE_VERSION`变量将根据我们在调用顶层`CMakeLists.txt`文件顶部的`project`时传递的`VERSION`参数进行填充。

`AnyNewerVersion COMPATIBILITY`表示如果我们的软件包比请求的版本更新或相同，它将被任何软件包搜索接受。其他选项包括`SameMajorVersion`，`SameMinorVersion`和`ExactVersion`。

一旦我们创建了我们的配置和配置版本文件，让我们告诉 CMake 它们应该与二进制文件和我们的目标文件一起安装：

```cpp
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/CustomerConfig.cmake
               ${CMAKE_CURRENT_BINARY_DIR}/CustomerConfigVersion.cmake
         DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Customer)
```

我们应该安装的最后一件事是我们项目的许可证。我们将利用 CMake 的安装文件的命令将它们放在我们的文档目录中：

```cpp
install(
   FILES ${PROJECT_SOURCE_DIR}/LICENSE
   DESTINATION ${CMAKE_INSTALL_DOCDIR})
```

这就是您成功在操作系统根目录中创建安装目标所需了解的全部内容。您可能会问如何将软件包安装到另一个目录，比如仅供当前用户使用。要这样做，您需要设置`CMAKE_INSTALL_PREFIX`变量，例如，在生成构建系统时。

请注意，如果我们不安装到 Unix 树的根目录，我们将不得不为依赖项目提供安装目录的路径，例如通过设置`CMAKE_PREFIX_PATH`。

现在让我们看看另一种您可以重用刚刚构建的东西的方法。

## 导出

导出是一种将您在本地构建的软件包的信息添加到 CMake 的软件包注册表中的技术。当您希望您的目标可以直接从它们的构建目录中看到，即使没有安装时，这将非常有用。导出的常见用途是当您在开发机器上检出了几个项目并在本地构建它们时。

从您的`CMakeLists.txt`文件中添加对此机制的支持非常容易。在我们的情况下，可以这样做：

```cpp
export(
   TARGETS libcustomer customer
   NAMESPACE domifair::
   FILE CustomerTargets.cmake)

set(CMAKE_EXPORT_PACKAGE_REGISTRY ON)
export(PACKAGE domifair)
```

这样，CMake 将创建一个类似于*Installing*部分中的目标文件，定义我们在提供的命名空间中的库和可执行目标。从 CMake 3.15 开始，默认情况下禁用软件包注册表，因此我们需要通过设置适当的前置变量来启用它。然后，通过导出我们的软件包，我们可以将有关我们的目标的信息直接放入注册表中。

请注意，现在我们有一个没有匹配配置文件的`targets`文件。这意味着如果我们的目标依赖于任何外部库，它们必须在我们的软件包被找到之前被找到。在我们的情况下，调用必须按照以下方式排序：

```cpp
 find_package(cpprestsdk 2.10.18)
 find_package(domifair)
```

首先，我们找到 C++ REST SDK，然后再寻找依赖于它的软件包。这就是你需要知道的一切，就可以开始导出你的目标了。比安装它们要容易得多，不是吗？

现在让我们继续介绍第三种将您的目标暴露给外部世界的方法。

## 使用 CPack

在本节中，我们将描述如何使用 CMake 附带的打包工具 CPack。

CPack 允许您轻松创建各种格式的软件包，从 ZIP 和 TGZ 存档到 DEB 和 RPM 软件包，甚至安装向导，如 NSIS 或一些特定于 OS X 的软件包。一旦您安装逻辑就位，集成工具并不难。让我们展示如何使用 CPack 来打包我们的项目。

首先，我们需要指定 CPack 在创建软件包时将使用的变量：

```cpp
 set(CPACK_PACKAGE_VENDOR "Authors")
 set(CPACK_PACKAGE_CONTACT "author@example.com")
 set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
     "Library and app for the Customer microservice")
```

我们需要手动提供一些信息，但是一些变量可以根据我们在定义项目时指定的项目版本来填充。CPack 变量还有很多，您可以在本章末尾的*进一步阅读*部分的 CPack 链接中阅读所有这些变量。其中一些对所有软件包生成器都是通用的，而另一些则特定于其中的一些。例如，如果您计划使用安装程序，您可以设置以下两个：

`set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")`

`set(CPACK_RESOURCE_FILE_README "${PROJECT_SOURCE_DIR}/README.md")`

一旦您设置了所有有趣的变量，就该选择 CPack 要使用的生成器了。让我们从在`CPACK_GENERATOR`中放置一些基本的生成器开始，这是 CPack 依赖的一个变量：

`list(APPEND CPACK_GENERATOR TGZ ZIP)`

这将导致 CPack 基于我们在本章前面定义的安装步骤生成这两种类型的存档。

你可以根据许多因素选择不同的软件包生成器，例如，正在运行的机器上可用的工具。例如，在 Windows 上构建时创建 Windows 安装程序，在 Linux 上构建时使用适当的工具安装 DEB 或 RPM 软件包。例如，如果你正在运行 Linux，你可以检查是否安装了`dpkg`，如果是，则创建 DEB 软件包：

```cpp
 if(UNIX)
   find_program(DPKG_PROGRAM dpkg)
   if(DPKG_PROGRAM)
     list(APPEND CPACK_GENERATOR DEB)
     set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS} libcpprest2.10 (>= 2.10.2-6)")
     set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
   else()
     message(STATUS "dpkg not found - won't be able to create DEB packages")
   endif()
```

我们使用了`CPACK_DEBIAN_PACKAGE_DEPENDS`变量，使 DEB 软件包要求首先安装 C++ REST SDK。

对于 RPM 软件包，您可以手动检查`rpmbuild`：

```cpp
 find_program(RPMBUILD_PROGRAM rpmbuild)
   if(RPMBUILD_PROGRAM)
     list(APPEND CPACK_GENERATOR RPM)
     set(CPACK_RPM_PACKAGE_REQUIRES "${CPACK_RPM_PACKAGE_REQUIRES} cpprest >= 2.10.2-6")
   else()
     message(STATUS "rpmbuild not found - won't be able to create RPM packages")
   endif()
 endif()
```

很巧妙，对吧？

这些生成器提供了大量其他有用的变量，所以如果您需要比这里描述的基本需求更多的东西，请随时查看 CMake 的文档。

当涉及到变量时，最后一件事是，您也可以使用它们来避免意外打包不需要的文件。这可以通过以下方式完成：

`set(CPACK_SOURCE_IGNORE_FILES /.git /dist /.*build.* /\\\\.DS_Store)`

一旦我们把所有这些都放在位子上，我们可以从我们的 CMake 列表中包含 CPack 本身：

`include(CPack)`

记住，始终将此作为最后一步进行，因为 CMake 不会将您稍后使用的任何变量传播给 CPack。

要运行它，直接调用`cpack`或更长的形式，它还会检查是否需要首先重新构建任何内容：`cmake --build . --target package`。您可以轻松地通过`-G`标志覆盖生成器，例如，`-G DEB`只需构建 DEB 软件包，`-G WIX -C Release`打包一个发布的 MSI 可执行文件，或`-G DragNDrop`获取 DMG 安装程序。

现在让我们讨论一种更原始的构建软件包的方法。

# 使用 Conan 打包

我们已经展示了如何使用 Conan 安装我们的依赖项。现在，让我们深入了解如何创建我们自己的 Conan 软件包。

让我们在我们的项目中创建一个新的顶级目录，简单地命名为`conan`，在那里我们将使用这个工具打包所需的文件：一个用于构建我们的软件包的脚本和一个用于测试的环境。

## 创建 conanfile.py 脚本

所有 Conan 软件包所需的最重要的文件是`conanfile.py`。在我们的情况下，我们将使用 CMake 变量填写一些细节，所以我们将创建一个`conanfile.py.in`文件。我们将使用它来通过将以下内容添加到我们的`CMakeLists.txt`文件来创建前一个文件：

```cpp
configure_file(${PROJECT_SOURCE_DIR}/conan/conanfile.py.in
                ${CMAKE_CURRENT_BINARY_DIR}/conan/conanfile.py @ONLY)
```

我们的文件将以一些无聊的 Python 导入开始，例如 Conan 对于 CMake 项目所需的导入：

```cpp
 import os
 from conans import ConanFile, CMake
```

现在我们需要创建一个定义我们软件包的类：

```cpp
class CustomerConan(ConanFile):
     name = "customer"
     version = "@PROJECT_VERSION@"
     license = "MIT"
     author = "Authors"
     description = "Library and app for the Customer microservice"
     topics = ("Customer", "domifair")
```

首先，我们从我们的 CMake 代码中获取一堆通用变量。通常，描述将是一个多行字符串。主题对于在 JFrog 的 Artifactory 等网站上找到我们的库非常有用，并且可以告诉读者我们的软件包是关于什么的。现在让我们浏览其他变量：

```cpp
     homepage = "https://example.com"
     url = "https://github.com/PacktPublishing/Hands-On-Software-Architecture-with-Cpp/"
```

`homepage`应该指向项目的主页：文档、教程、常见问题解答等内容的所在地。另一方面，`url`是软件包存储库的位置。许多开源库将其代码放在一个存储库中，将打包代码放在另一个存储库中。一个常见情况是软件包由中央 Conan 软件包服务器构建。在这种情况下，`url`应该指向`https://github.com/conan-io/conan-center-index`。

接下来，我们现在可以指定我们的软件包是如何构建的：

```cpp
     settings = "os", "compiler", "build_type", "arch"
     options = {"shared": [True, False], "fPIC": [True, False]}
     default_options = {"shared": False, "fPIC": True}
     generators = "CMakeDeps"
     keep_imports = True  # useful for repackaging, e.g. of licenses
```

`settings`将确定软件包是否需要构建，还是可以下载已构建的版本。

`options`和`default_options`的值可以是任何你喜欢的。`shared`和`fPIC`是大多数软件包提供的两个选项，所以让我们遵循这个约定。

现在我们已经定义了我们的变量，让我们开始编写 Conan 将用于打包我们软件的方法。首先，我们指定我们的库，消费我们软件包的人应该链接到：

```cpp
    def package_info(self):
         self.cpp_info.libs = ["customer"]
```

`self.cpp_info`对象允许设置更多内容，但这是最低限度。请随意查看 Conan 文档中的其他属性。

接下来，让我们指定其他需要的软件包：

```cpp
    def requirements(self):
         self.requires.add('cpprestsdk/2.10.18')
```

这一次，我们直接从 Conan 中获取 C++ REST SDK，而不是指定 OS 的软件包管理器应该依赖哪些软件包。现在，让我们指定 CMake 应该如何（以及在哪里）生成我们的构建系统：

```cpp
    def _configure_cmake(self):
         cmake = CMake(self)
         cmake.configure(source_folder="@CMAKE_SOURCE_DIR@")
         return cmake
```

在我们的情况下，我们只需将其指向源目录。一旦配置了构建系统，我们将需要实际构建我们的项目：

```cpp
    def build(self):
         cmake = self._configure_cmake()
         cmake.build()
```

Conan 还支持非基于 CMake 的构建系统。构建我们的软件包之后，就是打包时间，这需要我们提供另一种方法：

```cpp
    def package(self):
         cmake = self._configure_cmake()
         cmake.install()
         self.copy("license*", ignore_case=True, keep_path=True)
```

请注意，我们正在使用相同的`_configure_cmake()`函数来构建和打包我们的项目。除了安装二进制文件之外，我们还指定许可证应该部署的位置。最后，让我们告诉 Conan 在安装我们的软件包时应该复制什么：

```cpp
    def imports(self):
         self.copy("license*", dst="licenses", folder=True, ignore_case=True)

         # Use the following for the cmake_multi generator on Windows and/or Mac OS to copy libs to the right directory.
         # Invoke Conan like so:
         #   conan install . -e CONAN_IMPORT_PATH=Release -g cmake_multi
         dest = os.getenv("CONAN_IMPORT_PATH", "bin")
         self.copy("*.dll", dst=dest, src="img/bin")
         self.copy("*.dylib*", dst=dest, src="img/lib")
```

前面的代码指定了在安装库时解压许可文件、库和可执行文件的位置。

现在我们知道如何构建一个 Conan 软件包，让我们也看看如何测试它是否按预期工作。

## 测试我们的 Conan 软件包

一旦 Conan 构建我们的包，它应该测试它是否被正确构建。为了做到这一点，让我们首先在我们的`conan`目录中创建一个`test_package`子目录。

它还将包含一个`conanfile.py`脚本，但这次是一个更短的脚本。它应该从以下内容开始：

```cpp
import os

from conans import ConanFile, CMake, tools

```

```cpp
class CustomerTestConan(ConanFile):
     settings = "os", "compiler", "build_type", "arch"
     generators = "CMakeDeps"
```

这里没有太多花哨的东西。现在，我们应该提供构建测试包的逻辑：

```cpp
    def build(self):
        cmake = CMake(self)
        # Current dir is "test_package/build/<build_id>" and 
        # CMakeLists.txt is in "test_package"
        cmake.configure()
        cmake.build()
```

我们将在一秒钟内编写我们的`CMakeLists.txt`文件。但首先，让我们写两件事：`imports`方法和`test`方法。`imports`方法可以编写如下：

```cpp
    def imports(self):
        self.copy("*.dll", dst="bin", src="img/bin")
        self.copy("*.dylib*", dst="bin", src="img/lib")
        self.copy('*.so*', dst='bin', src='lib')
```

然后我们有我们的包测试逻辑的核心 - `test`方法：

```cpp
    def test(self):
         if not tools.cross_building(self.settings):
             self.run(".%sexample" % os.sep)
```

我们只希望在为本机架构构建时运行它。否则，我们很可能无法运行已编译的可执行文件。

现在让我们定义我们的`CMakeLists.txt`文件：

```cpp
 cmake_minimum_required(VERSION 3.12)
 project(PackageTest CXX)

 list(APPEND CMAKE_PREFIX_PATH "${CMAKE_BINARY_DIR}")

 find_package(customer CONFIG REQUIRED)

 add_executable(example example.cpp)
 target_link_libraries(example customer::customer)

 # CTest tests can be added here
```

就这么简单。我们链接到所有提供的 Conan 库（在我们的情况下，只有我们的 Customer 库）。

最后，让我们编写我们的`example.cpp`文件，其中包含足够的逻辑来检查包是否成功创建：

```cpp
 #include <customer/customer.h>

 int main() { responder{}.prepare_response("Conan"); }
```

在我们开始运行所有这些之前，我们需要在我们的 CMake 列表的主树中进行一些小的更改。现在让我们看看如何正确从我们的 CMake 文件中导出 Conan 目标。

## 将 Conan 打包代码添加到我们的 CMakeLists

记得我们在*重用优质代码*部分编写的安装逻辑吗？如果您依赖 Conan 进行打包，您可能不需要运行裸的 CMake 导出和安装逻辑。假设您只想在不使用 Conan 时导出和安装，您需要修改您的`CMakeLists`中的*安装*子部分，使其类似于以下内容：

```cpp
if(NOT CONAN_EXPORTED)
   install(
     EXPORT CustomerTargets
     FILE CustomerTargets.cmake
     NAMESPACE domifair::
     DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Customer)

   configure_file(${PROJECT_SOURCE_DIR}/cmake/CustomerConfig.cmake.in
                  CustomerConfig.cmake @ONLY)

   include(CMakePackageConfigHelpers)
   write_basic_package_version_file(
     CustomerConfigVersion.cmake
     VERSION ${PACKAGE_VERSION}
     COMPATIBILITY AnyNewerVersion)

   install(FILES ${CMAKE_CURRENT_BINARY_DIR}/CustomerConfig.cmake
                 ${CMAKE_CURRENT_BINARY_DIR}/CustomerConfigVersion.cmake
           DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Customer)
 endif()

 install(
   FILES ${PROJECT_SOURCE_DIR}/LICENSE
   DESTINATION $<IF:$<BOOL:${CONAN_EXPORTED}>,licenses,${CMAKE_INSTALL_DOCDIR}>)
```

添加 if 语句和生成器表达式是为了获得干净的包，这就是我们需要做的一切。

最后一件事是让我们的生活变得更轻松 - 一个我们可以**构建**以创建 Conan 包的目标。我们可以定义如下：

```cpp
add_custom_target(
   conan
   COMMAND
     ${CMAKE_COMMAND} -E copy_directory ${PROJECT_SOURCE_DIR}/conan/test_package/
     ${CMAKE_CURRENT_BINARY_DIR}/conan/test_package
   COMMAND conan create . customer/testing -s build_type=$<CONFIG>
   WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/conan
   VERBATIM)
```

现在，当我们运行`cmake --build . --target conan`（或者如果我们使用该生成器并且想要一个简短的调用，则为`ninja conan`），CMake 将把我们的`test_package`目录复制到`build`文件夹中，构建我们的 Conan 包，并使用复制的文件进行测试。

全部完成！

这是冰山一角，关于创建 Conan 包的更多信息，请参考 Conan 的文档。您可以在*进一步阅读*部分找到链接。

# 总结

在本章中，您已经学到了很多关于构建和打包代码的知识。您现在能够编写更快构建的模板代码，知道如何选择工具来更快地编译代码（您将在下一章中了解更多关于工具的知识），并知道何时使用前向声明而不是`#include`指令。

除此之外，您现在可以使用现代 CMake 定义构建目标和测试套件，使用查找模块和`FetchContent`管理外部依赖项，以各种格式创建包和安装程序，最重要的是，使用 Conan 安装依赖项并创建自己的构件。

在下一章中，我们将看看如何编写易于测试的代码。持续集成和持续部署只有在有很好的测试覆盖率时才有用。没有全面测试的持续部署将使您更快地向生产中引入新的错误。当我们设计软件架构时，这不是我们的目标。

# 问题

1.  在 CMake 中安装和导出目标有什么区别？

1.  如何使您的模板代码编译更快？

1.  如何在 Conan 中使用多个编译器？

1.  如果您想使用预 C++11 GCC ABI 编译您的 Conan 依赖项，该怎么办？

1.  如何确保在 CMake 中强制使用特定的 C++标准？

1.  如何在 CMake 中构建文档并将其与您的 RPM 包一起发布？

# 进一步阅读

+   GCC 维基上的编译器书籍列表：[`gcc.gnu.org/wiki/ListOfCompilerBooks`](https://gcc.gnu.org/wiki/ListOfCompilerBooks)

+   基于类型的模板元编程并没有消亡，Odin Holmes 在 C++Now 2017 上的演讲：[`www.youtube.com/watch?v=EtU4RDCCsiU`](https://www.youtube.com/watch?v=EtU4RDCCsiU)

+   现代 CMake 在线书籍：[`cliutils.gitlab.io/modern-cmake`](https://cliutils.gitlab.io/modern-cmake)

+   Conan 文档：[`docs.conan.io/en/latest/`](https://docs.conan.io/en/latest/)

+   CMake 关于创建查找脚本的文档：[`cmake.org/cmake/help/v3.17/manual/cmake-developer.7.html?highlight=find#a-sample-find-module`](https://cmake.org/cmake/help/v3.17/manual/cmake-developer.7.html?highlight=find#a-sample-find-module)


# 第三部分：架构质量属性

本节更专注于一起使软件项目成功的高层概念。在可能的情况下，我们还将展示有助于保持我们想要实现的高质量的工具。

本节包括以下章节：

+   第八章，可测试代码编写

+   第九章，持续集成和持续部署

+   第十章，代码和部署中的安全性

+   第十一章，性能


# 第八章：编写可测试的代码

代码测试的能力是任何软件产品最重要的质量。没有适当的测试，重构代码或改进其安全性、可扩展性或性能等其他部分将成本高昂。在本章中，我们将学习如何设计和管理自动化测试，以及在必要时如何正确使用伪造和模拟。

本章将涵盖以下主题：

+   为什么要测试代码？

+   引入测试框架

+   理解模拟和伪造

+   测试驱动的类设计

+   自动化测试以实现持续集成/持续部署

# 技术要求

本章的示例代码可以在[`github.com/PacktPublishing/Software-Architecture-with-Cpp/tree/master/Chapter08`](https://github.com/PacktPublishing/Software-Architecture-with-Cpp/tree/master/Chapter08)找到。

本章示例中将使用的软件如下：

+   GTest 1.10+

+   Catch2 2.10+

+   CppUnit 1.14+

+   Doctest 2.3+

+   Serverspec 2.41+

+   Testinfra 3.2+

+   Goss 0.3+

+   CMake 3.15+

+   Autoconf

+   Automake

+   Libtool

# 为什么要测试代码？

软件工程和软件架构是非常复杂的问题，应对不确定性的自然方式是对潜在风险进行保险。我们一直在做人寿保险、健康保险和汽车保险。然而，当涉及软件开发时，我们往往忘记了所有的安全预防措施，只是希望有一个乐观的结果。

知道事情不仅可能而且*一定*会出错，测试软件的话题仍然是一个有争议的话题，这是令人难以置信的。无论是因为缺乏技能还是缺乏预算，仍然有一些项目甚至缺乏一些最基本的测试。当客户决定更改需求时，简单的更正可能导致无休止的重做和火拼。

由于没有实施适当的测试而节省的时间将在第一次重做时丢失。如果您认为这次重做不会很快发生，那么您很可能是大错特错。在我们现在生活的敏捷环境中，重做是我们日常生活的一部分。我们对世界和客户的了解意味着需求会发生变化，随之而来的是对我们代码的更改。

因此，测试的主要目的是在项目后期保护您宝贵的时间。当您不得不实施各种测试而不是仅专注于功能时，这当然是一个早期的投资，但这是一个您不会后悔的投资。就像保险政策一样，当事情按计划进行时，测试会从您的预算中少扣一点，但当事情变糟时，您将获得丰厚的回报。

## 测试金字塔

在设计或实施软件系统时，您可能会遇到不同类型的测试。每个类别都有稍微不同的目的。它们可以归类如下：

+   单元测试：代码

+   集成测试：设计

+   系统测试：需求

+   验收测试（端到端或 E2E）：客户需求

这种区分是任意的，您可能经常看到金字塔的其他层，如下所示：

+   单元测试

+   服务测试

+   UI 测试（端到端或 E2E）

在这里，单元测试指的是与前面示例中相同的层。服务测试指的是集成测试和系统测试的组合。另一方面，UI 测试指的是验收测试。以下图显示了测试金字塔：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/sw-arch-cpp/img/38151759-9e75-4e63-a745-4364c71a9eaf.png)

图 8.1 - 测试金字塔

值得注意的是，单元测试不仅是最便宜的构建方式，而且执行速度相当快，通常可以并行运行。这意味着它们非常适合作为持续集成的门控机制。不仅如此，它们通常也提供有关系统健康状况的最佳反馈。高级别测试不仅更难正确编写，而且可能不够健壮。这可能导致测试结果闪烁，每隔一段时间就会有一次测试运行失败。如果高级别测试的失败与单元测试级别的任何失败都没有关联，那么问题很可能出在测试本身而不是被测试系统上。

我们不想说高级别测试完全没有用，也不是说您应该只专注于编写单元测试。情况并非如此。金字塔之所以呈现这种形状，是因为应该有由单元测试覆盖的坚实基础。然而，在这个基础上，您还应该以适当的比例拥有所有高级别测试。毕竟，很容易想象出一个系统，其中所有单元测试都通过了，但系统本身对客户没有任何价值。一个极端的例子是一个完全正常工作的后端，没有任何用户界面（无论是图形界面还是 API 形式）。当然，它通过了所有的单元测试，但这并不是借口！

正如您所想象的那样，测试金字塔的相反称为冰锥，这是一种反模式。违反测试金字塔通常会导致脆弱的代码和难以追踪的错误。这使得调试成本更高，也不会在测试开发中节省成本。

## 非功能性测试

我们已经涵盖的是所谓的功能测试。它们的目的是检查被测试系统是否满足功能要求。但除了功能要求之外，还有其他类型的要求我们可能想要控制。其中一些如下：

+   **性能**：您的应用程序可能在功能方面符合要求，但由于性能不佳，对最终用户来说仍然无法使用。我们将在第十一章中更多关注性能改进。

+   **耐久性**：即使您的系统可能表现得非常出色，也并不意味着它能够承受持续的高负载。即使能够承受，它能够承受组件的一些故障吗？当我们接受这样一个观念，即每一款软件都是脆弱的，可能在任何时刻都会出现故障，我们开始设计可以抵御故障的系统。这是艾林生态系统所采纳的概念，但这个概念本身并不局限于该环境。在第十三章中，*设计微服务*，以及第十五章中，*云原生设计*，我们将更多地提到设计具有容错能力的系统以及混沌工程的作用。

+   **安全性**：现在，应该没有必要重复强调安全性的重要性。但由于安全性仍未得到应有的重视，我们将再次强调这一点。与网络连接的每个系统都可能被破解。在开发早期进行安全性测试可以带来与其他类型测试相同的好处：您可以在问题变得过于昂贵之前发现问题。

+   **可用性**：性能不佳可能会阻止最终用户使用您的产品，而可用性不佳可能会阻止他们甚至访问该产品。虽然可用性问题可能是由于性能过载引起的，但也有其他导致可用性丧失的原因。

+   **完整性**：您的客户数据不仅应该受到外部攻击者的保护，还应该免受由于软件故障而导致的任何更改或损失。防止完整性损失的方法包括防止位腐败、快照和备份。通过将当前版本与先前记录的快照进行比较，您可以确保差异仅由采取的操作引起，还是由错误引起。

+   **可用性**：即使产品符合以前提到的所有要求，如果它具有笨拙的界面和不直观的交互，对用户来说仍然可能不尽人意。可用性测试大多是手动执行的。每次 UI 或系统工作流程发生变化时，执行可用性评估非常重要。

## 回归测试

回归测试通常是端到端测试，应该防止您再次犯同样的错误。当您（或您的质量保证团队或客户）在生产系统中发现错误时，仅仅应用热修复并忘记所有这些是不够的。

您需要做的一件事是编写一个回归测试，以防止相同的错误再次进入生产系统。良好的回归测试甚至可以防止相同的错误*类*再次进入生产。毕竟，一旦您知道自己做错了什么，您就可以想象其他搞砸事情的方式。另一件事是执行根本原因分析。

## 根本原因分析

根本原因分析是一个过程，它帮助您发现问题的根本原因，而不仅仅是其表现形式。执行根本原因分析的最常见方法是使用“5 个为什么”的方法，这一方法是由丰田公司所著名的。这种方法包括剥离问题表现的所有表面层，以揭示隐藏在其下的根本原因。您可以通过在每一层询问“为什么”来做到这一点，直到找到您正在寻找的根本原因。

让我们看一个这种方法在实际中的例子。

问题：我们没有收到一些交易的付款：

1.  为什么？系统没有向客户发送适当的电子邮件。

1.  为什么？邮件发送系统不支持客户姓名中的特殊字符。

1.  为什么？邮件发送系统没有得到适当测试。

1.  为什么？由于需要开发新功能，没有时间进行适当的测试。

1.  为什么？我们对功能的时间估计不正确。

在这个例子中，对功能的时间估计问题可能是在生产系统中发现的错误的根本原因。但它也可能是另一个需要剥离的层。该框架为您提供了一个应该在大多数情况下有效的启发式方法，但如果您并不完全确定您得到的是否就是您要找的，您可以继续剥离额外的层，直到找到导致所有麻烦的原因。

鉴于许多错误都是由完全相同且经常可重复的根本原因导致的，找到根本原因是非常有益的，因为您可以在未来*多个不同的层面*上保护自己免受相同错误的影响。这是深度防御原则在软件测试和问题解决中的应用。

## 进一步改进的基础

对代码进行测试可以保护您免受意外错误的影响。但它也开启了不同的可能性。当您的代码由测试用例覆盖时，您就不必担心重构。重构是将完成其工作的代码转换为功能上类似但内部组织更好的代码的过程。您可能会想知道为什么需要更改代码的组织。这样做有几个原因。

首先，你的代码可能已经不再可读，这意味着每次修改都需要太多时间。其次，修复一个你即将修复的错误会导致一些其他功能表现不正确，因为随着时间的推移，代码中积累了太多的变通和特殊情况。这两个原因都可以归结为提高生产力。它们将使维护成本长期更加便宜。

但除了生产力之外，您可能还希望提高性能。这可能意味着运行时性能（应用程序在生产中的行为）或编译时性能（基本上是另一种形式的生产力改进）。

您可以通过用更高效的算法替换当前的次优算法或通过更改正在重构的模块中使用的数据结构来进行运行时性能重构。

编译时性能重构通常包括将代码的部分移动到不同的编译单元，重新组织头文件或减少依赖关系。

无论您的最终目标是什么，重构通常是一项风险很大的工作。您拿到的是大部分正确工作的东西，最终可能会得到一个更好的版本，也可能会得到一个更糟糕的版本。您怎么知道哪种情况是您的？在这里，测试就派上了用场。

如果当前的功能集已经得到充分覆盖，并且您想修复最近发现的错误，您需要做的就是添加另一个在那时会失败的测试用例。当您的整个测试套件再次开始通过时，意味着您的重构工作是成功的。

最坏的情况是，如果您无法在指定的时间范围内满足所有测试用例，您将不得不中止重构过程。如果您想要提高性能，您将进行类似的过程，但是不是针对单元测试（或端到端测试），而是专注于性能测试。

随着自动化工具的崛起，这些工具可以帮助重构（例如 ReSharper C++：[`www.jetbrains.com/resharper-cpp/features/`](https://www.jetbrains.com/resharper-cpp/features/)）和代码维护，您甚至可以将部分编码外包给外部软件服务。像 Renovate（[`renovatebot.com/`](https://renovatebot.com/)）、Dependabot（[`dependabot.com`](https://dependabot.com)）和 Greenkeeper（[`greenkeeper.io/`](https://greenkeeper.io/)）这样的服务可能很快就会支持 C++依赖项。拥有坚实的测试覆盖率将使您能够在依赖项更新期间使用它们，而不用担心破坏应用程序。

由于始终要考虑保持依赖项的安全漏洞最新状态，这样的服务可以显著减轻负担。因此，测试不仅可以保护您免受错误，还可以减少引入新功能所需的工作量。它还可以帮助您改进代码库并保持其稳定和安全！

既然我们了解了测试的必要性，我们想要开始编写我们自己的测试。可以在没有任何外部依赖项的情况下编写测试。但是，我们只想专注于测试逻辑。我们对管理测试结果和报告的细节不感兴趣。因此，我们将选择一个测试框架来为我们处理这项繁琐的工作。在下一节中，我们将介绍一些最受欢迎的测试框架。

# 引入测试框架

至于框架，当前的事实标准是 Google 的 GTest。与其配对的 GMock 一起，它们形成了一套小型工具，使您能够遵循 C++中的最佳测试实践。

GTest/GMock 二人组的其他热门替代方案包括 Catch2、CppUnit 和 Doctest。CppUnit 已经存在很长时间了，但由于缺乏最近的发布，我们不建议将其用于新项目。Catch2 和 Doctest 都支持现代 C++标准-特别是 C++14、C++17 和 C++20。

为了比较这些测试框架，我们将使用相同的代码库来进行测试。基于此，我们将在每个框架中实现测试。

## GTest 示例

这是一个使用 GTest 编写的客户库的示例测试：

```cpp
#include "customer/customer.h"

#include <gtest/gtest.h>

TEST(basic_responses, given_name_when_prepare_responses_then_greets_friendly) {
  auto name = "Bob";
  auto code_and_string = responder{}.prepare_response(name);
  ASSERT_EQ(code_and_string.first, web::http::status_codes::OK);
  ASSERT_EQ(code_and_string.second, web::json::value("Hello, Bob!"));
}
```

大多数在测试期间通常完成的任务已经被抽象化了。我们主要关注提供我们想要测试的操作（`prepare_response`）和期望的行为（两个`ASSERT_EQ`行）。

## Catch2 示例

这是一个使用 Catch2 编写的客户库的示例测试：

```cpp
#include "customer/customer.h"

#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do
                           // this in one cpp file
#include "catch2/catch.hpp"

TEST_CASE("Basic responses",
          "Given Name When Prepare Responses Then Greets Friendly") {
  auto name = "Bob";
  auto code_and_string = responder{}.prepare_response(name);
  REQUIRE(code_and_string.first == web::http::status_codes::OK);
  REQUIRE(code_and_string.second == web::json::value("Hello, Bob!"));
}
```

它看起来与前一个非常相似。一些关键字不同（`TEST`和`TEST_CASE`），并且检查结果的方式略有不同（`REQUIRE(a == b)`而不是`ASSERT_EQ(a,b)`）。无论如何，两者都非常简洁和易读。

## CppUnit 示例

这是一个使用 CppUnit 编写的客户库的示例测试。我们将其拆分为几个片段。

以下代码块准备我们使用 CppUnit 库中的构造：

```cpp
#include <cppunit/BriefTestProgressListener.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/TestCase.h>
#include <cppunit/TestFixture.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TestRunner.h>
#include <cppunit/XmlOutputter.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TextTestRunner.h>

#include "customer/customer.h"

using namespace CppUnit;
using namespace std;
```

接下来，我们必须定义测试类并实现将执行我们的测试用例的方法。之后，我们必须注册类，以便我们可以在我们的测试运行器中使用它：

```cpp
class TestBasicResponses : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(TestBasicResponses);
  CPPUNIT_TEST(testBob);
  CPPUNIT_TEST_SUITE_END();

 protected:
  void testBob();
};

void TestBasicResponses::testBob() {
  auto name = "Bob";
  auto code_and_string = responder{}.prepare_response(name);
  CPPUNIT_ASSERT(code_and_string.first == web::http::status_codes::OK);
  CPPUNIT_ASSERT(code_and_string.second == web::json::value("Hello, Bob!"));
}

CPPUNIT_TEST_SUITE_REGISTRATION(TestBasicResponses);
```

最后，我们必须提供我们测试运行器的行为：

```cpp
int main() {
  CPPUNIT_NS::TestResult testresult;

  CPPUNIT_NS::TestResultCollector collectedresults;
  testresult.addListener(&collectedresults);

  CPPUNIT_NS::BriefTestProgressListener progress;
  testresult.addListener(&progress);

  CPPUNIT_NS::TestRunner testrunner;
  testrunner.addTest(CPPUNIT_NS::TestFactoryRegistry::getRegistry().makeTest());
  testrunner.run(testresult);

  CPPUNIT_NS::CompilerOutputter compileroutputter(&collectedresults, std::cerr);
  compileroutputter.write();

  ofstream xmlFileOut("cppTestBasicResponsesResults.xml");
  XmlOutputter xmlOut(&collectedresults, xmlFileOut);
  xmlOut.write();

  return collectedresults.wasSuccessful() ? 0 : 1;
}
```

与前两个示例相比，这里有很多样板代码。然而，测试本身看起来与前一个示例非常相似。

## Doctest 示例

这是一个使用 Doctest 编写的客户库的示例测试：

```cpp
#include "customer/customer.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

TEST_CASE("Basic responses") {
  auto name = "Bob";
  auto code_and_string = responder{}.prepare_response(name);
  REQUIRE(code_and_string.first == web::http::status_codes::OK);
  REQUIRE(code_and_string.second == web::json::value("Hello, Bob!"));
}
```

再次，它非常干净且易于理解。Doctest 的主要卖点是，与其他类似功能的替代品相比，它在编译时和运行时都是最快的。

## 测试编译时代码

模板元编程允许我们编写在编译时执行的 C++代码，而不是通常的执行时间。在 C++11 中添加的`constexpr`关键字允许我们使用更多的编译时代码，而 C++20 中的`consteval`关键字旨在让我们更好地控制代码的评估方式。

编译时编程的问题之一是没有简单的方法来测试它。虽然执行时间代码的单元测试框架很丰富（正如我们刚才看到的），但关于编译时编程的资源并不那么丰富。部分原因可能是编译时编程仍然被认为是复杂的，只针对专家。

仅仅因为某些事情不容易并不意味着它是不可能的。就像执行时间测试依赖于运行时检查断言一样，您可以使用`static_assert`来检查您的编译时代码的正确行为，这是在 C++11 中与`constexpr`一起引入的。

以下是使用`static_assert`的一个简单示例：

```cpp
#include <string_view>

constexpr int generate_lucky_number(std::string_view name) {
  if (name == "Bob") {
    number = number * 7 + static_cast<int>(letter);
  }
  return number;
}

static_assert(generate_lucky_number("Bob") == 808);
```

由于我们可以在编译时计算这里测试的每个值，我们可以有效地使用编译器作为我们的测试框架。

# 理解模拟对象和伪造对象

只要您测试的函数与外部世界的交互不太多，事情就会变得相当容易。当您测试的单元与数据库、HTTP 连接和特定文件等第三方组件进行接口时，问题就开始了。

一方面，您希望看到您的代码在各种情况下的行为。另一方面，您不希望等待数据库启动，而且您绝对不希望有几个包含不同数据版本的数据库，以便您可以检查所有必要的条件。

我们如何处理这种情况？这个想法不是执行触发所有这些副作用的实际代码，而是使用测试替身。测试替身是代码中模仿实际 API 的构造，除了它们不执行模仿函数或对象的操作。

最常见的测试替身是模拟对象、伪造对象和存根。许多人往往会将它们误认为是相同的，尽管它们并不相同。

## 不同的测试替身

模拟是注册所有接收到的调用但不做其他任何事情的测试替身。它们不返回任何值，也不以任何方式改变状态。当我们有一个应该调用我们代码的第三方框架时，使用模拟是有用的。通过使用模拟，我们可以观察所有调用，因此能够验证框架的行为是否符合预期。

当涉及到存根的实现时，它们会更加复杂。它们返回值，但这些值是预定义的。也许令人惊讶的是，`StubRandom.randomInteger()`方法总是返回相同的值（例如`3`），但当我们测试返回值的类型或者它是否返回值时，这可能是一个足够的存根实现。确切的值可能并不那么重要。

最后，伪装是具有工作实现并且行为大部分像实际生产实现的对象。主要区别在于伪装可能采取各种捷径，比如避免调用生产数据库或文件系统。

在实现**命令查询分离**（**CQS**）设计模式时，通常会使用存根来替代查询，使用模拟来替代命令。

## 测试替身的其他用途

伪装也可以在测试之外的有限范围内使用。在内存中处理数据而不依赖数据库访问也可以用于原型设计或者当您遇到性能瓶颈时。

## 编写测试替身

编写测试替身时，我们通常会使用外部库，就像我们在单元测试中所做的那样。一些最受欢迎的解决方案如下：

+   GoogleMock（也称为 gMock），现在是 GoogleTest 库的一部分：[`github.com/google/googletest`](https://github.com/google/googletest)。

+   Trompeloeil 专注于 C++14，与许多测试库（如 Catch2、doctest 和 GTest）集成得很好：[`github.com/rollbear/trompeloeil`](https://github.com/rollbear/trompeloeil)。

以下部分的代码将向您展示如何同时使用 GoogleMock 和 Trompeloeil。

### GoogleMock 示例

由于 GoogleMock 是 GoogleTest 的一部分，我们将它们一起介绍：

```cpp
#include "merchants/reviews.h"

#include <gmock/gmock.h>

#include <merchants/visited_merchant_history.h>

#include "fake_customer_review_store.h"

namespace {

class mock_visited_merchant : public i_visited_merchant {
 public:
  explicit mock_visited_merchant(fake_customer_review_store &store,
                                 merchant_id_t id)
      : review_store_{store},
        review_{store.get_review_for_merchant(id).value()} {
    ON_CALL(*this, post_rating).WillByDefault(this {
      review_.rating = s;
      review_store_.post_review(review_);
    });
    ON_CALL(*this, get_rating).WillByDefault([this] { return review_.rating; });
  }

  MOCK_METHOD(stars, get_rating, (), (override));
  MOCK_METHOD(void, post_rating, (stars s), (override));

 private:
  fake_customer_review_store &review_store_;
  review review_;
};

} // namespace

class history_with_one_rated_merchant : public ::testing::Test {
 public:
  static constexpr std::size_t CUSTOMER_ID = 7777;
  static constexpr std::size_t MERCHANT_ID = 1234;
  static constexpr const char *REVIEW_TEXT = "Very nice!";
  static constexpr stars RATING = stars{5.f};

 protected:
  void SetUp() final {
    fake_review_store_.post_review(
        {CUSTOMER_ID, MERCHANT_ID, REVIEW_TEXT, RATING});

    // nice mock will not warn on "uninteresting" call to get_rating
    auto mocked_merchant =
        std::make_unique<::testing::NiceMock<mock_visited_merchant>>(
            fake_review_store_, MERCHANT_ID);

    merchant_index_ = history_.add(std::move(mocked_merchant));
  }

  fake_customer_review_store fake_review_store_{CUSTOMER_ID};
  history_of_visited_merchants history_{};
  std::size_t merchant_index_{};
};

TEST_F(history_with_one_rated_merchant,
       when_user_changes_rating_then_the_review_is_updated_in_store) {
  const auto &mocked_merchant = dynamic_cast<const mock_visited_merchant &>(
      history_.get_merchant(merchant_index_));
  EXPECT_CALL(mocked_merchant, post_rating);

  constexpr auto new_rating = stars{4};
  static_assert(RATING != new_rating);
  history_.rate(merchant_index_, stars{new_rating});
}

TEST_F(history_with_one_rated_merchant,
       when_user_selects_same_rating_then_the_review_is_not_updated_in_store) {
  const auto &mocked_merchant = dynamic_cast<const mock_visited_merchant &>(
      history_.get_merchant(merchant_index_));
  EXPECT_CALL(mocked_merchant, post_rating).Times(0);

  history_.rate(merchant_index_, stars{RATING});
}
```

在撰写本书时，GTest 是最受欢迎的 C++测试框架。它与 GMock 的集成意味着 GMock 可能已经在您的项目中可用。如果您已经在使用 GTest，这种组合使用起来直观且功能齐全，因此没有理由寻找其他替代方案。

### Trompeloeil 示例

与前一个示例相比，这次我们使用 Trompeloeil 作为测试替身，Catch2 作为测试框架：

```cpp
#include "merchants/reviews.h"

#include "fake_customer_review_store.h"

// order is important
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include <catch2/trompeloeil.hpp>

#include <memory>

#include <merchants/visited_merchant_history.h>

using trompeloeil::_;

class mock_visited_merchant : public i_visited_merchant {
 public:
  MAKE_MOCK0(get_rating, stars(), override);
  MAKE_MOCK1(post_rating, void(stars s), override);
};

SCENARIO("merchant history keeps store up to date", "[mobile app]") {
  GIVEN("a history with one rated merchant") {
    static constexpr std::size_t CUSTOMER_ID = 7777;
    static constexpr std::size_t MERCHANT_ID = 1234;
    static constexpr const char *REVIEW_TEXT = "Very nice!";
    static constexpr stars RATING = stars{5.f};

    auto fake_review_store_ = fake_customer_review_store{CUSTOMER_ID};
    fake_review_store_.post_review(
        {CUSTOMER_ID, MERCHANT_ID, REVIEW_TEXT, RATING});

    auto history_ = history_of_visited_merchants{};
    const auto merchant_index_ =
        history_.add(std::make_unique<mock_visited_merchant>());

    auto &mocked_merchant = const_cast<mock_visited_merchant &>(
        dynamic_cast<const mock_visited_merchant &>(
            history_.get_merchant(merchant_index_)));

    auto review_ = review{CUSTOMER_ID, MERCHANT_ID, REVIEW_TEXT, RATING};
    ALLOW_CALL(mocked_merchant, post_rating(_))
        .LR_SIDE_EFFECT(review_.rating = _1;
                        fake_review_store_.post_review(review_););
    ALLOW_CALL(mocked_merchant, get_rating()).LR_RETURN(review_.rating);

    WHEN("a user changes rating") {
      constexpr auto new_rating = stars{4};
      static_assert(RATING != new_rating);

      THEN("the review is updated in store") {
        REQUIRE_CALL(mocked_merchant, post_rating(_));
        history_.rate(merchant_index_, stars{new_rating});
      }
    }

    WHEN("a user selects same rating") {
      THEN("the review is not updated in store") {
        FORBID_CALL(mocked_merchant, post_rating(_));
        history_.rate(merchant_index_, stars{RATING});
      }
    }
  }
}
```

Catch2 的一个很棒的特性是它可以轻松编写行为驱动开发风格的测试，就像这里展示的一样。如果您喜欢这种风格，那么 Catch2 与 Trompeloeil 将是一个很好的选择，因为它们集成得非常好。

# 测试驱动的类设计

区分不同类型的测试并学习特定的测试框架（或多个框架）是不够的。当您开始测试实际代码时，很快就会注意到并非所有类都能轻松测试。有时，您可能需要访问私有属性或方法。如果您想保持良好架构原则，请抵制这种冲动！相反，考虑测试通过类型的公共 API 可用的业务需求，或者重构类型，以便有另一个可以测试的代码单元。

## 当测试和类设计发生冲突时

您可能面临的问题并不是测试框架不足够。通常，您遇到的问题是类设计不当。即使您的类可能行为正确并且看起来正确，除非它们允许测试，否则它们并没有正确设计。

然而，这是个好消息。这意味着你可以在问题变得不方便之前修复它。当你开始基于它构建类层次结构时，类设计可能会在以后困扰你。在测试实现过程中修复设计将简单地减少可能的技术债务。

## 防御性编程

与其名字可能暗示的不同，防御性编程并不是一个安全功能。它的名字来自于保护你的类和函数不被用于与它们最初意图相反的方式。它与测试没有直接关系，但是它是一个很好的设计模式，因为它提高了你代码的质量，使你的项目具有未来的可靠性。

防御性编程始于静态类型。如果你创建一个处理自定义定义类型的函数作为参数，你必须确保没有人会用一些意外的值来调用它。用户将不得不有意识地检查函数的期望并相应地准备输入。

在 C++中，当我们编写模板代码时，我们也可以利用类型安全特性。当我们为我们客户的评论创建一个容器时，我们可以接受任何类型的列表并从中复制。为了得到更好的错误和精心设计的检查，我们可以编写以下内容：

```cpp
class CustomerReviewStore : public i_customer_review_store {
 public:
  CustomerReviewStore() = default;
  explicit CustomerReviewStore(const std::ranges::range auto &initial_reviews) {
    static_assert(is_range_of_reviews_v<decltype(initial_reviews)>,
                  "Must pass in a collection of reviews");
    std::ranges::copy(begin(initial_reviews), end(initial_reviews),
                      begin(reviews_));
  }
 // ...
 private:
  std::vector<review> reviews_;
};
```

`explicit`关键字保护我们免受不必要的隐式转换。通过指定我们的输入参数满足`range`概念，我们确保只会与有效的容器一起编译。通过使用概念，我们可以从我们对无效使用的防御中获得更清晰的错误消息。在我们的代码中使用`static_assert`也是一个很好的防御措施，因为它允许我们在需要时提供一个好的错误消息。我们的`is_range_of_reviews`检查可以实现如下：

```cpp
template <typename T>
constexpr bool is_range_of_reviews_v =
    std::is_same_v<std::ranges::range_value_t<T>, review>;
```

这样，我们确保得到的范围实际上包含我们想要的类型的评论。

静态类型不会阻止无效的运行时值被传递给函数。这就是防御性编程的下一个形式，检查前置条件。这样，你的代码将在问题的第一个迹象出现时失败，这总是比返回一个无效值传播到系统的其他部分要好。在 C++中，直到我们有合同，我们可以使用我们在前几章中提到的 GSL 库来检查我们代码的前置条件和后置条件：

```cpp
void post_review(review review) final {
  Expects(review.merchant);
  Expects(review.customer);
  Ensures(!reviews_.empty());

  reviews_.push_back(std::move(review));
}
```

在这里，通过使用`Expects`宏，我们检查我们传入的评论实际上是否设置了商家和评论者的 ID。除了它不设置的情况，我们还在使用`Ensures`后置条件宏时防范了将评论添加到我们的存储失败的情况。

当涉及到运行时检查时，首先想到的是检查一个或多个属性是否不是`nullptr`。防范自己免受这个问题的最佳方法是区分可空资源（可以取`nullptr`作为值的资源）和不可空资源。有一个很好的工具可以用于这个问题，并且在 C++17 的标准库中可用：`std::optional`。如果可以的话，在你设计的所有 API 中都要使用它。

## 无聊的重复——先写你的测试

这已经说了很多次，但很多人倾向于“忘记”这个规则。当你实际编写你的测试时，你必须做的第一件事是减少创建难以测试的类的风险。你从 API 的使用开始，需要调整实现以最好地服务 API。这样，你通常会得到更愉快使用和更容易测试的 API。当你实施**测试驱动开发**（**TDD**）或在编写代码之前编写测试时，你也会实施依赖注入，这意味着你的类可以更松散地耦合。

反过来做（先编写你的类，然后再为它们添加单元测试）可能意味着你会得到更容易编写但更难测试的代码。当测试变得更难时，你可能会感到诱惑跳过它。

# 自动化持续集成/持续部署的测试

在下一章中，我们将专注于持续集成和持续部署（CI/CD）。要使 CI/CD 流水线正常工作，您需要一组测试来捕捉错误，以防它们进入生产环境。要确保所有业务需求都被适当地表达为测试，这取决于您和您的团队。

测试在几个层面上都很有用。在行为驱动开发中，我们在前一节中提到，业务需求是自动化测试的基础。但是您正在构建的系统不仅仅由业务需求组成。您希望确保所有第三方集成都按预期工作。您希望确保所有子组件（如微服务）实际上可以相互接口。最后，您希望确保您构建的函数和类没有您可以想象到的任何错误。

您可以自动化的每个测试都是 CI/CD 流水线的候选项。它们每一个也都在这个流水线的某个地方有其位置。例如，端到端测试在部署后作为验收测试是最有意义的。另一方面，单元测试在编译后直接执行时是最有意义的。毕竟，我们的目标是一旦发现与规范可能有任何分歧，就尽快中断电路。

每次运行 CI/CD 流水线时，您不必运行所有自动化的测试。最好是每个流水线的运行时间相对较短。理想情况下，应该在提交后的几分钟内完成。如果我们希望保持运行时间最短，那么如何确保一切都经过了适当的测试呢？

一个答案是为不同目的准备不同套件的测试。例如，您可以为提交到功能分支的最小测试。由于每天有许多提交到功能分支，这意味着它们只会被简要测试，并且答案将很快可用。然后，将功能分支合并到共享开发分支需要稍大一些的测试用例集。这样，我们可以确保我们没有破坏其他团队成员将使用的任何内容。最后，对于合并到生产分支的测试将运行更广泛的用例。毕竟，我们希望对生产分支进行彻底测试，即使测试需要很长时间。

另一个答案是为 CI/CD 目的使用精简的测试用例集，并进行额外的持续测试过程。此过程定期运行，并对特定环境的当前状态进行深入检查。测试可以进行到安全测试和性能测试，因此可能评估环境是否有资格进行推广。

当我们选择一个环境并确认该环境具备成为更成熟环境的所有特质时，就会发生推广。例如，开发环境可以成为下一个暂存环境，或者暂存环境可以成为下一个生产环境。如果此推广是自动进行的，还有一个好的做法是在新推广的环境不再通过测试（例如域名或流量方面的微小差异）时提供自动回滚。

这也提出了另一个重要的做法：始终在生产环境上运行测试。当然，这些测试必须是最不具侵入性的，但它们应该告诉您系统在任何给定时间都在正确执行。

## 测试基础设施

如果您希望将配置管理、基础设施即代码或不可变部署的概念纳入应用程序的软件架构中，您还应该考虑测试基础设施本身。有几种工具可以用来做到这一点，包括 Serverspec、Testinfra、Goss 和 Terratest，它们是一些比较流行的工具之一。

这些工具在范围上略有不同，如下所述：

+   Serverspec 和 Testinfra 更专注于测试通过配置管理（如 Salt、Ansible、Puppet 和 Chef）配置的服务器的实际状态。它们分别用 Ruby 和 Python 编写，并插入到这些语言的测试引擎中。这意味着 Serverspec 使用 RSPec，而 Testinfra 使用 Pytest。

+   Goss 在范围和形式上都有些不同。除了测试服务器，您还可以使用 Goss 通过 dgoss 包装器来测试项目中使用的容器。至于其形式，它不使用您在 Serverspec 或 Testinfra 中看到的命令式代码。与 Ansible 或 Salt 类似，它使用 YAML 文件来描述我们要检查的期望状态。如果您已经使用声明性的配置管理方法（如前面提到的 Ansible 或 Salt），Goss 可能更直观，因此更适合测试。

+   最后，Terratest 是一种工具，允许您测试基础设施即代码工具（如 Packer 和 Terraform）的输出（因此得名）。就像 Serverspec 和 Testinfra 使用它们的语言测试引擎为服务器编写测试一样，Terratest 利用 Go 的测试包来编写适当的测试用例。

让我们看看如何使用这些工具来验证部署是否按计划进行（至少从基础设施的角度来看）。

## 使用 Serverspec 进行测试

以下是一个检查特定版本中 Git 的可用性和 Let's Encrypt 配置文件的 Serverspec 测试的示例：

```cpp
# We want to have git 1:2.1.4 installed if we're running Debian
describe package('git'), :if => os[:family] == 'debian' do

  it { should be_installed.with_version('1:2.1.4') }

end
# We want the file /etc/letsencrypt/config/example.com.conf to:

describe file('/etc/letsencrypt/config/example.com.conf') do

  it { should be_file } # be a regular file

  it { should be_owned_by 'letsencrypt' } # owned by the letsencrypt user

  it { should be_mode 600 } # access mode 0600

  it { should contain('example.com') } # contain the text example.com 
                                       # in the content
end
```

Ruby 的 DSL 语法应该即使对于不经常使用 Ruby 的人来说也是可读的。您可能需要习惯编写代码。

## 使用 Testinfra 进行测试

以下是一个检查特定版本中 Git 的可用性和 Let's Encrypt 配置文件的 Testinfra 测试的示例：

```cpp
# We want Git installed on our host
def test_git_is_installed(host):
    git = host.package("git")
    # we test if the package is installed
    assert git.is_installed
    # and if it matches version 1:2.1.4 (using Debian versioning)
    assert git.version.startswith("1:2.1.4")
# We want the file /etc/letsencrypt/config/example.com.conf to:
def test_letsencrypt_file(host):
    le = host.file("/etc/letsencrypt/config/example.com.conf")
    assert le.user == "letsencrypt" # be owned by the letsencrypt user
    assert le.mode == 0o600 # access mode 0600
    assert le.contains("example.com") # contain the text example.com in the contents
```

Testinfra 使用纯 Python 语法。它应该是可读的，但就像 Serverspec 一样，您可能需要一些训练来自信地编写测试。

## 使用 Goss 进行测试

以下是一个检查特定版本中 Git 的可用性和 Let's Encrypt 配置文件的 Goss YAML 文件的示例：

```cpp
# We want Git installed on our host
package:
  git:
    installed: true # we test if the package is installed
  versions:
  - 1:2.1.4 # and if it matches version 1:2.1.4 (using Debian versioning)
file:
  # We want the file /etc/letsencrypt/config/example.com.conf to:
  /etc/letsencrypt/config/example.com.conf:
    exists: true
  filetype: file # be a regular file
  owner: letsencrypt # be owned by the letsencrypt user
  mode: "0600" # access mode 0600
  contains:
  - "example.com" # contain the text example.com in the contents
```

YAML 的语法可能需要最少的准备来阅读和编写。但是，如果您的项目已经使用 Ruby 或 Python，当涉及编写更复杂的测试时，您可能希望坚持使用 Serverspec 或 Testinfra。

# 总结

本章既关注软件不同部分的架构和技术方面的测试。我们查看了测试金字塔，以了解不同类型的测试如何对软件项目的整体健康和稳定性做出贡献。由于测试既可以是功能性的，也可以是非功能性的，我们看到了这两种类型的一些示例。

从本章中最重要的事情之一是要记住测试不是最终阶段。我们希望进行测试不是因为它们带来了即时价值，而是因为我们可以使用它们来检查已知的回归、重构或更改系统现有部分的行为时。当我们想要进行根本原因分析时，测试也可以证明有用，因为它们可以快速验证不同的假设。

在建立了理论要求之后，我们展示了可以用来编写测试替身的不同测试框架和库的示例。尽管先编写测试，后实现它们需要一些实践，但它有一个重要的好处。这个好处就是更好的类设计。

最后，为了突出现代架构不仅仅是软件代码，我们还看了一些用于测试基础设施和部署的工具。在下一章中，我们将看到持续集成和持续部署如何为您设计的应用程序带来更好的服务质量和稳健性。

# 问题

1.  测试金字塔的基础层是什么？

1.  非功能性测试有哪些类型？

1.  著名的根本原因分析方法的名称是什么？

1.  在 C++中是否可能测试编译时代码？

1.  在编写具有外部依赖的代码的单元测试时应该使用什么？

1.  单元测试在持续集成/持续部署中的作用是什么？

1.  有哪些工具可以让您测试基础架构代码？

1.  在单元测试中访问类的私有属性和方法是一个好主意吗？

# 进一步阅读

测试 C++代码：[`www.packtpub.com/application-development/modern-c-programming-cookbook`](https://www.packtpub.com/application-development/modern-c-programming-cookbook)

测试替身：[`martinfowler.com/articles/mocksArentStubs.html`](https://martinfowler.com/articles/mocksArentStubs.html)

持续集成/持续部署：[`www.packtpub.com/virtualization-and-cloud/hands-continuous-integration-and-delivery`](https://www.packtpub.com/virtualization-and-cloud/hands-continuous-integration-and-delivery) 和 [`www.packtpub.com/virtualization-and-cloud/cloud-native-continuous-integration-and-delivery`](https://www.packtpub.com/virtualization-and-cloud/cloud-native-continuous-integration-and-delivery)


# 第九章：持续集成和持续部署

在之前的一章中，我们学习了关于不同构建系统和不同打包系统的知识，我们的应用程序可以使用。持续集成（CI）和持续部署（CD）允许我们利用构建和打包的知识来提高服务质量和我们正在开发的应用程序的健壮性。

CI 和 CD 都依赖于良好的测试覆盖率。CI 主要使用单元测试和集成测试，而 CD 更依赖于冒烟测试和端到端测试。您在《第八章》《编写可测试的代码》中了解了测试的不同方面。有了这些知识，您就可以构建 CI/CD 流水线了。

在本章中，我们将涵盖以下主题：

+   理解 CI

+   审查代码更改

+   探索测试驱动的自动化

+   将部署管理为代码

+   构建部署代码

+   构建 CD 流水线

+   使用不可变基础设施

# 技术要求

本章的示例代码可以在[`github.com/PacktPublishing/Software-Architecture-with-Cpp/tree/master/Chapter09`](https://github.com/PacktPublishing/Software-Architecture-with-Cpp/tree/master/Chapter09)找到。

要理解本章中解释的概念，您需要进行以下安装：

+   免费的 GitLab 账户

+   Ansible 版本 2.8+

+   Terraform 版本 0.12+

+   Packer 版本 1.4+

# 理解 CI

CI 是缩短集成周期的过程。在传统软件中，许多不同的功能可能是分开开发的，只有在发布之前才进行集成，而在 CI 项目中，集成可以每天发生多次。通常，开发人员进行的每个更改都会在提交到中央代码库时进行测试和集成。

由于测试发生在开发之后，反馈循环要快得多。这使得开发人员更容易修复错误（因为他们通常还记得做了什么改动）。与传统的在发布之前进行测试的方法相比，CI 节省了大量工作，并提高了软件的质量。

## 尽早发布，经常发布

您是否听说过“尽早发布，经常发布”的说法？这是一种强调短周期发布的软件开发理念。而短周期的发布循环则在规划、开发和验证之间提供了更短的反馈循环。当出现问题时，应该尽早出现，以便修复问题的成本相对较小。

这一理念是由埃里克·S·雷蒙德（也被称为 ESR）在他 1997 年的文章《大教堂与集市》中推广的。还有一本同名的书，其中包含了作者的这篇文章和其他文章。考虑到 ESR 在开源运动中的活动，"尽早发布，经常发布"的口号成为了开源项目运作方式的代名词。

几年后，同样的原则不仅仅适用于开源项目。随着对敏捷方法学（如 Scrum）日益增长的兴趣，“尽早发布，经常发布”的口号成为了以产品增量结束的开发冲刺的代名词。当然，这个增量是软件发布，但通常在冲刺期间会有许多其他发布。

如何实现这样的短周期发布循环？一个答案是尽可能依赖自动化。理想情况下，代码库的每次提交都应该以发布结束。这个发布是否面向客户是另一回事。重要的是，每次代码变更都可能导致可用的产品。

当然，为每个提交构建和发布到公共环境对于任何开发人员来说都是一项繁琐的工作。即使一切都是脚本化的，这也会给通常的琐事增加不必要的开销。这就是为什么您希望设置一个 CI 系统来自动化您和您的开发团队的发布。

## CI 的优点

CI 是将几个开发人员的工作至少每天集成在一起的概念。正如已经讨论过的，有时它可能意味着每天几次。进入存储库的每个提交都是单独集成和验证的。构建系统检查代码是否可以无错误地构建。打包系统可以创建一个准备保存为工件的软件包，甚至在使用 CD 时稍后部署。最后，自动化测试检查是否与更改相关的已知回归没有发生。现在让我们详细看看它的优点：

+   CI 允许快速解决问题。如果其中一个开发人员在行末忘记了一个分号，CI 系统上的编译器将立即捕捉到这个错误，这样错误的代码就不会传播给其他开发人员，从而阻碍他们的工作。当然，开发人员在提交代码之前应该构建更改并对其进行测试，但是在开发人员的机器上可能会忽略一些小错误，并且这些错误可能会进入共享存储库。

+   使用 CI 的另一个好处是，它可以防止常见的“在我的机器上可以运行”的借口。如果开发人员忘记提交必要的文件，CI 系统将无法构建更改，再次阻止它们进一步传播并对整个团队造成麻烦。一个开发人员环境的特殊配置也不再是问题。如果一个更改在两台机器上构建，即开发人员的计算机和 CI 系统，我们可以安全地假设它也应该在其他机器上构建。

## 门控机制

如果我们希望 CI 能够为我们带来价值，而不仅仅是为我们构建软件包，我们需要一个门控机制。这个门控机制将允许我们区分好的代码更改和坏的代码更改，从而使我们的应用程序免受使其无用的修改。为了实现这一点，我们需要一个全面的测试套件。这样的套件使我们能够自动识别何时更改有问题，并且我们能够迅速做到这一点。

对于单个组件，单元测试起到了门控机制的作用。CI 系统可以丢弃任何未通过单元测试的更改，或者任何未达到一定代码覆盖率阈值的更改。在构建单个组件时，CI 系统还可以使用集成测试来进一步确保更改是稳定的，不仅仅是它们自己，而且它们在一起的表现也是正常的。

## 使用 GitLab 实施流水线

在本章中，我们将使用流行的开源工具构建一个完整的 CI/CD 流水线，其中包括门控机制、自动部署，并展示基础设施自动化的概念。

第一个这样的工具是 GitLab。您可能听说过它作为一个 Git 托管解决方案，但实际上，它远不止于此。GitLab 有几个版本，即以下版本：

+   一种开源解决方案，您可以在自己的设施上托管

+   提供额外功能的自托管付费版本，超过开源社区版

+   最后，一个**软件即服务**（**SaaS**）托管在[`gitlab.com`](https://gitlab.com)下的托管服务

对于本书的要求，每个版本都具备所有必要的功能。因此，我们将专注于 SaaS 版本，因为这需要最少的准备工作。

尽管[`gitlab.com`](https://gitlab.com)主要针对开源项目，但如果您不想与整个世界分享您的工作，您也可以创建私有项目和存储库。这使我们能够在 GitLab 中创建一个新的私有项目，并用我们已经在第七章中演示的代码填充它，*构建和打包*。

许多现代 CI/CD 工具可以代替 GitLab CI/CD。例如 GitHub Actions、Travis CI、CircleCI 和 Jenkins。我们选择了 GitLab，因为它既可以作为 SaaS 形式使用，也可以在自己的设施上使用，因此应该适应许多不同的用例。

然后，我们将使用之前的构建系统在 GitLab 中创建一个简单的 CI 流水线。这些流水线在 YAML 文件中被描述为一系列步骤和元数据。一个构建所有要求的示例流水线，以及来自第七章的示例项目，*构建和打包*，将如下所示：

```cpp
# We want to cache the conan data and CMake build directory
cache:
  key: all
  paths:
    - .conan
    - build

# We're using conanio/gcc10 as the base image for all the subsequent commands
default:
  image: conanio/gcc10

stages:
  - prerequisites
  - build

before_script:
  - export CONAN_USER_HOME="$CI_PROJECT_DIR"

# Configure conan
prerequisites:
  stage: prerequisites
  script:
    - pip install conan==1.34.1
    - conan profile new default || true
    - conan profile update settings.compiler=gcc default
    - conan profile update settings.compiler.libcxx=libstdc++11 default
    - conan profile update settings.compiler.version=10 default
    - conan profile update settings.arch=x86_64 default
    - conan profile update settings.build_type=Release default
    - conan profile update settings.os=Linux default
    - conan remote add trompeloeil https://api.bintray.com/conan/trompeloeil/trompeloeil || true

# Build the project
build:
  stage: build
  script:
    - sudo apt-get update && sudo apt-get install -y docker.io
    - mkdir -p build
    - cd build
    - conan install ../ch08 --build=missing
    - cmake -DBUILD_TESTING=1 -DCMAKE_BUILD_TYPE=Release ../ch08/customer
    - cmake --build .
```

将上述文件保存为`.gitlab-ci.yml`，放在 Git 存储库的根目录中，将自动在 GitLab 中启用 CI，并在每次提交时运行流水线。

# 审查代码更改

代码审查可以在有 CI 系统和没有 CI 系统的情况下使用。它们的主要目的是对引入代码的每个更改进行双重检查，以确保其正确性，符合应用程序的架构，并遵循项目的指南和最佳实践。

当没有 CI 系统时，通常是审阅者的任务手动测试更改并验证其是否按预期工作。CI 减轻了这一负担，让软件开发人员专注于代码的逻辑结构。

## 自动化的门控机制

自动化测试只是门控机制的一个例子。当它们的质量足够高时，它们可以保证代码按照设计工作。但正确工作的代码和好的代码之间仍然存在差异。从本书到目前为止，您已经了解到，如果代码满足了几个价值观，那么它可以被认为是好的。功能上的正确性只是其中之一。

还有其他工具可以帮助实现代码基准的期望标准。其中一些在前几章中已经涵盖，所以我们不会详细介绍。请记住，在 CI/CD 流水线中使用代码检查器、代码格式化程序和静态分析是一个很好的做法。虽然静态分析可以作为一个门控机制，但你可以将代码检查和格式化应用到进入中央存储库的每个提交，以使其与代码库的其余部分保持一致。附录中会有更多关于代码检查器和格式化程序的内容。

理想情况下，这个机制只需要检查代码是否已经被格式化，因为在将代码推送到存储库之前，开发人员应该完成格式化步骤。当使用 Git 作为版本控制系统时，Git Hooks 机制可以防止在没有运行必要工具的情况下提交代码。

但自动化分析只能帮你解决一部分问题。你可以检查代码是否功能完整，是否没有已知的错误和漏洞，并且是否符合编码标准。这就是手动检查的作用。

## 代码审查-手动门控机制

对代码更改的手动检查通常被称为代码审查。代码审查的目的是识别问题，包括特定子系统的实现以及对应用程序整体架构的遵循。自动化性能测试可能会或可能不会发现给定功能的潜在问题。另一方面，人眼通常可以发现问题的次优解决方案。无论是错误的数据结构还是计算复杂度过高的算法，一个好的架构师应该能够找出问题所在。

但执行代码审查并不仅仅是架构师的角色。同行审查，也就是由作者的同行进行的代码审查，在开发过程中也有其作用。这样的审查之所以有价值，不仅因为它们允许同事发现彼此代码中的错误。更重要的方面是许多队友突然意识到其他人正在做什么。这样，当团队中有人缺席（无论是因为长时间会议、度假还是工作轮换），另一名团队成员可以替补缺席者。即使他们不是该主题的专家，每个成员至少知道有趣的代码位于何处，每个人都应该能够记住代码的最后更改。这意味着它们发生的时间、范围和内容。

随着更多人意识到应用程序内部的情况，他们更有可能发现一个组件最近的变化和一个新发现的错误之间的关联。即使团队中的每个人可能有不同的经验，但当每个人都非常了解代码时，他们可以共享资源。

因此，代码审查可以检查更改是否符合所需的架构，以及其实现是否正确。我们称这样的代码审查为架构审查或专家审查。

另一种类型的代码审查，同行审查，不仅有助于发现错误，还提高了团队对其他成员正在做什么的意识。如果需要，您还可以在处理与外部服务集成的更改时执行不同类型的专家审查。

由于每个接口都是潜在问题的源头，接近接口级别的更改应被视为特别危险。我们建议您将通常的同行审查与来自接口另一侧的专家的审查相结合。例如，如果您正在编写生产者的代码，请向消费者请求审查。这样，您可以确保不会错过一些您可能认为非常不太可能的重要用例，但另一方却经常使用。

## 代码审查的不同方法

您通常会进行异步代码审查。这意味着正在审查的更改的作者和审阅者之间的通信不是实时发生的。相反，每个参与者都可以在任何时间发表他们的评论和建议。一旦没有更多的评论，作者会重新修改原始更改，然后再次进行审查。这可能需要多轮，直到每个人都同意不需要进一步的更正为止。

当一个更改特别有争议并且异步代码审查需要太长时间时，进行同步代码审查是有益的。这意味着举行一次会议（面对面或远程），解决对未来方向的任何相反意见。这将在特定情况下发生，当一个更改与最初的决定之一相矛盾，因为在实施更改时获得了新的知识。

有一些专门针对代码审查的工具。更常见的是，您会希望使用内置到存储库服务器中的工具，其中包括以下服务：

+   GitHub

+   Bitbucket

+   GitLab

+   Gerrit

所有这些都提供 Git 托管和代码审查。其中一些甚至提供整个 CI/CD 流水线、问题管理、wiki 等等。

当您使用代码托管和代码审查的综合包时，默认工作流程是将更改推送为单独的分支，然后要求项目所有者合并更改，这个过程称为拉取请求（或合并请求）。尽管名字很花哨，但拉取请求或合并请求通知项目所有者，您有代码希望与主分支合并。这意味着审阅者应该审查您的更改，以确保一切都井井有条。

## 使用拉取请求（合并请求）进行代码审查

使用 GitLab 等系统创建拉取请求或合并请求非常容易。首先，当我们从命令行推送新分支到中央存储库时，我们可以观察到以下消息：

```cpp
remote:
remote: To create a merge request for fix-ci-cd, visit:
remote:   https://gitlab.com/hosacpp/continuous-integration/merge_requests/new?merge_request%5Bsource_branch%5D=fix-ci-cd
remote:                         
```

如果您之前已启用 CI（通过添加`.gitlab-ci.yml`文件），您还会看到新推送的分支已经经过了 CI 流程。这甚至发生在您打开合并请求之前，这意味着您可以在从 CI 获得每个自动检查都通过的信息之前推迟通知同事。

打开合并请求的两种主要方式如下：

+   通过按照推送消息中提到的链接

+   通过在 GitLab UI 中导航到合并请求并选择“创建合并请求”按钮或“新合并请求”按钮

当您提交合并请求并填写完所有相关字段时，您会看到 CI 流水线的状态也是可见的。如果流水线失败，将无法合并更改。

# 探索测试驱动的自动化

CI 主要侧重于集成部分。这意味着构建不同子系统的代码并确保它们可以一起工作。虽然测试不是严格要求实现此目的，但在没有测试的情况下运行 CI 似乎是一种浪费。没有自动化测试的 CI 使得更容易向代码引入微妙的错误，同时给人一种虚假的安全感。

这就是为什么 CI 经常与持续测试紧密结合的原因之一，我们将在下一节中介绍。

## 行为驱动开发

到目前为止，我们已经设立了一个可以称之为持续构建的流水线。我们对代码所做的每一次更改最终都会被编译，但我们不会进一步测试它。现在是时候引入持续测试的实践了。在低级别进行测试也将作为一个门控机制，自动拒绝所有不满足要求的更改。

您如何检查给定的更改是否满足要求？最好的方法是根据这些要求编写测试。其中一种方法是遵循**行为驱动开发**（**BDD**）。BDD 的概念是鼓励敏捷项目中不同参与者之间更深入的协作。

与传统方法不同，传统方法要么由开发人员编写测试，要么由 QA 团队编写测试，而 BDD 中，测试是由以下个人共同创建的：

+   开发人员

+   QA 工程师

+   业务代表。

指定 BDD 测试的最常见方式是使用 Cucumber 框架，该框架使用简单的英语短语来描述系统的任何部分的期望行为。这些句子遵循特定的模式，然后可以转换为可工作的代码，与所选的测试框架集成。

Cucumber 框架中有对 C++的官方支持，它基于 CMake、Boost、GTest 和 GMock。在以 cucumber 格式指定所需行为（使用称为 Gherkin 的领域特定语言）之后，我们还需要提供所谓的步骤定义。步骤定义是与 cucumber 规范中描述的操作相对应的实际代码。例如，考虑以下以 Gherkin 表达的行为：

```cpp
# language: en
Feature: Summing
In order to see how much we earn,
Sum must be able to add two numbers together

Scenario: Regular numbers
  Given I have entered 3 and 2 as parameters
  When I add them
  Then the result should be 5
```

我们可以将其保存为`sum.feature`文件。为了生成带有测试的有效 C++代码，我们将使用适当的步骤定义：

```cpp
#include <gtest/gtest.h>
#include <cucumber-cpp/autodetect.hpp>

#include <Sum.h>

using cucumber::ScenarioScope;

struct SumCtx {
  Sum sum;
  int a;
  int b;
  int result;
};

GIVEN("^I have entered (\\d+) and (\\d+) as parameters$", (const int a, const int b)) {
    ScenarioScope<SumCtx> context;

    context->a = a;
    context->b = b;
}

WHEN("^I add them") {
    ScenarioScope<SumCtx> context;

    context->result = context->sum.sum(context->a, context->b);
}

THEN("^the result should be (.*)$", (const int expected)) {
    ScenarioScope<SumCtx> context;

    EXPECT_EQ(expected, context->result);
}
```

在从头开始构建应用程序时，遵循 BDD 模式是一个好主意。本书旨在展示您可以在这样的绿地项目中使用的最佳实践。但这并不意味着您不能在现有项目中尝试我们的示例。在项目的生命周期中的任何时间都可以添加 CI 和 CD。由于尽可能经常运行测试总是一个好主意，因此几乎总是一个好主意仅出于持续测试目的使用 CI 系统。

如果你没有行为测试，你不需要担心。你可以稍后添加它们，目前只需专注于你已经有的那些测试。无论是单元测试还是端到端测试，任何有助于评估你的应用程序状态的东西都是一个很好的门控机制的候选者。

## 为 CI 编写测试

对于 CI 来说，最好专注于单元测试和集成测试。它们在可能的最低级别上工作，这意味着它们通常执行速度快，要求最小。理想情况下，所有单元测试应该是自包含的（没有像工作数据库这样的外部依赖）并且能够并行运行。这样，当问题出现在单元测试能够捕捉到的级别时，有问题的代码将在几秒钟内被标记出来。

有些人说单元测试只在解释性语言或动态类型语言中才有意义。论点是 C++已经通过类型系统和编译器检查内置了测试。虽然类型检查可以捕捉一些在动态类型语言中需要单独测试的错误，但这不应该成为不编写单元测试的借口。毕竟，单元测试的目的不是验证代码能够无问题地执行。我们编写单元测试是为了确保我们的代码不仅执行，而且还满足我们所有的业务需求。

作为一个极端的例子，看一下以下两个函数。它们都在语法上是正确的，并且使用了适当的类型。然而，仅仅通过看它们，你可能就能猜出哪一个是正确的，哪一个是错误的。单元测试有助于捕捉这种行为不当：

```cpp
int sum (int a, int b) {
 return a+b;
}
```

前面的函数返回提供的两个参数的总和。下一个函数只返回第一个参数的值：

```cpp
int sum (int a, int b) {
  return a;
}
```

即使类型匹配，编译器不会抱怨，这段代码也不能执行其任务。为了区分有用的代码和错误的代码，我们使用测试和断言。

## 持续测试

已经建立了一个简单的 CI 流水线，非常容易通过测试来扩展它。由于我们已经在构建和测试过程中使用 CMake 和 CTest，我们所需要做的就是在我们的流水线中添加另一个步骤来执行测试。这一步可能看起来像这样：

```cpp
# Run the unit tests with ctest
test:
  stage: test
  script:
    - cd build
    - ctest .
```

因此，整个流水线将如下所示：

```cpp
cache:
  key: all
  paths:
    - .conan
    - build

default:
  image: conanio/gcc9

stages:
  - prerequisites
  - build
 - test # We add another stage that tuns the tests

before_script:
  - export CONAN_USER_HOME="$CI_PROJECT_DIR"

prerequisites:
  stage: prerequisites
  script:
    - pip install conan==1.34.1
    - conan profile new default || true
    - conan profile update settings.compiler=gcc default
    - conan profile update settings.compiler.libcxx=libstdc++11 default
    - conan profile update settings.compiler.version=10 default
    - conan profile update settings.arch=x86_64 default
    - conan profile update settings.build_type=Release default
    - conan profile update settings.os=Linux default
    - conan remote add trompeloeil https://api.bintray.com/conan/trompeloeil/trompeloeil || true

build:
  stage: build
  script:
    - sudo apt-get update && sudo apt-get install -y docker.io
    - mkdir -p build
    - cd build
    - conan install ../ch08 --build=missing
    - cmake -DBUILD_TESTING=1 -DCMAKE_BUILD_TYPE=Release ../ch08/customer
    - cmake --build .

# Run the unit tests with ctest
test:
 stage: test
 script:
 - cd build
 - ctest .
```

这样，每个提交不仅会经历构建过程，还会经历测试。如果其中一个步骤失败，我们将收到通知，知道是哪一个步骤导致了失败，并且可以在仪表板上看到哪些步骤成功了。

# 管理部署作为代码

经过测试和批准的更改，现在是将它们部署到一个操作环境的时候了。

有许多工具可以帮助部署。我们决定提供 Ansible 的示例，因为这不需要在目标机器上进行任何设置，除了一个功能齐全的 Python 安装（大多数 UNIX 系统已经有了）。为什么选择 Ansible？它在配置管理领域非常流行，并且由一个值得信赖的开源公司（红帽）支持。

## 使用 Ansible

为什么不使用已经可用的东西，比如 Bourne shell 脚本或 PowerShell？对于简单的部署，shell 脚本可能是一个更好的方法。但是随着我们的部署过程变得更加复杂，使用 shell 的条件语句来处理每种可能的初始状态就变得更加困难。

处理初始状态之间的差异实际上是 Ansible 特别擅长的。与使用命令式形式（移动这个文件，编辑那个文件，运行特定命令）的传统 shell 脚本不同，Ansible playbook（它们被称为）使用声明式形式（确保文件在这个路径上可用，确保文件包含指定的行，确保程序正在运行，确保程序成功完成）。

这种声明性的方法也有助于实现幂等性。幂等性是函数的一个特性，意味着多次应用该函数将产生与单次应用完全相同的结果。如果 Ansible playbook 的第一次运行引入了对配置的一些更改，每次后续运行都将从所需状态开始。这可以防止 Ansible 执行任何额外的更改。

换句话说，当您调用 Ansible 时，它将首先评估您希望配置的所有机器的当前状态：

+   如果其中任何一个需要进行任何更改，Ansible 将只运行所需的任务以实现所需的状态。

+   如果没有必要修改特定的内容，Ansible 将不会触及它。只有当所需状态和实际状态不同时，您才会看到 Ansible 采取行动将实际状态收敛到 playbook 内容描述的所需状态。

## Ansible 如何与 CI/CD 流水线配合

Ansible 的幂等性使其成为 CI/CD 流水线中的一个很好的目标。毕竟，即使两次运行之间没有任何更改，多次运行相同的 Ansible playbook 也没有风险。如果您将 Ansible 用于部署代码，创建 CD 只是准备适当的验收测试（例如冒烟测试或端到端测试）的问题。

声明性方法可能需要改变您对部署的看法，但收益是非常值得的。除了运行 playbooks，您还可以使用 Ansible 在远程机器上执行一次性命令，但我们不会涵盖这种用例，因为它实际上对部署没有帮助。

您可以使用 Ansible 的`shell`模块执行与 shell 相同的操作。这是因为在 playbooks 中，您编写指定使用哪些模块及其各自参数的任务。其中一个模块就是前面提到的`shell`模块，它只是在远程机器上执行提供的参数。但是，使 Ansible 不仅方便而且跨平台（至少在涉及不同的 UNIX 发行版时）的是可以操作常见概念的模块的可用性，例如用户管理、软件包管理和类似实例。

## 使用组件创建部署代码

除了标准库中提供的常规模块外，还有第三方组件允许代码重用。您可以单独测试这些组件，这也使您的部署代码更加健壮。这些组件称为角色。它们包含一组任务，使机器适合承担特定角色，例如`webserver`、`db`或`docker`。虽然一些角色准备机器提供特定服务，其他角色可能更抽象，例如流行的`ansible-hardening`角色。这是由 OpenStack 团队创建的，它使使用该角色保护的机器更难被入侵。

当您开始理解 Ansible 使用的语言时，所有的 playbooks 都不再只是脚本。反过来，它们将成为部署过程的文档。您可以通过运行 Ansible 直接使用它们，或者您可以阅读描述的任务并手动执行所有操作，例如在离线机器上。

使用 Ansible 进行团队部署的一个风险是，一旦开始使用，您必须确保团队中的每个人都能够使用它并修改相关的任务。DevOps 是整个团队必须遵循的一种实践；它不能只部分实施。当应用程序的代码发生相当大的变化，需要在部署方面进行适当的更改时，负责应用程序更改的人也应提供部署代码的更改。当然，这是您的测试可以验证的内容，因此门控机制可以拒绝不完整的更改。

Ansible 的一个值得注意的方面是它可以在推送和拉取模型中运行：

+   推送模型是当您在自己的机器上或在 CI 系统中运行 Ansible 时。然后，Ansible 连接到目标机器，例如通过 SSH 连接，并在目标机器上执行必要的步骤。

+   在拉模型中，整个过程由目标机器发起。Ansible 的组件`ansible-pull`直接在目标机器上运行，并检查代码存储库以确定特定分支是否有任何更新。刷新本地 playbook 后，Ansible 像往常一样执行所有步骤。这一次，控制组件和实际执行都发生在同一台机器上。大多数情况下，您会希望定期运行`ansible-pull`，例如，从 cron 作业中运行。

# 构建部署代码

在其最简单的形式中，使用 Ansible 进行部署可能包括将单个二进制文件复制到目标机器，然后运行该二进制文件。我们可以使用以下 Ansible 代码来实现这一点：

```cpp
tasks:
  # Each Ansible task is written as a YAML object
  # This uses a copy module
  - name: Copy the binaries to the target machine
    copy:
      src: our_application
      dest: /opt/app/bin/our_application
  # This tasks invokes the shell module. The text after the `shell:` key
  # will run in a shell on target machine
  - name: start our application in detached mode
    shell: cd /opt/app/bin; nohup ./our_application </dev/null >/dev/null 2>&1 &
```

每个任务都以连字符开头。对于每个任务，您需要指定它使用的模块（例如`copy`模块或`shell`模块），以及它的参数（如果适用）。任务还可以有一个`name`参数，这样可以更容易地单独引用任务。

# 构建 CD 管道

我们已经达到了可以安全地使用本章学到的工具构建 CD 管道的地步。我们已经知道 CI 是如何运作的，以及它如何帮助拒绝不适合发布的更改。测试自动化部分介绍了使拒绝过程更加健壮的不同方法。拥有冒烟测试或端到端测试使我们能够超越 CI，并检查整个部署的服务是否满足要求。并且有了部署代码，我们不仅可以自动化部署过程，还可以在我们的测试开始失败时准备回滚。

## 持续部署和持续交付

出于有趣的巧合，CD 的缩写可以有两种不同的含义。持续交付和持续部署的概念非常相似，但它们有一些细微的差异。在整本书中，我们专注于持续部署的概念。这是一个自动化的过程，当一个人将更改推送到中央存储库时开始，并在更改成功部署到生产环境并通过所有测试时结束。因此，我们可以说这是一个端到端的过程，因为开发人员的工作可以在没有手动干预的情况下一直传递到客户那里（当然，要经过代码审查）。您可能听说过 GitOps 这个术语来描述这种方法。由于所有操作都是自动化的，将更改推送到 Git 中的指定分支会触发部署脚本。

持续交付并不会走得那么远。与 CD 一样，它具有能够发布最终产品并对其进行测试的管道，但最终产品永远不会自动交付给客户。它可以首先交付给 QA 或用于内部业务。理想情况下，交付的构件准备好在内部客户接受后立即部署到生产环境中。

## 构建一个示例 CD 管道

让我们再次将所有这些技能结合起来，以 GitLab CI 作为示例来构建我们的管道。在测试步骤之后，我们将添加另外两个步骤，一个用于创建包，另一个用于使用 Ansible 部署此包。

我们打包步骤所需的全部内容如下：

```cpp
# Package the application and publish the artifact
package:
  stage: package
  # Use cpack for packaging
  script:
    - cd build
    - cpack .
  # Save the deb package artifact
  artifacts:
    paths:
      - build/Customer*.deb
```

当我们添加包含构件定义的包步骤时，我们将能够从仪表板下载它们。

有了这个，我们可以将 Ansible 作为部署步骤的一部分来调用：

```cpp
# Deploy using Ansible
deploy:
  stage: deploy
  script:
    - cd build
    - ansible-playbook -i localhost, ansible.yml
```

最终的管道将如下所示：

```cpp
cache:
  key: all
  paths:
    - .conan
    - build

default:
  image: conanio/gcc9

stages:
  - prerequisites
  - build
  - test
 - package
 - deploy

before_script:
  - export CONAN_USER_HOME="$CI_PROJECT_DIR"

prerequisites:
  stage: prerequisites
  script:
    - pip install conan==1.34.1
    - conan profile new default || true
    - conan profile update settings.compiler=gcc default
    - conan profile update settings.compiler.libcxx=libstdc++11 default
    - conan profile update settings.compiler.version=10 default
    - conan profile update settings.arch=x86_64 default
    - conan profile update settings.build_type=Release default
    - conan profile update settings.os=Linux default
    - conan remote add trompeloeil https://api.bintray.com/conan/trompeloeil/trompeloeil || true

build:
  stage: build
  script:
    - sudo apt-get update && sudo apt-get install -y docker.io
    - mkdir -p build
    - cd build
    - conan install ../ch08 --build=missing
    - cmake -DBUILD_TESTING=1 -DCMAKE_BUILD_TYPE=Release ../ch08/customer
    - cmake --build .

test:
  stage: test
  script:
    - cd build
    - ctest .

# Package the application and publish the artifact
package:
 stage: package
 # Use cpack for packaging
 script:
 - cd build
 - cpack .
 # Save the deb package artifact
 artifacts:
 paths:
 - build/Customer*.deb

# Deploy using Ansible
deploy:
 stage: deploy
 script:
 - cd build
 - ansible-playbook -i localhost, ansible.yml
```

要查看整个示例，请转到原始来源的*技术要求*部分的存储库。

# 使用不可变基础设施

如果您对 CI/CD 流水线足够自信，您可以再走一步。您可以部署*系统*的构件，而不是应用程序的构件。有什么区别？我们将在以下部分了解到。

## 什么是不可变基础设施？

以前，我们关注的是如何使应用程序的代码可以部署到目标基础设施上。CI 系统创建软件包（如容器），然后 CD 流程部署这些软件包。每次流水线运行时，基础设施保持不变，但软件不同。

关键是，如果您使用云计算，您可以将基础设施视为任何其他构件。例如，您可以部署整个**虚拟机**（**VM**），作为 AWS EC2 实例的构件，而不是部署容器。您可以预先构建这样的 VM 镜像作为 CI 流程的另一个构件。这样，版本化的 VM 镜像以及部署它们所需的代码成为您的构件，而不是容器本身。

有两个工具，都由 HashiCorp 编写，处理这种情况。Packer 帮助以可重复的方式创建 VM 镜像，将所有指令存储为代码，通常以 JSON 文件的形式。Terraform 是一个基础设施即代码工具，这意味着它用于提供所有必要的基础设施资源。我们将使用 Packer 的输出作为 Terraform 的输入。这样，Terraform 将创建一个包含以下内容的整个系统：

+   实例组

+   负载均衡器

+   VPC

+   其他云元素，同时使用包含我们自己代码的 VM

这一部分的标题可能会让您感到困惑。为什么它被称为**不可变基础设施**，而我们明显是在提倡在每次提交后更改整个基础设施？如果您学过函数式语言，不可变性的概念可能对您更清晰。

可变对象是其状态可以改变的对象。在基础设施中，这很容易理解：您可以登录到虚拟机并下载更近期的代码。状态不再与您干预之前相同。

不可变对象是其状态我们无法改变的对象。这意味着我们无法登录到机器上并更改东西。一旦我们从镜像部署了虚拟机，它就会保持不变，直到我们销毁它。这听起来可能非常麻烦，但实际上，它解决了软件维护的一些问题。

## 不可变基础设施的好处

首先，不可变基础设施使配置漂移的概念过时。没有配置管理，因此也不会有漂移。升级也更安全，因为我们不会陷入一个半成品状态。这是既不是上一个版本也不是下一个版本，而是介于两者之间的状态。部署过程提供了二进制信息：机器要么被创建并运行，要么没有。没有其他方式。

为了使不可变基础设施在不影响正常运行时间的情况下工作，您还需要以下内容：

+   负载均衡

+   一定程度的冗余

毕竟，升级过程包括关闭整个实例。您不能依赖于这台机器的地址或任何特定于该机器的东西。相反，您需要至少有第二个机器来处理工作负载，同时用更近期的版本替换另一个机器。当您完成升级一个机器后，您可以重复相同的过程。这样，您将有两个升级的实例而不会丢失服务。这种策略被称为滚动升级。

从这个过程中，您可以意识到，当处理无状态服务时，不可变基础架构效果最佳。当您的服务具有某种持久性时，正确实施变得更加困难。在这种情况下，通常需要将持久性级别拆分为一个单独的对象，例如，包含所有应用程序数据的 NFS 卷。这些卷可以在实例组中的所有机器之间共享，并且每个新机器上线时都可以访问之前运行应用程序留下的共同状态。

## 使用 Packer 构建实例镜像

考虑到我们的示例应用程序已经是无状态的，我们可以继续在其上构建一个不可变的基础架构。由于 Packer 生成的工件是 VM 镜像，我们必须决定要使用的格式和构建器。

让我们专注于 Amazon Web Services 的示例，同时牢记类似的方法也适用于其他支持的提供者。一个简单的 Packer 模板可能如下所示：

```cpp
{
  "variables": {
    "aws_access_key": "",
    "aws_secret_key": ""
  },
  "builders": [{
    "type": "amazon-ebs",
    "access_key": "{{user `aws_access_key`}}",
    "secret_key": "{{user `aws_secret_key`}}",
    "region": "eu-central-1",
    "source_ami": "ami-0f1026b68319bad6c",
    "instance_type": "t2.micro",
    "ssh_username": "admin",
    "ami_name": "Project's Base Image {{timestamp}}"
  }],
  "provisioners": [{
    "type": "shell",
    "inline": [
      "sudo apt-get update",
      "sudo apt-get install -y nginx"
    ]
  }]
}
```

上述代码将使用 EBS 构建器为 Amazon Web Services 构建一个镜像。该镜像将驻留在`eu-central-1`地区，并将基于`ami-5900cc36`，这是一个 Debian Jessie 镜像。我们希望构建器是一个`t2.micro`实例（这是 AWS 中的 VM 大小）。为了准备我们的镜像，我们运行两个`apt-get`命令。

我们还可以重用先前定义的 Ansible 代码，而不是使用 Packer 来配置我们的应用程序，我们可以将 Ansible 替换为 provisioner。我们的代码将如下所示：

```cpp
{
  "variables": {
    "aws_access_key": "",
    "aws_secret_key": ""
  },
  "builders": [{
    "type": "amazon-ebs",
    "access_key": "{{user `aws_access_key`}}",
    "secret_key": "{{user `aws_secret_key`}}",
    "region": "eu-central-1",
    "source_ami": "ami-0f1026b68319bad6c",
    "instance_type": "t2.micro",
    "ssh_username": "admin",
    "ami_name": "Project's Base Image {{timestamp}}"
  }],
  "provisioners": [{
 "type": "ansible",
 "playbook_file": "./provision.yml",
 "user": "admin",
 "host_alias": "baseimage"
 }],
 "post-processors": [{
 "type": "manifest",
 "output": "manifest.json",
 "strip_path": true
 }]
}
```

更改在`provisioners`块中，还添加了一个新的块`post-processors`。这一次，我们不再使用 shell 命令，而是使用一个运行 Ansible 的不同的 provisioner。后处理器用于以机器可读的格式生成构建结果。一旦 Packer 完成构建所需的工件，它会返回其 ID，并将其保存在`manifest.json`中。对于 AWS 来说，这意味着一个 AMI ID，然后我们可以将其提供给 Terraform。

## 使用 Terraform 编排基础架构

使用 Packer 创建镜像是第一步。之后，我们希望部署该镜像以使用它。我们可以使用 Terraform 基于我们的 Packer 模板中的镜像构建一个 AWS EC2 实例。

示例 Terraform 代码如下所示：

```cpp
# Configure the AWS provider
provider "aws" {
  region = var.region
  version = "~> 2.7"
}

# Input variable pointing to an SSH key we want to associate with the 
# newly created machine
variable "public_key_path" {
  description = <<DESCRIPTION
Path to the SSH public key to be used for authentication.
Ensure this keypair is added to your local SSH agent so provisioners can
connect.
Example: ~/.ssh/terraform.pub
DESCRIPTION

  default = "~/.ssh/id_rsa.pub"
}

# Input variable with a name to attach to the SSH key
variable "aws_key_name" {
  description = "Desired name of AWS key pair"
  default = "terraformer"
}

# An ID from our previous Packer run that points to the custom base image
variable "packer_ami" {
}

variable "env" {
  default = "development"
}

variable "region" {
}

# Create a new AWS key pair cotaining the public key set as the input 
# variable
resource "aws_key_pair" "deployer" {
  key_name = var.aws_key_name

  public_key = file(var.public_key_path)
}

# Create a VM instance from the custom base image that uses the previously created key
# The VM size is t2.xlarge, it uses a persistent storage volume of 60GiB,
# and is tagged for easier filtering
resource "aws_instance" "project" {
  ami = var.packer_ami

  instance_type = "t2.xlarge"

  key_name = aws_key_pair.deployer.key_name

  root_block_device {
    volume_type = "gp2"
    volume_size = 60
  }

  tags = {
    Provider = "terraform"
    Env = var.env
    Name = "main-instance"
  }
}
```

这将创建一个密钥对和一个使用此密钥对的 EC2 实例。EC2 实例基于作为变量提供的 AMI。在调用 Terraform 时，我们将设置此变量指向 Packer 生成的镜像。

# 总结

到目前为止，您应该已经了解到，在项目开始阶段实施 CI 如何帮助您节省长期时间。尤其是与 CD 配对时，它还可以减少工作进展。在本章中，我们介绍了一些有用的工具，可以帮助您实施这两个过程。

我们已经展示了 GitLab CI 如何让我们在 YAML 文件中编写流水线。我们已经讨论了代码审查的重要性，并解释了各种形式的代码审查之间的区别。我们介绍了 Ansible，它有助于配置管理和部署代码的创建。最后，我们尝试了 Packer 和 Terraform，将我们的重点从创建应用程序转移到创建系统。

本章中的知识并不局限于 C++语言。您可以在使用任何技术编写的任何语言的项目中使用它。您应该牢记的重要事情是：所有应用程序都需要测试。编译器或静态分析器不足以验证您的软件。作为架构师，您还必须考虑的不仅是您的项目（应用程序本身），还有产品（您的应用程序将在其中运行的系统）。仅交付可工作的代码已不再足够。了解基础架构和部署过程至关重要，因为它们是现代系统的新构建模块。

下一章将专注于软件的安全性。我们将涵盖源代码本身、操作系统级别以及与外部服务和最终用户的可能交互。

# 问题

1.  CI 在开发过程中如何节省时间？

1.  您是否需要单独的工具来实施 CI 和 CD？

1.  在会议中进行代码审查有何意义？

1.  在 CI 期间，您可以使用哪些工具来评估代码的质量？

1.  谁参与指定 BDD 场景？

1.  在什么情况下会考虑使用不可变基础设施？在什么情况下会排除它？

1.  您如何描述 Ansible、Packer 和 Terraform 之间的区别？

# 进一步阅读

+   持续集成/持续部署/持续交付：

[`www.packtpub.com/virtualization-and-cloud/hands-continuous-integration-and-delivery`](https://www.packtpub.com/virtualization-and-cloud/hands-continuous-integration-and-delivery)

[`www.packtpub.com/virtualization-and-cloud/cloud-native-continuous-integration-and-delivery`](https://www.packtpub.com/virtualization-and-cloud/cloud-native-continuous-integration-and-delivery)

+   Ansible：

[`www.packtpub.com/virtualization-and-cloud/mastering-ansible-third-edition`](https://www.packtpub.com/virtualization-and-cloud/mastering-ansible-third-edition)

[`www.packtpub.com/application-development/hands-infrastructure-automation-ansible-video`](https://www.packtpub.com/application-development/hands-infrastructure-automation-ansible-video)

+   Terraform：

[`www.packtpub.com/networking-and-servers/getting-started-terraform-second-edition`](https://www.packtpub.com/networking-and-servers/getting-started-terraform-second-edition)

[`www.packtpub.com/big-data-and-business-intelligence/hands-infrastructure-automation-terraform-aws-video`](https://www.packtpub.com/big-data-and-business-intelligence/hands-infrastructure-automation-terraform-aws-video)

+   黄瓜：

[`www.packtpub.com/web-development/cucumber-cookbook`](https://www.packtpub.com/web-development/cucumber-cookbook)

+   GitLab：

[`www.packtpub.com/virtualization-and-cloud/gitlab-quick-start-guide`](https://www.packtpub.com/virtualization-and-cloud/gitlab-quick-start-guide)

[`www.packtpub.com/application-development/hands-auto-devops-gitlab-ci-video`](https://www.packtpub.com/application-development/hands-auto-devops-gitlab-ci-video)
