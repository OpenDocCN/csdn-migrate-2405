# CMake 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/ecf89da6185e63c44e748e0980911fef`](https://zh.annas-archive.org/md5/ecf89da6185e63c44e748e0980911fef)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：检测环境

在本章中，我们将介绍以下食谱：

+   发现操作系统

+   处理依赖于平台的源代码

+   处理依赖于编译器的源代码

+   发现主机处理器架构

+   发现主机处理器指令集

+   为 Eigen 库启用矢量化

# 引言

尽管 CMake 是跨平台的，在我们的项目中我们努力使源代码能够在不同平台、操作系统和编译器之间移植，但有时源代码并不完全可移植；例如，当使用依赖于供应商的扩展时，我们可能会发现有必要根据平台以略有不同的方式配置和/或构建代码。这对于遗留代码或交叉编译尤其相关，我们将在第十三章，*替代生成器和交叉编译*中回到这个话题。了解处理器指令集以针对特定目标平台优化性能也是有利的。本章提供了检测此类环境的食谱，并提供了如何实施此类解决方案的建议。

# 发现操作系统

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-02/recipe-01`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-02/recipe-01)找到。该食谱适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

尽管 CMake 是一套跨平台的工具，但了解配置或构建步骤在哪个操作系统（OS）上执行仍然非常有用。这种操作系统检测可以用来调整 CMake 代码以适应特定的操作系统，根据操作系统启用条件编译，或者在可用或必要时使用编译器特定的扩展。在本食谱中，我们将展示如何使用 CMake 来检测操作系统，并通过一个不需要编译任何源代码的示例来说明。为了简单起见，我们只考虑配置步骤。

# 如何操作

我们将通过一个非常简单的`CMakeLists.txt`来演示操作系统检测：

1.  我们首先定义最小 CMake 版本和项目名称。请注意，我们的语言要求是`NONE`：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-01 LANGUAGES NONE)

```

1.  然后我们希望根据检测到的操作系统打印一条自定义消息：

```cpp
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(STATUS "Configuring on/for Linux")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  message(STATUS "Configuring on/for macOS")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  message(STATUS "Configuring on/for Windows")
elseif(CMAKE_SYSTEM_NAME STREQUAL "AIX")
  message(STATUS "Configuring on/for IBM AIX")
else()
  message(STATUS "Configuring on/for ${CMAKE_SYSTEM_NAME}")
endif()
```

在尝试之前，首先检查前面的代码块，并考虑你期望在你的系统上看到的行为。

1.  现在我们准备测试并配置项目：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
```

1.  在 CMake 的输出中，有一行在这里很有趣——在 Linux 系统上，这是感兴趣的行（在其他系统上，输出可能会有所不同）：

```cpp
-- Configuring on/for Linux
```

# 它是如何工作的

CMake 正确地为目标操作系统定义了`CMAKE_SYSTEM_NAME`，因此通常不需要使用自定义命令、工具或脚本来查询此信息。该变量的值随后可用于实现操作系统特定的条件和解决方法。在具有`uname`命令的系统上，该变量设置为`uname -s`的输出。在 macOS 上，该变量设置为"Darwin"。在 Linux 和 Windows 上，它分别评估为"Linux"和"Windows"。现在我们知道，如果我们需要在特定操作系统上执行特定的 CMake 代码，该如何操作。当然，我们应该尽量减少这种定制，以便简化迁移到新平台的过程。

为了在从一个平台迁移到另一个平台时尽量减少麻烦，应避免直接使用 Shell 命令，并避免使用显式的路径分隔符（Linux 和 macOS 上的正斜杠和 Windows 上的反斜杠）。在 CMake 代码中只使用正斜杠作为路径分隔符，CMake 会自动为所涉及的操作系统环境进行转换。

# 处理平台依赖的源代码

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-02/recipe-02`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-02/recipe-02)找到，并包含一个 C++示例。该食谱适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

理想情况下，我们应该避免平台依赖的源代码，但有时我们别无选择——尤其是当我们被给予需要配置和编译的代码时，而这些代码并非我们自己编写的。在本食谱中，我们将演示如何使用 CMake 根据操作系统有条件地编译源代码。

# 准备工作

对于这个例子，我们将修改来自第一章，*从简单可执行文件到库*，食谱 1，*将单个源文件编译成可执行文件*的`hello-world.cpp`示例代码：

```cpp
#include <cstdlib>
#include <iostream>
#include <string>

std::string say_hello() {
#ifdef IS_WINDOWS
  return std::string("Hello from Windows!");
#elif IS_LINUX
  return std::string("Hello from Linux!");
#elif IS_MACOS
  return std::string("Hello from macOS!");
#else
  return std::string("Hello from an unknown system!");
#endif
}

int main() {
  std::cout << say_hello() << std::endl;
  return EXIT_SUCCESS;
}
```

# 如何操作

让我们构建一个对应的`CMakeLists.txt`实例，这将使我们能够根据目标操作系统有条件地编译源代码：

1.  我们首先设置最小 CMake 版本、项目名称和支持的语言：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-02 LANGUAGES CXX)
```

1.  然后我们定义可执行文件及其对应的源文件：

```cpp
add_executable(hello-world hello-world.cpp)
```

1.  然后我们通过定义以下目标编译定义来让预处理器知道系统名称：

```cpp
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(hello-world PUBLIC "IS_LINUX")
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  target_compile_definitions(hello-world PUBLIC "IS_MACOS")
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_compile_definitions(hello-world PUBLIC "IS_WINDOWS")
endif()
```

在继续之前，先检查前面的表达式并考虑在你的系统上你期望的行为。

1.  现在我们准备测试并配置项目：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
$ ./hello-world

Hello from Linux!
```

在 Windows 系统上，你会看到`Hello from Windows!`；其他操作系统将产生不同的输出。

# 工作原理

在`hello-world.cpp`示例中，有趣的部分是基于预处理器定义`IS_WINDOWS`、`IS_LINUX`或`IS_MACOS`的条件编译：

```cpp
std::string say_hello() {
#ifdef IS_WINDOWS
  return std::string("Hello from Windows!");
#elif IS_LINUX
  return std::string("Hello from Linux!");
#elif IS_MACOS
  return std::string("Hello from macOS!");
#else
  return std::string("Hello from an unknown system!");
#endif
}
```

这些定义在配置时由 CMake 在`CMakeLists.txt`中使用`target_compile_definitions`定义，然后传递给预处理器。我们可以实现一个更紧凑的表达式，而不重复`if-endif`语句，我们将在下一个食谱中演示这种重构。我们还可以将`if-endif`语句合并为一个`if-elseif-elseif-endif`语句。

在这一点上，我们应该指出，我们可以使用`add_definitions(-DIS_LINUX)`（当然，根据所讨论的平台调整定义）而不是使用`target_compile_definitions`来设置定义。使用`add_definitions`的缺点是它修改了整个项目的编译定义，而`target_compile_definitions`给了我们限制定义范围到特定目标的可能性，以及通过使用`PRIVATE`、`PUBLIC`或`INTERFACE`限定符限制这些定义的可见性。这些限定符具有与编译器标志相同的含义，正如我们在第一章，*从简单的可执行文件到库*，第 8 个食谱，*控制编译器标志*中已经看到的：

+   使用`PRIVATE`限定符，编译定义将仅应用于给定目标，而不会被其他消费目标应用。

+   使用`INTERFACE`限定符，编译定义将仅应用于消费该定义的目标。

+   使用`PUBLIC`限定符，编译定义将应用于给定目标以及所有其他消费目标。

尽量减少项目中依赖于平台的源代码，以便更容易移植。

# 处理依赖于编译器的源代码

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-02/recipe-03`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-02/recipe-03)找到，并包含 C++和 Fortran 示例。本食谱适用于 CMake 版本 3.5（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

本食谱与前一个食谱类似，因为我们使用 CMake 来适应依赖于环境的条件源代码的编译：在这种情况下，它将依赖于所选的编译器。同样，为了便携性，这是我们在编写新代码时尽量避免的情况，但这也是我们几乎肯定会在某个时候遇到的情况，尤其是在使用遗留代码或处理依赖于编译器的工具（如 sanitizers）时。从本章和前一章的食谱中，我们已经具备了实现这一点的所有要素。尽管如此，讨论处理依赖于编译器的源代码的问题仍然很有用，因为我们有机会介绍一些新的 CMake 方面。

# 准备就绪

在本配方中，我们将从 C++示例开始，稍后我们将展示一个 Fortran 示例，并尝试重构和简化 CMake 代码。

让我们考虑以下`hello-world.cpp`源代码：

```cpp
#include <cstdlib>
#include <iostream>
#include <string>

std::string say_hello() {
#ifdef IS_INTEL_CXX_COMPILER
  // only compiled when Intel compiler is selected
  // such compiler will not compile the other branches
  return std::string("Hello Intel compiler!");
#elif IS_GNU_CXX_COMPILER
  // only compiled when GNU compiler is selected
  // such compiler will not compile the other branches
  return std::string("Hello GNU compiler!");
#elif IS_PGI_CXX_COMPILER
  // etc.
  return std::string("Hello PGI compiler!");
#elif IS_XL_CXX_COMPILER
  return std::string("Hello XL compiler!");
#else
  return std::string("Hello unknown compiler - have we met before?");
#endif
}

int main() {
  std::cout << say_hello() << std::endl;
  std::cout << "compiler name is " COMPILER_NAME << std::endl;
  return EXIT_SUCCESS;
}
```

我们还将使用相应的 Fortran 示例（`hello-world.F90`）：

```cpp
program hello

  implicit none

#ifdef IS_Intel_FORTRAN_COMPILER
  print *, 'Hello Intel compiler!'
#elif IS_GNU_FORTRAN_COMPILER
  print *, 'Hello GNU compiler!'
#elif IS_PGI_FORTRAN_COMPILER
  print *, 'Hello PGI compiler!'
#elif IS_XL_FORTRAN_COMPILER
  print *, 'Hello XL compiler!'
#else
  print *, 'Hello unknown compiler - have we met before?'
#endif

end program
```

# 如何做到这一点

我们将在转向 Fortran 示例之前从 C++示例开始：

1.  在`CMakeLists.txt`文件中，我们定义了现在熟悉的最低版本、项目名称和支持的语言：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-03 LANGUAGES CXX)
```

1.  然后我们定义可执行目标及其对应的源文件：

```cpp
add_executable(hello-world hello-world.cpp)
```

1.  然后我们通过定义以下目标编译定义，让预处理器了解编译器名称和供应商：

```cpp
target_compile_definitions(hello-world PUBLIC "COMPILER_NAME=\"${CMAKE_CXX_COMPILER_ID}\"")

if(CMAKE_CXX_COMPILER_ID MATCHES Intel)
    target_compile_definitions(hello-world PUBLIC "IS_INTEL_CXX_COMPILER")
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES GNU)
    target_compile_definitions(hello-world PUBLIC "IS_GNU_CXX_COMPILER")
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES PGI)
    target_compile_definitions(hello-world PUBLIC "IS_PGI_CXX_COMPILER")
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES XL)
    target_compile_definitions(hello-world PUBLIC "IS_XL_CXX_COMPILER")
endif()
```

之前的配方已经训练了我们的眼睛，现在我们甚至可以预见到结果：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
$ ./hello-world

Hello GNU compiler!
```

如果您使用的是不同的编译器供应商，那么此示例代码将提供不同的问候。

在前面的示例和之前的配方中的`CMakeLists.txt`文件中的`if`语句似乎是重复的，作为程序员，我们不喜欢重复自己。我们能更简洁地表达这一点吗？确实可以！为此，让我们转向 Fortran 示例。

在 Fortran 示例的`CMakeLists.txt`文件中，我们需要执行以下操作：

1.  我们需要将语言调整为 Fortran：

```cpp
project(recipe-03 LANGUAGES Fortran)
```

1.  然后我们定义可执行文件及其对应的源文件；在这种情况下，使用大写的`.F90`后缀：

```cpp
add_executable(hello-world hello-world.F90)
```

1.  然后我们通过定义以下目标编译定义，让预处理器非常简洁地了解编译器供应商：

```cpp
target_compile_definitions(hello-world
  PUBLIC "IS_${CMAKE_Fortran_COMPILER_ID}_FORTRAN_COMPILER"
)
```

剩余的 Fortran 示例行为与 C++示例相同。

# 它是如何工作的

预处理器定义是在配置时由 CMake 在`CMakeLists.txt`中定义的，并传递给预处理器。Fortran 示例包含一个非常紧凑的表达式，我们使用`CMAKE_Fortran_COMPILER_ID`变量来构造预处理器定义，使用`target_compile_definitions`。为了适应这一点，我们不得不将“Intel”的案例从`IS_INTEL_CXX_COMPILER`更改为`IS_Intel_FORTRAN_COMPILER`。我们可以通过使用相应的`CMAKE_C_COMPILER_ID`和`CMAKE_CXX_COMPILER_ID`变量为 C 或 C++实现相同的效果。但是请注意，`CMAKE_<LANG>_COMPILER_ID`*并不保证*为所有编译器或语言定义。

对于应该被预处理的 Fortran 代码，使用`.F90`后缀，对于不应该被预处理的代码，使用`.f90`后缀。

# 探索主机处理器架构

本配方的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-02/recipe-04`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-02/recipe-04)获取，并包含一个 C++示例。该配方适用于 CMake 版本 3.5（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

20 世纪 70 年代超级计算中 64 位整数运算的出现以及 21 世纪初个人计算机中 64 位寻址的出现扩大了内存寻址范围，并且投入了大量资源将硬编码为 32 位架构的代码移植到支持 64 位寻址。许多博客文章，例如[`www.viva64.com/en/a/0004/`](https://www.viva64.com/en/a/0004/)，都致力于讨论在将 C++代码移植到 64 位平台时遇到的典型问题和解决方案。非常建议以避免明确硬编码限制的方式编程，但您可能处于需要容纳硬编码限制的代码配置与 CMake 的情况，在本菜谱中，我们希望讨论检测宿主处理器架构的选项。

# 准备工作

我们将使用以下`arch-dependent.cpp`示例源代码：

```cpp
#include <cstdlib>
#include <iostream>
#include <string>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

std::string say_hello() {
  std::string arch_info(TOSTRING(ARCHITECTURE));
  arch_info += std::string(" architecture. ");
#ifdef IS_32_BIT_ARCH
  return arch_info + std::string("Compiled on a 32 bit host processor.");
#elif IS_64_BIT_ARCH
  return arch_info + std::string("Compiled on a 64 bit host processor.");
#else
  return arch_info + std::string("Neither 32 nor 64 bit, puzzling ...");
#endif
}
int main() {
  std::cout << say_hello() << std::endl;
  return EXIT_SUCCESS;
}
```

# 如何操作

现在让我们转向 CMake 方面。在`CMakeLists.txt`文件中，我们需要应用以下内容：

1.  我们首先定义可执行文件及其源文件依赖项：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-04 LANGUAGES CXX)

add_executable(arch-dependent arch-dependent.cpp)
```

1.  我们检查`void`指针类型的大小。这在`CMAKE_SIZEOF_VOID_P` CMake 变量中定义，并将告诉我们 CPU 是 32 位还是 64 位。我们通过状态消息让用户知道检测到的大小，并设置一个预处理器定义：

```cpp
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  target_compile_definitions(arch-dependent PUBLIC "IS_64_BIT_ARCH")
  message(STATUS "Target is 64 bits")
else()
  target_compile_definitions(arch-dependent PUBLIC "IS_32_BIT_ARCH")
  message(STATUS "Target is 32 bits")
endif()
```

1.  然后我们通过定义以下目标编译定义让预处理器知道宿主处理器架构，同时在配置期间打印状态消息：

```cpp
if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "i386")
  message(STATUS "i386 architecture detected")
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "i686")
  message(STATUS "i686 architecture detected")
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "x86_64")
  message(STATUS "x86_64 architecture detected")
else()
  message(STATUS "host processor architecture is unknown")
endif()

target_compile_definitions(arch-dependent
  PUBLIC "ARCHITECTURE=${CMAKE_HOST_SYSTEM_PROCESSOR}"
  )
```

1.  我们配置项目并记录状态消息（当然，确切的消息可能会发生变化）：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..

...
-- Target is 64 bits
-- x86_64 architecture detected
...
```

1.  最后，我们构建并执行代码（实际输出将取决于宿主处理器架构）：

```cpp
$ cmake --build .
$ ./arch-dependent

x86_64 architecture. Compiled on a 64 bit host processor.
```

# 它是如何工作的

CMake 定义了`CMAKE_HOST_SYSTEM_PROCESSOR`变量，其中包含当前正在运行的处理器的名称。这可以设置为“i386”、“i686”、“x86_64”、“AMD64”等，当然，这取决于当前的 CPU。`CMAKE_SIZEOF_VOID_P`被定义为持有指向`void`类型的指针的大小。我们可以在 CMake 级别查询这两个变量，以便修改目标或目标编译定义。使用预处理器定义，我们可以根据检测到的宿主处理器架构分支源代码编译。正如在前面的菜谱中讨论的那样，在编写新代码时应避免这种定制，但在处理遗留代码或进行交叉编译时，有时是有用的，这是第十三章，*替代生成器和交叉编译*的主题。

使用`CMAKE_SIZEOF_VOID_P`是检查当前 CPU 是 32 位还是 64 位架构的唯一真正可移植的方法。

# 还有更多内容

除了`CMAKE_HOST_SYSTEM_PROCESSOR`，CMake 还定义了`CMAKE_SYSTEM_PROCESSOR`变量。前者包含 CMake**当前正在运行**的 CPU 的名称，后者将包含我们**当前正在构建**的 CPU 的名称。这是一个微妙的区别，在交叉编译时起着非常基本的作用。我们将在第十三章，*替代生成器和交叉编译*中了解更多关于交叉编译的信息。

让 CMake 检测主机处理器架构的替代方法是使用 C 或 C++中定义的符号，并使用 CMake 的`try_run`函数来构建并尝试执行源代码（参见第五章，*配置时间和构建时间操作*，第 8 个配方，*探测执行*），该操作由预处理器符号分支。这会返回可以在 CMake 侧捕获的定义良好的错误（此策略的灵感来自[`github.com/axr/solar-cmake/blob/master/TargetArch.cmake`](https://github.com/axr/solar-cmake/blob/master/TargetArch.cmake)）：

```cpp
#if defined(__i386) || defined(__i386__) || defined(_M_IX86)
    #error cmake_arch i386
#elif defined(__x86_64) || defined(__x86_64__) || defined(__amd64) || defined(_M_X64)
    #error cmake_arch x86_64
#endif
```

此策略也是检测目标处理器架构的首选方法，其中 CMake 似乎没有提供便携式内置解决方案。

还存在另一种替代方案。它将仅使用 CMake，完全摆脱预处理器，代价是每个情况都有一个不同的源文件，然后使用`target_sources` CMake 命令将其设置为可执行目标`arch-dependent`的源文件：

```cpp
add_executable(arch-dependent "")

if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "i386")
  message(STATUS "i386 architecture detected")
  target_sources(arch-dependent
    PRIVATE
      arch-dependent-i386.cpp
    )
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "i686")
  message(STATUS "i686 architecture detected")
  target_sources(arch-dependent
    PRIVATE
      arch-dependent-i686.cpp
    )
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "x86_64")
  message(STATUS "x86_64 architecture detected")
  target_sources(arch-dependent
    PRIVATE
      arch-dependent-x86_64.cpp
    )
else()
  message(STATUS "host processor architecture is unknown")
endif()
```

这种方法显然需要对现有项目进行更多工作，因为源文件需要分开。此外，不同源文件之间的代码重复可能确实成为一个问题。

# 发现主机处理器指令集

本配方的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-02/recipe-05`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-02/recipe-05)获取，并包含一个 C++示例。该配方适用于 CMake 版本 3.10（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

在本配方中，我们将讨论如何借助 CMake 发现主机处理器指令集。此功能相对较新地添加到 CMake 中，并需要 CMake 3.10 或更高版本。检测到的主机系统信息可用于设置相应的编译器标志，或根据主机系统实现可选的源代码编译或源代码生成。在本配方中，我们的目标是检测主机系统信息，使用预处理器定义将其传递给 C++源代码，并将信息打印到输出。

# 准备就绪

我们的示例 C++源文件（`processor-info.cpp`）包含以下内容：

```cpp
#include "config.h"

#include <cstdlib>
#include <iostream>

int main() {
  std::cout << "Number of logical cores: "
            << NUMBER_OF_LOGICAL_CORES << std::endl;
  std::cout << "Number of physical cores: "
            << NUMBER_OF_PHYSICAL_CORES << std::endl;

  std::cout << "Total virtual memory in megabytes: "
            << TOTAL_VIRTUAL_MEMORY << std::endl;
  std::cout << "Available virtual memory in megabytes: "
            << AVAILABLE_VIRTUAL_MEMORY << std::endl;
  std::cout << "Total physical memory in megabytes: "
            << TOTAL_PHYSICAL_MEMORY << std::endl;
  std::cout << "Available physical memory in megabytes: "
            << AVAILABLE_PHYSICAL_MEMORY << std::endl;

  std::cout << "Processor is 64Bit: "
            << IS_64BIT << std::endl;
  std::cout << "Processor has floating point unit: "
            << HAS_FPU << std::endl;
  std::cout << "Processor supports MMX instructions: "
            << HAS_MMX << std::endl;
  std::cout << "Processor supports Ext. MMX instructions: "
            << HAS_MMX_PLUS << std::endl;
  std::cout << "Processor supports SSE instructions: "
            << HAS_SSE << std::endl;
  std::cout << "Processor supports SSE2 instructions: "
            << HAS_SSE2 << std::endl;
  std::cout << "Processor supports SSE FP instructions: "
            << HAS_SSE_FP << std::endl;
  std::cout << "Processor supports SSE MMX instructions: "
            << HAS_SSE_MMX << std::endl;
  std::cout << "Processor supports 3DNow instructions: "
            << HAS_AMD_3DNOW << std::endl;
  std::cout << "Processor supports 3DNow+ instructions: "
            << HAS_AMD_3DNOW_PLUS << std::endl;
  std::cout << "IA64 processor emulating x86 : "
            << HAS_IA64 << std::endl;

  std::cout << "OS name: "
            << OS_NAME << std::endl;
  std::cout << "OS sub-type: "
            << OS_RELEASE << std::endl;
  std::cout << "OS build ID: "
            << OS_VERSION << std::endl;
  std::cout << "OS platform: "
            << OS_PLATFORM << std::endl;

  return EXIT_SUCCESS;
}
```

该文件包含`config.h`，我们将从`config.h.in`生成，如下所示：

```cpp
#pragma once

#define NUMBER_OF_LOGICAL_CORES @_NUMBER_OF_LOGICAL_CORES@
#define NUMBER_OF_PHYSICAL_CORES @_NUMBER_OF_PHYSICAL_CORES@
#define TOTAL_VIRTUAL_MEMORY @_TOTAL_VIRTUAL_MEMORY@
#define AVAILABLE_VIRTUAL_MEMORY @_AVAILABLE_VIRTUAL_MEMORY@
#define TOTAL_PHYSICAL_MEMORY @_TOTAL_PHYSICAL_MEMORY@
#define AVAILABLE_PHYSICAL_MEMORY @_AVAILABLE_PHYSICAL_MEMORY@
#define IS_64BIT @_IS_64BIT@
#define HAS_FPU @_HAS_FPU@
#define HAS_MMX @_HAS_MMX@
#define HAS_MMX_PLUS @_HAS_MMX_PLUS@
#define HAS_SSE @_HAS_SSE@
#define HAS_SSE2 @_HAS_SSE2@
#define HAS_SSE_FP @_HAS_SSE_FP@
#define HAS_SSE_MMX @_HAS_SSE_MMX@
#define HAS_AMD_3DNOW @_HAS_AMD_3DNOW@
#define HAS_AMD_3DNOW_PLUS @_HAS_AMD_3DNOW_PLUS@
#define HAS_IA64 @_HAS_IA64@
#define OS_NAME "@_OS_NAME@"
#define OS_RELEASE "@_OS_RELEASE@"
#define OS_VERSION "@_OS_VERSION@"
#define OS_PLATFORM "@_OS_PLATFORM@"
```

# 如何做到这一点

我们将使用 CMake 来填充`config.h`中对我们平台有意义的定义，并将我们的示例源文件编译成可执行文件：

1.  首先，我们定义最小 CMake 版本、项目名称和项目语言：

```cpp
cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(recipe-05 CXX)
```

1.  然后，我们定义目标可执行文件、其源文件和包含目录：

```cpp
add_executable(processor-info "")

target_sources(processor-info
  PRIVATE
    processor-info.cpp
  )

target_include_directories(processor-info
  PRIVATE
    ${PROJECT_BINARY_DIR}
  )
```

1.  然后，我们继续查询主机系统信息的一系列键：

```cpp
foreach(key
  IN ITEMS
    NUMBER_OF_LOGICAL_CORES
    NUMBER_OF_PHYSICAL_CORES
    TOTAL_VIRTUAL_MEMORY
    AVAILABLE_VIRTUAL_MEMORY
    TOTAL_PHYSICAL_MEMORY
    AVAILABLE_PHYSICAL_MEMORY
    IS_64BIT
    HAS_FPU
    HAS_MMX
    HAS_MMX_PLUS
    HAS_SSE
    HAS_SSE2
    HAS_SSE_FP
    HAS_SSE_MMX
    HAS_AMD_3DNOW
```

```cpp
    HAS_AMD_3DNOW_PLUS
    HAS_IA64
    OS_NAME
    OS_RELEASE
    OS_VERSION
    OS_PLATFORM
  )
  cmake_host_system_information(RESULT _${key} QUERY ${key})
endforeach()
```

1.  定义了相应的变量后，我们配置`config.h`：

```cpp
configure_file(config.h.in config.h @ONLY)
```

1.  现在我们准备好配置、构建和测试项目了：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
$ ./processor-info

Number of logical cores: 4
Number of physical cores: 2
Total virtual memory in megabytes: 15258
Available virtual memory in megabytes: 14678
Total physical memory in megabytes: 7858
Available physical memory in megabytes: 4072
Processor is 64Bit: 1
Processor has floating point unit: 1
Processor supports MMX instructions: 1
Processor supports Ext. MMX instructions: 0
Processor supports SSE instructions: 1
Processor supports SSE2 instructions: 1
Processor supports SSE FP instructions: 0
Processor supports SSE MMX instructions: 0
Processor supports 3DNow instructions: 0
Processor supports 3DNow+ instructions: 0
IA64 processor emulating x86 : 0
OS name: Linux
OS sub-type: 4.16.7-1-ARCH
OS build ID: #1 SMP PREEMPT Wed May 2 21:12:36 UTC 2018
OS platform: x86_64
```

1.  输出当然会根据处理器而变化。

# 它是如何工作的

在`CMakeLists.txt`中的`foreach`循环查询多个键的值，并定义相应的变量。本食谱的核心功能是`cmake_host_system_information`，它查询 CMake 运行所在的主机系统的系统信息。此函数可以一次调用多个键，但在这种情况下，我们为每个键使用一次函数调用。然后，我们使用这些变量来配置`config.h.in`中的占位符，并生成`config.h`。此配置是通过`configure_file`命令完成的。最后，`config.h`被包含在`processor-info.cpp`中，一旦编译，它将打印值到屏幕上。我们将在第五章，*配置时间和构建时间操作*，和第六章，*生成源代码*中重新审视这种方法。

# 还有更多

对于更精细的处理器指令集检测，请考虑使用此模块：[`github.com/VcDevel/Vc/blob/master/cmake/OptimizeForArchitecture.cmake`](https://github.com/VcDevel/Vc/blob/master/cmake/OptimizeForArchitecture.cmake)。我们还想指出，有时构建代码的主机可能与运行代码的主机不同。这在计算集群中很常见，登录节点的架构可能与计算节点的架构不同。解决此问题的一种方法是提交配置和编译作为计算步骤，并将其部署到计算节点。

我们没有使用`cmake_host_system_information`中的所有可用键。为此，请参考[`cmake.org/cmake/help/latest/command/cmake_host_system_information.html`](https://cmake.org/cmake/help/latest/command/cmake_host_system_information.html)。

# 为 Eigen 库启用矢量化

此食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-02/recipe-06`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-02/recipe-06)找到，并包含一个 C++示例。该食谱适用于 CMake 版本 3.5（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

现代处理器架构的向量能力可以显著提高代码的性能。对于某些类型的操作，这一点尤其明显，而线性代数是其中最突出的。本食谱将展示如何启用向量化以加速使用 Eigen C++库进行线性代数的简单可执行文件。

# 准备就绪

我们将使用 Eigen C++模板库进行线性代数运算，并展示如何设置编译器标志以启用向量化。本食谱的源代码是`linear-algebra.cpp`文件：

```cpp
#include <chrono>
#include <iostream>

#include <Eigen/Dense>

EIGEN_DONT_INLINE
double simple_function(Eigen::VectorXd &va, Eigen::VectorXd &vb) {
  // this simple function computes the dot product of two vectors
  // of course it could be expressed more compactly
  double d = va.dot(vb);
  return d;
}

int main() {
  int len = 1000000;
  int num_repetitions = 100;

  // generate two random vectors
  Eigen::VectorXd va = Eigen::VectorXd::Random(len);
  Eigen::VectorXd vb = Eigen::VectorXd::Random(len);

  double result;
  auto start = std::chrono::system_clock::now();
  for (auto i = 0; i < num_repetitions; i++) {
    result = simple_function(va, vb);
  }
  auto end = std::chrono::system_clock::now();
  auto elapsed_seconds = end - start;

  std::cout << "result: " << result << std::endl;
  std::cout << "elapsed seconds: " << elapsed_seconds.count() << std::endl;
}
```

我们期望向量化能够加速`simple_function`中点积操作的执行。

# 如何操作

根据 Eigen 库的文档，只需设置适当的编译器标志即可启用向量化代码的生成。让我们看看`CMakeLists.txt`：

1.  我们声明一个 C++11 项目：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-06 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  由于我们希望使用 Eigen 库，因此我们需要在系统上找到其头文件：

```cpp
find_package(Eigen3 3.3 REQUIRED CONFIG)
```

1.  我们包含`CheckCXXCompilerFlag.cmake`标准模块文件：

```cpp
include(CheckCXXCompilerFlag)
```

1.  我们检查`-march=native`编译器标志是否有效：

```cpp
check_cxx_compiler_flag("-march=native" _march_native_works)
```

1.  我们还检查了替代的`-xHost`编译器标志：

```cpp
check_cxx_compiler_flag("-xHost" _xhost_works)
```

1.  我们设置一个空变量`_CXX_FLAGS`，以保存我们刚刚检查的两个标志中找到的一个有效标志。如果我们看到`_march_native_works`，我们将`_CXX_FLAGS`设置为`-march=native`。如果我们看到`_xhost_works`，我们将`_CXX_FLAGS`设置为`-xHost`。如果两者都不起作用，我们将保持`_CXX_FLAGS`为空，向量化将被禁用：

```cpp
set(_CXX_FLAGS)
if(_march_native_works)
  message(STATUS "Using processor's vector instructions (-march=native compiler flag set)")
  set(_CXX_FLAGS "-march=native")
elseif(_xhost_works)
  message(STATUS "Using processor's vector instructions (-xHost compiler flag set)")
  set(_CXX_FLAGS "-xHost")
else()
  message(STATUS "No suitable compiler flag found for vectorization")
endif()
```

1.  为了进行比较，我们还为未优化的版本定义了一个可执行目标，其中我们不使用前面的优化标志：

```cpp
add_executable(linear-algebra-unoptimized linear-algebra.cpp)

target_link_libraries(linear-algebra-unoptimized
  PRIVATE
    Eigen3::Eigen
  )
```

1.  此外，我们还定义了一个优化版本：

```cpp
add_executable(linear-algebra linear-algebra.cpp)

target_compile_options(linear-algebra
  PRIVATE
    ${_CXX_FLAGS}
  )

target_link_libraries(linear-algebra
  PRIVATE
    Eigen3::Eigen
  )
```

1.  让我们比较这两个可执行文件——首先我们进行配置（在这种情况下，`-march=native_works`）：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..

...
-- Performing Test _march_native_works
-- Performing Test _march_native_works - Success
```

```cpp
-- Performing Test _xhost_works
-- Performing Test _xhost_works - Failed
-- Using processor's vector instructions (-march=native compiler flag set)
...
```

1.  最后，让我们编译并比较时间：

```cpp
$ cmake --build .

$ ./linear-algebra-unoptimized 
result: -261.505
elapsed seconds: 1.97964

$ ./linear-algebra 
result: -261.505
elapsed seconds: 1.05048
```

# 工作原理

大多数现代处理器提供向量指令集。精心编写的代码可以利用这些指令集，并在与非向量化代码相比时实现增强的性能。Eigen 库在编写时就明确考虑了向量化，因为线性代数操作可以从中大大受益。我们所需要做的就是指示编译器为我们检查处理器，并为当前架构生成原生指令集。不同的编译器供应商使用不同的标志来实现这一点：GNU 编译器通过`-march=native`标志实现这一点，而 Intel 编译器使用`-xHost`标志。然后我们使用`CheckCXXCompilerFlag.cmake`模块提供的`check_cxx_compiler_flag`函数：

```cpp
check_cxx_compiler_flag("-march=native" _march_native_works)
```

该函数接受两个参数：第一个是要检查的编译器标志，第二个是用于存储检查结果的变量，即`true`或`false`。如果检查结果为正，我们将工作标志添加到`_CXX_FLAGS`变量中，然后该变量将用于设置我们可执行目标的编译器标志。

# 还有更多

这个配方可以与之前的配方结合使用；可以使用`cmake_host_system_information`查询处理器能力。


# 第四章：检测外部库和程序

在本章中，我们将涵盖以下食谱：

+   检测 Python 解释器

+   检测 Python 库

+   检测 Python 模块和包

+   检测 BLAS 和 LAPACK 数学库

+   检测 OpenMP 并行环境

+   检测 MPI 并行环境

+   检测 Eigen 库

+   检测 Boost 库

+   检测外部库：I. 使用`pkg-config`

+   检测外部库：II. 编写一个查找模块

# 引言

项目通常依赖于其他项目和库。本章演示了如何检测外部库、框架和项目以及如何链接到这些。CMake 有一个相当广泛的预打包模块集，用于检测最常用的库和程序，例如 Python 和 Boost。你可以使用`cmake --help-module-list`获取现有模块的列表。然而，并非所有库和程序都被覆盖，有时你将不得不提供自己的检测脚本。在本章中，我们将讨论必要的工具并发现 CMake 命令的查找家族：

+   `find_file`来查找一个指定文件的完整路径

+   `find_library`来查找一个库

+   `find_package`来查找并加载来自外部项目的设置

+   `find_path`来查找包含指定文件的目录

+   `find_program`来查找一个程序

你可以使用`--help-command`命令行开关来打印任何 CMake 内置命令的文档到屏幕上。

# 检测 Python 解释器

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-01`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-01)找到。该食谱适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

Python 是一种非常流行的动态语言。许多项目将用 Python 编写的工具与它们的主程序和库一起打包，或者在配置或构建过程中使用 Python 脚本。在这种情况下，确保运行时依赖于 Python 解释器也得到满足是很重要的。本食谱将展示如何在配置步骤中检测和使用 Python 解释器。我们将介绍`find_package`命令，该命令将在本章中广泛使用。

# 如何操作

我们将逐步构建`CMakeLists.txt`文件：

1.  我们首先定义最小 CMake 版本和项目名称。请注意，对于这个例子，我们将不需要任何语言支持：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-01 LANGUAGES NONE)
```

1.  然后，我们使用`find_package`命令来查找 Python 解释器：

```cpp
find_package(PythonInterp REQUIRED)
```

1.  接着，我们执行一个 Python 命令并捕获其输出和返回值：

```cpp
execute_process(
  COMMAND
    ${PYTHON_EXECUTABLE} "-c" "print('Hello, world!')"
  RESULT_VARIABLE _status
  OUTPUT_VARIABLE _hello_world
  ERROR_QUIET
  OUTPUT_STRIP_TRAILING_WHITESPACE
  )
```

1.  最后，我们打印 Python 命令的返回值和输出：

```cpp
message(STATUS "RESULT_VARIABLE is: ${_status}")
message(STATUS "OUTPUT_VARIABLE is: ${_hello_world}")
```

1.  现在，我们可以检查配置步骤的输出：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..

-- Found PythonInterp: /usr/bin/python (found version "3.6.5") 
-- RESULT_VARIABLE is: 0
-- OUTPUT_VARIABLE is: Hello, world!
-- Configuring done
-- Generating done
-- Build files have been written to: /home/user/cmake-cookbook/chapter-03/recipe-01/example/build
```

# 它是如何工作的

`find_package`是 CMake 模块的包装命令，用于发现和设置软件包。这些模块包含用于在系统上的标准位置识别软件包的 CMake 命令。CMake 模块的文件称为`Find<name>.cmake`，当发出`find_package(<name>)`调用时，它们包含的命令将在内部运行。

除了实际在系统上发现请求的软件包之外，查找模块还设置了一组有用的变量，反映实际找到的内容，可以在自己的`CMakeLists.txt`中使用。对于 Python 解释器，相关模块是`FindPythonInterp.cmake`，随 CMake 一起提供，并设置以下变量：

+   `PYTHONINTERP_FOUND`，一个布尔值，表示是否找到了解释器

+   `PYTHON_EXECUTABLE`，Python 解释器可执行文件的路径

+   `PYTHON_VERSION_STRING`，Python 解释器的完整版本号

+   `PYTHON_VERSION_MAJOR`，Python 解释器的主版本号

+   `PYTHON_VERSION_MINOR`，Python 解释器的小版本号

+   `PYTHON_VERSION_PATCH`，Python 解释器的补丁号

可以强制 CMake 查找特定版本的软件包。例如，使用此方法请求 Python 解释器的版本大于或等于 2.7：

```cpp
find_package(PythonInterp 2.7)
```

也可以强制要求满足依赖关系：

```cpp
find_package(PythonInterp REQUIRED)
```

在这种情况下，如果在常规查找位置找不到适合的 Python 解释器可执行文件，CMake 将中止配置。

CMake 有许多用于查找广泛使用的软件包的模块。我们建议始终在 CMake 在线文档中搜索现有的`Find<package>.cmake`模块，并在使用它们之前阅读其文档。`find_package`命令的文档可以在[`cmake.org/cmake/help/v3.5/command/find_package.html`](https://cmake.org/cmake/help/v3.5/command/find_package.html)找到。在线文档的一个很好的替代方法是浏览[`github.com/Kitware/CMake/tree/master/Modules`](https://github.com/Kitware/CMake/tree/master/Modules)中的 CMake 模块源代码 - 它们的标题文档说明了模块使用的变量以及模块设置的变量，可以在自己的`CMakeLists.txt`中使用。

# 还有更多

有时，软件包未安装在标准位置，CMake 可能无法正确找到它们。可以使用 CLI 开关`-D`告诉 CMake 在特定位置查找特定软件以传递适当的选项。对于 Python 解释器，可以按以下方式配置：

```cpp
$ cmake -D PYTHON_EXECUTABLE=/custom/location/python ..
```

这将正确识别安装在非标准`/custom/location/python`目录中的 Python 可执行文件。

每个包都不同，`Find<package>.cmake`模块试图考虑到这一点并提供统一的检测接口。当系统上安装的包无法被 CMake 找到时，我们建议您阅读相应检测模块的文档，以了解如何正确指导 CMake。您可以直接在终端中浏览文档，例如使用`cmake --help-module FindPythonInterp`。

无论检测包的情况如何，我们都想提到一个方便的打印变量的辅助模块。在本食谱中，我们使用了以下内容：

```cpp
message(STATUS "RESULT_VARIABLE is: ${_status}")
message(STATUS "OUTPUT_VARIABLE is: ${_hello_world}")
```

调试的一个便捷替代方法是使用以下内容：

```cpp
include(CMakePrintHelpers)
cmake_print_variables(_status _hello_world)
```

这将产生以下输出：

```cpp
-- _status="0" ; _hello_world="Hello, world!"
```

关于打印属性和变量的便捷宏的更多文档，请参见[`cmake.org/cmake/help/v3.5/module/CMakePrintHelpers.html`](https://cmake.org/cmake/help/v3.5/module/CMakePrintHelpers.html)。

# 检测 Python 库

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-02`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-02)找到，包含一个 C 语言示例。该食谱适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

如今，使用 Python 工具分析和操作编译程序的输出已经非常普遍。然而，还有其他更强大的方法将解释型语言（如 Python）与编译型语言（如 C 或 C++）结合。一种方法是通过提供新的类型和在这些类型上的新功能来*扩展*Python，通过将 C 或 C++模块编译成共享库。这将是第九章，*混合语言项目*中食谱的主题。另一种方法是*嵌入*Python 解释器到一个 C 或 C++程序中。这两种方法都需要以下内容：

+   一个可用的 Python 解释器版本

+   可用的 Python 头文件`Python.h`

+   Python 运行时库`libpython`

这三个组件必须锁定到完全相同的版本。我们已经演示了如何找到 Python 解释器；在本食谱中，我们将展示如何找到成功嵌入所需的两个缺失成分。

# 准备工作

我们将使用 Python 文档页面上找到的一个简单的 Python 嵌入到 C 程序的示例。源文件名为`hello-embedded-python.c`：

```cpp
#include <Python.h>

int main(int argc, char *argv[]) {
  Py_SetProgramName(argv[0]); /* optional but recommended */
  Py_Initialize();
  PyRun_SimpleString("from time import time,ctime\n"
                     "print 'Today is',ctime(time())\n");
  Py_Finalize();
  return 0;
}
```

这些代码示例将在程序中初始化 Python 解释器的一个实例，并使用 Python 的`time`模块打印日期。

嵌入示例代码可以在 Python 文档页面上在线找到，网址为[`docs.python.org/2/extending/embedding.html`](https://docs.python.org/2/extending/embedding.html)和[`docs.python.org/3/extending/embedding.html`](https://docs.python.org/3/extending/embedding.html)。

# 如何操作

在我们的`CMakeLists.txt`中，需要遵循以下步骤：

1.  第一块包含最小 CMake 版本、项目名称和所需语言：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-02 LANGUAGES C)
```

1.  在本食谱中，我们强制使用 C99 标准进行 C 语言编程。这严格来说不是链接 Python 所必需的，但可能是您想要设置的东西：

```cpp
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD_REQUIRED ON)
```

1.  找到 Python 解释器。现在这是一个必需的依赖项：

```cpp
find_package(PythonInterp REQUIRED)
```

1.  找到 Python 头文件和库。适当的模块称为`FindPythonLibs.cmake`：

```cpp
find_package(PythonLibs ${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR} EXACT REQUIRED)
```

1.  我们添加一个使用`hello-embedded-python.c`源文件的可执行目标：

```cpp
add_executable(hello-embedded-python hello-embedded-python.c)
```

1.  可执行文件包含`Python.h`头文件。因此，此目标的包含目录必须包含 Python 包含目录，可通过`PYTHON_INCLUDE_DIRS`变量访问：

```cpp
target_include_directories(hello-embedded-python
  PRIVATE
    ${PYTHON_INCLUDE_DIRS}
  )
```

1.  最后，我们将可执行文件链接到 Python 库，通过`PYTHON_LIBRARIES`变量访问：

```cpp
target_link_libraries(hello-embedded-python
  PRIVATE
    ${PYTHON_LIBRARIES}
  )
```

1.  现在，我们准备运行配置步骤：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..

...
-- Found PythonInterp: /usr/bin/python (found version "3.6.5") 
-- Found PythonLibs: /usr/lib/libpython3.6m.so (found suitable exact version "3.6.5")
```

1.  最后，我们执行构建步骤并运行可执行文件：

```cpp
$ cmake --build .
$ ./hello-embedded-python

Today is Thu Jun 7 22:26:02 2018
```

# 它是如何工作的

`FindPythonLibs.cmake`模块将在标准位置查找 Python 头文件和库。由于这些是我们项目的必需依赖项，如果找不到这些依赖项，配置将停止并出现错误。

请注意，我们明确要求 CMake 检测 Python 可执行文件的安装。这是为了确保可执行文件、头文件和库具有匹配的版本。这对于确保运行时不会出现版本不匹配导致的崩溃至关重要。我们通过使用`FindPythonInterp.cmake`中定义的`PYTHON_VERSION_MAJOR`和`PYTHON_VERSION_MINOR`实现了这一点：

```cpp
find_package(PythonInterp REQUIRED)
find_package(PythonLibs ${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR} EXACT REQUIRED)
```

使用`EXACT`关键字，我们已约束 CMake 检测特定且在这种情况下匹配的 Python 包含文件和库版本。为了更精确匹配，我们可以使用精确的`PYTHON_VERSION_STRING`：

```cpp
find_package(PythonInterp REQUIRED)
find_package(PythonLibs ${PYTHON_VERSION_STRING} EXACT REQUIRED)
```

# 还有更多

我们如何确保即使 Python 头文件和库不在标准安装目录中，它们也能被正确找到？对于 Python 解释器，可以通过将`PYTHON_LIBRARY`和`PYTHON_INCLUDE_DIR`选项通过`-D`选项传递给 CLI 来强制 CMake 在特定目录中查找。这些选项指定以下内容：

+   `PYTHON_LIBRARY`，Python 库的路径

+   `PYTHON_INCLUDE_DIR`，`Python.h`所在的路径

这确保将选择所需的 Python 版本。

有时需要将`-D PYTHON_EXECUTABLE`、`-D PYTHON_LIBRARY`和`-D PYTHON_INCLUDE_DIR`传递给 CMake CLI，以便找到所有必需的组件并将它们固定到完全相同的版本。

# 另请参见

要精确匹配 Python 解释器及其开发组件的版本可能非常困难。这在它们安装在非标准位置或系统上安装了多个版本的情况下尤其如此。CMake 在其版本 3.12 中添加了新的 Python 检测模块，旨在解决这个棘手的问题。我们的`CMakeLists.txt`中的检测部分也将大大简化：

```cpp
find_package(Python COMPONENTS Interpreter Development REQUIRED)
```

我们鼓励您阅读新模块的文档：[`cmake.org/cmake/help/v3.12/module/FindPython.html`](https://cmake.org/cmake/help/v3.12/module/FindPython.html)

# 检测 Python 模块和包

本配方的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-03`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-03)找到，并包含一个 C++示例。本配方适用于 CMake 版本 3.5（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

在前一个配方中，我们展示了如何检测 Python 解释器以及如何编译一个简单的 C 程序，嵌入 Python 解释器。这两项任务是结合 Python 和编译语言时的基础。通常，你的代码会依赖于特定的 Python 模块，无论是 Python 工具、嵌入 Python 的编译程序，还是扩展它的库。例如，NumPy 在涉及矩阵代数的问题中在科学界变得非常流行。在依赖于 Python 模块或包的项目中，确保这些 Python 模块的依赖得到满足是很重要的。本配方将展示如何探测用户的环境以找到特定的 Python 模块和包。

# 准备工作

我们将在 C++程序中尝试一个稍微更复杂的嵌入示例。该示例再次取自 Python 在线文档（[`docs.python.org/3.5/extending/embedding.html#pure-embedding`](https://docs.python.org/3.5/extending/embedding.html#pure-embedding)），并展示了如何通过调用编译的 C++可执行文件来执行用户定义的 Python 模块中的函数。

Python 3 示例代码（`Py3-pure-embedding.cpp`）包含以下源代码（有关相应的 Python 2 等效内容，请参见[`docs.python.org/2/extending/embedding.html#pure-embedding`](https://docs.python.org/2/extending/embedding.html#pure-embedding)）：

```cpp
#include <Python.h>

int main(int argc, char *argv[]) {
  PyObject *pName, *pModule, *pDict, *pFunc;
  PyObject *pArgs, *pValue;
  int i;

  if (argc < 3) {
    fprintf(stderr, "Usage: pure-embedding pythonfile funcname [args]\n");
    return 1;
  }

  Py_Initialize();

  PyRun_SimpleString("import sys");
  PyRun_SimpleString("sys.path.append(\".\")");

  pName = PyUnicode_DecodeFSDefault(argv[1]);
  /* Error checking of pName left out */

  pModule = PyImport_Import(pName);
  Py_DECREF(pName);

  if (pModule != NULL) {
    pFunc = PyObject_GetAttrString(pModule, argv[2]);
    /* pFunc is a new reference */

    if (pFunc && PyCallable_Check(pFunc)) {
      pArgs = PyTuple_New(argc - 3);
      for (i = 0; i < argc - 3; ++i) {
        pValue = PyLong_FromLong(atoi(argv[i + 3]));
        if (!pValue) {
          Py_DECREF(pArgs);
          Py_DECREF(pModule);
          fprintf(stderr, "Cannot convert argument\n");
          return 1;
        }
        /* pValue reference stolen here: */
        PyTuple_SetItem(pArgs, i, pValue);
      }
      pValue = PyObject_CallObject(pFunc, pArgs);
      Py_DECREF(pArgs);
      if (pValue != NULL) {
        printf("Result of call: %ld\n", PyLong_AsLong(pValue));
        Py_DECREF(pValue);
      } else {
        Py_DECREF(pFunc);
        Py_DECREF(pModule);
        PyErr_Print();
        fprintf(stderr, "Call failed\n");
        return 1;
      }
    } else {
      if (PyErr_Occurred())
        PyErr_Print();
      fprintf(stderr, "Cannot find function \"%s\"\n", argv[2]);
    }
    Py_XDECREF(pFunc);
    Py_DECREF(pModule);
  } else {
    PyErr_Print();
    fprintf(stderr, "Failed to load \"%s\"\n", argv[1]);
    return 1;
  }
  Py_Finalize();
  return 0;
}
```

我们希望嵌入的 Python 代码（`use_numpy.py`）使用 NumPy 设置一个矩阵，其中所有矩阵元素都设置为 1.0：

```cpp
import numpy as np

def print_ones(rows, cols):

    A = np.ones(shape=(rows, cols), dtype=float)
    print(A)

    # we return the number of elements to verify
    # that the C++ code is able to receive return values
    num_elements = rows*cols
    return(num_elements)
```

# 如何操作

在下面的代码中，我们希望使用 CMake 检查 NumPy 是否可用。首先，我们需要确保 Python 解释器、头文件和库都在我们的系统上可用。然后，我们将继续确保 NumPy 可用：

1.  首先，我们定义最小 CMake 版本、项目名称、语言和 C++标准：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-03 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  找到解释器、头文件和库的过程与之前的脚本完全相同：

```cpp
find_package(PythonInterp REQUIRED)
find_package(PythonLibs ${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR} EXACT REQUIRED)
```

1.  正确打包的 Python 模块知道它们的安装位置和版本。这可以通过执行一个最小的 Python 脚本来探测。我们可以在`CMakeLists.txt`内部执行这一步骤：

```cpp
execute_process(
  COMMAND
    ${PYTHON_EXECUTABLE} "-c" "import re, numpy; print(re.compile('/__init__.py.*').sub('',numpy.__file__))"
  RESULT_VARIABLE _numpy_status
  OUTPUT_VARIABLE _numpy_location
  ERROR_QUIET
  OUTPUT_STRIP_TRAILING_WHITESPACE
  )
```

1.  `_numpy_status`变量将在找到 NumPy 时为整数，否则为带有某些错误消息的字符串，而`_numpy_location`将包含 NumPy 模块的路径。如果找到 NumPy，我们将其位置保存到一个简单的名为`NumPy`的新变量中。请注意，新变量被缓存；这意味着 CMake 创建了一个持久变量，用户可以稍后修改它：

```cpp
if(NOT _numpy_status)
  set(NumPy ${_numpy_location} CACHE STRING "Location of NumPy")
endif()
```

1.  下一步是检查模块的版本。再次，我们在`CMakeLists.txt`中部署一些 Python 魔法，将版本保存到一个`_numpy_version`变量中：

```cpp
execute_process(
  COMMAND
    ${PYTHON_EXECUTABLE} "-c" "import numpy; print(numpy.__version__)"
  OUTPUT_VARIABLE _numpy_version
  ERROR_QUIET
  OUTPUT_STRIP_TRAILING_WHITESPACE
  )
```

1.  最后，我们让`FindPackageHandleStandardArgs`CMake 包设置`NumPy_FOUND`变量并以正确格式输出状态信息：

```cpp
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NumPy
  FOUND_VAR NumPy_FOUND
  REQUIRED_VARS NumPy
  VERSION_VAR _numpy_version
  )
```

1.  一旦所有依赖项都被正确找到，我们就可以编译可执行文件并将其链接到 Python 库：

```cpp
add_executable(pure-embedding "")

target_sources(pure-embedding
  PRIVATE
    Py${PYTHON_VERSION_MAJOR}-pure-embedding.cpp
  )

target_include_directories(pure-embedding
  PRIVATE
    ${PYTHON_INCLUDE_DIRS}
  )

target_link_libraries(pure-embedding
  PRIVATE
    ${PYTHON_LIBRARIES}
  )
```

1.  我们还必须确保`use_numpy.py`在构建目录中可用：

```cpp
add_custom_command(
  OUTPUT
    ${CMAKE_CURRENT_BINARY_DIR}/use_numpy.py
  COMMAND
    ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/use_numpy.py
                                          ${CMAKE_CURRENT_BINARY_DIR}/use_numpy.py
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/use_numpy.py
  )

# make sure building pure-embedding triggers the above custom command
target_sources(pure-embedding
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/use_numpy.py
  )
```

1.  现在，我们可以测试检测和嵌入代码：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..

-- ...
-- Found PythonInterp: /usr/bin/python (found version "3.6.5") 
-- Found PythonLibs: /usr/lib/libpython3.6m.so (found suitable exact version "3.6.5") 
-- Found NumPy: /usr/lib/python3.6/site-packages/numpy (found version "1.14.3")

$ cmake --build .
$ ./pure-embedding use_numpy print_ones 2 3

[[1\. 1\. 1.]
 [1\. 1\. 1.]]
Result of call: 6
```

# 它是如何工作的

在这个 CMake 脚本中，有三个新的 CMake 命令：`execute_process`和`add_custom_command`，它们总是可用的，以及`find_package_handle_standard_args`，它需要`include(FindPackageHandleStandardArgs)`。

`execute_process`命令将执行一个或多个作为当前发出的 CMake 命令的子进程的命令。最后一个子进程的返回值将被保存到作为参数传递给`RESULT_VARIABLE`的变量中，而标准输出和标准错误管道的内容将被保存到作为参数传递给`OUTPUT_VARIABLE`和`ERROR_VARIABLE`的变量中。`execute_process`允许我们执行任意命令，并使用它们的结果来推断我们系统的配置。在我们的例子中，我们首先使用它来确保 NumPy 可用，然后获取模块的版本。

`find_package_handle_standard_args`命令提供了处理与在给定系统上找到的程序和库相关的常见操作的标准工具。版本相关的选项，`REQUIRED`和`EXACT`，在引用此命令时都得到了正确处理，无需进一步的 CMake 代码。额外的选项`QUIET`和`COMPONENTS`，我们很快就会遇到，也由这个 CMake 命令在幕后处理。在这个脚本中，我们使用了以下内容：

```cpp
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NumPy
  FOUND_VAR NumPy_FOUND
  REQUIRED_VARS NumPy
  VERSION_VAR _numpy_version
  )
```

当所有必需的变量都被设置为有效的文件路径（`NumPy`）时，该命令将设置变量以发出模块已被找到的信号（`NumPy_FOUND`）。它还将设置版本到传递的版本变量（`_numpy_version`），并为用户打印出状态消息：

```cpp
-- Found NumPy: /usr/lib/python3.6/site-packages/numpy (found version "1.14.3")
```

在本食谱中，我们没有进一步使用这些变量。我们可以做的是，如果`NumPy_FOUND`被返回为`FALSE`，则停止配置。

最后，我们应该对将`use_numpy.py`复制到构建目录的代码段进行评论：

```cpp
add_custom_command(
  OUTPUT
    ${CMAKE_CURRENT_BINARY_DIR}/use_numpy.py
  COMMAND
    ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/use_numpy.py
                                          ${CMAKE_CURRENT_BINARY_DIR}/use_numpy.py
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/use_numpy.py
  )

target_sources(pure-embedding
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/use_numpy.py
  )
```

我们本可以使用`file(COPY ...)`命令来实现复制。在这里，我们选择使用`add_custom_command`以确保每次文件更改时都会复制文件，而不仅仅是在我们首次运行配置时。我们将在第五章*, 配置时间和构建时间操作*中更详细地回顾`add_custom_command`。还请注意`target_sources`命令，它将依赖项添加到`${CMAKE_CURRENT_BINARY_DIR}/use_numpy.py`；这样做是为了确保构建`pure-embedding`目标会触发前面的自定义命令。

# 检测 BLAS 和 LAPACK 数学库

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-04`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-04)找到，并包含一个 C++示例。本食谱适用于 CMake 版本 3.5（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

许多数值代码严重依赖于矩阵和向量运算。例如，考虑矩阵-向量和矩阵-矩阵乘积、线性方程组的解、特征值和特征向量的计算或奇异值分解。这些操作可能在代码库中无处不在，或者必须在大数据集上运行，以至于高效的实现变得绝对必要。幸运的是，有专门为此目的的库：基本线性代数子程序（BLAS）和线性代数包（LAPACK）提供了*标准*API，用于涉及线性代数操作的许多任务。不同的供应商提供不同的实现，但它们都共享相同的 API。尽管数学库底层实现所用的实际编程语言随时间而变化（Fortran、C、汇编），但留下的历史痕迹是 Fortran 调用约定。在本食谱中，我们的任务将是链接到这些库，并展示如何无缝地使用用不同语言编写的库，考虑到上述调用约定。

# 准备工作

为了演示数学库的检测和链接，我们希望编译一个 C++程序，该程序接受矩阵维数作为命令行输入，生成一个随机方阵**A**，一个随机向量**b**，并解决随之而来的线性方程组：**Ax** = **b**。此外，我们将用一个随机因子缩放随机向量**b**。我们需要使用的子程序是来自 BLAS 的`DSCAL`，用于执行缩放，以及来自 LAPACK 的`DGESV`，用于找到线性方程组的解。示例 C++代码的列表包含在（`linear-algebra.cpp`）中：

```cpp
#include "CxxBLAS.hpp"
#include "CxxLAPACK.hpp"

#include <iostream>
#include <random>
#include <vector>

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cout << "Usage: ./linear-algebra dim" << std::endl;
    return EXIT_FAILURE;
  }

  // Generate a uniform distribution of real number between -1.0 and 1.0
  std::random_device rd;
  std::mt19937 mt(rd());
  std::uniform_real_distribution<double> dist(-1.0, 1.0);

  // Allocate matrices and right-hand side vector
  int dim = std::atoi(argv[1]);
  std::vector<double> A(dim * dim);
  std::vector<double> b(dim);
  std::vector<int> ipiv(dim);
  // Fill matrix and RHS with random numbers between -1.0 and 1.0
  for (int r = 0; r < dim; r++) {
    for (int c = 0; c < dim; c++) {
      A[r + c * dim] = dist(mt);
    }
    b[r] = dist(mt);
  }

  // Scale RHS vector by a random number between -1.0 and 1.0
  C_DSCAL(dim, dist(mt), b.data(), 1);
  std::cout << "C_DSCAL done" << std::endl;

  // Save matrix and RHS
  std::vector<double> A1(A);
  std::vector<double> b1(b);

  int info;
  info = C_DGESV(dim, 1, A.data(), dim, ipiv.data(), b.data(), dim);
  std::cout << "C_DGESV done" << std::endl;
  std::cout << "info is " << info << std::endl;

  double eps = 0.0;
  for (int i = 0; i < dim; ++i) {
    double sum = 0.0;
    for (int j = 0; j < dim; ++j)
      sum += A1[i + j * dim] * b[j];
    eps += std::abs(b1[i] - sum);
  }
  std::cout << "check is " << eps << std::endl;

  return 0;
}
```

我们使用 C++11 中引入的随机库来生成-1.0 到 1.0 之间的随机分布。`C_DSCAL`和`C_DGESV`是 BLAS 和 LAPACK 库的接口，分别负责名称修饰，以便从不同的编程语言调用这些函数。这是在以下接口文件中与我们将进一步讨论的 CMake 模块结合完成的。

文件`CxxBLAS.hpp`使用`extern "C"`链接包装 BLAS 例程：

```cpp
#pragma once

#include "fc_mangle.h"

#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

extern void DSCAL(int *n, double *alpha, double *vec, int *inc);

#ifdef __cplusplus
}
#endif

void C_DSCAL(size_t length, double alpha, double *vec, int inc);
```

相应的实现文件`CxxBLAS.cpp`包含：

```cpp
#include "CxxBLAS.hpp"

#include <climits>

// see http://www.netlib.no/netlib/blas/dscal.f
void C_DSCAL(size_t length, double alpha, double *vec, int inc) {
  int big_blocks = (int)(length / INT_MAX);
  int small_size = (int)(length % INT_MAX);
  for (int block = 0; block <= big_blocks; block++) {
    double *vec_s = &vec[block * inc * (size_t)INT_MAX];
    signed int length_s = (block == big_blocks) ? small_size : INT_MAX;
    ::DSCAL(&length_s, &alpha, vec_s, &inc);
  }
}
```

文件`CxxLAPACK.hpp`和`CxxLAPACK.cpp`为 LAPACK 调用执行相应的翻译。

# 如何做到这一点

相应的`CMakeLists.txt`包含以下构建块：

1.  我们定义了最小 CMake 版本、项目名称和支持的语言：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-04 LANGUAGES CXX C Fortran)
```

1.  我们要求使用 C++11 标准：

```cpp
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  此外，我们验证 Fortran 和 C/C++编译器是否能协同工作，并生成处理名称修饰的头部文件。这两项功能均由`FortranCInterface`模块提供：

```cpp
include(FortranCInterface)

FortranCInterface_VERIFY(CXX)

FortranCInterface_HEADER(
 fc_mangle.h
 MACRO_NAMESPACE "FC_"
 SYMBOLS DSCAL DGESV
 )
```

1.  然后，我们要求 CMake 查找 BLAS 和 LAPACK。这些是必需的依赖项：

```cpp
find_package(BLAS REQUIRED)
find_package(LAPACK REQUIRED)
```

1.  接下来，我们添加一个包含我们源代码的库，用于 BLAS 和 LAPACK 包装器，并链接到`LAPACK_LIBRARIES`，这也引入了`BLAS_LIBRARIES`：

```cpp
add_library(math "")

target_sources(math
  PRIVATE
    CxxBLAS.cpp
    CxxLAPACK.cpp
  )

target_include_directories(math
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
  )

target_link_libraries(math
  PUBLIC
    ${LAPACK_LIBRARIES}
  )
```

1.  注意，该目标的包含目录和链接库被声明为`PUBLIC`，因此任何依赖于数学库的额外目标也会在其包含目录中设置这些目录。

1.  最后，我们添加一个可执行目标，并链接到`math`：

```cpp
add_executable(linear-algebra "")

target_sources(linear-algebra
  PRIVATE
    linear-algebra.cpp
  )

target_link_libraries(linear-algebra
  PRIVATE
    math
  )
```

1.  在配置步骤中，我们可以专注于相关的输出：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..

...
-- Detecting Fortran/C Interface
-- Detecting Fortran/C Interface - Found GLOBAL and MODULE mangling
-- Verifying Fortran/C Compiler Compatibility
-- Verifying Fortran/C Compiler Compatibility - Success
...
-- Found BLAS: /usr/lib/libblas.so 
...
-- A library with LAPACK API found.
...
```

1.  最后，我们构建并测试可执行文件：

```cpp
$ cmake --build .
$ ./linear-algebra 1000

C_DSCAL done
C_DGESV done
info is 0
check is 1.54284e-10
```

# 它是如何工作的

`FindBLAS.cmake`和`FindLAPACK.cmake`将在标准位置查找提供标准 BLAS 和 LAPACK API 的库。对于前者，模块将查找 Fortran 实现的`SGEMM`函数，用于单精度矩阵-矩阵乘法，适用于一般矩阵。对于后者，模块搜索 Fortran 实现的`CHEEV`函数，用于计算复数、Hermitian 矩阵的特征值和特征向量。这些查找是通过内部编译一个调用这些函数的小程序并尝试链接到候选库来执行的。如果失败，则表明系统上没有符合要求的库。

每个编译器在生成机器代码时都会对符号进行名称混淆，不幸的是，这项操作的约定不是通用的，而是编译器依赖的。为了克服这个困难，我们使用了`FortranCInterface`模块（[`cmake.org/cmake/help/v3.5/module/FortranCInterface.html`](https://cmake.org/cmake/help/v3.5/module/FortranCInterface.html)）来验证 Fortran 和 C/C++编译器是否能协同工作，并生成一个与所讨论编译器兼容的 Fortran-C 接口头文件`fc_mangle.h`。生成的`fc_mangle.h`然后必须包含在接口头文件`CxxBLAS.hpp`和`CxxLAPACK.hpp`中。为了使用`FortranCInterface`，我们不得不在`LANGUAGES`列表中添加 C 和 Fortran 支持。当然，我们可以定义自己的预处理器定义，但代价是有限的移植性。

我们将在第九章，*混合语言项目*中更详细地讨论 Fortran 和 C 的互操作性。

如今，许多 BLAS 和 LAPACK 的实现已经附带了一个围绕 Fortran 子程序的薄 C 层包装器。这些包装器多年来已经标准化，被称为 CBLAS 和 LAPACKE。

# 还有更多内容

许多数值代码严重依赖于矩阵代数操作，正确地链接到高性能的 BLAS 和 LAPACK API 实现非常重要。不同供应商在不同架构和并行环境下打包其库的方式存在很大差异。`FindBLAS.cmake`和`FindLAPACK.cmake`很可能无法在所有可能的情况下定位现有的库。如果发生这种情况，您可以通过 CLI 的`-D`选项显式设置库。

# 检测 OpenMP 并行环境

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-05`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-05)找到，并包含 C++和 Fortran 示例。该食谱适用于 CMake 版本 3.9（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-05`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-05)，我们还提供了与 CMake 3.5 兼容的示例。

如今，市场上的基本任何计算机都是多核机器，对于专注于性能的程序，我们可能需要关注这些多核 CPU，并在我们的编程模型中使用并发。OpenMP 是多核 CPU 共享内存并行性的标准。现有的程序通常不需要进行根本性的修改或重写，以从 OpenMP 并行化中受益。一旦在代码中确定了性能关键部分，例如使用分析工具，程序员可以添加预处理器指令，这些指令将指示编译器为这些区域生成并行代码。

在本教程中，我们将展示如何编译包含 OpenMP 指令的程序，前提是我们使用的是支持 OpenMP 的编译器。许多 Fortran、C 和 C++编译器都可以利用 OpenMP 的并行性。CMake 对 C、C++或 Fortran 的相对较新版本提供了非常好的 OpenMP 支持。本教程将向您展示如何在使用 CMake 3.9 或更高版本时，为简单的 C++和 Fortran 程序检测并链接 OpenMP 使用导入的目标。

根据 Linux 发行版的不同，默认版本的 Clang 编译器可能不支持 OpenMP。本教程**不适用于**macOS，除非使用单独的 libomp 安装（[`iscinumpy.gitlab.io/post/omp-on-high-sierra/`](https://iscinumpy.gitlab.io/post/omp-on-high-sierra/)）或非 Apple 版本的 Clang（例如，由 Conda 提供）或 GNU 编译器。

# 准备工作

C 和 C++程序可以通过包含`omp.h`头文件并链接正确的库来访问 OpenMP 功能。编译器将根据性能关键部分之前的预处理器指令生成并行代码。在本教程中，我们将构建以下示例源代码（`example.cpp`）。该代码将 1 到*N*的整数求和，其中*N*作为命令行参数给出：

```cpp
#include <iostream>
#include <omp.h>
#include <string>

int main(int argc, char *argv[]) {
  std::cout << "number of available processors: " << omp_get_num_procs()
            << std::endl;
  std::cout << "number of threads: " << omp_get_max_threads() << std::endl;

  auto n = std::stol(argv[1]);
  std::cout << "we will form sum of numbers from 1 to " << n << std::endl;

  // start timer
  auto t0 = omp_get_wtime();

  auto s = 0LL;
#pragma omp parallel for reduction(+ : s)
  for (auto i = 1; i <= n; i++) {
    s += i;
  }

  // stop timer
  auto t1 = omp_get_wtime();

  std::cout << "sum: " << s << std::endl;
  std::cout << "elapsed wall clock time: " << t1 - t0 << " seconds" << std::endl;

  return 0;
}
```

在 Fortran 中，需要使用`omp_lib`模块并链接到正确的库。在性能关键部分之前的代码注释中再次可以使用并行指令。相应的`example.F90`包含以下内容：

```cpp
program example

  use omp_lib

  implicit none

  integer(8) :: i, n, s
  character(len=32) :: arg
  real(8) :: t0, t1

  print *, "number of available processors:", omp_get_num_procs()
  print *, "number of threads:", omp_get_max_threads()

  call get_command_argument(1, arg)
  read(arg , *) n

  print *, "we will form sum of numbers from 1 to", n

  ! start timer
  t0 = omp_get_wtime()

  s = 0
!$omp parallel do reduction(+:s)
  do i = 1, n
    s = s + i
  end do

  ! stop timer
  t1 = omp_get_wtime()

  print *, "sum:", s
  print *, "elapsed wall clock time (seconds):", t1 - t0

end program
```

# 如何操作

我们的 C++和 Fortran 示例的`CMakeLists.txt`将遵循一个在两种语言之间大体相似的模板：

1.  两者都定义了最小 CMake 版本、项目名称和语言（`CXX`或`Fortran`；我们将展示 C++版本）：

```cpp
cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(recipe-05 LANGUAGES CXX)
```

1.  对于 C++示例，我们需要 C++11 标准：

```cpp
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  两者都调用`find_package`来搜索 OpenMP：

```cpp
find_package(OpenMP REQUIRED)
```

1.  最后，我们定义可执行目标并链接到`FindOpenMP`模块提供的导入目标（在 Fortran 情况下，我们链接到`OpenMP::OpenMP_Fortran`）：

```cpp
add_executable(example example.cpp)

target_link_libraries(example
  PUBLIC
    OpenMP::OpenMP_CXX
  )
```

1.  现在，我们可以配置并构建代码：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
```

1.  首先让我们在并行环境下测试一下（本例中使用四个核心）：

```cpp
$ ./example 1000000000

number of available processors: 4
number of threads: 4
we will form sum of numbers from 1 to 1000000000
sum: 500000000500000000
elapsed wall clock time: 1.08343 seconds
```

1.  为了比较，我们可以将示例重新运行，将 OpenMP 线程数设置为 1：

```cpp
$ env OMP_NUM_THREADS=1 ./example 1000000000

number of available processors: 4
number of threads: 1
we will form sum of numbers from 1 to 1000000000
sum: 500000000500000000
elapsed wall clock time: 2.96427 seconds
```

# 它是如何工作的

我们的简单示例似乎有效：代码已编译并链接，并且在运行于多个核心时我们观察到了加速。加速不是`OMP_NUM_THREADS`的完美倍数并不是本教程的关注点，因为我们专注于需要 OpenMP 的项目中的 CMake 方面。我们发现由于`FindOpenMP`模块提供的导入目标，链接 OpenMP 极其简洁：

```cpp
target_link_libraries(example
  PUBLIC
    OpenMP::OpenMP_CXX
  )
```

我们不必担心编译标志或包含目录——这些设置和依赖关系都编码在库`OpenMP::OpenMP_CXX`的定义中，该库属于`IMPORTED`类型。正如我们在第 3 个配方中提到的，*构建和链接静态和共享库*，在第一章，*从简单的可执行文件到库*中，`IMPORTED`库是伪目标，它们完全编码了外部依赖的使用要求。要使用 OpenMP，需要设置编译器标志、包含目录和链接库。所有这些都作为属性设置在`OpenMP::OpenMP_CXX`目标上，并通过使用`target_link_libraries`命令间接应用于我们的`example`目标。这使得在我们的 CMake 脚本中使用库变得非常容易。我们可以使用`cmake_print_properties`命令打印接口的属性，该命令由`CMakePrintHelpers.cmake`标准模块提供：

```cpp
include(CMakePrintHelpers)
cmake_print_properties(
  TARGETS
    OpenMP::OpenMP_CXX
  PROPERTIES
    INTERFACE_COMPILE_OPTIONS
    INTERFACE_INCLUDE_DIRECTORIES
    INTERFACE_LINK_LIBRARIES
  )
```

请注意，所有感兴趣的属性都带有前缀`INTERFACE_`，因为这些属性的使用要求适用于任何希望*接口*并使用 OpenMP 目标的目标。

对于 CMake 版本低于 3.9 的情况，我们需要做更多的工作：

```cpp
add_executable(example example.cpp)

target_compile_options(example
  PUBLIC
    ${OpenMP_CXX_FLAGS}
  )

set_target_properties(example
  PROPERTIES
    LINK_FLAGS ${OpenMP_CXX_FLAGS}
  )
```

对于 CMake 版本低于 3.5 的情况，我们可能需要为 Fortran 项目明确定义编译标志。

在本配方中，我们讨论了 C++和 Fortran，但论点和方法同样适用于 C 项目。

# 检测 MPI 并行环境

本配方的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-06`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-06)找到，并包含 C++和 C 的示例。该配方适用于 CMake 版本 3.9（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-06`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-06)，我们还提供了一个与 CMake 3.5 兼容的 C 示例。

与 OpenMP 共享内存并行性的一种替代且通常互补的方法是消息传递接口（MPI），它已成为在分布式内存系统上并行执行程序的*事实*标准。尽管现代 MPI 实现也允许共享内存并行性，但在高性能计算中，典型的方法是使用 OpenMP 在计算节点内结合 MPI 跨计算节点。MPI 标准的实现包括以下内容：

1.  运行时库。

1.  头文件和 Fortran 90 模块。

1.  编译器包装器，它调用用于构建 MPI 库的编译器，并带有额外的命令行参数来处理包含目录和库。通常，可用的编译器包装器包括`mpic++`/`mpiCC`/`mpicxx`用于 C++，`mpicc`用于 C，以及`mpifort`用于 Fortran。

1.  MPI 启动器：这是您应该调用的程序，用于启动编译代码的并行执行。其名称取决于实现，通常是以下之一：`mpirun`、`mpiexec`或`orterun`。

本示例将展示如何在系统上找到合适的 MPI 实现，以便编译简单的 MPI“Hello, World”程序。

# 准备工作

本示例代码（`hello-mpi.cpp`，从[`www.mpitutorial.com`](http://www.mpitutorial.com)下载），我们将在本示例中编译，将初始化 MPI 库，让每个进程打印其名称，并最终关闭库：

```cpp
#include <iostream>

#include <mpi.h>

int main(int argc, char **argv) {
  // Initialize the MPI environment. The two arguments to MPI Init are not
  // currently used by MPI implementations, but are there in case future
  // implementations might need the arguments.
  MPI_Init(NULL, NULL);

  // Get the number of processes
  int world_size;
  MPI_Comm_size(MPI_COMM_WORLD, &world_size);

  // Get the rank of the process
  int world_rank;
  MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);

  // Get the name of the processor
  char processor_name[MPI_MAX_PROCESSOR_NAME];
  int name_len;
  MPI_Get_processor_name(processor_name, &name_len);

  // Print off a hello world message
  std::cout << "Hello world from processor " << processor_name << ", rank "
            << world_rank << " out of " << world_size << " processors" << std::endl;

  // Finalize the MPI environment. No more MPI calls can be made after this
  MPI_Finalize();
}
```

# 如何操作

在本示例中，我们旨在找到 MPI 实现：库、头文件、编译器包装器和启动器。为此，我们将利用`FindMPI.cmake`标准 CMake 模块：

1.  首先，我们定义最小 CMake 版本、项目名称、支持的语言和语言标准：

```cpp
cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(recipe-06 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  然后我们调用`find_package`来定位 MPI 实现：

```cpp
find_package(MPI REQUIRED)
```

1.  我们定义可执行文件的名称和源代码，并且与前面的示例类似，链接到导入的目标：

```cpp
add_executable(hello-mpi hello-mpi.cpp)

target_link_libraries(hello-mpi
  PUBLIC
    MPI::MPI_CXX
  )
```

1.  让我们配置并构建可执行文件：

```cpp
$ mkdir -p build
$ cd build
$ cmake -D CMAKE_CXX_COMPILER=mpicxx ..

-- ...
-- Found MPI_CXX: /usr/lib/openmpi/libmpi_cxx.so (found version "3.1") 
```

```cpp
-- Found MPI: TRUE (found version "3.1")
-- ...

$ cmake --build .
```

1.  为了并行执行此程序，我们使用`mpirun`启动器（在这种情况下，使用两个任务）：

```cpp
$ mpirun -np 2 ./hello-mpi

Hello world from processor larry, rank 1 out of 2 processors
Hello world from processor larry, rank 0 out of 2 processors
```

# 工作原理

请记住，编译器包装器是围绕编译器的一层薄层，用于构建 MPI 库。在底层，它将调用相同的编译器，并为其添加额外的参数，如包含路径和库，以成功构建并行程序。

包装器在编译和链接源文件时实际应用哪些标志？我们可以使用编译器包装器的`--showme`选项来探测这一点。要找出编译器标志，我们可以使用：

```cpp
$ mpicxx --showme:compile

-pthread
```

要找出链接器标志，我们使用以下方法：

```cpp
$ mpicxx --showme:link

-pthread -Wl,-rpath -Wl,/usr/lib/openmpi -Wl,--enable-new-dtags -L/usr/lib/openmpi -lmpi_cxx -lmpi
```

与前一个 OpenMP 示例类似，我们发现链接到 MPI 非常简洁，这得益于相对现代的`FindMPI`模块提供的导入目标：

```cpp
target_link_libraries(hello-mpi
  PUBLIC
    MPI::MPI_CXX
 )
```

我们不必担心编译标志或包含目录 - 这些设置和依赖关系已经作为`INTERFACE`类型属性编码在 CMake 提供的`IMPORTED`目标中。

正如在前一个示例中讨论的，对于 CMake 版本低于 3.9 的情况，我们需要做更多的工作：

```cpp
add_executable(hello-mpi hello-mpi.c)

target_compile_options(hello-mpi
  PUBLIC
    ${MPI_CXX_COMPILE_FLAGS}
  )

target_include_directories(hello-mpi
  PUBLIC
    ${MPI_CXX_INCLUDE_PATH}
  )

target_link_libraries(hello-mpi
  PUBLIC
    ${MPI_CXX_LIBRARIES}
  )
```

在本示例中，我们讨论了 C++，但参数和方法同样适用于 C 或 Fortran 项目。

# 检测 Eigen 库

本示例的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-07`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-07)找到，包含一个 C++示例。本示例适用于 CMake 版本 3.9（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-07`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-07)，我们还提供了一个与 CMake 3.5 兼容的 C++示例。

BLAS 库为涉及矩阵和向量的常见操作提供了一个标准化的接口。然而，这个接口是针对 Fortran 语言标准化的。虽然我们已经展示了如何从 C++中或多或少直接使用这些库，但在现代 C++程序中可能希望有一个更高层次的接口。

Eigen 库作为头文件使用模板编程来提供这样的接口。其矩阵和向量类型易于使用，甚至在编译时提供类型检查，以确保不混合不兼容的矩阵维度。密集和稀疏矩阵操作，如矩阵-矩阵乘积、线性系统求解器和特征值问题，也使用表达式模板实现效率。从版本 3.3 开始，Eigen 可以链接到 BLAS 和 LAPACK 库，这提供了灵活性，可以将某些操作卸载到这些库中提供的实现以获得额外的性能。

本配方将展示如何找到 Eigen 库，并指示它使用 OpenMP 并行化并将部分工作卸载到 BLAS 库。

# 准备就绪

在本例中，我们将编译一个程序，该程序分配一个随机方阵和从命令行传递的维度的向量。然后，我们将使用 LU 分解求解线性系统**Ax**=**b**。我们将使用以下源代码（`linear-algebra.cpp`）：

```cpp
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <vector>

#include <Eigen/Dense>

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cout << "Usage: ./linear-algebra dim" << std::endl;
    return EXIT_FAILURE;
  }

  std::chrono::time_point<std::chrono::system_clock> start, end;
  std::chrono::duration<double> elapsed_seconds;
  std::time_t end_time;

  std::cout << "Number of threads used by Eigen: " << Eigen::nbThreads()
            << std::endl;

  // Allocate matrices and right-hand side vector
  start = std::chrono::system_clock::now();
  int dim = std::atoi(argv[1]);
  Eigen::MatrixXd A = Eigen::MatrixXd::Random(dim, dim);
  Eigen::VectorXd b = Eigen::VectorXd::Random(dim);
  end = std::chrono::system_clock::now();

  // Report times
  elapsed_seconds = end - start;
  end_time = std::chrono::system_clock::to_time_t(end);
  std::cout << "matrices allocated and initialized "
            << std::put_time(std::localtime(&end_time), "%a %b %d %Y   
%r\n")
            << "elapsed time: " << elapsed_seconds.count() << "s\n";

  start = std::chrono::system_clock::now();
  // Save matrix and RHS
  Eigen::MatrixXd A1 = A;
  Eigen::VectorXd b1 = b;
  end = std::chrono::system_clock::now();
  end_time = std::chrono::system_clock::to_time_t(end);
  std::cout << "Scaling done, A and b saved "
            << std::put_time(std::localtime(&end_time), "%a %b %d %Y %r\n")
            << "elapsed time: " << elapsed_seconds.count() << "s\n";

  start = std::chrono::system_clock::now();
  Eigen::VectorXd x = A.lu().solve(b);
  end = std::chrono::system_clock::now();

  // Report times
  elapsed_seconds = end - start;
  end_time = std::chrono::system_clock::to_time_t(end);

  double relative_error = (A * x - b).norm() / b.norm();

  std::cout << "Linear system solver done "
            << std::put_time(std::localtime(&end_time), "%a %b %d %Y %r\n")
            << "elapsed time: " << elapsed_seconds.count() << "s\n";
  std::cout << "relative error is " << relative_error << std::endl;

  return 0;
}
```

矩阵-向量乘法和 LU 分解在 Eigen 中实现，但可以选择卸载到 BLAS 和 LAPACK 库。在本配方中，我们只考虑卸载到 BLAS 库。

# 如何做到这一点

在本项目中，我们将找到 Eigen 和 BLAS 库，以及 OpenMP，并指示 Eigen 使用 OpenMP 并行化，并将部分线性代数工作卸载到 BLAS 库：

1.  我们首先声明 CMake 的最低版本、项目名称以及使用 C++11 语言：

```cpp
cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(recipe-07 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  我们还请求 OpenMP，因为 Eigen 可以利用共享内存并行性进行密集操作：

```cpp
find_package(OpenMP REQUIRED)
```

1.  我们通过调用`find_package`在`CONFIG`模式下搜索 Eigen（我们将在下一节讨论这一点）：

```cpp
find_package(Eigen3 3.3 REQUIRED CONFIG)
```

1.  如果找到 Eigen，我们会打印出有帮助的状态消息。请注意，我们正在使用`Eigen3::Eigen`目标。正如我们在前两个配方中学到的，这是一个`IMPORTED`目标，由 Eigen 分发的原生 CMake 脚本提供：

```cpp
if(TARGET Eigen3::Eigen)
  message(STATUS "Eigen3 v${EIGEN3_VERSION_STRING} found in ${EIGEN3_INCLUDE_DIR}")
endif()
```

1.  接下来，我们为我们的源文件声明一个可执行目标：

```cpp
add_executable(linear-algebra linear-algebra.cpp)
```

1.  然后我们找到 BLAS。请注意，依赖项现在不是必需的：

```cpp
find_package(BLAS)
```

1.  如果找到 BLAS，我们为可执行目标设置相应的编译定义和链接库：

```cpp
if(BLAS_FOUND)
  message(STATUS "Eigen will use some subroutines from BLAS.")
  message(STATUS "See: http://eigen.tuxfamily.org/dox-devel/TopicUsingBlasLapack.html")
  target_compile_definitions(linear-algebra
    PRIVATE
      EIGEN_USE_BLAS
    )
  target_link_libraries(linear-algebra
    PUBLIC
      ${BLAS_LIBRARIES}
    )
else()
  message(STATUS "BLAS not found. Using Eigen own functions")
endif()
```

1.  最后，我们链接到导入的`Eigen3::Eigen`和`OpenMP::OpenMP_CXX`目标。这足以设置所有必要的编译和链接标志：

```cpp
target_link_libraries(linear-algebra
  PUBLIC
    Eigen3::Eigen
    OpenMP::OpenMP_CXX
  )
```

1.  我们现在已经准备好配置项目：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..

-- ...
-- Found OpenMP_CXX: -fopenmp (found version "4.5") 
-- Found OpenMP: TRUE (found version "4.5") 
-- Eigen3 v3.3.4 found in /usr/include/eigen3
-- ...
-- Found BLAS: /usr/lib/libblas.so 
-- Eigen will use some subroutines from BLAS.
-- See: http://eigen.tuxfamily.org/dox-devel/TopicUsingBlasLapack.html
```

1.  最后，我们编译并测试代码。请注意，在这种情况下，二进制文件使用了四个可用线程：

```cpp
$ cmake --build .
$ ./linear-algebra 1000

Number of threads used by Eigen: 4
matrices allocated and initialized Sun Jun 17 2018 11:04:20 AM
elapsed time: 0.0492328s
Scaling done, A and b saved Sun Jun 17 2018 11:04:20 AM
elapsed time: 0.0492328s
Linear system solver done Sun Jun 17 2018 11:04:20 AM
elapsed time: 0.483142s
relative error is 4.21946e-13
```

# 它是如何工作的

Eigen 提供了原生的 CMake 支持，这使得使用它来设置 C++ 项目变得简单。从版本 3.3 开始，Eigen 提供了 CMake 模块，导出适当的 target，即 `Eigen3::Eigen`，我们在这里使用了它。

您可能已经注意到 `find_package` 命令的 `CONFIG` 选项。这向 CMake 发出信号，表明包搜索不会通过 `FindEigen3.cmake` 模块进行，而是通过 Eigen3 包在标准位置提供的 `Eigen3Config.cmake`、`Eigen3ConfigVersion.cmake` 和 `Eigen3Targets.cmake` 文件进行，即 `<installation-prefix>/share/eigen3/cmake`。这种包位置模式称为“Config”模式，比我们迄今为止使用的 `Find<package>.cmake` 方法更灵活。有关“Module”模式与“Config”模式的更多信息，请查阅官方文档：[`cmake.org/cmake/help/v3.5/command/find_package.html`](https://cmake.org/cmake/help/v3.5/command/find_package.html)。

还要注意，尽管 Eigen3、BLAS 和 OpenMP 依赖项被声明为 `PUBLIC` 依赖项，但 `EIGEN_USE_BLAS` 编译定义被声明为 `PRIVATE`。我们不是直接链接可执行文件，而是可以将库依赖项收集到一个单独的库目标中。使用 `PUBLIC`/`PRIVATE` 关键字，我们可以调整相应标志和定义对库目标依赖项的可见性。

# 还有更多

CMake 会在预定义的位置层次结构中查找配置模块。首先是 `CMAKE_PREFIX_PATH`，而 `<package>_DIR` 是下一个搜索路径。因此，如果 Eigen3 安装在非标准位置，我们可以使用两种替代方法来告诉 CMake 在哪里查找它：

1.  通过传递 Eigen3 的安装前缀作为 `CMAKE_PREFIX_PATH`：

```cpp
$ cmake -D CMAKE_PREFIX_PATH=<installation-prefix> ..
```

1.  通过传递配置文件的位置作为 `Eigen3_DIR`：

```cpp
$ cmake -D Eigen3_DIR=<installation-prefix>/share/eigen3/cmake/
```

# 检测 Boost 库

本食谱的代码可在 [`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-08`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-08) 获取，并包含一个 C++ 示例。该食谱适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

Boost 库是一系列通用目的的 C++ 库。这些库提供了许多现代 C++ 项目中可能必不可少的特性，而这些特性在 C++ 标准中尚未提供。例如，Boost 提供了元编程、处理可选参数和文件系统操作等组件。许多这些库后来被 C++11、C++14 和 C++17 标准采纳，但对于需要保持与旧编译器兼容性的代码库，许多 Boost 组件仍然是首选库。

本食谱将向您展示如何检测并链接 Boost 库的某些组件。

# 准备就绪

我们将编译的源代码是 Boost 提供的文件系统库的示例之一，用于与文件系统交互。该库方便地跨平台，并将操作系统与文件系统的差异抽象成一个连贯的高级 API。以下示例代码（`path-info.cpp`）将接受一个路径作为参数，并将其组件的报告打印到屏幕上：

```cpp
#include <iostream>

#include <boost/filesystem.hpp>

using namespace std;
using namespace boost::filesystem;

const char *say_what(bool b) { return b ? "true" : "false"; }

int main(int argc, char *argv[]) {
  if (argc < 2) {
    cout
        << "Usage: path_info path-element [path-element...]\n"
           "Composes a path via operator/= from one or more path-element arguments\n"
           "Example: path_info foo/bar baz\n"
#ifdef BOOST_POSIX_API
           " would report info about the composed path foo/bar/baz\n";
#else // BOOST_WINDOWS_API
           " would report info about the composed path foo/bar\\baz\n";
#endif
    return 1;
  }

  path p;
  for (; argc > 1; --argc, ++argv)
    p /= argv[1]; // compose path p from the command line arguments

  cout << "\ncomposed path:\n";
  cout << " operator<<()---------: " << p << "\n";
  cout << " make_preferred()-----: " << p.make_preferred() << "\n";

  cout << "\nelements:\n";
  for (auto element : p)
    cout << " " << element << '\n';

  cout << "\nobservers, native format:" << endl;
#ifdef BOOST_POSIX_API
  cout << " native()-------------: " << p.native() << endl;
  cout << " c_str()--------------: " << p.c_str() << endl;
#else // BOOST_WINDOWS_API
  wcout << L" native()-------------: " << p.native() << endl;
  wcout << L" c_str()--------------: " << p.c_str() << endl;
#endif
  cout << " string()-------------: " << p.string() << endl;
  wcout << L" wstring()------------: " << p.wstring() << endl;

  cout << "\nobservers, generic format:\n";
  cout << " generic_string()-----: " << p.generic_string() << endl;
  wcout << L" generic_wstring()----: " << p.generic_wstring() << endl;

  cout << "\ndecomposition:\n";
  cout << " root_name()----------: " << p.root_name() << '\n';
  cout << " root_directory()-----: " << p.root_directory() << '\n';
  cout << " root_path()----------: " << p.root_path() << '\n';
  cout << " relative_path()------: " << p.relative_path() << '\n';
  cout << " parent_path()--------: " << p.parent_path() << '\n';
  cout << " filename()-----------: " << p.filename() << '\n';
  cout << " stem()---------------: " << p.stem() << '\n';
  cout << " extension()----------: " << p.extension() << '\n';

  cout << "\nquery:\n";
  cout << " empty()--------------: " << say_what(p.empty()) << '\n';
  cout << " is_absolute()--------: " << say_what(p.is_absolute()) << 
  '\n';
  cout << " has_root_name()------: " << say_what(p.has_root_name()) << 
  '\n';
  cout << " has_root_directory()-: " << say_what(p.has_root_directory()) << '\n';
  cout << " has_root_path()------: " << say_what(p.has_root_path()) << 
  '\n';
  cout << " has_relative_path()--: " << say_what(p.has_relative_path()) << '\n';
  cout << " has_parent_path()----: " << say_what(p.has_parent_path()) << '\n';
  cout << " has_filename()-------: " << say_what(p.has_filename()) << 
  '\n';
  cout << " has_stem()-----------: " << say_what(p.has_stem()) << '\n';
  cout << " has_extension()------: " << say_what(p.has_extension()) <<  
  '\n';

  return 0;
}
```

# 如何操作

Boost 包含许多不同的库，这些库几乎可以独立使用。在内部，CMake 将这个库集合表示为组件集合。`FindBoost.cmake`模块不仅可以搜索整个库集合的安装，还可以搜索集合中特定组件及其依赖项（如果有的话）。我们将逐步构建相应的`CMakeLists.txt`：

1.  我们首先声明了最低 CMake 版本、项目名称、语言，并强制使用 C++11 标准：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-08 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  然后，我们使用`find_package`来搜索 Boost。对 Boost 的依赖是强制性的，因此使用了`REQUIRED`参数。由于在本例中我们只需要文件系统组件，因此我们在`COMPONENTS`关键字后传递该组件作为参数给`find_package`：

```cpp
find_package(Boost 1.54 REQUIRED COMPONENTS filesystem)
```

1.  我们添加了一个可执行目标，用于编译示例源文件：

```cpp
add_executable(path-info path-info.cpp)
```

1.  最后，我们将目标链接到 Boost 库组件。由于依赖关系被声明为`PUBLIC`，依赖于我们目标的其他目标将自动获取该依赖关系：

```cpp
target_link_libraries(path-info
  PUBLIC
    Boost::filesystem
  )
```

# 工作原理

`FindBoost.cmake`模块，在本例中使用，将尝试在标准系统安装目录中定位 Boost 库。由于我们链接到导入的`Boost::filesystem`目标，CMake 将自动设置包含目录并调整编译和链接标志。如果 Boost 库安装在非标准位置，可以在配置时使用`BOOST_ROOT`变量传递 Boost 安装的根目录，以指示 CMake 也在非标准路径中搜索：

```cpp
$ cmake -D BOOST_ROOT=/custom/boost/
```

或者，可以同时传递`BOOST_INCLUDEDIR`和`BOOST_LIBRARYDIR`变量，以指定包含头文件和库的目录：

```cpp
$ cmake -D BOOST_INCLUDEDIR=/custom/boost/include -D BOOST_LIBRARYDIR=/custom/boost/lib
```

# 检测外部库：I. 使用 pkg-config

本例的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-09`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-09)找到，并包含一个 C 语言示例。本例适用于 CMake 3.6（及以上）版本，并在 GNU/Linux、macOS 和 Windows（使用 MSYS Makefiles）上进行了测试。在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-09`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-09)，我们还提供了一个与 CMake 3.5 兼容的示例。

到目前为止，我们已经讨论了两种检测外部依赖的方法：

+   使用 CMake 附带的 find-modules。这通常是可靠且经过良好测试的。然而，并非所有包在 CMake 的官方发布版中都有一个 find-module。

+   使用包供应商提供的`<package>Config.cmake`、`<package>ConfigVersion.cmake`和`<package>Targets.cmake`文件，这些文件与包本身一起安装在标准位置。

如果某个依赖项既不提供 find-module 也不提供 vendor-packaged CMake 文件，我们该怎么办？在这种情况下，我们有两个选择：

+   依赖`pkg-config`实用程序来发现系统上的包。这依赖于包供应商在`.pc`配置文件中分发有关其包的元数据。

+   为依赖项编写我们自己的 find-package 模块。

在本食谱中，我们将展示如何从 CMake 内部利用`pkg-config`来定位 ZeroMQ 消息库。下一个食谱，*检测外部库：II. 编写 find-module*，将展示如何为 ZeroMQ 编写自己的基本 find-module。

# 准备工作

我们将构建的代码是 ZeroMQ 手册中的一个示例，网址为[`zguide.zeromq.org/page:all`](http://zguide.zeromq.org/page:all)。它由两个源文件`hwserver.c`和`hwclient.c`组成，将构建为两个单独的可执行文件。执行时，它们将打印熟悉的“Hello, World”消息。

# 如何操作

这是一个 C 项目，我们将使用 C99 标准。我们将逐步构建`CMakeLists.txt`文件：

1.  我们声明一个 C 项目并强制执行 C99 标准：

```cpp
cmake_minimum_required(VERSION 3.6 FATAL_ERROR)

project(recipe-09 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD_REQUIRED ON)
```

1.  我们查找`pkg-config`，使用 CMake 附带的 find-module。注意传递给`find_package`的`QUIET`参数。只有当所需的`pkg-config`未找到时，CMake 才会打印消息：

```cpp
find_package(PkgConfig REQUIRED QUIET)
```

1.  当找到`pkg-config`时，我们将能够访问`pkg_search_module`函数来搜索任何带有包配置`.pc`文件的库或程序。在我们的例子中，我们查找 ZeroMQ 库：

```cpp
pkg_search_module(
  ZeroMQ
  REQUIRED
    libzeromq libzmq lib0mq
  IMPORTED_TARGET
  )
```

1.  如果找到 ZeroMQ 库，将打印状态消息：

```cpp
if(TARGET PkgConfig::ZeroMQ)
  message(STATUS "Found ZeroMQ")
endif()
```

1.  然后我们可以添加两个可执行目标，并与 ZeroMQ 的`IMPORTED`目标链接。这将自动设置包含目录和链接库：

```cpp
add_executable(hwserver hwserver.c)

target_link_libraries(hwserver PkgConfig::ZeroMQ)

add_executable(hwclient hwclient.c)

target_link_libraries(hwclient PkgConfig::ZeroMQ)
```

1.  现在，我们可以配置并构建示例：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
```

1.  在一个终端中启动服务器，它将响应类似于以下示例的消息：

```cpp
Current 0MQ version is 4.2.2
```

1.  然后，在另一个终端启动客户端，它将打印以下内容：

```cpp
Connecting to hello world server…
Sending Hello 0…
Received World 0
Sending Hello 1…
Received World 1
Sending Hello 2…
...
```

# 工作原理

一旦找到`pkg-config`，CMake 将提供两个函数来封装这个程序提供的功能：

+   `pkg_check_modules`，用于在传递的列表中查找所有模块（库和/或程序）

+   `pkg_search_module`，用于在传递的列表中查找第一个可用的模块

这些函数接受`REQUIRED`和`QUIET`参数，就像`find_package`一样。更详细地说，我们对`pkg_search_module`的调用如下：

```cpp
pkg_search_module(
  ZeroMQ
  REQUIRED
    libzeromq libzmq lib0mq
  IMPORTED_TARGET
  )
```

这里，第一个参数是用于命名存储 ZeroMQ 库搜索结果的目标的前缀：`PkgConfig::ZeroMQ`。注意，我们需要为系统上的库名称传递不同的选项：`libzeromq`、`libzmq`和`lib0mq`。这是因为不同的操作系统和包管理器可能会为同一个包选择不同的名称。

`pkg_check_modules`和`pkg_search_module`函数在 CMake 3.6 中获得了`IMPORTED_TARGET`选项和定义导入目标的功能。在此之前的 CMake 版本中，只会为稍后使用定义变量`ZeroMQ_INCLUDE_DIRS`（包含目录）和`ZeroMQ_LIBRARIES`（链接库）。

# 检测外部库：II. 编写查找模块

本配方的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-10`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-03/recipe-10)获取，并包含一个 C 示例。本配方适用于 CMake 版本 3.5（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

本配方补充了之前的配方，*检测外部库：I. 使用 pkg-config*。我们将展示如何编写一个基本的查找模块来定位系统上的 ZeroMQ 消息库，以便在非 Unix 操作系统上进行库检测。我们将重用相同的服务器-客户端示例代码。

# 如何操作

这是一个 C 项目，我们将使用 C99 标准。我们将逐步构建`CMakeLists.txt`文件：

1.  我们声明一个 C 项目并强制执行 C99 标准：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-10 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD_REQUIRED ON)
```

1.  我们将当前源目录，`CMAKE_CURRENT_SOURCE_DIR`，添加到 CMake 查找模块的路径列表中，`CMAKE_MODULE_PATH`。这是我们自己的`FindZeroMQ.cmake`模块所在的位置：

```cpp
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
```

1.  我们稍后将讨论`FindZeroMQ.cmake`，但现在`FindZeroMQ.cmake`模块可用，我们搜索库。这是我们项目的必要依赖项。由于我们没有使用`find_package`的`QUIET`选项，当找到库时，将自动打印状态消息：

```cpp
find_package(ZeroMQ REQUIRED)
```

1.  我们继续添加`hwserver`可执行目标。使用`ZeroMQ_INCLUDE_DIRS`和`ZeroMQ_LIBRARIES`变量指定包含目录和链接库，这些变量由成功的`find_package`命令设置：

```cpp
add_executable(hwserver hwserver.c)

target_include_directories(hwserver
  PRIVATE
    ${ZeroMQ_INCLUDE_DIRS}
  )

target_link_libraries(hwserver
  PRIVATE
    ${ZeroMQ_LIBRARIES}
  )
```

1.  最后，我们对`hwclient`可执行目标也做同样的事情：

```cpp
add_executable(hwclient hwclient.c)

target_include_directories(hwclient
  PRIVATE
    ${ZeroMQ_INCLUDE_DIRS}
  )

target_link_libraries(hwclient
  PRIVATE
    ${ZeroMQ_LIBRARIES}
  )
```

本配方的主要`CMakeLists.txt`与之前配方中使用的不同之处在于使用了`FindZeroMQ.cmake`模块。该模块使用`find_path`和`find_library`CMake 内置命令搜索 ZeroMQ 头文件和库，并使用`find_package_handle_standard_args`设置相关变量，正如我们在配方 3 中所做的，*检测 Python 模块和包*。

1.  在`FindZeroMQ.cmake`中，我们首先检查用户是否设置了`ZeroMQ_ROOT` CMake 变量。此变量可用于指导检测 ZeroMQ 库到非标准安装目录。用户可能已经将`ZeroMQ_ROOT`设置为环境变量，我们也检查了这一点：

```cpp
if(NOT ZeroMQ_ROOT)
  set(ZeroMQ_ROOT "$ENV{ZeroMQ_ROOT}")
endif()
```

1.  然后，我们在系统上搜索`zmq.h`头文件的位置。这是基于`_ZeroMQ_ROOT`变量，并使用 CMake 的`find_path`命令：

```cpp
if(NOT ZeroMQ_ROOT)
  find_path(_ZeroMQ_ROOT NAMES include/zmq.h)
else()
  set(_ZeroMQ_ROOT "${ZeroMQ_ROOT}")
endif()

find_path(ZeroMQ_INCLUDE_DIRS NAMES zmq.h HINTS ${_ZeroMQ_ROOT}/include)
```

1.  如果成功找到头文件，则将`ZeroMQ_INCLUDE_DIRS`设置为其位置。我们继续查找可用的 ZeroMQ 库版本，使用字符串操作和正则表达式：

```cpp
set(_ZeroMQ_H ${ZeroMQ_INCLUDE_DIRS}/zmq.h)

function(_zmqver_EXTRACT _ZeroMQ_VER_COMPONENT _ZeroMQ_VER_OUTPUT)
  set(CMAKE_MATCH_1 "0")
  set(_ZeroMQ_expr "^[ \\t]*#define[ \\t]+${_ZeroMQ_VER_COMPONENT}[ \\t]+([0-9]+)$")
  file(STRINGS "${_ZeroMQ_H}" _ZeroMQ_ver REGEX "${_ZeroMQ_expr}")
  string(REGEX MATCH "${_ZeroMQ_expr}" ZeroMQ_ver "${_ZeroMQ_ver}")
  set(${_ZeroMQ_VER_OUTPUT} "${CMAKE_MATCH_1}" PARENT_SCOPE)
endfunction()

_zmqver_EXTRACT("ZMQ_VERSION_MAJOR" ZeroMQ_VERSION_MAJOR)
_zmqver_EXTRACT("ZMQ_VERSION_MINOR" ZeroMQ_VERSION_MINOR)
_zmqver_EXTRACT("ZMQ_VERSION_PATCH" ZeroMQ_VERSION_PATCH)
```

1.  然后，我们为`find_package_handle_standard_args`命令准备`ZeroMQ_VERSION`变量：

```cpp
if(ZeroMQ_FIND_VERSION_COUNT GREATER 2)
  set(ZeroMQ_VERSION "${ZeroMQ_VERSION_MAJOR}.${ZeroMQ_VERSION_MINOR}.${ZeroMQ_VERSION_PATCH}")
else()
  set(ZeroMQ_VERSION "${ZeroMQ_VERSION_MAJOR}.${ZeroMQ_VERSION_MINOR}")
endif()
```

1.  我们使用`find_library`命令来搜索`ZeroMQ`库。在这里，我们需要在 Unix 基础和 Windows 平台之间做出区分，因为库的命名约定不同：

```cpp
if(NOT ${CMAKE_C_PLATFORM_ID} STREQUAL "Windows")
  find_library(ZeroMQ_LIBRARIES 
      NAMES 
        zmq 
      HINTS 
        ${_ZeroMQ_ROOT}/lib
        ${_ZeroMQ_ROOT}/lib/x86_64-linux-gnu
      )
else()
  find_library(ZeroMQ_LIBRARIES
      NAMES
        libzmq
        "libzmq-mt-${ZeroMQ_VERSION_MAJOR}_${ZeroMQ_VERSION_MINOR}_${ZeroMQ_VERSION_PATCH}"
        "libzmq-${CMAKE_VS_PLATFORM_TOOLSET}-mt-${ZeroMQ_VERSION_MAJOR}_${ZeroMQ_VERSION_MINOR}_${ZeroMQ_VERSION_PATCH}"
        libzmq_d
        "libzmq-mt-gd-${ZeroMQ_VERSION_MAJOR}_${ZeroMQ_VERSION_MINOR}_${ZeroMQ_VERSION_PATCH}"
        "libzmq-${CMAKE_VS_PLATFORM_TOOLSET}-mt-gd-${ZeroMQ_VERSION_MAJOR}_${ZeroMQ_VERSION_MINOR}_${ZeroMQ_VERSION_PATCH}"
      HINTS
        ${_ZeroMQ_ROOT}/lib
      )
endif()
```

1.  最后，我们包含标准的`FindPackageHandleStandardArgs.cmake`模块并调用相应的 CMake 命令。如果找到所有必需的变量并且版本匹配，则将`ZeroMQ_FOUND`变量设置为`TRUE`：

```cpp
include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(ZeroMQ
  FOUND_VAR
    ZeroMQ_FOUND
  REQUIRED_VARS
```

```cpp
    ZeroMQ_INCLUDE_DIRS
    ZeroMQ_LIBRARIES
  VERSION_VAR
    ZeroMQ_VERSION
  )
```

我们刚才描述的`FindZeroMQ.cmake`模块是从[`github.com/zeromq/azmq/blob/master/config/FindZeroMQ.cmake`](https://github.com/zeromq/azmq/blob/master/config/FindZeroMQ.cmake)改编而来的。

# 它是如何工作的

查找模块通常遵循特定的模式：

1.  检查用户是否为所需包提供了自定义位置。

1.  使用`find_`家族的命令来搜索所需包的已知必需组件，即头文件、库、可执行文件等。我们已经使用`find_path`来找到头文件的完整路径，并使用`find_library`来找到一个库。CMake 还提供了`find_file`、`find_program`和`find_package`。这些命令具有以下一般签名：

```cpp
find_path(<VAR> NAMES name PATHS paths)
```

1.  在这里，`<VAR>`将持有搜索的结果，如果成功，或者`<VAR>-NOTFOUND`如果失败。`NAMES`和`PATHS`是 CMake 应该查找的文件的名称和搜索应该指向的路径，分别。

1.  从这次初步搜索的结果中，提取版本号。在我们的例子中，ZeroMQ 头文件包含库版本，可以使用字符串操作和正则表达式提取。

1.  最后，调用`find_package_handle_standard_args`命令。这将处理`find_package`命令的标准`REQUIRED`、`QUIET`和版本参数，此外还设置`ZeroMQ_FOUND`变量。

任何 CMake 命令的完整文档都可以从命令行获取。例如，`cmake --help-command find_file` 将输出 `find_file` 命令的手册页。对于 CMake 标准模块的手册页，使用 `--help-module` CLI 开关。例如，`cmake --help-module FindPackageHandleStandardArgs` 将屏幕输出 `FindPackageHandleStandardArgs.cmake` 模块的手册页。

# 还有更多

总结一下，在发现软件包时，有四种可用的路线：

1.  使用软件包供应商提供的 CMake 文件 `packageConfig.cmake`、`packageConfigVersion.cmake` 和 `packageTargets.cmake`，并将其安装在与软件包本身一起的标准位置。

1.  使用所需的软件包的 find-module，无论是由 CMake 还是第三方提供的。

1.  采用本食谱中所示的 `pkg-config` 方法。

1.  如果这些都不适用，编写自己的 find-module。

四种替代路线已经按相关性排名，但每种方法都有其挑战。

并非所有软件包供应商都提供 CMake 发现文件，但这变得越来越普遍。这是因为导出 CMake 目标使得第三方代码消费库和/或程序所依赖的额外依赖项变得非常容易。

Find-modules 自 CMake 诞生之初就是依赖定位的工作马。然而，它们中的大多数仍然依赖于设置由依赖方消费的变量，例如 `Boost_INCLUDE_DIRS`、`PYTHON_INTERPRETER` 等。这种方法使得为第三方重新分发自己的软件包并确保依赖项得到一致满足变得困难。

使用 `pkg-config` 的方法可以很好地工作，因为它已经成为基于 Unix 的系统的*事实*标准。因此，它不是一个完全跨平台的方法。此外，正如 CMake 文档所述，在某些情况下，用户可能会意外地覆盖软件包检测，导致 `pkg-config` 提供错误的信息。

最后的选择是编写自己的 find-module CMake 脚本，正如我们在本食谱中所做的那样。这是可行的，并且依赖于我们简要讨论过的 `FindPackageHandleStandardArgs.cmake` 模块。然而，编写一个完全全面的 find-module 远非易事；有许多难以发现的边缘情况，我们在寻找 Unix 和 Windows 平台上的 ZeroMQ 库文件时展示了这样一个例子。

这些关注点和困难对于所有软件开发者来说都非常熟悉，这一点在 CMake 邮件列表上的热烈讨论中得到了证明：[`cmake.org/pipermail/cmake/2018-May/067556.html`](https://cmake.org/pipermail/cmake/2018-May/067556.html)。`pkg-config`在 Unix 软件包开发者中被广泛接受，但它不容易移植到非 Unix 平台。CMake 配置文件功能强大，但并非所有软件开发者都熟悉 CMake 语法。Common Package Specification 项目是一个非常新的尝试，旨在统一`pkg-config`和 CMake 配置文件的软件包发现方法。您可以在项目网站上找到更多信息：[`mwoehlke.github.io/cps/`](https://mwoehlke.github.io/cps/)

在第十章《编写安装程序》中，我们将讨论如何通过使用前述讨论中概述的第一条路径，即在项目旁边提供自己的 CMake 发现文件，使您自己的软件包对第三方应用程序可发现。
