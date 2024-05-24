# CMake 秘籍（五）

> 原文：[`zh.annas-archive.org/md5/ecf89da6185e63c44e748e0980911fef`](https://zh.annas-archive.org/md5/ecf89da6185e63c44e748e0980911fef)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：超级构建模式

在本章中，我们将涵盖以下内容：

+   使用超级构建模式

+   使用超级构建管理依赖：I. Boost 库

+   使用超级构建管理依赖：II. FFTW 库

+   使用超级构建管理依赖：III. Google Test 框架

+   将项目作为超级构建进行管理

# 引言

每个项目都必须处理依赖关系，而 CMake 使得在配置项目的系统上查找这些依赖关系变得相对容易。第三章，*检测外部库和程序*，展示了如何在系统上找到已安装的依赖项，并且到目前为止我们一直使用相同的模式。然而，如果依赖关系未得到满足，我们最多只能导致配置失败并告知用户失败的原因。但是，使用 CMake，我们可以组织项目，以便在系统上找不到依赖项时自动获取和构建它们。本章将介绍和分析`ExternalProject.cmake`和`FetchContent.cmake`标准模块以及它们在*超级构建模式*中的使用。前者允许我们在*构建时间*获取项目的依赖项，并且长期以来一直是 CMake 的一部分。后者模块是在 CMake 3.11 版本中添加的，允许我们在*配置时间*获取依赖项。通过超级构建模式，我们可以有效地利用 CMake 作为高级包管理器：在您的项目中，您将以相同的方式处理依赖项，无论它们是否已经在系统上可用，或者它们是否需要从头开始构建。接下来的五个示例将引导您了解该模式，并展示如何使用它来获取和构建几乎任何依赖项。

两个模块都在网上有详尽的文档。对于`ExternalProject.cmake`，我们建议读者参考[`cmake.org/cmake/help/v3.5/module/ExternalProject.html`](https://cmake.org/cmake/help/v3.5/module/ExternalProject.html)。对于`FetchContent.cmake`，我们建议读者参考[`cmake.org/cmake/help/v3.11/module/FetchContent.html`](https://cmake.org/cmake/help/v3.11/module/FetchContent.html)。

# 使用超级构建模式

本示例的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-08/recipe-01`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-08/recipe-01)找到，并包含一个 C++示例。该示例适用于 CMake 3.5（及以上）版本，并在 GNU/Linux、macOS 和 Windows 上进行了测试。

本示例将通过一个非常简单的示例介绍超级构建模式。我们将展示如何使用`ExternalProject_Add`命令来构建一个简单的“Hello, World”程序。

# 准备工作

本示例将构建以下源代码（`hello-world.cpp`）中的“Hello, World”可执行文件：

```cpp
#include <cstdlib>
#include <iostream>
#include <string>

std::string say_hello() { return std::string("Hello, CMake superbuild world!"); }

int main() {
  std::cout << say_hello() << std::endl;
  return EXIT_SUCCESS;
}
```

项目结构如下，包含一个根目录`CMakeLists.txt`和一个`src/CMakeLists.txt`文件：

```cpp
.
├── CMakeLists.txt
└── src
    ├── CMakeLists.txt
    └── hello-world.cpp
```

# 如何操作

首先让我们看一下根文件夹中的`CMakeLists.txt`：

1.  我们声明一个 C++11 项目，并指定最低要求的 CMake 版本：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-01 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  我们为当前和任何底层目录设置`EP_BASE`目录属性。这将在稍后讨论：

```cpp
set_property(DIRECTORY PROPERTY EP_BASE ${CMAKE_BINARY_DIR}/subprojects)
```

1.  我们包含`ExternalProject.cmake`标准模块。该模块提供了`ExternalProject_Add`函数：

```cpp
include(ExternalProject)
```

1.  通过调用`ExternalProject_Add`函数，将我们的“Hello, World”示例的源代码作为外部项目添加。外部项目的名称为`recipe-01_core`：

```cpp
ExternalProject_Add(${PROJECT_NAME}_core
```

1.  我们使用`SOURCE_DIR`选项设置外部项目的源目录：

```cpp
SOURCE_DIR
${CMAKE_CURRENT_LIST_DIR}/src
```

1.  `src`子目录包含一个完整的 CMake 项目。为了配置和构建它，我们通过`CMAKE_ARGS`选项将适当的 CMake 选项传递给外部项目。在我们的情况下，我们只需要传递 C++编译器和对 C++标准的要求：

```cpp
CMAKE_ARGS
  -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
  -DCMAKE_CXX_STANDARD=${CMAKE_CXX_STANDARD}
  -DCMAKE_CXX_EXTENSIONS=${CMAKE_CXX_EXTENSIONS}
  -DCMAKE_CXX_STANDARD_REQUIRED=${CMAKE_CXX_STANDARD_REQUIRED}
```

1.  我们还设置了 C++编译器标志。这些标志通过`CMAKE_CACHE_ARGS`选项传递给`ExternalProject_Add`命令：

```cpp
CMAKE_CACHE_ARGS
  -DCMAKE_CXX_FLAGS:STRING=${CMAKE_CXX_FLAGS}
```

1.  我们配置外部项目，使其始终处于构建状态：

```cpp
BUILD_ALWAYS
  1
```

1.  安装步骤不会执行任何操作（我们将在第 4 个配方中重新讨论安装，即“编写安装程序”中的“安装超级构建”）：

```cpp
INSTALL_COMMAND
  ""
)
```

现在让我们转向`src/CMakeLists.txt`。由于我们将“Hello, World”源代码作为外部项目添加，这是一个完整的`CMakeLists.txt`文件，用于独立项目：

1.  同样，这里我们声明了最低要求的 CMake 版本：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
```

1.  我们声明一个 C++项目：

```cpp
project(recipe-01_core LANGUAGES CXX)
```

1.  最后，我们从`hello-world.cpp`源文件添加一个可执行目标，即`hello-world`：

```cpp
add_executable(hello-world hello-world.cpp)
```

配置和构建我们的项目按照常规方式进行：

```cpp
$ mkdir -p build
$ cmake ..
$ cmake --build .
```

构建目录的结构现在稍微复杂一些。特别是，我们注意到`subprojects`文件夹及其内容：

```cpp
build/subprojects/
├── Build
│   └── recipe-01_core
│       ├── CMakeCache.txt
│       ├── CMakeFiles
│       ├── cmake_install.cmake
│       ├── hello-world
│       └── Makefile
├── Download
│   └── recipe-01_core
├── Install
│   └── recipe-01_core
├── Stamp
│   └── recipe-01_core
│       ├── recipe-01_core-configure
│       ├── recipe-01_core-done
│       ├── recipe-01_core-download
│       ├── recipe-01_core-install
│       ├── recipe-01_core-mkdir
│       ├── recipe-01_core-patch
│       └── recipe-01_core-update
└── tmp
    └── recipe-01_core
        ├── recipe-01_core-cache-.cmake
        ├── recipe-01_core-cfgcmd.txt
        └── recipe-01_core-cfgcmd.txt.in
```

`recipe-01_core`已构建到`build/subprojects`的子目录中，称为`Build/recipe-01_core`，这是我们设置的`EP_BASE`。

`hello-world`可执行文件已在`Build/recipe-01_core`下创建。额外的子文件夹`tmp/recipe-01_core`和`Stamp/recipe-01_core`包含临时文件，例如 CMake 缓存脚本`recipe-01_core-cache-.cmake`，以及 CMake 为构建外部项目执行的各种步骤的标记文件。

# 它是如何工作的

`ExternalProject_Add`命令可用于添加第三方源代码。然而，我们的第一个示例展示了如何将我们自己的项目作为不同 CMake 项目的集合来管理。在这个示例中，根目录和叶目录的`CMakeLists.txt`都声明了一个 CMake 项目，即它们都使用了`project`命令。

`ExternalProject_Add`有许多选项，可用于微调外部项目的配置和编译的所有方面。这些选项可以分为以下几类：

+   **目录**选项：这些用于调整外部项目的源代码和构建目录的结构。在我们的例子中，我们使用了 `SOURCE_DIR` 选项让 CMake 知道源代码可在 `${CMAKE_CURRENT_LIST_DIR}/src` 文件夹中找到，因此不应从其他地方获取。构建项目和存储临时文件的目录也可以在此类选项中指定，或者作为目录属性指定。我们通过设置 `EP_BASE` 目录属性遵循了后者的方式。CMake 将为各种子项目设置所有目录，布局如下：

```cpp
TMP_DIR      = <EP_BASE>/tmp/<name>
STAMP_DIR    = <EP_BASE>/Stamp/<name>
DOWNLOAD_DIR = <EP_BASE>/Download/<name>
SOURCE_DIR   = <EP_BASE>/Source/<name>
BINARY_DIR   = <EP_BASE>/Build/<name>
INSTALL_DIR  = <EP_BASE>/Install/<name>
```

+   **下载**选项：外部项目的代码可能需要从在线存储库或资源下载。此类选项允许您控制此步骤的所有方面。

+   **更新**和**补丁**选项：这类选项可用于定义如何更新外部项目的源代码或如何应用补丁。

+   **配置**选项：默认情况下，CMake 假设外部项目本身使用 CMake 进行配置。然而，正如后续章节将展示的，我们并不局限于这种情况。如果外部项目是 CMake 项目，`ExternalProject_Add` 将调用 CMake 可执行文件并传递选项给它。对于我们当前的示例，我们通过 `CMAKE_ARGS` 和 `CMAKE_CACHE_ARGS` 选项传递配置参数。前者直接作为命令行参数传递，而后者通过 CMake 脚本文件传递。在我们的示例中，脚本文件位于 `build/subprojects/tmp/recipe-01_core/recipe-01_core-cache-.cmake`。配置将如下所示：

```cpp
$ cmake -DCMAKE_CXX_COMPILER=g++ -DCMAKE_CXX_STANDARD=11 
-DCMAKE_CXX_EXTENSIONS=OFF -DCMAKE_CXX_STANDARD_REQUIRED=ON 
-C/home/roberto/Workspace/robertodr/cmake-cookbook/chapter-08/recipe-01/cxx-example/build/subprojects/tmp/recipe-01_core/recipe-01_core-cache-.cmake "-GUnix Makefiles" /home/roberto/Workspace/robertodr/cmake-cookbook/chapter-08/recipe-01/cxx-example/src
```

+   **构建**选项：这类选项可用于调整外部项目的实际编译。我们的示例使用了 `BUILD_ALWAYS` 选项以确保外部项目总是被新鲜构建。

+   **安装**选项：这些是配置外部项目应如何安装的选项。我们的示例将 `INSTALL_COMMAND` 留空，我们将在 第十章，*编写安装程序*中更详细地讨论使用 CMake 进行安装。

+   **测试**选项：对于从源代码构建的任何软件，运行测试总是一个好主意。`ExternalProject_Add` 的这类选项就是为了这个目的。我们的示例没有使用这些选项，因为“Hello, World”示例没有任何测试，但在第五章，*将您的项目作为超级构建管理*中，我们将触发测试步骤。

`ExternalProject.cmake` 定义了命令 `ExternalProject_Get_Property`，顾名思义，这对于检索外部项目的属性非常有用。外部项目的属性在首次调用 `ExternalProject_Add` 命令时设置。例如，检索配置 `recipe-01_core` 时传递给 CMake 的参数可以通过以下方式实现：

```cpp
ExternalProject_Get_Property(${PROJECT_NAME}_core CMAKE_ARGS)
message(STATUS "CMAKE_ARGS of ${PROJECT_NAME}_core ${CMAKE_ARGS}")
```

`ExternalProject_Add`的完整选项列表可以在 CMake 文档中找到：[`cmake.org/cmake/help/v3.5/module/ExternalProject.html#command:externalproject_add`](https://cmake.org/cmake/help/v3.5/module/ExternalProject.html#command:externalproject_add)

# 还有更多

我们将在以下配方中详细探讨`ExternalProject_Add`命令的灵活性。然而，有时我们想要使用的外部项目可能需要执行额外的、非标准的步骤。为此，`ExternalProject.cmake`模块定义了以下附加命令：

1.  `ExternalProject_Add_Step`。一旦添加了外部项目，此命令允许将附加命令作为自定义步骤附加到该项目上。另请参见：[`cmake.org/cmake/help/v3.5/module/ExternalProject.html#command:externalproject_add_step`](https://cmake.org/cmake/help/v3.5/module/ExternalProject.html#command:externalproject_add_step)

1.  `ExternalProject_Add_StepTargets`。它允许您在任何外部项目中定义步骤，例如构建和测试步骤，作为单独的目标。这意味着可以从完整的外部项目中单独触发这些步骤，并允许对项目内的复杂依赖关系进行精细控制。另请参见：[`cmake.org/cmake/help/v3.5/module/ExternalProject.html#command:externalproject_add_steptargets`](https://cmake.org/cmake/help/v3.5/module/ExternalProject.html#command:externalproject_add_steptargets)

1.  `ExternalProject_Add_StepDependencies`。有时外部项目的步骤可能依赖于项目之外的目标，此命令旨在处理这些情况。另请参见：[`cmake.org/cmake/help/v3.5/module/ExternalProject.html#command:externalproject_add_stepdependencies`](https://cmake.org/cmake/help/v3.5/module/ExternalProject.html#command:externalproject_add_stepdependencies)

# 使用超级构建管理依赖项：I. Boost 库

本配方的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-08/recipe-02`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-08/recipe-02) 获取，并包含一个 C++示例。该配方适用于 CMake 版本 3.5（及更高版本），并在 GNU/Linux、macOS、Windows（使用 MSYS Makefiles 和 Ninja）上进行了测试。

Boost 库提供了丰富的 C++编程基础设施，并且受到 C++开发者的欢迎。我们已经在第三章，*检测外部库和程序*中展示了如何在系统上找到 Boost 库。然而，有时您的项目所需的 Boost 版本可能不在系统上。本食谱将展示如何利用超级构建模式来确保缺少的依赖不会阻止配置。我们将重用来自第三章，*检测外部库和程序*中第 8 个食谱，*检测 Boost 库*的代码示例，但将其重新组织为超级构建的形式。这将是项目的布局：

```cpp
.
├── CMakeLists.txt
├── external
│   └── upstream
│       ├── boost
│       │   └── CMakeLists.txt
│       └── CMakeLists.txt
└── src
    ├── CMakeLists.txt
    └── path-info.cpp
```

您会注意到项目源代码树中有四个`CMakeLists.txt`文件。以下部分将引导您了解这些文件。

# 如何操作

我们将从根`CMakeLists.txt`开始：

1.  我们像往常一样声明一个 C++11 项目：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-02 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  我们设置`EP_BASE`目录属性：

```cpp
set_property(DIRECTORY PROPERTY EP_BASE ${CMAKE_BINARY_DIR}/subprojects)
```

1.  我们设置`STAGED_INSTALL_PREFIX`变量。该目录将用于在我们的构建树中安装依赖项：

```cpp
set(STAGED_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/stage)
message(STATUS "${PROJECT_NAME} staged install: ${STAGED_INSTALL_PREFIX}")
```

1.  我们的项目需要 Boost 库的文件系统和系统组件。我们声明一个列表变量来保存此信息，并设置所需的最小 Boost 版本：

```cpp
list(APPEND BOOST_COMPONENTS_REQUIRED filesystem system)
set(Boost_MINIMUM_REQUIRED 1.61)
```

1.  我们添加`external/upstream`子目录，它将依次添加`external/upstream/boost`子目录：

```cpp
add_subdirectory(external/upstream)
```

1.  然后，我们包含`ExternalProject.cmake`标准 CMake 模块。这定义了，除其他外，`ExternalProject_Add`命令，这是协调超级构建的关键：

```cpp
include(ExternalProject)
```

1.  我们的项目位于`src`子目录下，并将其作为外部项目添加。我们使用`CMAKE_ARGS`和`CMAKE_CACHE_ARGS`传递 CMake 选项：

```cpp
ExternalProject_Add(${PROJECT_NAME}_core
  DEPENDS
    boost_external
  SOURCE_DIR
    ${CMAKE_CURRENT_LIST_DIR}/src
  CMAKE_ARGS
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_CXX_STANDARD=${CMAKE_CXX_STANDARD}
    -DCMAKE_CXX_EXTENSIONS=${CMAKE_CXX_EXTENSIONS}
    -DCMAKE_CXX_STANDARD_REQUIRED=${CMAKE_CXX_STANDARD_REQUIRED}
  CMAKE_CACHE_ARGS
    -DCMAKE_CXX_FLAGS:STRING=${CMAKE_CXX_FLAGS}
    -DCMAKE_INCLUDE_PATH:PATH=${BOOST_INCLUDEDIR}
    -DCMAKE_LIBRARY_PATH:PATH=${BOOST_LIBRARYDIR}
```

```cpp
  BUILD_ALWAYS
    1
  INSTALL_COMMAND
    ""
  )
```

现在让我们看看`external/upstream`中的`CMakeLists.txt`文件。该文件只是将`boost`文件夹添加为附加目录：

```cpp
add_subdirectory(boost)
```

`external/upstream/boost`中的`CMakeLists.txt`描述了满足对 Boost 依赖所需的操作。我们的目标很简单，如果所需版本未安装，下载源代码存档并构建它：

1.  首先，我们尝试找到所需的最小版本的 Boost 组件：

```cpp
find_package(Boost ${Boost_MINIMUM_REQUIRED} QUIET COMPONENTS "${BOOST_COMPONENTS_REQUIRED}")
```

1.  如果找到这些选项，我们会添加一个接口库，`boost_external`。这是一个虚拟目标，用于在我们的超级构建中正确处理构建顺序：

```cpp
if(Boost_FOUND)
  message(STATUS "Found Boost version ${Boost_MAJOR_VERSION}.${Boost_MINOR_VERSION}.${Boost_SUBMINOR_VERSION}")
  add_library(boost_external INTERFACE)
else()    
  # ... discussed below
endif()
```

1.  如果`find_package`不成功或者我们强制进行超级构建，我们需要设置一个本地的 Boost 构建，为此，我们进入前一个条件语句的 else 部分：

```cpp
else()
  message(STATUS "Boost ${Boost_MINIMUM_REQUIRED} could not be located, Building Boost 1.61.0 instead.")
```

1.  由于这些库不使用 CMake，我们需要为它们的原生构建工具链准备参数。首先，我们设置要使用的编译器：

```cpp
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    if(APPLE)
      set(_toolset "darwin")
    else()
      set(_toolset "gcc")
    endif()
  elseif(CMAKE_CXX_COMPILER_ID MATCHES ".*Clang")
    set(_toolset "clang")
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "Intel")
    if(APPLE)
      set(_toolset "intel-darwin")
    else()
      set(_toolset "intel-linux")
    endif()
  endif()
```

1.  我们根据所需组件准备要构建的库列表。我们定义了一些列表变量：`_build_byproducts`，用于包含将要构建的库的绝对路径；`_b2_select_libraries`，用于包含我们想要构建的库列表；以及`_bootstrap_select_libraries`，这是一个内容相同但格式不同的字符串：

```cpp
  if(NOT "${BOOST_COMPONENTS_REQUIRED}" STREQUAL "")
    # Replace unit_test_framework (used by CMake's find_package) with test (understood by Boost build toolchain)
    string(REPLACE "unit_test_framework" "test" _b2_needed_components "${BOOST_COMPONENTS_REQUIRED}")
    # Generate argument for BUILD_BYPRODUCTS
    set(_build_byproducts)
    set(_b2_select_libraries)
    foreach(_lib IN LISTS _b2_needed_components)
      list(APPEND _build_byproducts ${STAGED_INSTALL_PREFIX}/boost/lib/libboost_${_lib}${CMAKE_SHARED_LIBRARY_SUFFIX})
      list(APPEND _b2_select_libraries --with-${_lib})
    endforeach()
    # Transform the ;-separated list to a ,-separated list (digested by the Boost build toolchain!)
    string(REPLACE ";" "," _b2_needed_components "${_b2_needed_components}")
    set(_bootstrap_select_libraries "--with-libraries=${_b2_needed_components}")
    string(REPLACE ";" ", " printout "${BOOST_COMPONENTS_REQUIRED}")
    message(STATUS "  Libraries to be built: ${printout}")
  endif()
```

1.  我们现在可以将 Boost 项目作为外部项目添加。首先，我们在**下载**选项类中指定下载 URL 和校验和。将`DOWNLOAD_NO_PROGRESS`设置为`1`以抑制打印下载进度信息：

```cpp
include(ExternalProject)
ExternalProject_Add(boost_external
  URL
    https://sourceforge.net/projects/boost/files/boost/1.61.0/boost_1_61_0.zip
  URL_HASH
    SHA256=02d420e6908016d4ac74dfc712eec7d9616a7fc0da78b0a1b5b937536b2e01e8
  DOWNLOAD_NO_PROGRESS
    1
```

1.  接下来，我们设置**更新/修补**和**配置**选项：

```cpp
 UPDATE_COMMAND
   ""
 CONFIGURE_COMMAND
   <SOURCE_DIR>/bootstrap.sh
     --with-toolset=${_toolset}
     --prefix=${STAGED_INSTALL_PREFIX}/boost
     ${_bootstrap_select_libraries}
```

1.  使用`BUILD_COMMAND`指令设置构建选项。将`BUILD_IN_SOURCE`设置为`1`以指示构建将在源目录内发生。此外，我们将`LOG_BUILD`设置为`1`以将构建脚本的输出记录到文件中：

```cpp
  BUILD_COMMAND
    <SOURCE_DIR>/b2 -q
         link=shared
         threading=multi
         variant=release
         toolset=${_toolset}
         ${_b2_select_libraries}
  LOG_BUILD
    1
  BUILD_IN_SOURCE
    1
```

1.  使用`INSTALL_COMMAND`指令设置安装选项。注意使用`LOG_INSTALL`选项也将安装步骤记录到文件中：

```cpp
  INSTALL_COMMAND
    <SOURCE_DIR>/b2 -q install
         link=shared
         threading=multi
         variant=release
         toolset=${_toolset}
         ${_b2_select_libraries}
  LOG_INSTALL
    1
```

1.  最后，我们将我们的库列为`BUILD_BYPRODUCTS`并关闭`ExternalProject_Add`命令：

```cpp
  BUILD_BYPRODUCTS
    "${_build_byproducts}"
  )
```

1.  我们设置了一些对指导新安装的 Boost 检测有用的变量：

```cpp
set(
  BOOST_ROOT ${STAGED_INSTALL_PREFIX}/boost
  CACHE PATH "Path to internally built Boost installation root"
  FORCE
  )
set(
  BOOST_INCLUDEDIR ${BOOST_ROOT}/include
  CACHE PATH "Path to internally built Boost include directories"
  FORCE
  )
set(
  BOOST_LIBRARYDIR ${BOOST_ROOT}/lib
  CACHE PATH "Path to internally built Boost library directories"
  FORCE
  )
```

1.  在条件分支的最后执行的操作是取消设置所有内部变量：

```cpp
  unset(_toolset)
  unset(_b2_needed_components)
  unset(_build_byproducts)
  unset(_b2_select_libraries)
  unset(_boostrap_select_libraries)
```

最后，让我们看看`src/CMakeLists.txt`。该文件描述了一个独立项目：

1.  我们声明一个 C++项目：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-02_core LANGUAGES CXX)
```

1.  项目依赖于 Boost，我们调用`find_package`。从根目录的`CMakeLists.txt`配置项目保证了依赖项始终得到满足，无论是使用系统上预装的 Boost 还是我们作为子项目构建的 Boost：

```cpp
find_package(Boost 1.61 REQUIRED COMPONENTS filesystem)
```

1.  我们添加我们的示例可执行目标，描述其链接库：

```cpp
add_executable(path-info path-info.cpp)

target_link_libraries(path-info
  PUBLIC
    Boost::filesystem
  )
```

虽然导入目标的使用很整洁，但并不能保证对任意 Boost 和 CMake 版本组合都能正常工作。这是因为 CMake 的`FindBoost.cmake`模块手动创建了导入目标，所以如果 CMake 发布时不知道 Boost 版本，将会有`Boost_LIBRARIES`和`Boost_INCLUDE_DIRS`，但没有导入目标（另请参见[`stackoverflow.com/questions/42123509/cmake-finds-boost-but-the-imported-targets-not-available-for-boost-version`](https://stackoverflow.com/questions/42123509/cmake-finds-boost-but-the-imported-targets-not-available-for-boost-version)）。

# 工作原理

本食谱展示了如何利用超级构建模式来集结项目的依赖项。让我们再次审视项目的布局：

```cpp
.
├── CMakeLists.txt
├── external
│   └── upstream
│       ├── boost
│       │   └── CMakeLists.txt
│       └── CMakeLists.txt
└── src
    ├── CMakeLists.txt
    └── path-info.cpp
```

我们在项目源树中引入了四个`CMakeLists.txt`文件：

1.  根目录的`CMakeLists.txt`将协调超级构建。

1.  位于`external/upstream`的文件将引导我们到`boost`叶目录。

1.  `external/upstream/boost/CMakeLists.txt`将负责处理 Boost 依赖项。

1.  最后，位于`src`下的`CMakeLists.txt`将构建我们的示例代码，该代码依赖于 Boost。

让我们从`external/upstream/boost/CMakeLists.txt`文件开始讨论。Boost 使用自己的构建系统，因此我们需要在`ExternalProject_Add`中稍微详细一些，以确保一切正确设置：

1.  我们保留**目录**选项的默认值。

1.  **下载**步骤将从 Boost 的在线服务器下载所需版本的存档。因此，我们设置了`URL`和`URL_HASH`。后者用于检查下载存档的完整性。由于我们不希望看到下载的进度报告，我们还设置了`DOWNLOAD_NO_PROGRESS`选项为 true。

1.  **更新**步骤留空。如果需要重新构建，我们不希望再次下载 Boost。

1.  **配置**步骤将使用 Boost 提供的本地配置工具，在`CONFIGURE_COMMAND`中。由于我们希望超级构建是跨平台的，我们使用`<SOURCE_DIR>`变量来引用解压源代码的位置：

```cpp
CONFIGURE_COMMAND
  <SOURCE_DIR>/bootstrap.sh
  --with-toolset=${_toolset}
  --prefix=${STAGED_INSTALL_PREFIX}/boost
  ${_bootstrap_select_libraries}
```

1.  **构建**选项声明了一个*源码内*构建，通过将`BUILD_IN_SOURCE`选项设置为 true。`BUILD_COMMAND`使用 Boost 的本地构建工具`b2`。由于我们将进行源码内构建，我们再次使用`<SOURCE_DIR>`变量来引用解压源代码的位置。

1.  接下来，我们转向**安装**选项。Boost 使用相同的本地构建工具进行管理。实际上，构建和安装命令可以很容易地合并为一个。

1.  **输出**日志选项`LOG_BUILD`和`LOG_INSTALL`指示`ExternalProject_Add`为构建和安装操作编写日志文件，而不是输出到屏幕。

1.  最后，`BUILD_BYPRODUCTS`选项允许`ExternalProject_Add`在后续构建中跟踪新近构建的 Boost 库，即使它们的修改时间可能不会更新。

Boost 构建完成后，构建目录中的`${STAGED_INSTALL_PREFIX}/boost`文件夹将包含我们所需的库。我们需要将此信息传递给我们的项目，其构建系统在`src/CMakeLists.txt`中生成。为了实现这一目标，我们在根`CMakeLists.txt`中的`ExternalProject_Add`中传递两个额外的`CMAKE_CACHE_ARGS`：

1.  `CMAKE_INCLUDE_PATH`：CMake 查找 C/C++头文件的路径

1.  `CMAKE_LIBRARY_PATH`：CMake 查找库的路径

通过将这些变量设置为我们新近构建的 Boost 安装，我们确保依赖项将被正确地检测到。

在配置项目时将`CMAKE_DISABLE_FIND_PACKAGE_Boost`设置为`ON`，将跳过 Boost 库的检测并始终执行超级构建。请参阅文档：[`cmake.org/cmake/help/v3.5/variable/CMAKE_DISABLE_FIND_PACKAGE_PackageName.html`](https://cmake.org/cmake/help/v3.5/variable/CMAKE_DISABLE_FIND_PACKAGE_PackageName.html)

# 使用超级构建管理依赖项：II. FFTW 库

本示例的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-08/recipe-03`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-08/recipe-03)找到，并包含一个 C 语言示例。该示例适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

超级构建模式可用于管理 CMake 支持的所有语言项目的相当复杂的依赖关系。如前一示例所示，各个子项目并非必须由 CMake 管理。与前一示例相反，本示例中的外部子项目将是一个 CMake 项目，并将展示如何使用超级构建下载、构建和安装 FFTW 库。FFTW 是一个快速傅里叶变换库，可免费在[`www.fftw.org`](http://www.fftw.org/)获取。

# 准备就绪

本示例的目录布局展示了超级构建的熟悉结构：

```cpp
.
├── CMakeLists.txt
├── external
│   └── upstream
│       ├── CMakeLists.txt
│       └── fftw3
│           └── CMakeLists.txt
└── src
    ├── CMakeLists.txt
    └── fftw_example.c
```

我们项目的代码`fftw_example.c`位于`src`子目录中，并将计算源代码中定义的函数的傅里叶变换。

# 如何操作

让我们从根`CMakeLists.txt`开始。此文件组合了整个超级构建过程：

1.  我们声明一个 C99 项目：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-03 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD_REQUIRED ON)
```

1.  与前一示例一样，我们设置`EP_BASE`目录属性和暂存安装前缀：

```cpp
set_property(DIRECTORY PROPERTY EP_BASE ${CMAKE_BINARY_DIR}/subprojects)

set(STAGED_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/stage)
message(STATUS "${PROJECT_NAME} staged install: ${STAGED_INSTALL_PREFIX}")
```

1.  FFTW 的依赖关系在`external/upstream`子目录中进行检查，我们继续将此子目录添加到构建系统中：

```cpp
add_subdirectory(external/upstream)
```

1.  我们包含`ExternalProject.cmake`模块：

```cpp
include(ExternalProject)
```

1.  我们声明`recipe-03_core`外部项目。该项目的源代码位于`${CMAKE_CURRENT_LIST_DIR}/src`文件夹中。该项目设置为使用`FFTW3_DIR`选项选择正确的 FFTW 库：

```cpp
ExternalProject_Add(${PROJECT_NAME}_core
  DEPENDS
    fftw3_external
  SOURCE_DIR
    ${CMAKE_CURRENT_LIST_DIR}/src
  CMAKE_ARGS
    -DFFTW3_DIR=${FFTW3_DIR}
    -DCMAKE_C_STANDARD=${CMAKE_C_STANDARD}
    -DCMAKE_C_EXTENSIONS=${CMAKE_C_EXTENSIONS}
    -DCMAKE_C_STANDARD_REQUIRED=${CMAKE_C_STANDARD_REQUIRED}
  CMAKE_CACHE_ARGS
    -DCMAKE_C_FLAGS:STRING=${CMAKE_C_FLAGS}
    -DCMAKE_PREFIX_PATH:PATH=${CMAKE_PREFIX_PATH}
  BUILD_ALWAYS
    1
  INSTALL_COMMAND
    ""
  )
```

在`external/upstream`子目录中还包含一个`CMakeLists.txt`：

1.  在此文件中，我们将`fftw3`文件夹添加为构建系统中的另一个子目录：

```cpp
add_subdirectory(fftw3)
```

`external/upstream/fftw3`中的`CMakeLists.txt`负责我们的依赖关系：

1.  首先，我们尝试在系统上查找 FFTW3 库。请注意，我们使用了`find_package`的`CONFIG`参数：

```cpp
find_package(FFTW3 CONFIG QUIET)
```

1.  如果找到了库，我们可以使用导入的目标`FFTW3::fftw3`与之链接。我们向用户打印一条消息，显示库的位置。我们添加一个虚拟的`INTERFACE`库`fftw3_external`。这在超级构建中子项目之间的依赖树正确修复时是必需的：

```cpp
find_package(FFTW3 CONFIG QUIET)

if(FFTW3_FOUND)
  get_property(_loc TARGET FFTW3::fftw3 PROPERTY LOCATION)
  message(STATUS "Found FFTW3: ${_loc} (found version ${FFTW3_VERSION})")
  add_library(fftw3_external INTERFACE) # dummy
else()
  # this branch will be discussed below
endif()
```

1.  如果 CMake 无法找到预安装的 FFTW 版本，我们进入条件语句的 else 分支，在其中我们使用`ExternalProject_Add`下载、构建和安装它。外部项目的名称为`fftw3_external`。`fftw3_external`项目将从官方在线档案下载。下载的完整性将使用 MD5 校验和进行检查：

```cpp
message(STATUS "Suitable FFTW3 could not be located. Downloading and building!")

include(ExternalProject)
ExternalProject_Add(fftw3_external
  URL
    http://www.fftw.org/fftw-3.3.8.tar.gz
  URL_HASH
    MD5=8aac833c943d8e90d51b697b27d4384d
```

1.  我们禁用下载的进度打印，并将更新命令定义为空：

```cpp
  DOWNLOAD_NO_PROGRESS
    1
  UPDATE_COMMAND
    ""
```

1.  配置、构建和安装输出将被记录到文件中：

```cpp
  LOG_CONFIGURE
    1
  LOG_BUILD
    1
  LOG_INSTALL
    1
```

1.  我们将`fftw3_external`项目的安装前缀设置为之前定义的`STAGED_INSTALL_PREFIX`目录，并关闭 FFTW3 的测试套件构建：

```cpp
  CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${STAGED_INSTALL_PREFIX}
    -DBUILD_TESTS=OFF
```

1.  如果我们在 Windows 上构建，我们通过生成表达式设置`WITH_OUR_MALLOC`预处理器选项，并关闭`ExternalProject_Add`命令：

```cpp
  CMAKE_CACHE_ARGS
    -DCMAKE_C_FLAGS:STRING=$<$<BOOL:WIN32>:-DWITH_OUR_MALLOC>
  )
```

1.  最后，我们定义了`FFTW3_DIR`变量并将其缓存。该变量将由 CMake 用作导出的`FFTW3::fftw3`目标的搜索目录：

```cpp
include(GNUInstallDirs)

set(
  FFTW3_DIR ${STAGED_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/cmake/fftw3
  CACHE PATH "Path to internally built FFTW3Config.cmake"
  FORCE
  )
```

位于`src`文件夹中的`CMakeLists.txt`文件相当简洁：

1.  同样在这个文件中，我们声明了一个 C 项目：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-03_core LANGUAGES C)
```

1.  我们调用`find_package`来检测 FFTW 库。再次使用`CONFIG`检测模式：

```cpp
find_package(FFTW3 CONFIG REQUIRED)
get_property(_loc TARGET FFTW3::fftw3 PROPERTY LOCATION)
message(STATUS "Found FFTW3: ${_loc} (found version ${FFTW3_VERSION})")
```

1.  我们将`fftw_example.c`源文件添加到可执行目标`fftw_example`中：

```cpp
add_executable(fftw_example fftw_example.c)
```

1.  我们为目标可执行文件设置链接库：

```cpp
target_link_libraries(fftw_example
  PRIVATE
    FFTW3::fftw3
  )
```

# 工作原理

本示例展示了如何下载、构建和安装由 CMake 管理的构建系统的外部项目。与之前的示例不同，那里必须使用自定义构建系统，这种超级构建设置相对简洁。值得注意的是，`find_package`命令使用了`CONFIG`选项；这告诉 CMake 首先查找`FFTW3Config.cmake`文件以定位 FFTW3 库。这样的文件将库作为目标导出，供第三方项目使用。目标包含版本、配置和库的位置，即有关目标如何配置和构建的完整信息。如果系统上未安装该库，我们需要告诉 CMake`FFTW3Config.cmake`文件的位置。这可以通过设置`FFTW3_DIR`变量来完成。这是在`external/upstream/fftw3/CMakeLists.txt`文件的最后一步，通过使用`GNUInstallDirs.cmake`模块，我们将`FFTW3_DIR`设置为缓存变量，以便稍后在超级构建中被拾取。

在配置项目时将`CMAKE_DISABLE_FIND_PACKAGE_FFTW3`设置为`ON`，将跳过 FFTW 库的检测并始终执行超级构建。请参阅文档：[`cmake.org/cmake/help/v3.5/variable/CMAKE_DISABLE_FIND_PACKAGE_PackageName.html`](https://cmake.org/cmake/help/v3.5/variable/CMAKE_DISABLE_FIND_PACKAGE_PackageName.html)

# 使用超级构建管理依赖项：III. Google Test 框架

本示例的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-08/recipe-04`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-08/recipe-04)找到，并包含一个 C++示例。该示例适用于 CMake 版本 3.11（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。代码仓库还包含一个与 CMake 3.5 兼容的示例。

在第四章，*创建和运行测试*，第 3 个菜谱，*定义单元测试并链接到 Google Test*，我们使用 Google Test 框架实现了单元测试，并在配置时使用相对较新的`FetchContent`模块（自 CMake 3.11 起可用）获取了 Google Test 源码。在本章中，我们将重温这个菜谱，减少对测试方面的关注，并深入探讨`FetchContent`，它提供了一个紧凑且多功能的模块，用于在配置时组装项目依赖。为了获得更多见解，以及对于 CMake 3.11 以下的版本，我们还将讨论如何使用`ExternalProject_Add` *在配置时*模拟`FetchContent`。

# 准备工作

在本菜谱中，我们将构建并测试与第四章，*创建和运行测试*，第 3 个菜谱，*定义单元测试并链接到 Google Test*中相同的源文件，`main.cpp`、`sum_integers.cpp`、`sum_integers.hpp`和`test.cpp`。我们将使用`FetchContent`或`ExternalProject_Add`在配置时下载所有必需的 Google Test 源码，并且在本菜谱中只关注在配置时获取依赖，而不是实际的源码及其单元测试。

# 如何操作

在本菜谱中，我们将只关注如何获取 Google Test 源码以构建`gtest_main`目标。关于如何使用该目标测试示例源码的讨论，我们请读者参考第四章，*创建和运行测试*，第 3 个菜谱，*定义单元测试并链接到 Google Test*：

1.  我们首先包含`FetchContent`模块，它将提供我们所需的函数来声明、查询和填充依赖：

```cpp
include(FetchContent)
```

1.  接着，我们声明内容——其名称、仓库位置以及要获取的确切版本：

```cpp
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.8.0
)
```

1.  然后我们查询内容是否已经被获取/填充：

```cpp
FetchContent_GetProperties(googletest)
```

1.  之前的函数调用定义了`googletest_POPULATED`。如果内容尚未填充，我们将获取内容并配置子项目：

```cpp
if(NOT googletest_POPULATED)
  FetchContent_Populate(googletest)

  # ...

  # adds the targets: gtest, gtest_main, gmock, gmock_main
  add_subdirectory(
    ${googletest_SOURCE_DIR}
    ${googletest_BINARY_DIR}
    )

  # ...

endif()
```

1.  注意内容是在配置时获取的：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
```

1.  这将生成以下构建目录树。Google Test 源码现在已就位，可以由 CMake 处理并提供所需的目标：

```cpp
build/
├── ...
├── _deps
│   ├── googletest-build
│   │   ├── ...
│   │   └── ...
│   ├── googletest-src
│   │   ├── ...
│   │   └── ...
│   └── googletest-subbuild
│       ├── ...
│       └── ...
└── ...
```

# 它是如何工作的

`FetchContent`模块允许在配置时填充内容。在我们的例子中，我们获取了一个带有明确 Git 标签的 Git 仓库：

```cpp
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.8.0
)
```

`FetchContent`模块支持通过`ExternalProject`模块支持的任何方法*获取*内容 - 换句话说，*通过*Subversion、Mercurial、CVS 或 HTTP(S)。内容名称“googletest”是我们的选择，有了这个，我们将能够在查询其属性、填充目录以及稍后配置子项目时引用内容。在填充项目之前，我们检查内容是否已经获取，否则如果`FetchContent_Populate()`被调用超过一次，它将抛出错误：

```cpp
if(NOT googletest_POPULATED)
  FetchContent_Populate(googletest)

  # ...

endif()
```

只有在那时我们才配置了子目录，我们可以通过`googletest_SOURCE_DIR`和`googletest_BINARY_DIR`变量来引用它。这些变量是由`FetchContent_Populate(googletest)`设置的，并根据我们在声明内容时给出的项目名称构建的。

```cpp
add_subdirectory(
  ${googletest_SOURCE_DIR}
  ${googletest_BINARY_DIR}
  )
```

`FetchContent`模块有许多选项（参见[`cmake.org/cmake/help/v3.11/module/FetchContent.html`](https://cmake.org/cmake/help/v3.11/module/FetchContent.html)），这里我们可以展示一个：如何更改外部项目将被放置的默认路径。之前，我们看到默认情况下内容被保存到`${CMAKE_BINARY_DIR}/_deps`。我们可以通过设置`FETCHCONTENT_BASE_DIR`来更改此位置：

```cpp
set(FETCHCONTENT_BASE_DIR ${CMAKE_BINARY_DIR}/custom)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.8.0
)
```

`FetchContent`已成为 CMake 3.11 版本中的标准部分。在下面的代码中，我们将尝试在*配置时间*使用`ExternalProject_Add`来模拟`FetchContent`。这不仅对旧版本的 CMake 实用，而且有望让我们更深入地了解`FetchContent`层下面发生的事情，并提供一个有趣的替代方案，以替代使用`ExternalProject_Add`在构建时间获取项目的典型方式。我们的目标是编写一个`fetch_git_repo`宏，并将其放置在`fetch_git_repo.cmake`中，以便我们可以这样获取内容：

```cpp
include(fetch_git_repo.cmake)

fetch_git_repo(
  googletest
  ${CMAKE_BINARY_DIR}/_deps
  https://github.com/google/googletest.git
  release-1.8.0
)

# ...

# adds the targets: gtest, gtest_main, gmock, gmock_main
add_subdirectory(
  ${googletest_SOURCE_DIR}
  ${googletest_BINARY_DIR}
  )

# ...
```

这感觉类似于使用`FetchContent`。在幕后，我们将使用`ExternalProject_Add`。现在让我们揭开盖子，检查`fetch_git_repo`在`fetch_git_repo.cmake`中的定义：

```cpp
macro(fetch_git_repo _project_name _download_root _git_url _git_tag)

  set(${_project_name}_SOURCE_DIR ${_download_root}/${_project_name}-src)
  set(${_project_name}_BINARY_DIR ${_download_root}/${_project_name}-build)

  # variables used configuring fetch_git_repo_sub.cmake
  set(FETCH_PROJECT_NAME ${_project_name})
  set(FETCH_SOURCE_DIR ${${_project_name}_SOURCE_DIR})
  set(FETCH_BINARY_DIR ${${_project_name}_BINARY_DIR})
  set(FETCH_GIT_REPOSITORY ${_git_url})
  set(FETCH_GIT_TAG ${_git_tag})

  configure_file(
    ${CMAKE_CURRENT_LIST_DIR}/fetch_at_configure_step.in
    ${_download_root}/CMakeLists.txt
    @ONLY
    )

  # undefine them again
  unset(FETCH_PROJECT_NAME)
  unset(FETCH_SOURCE_DIR)
  unset(FETCH_BINARY_DIR)
  unset(FETCH_GIT_REPOSITORY)
  unset(FETCH_GIT_TAG)

  # configure sub-project
  execute_process(
    COMMAND
      "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
    WORKING_DIRECTORY
      ${_download_root}
    )
  # build sub-project which triggers ExternalProject_Add
  execute_process(
    COMMAND
      "${CMAKE_COMMAND}" --build .
    WORKING_DIRECTORY
      ${_download_root}
    )
endmacro()
```

宏接收项目名称、下载根目录、Git 仓库 URL 和 Git 标签。宏定义了`${_project_name}_SOURCE_DIR`和`${_project_name}_BINARY_DIR`，我们使用宏而不是函数，因为`${_project_name}_SOURCE_DIR`和`${_project_name}_BINARY_DIR`需要在`fetch_git_repo`的作用域之外存活，因为我们稍后在主作用域中使用它们来配置子目录：

```cpp
add_subdirectory(
  ${googletest_SOURCE_DIR}
  ${googletest_BINARY_DIR}
  )
```

在`fetch_git_repo`宏内部，我们希望使用`ExternalProject_Add`在*配置时间*获取外部项目，我们通过一个三步的技巧来实现这一点：

1.  首先，我们配置`fetch_at_configure_step.in`：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(fetch_git_repo_sub LANGUAGES NONE)

include(ExternalProject)

ExternalProject_Add(
  @FETCH_PROJECT_NAME@
  SOURCE_DIR "@FETCH_SOURCE_DIR@"
  BINARY_DIR "@FETCH_BINARY_DIR@"
  GIT_REPOSITORY
    @FETCH_GIT_REPOSITORY@
  GIT_TAG
    @FETCH_GIT_TAG@
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
  TEST_COMMAND ""
  )
```

使用`configure_file`，我们生成一个`CMakeLists.txt`文件，其中之前的占位符被替换为在`fetch_git_repo.cmake`中定义的值。注意，之前的`ExternalProject_Add`命令被构造为仅获取，而不进行配置、构建、安装或测试。

1.  其次，我们在配置时间（从根项目的角度）使用配置步骤触发`ExternalProject_Add`：

```cpp
# configure sub-project
execute_process(
  COMMAND
    "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" . 
  WORKING_DIRECTORY
    ${_download_root}
  ) 
```

1.  第三个也是最后一个技巧在`fetch_git_repo.cmake`中触发配置时间构建步骤：

```cpp
# build sub-project which triggers ExternalProject_Add
execute_process(
  COMMAND
    "${CMAKE_COMMAND}" --build . 
  WORKING_DIRECTORY
    ${_download_root}
  )
```

这个解决方案的一个很好的方面是，由于外部依赖项不是由`ExternalProject_Add`配置的，我们不需要通过`ExternalProject_Add`调用将任何配置设置传递给项目。我们可以使用`add_subdirectory`配置和构建模块，就好像外部依赖项是我们项目源代码树的一部分一样。巧妙的伪装！

# 另请参阅

有关可用的`FetchContent`选项的详细讨论，请咨询[`cmake.org/cmake/help/v3.11/module/FetchContent.html`](https://cmake.org/cmake/help/v3.11/module/FetchContent.html)。

配置时间`ExternalProject_Add`解决方案的灵感来自 Craig Scott 的工作和博客文章：[`crascit.com/2015/07/25/cmake-gtest/`](https://crascit.com/2015/07/25/cmake-gtest/)。

# 将您的项目作为超级构建进行管理

本示例的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-08/recipe-05`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-08/recipe-05)获取，并且有一个 C++示例。本示例适用于 CMake 版本 3.6（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

`ExternalProject`和`FetchContent`是 CMake 工具箱中的两个非常强大的工具。之前的示例应该已经说服了您超级构建方法在管理具有复杂依赖关系的项目方面的多功能性。到目前为止，我们已经展示了如何使用`ExternalProject`来处理以下内容：

+   存储在您的源代码树中的源代码

+   从在线服务器上的档案中检索来源

之前的示例展示了如何使用`FetchContent`来处理来自开源 Git 存储库的依赖项。本示例将展示如何使用`ExternalProject`达到相同的效果。最后一个示例将介绍一个将在第 4 个示例中重复使用的示例，即*安装超级构建*，在第十章，*编写安装程序*。

# 准备工作

这个超级构建的源代码树现在应该感觉很熟悉：

```cpp
.
├── CMakeLists.txt
├── external
│   └── upstream
│       ├── CMakeLists.txt
│       └── message
│           └── CMakeLists.txt
└── src
    ├── CMakeLists.txt
    └── use_message.cpp
```

根目录有一个`CMakeLists.txt`，我们已经知道它将协调超级构建。叶目录`src`和`external`托管我们自己的源代码和满足对`message`库的依赖所需的 CMake 指令，我们将在本示例中构建该库。

# 如何操作

到目前为止，设置超级构建的过程应该感觉很熟悉。让我们再次看一下必要的步骤，从根`CMakeLists.txt`开始：

1.  我们声明了一个具有相同默认构建类型的 C++11 项目：

```cpp
cmake_minimum_required(VERSION 3.6 FATAL_ERROR)

project(recipe-05 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED CMAKE_BUILD_TYPE OR "${CMAKE_BUILD_TYPE}" STREQUAL "")
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

message(STATUS "Build type set to ${CMAKE_BUILD_TYPE}")
```

1.  设置了`EP_BASE`目录属性。这将固定由`ExternalProject`管理的所有子项目的布局：

```cpp
set_property(DIRECTORY PROPERTY EP_BASE ${CMAKE_BINARY_DIR}/subprojects)
```

1.  我们设置了`STAGED_INSTALL_PREFIX`。与之前一样，此位置将用作构建树中依赖项的安装前缀：

```cpp
set(STAGED_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/stage)
message(STATUS "${PROJECT_NAME} staged install: ${STAGED_INSTALL_PREFIX}")
```

1.  我们添加`external/upstream`子目录：

```cpp
add_subdirectory(external/upstream)
```

1.  我们自己的项目也将由超级构建管理，因此使用`ExternalProject_Add`添加：

```cpp
include(ExternalProject)
ExternalProject_Add(${PROJECT_NAME}_core
  DEPENDS
    message_external
  SOURCE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/src
  CMAKE_ARGS
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_CXX_STANDARD=${CMAKE_CXX_STANDARD}
    -DCMAKE_CXX_EXTENSIONS=${CMAKE_CXX_EXTENSIONS}
    -DCMAKE_CXX_STANDARD_REQUIRED=${CMAKE_CXX_STANDARD_REQUIRED}
    -Dmessage_DIR=${message_DIR}
  CMAKE_CACHE_ARGS
    -DCMAKE_CXX_FLAGS:STRING=${CMAKE_CXX_FLAGS}
    -DCMAKE_PREFIX_PATH:PATH=${CMAKE_PREFIX_PATH}
  BUILD_ALWAYS
    1
  INSTALL_COMMAND
    ""
  )
```

`external/upstream`中的`CMakeLists.txt`只包含一个命令：

```cpp
add_subdirectory(message)
```

跳转到`message`文件夹，我们再次看到管理我们对`message`库依赖的常用命令：

1.  首先，我们调用`find_package`来找到一个合适的库版本：

```cpp
find_package(message 1 CONFIG QUIET)
```

1.  如果找到，我们通知用户并添加一个虚拟的`INTERFACE`库：

```cpp
get_property(_loc TARGET message::message-shared PROPERTY LOCATION)
message(STATUS "Found message: ${_loc} (found version ${message_VERSION})")
add_library(message_external INTERFACE) # dummy
```

1.  如果未找到，我们再次通知用户并继续使用`ExternalProject_Add`：

```cpp
message(STATUS "Suitable message could not be located, Building message instead.")
```

1.  该项目托管在一个公共 Git 仓库中，我们使用`GIT_TAG`选项来指定下载哪个分支。像之前一样，我们让`UPDATE_COMMAND`选项保持空白：

```cpp
include(ExternalProject)
ExternalProject_Add(message_external
  GIT_REPOSITORY
    https://github.com/dev-cafe/message.git
  GIT_TAG
    master
  UPDATE_COMMAND
    ""
```

1.  外部项目使用 CMake 进行配置和构建。我们传递所有必要的构建选项：

```cpp
 CMAKE_ARGS
   -DCMAKE_INSTALL_PREFIX=${STAGED_INSTALL_PREFIX}
   -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
   -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
   -DCMAKE_CXX_STANDARD=${CMAKE_CXX_STANDARD}
   -DCMAKE_CXX_EXTENSIONS=${CMAKE_CXX_EXTENSIONS}
   -DCMAKE_CXX_STANDARD_REQUIRED=${CMAKE_CXX_STANDARD_REQUIRED}
 CMAKE_CACHE_ARGS
   -DCMAKE_CXX_FLAGS:STRING=${CMAKE_CXX_FLAGS}
```

1.  我们决定在项目安装后进行测试：

```cpp
  TEST_AFTER_INSTALL
    1
```

1.  我们不希望看到下载进度，也不希望屏幕上显示配置、构建和安装的信息，我们关闭`ExternalProject_Add`命令：

```cpp
  DOWNLOAD_NO_PROGRESS
    1
  LOG_CONFIGURE
    1
  LOG_BUILD
    1
  LOG_INSTALL
    1
  )
```

1.  为了确保子项目在超级构建的其余部分中可被发现，我们设置`message_DIR`目录：

```cpp
if(WIN32 AND NOT CYGWIN)
  set(DEF_message_DIR ${STAGED_INSTALL_PREFIX}/CMake)
else()
  set(DEF_message_DIR ${STAGED_INSTALL_PREFIX}/share/cmake/message)
endif()

file(TO_NATIVE_PATH "${DEF_message_DIR}" DEF_message_DIR)
set(message_DIR ${DEF_message_DIR}
    CACHE PATH "Path to internally built messageConfig.cmake" FORCE)
```

最后，让我们看看`src`文件夹中的`CMakeLists.txt`：

1.  再次，我们声明一个 C++11 项目：

```cpp
cmake_minimum_required(VERSION 3.6 FATAL_ERROR)

project(recipe-05_core
  LANGUAGES CXX
  )

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  这个项目需要`message`库：

```cpp
find_package(message 1 CONFIG REQUIRED)
get_property(_loc TARGET message::message-shared PROPERTY LOCATION)
message(STATUS "Found message: ${_loc} (found version ${message_VERSION})")
```

1.  我们声明一个可执行目标，并将其链接到我们依赖项提供的`message-shared`库：

```cpp
add_executable(use_message use_message.cpp)

target_link_libraries(use_message
  PUBLIC
    message::message-shared
  )
```

# 它是如何工作的

这个配方突出了`ExternalProject_Add`命令的一些新选项：

1.  `GIT_REPOSITORY`：这可以用来指定包含我们依赖源代码的仓库的 URL。CMake 还可以使用其他版本控制系统，如 CVS（`CVS_REPOSITORY`）、SVN（`SVN_REPOSITORY`）或 Mercurial（`HG_REPOSITORY`）。

1.  `GIT_TAG`：默认情况下，CMake 将检出给定仓库的默认分支。然而，依赖于一个已知稳定的定义良好的版本是更可取的。这可以通过这个选项来指定，它可以接受 Git 识别为“版本”信息的任何标识符，如 Git 提交 SHA、Git 标签，或者仅仅是一个分支名称。对于 CMake 理解的其他版本控制系统，也有类似的选项。

1.  `TEST_AFTER_INSTALL`：很可能，你的依赖项有自己的测试套件，你可能想要运行测试套件以确保超级构建过程中一切顺利。这个选项将在安装步骤之后立即运行测试。

下面是`ExternalProject_Add`理解的额外**测试**选项：

+   `TEST_BEFORE_INSTALL`，它将在安装步骤*之前*运行测试套件

+   `TEST_EXCLUDE_FROM_MAIN`，我们可以使用它从测试套件中移除对外部项目主要目标的依赖

这些选项假设外部项目使用 CTest 管理测试。如果外部项目不使用 CTest 管理测试，我们可以设置`TEST_COMMAND`选项来执行测试。

引入超级构建模式，即使对于项目中包含的模块，也会带来额外的层次，重新声明小型 CMake 项目，并通过`ExternalProject_Add`显式传递配置设置。引入这一额外层次的好处是变量和目标作用域的清晰分离，这有助于管理复杂性、依赖关系和由多个组件组成的项目的命名空间，这些组件可以是内部的或外部的，并通过 CMake 组合在一起。


# 第十章：混合语言项目

在本章中，我们将涵盖以下示例：

+   构建使用 C/C++库的 Fortran 项目

+   构建使用 Fortran 库的 C/C++项目

+   使用 Cython 构建 C++和 Python 项目

+   使用 Boost.Python 构建 C++和 Python 项目

+   使用 pybind11 构建 C++和 Python 项目

+   使用 Python CFFI 混合 C、C++、Fortran 和 Python

# 引言

有许多现有的库在特定任务上表现出色。通常，在我们的代码库中重用这些库是一个非常好的主意，因为我们可以依赖其他专家团队多年的经验。随着计算机架构和编译器的演变，编程语言也在发展。过去，大多数科学软件都是用 Fortran 编写的，而现在，C、C++和解释型语言——尤其是 Python——正占据主导地位。将编译型语言编写的代码与解释型语言的绑定相结合变得越来越普遍，因为它提供了以下好处：

+   终端用户可以自定义和扩展代码本身提供的能力，以完全满足他们的需求。

+   人们可以将 Python 等语言的表达力与编译型语言的性能相结合，这种编译型语言在内存寻址方面更接近“硬件层面”，从而获得两者的最佳效果。

正如我们在之前的各个示例中一直展示的那样，`project`命令可以通过`LANGUAGES`关键字来设置项目中使用的语言。CMake 支持多种编译型编程语言，但并非全部。截至 CMake 3.5 版本，各种汇编语言（如 ASM-ATT、ASM、ASM-MASM 和 ASM-NASM）、C、C++、Fortran、Java、RC（Windows 资源编译器）和 Swift 都是有效选项。CMake 3.8 版本增加了对两种新语言的支持：C#和 CUDA（详见此处发布说明：[`cmake.org/cmake/help/v3.8/release/3.8.html#languages`](https://cmake.org/cmake/help/v3.8/release/3.8.html#languages)）。

在本章中，我们将展示如何将用不同编译型（C、C++和 Fortran）和解释型（Python）语言编写的代码集成到一个可移植和跨平台的解决方案中。我们将展示如何利用 CMake 和不同编程语言固有的工具来实现集成。

# 构建使用 C/C++库的 Fortran 项目

本示例的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-09/recipe-01`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-09/recipe-01)找到，并包含两个示例：一个是混合 Fortran 和 C，另一个是混合 Fortran 和 C++。该示例适用于 CMake 3.5 版本（及以上）。两个版本的示例都已在 GNU/Linux 和 macOS 上进行了测试。

Fortran 作为高性能计算语言有着悠久的历史。许多数值线性代数库仍然主要用 Fortran 编写，许多需要与过去几十年积累的遗留代码保持兼容的大型数字处理软件包也是如此。虽然 Fortran 在处理数值数组时提供了非常自然的语法，但在与操作系统交互时却显得不足，主要是因为直到 Fortran 2003 标准发布时，才强制要求与 C 语言（计算机编程的*事实上的通用语言*）的互操作层。本食谱将展示如何将 Fortran 代码与 C 系统库和自定义 C 代码接口。

# 准备工作

如第七章，*项目结构化*所示，我们将把项目结构化为树状。每个子目录都有一个`CMakeLists.txt`文件，其中包含与该目录相关的指令。这使我们能够尽可能地将信息限制在叶目录中，如下例所示：

```cpp
.
├── CMakeLists.txt
└── src
    ├── bt-randomgen-example.f90
    ├── CMakeLists.txt
    ├── interfaces
    │   ├── CMakeLists.txt
    │   ├── interface_backtrace.f90
    │   ├── interface_randomgen.f90
    │   └── randomgen.c
    └── utils
        ├── CMakeLists.txt
        └── util_strings.f90
```

在我们的例子中，我们有一个包含源代码的`src`子目录，包括我们的可执行文件`bt-randomgen-example.f90`。另外两个子目录，`interfaces`和`utils`，包含将被编译成库的更多源代码。

在`interfaces`子目录中的源代码展示了如何封装 backtrace C 系统库。例如，`interface_backtrace.f90`包含：

```cpp
module interface_backtrace

  implicit none

  interface
    function backtrace(buffer, size) result(bt) bind(C, name="backtrace")
      use, intrinsic :: iso_c_binding, only: c_int, c_ptr
      type(c_ptr) :: buffer
      integer(c_int), value :: size
      integer(c_int) :: bt
    end function

    subroutine backtrace_symbols_fd(buffer, size, fd) bind(C, name="backtrace_symbols_fd")
      use, intrinsic :: iso_c_binding, only: c_int, c_ptr
      type(c_ptr) :: buffer
      integer(c_int), value :: size, fd
    end subroutine
  end interface

end module
```

上述示例展示了以下用法：

+   内置的`iso_c_binding`模块，确保了 Fortran 和 C 类型及函数的互操作性。

+   `interface`声明，它将函数绑定到单独库中的符号。

+   `bind(C)`属性，它固定了声明函数的名称混淆。

这个子目录包含另外两个源文件：

+   `randomgen.c`，这是一个 C 源文件，它使用 C 标准的`rand`函数公开一个函数，用于在区间内生成随机整数。

+   `interface_randomgen.f90`，它封装了用于 Fortran 可执行文件中的 C 函数。

# 如何操作

我们有四个`CMakeLists.txt`实例需要查看：一个根目录和三个叶目录。让我们从根目录的`CMakeLists.txt`开始：

1.  我们声明了一个混合语言的 Fortran 和 C 项目：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-01 LANGUAGES Fortran C)
```

1.  我们指示 CMake 在构建目录的`lib`子目录下保存静态和共享库。可执行文件将保存在`bin`下，而 Fortran 编译模块文件将保存在`modules`下：

```cpp
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(CMAKE_Fortran_MODULE_DIRECTORY
  ${CMAKE_CURRENT_BINARY_DIR}/modules)
```

1.  接下来，我们转到第一个叶目录，通过添加`src`子目录来编辑`CMakeLists.txt`：

```cpp
add_subdirectory(src)
```

1.  `src/CMakeLists.txt`文件添加了另外两个子目录：

```cpp
add_subdirectory(interfaces)
add_subdirectory(utils)
```

在`interfaces`子目录中，我们执行以下操作：

1.  我们包含了`FortranCInterface.cmake`模块，并验证 C 和 Fortran 编译器可以正确地相互通信：

```cpp
include(FortranCInterface)
FortranCInterface_VERIFY()
```

1.  接下来，我们找到 backtrace 系统库，因为我们想在 Fortran 代码中使用它：

```cpp
find_package(Backtrace REQUIRED)
```

1.  然后，我们使用回溯包装器、随机数生成器及其 Fortran 包装器的源文件创建一个共享库目标：

```cpp
add_library(bt-randomgen-wrap SHARED "")

target_sources(bt-randomgen-wrap
  PRIVATE
    interface_backtrace.f90
    interface_randomgen.f90
    randomgen.c
  )
```

1.  我们还为新生成的库目标设置了链接库。我们使用`PUBLIC`属性，以便链接我们的库的其他目标能够正确看到依赖关系：

```cpp
target_link_libraries(bt-randomgen-wrap
  PUBLIC
    ${Backtrace_LIBRARIES}
  )
```

在`utils`子目录中，我们还有一个`CMakeLists.txt`。这是一个一行代码：我们创建一个新的库目标，该子目录中的源文件将被编译到这个目标中。这个目标没有依赖关系：

```cpp
add_library(utils SHARED util_strings.f90)
```

让我们回到`src/CMakeLists.txt`：

1.  我们添加一个可执行目标，使用`bt-randomgen-example.f90`作为源文件：

```cpp
add_executable(bt-randomgen-example bt-randomgen-example.f90)
```

1.  最后，我们将`CMakeLists.txt`叶中生成的库目标链接到我们的可执行目标：

```cpp
target_link_libraries(bt-randomgen-example
  PRIVATE
    bt-randomgen-wrap
    utils
  )
```

# **它是如何工作的**

在确定了要链接的正确库之后，我们需要确保我们的程序能够正确调用它们定义的函数。每个编译器在生成机器代码时都会执行名称重整，不幸的是，这项操作的约定并不是通用的，而是依赖于编译器。我们已经在《第三章》（c1fec057-4e5f-4a9b-b404-30dc74f5d7b7.xhtml），*检测外部库和程序*，第 4 个配方，*检测 BLAS 和 LAPACK 数学库*中遇到的`FortranCInterface`，检查所选 C 编译器与 Fortran 编译器的兼容性。对于我们当前的目的，名称重整并不是真正的问题。Fortran 2003 标准为函数和子程序定义了一个`bind`属性，它接受一个可选的`name`参数。如果提供了这个参数，编译器将使用程序员固定的名称为这些子程序和函数生成符号。例如，回溯函数可以从 C 暴露给 Fortran，保留名称，如下所示：

```cpp
function backtrace(buffer, size) result(bt) bind(C, name="backtrace")
```

# **还有更多**

在`interfaces/CMakeLists.txt`中的 CMake 代码也表明，可以从不同语言的源文件创建库。显然，CMake 能够执行以下操作：

+   确定使用哪个编译器从列出的源文件获取目标文件。

+   选择适当的链接器来从这些目标文件构建库（或可执行文件）。

CMake 如何确定使用哪个编译器？通过在`project`命令中指定`LANGUAGES`选项，CMake 将检查您的系统上是否存在适用于给定语言的工作编译器。当添加目标并列出源文件时，CMake 将根据文件扩展名适当地确定编译器。因此，以`.c`结尾的文件将使用已确定的 C 编译器编译为对象文件，而以`.f90`（或需要预处理的`.F90`）结尾的文件将使用工作的 Fortran 编译器进行编译。同样，对于 C++，`.cpp`或`.cxx`扩展名将触发使用 C++编译器。我们仅列出了 C、C++和 Fortran 语言的一些可能的有效文件扩展名，但 CMake 可以识别更多。如果项目中的文件扩展名由于任何原因不在识别的扩展名之列，该怎么办？可以使用`LANGUAGE`源文件属性来告诉 CMake 在特定源文件上使用哪个编译器，如下所示：

```cpp
set_source_files_properties(my_source_file.axx
  PROPERTIES
    LANGUAGE CXX
  )
```

最后，链接器呢？CMake 如何确定目标的链接器语言？对于**不混合**编程语言的目标，选择很简单：通过用于生成对象文件的编译器命令调用链接器。如果目标**确实混合**了编程语言，如我们的示例，链接器语言的选择基于在语言混合中偏好值最高的那个。在我们的示例中混合了 Fortran 和 C，Fortran 语言的偏好高于 C 语言，因此被用作链接器语言。当混合 Fortran 和 C++时，后者具有更高的偏好，因此被用作链接器语言。与编译器语言一样，我们可以通过在目标上设置相应的`LINKER_LANGUAGE`属性来强制 CMake 为我们的目标使用特定的链接器语言：

```cpp
set_target_properties(my_target
   PROPERTIES
     LINKER_LANGUAGE Fortran
   )
```

# 构建使用 Fortran 库的 C/C++项目

本配方的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-09/recipe-02`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-09/recipe-02)找到，并提供了一个混合 C++、C 和 Fortran 的示例。该配方适用于 CMake 版本 3.5（及以上），并在 GNU/Linux 和 macOS 上进行了测试。

第三章的配方 4，*检测 BLAS 和 LAPACK 数学库*，在第三章，*检测外部库和程序*，展示了如何检测用 Fortran 编写的 BLAS 和 LAPACK 线性代数库，以及如何在 C++代码中使用它们。在这里，我们将重新审视这个配方，但这次从不同的角度出发：更少关注检测外部库，而是更深入地讨论混合 C++和 Fortran 以及名称修饰的方面。

# 准备工作

在本食谱中，我们将重用来自第三章，*检测外部库和程序*，食谱 4，*检测 BLAS 和 LAPACK 数学库*的源代码。尽管我们不会修改实际的实现源文件或头文件，但我们将根据第七章，*项目结构*中讨论的建议修改项目树结构，并得出以下源代码结构：

```cpp
.
├── CMakeLists.txt
├── README.md
└── src
    ├── CMakeLists.txt
    ├── linear-algebra.cpp
    └── math
        ├── CMakeLists.txt
        ├── CxxBLAS.cpp
        ├── CxxBLAS.hpp
        ├── CxxLAPACK.cpp
        └── CxxLAPACK.hpp
```

这里我们收集了所有 BLAS 和 LAPACK 的包装器，它们在`src/math`下提供了`math`库。主程序是`linear-algebra.cpp`。所有源文件都组织在`src`子目录下。为了限定范围，我们将 CMake 代码拆分到三个`CMakeLists.txt`文件中，现在我们将讨论这些文件。

# 如何操作

这个项目混合了 C++（主程序的语言）、Fortran（因为这是库所写的语言）和 C（需要用来包装 Fortran 子例程）。在根`CMakeLists.txt`文件中，我们需要执行以下操作：

1.  将项目声明为混合语言并设置 C++标准：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-02 LANGUAGES CXX C Fortran)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  我们使用`GNUInstallDirs`模块来指导 CMake 将静态和共享库以及可执行文件保存到标准目录中。我们还指示 CMake 将 Fortran 编译的模块文件放置在`modules`下：

```cpp
include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})
set(CMAKE_Fortran_MODULE_DIRECTORY ${PROJECT_BINARY_DIR}/modules)
```

1.  然后我们转到下一个叶子子目录：

```cpp
add_subdirectory(src)
```

在`src/CMakeLists.txt`文件中，我们添加了另一个子目录`math`，其中包含了线性代数包装器。在`src/math/CMakeLists.txt`中，我们需要执行以下操作：

1.  我们调用`find_package`来获取 BLAS 和 LAPACK 库的位置：

```cpp
find_package(BLAS REQUIRED)
find_package(LAPACK REQUIRED)
```

1.  我们包含`FortranCInterface.cmake`模块，并验证 Fortran、C 和 C++编译器是否兼容：

```cpp
include(FortranCInterface)
FortranCInterface_VERIFY(CXX)
```

1.  我们还需要生成预处理器宏来处理 BLAS 和 LAPACK 子例程的名称修饰。再次，`FortranCInterface`通过在当前构建目录中生成一个名为`fc_mangle.h`的头文件来提供帮助：

```cpp
FortranCInterface_HEADER(
  fc_mangle.h
  MACRO_NAMESPACE "FC_"
  SYMBOLS DSCAL DGESV
  )
```

1.  接下来，我们为 BLAS 和 LAPACK 包装器添加一个库，并指定头文件和库所在的目录。注意`PUBLIC`属性，它将允许依赖于`math`的其他目标正确获取其依赖项：

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

回到`src/CMakeLists.txt`，我们最终添加了一个可执行目标，并将其链接到我们的 BLAS/LAPACK 包装器的`math`库：

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

# 它是如何工作的

使用`find_package`，我们已经确定了要链接的正确库。与之前的食谱一样，我们需要确保我们的程序能够正确调用它们定义的函数。在第三章，*检测外部库和程序*，第 4 个食谱，*检测 BLAS 和 LAPACK 数学库*，我们面临编译器依赖的符号修饰问题。我们使用`FortranCInterface` CMake 模块来检查所选 C 和 C++编译器与 Fortran 编译器的兼容性。我们还使用`FortranCInterface_HEADER`函数来生成包含宏的头文件，以处理 Fortran 子程序的符号修饰。这是通过以下代码实现的：

```cpp
FortranCInterface_HEADER(
  fc_mangle.h
  MACRO_NAMESPACE "FC_"
  SYMBOLS DSCAL DGESV
  )
```

此命令将生成包含符号修饰宏的`fc_mangle.h`头文件，如 Fortran 编译器所推断，并将其保存到当前二进制目录`CMAKE_CURRENT_BINARY_DIR`。我们小心地将`CMAKE_CURRENT_BINARY_DIR`设置为`math`目标的包含路径。考虑以下生成的`fc_mangle.h`：

```cpp
#ifndef FC_HEADER_INCLUDED
#define FC_HEADER_INCLUDED

/* Mangling for Fortran global symbols without underscores. */
#define FC_GLOBAL(name,NAME) name##_

/* Mangling for Fortran global symbols with underscores. */
#define FC_GLOBAL_(name,NAME) name##_

/* Mangling for Fortran module symbols without underscores. */
#define FC_MODULE(mod_name,name, mod_NAME,NAME) __##mod_name##_MOD_##name

/* Mangling for Fortran module symbols with underscores. */
#define FC_MODULE_(mod_name,name, mod_NAME,NAME) __##mod_name##_MOD_##name

/* Mangle some symbols automatically. */
#define DSCAL FC_GLOBAL(dscal, DSCAL)
#define DGESV FC_GLOBAL(dgesv, DGESV)

#endif
```

本示例中的编译器使用下划线进行符号修饰。由于 Fortran 不区分大小写，子程序可能以小写或大写形式出现，因此需要将两种情况都传递给宏。请注意，CMake 还将为隐藏在 Fortran 模块后面的符号生成修饰宏。

如今，许多 BLAS 和 LAPACK 的实现都附带了一个围绕 Fortran 子程序的薄 C 层包装器。这些包装器多年来已经标准化，并分别称为 CBLAS 和 LAPACKE。

由于我们已将源文件仔细组织成一个库目标和一个可执行目标，我们应该对目标的`PUBLIC`、`INTERFACE`和`PRIVATE`可见性属性进行注释。这些对于清晰的 CMake 项目结构至关重要。与源文件一样，包含目录、编译定义和选项，当与`target_link_libraries`一起使用时，这些属性的含义保持不变：

+   使用`PRIVATE`属性，库将仅被链接到当前目标，而不会被链接到以它作为依赖的其他目标。

+   使用`INTERFACE`属性，库将仅被链接到以当前目标作为依赖的目标。

+   使用`PUBLIC`属性，库将被链接到当前目标以及任何以它作为依赖的其他目标。

# 使用 Cython 构建 C++和 Python 项目

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-09/recipe-03`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-09/recipe-03)找到，并包含一个 C++示例。该食谱适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

Cython 是一个优化的静态编译器，允许为 Python 编写 C 扩展。Cython 是一个非常强大的工具，使用基于 Pyrex 的扩展 Cython 编程语言。Cython 的一个典型用例是加速 Python 代码，但它也可以用于通过 Cython 层将 C/C++与 Python 接口。在本食谱中，我们将专注于后一种用例，并演示如何使用 CMake 帮助下的 Cython 将 C/C++和 Python 接口。

# 准备就绪

作为一个例子，我们将使用以下 C++代码（`account.cpp`）：

```cpp
#include "account.hpp"

Account::Account() : balance(0.0) {}

Account::~Account() {}

void Account::deposit(const double amount) { balance += amount; }

void Account::withdraw(const double amount) { balance -= amount; }

double Account::get_balance() const { return balance; }
```

这段代码提供了以下接口（`account.hpp`）：

```cpp
#pragma once

class Account {
public:
  Account();
  ~Account();

  void deposit(const double amount);
  void withdraw(const double amount);
  double get_balance() const;

private:
  double balance;
};
```

使用这段示例代码，我们可以创建起始余额为零的银行账户。我们可以向账户存款和取款，也可以使用`get_balance()`查询账户余额。余额本身是`Account`类的私有成员。

我们的目标是能够直接从 Python 与这个 C++类交互——换句话说，在 Python 方面，我们希望能够这样做：

```cpp
account = Account()

account.deposit(100.0)
account.withdraw(50.0)

balance = account.get_balance()
```

为了实现这一点，我们需要一个 Cython 接口文件（我们将称这个文件为`account.pyx`）：

```cpp
# describe the c++ interface
cdef extern from "account.hpp":
    cdef cppclass Account:
        Account() except +
        void deposit(double)
        void withdraw(double)
        double get_balance()

# describe the python interface
cdef class pyAccount:
    cdef Account *thisptr
    def __cinit__(self):
        self.thisptr = new Account()
    def __dealloc__(self):
        del self.thisptr
    def deposit(self, amount):
        self.thisptr.deposit(amount)
    def withdraw(self, amount):
        self.thisptr.withdraw(amount)
    def get_balance(self):
        return self.thisptr.get_balance()
```

# 如何操作

让我们看看如何生成 Python 接口：

1.  我们的`CMakeLists.txt`开始定义 CMake 依赖项、项目名称和语言：

```cpp
# define minimum cmake version
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# project name and supported language
project(recipe-03 LANGUAGES CXX)

# require C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  在 Windows 上，最好不要让构建类型未定义，这样我们就可以使此项目的构建类型与 Python 环境的构建类型相匹配。这里我们默认使用`Release`构建类型：

```cpp
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
```

1.  在本食谱中，我们还将需要 Python 解释器：

```cpp
find_package(PythonInterp REQUIRED)
```

1.  以下 CMake 代码将允许我们构建 Python 模块：

```cpp
# directory cointaining UseCython.cmake and FindCython.cmake
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake-cython)

# this defines cython_add_module
include(UseCython)

# tells UseCython to compile this file as a c++ file
set_source_files_properties(account.pyx PROPERTIES CYTHON_IS_CXX TRUE)

# create python module
cython_add_module(account account.pyx account.cpp)

# location of account.hpp
target_include_directories(account
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
  )
```

1.  现在我们定义一个测试：

```cpp
# turn on testing
enable_testing()

# define test
add_test(
  NAME
    python_test
  COMMAND
    ${CMAKE_COMMAND} -E env ACCOUNT_MODULE_PATH=$<TARGET_FILE_DIR:account>
    ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test.py
  )
```

1.  `python_test`执行`test.py`，在其中我们进行了几次存款和取款，并验证了余额：

```cpp
import os
import sys
sys.path.append(os.getenv('ACCOUNT_MODULE_PATH'))

from account import pyAccount as Account

account1 = Account()

account1.deposit(100.0)
account1.deposit(100.0)

account2 = Account()

account2.deposit(200.0)
account2.deposit(200.0)

account1.withdraw(50.0)

assert account1.get_balance() == 150.0
assert account2.get_balance() == 400.0
```

1.  有了这些，我们就可以配置、构建和测试代码了：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
$ ctest

 Start 1: python_test
1/1 Test #1: python_test ...................... Passed 0.03 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) = 0.03 sec
```

# 工作原理

在本食谱中，我们通过一个相对紧凑的`CMakeLists.txt`文件实现了 Python 与 C++的接口，但我们通过使用`FindCython.cmake`和`UseCython.cmake`模块实现了这一点，这些模块被放置在`cmake-cython`下。这些模块通过以下代码包含：

```cpp
# directory contains UseCython.cmake and FindCython.cmake
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake-cython)

# this defines cython_add_module
include(UseCython)
```

`FindCython.cmake`包含在`UseCython.cmake`中，并定位和定义`${CYTHON_EXECUTABLE}`。后一个模块定义了`cython_add_module`和`cython_add_standalone_executable`函数，这些函数可用于创建 Python 模块和独立可执行文件。这两个模块都已从[`github.com/thewtex/cython-cmake-example/tree/master/cmake`](https://github.com/thewtex/cython-cmake-example/tree/master/cmake)下载。

在本食谱中，我们使用`cython_add_module`来创建一个 Python 模块库。请注意，我们将非标准的`CYTHON_IS_CXX`源文件属性设置为`TRUE`，这样`cython_add_module`函数就会知道将`pyx`文件编译为 C++文件：

```cpp
# tells UseCython to compile this file as a c++ file
set_source_files_properties(account.pyx PROPERTIES CYTHON_IS_CXX TRUE)

# create python module
cython_add_module(account account.pyx account.cpp)
```

Python 模块在`${CMAKE_CURRENT_BINARY_DIR}`内部创建，为了让 Python `test.py`脚本能够找到它，我们通过自定义环境变量传递相关路径，该变量在`test.py`内部用于设置`PATH`变量。注意`COMMAND`是如何设置为调用 CMake 可执行文件本身以在执行 Python 脚本之前正确设置本地环境的。这为我们提供了平台独立性，并避免了用无关变量污染环境：

```cpp
add_test(
  NAME
    python_test
  COMMAND
    ${CMAKE_COMMAND} -E env ACCOUNT_MODULE_PATH=$<TARGET_FILE_DIR:account>
    ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test.py
  )
```

我们还应该查看`account.pyx`文件，它是 Python 和 C++之间的接口文件，描述了 C++接口：

```cpp
# describe the c++ interface
cdef extern from "account.hpp":
    cdef cppclass Account:
        Account() except +
        void deposit(double)
        void withdraw(double)
        double get_balance()
```

在`Account`类构造函数中可以看到`except +`。这个指令允许 Cython 处理由 C++代码引发的异常。

`account.pyx`接口文件还描述了 Python 接口：

```cpp
# describe the python interface
cdef class pyAccount:
    cdef Account *thisptr
    def __cinit__(self):
        self.thisptr = new Account()
    def __dealloc__(self):
        del self.thisptr
    def deposit(self, amount):
        self.thisptr.deposit(amount)
    def withdraw(self, amount):
        self.thisptr.withdraw(amount)
    def get_balance(self):
        return self.thisptr.get_balance()
```

我们可以看到`cinit`构造函数、`__dealloc__`析构函数以及`deposit`和`withdraw`方法是如何与相应的 C++实现对应部分匹配的。

总结一下，我们找到了一种通过引入对 Cython 模块的依赖来结合 Python 和 C++的机制。这个模块可以通过`pip`安装到虚拟环境或 Pipenv 中，或者使用 Anaconda 安装。

# 还有更多内容

C 也可以类似地耦合。如果我们希望利用构造函数和析构函数，我们可以围绕 C 接口编写一个薄的 C++层。

Typed Memoryviews 提供了有趣的功能，可以直接在 Python 中映射和访问由 C/C++分配的内存缓冲区，而不会产生任何开销：[`cython.readthedocs.io/en/latest/src/userguide/memoryviews.html`](http://cython.readthedocs.io/en/latest/src/userguide/memoryviews.html)。它们使得可以直接将 NumPy 数组映射到 C++数组。

# 使用 Boost.Python 构建 C++和 Python 项目

本节的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-09/recipe-04`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-09/recipe-04)找到，并包含一个 C++示例。本节适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

Boost 库提供了另一种流行的选择，用于将 C++代码与 Python 接口。本节将展示如何使用 CMake 为依赖于 Boost.Python 的 C++项目构建，以便将它们的功能作为 Python 模块暴露出来。我们将重用前一节的示例，并尝试与 Cython 示例中的相同 C++实现(`account.cpp`)进行交互。

# 准备工作

虽然我们保持`account.cpp`不变，但我们修改了前一节的接口文件(`account.hpp`)：

```cpp
#pragma once

#define BOOST_PYTHON_STATIC_LIB
#include <boost/python.hpp>

class Account {
public:
  Account();
  ~Account();

  void deposit(const double amount);
  void withdraw(const double amount);
  double get_balance() const;

private:
  double balance;
};

namespace py = boost::python;

BOOST_PYTHON_MODULE(account) {
  py::class_<Account>("Account")
      .def("deposit", &Account::deposit)
      .def("withdraw", &Account::withdraw)
      .def("get_balance", &Account::get_balance);
}
```

# 如何操作

以下是使用 Boost.Python 与您的 C++项目所需的步骤：

1.  与前一节一样，我们首先定义最小版本、项目名称、支持的语言和默认构建类型：

```cpp
# define minimum cmake version
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# project name and supported language
project(recipe-04 LANGUAGES CXX)

# require C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# we default to Release build type
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
```

1.  在本配方中，我们依赖于 Python 和 Boost 库以及 Python 解释器进行测试。Boost.Python 组件的名称取决于 Boost 版本和 Python 版本，因此我们探测几个可能的组件名称：

```cpp
# for testing we will need the python interpreter
find_package(PythonInterp REQUIRED)

# we require python development headers
find_package(PythonLibs ${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR} EXACT REQUIRED)
```

```cpp
# now search for the boost component
# depending on the boost version it is called either python,
# python2, python27, python3, python36, python37, ...

list(
  APPEND _components
    python${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}
    python${PYTHON_VERSION_MAJOR}
    python
  )

set(_boost_component_found "")

foreach(_component IN ITEMS ${_components})
  find_package(Boost COMPONENTS ${_component})
  if(Boost_FOUND)
    set(_boost_component_found ${_component})
    break()
  endif()
endforeach()

if(_boost_component_found STREQUAL "")
  message(FATAL_ERROR "No matching Boost.Python component found")
endif()
```

1.  使用以下命令，我们定义了 Python 模块及其依赖项：

```cpp
# create python module
add_library(account
  MODULE
    account.cpp
  )

target_link_libraries(account
  PUBLIC
    Boost::${_boost_component_found}
    ${PYTHON_LIBRARIES}
  )

target_include_directories(account
  PRIVATE
    ${PYTHON_INCLUDE_DIRS}
  )
```

```cpp
# prevent cmake from creating a "lib" prefix
set_target_properties(account
  PROPERTIES
    PREFIX ""
  )

if(WIN32)
  # python will not import dll but expects pyd
  set_target_properties(account
    PROPERTIES
      SUFFIX ".pyd"
    )
endif()
```

1.  最后，我们为这个实现定义了一个测试：

```cpp
# turn on testing
enable_testing()

# define test
add_test(
  NAME
    python_test
  COMMAND
    ${CMAKE_COMMAND} -E env ACCOUNT_MODULE_PATH=$<TARGET_FILE_DIR:account>
    ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test.py
  )
```

1.  现在可以配置、编译和测试代码：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
$ ctest

    Start 1: python_test
1/1 Test #1: python_test ......................   Passed    0.10 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) =   0.11 sec
```

# 它是如何工作的

与依赖 Cython 模块不同，本配方现在依赖于在系统上定位 Boost 库，以及 Python 开发头文件和库。

使用以下命令搜索 Python 开发头文件和库：

```cpp
find_package(PythonInterp REQUIRED)

find_package(PythonLibs ${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR} EXACT REQUIRED)
```

请注意，我们首先搜索解释器，然后搜索开发头文件和库。此外，对`PythonLibs`的搜索要求开发头文件和库的相同主要和次要版本与解释器发现的版本相同。这是为了确保在整个项目中使用一致的解释器和库版本。然而，这种命令组合并不能保证会找到完全匹配的两个版本。

在定位 Boost.Python 组件时，我们遇到了一个难题，即我们尝试定位的组件名称取决于 Boost 版本和我们的 Python 环境。根据 Boost 版本，组件可以称为`python`、`python2`、`python3`、`python27`、`python36`、`python37`等。我们通过从特定到更通用的名称进行搜索，并且只有在找不到匹配项时才失败来解决这个问题：

```cpp
list(
  APPEND _components
    python${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}
    python${PYTHON_VERSION_MAJOR}
    python
  )

set(_boost_component_found "")

foreach(_component IN ITEMS ${_components})
  find_package(Boost COMPONENTS ${_component})
  if(Boost_FOUND)
    set(_boost_component_found ${_component})
    break()
  endif()
endforeach()
if(_boost_component_found STREQUAL "")
  message(FATAL_ERROR "No matching Boost.Python component found")
endif()
```

可以通过设置额外的 CMake 变量来调整 Boost 库的发现和使用。例如，CMake 提供以下选项：

+   `Boost_USE_STATIC_LIBS`可以设置为`ON`以强制使用 Boost 库的静态版本。

+   `Boost_USE_MULTITHREADED`可以设置为`ON`以确保选择并使用多线程版本。

+   `Boost_USE_STATIC_RUNTIME`可以设置为`ON`，以便我们的目标将使用链接 C++运行时静态的 Boost 变体。

本配方引入的另一个新方面是在`add_library`命令中使用`MODULE`选项。我们从第 3 个配方，*构建和链接共享和静态库*，在第一章，*从简单可执行文件到库*中已经知道，CMake 接受以下选项作为`add_library`的第二个有效参数：

+   `STATIC`，用于创建静态库；即，用于链接其他目标（如可执行文件）的对象文件的档案

+   `SHARED`，用于创建共享库；即，可以在运行时动态链接和加载的库

+   `OBJECT`，用于创建对象库；即，不将对象文件归档到静态库中，也不将它们链接成共享对象

这里引入的`MODULE`选项将生成一个*插件库*；也就是说，一个动态共享对象（DSO），它不会被动态链接到任何可执行文件中，但仍然可以在运行时加载。由于我们正在用自己编写的 C++功能扩展 Python，Python 解释器将需要在运行时能够加载我们的库。这可以通过使用`add_library`的`MODULE`选项并阻止在我们的库目标名称中添加任何前缀（例如，Unix 系统上的`lib`）来实现。后者操作是通过设置适当的 target 属性来完成的，如下所示：

```cpp
set_target_properties(account
  PROPERTIES
    PREFIX ""
  )
```

所有展示 Python 和 C++接口的示例都有一个共同点，那就是我们需要向 Python 代码描述如何与 C++层连接，并列出应该对 Python 可见的符号。我们还可以（重新）命名这些符号。在前面的示例中，我们在一个单独的`account.pyx`文件中完成了这一点。当使用`Boost.Python`时，我们直接在 C++代码中描述接口，最好靠近我们希望接口的类或函数的定义：

```cpp
BOOST_PYTHON_MODULE(account) {
  py::class_<Account>("Account")
      .def("deposit", &Account::deposit)
      .def("withdraw", &Account::withdraw)
      .def("get_balance", &Account::get_balance);
}
```

`BOOST_PYTHON_MODULE`模板包含在`<boost/python.hpp>`中，负责创建 Python 接口。该模块将暴露一个`Account` Python 类，该类映射到 C++类。在这种情况下，我们不必显式声明构造函数和析构函数——这些会为我们自动创建，并在 Python 对象创建时自动调用：

```cpp
myaccount = Account()
```

当对象超出作用域并被 Python 垃圾回收机制收集时，析构函数会被调用。同时，注意`BOOST_PYTHON_MODULE`是如何暴露`deposit`、`withdraw`和`get_balance`这些函数，并将它们映射到相应的 C++类方法上的。

这样，编译后的模块可以在`PYTHONPATH`中找到。在本示例中，我们实现了 Python 和 C++层之间相对干净的分离。Python 代码在功能上不受限制，不需要类型注释或重命名，并且保持了*pythonic*：

```cpp
from account import Account

account1 = Account()

account1.deposit(100.0)
account1.deposit(100.0)

account2 = Account()

account2.deposit(200.0)
account2.deposit(200.0)

```

```cpp
account1.withdraw(50.0)

assert account1.get_balance() == 150.0
assert account2.get_balance() == 400.0
```

# 还有更多内容

在本示例中，我们依赖于系统上已安装的 Boost，因此 CMake 代码尝试检测相应的库。或者，我们可以将 Boost 源代码与我们的项目一起打包，并将此依赖项作为项目的一部分进行构建。Boost 是一种便携式的方式，用于将 Python 与 C++接口。然而，考虑到编译器支持和 C++标准的可移植性，Boost.Python 并不是一个轻量级的依赖。在下面的示例中，我们将讨论 Boost.Python 的一个轻量级替代方案。

# 使用 pybind11 构建 C++和 Python 项目

本示例的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-09/recipe-05`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-09/recipe-05)找到，并包含一个 C++示例。该示例适用于 CMake 版本 3.11（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

在前一个示例中，我们使用了 Boost.Python 来实现 Python 与 C(++)的接口。在这个示例中，我们将尝试使用 pybind11 作为轻量级替代方案，该方案利用了 C++11 特性，因此需要支持 C++11 的编译器。与前一个示例相比，我们将展示如何在配置时获取 pybind11 依赖项，并使用我们在第四章，*创建和运行测试*，示例 3，*定义单元测试并与 Google Test 链接*中遇到的 FetchContent 方法构建我们的项目，包括 Python 接口，并在第八章，*超级构建模式*，示例 4，*使用超级构建管理依赖项：III. Google Test 框架*中进行了讨论。在第十一章，*打包项目*，示例 2，*通过 PyPI 分发使用 CMake/pybind11 构建的 C++/Python 项目*中，我们将重新访问此示例，并展示如何打包它并通过 pip 安装。

# 准备就绪

我们将保持`account.cpp`相对于前两个示例不变，只修改`account.hpp`：

```cpp
#pragma once

#include <pybind11/pybind11.h>

class Account {
public:
  Account();
  ~Account();

  void deposit(const double amount);
  void withdraw(const double amount);
  double get_balance() const;

private:
  double balance;
};

namespace py = pybind11;

PYBIND11_MODULE(account, m) {
  py::class_<Account>(m, "Account")
      .def(py::init())
      .def("deposit", &Account::deposit)
      .def("withdraw", &Account::withdraw)
      .def("get_balance", &Account::get_balance);
}
```

我们将遵循 pybind11 文档中的“使用 CMake 构建”指南（[`pybind11.readthedocs.io/en/stable/compiling.html#building-with-cmake`](https://pybind11.readthedocs.io/en/stable/compiling.html#building-with-cmake)），并介绍使用`add_subdirectory`添加 pybind11 的 CMake 代码。然而，我们不会将 pybind11 源代码明确放入我们的项目目录中，而是演示如何在配置时使用`FetchContent`（[`cmake.org/cmake/help/v3.11/module/FetchContent.html`](https://cmake.org/cmake/help/v3.11/module/FetchContent.html)）获取 pybind11 源代码。

为了在下一个示例中更好地重用代码，我们还将所有源代码放入子目录中，并使用以下项目布局：

```cpp
.
├── account
│   ├── account.cpp
│   ├── account.hpp
│   ├── CMakeLists.txt
│   └── test.py
└── CMakeLists.txt
```

# 如何操作

让我们详细分析这个项目中各个`CMakeLists.txt`文件的内容：

1.  根目录的`CMakeLists.txt`文件包含熟悉的头部信息：

```cpp
# define minimum cmake version
cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

# project name and supported language
project(recipe-05 LANGUAGES CXX)

# require C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  在此文件中，我们还查询将用于测试的 Python 解释器：

```cpp
find_package(PythonInterp REQUIRED)
```

1.  然后，我们包含账户子目录：

```cpp
add_subdirectory(account)
```

1.  之后，我们定义单元测试：

```cpp
# turn on testing
enable_testing()

# define test
add_test(
  NAME
    python_test
  COMMAND
    ${CMAKE_COMMAND} -E env ACCOUNT_MODULE_PATH=$<TARGET_FILE_DIR:account>
    ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/account/test.py
  )
```

1.  在`account/CMakeLists.txt`文件中，我们在配置时获取 pybind11 源代码：

```cpp
include(FetchContent)

FetchContent_Declare(
  pybind11_sources
  GIT_REPOSITORY https://github.com/pybind/pybind11.git
  GIT_TAG v2.2
)

FetchContent_GetProperties(pybind11_sources)

if(NOT pybind11_sources_POPULATED)
  FetchContent_Populate(pybind11_sources)

  add_subdirectory(
    ${pybind11_sources_SOURCE_DIR}
    ${pybind11_sources_BINARY_DIR}
    )
endif()
```

1.  最后，我们定义 Python 模块。再次使用`add_library`的`MODULE`选项。我们还为我们的库目标设置前缀和后缀属性为`PYTHON_MODULE_PREFIX`和`PYTHON_MODULE_EXTENSION`，这些属性由 pybind11 适当地推断出来：

```cpp
add_library(account
  MODULE
    account.cpp
  )

target_link_libraries(account
  PUBLIC
    pybind11::module
  )

set_target_properties(account
  PROPERTIES
    PREFIX "${PYTHON_MODULE_PREFIX}"
    SUFFIX "${PYTHON_MODULE_EXTENSION}"
  )
```

1.  让我们测试一下：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
$ ctest

 Start 1: python_test
1/1 Test #1: python_test ...................... Passed 0.04 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) = 0.04 sec
```

# 它是如何工作的

pybind11 的功能和使用与 Boost.Python 非常相似，不同的是 pybind11 是一个更轻量级的依赖项——尽管我们需要编译器的 C++11 支持。在`account.hpp`中的接口定义与前一个示例中的定义相当相似：

```cpp
#include <pybind11/pybind11.h>

// ...

namespace py = pybind11;

PYBIND11_MODULE(account, m) {
  py::class_<Account>(m, "Account")
      .def(py::init())
      .def("deposit", &Account::deposit)
      .def("withdraw", &Account::withdraw)
      .def("get_balance", &Account::get_balance);
}
```

再次，我们可以清楚地看到 Python 方法是如何映射到 C++函数的。解释`PYBIND11_MODULE`的库在导入的目标`pybind11::module`中定义，我们使用以下方式包含它：

```cpp
add_subdirectory(
  ${pybind11_sources_SOURCE_DIR}
  ${pybind11_sources_BINARY_DIR}
  )
```

与前一个配方相比，有两个不同之处：

+   我们不要求系统上安装了 pybind11，因此不会尝试定位它。

+   在项目开始构建时，包含 pybind11 `CMakeLists.txt`的`${pybind11_sources_SOURCE_DIR}`子目录并不存在。

解决此挑战的一种方法是使用`FetchContent`模块，该模块在配置时获取 pybind11 源代码和 CMake 基础设施，以便我们可以使用`add_subdirectory`引用它。采用`FetchContent`模式，我们现在可以假设 pybind11 在构建树中可用，这使得我们能够构建并链接 Python 模块。

```cpp
add_library(account
  MODULE
    account.cpp
  )

target_link_libraries(account
  PUBLIC
    pybind11::module
  )
```

我们使用以下命令确保 Python 模块库获得一个与 Python 环境兼容的定义良好的前缀和后缀：

```cpp
set_target_properties(account
  PROPERTIES
    PREFIX ${PYTHON_MODULE_PREFIX}
    SUFFIX ${PYTHON_MODULE_EXTENSION}
  )
```

顶级`CMakeLists.txt`文件的其余部分用于测试（我们使用与前一个配方相同的`test.py`）。

# 还有更多

我们可以将 pybind11 源代码作为项目源代码仓库的一部分，这将简化 CMake 结构并消除在编译时需要网络访问 pybind11 源代码的要求。或者，我们可以将 pybind11 源路径定义为 Git 子模块（[`git-scm.com/book/en/v2/Git-Tools-Submodules`](https://git-scm.com/book/en/v2/Git-Tools-Submodules)），以简化更新 pybind11 源依赖关系。

在本例中，我们使用`FetchContent`解决了这个问题，它提供了一种非常紧凑的方法来引用 CMake 子项目，而无需显式跟踪其源代码。此外，我们还可以使用所谓的超级构建方法来解决这个问题（参见第八章，*The Superbuild Pattern*）。

# 另请参阅

若想了解如何暴露简单函数、定义文档字符串、映射内存缓冲区以及获取更多阅读材料，请参考 pybind11 文档：[`pybind11.readthedocs.io`](https://pybind11.readthedocs.io)。

# 使用 Python CFFI 混合 C、C++、Fortran 和 Python

本配方的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-09/recipe-06`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-09/recipe-06)找到，并包含 C++和 Fortran 示例。这些配方适用于 CMake 版本 3.5（及更高版本）。这两个版本的配方已在 GNU/Linux、macOS 和 Windows 上进行了测试。

在前三个菜谱中，我们讨论了 Cython、Boost.Python 和 pybind11 作为连接 Python 和 C++的工具，提供了一种现代且清晰的方法。在前面的菜谱中，主要接口是 C++接口。然而，我们可能会遇到没有 C++接口可供连接的情况，这时我们可能希望将 Python 与 Fortran 或其他语言连接起来。

在本菜谱中，我们将展示一种使用 Python C Foreign Function Interface（CFFI；另见[`cffi.readthedocs.io`](https://cffi.readthedocs.io)）的替代方法来连接 Python。由于 C 是编程语言的*通用语*，大多数编程语言（包括 Fortran）都能够与 C 接口通信，Python CFFI 是一种将 Python 与大量语言连接的工具。Python CFFI 的一个非常好的特点是，生成的接口是薄的且不侵入的，这意味着它既不限制 Python 层的语言特性，也不对 C 层以下的代码施加任何限制，除了需要一个 C 接口。

在本菜谱中，我们将应用 Python CFFI 通过 C 接口将 Python 和 C++连接起来，使用在前述菜谱中介绍的银行账户示例。我们的目标是实现一个上下文感知的接口，可以实例化多个银行账户，每个账户都携带其内部状态。我们将通过本菜谱结束时对如何使用 Python CFFI 将 Python 与 Fortran 连接进行评论。在第十一章，*打包项目*，菜谱 3，*通过 CMake/CFFI 构建的 C/Fortran/Python 项目通过 PyPI 分发*，我们将重新审视这个示例，并展示如何打包它，使其可以通过 pip 安装。

# 准备工作

我们将需要几个文件来完成这个菜谱。让我们从 C++实现和接口开始。我们将把这些文件放在一个名为`account/implementation`的子目录中。实现文件（`cpp_implementation.cpp`）与之前的菜谱类似，但包含了额外的`assert`语句，因为我们将在一个不透明的句柄中保持对象的状态，并且我们必须确保在尝试访问它之前创建了对象：

```cpp
#include "cpp_implementation.hpp"

#include <cassert>

Account::Account() {
  balance = 0.0;
  is_initialized = true;
}

Account::~Account() {
  assert(is_initialized);
  is_initialized = false;
}

void Account::deposit(const double amount) {
  assert(is_initialized);
  balance += amount;
}

void Account::withdraw(const double amount) {
  assert(is_initialized);
  balance -= amount;
}

double Account::get_balance() const {
  assert(is_initialized);
  return balance;
}
```

接口文件（`cpp_implementation.hpp`）包含以下内容：

```cpp
#pragma once

class Account {
public:
  Account();
  ~Account();

  void deposit(const double amount);
  void withdraw(const double amount);
  double get_balance() const;

private:
  double balance;
  bool is_initialized;
};
```

此外，我们隔离了一个 C—C++接口（`c_cpp_interface.cpp`）。这将是我们尝试使用 Python CFFI 连接的接口：

```cpp
#include "account.h"
#include "cpp_implementation.hpp"

#define AS_TYPE(Type, Obj) reinterpret_cast<Type *>(Obj)
#define AS_CTYPE(Type, Obj) reinterpret_cast<const Type *>(Obj)

account_context_t *account_new() {
  return AS_TYPE(account_context_t, new Account());
}

void account_free(account_context_t *context) { delete AS_TYPE(Account, context); }

void account_deposit(account_context_t *context, const double amount) {
  return AS_TYPE(Account, context)->deposit(amount);
}

void account_withdraw(account_context_t *context, const double amount) {
  return AS_TYPE(Account, context)->withdraw(amount);
}

double account_get_balance(const account_context_t *context) {
  return AS_CTYPE(Account, context)->get_balance();
}
```

在`account`目录下，我们描述了 C 接口（`account.h`）：

```cpp
/* CFFI would issue warning with pragma once */
#ifndef ACCOUNT_H_INCLUDED
#define ACCOUNT_H_INCLUDED

#ifndef ACCOUNT_API
#include "account_export.h"
#define ACCOUNT_API ACCOUNT_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct account_context;
typedef struct account_context account_context_t;

ACCOUNT_API
account_context_t *account_new();

ACCOUNT_API
void account_free(account_context_t *context);

ACCOUNT_API
void account_deposit(account_context_t *context, const double amount);

ACCOUNT_API
void account_withdraw(account_context_t *context, const double amount);

ACCOUNT_API
double account_get_balance(const account_context_t *context);

#ifdef __cplusplus
}
#endif

#endif /* ACCOUNT_H_INCLUDED */
```

我们还描述了 Python 接口，我们将在下面进行评论（`__init__.py`）：

```cpp
from subprocess import check_output
from cffi import FFI
import os
import sys
from configparser import ConfigParser
from pathlib import Path

def get_lib_handle(definitions, header_file, library_file):
    ffi = FFI()
    command = ['cc', '-E'] + definitions + [header_file]
    interface = check_output(command).decode('utf-8')

    # remove possible \r characters on windows which
    # would confuse cdef
    _interface = [l.strip('\r') for l in interface.split('\n')]

    ffi.cdef('\n'.join(_interface))
    lib = ffi.dlopen(library_file)
    return lib

# this interface requires the header file and library file
# and these can be either provided by interface_file_names.cfg
# in the same path as this file
# or if this is not found then using environment variables
_this_path = Path(os.path.dirname(os.path.realpath(__file__)))
_cfg_file = _this_path / 'interface_file_names.cfg'
if _cfg_file.exists():
    config = ConfigParser()
    config.read(_cfg_file)
    header_file_name = config.get('configuration', 'header_file_name')
    _header_file = _this_path / 'include' / header_file_name
    _header_file = str(_header_file)
    library_file_name = config.get('configuration', 'library_file_name')
    _library_file = _this_path / 'lib' / library_file_name
    _library_file = str(_library_file)
else:
    _header_file = os.getenv('ACCOUNT_HEADER_FILE')
    assert _header_file is not None
    _library_file = os.getenv('ACCOUNT_LIBRARY_FILE')
    assert _library_file is not None

_lib = get_lib_handle(definitions=['-DACCOUNT_API=', '-DACCOUNT_NOINCLUDE'],
                      header_file=_header_file,
                      library_file=_library_file)

# we change names to obtain a more pythonic API
new = _lib.account_new
free = _lib.account_free
deposit = _lib.account_deposit
withdraw = _lib.account_withdraw
get_balance = _lib.account_get_balance

__all__ = [
    '__version__',
    'new',
    'free',
    'deposit',
    'withdraw',
    'get_balance',
]
```

这是一堆文件，但是，正如我们将看到的，大部分接口工作是通用的和可重用的，实际的接口相当薄。总之，这是我们项目的布局：

```cpp
.
├── account
│   ├── account.h
│   ├── CMakeLists.txt
│   ├── implementation
│   │   ├── c_cpp_interface.cpp
│   │   ├── cpp_implementation.cpp
│   │   └── cpp_implementation.hpp
│   ├── __init__.py
│   └── test.py
└── CMakeLists.txt
```

# 如何操作

现在让我们使用 CMake 将这些文件组合成一个 Python 模块：

1.  顶层`CMakeLists.txt`文件包含一个熟悉的标题。此外，我们还根据 GNU 标准设置了编译库的位置：

```cpp
# define minimum cmake version
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# project name and supported language
project(recipe-06 LANGUAGES CXX)

# require C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# specify where to place libraries
include(GNUInstallDirs)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
```

1.  第二步是在 `account` 子目录下包含接口定义和实现源代码，我们将在下面详细介绍：

```cpp
# interface and sources
add_subdirectory(account)
```

1.  顶层的 `CMakeLists.txt` 文件以定义测试（需要 Python 解释器）结束：

```cpp
# turn on testing
enable_testing()

# require python
find_package(PythonInterp REQUIRED)

# define test
add_test(
  NAME
    python_test
  COMMAND
    ${CMAKE_COMMAND} -E env ACCOUNT_MODULE_PATH=${CMAKE_CURRENT_SOURCE_DIR}
                            ACCOUNT_HEADER_FILE=${CMAKE_CURRENT_SOURCE_DIR}/account/account.h
                            ACCOUNT_LIBRARY_FILE=$<TARGET_FILE:account>
    ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/account/test.py
  )
```

1.  包含的 `account/CMakeLists.txt` 定义了共享库：

```cpp
add_library(account
  SHARED
    implementation/c_cpp_interface.cpp
    implementation/cpp_implementation.cpp
  )

target_include_directories(account
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
  )
```

1.  然后我们生成一个可移植的导出头文件：

```cpp
include(GenerateExportHeader)
generate_export_header(account
  BASE_NAME account
  )
```

1.  现在我们准备好了对 Python—C 接口进行测试：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
$ ctest

    Start 1: python_test
1/1 Test #1: python_test ...................... Passed 0.14 sec

100% tests passed, 0 tests failed out of 1
```

# 它是如何工作的

虽然前面的示例要求我们显式声明 Python—C 接口并将 Python 名称映射到 C(++) 符号，但 Python CFFI 会根据 C 头文件（在我们的例子中是 `account.h`）自动推断此映射。我们只需要向 Python CFFI 层提供描述 C 接口的头文件和包含符号的共享库。我们已经在主 `CMakeLists.txt` 文件中使用环境变量完成了此操作，并在 `__init__.py` 中查询了这些环境变量：

```cpp
# ...

def get_lib_handle(definitions, header_file, library_file):
    ffi = FFI()
    command = ['cc', '-E'] + definitions + [header_file]
    interface = check_output(command).decode('utf-8')

    # remove possible \r characters on windows which
    # would confuse cdef
    _interface = [l.strip('\r') for l in interface.split('\n')]

    ffi.cdef('\n'.join(_interface))
    lib = ffi.dlopen(library_file)
    return lib

# ...

_this_path = Path(os.path.dirname(os.path.realpath(__file__)))
_cfg_file = _this_path / 'interface_file_names.cfg'
if _cfg_file.exists():
    # we will discuss this section in chapter 11, recipe 3
else:
    _header_file = os.getenv('ACCOUNT_HEADER_FILE')
    assert _header_file is not None
    _library_file = os.getenv('ACCOUNT_LIBRARY_FILE')
    assert _library_file is not None

_lib = get_lib_handle(definitions=['-DACCOUNT_API=', '-DACCOUNT_NOINCLUDE'],
                      header_file=_header_file,
                      library_file=_library_file)

# ...
```

`get_lib_handle` 函数打开并解析头文件（使用 `ffi.cdef`），加载库（使用 `ffi.dlopen`），并返回库对象。前面的文件原则上具有通用性，可以不经修改地重用于其他连接 Python 和 C 或其他使用 Python CFFI 语言的项目。

`_lib` 库对象可以直接导出，但我们又多做了一步，以便在 Python 端使用时 Python 接口感觉更 *pythonic*：

```cpp
# we change names to obtain a more pythonic API
new = _lib.account_new
free = _lib.account_free
deposit = _lib.account_deposit
withdraw = _lib.account_withdraw
get_balance = _lib.account_get_balance

__all__ = [
    '__version__',
    'new',
    'free',
    'deposit',
    'withdraw',
    'get_balance',
]
```

有了这个改动，我们可以这样写：

```cpp
import account

account1 = account.new()

account.deposit(account1, 100.0)
```

另一种方法则不那么直观：

```cpp
from account import lib

account1 = lib.account_new()

lib.account_deposit(account1, 100.0)
```

请注意，我们能够使用上下文感知的 API 实例化和跟踪隔离的上下文：

```cpp
account1 = account.new()
account.deposit(account1, 10.0)

account2 = account.new()
account.withdraw(account1, 5.0)
account.deposit(account2, 5.0)
```

为了导入 `account` Python 模块，我们需要提供 `ACCOUNT_HEADER_FILE` 和 `ACCOUNT_LIBRARY_FILE` 环境变量，就像我们为测试所做的那样：

```cpp
add_test(
  NAME
    python_test
  COMMAND
    ${CMAKE_COMMAND} -E env ACCOUNT_MODULE_PATH=${CMAKE_CURRENT_SOURCE_DIR}
                            ACCOUNT_HEADER_FILE=${CMAKE_CURRENT_SOURCE_DIR}/account/account.h
                            ACCOUNT_LIBRARY_FILE=$<TARGET_FILE:account>
    ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/account/test.py
  )
```

在 第十一章《打包项目》中，我们将讨论如何创建一个可以使用 pip 安装的 Python 包，其中头文件和库文件将安装在定义良好的位置，这样我们就不必定义任何环境变量来使用 Python 模块。

讨论了接口的 Python 方面之后，现在让我们考虑接口的 C 方面。`account.h` 的本质是这一部分：

```cpp
struct account_context;
typedef struct account_context account_context_t;

ACCOUNT_API
account_context_t *account_new();

ACCOUNT_API
void account_free(account_context_t *context);

ACCOUNT_API
void account_deposit(account_context_t *context, const double amount);

ACCOUNT_API
void account_withdraw(account_context_t *context, const double amount);

ACCOUNT_API
double account_get_balance(const account_context_t *context);
```

不透明的句柄 `account_context` 保存对象的状态。`ACCOUNT_API` 在 `account_export.h` 中定义，该文件由 CMake 在 `account/interface/CMakeLists.txt` 中生成：

```cpp
include(GenerateExportHeader)
generate_export_header(account
  BASE_NAME account
  )
```

`account_export.h` 导出头文件定义了接口函数的可见性，并确保以可移植的方式完成。我们将在 第十章《编写安装程序》中更详细地讨论这一点。实际的实现可以在 `cpp_implementation.cpp` 中找到。它包含 `is_initialized` 布尔值，我们可以检查该值以确保 API 函数按预期顺序调用：上下文不应在创建之前或释放之后被访问。

# 还有更多内容

在设计 Python-C 接口时，重要的是要仔细考虑在哪一侧分配数组：数组可以在 Python 侧分配并传递给 C(++)实现，或者可以在 C(++)实现中分配并返回一个指针。后一种方法在缓冲区大小*事先*未知的情况下很方便。然而，从 C(++)-侧返回分配的数组指针可能会导致内存泄漏，因为 Python 的垃圾回收不会“看到”已分配的数组。我们建议设计 C API，使得数组可以在外部分配并传递给 C 实现。然后，这些数组可以在`__init__.py`内部分配，如本例所示：

```cpp
from cffi import FFI
import numpy as np

_ffi = FFI()

def return_array(context, array_len):

    # create numpy array
    array_np = np.zeros(array_len, dtype=np.float64)

    # cast a pointer to its data
    array_p = _ffi.cast("double *", array_np.ctypes.data)

    # pass the pointer
    _lib.mylib_myfunction(context, array_len, array_p)

    # return the array as a list
    return array_np.tolist()
```

`return_array`函数返回一个 Python 列表。由于我们已经在 Python 侧完成了所有的分配工作，因此我们不必担心内存泄漏，可以将清理工作留给垃圾回收。

对于 Fortran 示例，我们建议读者参考以下配方仓库：[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-09/recipe-06/fortran-example`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-09/recipe-06/fortran-example)。与 C++实现的主要区别在于，账户库是由 Fortran 90 源文件编译而成，我们在`account/CMakeLists.txt`中对此进行了考虑：

```cpp
add_library(account
  SHARED
    implementation/fortran_implementation.f90
  )
```

上下文保存在用户定义的类型中：

```cpp
type :: account
  private
  real(c_double) :: balance
  logical :: is_initialized = .false.
end type
```

Fortran 实现能够通过使用`iso_c_binding`模块解析未更改的`account.h`中定义的符号和方法：

```cpp
module account_implementation

  use, intrinsic :: iso_c_binding, only: c_double, c_ptr

  implicit none

  private

  public account_new
  public account_free
  public account_deposit
  public account_withdraw
  public account_get_balance

  type :: account
    private
    real(c_double) :: balance
    logical :: is_initialized = .false.
  end type

contains

  type(c_ptr) function account_new() bind (c)
    use, intrinsic :: iso_c_binding, only: c_loc
    type(account), pointer :: f_context
    type(c_ptr) :: context

    allocate(f_context)
    context = c_loc(f_context)
    account_new = context
    f_context%balance = 0.0d0
    f_context%is_initialized = .true.
  end function

  subroutine account_free(context) bind (c)
    use, intrinsic :: iso_c_binding, only: c_f_pointer
    type(c_ptr), value :: context
    type(account), pointer :: f_context

    call c_f_pointer(context, f_context)
    call check_valid_context(f_context)
    f_context%balance = 0.0d0
    f_context%is_initialized = .false.
    deallocate(f_context)
  end subroutine

  subroutine check_valid_context(f_context)
    type(account), pointer, intent(in) :: f_context
    if (.not. associated(f_context)) then
        print *, 'ERROR: context is not associated'
        stop 1
    end if
    if (.not. f_context%is_initialized) then
        print *, 'ERROR: context is not initialized'
        stop 1
    end if
  end subroutine

  subroutine account_withdraw(context, amount) bind (c)
    use, intrinsic :: iso_c_binding, only: c_f_pointer
    type(c_ptr), value :: context
    real(c_double), value :: amount
    type(account), pointer :: f_context

    call c_f_pointer(context, f_context)
    call check_valid_context(f_context)
    f_context%balance = f_context%balance - amount
  end subroutine

  subroutine account_deposit(context, amount) bind (c)
    use, intrinsic :: iso_c_binding, only: c_f_pointer
    type(c_ptr), value :: context
    real(c_double), value :: amount
    type(account), pointer :: f_context

    call c_f_pointer(context, f_context)
    call check_valid_context(f_context)
    f_context%balance = f_context%balance + amount
  end subroutine

  real(c_double) function account_get_balance(context) bind (c)
    use, intrinsic :: iso_c_binding, only: c_f_pointer
    type(c_ptr), value, intent(in) :: context
    type(account), pointer :: f_context

    call c_f_pointer(context, f_context)
    call check_valid_context(f_context)
    account_get_balance = f_context%balance
  end function

end module
```

# 另请参阅

本配方和解决方案的灵感来源于 Armin Ronacher 的帖子“Beautiful Native Libraries”，[`lucumr.pocoo.org/2013/8/18/beautiful-native-libraries/`](http://lucumr.pocoo.org/2013/8/18/beautiful-native-libraries/)。
