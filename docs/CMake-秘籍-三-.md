# CMake 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/ecf89da6185e63c44e748e0980911fef`](https://zh.annas-archive.org/md5/ecf89da6185e63c44e748e0980911fef)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：创建和运行测试

在本章中，我们将介绍以下内容：

+   创建一个简单的单元测试

+   使用 Catch2 库定义单元测试

+   定义单元测试并链接到 Google Test

+   定义单元测试并链接到 Boost 测试

+   使用动态分析检测内存缺陷

+   测试预期失败

+   为长时间测试设置超时

+   并行运行测试

+   运行测试的子集

+   使用测试夹具

# 引言

测试是代码开发工具箱的核心组成部分。通过使用单元和集成测试进行自动化测试，不仅可以帮助开发者在早期检测功能回归，还可以作为新加入项目的开发者的起点。它可以帮助新开发者提交代码变更，并确保预期的功能得以保留。对于代码的用户来说，自动化测试在验证安装是否保留了代码功能方面至关重要。从一开始就为单元、模块或库使用测试的一个好处是，它可以引导程序员编写更加模块化和不那么复杂的代码结构，采用纯粹的、函数式的风格，最小化并局部化全局变量和全局状态。

在本章中，我们将演示如何将测试集成到 CMake 构建结构中，使用流行的测试库和框架，并牢记以下目标：

+   让用户、开发者和持续集成服务轻松运行测试套件。在使用 Unix Makefiles 时，应该简单到只需输入`make test`。

+   通过最小化总测试时间来高效运行测试，以最大化测试经常运行的概率——理想情况下，每次代码更改后都进行测试。

# 创建一个简单的单元测试

本示例的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-01`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-01)找到，并包含一个 C++示例。该示例适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

在本食谱中，我们将介绍使用 CTest 进行单元测试，CTest 是作为 CMake 一部分分发的测试工具。为了保持对 CMake/CTest 方面的关注并最小化认知负荷，我们希望尽可能简化要测试的代码。我们的计划是编写并测试能够求和整数的代码，仅此而已。就像在小学时，我们在学会加法后学习乘法和除法一样，此时，我们的示例代码只会加法，并且只会理解整数；它不需要处理浮点数。而且，就像年轻的卡尔·弗里德里希·高斯被他的老师测试从 1 到 100 求和所有自然数一样，我们将要求我们的代码做同样的事情——尽管没有使用高斯所用的聪明分组技巧。为了展示 CMake 对实现实际测试的语言没有任何限制，我们将不仅使用 C++可执行文件，还使用 Python 脚本和 shell 脚本来测试我们的代码。为了简单起见，我们将不使用任何测试库来完成这个任务，但我们将在本章后面的食谱中介绍 C++测试框架。

# 准备就绪

我们的代码示例包含三个文件。实现源文件`sum_integers.cpp`负责对整数向量进行求和，并返回总和：

```cpp
#include "sum_integers.hpp"

#include <vector>

int sum_integers(const std::vector<int> integers) {
  auto sum = 0;
  for (auto i : integers) {
    sum += i;
  }
  return sum;
}
```

对于这个例子，无论这是否是最优雅的向量求和实现方式都无关紧要。接口被导出到我们的示例库中的`sum_integers.hpp`，如下所示：

```cpp
#pragma once

#include <vector>

int sum_integers(const std::vector<int> integers);
```

最后，`main.cpp`中定义了主函数，它从`argv[]`收集命令行参数，将它们转换成一个整数向量，调用`sum_integers`函数，并将结果打印到输出：

```cpp
#include "sum_integers.hpp"

#include <iostream>
#include <string>
#include <vector>

// we assume all arguments are integers and we sum them up
// for simplicity we do not verify the type of arguments
int main(int argc, char *argv[]) {

  std::vector<int> integers;
  for (auto i = 1; i < argc; i++) {
    integers.push_back(std::stoi(argv[i]));
  }
  auto sum = sum_integers(integers);

  std::cout << sum << std::endl;
}
```

我们的目标是使用 C++可执行文件（`test.cpp`）、Bash shell 脚本（`test.sh`）和 Python 脚本（`test.py`）来测试这段代码，以证明 CMake 并不真正关心我们偏好哪种编程或脚本语言，只要实现能够返回零或非零值，CMake 可以将其解释为成功或失败，分别。

在 C++示例（`test.cpp`）中，我们通过调用`sum_integers`验证 1 + 2 + 3 + 4 + 5 等于 15：

```cpp
#include "sum_integers.hpp"

#include <vector>

int main() {
  auto integers = {1, 2, 3, 4, 5};

  if (sum_integers(integers) == 15) {
    return 0;
  } else {
    return 1;
  }
}
```

Bash shell 脚本测试示例调用可执行文件，该文件作为位置参数接收：

```cpp
#!/usr/bin/env bash

EXECUTABLE=$1

OUTPUT=$($EXECUTABLE 1 2 3 4)

if [ "$OUTPUT" = "10" ]
then
    exit 0
else
    exit 1
fi
```

此外，Python 测试脚本直接调用可执行文件（使用`--executable`命令行参数传递），并允许它使用`--short`命令行参数执行：

```cpp
import subprocess
import argparse

# test script expects the executable as argument
parser = argparse.ArgumentParser()
parser.add_argument('--executable',
                    help='full path to executable')
parser.add_argument('--short',
                    default=False,
                    action='store_true',
                    help='run a shorter test')
args = parser.parse_args()

def execute_cpp_code(integers):
    result = subprocess.check_output([args.executable] + integers)
    return int(result)

if args.short:
    # we collect [1, 2, ..., 100] as a list of strings
    result = execute_cpp_code([str(i) for i in range(1, 101)])
    assert result == 5050, 'summing up to 100 failed'
else:
    # we collect [1, 2, ..., 1000] as a list of strings
    result = execute_cpp_code([str(i) for i in range(1, 1001)])
    assert result == 500500, 'summing up to 1000 failed'
```

# 如何操作

现在我们将逐步描述如何为我们的项目设置测试，如下所示：

1.  对于这个例子，我们需要 C++11 支持、一个可用的 Python 解释器以及 Bash shell：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-01 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PythonInterp REQUIRED)
find_program(BASH_EXECUTABLE NAMES bash REQUIRED)
```

1.  然后我们定义了库、主可执行文件的依赖项以及测试可执行文件：

```cpp
# example library
add_library(sum_integers sum_integers.cpp)

# main code
add_executable(sum_up main.cpp)
target_link_libraries(sum_up sum_integers)
```

```cpp
# testing binary
add_executable(cpp_test test.cpp)
target_link_libraries(cpp_test sum_integers)
```

1.  最后，我们开启测试功能并定义了四个测试。最后两个测试调用同一个 Python 脚本；首先是没有任何命令行参数，然后是使用`--short`：

```cpp
enable_testing()

add_test(
  NAME bash_test
  COMMAND ${BASH_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test.sh $<TARGET_FILE:sum_up>
  )

add_test(
  NAME cpp_test
  COMMAND $<TARGET_FILE:cpp_test>
  )

add_test(
  NAME python_test_long
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test.py --executable $<TARGET_FILE:sum_up>
  )

add_test(
  NAME python_test_short
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test.py --short --executable $<TARGET_FILE:sum_up>
  )
```

1.  现在，我们准备好配置和构建代码了。首先，我们手动测试它：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
$ ./sum_up 1 2 3 4 5

15
```

1.  然后，我们可以使用`ctest`运行测试集。

```cpp
$ ctest

Test project /home/user/cmake-recipes/chapter-04/recipe-01/cxx-example/build
    Start 1: bash_test
1/4 Test #1: bash_test ........................ Passed 0.01 sec
    Start 2: cpp_test
2/4 Test #2: cpp_test ......................... Passed 0.00 sec
    Start 3: python_test_long
3/4 Test #3: python_test_long ................. Passed 0.06 sec
    Start 4: python_test_short
4/4 Test #4: python_test_short ................ Passed 0.05 sec

100% tests passed, 0 tests failed out of 4

Total Test time (real) = 0.12 sec
```

1.  您还应该尝试破坏实现，以验证测试集是否捕获了更改。

# 它是如何工作的

这里的两个关键命令是`enable_testing()`，它为这个目录及其所有子文件夹（在本例中，整个项目，因为我们将其放在主`CMakeLists.txt`中）启用测试，以及`add_test()`，它定义一个新测试并设置测试名称和运行命令；例如：

```cpp
add_test(
  NAME cpp_test
  COMMAND $<TARGET_FILE:cpp_test>
  )
```

在前面的示例中，我们使用了一个生成器表达式：`$<TARGET_FILE:cpp_test>`。生成器表达式是在**构建系统生成时间**评估的表达式。我们将在第五章，*配置时间和构建时间操作*，第 9 个配方，*使用生成器表达式微调配置和编译*中更详细地返回生成器表达式。目前，我们可以声明`$<TARGET_FILE:cpp_test>`将被替换为`cpp_test`可执行目标的完整路径。

生成器表达式在定义测试的上下文中非常方便，因为我们不必将可执行文件的位置和名称硬编码到测试定义中。以可移植的方式实现这一点将非常繁琐，因为可执行文件的位置和可执行文件后缀（例如，Windows 上的`.exe`后缀）可能在操作系统、构建类型和生成器之间有所不同。使用生成器表达式，我们不必明确知道位置和名称。

还可以向测试命令传递参数以运行；例如：

```cpp
add_test(
  NAME python_test_short
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test.py --short --executable $<TARGET_FILE:sum_up>
  )
```

在本例中，我们按顺序运行测试（第 8 个配方，*并行运行测试*，将向您展示如何通过并行执行测试来缩短总测试时间），并且测试按定义的顺序执行（第 9 个配方，*运行测试子集*，将向您展示如何更改顺序或运行测试子集）。程序员负责定义实际的测试命令，该命令可以用操作系统环境支持的任何语言编程。CTest 唯一关心的是决定测试是否通过或失败的测试命令的返回代码。CTest 遵循标准约定，即零返回代码表示成功，非零返回代码表示失败。任何可以返回零或非零的脚本都可以用来实现测试用例。

既然我们知道如何定义和执行测试，了解如何诊断测试失败也很重要。为此，我们可以向代码中引入一个错误，并让所有测试失败：

```cpp
    Start 1: bash_test
1/4 Test #1: bash_test ........................***Failed 0.01 sec
    Start 2: cpp_test
2/4 Test #2: cpp_test .........................***Failed 0.00 sec
    Start 3: python_test_long
3/4 Test #3: python_test_long .................***Failed 0.06 sec
    Start 4: python_test_short
4/4 Test #4: python_test_short ................***Failed 0.06 sec

0% tests passed, 4 tests failed out of 4

Total Test time (real) = 0.13 sec
The following tests FAILED:
    1 - bash_test (Failed)
    2 - cpp_test (Failed)
    3 - python_test_long (Failed)
    4 - python_test_short (Failed)
Errors while running CTest
```

如果我们希望了解更多信息，可以检查文件`Testing/Temporary/LastTestsFailed.log`。该文件包含测试命令的完整输出，是进行事后分析时的第一个查看地点。通过使用以下 CLI 开关，可以从 CTest 获得更详细的测试输出：

+   `--output-on-failure`：如果测试失败，将打印测试程序产生的任何内容到屏幕上。

+   `-V`：将启用测试的详细输出。

+   `-VV`：启用更详细的测试输出。

CTest 提供了一个非常方便的快捷方式，可以仅重新运行先前失败的测试；使用的 CLI 开关是`--rerun-failed`，这在调试过程中证明极其有用。

# 还有更多内容。

考虑以下定义：

```cpp
add_test(
  NAME python_test_long
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test.py --executable $<TARGET_FILE:sum_up>
  )
```

前面的定义可以通过显式指定脚本将在其中运行的`WORKING_DIRECTORY`来重新表达，如下所示：

```cpp
add_test(
  NAME python_test_long
  COMMAND ${PYTHON_EXECUTABLE} test.py --executable $<TARGET_FILE:sum_up>
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  )
```

我们还将提到，测试名称可以包含`/`字符，这在按名称组织相关测试时可能很有用；例如：

```cpp
add_test(
  NAME python/long
  COMMAND ${PYTHON_EXECUTABLE} test.py --executable $<TARGET_FILE:sum_up>
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  )
```

有时，我们需要为测试脚本设置环境变量。这可以通过`set_tests_properties`实现。

```cpp
set_tests_properties(python_test
  PROPERTIES 
    ENVIRONMENT
      ACCOUNT_MODULE_PATH=${CMAKE_CURRENT_SOURCE_DIR}
      ACCOUNT_HEADER_FILE=${CMAKE_CURRENT_SOURCE_DIR}/account/account.h
      ACCOUNT_LIBRARY_FILE=$<TARGET_FILE:account>
  )
```

这种方法可能并不总是跨不同平台都健壮，但 CMake 提供了一种绕过这种潜在健壮性不足的方法。以下代码片段等同于上述代码片段，并通过`CMAKE_COMMAND`预先添加环境变量，然后执行实际的 Python 测试脚本：

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

再次注意，使用生成器表达式`$<TARGET_FILE:account>`来传递库文件的位置，而无需显式硬编码路径。

我们使用`ctest`命令执行了测试集，但 CMake 还将为生成器创建目标（对于 Unix Makefile 生成器使用`make test`，对于 Ninja 工具使用`ninja test`，或对于 Visual Studio 使用`RUN_TESTS`）。这意味着还有另一种（几乎）便携的方式来运行测试步骤：

```cpp
$ cmake --build . --target test
```

不幸的是，在使用 Visual Studio 生成器时这会失败，我们必须使用`RUN_TESTS`代替：

```cpp
$ cmake --build . --target RUN_TESTS
```

`ctest`命令提供了丰富的命令行参数。其中一些将在后面的食谱中探讨。要获取完整列表，请尝试`ctest --help`。命令`cmake --help-manual ctest`将输出完整的 CTest 手册到屏幕上。

# 使用 Catch2 库定义单元测试

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-02`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-02)获取，并包含一个 C++示例。该食谱适用于 CMake 版本 3.5（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

在前一个配方中，我们在`test.cpp`中使用整数返回码来表示成功或失败。这对于简单的测试来说是可以的，但通常我们希望使用一个提供基础设施的测试框架，以便运行更复杂的测试，包括固定装置、与数值容差的比较，以及如果测试失败时更好的错误报告。一个现代且流行的测试库是 Catch2（[`github.com/catchorg/Catch2`](https://github.com/catchorg/Catch2)）。这个测试框架的一个很好的特点是它可以作为单个头文件库包含在你的项目中，这使得编译和更新框架特别容易。在本配方中，我们将使用 CMake 与 Catch2 结合，测试在前一个配方中介绍的求和代码。

# 准备就绪

我们将保持`main.cpp`、`sum_integers.cpp`和`sum_integers.hpp`与之前的配方不变，但将更新`test.cpp`：

```cpp
#include "sum_integers.hpp"

// this tells catch to provide a main()
// only do this in one cpp file
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include <vector>

TEST_CASE("Sum of integers for a short vector", "[short]") {
  auto integers = {1, 2, 3, 4, 5};
  REQUIRE(sum_integers(integers) == 15);
}

TEST_CASE("Sum of integers for a longer vector", "[long]") {
  std::vector<int> integers;
  for (int i = 1; i < 1001; ++i) {
    integers.push_back(i);
  }
  REQUIRE(sum_integers(integers) == 500500);
}
```

我们还需要`catch.hpp`头文件，可以从[`github.com/catchorg/Catch2`](https://github.com/catchorg/Catch2)（我们使用了 2.0.1 版本）下载，并将其放置在项目根目录中，与`test.cpp`并列。

# 如何做

为了使用 Catch2 库，我们将修改前一个配方的`CMakeLists.txt`，执行以下步骤：

1.  我们可以保持`CMakeLists.txt`的大部分内容不变：

```cpp
# set minimum cmake version
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# project name and language
project(recipe-02 LANGUAGES CXX)

# require C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# example library
add_library(sum_integers sum_integers.cpp)

# main code
add_executable(sum_up main.cpp)
target_link_libraries(sum_up sum_integers)

# testing binary
add_executable(cpp_test test.cpp)
target_link_libraries(cpp_test sum_integers)
```

1.  与前一个配方相比，唯一的改变是删除所有测试，只保留一个，并重命名它（以明确我们改变了什么）。请注意，我们向我们的单元测试可执行文件传递了`--success`选项。这是 Catch2 的一个选项，即使在成功时也会从测试中产生输出：

```cpp
enable_testing()

add_test(
  NAME catch_test
  COMMAND $<TARGET_FILE:cpp_test> --success
  )
```

1.  就这样！让我们配置、构建并测试。测试将使用 CTest 中的`-VV`选项运行，以从单元测试可执行文件获取输出：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
$ ctest -V

UpdateCTestConfiguration from :/home/user/cmake-cookbook/chapter-04/recipe-02/cxx-example/build/DartConfiguration.tcl
UpdateCTestConfiguration from :/home/user/cmake-cookbook/chapter-04/recipe-02/cxx-example/build/DartConfiguration.tcl
Test project /home/user/cmake-cookbook/chapter-04/recipe-02/cxx-example/build
Constructing a list of tests
Done constructing a list of tests
Updating test list for fixtures
Added 0 tests to meet fixture requirements
Checking test dependency graph...
Checking test dependency graph end
test 1
 Start 1: catch_test

1: Test command: /home/user/cmake-cookbook/chapter-04/recipe-02/cxx-example/build/cpp_test "--success"
1: Test timeout computed to be: 10000000
1: 
1: ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1: cpp_test is a Catch v2.0.1 host application.
1: Run with -? for options
1: 
1: ----------------------------------------------------------------
1: Sum of integers for a short vector
1: ----------------------------------------------------------------
1: /home/user/cmake-cookbook/chapter-04/recipe-02/cxx-example/test.cpp:10
1: ...................................................................
1: 
1: /home/user/cmake-cookbook/chapter-04/recipe-02/cxx-example/test.cpp:12: 
1: PASSED:
1: REQUIRE( sum_integers(integers) == 15 )
1: with expansion:
1: 15 == 15
1: 
1: ----------------------------------------------------------------
1: Sum of integers for a longer vector
1: ----------------------------------------------------------------
1: /home/user/cmake-cookbook/chapter-04/recipe-02/cxx-example/test.cpp:15
1: ...................................................................
1: 
1: /home/user/cmake-cookbook/chapter-04/recipe-02/cxx-example/test.cpp:20: 
1: PASSED:
1: REQUIRE( sum_integers(integers) == 500500 )
1: with expansion:
1: 500500 (0x7a314) == 500500 (0x7a314)
1: 
1: ===================================================================
1: All tests passed (2 assertions in 2 test cases)
1:
1/1 Test #1: catch_test ....................... Passed 0.00 s

100% tests passed, 0 tests failed out of 1

Total Test time (real) = 0.00 sec
```

1.  我们也可以直接尝试运行`cpp_test`二进制文件，并直接从 Catch2 看到输出：

```cpp
$ ./cpp_test --success

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
cpp_test is a Catch v2.0.1 host application.
Run with -? for options

-------------------------------------------------------------------
Sum of integers for a short vector
-------------------------------------------------------------------
/home/user/cmake-cookbook/chapter-04/recipe-02/cxx-example/test.cpp:10
...................................................................

/home/user/cmake-cookbook/chapter-04/recipe-02/cxx-example/test.cpp:12: 
PASSED:
  REQUIRE( sum_integers(integers) == 15 )
with expansion:
  15 == 15

-------------------------------------------------------------------
Sum of integers for a longer vector
-------------------------------------------------------------------
/home/user/cmake-cookbook/chapter-04/recipe-02/cxx-example/test.cpp:15
...................................................................

/home/user/cmake-cookbook/chapter-04/recipe-02/cxx-example/test.cpp:20: 
PASSED:
  REQUIRE( sum_integers(integers) == 500500 )
with expansion:
  500500 (0x7a314) == 500500 (0x7a314)

===================================================================
All tests passed (2 assertions in 2 test cases)
```

1.  Catch 将生成一个具有命令行界面的可执行文件。我们邀请你也尝试执行以下命令，以探索单元测试框架提供的选项：

```cpp
$ ./cpp_test --help
```

# 它是如何工作的

由于 Catch2 是一个单头文件框架，因此不需要定义和构建额外的目标。我们只需要确保 CMake 能够找到`catch.hpp`来构建`test.cpp`。为了方便，我们将其放置在与`test.cpp`相同的目录中，但我们也可以选择不同的位置，并使用`target_include_directories`指示该位置。另一种方法是将头文件包装成一个`INTERFACE`库。这可以按照 Catch2 文档中的说明进行（`https://github.com/catchorg/Catch2/blob/master/docs/build-systems.md#cmake`）：

```cpp
# Prepare "Catch" library for other executables
set(CATCH_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/catch)
add_library(Catch INTERFACE)
target_include_directories(Catch INTERFACE ${CATCH_INCLUDE_DIR})
```

那么我们将按照以下方式链接库：

```cpp
target_link_libraries(cpp_test Catch)
```

我们从第一章，*从简单可执行文件到库*中的食谱 3，*构建和链接静态和共享库*的讨论中回忆起，`INTERFACE`库是 CMake 提供的伪目标，对于指定项目外部的目标使用要求非常有用。

# 还有更多

这是一个简单的例子，重点在于 CMake。当然，Catch2 提供了更多功能。要获取 Catch2 框架的完整文档，请访问[`github.com/catchorg/Catch2`](https://github.com/catchorg/Catch2)。

# 另请参阅

Catch2 代码仓库包含一个由贡献的 CMake 函数，用于解析 Catch 测试并自动创建 CMake 测试，而无需显式键入`add_test()`函数；请参阅[`github.com/catchorg/Catch2/blob/master/contrib/ParseAndAddCatchTests.cmake`](https://github.com/catchorg/Catch2/blob/master/contrib/ParseAndAddCatchTests.cmake)。

# 定义单元测试并链接 Google Test

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-03`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-03)找到，并包含一个 C++示例。本食谱适用于 CMake 版本 3.11（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。代码仓库还包含一个与 CMake 3.5 兼容的示例。

在本食谱中，我们将演示如何使用 CMake 和 Google Test 框架实现单元测试。与之前的食谱不同，Google Test 框架不仅仅是一个头文件；它是一个包含多个需要构建和链接的文件的库。我们可以将这些文件与我们的代码项目放在一起，但为了让代码项目更轻量级，我们将在配置时下载 Google Test 源代码的明确定义版本，然后构建框架并与之链接。我们将使用相对较新的`FetchContent`模块（自 CMake 版本 3.11 起可用）。我们将在第八章，*超级构建模式*中重新讨论`FetchContent`，在那里我们将讨论模块在幕后是如何工作的，以及我们还将说明如何使用`ExternalProject_Add`来模拟它。本食谱的灵感来自（并改编自）[`cmake.org/cmake/help/v3.11/module/FetchContent.html`](https://cmake.org/cmake/help/v3.11/module/FetchContent.html)的示例。

# 准备工作

我们将保持`main.cpp`、`sum_integers.cpp`和`sum_integers.hpp`与之前的食谱不变，但将更新`test.cpp`源代码，如下所示：

```cpp
#include "sum_integers.hpp"
#include "gtest/gtest.h"

#include <vector>

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

TEST(example, sum_zero) {
  auto integers = {1, -1, 2, -2, 3, -3};
  auto result = sum_integers(integers);
  ASSERT_EQ(result, 0);
}

TEST(example, sum_five) {
  auto integers = {1, 2, 3, 4, 5};
  auto result = sum_integers(integers);
  ASSERT_EQ(result, 15);
}
```

如前述代码所示，我们选择不在我们的代码项目仓库中显式放置`gtest.h`或其他 Google Test 源文件，而是通过使用`FetchContent`模块在配置时下载它们。

# 如何操作

以下步骤描述了如何逐步设置`CMakeLists.txt`，以使用 GTest 编译可执行文件及其相应的测试：

1.  `CMakeLists.txt`的开头与前两个配方相比大部分未变，只是我们需要 CMake 3.11 以访问`FetchContent`模块：

```cpp
# set minimum cmake version
cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

# project name and language
project(recipe-03 LANGUAGES CXX)

# require C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

# example library
add_library(sum_integers sum_integers.cpp)

# main code
add_executable(sum_up main.cpp)
target_link_libraries(sum_up sum_integers)
```

1.  然后我们引入了一个 if 语句，检查`ENABLE_UNIT_TESTS`。默认情况下它是`ON`，但我们希望有可能将其关闭，以防我们没有网络下载 Google Test 源码：

```cpp
option(ENABLE_UNIT_TESTS "Enable unit tests" ON)
message(STATUS "Enable testing: ${ENABLE_UNIT_TESTS}")

if(ENABLE_UNIT_TESTS)
  # all the remaining CMake code will be placed here
endif()
```

1.  在 if 语句内部，我们首先包含`FetchContent`模块，声明一个新的要获取的内容，并查询其属性：

```cpp
include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.8.0
)

FetchContent_GetProperties(googletest)
```

1.  如果内容尚未填充（获取），我们获取并配置它。这将添加一些我们可以链接的目标。在本例中，我们对`gtest_main`感兴趣。该示例还包含一些使用 Visual Studio 编译的解决方法：

```cpp
if(NOT googletest_POPULATED)
  FetchContent_Populate(googletest)

  # Prevent GoogleTest from overriding our compiler/linker options
  # when building with Visual Studio
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  # Prevent GoogleTest from using PThreads
  set(gtest_disable_pthreads ON CACHE BOOL "" FORCE)

  # adds the targers: gtest, gtest_main, gmock, gmock_main
  add_subdirectory(
    ${googletest_SOURCE_DIR}
    ${googletest_BINARY_DIR}
    )

  # Silence std::tr1 warning on MSVC
  if(MSVC)
    foreach(_tgt gtest gtest_main gmock gmock_main)
      target_compile_definitions(${_tgt}
        PRIVATE
          "_SILENCE_TR1_NAMESPACE_DEPRECATION_WARNING"
        )
    endforeach()
  endif()
endif()
```

1.  然后我们定义了`cpp_test`可执行目标，并使用`target_sources`命令指定其源文件，使用`target_link_libraries`命令指定其链接库：

```cpp
add_executable(cpp_test "")

target_sources(cpp_test
  PRIVATE
    test.cpp
  )

target_link_libraries(cpp_test
  PRIVATE
    sum_integers
    gtest_main
  )
```

1.  最后，我们使用熟悉的`enable_testing`和`add_test`命令来定义单元测试：

```cpp
enable_testing()

add_test(
  NAME google_test
  COMMAND $<TARGET_FILE:cpp_test>
  )
```

1.  现在，我们准备好配置、构建和测试项目了：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
$ ctest

Test project /home/user/cmake-cookbook/chapter-04/recipe-03/cxx-example/build
    Start 1: google_test
1/1 Test #1: google_test ...................... Passed 0.00 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) = 0.00 sec
```

1.  我们也可以尝试直接运行`cpp_test`，如下所示：

```cpp
$ ./cpp_test

[==========] Running 2 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 2 tests from example
[ RUN      ] example.sum_zero
[       OK ] example.sum_zero (0 ms)
[ RUN      ] example.sum_five
[       OK ] example.sum_five (0 ms)
[----------] 2 tests from example (0 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test case ran. (0 ms total)
[  PASSED  ] 2 tests.
```

# 它是如何工作的

`FetchContent`模块允许在配置时填充内容，*通过*任何`ExternalProject`模块支持的方法，并且已成为 CMake 3.11 版本的标准部分。而`ExternalProject_Add()`在构建时下载（如第八章，*超级构建模式*所示），`FetchContent`模块使内容立即可用，以便主项目和获取的外部项目（在本例中为 Google Test）可以在 CMake 首次调用时处理，并且可以使用`add_subdirectory`嵌套。

为了获取 Google Test 源码，我们首先声明了外部内容：

```cpp
include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.8.0
)
```

在这种情况下，我们获取了一个带有特定标签（`release-1.8.0`）的 Git 仓库，但我们也可以从 Subversion、Mercurial 或 HTTP(S)源获取外部项目。有关可用选项，请参阅[`cmake.org/cmake/help/v3.11/module/ExternalProject.html`](https://cmake.org/cmake/help/v3.11/module/ExternalProject.html)上相应`ExternalProject_Add`命令的选项。

我们在调用`FetchContent_Populate()`之前使用`FetchContent_GetProperties()`命令检查内容填充是否已经处理；否则，如果`FetchContent_Populate()`被调用多次，它会抛出一个错误。

`FetchContent_Populate(googletest)`命令填充源码并定义`googletest_SOURCE_DIR`和`googletest_BINARY_DIR`，我们可以使用它们来处理 Google Test 项目（使用`add_subdirectory()`，因为它恰好也是一个 CMake 项目）：

```cpp
add_subdirectory(
  ${googletest_SOURCE_DIR}
  ${googletest_BINARY_DIR}
  )
```

上述定义了以下目标：`gtest`、`gtest_main`、`gmock`和`gmock_main`。在本示例中，我们只对`gtest_main`目标感兴趣，作为单元测试示例的库依赖项：

```cpp
target_link_libraries(cpp_test
  PRIVATE
    sum_integers
    gtest_main
  )
```

在构建我们的代码时，我们可以看到它如何正确地触发了 Google Test 的配置和构建步骤。有一天，我们可能希望升级到更新的 Google Test 版本，我们可能需要更改的唯一一行是详细说明`GIT_TAG`的那一行。

# 还有更多

我们已经初步了解了`FetchContent`及其构建时的表亲`ExternalProject_Add`，我们将在第八章，*超级构建模式*中重新审视这些命令。对于可用选项的详细讨论，请参考[`cmake.org/cmake/help/v3.11/module/FetchContent.html`](https://cmake.org/cmake/help/v3.11/module/FetchContent.html)。

在本示例中，我们在配置时获取了源代码，但我们也可以在系统环境中安装它们，并使用`FindGTest`模块来检测库和头文件（[`cmake.org/cmake/help/v3.5/module/FindGTest.html`](https://cmake.org/cmake/help/v3.5/module/FindGTest.html)）。从版本 3.9 开始，CMake 还提供了一个`GoogleTest`模块（[`cmake.org/cmake/help/v3.9/module/GoogleTest.html`](https://cmake.org/cmake/help/v3.9/module/GoogleTest.html)），该模块提供了一个`gtest_add_tests`函数。这个函数可以用来自动添加测试，通过扫描源代码中的 Google Test 宏。

# 另请参阅

显然，Google Test 有许多超出本示例范围的功能，如[`github.com/google/googletest`](https://github.com/google/googletest)所列。

# 定义单元测试并链接到 Boost 测试

本示例的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-04`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-04)找到，并包含一个 C++示例。本示例适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

Boost 测试是 C++社区中另一个非常流行的单元测试框架，在本示例中，我们将演示如何使用 Boost 测试对我们的熟悉求和示例代码进行单元测试。

# 准备工作

我们将保持`main.cpp`、`sum_integers.cpp`和`sum_integers.hpp`与之前的示例不变，但我们将更新`test.cpp`作为使用 Boost 测试库的单元测试的简单示例：

```cpp
#include "sum_integers.hpp"

#include <vector>

#define BOOST_TEST_MODULE example_test_suite
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_CASE(add_example) {
  auto integers = {1, 2, 3, 4, 5};
  auto result = sum_integers(integers);
  BOOST_REQUIRE(result == 15);
}
```

# 如何操作

以下是使用 Boost 测试构建我们项目的步骤：

1.  我们从熟悉的`CMakeLists.txt`结构开始：

```cpp
# set minimum cmake version
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# project name and language
project(recipe-04 LANGUAGES CXX)

# require C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# example library
add_library(sum_integers sum_integers.cpp)

# main code
add_executable(sum_up main.cpp)
target_link_libraries(sum_up sum_integers)
```

1.  我们检测 Boost 库并链接`cpp_test`：

```cpp
find_package(Boost 1.54 REQUIRED COMPONENTS unit_test_framework)

add_executable(cpp_test test.cpp)

target_link_libraries(cpp_test
  PRIVATE
    sum_integers
    Boost::unit_test_framework
  )

# avoid undefined reference to "main" in test.cpp
target_compile_definitions(cpp_test
  PRIVATE
    BOOST_TEST_DYN_LINK
  )
```

1.  最后，我们定义单元测试：

```cpp
enable_testing()

add_test(
  NAME boost_test
  COMMAND $<TARGET_FILE:cpp_test>
  )
```

1.  以下是我们需要配置、构建和测试代码的所有内容：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
$ ctest

Test project /home/user/cmake-recipes/chapter-04/recipe-04/cxx-example/build
    Start 1: boost_test
1/1 Test #1: boost_test ....................... Passed 0.01 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) = 0.01 sec

$ ./cpp_test

Running 1 test case...

*** No errors detected
```

# 工作原理

我们使用了`find_package`来检测 Boost 的`unit_test_framework`组件（请参阅第三章，*检测外部库和程序*，第八部分，*检测 Boost 库*）。我们坚持认为这个组件是`REQUIRED`，如果无法在系统环境中找到，配置将停止。`cpp_test`目标需要知道在哪里找到 Boost 头文件，并需要链接到相应的库；这两者都由`IMPORTED`库目标`Boost::unit_test_framework`提供，该目标由成功的`find_package`调用设置。我们从第一章，*从简单可执行文件到库*中的第三部分，*构建和链接静态和共享库*的讨论中回忆起，`IMPORTED`库是 CMake 提供的伪目标，用于表示预先存在的依赖关系及其使用要求。

# 还有更多内容

在本节中，我们假设 Boost 已安装在系统上。或者，我们可以在编译时获取并构建 Boost 依赖项（请参阅第八章，*超级构建模式*，第二部分，*使用超级构建管理依赖项：I. Boost 库*）。然而，Boost 不是一个轻量级依赖项。在我们的示例代码中，我们仅使用了最基本的基础设施，但 Boost 提供了丰富的功能和选项，我们将引导感兴趣的读者访问[`www.boost.org/doc/libs/1_65_1/libs/test/doc/html/index.html`](http://www.boost.org/doc/libs/1_65_1/libs/test/doc/html/index.html)。

# 使用动态分析检测内存缺陷

本节的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-05`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-05)找到，并提供了一个 C++示例。本节适用于 CMake 版本 3.5（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

内存缺陷，例如越界写入或读取内存，或者内存泄漏（已分配但从未释放的内存），可能会产生难以追踪的讨厌错误，因此尽早检测它们是有用的。Valgrind（[`valgrind.org`](http://valgrind.org)）是一个流行且多功能的工具，用于检测内存缺陷和内存泄漏，在本节中，我们将使用 Valgrind 来提醒我们使用 CMake/CTest 运行测试时的内存问题（请参阅第十四章，*测试仪表板*，以讨论相关的`AddressSanitizer`和`ThreadSanitizer`）。

# 准备就绪

对于本节，我们需要三个文件。第一个是我们希望测试的实现（我们可以将文件称为`leaky_implementation.cpp`）：

```cpp
#include "leaky_implementation.hpp"

int do_some_work() {

  // we allocate an array
  double *my_array = new double[1000];

  // do some work
  // ...

  // we forget to deallocate it
  // delete[] my_array;

  return 0;
}
```

我们还需要相应的头文件（`leaky_implementation.hpp`）：

```cpp
#pragma once

int do_some_work();
```

我们需要测试文件（`test.cpp`）：

```cpp
#include "leaky_implementation.hpp"

int main() {
  int return_code = do_some_work();

  return return_code;
}
```

我们期望测试通过，因为`return_code`被硬编码为`0`。然而，我们也希望检测到内存泄漏，因为我们忘记了释放`my_array`。

# 如何操作

以下是如何设置`CMakeLists.txt`以执行代码的动态分析：

1.  我们首先定义了最低 CMake 版本、项目名称、语言、目标和依赖项：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-05 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(example_library leaky_implementation.cpp)

```

```cpp

add_executable(cpp_test test.cpp)
target_link_libraries(cpp_test example_library)
```

1.  然后，我们不仅定义了测试，还定义了`MEMORYCHECK_COMMAND`：

```cpp
find_program(MEMORYCHECK_COMMAND NAMES valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full")

# add memcheck test action
include(CTest)

enable_testing()

add_test(
  NAME cpp_test
  COMMAND $<TARGET_FILE:cpp_test>
  )
```

1.  运行测试集报告测试通过，如下所示：

```cpp
$ ctest 
Test project /home/user/cmake-recipes/chapter-04/recipe-05/cxx-example/build
    Start 1: cpp_test
1/1 Test #1: cpp_test ......................... Passed 0.00 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) = 0.00 sec
```

1.  现在，我们希望检查内存缺陷，并可以观察到内存泄漏被检测到：

```cpp
$ ctest -T memcheck

   Site: myhost
   Build name: Linux-c++
Create new tag: 20171127-1717 - Experimental
Memory check project /home/user/cmake-recipes/chapter-04/recipe-05/cxx-example/build
    Start 1: cpp_test
1/1 MemCheck #1: cpp_test ......................... Passed 0.40 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) = 0.40 sec
-- Processing memory checking output:
1/1 MemCheck: #1: cpp_test ......................... Defects: 1
MemCheck log files can be found here: ( * corresponds to test number)
/home/user/cmake-recipes/chapter-04/recipe-05/cxx-example/build/Testing/Temporary/MemoryChecker.*.log
Memory checking results:
Memory Leak - 1
```

1.  作为最后一步，你应该尝试修复内存泄漏，并验证`ctest -T memcheck`报告没有错误。

# 工作原理

我们使用`find_program(MEMORYCHECK_COMMAND NAMES valgrind)`来查找 Valgrind 并将其完整路径设置为`MEMORYCHECK_COMMAND`。我们还需要显式包含`CTest`模块以启用`memcheck`测试动作，我们可以通过使用`ctest -T memcheck`来使用它。此外，请注意我们能够使用`set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full")`将选项传递给 Valgrind。内存检查步骤创建一个日志文件，可用于详细检查内存缺陷。

一些工具，如代码覆盖率和静态分析工具，可以类似地设置。然而，使用其中一些工具更为复杂，因为需要专门的构建和工具链。Sanitizers 就是一个例子。有关更多信息，请参阅[`github.com/arsenm/sanitizers-cmake`](https://github.com/arsenm/sanitizers-cmake)。此外，请查看第十四章，*测试仪表板*，以讨论`AddressSanitizer`和`ThreadSanitizer`。

# 还有更多

本食谱可用于向夜间测试仪表板报告内存缺陷，但我们在这里演示了此功能也可以独立于测试仪表板使用。我们将在第十四章，*测试仪表板*中重新讨论与 CDash 结合使用的情况。

# 另请参阅

有关 Valgrind 及其功能和选项的文档，请参阅[`valgrind.org`](http://valgrind.org)。

# 测试预期失败

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-06`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-06)找到。该食谱适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

理想情况下，我们希望我们的所有测试在每个平台上都能始终通过。然而，我们可能想要测试在受控环境中是否会发生预期的失败或异常，在这种情况下，我们将预期的失败定义为成功的结果。我们相信，通常这应该是测试框架（如 Catch2 或 Google Test）的任务，它应该检查预期的失败并将成功报告给 CMake。但是，可能会有情况，你希望将测试的非零返回代码定义为成功；换句话说，你可能想要反转成功和失败的定义。在本节中，我们将展示这样的情况。

# 准备工作

本节的成分将是一个微小的 Python 脚本（`test.py`），它总是返回`1`，CMake 将其解释为失败：

```cpp
import sys

# simulate a failing test
sys.exit(1)
```

# 如何操作

逐步地，这是如何编写`CMakeLists.txt`来完成我们的任务：

1.  在本节中，我们不需要 CMake 提供任何语言支持，但我们需要找到一个可用的 Python 解释器：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-06 LANGUAGES NONE)

find_package(PythonInterp REQUIRED)
```

1.  然后我们定义测试并告诉 CMake 我们期望它失败：

```cpp
enable_testing()

add_test(example ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test.py)

set_tests_properties(example PROPERTIES WILL_FAIL true)
```

1.  最后，我们验证它被报告为成功的测试，如下所示：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
$ ctest

Test project /home/user/cmake-recipes/chapter-04/recipe-06/example/build
    Start 1: example
1/1 Test #1: example .......................... Passed 0.00 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) = 0.01 sec
```

# 它是如何工作的

使用`set_tests_properties(example PROPERTIES WILL_FAIL true)`，我们将属性`WILL_FAIL`设置为`true`，这会反转成功/失败的状态。然而，这个功能不应该用来临时修复损坏的测试。

# 还有更多

如果你需要更多的灵活性，你可以结合使用测试属性`PASS_REGULAR_EXPRESSION`和`FAIL_REGULAR_EXPRESSION`与`set_tests_properties`。如果设置了这些属性，测试输出将被检查与作为参数给出的正则表达式列表进行匹配，如果至少有一个正则表达式匹配，则测试分别通过或失败。还有许多其他属性可以设置在测试上。可以在[`cmake.org/cmake/help/v3.5/manual/cmake-properties.7.html#properties-on-tests`](https://cmake.org/cmake/help/v3.5/manual/cmake-properties.7.html#properties-on-tests)找到所有可用属性的完整列表。

# 为长时间测试设置超时

本节的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-07`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-07)找到。本节适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

理想情况下，测试集应该只需要很短的时间，以激励开发者频繁运行测试集，并使得对每次提交（变更集）进行测试成为可能（或更容易）。然而，有些测试可能会耗时较长或卡住（例如，由于高文件 I/O 负载），我们可能需要实施超时机制来终止超时的测试，以免它们堆积起来延迟整个测试和部署流水线。在本节中，我们将展示一种实施超时的方法，可以为每个测试单独调整。

# 准备工作

本食谱的成分将是一个微小的 Python 脚本（`test.py`），它总是返回`0`。为了保持超级简单并专注于 CMake 方面，测试脚本除了等待两秒钟之外不做任何事情；但是，我们可以想象在现实生活中，这个测试脚本会执行更有意义的工作：

```cpp
import sys
import time

# wait for 2 seconds
time.sleep(2)

# report success
sys.exit(0)
```

# 如何操作

我们需要通知 CTest，如果测试超时，需要终止测试，如下所示：

1.  我们定义项目名称，启用测试，并定义测试：

```cpp
# set minimum cmake version
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# project name
project(recipe-07 LANGUAGES NONE)

# detect python
find_package(PythonInterp REQUIRED)

# define tests
enable_testing()

# we expect this test to run for 2 seconds
add_test(example ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test.py)
```

1.  此外，我们为测试指定了一个`TIMEOUT`，并将其设置为 10 秒：

```cpp
set_tests_properties(example PROPERTIES TIMEOUT 10)
```

1.  我们知道如何配置和构建，我们期望测试通过：

```cpp
$ ctest 
Test project /home/user/cmake-recipes/chapter-04/recipe-07/example/build
    Start 1: example
1/1 Test #1: example .......................... Passed 2.01 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) = 2.01 sec
```

1.  现在，为了验证`TIMEOUT`是否有效，我们将`test.py`中的睡眠命令增加到 11 秒，并重新运行测试：

```cpp
$ ctest

Test project /home/user/cmake-recipes/chapter-04/recipe-07/example/build
    Start 1: example
1/1 Test #1: example ..........................***Timeout 10.01 sec

0% tests passed, 1 tests failed out of 1

Total Test time (real) = 10.01 sec

The following tests FAILED:
          1 - example (Timeout)
Errors while running CTest
```

# 工作原理

`TIMEOUT`是一个方便的属性，可用于通过使用`set_tests_properties`为单个测试指定超时。如果测试超过该时间，无论出于何种原因（测试停滞或机器太慢），测试都会被终止并标记为失败。

# 并行运行测试

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-08`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-08)找到。该食谱适用于 CMake 版本 3.5（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

大多数现代计算机都有四个或更多的 CPU 核心。CTest 的一个很棒的功能是，如果你有多个核心可用，它可以并行运行测试。这可以显著减少总测试时间，减少总测试时间才是真正重要的，以激励开发者频繁测试。在这个食谱中，我们将演示这个功能，并讨论如何优化你的测试定义以获得最大性能。

# 准备就绪

让我们假设我们的测试集包含标记为*a, b, ..., j*的测试，每个测试都有特定的持续时间：

| 测试 | 持续时间（以时间单位计） |
| --- | --- |
| *a, b, c, d* | 0.5 |
| *e, f, g* | 1.5 |
| *h* | 2.5 |
| *i* | 3.5 |
| *j* | 4.5 |

时间单位可以是分钟，但为了保持简单和短，我们将使用秒。为了简单起见，我们可以用一个 Python 脚本来表示消耗 0.5 时间单位的测试*a*：

```cpp
import sys
import time

# wait for 0.5 seconds
time.sleep(0.5)

# finally report success
sys.exit(0)
```

其他测试可以相应地表示。我们将把这些脚本放在`CMakeLists.txt`下面的一个目录中，目录名为`test`。

# 如何操作

对于这个食谱，我们需要声明一个测试列表，如下所示：

1.  `CMakeLists.txt`非常简短：

```cpp
# set minimum cmake version
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# project name
project(recipe-08 LANGUAGES NONE)

# detect python
find_package(PythonInterp REQUIRED)

# define tests
enable_testing()

add_test(a ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/a.py)
add_test(b ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/b.py)
add_test(c ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/c.py)
add_test(d ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/d.py)
add_test(e ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/e.py)
add_test(f ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/f.py)
add_test(g ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/g.py)
add_test(h ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/h.py)
add_test(i ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/i.py)
add_test(j ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/j.py)
```

1.  我们可以使用`ctest`配置项目并运行测试，总共需要 17 秒：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ ctest

      Start 1: a
 1/10 Test #1: a ................................ Passed 0.51 sec
      Start 2: b
 2/10 Test #2: b ................................ Passed 0.51 sec
      Start 3: c
 3/10 Test #3: c ................................ Passed 0.51 sec
      Start 4: d
 4/10 Test #4: d ................................ Passed 0.51 sec
      Start 5: e
 5/10 Test #5: e ................................ Passed 1.51 sec
      Start 6: f
 6/10 Test #6: f ................................ Passed 1.51 sec
      Start 7: g
 7/10 Test #7: g ................................ Passed 1.51 sec
      Start 8: h
 8/10 Test #8: h ................................ Passed 2.51 sec
      Start 9: i
 9/10 Test #9: i ................................ Passed 3.51 sec
      Start 10: j
10/10 Test #10: j ................................ Passed 4.51 sec

100% tests passed, 0 tests failed out of 10

Total Test time (real) = 17.11 sec
```

1.  现在，如果我们碰巧有四个核心可用，我们可以在不到五秒的时间内将测试集运行在四个核心上：

```cpp
$ ctest --parallel 4

      Start 10: j
      Start 9: i
      Start 8: h
      Start 5: e
 1/10 Test #5: e ................................ Passed 1.51 sec
      Start 7: g
 2/10 Test #8: h ................................ Passed 2.51 sec
      Start 6: f
 3/10 Test #7: g ................................ Passed 1.51 sec
      Start 3: c
 4/10 Test #9: i ................................ Passed 3.63 sec
 5/10 Test #3: c ................................ Passed 0.60 sec
      Start 2: b
      Start 4: d
 6/10 Test #6: f ................................ Passed 1.51 sec
 7/10 Test #4: d ................................ Passed 0.59 sec
 8/10 Test #2: b ................................ Passed 0.59 sec
      Start 1: a
 9/10 Test #10: j ................................ Passed 4.51 sec
10/10 Test #1: a ................................ Passed 0.51 sec

100% tests passed, 0 tests failed out of 10

Total Test time (real) = 4.74 sec
```

# 工作原理

我们可以看到，在并行情况下，测试*j, i, h*和*e*同时开始。并行运行时总测试时间的减少可能是显著的。查看`ctest --parallel 4`的输出，我们可以看到并行测试运行从最长的测试开始，并在最后运行最短的测试。从最长的测试开始是一个非常好的策略。这就像打包搬家箱子：我们从较大的物品开始，然后用较小的物品填充空隙。比较在四个核心上从最长测试开始的*a-j*测试的堆叠，看起来如下：

```cpp
        --> time
core 1: jjjjjjjjj
core 2: iiiiiiibd
core 3: hhhhhggg
core 4: eeefffac
```

按照定义的顺序运行测试看起来如下：

```cpp
        --> time
core 1: aeeeiiiiiii
core 2: bfffjjjjjjjjj
core 3: cggg
core 4: dhhhhh
```

按照定义的顺序运行测试总体上需要更多时间，因为它让两个核心大部分时间处于空闲状态（这里，核心 3 和 4）。CMake 是如何知道哪些测试需要最长的时间？CMake 知道每个测试的时间成本，因为我们首先按顺序运行了测试，这记录了每个测试的成本数据在文件`Testing/Temporary/CTestCostData.txt`中，看起来如下：

```cpp
a 1 0.506776
b 1 0.507882
c 1 0.508175
d 1 0.504618
e 1 1.51006
f 1 1.50975
g 1 1.50648
h 1 2.51032
i 1 3.50475
j 1 4.51111
```

如果我们刚配置完项目就立即开始并行测试，它将按照定义的顺序运行测试，并且在四个核心上，总测试时间会明显更长。这对我们意味着什么？这是否意味着我们应该根据递减的时间成本来排序测试？这是一个选项，但事实证明还有另一种方法；我们可以自行指示每个测试的时间成本：

```cpp
add_test(a ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/a.py)
add_test(b ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/b.py)
add_test(c ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/c.py)
add_test(d ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/d.py)
set_tests_properties(a b c d PROPERTIES COST 0.5)

add_test(e ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/e.py)
add_test(f ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/f.py)
add_test(g ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/g.py)
set_tests_properties(e f g PROPERTIES COST 1.5)

add_test(h ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/h.py)
set_tests_properties(h PROPERTIES COST 2.5)

add_test(i ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/i.py)
set_tests_properties(i PROPERTIES COST 3.5)

add_test(j ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/j.py)
set_tests_properties(j PROPERTIES COST 4.5)
```

`COST`参数可以是估计值或从`Testing/Temporary/CTestCostData.txt`提取。

# 还有更多内容。

除了使用`ctest --parallel N`，你还可以使用环境变量`CTEST_PARALLEL_LEVEL`，并将其设置为所需的级别。

# 运行测试子集

本示例的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-09`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-09)找到。本示例适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

在前面的示例中，我们学习了如何借助 CMake 并行运行测试，并讨论了从最长的测试开始的优势。虽然这种策略可以最小化总测试时间，但在特定功能的代码开发或调试过程中，我们可能不希望运行整个测试集。我们可能更倾向于从最长的测试开始，特别是在调试由短测试执行的功能时。对于调试和代码开发，我们需要能够仅运行选定的测试子集。在本示例中，我们将介绍实现这一目标的策略。

# 准备工作

在本例中，我们假设总共有六个测试；前三个测试较短，名称分别为`feature-a`、`feature-b`和`feature-c`。我们还有三个较长的测试，名称分别为`feature-d`、`benchmark-a`和`benchmark-b`。在本例中，我们可以使用 Python 脚本来表示这些测试，其中我们可以调整睡眠时间：

```cpp
import sys
import time

# wait for 0.1 seconds
time.sleep(0.1)

# finally report success
sys.exit(0)
```

# 如何操作

以下是对我们的`CMakeLists.txt`内容的详细分解：

1.  我们从一个相对紧凑的`CMakeLists.txt`开始，定义了六个测试：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# project name
project(recipe-09 LANGUAGES NONE)

# detect python
find_package(PythonInterp REQUIRED)

# define tests
enable_testing()

add_test(
  NAME feature-a
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/feature-a.py
  )
add_test(
  NAME feature-b
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/feature-b.py
  )
add_test(
  NAME feature-c
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/feature-c.py
  )
add_test(
  NAME feature-d
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/feature-d.py
  )

add_test(
  NAME benchmark-a
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/benchmark-a.py
  )
```

```cpp
add_test(
  NAME benchmark-b
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/benchmark-b.py
  )
```

1.  此外，我们将较短的测试标记为`"quick"`，将较长的测试标记为`"long"`：

```cpp
set_tests_properties(
  feature-a
  feature-b
  feature-c
  PROPERTIES
    LABELS "quick"
  )

set_tests_properties(
  feature-d
  benchmark-a
  benchmark-b
  PROPERTIES
    LABELS "long"
  )
```

1.  我们现在准备运行测试集，如下所示：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ ctest

    Start 1: feature-a
1/6 Test #1: feature-a ........................ Passed 0.11 sec
    Start 2: feature-b
2/6 Test #2: feature-b ........................ Passed 0.11 sec
    Start 3: feature-c
3/6 Test #3: feature-c ........................ Passed 0.11 sec
    Start 4: feature-d
4/6 Test #4: feature-d ........................ Passed 0.51 sec
    Start 5: benchmark-a
5/6 Test #5: benchmark-a ...................... Passed 0.51 sec
    Start 6: benchmark-b
6/6 Test #6: benchmark-b ...................... Passed 0.51 sec
```

```cpp
100% tests passed, 0 tests failed out of 6

Label Time Summary:
long = 1.54 sec*proc (3 tests)
quick = 0.33 sec*proc (3 tests)

Total Test time (real) = 1.87 sec
```

# 工作原理

现在每个测试都有一个名称和一个标签。在 CMake 中，所有测试都有编号，因此它们也具有唯一编号。定义了测试标签后，我们现在可以运行整个集合，也可以根据测试的名称（使用正则表达式）、标签或编号来运行测试。

通过名称运行测试（这里，我们运行所有名称匹配`feature`的测试）如下所示：

```cpp
$ ctest -R feature

    Start 1: feature-a
1/4 Test #1: feature-a ........................ Passed 0.11 sec
    Start 2: feature-b
2/4 Test #2: feature-b ........................ Passed 0.11 sec
    Start 3: feature-c
3/4 Test #3: feature-c ........................ Passed 0.11 sec
    Start 4: feature-d
4/4 Test #4: feature-d ........................ Passed 0.51 sec

100% tests passed, 0 tests failed out of 4
```

通过标签运行测试（这里，我们运行所有`long`测试）产生：

```cpp
$ ctest -L long

    Start 4: feature-d
1/3 Test #4: feature-d ........................ Passed 0.51 sec
    Start 5: benchmark-a
2/3 Test #5: benchmark-a ...................... Passed 0.51 sec
    Start 6: benchmark-b
3/3 Test #6: benchmark-b ...................... Passed 0.51 sec

100% tests passed, 0 tests failed out of 3
```

通过编号运行测试（这里，我们运行第 2 到第 4 个测试）得到：

```cpp
$ ctest -I 2,4

    Start 2: feature-b
1/3 Test #2: feature-b ........................ Passed 0.11 sec
    Start 3: feature-c
2/3 Test #3: feature-c ........................ Passed 0.11 sec
    Start 4: feature-d
3/3 Test #4: feature-d ........................ Passed 0.51 sec

100% tests passed, 0 tests failed out of 3
```

# 不仅如此

尝试使用`**$ ctest --help**`，您将看到大量可供选择的选项来定制您的测试。

# 使用测试夹具

本例的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-10`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-04/recipe-10)找到。本例适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

本例灵感来源于 Craig Scott 的工作，我们建议读者也参考相应的博客文章以获取更多背景信息，网址为[`crascit.com/2016/10/18/test-fixtures-with-cmake-ctest/`](https://crascit.com/2016/10/18/test-fixtures-with-cmake-ctest/)。本例的动机是展示如何使用测试夹具。对于需要测试前设置动作和测试后清理动作的更复杂的测试来说，这些夹具非常有用（例如创建示例数据库、设置连接、断开连接、清理测试数据库等）。我们希望确保运行需要设置或清理动作的测试时，这些步骤能以可预测和稳健的方式自动触发，而不会引入代码重复。这些设置和清理步骤可以委托给测试框架，如 Google Test 或 Catch2，但在这里，我们展示了如何在 CMake 级别实现测试夹具。

# 准备就绪

我们将准备四个小型 Python 脚本，并将它们放置在`test`目录下：`setup.py`、`feature-a.py`、`feature-b.py`和`cleanup.py`。

# 如何操作

我们从熟悉的`CMakeLists.txt`结构开始，并添加了一些额外的步骤，如下所示：

1.  我们准备好了熟悉的基础设施：

```cpp
# set minimum cmake version
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# project name
project(recipe-10 LANGUAGES NONE)

# detect python
find_package(PythonInterp REQUIRED)

# define tests
enable_testing()
```

1.  然后，我们定义了四个测试步骤并将它们与一个固定装置绑定：

```cpp
add_test(
  NAME setup
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/setup.py
  )
set_tests_properties(
  setup
  PROPERTIES
    FIXTURES_SETUP my-fixture
  )

add_test(
  NAME feature-a
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/feature-a.py
  )
add_test(
  NAME feature-b
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/feature-b.py
  )
set_tests_properties(
  feature-a
  feature-b
  PROPERTIES
    FIXTURES_REQUIRED my-fixture
  )

add_test(
  NAME cleanup
  COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/cleanup.py
  )
set_tests_properties(
  cleanup
  PROPERTIES
    FIXTURES_CLEANUP my-fixture
  )
```

1.  运行整个集合并不会带来任何惊喜，正如以下输出所示：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ ctest

    Start 1: setup
1/4 Test #1: setup ............................ Passed 0.01 sec
    Start 2: feature-a
2/4 Test #2: feature-a ........................ Passed 0.01 sec
    Start 3: feature-b
3/4 Test #3: feature-b ........................ Passed 0.00 sec
    Start 4: cleanup
4/4 Test #4: cleanup .......................... Passed 0.01 sec

100% tests passed, 0 tests failed out of 4
```

1.  然而，有趣的部分在于当我们尝试单独运行测试`feature-a`时。它正确地调用了`setup`步骤和`cleanup`步骤：

```cpp
$ ctest -R feature-a

 Start 1: setup
1/3 Test #1: setup ............................ Passed 0.01 sec
 Start 2: feature-a
```

```cpp
2/3 Test #2: feature-a ........................ Passed 0.00 sec
 Start 4: cleanup
3/3 Test #4: cleanup .......................... Passed 0.01 sec

100% tests passed, 0 tests failed out of 3
```

# 工作原理

在本例中，我们定义了一个文本固定装置并将其命名为`my-fixture`。我们为设置测试赋予了`FIXTURES_SETUP`属性，为清理测试赋予了`FIXTURES_CLEANUP`属性，并且使用`FIXTURES_REQUIRED`确保测试`feature-a`和`feature-b`都需要设置和清理步骤才能运行。将这些绑定在一起，确保我们始终以明确定义的状态进入和退出步骤。

# 还有更多内容

如需了解更多背景信息以及使用此技术进行固定装置的出色动机，请参阅[`crascit.com/2016/10/18/test-fixtures-with-cmake-ctest/`](https://crascit.com/2016/10/18/test-fixtures-with-cmake-ctest/)。


# 第六章：配置时间和构建时间操作

在本章中，我们将涵盖以下食谱：

+   使用平台无关的文件操作

+   在配置时间运行自定义命令

+   在构建时间运行自定义命令：I. 使用 `add_custom_command`

+   在构建时间运行自定义命令：II. 使用 `add_custom_target`

+   在构建时间对特定目标运行自定义命令

+   探测编译和链接

+   探测编译器标志

+   探测执行

+   使用生成器表达式微调配置和编译

# 引言

在本章中，我们将学习如何在配置时间和构建时间执行自定义操作。让我们简要回顾一下与由 CMake 管理的项目工作流程相关的*时间*概念：

1.  **CMake 时间**或**配置时间**：这是当 CMake 正在运行并处理项目中的`CMakeLists.txt`文件时。

1.  **生成时间**：这是当生成用于本地构建工具的文件，如 Makefiles 或 Visual Studio 项目文件时。

1.  **构建时间**：这是当平台和工具本地的构建工具被调用时，在之前由 CMake 生成的平台和工具本地的构建脚本上。此时，编译器将被调用，目标（可执行文件和库）将在特定的构建目录中被构建。

1.  **CTest 时间**或**测试时间**：当我们运行测试套件以检查目标是否按预期执行时。

1.  **CDash 时间**或**报告时间**：当测试项目的结果上传到一个仪表板以与其他开发者共享时。

1.  **安装时间**：当从构建目录到安装位置安装目标、源文件、可执行文件和库时。

1.  **CPack 时间**或**打包时间**：当我们打包我们的项目以供分发，无论是作为源代码还是二进制。

1.  **包安装时间**：当新制作的包被系统全局安装时。

完整的流程及其对应的时间在下图中描述：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/6d8d214c-69fb-43b4-8769-20a5770453bb.jpg)

本章关注于在配置时间和构建时间自定义行为。我们将学习如何使用这些命令：

+   `execute_process` 以从 CMake 内部执行任意进程并检索其输出

+   `add_custom_target` 以创建将执行自定义命令的目标

+   `add_custom_command` 以指定必须执行以生成文件或在其他目标的特定构建事件上的命令

# 使用平台无关的文件操作

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-01`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-01) 获取，并包含一个 C++示例。该食谱适用于 CMake 版本 3.5（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

在构建某些项目时，我们可能需要与主机平台文件系统进行交互。与文件的交互可能只是检查文件是否存在，创建一个新文件来存储临时信息，创建或提取存档等等。使用 CMake，我们不仅能够在不同的平台上生成构建系统，还能够执行这些操作，而不需要复杂的逻辑来抽象不同的操作系统。本节将展示如何以可移植的方式提取先前下载的存档。

# 准备就绪

我们将展示如何提取包含 Eigen 库的存档，并使用提取的源文件来编译我们的项目。在本节中，我们将重用来自第三章，*检测外部库和程序*，第七部分，*检测 Eigen 库*的线性代数示例`linear-algebra.cpp`。本节还假设包含 Eigen 源代码的存档已下载在与项目本身相同的目录中。

# 如何做到这一点

项目需要解包 Eigen 存档，并相应地设置目标的包含目录：

1.  让我们首先声明一个 C++11 项目：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-01 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  我们向构建系统添加一个自定义目标。该自定义目标将在构建目录内提取存档：

```cpp
add_custom_target(unpack-eigen
  ALL
  COMMAND
    ${CMAKE_COMMAND} -E tar xzf ${CMAKE_CURRENT_SOURCE_DIR}/eigen-eigen-5a0156e40feb.tar.gz
  COMMAND
    ${CMAKE_COMMAND} -E rename eigen-eigen-5a0156e40feb eigen-3.3.4
  WORKING_DIRECTORY
    ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT
    "Unpacking Eigen3 in ${CMAKE_CURRENT_BINARY_DIR}/eigen-3.3.4"
  )
```

1.  我们为源文件添加一个可执行目标：

```cpp
add_executable(linear-algebra linear-algebra.cpp)
```

1.  由于我们的源文件的编译依赖于 Eigen 头文件，我们需要明确指定可执行目标对自定义目标的依赖：

```cpp
add_dependencies(linear-algebra unpack-eigen)
```

1.  最后，我们可以指定我们需要编译源文件的包含目录：

```cpp
target_include_directories(linear-algebra
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/eigen-3.3.4
  )
```

# 它是如何工作的

让我们更仔细地看一下`add_custom_target`的调用：

```cpp
add_custom_target(unpack-eigen
  ALL
  COMMAND
    ${CMAKE_COMMAND} -E tar xzf ${CMAKE_CURRENT_SOURCE_DIR}/eigen-eigen-5a0156e40feb.tar.gz
  COMMAND
    ${CMAKE_COMMAND} -E rename eigen-eigen-5a0156e40feb eigen-3.3.4
  WORKING_DIRECTORY
    ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT
    "Unpacking Eigen3 in ${CMAKE_CURRENT_BINARY_DIR}/eigen-3.3.4"
  )
```

我们正在向构建系统引入一个名为`unpack-eigen`的目标。由于我们传递了`ALL`参数，该目标将始终被执行。`COMMAND`参数允许您指定要执行的命令。在本例中，我们希望提取存档并将提取的目录重命名为`eigen-3.3.4`。这是通过这两个命令实现的：

1.  `${CMAKE_COMMAND} -E tar xzf ${CMAKE_CURRENT_SOURCE_DIR}/eigen-eigen-5a0156e40feb.tar.gz`

1.  `${CMAKE_COMMAND} -E rename eigen-eigen-5a0156e40feb eigen-3.3.4`

注意我们是如何调用 CMake 命令本身，使用`-E`标志来执行实际的工作。对于许多常见操作，CMake 实现了一个在它运行的所有操作系统上都通用的接口。这使得构建系统的生成在很大程度上独立于特定的平台。`add_custom_target`命令中的下一个参数是工作目录，在我们的例子中对应于构建目录：`CMAKE_CURRENT_BINARY_DIR`。最后一个参数`COMMENT`用于指定在执行自定义目标时 CMake 应该打印出什么消息。

# 还有更多

`add_custom_target` 命令可用于在构建过程中执行一系列没有输出的自定义命令。正如我们在本食谱中所展示的，自定义目标可以被指定为项目中其他目标的依赖项。此外，自定义目标也可以依赖于其他目标，从而提供了在我们的构建中设置执行顺序的可能性。

使用 CMake 的 `-E` 标志，我们可以以操作系统无关的方式运行许多常见操作。在特定操作系统上可以运行的完整命令列表可以通过运行 `cmake -E` 或 `cmake -E help` 获得。例如，这是一个在 Linux 系统上的命令摘要：

```cpp
Usage: cmake -E <command> [arguments...]
Available commands: 
  capabilities - Report capabilities built into cmake in JSON format
  chdir dir cmd [args...] - run command in a given directory
  compare_files file1 file2 - check if file1 is same as file2
  copy <file>... destination - copy files to destination (either file or directory)
  copy_directory <dir>... destination - copy content of <dir>... directories to 'destination' directory
  copy_if_different <file>... destination - copy files if it has changed
  echo [<string>...] - displays arguments as text
  echo_append [<string>...] - displays arguments as text but no new line
  env [--unset=NAME]... [NAME=VALUE]... COMMAND [ARG]...
                            - run command in a modified environment
  environment - display the current environment
  make_directory <dir>... - create parent and <dir> directories
  md5sum <file>... - create MD5 checksum of files
  remove [-f] <file>... - remove the file(s), use -f to force it
  remove_directory dir - remove a directory and its contents
  rename oldname newname - rename a file or directory (on one volume)
  server - start cmake in server mode
  sleep <number>... - sleep for given number of seconds
  tar [cxt][vf][zjJ] file.tar [file/dir1 file/dir2 ...]
                            - create or extract a tar or zip archive
  time command [args...] - run command and return elapsed time
  touch file - touch a file.
  touch_nocreate file - touch a file but do not create it.
Available on UNIX only:
  create_symlink old new - create a symbolic link new -> old
```

# 在配置时运行自定义命令

本食谱的代码可在 [`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-02`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-02) 获取。该食谱适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

运行 CMake 会生成构建系统，从而指定本地构建工具必须执行哪些命令来构建您的项目，以及以什么顺序执行。我们已经看到 CMake 在配置时运行许多子任务，以找出工作编译器和必要的依赖项。在本食谱中，我们将讨论如何在配置时通过使用 `execute_process` 命令来运行自定义命令。

# 如何做到这一点

在 第三章，*检测外部库和程序*，食谱 3，*检测 Python 模块和包*中，我们已经展示了在尝试查找 NumPy Python 模块时使用 `execute_process` 的情况。在这个例子中，我们将使用 `execute_process` 命令来检查特定的 Python 模块（在这种情况下，Python CFFI）是否存在，如果存在，我们将发现其版本：

1.  对于这个简单的示例，我们将不需要任何语言支持：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-02 LANGUAGES NONE)
```

1.  我们将要求 Python 解释器执行一个简短的 Python 代码片段，为此我们使用 `find_package` 来发现解释器：

```cpp
find_package(PythonInterp REQUIRED)
```

1.  然后我们调用 `execute_process` 来运行一个简短的 Python 代码片段；我们将在下一节中更详细地讨论这个命令：

```cpp
# this is set as variable to prepare
# for abstraction using loops or functions
set(_module_name "cffi")

execute_process(
  COMMAND
    ${PYTHON_EXECUTABLE} "-c" "import ${_module_name}; print(${_module_name}.__version__)"
  OUTPUT_VARIABLE _stdout
  ERROR_VARIABLE _stderr
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_STRIP_TRAILING_WHITESPACE
  )
```

1.  然后，我们打印结果：

```cpp
if(_stderr MATCHES "ModuleNotFoundError")
  message(STATUS "Module ${_module_name} not found")
else()
  message(STATUS "Found module ${_module_name} v${_stdout}")
endif()
```

1.  一个示例配置产生以下结果（假设 Python CFFI 包已安装在相应的 Python 环境中）：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..

-- Found PythonInterp: /home/user/cmake-cookbook/chapter-05/recipe-02/example/venv/bin/python (found version "3.6.5") 
-- Found module cffi v1.11.5
```

# 它是如何工作的

`execute_process` 命令会在当前执行的 CMake 进程中产生一个或多个子进程，从而提供了一种强大且方便的方式来在配置项目时运行任意命令。在一次 `execute_process` 调用中可以执行多个命令。然而，请注意，每个命令的输出将被管道传输到下一个命令。该命令接受多个参数：

+   `WORKING_DIRECTORY` 允许您指定在哪个目录中执行命令。

+   `RESULT_VARIABLE`将包含运行进程的结果。这要么是一个整数，表示成功执行，要么是一个包含错误条件的字符串。

+   `OUTPUT_VARIABLE`和`ERROR_VARIABLE`将包含执行命令的标准输出和标准错误。请记住，由于命令的输出被输入，只有最后一个命令的标准输出将被保存到`OUTPUT_VARIABLE`中。

+   `INPUT_FILE`、`OUTPUT_FILE`和`ERROR_FILE`指定最后一个命令的标准输入和标准输出文件名，以及所有命令的标准错误文件名。

+   通过设置`OUTPUT_QUIET`和`ERROR_QUIET`，CMake 将分别忽略标准输出和标准错误。

+   通过设置`OUTPUT_STRIP_TRAILING_WHITESPACE`和`ERROR_STRIP_TRAILING_WHITESPACE`，可以分别去除标准输出和标准错误中运行命令的尾随空格。

通过这些解释，我们可以回到我们的示例：

```cpp
set(_module_name "cffi")

execute_process(
  COMMAND
    ${PYTHON_EXECUTABLE} "-c" "import ${_module_name}; print(${_module_name}.__version__)"
  OUTPUT_VARIABLE _stdout
  ERROR_VARIABLE _stderr
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_STRIP_TRAILING_WHITESPACE
  )

if(_stderr MATCHES "ModuleNotFoundError")
  message(STATUS "Module ${_module_name} not found")
else()
  message(STATUS "Found module ${_module_name} v${_stdout}")
endif()
```

该命令检查`python -c "import cffi; print(cffi.__version__)"`的输出。如果找不到模块，`_stderr`将包含`ModuleNotFoundError`，我们在 if 语句中对此进行检查，在这种情况下，我们会打印`找不到 cffi 模块`。如果导入成功，Python 代码将打印模块版本，该版本被输入到`_stdout`，以便我们可以打印以下内容：

```cpp
message(STATUS "Found module ${_module_name} v${_stdout}")
```

# 还有更多内容

在本示例中，我们仅打印了结果，但在实际项目中，我们可以警告、中止配置或设置可以查询以切换某些配置选项的变量。

将代码示例扩展到多个 Python 模块，如 Cython，避免代码重复，这将是一个有趣的练习。一种选择可能是使用`foreach`循环遍历模块名称；另一种方法可能是将代码抽象为函数或宏。我们将在第七章，*项目结构化*中讨论此类抽象。

在第九章，*混合语言项目*中，我们将使用 Python CFFI 和 Cython，而本节内容可以作为一个有用且可复用的代码片段，用于检测这些包是否存在。

# 在构建时运行自定义命令：I. 使用`add_custom_command`

本节代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-03`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-03)找到，并包含一个 C++示例。本节内容适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

项目构建目标可能依赖于只能在构建时执行的命令的结果，即在构建系统生成完成后。CMake 提供了三种选项来在构建时执行自定义命令：

1.  使用`add_custom_command`生成要在目标内编译的输出文件。

1.  使用 `add_custom_target` 执行没有输出的命令。

1.  使用 `add_custom_command` 执行没有输出的命令，在目标构建之前或之后。

这三个选项强制特定的语义，并且不可互换。接下来的三个配方将阐明它们的使用案例。

# 准备就绪

我们将重用 第三章，*检测外部库和程序*，第 4 个配方，*检测 BLAS 和 LAPACK 数学库* 中的 C++ 示例，以说明 `add_custom_command` 第一种变体的使用。在该代码示例中，我们探测现有的 BLAS 和 LAPACK 库，并编译了一个微小的 C++ 包装器库，以调用我们需要的线性代数例程的 Fortran 实现。

我们将代码分成两部分。`linear-algebra.cpp` 的源文件与 第三章，*检测外部库和程序*，第 4 个配方，*检测 BLAS 和 LAPACK 数学库* 相比没有变化，并将包含线性代数包装器库的头文件并链接到编译库。然而，该库的源文件将被打包成一个与示例项目一起交付的压缩 tar 存档。该存档将在构建时提取，并在可执行文件之前编译线性代数包装器库。

# 如何做到这一点

我们的 `CMakeLists.txt` 将不得不包含一个自定义命令来提取线性代数包装器库的源文件。让我们详细看一下：

1.  我们从熟悉的 CMake 版本、项目名称和支持的语言的定义开始：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-03 LANGUAGES CXX Fortran)
```

1.  我们一如既往地选择 C++11 标准：

```cpp
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  然后是时候在我们的系统上寻找 BLAS 和 LAPACK 库了：

```cpp
find_package(BLAS REQUIRED)
find_package(LAPACK REQUIRED)
```

1.  我们声明一个变量 `wrap_BLAS_LAPACK_sources`，用于保存 `wrap_BLAS_LAPACK.tar.gz` 存档中包含的源文件的名称：

```cpp
set(wrap_BLAS_LAPACK_sources
  ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxBLAS.hpp
  ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxBLAS.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxLAPACK.hpp
  ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxLAPACK.cpp
  )
```

1.  我们声明自定义命令以提取 `wrap_BLAS_LAPACK.tar.gz` 存档并更新提取文件的时间戳。请注意，`wrap_BLAS_LAPACK_sources` 变量的内容是自定义命令的预期输出：

```cpp
add_custom_command(
  OUTPUT
    ${wrap_BLAS_LAPACK_sources}
  COMMAND
    ${CMAKE_COMMAND} -E tar xzf ${CMAKE_CURRENT_SOURCE_DIR}/wrap_BLAS_LAPACK.tar.gz
  COMMAND
```

```cpp
    ${CMAKE_COMMAND} -E touch ${wrap_BLAS_LAPACK_sources}
  WORKING_DIRECTORY
    ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/wrap_BLAS_LAPACK.tar.gz
  COMMENT
    "Unpacking C++ wrappers for BLAS/LAPACK"
  VERBATIM
  )
```

1.  接下来，我们添加一个库目标，其源文件是新提取的文件：

```cpp
add_library(math "")

target_sources(math
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxBLAS.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxLAPACK.cpp
  PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxBLAS.hpp
    ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxLAPACK.hpp
  )

target_include_directories(math
  INTERFACE
    ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK
  )

target_link_libraries(math
  PUBLIC
    ${LAPACK_LIBRARIES}
  )
```

1.  最后，添加了 `linear-algebra` 可执行目标。此可执行目标链接到包装器库：

```cpp
add_executable(linear-algebra linear-algebra.cpp)

target_link_libraries(linear-algebra
  PRIVATE
    math
  )
```

1.  有了这个，我们就可以配置、构建和执行示例：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
$ ./linear-algebra 1000

C_DSCAL done
C_DGESV done
info is 0
check is 4.35597e-10
```

# 它是如何工作的

让我们更仔细地看一下 `add_custom_command` 的调用：

```cpp
add_custom_command(
  OUTPUT
    ${wrap_BLAS_LAPACK_sources}
  COMMAND
    ${CMAKE_COMMAND} -E tar xzf ${CMAKE_CURRENT_SOURCE_DIR}/wrap_BLAS_LAPACK.tar.gz
  COMMAND
    ${CMAKE_COMMAND} -E touch ${wrap_BLAS_LAPACK_sources}
  WORKING_DIRECTORY
    ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/wrap_BLAS_LAPACK.tar.gz
  COMMENT
    "Unpacking C++ wrappers for BLAS/LAPACK"
  VERBATIM
  )
```

`add_custom_command` 向目标添加规则，以便它们知道如何通过执行命令来生成输出。*任何目标* 在 `add_custom_command` 的同一目录中声明，即在同一个 `CMakeLists.txt` 中，并且使用输出中的 *任何文件* 作为其源文件，将在构建时被赋予生成这些文件的规则。目标和自定义命令之间的依赖关系在构建系统生成时自动处理，而源文件的实际生成发生在构建时。

在我们特定的情况下，输出是包含在压缩的 tar 存档中的源文件。为了检索和使用这些文件，必须在构建时解压缩存档。这是通过使用 CMake 命令本身与`-E`标志来实现的，以实现平台独立性。下一个命令更新提取文件的时间戳。我们这样做是为了确保我们不会处理陈旧的源文件。`WORKING_DIRECTORY`指定执行命令的位置。在我们的例子中，这是`CMAKE_CURRENT_BINARY_DIR`，即当前正在处理的构建目录。`DEPENDS`关键字后面的参数列出了自定义命令的依赖项。在我们的例子中，压缩的 tar 存档是一个依赖项。`COMMENT`字段将由 CMake 用于在构建时打印状态消息。最后，`VERBATIM`告诉 CMake 为特定的生成器和平台生成正确的命令，从而确保完全的平台独立性。

让我们也仔细看看创建带有包装器的库的方式：

```cpp
add_library(math "")

target_sources(math
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxBLAS.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxLAPACK.cpp
  PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxBLAS.hpp
    ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxLAPACK.hpp
  )

target_include_directories(math
  INTERFACE
    ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK
  )

target_link_libraries(math
  PUBLIC
    ${LAPACK_LIBRARIES}
  )
```

我们声明一个没有源文件的库目标。这是因为我们随后使用`target_sources`来填充目标的源文件。这实现了非常重要的任务，即让依赖于此目标的其他目标知道它们需要哪些包含目录和头文件，以便成功使用该库。C++源文件对于目标是`PRIVATE`，因此仅用于构建库。头文件是`PUBLIC`，因为目标及其依赖项都需要使用它们来成功编译。使用`target_include_directories`指定包含目录，并将`wrap_BLAS_LAPACK`声明为`INTERFACE`，因为只有`math`目标的依赖项才需要它。

`add_custom_command`的这种形式有两个限制：

+   只有当所有依赖于其输出的目标都在同一个`CMakeLists.txt`中指定时，它才有效。

+   对于不同的独立目标使用相同的输出，`add_custom_command`可能会重新执行自定义命令规则。这可能导致冲突，应予以避免。

第二个限制可以通过仔细使用`add_dependencies`引入依赖关系来避免，但为了规避这两个问题，正确的方法是使用`add_custom_target`命令，我们将在下一个示例中详细说明。

# 在构建时运行自定义命令：II. 使用 add_custom_target

本示例的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-04`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-04)找到，并包含一个 C++示例。该示例适用于 CMake 版本 3.5（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

正如我们在前一个配方中讨论的，`add_custom_command`有一些局限性，可以通过使用`add_custom_target`来规避。这个 CMake 命令将在构建系统中引入新的目标。这些目标反过来执行不返回输出的命令，与`add_custom_command`相反。命令`add_custom_target`和`add_custom_command`可以结合使用。这样，自定义目标可以在与其依赖项不同的目录中指定，这在为项目设计模块化 CMake 基础设施时非常有用。

# 准备工作

对于这个配方，我们将重用前一个配方的源代码示例。然而，我们将稍微修改源文件的布局。特别是，我们不再将压缩的 tar 存档存储在顶层目录中，而是将其放置在一个名为`deps`的子目录中。这个子目录包含自己的`CMakeLists.txt`，它将被主`CMakeLists.txt`包含。

# 如何操作

我们将从主`CMakeLists.txt`开始，然后转到`deps/CMakeLists.txt`：

1.  与之前一样，我们声明一个 C++11 项目：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-04 LANGUAGES CXX Fortran)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  此时，我们转到`deps/CMakeLists.txt`。这是通过`add_subdirectory`命令实现的：

```cpp
add_subdirectory(deps)
```

1.  在`deps/CMakeLists.txt`内部，我们首先定位必要的库（BLAS 和 LAPACK）：

```cpp
find_package(BLAS REQUIRED)
find_package(LAPACK REQUIRED)
```

1.  然后，我们将 tarball 存档的内容收集到一个变量`MATH_SRCS`中：

```cpp
set(MATH_SRCS
  ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxBLAS.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxLAPACK.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxBLAS.hpp
  ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxLAPACK.hpp
  )
```

1.  列出要提取的源文件后，我们定义一个自定义目标和一个自定义命令。这种组合在`${CMAKE_CURRENT_BINARY_DIR}`中提取存档。然而，我们现在处于不同的作用域，并引用`deps/CMakeLists.txt`，因此 tarball 将被提取到主项目构建目录下的`deps`子目录中：

```cpp
add_custom_target(BLAS_LAPACK_wrappers
  WORKING_DIRECTORY
    ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS
    ${MATH_SRCS}
  COMMENT
    "Intermediate BLAS_LAPACK_wrappers target"
  VERBATIM
  )

add_custom_command(
  OUTPUT
    ${MATH_SRCS}
  COMMAND
    ${CMAKE_COMMAND} -E tar xzf ${CMAKE_CURRENT_SOURCE_DIR}/wrap_BLAS_LAPACK.tar.gz
  WORKING_DIRECTORY
    ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/wrap_BLAS_LAPACK.tar.gz
  COMMENT
    "Unpacking C++ wrappers for BLAS/LAPACK"
  )
```

1.  然后，我们将`math`库作为目标添加，并指定相应的源文件、包含目录和链接库：

```cpp
add_library(math "")

target_sources(math
  PRIVATE
    ${MATH_SRCS}
  )

target_include_directories(math
  INTERFACE
    ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK
  )

# BLAS_LIBRARIES are included in LAPACK_LIBRARIES
target_link_libraries(math
  PUBLIC
    ${LAPACK_LIBRARIES} 
  )
```

1.  一旦`deps/CMakeLists.txt`中的命令执行完毕，我们返回到父作用域，定义可执行目标，并将其与我们在下一目录定义的`math`库链接：

```cpp
add_executable(linear-algebra linear-algebra.cpp)

target_link_libraries(linear-algebra
  PRIVATE
    math
  )
```

# 它是如何工作的

使用`add_custom_target`，用户可以在目标内部执行自定义命令。这与我们之前讨论的`add_custom_command`配方有所不同。通过`add_custom_target`添加的目标没有输出，因此总是被执行。因此，可以在子目录中引入自定义目标，并且仍然能够在顶层的`CMakeLists.txt`中引用它。

在本例中，我们通过结合使用`add_custom_target`和`add_custom_command`提取了一个源文件归档。随后，这些源文件被用来编译一个库，我们设法在不同的（父）目录范围内将其链接起来。在构建`CMakeLists.txt`文件时，我们简要注释了 tarball 在`deps`下被提取，即项目构建目录的下一级子目录。这是因为，在 CMake 中，构建树的结构模仿了源树的层次结构。

在这个配方中，有一个值得注意的细节，我们应该讨论的是，我们将数学库源文件标记为`PRIVATE`的奇特事实：

```cpp
set(MATH_SRCS
  ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxBLAS.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxLAPACK.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxBLAS.hpp
  ${CMAKE_CURRENT_BINARY_DIR}/wrap_BLAS_LAPACK/CxxLAPACK.hpp
  )

# ...

add_library(math "")

target_sources(math
  PRIVATE
    ${MATH_SRCS}
  )

# ...
```

尽管这些源文件是`PRIVATE`，我们在父作用域中编译了`linear-algebra.cpp`，并且该源代码包含了`CxxBLAS.hpp`和`CxxLAPACK.hpp`。为什么在这里使用`PRIVATE`，以及如何可能编译`linear-algebra.cpp`并构建可执行文件？如果我们将头文件标记为`PUBLIC`，CMake 会在 CMake 时停止并报错，“找不到源文件”，因为尚未在文件树中生成（提取）的源文件不存在。

这是一个已知的限制（参见[`gitlab.kitware.com/cmake/cmake/issues/14633`](https://gitlab.kitware.com/cmake/cmake/issues/14633)，以及相关博客文章：[`samthursfield.wordpress.com/2015/11/21/cmake-dependencies-between-targets-and-files-and-custom-commands`](https://samthursfield.wordpress.com/2015/11/21/cmake-dependencies-between-targets-and-files-and-custom-commands)）。我们通过将源文件声明为`PRIVATE`来规避这个限制。这样做，我们在 CMake 时没有得到任何对不存在源文件的文件依赖。然而，CMake 内置的 C/C++文件依赖扫描器在构建时识别了它们，并且源文件被编译和链接。

# 在构建时为特定目标运行自定义命令

本配方的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-05`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-05)找到，并包含一个 Fortran 示例。该配方适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows（使用 MSYS Makefiles）上进行了测试。

本配方将展示如何使用`add_custom_command`的第二个签名来执行无输出的自定义操作。这对于在特定目标构建或链接之前或之后执行某些操作非常有用。由于自定义命令仅在目标本身需要构建时执行，我们实现了对它们执行的目标级控制。我们将通过一个示例来演示这一点，在该示例中，我们在目标构建之前打印其链接行，然后在编译后的可执行文件之后测量其静态大小分配。

# 准备工作

在本配方中，我们将使用以下示例 Fortran 代码（`example.f90`）：

```cpp
program example

  implicit none

  real(8) :: array(20000000)
  real(8) :: r
  integer :: i

  do i = 1, size(array)
    call random_number(r)
    array(i) = r
  end do

  print *, sum(array)

end program
```

这段代码是 Fortran 的事实对后续讨论影响不大，但我们选择 Fortran 是因为那里有很多遗留的 Fortran 代码，其中静态大小分配是一个问题。

在这段代码中，我们定义了一个包含 20,000,000 个双精度浮点的数组，我们期望这个数组占用 160MB 内存。我们在这里所做的并不是推荐的编程实践，因为在一般情况下，无论代码中是否使用，都会消耗内存。更好的方法是在需要时动态分配数组，并在使用后立即释放。

示例代码用随机数填充数组并计算它们的总和 - 这是为了确保数组确实被使用，编译器不会优化分配。我们将使用一个 Python 脚本（`static-size.py`）来测量示例二进制文件的静态分配大小，该脚本围绕 `size` 命令：

```cpp
import subprocess
import sys

# for simplicity we do not check number of
# arguments and whether the file really exists
file_path = sys.argv[-1]

try:
    output = subprocess.check_output(['size', file_path]).decode('utf-8')
except FileNotFoundError:
    print('command "size" is not available on this platform')
    sys.exit(0)

size = 0.0
for line in output.split('\n'):
    if file_path in line:
        # we are interested in the 4th number on this line
        size = int(line.split()[3])

print('{0:.3f} MB'.format(size/1.0e6))
```

为了打印链接行，我们将使用第二个 Python 辅助脚本（`echo-file.py`）来打印文件内容：

```cpp
import sys

# for simplicity we do not verify the number and
# type of arguments
file_path = sys.argv[-1]

try:
    with open(file_path, 'r') as f:
        print(f.read())
except FileNotFoundError:
    print('ERROR: file {0} not found'.format(file_path))
```

# 如何实现

让我们看一下我们的 `CMakeLists.txt`：

1.  我们首先声明一个 Fortran 项目：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-05 LANGUAGES Fortran)
```

1.  这个例子依赖于 Python 解释器，以便我们可以以可移植的方式执行辅助脚本：

```cpp
find_package(PythonInterp REQUIRED)
```

1.  在这个例子中，我们默认使用 `"Release"` 构建类型，以便 CMake 添加优化标志，以便我们稍后有东西可以打印：

```cpp
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
```

1.  现在，我们定义可执行目标：

```cpp
add_executable(example "")

target_sources(example
  PRIVATE
    example.f90
  )
```

1.  然后，我们定义一个自定义命令，在链接 `example` 目标之前打印链接行：

```cpp
add_custom_command(
  TARGET
    example
  PRE_LINK
```

```cpp
  COMMAND
    ${PYTHON_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/echo-file.py
      ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/example.dir/link.txt
  COMMENT
    "link line:"
  VERBATIM
  )
```

1.  最后，我们定义一个自定义命令，在成功构建后打印可执行文件的静态大小：

```cpp
add_custom_command(
  TARGET
    example
  POST_BUILD
  COMMAND
    ${PYTHON_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/static-size.py
      $<TARGET_FILE:example>
  COMMENT
    "static size of executable:"
  VERBATIM
  )
```

1.  让我们来测试一下。观察打印出的链接行和可执行文件的静态大小：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .

Scanning dependencies of target example
[ 50%] Building Fortran object CMakeFiles/example.dir/example.f90.o
[100%] Linking Fortran executable example
link line:
/usr/bin/f95 -O3 -DNDEBUG -O3 CMakeFiles/example.dir/example.f90.o -o example 

static size of executable:
160.003 MB
[100%] Built target example
```

# 工作原理

一旦声明了库或可执行目标，就可以通过使用 `add_custom_command` 将附加命令附加到目标上。正如我们所见，这些命令将在特定时间执行，与它们所附加的目标的执行上下文相关。CMake 理解以下选项，用于自定义命令的执行顺序：

+   `PRE_BUILD`：用于在执行与目标相关的任何其他规则之前执行的命令。但是，这只支持 Visual Studio 7 或更高版本。

+   `PRE_LINK`：使用此选项，命令将在目标编译后但在链接器或归档器调用之前执行。使用 `PRE_BUILD` 与 Visual Studio 7 或更高版本以外的生成器将被解释为 `PRE_LINK`。

+   `POST_BUILD`：如前所述，命令将在执行给定目标的所有规则之后运行。

在这个例子中，我们向可执行目标添加了两个自定义命令。`PRE_LINK` 命令将屏幕上打印出 `${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/example.dir/link.txt` 的内容。该文件包含链接命令，在我们的例子中，链接行结果如下：

```cpp
link line:
/usr/bin/f95 -O3 -DNDEBUG -O3 CMakeFiles/example.dir/example.f90.o -o example
```

我们为此使用了一个 Python 包装器，以不依赖于可能不具有可移植性的 shell 命令。

在第二步中，`POST_BUILD`自定义命令调用了 Python 辅助脚本`static-size.py`，其参数为生成器表达式`$<TARGET_FILE:example>`。CMake 将在*生成时间*，即构建系统生成时，将生成器表达式扩展为目标文件路径。Python 脚本`static-size.py`反过来使用`size`命令来获取可执行文件的静态分配大小，将其转换为 MB，并打印结果。在我们的例子中，我们得到了预期的 160 MB：

```cpp
static size of executable:
160.003 MB
```

# 探究编译和链接

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-06`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-06)找到，并提供了一个 C++示例。该食谱适用于 CMake 版本 3.9（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。代码仓库还包含了一个与 CMake 3.5 兼容的示例。

在构建系统生成过程中最常见的操作之一是评估我们试图在哪种系统上构建项目。这意味着尝试找出哪些功能有效，哪些无效，并相应地调整项目的编译，无论是通过发出依赖项未满足的信号，还是在我们的代码库中启用适当的变通方法。接下来的几个食谱将展示如何使用 CMake 执行这些操作。特别是，我们将考虑以下内容：

1.  如何确保特定的代码片段能够成功编译成可执行文件。

1.  如何确保编译器理解所需的标志。

1.  如何确保特定的代码片段能够成功编译成*运行的可执行文件*。

# 准备就绪

本食谱将展示如何使用相应的`Check<LANG>SourceCompiles.cmake`标准模块中的`check_<lang>_source_compiles`函数，以评估给定的编译器是否能够将预定义的代码片段编译成可执行文件。该命令可以帮助您确定：

+   您的编译器支持所需的功能。

+   链接器工作正常并理解特定的标志。

+   使用`find_package`找到的包含目录和库是可用的。

在本食谱中，我们将展示如何检测 OpenMP 4.5 标准中的任务循环功能，以便在 C++可执行文件中使用。我们将使用一个示例 C++源文件来探测编译器是否支持这样的功能。CMake 提供了一个额外的命令`try_compile`来探测编译。本食谱将展示如何使用这两种方法。

您可以使用 CMake 命令行界面来获取特定模块（`cmake --help-module <module-name>`）和命令（`cmake --help-command <command-name>`）的文档。在我们的例子中，`cmake --help-module CheckCXXSourceCompiles`将输出`check_cxx_source_compiles`函数的文档到屏幕，而`cmake --help-command try_compile`将做同样的事情，为`try_compile`命令。

# 如何操作

我们将同时使用`try_compile`和`check_cxx_source_compiles`，并比较这两个命令的工作方式：

1.  我们首先创建一个 C++11 项目：

```cpp
cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(recipe-06 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  我们找到编译器的 OpenMP 支持：

```cpp
find_package(OpenMP)

if(OpenMP_FOUND)
  # ... <- the steps below will be placed here
else()
  message(STATUS "OpenMP not found: no test for taskloop is run")
endif()
```

1.  如果找到了 OpenMP，我们继续前进并探测所需功能是否可用。为此，我们设置一个临时目录。这将由`try_compile`用于生成其中间文件。我们将这个放在前一步引入的 if 子句中：

```cpp
set(_scratch_dir ${CMAKE_CURRENT_BINARY_DIR}/omp_try_compile)
```

1.  我们调用`try_compile`来生成一个小项目，尝试编译源文件`taskloop.cpp`。成功或失败将被保存到`omp_taskloop_test_1`变量中。我们需要为这个小样本编译设置适当的编译器标志、包含目录和链接库。由于我们使用的是*导入的目标* `OpenMP::OpenMP_CXX`，这只需通过设置`LINK_LIBRARIES`选项为`try_compile`来简单完成。如果编译成功，那么任务循环功能是可用的，我们向用户打印一条消息：

```cpp
try_compile(
  omp_taskloop_test_1
  ${_scratch_dir}
  SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/taskloop.cpp
  LINK_LIBRARIES
    OpenMP::OpenMP_CXX
  ) 
message(STATUS "Result of try_compile: ${omp_taskloop_test_1}")
```

1.  为了使用`check_cxx_source_compiles`函数，我们需要包含`CheckCXXSourceCompiles.cmake`模块文件。这是随 CMake 一起分发的，与 C（`CheckCSourceCompiles.cmake`）和 Fortran（`CheckFortranSourceCompiles.cmake`）的类似文件一起：

```cpp
include(CheckCXXSourceCompiles)
```

1.  我们通过使用`file(READ ...)`命令读取其内容，将我们尝试编译和链接的源文件的内容复制到 CMake 变量中：

```cpp
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/taskloop.cpp _snippet)
```

1.  我们设置`CMAKE_REQUIRED_LIBRARIES`。这是为了在下一步中正确调用编译器所必需的。注意使用了*导入的* `OpenMP::OpenMP_CXX`目标，这将同时设置适当的编译器标志和包含目录：

```cpp
set(CMAKE_REQUIRED_LIBRARIES OpenMP::OpenMP_CXX)
```

1.  我们调用`check_cxx_source_compiles`函数并传入我们的代码片段。检查的结果将被保存到`omp_taskloop_test_2`变量中：

```cpp
check_cxx_source_compiles("${_snippet}" omp_taskloop_test_2)
```

1.  在调用`check_cxx_source_compiles`之前，我们取消设置之前定义的变量，并向用户打印一条消息：

```cpp
unset(CMAKE_REQUIRED_LIBRARIES)
message(STATUS "Result of check_cxx_source_compiles: ${omp_taskloop_test_2}"
```

1.  最后，我们测试这个配方：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..

-- ...
-- Found OpenMP_CXX: -fopenmp (found version "4.5") 
-- Found OpenMP: TRUE (found version "4.5") 
-- Result of try_compile: TRUE
-- Performing Test omp_taskloop_test_2
-- Performing Test omp_taskloop_test_2 - Success
-- Result of check_cxx_source_compiles: 1
```

# 工作原理

`try_compile`和`check_cxx_source_compiles`都将编译并链接一个源文件到一个可执行文件。如果这些操作成功，那么输出变量，对于前者是`omp_task_loop_test_1`，对于后者是`omp_task_loop_test_2`，将被设置为`TRUE`。这两个命令完成任务的方式略有不同，然而。`check_<lang>_source_compiles`系列命令是`try_compile`命令的一个简化包装。因此，它提供了一个最小化的接口：

1.  要编译的代码片段必须作为 CMake 变量传递。大多数情况下，这意味着必须使用 `file(READ ...)` 读取文件，正如我们在示例中所做的那样。然后，该片段将保存到构建目录的 `CMakeFiles/CMakeTmp` 子目录中的文件中。

1.  通过在调用函数之前设置以下 CMake 变量来微调编译和链接：

    +   `CMAKE_REQUIRED_FLAGS` 用于设置编译器标志

    +   `CMAKE_REQUIRED_DEFINITIONS` 用于设置预处理器宏

    +   `CMAKE_REQUIRED_INCLUDES` 用于设置包含目录列表

    +   `CMAKE_REQUIRED_LIBRARIES` 用于设置链接到可执行文件的库列表

1.  在调用 `check_<lang>_compiles_function` 后，必须手动取消设置这些变量，以确保同一变量的后续使用不会包含虚假内容。

在 CMake 3.9 中引入了 OpenMP 导入目标，但当前的方案也可以通过手动设置所需的标志和库，使其与早期版本的 CMake 兼容，方法如下：`set(CMAKE_REQUIRED_FLAGS ${OpenMP_CXX_FLAGS})` 和 `set(CMAKE_REQUIRED_LIBRARIES ${OpenMP_CXX_LIBRARIES})`。

对于 Fortran，CMake 假定样本片段采用固定格式，但这并不总是正确的。为了克服假阴性，需要为 `check_fortran_source_compiles` 设置 `-ffree-form` 编译器标志。这可以通过 `set(CMAKE_REQUIRED_FLAGS "-ffree-form")` 实现。

这种最小接口反映了测试编译是通过在 CMake 调用中直接生成和执行构建和链接命令来进行的。

`try_compile` 命令提供了更完整的接口和两种不同的操作模式：

1.  第一种方式接受一个完整的 CMake 项目作为输入，并根据其 `CMakeLists.txt` 配置、构建和链接它。这种操作模式提供了更多的灵活性，因为要编译的项目可以任意复杂。

1.  第二种方式，我们使用的方式，提供了一个源文件以及用于包含目录、链接库和编译器标志的配置选项。

`try_compile` 因此基于调用 CMake 的项目，要么是已经存在 `CMakeLists.txt` 的项目（在第一种操作模式下），要么是根据传递给 `try_compile` 的参数动态生成的项目。

# 还有更多

本方案中概述的检查类型并不总是万无一失的，可能会产生假阳性和假阴性。例如，你可以尝试注释掉包含 `CMAKE_REQUIRED_LIBRARIES` 的行，示例仍将报告“成功”。这是因为编译器将忽略 OpenMP 指令。

当你怀疑返回了错误的结果时，应该怎么办？`CMakeOutput.log`和`CMakeError.log`文件位于构建目录的`CMakeFiles`子目录中，它们提供了出错线索。它们报告了 CMake 运行的操作的标准输出和标准错误。如果你怀疑有误报，应该检查前者，通过搜索设置为保存编译检查结果的变量。如果你怀疑有漏报，应该检查后者。

调试`try_compile`需要小心。CMake 会删除该命令生成的所有文件，即使检查不成功。幸运的是，`--debug-trycompile`将阻止 CMake 进行清理。如果你的代码中有多个`try_compile`调用，你将只能一次调试一个：

1.  运行一次 CMake，不带`--debug-trycompile`。所有`try_compile`命令都将运行，并且它们的执行目录和文件将被清理。

1.  从 CMake 缓存中删除保存检查结果的变量。缓存保存在`CMakeCache.txt`文件中。要清除变量的内容，可以使用`-U`CLI 开关，后跟变量的名称，该名称将被解释为全局表达式，因此可以使用`*`和`?`：

```cpp
$ cmake -U <variable-name>
```

1.  再次运行 CMake，使用`--debug-trycompile`选项。只有清除缓存的检查会被重新运行。这次执行目录和文件不会被清理。

`try_compile`提供了更多的灵活性和更清晰的接口，特别是当要编译的代码不是简短的代码片段时。我们建议在需要测试编译的代码是简短、自包含且不需要广泛配置的情况下，使用`check_<lang>_source_compiles`。在所有其他情况下，`try_compile`被认为是更优越的替代方案。

# 探测编译器标志

本节代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-07`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-07)获取，并包含一个 C++示例。本节适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

设置编译器标志至关重要，以确保代码正确编译。不同的编译器供应商为相似的任务实现不同的标志。即使是同一供应商的不同编译器版本，也可能在可用的标志上略有差异。有时，会引入新的标志，这些标志对于调试或优化目的极为方便。在本节中，我们将展示如何检查所选编译器是否支持某些标志。

# 准备工作

消毒器（参考[`github.com/google/sanitizers`](https://github.com/google/sanitizers)）已经成为静态和动态代码分析的极其有用的工具。只需使用适当的标志重新编译代码并链接必要的库，您就可以调查和调试与内存错误（地址消毒器）、未初始化读取（内存消毒器）、线程安全（线程消毒器）和未定义行为（未定义行为消毒器）相关的问题。与类似的分析工具相比，消毒器通常引入的性能开销要小得多，并且往往提供更详细的问题检测信息。缺点是您的代码，可能还有部分工具链，需要使用额外的标志重新编译。

在本教程中，我们将设置一个项目以使用激活的不同消毒器编译代码，并展示如何检查正确的编译器标志是否可用。

# 如何操作

消毒器已经有一段时间与 Clang 编译器一起可用，并且后来也被引入到 GCC 工具集中。它们是为 C 和 C++程序设计的，但最近的 Fortran 版本将理解相同的标志并生成正确检测的库和可执行文件。然而，本教程将重点介绍一个 C++示例。

1.  通常，我们首先声明一个 C++11 项目：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-07 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  我们声明一个列表`CXX_BASIC_FLAGS`，包含构建项目时始终使用的编译器标志，`-g3`和`-O1`：

```cpp
list(APPEND CXX_BASIC_FLAGS "-g3" "-O1")
```

1.  我们包含 CMake 模块`CheckCXXCompilerFlag.cmake`。类似的模块也可用于 C（`CheckCCompilerFlag.cmake`）和 Fortran（`CheckFortranCompilerFlag.cmake`，自 CMake 3.3 起）：

```cpp
include(CheckCXXCompilerFlag)
```

1.  我们声明一个`ASAN_FLAGS`变量，它包含激活地址消毒器所需的标志，并设置`CMAKE_REQUIRED_FLAGS`变量，该变量由`check_cxx_compiler_flag`函数内部使用：

```cpp
set(ASAN_FLAGS "-fsanitize=address -fno-omit-frame-pointer")
set(CMAKE_REQUIRED_FLAGS ${ASAN_FLAGS})
```

1.  我们调用`check_cxx_compiler_flag`以确保编译器理解`ASAN_FLAGS`变量中的标志。调用函数后，我们取消设置`CMAKE_REQUIRED_FLAGS`：

```cpp
check_cxx_compiler_flag(${ASAN_FLAGS} asan_works)
unset(CMAKE_REQUIRED_FLAGS)
```

1.  如果编译器理解这些选项，我们将变量转换为列表，方法是替换空格为分号：

```cpp
if(asan_works)
  string(REPLACE " " ";" _asan_flags ${ASAN_FLAGS})
```

1.  我们为我们的代码示例添加一个带有地址消毒器的可执行目标：

```cpp
  add_executable(asan-example asan-example.cpp)
```

1.  我们将可执行文件的编译器标志设置为包含基本和地址消毒器标志：

```cpp
  target_compile_options(asan-example
    PUBLIC
      ${CXX_BASIC_FLAGS}
      ${_asan_flags}
    )
```

1.  最后，我们将地址消毒器标志也添加到链接器使用的标志集中。这关闭了`if(asan_works)`块：

```cpp
  target_link_libraries(asan-example PUBLIC ${_asan_flags})
endif()
```

完整的教程源代码还展示了如何为线程、内存和未定义行为消毒器编译和链接示例可执行文件。这些在这里没有详细讨论，因为我们使用相同的模式来检查编译器标志。

一个用于在您的系统上查找消毒器支持的自定义 CMake 模块可在 GitHub 上获得：[`github.com/arsenm/sanitizers-cmake`](https://github.com/arsenm/sanitizers-cmake)。

# 它是如何工作的

`check_<lang>_compiler_flag`函数只是`check_<lang>_source_compiles`函数的包装器，我们在上一节中讨论过。这些包装器为常见用例提供了一个快捷方式，即不重要检查特定的代码片段是否编译，而是检查编译器是否理解一组标志。

对于 sanitizer 的编译器标志来说，它们还需要传递给链接器。为了使用`check_<lang>_compiler_flag`函数实现这一点，我们需要在调用之前设置`CMAKE_REQUIRED_FLAGS`变量。否则，作为第一个参数传递的标志只会在调用编译器时使用，导致错误的否定结果。

在本节中还有一个要点需要注意，那就是使用字符串变量和列表来设置编译器标志。如果在`target_compile_options`和`target_link_libraries`函数中使用字符串变量，将会导致编译器和/或链接器错误。CMake 会将这些选项用引号括起来，导致解析错误。这就解释了为什么需要以列表的形式表达这些选项，并进行后续的字符串操作，将字符串变量中的空格替换为分号。我们再次提醒，CMake 中的列表是分号分隔的字符串。

# 另请参阅

我们将在第七章，*项目结构化*，第三部分，*编写测试和设置编译器标志的函数*中重新审视并概括测试和设置编译器标志的模式。

# 探测执行

本节的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-08`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-08)找到，并提供了一个 C/C++示例。本节适用于 CMake 版本 3.6（及以上），并在 GNU/Linux 和 macOS 上进行了测试。代码仓库还包含了一个与 CMake 3.5 兼容的示例。

到目前为止，我们已经展示了如何检查给定的源代码片段是否能被选定的编译器编译，以及如何确保所需的编译器和链接器标志可用。本节将展示如何检查代码片段是否可以在当前系统上编译、链接和运行。

# 准备工作

本节的代码示例是对第三章，*检测外部库和程序*，第九部分，*检测外部库：I. 使用`pkg-config`*的轻微变体。在那里，我们展示了如何在系统上找到 ZeroMQ 库并将其链接到 C 程序中。在本节中，我们将检查使用 GNU/Linux 系统 UUID 库的小型 C 程序是否可以实际运行，然后再生成实际的 C++程序。

# 如何操作

我们希望检查 GNU/Linux 上的 UUID 系统库是否可以链接，然后再开始构建我们自己的 C++项目。这可以通过以下一系列步骤实现：

1.  我们首先声明一个混合 C 和 C++11 程序。这是必要的，因为我们要编译和运行的测试代码片段是用 C 语言编写的：

```cpp
cmake_minimum_required(VERSION 3.6 FATAL_ERROR)

project(recipe-08 LANGUAGES CXX C)

```

```cpp
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  我们需要在我们的系统上找到 UUID 库。这可以通过使用 `pkg-config` 来实现。我们要求搜索返回一个 CMake 导入目标，使用 `IMPORTED_TARGET` 参数：

```cpp
find_package(PkgConfig REQUIRED QUIET)
pkg_search_module(UUID REQUIRED uuid IMPORTED_TARGET)
if(TARGET PkgConfig::UUID)
  message(STATUS "Found libuuid")
endif()
```

1.  接下来，我们包含 `CheckCSourceRuns.cmake` 模块。对于 C++ 有一个类似的 `CheckCXXSourceRuns.cmake` 模块。然而，对于 Fortran 语言，在 CMake 3.11 中没有这样的模块：

```cpp
include(CheckCSourceRuns)
```

1.  我们声明一个包含要编译和运行的 C 代码片段的 `_test_uuid` 变量：

```cpp
set(_test_uuid
  "
#include <uuid/uuid.h>

int main(int argc, char * argv[]) {
  uuid_t uuid;

  uuid_generate(uuid);

  return 0;
}
  ")
```

1.  我们声明 `CMAKE_REQUIRED_LIBRARIES` 变量以微调对 `check_c_source_runs` 函数的调用。接下来，我们使用测试代码片段作为第一个参数和对 `_runs` 变量作为第二个参数调用 `check_c_source_runs`，以保存执行的检查结果。我们还取消设置 `CMAKE_REQUIRED_LIBRARIES` 变量：

```cpp
set(CMAKE_REQUIRED_LIBRARIES PkgConfig::UUID)
check_c_source_runs("${_test_uuid}" _runs)
unset(CMAKE_REQUIRED_LIBRARIES)
```

1.  如果检查未成功，可能是因为代码片段未编译或未运行，我们以致命错误停止配置：

```cpp
if(NOT _runs)
  message(FATAL_ERROR "Cannot run a simple C executable using libuuid!")
endif()
```

1.  否则，我们继续添加 C++ 可执行文件作为目标并链接到 UUID：

```cpp
add_executable(use-uuid use-uuid.cpp)

target_link_libraries(use-uuid
  PUBLIC
    PkgConfig::UUID
  )
```

# 工作原理

`check_<lang>_source_runs` 函数对于 C 和 C++ 的操作原理与 `check_<lang>_source_compiles` 相同，但在实际运行生成的可执行文件时增加了额外步骤。与 `check_<lang>_source_compiles` 一样，`check_<lang>_source_runs` 的执行可以通过以下变量进行指导：

+   `CMAKE_REQUIRED_FLAGS` 用于设置编译器标志

+   `CMAKE_REQUIRED_DEFINITIONS` 用于设置预处理器宏

+   `CMAKE_REQUIRED_INCLUDES` 用于设置包含目录列表

+   `CMAKE_REQUIRED_LIBRARIES` 用于设置链接到可执行文件的库列表

由于我们使用了由 `pkg_search_module` 生成的导入目标，因此只需将 `CMAKE_REQUIRES_LIBRARIES` 设置为 `PkgConfig::UUID`，即可正确设置包含目录。

正如 `check_<lang>_source_compiles` 是 `try_compile` 的包装器，`check_<lang>_source_runs` 是 CMake 中另一个更强大的命令 `try_run` 的包装器。因此，可以通过适当地包装 `try_run` 来编写一个提供与 C 和 C++ 模块相同功能的 `CheckFortranSourceRuns.cmake` 模块。

`pkg_search_module` 仅在 CMake 3.6 中学会了如何定义导入目标，但当前的配方也可以通过手动设置 `check_c_source_runs` 所需的包含目录和库来与早期版本的 CMake 一起工作，如下所示：`set(CMAKE_REQUIRED_INCLUDES ${UUID_INCLUDE_DIRS})` 和 `set(CMAKE_REQUIRED_LIBRARIES ${UUID_LIBRARIES})`。

# 使用生成器表达式微调配置和编译

本配方的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-09`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-05/recipe-09)获取，并包含一个 C++示例。该配方适用于 CMake 版本 3.9（及更高版本），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

CMake 提供了一种特定于领域的语言来描述如何配置和构建项目。自然地，描述特定条件的变量被引入，并且基于这些变量的条件语句被包含在`CMakeLists.txt`中。

在本配方中，我们将重新审视生成器表达式，我们在第四章，*创建和运行测试*中广泛使用它们，以紧凑地引用明确的测试可执行路径。生成器表达式提供了一个强大而紧凑的模式，用于逻辑和信息表达，这些表达在构建系统生成期间被评估，并产生特定于每个构建配置的信息。换句话说，生成器表达式对于引用仅在生成时已知的信息非常有用，但在配置时未知或难以知道；这在文件名、文件位置和库文件后缀的情况下尤其如此。

在本例中，我们将使用生成器表达式来有条件地设置预处理器定义，并有条件地链接消息传递接口（MPI）库，使我们能够构建相同的源代码，无论是顺序执行还是使用 MPI 并行性。

在本例中，我们将使用一个导入的目标来链接 MPI，该功能仅从 CMake 3.9 开始提供。然而，生成器表达式的方面可以转移到 CMake 3.0 或更高版本。

# 准备就绪

我们将编译以下示例源代码（`example.cpp`）：

```cpp
#include <iostream>

#ifdef HAVE_MPI
#include <mpi.h>
#endif

int main() {
#ifdef HAVE_MPI
  // initialize MPI
  MPI_Init(NULL, NULL);

  // query and print the rank
  int rank;
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  std::cout << "hello from rank " << rank << std::endl;

  // initialize MPI
  MPI_Finalize();
#else
  std::cout << "hello from a sequential binary" << std::endl;
#endif /* HAVE_MPI */
}
```

代码包含预处理器语句（`#ifdef HAVE_MPI` ... `#else` ... `#endif`），以便我们可以使用相同的源代码编译顺序或并行可执行文件。

# 如何操作

在编写`CMakeLists.txt`文件时，我们将重用我们在第三章，*检测外部库和程序*，第 6 个配方，*检测 MPI 并行环境*中遇到的构建块：

1.  我们声明一个 C++11 项目：

```cpp
cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(recipe-09 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  然后，我们引入一个选项`USE_MPI`，以选择 MPI 并行化，并默认设置为`ON`。如果它是`ON`，我们使用`find_package`来定位 MPI 环境：

```cpp
option(USE_MPI "Use MPI parallelization" ON)

if(USE_MPI)
  find_package(MPI REQUIRED)
endif()
```

1.  然后，我们定义可执行目标，并根据条件设置相应的库依赖项（`MPI::MPI_CXX`）和预处理器定义（`HAVE_MPI`），我们将在稍后解释：

```cpp
add_executable(example example.cpp)

target_link_libraries(example
  PUBLIC
    $<$<BOOL:${MPI_FOUND}>:MPI::MPI_CXX>
  )

target_compile_definitions(example
  PRIVATE
    $<$<BOOL:${MPI_FOUND}>:HAVE_MPI>
  )
```

1.  如果找到 MPI，我们还打印由`FindMPI.cmake`导出的`INTERFACE_LINK_LIBRARIES`，以演示非常方便的`cmake_print_properties()`函数：

```cpp
if(MPI_FOUND)
  include(CMakePrintHelpers)
  cmake_print_properties(
    TARGETS MPI::MPI_CXX
    PROPERTIES INTERFACE_LINK_LIBRARIES
    )
endif()
```

1.  让我们首先使用默认的 MPI 并行化开关`ON`配置代码。观察`cmake_print_properties()`的输出：

```cpp
$ mkdir -p build_mpi
$ cd build_mpi
$ cmake ..

-- ...
-- 
 Properties for TARGET MPI::MPI_CXX:
 MPI::MPI_CXX.INTERFACE_LINK_LIBRARIES = "-Wl,-rpath -Wl,/usr/lib/openmpi -Wl,--enable-new-dtags -pthread;/usr/lib/openmpi/libmpi_cxx.so;/usr/lib/openmpi/libmpi.so"
```

1.  我们编译并运行并行示例：

```cpp
$ cmake --build .
$ mpirun -np 2 ./example

hello from rank 0
hello from rank 1
```

1.  现在，让我们向上移动一个目录，创建一个新的构建目录，这次构建顺序版本：

```cpp
$ mkdir -p build_seq
$ cd build_seq
$ cmake -D USE_MPI=OFF ..
$ cmake --build .
$ ./example

hello from a sequential binary
```

# 工作原理

项目的构建系统由 CMake 在两个阶段生成：配置阶段，其中解析`CMakeLists.txt`，生成阶段，实际生成构建环境。生成器表达式在这个第二阶段评估，并可用于使用只能在生成时知道的信息调整构建系统。因此，生成器表达式在交叉编译时特别有用，其中一些信息只有在解析`CMakeLists.txt`后才可用，或者在多配置项目中，构建系统为项目的所有不同配置（如`Debug`和`Release`）一次性生成。

在我们的例子中，我们将使用生成器表达式来有条件地设置链接依赖和编译定义。为此，我们可以关注这两个表达式：

```cpp
target_link_libraries(example
  PUBLIC
    $<$<BOOL:${MPI_FOUND}>:MPI::MPI_CXX>
  )

target_compile_definitions(example
  PRIVATE
    $<$<BOOL:${MPI_FOUND}>:HAVE_MPI>
  )
```

如果`MPI_FOUND`为真，那么`$<BOOL:${MPI_FOUND}>`将评估为 1。在这种情况下，`$<$<BOOL:${MPI_FOUND}>:MPI::MPI_CXX>`将评估为`MPI::MPI_CXX`，第二个生成器表达式将评估为`HAVE_MPI`。如果我们设置`USE_MPI`为`OFF`，`MPI_FOUND`为假，两个生成器表达式都将评估为空字符串，因此不会引入链接依赖，也不会设置预处理器定义。

我们可以通过引入 if 语句来实现相同的效果：

```cpp
if(MPI_FOUND)
  target_link_libraries(example
    PUBLIC
      MPI::MPI_CXX
    )

  target_compile_definitions(example
    PRIVATE
      HAVE_MPI
    )
endif()
```

这个解决方案可能不那么紧凑，但可能更易读。我们经常可以使用生成器表达式重新表达 if 语句，选择通常是个人喜好的问题。然而，生成器表达式在需要访问或操作显式文件路径时特别有用，因为这些路径使用变量和 if 子句构造起来可能很困难，在这种情况下，我们明显倾向于使用生成器表达式以提高可读性。在第四章，*创建和运行测试*中，我们使用生成器表达式来解析特定目标的文件路径。在第十一章，*打包项目*中，我们也会欣赏生成器表达式。

# 还有更多

CMake 提供了三种类型的生成器表达式：

+   逻辑表达式，基本模式为`$<condition:outcome>`。基本条件是`0`表示假，`1`表示真，但任何布尔值都可以用作条件，只要使用正确的关键字即可。

+   信息表达式，基本模式为`$<information>`或`$<information:input>`。这些表达式评估为某些构建系统信息，例如，包含目录，目标属性等。这些表达式的输入参数可能是目标的名称，如表达式`$<TARGET_PROPERTY:tgt,prop>`，其中获取的信息将是`tgt`目标的`prop`属性。

+   输出表达式，基本模式为`$<operation>`或`$<operation:input>`。这些表达式生成输出，可能基于某些输入参数。它们的输出可以直接在 CMake 命令中使用，也可以与其他生成器表达式结合使用。例如，`-I$<JOIN:$<TARGET_PROPERTY:INCLUDE_DIRECTORIES>, -I>`将生成一个包含正在处理的目标的包含目录的字符串，每个目录前都添加了`-I`。

# 另请参阅

如需查看生成器表达式的完整列表，请查阅[`cmake.org/cmake/help/latest/manual/cmake-generator-expressions.7.html`](https://cmake.org/cmake/help/latest/manual/cmake-generator-expressions.7.html)。
