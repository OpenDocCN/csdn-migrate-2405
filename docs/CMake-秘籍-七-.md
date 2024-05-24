# CMake 秘籍（七）

> 原文：[`zh.annas-archive.org/md5/ecf89da6185e63c44e748e0980911fef`](https://zh.annas-archive.org/md5/ecf89da6185e63c44e748e0980911fef)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：构建文档

在本章中，我们将涵盖以下食谱：

+   使用 Doxygen 构建文档

+   使用 Sphinx 构建文档

+   结合 Doxygen 和 Sphinx

# 引言

文档在所有软件项目中都是必不可少的：对于用户，解释如何获取和构建代码，并说明如何有效地使用您的代码或库，对于开发者，描述库的内部细节，并帮助其他程序员参与并贡献于您的项目。本章将展示如何使用 CMake 构建代码文档，使用两个流行的框架：Doxygen 和 Sphinx。

# 使用 Doxygen 构建文档

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-12/recipe-01`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-12/recipe-01)找到，并包含一个 C++示例。该食谱适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

Doxygen（[`www.doxygen.nl`](http://www.doxygen.nl)）是一个非常流行的源代码文档工具。您可以在代码中添加文档标签作为注释。运行 Doxygen 将提取这些注释并在 Doxyfile 配置文件中定义的格式中创建文档。Doxygen 可以输出 HTML、XML，甚至是 LaTeX 或 PDF。本食谱将向您展示如何使用 CMake 构建您的 Doxygen 文档。

# 准备就绪

我们将使用之前章节中介绍的`message`库的简化版本。源树组织如下：

```cpp
.
├── cmake
│   └── UseDoxygenDoc.cmake
├── CMakeLists.txt
├── docs
│   ├── Doxyfile.in
│   └── front_page.md
└── src
    ├── CMakeLists.txt
    ├── hello-world.cpp
    ├── Message.cpp
    └── Message.hpp
```

我们的源代码仍然位于`src`子目录下，自定义 CMake 模块位于`cmake`子目录下。由于我们的重点是文档，我们删除了对 UUID 的依赖并简化了源代码。最显著的区别是头文件中的大量代码注释：

```cpp
#pragma once

#include <iosfwd>
#include <string>

/*! \file Message.hpp */

/*! \class Message
 * \brief Forwards string to screen
 * \author Roberto Di Remigio
 * \date 2018
 */
class Message {
public:
  /*! \brief Constructor from a string
   * \param[in] m a message
   */
  Message(const std::string &m) : message_(m) {}
  /*! \brief Constructor from a character array
   * \param[in] m a message
   */
  Message(const char *m) : message_(std::string(m)) {}

  friend std::ostream &operator<<(std::ostream &os, Message &obj) {
    return obj.printObject(os);
  }

private:
  /*! The message to be forwarded to screen */
  std::string message_;
  /*! \brief Function to forward message to screen
   * \param[in, out] os output stream
   */
  std::ostream &printObject(std::ostream &os);
};
```

这些注释采用`/*! */`格式，并包含一些特殊标签，这些标签被 Doxygen 理解（参见[`www.stack.nl/~dimitri/doxygen/manual/docblocks.html`](http://www.stack.nl/~dimitri/doxygen/manual/docblocks.html)）。

# 如何操作

首先，让我们讨论根目录中的`CMakeLists.txt`文件：

1.  如您所熟悉，我们声明一个 C++11 项目，如下所示：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-01 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  我们定义共享和静态库以及可执行文件的输出目录，如下所示：

```cpp
include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})
```

1.  我们将`cmake`子目录附加到`CMAKE_MODULE_PATH`。这是 CMake 找到我们的自定义模块所必需的：

```cpp
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
```

1.  包含自定义模块`UseDoxygenDoc.cmake`。我们将在后面讨论其内容：

```cpp
include(UseDoxygenDoc)
```

1.  然后我们添加`src`子目录：

```cpp
add_subdirectory(src)
```

`src`子目录中的`CMakeLists.txt`文件包含以下构建块：

1.  我们添加一个`message`静态库，如下所示：

```cpp
add_library(message STATIC
  Message.hpp
  Message.cpp
  )
```

1.  然后我们添加一个可执行目标，`hello-world`：

```cpp
add_executable(hello-world hello-world.cpp)
```

1.  然后，`hello-world`可执行文件应该链接到消息库：

```cpp
target_link_libraries(hello-world
  PUBLIC
    message
  )
```

在根`CMakeLists.txt`文件的最后一节中，我们调用了`add_doxygen_doc`函数。这添加了一个新的`docs`目标，该目标将调用 Doxygen 来构建我们的文档：

```cpp
add_doxygen_doc(
  BUILD_DIR
    ${CMAKE_CURRENT_BINARY_DIR}/_build
  DOXY_FILE
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in
  TARGET_NAME
    docs
  COMMENT
    "HTML documentation"
  )
```

最后，让我们看一下`UseDoxygenDoc.cmake`模块，其中定义了`add_doxygen_doc`函数：

1.  我们找到`Doxygen`和`Perl`可执行文件，如下所示：

```cpp
find_package(Perl REQUIRED)
find_package(Doxygen REQUIRED)
```

1.  然后，我们声明`add_doxygen_doc`函数。该函数理解单值参数：`BUILD_DIR`、`DOXY_FILE`、`TARGET_NAME`和`COMMENT`。我们使用 CMake 的标准命令`cmake_parse_arguments`来解析这些参数：

```cpp
function(add_doxygen_doc)
  set(options)
  set(oneValueArgs BUILD_DIR DOXY_FILE TARGET_NAME COMMENT)
  set(multiValueArgs)

  cmake_parse_arguments(DOXY_DOC
    "${options}"
    "${oneValueArgs}"
    "${multiValueArgs}"
    ${ARGN}
    )

  # ...

endfunction()
```

1.  `Doxyfile`包含构建文档所需的所有 Doxygen 设置。模板`Doxyfile.in`作为函数参数`DOXY_FILE`传递，并被解析到`DOXY_DOC_DOXY_FILE`变量中。我们按照以下方式配置模板文件`Doxyfile.in`：

```cpp
configure_file(
  ${DOXY_DOC_DOXY_FILE}
  ${DOXY_DOC_BUILD_DIR}/Doxyfile
  @ONLY
  )
```

1.  然后，我们定义一个名为`DOXY_DOC_TARGET_NAME`的自定义目标，它将使用`Doxyfile`中的设置执行 Doxygen，并将结果输出到`DOXY_DOC_BUILD_DIR`：

```cpp
add_custom_target(${DOXY_DOC_TARGET_NAME}
  COMMAND
    ${DOXYGEN_EXECUTABLE} Doxyfile
  WORKING_DIRECTORY
    ${DOXY_DOC_BUILD_DIR}
  COMMENT
    "Building ${DOXY_DOC_COMMENT} with Doxygen"
  VERBATIM
  )
```

1.  最终，会向用户打印一条状态消息：

```cpp
message(STATUS "Added ${DOXY_DOC_TARGET_NAME} [Doxygen] target to build documentation")
```

我们可以像往常一样配置项目：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
```

通过调用我们的自定义`docs`目标，可以构建文档：

```cpp
$ cmake --build . --target docs
```

你会注意到，在构建树中会出现一个`_build`子目录。这包含 Doxygen 从你的源文件生成的 HTML 文档。使用你喜欢的浏览器打开`index.html`将显示 Doxygen 欢迎页面。

如果你导航到类列表，你可以例如浏览`Message`类的文档：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/1b2323e8-2dc6-4a22-90e5-b1dfedcfc6d1.png)

# 工作原理

CMake 默认不支持文档构建。但是，我们可以使用`add_custom_target`来执行任意操作，这是我们在本食谱中利用的机制。需要注意的是，我们需要确保系统上存在构建文档所需的工具（在本例中为 Doxygen 和 Perl）。

此外，请注意`UseDoxygenDoc.cmake`自定义模块仅执行以下操作：

+   执行对 Doxygen 和 Perl 可执行文件的搜索

+   定义一个函数

实际创建`docs`目标的操作留给了稍后调用`add_doxygen_doc`函数。这是一种“显式优于隐式”的模式，我们认为这是良好的 CMake 实践：不要使用模块包含来执行类似宏（或函数）的操作。

我们通过使用函数而不是宏来实现`add_doxygen_doc`，以限制变量定义的作用域和可能的副作用。在这种情况下，函数和宏都可以工作（并且会产生相同的结果），但我们建议除非需要修改父作用域中的变量，否则应优先使用函数而不是宏。

CMake 3.9 中添加了一个新的改进的`FindDoxygen.cmake`模块。实现了便利函数`doxygen_add_docs`，它将作为我们在本食谱中介绍的宏。有关更多详细信息，请查看在线文档[`cmake.org/cmake/help/v3.9/module/FindDoxygen.html`](https://cmake.org/cmake/help/v3.9/module/FindDoxygen.html)。

# 使用 Sphinx 构建文档

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-12/recipe-02`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-12/recipe-02)找到，并包含一个 C++示例。该食谱适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

Sphinx 是一个 Python 程序，也是一个非常流行的文档系统（[`www.sphinx-doc.org`](http://www.sphinx-doc.org)）。当与 Python 项目一起使用时，它可以解析源文件中的所谓 docstrings，并自动为函数和类生成文档页面。然而，Sphinx 不仅限于 Python，还可以解析 reStructuredText、Markdown 纯文本文件，并生成 HTML、ePUB 或 PDF 文档。与在线 Read the Docs 服务（[`readthedocs.org`](https://readthedocs.org)）结合使用，它提供了一种快速开始编写和部署文档的绝佳方式。本食谱将向您展示如何使用 CMake 基于 Sphinx 构建文档。

# 准备工作

我们希望构建一个简单的网站来记录我们的消息库。源树现在看起来如下：

```cpp
.
├── cmake
│   ├── FindSphinx.cmake
│   └── UseSphinxDoc.cmake
├── CMakeLists.txt
├── docs
│   ├── conf.py.in
│   └── index.rst
└── src
    ├── CMakeLists.txt
    ├── hello-world.cpp
    ├── Message.cpp
    └── Message.hpp
```

我们在`cmake`子目录中有一些自定义模块，`docs`子目录包含我们网站的主页，以纯文本 reStructuredText 格式，`index.rst`，以及一个 Python 模板文件，`conf.py.in`，用于 Sphinx 的设置。此文件可以使用 Sphinx 安装的一部分`sphinx-quickstart`实用程序自动生成。

# 如何操作

与之前的食谱相比，我们将修改根`CMakeLists.txt`文件，并实现一个函数（`add_sphinx_doc`）：

1.  在将`cmake`文件夹附加到`CMAKE_MODULE_PATH`之后，我们如下包含`UseSphinxDoc.cmake`自定义模块：

```cpp
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

include(UseSphinxDoc)
```

1.  `UseSphinxDoc.cmake`模块定义了`add_sphinx_doc`函数。我们使用关键字参数调用此函数，以设置我们的 Sphinx 文档构建。自定义文档目标将被称为`docs`：

```cpp
add_sphinx_doc(
  SOURCE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/docs
  BUILD_DIR
    ${CMAKE_CURRENT_BINARY_DIR}/_build
  CACHE_DIR
    ${CMAKE_CURRENT_BINARY_DIR}/_doctrees
  HTML_DIR
    ${CMAKE_CURRENT_BINARY_DIR}/sphinx_html
  CONF_FILE
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/conf.py.in
  TARGET_NAME
    docs
  COMMENT
    "HTML documentation"
  )
```

`UseSphinxDoc.cmake`模块遵循我们在前一个食谱中使用的相同“显式优于隐式”模式：

1.  我们需要找到 Python 解释器和`Sphinx`可执行文件，如下所示：

```cpp
find_package(PythonInterp REQUIRED)
find_package(Sphinx REQUIRED)
```

1.  然后我们定义带有单值关键字参数的`add_sphinx_doc`函数。这些参数由`cmake_parse_arguments`命令解析：

```cpp
function(add_sphinx_doc)
  set(options)
  set(oneValueArgs
    SOURCE_DIR
    BUILD_DIR
    CACHE_DIR
    HTML_DIR
    CONF_FILE
    TARGET_NAME
    COMMENT
    )
  set(multiValueArgs)

  cmake_parse_arguments(SPHINX_DOC
    "${options}"
    "${oneValueArgs}"
    "${multiValueArgs}"
    ${ARGN}
    )

  # ...

endfunction()
```

1.  模板文件`conf.py.in`，作为`CONF_FILE`关键字参数传递，配置为在`SPHINX_DOC_BUILD_DIR`中的`conf.py`：

```cpp
configure_file(
  ${SPHINX_DOC_CONF_FILE}
  ${SPHINX_DOC_BUILD_DIR}/conf.py
  @ONLY
  )
```

1.  我们添加了一个名为`SPHINX_DOC_TARGET_NAME`的自定义目标，以协调使用 Sphinx 构建文档：

```cpp
add_custom_target(${SPHINX_DOC_TARGET_NAME}
  COMMAND
    ${SPHINX_EXECUTABLE}
       -q
       -b html
       -c ${SPHINX_DOC_BUILD_DIR}
       -d ${SPHINX_DOC_CACHE_DIR}
       ${SPHINX_DOC_SOURCE_DIR}
       ${SPHINX_DOC_HTML_DIR}
  COMMENT
    "Building ${SPHINX_DOC_COMMENT} with Sphinx"
  VERBATIM
  )
```

1.  最后，我们向用户打印出一条状态消息：

```cpp
message(STATUS "Added ${SPHINX_DOC_TARGET_NAME} [Sphinx] target to build documentation")
```

1.  我们配置项目并构建`docs`目标：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build . --target docs
```

这将在构建树的`SPHINX_DOC_HTML_DIR`子目录中生成 HTML 文档。再次，您可以使用您喜欢的浏览器打开`index.html`并查看闪亮（但仍然稀疏）的文档：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/b3ae5f45-8d88-4aec-83e4-c44e4b8890c3.png)

# 它是如何工作的

再次，我们利用了`add_custom_target`的强大功能，向我们的构建系统添加了一个任意构建目标。在这种情况下，文档将使用 Sphinx 构建。由于 Sphinx 是一个可以与其他 Python 模块扩展的 Python 程序，因此`docs`目标将依赖于 Python 解释器。我们确保通过使用`find_package`来满足依赖关系。请注意，`FindSphinx.cmake`模块还不是标准的 CMake 模块；它的副本包含在项目源代码的`cmake`子目录下。

# 结合 Doxygen 和 Sphinx

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-12/recipe-03`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-12/recipe-03)找到，并包含一个 C++示例。该食谱适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

我们有一个 C++项目，因此，Doxygen 是生成源代码文档的理想选择。然而，我们也希望发布面向用户的文档，例如解释我们的设计选择。我们更愿意使用 Sphinx 来实现这一点，因为生成的 HTML 也可以在移动设备上工作，而且我们可以将文档部署到 Read the Docs（[`readthedocs.org`](https://readthedocs.org)）。本食谱将说明如何使用 Breathe 插件（[`breathe.readthedocs.io`](https://breathe.readthedocs.io)）来桥接 Doxygen 和 Sphinx。

# 准备就绪

本食谱的源代码树与前两个食谱类似：

```cpp
.
├── cmake
│   ├── FindPythonModule.cmake
│   ├── FindSphinx.cmake
│   └── UseBreathe.cmake
├── CMakeLists.txt
├── docs
│   ├── code-reference
│   │   ├── classes-and-functions.rst
│   │   └── message.rst
│   ├── conf.py.in
│   ├── Doxyfile.in
│   └── index.rst
└── src
    ├── CMakeLists.txt
    ├── hello-world.cpp
    ├── Message.cpp
    └── Message.hpp
```

现在，`docs`子目录中包含了`Doxyfile.in`和`conf.py.in`模板文件，分别用于 Doxygen 和 Sphinx 的设置。此外，我们还有一个`code-reference`子目录。

紧随`code-reference`的文件包含 Breathe 指令，以在 Sphinx 中包含 Doxygen 生成的文档：

```cpp
Messaging classes
=================

Message
-------
.. doxygenclass:: Message
   :project: recipe-03
   :members:
   :protected-members:
   :private-members:
```

这将输出`Message`类的文档。

# 如何操作

`src`目录中的`CMakeLists.txt`文件未更改。根目录中的`CMakeLists.txt`文件的唯一更改如下：

1.  我们包含`UseBreathe.cmake`自定义模块：

```cpp
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

include(UseBreathe)
```

1.  我们调用了`add_breathe_doc`函数。该函数在自定义模块中定义，并接受关键字参数来设置结合 Doxygen 和 Sphinx 的构建：

```cpp
add_breathe_doc(
  SOURCE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/docs
  BUILD_DIR
    ${CMAKE_CURRENT_BINARY_DIR}/_build
  CACHE_DIR
    ${CMAKE_CURRENT_BINARY_DIR}/_doctrees
  HTML_DIR
    ${CMAKE_CURRENT_BINARY_DIR}/html
  DOXY_FILE
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in
  CONF_FILE
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/conf.py.in
  TARGET_NAME
    docs
  COMMENT
    "HTML documentation"
  )
```

让我们检查`UseBreatheDoc.cmake`模块。这遵循了我们之前两个配方中描述的明确优于隐式的相同模式。该模块详细描述如下：

1.  文档生成依赖于 Doxygen：

```cpp
find_package(Doxygen REQUIRED)
find_package(Perl REQUIRED)
```

1.  我们还依赖于 Python 解释器和`Sphinx`：

```cpp
find_package(PythonInterp REQUIRED)
find_package(Sphinx REQUIRED)
```

1.  此外，我们还必须找到`breathe` Python 模块。我们使用`FindPythonModule.cmake`模块：

```cpp
include(FindPythonModule)
find_python_module(breathe REQUIRED)
```

1.  我们定义了`add_breathe_doc`函数。该函数有一个单值关键字参数，我们将使用`cmake_parse_arguments`命令对其进行解析：

```cpp
function(add_breathe_doc)
  set(options)
  set(oneValueArgs
    SOURCE_DIR
    BUILD_DIR
    CACHE_DIR
    HTML_DIR
    DOXY_FILE
    CONF_FILE
    TARGET_NAME
    COMMENT
    )
  set(multiValueArgs)

  cmake_parse_arguments(BREATHE_DOC
    "${options}"
    "${oneValueArgs}"
    "${multiValueArgs}"
    ${ARGN}
    )

  # ...

endfunction()
```

1.  `BREATHE_DOC_CONF_FILE`模板文件用于 Sphinx，配置为`conf.py`在`BREATHE_DOC_BUILD_DIR`中：

```cpp
configure_file(
  ${BREATHE_DOC_CONF_FILE}
  ${BREATHE_DOC_BUILD_DIR}/conf.py
  @ONLY
  )
```

1.  相应地，Doxygen 的`BREATHE_DOC_DOXY_FILE`模板文件配置为`Doxyfile`在`BREATHE_DOC_BUILD_DIR`中：

```cpp
configure_file(
  ${BREATHE_DOC_DOXY_FILE}
  ${BREATHE_DOC_BUILD_DIR}/Doxyfile
  @ONLY
  )
```

1.  然后我们添加了自定义目标`BREATHE_DOC_TARGET_NAME`。请注意，只运行了 Sphinx；对 Doxygen 的必要调用在`BREATHE_DOC_SPHINX_FILE`内部发生：

```cpp
add_custom_target(${BREATHE_DOC_TARGET_NAME}
  COMMAND
    ${SPHINX_EXECUTABLE}
       -q
       -b html
       -c ${BREATHE_DOC_BUILD_DIR}
       -d ${BREATHE_DOC_CACHE_DIR}
       ${BREATHE_DOC_SOURCE_DIR}
       ${BREATHE_DOC_HTML_DIR}
  COMMENT
    "Building ${BREATHE_DOC_TARGET_NAME} documentation with Breathe, Sphinx and Doxygen"
  VERBATIM
  )
```

1.  最后，向用户打印一条状态消息：

```cpp
message(STATUS "Added ${BREATHE_DOC_TARGET_NAME} [Breathe+Sphinx+Doxygen] target to build documentation")
```

1.  配置完成后，我们可以像往常一样构建文档：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build . --target docs
```

文档将可在构建树的`BREATHE_DOC_HTML_DIR`子目录中找到。启动浏览器打开`index.html`文件后，您可以导航到`Message`类的文档：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/0f7ce5f6-86c1-47c7-aeb6-9f045c12b203.png)

# 工作原理

您会注意到，尽管在声明自定义`BREATHE_DOC_TARGET_NAME`目标时只给出了对 Sphinx 的调用，但 Doxygen 和 Sphinx 都运行了。这是由于 Sphinx 的`conf.py`文件中定义的以下设置：

```cpp
def run_doxygen(folder):
    """Run the doxygen make command in the designated folder"""

    try:
        retcode = subprocess.call("cd {}; doxygen".format(folder), shell=True)
        if retcode < 0:
            sys.stderr.write(
                "doxygen terminated by signal {}".format(-retcode))
    except OSError as e:
        sys.stderr.write("doxygen execution failed: {}".format(e))

def setup(app):
    run_doxygen('@BREATHE_DOC_BUILD_DIR@')
```

Doxygen 将生成 XML 输出，Breathe 插件将能够以与所选 Sphinx 文档样式一致的形式呈现这些输出。


# 第十四章：替代生成器和跨编译

在本章中，我们将介绍以下内容：

+   在 Visual Studio 中构建 CMake 项目

+   跨编译一个 hello world 示例

+   使用 OpenMP 并行化跨编译 Windows 二进制文件

# 引言

CMake 本身并不构建可执行文件和库。相反，CMake 配置一个项目并*生成*由另一个构建工具或框架用来构建项目的文件。在 GNU/Linux 和 macOS 上，CMake 通常生成 Unix Makefiles，但存在许多替代方案。在 Windows 上，这些通常是 Visual Studio 项目文件或 MinGW 或 MSYS Makefiles。CMake 包含了一系列针对本地命令行构建工具或集成开发环境（IDEs）的生成器。您可以在以下链接了解更多信息：[`cmake.org/cmake/help/latest/manual/cmake-generators.7.html`](https://cmake.org/cmake/help/latest/manual/cmake-generators.7.html)。

这些生成器可以使用`cmake -G`来选择，例如：

```cpp
$ cmake -G "Visual Studio 15 2017"
```

并非所有生成器在每个平台上都可用，根据 CMake 运行的平台，通常只有一部分可用。要查看当前平台上所有可用的生成器列表，请输入以下内容：

```cpp
$ cmake -G
```

在本章中，我们不会遍历所有可用的生成器，但我们注意到本书中的大多数配方都使用`Unix Makefiles`、`MSYS Makefiles`、`Ninja`和`Visual Studio 15 2017`生成器进行了测试。在本章中，我们将专注于在 Windows 平台上进行开发。我们将演示如何直接使用 Visual Studio 15 2017 构建 CMake 项目，而不使用命令行。我们还将讨论如何在 Linux 或 macOS 系统上跨编译 Windows 可执行文件。

# 使用 Visual Studio 2017 构建 CMake 项目

本配方的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-13/recipe-01`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-13/recipe-01)找到，并包含一个 C++示例。该配方适用于 CMake 版本 3.5（及以上），并在 Windows 上进行了测试。

虽然早期的 Visual Studio 版本要求开发者在不同的窗口中编辑源代码和运行 CMake 命令，但 Visual Studio 2017 引入了对 CMake 项目的内置支持（[`aka.ms/cmake`](https://aka.ms/cmake)），允许整个编码、配置、构建和测试工作流程在同一个 IDE 中发生。在本节中，我们将测试这一点，并直接使用 Visual Studio 2017 构建一个简单的“hello world”CMake 示例项目，而不求助于命令行。

# 准备工作

首先，我们将使用 Windows 平台，下载并安装 Visual Studio Community 2017（[`www.visualstudio.com/downloads/`](https://www.visualstudio.com/downloads/)）。在撰写本文时，该版本可免费使用 30 天试用期。我们将遵循的步骤也在此视频中得到了很好的解释：[`www.youtube.com/watch?v=_lKxJjV8r3Y`](https://www.youtube.com/watch?v=_lKxJjV8r3Y)。

在运行安装程序时，请确保在左侧面板中选择“使用 C++的桌面开发”，并验证“Visual C++工具用于 CMake”在右侧的摘要面板中被选中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/3e7b747b-5049-444e-a5ce-f261aa133fca.png)

在 Visual Studio 2017 15.4 中，您还可以为 Linux 平台编译代码。为此，请在其他工具集中选择“Linux 开发与 C++”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/51a1afdc-95b9-49b2-93f8-e8e1f766d757.png)

启用此选项后，您可以从 Visual Studio 内部为 Windows 和 Linux 机器编译代码，前提是您已配置了对 Linux 服务器的访问。但是，我们不会在本章中演示这种方法。

在本节中，我们将在 Windows 上构建 Windows 二进制文件，我们的目标是配置和构建以下示例代码（`hello-world.cpp`）：

```cpp
#include <cstdlib>
#include <iostream>
#include <string>

const std::string cmake_system_name = SYSTEM_NAME;

int main() {
  std::cout << "Hello from " << cmake_system_name << std::endl;

  return EXIT_SUCCESS;
}
```

# 操作方法

要创建相应的源代码，请按照以下步骤操作：

1.  创建一个目录并将`hello-world.cpp`文件放入新创建的目录中。

1.  在此目录中，创建一个`CMakeLists.txt`文件，其中包含以下内容：

```cpp
# set minimum cmake version
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# project name and language
project(recipe-01 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})

# define executable and its source file
add_executable(hello-world hello-world.cpp)

# we will print the system name in the code
target_compile_definitions(hello-world
  PUBLIC
    "SYSTEM_NAME=\"${CMAKE_SYSTEM_NAME}\""
  )

install(
  TARGETS
    hello-world
  DESTINATION
    ${CMAKE_INSTALL_BINDIR}
  )
```

1.  打开 Visual Studio 2017，然后导航到包含源文件和`CMakeLists.txt`的新建文件夹，通过以下方式：文件 | 打开 | 文件夹。

1.  一旦文件夹打开，请注意 CMake 配置步骤是如何自动运行的（底部面板）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/455fb1b1-7946-474e-abb3-c8c2c157c7df.png)

1.  现在，我们可以右键单击`CMakeLists.txt`（右侧面板）并选择“构建”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/e119f318-5f04-4643-a154-f04eeee87cd9.png)

1.  这构建了项目（请参见底部面板的输出）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/093bbdb8-c08f-4a58-bf51-983446b33482.png)

1.  这样就成功编译了可执行文件。在下一个子节中，我们将学习如何定位可执行文件，并可能更改构建和安装路径。

# 工作原理

我们已经看到，Visual Studio 2017 很好地与 CMake 接口，并且我们已经能够从 IDE 内部配置和构建代码。除了构建步骤，我们还可以运行安装或测试步骤。这些可以通过右键单击`CMakeLists.txt`（右侧面板）来访问。

然而，配置步骤是自动运行的，我们可能更倾向于修改配置选项。我们还希望知道实际的构建和安装路径，以便我们可以测试我们的可执行文件。为此，我们可以选择 CMake | 更改 CMake 设置，然后我们到达以下屏幕：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/b40fbce2-b515-4f7d-9e40-e36da1b31157.png)

在左上角的面板中，我们现在可以检查和修改生成器（在本例中为 Ninja）、设置、参数以及路径。构建路径在上面的截图中突出显示。设置被分组到构建类型（`x86-Debug`、`x86-Release`等）中，我们可以在顶部面板栏的中间在这些构建类型之间切换。

现在我们知道实际的构建路径，我们可以测试编译的可执行文件：

```cpp
$ ./hello-world.exe

Hello from Windows
```

当然，构建和安装路径可以进行调整。

# 另请参阅

+   Visual Studio 中的 CMake 支持：[`aka.ms/cmake`](https://aka.ms/cmake)

+   使用 CMake 进行 Linux 开发的 Visual C++：[`blogs.msdn.microsoft.com/vcblog/2017/08/25/visual-c-for-linux-development-with-cmake/`](https://blogs.msdn.microsoft.com/vcblog/2017/08/25/visual-c-for-linux-development-with-cmake/)

+   Visual Studio 的官方文档：[`www.visualstudio.com/vs/features/ide/`](https://www.visualstudio.com/vs/features/ide/)

# 交叉编译一个“Hello World”示例

本配方的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-13/recipe-01`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-13/recipe-01)找到，并包含一个 C++示例。本配方适用于 CMake 版本 3.5（及以上），并在 GNU/Linux 和 macOS 上进行了测试。

在本配方中，我们将重用上一个配方中的“Hello World”示例，并从 Linux 或 macOS 交叉编译到 Windows。换句话说，我们将在 Linux 或 macOS 上配置和编译代码，并获得一个 Windows 平台的可执行文件。

# 准备工作

我们从一个简单的“Hello World”示例开始（`hello-world.cpp`）：

```cpp
#include <cstdlib>
#include <iostream>
#include <string>

const std::string cmake_system_name = SYSTEM_NAME;

int main() {
  std::cout << "Hello from " << cmake_system_name << std::endl;

  return EXIT_SUCCESS;
}
```

我们还将使用上一个配方中未更改的`CMakeLists.txt`：

```cpp
# set minimum cmake version
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# project name and language
project(recipe-01 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})

# define executable and its source file
add_executable(hello-world hello-world.cpp)

# we will print the system name in the code
target_compile_definitions(hello-world
  PUBLIC
    "SYSTEM_NAME=\"${CMAKE_SYSTEM_NAME}\""
  )

install(
  TARGETS
    hello-world
  DESTINATION
    ${CMAKE_INSTALL_BINDIR}
  )
```

为了交叉编译源代码，我们需要安装一个 C++的交叉编译器，以及可选的 C 和 Fortran 编译器。一个选项是使用打包的 MinGW 编译器。作为打包的交叉编译器的替代方案，我们还可以使用 MXE（M 交叉环境）从源代码构建一套交叉编译器：[`mxe.cc`](http://mxe.cc)。

# 如何操作

我们将按照以下步骤在这个交叉编译的“Hello World”示例中创建三个文件：

1.  创建一个目录，其中包含`hello-world.cpp`和前面列出的`CMakeLists.txt`。

1.  创建一个`toolchain.cmake`文件，其中包含以下内容：

```cpp
# the name of the target operating system
set(CMAKE_SYSTEM_NAME Windows)

# which compilers to use
set(CMAKE_CXX_COMPILER i686-w64-mingw32-g++)

# adjust the default behaviour of the find commands:
# search headers and libraries in the target environment
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
# search programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
```

1.  将`CMAKE_CXX_COMPILER`调整为相应的编译器（路径）。

1.  然后，通过指向`CMAKE_TOOLCHAIN_FILE`到工具链文件来配置代码（在本例中，使用了从源代码构建的 MXE 编译器）：

```cpp
$ mkdir -p build
$ cd build
$ cmake -D CMAKE_TOOLCHAIN_FILE=toolchain.cmake .. 
-- The CXX compiler identification is GNU 5.4.0
-- Check for working CXX compiler: /home/user/mxe/usr/bin/i686-w64-mingw32.static-g++
-- Check for working CXX compiler: /home/user/mxe/usr/bin/i686-w64-mingw32.static-g++ -- works
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Configuring done
-- Generating done
-- Build files have been written to: /home/user/cmake-recipes/chapter-13/recipe-01/cxx-example/build
```

1.  现在，让我们构建可执行文件：

```cpp
$ cmake --build .

Scanning dependencies of target hello-world
[ 50%] Building CXX object CMakeFiles/hello-world.dir/hello-world.cpp.obj
[100%] Linking CXX executable bin/hello-world.exe
[100%] Built target hello-world
```

1.  请注意，我们在 Linux 上获得了`hello-world.exe`。将二进制文件复制到 Windows 计算机。

1.  在 Windows 计算机上，我们可以观察到以下输出：

```cpp
Hello from Windows
```

1.  如您所见，该二进制文件在 Windows 上运行！

# 它是如何工作的

由于我们在与目标环境（Windows）不同的宿主环境（在这种情况下，GNU/Linux 或 macOS）上配置和构建代码，我们需要向 CMake 提供有关目标环境的信息，我们已经在`toolchain.cmake`文件中对其进行了编码（[`cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html#cross-compiling`](https://cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html#cross-compiling)）。

首先，我们提供目标操作系统的名称：

```cpp
set(CMAKE_SYSTEM_NAME Windows)
```

然后，我们指定编译器，例如：

```cpp
set(CMAKE_C_COMPILER i686-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER i686-w64-mingw32-g++)
set(CMAKE_Fortran_COMPILER i686-w64-mingw32-gfortran)
```

在这个简单的例子中，我们不需要检测任何库或头文件，但如果需要，我们将使用以下方式指定根路径：

```cpp
set(CMAKE_FIND_ROOT_PATH /path/to/target/environment)
```

目标环境可以是例如由 MXE 安装提供的环境。

最后，我们调整 find 命令的默认行为。我们指示 CMake 在目标环境中搜索头文件和库：

```cpp
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
```

并在宿主环境中搜索程序：

```cpp
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
```

# 另请参阅

有关各种选项的更详细讨论，请参阅[`cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html#cross-compiling`](https://cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html#cross-compiling)。

# 使用 OpenMP 并行化交叉编译 Windows 二进制文件

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-13/recipe-02`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-13/recipe-02)找到，并包含 C++和 Fortran 示例。本食谱适用于 CMake 版本 3.9（及以上），并在 GNU/Linux 上进行了测试。

在本食谱中，我们将应用在前一个食谱中学到的知识，尽管是针对一个更有趣和更现实的例子：我们将交叉编译一个使用 OpenMP 并行化的 Windows 二进制文件。

# 准备工作

我们将使用第三章，*检测外部库和程序*，食谱 5，*检测 OpenMP 并行环境*中的未修改源代码。示例代码计算所有自然数到*N*的总和（`example.cpp`）：

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

`CMakeLists.txt`文件与第三章，*检测外部库和程序*，食谱 5，*检测 OpenMP 并行环境*相比，基本上没有变化，除了增加了一个安装目标：

```cpp
# set minimum cmake version
cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

# project name and language
project(recipe-02 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})

find_package(OpenMP REQUIRED)

add_executable(example example.cpp)

target_link_libraries(example
  PUBLIC
    OpenMP::OpenMP_CXX
  )

install(
  TARGETS
    example
  DESTINATION
    ${CMAKE_INSTALL_BINDIR}
  )
```

# 如何操作

通过以下步骤，我们将能够交叉编译一个使用 OpenMP 并行化的 Windows 可执行文件：

1.  创建一个目录，其中包含之前列出的`example.cpp`和`CMakeLists.txt`。

1.  我们将使用与前一个食谱相同的`toolchain.cmake`：

```cpp
# the name of the target operating system
set(CMAKE_SYSTEM_NAME Windows)

# which compilers to use
set(CMAKE_CXX_COMPILER i686-w64-mingw32-g++)

# adjust the default behaviour of the find commands:
# search headers and libraries in the target environment
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
# search programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
```

1.  将`CMAKE_CXX_COMPILER`调整为相应的编译器（路径）。

1.  然后，通过指向`CMAKE_TOOLCHAIN_FILE`到工具链文件来配置代码（在本例中，使用了从源代码构建的 MXE 编译器）：

```cpp
$ mkdir -p build
$ cd build
$ cmake -D CMAKE_TOOLCHAIN_FILE=toolchain.cmake .. 
-- The CXX compiler identification is GNU 5.4.0
-- Check for working CXX compiler: /home/user/mxe/usr/bin/i686-w64-mingw32.static-g++
-- Check for working CXX compiler: /home/user/mxe/usr/bin/i686-w64-mingw32.static-g++ -- works
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Found OpenMP_CXX: -fopenmp (found version "4.0")
-- Found OpenMP: TRUE (found version "4.0")
-- Configuring done
-- Generating done
-- Build files have been written to: /home/user/cmake-recipes/chapter-13/recipe-02/cxx-example/build
```

1.  现在，让我们构建可执行文件：

```cpp
$ cmake --build .

Scanning dependencies of target example
[ 50%] Building CXX object CMakeFiles/example.dir/example.cpp.obj
[100%] Linking CXX executable bin/example.exe
[100%] Built target example
```

1.  将二进制文件`example.exe`复制到 Windows 计算机。

1.  在 Windows 计算机上，我们可以看到以下示例输出：

```cpp
$ set OMP_NUM_THREADS=1
$ example.exe 1000000000

number of available processors: 2
number of threads: 1
we will form sum of numbers from 1 to 1000000000
sum: 500000000500000000
elapsed wall clock time: 2.641 seconds

$ set OMP_NUM_THREADS=2
$ example.exe 1000000000

number of available processors: 2
number of threads: 2
we will form sum of numbers from 1 to 1000000000
sum: 500000000500000000
elapsed wall clock time: 1.328 seconds
```

1.  正如我们所见，二进制文件在 Windows 上运行，并且我们可以观察到由于 OpenMP 并行化带来的速度提升！

# 它是如何工作的

我们已成功使用简单的工具链进行交叉编译，在 Windows 平台上构建了用于并行执行的可执行文件。我们能够通过设置`OMP_NUM_THREADS`来指定 OpenMP 线程的数量。从 1 个线程增加到 2 个线程，我们观察到运行时间从 2.6 秒减少到 1.3 秒。有关工具链文件的讨论，请参阅之前的配方。

# 还有更多

可以为一组目标平台进行交叉编译，例如 Android。有关示例，我们请读者参考[`cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html`](https://cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html)。


# 第十五章：测试仪表板

在本章中，我们将介绍以下内容：

+   将测试部署到 CDash 仪表板

+   向 CDash 仪表板报告测试覆盖率

+   使用 AddressSanitizer 并向 CDash 报告内存缺陷

+   使用 ThreadSanitizer 并向 CDash 报告数据竞争

# 引言

CDash 是一个 Web 服务，用于聚合 CTest 在测试运行、夜间测试或在持续集成设置中报告的测试结果。向仪表板报告就是我们所说的**CDash 时间**，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/fa7c19ee-f725-4708-b9bc-e12a2f761021.jpg)

在本章中，我们将演示如何向 CDash 仪表板报告测试结果。我们将讨论报告测试覆盖率的策略，以及使用 AddressSanitizer 和 ThreadSanitizer 等工具收集的内存缺陷和数据竞争。

向 CDash 报告有两种方式：通过构建的测试目标或使用 CTest 脚本。我们将在前两个食谱中演示测试目标的方法，并在最后两个食谱中使用 CTest 脚本的方法。

# 设置 CDash 仪表板

CDash 的安装需要一个带有 PHP 和 SSL 启用的 Web 服务器（Apache、NGINX 或 IIS），以及访问 MySQL 或 PostgreSQL 数据库服务器的权限。本书不详细讨论 CDash Web 服务的设置；我们建议读者参考其官方文档，网址为[`public.kitware.com/Wiki/CDash:Installation`](https://public.kitware.com/Wiki/CDash:Installation)。

安装 CDash 实例不是本章食谱的必要条件，因为 Kitware 提供了两个公共仪表板（[`my.cdash.org`](https://my.cdash.org)和[`open.cdash.org`](https://open.cdash.org)）。我们将在食谱中引用前者。

对于决定自行安装 CDash 实例的读者，我们建议使用 MySQL 后端，因为这似乎是[`my.cdash.org`](https://my.cdash.org)和[`open.cdash.org`](https://open.cdash.org)所使用的配置，并且社区对其进行了更充分的测试。

也可以使用 Docker 来部署 CDash 实例，而无需太多努力。目前，在 CDash 问题跟踪器上有一个关于官方镜像的请求，网址为[`github.com/Kitware/CDash/issues/562`](https://github.com/Kitware/CDash/issues/562)。

# 将测试部署到 CDash 仪表板

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-14/recipe-01`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-14/recipe-01)找到，并包含一个 C++示例。该食谱适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

在本食谱中，我们将扩展第 1 个食谱，即“创建一个简单的单元测试”，来自第四章，“创建和运行测试”，并将测试结果部署到[`my.cdash.org/index.php?project=cmake-cookbook`](https://my.cdash.org/index.php?project=cmake-cookbook)，这是我们在公共仪表板（[`my.cdash.org`](https://my.cdash.org)）上为本书创建的，由 Kitware 提供给社区。

# 准备工作

我们将从重用第 1 个食谱，即“创建一个简单的单元测试”，来自第四章，“创建和运行测试”的示例源代码开始，该示例对作为命令行参数给出的整数求和。示例由三个源文件组成：`main.cpp`、`sum_integers.cpp`和`sum_integers.hpp`。这些源文件保持不变。我们还将重用来自第四章，“创建和运行测试”的文件`test.cpp`，但将其重命名为`test_short.cpp`。我们将通过`test_long.cpp`扩展示例，其中包含以下代码：

```cpp
#include "sum_integers.hpp"

#include <numeric>
#include <vector>

int main() {
  // creates vector {1, 2, 3, ..., 999, 1000}
  std::vector<int> integers(1000);
  std::iota(integers.begin(), integers.end(), 1);

  if (sum_integers(integers) == 500500) {
    return 0;
  } else {
    return 1;
  }
}
```

然后，我们将这些文件组织成以下文件树：

```cpp
.
├── CMakeLists.txt
├── CTestConfig.cmake
├── src
│   ├── CMakeLists.txt
│   ├── main.cpp
│   ├── sum_integers.cpp
│   └── sum_integers.hpp
└── tests
    ├── CMakeLists.txt
    ├── test_long.cpp
    └── test_short.cpp
```

# 如何做到这一点

现在，我们将描述如何配置、构建、测试，最后，将我们示例项目的测试结果提交到仪表板：

1.  源目标在`src/CMakeLists.txt`中定义，如下所示：

```cpp
# example library
add_library(sum_integers "")

target_sources(sum_integers
  PRIVATE
    sum_integers.cpp
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/sum_integers.hpp
  )

target_include_directories(sum_integers
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
  )

# main code
add_executable(sum_up main.cpp)

target_link_libraries(sum_up sum_integers)
```

1.  测试在`tests/CMakeLists.txt`中定义：

```cpp
add_executable(test_short test_short.cpp)
target_link_libraries(test_short sum_integers)

add_executable(test_long test_long.cpp)
target_link_libraries(test_long sum_integers)

add_test(
  NAME
    test_short
  COMMAND
    $<TARGET_FILE:test_short>
  )

add_test(
  NAME
    test_long
  COMMAND
    $<TARGET_FILE:test_long>
  )
```

1.  顶级`CMakeLists.txt`文件引用了前面两个文件，本食谱中的新元素是包含`include(CTest)`的行，它允许我们向 CDash 仪表板报告：

```cpp
# set minimum cmake version
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# project name and language
project(recipe-01 LANGUAGES CXX)

# require C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# process src/CMakeLists.txt
add_subdirectory(src)

enable_testing()

# allow to report to a cdash dashboard
include(CTest)

# process tests/CMakeLists.txt
add_subdirectory(tests)
```

1.  此外，我们在顶级`CMakeLists.txt`文件所在的同一目录中创建了文件`CTestConfig.cmake`。这个新文件包含以下行：

```cpp
set(CTEST_DROP_METHOD "http")
set(CTEST_DROP_SITE "my.cdash.org")
set(CTEST_DROP_LOCATION "/submit.php?project=cmake-cookbook")
set(CTEST_DROP_SITE_CDASH TRUE)
```

1.  我们现在准备配置并构建项目，如下所示：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build .
```

1.  在构建代码之后，我们可以运行测试集并将测试结果报告给仪表板：

```cpp
$ ctest --dashboard Experimental

 Site: larry
 Build name: Linux-c++
Create new tag: 20180408-1449 - Experimental
Configure project
 Each . represents 1024 bytes of output
 . Size of output: 0K
Build project
 Each symbol represents 1024 bytes of output.
 '!' represents an error and '*' a warning.
 . Size of output: 0K
 0 Compiler errors
 0 Compiler warnings
Test project /home/user/cmake-recipes/chapter-15/recipe-01/cxx-example/build
 Start 1: test_short
1/2 Test #1: test_short ....................... Passed 0.00 sec
 Start 2: test_long
2/2 Test #2: test_long ........................ Passed 0.00 sec

100% tests passed, 0 tests failed out of 2

Total Test time (real) = 0.01 sec
Performing coverage
 Cannot find any coverage files. Ignoring Coverage request.
Submit files (using http)
 Using HTTP submit method
 Drop site:http://my.cdash.org/submit.php?project=cmake-cookbook
 Uploaded: /home/user/cmake-recipes/chapter-14/recipe-01/cxx-example/build/Testing/20180408-1449/Build.xml
 Uploaded: /home/user/cmake-recipes/chapter-14/recipe-01/cxx-example/build/Testing/20180408-1449/Configure.xml
 Uploaded: /home/user/cmake-recipes/chapter-14/recipe-01/cxx-example/build/Testing/20180408-1449/Test.xml
 Submission successful
```

1.  最后，我们可以在浏览器中浏览测试结果（在本例中，测试结果被报告给[`my.cdash.org/index.php?project=cmake-cookbook`](https://my.cdash.org/index.php?project=cmake-cookbook))[:](https://my.cdash.org/index.php?project=cmake-cookbook))

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/c8d388dc-34e6-4a5f-8fa7-346970897f2f.png)

# 它是如何工作的

工作流程的高层次概览显示，CTest 运行测试并将结果记录在本地 XML 文件中。这些 XML 文件随后被发送到 CDash 服务器，在那里可以进行浏览和分析。通过点击前面截图中显示的“通过”下的 2，我们可以获得关于通过或失败的测试的更多细节（在本例中，没有失败的测试）。如后续截图所示，详细记录了运行测试的机器信息以及时间信息。同样，个别测试的输出可以在网上浏览。

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/3cb76099-2d97-4568-94d3-385789b08490.png)

CTest 支持三种不同的运行提交模式：实验性、夜间和连续性。我们使用了`ctest --dashboard Experimental`，因此测试结果出现在实验性下。实验模式适用于测试代码的当前状态，用于调试新的仪表板脚本（参见本章的第 3 和第 4 个食谱），或用于调试 CDash 服务器或项目。夜间模式将更新（或降级）代码到最接近最新夜间开始时间的仓库快照，这可以在`CTestConfig.cmake`中设置；它为接收频繁更新的项目中的所有夜间测试提供了一个定义良好的参考点。例如，可以将夜间开始时间设置为协调世界时午夜，如下所示：

```cpp
set(CTEST_NIGHTLY_START_TIME "00:00:00 UTC")
```

连续模式适用于持续集成工作流程，并将更新代码到最新版本。

使用单个命令即可完成构建、测试并提交到实验仪表板 - 即`cmake --build . --target Experimental`命令。

# 还有更多

在本食谱中，我们直接从测试目标部署到 CDash。也可以使用专门的 CTest 脚本，我们将在本章稍后的第 3 和第 4 个食谱中演示这种方法。

CDash 不仅允许您监控测试是否通过或失败，还允许您监控测试时间。您可以为测试时间配置边际：如果测试花费的时间超过分配的时间，它将被标记为失败。这对于基准测试很有用，可以自动检测在重构代码时测试时间性能下降的情况。

# 另请参见

有关 CDash 定义和配置设置的详细讨论，请参阅官方 CDash 文档，网址为[`public.kitware.com/Wiki/CDash:Documentation`](https://public.kitware.com/Wiki/CDash:Documentation)。

# 向 CDash 仪表板报告测试覆盖率

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-14/recipe-02`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-14/recipe-02)获取，并包含一个 C++示例。该食谱适用于 CMake 版本 3.5（及以上），并在 GNU/Linux、macOS 和 Windows 上进行了测试。

在本食谱中，我们将测量测试覆盖率并将其报告给 CDash 仪表板，以便我们能够逐行浏览测试覆盖率分析，以识别未测试或未使用的代码。

# 准备就绪

我们将在前一个食谱的源代码中添加一个微小的变化，在`src/sum_integers.cpp`中，我们将添加一个函数 - `sum_integers_unused`：

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

int sum_integers_unused(const std::vector<int> integers) {
  auto sum = 0;
  for (auto i : integers) {
    sum += i;
  }
  return sum;
}
```

我们的目标是使用测试覆盖率分析来检测这段未使用的代码，方法是使用 gcov（[`gcc.gnu.org/onlinedocs/gcc/Gcov.html`](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html)）。除了上述修改外，我们将使用前一个食谱的未修改源代码。

# 如何操作

通过以下步骤，我们将启用覆盖率分析并将结果上传到仪表板：

1.  顶级`CMakeLists.txt`和`tests/CMakeLists.txt`文件与之前的配方保持不变。

1.  我们将在`src/CMakeLists.txt`中扩展，添加一个选项以添加代码覆盖率的编译标志。此选项默认启用，如下所示：

```cpp
option(ENABLE_COVERAGE "Enable coverage" ON)

if(ENABLE_COVERAGE)
  if(CMAKE_CXX_COMPILER_ID MATCHES GNU)
    message(STATUS "Coverage analysis with gcov enabled") 
    target_compile_options(sum_integers
      PUBLIC
        -fprofile-arcs -ftest-coverage -g
      )
    target_link_libraries(sum_integers
      PUBLIC
        gcov
      )
  else()
    message(WARNING "Coverage not supported for this compiler")
  endif()
endif()
```

1.  然后，我们将配置、构建并部署到 CDash：

```cpp
$ mkdir -p build
$ cd build
$ cmake ..
$ cmake --build . --target Experimental
```

1.  这将产生与之前配方类似的输出，但最后一步将执行测试覆盖率分析：

```cpp
Performing coverage
   Processing coverage (each . represents one file):
    ...
   Accumulating results (each . represents one file):
    ...
        Covered LOC: 14
        Not covered LOC: 7
        Total LOC: 21
        Percentage Coverage: 66.67%
Submit files (using http)
   Using HTTP submit method
   Drop site:http://my.cdash.org/submit.php?project=cmake-cookbook
   Uploaded: /home/user/cmake-recipes/chapter-14/recipe-02/cxx-example/build/Testing/20180408-1530/Build.xml
   Uploaded: /home/user/cmake-recipes/chapter-14/recipe-02/cxx-example/build/Testing/20180408-1530/Configure.xml
   Uploaded: /home/user/cmake-recipes/chapter-14/recipe-02/cxx-example/build/Testing/20180408-1530/Coverage.xml
   Uploaded: /home/user/cmake-recipes/chapter-14/recipe-02/cxx-example/build/Testing/20180408-1530/CoverageLog-0.xml
   Uploaded: /home/user/cmake-recipes/chapter-14/recipe-02/cxx-example/build/Testing/20180408-1530/Test.xml
   Submission successful
```

1.  最后，我们可以在浏览器中验证测试结果（在本例中，测试结果报告给[`my.cdash.org/index.php?project=cmake-cookbook`](https://my.cdash.org/index.php?project=cmake-cookbook)）。

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/e22437a3-f9f6-443d-bd7f-491693d1e7bd.png)

# 工作原理

测试覆盖率分析以 66.67%的百分比进行总结。为了获得更深入的见解，我们可以点击该百分比，并获得两个子目录的覆盖率分析，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/3e4cef79-019f-463a-8842-d147e4218bdb.png)

通过浏览子目录链接，我们可以检查单个文件的测试覆盖率百分比，甚至可以浏览逐行的总结（例如，`src/sum_integers.cpp`）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/09b351b7-fae6-49fb-b13d-919aaa31175f.png)

绿色线条在运行测试套件时已被遍历，而红色线条则没有。通过这一点，我们不仅可以识别未使用/未测试的代码（使用`sum_integers_unused`函数），还可以看到每行代码被遍历的频率。例如，代码行`sum += i`已被访问 1,005 次（`test_short`期间 5 次，`test_long`期间 1,000 次）。测试覆盖率分析是自动化测试不可或缺的伴侣，CDash 为我们提供了一个在浏览器中浏览和图形化分析结果的界面。

# 另请参阅

如需进一步阅读，我们推荐以下博客文章，该文章讨论了 CDash 中的额外覆盖功能：[`blog.kitware.com/additional-coverage-features-in-cdash/`](https://blog.kitware.com/additional-coverage-features-in-cdash/)。

# 使用 AddressSanitizer 并将内存缺陷报告给 CDash

本配方的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-14/recipe-03`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-14/recipe-03)找到，包括一个 C++和一个 Fortran 示例。本配方适用于 CMake 版本 3.5（及更高版本），并在 GNU/Linux 和 macOS 上进行了测试。

AddressSanitizer（ASan）是 C++、C 和 Fortran 的内存错误检测器。它可以发现内存缺陷，如使用后释放、使用后返回、使用后作用域、缓冲区溢出、初始化顺序错误和内存泄漏（参见[`github.com/google/sanitizers/wiki/AddressSanitizer`](https://github.com/google/sanitizers/wiki/AddressSanitizer)）。AddressSanitizer 是 LLVM 的一部分，从版本 3.1 开始，也是 GCC 的一部分，从版本 4.8 开始。在本菜谱中，我们将在我们的代码中制造两个可能未在正常测试运行中检测到的错误。为了检测这些错误，我们将 CTest 与使用 AddressSanitizer 的动态分析相结合，并将缺陷报告给 CDash。

# 准备工作

在本例中，我们将使用两个源文件和两个测试，如下所示：

```cpp
.
├── CMakeLists.txt
├── CTestConfig.cmake
├── dashboard.cmake
├── src
│   ├── buggy.cpp
│   ├── buggy.hpp
│   └── CMakeLists.txt
└── tests
    ├── CMakeLists.txt
    ├── leaky.cpp
    └── use_after_free.cpp
```

文件`buggy.cpp`包含两个有问题的函数，如下所示：

```cpp
#include "buggy.hpp"

#include <iostream>

int function_leaky() {

  double *my_array = new double[1000];

  // do some work ...

  // we forget to deallocate the array
  // delete[] my_array;

  return 0;
}

int function_use_after_free() {

  double *another_array = new double[1000];

  // do some work ...

  // deallocate it, good!
  delete[] another_array;

  // however, we accidentally use the array
  // after it has been deallocated
  std::cout << "not sure what we get: " << another_array[123] << std::endl;

  return 0;
}
```

这些函数在相应的头文件（`buggy.hpp`）中公开：

```cpp
#pragma once

int function_leaky();
int function_use_after_free();
```

测试源码`leaky.cpp`验证`function_leaky`的返回码：

```cpp
#include "buggy.hpp"

int main() {
  int return_code = function_leaky();
  return return_code;
}
```

相应地，`use_after_free.cpp`检查`function_use_after_free`的返回值，如下所示：

```cpp
#include "buggy.hpp"

int main() {
  int return_code = function_use_after_free();
  return return_code;
}
```

# 如何操作

我们需要使用特定的标志编译我们的代码以利用 ASan。然后，我们将运行测试并将它们提交到仪表板。让我们看看如何做到这一点：

1.  有问题的库在`src/CMakeLists.txt`中定义：

```cpp
add_library(buggy "")

target_sources(buggy
  PRIVATE
    buggy.cpp
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/buggy.hpp
  )

target_include_directories(buggy
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
  )
```

1.  对于文件`src/CMakeLists.txt`，我们将添加一个选项和代码以使用 ASan 进行消毒：

```cpp
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)

if(ENABLE_ASAN)
  if(CMAKE_CXX_COMPILER_ID MATCHES GNU)
    message(STATUS "AddressSanitizer enabled")
    target_compile_options(buggy
      PUBLIC
        -g -O1 -fsanitize=address -fno-omit-frame-pointer
      )
    target_link_libraries(buggy
      PUBLIC
        asan
      )
  else()
    message(WARNING "AddressSanitizer not supported for this compiler")
  endif()
endif()
```

1.  两个测试在`tests/CMakeLists.txt`中紧凑地定义，使用`foreach`循环：

```cpp
foreach(_test IN ITEMS leaky use_after_free)
  add_executable(${_test} ${_test}.cpp)
  target_link_libraries(${_test} buggy)

  add_test(
    NAME
      ${_test}
    COMMAND
      $<TARGET_FILE:${_test}>
    )
endforeach()
```

1.  顶级`CMakeLists.txt`基本上与之前的菜谱保持不变：

```cpp
# set minimum cmake version
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# project name and language
project(recipe-03 LANGUAGES CXX)

# require C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# process src/CMakeLists.txt
add_subdirectory(src)

enable_testing()

# allow to report to a cdash dashboard
include(CTest)

# process tests/CMakeLists.txt
add_subdirectory(tests)
```

1.  同样，`CTestConfig.cmake`文件保持不变：

```cpp
set(CTEST_DROP_METHOD "http")
set(CTEST_DROP_SITE "my.cdash.org")
set(CTEST_DROP_LOCATION "/submit.php?project=cmake-cookbook")
set(CTEST_DROP_SITE_CDASH TRUE)
```

1.  在本菜谱中，我们将使用 CTest 脚本向 CDash 报告；为此，我们将创建一个文件，`dashboard.cmake`（与主`CMakeLists.txt`和`CTestConfig.cmake`在同一目录中），包含以下内容：

```cpp
set(CTEST_PROJECT_NAME "example")
cmake_host_system_information(RESULT _site QUERY HOSTNAME)
set(CTEST_SITE ${_site})
set(CTEST_BUILD_NAME "${CMAKE_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}")

set(CTEST_SOURCE_DIRECTORY "${CTEST_SCRIPT_DIRECTORY}")
set(CTEST_BINARY_DIRECTORY "${CTEST_SCRIPT_DIRECTORY}/build")

include(ProcessorCount)
ProcessorCount(N)
if(NOT N EQUAL 0)
  set(CTEST_BUILD_FLAGS -j${N})
  set(ctest_test_args ${ctest_test_args} PARALLEL_LEVEL ${N})
endif()

ctest_start(Experimental)

ctest_configure(
  OPTIONS
    -DENABLE_ASAN:BOOL=ON
  )

ctest_build()
ctest_test()

set(CTEST_MEMORYCHECK_TYPE "AddressSanitizer")
ctest_memcheck()

ctest_submit()
```

1.  我们将直接执行`dashboard.cmake`脚本。请注意我们如何使用`CTEST_CMAKE_GENERATOR`选项传递要使用的生成器，如下所示：

```cpp
$ ctest -S dashboard.cmake -D CTEST_CMAKE_GENERATOR="Unix Makefiles"

   Each . represents 1024 bytes of output
    . Size of output: 0K
   Each symbol represents 1024 bytes of output.
   '!' represents an error and '*' a warning.
    . Size of output: 1K
```

1.  结果将出现在 CDash 站点上，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/c1e9c27b-1250-42b4-ad1a-1e9afa699d37.png)

# 工作原理

在本菜谱中，我们成功地将内存错误报告到了仪表板的动态分析部分。我们可以通过浏览缺陷（在缺陷计数下）获得更深入的见解：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/efcbb7fd-4cb6-4843-9b32-6904c5d15419.png)

通过点击各个链接，可以浏览完整输出。

请注意，也可以在本地生成 AddressSanitizer 报告。在本例中，我们需要设置`ENABLE_ASAN`，如下所示：

```cpp
$ mkdir -p build
$ cd build
$ cmake -DENABLE_ASAN=ON ..
$ cmake --build .
$ cmake --build . --target test

    Start 1: leaky
1/2 Test #1: leaky ............................***Failed 0.07 sec
    Start 2: use_after_free
2/2 Test #2: use_after_free ...................***Failed 0.04 sec

0% tests passed, 2 tests failed out of 2
```

直接运行`leaky`测试可执行文件产生以下结果：

```cpp
$ ./build/tests/leaky

=================================================================
==18536==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 8000 byte(s) in 1 object(s) allocated from:
    #0 0x7ff984da1669 in operator new[](unsigned long) /build/gcc/src/gcc/libsanitizer/asan/asan_new_delete.cc:82
    #1 0x564925c93fd2 in function_leaky() /home/user/cmake-recipes/chapter-14/recipe-03/cxx-example/src/buggy.cpp:7
    #2 0x564925c93fb2 in main /home/user/cmake-recipes/chapter-14/recipe-03/cxx-example/tests/leaky.cpp:4
    #3 0x7ff98403df49 in __libc_start_main (/usr/lib/libc.so.6+0x20f49)

SUMMARY: AddressSanitizer: 8000 byte(s) leaked in 1 allocation(s).
```

相应地，我们可以通过直接运行`use_after_free`可执行文件来获得详细的输出，如下所示：

```cpp
$ ./build/tests/use_after_free

=================================================================
==18571==ERROR: AddressSanitizer: heap-use-after-free on address 0x6250000004d8 at pc 0x557ffa8b0102 bp 0x7ffe8c560200 sp 0x7ffe8c5601f0
READ of size 8 at 0x6250000004d8 thread T0
 #0 0x557ffa8b0101 in function_use_after_free() /home/user/cmake-recipes/chapter-14/recipe-03/cxx-example/src/buggy.cpp:28
 #1 0x557ffa8affb2 in main /home/user/cmake-recipes/chapter-14/recipe-03/cxx-example/tests/use_after_free.cpp:4
 #2 0x7ff1d6088f49 in __libc_start_main (/usr/lib/libc.so.6+0x20f49)
 #3 0x557ffa8afec9 in _start (/home/user/cmake-recipes/chapter-14/recipe-03/cxx-example/build/tests/use_after_free+0xec9)

0x6250000004d8 is located 984 bytes inside of 8000-byte region 0x625000000100,0x625000002040)
freed by thread T0 here:
 #0 0x7ff1d6ded5a9 in operator delete[ /build/gcc/src/gcc/libsanitizer/asan/asan_new_delete.cc:128
 #1 0x557ffa8afffa in function_use_after_free() /home/user/cmake-recipes/chapter-14/recipe-03/cxx-example/src/buggy.cpp:24
 #2 0x557ffa8affb2 in main /home/user/cmake-recipes/chapter-14/recipe-03/cxx-example/tests/use_after_free.cpp:4
 #3 0x7ff1d6088f49 in __libc_start_main (/usr/lib/libc.so.6+0x20f49)

previously allocated by thread T0 here:
 #0 0x7ff1d6dec669 in operator new[](unsigned long) /build/gcc/src/gcc/libsanitizer/asan/asan_new_delete.cc:82
 #1 0x557ffa8affea in function_use_after_free() /home/user/cmake-recipes/chapter-14/recipe-03/cxx-example/src/buggy.cpp:19
 #2 0x557ffa8affb2 in main /home/user/cmake-recipes/chapter-14/recipe-03/cxx-example/tests/use_after_free.cpp:4
 #3 0x7ff1d6088f49 in __libc_start_main (/usr/lib/libc.so.6+0x20f49)

SUMMARY: AddressSanitizer: heap-use-after-free /home/user/cmake-recipes/chapter-14/recipe-03/cxx-example/src/buggy.cpp:28 in function_use_after_free()
Shadow bytes around the buggy address:
 0x0c4a7fff8040: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
 0x0c4a7fff8050: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
 0x0c4a7fff8060: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
 0x0c4a7fff8070: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
 0x0c4a7fff8080: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
=>0x0c4a7fff8090: fd fd fd fd fd fd fd fd fd fd fd[fd]fd fd fd fd
 0x0c4a7fff80a0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
 0x0c4a7fff80b0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
 0x0c4a7fff80c0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
 0x0c4a7fff80d0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
 0x0c4a7fff80e0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
Shadow byte legend (one shadow byte represents 8 application bytes):
 Addressable: 00
 Partially addressable: 01 02 03 04 05 06 07
 Heap left redzone: fa
 Freed heap region: fd
 Stack left redzone: f1
 Stack mid redzone: f2
 Stack right redzone: f3
 Stack after return: f5
 Stack use after scope: f8
 Global redzone: f9
 Global init order: f6
 Poisoned by user: f7
 Container overflow: fc
 Array cookie: ac
 Intra object redzone: bb
 ASan internal: fe
 Left alloca redzone: ca
 Right alloca redzone: cb
==18571==ABORTING
```

如果我们不使用 AddressSanitizer 进行测试（默认情况下`ENABLE_ASAN`为`OFF`），则以下示例不会报告任何错误：

```cpp
$ mkdir -p build_no_asan
$ cd build_no_asan
$ cmake ..
$ cmake --build .
$ cmake --build . --target test

    Start 1: leaky
1/2 Test #1: leaky ............................ Passed 0.00 sec
    Start 2: use_after_free
2/2 Test #2: use_after_free ................... Passed 0.00 sec

100% tests passed, 0 tests failed out of 2
```

确实，`leaky`只会浪费内存，而`use_after_free`可能导致非确定性失败。调试这些失败的一种方法是使用 valgrind（[`valgrind.org`](http://valgrind.org/)）。

与前两个方案不同，我们使用了一个 CTest 脚本来配置、构建和测试代码，并将报告提交到仪表板。要了解这个方案的工作原理，请仔细查看`dashboard.cmake`脚本。首先，我们定义项目名称并设置主机报告和构建名称，如下所示：

```cpp
set(CTEST_PROJECT_NAME "example")
cmake_host_system_information(RESULT _site QUERY HOSTNAME)
set(CTEST_SITE ${_site})
set(CTEST_BUILD_NAME "${CMAKE_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}")
```

在我们的例子中，`CTEST_BUILD_NAME`评估为`Linux-x86_64`。在您的例子中，您可能会观察到不同的结果，这取决于您的操作系统。

接下来，我们为源代码和构建目录指定路径：

```cpp
set(CTEST_SOURCE_DIRECTORY "${CTEST_SCRIPT_DIRECTORY}")
set(CTEST_BINARY_DIRECTORY "${CTEST_SCRIPT_DIRECTORY}/build")
```

我们可以将生成器设置为`Unix Makefiles`：

```cpp
set(CTEST_CMAKE_GENERATOR "Unix Makefiles")
```

然而，为了编写更便携的测试脚本，我们更倾向于通过命令行提供生成器，如下所示：

```cpp
$ ctest -S dashboard.cmake -D CTEST_CMAKE_GENERATOR="Unix Makefiles"
```

`dashboard.cmake`中的下一个代码片段计算出机器上可用的核心数，并将测试步骤的并行级别设置为可用核心数，以最小化总测试时间：

```cpp
include(ProcessorCount)
ProcessorCount(N)
if(NOT N EQUAL 0)
  set(CTEST_BUILD_FLAGS -j${N})
  set(ctest_test_args ${ctest_test_args} PARALLEL_LEVEL ${N})
endif()
```

接下来，我们开始测试步骤并配置代码，设置`ENABLE_ASAN`为`ON`：

```cpp
ctest_start(Experimental)

ctest_configure(
  OPTIONS
    -DENABLE_ASAN:BOOL=ON
  )
```

剩余的`dashboard.cmake`中的命令对应于构建、测试、内存检查和提交步骤：

```cpp
ctest_build()
ctest_test()

set(CTEST_MEMORYCHECK_TYPE "AddressSanitizer")
ctest_memcheck()

ctest_submit()
```

# 还有更多

细心的读者会注意到，我们在链接目标之前并没有在我们的系统上搜索 AddressSanitizer。在现实世界的完整用例中，这样做是为了避免在链接阶段出现不愉快的意外。我们将提醒读者，我们在第 7 个方案中展示了一种方法来探测 sanitizers 的可用性，即“探测编译器标志”，在第五章“配置时间和构建时间操作”中。

更多关于 AddressSanitizer 的文档和示例，请参见[`github.com/google/sanitizers/wiki/AddressSanitizer`](https://github.com/google/sanitizers/wiki/AddressSanitizer)。AddressSanitizer 不仅限于 C 和 C++。对于 Fortran 示例，我们建议读者参考位于[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-14/recipe-03/fortran-example`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-14/recipe-03/fortran-example)的代码仓库。

在[`github.com/arsenm/sanitizers-cmake`](https://github.com/arsenm/sanitizers-cmake)上可以找到用于发现 sanitizers 并调整编译器标志的 CMake 工具。

# 另请参阅

以下博客文章讨论了如何添加对动态分析工具的支持的示例，并启发了当前的方案：[`blog.kitware.com/ctest-cdash-add-support-for-new-dynamic-analysis-tools/`](https://blog.kitware.com/ctest-cdash-add-support-for-new-dynamic-analysis-tools/)。

# 使用 ThreadSanitizer 并将数据竞争报告给 CDash

本食谱的代码可在[`github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-14/recipe-04`](https://github.com/dev-cafe/cmake-cookbook/tree/v1.0/chapter-14/recipe-04)找到，并包含一个 C++示例。该食谱适用于 CMake 版本 3.5（及以上），并在 GNU/Linux 和 macOS 上进行了测试。

在本食谱中，我们将重用前一个示例的方法，但结合使用 ThreadSanitizer（或 TSan）与 CTest 和 CDash，以识别数据竞争并将这些信息报告给 CDash 仪表板。ThreadSanitizer 的文档可以在网上找到，网址为[`github.com/google/sanitizers/wiki/ThreadSanitizerCppManual`](https://github.com/google/sanitizers/wiki/ThreadSanitizerCppManual)。

# 准备就绪

在本食谱中，我们将使用以下示例代码（`example.cpp`）：

```cpp
#include <chrono>
#include <iostream>
#include <thread>

static const int num_threads = 16;

void increase(int i, int &s) {
  std::this_thread::sleep_for(std::chrono::seconds(1));
  std::cout << "thread " << i << " increases " << s++ << std::endl;
}

int main() {
  std::thread t[num_threads];

  int s = 0;

  // start threads
  for (auto i = 0; i < num_threads; i++) {
    t[i] = std::thread(increase, i, std::ref(s));
  }

  // join threads with main thread
  for (auto i = 0; i < num_threads; i++) {
    t[i].join();
  }

  std::cout << "final s: " << s << std::endl;

  return 0;
}
```

在这个示例代码中，我们启动了 16 个线程，每个线程都调用了`increase`函数。`increase`函数休眠一秒钟，然后打印并递增一个整数`s`。我们预计这段代码会表现出数据竞争，因为所有线程都在没有明确同步或协调的情况下读取和修改同一地址。换句话说，我们预计最终的`s`，即代码末尾打印的`s`，可能会在每次运行中有所不同。这段代码存在缺陷，我们将尝试借助 ThreadSanitizer 来识别数据竞争。如果不运行 ThreadSanitizer，我们可能不会发现代码中的任何问题：

```cpp
$ ./example

thread thread 0 increases 01 increases 1
thread 9 increases 2
thread 4 increases 3
thread 10 increases 4
thread 2 increases 5
thread 3 increases 6
thread 13 increases 7
thread thread 7 increases 8
thread 14 increases 9
thread 8 increases 10
thread 12 increases 11
thread 15 increases 12
thread 11 increases 13
```

```cpp
5 increases 14
thread 6 increases 15

final s: 16
```

# 如何操作

让我们详细地逐一介绍必要的步骤：

1.  `CMakeLists.txt`文件首先定义了最低支持版本、项目名称、支持的语言，以及在这种情况下，对 C++11 标准的要求：

```cpp
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(recipe-04 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

1.  接下来，我们定位 Threads 库，定义可执行文件，并将其与 Threads 库链接：

```cpp
find_package(Threads REQUIRED)

add_executable(example example.cpp)

target_link_libraries(example
  PUBLIC
    Threads::Threads
  )
```

1.  然后，我们提供选项和代码以支持 ThreadSanitizer 的编译和链接：

```cpp
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)

if(ENABLE_TSAN)
  if(CMAKE_CXX_COMPILER_ID MATCHES GNU)
    message(STATUS "ThreadSanitizer enabled")
    target_compile_options(example
      PUBLIC
        -g -O1 -fsanitize=thread -fno-omit-frame-pointer -fPIC
      )
    target_link_libraries(example
      PUBLIC
        tsan
      )
  else()
    message(WARNING "ThreadSanitizer not supported for this compiler")
  endif()
endif()
```

1.  最后，作为测试，我们执行编译后的示例本身：

```cpp
enable_testing()

# allow to report to a cdash dashboard
include(CTest)

add_test(
  NAME
    example
  COMMAND
    $<TARGET_FILE:example>
  )
```

1.  `CTestConfig.cmake`文件与前一个食谱相比没有变化：

```cpp
set(CTEST_DROP_METHOD "http")
set(CTEST_DROP_SITE "my.cdash.org")
set(CTEST_DROP_LOCATION "/submit.php?project=cmake-cookbook")
set(CTEST_DROP_SITE_CDASH TRUE)
```

1.  相应的`dashboard.cmake`脚本是对前一个食谱的简单改编，以适应 TSan：

```cpp
set(CTEST_PROJECT_NAME "example")
cmake_host_system_information(RESULT _site QUERY HOSTNAME)
set(CTEST_SITE ${_site})
set(CTEST_BUILD_NAME "${CMAKE_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}")

set(CTEST_SOURCE_DIRECTORY "${CTEST_SCRIPT_DIRECTORY}")
set(CTEST_BINARY_DIRECTORY "${CTEST_SCRIPT_DIRECTORY}/build")

include(ProcessorCount)
ProcessorCount(N)
if(NOT N EQUAL 0)
  set(CTEST_BUILD_FLAGS -j${N})
  set(ctest_test_args ${ctest_test_args} PARALLEL_LEVEL ${N})
endif()

ctest_start(Experimental)

ctest_configure(
  OPTIONS
    -DENABLE_TSAN:BOOL=ON
  )

ctest_build()
ctest_test()

set(CTEST_MEMORYCHECK_TYPE "ThreadSanitizer")
ctest_memcheck()

ctest_submit()
```

1.  让我们再次为这个示例设置生成器，通过传递`CTEST_CMAKE_GENERATOR`选项：

```cpp
$ ctest -S dashboard.cmake -D CTEST_CMAKE_GENERATOR="Unix Makefiles"

   Each . represents 1024 bytes of output
    . Size of output: 0K
   Each symbol represents 1024 bytes of output.
   '!' represents an error and '*' a warning.
    . Size of output: 0K
```

1.  在仪表板上，我们将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/2fcd3c00-6d80-44c6-b1a5-2b41ba53258d.png)

1.  我们可以更详细地看到动态分析如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cmk-cb/img/e8eaa44b-4031-4992-979b-24e772d3b04b.png)

# 它是如何工作的

本食谱的核心成分位于以下部分的`CMakeLists.txt`中：

```cpp
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)

if(ENABLE_TSAN)
  if(CMAKE_CXX_COMPILER_ID MATCHES GNU)
    message(STATUS "ThreadSanitizer enabled")
    target_compile_options(example
      PUBLIC
        -g -O1 -fsanitize=thread -fno-omit-frame-pointer -fPIC
      )
    target_link_libraries(example
      PUBLIC
        tsan
      )
  else()
    message(WARNING "ThreadSanitizer not supported for this compiler")
  endif()
endif()
```

成分也包含在`dashboard.cmake`中更新的步骤中：

```cpp
# ...

ctest_start(Experimental)

ctest_configure(
  OPTIONS
    -DENABLE_TSAN:BOOL=ON
  )

ctest_build()
ctest_test()

set(CTEST_MEMORYCHECK_TYPE "ThreadSanitizer")
ctest_memcheck()

ctest_submit()
```

与前一个食谱一样，我们也可以在本地检查 ThreadSanitizer 的输出：

```cpp
$ mkdir -p build
$ cd build
$ cmake -DENABLE_TSAN=ON ..
$ cmake --build .
$ cmake --build . --target test

 Start 1: example
1/1 Test #1: example ..........................***Failed 1.07 sec

0% tests passed, 1 tests failed out of 1

$ ./build/example 

thread 0 increases 0
==================
WARNING: ThreadSanitizer: data race (pid=24563)

... lots of output ...

SUMMARY: ThreadSanitizer: data race /home/user/cmake-recipes/chapter-14/recipe-04/cxx-example/example.cpp:9 in increase(int, int&)
```

# 还有更多内容

对 OpenMP 代码应用 TSan 是一个自然的步骤，但请注意，在某些情况下，OpenMP 在 TSan 下会产生误报。对于 Clang 编译器，一个解决办法是重新编译编译器本身及其`libomp`，并使用`-DLIBOMP_TSAN_SUPPORT=TRUE`。通常，合理地使用检测器可能需要重新编译整个工具栈，以避免误报。对于使用 pybind11 的 C++项目，我们可能需要重新编译启用了检测器的 Python，以获得有意义的结果。或者，可以通过使用检测器抑制来将 Python 绑定排除在检测之外，如[`github.com/google/sanitizers/wiki/ThreadSanitizerSuppressions`](https://github.com/google/sanitizers/wiki/ThreadSanitizerSuppressions)所述。如果例如一个共享库被一个启用了检测的二进制文件和一个 Python 插件同时调用，这可能是不可能的。

# 另请参阅

以下博客文章讨论了如何为动态分析工具添加支持的示例，并激发了当前的方案：[`blog.kitware.com/ctest-cdash-add-support-for-new-dynamic-analysis-tools/`](https://blog.kitware.com/ctest-cdash-add-support-for-new-dynamic-analysis-tools/)。
