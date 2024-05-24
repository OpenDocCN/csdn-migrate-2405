# Python 专家级编程第二版（四）

> 原文：[`zh.annas-archive.org/md5/4CC2EF9A4469C814CC3EEBD966D2E707`](https://zh.annas-archive.org/md5/4CC2EF9A4469C814CC3EEBD966D2E707)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：其他语言中的 Python 扩展

在编写基于 Python 的应用程序时，您不仅限于 Python 语言。还有一些工具，比如 Hy，在第三章中简要提到，*语法最佳实践-类级别以上*。它允许您使用其他语言（Lisp 的方言）编写模块、包，甚至整个应用程序，这些应用程序将在 Python 虚拟机中运行。尽管它使您能够用完全不同的语法表达程序逻辑，但它仍然是相同的语言，因为它编译成相同的字节码。这意味着它具有与普通 Python 代码相同的限制：

+   由于 GIL 的存在，线程的可用性大大降低

+   它没有被编译

+   它不提供静态类型和可能的优化

帮助克服这些核心限制的解决方案是完全用不同的语言编写的扩展，并通过 Python 扩展 API 公开它们的接口。

本章将讨论使用其他语言编写自己的扩展的主要原因，并向您介绍帮助创建它们的流行工具。您将学到：

+   如何使用 Python/C API 编写简单的 C 扩展

+   如何使用 Cython 做同样的事情

+   扩展引入的主要挑战和问题是什么

+   如何与编译的动态库进行接口，而不创建专用扩展，仅使用 Python 代码

# 不同的语言意味着-C 或 C++

当我们谈论不同语言的扩展时，我们几乎只考虑 C 和 C++。甚至像 Cython 或 Pyrex 这样的工具，它们提供 Python 语言的超集，仅用于扩展的目的，实际上是源到源编译器，从扩展的 Python-like 语法生成 C 代码。

如果只有这样的编译是可能的，那么确实可以在 Python 中使用任何语言编写的动态/共享库，因此它远远超出了 C 和 C++。但共享库本质上是通用的。它们可以在支持它们加载的任何语言中使用。因此，即使您用完全不同的语言（比如 Delphi 或 Prolog）编写这样的库，很难称这样的库为 Python 扩展，如果它不使用 Python/C API。

不幸的是，仅使用裸的 Python/C API 在 C 或 C++中编写自己的扩展是相当苛刻的。这不仅因为它需要对这两种相对难以掌握的语言之一有很好的理解，而且还因为它需要大量的样板文件。有很多重复的代码必须编写，只是为了提供一个接口，将您实现的逻辑与 Python 及其数据类型粘合在一起。无论如何，了解纯 C 扩展是如何构建的是很好的，因为：

+   您将更好地了解 Python 的工作原理

+   有一天，您可能需要调试或维护本机 C/C++扩展

+   它有助于理解构建扩展的高级工具的工作原理

## C 或 C++中的扩展是如何工作的

如果 Python 解释器能够使用 Python/C API 提供适当的接口，它就能从动态/共享库中加载扩展。这个 API 必须被合并到扩展的源代码中，使用与 Python 源代码一起分发的`Python.h` C 头文件。在许多 Linux 发行版中，这个头文件包含在一个单独的软件包中（例如，在 Debian/Ubuntu 中是`python-dev`），但在 Windows 下，默认情况下分发，并且可以在 Python 安装的`includes/`目录中找到。

Python/C API 通常会随着 Python 的每个版本发布而改变。在大多数情况下，这些只是对 API 的新功能的添加，因此通常是源代码兼容的。无论如何，在大多数情况下，它们不是二进制兼容的，因为**应用程序二进制接口**（**ABI**）发生了变化。这意味着扩展必须为每个 Python 版本单独构建。还要注意，不同的操作系统具有不兼容的 ABI，因此这几乎不可能为每种可能的环境创建二进制分发。这就是为什么大多数 Python 扩展以源代码形式分发的原因。

自 Python 3.2 以来，已经定义了 Python/C API 的一个子集，具有稳定的 ABI。因此可以使用这个有限的 API（具有稳定的 ABI）构建扩展，因此扩展只需构建一次，就可以在任何高于或等于 3.2 的 Python 版本上工作，无需重新编译。无论如何，这限制了 API 功能的数量，并且不能解决旧版本 Python 或以二进制形式分发扩展到使用不同操作系统的环境的问题。因此这是一个权衡，稳定 ABI 的代价似乎有点高而收益很低。

你需要知道的一件事是，Python/C API 是限于 CPython 实现的功能。一些努力已经为 PyPI、Jython 或 IronPython 等替代实现带来了扩展支持，但目前似乎没有可行的解决方案。唯一一个应该轻松处理扩展的替代 Python 实现是 Stackless Python，因为它实际上只是 CPython 的修改版本。

Python 的 C 扩展需要在可用之前编译成共享/动态库，因为显然没有本地的方法可以直接从源代码将 C/C++代码导入 Python。幸运的是，`distutils`和`setuptools`提供了帮助，将编译的扩展定义为模块，因此可以使用`setup.py`脚本处理编译和分发，就像它们是普通的 Python 包一样。这是官方文档中处理带有构建扩展的简单包的`setup.py`脚本的一个示例：

```py
from distutils.core import setup, Extension

module1 = Extension(
    'demo',
    sources=['demo.c']
)

setup(
    name='PackageName',
    version='1.0',
    description='This is a demo package',
    ext_modules=[module1]
)
```

准备好之后，你的分发流程还需要一个额外的步骤：

```py
python setup.py build

```

这将根据`ext_modules`参数编译所有你的扩展，根据`Extension()`调用提供的所有额外编译器设置。将使用的编译器是你的环境的默认编译器。如果要分发源代码分发包，则不需要进行这个编译步骤。在这种情况下，你需要确保目标环境具有所有编译的先决条件，例如编译器、头文件和将链接到二进制文件的其他库（如果你的扩展需要）。有关打包 Python 扩展的更多细节将在*挑战*部分中解释。

# 为什么你可能想使用扩展

写 C/C++扩展是否明智的决定并不容易。一般的经验法则可能是，“除非别无选择，否则永远不要”。但这是一个非常主观的说法，留下了很多解释空间，关于在 Python 中做不到的事情。事实上，很难找到一件事情，纯 Python 代码做不到，但有一些问题，扩展可能特别有用：

+   绕过 Python 线程模型中的**全局解释器锁**（**GIL**）

+   改进关键代码部分的性能

+   集成第三方动态库

+   集成用不同语言编写的源代码

+   创建自定义数据类型

例如，核心语言约束，如 GIL，可以通过不同的并发方法轻松克服，例如绿色线程或多进程，而不是线程模型。

## 改进关键代码部分的性能

让我们诚实一点。开发人员选择 Python 并不是因为性能。它执行速度不快，但可以让你快速开发。尽管我们作为程序员有多么高效，多亏了这种语言，有时我们可能会发现一些问题，这些问题可能无法使用纯 Python 有效解决。

在大多数情况下，解决性能问题实际上只是选择合适的算法和数据结构，而不是限制语言开销的常数因子。如果代码已经编写得很差或者没有使用适当的算法，依赖扩展来节省一些 CPU 周期实际上并不是一个好的解决方案。通常情况下，性能可以在不需要通过在堆栈中循环另一种语言来增加项目复杂性的情况下提高到可接受的水平。如果可能的话，应该首先这样做。无论如何，即使使用*最先进*的算法方法和最适合的数据结构，我们也很可能无法仅仅使用 Python 就满足一些任意的技术约束。

将一些对应用程序性能施加了明确定义限制的示例领域是**实时竞价**（**RTB**）业务。简而言之，整个 RTB 都是关于以类似于真实拍卖或证券交易的方式购买和销售广告库存（广告位置）。交易通常通过一些广告交换服务进行，该服务向有兴趣购买它们的**需求方平台**（**DSP**）发送有关可用库存的信息。这就是事情变得令人兴奋的地方。大多数广告交换使用基于 HTTP 的 OpenRTB 协议与潜在竞标者进行通信，其中 DSP 是负责对其 HTTP 请求提供响应的站点。广告交换总是对整个过程施加非常有限的时间限制（通常在 50 到 100 毫秒之间）——从接收到第一个 TPC 数据包到服务器写入的最后一个字节。为了增加趣味，DSP 平台通常每秒处理成千上万个请求并不罕见。能够将请求处理时间推迟几毫秒甚至是这个行业的生死攸关。这意味着即使是将微不足道的代码移植到 C 语言在这种情况下也是合理的，但前提是它是性能瓶颈的一部分，并且在算法上不能进一步改进。正如有人曾经说过的：

> *“你无法击败用 C 语言编写的循环。”*

## 整合不同语言编写的现有代码

在计算机科学的短暂历史中，已经编写了许多有用的库。每次出现新的编程语言时忘记所有这些遗产将是一个巨大的损失，但也不可能可靠地将曾经编写的任何软件完全移植到任何可用的语言。

C 和 C++语言似乎是提供了许多库和实现的最重要的语言，你可能希望在应用程序代码中集成它们，而无需完全将它们移植到 Python。幸运的是，CPython 已经是用 C 编写的，因此通过自定义扩展是集成这样的代码的最自然的方式。

## 集成第三方动态库

使用不同技术编写的代码的集成并不仅限于 C/C++。许多库，特别是具有闭源的第三方软件，都是以编译后的二进制形式分发的。在 C 中，加载这样的共享/动态库并调用它们的函数非常容易。这意味着只要使用 Python/C API 包装它，就可以使用任何 C 库。

当然，这并不是唯一的解决方案，还有诸如`ctypes`或 CFFI 之类的工具，允许您使用纯 Python 与动态库进行交互，而无需编写 C 扩展。通常情况下，Python/C API 可能仍然是更好的选择，因为它在集成层（用 C 编写）和应用程序的其余部分之间提供了更好的分离。

## 创建自定义数据类型

Python 提供了非常多样化的内置数据类型。其中一些真正使用了最先进的内部实现（至少在 CPython 中），专门为在 Python 语言中使用而量身定制。基本类型和可用的集合数量对于新手来说可能看起来令人印象深刻，但显然它并不能涵盖我们所有可能的需求。

当然，您可以通过完全基于一些内置类型或从头开始构建全新类来在 Python 中创建许多自定义数据结构。不幸的是，对于一些可能严重依赖这些自定义数据结构的应用程序来说，性能可能不够。像`dict`或`set`这样的复杂集合的全部功能来自它们的底层 C 实现。为什么不做同样的事情，也在 C 中实现一些自定义数据结构呢？

# 编写扩展

如前所述，编写扩展并不是一项简单的任务，但作为您辛勤工作的回报，它可以给您带来许多优势。编写自己扩展的最简单和推荐的方法是使用诸如 Cython 或 Pyrex 的工具，或者简单地使用`ctypes`或`cffi`集成现有的动态库。这些项目将提高您的生产力，还会使代码更易于开发、阅读和维护。

无论如何，如果您对这个主题还不熟悉，了解一点是好的，即您可以通过仅使用裸 C 代码和 Python/C API 编写一个扩展来开始您的扩展之旅。这将提高您对扩展工作原理的理解，并帮助您欣赏替代解决方案的优势。为了简单起见，我们将以一个简单的算法问题作为示例，并尝试使用三种不同的方法来实现它：

+   编写纯 C 扩展

+   使用 Cython

+   使用 Pyrex

我们的问题将是找到斐波那契数列的第*n*个数字。很少有人会仅为了这个问题创建编译扩展，但它非常简单，因此它将作为将任何 C 函数连接到 Python/C API 的非常好的示例。我们的唯一目标是清晰和简单，因此我们不会试图提供最有效的解决方案。一旦我们知道这一点，我们在 Python 中实现的斐波那契函数的参考实现如下：

```py
"""Python module that provides fibonacci sequence function"""

def fibonacci(n):
    """Return nth Fibonacci sequence number computed recursively.
    """
    if n < 2:
        return 1
    else:
        return fibonacci(n - 1) + fibonacci(n - 2)
```

请注意，这是`fibonnaci()`函数的最简单实现之一，可以对其进行许多改进。尽管如此，我们拒绝改进我们的实现（例如使用记忆化模式），因为这不是我们示例的目的。同样地，即使编译后的代码提供了更多的优化可能性，我们在讨论 C 或 Cython 中的实现时也不会优化我们的代码。

## 纯 C 扩展

在我们完全深入 C 编写的 Python 扩展的代码示例之前，这里有一个重要的警告。如果您想用 C 扩展 Python，您需要已经对这两种语言非常了解。这对于 C 尤其如此。对它的熟练程度不足可能会导致真正的灾难，因为它很容易被误用。

如果您已经决定需要为 Python 编写 C 扩展，我假设您已经对 C 语言有了足够的了解，可以完全理解所呈现的示例。这里将不会解释除 Python/C API 细节之外的任何内容。本书是关于 Python 而不是其他任何语言。如果您根本不懂 C，那么在获得足够的经验和技能之前，绝对不应该尝试用 C 编写自己的 Python 扩展。把它留给其他人，坚持使用 Cython 或 Pyrex，因为从初学者的角度来看，它们更安全得多。这主要是因为 Python/C API，尽管经过精心设计，但绝对不是 C 的良好入门。

如前所述，我们将尝试将`fibonacci()`函数移植到 C 并将其作为扩展暴露给 Python 代码。没有与 Python/C API 连接的裸实现，类似于前面的 Python 示例，大致如下：

```py
long long fibonacci(unsigned int n) {
    if (n < 2) {
        return 1;
    } else {
        return fibonacci(n - 2) + fibonacci(n - 1);
    }
}
```

以下是一个完整、完全功能的扩展的示例，它在编译模块中公开了这个单一函数：

```py
#include <Python.h>

long long fibonacci(unsigned int n) {
    if (n < 2) {
        return 1;
    } else {
        return fibonacci(n-2) + fibonacci(n-1);
    }
}

static PyObject* fibonacci_py(PyObject* self, PyObject* args) {
    PyObject *result = NULL;
    long n;

    if (PyArg_ParseTuple(args, "l", &n)) {
        result = Py_BuildValue("L", fibonacci((unsigned int)n));
    }

    return result;
}

static char fibonacci_docs[] =
    "fibonacci(n): Return nth Fibonacci sequence number "
    "computed recursively\n";

static PyMethodDef fibonacci_module_methods[] = {
    {"fibonacci", (PyCFunction)fibonacci_py,
     METH_VARARGS, fibonacci_docs},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef fibonacci_module_definition = {
    PyModuleDef_HEAD_INIT,
    "fibonacci",
    "Extension module that provides fibonacci sequence function",
    -1,
    fibonacci_module_methods
};

PyMODINIT_FUNC PyInit_fibonacci(void) {
    Py_Initialize();

    return PyModule_Create(&fibonacci_module_definition);
}
```

前面的例子乍一看可能有点令人不知所措，因为我们不得不添加四倍的代码才能让`fibonacci()` C 函数可以从 Python 中访问。我们稍后会讨论代码的每一部分，所以不用担心。但在我们讨论之前，让我们看看如何将其打包并在 Python 中执行。我们模块的最小`setuptools`配置需要使用`setuptools.Extension`类来指示解释器如何编译我们的扩展：

```py
from setuptools import setup, Extension

setup(
    name='fibonacci',
    ext_modules=[
        Extension('fibonacci', ['fibonacci.c']),
    ]
)
```

扩展的构建过程可以通过 Python 的`setup.py`构建命令来初始化，但也会在包安装时自动执行。以下是在开发模式下安装的结果以及一个简单的交互会话，我们在其中检查和执行我们编译的`fibonacci()`函数：

```py
$ ls -1a
fibonacci.c
setup.py

$ pip install -e .
Obtaining file:///Users/swistakm/dev/book/chapter7
Installing collected packages: fibonacci
 **Running setup.py develop for fibonacci
Successfully installed Fibonacci

$ ls -1ap
build/
fibonacci.c
fibonacci.cpython-35m-darwin.so
fibonacci.egg-info/
setup.py

$ python
Python 3.5.1 (v3.5.1:37a07cee5969, Dec  5 2015, 21:12:44)** 
[GCC 4.2.1 (Apple Inc. build 5666) (dot 3)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import fibonacci
>>> help(fibonacci.fibonacci)

Help on built-in function fibonacci in fibonacci:

fibonacci.fibonacci = fibonacci(...)
 **fibonacci(n): Return nth Fibonacci sequence number computed recursively

>>> [fibonacci.fibonacci(n) for n in range(10)]
[1, 1, 2, 3, 5, 8, 13, 21, 34, 55]
>>>** 

```

### 对 Python/C API 的更详细了解

由于我们知道如何正确地打包、编译和安装自定义 C 扩展，并且确信它按预期工作，现在是讨论我们的代码的正确时间。

扩展模块以一个包含`Python.h`头文件的单个 C 预处理指令开始：

```py
#include <Python.h>
```

这将引入整个 Python/C API，并且是您需要包含的一切，以便能够编写您的扩展。在更现实的情况下，您的代码将需要更多的预处理指令，以从 C 标准库函数中获益或集成其他源文件。我们的示例很简单，因此不需要更多的指令。

接下来是我们模块的核心：

```py
long long fibonacci(unsigned int n) {
    if (n < 2) {
        return 1;
    } else {
        return fibonacci(n - 2) + fibonacci(n - 1);
    }
}
```

前面的`fibonacci()`函数是我们代码中唯一有用的部分。它是纯 C 实现，Python 默认情况下无法理解。我们的示例的其余部分将创建接口层，通过 Python/C API 将其暴露出来。

将此代码暴露给 Python 的第一步是创建与 CPython 解释器兼容的 C 函数。在 Python 中，一切都是对象。这意味着在 Python 中调用的 C 函数也需要返回真正的 Python 对象。Python/C API 提供了`PyObject`类型，每个可调用函数都必须返回指向它的指针。我们函数的签名是：

```py
static PyObject* fibonacci_py(PyObject* self, PyObject* args)s
```

请注意，前面的签名并未指定确切的参数列表，而只是`PyObject* args`，它将保存指向包含提供的值元组的结构的指针。参数列表的实际验证必须在函数体内执行，这正是`fibonacci_py()`所做的。它解析`args`参数列表，假设它是单个`unsigned int`类型，并将该值用作`fibonacci()`函数的参数来检索斐波那契数列元素：

```py
static PyObject* fibonacci_py(PyObject* self, PyObject* args) {
    PyObject *result = NULL;
    long n;

    if (PyArg_ParseTuple(args, "l", &n)) {
        result = Py_BuildValue("L", fibonacci((unsigned int)n));
    }

    return result;
}
```

### 注意

前面的示例函数有一些严重的错误，有经验的开发人员的眼睛应该很容易发现。尝试找到它，作为使用 C 扩展的练习。现在，为了简洁起见，我们将它保留下来。在*异常处理*部分讨论处理错误的细节时，我们将尝试稍后修复它。

`"l"`字符串在`PyArg_ParseTuple(args, "l", &n)`调用中意味着我们希望`args`只包含一个`long`值。如果失败，它将返回`NULL`并在每个线程的解释器状态中存储有关异常的信息。关于异常处理的详细信息将在*异常处理*部分稍后描述。

解析函数的实际签名是`int PyArg_ParseTuple(PyObject *args, const char *format, ...)`，在`format`字符串之后的是一个可变长度的参数列表，表示解析值输出（作为指针）。这类似于 C 标准库中的`scanf()`函数的工作方式。如果我们的假设失败，用户提供了不兼容的参数列表，那么`PyArg_ParseTuple()`将引发适当的异常。一旦你习惯了这种方式，这是一种非常方便的编码函数签名的方式，但与纯 Python 代码相比，它有一个巨大的缺点。由`PyArg_ParseTuple()`调用隐式定义的这种 Python 调用签名在 Python 解释器内部不能轻松地检查。在使用作为扩展提供的代码时，您需要记住这一点。

如前所述，Python 期望从可调用对象返回对象。这意味着我们不能将从`fibonacci()`函数获得的`long long`值作为`fibonacci_py()`的结果返回。这样的尝试甚至不会编译，基本 C 类型不会自动转换为 Python 对象。必须使用`Py_BuildValue(*format, ...)`函数。它是`PyArg_ParseTuple()`的对应物，并接受类似的格式字符串集。主要区别在于参数列表不是函数输出而是输入，因此必须提供实际值而不是指针。

在定义了`fibonacci_py()`之后，大部分繁重的工作都已完成。最后一步是执行模块初始化并向我们的函数添加元数据，这将使用户的使用变得更简单一些。这是我们扩展代码的样板部分，对于一些简单的例子，比如这个例子，可能会占用比我们想要公开的实际函数更多的空间。在大多数情况下，它只是由一些静态结构和一个初始化函数组成，该函数将由解释器在模块导入时执行。

首先，我们创建一个静态字符串，它将成为`fibonacci_py()`函数的 Python 文档字符串的内容：

```py
static char fibonacci_docs[] =
    "fibonacci(n): Return nth Fibonacci sequence number "
    "computed recursively\n";
```

请注意，这可能会*内联*在`fibonacci_module_methods`的某个地方，但将文档字符串分开并存储在与其引用的实际函数定义的附近是一个很好的做法。

我们定义的下一部分是`PyMethodDef`结构的数组，该数组定义了将在我们的模块中可用的方法（函数）。该结构包含四个字段：

+   `char* ml_name`: 这是方法的名称。

+   `PyCFunction ml_meth`: 这是指向函数的 C 实现的指针。

+   `int ml_flags`: 这包括指示调用约定或绑定约定的标志。后者仅适用于定义类方法。

+   `char* ml_doc`: 这是指向方法/函数文档字符串内容的指针。

这样的数组必须始终以`{NULL, NULL, 0, NULL}`的哨兵值结束，表示其结束。在我们的简单情况下，我们创建了`static PyMethodDef fibonacci_module_methods[]`数组，其中只包含两个元素（包括哨兵值）：

```py
static PyMethodDef fibonacci_module_methods[] = {
    {"fibonacci", (PyCFunction)fibonacci_py,
     METH_VARARGS, fibonacci_docs},
    {NULL, NULL, 0, NULL}
};
```

这就是第一个条目如何映射到`PyMethodDef`结构：

+   `ml_name = "fibonacci"`: 在这里，`fibonacci_py()` C 函数将以`fibonacci`名称作为 Python 函数公开

+   `ml_meth = (PyCFunction)fibonacci_py`: 在这里，将`PyCFunction`转换仅仅是 Python/C API 所需的，并且由`ml_flags`中定义的调用约定决定

+   `ml_flags = METH_VARARGS`: 在这里，`METH_VARARGS`标志表示我们的函数的调用约定接受可变参数列表，不接受关键字参数

+   `ml_doc = fibonacci_docs`: 在这里，Python 函数将使用`fibonacci_docs`字符串的内容进行文档化

当函数定义数组完成时，我们可以创建另一个结构，其中包含整个模块的定义。它使用`PyModuleDef`类型进行描述，并包含多个字段。其中一些仅适用于需要对模块初始化过程进行细粒度控制的更复杂的情况。在这里，我们只对其中的前五个感兴趣：

+   `PyModuleDef_Base m_base`: 这应该始终用`PyModuleDef_HEAD_INIT`进行初始化。

+   `char* m_name`: 这是新创建模块的名称。在我们的例子中是`fibonacci`。

+   `char* m_doc`: 这是模块的文档字符串内容的指针。通常在一个 C 源文件中只定义一个模块，因此将我们的文档字符串内联在整个结构中是可以的。

+   `Py_ssize_t m_size`: 这是分配给保持模块状态的内存的大小。只有在需要支持多个子解释器或多阶段初始化时才会使用。在大多数情况下，您不需要它，它的值为`-1`。

+   `PyMethodDef* m_methods`: 这是指向包含由`PyMethodDef`值描述的模块级函数的数组的指针。如果模块不公开任何函数，则可以为`NULL`。在我们的情况下，它是`fibonacci_module_methods`。

其他字段在官方 Python 文档中有详细解释（参考[`docs.python.org/3/c-api/module.html`](https://docs.python.org/3/c-api/module.html)），但在我们的示例扩展中不需要。如果不需要，它们应该设置为`NULL`，当未指定时，它们将隐式地初始化为该值。这就是为什么我们的模块描述包含在`fibonacci_module_definition`变量中可以采用这种简单的五元素形式的原因：

```py
static struct PyModuleDef fibonacci_module_definition = {
    PyModuleDef_HEAD_INIT,
    "fibonacci",
    "Extension module that provides fibonacci sequence function",
    -1,
    fibonacci_module_methods
};
```

最后一段代码是我们工作的巅峰，即模块初始化函数。这必须遵循非常特定的命名约定，以便 Python 解释器在加载动态/共享库时可以轻松地选择它。它应该被命名为`PyInit_name`，其中*name*是您的模块名称。因此，它与在`PyModuleDef`定义中用作`m_base`字段和`setuptools.Extension()`调用的第一个参数的字符串完全相同。如果您不需要对模块进行复杂的初始化过程，它将采用与我们示例中完全相同的非常简单的形式：

```py
PyMODINIT_FUNC PyInit_fibonacci(void) {
    return PyModule_Create(&fibonacci_module_definition);
}
```

`PyMODINIT_FUNC`宏是一个预处理宏，它将声明此初始化函数的返回类型为`PyObject*`，并根据平台需要添加任何特殊的链接声明。

### 调用和绑定约定

如*深入了解 Python/C API*部分所述，`PyMethodDef`结构的`ml_flags`位字段包含调用和绑定约定的标志。**调用约定标志**包括：

+   `METH_VARARGS`: 这是 Python 函数或方法的典型约定，只接受参数作为其参数。对于这样的函数，`ml_meth`字段提供的类型应该是`PyCFunction`。该函数将提供两个`PyObject*`类型的参数。第一个要么是`self`对象（对于方法），要么是`module`对象（对于模块函数）。具有该调用约定的 C 函数的典型签名是`PyObject* function(PyObject* self, PyObject* args)`。

+   `METH_KEYWORDS`：这是 Python 函数在调用时接受关键字参数的约定。其关联的 C 类型是`PyCFunctionWithKeywords`。C 函数必须接受三个`PyObject*`类型的参数：`self`，`args`和关键字参数的字典。如果与`METH_VARARGS`组合，前两个参数的含义与前一个调用约定相同，否则`args`将为`NULL`。典型的 C 函数签名是：`PyObject* function(PyObject* self, PyObject* args, PyObject* keywds)`。

+   `METH_NOARGS`：这是 Python 函数不接受任何其他参数的约定。C 函数应该是`PyCFunction`类型，因此签名与`METH_VARARGS`约定相同（两个`self`和`args`参数）。唯一的区别是`args`将始终为`NULL`，因此不需要调用`PyArg_ParseTuple()`。这不能与任何其他调用约定标志组合。

+   `METH_O`：这是接受单个对象参数的函数和方法的简写。C 函数的类型再次是`PyCFunction`，因此它接受两个`PyObject*`参数：`self`和`args`。它与`METH_VARARGS`的区别在于不需要调用`PyArg_ParseTuple()`，因为作为`args`提供的`PyObject*`将已经表示在 Python 调用该函数时提供的单个参数。这也不能与任何其他调用约定标志组合。

接受关键字的函数可以用`METH_KEYWORDS`或者`METH_VARARGS |` `METH_KEYWORDS`的形式来描述。如果是这样，它应该使用`PyArg_ParseTupleAndKeywords()`来解析它的参数，而不是`PyArg_ParseTuple()`或者`PyArg_UnpackTuple()`。下面是一个示例模块，其中有一个返回`None`的函数，接受两个命名关键字参数，并将它们打印到标准输出：

```py
#include <Python.h>

static PyObject* print_args(PyObject *self, PyObject *args, PyObject *keywds)
{
    char *first;
    char *second;

    static char *kwlist[] = {"first", "second", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ss", kwlist,
                                     &first, &second))
        return NULL;

    printf("%s %s\n", first, second);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyMethodDef module_methods[] = {
    {"print_args", (PyCFunction)print_args,
     METH_VARARGS | METH_KEYWORDS,
     "print provided arguments"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module_definition = {
    PyModuleDef_HEAD_INIT,
    "kwargs",
    "Keyword argument processing example",
    -1,
    module_methods
};

PyMODINIT_FUNC PyInit_kwargs(void) {
    return PyModule_Create(&module_definition);
}
```

Python/C API 中的参数解析非常灵活，并且在官方文档中有详细描述。`PyArg_ParseTuple()`和`PyArg_ParseTupleAndKeywords()`中的格式参数允许对参数数量和类型进行精细的控制。Python 中已知的每个高级调用约定都可以使用此 API 在 C 中编码，包括：

+   带有默认参数值的函数

+   指定为关键字参数的函数

+   带有可变数量参数的函数

**绑定约定标志**是`METH_CLASS`，`METH_STATIC`和`METH_COEXIST`，它们保留给方法，并且不能用于描述模块函数。前两个相当不言自明。它们是`classmethod`和`staticmethod`装饰器的 C 对应物，并且改变了传递给 C 函数的`self`参数的含义。

`METH_COEXIST`允许在现有定义的位置加载一个方法。这很少有用。这主要是当您想要提供一个从已定义的类型的其他特性自动生成的 C 方法的实现时。Python 文档给出了`__contains__()`包装器方法的示例，如果类型定义了`sq_contains`槽，它将自动生成。不幸的是，使用 Python/C API 定义自己的类和类型超出了本入门章节的范围。在讨论 Cython 时，我们将在以后讨论创建自己的类型，因为在纯 C 中这样做需要太多样板代码，并且容易出错。

### 异常处理

与 Python 甚至 C++不同，C 没有语法来引发和捕获异常。所有错误处理通常通过函数返回值和可选的全局状态来处理，用于存储可以解释最后一次失败原因的细节。

Python/C API 中的异常处理建立在这个简单原则的基础上。有一个全局的每个线程指示器，用于描述 C API 中发生的最后一个错误。它被设置为描述问题的原因。还有一种标准化的方法，用于在调用期间通知函数的调用者是否更改了此状态：

+   如果函数应返回指针，则返回`NULL`

+   如果函数应返回`int`类型，则返回`-1`

在 Python/C API 中，前述规则的唯一例外是返回`1`表示成功，返回`0`表示失败的`PyArg_*（）`函数。

为了了解这在实践中是如何工作的，让我们回顾一下前几节中示例中的`fibonacci_py（）`函数：

```py
static PyObject* fibonacci_py(PyObject* self, PyObject* args) {
 **PyObject *result = NULL;
    long n;

 **if (PyArg_ParseTuple(args, "l", &n)) {
 **result = Py_BuildValue("L", fibonacci((unsigned int) n));
    }

 **return result;
}
```

以某种方式参与我们的错误处理的行已经被突出显示。它从初始化`result`变量开始，该变量应存储我们函数的返回值。它被初始化为`NULL`，正如我们已经知道的那样，这是一个错误指示器。这通常是您编写扩展的方式，假设错误是代码的默认状态。

稍后，我们有`PyArg_ParseTuple（）`调用，如果发生异常，将设置错误信息并返回`0`。这是`if`语句的一部分，在这种情况下，我们不做任何其他操作并返回`NULL`。调用我们的函数的人将收到有关错误的通知。

`Py_BuildValue（）`也可能引发异常。它应返回`PyObject*`（指针），因此在失败的情况下会返回`NULL`。我们可以简单地将其存储为我们的结果变量，并将其作为返回值传递。

但我们的工作并不仅仅是关心 Python/C API 调用引发的异常。很可能您需要通知扩展用户发生了其他类型的错误或失败。Python/C API 有多个函数可帮助您引发异常，但最常见的是`PyErr_SetString（）`。它使用提供的附加字符串设置错误指示器和给定的异常类型作为错误原因的解释。此函数的完整签名是：

```py
void PyErr_SetString(PyObject* type, const char* message)
```

我已经说过我们的`fibonacci_py（）`函数的实现存在严重错误。现在是修复它的正确时机。幸运的是，我们有适当的工具来做到这一点。问题在于在以下行中将`long`类型不安全地转换为`unsigned int`：

```py
    if (PyArg_ParseTuple(args, "l", &n)) {
      result = Py_BuildValue("L", fibonacci((unsigned int) n));
    }
```

感谢`PyArg_ParseTuple（）`调用，第一个且唯一的参数将被解释为`long`类型（`"l"`指定符），并存储在本地`n`变量中。然后将其转换为`unsigned int`，因此如果用户使用负值从 Python 调用`fibonacci（）`函数，则会出现问题。例如，作为有符号 32 位整数的`-1`在转换为无符号 32 位整数时将被解释为`4294967295`。这样的值将导致深度递归，并导致堆栈溢出和分段错误。请注意，如果用户提供任意大的正参数，也可能会发生相同的情况。我们无法在没有完全重新设计 C `fibonacci（）`函数的情况下解决这个问题，但至少我们可以尝试确保传递的参数满足一些先决条件。在这里，我们检查`n`参数的值是否大于或等于零，如果不是，则引发`ValueError`异常：

```py
static PyObject* fibonacci_py(PyObject* self, PyObject* args) {
    PyObject *result = NULL;
    long n;
    long long fib;

    if (PyArg_ParseTuple(args, "l", &n)) {
        if (n<0) {
            PyErr_SetString(PyExc_ValueError,
                            "n must not be less than 0");
        } else {
            result = Py_BuildValue("L", fibonacci((unsigned int)n));
        }
    }

    return result;
}
```

最后一点是全局错误状态不会自行清除。您的 C 函数中可能会优雅地处理一些错误（就像在 Python 中使用`try ... except`子句一样），如果错误指示器不再有效，则需要能够清除错误指示器。用于此目的的函数是`PyErr_Clear（）`。

### 释放 GIL

我已经提到扩展可以是绕过 Python GIL 的一种方法。CPython 实现有一个著名的限制，即一次只能有一个线程执行 Python 代码。虽然多进程是绕过这个问题的建议方法，但对于一些高度可并行化的算法来说，由于运行额外进程的资源开销，这可能不是一个好的解决方案。

因为扩展主要用于在纯 C 中执行大部分工作而没有调用 Python/C API 的情况下，所以在一些应用程序部分释放 GIL 是可能的（甚至是建议的）。由于这一点，您仍然可以从拥有多个 CPU 核心和多线程应用程序设计中受益。您唯一需要做的就是使用 Python/C API 提供的特定宏将已知不使用任何 Python/C API 调用或 Python 结构的代码块进行包装。这两个预处理器宏旨在简化释放和重新获取全局解释器锁的整个过程：

+   `Py_BEGIN_ALLOW_THREADS`：这声明了隐藏的本地变量，保存了当前线程状态并释放了 GIL

+   `Py_END_ALLOW_THREADS`：这重新获取 GIL 并从使用前一个宏声明的本地变量恢复线程状态

当我们仔细观察我们的`fibonacci`扩展示例时，我们可以清楚地看到`fibonacci()`函数不执行任何 Python 代码，也不触及任何 Python 结构。这意味着简单包装`fibonacci(n)`执行的`fibonacci_py()`函数可以更新以在调用周围释放 GIL：

```py
static PyObject* fibonacci_py(PyObject* self, PyObject* args) {
    PyObject *result = NULL;
    long n;
    long long fib;

    if (PyArg_ParseTuple(args, "l", &n)) {
        if (n<0) {
            PyErr_SetString(PyExc_ValueError,
                            "n must not be less than 0");
        } else {
            Py_BEGIN_ALLOW_THREADS;
            fib = fibonacci(n);
            Py_END_ALLOW_THREADS;

            result = Py_BuildValue("L", fib);
        }}

    return result;
}
```

### 引用计数

最后，我们来到了 Python 中内存管理的重要主题。Python 有自己的垃圾回收器，但它只设计用来解决**引用计数**算法中的循环引用问题。引用计数是管理不再需要的对象的释放的主要方法。

Python/C API 文档引入了*引用的所有权*来解释它如何处理对象的释放。Python 中的对象从不被拥有，它们总是被共享。对象的实际创建由 Python 的内存管理器管理。这是 CPython 解释器的一个组件，负责为存储在私有堆中的对象分配和释放内存。可以拥有的是对对象的引用。

Python 中的每个对象，由一个引用（`PyObject*`指针）表示，都有一个关联的引用计数。当引用计数为零时，意味着没有人持有对象的有效引用，可以调用与其类型相关联的解分配器。Python/C API 提供了两个宏来增加和减少引用计数：`Py_INCREF()`和`Py_DECREF()`。但在讨论它们的细节之前，我们需要了解与引用所有权相关的一些术语：

+   **所有权的传递**：每当我们说函数*传递了对引用的所有权*时，这意味着它已经增加了引用计数，调用者有责任在不再需要对象的引用时减少计数。大多数返回新创建对象的函数，比如`Py_BuildValue`，都会这样做。如果该对象将从我们的函数返回给另一个调用者，那么所有权会再次传递。在这种情况下，我们不会减少引用计数，因为这不再是我们的责任。这就是为什么`fibonacci_py()`函数不在`result`变量上调用`Py_DECREF()`的原因。

+   **借用引用**：*借用*引用发生在函数将某个 Python 对象的引用作为参数接收时。在该函数中，除非在其范围内明确增加了引用计数，否则不应该减少此类引用的引用计数。在我们的`fibonacci_py()`函数中，`self`和`args`参数就是这样的借用引用，因此我们不对它们调用`PyDECREF()`。Python/C API 的一些函数也可能返回借用引用。值得注意的例子是`PyTuple_GetItem()`和`PyList_GetItem()`。通常说这样的引用是*不受保护*的。除非它将作为函数的返回值返回，否则不需要释放其所有权。在大多数情况下，如果我们将这样的借用引用用作其他 Python/C API 调用的参数，就需要额外小心。在某些情况下，可能需要在将其用作其他函数的参数之前，额外使用`Py_INCREF()`来保护这样的引用，然后在不再需要时调用`Py_DECREF()`。

+   **窃取引用**：Python/C API 函数还可以在提供为调用参数时*窃取*引用，而不是*借用*引用。这是确切的两个函数的情况：`PyTuple_SetItem()`和`PyList_SetItem()`。它们完全承担了传递给它们的引用的责任。它们本身不增加引用计数，但在不再需要引用时会调用`Py_DECREF()`。

在编写复杂的扩展时，监视引用计数是最困难的事情之一。一些不那么明显的问题可能直到在多线程设置中运行代码时才会被注意到。

另一个常见的问题是由 Python 对象模型的本质和一些函数返回借用引用的事实引起的。当引用计数变为零时，将执行解分配函数。对于用户定义的类，可以定义一个`__del__()`方法，在那时将被调用。这可以是任何 Python 代码，可能会影响其他对象及其引用计数。官方 Python 文档给出了以下可能受到此问题影响的代码示例：

```py
void bug(PyObject *list) {
    PyObject *item = PyList_GetItem(list, 0);

    PyList_SetItem(list, 1, PyLong_FromLong(0L));
    PyObject_Print(item, stdout, 0); /* BUG! */
}
```

看起来完全无害，但问题实际上是我们无法知道`list`对象包含哪些元素。当`PyList_SetItem()`在`list[1]`索引上设置一个新值时，之前存储在该索引处的对象的所有权被处理。如果它是唯一存在的引用，引用计数将变为 0，并且对象将被解分配。可能是某个用户定义的类，具有`__del__()`方法的自定义实现。如果在这样的`__del__()`执行的结果中，`item[0]`将从列表中移除，将会出现严重问题。请注意，`PyList_GetItem()`返回一个*借用*引用！在返回引用之前，它不会调用`Py_INCREF()`。因此，在该代码中，可能会调用`PyObject_Print()`，并且会使用一个不再存在的对象的引用。这将导致分段错误并使 Python 解释器崩溃。

正确的方法是在我们需要它们的整个时间内保护借用引用，因为有可能在其中的任何调用可能导致任何其他对象的解分配，即使它们看似无关：

```py
void no_bug(PyObject *list) {
    PyObject *item = PyList_GetItem(list, 0);

    Py_INCREF(item);
    PyList_SetItem(list, 1, PyLong_FromLong(0L));
    PyObject_Print(item, stdout, 0);
    Py_DECREF(item);
}
```

## Cython

Cython 既是一个优化的静态编译器，也是 Python 的超集编程语言的名称。作为编译器，它可以对本地 Python 代码和其 Cython 方言进行*源到源*编译，使用 Python/C API 将其转换为 Python C 扩展。它允许您结合 Python 和 C 的强大功能，而无需手动处理 Python/C API。

### Cython 作为源到源编译器

使用 Cython 创建的扩展的主要优势是可以使用它提供的超集语言。无论如何，也可以使用*源到源*编译从纯 Python 代码创建扩展。这是 Cython 的最简单方法，因为它几乎不需要对代码进行任何更改，并且可以在非常低的开发成本下获得一些显著的性能改进。

Cython 提供了一个简单的`cythonize`实用函数，允许您轻松地将编译过程与`distutils`或`setuptools`集成。假设我们想将`fibonacci()`函数的纯 Python 实现编译为 C 扩展。如果它位于`fibonacci`模块中，最小的`setup.py`脚本可能如下所示：

```py
from setuptools import setup
from Cython.Build import cythonize

setup(
    name='fibonacci',
    ext_modules=cythonize(['fibonacci.py'])
)
```

Cython 作为 Python 语言的源编译工具还有另一个好处。源到源编译到扩展可以是源分发安装过程的完全可选部分。如果需要安装包的环境没有 Cython 或任何其他构建先决条件，它可以像普通的*纯 Python*包一样安装。用户不应该注意到以这种方式分发的代码行为上的任何功能差异。

使用 Cython 构建的扩展的常见方法是包括 Python/Cython 源代码和从这些源文件生成的 C 代码。这样，该包可以根据构建先决条件的存在以三种不同的方式安装：

+   如果安装环境中有 Cython 可用，则会从提供的 Python/Cython 源代码生成扩展 C 代码。

+   如果 Cython 不可用，但存在构建先决条件（C 编译器，Python/C API 头文件），则从分发的预生成 C 文件构建扩展。

+   如果前述的先决条件都不可用，但扩展是从纯 Python 源创建的，则模块将像普通的 Python 代码一样安装，并且跳过编译步骤。

请注意，Cython 文档表示，包括生成的 C 文件以及 Cython 源是分发 Cython 扩展的推荐方式。同样的文档表示，Cython 编译应该默认禁用，因为用户可能在他的环境中没有所需版本的 Cython，这可能导致意外的编译问题。无论如何，随着环境隔离的出现，这似乎是一个今天不太令人担忧的问题。此外，Cython 是一个有效的 Python 包，可以在 PyPI 上获得，因此可以很容易地在特定版本中定义为您项目的要求。当然，包括这样的先决条件是一个具有严重影响的决定，应该非常谨慎地考虑。更安全的解决方案是利用`setuptools`包中的`extras_require`功能的强大功能，并允许用户决定是否要使用特定环境变量来使用 Cython：

```py
import os

from distutils.core import setup
from distutils.extension import Extension

try:
    # cython source to source compilation available
    # only when Cython is available
    import Cython
    # and specific environment variable says
    # explicitely that Cython should be used
    # to generate C sources
    USE_CYTHON = bool(os.environ.get("USE_CYTHON"))

except ImportError:
    USE_CYTHON = False

ext = '.pyx' if USE_CYTHON else '.c'

extensions = [Extension("fibonacci", ["fibonacci"+ext])]

if USE_CYTHON:
    from Cython.Build import cythonize
    extensions = cythonize(extensions)

setup(
    name='fibonacci',
    ext_modules=extensions,
    extras_require={
        # Cython will be set in that specific version
        # as a requirement if package will be intalled
        # with '[with-cython]' extra feature
        'cython': ['cython==0.23.4']
    }
)
```

`pip`安装工具支持通过在包名后添加`[extra-name]`后缀来使用*extras*选项安装包。对于前面的示例，可以使用以下命令启用从本地源安装时的可选 Cython 要求和编译：

```py
$ USE_CYTHON=1 pip install .[with-cython]

```

### Cython 作为一种语言

Cython 不仅是一个编译器，还是 Python 语言的超集。超集意味着任何有效的 Python 代码都是允许的，并且可以进一步更新为具有额外功能的代码，例如支持调用 C 函数或在变量和类属性上声明 C 类型。因此，任何用 Python 编写的代码也是用 Cython 编写的。这解释了为什么普通的 Python 模块可以如此轻松地使用 Cython 编译为 C。

但我们不会停留在这个简单的事实上。我们将尝试对我们的参考`fibonacci()`函数进行一些改进，而不是说它也是 Python 的超集中有效扩展的代码。这不会对我们的函数设计进行任何真正的优化，而是一些小的更新，使它能够从在 Cython 中编写的好处中受益。

Cython 源文件使用不同的文件扩展名。它是`.pyx`而不是`.py`。假设我们仍然想要实现我们的 Fibbonacci 序列。`fibonacci.pyx`的内容可能如下所示：

```py
"""Cython module that provides fibonacci sequence function."""

def fibonacci(unsigned int n):
    """Return nth Fibonacci sequence number computed recursively."""
    if n < 2:
        return n
    else:
        return fibonacci(n - 1) + fibonacci(n - 2)
```

正如您所看到的，真正改变的只是`fibonacci()`函数的签名。由于 Cython 中的可选静态类型，我们可以将`n`参数声明为`unsigned int`，这应该稍微改进了我们函数的工作方式。此外，它比我们以前手工编写扩展时做的事情要多得多。如果 Cython 函数的参数声明为静态类型，则扩展将自动处理转换和溢出错误，引发适当的异常：

```py
>>> from fibonacci import fibonacci
>>> fibonacci(5)
5
>>> fibonacci(-1)
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
 **File "fibonacci.pyx", line 21, in fibonacci.fibonacci (fibonacci.c:704)
OverflowError: can't convert negative value to unsigned int
>>> fibonacci(10 ** 10)
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
 **File "fibonacci.pyx", line 21, in fibonacci.fibonacci (fibonacci.c:704)
OverflowError: value too large to convert to unsigned int

```

我们已经知道 Cython 只编译*源到源*，生成的代码使用与我们手工编写 C 代码扩展时相同的 Python/C API。请注意，`fibonacci()`是一个递归函数，因此它经常调用自身。这意味着尽管我们为输入参数声明了静态类型，在递归调用期间，它将像任何其他 Python 函数一样对待自己。因此，`n-1`和`n-2`将被打包回 Python 对象，然后传递给内部`fibonacci()`实现的隐藏包装层，再次将其转换为`unsigned int`类型。这将一次又一次地发生，直到我们达到递归的最终深度。这不一定是一个问题，但涉及到比实际需要的更多的参数处理。

我们可以通过将更多的工作委托给一个纯 C 函数来削减 Python 函数调用和参数处理的开销。我们以前在使用纯 C 创建 C 扩展时就这样做过，我们在 Cython 中也可以这样做。我们可以使用`cdef`关键字声明只接受和返回 C 类型的 C 风格函数：

```py
cdef long long fibonacci_cc(unsigned int n):
    if n < 2:
        return n
    else:
        return fibonacci_cc(n - 1) + fibonacci_cc(n - 2)

def fibonacci(unsigned int n):
    """ Return nth Fibonacci sequence number computed recursively
    """
    return fibonacci_cc(n)
```

我们甚至可以走得更远。通过一个简单的 C 示例，我们最终展示了如何在调用我们的纯 C 函数时释放 GIL，因此扩展对多线程应用程序来说更加友好。在以前的示例中，我们使用了 Python/C API 头文件中的`Py_BEGIN_ALLOW_THREADS`和`Py_END_ALLOW_THREADS`预处理器宏来标记代码段为无需 Python 调用。Cython 语法要简短得多，更容易记住。可以使用简单的`with nogil`语句在代码段周围释放 GIL：

```py
def fibonacci(unsigned int n):
    """ Return nth Fibonacci sequence number computed recursively
    """
 **with nogil:
        result = fibonacci_cc(n)

    return fibonacci_cc(n)
```

您还可以将整个 C 风格函数标记为无需 GIL 即可调用：

```py
cdef long long fibonacci_cc(unsigned int n) nogil:
    if n < 2:
        return n
    else:
        return fibonacci_cc(n - 1) + fibonacci_cc(n - 2)
```

重要的是要知道，这样的函数不能将 Python 对象作为参数或返回类型。每当标记为`nogil`的函数需要执行任何 Python/C API 调用时，它必须使用`with gil`语句获取 GIL。

# 挑战

老实说，我之所以开始接触 Python，只是因为我厌倦了用 C 和 C++编写软件的所有困难。事实上，程序员们意识到其他语言无法满足用户需求时，很常见的是开始学习 Python。与 C、C++或 Java 相比，用 Python 编程是一件轻而易举的事情。一切似乎都很简单而且设计良好。你可能会认为没有地方会让你绊倒，也不再需要其他编程语言了。

当然，这种想法是错误的。是的，Python 是一种令人惊叹的语言，具有许多很酷的功能，并且在许多领域中被使用。但这并不意味着它是完美的，也没有任何缺点。它易于理解和编写，但这种简单性是有代价的。它并不像许多人认为的那样慢，但永远不会像 C 那样快。它高度可移植，但它的解释器并不像其他语言的编译器那样在许多架构上都可用。我们可以永远列出这样的列表。

解决这个问题的一个方法是编写扩展，这样我们就可以将*好老的 C*的一些优点带回 Python。在大多数情况下，这样做效果很好。问题是：我们真的是因为想用 C 来扩展 Python 吗？答案是否定的。这只是在我们没有更好选择的情况下的一种不便的必要性。

## 额外的复杂性

毫无秘密，用许多不同的语言开发应用程序并不是一件容易的事情。Python 和 C 是完全不同的技术，很难找到它们共同之处。同样真实的是没有一个应用程序是没有 bug 的。如果在你的代码库中扩展变得很常见，调试可能会变得痛苦。不仅因为调试 C 代码需要完全不同的工作流程和工具，而且因为你需要经常在两种不同的语言之间切换上下文。

我们都是人类，都有有限的认知能力。当然，有些人可以有效地处理多层抽象和技术堆栈，但他们似乎是非常罕见的。无论你有多么有技巧，对于维护这样的混合解决方案，总是需要额外付出代价。这要么涉及额外的努力和时间来在 C 和 Python 之间切换，要么涉及额外的压力，最终会使你效率降低。

根据 TIOBE 指数，C 仍然是最流行的编程语言之一。尽管事实如此，Python 程序员很常见地对它知之甚少，甚至几乎一无所知。就我个人而言，我认为 C 应该是编程世界的*通用语言*，但我的观点在这个问题上很不可能改变任何事情。Python 也是如此诱人和易学，以至于许多程序员忘记了他们以前的所有经验，完全转向了新技术。而编程不像骑自行车。如果不经常使用和充分磨练，这种特定的技能会更快地消失。即使是具有扎实 C 背景的程序员，如果决定长时间深入 Python，也会逐渐失去他们以前的知识。以上所有情况都导致一个简单的结论——很难找到能够理解和扩展你的代码的人。对于开源软件包，这意味着更少的自愿贡献者。对于闭源软件，这意味着并非所有的队友都能够在不破坏东西的情况下开发和维护扩展。

## 调试

当涉及到失败时，扩展可能会出现严重故障。静态类型给你比 Python 更多的优势，并允许你在编译步骤中捕获很多问题，这些问题在 Python 中很难注意到，除非进行严格的测试例程和全面的测试覆盖。另一方面，所有内存管理必须手动执行。错误的内存管理是 C 中大多数编程错误的主要原因。在最好的情况下，这样的错误只会导致一些内存泄漏，逐渐消耗所有环境资源。最好的情况并不意味着容易处理。内存泄漏真的很难在不使用适当的外部工具（如 Valgrind）的情况下找到。无论如何，在大多数情况下，扩展代码中的内存管理问题将导致分段错误，在 Python 中无法恢复，并且会导致解释器崩溃而不引发任何异常。这意味着最终您将需要额外的工具，大多数 Python 程序员不需要使用。这给您的开发环境和工作流程增加了复杂性。

# 无需扩展即可与动态库进行接口

由于`ctypes`（标准库中的一个模块）或`cffi`（一个外部包），您可以在 Python 中集成几乎所有编译的动态/共享库，无论它是用什么语言编写的。而且您可以在纯 Python 中进行，无需任何编译步骤，因此这是编写 C 扩展的有趣替代方案。

这并不意味着您不需要了解 C。这两种解决方案都需要您对 C 有合理的理解，以及对动态库的工作原理有所了解。另一方面，它们消除了处理 Python 引用计数的负担，并大大减少了犯错误的风险。通过`ctypes`或`cffi`与 C 代码进行接口，比编写和编译 C 扩展模块更具可移植性。

## ctypes

`ctypes` 是调用动态或共享库函数最流行的模块，无需编写自定义的 C 扩展。其原因是显而易见的。它是标准库的一部分，因此始终可用，不需要任何外部依赖。它是一个**外部函数接口**（**FFI**）库，并提供了一个用于创建兼容 C 数据类型的 API。

### 加载库

`ctypes`中有四种类型的动态库加载器，以及两种使用它们的约定。表示动态和共享库的类有`ctypes.CDLL`、`ctypes.PyDLL`、`ctypes.OleDLL`和`ctypes.WinDLL`。最后两个仅在 Windows 上可用，因此我们不会在这里讨论它们。`CDLL`和`PyDLL`之间的区别如下：

+   `ctypes.CDLL`：此类表示已加载的共享库。这些库中的函数使用标准调用约定，并假定返回`int`。在调用期间释放 GIL。

+   `ctypes.PyDLL`：此类与`CDLL`类似，但在调用期间不会释放 GIL。执行后，将检查 Python 错误标志，并在设置时引发异常。仅在直接从 Python/C API 调用函数时才有用。

要加载库，您可以使用前述类之一实例化，并使用适当的参数，或者调用与特定类相关联的子模块的`LoadLibrary()`函数：

+   `ctypes.cdll.LoadLibrary()` 用于 `ctypes.CDLL`

+   `ctypes.pydll.LoadLibrary()` 用于 `ctypes.PyDLL`

+   `ctypes.windll.LoadLibrary()` 用于 `ctypes.WinDLL`

+   `ctypes.oledll.LoadLibrary()` 用于 `ctypes.OleDLL`

在加载共享库时的主要挑战是如何以便携方式找到它们。不同的系统对共享库使用不同的后缀（Windows 上为`.dll`，OS X 上为`.dylib`，Linux 上为`.so`）并在不同的位置搜索它们。在这方面的主要问题是 Windows，它没有预定义的库命名方案。因此，我们不会讨论在这个系统上使用`ctypes`加载库的细节，而主要集中在处理这个问题的一致和类似方式的 Linux 和 Mac OS X 上。如果您对 Windows 平台感兴趣，可以参考官方的`ctypes`文档，其中有大量关于支持该系统的信息（参见[`docs.python.org/3.5/library/ctypes.html`](https://docs.python.org/3.5/library/ctypes.html)）。

加载库的两种约定（`LoadLibrary()`函数和特定的库类型类）都要求您使用完整的库名称。这意味着需要包括所有预定义的库前缀和后缀。例如，在 Linux 上加载 C 标准库，您需要编写以下内容：

```py
>>> import ctypes
>>> ctypes.cdll.LoadLibrary('libc.so.6')
<CDLL 'libc.so.6', handle 7f0603e5f000 at 7f0603d4cbd0>

```

在这里，对于 Mac OS X，这将是：

```py
>>> import ctypes
>>> ctypes.cdll.LoadLibrary('libc.dylib')

```

幸运的是，`ctypes.util`子模块提供了一个`find_library()`函数，允许使用其名称加载库，而无需任何前缀或后缀，并且将在具有预定义共享库命名方案的任何系统上工作：

```py
>>> import ctypes
>>> from ctypes.util import find_library
>>> ctypes.cdll.LoadLibrary(find_library('c'))
<CDLL '/usr/lib/libc.dylib', handle 7fff69b97c98 at 0x101b73ac8>
>>> ctypes.cdll.LoadLibrary(find_library('bz2'))
<CDLL '/usr/lib/libbz2.dylib', handle 10042d170 at 0x101b6ee80>
>>> ctypes.cdll.LoadLibrary(find_library('AGL'))
<CDLL '/System/Library/Frameworks/AGL.framework/AGL', handle 101811610 at 0x101b73a58>

```

### 使用 ctypes 调用 C 函数

当成功加载库时，通常的模式是将其存储为与库同名的模块级变量。函数可以作为对象属性访问，因此调用它们就像调用来自任何其他已导入模块的 Python 函数一样：

```py
>>> import ctypes
>>> from ctypes.util import find_library
>>>** 
>>> libc = ctypes.cdll.LoadLibrary(find_library('c'))
>>>** 
>>> libc.printf(b"Hello world!\n")
Hello world!
13

```

不幸的是，除了整数、字符串和字节之外，所有内置的 Python 类型都与 C 数据类型不兼容，因此必须包装在`ctypes`模块提供的相应类中。以下是来自`ctypes`文档的完整兼容数据类型列表：

| ctypes 类型 | C 类型 | Python 类型 |
| --- | --- | --- |
| --- | --- | --- |
| `c_bool` | `_Bool` | `bool`（1） |
| `c_char` | `char` | 1 个字符的`bytes`对象 |
| `c_wchar` | `wchar_t` | 1 个字符的`string` |
| `c_byte` | `char` | `int` |
| `c_ubyte` | `unsigned char` | `int` |
| `c_short` | `short` | `int` |
| `c_ushort` | `unsigned short` | `int` |
| `c_int` | `int` | `int` |
| `c_uint` | `unsigned int` | `int` |
| `c_long` | `long` | `int` |
| `c_ulong` | `unsigned long` | `int` |
| `c_longlong` | `__int64 或 long long` | `int` |
| `c_ulonglong` | `unsigned __int64 或 unsigned long long` | `int` |
| `c_size_t` | `size_t` | `int` |
| `c_ssize_t` | `ssize_t 或 Py_ssize_t` | `int` |
| `c_float` | `float` | `float` |
| `c_double` | `double` | `float` |
| `c_longdouble` | `long double` | `float` |
| `c_char_p` | `char *（NUL 终止）` | `bytes`对象或`None` |
| `c_wchar_p` | `wchar_t *（NUL 终止）` | `string`或`None` |
| `c_void_p` | `void *` | `int`或`None` |

正如您所看到的，上表中没有专门的类型来反映任何 Python 集合作为 C 数组。创建 C 数组类型的推荐方法是简单地使用所需的基本`ctypes`类型与乘法运算符：

```py
>>> import ctypes
>>> IntArray5 = ctypes.c_int * 5
>>> c_int_array = IntArray5(1, 2, 3, 4, 5)
>>> FloatArray2 = ctypes.c_float * 2
>>> c_float_array = FloatArray2(0, 3.14)
>>> c_float_array[1]
3.140000104904175

```

### 将 Python 函数作为 C 回调传递

将函数实现的一部分委托给用户提供的自定义回调是一种非常流行的设计模式。C 标准库中接受此类回调的最知名函数是提供了**Quicksort**算法的`qsort()`函数。您可能不太可能使用此算法而不是更适合对 Python 集合进行排序的默认 Python **Timsort**。无论如何，`qsort()`似乎是一个高效排序算法和使用回调机制的 C API 的典型示例，在许多编程书籍中都可以找到。这就是为什么我们将尝试将其用作将 Python 函数作为 C 回调传递的示例。

普通的 Python 函数类型将不兼容`qsort()`规范所需的回调函数类型。以下是来自 BSD `man`页面的`qsort()`签名，其中还包含了接受的回调类型（`compar`参数）的类型：

```py
void qsort(void *base, size_t nel, size_t width,
           int (*compar)(const void *, const void *));
```

因此，为了执行`libc`中的`qsort()`，您需要传递：

+   `base`：这是需要作为`void*`指针排序的数组。

+   `nel`：这是`size_t`类型的元素数量。

+   `width`：这是`size_t`类型的数组中单个元素的大小。

+   `compar`：这是指向应该返回`int`并接受两个`void*`指针的函数的指针。它指向比较正在排序的两个元素大小的函数。

我们已经从*使用 ctypes 调用 C 函数*部分知道了如何使用乘法运算符从其他`ctypes`类型构造 C 数组。`nel`应该是`size_t`，它映射到 Python `int`，因此不需要任何额外的包装，可以作为`len(iterable)`传递。一旦我们知道了`base`数组的类型，就可以使用`ctypes.sizeof()`函数获取`width`值。我们需要知道的最后一件事是如何创建与`compar`参数兼容的 Python 函数指针。

`ctypes`模块包含一个`CFUNTYPE()`工厂函数，允许我们将 Python 函数包装并表示为 C 可调用函数指针。第一个参数是包装函数应该返回的 C 返回类型。它后面是作为其参数接受的 C 类型的可变列表。与`qsort()`的`compar`参数兼容的函数类型将是：

```py
CMPFUNC = ctypes.CFUNCTYPE(
    # return type
    ctypes.c_int,
    # first argument type
    ctypes.POINTER(ctypes.c_int),
    # second argument type
    ctypes.POINTER(ctypes.c_int),
)
```

### 注意

`CFUNTYPE()`使用`cdecl`调用约定，因此只与`CDLL`和`PyDLL`共享库兼容。在 Windows 上使用`WinDLL`或`OleDLL`加载的动态库使用`stdcall`调用约定。这意味着必须使用其他工厂将 Python 函数包装为 C 可调用函数指针。在`ctypes`中，它是`WINFUNCTYPE()`。

总结一切，假设我们想要使用标准 C 库中的`qsort()`函数对随机洗牌的整数列表进行排序。以下是一个示例脚本，展示了如何使用到目前为止我们学到的关于`ctypes`的一切来实现这一点：

```py
from random import shuffle

import ctypes
from ctypes.util import find_library

libc = ctypes.cdll.LoadLibrary(find_library('c'))

CMPFUNC = ctypes.CFUNCTYPE(
    # return type
    ctypes.c_int,
    # first argument type
    ctypes.POINTER(ctypes.c_int),
    # second argument type
    ctypes.POINTER(ctypes.c_int),
)

def ctypes_int_compare(a, b):
    # arguments are pointers so we access using [0] index
    print(" %s cmp %s" % (a[0], b[0]))

    # according to qsort specification this should return:
    # * less than zero if a < b
    # * zero if a == b
    # * more than zero if a > b
    return a[0] - b[0]

def main():
    numbers = list(range(5))
    shuffle(numbers)
    print("shuffled: ", numbers)

    # create new type representing array with length
    # same as the length of numbers list
    NumbersArray = ctypes.c_int * len(numbers)
    # create new C array using a new type
    c_array = NumbersArray(*numbers)

    libc.qsort(
        # pointer to the sorted array
        c_array,
        # length of the array
        len(c_array),
        # size of single array element
        ctypes.sizeof(ctypes.c_int),
        # callback (pointer to the C comparison function)
        CMPFUNC(ctypes_int_compare)
    )
    print("sorted:   ", list(c_array))

if __name__ == "__main__":
    main()
```

作为回调提供的比较函数有一个额外的`print`语句，因此我们可以看到它在排序过程中是如何执行的：

```py
$ python ctypes_qsort.py** 
shuffled:  [4, 3, 0, 1, 2]
 **4 cmp 3
 **4 cmp 0
 **3 cmp 0
 **4 cmp 1
 **3 cmp 1
 **0 cmp 1
 **4 cmp 2
 **3 cmp 2
 **1 cmp 2
sorted:    [0, 1, 2, 3, 4]

```

## CFFI

CFFI 是 Python 的外部函数接口，是`ctypes`的一个有趣的替代方案。它不是标准库的一部分，但在 PyPI 上很容易获得作为`cffi`软件包。它与`ctypes`不同，因为它更注重重用纯 C 声明，而不是在单个模块中提供广泛的 Python API。它更加复杂，还具有一个功能，允许您自动将集成层的某些部分编译成扩展，使用 C 编译器。因此，它可以用作填补 C 扩展和`ctypes`之间差距的混合解决方案。

因为这是一个非常庞大的项目，不可能在几段话中简要介绍它。另一方面，不多说一些关于它的东西会很遗憾。我们已经讨论了使用`ctypes`集成标准库中的`qsort()`函数的一个例子。因此，展示这两种解决方案之间的主要区别的最佳方式将是使用`cffi`重新实现相同的例子。我希望一段代码能比几段文字更有价值：

```py
from random import shuffle

from cffi import FFI

ffi = FFI()

ffi.cdef("""
void qsort(void *base, size_t nel, size_t width,
           int (*compar)(const void *, const void *));
""")
C = ffi.dlopen(None)

@ffi.callback("int(void*, void*)")
def cffi_int_compare(a, b):
    # Callback signature requires exact matching of types.
    # This involves less more magic than in ctypes
    # but also makes you more specific and requires
    # explicit casting
    int_a = ffi.cast('int*', a)[0]
    int_b = ffi.cast('int*', b)[0]
    print(" %s cmp %s" % (int_a, int_b))

    # according to qsort specification this should return:
    # * less than zero if a < b
    # * zero if a == b
    # * more than zero if a > b
    return int_a - int_b

def main():
    numbers = list(range(5))
    shuffle(numbers)
    print("shuffled: ", numbers)

    c_array = ffi.new("int[]", numbers)

    C.qsort(
        # pointer to the sorted array
        c_array,
        # length of the array
        len(c_array),
        # size of single array element
        ffi.sizeof('int'),
        # callback (pointer to the C comparison function)
        cffi_int_compare,
    )
    print("sorted:   ", list(c_array))

if __name__ == "__main__":
    main()
```

# 总结

本章解释了本书中最高级的主题之一。我们讨论了构建 Python 扩展的原因和工具。我们从编写纯 C 扩展开始，这些扩展仅依赖于 Python/C API，然后用 Cython 重新实现它们，以展示如果你选择合适的工具，它可以是多么容易。

仍然有一些理由可以*以困难的方式*做事，并且仅使用纯 C 编译器和`Python.h`头文件。无论如何，最好的建议是使用诸如 Cython 或 Pyrex（这里没有介绍）这样的工具，因为它将使您的代码库更易读和可维护。它还将使您免受由粗心的引用计数和内存管理引起的大部分问题的困扰。

我们对扩展的讨论以`ctypes`和 CFFI 作为集成共享库的替代方法的介绍结束。因为它们不需要编写自定义扩展来调用编译后的二进制文件中的函数，所以它们应该是你在这方面的首选工具，特别是如果你不需要使用自定义的 C 代码。

在下一章中，我们将从低级编程技术中短暂休息，并深入探讨同样重要的主题——代码管理和版本控制系统。


# 第八章：管理代码

在涉及多人的软件项目上工作是困难的。一切都变慢并变得更加困难。这是由于几个原因。本章将揭示这些原因，并尝试提供一些对抗它们的方法。

本章分为两部分，分别解释：

+   如何使用版本控制系统

+   如何建立持续开发流程

首先，代码库的演变非常重要，需要跟踪所有的更改，尤其是当许多开发人员在其上工作时。这就是**版本控制系统**的作用。

接下来，即使没有直接连接在一起的几个大脑仍然可以在同一个项目上工作。他们有不同的角色并且在不同的方面工作。因此，缺乏全局可见性会导致对其他人正在进行的工作和正在做的事情产生很多困惑。这是不可避免的，必须使用一些工具来提供持续的可见性并减轻问题。这是通过建立一系列持续开发流程的工具来实现的，如**持续集成**或**持续交付**。

现在我们将详细讨论这两个方面。

# 版本控制系统

**版本控制系统**（**VCS**）提供了一种分享、同步和备份任何类型文件的方法。它们分为两个家族：

+   集中式系统

+   分布式系统

## 集中式系统

集中式版本控制系统基于一个保存文件并允许人们检入和检出对这些文件所做更改的单个服务器。原则非常简单——每个人都可以在自己的系统上获取文件的副本并对其进行操作。从那里，每个用户都可以将他/她的更改提交到服务器。它们将被应用并且*修订*号将被提升。然后其他用户将能够通过*更新*来同步他们的*仓库*副本以获取这些更改。

仓库通过所有的提交而发展，系统将所有修订版本存档到数据库中，以撤消任何更改或提供有关已完成的工作的信息：

![集中式系统](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_08_01.jpg)

图 1

在这种集中式配置中，每个用户都负责将他/她的本地仓库与主要仓库同步，以获取其他用户的更改。这意味着当本地修改的文件已被其他人更改并检入时，可能会发生一些冲突。在这种情况下，冲突解决机制是在用户系统上进行的，如下图所示：

![集中式系统](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_08_02.jpg)

图 2

这将帮助您更好地理解：

1.  Joe 提交了一个更改。

1.  Pamela 试图在同一个文件上进行更改检入。

1.  服务器抱怨她的文件副本已经过时。

1.  Pamela 更新了她的本地副本。版本控制软件可能能够无缝地合并这两个版本（即，没有冲突）。

1.  Pamela 提交了一个包含 Joe 和她自己最新更改的新版本。

这个过程在涉及少数开发人员和少量文件的小型项目中是完全可以的。但对于更大的项目来说就会有问题。例如，复杂的更改涉及大量文件，这是耗时的，并且在整个工作完成之前将所有内容保留在本地是不可行的。这种方法的问题包括：

+   这是危险的，因为用户可能会保留他/她的计算机更改，而这些更改不一定被备份

+   在检查之前很难与其他人分享，而在完成之前分享它会使仓库处于不稳定状态，因此其他用户不会想要分享

集中式版本控制系统通过提供*分支*和*合并*来解决了这个问题。可以从主要修订流中分叉出来，然后再回到主要流中。

在*图 3*中，乔从修订版 2 开始创建一个新的分支来开发一个新功能。每次检入更改时，主流和他的分支中的修订版都会增加。在第 7 个修订版，乔完成了他的工作，并将更改提交到主干（主分支）。这通常需要一些冲突解决。

但是，尽管它们有优势，集中式版本控制系统也有一些缺陷：

+   分支和合并是非常难处理的。它可能变成一场噩梦。

+   由于系统是集中式的，离线提交更改是不可能的。这可能导致用户在重新联机时向服务器进行大量的单一提交。最后，对于像 Linux 这样的项目来说，它并不适用得很好，许多公司永久地维护着软件的自己的分支，并且没有每个人都有账户的中央仓库。

对于后者，一些工具使得离线工作成为可能，比如 SVK，但更根本的问题是集中式版本控制系统的工作方式。

![集中式系统](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_08_03.jpg)

图 3

尽管存在这些缺陷，集中式版本控制系统在许多公司中仍然非常受欢迎，主要是由于企业环境的惯性。许多组织使用的集中式版本控制系统的主要示例是**Subversion**（**SVN**）和**Concurrent Version System**（**CVS**）。集中式架构对版本控制系统的明显问题是为什么大多数开源社区已经转向更可靠的**分布式版本控制系统**（**DVCS**）的架构。

## 分布式系统

分布式版本控制系统是对集中式版本控制系统缺陷的答案。它不依赖于人们使用的主服务器，而是依赖于点对点的原则。每个人都可以拥有和管理自己独立的项目仓库，并将其与其他仓库同步：

![分布式系统](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_08_04.jpg)

图 4

在*图 4*中，我们可以看到这样一个系统的使用示例：

1.  比尔从 HAL 的仓库*拉取*文件。

1.  比尔对文件进行了一些更改。

1.  阿米娜从比尔的仓库*拉取*文件。

1.  阿米娜也改变了文件。

1.  阿米娜*推送*更改到 HAL。

1.  肯尼从 HAL*拉取*文件。

1.  肯尼做出了改变。

1.  肯尼定期*推送*他的更改到 HAL。

关键概念是人们*推送*和*拉取*文件到其他仓库，这种行为会根据人们的工作方式和项目管理方式而改变。由于不再有主要仓库，项目的维护者需要为人们*推送*和*拉取*更改定义一种策略。

此外，当人们使用多个仓库时，他们必须更加聪明。在大多数分布式版本控制系统中，修订号是针对每个仓库的，没有全局的修订号可以供任何人参考。因此，必须使用*标签*来使事情更清晰。它们是可以附加到修订版的文本标签。最后，用户需要负责备份他们自己的仓库，而在集中式基础设施中，通常是管理员设置备份策略。

### 分布式策略

当然，在公司环境中，如果所有人都朝着同一个目标努力工作，使用分布式版本控制系统仍然需要一个中央服务器。但是，该服务器的目的与集中式版本控制系统中的完全不同。它只是一个中心，允许所有开发人员在一个地方共享他们的更改，而不是在彼此的仓库之间进行拉取和推送。这样一个单一的中央仓库（通常称为*上游*）也作为所有团队成员个人仓库中跟踪的所有更改的备份。

可以采用不同的方法与 DVCS 中央存储库共享代码。最简单的方法是设置一个像常规集中式服务器一样运行的服务器，项目的每个成员都可以将自己的更改推送到一个公共流中。但这种方法有点简单化。它没有充分利用分布式系统，因为人们将使用推送和拉取命令的方式与集中式系统相同。

另一种方法是在服务器上提供几个具有不同访问级别的存储库：

+   **不稳定** **存储库**是每个人都可以推送更改的地方。

+   **稳定** **存储库**对于除发布经理之外的所有成员都是只读的。他们被允许从不稳定的存储库中拉取更改并决定应该合并什么。

+   各种**发布** **存储库**对应于发布，并且是只读的，正如我们将在本章后面看到的那样。

这使人们可以贡献，管理者可以审查更改，然后再将其提交到稳定的存储库。无论如何，根据所使用的工具，这可能是太多的开销。在许多分布式版本控制系统中，这也可以通过适当的分支策略来处理。

其他策略可以根据 DVCS 提供的无限组合进行制定。例如，使用 Git（[`git-scm.com/`](http://git-scm.com/)）的 Linux 内核基于星型模型，Linus Torvalds 维护官方存储库，并从一组他信任的开发人员那里拉取更改。在这种模型中，希望向内核推送更改的人将尝试将它们推送给受信任的开发人员，以便通过他们达到 Linus。

## 集中式还是分布式？

忘记集中式版本控制系统。

让我们诚实一点。集中式版本控制系统是过去的遗物。在大多数人都有全职远程工作的机会时，受到集中式 VCS 所有缺陷的限制是不合理的。例如，使用 CVS 或 SVN 时，您无法在离线时跟踪更改。这太愚蠢了。当您的工作场所的互联网连接暂时中断或中央存储库崩溃时，您该怎么办？您应该忘记所有的工作流程，只允许更改堆积直到情况改变，然后将其作为一个巨大的非结构化更新提交吗？不！

此外，大多数集中式版本控制系统无法有效处理分支方案。分支是一种非常有用的技术，可以让您在许多人在多个功能上工作的项目中限制合并冲突的数量。在 SVN 中，分支是如此荒谬，以至于大多数开发人员都尽量避免使用它。相反，大多数集中式 VCS 提供了一些文件锁定原语，应该被视为任何版本控制系统的反模式。关于每个版本控制工具的悲哀事实是，如果它包含危险的选项，您团队中的某个人最终将开始每天使用它。锁定是这样一个功能，它虽然减少了合并冲突，但会极大地降低整个团队的生产力。通过选择不允许这种糟糕工作流的版本控制系统，您正在创造一种更有可能使您的开发人员有效使用它的情况。

## 如果可以，请使用 Git

Git 目前是最流行的分布式版本控制系统。它是由 Linus Torvalds 创建的，用于维护 Linux 内核的版本，当其核心开发人员需要从之前使用的专有 BitKeeper 辞职时。

如果您尚未使用任何版本控制系统，则应从头开始使用 Git。如果您已经使用其他工具进行版本控制，请无论如何学习 Git。即使您的组织在不久的将来不愿切换到 Git，您也应该这样做，否则您可能会成为一个活化石。

我并不是说 Git 是最终和最好的 DVCS 版本控制系统。它肯定有一些缺点。最重要的是，它不是一个易于使用的工具，对新手来说非常具有挑战性。Git 的陡峭学习曲线已经成为网络上许多笑话的来源。可能有一些版本控制系统对许多项目表现更好，开源 Git 竞争者的完整列表会相当长。无论如何，Git 目前是最受欢迎的 DVCS，因此*网络效应*确实对它有利。

简而言之，网络效应导致使用流行工具的整体效益大于使用其他工具，即使稍微更好，也是因为其高度的流行（这就是 VHS 击败 Betamax 的原因）。很可能你的组织中的人，以及新员工，对 Git 都有一定的熟练程度，因此集成这个 DVCS 的成本会比尝试一些不那么流行的工具要低。

无论如何，了解更多并熟悉其他分布式版本控制系统总是好的。Git 最受欢迎的开源竞争对手是 Mercurial、Bazaar 和 Fossil。第一个特别好，因为它是用 Python 编写的，并且是 CPython 源代码的官方版本控制系统。有迹象表明，这种情况可能会在不久的将来发生变化，所以当你读到这本书的时候，CPython 开发人员可能已经在使用 Git 了。但这并不重要。这两个系统都很棒。如果没有 Git，或者它不那么受欢迎，我肯定会推荐 Mercurial。它的设计显然很美。它肯定没有 Git 那么强大，但对初学者来说更容易掌握。

## Git flow 和 GitHub flow

与 Git 一起工作的非常流行和标准化的方法简称为**Git flow**。以下是该流程的主要规则的简要描述：

+   通常有一个主要的工作分支，通常称为`develop`，所有最新版本应用的开发都在这里进行。

+   新项目功能是在称为*功能分支*的单独分支上实现的，这些分支总是从`develop`分支开始。当功能完成并且代码经过适当测试后，该分支会合并回`develop`。

+   当`develop`中的代码稳定下来（没有已知的错误）并且需要发布新的应用程序版本时，会创建一个新的*发布分支*。这个发布分支通常需要额外的测试（广泛的 QA 测试、集成测试等），所以一定会发现新的错误。如果发布分支包括额外的更改（如错误修复），它们最终需要合并回`develop`分支。

+   当*发布分支*上的代码准备部署/发布时，它会合并到`master`分支，并且`master`上的最新提交会被标记为适当的版本标签。除了`release`分支，没有其他分支可以合并到`master`。唯一的例外是需要立即部署或发布的紧急修复。

+   需要紧急发布的热修复总是在从`master`开始的单独分支上实现。修复完成后，它会合并到`develop`和`master`分支。热修复分支的合并就像普通的发布分支一样进行，因此必须正确标记，并相应地修改应用程序版本标识符。

*图 5*中展示了*Git flow*的视觉示例。对于那些从未以这种方式工作过，也从未使用过分布式版本控制系统的人来说，这可能有点压倒性。无论如何，如果你的组织没有任何正式的工作流程，值得尝试。它有多重好处，也解决了真正的问题。对于多名程序员团队，他们正在开发许多独立功能，并且需要为多个版本提供持续支持时，它尤其有用。

如果您想使用持续部署流程来实现持续交付，这种方法也很方便，因为在您的组织中始终清楚哪个代码版本代表了您的应用程序或服务的可交付版本。对于开源项目来说，它也是一个很好的工具，因为它为用户和活跃的贡献者提供了很好的透明度。

![Git 流程和 GitHub 流程](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_08_05.jpg)

图 5 展示了 Git 流程的视觉呈现

因此，如果您认为这个对*Git 流程*的简短总结有点意义，并且还没有吓到您，那么您应该深入研究该主题的在线资源。很难说出这个工作流的原始作者是谁，但大多数在线来源都指向 Vincent Driessen。因此，学习*Git 流程*的最佳起点材料是他的在线文章，标题为*成功的 Git* *分支模型*（参考[`nvie.com/posts/a-successful-git-branching-model/`](http://nvie.com/posts/a-successful-git-branching-model/)）。

像其他流行的方法一样，*Git 流程*在互联网上受到了很多程序员的批评。Vincent Driessen 的文章中最受评论的事情是（严格技术性的）规则，即每次合并都应该创建一个代表该合并的新人工提交。Git 有一个选项可以进行*快进*合并，Vincent 不鼓励使用该选项。当然，这是一个无法解决的问题，因为执行合并的最佳方式完全是组织 Git 正在使用的主观问题。无论如何，*Git 流程*的真正问题在于它显然很复杂。完整的规则集非常长，因此很容易犯一些错误。您很可能希望选择一些更简单的东西。

GitHub 使用了这样的流程，并由 Scott Chacon 在他的博客上描述（参考[`scottchacon.com/2011/08/31/github-flow.html`](http://scottchacon.com/2011/08/31/github-flow.html)）。它被称为**GitHub 流程**，与*Git 流程*非常相似：

+   主分支中的任何内容都可以部署

+   新功能是在单独的分支上实现的

与*Git 流程*的主要区别在于简单性。只有一个主要开发分支（`master`），它始终是稳定的（与*Git 流程*中的`develop`分支相反）。也没有发布分支，而且非常强调对代码进行标记。在 GitHub 上没有这样的需要，因为他们说，当某些东西合并到主分支时，通常会立即部署到生产环境。图 6 展示了 GitHub 流程示例的图表。

GitHub 流程似乎是一个适合希望为其项目设置持续部署流程的团队的良好且轻量级的工作流。当然，这样的工作流对于具有严格版本号概念的任何项目来说都是不可行的，至少没有进行任何修改。重要的是要知道*始终可部署* `master`分支的主要假设是，没有适当的自动化测试和构建程序就无法保证。这就是持续集成系统要处理的问题，我们稍后会讨论这个问题。以下是一个展示 GitHub 流程示例的图表：

![Git 流程和 GitHub 流程](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_08_06.jpg)

图 6 展示了 GitHub 流程的视觉呈现

请注意，*Git flow*和*GitHub flow*都只是分支策略，所以尽管它们的名字中都有*Git*，但它们并不局限于单一的分布式版本控制系统。*Git flow*的官方文章提到了在执行合并时应该使用的特定`git`命令参数，但这个基本思想几乎可以轻松应用于几乎任何其他分布式版本控制系统。事实上，由于它建议如何处理合并，Mercurial 似乎是更好的工具来使用这种特定的分支策略！*GitHub flow*也是一样。这是唯一一种带有一点特定开发文化的分支策略，因此它可以在任何允许你轻松创建和合并代码分支的版本控制系统中使用。

最后一点要记住的是，没有一种方法论是铁板一块，也没有人强迫你使用它。它们被创造出来是为了解决一些现有的问题，并防止你犯一些常见的错误。你可以接受它们的所有规则，或者根据自己的需要修改其中一些。它们是初学者的好工具，可以轻松地避开常见的陷阱。如果你不熟悉任何版本控制系统，那么你应该从像*GitHub flow*这样的轻量级方法开始，不做任何自定义修改。只有当你对 Git 或你选择的其他工具有足够的经验时，你才应该考虑更复杂的工作流。无论如何，随着你的熟练程度越来越高，你最终会意识到没有一种完美的工作流适用于每个项目。在一个组织中运行良好的东西不一定在其他组织中也能运行良好。

# 持续开发过程

有一些过程可以极大地简化你的开发，并减少将应用程序准备好发布或部署到生产环境所需的时间。它们的名字中经常带有`continuous`，我们将在本节讨论最重要和最受欢迎的过程。需要强调的是，它们是严格的技术过程，因此它们几乎与项目管理技术无关，尽管它们可以与后者高度契合。

我们将提到的最重要的过程是：

+   持续集成

+   持续交付

+   持续部署

列出顺序很重要，因为它们中的每一个都是前一个的延伸。持续部署甚至可以简单地被认为是持续交付的变体。无论如何，我们将分别讨论它们，因为对一个组织来说只是一个微小的差异，对其他组织来说可能是至关重要的。

这些都是技术过程的事实意味着它们的实施严格依赖于适当工具的使用。它们背后的基本思想都相当简单，所以你可以构建自己的持续集成/交付/部署工具，但最好的方法是选择已经构建好的工具。这样，你就可以更多地专注于构建产品，而不是持续开发的工具链。

## 持续集成

**持续集成**，通常缩写为**CI**，是一种利用自动化测试和版本控制系统来提供完全自动化集成环境的过程。它可以与集中式版本控制系统一起使用，但在实践中，只有在使用良好的分布式版本控制系统来管理代码时，它才能充分发挥作用。

设置仓库是持续集成的第一步，这是一组从**极限编程**(**XP**)中出现的软件实践。这些原则在维基百科上清楚地描述了([`en.wikipedia.org/wiki/Continuous_integration#The_Practices`](http://en.wikipedia.org/wiki/Continuous_integration#The_Practices))，并定义了一种确保软件易于构建、测试和交付的方式。

实施持续集成的第一个和最重要的要求是拥有一个完全自动化的工作流程，可以在给定的修订版中测试整个应用程序，以决定其是否在技术上正确。技术上正确意味着它没有已知的错误，并且所有功能都按预期工作。

CI 的一般理念是在合并到主流开发分支之前始终运行测试。这只能通过开发团队中的正式安排来处理，但实践表明这不是一种可靠的方法。问题在于，作为程序员，我们倾向于过于自信，无法对我们的代码进行批判性的审视。如果持续集成仅建立在团队安排上，它将不可避免地失败，因为一些开发人员最终会跳过他们的测试阶段，并将可能有缺陷的代码提交到应始终保持稳定的主流开发分支。而且，实际上，即使是简单的更改也可能引入关键问题。

明显的解决方案是利用专用构建服务器，它在代码库发生更改时自动运行所有必需的应用程序测试。有许多工具可以简化这个过程，并且它们可以很容易地集成到诸如 GitHub 或 Bitbucket 等版本控制托管服务以及 GitLab 等自托管服务中。使用这些工具的好处是开发人员可以在本地仅运行与他当前工作相关的选定测试子集，并将潜在耗时的整个集成测试套件留给构建服务器。这确实加快了开发速度，但仍然减少了新功能破坏主流代码分支中现有稳定代码的风险。

使用专用构建服务器的另一个好处是可以在接近生产环境的环境中运行测试。开发人员还应尽可能使用与生产环境尽可能匹配的环境，并且有很好的工具可以做到这一点（例如 Vagrant）；然而，在任何组织中强制执行这一点是很困难的。您可以在一个专用的构建服务器上甚至在一个构建服务器集群上轻松实现这一点。许多 CI 工具通过利用各种虚拟化工具来确保测试始终在相同的、完全新鲜的测试环境中运行，使这一点变得更加不成问题。

拥有一个构建服务器对于创建必须以二进制形式交付给用户的桌面或移动应用程序也是必不可少的。显而易见的做法是始终在相同的环境中执行这样的构建过程。几乎每个 CI 系统都考虑到应用程序通常需要在测试/构建完成后以二进制形式下载。这样的构建结果通常被称为**构建产物**。

因为 CI 工具起源于大多数应用程序都是用编译语言编写的时代，它们大多使用术语“构建”来描述它们的主要活动。对于诸如 C 或 C ++之类的语言，这是显而易见的，因为如果不构建（编译）应用程序，则无法运行和测试。对于 Python 来说，这就显得有点不合理，因为大多数程序以源代码形式分发，并且可以在没有任何额外构建步骤的情况下运行。因此，在我们的语境中，当谈论持续集成时，“构建”和“测试”这两个术语经常可以互换使用。

### 测试每次提交

持续集成的最佳方法是在每次更改推送到中央存储库时对整个测试套件进行测试。即使一个程序员在单个分支中推送了一系列多个提交，通常也有意义对每个更改进行单独测试。如果您决定仅测试单个存储库推送中的最新更改集，那么将更难找到可能在中间某个地方引入的潜在回归问题的源头。

当然，许多分布式版本控制系统，如 Git 或 Mercurial，允许你通过提供*二分*历史更改的命令来限制搜索回归源的时间，但实际上，将其作为持续集成过程的一部分自动完成会更加方便。

当然，还有一个问题是，一些测试套件运行时间非常长，可能需要数十分钟甚至数小时才能完成。一个服务器可能无法在给定时间内处理每次提交的所有构建。这将使等待结果的时间更长。事实上，长时间运行的测试本身就是一个问题，稍后将在*问题 2-构建时间过长*部分进行描述。现在，你应该知道，你应该始终努力测试推送到仓库的每次提交。如果你没有能力在单个服务器上做到这一点，那么就建立整个构建集群。如果你使用的是付费服务，那么就支付更高价格的计划，进行更多并行构建。硬件是便宜的，你开发人员的时间不是。最终，通过拥有更快的并行构建和更昂贵的 CI 设置，你将节省更多的钱，而不是通过跳过对选定更改的测试来节省钱。

### 通过 CI 进行合并测试

现实是复杂的。如果功能分支上的代码通过了所有测试，并不意味着当它合并到稳定主干分支时构建不会失败。在*Git flow*和*GitHub flow*部分提到的两种流行的分支策略都假设合并到`master`分支的代码总是经过测试并可部署。但是如果你还没有执行合并，你怎么能确定这个假设是成立的呢？对于*Git flow*来说，这个问题相对较小（如果实施得当并且使用得当），因为它强调发布分支。但对于简单的*GitHub flow*来说，这是一个真正的问题，因为合并到`master`通常会导致冲突，并且很可能会引入测试回归。即使对于*Git flow*来说，这也是一个严重的问题。这是一个复杂的分支模型，所以当人们使用它时肯定会犯错误。因此，如果你不采取特殊预防措施，你永远无法确定合并后`master`上的代码是否会通过测试。

解决这个问题的一个方法是将合并功能分支到稳定主干分支的责任委托给你的 CI 系统。在许多 CI 工具中，你可以轻松地设置一个按需构建作业，该作业将在本地合并特定功能分支到稳定分支，并且只有在通过了所有测试后才将其推送到中央仓库。如果构建失败，那么这样的合并将被撤销，使稳定分支保持不变。当然，在快节奏的项目中，这种方法会变得更加复杂，因为同时开发许多功能分支会存在高风险的冲突，这些冲突无法被任何 CI 系统自动解决。当然，针对这个问题也有解决方案，比如在 Git 中进行变基。

如果你考虑进一步实施持续交付流程，或者如果你的工作流程严格规定稳定分支中的所有内容都是可发布的，那么将任何东西合并到版本控制系统的稳定分支中实际上是必须的。

### 矩阵测试

如果你的代码需要在不同的环境中进行测试，矩阵测试是一个非常有用的工具。根据你的项目需求，你的 CI 解决方案对这种功能的直接支持可能更或更少需要。

解释矩阵测试的最简单方法是以一些开源的 Python 软件包为例。例如，Django 是一个严格指定支持的 Python 语言版本的项目。1.9.3 版本列出了运行 Django 代码所需的 Python 2.7、Python 3.4 和 Python 3.5 版本。这意味着每次 Django 核心开发人员对项目进行更改时，必须在这三个 Python 版本上执行完整的测试套件，以支持这一说法。如果在一个环境中甚至有一个测试失败，整个构建必须标记为失败，因为可能违反了向后兼容性约束。对于这样一个简单的情况，你不需要 CI 的任何支持。有一个很棒的 Tox 工具（参见[`tox.readthedocs.org/`](https://tox.readthedocs.org/)），除了其他功能外，它还允许你在隔离的虚拟环境中轻松运行不同 Python 版本的测试套件。这个实用程序也可以很容易地用于本地开发。

但这只是最简单的例子。不少应用程序必须在多个环境中进行测试，其中必须测试完全不同的参数。举几个例子：

+   不同的操作系统

+   不同的数据库

+   不同版本的后备服务

+   不同类型的文件系统

完整的组合形成了一个多维环境参数矩阵，这就是为什么这样的设置被称为矩阵测试。当你需要这样一个深层测试工作流程时，很可能需要一些集成支持来进行矩阵测试。对于可能的组合数量很大，你还需要一个高度可并行化的构建过程，因为每次在矩阵上运行都需要大量的工作来自你的构建服务器。在某些情况下，如果你的测试矩阵有太多维度，你将被迫做一些权衡。

## 持续交付

持续交付是持续集成思想的一个简单延伸。这种软件工程方法旨在确保应用程序可以随时可靠地发布。持续交付的目标是在短时间内发布软件。它通常通过允许将应用程序的变更逐步交付到生产环境中来降低成本和发布软件的风险。

构建成功的持续交付过程的主要先决条件是：

+   可靠的持续集成过程

+   自动部署到生产环境的流程（如果项目有生产环境的概念）

+   一个明确定义的版本控制系统工作流程或分支策略，允许你轻松定义哪个软件版本代表可发布的代码

在许多项目中，自动化测试并不足以可靠地告诉你软件的给定版本是否真的准备好发布。在这种情况下，通常由熟练的 QA 人员执行额外的手动用户验收测试。根据你的项目管理方法论，这可能还需要客户的批准。这并不意味着如果你的验收测试必须由人工手动执行，你就不能使用*Git flow*、*GitHub flow*或类似的分支策略。这只是将你的稳定和发布分支的语义从*准备部署*更改为*准备进行用户验收测试和批准*。

此外，前面的段落并不改变代码部署应始终自动化的事实。我们已经在第六章中讨论了一些工具和自动化的好处，*部署代码*。正如在那里所述，它将始终降低新版本发布的成本和风险。此外，大多数可用的 CI 工具都允许你设置特殊的构建目标，而不是测试，将为你执行自动化部署。在大多数持续交付过程中，这通常是由授权人员手动触发的，当他们确信已经获得了必要的批准并且所有验收测试都以成功结束时。

## 持续部署

持续部署是将持续交付推向更高水平的过程。对于所有验收测试都是自动化的项目来说，这是一个完美的方法，而且不需要客户的手动批准。简而言之，一旦代码合并到稳定分支（通常是`master`），它就会自动部署到生产环境。

这种方法似乎非常好和稳健，但并不经常使用，因为很难找到一个不需要在发布新版本之前进行手动 QA 测试和某人批准的项目。无论如何，这是可行的，一些公司声称他们正在以这种方式工作。

为了实现持续部署，你需要与持续交付过程相同的基本先决条件。此外，对合并到稳定分支的更加谨慎的方法通常是必需的。在持续集成中合并到`master`的内容通常会立即进入生产环境。因此，将合并任务交给你的 CI 系统是合理的，就像在*通过 CI 进行合并测试*部分中所解释的那样。

## 持续集成的流行工具

现在有大量的持续集成工具可供选择。它们在易用性和可用功能上有很大的差异，几乎每一个都有一些其他工具缺乏的独特功能。因此，很难给出一个好的一般性建议，因为每个项目的需求完全不同，开发工作流也不同。当然，有一些很棒的免费开源项目，但付费托管服务也值得研究。这是因为尽管像 Jenkins 或 Buildbot 这样的开源软件可以免费安装，但错误地认为它们是免费运行的。拥有自己的 CI 系统还需要硬件和维护成本。在某些情况下，支付这样的服务可能比支付额外的基础设施成本和花费时间解决开源 CI 软件中的任何问题更便宜。但是，你需要确保将代码发送到任何第三方服务是否符合公司的安全政策。

在这里，我们将回顾一些流行的免费开源工具，以及付费托管服务。我真的不想为任何供应商做广告，所以我们只讨论那些对开源项目免费提供的工具，以证明这种相当主观的选择。我们不会给出最佳建议，但我们会指出任何解决方案的优缺点。如果你还在犹豫不决，下一节描述常见持续集成陷阱的部分应该能帮助你做出明智的决定。

### Jenkins

Jenkins ([`jenkins-ci.org`](https://jenkins-ci.org)) 似乎是最受欢迎的持续集成工具。它也是这一领域最古老的开源项目之一，与 Hudson 一起（这两个项目的开发分离，Jenkins 是 Hudson 的一个分支）。

![Jenkins](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_08_07.jpg)

图 7 Jenkins 主界面预览

Jenkins 是用 Java 编写的，最初主要用于构建用 Java 语言编写的项目。这意味着对于 Java 开发人员来说，它是一个完美的 CI 系统，但如果您想将其与其他技术栈一起使用，可能需要花费一些精力。

Jenkins 的一个重大优势是其非常广泛的功能列表，这些功能已经直接实现在 Jenkins 中。从 Python 程序员的角度来看，最重要的功能是能够理解测试结果。Jenkins 不仅提供有关构建成功的简单二进制信息，还能够以表格和图形的形式呈现运行期间执行的所有测试的结果。当然，这不会自动工作，您需要以特定格式提供这些结果（默认情况下，Jenkins 理解 JUnit 文件）在构建期间。幸运的是，许多 Python 测试框架能够以机器可读的格式导出结果。

以下是 Jenkins 在其 Web UI 中单元测试结果的示例演示：

![Jenkins](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_08_08.jpg)

图 8 展示了 Jenkins 中单元测试结果

以下截图说明了 Jenkins 如何呈现额外的构建信息，例如趋势或可下载的构建产物：

![Jenkins](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_08_09.jpg)

图 9 示例 Jenkins 项目上的测试结果趋势图

令人惊讶的是，Jenkins 的大部分功能并不来自其内置功能，而是来自一个庞大的免费插件库。从干净的安装中可用的内容对于 Java 开发人员可能很棒，但使用不同技术的程序员将需要花费大量时间使其适用于其项目。甚至对 Git 的支持也是由一些插件提供的。

Jenkins 如此易于扩展是很棒的，但这也有一些严重的缺点。您最终将依赖于安装的插件来驱动您的持续集成过程，这些插件是独立于 Jenkins 核心开发的。大多数流行插件的作者都会尽力使其与 Jenkins 的最新版本保持兼容并及时更新。然而，较小社区的扩展将更新频率较低，有一天您可能不得不放弃它们或推迟核心系统的更新。当需要紧急更新（例如安全修复）时，这可能是一个真正的问题，但您的 CI 过程中一些关键插件将无法与新版本一起使用。

提供主 CI 服务器的基本 Jenkins 安装也能够执行构建。这与其他 CI 系统不同，其他系统更加注重分发并严格区分主构建服务器和从构建服务器。这既有利也有弊。一方面，它允许您在几分钟内设置一个完全工作的 CI 服务器。当然，Jenkins 支持将工作推迟到构建从节点，因此在未来需要时可以进行扩展。另一方面，Jenkins 通常性能不佳，因为它部署在单服务器设置中，其用户抱怨性能问题而未为其提供足够的资源。向 Jenkins 集群添加新的构建节点并不困难。对于那些习惯于单服务器设置的人来说，这似乎更多是一种心理挑战而不是技术问题。

### Buildbot

Buildbot ([`buildbot.net/`](http://buildbot.net/))是一个用 Python 编写的软件，可以自动化任何类型的软件项目的编译和测试周期。它可以配置为对源代码存储库上的每个更改生成一些构建，启动一些测试，然后提供一些反馈：

![Buildbot](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_08_10.jpg)

图 10 CPython 3.x 分支的 Buildbot 瀑布视图

例如，CPython 核心使用此工具，可以在[`buildbot.python.org/all/waterfall?&category=3.x.stable`](http://buildbot.python.org/all/waterfall?&category=3.x.stable)中找到。

Buildbot 的默认构建结果表示是一个瀑布视图，如*图 10*所示。每一列对应一个**构建**，由**步骤**组成，并与一些**构建** **从机**相关联。整个系统由构建主机驱动：

+   构建主机集中和驱动一切

+   构建是用于构建应用程序并对其运行测试的一系列步骤

+   一个**步骤**是一个原子命令，例如：

+   检出项目的文件

+   构建应用程序

+   运行测试

构建从机是负责运行构建的机器。只要它能够连接到构建主机，它可以位于任何位置。由于这种架构，Buildbot 的扩展性非常好。所有繁重的工作都是在构建从机上完成的，你可以拥有任意数量的构建从机。

Buildbot 的设计非常简单和清晰，使其非常灵活。每个构建步骤只是一个单独的命令。Buildbot 是用 Python 编写的，但它完全与语言无关。因此，构建步骤可以是任何东西。进程退出代码用于决定步骤是否以成功结束，步骤命令的所有标准输出默认情况下都会被捕获。大多数测试工具和编译器遵循良好的设计实践，并使用适当的退出代码指示失败，并在`stdout`或`stderr`输出流中返回可读的错误/警告消息。如果这不是真的，通常可以很容易地用 Bash 脚本包装它们。在大多数情况下，这是一个简单的任务。由于这个原因，许多项目可以只需很少的努力就可以与 Buildbot 集成。

Buildbot 的另一个优势是，它支持许多版本控制系统，无需安装任何额外的插件：

+   CVS

+   Subversion

+   Perforce

+   Bzr

+   Darcs

+   Git

+   Mercurial

+   Monotone

Buildbot 的主要缺点是缺乏用于呈现构建结果的高级呈现工具。例如，其他项目（如 Jenkins）可以考虑在构建过程中运行的单元测试。如果你用适当的格式（通常是 XML）呈现测试结果数据，它们可以以表格和图形的形式呈现所有测试。Buildbot 没有这样的内置功能，这是它为了灵活性和简单性所付出的代价。如果你需要一些额外的功能，你需要自己构建它们或者寻找一些定制的扩展。另一方面，由于这种简单性，更容易推理 Buildbot 的行为并维护它。因此，总是有一个权衡。

### Travis CI

Travis CI ([`travis-ci.org/`](https://travis-ci.org/))是一个以软件即服务形式出售的持续集成系统。对企业来说是付费服务，但在 GitHub 上托管的开源项目中可以完全免费使用。

![Travis CI](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_08_11.jpg)

图 11 django-userena 项目的 Travis CI 页面显示了构建矩阵中的失败构建

当然，这是它定价计划中的免费部分，这使它非常受欢迎。目前，它是 GitHub 上托管的项目中最受欢迎的 CI 解决方案之一。但与 Buildbot 或 Jenkins 等旧项目相比，最大的优势在于构建配置的存储方式。所有构建定义都在项目存储库的根目录中的一个`.travis.yml`文件中提供。Travis 只与 GitHub 一起工作，因此如果你启用了这样的集成，你的项目将在每次提交时进行测试，只要有一个`.travis.yml`文件。

在项目的代码存储库中拥有整个 CI 配置确实是一个很好的方法。这使得整个过程对开发人员来说更加清晰，也允许更灵活性。在必须提供构建配置以单独构建服务器的系统中（使用 Web 界面或通过服务器配置），当需要向测试装置添加新内容时，总会有一些额外的摩擦。在一些只有选定员工被授权维护 CI 系统的组织中，这确实减慢了添加新构建步骤的过程。而且，有时需要使用完全不同的程序测试代码的不同分支。当构建配置在项目源代码中可用时，这样做就容易得多。

Travis 的另一个重要特性是它强调在干净的环境中运行构建。每个构建都在一个完全新的虚拟机中执行，因此没有一些持久状态会影响构建结果的风险。Travis 使用一个相当大的虚拟机镜像，因此您可以使用许多开源软件和编程环境，而无需额外安装。在这个隔离的环境中，您拥有完全的管理权限，因此可以下载和安装任何您需要执行构建的东西，而`.travis.yml`文件的语法使其非常容易。不幸的是，您对可用的操作系统没有太多选择。Travis 不允许提供自己的虚拟机镜像，因此您必须依赖提供的非常有限的选项。通常根本没有选择，所有构建都必须在某个版本的 Ubuntu 或 Mac OS X 中进行（在撰写本书时仍处于实验阶段）。有时可以选择系统的某个旧版本或新测试环境的预览，但这种可能性总是暂时的。总是有办法绕过这一点。您可以在 Travis 提供的虚拟机内运行另一个虚拟机。这应该是一些允许您在项目源代码中轻松编码虚拟机配置的东西，比如 Vagrant 或 Docker。但这将增加构建的时间，因此这不是您将采取的最佳方法。以这种方式堆叠虚拟机可能不是在不同操作系统下执行测试的最佳和最有效的方法。如果这对您很重要，那么这表明 Travis 不适合您。

Travis 最大的缺点是它完全锁定在 GitHub 上。如果您想在开源项目中使用它，那么这不是什么大问题。对于企业和闭源项目，这基本上是一个无法解决的问题。

### GitLab CI

GitLab CI 是 GitLab 项目的一部分。它既可以作为付费服务（企业版）提供，也可以作为您自己基础设施上托管的开源项目（社区版）提供。开源版本缺少一些付费服务功能，但在大多数情况下，它是任何公司从管理版本控制存储库和持续集成的软件中所需要的一切。

GitLab CI 在功能集方面与 Travis 非常相似。它甚至使用存储在`.gitlab-ci.yml`文件中的非常相似的 YAML 语法进行配置。最大的区别在于，GitLab 企业版定价模型不为开源项目提供免费帐户。社区版本身是开源的，但您需要拥有一些自己的基础设施才能运行它。

与 Travis 相比，GitLab 在执行环境上具有明显的优势。不幸的是，在环境隔离方面，GitLab 的默认构建运行程序略逊一筹。名为 Gitlab Runner 的进程在相同的环境中执行所有构建步骤，因此它更像 Jenkins 或 Buildbot 的从属服务器。幸运的是，它与 Docker 兼容，因此你可以通过基于容器的虚拟化轻松添加更多隔离，但这需要一些努力和额外的设置。在 Travis 中，你可以立即获得完全隔离。

## 选择合适的工具和常见陷阱

正如前面所说，没有完美的 CI 工具适用于每个项目，更重要的是，适用于每个组织和使用的工作流。我只能为托管在 GitHub 上的开源项目提供一个建议。对于平台无关代码的小型代码库，Travis CI 似乎是最佳选择。它易于开始，并且几乎可以立即获得最小量的工作的满足感。

对于闭源项目来说，情况完全不同。可能需要在不同的设置中评估几个 CI 系统，直到能够决定哪一个最适合你。我们只讨论了四种流行的工具，但这应该是一个相当代表性的群体。为了让你的决定变得更容易一些，我们将讨论一些与持续集成系统相关的常见问题。在一些可用的 CI 系统中，可能会比其他系统更容易犯某些类型的错误。另一方面，一些问题可能对每个应用程序都不重要。我希望通过结合你的需求的知识和这个简短的总结，能够更容易地做出正确的第一个决定。

### 问题 1 - 构建策略太复杂

一些组织喜欢在合理的水平之外正式化和结构化事物。在创建计算机软件的公司中，这在两个领域尤其真实：项目管理工具和 CI 服务器上的构建策略。

过度配置项目管理工具通常会导致在 JIRA（或任何其他管理软件）上处理问题工作流程变得如此复杂，以至于无法用图表表示。如果你的经理有这种配置/控制狂，你可以和他谈谈，或者换一个经理（即：辞职）。不幸的是，这并不能可靠地保证在这方面有任何改进。

但是当涉及到 CI 时，我们可以做更多。持续集成工具通常由我们开发人员维护和配置。这些是我们的工具，应该改善我们的工作。如果有人对每个开关和旋钮都有无法抗拒的诱惑，那么他应该远离 CI 系统的配置，尤其是如果他的主要工作是整天说话和做决定。

没有必要制定复杂的策略来决定哪个提交或分支应该被测试。也不需要将测试限制在特定的标签上。也不需要排队提交以执行更大的构建。也不需要通过自定义提交消息禁用构建。你的持续集成过程应该简单易懂。测试一切！一直测试！就这样！如果没有足够的硬件资源来测试每个提交，那就增加更多的硬件。记住，程序员的时间比硅片更贵。

### 问题 2 - 构建时间太长

长时间的构建是任何开发人员的性能杀手。如果你需要等待几个小时才能知道你的工作是否做得正确，那么你就无法高效地工作。当然，在测试功能时有其他事情要做会有所帮助。无论如何，作为人类，我们真的很擅长多任务处理。在不同问题之间切换需要时间，并且最终会将我们的编程性能降至零。在同时处理多个问题时，保持专注是非常困难的。

解决方案非常简单：不惜一切代价保持构建速度快。首先，尝试找到瓶颈并对其进行优化。如果构建服务器的性能是问题，那么尝试扩展。如果这没有帮助，那么将每个构建拆分成较小的部分并并行化。

有很多解决方案可以加快缓慢的构建测试，但有时候这个问题无法解决。例如，如果你有自动化的浏览器测试或需要对外部服务进行长时间调用，那么很难在某个硬性限制之外提高性能。例如，当你的 CI 中自动接受测试的速度成为问题时，你可以放松*测试一切，始终测试*的规则。对程序员来说，最重要的通常是单元测试和静态分析。因此，根据你的工作流程，缓慢的浏览器测试有时可以推迟到准备发布时。

解决缓慢构建运行的另一个方法是重新思考应用程序的整体架构设计。如果测试应用程序需要很长时间，很多时候这是一个信号，表明它应该被拆分成几个可以独立开发和测试的组件。将软件编写为庞大的单体是通往失败的最短路径之一。通常，任何软件工程过程都会因为软件没有适当模块化而失败。

### 问题 3 - 外部作业定义

一些持续集成系统，特别是 Jenkins，允许你完全通过 Web UI 设置大部分构建配置和测试过程，而无需触及代码存储库。但你真的应该避免将除构建步骤/命令的简单入口之外的任何东西放入外部系统。这是一种可能会带来麻烦的 CI 反模式。

你的构建和测试过程通常与你的代码库紧密相关。如果你将其整个定义存储在 Jenkins 或 Buildbot 等外部系统中，那么要对该过程进行更改将非常困难。

举一个由全局外部构建定义引入的问题的例子，假设我们有一些开源项目。最初的开发很忙碌，我们并不关心任何样式指南。我们的项目很成功，所以开发需要另一个重大发布。过了一段时间，我们从`0.x`版本移动到`1.0`，并决定重新格式化所有代码以符合 PEP 8 指南。将静态分析检查作为 CI 构建的一部分是一个很好的方法，所以我们决定将`pep8`工具的执行添加到我们的构建定义中。如果我们只有一个全局外部构建配置，那么如果需要对旧版本的代码进行改进，就会出现问题。假设应用程序的两个分支：`0.x`和`1.y`都需要修复一个关键的安全问题。我们知道 1.0 版本以下的任何内容都不符合样式指南，而新引入的针对 PEP 8 的检查将标记构建为失败。

解决问题的方法是尽可能将构建过程的定义与源代码保持接近。对于一些 CI 系统（如 Travis CI 和 GitLab CI），您默认就可以得到这样的工作流程。对于其他解决方案（如 Jenkins 和 Buildbot），您需要额外小心，以确保大部分构建过程都包含在您的代码中，而不是一些外部工具配置中。幸运的是，您有很多选择可以实现这种自动化。

+   Bash 脚本

+   Makefiles

+   Python 代码

### 问题 4 - 缺乏隔离

我们已经多次讨论了在 Python 编程时隔离的重要性。我们知道在包级别上隔离 Python 执行环境的最佳方法是使用 `virtualenv` 或 `python -m venv`。不幸的是，在测试代码以进行持续集成流程的目的时，通常还不够。测试环境应尽可能接近生产环境，而要在没有额外的系统级虚拟化的情况下实现这一点确实很困难。

在构建应用程序时，如果不确保适当的系统级隔离，可能会遇到的主要问题有：

+   在构建之间持久存在的一些状态，无论是在文件系统上还是在后备服务中（缓存、数据库等）

+   通过环境、文件系统或后备服务进行多个构建或测试的接口

+   由于生产操作系统的特定特性而可能发生的问题没有在构建服务器上被捕捉到

如果您需要对同一应用程序执行并发构建，甚至并行化单个构建，上述问题尤为棘手。

一些 Python 框架（主要是 Django）为数据库提供了一些额外的隔离级别，试图确保在运行测试之前存储将被清理。`py.test` 还有一个非常有用的扩展叫做 `pytest-dbfixtures`（参见 [`github.com/ClearcodeHQ/pytest-dbfixtures`](https://github.com/ClearcodeHQ/pytest-dbfixtures)），它甚至可以更可靠地实现这一点。无论如何，这样的解决方案会增加构建的复杂性，而不是减少它。始终在每次构建时清除虚拟机（类似于 Travis CI 的风格）似乎是一种更优雅、更简单的方法。

# 总结

我们在本章中学到了以下内容：

+   集中式和分布式版本控制系统之间有什么区别

+   为什么您应该更喜欢分布式版本控制系统而不是集中式

+   为什么 Git 应该是您选择分布式版本控制系统的首选

+   Git 的常见工作流程和分支策略是什么

+   什么是持续集成/交付/部署，以及允许您实施这些流程的流行工具是什么

下一章将解释如何清晰地记录您的代码。


# 第九章：记录你的项目

文档经常被开发者忽视，有时也被管理者忽视。这往往是由于在开发周期结束时缺乏时间，以及人们认为自己写作水平不佳。其中一些确实写得不好，但大多数人能够制作出良好的文档。

无论如何，结果都是由匆忙写成的文档组成的混乱文档。大多数时候，开发者都讨厌做这种工作。当需要更新现有文档时，情况变得更糟。许多项目只提供质量低劣、过时的文档，因为管理者不知道如何处理它。

但在项目开始时建立文档流程，并将文档视为代码模块，可以使文档编写变得更容易。遵循一些规则时，写作甚至可以成为一种乐趣。

本章提供了一些开始记录项目的提示：

+   总结最佳实践的技术写作的七条规则

+   reStructuredText 入门，这是 Python 项目中使用的纯文本标记语法

+   构建良好项目文档的指南

# 技术写作的七条规则

写好文档在许多方面比写代码更容易。大多数开发者认为这很难，但遵循一套简单的规则后，它变得非常容易。

我们这里讨论的不是写一本诗集，而是一篇全面的文本，可以用来理解设计、API 或构成代码库的任何内容。

每个开发者都能够制作这样的材料，本节提供了七条规则，可以在所有情况下应用：

+   **分两步写**：先关注想法，然后再审查和塑造你的文本。

+   **针对读者群**：谁会阅读它？

+   **使用简单的风格**：保持简洁明了。使用良好的语法。

+   **限制信息的范围**：一次引入一个概念。

+   **使用现实的代码示例**："Foos"和"bars"应该避免。

+   **使用轻量但足够的方法**：你不是在写一本书！

+   **使用模板**：帮助读者养成习惯。

这些规则大多受到 Andreas Rüping 的《敏捷文档：软件项目轻量级文档的模式指南》（Wiley）的启发和改编，该书侧重于在软件项目中制作最佳文档。

## 分两步写

Peter Elbow 在《写作的力量：掌握写作过程的技巧》（牛津大学出版社）中解释说，任何人几乎不可能一次写出完美的文本。问题在于，许多开发者写文档并试图直接得到一些完美的文本。他们成功的唯一方法是在每写两个句子后停下来阅读它们并做一些修改。这意味着他们同时关注文本的内容和风格。

这对大脑来说太难了，结果往往不如预期的那么好。在完全思考其含义之前，花费了大量时间和精力来打磨文本的风格和形状。

另一种方法是放弃文本的风格和组织，专注于其内容。所有想法都被记录在纸上，无论它们是如何书写的。开发者开始写一个连续的流，不会在犯语法错误或任何与内容无关的事情时停下来。例如，只要想法被写下来，句子几乎无法理解并不重要。他/她只是以粗略的组织写下他想说的话。

通过这样做，开发者专注于他/她想要表达的内容，可能会从他/她的头脑中得到比最初想象的更多的内容。

进行自由写作时的另一个副作用是，与主题无关的其他想法会很容易浮现在脑海中。一个好的做法是，当它们出现时，在第二张纸或屏幕上把它们写下来，这样它们就不会丢失，然后回到主要写作上。

第二步是回读整个文本，并对其进行润色，使其对每个人都能理解。润色文本意味着增强其风格，纠正其错误，稍微重新组织它，并删除任何多余的信息。

当写作文档的时间有限时，一个好的做法是将这段时间分成两半——一半用于写作内容，一半用于清理和组织文本。

### 注意

专注于内容，然后是风格和整洁。

## 针对读者群

在撰写内容时，作家应考虑一个简单的问题：*谁会阅读它？*

这并不总是显而易见，因为技术文本解释了软件的工作原理，并且通常是为可能获得和使用代码的每个人而写的。读者可能是正在寻找适当技术解决方案的研究人员，或者需要用它实现功能的开发人员。设计师也可能会阅读它，以了解包是否从架构的角度符合他/她的需求。

良好的文档应遵循一个简单的规则——每个文本只应有一种读者。

这种理念使写作变得更容易。作家清楚地知道自己正在与何种读者打交道。他/她可以提供简明而准确的文档，而不是模糊地面向各种读者。

一个好的做法是提供一个简短的介绍性文本，简要解释文档的内容，并引导读者到适当的部分：

```py
Atomisator is a product that fetches RSS feeds and saves them in a database, with a filtering process.

If you are a developer, you might want to look at the API description (api.txt)

If you are a manager, you can read the features list and the FAQ (features.txt)

If you are a designer, you can read the architecture and infrastructure notes (arch.txt)
```

通过这种方式引导读者，你可能会产生更好的文档。

### 注意

在开始写作之前了解你的读者群。

## 使用简单的风格

塞思·戈丁是营销领域畅销书作家之一。你可能想阅读《Ideavirus 的释放》，哈希特图书，它可以在互联网上免费获取。

不久前，他在博客上进行了一项分析，试图理解为什么他的书卖得这么好。他列出了营销领域所有畅销书的清单，并比较了它们每句话的平均字数。

他意识到他的书每句话的字数最少（十三个字）。塞思解释说，这个简单的事实证明读者更喜欢简短而简单的句子，而不是长而时髦的句子。

通过保持句子简短和简单，你的写作将消耗更少的大脑力量来提取、处理和理解其内容。技术文档的撰写旨在为读者提供软件指南。它不是一部小说，应该更接近你的微波炉使用说明书，而不是最新的斯蒂芬·金小说。

要牢记的一些建议是：

+   使用简单的句子。句子不应超过两行。

+   每个段落应由三到四个句子组成，最多表达一个主要观点。让你的文本有呼吸空间。

+   不要重复太多。避免新闻报道风格，其中的想法一遍又一遍地重复，以确保它们被理解。

+   不要使用多种时态。大多数情况下，现在时就足够了。

+   如果你不是一个真正优秀的作家，就不要在文本中开玩笑。在技术文本中搞笑真的很难，很少有作家能掌握。如果你真的想表达一些幽默，把它放在代码示例中，你就没问题了。

### 注意

你不是在写小说，所以尽量保持风格简单。

## 限制信息范围

在软件文档中有一个简单的坏迹象——你正在寻找一些你知道存在的信息，但找不到它。在阅读目录表一段时间后，你开始在文件中使用 grep 尝试几个单词组合，但找不到你要找的东西。

当作者没有按主题组织他们的文本时，就会发生这种情况。他们可能提供了大量的信息，但它只是以单一或非逻辑的方式聚集在一起。例如，如果读者正在寻找你的应用程序的整体情况，他或她不应该阅读 API 文档——那是一个低级的问题。

为了避免这种效果，段落应该被聚集在一个有意义的标题下，全局文档标题应该用简短的短语来概括内容。

目录可以由所有章节的标题组成。

组成标题的一个简单做法是问自己，“我会在 Google 中输入什么短语来找到这个部分？”

## 使用现实的代码示例

*Foo*和*bar*是不好的用法。当读者试图理解代码片段的工作方式时，如果有一个不切实际的例子，将会使理解变得更加困难。

为什么不使用一个真实的例子呢？一个常见的做法是确保每个代码示例都可以在真实的程序中剪切和粘贴。

为了展示一个糟糕的用法示例，让我们假设我们想展示如何使用`parse()`函数：

```py
>>> from atomisator.parser import parse
>>> # Let's use it:
>>> stuff = parse('some-feed.xml')
>>> next(stuff)
{'title': 'foo', 'content': 'blabla'}

```

一个更好的例子是，当解析器知道如何使用 parse 函数返回一个 feed 内容时，它作为一个顶级函数可用：

```py
>>> from atomisator.parser import parse
>>> # Let's use it:
>>> my_feed = parse('http://tarekziade.wordpress.com/feed')
>>> next(my_feed)
{'title': 'eight tips to start with python', 'content': 'The first tip is..., ...'}

```

这种细微的差别可能听起来有些过分，但事实上它会使你的文档更有用。读者可以将这些行复制到 shell 中，理解 parse 使用 URL 作为参数，并且它返回一个包含博客条目的迭代器。

当然，提供一个现实的例子并不总是可能或可行的。这对于非常通用的代码尤其如此。即使这本书中也有一些模糊的`foo`和`bar`字符串的出现，其中名称上下文并不重要。无论如何，你应该始终努力将这种不切实际的例子的数量减少到最低。

### 注意

代码示例应该直接在真实程序中可重用。

## 使用轻量但足够的方法

在大多数敏捷方法论中，文档不是第一位的。使软件正常工作比详细的文档更重要。因此，一个好的做法，正如 Scott Ambler 在他的书《敏捷建模：极限编程和统一过程的有效实践》中所解释的那样，是定义真正的文档需求，而不是创建详尽的文档集。

例如，让我们看一个简单项目的文档示例——`ianitor`——它在 GitHub 上可用[`github.com/ClearcodeHQ/ianitor`](https://github.com/ClearcodeHQ/ianitor)。这是一个帮助在 Consul 服务发现集群中注册进程的工具，因此主要面向系统管理员。如果你看一下它的文档，你会意识到这只是一个单一的文档（`README.md`文件）。它只解释了它的工作原理和如何使用它。从管理员的角度来看，这是足够的。他们只需要知道如何配置和运行这个工具，没有其他人群预期使用`ianitor`。这个文档通过回答一个问题来限制其范围，“我如何在我的服务器上使用`ianitor`？”

## 使用模板

维基百科上的每一页都很相似。一侧有用于总结日期或事实的框。文件的开头是一个带有链接的目录，这些链接指向同一文本中的锚点。最后总是有一个参考部分。

用户习惯了。例如，他们知道他们可以快速查看目录，如果找不到所需信息，他们将直接转到参考部分，看看是否可以在该主题上找到另一个网站。这对维基百科上的任何页面都适用。你学会了*维基百科方式*，更有效率。

因此，使用模板强制了文档的通用模式，因此使人们更有效地使用它们。他们习惯了结构并知道如何快速阅读它。

为每种文档提供模板也为作者提供了快速入门。

# reStructuredText 入门

reStructuredText 也被称为 reST（参见[`docutils.sourceforge.net/rst.html`](http://docutils.sourceforge.net/rst.html)）。它是一种纯文本标记语言，在 Python 社区广泛用于文档化包。reST 的好处在于文本仍然可读，因为标记语法不像 LaTeX 那样混淆文本。

这是这样一个文档的示例：

```py
=====
Title
=====

Section 1
=========
This *word* has emphasis.

Section 2
=========

Subsection
::::::::::

Text.
```

reST 包含在`docutils`中，该软件包提供了一套脚本，可将 reST 文件转换为各种格式，如 HTML、LaTeX、XML，甚至是 S5，Eric Meyer 的幻灯片系统（参见[`meyerweb.com/eric/tools/s5`](http://meyerweb.com/eric/tools/s5)）。

作者可以专注于内容，然后根据需要决定如何呈现它。例如，Python 本身是用 reST 文档化的，然后呈现为 HTML 以构建[`docs.python.org`](http://docs.python.org)，以及其他各种格式。

开始写 reST 所需了解的最少元素是：

+   部分结构

+   列表

+   内联标记

+   文字块

+   链接

本节是语法的快速概述。更多信息可在以下网址找到快速参考：[`docutils.sourceforge.net/docs/user/rst/quickref.html`](http://docutils.sourceforge.net/docs/user/rst/quickref.html)，这是开始使用 reST 的好地方。

要安装 reStructuredText，安装`docutils`：

```py
$ pip install docutils

```

例如，由`docutils`包提供的`rst2html`脚本将根据 reST 文件生成 HTML 输出：

```py
$ more text.txt
Title
=====

content.

$ rst2html.py text.txt
<?xml version="1.0" encoding="utf-8" ?>
...
<html ...>
<head>
...
</head>
<body>
<div class="document" id="title">
<h1 class="title">Title</h1>
<p>content.</p>
</div>
</body>
</html>

```

## 部分结构

文档的标题及其各节使用非字母数字字符进行下划线。它们可以被上下划线覆盖，并且一种常见的做法是为标题使用这种双重标记，并为各节保持简单的下划线。

用于下划线部分标题的最常用字符按优先顺序排列：`=, -, _, :, #, +, ^`。

当一个字符用于一个部分时，它与其级别相关联，并且必须在整个文档中一致使用。

例如，考虑以下代码：

```py
==============
Document title
==============

Introduction to the document content.

Section 1
=========

First document section with two subsections.

Note the ``=`` used as heading underline.

Subsection A
------------

First subsection (A) of Section 1.

Note the ``-`` used as heading underline.

Subsection B
------------
Second subsection (B) of Section 1.

Section 2
=========

Second section of document with one subsection.

Subsection C
------------

Subsection (C) of Section 2.
```

![部分结构](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_09_01.jpg)

图 1 reStructuredText 转换为 HTML 并在浏览器中呈现

## 列表

reST 为项目列表、编号列表和具有自动编号功能的定义列表提供可读的语法：

```py
Bullet list:

- one
- two
- three

Enumerated list:

1\. one
2\. two
#. auto-enumerated

Definition list:

one
    one is a number.

two
    two is also a number.
```

![列表](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_09_02.jpg)

图 2 不同类型的列表呈现为 HTML

## 内联标记

文本可以使用内联标记进行样式化：

+   `*强调*`：斜体

+   `**强调**`：粗体

+   `inline preformated`：内联预格式化文本（通常是等宽的，类似终端）

+   ``带有链接的文本`_`：只要在文档中提供了它（请参阅*链接*部分），它将被替换为超链接

## 文字块

当您需要展示一些代码示例时，可以使用文字块。两个冒号用于标记块，这是一个缩进的段落：

```py
This is a code example

::

    >>> 1 + 1
    2

Let's continue our text
```

### 注意

不要忘记在`::`后和块后添加空行，否则它将无法呈现。

请注意，冒号字符可以放在文本行中。在这种情况下，它们将在各种呈现格式中被替换为单个冒号：

```py
This is a code example::

    >>> 1 + 1
    2

Let's continue our text
```

如果不想保留单个冒号，可以在前导文本和`::`之间插入一个空格。在这种情况下，`::`将被解释并完全删除。

![文字块](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_09_03.jpg)

图 3 reST 中呈现为 HTML 的代码示例

## 链接

只要提供在文档中，文本就可以通过以两个点开头的特殊行更改为外部链接：

```py
Try `Plone CMS`_, it is great ! It is based on Zope_.

.. _`Plone CMS`: http://plone.org
.. _Zope: http://zope.org
```

通常的做法是将外部链接分组放在文档的末尾。当要链接的文本包含空格时，必须用`` ` ``（反引号）字符括起来。

通过在文本中添加标记，也可以使用内部链接：

```py

This is a code example

.. _example:

::

    >>> 1 + 1
    2

Let's continue our text, or maybe go back to
the example_.
```

还可以使用目标作为部分：

```py

==============
Document title
==============

Introduction to the document content.


Section 1
=========

First document section.


Section 2
=========

-> go back to `Section 1`_
```

# 搭建文档

引导读者和作者更简单的方法是为每个人提供助手和指南，就像我们在本章的前一节中学到的那样。

从作者的角度来看，这是通过具有一组可重用的模板以及描述何时何地在项目中使用它们的指南来完成的。这被称为**文档投资组合**。

从读者的角度来看，能够毫无困难地浏览文档并有效地查找信息是很重要的。通过构建一个**文档景观**来实现。

## 构建投资组合

软件项目可能有许多种类的文档，从直接参考代码的低级文档到提供应用程序高级概述的设计论文。

例如，Scott Ambler 在他的书 *敏捷建模：极限编程和统一过程的有效实践* 中定义了一个广泛的文档类型列表，*约翰·威利和儿子*。他从早期规格到操作文档构建了一个投资组合。甚至项目管理文档也包括在内，因此整个文档需求都建立在一套标准化的模板集合上。

由于完整的投资组合与用于构建软件的方法密切相关，本章将只关注你可以根据自己的特定需求完成的常见子集。构建高效的投资组合需要很长时间，因为它涵盖了你的工作习惯。

软件项目中的一组常见文档可以分为三类：

+   **设计**：这包括所有提供架构信息和低级设计信息的文档，如类图或数据库图

+   **用法**：这包括所有关于如何使用软件的文档；这可以是烹饪书和教程或模块级别的帮助

+   **操作**：这提供了有关如何部署、升级或操作软件的指南

### 设计

创建此类文档的重要点是确保目标读者群体完全了解，内容范围受限。因此，设计文档的通用模板可以提供轻量级结构，并为作者提供一点建议。

这样的结构可能包括：

+   标题

+   作者

+   标签（关键字）

+   描述（摘要）

+   目标（谁应该阅读这个？）

+   内容（含图表）

+   引用其他文档

打印时，内容应为三至四页，以确保范围受限。如果内容变得更大，应将其拆分为几个文档或进行摘要。

该模板还提供了作者的姓名和一系列标签，以管理其发展并便于分类。这将在本章后面介绍。

在 reST 中的示例设计文档模板可以如下所示：

```py

=========================================
Design document title
=========================================

:Author: Document Author
:Tags: document tags separated with spaces

:abstract:

    Write here a small abstract about your design document.

.. contents ::


Audience
========

Explain here who is the target readership.


Content
=======

Write your document here. Do not hesitate to split it in several sections.


References
==========

Put here references, and links to other documents.
```

### 用法

使用文档描述了软件的特定部分如何使用。 此文档可以描述低级部分，例如函数的工作原理，但也可以描述高级部分，例如调用程序的命令行参数。 这是框架应用程序中文档的最重要部分，因为目标读者主要是将重用代码的开发人员。

三种主要类型的文档是：

+   **配方**：这是一份简短的文档，解释如何做某事。 这种文档针对一个读者群，重点是一个特定主题。

+   **教程**：这是一份逐步解释如何使用软件功能的文档。 这个文档可以参考配方，每个实例都针对一个读者群。

+   **模块助手**：这是一份低级文档，解释模块包含什么内容。 例如，当您调用模块上的`help`内置时，可以显示此文档。

#### 配方

配方回答了一个非常具体的问题，并提供了解决方案以解决它。 例如，ActiveState 在线提供了一个巨大的 Python 配方库，开发人员可以在其中描述如何在 Python 中做某事（参见[`code.activestate.com/recipes/langs/python/`](http://code.activestate.com/recipes/langs/python/)）。 这样一个与单一领域/项目相关的配方集合通常称为*食谱*。

这些配方必须简短，结构如下：

+   标题

+   提交者

+   最后更新

+   版本

+   类别

+   描述

+   来源（源代码）

+   讨论（解释代码的文本）

+   评论（来自 Web）

往往只有一个屏幕长，不会详细说明。 这种结构非常适合软件的需要，并且可以适应通用结构，在这个结构中，添加了目标读者，并用标签替换了类别：

+   标题（简短的句子）

+   作者

+   标签（关键词）

+   谁应该阅读这个？

+   先决条件（要阅读的其他文档，例如）

+   问题（简短描述）

+   解决方案（主要内容，一个或两个屏幕）

+   引用（链接到其他文档）

这里的日期和版本不太有用，因为项目文档应该像项目中的源代码一样管理。 这意味着最好的处理文档的方法是通过版本控制系统进行管理。 在大多数情况下，这与用于项目代码的代码存储库完全相同。

一个简单的可重用的模板，用于配方，可以如下所示：

```py

===========
Recipe name
===========

:Author: Recipe Author
:Tags: document tags separated with spaces

:abstract:

    Write here a small abstract about your design document.

.. contents ::


Audience
========

Explain here who is the target readership.


Prerequisites
=============

Write the list of prerequisites for implementing this recipe. This can be additional documents, software, specific libraries, environment settings or just anything that is required beyond the obvious language interpreter.


Problem
=======

Explain the problem that this recipe is trying to solve.


Solution
========

Give solution to problem explained earlier. This is the core of a recipe.


References
==========

Put here references, and links to other documents.
```

#### 教程

教程与配方在目的上有所不同。 它不是为了解决一个孤立的问题，而是描述如何逐步使用应用程序的功能。 这可能比配方长，并且可能涉及应用程序的许多部分。 例如，Django 在其网站上提供了一系列教程。 *编写你的第一个 Django 应用程序，第一部分*（参见[`docs.djangoproject.com/en/1.9/intro/tutorial01/`](https://docs.djangoproject.com/en/1.9/intro/tutorial01/)）简要解释了如何使用 Django 构建应用程序的几个屏幕。

这种文档的结构将是：

+   标题（简短的句子）

+   作者

+   标签 (单词)

+   描述（摘要）

+   谁应该阅读这个？

+   先决条件（要阅读的其他文档，例如）

+   教程（主要文本）

+   参考文献 (链接到其他文档)

#### 模块助手

我们收集的最后一个模板是模块助手模板。模块助手指的是单个模块，并提供其内容的描述以及用法示例。

一些工具可以通过提取文档字符串并使用`pydoc`来计算模块帮助来自动生成这样的文档，例如 Epydoc（参见 [`epydoc.sourceforge.net`](http://epydoc.sourceforge.net)）。因此，可以基于 API 内省生成广泛的文档。这种类型的文档通常在 Python 框架中提供。例如，Plone 提供了一个 [`api.plone.org`](http://api.plone.org) 服务器，保存了一个最新的模块助手集合。

这种方法的主要问题有：

+   没有进行对真正有趣的模块的智能选择

+   文档可以使代码变得晦涩难懂

此外，模块文档提供的示例有时涉及模块的几个部分，很难将其分割为函数和类文档字符串之间。模块文档字符串可以通过在模块顶部编写文本来用于这一目的。但这会导致具有一段文本而非代码块的混合文件。当代码占总长度的不到 50%时，这会导致混淆。如果你是作者，这很正常。但当人们尝试阅读代码（而不是文档）时，他们将不得不跳过文档字符串部分。

另一种方法是将文本分开存储在自己的文件中。然后可以进行手动选择，决定哪个 Python 模块将拥有自己的模块助手文件。然后，文档可以从代码库中分离出来，允许它们独立存在，就像我们将在下一部分看到的那样。这就是 Python 的文档方式。

许多开发人员对文档和代码分离是否比文档字符串更好持不同意见。这种方法意味着文档过程完全集成在开发周期中； 否则它将很快变得过时。文档字符串方法通过提供代码和使用示例之间的接近性来解决了这个问题，但并未将其提升到更高的水平——可以作为纯文档的一部分使用的文档。

模块助手的模板非常简单，因为在编写内容之前它只包含一些元数据。目标未定义，因为希望使用该模块的是开发人员：

+   标题（模块名称）

+   作者

+   标签 (单词)

+   内容

### 注意

下一章将涵盖使用 doctests 和模块助手进行测试驱动开发。

### 操作

操作文档用于描述如何操作软件。例如，请考虑以下几点：

+   安装和部署文档

+   管理文档

+   常见问题（FAQ）文档

+   解释人们如何贡献、寻求帮助或提供反馈的文档

这些文档非常具体，但它们可能可以使用在前面一节中定义的教程模板。

# 制作你自己的作品集

我们之前讨论的模板只是你可以用来记录软件的基础。随着时间的推移，你最终会开发出自己的模板和文档风格。但始终要记住轻量但足够的项目文档编写方法：每个添加的文档都应该有一个明确定义的目标读者群，并填补一个真实的需求。不增加真实价值的文档不应该被写入。

每个项目都是独特的，有不同的文档需求。例如，具有简单使用的小型终端工具绝对可以只使用单个`README`文件作为其文档景观。如果目标读者被精确定义并始终分组（例如系统管理员），那么采用这种最小单文档方法完全可以接受。

同样，不要过于严格地应用提供的模板。例如，在大型项目或严格规范化的团队中，提供的一些附加元数据作为示例真的很有用。例如，标签旨在提高大型文档中的文本搜索，但在只包含几个文档的文档景观中将不提供任何价值。

此外，包括文档作者并不总是一个好主意。这种方法在开源项目中可能尤其值得怀疑。在这类项目中，你会希望社区也为文档做出贡献。在大多数情况下，这样的文档在需要时会由任何人不断更新。人们往往也会将文档的 *作者* 视为文档的 *所有者*。如果每个文档都明确指定了作者，这可能会阻止人们更新文档。通常，版本控制软件提供了关于真实文档作者的更清晰、更透明的信息，而不是提供明确的元数据注释。确实建议明确指定作者的情况是各种设计文档，特别是在设计过程严格规范化的项目中。最好的例子是 Python 语言增强提案系列（PEP）文档。

## 构建景观

在前一节中构建的文档组合在文档级别提供了一个结构，但没有提供一种组织和分类来构建读者将拥有的文档。这就是安德烈亚斯·鲁平格所称的文档景观，指的是读者在浏览文档时使用的心智地图。他得出结论，组织文档的最佳方式是构建一个逻辑树。

换句话说，组成作品集的不同类型的文档需要在目录树中找到一个存放的位置。当作者创建文档时，这个位置对他们来说必须是明显的；当读者寻找文档时，这个位置对他们也必须是明显的。

浏览文档时一个很大的帮助是每个级别都有索引页面可以引导作者和读者。

构建文档景观有两个步骤：

+   为制片人（作者）构建一个树

+   在制片人树的基础上为消费者（读者）构建一个树

制片人和消费者之间的区别很重要，因为它们以不同的方式访问文档，而且使用不同的格式。

### 制片人布局

从制片人的角度来看，每个文档都要像 Python 模块一样处理。它应该存储在版本控制系统中，并且像代码一样工作。作者不关心他们的散文最终的外观和可用性，他们只是想确保他们在写一篇文档，因此它是有关主题的唯一真相来源。存储在文件夹树中的 reStructuredText 文件与软件代码一起存储在版本控制系统中，并且是制片人构建文档景观的方便解决方案。

按照惯例，`docs`文件夹被用作文档树的根：

```py

$ cd my-project
$ find docs
docs
docs/source
docs/source/design
docs/source/operations
docs/source/usage
docs/source/usage/cookbook
docs/source/usage/modules
docs/source/usage/tutorial
```

注意，这个树位于一个`source`文件夹中，因为`docs`文件夹将被用作下一节中设置特殊工具的根文件夹。

从那里，可以在每个级别（除了根目录）添加一个`index.txt`文件，解释文件夹包含什么类型的文档或总结每个子文件夹包含的内容。这些索引文件可以定义它们所包含的文档列表。例如，`operations`文件夹可以包含一个可用的操作文档列表：

```py

==========
Operations
==========

This section contains operations documents:

− How to install and run the project
− How to install and manage a database for the project
It is important to know that people tend to forget 

```

需要知道的是，人们往往会忘记更新这些文档列表和目录。因此最好是自动更新它们。在下一小节，我们将讨论一个工具，它除了许多其他功能之外，也可以处理这种情况。

### 消费者的布局

从消费者的角度来看，重要的是制作出索引文件，并以易于阅读和美观的格式呈现整个文档。网页是最好的选择，也很容易从 reStructuredText 文件中生成。

**Sphinx** ([`sphinx.pocoo.org`](http://sphinx.pocoo.org)) 是一组脚本和`docutils`扩展，可以用来从我们的文本树生成 HTML 结构。这个工具被用于（例如）构建 Python 文档，并且现在有许多项目都在用它来编写文档。其中内置的功能之一是，它生成了一个真正好用的浏览系统，还有一个轻量但足够的客户端 JavaScript 搜索引擎。它还使用`pygments`来渲染代码示例，因此产生了非常好的语法高亮。

Sphinx 可以轻松配置为与前一节中定义的文档方向保持一致。它可以使用`pip`轻松安装为`Sphinx`包。

与 Sphinx 一起工作的最简单方法是使用`sphinx-quickstart`脚本。此实用程序将生成一个脚本和`Makefile`，可用于在需要时生成 Web 文档。它将交互式地询问您一些问题，然后引导整个初始文档源树和配置文件。一旦完成，您可以随时轻松调整它。假设我们已经引导了整个 Sphinx 环境，并且我们想要查看其 HTML 表示。这可以通过使用`make html`命令轻松完成：

```py

project/docs$ make html
sphinx-build -b html -d _build/doctrees   . _build/html
Running Sphinx v1.3.6
making output directory...
loading pickled environment... not yet created
building [mo]: targets for 0 po files that are out of date
building [html]: targets for 1 source files that are out of date
updating environment: 1 added, 0 changed, 0 removed
reading sources... [100%] index
looking for now-outdated files... none found
pickling environment... done
checking consistency... done
preparing documents... done
writing output... [100%] index
generating indices... genindex
writing additional pages... search
copying static files... done
copying extra files... done
dumping search index in English (code: en) ... done
dumping object inventory... done
build succeeded.
Build finished. The HTML pages are in _build/html.

```

![消费者布局](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/5295_09_04.jpg)

图 4 使用 Sphinx 构建的文档的示例 HTML 版本 - [`graceful.readthedocs.org/en/latest/`](http://graceful.readthedocs.org/en/latest/)

除了文档的 HTML 版本外，该工具还构建了自动页面，例如模块列表和索引。Sphinx 提供了一些`docutils`扩展来驱动这些功能。主要的是：

+   构建目录的指令

+   可用于将文档注册为模块助手的标记

+   添加索引中的元素的标记

#### 处理索引页面

Sphinx 提供了一个`toctree`指令，可用于在文档中注入带有指向其他文档链接的目录。每行必须是具有其相对路径的文件，从当前文档开始。还可以提供 Glob 样式名称以添加匹配表达式的多个文件。

例如，`cookbook`文件夹中的索引文件，我们之前在生产者景观中定义的，可以是这样的：

```py

========
Cookbook
========

Welcome to the Cookbook.

Available recipes:

.. toctree::
   :glob:
   *

```

使用这种语法，HTML 页面将显示`cookbook`文件夹中所有可用的 reStructuredText 文档的列表。此指令可用于所有索引文件中以构建可浏览的文档。

#### 注册模块助手

对于模块助手，可以添加标记，以便它自动列在模块的索引页面中并可用：

```py

=======
session
=======

.. module:: db.session

The module session...

```

注意，这里的`db`前缀可以用来避免模块冲突。Sphinx 将其用作模块类别，并将以`db.`开头的所有模块分组到此类别中。

#### 添加索引标记

还可以使用另一个选项填充索引页面，将文档链接到条目：

```py
=======
session
=======

.. module:: db.session

.. index::
   Database Access
   Session

The module session...

```

将在索引页面中添加两个新条目，`Database Access`和`Session`。

#### 交叉引用

最后，Sphinx 提供了一种内联标记来设置交叉引用。例如，可以这样链接到模块：


```py

:mod:`db.session`

```

在这里，`:mod:`是模块标记的前缀，``db.session``是要链接到的模块的名称（如之前注册的）；请记住，`：mod:`以及之前的元素都是 Sphinx 在 reSTructuredText 中引入的特定指令。

### 注意

Sphinx 提供了更多功能，您可以在其网站上发现。例如，*autodoc*功能是自动提取您的 doctests 以构建文档的一个很好的选项。请参阅[`sphinx.pocoo.org`](http://sphinx.pocoo.org)。

## 文档构建和持续集成

Sphinx 确实提高了从消费者角度阅读文档的可读性和体验。正如前面所说的，当其部分与代码紧密耦合时，特别有帮助，比如 dosctrings 或模块助手。虽然这种方法确实使得确保文档的源版本与其所记录的代码匹配变得更容易，但并不能保证文档读者能够访问到最新和最新的编译版本。

如果文档的目标读者不熟练使用命令行工具，也不知道如何将其构建成可浏览和可读的形式，那么仅有最小的源表示也是不够的。这就是为什么在代码存储库发生任何更改时，自动将文档构建成消费者友好的形式非常重要。

使用 Sphinx 托管文档的最佳方式是生成 HTML 构建，并将其作为静态资源提供给您选择的 Web 服务器。Sphinx 提供了适当的`Makefile`来使用`make html`命令构建 HTML 文件。因为`make`是一个非常常见的实用工具，所以很容易将这个过程与第八章中讨论的任何持续集成系统集成，*管理代码*。

如果您正在使用 Sphinx 记录一个开源项目，那么使用**Read the Docs**（[`readthedocs.org/`](https://readthedocs.org/)）会让您的生活变得轻松很多。这是一个免费的服务，用于托管使用 Sphinx 的开源 Python 项目的文档。配置完全无忧，而且非常容易与两个流行的代码托管服务集成：GitHub 和 Bitbucket。实际上，如果您的账户正确连接并且代码存储库正确设置，启用 Read the Docs 上的文档托管只需要点击几下。

# 总结

本章详细解释了如何：

+   使用一些高效写作的规则

+   使用 reStructuredText，Python 程序员的 LaTeX

+   构建文档组合和布局

+   使用 Sphinx 生成有用的 Web 文档

在记录项目时最难的事情是保持准确和最新。将文档作为代码存储库的一部分使得这变得更容易。从那里，每当开发人员更改一个模块时，他或她也应该相应地更改文档。

在大型项目中可能会很困难，在这种情况下，在模块头部添加相关文档列表可以有所帮助。

确保文档始终准确的一个补充方法是通过 doctests 将文档与测试结合起来。这将在下一章中介绍，该章节将介绍测试驱动开发原则，然后是文档驱动开发。
