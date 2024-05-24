# C++ 系统编程实用指南（三）

> 原文：[`zh.annas-archive.org/md5/F0907D5DE5A0BFF31E8751590DCE27D9`](https://zh.annas-archive.org/md5/F0907D5DE5A0BFF31E8751590DCE27D9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：学习编程控制台输入/输出

控制台 IO 对于任何程序都是必不可少的。它可以用于获取用户输入，提供输出，并支持调试和诊断。程序不稳定的常见原因通常源于 IO 编写不佳，这只会加剧标准 C `printf()`/`scanf()` IO 函数的滥用。在本章中，我们将讨论使用 C++ IO 的利弊，通常称为基于流的 IO，与标准 C 风格的替代方法相比。此外，我们将提供一个关于 C++操作器的高级介绍，以及它们如何可以用来替代标准 C 风格的格式字符串。我们将以一组示例结束本章，旨在引导读者如何使用`std::cout`和`std::cin`。

本章有以下目标：

+   学习基于流的 IO

+   用户定义的类型操作器

+   回声的例子

+   串行回声服务器示例

# 技术要求

为了编译和执行本章中的示例，读者必须具备：

+   能够编译和执行 C++17 的基于 Linux 的系统（例如，Ubuntu 17.10+）

+   GCC 7+

+   CMake 3.6+

+   互联网连接

要下载本章中的所有代码，包括示例和代码片段，请参阅以下 GitHub 链接：[`github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/tree/master/Chapter06`](https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/tree/master/Chapter06)。

# 学习基于流的 IO

在本节中，我们将学习基于流的 IO 的基础知识以及一些优缺点。

# 流的基础知识

与 C 风格的`printf()`和`scanf()`函数不同，C++ IO 使用流（`std::ostream`用于输出，`std::istream`用于输入），利用`<<`和`>>`操作符。例如，以下代码使用`basic_ostream`的非成员`<<`重载将`Hello World`输出到`stdout`：

```cpp
#include <iostream>

int main()
{
    std::cout << "Hello World\n";
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
Hello World
```

默认情况下，`std::cout`和`std::wcout`对象是`std::ostream`的实例，将数据输出到标准 C `stdout`，唯一的区别是`std::wcout`支持 Unicode，而`std::cout`支持 ASCII。除了几个非成员重载外，C++还提供了以下算术风格的成员重载：

```cpp
basic_ostream &operator<<(short value);
basic_ostream &operator<<(unsigned short value);
basic_ostream &operator<<(int value);
basic_ostream &operator<<(unsigned int value);
basic_ostream &operator<<(long value);
basic_ostream &operator<<(unsigned long value);
basic_ostream &operator<<(long long value);
basic_ostream &operator<<(unsigned long long value);
basic_ostream &operator<<(float value);
basic_ostream &operator<<(double value);
basic_ostream &operator<<(long double value);
basic_ostream &operator<<(bool value);
basic_ostream &operator<<(const void* value);
```

这些重载可以用于将各种类型的数字流到`stdout`或`stderr`。考虑以下例子：

```cpp
#include <iostream>

int main()
{
    std::cout << "The answer is: " << 42 << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 42
```

默认情况下，使用`stdin`进行输入，通过`std::cin`和`std::wcin`执行输入。与`std::cout`不同，`std::cin`使用`>>`流操作符，而不是`<<`流操作符。以下接受来自`stdin`的输入并将结果输出到`stdout`：

```cpp
#include <iostream>

int main()
{
    auto n = 0;

    std::cin >> n; 
    std::cout << "input: " << n << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
42 ↵
input: 42
```

# C++基于流的 IO 的优缺点

使用 C++进行 IO 而不是标准 C 函数有许多优缺点。

# C++基于流的 IO 的优点

通常情况下，C++流优于使用格式说明符的标准 C 函数，因为 C++流具有以下特点：

+   能够处理用户定义的类型，提供更清晰、类型安全的 IO

+   更安全，可以防止更多的意外缓冲区溢出漏洞，因为并非所有格式说明符错误都可以被编译器检测到或使用 C11 添加的`_s` C 函数变体来预防

+   能够提供隐式内存管理，不需要可变参数函数

因此，C++核心指南不鼓励使用格式说明符，包括`printf()`、`scanf()`等函数。尽管使用 C++流有许多优点，但也有一些缺点。

# C++基于流的 IO 的缺点

关于 C++流的两个最常见的抱怨如下：

+   标准 C 函数（特别是`printf()`）通常优于 C++流（这在很大程度上取决于您的操作系统和 C++实现）

+   格式说明符通常比`#include <iomanip>`更灵活

尽管这些通常是有效的抱怨，但有方法可以解决这些问题，而不必牺牲 C++流的优势，我们将在接下来的部分中解释。

# 从用户定义的类型开始

C++流提供了为用户定义的类型重载`<<`和`>>`运算符的能力。这提供了为任何数据类型创建自定义、类型安全的 IO 的能力，包括系统级数据类型、结构，甚至更复杂的类型，如类。例如，以下提供了对`<<`流运算符的重载，以打印由 POSIX 风格函数提供的错误代码：

```cpp
#include <fcntl.h>
#include <string.h>
#include <iostream>

class custom_errno
{ };

std::ostream &operator<<(std::ostream &os, const custom_errno &e)
{ return os << strerror(errno); }

int main()
{
    if (open("filename.txt", O_RDWR) == -1) {
        std::cout << custom_errno{} << '\n';
    }
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
No such file or directory
```

在这个例子中，我们创建了一个空类，为我们提供了一个自定义类型，并重载了这个自定义类型的`<<`运算符。然后我们使用`strerror()`来输出`errno`的错误字符串到提供的输出流。虽然可以通过直接将`strerror()`的结果输出到流中来实现这一点，但它演示了如何创建并使用流的用户定义类型。

除了更复杂的类型，用户定义的类型也可以通过输入流进行利用。考虑以下例子：

```cpp
#include <iostream>

struct object_t
{
    int data1;
    int data2;
};

std::ostream &operator<<(std::ostream &os, const object_t &obj)
{
    os << "data1: " << obj.data1 << '\n';
    os << "data2: " << obj.data2 << '\n';
    return os;
}

std::istream &operator>>(std::istream &is, object_t &obj)
{
    is >> obj.data1;
    is >> obj.data2;
    return is;
}

int main()
{
    object_t obj;

    std::cin >> obj;
    std::cout << obj;
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
42 ↵
43 ↵
data1: 42
data2: 43
```

在这个例子中，我们创建了一个存储两个整数的结构。然后我们为这个用户定义的类型重载了`<<`和`>>`运算符，通过读取数据到我们类型的实例来练习这些重载，然后输出结果。通过我们的重载，我们已经指示了`std::cin`和`std::cout`如何处理我们用户定义的类型的输入和输出。

# 安全和隐式内存管理

尽管 C++流仍然可能存在漏洞，但与它们的标准 C 对应物相比，这种可能性较小。使用标准 C 的`scanf()`函数进行缓冲区溢出的经典示例如下：

```cpp
#include <stdio.h>

int main()
{
    char buf[2];
    scanf("%s", buf);
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is 42 ↵
*** stack smashing detected ***: <unknown> terminated
Aborted (core dumped)
```

用户输入的缓冲区大于为该缓冲区分配的空间，导致缓冲区溢出的情况。在这个例子中增加`buf`的大小不会解决问题，因为用户总是可以输入一个比提供的缓冲区更大的字符串。这个问题可以通过在`scanf()`上指定长度限制来解决：

```cpp
#include <stdio.h>

int main()
{
    char buf[2];
    scanf("%2s", buf);
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is 42 ↵
```

在这里，我们向`scanf()`函数提供了`buf`的大小，防止了缓冲区溢出。这种方法的问题是`buf`的大小声明了两次。如果这两者中的一个改变了，就可能重新引入缓冲区溢出。可以使用 C 风格的宏来解决这个问题，但缓冲区和其大小的解耦仍然存在。

虽然还有其他方法可以用 C 来解决这个问题，但解决 C++中前面提到的问题的一种方法如下：

```cpp
#include <iomanip>
#include <iostream>

template<std::size_t N>
class buf_t
{
    char m_buf[N];

public:

    constexpr auto size()
    { return N; }

    constexpr auto data()
    { return m_buf; }
};

template<std::size_t N>
std::istream &operator>>(std::istream &is, buf_t<N> &b)
{
    is >> std::setw(b.size()) >> b.data();
    return is;
}

int main()
{
    buf_t<2> buf;
    std::cin >> buf;
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is 42 ↵
```

我们不是使用`*` char，而是创建一个封装`*` char 及其长度的用户定义类型。缓冲区的总大小与缓冲区本身耦合在一起，防止意外的缓冲区溢出。然而，如果允许内存分配（在编程系统中并非总是如此），我们可以做得更好：

```cpp
#include <string>
#include <iostream>

int main()
{
    std::string buf;
    std::cin >> buf;
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is 42 ↵
```

在这个例子中，我们使用`std::string`来存储从`std::cin`输入的内容。这里的区别在于`std::string`根据需要动态分配内存来存储输入，防止可能的缓冲区溢出。如果需要更多的内存，就分配更多的内存，或者抛出`std::bad_alloc`并中止程序。C++流的用户定义类型提供了更安全的处理 IO 的机制。

# 常见的调试模式

在编程系统中，控制台输出的主要用途之一是调试。C++流提供了两个不同的全局对象——`std::cout`和`std::cerr`。第一个选项`std::cout`通常是缓冲的，发送到`stdout`，并且只有在发送到流的`std::flush`或`std::endl`时才会刷新。第二个选项`std::cerr`提供了与`std::cout`相同的功能，但是发送到`stderr`而不是`stdout`，并且在每次调用全局对象时都会刷新。看一下以下的例子：

```cpp
#include <iostream>

int main()
{
    std::cout << "buffered" << '\n';
    std::cout << "buffer flushed" << std::endl;
    std::cerr << "buffer flushed" << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
buffer
buffer flushed
buffer flushed
```

因此，错误逻辑通常使用`std::cerr`发送到`stderr`，以确保在发生灾难性问题时接收所有错误控制台输出。同样，一般输出，包括调试逻辑，使用`std::cout`发送到`stdout`，以利用缓冲加快控制台输出速度，并且使用`'\n'`发送换行而不是`std::endl`，除非需要显式刷新。

以下是 C 语言中调试的典型模式：

```cpp
#include <iostream>

#ifndef NDEBUG
#define DEBUG(...) fprintf(stdout, __VA_ARGS__);
#else
#define DEBUG(...)
#endif

int main()
{
    DEBUG("The answer is: %d\n", 42);
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 42
```

如果启用了调试，通常意味着定义了`NDEBUG`，则可以使用`DEBUG`宏将调试语句发送到控制台。使用`NDEBUG`是因为这是大多数编译器设置为发布模式时定义的宏，禁用了标准 C 中的`assert()`。另一个常见的调试模式是为调试宏提供调试级别，允许开发人员在调试时调整程序的详细程度：

```cpp
#include <iostream>

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif

#ifndef NDEBUG
#define DEBUG(level,...) \
    if(level <= DEBUG_LEVEL) fprintf(stdout, __VA_ARGS__);
#else
#define DEBUG(...)
#endif

int main()
{
    DEBUG(0, "The answer is: %d\n", 42);
    DEBUG(1, "The answer no is: %d\n", 43);
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 42
```

这种逻辑的问题在于过度使用宏来实现调试，这是 C++核心指南不赞成的模式。使用 C++17 进行调试的简单方法如下：

```cpp
#include <iostream>

#ifdef NDEBUG
constexpr auto g_ndebug = true;
#else
constexpr auto g_ndebug = false;
#endif

int main()
{
    if constexpr (!g_ndebug) {
        std::cout << "The answer is: " << 42 << '\n';
    }
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 42
```

即使使用了 C++17，仍然需要一些宏逻辑来处理启用调试时编译器提供的`NDEBUG`宏。在这个例子中，`NDEBUG`宏被转换为`constexpr`，然后在源代码中用于处理调试。调试级别也可以使用以下方式实现：

```cpp
#include <iostream>

#ifdef DEBUG_LEVEL
constexpr auto g_debug_level = DEBUG_LEVEL;
#else
constexpr auto g_debug_level = 0;
#endif

#ifdef NDEBUG
constexpr auto g_ndebug = true;
#else
constexpr auto g_ndebug = false;
#endif

int main()
{
    if constexpr (!g_ndebug && (0 <= g_debug_level)) {
        std::cout << "The answer is: " << 42 << '\n';
    }

    if constexpr (!g_ndebug && (1 <= g_debug_level)) {
        std::cout << "The answer is not: " << 43 << '\n';
    }
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 42
```

由于在这个例子中调试级别是一个编译时特性，它将使用`-DDEBUG_LEVEL=xxx`传递给编译器，因此仍然需要宏逻辑将 C 宏转换为 C++的`constexpr`。正如在这个例子中所看到的，C++实现比利用`fprintf()`和其他函数的简单`DEBUG`宏要复杂得多。为了克服这种复杂性，我们将利用封装，而不会牺牲编译时优化：

```cpp
#include <iostream>

#ifdef DEBUG_LEVEL
constexpr auto g_debug_level = DEBUG_LEVEL;
#else
constexpr auto g_debug_level = 0;
#endif

#ifdef NDEBUG
constexpr auto g_ndebug = true;
#else
constexpr auto g_ndebug = false;
#endif

template <std::size_t LEVEL>
constexpr void debug(void(*func)()) {
    if constexpr (!g_ndebug && (LEVEL <= g_debug_level)) {
        func();
    };
}

int main()
{
    debug<0>([] {
        std::cout << "The answer is: " << 42 << '\n';
    });

    debug<1>([] {
        std::cout << "The answer is not: " << 43 << '\n';
    });
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 42
```

在这个例子中，调试逻辑被封装为一个接受 Lambda 的`constexpr`函数。调试级别使用模板参数来保持常数。与典型的标准 C 调试模式不同，这个实现将接受任何适合于`void(*func)()`函数或 lambda 的调试逻辑，并且与标准 C 版本一样，在编译器设置为发布模式时将被编译和移除（即定义了`NDEBUG`并且通常启用了优化）。为了证明这一点，当启用发布模式时，GCC 7.3 输出如下内容：

```cpp
> g++ -std=c++17 -O3 -DNDEBUG scratchpad.cpp; ./a.out
> ls -al a.out
-rwxr-xr-x 1 user users 8600 Apr 13 18:23 a.out

> readelf -s a.out | grep cout
```

当在源代码中添加`#undef NDEBUG`时，GCC 7.3 输出如下内容（确保唯一的区别是调试逻辑被禁用，但编译标志保持不变）：

```cpp
> g++ -std=c++17 scratchpad.cpp; ./a.out
> ls -al a.out
-rwxr-xr-x 1 user users 8888 Apr 13 18:24 a.out

> readelf -s a.out | grep cout
    23: 0000000000201060 272 OBJECT GLOBAL DEFAULT 24 _ZSt4cout@GLIBCXX_3.4 (5)
    59: 0000000000201060 272 OBJECT GLOBAL DEFAULT 24 _ZSt4cout@@GLIBCXX_3.4
```

额外的 288 字节来自于调试逻辑，这些逻辑完全被编译器移除，这要归功于 C++17 中`constexpr`的常数性，提供了一种更清晰的调试方法，而无需大量使用宏。

另一个常见的调试模式是在调试语句中包含当前行号和文件名，以提供额外的上下文。`__LINE__`和`__FILE__`宏用于提供这些信息。遗憾的是，在 C++17 中没有包含源位置 TS，因此没有办法在没有这些宏的情况下提供这些信息，也没有类似以下模式的包含：

```cpp
#include <iostream>

#ifndef NDEBUG
#define DEBUG(fmt, args...) \
    fprintf(stdout, "%s [%d]: " fmt, __FILE__, __LINE__, args);
#else
#define DEBUG(...)
#endif

int main()
{
    DEBUG("The answer is: %d\n", 42);
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
scratchpad.cpp [11]: The answer is: 42
```

在这个例子中，`DEBUG`宏会自动将文件名和行号插入标准 C 风格的`fprintf()`函数中。这是因为无论编译器在哪里看到`DEBUG`宏，它都会插入`fprintf(stdout, "%s [%d]: " fmt, __FILE__, __LINE__, args);`，然后必须评估行和文件宏，从而产生预期的输出。将这种模式转换为我们现有的 C++示例的一个例子如下：

```cpp
#include <iostream>

#ifdef DEBUG_LEVEL
constexpr auto g_debug_level = DEBUG_LEVEL;
#else
constexpr auto g_debug_level = 0;
#endif

#ifdef NDEBUG
constexpr auto g_ndebug = true;
#else
constexpr auto g_ndebug = false;
#endif

#define console std::cout << __FILE__ << " [" << __LINE__ << "]: "

template <std::size_t LEVEL>
constexpr void debug(void(*func)()) {
    if constexpr (!g_ndebug && (LEVEL <= g_debug_level)) {
        func();
    };
}

int main()
{
    debug<0>([] {
        console << "The answer is: " << 42 << '\n';
    });
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
scratchpad.cpp [27]: The answer is: 42
```

在我们的调试 lambda 中，我们不再使用`std::cout`，而是添加一个使用`std::cout`的控制台宏，但也将文件名和行号添加到调试语句中，以提供与标准 C 版本相同的功能。与标准 C 版本不同的是，不需要额外的 C 宏函数，因为控制台宏将正确提供使用的文件名和行号。

最后，为了完成我们的 C++17 调试模式，我们添加了一个带颜色的调试、警告和致命错误版本的前面示例，并为`fatal`函数添加了一个默认退出错误码为`-1`的重载版本。

首先，我们利用与前面代码片段中相同的标准 C 宏：

```cpp
#ifdef DEBUG_LEVEL
constexpr auto g_debug_level = DEBUG_LEVEL;
#else
constexpr auto g_debug_level = 0;
#endif

#ifdef NDEBUG
constexpr auto g_ndebug = true;
#else
constexpr auto g_ndebug = false;
#endif
```

这些宏将标准 C 风格的宏转换为 C++风格的常量表达式，这些宏在命令行兼容性中是必需的。接下来，我们创建一个名为`debug`的模板函数，能够接受一个 lambda 函数。这个`debug`函数首先将绿色的`debug`输出到`stdout`，然后执行 lambda 函数，只有在调试被启用并且调试级别与提供给`debug`函数本身的级别匹配时才执行。如果调试未启用，`debug`函数将在不影响程序大小或性能的情况下编译。

```cpp
template <std::size_t LEVEL>
constexpr void debug(void(*func)()) {
    if constexpr (!g_ndebug && (LEVEL <= g_debug_level)) {
        std::cout << "\033[1;32mDEBUG\033[0m ";
        func();
    };
}
```

这个相同的`debug`函数被重复使用来提供警告和致命错误版本的函数，唯一的区别是颜色（这是特定于平台的，在这种情况下是为 UNIX 操作系统设计的），而`fatal`函数在执行 lambda 函数后退出程序，退出时使用用户定义的错误码或`-1`。

```cpp
template <std::size_t LEVEL>
constexpr void warning(void(*func)()) {
    if constexpr (!g_ndebug && (LEVEL <= g_debug_level)) {
        std::cout << "\033[1;33mWARNING\033[0m ";
        func();
    };
}

template <std::size_t LEVEL>
constexpr void fatal(void(*func)()) {
    if constexpr (!g_ndebug && (LEVEL <= g_debug_level)) {
        std::cout << "\033[1;31mFATAL ERROR\033[0m ";
        func();
        ::exit(-1);
    };
}

template <std::size_t LEVEL>
constexpr void fatal(int error_code, void(*func)()) {
    if constexpr (!g_ndebug && (LEVEL <= g_debug_level)) {
        std::cout << "\033[1;31mFATAL ERROR\033[0m ";
        func();
        ::exit(error_code);
    };
}
```

最后，这些调试模式在`main()`函数中得到了应用，以演示它们的使用方法。

```cpp
int main()
{
    debug<0>([] {
        console << "The answer is: " << 42 << '\n';
    });

    warning<0>([] {
        console << "The answer might be: " << 42 << '\n';
    });

    fatal<0>([] {
        console << "The answer was not: " << 42 << '\n';
    });
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
DEBUG scratchpad.cpp [54]: The answer is: 42
WARNING scratchpad.cpp [58]: The answer might be: 42
FATAL ERROR scratchpad.cpp [62]: The answer was not: 42
```

# C++流的性能

关于 C++流的一个常见抱怨是性能问题，这个问题在多年来已经得到了很大的缓解。为了确保 C++流的最佳性能，可以应用一些优化：

+   **禁用 std::ios::sync_with_stdio**：C++流默认会与标准 C 函数（如`printf()`等）同步。如果不使用这些函数，应该禁用这个同步功能，因为这将显著提高性能。

+   **避免刷新**：在可能的情况下，避免刷新 C++流，让`libc++`和操作系统来处理刷新。这包括不使用`std::flush`，而是使用`'\n'`代替`std::endl`，后者在输出换行后会刷新。避免刷新时，所有输出都会被缓冲，减少了向操作系统传递输出的次数。

+   **使用 std::cout 和 std::clog 而不是 std::cerr**：出于同样的原因，`std::cerr`在销毁时会刷新，增加了操作系统传递输出的次数。在可能的情况下，应该使用`std::cout`，只有在出现致命错误后才使用`std::cerr`，例如退出、异常、断言和可能的崩溃。

对于问题“*哪个更快*，`printf()` *还是* `std::cout`*？*”，不可能提供一个一般性的答案。但实际上，如果使用了前面的优化，`std::cout`通常可以优于标准 C 的`printf()`，但这高度依赖于您的环境和用例。

除了前面的例子，避免不必要的刷新以提高性能的一种方法是使用`std::stringstream`而不是`std::cout`。

```cpp
#include <sstream>
#include <iostream>

int main()
{
    std::stringstream stream;
    stream << "The answer is: " << 42 << '\n';

    std::cout << stream.str() << std::flush;
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 42
```

通过使用`std::stringstream`，所有输出都被定向到您控制的缓冲区，直到您准备通过`std::cout`和手动刷新将输出发送到操作系统。这也可以用于缓冲输出到`std::cerr`，减少总刷新次数。避免刷新的另一种方法是使用`std::clog`：

```cpp
#include <iostream>

int main()
{
    std::clog << "The answer is: " << 42 << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 42
```

`std::clog`的操作方式类似于`std::cout`，但是不是将输出发送到`stdout`，而是将输出发送到`stderr`。

# 学习操纵器

C++流有几种不同的操纵器，可以用来控制输入和输出，其中一些已经讨论过。最常见的操纵器是`std::endl`，它输出一个换行符，然后刷新输出流：

```cpp
#include <iostream>

int main()
{
    std::cout << "Hello World" << std::endl;
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
Hello World
```

编写相同逻辑的另一种方法是使用`std::flush`操纵器：

```cpp
#include <iostream>

int main()
{
    std::cout << "Hello World\n" << std::flush;
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
Hello World
```

两者是相同的，尽管除非明确需要刷新，否则应始终使用`'\n'`。例如，如果需要多行，应首选以下方式：

```cpp
#include <iostream>

int main()
{
    std::cout << "Hello World\n";
    std::cout << "Hello World\n";
    std::cout << "Hello World\n";
    std::cout << "Hello World" << std::endl;
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
Hello World
Hello World
Hello World
Hello World
```

与前面的代码相比，以下代码不是首选：

```cpp
#include <iostream>

int main()
{
    std::cout << "Hello World" << std::endl;
    std::cout << "Hello World" << std::endl;
    std::cout << "Hello World" << std::endl;
    std::cout << "Hello World" << std::endl;
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
Hello World
Hello World
Hello World
Hello World
```

应该注意，不需要尾随刷新，因为`::exit()`在`main`完成时会为您刷新`stdout`。

在任何程序开始时设置的常见操纵器是`std::boolalpha`，它导致布尔值输出为`true`或`false`，而不是`1`或`0`（`std::noboolalpha`提供相反的效果，这也是默认值）：

```cpp
#include <iostream>

int main()
{
    std::cout << std::boolalpha;
    std::cout << "The answer is: " << true << '\n';
    std::cout << "The answer is: " << false << '\n';

    std::cout << std::noboolalpha;
    std::cout << "The answer is: " << true << '\n';
    std::cout << "The answer is: " << false << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: true
The answer is: false
The answer is: 1
The answer is: 0
```

另一组常见的操纵器是数字基操纵器——`std::hex`、`std::dec`和`std::oct`。这些操纵器类似于标准 C 格式说明符（例如`printf()`使用的`%d`、`%x`和`%o`）。与标准 C 版本不同，这些操纵器是全局的，因此在库中使用时应谨慎使用。要使用这些操纵器，只需在添加所需基数的数字之前将它们添加到流中：

```cpp
#include <iostream>

int main()
{
    std::cout << "The answer is: " << 42 << '\n' << std::hex 
              << "The answer is: " << 42 << '\n';
    std::cout << "The answer is: " << 42 << '\n' << std::dec 
              << "The answer is: " << 42 << '\n';
    std::cout << "The answer is: " << 42 << '\n' << std::oct 
              << "The answer is: " << 42 << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 42
The answer is: 2a
The answer is: 2a
The answer is: 42
The answer is: 42
The answer is: 52
```

第一个数字`42`打印为`42`，因为尚未使用任何数字基操纵器。第二个数字打印为`2a`，因为使用了`std::hex`操纵器，导致`2a`是`42`的十六进制值。打印的第三个数字也是`2a`，因为数字基操纵器是全局的，因此，即使第二次调用`std::cout`，流仍然被告知使用十六进制值而不是十进制值。这种模式对于`std::dec`（例如，十进制数）和`std::oct`（例如，八进制数）都是一样的，结果是`42`、`2a`、`2a`、`42`、`42`，最后是`52`。

还可以使用`std::hex`的大写版本，而不是前面示例中看到的默认小写版本。要实现这一点，使用`std::uppercase`和`std::nouppercase`（`std::uppercase`显示大写字母数字字符，而`std::nouppercase`不显示，这是默认值）：

```cpp
#include <iostream>

int main()
{
    std::cout << std::hex << std::uppercase << "The answer is: " 
              << 42 << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 2A
```

在这个例子中，`42`不再输出为`2a`，而是输出为`2A`，其中字母数字字符是大写的。

通常，特别是在编程系统方面，十六进制和八进制数以它们的基数标识符（例如`0x`和`0`）打印。要实现这一点，使用`std::showbase`和`std::noshowbase`操纵器（`std::showbase`显示基数，`std::noshowbase`不显示，这是默认值）：

```cpp
#include <iostream>

int main()
{
    std::cout << std::showbase;
    std::cout << std::hex << "The answer is: " << 42 << '\n';
    std::cout << std::dec << "The answer is: " << 42 << '\n';
    std::cout << std::oct << "The answer is: " << 42 << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 0x2a
The answer is: 42
The answer is: 052
```

从这个例子中可以看出，`std::hex`现在输出`0x2a`，而不是`2a`，`std::oct`输出`052`，而不是`52`，而`std::dec`继续按预期输出`42`（因为十进制数没有基数标识符）。与数字不同，指针始终以十六进制、小写形式输出，并显示它们的基数，`std::uppercase`、`std::noshowbase`、`std::dec`和`std::oct`不会影响输出。解决这个问题的一个方法是将指针转换为数字，然后可以使用前面的操纵器，如下例所示，但是 C++核心指南不鼓励这种逻辑，因为需要使用`reinterpret_cast`：

```cpp
#include <iostream>

int main()
{
    int i = 0;
    std::cout << &i << '\n';
    std::cout << std::hex << std::showbase << std::uppercase 
              << reinterpret_cast<uintptr_t>(&i) << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
0x7fff51d370b4
0X7FFF51D370B4
```

输出指针的一个问题是它们的总长度（即字符的总数）会从一个指针变化到另一个指针。当同时输出多个指针时，这通常会分散注意力，因为它们的基本修改器可能不匹配。为了克服这一点，可以使用`std::setw`和`std::setfill`。`std::setw`设置下一个输出的总宽度（即字符的总数）。如果下一个输出的大小不至少是传递给`std::setw`的值的大小，流将自动向流中添加空格：

```cpp
#include <iomanip>
#include <iostream>

int main()
{
    std::cout << "The answer is: " << std::setw(18) << 42 << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is:                 42
```

在这个例子中，宽度设置为`18`。由于流的下一个添加是两个字符（来自数字`42`），在将`42`添加到流之前添加了`16`个空格。要更改由`std::setw`添加到流中的字符，请使用`std::setfill`：

```cpp
#include <iomanip>
#include <iostream>

int main()
{
    std::cout << "The answer is: " << std::setw(18) << std::setfill('0') 
              << 42 << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 000000000000000042
```

可以看到，流中添加的不是空格（默认情况下），而是添加到流中的'0'字符。可以使用`std::left`，`std::right`和`std::internal`来控制添加到流中的字符的方向：

```cpp
#include <iomanip>
#include <iostream>

int main()
{
    std::cout << "The answer is: "
              << std::setw(18) << std::left << std::setfill('0')
              << 42 << '\n';

    std::cout << "The answer is: "
              << std::setw(18) << std::right << std::setfill('0')
              << 42 << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 420000000000000000
The answer is: 000000000000000042
```

`std::left`首先输出到流中，然后用剩余的字符填充流，而`std::right`用未使用的字符填充流，然后输出到流中。`std::internal`特定于使用基本标识符（如`std::hex`和`std::oct`）的文本以及使用`std::showbase`或自动显示基本标识符的指针。

```cpp
#include <iomanip>
#include <iostream>

int main()
{
    int i = 0;

    std::cout << std::hex
              << std::showbase;

    std::cout << "The answer is: "
              << std::setw(18) << std::internal << std::setfill('0')
              << 42 << '\n';

    std::cout << "The answer is: "
              << std::setw(18) << std::internal << std::setfill('0')
              << &i << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 0x000000000000002a
The answer is: 0x00007ffc074c9be4
```

通常，特别是在库中，设置一些操纵器然后将流恢复到其原始状态是有用的。例如，如果您正在编写一个库，并且想要以`hex`输出一个数字，您需要使用`std::hex`操纵器，但这样做会导致从那时起用户输出的所有数字也以`hex`输出。问题是，您不能简单地使用`std::dec`将流设置回十进制，因为用户可能实际上是首先使用`std::hex`。解决这个问题的一种方法是使用`std::cout.flags()`函数，它允许您获取和设置流的内部标志：

```cpp
#include <iostream>

int main()
{
    auto flags = std::cout.flags();
    std::cout.flags(flags);
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
```

总的来说，所有已经讨论过的操纵器以及其他一些操纵器都可以使用`std::cout.flags()`函数启用/禁用，所讨论的操纵器只是这个函数的包装器，以减少冗长。虽然这个函数可以用来配置操纵器（应该避免），`std::cout.flags()`函数是在流被更改后恢复操纵器的便捷方法。还应该注意，前面的方法适用于所有流，而不仅仅是`std::cout`。简化恢复操纵器的一种方法是使用一些函数式编程，并用保存/恢复逻辑包装用户函数，如下所示：

```cpp
#include <iomanip>
#include <iostream>

template<typename FUNC>
void cout_transaction(FUNC f)
{
    auto flags = std::cout.flags();
    f();
    std::cout.flags(flags);
}

int main()
{
    cout_transaction([]{
        std::cout << std::hex << std::showbase;
        std::cout << "The answer is: " << 42 << '\n';
    });

    std::cout << "The answer is: " << 42 << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 0x2a
The answer is: 42
```

在这个例子中，我们将`std::cout`的使用包装在`cout_transation`中。这个包装器存储操纵器的当前状态，调用用户提供的函数（改变操纵器），然后在完成之前恢复操纵器。结果是，事务完成后操纵器不受影响，这意味着这个例子中的第二个`std::cout`输出`42`而不是`0x2a`。

最后，为了简化操纵器的使用，有时创建自定义的用户定义操纵器可以封装自定义逻辑是很有用的：

```cpp
#include <iomanip>
#include <iostream>

namespace usr
{
    class hex_t { } hex;
}

std::ostream &
operator<<(std::ostream &os, const usr::hex_t &obj)
{
    os << std::hex << std::showbase << std::internal
        << std::setfill('0') << std::setw(18);

    return os;
}

int main()
{
    std::cout << "The answer is: " << usr::hex << 42 << '\n';
}

> g++ -std=c++17 scratchpad.cpp; ./a.out
The answer is: 0x000000000000002a
```

从这个例子可以看出，只需使用`usr::hex`而不是`std::hex`，就可以使用`std::hex`，`std::showbase`，`std::internal`，`std::setfill('0')`和`std::setw(18)`输出`42`，减少冗长并简化对相同逻辑的多次使用。

# 重新创建 echo 程序

在这个实际例子中，我们将重新创建几乎所有`POSIX`系统上都可以找到的流行的 echo 程序。echo 程序接受程序提供的所有输入并将其回显到`stdout`。这个程序非常简单，具有以下程序选项：

+   -n：防止 echo 在退出时输出换行符

+   `--help`：打印帮助菜单

+   `--version`：打印一些版本信息

还有两个选项，`-e`和`-E`；我们在这里省略了它们，以保持简单，但如果需要，可以作为读者的一个独特练习。

要查看此示例的完整源代码，请参见以下链接：[`github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/blob/master/Chapter06/example1.cpp`](https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/blob/master/Chapter06/example1.cpp)。

此处呈现的`main`函数是一个有用的模式，与原始的 echo 程序略有不同，因为异常（在本例中极不可能）可能会生成原始 echo 程序中看不到的错误消息；但是，它仍然很有用：

```cpp
int
main(int argc, char **argv)
{
    try {
        return protected_main(argc, argv);
    }
    catch (const std::exception &e) {
        std::cerr << "Caught unhandled exception:\n";
        std::cerr << " - what(): " << e.what() << '\n';
    }
    catch (...) {
        std::cerr << "Caught unknown exception\n";
    }

    return EXIT_FAILURE;
}
```

此逻辑的目标是在程序退出之前捕获任何异常，并在退出之前将异常描述输出到`stderr`。

考虑以下示例：

```cpp
catch (const std::exception &e) {
    std::cerr << "Caught unhandled exception:\n";
    std::cerr << " - what(): " << e.what() << '\n';
}
```

前面的代码捕获所有`std::exceptions`并将捕获的异常描述（即`e.what()`）输出到`stderr`。请注意，这里使用的是`std::cerr`（而不是`std::clog`），以防异常的使用会导致不稳定性，确保发生刷新。在使用错误处理逻辑时，最好始终保持谨慎，并确保所有调试输出都以性能为次要考虑因素进行。

考虑以下示例：

```cpp
catch (...) {
    std::cerr << "Caught unknown exception\n";
}
```

前面的代码捕获所有未知异常，在本程序中几乎肯定永远不会发生，并且纯粹是为了完整性而添加：

```cpp
try {
    return protected_main(argc, argv);
}
```

`try`块尝试执行`protected_main()`函数，如果出现异常，则执行先前描述的`catch`块；否则，从`main`函数返回，最终退出程序。

`protected_main()`函数的目标是解析程序提供的参数，并按预期处理每个参数：

```cpp
int
protected_main(int argc, char **argv)
{
    using namespace gsl;

    auto endl = true;
    auto args = make_span(argv, argc);

    for (int i = 1, num = 0; i < argc; i++) {
        cstring_span<> span_arg = ensure_z(args.at(i));

        if (span_arg == "-n") {
            endl = false;
            continue;
        }

        if (span_arg == "--help") {
            handle_help();
        }

        if (span_arg == "--version") {
            handle_version();
        }

        if (num++ > 0) {
            std::cout << " ";
        }

        std::cout << span_arg.data();
    }

    if (endl) {
        std::cout << '\n';
    }

    return EXIT_SUCCESS;
}
```

以下是第一行：

```cpp
auto endl = true;
```

它用于控制是否在退出时向`stdout`添加换行符，就像原始的 echo 程序一样，并由`-n`程序参数控制。以下是下一行：

```cpp
auto args = make_span(argv, argc);
```

前面的代码将标准 C `argv`和`argc`参数转换为 C++ GSL span，使我们能够以符合 C++核心指南的方式安全地处理程序参数。该 span 只不过是一个列表（具体来说，它与`std::array`非常相似），每次访问列表时都会检查此列表的边界（不像`std::array`）。如果我们的代码尝试访问不存在的参数，将抛出异常，并且程序将以错误代码安全退出，通过`stderr`告诉我们尝试访问不存在的列表元素（通过`main`函数中的`try`/`catch`逻辑）。

以下是下一部分：

```cpp
for (int i = 1, num = 0; i < argc; i++) {
    cstring_span<> span_arg = ensure_z(args.at(i));
```

它循环遍历列表中的每个参数。通常，我们会使用范围`for`语法循环遍历列表中的每个元素：

```cpp
for (const auto &arg : args) {
    ...
}
```

但是，不能使用此语法，因为参数列表中的第一个参数始终是程序名称，在我们的情况下应该被忽略。因此，我们从`1`开始（而不是`0`），如前所述，然后循环遍历列表中的其余元素。此片段中的第二行从列表中的每个程序参数创建`cstring_span{}`。`cstring_span{}`只不过是一个标准的 C 风格字符串，包装在 GSL span 中，以保护对字符串的任何访问，使 C 风格字符串访问符合 C++核心指南。稍后将使用此包装器来比较字符串，以安全和符合规范的方式查找我们的程序选项，例如`-n`，`--help`和`--version`。`ensure_z()`函数确保字符串完整，防止可能的意外损坏。

下一步是将每个参数与我们计划支持的参数列表进行比较：

```cpp
if (span_arg == "-n") {
    endl = false;
    continue;
}
```

由于我们使用`cstring_span{}`而不是标准的 C 风格字符串，我们可以安全地直接将参数与`"-n"`字面字符串进行比较，而无需使用不安全的函数（如`strcmp()`）或直接字符比较，这是原始 echo 实现所做的（由于我们只支持一个单个字符选项，性能是相同的）。如果参数是`-n`，我们指示我们的实现在程序退出时不应向`stdout`添加换行符，通过将`endl`设置为`false`，然后我们继续循环处理参数，直到它们全部被处理。

以下是接下来的两个代码块：

```cpp
if (span_arg == "--help") {
    handle_help();
}

if (span_arg == "--version") {
    handle_version();
}
```

它们检查参数是否为`--help`或`--version`。如果用户提供了其中任何一个，将执行特殊的`handle_help()`或`handle_version()`函数。需要注意的是，`handle_xxx()`函数在完成时退出程序，因此不需要进一步的逻辑，并且应该假定这些函数永远不会返回（因为程序退出）。

此时，所有可选参数都已处理。所有其他参数应该像原始的 echo 程序一样输出到`stdout`。问题在于用户可能提供多个希望输出到`stdout`的参数。考虑以下例子：

```cpp
> echo Hello World
Hello World
```

在这个例子中，用户提供了两个参数——`Hello`和`World`。预期输出是`Hello World`（有一个空格），而不是`HelloWorld`（没有空格），需要一些额外的逻辑来确保根据需要将空格输出到`stdout`。

以下是下一个代码块：

```cpp
if (num++ > 0) {
    std::cout << " ";
}
```

这在第一个参数已经输出后向`stdout`输出一个空格，但在下一个参数即将输出之前（以及所有剩余的参数）。这是因为`num`开始为`0`（`0`等于`0`，而不是大于`0`，因此在第一个参数上不会输出空格），然后`num`被递增。当处理下一个参数时，`num`为`1`（或更大），大于`0`，因此空格被添加到`stdout`。

最后，通过向`std::cout`提供参数的数据，将参数添加到`stdout`，这只是`std::cout`可以安全处理的参数的不安全的标准 C 版本：

```cpp
std::cout << span_arg.data();
```

`protected_main()`函数中的最后一个代码块是：

```cpp
if (endl) {
    std::cout << '\n';
}

return EXIT_SUCCESS;
```

默认情况下，`endl`是`true`，因此在程序退出之前会向`stdout`添加一个换行符。然而，如果用户提供了`-n`，那么`endl`将被设置为`false`。

```cpp
if (span_arg == "-n") {
    endl = false;
    continue;
}
```

在上述代码中，如果用户提供了`--help`，则会执行`handle_help()`函数如下：

```cpp
void
handle_help()
{
    std::cout
            << "Usage: echo [SHORT-OPTION]... [STRING]...\n"
            << " or: echo LONG-OPTION\n"
            << "Echo the STRING(s) to standard output.\n"
            << "\n"
            << " -n do not output the trailing newline\n"
            << " --help display this help and exit\n"
            << " --version output version information and exit\n";

    ::exit(EXIT_SUCCESS);
}
```

该函数使用`std::cout`将帮助菜单输出到`stdout`，然后成功退出程序。如果用户提供了`--version`，`handle_version()`函数也会执行相同的操作：

```cpp
void
handle_version()
{
    std::cout
            << "echo (example) 1.0\n"
            << "Copyright (C) ???\n"
            << "\n"
            << "Written by Rian Quinn.\n";

    ::exit(EXIT_SUCCESS);
}
```

要编译这个例子，我们使用 CMake：

```cpp
# ------------------------------------------------------------------------------
# Header
# ------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.6)
project(chapter6)

include(ExternalProject)
find_package(Git REQUIRED)

set(CMAKE_CXX_STANDARD 17)

# ------------------------------------------------------------------------------
# Guideline Support Library
# ------------------------------------------------------------------------------

list(APPEND GSL_CMAKE_ARGS
    -DGSL_TEST=OFF
    -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}
)

ExternalProject_Add(
    gsl
    GIT_REPOSITORY https://github.com/Microsoft/GSL.git
    GIT_SHALLOW 1
    CMAKE_ARGS ${GSL_CMAKE_ARGS}
    PREFIX ${CMAKE_BINARY_DIR}/external/gsl/prefix
    TMP_DIR ${CMAKE_BINARY_DIR}/external/gsl/tmp
    STAMP_DIR ${CMAKE_BINARY_DIR}/external/gsl/stamp
    DOWNLOAD_DIR ${CMAKE_BINARY_DIR}/external/gsl/download
    SOURCE_DIR ${CMAKE_BINARY_DIR}/external/gsl/src
    BINARY_DIR ${CMAKE_BINARY_DIR}/external/gsl/build
)

# ------------------------------------------------------------------------------
# Executable
# ------------------------------------------------------------------------------
```

```cpp

include_directories(${CMAKE_BINARY_DIR}/include)
add_executable(example1 example1.cpp)
add_dependencies(example1 gsl)
```

这是`CMakeLists.txt`文件的头部分：

```cpp
cmake_minimum_required(VERSION 3.6)
project(chapter6)

include(ExternalProject)
find_package(Git REQUIRED)

set(CMAKE_CXX_STANDARD 17)
```

这设置了 CMake 要求版本为 3.6（因为我们使用`GIT_SHALLOW`），为项目命名，包括`ExternalProject`模块（提供了`ExternalProject_Add`），并将 C++标准设置为 C++17。

以下是下一部分：

```cpp
# ------------------------------------------------------------------------------
# Guideline Support Library
# ------------------------------------------------------------------------------

list(APPEND GSL_CMAKE_ARGS
    -DGSL_TEST=OFF
    -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}
)

ExternalProject_Add(
    gsl
    GIT_REPOSITORY https://github.com/Microsoft/GSL.git
    GIT_SHALLOW 1
    CMAKE_ARGS ${GSL_CMAKE_ARGS}
    PREFIX ${CMAKE_BINARY_DIR}/external/gsl/prefix
    TMP_DIR ${CMAKE_BINARY_DIR}/external/gsl/tmp
    STAMP_DIR ${CMAKE_BINARY_DIR}/external/gsl/stamp
    DOWNLOAD_DIR ${CMAKE_BINARY_DIR}/external/gsl/download
    SOURCE_DIR ${CMAKE_BINARY_DIR}/external/gsl/src
    BINARY_DIR ${CMAKE_BINARY_DIR}/external/gsl/build
)
```

它使用 CMake 的`ExternalProject_Add`从 GitHub 上的 Git 存储库下载并安装 GSL，使用深度为 1（即`GIT_SHALLOW 1`）来加快下载过程。提供给`ExternalProject_Add`的参数（即`GSL_CMAKE_ARGS`）告诉 GSL 的构建系统关闭单元测试（我们的项目不需要）并将生成的头文件安装到我们的构建目录中（将它们放在我们的`build`目录中的`include`文件夹中）。提供给`ExternalProject_Add`的其余参数是可选的，只是用来清理`ExternalProject_Add`的输出，并且可以被忽略，甚至在需要时删除。

最后，这是最后一个代码块：

```cpp
include_directories(${CMAKE_BINARY_DIR}/include)
add_executable(example1 example1.cpp)
```

它告诉构建系统在哪里找到我们新安装的 GSL 头文件，然后从`example1.cpp`源代码创建一个名为`example1`的可执行文件。要编译和运行此示例，只需执行：

```cpp
> mkdir build; cd build
> cmake ..; make
...
> ./example1 Hello World
Hello World
```

# 理解串行回显服务器示例

在这个实际示例中，我们将创建一个基于串行的回显服务器。回显服务器（无论类型如何）都会接收输入并将输入回显到程序的输出（类似于第一个示例，但在这种情况下使用串行端口上的服务器式应用程序）。

要查看此示例的完整源代码，请参阅以下内容：[`github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/blob/master/Chapter06/example2.cpp`](https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/blob/master/Chapter06/example2.cpp)。

```cpp
#include <fstream>
#include <iostream>

#include <gsl/gsl>
using namespace gsl;

void
redirect_output(
    const std::ifstream &is,
    const std::ofstream &os,
    std::function<void()> f)
{
    auto cinrdbuf = std::cin.rdbuf();
    auto coutrdbuf = std::cout.rdbuf();

    std::cin.rdbuf(is.rdbuf());
    std::cout.rdbuf(os.rdbuf());

    f();

    std::cin.rdbuf(cinrdbuf);
    std::cout.rdbuf(coutrdbuf);
}

auto
open_streams(cstring_span<> port)
{
    std::ifstream is(port.data());
    std::ofstream os(port.data());

    if (!is || !os) {
        std::clog << "ERROR: unable to open serial port:" << port.data() << '\n';
        ::exit(EXIT_FAILURE);
    }

    return std::make_pair(std::move(is), std::move(os));
}

int
protected_main(int argc, char** argv)
{
    auto args = make_span(argv, argc);

    if (argc != 2) {
        std::clog << "ERROR: unsupported number of arguments\n";
        ::exit(EXIT_FAILURE);
    }

    auto [is, os] = open_streams(
        ensure_z(args.at(1))
    );

    redirect_output(is, os, []{
        std::string buf;

        std::cin >> buf;
        std::cout << buf << std::flush;
    });

    return EXIT_SUCCESS;
}
```

`main`函数与第一个示例相同。它的唯一目的是捕获可能触发的任何异常，将异常的描述输出到`stderr`，并以失败状态安全地退出程序。有关其工作原理的更多信息，请参见第一个示例。`protected_main()`函数的目的是打开串行端口，读取输入，并将输入回显到输出：

```cpp
int
protected_main(int argc, char** argv)
{
    auto args = make_span(argv, argc);

    if (argc != 2) {
        std::clog << "ERROR: unsupported number of arguments\n";
        ::exit(EXIT_FAILURE);
    }

    auto [is, os] = open_streams(
        ensure_z(args.at(1))
    );

    redirect_output(is, os, []{
        std::string buf;

        std::cin >> buf;
        std::cout << buf << std::flush;
    });

    return EXIT_SUCCESS;
}
```

这是第一行：

```cpp
auto args = make_span(argv, argc);
```

它做的事情和第一个示例一样，将`argc`和`argv`参数参数包装在 GSL span 中，为解析用户提供的参数提供了安全机制。

这是第二个块：

```cpp
if (argc != 2) {
    std::clog << "ERROR: unsupported number of arguments\n";
    ::exit(EXIT_FAILURE);
}
```

它检查确保用户提供了一个且仅一个参数。`argc`的总数为`2`而不是`1`的原因是因为第一个参数总是程序的名称，在这种情况下应该被忽略，因此用户提供的`1`个参数实际上等于`argc`的`2`。此外，我们使用`std::clog`而不是`std::cerr`，因为在这种情况下不太可能不稳定，并且当调用`::exit()`时，`libc`将为我们执行刷新。

这是第二个块：

```cpp
auto [is, os] = open_streams(
    ensure_z(args.at(1))
);
```

它打开串行端口并返回输入和输出流，`std::cout`和`std::cin`可以使用串行端口而不是`stdout`和`stdin`。为此，使用了`open_streams()`函数：

```cpp
auto
open_streams(cstring_span<> port)
{
    std::ifstream is(port.data());
    std::ofstream os(port.data());

    if (!is || !os) {
        std::clog << "ERROR: unable to open serial port:" << port.data() << '\n';
        ::exit(EXIT_FAILURE);
    }

    return std::make_pair(std::move(is), std::move(os));
}
```

此函数接受一个`cstring_span{}`，用于存储要打开的串行端口（例如`/dev/ttyS0`）。

接下来我们转到以下流：

```cpp
std::ifstream is(port.data());
std::ofstream os(port.data());
```

前面的代码打开了一个输入和输出流，绑定到这个串行端口。`ifstream{}`和`ofstream{}`都是文件流，超出了本章的范围（它们将在以后的章节中解释），但简而言之，这些打开了串行设备并提供了一个流对象，`std::cout`和`std::cin`可以使用它们，就好像它们在使用`stdout`和`stdin`（这在`POSIX`系统上也是技术上的文件流）。

这是下一个块：

```cpp
if (!is || !os) {
    std::clog << "ERROR: unable to open serial port:" << port.data() << '\n';
    ::exit(EXIT_FAILURE);
}
```

它验证了输入流和输出流是否成功打开，这很重要，因为这种类型的错误可能发生（例如，提供了无效的串行端口，或者用户无法访问串行端口）。如果发生错误，用户将通过输出到`std::clog`的消息得到通知，并且程序以失败状态退出。

最后，如果输入流和输出流成功打开，它们将作为一对返回，`protected_main()`函数将使用结构化绑定语法（C++17 中添加的功能）读取它们。

这是`protected_main()`函数中的下一个块：

```cpp
redirect_output(is, os, []{
    std::string buf;

    std::cin >> buf;
    std::cout << buf << std::flush;
});
```

它将`std::cout`和`std::cin`重定向到串行端口，然后将输入回显到程序的输出，实际上回显了用户提供的串行端口。为了执行重定向，使用了`redirect_output()`函数：

```cpp
void
redirect_output(
    const std::ifstream &is,
    const std::ofstream &os,
    std::function<void()> f)
{
    auto cinrdbuf = std::cin.rdbuf();
    auto coutrdbuf = std::cout.rdbuf();

    std::cin.rdbuf(is.rdbuf());
    std::cout.rdbuf(os.rdbuf());

    f();

    std::cin.rdbuf(cinrdbuf);
    std::cout.rdbuf(coutrdbuf);
}
```

`redirect_output()`函数将输入和输出流作为参数，以及要执行的函数和最终参数。`redirect_function()`的第一件事是保存`std::cin`和`std::cout`的当前缓冲区：

```cpp
auto cinrdbuf = std::cin.rdbuf();
auto coutrdbuf = std::cout.rdbuf();
```

接下来我们看到：

```cpp
std::cin.rdbuf(is.rdbuf());
std::cout.rdbuf(os.rdbuf());
```

`std::cin`和`std::cout`都重定向到提供的输入和输出流。完成此操作后，将执行提供的函数。任何对`std::cin`和`std::cout`的使用都将重定向到提供的串行端口，而不是标准的`stdout`和`stdin`。当`f()`函数完成时，`std::cin`和`std::cout`将恢复到它们的原始缓冲区，将它们重定向回`stdout`和`stdin`：

```cpp
std::cin.rdbuf(cinrdbuf);
std::cout.rdbuf(coutrdbuf);
```

最后，程序成功退出。要编译此示例，我们使用 CMake：

```cpp
# ------------------------------------------------------------------------------
# Header
# ------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.6)
project(chapter6)

include(ExternalProject)
find_package(Git REQUIRED)

set(CMAKE_CXX_STANDARD 17)

# ------------------------------------------------------------------------------
# Guideline Support Library
# ------------------------------------------------------------------------------

list(APPEND GSL_CMAKE_ARGS
    -DGSL_TEST=OFF
    -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}
)

ExternalProject_Add(
    gsl
    GIT_REPOSITORY https://github.com/Microsoft/GSL.git
    GIT_SHALLOW 1
    CMAKE_ARGS ${GSL_CMAKE_ARGS}
    PREFIX ${CMAKE_BINARY_DIR}/external/gsl/prefix
    TMP_DIR ${CMAKE_BINARY_DIR}/external/gsl/tmp
    STAMP_DIR ${CMAKE_BINARY_DIR}/external/gsl/stamp
    DOWNLOAD_DIR ${CMAKE_BINARY_DIR}/external/gsl/download
    SOURCE_DIR ${CMAKE_BINARY_DIR}/external/gsl/src
    BINARY_DIR ${CMAKE_BINARY_DIR}/external/gsl/build
)

# ------------------------------------------------------------------------------
# Executable
# ------------------------------------------------------------------------------

include_directories(${CMAKE_BINARY_DIR}/include)
add_executable(example2 example2.cpp)
add_dependencies(example2 gsl)
```

这个`CMakeLists.txt`与第一个例子中的`CMakeLists.txt`相同（减去了使用`example1`而不是`example2`）。有关此操作原理的完整解释，请参阅本章中的第一个例子。

要编译和使用此示例，需要两台计算机，一台用作 echo 服务器，另一台用作客户端，两台计算机的串行端口连接在一起。在 echo 服务器计算机上，使用以下命令：

```cpp
> mkdir build; cd build
> cmake ..; make
...
> ./example2 /dev/ttyS0
```

请注意，您的串行端口设备可能不同。在客户计算机上，打开两个终端。在第一个终端中，运行以下命令：

```cpp
> cat < /dev/ttyS0
```

这段代码等待串行设备输出数据。在第二个终端中运行：

```cpp
> echo "Hello World" > /dev/ttyS0
```

这将通过串行端口将数据发送到 echo 服务器。当您按下*Enter*时，您将看到我们在 echo 服务器上成功关闭的`example2`程序，并且客户端的第一个终端将显示`Hello World`：

```cpp
> cat < /dev/ttyS0
Hello World
```

# 摘要

在本章中，我们学习了如何使用 C++17 执行基于控制台的 IO，这是一种常见的系统编程需求。与`printf()`和`scanf()`等标准 C 风格的 IO 函数不同，C++使用基于流的 IO 函数，如`std::cout`和`std::cin`。使用基于流的 IO 有许多优点和一些缺点。例如，基于流的 IO 提供了一种类型安全的机制来执行 IO，而原始的 POSIX 风格的`write()`函数通常由于不调用`malloc()`和`free()`而能够优于基于流的 IO。

此外，我们还研究了基于流的操作符，它们为基于流的 IO 提供了与标准 C 风格格式字符串类似的功能集，但没有 C 等效项中常见的不稳定性问题。除了操纵数字和布尔值的格式之外，我们还探讨了字段属性，包括宽度和对齐。

最后，我们用两个不同的例子结束了本章。第一个例子展示了如何在 C++中实现流行的 POSIX *echo*程序，而不是在 C 中。第二个例子创建了一个*echo*服务器，用于串行端口，它使用`std::cin`从串行端口接收输入，并使用`std::cout`将该输入作为输出发送回串行端口。

在下一章中，我们将全面介绍 C、C++和 POSIX 提供的内存管理设施，包括对齐内存和 C++智能指针。

# 问题

1.  相比标准 C 的`scanf`，`std::cin`如何帮助防止缓冲区溢出？

1.  至少列举一个使用 C++流相对于标准 C 风格的`printf`/`scanf`的优点。

1.  至少列举一个使用 C++流相对于标准 C 风格的`printf`/`scanf`的缺点。

1.  何时应该使用`std::endl`而不是`\n`？

1.  `std::cerr`和`std::clog`之间有什么区别，何时应该使用`std::cerr`？

1.  如何在基数标识符和十六进制值之间输出额外字符？

1.  如何输出八进制和大写字母？

1.  如何使用 C++和 GSL 安全地解析标准 C 风格的程序参数？

1.  如何保存/恢复`std::cin`的读取缓冲区？

# 进一步阅读

+   [`www.packtpub.com/application-development/c17-example`](https://www.packtpub.com/application-development/c17-example)

+   [`www.packtpub.com/application-development/getting-started-c17-programming-video`](https://www.packtpub.com/application-development/getting-started-c17-programming-video)


# 第七章：内存管理的全面视角

在本章中，我们将逐步指导读者如何正确和安全地执行 C++风格的内存管理，同时尽可能遵守 C++核心指南，利用 C++11、C++14 和 C++17 对 C++标准模板库的增强，以增加读者系统程序的安全性、可靠性和稳定性。我们将首先介绍`new()`和`delete()`函数，以及它们如何用于分配类型安全的内存，包括对齐内存。接下来，本章将讨论使用`new()`和`delete()`直接的安全问题，以及如何使用智能指针来处理这些安全问题，包括它们对 C++核心指南合规性的影响。还将讨论如何执行内存映射和权限，并在章节结束时简要讨论碎片化问题。

# 技术要求

为了编译和执行本章中的示例，读者必须具备以下条件：

+   一个能够编译和执行 C++17 的基于 Linux 的系统（例如，Ubuntu 17.10+）

+   GCC 7+

+   CMake 3.6+

+   互联网连接

要下载本章中的所有代码，包括示例和代码片段，请访问：[`github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/tree/master/Chapter07`](https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/tree/master/Chapter07)。

# 学习关于 new 和 delete 函数

在本节中，读者将学习如何使用 C++17 分配和释放内存。您将学习如何使用`new()`和`delete()`而不是`malloc()`/`free()`来增加分配和释放的类型安全性。将解释这些函数的各个版本，包括数组、对齐和放置式分配。

# 编写程序的基础知识

在编写程序时，包括系统编程，作者可以利用几种不同类型的内存：

+   全局内存

+   堆栈内存

+   堆内存

全局内存存在于程序本身中，由操作系统的加载器分配，并且通常存在于两个不同的位置（假设是 ELF 二进制文件）：

+   `.bss`: 零初始化（或未初始化）内存

+   `.data`: value-initialized memory

考虑以下示例：

```cpp
#include <iostream>

int bss_mem = 0;
int data_mem = 42;

int main()
{
    std::cout << bss_mem << '\n';
    std::cout << data_mem << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0
// 42
```

尽管在系统编程中经常使用，但全局内存通常不鼓励使用，而是推荐使用堆栈内存和动态内存。在使用值初始化的全局内存时需要特别小心，因为这种内存使用会增加程序在磁盘上的大小，导致更大的存储影响，以及长时间的加载时间，而零初始化的内存是由操作系统加载器在链接期间提供的。

**堆栈内存**是在堆栈上分配的内存：

```cpp
#include <iostream>

int main()
{
    int stack_mem = 42;
    std::cout << stack_mem << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 42
```

如本例所示，`stack_mem`是在堆栈上分配而不是全局分配，因为它存在于`main()`函数中。堆栈内存绑定到创建它的作用域——在这种情况下是`main()`函数。除了有作用域之外，堆栈内存的另一个优点是，当内存的作用域完成时，内存将自动释放。在使用堆栈内存时需要小心，因为这种内存的大小是有限的。

应注意，堆栈的总大小完全取决于系统，并且可能差异很大。除非知道堆栈的大小，否则应假定它很小，并小心使用，因为没有简单的方法来确定堆栈何时耗尽。与通常在内存不可用时返回某种错误的动态内存分配不同，在大多数系统上，当堆栈耗尽时，程序将简单崩溃。

例如，在我们的测试系统上，尝试在堆栈上分配一个整数数组`268435456`，如下所示的代码：

```cpp
#include <iostream>

int main()
{
    int stack_mem[268435456];
    std::cout << stack_mem[0] << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// Segmentation fault (core dumped)
```

这导致分段错误，因为`stack_mem`变量超出了堆栈的总大小。

内存的第三种形式，也是本章的主题，是动态内存（也称为**堆内存**）。与堆栈一样，每个程序都会被操作系统分配一块堆内存池，这个池通常可以根据需求增长。与堆栈甚至全局内存不同，堆内存分配可以非常大，如果物理系统和操作系统支持的话。此外，与堆栈和全局内存不同，堆内存的分配速度较慢，用户按需分配的任何内存在完成时也必须由用户释放回堆。在 C++中，分配堆内存的基本方法是通过使用`new()`和`delete()`运算符函数，如下所示：

```cpp
#include <iostream>

int main()
{
    auto ptr = new int;
    std::cout << ptr << '\n';
    delete ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x5639c77e4e70
```

在这个简单的例子中，使用 new 运算符在堆上分配了一个整数（其大小取决于体系结构，但在这里假定为`4`字节）。新分配的内存的地址被输出到`stdout`，然后使用`delete()`运算符将内存释放回堆。除了单个对象，也可以使用`new()`/`delete()`运算符分配/释放数组，如下所示：

```cpp
#include <iostream>

int main()
{
    auto ptr = new int[42];
    std::cout << ptr << '\n';
    delete [] ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x5594a7d47e70
```

在这个例子中，分配了一个大小为`42`的整数数组。请注意，与标准 C 中的`malloc()`不同，new 运算符会自动计算对象或对象数组所需的总字节数。假设一个整数是`4`字节，在这个例子中，new 运算符分配了`42 * sizeof(int) == 42 * 4 == 11088`字节。除了使用`new[]()`来分配数组外，还使用了`delete[]()`运算符，而不是`delete`运算符。delete 运算符调用单个对象的析构函数，而`delete[]()`运算符调用数组中每个对象的析构函数。

```cpp
#include <iostream>

class myclass
{
public:
    ~myclass()
    {
        std::cout << "my delete\n";
    }
};

int main()
{
    auto ptr = new myclass[2];
    std::cout << ptr << '\n';
    delete [] ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x56171064ae78
// my delete
// my delete
```

重要的是要注意，一些系统可能使用不同的池来分配单个对象、对象数组、对齐对象等。需要注意确保释放内存的例程与分配内存的例程匹配。例如，如果使用`new[]()`，应该始终使用`delete[]()`而不是`delete()`。如果发生不匹配，共享相同池的系统将正常运行，但在不共享这些池的系统上可能会崩溃，因为您会尝试释放内存到原本不属于的池中。预防这些类型的错误的最简单方法是使用`std::unique_ptr{}`和`std::shared_ptr{}`，这将在*理解智能指针和所有权*部分讨论。

# 对齐内存

在编程系统时，通常需要分配对齐内存（即，可以被特定对齐方式整除的内存）。具体来说，当分配内存时，指向所分配内存的地址可以是任何值。然而，在编程系统时，这通常会有问题，因为一些 API 和物理设备要求内存以一定的最小粒度进行分配。考虑以下例子：

```cpp
0x0ABCDEF123456789 // Unaligned
0x0ABCDEF12345F000 // 4 Kb aligned
```

可以使用所有三种内存类型来分配对齐内存：

+   全局

+   在堆栈上

+   动态地

要在 C++中全局分配对齐内存，使用`alignas()`说明符：

```cpp
#include <iostream>

alignas(0x1000) int ptr[42];

int main()
{
    std::cout << ptr << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x560809897000
```

在这个例子中，全局分配了一个大小为`42`的整数数组，并使用`alignas()`说明符将数组对齐到 4k 页边界。然后输出数组的地址，如所示，该地址可以被 4k 页整除（即，前 12 位为零）。要在堆栈上分配对齐内存，也可以使用`alignas()`说明符：

```cpp
#include <iostream>

int main()
{
    alignas(0x1000) int ptr[42];
    std::cout << ptr << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x560809897000
```

数组不是全局分配的，而是移动到`main`函数的作用域中，因此在`main`函数执行时使用堆栈分配，并在`main`函数完成时自动释放。这种类型的分配应该谨慎使用，因为编译器必须向程序的可执行文件中添加代码，以移动堆栈指针以对齐内存。因此，堆栈上的对齐分配间接分配了额外的不可用内存，以确保指针对齐（在 Intel 的 x86_64 上使用 GCC 7.3 显示）：

```cpp
> objdump -d | grep main
...
00000000000008da <main>:
 8da: 4c 8d 54 24 08 lea 0x8(%rsp),%r10
 8df: 48 81 e4 00 f0 ff ff and $0xfffffffffffff000,%rsp
 8e6: 41 ff 72 f8 pushq -0x8(%r10)
```

可以看到，堆栈指针（即本例中的 RSP 寄存器）被移动以对齐整数数组。如果这种类型的分配频繁进行，或者对齐要求很高（比如 2MB 对齐），堆栈空间可能很快用完。无论类型如何，另一种分配对齐内存的方法是在现有字符缓冲区内手动计算对齐位置：

```cpp
#include <iostream>

int main()
{
    char buffer[0x2000];
    auto ptr1 = reinterpret_cast<uintptr_t>(buffer);
    auto ptr2 = ptr1 - (ptr1 % 0x1000) + 0x1000;

    std::cout << std::hex << std::showbase;
    std::cout << ptr1 << '\n';
    std::cout << ptr2 << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x7ffd160dec20
// 0x7ffd160df000
```

在这个例子中，堆栈上分配了一个足够大的字符缓冲区。然后将字符缓冲区的地址转换为无符号整数指针类型，这是 C++核心指南所不鼓励的操作，然后对字符缓冲区的指针进行算术运算，以定位缓冲区内的页面对齐地址，这也是 C++核心指南所不鼓励的操作，因为应该避免指针算术。原始指针和结果指针都输出到`stdout`，如所示，计算出的指针在字符缓冲区内对齐到 4k 页面边界。要了解这个算法是如何工作的，请参见以下内容：

```cpp
// ptr1 = 0x7ffd160dec20
// ptr1 % 0x1000 = 0xc20
// ptr1 - (ptr1 % 0x1000) = 0x7ffd160de000   
// ptr1 - (ptr1 % 0x1000) + 0x1000 = 0x7ffd160df000 
```

这种类型的处理方式有效，并且已经使用了多年，但应该避免使用，因为有更好的方法可以使用`alignas()`来完成相同的任务，而无需进行类型转换和指针算术，这种方法容易出错，并且被 C++核心指南所不鼓励。

最后，分配对齐内存的第三种方法是使用动态分配。在 C++17 之前，可以使用`posix_memalign()`或更新的 C11 `aligned_alloc()`来实现，如下所示：

```cpp
#include <iostream>

int main()
{
    int *ptr;

    if (posix_memalign(reinterpret_cast<void **>(&ptr), 0x1000, 42 * sizeof(int))) {
        std::clog << "ERROR: unable to allocate aligned memory\n";
        ::exit(EXIT_FAILURE);
    }

    std::cout << ptr << '\n';
    free(ptr);
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x55c5d31d1000
```

`posix_memalign()` API 有点笨拙。首先，必须声明一个指针，然后提供对齐和大小（必须手动计算），最后，函数在成功时返回 0。最后，需要使用`reinterpret_cast()`来告诉`posix_memalign()`函数提供的指针是`void **`而不是`int**`。由于`posix_memalign()`函数是 C 风格的函数，所以使用`free()`来释放内存。

另一种分配对齐内存的方法是使用相对较新的`aligned_alloc()`函数，它提供了一个更简洁、更便携的实现方式：

```cpp
#include <iostream>

int main()
{
    if (auto ptr = aligned_alloc(0x1000, 42 * sizeof(int))) {
        std::cout << ptr << '\n';
        free(ptr);
    }
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x55c5d31d1000
```

如所示，`aligned_alloc()`的功能类似于常规的`malloc()`，但具有额外的对齐参数。这个 API 仍然存在与`malloc()`和`posix_memalign()`相同的大小问题，其中数组的总大小必须手动计算。

为了解决这些问题，C++17 添加了`new()`和`delete()`运算符的对齐分配版本，利用了`alignas()`，如下所示：

```cpp
#include <iostream>

using aligned_int alignas(0x1000) = int;

int main()
{
    auto ptr = new aligned_int;
    std::cout << ptr << '\n';
    delete ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x55e32ece1000
```

在这个例子中，我们使用`alignas()`和`new()`和`delete()`运算符来分配一个单个整数。为了实现这一点，我们创建了一个新类型，称为`aligned_int`，它在类型定义中利用了`alignas()`。以下内容也可以用来分配一个对齐的数组：

```cpp
#include <iostream>

using aligned_int alignas(0x1000) = int;

int main()
{
    auto ptr = new aligned_int[42];
    std::cout << ptr << '\n';
    delete [] ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x5649c0597000
```

使用相同的对齐整数类型，唯一的区别是使用`new []()`和`delete []()`而不是`new()`和`delete()`。与前面代码中显示的 C API 不同，`new()`和`delete()`，包括 C++17 中添加的对齐版本，会自动计算需要分配的总字节数，从而消除了潜在的错误。

# nothrow

`new()`和`delete()`运算符允许抛出异常。实际上，如果分配失败，默认的 new 运算符会抛出`std::bad_alloc`，而不是返回`nullptr`。在某些情况下，通常在编程系统中经常见到，不希望在无效的分配上抛出异常，因此提供了`nothrow`版本。

```cpp
#include <iostream>

int main()
{
    auto ptr = new (std::nothrow) int;
    std::cout << ptr << '\n';
    delete ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x55893e230e70
```

具体来说，使用`new (std::nothrow)`代替`new()`，告诉 C++在无效分配时希望返回`nullptr`，而不是`new()`抛出`std::bad_alloc`。数组版本也提供如下：

```cpp
#include <iostream>

int main()
{
    auto ptr = new (std::nothrow) int[42];
    std::cout << ptr << '\n';
    delete [] ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x5623076e9e70
```

正如人们所期望的那样，这些函数的对齐分配版本也适用于单个对象的分配：

```cpp
#include <iostream>

using aligned_int alignas(0x1000) = int;

int main()
{
    auto ptr = new (std::nothrow) aligned_int;
    std::cout << ptr << '\n';
    delete ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x55e36201a000
```

还有数组样式的分配：

```cpp
#include <iostream>

using aligned_int alignas(0x1000) = int;

int main()
{
    auto ptr = new (std::nothrow) aligned_int[42];
    std::cout << ptr << '\n';
    delete [] ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x557222103000
```

应该注意，`nullptr`仅对 C++提供的类型返回。对于用户定义的类型，如果在构造过程中抛出异常，标记为`nothrow`的`new()`版本将调用`std::terminate`并中止：

```cpp
#include <iostream>

class myclass
{
public:
    myclass()
    {
        throw std::runtime_error("the answer was not 42");
    }
};

int main()
{
    auto ptr = new (std::nothrow) myclass;
    std::cout << ptr << '\n';
    delete ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// terminate called after throwing an instance of 'std::runtime_error'
// what(): the answer was not 42
// Aborted (core dumped)
```

为了解决这个问题，可以使用特定于类的`new`和`delete`运算符（在*重载*部分进行解释）。

# 放置 new

除了对齐分配和`nothrow`指定符，C++还提供了从现有的、用户控制的缓冲区分配内存的能力，这种情况在编程系统中经常见到。例如，假设您已经从物理设备映射了一个缓冲区。现在假设您希望从这个缓冲区分配一个整数，可以使用`new()`放置运算符来实现：

```cpp
#include <iostream>

char buf[0x1000];

int main()
{
    auto ptr = new (buf) int;
    std::cout << ptr << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x5567b8884000
```

在这个例子中，我们利用`new()`放置运算符从现有的用户控制的缓冲区分配内存。`new()`放置运算符提供了要分配的对象的地址，然后像往常一样调用对象的构造函数。应该注意，在这种情况下不需要`delete()`运算符，因为分配给对象的内存是用户定义的，因此在完成时没有堆内存需要返回到堆中。此外，`new()`放置运算符不管理提供给一组对象的内存，这是用户必须执行的任务。为了证明这一点，可以参考以下内容：

```cpp
#include <iostream>

char buf[0x1000];

int main()
{
    auto ptr1 = new (buf) int;
    auto ptr2 = new (buf) int;
    std::cout << ptr1 << '\n';
    std::cout << ptr2 << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x558044c66180
// 0x558044c66180
```

在这个例子中，`new()`放置被使用了两次。如图所示，提供的地址是相同的，因为我们没有手动提前提供给`new()`放置的地址，这表明当使用`new()`放置时，C++不会自动管理用户定义的内存。通常，这种类型的例子如果执行会导致未定义的行为（在这种情况下并不会，因为我们实际上并没有使用新分配的内存）。因此，`new()`放置应该特别小心使用。除了单个分配外，还提供了数组分配：

```cpp
#include <iostream>

char buf[0x1000];

int main()
{
    auto ptr = new (buf) int[42];
    std::cout << ptr << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x55594aff0000
```

由于 C++不管理`new()`放置分配，用户还必须提供对齐分配。在前面的代码中提供的对齐算法可以用于从用户定义的缓冲区提供对齐分配，也可以使用已经对齐的内存（例如，通过`mmap()`与物理设备进行接口），或者也可以使用`alignas()`，如下所示：

```cpp
#include <iostream>

alignas(0x1000) char buf[0x1000];

int main()
{
    auto ptr = new (buf) int;
    std::cout << ptr << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x5567b8884000
```

在这个例子中，由于使用`alignas()`对缓冲区进行了对齐，因此当提供该缓冲区时，得到的新的放置分配也是对齐的。这种类型的分配对于数组分配也是适用的：

```cpp
#include <iostream>

alignas(0x1000) char buf[0x1000];

int main()
{
    auto ptr = new (buf) int[42];
    std::cout << ptr << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x55594aff0000
```

# 重载

在编程系统时，C++提供的默认分配方案通常是不理想的。例如（但不限于）：

+   自定义内存布局

+   碎片化

+   性能优化

+   调试和统计

克服这些问题的一种方法是利用 C++分配器，这是一个复杂的话题，将在第九章中讨论，*分配器的实践方法*。另一种更严厉的方法是利用`new()`和`delete()`运算符的用户定义重载：

```cpp
#include <iostream>

void *operator new (std::size_t count)
{
    // WARNING: Do not use std::cout here
    return malloc(count);
}

void operator delete (void *ptr)
{
    // WARNING: Do not use std::cout here
    return free(ptr);
}

int main()
{
    auto ptr = new int;
    std::cout << ptr << '\n';
    delete ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x55f204617e70
```

在这个例子中，提供了自定义的`new()`和`delete()`运算符重载。你的程序将使用`new()`和`delete()`函数提供的默认分配方案，而是使用你定义的版本。

这些重载会影响所有的分配，包括 C++库使用的分配，因此在利用这些重载时需要小心，因为如果在这些函数内执行分配，可能会发生无限循环递归。例如，像`std::vector`和`std::list`这样的数据结构，或者像`std::cout`和`std::cerr`这样的调试函数都不能使用，因为这些设施使用`new()`和`delete()`运算符来分配内存。

除了单个对象的`new()`和`delete()`运算符外，所有其他运算符也可以进行重载，包括数组分配版本：

```cpp
#include <iostream>

void *operator new[](std::size_t count)
{
    // WARNING: Do not use std::cout here
    return malloc(count);
}

void operator delete[](void *ptr)
{
    // WARNING: Do not use std::cout here
    return free(ptr);
}

int main()
{
    auto ptr = new int[42];
    std::cout << ptr << '\n';
    delete [] ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x55e5e2c62e70
```

调试和统计是重载`new()`和`delete()`运算符的常见原因，提供有关正在发生的分配类型的有用信息。例如，假设你希望记录大于或等于一页的总分配数：

```cpp
#include <iostream>

std::size_t allocations = 0;

void *operator new (std::size_t count)
{
    if (count >= 0x1000) {
        allocations++;
    }

    return malloc(count);
}

void operator delete (void *ptr)
{
    return free(ptr);
}

int main()
{
    auto ptr = new int;
    std::cout << allocations << '\n';
    delete ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0
```

如图所示，我们的程序没有执行大于一页的分配，包括由 C++库进行的分配。让我们看看如果我们按照这里所示的方式分配一页会发生什么：

```cpp
#include <iostream>

std::size_t allocations = 0;

void *operator new (std::size_t count)
{
    if (count >= 0x1000) {
        allocations++;
    }

    return malloc(count);
}

void operator delete (void *ptr)
{
    return free(ptr);
}

struct mystruct
{
    char buf[0x1000];
};

int main()
{
    auto ptr = new mystruct;
    std::cout << allocations << '\n';
    delete ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 1
```

如预期的那样，我们得到了一个大于或等于一页的单个分配。这种使用重载的`new()`和`delete()`的方式对于调试内存泄漏、定位分配优化等非常有用。然而，需要注意的是，在编写这些类型的重载时需要小心。如果你意外地分配内存（例如，在使用 C++数据结构如`std::vector{}`时，或者在使用`std::cout`时），你可能会陷入无限循环，或者增加你可能正在记录的统计数据。

除了全局运算符`new`和`delete`运算符重载外，还提供了特定于类的版本：

```cpp
#include <iostream>

class myclass
{
public:
    void *operator new (std::size_t count)
    {
        std::cout << "my new\n";
        return ::operator new (count);
    }

    void operator delete (void *ptr)
    {
        std::cout << "my delete\n";
        return ::operator delete (ptr);
    }
};

int main()
{
    auto ptr = new myclass;
    std::cout << ptr << '\n';
    delete ptr;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// my new
// 0x5561cac52280
// my delete
```

当使用特定于类的运算符时，只有为特定类或类提供重载的分配才会被指向你的重载。如前面的例子所示，`std::cout`所做的分配不会指向我们特定于类的重载，从而防止无限递归。唯一使用重载的分配和释放是`myclass`的分配和释放。

如预期的那样，所有全局运算符也存在于特定于类的运算符中，包括对齐分配的版本：

```cpp
#include <iostream>

class myclass
{
public:
    void *operator new[](std::size_t count, std::align_val_t al)
    {
        std::cout << "my new\n";
        return ::operator new (count, al);
    }

    void operator delete[](void *ptr, std::align_val_t al)
    {
        std::cout << "my delete\n";
        return ::operator delete (ptr, al);
    }
};

using aligned_myclass alignas(0x1000) = myclass;

int main()
{
    auto ptr1 = new aligned_myclass;
    auto ptr2 = new aligned_myclass[42];
    std::cout << ptr1 << '\n';
    std::cout << ptr2 << '\n';
    delete ptr1;
    delete [] ptr2;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// my new
// 0x563b49b74000
// 0x563b49b76000
// my delete
```

# 理解智能指针和所有权

在本节中，读者将学习如何使用智能指针来增加程序的安全性、可靠性和稳定性，同时也遵循 C++核心准则。

# std::unique_ptr{}指针

现在应该清楚了，C++提供了一套广泛的 API 来分配和释放动态内存。同时也应该清楚，无论你使用`malloc()`/`free()`还是`new()`/`delete()`，在大型应用程序中错误不仅可能而且很可能发生。例如，你可能会忘记将内存释放回堆：

```cpp
#include <iostream>

int main()
{
    auto ptr = new int;
    std::cout << ptr << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; valgrind ./a.out
// ==8627== LEAK SUMMARY:
// ==8627== definitely lost: 4 bytes in 1 blocks
// ==8627== indirectly lost: 0 bytes in 0 blocks
// ==8627== possibly lost: 0 bytes in 0 blocks
// ==8627== still reachable: 0 bytes in 0 blocks
// ==8627== suppressed: 0 bytes in 0 blocks
// ==8627== Rerun with --leak-check=full to see details of leaked memory
```

或者在分配数组时，你可以使用`delete`而不是`delete []`：

```cpp
#include <iostream>

int main()
{
    auto ptr = new int[42];
    std::cout << ptr << '\n';
    delete ptr;
}

// > g++ -std=c++17 scratchpad.cpp; valgrind ./a.out
// ==8656== Mismatched free() / delete / delete []
// ==8656== at 0x4C2E60B: operator delete(void*) (vg_replace_malloc.c:576)
// ==8656== by 0x108960: main (in /home/user/examples/chapter_7/a.out)
// ==8656== Address 0x5aebc80 is 0 bytes inside a block of size 168 alloc'd
// ==8656== at 0x4C2DC6F: operator new[](unsigned long) (vg_replace_malloc.c:423)
// ==8656== by 0x10892B: main (in /home/user/examples/chapter_7/a.out)
```

为了克服这一点，C++11 引入了指针所有权的概念，使用了两个类：

+   `std::unique_ptr{}`：定义了一个由单个实体独有拥有的指针。不允许复制该指针，并且由 C++自动处理内存释放。

+   `std::shared_ptr{}`: 定义一个可能由一个或多个实体拥有的指针。允许复制此指针，并且只有在所有所有者释放所有权时才会释放内存。

总的来说，C++核心指南不鼓励不是由这两个类执行的任何动态分配。在大多数情况下，通常会使用`new`和`delete`的地方，应该改用`std::unique_ptr{}`。考虑以下例子：

```cpp
#include <memory>
#include <iostream>

int main()
{
    auto ptr = std::make_unique<int>(42);
    std::cout << *ptr << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 42
```

为了创建`std::unique_ptr{}`和`std::shared_ptr`，C++提供了以下内容：

+   `std::make_unique()`: 创建`std::unique_ptr{}`

+   `std::make_shared()`: 创建`std::shared_ptr{}`

如果您计划遵守 C++核心指南，请熟悉这些函数。如上所示，要创建`std::unique_ptr{}`，必须提供要分配的对象类型以及对象的初始值作为模板参数。此外，如上所示，无需手动调用`delete()`运算符，因为这是由系统自动完成的。为了证明这一点，看下面的例子：

```cpp
#include <memory>
#include <iostream>

class myclass
{
public:
    ~myclass()
    {
        std::cout << "my delete\n";
    }
};

int main()
{
    auto ptr = std::make_unique<myclass>();
    std::cout << ptr.get() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x5621eb029e70
// my delete
```

在这个例子中使用`std::unique_ptr{}`，防止了内存泄漏和内存 API 不匹配。此外，这种智能分配和释放是有范围的。考虑以下例子：

```cpp
#include <memory>
#include <iostream>

class myclass1
{
public:
    ~myclass1()
    {
        std::cout << "my delete\n";
    }
};

class myclass2
{
    std::unique_ptr<myclass1> m_data;

public:
    myclass2() :
        m_data{std::make_unique<myclass1>()}
    { }
};

int main()
{
    myclass2();
    std::cout << "complete\n";
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// my delete
// complete
```

`myclass1`作为`myclass2`的成员变量存储。在`main`函数中，创建并立即销毁`myclass2`，结果是当销毁`myclass2`时，`myclass1`也会被释放回堆。

`std::unique_ptr{}`接受指向先前分配的内存的指针（例如通过`new()`运算符），然后在销毁时默认释放通过`delete()`运算符给出的内存。如果提供给`std::unique_ptr{}`的内存是使用`new[]()`而不是`new()`分配的，则应该使用`[]`版本的`std::unique_ptr{}`，以确保它使用`delete[]()`而不是`delete()`释放分配的内存：

```cpp
#include <memory>
#include <iostream>

class myclass1
{
public:
    ~myclass1()
    {
        std::cout << "my delete\n";
    }
};

int main()
{
    std::unique_ptr<myclass1[]>(new myclass1[2]);
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// my delete
// my delete
```

使用`std::unique_ptr{}`分配和释放数组的更符合 C++核心指南的方法是使用`std::make_unique()`的数组版本：

```cpp
#include <memory>
#include <iostream>

int main()
{
    auto ptr = std::make_unique<int[]>(42);
    std::cout << ptr.get() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x55b25f224e70
// my delete
```

`std::make_unique()`代替手动分配数组。使用`std::make_unique()`进行单个对象分配和数组分配的区别如下：

+   `std::make_unique<type>(args)`: 要执行单个对象分配，需要将类型作为模板参数提供，并将对象的构造函数参数作为参数提供给`std::make_unique()`

+   `std::make_unique<type[]>(size)`: 要执行数组分配，需要将数组类型作为模板参数提供，并将数组的大小作为参数提供给`std::make_unique()`

在某些情况下，提供给`std::unique_ptr{}`的内存无法使用`delete()`或`delete[]()`释放（例如`mmap()`缓冲区，放置`new()`等）。为支持这些类型的情况，`std::unique_ptr{}`接受自定义删除器：

```cpp
#include <memory>
#include <iostream>

class int_deleter
{
public:
    void operator()(int *ptr) const
    {
        std::cout << "my delete\n";
        delete ptr;
    };
};

int main()
{
    auto ptr = std::unique_ptr<int, int_deleter>(new int, int_deleter());
    std::cout << ptr.get() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x5615be977e70
// my delete
```

在上面的例子中，创建了一个`deleter`类，并提供了一个函数对象（即`operator ()`），用于执行自定义删除。当需要释放分配的内存时，`std::unique_ptr{}`会调用这个函数对象。

C++17 中`std::unique_ptr{}`的一个缺点是，`new`和`delete`运算符的对齐版本没有扩展到`std::unique_ptr{}`（或`std::shared_pointer{}`）。由于`std::unique_ptr{}`没有对齐版本，如果需要对齐内存，必须手动分配（希望这个问题在未来的 C++版本中得到解决，因为这种分配方式通常是 C++核心指南所不鼓励的）：

```cpp
#include <memory>
#include <iostream>

using aligned_int alignas(0x1000) = int;

int main()
{
    auto ptr = std::unique_ptr<int>(new aligned_int);
    std::cout << ptr.get() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x560eb6a0a000
```

与普通的 C++风格指针一样，`*`和`->`可以用于解引用`std::unique_ptr{}`：

```cpp
#include <memory>
#include <iostream>

struct mystruct {
    int data{42};
};

int main()
{
    auto ptr1 = std::make_unique<int>(42);
    auto ptr2 = std::make_unique<mystruct>();
    std::cout << *ptr1 << '\n';
    std::cout << ptr2->data << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 42
// 42
```

要使`std::unique_ptr{}`释放其分配，指针需要失去作用域，导致调用`std::unique_ptr{}`的析构函数，从而将分配释放回堆。`std::unique_ptr{}`还提供了`reset()`函数，它明确告诉指针在需要时释放其内存，而无需失去作用域：

```cpp
#include <memory>
#include <iostream>

int main()
{
    auto ptr = std::make_unique<int>();
    std::cout << ptr.get() << '\n';
    ptr.reset();
    std::cout << ptr.get() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x55bcfa2b1e70
// 0
```

在此示例中，`std::unique_ptr{}`被重置，因此它存储的指针等同于`nullptr`。`std::unique_ptr{}`在使用`->`和`*`等运算符对其进行解引用时不会检查指针是否有效。因此，应谨慎使用`reset()`函数，并且仅在需要时使用（例如，释放分配的顺序很重要时）。

以下是`std::unique_ptr{}`可能无效的几种方式（但这不是详尽列表）：

+   最初是使用`nullptr`创建的

+   调用了`reset()`或`release()`

为了检查`std::unique_ptr{}`是否有效，以确保不会意外发生空指针解引用，可以使用布尔运算符：

```cpp
#include <memory>
#include <iostream>

int main()
{
    auto ptr = std::make_unique<int>(42);
    if (ptr) {
        std::cout << *ptr << '\n';
    }
    ptr.reset();
    if (ptr) {
        std::cout << *ptr << '\n';
    }
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 42
```

如本例所示，一旦在`std::unique_ptr{}`上调用`reset()`，它就变得无效（即等于`nullptr`），布尔运算符返回`false`，防止`nullptr`解引用。

如果使用数组语法创建`std::unique_ptr{}`，则可以使用下标运算符来访问数组中的特定元素，类似于使用下标运算符访问标准 C 数组或`std::array{}`：

```cpp
#include <memory>
#include <iostream>

int main()
{
    auto ptr = std::make_unique<int[]>(42);
    std::cout << ptr[0] << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0
```

在上面的示例中，分配了大小为`42`的整数数组，并将数组中的第一个元素输出到`stdout`，其中包含值`0`，因为`std::make_unique()`使用值初始化来对所有分配进行零初始化。

应该注意，尽管 C++核心指南鼓励使用`std::unique_ptr{}`而不是手动分配和释放 C 风格数组，但指南不鼓励使用下标运算符来访问数组，因为这样做会执行不安全的指针算术，并可能导致`nullptr`解引用。相反，应该在访问之前将使用`std::unique_ptr{}`新分配的数组提供给`gsl::span`。

关于`std::unique_ptr{}`，C++17 的一个限制是无法直接将其添加到诸如`std::cout`之类的 IO 流。在 C++17 中，输出`std::unique_ptr{}`的地址的最佳方法是使用`get()`函数，该函数返回指针的地址。另一种实现这一点的方法是创建用户定义的重载：

```cpp
#include <memory>
#include <iostream>

template<typename T> std::ostream &
operator<<(std::ostream &os, const std::unique_ptr<T> &ptr)
{
    os << ptr.get();
    return os;
}

int main()
{
    auto ptr = std::make_unique<int>();
    std::cout << ptr << '\n';
    std::cout << ptr.get() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x55ed70997e70
```

# std::shared_ptr 指针

在大多数情况下，应该使用`std::unique_ptr{}`来分配动态内存。然而，在某些用例中，`std::unique_ptr{}`无法正确表示指针所有权。指针所有权指的是谁拥有指针，或者换句话说，谁负责分配，更重要的是，释放指针。在大多数情况下，程序中的单个实体负责此任务。然而，有一些用例需要多个实体来声明释放指针的责任。

最常见的情况是多个实体必须声明对变量的所有权，涉及线程。假设您有两个线程：

+   线程＃1 创建指针（因此拥有它）

+   线程＃2 使用来自线程＃1 的指针

在此示例中，第二个线程拥有指针，就像创建指针并在第一次提供它的第一个线程一样。以下示例演示了这种情况：

```cpp
#include <thread>
#include <iostream>

class myclass
{
    int m_data{0};

public:

    ~myclass()
    {
        std::cout << "myclass deleted\n";
    }

    void inc()
    { m_data++; }
};

std::thread t1;
std::thread t2;

void
thread2(myclass *ptr)
{
    for (auto i = 0; i < 100000; i++) {
        ptr->inc();
    }

    std::cout << "thread2: complete\n";
}

void
thread1()
{
    auto ptr = std::make_unique<myclass>();
    t2 = std::thread(thread2, ptr.get());

    for (auto i = 0; i < 10; i++) {
        ptr->inc();
    }

    std::cout << "thread1: complete\n";
}

int main()
{
    t1 = std::thread(thread1);

    t1.join();
    t2.join();
}

// > g++ -std=c++17 -lpthread scratchpad.cpp; ./a.out
// thread1: complete
// myclass deleted
// thread2: complete
```

在这个例子中，首先创建了第一个线程，它创建了一个指向`myclass`的指针。然后创建第二个线程，并将新创建的指针传递给这个第二个线程。两个线程对指针执行一系列操作，然后完成。问题在于，第一个线程没有第二个线程那么多的工作要做，所以它很快就完成了，释放了指针，而第二个线程还没有完成的机会，因为在这种情况下，我们明确声明`thread1`是指针的所有者，而`thread2`只是指针的使用者。

为了解决这个问题，C++提供了第二个智能指针，称为`std::shared_ptr{}`，它能够将所有权分配给多个实体。`std::shared_ptr{}`的语法几乎与`std::unique_ptr{}`相同。

```cpp
#include <memory>
#include <iostream>

int main()
{
    auto ptr = std::make_shared<int>();
    std::cout << ptr.get() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x562e6ba9ce80
```

在内部，`std::shared_ptr{}`将托管对象保存在一个单独的对象中，该对象在所有原始`std::shared_ptr{}`的副本之间共享。这个托管对象存储了`std::shared_ptr{}`副本的总数。每次创建一个副本，托管对象内的计数就会增加。当`std::shared_ptr{}`需要访问指针本身时，它必须使用指向托管对象的指针来请求指针（也就是说，`std::shared_ptr{}`并不存储指针本身，而是存储指向存储指针的托管对象的指针）。每次销毁`std::shared_ptr{}`时，托管对象的计数都会减少，当计数达到 0 时，指针最终会被释放回堆。

使用这种模式，`std::shared_ptr{}`能够将单个指针的所有权提供给多个实体。以下是使用`std::shared_ptr{}`而不是`std::unique_ptr{}`重写前面的示例：

```cpp
#include <thread>
#include <iostream>

class myclass
{
    int m_data{0};

public:

    ~myclass()
    {
        std::cout << "myclass deleted\n";
    }

    void inc()
    { m_data++; }
};

std::thread t1;
std::thread t2;

void
thread2(const std::shared_ptr<myclass> ptr)
{
    for (auto i = 0; i < 100000; i++) {
        ptr->inc();
    }

    std::cout << "thread2: complete\n";
}

void
thread1()
{
    auto ptr = std::make_shared<myclass>();
    t2 = std::thread(thread2, ptr);

    for (auto i = 0; i < 10; i++) {
        ptr->inc();
    }

    std::cout << "thread1: complete\n";
}

int main()
{
    t1 = std::thread(thread1);

    t1.join();
    t2.join();
}

// > g++ -std=c++17 -lpthread scratchpad.cpp; ./a.out
// thread1: complete
// thread2: complete
// myclass deleted
```

正如这个例子所示，`thread2`得到了原始`std::shared_ptr{}`的一个副本，实际上创建了指向单个托管对象的两个副本。当`thread1`完成时，`thread2`仍然保持对托管对象的引用，因此指针保持完好。直到第二个线程完成，托管对象的引用计数达到 0，指针才会被释放回堆。

需要注意的是，`std::shared_ptr{}`也存在一些缺点：

+   内存占用：由于`std::shared_ptr{}`保持对托管对象的指针，`std::shared_ptr{}`可能会导致两次 malloc 而不是一次（一些实现能够分配单个更大的内存块，并将其用于指针和托管对象）。无论实现方式如何，`std::shared_ptr{}`所需的内存量都大于`std::unique_ptr{}`，通常与常规 C 风格指针的大小相同。

+   性能：所有对指针的访问都必须首先重定向到托管对象，因为`std::shared_ptr{}`实际上并没有指针本身的副本（只有指向托管对象的指针）。因此，需要额外的函数调用（即指针解引用）。

+   内存泄漏：在管理内存的方式上，`std::unique_ptr{}`和`std::shared_ptr{}`之间存在权衡，两者都不能提供完美的解决方案，既能防止可能的`nullptr`解引用，又能防止内存泄漏。正如所示，在某些情况下使用`std::unique_ptr{}`可能会导致`nullptr`解引用。另一方面，`std::shared_ptr{}`可能会导致内存泄漏，如果`std::shared_ptr{}`的副本数量从未达到 0。尽管存在这些智能指针的问题，手动使用`new()`/`delete()`并不能解决这些问题（几乎肯定会使问题变得更糟），通常情况下，如果在正确的场景中使用正确的智能指针类型，这些问题可以得到缓解。

+   循环引用：使用`std::shared_ptr{}`可以创建循环引用。

与`std::unique_ptr{}`一样，`std::shared_ptr{}`提供了一个`reset()`函数：

```cpp
#include <memory>
#include <iostream>

int main()
{
    auto ptr1 = std::make_shared<int>();
    auto ptr2 = ptr1;
    std::cout << ptr1.get() << '\n';
    std::cout << ptr2.get() << '\n';
    ptr2.reset();
    std::cout << ptr1.get() << '\n';
    std::cout << ptr2.get() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x555b99574e80
// 0x555b99574e80
// 0x555b99574e80
// 0
```

在这个例子中，创建了两个`std::shared_ptr{}`的副本。我们首先将这些指针的地址输出到`stdout`，如预期的那样，地址是有效的，它们是相同的（因为它们都指向同一个托管对象）。接下来，使用`reset()`函数释放第二个指针，然后再次输出指针的地址。第二次，第一个`std::shared_ptr{}`仍然指向有效指针，而第二个指向`nullptr`，因为它不再引用原始托管对象。当`main()`函数完成时，指针最终将被释放到堆上。

C++17 版本的`std::shared_ptr{}`的一个问题是缺乏类似`std::unique_ptr{}`的数组版本。也就是说，没有`std::shared_ptr<type[]>`版本的`std::shared_ptr{}`，类似于`std::unique_ptr<type[]>{}`的 API。因此，无法使用`std::make_shared()`来分配数组，并且没有下标运算符来访问数组中的每个元素。相反，必须执行以下操作：

```cpp
#include <memory>
#include <iostream>

int main()
{
    auto ptr = std::shared_ptr<int>(new int[42]());
    std::cout << ptr.get()[0] << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0
```

C++还提供了一种确定`std::shared_ptr{}`存在多少个副本的方法（实质上只是询问托管对象的引用计数）：

```cpp
#include <memory>
#include <iostream>

int main()
{
    auto ptr1 = std::make_shared<int>();
    auto ptr2 = ptr1;
    std::cout << ptr1.get() << '\n';
    std::cout << ptr2.get() << '\n';
    std::cout << ptr1.use_count() << '\n';
    ptr2.reset();
    std::cout << ptr1.get() << '\n';
    std::cout << ptr2.get() << '\n';
    std::cout << ptr1.use_count() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x5644edde7e80
// 0x5644edde7e80
// 2
// 0x5644edde7e80
// 0
// 1
```

这个示例与前面的`reset()`示例类似，但增加了对`use_count()`函数的调用，该函数报告`std::shared_ptr{}`的总副本数。如示例所示，当创建两个`std::shared_ptr{}`的副本时，`use_count()`报告`2`。当运行`reset()`时，`use_count()`减少为`1`，最终当`main()`完成时，此计数将减少为`0`，指针将被释放到堆上。应该注意，在多线程环境中应谨慎使用此函数，因为可能会发生关于报告的计数的竞争。

与`std::unique_ptr{}`类似，`std::shared_ptr{}`也提供了一个布尔运算符来检查指针是否有效。与`std::unique_ptr{}`不同，布尔运算符不确定托管对象是否已被释放（因为可能有一个`std::shared_ptr{}`的副本在某个地方）。相反，布尔运算符报告`std::shared_ptr{}`是否在维护对托管对象的引用。如果`std::shared_ptr{}`有效，则它引用托管对象（因此可以访问分配的指针），布尔运算符报告`true`。如果`std::shared_ptr{}`无效，则不再维护对托管对象的引用（因此无法访问分配的指针），调用`get()`时返回`nullptr`，布尔运算符报告`false`：

```cpp
#include <memory>
#include <iostream>

int main()
{
    auto ptr = std::make_shared<int>();
    if (ptr) {
        std::cout << "before: " << ptr.get() << '\n';
    }
    ptr.reset();
    if (ptr) {
        std::cout << "after: "<< ptr.get() << '\n';
    }
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// before: 0x55ac226b5e80
```

如前面的示例所示，当调用`reset()`函数时，指针将不再有效，因为智能指针内部管理的对象现在指向`nullptr`，因此布尔运算符返回`false`。由于没有其他`std::shared_ptr{}`的副本（即，托管对象的计数为`0`），分配的指针也将被释放到堆上。

与`std::unique_ptr{}`一样，`std::shared_ptr{}`提供了`*`和`->`运算符来取消引用`std::shared_ptr{}`（但不提供下标运算符，因为不支持数组）：

```cpp

#include <memory>
#include <iostream>

struct mystruct {
    int data;
};

int main()
{
    auto ptr = std::make_shared<mystruct>();
    std::cout << ptr->data << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0
```

最后，`std::shared_ptr{}`的一个问题是循环引用。以下示例最好地描述了这个问题：

```cpp
#include <memory>
#include <iostream>

class myclass2;

class myclass1
{
public:

    ~myclass1()
    {
        std::cout << "delete myclass1\n";
    }

    std::shared_ptr<myclass2> m;
};

class myclass2
{
public:

    ~myclass2()
    {
        std::cout << "delete myclass2\n";
    }

    std::shared_ptr<myclass1> m;
};

int main()
{
    auto ptr1 = std::make_shared<myclass1>();
    auto ptr2 = std::make_shared<myclass2>();
    ptr1->m = ptr2;
    ptr2->m = ptr1;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
```

在这个例子中，创建了两个类——`myclass1`和`myclass2`。`myclass1`和`myclass2`都维护对彼此的`std::shared_ptr{}`引用（也就是说，出于某种原因，两个类都声称拥有对另一个类的所有权）。当指针被销毁时，没有内存被释放到堆上，因为没有一个析构函数被调用。要理解原因，我们需要分解所做的副本数量以及它们存在的位置。

`ptr1`和`ptr2`的原始`std::shared_ptr{}`都是在`main()`函数中创建的，这意味着`#1`和`#2`管理的对象在创建时都有`use_count()`为`1`。接下来，`ptr1`得到了`ptr2`的`std::shared_ptr{}`的副本，反之亦然，这意味着`#1`和`#2`管理的对象现在都有`use_count()`为`2`。当`main()`完成时，`main()`函数中的`ptr2`的`std::shared_ptr{}`被销毁（而不是`ptr1`中的`std::shared_ptr{}`），但由于`ptr1`中仍然有`ptr2`的`std::shared_ptr{}`的副本，指针本身并没有被释放。接下来，`main()`中的`ptr1`被销毁，但由于`ptr1`的副本仍然存在于`ptr1`的一个副本中，`ptr1`本身也没有被释放，因此，我们创建了一个指向彼此的`ptr1`和`ptr2`的副本，但代码本身没有剩余的这些指针的副本来释放这个内存，因此内存被永久删除。

为了解决这个问题，`std::shared_ptr{}`提供了一个称为`std::weak_ptr{}`的版本。它具有`std::shared_ptr{}`的所有属性，但不会增加托管对象的引用计数。虽然`get()`函数可以用来存储原始指针，但`std::weak_ptr{}`仍然与托管对象保持连接，提供了一种确定托管对象是否已被销毁的方法，这是使用原始指针无法做到的。为了证明这一点，前面的例子已经被转换为在`myclass1`和`myclass2`中使用`std::weak_ptr{}`而不是`std::shared_ptr{}`：

```cpp
#include <memory>
#include <iostream>

class myclass2;

class myclass1
{
public:

    ~myclass1()
    {
        std::cout << "delete myclass1\n";
    }

    std::weak_ptr<myclass2> m;
};

class myclass2
{
public:

    ~myclass2()
    {
        std::cout << "delete myclass2\n";
    }

    std::weak_ptr<myclass1> m;
};

int main()
{
    auto ptr1 = std::make_shared<myclass1>();
    auto ptr2 = std::make_shared<myclass2>();
    ptr1->m = ptr2;
    ptr2->m = ptr1;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// delete myclass2
// delete myclass1
```

正如本例所示，即使存在循环引用，当`main()`完成时，分配的指针也会被释放回堆。最后，应该注意，可以使用以下语法将`std::unique_ptr`转换为`std::shared_ptr`：

```cpp
auto ptr = std::make_unique<int>();
std::shared_ptr<int> shared = std::move(ptr);
```

由于`std::unique_ptr`被移动，它不再拥有指针，而是`std::shared_ptr`现在拥有指针。从`std::shared_ptr`移动到`std::unqiue_ptr`是不允许的。

# 学习映射和权限

在本节中，读者将学习如何使用 C++模式映射内存。您将学习如何映射内存（一种常见的系统编程技术），同时使用 C++模式进行操作。

# 基础知识

`malloc()`/`free()`、`new()`/`delete()`和`std::unique_ptr{}`/`std::shared_ptr{}`并不是在 POSIX 系统上分配内存的唯一方法。C++风格的分配器是另一种更复杂的分配内存的方法，将在第九章中更详细地讨论，*分配器的实践方法*。一种更直接的、POSIX 风格的分配内存的方法是使用`mmap()`：

```cpp
#include <iostream>
#include <sys/mman.h>

constexpr auto PROT_RW = PROT_READ | PROT_WRITE;
constexpr auto MAP_ALLOC = MAP_PRIVATE | MAP_ANONYMOUS;

int main()
{
    auto ptr = mmap(0, 0x1000, PROT_RW, MAP_ALLOC, -1, 0);
    std::cout << ptr << '\n';

    munmap(ptr, 0x1000);
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x7feb41ab6000
```

`mmap()`函数可以用来将来自不同来源的内存映射到程序中。例如，如果要将设备内存映射到应用程序中，可以使用`mmap()`。如果将`MAP_ANONYMOUS`传递给`mmap()`，它可以用来分配内存，就像使用`malloc()`和`free()`分配内存一样。在前面的例子中，`mmap()`用于分配一个标记为读/写的 4k 页面的内存。使用`MAP_PRIVATE`告诉`mmap()`您不打算与其他应用程序共享此内存（例如，用于进程间通信）。与使用`malloc()`/`free()`分配内存相比，以这种方式映射内存有一些优点和缺点。

**优点**：

+   **碎片化**：使用`MAP_ANONYMOUS`分配内存通常会将内存映射为页面大小的倍数，或者在最坏的情况下，是 2 的幂。这是因为`mmap()`正在向操作系统内核请求一个内存块，而该内存必须映射到应用程序中，这只能以不小于一个页面的块来完成。因此，与通常使用`malloc()`进行多次随机内存分配相比，这种内存的碎片化可能性要小得多。

+   **权限**：在使用`mmap()`时，您可以指定要应用于新分配内存的权限。如果您需要具有特殊权限的内存，例如读/执行内存，这将非常有用。

+   **共享内存**：使用`mmap()`分配的内存也可以被另一个应用程序共享，而不是为特定应用程序私有分配，就像使用`malloc()`一样。

**缺点**：

+   **性能**：`malloc()`/`free()`分配和释放由应用程序内部的 C 库管理的内存块。如果需要更多内存，C 库将调用操作系统，使用诸如`brk()`甚至`mmap()`的函数，从操作系统获取更多内存。调用 free 时，释放的内存将返回到由 C 库管理的内存中，并且在许多情况下实际上从未返回到操作系统。因此，`malloc()`/`free()`可以快速为应用程序分配内存，因为不会进行任何特定于操作系统的调用（除非当然 C 库耗尽内存）。另一方面，`mmap()`必须在每次分配时调用操作系统。因此，它的性能不如`malloc()`/`free()`，因为操作系统调用可能很昂贵。

+   **粒度**：与`mmap()`减少碎片化的原因相同，它也减少了粒度。`mmap()`进行的每次分配至少是一个页面大小，即使请求的内存只有一个字节。

为了演示`mmap()`的潜在浪费，请参阅以下内容：

```cpp
#include <iostream>
#include <sys/mman.h>

constexpr auto PROT_RW = PROT_READ | PROT_WRITE;
constexpr auto MAP_ALLOC = MAP_PRIVATE | MAP_ANONYMOUS;

int main()
{
    auto ptr1 = mmap(0, 42, PROT_RW, MAP_ALLOC, -1, 0);
    auto ptr2 = mmap(0, 42, PROT_RW, MAP_ALLOC, -1, 0);

    std::cout << ptr1 << '\n';
    std::cout << ptr2 << '\n';

    munmap(ptr1, 42);
    munmap(ptr2, 42);
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x7fc1637ad000
// 0x7fc1637ac000
```

在此示例中，分配了 42 字节两次，但生成的地址相隔 4k 页。这是因为由`mmap()`进行的分配必须至少是一个页面大小，即使请求的数量仅为 42 字节。`malloc()`/`free()`没有这种浪费的原因是这些函数一次从操作系统请求大块内存，然后在 C 库内部使用各种不同的分配方案管理这些内存。有关如何执行此操作的更多信息，在`newlib`中有一个关于此主题的非常好的解释：[`sourceware.org/git/?p=newlib-cygwin.git;a=blob;f=newlib/libc/stdlib/malloc.c.`](https://sourceware.org/git/?p=newlib-cygwin.git;a=blob;f=newlib/libc/stdlib/malloc.c;h=f5ac2920888563013663454758cce102e40b69ad;hb=HEAD)

# 权限

`mmap()`可用于使用特殊参数分配内存。例如，假设您需要分配具有读/执行权限而不是通常与`malloc()`/`free()`相关联的读/写权限的内存：

```cpp
#include <iostream>
#include <sys/mman.h>

constexpr auto PROT_RE = PROT_READ | PROT_EXEC;
constexpr auto MAP_ALLOC = MAP_PRIVATE | MAP_ANONYMOUS;

int main()
{
    auto ptr = mmap(0, 0x1000, PROT_RE, MAP_ALLOC, -1, 0);
    std::cout << ptr << '\n';

    munmap(ptr, 0x1000);
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x7feb41ab6000
```

如所示，使用读/执行权限分配内存与使用读/写权限分配内存相同，将`PROT_WRITE`替换为`PROT_EXEC`。

在支持读/写或读/执行（也称为 W^E，表示写与执行互斥）的系统上，不应同时使用写和执行权限。特别是在程序被恶意使用的情况下，防止可执行内存同时具有写权限可以防止许多已知的网络攻击。

将内存分配为只读/执行而不是读/写/执行的问题在于，没有简单的方法将可执行代码放入新分配的缓冲区中，因为内存被标记为只读/执行。如果您希望分配只读内存也是如此。再次，由于从未添加写权限，因此无法向只读内存添加数据，因为它没有写权限。

为了解决这个问题，一些操作系统阻止应用程序分配读/写/执行内存，因为它们试图强制执行 W^E 权限。为了克服这个问题，同时仍然提供设置所需权限的手段，POSIX 提供了`mprotect()`，它允许您更改已经分配的内存的权限。尽管这可能与由`malloc()`/`free()`管理的内存一起使用，但它应该与`mmap()`一起使用，因为大多数体系结构上的页面级别上只能强制执行内存权限。`malloc()`/`free()`从一个大缓冲区中分配，该缓冲区在程序的所有分配之间共享，而`mmap()`只分配页面粒度的内存，因此不会被其他分配共享。

以下是如何使用`mprotect`的示例：

```cpp
#include <iostream>
#include <sys/mman.h>

constexpr auto PROT_RW = PROT_READ | PROT_WRITE;
constexpr auto MAP_ALLOC = MAP_PRIVATE | MAP_ANONYMOUS;

int main()
{
    auto ptr = mmap(0, 0x1000, PROT_RW, MAP_ALLOC, -1, 0);
    std::cout << ptr << '\n';

    if (mprotect(ptr, 0x1000, PROT_READ) == -1) {
        std::clog << "ERROR: Failed to change memory permissions\n";
        ::exit(EXIT_FAILURE);
    }

    munmap(ptr, 0x1000);
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 0x7fb05b4b6000
```

在这个例子中，`mmap()`用于分配一个大小为 4k 页面的缓冲区，并具有读/写权限。分配内存后，`mprotect()`用于将内存的权限更改为只读。最后，`munmap()`用于将内存释放回操作系统。

# 智能指针和 mmap()

就 C++而言，`mmap()`和`munmap()`的最大问题是它们遭受了与`malloc()`/`free()`相同的许多缺点：

+   **内存泄漏**：由于`mmap()`和`munmap()`必须手动执行，用户可能会忘记在不再需要内存时调用`munmap()`，或者复杂的逻辑错误可能导致在正确的时间不调用`munmap()`。

+   **内存不匹配**：`mmap()`的用户可能会错误地调用`free()`而不是`munmap()`，这几乎肯定会导致不稳定，因为来自`mmap()`的内存来自操作系统内核，而`free()`期望来自应用程序堆的内存。

为了克服这个问题，`mmap()`应该用`std::unique_ptr{}`包装：

```cpp
#include <memory>
#include <iostream>

#include <string.h>
#include <sys/mman.h>

constexpr auto PROT_RW = PROT_READ | PROT_WRITE;
constexpr auto MAP_ALLOC = MAP_PRIVATE | MAP_ANONYMOUS;

class mmap_deleter
{
    std::size_t m_size;

public:
    mmap_deleter(std::size_t size) :
        m_size{size}
    { }

    void operator()(int *ptr) const
    {
        munmap(ptr, m_size);
    }
};

template<typename T, typename... Args>
auto mmap_unique(Args&&... args)
{
    if (auto ptr = mmap(0, sizeof(T), PROT_RW, MAP_ALLOC, -1, 0)) {

        auto obj = new (ptr) T(args...);
        auto del = mmap_deleter(sizeof(T));

        return std::unique_ptr<T, mmap_deleter>(obj, del);
    }

    throw std::bad_alloc();
}

int main()
{
    auto ptr = mmap_unique<int>(42);
    std::cout << *ptr << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// 42
```

在这个例子中，主函数调用`mmap_unique()`而不是`std::make_unqiue()`，因为`std::make_unique()`使用`new()`/`delete()`分配内存，而我们希望使用`mmap()`/`munmap()`。`mmap_unique()`函数的第一部分使用`mmap()`分配内存的方式与我们之前的例子相同。在这种情况下，权限被设置为读/写，但也可以使用`mprotect()`进行更改，以提供只读或读/执行权限。如果`mmap()`调用失败，就像 C++库一样，会抛出`std::bad_alloc()`。

在这个例子中的下一行使用了`new()`放置运算符，如前面在*放置 new*部分中讨论的。这个调用的目标是创建一个对象，其构造函数已被调用以初始化所需的`T`类型。在这个例子中，这是将一个整数设置为`42`，但如果使用的是类而不是整数，类的构造函数将被调用，并传递给`mmap_unique()`的任何参数。

下一步是为我们的`std::unqiue_ptr{}`创建自定义删除器。这是因为默认情况下，`std::unqiue_ptr{}`将调用`delete()`运算符而不是`munmap()`。自定义删除器接受一个参数，即原始分配的大小。这是因为`munmap()`需要知道原始分配的大小，而`delete()`和`free()`只需要一个指针。

最后，使用新创建的对象和自定义删除器创建了`std::unique_ptr{}`。从这一点开始，使用`mmap()`分配的所有内存都可以使用标准的`std::unique_ptr{}`接口访问，并被视为正常分配。当指针不再需要，并且`std::unique_ptr{}`超出范围时，将调用`munmap()`将指针释放回操作系统内核。

# 共享内存

除了分配内存外，`mmap（）`还可用于分配共享内存，通常用于进程间通信。为了演示这一点，我们首先定义一个共享内存名称`"/shm"`，以及我们的读取、写入和执行权限：

```cpp
#include <memory>
#include <iostream>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

constexpr auto PROT_RW = PROT_READ | PROT_WRITE;

auto name = "/shm";
```

接下来，我们必须定义我们的自定义删除器，它使用`munmap（）`而不是`free（）`：

```cpp
class mmap_deleter
{
    std::size_t m_size;

public:
    mmap_deleter(std::size_t size) :
        m_size{size}
    { }

    void operator()(int *ptr) const
    {
        munmap(ptr, m_size);
    }
};
```

在这个例子中，我们基于之前的例子，但现在不再只有一个`mmap_unique（）`函数，而是有一个服务器版本和一个客户端版本。尽管通常共享内存会用于进程间通信，在这个例子中，我们在同一个应用程序中共享内存，以保持简单。

`main`函数创建了一个服务器和一个客户端共享指针。服务器版本使用以下方式创建共享内存：

```cpp
template<typename T, typename... Args>
auto mmap_unique_server(Args&&... args)
{
  if(int fd = shm_open(name, O_CREAT | O_RDWR, 0644); fd != -1) {
      ftruncate(fd, sizeof(T));

        if (auto ptr = mmap(0, sizeof(T), PROT_RW, MAP_SHARED, fd, 0)) {

            auto obj = new (ptr) T(args...);
            auto del = mmap_deleter(sizeof(T));

            return std::unique_ptr<T, mmap_deleter>(obj, del);
        }
    }

    throw std::bad_alloc();
}
```

这个函数类似于之前例子中的`mmap_unique（）`函数，但是打开了一个共享内存文件的句柄，而不是使用`MAP*_*ANONYMOUS`来分配内存。为了打开共享内存文件，我们使用`POSIX shm_open（）`函数。这个函数类似于`open（）`函数。第一个参数是共享内存文件的名称。第二个参数定义了文件的打开方式，而第三个参数提供了模式。`shm_open（）`用于打开共享内存文件，并检查文件描述符以确保分配成功（即文件描述符不是`-1`）。

接下来，文件描述符被截断。这确保了共享内存文件的大小等于我们希望共享的内存大小。在这种情况下，我们希望共享一个单一的`T`类型，所以我们需要获取`T`的大小。一旦共享内存文件的大小被正确调整，我们需要使用`mmap（）`映射共享内存。对`mmap（）`的调用与我们之前的示例相同，唯一的区别是使用了`MAP_SHARED`。

最后，就像之前的例子一样，我们利用`new()`放置运算符在共享内存中创建新分配的类型，我们创建自定义删除器，然后最后，我们返回`std::unique_ptr{}`以用于这个共享内存。

连接到这个共享内存（可以从另一个应用程序中完成），我们需要使用`mmap_unique（）`函数的客户端版本：

```cpp
template<typename T>
auto mmap_unique_client()
{
  if(int fd = shm_open(name, O_RDWR, 0644); fd != -1) {
      ftruncate(fd, sizeof(T));

        if (auto ptr = mmap(0, sizeof(T), PROT_RW, MAP_SHARED, fd, 0)) {

            auto obj = static_cast<T*>(ptr);
            auto del = mmap_deleter(sizeof(T));

            return std::unique_ptr<T, mmap_deleter>(obj, del);
        }
    }

    throw std::bad_alloc();
}
```

这些函数的服务器和客户端版本看起来相似，但也有区别。首先，共享内存文件是在没有`O_CREAT`的情况下打开的。这是因为服务器创建共享内存文件，而客户端连接到共享内存文件，因此在客户端版本中不需要传递`O_CREAT`。最后，这个函数的客户端版本的签名不像服务器版本那样带有任何参数。这是因为服务器版本使用`new()`放置来初始化共享内存，不需要再次执行。而不是使用新的放置，`static_cast()`被用来将`void *`转换为适当的类型，然后将指针传递给新创建的`std::unique_ptr{}`：

```cpp
int main()
{
    auto ptr1 = mmap_unique_server<int>(42);
    auto ptr2 = mmap_unique_client<int>();
    std::cout << *ptr1 << '\n';
    std::cout << *ptr2 << '\n';
}

// > g++ -std=c++17 scratchpad.cpp -lrt; ./a.out
// 42
// 42
```

这个例子的结果是，内存在服务器和客户端之间共享，将共享内存包装在`std::unique_ptr{}`中。此外，正如例子中所示，内存被正确共享，可以看到服务器和客户端版本的指针都打印出`42`。尽管我们用于整数类型，但这种类型的共享内存可以根据需要与任何复杂类型一起使用（尽管在尝试共享类时应该小心，特别是那些利用继承并包含`vTable`的类）。

# 学习内存碎片化的重要性

没有关于内存管理的章节是完整的，而没有对碎片的简要讨论。内存碎片指的是一种将内存分割成块的过程，通常是分散的，几乎总是导致分配器无法为应用程序分配内存，最终导致在 C++中抛出`std::bad_alloc()`。在编程系统时，碎片应该始终是一个关注点，因为它可能会极大地影响程序的稳定性和可靠性，特别是在资源受限的系统上，比如嵌入式和移动应用程序。在本节中，读者将简要介绍碎片，以及它如何影响他们创建的程序。

有两种类型的碎片——外部碎片和内部碎片。

# 外部碎片

外部碎片指的是内存分配和释放的过程，以不同大小的块进行，最终导致大量不可用的未分配内存。为了证明这一点，假设我们有五次分配：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-sys-prog-cpp/img/9fc89297-46e9-493a-994f-e7b8b2386dcf.png)

所有五次分配都成功了，所有内存都被分配了。现在，假设第二次和第四次分配被释放回堆：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-sys-prog-cpp/img/02d7340a-fdc8-4d25-9506-74b811a03676.png)

通过将内存释放回堆，内存现在可以再次用于分配。问题在于，由于最初的 1、3 和 5 次分配，这些内存是分散的。现在假设我们想进行最后一次分配：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-sys-prog-cpp/img/bdfab869-a161-4d4f-ae94-adc506cc324c.png)

最终的分配失败了，即使有足够的空闲内存进行分配，因为空闲内存是分散的——换句话说，空闲内存是碎片化的。

在一般情况下，外部碎片是一个极其难以解决的问题，这个问题已经研究了多年，操作系统随着时间的推移实施了各种不同的方法。在第九章中，《分配器的实践方法》，我们将讨论如何使用 C++分配器来解决程序中一些外部碎片问题，使用各种不同的自定义分配器模式。

# 内部碎片

内部碎片指的是在分配过程中浪费的内存。例如，当我们使用`mmap()`分配一个整数时，就像我们在前面的例子中所做的那样，`mmap()`为整数分配了整个页面，从而在过程中浪费了将近 4k 的内存。这就是所谓的内部碎片：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-sys-prog-cpp/img/5e7d70c8-4671-46ec-8946-83c569822fd1.png)

与外部碎片一样，内部碎片的丢失内存也不能用于其他分配。事实上，从高层次上看，内存的视图看起来就像外部碎片一样。不同之处在于，外部碎片不断地将大块的空闲未分配内存分割成越来越小的碎片内存，最终变得太小而无法在将来分配。内部碎片看起来也是一样的，但在某些情况下，甚至更大的不可用内存块会出现在整个内存中。这些不可用的内存不是因为它对于给定的分配来说不够大，而是因为不可用的内存已经被较小的先前分配所占用，而这些分配根本没有使用它所获得的所有内存。

应该注意的是，在解决碎片问题时，通常的解决方案是优化一种类型的碎片而不是另一种，每种选择都有其优点和缺点。

# 内部碎片和外部碎片

`malloc()`和`free()`使用的分配器通常更倾向于优化内部碎片而不是外部碎片。目标是提供一个尽可能少浪费的分配器，然后利用各种不同的分配模式来尽可能减少外部碎片的可能性。这些类型的分配器被应用程序所青睐，因为它们最小化了在任何给定操作系统上单个应用程序的内存需求，为其他应用程序留下了额外的内存。此外，如果外部碎片化阻止了分配的发生，应用程序总是向操作系统请求更多的内存（直到操作系统用尽）。

# 外部碎片优于内部碎片

操作系统倾向于优化外部碎片而不是内部碎片。这是因为操作系统通常只能以页面粒度分配内存，这意味着在许多情况下内部碎片是不可避免的。此外，如果允许外部碎片随时间发生，最终会导致操作系统崩溃。因此，操作系统使用分配模式，如伙伴分配器模式，它优化外部碎片，即使以牺牲大量内部碎片为代价。

# 摘要

在本章中，我们学习了使用`new()`、`delete()`、`malloc()`和`free()`来分配内存的各种方法，包括对齐内存和 C 风格数组。我们研究了全局内存（全局空间中的内存）、堆栈内存（或作用域内存）和动态分配内存（使用`new()`和`delete()`分配的内存）之间的区别。还讨论了`new()`和`delete()`的安全性问题，并演示了 C++智能指针，包括`std::shared_ptr{}`和`std::unique_ptr{}`，如何防止程序中常见的不稳定性问题，以及它们如何提供 C++核心指导支持。我们通过快速回顾碎片化以及它如何影响系统程序来结束本章。

在下一章中，我们将涵盖文件输入和输出，包括读写文件以及 C++17 添加的文件系统 API。

# 问题

1.  `new()`和`new[]()`之间有什么区别？

1.  `delete()`可以安全地用于释放使用`new[]()`分配的内存吗？

1.  全局内存和静态内存之间有什么区别？

1.  如何使用`new()`分配对齐内存？

1.  `std::make_shared()`可以用来分配数组吗？

1.  在什么情况下应该使用`std::shared_ptr{}`而不是`std::unique_ptr{}`？

1.  `mmap()`可以用来分配读/执行内存吗？

1.  内部碎片和外部碎片之间有什么区别？

# 进一步阅读

+   [`www.packtpub.com/application-development/c17-example`](https://www.packtpub.com/application-development/c17-example)

+   [`www.packtpub.com/application-development/getting-started-c17-programming-video`](https://www.packtpub.com/application-development/getting-started-c17-programming-video)
