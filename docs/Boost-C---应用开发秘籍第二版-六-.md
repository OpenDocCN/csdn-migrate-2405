# Boost C++ 应用开发秘籍第二版（六）

> 原文：[`annas-archive.org/md5/8a1821d22bcd421390c328e6f1d92500`](https://annas-archive.org/md5/8a1821d22bcd421390c328e6f1d92500)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：与系统一起工作

在本章中，我们将涵盖：

+   在目录中列出文件

+   删除和创建文件和目录

+   编写和使用插件

+   获取回溯-当前调用序列

+   快速从一个进程传递数据到另一个进程

+   同步进程间通信

+   在共享内存中使用指针

+   读取文件的最快方式

+   协程-保存状态和推迟执行

# 介绍

每个操作系统都有许多系统调用。这些调用在一个操作系统和另一个操作系统之间有所不同，但执行的功能非常接近。Boost 提供了对这些调用的可移植和安全的包装器。了解包装器对于编写良好的程序至关重要。

本章专门讨论与操作系统的工作。我们已经看到如何处理网络通信和信号第六章中的*操作任务*。在本章中，我们将更仔细地研究文件系统，创建和删除文件。我们将看到如何在不同系统进程之间传递数据，如何以最大速度读取文件，以及如何执行其他技巧。

# 在目录中列出文件

有标准库函数和类来读取和写入文件数据。但在 C++17 之前，没有函数来列出目录中的文件，获取文件类型或获取文件的访问权限。

让我们看看如何使用 Boost 来修复这些不平等。我们将编写一个程序，列出当前目录中的文件名、写入访问权限和文件类型。

# 准备工作

对 C++的一些基础知识就足够使用这个示例了。

此示例需要链接`boost_system`和`boost_filesystem`库。

# 如何做...

这个和下一个示例是关于使用文件系统的可移植包装器：

1.  我们需要包括以下两个头文件：

```cpp
#include <boost/filesystem/operations.hpp> 
#include <iostream> 
```

1.  现在，我们需要指定一个目录：

```cpp
int main() { 
    boost::filesystem::directory_iterator begin("./"); 
```

1.  在指定目录之后，循环遍历其内容：

```cpp
    boost::filesystem::directory_iterator end; 
    for (; begin != end; ++ begin) { 
```

1.  下一步是获取文件信息：

```cpp
        boost::filesystem::file_status fs = 
            boost::filesystem::status(*begin);
```

1.  现在，输出文件信息：

```cpp
        switch (fs.type()) { 
        case boost::filesystem::regular_file: 
            std::cout << "FILE       ";  
            break; 
        case boost::filesystem::symlink_file: 
            std::cout << "SYMLINK    ";  
            break; 
        case boost::filesystem::directory_file: 
            std::cout << "DIRECTORY  ";  
            break; 
        default: 
            std::cout << "OTHER      ";  
            break; 
        } 
        if (fs.permissions() & boost::filesystem::owner_write) { 
            std::cout << "W "; 
        } else { 
            std::cout << "  "; 
        } 
```

1.  最后一步是输出文件名：

```cpp
        std::cout << *begin << '\n'; 
    } /*for*/ 
} /*main*/ 
```

就是这样；现在如果我们运行程序，它将输出类似这样的内容：

```cpp
FILE W "./main.o" 
FILE W "./listing_files" 
DIRECTORY W "./some_directory" 
FILE W "./Makefile" 
```

# 它是如何工作的...

`Boost.Filesystem`的函数和类只是包装了特定于系统的函数，以便处理文件。

注意*步骤 2*中`/`的使用。 POSIX 系统使用斜杠来指定路径； Windows 默认使用反斜杠。 但是，Windows 也理解正斜杠，因此`./`将在所有流行的操作系统上工作，并且表示当前目录。

看看*步骤 3*，在那里我们正在默认构造`boost::filesystem::directory_iterator`类。它的工作方式就像`std::istream_iterator`类，当默认构造时充当`end`迭代器。

*步骤 4*是一个棘手的步骤，不是因为这个函数很难理解，而是因为发生了许多转换。解引用`begin`迭代器返回`boost::filesystem::directory_entry`，它隐式转换为`boost::filesystem::path`，然后用作`boost::filesystem::status`函数的参数。实际上，我们可以做得更好：

```cpp
boost::filesystem::file_status fs = begin->status(); 
```

仔细阅读参考文档，以避免不必要的隐式转换。

*步骤 5*是显而易见的，所以我们转到*步骤 6*，在那里再次发生对路径的隐式转换。更好的解决方案是：

```cpp
std::cout << begin->path() << '\n'; 
```

在这里，`begin->path()`返回`boost::filesystem::directory_entry`内包含的`boost::filesystem::path`变量的常量引用。

# 还有更多...

;`Boost.Filesystem`是 C++17 的一部分。C++17 中的所有内容都位于单个头文件`<filesystem>`中，位于`std::filesystem`命名空间中。标准库版本的文件系统与 Boost 版本略有不同，主要是通过使用作用域枚举（`enum class`）来区分，而`Boost.Filesystem`使用的是非作用域`enum`。

有一个类；`directory_entry`。该类提供了文件系统信息的缓存，因此如果您经常使用文件系统并查询不同的信息，请尝试使用`directory_entry`以获得更好的性能。

就像其他 Boost 库一样，`Boost.Filesystem`可以在 C++17 编译器之前甚至在 C++11 编译器之前工作。

# 另请参阅

+   *擦除和创建文件和目录*教程将展示`Boost.Filesystem`的另一个用法示例

+   阅读 Boost 关于`Boost.Filesystem`的官方文档，以获取有关其功能的更多信息；可以在以下链接找到：[`boost.org/libs/filesystem`](http://boost.org/libs/filesystem)

+   您可以在[`www.open-std.org/jtc1/sc22/wg21/docs/papers/2017/n4659.pdf`](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2017/n4659.pdf)找到 C++17 草案

# 擦除和创建文件和目录

让我们考虑以下代码行：

```cpp
    std::ofstream ofs("dir/subdir/file.txt"); 
    ofs << "Boost.Filesystem is fun!"; 
```

在这些行中，我们尝试向`dir/subdir`目录中的`file.txt`写入一些内容。如果没有这样的目录，这个尝试将失败。与文件系统的工作能力对于编写良好的工作代码是必要的。

在本教程中，我们将构建一个目录和一个子目录，向文件写入一些数据，并尝试创建`symlink`。如果符号链接的创建失败，则擦除已创建的实体。我们还应该避免使用异常作为错误报告的机制，而更倾向于某种返回代码。

让我们看看如何使用 Boost 以优雅的方式完成这个任务。

# 准备工作

本教程需要对 C++和`std::ofstream`类有基本了解。

`Boost.Filesystem`不是一个仅头文件的库，因此本教程中的代码需要链接到`boost_system`和`boost_filesystem`库。

# 如何做...

我们继续处理文件系统的可移植包装器，在本教程中，我们将看到如何修改目录内容：

1.  与其他 Boost 库一样，我们需要包含一些头文件：

```cpp
#include <boost/filesystem/operations.hpp> 
#include <cassert> 
#include <fstream> 
```

1.  现在，我们需要一个变量来存储错误（如果有的话）：

```cpp
int main() { 
    boost::system::error_code error; 
```

1.  如果需要，我们还将创建目录，如下所示：

```cpp
    boost::filesystem::create_directories("dir/subdir", error); 
    assert(!error); 
```

1.  然后，我们将数据写入文件：

```cpp
    std::ofstream ofs("dir/subdir/file.txt");
    ofs << "Boost.Filesystem is fun!";
    assert(ofs);
    ofs.close();
```

1.  我们需要尝试创建`symlink`：

```cpp
    boost::filesystem::create_symlink(
        "dir/subdir/file.txt", "symlink", error);
```

1.  然后，我们需要检查通过`symlink`是否可以访问文件：

```cpp
    if (!error) {
        std::cerr << "Symlink created\n";
        assert(boost::filesystem::exists("symlink"));
```

1.  如果`symlink`创建失败，我们将删除创建的文件：

```cpp
    } else {
        std::cerr << "Failed to create a symlink\n";

        boost::filesystem::remove_all("dir", error);
        assert(!error);

        boost::filesystem::remove("symlink", error);
        assert(!error);
    } /*if (!error)*/
} /*main*/
```

# 它是如何工作的...

我们在第六章的几乎所有教程中都看到了`boost::system::error_code`的实际应用，*操作任务*。它可以存储有关错误的信息，并且在整个 Boost 库中广泛使用。

如果您没有为`Boost.Filesystem`函数提供`boost::system::error_code`的实例，代码将编译成功。在这种情况下，当发生错误时，会抛出`boost::filesystem::filesystem_error`异常。

仔细看看*步骤 3*。我们使用了`boost::filesystem::create_directories`函数，而不是`boost::filesystem::create_directory`，因为后者无法创建子目录。`boost::filesystem::remove_all`和`boost::filesystem::remove`也是同样的情况。前者可以删除包含文件和子目录的非空目录。后者删除单个文件。

其余步骤很容易理解，不应该引起任何麻烦。

# 还有更多...

`boost::system::error_code`类是 C++11 的一部分，可以在`std::`命名空间的`<system_error>`头文件中找到。`Boost.Filesystem`的类是 C++17 的一部分。

最后，这里是一个对于那些打算使用`Boost.Filesystem`的小建议。当文件系统操作中发生错误时，如果是例行操作或应用程序需要高度的责任/性能，使用`boost::system::error_codes`。否则，捕获异常更可取且更可靠。

# 另请参阅

*在目录中列出文件*的配方还包含有关`Boost.Filesystem`的信息。阅读 Boost 的官方文档[`boost.org/libs/filesystem`](http://boost.org/libs/filesystem)以获取更多信息和示例。

# 编写和使用插件

这里有一个棘手的问题：我们希望允许用户编写扩展我们程序功能的功能，但我们不想给他们源代码。换句话说，我们想说，“*编写一个函数 X 并将其打包到共享库中。我们可以使用您的函数以及其他一些用户的函数！*”

您在日常生活中会遇到这种技术：您的浏览器使用它来允许第三方插件，您的文本编辑器可能使用它进行语法高亮显示，游戏使用**动态库加载**进行**可下载内容**（**DLC**）和添加游戏玩家内容，服务器返回的网页使用模块/插件进行加密/身份验证等。

用户功能的要求是什么，我们如何在某个时刻使用该功能，而不将其链接到共享库？

# 准备就绪

这个配方需要基本的 C++知识。阅读第十章中的*导出和导入函数和类的便携式方法*是必需的。

# 如何做...

首先，您必须与用户达成协议：

1.  记录插件接口的要求。例如，您可以说所有插件必须导出一个名为`greet`的函数，并且该函数必须接受`const std::string&`并返回`std::string`。

1.  之后，用户可以按以下方式编写插件/共享库：

```cpp
#include <string>
#include <boost/config.hpp>

#define API extern "C" BOOST_SYMBOL_EXPORT

API std::string greeter(const std::string& name) {
    return "Good to meet you, " + name + ".";
}
```

1.  加载共享库的程序代码必须包括来自`Boost.DLL`的头文件：

```cpp
#include <boost/dll/shared_library.hpp>
```

1.  加载库的代码必须如下所示：

```cpp
int main() {
    boost::filesystem::path plugin_path = /* path-to-pligin */;

    boost::dll::shared_library plugin(
        plugin_path,
        boost::dll::load_mode::append_decorations
    );
```

1.  获取用户功能必须如下所示：

```cpp
    auto greeter = plugin.get<std::string(const std::string&)>("greeter");
```

1.  完成。现在，您可以使用该功能：

```cpp
    std::cout << greeter("Sally Sparrow");
}
```

根据加载的插件，您将获得不同的结果：

`plugin_hello`:

```cpp
Good to meet you, Sally Sparrow.
```

`plugin_do_not`:

```cpp
They are fast. Faster than you can believe. Don't turn 

your back, don't look away, and don't blink. Good luck, Sally Sparrow.
```

# 它是如何工作的...

*步骤 2*中有一个小技巧。当您将函数声明为`extern "C"`时，这意味着编译器不得**操纵**（更改）函数名称。换句话说，在*步骤 2*中，我们只是创建一个名为`greet`的函数，并且以该确切名称从共享库中导出。

在*步骤 4*中，我们创建一个名为`plugin`的`boost::dll::shared_library`变量。该变量的构造函数将共享库加载到当前可执行文件的地址空间中。在*步骤 5*中，我们在`plugin`中搜索名为`greet`的函数。我们还指定该函数具有`std::string(const std::string&)`的签名，并将该函数的指针存储在变量`greet`中。

就是这样！从现在开始，我们可以将`greet`变量用作函数，只要`plugin`变量及其所有副本未被销毁。

您可以从共享库中导出多个函数；甚至可以导出变量。

小心！始终将 C 和 C++库动态链接到插件和主可执行文件中，否则您的应用程序将崩溃。始终在插件和应用程序中使用相同或 ABI 兼容的 C 和 C++库版本。否则您的应用程序将崩溃。阅读典型误用的文档！

# 还有更多...

`Boost.DLL`是一个新库；它出现在 Boost 1.61 中。我最喜欢的部分是该库具有向共享库名称添加特定于平台的装饰的能力。例如，根据平台，以下代码将尝试加载`"./some/path/libplugin_name.so"`、`"./some/path/plugin_name.dll"`或`"./some/path/libplugin_name.dll"`：

```cpp
boost::dll::shared_library lib(
    "./some/path/plugin_name",
    boost::dll::load_mode::append_decorations
);
```

C++17 没有类似`boost::dll::shared_library`的类。但是，工作正在进行中，总有一天我们可能会在 C++标准中看到它。

# 另请参阅

官方文档包含多个示例，更重要的是，库的典型问题/误用[`boost.org/libs/dll`](http://boost.org/libs/dll)网站。

# 获取回溯 - 当前调用序列

在报告错误或失败时，更重要的是报告导致错误的步骤，而不是错误本身。考虑一个简单的交易模拟器：

```cpp
int main() {
    int money = 1000;
    start_trading(money);
}
```

它只报告一行：

```cpp
Sorry, you're bankrupt!
```

这是行不通的。我们想知道是怎么发生的，导致破产的步骤是什么！

好的。让我们修复以下函数，并让它报告导致破产的步骤：

```cpp
void report_bankruptcy() {
    std::cout << "Sorry, you're bankrupt!\n";

    std::exit(0);
}
```

# 入门

您需要 Boost 1.65 或更新版本。还需要基本的 C++知识。

# 如何做到...

对于这个示例，我们只需要构造一个单独的类并输出它：

```cpp
#include <iostream>
#include <boost/stacktrace.hpp>

void report_bankruptcy() {
    std::cout << "Sorry, you're bankrupt!\n";
    std::cout << "Here's how it happened:\n" 
        << boost::stacktrace::stacktrace();

    std::exit(0);
}
```

完成。现在`report_bankruptcy()`输出的内容与以下内容接近（从下往上读）：

```cpp
Sorry, you're bankrupt!
Here's how it happened:
 0# report_bankruptcy()
 1# loose(int)
 2# go_to_casino(int)
 3# go_to_bar(int)
 4# win(int)
 5# go_to_casino(int)
 6# go_to_bar(int)
 7# win(int)
 8# make_a_bet(int)
 9# loose(int)
10# make_a_bet(int)
11# loose(int)
12# make_a_bet(int)
13# start_trading(int)
14# main
15# 0x00007F79D4C48F45 in /lib/x86_64-linux-

gnu/libc.so.6
16# 0x0000000000401F39 in ./04_stacktrace
```

# 它是如何工作的...

所有的魔法都在`boost::stacktrace::stacktrace`类中。在构造时，它会快速将当前调用堆栈存储在自身中。`boost::stacktrace::stacktrace`是可复制和可移动的，因此存储的调用序列可以传递给其他函数，复制到异常类中，甚至存储在某个文件中。随心所欲地使用它吧！

在输出的`boost::stacktrace::stacktrace`实例上，解码存储的调用序列并尝试获取人类可读的函数名称。这就是您在之前的示例中看到的：导致`report_bankruptcy()`函数调用的调用序列。

`boost::stacktrace::stacktrace`允许您迭代存储的地址，将单个地址解码为人类可读的名称。如果您不喜欢跟踪的默认输出格式，可以编写自己喜欢的输出方式的函数。

请注意，回溯的有用性取决于多个因素。程序的发布版本可能包含内联函数，导致跟踪不太可读：

```cpp
 0# report_bankruptcy()
 1# go_to_casino(int)
 2# win(int)
 3# make_a_bet(int)
 4# make_a_bet(int)
 5# make_a_bet(int)
 6# main
```

在没有调试符号的情况下构建可执行文件可能会产生没有许多函数名称的跟踪。

阅读官方文档的*配置和构建*部分，了解有关可能影响跟踪可读性的不同编译标志和宏的更多信息。

# 还有更多...

`Boost.Stacktrace`库对于大型项目有一个非常好的功能。您可以在链接程序时禁用所有跟踪。这意味着您不需要重新构建所有源文件。只需为整个项目定义`BOOST_STACKTRACE_LINK`宏。现在，如果您链接`boost_stacktrace_noop`库，将收集空跟踪。链接`boost_stacktrace_windbg`/`boost_stacktrace_windbg_cached`/`boost_stacktrace_backtrace`/`...库`以获得不同可读性的跟踪。

`Boost.Stacktrace`是一个新库；它出现在 Boost 1.65 中。

`boost::stacktrace::stacktrace`相当快地收集当前的调用序列；它只是动态分配一块内存并将一堆地址复制到其中。解码地址要慢得多；它使用多个特定于平台的调用，可能会分叉进程，并且可能会初始化和使用**COM**。

C++17 没有`Boost.Stacktrace`功能。正在进行工作，将其添加到下一个 C++标准中。

# 另请参阅

官方文档[`boost.org/libs/stacktrace/`](http://boost.org/libs/stacktrace)中有一些关于异步信号安全的堆栈跟踪的示例，以及有关所有`Boost.Stacktrace`功能的详细描述。

# 快速将数据从一个进程传递到另一个进程

有时，我们编写大量相互通信的程序。当程序在不同的机器上运行时，使用套接字是最常见的通信技术。但是，如果多个进程在单台机器上运行，我们可以做得更好！

让我们看看如何使用`Boost.Interprocess`库使单个内存片段可在不同进程中使用。

# 准备就绪

这个配方需要对 C++有基本的了解。还需要了解原子变量（查看*另请参阅*部分，了解有关原子的更多信息）。一些平台需要链接到运行时库`rt`。

# 如何做...

在这个例子中，我们将在进程之间共享一个原子变量，使其在新进程启动时递增，在进程终止时递减：

1.  我们需要包含以下头文件进行跨进程通信：

```cpp
#include <boost/interprocess/managed_shared_memory.hpp> 
```

1.  在头文件、`typedef`和检查之后，将帮助我们确保原子对于这个例子是可用的：

```cpp
#include <boost/atomic.hpp> 

typedef boost::atomic<int> atomic_t; 
#if (BOOST_ATOMIC_INT_LOCK_FREE != 2) 
#error "This code requires lock-free boost::atomic<int>" 
#endif 
```

1.  创建或获取共享内存段：

```cpp
int main() {
    boost::interprocess::managed_shared_memory 
        segment(boost::interprocess::open_or_create, "shm1-cache", 1024);
```

1.  获取或构造`atomic`变量：

```cpp
    atomic_t& atomic 
        = *segment.find_or_construct<atomic_t> // 1
            ("shm1-counter")                   // 2
            (0)                                // 3
    ;
```

1.  以通常的方式处理`atomic`变量：

```cpp
    std::cout << "I have index " << ++ atomic 
        << ". Press any key...\n";
    std::cin.get();
```

1.  销毁`atomic`变量：

```cpp
    const int snapshot = --atomic;
    if (!snapshot) {
        segment.destroy<atomic_t>("shm1-counter");
        boost::interprocess::shared_memory_object
                ::remove("shm1-cache");
    }
} /*main*/ 
```

就是这样！现在，如果我们同时运行这个程序的多个实例，我们会看到每个新实例都会递增其索引值：

```cpp
I have index 1\. Press any key...
I have index 2\. 

Press any key...
I have index 3\. Press any key...
I have index 4\. Press any key...
I have index 5\. 

Press any key...
```

# 它是如何工作的...

这个配方的主要思想是获得一个对所有进程可见的内存段，并在其中放置一些数据。让我们看看*步骤 3*，在那里我们检索这样一个内存段。在这里，`shm1-cache`是段的名称（不同的段有不同的名称）。您可以为段指定任何名称。第一个参数是`boost::interprocess::open_or_create`，它告诉`boost::interprocess::managed_shared_memory`必须打开一个具有名称`shm1-cache`的现有段或构造它。最后一个参数是段的大小。

段的大小必顺应足够大，以适应`Boost.Interprocess`库特定的数据。这就是为什么我们使用`1024`而不是`sizeof(atomic_t)`。但实际上，操作系统会将这个值舍入到最接近的更大的支持值，通常等于或大于 4 千字节。

*步骤 4*是一个棘手的步骤，因为我们在这里同时执行多个任务。在这一步的第 2 部分，我们在段中找到或构造一个名为`shm1-counter`的变量。在*步骤 4*的第 3 部分，我们提供一个参数，用于初始化变量，如果在*步骤 2*中没有找到。只有在找不到变量并且必须构造变量时，才会使用此参数，否则将被忽略。仔细看第二行（第 1 部分）。看到解引用运算符`*`的调用。我们这样做是因为`segment.find_or_construct<atomic_t>`返回一个指向`atomic_t`的指针，在 C++中使用裸指针是一种不好的风格。

我们在共享内存中使用原子变量！这是必需的，因为两个或更多进程可能同时使用相同的`shm1-counter`原子变量。

在处理共享内存中的对象时，您必须非常小心；不要忘记销毁它们！在*步骤 6*中，我们使用它们的名称销毁对象和段。

# 还有更多...

仔细看看*步骤 2*，我们在那里检查`BOOST_ATOMIC_INT_LOCK_FREE != 2`。我们正在检查`atomic_t`是否不使用互斥锁。这非常重要，因为通常的互斥锁在共享内存中不起作用。因此，如果`BOOST_ATOMIC_INT_LOCK_FREE`不等于`2`，我们会得到未定义的行为。

不幸的是，C++11 没有跨进程类，据我所知，`Boost.Interprocess`也没有被提议纳入 C++20。

一旦创建了托管段，它就不能自动增加大小！确保您创建的段足够大以满足您的需求，或者查看*另请参阅*部分，了解有关增加托管段的信息。

共享内存是进程进行通信的最快方式，但适用于可能共享内存的进程。这通常意味着进程必须在同一主机上运行，或者在**对称多处理**（**SMP**）集群上运行。

# 另请参阅

+   *同步跨进程通信*配方将告诉您更多关于共享内存、跨进程通信和同步访问共享内存资源的信息。

+   有关原子操作的更多信息，请参阅*使用原子快速访问共享资源*示例

+   Boost 的官方文档`Boost.Interprocess`也可能会有所帮助；可以在[`boost.org/libs/interprocess`](http://boost.org/libs/interprocess)找到。

+   如何增加托管段的方法在[`boost.org/libs/interprocess`](http://boost.org/libs/interprocess)的*增长托管段*中有描述

# 同步进程间通信

在上一个示例中，我们看到了如何创建共享内存以及如何在其中放置一些对象。现在，是时候做一些有用的事情了。让我们从第五章的*多线程*中的*制作工作队列*示例中获取一个例子，并使其适用于多个进程。在这个示例结束时，我们将得到一个可以存储不同任务并在进程之间传递它们的类。

# 准备工作

这个示例使用了前一个示例中的技术。你还需要阅读第五章的*多线程*中的*制作工作队列*示例，并理解它的主要思想。该示例需要在某些平台上链接运行时库`rt`。

# 如何做...

认为将独立的子进程代替线程使程序更可靠，因为子进程的终止不会终止主进程。我们不会在这里对这个假设进行争论，只是看看如何实现进程之间的数据共享。

1.  这个示例需要很多头文件：

```cpp
#include <boost/interprocess/managed_shared_memory.hpp> 
#include <boost/interprocess/containers/deque.hpp> 
#include <boost/interprocess/allocators/allocator.hpp> 
#include <boost/interprocess/sync/interprocess_mutex.hpp> 
#include <boost/interprocess/sync/interprocess_condition.hpp> 
#include <boost/interprocess/sync/scoped_lock.hpp> 

#include <boost/optional.hpp> 
```

1.  现在，我们需要定义我们的结构`task_structure`，它将用于存储任务：

```cpp
struct task_structure { 
    // ... 
}; 
```

1.  让我们开始编写`work_queue`类：

```cpp
class work_queue { 
public: 
    typedef boost::interprocess::managed_shared_memory  
            managed_shared_memory_t; 

    typedef task_structure task_type; 
    typedef boost::interprocess::allocator< 
        task_type,  
        boost::interprocess::managed_shared_memory::segment_manager 
    > allocator_t; 
```

1.  将`work_queue`的成员写成以下形式：

```cpp
private: 
    managed_shared_memory_t segment_; 
    const allocator_t       allocator_; 

    typedef boost::interprocess::deque<task_type, allocator_t> deque_t; 
    deque_t&        tasks_; 

    typedef boost::interprocess::interprocess_mutex mutex_t; 
    mutex_t&        mutex_; 

    typedef boost::interprocess::interprocess_condition condition_t; 
    condition_t&    cond_; 

    typedef boost::interprocess::scoped_lock<mutex_t> scoped_lock_t;
```

1.  成员的初始化必须如下所示：

```cpp
public: 
    explicit work_queue()
        : segment_(
              boost::interprocess::open_or_create,
              "work-queue",
              1024 * 1024 * 32
        )
        , allocator_(segment_.get_segment_manager())
        , tasks_(
            *segment_.find_or_construct<deque_t>
              ("work-queue:deque")(allocator_)
        )
        , mutex_(
            *segment_.find_or_construct<mutex_t>
              ("work-queue:mutex")()
        )
        , cond_(
            *segment_.find_or_construct<condition_t>
              ("work-queue:condition")()
        )
    {}
```

1.  我们需要对`work_queue`的成员函数进行一些微小的更改，比如使用`scoped_lock_t`，而不是原始的 unique locks：

```cpp
    boost::optional<task_type> try_pop_task() { 
        boost::optional<task_type> ret; 
        scoped_lock_t lock(mutex_); 
        if (!tasks_.empty()) { 
            ret = tasks_.front(); 
            tasks_.pop_front(); 
        } 
        return ret; 
    }
```

1.  不要忘记清理资源：

```cpp
    void cleanup() {
        segment_.destroy<condition_t>("work-queue:condition");
        segment_.destroy<mutex_t>("work-queue:mutex");
        segment_.destroy<deque_t>("work-queue:deque");

        boost::interprocess::shared_memory_object
            ::remove("work-queue");
    }
```

# 工作原理...

在这个示例中，我们几乎做了和第五章的*多线程*中的*制作工作队列* *类*示例中完全相同的事情，但我们是在共享内存中分配数据。

在存储具有指针或引用作为成员字段的共享内存对象时需要额外小心。我们将在下一个示例中看到如何处理指针。

看一下*步骤 2*。我们没有使用`boost::function`作为任务类型，因为它里面有指针，所以它在共享内存中无法工作。

*步骤 3*很有趣，因为涉及`allocator_t`。如果内存不是从共享内存段分配的，它就可以被其他进程使用；这就是为什么需要为容器使用特定的分配器。`allocator_t`是一个有状态的分配器，这意味着它会随着容器一起被复制。此外，它不能被默认构造。

*步骤 4*非常简单，只是`tasks_`、`mutex_`和`cond_`只有引用。这是因为对象本身是在共享内存中构造的。所以，`work_queue`只能在其中存储引用。

在*步骤 5*中，我们正在初始化成员。这段代码对你来说一定很熟悉。在上一个示例中，我们做了完全相同的事情。

在构造`tasks_`时，我们提供了一个分配器的实例。这是因为`allocator_t`不能由容器本身构造。共享内存在进程退出事件时不会被销毁，所以我们可以运行程序一次，将任务发布到工作队列，停止程序，启动其他程序，并获取由第一个程序实例存储的任务。共享内存只有在重新启动时才会被销毁，或者如果你显式调用`segment.deallocate("work-queue");`。

# 还有更多...

正如前面的内容中已经提到的，C++17 没有 `Boost.Interprocess` 中的类。此外，不得在共享内存段中使用 C++17 或 C++03 容器。其中一些容器可能有效，但这种行为不具有可移植性。

如果你查看一些 `<boost/interprocess/containers/*.hpp>` 头文件，你会发现它们只是使用了 `Boost.Containers` 库中的容器：

```cpp
namespace boost { namespace interprocess { 
    using boost::container::vector; 
}} 
```

`Boost.Interprocess` 的容器具有 `Boost.Containers` 库的所有优点，包括右值引用及其在旧编译器上的模拟。

`Boost.Interprocess` 是在同一台机器上运行的进程之间进行通信的最快解决方案。

# 另请参阅

+   *在共享内存中使用指针* 的方法

+   阅读 第五章*,* *多线程*，了解更多关于同步原语和多线程的信息

+   有关 `Boost.Interprocess` 库的更多示例和信息，请参考 Boost 官方文档；可在以下链接找到：[`boost.org/libs/interprocess`](http://boost.org/libs/interprocess)

# 在共享内存中使用指针

很难想象在没有指针的情况下编写一些低级别的 C++ 核心类。指针和引用在 C++ 中随处可见，但它们在共享内存中无法使用！因此，如果我们在共享内存中有这样的结构，并将共享内存中某个整数变量的地址分配给 `pointer_`，那么 `pointer_` 在其他进程中将无效：

```cpp
struct with_pointer { 
    int* pointer_; 
    // ... 
    int value_holder_; 
}; 
```

我们如何修复这个问题？

# 准备工作

理解前面的内容是理解这个的前提。在某些平台上，示例需要链接运行时系统库 `rt`。

# 如何做...

修复很简单；我们只需要用 `offset_ptr<>` 替换指针：

```cpp
#include <boost/interprocess/offset_ptr.hpp> 

struct correct_struct { 
    boost::interprocess::offset_ptr<int> pointer_; 
    // ... 
    int value_holder_; 
}; 
```

现在，我们可以像使用普通指针一样自由使用它：

```cpp
int main() {
    boost::interprocess::managed_shared_memory 
        segment(boost::interprocess::open_or_create, "segment", 4096);

    correct_struct* ptr =
        segment.find<correct_struct>("structure").first;

    if (ptr) {
        std::cout << "Structure found\n";
        assert(*ptr->pointer_ == ethalon_value);
        segment.destroy<correct_struct>("structure");
    }
}
```

# 工作原理...

我们无法在共享内存中使用指针，因为当共享内存的一部分映射到进程的地址空间时，其地址仅对该进程有效。当我们获取变量的地址时，它只是该进程的本地地址。其他进程将共享内存映射到不同的基地址，因此变量地址会有所不同。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/boost-cpp-appdev-cb-2e/img/00019.jpeg)

那么，我们如何处理始终在变化的地址？有一个技巧！由于指针和结构位于同一共享内存段中，它们之间的距离不会改变。`boost::interprocess::offset_ptr` 的想法是记住 `offset_ptr` 和指向值之间的距离。在解引用时，`offset_ptr` 将距离值添加到 `offset_ptr` 变量的进程相关地址上。

偏移指针模拟了指针的行为，因此可以快速应用替换。

不要将可能包含指针或引用的类放入共享内存中！

# 还有更多...

偏移指针的工作速度略慢于通常的指针，因为每次解引用都需要计算地址。但是，这种差异通常不应该让你担心。

C++17 没有偏移指针。

# 另请参阅

+   Boost 官方文档包含许多示例和更高级的 `Boost.Interprocess` 功能；可在 [`boost.org/libs/interprocess`](http://boost.org/libs/interprocess) 找到

+   *最快的文件读取方法* 的方法包含了 `Boost.Interprocess` 库的一些非传统用法的信息

# 读取文件的最快方法

在互联网上，人们一直在问“读取文件的最快方法是什么？”让我们让这个问题更加困难：读取二进制文件的最快和可移植的方法是什么？

# 准备工作

这个方法需要基本的 C++ 知识和 `std::fstream`。

# 如何做...

这个方法广泛用于对输入和输出性能要求严格的应用程序。这是读取文件的最快方法：

1.  我们需要包括 `Boost.Interprocess` 库中的两个头文件：

```cpp
#include <boost/interprocess/file_mapping.hpp> 
#include <boost/interprocess/mapped_region.hpp> 
```

1.  现在，我们需要打开一个文件：

```cpp
const boost::interprocess::mode_t mode = boost::interprocess::read_only; 
boost::interprocess::file_mapping fm(filename, mode); 
```

1.  这个食谱的主要部分是将所有文件映射到内存中：

```cpp
boost::interprocess::mapped_region region(fm, mode, 0, 0);
```

1.  获取文件中数据的指针：

```cpp
const char* begin = static_cast<const char*>(
    region.get_address()
);
```

就是这样！现在，我们可以像处理常规内存一样处理文件：

```cpp
const char* pos = std::find(
    begin, begin + region.get_size(), '\1'
);
```

# 它是如何工作的...

所有流行的操作系统都具有将文件映射到进程地址空间的能力。在这样的映射完成后，进程可以像处理常规内存一样处理这些地址。操作系统会处理所有文件操作，如缓存和预读。

为什么它比传统的读/写更快？这是因为在大多数情况下，读/写是作为内存映射和将数据复制到用户指定的缓冲区来实现的。因此，读取通常比内存映射多做一点。

就像标准库的`std::fstream`一样，在打开文件时必须提供打开模式。请参阅*步骤 2*，我们在那里提供了`boost::interprocess::read_only`模式。

请参阅*步骤 3*，我们在那里一次映射了整个文件。这个操作实际上非常快，因为操作系统不会从磁盘读取数据，而是等待对映射区域的请求。在请求了映射区域的一部分后，操作系统将该文件的那部分加载到内存中。正如我们所看到的，内存映射操作是懒惰的，并且映射区域的大小不会影响性能。

但是，32 位操作系统无法内存映射大文件，因此您必须按部就班地映射它们。POSIX（Linux）操作系统要求在 32 位平台上处理大文件时定义`_FILE_OFFSET_BITS=64`宏。否则，操作系统将无法映射超过 4GB 的文件部分。

现在，是时候测量性能了：

```cpp
    $ TIME="%E" time ./reading_files m
    mapped_region: 0:00.08

    $ TIME="%E" time ./reading_files r
    ifstream: 0:00.09

    $ TIME="%E" time ./reading_files a
    C: 0:00.09
```

正如预期的那样，内存映射文件比传统读取稍快。我们还可以看到纯 C 方法与 C++的`std::ifstream`类具有相同的性能，因此不要在 C++中使用与`FILE*`相关的函数。它们只适用于 C，而不适用于 C++！

为了获得`std::ifstream`的最佳性能，请不要忘记以二进制模式打开文件并按块读取数据：

```cpp
std::ifstream f(filename, std::ifstream::binary); 
// ... 
char c[kilobyte]; 
f.read(c, kilobyte); 
```

# 还有更多...

不幸的是，用于内存映射文件的类不是 C++17 的一部分，看起来它们在 C++20 中也不会是。

写入内存映射区域也是一个非常快的操作。操作系统会缓存写入操作，并不会立即将修改刷新到磁盘。操作系统和`std::ofstream`数据缓存之间存在差异。如果`std::ofstream`数据由应用程序缓存，并且应用程序终止，则缓存的数据可能会丢失。当数据由操作系统缓存时，应用程序的终止不会导致数据丢失。断电和操作系统崩溃都会导致数据丢失。

如果多个进程映射单个文件，并且其中一个进程修改了映射区域，则其他进程立即看到更改（甚至无需实际将数据写入磁盘！现代操作系统非常聪明！）。

# 另请参阅

`Boost.Interprocess`库包含许多有用的功能，用于与系统一起工作；并非所有功能都在本书中涵盖。您可以在官方网站上阅读有关这个伟大库的更多信息：[`boost.org/libs/interprocess`](http://boost.org/libs/interprocess)。

# 协程-保存状态和推迟执行

如今，许多嵌入式设备仍然只有一个核心。开发人员为这些设备编写代码，试图从中挤取最大的性能。

对于这些设备使用`Boost.Threads`或其他线程库并不有效。操作系统将被迫调度线程进行执行，管理资源等，因为硬件无法并行运行它们。

那么，我们如何强制程序在等待主程序的某些资源时切换到子程序的执行？此外，我们如何控制子程序的执行时间？

# 准备工作

这个食谱需要基本的 C++和模板知识。阅读一些关于`Boost.Function`的食谱也可能有所帮助。

# 如何做到...

这个教程是关于**协程**或**子程序**，允许多个入口点。多个入口点使我们能够在特定位置暂停和恢复程序的执行，切换到/从其他子程序。

1.  `Boost.Coroutine2`库几乎负责一切。我们只需要包含它的头文件：

```cpp
#include <boost/coroutine2/coroutine.hpp> 
```

1.  创建具有所需输入参数类型的协程类型：

```cpp
typedef boost::coroutines2::asymmetric_coroutine<std::size_t> corout_t;
```

1.  创建一个表示子程序的类：

```cpp
struct coroutine_task {
    std::string& result;

    coroutine_task(std::string& r)
        : result(r)
    {}

    void operator()(corout_t::pull_type& yield);

private:
    std::size_t ticks_to_work;
    void tick(corout_t::pull_type& yield);
};
```

1.  让我们创建协程本身：

```cpp
int main() {
    std::string result;
    coroutine_task task(result);
    corout_t::push_type coroutine(task);
```

1.  现在，我们可以在主程序中等待某个事件的同时执行子程序：

```cpp
    // Somewhere in main():

    while (!spinlock.try_lock()) {
        // We may do some useful work, before
        // attempting to lock a spinlock once more.
        coroutine(10); // 10 is the ticks count to run.
    }
    // Spinlock is locked.
    // ...

    while (!port.block_ready()) {
        // We may do some useful work, before
        // attempting to get block of data once more.
        coroutine(300); // 300 is the ticks count to run.

        // Do something with `result` variable.
    }
```

1.  协程方法可能如下所示：

```cpp
void coroutine_task::operator()(corout_t::pull_type& yield) {
    ticks_to_work = yield.get();

    // Prepare buffers.
    std::string buffer0;

    while (1) {
        const bool requiers_1_more_copy = copy_to_buffer(buffer0);
        tick(yield);

        if (requiers_1_more_copy) {
            std::string buffer1;
            copy_to_buffer(buffer1);
            tick(yield);

            process(buffer1);
            tick(yield);
        }

        process(buffer0);
        tick(yield);
    }
}
```

1.  `tick()`函数可以这样实现：

```cpp
void coroutine_task::tick(corout_t::pull_type& yield) {
    if (ticks_to_work != 0) {
        --ticks_to_work;
    }

    if (ticks_to_work == 0) {
        // Switching back to main.
        yield();

        ticks_to_work = yield.get();
    }
}
```

# 它是如何工作的...

在*步骤 2*中，我们使用`std::size_t`作为模板参数描述了子程序的输入参数。

*步骤 3*相当简单，除了`corout_t::pull_type& yield`参数。我们马上就会看到它的作用。

当我们在*步骤 5*中调用`coroutine(10)`时，我们正在执行一个协程程序。执行跳转到`coroutine_task::operator()`，在那里调用`yield.get()`返回输入参数`10`。执行继续进行，`coroutine_task::tick`函数测量经过的滴答声。

最有趣的部分来了！

在*步骤 7*中，如果在函数`coroutine_task::tick`中`ticks_to_work`变量变为`0`，协程的执行将在`yield()`处暂停，而`main()`继续执行。在下一次调用`coroutine(some_value)`时，协程的执行将从`tick`函数的中间位置继续，就在`yield()`旁边的行。在那一行，`ticks_to_work = yield.get();`被执行，`ticks_to_work`变量开始保存一个新的输入值`some_value`。

这意味着我们可以在函数的多个位置暂停/继续协程。所有函数状态和变量都会被恢复：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/boost-cpp-appdev-cb-2e/img/00020.jpeg)

让我描述一下协程和线程之间的主要区别。当执行协程时，主任务什么也不做。当执行主任务时，协程任务什么也不做。使用线程时，您没有这样的保证。使用协程，您明确指定何时启动子任务以及何时暂停它。在单核环境中，线程可能随时切换；您无法控制这种行为。

# 还有更多...

在切换线程时，操作系统会做很多工作，因此这不是一个非常快的操作。然而，使用协程，您可以完全控制切换任务；此外，您不需要执行一些特定于操作系统的内部内核工作。切换协程比切换线程快得多，尽管不像调用`boost::function`那样快。

`Boost.Coroutine2`库负责调用协程任务中变量的析构函数，因此无需担心泄漏。

协程使用`boost::coroutines2::detail::forced_unwind`异常来释放不是从`std::exception`派生的资源。您必须小心不要在协程任务中捕获该异常。

您不能复制`Boost.Coroutine2`协程，但可以`std::move`它们。

有一个`Boost.Coroutine`库（末尾没有`2`！），它不需要 C++11 兼容的编译器。但是该库已经被弃用，并且有一些区别（例如它不会从协程中传播异常）。注意区别！`Boost.Coroutine`在 Boost 1.56 中也显著改变了其接口。

C++17 没有协程。但**协程 TS**几乎准备就绪，所以很有可能下一个 C++标准将直接包含它们。

协程 TS 与 `Boost.Coroutine2` 不同！Boost 提供了 **有栈** 协程，这意味着您不需要特别使用宏/关键字来使用它们。但这也意味着 Boost 协程更难被编译器优化，并且可能分配更多内存。协程 TS 提供了 **无栈** 协程，这意味着编译器可以精确计算协程所需的内存，甚至可以优化整个协程。然而，这种方法需要代码更改，可能稍微难以采用。

# 另请参阅

+   Boost 的官方文档包含了更多关于 `Boost.Coroutines2` 库的示例、性能说明、限制和用例；请访问以下链接 [`boost.org/libs/coroutine2`](http://boost.org/libs/coroutine2)

+   查看第二章的示例，*资源管理*，以及第五章，*多线程*，了解 `Boost.Coroutine`、`Boost.Thread` 和 `Boost.Function` 库之间的区别

+   对 Coroutines TS 感兴趣吗？这里有一场有趣的关于作者 Gor Nishanov 的实现讨论 *CppCon 2016: Gor Nishanov. C++ Coroutines: Under the covers*，链接在 [`www.youtube.com/watch?v=8C8NnE1Dg4A`](https://www.youtube.com/watch?v=8C8NnE1Dg4A)


# 第十二章：只是冰山一角

在本章中，我们将涵盖：

+   处理图

+   可视化图

+   使用真随机数生成器

+   使用可移植数学函数

+   编写测试用例

+   将多个测试用例组合在一个测试模块中

+   操作图像

# 介绍

Boost 是一个庞大的库集合。其中一些库很小，适用于日常使用，而其他一些则需要单独的书来描述它们的所有特性。本章专门介绍了其中一些大型库，并提供了对它的基本理解。

前两篇食谱将解释`Boost.Graph`的用法。这是一个拥有大量算法的大型库。我们将看到一些基础知识，也可能是开发中最重要的部分--图的可视化。

我们还将看到一个非常有用的食谱，用于生成真随机数。这对于编写安全的加密系统非常重要。

一些 C++标准库缺乏数学函数。我们将看到如何使用 Boost 来解决这个问题。但是，本书的格式没有空间来描述所有的函数。

编写测试用例在*编写测试用例*和*将多个测试用例组合在一个测试模块中*的食谱中有所描述。这对于任何生产质量的系统都很重要。

最后一篇食谱是关于一个在我大学时代的很多课程作业中帮助过我的库。可以使用它来创建和修改图像。我个人用它来可视化不同的算法，隐藏图像中的数据，签名图像和生成纹理。

不幸的是，即使这一章也不能告诉你关于所有的 Boost 库。也许有一天，我会再写一本书，然后再写几本。

# 处理图

有些任务需要将数据表示为图。`Boost.Graph`是一个旨在提供一种灵活的方式在内存中构建和表示图的库。它还包含了许多处理图的算法，如拓扑排序、广度优先搜索、深度优先搜索和 Dijkstra 最短路径。

好吧，让我们用`Boost.Graph`执行一些基本任务！

# 准备工作

这个食谱只需要基本的 C++和模板知识。

# 如何做...

在这个食谱中，我们将描述一个图类型，创建该类型的图，向图中添加一些顶点和边，并搜索特定的顶点。这应该足以开始使用`Boost.Graph`了。

1.  我们首先描述图的类型：

```cpp
#include <boost/graph/adjacency_list.hpp> 
#include <string> 

typedef std::string vertex_t; 
typedef boost::adjacency_list< 
    boost::vecS 
    , boost::vecS 
    , boost::bidirectionalS 
    , vertex_t 
> graph_type; 
```

1.  现在，我们构建它：

```cpp
int main() {
    graph_type graph; 
```

1.  让我们进行一些未记录的技巧，加快图的构建速度：

```cpp
    static const std::size_t vertex_count = 5; 
    graph.m_vertices.reserve(vertex_count); 
```

1.  现在，我们准备向图中添加顶点：

```cpp
    typedef boost::graph_traits<
        graph_type
    >::vertex_descriptor descriptor_t;

    descriptor_t cpp
        = boost::add_vertex(vertex_t("C++"), graph);
    descriptor_t stl
        = boost::add_vertex(vertex_t("STL"), graph);
    descriptor_t boost
        = boost::add_vertex(vertex_t("Boost"), graph);
    descriptor_t guru
        = boost::add_vertex(vertex_t("C++ guru"), graph);
    descriptor_t ansic
        = boost::add_vertex(vertex_t("C"), graph);
```

1.  是时候用边连接顶点了：

```cpp
    boost::add_edge(cpp, stl, graph); 
    boost::add_edge(stl, boost, graph); 
    boost::add_edge(boost, guru, graph); 
    boost::add_edge(ansic, guru, graph); 
} // end of main()
```

1.  我们可以创建一个搜索某个顶点的函数：

```cpp
inline void find_and_print(
    const graph_type& graph, boost::string_ref name)
{
```

1.  接下来是一个获取所有顶点迭代器的代码：

```cpp
    typedef typename boost::graph_traits<
        graph_type
    >::vertex_iterator vert_it_t;

    vert_it_t it, end;
    boost::tie(it, end) = boost::vertices(graph);
```

1.  是时候运行搜索所需的顶点了：

```cpp
    typedef typename boost::graph_traits<
        graph_type
    >::vertex_descriptor desc_t;

    for (; it != end; ++ it) {
        const desc_t desc = *it;
        const vertex_t& vertex = boost::get(
            boost::vertex_bundle, graph
        )[desc];

        if (vertex == name.data()) {
            break;
        }
    }

    assert(it != end);
    std::cout << name << '\n';
} /* find_and_print */
```

# 它是如何工作的...

在*步骤 1*中，我们描述了我们的图必须是什么样子，以及它必须基于什么类型。`boost::adjacency_list`是一个表示图为二维结构的类，其中第一维包含顶点，第二维包含该顶点的边。`boost::adjacency_list`必须是表示图的默认选择，因为它适用于大多数情况。

第一个模板参数`boost::adjacency_list`描述了用于表示每个顶点的边列表的结构。第二个描述了存储顶点的结构。我们可以使用特定选择器在这些结构中选择不同的标准库容器，如下表所列：

| 选择器 | 标准库容器 |
| --- | --- |
| `boost::vecS` | `std::vector` |
| `boost::listS` | `std::list` |
| `boost::slistS` | `std::slist` |
| `boost::setS` | `std::set` |
| `boost::multisetS` | `std::multiset` |
| `boost::hash_setS` | `std::hash_set` |

第三个模板参数用于创建一个间接的、有向的或双向的图。分别使用`boost::undirectedS`、`boost::directedS`和`boost::bidirectionalS`选择器。

第五个模板参数描述了用作顶点的数据类型。在我们的示例中，我们选择了`std::string`。我们还可以支持边缘的数据类型，并将其作为模板参数提供。

*步骤 2*和*3*很简单，但在*步骤 4*中，您可能会看到一些未记录的加速图表构建的方法。在我们的示例中，我们使用`std::vector`作为存储顶点的容器，因此我们可以强制它为所需数量的顶点保留内存。这会减少插入顶点时的内存分配/释放和复制操作。这一步并不是非常可移植的，可能会在未来的 Boost 版本中出现问题，因为这一步高度依赖于`boost::adjacency_list`的当前实现和所选的用于存储顶点的容器类型。

在*步骤 4*中，我们看到了如何向图表中添加顶点。请注意`boost::graph_traits<graph_type>`的使用。`boost::graph_traits`类用于获取特定于图表类型的类型。我们将在本章后面看到它的用法和一些特定于图表的类型的描述。*步骤 5*显示了连接顶点和边缘所需的内容。

如果我们为边缘提供了一些数据类型，添加边缘将如下所示：`boost::add_edge(ansic, guru, edge_t(initialization_parameters), graph)`

在*步骤 6*中，图表类型是一个`template`参数。这是为了实现更好的代码重用性，并使此函数适用于其他图表类型。

在*步骤 7*中，我们看到了如何遍历图表的所有顶点。顶点迭代器的类型是从`boost::graph_traits`中获得的。函数`boost::tie`是`Boost.Tuple`的一部分，用于从元组中获取值到变量中。因此，调用`boost::tie(it, end) = boost::vertices(g)`将`begin`迭代器放入`it`变量中，将`end`迭代器放入`end`变量中。

您可能会感到惊讶，但解引用顶点迭代器并不会返回顶点数据。相反，它返回顶点描述符`desc`，可以在`boost::get(boost::vertex_bundle, g)[desc]`中使用，以获取顶点数据，就像我们在*步骤 8*中所做的那样。顶点描述符类型在许多`Boost.Graph`函数中使用。我们已经在*步骤 5*中看到了它的用法。

如前所述，`Boost.Graph`库包含许多算法的实现。您可能会发现许多搜索策略的实现，但我们不会在本书中讨论它们。我们将此教程限制在图表库的基础知识上。

# 还有更多...

`Boost.Graph`库不是 C++17 的一部分，也不会成为下一个 C++标准的一部分。当前的实现不支持 C++11 的特性，如右值引用。如果我们使用的顶点很难复制，可以使用以下技巧来提高速度：

```cpp
 vertex_descriptor desc = boost::add_vertex(graph);
 boost::get(boost::vertex_bundle, g_)[desc] = std::move(vertex_data);
```

它避免了在`boost::add_vertex(vertex_data, graph)`内部进行复制构造，并使用默认构造和移动赋值代替。

`Boost.Graph`的效率取决于多个因素，如底层容器类型、图表表示、边缘和顶点数据类型。

# 另请参阅

阅读*可视化图表*的教程可以帮助您轻松处理图表。您还可以考虑阅读其官方文档，链接如下：[`boost.org/libs/graph`](http://boost.org/libs/graph)

# 可视化图表

制作操作图表的程序从来都不容易，因为可视化存在问题。当我们使用标准库容器，如`std::map`和`std::vector`时，我们可以始终打印容器的内容并查看内部情况。但是，当我们使用复杂的图表时，很难以清晰的方式可视化内容；文本表示对人类不友好，因为它通常包含太多的顶点和边缘。

在本教程中，我们将使用**Graphviz**工具来可视化`Boost.Graph`。

# 准备工作

要可视化图形，您将需要一个 Graphviz 可视化工具。还需要了解前面的食谱。

# 如何做...

可视化分为两个阶段。在第一阶段，我们使我们的程序以适合 Graphviz 的文本格式输出图形描述。在第二阶段，我们将第一步的输出导入到可视化工具中。本食谱中编号的步骤都是关于第一阶段的。

1.  让我们按照前面的食谱为`graph_type`编写`std::ostream`运算符：

```cpp
#include <boost/graph/graphviz.hpp>

std::ostream& operator<<(std::ostream& out, const graph_type& g) {
    detail::vertex_writer<graph_type> vw(g);
    boost::write_graphviz(out, g, vw);

    return out;
}
```

1.  在前面的步骤中使用的`detail::vertex_writer`结构必须定义如下：

```cpp
#include <iosfwd>

namespace detail {
    template <class GraphT>
    class vertex_writer {
        const GraphT& g_;

    public:
        explicit vertex_writer(const GraphT& g)
            : g_(g)
        {}

        template <class VertexDescriptorT>
        void operator()(
            std::ostream& out,
            const VertexDescriptorT& d) const
        {
            out << " [label=\""
                << boost::get(boost::vertex_bundle, g_)[d] 
                << "\"]"; 
        }
    }; // vertex_writer
} // namespace detail
```

就是这样。现在，如果我们使用`std::cout << graph;`命令可视化前一个食谱中的图形，输出可以用于使用`dot`命令行实用程序创建图形图片：

```cpp
    $ dot -Tpng -o dot.png

    digraph G {
    0 [label="C++"];
    1 [label="STL"];
    2 [label="Boost"];
    3 [label="C++ guru"];
    4 [label="C"];
    0->1 ;
    1->2 ;
    2->3 ;
    4->3 ;
    }

```

前一个命令的输出如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/boost-cpp-appdev-cb-2e/img/00021.gif)

如果命令行让您害怕，我们还可以使用**Gvedit**或**XDot**程序进行可视化。

# 它是如何工作的...

`Boost.Graph`库包含以 Graphviz（DOT）格式输出图形的函数。如果我们在*步骤 1*中使用两个参数写`boost::write_graphviz(out, g)`，该函数将输出一个以`0`为顶点编号的图形图片。这并不是很有用，因此我们提供了一个手写的`vertex_writer`类的实例，用于输出顶点名称。

正如我们在*步骤 2*中看到的，Graphviz 工具理解 DOT 格式。如果您希望为图形输出更多信息，则可能需要阅读有关 DOT 格式的 Graphviz 文档以获取更多信息。

如果您希望在可视化过程中向边添加一些数据，我们需要在`boost::write_graphviz`的第四个参数中提供边可视化器的实例。

# 还有更多...

C++17 不包含`Boost.Graph`或用于图形可视化的工具。但是您不必担心，因为还有很多其他图形格式和可视化工具，`Boost.Graph`可以与其中许多工作。

# 另请参阅

+   *使用图形*食谱包含有关构建`Boost.Graphs`的信息

+   您可以在[`www.graphviz.org/`](http://www.graphviz.org/)找到有关 DOT 格式和 Graphviz 的大量信息

+   `Boost.Graph`库的官方文档包含多个示例和有用信息，可以在[`boost.org/libs/graph`](http://boost.org/libs/graph)找到

# 使用真正的随机数生成器

我知道许多商业产品使用不正确的方法来获取随机数。一些公司仍然在密码学和银行软件中使用`rand()`，这是令人遗憾的。

让我们看看如何使用`Boost.Random`获取适用于银行软件的完全随机的**均匀分布**。

# 入门

本食谱需要基本的 C++知识。对于不同类型的分布的了解也将有所帮助。本食谱中的代码需要链接到`boost_random`库。

# 如何做...

要创建真正的随机数，我们需要操作系统或处理器的帮助。以下是使用 Boost 的方法：

1.  我们需要包括以下头文件：

```cpp
#include <boost/config.hpp> 
#include <boost/random/random_device.hpp> 
#include <boost/random/uniform_int_distribution.hpp>
```

1.  高级随机位提供程序在不同平台下有不同的名称：

```cpp
int main() {
    static const std::string provider = 
#ifdef BOOST_WINDOWS 
        "Microsoft Strong Cryptographic Provider" 
#else 
        "/dev/urandom" 
#endif 
    ; 
```

1.  现在，我们准备使用`Boost.Random`初始化生成器：

```cpp
    boost::random_device device(provider); 
```

1.  让我们得到一个返回介于`1000`和`65535`之间的均匀分布：

```cpp
    boost::random::uniform_int_distribution<unsigned short> random(1000);
```

就是这样。现在，我们可以使用`random(device)`调用获取真正的随机数。

# 它是如何工作的...

为什么`rand()`函数不适用于银行业？因为它生成伪随机数，这意味着黑客可能会预测下一个生成的数字。这是所有伪随机数算法的问题。有些算法更容易预测，有些更难，但仍然是可能的。

这就是为什么在这个示例中我们使用`boost::random_device`（见*步骤 3*）。该设备收集**熵**--来自操作系统各处的随机事件信息，以产生不可预测的均匀随机位。这些事件的例子包括按键之间的延迟、一些硬件中断之间的延迟以及内部 CPU 的随机位生成器。

操作系统可能有多种此类随机位生成器。在我们的 POSIX 系统示例中，我们使用了`/dev/urandom`，而不是更安全的`/dev/random`，因为后者在操作系统捕获足够的随机事件之前会保持阻塞状态。等待熵可能需要几秒钟，这通常不适用于应用程序。对于长期使用的**GPG**/**SSL**/**SSH**密钥，请使用`/dev/random`。

现在我们已经完成了生成器，是时候转到*步骤 4*并讨论分布类了。如果生成器只生成均匀分布的位，分布类将从这些位生成一个随机数。在*步骤 4*中，我们创建了一个返回`unsigned short`类型的随机数的均匀分布。参数`1000`表示分布必须返回大于或等于`1000`的数字。我们还可以提供最大数字作为第二个参数，该参数默认等于返回类型中可存储的最大值。

# 还有更多...

`Boost.Random`有大量用于不同需求的真/伪随机位生成器和分布。避免复制分布和生成器。这可能是一个昂贵的操作。

C++11 支持不同的分布类和生成器。您可以在`std::`命名空间的`<random>`头文件中找到这个示例中的所有类。`Boost.Random`库不使用 C++11 特性，而且该库也不真正需要。您应该使用 Boost 实现还是标准库？Boost 在各个系统之间提供更好的可移植性。但是，一些标准库可能具有汇编优化的实现，并且可能提供一些有用的扩展。

# 另请参阅

官方文档包含了一份带有描述的生成器和分布的完整列表。它可以在以下链接找到：[`boost.org/libs/random.`](http://boost.org/libs/random)

# 使用可移植数学函数

一些项目需要特定的三角函数、用于数值求解常微分方程和处理分布和常数的库。`Boost.Math`的所有这些部分甚至在一本单独的书中都很难涵盖。单一的示例肯定是不够的。因此，让我们专注于与浮点类型一起使用的非常基本的日常函数。

我们将编写一个可移植的函数，用于检查输入值是否为无穷大和**非数值**（**NaN**）值，并在值为负时更改符号。

# 准备工作

这个示例需要基本的 C++知识。熟悉 C99 标准的人会在这个示例中找到很多共同之处。

# 如何做...

执行以下步骤来检查输入值是否为无穷大和 NaN 值，并在值为负时更改符号：

1.  我们需要以下头文件：

```cpp
#include <boost/math/special_functions.hpp> 
#include <cassert> 
```

1.  对无穷大和 NaN 进行断言可以这样做：

```cpp
template <class T> 
void check_float_inputs(T value) { 
    assert(!boost::math::isinf(value)); 
    assert(!boost::math::isnan(value)); 
```

1.  使用以下代码更改符号：

```cpp
    if (boost::math::signbit(value)) { 
        value = boost::math::changesign(value); 
    } 

    // ... 
} // check_float_inputs 
```

就是这样！现在，我们可以检查`check_float_inputs(std::sqrt(-1.0))`和`check_float_inputs(std::numeric_limits<double>::max() * 2.0)`是否会触发断言。

# 它是如何工作的...

实数类型具有特定的值，不能使用相等运算符进行检查。例如，如果变量`v`包含 NaN，则`assert(v != v)`可能会通过也可能不会，这取决于编译器。

对于这种情况，`Boost.Math`提供了可靠检查无穷大和 NaN 值的函数。

*步骤 3*包含`boost::math::signbit`函数，需要澄清。该函数返回一个带符号的位，当数字为负时为`1`，当数字为正时为`0`。换句话说，如果值为负，则返回`true`。

看看*步骤 3*，一些读者可能会问，为什么我们不能只乘以`-1`而不是调用`boost::math::changesign`？我们可以。但是，乘法可能比`boost::math::changesign`慢，并且不能保证对特殊值起作用。例如，如果你的代码可以处理`nan`，*步骤 3*中的代码可以改变`-nan`的符号，并将`nan`写入变量。

`Boost.Math`库的维护者建议将此示例中的数学函数用圆括号括起来，以避免与 C 宏发生冲突。最好写成`(boost::math::isinf)(value)`，而不是`boost::math::isinf(value)`。

# 还有更多...

C99 包含了这个配方中描述的所有函数。为什么我们需要它们在 Boost 中？嗯，一些编译器供应商认为程序员不需要完全支持 C99，所以你在至少一个非常流行的编译器中找不到这些函数。另一个原因是`Boost.Math`函数可能被用于行为类似数字的类。

`Boost.Math`是一个非常快速、便携和可靠的库。**数学特殊函数**是`Boost.Math`库的一部分，一些数学特殊函数已经被接受到 C++17 中。然而，`Boost.Math`提供了更多的数学特殊函数，并且具有高度可用的递归版本，具有更好的复杂度，更适合一些任务（如数值积分）。

# 另请参阅

Boost 的官方文档包含许多有趣的示例和教程，这些将帮助你熟悉`Boost.Math`。浏览[`boost.org/libs/math`](http://boost.org/libs/math)了解更多信息。

# 编写测试用例

这个配方和下一个配方都致力于使用`Boost.Test`库进行自动测试，这个库被许多 Boost 库使用。让我们动手写一些针对我们自己类的测试：

```cpp
#include <stdexcept> 
struct foo { 
    int val_; 

    operator int() const; 
    bool is_not_null() const; 
    void throws() const; // throws(std::logic_error) 
}; 
```

# 准备工作

这个配方需要基本的 C++知识。要编译这个配方的代码，需要定义`BOOST_TEST_DYN_LINK`宏，并链接`boost_unit_test_framework`和`boost_system`库。

# 如何做...

老实说，在 Boost 中有不止一个测试库。我们将看看最功能强大的一个。

1.  要使用它，我们需要定义宏并包含以下头文件：

```cpp
#define BOOST_TEST_MODULE test_module_name 
#include <boost/test/unit_test.hpp> 
```

1.  每组测试必须写在测试用例中：

```cpp
BOOST_AUTO_TEST_CASE(test_no_1) { 
```

1.  检查某些函数的`true`结果必须按照以下方式进行：

```cpp
    foo f1 = {1}, f2 = {2}; 
    BOOST_CHECK(f1.is_not_null());
```

1.  检查不相等必须以以下方式实现：

```cpp
    BOOST_CHECK_NE(f1, f2); 
```

1.  检查是否抛出异常必须像这样：

```cpp
    BOOST_CHECK_THROW(f1.throws(), std::logic_error); 
} // BOOST_AUTO_TEST_CASE(test_no_1) 
```

就是这样！编译和链接后，我们将得到一个二进制文件，它会自动测试`foo`并以人类可读的格式输出测试结果。

# 它是如何工作的...

编写单元测试很容易。你知道函数的工作原理以及在特定情况下它会产生什么结果。因此，你只需检查预期结果是否与函数的实际输出相同。这就是我们在*步骤 3*中所做的。我们知道`f1.is_not_null()`返回`true`，我们进行了检查。在*步骤 4*中，我们知道`f1`不等于`f2`，所以我们也进行了检查。调用`f1.throws()`会产生`std::logic_error`异常，我们检查是否抛出了预期类型的异常。

在*步骤 2*中，我们正在创建一个测试用例--一组检查，以验证`foo`结构的正确行为。我们可以在单个源文件中有多个测试用例。例如，如果我们添加以下代码：

```cpp
BOOST_AUTO_TEST_CASE(test_no_2) { 
    foo f1 = {1}, f2 = {2}; 
    BOOST_REQUIRE_NE(f1, f2); 
    // ... 
} // BOOST_AUTO_TEST_CASE(test_no_2) 
```

这段代码将与`test_no_1`测试用例一起运行。

传递给`BOOST_AUTO_TEST_CASE`宏的参数只是测试用例的唯一名称，在出现错误时显示。

```cpp
Running 2 test cases... 
main.cpp(15): error in "test_no_1": check f1.is_not_null() failed 
main.cpp(17): error in "test_no_1": check f1 != f2 failed [0 == 0] 
main.cpp(19): error in "test_no_1": exception std::logic_error is expected 
main.cpp(24): fatal error in "test_no_2": critical check f1 != f2 failed [0 == 0] 

*** 4 failures detected in test suite "test_module_name" 
```

`BOOST_REQUIRE_*`和`BOOST_CHECK_*`宏之间有一个小差异。如果`BOOST_REQUIRE_*`宏检查失败，当前测试用例的执行将停止，`Boost.Test`将运行下一个测试用例。然而，失败的`BOOST_CHECK_*`不会停止当前测试用例的执行。

*步骤 1*需要额外的注意。请注意`BOOST_TEST_MODULE`宏的定义。这个宏必须在包含`Boost.Test`头文件之前定义；否则，链接程序将失败。更多信息可以在这个配方的*另请参阅*部分找到。

# 还有更多...

一些读者可能会想，为什么在*步骤 4*中我们写了`BOOST_CHECK_NE(f1, f2)`而不是`BOOST_CHECK(f1 != f2)`？答案很简单：*步骤 4*中的宏在旧版本的`Boost.Test`库上提供了更易读和冗长的输出。

C++17 缺乏对单元测试的支持。然而，`Boost.Test`库可以用来测试 C++17 和 C++11 之前的代码。

请记住，你拥有的测试越多，你得到的可靠代码就越多！

# 另请参阅

+   *将多个测试用例组合在一个测试模块中*配方包含了更多关于测试和`BOOST_TEST_MODULE`宏的信息。

+   请参阅 Boost 官方文档 [`boost.org/libs/test`](http://boost.org/libs/test) 以获取关于`Boost.Test`的所有测试宏和高级功能的信息

# 将多个测试用例组合在一个测试模块中

编写自动测试对你的项目很有好处。然而，当项目很大并且有许多开发人员在上面工作时，管理测试用例是很困难的。在这个配方中，我们将看看如何运行单独的测试以及如何将多个测试用例组合在一个单一模块中。

假设有两个开发人员正在测试`foo.hpp`头文件中声明的`foo`结构，我们希望给他们单独的源文件来编写测试。在这种情况下，两个开发人员不会互相打扰，并且可以并行工作。然而，默认的测试运行必须执行两个开发人员的测试。

# 准备就绪

这个配方需要基本的 C++知识。这个配方部分地重用了上一个配方中的代码，还需要定义`BOOST_TEST_DYN_LINK`宏，并链接`boost_unit_test_framework`和`boost_system`库。

# 如何做...

这个配方使用了上一个配方中的代码。这是一个非常有用的测试大型项目的配方。不要低估它。

1.  从上一个配方的`main.cpp`头文件中，只留下这两行：

```cpp
#define BOOST_TEST_MODULE test_module_name 
#include <boost/test/unit_test.hpp> 
```

1.  让我们将上一个示例中的测试用例移动到两个不同的源文件中：

```cpp
// developer1.cpp 
#include <boost/test/unit_test.hpp> 
#include "foo.hpp" 
BOOST_AUTO_TEST_CASE(test_no_1) { 
    // ... 
} 
// developer2.cpp 
#include <boost/test/unit_test.hpp> 
#include "foo.hpp" 
BOOST_AUTO_TEST_CASE(test_no_2) { 
    // ... 
} 
```

就是这样！因此，在程序执行时，编译和链接所有源代码和两个测试用例都将正常工作。

# 它是如何工作的...

所有的魔法都是由`BOOST_TEST_MODULE`宏完成的。如果在`<boost/test/unit_test.hpp>`之前定义了它，`Boost.Test`会认为这个源文件是主文件，所有的辅助测试基础设施都必须放在其中。否则，只有测试宏会被包含在`<boost/test/unit_test.hpp>`中。

如果将它们与包含`BOOST_TEST_MODULE`宏的源文件链接，所有的`BOOST_AUTO_TEST_CASE`测试都将运行。在处理大型项目时，每个开发人员可以启用仅编译和链接他们自己的源文件。这样可以独立于其他开发人员，并增加开发速度-在调试时不需要编译外部源文件和运行外部测试。

# 还有更多...

`Boost.Test`库很好，因为它能够有选择地运行测试。我们可以选择要运行的测试，并将它们作为命令行参数传递。例如，以下命令只运行`test_no_1`测试用例：

```cpp
    ./testing_advanced -run=test_no_1
```

以下命令运行两个测试用例：

```cpp
    ./testing_advanced -run=test_no_1,test_no_2
```

很遗憾，C++17 标准不支持内置的测试支持，而且看起来 C++20 也不会采用`Boost.Test`的类和方法。

# 另请参阅

+   *编写测试用例*配方包含了更多关于`Boost.Test`库的信息。阅读 Boost 官方文档 [`boost.org/libs/test`](http://boost.org/libs/test) 以获取更多关于`Boost.Test`的信息。

+   勇敢的人可以尝试查看 Boost 库中的一些测试用例。这些测试用例位于`boost`文件夹中的`libs`子文件夹中。例如，`Boost.LexicalCast`的测试用例位于`boost_1_XX_0/libs/lexical_cast/test`。

# 操作图像

我已经为你留下了一些非常美味的甜点 - Boost 的通用图像库或者`Boost.GIL`，它允许你在不太担心图像格式的情况下操作图像。

让我们做一些简单有趣的事情。例如，让我们制作一个对任何图片进行否定的程序。

# 准备工作

这个配方需要基本的 C++、模板和`Boost.Variant`的知识。示例需要链接`png`库。

# 如何做...

为了简化示例，我们将只使用 PNG 图像。

1.  让我们从包含头文件开始：

```cpp
#include <boost/gil/gil_all.hpp> 
#include <boost/gil/extension/io/png_dynamic_io.hpp> 
#include <string> 
```

1.  现在，我们需要定义我们希望使用的图像类型：

```cpp
int main(nt argc, char *argv[]) {
    typedef boost::mpl::vector<
            boost::gil::gray8_image_t,
            boost::gil::gray16_image_t,
            boost::gil::rgb8_image_t
    > img_types;
```

1.  打开现有的 PNG 图像可以这样实现：

```cpp
    std::string file_name(argv[1]); 
    boost::gil::any_image<img_types> source; 
    boost::gil::png_read_image(file_name, source);
```

1.  我们需要按照以下方式对图片进行操作：

```cpp
    boost::gil::apply_operation( 
        view(source), 
        negate() 
    ); 
```

1.  以下代码行将帮助你编写一张图片：

```cpp
    boost::gil::png_write_view("negate_" + file_name, const_view(source)); 
```

1.  让我们来看看修改操作：

```cpp
struct negate { 
    typedef void result_type; // required 

    template <class View> 
    void operator()(const View& source) const { 
        // ... 
    } 
}; // negate 
```

1.  `operator()`的主体包括获取通道类型：

```cpp
typedef typename View::value_type value_type; 
typedef typename boost::gil::channel_type<value_type>::type channel_t; 
```

1.  它还遍历像素：

```cpp
const std::size_t channels = boost::gil::num_channels<View>::value; 
const channel_t max_val = (std::numeric_limits<channel_t>::max)(); 

for (unsigned int y = 0; y < source.height(); ++y) { 
    for (unsigned int x = 0; x < source.width(); ++x) { 
        for (unsigned int c = 0; c < channels; ++c) { 
            source(x, y)[c] = max_val - source(x, y)[c]; 
        } 
    } 
} 
```

现在让我们看看我们程序的结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/boost-cpp-appdev-cb-2e/img/00022.gif)

前面的图片是接下来的图片的负片：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/boost-cpp-appdev-cb-2e/img/00023.gif)

# 工作原理...

在*步骤 2*中，我们描述了我们希望使用的图像类型。这些图像是每像素 8 位和 16 位的灰度图像，以及每像素 8 位的 RGB 图片。

`boost::gil::any_image<img_types>`类是一种可以容纳`img_types`变量之一的图像的`Boost.Variant`。正如你可能已经猜到的那样，`boost::gil::png_read_image`将图像读入图像变量中。

*步骤 4*中的`boost::gil::apply_operation`函数几乎等同于`Boost.Variant`库中的`boost::apply_visitor`。注意`view(source)`的用法。`boost::gil::view`函数构造了一个轻量级的包装器，将图像解释为像素的二维数组。

你还记得对于`Boost.Variant`，我们是从`boost::static_visitor`派生访问者的吗？当我们使用 GIL 的变体版本时，我们需要在`visitor`内部进行`result_type`的 typedef。你可以在*步骤 6*中看到它。

一点理论知识：图像由称为**像素**的点组成。一个图像有相同类型的像素。然而，不同图像的像素可能在通道计数和单个通道的颜色位方面有所不同。通道代表主要颜色。在 RGB 图像的情况下，我们有一个由三个通道 - 红色、绿色和蓝色组成的像素。在灰度图像的情况下，我们有一个表示灰度的单个通道。

回到我们的图片。在*步骤 2*中，我们描述了我们希望使用的图像类型。在*步骤 3*中，其中一种图像类型从文件中读取并存储在源变量中。在*步骤 4*中，为所有图像类型实例化了`negate`访问者的`operator()`方法。

在*步骤 7*中，我们可以看到如何从图像视图中获取通道类型。

在*步骤 8*中，我们遍历像素和通道并对其进行否定。否定是通过`max_val - source(x, y)[c]`来完成的，并将结果写回图像视图。

我们在*步骤 5*中将图像写回。

# 还有更多...

C++17 没有内置的方法来处理图像。目前正在进行工作，将 2D 绘图添加到 C++标准库中，尽管这是一种有点正交的功能。

`Boost.GIL`库快速高效。编译器对其代码进行了良好的优化，我们甚至可以使用一些`Boost.GIL`方法来帮助优化器展开循环。但本章仅讨论了库的一些基础知识，所以是时候停下来了。

# 另请参阅

+   有关`Boost.GIL`的更多信息可以在 Boost 的官方文档[`boost.org/libs/gil`](http://boost.org/libs/gil)中找到

+   在第一章的*存储多种选择的类型在一个变量/容器中*配方中查看更多关于`Boost.Variant`库的信息

+   请查看[`isocpp.org/`](https://isocpp.org/)了解更多关于 C++的新闻

+   查看[`stdcpp.ru/`](https://stdcpp.ru/)讨论关于 C++提案的俄语文章
