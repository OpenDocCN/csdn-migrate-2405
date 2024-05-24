# Boost C++ 应用开发秘籍第二版（一）

> 原文：[`annas-archive.org/md5/8a1821d22bcd421390c328e6f1d92500`](https://annas-archive.org/md5/8a1821d22bcd421390c328e6f1d92500)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

如果您想充分利用 Boost 和 C++的真正力量，并避免在不同情况下使用哪个库的困惑，那么这本书适合您。

从 Boost C++的基础知识开始，您将学习如何利用 Boost 库简化应用程序开发。您将学会将数据转换，例如将字符串转换为数字，数字转换为字符串，数字转换为数字等。资源管理将变得轻而易举。您将了解可以在编译时完成哪些工作以及 Boost 容器的功能。您将学会为高质量、快速和可移植的应用程序开发所需的一切。只需编写一次程序，然后就可以在 Linux、Windows、macOS 和 Android 操作系统上使用。从操作图像到图形、目录、定时器、文件和网络，每个人都会找到一个有趣的主题。

请注意，本书的知识不会过时，因为越来越多的 Boost 库成为 C++标准的一部分。

# 本书涵盖的内容

第一章，“开始编写您的应用程序”，介绍了日常使用的库。我们将看到如何从不同来源获取配置选项，以及使用 Boost 库作者引入的一些数据类型可以做些什么。

第二章，“资源管理”，涉及由 Boost 库引入的数据类型，主要关注指针的使用。我们将看到如何轻松管理资源，以及如何使用能够存储任何功能对象、函数和 lambda 表达式的数据类型。阅读完本章后，您的代码将变得更加可靠，内存泄漏将成为历史。

第三章，“转换和强制转换”，描述了如何将字符串、数字和用户定义的类型相互转换，如何安全地转换多态类型，以及如何在 C++源文件中编写小型和大型解析器。涵盖了日常使用和罕见情况下数据转换的多种方式。

第四章，“编译时技巧”，描述了 Boost 库的一些基本示例，可以用于调整算法的编译时检查，以及其他元编程任务。没有理解这些内容，就无法理解 Boost 源代码和其他类似 Boost 的库。

第五章，“多线程”，着重介绍了多线程编程的基础知识以及与之相关的所有内容。

第六章，“任务操作”，展示了将功能对象称为任务。本章的主要思想是，我们可以将所有处理、计算和交互分解为函数对象（任务），并几乎独立地处理每个任务。此外，我们可以不阻塞一些慢操作（例如从套接字接收数据或等待超时），而是提供一个回调任务，并继续处理其他任务。一旦操作系统完成慢操作，我们的回调将被执行。

第七章，“字符串操作”，展示了改变、搜索和表示字符串的不同方面。我们将看到如何使用 Boost 库轻松完成一些常见的与字符串相关的任务。它涉及非常常见的字符串操作任务。

第八章，“元编程”，介绍了一些酷而难以理解的元编程方法。在本章中，我们将深入了解如何将多种类型打包成单个类似元组的类型。我们将创建用于操作类型集合的函数，看到如何改变编译时集合的类型，以及如何将编译时技巧与运行时混合使用。

第九章《容器》介绍了 boost 容器及与之直接相关的内容。本章提供了关于 Boost 类的信息，这些类可以在日常编程中使用，可以使您的代码运行速度更快，开发新应用程序更容易。

第十章《收集平台和编译器信息》描述了用于检测编译器、平台和 Boost 特性的不同辅助宏--这些宏广泛用于 boost 库，并且对于编写能够使用任何编译器标志的可移植代码至关重要。

第十一章《与系统一起工作》提供了对文件系统的更详细的了解，以及如何创建和删除文件。我们将看到数据如何在不同的系统进程之间传递，如何以最大速度读取文件，以及如何执行其他技巧。

第十二章《触类旁通》致力于一些大型库，并为您提供一些入门基础知识。

# 您需要为本书做好准备

您需要一个现代的 C++编译器，Boost 库（任何版本都可以，建议使用 1.65 或更高版本），以及 QtCreator/qmake，或者只需访问[`apolukhin.GitHub.io/Boost-Cookbook/`](http://apolukhin.github.io/Boost-Cookbook/)在线运行和实验示例。

# 这本书适用对象

这本书适用于希望提高对 Boost 的了解并希望简化其应用程序开发流程的开发人员。假定具有先前的 C++知识和标准库的基本知识。

# 章节

在本书中，您将经常看到几个标题（准备工作，如何做...，它是如何工作的...，还有更多...，另请参阅）。为了清晰地说明如何完成配方，我们使用这些部分如下：

# 准备工作

本节告诉您配方中可以期望的内容，并描述了为配方设置任何软件或任何预备设置所需的步骤。

# 如何做...

本节包含遵循该配方所需的步骤。

# 它是如何工作...

本节通常包括对前一节发生的事情的详细解释。

# 还有更多...

本节包含有关配方的其他信息，以使读者更加了解配方。

# 另请参阅

本节提供了有关配方的其他有用信息的链接。

# 约定

在本书中，您将找到一些区分不同类型信息的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：

“请记住，这个库不仅仅是一个头文件，所以您的程序必须链接到`libboost_program_options`库”。

代码块设置如下：

```cpp
#include <boost/program_options.hpp> 
#include <iostream>
namespace opt = boost::program_options; 
int main(int argc, char *argv[])
{
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目以粗体显示：

```cpp
#include <boost/program_options.hpp> 
#include <iostream>
namespace opt = boost::program_options; 
int main(int argc, char *argv[])
```

任何命令行输入或输出都以以下方式编写：

```cpp
 $ ./our_program.exe --apples=10 --oranges=20
Fruits count: 30
```

**新术语**和**重要单词**以粗体显示。

警告或重要说明会以这样的形式出现在一个框中。

提示和技巧会出现在这样的形式中。

# 第一章：开始编写你的应用程序

在本章中，我们将涵盖：

+   获取配置选项

+   将任何值存储在一个容器/变量中

+   将多个选择的类型存储在一个容器/变量中

+   使用更安全的方式处理存储多个选择类型的容器

+   在没有值的情况下返回一个值或标志

+   从函数返回数组

+   将多个值合并为一个

+   绑定和重新排序函数参数

+   获取可读的类型名称

+   使用 C++11 移动模拟

+   创建一个不可复制的类

+   创建一个不可复制但可移动的类

+   使用 C++14 和 C++11 算法

# 介绍

**Boost**是一个 C++库集合。每个库在被 Boost 接受之前都经过许多专业程序员的审查。库在多个平台上使用多个编译器和多个 C++标准库实现进行测试。在使用 Boost 时，您可以确信您正在使用一个最具可移植性、快速和可靠的解决方案之一，该解决方案在商业和开源项目中都适用的许可证下分发。

Boost 的许多部分已经包含在 C++11、C++14 和 C++17 中。此外，Boost 库将包含在 C++的下一个标准中。您将在本书的每个配方中找到特定于 C++标准的注释。

不需要长篇介绍，让我们开始吧！

在本章中，我们将看到一些日常使用的配方。我们将看到如何从不同来源获取配置选项，以及使用 Boost 库作者介绍的一些数据类型可以做些什么。

# 获取配置选项

看看一些控制台程序，比如 Linux 中的`cp`。它们都有一个漂亮的帮助；它们的输入参数不依赖于任何位置，并且具有人类可读的语法。例如：

```cpp
$ cp --help
Usage: cp [OPTION]... [-T] SOURCE DEST
  -a, --archive           same as -dR --preserve=all
  -b                      like --backup but does not accept an argument 
```

你可以在 10 分钟内为你的程序实现相同的功能。你所需要的只是`Boost.ProgramOptions`库。

# 准备就绪

这个配方只需要基本的 C++知识。请记住，这个库不仅仅是一个头文件，所以你的程序必须链接到`libboost_program_options`库。

# 如何做...

让我们从一个简单的程序开始，该程序接受`apples`和`oranges`的数量作为输入，并计算水果的总数。我们希望实现以下结果：

```cpp
 $ ./our_program.exe --apples=10 --oranges=20 Fruits count: 30
```

执行以下步骤：

1.  包括`boost/program_options.hpp`头文件，并为`boost::program_options`命名空间创建一个别名（它太长了！）。我们还需要一个`<iostream>`头文件：

```cpp
#include <boost/program_options.hpp> 
#include <iostream> 

namespace opt = boost::program_options; 
```

1.  现在，我们准备在`main()`函数中描述我们的选项：

```cpp
int main(int argc, char *argv[])
{
    // Constructing an options describing variable and giving 
    // it a textual description "All options". 
    opt::options_description desc("All options"); 

    // When we are adding options, first parameter is a name
    // to be used in command line. Second parameter is a type
    // of that option, wrapped in value<> class. Third parameter
    // must be a short description of that option.
    desc.add_options()
        ("apples", opt::value<int>(), "how many apples do 
                                       you have")
        ("oranges", opt::value<int>(), "how many oranges do you 
                                        have")
        ("help", "produce help message")
    ;
```

1.  让我们解析命令行：

```cpp
    // Variable to store our command line arguments.
    opt::variables_map vm; 

    // Parsing and storing arguments.
    opt::store(opt::parse_command_line(argc, argv, desc), vm); 

    // Must be called after all the parsing and storing.
    opt::notify(vm);
```

1.  让我们为处理`help`选项添加一些代码：

```cpp
    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 1;
    }
```

1.  最后一步。计算水果可以以以下方式实现：

```cpp
    std::cout << "Fruits count: "
        << vm["apples"].as<int>() + vm["oranges"].as<int>()
        << std::endl;

} // end of `main`
```

现在，如果我们用`help`参数调用我们的程序，我们将得到以下输出：

```cpp
All options: 
    --apples arg          how many apples do you have
    --oranges arg        how many oranges do you have 
    --help                    produce help message 
```

如你所见，我们没有为`help`选项的值提供类型，因为我们不希望向其传递任何值。

# 它是如何工作的...

这个例子从代码和注释中很容易理解。运行它会产生预期的结果：

```cpp
 $ ./our_program.exe --apples=100 --oranges=20 Fruits count: 120
```

# 还有更多...

C++标准采用了许多 Boost 库；然而，即使在 C++17 中，你也找不到`Boost.ProgramOptions`。目前，没有计划将其纳入 C++2a。

`ProgramOptions`库非常强大，具有许多功能。以下是如何做的：

+   将配置选项值直接解析到一个变量中，并将该选项设置为必需的：

```cpp
    int oranges_var = 0;
    desc.add_options()
        // ProgramOptions stores the option value into 
        // the variable that is passed by pointer. Here value of 
        // "--oranges" option will be stored into 'oranges_var'.
        ("oranges,o", opt::value<int>(&oranges_var)->required(), 
                                                "oranges you have")
```

+   获取一些必需的字符串选项：

```cpp
        // 'name' option is not marked with 'required()',
        // so user may not provide it.
        ("name", opt::value<std::string>(), "your name")
```

+   为苹果添加简称，将`10`设置为`apples`的默认值：

```cpp
        // 'a' is a short option name for apples. Use as '-a 10'.
        // If no value provided, then the default value is used.
        ("apples,a", opt::value<int>()->default_value(10),
                                   "apples that you have");
```

+   从配置文件获取缺失的选项：

```cpp
    opt::variables_map vm;

    // Parsing command line options and storing values to 'vm'.
    opt::store(opt::parse_command_line(argc, argv, desc), vm);

    // We can also parse environment variables. Just use
    // 'opt::store with' 'opt::parse_environment' function.

    // Adding missing options from "apples_oranges.cfg" config file.
    try {
        opt::store(
            opt::parse_config_file<char>("apples_oranges.cfg", desc),
            vm
        );
    } catch (const opt::reading_file& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
```

配置文件语法与命令行语法不同。我们不需要在选项前加上减号。因此，我们的`apples_oranges.cfg`文件必须如下所示：

`oranges=20`

+   验证是否设置了所有必需的选项：

```cpp
    try {
        // `opt::required_option` exception is thrown if
        // one of the required options was not set.
        opt::notify(vm);

    } catch (const opt::required_option& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return 2;
    }
```

如果我们将所有提到的提示组合成一个可执行文件，那么它的`help`命令将产生以下输出：

```cpp
$ ./our_program.exe --help
 All options:
   -o [ --oranges ] arg          oranges that you have
   --name arg                       your name
   -a [ --apples ] arg (=10)  apples that you have
   --help                              produce help message

```

如果没有配置文件运行，将产生以下输出：

```cpp
$ ./our_program.exe
 Error: can not read options configuration file 'apples_oranges.cfg'
 Error: the option '--oranges' is required but missing 
```

在配置文件中以`oranges=20`运行程序将生成++，因为 apples 的默认值是`10`：

```cpp
$ ./our_program.exe
 Fruits count: 30
```

# 另请参阅

+   Boost 的官方文档包含了更多的例子，并告诉我们关于`Boost.ProgramOptions`更高级的特性，比如位置相关的选项，非常规的语法等；可以在[`boost.org/libs/program_options`](http://boost.org/libs/program_options)找到。

+   你可以在[`apolukhin.github.io/Boost-Cookbook`](http://apolukhin.github.io/Boost-Cookbook)上修改并运行本书中的所有示例。

# 在容器/变量中存储任何值

如果你一直在使用 Java、C#或 Delphi 进行编程，你肯定会想念在 C++中使用`Object`值类型创建容器的能力。在这些语言中，`Object`类是几乎所有类型的基本类，因此你可以随时将几乎任何值赋给它。想象一下，如果 C++中有这样的功能会多么棒：

```cpp
typedef std::unique_ptr<Object> object_ptr; 

std::vector<object_ptr> some_values; 
some_values.push_back(new Object(10)); 
some_values.push_back(new Object("Hello there")); 
some_values.push_back(new Object(std::string("Wow!"))); 

std::string* p = dynamic_cast<std::string*>(some_values.back().get()); 
assert(p); 
(*p) += " That is great!\n"; 
std::cout << *p; 
```

# 准备工作

我们将使用这个仅包含头文件的库。这个示例只需要基本的 C++知识。

# 如何做...

Boost 提供了一个解决方案，`Boost.Any`库，它具有更好的语法：

```cpp
#include <boost/any.hpp> 
#include <iostream> 
#include <vector> 
#include <string> 

int main() { 
    std::vector<boost::any> some_values; 
    some_values.push_back(10); 
    some_values.push_back("Hello there!"); 
    some_values.push_back(std::string("Wow!"));

    std::string& s = boost::any_cast<std::string&>(some_values.back()); 
    s += " That is great!"; 
    std::cout << s; 
} 
```

很棒，不是吗？顺便说一句，它有一个空状态，可以使用`empty()`成员函数进行检查（就像标准库容器一样）。

你可以使用两种方法从`boost::any`中获取值：

```cpp
void example() {
    boost::any variable(std::string("Hello world!"));

    // Following method may throw a boost::bad_any_cast exception
    // if actual value in variable is not a std::string.
    std::string s1 = boost::any_cast<std::string>(variable);

    // Never throws. If actual value in variable is not a std::string
    // will return an NULL pointer.
    std::string* s2 = boost::any_cast<std::string>(&variable);
}
```

# 它是如何工作的...

`boost::any`类只是在其中存储任何值。为了实现这一点，它使用**类型擦除**技术（与 Java 或 C#对所有类型的处理方式相似）。要使用这个库，你不需要详细了解它的内部实现，但是对于好奇的人来说，这里有一个类型擦除技术的快速概述。

在对类型为`T`的某个变量进行赋值时，`Boost.Any`实例化一个`holder<T>`类型，该类型可以存储指定类型`T`的值，并且派生自某个基本类型`placeholder`：

```cpp
template<typename ValueType>
struct holder : public placeholder {
    virtual const std::type_info& type() const {
         return typeid(ValueType);
    }
     ValueType held;
};
```

`placeholder`类型有虚函数，用于获取存储类型`T`的`std::type_info`和克隆存储类型：

```cpp
struct placeholder {
    virtual ~placeholder() {}
    virtual const std::type_info& type() const = 0;
};
```

`boost::any`存储`ptr`-- 指向`placeholder`的指针。当使用`any_cast<T>()`时，`boost::any`会检查调用`ptr->type()`是否给出`std::type_info`等于`typeid(T)`，并返回`static_cast<holder<T>*>(ptr)->held`。

# 还有更多...

这种灵活性并非没有代价。对`boost::any`的实例进行复制构造、值构造、复制赋值和赋值操作都会进行动态内存分配；所有类型转换都会进行**运行时类型信息**（**RTTI**）检查；`boost::any`大量使用虚函数。如果你对性能很敏感，下一个示例将让你了解如何在不使用动态分配和 RTTI 的情况下实现几乎相同的结果。

`boost::any`使用**右值引用**，但不能在**constexpr**中使用。

`Boost.Any`库已被接受到 C++17 中。如果你的编译器兼容 C++17，并且希望避免使用`boost`来使用`any`，只需将`boost`命名空间替换为`std`命名空间，并包含`<any>`而不是`<boost/any.hpp>`。如果你在`std::any`中存储小对象，你的标准库实现可能会稍微更快。

`std::any`具有`reset()`函数，而不是`clear()`，还有`has_value()`而不是`empty()`。Boost 中几乎所有的异常都源自`std::exception`类或其派生类，例如，`boost::bad_any_cast`源自`std::bad_cast`。这意味着你几乎可以使用`catch (const std::exception& e)`捕获所有 Boost 异常。

# 另请参阅

+   Boost 的官方文档可能会给你一些更多的例子；可以在[`boost.org/libs/any`](http://www.boost.org/libs/any)找到。

+   有关此主题的更多信息，请参阅*使用更安全的方式处理存储多种选择类型的容器*的示例

# 在容器/变量中存储多种选择类型

C++03 联合体只能容纳称为**POD**（**Plain Old Data**）的极其简单的类型。例如，在 C++03 中，你不能在联合体中存储`std::string`或`std::vector`。

你是否了解 C++11 中**不受限制的联合体**的概念？让我简要地告诉你。C++11 放宽了对联合体的要求，但你必须自己管理非 POD 类型的构造和销毁。你必须调用就地构造/销毁，并记住联合体中存储的类型。这是一项巨大的工作，不是吗？

我们是否可以在 C++03 中拥有一个像变量一样管理对象生命周期并记住其类型的不受限制的联合体？

# 准备工作

我们将使用这个只有头文件的库，它很容易使用。这个配方只需要基本的 C++知识。

# 如何做...

让我向你介绍`Boost.Variant`库。

1.  `Boost.Variant`库可以在编译时存储任何指定的类型。它还管理就地构造/销毁，甚至不需要 C++11 标准：

```cpp
#include <boost/variant.hpp>
#include <iostream>
#include <vector>
#include <string>

int main() {
    typedef boost::variant<int, const char*, std::string> my_var_t;
    std::vector<my_var_t> some_values;
    some_values.push_back(10);
    some_values.push_back("Hello there!");
    some_values.push_back(std::string("Wow!"));

    std::string& s = boost::get<std::string>(some_values.back());
    s += " That is great!\n";
    std::cout << s;
} 
```

很棒，不是吗？

1.  `Boost.Variant`没有空状态，但有一个无用且总是返回`false`的`empty()`函数。如果你需要表示一个空状态，只需在`Boost.Variant`库支持的类型列表的第一个位置添加一些简单的类型。当`Boost.Variant`包含该类型时，将其解释为空状态。以下是一个例子，我们将使用`boost::blank`类型来表示一个空状态：

```cpp
void example1() {
    // Default constructor constructs an instance of boost::blank.
    boost::variant<
        boost::blank, int, const char*, std::string
    > var;

    // 'which()' method returns an index of a type
    // currently held by variant.
    assert(var.which() == 0); // boost::blank

    var = "Hello, dear reader";
    assert(var.which() != 0);
}
```

1.  你可以使用两种方法从变体中获取值：

```cpp
void example2() {
    boost::variant<int, std::string> variable(0);

    // Following method may throw a boost::bad_get
    // exception if actual value in variable is not an int.
    int s1 = boost::get<int>(variable);

    // If actual value in variable is not an int will return NULL.
    int* s2 = boost::get<int>(&variable);
}
```

# 它是如何工作的...

`boost::variant`类持有一个字节数组并在该数组中存储值。数组的大小是通过在编译时应用`sizeof()`和函数来获取每个模板类型的对齐方式来确定的。在赋值或构造`boost::variant`时，先前的值将就地销毁，并且新值将在字节数组的顶部构造，使用就地新放置。

# 还有更多...

`Boost.Variant`变量通常不会动态分配内存，也不需要启用 RTTI。`Boost.Variant`非常快速，并被其他 Boost 库广泛使用。为了实现最大的性能，确保在支持的类型列表的第一个位置有一个简单的类型。如果你的编译器支持 C++11 的右值引用，`boost::variant`将会利用它。

`Boost.Variant`是 C++17 标准的一部分。`std::variant`与`boost::variant`略有不同：

+   `std::variant`声明在`<variant>`头文件中，而不是在`<boost.variant.hpp>`中。

+   `std::variant`永远不会分配内存

+   `std::variant`可用于 constexpr

+   你不再需要写`boost::get<int>(&variable)`，而是需要为`std::variant`写`std::get_if<int>(&variable)`

+   `std::variant`不能递归地持有自身，并且缺少一些其他高级技术

+   `std::variant`可以就地构造对象

+   `std::variant`有`index()`而不是`which()`

# 另请参阅

+   *使用更安全的方式来处理存储多种选择类型的容器*配方

+   Boost 的官方文档包含了更多的例子和对`Boost.Variant`的一些其他特性的描述，可以在[`boost.org/libs/variant`](http://www.boost.org/libs/variant)找到

+   在[`apolukhin.github.io/Boost-Cookbook`](http://apolukhin.github.io/Boost-Cookbook)上在线尝试这段代码

# 使用更安全的方式来处理存储多种选择类型的容器

想象一下，你正在创建一个围绕某个 SQL 数据库接口的包装器。你决定`boost::any`完全符合数据库表的单个单元格的要求。

其他程序员将使用你的类，他/她的任务是从数据库中获取一行并计算该行中算术类型的总和。

这就是这样一个代码会是什么样子：

```cpp
#include <boost/any.hpp> 
#include <vector> 
#include <string> 
#include <typeinfo> 
#include <algorithm> 
#include <iostream> 

// This typedefs and methods will be in our header, 
// that wraps around native SQL interface.
typedef boost::any cell_t; 
typedef std::vector<cell_t> db_row_t; 

// This is just an example, no actual work with database. 
db_row_t get_row(const char* /*query*/) { 
    // In real application 'query' parameter shall have a 'const 
    // char*' or 'const std::string&' type? See recipe "Type  
    // 'reference to string'" for an answer. 
    db_row_t row; 
    row.push_back(10); 
    row.push_back(10.1f); 
    row.push_back(std::string("hello again")); 
    return row; 
} 

// This is how a user will use your classes 
struct db_sum { 
private: 
    double& sum_; 
public: 
    explicit db_sum(double& sum) 
        : sum_(sum) 
    {} 

    void operator()(const cell_t& value) { 
        const std::type_info& ti = value.type(); 
        if (ti == typeid(int)) { 
            sum_ += boost::any_cast<int>(value); 
        } else if (ti == typeid(float)) { 
            sum_ += boost::any_cast<float>(value); 
        } 
    } 
}; 

int main() { 
    db_row_t row = get_row("Query: Give me some row, please."); 
    double res = 0.0; 
    std::for_each(row.begin(), row.end(), db_sum(res)); 
    std::cout << "Sum of arithmetic types in database row is: "
              << res << std::endl; 
} 
```

如果你编译并运行这个例子，它将输出一个正确的答案：

```cpp
Sum of arithmetic types in database row is: 20.1
```

您还记得阅读`operator()`实现时的想法吗？我猜它们是：“那 double、long、short、unsigned 和其他类型呢？”使用您的接口的程序员的头脑中也会出现同样的想法。因此，您需要仔细记录`cell_t`存储的值，或者使用以下部分描述的更优雅的解决方案。

# 做好准备

如果您还不熟悉`Boost.Variant`和`Boost.Any`库，强烈建议阅读前两个教程。

# 如何做到...

`Boost.Variant`库实现了访问存储数据的访问者编程模式，比通过`boost::get<>`获取值更安全。这种模式强制程序员注意 variant 中的每种类型，否则代码将无法编译。您可以通过`boost::apply_visitor`函数使用此模式，该函数将`visitor`函数对象作为第一个参数，将`variant`作为第二个参数。如果您使用的是 C++14 之前的编译器，则`visitor`函数对象必须派生自`boost::static_visitor<T>`类，其中`T`是`visitor`返回的类型。`visitor`对象必须对 variant 存储的每种类型重载`operator()`。

让我们将`cell_t`类型更改为`boost::variant<int, float, string>`并修改我们的例子：

```cpp
#include <boost/variant.hpp> 
#include <vector> 
#include <string> 
#include <iostream> 

// This typedefs and methods will be in header, 
// that wraps around native SQL interface. 
typedef boost::variant<int, float, std::string> cell_t; 
typedef std::vector<cell_t> db_row_t; 

// This is just an example, no actual work with database. 
db_row_t get_row(const char* /*query*/) { 
    // See recipe "Type 'reference to string'" 
    // for a better type for 'query' parameter. 
    db_row_t row; 
    row.push_back(10); 
    row.push_back(10.1f); 
    row.push_back("hello again"); 
    return row; 
} 

// This is a code required to sum values. 
// We can provide no template parameter 
// to boost::static_visitor<> if our visitor returns nothing. 
struct db_sum_visitor: public boost::static_visitor<double> { 
    double operator()(int value) const { 
        return value; 
    } 
    double operator()(float value) const { 
        return value; 
    } 
    double operator()(const std::string& /*value*/) const { 
        return 0.0; 
    } 
}; 

int main() { 
    db_row_t row = get_row("Query: Give me some row, please."); 
    double res = 0.0; 
    for (auto it = row.begin(), end = row.end(); it != end; ++it) { 
        res += boost::apply_visitor(db_sum_visitor(), *it); 
    } 

    std::cout << "Sum of arithmetic types in database row is: "
              << res << std::endl;
}
```

# 工作原理

在编译时，`Boost.Variant`库生成一个大的`switch`语句，每个 case 都调用 variant 类型列表中的单个类型的`visitor`。在运行时，使用`which()`检索存储类型的索引，并跳转到`switch`语句中的正确 case。对于`boost::variant<int, float, std::string>`，将生成类似于以下内容：

```cpp
switch (which()) 
{ 
case 0 /*int*/: 
    return visitor(*reinterpret_cast<int*>(address())); 
case 1 /*float*/: 
    return visitor(*reinterpret_cast<float*>(address())); 
case 2 /*std::string*/: 
    return visitor(*reinterpret_cast<std::string*>(address())); 
default: assert(false); 
} 
```

在这里，`address()`函数返回一个指向`boost::variant<int, float, std::string>`内部存储的指针。

# 还有更多...

如果我们将这个例子与本教程中的第一个例子进行比较，我们会看到`boost::variant`的以下优点：

+   我们知道变量可以存储哪些类型。

+   如果 SQL 接口的库编写者添加或修改了`variant`持有的类型，我们将得到编译时错误而不是不正确的行为

C++17 中的`std::variant`也支持访问。只需使用`std::visit`而不是`boost::apply_visitor`即可。

您可以从您在[`www.PacktPub.com`](http://www.PacktPub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，可以访问[`www.PacktPub.com/`](http://www.PacktPub.com/)support，并注册以直接通过电子邮件接收文件。

# 另请参阅

+   阅读第四章的一些教程后，即*编译时技巧*，即使底层类型发生变化，您也能够正确地编写通用的`visitor`对象

+   Boost 的官方文档包含更多示例和`Boost.Variant`的一些其他特性的描述；可以在以下链接找到：[`boost.org/libs/variant`](http://www.boost.org/libs/variant)

# 在没有值的情况下返回值或标志

假设我们有一个不会抛出异常并返回值或指示发生错误的函数。在 Java 或 C#编程语言中，通过将函数值与`null`指针进行比较来处理这种情况。如果函数返回了`null`，则发生了错误。在 C++中，从函数返回指针会使库用户感到困惑，并且通常需要缓慢的动态内存分配。

# 做好准备

本教程只需要基本的 C++知识。

# 如何做到...

女士们先生们，让我通过以下示例向您介绍`Boost.Optional`库：

`try_lock_device()`函数尝试获取设备的锁，可能成功也可能不成功，这取决于不同的条件（在我们的示例中，这取决于一些`try_lock_device_impl()`函数的调用）：

```cpp
#include <boost/optional.hpp>
#include <iostream>

class locked_device {
    explicit locked_device(const char* /*param*/) {
        // We have unique access to device.
        std::cout << "Device is locked\n";
    }

    static bool try_lock_device_impl();

public:
    void use() {
        std::cout << "Success!\n";
    }

    static boost::optional<locked_device> try_lock_device() {
        if (!try_lock_device_impl()) {
            // Failed to lock device.
            return boost::none;
        }

        // Success!
        return locked_device("device name");
    }

    ~locked_device(); // Releases device lock.
};
```

该函数返回可转换为`bool`的`boost::optional`变量。如果返回值等于`true`，则锁已获取，并且可以通过解引用返回的可选变量获得用于处理设备的类的实例：

```cpp
int main() { 
    for (unsigned i = 0; i < 10; ++i) { 
        boost::optional<locked_device> t
            = locked_device::try_lock_device(); 

        // optional is convertible to bool.
        if (t) { 
            t->use(); 
            return 0; 
        } else { 
            std::cout << "...trying again\n"; 
        } 
    } 

    std::cout << "Failure!\n"; 
    return -1; 
} 
```

这个程序将输出以下内容：

```cpp
...trying again
...trying again
Device is locked
Success!
```

默认构造的`optional`变量可转换为`false`，不得解引用，因为这样的`optional`没有构造的基础类型。

# 工作原理...

`boost::optional<T>`在内部有一个正确对齐的字节数组，可以在其中就地构造类型为`T`的对象。它还有一个`bool`变量来记住对象的状态（它是否被构造了？）。

# 还有更多...

`Boost.Optional`类不使用动态分配，也不需要基础类型的默认构造函数。当前的`boost::optional`实现可以使用 C++11 的右值引用，但不能在 constexpr 中使用。

如果你有一个类`T`，它没有空状态，但你的程序逻辑需要一个空状态或未初始化的`T`，那么你必须想出一些解决方法。传统上，用户会创建一些指向类`T`的智能指针，在其中保留一个`nullptr`，并在需要非空状态时动态分配`T`。别这样做！使用`boost::optional<T>`。这是一个更快、更可靠的解决方案。

C++17 标准包括`std::optional`类。只需将`<boost/optional.hpp>`替换为`<optional>`，将`boost::`替换为`std::`即可使用此类的标准版本。`std::optional`可在 constexpr 中使用。

# 另请参阅

Boost 的官方文档包含了更多例子，并描述了`Boost.Optional`的高级特性（比如就地构造）。文档可在以下链接找到：[`boost.org/libs/optional.`](http://www.boost.org/libs/optional)

# 从函数返回数组

让我们来玩一个猜谜游戏！你能从以下函数中得出什么？

```cpp
char* vector_advance(char* val); 
```

返回值是否应该由程序员释放？函数是否尝试释放输入参数？输入参数是否应该以零结尾，还是函数应该假定输入参数具有指定的宽度？

现在，让我们让任务更加困难！看看以下行：

```cpp
char ( &vector_advance( char (&val)[4] ) )[4];
```

不用担心。在弄清楚这里发生了什么之前，我也曾经思考了半个小时。`vector_advance`是一个接受并返回四个元素的数组的函数。有没有办法清晰地编写这样的函数？

# 准备工作

这个配方只需要基本的 C++知识。

# 如何做...

我们可以这样重写函数：

```cpp
#include <boost/array.hpp>

typedef boost::array<char, 4> array4_t;
array4_t& vector_advance(array4_t& val);
```

在这里，`boost::array<char, 4>`只是一个围绕四个`char`元素的数组的简单包装器。

这段代码回答了我们第一个例子中的所有问题，并且比第二个例子中的代码更易读。

# 工作原理...

`boost::array`是一个固定大小的数组。`boost::array`的第一个模板参数是元素类型，第二个是数组的大小。如果需要在运行时更改数组大小，可以使用`std::vector`、`boost::container::small_vector`、`boost::container::stack_vector`或`boost::container::vector`。

`boost::array<>`类没有手写的构造函数，所有成员都是公共的，因此编译器会将其视为 POD 类型。

# 还有更多...

让我们看一些更多关于`boost::array`的用法的例子：

```cpp
#include <boost/array.hpp> 
#include <algorithm> 

typedef boost::array<char, 4> array4_t; 

array4_t& vector_advance(array4_t& val) {
    // C++11 lambda function
    const auto inc = [](char& c){ ++c; };

    // boost::array has begin(), cbegin(), end(), cend(),
    // rbegin(), size(), empty() and other functions that are
    // common for standard library containers.
    std::for_each(val.begin(), val.end(), inc);
    return val;
}

int main() { 
    // We can initialize boost::array just like an array in C++11: 
    // array4_t val = {0, 1, 2, 3}; 
    // but in C++03 additional pair of curly brackets is required. 
    array4_t val = {{0, 1, 2, 3}}; 

    array4_t val_res;               // it is default constructible
    val_res = vector_advance(val);  // it is assignable

    assert(val.size() == 4); 
    assert(val[0] == 1); 
    /*val[4];*/ // Will trigger an assert because max index is 3 

    // We can make this assert work at compile-time. 
    // Interested? See recipe 'Check sizes at compile-time' 
    assert(sizeof(val) == sizeof(char) * array4_t::static_size); 
} 
```

`boost::array`最大的优势之一是它不分配动态内存，并且提供与普通 C 数组完全相同的性能。C++标准委员会的人员也很喜欢它，因此它被接受为 C++11 标准。尝试包含`<array>`头文件，并检查`std::array`的可用性。`std::array`自 C++17 以来对 constexpr 的使用支持更好。

# 参见

+   Boost 的官方文档提供了`Boost.Array`方法的完整列表，包括方法的复杂性和抛出行为的描述。可以在以下链接找到：[`boost.org/libs/array.`](http://www.boost.org/libs/array)

+   `boost::array`函数在许多配方中被广泛使用；例如，参考*将值绑定为函数参数*配方。

# 将多个值组合成一个

对于那些喜欢`std::pair`的人来说，这是一个非常好的礼物。Boost 有一个名为`Boost.Tuple`的库。它就像`std::pair`，但也可以处理三元组、四元组甚至更大的类型集合。

# 准备工作

此配方只需要基本的 C++知识和标准库。

# 如何做...

执行以下步骤将多个值组合成一个：

1.  要开始使用元组，您需要包含适当的头文件并声明一个变量：

```cpp
#include <boost/tuple/tuple.hpp> 
#include <string> 

boost::tuple<int, std::string> almost_a_pair(10, "Hello");
boost::tuple<int, float, double, int> quad(10, 1.0f, 10.0, 1);
```

1.  通过`boost::get<N>()`函数实现获取特定值，其中`N`是所需值的基于零的索引：

```cpp
#include <boost/tuple/tuple.hpp>

void sample1() {
    const int i = boost::get<0>(almost_a_pair); 
    const std::string& str = boost::get<1>(almost_a_pair); 
    const double d = boost::get<2>(quad);
}
```

`boost::get<>`函数有许多重载，在 Boost 中被广泛使用。我们已经看到它如何与其他库一起在*将多个选择的类型存储在容器/变量中*配方中使用。

1.  您可以使用`boost::make_tuple()`函数构造元组，这样写起来更短，因为不需要完全限定元组类型：

```cpp
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <set>

void sample2() {
    // Tuple comparison operators are
    // defined in header "boost/tuple/tuple_comparison.hpp"
    // Don't forget to include it!
    std::set<boost::tuple<int, double, int> > s;
    s.insert(boost::make_tuple(1, 1.0, 2));
    s.insert(boost::make_tuple(2, 10.0, 2));
    s.insert(boost::make_tuple(3, 100.0, 2));

    // Requires C++11
    const auto t = boost::make_tuple(0, -1.0, 2);
    assert(2 == boost::get<2>(t));
    // We can make a compile time assert for type
    // of t. Interested? See chapter 'Compile time tricks'
}
```

1.  另一个使生活更轻松的函数是`boost::tie()`。它几乎与`make_tuple`一样工作，但为传递的每种类型添加了一个非 const 引用。这样的元组可以用于从另一个元组中获取值到变量。可以从以下示例更好地理解：

```cpp
#include <boost/tuple/tuple.hpp>
#include <cassert>

void sample3() {
    boost::tuple<int, float, double, int> quad(10, 1.0f, 10.0, 1); 
    int i; 
    float f; 
    double d; 
    int i2; 

    // Passing values from 'quad' variables 
    // to variables 'i', 'f', 'd', 'i2'.
    boost::tie(i, f, d, i2) = quad; 
    assert(i == 10); 
    assert(i2 == 1); 
}
```

# 它是如何工作的...

一些读者可能会想知道为什么我们需要元组，当我们总是可以编写自己的结构并使用更好的名称；例如，我们可以创建一个结构，而不是写`boost::tuple<int, std::string>`：

```cpp
struct id_name_pair { 
    int id; 
    std::string name; 
}; 
```

嗯，这个结构肯定比`boost::tuple<int, std::string>`更清晰。元组库的主要思想是简化模板编程。

# 还有更多...

元组的工作速度与`std::pair`一样快（它不在堆上分配内存，也没有虚函数）。C++委员会发现这个类非常有用，因此它被包含在标准库中。您可以在头文件`<tuple>`中找到与 C++11 兼容的实现（不要忘记用`std::`替换所有`boost::`命名空间）。

元组的标准库版本必须具有多个微优化，并通常提供略好的用户体验。但是，不能保证元组元素的构造顺序，因此，如果需要一个从第一个元素开始构造其元素的元组，必须使用`boost::tuple`：

```cpp
#include <boost/tuple/tuple.hpp>
#include <iostream>

template <int I>
struct printer {
    printer() { std::cout << I; }
};

int main() {
    // Outputs 012
    boost::tuple<printer<0>, printer<1>, printer<2> > t;
}
```

当前的 Boost 元组实现不使用可变模板，不支持右值引用，不支持 C++17 结构化绑定，并且不支持 constexpr。

# 参见

+   Boost 的官方文档包含了更多关于`Boost.Tuple`的示例、性能信息和能力。可以在以下链接找到：[`boost.org/libs/tuple`](http://www.boost.org/libs/tuple)。

+   在第八章的*元编程*中，*将所有元组元素转换为字符串*配方展示了元组的一些高级用法。

# 绑定和重新排序函数参数

如果您经常使用标准库并使用`<algorithm>`头文件，那么您肯定会编写很多功能对象。在 C++14 中，您可以使用通用 lambda 来实现。在 C++11 中，您只能使用非通用 lambda。在较早版本的 C++标准中，您可以使用适配器函数（如`bind1st`、`bind2nd`、`ptr_fun`、`mem_fun`、`mem_fun_ref`），或者您可以手动编写它们（因为适配器函数看起来很可怕）。好消息是：`Boost.Bind`可以代替丑陋的适配器函数，并提供更易读的语法。

# 准备工作

熟悉标准库函数和算法将会有所帮助。

# 如何做...

让我们看一些使用`Boost.Bind`与 C++11 lambda 类的例子：

1.  所有示例都需要以下头文件：

```cpp
// Contains boost::bind and placeholders.
#include <boost/bind.hpp>

// Utility stuff required by samples.
#include <boost/array.hpp>
#include <algorithm>
#include <functional>
#include <string>
#include <cassert>
```

1.  按照以下代码显示的方式计算大于 5 的值：

```cpp
void sample1() {
    const boost::array<int, 12> v = {{
        1, 2, 3, 4, 5, 6, 7, 100, 99, 98, 97, 96
    }};

    const std::size_t count0 = std::count_if(v.begin(), v.end(),
        [](int x) { return 5 < x; }
    );
    const std::size_t count1 = std::count_if(v.begin(), v.end(), 
        boost::bind(std::less<int>(), 5, _1)
    ); 
    assert(count0 == count1); 
}
```

1.  这是我们如何计算空字符串的方法：

```cpp
void sample2() {
    const boost::array<std::string, 3> v = {{
        "We ", "are", " the champions!"
    }}; 

    const std::size_t count0 = std::count_if(v.begin(), v.end(),
        [](const std::string& s) { return s.empty(); }
    );
    const std::size_t count1 = std::count_if(v.begin(), v.end(), 
        boost::bind(&std::string::empty, _1)
    ); 
    assert(count0 == count1); 
} 
```

1.  现在，让我们计算长度小于`5`的字符串：

```cpp
void sample3() {
    const boost::array<std::string, 3> v = {{
        "We ", "are", " the champions!"
    }};

    const std::size_t count0 = std::count_if(v.begin(), v.end(), 
        [](const std::string& s) {  return s.size() < 5; }
    ); 
    const std::size_t count1 = std::count_if(v.begin(), v.end(), 
        boost::bind(
            std::less<std::size_t>(),
            boost::bind(&std::string::size, _1),
            5
        )
    ); 
    assert(count0 == count1);  
} 
```

1.  比较字符串：

```cpp
void sample4() {
    const boost::array<std::string, 3> v = {{
        "We ", "are", " the champions!"
    }}; 
    std::string s(
        "Expensive copy constructor is called when binding"
    );

    const std::size_t count0 = std::count_if(v.begin(), v.end(),
        &s {  return x < s; }
    ); 
    const std::size_t count1 = std::count_if(v.begin(), v.end(), 
        boost::bind(std::less<std::string>(), _1, s)
    ); 
    assert(count0 == count1); 
} 
```

# 它是如何工作的...

`boost::bind`函数返回一个存储绑定值的功能对象，以及原始功能对象的副本。当实际调用`operator()`时，存储的参数将与调用时传递的参数一起传递给原始功能对象。

# 还有更多...

看一下之前的例子。当我们绑定值时，我们将一个值复制到一个函数对象中。对于一些类来说，这个操作是昂贵的。有没有办法避免复制？

是的，有！`Boost.Ref`库将在这里帮助我们！它包含两个函数，`boost::ref()`和`boost::cref()`，第一个允许我们将参数作为引用传递，第二个将参数作为常量引用传递。`ref()`和`cref()`函数只是构造了一个`reference_wrapper<T>`或`reference_wrapper<const T>`类型的对象，它们可以隐式转换为引用类型。让我们改变我们的最后一些例子：

```cpp
#include <boost/ref.hpp> 

void sample5() {
    const boost::array<std::string, 3> v = {{
        "We ", "are", " the champions!"
    }}; 
    std::string s(
        "Expensive copy constructor is NOT called when binding"
    );  

    const std::size_t count1 = std::count_if(v.begin(), v.end(), 
        boost::bind(std::less<std::string>(), _1, boost::cref(s))
    ); 
    // ...
} 
```

您还可以使用`bind`重新排序、忽略和复制函数参数：

```cpp
void sample6() {
    const auto twice = boost::bind(std::plus<int>(), _1, _1);
    assert(twice(2) == 4);

    const auto minus_from_second = boost::bind(std::minus<int>(), _2, _1);
    assert(minus_from_second(2, 4) == 2);

    const auto sum_second_and_third = boost::bind(
        std::plus<int>(), _2, _3
    );
    assert(sum_second_and_third(10, 20, 30) == 50);
}
```

`ref`、`cref`和`bind`函数被 C++11 标准接受，并在`std::`命名空间的`<functional>`头文件中定义。所有这些函数都不会动态分配内存，也不会使用虚函数。它们返回的对象易于优化，适用于良好的编译器。

这些函数的标准库实现可能具有额外的优化，以减少编译时间或仅仅是特定于编译器的优化。您可以使用`bind`、`ref`、`cref`函数的标准库版本与任何 Boost 库一起使用，甚至混合使用 Boost 和标准库版本。

如果您使用的是 C++14 编译器，那么请使用通用 lambda 代替`std::bind`和`boost::bind`，因为它们更不晦涩，更容易理解。C++17 的 lambda 可以与 constexpr 一起使用，而`std::bind`和`boost::bind`不行。

# 另请参阅

官方文档包含更多示例和高级功能的描述，网址为[`boost.org/libs/bind.`](http://www.boost.org/libs/bind)

# 获取可读的类型名称

通常需要在运行时获取可读的类型名称：

```cpp
#include <iostream>
#include <typeinfo>

template <class T>
void do_something(const T& x) {
    if (x == 0) {
        std::cout << "Error: x == 0\. T is " << typeid(T).name() 
        << std::endl;
    }
    // ...
}
```

然而，之前的例子并不是很通用。当禁用 RTTI 时，它无法工作，并且并不总是产生一个漂亮的可读名称。在一些平台上，之前的代码将只输出`i`或`d`。

如果我们需要一个不带`const`、`volatile`和引用的类型名称，情况会变得更糟：

```cpp
void sample1() {
    auto&& x = 42;
    std::cout << "x is "
              << typeid(decltype(x)).name()
              << std::endl;
}
```

不幸的是，前面的代码在最好的情况下输出`int`，这不是我们期望的结果。

# 准备工作

这个配方需要对 C++有基本的了解。

# 如何做

在第一种情况下，我们需要一个不带限定符的可读类型名称。`Boost.TypeIndex`库将帮助我们：

```cpp
#include <iostream>
#include <boost/type_index.hpp>

template <class T>
void do_something_again(const T& x) {
    if (x == 0) {
        std::cout << "x == 0\. T is " << boost::typeindex::type_id<T>()
                  << std::endl;
    }
    // ...
}
```

在第二种情况下，我们需要保留限定符，因此我们需要从同一库中调用一个略有不同的函数：

```cpp
#include <boost/type_index.hpp>

void sample2() {
    auto&& x = 42;
    std::cout << "x is "
              << boost::typeindex::type_id_with_cvr<decltype(x)>()
              << std::endl;
}
```

# 它是如何工作的...

`Boost.TypeIndex`库为不同的编译器提供了许多解决方法，并且知道为类型生成可读名称的最有效方式。如果你将类型作为模板参数提供，该库保证所有可能的类型相关计算将在编译时执行，并且即使禁用了 RTTI，代码也能正常工作。

`boost::typeindex::type_id_with_cvr`中的`cvr`代表`const`、`volatile`和引用。这可以确保类型不会被衰减。

# 还有更多...

所有`boost::typeindex::type_id*`函数返回`boost::typeindex::type_index`的实例。它与`std::type_index`非常接近；另外，它还有一个`raw_name()`方法用于获取原始类型名称，以及一个`pretty_name()`用于获取可读的类型名称。

即使在 C++17 中，`std::type_index`和`std::type_info`返回的是平台特定的类型名称表示，而这些表示相当难以解码或在可移植性上使用。

与标准库的`typeid()`不同，`Boost.TypeIndex`的一些类可用于 constexpr。这意味着如果你使用特定的`boost::typeindex::ctti_type_index`类，你可以在编译时获取类型的文本表示。

用户可以使用`Boost.TypeIndex`库发明自己的 RTTI 实现。这对于嵌入式开发人员和需要针对特定类型进行极其高效的 RTTI 的应用程序非常有用。

# 另请参阅

高级特性和更多示例的文档可在[`boost.org/libs/type_index`](http://www.boost.org/libs/type_index)找到。

# 使用 C++11 移动模拟

C++11 标准的最大特点之一是右值引用。这个特性允许我们修改临时对象，从中窃取资源。你可以猜到，C++03 标准没有右值引用，但是使用`Boost.Move`库，你可以编写一个模拟它们的可移植代码。

# 准备就绪

强烈建议您至少熟悉 C++11 右值引用的基础知识。

# 如何做...

1.  假设你有一个类，其中包含多个字段，其中一些是标准库容器：

```cpp
namespace other { 
    class characteristics{}; 
} 

struct person_info {
    std::string name_; 
    std::string second_name_; 
    other::characteristics characteristic_; 
    // ...
}; 
```

1.  现在是时候为其添加移动赋值和移动构造函数了！只需记住，在 C++03 标准库中，容器既没有移动运算符也没有移动构造函数。

1.  移动赋值的正确实现与移动构造对象并与`this`交换的方式相同。移动构造函数的正确实现接近于默认构造和`swap`。因此，让我们从`swap`成员函数开始：

```cpp
#include <boost/swap.hpp> 

void person_info::swap(person_info& rhs) {
    name_.swap(rhs.name_);
    second_name_.swap(rhs.second_name_);
    boost::swap(characteristic_, rhs.characteristic_);
} 
```

1.  现在，在`private`部分放入以下宏：

```cpp
    BOOST_COPYABLE_AND_MOVABLE(person_info) 
```

1.  编写一个拷贝构造函数。

1.  编写一个拷贝赋值，参数为：`BOOST_COPY_ASSIGN_REF(person_info)`。

1.  编写一个`move`构造函数和一个移动赋值，参数为`BOOST_RV_REF(person_info)`：

```cpp
struct person_info {
    // Fields declared here
    // ...
private:
    BOOST_COPYABLE_AND_MOVABLE(person_info)
public:
    // For the simplicity of example we will assume that
    // person_info default constructor and swap are very
    // fast/cheap to call.
    person_info();

    person_info(const person_info& p)
        : name_(p.name_)
        , second_name_(p.second_name_)
        , characteristic_(p.characteristic_)
    {}

    person_info(BOOST_RV_REF(person_info) person) {
        swap(person);
    }

    person_info& operator=(BOOST_COPY_ASSIGN_REF(person_info) person) {
        person_info tmp(person);
        swap(tmp);
        return *this;
    }

    person_info& operator=(BOOST_RV_REF(person_info) person) {
        person_info tmp(boost::move(person));
        swap(tmp);
        return *this;
    }

    void swap(person_info& rhs);
};
```

1.  现在，我们有了`person_info`类的可移植快速实现的移动赋值和移动构造运算符。

# 工作原理...

以下是移动赋值的示例用法：

```cpp
int main() {
    person_info vasya;
    vasya.name_ = "Vasya";
    vasya.second_name_ = "Snow"; 

    person_info new_vasya(boost::move(vasya)); 
    assert(new_vasya.name_ == "Vasya"); 
    assert(new_vasya.second_name_ == "Snow"); 
    assert(vasya.name_.empty()); 
    assert(vasya.second_name_.empty()); 

    vasya = boost::move(new_vasya); 
    assert(vasya.name_ == "Vasya"); 
    assert(vasya.second_name_ == "Snow"); 
    assert(new_vasya.name_.empty()); 
    assert(new_vasya.second_name_.empty()); 
}
```

`Boost.Move`库的实现非常高效。当使用 C++11 编译器时，所有用于模拟右值的宏都会扩展为 C++11 特定的特性，否则（在 C++03 编译器上），右值将被模拟。

# 还有更多...

你注意到了`boost::swap`的调用吗？这是一个非常有用的实用函数，它首先在变量的命名空间中搜索`swap`函数（在我们的示例中是`other::`命名空间），如果没有匹配的交换函数，则使用`std::swap`。

# 另请参阅

+   有关模拟实现的更多信息可以在 Boost 网站上找到，并且在`Boost.Move`库的源代码中找到[`boost.org/libs/move`](http://www.boost.org/libs/move)。

+   `Boost.Utility`库包含`boost::swap`，并且拥有许多有用的函数和类。请参考[`boost.org/libs/utility`](http://www.boost.org/libs/utility)获取其文档。

+   在第二章的*通过派生类的成员初始化基类*食谱中，*管理资源*

+   *创建一个不可复制类*食谱。

+   在*创建一个不可复制但可移动的类*食谱中，有关`Boost.Move`的更多信息以及如何以便携和高效的方式在容器中使用可移动对象的一些示例。

# 创建一个不可复制的类

您几乎肯定遇到过某些情况，其中一个类拥有一些由于技术原因不能被复制的资源：

```cpp
class descriptor_owner { 
    void* descriptor_; 

public: 
    explicit descriptor_owner(const char* params); 

    ~descriptor_owner() { 
        system_api_free_descriptor(descriptor_); 
    } 
}; 
```

在前面的示例中，C++编译器生成了一个复制构造函数和一个赋值运算符，因此`descriptor_owner`类的潜在用户将能够创建以下糟糕的事情：

```cpp
void i_am_bad() {
    descriptor_owner d1("O_o");   
    descriptor_owner d2("^_^"); 

    // Descriptor of d2 was not correctly freed 
    d2 = d1; 

    // destructor of d2 will free the descriptor 
    // destructor of d1 will try to free already freed descriptor 
}
```

# 准备工作

这个食谱只需要非常基本的 C++知识。

# 如何做...

为了避免这种情况，发明了`boost::noncopyable`类。如果你从它派生自己的类，C++编译器将不会生成复制构造函数和赋值运算符：

```cpp
#include <boost/noncopyable.hpp> 

class descriptor_owner_fixed : private boost::noncopyable { 
    // ... 
```

现在，用户将无法做坏事：

```cpp
void i_am_good() {
    descriptor_owner_fixed d1("O_o"); 
    descriptor_owner_fixed d2("^_^"); 

    // Won't compile 
    d2 = d1; 

    // Won't compile either 
    descriptor_owner_fixed d3(d1); 
}
```

# 它是如何工作的...

一个经过精心雕琢的读者会注意到，我们可以通过以下方式实现完全相同的结果：

+   将`descriptor_owning_fixed`的复制构造函数和赋值运算符设为私有

+   定义它们而不实际实现

+   使用 C++11 语法`= delete;`显式删除它们

是的，你是正确的。根据你的编译器的能力，`boost::noncopyable`类选择了使类不可复制的最佳方式。

`boost::noncopyable`也可以作为您的类的良好文档。它永远不会引发诸如“复制构造函数体在其他地方定义吗？”或“它有一个非标准的复制构造函数（带有非 const 引用参数）吗？”等问题。

# 另请参阅

+   *创建一个不可复制但可移动的类*食谱将为您提供如何通过移动来允许在 C++03 中独占资源的想法

+   您可以在`Boost.Core`库的官方文档[`boost.org/libs/core`](http://boost.org/libs/core)中找到许多有用的函数和类

+   在第二章的*通过派生类的成员初始化基类*食谱中，*管理资源*

+   *使用 C++11 移动模拟*食谱

# 创建一个不可复制但可移动的类

现在，想象一下以下情况：我们有一个不能复制的资源，应该在析构函数中正确释放，并且我们希望从一个函数中返回它：

```cpp
descriptor_owner construct_descriptor() 
{ 
    return descriptor_owner("Construct using this string"); 
} 
```

实际上，你可以使用`swap`方法解决这种情况：

```cpp
void construct_descriptor1(descriptor_owner& ret) 
{ 
    descriptor_owner("Construct using this string").swap(ret); 
} 
```

然而，这样的变通方法不允许我们在容器中使用`descriptor_owner`。顺便说一句，这看起来很糟糕！

# 准备工作

强烈建议您至少熟悉 C++11 右值引用的基础知识。阅读*使用 C++11 移动模拟*食谱也是推荐的。

# 如何做...

那些使用 C++11 的读者已经知道移动唯一类（如`std::unique_ptr`或`std::thread`）。使用这种方法，我们可以创建一个仅移动的`descriptor_owner`类：

```cpp
class descriptor_owner1 {
    void* descriptor_;

public:
    descriptor_owner1()
        : descriptor_(nullptr)
    {}

    explicit descriptor_owner1(const char* param);

    descriptor_owner1(descriptor_owner1&& param)
        : descriptor_(param.descriptor_)
    {
        param.descriptor_ = nullptr;
    }

    descriptor_owner1& operator=(descriptor_owner1&& param) {
        descriptor_owner1 tmp(std::move(param));
        std::swap(descriptor_, tmp.descriptor_);
        return *this;
    }

    void clear() {
        free(descriptor_);
        descriptor_ = nullptr;
    }

    bool empty() const {
        return !descriptor_;
    }

    ~descriptor_owner1() {
        clear();
    }
};

// GCC compiles the following in C++11 and later modes.
descriptor_owner1 construct_descriptor2() {
    return descriptor_owner1("Construct using this string");
}

void foo_rv() {
    std::cout << "C++11n";
    descriptor_owner1 desc;
    desc = construct_descriptor2();
    assert(!desc.empty());
} 
```

这只适用于 C++11 兼容的编译器。这是`Boost.Move`的正确时机！让我们修改我们的示例，以便在 C++03 编译器上使用。

根据文档，要以便携的语法编写一个可移动但不可复制的类型，我们需要遵循这些简单的步骤：

1.  将`BOOST_MOVABLE_BUT_NOT_COPYABLE(classname)`宏放在`private`部分：

```cpp
#include <boost/move/move.hpp>

class descriptor_owner_movable {
    void* descriptor_;

    BOOST_MOVABLE_BUT_NOT_COPYABLE(descriptor_owner_movable
```

1.  编写一个移动构造函数和一个移动赋值，将参数作为`BOOST_RV_REF(classname)`：

```cpp
public:
    descriptor_owner_movable()
        : descriptor_(NULL)
    {}

    explicit descriptor_owner_movable(const char* param)
        : descriptor_(strdup(param))
    {}

    descriptor_owner_movable(
        BOOST_RV_REF(descriptor_owner_movable) param
    ) BOOST_NOEXCEPT
        : descriptor_(param.descriptor_)
    {
        param.descriptor_ = NULL;
    }

    descriptor_owner_movable& operator=(
        BOOST_RV_REF(descriptor_owner_movable) param) BOOST_NOEXCEPT
    {
        descriptor_owner_movable tmp(boost::move(param));
        std::swap(descriptor_, tmp.descriptor_);
        return *this;
    }

    // ...
};

descriptor_owner_movable construct_descriptor3() {
    return descriptor_owner_movable("Construct using this string");
} 
```

# 它是如何工作的...

现在，我们有一个可移动的，但不可复制的类，即使在 C++03 编译器和`Boost.Containers`中也可以使用：

```cpp
#include <boost/container/vector.hpp> 
#include <your_project/descriptor_owner_movable.h>

int main() {
    // Following code will work on C++11 and C++03 compilers 
    descriptor_owner_movable movable; 
    movable = construct_descriptor3(); 
    boost::container::vector<descriptor_owner_movable> vec; 
    vec.resize(10); 
    vec.push_back(construct_descriptor3()); 

    vec.back() = boost::move(vec.front()); 
}
```

很不幸，C++03 标准库容器仍然无法使用它（这就是为什么我们在前面的示例中使用了来自`Boost.Containers`的 vector）。

# 还有更多...

如果您想在 C++03 编译器上使用`Boost.Containers`，但在 C++11 编译器上使用标准库容器，您可以使用以下简单技巧。将以下内容的头文件添加到您的项目中：

```cpp
// your_project/vector.hpp 
// Copyright and other stuff goes here 

// include guards 
#ifndef YOUR_PROJECT_VECTOR_HPP 
#define YOUR_PROJECT_VECTOR_HPP 

// Contains BOOST_NO_CXX11_RVALUE_REFERENCES macro.
#include <boost/config.hpp>

#if !defined(BOOST_NO_CXX11_RVALUE_REFERENCES) 
// We do have rvalues 
#include <vector> 

namespace your_project_namespace { 
  using std::vector; 
} // your_project_namespace 

#else 
// We do NOT have rvalues 
#include <boost/container/vector.hpp> 

namespace your_project_namespace { 
  using boost::container::vector; 
} // your_project_namespace 

#endif // !defined(BOOST_NO_CXX11_RVALUE_REFERENCES) 
#endif // YOUR_PROJECT_VECTOR_HPP 
```

现在，您可以包含`<your_project/vector.hpp>`并使用命名空间`your_project_namespace`中的向量：

```cpp
int main() {
    your_project_namespace::vector<descriptor_owner_movable> v; 
    v.resize(10); 
    v.push_back(construct_descriptor3()); 
    v.back() = boost::move(v.front()); 
}
```

但是，要注意编译器和标准库实现特定的问题！例如，只有在 GCC 4.7 的 C++11 模式下，如果您使用`noexcept`或`BOOST_NOECEPT`标记移动构造函数、析构函数和移动赋值运算符，此代码才会编译。

# 参见

+   第十章中的*C++11 中减少代码大小和增加用户定义类型性能*食谱提供了有关`noexcept`和`BOOST_NOEXCEPT`的更多信息。

+   有关`Boost.Move`的更多信息可以在 Boost 的网站上找到[`boost.org/libs/move.`](http://www.boost.org/libs/move)

# 使用 C++14 和 C++11 算法

C++11 在`<algorithm>`头文件中有一堆新的酷算法。C++14 有更多的算法。如果您被困在 C++11 之前的编译器上，您必须从头开始编写这些算法。例如，如果您希望输出从 65 到 125 的字符编码点，您必须在 C++11 之前的编译器上编写以下代码：

```cpp
#include <boost/array.hpp>

boost::array<unsigned char, 60> chars_65_125_pre11() {
    boost::array<unsigned char, 60> res;

    const unsigned char offset = 65;
    for (std::size_t i = 0; i < res.size(); ++i) {
        res[i] = i + offset;
    }

    return res;
}
```

# 准备工作

本食谱需要基本的 C++知识以及对`Boost.Array`库的基本了解。

# 如何做...

`Boost.Algorithm`库具有所有新的 C++11 和 C++14 算法。使用它，您可以按照以下方式重写前面的示例：

```cpp
#include <boost/algorithm/cxx11/iota.hpp>
#include <boost/array.hpp>

boost::array<unsigned char, 60> chars_65_125() {
    boost::array<unsigned char, 60> res;
    boost::algorithm::iota(res.begin(), res.end(), 65);
    return res;
}
```

# 工作原理...

您可能已经知道，`Boost.Algorithm`为每个算法都有一个头文件。只需包含头文件并使用所需的函数。

# 还有更多...

拥有一个仅实现 C++标准算法的库是无聊的。那不是创新的；那不是 Boost 的方式！这就是为什么在`Boost.Algorithm`中，您可以找到不是 C++一部分的函数。例如，这里有一个将输入转换为十六进制表示的函数：

```cpp
#include <boost/algorithm/hex.hpp>
#include <iterator>
#include <iostream>

void to_hex_test1() {
    const std::string data = "Hello word";
    boost::algorithm::hex(
        data.begin(), data.end(),
        std::ostream_iterator<char>(std::cout)
    );
}
```

前面的代码输出如下：

```cpp
48656C6C6F20776F7264
```

更有趣的是，所有函数都有额外的重载，接受范围作为第一个参数，而不是两个迭代器。**Range**是**Ranges TS**的概念。具有`.begin()`和`.end()`函数的数组和容器满足范围概念。有了这个知识，前面的示例可以被缩短：

```cpp
#include <boost/algorithm/hex.hpp>
#include <iterator>
#include <iostream>

void to_hex_test2() {
    const std::string data = "Hello word";
    boost::algorithm::hex(
        data,
        std::ostream_iterator<char>(std::cout)
    );
}
```

C++17 将具有来自`Boost.Algorithm`的搜索算法。`Boost.Algorithm`库将很快扩展为具有新算法和 C++20 功能，如可用的 constexpr 算法。密切关注该库，因为有一天，它可能会为您正在处理的问题提供现成的解决方案。

# 参见

+   `Boost.Algorithm`的官方文档包含了所有函数的完整列表以及它们的简短描述，网址为[`boost.org/libs/algorithm`](http://boost.org/libs/algorithm)

+   在线尝试新算法：[`apolukhin.github.io/Boost-Cookbook`](http://apolukhin.github.io/Boost-Cookbook)


# 第二章：管理资源

在本章中，我们将涵盖以下主题：

+   管理不离开作用域的类的本地指针

+   对跨函数使用的类指针进行引用计数

+   管理不离开作用域的数组的本地指针

+   对跨函数使用的数组指针进行引用计数

+   在变量中存储任何功能对象

+   在变量中传递函数指针

+   在变量中传递 C++11 lambda 函数

+   指针的容器

+   在作用域退出时执行！

+   通过派生类的成员初始化基类

# 介绍

在本章中，我们将继续处理 Boost 库引入的数据类型，主要关注指针的处理。我们将看到如何轻松管理资源，如何使用能够存储任何功能对象、函数和 lambda 表达式的数据类型。阅读完本章后，你的代码将变得更加可靠，内存泄漏将成为历史。

# 管理不离开作用域的类的本地指针

有时，我们需要动态分配内存并在该内存中构造一个类。问题就出在这里。看一下以下代码：

```cpp
bool foo1() { 
    foo_class* p = new foo_class("Some data"); 

    const bool something_else_happened = some_function1(*p);  
    if (something_else_happened) { 
        delete p; 
        return false; 
    } 

    some_function2(p); 

    delete p; 
    return true; 
}
```

这段代码乍一看是正确的。但是，如果`some_function1()`或`some_function2()`抛出异常怎么办？在这种情况下，`p`不会被删除。让我们以以下方式修复它：

```cpp
bool foo2() { 
    foo_class* p = new foo_class("Some data"); 
    try { 
        const bool something_else_happened = some_function1(*p); 
        if (something_else_happened) { 
            delete p; 
            return false; 
        } 
       some_function2(p); 
    } catch (...) { 
        delete p; 
        throw; 
    } 
    delete p; 
    return true; 
}
```

现在代码是正确的，但是丑陋且难以阅读。我们能做得比这更好吗？

# 入门

需要对 C++的基本知识和异常期间代码行为有所了解。

# 如何做到这一点...

只需看一下`Boost.SmartPtr`库。有一个`boost::scoped_ptr`类可能会帮到你：

```cpp
#include <boost/scoped_ptr.hpp> 

bool foo3() { 
    const boost::scoped_ptr<foo_class> p(new foo_class("Some data")); 

    const bool something_else_happened = some_function1(*p); 
    if (something_else_happened) { 
       return false; 
    } 
    some_function2(p.get()); 
    return true; 
}
```

现在，资源不会泄漏，源代码也更清晰。

如果你可以控制`some_function2(foo_class*)`，你可能希望将其重写为接受`foo_class`的引用而不是指针。具有引用的接口比具有指针的接口更直观，除非你的公司有一个特殊的约定，即输出参数只能通过指针传递。

顺便说一句，`Boost.Move`还有一个`boost::movelib::unique_ptr`，你可以用它来代替`boost::scoped_ptr`：

```cpp
#include <boost/move/make_unique.hpp> 

bool foo3_1() { 
    const boost::movelib::unique_ptr<foo_class> p
        = boost::movelib::make_unique<foo_class>("Some data"); 

    const bool something_else_happened = some_function1(*p); 
    if (something_else_happened) { 
       return false; 
    } 
    some_function2(p.get()); 
    return true; 
}
```

# 它是如何工作的...

`boost::scoped_ptr<T>`和`boost::movelib::unique_ptr`是典型的**RAII**类。当抛出异常或变量超出作用域时，堆栈被展开并调用析构函数。在析构函数中，`scoped_ptr<T>`和`unique_ptr<T>`调用`delete`来删除它们存储的指针。因为这两个类默认调用`delete`，所以如果基类的析构函数是虚拟的，通过指向`base`类的指针持有`derived`类是安全的：

```cpp
#include <iostream>
#include <string>

struct base {
    virtual ~base(){}
};

class derived: public base {
    std::string str_;

public:
    explicit derived(const char* str)
        : str_(str)
    {}

    ~derived() /*override*/ {
        std::cout << "str == " << str_ << '\n';
    }
};

void base_and_derived() {
    const boost::movelib::unique_ptr<base> p1(
        boost::movelib::make_unique<derived>("unique_ptr")
    );

    const boost::scoped_ptr<base> p2(
        new derived("scoped_ptr")
    );
}
```

运行`base_and_derived()`函数将产生以下输出：

```cpp
str == scoped_ptr
str == unique_ptr
```

在 C++中，对象的析构函数是按照相反的构造顺序调用的。这就是为什么在`scoped_ptr`的析构函数之前调用了`unique_ptr`的析构函数。

`boost::scoped_ptr<T>`类模板既不可复制也不可移动。`boost::movelib::unique_ptr`类是一个只能移动的类，并且在 C++11 之前的编译器上使用移动模拟。这两个类都存储指向它们拥有的资源的指针，并且不要求`T`是一个完整类型（`T`可以被前向声明）。

有些编译器在删除不完整类型时不会发出警告，这可能导致难以检测的错误。幸运的是，Boost 类具有特定的编译时断言来处理这种情况。这使得`scoped_ptr`和`unique_ptr`非常适合实现**Pimpl**习惯用法：

```cpp
// In header file:
struct public_interface {
    // ...
private:
    struct impl; // Forward declaration.
    boost::movelib::unique_ptr<impl> impl_;
};
```

# 还有更多...

这些类非常快。编译器会将使用`scoped_ptr`和`unique_ptr`的代码优化为机器代码，与手动编写的内存管理代码相比，几乎没有额外的开销。

C++11 有一个`std::unique_ptr<T, D>`类，它独占资源，并且与`boost::movelib::unique_ptr<T, D>`的行为完全相同。

C++标准库没有`boost::scoped_ptr<T>`，但您可以使用`const std::unique_ptr<T>`代替。唯一的区别是`boost::scoped_ptr<T>`仍然可以调用`reset()`，而`const std::unique_ptr<T>`不行。

# 另请参阅

+   `Boost.SmartPtr`库的文档包含了许多关于所有智能指针类的示例和其他有用信息。您可以在[`boost.org/libs/smart_ptr`](http://boost.org/libs/smart_ptr)上阅读有关它们的信息。

+   如果您使用`boost::movelib::unique_ptr`进行移动模拟，`Boost.Move`文档可能会帮助您[`boost.org/libs/move`](http://boost.org/libs/move)。

# 跨函数使用的类指针的引用计数

假设您有一些包含数据的动态分配的结构，并且您希望在不同的执行线程中处理它。要执行此操作的代码如下：

```cpp
#include <boost/thread.hpp> 
#include <boost/bind.hpp> 

void process1(const foo_class* p); 
void process2(const foo_class* p); 
void process3(const foo_class* p); 

void foo1() { 
    while (foo_class* p = get_data()) // C way 
    { 
        // There will be too many threads soon, see 
        // recipe 'Parallel execution of different tasks' 
        // for a good way to avoid uncontrolled growth of threads 
        boost::thread(boost::bind(&process1, p)) 
            .detach(); 
        boost::thread(boost::bind(&process2, p)) 
            .detach(); 
        boost::thread(boost::bind(&process3, p)) 
            .detach(); 

        // delete p; Oops!!!! 
    } 
}
```

我们不能在`while`循环结束时释放`p`，因为它仍然可以被运行`process`函数的线程使用。这些`process`函数不能删除`p`，因为它们不知道其他线程不再使用它。

# 准备工作

此示例使用`Boost.Thread`库，这不是一个仅头文件的库。您的程序必须链接到`boost_thread`、`boost_chrono`和`boost_system`库。在继续阅读之前，请确保您了解线程的概念。有关描述线程的配方的参考，请参阅*另请参阅*部分。

您还需要对`boost::bind`或`std::bind`有一些基本的了解，它们几乎是一样的。

# 如何做...

正如您可能已经猜到的，Boost（和 C++11）中有一个类可以帮助您解决这个问题。它被称为`boost::shared_ptr`。可以按以下方式使用：

```cpp
#include <boost/shared_ptr.hpp> 

void process_sp1(const boost::shared_ptr<foo_class>& p); 
void process_sp2(const boost::shared_ptr<foo_class>& p); 
void process_sp3(const boost::shared_ptr<foo_class>& p); 

void foo2() { 
    typedef boost::shared_ptr<foo_class> ptr_t; 
    ptr_t p; 
    while (p = ptr_t(get_data())) // C way 
    { 
        boost::thread(boost::bind(&process_sp1, p)) 
            .detach(); 
        boost::thread(boost::bind(&process_sp2, p)) 
            .detach(); 
        boost::thread(boost::bind(&process_sp3, p)) 
            .detach(); 

        // no need to anything 
    } 
}
```

另一个例子如下：

```cpp
#include <string> 
#include <boost/smart_ptr/make_shared.hpp> 

void process_str1(boost::shared_ptr<std::string> p); 
void process_str2(const boost::shared_ptr<std::string>& p); 

void foo3() { 
    boost::shared_ptr<std::string> ps = boost::make_shared<std::string>( 
        "Guess why make_shared<std::string> " 
        "is faster than shared_ptr<std::string> " 
        "ps(new std::string('this string'))" 
    ); 

    boost::thread(boost::bind(&process_str1, ps)) 
            .detach(); 
    boost::thread(boost::bind(&process_str2, ps)) 
            .detach(); 
}
```

# 它是如何工作的...

`shared_ptr`类内部有一个原子引用计数器。当您复制它时，引用计数会增加，当调用其`析构函数`时，引用计数会减少。当引用计数等于零时，将为`shred_ptr`指向的对象调用`delete`。

现在，让我们看看在`boost::thread (boost::bind(&process_sp1, p))`的情况下发生了什么。函数`process_sp1`以引用参数作为参数，那么当我们退出`while`循环时为什么它不会被释放？答案很简单。`bind()`返回的函数对象包含`shared`指针的副本，这意味着`p`指向的数据直到函数对象被销毁才会被释放。函数对象被复制到线程中，并在线程执行时保持活动状态。

回到`boost::make_shared`，让我们看看`shared_ptr<std::string> ps(new int(0))`。在这种情况下，我们有两个调用`new`：

+   通过`new int(0)`构造一个指向整数的指针

+   在构造`shared_ptr`类内部引用计数器分配在堆上

使用`make_shared<T>`只需一次调用`new`。`make_shared<T>`分配一个单一的内存块，并在该内存块中构造原子计数器和`T`对象。

# 还有更多...

原子引用计数器保证了`shared_ptr`在线程之间的正确行为，但您必须记住原子操作不如非原子操作快。`shared_ptr`在赋值、复制构造和未移动的`shared_ptr`销毁时会触及原子变量。这意味着在兼容 C++11 的编译器上，您可以尽可能使用移动构造和移动赋值来减少原子操作的次数。如果您不打算再使用`p`变量，只需使用`shared_ptr<T> p1(std::move(p))`。如果您不打算修改指向的值，建议将其设置为`const`。只需将`const`添加到智能指针的模板参数中，编译器将确保您不会修改内存：

```cpp
void process_cstr1(boost::shared_ptr<const std::string> p);
void process_cstr2(const boost::shared_ptr<const std::string>& p);

void foo3_const() {
    boost::shared_ptr<const std::string> ps
        = boost::make_shared<const std::string>(
            "Some immutable string"
        );

    boost::thread(boost::bind(&process_cstr1, ps))
            .detach();
    boost::thread(boost::bind(&process_cstr2, ps))
            .detach();

    // *ps = "qwe"; // Compile time error, string is const!
}
```

对`const`感到困惑？以下是智能指针 constness 到简单指针 constness 的映射：

| `shared_ptr<T>` | `T*`  |
| --- | --- |
| `shared_ptr<const T>` | `const T*`  |
| `const shared_ptr<T>` | `T* const` |
| `const shared_ptr<const T>` | `const T* const` |

`shared_ptr`调用和`make_shared`函数是 C++11 的一部分，它们在`std::`命名空间的头文件`<memory>`中声明。它们几乎具有与 Boost 版本相同的特性。

# 另请参阅

+   有关`Boost.Thread`和原子操作的更多信息，请参阅第五章*，* *多线程*。

+   有关如何绑定和重新排序函数参数的信息，请参阅第一章的*开始编写您的应用程序*中的*绑定和重新排序函数参数*食谱，了解更多关于`Boost.Bind`的信息。

+   有关如何将`shared_ptr<U>`转换为`shared_ptr<T>`的信息，请参阅第三章的*转换智能指针*。

+   `Boost.SmartPtr`库的文档包含了许多关于所有智能指针类的示例和其他有用信息。请参阅链接[`boost.org/libs/smart_ptr`](http://boost.org/libs/smart_ptr)了解相关内容。

# 管理不离开作用域的数组指针

我们已经看到如何在*管理不离开作用域的类的指针*食谱中管理指向资源的指针。但是，当我们处理数组时，我们需要调用`delete[]`而不是简单的`delete`。否则，将会发生内存泄漏。请看下面的代码：

```cpp
void may_throw1(char ch); 
void may_throw2(const char* buffer); 

void foo() { 
    // we cannot allocate 10MB of memory on stack, 
    // so we allocate it on heap 
    char* buffer = new char[1024 * 1024 * 10]; 

    // Oops. Here comes some code, that may throw.
    // It was a bad idea to use raw pointer as the memory may leak!!
    may_throw1(buffer[0]); 
    may_throw2(buffer); 

    delete[] buffer; 
}
```

# 准备就绪

此食谱需要了解 C++异常和模板的知识。

# 如何做...

`Boost.SmartPointer`库不仅有`scoped_ptr<>`类，还有`scoped_array<>`类：

```cpp
#include <boost/scoped_array.hpp> 

void foo_fixed() { 
    // We allocate array on heap 
    boost::scoped_array<char> buffer(new char[1024 * 1024 * 10]); 

    // Here comes some code, that may throw, 
    // but now exception won't cause a memory leak 
    may_throw1(buffer[0]); 
    may_throw2(buffer.get()); 

    // destructor of 'buffer' variable will call delete[] 
}
```

`Boost.Move`库的`boost::movelib::unique_ptr<>`类也可以与数组一起使用。您只需要在模板参数的末尾提供`[]`来指示它存储的是数组。

```cpp
#include <boost/move/make_unique.hpp> 

void foo_fixed2() { 
    // We allocate array on heap 
    const boost::movelib::unique_ptr<char[]> buffer 
        = boost::movelib::make_unique<char[]>(1024 * 1024 * 10); 

    // Here comes some code, that may throw, 
    // but now exception won't cause a memory leak 
    may_throw1(buffer[0]); 
    may_throw2(buffer.get()); 

    // destructor of 'buffer' variable will call delete[] 
}
```

# 工作原理...

`scoped_array<>`的工作原理与`scoped_ptr<>`类完全相同，但在析构函数中调用`delete[]`而不是`delete`。`unique_ptr<T[]>`也是这样做的。

# 还有更多...

`scoped_array<>`类与`scoped_ptr<>`具有相同的保证和设计。它既没有额外的内存分配，也没有虚函数的调用。它不能被复制，也不是 C++11 的一部分。`std::unique_ptr<T[]>`是 C++11 的一部分，具有与`boost::movelib::unique_ptr<T[]>`类相同的保证和性能。

实际上，`make_unique<char[]>(1024)`与`new char[1024]`不同，因为第一个进行值初始化，而第二个进行默认初始化。默认初始化的等效函数是`boost::movelib::make_unique_definit`。

请注意，Boost 版本也可以在 C++11 之前的编译器上工作，甚至在这些编译器上模拟 rvalues，使`boost::movelib::unique_ptr`成为仅移动类型。如果您的标准库没有提供`std::make_unique`，那么`Boost.SmartPtr`可能会帮助您。它提供了`boost::make_unique`，在头文件`boost/smart_ptr/make_unique.hpp`中返回一个`std::unique_ptr`。它还提供了`boost::make_unique_noinit`，用于在相同的头文件中进行默认初始化。C++17 没有`make_unique_noinit`函数。

在 C++中使用`new`进行内存分配和手动内存管理是一种不好的习惯。尽可能使用`make_unique`和`make_shared`函数。

# 另请参阅

+   `Boost.SmartPtr`库的文档包含了许多关于所有智能指针类的示例和其他有用信息，您可以在[`boost.org/libs/smart_ptr.`](http://boost.org/libs/smart_ptr)上阅读相关内容。

+   如果您希望使用`boost::movelib::unique_ptr`进行移动模拟，`Boost.Move`文档可能会对您有所帮助，请阅读[`boost.org/libs/move.`](http://boost.org/libs/move) [﻿](http://boost.org/libs/move)

# 引用计数的指向跨函数使用的数组的指针

我们继续处理指针，我们的下一个任务是对数组进行引用计数。让我们看一下从流中获取一些数据并在不同的线程中处理它的程序。代码如下：

```cpp
#include <cstring> 
#include <boost/thread.hpp> 
#include <boost/bind.hpp> 

void do_process(const char* data, std::size_t size); 

void do_process_in_background(const char* data, std::size_t size) { 
    // We need to copy data, because we do not know, 
    // when it will be deallocated by the caller.
    char* data_cpy = new char[size]; 
    std::memcpy(data_cpy, data, size); 

    // Starting thread of execution to process data.
    boost::thread(boost::bind(&do_process, data_cpy, size)) 
            .detach(); 
    boost::thread(boost::bind(&do_process, data_cpy, size)) 
            .detach();

    // Oops!!! We cannot delete[] data_cpy, because 
    // do_process() function may still work with it.
}
```

与*跨函数使用类指针的引用计数*示例中发生的相同问题。

# 准备工作

这个示例使用了`Boost.Thread`库，这不是一个仅包含头文件的库，所以你的程序需要链接`boost_thread`、`boost_chrono`和`boost_system`库。在继续阅读之前，请确保你理解了线程的概念。

你还需要一些关于`boost::bind`或`std::bind`的基本知识，它们几乎是一样的。

# 如何做...

有四种解决方案。它们之间的主要区别在于`data_cpy`变量的类型和构造方式。所有这些解决方案都完全做了本示例开头描述的相同的事情，但没有内存泄漏。这些解决方案如下：

+   第一个解决方案适用于在编译时已知数组大小的情况：

```cpp
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>

template <std::size_t Size>
void do_process_shared(const boost::shared_ptr<char[Size]>& data);

template <std::size_t Size>
void do_process_in_background_v1(const char* data) {
    // Same speed as in 'First solution'.
    boost::shared_ptr<char[Size]> data_cpy
        = boost::make_shared<char[Size]>();
    std::memcpy(data_cpy.get(), data, Size);

    // Starting threads of execution to process data.
    boost::thread(boost::bind(&do_process_shared<Size>, data_cpy))
            .detach();
    boost::thread(boost::bind(&do_process_shared<Size>, data_cpy))
            .detach();

    // data_cpy destructor will deallocate data when
    // reference count is zero.
}
```

+   自 Boost 1.53 以来，`shared_ptr`本身可以处理未知大小的数组。第二个解决方案：

```cpp
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>

void do_process_shared_ptr(
        const boost::shared_ptr<char[]>& data,
        std::size_t size);

void do_process_in_background_v2(const char* data, std::size_t size) {
    // Faster than 'First solution'.
    boost::shared_ptr<char[]> data_cpy = boost::make_shared<char[]>(size);
    std::memcpy(data_cpy.get(), data, size);

    // Starting threads of execution to process data.
    boost::thread(boost::bind(&do_process_shared_ptr, data_cpy, size))
            .detach();
    boost::thread(boost::bind(&do_process_shared_ptr, data_cpy, size))
            .detach();

    // data_cpy destructor will deallocate data when
    // reference count is zero.
}
```

+   第三个解决方案：

```cpp
#include <boost/shared_ptr.hpp>

void do_process_shared_ptr2(
        const boost::shared_ptr<char>& data,
        std::size_t size);

void do_process_in_background_v3(const char* data, std::size_t size) {
    // Same speed as in 'First solution'.
    boost::shared_ptr<char> data_cpy(
                new char[size],
                boost::checked_array_deleter<char>()
    );
    std::memcpy(data_cpy.get(), data, size);

    // Starting threads of execution to process data.
    boost::thread(boost::bind(&do_process_shared_ptr2, data_cpy, size))
            .detach();
    boost::thread(boost::bind(&do_process_shared_ptr2, data_cpy, size))
            .detach();

    // data_cpy destructor will deallocate data when
    // reference count is zero.
}
```

+   最后一个解决方案自 Boost 1.65 以来已经被弃用，但在古老的 Boost 版本中可能会有用：

```cpp
#include <boost/shared_array.hpp>

void do_process_shared_array(
        const boost::shared_array<char>& data,
        std::size_t size);

void do_process_in_background_v4(const char* data, std::size_t size) {
    // We need to copy data, because we do not know, when it will be
    // deallocated by the caller.
    boost::shared_array<char> data_cpy(new char[size]);
    std::memcpy(data_cpy.get(), data, size);

    // Starting threads of execution to process data.
    boost::thread(
        boost::bind(&do_process_shared_array, data_cpy, size)
    ).detach();
    boost::thread(
        boost::bind(&do_process_shared_array, data_cpy, size)
    ).detach();

    // No need to call delete[] for data_cpy, because
    // data_cpy destructor will deallocate data when
    // reference count is zero.
}
```

# 它是如何工作的...

在所有示例中，**智能指针**类计算引用并在引用计数变为零时调用`delete[]`释放指针。第一个和第二个示例很简单。在第三个示例中，我们为`shared`指针提供了一个自定义的`deleter`对象。当智能指针决定释放资源时，智能指针的`deleter`对象被调用。当智能指针在没有显式`deleter`的情况下构造时，会构造默认的`deleter`，它根据智能指针的模板类型调用`delete`或`delete[]`。

# 还有更多...

第四个解决方案是最保守的，因为在 Boost 1.53 之前，第二个解决方案的功能没有在`shared_ptr`中实现。第一个和第二个解决方案是最快的，因为它们只使用了一次内存分配调用。第三个解决方案可以与较旧版本的 Boost 和 C++11 标准库的`std::shared_ptr<>`一起使用（只需不要忘记将`boost::checked_array_deleter<T>()`更改为`std::default_delete<T[]>()`）。

实际上，`boost::make_shared<char[]>(size)`并不等同于`new char[size]`，因为它涉及到所有元素的值初始化。默认初始化的等效函数是`boost::make_shared_noinit`。

注意！C++11 和 C++14 版本的`std::shared_ptr`不能处理数组！只有在 C++17 中`std::shared_ptr<T[]>`才能正常工作。如果你计划编写可移植的代码，请考虑使用`boost::shared_ptr`、`boost::shared_array`，或者显式地将`deleter`传递给`std::shared_ptr`。

`boost::shared_ptr<T[]>`、`boost::shared_array`和 C++17 的`std::shared_ptr<T[]>`都有`operator[](std::size_t index)`，允许你通过索引访问共享数组的元素。`boost::shared_ptr<T>`和带有自定义`deleter`的`std::shared_ptr<T>`没有`operator[]`，这使它们不太有用。

# 另请参阅

`Boost.SmartPtr`库的文档包含了许多关于所有智能指针类的示例和其他有用信息。你可以在[`boost.org/libs/smart_ptr`](http://boost.org/libs/smart_ptr)上阅读相关内容。

# 将任何功能对象存储在变量中

考虑这样一种情况，当你开发一个库，它的 API 在头文件中声明，而在源文件中实现。这个库应该有一个接受任何功能对象的函数。看一下下面的代码：

```cpp
// making a typedef for function pointer accepting int 
// and returning nothing 
typedef void (*func_t)(int); 

// Function that accepts pointer to function and 
// calls accepted function for each integer that it has.
// It cannot work with functional objects :( 
void process_integers(func_t f); 

// Functional object 
class int_processor { 
   const int min_; 
   const int max_; 
   bool& triggered_; 

public: 
    int_processor(int min, int max, bool& triggered) 
        : min_(min) 
        , max_(max) 
        , triggered_(triggered) 
    {} 

    void operator()(int i) const { 
        if (i < min_ || i > max_) { 
            triggered_ = true; 
        } 
    } 
};
```

如何修改`process_integers`函数以接受任何功能对象？

# 准备工作

在开始本教程之前，建议先阅读第一章中的*在容器/变量中存储任何值*教程，*开始编写您的应用程序*。

# 如何做...

有一个解决方案，它被称为`Boost.Function`库。它允许您存储任何函数、成员函数或者函数对象，只要它的签名与模板参数中描述的一致：

```cpp
#include <boost/function.hpp> 

typedef boost::function<void(int)> fobject_t; 

// Now this function may accept functional objects 
void process_integers(const fobject_t& f); 

int main() { 
    bool is_triggered = false; 
    int_processor fo(0, 200, is_triggered); 
    process_integers(fo); 
    assert(is_triggered); 
}
```

# 它是如何工作的...

`fobject_t`对象在自身中存储函数对象并擦除它们的确切类型。使用`boost::function`来存储有状态的对象是安全的：

```cpp
bool g_is_triggered = false; 
void set_functional_object(fobject_t& f) {
    // Local variable
    int_processor fo( 100, 200, g_is_triggered); 

    f = fo;
    // now 'f' holds a copy of 'fo'

    // 'fo' leavs scope and will be destroyed,
    // but it's OK to use 'f' in outer scope.
}
```

`boost::function`是否记得`boost::any`类？那是因为它使用相同的技术**类型擦除**来存储任何函数对象。

# 还有更多...

`boost::function`类有一个默认构造函数并且有一个空状态。可以像这样检查是否为空/默认构造状态：

```cpp
void foo(const fobject_t& f) { 
    // boost::function is convertible to bool 
    if (f) { 
        // we have value in 'f' 
        // ... 
    } else { 
        // 'f' is empty 
        // ... 
    } 
}
```

`Boost.Function`库有大量的优化。它可以存储小型函数对象而无需额外的内存分配，并且具有优化的移动赋值运算符。它被接受为 C++11 标准库的一部分，并且在`std::`命名空间的`<functional>`头文件中定义。

`boost::function`对存储在其中的对象使用 RTTI。如果禁用 RTTI，库将继续工作，但会大幅增加编译后的二进制文件的大小。

# 另请参阅

+   Boost.Function 的官方文档包含更多示例、性能测量和类参考文档。请参考链接[`boost.org/libs/function`](http://boost.org/libs/function)进行阅读。

+   *在变量中传递函数指针*教程。

+   *在变量中传递 C++11 lambda 函数*教程。

# 在变量中传递函数指针

我们将继续使用之前的示例，现在我们想在`process_integers()`方法中传递一个函数指针。我们应该为函数指针添加一个重载，还是有更加优雅的方法？

# 准备工作

这个教程是前一个的延续。你必须先阅读前一个教程。

# 如何做...

不需要做任何事情，因为`boost::function<>`也可以从函数指针中构造：

```cpp
void my_ints_function(int i); 

int main() { 
    process_integers(&my_ints_function); 
}
```

# 它是如何工作的...

指向`my_ints_function`的指针将被存储在`boost::function`类中，并且对`boost::function`的调用将被转发到存储的指针。

# 还有更多...

`Boost.Function`库为函数指针提供了良好的性能，并且不会在堆上分配内存。标准库`std::function`也有效地存储函数指针。自 Boost 1.58 以来，`Boost.Function`库可以存储具有 rvalue 引用调用签名的函数和函数对象：

```cpp
boost::function<int(std::string&&)> f = &something;
f(std::string("Hello")); // Works
```

# 另请参阅

+   Boost.Function 的官方文档包含更多示例、性能测量和类参考文档。请访问[`boost.org/libs/function`](http://boost.org/libs/function)进行阅读。

+   *在变量中传递 C++11 lambda 函数*教程。

# 在变量中传递 C++11 lambda 函数

我们将继续使用之前的示例，现在我们想在`process_integers()`方法中使用一个 lambda 函数。

# 准备工作

这个教程是前两个教程的延续。你必须先阅读它们。你还需要一个兼容 C++11 的编译器，或者至少支持 C++11 lambda 的编译器。

# 如何做...

不需要做任何事情，因为`boost::function<>`也可以用于任何难度的 lambda 函数：

```cpp
#include <deque>
//#include "your_project/process_integers.h"

void sample() {
    // lambda function with no parameters that does nothing 
    process_integers([](int /*i*/){}); 

    // lambda function that stores a reference 
    std::deque<int> ints; 
    process_integers(&ints{ 
        ints.push_back(i); 
    }); 

    // lambda function that modifies its content 
    std::size_t match_count = 0; 
    process_integers(ints, &match_count mutable { 
        if (ints.front() == i) { 
           ++ match_count; 
        } 
        ints.pop_front(); 
    });
}
```

# 还有更多...

`Boost.Functional`中的 lambda 函数存储性能与其他情况相同。lambda 表达式生成的函数对象足够小，可以适应`boost::function`的实例，不会执行动态内存分配。调用存储在`boost::function`中的对象的速度接近通过指针调用函数的速度。只有在初始`boost::function`中存储的对象不适合在没有分配的情况下存储时，复制`boost::function`才会分配堆内存。移动实例不会分配和释放内存。

请记住，`boost::function`意味着对编译器的优化障碍。这意味着：

```cpp
    std::for_each(v.begin(), v.end(), [](int& v) { v += 10; });
```

通常由编译器优化得更好：

```cpp
    const boost::function<void(int&)> f0(
        [](int& v) { v += 10; }
    ); 
    std::for_each(v.begin(), v.end(), f0);
```

这就是为什么在不真正需要时应该尽量避免使用`Boost.Function`。在某些情况下，C++11 的`auto`关键字可能更方便：

```cpp
    const auto f1 = [](int& v) { v += 10; }; 
    std::for_each(v.begin(), v.end(), f1);
```

# 另请参阅

有关性能和`Boost.Function`的其他信息，请访问官方文档页面[`www.boost.org/libs/function`](http://www.boost.org/libs/function)。

# 指针容器

有这样的情况，当我们需要在容器中存储指针。示例包括：在容器中存储多态数据，强制在容器中快速复制数据，以及对容器中的数据操作有严格的异常要求。在这种情况下，C++程序员有以下选择：

+   在容器中存储指针并使用`delete`来处理它们的销毁：

```cpp
#include <set>
#include <algorithm>
#include <cassert>

template <class T>
struct ptr_cmp {
    template <class T1>
    bool operator()(const T1& v1, const T1& v2) const {
        return operator ()(*v1, *v2);
    }

    bool operator()(const T& v1, const T& v2) const {
        return std::less<T>()(v1, v2);
    }
};

void example1() {
    std::set<int*, ptr_cmp<int> > s;
    s.insert(new int(1));
    s.insert(new int(0));

    // ...
    assert(**s.begin() == 0);
    // ...

    // Oops! Any exception in the above code leads to
    // memory leak.

    // Deallocating resources.
    std::for_each(s.begin(), s.end(), [](int* p) { delete p; });
}
```

这种方法容易出错，需要大量编写。

+   在容器中存储 C++11 智能指针：

```cpp
#include <memory>
#include <set>

void example2_cpp11() {
    typedef std::unique_ptr<int> int_uptr_t;
    std::set<int_uptr_t, ptr_cmp<int> > s;
    s.insert(int_uptr_t(new int(1)));
    s.insert(int_uptr_t(new int(0)));

    // ...
    assert(**s.begin() == 0);
    // ...

    // Resources will be deallocated by unique_ptr<>.
}
```

这种解决方案很好，但不能在 C++03 中使用，而且您仍然需要编写一个比较器函数对象。

C++14 有一个`std::make_unique`函数用于构造`std::uniue_ptr`。使用它而不是`new`是一个很好的编码风格！

+   在容器中使用`Boost.SmartPtr`：

```cpp
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>

void example3() {
    typedef boost::shared_ptr<int> int_sptr_t;
    std::set<int_sptr_t, ptr_cmp<int> > s;
    s.insert(boost::make_shared<int>(1));
    s.insert(boost::make_shared<int>(0));

    // ...
    assert(**s.begin() == 0);
    // ...

    // Resources will be deallocated by shared_ptr<>.
}
```

这种解决方案是可移植的，但会增加性能损失（原子计数器需要额外的内存，并且其增量/减量不如非原子操作快），而且您仍然需要编写比较器。

# 准备工作

更好地理解本配方需要了解标准库容器的知识。

# 如何做...

`Boost.PointerContainer`库提供了一个很好的可移植解决方案：

```cpp
#include <boost/ptr_container/ptr_set.hpp> 

void correct_impl() { 
    boost::ptr_set<int> s; 
    s.insert(new int(1)); 
    s.insert(new int(0)); 

    // ... 
    assert(*s.begin() == 0); 
    // ... 

    // Resources will be deallocated by container itself.
}
```

# 工作原理...

`Boost.PointerContainer`库有`ptr_array`、`ptr_vector`、`ptr_set`、`ptr_multimap`等类。这些类根据需要释放指针，并简化了指针指向的数据的访问（在`assert(*s.begin() == 0);`中不需要额外的解引用）。

# 还有更多...

当我们想要克隆一些数据时，我们需要在要克隆的对象的命名空间中定义一个独立的函数`T*new_clone(const T& r)`。此外，如果您包含头文件`<boost/ptr_container/clone_allocator.hpp>`，则可以使用默认的`T* new_clone(const T& r)`实现，如下面的代码所示：

```cpp
#include <boost/ptr_container/clone_allocator.hpp>
#include <boost/ptr_container/ptr_vector.hpp>
#include <cassert>

void theres_more_example() {
    // Creating vector of 10 elements with values 100
    boost::ptr_vector<int> v;
    int value = 100;
    v.resize(10, &value); // Beware! No ownership of pointer!

    assert(v.size() == 10);
    assert(v.back() == 100);
}
```

C++标准库没有指针容器，但您可以使用`std::unique_ptr`的容器来实现相同的功能。顺便说一句，自 Boost 1.58 以来，有一个`boost::movelib::unique_ptr`类，可在 C++03 中使用。您可以将其与`Boost.Container`库中的容器混合使用，以获得存储指针的 C++11 功能：

```cpp
#include <boost/container/set.hpp>
#include <boost/move/make_unique.hpp>
#include <cassert>

void example2_cpp03() { 
    typedef boost::movelib::unique_ptr<int> int_uptr_t; 
    boost::container::set<int_uptr_t, ptr_cmp<int> > s; 
    s.insert(boost::movelib::make_unique<int>(1)); 
    s.insert(boost::movelib::make_unique<int>(0)); 
    // ... 
    assert(**s.begin() == 0); 
}
```

并非所有开发人员都很了解 Boost 库。使用具有 C++标准库替代品的函数和类更加友好，因为开发人员通常更了解标准库的特性。因此，如果对您来说没有太大区别，请使用`Boost.Container`与`boost::movelib::unique_ptr`。

# 另请参阅

+   官方文档包含了每个类的详细参考，请访问链接[`boost.org/libs/ptr_container`](http://boost.org/libs/ptr_container)了解更多信息。

+   本章的前四个配方为您提供了一些智能指针使用的示例。

+   第九章*，容器*中的多个食谱描述了`Boost.Container`库的特性。查看该章节，了解有用的快速容器。

# 在作用域退出时执行它！

如果您处理的是 Java、C#或 Delphi 等语言，显然您正在使用`try {} finally{}`结构。让我简要地描述一下这些语言结构的作用。

当程序通过返回或异常离开当前作用域时，`finally`块中的代码将被执行。这种机制用作 RAII 模式的替代：

```cpp
// Some pseudo code (suspiciously similar to Java code) 
try { 
    FileWriter f = new FileWriter("example_file.txt"); 
    // Some code that may throw or return 
    // ... 
} finally { 
    // Whatever happened in scope, this code will be executed 
    // and file will be correctly closed 
    if (f != null) { 
        f.close() 
    } 
}
```

在 C++中有办法做到这一点吗？

# 准备工作

此食谱需要基本的 C++知识。了解在抛出异常时代码的行为将会很有帮助。

# 如何做...

C++使用 RAII 模式而不是`try {} finally{}`结构。`Boost.ScopeExit`库旨在允许用户在函数体内定义 RAII 包装器：

```cpp
#include <boost/scope_exit.hpp> 
#include <cstdlib> 
#include <cstdio> 
#include <cassert> 

int main() { 
    std::FILE* f = std::fopen("example_file.txt", "w"); 
    assert(f); 

    BOOST_SCOPE_EXIT(f) { 
    // Whatever happened in outer scope, this code will be executed 
    // and file will be correctly closed. 
        std::fclose(f); 
    } BOOST_SCOPE_EXIT_END 

    // Some code that may throw or return. 
    // ... 
}
```

# 它是如何工作的...

`f`通过`BOOST_SCOPE_EXIT(f)`按值传递。当程序离开执行范围时，`BOOST_SCOPE_EXIT(f) {`和`} BOOST_SCOPE_EXIT_END`之间的代码将被执行。如果我们希望通过引用传递值，使用`BOOST_SCOPE_EXIT`宏中的`&`符号。如果我们希望传递多个值，只需用逗号分隔它们。

在某些编译器上，将引用传递给指针并不奏效。`BOOST_SCOPE_EXIT(&f)`宏在那里无法编译，这就是为什么我们在示例中没有通过引用捕获它的原因。

# 更多信息...

为了在成员函数中捕获这个，我们将使用一个特殊的符号`this_`：

```cpp
class theres_more_example { 
public: 
    void close(std::FILE*); 

    void theres_more_example_func() { 
        std::FILE* f = 0; 
        BOOST_SCOPE_EXIT(f, this_) { // Capturing `this` as 'this_' 
            this_->close(f); 
        } BOOST_SCOPE_EXIT_END 
    } 
};
```

`Boost.ScopeExit`库在堆上不分配额外的内存，也不使用虚函数。使用默认语法，不要定义`BOOST_SCOPE_EXIT_CONFIG_USE_LAMBDAS`，否则将使用`boost::function`来实现作用域退出，这可能会分配额外的内存并意味着一个优化障碍。您可以通过指定自定义的`deleter`，使用`boost::movelib::unique_ptr`或`std::unique_ptr`来实现接近`BOOST_SCOPE_EXIT`结果：

```cpp
#include <boost/move/unique_ptr.hpp>
#include <cstdio>

void unique_ptr_example() {
    boost::movelib::unique_ptr<std::FILE, int(*)(std::FILE*)> f(
        std::fopen("example_file.txt", "w"), // open file
        &std::fclose  // specific deleter
    );
    // ...
}
```

如果您为`BOOST_SCOPE_EXIT`编写了两个或更多类似的代码块，那么现在是时候考虑一些重构，并将代码移动到一个完全功能的 RAII 类中。

# 另请参阅

官方文档包含更多示例和用例。您可以在[`boost.org/libs/scope_exit.`](http://boost.org/libs/scope_exit)上阅读相关内容

# 通过派生类的成员初始化基类

让我们看一个例子。我们有一个基类，它有虚函数，并且必须用`std::ostream`对象的引用进行初始化：

```cpp
#include <boost/noncopyable.hpp> 
#include <sstream> 

class tasks_processor: boost::noncopyable { 
    std::ostream& log_; 

protected: 
    virtual void do_process() = 0; 

public: 
    explicit tasks_processor(std::ostream& log) 
        : log_(log) 
    {} 

    void process() { 
        log_ << "Starting data processing"; 
        do_process(); 
    } 
};
```

我们还有一个派生类，它有一个`std::ostream`对象，并实现了`do_process()`函数：

```cpp
class fake_tasks_processor: public tasks_processor { 
    std::ostringstream logger_; 

    virtual void do_process() { 
        logger_ << "Fake processor processed!"; 
    } 

public: 
    fake_tasks_processor() 
        : tasks_processor(logger_) // Oops! logger_ does not exist here 
        , logger_() 
    {} 
};
```

这在编程中并不是一个很常见的情况，但当发生这样的错误时，要想绕过它并不总是简单的。有些人试图通过改变`logger_`和基类型初始化的顺序来绕过它：

```cpp
    fake_tasks_processor() 
        : logger_() // Oops! It is still constructed AFTER tasks_processor. 
        , tasks_processor(logger_) 
    {}
```

直接基类在非静态数据成员之前初始化，而不管成员初始化器的顺序，这样不会按预期工作。

# 入门

这个食谱需要基本的 C++知识。

# 如何做...

`Boost.Utility`库为这种情况提供了一个快速解决方案。解决方案称为`boost::base_from_member`模板。要使用它，您需要执行以下步骤：

1.  包括`base_from_member.hpp`头文件：

```cpp
#include <boost/utility/base_from_member.hpp>
```

1.  从`boost::base_from_member<T>`派生您的类，其中`T`是在基类之前必须初始化的类型（注意基类的顺序；`boost::base_from_member<T>`必须放在使用`T`的类之前）：

```cpp
class fake_tasks_processor_fixed
    : boost::base_from_member<std::ostringstream>
    , public tasks_processor
```

1.  正确地，编写构造函数如下：

```cpp
{
    typedef boost::base_from_member<std::ostringstream> logger_t;

    virtual void do_process() {
        logger_t::member << "Fake processor processed!";
    }

public:
    fake_tasks_processor_fixed()
        : logger_t()
        , tasks_processor(logger_t::member)
    {}
};
```

# 它是如何工作的...

直接基类在非静态数据成员之前进行初始化，并且按照它们在基类指定符列表中出现的顺序进行初始化。如果我们需要用*something*初始化基类`B`，我们需要将*something*作为在`B`之前声明的基类`A`的一部分。换句话说，`boost::base_from_member`只是一个简单的类，它将其模板参数作为非静态数据成员：

```cpp
template < typename MemberType, int UniqueID = 0 >
class base_from_member {
protected:
    MemberType  member;
    //      Constructors go there...
};
```

# 还有更多...

正如你所看到的，`base_from_member`有一个整数作为第二个模板参数。这是为了在我们需要多个相同类型的`base_from_member`类的情况下使用：

```cpp
class fake_tasks_processor2 
    : boost::base_from_member<std::ostringstream, 0> 
    , boost::base_from_member<std::ostringstream, 1> 
    , public tasks_processor 
{ 
    typedef boost::base_from_member<std::ostringstream, 0> logger0_t;
    typedef boost::base_from_member<std::ostringstream, 1> logger1_t;

    virtual void do_process() { 
        logger0_t::member << "0: Fake processor2 processed!"; 
        logger1_t::member << "1: Fake processor2 processed!"; 
    } 

public: 
    fake_tasks_processor2() 
        : logger0_t() 
        , logger1_t() 
        , tasks_processor(logger0_t::member) 
    {} 
};
```

`boost::base_from_member`类既不应用额外的动态内存分配，也没有虚函数。如果您的编译器支持，当前实现支持**完美转发**和**可变模板**。

C++标准库中没有`base_from_member`。

# 另请参阅

+   `Boost.Utility`库包含许多有用的类和函数；有关更多信息的文档，请访问[`boost.org/libs/utility`](http://boost.org/libs/utility)

+   在第一章 *开始编写您的应用程序*中的*制作不可复制的类*示例中，包含了来自`Boost.Utility`的更多类的示例

+   此外，在第一章 *开始编写您的应用程序*中的*使用 C++11 移动模拟*示例中，包含了更多来自`Boost.Utility`的类的示例。
