# C++ 高级编程秘籍（一）

> 原文：[`annas-archive.org/md5/24e080e694c59b3f8e0220d0902724b0`](https://annas-archive.org/md5/24e080e694c59b3f8e0220d0902724b0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在本书中，你将学习高级 C++技术，可以应用于自己的 C++项目。本书使用食谱式方法教授 C++，每个食谱都有示例和屏幕截图，可以从 GitHub 下载并自行操作。本书使用 C++17 规范教授 C++，并在最后一章预览了添加到 C++20 的新功能。在一些食谱中，我们甚至会使用反汇编器来更好地理解 C++的编译方式，以及某些决策对应用程序的影响。通过本书，你将掌握 C++的高级概念，并能解决日常问题，从而将你的 C++编程提升到更高水平。

# 本书适合谁

本书适用于熟悉 C++并希望获得专业技能并成为熟练 C++开发人员的中级 C++开发人员。假定对语言有很好的理解，包括对汇编语言的基本理解。

# 本书涵盖内容

第一章，*开始使用库开发*，教你如何开发自己的库，包括最少惊讶原则的解释，如何对所有内容进行命名空间处理，如何编写仅包含头文件的库，以及如何确保其他人将继续使用你的库。

第二章，*使用异常进行错误处理*，涵盖了 C++异常和错误处理的更高级主题，包括对`noexcept`说明符和运算符的详细解释，RAII 如何在异常存在的情况下支持资源管理，为什么应避免从析构函数中抛出异常，以及如何编写自己的异常。

第三章，*实现移动语义*，详细解释了 C++移动语义，包括*大五*的解释，如何使你的类可移动，如何编写仅移动（和非移动）非复制样式的类，如何正确实现移动构造函数，为什么`const &&`没有意义，以及如何使用引用资格。

第四章，*使用模板进行通用编程*，教你如何像专家一样编写模板函数，包括如何实现自己的 SFINAE，如何执行完美转发，如何使用`constexpr-if`语句，如何利用参数包的元组，如何在编译时循环参数包，如何使用类型特征来实现相同函数的不同版本，如何使用`template<auto>`，以及如何在自己的应用程序中利用显式类型声明。

第五章，*并发和同步*，教你如何使用`std::mutex`（及其相关内容），何时使用原子类型，如何使用`mutable`关键字处理具有线程安全性的`const`类，如何编写线程安全类，如何编写线程安全包装器，以及如何编写异步 C++，包括 promises 和 futures。

第六章，*优化代码以提高性能*，介绍了如何对 C++进行性能分析和基准测试，如何反汇编 C++以更好地理解如何优化代码，如何定位并删除不需要的内存分配，以及为什么`noexcept`有助于优化。

第七章，*调试和测试*，指导你如何使用`Catch2`来对 C++进行单元测试，如何使用 Google 的 ASAN 和 UBSAN 清除器动态分析代码以检测内存损坏和未定义行为，以及如何使用 NDEBUG。

第八章，*创建和实现自己的容器*，教你如何通过创建始终排序的`std::vector`来编写自己的容器包装器。

第九章，*探索类型擦除*，教授了关于类型擦除的一切，包括如何通过继承和使用模板来擦除类型，如何实现类型擦除模式，以及如何实现委托模式。

第十章，*深入了解动态分配*，教授动态内存分配的高级主题，包括如何正确使用`std::unique_ptr`和`std::shared_ptr`，如何处理循环引用，如何对智能指针进行类型转换，以及堆是如何在后台工作以为应用程序提供动态内存的。

第十一章，*C++中的常见模式*，解释了计算机科学中不同模式在 C++中的实现，包括工厂模式、单例模式、装饰器模式和观察者模式，以及如何实现静态多态性以编写自己的静态接口而无需虚继承。

第十二章，*深入了解类型推导*，深入探讨了 C++17 中类型推导的执行方式，包括`auto`、`decltype`和`template`如何自动推断其类型。本章最后还提供了如何编写自己的 C++17 用户定义的推导指南的示例。

第十三章，*奖励：使用 C++20 特性*，提供了 C++20 即将推出的新特性的预览，包括概念、模块、范围和协程。

# 充分利用本书

我们假设您以前已经编写过 C++，并且已经熟悉了一些现代 C++特性。

本书使用 Ubuntu 提供示例，您可以在阅读本书时自行编译和运行。我们假设您对 Ubuntu 有一些基本的了解，知道如何安装它，以及如何使用 Linux 终端。

我们在一些示例中使用反汇编器来更好地理解编译器在幕后的工作。虽然您不需要知道如何阅读汇编代码来理解所教授的内容，但对 x86_64 汇编的基本理解将有所帮助。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](https://www.packtpub.com/support)注册，直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或在[www.packt.com](http://www.packt.com)注册。

1.  选择支持选项卡。

1.  点击代码下载。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压或提取文件夹。

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Advanced-CPP-Programming-CookBook`](https://github.com/PacktPublishing/Advanced-CPP-Programming-CookBook)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。快去看看吧！

# 代码实例

访问以下链接查看代码运行的视频：[`bit.ly/2tQoZyW`](https://bit.ly/2tQoZyW)

# 使用的约定

本书中使用了许多文本约定。

`constexpr`：指示文本中的代码字、数字、文件夹名称、文件名、文件扩展名、路径名、虚拟 URL 和用户输入。例如："`noexcept`说明符用于告诉编译器函数是否可能引发 C++异常。"

代码块设置如下：

```cpp
int main(void)
{
    the_answer is;
    return 0;
}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```cpp
int main(void)
{
    auto execute_on_exit = finally{[]{
        std::cout << "The answer is: 42\n";
    }};
}
```

任何命令行输入或输出都将按以下方式编写：

```cpp
> mkdir build && cd build
> cmake ..
> make recipe04_examples
```

**粗体**：表示一个新术语，一个重要词或您在屏幕上看到的词。例如，重要单词会以这种方式出现在文本中。这里有一个例子：“在这个食谱中，我们将学习为什么在析构函数中抛出异常是一个**坏主意**。”

警告或重要说明会出现在这样的地方。

提示和技巧会出现在这样的地方。

# 部分

在这本书中，您会发现一些经常出现的标题（*准备好*，*如何做...*，*它是如何工作的...*，*还有更多...*和*另请参阅*）。

为了清晰地说明如何完成一个食谱，请按照以下部分进行操作：

# 准备好

这一部分告诉您在食谱中可以期待什么，并描述如何设置任何软件或食谱所需的任何初步设置。

# 如何做...

这一部分包含了遵循食谱所需的步骤。

# 它是如何工作的...

这一部分通常包括了对前一部分发生的事情的详细解释。

# 还有更多...

这部分包括有关食谱的额外信息，以使您对食谱更加了解。

# 另请参阅

这一部分为食谱提供了其他有用信息的有用链接。

# 第一章：开始使用库开发

在本章中，我们将介绍一些有用的配方，用于创建我们自己的库，包括最少惊讶原则的解释，该原则鼓励我们使用用户已经熟悉的语义来实现库。我们还将看看如何对所有内容进行命名空间处理，以确保我们的自定义库不会与其他库发生冲突。此外，我们还将介绍如何创建仅包含头文件的库，以及与库开发相关的一些最佳实践。最后，我们将通过演示 boost 库来结束本章，以向您展示一个大型库的样子以及用户如何在自己的项目中使用它。

在本章中，我们将介绍以下配方：

+   理解最少惊讶原则

+   如何对所有内容进行命名空间处理

+   仅包含头文件的库

+   学习库开发的最佳实践

+   学习如何使用 boost API

让我们开始吧！

# 技术要求

要编译和运行本章中的示例，您必须具有管理访问权限，可以访问运行 Ubuntu 18.04 的计算机，并具有正常的互联网连接。在运行这些示例之前，您必须使用以下命令安装以下软件包：

```cpp
> sudo apt-get install build-essential git cmake
```

如果这个安装在除 Ubuntu 18.04 之外的任何操作系统上，那么将需要 GCC 7.4 或更高版本和 CMake 3.6 或更高版本。

# 理解最少惊讶原则

在使用现有的 C++库或创建自己的库时，理解**最少惊讶原则**（也称为**最少惊讶原则**）对于高效和有效地开发源代码至关重要。这个原则简单地指出，C++库提供的任何功能都应该是直观的，并且应该按照开发人员的期望进行操作。另一种说法是，库的 API 应该是自我记录的。尽管这个原则在设计库时至关重要，但它可以并且应该应用于所有形式的软件开发。在本教程中，我们将深入探讨这个原则。

# 准备工作

与本章中的所有配方一样，确保已满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有正确的工具来编译和执行本教程中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

执行以下步骤完成本教程：

1.  从新的终端运行以下代码来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter01
```

1.  要编译源代码，请运行以下代码：

```cpp
> mkdir build && cd build
> cmake ..
> make recipe01_examples
```

1.  一旦源代码被编译，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe01_example01
The answer is: 42

> ./recipe01_example02
The answer is: 42

> ./recipe01_example03
The answer is: 42

> ./recipe01_example04
The answer is: 42
The answer is: 42

> ./recipe01_example05
The answer is: 42
The answer is: 42

> ./recipe01_example06
The answer is: 42
The answer is: 42

> ./recipe01_example07
The answer is: 42

> ./recipe01_example08
The answer is: 42

> ./recipe01_example09
The answer is: 42
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的功能以及它与本教程中所教授的课程的关系。

# 它是如何工作的...

如前一节所述，最少惊讶原则指出，库的 API 应该直观且自我记录，这个原则通常适用于所有形式的软件开发，而不仅仅是库设计。为了理解这一点，我们将看一些例子。

# 示例 1

示例 1 演示了最少惊讶原则，如下所示：

```cpp
#include <iostream>

int sub(int a, int b)
{ return a + b; }

int main(void)
{
    std::cout << "The answer is: " << sub(41, 1) << '\n';
    return 0;
}
```

如前面的示例所示，我们实现了一个库 API，它可以将两个整数相加并返回结果。问题在于我们将函数命名为`sub`，大多数开发人员会将其与减法而不是加法联系起来；尽管 API 按设计工作，但它违反了最少惊讶原则，因为 API 的名称不直观。

# 示例 2

示例 2 演示了最少惊讶原则，如下所示：

```cpp
#include <iostream>

void add(int a, int &b)
{ b += a; }

int main(void)
{
    int a = 41, b = 1;
    add(a, b);

    std::cout << "The answer is: " << b << '\n';
    return 0;
}
```

如前面的例子所示，我们已经实现了与上一个练习中实现的相同的库 API；它旨在添加两个数字并返回结果。这个例子的问题在于 API 实现了以下内容：

```cpp
b += a;
```

在这个例子中，最少惊讶原则以两种不同的方式被违反：

+   add 函数的参数是`a`，然后是`b`，尽管我们会将这个等式写成`b += a`，这意味着参数的顺序在直觉上是相反的。

+   对于这个 API 的用户来说，不会立即明显地意识到结果将在`b`中返回，而不必阅读源代码。

函数的签名应该使用用户已经习惯的语义来记录函数将如何执行，从而降低用户错误执行 API 的概率。

# 示例 3

示例 3 演示了最少惊讶原则如下：

```cpp
#include <iostream>

int add(int a, int b)
{ return a + b; }

int main(void)
{
    std::cout << "The answer is: " << add(41, 1) << '\n';
    return 0;
}
```

如前面的例子所示，我们在这里遵循了最少惊讶原则。API 旨在将两个整数相加并返回结果，API 直观地执行了预期的操作。

# 示例 4

示例 4 演示了最少惊讶原则如下：

```cpp
#include <stdio.h>
#include <iostream>

int main(void)
{
    printf("The answer is: %d\n", 42);
    std::cout << "The answer is: " << 42 << '\n';
    return 0;
}
```

如前面的例子所示，另一个很好的最少惊讶原则的例子是`printf()`和`std::cout`之间的区别。`printf()`函数需要添加格式说明符来将整数输出到`stdout`。`printf()`不直观的原因有很多：

+   对于初学者来说，`printf()`函数的名称，代表打印格式化，不直观（或者换句话说，函数的名称不是自我说明的）。其他语言通过选择更直观的打印函数名称来避免这个问题，比如`print()`或`console()`，这些名称更好地遵循了最少惊讶原则。

+   整数的格式说明符符号是`d`。对于初学者来说，这是不直观的。在这种特定情况下，`d`代表十进制，这是说*有符号整数*的另一种方式。更好的格式说明符可能是`i`，以匹配语言对`int`的使用。

与`std::cout`相比，它代表字符输出。虽然与`print()`或`console()`相比这不太直观，但比`printf()`更直观。此外，要将整数输出到`stdout`，用户不必记忆格式说明符表来完成任务。相反，他们可以简单地使用`<<`运算符。然后，API 会为您处理格式，这不仅更直观，而且更安全（特别是在使用`std::cin`而不是`scanf()`时）。

# 示例 5

示例 5 演示了最少惊讶原则如下：

```cpp
#include <iostream>

int main(void)
{
    auto answer = 41;

    std::cout << "The answer is: " << ++answer << '\n';
    std::cout << "The answer is: " << answer++ << '\n';

    return 0;
}
```

在前面的例子中，`++`运算符遵循最少惊讶原则。尽管初学者需要学习`++`代表递增运算符，意味着变量增加`1`，但`++`与变量的位置相当有帮助。

要理解`++variable`和`variable++`之间的区别，用户只需像平常一样从左到右阅读代码。当`++`在左边时，变量被递增，然后返回变量的内容。当`++`在右边时，返回变量的内容，然后递增变量。关于`++`位置的唯一问题是，左边的`++`通常更有效率（因为实现不需要额外的逻辑来存储递增操作之前的变量值）。

# 示例 6

示例 6 演示了最少惊讶原则如下：

```cpp
#include <iostream>

int add(int a, int b)
{ return a + b; }

int Sub(int a, int b)
{ return a - b; }

int main(void)
{
    std::cout << "The answer is: " << add(41, 1) << '\n';
    std::cout << "The answer is: " << Sub(43, 1) << '\n';

    return 0;
}
```

如前面的代码所示，我们实现了两个不同的 API。第一个是将两个整数相加并返回结果，而第二个是将两个整数相减并返回结果。减法函数的问题有两个：

+   加法函数是小写的，而减法函数是大写的。这不直观，API 的用户必须学习哪些 API 是小写的，哪些是大写的。

+   C++标准 API 都是蛇形命名法，意思是它们利用小写单词并使用`_`来表示空格。一般来说，最好设计 C++库 API 时使用蛇形命名法，因为初学者更有可能找到这种方式直观。值得注意的是，尽管这通常是这样，但蛇形命名法的使用是高度主观的，有几种语言不遵循这一指导。最重要的是选择一个约定并坚持下去。

再次确保您的 API 模仿现有语义，确保用户可以快速轻松地学会使用您的 API，同时降低用户错误编写 API 的可能性，从而导致编译错误。

# 示例 7

示例 7 演示了最小惊讶原则的如下内容：

```cpp
#include <queue>
#include <iostream>

int main(void)
{
    std::queue<int> my_queue;

    my_queue.emplace(42);
    std::cout << "The answer is: " << my_queue.front() << '\n';
    my_queue.pop();

    return 0;
}
```

在前面的例子中，我们向您展示了如何使用`std::queue`将整数添加到队列中，将队列输出到`stdout`，并从队列中删除元素。这个例子的重点是要突出 C++已经有一套标准的命名约定，应该在 C++库开发过程中加以利用。

如果您正在设计一个新的库，使用 C++已经定义的相同命名约定对您的库的用户是有帮助的。这样做将降低使用门槛，并提供更直观的 API。

# 示例 8

示例 8 演示了最小惊讶原则的如下内容：

```cpp
#include <iostream>

auto add(int a, int b)
{ return a + b; }

int main(void)
{
    std::cout << "The answer is: " << add(41, 1) << '\n';
    return 0;
}
```

如前面的例子所示，我们展示了`auto`的使用方式，告诉编译器自动确定函数的返回类型，这不符合最小惊讶原则。尽管`auto`对于编写通用代码非常有帮助，但在设计库 API 时应尽量避免使用。特别是为了让 API 的用户理解 API 的输入和输出，用户必须阅读 API 的实现，因为`auto`不指定输出类型。

# 示例 9

示例 9 演示了最小惊讶原则的如下内容：

```cpp
#include <iostream>

template <typename T>
T add(T a, T b)
{ return a + b; }

int main(void)
{
    std::cout << "The answer is: " << add(41, 1) << '\n';
    return 0;
}
```

如前面的例子所示，我们展示了一种更合适的方式来支持最小惊讶原则，同时支持通用编程。通用编程（也称为模板元编程或使用 C++模板进行编程）为程序员提供了一种在不声明算法中使用的类型的情况下创建算法的方法。在这种情况下，`add`函数不会规定输入类型，允许用户添加任何类型的两个值（在这种情况下，类型称为`T`，可以采用支持`add`运算符的任何类型）。我们返回一个类型`T`，而不是返回`auto`，因为`auto`不会声明输出类型。尽管`T`在这里没有定义，因为它代表任何类型，但它告诉 API 的用户，我们输入到这个函数中的任何类型也将被函数返回。这种逻辑在 C++标准库中大量使用。

# 如何对一切进行命名空间

创建库时，对一切进行命名空间是很重要的。这样做可以确保库提供的 API 不会与用户代码或其他库提供的设施发生名称冲突。在本示例中，我们将演示如何在我们自己的库中做到这一点。

# 准备工作

与本章中的所有示例一样，请确保已满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

要完成本文，您需要执行以下步骤：

1.  从新的终端中，运行以下命令下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter01
```

1.  要编译源代码，请运行以下代码：

```cpp
> mkdir build && cd build
> cmake ..
> make recipe02_examples
```

1.  一旦源代码被编译，您可以通过运行以下命令来执行本文中的每个示例：

```cpp
> ./recipe02_example01
The answer is: 42

> ./recipe02_example02
The answer is: 42
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本文所教授的课程的关系。

# 它是如何工作的...

C++提供了将代码包裹在`namespace`中的能力，这简单地将`namespace`名称添加到`namespace`代码中的所有函数和变量（应该注意的是，C 风格的宏不包括在`namespace`中，并且应该谨慎使用，因为 C 宏是预处理器功能，不会对代码的编译语法产生影响）。为了解释为什么我们在创建自己的库时应该将所有东西都放在`namespace`中，我们将看一些例子。

# 示例 1

示例 1 演示了如何在 C++`namespace`中包裹库的 API：

```cpp
// Contents of library.h

namespace library_name
{
    int my_api() { return 42; }
    // ...
}

// Contents of main.cpp

#include <iostream>

int main(void)
{
    using namespace library_name;

    std::cout << "The answer is: " << my_api() << '\n';
    return 0;
}
```

如上例所示，库的内容被包裹在一个`namespace`中，并存储在头文件中（这个例子演示了一个头文件库，这是一种非常有用的设计方法，因为最终用户不需要编译库，将其安装在他/她的系统上，然后链接到它们）。库用户只需包含库头文件，并使用`using namespace library_name`语句来解开库的 API。如果用户有多个具有相同 API 名称的库，可以省略此语句以消除任何歧义。

# 示例 2

示例 2 扩展了上一个示例，并演示了如何在 C++命名空间头文件库中包裹库的 API，同时包括全局变量：

```cpp
// Contents of library.h

namespace library_name
{
    namespace details { inline int answer = 42; }

    int my_api() { return details::answer; }
    // ...
}

// Contents of main.cpp

#include <iostream>

int main(void)
{
    using namespace library_name;

    std::cout << "The answer is: " << my_api() << '\n';
    return 0;
}
```

在上面的例子中，利用 C++17 创建了一个包裹在我们库的`namespace`中的`inline`全局变量。`inline`变量是必需的，因为头文件库没有源文件来定义全局变量；没有`inline`关键字，在头文件中定义全局变量会导致变量被多次定义（也就是说，在编译过程中会出现链接错误）。C++17 通过添加`inline`全局变量解决了这个问题，这允许头文件库定义全局变量而无需使用 tricky magic（比如从单例样式函数返回静态变量的指针）。

除了库的`namespace`，我们还将全局变量包裹在`details namespace`中。这是为了在库的用户声明`using namespace library_name`的情况下，在库内创建一个`private`的地方。如果用户这样做，所有被`library_name`命名空间包裹的 API 和变量都会在`main()`函数的范围内变得全局可访问。因此，任何不希望用户访问的私有 API 或变量都应该被第二个`namespace`（通常称为`details`）包裹起来，以防止它们的全局可访问性。最后，利用 C++17 的`inline`关键字允许我们在库中创建全局变量，同时仍然支持头文件库的设计。

# 头文件库

头文件库就像它们的名字一样；整个库都是使用头文件实现的（通常是一个头文件）。头文件库的好处在于，它们很容易包含到您的项目中，只需包含头文件即可（不需要编译库，因为没有需要编译的源文件）。在本配方中，我们将学习在尝试创建头文件库时出现的一些问题以及如何克服这些问题。这个配方很重要，因为如果您计划创建自己的库，头文件库是一个很好的起点，并且可能会增加您的库被下游用户整合到他们的代码库中的几率。

# 准备工作

与本章中的所有配方一样，请确保已满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有正确的工具来编译和执行本配方中的示例。完成这些步骤后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 操作步骤...

完成此配方，您需要执行以下步骤：

1.  从新的终端中，运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter01
```

1.  要编译源代码，请运行以下代码：

```cpp
> mkdir build && cd build
> cmake ..
> make recipe03_examples
```

1.  源代码编译完成后，您可以通过运行以下命令执行本配方中的每个示例：

```cpp
> ./recipe03_example01
The answer is: 42

> ./recipe03_example02
The answer is: 42

> ./recipe03_example03
The answer is: 42

> ./recipe03_example04
The answer is: 42
The answer is: 2a

> ./recipe03_example05

> ./recipe03_example06
The answer is: 42

> ./recipe03_example07
The answer is: 42
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它们与本配方中所教授的课程的关系。

# 工作原理...

要创建一个头文件库，只需确保所有代码都在头文件中实现，如下所示：

```cpp
#ifndef MY_LIBRARY
#define MY_LIBRARY

namespace library_name
{
    int my_api() { return 42; }
}

#endif
```

前面的示例实现了一个简单的库，其中有一个函数。这个库的整个实现可以在一个头文件中实现，并包含在我们的代码中，如下所示：

```cpp
#include "my_library.h"
#include <iostream>

int main(void)
{
    using namespace library_name;

    std::cout << "The answer is: " << my_api() << '\n';
    return 0;
}
```

尽管创建头文件库似乎很简单，但在尝试创建头文件库时会出现一些问题，这些问题应该考虑在内。

# 如何处理包含

在前面的示例中，您可能已经注意到，当我们使用我们的自定义头文件库时，我们首先包含了库。这是编写头文件库的一个基本步骤。在为头文件库编写示例或测试时，我们的库应该是我们包含的第一件事，以确保所有头文件的依赖关系都在头文件库中定义，而不是在我们的示例或测试中定义。

例如，假设我们将我们的库更改如下：

```cpp
#ifndef MY_LIBRARY
#define MY_LIBRARY

namespace library_name
{
    void my_api()
    {
        std::cout << "The answer is: 42" << '\n';
    }
}

#endif
```

如前面的代码片段所示，我们的 API 现在不再返回整数，而是输出到 `stdout`。我们可以如下使用我们的新 API：

```cpp
#include <iostream>
#include "my_library.h"

int main(void)
{
    library_name::my_api();
    return 0;
}
```

尽管前面的代码编译和运行如预期，但代码中存在一个错误，这个错误可能只有您的库的用户才能识别出来。具体来说，如果您的库的用户交换了包含的顺序或者没有`#include <iostream>`，代码将无法编译并产生以下错误：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/14a94075-f946-458b-aa5c-a4bfd158978a.png)

这是因为头文件库本身没有包含所有的依赖关系。由于我们的示例将库放在其他包含之后，我们的示例意外地隐藏了这个问题。因此，当创建自己的头文件库时，始终在测试和示例中首先包含库，以确保这种类型的问题永远不会发生在您的用户身上。

# 全局变量

头文件库的最大限制之一是，在 C++17 之前，没有办法创建全局变量。尽管应尽量避免使用全局变量，但有些情况下是必需的。为了演示这一点，让我们创建一个简单的 API，输出到 `stdout` 如下：

```cpp
#ifndef MY_LIBRARY
#define MY_LIBRARY

#include <iostream>
#include <iomanip>

namespace library_name
{
    void my_api(bool show_hex = false)
    {
        if (show_hex) {
            std::cout << std::hex << "The answer is: " << 42 << '\n';
        }
        else {
            std::cout << std::dec << "The answer is: " << 42 << '\n';
        }
    }
}

#endif
```

前面的示例创建了一个 API，将输出到`stdout`。如果使用`true`而不是默认的`false`执行 API，则将以十六进制而不是十进制格式输出整数。在这个例子中，从十进制到十六进制的转换实际上是我们库中的一个配置设置。然而，如果没有全局变量，我们将不得不采用其他机制来实现这一点，包括宏或前面的示例中的函数参数；后者选择甚至更糟，因为它将库的配置与其 API 耦合在一起，这意味着任何额外的配置选项都会改变 API 本身。

解决这个问题的最佳方法之一是在 C++17 中使用全局变量，如下所示：

```cpp
#ifndef MY_LIBRARY
#define MY_LIBRARY

#include <iostream>
#include <iomanip>

namespace library_name
{
    namespace config
    {
        inline bool show_hex = false;
    }

    void my_api()
    {
        if (config::show_hex) {
            std::cout << std::hex << "The answer is: " << 42 << '\n';
        }
        else {
            std::cout << std::dec << "The answer is: " << 42 << '\n';
        }
    }
}

#endif
```

如前面的示例所示，我们在库中添加了一个名为`config`的新命名空间。我们的 API 不再需要任何参数，并根据内联全局变量确定如何运行。现在，我们可以按以下方式使用此 API：

```cpp
#include "my_library.h"
#include <iostream>

int main(void)
{
    library_name::my_api();
    library_name::config::show_hex = true;
    library_name::my_api();

    return 0;
}
```

以下是输出的结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/2abe9bca-2a0e-4075-a8f8-e5fa3140663e.png)

需要注意的是，我们将配置设置放在`config`命名空间中，以确保我们的库命名空间不会因名称冲突而被污染，从而确保全局变量的意图是明显的。

# C 风格宏的问题

C 风格宏的最大问题在于，如果将它们放在 C++命名空间中，它们的名称不会被命名空间修饰。这意味着宏总是污染全局命名空间。例如，假设您正在编写一个需要检查变量值的库，如下所示：

```cpp
#ifndef MY_LIBRARY
#define MY_LIBRARY

#include <cassert>

namespace library_name
{
    #define CHECK(a) assert(a == 42)

    void my_api(int val)
    {
        CHECK(val);
    }
}

#endif
```

如前面的代码片段所示，我们创建了一个简单的 API，它在实现中使用了 C 风格的宏来检查整数值。前面示例的问题在于，如果您尝试在自己的库中使用单元测试库，很可能会遇到命名空间冲突。

C++20 可以通过使用 C++20 模块来解决这个问题，并且这是我们将在第十三章中更详细讨论的一个主题，*奖励-使用 C++20 功能*。具体来说，C++20 模块不会向库的用户公开 C 风格的宏。这样做的积极方面是，您将能够使用宏而不会出现命名空间问题，因为您的宏不会暴露给用户。这种方法的缺点是，许多库作者使用 C 风格的宏来配置库（例如，在包含库之前定义宏以更改其默认行为）。这种类型的库配置在 C++模块中将无法工作，除非在编译库时在命令行上定义了这些宏。

直到 C++20 可用，如果需要使用宏，请确保手动向宏名称添加修饰，如下所示：

```cpp
#define LIBRARY_NAME__CHECK(a) assert(a == 42)
```

前面的代码行将执行与宏位于 C++命名空间内相同的操作，确保您的宏不会与其他库的宏或用户可能定义的宏发生冲突。

# 如何将大型库实现为仅头文件

理想情况下，头文件库应使用单个头文件实现。也就是说，用户只需将单个头文件复制到其源代码中即可使用该库。这种方法的问题在于，对于非常大的项目，单个头文件可能会变得非常庞大。一个很好的例子是 C++中一个流行的 JSON 库，位于此处：[`github.com/nlohmann/json/blob/develop/single_include/nlohmann/json.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json.hpp)。

在撰写本文时，上述库的代码行数超过 22,000 行。尝试对一个有 22,000 行代码的文件进行修改将是非常糟糕的（即使您的编辑器能够处理）。一些项目通过使用多个头文件实现其仅包含头文件库，并使用单个头文件根据需要包含各个头文件来解决这个问题（例如，Microsoft 的 C++指南支持库就是这样实现的）。这种方法的问题在于用户必须复制和维护多个头文件，随着复杂性的增加，这开始破坏头文件库的目的。

另一种处理这个问题的方法是使用诸如 CMake 之类的工具从多个头文件中自动生成单个头文件。例如，在下面的示例中，我们有一个仅包含头文件的库，其中包含以下头文件：

```cpp
#include "config.h"

namespace library_name
{
    void my_api()
    {
        if (config::show_hex) {
            std::cout << std::hex << "The answer is: " << 42 << '\n';
        }
        else {
            std::cout << std::dec << "The answer is: " << 42 << '\n';
        }
    }
}
```

如前面的代码片段所示，这与我们的配置示例相同，唯一的区别是示例的配置部分已被替换为对`config.h`文件的包含。我们可以按照以下方式创建这个第二个头文件：

```cpp
namespace library_name
{
    namespace config
    {
        inline bool show_hex = false;
    }
}
```

这实现了示例的剩余部分。换句话说，我们已经将我们的头文件分成了两个头文件。我们仍然可以像下面这样使用我们的头文件：

```cpp
#include "apis.h"

int main(void)
{
    library_name::my_api();
    return 0;
}
```

然而，问题在于我们的库的用户需要拥有两个头文件的副本。为了解决这个问题，我们需要自动生成一个头文件。有许多方法可以做到这一点，但以下是使用 CMake 的一种方法：

```cpp
file(STRINGS "config.h" CONFIG_H)
file(STRINGS "apis.h" APIS_H)

list(APPEND MY_LIBRARY_SINGLE
    "${CONFIG_H}"
    ""
    "${APIS_H}"
)

file(REMOVE "my_library_single.h")
foreach(LINE IN LISTS MY_LIBRARY_SINGLE)
    if(LINE MATCHES "#include \"")
        file(APPEND "my_library_single.h" "// ${LINE}\n")
    else()
        file(APPEND "my_library_single.h" "${LINE}\n")
    endif()
endforeach()
```

上面的代码使用`file()`函数将两个头文件读入 CMake 变量。这个函数将每个变量转换为 CMake 字符串列表（每个字符串是文件中的一行）。然后，我们将两个文件合并成一个列表。为了创建我们的新的自动生成的单个头文件，我们遍历列表，并将每一行写入一个名为`my_library_single.h`的新头文件。最后，如果我们看到对本地包含的引用，我们将其注释掉，以确保没有引用我们的额外头文件。

现在，我们可以像下面这样使用我们的新单个头文件：

```cpp
#include "my_library_single.h"

int main(void)
{
    library_name::my_api();
    return 0;
}
```

使用上述方法，我们可以开发我们的库，使用尽可能多的包含，并且我们的构建系统可以自动生成我们的单个头文件，这将被最终用户使用，为我们提供了最好的两全其美。

# 学习库开发最佳实践

在编写自己的库时，所有库作者都应该遵循某些最佳实践。在本教程中，我们将探讨一些优先级较高的最佳实践，并总结一些关于一个专门定义这些最佳实践的项目的信息，包括一个注册系统，为您的库提供编译的评分。这个教程很重要，因为它将教会您如何制作最高质量的库，确保强大和充满活力的用户群体。

# 准备工作

与本章中的所有示例一样，请确保所有技术要求都已满足，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake clang-tidy valgrind
```

这将确保您的操作系统具有正确的工具来编译和执行本教程中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

您需要执行以下步骤来完成本教程：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter01
```

1.  要编译源代码，请运行以下代码：

```cpp
> mkdir build && cd build
> cmake ..
> make recipe04_examples
```

1.  一旦源代码被编译，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe04_example01 
21862
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本教程中所教授的课程的关系。

# 它是如何工作的...

每个图书馆的作者都应该确保他们的图书馆易于使用并且可以整合到用户自己的项目中。这样做将确保您的用户继续使用您的图书馆，从而导致用户群随着时间的推移不断增长。让我们来看看其中一些最佳实践。

# 警告呢？

任何图书馆作者的最低挂果是确保您的代码尽可能多地编译。遗憾的是，GCC 并没有简化这个过程，因为没有一个警告标志可以统治所有警告，特别是因为 GCC 有许多对于现代 C ++版本来说并不有用的警告标志（换句话说，它们在某种程度上是相互排斥的）。开始的最佳地方是以下警告：

```cpp
-Wall -Wextra -pedantic -Werror
```

这将打开大部分重要的警告，同时确保您的示例或测试编译时生成错误的任何警告。然而，对于一些库来说，这还不够。在撰写本文时，微软的指南支持库使用以下标志：

```cpp
-Wall -Wcast-align -Wconversion -Wctor-dtor-privacy -Werror -Wextra -Wpedantic -Wshadow -Wsign-conversion
```

GSL 使用的另一个警告是转换警告，它会在您在不同的整数类型之间转换时告诉您。如果您使用 Clang，这个过程可能会更容易，因为它提供了`-Weverything`。如果筛选 GCC 提供的所有警告太麻烦，解决这个问题的一种方法是确保您的库在打开此警告的情况下与 Clang 编译器编译，这将确保您的代码与 GCC 提供的大部分警告一起编译。这样，当用户必须确保他们的代码中启用了特定警告时，您的用户在使用您的库时就不会遇到麻烦，因为您已经尽可能地测试了其中的许多。

# 静态和动态分析

除了测试警告之外，库还应该使用静态和动态分析工具进行测试。再次强调，作为图书馆的作者，您必须假设您的用户可能会使用静态和动态分析工具来加强他们自己应用程序的质量。如果您的库触发了这些工具，您的用户更有可能寻找经过更彻底测试的替代方案。

对于 C ++，有大量工具可用于分析您的库。在本教程中，我们将专注于 Clang Tidy 和 Valgrind，它们都是免费使用的。让我们看看以下简单的例子：

```cpp
#include <iostream>

int universe()
{
    auto i = new int;
    int the_answer;
    return the_answer;
}

int main()
{
    std::cout << universe() << '\n';
    return 0;
}
```

在前面的例子中，我们创建了一个名为`universe()`的函数，它返回一个整数并分配一个整数。在我们的主函数中，我们的`universe()`函数将结果输出到`stdout`。

要对前面的代码进行静态分析，我们可以使用 CMake，如下所示：

```cpp
set(CMAKE_CXX_CLANG_TIDY clang-tidy)
```

前面的代码告诉 CMake 在编译前面的示例时使用`clang-tidy`。当我们编译代码时，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/90475cde-2dd5-45e5-a2fe-e2a0ed81b304.png)

如果您的库的用户已经打开了使用 Clang Tidy 进行静态分析，这可能是他们会收到的错误，即使他们的代码完全正常。如果您正在使用别人的库并遇到了这个问题，克服这个问题的一种方法是将库包含为系统包含，这告诉 Clang Tidy 等工具忽略这些错误。然而，这并不总是有效，因为有些库需要使用宏，这会将库的逻辑暴露给您自己的代码，导致混乱。一般来说，如果您是库开发人员，尽可能多地对您的库进行静态分析，因为您不知道您的用户可能如何使用您的库。

动态分析也是一样。前面的分析没有检测到明显的内存泄漏。为了识别这一点，我们可以使用`valgrind`，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/e501ffa7-bfb7-46d1-b2e1-38630c9e0921.png)

如前面的屏幕截图所示，`valgrind`能够检测到我们代码中的内存泄漏。实际上，`valgrind`还检测到我们在`universe()`函数中从未初始化临时变量的事实，但输出内容过于冗长，无法在此展示。再次强调，如果你未能识别出这些类型的问题，你最终会暴露这些错误给你的用户。

# 文档

文档对于任何良好的库来说都是绝对必要的。除了有 bug 的代码，缺乏文档也会绝对阻止其他人使用你的库。库应该易于设置和安装，甚至更容易学习和融入到你自己的应用程序中。使用现有的 C++库最令人沮丧的一点就是缺乏文档。

# CII 最佳实践

在这个示例中，我们涉及了一些所有库开发者都应该在其项目中应用的常见最佳实践。除了这些最佳实践，CII 最佳实践项目在这里提供了更完整的最佳实践清单：[`bestpractices.coreinfrastructure.org/en`](https://bestpractices.coreinfrastructure.org/en)。

CII 最佳实践项目提供了一个全面的最佳实践清单，随着时间的推移进行更新，库开发者（以及一般的应用程序）可以利用这些最佳实践。这些最佳实践分为通过、银和金三个级别，金级实践是最难实现的。你的得分越高，用户使用你的库的可能性就越大，因为这显示了承诺和稳定性。

# 学习如何使用 boost API

boost 库是一组设计用于与标准 C++库配合使用的库。事实上，目前由 C++提供的许多库都起源于 boost 库。boost 库提供了从容器、时钟和定时器到更复杂的数学 API，如图形和 CRC 计算等一切。在这个示例中，我们将学习如何使用 boost 库，特别是演示一个大型库的样子以及如何将这样的库包含在用户的项目中。这个示例很重要，因为它将演示一个库可以变得多么复杂，教会你如何相应地编写你自己的库。

# 准备工作

与本章中的所有示例一样，请确保已满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake libboost-all-dev
```

这将确保你的操作系统具有编译和执行本教程中示例所需的正确工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做到...

你需要执行以下步骤来完成这个示例：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter01
```

1.  要编译源代码，请运行以下代码：

```cpp
> mkdir build && cd build
> cmake ..
> make recipe05_examples
```

1.  源代码编译完成后，你可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe05_example01
Date/Time: 1553894555446451393 nanoseconds since Jan 1, 1970
> ./recipe05_example02
[2019-03-29 15:22:36.756819] [0x00007f5ee158b740] [debug] debug message
[2019-03-29 15:22:36.756846] [0x00007f5ee158b740] [info] info message
```

在接下来的部分，我们将逐个介绍这些例子，并解释每个示例程序的作用，以及它们与本教程中所教授的课程的关系。

# 工作原理...

boost 库提供了一组用户 API，实现了大多数程序中常用的功能。这些库可以包含在你自己的项目中，简化你的代码，并提供一个完成的库可能是什么样子的示例。为了解释你自己的库如何被他人利用，让我们看一些如何使用 boost 库的示例。

# 例子 1

在这个例子中，我们使用 boost API 将当前日期和时间输出到`stdout`，如下所示：

```cpp
#include <iostream>
#include <boost/chrono.hpp>

int main(void)
{
    using namespace boost::chrono;

    std::cout << "Date/Time: " << system_clock::now() << '\n';
    return 0;
}
```

如前面的示例所示，当前日期和时间以自 Unix 纪元（1970 年 1 月 1 日）以来的纳秒总数的形式被输出到`stdout`。除了在源代码中包含 boost，你还必须将你的应用程序链接到 boost 库。在这种情况下，我们需要链接到以下内容：

```cpp
-lboost_chrono -lboost_system -lpthread
```

如何完成这一步骤的示例可以在随这个示例一起下载的`CMakeLists.txt`文件中看到。一旦这些库被链接到你的项目中，你的代码就能够利用它们内部的 API。这个额外的步骤就是为什么仅包含头文件的库在创建自己的库时可以如此有用，因为它们消除了额外链接的需要。

# 示例 2

在这个例子中，我们演示了如何使用 boost 的 trivial logging APIs 来记录到控制台，如下所示：

```cpp
#include <boost/log/trivial.hpp>

int main(void)
{
    BOOST_LOG_TRIVIAL(debug) << "debug message";
    BOOST_LOG_TRIVIAL(info) << "info message";
    return 0;
}
```

如前面的示例所示，`"debug message"`和`"info message"`消息被输出到`stdout`。除了链接正确的 boost 库，我们还必须在编译过程中包含以下定义：

```cpp
-DBOOST_LOG_DYN_LINK -lboost_log -lboost_system -lpthread
```

再次，链接这些库可以确保你在代码中使用的 API（如前面的示例所示）存在于可执行文件中。

# 另请参阅

有关 boost 库的更多信息，请查看[`www.boost.org/`](https://www.boost.org/)。


# 第二章：使用异常处理错误

在本章中，我们将学习一些高级的 C++异常处理技术。我们在这里假设您已经基本了解如何抛出和捕获 C++异常。本章不是专注于 C++异常的基础知识，而是教会您一些更高级的 C++异常处理技术。这包括正确使用`noexcept`指定符和`noexcept`运算符，以便您可以正确地标记您的 API，要么可能抛出异常，要么明确地不抛出 C++异常，而是在发生无法处理的错误时调用`std::terminate()`。

本章还将解释术语**资源获取即初始化**（**RAII**）是什么，以及它如何补充 C++异常处理。我们还将讨论为什么不应该从类的析构函数中抛出 C++异常以及如何处理这些类型的问题。最后，我们将看看如何创建自己的自定义 C++异常，包括提供一些关于创建自己的异常时要做和不要做的基本准则。

从本章提供的信息中，您将更好地了解 C++异常在底层是如何工作的，以及可以用 C++异常做哪些事情来构建更健壮和可靠的 C++程序。

本章中的配方如下：

+   使用`noexcept`指定符

+   使用`noexcept`运算符

+   使用 RAII

+   学习为什么永远不要在析构函数中抛出异常

+   轻松创建自己的异常类

# 技术要求

要编译和运行本章中的示例，您必须具有对运行 Ubuntu 18.04 的计算机的管理访问权限，并且具有功能正常的互联网连接。在运行这些示例之前，您必须安装以下内容：

```cpp
sudo apt-get install build-essential git cmake
```

如果这是安装在 Ubuntu 18.04 以外的任何操作系统上，则需要 GCC 7.4 或更高版本和 CMake 3.6 或更高版本。

# 使用`noexcept`指定符

`noexcept`指定符用于告诉编译器一个函数是否可能抛出 C++异常。如果一个函数标记有`noexcept`指定符，它是不允许抛出异常的，如果抛出异常，将会调用`std::terminate()`。如果函数没有`noexcept`指定符，异常可以像平常一样被抛出。

在这个配方中，我们将探讨如何在自己的代码中使用`noexcept`指定符。这个指定符很重要，因为它是你正在创建的 API 和 API 的用户之间的一个合同。当使用`noexcept`指定符时，它告诉 API 的用户在使用 API 时不需要考虑异常。它还告诉作者，如果他们将`noexcept`指定符添加到他们的 API 中，他们必须确保不会抛出任何异常，这在某些情况下需要作者捕获所有可能的异常并处理它们，或者在无法处理异常时调用`std::terminate()`。此外，有一些操作，比如`std::move`，在这些操作中不能抛出异常，因为移动操作通常无法安全地被逆转。最后，对于一些编译器，将`noexcept`添加到你的 API 中将减少函数的总体大小，从而使应用程序的总体大小更小。

# 准备工作

开始之前，请确保满足所有的技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有正确的工具来编译和执行本配方中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

要尝试这个配方，请执行以下步骤：

1.  从新的终端中运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter02
```

1.  要编译源代码，请运行以下命令：

```cpp
> mkdir build && cd build
> cmake ..
> make recipe01_examples
```

1.  一旦源代码被编译，您可以通过运行以下命令来执行本食谱中的每个示例：

```cpp
> ./recipe01_example01
The answer is: 42

> ./recipe01_example02
terminate called after throwing an instance of 'std::runtime_error'
what(): The answer is: 42
Aborted

> ./recipe01_example03
The answer is: 42

> ./recipe01_example04
terminate called after throwing an instance of 'std::runtime_error'
what(): The answer is: 42
Aborted

> ./recipe01_example05
foo: 18446744069414584320
foo: T is too large
```

在下一节中，我们将逐个介绍这些例子，并解释每个示例程序的作用，以及它与本食谱中所教授的课程的关系。

# 它是如何工作的...

首先，让我们简要回顾一下 C++异常是如何抛出和捕获的。在下面的例子中，我们将从一个函数中抛出一个异常，然后在我们的`main()`函数中捕获异常：

```cpp
#include <iostream>
#include <stdexcept>

void foo()
{
    throw std::runtime_error("The answer is: 42");
}

int main(void)
{
    try {
        foo();
    }
    catch(const std::exception &e) {
        std::cout << e.what() << '\n';
    }

    return 0;
}
```

如前面的例子所示，我们创建了一个名为`foo()`的函数，它会抛出一个异常。这个函数在我们的`main()`函数中被调用，位于一个`try`/`catch`块中，用于捕获在`try`块中执行的代码可能抛出的任何异常，这种情况下是`foo()`函数。当`foo()`函数抛出异常时，它被成功捕获并输出到`stdout`。

所有这些都是因为我们没有向`foo()`函数添加`noexcept`说明符。默认情况下，函数允许抛出异常，就像我们在这个例子中所做的那样。然而，在某些情况下，我们不希望允许抛出异常，这取决于我们期望函数执行的方式。具体来说，函数如何处理异常可以定义为以下内容（称为异常安全性）：

+   **无抛出保证**：函数不能抛出异常，如果内部抛出异常，必须捕获和处理异常，包括分配失败。

+   **强异常安全性**：函数可以抛出异常，如果抛出异常，函数修改的任何状态都将被回滚或撤消，没有副作用。

+   **基本异常安全性**：函数可以抛出异常，如果抛出异常，函数修改的任何状态都将被回滚或撤消，但可能会有副作用。应该注意，这些副作用不包括不变量，这意味着程序处于有效的、非损坏的状态。

+   **无异常安全性**：函数可以抛出异常，如果抛出异常，程序可能会进入损坏的状态。

一般来说，如果一个函数具有无抛出保证，它会被标记为`noexcept`；否则，它不会。异常安全性如此重要的一个例子是`std::move`。例如，假设我们有两个`std::vector`实例，我们希望将一个向量移动到另一个向量中。为了执行移动，`std::vector`可能会将向量的每个元素从一个实例移动到另一个实例。如果在移动时允许对象抛出异常，向量可能会在移动过程中出现异常（也就是说，向量中的一半对象被成功移动）。当异常发生时，`std::vector`显然会尝试撤消已经执行的移动，将这些移回原始向量，然后返回异常。问题是，尝试将对象移回将需要`std::move()`，这可能再次抛出异常，导致嵌套异常。实际上，将一个`std::vector`实例移动到另一个实例并不实际执行逐个对象的移动，但调整大小会，而在这个特定问题中，标准库要求使用`std::move_if_noexcept`来处理这种情况以提供异常安全性，当对象的移动构造函数允许抛出时，会退回到复制。

`noexcept`说明符通过明确声明函数不允许抛出异常来解决这些问题。这不仅告诉 API 的用户他们可以安全地使用该函数，而不必担心抛出异常可能会破坏程序的执行，而且还迫使函数的作者安全地处理所有可能的异常或调用`std::terminate()`。尽管`noexcept`根据编译器的不同还提供了通过减少应用程序的整体大小来进行优化，但它的主要用途是说明函数的异常安全性，以便其他函数可以推断函数的执行方式。

在下面的示例中，我们为之前定义的`foo()`函数添加了`noexcept`说明符：

```cpp
#include <iostream>
#include <stdexcept>

void foo() noexcept
{
    throw std::runtime_error("The answer is: 42");
}

int main(void)
{
    try {
        foo();
    }
    catch(const std::exception &e) {
        std::cout << e.what() << '\n';
    }

    return 0;
}
```

当编译并执行此示例时，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/f99d2218-74b5-47f1-8108-6a38646732a8.png)

如前面的示例所示，添加了`noexcept`说明符，告诉编译器`foo()`不允许抛出异常。然而，`foo()`函数确实抛出异常，因此在执行时会调用`std::terminate()`。实际上，在这个示例中，`std::terminate()`总是会被调用，这是编译器能够检测并警告的事情。

显然调用`std::terminate()`并不是程序的期望结果。在这种特定情况下，由于作者已经将函数标记为`noexcept`，因此需要作者处理所有可能的异常。可以按照以下方式处理：

```cpp
#include <iostream>
#include <stdexcept>

void foo() noexcept
{
    try {
        throw std::runtime_error("The answer is: 42");
    }
    catch(const std::exception &e) {
        std::cout << e.what() << '\n';
    }
}

int main(void)
{
    foo();
    return 0;
}
```

如前面的示例所示，异常被包裹在`try`/`catch`块中，以确保在`foo()`函数完成执行之前安全地处理异常。此外，在这个示例中，只捕获了源自`std::exception()`的异常。这是作者表明可以安全处理哪些类型的异常的方式。例如，如果抛出的是整数而不是`std::exception()`，由于`foo()`函数添加了`noexcept`，`std::terminate()`仍然会自动执行。换句话说，作为作者，你只需要处理你确实能够安全处理的异常。其余的将被发送到`std::terminate()`；只需理解，这样做会改变函数的异常安全性。如果你打算定义一个不抛出异常的函数，那么该函数就不能抛出异常。

还需注意的是，如果将函数标记为`noexcept`，不仅需要关注自己抛出的异常，还需要关注可能抛出异常的函数。在这种情况下，`foo()`函数内部使用了`std::cout`，这意味着作者要么故意忽略`std::cout`可能抛出的任何异常，导致调用`std::terminate()`（这就是我们这里正在做的），要么作者需要确定`std::cout`可能抛出的异常，并尝试安全地处理它们，包括`std::bad_alloc`等异常。

如果提供的索引超出了向量的边界，`std::vector.at()`函数会抛出`std::out_of_range()`异常。在这种情况下，作者可以捕获这种类型的异常并返回默认值，从而可以安全地将函数标记为`noexcept`。

`noexcept`说明符还可以作为一个函数，接受一个布尔表达式，如下面的示例所示：

```cpp
#include <iostream>
#include <stdexcept>

void foo() noexcept(true)
{
    throw std::runtime_error("The answer is: 42");
}

int main(void)
{
    try {
        foo();
    }
    catch(const std::exception &e) {
        std::cout << e.what() << '\n';
    }

    return 0;
}
```

执行时会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/c75fc0ac-3445-4fe6-a20c-934b783a5d96.png)

如前面的示例所示，`noexcept`说明符被写为`noexcept(true)`。如果表达式求值为 true，则就好像提供了`noexcept`一样。如果表达式求值为 false，则就好像省略了`noexcept`说明符，允许抛出异常。在前面的示例中，表达式求值为 true，这意味着该函数不允许抛出异常，这导致在`foo()`抛出异常时调用`std::terminate()`。

让我们看一个更复杂的示例来演示如何使用它。在下面的示例中，我们将创建一个名为`foo()`的函数，它将一个整数值向左移 32 位并将结果转换为 64 位整数。这个示例将使用模板元编程来编写，允许我们在任何整数类型上使用这个函数：

```cpp
#include <limits>
#include <iostream>
#include <stdexcept>

template<typename T>
uint64_t foo(T val) noexcept(sizeof(T) <= 4)
{
    if constexpr(sizeof(T) <= 4) {
        return static_cast<uint64_t>(val) << 32;
    }

    throw std::runtime_error("T is too large");
}

int main(void)
{
    try {
        uint32_t val1 = std::numeric_limits<uint32_t>::max();
        std::cout << "foo: " << foo(val1) << '\n';

        uint64_t val2 = std::numeric_limits<uint64_t>::max();
        std::cout << "foo: " << foo(val2) << '\n';
    }
    catch(const std::exception &e) {
        std::cout << e.what() << '\n';
    }

    return 0;
}
```

执行时将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/182cbe31-a769-4160-884a-7f9445e380d2.png)

如前面的示例所示，`foo()`函数的问题在于，如果用户提供了 64 位整数，它无法进行 32 位的移位而不产生溢出。然而，如果提供的整数是 32 位或更少，`foo()`函数就是完全安全的。为了实现`foo()`函数，我们使用了`noexcept`说明符来声明如果提供的整数是 32 位或更少，则该函数不允许抛出异常。如果提供的整数大于 32 位，则允许抛出异常，在这种情况下是一个`std::runtime_error()`异常，说明整数太大无法安全移位。

# 使用 noexcept 运算符

`noexcept`运算符是一个编译时检查，用于询问编译器一个函数是否被标记为`noexcept`。在 C++17 中，这可以与编译时`if`语句配对使用（即在编译时评估的`if`语句，可用于根据函数是否允许抛出异常来改变程序的语义）来改变程序的语义。

在本教程中，我们将探讨如何在自己的代码中使用`noexcept`运算符。这个运算符很重要，因为在某些情况下，你可能无法通过简单地查看函数的定义来确定函数是否能够抛出异常。例如，如果一个函数使用了`noexcept`说明符，你的代码可能无法确定该函数是否会抛出异常，因为你可能无法根据函数的输入来确定`noexcept`说明符将求值为什么。`noexcept`运算符为你提供了处理这些情况的机制，这是至关重要的，特别是在元编程时。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有适当的工具来编译和执行本教程中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

按照以下步骤尝试本教程：

1.  从新的终端中，运行以下命令下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter02
```

1.  要编译源代码，请运行以下命令：

```cpp
> mkdir build && cd build
> cmake ..
> make recipe02_examples
```

1.  源代码编译后，可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe02_example01
could foo throw: true

> ./recipe02_example02
could foo throw: true
could foo throw: true
could foo throw: false
could foo throw: false

> ./recipe02_example03
terminate called after throwing an instance of 'std::runtime_error'
what(): The answer is: 42
Aborted

> ./recipe02_example04

> ./recipe02_example05
terminate called after throwing an instance of 'std::runtime_error'
what(): The answer is: 42
Aborted

> ./recipe02_example06
could foo throw: true
could foo throw: true
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本教程中所教授的课程的关系。

# 它是如何工作的...

`noexcept`运算符用于确定一个函数是否能够抛出异常。让我们从一个简单的示例开始：

```cpp
#include <iostream>
#include <stdexcept>

void foo()
{
    std::cout << "The answer is: 42\n";
}

int main(void)
{
    std::cout << std::boolalpha;
    std::cout << "could foo throw: " << !noexcept(foo()) << '\n';
    return 0;
}
```

这将导致以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/afafa314-071a-4aa9-8896-0c19d3282f99.png)

如前面的例子所示，我们定义了一个输出到`stdout`的`foo()`函数。我们实际上没有执行`foo()`，而是使用`noexcept`操作符来检查`foo()`函数是否可能抛出异常。如你所见，答案是肯定的；这个函数可能会抛出异常。这是因为我们没有用`noexcept`标记`foo()`函数，正如前面的例子所述，函数默认可以抛出异常。

还应该注意到我们在`noexcept`表达式中添加了`!`。这是因为如果函数被标记为`noexcept`，`noexcept`会返回`true`，这意味着函数不允许抛出异常。然而，在我们的例子中，我们询问的不是函数是否不会抛出异常，而是函数是否可能抛出异常，因此需要逻辑布尔反转。

让我们通过在我们的例子中添加一些函数来扩展这一点。具体来说，在下面的例子中，我们将添加一些会抛出异常的函数以及一些被标记为`noexcept`的函数：

```cpp
#include <iostream>
#include <stdexcept>

void foo1()
{
    std::cout << "The answer is: 42\n";
}

void foo2()
{
    throw std::runtime_error("The answer is: 42");
}

void foo3() noexcept
{
    std::cout << "The answer is: 42\n";
}

void foo4() noexcept
{
    throw std::runtime_error("The answer is: 42");
}

int main(void)
{
    std::cout << std::boolalpha;
    std::cout << "could foo throw: " << !noexcept(foo1()) << '\n';
    std::cout << "could foo throw: " << !noexcept(foo2()) << '\n';
    std::cout << "could foo throw: " << !noexcept(foo3()) << '\n';
    std::cout << "could foo throw: " << !noexcept(foo4()) << '\n';
    return 0;
}
```

结果如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/6c634422-311e-40ae-a7f8-e20aa940f7a4.png)

在前面的例子中，如果一个函数被标记为`noexcept`，`noexcept`操作符会返回`true`（在我们的例子中输出为`false`）。更重要的是，敏锐的观察者会注意到抛出异常的函数并不会改变`noexcept`操作符的输出。也就是说，如果一个函数*可以*抛出异常，`noexcept`操作符会返回`false`，而不是*会*抛出异常。这一点很重要，因为唯一能知道一个函数*会*抛出异常的方法就是执行它。`noexcept`指定符唯一说明的是函数是否允许抛出异常。它并不说明是否*会*抛出异常。同样，`noexcept`操作符并不能告诉你函数*会*抛出异常与否，而是告诉你函数是否被标记为`noexcept`（更重要的是，`noexcept`指定符的求值结果）。

在我们尝试在更现实的例子中使用`noexcept`指定符之前，让我们看下面的例子：

```cpp
#include <iostream>
#include <stdexcept>

void foo()
{
    throw std::runtime_error("The answer is: 42");
}

int main(void)
{
    foo();
}
```

如前面的例子所示，我们定义了一个会抛出异常的`foo()`函数，然后从我们的主函数中调用这个函数，导致调用`std::terminate()`，因为我们在离开程序之前没有处理异常。在更复杂的情况下，我们可能不知道`foo()`是否会抛出异常，因此可能不希望在不需要的情况下添加额外的异常处理开销。为了更好地解释这一点，让我们检查这个例子中`main()`函数的汇编代码：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/8741e7cf-194c-44e7-84c5-b48af8c04011.png)

如你所见，`main`函数很简单，除了调用`foo`函数外没有其他逻辑。具体来说，`main`函数中没有任何捕获逻辑。

现在，让我们在一个更具体的例子中使用`noexcept`操作符：

```cpp
#include <iostream>
#include <stdexcept>

void foo()
{
    throw std::runtime_error("The answer is: 42");
}

int main(void)
{
    if constexpr(noexcept(foo())) {
        foo();
    }
    else {
        try {
            foo();
        }
        catch (...)
        { }
    }
}
```

如前面的例子所示，我们在 C++17 中添加的`if`语句中使用了`noexcept`操作符和`constepxr`操作符。这使我们能够询问编译器`foo()`是否允许抛出异常。如果允许，我们在`try`/`catch`块中执行`foo()`函数，以便根据需要处理任何可能的异常。如果我们检查这个函数的汇编代码，如下面的截图所示，我们可以看到一些额外的`catch`逻辑被添加到生成的二进制文件中，以根据需要处理异常：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/49f6bfba-8bae-40ba-8987-e352f7b9625c.png)

现在，让我们进一步说明，使用`noexcept`指定符来声明`foo()`函数不允许抛出异常：

```cpp
#include <iostream>
#include <stdexcept>

void foo() noexcept
{
    throw std::runtime_error("The answer is: 42");
}

int main(void)
{
    if constexpr(noexcept(foo())) {
        foo();
    }
    else {
        try {
            foo();
        }
        catch (...)
        { }
    }
}
```

如前面的示例所示，程序调用了`std::terminate()`，因为`foo()`函数被标记为`noexcept`。此外，如果我们查看生成的汇编代码，我们可以看到`main()`函数不再包含额外的`try`/`catch`逻辑，这意味着我们的优化起作用了：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/2d0478f9-51e3-4438-b303-7d4872bf5a80.png)

最后，如果我们不知道被调用的函数是否会抛出异常，可能无法正确标记自己的函数。让我们看下面的例子来演示这个问题：

```cpp
#include <iostream>
#include <stdexcept>

void foo1()
{
    std::cout << "The answer is: 42\n";
}

void foo2() noexcept(noexcept(foo1()))
{
    foo1();
}

int main(void)
{
    std::cout << std::boolalpha;
    std::cout << "could foo throw: " << !noexcept(foo1()) << '\n';
    std::cout << "could foo throw: " << !noexcept(foo2()) << '\n';
}
```

这将导致以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/5c98505b-2992-4bc6-a927-e4eb3315fd00.png)

如前面的示例所示，`foo1()`函数没有使用`noexcept`指定符标记，这意味着它允许抛出异常。在`foo2()`中，我们希望确保我们的`noexcept`指定符是正确的，但我们调用了`foo1()`，在这个例子中，我们假设我们不知道`foo1()`是否是`noexcept`。

为了确保`foo2()`被正确标记，我们结合了本示例和上一个示例中学到的知识来正确标记函数。具体来说，我们使用`noexcept`运算符来告诉我们`foo1()`函数是否会抛出异常，然后我们使用`noexcept`指定符的布尔表达式语法来使用`noexcept`运算符的结果来标记`foo2()`是否为`noexcept`。如果`foo1()`被标记为`noexcept`，`noexcept`运算符将返回`true`，导致`foo2()`被标记为`noexcept(true)`，这与简单地声明`noexcept`相同。如果`foo1()`没有被标记为`noexcept`，`noexcept`运算符将返回`false`，在这种情况下，`noexcept`指定符将被标记为`noexcept(false)`，这与不添加`noexcept`指定符相同（即，函数允许抛出异常）。

# 使用 RAII

RAII 是一种编程原则，它规定资源与获取资源的对象的生命周期绑定。RAII 是 C++语言的一个强大特性，它真正有助于将 C++与 C 区分开来，有助于防止资源泄漏和一般不稳定性。

在这个示例中，我们将深入探讨 RAII 的工作原理以及如何使用 RAII 来确保 C++异常不会引入资源泄漏。RAII 对于任何 C++应用程序来说都是至关重要的技术，应该尽可能地使用。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 操作步骤...

您需要执行以下步骤来尝试这个示例：

1.  从新的终端中运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter02
```

1.  要编译源代码，请运行以下命令：

```cpp
> mkdir build && cd build
> cmake ..
> make recipe03_examples
```

1.  一旦源代码编译完成，您可以通过运行以下命令来执行本示例中的每个示例：

```cpp
> ./recipe03_example01
The answer is: 42

> ./recipe03_example02
The answer is: 42

> ./recipe03_example03
The answer is not: 43

> ./recipe03_example04
The answer is: 42

> ./recipe03_example05
step 1: Collect answers
The answer is: 42
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它们与本示例中所教授的课程的关系。

# 工作原理...

为了更好地理解 RAII 的工作原理，我们必须首先研究 C++中类的工作原理，因为 C++类用于实现 RAII。让我们看一个简单的例子。C++类提供了对构造函数和析构函数的支持，如下所示：

```cpp
#include <iostream>
#include <stdexcept>

class the_answer
{
public:
    the_answer()
    {
        std::cout << "The answer is: ";
    }

    ~the_answer()
    {
        std::cout << "42\n";
    }
};

int main(void)
{
    the_answer is;
    return 0;
}
```

这将导致编译和执行时的以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/1991efef-e0b0-48f0-9c36-1a62bfbec715.png)

在上面的例子中，我们创建了一个既有构造函数又有析构函数的类。当我们创建类的实例时，构造函数被调用，当类的实例失去作用域时，类被销毁。这是一个简单的 C++模式，自从 Bjarne Stroustrup 创建了最初的 C++版本以来一直存在。在底层，编译器在类首次实例化时调用一个构造函数，但更重要的是，编译器必须向程序注入代码，当类的实例失去作用域时执行析构函数。这里需要理解的重要一点是，这个额外的逻辑是由编译器自动为程序员插入的。

在引入类之前，程序员必须手动向程序添加构造和析构逻辑，而构造是一个相当容易做到正确的事情，但析构却不是。在 C 中这种问题的一个经典例子是存储文件句柄。程序员会添加一个调用`open()`函数来打开文件句柄，当文件完成时，会添加一个调用`close()`来关闭文件句柄，忘记在可能出现的所有错误情况下执行`close()`函数。这包括当代码有数百行长，而程序的新成员添加了另一个错误情况，同样忘记根据需要调用`close()`。

RAII 通过确保一旦类失去作用域，所获取的资源就会被释放，解决了这个问题，无论控制流路径是什么。让我们看下面的例子：

```cpp
#include <iostream>
#include <stdexcept>

class the_answer
{
public:

    int *answer{};

    the_answer() :
        answer{new int}
    {
        *answer = 42;
    }

    ~the_answer()
    {
        std::cout << "The answer is: " << *answer << '\n';
        delete answer;
    }
};

int main(void)
{
    the_answer is;

    if (*is.answer == 42) {
        return 0;
    }

    return 1;
}
```

在这个例子中，我们在类的构造函数中分配一个整数并对其进行初始化。这里需要注意的重要一点是，我们不需要从`new`运算符中检查`nullptr`。这是因为如果内存分配失败，`new`运算符会抛出异常。如果发生这种情况，不仅构造函数的其余部分不会被执行，而且对象本身也不会被构造。这意味着如果构造函数成功执行，你就知道类的实例处于有效状态，并且实际上包含一个在类的实例失去作用域时将被销毁的资源。

然后，类的析构函数输出到`stdout`并删除先前分配的内存。这里需要理解的重要一点是，无论代码采取什么控制路径，当类的实例失去作用域时，这个资源都将被释放。程序员只需要担心类的生命周期。

资源的生命周期与分配资源的对象的生命周期直接相关的这个想法很重要，因为它解决了在 C++异常存在的情况下程序的控制流的一个复杂问题。让我们看下面的例子：

```cpp
#include <iostream>
#include <stdexcept>

class the_answer
{
public:

    int *answer{};

    the_answer() :
        answer{new int}
    {
        *answer = 43;
    }

    ~the_answer()
    {
        std::cout << "The answer is not: " << *answer << '\n';
        delete answer;
    }
};

void foo()
{
    the_answer is;

    if (*is.answer == 42) {
        return;
    }

    throw std::runtime_error("");
}

int main(void)
{
    try {
        foo();
    }
    catch(...)
    { }

    return 0;
}
```

在这个例子中，我们创建了与上一个例子相同的类，但是在我们的`foo()`函数中，我们抛出了一个异常。然而，`foo()`函数不需要捕获这个异常来确保分配的内存被正确释放。相反，析构函数会为我们处理这个问题。在 C++中，许多函数可能会抛出异常，如果没有 RAII，每个可能抛出异常的函数都需要被包裹在`try`/`catch`块中，以确保任何分配的资源都被正确释放。事实上，在 C 代码中，我们经常看到这种模式，特别是在内核级编程中，使用`goto`语句来确保在函数内部，如果发生错误，函数可以正确地释放之前获取的任何资源。结果就是代码的嵌套，专门用于检查程序中每个函数调用的结果和正确处理错误所需的逻辑。

有了这种类型的编程模型，难怪资源泄漏在 C 中如此普遍。RAII 与 C++异常结合消除了这种容易出错的逻辑，从而使代码不太可能泄漏资源。

在 C++异常存在的情况下如何处理 RAII 超出了本书的范围，因为这需要更深入地了解 C++异常支持是如何实现的。重要的是要记住，C++异常比检查函数的返回值是否有错误更快（因为 C++异常是使用无开销算法实现的），但当实际抛出异常时速度较慢（因为程序必须解开堆栈并根据需要正确执行每个类的析构函数）。因此，出于这个原因以及其他原因，比如可维护性，C++异常不应该用于有效的控制流。

RAII 的另一种用法是`finally`模式，它由 C++ **指导支持库** (**GSL**) 提供。`finally`模式利用了 RAII 的仅析构函数部分，提供了一个简单的机制，在函数的控制流复杂或可能抛出异常时执行非基于资源的清理。考虑以下例子：

```cpp
#include <iostream>
#include <stdexcept>

template<typename FUNC>
class finally
{
    FUNC m_func;

public:
    finally(FUNC func) :
        m_func{func}
    { }

    ~finally()
    {
        m_func();
    }
};

int main(void)
{
    auto execute_on_exit = finally{[]{
        std::cout << "The answer is: 42\n";
    }};
}
```

在前面的例子中，我们创建了一个能够存储在`finally`类实例失去作用域时执行的 lambda 函数的类。在这种特殊情况下，当`finally`类被销毁时，我们输出到`stdout`。尽管这使用了类似于 RAII 的模式，但从技术上讲，这不是 RAII，因为没有获取任何资源。

此外，如果确实需要获取资源，应该使用 RAII 而不是`finally`模式。`finally`模式则在不获取资源但希望在函数返回时执行代码时非常有用（无论程序采取什么控制流路径，条件分支或 C++异常）。

为了证明这一点，让我们看一个更复杂的例子：

```cpp
#include <iostream>
#include <stdexcept>

template<typename FUNC>
class finally
{
    FUNC m_func;

public:
    finally(FUNC func) :
        m_func{func}
    { }

    ~finally()
    {
        m_func();
    }
};

int main(void)
{
    try {
        auto execute_on_exit = finally{[]{
            std::cout << "The answer is: 42\n";
        }};

        std::cout << "step 1: Collect answers\n";
        throw std::runtime_error("???");
        std::cout << "step 3: Profit\n";
    }
    catch (...)
    { }
}
```

执行时，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/974fa02a-a5bd-462b-aa43-3951b03d15dc.png)

在前面的例子中，我们希望无论代码做什么，都能始终输出到`stdout`。在执行过程中，我们抛出了一个异常，尽管抛出了异常，我们的`finally`代码仍然按预期执行。

# 学习为什么永远不要在析构函数中抛出异常

在这个食谱中，我们将讨论 C++异常的问题，特别是在类析构函数中抛出异常的问题，这是应该尽量避免的。这个食谱中学到的经验很重要，因为与其他函数不同，C++类析构函数默认标记为`noexcept`，这意味着如果你在类析构函数中意外地抛出异常，你的程序将调用`std::terminate()`，即使析构函数没有明确标记为`noexcept`。

# 准备工作

在开始之前，请确保满足所有的技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有适当的工具来编译和执行本食谱中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

执行以下步骤来尝试这个食谱：

1.  从新的终端中运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter02
```

1.  要编译源代码，请运行以下命令：

```cpp
> mkdir build && cd build
> cmake ..
> make recipe04_examples
```

1.  源代码编译完成后，您可以通过运行以下命令在本食谱中执行每个示例：

```cpp
> ./recipe04_example01
terminate called after throwing an instance of 'std::runtime_error'
what(): 42
Aborted

> ./recipe04_example02
The answer is: 42

> ./recipe04_example03
terminate called after throwing an instance of 'std::runtime_error'
what(): 42
Aborted

> ./recipe04_example04
# exceptions: 2
The answer is: 42
The answer is: always 42
```

在下一节中，我们将逐步介绍这些示例，并解释每个示例程序的作用以及它与本食谱中教授的课程的关系。

# 它是如何工作的...

在这个食谱中，我们将学习为什么在析构函数中抛出异常是一个*糟糕*的想法，以及为什么类析构函数默认标记为`noexcept`。首先，让我们看一个简单的例子：

```cpp
#include <iostream>
#include <stdexcept>

class the_answer
{
public:
    ~the_answer()
    {
        throw std::runtime_error("42");
    }
};

int main(void)
{
    try {
        the_answer is;
    }
    catch (const std::exception &e) {
        std::cout << "The answer is: " << e.what() << '\n';
    }
}
```

当我们执行这个时，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/3d30c668-41a6-430a-8fc4-a95a1da1f660.png)

在这个例子中，我们可以看到，如果我们从类析构函数中抛出异常，将调用`std::terminate()`。这是因为，默认情况下，类析构函数被标记为`noexcept`。

我们可以通过将类的析构函数标记为`noexcept(false)`来明确允许类析构函数抛出异常，就像下一个例子中所示的那样：

```cpp
#include <iostream>
#include <stdexcept>

class the_answer
{
public:
    ~the_answer() noexcept(false)
    {
        throw std::runtime_error("42");
    }
};

int main(void)
{
    try {
        the_answer is;
 }
    catch (const std::exception &e) {
        std::cout << "The answer is: " << e.what() << '\n';
    }
}
```

如前面的例子所示，当销毁类时，会抛出异常并得到正确处理。即使这个异常被成功处理了，我们仍然要问自己，在捕获这个异常后程序的状态是什么？析构函数并没有成功完成。如果这个类更复杂，并且有状态/资源需要管理，我们能否得出结论，我们关心的状态/资源是否得到了正确处理/释放？简短的答案是否定的。这就像用锤子摧毁硬盘一样。如果你用锤子猛击硬盘来摧毁它，你真的摧毁了硬盘上的数据吗？没有办法知道，因为当你用锤子猛击硬盘时，你损坏了本来可以用来回答这个问题的电子设备。当你试图销毁硬盘时，你需要一个可靠的过程，确保在任何情况下都不会使销毁硬盘的过程留下可恢复的数据。否则，你无法知道自己处于什么状态，也无法回头。

同样适用于 C++类。销毁 C++类必须是一个必须提供基本异常安全性的操作（即，程序的状态是确定性的，可能会有一些副作用）。否则，唯一的逻辑行为是调用`std::terminate()`，因为你无法确定程序继续执行会发生什么。

除了将程序置于未定义状态之外，从析构函数中抛出异常的另一个问题是，如果已经抛出了异常会发生什么？`try`/`catch`块会捕获什么？让我们看一个这种类型问题的例子：

```cpp
#include <iostream>
#include <stdexcept>

class the_answer
{
public:
    ~the_answer() noexcept(false)
    {
        throw std::runtime_error("42");
    }
};

int main(void)
{
    try {
        the_answer is;
        throw std::runtime_error("first exception");
    }
    catch (const std::exception &e) {
        std::cout << "The answer is: " << e.what() << '\n';
    }
}
```

在前面的例子中，我们像在前一个例子中一样将析构函数标记为`noexcept(false)`，但是在调用析构函数之前抛出异常，这意味着当调用析构函数时，已经有一个异常正在被处理。现在，当我们尝试抛出异常时，即使析构函数被标记为`noexcept(false)`，也会调用`std::terminate()`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/afeb2214-83a3-4320-bc7d-abea44492169.png)

这是因为 C++库无法处理这种情况，因为`try`/`catch`块无法处理多个异常。然而，可以有多个待处理的异常；我们只需要一个`try`/`catch`块来处理每个异常。当我们有嵌套异常时，就会出现这种情况，就像这个例子一样：

```cpp
#include <iostream>
#include <stdexcept>

class nested
{
public:
    ~nested()
    {
        std::cout << "# exceptions: " << std::uncaught_exceptions() << '\n';
    }
};

class the_answer
{
public:
    ~the_answer()
    {
        try {
            nested n;
            throw std::runtime_error("42");
        }
        catch (const std::exception &e) {
            std::cout << "The answer is: " << e.what() << '\n';
        }
    }
};
```

在这个例子中，我们将首先创建一个类，输出调用`std::uncaught_exceptions()`的结果，该函数返回当前正在处理的异常总数。然后我们将创建一个第二个类，创建第一个类，然后从其析构函数中抛出异常，重要的是要注意，析构函数中的所有代码都包裹在一个`try`/`catch`块中：

```cpp
int main(void)
{
    try {
        the_answer is;
        throw std::runtime_error("always 42");
    }
    catch (const std::exception &e) {
        std::cout << "The answer is: " << e.what() << '\n';
    }
}
```

当执行此示例时，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/afcfefea-5caa-45ba-8cb6-817eb3023c2f.png)

最后，我们将创建第二个类，并再次使用另一个`try`/`catch`块抛出异常。与前一个例子不同的是，所有的异常都被正确处理了，实际上，不需要`noexcept(false)`来确保这段代码的正常执行，因为对于每个抛出的异常，我们都有一个`try`/`catch`块。即使在析构函数中抛出了异常，它也被正确处理了，这意味着析构函数安全地执行并保持了`noexcept`的兼容性，即使第二个类在处理两个异常的情况下执行。

# 轻松创建自己的异常类

在本示例中，您将学习如何轻松创建自己的异常类型。这是一个重要的课程，因为尽管 C++异常很容易自己创建，但应遵循一些准则以确保安全地完成这些操作。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本示例所需的适当工具。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行示例。

# 如何做到...

按照以下步骤尝试本示例：

1.  从新的终端中运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter02
```

1.  要编译源代码，请运行以下命令：

```cpp
> mkdir build && cd build
> cmake ..
> make recipe05_examples
```

1.  源代码编译完成后，您可以通过运行以下命令来执行本示例中的每个示例：

```cpp
> ./recipe05_example01
The answer is: 42

> ./recipe05_example02
The answer is: 42

> ./recipe05_example03
The answer is: 42
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 工作原理...

创建自己的 C++异常允许您过滤出您所获得的异常类型。例如，异常是来自您的代码还是 C++库？通过创建自己的 C++异常，您可以在运行时轻松回答这些问题。让我们看下面的例子：

```cpp
#include <iostream>
#include <stdexcept>

class the_answer : public std::exception
{
public:
    the_answer() = default;
    const char *what() const noexcept
    {
        return "The answer is: 42";
    }
};

int main(void)
{
    try {
        throw the_answer{};
    }
    catch (const std::exception &e) {
        std::cout << e.what() << '\n';
    }
}
```

如上例所示，我们通过继承`std::exception`创建了自己的 C++异常。这不是必需的。从技术上讲，任何东西都可以是 C++异常，包括整数。然而，从`std::exception`开始，可以为您提供一个标准接口，包括重写`what()`函数，描述抛出的异常。

在上述示例中，我们在`what()`函数中返回了一个硬编码的字符串。这是理想的异常类型（甚至比 C++库提供的异常更理想）。这是因为这种类型的异常是`nothrow copy-constructable`。具体来说，这意味着异常本身可以被复制，而复制不会引发异常，例如由于`std::bad_alloc`。C++库提供的异常类型支持从`std::string()`构造，这可能会引发`std::bad_alloc`。

上述 C++异常的问题在于，您需要为每种消息类型提供`1`种异常类型。实现安全异常类型的另一种方法是使用以下方法：

```cpp
#include <iostream>
#include <stdexcept>

class the_answer : public std::exception
{
    const char *m_str;
public:

    the_answer(const char *str):
        m_str{str}
    { }

    const char *what() const noexcept
    {
        return m_str;
    }
};

int main(void)
{
    try {
        throw the_answer("42");
    }
    catch (const std::exception &e) {
        std::cout << "The answer is: " << e.what() << '\n';
    }
}
```

在上述示例中，我们存储了指向`const char*`（即 C 风格字符串）的指针。C 风格字符串作为常量存储在程序中。这种类型的异常满足了所有先前的规则，并且在构造异常期间不会发生任何分配。还应该注意，由于字符串是全局存储的，这种操作是安全的。

使用这种方法可以创建许多类型的异常，包括通过自定义 getter 访问的字符串以外的其他内容（即，无需使用`what()`函数）。然而，如果这些先前的规则对您不是问题，创建自定义 C++异常的最简单方法是简单地对现有的 C++异常进行子类化，例如`std::runtime_error()`，如下例所示：

```cpp
#include <iostream>
#include <stdexcept>
#include <string.h>

class the_answer : public std::runtime_error
{
public:
    explicit the_answer(const char *str) :
        std::runtime_error{str}
    { }
};

int main(void)
{
    try {
        throw the_answer("42");
    }
    catch (const the_answer &e) {
        std::cout << "The answer is: " << e.what() << '\n';
    }
    catch (const std::exception &e) {
        std::cout << "unknown exception: " << e.what() << '\n';
    }
}
```

当执行此示例时，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/a982b81c-4220-43df-82f3-73b32e54b2ae.png)

在上面的示例中，我们通过对`std::runtime_error()`进行子类化，仅用几行代码就创建了自己的 C++异常。然后，我们可以使用不同的`catch`块来确定抛出了什么类型的异常。只需记住，如果您使用`std::runtime_error()`的`std::string`版本，您可能会在异常本身的构造过程中遇到`std::bad_alloc`的情况。
