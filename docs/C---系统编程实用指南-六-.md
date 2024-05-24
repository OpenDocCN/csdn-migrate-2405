# C++ 系统编程实用指南（六）

> 原文：[`zh.annas-archive.org/md5/F0907D5DE5A0BFF31E8751590DCE27D9`](https://zh.annas-archive.org/md5/F0907D5DE5A0BFF31E8751590DCE27D9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：Unix 中的时间接口

在本章中，读者将学习如何使用 C++17 编程 POSIX 和 C++时间接口。首先，本章将介绍 UNIX 纪元和 POSIX `time.h` API 以及如何使用它们。接下来，将简要解释 C++ Chrono API，它们与`time.h`的关系，并提供一些示例。最后，本章将以两个简单的示例结束，演示如何使用时间接口。第一个示例将演示如何读取系统时钟并在间隔上将结果输出到控制台，第二个示例将演示如何使用 C++高分辨率计时器对软件进行基准测试。

在本章中，我们将涵盖以下主题：

+   学习 POSIX `time.h` API

+   C++ Chrono API

+   通过示例了解读取系统时钟

+   涉及高分辨率计时器的示例

# 技术要求

为了编译和执行本章中的示例，读者必须具备以下条件：

+   能够编译和执行 C++17 的基于 Linux 的系统（例如，Ubuntu 17.10+）

+   GCC 7+

+   CMake 3.6+

+   互联网连接

要下载本章中的所有代码，包括示例和代码片段，请访问以下链接：[`github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/tree/master/Chapter11`](https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/tree/master/Chapter11)。

# 学习 POSIX `time.h` API

我们将从讨论 POSIX `time.h` API 开始，该 API 提供了用于读取各种时钟并对这些时钟时间进行计算的 API。尽管这些 API 特定于标准 C，但如下一节所示，当使用 C++时仍然需要 C 时间接口，这是 C++20 正在解决的问题。

# 学习有关 API 类型

UNIX 纪元定义了从 1970 年 1 月 1 日起的秒数。本章描述的接口利用 UNIX 纪元来定义时间的概念。本章中描述的 POSIX `time.h` API 定义了三种不同的不透明类型：

+   `tm`：一个不透明的结构，保存日期和时间。

+   `time_t`：一个`typedef`，通常使用存储从 UNIX 纪元起的秒数的整数来实现。

+   `clock_t`：一个`typedef`，用于存储应用程序执行的处理器时间量。

这些 API 提供了各种函数来创建这些类型并对其进行操作。应该注意，有不同类型的时钟：

+   **系统时钟**：系统时钟读取操作系统维护的时钟，并存储向用户呈现的日期和时间（例如，任务栏上显示的时钟）。这个时钟可以在任何时间改变，因此通常不建议在应用程序中使用它进行计时，因为所使用的时钟可能以意想不到的方式向后/向前移动。

+   **稳定时钟**：稳定时钟是程序执行时会滴答作响的时钟。程序执行得越多，这个时钟就会变得越大。应该注意，这个时钟不会与系统时钟的结果匹配，通常只有两个这些时钟之间的差异才有真正的价值。

+   **高分辨率时钟**：这与稳定时钟相同，唯一的区别是返回的结果具有更高的分辨率。这些类型的时钟通常用于基准测试。

# `time()` API

`time()` API 返回当前系统时钟，并采用以下形式：

```cpp
time_t time(time_t *arg);
```

您可以使用预先定义的`time_t`变量提供`time()`函数，或者它将为您返回一个（如果您将`nullptr`作为参数传递），如下所示：

```cpp
#include <ctime>
#include <iostream>

int main()
{
    auto t = time(nullptr);
    std::cout << "time: " << t << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: 1531603643
```

在前面的例子中，我们使用`time()` API 创建一个名为`t`的变量，以获取从 UNIX 纪元开始的当前秒数。然后将这个值输出到`stdout`。应该注意，`time_t` typedef 通常使用整数值实现，这就是为什么我们可以直接将其值输出到`stdout`的原因，就像前面的例子中所示的那样。

正如所述，也可以像下面这样使用`time()`提供自己之前定义的变量：

```cpp
#include <ctime>
#include <iostream>

int main()
{
    time_t t;
    time(&t);
    std::cout << "time: " << t << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: 1531603652
```

前面的例子与第一个例子相同，但是不是存储`time()`的返回值，而是将我们的`time_t`变量作为参数传递给函数。虽然这种语法是支持的，但前者更受青睐。`time()`在出现错误时会返回`-1`，可以根据需要进行检查和处理。

# `ctime()` typedef

`time_t` typedef 是特定于实现的，尽管它通常使用存储从 Unix 纪元开始的秒数的整数实现，但不能保证这种情况，这意味着前面的例子可能不会编译。相反，要以支持的方式输出`time_t`变量的值，使用`ctime()` API，形式如下：

```cpp
char* ctime(const time_t* time);
```

`ctime()` API 接受一个指向`time_t`变量的指针，并输出一个标准的 C 字符串。返回的字符串所使用的内存由`time.h` API 维护（因此不需要被释放），因此不是线程安全的。可以如下使用这个 API：

```cpp
#include <ctime>
#include <iostream>

int main()
{
    auto t = time(nullptr);
    std::cout << "time: " << ctime(&t);
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: Sat Jul 14 15:27:44 2018
```

从前面的例子可以看出，返回的不是从 Unix 纪元开始的秒数，而是当前时间和日期的可读版本。还应该注意的是，除了`ctime()`函数不是线程安全的之外，它也没有提供调整输出格式的机制。因此，通常不鼓励使用这个函数，而是使用其他`time.h`函数。

# `localtime()`和`gmtime()` API

`time()` API 返回一个存储从 Unix 纪元开始的秒数的`time_t`值，正如前面所述。这个值可以进一步处理以暴露日期和时间信息，使我们能够将日期和时间转换为本地时间或**格林尼治标准时间**（**GMT**）。为此，POSIX API 提供了`localtime()`和`gmtime()`函数，形式如下：

```cpp
struct tm *localtime( const time_t *time );
struct tm *gmtime( const time_t *time );
```

这两个函数都接受一个指向`time_t`变量的指针，并返回一个指向`tm`不透明结构的指针。应该注意，返回值指向的结构像`ctime()`一样由`time.h`实现管理，因此不会被用户释放，这意味着这个函数的结果不是线程安全的。

# `asctime()`函数

要将不透明的`tm`结构输出到`stdout`（或者一般来说，只是将结构转换为标准的 C 字符串），POSIX API 提供了`asctime()`函数，形式如下：

```cpp
char* asctime( const struct tm* time_ptr );
```

`asctime()`函数的形式与`ctime()`相同，唯一的区别是主要参数是指向`tm`结构的指针，而不是`time_t`变量，如下所示：

```cpp
#include <ctime>
#include <iostream>

int main()
{
    auto t = time(nullptr);
    std::cout << "time: " << asctime(localtime(&t));
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: Sat Jul 14 15:28:59 2018
```

如前面的例子所示，`ctime()`和`asctime(localtime())`的输出没有区别。要输出 GMT 时间而不是本地时间，使用以下方式：

```cpp
#include <ctime>
#include <iostream>

int main()
{
    auto t = time(nullptr);
    std::cout << "time: " << asctime(gmtime(&t));
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: Sat Jul 14 21:46:12 2018
```

如前面的例子所示，`gmtime()`和`localtime()`执行相同，唯一的区别是时区的改变。

# `strftime()`函数

到目前为止，`ctime()`和`asctime()`的输出是由 POSIX API 预先确定的。也就是说，没有办法控制输出格式。此外，这些函数返回内部内存，阻止了它们的线程安全性。为了解决这些问题，POSIX API 添加了`strftime()`函数，这是将不透明的`tm`结构转换为字符串的推荐 API，形式如下：

```cpp
size_t strftime(char * str, size_t count, const char *format, const struct tm *time);
```

`str`参数接受预分配的标准 C 字符串，而`count`参数定义第一个参数的大小。`format`参数接受一个以空字符结尾的标准 C 字符串，定义要将日期和时间转换为的格式，而最终的`time`参数接受不透明的`tm`结构以转换为字符串。提供给此函数的格式字符串类似于提供给其他 POSIX 函数的格式字符串，例如`printf()`。接下来的几个示例将演示一些这些格式说明符。

为了演示`strftime()`函数，以下将当前日期输出到`stdout`：

```cpp
#include <ctime>
#include <iostream>

int main()
{
    auto t = time(nullptr);

    char buf[256]{};
    strftime(buf, sizeof(buf), "%m/%d/%Y", localtime(&t));

    std::cout << "time: " << buf << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: 07/14/2018
```

如前面的例子所示，`time()` API 用于获取当前日期和时间。`localtime()`函数用于将`time()`的结果（即`time_t`）转换为表示本地日期和时间的不透明`tm`结构。得到的`tm`结构传递给`strftime()`，格式字符串为`"%m/%d/%Y"`，将*月/日/年*输出到提供的标准 C 字符串。最后，将此字符串输出到`stdout`，结果为`07/14/2018`。

同样，此函数可用于输出当前时间：

```cpp
#include <ctime>
#include <iostream>

int main()
{
    auto t = time(nullptr);

    char buf[256]{};
    strftime(buf, sizeof buf, "%H:%M", localtime(&t));

    std::cout << "time: " << buf << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: 15:41
```

前面的例子与上一个例子相同，唯一的区别是格式说明符是`％H：％M`，表示`小时：分钟`，结果为`15:41`。

最后，要输出与`ctime()`和`asctime()`相同的字符串，请使用以下示例：

```cpp
#include <ctime>
#include <iostream>

int main()
{
    auto t = time(nullptr);

    char buf[256]{};
    strftime(buf, sizeof buf, "%a %b %d %H:%M:%S %Y", localtime(&t));

    std::cout << "time: " << buf << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: Sat Jul 14 15:44:57 2018
```

前面的例子与前两个例子相同，唯一的区别是格式说明符为`"%a %b %d %H:%M:%S %Y"`，输出与`ctime()`和`asctime()`相同的结果。

# difftime()函数

从技术上讲，`time_t` typedef 被认为是不透明的（尽管在 Unix 系统上几乎总是一个带符号的 32 位整数）。因此，为了确定两个`time_t`值之间的差异，提供了`difftime()`函数，如下所示：

```cpp
double difftime(time_t time_end, time_t time_beg);
```

`difftime()`函数接受两个`time_t`值，并将差异作为双精度返回（因为非 POSIX 函数可能支持分数时间）：

```cpp
#include <ctime>
#include <iostream>

#include <unistd.h>

int main()
{
    auto t1 = time(nullptr);
    sleep(2);
    auto t2 = time(nullptr);

    std::cout << "diff: " << difftime(t2, t1) << '\n';
    std::cout << "diff: " << t2 - t1 << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// diff: 2
```

如前面的例子所示，`difftime()`函数返回两个时间之间的差异。应该注意的是，尽管前面的代码在大多数系统上都可以编译，但应该使用`difftime()`而不是直接减去两个值的第二个示例。

# mktime()函数

如果您有两个不透明的`tm`结构，并希望计算它们的差异怎么办？问题在于`difftime()`函数只接受`time_t`而不是`tm`结构。为了支持`localtime()`和`gmtime()`函数的反向操作，它们将`time_t`转换为`tm`结构，`mktime()`函数将`tm`结构转换回`time_t`值，如下所示：

```cpp
time_t mktime(struct tm *time);
```

`mktime()`函数接受一个参数，即您希望将其转换为`time_t`值的不透明`tm`结构：

```cpp
#include <ctime>
#include <iostream>

int main()
{
    auto t1 = time(nullptr);
    auto lt = localtime(&t1);
    auto t2 = mktime(lt);

    std::cout << "time: " << ctime(&t2);
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: Sat Jul 14 16:00:13 2018
```

前面的例子使用`time()` API 获取当前时间和日期，并使用`localtime()` API 将结果转换为`tm`结构。然后将得到的`tm`结构转换回`time_t`值，使用`mktime()`输出结果到`stdout`使用`ctime()`。

# clock()函数

到目前为止，`time()`已用于获取当前系统日期和时间。这种类型的时钟的问题在于它返回操作系统管理的与当前日期和时间相关的值，这可以在任何时间点发生变化（例如，用户可能在不同时区之间飞行）。例如，如果您使用时间 API 来跟踪某个操作执行了多长时间，这可能是一个问题。在这种情况下，当时区发生变化时，使用`time()`的应用程序可能会记录经过的时间为负数。

为了解决这个问题，POSIX 提供了`clock()`函数，如下所示：

```cpp
clock_t clock(void);
```

`clock()` API 返回一个`clock_t`值，它类似于`time_t`值。`time()`和`clock()`之间的区别在于，`time()`返回当前系统时间，而`clock()`返回一个代表自应用程序启动以来经过的总时间的值，例如：

```cpp
#include <ctime>
#include <iostream>

int main()
{
    std::cout << "clock: " << clock() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// clock: 2002
```

在上面的例子中，`clock()`的结果输出到`stdout`。如图所示，该值是特定于实现的，只有两个`clock_t`值之间的差异才有意义。要将`clock_t`转换为秒，POSIX 提供了`CLOCKS_PER_SEC`宏，它提供了必要的转换，如下例所示：

```cpp
#include <ctime>
#include <iostream>

#include <unistd.h>

int main()
{
    auto c1 = clock();
    sleep(2);
    auto c2 = clock();

    std::cout << "clock: " <<
        static_cast<double>(c2 - c1) / CLOCKS_PER_SEC << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// clock: 3.2e-05
```

在上面的例子中，使用`clock()`API 获取第一个时钟值，然后应用程序睡眠两秒。一旦操作系统再次执行应用程序，就会再次读取时钟值，并将差异转换为毫秒，使用`CLOCKS_PER_SEC`（然后乘以 1,000）。请注意，该值不等于 2,000 毫秒。这是因为应用程序在睡眠时不记录执行时间，因此`clock()`只能看到应用程序的执行时间。

为了更好地展示时间的差异，以下示例演示了`clock()`和`time()`的一对一比较：

```cpp
#include <ctime>
#include <iostream>

#include <unistd.h>

int main()
{
    auto c1 = clock();

    auto t1 = time(nullptr);
    while(time(nullptr) - t1 <= 2);

    auto c2 = clock();

    std::cout << "clock: " <<
        static_cast<double>(c2 - c1) / CLOCKS_PER_SEC << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// clock: 2.05336
```

上面的例子与前面的例子相同，唯一的区别是我们使用`time()`旋转两秒，而不是睡眠两秒，导致`clock()`返回两秒。

# 探索 C++ Chrono API

C++包括 Chrono API，大多数情况下提供了对 POSIX `time.h` API 的 C++包装。因此，仍然需要一些 time.h 函数来提供完整的功能，包括转换为标准 C 字符串。值得注意的是，尽管在 C++17 中进行了一些添加（特别是`floor()`、`ceil()`和`round()`），但随着 C++20 的引入，Chrono API 预计会进行相当大的改进，这超出了本书的范围。因此，本节简要解释了 C++ Chrono API，以提供当前 API 的概述。

# system_clock() API

`std::chrono::system_clock{}` API 类似于`time()`，它能够获取系统时钟。`system_clock{}`也是唯一能够转换为`time_t`的时钟（因为它很可能是使用`time()`实现的），如下例所示：

```cpp
#include <chrono>
#include <iostream>

int main()
{
    auto t = std::chrono::system_clock::now();
    std::cout << "time: " << std::chrono::system_clock::to_time_t(t) << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: 1531606644
```

在上面的例子中，使用`system_clock::now()`API 读取当前系统时钟，并使用`system_clock::to_time_t()`API 将结果转换为`time_t`值。与前面的例子一样，结果是从 Unix 纪元开始的秒数。

# time_point API

`system_clock::now()` API 的结果是一个`time_point{}`。C++没有提供将`time_point{}`转换为字符串的函数（直到 C++20 才会提供），因此仍然需要使用前面讨论过的 POSIX 函数来执行这种转换，如下所示：

```cpp
#include <chrono>
#include <iostream>

template<typename C, typename D>
std::ostream &
operator<<(std::ostream &os, std::chrono::time_point<C,D> &obj)
{
    auto t = std::chrono::system_clock::to_time_t(obj);
    return os << ctime(&t);
}

int main()
{
    auto now = std::chrono::system_clock::now();
    std::cout << "time: " << now;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: Sat Jul 14 19:01:55 2018
```

在上面的例子中，我们首先为`std::chrono::system_clock::now()`API 的结果`time_point{}`定义了一个用户定义的重载。这个用户定义的重载使用 C++的`std::chrono::system_clock::to_time_t()`API 将`time_point{}`转换为`time_t`值，然后使用`ctime()`将`time_t`转换为标准 C 字符串，并将结果流式输出到`stdout`。

与 POSIX `time.h` API 不同，Chrono 库提供了各种函数来使用 C++运算符重载对`time_point{}`进行递增、递减和比较，如下所示：

```cpp
#include <chrono>
#include <iostream>

template<typename C, typename D>
std::ostream &
operator<<(std::ostream &os, const std::chrono::time_point<C,D> &obj)
{
    auto t = std::chrono::system_clock::to_time_t(obj);
    return os << ctime(&t);
}

int main()
{
    using namespace std::chrono;

    auto now = std::chrono::system_clock::now();

    std::cout << "time: " << now;

    now += 1h;
    std::cout << "time: " << now;

    now -= 1h;
    std::cout << "time: " << now;
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: 1531606644
```

在上面的例子中，提供了`time_point{}`的用户定义重载，与前面的例子一样。使用`std::chrono::system_clock::now()`读取当前日期和时间，并将结果输出到`stdout`。最后，将得到的`time_point{}`增加一个小时，然后减少一个小时（使用小时字面量），并将结果也输出到`stdout`。

此外，还支持算术比较，如下所示：

```cpp
#include <chrono>
#include <iostream>

int main()
{
    auto now1 = std::chrono::system_clock::now();
    auto now2 = std::chrono::system_clock::now();

    std::cout << std::boolalpha;
    std::cout << "compare: " << (now1 < now2) << '\n';
    std::cout << "compare: " << (now1 > now2) << '\n';
    std::cout << "compare: " << (now1 <= now2) << '\n';
    std::cout << "compare: " << (now1 >= now2) << '\n';
    std::cout << "compare: " << (now1 == now2) << '\n';
    std::cout << "compare: " << (now1 != now2) << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// compare: true
// compare: false
// compare: true
// compare: false
// compare: false
// compare: true
```

在上面的例子中，系统时钟被读取两次，然后使用支持的比较运算符比较得到的`time_point{}`值。应该注意，这个例子的结果可能因执行代码的系统不同而不同，因为时间的分辨率可能不同。

# 持续时间

`time_point{}`类型提供了增加、减少、执行加法和减法的算术运算。所有这些算术运算都是使用 C++ Chrono `duration{}`完成的，它定义了一段时间。另一种看待`duration{}`的方式是它将是 POSIX `difftime()`调用的结果抽象。事实上，两个`time_point{}`类型的减法结果是一个`duration{}`。

在前面的例子中，`time_point{}`使用*小时*持续时间字面量增加和减少了一个小时。与小时字面量类似，C++还为时间持续时间提供了以下字面量，可用于此类算术运算：

+   **小时**：*h*

+   **分钟**：*min*

+   **秒**：*s*

+   **毫秒**：*ms*

+   **微秒**：*us*

+   **纳秒**：*ns*

持续时间具有相对复杂的模板结构，超出了本书的范围，用于定义它们的分辨率（即持续时间是以秒、毫秒还是小时为单位），并且在技术上可以以几乎任何分辨率进行。尽管存在这种功能，但 C++提供了一些预定义的辅助程序，用于将一种持续时间转换为另一种，从而避免您需要了解`duration{}`的内部工作方式：

+   `std::chrono::nanoseconds`

+   `std::chrono::microseconds`

+   `std::chrono::milliseconds`

+   `std::chrono::seconds`

+   `std::chrono::minutes`

+   `std::chrono::hours `

例如，下面我们将使用这些预定义的辅助程序将系统时钟转换为秒和毫秒：

```cpp
#include <chrono>
#include <iostream>

#include <unistd.h>

int main()
{
    using namespace std::chrono;

    auto now1 = system_clock::now();
    sleep(2);
    auto now2 = system_clock::now();

    std::cout << "time: " <<
        duration_cast<seconds>(now2 - now1).count() << '\n';

    std::cout << "time: " <<
        duration_cast<milliseconds>(now2 - now1).count() << '\n';

    std::cout << "time: " <<
        duration_cast<nanoseconds>(now2 - now1).count() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: 2
// time: 2001
// time: 2001415132
```

在上面的例子中，系统时钟被读取两次，每次读取之间间隔两秒的睡眠。然后将得到的`time_point{}`值相减以创建一个`duration{}`，并将得到的`duration{}`转换为秒、毫秒和纳秒，结果使用`count()`成员函数输出到`stdout`，该函数简单地返回`duration{}`的值。

与`time_point{}`一样，持续时间也可以使用算术运算进行操作，如下所示：

```cpp
#include <chrono>
#include <iostream>

int main()
{
    using namespace std::chrono;

    seconds t(42);

    t++;
    std::cout << "time: " << t.count() << '\n';

    t--;
    std::cout << "time: " << t.count() << '\n';

    t += 1s;
    std::cout << "time: " << t.count() << '\n';

    t -= 1s;
    std::cout << "time: " << t.count() << '\n';

    t %= 2s;
    std::cout << "time: " << t.count() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: 43
// time: 42
// time: 43
// time: 42
// time: 0
```

在上面的例子中，创建了两个代表一秒的`duration{}`变量，一个值为`0`秒，另一个值为`42`秒。然后对第一个持续时间进行算术运算，并将结果输出到`stdout`。

此外，还支持比较：

```cpp
#include <chrono>
#include <iostream>

int main()
{
    using namespace std::chrono;

    auto t1 = 0s;
    auto t2 = 42s;

    std::cout << std::boolalpha;
    std::cout << "compare: " << (t1 < t2) << '\n';
    std::cout << "compare: " << (t1 > t2) << '\n';
    std::cout << "compare: " << (t1 <= t2) << '\n';
    std::cout << "compare: " << (t1 >= t2) << '\n';
    std::cout << "compare: " << (t1 == t2) << '\n';
    std::cout << "compare: " << (t1 != t2) << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// compare: true
// compare: false
// compare: true
// compare: false
// compare: false
// compare: true
```

在上面的例子中，创建了两个分别代表`0`秒和`42`秒的持续时间，并使用比较运算符进行比较。

大多数对 Chrono 库的修改可能会在 C++20 中进行，大量的 API 将被添加以解决现有 API 的明显缺陷。然而，在 C++17 中，`floor()`、`ceil()`、`round()`和`abs()` API 被添加到了 Chrono API 中，它们返回持续时间的 floor、ceil、round 或绝对值，如下例所示（类似的 API 也被添加到了`time_point{}`类型中）：

```cpp
#include <chrono>
#include <iostream>

int main()
{
    using namespace std::chrono;

    auto s1 = -42001ms;

    std::cout << "floor: " << floor<seconds>(s1).count() << '\n';
    std::cout << "ceil: " << ceil<seconds>(s1).count() << '\n';
    std::cout << "round: " << round<seconds>(s1).count() << '\n';
    std::cout << "abs: " << abs(s1).count() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// floor: -43
// ceil: -42
// round: -42
// abs: 42001
```

# 稳定时钟函数

`system_clock{}`类似于`time()`，而`steady_clock{}`类似于`clock()`，并且执行相同的目标——提供一个代表应用程序执行时间的时钟，而不考虑当前系统日期和时间（这可能会根据系统用户而改变）；例如：

```cpp
#include <chrono>
#include <iostream>

#include <unistd.h>

int main()
{
    using namespace std::chrono;

    auto now1 = steady_clock::now();
    sleep(2);
    auto now2 = steady_clock::now();

    std::cout << "time: " <<
        duration_cast<seconds>(now2 - now1).count() << '\n';

    std::cout << "time: " <<
        duration_cast<milliseconds>(now2 - now1).count() << '\n';

    std::cout << "time: " <<
        duration_cast<nanoseconds>(now2 - now1).count() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: 2
// time: 2001
// time: 2001447628
```

在上面的示例中，`steady_clock::now()`函数被调用两次，两次调用之间有一个睡眠。然后将得到的值相减，转换为秒、毫秒和纳秒，并将结果输出到`stdout`。需要注意的是，与`clock()`不同，得到的稳定时钟考虑了应用程序休眠的时间。

# 高分辨率时钟函数

在大多数系统上，`high_resolution_clock{}`和`steady_clock{}`是相同的。一般来说，`high_resolution_clock{}`代表最高分辨率的稳定时钟，并且如下例所示，与`stead_clock{}`的结果相同：

```cpp
#include <chrono>
#include <iostream>

#include <unistd.h>

int main()
{
    using namespace std::chrono;

    auto now1 = high_resolution_clock::now();
    sleep(2);
    auto now2 = high_resolution_clock::now();

    std::cout << "time: " <<
        duration_cast<seconds>(now2 - now1).count() << '\n';

    std::cout << "time: " <<
        duration_cast<milliseconds>(now2 - now1).count() << '\n';

    std::cout << "time: " <<
        duration_cast<nanoseconds>(now2 - now1).count() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp; ./a.out
// time: 2
// time: 2000
// time: 2002297281
```

在上面的示例中，`high_resolution_clock::now()`函数被调用两次，两次调用之间有一个睡眠。然后将得到的值相减，转换为秒、毫秒和纳秒，并将结果输出到`stdout`。

# 研究读取系统时钟的示例

在这个示例中，我们将把本章学到的所有内容融入到一个简单的演示中，该演示按用户指定的间隔读取系统时钟。为了实现这一点，需要以下包含和命名空间：

```cpp
#include <chrono>
#include <iostream>

#include <gsl/gsl>

#include <unistd.h>

using namespace std::chrono;
```

与本章中的其他示例一样，提供了一个用户定义的`std::ostream{}`重载，将`time_point{}`转换为标准 C 字符串，然后将结果流式输出到`stdout`：

```cpp
template<typename C, typename D>
std::ostream &
operator<<(std::ostream &os, std::chrono::time_point<C,D> &obj)
{
    auto t = std::chrono::system_clock::to_time_t(obj);
    return os << ctime(&t);
}
```

在我们的`protected_main()`函数中（这是本书中使用的一种模式），我们按用户提供的间隔输出当前系统时间，如下所示：

```cpp
int
protected_main(int argc, char **argv)
{
    using namespace std::chrono;
    auto args = gsl::make_span(argv, argc);

    if (args.size() != 2) {
        std::cerr << "wrong number of arguments\n";
        ::exit(1);
    }

    gsl::cstring_span<> arg = gsl::ensure_z(args.at(1));

    while(true) {
        auto now = std::chrono::system_clock::now();
        std::cout << "time: " << now;

        sleep(std::stoi(arg.data()));
    }
}
```

在上面的代码中，我们将参数列表转换为`gsl::span{}`，然后确保我们提供了一个参数。如果没有提供参数，我们就退出程序。然后将参数转换为`cstring_span{}`，并启动一个无限循环。在循环中，读取系统时钟并将其输出到`stdout`，然后程序休眠用户提供的时间：

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

与我们所有的示例一样，`protected_main()`函数由`main()`函数执行，如果发生异常，`main()`函数会捕获异常。

# 编译和测试

要编译这段代码，我们利用了与其他示例相同的`CMakeLists.txt`文件：[`github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/blob/master/Chapter11/CMakeLists.txt`](https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/blob/master/Chapter11/CMakeLists.txt)。

有了这段代码，我们可以使用以下命令编译这段代码：

```cpp
> git clone https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP.git
> cd Hands-On-System-Programming-with-CPP/Chapter10/
> mkdir build
> cd build

> cmake ..
> make
```

要执行这个示例，运行以下命令：

```cpp
> ./example1 2
time: Sun Jul 15 15:04:41 2018
time: Sun Jul 15 15:04:43 2018
time: Sun Jul 15 15:04:45 2018
time: Sun Jul 15 15:04:47 2018
time: Sun Jul 15 15:04:49 2018
```

如前面的片段所示，示例以两秒的间隔运行，并且应用程序每两秒将系统时钟输出到控制台。

# 研究高分辨率定时器的示例

在这个示例中，我们将使用`high_resolution_clock{}`创建一个简单的基准测试。为了实现这一点，需要以下包含和命名空间：

```cpp
#include <chrono>
#include <iostream>

#include <gsl/gsl>
```

要创建一个`benchmark`函数，我们使用以下内容：

```cpp
template<typename FUNC>
auto benchmark(FUNC func) {
    auto stime = std::chrono::high_resolution_clock::now();
    func();
    auto etime = std::chrono::high_resolution_clock::now();

    return etime - stime;
}
```

这个函数在第八章中已经见过，*学习文件输入/输出编程*，日志示例。这段代码利用函数式编程将一个函数调用（可能是一个 lambda）包装在两次高分辨率时钟调用之间。然后相减并返回结果。正如我们在本章中学到的，`high_resolution_clock{}`返回一个`time_point{}`，它们的差值创建一个`duration{}`。

`protected_main()`函数的实现如下：

```cpp
int
protected_main(int argc, char **argv)
{
    using namespace std::chrono;

    auto args = gsl::make_span(argv, argc);

    if (args.size() != 2) {
        std::cerr << "wrong number of arguments\n";
        ::exit(1);
    }

    gsl::cstring_span<> arg = gsl::ensure_z(args.at(1));

    auto d = benchmark([&arg]{
        for (uint64_t i = 0; i < std::stoi(arg.data()); i++);
    });

    std::cout << "time: " <<
        duration_cast<seconds>(d).count() << '\n';

    std::cout << "time: " <<
        duration_cast<milliseconds>(d).count() << '\n';

    std::cout << "time: " <<
        duration_cast<nanoseconds>(d).count() << '\n';
}
```

在上述代码中，我们将参数列表转换为`gsl::span{}`，然后检查确保我们得到了一个参数。如果没有提供参数，我们就退出程序。然后将参数转换为`cstring_span{}`，并对用户希望运行的时间进行基准测试。基准测试的结果然后转换为秒、毫秒和纳秒，并输出到`stdout`：

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

与我们所有的示例一样，`protected_main()`函数由`main()`函数执行，如果发生异常，`main()`函数会捕获异常。

# 编译和测试

为了编译这段代码，我们利用了与其他示例相同的`CMakeLists.txt`文件：[`github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/blob/master/Chapter11/CMakeLists.txt`](https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/blob/master/Chapter11/CMakeLists.txt)。

有了这段代码，我们可以使用以下方法编译这段代码：

```cpp
> git clone https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP.git
> cd Hands-On-System-Programming-with-CPP/Chapter10/
> mkdir build
> cd build

> cmake ..
> make
```

要执行这个示例，运行以下命令：

```cpp
> ./example2 1000000
time: 0
time: 167
time: 167455690
```

如前面的片段所示，示例是通过一个循环运行的，循环次数为`1000000`，并且执行该循环所需的时间被输出到控制台。

# 总结

在本章中，我们学习了如何使用 POSIX 和 C++时间接口来读取系统时钟，以及使用稳定时钟进行更精确的计时。本章以两个示例结束；第一个示例演示了如何读取系统时钟并在用户定义的间隔内将结果输出到控制台，第二个示例演示了如何使用 C++高分辨率计时器对软件进行基准测试。在下一章中，我们将学习如何使用 POSIX 和 C++线程，并且会通过本章所学的知识构建示例。

在下一章中，我们将讨论 C++线程、互斥锁等同步原语，以及如何对它们进行编程。

# 问题

1.  Unix 纪元是什么？

1.  `time_t`通常表示什么类型？

1.  `time()`和`clock()`之间有什么区别？

1.  为什么`difftime()`返回一个 double？

1.  C++ `duration{}`是什么？

1.  `steady_clock{}`和`high_resolution_clock{}`之间有什么区别？

# 进一步阅读

+   [`www.packtpub.com/application-development/c17-example`](https://www.packtpub.com/application-development/c17-example)

+   [`www.packtpub.com/application-development/getting-started-c17-programming-video`](https://www.packtpub.com/application-development/getting-started-c17-programming-video)


# 第十二章：学习编程 POSIX 和 C++ 线程

在本章中，读者将学习如何编程使用 POSIX 和 C++ 线程。我们将首先讨论如何使用 POSIX 线程编程，然后转向 C++ 线程，提供每个 API 的比较。

然后我们将呈现三个示例。第一个示例将演示如何使用线程执行并行计算。第二个示例将演示如何使用线程创建自己的高分辨率计时器以进行基准测试（尽管该计时器可能不太准确）。

第三个和最后一个示例将在现有的调试示例基础上构建，以提供对多个客户端的支持。

应注意，本章假定读者已经基本了解线程、线程同步以及与竞争条件和死锁相关的挑战。在这里，我们将只关注 POSIX 和 C++ 提供的用于处理线程的 API。

本章将涵盖以下内容：

+   POSIX 线程

+   C++ 线程

+   并行计算

+   使用线程进行基准测试

+   线程日志记录

# 技术要求

为了遵循本章的示例，读者必须具备以下知识：

+   能够编译和执行 C++17 的基于 Linux 的系统（例如，Ubuntu 17.10+）

+   GCC 7+

+   CMake 3.6+

+   互联网连接

要下载本章中的所有代码，包括示例和代码片段，请转到以下链接：[`github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/tree/master/Chapter12`](https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/tree/master/Chapter12)。

# 理解 POSIX 线程

线程类似于进程，主要区别如下：

+   线程包含在进程内

+   线程本质上与同一进程的其他线程共享内存空间，而进程不共享资源，除非明确告知（使用进程间通信机制）。

与进程一样，线程也可以被操作系统随时调度执行。如果正确使用，这可能意味着与其他线程并行执行，从而导致性能优化，但代价是引入特定于线程的逻辑错误，如竞争条件和死锁。

本节的目标是简要回顾 POSIX 线程。这些在很大程度上影响了 C++ 线程的设计，稍后将进行讨论。

# POSIX 线程的基础知识

线程的最基本用法是创建它，然后加入线程，这实际上是在线程完成工作之前等待线程完成。

```cpp
#include <iostream>
#include <pthread.h>

void *mythread(void *ptr)
{
    std::cout << "Hello World\n";
    return nullptr;
}

int main()
{
    pthread_t thread1;
    pthread_t thread2;

    pthread_create(&thread1, nullptr, mythread, nullptr);
    pthread_create(&thread2, nullptr, mythread, nullptr);

    pthread_join(thread1, nullptr);
    pthread_join(thread2, nullptr);
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// Hello World
// Hello World
```

在前面的示例中，创建了一个具有 `(void *)(*)(void *)` 签名的 `mythread()` 函数，这是 POSIX 线程所需的。在此示例中，线程只是简单地输出到 `stdout` 并返回。

在 `main()` 函数中，使用 `pthread_create()` 函数创建了两个线程，其形式如下：

```cpp
int pthread_create(
    pthread_t *thread, 
    const pthread_attr_t *attr, 
    void *(*start_routine)(void*), 
    void *arg
);
```

在此示例中，创建了一个 `pthread_t` 类型，并传递给第一个参数。使用 `nullptr` 忽略了属性参数，线程本身的参数也是如此（因为它没有被使用）。我们向 `pthread_create` 函数提供的唯一其他内容是线程本身，它是指向我们的 `mythread()` 函数的函数指针。

要等待线程完成，我们使用 `pthread_join()` 函数，其形式如下：

```cpp
int pthread_join(pthread_t thread, void **value_ptr);
```

先前创建的 `pthread` 作为此函数的第一个参数提供，而 `pthread` 的返回值使用 `nullptr` 忽略（因为线程不返回值）。

此示例的结果是`Hello World`被输出到`stdout`两次（因为创建了两个线程）。

应注意，此示例存在几个问题，我们将在本章中简要讨论（因为整本书都可以写关于并行计算的主题）：

+   **类型安全**：线程的参数和返回值都作为`void *`传递，完全消除了与线程本身相关的任何形式的类型安全。因此，`pthread`接口不符合 C++核心指南，并鼓励创建难以发现的逻辑错误。正如将要演示的，C++在很大程度上解决了这些问题，尽管有时可能难以遵循接口。

+   **竞争条件**：前面的例子并没有尝试解决两个线程同时输出到`stdout`可能出现的竞争条件。因此，如果这个例子被执行足够多次，很可能会导致输出方面的损坏。

+   **没有输入/输出**：通常，线程在不需要输入或输出的情况下操作全局定义的数据，但完全有可能在不同的情况下需要输入和/或输出。这个例子没有解决如何实现这一点。

线程的实现方式因操作系统而异，跨平台软件需要考虑这一点。一些操作系统将线程实现为单独的进程，而另一些将线程实现为进程内的单独的可调度任务。

无论如何，POSIX 规范规定线程是可识别的，而不管底层实现如何。

要识别线程，可以使用以下方法：

```cpp
#include <iostream>
#include <pthread.h>

void *mythread(void *ptr)
{
    std::cout << "thread id: " 
              << pthread_self() << '\n';

    return nullptr;
}

main()
{
    pthread_t thread1;
    pthread_t thread2;

    pthread_create(&thread1, nullptr, mythread, nullptr);
    pthread_create(&thread2, nullptr, mythread, nullptr);

    pthread_join(thread1, nullptr);
    pthread_join(thread2, nullptr);
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// thread id: 140232513570560
// thread id: 140232505177856
```

前面的例子与第一个例子相同，唯一的区别是，我们使用`pthread_self（）`函数而不是将`Hello World`输出到`stdout`来输出线程的标识符。`pthread_self（）`函数采用以下形式：

```cpp
pthread_t pthread_self(void);
```

由于`pthread_t`类型通常使用整数类型实现，在我们前面的例子中，我们可以使用`std::cout`将这种类型的值输出到`stdout`。

为了支持输入和输出，`pthread` API 为线程函数的输入和输出都提供了`void *`。以下示例演示了如何做到这一点：

```cpp
#include <iostream>
#include <pthread.h>

void *mythread(void *ptr)
{
    (*reinterpret_cast<int *>(ptr))++;
    return ptr;
}

main()
{
    int in_value = 42;
    void *out_value = nullptr;

    pthread_t thread1;
    pthread_t thread2;

    pthread_create(&thread1, nullptr, mythread, &in_value);
    pthread_create(&thread2, nullptr, mythread, &in_value);

    pthread_join(thread1, &out_value);
    pthread_join(thread2, &out_value);

    std::cout << "value: " 
              << *reinterpret_cast<int *>(out_value) << '\n';
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// 44
```

在这个例子中，线程函数假设它传递的参数是一个整数的指针。它获取提供的值，递增它，然后将其返回给调用者（在这种情况下是`main（）`函数）。

在`main（）`函数中，我们创建了一个输入值和一个输出值，其中输入被初始化为`42`。在线程创建时提供了指向输入值的指针，并在加入线程时提供了指向输出值的指针。

最后，结果值被输出到`stdout`。这是`44`，因为创建了两个线程，每个线程递增了提供的输入一次。

由于两个线程都在同一个整数上操作，如果它们恰好同时执行，可能会出现竞争条件，这可能会破坏这些线程的结果；这个问题将在以后解决。

# 产量

使用线程的一个优点是它们可以长时间执行而不会阻止主线程/应用程序的执行。缺点是，没有结束的线程可能会消耗太多的 CPU。

例如，考虑以下代码：

```cpp
#include <iostream>
#include <pthread.h>

void *mythread(void *ptr)
{
    while(true) {
        std::clog << static_cast<char *>(ptr) << '\n';
        pthread_yield();
    }
}

main()
{
    char name1[9] = "thread 1";
    char name2[9] = "thread 2";

    pthread_t thread1;
    pthread_t thread2;

    pthread_create(&thread1, nullptr, mythread, name1);
    pthread_create(&thread2, nullptr, mythread, name2);

    pthread_join(thread1, nullptr);
    pthread_join(thread2, nullptr);
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// thread 2
// thread 2
// thread 2
// thread 1
// thread 2
// thread 2
// thread 1
// thread 1
// thread 1
```

在前面的例子中，我们创建了一个使用`while(true)`语句的线程，它尽可能快地永远执行。这样的线程将执行，直到操作系统决定抢占线程以调度另一个线程或进程，导致线程的输出以阻塞的几乎串行的方式发生。

然而，在某些情况下，用户可能需要线程执行一个动作，然后释放其对 CPU 的访问权，以允许另一个线程执行其任务。为了实现这一点，我们使用`pthread_yield（）`API，它采用以下形式：

```cpp
int pthread_yield(void)
```

在前面的例子中，使用`yield`函数为每个线程提供了执行的机会，导致`线程 1`和`线程 2`的输出更好地混合在一起。

尽管提供了这个函数，但应该注意操作系统在处理必须执行大量工作的线程时非常出色，`pthread_yield()`只有在用户明确了解它如何在特定用例中提供优化时才应该使用（因为过度使用`pthread_yield()`函数实际上可能会导致性能下降）。

还应该注意到`pthread_yield()`并不是所有 Unix 系统都可用。

除了`pthread_yield()`，POSIX API 还提供了一些函数，如果没有要执行的任务，可以使线程休眠（从而提高性能和电池寿命），如下所示：

```cpp
#include <iostream>

#include <unistd.h>
#include <pthread.h>

void *mythread(void *ptr)
{
    while (true) {
        sleep(1);
        std::cout << "hello world\n";
    }
}

main()
{
    pthread_t thread;
    pthread_create(&thread, nullptr, mythread, nullptr);
    pthread_join(thread, nullptr);
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// hello world
// hello world
// hello world
```

在前面的示例中，我们创建了一个线程，每秒输出一次`Hello World`，方法是创建一个输出到`stdout`的单个线程，然后使用`sleep()`函数使线程休眠一秒钟。

应该注意，对`sleep()`的使用应该谨慎，因为操作系统可能在调用`sleep()`之前就已经执行了`sleep()`调用。

# 同步

竞争条件在使用线程时是一个常见问题，解决竞争条件而不引入死锁（由于线程同步逻辑的逻辑错误而无法执行的线程）是一个复杂的主题，值得有专门的书籍来讨论。

以下示例试图演示潜在竞争条件的问题：

```cpp
#include <array>
#include <iostream>
#include <pthread.h>

int count = 0;

void *mythread(void *ptr)
{
    count++;
}

main()
{
    while (true) {
        count = 0;
        for (auto i = 0; i < 1000; i++) {
            std::array<pthread_t, 8> threads;

            for (auto &t : threads) {
                pthread_create(&t, nullptr, mythread, nullptr);
            }

            for (auto &t : threads) {
                pthread_join(t, nullptr);
            }
        }

        std::cout << "count: " << count << '\n';
    }
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// count: 7992
// count: 7996
// count: 7998
// count: 8000
// count: 8000
```

要产生竞争条件，我们必须以足够快的速度执行线程，并且足够长的时间（特别是在现代硬件上），以便一个线程在另一个线程在同一共享资源上执行操作时，另一个线程正在完成自己对该共享资源的操作。

有很多种方法可以做到这一点。在前面的示例中，我们有一个递增计数器的线程，然后我们创建了`8000`个这样的线程，增加了竞争条件发生的机会。在执行过程中的某个时刻，两个线程同时读取计数器的当前值，增加该值并同时存储增加后的值。这导致计数器只增加了一次，尽管有两个线程在执行。

因此，从示例的输出中可以看出，在某些情况下，计数小于`8000`。在这些情况下，发生了竞争条件，导致了数据损坏。

为了解决这个问题，我们必须保护关键区域，这在这种情况下是使用共享资源的线程部分。以下示例演示了使用互斥锁（确保对关键区域的互斥访问）的一种方法：

```cpp
#include <array>
#include <iostream>
#include <pthread.h>

int count = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *mythread(void *ptr)
{
    pthread_mutex_lock(&lock);
    count++;
    pthread_mutex_unlock(&lock);
}

main()
{
    while (true) {
        count = 0;
        for (auto i = 0; i < 1000; i++) {
            std::array<pthread_t, 8> threads;

            for (auto &t : threads) {
                pthread_create(&t, nullptr, mythread, nullptr);
            }

            for (auto &t : threads) {
                pthread_join(t, nullptr);
            }
        }

        std::cout << "count: " << count << '\n';
    }
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// count: 8000
// count: 8000
// count: 8000
// count: 8000
// count: 8000
```

在前面的示例中，我们用互斥锁包装了关键区域。互斥锁利用原子操作（由硬件保证的操作，可以在不损坏的情况下操作共享资源）来一次让一个线程访问关键区域。

如果一个线程在另一个线程正在使用关键区域时尝试访问关键区域，它将等待直到该线程完成。一旦线程完成，所有等待的线程都会竞争访问关键区域，获胜的线程获得访问权限，而其余线程继续等待。（每个操作系统都有自己的实现方式，以防止饥饿的可能性；这是本书范围之外的另一个主题。）

从前面示例的输出中可以看出，使用互斥锁包围关键区域（在这种情况下是递增`count`变量）可以防止竞争条件的发生，每次输出都是`8000`。

互斥锁的问题在于每次锁定互斥锁时，线程必须等待直到解锁才能继续。这样可以保护关键区域免受其他线程的干扰，但如果同一线程尝试多次锁定同一互斥锁（例如在使用递归时），或者以错误的顺序锁定互斥锁，就会导致死锁。

为了解决这个问题，POSIX API 提供了将互斥锁转换为递归互斥锁的能力，如下所示：

```cpp
#include <iostream>
#include <pthread.h>

int count = 0;
pthread_mutex_t lock;
pthread_mutexattr_t attr;

void *mythread(void *ptr)
{
    pthread_mutex_lock(&lock);
    pthread_mutex_lock(&lock);
    pthread_mutex_lock(&lock);
    count++;
    pthread_mutex_unlock(&lock);
    pthread_mutex_unlock(&lock);
    pthread_mutex_unlock(&lock);
}

int main()
{
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&lock, &attr);

    pthread_t thread1;
    pthread_t thread2;

    pthread_create(&thread1, nullptr, mythread, nullptr);
    pthread_create(&thread2, nullptr, mythread, nullptr);

    pthread_join(thread1, nullptr);
    pthread_join(thread2, nullptr);

    std::cout << "count: " << count << '\n';
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// count: 2
```

在前面的例子中，我们能够多次锁定互斥锁，而不会因此造成死锁，首先使用互斥锁属性将互斥锁设置为递归模式。应该注意，这种额外的灵活性通常伴随着额外的开销。

我们将在本章讨论的最后一个 POSIX API 是条件变量。正如之前所演示的，互斥锁可以用来同步对代码的关键区域的访问。线程同步的另一种形式是确保线程按正确的顺序执行，这就是条件变量所允许的。

在下面的例子中，线程 1 和 2 可以随时执行：

```cpp
#include <iostream>
#include <pthread.h>

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *mythread1(void *ptr)
{
    pthread_mutex_lock(&lock);
    std::cout << "Hello World: 1\n";
    pthread_mutex_unlock(&lock);

    return nullptr;
}

void *mythread2(void *ptr)
{
    pthread_mutex_lock(&lock);
    std::cout << "Hello World: 2\n";
    pthread_mutex_unlock(&lock);

    return nullptr;
}

main()
{
    pthread_t thread1;
    pthread_t thread2;

    pthread_create(&thread2, nullptr, mythread2, nullptr);
    pthread_create(&thread1, nullptr, mythread1, nullptr);

    pthread_join(thread1, nullptr);
    pthread_join(thread2, nullptr);
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// Hello World: 2
// Hello World: 1
```

在这个例子中，我们创建了两个线程，每个线程都在使用互斥锁保护的关键区域中输出到`stdout`。示例的其余部分与本章中之前的示例相同。如所示，`线程 2`首先执行，然后是`线程 1`（这主要是因为`线程 2`先创建）。然而，仍然有可能`线程 1`先执行，因为没有控制线程执行顺序的东西。

为了解决这个问题，POSIX API 提供了一个条件变量，可以用来同步线程的顺序，如下所示：

```cpp
#include <iostream>
#include <pthread.h>

bool predicate = false;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *mythread1(void *ptr)
{
    pthread_mutex_lock(&lock);
    std::cout << "Hello World: 1\n";
    predicate = true;
    pthread_mutex_unlock(&lock);
    pthread_cond_signal(&cond);

    return nullptr;
}

void *mythread2(void *ptr)
{
    pthread_mutex_lock(&lock);
    while(!predicate) {
        pthread_cond_wait(&cond, &lock);
    }
    std::cout << "Hello World: 2\n";
    pthread_mutex_unlock(&lock);

    return nullptr;
}

main()
{
    pthread_t thread1;
    pthread_t thread2;

    pthread_create(&thread2, nullptr, mythread2, nullptr);
    pthread_create(&thread1, nullptr, mythread1, nullptr);

    pthread_join(thread1, nullptr);
    pthread_join(thread2, nullptr);
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// Hello World: 1
// Hello World: 2
```

正如我们所看到的，`线程 1`首先执行，然后是`线程 2`，尽管`线程 2`是先创建的。为了实现这一点，我们使用`pthread_cond_wait()`和`pthread_cond_signal()`函数，如下所示：

```cpp
bool predicate = false;
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int pthread_cond_signal(pthread_cond_t *cond);
```

`pthread_cond_wait()`函数接受一个指向条件变量和互斥锁的指针。当它被执行时，它会解锁互斥锁并等待`pthread_cond_signal()`的调用。一旦发送了信号，`pthread_cond_wait()`再次锁定互斥锁并继续执行。

使用`predicate`变量，它也受到互斥锁的保护，用于确保处理任何虚假唤醒。具体来说，`pthread_cond_wait()`函数可能会在条件变量尚未被发出信号的情况下唤醒。因此，您必须始终将`pthread_cond_wait()`函数与`predicate`配对使用。

# 探索 C++线程

在前一节中，我们学习了 POSIX 如何支持线程。在本节中，我们将讨论 C++线程，它们在很大程度上受到了 POSIX 线程的启发。它们提供了类似的功能，同时在某些方面简化了 API，并提供了类型安全性。

# C++线程的基础知识

为了展示 C++线程的简单性，下面的例子，就像本章中的第一个例子一样，创建了两个线程，然后等待它们执行完毕：

```cpp
#include <thread>
#include <iostream>

void mythread()
{
    std::cout << "Hello World\n";
}

main()
{
    std::thread t1{mythread};
    std::thread t2{mythread};

    t1.join();
    t2.join();
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// Hello World
// Hello World
```

与此示例的 POSIX 版本相比，有一些显著的区别：

+   线程函数本身可能具有多种不同的函数签名，并不限于`(void *)(*)(void *)`。在这个例子中，线程函数使用了`void(*)()`签名。

+   线程类型的构造函数也创建了线程（无需定义类型，然后显式创建线程）。

应该注意，在 Linux 中，仍然需要将`pthread`库链接到示例中。这是因为在底层，C++使用`pthread`实例来提供线程支持。

与 POSIX 版本相似，C++也提供了获取线程 ID 的能力，如下所示：

```cpp
#include <thread>
#include <iostream>

void mythread()
{
    std::cout << "thread id: " 
              << std::this_thread::get_id() << '\n';
}

main()
{
    std::thread t1{mythread};
    std::thread t2{mythread};

    std::cout << "thread1 id: " << t1.get_id() << '\n';
    std::cout << "thread2 id: " << t2.get_id() << '\n';

    t1.join();
    t2.join();
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// thread1 id: 139960486229760
// thread2 id: 139960477837056
// thread id: 139960477837056
// thread id: 139960486229760
```

在前面的例子中，我们同时使用了`this_thread`命名空间和线程本身来获取 ID，演示了查询线程 ID 的两种不同方式（取决于调用者的观点）。

C++线程的输入和输出是 C++线程在某些方面比 POSIX 线程更复杂的一个很好的例子。正如所述，关于输入和输出，POSIX 线程最大的问题是明显缺乏类型安全性。

为了解决这个问题，C++提供了一个叫做 C++ futures 的概念，它本身可能值得有自己的章节。我们将在这里简要描述它们，以便让读者对它们的工作原理有一些一般性的了解。

在下面的例子中，我们创建了一个`mythread()`函数，它的签名是`int(*)(int)`，它接受一个值，加一，然后返回结果（与前面的 POSIX 例子的输入和输出非常相似）：

```cpp
#include <thread>
#include <future>
#include <iostream>

int mythread(int value)
{
    return ++value;
}

int main()
{
    std::packaged_task<int(int)> task1(mythread);
    std::packaged_task<int(int)> task2(mythread);

    auto f1 = task1.get_future();
    auto f2 = task2.get_future();

    std::thread t1(std::move(task1), 42);
    std::thread t2(std::move(task2), 42);

    t1.join();
    t2.join();

    std::cout << "value1: " << f1.get() << '\n';
    std::cout << "value2: " << f2.get() << '\n';
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// Hello World
// Hello World
```

使用 C++ futures，我们需要首先告诉 C++我们的线程的签名类型，以确保类型安全。为了在我们的例子中实现这一点（利用 future 的 API 有很多种方式，这只是其中一种），我们创建了一个`std::packaged_task{}`，并为它提供了我们的线程函数签名。

这做了一些事情。首先，它告诉 API 调用哪个线程，另外，它为线程的结果设置了存储，以便稍后使用`std::future{}`检索。一旦创建了`std::packaged_task{}`，我们就可以使用`get_future()`函数从`packaged_task{}`中获取`std::future{}`。

最后，我们通过创建一个线程对象并将之前创建的`std::packaged_task{}`对象传递给它来启动线程。

我们可以在线程的构造函数中为线程提供初始输入，将所有的线程参数作为额外的基于模板的参数。要检索线程的结果，我们使用来自 future 的`get()`，这在线程完成并加入后是有效的（因此称为*future*）。

尽管 futures 在某些方面比简单地传递`void *`更复杂，但接口是优雅的，允许线程采用任何所需的签名类型，同时也提供类型安全。（在这个例子中不需要`reinterpret_casts()`，确保了核心指导方针的合规性，减少了难以发现的逻辑错误的可能性。）

# 让出

与 POSIX 线程类似，C++线程提供了让出线程的能力，让出 CPU，以便其他需要执行任务的线程可以这样做。表达如下：

```cpp
#include <thread>
#include <iostream>

void mythread(const char *str)
{
    while(true) {
        std::clog << str << '\n';
        std::this_thread::yield();
    }
}

main()
{
    std::thread t1{mythread, "thread 1"};
    std::thread t2{mythread, "thread 2"};

    t1.join();
    t2.join();
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// thread 2
// thread 2
// thread 1
// thread 1
// thread 1
// thread 1
// thread 1
// thread 2
// thread 1
```

在前面的例子中，我们利用了`this_thread`命名空间提供的`yield()`函数，它让出调用线程。因此，它更能够在两个线程之间重新排列线程的输出，正如之前所演示的那样。

除了让出，线程可能需要停止执行一段时间。类似于 POSIX 中的`sleep()`，C++提供了让当前执行线程休眠的能力。C++的不同之处在于提供了更精细的 API，允许用户轻松地决定他们喜欢哪种类型的粒度（包括纳秒和秒的分辨率），如下所示：

```cpp
#include <thread>
#include <chrono>
#include <iostream>

using namespace std::chrono_literals;

void mythread()
{
    while (true) {
        std::this_thread::sleep_for(1s);
        std::cout << "hello world\n";
    }
}

main()
{
    std::thread t{mythread};
    t.join();
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// hello world
// hello world
// hello world
```

在前面的例子中，我们创建了一个线程，将`Hello World`输出到`stdout`。在输出到`stdout`之前，线程通过调用`this_thread`命名空间提供的`sleep_for()`来休眠一秒，并使用秒字面量来定义`1`秒，结果是每秒将`Hello World`输出到`stdout`。

# 同步

POSIX 线程和 C++线程之间的另一个显著区别是线程同步的简单性。与 POSIX API 类似，C++提供了创建互斥锁的能力，如下所示：

```cpp
#include <mutex>
#include <thread>
#include <iostream>

int count = 0;
std::mutex mutex;

void mythread()
{
    mutex.lock();
    count++;
    mutex.unlock();
}

main()
{
    std::thread t1{mythread};
    std::thread t2{mythread};

    t1.join();
    t2.join();

    std::cout << "count: " << count << '\n';
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// count: 2
```

在前面的例子中，我们创建了一个线程，它会增加一个共享的计数器，这个计数器被 C++的`std::mutex{}`包围，实际上创建了一个受保护的临界区。然后我们创建了两个线程，等待它们完成，然后将结果输出到`stdout`，结果是`2`，因为我们执行了两个线程。

POSIX 线程和前面的 C++例子的问题在于当一个线程不得不在多个地方离开临界区时，会出现问题：

```cpp
void mythread()
{
    mutex.lock();

    if (count == 1) {
        mutex.unlock();
        return;
    }

    count++;
    mutex.unlock();
}
```

在之前的例子中，临界区在多个地方退出，因此必须在多个地方解锁互斥锁，以防止死锁。尽管这似乎是一个简单的例子，但由于简单地忘记在从临界区返回之前解锁互斥锁，导致了无数的死锁错误。

为了防止这个问题，C++提供了`std::lock_guard{}`，它提供了一个使用**资源获取即初始化**（**RAII**）的简单机制来解锁互斥锁。

```cpp
#include <mutex>
#include <thread>
#include <iostream>

int count = 0;
std::mutex mutex;

void mythread()
{
    std::lock_guard lock(mutex);

    if (count == 1) {
        return;
    }

    count++;
}

main()
{
    std::thread t1{mythread};
    std::thread t2{mythread};

    t1.join();
    t2.join();

    std::cout << "count: " << count << '\n';
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// count: 1
```

在之前的例子中，我们在线程中创建了一个基于 RAII 的锁保护，而不是手动锁定和解锁互斥锁。因此，在这个例子中，整个线程都处于临界区，因为当创建保护时互斥锁被锁定，当锁超出范围时（即线程返回时）被解锁。

正如在之前的例子中所演示的，不可能意外忘记解锁互斥锁，因为解锁互斥锁是由锁保护处理的。

在某些情况下，用户可能希望线程在等待访问临界区时执行其他有用的工作。为了实现这一点，`std::mutex{}`提供了`try_lock()`作为`lock()`的替代方法，如果无法获得锁，则返回`false`。

```cpp
#include <mutex>
#include <thread>
#include <iostream>

int count = 0;
std::mutex mutex;

void mythread()
{
    while(!mutex.try_lock());
    count++;
    mutex.unlock();
}

main()
{
    std::thread t1{mythread};
    std::thread t2{mythread};

    t1.join();
    t2.join();

    std::cout << "count: " << count << '\n';
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// count: 2
```

在之前的例子中，我们继续在无限的`while`循环中尝试锁定互斥锁。然而，如果`try_lock()`返回`false`，我们可以执行一些额外的工作，或者在再次尝试之前睡眠一段时间，从而减轻操作系统和电池的压力。

如果希望使用`try_lock`与锁保护一起，以防止手动解锁互斥锁的需要，可以使用以下方法：

```cpp
#include <mutex>
#include <thread>
#include <chrono>
#include <iostream>

int count = 0;
std::mutex mutex;

using namespace std::chrono_literals;

void mythread()
{
    std::unique_lock lock(mutex, std::defer_lock);

    while(!lock.try_lock()) {
        std::this_thread::sleep_for(1s);
    }

    count++;
}

main()
{
    std::thread t1{mythread};
    std::thread t2{mythread};

    t1.join();
    t2.join();

    std::cout << "count: " << count << '\n';
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// count: 2
```

在这个例子中，我们介绍了 C++线程的两个新特性。第一个是`std::unique_lock{}`，它类似于`std::lock_guard{}`。

`std::lock_guard{}`是一个简单的 RAII 包装器，而`std::unique_lock`提供了类似于`std::unique_ptr{}`的功能，即生成的锁是可移动的（不可复制的），并提供了超出简单 RAII 包装器的额外 API。

作为一个副作用，关于所有这些锁保护，不要忘记定义保护的变量，否则锁将立即被锁定和解锁，导致难以发现的错误。

`std::unique_lock`提供的另一个额外 API 是延迟锁定互斥锁的能力（即在锁本身的构造时不锁定）。这使用户能够更好地控制锁定发生的时间，使用诸如`lock()`、`try_lock()`、`try_lock_for()`和`try_lock_until()`之类的许多锁函数。

在我们之前的例子中，我们尝试锁定临界区，如果失败，就在再次尝试之前睡眠一秒。其他修饰符包括`std::adopt_lock{}`和`std::try_lock{}`修饰符，它们要么假设互斥锁已经被锁定，要么构造函数尝试锁定而不阻塞。

除了常规的互斥锁，C++还提供了像 POSIX 一样的递归互斥锁，如下所示：

```cpp
#include <mutex>
#include <thread>
#include <iostream>

int count = 0;
std::recursive_mutex mutex;

void mythread()
{
    std::lock_guard lock1(mutex);
    std::lock_guard lock2(mutex);
    count++;
}

main()
{
    std::thread t1{mythread};
    std::thread t2{mythread};

    t1.join();
    t2.join();

    std::cout << "count: " << count << '\n';
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// count: 2
```

在这个例子中，我们能够在同一个递归锁上创建两个锁保护，而不会创建死锁（因为析构函数的执行顺序与构造相反，确保锁以正确的顺序被解锁）。

互斥锁的另一个常见问题与同时锁定多个互斥锁有关；也就是说，如果存在多个临界区，并且特定操作必须同时在两个临界区上操作。为了实现这一点，C++17 添加了`std::scoped_lock{}`，它类似于`std::lock_guard{}`，但接受多个锁，如下所示：

```cpp
#include <mutex>
#include <thread>
#include <iostream>

int count = 0;
std::mutex mutex1;
std::mutex mutex2;

void mythread()
{
    std::scoped_lock lock(mutex1, mutex2);
    count++;
}

main()
{
    std::thread t1{mythread};
    std::thread t2{mythread};

    t1.join();
    t2.join();

    std::cout << "count: " << count << '\n';
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// count: 2
```

在这个例子中，使用`std::scoped_lock{}`类锁定和解锁了不止一个互斥锁。

`std::unique_lock{}`类似于`std::unique_ptr{}`，它保护资源并防止复制。与`std::shared_ptr{}`类似，互斥量 API 还提供`std::shared_lock{}`，它提供了多个线程访问同一互斥量的能力。以下代码演示了这一点：

```cpp
#include <shared_mutex>
#include <thread>
#include <iostream>

int count = 0;
std::shared_mutex mutex;

void mythread1()
{
    while(true) {
        std::unique_lock lock(mutex);
        count++;
    }
}

void mythread2()
{
    while(true) {
        std::shared_lock lock(mutex);
        std::cout << "count: " << count << '\n';
    }
}

main()
{
    std::thread t1{mythread1};
    std::thread t2{mythread2};
    std::thread t3{mythread2};

    t1.join();
    t2.join();
    t3.join();
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// count: 999
// count: 1000
// count: 1000
// count: 1000
// count: 1000
// count: 1000
// count: count: 1000
// count: 1000
```

在前面的例子中，我们有两个线程——一个生产者和一个消费者。生产者（`mythread1`）增加计数器，而消费者（`mythread2`）将计数输出到`stdout`。在`main()`函数中，我们创建三个线程——一个生产者和两个消费者。

我们可以使用常规的`std::mutex`来实现这种情况；但是，这样的实现将是次优的，因为两个消费者都没有修改计数器，这意味着多个消费者可以在不损坏结果的情况下同时执行，如果它们碰巧发生冲突（因为没有进行修改）。

然而，如果使用常规的`std::muted`，消费者将不得不互相等待，这也是次优的（显然忽略了`stdout`也是一个共享资源，应该被视为自己的临界区，以防止`stdout`本身的损坏）。

为了解决这个问题，我们利用`std::shared_mutex`代替常规的`std::mutex`。在生产者中，我们使用`std::unique_lock{}`锁定互斥量，这确保了对临界区的独占访问。然而，在消费者中，我们利用`std::shared_lock{}`，它只等待使用`std::unique_lock{}`的先前锁定。如果使用`std::shared_lock{}`获取了互斥量，线程将继续执行而不等待，共享对临界区的访问。

最后，在 C++17 之前，通过添加`std::scoped_lock{}`，锁定多个互斥量的唯一方法是使用`std::lock()`（和 friends）函数，如下所示：

```cpp
#include <mutex>
#include <thread>
#include <iostream>

int count = 0;
std::mutex mutex1;
std::mutex mutex2;

void mythread()
{
    std::unique_lock lock1(mutex1, std::defer_lock);
    std::unique_lock lock2(mutex2, std::defer_lock);

    std::lock(lock1, lock2);

    count++;
}

main()
{
    std::thread t1{mythread};
    std::thread t2{mythread};

    t1.join();
    t2.join();

    std::cout << "count: " << count << '\n';
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// count: 2
```

与 POSIX 一样，C++也提供了使用条件变量控制线程执行顺序的能力。在下面的例子中，我们创建两个线程，并使用条件变量来同步它们的执行顺序，类似于 POSIX 的条件变量示例：

```cpp
#include <mutex>
#include <condition_variable>
#include <thread>
#include <iostream>

std::mutex mutex;
std::condition_variable cond;

void mythread1()
{
    std::cout << "Hello World: 1\n";
    cond.notify_one();
}

void mythread2()
{
    std::unique_lock lock(mutex);
    cond.wait(lock);
    std::cout << "Hello World: 2\n";
}

main()
{
    std::thread t2{mythread2};
    std::thread t1{mythread1};

    t1.join();
    t2.join();
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// Hello World: 1
// Hello World: 2
```

如前面的例子所示，尽管第二个线程是先创建的，但它最后执行。这是通过创建一个 C++条件变量实现的。在第二个线程中，我们使用`std::unique_lock{}`保护临界区，然后等待第一个线程通过调用`notify_one()`来发出已完成的信号。

一旦第一个线程完成并通知第二个线程，第二个线程就完成了它的执行。

这种方法也适用于使用 C++线程进行广播模式的多个线程，如下所示：

```cpp
#include <mutex>
#include <condition_variable>
#include <thread>
#include <iostream>

std::mutex mutex;
std::condition_variable cond;

void mythread1()
{
    std::cout << "Hello World: 1\n";
    cond.notify_all();
}

void mythread2()
{
    std::unique_lock lock(mutex);
    cond.wait(lock);
    std::cout << "Hello World: 2\n";
    cond.notify_one();
}

main()
{
    std::thread t2{mythread2};
    std::thread t3{mythread2};
    std::thread t1{mythread1};

    t1.join();
    t2.join();
    t3.join();
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// Hello World: 1
// Hello World: 2
// Hello World: 2
```

在这个例子中，第一个线程完成它的工作，然后通知所有剩余的线程完成。第二个线程用互斥量保护临界区，并等待第一个线程的信号。

问题在于一旦第一个线程执行并发出完成的信号，剩余的线程将尝试执行，但只有一个线程可以获取临界区，导致第三个线程等待临界区被解锁并收到通知。因此，当第二个线程完成时，它必须再次通知条件变量以解锁剩余的线程，从而允许所有三个线程完成。

为了解决这个问题，我们将结合本节学到的所有内容，如下所示：

```cpp
#include <shared_mutex>
#include <condition_variable>
#include <thread>
#include <iostream>

std::shared_mutex mutex;
std::condition_variable_any cond;

void mythread1()
{
    std::unique_lock lock(mutex);
    std::cout << "Hello World: 1\n";

    cond.notify_all();
}

void mythread2()
{
    std::shared_lock lock(mutex);
    cond.wait(lock);

    std::cout << "Hello World: 2\n";
}

main()
{
    std::thread t2{mythread2};
    std::thread t3{mythread2};
    std::thread t1{mythread1};

    t1.join();
    t2.join();
    t3.join();
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// Hello World: 1
// Hello World: 2
// Hello World: 2
```

这个例子与前一个例子相同，只有一个简单的改变。我们使用`std::shared_mutex{}`而不是`std::mutex{}`，并且使用`std::shared_lock{}`来锁定互斥量。

为了能够使用共享互斥量代替常规互斥量，必须使用`std::condition_variable_any{}`而不是`std::condition_variable{}`。通过使用`std::shared_mutex{}`而不是`std::mutex{}`，当第一个线程发出已完成的信号时，剩余的线程可以自由完成它们的工作并同时处理临界区。

最后，C++提供了一个方便的机制，如果需要多个线程，但只允许一个执行初始化逻辑（这也是 POSIX 提供的功能，但本书未涵盖），如下所示：

```cpp
#include <mutex>
#include <thread>
#include <iostream>

std::once_flag flag;

void mythread()
{
    std::call_once(flag, [] {
        std::cout << "Hello World\n";
    });
}

main()
{
    std::thread t1{mythread};
    std::thread t2{mythread};

    t1.join();
    t2.join();
}

// > g++ -std=c++17 scratchpad.cpp -lpthread; ./a.out
// Hello World
```

在这个示例中，创建了多个线程，但是使用`std::call_once{}`包装器只执行了一次`Hello World`。值得注意的是，尽管这看起来很简单，但`std::call_once{}`确保了标志的原子翻转，以确定包装逻辑是否已经执行，从而防止可能的竞争条件，尽管它们可能是不太可能发生的。

# 研究并行计算的示例

在这个示例中，我们将演示如何使用线程执行并行计算任务，计算质数。在这个示例中，需要以下包含文件和命名空间：

```cpp
#include <list>
#include <mutex>
#include <thread>
#include <iostream>
#include <algorithm>

#include <gsl/gsl>
using namespace gsl;

using namespace std::string_literals;
```

对于大数来说，计算质数值是一项昂贵的操作，但幸运的是，它们可以并行计算。值得注意的是，在我们的示例中，我们并没有尝试优化我们的搜索算法，因为我们的目标是提供一个可读的线程示例。有许多方法，一些简单的方法，可以改进此示例中代码的性能。

为了存储我们的程序找到的质数，我们将定义以下类：

```cpp

class primes
{
    std::list<int> m_primes;
    mutable std::mutex m_mutex;

public:

    void add(int prime)
    {
        std::unique_lock lock(m_mutex);
        m_primes.push_back(prime);
    }

    void print()
    {
        std::unique_lock lock(m_mutex);
        m_primes.sort();

        for (const auto prime : m_primes) {
            std::cout << prime << ' ';
        }

        std::cout << '\n';
    }
};

primes g_primes;
```

这个类提供了一个地方，让我们使用`add()`函数存储每个质数。一旦找到我们计划搜索的所有质数，我们提供一个`print()`函数，能够按排序顺序打印已识别的质数。

我们将用来检查一个数字是否为质数的线程如下：

```cpp
void check_prime(int num)
{
    for (auto i = 2; i < num; i++) {
        if (num % i == 0) {
            return;
        }
    }

    g_primes.add(num);
}
```

在这个线程中，我们循环遍历用户提供的数字的每个可能的倍数，并检查模是否为`0`。如果是`0`，则该数字不是质数。如果没有找到任何倍数，则该数字是质数，并且将其添加到我们的列表中。

最后，在我们的`protected_main()`函数中，我们搜索一组质数。我们首先将所有参数转换，以便对其进行处理：

```cpp
int
protected_main(int argc, char** argv)
{
    auto args = make_span(argv, argc);

    if (args.size() != 4) {
        std::cerr << "wrong number of arguments\n";
        ::exit(1);
    }
```

我们期望有三个参数。第一个参数将提供我们希望检查是否为质数的最大可能数字；第二个参数是我们希望创建的用于搜索质数的线程总数；第三个参数将确定我们是否要打印结果。

下一个任务是获取要搜索的最大可能质数，以及获取要创建的线程总数。考虑以下代码：

```cpp
    int max_prime = std::stoi(args.at(1));
    int max_threads = std::stoi(args.at(2));

    if (max_prime < 3) {
        std::cerr << "max_prime must be 2 or more\n";
        ::exit(1);
    }

    if (max_threads < 1) {
        std::cerr << "max_threads must be 1 or more\n";
        ::exit(1);
    }
```

一旦我们知道要搜索多少个质数，以及要创建多少个线程，我们就按照以下方式搜索我们的质数：

```cpp
    for (auto i = 2; i < max_prime; i += max_threads) {

        std::list<std::thread> threads;
        for (auto t = 0; t < max_threads; t++) {
            threads.push_back(std::thread{check_prime, i + t});
        }

        for (auto &thread : threads) {
            thread.join();
        }
    }
```

在这段代码中，我们搜索用户提供的数字范围内的所有质数，逐个增加用户提供的线程总数。然后，我们创建一个线程列表，为每个线程提供它应该从哪个数字开始寻找质数。

一旦所有线程都创建好了，我们就等待这些线程完成。值得注意的是，有许多方法可以进一步优化这个逻辑，包括防止线程的重新创建，从而防止过度使用`malloc()`，但这个示例提供了一个简单的机制来演示这个示例的要点。

在`protected_main()`函数中，我们做的最后一件事是检查用户是否想要查看结果，并在需要时打印它们：

```cpp

    if (args.at(3) == "print"s) {
        g_primes.print();
    }

    return EXIT_SUCCESS;
}
```

最后，我们使用我们的`main()`执行`protected_main()`函数，并捕获可能出现的任何异常，如下所示：

```cpp
int
main(int argc, char** argv)
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

# 编译和测试

要编译这段代码，我们利用了与其他示例相同的`CMakeLists.txt`文件，可以在以下链接找到：[`github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/blob/master/Chapter12/CMakeLists.txt`](https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/blob/master/Chapter12/CMakeLists.txt)。

有了这段代码，我们可以使用以下方式编译这段代码：

```cpp
> git clone https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP.git
> cd Hands-On-System-Programming-with-CPP/Chapter12/
> mkdir build
> cd build

> cmake ..
> make
```

要执行此示例，请运行以下命令：

```cpp
> time ./example1 20 4 print
2 3 5 7 11 13 17 19
```

如本片段所示，找到了最多`20`个素数。为了演示线程的有效性，请执行以下操作：

```cpp
> time ./example1 50000 4 no
real 0m2.180s
user 0m0.908s
sys 0m3.280s

> time ./example1 50000 2 no
real 0m2.900s
user 0m1.073s
sys 0m3.230s

> time ./example1 50000 1 no
real 0m4.546s
user 0m0.910s
sys 0m3.615s
```

可以看到，随着线程总数的减少，应用程序查找素数所需的总时间也会增加。

# 研究使用线程进行基准测试的示例

在之前的章节中，我们讨论了如何使用各种不同的机制对软件进行基准测试。在本章中，我们将探讨使用线程创建自己的高分辨率计时器，而不是使用 C++ chrono API 提供的高分辨率计时器。

为了实现这一点，我们将创建一个线程，其唯一工作是尽可能快地计数。值得注意的是，尽管这将提供一个非常敏感的高分辨率计时器，但与英特尔等计算机架构相比，它有很多缺点。这些提供了比这里可能的更高分辨率的硬件指令，同时对 CPU 频率缩放的影响较小。

在这个示例中，需要以下包含和命名空间：

```cpp
#include <thread>
#include <mutex>
#include <condition_variable>
#include <iostream>

#include <gsl/gsl>
using namespace gsl;
```

我们将把高分辨率计时器存储在`count`变量中，如下所示：

```cpp
int count = 0;
bool enable_counter = true;

std::mutex mutex;
std::condition_variable cond;
```

`enable_counter`布尔值将用于关闭计时器，而互斥锁和条件变量将用于在正确的时间打开计时器。

我们的高分辨率计时器将包括以下内容：

```cpp
void tick()
{
    cond.notify_one();

    while (enable_counter) {
        count++;
    }
}
```

计时器将在启动后通知条件变量它正在运行，并将继续计数，直到`enable_counter`标志被设置为`false`。为了计时一个操作，我们将使用以下命令：

```cpp
template<typename FUNC>
auto timer(FUNC func) {
    std::thread timer{tick};

    std::unique_lock lock(mutex);
    cond.wait(lock);

    func();

    enable_counter = false;
    timer.join();

    return count;
}
```

这个逻辑创建了计时器线程，然后使用条件变量等待它启动。一旦计时器启动，它将执行测试函数，然后禁用计时器并等待线程完成，返回结果的总计时数。

在我们的`protected_main()`函数中，我们要求用户输入在`for`循环中循环的总次数，然后计算执行`for`循环所需的时间，并在完成后将结果输出到`stdout`，如下所示：

```cpp
int
protected_main(int argc, char** argv)
{
    auto args = make_span(argv, argc);

    if (args.size() != 2) {
        std::cerr << "wrong number of arguments\n";
        ::exit(1);
    }

    auto ticks = timer([&] {
        for (auto i = 0; i < std::stoi(args.at(1)); i++) {
        }
    });

    std::cout << "ticks: " << ticks << '\n';

    return EXIT_SUCCESS;
}
```

最后，我们使用我们的`main()`执行`protected_main()`函数，并捕获可能出现的任何异常，如下所示：

```cpp
int
main(int argc, char** argv)
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

# 编译和测试

要编译此代码，我们将利用我们一直在使用的相同`CMakeLists.txt`文件：[`github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/blob/master/Chapter12/CMakeLists.txt`](https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/blob/master/Chapter12/CMakeLists.txt)。

有了这段代码，我们可以使用以下命令编译此代码：

```cpp
> git clone https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP.git
> cd Hands-On-System-Programming-with-CPP/Chapter12/
> mkdir build
> cd build

> cmake ..
> make
```

要执行代码，请运行以下命令：

```cpp
> ./example2 1000000
ticks: 103749316
```

如本片段所示，示例将循环`1000000`次，并将执行循环所需的时钟周期数输出到控制台。

# 研究线程日志示例

本章的最后一个示例将在现有的调试器示例基础上构建，以支持多个客户端。在第十章中，*使用 C++编程 POSIX 套接字*，我们为示例调试器添加了对网络的支持，除了本地系统外，还提供了将调试日志卸载到服务器的功能。

问题在于服务器在关闭之前只能接受一个连接，因为它没有处理多个客户端的逻辑。在这个示例中，我们将解决这个问题。

首先，我们需要定义我们的端口和最大调试字符串长度，如下所示：

```cpp
#define PORT 22000
#define MAX_SIZE 0x1000
```

服务器将需要以下包含语句：

```cpp
#include <array>
#include <unordered_map>

#include <sstream>
#include <fstream>
#include <iostream>

#include <mutex>
#include <thread>

#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
```

与之前的示例一样，日志文件将被定义为全局，并且将添加互斥锁以同步对日志的访问：

```cpp
std::mutex log_mutex;
std::fstream g_log{"server_log.txt", std::ios::out | std::ios::app};
```

我们将全局定义`recv()`函数，而不是在服务器中定义它，以便为客户端线程提供方便访问（每个客户端将生成一个新线程）：

```cpp
ssize_t
recv(int handle, std::array<char, MAX_SIZE> &buf)
{
    return ::recv(
        handle,
        buf.data(),
        buf.size(),
        0
    );
}
```

与`recv()`函数一样，`log()`函数也将从服务器中移出，并将创建我们的客户端线程。每当客户端建立连接时，服务器将生成一个新线程（`log()`函数），其实现如下：

```cpp
void
log(int handle)
{
    while(true)
    {
        std::array<char, MAX_SIZE> buf{};

        if (auto len = recv(handle, buf); len != 0) {

            std::unique_lock lock(log_mutex);

            g_log.write(buf.data(), len);
            std::clog.write(buf.data(), len);

            g_log.flush();
        }
        else {
            break;
        }
    }

    close(handle);
}
```

与在第十章中的示例相比，使用`log()`函数的唯一区别是添加了`std::unique_lock{}`以保护对日志的访问（以防多个客户端同时尝试写入日志）。句柄被传递给日志函数，而不是句柄作为服务器的成员，我们在每次写入后刷新日志文件，以确保所有写入实际写入磁盘，因为我们将通过终止服务器应用程序来关闭它。

最后，服务器被修改为接受传入的连接并生成线程作为结果。服务器从前一个示例中的相同逻辑开始：

```cpp
class myserver
{
    int m_fd{};
    struct sockaddr_in m_addr{};

public:

    myserver(uint16_t port)
    {
        if (m_fd = ::socket(AF_INET, SOCK_STREAM, 0); m_fd == -1) {
            throw std::runtime_error(strerror(errno));
        }

        m_addr.sin_family = AF_INET;
        m_addr.sin_port = htons(port);
        m_addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind() == -1) {
            throw std::runtime_error(strerror(errno));
        }
    }

    int bind()
    {
        return ::bind(
            m_fd,
            reinterpret_cast<struct sockaddr *>(&m_addr),
            sizeof(m_addr)
        );
    }
```

服务器的构造函数创建一个套接字，并将套接字绑定到标识的端口。服务器的主要区别在于使用`listen()`函数，该函数曾经是`log()`函数。考虑以下代码：

```cpp
    void listen()
    {
        if (::listen(m_fd, 0) == -1) {
            throw std::runtime_error(strerror(errno));
        }

        while (true) {
            if (int c = ::accept(m_fd, nullptr, nullptr); c != -1) {

                std::thread t{log, c};
                t.detach();

                continue;
            }

            throw std::runtime_error(strerror(errno));
        }
    }
```

`listen()`函数在套接字上监听新连接。当建立连接时，它使用`log()`函数创建一个线程，并向`log`函数提供新客户端的句柄。

无需确保服务器和/或客户端正确关闭，因为 TCP 将为我们处理这一点，消除了创建每个客户端线程后跟踪每个客户端线程的需要（即，当完成时无需`join()`线程）。因此，我们使用`detach()`函数，告诉 C++不会发生`join()`，线程应该在线程对象被销毁后继续执行。

最后，我们循环等待更多客户端连接。

服务器的剩余逻辑是相同的。我们在`protected_main()`函数中创建服务器，并在`main()`函数中执行`protected_main()`函数，尝试捕获可能发生的任何异常。以下代码显示了这一点：

```cpp
int
protected_main(int argc, char** argv)
{
    (void) argc;
    (void) argv;

    myserver server{PORT};
    server.listen();
}

int
main(int argc, char** argv)
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

最后，此示例的客户端逻辑与第十章中找到的客户端逻辑相同。

# 编译和测试

要编译此代码，我们利用了与其他示例相同的`CMakeLists.txt`文件——[`github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/blob/master/Chapter11/CMakeLists.txt`](https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP/blob/master/Chapter11/CMakeLists.txt)。

有了这个，我们可以使用以下命令编译代码：

```cpp
> git clone https://github.com/PacktPublishing/Hands-On-System-Programming-with-CPP.git
> cd Hands-On-System-Programming-with-CPP/Chapter12/
> mkdir build
> cd build

> cmake ..
> make
```

要执行服务器，请运行以下命令：

```cpp
> ./example3_server
```

要执行客户端，请打开一个新的终端并运行以下命令：

```cpp
> cd Hands-On-System-Programming-with-CPP/Chapter12/build
> ./example3_client
Debug: Hello World
Hello World

> ./example3_client
Debug: Hello World
Hello World

> cat client_log.txt
Debug: Hello World
Debug: Hello World

> cat server_log.txt
Debug: Hello World
Debug: Hello World

```

如本片段所示，当客户端执行时，客户端和服务器端都会将`DEBUG: Hello World`输出到`stderr`。此外，客户端将`Hello World`输出到`stderr`，因为第二次调用`std::clog`时未重定向。

两个日志文件都包含重定向的`DEBUG: Hello World`。最后，我们可以多次执行客户端，导致服务器记录来自两个客户端的输出，而不仅仅是一个。

# 总结

在本章中，我们讨论了如何使用 POSIX 和 C++ API 编程线程。然后我们讨论了三个示例。第一个示例演示了如何使用线程执行并行计算，而第二个示例演示了如何使用线程创建自己的高分辨率计时器来进行基准测试。

最后，第三个示例建立在我们现有的调试示例基础上，为多个客户端提供支持。下一章，也是最后一章，将讨论 C 和 C++提供的错误处理功能，包括 C 风格的错误处理和异常。

# 问题

1.  如何使用 POSIX 获取线程的 ID？在使用 C++时呢？

1.  POSIX 线程输入和输出的主要问题是什么？

1.  什么是竞争条件？

1.  死锁是什么？

1.  C++中的`std::future{}`是什么，它试图解决什么问题？

1.  使用`std::call_once()`的主要原因是什么？

1.  `std::shared_mutex`和`std::mutex`之间有什么区别？

1.  递归互斥锁的目的是什么？

# 进一步阅读

+   [`www.packtpub.com/application-development/c17-example`](https://www.packtpub.com/application-development/c17-example)

+   [`www.packtpub.com/application-development/getting-started-c17-programming-video`](https://www.packtpub.com/application-development/getting-started-c17-programming-video)
