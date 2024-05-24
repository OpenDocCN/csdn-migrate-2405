# C++ 高级编程秘籍（五）

> 原文：[`annas-archive.org/md5/24e080e694c59b3f8e0220d0902724b0`](https://annas-archive.org/md5/24e080e694c59b3f8e0220d0902724b0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：深入了解动态分配

在本章中，您将学习如何处理动态内存分配。本章很重要，因为并非所有变量都可以在全局范围内或堆栈上（即在函数内部）定义，全局内存应尽可能避免使用，而堆栈内存通常比堆内存（用于动态内存分配的内存）有限得多。然而，使用堆内存已经多年导致了许多关于泄漏和悬空指针的错误。

本章不仅将教你动态内存分配的工作原理，还将教你如何在符合 C++核心指南的情况下正确地从堆中分配内存。

从为什么我们使用智能指针以及它们之间的区别，转换和其他引用开始，我们将在本章中简要解释 Linux 下堆的工作原理以及为什么动态内存分配如此缓慢。

在本章中，我们将涵盖以下示例：

+   比较 std::shared_ptr 和 std::unique_ptr

+   从 unique_ptr 转换为 shared_ptr

+   处理循环引用

+   使用智能指针进行类型转换

+   放大堆内存

# 技术要求

要编译和运行本章中的示例，您必须具有对运行 Ubuntu 18.04 的计算机的管理访问权限，并具有功能正常的互联网连接。在运行这些示例之前，您必须使用以下命令安装 Valgrind：

```cpp
> sudo apt-get install build-essential git cmake valgrind 
```

如果这是在 Ubuntu 18.04 之外的任何操作系统上安装的，则需要 GCC 7.4 或更高版本和 CMake 3.6 或更高版本。

本章的代码文件可以在[`github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter10`](https://github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter10)找到。

# 比较 std::shared_ptr 和 std::unique_ptr

在本示例中，我们将学习为什么 C++核心指南不鼓励手动调用 new 和 delete，而是建议使用`std::unique_ptr`和`std::shared_ptr`。我们还将了解`std::unique_ptr`和`std::shared_ptr`之间的区别，以及为什么`std::shared_ptr`应该只在某些情况下使用（也就是说，为什么`std::unique_ptr`很可能是您在大多数情况下应该使用的智能指针类型）。这个示例很重要，因为它将教会你如何在现代 C++中正确分配动态（堆）内存。

# 准备工作

开始之前，请确保已满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

完成此操作后，打开一个新的终端。我们将使用此终端来下载、编译和运行我们的示例。

# 如何做...

按照以下步骤完成这个示例：

1.  从新的终端运行以下命令下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter10
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe01_examples
```

1.  源代码编译完成后，您可以通过运行以下命令来执行本示例中的每个示例：

```cpp
> ./recipe01_example01

> ./recipe01_example02
free(): double free detected in tcache 2
Aborted (core dumped)

> ./recipe01_example03

> ./recipe01_example04

> ./recipe01_example05

> ./recipe01_example06
count: 42

> ./recipe01_example07
count: 33320633

> ./recipe01_example08
count: 42
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 工作原理...

在 C++中，有三种不同的声明变量的方式：

+   **全局变量**：这些是全局可访问的变量。在 Linux 上，这些变量通常存在于可执行文件的`.data`、`.rodata`或`.bss`部分。

+   **堆变量**：这些是你在函数内定义的变量，驻留在应用程序的堆栈内存中，由编译器管理。

+   **堆变量**：这些是使用`malloc()`/`free()`或`new()`/`delete()`创建的变量，并使用由动态内存管理算法（例如`dlmalloc`、`jemalloc`、`tcmalloc`等）管理的堆内存。

在本章中，我们将专注于堆式内存分配。你可能已经知道，在 C++ 中，内存是使用 `new()` 和 `delete()` 分配的，如下所示：

```cpp
int main(void)
{
    auto ptr = new int;
    *ptr = 42;
}
```

正如我们所看到的，一个整数指针（也就是指向整数的指针）被分配，然后设置为 `42`。我们在 C++ 中使用 `new()` 而不是 `malloc()` 有以下原因：

+   `malloc()` 返回 `void *` 而不是我们关心的类型。这可能导致分配不匹配的 bug（也就是说，你想分配一辆车，但实际上分配了一个橙子）。换句话说，`malloc()` 不提供类型安全性。

+   `malloc()` 需要一个大小参数。为了分配内存，我们需要知道为我们关心的类型分配多少字节。这可能导致分配大小不匹配的 bug（也就是说，你想为一辆车分配足够的字节，但实际上只为一个橙子分配了足够的字节）。

+   `malloc()` 在错误时返回 `NULL`，需要在每次分配时进行 `NULL` 检查。

`new()` 运算符解决了所有这些问题：

+   `new()` 返回 `T*`。正如前面的例子所示，这甚至允许使用 `auto`，避免了冗余，因为 C++ 的类型系统有足够的信息来正确分配和跟踪所需的类型。

+   `new()` 不需要大小参数。相反，你告诉它你想要分配的类型，这个类型已经隐含地包含了关于类型的大小信息。再一次，通过简单地声明你想要分配的内容，你就得到了你想要分配的内容，包括适当的指针和大小。

+   `new()` 如果分配失败会抛出异常。这避免了需要进行 `NULL` 检查。如果下一行代码执行，你可以确保分配成功（假设你没有禁用异常）。

然而，`new()` 运算符仍然存在一个问题；`new()` 不跟踪所有权。和 `malloc()` 一样，`new()` 运算符返回一个指针，这个指针可以在函数之间传递，而没有实际拥有指针的概念，这意味着当不再需要指针时应该删除指针。

所有权的概念是 C++ 核心指南的关键组成部分（除了内存跨度），旨在解决 C++ 中常见的导致不稳定、可靠性和安全性错误的 bug。让我们来看一个例子：

```cpp
int main(void)
{
    auto p = new int;
    delete p;

    delete p;
}
```

在上面的例子中，我们分配了一个整数指针，然后两次删除了指针。在之前的例子中，我们实际上从未在退出程序之前删除整数指针。现在，考虑以下代码块：

```cpp
int main(void)
{
    auto p = new int;
    delete p;

    *p = 42;
}
```

在上面的例子中，我们分配了一个整数指针，删除了它，然后使用了它。尽管这些例子看起来简单明了，可以避免，但在大型复杂项目中，这些类型的 bug 经常发生，因此 C++ 社区已经开发了静态和动态分析工具来自动识别这些类型的 bug（尽管它们并不完美），以及 C++ 核心指南本身，试图在第一时间防止这些类型的 bug。

在 C++11 中，标准委员会引入了 `std::unique_ptr` 来解决 `new()` 和 `delete()` 的所有权问题。它的工作原理如下：

```cpp
#include <memory>

int main(void)
{
    auto ptr = std::make_unique<int>();
    *ptr = 42;
}
```

在上面的例子中，我们使用 `std::make_unique()` 函数分配了一个整数指针。这个函数创建了一个 `std::unique_ptr` 并给它分配了一个使用 `new()` 分配的指针。在这里，结果指针（大部分情况下）看起来和行为像一个常规指针，唯一的例外是当 `std::unique_ptr` 失去作用域时，指针会自动被删除。也就是说，`std::unique_ptr` 拥有使用 `std::make_unique()` 分配的指针，并负责指针本身的生命周期。在这个例子中，我们不需要手动运行 `delete()`，因为当 `main()` 函数完成时（也就是 `std::unique_ptr` 失去作用域时），`delete()` 会自动运行。

通过管理所有权的这种简单技巧，可以避免前面代码中显示的大部分错误（我们稍后会讨论）。尽管以下代码不符合 C++核心指南（因为下标运算符不被鼓励），但您也可以使用`std::unique_ptr`来分配数组，如下所示：

```cpp
#include <memory>
#include <iostream>

int main(void)
{
    auto ptr = std::make_unique<int[]>(100);
    ptr[0] = 42;
}
```

如前面的代码所示，我们分配了一个大小为`100`的 C 风格数组，然后设置了数组中的第一个元素。一般来说，您唯一需要的指针类型是`std::unique_ptr`。然而，仍然可能出现一些问题：

+   未正确跟踪指针的生命周期，例如，在函数中分配`std::unique_ptr`并返回生成的指针。一旦函数返回，`std::unique_ptr`失去作用域，因此删除了刚刚返回的指针。`std::unique_ptr` *不* 实现自动垃圾回收。您仍然需要了解指针的生命周期以及它对代码的影响。

+   尽管更加困难，但仍然有可能泄漏内存，因为从未给`std::unique_ptr`提供失去作用域的机会；例如，将`std::unique_ptr`添加到全局列表中，或者在使用`new()`手动分配的类中分配`std::unique_ptr`，然后泄漏。再次强调，`std::unique_ptr` *不* 实现自动垃圾回收，您仍然需要确保在需要时`std::unique_ptr`失去作用域。

+   `std::unique_ptr`也无法支持共享所有权。尽管这是一个问题，但这种类型的情况很少发生。在大多数情况下，`std::unique_ptr`就足以确保适当的所有权。

经常提出的一个问题是，*一旦分配了指针，我们如何安全地将该指针传递给其他函数？* 答案是，您使用`get()`函数并将指针作为常规的 C 风格指针传递。`std::unique_ptr`定义所有权，而不是`NULL`指针安全。`NULL`指针安全由指南支持库提供，其中包括`gsl::not_null`包装器和`expects()`宏。

如何使用这些取决于您的指针哲学：

+   有人认为，任何接受指针作为参数的函数都应该检查`NULL`指针。这种方法的优点是可以快速识别和安全处理`NULL`指针，而缺点是您引入了额外的分支逻辑，这会降低代码的性能和可读性。

+   有人认为接受指针作为参数的*公共*函数应该检查`NULL`指针。这种方法的优点是，性能得到了改善，因为并非所有函数都需要`NULL`指针检查。这种方法的缺点是，公共接口仍然具有额外的分支逻辑。

+   有人认为函数应该简单地记录其期望（称为合同）。这种方法的好处是，`assert()`和`expects()`宏可以在调试模式下用于检查`NULL`指针以强制执行此合同，而在发布模式下，不会有性能损失。这种方法的缺点是，在发布模式下，所有的赌注都关闭。

您采取的方法很大程度上取决于您正在编写的应用程序类型。如果您正在编写下一个 Crush 游戏，您可能更关心后一种方法，因为它的性能最佳。如果您正在编写一个将自动驾驶飞机的应用程序，我们都希望您使用第一种方法。

为了演示如何使用`std::unique_ptr`传递指针，让我们看一下以下示例：

```cpp
std::atomic<int> count;

void inc(int *val)
{
    count += *val;
}
```

假设您有一个作为线程执行的超级关键函数，该函数以整数指针作为参数，并将提供的整数添加到全局计数器中。该线程的前面实现是*所有的赌注都关闭*，交叉双手，然后希望最好的方法。可以实现此函数如下：

```cpp
void inc(int *val)
{
    if (val != nullptr) {
        count += *val;
    }
    else {
        std::terminate();
    }
}
```

前面的函数调用`std::terminate()`（不是一个非常容错的方法），如果提供的指针是`NULL`指针。正如我们所看到的，这种方法很难阅读，因为这里有很多额外的逻辑。我们可以按照以下方式实现这一点：

```cpp
void inc(gsl::not_null<int *> val)
{
    count += *val;
}
```

这与`NULL`指针检查做的事情相同（取决于您如何定义`gsl::not_null`的工作方式，因为这也可能会抛出异常）。您也可以按照以下方式实现这一点：

```cpp
void inc(int *val)
{
    expects(val);
    count += *val;
}
```

前面的示例总是检查`NULL`指针，而前面的方法使用了合同方法，允许在发布模式中删除检查。您也可以使用`assert()`（如果您没有使用 GSL...当然，这绝对不应该是这种情况）。

还应该注意，C++标准委员会正在通过使用 C++合同将`expects()`逻辑作为语言的核心组件添加到语言中，这是一个遗憾的特性，它在 C++20 中被删除了，但希望它会在未来的标准版本中添加，因为我们可能能够按照以下方式编写前面的函数（并告诉编译器我们希望使用哪种方法，而不必手动编写）：

```cpp
void inc(int *val) [[expects: val]]
{
    count += *val;
}
```

我们可以按以下方式使用这个函数：

```cpp
int main(void)
{
    auto ptr = std::make_unique<int>(1);
    std::array<std::thread, 42> threads;

    for (auto &thread : threads) {
        thread = std::thread{inc, ptr.get()};
    }

    for (auto &thread : threads) {
        thread.join();
    }

    std::cout << "count: " << count << '\n';

    return 0;
}
```

从前面的代码示例中，我们可以观察到以下内容：

+   我们使用`std::make_unique()`从堆中分配一个整数指针，它返回`std::unique_ptr()`。

+   我们创建一个线程数组，并执行每个线程，将新分配的指针传递给每个线程。

+   最后，我们等待所有线程完成并输出结果计数。由于`std::unique_ptr`的作用域限于`main()`函数，我们必须确保线程在`main()`函数返回之前完成。

前面的示例导致以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/174f4cca-9a24-4400-8cc9-193f3b2d646b.png)

如前面提到的，前面的示例将`std::unique_ptr`定义为`main()`函数的作用域，这意味着我们必须确保线程在`main()`函数返回之前完成。这种情况并非总是如此。让我们看下面的例子：

```cpp
std::atomic<int> count;

void inc(int *val)
{
    count += *val;
}
```

在这里，我们创建一个函数，当给定一个整数指针时，它会增加一个计数：

```cpp
int main(void)
{
    std::array<std::thread, 42> threads;

    {
        auto ptr = std::make_unique<int>(1);

        for (auto &thread : threads) {
            thread = std::thread{inc, ptr.get()};
        }
    }

    for (auto &thread : threads) {
        thread.join();
    }

    std::cout << "count: " << count << '\n';

    return 0;
}
```

如前面的代码所示，`main()`函数与我们之前的示例相同，唯一的区别是`std::unique_ptr`是在自己的作用域中创建的，并在需要完成线程之前释放。这导致以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/cf6bd321-786d-4be2-9694-3287c2c6229f.png)

如前面的截图所示，由于线程试图从已删除的内存中读取（即，线程被给予了悬空指针），结果输出是垃圾。

尽管这是一个简单的例子，但在更复杂的情况下，这种情况可能会发生，问题的根源是共享所有权。在这个例子中，每个线程都拥有指针。换句话说，没有一个线程试图独占指针（包括分配和执行其他线程的主线程）。尽管这种问题通常发生在具有无主线程设计的多线程应用程序中，但这也可能发生在异步逻辑中，其中指针被分配然后传递给多个异步作业，其生命周期和执行点是未知的。

为了处理这些特定类型的问题，C++提供了`std::shared_ptr`。这是一个受控对象的包装器。每次复制`std::shared_ptr`时，受控对象会增加一个内部计数器，用于跟踪指针（受控对象存储的）的所有者数量。每次`std::shared_ptr`失去作用域时，受控对象会减少内部计数器，并在此计数达到`0`时删除指针。使用这种方法，`std::shared_ptr`能够支持一对多的所有权模型，可以处理我们之前定义的情况。

让我们看下面的例子：

```cpp
std::atomic<int> count;

void inc(std::shared_ptr<int> val)
{
    count += *val;
}
```

如前面的代码所示，我们有相同的线程函数来增加一个计数器，但不同之处在于它接受`std::shared_ptr`而不是常规整数指针。现在，我们可以按照前面的示例实现如下：

```cpp
int main(void)
{
    std::array<std::thread, 42> threads;

    {
        auto ptr = std::make_shared<int>(1);

        for (auto &thread : threads) {
            thread = std::thread{inc, ptr};
        }
    }

    for (auto &thread : threads) {
        thread.join();
    }

    std::cout << "count: " << count << '\n';

    return 0;
}
```

如前面的代码所示，指针在自己的作用域中创建，然后在需要完成线程之前被移除。然而，与之前的示例不同，这段代码的结果如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/510ee43e-1a06-46ff-8411-882af9ebb984.png)

前面的代码之所以能够正确执行，是因为指针的所有权在所有线程之间共享，并且指针本身在所有线程完成之前不会被删除（即使作用域丢失）。

最后一点说明：当`std::unique_ptr`应该被使用时，可能会诱人使用`std::shared_ptr`来代替，因为它具有良好的类型转换 API，并且理论上可以确保函数具有有效的指针。现实情况是，无论使用`std::shared_ptr`还是`std::unique_ptr`，函数都必须根据应用程序的需求执行其`NULL`检查，因为`std::shared_ptr`仍然可以被创建为`NULL`指针。

`std::shared_ptr`也有额外的开销，因为它必须在内部存储所需的删除器。它还需要为受管理对象进行额外的堆分配。`std::shared_ptr`和`std::unique_ptr`都定义了指针所有权。它们不提供自动垃圾回收（即它们不自动处理指针的生命周期），也不能保证指针不是`NULL`。`std::shared_ptr`应该只在多个东西必须拥有指针的生命周期以确保应用程序的正确执行时使用；否则，请使用`std::unique_ptr`。

# 从`std::unique_ptr`转换为`std::shared_ptr`

在这个配方中，我们将学习如何将`std::unique_ptr`转换为`std::shared_ptr`。这个配方很重要，因为通常在定义 API 时，接受`std::unique_ptr`是很方便的，而 API 本身实际上需要`std::shared_ptr`来进行内部使用。一个很好的例子是创建 GUI API。您可能会将一个小部件传递给 API 来存储和拥有，而不知道以后在 GUI 的实现中可能需要添加线程，这种情况下`std::shared_pointer`可能是一个更好的选择。这个配方将为您提供将`std::unique_ptr`转换为`std::shared_ptr`的技能，如果需要的话，而不必修改 API 本身。

# 准备工作

开始之前，请确保已满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 操作步骤

按照以下步骤完成这个配方：

1.  从一个新的终端中运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter10
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe02_examples
```

1.  源代码编译完成后，可以通过运行以下命令来执行本配方中的每个示例：

```cpp
> ./recipe02_example01 
count: 42
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本配方中所教授的课程的关系。

# 工作原理

`std::shared_ptr`用于管理指针，当多个东西必须拥有指针才能正确执行应用程序时。然而，假设您提供了一个必须接受整数指针的 API，如下所示：

```cpp
void execute_threads(int *ptr);
```

前面的 API 表明，调用这个函数的人拥有整数指针。也就是说，调用这个函数的人需要分配整数指针，并在函数完成后删除它。然而，如果我们打算让前面的 API 拥有指针，我们真的应该将这个 API 写成如下形式：

```cpp
void execute_threads(std::unique_ptr<int> ptr);
```

这个 API 说，*请为我分配一个整数指针，但一旦传递给我，我就拥有它，并将在需要时确保它被删除。*现在，假设这个函数将在一个一对多的所有权场景中使用这个指针。你会怎么做？你可以将你的 API 写成下面这样：

```cpp
void execute_threads(std::shared_ptr<int> ptr);
```

然而，这将阻止您的 API 在将来优化一对多的关系（也就是说，如果将来能够移除这种关系，您仍将被困在`std::shared_ptr`中，即使在不修改 API 函数签名的情况下，它也是次优的）。

为了解决这个问题，C++ API 提供了将`std::unique_ptr`转换为`std::shared_ptr`的能力，如下所示：

```cpp
std::atomic<int> count;

void
inc(std::shared_ptr<int> val)
{
    count += *val;
}
```

假设我们有一个内部函数，暂时以`std::shared_ptr`的整数指针作为参数，使用它的值来增加`count`，并将其作为线程执行。然后，我们为其提供一个公共 API 来使用这个内部函数，如下所示：

```cpp
void
execute_threads(std::unique_ptr<int> ptr)
{
    std::array<std::thread, 42> threads;
    auto shared = std::shared_ptr<int>(std::move(ptr));

    for (auto &thread : threads) {
        thread = std::thread{inc, shared};
    }

    for (auto &thread : threads) {
        thread.join();
    }
}
```

如前面的代码所示，我们的 API 声明拥有先前分配的整数指针。然后，它创建一系列线程，执行每一个并等待每个线程完成。问题在于我们的内部函数需要一个`std::shared_ptr`（例如，也许这个内部函数在代码的其他地方被使用，那里有一个一对多的所有权场景，我们目前无法移除）。

为了避免需要用`std::shared_ptr`定义我们的公共 API，我们可以通过将`std::unique_ptr`移动到一个新的`std::shared_ptr`中，然后从那里调用我们的线程来将`std::unique_ptr`转换为`std::shared_ptr`。

`std::move()`是必需的，因为传递`std::unique_ptr`所有权的唯一方法是通过使用`std::move()`（因为在任何给定时间只有一个`std::unique_ptr`可以拥有指针）。

现在，我们可以执行这个公共 API，如下所示：

```cpp
int main(void)
{
    execute_threads(std::make_unique<int>(1));
    std::cout << "count: " << count << '\n';

    return 0;
}
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/3662afb6-a730-4b83-a259-0d9182ad87de.png)

在未来，我们可能能够消除对`std::shared_ptr`的需求，并使用`get()`函数将`std::unique_ptr`传递给我们的内部函数，当那个时候，我们就不必修改公共 API 了。

# 处理循环引用

在这个示例中，我们将学习如何处理循环引用。循环引用发生在我们使用多个`std::shared_ptr`时，每个`std::shared_ptr`都拥有对另一个的引用。这个示例很重要，因为在处理循环依赖对象时可能会出现这种循环引用（尽管在可能的情况下应该避免）。如果发生了，`std::shared_ptr`的共享特性会导致内存泄漏。这个示例将教会你如何使用`std::weak_ptr`来避免这种内存泄漏。

# 准备工作

在开始之前，请确保已满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake valgrind 
```

完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

要处理循环引用，请执行以下步骤：

1.  从一个新的终端，运行以下命令下载本示例的源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter10
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe03_examples
```

1.  一旦源代码编译完成，您可以通过运行以下命令来执行本示例中的每个示例：

```cpp
> valgrind ./recipe03_example01
...
==7960== HEAP SUMMARY:
==7960== in use at exit: 64 bytes in 2 blocks
==7960== total heap usage: 3 allocs, 1 frees, 72,768 bytes allocated
...

> valgrind ./recipe03_example02
...
==7966== HEAP SUMMARY:
==7966== in use at exit: 64 bytes in 2 blocks
==7966== total heap usage: 4 allocs, 2 frees, 73,792 bytes allocated
...

> valgrind ./recipe03_example03
...
==7972== HEAP SUMMARY:
==7972== in use at exit: 0 bytes in 0 blocks
==7972== total heap usage: 4 allocs, 4 frees, 73,792 bytes allocated
...

> valgrind ./recipe03_example04
...
==7978== HEAP SUMMARY:
==7978== in use at exit: 0 bytes in 0 blocks
==7978== total heap usage: 4 allocs, 4 frees, 73,792 bytes allocated
...
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本示例教授的课程的关系。

# 它是如何工作的...

尽管应该避免，但随着项目变得越来越复杂和庞大，循环引用很可能会发生。当这些循环引用发生时，如果使用共享智能指针，可能会导致难以发现的内存泄漏。为了理解这是如何可能的，让我们看下面的例子：

```cpp
class car;
class engine;
```

如前所示，我们从两个类原型开始。循环引用几乎总是以这种方式开始，因为一个类依赖于另一个类，反之亦然，需要使用类原型。

让我们定义一个`car`如下：

```cpp
class car
{
    friend void build_car();
    std::shared_ptr<engine> m_engine;

public:
    car() = default;
};
```

如前所示，这是一个简单的类，它存储了一个指向`engine`的 shared pointer，并且是`build_car()`函数的友元。现在，我们可以定义一个`engine`如下：

```cpp
class engine
{
    friend void build_car();
    std::shared_ptr<car> m_car;

public:
    engine() = default;
};
```

如前所示，`engine`类似于`car`，不同之处在于 engine 存储了一个指向 car 的 shared pointer。两者都是`build_car()`函数的友元。它们都创建默认构造的 shared pointers，这意味着它们的 shared pointers 在构造时是`NULL`指针。

`build_car()`函数用于完成每个对象的构建，如下所示：

```cpp
void build_car()
{
    auto c = std::make_shared<car>();
    auto e = std::make_shared<engine>();

    c->m_engine = e;
    e->m_car = c;
}
```

如前所示，我们创建每个对象，然后设置 car 的 engine，反之亦然。由于 car 和 engine 都限定在`build_car()`函数中，我们期望一旦`build_car()`函数返回，这些指针将被删除。现在，我们可以执行`build_car()`函数如下：

```cpp
int main(void)
{
    build_car();
    return 0;
}
```

这似乎是一个简单的程序，但却很难找到内存泄漏。为了证明这一点，让我们在`valgrind`中运行此应用程序，`valgrind`是一种动态内存分析工具，能够检测内存泄漏：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/d039e626-58e3-4399-88f3-bb7b58a9d235.png)

如前所示的截图显示，`valgrind`表示有内存泄漏。如果我们使用`--leak-check=full`运行`valgrind`，它会告诉我们内存泄漏出现在 car 和 engine 的 shared pointers 中。这种内存泄漏发生的原因是 car 持有对 engine 的 shared reference。同样的 engine 也持有对 car 本身的 shared reference。

例如，考虑以下代码：

```cpp
void build_car()
{
    auto c = std::make_shared<car>();
    auto e = std::make_shared<engine>();

    c->m_engine = e;
    e->m_car = c;

    std::cout << c.use_count() << '\n';
    std::cout << e.use_count() << '\n';
}
```

如前所示，我们添加了对`use_count()`的调用，它输出`std::shared_ptr`包含的所有者数量。如果执行此操作，将会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/0fe8e3a7-4ec9-46f6-9e6f-14f91b815586.png)

我们看到两个所有者是因为`build_car()`函数在这里持有对 car 和 engine 的引用：

```cpp
    auto c = std::make_shared<car>();
    auto e = std::make_shared<engine>();
```

由于这个原因，car 持有对 engine 的第二个引用：

```cpp
    c->m_engine = e;
```

对于 engine 和 car 也是一样的。当`build_car()`函数完成时，以下内容首先失去了作用域：

```cpp
    auto e = std::make_shared<engine>();
```

然而，engine 不会被删除，因为 car 仍然持有对 engine 的引用。然后，car 失去了作用域：

```cpp
    auto c = std::make_shared<car>();
```

然而，car 没有被删除，因为 engine（尚未被删除）也持有对 car 的引用。这导致`build_car()`返回时，car 和 engine 都没有被删除，因为它们仍然相互持有引用，没有办法告诉任何一个对象删除它们的引用。

尽管在我们的示例中很容易识别出这种循环内存泄漏，但在复杂的代码中很难识别，这是共享指针和循环依赖应该避免的许多原因之一（通常更好的设计可以消除对两者的需求）。如果无法避免，可以使用`std::weak_ptr`，如下所示：

```cpp
class car
{
    friend void build_car();
    std::shared_ptr<engine> m_engine;

public:
    car() = default;
};
```

如前所示，我们仍然定义我们的 car 持有对 engine 的 shared reference。我们这样做是因为我们假设 car 的寿命更长（也就是说，在我们的模型中，你可以有一辆没有发动机的车，但你不能没有车的发动机）。然而，engine 的定义如下：

```cpp
class engine
{
    friend void build_car();
    std::weak_ptr<car> m_car;

public:
    engine() = default;
};
```

如前所示，engine 现在存储了对 car 的弱引用。我们的`build_car()`函数定义如下：

```cpp
void build_car()
{
    auto c = std::make_shared<car>();
    auto e = std::make_shared<engine>();

    c->m_engine = e;
    e->m_car = c;

    std::cout << c.use_count() << '\n';
    std::cout << e.use_count() << '\n';
}
```

如前所示，`build_car()`函数没有改变。现在的区别在于，当我们使用`valgrind`执行此应用程序时，会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/0ac121f9-776c-48ff-a5e0-fdbe56d97fa4.png)

如前面的屏幕截图所示，没有内存泄漏，汽车的`use_count()`为`1`，而引擎的`use_count()`与之前的例子相比仍为`2`。在引擎类中，我们使用`std::weak_ptr`，它可以访问`std::shared_ptr`管理的托管对象，但在创建时不会增加托管对象的内部计数。这使得`std::weak_ptr`能够查询`std::shared_ptr`是否有效，而无需持有指针本身的强引用。

内存泄漏被消除的原因是，当引擎失去作用域时，其使用计数从`2`减少到`1`。一旦汽车失去作用域，其使用计数仅为`1`，就会被删除，从而将引擎的使用计数减少到`0`，这将导致引擎也被删除。

我们在引擎中使用`std::weak_ptr`而不是 C 风格指针的原因是，`std::weak_ptr`使我们能够查询托管对象，以查看指针是否仍然有效。例如，假设我们需要检查汽车是否仍然存在，如下所示：

```cpp
class engine
{
    friend void build_car();
    std::weak_ptr<car> m_car;

public:
    engine() = default;

    void test()
    {
        if (m_car.expired()) {
            std::cout << "car deleted\n";
        }
    }
};
```

通过使用`expired()`函数，我们可以在使用汽车之前测试汽车是否仍然存在，这是使用 C 风格指针无法实现的。现在，我们可以编写我们的`build_car()`函数如下：

```cpp
void build_car()
{
 auto e = std::make_shared<engine>();

 {
 auto c = std::make_shared<car>();

 c->m_engine = e;
 e->m_car = c;
 }

 e->test();
}
```

在前面的示例中，我们创建了一个引擎，然后创建了一个创建汽车的新作用域。然后，我们创建了我们的循环引用并失去了作用域。这导致汽车被删除，这是预期的。不同之处在于，我们的引擎尚未被删除，因为我们仍然持有对它的引用。现在，我们可以运行我们的测试函数，当使用`valgrind`运行时，会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/37efcbf4-6ee5-4fef-b31a-150aa6c7b76f.png)

如前面的屏幕截图所示，没有内存泄漏。`std::weak_ptr`成功消除了循环引用引入的鸡和蛋问题。因此，`std::shared_ptr`能够按预期释放内存。通常情况下，应尽量避免循环引用和依赖关系，但如果无法避免，可以使用`std::weak_ptr`（如本教程所示）来防止内存泄漏。

# 使用智能指针进行类型转换

在本教程中，我们将学习如何使用`std::unique_ptr`和`std::shared_ptr`进行类型转换。类型转换允许将一种类型转换为另一种类型。本教程很重要，因为它演示了在尝试转换智能指针类型（例如，在虚拟继承中进行向上转型或向下转型）时，使用`std::unique_ptr`和`std::shared_ptr`处理类型转换的正确方式。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

为了了解类型转换的工作原理，请执行以下步骤：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter10
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe04_examples
```

1.  源代码编译完成后，可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe04_example01
downcast successful!!

> ./recipe04_example02
downcast successful!!
```

在接下来的部分，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本教程所教授的课程的关系。

# 工作原理...

使用智能指针进行类型转换并不像你期望的那样简单。

为了更好地解释这一点，让我们看一个简单的例子，演示如何使用`std::unique_ptr`从基类转换为子类：

```cpp
class base
{
public:
    base() = default;
    virtual ~base() = default;
};
```

让我们看看这是如何工作的：

1.  我们从一个虚拟基类开始，如前面的代码所示，然后我们将基类子类化如下：

```cpp
class subclass : public base
{
public:
    subclass() = default;
    ~subclass() override = default;
};
```

1.  接下来，在我们的`main()`函数中创建一个`std::unique_ptr`，并将指针传递给一个`foo()`函数：

```cpp
int main(void)
{
    auto ptr = std::make_unique<subclass>();
    foo(ptr.get());

    return 0;
}
```

`std::unique_ptr`只是简单地拥有指针的生命周期。对指针的任何使用都需要使用`get()`函数，从那时起将`std::unique_ptr`转换为普通的 C 风格指针。这是`std::unique_ptr`的预期用法，因为它不是设计为确保指针安全，而是设计为确保谁拥有指针是明确定义的，最终确定指针何时应该被删除。

1.  现在，`foo()`函数可以定义如下：

```cpp
void foo(base *b)
{
    if (dynamic_cast<subclass *>(b)) {
        std::cout << "downcast successful!!\n";
    }
}
```

在上面的代码中，`foo()`函数可以将指针视为普通的 C 风格指针，使用`dynamic_cast()`从基类指针向下转换回原始子类。

标准 C++的这种类型转换方式在`std::shared_ptr`中不起作用。原因是需要类型转换版本的`std::shared_ptr`的代码可能还需要保存指针的引用（即`std::shared_ptr`的副本以防止删除）。

也就是说，从`base *b`到`std::shared_ptr<subclass>`是不可能的，因为`std::shared_ptr`不持有指针的引用；相反，它持有托管对象的引用，该对象存储对实际指针的引用。由于`base *b`不存储托管对象，因此无法从中创建`std::shared_ptr`。

然而，C++提供了`std::shared_ptr`版本的`static_cast()`、`reinterpret_cast()`、`const_cast()`和`dynamic_cast()`来执行共享指针的类型转换，这样在类型转换时可以保留托管对象。让我们看一个例子：

```cpp
class base
{
public:
    base() = default;
    virtual ~base() = default;
};

class subclass : public base
{
public:
    subclass() = default;
    ~subclass() override = default;
};
```

如上所示，我们从相同的基类和子类开始。不同之处在于我们的`foo()`函数：

```cpp
void foo(std::shared_ptr<base> b)
{
    if (std::dynamic_pointer_cast<subclass>(b)) {
        std::cout << "downcast successful!!\n";
    }
}
```

它不再使用`base *b`，而是使用`std::shared_ptr<base>`。现在，我们可以使用`std::dynamic_pointer_cast()`函数而不是`dynamic_cast()`来将`std::shared_ptr<base>`向下转换为`std::shared_ptr<subclass>`。`std::shared_ptr`类型转换函数为我们提供了在需要时进行类型转换并仍然保持对`std::shared_ptr`的访问权限的能力。

生成的`main()`函数将如下所示：

```cpp
int main(void)
{
    auto ptr = std::make_shared<subclass>();
    foo(ptr);

    return 0;
}
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/8b7d0aa2-1117-4b34-a220-0b1bba6777d6.png)

需要注意的是，我们不需要显式上转型，因为这可以自动完成（类似于常规指针）。我们只需要显式下转型。

# 放大堆

在这个示例中，我们将学习 Linux 中堆的工作原理。我们将深入了解 Linux 在您使用`std::unique_ptr`时如何提供堆内存。

尽管本示例是为那些具有更高级能力的人准备的，但它很重要，因为它将教会您如何从堆中分配内存（即使用`new()`/`delete()`）的应用程序，从而向您展示为什么堆分配不应该从时间关键代码中执行，因为它们很慢。本示例将教会您在何时执行堆分配是安全的，以及何时应该避免在您的应用程序中执行堆分配，即使我们检查的一些汇编代码很难跟踪。

# 准备工作

开始之前，请确保已满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做到...

要尝试本章的代码文件，请按照以下步骤进行：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter10
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe05_examples
```

1.  源代码编译完成后，可以通过运行以下命令执行本示例中的每个示例：

```cpp
> ./recipe05_example01
```

在下一节中，我们将逐个步骤地介绍每个示例，并解释每个示例程序的作用以及它与本示例教授的课程的关系。

# 工作原理...

为了更好地理解代码需要执行多少次以在堆上分配变量，我们将从以下简单示例开始：

```cpp
int main(void)
{
    auto ptr = std::make_unique<int>();
}
```

如前面的示例所示，我们使用`std::unique_ptr()`分配了一个整数。我们使用`std::unique_ptr()`作为起点，因为这是大多数 C++核心指南代码在堆上分配内存的方式。

`std::make_unique()`函数使用以下伪逻辑分配了一个`std::unique_ptr`（这是一个简化的例子，因为这并没有显示如何处理自定义删除器）：

```cpp
namespace std
{
    template<typename T, typename... ARGS>
    auto make_unique(ARGS... args)
    {
        return std::unique_ptr(new T(std::forward<ARGS>(args)...));
    }
}
```

如前面的代码所示，`std::make_unique()`函数创建了一个`std::unique_ptr`，并为其分配了一个使用`new()`操作符的指针。一旦`std::unique_ptr`失去作用域，它将使用`delete()`删除指针。

当编译器看到`new`操作符时，它会用对`new(unsigned long)`的调用替换代码。为了看到这一点，让我们看下面的例子：

```cpp
int main(void)
{
    auto ptr = new int;
}
```

在前面的示例中，我们使用`new()`分配了一个简单指针。现在，我们可以查看生成的汇编代码，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/b091f70c-4180-4aa8-a75b-8d820a238fbb.png)

如下截图所示，调用了`_Znwm`，这是 C++代码的名称修饰，对应的是`operator new(unsigned long)`，很容易进行名称还原：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/c027acee-fceb-4dbb-89c2-3bd138eecd8c.png)

`new()`操作符本身看起来像以下伪代码（请注意，这不考虑禁用异常支持或提供新处理程序的能力）：

```cpp
void* operator new(size_t size)
{
    if (auto ptr = malloc(size)) {
        return ptr;
    }

    throw std::bad_alloc();
}
```

现在，我们可以查看`new`操作符，看看`malloc()`是如何被调用的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/837ddc0c-aa39-4480-a9dd-618520a38d5f.png)

如前面的截图所示，调用了`malloc()`。如果结果指针不是`NULL`，则操作符返回；否则，它进入错误状态，这涉及调用新处理程序，最终抛出`std::bad_alloc()`（至少默认情况下）。

`malloc()`本身的调用要复杂得多。当应用程序启动时，它首先要做的是保留堆空间。操作系统为每个应用程序提供了一个连续的虚拟内存块，而在 Linux 上，堆是应用程序内存中的最后一个块（也就是说，`new()`返回的内存来自应用程序内存空间的末尾）。将堆放在这里为操作系统提供了一种在需要时向应用程序添加额外内存的方法（因为操作系统只是扩展应用程序的虚拟内存的末尾）。

应用程序本身使用`sbrk()`函数在内存不足时向操作系统请求更多内存。调用此函数时，操作系统会从内部页池中分配内存页，并通过移动应用程序的内存空间末尾将此内存映射到应用程序中。映射过程本身很慢，因为操作系统不仅需要从池中分配页，这需要某种搜索和保留逻辑，还必须遍历应用程序的页表，将此额外内存添加到其虚拟地址空间中。

一旦`sbrk()`提供了额外内存，`malloc()`引擎接管。正如我们之前提到的，操作系统只是将内存页映射到应用程序中。每个页面的大小可以是 4k 字节，也可以是从 2MB 到 1GB 不等，具体取决于请求。然而，在我们的例子中，我们只分配了一个简单的整数，大小只有`4`字节。为了将页面转换为小对象而不浪费内存，`malloc()`本身有一个算法，将操作系统提供的内存分成小块。该引擎还必须处理这些内存块何时被释放，以便它们可以再次使用。这需要复杂的数据结构来管理应用程序的所有内存，并且每次调用`malloc()`、`free()`、`new()`和`delete()`都必须执行这种逻辑。

使用`std::make_unique()`创建`std::unique_ptr`的简单调用必须使用`new()`分配内存来创建`std::unique_ptr`，而`new()`实际上调用`malloc()`，必须通过复杂的数据结构搜索可用的内存块，最终可以返回，也就是假设`malloc()`有空闲内存，并且不必使用`sbrk()`向操作系统请求更多内存。

换句话说，动态（即堆）内存很慢，应该只在需要时使用，并且在时间关键的代码中最好不要使用。


# 第十一章：C++中的常见模式

在本章中，您将学习 C++中的各种设计模式。设计模式提供了解决不同类型问题的常见方法，通常在互联网上、会议上以及在工作中的水机前讨论设计模式的优缺点。

本章的目标是向您介绍一些更受欢迎、不太受欢迎甚至有争议的模式，让您了解设计模式试图解决的不同类型问题。这是一个重要的章节，因为它将教会您如何通过教授已经存在的解决方案来解决自己应用程序中遇到的常见问题。学习这些设计模式中的任何一种都将为您打下基础，使您能够在自己的应用程序中遇到问题时自行发现其他设计模式。

本章中的示例如下：

+   学习工厂模式

+   正确使用单例模式

+   使用装饰器模式扩展您的对象

+   使用观察者模式添加通信

+   通过静态多态性提高性能

# 技术要求

要编译和运行本章中的示例，您必须具有管理访问权限，可以访问具有功能互联网连接的运行 Ubuntu 18.04 的计算机。在运行这些示例之前，您必须安装以下内容：

```cpp
> sudo apt-get install build-essential git cmake 
```

如果这是在 Ubuntu 18.04 之外的任何操作系统上安装的，则需要 GCC 7.4 或更高版本和 CMake 3.6 或更高版本。

本章的代码文件可以在[`github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter11`](https://github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter11)找到。

# 学习工厂模式

在本示例中，我们将学习工厂模式是什么，如何实现它以及何时使用它。这个示例很重要，特别是在单元测试时，因为工厂模式提供了添加接缝（即，代码中提供机会进行更改的有意义的地方）的能力，能够改变另一个对象分配的对象类型，包括分配虚假对象进行测试的能力。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

按照以下步骤尝试工厂模式的代码：

1.  从一个新的终端中，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter11
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe01_examples
```

1.  一旦源代码编译完成，您可以通过运行以下命令来执行本章中的每个示例：

```cpp
> ./recipe01_example01

> ./recipe01_example02

> ./recipe01_example03
correct answer: The answer is: 42

> ./recipe01_example04
wrong answer: Not sure

> ./recipe01_example05
correct answer: The answer is: 42
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 它是如何工作的...

工厂模式提供了一个分配资源的对象，可以更改对象分配的类型。为了更好地理解这种模式的工作原理以及它为什么如此有用，让我们看下面的例子：

```cpp
class know_it_all
{
public:
    auto ask_question(const char *question)
    {
        (void) question;
        return answer("The answer is: 42");
    }
};
```

正如前面的代码所示，我们从一个名为`know_it_all`的类开始，当被问及问题时，它会提供一个答案。在这种情况下，无论问什么问题，它总是返回相同的答案。答案定义如下：

```cpp
class answer
{
    std::string m_answer;

public:
    answer(std::string str) :
        m_answer{std::move(str)}
    { }
};
```

如前所示，答案是一个简单的类，它根据一个字符串构造并在内部存储字符串。在这种情况下，重要的是要注意，这个 API 的用户实际上无法提取答案类存储的字符串，这意味着使用这些 API 的方式如下：

```cpp
int main(void)
{
    know_it_all universe;
    auto ___ = universe.ask_question("What is the meaning of life?");
}
```

如上所示，我们可以提问，得到一个结果，但我们不确定实际提供了什么结果。这种问题在面向对象编程中经常存在，测试这种逻辑是为什么整本书都写了。模拟是一个专门设计用来验证测试输出的假对象（不像假对象，它只是提供测试输入的对象）。然而，在上面的例子中，模拟仍然需要一种方式来创建，以便验证函数的输出。这就是工厂模式的作用。

让我们修改`answer`类，如下所示：

```cpp
class answer
{
    std::string m_answer;

public:
    answer(std::string str) :
        m_answer{std::move(str)}
    { }

    static inline auto make_answer(std::string str)
    { return answer(str); }
};
```

如上所示的代码中，我们添加了一个静态函数，允许`answer`类创建自己的实例。我们没有改变`answer`类不提供提取其内部内容的能力，只是改变了`answer`类的创建方式。然后我们可以修改`know_it_all`类，如下所示：

```cpp
template<factory_t factory = answer::make_answer>
class know_it_all
{
public:
    auto ask_question(const char *question)
    {
        (void) question;
        return factory("The answer is: 42");
    }
};
```

如上所示的代码中，唯一的区别是`know_it_all`类接受`factory_t`的模板参数，并使用它来创建`answer`类，而不是直接创建`answer`类。`factory_t`的定义如下：

```cpp
using factory_t = answer(*)(std::string str);
```

这默认使用了我们添加到`answer`类中的静态`make_answer()`函数。在最简单的形式下，上面的例子演示了工厂模式。我们不直接创建对象，而是将对象的创建委托给另一个对象。上述实现并不改变这两个类的使用方式，如下所示：

```cpp
int main(void)
{
    know_it_all universe;
    auto ___ = universe.ask_question("What is the meaning of life?");
}
```

如上所示，`main()`逻辑保持不变，但这种新方法确保`know_it_all`类专注于回答问题，而不必担心如何创建`answer`类本身，将这个任务留给另一个对象。这个微妙变化背后的真正力量是，我们现在可以为`know_it_all`类提供一个不同的工厂，从而返回一个不同的`answer`类。为了演示这一点，让我们创建一个新的`answer`类，如下所示：

```cpp
class expected_answer : public answer
{
public:
    expected_answer(std::string str) :
        answer{str}
    {
        if (str != "The answer is: 42") {
            std::cerr << "wrong answer: " << str << '\n';
            exit(1);
        }

        std::cout << "correct answer: " << str << '\n';
    }

    static inline answer make_answer(std::string str)
    { return expected_answer(str); }
};
```

如上所示，我们创建了一个新的`answer`类，它是原始`answer`类的子类。这个新类在构造时检查给定的值，并根据提供的字符串输出成功或失败。然后我们可以使用这个新的`answer`类，如下所示：

```cpp
int main(void)
{
    know_it_all<expected_answer::make_answer> universe;
    auto ___ = universe.ask_question("What is the meaning of life?");
}
```

以下是结果输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/41a225db-9424-4bd1-aa9f-8be824d88b8d.png)

使用上述方法，我们可以询问不同的问题，以查看`know_it_all`类是否提供了正确的答案，而无需修改原始的`answer`类。例如，假设`know_it_all`类是这样实现的：

```cpp
template<factory_t factory = answer::make_answer>
class know_it_all
{
public:
    auto ask_question(const char *question)
    {
        (void) question;
        return factory("Not sure");
    }
};
```

我们测试了这个`know_it_all`类的版本，如下所示：

```cpp
int main(void)
{
    know_it_all<expected_answer::make_answer> universe;
    auto ___ = universe.ask_question("What is the meaning of life?");
}
```

结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/3626806f-b78e-4c07-81cf-329507c18135.png)

应该注意的是，有几种实现工厂模式的方法。上述方法使用模板参数来改变`know_it_all`类创建答案的方式，但我们也可以使用运行时方法，就像这个例子中一样：

```cpp
class know_it_all
{
    std::function<answer(std::string str)> m_factory;

public:
    know_it_all(answer(*f)(std::string str) = answer::make_answer) :
        m_factory{f}
    { }

    auto ask_question(const char *question)
    {
        (void) question;
        return m_factory("The answer is: 42");
    }
};
```

在上文中，我们首先使用自定义的`know_it_all`构造函数，它存储了一个指向工厂函数的指针，该函数默认为我们的`answer`类，但提供了更改工厂的能力，如下所示：

```cpp
int main(void)
{
    know_it_all universe(expected_answer::make_answer);
    auto ___ = universe.ask_question("What is the meaning of life?");
}
```

如果需要，我们还可以为这个类添加一个 setter 来在运行时更改这个函数指针。

# 正确使用单例模式

在这个教程中，我们将学习如何在 C++11 及以上正确实现单例模式，以及何时适合使用单例模式。这个教程很重要，因为它将教会你何时使用单例模式，它提供了对单个全局资源的清晰定义，确保资源保持全局，而不会出现多个副本的可能性。

# 准备工作

在开始之前，请确保满足所有的技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保你的操作系统具有编译和执行本书中示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

按照以下步骤尝试单例模式：

1.  从一个新的终端，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter11
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe01_examples
```

1.  一旦源代码被编译，你可以通过运行以下命令来执行本书中的每个示例：

```cpp
> ./recipe02_example01
memory: 0x4041a0
i1: 0x4041a0
i2: 0x4041a4
i3: 0x4041a8
i4: 0x4041ac

> ./recipe02_example02
memory: 0x4041a0
i1: 0x4041a0
i2: 0x4041a4
i3: 0x4041a0
i4: 0x4041a4

> ./recipe02_example03
memory: 0x4041a0
i1: 0x4041a0
i2: 0x4041a4
i3: 0x4041a8
i4: 0x4041ac

> ./recipe02_example04
memory: 0x4041a0
i1: 0x4041a0
i2: 0x4041a4
i3: 0x4041a8
i4: 0x4041ac
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本书所教授的课程的关系。

# 工作原理...

单例模式在 C++中已经存在了好几年，可以说是 C++中最具争议的模式之一，因为其全局性质会在应用程序中引入耦合（类似于全局变量引入的耦合）。单例模式实现了一个单一的全局资源。具体来说，它创建了一个维持全局范围的对象，同时确保自身没有副本存在。关于是否应该在代码中使用单例模式的争论将不会在本书中得到解答，因为这取决于你的用例，但至少让我们来讨论一下这种模式的一些优缺点。

**优点：**单例模式为只能包含一个实例的全局资源提供了一个明确定义的接口。不管我们喜欢与否，全局资源存在于我们所有的应用程序中（例如，堆内存）。如果需要这样一个全局资源，并且你有一种处理耦合的机制（例如，Hippomocks 这样的模拟引擎），单例模式是确保全局资源得到正确管理的好方法。

**缺点：**以下是缺点：

+   单例模式定义了一个全局资源，就像任何全局资源（例如，全局变量）一样，使用单例对象的任何代码都会与单例对象紧密耦合。在面向对象设计中，耦合应该始终被避免，因为它会阻止你能够伪造代码可能依赖的资源，这会限制测试时的灵活性。

+   单例模式隐藏了依赖关系。当检查一个对象的接口时，无法确定对象的实现是否依赖于全局资源。大多数人认为这可以通过良好的文档来处理。

+   单例模式在应用程序的整个生命周期中保持其状态。这在单元测试时尤其明显（也就是说，缺点是显而易见的），因为单例的状态会从一个单元测试传递到下一个单元测试，这被大多数人认为是对单元测试的违反。

一般来说，全局资源应该始终被避免。为了确保你的代码被正确编写以实施单例设计模式，如果你需要一个单一的全局资源。让我们讨论以下的例子。

假设你正在为一个嵌入式设备编写应用程序，你的嵌入式设备有一个额外的内存池，你可以将其映射到你的应用程序中（例如，用于视频或网络设备的设备内存）。现在，假设你只能有一个这样的额外内存池，并且你需要实现一组 API 来从这个池中分配内存。在我们的例子中，我们将使用以下方式来实现这个内存池：

```cpp
uint8_t memory[0x1000] = {};
```

接下来，我们将实现一个内存管理器类，以从这个池中分配内存，如下所示：

```cpp
class mm
{
    uint8_t *cursor{memory};

public:
    template<typename T>
    T *allocate()
    {
        if (cursor + sizeof(T) > memory + 0x1000) {
            throw std::bad_alloc();
        }

        auto ptr = new (cursor) T;
        cursor += sizeof(T);

        return ptr;
    }
};
```

如前所示的代码，我们创建了一个内存管理器类，它存储指向包含我们单一全局资源的内存缓冲区的指针。然后我们创建一个简单的分配函数，根据需要处理这个内存（没有释放的能力，这使得算法非常简单）。

由于这是一个全局资源，我们可以全局创建这个类，如下所示：

```cpp
mm g_mm;
```

最后，我们可以按照以下方式使用我们的新内存管理器：

```cpp
int main(void)
{
    auto i1 = g_mm.allocate<int>();
    auto i2 = g_mm.allocate<int>();
    auto i3 = g_mm.allocate<int>();
    auto i4 = g_mm.allocate<int>();

    std::cout << "memory: " << (void *)memory << '\n';
    std::cout << "i1: " << (void *)i1 << '\n';
    std::cout << "i2: " << (void *)i2 << '\n';
    std::cout << "i3: " << (void *)i3 << '\n';
    std::cout << "i4: " << (void *)i4 << '\n';
}
```

在上面的例子中，我们分配了四个整数指针，然后输出我们内存块的地址和整数指针的地址，以确保算法按预期工作，结果如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/4538b81d-108f-4a76-98a9-f759ccfadcff.png)

如前所示，内存管理器根据需要正确分配内存。

前面实现的问题在于内存管理器只是一个像其他类一样的类，这意味着它可以被创建多次以及被复制。为了更好地说明这是一个问题，让我们看下面的例子。我们不是创建一个内存管理器，而是创建两个：

```cpp
mm g_mm1;
mm g_mm2;
```

接下来，让我们按照以下方式使用这两个内存管理器：

```cpp
int main(void)
{
    auto i1 = g_mm1.allocate<int>();
    auto i2 = g_mm1.allocate<int>();
    auto i3 = g_mm2.allocate<int>();
    auto i4 = g_mm2.allocate<int>();

    std::cout << "memory: " << (void *)memory << '\n';
    std::cout << "i1: " << (void *)i1 << '\n';
    std::cout << "i2: " << (void *)i2 << '\n';
    std::cout << "i3: " << (void *)i3 << '\n';
    std::cout << "i4: " << (void *)i4 << '\n';
}
```

如前所示，唯一的区别是现在我们使用两个内存管理器而不是一个。这导致以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/8a5fd1a4-19c6-44c5-8250-18a3e61714ec.png)

如前所示，内存已经被双重分配，这可能导致损坏和未定义的行为。发生这种情况的原因是内存缓冲区本身是一个全局资源，这是我们无法改变的。内存管理器本身并没有做任何事情来确保这种情况不会发生，因此，这个 API 的用户可能会意外地创建第二个内存管理器。请注意，在我们的例子中，我们明确地创建了第二个副本，但通过简单地传递内存管理器，可能会意外地创建副本。

为了解决这个问题，我们必须处理两种特定的情况：

+   创建多个内存管理器实例

+   复制内存管理器

为了解决这两个问题，让我们现在展示单例模式：

```cpp
class mm
{
    uint8_t *cursor{memory};
    mm() = default;
```

如前所示，我们从将构造函数标记为`private`开始。将构造函数标记为`private`可以防止内存管理器的使用者创建自己的内存管理器实例。相反，要获得内存管理器的实例，我们将使用以下`public`函数：

```cpp
    static auto &instance()
    {
        static mm s_mm;
        return s_mm;
    }
```

这个前面的函数创建了内存管理器的静态（即全局）实例，然后返回对这个实例的引用。使用这个函数，API 的用户只能从这个函数中获得内存管理器的实例，这个函数总是只返回对全局定义资源的引用。换句话说，没有能力创建额外的类实例，否则编译器会报错。

创建单例类的最后一步是以下：

```cpp
    mm(const mm &) = delete;
    mm &operator=(const mm &) = delete;
    mm(mm &&) = delete;
    mm &operator=(mm &&) = delete;
```

如前所示，复制和移动构造函数/操作符被明确删除。这解决了第二个问题。通过删除复制构造函数和操作符，就没有能力创建全局资源的副本，确保类只存在为单一全局对象。

要使用这个单例类，我们需要做以下操作：

```cpp
int main(void)
{
    auto i1 = mm::instance().allocate<int>();
    auto i2 = mm::instance().allocate<int>();
    auto i3 = mm::instance().allocate<int>();
    auto i4 = mm::instance().allocate<int>();

    std::cout << "memory: " << (void *)memory << '\n';
    std::cout << "i1: " << (void *)i1 << '\n';
    std::cout << "i2: " << (void *)i2 << '\n';
    std::cout << "i3: " << (void *)i3 << '\n';
    std::cout << "i4: " << (void *)i4 << '\n';
}
```

这导致以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/cde66b36-11d4-4296-b84d-0a76d9e7da36.png)

如果我们尝试自己创建另一个内存管理器实例，我们会得到类似以下的错误：

```cpp
/home/user/book/chapter11/recipe02.cpp:166:4: error: ‘constexpr mm::mm()’ is private within this context
  166 | mm g_mm;
```

最后，由于单例类是一个单一的全局资源，我们可以创建包装器来消除冗长，如下所示：

```cpp
template<typename T>
constexpr T *allocate()
{
    return mm::instance().allocate<T>();
}
```

这个改变可以按照以下方式使用：

```cpp
int main(void)
{
    auto i1 = allocate<int>();
    auto i2 = allocate<int>();
    auto i3 = allocate<int>();
    auto i4 = allocate<int>();

    std::cout << "memory: " << (void *)memory << '\n';
    std::cout << "i1: " << (void *)i1 << '\n';
    std::cout << "i2: " << (void *)i2 << '\n';
    std::cout << "i3: " << (void *)i3 << '\n';
    std::cout << "i4: " << (void *)i4 << '\n';
}
```

如前所示，`constexpr`包装器提供了一种简单的方法来消除我们单例类的冗长，如果内存管理器不是单例的话，这将是很难做到的。

# 使用装饰器模式扩展您的对象

在这个示例中，我们将学习如何实现装饰器模式，该模式提供了在不需要继承的情况下扩展类功能的能力，这是静态性质的设计。这个示例很重要，因为继承不支持在运行时扩展类的能力，这是装饰器模式解决的问题。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

执行以下步骤尝试这个示例：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter11
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe03_examples
```

1.  源代码编译完成后，您可以通过运行以下命令执行本示例中的每个示例：

```cpp
> ./recipe03_example01
button width: 42

> ./recipe03_example02
button1 width: 10
button2 width: 42

> ./recipe03_example03
button width: 74

> ./recipe03_example04
button width: 42
button content width: 4
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 它是如何工作的...

在这个示例中，我们将学习如何实现装饰器模式。首先，让我们看一个简单的例子：假设我们正在编写一个 C++应用程序，将托管一个网站。在我们的网站中，我们需要定义一个用户可以点击的按钮，但我们需要计算给定额外边距的按钮的宽度：

```cpp
class margin
{
public:
    int width()
    {
        return 32;
    }
};
```

如前所示，我们创建了一个名为`margin`的类，返回所讨论边距的宽度（我们只关注宽度以简化我们的示例）。然后我们可以按照以下方式定义我们的按钮：

```cpp
class button : public margin
{
public:
    int width()
    {
        return margin::width() + 10;
    }
};
```

如前所示，我们按钮的总宽度是按钮本身的宽度加上边距的宽度。然后我们可以按照以下方式获取按钮的宽度：

```cpp
int main()
{
    auto b = new button();
    std::cout << "button width: " << b->width() << '\n';
}
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/697bea8a-1cdb-45ac-8431-53344285e825.png)

前面示例的问题是按钮必须始终具有边距，因为按钮直接继承了边距类。有方法可以防止这种情况发生（例如，我们的按钮可以有一个配置选项，确定按钮是否返回带有边距的宽度），但在这个示例中，我们将使用装饰器模式来解决这个问题，允许我们创建两个按钮：一个带有边距的按钮，一个没有边距的按钮。让我们试试看：

1.  首先，让我们定义以下纯虚基类如下：

```cpp
class base
{
public:
    virtual int width() = 0;
};
```

如前所示，纯虚基类定义了`width`函数。

1.  然后我们可以按照以下方式实现我们的按钮：

```cpp
class button : public base
{
public:
    int width() override
    {
        return 10;
    }
};
```

如前所示，按钮继承了基类并返回`10`的宽度。使用上述，我们可以开始`button`始终是`10`的宽度，按钮没有边距的概念。

1.  要向按钮添加边距，我们首先必须创建一个装饰器类，如下所示：

```cpp
class decorator : public base
{
    std::unique_ptr<base> m_base;

public:
    decorator(std::unique_ptr<base> b) :
        m_base{std::move(b)}
    { }

    int width()
    {
        return m_base->width();
    }
};
```

装饰器模式从一个私有成员开始，指向一个`base`指针，该指针在装饰器的构造函数中设置。装饰器还定义了`width`函数，但将调用转发给基类。

1.  现在，我们可以创建一个边距类，它是一个装饰器，如下所示：

```cpp
class margin : public decorator
{
public:
    margin(std::unique_ptr<base> b) :
        decorator{std::move(b)}
    { }

    int width()
    {
        return decorator::width() + 32;
    }
};
```

如前所示，边距类返回所装饰对象的宽度，并额外添加`32`。

1.  然后我们可以按照以下方式创建我们的两个按钮：

```cpp
int main()
{
    auto button1 = std::make_unique<button>();
    auto button2 = std::make_unique<margin>(std::make_unique<button>());

    std::cout << "button1 width: " << button1->width() << '\n';
    std::cout << "button2 width: " << button2->width() << '\n';
}
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/c40ae265-8e79-4f31-8cea-5a48a0d65d00.png)

装饰器模式的最大优势是它允许我们在运行时扩展一个类。例如，我们可以创建一个带有两个边距的按钮：

```cpp
int main()
{
    auto b =
        std::make_unique<margin>(
            std::make_unique<margin>(
                std::make_unique<button>()
            )
        );

    std::cout << "button width: " << b->width() << '\n';
}
```

否则，我们可以创建另一个装饰器。为了演示这一点，让我们扩展我们的基类如下：

```cpp
class base
{
public:
    virtual int width() = 0;
    virtual int content_width() = 0;
};
```

前面的基类现在定义了一个宽度和一个内容宽度（我们按钮内部可以实际使用的空间）。现在，我们可以按照以下方式创建我们的按钮：

```cpp
class button : public base
{
public:
    int width() override
    {
        return 10;
    }

    int content_width() override
    {
        return width() - 1;
    }
};
```

如前所示，我们的按钮具有静态宽度，内容宽度与宽度本身相同减去 1（为按钮的边框留出空间）。然后我们定义我们的装饰器如下：

```cpp
class decorator : public base
{
    std::unique_ptr<base> m_base;

public:
    decorator(std::unique_ptr<base> b) :
        m_base{std::move(b)}
    { }

    int width() override
    {
        return m_base->width();
    }

    int content_width() override
    {
        return m_base->content_width();
    }
};
```

如前所示，唯一的区别是装饰器现在必须转发宽度和内容宽度函数。我们的边距装饰器如下所示：

```cpp
class margin : public decorator
{
public:
    margin(std::unique_ptr<base> b) :
        decorator{std::move(b)}
    { }

    int width() override
    {
        return decorator::width() + 32;
    }

    int content_width() override
    {
        return decorator::content_width();
    }
};
```

与 Web 编程一样，边距增加了对象的大小。它不会改变对象内部内容的空间，因此边距返回的是内容宽度，没有进行修改。通过前面的更改，我们现在可以按照以下方式添加填充装饰器：

```cpp
class padding : public decorator
{
public:
    padding(std::unique_ptr<base> b) :
        decorator{std::move(b)}
    { }

    int width() override
    {
        return decorator::width();
    }

    int content_width() override
    {
        return decorator::content_width() - 5;
    }
};
```

填充装饰器与边距装饰器相反。它不会改变对象的大小，而是减少了给对象内部内容的总空间。因此，它不会改变宽度，但会减小内容的大小。

使用我们的新装饰器创建一个按钮，我们可以使用以下命令：

```cpp
int main()
{
    auto b =
        std::make_unique<margin>(
            std::make_unique<padding>(
                std::make_unique<button>()
            )
        );

    std::cout << "button width: " << b->width() << '\n';
    std::cout << "button content width: " << b->content_width() << '\n';
}
```

如前所示，我们创建了一个具有额外边距和填充的按钮，结果如下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/2d871265-d736-4585-83b8-30b74a6b04e9.png)

装饰器模式提供了创建不同按钮的能力，而无需编译时继承，这将要求我们为每种可能的按钮类型都有一个不同的按钮定义。然而，需要注意的是，装饰器模式会增加分配和函数调用的重定向成本，因此这种运行时灵活性是有代价的。

# 添加与观察者模式的通信

在这个食谱中，我们将学习如何实现观察者模式。观察者模式提供了一个类注册到另一个类以接收事件发生时的通知的能力。Qt 语言通过使用其信号和槽机制提供了这一功能，同时需要使用 MOC 编译器使其工作。这个食谱很重要，因为我们将学习如何在不需要 Qt 的情况下实现观察者模式，而是使用标准的 C++。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本食谱中示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 操作步骤...

执行以下步骤来尝试这个食谱：

1.  从一个新的终端，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter11
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe04_examples
```

1.  一旦源代码编译完成，您可以通过运行以下命令来执行本食谱中的每个示例：

```cpp
> ./recipe04_example01 
mom's phone received alarm notification
dad's phone received alarm notification
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用，以及它与本食谱中所教授的课程的关系。

# 工作原理...

观察者模式提供了观察者在事件发生时被通知的能力。为了解释这是如何工作的，让我们从以下纯虚基类开始：

```cpp
class observer
{
public:
    virtual void trigger() = 0;
};
```

如前所示，我们定义了`observer`，它必须实现`trigger()`函数。然后我们可以创建两个不同版本的这个纯虚基类，如下所示：

```cpp
class moms_phone : public observer
{
public:
    void trigger() override
    {
        std::cout << "mom's phone received alarm notification\n";
    }
};

class dads_phone : public observer
{
public:
    void trigger() override
    {
        std::cout << "dad's phone received alarm notification\n";
    }
};
```

如前所示的代码，我们创建了两个不同的类，它们都是观察者纯虚类的子类，重写了触发函数。然后我们可以实现一个产生观察者可能感兴趣的事件的类，如下所示：

```cpp
class alarm
{
    std::vector<observer *> m_observers;

public:
    void trigger()
    {
        for (const auto &o : m_observers) {
            o->trigger();
        }
    }

    void add_phone(observer *o)
    {
        m_observers.push_back(o);
    }
};
```

如前面的代码所示，我们首先使用`std::vector`来存储任意数量的观察者。然后我们提供一个触发函数，代表我们的事件。当执行此函数时，我们循环遍历所有观察者，并通过调用它们的`trigger()`函数来通知它们事件。最后，我们提供一个函数，允许观察者订阅相关事件。

以下演示了如何使用这些类：

```cpp
int main(void)
{
    alarm a;
    moms_phone mp;
    dads_phone dp;

    a.add_phone(&mp);
    a.add_phone(&dp);

    a.trigger();
}
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/381ac2b5-23b3-46d9-9c09-6eda2174b3b4.png)

如前所示，当触发警报类时，观察者将收到事件通知并根据需要处理通知。

# 使用静态多态性来提高性能

在这个教程中，我们将学习如何创建多态性，而无需虚拟继承。相反，我们将使用编译时继承（称为静态多态性）。这个教程很重要，因为静态多态性不会像运行时虚拟继承那样产生性能和内存使用的惩罚（因为不需要 vTable），但会牺牲可读性和无法利用虚拟子类化的运行时优势。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本教程中示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

按照以下步骤尝试本教程：

1.  从新的终端中运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter11
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe05_examples
```

1.  源代码编译完成后，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe05_example01
subclass1 specific
common
subclass2 specific
common
> ./recipe05_example02
subclass1 specific
common
subclass2 specific
common
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用，以及它与本教程中所教授的课程的关系。

# 工作原理...

多态性的主要目标之一是它提供了覆盖对象执行特定函数的能力，同时也提供了在一组对象中提供通用逻辑的能力。虚拟继承的问题在于，如果希望使用基类作为接口，覆盖的能力就需要使用 vTable（即虚拟表，这是处理虚拟继承所需的额外内存块）。

例如，考虑以下代码：

```cpp
class base
{
public:
    virtual void foo() = 0;

    void common()
    {
        std::cout << "common\n";
    }
};
```

让我们从之前定义的基类开始。它提供了一个`foo()`函数作为纯虚函数（即，子类必须实现此函数），同时还提供了自己的通用逻辑。然后我们可以创建两个子类，如下所示：

```cpp
class subclass1 : public base
{
public:
    void foo() override
    {
        std::cout << "subclass1 specific\n";
    }
};

class subclass2 : public base
{
public:
    void foo() override
    {
        std::cout << "subclass2 specific\n";
    }
};
```

如前所示，我们对基类进行子类化，并使用子类特定功能重写`foo()`函数。然后我们可以从基类调用子类特定的`foo()`函数，如下所示：

```cpp
int main(void)
{
    subclass1 s1;
    subclass2 s2;

    base *b1 = &s1;
    base *b2 = &s2;

    b1->foo();
    b1->common();

    b2->foo();
    b2->common();
}
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/523debdb-a99c-47b7-9ea3-d8aa453ca274.png)

这种类型的运行时多态性需要使用 vTable，这不仅增加了每个对象的内存占用，还会导致性能损失，因为每个函数调用都需要进行 vTable 查找。如果不需要虚拟继承的运行时特性，静态多态性可以提供相同的功能而不会产生这些惩罚。

首先，让我们定义基类如下：

```cpp
template<typename T>
class base
{
public:
    void foo()
    { static_cast<T *>(this)->foo(); }

    void common()
    {
        std::cout << "common\n";
    }
};
```

与我们之前的示例一样，基类不实现`foo()`函数，而是要求子类实现此函数（这就允许静态转换将其转换为类型`T`）。

然后我们可以按以下方式实现我们的子类：

```cpp
class subclass1 : public base<subclass1>
{
public:
    void foo()
    {
        std::cout << "subclass1 specific\n";
    }
};

class subclass2 : public base<subclass2>
{
public:
    void foo()
    {
        std::cout << "subclass2 specific\n";
    }
};
```

与前面的例子一样，子类只是实现了`foo()`函数。不同之处在于，这种情况下继承需要使用模板参数，这消除了`foo()`函数需要覆盖的需要，因为基类从未使用虚函数。

前面的静态多态性允许我们执行来自基类的`foo()`函数如下：

```cpp
template<typename T>
void test(base<T> b)
{
    b.foo();
    b.common();
}
```

如前所示，`test()`函数对每个子类都没有任何信息。它只有关于基类（或接口）的信息。这个`test()`函数可以这样执行：

```cpp
int main(void)
{
    subclass1 c1;
    subclass2 c2;

    test(c1);
    test(c2);
}
```

这再次导致相同的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/18a35eb7-3016-43dc-9871-77f0e57eb78f.png)

如前所示，如果在编译时知道多态类型，可以使用静态多态性来消除对`virtual`的需要，从而消除对 vTable 的需要。这种逻辑在使用模板类时特别有帮助，其中基本类型已知但子类类型不知道（并且已提供），允许模板函数只需要基本接口。
