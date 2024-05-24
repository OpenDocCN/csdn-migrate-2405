# C++ 高性能编程（一）

> 原文：[`annas-archive.org/md5/753c0f2773b6b78b5104ecb1b57442d4`](https://annas-archive.org/md5/753c0f2773b6b78b5104ecb1b57442d4)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

如今的 C++为程序员提供了编写富有表现力和健壮的代码的能力，同时仍然可以针对几乎任何硬件平台，并且同时满足性能关键的要求。这使得 C++成为一种独特的语言。在过去的几年里，C++已经变成了一种更有趣、具有更好默认值的现代语言。

本书旨在为你提供编写高效应用程序的坚实基础，以及现代 C++中实现库的策略的洞察。我试图以实用的方式来解释当今的 C++是如何工作的，其中 C++17 和 C++20 的特性是语言的自然部分，而不是从历史上看待 C++。

本书的第二版是为了涵盖 C++20 新增的功能而撰写的。我包括了我认为与本书其余内容和重点相契合的功能。自然地，讨论新功能的章节更多地作为介绍，并包含较少的最佳实践和经过验证的解决方案。

在出版本书时，一些 C++20 功能的编译器支持仍然是实验性的。如果你在出版日期附近阅读本书，很可能你将不得不等待一些功能被你的编译器完全支持。

许多章节涵盖了广泛的难度范围。它们从绝对基础开始，最后涉及高级主题，如自定义内存分配器。如果某个部分对你不相关，可以随意跳过，或者以后再回来看。除了前三章外，大多数章节都可以独立阅读。

我们的主要技术审阅者 Timur Doumler 对这个新版本产生了很大的影响。他的热情和出色的反馈导致第一版的一些章节被重新修改，以更彻底、更深入地解释主题。在自然地融入新的 C++20 功能的章节中，Timur 也是一个重要的贡献者。本书的部分内容也经过了 Arthur O'Dwyer、Marius Bancila 和 Lewis Baker 的审阅。能够有这样优秀的审阅者参与这个项目是一种真正的快乐。我希望你能像我写作时那样享受阅读这个新版本。

# 本书适合对象

本书希望你具备 C++和计算机体系结构的基本知识，并对提升自己的技能有真正的兴趣。希望在你完成本书时，你能够对如何改进 C++应用程序在性能和语法上有一些见解。此外，我也希望你能有一些"啊哈"时刻。

# 本书涵盖内容

*第一章*，*C++简介*，介绍了 C++的一些重要特性，如零成本抽象、值语义、const 正确性、显式所有权和错误处理。它还讨论了 C++的缺点。

*第二章*，*基本 C++技术*，概述了使用 auto 进行自动类型推导，lambda 函数，移动语义和错误处理。

*第三章*，*分析和测量性能*，将教你如何使用大 O 符号分析算法复杂性。本章还讨论了如何对代码进行性能分析，找出热点，并使用 Google Benchmark 设置性能测试。

*第四章*，*数据结构*，带你了解了数据结构的重要性，以便可以快速访问。介绍了标准库中的容器，如`std::vector`，`std::list`，`std::unordered_map`和`std::priority_queue`。最后，本章演示了如何使用并行数组。

*第五章*，*算法*，介绍了标准库中最重要的算法。你还将学习如何使用迭代器和范围，以及如何实现自己的通用算法。

第六章，范围和视图，将教您如何使用 C++20 引入的范围库组合算法。您将了解范围库中视图的用途以及延迟评估的一些好处。

第七章，内存管理，侧重于安全高效的内存管理。这包括内存所有权、RAII、智能指针、栈内存、动态内存和自定义内存分配器。

第八章，编译时编程，解释了使用`constexpr`、`consteval`和类型特征的元编程技术。您还将学习如何使用 C++20 概念和新的概念库。最后，它提供了元编程用例的实际示例，如反射。

第九章，基本实用程序，将指导您了解实用程序库以及如何利用`std::optional`、`std::any`和`std::variant`等类型，使用编译时编程技术。

第十章，代理对象和延迟评估，探讨了如何利用代理对象进行底层优化，同时保持清晰的语法。此外，还演示了一些创造性的运算符重载用法。

第十一章，并发，涵盖了并发编程的基础知识，包括并行执行、共享内存、数据竞争和死锁。还介绍了 C++线程支持库、原子库和 C++内存模型。

第十二章，协程和延迟生成器，包含对协程抽象的一般介绍。您将了解普通函数和协程如何在 CPU 上使用堆栈和堆执行。引入了 C++20 无栈协程，并将发现如何使用生成器解决问题。

第十三章，使用协程进行异步编程，介绍了使用 C++20 的无栈协程进行并发编程，并涉及使用 Boost.Asio 进行异步网络编程的主题。

第十四章，并行算法，首先展示了编写并行算法的复杂性以及如何衡量它们的性能。然后演示了如何使用执行策略在并行上下文中利用标准库算法。

# 充分利用本书

要充分利用本书，您需要具备 C++的基本知识。最好您已经遇到与性能相关的问题，并且现在正在寻找新的工具和实践，以备下次需要处理性能和 C++时使用。

本书中有很多代码示例。其中一些来自现实世界，但大多数是人工的或大大简化的示例，用来证明一个概念，而不是提供生产就绪的代码。

我已将所有代码示例放在按章节划分的源文件中，这样您可以很容易找到想要尝试的示例。如果您打开源代码文件，您会注意到我已经用 Google 测试框架编写了大部分示例的`main()`函数的测试用例。我希望这会对您有所帮助，而不是让您感到困惑。这使我能够为每个示例编写有用的描述，并且使得一次运行一个章节中的所有示例变得更容易。

为了编译和运行示例，您需要以下内容：

+   一台计算机

+   操作系统（示例已在 Windows、Linux 和 macOS 上验证）

+   一个编译器（我使用了 Clang、GCC 和 Microsoft Visual C++）

+   CMake

提供的示例代码中的 CMake 脚本将下载并安装进一步的依赖项，如 Boost、Google Benchmark 和 Google 测试。

在写作本书的过程中，我发现使用**Compiler Explorer**很有帮助，该工具可在[`godbolt.org/`](https://godbolt.org/)上使用。Compiler Explorer 是一个在线编译器服务，可以让您尝试各种编译器和版本。如果您还没有尝试过，请试一试！

## 下载示例代码文件

本书的代码包托管在 GitHub 上，网址为[`github.com/PacktPublishing/Cpp-High-Performance-Second-Edition`](https://github.com/PacktPublishing/Cpp-High-Performance-Second-Edition)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

Packt 的丰富图书和视频目录中还有其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

## 下载彩色图片

Packt 还提供了一份 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`static.packt-cdn.com/downloads/9781839216541_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781839216541_ColorImages.pdf)。

## 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、文件夹名称、文件名、文件扩展名、虚拟 URL 和用户输入。例如："关键字`constexpr`是在 C++11 中引入的。"

一段代码块设置如下：

```cpp
#include <iostream>
int main() {
  std::cout << "High Performance C++\n"; 
} 
```

当我希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cpp
#include <iostream>
int main() {
std`::`cout `<<` "High Performance C++\n"`;`
} 
```

任何命令行输入或输出都以以下形式书写：

```cpp
$ clang++ -std=c++20 high_performance.cpp
$ ./a.out
$ High Performance C++ 
```

**粗体**：表示一个新术语、一个重要词或者屏幕上看到的词。例如："填写表格，然后点击**保存**按钮。"

警告或重要说明会出现在这样的形式中。

# 第一章：C++简介

这本书旨在为您提供编写高效应用程序的坚实基础，以及实现现代 C++库的策略。我试图以实用的方式来解释 C++如何运作，现代 C++11 到 C++20 的现代特性是语言的自然部分，而不是从历史上看 C++。

在本章中，我们将：

+   介绍一些对编写健壮、高性能应用程序很重要的 C++特性

+   讨论 C++相对于竞争语言的优势和劣势

+   查看本书中使用的库和编译器

# 为什么选择 C++？

让我们开始探讨一些今天使用 C++的原因。简而言之，C++是一种高度可移植的语言，提供了零成本的抽象。此外，C++为程序员提供了编写和管理大型、富有表现力和健壮的代码库的能力。在本节中，我们将探讨*零成本抽象*的含义，将 C++的抽象与其他语言中的抽象进行比较，并讨论可移植性和健壮性，以及为什么这些特性很重要。

让我们开始进入零成本抽象。

## 零成本抽象

活跃的代码库会不断增长。有更多的开发人员在一个代码库上工作，代码库就会变得更大。为了管理代码库不断增长的复杂性，我们需要语言特性，比如变量、函数和类，能够使用自定义名称和接口创建我们自己的抽象，以抑制实现的细节。

C++允许我们定义自己的抽象，但它也带有内置的抽象。例如，C++函数的概念本身就是控制程序流的抽象。基于范围的`for`循环是另一个内置抽象的例子，它使得直接迭代一系列值成为可能。作为程序员，我们在开发程序时不断添加新的抽象。同样，C++的新版本引入了语言和标准库的新抽象。但是不断添加抽象和新的间接层是有代价的——效率。这就是零成本抽象发挥作用的地方。C++提供的许多抽象在空间和时间方面的运行成本非常低。

使用 C++，当需要时可以自由地谈论内存地址和其他与计算机相关的低级术语。然而，在大型软件项目中，希望用处理应用程序正在执行的任务的术语来表达代码，并让库处理与计算机相关的术语。图形应用程序的源代码可能涉及铅笔、颜色和滤镜，而游戏可能涉及吉祥物、城堡和蘑菇。低级的与计算机相关的术语，比如内存地址，可以留在 C++库代码中，其中性能至关重要。

### 编程语言和机器码抽象

为了让程序员摆脱处理与计算机相关的术语的需要，现代编程语言使用抽象，这样一个字符串列表，例如，可以被处理和看作是一个字符串列表，而不是一个我们可能会因为轻微的拼写错误而失去追踪的地址列表。这些抽象不仅让程序员摆脱了错误，还通过使用应用程序领域的概念使代码更具表现力。换句话说，代码用更接近口语的术语表达，而不是用抽象的编程关键字表达。

C++和 C 现在是两种完全不同的语言。不过，C++与 C 高度兼容，并且从 C 继承了很多语法和习惯用法。为了给你一些 C++抽象的例子，我将展示如何在 C 和 C++中解决一个问题。

看一下以下 C/C++代码片段，它们对应于问题：“这个书籍列表中有多少本《哈姆雷特》？”

我们将从 C 版本开始：

```cpp
// C version
struct string_elem_t { const char* str_; string_elem_t* next_; };
int num_hamlet(string_elem_t* books) {
  const char* hamlet = "Hamlet";
  int n = 0;
  string_elem_t* b; 
  for (b = books; b != 0; b = b->next_)
    if (strcmp(b->str_, hamlet) == 0)
      ++n;
  return n;
} 
```

使用 C++的等效版本看起来会是这样的：

```cpp
// C++ version
int num_hamlet(const std::forward_list<std::string>& books) {
  return std::count(books.begin(), books.end(), "Hamlet");
} 
```

尽管 C++版本仍然更像机器语言而不是人类语言，但由于更高级别的抽象，许多编程术语已经消失。以下是前两个代码片段之间的一些显著差异：

+   原始内存地址的指针根本不可见

+   `std::forward_list<std::string>`容器替换了手工制作的使用`string_elem_t`的链表

+   `std::count()`函数替换了`for`循环和`if`语句

+   `std::string`类提供了对`char*`和`strcmp()`的更高级别抽象

基本上，`num_hamlet()`的两个版本都会转换为大致相同的机器代码，但 C++的语言特性使得库可以隐藏计算机相关的术语，比如指针。许多现代 C++语言特性可以被视为对基本 C 功能的抽象。

### 其他语言中的抽象

大多数编程语言都是基于抽象构建的，这些抽象被转换为机器代码，由 CPU 执行。C++已经发展成为一种高度表达性的语言，就像今天许多其他流行的编程语言一样。C++与大多数其他语言的区别在于，其他语言实现这些抽象是以运行时性能为代价的，而 C++始终致力于以零成本实现其抽象。这并不意味着用 C++编写的应用程序默认比用其他语言（比如 C#）编写的应用程序更快。相反，这意味着通过使用 C++，您可以对生成的机器代码指令和内存占用进行精细控制（如果需要）。

公平地说，如今很少需要最佳性能，而为了更低的编译时间、垃圾回收或安全性而牺牲性能，就像其他语言所做的那样，在许多情况下更为合理。

### 零开销原则

“零成本抽象”是一个常用的术语，但它存在一个问题 - 大多数抽象通常都是有成本的。即使在程序运行时没有成本，也几乎总是在某个地方产生成本，比如长时间的编译时间，难以解释的编译错误消息等等。通常更有趣的是讨论零开销原则。C++的发明者 Bjarne Stroustrup 这样定义零开销原则：

+   你不使用的东西，你就不需要付费

+   你使用的东西，你无法手工编码得更好

这是 C++的一个核心原则，也是语言演变的一个非常重要的方面。为什么，你可能会问？基于这一原则构建的抽象将被性能意识强烈的程序员广泛接受和使用，并且在性能非常关键的环境中使用。找到许多人都同意并广泛使用的抽象，使我们的代码库更易于阅读和维护。

相反，C++语言中不完全遵循零开销原则的特性往往会被程序员、项目和公司所放弃。在这一类中最显著的两个特性是异常（不幸的是）和运行时类型信息（RTTI）。即使没有使用这些特性，它们都可能对性能产生影响。我强烈建议使用异常，除非你有非常充分的理由不这样做。与使用其他机制处理错误相比，性能开销在大多数情况下都是可以忽略的。

## 可移植性

C++长期以来一直是一种受欢迎且全面的语言。它与 C 高度兼容，语言中很少有被弃用的部分，无论是好是坏。C++的历史和设计使其成为一种高度可移植的语言，而现代 C++的发展确保了它将长期保持这种状态。C++是一种活跃的语言，编译器供应商目前正在非常出色地迅速实现新的语言特性。

## 健壮性

除了性能、表现力和可移植性之外，C++还提供了一系列语言特性，使程序员能够编写健壮的代码。

在作者的经验中，健壮性并不是指编程语言本身的强大性 - 在任何语言中都可以编写健壮的代码。相反，资源的严格所有权，const 正确性，值语义，类型安全以及对象的确定性销毁是 C++提供的一些功能，使得编写健壮的代码更容易。也就是说，能够编写易于使用且难以误用的函数、类和库。

## 今天的 C++

总之，今天的 C++为程序员提供了编写富有表现力和健壮的代码基础的能力，同时还可以选择针对几乎任何硬件平台或实时需求。在今天最常用的语言中，只有 C++具有所有这些特性。

我已经简要介绍了为什么 C++仍然是一种相关且广泛使用的编程语言。在接下来的部分，我们将看看 C++与其他现代编程语言的比较。

# 与其他语言相比的 C++

自 C++首次发布以来，出现了大量的应用类型、平台和编程语言。然而，C++仍然是一种广泛使用的语言，其编译器适用于大多数平台。截至今天，唯一的例外是 Web 平台，JavaScript 及其相关技术是其基础。然而，Web 平台正在发展，能够执行以前只在桌面应用程序中可能的功能，在这种情况下，C++已经通过使用诸如 Emscripten、asm.js 和 WebAssembly 等技术进入了 Web 应用程序。

在这一部分，我们将首先从性能的角度比较竞争性语言。接下来，我们将看看 C++如何处理对象所有权和垃圾回收，以及如何避免在 C++中出现空对象。最后，我们将介绍一些 C++的缺点，用户在考虑语言是否适合其需求时应该牢记。

## 竞争性语言和性能

为了了解 C++如何实现与其他编程语言相比的性能，让我们讨论一些 C++与大多数其他现代编程语言之间的基本区别。

为简单起见，本节将重点比较 C++和 Java，尽管大部分比较也适用于基于垃圾收集器的其他编程语言，如 C#和 JavaScript。

首先，Java 编译为字节码，然后在应用程序执行时将其编译为机器代码，而大多数 C++实现直接将源代码编译为机器代码。尽管字节码和即时编译器在理论上可能能够实现与预编译的机器代码相同（或者在理论上甚至更好）的性能，但截至今天，它们通常做不到。不过，公平地说，它们对大多数情况来说表现得足够好。

其次，Java 以完全不同的方式处理动态内存，与 C++不同。在 Java 中，内存由垃圾收集器自动释放，而 C++程序通过手动或引用计数机制处理内存释放。垃圾收集器确实可以防止内存泄漏，但以性能和可预测性为代价。

第三，Java 将所有对象放在单独的堆分配中，而 C++允许程序员将对象放在堆和栈上。在 C++中，还可以在一个单一的堆分配中创建多个对象。这可以有两个原因带来巨大的性能提升：对象可以在不总是分配动态内存的情况下创建，并且多个相关对象可以相邻地放置在内存中。

看看下面的例子中内存是如何分配的。C++函数在栈上同时使用对象和整数；Java 将对象放在堆上：

| C++ | Java |
| --- | --- |

|

```cpp
class Car {
public:
  Car(int doors)
      : doors_(doors) {}
private:
  int doors_{}; 
};
auto some_func() {
  auto num_doors = 2;
  auto car1 = Car{num_doors};
  auto car2 = Car{num_doors};
  // ...
} 
```

|

```cpp
class Car {
  public Car(int doors) { 
    doors_ = doors;
  }
  private int doors_;
  static void some_func() {
    int numDoors = 2;
    Car car1 = new Car(numDoors);
    Car car2 = new Car(numDoors);
    // ...
  }
} 
```

|

| C++将所有内容都放在堆栈上:![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_01_01.png) | Java 将`Car`对象放在堆上:![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_01_02.png) |
| --- | --- |

现在让我们看看下一个例子，看看在使用 C++和 Java 时，`Car`对象的数组是如何放置在内存中的：

| C++ | Java |
| --- | --- |

|

```cpp
auto n = 4;
auto cars = std::vector<Car>{};
cars.reserve(n);
for (auto i=0; i<n;++i) {
   cars.push_back(Car{2});
} 
```

|

```cpp
int n = 4;
ArrayList<Car> cars = 
  new ArrayList<Car>();
for (int i=0; i<n; i++) {
  cars.addElement(new Car(2));
} 
```

|

| 以下图表显示了在 C++中`Car`对象在内存中的布局:![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_01_03.png) | 以下图表显示了在 Java 中`Car`对象在内存中的布局:![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_01_04.png) |
| --- | --- |

C++向量包含放置在一个连续内存块中的实际`Car`对象，而 Java 中的等价物是对`Car`对象的*引用*的连续内存块。在 Java 中，对象已经分别分配，这意味着它们可以位于堆的任何位置。

这会影响性能，因为在这个例子中，Java 实际上需要在 Java 堆空间中执行五次分配。这也意味着每当应用程序迭代列表时，C++都会获得性能优势，因为访问附近的内存位置比访问内存中的几个随机位置更快。

## C++语言的非性能相关特性

很容易认为只有在性能是主要关注点时才应该使用 C++。难道不是这样吗？C++只是因为手动内存处理而增加了代码库的复杂性，这可能导致内存泄漏和难以跟踪的错误吗？

这可能在几个 C++版本前是真的，但现代 C++程序员依赖于标准库中提供的容器和智能指针类型。在过去的 10 年中，C++增加的大部分特性使得这门语言更加强大和更容易使用。

我想在这里强调一些 C++的旧但强大的特性，这些特性与健壮性有关，而不是性能，很容易被忽视：值语义、`const`正确性、所有权、确定性销毁和引用。

### 值语义

C++支持值语义和引用语义。值语义允许我们按值传递对象，而不仅仅是传递对象的引用。在 C++中，值语义是默认的，这意味着当你传递一个类或结构的实例时，它的行为与传递`int`、`float`或任何其他基本类型的行为相同。要使用引用语义，我们需要明确使用引用或指针。

C++类型系统使我们能够明确陈述对象的所有权。比较 C++和 Java 中一个简单类的以下实现。我们将从 C++版本开始：

```cpp
// C++
class Bagel {
public:
  Bagel(std::set<std::string> ts) : toppings_(std::move(ts)) {}
private:
  std::set<std::string> toppings_;
}; 
```

在 Java 中对应的实现可能如下所示：

```cpp
// Java
class Bagel {
  public Bagel(ArrayList<String> ts) { toppings_ = ts; }
  private ArrayList<String> toppings_;
} 
```

在 C++版本中，程序员声明`toppings`完全被`Bagel`类封装。如果程序员打算让夹料列表在几个百吉饼之间共享，它将被声明为某种指针：如果所有权在几个百吉饼之间共享，则为`std::shared_ptr`，如果其他人拥有夹料列表并且应该在程序执行时修改它，则为`std::weak_ptr`。

在 Java 中，对象之间共享所有权。因此，无法区分夹心面包的夹料列表是打算在几个百吉饼之间共享还是不共享，或者它是否在其他地方处理，或者如果是在大多数情况下，是否完全由`Bagel`类拥有。

比较以下函数；由于在 Java（和大多数其他语言）中默认情况下每个对象都是共享的，程序员必须对诸如此类的微妙错误采取预防措施：

| C++ | Java |
| --- | --- |

|

```cpp
// Note how the bagels do
// not share toppings:
auto t = std::set<std::string>{};
t.insert("salt");
auto a = Bagel{t};
// 'a' is not affected
// when adding pepper
t.insert("pepper");
// 'a' will have salt
// 'b' will have salt & pepper 
auto b = Bagel{t};
// No bagel is affected
t.insert("oregano"); 
```

|

```cpp
// Note how both the bagels
// share toppings:
TreeSet<String> t = 
  new TreeSet<String>();
t.add("salt");
Bagel a = new Bagel(t);
// Now 'a' will subtly 
// also have pepper
t.add("pepper");
// 'a' and 'b' share the
// toppings in 't'
Bagel b = new Bagel(t);
// Both bagels are affected
toppings.add("oregano"); 
```

|

### const 正确性

C++的另一个强大特性是能够编写完全`const`正确的代码，而 Java 和许多其他语言则缺乏这一能力。Const 正确性意味着类的每个成员函数签名都明确告诉调用者对象是否会被修改；如果调用者尝试修改声明为`const`的对象，则不会编译。在 Java 中，可以使用`final`关键字声明常量，但这缺乏将成员函数声明为`const`的能力。

以下是一个示例，说明如何使用`const`成员函数防止意外修改对象。在下面的`Person`类中，成员函数`age()`声明为`const`，因此不允许改变`Person`对象，而`set_age()`改变对象，*不能*声明为`const`：

```cpp
class Person {
public:
  auto age() const { return age_; }
  auto set_age(int age) { age_ = age; }
private:
  int age_{};
}; 
```

还可以区分返回可变和不可变引用的成员。在下面的`Team`类中，成员函数“leader() const”返回一个不可变的`Person`，而`leader()`返回一个可能被改变的`Person`对象：

```cpp
class Team {
public:
  auto& leader() const { return leader_; }
  auto& leader() { return leader_; }
private:
  Person leader_{};
}; 
```

现在让我们看看编译器如何帮助我们找到在尝试改变不可变对象时的错误。在下面的示例中，函数参数`teams`声明为`const`，明确显示此函数不允许修改它们：

```cpp
void nonmutating_func(const std::vector<Team>& teams) {
  auto tot_age = 0;

  // Compiles, both leader() and age() are declared const
  for (const auto& team : teams) 
    tot_age += team.leader().age();
  // Will not compile, set_age() requires a mutable object
  for (auto& team : teams) 
    team.leader().set_age(20);
} 
```

如果我们想编写一个*可以*改变`teams`对象的函数，我们只需删除`const`。这向调用者发出信号，表明此函数可能会改变`teams`：

```cpp
void mutating_func(std::vector<Team>& teams) {
  auto tot_age = 0;

  // Compiles, const functions can be called on mutable objects
  for (const auto& team : teams) 
    tot_age += team.leader().age();
  // Compiles, teams is a mutable variable
  for (auto& team : teams) 
    team.leader().set_age(20);
} 
```

### 对象所有权

除非在非常罕见的情况下，C++程序员应该将内存处理留给容器和智能指针，而不必依赖手动内存处理。

明确地说，通过使用`std::shared_ptr`可以在 C++中几乎模拟 Java 中的垃圾收集模型。请注意，垃圾收集语言不使用与`std::shared_ptr`相同的分配跟踪算法。`std::shared_ptr`是基于引用计数算法的智能指针，如果对象具有循环依赖关系，它将泄漏内存。垃圾收集语言具有更复杂的方法，可以处理和释放循环依赖对象。

然而，与依赖垃圾收集器不同，通过精心避免共享对象默认情况下的严格所有权，可以避免由此产生的微妙错误，就像 Java 中的情况一样。

如果程序员在 C++中最小化了共享所有权，生成的代码将更易于使用，更难被滥用，因为它可以强制类的用户按照预期使用它。

### C++中的确定性销毁

在 C++中，对象的销毁是确定性的。这意味着我们（可以）确切地知道对象何时被销毁。而在 Java 等垃圾收集语言中，垃圾收集器决定未引用对象何时被终结，这种情况并非如此。

在 C++中，我们可以可靠地撤销对象生命周期中所做的操作。起初，这可能看起来微不足道。但事实证明，这对我们如何提供异常安全保证以及在 C++中处理资源（如内存、文件句柄、互斥锁等）有很大影响。

确定性销毁也是使 C++可预测的特性之一。这是程序员非常重视的东西，也是对性能关键应用的要求。

我们将在本书的后面花更多时间讨论对象所有权、生命周期和资源管理。因此，如果目前这些内容还不太清楚，不要太担心。

### 使用 C++引用避免空对象

除了严格的所有权外，C++还有引用的概念，这与 Java 中的引用不同。在内部，引用是一个不允许为空或重新指向的指针；因此，当将其传递给函数时不涉及复制。

因此，C++中的函数签名可以明确限制程序员传递 null 对象作为参数。在 Java 中，程序员必须使用文档或注释来指示非 null 参数。

看一下这两个用于计算球体体积的 Java 函数。第一个如果传递了 null 对象就会抛出运行时异常，而第二个则会悄悄地忽略 null 对象。

在 Java 中，第一个实现如果传递了 null 对象就会抛出运行时异常：

```cpp
// Java
float getVolume1(Sphere s) {
  float cube = Math.pow(s.radius(), 3);
  return (Math.PI * 4 / 3) * cube; 
} 
```

在 Java 中，第二个实现会悄悄地处理 null 对象：

```cpp
// Java
float getVolume2(Sphere s) { 
  float rad = s == null ? 0.0f : s.radius();
  float cube = Math.pow(rad, 3);
  return (Math.PI * 4 / 3) * cube;
} 
```

在 Java 中实现的这两个函数中，调用函数的人必须检查函数的实现，以确定是否允许 null 对象。

在 C++中，第一个函数签名明确只接受通过引用初始化的对象，引用不能为 null。使用指针作为参数的第二个版本明确显示了处理 null 对象。

C++中作为引用传递的参数表示不允许 null 值：

```cpp
auto get_volume1(const Sphere& s) {   
  auto cube = std::pow(s.radius(), 3.f);
  auto pi = 3.14f;
  return (pi * 4.f / 3.f) * cube;
} 
```

C++中作为指针传递的参数表示正在处理 null 值：

```cpp
auto get_volume2(const Sphere* s) {
  auto rad = s ? s->radius() : 0.f;
  auto cube = std::pow(rad, 3);
  auto pi = 3.14f;
  return (pi * 4.f / 3.f) * cube;
} 
```

能够在 C++中使用引用或值作为参数立即告知 C++程序员函数的预期使用方式。相反，在 Java 中，用户必须检查函数的实现，因为对象总是作为指针传递，并且存在它们可能为 null 的可能性。

## C++的缺点

如果不提及一些缺点，将 C++与其他编程语言进行比较是不公平的。正如前面提到的，C++有更多的概念需要学习，因此更难正确使用和发挥其全部潜力。然而，如果程序员能够掌握 C++，更高的复杂性就会变成优势，代码库变得更加健壮并且性能更好。

然而，C++也有一些缺点，这些缺点只是缺点。其中最严重的是长时间的编译时间和导入库的复杂性。直到 C++20，C++一直依赖于一个过时的导入系统，其中导入的头文件只是简单地粘贴到需要它们的地方。C++20 中引入的模块将解决系统的一些问题，该系统基于包含头文件，并且还将对大型项目的编译时间产生积极影响。

C++的另一个明显缺点是缺乏提供的库。而其他语言通常提供大多数应用程序所需的所有库，例如图形、用户界面、网络、线程、资源处理等，C++提供的几乎只是最基本的算法、线程，以及从 C++17 开始的文件系统处理。对于其他一切，程序员必须依赖外部库。

总之，尽管 C++的学习曲线比大多数其他语言要陡峭，但如果使用正确，C++的健壮性与许多其他语言相比是一个优势。因此，尽管编译时间长且缺乏提供的库，我认为 C++是一个非常适合大型项目的语言，即使对于性能不是最高优先级的项目也是如此。

# 本书中使用的库和编译器

正如前面提到的，C++在库方面并没有提供更多的东西。因此，在本书中，我们必须在必要时依赖外部库。在 C++世界中最常用的库可能是 Boost 库（[`www.boost.org`](http://www.boost.org)）。

本书的一些部分使用了 Boost 库，因为标准 C++库不够。我们只会使用 Boost 库的头文件部分，这意味着使用它们自己不需要任何特定的构建设置；而只需要包含指定的头文件即可。

此外，我们将使用 Google Benchmark，一个微基准支持库，来评估小代码片段的性能。Google Benchmark 将在*第三章* *分析和测量性能*中介绍。

可在[`github.com/PacktPublishing/Cpp-High-Performance-Second-Edition`](https://github.com/PacktPublishing/Cpp-High-Performance-Second-Edition)找到本书的存储库，其中包含了书中的源代码，使用了 Google Test 框架，使您更容易构建、运行和测试代码。

还应该提到，本书使用了很多来自 C++20 的新功能。在撰写本文时，我们使用的编译器（Clang、GCC 和 Microsoft Visual C++）尚未完全实现其中一些功能。其中一些功能完全缺失或仅支持实验性功能。关于主要 C++编译器当前状态的最新摘要可以在[`en.cppreference.com/w/cpp/compiler_support`](https://en.cppreference.com/w/cpp/compiler_support)找到。

# 总结

在本章中，我已经强调了 C++的一些特点和缺点，以及它是如何发展到今天的状态的。此外，我们讨论了 C++与其他语言相比的优缺点，从性能和健壮性的角度来看。

在下一章中，我们将探讨一些对 C++语言发展产生重大影响的现代和基本功能。


# 第二章：基本的 C++技术

在本章中，我们将深入研究一些基本的 C++技术，如移动语义、错误处理和 lambda 表达式，这些技术将贯穿本书使用。即使是经验丰富的 C++程序员，有些概念仍然会让人困惑，因此我们将探讨它们的用例和工作原理。

本章将涵盖以下主题：

+   自动类型推导以及在声明函数和变量时如何使用`auto`关键字。

+   移动语义和*五法则*和*零法则*。

+   错误处理和契约。虽然这些主题并没有提供可以被视为现代 C++的任何内容，但异常和契约在当今的 C++中都是高度争议的领域。

+   使用 lambda 表达式创建函数对象，这是 C++11 中最重要的功能之一。

让我们首先来看一下自动类型推导。

# 使用 auto 关键字进行自动类型推导

自从 C++11 引入了`auto`关键字以来，C++社区对如何使用不同类型的`auto`（如`const` `auto&`、`auto&`、`auto&&`和`decltype(auto)`）产生了很多困惑。

## 在函数签名中使用 auto

尽管一些 C++程序员不赞成，但在我的经验中，在函数签名中使用`auto`可以增加可读性，方便浏览和查看头文件。

以下是`auto`语法与显式类型的传统语法相比的样子：

| 显式类型的传统语法： | 使用 auto 的新语法： |
| --- | --- |

|

```cpp
struct Foo {
  int val() const {    return m_;   }  const int& cref() const {    return m_;   }  int& mref() {    return m_;   }  int m_{};}; 
```

|

```cpp
struct Foo {
  auto val() const {    return m_;   }  auto& cref() const {    return m_;   }  auto& mref() {    return m_;   }  int m_{};}; 
```

|

`auto`语法可以在有或没有尾随返回类型的情况下使用。在某些情境下，尾随返回类型是必要的。例如，如果我们正在编写虚函数，或者函数声明放在头文件中，函数定义在`.cpp`文件中。

请注意，`auto`语法也可以用于自由函数：

| 返回类型 | 语法变体（a、b 和 c 对应相同的结果）： |
| --- | --- |
| 值 |

```cpp
auto val() const                // a) auto, deduced type
auto val() const -> int         // b) auto, trailing type
int val() const                 // c) explicit type 
```

|

| 常量引用 |
| --- |

```cpp
auto& cref() const              // a) auto, deduced type
auto cref() const -> const int& // b) auto, trailing type
const int& cref() const         // c) explicit type 
```

|

| 可变引用 |
| --- |

```cpp
auto& mref()                    // a) auto, deduced type
auto mref() -> int&             // b) auto, trailing type
int& mref()                     // c) explicit type 
```

|

### 使用 decltype(auto)进行返回类型转发

还有一种相对罕见的自动类型推导版本称为`decltype(auto)`。它最常见的用途是从函数中转发确切的类型。想象一下，我们正在为前面表格中声明的`val()`和`mref()`编写包装函数，就像这样：

```cpp
int val_wrapper() { return val(); }    // Returns int
int& mref_wrapper() { return mref(); } // Returns int& 
```

现在，如果我们希望对包装函数使用返回类型推导，`auto`关键字将在两种情况下推导返回类型为`int`：

```cpp
auto val_wrapper() { return val(); }   // Returns int
auto mref_wrapper() { return mref(); } // Also returns int 
```

如果我们希望`mref_wrapper()`返回`int&`，我们需要写`auto&`。在这个例子中，这是可以的，因为我们知道`mref()`的返回类型。然而，并非总是如此。因此，如果我们希望编译器选择与`int&`或`auto&`相同的类型而不明确指定`mref_wrapper()`的返回类型，我们可以使用`decltype(auto)`：

```cpp
decltype(auto) val_wrapper() { return val(); }   // Returns int
decltype(auto) mref_wrapper() { return mref(); } // Returns int& 
```

通过这种方式，我们可以避免在不知道函数`val()`或`mref()`返回的类型时明确选择写`auto`或`auto&`。这通常发生在泛型代码中，其中被包装的函数的类型是模板参数。

## 使用 auto 声明变量

C++11 引入`auto`关键字引发了 C++程序员之间的激烈辩论。许多人认为它降低了可读性，甚至使 C++变得类似于动态类型语言。我倾向于不参与这些辩论，但我个人认为你应该（几乎）总是使用`auto`，因为在我的经验中，它使代码更安全，减少了混乱。

过度使用`auto`可能会使代码难以理解。在阅读代码时，我们通常想知道某个对象支持哪些操作。一个好的 IDE 可以为我们提供这些信息，但在源代码中并没有明确显示。C++20 概念通过关注对象的行为来解决这个问题。有关 C++概念的更多信息，请参阅*第八章*，*编译时编程*。

我喜欢使用`auto`来定义使用从左到右的初始化样式的局部变量。这意味着将变量保留在左侧，后跟一个等号，然后在右侧是类型，就像这样：

```cpp
auto i = 0;
auto x = Foo{};
auto y = create_object();
auto z = std::mutex{};     // OK since C++17 
```

在 C++17 中引入了*保证的拷贝省略*，语句`auto x = Foo{}`与`Foo x{}`是相同的；也就是说，语言保证在这种情况下没有需要移动或复制的临时对象。这意味着我们现在可以使用从左到右的初始化样式，而不用担心性能，我们还可以用于不可移动/不可复制的类型，如`std::atomic`或`std::mutex`。

使用`auto`定义变量的一个很大的优势是，您永远不会留下未初始化的变量，因为`auto x;`不会编译。未初始化的变量是未定义行为的一个常见来源，您可以通过遵循这里建议的样式完全消除。

使用`auto`将帮助您使用正确的类型来定义变量。但您仍然需要通过指定需要引用还是副本，以及是否要修改变量或仅从中读取来表达您打算如何使用变量。

### 一个 const 引用

`const`引用，用`const auto&`表示，具有绑定到任何东西的能力。原始对象永远不会通过这样的引用发生变异。我认为`const`引用应该是潜在昂贵的对象的默认选择。

如果`const`引用绑定到临时对象，则临时对象的生命周期将延长到引用的生命周期。这在以下示例中得到了证明：

```cpp
void some_func(const std::string& a, const std::string& b) {
  const auto& str = a + b;  // a + b returns a temporary
  // ...
} // str goes out of scope, temporary will be destroyed 
```

也可以通过使用`auto&`得到一个`const`引用。可以在以下示例中看到：

```cpp
 auto foo = Foo{};
 auto& cref = foo.cref(); // cref is a const reference
 auto& mref = foo.mref(); // mref is a mutable reference 
```

尽管这是完全有效的，但最好始终明确表示我们正在处理`const`引用，使用`const auto&`，更重要的是，我们应该使用`auto&`仅表示可变引用。

### 一个可变引用

与`const`引用相反，可变引用不能绑定到临时对象。如前所述，我们使用`auto&`来表示可变引用。只有在打算更改引用的对象时才使用可变引用。

### 转发引用

`auto&&`被称为转发引用（也称为*通用引用*）。它可以绑定到任何东西，这对某些情况很有用。转发引用将像`const`引用一样，延长临时对象的生命周期。但与`const`引用相反，`auto&&`允许我们改变它引用的对象，包括临时对象。

对于只转发到其他代码的变量，请使用`auto&&`。在这些转发情况下，您很少关心变量是`const`还是可变的；您只是想将其传递给实际要使用变量的一些代码。

重要的是要注意，只有在函数模板中使用`T`作为该函数模板的模板参数时，`auto&&`和`T&&`才是转发引用。使用显式类型，例如`std::string&&`，带有`&&`语法表示**右值**引用，并且不具有转发引用的属性（右值和移动语义将在本章后面讨论）。

### 便于使用的实践

尽管这是我的个人意见，我建议对基本类型（`int`，`float`等）和小的非基本类型（如`std::pair`和`std::complex`）使用`const auto`。对于潜在昂贵的大型类型，使用`const auto&`。这应该涵盖 C++代码库中大多数变量声明。

只有在需要可变引用或显式复制的行为时，才应使用`auto&`和`auto`；这向代码的读者传达了这些变量的重要性，因为它们要么复制一个对象，要么改变一个引用的对象。最后，只在转发代码时使用`auto&&`。

遵循这些规则可以使您的代码库更易于阅读、调试和理解。

也许会觉得奇怪，虽然我建议在大多数变量声明中使用`const auto`和`const auto&`，但在本书的某些地方我倾向于使用简单的`auto`。使用普通的`auto`的原因是书籍格式提供的有限空间。

在继续之前，我们将花一点时间讨论`const`以及在使用指针时如何传播`const`。

## 指针的 const 传播

通过使用关键字`const`，我们可以告诉编译器哪些对象是不可变的。然后编译器可以检查我们是否尝试改变不打算改变的对象。换句话说，编译器检查我们的代码是否符合`const`-correctness。在 C++中编写`const`-correct 代码时的一个常见错误是，`const`初始化的对象仍然可以操作成员指针指向的值。以下示例说明了这个问题：

```cpp
class Foo {
public:
  Foo(int* ptr) : ptr_{ptr} {} 
  auto set_ptr_val(int v) const { 
    *ptr_ = v; // Compiles despite function being declared const!
  }
private:
  int* ptr_{};
};
int main() {
  auto i = 0;
  const auto foo = Foo{&i};
  foo.set_ptr_val(42);
} 
```

虽然函数`set_ptr_val()`正在改变`int`值，但声明它为`const`是有效的，因为指针`ptr_`本身没有被改变，只有指针指向的`int`对象被改变。

为了以一种可读的方式防止这种情况，标准库扩展中添加了一个名为`std::experimental::propagate_const`的包装器（在撰写本文时，已包含在最新版本的 Clang 和 GCC 中）。使用`propagate_const`，函数`set_ptr_val()`将无法编译。请注意，`propagate_const`仅适用于指针和类似指针的类，如`std::shared_ptr`和`std::unique_ptr`，而不适用于`std::function`。

以下示例演示了如何使用`propagate_const`在尝试在`const`函数内部改变对象时生成编译错误：

```cpp
#include <experimental/propagate_const>
class Foo { 
public: 
  Foo(int* ptr) : ptr_{ptr} {}
  auto set_ptr(int* p) const { 
    ptr_ = p;  // Will not compile, as expected
  }
  auto set_val(int v) const { 
    val_ = v;  // Will not compile, as expected
  }
  auto set_ptr_val(int v) const { 
    *ptr_ = v; // Will not compile, const is propagated
  }
private:
  std::experimental::propagate_const<int*> ptr_ = nullptr; 
  int val_{}; 
}; 
```

在大型代码库中正确使用`const`的重要性不言而喻，而引入`propagate_const`使`const`-correctness 变得更加有效。

接下来，我们将看一下移动语义以及处理类内部资源的一些重要规则。

# 解释移动语义

移动语义是 C++11 中引入的一个概念，在我看来，即使是经验丰富的程序员也很难理解。因此，我将尝试为您深入解释它的工作原理，编译器如何利用它，以及为什么它是必要的。

基本上，C++之所以有移动语义的概念，而大多数其他语言没有，是因为它是一种基于值的语言，正如在《第一章 C++简介》中讨论的那样。如果 C++没有内置移动语义，那么基于值的语义的优势在许多情况下将会丢失，程序员将不得不进行以下折衷之一：

+   执行性能成本高的冗余深克隆操作

+   像 Java 一样使用对象指针，失去值语义的健壮性

+   以牺牲可读性为代价进行容易出错的交换操作

我们不希望出现这些情况，所以让我们看看移动语义如何帮助我们。

## 复制构造、交换和移动

在深入了解移动的细节之前，我将首先解释并说明复制构造对象、交换两个对象和移动构造对象之间的区别。

### 复制构造对象

在复制处理资源的对象时，需要分配新资源，并且需要复制源对象的资源，以便使这两个对象完全分离。想象一下，我们有一个类`Widget`，它引用需要在构造时分配的某种资源。以下代码默认构造了一个`Widget`对象，然后复制构造了一个新实例：

```cpp
auto a = Widget{}; 
auto b = a;        // Copy-construction 
```

所进行的资源分配如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_02_01.png)

图 2.1：复制具有资源的对象

分配和复制是缓慢的过程，在许多情况下，源对象不再需要。使用移动语义，编译器会检测到这样的情况，其中旧对象不与变量绑定，而是执行移动操作。

#### 交换两个对象

在 C++11 中添加移动语义之前，交换两个对象的内容是一种常见的在不分配和复制的情况下传输数据的方式。如下所示，对象只是互相交换它们的内容：

```cpp
auto a = Widget{};
auto b = Widget{};
std::swap(a, b); 
```

以下图示说明了这个过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_02_02.png)

图 2.2：在两个对象之间交换资源

`std::swap()`函数是一个简单但有用的实用程序，在本章后面将介绍的复制和交换习语中使用。

#### 移动构造对象

移动对象时，目标对象直接从源对象中夺取资源，而源对象被重置。

正如您所见，这与交换非常相似，只是*移出*的对象不必从*移入*对象那里接收资源：

```cpp
auto a = Widget{}; 
auto b = std::move(a); // Tell the compiler to move the resource into b 
```

以下图示说明了这个过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_02_03.png)

图 2.3：将资源从一个对象移动到另一个对象

尽管源对象被重置，但它仍处于有效状态。源对象的重置不是编译器自动为我们执行的。相反，我们需要在移动构造函数中实现重置，以确保对象处于可以被销毁或赋值的有效状态。我们将在本章后面更多地讨论有效状态。

只有在对象类型拥有某种资源（最常见的情况是堆分配的内存）时，移动对象才有意义。如果所有数据都包含在对象内部，移动对象的最有效方式就是简单地复制它。

现在您已经基本掌握了移动语义，让我们深入了解一下细节。

## 资源获取和五法则

要完全理解移动语义，我们需要回到 C++中类和资源获取的基础概念。C++中的一个基本概念是，一个类应该完全处理其资源。这意味着当一个类被复制、移动、复制赋值、移动赋值或销毁时，类应该确保其资源得到适当处理。实现这五个函数的必要性通常被称为**五法则**。

```cpp
floats pointed at by the raw pointer ptr_:
```

```cpp
class Buffer { 
public: 
  // Constructor 
  Buffer(const std::initializer_list<float>& values)       : size_{values.size()} { 
    ptr_ = new float[values.size()]; 
    std::copy(values.begin(), values.end(), ptr_); 
  }
  auto begin() const { return ptr_; } 
  auto end() const { return ptr_ + size_; } 
  /* The 5 special functions are defined below */
private: 
  size_t size_{0}; 
  float* ptr_{nullptr};
}; 
```

在这种情况下，处理的资源是在`Buffer`类的构造函数中分配的一块内存。内存可能是类处理的最常见资源，但资源可以是更多：互斥锁、图形卡上纹理的句柄、线程句柄等等。

在“五法则”中提到的五个函数已被省略，将在下文中介绍。我们将从复制构造函数、复制赋值运算符和析构函数开始，这些函数都需要参与资源处理：

```cpp
// 1\. Copy constructor 
Buffer::Buffer(const Buffer& other) : size_{other.size_} { 
  ptr_ = new float[size_]; 
  std::copy(other.ptr_, other.ptr_ + size_, ptr_); 
} 
// 2\. Copy assignment 
auto& Buffer::operator=(const Buffer& other) {
  delete [] ptr_;
  ptr_ = new float[other.size_];
  size_ = other.size_;
  std::copy(other.ptr_, other.ptr_ + size_, ptr_);
  return *this;
} 
// 3\. Destructor 
Buffer::~Buffer() { 
  delete [] ptr_; // OK, it is valid to delete a nullptr
  ptr_ = nullptr;  
} 
```

在 C++11 中引入移动语义之前，这三个函数通常被称为**三法则**。复制构造函数、复制赋值运算符和析构函数在以下情况下被调用：

```cpp
auto func() { 
  // Construct 
  auto b0 = Buffer({0.0f, 0.5f, 1.0f, 1.5f}); 
  // 1\. Copy-construct 
  auto b1 = b0; 
  // 2\. Copy-assignment as b0 is already initialized 
  b0 = b1; 
} // 3\. End of scope, the destructors are automatically invoked 
```

虽然正确实现这三个函数是类处理内部资源所需的全部内容，但会出现两个问题：

+   **无法复制的资源**：在`Buffer`类示例中，我们的资源可以被复制，但还有其他类型的资源，复制是没有意义的。例如，类中包含的资源可能是`std::thread`、网络连接或其他无法复制的资源。在这些情况下，我们无法传递对象。

+   **不必要的复制**：如果我们从函数中返回我们的`Buffer`类，整个数组都需要被复制。（编译器在某些情况下会优化掉复制，但现在让我们忽略这一点。）

解决这些问题的方法是移动语义。除了复制构造函数和复制赋值，我们还可以在我们的类中添加移动构造函数和移动赋值运算符。移动版本不是以`const`引用（`const Buffer&`）作为参数，而是接受`Buffer&&`对象。

`&&`修饰符表示参数是我们打算从中移动而不是复制的对象。用 C++术语来说，这被称为 rvalue，我们稍后会更详细地讨论这些。

而`copy()`函数复制对象，移动等效函数旨在将资源从一个对象移动到另一个对象，释放被移动对象的资源。

这就是我们如何通过移动构造函数和移动赋值来扩展我们的`Buffer`类。如您所见，这些函数不会抛出任何异常，因此可以标记为`noexcept`。这是因为，与复制构造函数/复制赋值相反，它们不会分配内存或执行可能引发异常的操作：

```cpp
// 4\. Move constructor
Buffer::Buffer(Buffer&& other) noexcept     : size_{other.size_}, ptr_{other.ptr_} {
  other.ptr_ = nullptr;
  other.size_ = 0;
}
// 5\. Move assignment
auto& Buffer::operator=(Buffer&& other) noexcept {
  ptr_ = other.ptr_;
  size_ = other.size_;
  other.ptr_ = nullptr;
  other.size_ = 0;
  return *this;
} 
```

现在，当编译器检测到我们执行了似乎是复制的操作，例如从函数返回一个`Buffer`，但复制的值不再被使用时，它将使用不抛出异常的移动构造函数/移动赋值代替复制。

这非常棒；接口保持与复制时一样清晰，但在底层，编译器执行了一个简单的移动。因此，程序员不需要使用任何奇怪的指针或输出参数来避免复制；因为类已经实现了移动语义，编译器会自动处理这个问题。

不要忘记将您的移动构造函数和移动赋值运算符标记为`noexcept`（除非它们可能抛出异常）。不标记它们为`noexcept`会阻止标准库容器和算法在某些条件下使用它们，而是转而使用常规的复制/赋值。

为了能够知道编译器何时允许移动对象而不是复制，需要了解 rvalue。

## 命名变量和 rvalue

那么，编译器何时允许移动对象而不是复制呢？简短的答案是，当对象可以被归类为 rvalue 时，编译器会移动对象。术语**rvalue**听起来可能很复杂，但本质上它只是一个不与命名变量绑定的对象，原因如下：

+   它直接来自函数

+   通过使用`std::move()`，我们可以将变量变成 rvalue

以下示例演示了这两种情况：

```cpp
// The object returned by make_buffer is not tied to a variable
x = make_buffer();  // move-assigned
// The variable "x" is passed into std::move()
y = std::move(x);   // move-assigned 
```

在本书中，我还将交替使用术语**lvalue**和**命名变量**。lvalue 对应于我们在代码中可以通过名称引用的对象。

现在，我们将通过在类中使用`std::string`类型的成员变量来使其更加高级。以下的`Button`类将作为一个例子：

```cpp
class Button { 
public: 
  Button() {} 
  auto set_title(const std::string& s) { 
    title_ = s; 
  } 
  auto set_title(std::string&& s) { 
    title_ = std::move(s); 
  } 
  std::string title_; 
}; 
```

我们还需要一个返回标题和`Button`变量的自由函数：

```cpp
auto get_ok() {
  return std::string("OK");
}
auto button = Button{}; 
```

在满足这些先决条件的情况下，让我们详细看一些复制和移动的案例：

+   **Case 1**：`Button::title_`被移动赋值，因为`string`对象通过`std::move()`传递：

```cpp
auto str = std::string{"OK"};
button.set_title(str);              // copy-assigned 
```

+   **Case 2**：`Button::title_`被移动赋值，因为`str`通过`std::move()`传递：

```cpp
auto str = std::string{"OK"};
button.set_title(std::move(str));   // move-assigned 
```

+   **Case 3**：`Button::title_`被移动赋值，因为新的`std::string`对象直接来自函数：

```cpp
button.set_title(get_ok());        // move-assigned 
```

+   **Case 4**：`Button::title_`被复制赋值，因为`string`对象与`s`绑定（这与*Case 1*相同）：

```cpp
auto str = get_ok();
button.set_title(str);             // copy-assigned 
```

+   **Case 5**：`Button::title_`被复制赋值，因为`str`被声明为`const`，因此不允许改变：

```cpp
const auto str = get_ok();
button.set_title(std::move(str));  // copy-assigned 
```

如您所见，确定对象是移动还是复制非常简单。如果它有一个变量名，它就会被复制；否则，它就会被移动。如果您正在使用`std::move()`来移动一个命名对象，那么该对象就不能被声明为`const`。

## 默认移动语义和零规则

本节讨论自动生成的复制赋值运算符。重要的是要知道生成的函数没有强异常保证。因此，如果在复制赋值期间抛出异常，对象可能最终处于部分复制的状态。

与复制构造函数和复制赋值一样，移动构造函数和移动赋值可以由编译器生成。尽管一些编译器允许在某些条件下自动生成这些函数（稍后会详细介绍），但我们可以通过使用`default`关键字简单地强制编译器生成它们。

对于不手动处理任何资源的`Button`类，我们可以简单地扩展它如下：

```cpp
class Button {
public: 
  Button() {} // Same as before

  // Copy-constructor/copy-assignment 
  Button(const Button&) = default; 
  auto operator=(const Button&) -> Button& = default;
  // Move-constructor/move-assignment 
  Button(Button&&) noexcept = default; 
  auto operator=(Button&&) noexcept -> Button& = default; 
  // Destructor
  ~Button() = default; 
  // ...
}; 
```

更简单的是，如果我们不声明*任何*自定义复制构造函数/复制赋值或析构函数，移动构造函数/移动赋值将被隐式声明，这意味着第一个`Button`类实际上处理了一切：

```cpp
class Button {
public: 
  Button() {} // Same as before

  // Nothing here, the compiler generates everything automatically! 
  // ...
}; 
```

很容易忘记只添加五个函数中的一个会阻止编译器生成其他函数。以下版本的`Button`类具有自定义析构函数。因此，移动运算符不会生成，并且该类将始终被复制：

```cpp
class Button {
public: 
  Button() {} 
  ~Button() 
    std::cout << "destructed\n"
  }
  // ...
}; 
```

让我们看看在实现应用程序类时如何使用这些生成函数的见解。

### 实际代码库中的零规则

实际上，必须编写自己的复制/移动构造函数、复制/移动赋值和构造函数的情况应该非常少。编写类，使其不需要显式编写任何这些特殊成员函数（或声明为`default`）通常被称为**零规则**。这意味着如果应用程序代码库中的类需要显式编写任何这些函数，那么该代码片段可能更适合于代码库的一部分。

在本书的后面，我们将讨论`std::optional`，这是一个方便的实用类，用于处理可选成员，同时应用零规则。

#### 关于空析构函数的说明

编写空析构函数可以防止编译器实现某些优化。如下片段所示，使用具有空析构函数的平凡类的数组复制产生与使用手工制作的`for`循环复制相同（非优化）的汇编代码。第一个版本使用具有`std::copy()`的空析构函数：

```cpp
struct Point {
 int x_, y_;
 ~Point() {}     // Empty destructor, don't use!
};
auto copy(Point* src, Point* dst) {
  std::copy(src, src+64, dst);
} 
```

第二个版本使用了一个没有析构函数但有手工制作的`for`循环的`Point`类：

```cpp
struct Point {
  int x_, y_;
};
auto copy(Point* src, Point* dst) {
  const auto end = src + 64;
  for (; src != end; ++src, ++dst) {
    *dst = *src;
  }
} 
```

两个版本生成以下 x86 汇编代码，对应一个简单的循环：

```cpp
 xor eax, eax
.L2:
 mov rdx, QWORD PTR [rdi+rax]
 mov QWORD PTR [rsi+rax], rdx
 add rax, 8
 cmp rax, 512
 jne .L2
 rep ret 
```

但是，如果我们删除析构函数或声明析构函数为`default`，编译器将优化`std::copy()`以利用`memmove()`而不是循环：

```cpp
struct Point { 
  int x_, y_; 
  ~Point() = default; // OK: Use default or no constructor at all
};
auto copy(Point* src, Point* dst) {
  std::copy(src, src+64, dst);
} 
```

前面的代码生成以下 x86 汇编代码，带有`memmove()`优化：

```cpp
 mov rax, rdi
 mov edx, 512
 mov rdi, rsi
 mov rsi, rax
 jmp memmove 
```

汇编是使用*Compiler Explorer*中的 GCC 7.1 生成的，可在[`godbolt.org/`](https://godbolt.org/)上找到。

总之，使用`default`析构函数或根本不使用析构函数，以便在应用程序中挤出更多性能。

### 一个常见的陷阱-移动非资源

在使用默认创建的移动赋值时存在一个常见的陷阱：将基本类型与更高级的复合类型混合使用。与复合类型相反，基本类型（如`int`、`float`和`bool`）在移动时只是被复制，因为它们不处理任何资源。

当简单类型与拥有资源的类型混合在一起时，移动赋值成为移动和复制的混合。

这是一个将失败的类的示例：

```cpp
class Menu {
public:
  Menu(const std::initializer_list<std::string>& items)       : items_{items} {}
  auto select(int i) {
    index_ = i;
  }
  auto selected_item() const {
     return index_ != -1 ? items_[index_] : "";
  }
  // ...
private:
  int index_{-1}; // Currently selected item
  std::vector<std::string> items_; 
}; 
```

如果像这样使用`Menu`类，它将具有未定义的行为：

```cpp
auto a = Menu{"New", "Open", "Close", "Save"};
a.select(2);
auto b = std::move(a);
auto selected = a.selected_item(); // crash 
```

未定义的行为发生在`items_`向量被移动并且因此为空。另一方面，`index_`被复制，因此在移动的对象`a`中仍然具有值`2`。当调用`selected_item()`时，函数将尝试访问索引`2`处的`items_`，程序将崩溃。

在这些情况下，移动构造函数/赋值最好通过简单交换成员来实现，就像这样：

```cpp
Menu(Menu&& other) noexcept { 
  std::swap(items_, other.items_); 
  std::swap(index_, other.index_); 
} 
auto& operator=(Menu&& other) noexcept { 
  std::swap(items_, other.items_); 
  std::swap(index_, other.index_); 
  return *this; 
} 
```

这种方式，`Menu`类可以安全地移动，同时保留无抛出保证。在*第八章*，*编译时编程*中，您将学习如何利用 C++中的反射技术来自动创建交换元素的移动构造函数/赋值函数。

## 将`&&`修饰符应用于类成员函数

除了应用于对象之外，您还可以向类的成员函数添加`&&`修饰符，就像您可以向成员函数应用`const`修饰符一样。与`const`修饰符一样，具有`&&`修饰符的成员函数只有在对象是右值时才会被重载解析考虑：

```cpp
struct Foo { 
  auto func() && {} 
}; 
auto a = Foo{}; 
a.func();            // Doesn't compile, 'a' is not an rvalue 
std::move(a).func(); // Compiles 
Foo{}.func();        // Compiles 
```

也许有些奇怪，有人会想要这种行为，但确实有用例。我们将在*第十章*，*代理对象和延迟评估*中调查其中之一。

## 当复制被省略时不要移动

当从函数返回值时，可能会诱人使用`std::move()`，就像这样：

```cpp
auto func() {
  auto x = X{};
  // ...
  return std::move(x);  // Don't, RVO is prevented
} 
```

然而，除非`x`是一个仅移动类型，否则不应该这样做。使用`std::move()`会阻止编译器使用**返回值优化**（**RVO**），从而完全省略了`x`的复制，这比移动更有效。因此，当通过值返回新创建的对象时，不要使用`std::move()`；而是直接返回对象：

```cpp
auto func() {
  auto x = X{};
  // ...
  return x;  // OK
} 
```

这种特定的例子，其中*命名*对象被省略，通常称为**NRVO**或**Named-RVO**。 RVO 和 NRVO 由今天所有主要的 C++编译器实现。如果您想了解更多关于 RVO 和复制省略的信息，您可以在[`en.cppreference.com/w/cpp/language/copy_elision`](https://en.cppreference.com/w/cpp/language/copy_elision)找到详细的摘要。

## 在适用时传递值

考虑一个将`std::string`转换为小写的函数。为了在适用时使用移动构造函数，在不适用时使用复制构造函数，似乎需要两个函数：

```cpp
// Argument s is a const reference
auto str_to_lower(const std::string& s) -> std::string {
  auto clone = s;
  for (auto& c: clone) c = std::tolower(c);
  return clone;
}
// Argument s is an rvalue reference
auto str_to_lower(std ::string&& s) -> std::string {
  for (auto& c: s) c = std::tolower(c);
  return s;
} 
```

然而，通过按值传递`std::string`，我们可以编写一个函数来涵盖这两种情况：

```cpp
auto str_to_lower(std::string s) -> std::string {
  for (auto& c: s) c = std::tolower(c);
  return s;
} 
```

让我们看看`str_to_lower()`的这种实现如何避免可能的不必要的复制。当传递一个常规变量时，如下所示，函数调用之前`str`的内容被复制构造到`s`中，然后在函数返回时移动分配回`str`：

```cpp
auto str = std::string{"ABC"};
str = str_to_lower(str); 
```

当传递一个右值时，如下所示，函数调用之前`str`的内容被移动构造到`s`中，然后在函数返回时移动分配回`str`。因此，没有通过函数调用进行复制：

```cpp
auto str = std::string{"ABC"};
str = str_to_lower(std::move(str)); 
```

乍一看，这种技术似乎适用于所有参数。然而，这种模式并不总是最佳的，接下来您将看到。

### 不适用传值的情况

有时，接受按值然后移动的模式实际上是一种悲观化。例如，考虑以下类，其中函数`set_data()`将保留传递给它的参数的副本：

```cpp
class Widget {
  std::vector<int> data_{};
  // ...
public:
  void set_data(std::vector<int> x) { 
    data_ = std::move(x);               
  }
}; 
```

假设我们调用`set_data()`并将一个左值传递给它，就像这样：

```cpp
auto v = std::vector<int>{1, 2, 3, 4};
widget.set_data(v);                  // Pass an lvalue 
```

由于我们传递了一个命名对象`v`，代码将复制构造一个新的`std::vector`对象`x`，然后将该对象移动分配到`data_`成员中。除非我们将一个空的向量对象传递给`set_data()`，否则`std::vector`复制构造函数将为其内部缓冲区执行堆分配。

现在将其与`set_data()`的以下版本进行比较，该版本针对左值进行了优化：

```cpp
void set_data(const std::vector<int>& x) { 
    data_ = x;  // Reuse internal buffer in data_ if possible
} 
```

在这里，如果当前向量`data_`的容量小于源对象`x`的大小，那么赋值运算符内部将只有一个堆分配。换句话说，在许多情况下，`data_`的内部预分配缓冲区可以在赋值运算符中被重用，从而避免额外的堆分配。

如果我们发现有必要优化`set_data()`以适应 lvalues 和 rvalues，最好在这种情况下提供两个重载：

```cpp
void set_data(const std::vector<int>& x) {
  data_ = x;
}
void set_data(std::vector<int>&& x) noexcept { 
  data_ = std::move(x);
} 
```

第一个版本对于 lvalues 是最佳的，第二个版本对于 rvalues 是最佳的。

最后，我们现在将看一个场景，在这个场景中我们可以安全地传值，而不用担心刚刚演示的悲观情况。

### 移动构造函数参数

在构造函数中初始化类成员时，我们可以安全地使用传值然后移动的模式。在构造新对象时，没有机会利用预分配的缓冲区来避免堆分配。接下来是一个具有一个`std::vector`成员和一个构造函数的类的示例，用于演示这种模式：

```cpp
class Widget {
  std::vector<int> data_;
public:
  Widget(std::vector<int> x)       // By value
      : data_{std::move(x)} {}     // Move-construct
  // ...
}; 
```

我们现在将把焦点转移到一个不能被视为*现代 C++*但即使在今天也经常被讨论的话题。

# 设计带有错误处理的接口

错误处理是函数和类接口中重要但经常被忽视的部分。错误处理是 C++中一个备受争议的话题，但讨论往往倾向于异常与其他错误机制之间的对比。虽然这是一个有趣的领域，但在关注错误处理的实际实现之前，还有其他更重要的错误处理方面需要理解。显然，异常和错误码在许多成功的软件项目中都被使用过，而且经常会遇到将两者结合在一起的项目。

无论编程语言如何，错误处理的一个基本方面是区分**编程错误**（也称为错误）和**运行时错误**。运行时错误可以进一步分为**可恢复的运行时错误**和**不可恢复的运行时错误**。不可恢复的运行时错误的一个例子是*堆栈溢出*（见*第七章*，*内存管理*）。当发生不可恢复的错误时，程序通常会立即终止，因此没有必要发出这些类型的错误。然而，一些错误在某种类型的应用程序中可能被认为是可恢复的，但在其他应用程序中是不可恢复的。

讨论可恢复和不可恢复错误时经常出现的一个边缘情况是 C++标准库在内存耗尽时的不太幸运的行为。当程序耗尽内存时，这通常是不可恢复的，但标准库在这种情况下会尝试抛出`std::bad_alloc`异常。我们不会在这里花时间讨论不可恢复的错误，但是 Herb Sutter 的演讲《De-fragmenting C++: Making Exceptions and RTTI More Affordable and Usable》（[`sched.co/SiVW`](https://sched.co/SiVW)）非常推荐，如果你想深入了解这个话题。

在设计和实现 API 时，您应该始终反思您正在处理的错误类型，因为不同类别的错误应该以完全不同的方式处理。决定错误是编程错误还是运行时错误可以通过使用一种称为**设计契约**的方法来完成；这是一个值得一本书的话题。然而，我在这里将介绍足够我们目的的基本原则。

有关在 C++中添加契约语言支持的提案，但目前契约尚未成为标准的一部分。然而，许多 C++ API 和指南都假定您了解契约的基础知识，因为契约使用的术语使得更容易讨论和记录类和函数的接口。

## 契约

**合同**是调用某个函数的调用者和函数本身（被调用者）之间的一组规则。C++允许我们使用 C++类型系统明确指定一些规则。例如，考虑以下函数签名：

```cpp
int func(float x, float y) 
```

它指定`func()`返回一个整数（除非它抛出异常），并且调用者必须传递两个浮点值。但它并没有说明允许使用什么浮点值。例如，我们可以传递值 0.0 或负值吗？此外，`x`和`y`之间可能存在一些必需的关系，这些关系不能很容易地使用 C++类型系统来表达。当我们谈论 C++中的合同时，通常指的是调用者和被调用者之间存在的一些规则，这些规则不能很容易地使用类型系统来表达。

在不太正式的情况下，这里将介绍与设计合同相关的一些概念，以便为您提供一些可以用来推理接口和错误处理的术语：

+   前置条件指定了函数的*调用者*的*责任*。对函数传递的参数可能有约束。或者，如果它是一个成员函数，在调用函数之前对象可能必须处于特定状态。例如，在`std::vector`上调用`pop_back()`时的前置条件是向量不为空。确保向量不为空是`pop_back()`的*调用者*的责任。

+   后置条件指定了函数返回时的*职责*。如果它是一个成员函数，函数在什么状态下离开对象？例如，`std::list::sort()`的后置条件是列表中的元素按升序排序。

+   不变量是一个应该始终成立的条件。不变量可以在许多情境中使用。循环不变量是每次循环迭代开始时必须为真的条件。此外，类不变量定义了对象的有效状态。例如，`std::vector`的不变量是`size() <= capacity()`。明确陈述某些代码周围的不变量使我们更好地理解代码。不变量也是一种工具，可以用来证明某些算法是否按预期运行。

类不变量非常重要；因此，我们将花费更多时间讨论它们是什么以及它们如何影响类的设计。

### 类不变量

如前所述，**类不变量**定义了对象的有效状态。它指定了类内部数据成员之间的关系。在执行成员函数时，对象可能暂时处于无效状态。重要的是，当函数将控制权传递给可以观察对象状态的其他代码时，不变量得到维持。这可能发生在函数：

+   返回

+   抛出异常

+   调用回调函数

+   调用可能观察当前调用对象状态的其他函数；一个常见的情况是将`this`的引用传递给其他函数

重要的是要意识到类不变量是类的每个成员函数的前置条件和后置条件的隐含部分。如果成员函数使对象处于无效状态，则未满足后置条件。类似地，成员函数在调用函数时始终可以假定对象处于有效状态。这条规则的例外是类的构造函数和析构函数。如果我们想要插入代码来检查类不变量是否成立，我们可以在以下点进行：

```cpp
struct Widget {
  Widget() {
    // Initialize object…
    // Check class invariant
  }
  ~Widget() {
    // Check class invariant
    // Destroy object…
   }
   auto some_func() {
     // Check precondition (including class invariant)
     // Do the actual work…
     // Check postcondition (including class invariant)
   }
}; 
```

复制/移动构造函数和复制/移动赋值运算符在这里没有提到，但它们遵循与构造函数和`some_func()`相同的模式。

当对象已被移动后，对象可能处于某种空或重置状态。这也是对象的有效状态之一，因此是类不变式的一部分。然而，通常只有少数成员函数可以在对象处于此状态时调用。例如，您不能在已移动的`std::vector`上调用`push_back()`、`empty()`或`size()`，但可以调用`clear()`，这将使向量处于准备再次使用的状态。

您应该知道，这种额外的重置状态使类不变式变得更弱，也更不实用。为了完全避免这种状态，您应该以这样的方式实现您的类，使得已移动的对象被重置为对象在默认构造后的状态。我的建议是总是这样做，除非在很少的情况下，将已移动的状态重置为默认状态会带来无法接受的性能损失。这样，您可以更好地推理有关已移动状态的情况，而且类的使用更安全，因为在该对象上调用成员函数是可以的。

如果您可以确保对象始终处于有效状态（类不变式成立），那么您可能会拥有一个难以被误用的类，如果实现中存在错误，通常很容易发现。您最不希望的是在代码库中找到一个类，并想知道该类的某些行为是一个错误还是一个特性。违反合同始终是一个严重的错误。

为了能够编写有意义的类不变式，我们需要编写具有高内聚性和少可能状态的类。如果您曾经为自己编写的类编写单元测试，您可能会注意到，在编写单元测试时，很明显可以从初始版本改进 API。单元测试迫使您使用和反思类的接口而不是实现细节。同样，类不变式使您考虑对象可能处于的所有有效状态。如果您发现很难定义类不变式，通常是因为您的类承担了太多的责任并处理了太多的状态。因此，定义类不变式通常意味着您最终会得到设计良好的类。

### 维护合同

合同是您设计和实现的 API 的一部分。但是，您如何维护和向使用您的 API 的客户端传达合同呢？C++尚没有内置支持合同的功能，但正在进行工作以将其添加到未来的 C++版本中。不过，也有一些选择：

+   使用诸如 Boost.Contract 之类的库。

+   记录合同。这样做的缺点是在运行程序时不会检查合同。此外，文档往往在代码更改时过时。

+   使用`static_assert()`和`<cassert>`中定义的`assert()`宏。断言是可移植的，标准的 C++。

+   构建一个自定义库，其中包含类似断言的自定义宏，但对失败合同的行为具有更好的控制。

在本书中，我们将使用断言，这是检查合同违规的最原始的方式之一。然而，断言可以非常有效，并对代码质量产生巨大影响。

#### 启用和禁用断言

从技术上讲，在 C++中有两种标准的断言方式：使用`<cassert>`头文件中的`static_assert()`或`assert()`宏。`static_assert()`在代码编译期间进行验证，因此需要一个可以在编译时而不是运行时进行检查的表达式。失败的`static_assert()`会导致编译错误。

对于只能在运行时评估的断言，您需要使用`assert()`宏。`assert()`宏是一种运行时检查，通常在调试和测试期间处于活动状态，并在以发布模式构建程序时完全禁用。`assert()`宏通常定义如下：

```cpp
#ifdef NDEBUG
#define assert(condition) ((void)0)
#else
#define assert(condition) /* implementation defined */
#endif 
```

这意味着您可以通过定义`NDEBUG`完全删除所有断言和用于检查条件的代码。

现在，有了一些设计合同的术语，让我们专注于合同违反（错误）以及如何在您的代码中处理它们。

## 错误处理

在设计具有适当错误处理的 API 时，首先要做的是区分编程错误和运行时错误。因此，在我们深入讨论错误处理策略之前，我们将使用设计合同来定义我们正在处理的错误类型。

### 编程错误还是运行时错误？

如果我们发现合同违反，我们也发现了我们程序中的错误。例如，如果我们可以检测到有人在空向量上调用`pop_back()`，我们知道我们的源代码中至少有一个错误需要修复。每当前提条件不满足时，我们知道我们正在处理一个*编程错误*。

另一方面，如果我们有一个从磁盘加载某个记录的函数，并且由于磁盘上的读取错误而无法返回记录，那么我们已经检测到了一个*运行时错误*：

```cpp
auto load_record(std::uint32_t id) {
  assert(id != 0);           // Precondition
  auto record = read(id);    // Read from disk, may throw
  assert(record.is_valid()); // Postcondition
  return record;
} 
```

前提条件得到满足，但由于程序外部的某些原因，后置条件无法满足。源代码中没有错误，但由于某些与磁盘相关的错误，函数无法返回在磁盘上找到的记录。由于无法满足后置条件，必须将运行时错误报告给调用者，除非调用者可以自行通过重试等方式恢复。

### 编程错误（错误）

一般来说，编写代码来发出并处理代码中的错误没有意义。相反，使用断言（或先前提到的其他一些替代方案）来使开发人员意识到代码中的问题。您应该只对可恢复的运行时错误使用异常或错误代码。

#### 通过假设缩小问题空间

断言指定了您作为某些代码的作者所做的假设。只有在您的代码中的所有断言都为真时，您才能保证代码按预期工作。这使编码变得更容易，因为您可以有效地限制需要处理的情况数量。断言在您的团队使用、阅读和修改您编写的代码时也是巨大的帮助。所有假设都以断言语句的形式清楚地记录下来。

#### 使用断言查找错误

失败的断言总是严重的错误。当您在测试过程中发现一个失败的断言时，基本上有三种选择：

+   断言是正确的，但代码是错误的（要么是因为函数实现中的错误，要么是因为调用站点上的错误）。根据我的经验，这是最常见的情况。通常情况下，使断言正确比使其周围的代码正确要容易得多。修复代码并重新测试。

+   代码是正确的，但断言是错误的。有时会发生这种情况，如果您看的是旧代码，通常会感到非常不舒服。更改或删除失败的断言可能会耗费时间，因为您需要确保代码实际上是有效的，并理解为什么旧断言突然开始失败。通常，这是因为原始作者没有考虑到一个新的用例。

+   断言和代码都是错误的。这通常需要重新设计类或函数。也许要求已经改变，程序员所做的假设不再成立。但不要绝望；相反，您应该高兴那些假设是明确地使用断言写出来的；现在您知道为什么代码不再起作用了。

运行时断言需要测试，否则断言将不会被执行。新编写的带有许多断言的代码通常在测试时会出现故障。这并不意味着您是一个糟糕的程序员；这意味着您添加了有意义的断言，可以捕获一些本来可能会进入生产的错误。此外，使测试版本的程序终止的错误也很可能会被修复。

#### 性能影响

在代码中有许多运行时断言很可能会降低测试构建的性能。然而，断言从不应该在优化程序的最终版本中使用。如果您的断言使您的测试构建速度太慢而无法使用，通常很容易在分析器中跟踪到减慢代码速度的断言集（有关分析器的更多信息，请参见*第三章*，*分析和测量性能*）。

通过使程序的发布构建完全忽略由错误引起的错误状态，程序将不会花时间检查由错误引起的错误状态。相反，您的代码将运行得更快，只花时间解决它本来要解决的实际问题。它只会检查需要恢复的运行时错误。

总结一下，编程错误应该在测试程序时被检测出来。没有必要使用异常或其他错误处理机制来处理编程错误。相反，编程错误应该记录一些有意义的东西，并终止程序，以通知程序员需要修复错误。遵循这一准则显著减少了我们需要在代码中处理异常的地方。我们在优化构建中会有更好的性能，希望由于断言失败而检测到的错误会更少。然而，有些情况下可能会发生运行时错误，这些错误需要被我们实现的代码处理和恢复。

### 可恢复的运行时错误

如果一个函数无法履行其合同的一部分（即后置条件），则发生了运行时错误，需要将其通知到可以处理并恢复有效状态的代码中。处理可恢复错误的目的是将错误从发生错误的地方传递到可以恢复有效状态的地方。有许多方法可以实现这一点。这是一个硬币的两面：

+   对于信号部分，我们可以选择 C++异常、错误代码、返回`std::optional`或`std::pair`，或使用`boost::outcome`或`std::experimental::expected`。

+   保持程序的有效状态而不泄漏任何资源。确定性析构函数和自动存储期是 C++中使这成为可能的工具。

实用类`std::optional`和`std::pair`将在*第九章*，*基本实用程序*中介绍。现在我们将专注于 C++异常以及如何在从错误中恢复时避免泄漏资源。

#### 异常

异常是 C++提供的标准错误处理机制。该语言设计用于与异常一起使用。一个例子是构造函数失败；从构造函数中发出错误的唯一方法是使用异常。

根据我的经验，异常以许多不同的方式使用。造成这种情况的一个原因是不同的应用在处理运行时错误时可能有非常不同的要求。对于一些应用，比如起搏器或发电厂控制系统，如果它们崩溃可能会产生严重影响，我们可能必须处理每种可能的异常情况，比如内存耗尽，并保持应用程序处于运行状态。有些应用甚至完全不使用堆内存，要么是因为平台根本没有可用的堆，要么是因为堆引入了无法控制的不确定性，因为分配新内存的机制超出了应用程序的控制。

我假设您已经知道抛出和捕获异常的语法，并且不会在这里涵盖它。可以标记为`noexcept`的函数保证不会抛出异常。重要的是要理解编译器*不*验证这一点；相反，这取决于代码的作者来弄清楚他们的函数是否可能抛出异常。

标记为`noexcept`的函数在某些情况下可以使编译器生成更快的代码。如果从标记为`noexcept`的函数中抛出异常，程序将调用`std::terminate()`而不是展开堆栈。以下代码演示了如何将函数标记为不抛出异常：

```cpp
auto add(int a, int b) noexcept {
  return a + b;
} 
```

您可能会注意到，本书中的许多代码示例即使在生产代码中也适用`noexcept`（或`const`），也没有使用。这仅仅是因为书的格式；如果在我通常会添加`noexcept`和`const`的所有地方添加它们，会使代码难以阅读。

#### 保持有效状态

异常处理要求我们程序员考虑异常安全性保证；也就是说，在异常发生之前和之后程序的状态是什么？强异常安全性可以被视为一个事务。一个函数要么提交所有状态更改，要么在发生异常时执行完全回滚。

为了使这更具体化，让我们来看一个简单的函数：

```cpp
void func(std::string& str) {
  str += f1();  // Could throw
  str += f2();  // Could throw
} 
```

该函数将`f1()`和`f2()`的结果附加到字符串`str`。现在考虑一下，如果调用函数`f2()`时抛出异常会发生什么；只有`f1()`的结果会附加到`str`。相反，我们希望在发生异常时`str`保持不变。这可以通过使用一种称为**复制和交换**的惯用法来解决。这意味着我们在让应用程序状态被非抛出`swap()`函数修改之前，在临时副本上执行可能引发异常的操作：

```cpp
void func(std::string& str) {
  auto tmp = std::string{str};  // Copy
  tmp += f1();                  // Mutate copy, may throw
  tmp += f2();                  // Mutate copy, may throw
  std::swap(tmp, str);          // Swap, never throws
} 
```

相同的模式可以在成员函数中使用，以保持对象的有效状态。假设我们有一个类，其中包含两个数据成员和一个类不变式，该不变式规定数据成员不能相等，如下所示：

```cpp
class Number { /* ... */ };
class Widget {
public:
  Widget(const Number& x, const Number& y) : x_{x}, y_{y} {
    assert(is_valid());           // Check class invariant
  }
private:
  Number x_{};
  Number y_{};
  bool is_valid() const {         // Class invariant
   return x_ != y_;               // x_ and y_ must not be equal
  }
}; 
```

接下来，假设我们正在添加一个成员函数，该函数更新两个数据成员，如下所示：

```cpp
void Widget::update(const Number& x, const Number& y) {
  assert(x != y && is_valid());   // Precondition
  x_ = x;
  y_ = y;          
  assert(is_valid());             // Postcondition
} 
```

前提条件规定`x`和`y`不能相等。如果`x_`和`y_`的赋值可能会抛出异常，`x_`可能会被更新，但`y_`不会。这可能导致破坏类不变式；也就是说，对象处于无效状态。如果发生错误，我们希望函数保持对象在赋值操作之前的有效状态。再次，一个可能的解决方案是使用复制和交换惯用法：

```cpp
void Widget::update(const Number& x, const Number& y) {
    assert(x != y && is_valid());     // Precondition
    auto x_tmp = x;  
    auto y_tmp = y;  
    std::swap(x_tmp, x_); 
    std::swap(y_tmp, y_); 
    assert(is_valid());               // Postcondition
  } 
```

首先，创建本地副本，而不修改对象的状态。然后，如果没有抛出异常，可以使用非抛出`swap()`来更改对象的状态。复制和交换惯用法也可以在实现赋值运算符时使用，以实现强异常安全性保证。

错误处理的另一个重要方面是避免在发生错误时泄漏资源。

#### 资源获取

C++对象的销毁是可预测的，这意味着我们完全控制我们何时以及以何种顺序释放我们获取的资源。在下面的示例中进一步说明了这一点，当退出函数时，互斥变量`m`总是被解锁，因为作用域锁在我们退出作用域时释放它，无论我们如何以及在何处退出：

```cpp
auto func(std::mutex& m, bool x, bool y) {
  auto guard = std::scoped_lock{m}; // Lock mutex 
  if (x) { 
    // The guard automatically releases the mutex at early exit
    return; 
  }
  if (y) {
    // The guard automatically releases if an exception is thrown
    throw std::exception{};
  }
  // The guard automatically releases the mutex at function exit
} 
```

所有权、对象的生命周期和资源获取是 C++中的基本概念，我们将在*第七章* *内存管理*中进行讨论。

#### 性能

不幸的是，异常在性能方面声誉不佳。一些担忧是合理的，而一些是基于历史观察的，当时编译器没有有效地实现异常。然而，今天人们放弃异常的两个主要原因是：

+   即使不抛出异常，二进制程序的大小也会增加。尽管这通常不是问题，但它并不遵循零开销原则，因为我们为我们不使用的东西付费。

+   抛出和捕获异常相对昂贵。抛出和捕获异常的运行时成本是不确定的。这使得异常在具有硬实时要求的情况下不适用。在这种情况下，其他替代方案，如返回带有返回值和错误代码的`std::pair`可能更好。

另一方面，当没有抛出异常时，异常的性能表现非常出色；也就是说，当程序遵循成功路径时。其他错误报告机制，如错误代码，即使在程序没有任何错误时也需要在`if-else`语句中检查返回代码。

异常情况应该很少发生，通常当异常发生时，异常处理所增加的额外性能损耗通常不是这些情况的问题。通常可以在一些性能关键代码运行之前或之后执行可能引发异常的计算。这样，我们可以避免在程序中不能容忍异常的地方抛出和捕获异常。

为了公平比较异常和其他错误报告机制，重要的是要指定要比较的内容。有时异常与根本没有错误处理的情况进行比较是不公平的；异常需要与提供相同功能的机制进行比较。在你测量它们可能产生的影响之前，不要因为性能原因而放弃异常。你可以在下一章中了解更多关于分析和测量性能的内容。

现在我们将远离错误处理，探讨如何使用 lambda 表达式创建函数对象。

# 函数对象和 lambda 表达式

Lambda 表达式，引入于 C++11，并在每个 C++版本中进一步增强，是现代 C++中最有用的功能之一。它们的多功能性不仅来自于轻松地将函数传递给算法，还来自于在许多需要传递代码的情况下的使用，特别是可以将 lambda 存储在`std::function`中。

尽管 lambda 使得这些编程技术变得更加简单易用，但本节提到的所有内容都可以在没有 lambda 的情况下执行。lambda，或者更正式地说，lambda 表达式是构造函数对象的一种便捷方式。但是，我们可以不使用 lambda 表达式，而是实现重载了`operator()`的类，然后实例化这些类来创建函数对象。

我们将在稍后探讨 lambda 与这些类的相似之处，但首先我将在一个简单的用例中介绍 lambda 表达式。

## C++ lambda 的基本语法

简而言之，lambda 使程序员能够像传递变量一样轻松地将函数传递给其他函数。

让我们比较将 lambda 传递给算法和将变量传递给算法：

```cpp
// Prerequisite 
auto v = std::vector{1, 3, 2, 5, 4}; 

// Look for number three 
auto three = 3; 
auto num_threes = std::count(v.begin(), v.end(), three); 
// num_threes is 1 

// Look for numbers which is larger than three 
auto is_above_3 = [](int v) { return v > 3; }; 
auto num_above_3 = std::count_if(v.begin(), v.end(), is_above_3);
// num_above_3 is 2 
```

在第一种情况下，我们将一个变量传递给`std::count()`，而在后一种情况下，我们将一个函数对象传递给`std::count_if()`。这是 lambda 的典型用例；我们传递一个函数，由另一个函数（在本例中是`std::count_if()`）多次评估。

此外，lambda 不需要与变量绑定；就像我们可以将变量直接放入表达式中一样，我们也可以将 lambda 放入表达式中：

```cpp
auto num_3 = std::count(v.begin(), v.end(), 3); 
auto num_above_3 = std::count_if(v.begin(), v.end(), [](int i) { 
  return i > 3; 
}); 
```

到目前为止，你看到的 lambda 被称为**无状态 lambda**；它们不复制或引用 lambda 外部的任何变量，因此不需要任何内部状态。让我们通过使用捕获块引入**有状态 lambda**来使其更加高级。

## 捕获子句

在前面的例子中，我们在 lambda 中硬编码了值`3`，以便我们始终计算大于三的数字。如果我们想在 lambda 中使用外部变量怎么办？我们通过将外部变量放入**捕获子句**（即 lambda 的`[]`部分）来捕获外部变量：

```cpp
auto count_value_above(const std::vector<int>& v, int x) { 
  auto is_above = x { return i > x; }; 
  return std::count_if(v.begin(), v.end(), is_above); 
} 
```

在这个例子中，我们通过将变量`x`复制到 lambda 中来捕获它。如果我们想要将`x`声明为引用，我们在开头加上`&`，像这样：

```cpp
auto is_above = &x { return i > x; }; 
```

该变量现在只是外部`x`变量的引用，就像 C++中的常规引用变量一样。当然，我们需要非常小心引用到 lambda 中的对象的生命周期，因为 lambda 可能在引用的对象已经不存在的情况下执行。因此，通过值捕获更安全。

### 通过引用捕获与通过值捕获

使用捕获子句引用和复制变量的工作方式与常规变量一样。看看这两个例子，看看你能否发现区别：

| 通过值捕获 | 通过引用捕获 |
| --- | --- |

|

```cpp
auto func() {
  auto vals = {1,2,3,4,5,6};
  auto x = 3;
  auto is_above = x {
    return v > x;
  };
  x = 4;
  auto count_b = std::count_if(
    vals.begin(),
    vals.end(),
    is_above
   );  // count_b equals 3 } 
```

|

```cpp
auto func() {
  auto vals = {1,2,3,4,5,6};
  auto x = 3;
  auto is_above = &x {
    return v > x;
  };
  x = 4;
  auto count_b = std::count_if(
    vals.begin(),
    vals.end(),
    is_above
   );  // count_b equals 2 } 
```

|

在第一个例子中，`x`被*复制*到 lambda 中，因此当`x`被改变时不受影响；因此`std::count_if()`计算的是大于 3 的值的数量。

在第二个例子中，`x`被*引用捕获*，因此`std::count_if()`实际上计算的是大于 4 的值的数量。

### lambda 和类之间的相似之处

我之前提到过，lambda 表达式生成函数对象。函数对象是一个具有调用运算符`operator()()`定义的类的实例。

要理解 lambda 表达式的组成，你可以将其视为具有限制的常规类：

+   该类只包含一个成员函数

+   捕获子句是类的成员变量和其构造函数的组合

下表显示了 lambda 表达式和相应的类。左列使用*通过值捕获*，右列使用*通过引用捕获*：

| 通过值捕获的 lambda... | 通过引用捕获的 lambda... |
| --- | --- |

|

```cpp
auto x = 3;auto is_above = x { return y > x;};auto test = is_above(5); 
```

|

```cpp
auto x = 3;auto is_above = &x { return y > x;};auto test = is_above(5); 
```

|

| ...对应于这个类： | ...对应于这个类： |
| --- | --- |

|

```cpp
auto x = 3;class IsAbove {
public: IsAbove(int x) : x{x} {} auto operator()(int y) const {   return y > x; }private: int x{}; // Value };auto is_above = IsAbove{x};
auto test = is_above(5); 
```

|

```cpp
auto x = 3;class IsAbove {
public: IsAbove(int& x) : x{x} {} auto operator()(int y) const {   return y > x; }private: int& x; // Reference };
auto is_above = IsAbove{x};
auto test = is_above(5); 
```

|

由于 lambda 表达式，我们不必手动实现这些函数对象类型作为类。

### 初始化捕获变量

如前面的例子所示，捕获子句初始化了相应类中的成员变量。这意味着我们也可以在 lambda 中初始化成员变量。这些变量只能在 lambda 内部可见。下面是一个初始化名为`numbers`的捕获变量的 lambda 的示例：

```cpp
auto some_func = [numbers = std::list<int>{4,2}]() {
  for (auto i : numbers)
    std::cout << i;
};
some_func();  // Output: 42 
```

相应的类看起来像这样：

```cpp
class SomeFunc {
public:
 SomeFunc() : numbers{4, 2} {}
 void operator()() const {
  for (auto i : numbers)
    std::cout << i;
 }
private:
 std::list<int> numbers;
};
auto some_func = SomeFunc{};
some_func(); // Output: 42 
```

在捕获中初始化变量时，你可以想象在变量名前面有一个隐藏的`auto`关键字。在这种情况下，你可以将`numbers`视为被定义为`auto numbers = std::list<int>{4, 2}`。如果你想初始化一个引用，你可以在名称前面使用一个`&`，这对应于`auto&`。下面是一个例子：

```cpp
auto x = 1;
auto some_func = [&y = x]() {
  // y is a reference to x
}; 
```

同样，当引用（而不是复制）lambda 外部的对象时，你必须非常小心对象的生命周期。

在 lambda 中也可以移动对象，这在使用`std::unique_ptr`等移动类型时是必要的。以下是如何实现的：

```cpp
auto x = std::make_unique<int>(); 
auto some_func = [x = std::move(x)]() {
  // Use x here..
}; 
```

这也表明在 lambda 中使用相同的名称（`x`）是可能的。这并非必须。相反，我们可以在 lambda 内部使用其他名称，例如`[y = std::move(x)]`。

### 改变 lambda 成员变量

由于 lambda 的工作方式就像一个具有成员变量的类，它也可以改变它们。然而，lambda 的函数调用运算符默认为`const`，因此我们需要使用`mutable`关键字明确指定 lambda 可以改变其成员。在下面的示例中，lambda 在每次调用时改变`counter`变量：

```cpp
auto counter_func = [counter = 1]() mutable {
  std::cout << counter++;
};
counter_func(); // Output: 1
counter_func(); // Output: 2
counter_func(); // Output: 3 
```

如果 lambda 只通过引用捕获变量，我们不必在声明中添加`mutable`修饰符，因为 lambda 本身不会改变。可变和不可变 lambda 之间的区别在下面的代码片段中进行了演示：

| 通过值捕获 | 通过引用捕获 |
| --- | --- |

|

```cpp
auto some_func() {
  auto v = 7;
  auto lambda = [v]() mutable {
    std::cout << v << " ";
    ++v;
  };
  assert(v == 7);
  lambda();  lambda();
  assert(v == 7);
  std::cout << v;
} 
```

|

```cpp
auto some_func() {
  auto v = 7;
  auto lambda = [&v]() {
    std::cout << v << " ";
    ++v;
  };
  assert(v == 7);
  lambda();
  lambda();
  assert(v == 9);
  std::cout << v;
} 
```

|

| 输出：`7 8 7` | 输出：`7 8 9` |
| --- | --- |

在右侧的示例中，`v`被引用捕获，lambda 将改变`some_func()`作用域拥有的变量`v`。左侧列中的可变 lambda 只会改变 lambda 本身拥有的`v`的副本。这就是为什么我们会得到两个版本中不同的输出的原因。

#### 从编译器的角度改变成员变量

要理解前面示例中发生了什么，看一下编译器如何看待前面的 lambda 对象：

| 通过值捕获 | 通过引用捕获 |
| --- | --- |

|

```cpp
class Lambda {
 public:
 Lambda(int m) : v{m} {}
 auto operator()() {
   std::cout<< v << " ";
   ++v;
 }
private:
  int v{};
}; 
```

|

```cpp
class Lambda {
 public:
 Lambda(int& m) : v{m} {}
 auto operator()() const {
   std::cout<< v << " ";
   ++v;
 }
private:
 int& v;
}; 
```

|

正如你所看到的，第一种情况对应于具有常规成员的类，而通过引用捕获的情况只是对应于成员变量是引用的类。

你可能已经注意到我们在通过引用捕获类的`operator()`成员函数上添加了`const`修饰符，并且在相应的 lambda 上也没有指定`mutable`。这个类仍然被认为是`const`的原因是我们没有在实际的类/lambda 内部改变任何东西；实际的改变应用于引用的值，因此函数仍然被认为是`const`的。

### 捕获所有

除了逐个捕获变量，还可以通过简单地写`[=]`或`[&]`来捕获作用域中的所有变量。

使用`[=]`意味着每个变量都将被值捕获，而`[&]`则通过引用捕获所有变量。

如果我们在成员函数内部使用 lambda，也可以通过使用`[this]`来通过引用捕获整个对象，或者通过写`[*this]`来通过复制捕获整个对象：

```cpp
class Foo { 
public: 
 auto member_function() { 
   auto a = 0; 
   auto b = 1.0f;
   // Capture all variables by copy 
   auto lambda_0 = [=]() { std::cout << a << b; }; 
   // Capture all variables by reference 
   auto lambda_1 = [&]() { std::cout << a << b; }; 
   // Capture object by reference 
   auto lambda_2 = [this]() { std::cout << m_; }; 
   // Capture object by copy 
   auto lambda_3 = [*this]() { std::cout << m_; }; 
 }
private: 
 int m_{}; 
}; 
```

请注意，使用`[=]`并不意味着作用域内的所有变量都会被复制到 lambda 中；只有实际在 lambda 内部使用的变量才会被复制。

当通过值捕获所有变量时，可以指定通过引用捕获变量（反之亦然）。以下表格显示了捕获块中不同组合的结果：

| 捕获块 | 结果捕获类型 |
| --- | --- |

|

```cpp
int a, b, c;auto func = [=] { /*...*/ }; 
```

| 通过值捕获`a`、`b`、`c`。 |
| --- |

|

```cpp
int a, b, c;auto func = [&] { /*...*/ }; 
```

| 通过引用捕获`a`、`b`、`c`。 |
| --- |

|

```cpp
int a, b, c;auto func = [=, &c] { /*...*/ }; 
```

| 通过值捕获`a`、`b`。通过引用捕获`c`。 |
| --- |

|

```cpp
int a, b, c;auto func = [&, c] { /*...*/ }; 
```

| 通过引用捕获`a`、`b`。通过值捕获`c`。 |
| --- |

虽然使用`[&]`或`[=]`捕获所有变量很方便，但我建议逐个捕获变量，因为这样可以通过明确指出 lambda 作用域内使用了哪些变量来提高代码的可读性。

## 将 C 函数指针分配给 lambda

没有捕获的 lambda 可以隐式转换为函数指针。假设你正在使用一个 C 库，或者一个旧的 C++库，它使用回调函数作为参数，就像这样：

```cpp
extern void download_webpage(const char* url,
                              void (*callback)(int, const char*)); 
```

回调函数将以返回代码和一些下载内容的形式被调用。在调用`download_webpage()`时，可以将 lambda 作为参数传递。由于回调是常规函数指针，lambda 不能有任何捕获，必须在 lambda 前面加上加号（`+`）：

```cpp
auto lambda = +[](int result, const char* str) {
  // Process result and str
};
download_webpage("http://www.packt.com", lambda); 
```

这样，lambda 就转换为常规函数指针。请注意，lambda 不能有任何捕获，以便使用此功能。

## Lambda 类型

自 C++20 以来，没有捕获的 lambda 是可默认构造和可赋值的。通过使用`decltype`，现在可以轻松构造具有相同类型的不同 lambda 对象：

```cpp
auto x = [] {};   // A lambda without captures
auto y = x;       // Assignable
decltype(y) z;    // Default-constructible
static_assert(std::is_same_v<decltype(x), decltype(y)>); // passes
static_assert(std::is_same_v<decltype(x), decltype(z)>); // passes 
```

然而，这仅适用于没有捕获的 lambda。具有捕获的 lambda 有它们自己的唯一类型。即使两个具有捕获的 lambda 函数是彼此的克隆，它们仍然具有自己的唯一类型。因此，不可能将一个具有捕获的 lambda 分配给另一个 lambda。

## Lambda 和 std::function

如前一节所述，具有捕获的 lambda（有状态的 lambda）不能相互赋值，因为它们具有唯一的类型，即使它们看起来完全相同。为了能够存储和传递具有捕获的 lambda，我们可以使用`std::function`来保存由 lambda 表达式构造的函数对象。

`std::function`的签名定义如下：

```cpp
std::function< return_type ( parameter0, parameter1...) > 
```

因此，返回空并且没有参数的`std::function`定义如下：

```cpp
auto func = std::function<void(void)>{}; 
```

返回`bool`类型，带有`int`和`std::string`作为参数的`std::function`定义如下：

```cpp
auto func = std::function<bool(int, std::string)>{}; 
```

共享相同签名（相同参数和相同返回类型）的 lambda 函数可以由相同类型的`std::function`对象持有。`std::function`也可以在运行时重新分配。

重要的是，lambda 捕获的内容不会影响其签名，因此具有捕获和不捕获的 lambda 可以分配给相同的`std::function`变量。以下代码展示了如何将不同的 lambda 分配给同一个名为`func`的`std::function`对象：

```cpp
// Create an unassigned std::function object 
auto func = std::function<void(int)>{}; 
// Assign a lambda without capture to the std::function object 
func = [](int v) { std::cout << v; }; 
func(12); // Prints 12 
// Assign a lambda with capture to the same std::function object 
auto forty_two = 42; 
func = forty_two { std::cout << (v + forty_two); }; 
func(12); // Prints 54 
```

让我们在接下来的一个类似真实世界的例子中使用`std::function`。

### 使用 std::function 实现一个简单的 Button 类

假设我们着手实现一个`Button`类。然后我们可以使用`std::function`来存储与点击按钮对应的动作，这样当我们调用`on_click()`成员函数时，相应的代码就会被执行。

我们可以这样声明`Button`类：

```cpp
class Button {
public: 
  Button(std::function<void(void)> click) : handler_{click} {} 
  auto on_click() const { handler_(); } 
private: 
  std::function<void(void)> handler_{};
}; 
```

然后我们可以使用它来创建多种具有不同动作的按钮。这些按钮可以方便地存储在容器中，因为它们都具有相同的类型：

```cpp
auto create_buttons () { 
  auto beep = Button([counter = 0]() mutable {  
    std::cout << "Beep:" << counter << "! "; 
    ++counter; 
  }); 
  auto bop = Button([] { std::cout << "Bop. "; }); 
  auto silent = Button([] {});
  return std::vector<Button>{beep, bop, silent}; 
} 
```

在列表上进行迭代，并对每个按钮调用`on_click()`将执行相应的函数：

```cpp
const auto& buttons = create_buttons();
for (const auto& b: buttons) {
  b.on_click();
}
buttons.front().on_click(); // counter has been incremented
// Output: "Beep:0! Bop. Beep:1!" 
```

前面的按钮和点击处理程序示例展示了在 lambda 与`std::function`结合使用时的一些好处；即使每个有状态的 lambda 都有其自己独特的类型，一个`std::function`类型可以包装共享相同签名（返回类型和参数）的 lambda。

顺便说一句，你可能已经注意到`on_click()`成员函数被声明为`const`。然而，它通过增加一个点击处理程序中的`counter`变量来改变成员变量`handler_`。这可能看起来违反了 const 正确性规则，因为`Button`的 const 成员函数允许调用其类成员的变异函数。之所以允许这样做，是因为成员指针在 const 上下文中允许改变其指向的值。在本章的前面，我们讨论了如何传播指针数据成员的 const 性。

### std::function 的性能考虑

与通过 lambda 表达式直接构造的函数对象相比，`std::function`有一些性能损失。本节将讨论在使用`std::function`时需要考虑的一些与性能相关的事项。

#### 阻止内联优化

在谈到 lambda 时，编译器有能力内联函数调用；也就是说，函数调用的开销被消除了。`std::function`的灵活设计使得编译器几乎不可能内联包装在`std::function`中的函数。如果非常频繁地调用包装在`std::function`中的小函数，那么阻止内联优化可能会对性能产生负面影响。

#### 捕获变量的动态分配内存

如果将`std::function`分配给带有捕获变量/引用的 lambda，那么`std::function`在大多数情况下将使用堆分配的内存来存储捕获的变量。如果捕获变量的大小低于某个阈值，一些`std::function`的实现将不分配额外的内存。

这意味着不仅由于额外的动态内存分配而产生性能损失，而且由于堆分配的内存可能增加缓存未命中的次数（在*第四章*的*数据结构*中了解更多关于缓存未命中的信息）。

#### 额外的运行时计算

调用`std::function`通常比执行 lambda 慢一点，因为涉及到更多的代码。对于小而频繁调用的`std::function`来说，这种开销可能变得很大。想象一下，我们定义了一个非常小的 lambda：

```cpp
auto lambda = [](int v) { return v * 3; }; 
```

接下来的基准测试演示了对于一个`std::vector`的 1000 万次函数调用，使用显式 lambda 类型与相应的`std::function`的`std::vector`之间的差异。我们将从使用显式 lambda 的版本开始：

```cpp
auto use_lambda() { 
  using T = decltype(lambda);
  auto fs = std::vector<T>(10'000'000, lambda);
  auto res = 1;
  // Start clock
  for (const auto& f: fs)
    res = f(res);
  // Stop clock here
  return res;
} 
```

我们只测量执行函数内部循环所需的时间。下一个版本将我们的 lambda 包装在`std::function`中，如下所示：

```cpp
auto use_std_function() { 
  using T = std::function<int(int)>;
  auto fs = std::vector<T>(10'000'000, T{lambda});
  auto res = 1;
  // Start clock
  for (const auto& f: fs)
    res = f(res);
  // Stop clock here
  return res;
} 
```

我正在使用 2018 年的 MacBook Pro 上使用 Clang 编译此代码，并打开了优化（`-O3`）。第一个版本`use_lambda()`在大约 2 毫秒内执行循环，而第二个版本`use_std_function()`则需要近 36 毫秒来执行循环。

## 通用 lambda

通用 lambda 是一个接受`auto`参数的 lambda，使得可以用任何类型调用它。它的工作原理与常规 lambda 一样，但`operator()`已被定义为成员函数模板。

只有参数是模板变量，而不是捕获的值。换句话说，以下示例中捕获的值`v`将始终是`int`类型，而不管`v0`和`v1`的类型如何：

```cpp
auto v = 3; // int
auto lambda = v {
  return v + v0*v1;
}; 
```

如果我们将上述 lambda 表达式转换为一个类，它将对应于以下内容：

```cpp
class Lambda {
public:
  Lambda(int v) : v_{v} {}
  template <typename T0, typename T1>
  auto operator()(T0 v0, T1 v1) const { 
    return v_ + v0*v1; 
  }
private:
  int v_{};
};
auto v = 3;
auto lambda = Lambda{v}; 
```

就像模板化版本一样，直到调用 lambda 表达式，编译器才会生成实际的函数。因此，如果我们像这样调用之前的 lambda：

```cpp
auto res_int = lambda(1, 2);
auto res_float = lambda(1.0f, 2.0f); 
```

编译器将生成类似于以下 lambda 表达式：

```cpp
auto lambda_int = v { return v + v0*v1; };
auto lambda_float = v { return v + v0*v1; };
auto res_int = lambda_int(1, 2);
auto res_float = lambda_float(1.0f, 2.0f); 
```

正如您可能已经发现的那样，这些版本将进一步处理，就像常规 lambda 一样。

C++20 的一个新特性是，我们可以在通用 lambda 的参数类型中使用`typename`而不仅仅是`auto`。以下通用 lambda 是相同的：

```cpp
// Using auto
auto x = [](auto v) { return v + 1; };
// Using typename
auto y = []<typename Val>(Val v) { return v + 1; }; 
```

这使得在 lambda 的主体内部命名类型或引用类型成为可能。

# 总结

在本章中，您已经学会了如何使用现代 C++特性，这些特性将在整本书中使用。自动类型推导、移动语义和 lambda 表达式是每个 C++程序员今天都需要熟悉的基本技术。

我们还花了一些时间来研究错误处理以及如何思考错误和有效状态，以及如何从运行时错误中恢复。错误处理是编程中极其重要的一部分，很容易被忽视。考虑调用方和被调用方之间的契约是使您的代码正确并避免在程序的发布版本中进行不必要的防御性检查的一种方法。

在下一章中，我们将探讨在 C++中分析和测量性能的策略。
