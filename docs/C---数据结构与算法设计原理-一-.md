# C++ 数据结构与算法设计原理（一）

> 原文：[`annas-archive.org/md5/89b76b51877d088e41b92eef0985a12b`](https://annas-archive.org/md5/89b76b51877d088e41b92eef0985a12b)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

## 关于

本节简要介绍了作者、本书的覆盖范围、开始所需的技术技能，以及完成所有包含的活动和练习所需的硬件和软件要求。

## 关于本书

C++是一种成熟的多范式编程语言，可以让您编写具有对硬件高度控制的高级代码。今天，包括数据库、浏览器、多媒体框架和 GUI 工具包在内的重要软件基础设施都是用 C++编写的。

本书首先介绍了 C++数据结构以及如何使用链表、数组、栈和队列存储数据。在后面的章节中，本书解释了基本的算法设计范式，如贪婪方法和分治方法，用于解决各种计算问题。最后，您将学习动态规划的高级技术，以开发本书讨论的几种算法的优化实现。

通过本书，您将学会如何在高效且可扩展的 C++ 14 代码中实现标准数据结构和算法。

### 关于作者

**John Carey**

作曲家和钢琴家 John Carey 的正式教育几乎完全基于音乐领域。在他的艺术努力中广泛使用计算机和其他形式的技术后，他投入了多年的自学，学习编程和数学，并现在作为软件工程师专业工作。他相信他不寻常的背景为他提供了对软件开发主题的独特和相对非学术的视角。他目前在 Hydratec Industries 工作，该公司主要为消防洒水系统设计师开发 CAD 软件，用于对拟议设计进行水力计算，以确定其有效性和合法性。

**Shreyans Doshi**

Shreyans 毕业于 Nirma 大学，获得计算机工程学士学位。毕业后，他加入了金融行业，致力于使用尖端 C++应用程序开发超低延迟交易系统。在过去的三年里，他一直在 C++中设计交易基础设施。

**Payas Rajan**

Payas 毕业于 NIT Allahabad，获得计算机科学技术学士学位。后来，他加入了三星研究印度，在那里帮助开发了 Tizen 设备的多媒体框架。目前，他在加州大学河滨分校攻读博士学位，专攻地理空间数据库和路径规划算法，并担任教学和研究助理，他已经使用 C++创建应用程序十年。

### 学习目标

通过本书，您将能够：

+   使用哈希表、字典和集合构建应用程序

+   使用布隆过滤器实现 URL 缩短服务

+   应用常见算法，如堆排序和归并排序，用于字符串数据类型

+   使用 C++模板元编程编写代码库

+   探索现代硬件如何影响程序的实际运行性能

+   使用适当的现代 C++习语，如`std::array`，而不是 C 风格数组

### 受众

这本书适用于想要重新学习基本数据结构和算法设计技术的开发人员或学生。虽然不需要数学背景，但一些复杂度类和大 O 符号的基本知识，以及算法课程的资格，将帮助您充分利用本书。假定您熟悉 C++ 14 标准。

### 方法

本书采用实用的、动手的方法来解释各种概念。通过练习，本书展示了在现代计算机上，理论上应该执行类似的不同数据结构实际上表现出了不同的性能。本书不涉及任何理论分析，而是专注于基准测试和实际结果。

### 硬件要求

为了获得最佳的学生体验，我们建议以下硬件配置：

+   任何带有 Windows、Linux 或 macOS 的入门级 PC/Mac 都足够了

+   处理器：Intel Core 2 Duo，Athlon X2 或更好

+   内存：4 GB RAM

+   存储：10 GB 可用空间

### 软件要求

您还需要提前安装以下软件：

+   操作系统：Windows 7 SP1 32/64 位，Windows 8.1 32/64 位，或 Windows 10 32/64 位，Ubuntu 14.04 或更高版本，或 macOS Sierra 或更高版本

+   浏览器：Google Chrome 或 Mozilla Firefox

+   任何支持 C++ 14 标准的现代编译器和集成开发环境（可选）。

### 安装和设置

在开始阅读本书之前，请安装本书中使用的以下库。您将在这里找到安装这些库的步骤：

安装 Boost 库：

本书中的一些练习和活动需要 Boost C++库。您可以在以下链接找到库以及安装说明：

Windows：[`www.boost.org/doc/libs/1_71_0/more/getting_started/windows.html`](https://www.boost.org/doc/libs/1_71_0/more/getting_started/windows.html)

Linux/macOS：[`www.boost.org/doc/libs/1_71_0/more/getting_started/unix-variants.html`](https://www.boost.org/doc/libs/1_71_0/more/getting_started/unix-variants.html)

### 安装代码包

将课程的代码包复制到`C:/Code`文件夹中。

### 额外资源

本书的代码包也托管在 GitHub 上，网址为[`github.com/TrainingByPackt/CPP-Data-Structures-and-Algorithm-Design-Principles`](https://github.com/TrainingByPackt/CPP-Data-Structures-and-Algorithm-Design-Principles)。

我们还有来自丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！


# 第一章：列表、栈和队列

## 学习目标

在本章结束时，您将能够：

+   描述在任何应用程序中使用正确数据结构的重要性

+   根据问题实现各种内置数据结构，以使应用程序开发更加简单

+   如果 C++提供的数据结构不适合用例，实现适合特定情况的自定义线性数据结构

+   分析现实生活中的问题，不同类型的线性数据结构如何有帮助，并决定哪种对于给定的用例最合适

本章描述了在任何应用程序中使用正确数据结构的重要性。我们将学习如何在 C++中使用一些最常见的数据结构，以及使用这些结构的内置和自定义容器。

## 介绍

在设计任何应用程序时，数据管理是需要牢记的最重要考虑因素之一。任何应用程序的目的都是获取一些数据作为输入，对其进行处理或操作，然后提供合适的数据作为输出。例如，让我们考虑一个医院管理系统。在这里，我们可能有关于不同医生、患者和档案记录等的数据。医院管理系统应该允许我们执行各种操作，比如接收患者，并更新不同专业医生的加入和离开情况。虽然用户界面会以对医院管理员相关的格式呈现信息，但在内部，系统会管理不同的记录和项目列表。

程序员可以使用多种结构来保存内存中的任何数据。选择正确的数据结构对于确保可靠性、性能和在应用程序中实现所需功能至关重要。除了正确的数据结构，还需要选择正确的算法来访问和操作数据，以实现应用程序的最佳行为。本书将使您能够为应用程序设计实现正确的数据结构和算法，从而使您能够开发出经过优化和可扩展的应用程序。

本章介绍了 C++中提供的基本和常用的线性数据结构。我们将研究它们的设计、优缺点。我们还将通过练习来实现这些结构。了解这些数据结构将帮助您以更高效、标准化、可读和可维护的方式管理任何应用程序中的数据。

线性数据结构可以广泛地分为连续或链式结构。让我们了解一下两者之间的区别。

## 连续与链式数据结构

在处理任何应用程序中的数据之前，我们必须决定如何存储数据。对这个问题的答案取决于我们想要对数据执行什么样的操作以及操作的频率。我们应该选择能够在延迟、内存或任何其他参数方面给我们最佳性能的实现，而不影响应用程序的正确性。

确定要使用的数据结构类型的一个有用的度量标准是算法复杂度，也称为时间复杂度。时间复杂度表示执行某个操作所需的时间相对于数据大小的比例。因此，时间复杂度显示了如果我们改变数据集的大小，时间将如何变化。对于任何数据类型上的不同操作的时间复杂度取决于数据在其中的存储方式。

数据结构可以分为两种类型：连续和链式数据结构。我们将在接下来的章节中更仔细地看看它们。

### 连续数据结构

如前所述，**连续数据结构**将所有元素存储在单个内存块中。下图显示了连续数据结构中数据的存储方式：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_01_01.jpg)

###### 图 1.1：连续数据结构的图示表示

在上图中，考虑较大的矩形是存储所有元素的单个内存块，而较小的矩形表示为每个元素分配的内存。这里需要注意的一点是，所有元素都是相同类型的。因此，它们都需要相同数量的内存，这由`sizeof(type)`表示。第一个元素的地址也被称为`BA + sizeof(type)`位置，其后的元素位于`BA + 2 * sizeof(type)`，依此类推。因此，要访问索引`i`处的任何元素，我们可以使用通用公式获取：`BA + i * sizeof(type)`。

在这种情况下，我们可以立即使用公式访问任何元素，而不管数组的大小如何。因此，访问时间始终是恒定的。这在大 O 符号中用*O(1)*表示。

数组的两种主要类型是静态和动态。静态数组仅在其声明块内存在，但动态数组提供了更好的灵活性，因为程序员可以确定何时应该分配它，何时应该释放它。根据需求，我们可以选择其中之一。对于不同的操作，它们的性能是相同的。由于这个数组是在 C 中引入的，它也被称为 C 风格数组。以下是这些数组的声明方式：

+   静态数组声明为`int arr[size];`。

+   C 中声明动态数组为`int* arr = (int*)malloc(size * sizeof(int));`。

+   C++中声明动态数组为`int* arr = new int[size];`。

静态数组是聚合的，这意味着它是在堆栈上分配的，因此在流程离开函数时被释放。另一方面，动态数组是在堆上分配的，并且会一直保留在那里，直到手动释放内存。

由于所有元素都是相邻的，当访问其中一个元素时，它旁边的几个元素也会被带入缓存。因此，如果要访问这些元素，这是一个非常快速的操作，因为数据已经存在于缓存中。这个属性也被称为缓存局部性。虽然它不会影响任何操作的渐近时间复杂度，但在遍历数组时，对于实际上连续的数据，它可以提供令人印象深刻的优势。由于遍历需要顺序地遍历所有元素，获取第一个元素后，接下来的几个元素可以直接从缓存中检索。因此，该数组被认为具有良好的缓存局部性。

### 链接数据结构

链接数据结构将数据存储在多个内存块中，也称为节点，这些节点可以放置在内存的不同位置。下图显示了链接数据结构中数据的存储方式：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_01_02.jpg)

###### 图 1.2：链接数据结构

在链表的基本结构中，每个节点包含要存储在该节点中的数据和指向下一个节点的指针。最后一个节点包含一个`NULL`指针，表示列表的结尾。要访问任何元素，我们必须从链表的开头，即头部开始，然后沿着下一个指针继续，直到达到预期的元素。因此，要到达索引`i`处的元素，我们需要遍历链表并迭代`i`次。因此，我们可以说访问元素的复杂度是*O(n)*；也就是说，时间与节点数成比例变化。

如果我们想要插入或删除任何元素，并且我们有指向该元素的指针，与数组相比，对于链表来说，这个操作是非常小且相当快的。让我们看看在链表中如何插入一个元素。下图说明了在链表中插入两个元素之间的情况：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_01_03.jpg)

###### 图 1.3：向链表中插入一个元素

对于插入，一旦我们构造了要插入的新节点，我们只需要重新排列链接，使得前一个元素的下一个指针*(i = 1)*指向新元素*(i = 2)*，而不是当前元素的当前元素*(i = 3)*，并且新元素*(i = 2)*的下一个指针指向当前元素的下一个元素*(i = 3)*。这样，新节点就成为链表的一部分。

同样，如果我们想要删除任何元素，我们只需要重新排列链接，使得要删除的元素不再连接到任何列表元素。然后，我们可以释放该元素或对其采取任何其他适当的操作。

由于链表中的元素不是连续存储在内存中的，所以链表根本无法提供缓存局部性。因此，没有办法将下一个元素带入缓存，而不是通过当前元素中存储的指针实际访问它。因此，尽管在理论上，它的遍历时间复杂度与数组相同，但在实践中，它的性能很差。

以下部分提供了关于连续和链式数据结构的比较总结。

### 比较

以下表格简要总结了链式和连续数据结构之间的重要区别：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_01_04.jpg)

###### 图 1.4：比较连续和链式数据结构的表

以下表格包含了关于数组和链表在各种参数方面的性能总结：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_01_05.jpg)

###### 图 1.5：显示数组和链表某些操作的时间复杂度的表

对于任何应用程序，我们可以根据要求和不同操作的频率选择数据结构或两者的组合。

数组和链表是非常常见的，广泛用于任何应用程序中存储数据。因此，这些数据结构的实现必须尽可能无缺陷和高效。为了避免重新编写代码，C++提供了各种结构，如`std::array`、`std::vector`和`std::list`。我们将在接下来的章节中更详细地看到其中一些。

### C 风格数组的限制

虽然 C 风格的数组可以完成任务，但它们并不常用。有许多限制表明需要更好的解决方案。其中一些主要限制如下：

+   内存分配和释放必须手动处理。未能释放可能导致内存泄漏，即内存地址变得不可访问。

+   `operator[]`函数不会检查参数是否大于数组的大小。如果使用不正确，这可能导致分段错误或内存损坏。

+   嵌套数组的语法变得非常复杂，导致代码难以阅读。

+   默认情况下不提供深拷贝功能，必须手动实现。

为了避免这些问题，C++提供了一个非常薄的包装器，称为`std::array`，覆盖了 C 风格数组。

## std::array

`std::array`自动分配和释放内存。`std::array`是一个带有两个参数的模板类——元素的类型和数组的大小。

在下面的例子中，我们将声明大小为`10`的`int`类型的`std::array`，设置任何一个元素的值，然后打印该值以确保它能正常工作：

```cpp
std::array<int, 10> arr;        // array of int of size 10
arr[0] = 1;                    // Sets the first element as 1
std::cout << "First element: " << arr[0] << std::endl;
std::array<int, 4> arr2 = {1, 2, 3, 4};
std::cout << "Elements in second array: ";
  for(int i = 0; i < arr.size(); i++)
    std::cout << arr2[i] << " ";
```

这个例子将产生以下输出：

```cpp
First element: 1
Elements in second array: 1 2 3 4 
```

正如我们所看到的，`std::array`提供了`operator[]`，与 C 风格数组相同，以避免检查索引是否小于数组的大小的成本。此外，它还提供了一个名为`at(index)`的函数，如果参数无效，则会抛出异常。通过这种方式，我们可以适当地处理异常。因此，如果我们有一段代码，其中将访问一个具有一定不确定性的元素，例如依赖于用户输入的数组索引，我们总是可以使用异常处理来捕获错误，就像以下示例中演示的那样。

```cpp
try
{
    std::cout << arr.at(4);    // No error
    std::cout << arr.at(5);    // Throws exception std::out_of_range
}
catch (const std::out_of_range& ex)
{
    std::cerr << ex.what();
}
```

除此之外，将`std::array`传递给另一个函数类似于传递任何内置数据类型。我们可以按值或引用传递它，可以使用`const`也可以不使用。此外，语法不涉及任何指针相关操作或引用和解引用操作。因此，与 C 风格数组相比，即使是多维数组，可读性要好得多。以下示例演示了如何按值传递数组：

```cpp
void print(std::array<int, 5> arr)
{
    for(auto ele: arr)
    {
        std::cout << ele << ", ";
    }
}
std::array<int, 5> arr = {1, 2, 3, 4, 5};
print(arr);
```

这个例子将产生以下输出：

```cpp
1, 2, 3, 4, 5
```

我们不能将任何其他大小的数组传递给这个函数，因为数组的大小是函数参数数据类型的一部分。因此，例如，如果我们传递`std::array<int, 10>`，编译器将返回一个错误，说它无法匹配函数参数，也无法从一个类型转换为另一个类型。然而，如果我们想要一个通用函数，可以处理任何大小的`std::array`，我们可以使该函数的数组大小成为模板化，并且它将为所需大小的数组生成代码。因此，签名将如下所示：

```cpp
template <size_t N>
void print(const std::array<int, N>& arr)
```

除了可读性之外，在传递`std::array`时，默认情况下会将所有元素复制到一个新数组中。因此，会执行自动深复制。如果我们不想要这个特性，我们总是可以使用其他类型，比如引用和`const`引用。因此，它为程序员提供了更大的灵活性。

在实践中，对于大多数操作，`std::array`提供与 C 风格数组类似的性能，因为它只是一个薄包装器，减少了程序员的工作量并使代码更安全。`std::array`提供两个不同的函数来访问数组元素——`operator[]`和`at()`。`operator[]`类似于 C 风格数组，并且不对索引进行任何检查。然而，`at()`函数对索引进行检查，如果索引超出范围，则抛出异常。因此，在实践中它会慢一些。

如前所述，迭代数组是一个非常常见的操作。`std::array`通过范围循环和迭代器提供了一个非常好的接口。因此，打印数组中所有元素的代码如下所示：

```cpp
std::array<int, 5> arr = {1, 2, 3, 4, 5};
for(auto element: arr)
{
    std::cout << element << ' ';
}
```

这个例子将显示以下输出：

```cpp
1 2 3 4 5 
```

在前面的示例中，当我们演示打印所有元素时，我们使用了一个索引变量进行迭代，我们必须确保它根据数组的大小正确使用。因此，与这个示例相比，它更容易出现人为错误。

我们可以使用范围循环迭代`std::array`是因为迭代器。`std::array`有名为`begin()`和`end()`的成员函数，返回访问第一个和最后一个元素的方法。为了从一个元素移动到下一个元素，它还提供了算术运算符，比如递增运算符(`++`)和加法运算符(`+`)。因此，范围循环从`begin()`开始，到`end()`结束，使用递增运算符(`++`)逐步前进。迭代器为所有动态可迭代的 STL 容器提供了统一的接口，比如`std::array`、`std::vector`、`std::map`、`std::set`和`std::list`。

除了迭代之外，所有需要在容器内指定位置的函数都基于迭代器；例如，在特定位置插入、在范围内或特定位置删除元素以及其他类似的函数。这使得代码更具可重用性、可维护性和可读性。

#### 注意

对于 C++中使用迭代器指定范围的所有函数，`start()`迭代器通常是包含的，而`end()`迭代器通常是排除的，除非另有说明。

因此，`array::begin()`函数返回一个指向第一个元素的迭代器，但`array::end()`返回一个指向最后一个元素之后的迭代器。因此，可以编写基于范围的循环如下：

```cpp
for(auto it = arr.begin(); it != arr.end(); it++)
{
    auto element = (*it);
    std::cout << element << ' ';
}
```

还有一些其他形式的迭代器，比如`const_iterator`和`reverse_iterator`，它们也非常有用。`const_iterator`是正常迭代器的`const`版本。如果数组被声明为`const`，与迭代器相关的函数（如`begin()`和`end()`）会返回`const_iterator`。

`reverse_iterator`允许我们以相反的方向遍历数组。因此，它的函数，如增量运算符（`++`）和`advance`，是正常迭代器的逆操作。

除了`operator[]`和`at()`函数外，`std::array`还提供了其他访问器，如下表所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_01_06.jpg)

###### 图 1.6：显示`std::array`的一些访问器

以下代码片段演示了这些函数的使用：

```cpp
std::array<int, 5> arr = {1, 2, 3, 4, 5};
std::cout << arr.front() << std::endl;       // Prints 1
std::cout << arr.back() << std::endl;        // Prints 5
std::cout << *(arr.data() + 1) << std::endl; // Prints 2
```

`std::array`提供的另一个有用功能是用于深度比较的关系运算符和用于深度复制的复制赋值运算符。所有大小运算符（`<`，`>`，`<=`，`>=`，`==`，`!=`）都被定义用于比较两个数组，前提是相同的运算符也被提供给`std::array`的基础类型。

C 风格数组也支持所有关系运算符，但这些运算符实际上并不比较数组内部的元素；事实上，它们只是比较指针。因此，只是将元素的地址作为整数进行比较，而不是对数组进行深度比较。这也被称为**浅比较**，并且并不太实用。同样，赋值也不会创建分配数据的副本。相反，它只是创建一个指向相同数据的新指针。

#### 注意

关系运算符仅适用于相同大小的`std::array`。这是因为数组的大小是数据类型本身的一部分，它不允许比较两种不同数据类型的值。

在下面的示例中，我们将看到如何包装由用户定义大小的 C 风格数组。

### 练习 1：实现动态大小数组

让我们编写一个小型应用程序来管理学校中学生的记录。班级中的学生数量和他们的详细信息将作为输入给出。编写一个类似数组的容器来管理数据，该容器还可以支持动态大小。我们还将实现一些实用函数来合并不同的班级。

执行以下步骤以完成练习：

1.  首先，包括所需的头文件：

```cpp
#include <iostream>
#include <sstream>
#include <algorithm>
```

1.  现在，让我们编写一个名为`dynamic_array`的基本模板结构，以及主要数据成员：

```cpp
template <typename T>
class dynamic_array
{
    T* data;
    size_t n;
```

1.  现在，让我们添加一个接受数组大小并复制它的构造函数：

```cpp
public:
dynamic_array(int n)
{
    this->n = n;
    data = new T[n];
}
    dynamic_array(const dynamic_array<T>& other)
  {
    n = other.n;
    data = new T[n];
    for(int i = 0; i < n; i++)
    data[i] = other[i];
  }
```

1.  现在，让我们在`public`访问器中添加`operator[]`和`function()`来支持直接访问数据，类似于`std::array`：

```cpp
T& operator[](int index)
{
    return data[index];
}
const T& operator[](int index) const
{
    return data[index];
}
T& at(int index)
{
    if(index < n)
    return data[index];
    throw "Index out of range";
}
```

1.  现在，让我们添加一个名为`size()`的函数来返回数组的大小，以及一个析构函数来避免内存泄漏：

```cpp
size_t size() const
{
    return n;
}
~dynamic_array()
{
    delete[] data;   // A destructor to prevent memory leak
}
```

1.  现在，让我们添加迭代器函数来支持基于范围的循环，以便遍历`dynamic_array`：

```cpp
T* begin()
{
    return data;
}
const T* begin() const
{
    return data;
}
T* end()
{
    return data + n;
}
const T* end() const
{
    return data + n;
}
```

1.  现在，让我们添加一个函数，使用`+`运算符将一个数组追加到另一个数组中。让我们将其保持为`friend`函数以提高可用性：

```cpp
friend dynamic_array<T> operator+(const dynamic_array<T>& arr1, dynamic_array<T>& arr2)
{
    dynamic_array<T> result(arr1.size() + arr2.size());
    std::copy(arr1.begin(), arr1.end(), result.begin());
    std::copy(arr2.begin(), arr2.end(), result.begin() + arr1.size());
    return result;
}
```

1.  现在，让我们添加一个名为`to_string`的函数，它接受一个分隔符作为参数，默认值为“`,`”：

```cpp
std::string to_string(const std::string& sep = ", ")
{
  if(n == 0)
    return "";
  std::ostringstream os;
  os << data[0];
  for(int i = 1; i < n; i++)
    os << sep << data[i];
  return os.str();
}
};
```

1.  现在，让我们为学生添加一个`struct`。我们将只保留姓名和标准（即学生所在的年级/班级）以简化，并添加`operator<<`以正确打印它：

```cpp
struct student
{
    std::string name;
    int standard;
};
std::ostream& operator<<(std::ostream& os, const student& s)
{
    return (os << "[Name: " << s.name << ", Standard: " << s.standard << "]");
}
```

1.  现在，让我们添加一个`main`函数来使用这个数组：

```cpp
int main()
{
    int nStudents;
    std::cout << "Enter number of students in class 1: ";
    std::cin >> nStudents;
dynamic_array<student> class1(nStudents);
for(int i = 0; i < nStudents; i++)
{
    std::cout << "Enter name and class of student " << i + 1 << ": ";
    std::string name;
    int standard;
    std::cin >> name >> standard;
    class1[i] = student{name, standard};
}
// Now, let's try to access the student out of range in the array
try
{
    class1[nStudents] = student{"John", 8};  // No exception, undefined behavior
    std::cout << "class1 student set out of range without exception" << std::endl;
    class1.at(nStudents) = student{"John", 8};  // Will throw exception
}
catch(...)
{
std::cout << "Exception caught" << std::endl;
}
auto class2 = class1;  // Deep copy
    std::cout << "Second class after initialized using first array: " << class2.to_string() << std::endl;
    auto class3 = class1 + class2;
    // Combines both classes and creates a bigger one
    std::cout << "Combined class: ";
    std::cout << class3.to_string() << std::endl;
    return 0;
}
```

1.  使用三个学生`Raj(8)`，`Rahul(10)`，和`Viraj(6)`作为输入执行上述代码。在控制台中输出如下：

```cpp
Enter number of students in class 1 : 3
Enter name and class of student 1: Raj 8
Enter name and class of student 2: Rahul 10
Enter name and class of student 3: Viraj 6
class1 student set out of range without exception
Exception caught
Second class after initialized using first array : [Name: Raj, Standard: 8], [Name: Rahul, Standard: 10], [Name: Viraj, Standard: 6]
Combined class : [Name: Raj, Standard: 8], [Name: Rahul, Standard: 10], [Name: Viraj, Standard: 6], [Name: Raj, Standard: 8], [Name: Rahul, Standard: 10], [Name: Viraj, Standard: 6]
```

这里提到的大多数函数都有类似于`std::array`的实现。

现在我们已经看到了各种容器，接下来我们将学习如何实现一个容器，它可以接受任何类型的数据并以通用形式存储在下一个练习中。

### 练习 2：通用且快速的数据存储容器构建器

在这个练习中，我们将编写一个函数，该函数接受任意数量的任意类型的元素，这些元素可以转换为一个通用类型。该函数还应返回一个包含所有元素转换为该通用类型的容器，并且遍历速度应该很快：

1.  让我们首先包括所需的库：

```cpp
#include <iostream>
#include <array>
#include <type_traits>
```

1.  首先，我们将尝试构建函数的签名。由于返回类型是一个快速遍历的容器，我们将使用`std::array`。为了允许任意数量的参数，我们将使用可变模板：

```cpp
template<typename ... Args>
std::array<?,?> build_array(Args&&... args)
```

考虑到返回类型的容器应该是快速遍历的要求，我们可以选择数组或向量。由于元素的数量在编译时基于函数的参数数量是已知的，我们可以继续使用`std::array`。

1.  现在，我们必须为`std::array`提供元素的类型和元素的数量。我们可以使用`std::common_type`模板来找出`std::array`内部元素的类型。由于这取决于参数，我们将函数的返回类型作为尾随类型提供：

```cpp
template<typename ... Args>
auto build_array(Args&&... args) -> std::array<typename std::common_type<Args...>::type, ?>
{
    using commonType = typename std::common_type<Args...>::type;
    // Create array
}
```

1.  如前面的代码所示，我们现在需要弄清楚两件事——元素的数量，以及如何使用`commonType`创建数组：

```cpp
template< typename ... Args>
auto build_array(Args&&... args) -> std::array<typename std::common_type<Args...>::type, sizeof...(args)>
{
    using commonType = typename std::common_type<Args...>::type;
    return {std::forward<commonType>(args)...};
}
```

1.  现在，让我们编写`main`函数来看看我们的函数如何工作：

```cpp
int main()
{
    auto data = build_array(1, 0u, 'a', 3.2f, false);
    for(auto i: data)
        std::cout << i << " ";
    std::cout << std::endl;
}
```

1.  运行代码应该得到以下输出：

```cpp
1 0 97 3.2 0
```

正如我们所看到的，所有最终输出都是浮点数形式，因为一切都可以转换为浮点数。

1.  为了进一步测试，我们可以在`main`函数中添加以下内容并测试输出：

```cpp
auto data2 = build_array(1, "Packt", 2.0);
```

通过这种修改，我们应该会得到一个错误，说所有类型都无法转换为通用类型。确切的错误消息应该提到模板推导失败。这是因为没有单一类型可以将字符串和数字都转换为。

构建器函数，比如我们在这个练习中创建的函数，可以在你不确定数据类型但需要优化效率时使用。

`std::array`没有提供许多有用的功能和实用函数。其中一个主要原因是为了保持与 C 风格数组相比类似或更好的性能和内存需求。

对于更高级的功能和灵活性，C++提供了另一个称为`std::vector`的结构。我们将在下一节中看看它是如何工作的。

## std::vector

正如我们之前看到的，`std::array`相对于 C 风格数组是一个真正的改进。但是`std::array`也有一些局限性，在某些常见的应用程序编写用例中缺乏函数。以下是`std::array`的一些主要缺点：

+   `std::array`的大小必须是常量且在编译时提供，并且是固定的。因此，我们无法在运行时更改它。

+   由于大小限制，我们无法向数组中插入或删除元素。

+   `std::array`不允许自定义分配。它总是使用堆栈内存。

在大多数现实生活应用中，数据是非常动态的，而不是固定大小的。例如，在我们之前的医院管理系统示例中，我们可能会有更多的医生加入医院，我们可能会有更多的急诊病人等。因此，提前知道数据的大小并不总是可能的。因此，`std::array`并不总是最佳选择，我们需要一些具有动态大小的东西。

现在，我们将看一下`std::vector`如何解决这些问题。

### std::vector - 变长数组

正如标题所示，`std::vector`解决了数组的一个最突出的问题 - 固定大小。在初始化时，`std::vector`不需要我们提供其长度。

以下是一些初始化向量的方法：

```cpp
std::vector<int> vec;
// Declares vector of size 0
std::vector<int> vec = {1, 2, 3, 4, 5};
// Declares vector of size 5 with provided elements
std::vector<int> vec(10);
// Declares vector of size 10
std::vector<int> vec(10, 5);
// Declares vector of size 10 with each element's value = 5
```

正如我们从第一个初始化中看到的，提供大小并不是强制的。如果我们没有明确指定大小，并且没有通过指定元素来推断大小，向量将根据编译器的实现初始化元素的容量。术语“大小”指的是向量中实际存在的元素数量，这可能与其容量不同。因此，对于第一次初始化，大小将为零，但容量可能是一些小数字或零。

我们可以使用`push_back`或`insert`函数在向量中插入元素。`push_back`会在末尾插入元素。`insert`以迭代器作为第一个参数表示位置，可以用来在任何位置插入元素。`push_back`是向量中非常常用的函数，因为它的性能很好。`push_back`的伪代码如下：

```cpp
push_back(val):
    if size < capacity
    // If vector has enough space to accommodate this element
    - Set element after the current last element = val
    - Increment size
    - return; 
    if vector is already full
    - Allocate memory of size 2*size
    - Copy/Move elements to newly allocated memory
    - Make original data point to new memory
    - Insert the element at the end
```

实际的实现可能会有所不同，但逻辑是相同的。正如我们所看到的，如果有足够的空间，向后插入元素只需要*O(1)*的时间。但是，如果没有足够的空间，它将不得不复制/移动所有元素，这将需要*O(n)*的时间。大多数实现在容量不足时会将向量的大小加倍。因此，*O(n)*的时间操作是在 n 个元素之后进行的。因此，平均而言，它只需要额外的一步，使其平均时间复杂度更接近*O(1)*。实际上，这提供了相当不错的性能，因此它是一个被广泛使用的容器。

对于`insert`函数，除了将给定迭代器后面的元素向右移动之外，没有其他选项。`insert`函数会为我们完成这些操作。它还会在需要时进行重新分配。由于需要移动元素，它的时间复杂度为*O(n)*。以下示例演示了如何实现向量插入函数。

考虑一个包含前五个自然数的向量：

```cpp
std::vector<int> vec = {1, 2, 3, 4, 5};
```

#### 注意

向量没有`push_front`函数。它有通用的`insert`函数，它以迭代器作为参数表示位置。

通用的`insert`函数可以用来在前面插入元素，如下所示：

```cpp
vec.insert(int.begin(), 0);
```

让我们看一些`push_back`和`insert`函数的更多示例：

```cpp
std::vector<int> vec;
// Empty vector {}
vec.push_back(1);
// Vector has one element {1}
vec.push_back(2);
// Vector has 2 elements {1, 2}
vec.insert(vec.begin(), 0);
// Vector has 3 elements {0, 1, 2}
vec.insert(find(vec.begin(), vec.end(), 1), 4);
// Vector has 4 elements {0, 4, 1, 2}
```

如前面的代码所示，`push_back`在末尾插入元素。此外，`insert`函数以插入位置作为参数。它以迭代器的形式接受。因此，`begin()`函数允许我们在开头插入元素。

现在我们已经了解了常规插入函数，让我们来看一些更好的替代方案，与`push_back`和`insert`函数相比，这些替代方案对于向量来说更好。`push_back`和`insert`的一个缺点是它们首先构造元素，然后将元素复制或移动到向量缓冲区内的新位置。这个操作可以通过在新位置本身调用构造函数来优化，这可以通过`emplace_back`和`emplace`函数来实现。建议您使用这些函数而不是普通的插入函数以获得更好的性能。由于我们是就地构造元素，我们只需要传递构造函数参数，而不是构造的值本身。然后，函数将负责将参数转发到适当位置的构造函数。

`std::vector`还提供了`pop_back`和`erase`函数来从中删除元素。`pop_back`从向量中删除最后一个元素，有效地减小了大小。`erase`有两种重载方式 - 通过指向单个元素的迭代器来删除该元素，以及通过迭代器提供的元素范围来删除元素，其中范围由定义要删除的第一个元素（包括）和要删除的最后一个元素（不包括）来定义。C++标准不要求这些函数减少向量的容量。这完全取决于编译器的实现。`pop_back`不需要对元素进行重新排列，因此可以非常快速地完成。它的复杂度是*O(1)*。然而，`erase`需要对元素进行移动，因此需要*O(n)*的时间。在接下来的练习中，我们将看到这些函数是如何实现的。

现在，让我们看一个关于不同方式从向量中删除元素的示例：

考虑一个有 10 个元素的向量 - `{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}`:

```cpp
vec.pop_back();
// Vector has now 9 elements {0, 1, 2, 3, 4, 5, 6, 7, 8}
vec.erase(vec.begin());
// vector has now 7 elements {1, 2, 3, 4, 5, 6, 7, 8}
vec.erase(vec.begin() + 1, vec.begin() + 4);
// Now, vector has 4 elements {1, 5, 6, 7, 8}
```

现在，让我们来看一些其他有用的函数：

+   `clear()`: 这个函数通过删除所有元素来简单地清空向量。

+   `reserve(capacity)`: 这个函数用于指定向量的容量。如果指定的参数值大于当前容量，它将重新分配内存，新的容量将等于参数。然而，对于所有其他情况，它不会影响向量的容量。这个函数不会修改向量的大小。

+   `shrink_to_fit()`: 这个函数可以用来释放额外的空间。调用这个函数后，大小和容量变得相等。当我们不希望向量的大小进一步增加时，可以使用这个函数。

### std::vector 的分配器

`std::vector`通过允许我们在数据类型之后将分配器作为模板参数传递来解决了`std::array`关于自定义分配器的缺点。

为了使用自定义分配器，我们遵循一些概念和接口。由于向量使用分配器函数来处理与内存访问相关的大部分行为，我们需要将这些函数作为分配器的一部分提供 - `allocate`、`deallocate`、`construct`和`destroy`。这个分配器将负责内存分配、释放和处理，以免损坏任何数据。对于高级应用程序，其中依赖自动内存管理机制可能太昂贵，而应用程序拥有自己的内存池或类似资源必须使用而不是默认的堆内存时，自定义分配器非常方便。

因此，`std::vector`是`std::array`的一个非常好的替代品，并在大小、增长和其他方面提供了更多的灵活性。从渐近的角度来看，数组的所有类似函数的时间复杂度与向量相同。我们通常只为额外的功能付出额外的性能成本，这是相当合理的。在平均情况下，向量的性能与数组的性能相差不大。因此，在实践中，由于其灵活性和性能，`std::vector`是 C++中最常用的 STL 容器之一。

## std::forward_list

到目前为止，我们只看到了类似数组的结构，但是，正如我们所看到的，对于连续数据结构来说，在数据结构的中间进行插入和删除是非常低效的操作。这就是链表结构的作用所在。许多应用程序需要在数据结构的中间频繁进行插入和删除。例如，任何具有多个选项卡的浏览器都可以在任何时间点和任何位置添加额外的选项卡。同样，任何音乐播放器都会有一个可以循环播放的歌曲列表，并且您还可以在其中插入任何歌曲。在这种情况下，我们可以使用链表结构来获得良好的性能。我们将在*Activity 1*中看到音乐播放器的用例，*实现歌曲播放列表*。现在，让我们探索 C++为我们提供了哪些类型的容器。

链表的基本结构要求我们使用指针，并手动使用`new`和`delete`运算符来管理内存分配和释放。虽然这并不困难，但可能会导致难以追踪的错误。因此，就像`std::array`提供了对 C 风格数组的薄包装一样，`std::forward_list`提供了对基本链表的薄包装。

`std::forward_list`的目的是在不影响性能的情况下提供一些额外的功能，与基本链表相比。为了保持性能，它不提供获取列表大小或直接获取除第一个元素之外的任何元素的函数。因此，它有一个名为`front()`的函数，用于获取对第一个元素的引用，但没有像`back()`那样访问最后一个元素的函数。它确实提供了常见操作的函数，如插入、删除、反转和拼接。这些函数不会影响基本链表的内存需求或性能。

此外，就像`std::vector`一样，如果需要，`std::forward_list`也可以接受自定义分配器作为第二个模板参数。因此，我们可以轻松地将其用于受益于自定义内存管理的高级应用程序。

### 在`forward_list`中插入和删除元素

`std::forward_list`提供了`push_front`和`insert_after`函数，可用于在链表中插入元素。这两个函数与向量的插入函数略有不同。`push_front`用于在前面插入元素。由于`forward_list`无法直接访问最后一个元素，因此它不提供`push_back`函数。对于特定位置的插入，我们使用`insert_after`而不是`insert`。这是因为在链表中插入元素需要更新元素的下一个指针，然后我们想要插入一个新元素。如果我们只提供要插入新元素的迭代器，我们无法快速访问前一个元素，因为在`forward_list`中不允许向后遍历。

由于这是基于指针的机制，因此在插入期间我们实际上不需要移动元素。因此，这两个插入函数与任何基于数组的结构相比要快得多。这两个函数只是修改指针以在预期位置插入新元素。这个操作不依赖于列表的大小，因此时间复杂度为*O(1)*。我们将在接下来的练习中看一下这些函数的实现。

现在，让我们看看如何在链表中插入元素：

```cpp
std::forward_list<int> fwd_list = {1, 2, 3};
fwd_list.push_front(0);
// list becomes {0, 1, 2, 3}
auto it = fwd_list.begin();
fwd_list.insert_after(it, 5);
// list becomes {0, 5, 1, 2, 3}
fwd_list.insert_after(it, 6);
// list becomes {0, 6, 5, 1, 2, 3}
```

`forward_list`还提供了`emplace_front`和`emplace_after`，类似于向量的`emplace`。这两个函数都与插入函数做相同的事情，但通过避免额外的复制和移动来更有效地执行。

`forward_list`还具有`pop_front`和`erase_after`函数用于删除元素。`pop_front`如其名称所示，删除第一个元素。由于不需要任何移动，实际上操作非常快，时间复杂度为*O(1)*。`erase_after`有两个重载 - 通过取其前一个元素的迭代器来删除单个元素，以及通过取范围的第一个元素之前的迭代器和最后一个元素的另一个迭代器来删除多个元素。

`erase_after`函数的时间复杂度与被删除的元素数量成正比，因为无法通过释放单个内存块来删除元素。由于所有节点都分散在内存中的随机位置，函数需要分别释放每个节点。

现在，让我们看看如何从列表中删除元素：

```cpp
std::forward_list<int> fwd_list = {1, 2, 3, 4, 5};
fwd_list.pop_front();
// list becomes {2, 3, 4, 5}
auto it = fwd_list.begin();
fwd_list.erase_after(it);
// list becomes {2, 4, 5}
fwd_list.erase_after(it, fwd_list.end());
// list becomes {2}
```

让我们在下一节中探讨`forward_list`可以进行的其他操作。

### forward_list 上的其他操作

除了根据迭代器确定位置来删除元素的`erase`函数外，`forward_list`还提供了`remove`和`remove_if`函数来根据其值删除元素。`remove`函数接受一个参数 - 要删除的元素的值。它会删除所有与给定元素匹配的元素，基于该值类型定义的相等运算符。如果没有相等运算符，编译器将不允许我们调用该函数，并抛出编译错误。由于`remove`仅根据相等运算符删除元素，因此无法根据其他条件使用它进行删除，因为我们无法在定义一次后更改相等运算符。对于条件删除，`forward_list`提供了`remove_if`函数。它接受一个谓词作为参数，该谓词是一个接受值类型元素作为参数并返回布尔值的函数。因此，谓词返回 true 的所有元素都将从列表中删除。使用最新的 C++版本，我们也可以使用 lambda 轻松指定谓词。以下练习应该帮助你了解如何实现这些函数。

### 练习 3：使用 remove_if 条件删除链表中的元素

在这个练习中，我们将使用印度选民的样本信息，并根据他们的年龄从选民名单中删除不合格的公民。为简单起见，我们只存储公民的姓名和年龄。

我们将在链表中存储数据，并使用`remove_if`删除所需的元素，该函数提供了一种删除满足特定条件的元素的方法，而不是定义要删除的元素的位置：

1.  让我们首先包含所需的头文件并添加`struct citizen`：

```cpp
#include <iostream>
#include <forward_list>
struct citizen
{
    std::string name;
    int age;
};
std::ostream& operator<<(std::ostream& os, const citizen& c)
{
    return (os << "[Name: " << c.name << ", Age: " << c.age << "]");
}
```

1.  现在，让我们编写一个`main`函数，并在`std::forward_list`中初始化一些公民。我们还将对其进行复制，以避免再次初始化：

```cpp
int main()
{
  std::forward_list<citizen> citizens = {{"Raj", 22}, {"Rohit", 25}, {"Rohan", 17}, {"Sachin", 16}};
  auto citizens_copy = citizens;
  std::cout << "All the citizens: ";
  for (const auto &c : citizens)
      std::cout << c << " ";
  std::cout << std::endl;
```

1.  现在，让我们从列表中删除所有不合格的公民：

```cpp
citizens.remove_if(
    [](const citizen& c)
    {
        return (c.age < 18);
    });
std::cout << "Eligible citizens for voting: ";
for(const auto& c: citizens)
    std::cout << c << " ";
std::cout << std::endl;
```

`remove_if`函数会删除所有满足给定条件的元素。在这里，我们提供了一个 lambda，因为条件非常简单。如果条件很复杂，我们也可以编写一个接受链表底层类型的参数并返回布尔值的普通函数。

1.  现在，让我们找出明年有资格投票的人：

```cpp
citizens_copy.remove_if(
    [](const citizen& c)
    {
    // Returns true if age is less than 18
        return (c.age != 17);
    });
std::cout << "Citizens that will be eligible for voting next year: ";
for(const auto& c: citizens_copy)
    std::cout << c << " ";
std::cout << std::endl;
}
```

正如你所看到的，我们只保留那些年龄为 17 岁的公民。

1.  运行练习。你应该会得到这样的输出：

```cpp
All the citizens: [Name: Raj, Age: 22] [Name: Rohit, Age: 25] [Name: Rohan, Age: 17] [Name: Sachin, Age: 16] 
Eligible citizens for voting: [Name: Raj, Age: 22] [Name: Rohit, Age: 25] 
Citizens that will be eligible for voting next year: [Name: Rohan, Age: 17] 
```

`remove_if`函数的时间复杂度为*O(n)*，因为它只需遍历列表一次，同时根据需要删除所有元素。如果我们想要删除具有特定值的元素，我们可以使用`remove`的另一个版本，它只需要一个对象的参数，并删除列表中与给定值匹配的所有对象。它还要求我们为给定类型实现`==`运算符。

`forward_list`还提供了一个`sort`函数来对数据进行排序。所有与数组相关的结构都可以通过通用函数`std::sort(first iterator, last iterator)`进行排序。然而，它不能被链表结构使用，因为我们无法随机访问任何数据。这也使得`forward_list`提供的迭代器与数组或向量的迭代器不同。我们将在下一节中更详细地看一下这一点。`forward_list`提供的`sort`函数有两个重载版本 - 基于小于运算符（`<`）的`sort`，以及基于作为参数提供的比较器的`sort`。默认的`sort`函数使用`std::less<value_type>`进行比较。如果第一个参数小于第二个参数，则简单地返回`true`，因此，需要我们为自定义类型定义小于运算符（`<`）。

此外，如果我们想要基于其他参数进行比较，我们可以使用参数化重载，它接受一个二元谓词。这两个重载的时间复杂度都是线性对数级的 - *O(n × log n)*。以下示例演示了`sort`的两个重载：

```cpp
std::forward_list<int> list1 = {23, 0, 1, -3, 34, 32};
list1.sort();
// list becomes {-3, 0, 1, 23, 32, 34}
list1.sort(std::greater<int>());
// list becomes {34, 32, 23, 1, 0, -3}
```

在这里，`greater<int>`是标准库中提供的一个谓词，它是对大于运算符（`>`）的包装器，用于将元素按降序排序，正如我们从列表的值中所看到的。

`forward_list`中提供的其他函数包括`reverse`和`unique`。`reverse`函数简单地颠倒元素的顺序，其时间复杂度与列表中元素的数量成正比，即时间复杂度为*O(n)*。`unique`函数仅保留列表中的唯一元素，并删除除第一个元素外的所有重复值函数。由于它依赖于元素的相等性，它有两个重载版本 - 第一个不带参数，使用值类型的相等运算符，而第二个带有两个值类型参数的二元谓词。`unique`函数的时间复杂度是线性的。因此，它不会将每个元素与其他每个元素进行比较。相反，它只会比较连续的元素是否相等，并根据默认或自定义的二元谓词删除后一个元素。因此，要使用`unique`函数从列表中删除所有唯一元素，我们需要在调用函数之前对元素进行排序。借助给定的谓词，`unique`将比较所有元素与其相邻元素，并在谓词返回`true`时删除后一个元素。

现在让我们看看如何使用`reverse`、`sort`和`unique`函数来操作列表：

```cpp
std::forward_list<int> list1 = {2, 53, 1, 0, 4, 10};
list1.reverse();
// list becomes {2, 53, 1, 0, 4, 10}
list1 = {0, 1, 0, 1, -1, 10, 5, 10, 5, 0};
list1.sort();
// list becomes {-1, 0, 0, 0, 1, 1, 5, 5, 10, 10}
list1.unique();
// list becomes {-1, 0, 1, 5, 10}
list1 = {0, 1, 0, 1, -1, 10, 5, 10, 5, 0};
list1.sort();
// list becomes {-1, 0, 0, 0, 1, 1, 5, 5, 10, 10}
```

以下示例将删除元素，如果它们与之前的有效元素相比至少相差 2：

```cpp
list1.unique([](int a, int b) { return (b - a) < 2; });
// list becomes {-1, 1, 5, 10}
```

#### 注意

在调用`unique`函数之前，程序员必须确保数据已经排序。因此，在调用`unique`函数之前，我们会先调用`sort`函数。`unique`函数将元素与已满足条件的前一个元素进行比较。此外，它始终保留原始列表的第一个元素。因此，总是有一个元素可以进行比较。

在下一节中，我们将看一看`forward_list`迭代器与向量/数组迭代器的不同之处。

## 迭代器

正如您可能已经注意到的，在一些数组和向量的例子中，我们向迭代器添加数字。迭代器类似于指针，但它们还为 STL 容器提供了一个公共接口。这些迭代器上的操作严格基于迭代器的类型，这取决于容器。对于向量和数组的迭代器在功能上是最灵活的。我们可以根据位置直接访问容器中的任何元素，使用`operator[]`，因为数据的连续性。这个迭代器也被称为随机访问迭代器。然而，对于`forward_list`，没有直接的方法可以向后遍历，甚至从一个节点到其前一个节点，而不是从头开始。因此，这个迭代器允许的唯一算术运算符是增量。这个迭代器也被称为前向迭代器。

还有其他实用函数可以使用，比如`advance`、`next`和`prev`，取决于迭代器的类型。`next`和`prev`接受一个迭代器和一个距离值，然后返回指向距离给定迭代器给定距离的元素的迭代器。这在给定迭代器支持该操作的情况下可以正常工作。例如，如果我们尝试使用`prev`函数与`forward`迭代器，它将抛出编译错误，因为这个迭代器是一个前向迭代器，只能向前移动。这些函数所花费的时间取决于所使用的迭代器的类型。对于随机访问迭代器，所有这些都是常数时间函数，因为加法和减法都是常数时间操作。对于其余的迭代器，所有这些都是线性的，需要向前或向后遍历的距离。我们将在接下来的练习中使用这些迭代器。

### 练习 4：探索不同类型的迭代器

让我们假设我们有一份新加坡 F1 大奖赛近年来的获奖者名单。借助向量迭代器的帮助，我们将发现如何从这些数据中检索有用的信息。之后，我们将尝试使用`forward_list`做同样的事情，并看看它与向量迭代器有何不同：

1.  让我们首先包含头文件：

```cpp
#include <iostream>
#include <forward_list>
#include <vector>
int main()
{
```

1.  让我们写一个包含获奖者名单的向量：

```cpp
std::vector<std::string> vec = {"Lewis Hamilton", "Lewis Hamilton", "Nico Roseberg", "Sebastian Vettel", "Lewis Hamilton", "Sebastian Vettel", "Sebastian Vettel", "Sebastian Vettel", "Fernando Alonso"};
auto it = vec.begin();       // Constant time
std::cout << "Latest winner is: " << *it << std::endl;
it += 8;                    // Constant time
std::cout << "Winner before 8 years was: " << *it << std::endl;
advance(it, -3);            // Constant time
std::cout << "Winner before 3 years of that was: " << *it << std::endl;
```

1.  让我们尝试使用`forward_list`迭代器做同样的事情，并看看它们与向量迭代器有何不同：

```cpp
std::forward_list<std::string> fwd(vec.begin(), vec.end());
auto it1 = fwd.begin();
std::cout << "Latest winner is: " << *it << std::endl;
advance(it1, 5);   // Time taken is proportional to the number of elements
std::cout << "Winner before 5 years was: " << *it << std::endl;
// Going back will result in compile time error as forward_list only allows us to move towards the end.
// advance(it1, -2);      // Compiler error
}
```

1.  运行这个练习应该产生以下输出：

```cpp
Latest winner is : Lewis Hamilton
Winner before 8 years was : Fernando Alonso
Winner before 3 years of that was : Sebastian Vettel
Latest winner is : Sebastian Vettel
Winner before 5 years was : Sebastian Vettel
```

1.  现在，让我们看看如果我们在`main`函数的末尾放入以下行会发生什么：

```cpp
it1 += 2;
```

我们将得到类似于这样的错误消息：

```cpp
no match for 'operator+=' (operand types are std::_Fwd_list_iterator<int>' and 'int')
```

我们在这个练习中探索的各种迭代器对于轻松获取数据集中的任何数据非常有用。

正如我们所见，`std::array`是 C 风格数组的一个薄包装器，`std::forward_list`只是一个薄包装器，它提供了一个简单且不易出错的接口，而不会影响性能或内存。

除此之外，由于我们可以立即访问向量中的任何元素，因此向量迭代器的加法和减法操作为*O(1)*。另一方面，`forward_list`只支持通过遍历访问元素。因此，它的迭代器的加法操作为*O(n)*，其中 n 是我们正在前进的步数。

在接下来的练习中，我们将制作一个自定义容器，其工作方式类似于`std::forward_list`，但具有一些改进。我们将定义许多等效于`forward_list`函数的函数。这也应该帮助您了解这些函数在底层是如何工作的。

### 练习 5：构建基本自定义容器

在这个练习中，我们将实现一个带有一些改进的`std::forward_list`等效容器。我们将从一个名为`singly_ll`的基本实现开始，并逐渐不断改进：

1.  让我们添加所需的头文件，然后从一个单节点开始基本实现`singly_ll`：

```cpp
#include <iostream>
#include <algorithm>
struct singly_ll_node
{
    int data;
    singly_ll_node* next;
};
```

1.  现在，我们将实现实际的`singly_ll`类，它将节点包装起来以便更好地进行接口设计。

```cpp
class singly_ll
{
public:
    using node = singly_ll_node;
    using node_ptr = node*;
private:
    node_ptr head;
```

1.  现在，让我们添加`push_front`和`pop_front`，就像在`forward_list`中一样：

```cpp
public:
void push_front(int val)
{
    auto new_node = new node{val, NULL};
    if(head != NULL)
        new_node->next = head;
    head = new_node;
}
void pop_front()
{
    auto first = head;
    if(head)
    {
        head = head->next;
        delete first;
    }
    else
        throw "Empty ";
}
```

1.  现在让我们为我们的`singly_ll`类实现一个基本的迭代器，包括构造函数和访问器：

```cpp
struct singly_ll_iterator
{
private:
    node_ptr ptr;
public:
    singly_ll_iterator(node_ptr p) : ptr(p)
    {
}
int& operator*()
{
    return ptr->data;
}
node_ptr get()
{
    return ptr;
}
```

1.  让我们为前置和后置递增添加`operator++`函数：

```cpp
singly_ll_iterator& operator++()     // pre-increment
{
        ptr = ptr->next;
        return *this;
}
singly_ll_iterator operator++(int)    // post-increment
{
    singly_ll_iterator result = *this;
++(*this);
return result;
}
```

1.  让我们添加等式操作作为`friend`函数：

```cpp
    friend bool operator==(const singly_ll_iterator& left, const singly_ll_iterator& right)
    {
        return left.ptr == right.ptr;
    }
    friend bool operator!=(const singly_ll_iterator& left, const singly_ll_iterator& right)
    {
        return left.ptr != right.ptr;
    }
};
```

1.  让我们回到我们的链表类。现在我们已经有了迭代器类，让我们实现`begin`和`end`函数来方便遍历。我们还将为两者添加`const`版本：

```cpp
singly_ll_iterator begin()
{
    return singly_ll_iterator(head);
}
singly_ll_iterator end()
{
    return singly_ll_iterator(NULL);
}
singly_ll_iterator begin() const
{
    return singly_ll_iterator(head);
}
singly_ll_iterator end() const
{
    return singly_ll_iterator(NULL);
}
```

1.  让我们实现一个默认构造函数，一个用于深度复制的复制构造函数，以及一个带有`initializer_list`的构造函数：

```cpp
singly_ll() = default;
singly_ll(const singly_ll& other) : head(NULL)
{
    if(other.head)
        {
            head = new node;
            auto cur = head;
            auto it = other.begin();
            while(true)
            {
                cur->data = *it;
                auto tmp = it;
                ++tmp;
                if(tmp == other.end())
                    break;
                cur->next = new node;
                cur = cur->next;
                it = tmp;
            }
        }
}
singly_ll(const std::initializer_list<int>& ilist) : head(NULL)
{
    for(auto it = std::rbegin(ilist); it != std::rend(ilist); it++)
            push_front(*it);
}
};
```

1.  让我们编写一个`main`函数来使用前面的函数：

```cpp
int main()
{
    singly_ll sll = {1, 2, 3};
    sll.push_front(0);
    std::cout << "First list: ";
    for(auto i: sll)
        std::cout << i << " ";
    std::cout << std::endl;

    auto sll2 = sll;
    sll2.push_front(-1);
    std::cout << "Second list after copying from first list and inserting -1 in front: ";
    for(auto i: sll2)
        std::cout << i << ' ';  // Prints -1 0 1 2 3
    std::cout << std::endl;
    std::cout << "First list after copying - deep copy: ";
for(auto i: sll)
        std::cout << i << ' ';  // Prints 0 1 2 3
    std::cout << std::endl;
}
```

1.  运行这个练习应该产生以下输出：

```cpp
First list: 0 1 2 3
Second list after copying from first list and inserting -1 in front: -1 0 1 2 3 
First list after copying - deep copy: 0 1 2 3
```

正如我们在前面的例子中看到的，我们能够使用`std::initializer_list`初始化我们的列表。我们可以调用`push`、`pop_front`和`back`函数。正如我们所看到的，`sll2.pop_back`只从`sll2`中删除了元素，而不是`sll`。`sll`仍然保持完整，有五个元素。因此，我们也可以执行深度复制。

### 活动 1：实现歌曲播放列表

在这个活动中，我们将看一些双向链表不足或不方便的应用。我们将构建一个适合应用的调整版本。我们经常遇到需要自定义默认实现的情况，比如在音乐播放器中循环播放歌曲或者在游戏中多个玩家依次在圈内轮流。

这些应用有一个共同的特点——我们以循环方式遍历序列的元素。因此，在遍历列表时，最后一个节点之后的节点将是第一个节点。这就是所谓的循环链表。

我们将以音乐播放器的用例为例。它应该支持以下功能：

1.  使用多首歌曲创建一个播放列表。

1.  向播放列表添加歌曲。

1.  从播放列表中删除一首歌曲。

1.  循环播放歌曲（对于这个活动，我们将打印所有歌曲一次）。

#### 注意

您可以参考*练习 5*，*构建基本自定义容器*，我们在那里从头开始构建了一个支持类似功能的容器。

解决问题的步骤如下：

1.  首先，设计一个支持循环数据表示的基本结构。

1.  之后，在结构中实现`insert`和`erase`函数，以支持各种操作。

1.  我们必须编写一个自定义迭代器。这有点棘手。重要的是要确保我们能够使用基于范围的方法来遍历容器。因此，`begin()`和`end()`应该返回不同的地址，尽管结构是循环的。

1.  构建容器后，再构建一个包装器，它将在播放列表中存储不同的歌曲并执行相关操作，比如`next`、`previous`、`print all`、`insert`和`remove`。

#### 注意

这个活动的解决方案可以在第 476 页找到。

`std::forward_list`有一些限制。`std::list`提供了更灵活的列表实现，并帮助克服了`forward_list`的一些缺点。

## std::list

正如前面的部分所示，`std::forward_list`只是一个基本链表的简单包装。它不提供在末尾插入元素、向后遍历或获取列表大小等有用操作。功能受限是为了节省内存并保持快速性能。除此之外，`forward_list`的迭代器只支持很少的操作。在任何应用的实际情况中，像在容器末尾插入东西和获取容器大小这样的函数是非常有用且经常使用的。因此，当需要快速插入时，`std::forward_list`并不总是理想的容器。为了克服`std::forward_list`的这些限制，C++提供了`std::list`，它由于是双向链表，也被称为双向链表，因此具有几个额外的特性。但是，请注意，这是以额外的内存需求为代价的。

双向链表的普通版本看起来像这样：

```cpp
struct doubly_linked_list
{
    int data;
    doubly_linked_list *next, *prev;
};
```

正如你所看到的，它有一个额外的指针指向前一个元素。因此，它为我们提供了一种向后遍历的方式，我们还可以存储大小和最后一个元素以支持快速的`push_back`和`size`操作。而且，就像`forward_list`一样，它也可以支持客户分配器作为模板参数。

### `std::list`的常用函数

`std::list`的大多数函数要么与`std::forward_list`的函数相同，要么类似，只是有一些调整。其中一个调整是以`_after`结尾的函数有没有`_after`的等价函数。因此，`insert_after`和`emplace_after`变成了简单的`insert`和`emplace`。这是因为，使用`std::list`迭代器，我们也可以向后遍历，因此不需要提供前一个元素的迭代器。相反，我们可以提供我们想要执行操作的确切元素的迭代器。除此之外，`std::list`还提供了`push_back`、`emplace_back`和`pop_back`的快速操作。以下练习演示了`std::list`的插入和删除函数的使用。

### 练习 6：`std::list`的插入和删除函数

在这个练习中，我们将使用`std::list`创建一个简单的整数列表，并探索各种插入和删除元素的方法：

1.  首先，让我们包含所需的头文件：

```cpp
#include <iostream>
#include <list>
int main()
{
```

1.  然后，用一些元素初始化一个列表，并用各种插入函数进行实验：

```cpp
std::list<int> list1 = {1, 2, 3, 4, 5};
list1.push_back(6);
// list becomes {1, 2, 3, 4, 5, 6}
list1.insert(next(list1.begin()), 0);
// list becomes {1, 0, 2, 3, 4, 5, 6}
list1.insert(list1.end(), 7);
// list becomes {1, 0, 2, 3, 4, 5, 6, 7}
```

正如你所看到的，`push_back`函数在末尾插入一个元素。`insert`函数在第一个元素后插入`0`，这由`next(list1.begin())`表示。之后，我们在最后一个元素后插入`7`，这由`list1.end()`表示。

1.  现在，让我们来看看`pop_back`这个删除函数，它在`forward_list`中不存在：

```cpp
list1.pop_back();
// list becomes {1, 0, 2, 3, 4, 5, 6}
std::cout << "List after insertion & deletion functions: ";
for(auto i: list1)
    std::cout << i << " ";
}
```

1.  运行这个练习应该会得到以下输出：

```cpp
List after insertion & deletion functions: 1 0 2 3 4 5 6
```

在这里，我们正在删除刚刚插入的最后一个元素。

#### 注意

尽管`push_front`、`insert`、`pop_front`和`erase`的时间复杂度与`forward_list`的等价函数相同，但对于`std::list`来说，这些函数稍微昂贵一些。原因是列表中每个节点有两个指针，而不是`forward_list`中的一个。因此，我们需要维护这些指针的有效性。因此，在重新指向这些变量时，我们需要付出几乎是单向链表的两倍的努力。

之前，我们看到了单向链表的插入。现在让我们在下图中演示双向链表的指针操作是什么样子的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_01_07.jpg)

###### 图 1.7：在双向链表中插入元素

正如您所看到的，即使在`std::list`的情况下，操作的数量也是恒定的；然而，与`forward_list`相比，为了维护双向链表，我们必须修复`prev`和`next`指针，这在内存和性能方面几乎是双倍的成本。其他函数也适用类似的想法。

其他函数，如`remove`、`remove_if`、`sort`、`unique`和`reverse`，提供了与它们在`std::forward_list`中等效函数相似的功能。

### 双向迭代器

在*迭代器*部分，我们看到了基于数组的随机访问迭代器和`forward_list`的前向迭代器之间的灵活性差异。`std::list::iterator`的灵活性介于两者之间。与前向迭代器相比，它更灵活，因为它允许我们向后遍历。因此，`std::list`还支持通过暴露反向迭代器来进行反向遍历的函数，其中操作是反转的。话虽如此，它不像随机访问迭代器那样灵活。虽然我们可以向任何方向移动任意数量的步骤，但由于这些步骤必须逐个遍历元素而不是直接跳转到所需的元素，因此时间复杂度仍然是线性的，而不是常数，就像随机访问迭代器的情况一样。由于这些迭代器可以向任何方向移动，它们被称为双向迭代器。

### 不同容器的迭代器失效

到目前为止，我们已经看到迭代器为我们提供了一种统一的方式来访问、遍历、插入和删除任何容器中的元素。但是在某些情况下，迭代器在修改容器后会变为无效，因为迭代器是基于指针实现的，而指针绑定到内存地址。因此，如果由于容器的修改而改变了任何节点或元素的内存地址，迭代器就会失效，而不管如何使用它都可能导致未定义的行为。

例如，一个非常基本的例子是`vector::push_back`，它只是在末尾添加一个新元素。然而，正如我们之前所看到的，在某些情况下，它也需要将所有元素移动到一个新的缓冲区。因此，所有迭代器、指针，甚至对任何现有元素的引用都将失效。同样，如果`vector::insert`函数导致重新分配，所有元素都将需要移动。因此，所有迭代器、指针和引用都将失效。如果不是这样，该函数将使指向插入位置右侧元素的所有迭代器失效，因为这些元素在过程中将被移动。

与向量不同，基于链表的迭代器对于插入和删除操作更安全，因为元素不会被移动或移位。因此，`std::list`或`forward_list`的所有插入函数都不会影响迭代器的有效性。一个例外是与删除相关的操作会使被删除的元素的迭代器失效，这是显而易见和合理的。它不会影响其余元素的迭代器的有效性。以下示例显示了不同迭代器的失效：

```cpp
std::vector<int> vec = {1, 2, 3, 4, 5};
auto it4 = vec.begin() + 4;
// it4 now points to vec[4]
vec.insert(vec.begin() + 2, 0);
// vec becomes {1, 2, 0, 3, 4, 5}
```

`it4`现在无效，因为它位于插入位置之后。访问它将导致未定义的行为：

```cpp
std::list<int> lst = {1, 2, 3, 4, 5};
auto l_it4 = next(lst.begin(), 4);
lst.insert(next(lst.begin(), 2), 0);
// l_it4 remains valid
```

正如我们所看到的，与`std::forward_list`相比，`std::list`更加灵活。许多操作，如`size`、`push_back`和`pop_back`，都具有*O(1)*的时间复杂度。因此，与`std::forward_list`相比，`std::list`更常用。如果我们对内存和性能有非常严格的限制，并且确定不需要向后遍历，那么`forward_list`是一个更好的选择。因此，在大多数情况下，`std::list`是一个更安全的选择。

### 活动 2：模拟一场纸牌游戏

在这个活动中，我们将分析一个给定的情况，并尝试找到最适合的数据结构，以实现最佳性能。

我们将尝试模拟一场纸牌游戏。游戏中有 4 名玩家，每个玩家从 13 张随机牌开始。然后，我们将尝试从每个玩家手中随机抽取一张牌。这样，我们将有 4 张牌进行比较。之后，我们将从这 4 张牌中移除匹配的牌。剩下的牌（如果有的话）将由放出的玩家重新抽取。如果有多个匹配对，但只能移除一个，我们可以选择任意一个。如果没有匹配对，玩家可以洗牌。

现在，我们需要一遍又一遍地继续这个过程，直到其中至少有一名玩家没有牌。第一个摆脱所有牌的人赢得比赛。然后，我们将在最后打印获胜者。

执行以下步骤来解决这个活动：

1.  首先确定哪种容器最适合存储每个玩家的牌。我们应该有四个包含一组牌的容器 - 每个玩家一个。

1.  编写一个函数来初始化和洗牌。

1.  编写一个函数，将所有的牌随机分配给四名玩家。

1.  编写一个匹配函数。这个函数将从每个玩家那里抽取一张牌，并按照游戏规则进行比较。然后，它将移除必要的牌。我们必须明智地选择牌，以便更快地移除它。在决定容器时，也应考虑这个参数。

1.  现在，让我们编写一个函数，看看是否有获胜者。

1.  最后，我们将编写游戏的核心逻辑。这将简单地调用匹配函数，直到根据上一步中编写的函数找到获胜者。

#### 注意

这个活动的解决方案可以在第 482 页找到。

## std::deque - std::vector 的特殊版本

到目前为止，我们已经看到了基于数组和链表的容器。`std::deque`将它们两者结合起来，并在一定程度上结合了它们各自的优点。正如我们所见，尽管向量是一个可变长度的数组，但它的一些函数，比如`push_front`和`pop_front`，是非常昂贵的操作。`std::deque`可以帮助我们克服这一点。Deque 是双端队列的缩写。

### Deque 的结构

C++标准只定义了容器的行为，而没有实现。到目前为止，我们所见过的容器对于我们来说足够简单，可以预测它们的实现。然而，deque 比这要复杂一些。因此，我们将首先看一下它的要求，然后再尝试深入一点的实现。

C++标准保证 deque 的不同操作的时间复杂度如下：

+   * O(1) * 对于`push_front`、`pop_front`、`push_back`和`pop_back`

+   * O(1) * 对于所有元素的随机访问

+   在插入或删除中，最多 * N/2 * 步骤，其中 * N * = deque 的大小

从要求来看，我们可以说这个容器应该能够快速地向任一方向扩展，并且仍然能够提供对所有元素的随机访问。因此，这个结构必须有点像一个向量，但仍然可以从前面和后面扩展。插入和删除的要求略微暗示了我们将移动元素，因为我们只能走 * N/2 * 步。这也验证了我们之前关于行为类似于向量的假设。由于容器可以快速向任一方向扩展，我们不一定每次都要将元素向右移动。相反，我们可以将元素移向最近的端点。这将给我们一个最多 * N/2 * 步的时间复杂度，因为最近的端点不能比容器内的任何插入点更远超过 * N/2 * 个节点。

现在，让我们专注于随机访问和在前端插入。这种结构无法存储在单个内存块中。相反，我们可以有多个相同大小的内存块。通过这种方式，根据块的索引和大小（或每块元素的数量），我们可以决定我们想要哪个块的索引元素。这有助于我们在*O(1)*时间内实现随机访问，只要我们将所有内存块的指针存储在连续的位置上。因此，该结构可以被假定为类似于数组的向量。

当我们想要在前面插入一些东西时，如果第一个内存块中没有足够的空间，我们必须分配另一个块，并将其地址插入到指针向量的前面。这可能需要重新分配指针向量，但实际数据不会被移动。为了优化该重新分配，我们可以从向量的中间块开始插入，而不是从第一个块开始。这样，我们可以在一定数量的前端插入中保持安全。在重新分配指针向量时，我们可以采取相同的方法。

#### 注意

由于 deque 不像本章讨论的其他容器那样简单，实际的实现可能会有所不同，或者可能有比我们讨论的更多的优化，但基本思想仍然是一样的。也就是说，我们需要多个连续内存块来实现这样一个容器。

deque 支持的函数和操作更多地是向量和列表支持的函数的组合；因此，我们有`push_front`，`push_back`，`insert`，`emplace_front`，`emplace_back`，`emplace`，`pop_front`，`pop_back`和`erase`等。我们还有向量的函数，比如`shrink_to_fit`，以优化容量，但我们没有一个叫做`capacity`的函数，因为这高度依赖于实现，因此不会被暴露。正如你所期望的，它提供了与向量一样的随机访问迭代器。

让我们看看如何在 deque 上使用不同的插入和删除操作：

```cpp
std::deque<int> deq = {1, 2, 3, 4, 5};
deq.push_front(0);
// deque becomes {0, 1, 2, 3, 4, 5}
deq.push_back(6);
// deque becomes {0, 1, 2, 3, 4, 5, 6}
deq.insert(deq.begin() + 2, 10);
// deque becomes {0, 1, 10, 2, 3, 4, 5, 6}
deq.pop_back();
// deque becomes {0, 1, 10, 2, 3, 4, 5}
deq.pop_front();
// deque becomes {1, 10, 2, 3, 4, 5}
deq.erase(deq.begin() + 1);
// deque becomes {1, 2, 3, 4, 5}
deq.erase(deq.begin() + 3, deq.end());
// deque becomes {1, 2, 3}
```

这样的结构可以用于飞行登机队列等情况。

容器之间唯一不同的是性能和内存需求。对于插入和删除，deque 在前端和末尾都提供非常好的性能。在中间插入和删除的速度也比向量平均快一点，尽管在渐近意义上，它与向量相同。

除此之外，deque 还允许我们像向量一样拥有自定义分配器。我们可以在初始化时将其指定为第二个模板参数。这里需要注意的一点是，分配器是类型的一部分，而不是对象的一部分。这意味着我们不能比较两个具有不同类型分配器的 deque 或两个向量的对象。同样，我们不能对具有不同类型分配器的对象进行其他操作，比如赋值或复制构造函数。

正如我们所看到的，`std::deque`与我们之前讨论过的其他容器相比具有稍微复杂的结构。事实上，它是唯一一个既提供高效的随机访问又提供快速的`push_front`和`push_back`函数的容器。Deque 被用作其他容器的底层容器，我们将在接下来的部分中看到。

## 容器适配器

到目前为止，我们看到的容器都是从头开始构建的。在本节中，我们将看看建立在其他容器之上的容器。提供对现有容器的包装有多种原因，比如为代码提供更多的语义含义，防止某人意外使用不期望的函数，以及提供特定的接口。

一个这样的特定用例是**栈**数据结构。栈遵循**LIFO**（后进先出）结构来访问和处理数据。在功能方面，它只能在容器的一端插入和删除，并且不能更新或甚至访问除了变异端之外的任何元素。这一端被称为栈顶。我们也可以轻松地使用任何其他容器，比如 vector 或 deque，因为它默认可以满足这些要求。然而，这样做会有一些根本性的问题。

以下示例展示了栈的两种实现：

```cpp
std::deque<int> stk;
stk.push_back(1);  // Pushes 1 on the stack = {1}
stk.push_back(2);  // Pushes 2 on the stack = {1, 2}
stk.pop_back();    // Pops the top element off the stack = {1}
stk.push_front(0); // This operation should not be allowed for a stack
std::stack<int> stk;
stk.push(1);       // Pushes 1 on the stack = {1}
stk.push(2);       // Pushes 2 on the stack = {1, 2}
stk.pop();         // Pops the top element off the stack = {1}
stk.push_front(0); // Compilation error
```

正如我们在这个例子中所看到的，使用 deque 的栈的第一个块仅通过变量的名称提供了语义上的含义。操作数据的函数仍然不会强迫程序员添加不应该被允许的代码，比如`push_front`。此外，`push_back`和`pop_back`函数暴露了不必要的细节，这些细节应该默认情况下就应该知道，因为它是一个栈。

与此相比，如果我们看第二个版本，它看起来更准确地指示了它的功能。而且，最重要的是，它不允许任何人做任何意外的事情。

栈的第二个版本只是通过为用户提供一个良好且受限的接口来包装前一个容器 deque。这被称为容器适配器。C++提供了三个容器适配器：`std::stack`、`std::queue`和`std::priority_queue`。现在让我们简要地看一下它们各自。

### std::stack

如前所述，适配器简单地重用其他容器，比如 deque、vector 或其他任何容器。`std::stack`默认适配`std::deque`作为其底层容器。它提供了一个仅与 stack 相关的接口——`empty`、`size`、`top`、`push`、`pop`和`emplace`。在这里，`push`只是调用底层容器的`push_back`函数，而`pop`只是调用`pop_back`函数。`top`调用底层容器的`back`函数来获取最后一个元素，也就是栈顶。因此，它限制了用户操作为 LIFO，因为它只允许我们在底层容器的一端更新值。

在这里，我们使用 deque 作为底层容器，而不是 vector。其背后的原因是 deque 在重新分配时不需要您移动所有元素，而 vector 需要。因此，与 vector 相比，使用 deque 更有效率。然而，如果在某种情况下，任何其他容器更可能提供更好的性能，stack 允许我们将容器作为模板参数提供。因此，我们可以使用 vector 或 list 构建一个 stack，就像这里所示：

```cpp
std::stack<int, std::vector<int>> stk;
std::stack<int, std::list<int>> stk;
```

栈的所有操作的时间复杂度都是*O(1)*。通常不会有将调用转发到底层容器的开销，因为编译器可以通过优化将所有内容内联化。

### std::queue

就像`std::stack`一样，我们还有另一个容器适配器来处理频繁的`std::queue`场景。它几乎具有与栈相同的一组函数，但意义和行为不同，以遵循 FIFO 而不是 LIFO。对于`std::queue`，`push`意味着`push_back`，就像栈一样，但`pop`是`pop_front`。而不是`pop`，因为队列应该暴露两端以供读取，它有`front`和`back`函数。

以下是`std::queue`的一个小例子：

```cpp
std::queue<int> q;
q.push(1);  // queue becomes {1}
q.push(2);  // queue becomes {1, 2}
q.push(3);  // queue becomes {1, 2, 3}
q.pop();    // queue becomes {2, 3}
q.push(4);  // queue becomes {2, 3, 4}
```

如本例所示，首先，我们按顺序插入`1`、`2`和`3`。然后，我们从队列中弹出一个元素。由于`1`被先推入，所以它首先从队列中移除。然后，下一个推入将`4`插入到队列的末尾。

`std::queue`也出于与 stack 相同的原因使用`std::deque`作为底层容器，它的所有方法的时间复杂度也都是*O(1)*。

### std::priority_queue

优先队列通过其接口提供了一个非常有用的结构称为**堆**。堆数据结构以快速访问容器中的最小（或最大）元素而闻名。获取最小/最大元素是一个时间复杂度为*O(1)*的操作。插入的时间复杂度为*O(log n)*，而删除只能针对最小/最大元素进行，它总是位于顶部。

这里需要注意的一点是，我们只能快速获得最小值或最大值函数中的一个，而不是两者都有。这是由提供给容器的比较器决定的。与栈和队列不同，优先队列默认基于向量，但如果需要，我们可以更改它。此外，默认情况下，比较器是`std::less`。由于这是一个堆，结果容器是一个最大堆。这意味着默认情况下最大元素将位于顶部。

在这里，由于插入需要确保我们可以立即访问顶部元素（根据比较器是最小值还是最大值），它不仅仅是将调用转发给底层容器。相反，它通过使用比较器实现了堆化数据的算法，根据需要将其冒泡到顶部。这个操作的时间复杂度与容器的大小成对数比例，因此时间复杂度为*O(log n)*。在初始化时也需要保持不变。然而，在这里，`priority_queue`构造函数不仅仅是为每个元素调用插入函数；相反，它应用不同的堆化算法以在*O(n)*的时间内更快地完成。

### 适配器的迭代器

到目前为止我们所见过的所有适配器都只暴露出满足其语义意义所需的功能。从逻辑上讲，遍历栈、队列和优先队列是没有意义的。在任何时候，我们只能看到前面的元素。因此，STL 不为此提供迭代器。

## 基准测试

正如我们所见，不同的容器有各种优缺点，没有一个容器是每种情况的完美选择。有时，多个容器可能在给定情况下平均表现出类似的性能。在这种情况下，基准测试是我们的朋友。这是一个根据统计数据确定更好方法的过程。

考虑这样一个情景，我们想要在连续的内存中存储数据，访问它，并使用各种函数对其进行操作。我们可以说我们应该使用`std::vector`或`std::deque`中的一个。但我们不确定其中哪一个是最好的。乍一看，它们两个似乎都对这种情况有良好的性能。在不同的操作中，比如访问、插入、`push_back`和修改特定元素，有些对`std::vector`有利，有些对`std::deque`有利。那么，我们应该如何继续？

这个想法是创建一个实际模型的小型原型，并使用`std::vector`和`std::deque`来实现它。然后，测量原型的性能。根据性能测试的结果，我们可以选择总体表现更好的那个。

最简单的方法是测量执行不同操作所需的时间，并比较它们。然而，同样的操作在不同运行时可能需要不同的时间，因为还有其他因素会影响，比如操作系统调度、缓存和中断等。这些参数可能会导致我们的结果相差很大，因为执行任何操作一次只需要几百纳秒。为了克服这一点，我们可以多次执行操作（也就是说，几百万次），直到我们在两次测量之间得到了相当大的时间差异。

有一些基准测试工具可以使用，比如[quic[k-bench.com](http://k-bench.com)]，它们为我们提供了一个简单的方法来运行基准测试。您可以尝试在向量和双端队列上快速比较性能差异。

### 活动 3：模拟办公室中共享打印机的队列

在这个活动中，我们将模拟办公室中共享打印机的队列。在任何公司办公室中，通常打印机是在打印机房间整个楼层共享的。这个房间里的所有计算机都连接到同一台打印机。但是一台打印机一次只能做一项打印工作，而且完成任何工作也需要一些时间。与此同时，其他用户可以发送另一个打印请求。在这种情况下，打印机需要将所有待处理的作业存储在某个地方，以便在当前任务完成后可以处理它们。

执行以下步骤来解决这个活动：

1.  创建一个名为`Job`的类（包括作业的 ID、提交作业的用户的名称和页数）。

1.  创建一个名为`Printer`的类。这将提供一个接口来添加新的作业并处理到目前为止添加的所有作业。

1.  要实现`printer`类，它将需要存储所有待处理的作业。我们将实现一个非常基本的策略 - 先来先服务。谁先提交作业，谁就会第一个完成作业。

1.  最后，模拟多人向打印机添加作业，并且打印机逐个处理它们的情景。

#### 注意

此活动的解决方案可在第 487 页找到。

## 总结

在本章中，我们学习了根据需求设计应用程序的方法，选择我们想要存储数据的方式。我们解释了可以对数据执行的不同类型的操作，这些操作可以用作多个数据结构之间比较的参数，基于这些操作的频率。我们了解到容器适配器为我们在代码中指示我们的意图提供了一种非常有用的方式。我们看到，使用更为限制的容器适配器，而不是使用提供更多功能的主要容器，从可维护性的角度来看更有效，并且还可以减少人为错误。我们详细解释了各种数据结构 - `std::array`、`std::vector`、`std::list`和`std::forward_list`，这些数据结构在任何应用程序开发过程中都非常频繁，并且它们的接口是由 C++默认提供的。这帮助我们编写高效的代码，而不需要重新发明整个周期，使整个过程更快。

在本章中，我们看到的所有结构在逻辑上都是线性的，也就是说，我们可以从任何元素向前或向后移动。在下一章中，我们将探讨无法轻松解决这些结构的问题，并实现新类型的结构来解决这些问题。


# 第二章：树、堆和图

## 学习目标

在本章结束时，您将能够：

+   分析和确定非线性数据结构可以使用的地方

+   实现和操作树结构来表示数据和解决问题

+   使用各种方法遍历树

+   实现图结构来表示数据和解决问题

+   根据给定的场景使用不同的方法表示图

在本章中，我们将看两种非线性数据结构，即树和图，以及它们如何用于表示现实世界的场景和解决各种问题。

## 介绍

在上一章中，我们实现了不同类型的线性数据结构，以线性方式存储和管理数据。在线性结构中，我们最多可以沿着两个方向遍历 - 向前或向后。然而，这些结构的范围非常有限，不能用来解决高级问题。在本章中，我们将探讨更高级的问题。我们将看到我们之前实现的解决方案不足以直接使用。因此，我们将扩展这些数据结构，以创建更复杂的结构，用于表示非线性数据。

在查看了这些问题之后，我们将讨论使用**树**数据结构的基本解决方案。我们将实现不同类型的树来解决不同类型的问题。之后，我们将看一种特殊类型的树，称为**堆**，以及它的可能实现和应用。接下来，我们将看另一种复杂结构 - **图**。我们将实现图的两种不同表示。这些结构有助于将现实世界的场景转化为数学形式。然后，我们将应用我们的编程技能和技术来解决与这些场景相关的问题。

对树和图有深刻的理解是理解更高级问题的基础。数据库（B 树）、数据编码/压缩（哈夫曼树）、图着色、分配问题、最小距离问题等许多问题都是使用树和图的某些变体来解决的。

现在，让我们看一些不能用线性数据结构表示的问题的例子。

## 非线性问题

无法使用线性数据结构表示的两种主要情况是分层问题和循环依赖。让我们更仔细地看看这些情况。

### 分层问题

让我们看一些固有分层属性的例子。以下是一个组织的结构：

![图 2.1：组织结构](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_01.jpg)

###### 图 2.1：组织结构

正如我们所看到的，CEO 是公司的负责人，管理副总监。副总监领导其他三名官员，依此类推。

数据本质上是分层的。使用简单的数组、向量或链表来管理这种类型的数据是困难的。为了巩固我们的理解，让我们看另一个用例；即，大学课程的结构，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_02.jpg)

###### 图 2.2：大学课程结构中的课程层次结构

前面的图显示了一个假设大学中一些课程的课程依赖关系。正如我们所看到的，要学习高等物理 II，学生必须成功完成以下课程：高等物理和高等数学。同样，许多其他课程也有它们自己的先决条件。

有了这样的数据，我们可以有不同类型的查询。例如，我们可能想找出需要成功完成哪些课程，以便学习高等数学。

这些问题可以使用一种称为树的数据结构来解决。所有的对象都被称为树的节点，而从一个节点到另一个节点的路径被称为边。我们将在本章后面的*图*部分更深入地研究这一点。

### 循环依赖

让我们来看另一个可以用非线性结构更好地表示的复杂现实场景。以下图表示了几个人之间的友谊：

![图 2.3：朋友网络](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_03.jpg)

###### 图 2.3：朋友网络

这种结构称为图。人的名字，或元素，称为节点，它们之间的关系表示为边。各种社交网络通常使用这样的结构来表示他们的用户及其之间的连接。我们可以观察到 Alice 和 Charlie 是朋友，Charlie 和 Eddard 是朋友，Eddard 和 Grace 是朋友，依此类推。我们还可以推断 Alice、Bob 和 Charlie 彼此认识。我们还可以推断 Eddard 是 Grace 的一级连接，Charlie 是二级连接，Alice 和 Bob 是三级连接。

图表在*图表*部分中的另一个有用的领域是当我们想要表示城市之间的道路网络时，您将在本章后面的*图表*部分中看到。

## 树-它颠倒了！

正如我们在上一节中讨论的那样，树只是通过关系连接到其他节点的一些对象或节点，从而产生某种层次结构。如果我们要以图形方式显示这种层次结构，它看起来像一棵树，而不同的边缘看起来像它的分支。主节点，不依赖于任何其他节点，也被称为根节点，并通常表示在顶部。因此，与实际树不同，这棵树是颠倒的，根在顶部！

让我们尝试构建一个非常基本版本的组织层次结构的结构。

### 练习 7：创建组织结构

在这个练习中，我们将实现我们在本章开头看到的组织树的基本版本。让我们开始吧：

1.  首先，让我们包括所需的标头：

```cpp
#include <iostream>
#include <queue>
```

1.  为简单起见，我们假设任何人最多可以有两个下属。我们将看到这不难扩展以类似于现实生活中的情况。这种树也被称为**二叉树**。让我们为此编写一个基本结构：

```cpp
struct node
{
    std::string position;
    node *first, *second;
};
```

正如我们所看到的，任何节点都将有两个链接到其他节点-它们的下属。通过这样做，我们可以显示数据的递归结构。我们目前只存储位置，但我们可以轻松扩展此功能，以包括该位置的名称，甚至包括关于该位置的人的所有信息的整个结构。

1.  我们不希望最终用户处理这种原始数据结构。因此，让我们将其包装在一个名为`org_tree`的良好接口中：

```cpp
struct org_tree
{
    node *root;
```

1.  现在，让我们添加一个函数来创建根，从公司的最高指挥官开始：

```cpp
static org_tree create_org_structure(const std::string& pos)
{
    org_tree tree;
    tree.root = new node{pos, NULL, NULL};
    return tree;
}
```

这只是一个静态函数，用于创建树。现在，让我们看看如何扩展树。

1.  现在，我们想要添加一个员工的下属。该函数应该接受两个参数-树中已存在的员工的名字和要添加为下属的新员工的名字。但在此之前，让我们编写另一个函数，以便更容易地找到基于值的特定节点来帮助我们编写插入函数：

```cpp
static node* find(node* root, const std::string& value)
{
    if(root == NULL)
        return NULL;
    if(root->position == value)
        return root;
    auto firstFound = org_tree::find(root->first, value);
    if(firstFound != NULL)
        return firstFound;
    return org_tree::find(root->second, value);
}
```

当我们在搜索元素时遍历树时，要么元素将是我们所在的节点，要么它将在右子树或左子树中。

因此，我们需要首先检查根节点。如果不是所需的节点，我们将尝试在左子树中找到它。最后，如果我们没有成功做到这一点，我们将查看右子树。

1.  现在，让我们实现插入函数。我们将利用`find`函数以便重用代码：

```cpp
bool addSubordinate(const std::string& manager, const std::string& subordinate)
{
    auto managerNode = org_tree::find(root, manager);
    if(!managerNode)
    {
        std::cout << "No position named " << manager << std::endl;
        return false;
    }
    if(managerNode->first && managerNode->second)
    {
        std::cout << manager << " already has 2 subordinates." << std::endl;
        return false;
    }
    if(!managerNode->first)
        managerNode->first = new node{subordinate, NULL, NULL};
    else
        managerNode->second = new node{subordinate, NULL, NULL};
    return true;
}
};
```

正如我们所看到的，该函数返回一个布尔值，指示我们是否可以成功插入节点。

1.  现在，让我们使用此代码在`main`函数中创建一棵树：

```cpp
int main()
{
    auto tree = org_tree::create_org_structure("CEO");
    if(tree.addSubordinate("CEO", "Deputy Director"))
        std::cout << "Added Deputy Director in the tree." << std::endl;
    else
        std::cout << "Couldn't add Deputy Director in the tree" << std::endl;
    if(tree.addSubordinate("Deputy Director", "IT Head"))
        std::cout << "Added IT Head in the tree." << std::endl;
    else
        std::cout << "Couldn't add IT Head in the tree" << std::endl;
    if(tree.addSubordinate("Deputy Director", "Marketing Head"))
        std::cout << "Added Marketing Head in the tree." << std::endl;
    else
        std::cout << "Couldn't add Marketing Head in the tree" << std::endl;
    if(tree.addSubordinate("IT Head", "Security Head"))
        std::cout << "Added Security Head in the tree." << std::endl;
    else
        std::cout << "Couldn't add Security Head in the tree" << std::endl;
    if(tree.addSubordinate("IT Head", "App Development Head"))
        std::cout << "Added App Development Head in the tree." << std::endl;
    else
        std::cout << "Couldn't add App Development Head in the tree" << std::endl;
if(tree.addSubordinate("Marketing Head", "Logistics Head"))
        std::cout << "Added Logistics Head in the tree." << std::endl;
    else
        std::cout << "Couldn't add Logistics Head in the tree" << std::endl;
    if(tree.addSubordinate("Marketing Head", "Public Relations Head"))
        std::cout << "Added Public Relations Head in the tree." << std::endl;
    else
        std::cout << "Couldn't add Public Relations Head in the tree" << std::endl;
    if(tree.addSubordinate("Deputy Director", "Finance Head"))
        std::cout << "Added Finance Head in the tree." << std::endl;
    else
        std::cout << "Couldn't add Finance Head in the tree" << std::endl;
}
```

在执行上述代码后，您应该获得以下输出：

```cpp
Added Deputy Director in the tree.
Added IT Head in the tree.
Added Marketing Head in the tree.
Added Security Head in the tree.
Added App Development Head in the tree.
Added Logistics Head in the tree.
Added Public Relations Head in the tree.
Deputy Director already has 2 subordinates.
Couldn't add Finance Head in the tree
```

此输出在以下图表中说明：

![图 2.4：基于组织层次结构的二叉家谱树](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_04.jpg)

###### 图 2.4：基于组织层次结构的二叉树

到目前为止，我们只是插入了元素。现在，我们将看看如何遍历树。虽然我们已经看到了如何使用`find`函数进行遍历，但这只是我们可以做的其中一种方式。我们可以以许多其他方式遍历树，所有这些方式我们将在下一节中看到。

### 遍历树

一旦我们有了一棵树，就有各种方法可以遍历它并到达我们需要的节点。让我们简要看一下各种遍历方法：

+   先序遍历：在这种方法中，我们首先访问当前节点，然后是当前节点的左子节点，然后是当前节点的右子节点，以递归的方式。这里，前缀“pre”表示父节点在其子节点之前被访问。使用先序方法遍历*图 2.4*中显示的树如下：

```cpp
CEO, Deputy Director, IT Head, Security Head, App Development Head, Marketing Head, Logistics Head, Public Relations Head,
```

正如我们所看到的，我们总是先访问父节点，然后是左子节点，然后是右子节点。我们不仅对根节点是这样，对于任何节点都是这样。我们使用以下函数实现前序遍历：

```cpp
static void preOrder(node* start)
{
    if(!start)
        return;
    std::cout << start->position << ", ";
    preOrder(start->first);
    preOrder(start->second);
}
```

+   中序遍历：在这种遍历中，首先访问左节点，然后是父节点，最后是右节点。遍历*图 2.4*中显示的树如下：

```cpp
Security Head, IT Head, App Development Head, Deputy Director, Logistics Head, Marketing Head, Public Relations Head, CEO, 
```

我们可以这样实现一个函数：

```cpp
static void inOrder(node* start)
{
    if(!start)
        return;
    inOrder(start->first);
std::cout << start->position << ", ";
    inOrder(start->second);
}
```

+   后序遍历：在这种遍历中，我们首先访问两个子节点，然后是父节点。遍历*图 2.4*中显示的树如下：

```cpp
Security Head, App Development Head, IT Head, Logistics Head, Public Relations Head, Marketing Head, Deputy Director, CEO, 
```

我们可以这样实现一个函数：

```cpp
static void postOrder(node* start)
{
    if(!start)
        return;
    postOrder(start->first);
    postOrder(start->second);
    std::cout << start->position << ", ";
}
```

+   层次遍历：这要求我们逐层遍历树，从顶部到底部，从左到右。这类似于列出树的每个级别的元素，从根级别开始。这种遍历的结果通常表示为每个级别，如下所示：

```cpp
CEO, 
Deputy Director, 
IT Head, Marketing Head, 
Security Head, App Development Head, Logistics Head, Public Relations Head, 
```

这种遍历方法的实现在以下练习中演示。

### 练习 8：演示层次遍历

在这个练习中，我们将在*练习 7*中创建的组织结构中实现层次遍历。与先前的遍历方法不同，这里我们不是直接遍历到当前节点直接连接的节点。这意味着遍历更容易实现而不需要递归。我们将扩展*练习 7*中显示的代码来演示这种遍历。让我们开始吧：

1.  首先，我们将在*练习 7*中的`org_tree`结构中添加以下函数：

```cpp
static void levelOrder(node* start)
{
    if(!start)
        return;
    std::queue<node*> q;
    q.push(start);
    while(!q.empty())
    {
        int size = q.size();
        for(int i = 0; i < size; i++)
        {
            auto current = q.front();
            q.pop();
            std::cout << current->position << ", ";
            if(current->first)
                q.push(current->first);
            if(current->second)
                q.push(current->second);
        }
        std::cout << std::endl;
    }
}
```

如前面的代码所示，首先我们遍历根节点，然后是它的子节点。在访问子节点时，我们将它们的子节点推入队列中，以便在当前级别完成后处理。这个想法是从第一级开始队列，并将下一级的节点添加到队列中。我们将继续这样做，直到队列为空，表示下一级没有更多的节点。

1.  我们的输出应该是这样的：

```cpp
CEO, 
Deputy Director, 
IT Head, Marketing Head, 
Security Head, App Development Head, Logistics Head, Public Relations Head, 
```

## 树的变体

在以前的练习中，我们主要看了**二叉树**，这是最常见的树之一。在二叉树中，每个节点最多可以有两个子节点。然而，普通的二叉树并不总是满足这个目的。接下来，我们将看一下二叉树的更专业版本，称为二叉搜索树。

### 二叉搜索树

**二叉搜索树**（**BST**）是二叉树的一种流行版本。BST 只是具有以下属性的二叉树：

+   父节点的值≥左子节点的值

+   父节点的值≤右子节点的值

简而言之，左子节点≤父节点≤右子节点。

这带我们到一个有趣的特性。在任何时候，我们总是可以说小于或等于父节点的所有元素将在左侧，而大于或等于父节点的所有元素将在右侧。因此，搜索元素的问题在每一步中都会减少一半，就搜索空间而言。

如果 BST 构造成除了最后一级的所有元素都有两个子节点的方式，树的高度将为*log n*，其中*n*是元素的数量。由于这个原因，搜索和插入的时间复杂度将为*O(log n)*。这种二叉树也被称为**完全二叉树**。

**在 BST 中搜索**

让我们看看如何在二叉搜索树中搜索、插入和删除元素。考虑一个具有唯一正整数的 BST，如下图所示：

![图 2.5：在二叉搜索树中搜索元素](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_05.jpg)

###### 图 2.5：在二叉搜索树中搜索元素

假设我们要搜索 7。从前面图中箭头表示的步骤中可以看出，我们在比较值与当前节点数据后选择侧边。正如我们已经提到的，左侧的所有节点始终小于当前节点，右侧的所有节点始终大于当前节点。

因此，我们首先将根节点与 7 进行比较。如果大于 7，则移动到左子树，因为那里的所有元素都小于父节点，反之亦然。我们比较每个子节点，直到我们遇到 7，或者小于 7 且没有右节点的节点。在这种情况下，来到节点 4 会导致我们的目标 7。

正如我们所看到的，我们并没有遍历整个树。相反，每次当前节点不是所需节点时，我们通过选择左侧或右侧来减少我们的范围一半。这类似于对线性结构进行二分搜索，我们将在第四章“分而治之”中学习。

**向 BST 中插入新元素**

现在，让我们看看插入是如何工作的。步骤如下图所示：

![图 2.6：向二叉搜索树插入元素](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_06.jpg)

###### 图 2.6：向二叉搜索树插入元素

正如您所看到的，首先我们必须找到要插入新值的父节点。因此，我们必须采取与搜索相似的方法；也就是说，通过根据每个节点与我们的新元素进行比较的方向前进，从根节点开始。在最后一步，18 大于 17，但 17 没有右子节点。因此，我们在那个位置插入 18。

**从 BST 中删除元素**

现在，让我们看看删除是如何工作的。考虑以下 BST：

![图 2.7：根节点为 12 的二叉搜索树](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_07.jpg)

###### 图 2.7：根节点为 12 的二叉搜索树

我们将删除树中的根节点 12。让我们看看如何删除任何值。这比插入要棘手，因为我们需要找到已删除节点的替代品，以使 BST 的属性保持真实。

第一步是找到要删除的节点。之后，有三种可能性：

+   节点没有子节点：只需删除节点。

+   节点只有一个子节点：将父节点的相应指针指向唯一存在的子节点。

+   节点有两个子节点：在这种情况下，我们用它的后继替换当前节点。

后继是当前节点之后的下一个最大数。换句话说，后继是所有大于当前元素的所有元素中最小的元素。因此，我们首先转到右子树，其中包含所有大于当前元素的元素，并找到其中最小的元素。找到最小的节点意味着尽可能多地向子树的左侧移动，因为左子节点始终小于其父节点。在*图 2.7*中显示的树中，12 的右子树从 18 开始。因此，我们从那里开始查找，然后尝试向 15 的左子节点移动。但是 15 没有左子节点，另一个子节点 16 大于 15。因此，15 应该是这里的后继。

要用 15 替换 12，首先，我们将复制根节点处的后继的值，同时删除 12，如下图所示：

![图 2.8：后继复制到根节点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_08.jpg)

###### 图 2.8：后继复制到根节点

接下来，我们需要从右子树中删除后继 15，如下图所示：

![图 2.9：从旧位置删除的后继](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_09.jpg)

###### 图 2.9：从旧位置删除的后继

在最后一步中，我们正在删除节点 15。我们对此删除使用相同的过程。由于 15 只有一个子节点，我们将用 15 的子节点替换 18 的左子节点。因此，以 16 为根的整个子树成为 18 的左子节点。

#### 注意

后继节点最多只能有一个子节点。如果它有一个左子节点，我们将选择该子节点而不是当前节点作为后继。

### 树上操作的时间复杂度

现在，让我们看看这些函数的时间复杂度。理论上，我们可以说每次将搜索范围减半。因此，搜索具有*n*个节点的 BST 所需的时间为*T(n) = T(n / 2) + 1*。这个方程导致时间复杂度为*T(n) = O(log n)*。

但这里有一个问题。如果我们仔细看插入函数，插入的顺序实际上决定了树的形状。并不一定总是减半搜索范围，如前面公式中的*T(n/2)*所描述的那样。因此，复杂度*O(log n)*并不总是准确的。我们将在*平衡树*部分更深入地研究这个问题及其解决方案，我们将看到如何更准确地计算时间复杂度。

现在，让我们在 C++中实现我们刚刚看到的操作。

### 练习 9：实现二叉搜索树

在这个练习中，我们将实现*图 2.7*中显示的 BST，并添加一个“查找”函数来搜索元素。我们还将尝试在前面的子节中解释的插入和删除元素。让我们开始吧：

1.  首先，让我们包括所需的头文件：

```cpp
#include <iostream>
```

1.  现在，让我们写一个节点。这将类似于我们之前的练习，只是我们将有一个整数而不是一个字符串：

```cpp
struct node
{
    int data;
    node *left, *right;
};
```

1.  现在，让我们在节点上添加一个包装器，以提供一个清晰的接口：

```cpp
struct bst
{
    node* root = nullptr;
```

1.  在编写插入函数之前，我们需要编写“查找”函数：

```cpp
node* find(int value)
{
    return find_impl(root, value);
}
    private:
node* find_impl(node* current, int value)
{
    if(!current)
    {
        std::cout << std::endl;
        return NULL;
    }
    if(current->data == value)
    {
        std::cout << "Found " << value << std::endl;
        return current;
    }
    if(value < current->data)  // Value will be in the left subtree
    {
        std::cout << "Going left from " << current->data << ", ";
        return find_impl(current->left, value);
    }
    if(value > current->data) // Value will be in the right subtree
    {
        std::cout << "Going right from " << current->data << ", ";
        return find_impl(current->right, value);
    }
}
```

由于这是递归的，我们将实现放在一个单独的函数中，并将其设置为私有，以防止有人直接使用它。

1.  现在，让我们编写一个“插入”函数。它将类似于“查找”函数，但有一些小调整。首先，让我们找到父节点，这是我们想要插入新值的地方：

```cpp
public:
void insert(int value)
{
    if(!root)
        root = new node{value, NULL, NULL};
    else
        insert_impl(root, value);
}
private:
void insert_impl(node* current, int value)
{
    if(value < current->data)
    {
        if(!current->left)
            current->left = new node{value, NULL, NULL};
        else
            insert_impl(current->left, value);
    }
    else
    {
        if(!current->right)
            current->right = new node{value, NULL, NULL};
            else
                insert_impl(current->right, value);
    }
}
```

正如我们所看到的，我们正在检查值应该插入左侧还是右侧子树。如果所需侧面没有任何内容，我们直接在那里插入节点；否则，我们递归调用该侧的“插入”函数。

1.  现在，让我们编写一个“中序”遍历函数。中序遍历在应用于 BST 时提供了重要的优势，正如我们将在输出中看到的：

```cpp
public:
void inorder()
{
    inorder_impl(root);
}
private:
void inorder_impl(node* start)
{
    if(!start)
        return;
    inorder_impl(start->left);        // Visit the left sub-tree
    std::cout << start->data << " ";  // Print out the current node
    inorder_impl(start->right);       // Visit the right sub-tree
}
```

1.  现在，让我们实现一个实用函数来获取后继：

```cpp
public:
node* successor(node* start)
{
    auto current = start->right;
    while(current && current->left)
        current = current->left;
    return current;
}
```

这遵循了我们在*删除 BST 中的元素*子节中讨论的逻辑。

1.  现在，让我们看一下`delete`的实际实现。由于删除需要重新指向父节点，我们将通过每次返回新节点来执行此操作。我们将通过在其上放置更好的接口来隐藏这种复杂性。我们将命名接口为`deleteValue`，因为`delete`是 C++标准中的保留关键字：

```cpp
void deleteValue(int value)
{
    root = delete_impl(root, value);
}
private:
node* delete_impl(node* start, int value)
{
    if(!start)
        return NULL;
    if(value < start->data)
        start->left = delete_impl(start->left, value);
    else if(value > start->data)
        start->right = delete_impl(start->right, value);
    else
    {
        if(!start->left)  // Either both children are absent or only left child is absent
        {
            auto tmp = start->right;
            delete start;
            return tmp;
        }
        if(!start->right)  // Only right child is absent
        {
            auto tmp = start->left;
            delete start;
            return tmp;
        }
        auto succNode = successor(start);
        start->data = succNode->data;
        // Delete the successor from right subtree, since it will always be in the right subtree
        start->right = delete_impl(start->right, succNode->data);
    }
    return start;
}
};
```

1.  让我们编写`main`函数，以便我们可以使用 BST：

```cpp
int main()
{
    bst tree;
    tree.insert(12);
    tree.insert(10);
    tree.insert(20);
    tree.insert(8);
    tree.insert(11);
    tree.insert(15);
    tree.insert(28);
    tree.insert(4);
    tree.insert(2);
    std::cout << "Inorder: ";
    tree.inorder();  // This will print all the elements in ascending order
    std::cout << std::endl;
    tree.deleteValue(12);
    std::cout << "Inorder after deleting 12: ";
    tree.inorder();  // This will print all the elements in ascending order
    std::cout << std::endl;
    if(tree.find(12))
        std::cout << "Element 12 is present in the tree" << std::endl;
    else
        std::cout << "Element 12 is NOT present in the tree" << std::endl;
}
```

执行上述代码的输出应该如下所示：

```cpp
Inorder: 2 4 8 10 11 12 15 20 28 
Inorder after deleting 12: 2 4 8 10 11 15 20 28 
Going left from 15, Going right from 10, Going right from 11, 
Element 12 is NOT present in the tree
```

观察 BST 的中序遍历结果。中序遍历将首先访问左子树，然后是当前节点，然后是右子树，如代码片段中的注释所示。因此，根据 BST 的属性，我们将首先访问所有小于当前值的值，然后是当前值，然后我们将访问所有大于当前值的值。由于这是递归进行的，我们将按升序排序获取我们的数据。

### 平衡树

在我们理解平衡树之前，让我们从以下插入顺序的 BST 示例开始：

```cpp
bst tree;
tree.insert(10);
tree.insert(9);
tree.insert(11);
tree.insert(8);
tree.insert(7);
tree.insert(6);
tree.insert(5);
tree.insert(4);
```

可以使用以下图来可视化这个 BST：

![图 2.10：倾斜的二叉搜索树](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_10.jpg)

###### 图 2.10：倾斜的二叉搜索树

如前图所示，几乎整个树都向左倾斜。如果我们调用`find`函数，即`bst.find(4)`，步骤将如下所示：

![图 2.11：在倾斜的二叉搜索树中查找元素](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_11.jpg)

###### 图 2.11：在倾斜的二叉搜索树中查找元素

正如我们所看到的，步骤数几乎等于元素数。现在，让我们尝试以不同的插入顺序再次尝试相同的操作，如下所示：

```cpp
bst tree;
tree.insert(7);
tree.insert(5);
tree.insert(9);
tree.insert(4);
tree.insert(6);
tree.insert(10);
tree.insert(11);
tree.insert(8);
```

现在，查找元素 4 所需的 BST 和步骤如下：

![图 2.12：在平衡树中查找元素](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_12.jpg)

###### 图 2.12：在平衡树中查找元素

正如我们所看到的，树不再倾斜。换句话说，树是平衡的。通过这种配置，查找 4 的步骤已经大大减少。因此，`find`的时间复杂度不仅取决于元素的数量，还取决于它们在树中的配置。如果我们仔细观察步骤，我们在搜索时总是朝树的底部前进一步。最后，我们将到达叶节点（没有任何子节点的节点）。在这里，我们根据元素的可用性返回所需的节点或 NULL。因此，我们可以说步骤数始终小于 BST 的最大级别数，也称为 BST 的高度。因此，查找元素的实际时间复杂度为 O(height)。

为了优化时间复杂度，我们需要优化树的高度。这也被称为*平衡树*。其思想是在插入/删除后重新组织节点以减少树的倾斜程度。结果树称为高度平衡 BST。

我们可以以各种方式执行此操作并获得不同类型的树，例如 AVL 树、红黑树等。AVL 树的思想是执行一些旋转以平衡树的高度，同时仍保持 BST 的属性。考虑下面图中显示的例子：

![图 2.13：旋转树](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_13.jpg)

###### 图 2.13：旋转树

正如我们所看到的，右侧的树与左侧的树相比更加平衡。旋转超出了本书的范围，因此我们不会深入探讨这个例子的细节。

### N 叉树

到目前为止，我们主要看到了二叉树或其变体。对于 N 叉树，每个节点可以有*N*个子节点。由于*N*在这里是任意的，我们将其存储在一个向量中。因此，最终的结构看起来像这样：

```cpp
struct nTree
{
    int data;
    std::vector<nTree*> children;
};
```

正如我们所看到的，每个节点可以有任意数量的子节点。因此，整个树是完全任意的。然而，就像普通的二叉树一样，普通的 N 叉树也不是很有用。因此，我们必须为不同类型的应用构建不同的树，其中的层次结构比二叉树的度要高。*图 2.1*中所示的例子代表了一个组织的层次结构，是一个 N 叉树。

在计算机世界中，有两种非常好的、著名的 N 叉树实现，如下所示：

+   计算机中的文件系统结构：从 Linux 中的`root`（`/`）或 Windows 中的驱动器开始，我们可以在任何文件夹内拥有任意数量的文件（终端节点）和任意数量的文件夹。我们将在*活动 1，为文件系统创建数据结构*中更详细地讨论这一点。

+   编译器：大多数编译器根据源代码的语法构建抽象语法树（AST）。编译器通过解析 AST 生成低级别代码。

### 活动 4：为文件系统创建数据结构

使用 N 叉树创建一个文件系统的数据结构，支持以下操作：转到目录，查找文件/目录，添加文件/目录和列出文件/目录。我们的树将保存文件系统中所有元素（文件和文件夹）的信息和文件夹层次结构（路径）。

执行以下步骤来解决此活动：

1.  创建一个 N 叉树，其中一个节点中有两个数据元素-目录/文件的名称和指示它是目录还是文件的标志。

1.  添加一个数据成员来存储当前目录。

1.  用单个目录根（`/`）初始化树。

1.  添加查找目录/文件的函数，它接受一个参数-`path`。`path`可以是绝对的（以`/`开头）或相对的。

1.  添加函数以添加文件/目录并列出位于给定路径的文件/目录。

1.  同样，添加一个函数来更改当前目录。

#### 注意

此活动的解决方案可在第 490 页找到。

我们已经打印了带有`d`的目录，以区分它们与文件，文件是以"`-`"（连字符）开头打印的。您可以通过创建具有绝对或相对路径的更多目录和文件来进行实验。

到目前为止，我们还没有支持某些 Linux 约定，例如用单个点寻址任何目录和用双点寻址父目录。这可以通过扩展我们的节点来完成，以便还保存指向其父节点的指针。这样，我们可以非常容易地在两个方向上遍历。还有其他各种可能的扩展，例如添加符号链接，以及使用"`*`"扩展各种文件/目录名称的通配符操作符。这个练习为我们提供了一个基础，这样我们就可以根据自己的需求构建一些东西。

## 堆

在上一章中，我们简要介绍了堆以及 C++如何通过 STL 提供堆。在本章中，我们将更深入地了解堆。简而言之，以下是预期的时间复杂度：

+   *O(1)*：立即访问最大元素

+   *O(log n)*：插入任何元素

+   *O(log n)*：删除最大元素

为了实现*O(log n)*的插入/删除，我们将使用树来存储数据。但在这种情况下，我们将使用完全树。**完全树**被定义为一个树，其中除了最后一层以外的所有级别的节点都有两个子节点，并且最后一层尽可能多地在左侧具有元素。例如，考虑以下图中显示的两棵树：

![图 2.14：完全树与非完全树](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_14.jpg)

###### 图 2.14：完全树与非完全树

因此，可以通过在最后一级插入元素来构建完整的树，只要那里有足够的空间。如果没有，我们将在新级别的最左边位置插入它们。这给了我们一个很好的机会，可以使用数组逐级存储这棵树。因此，树的根将是数组/向量的第一个元素，其后是其左孩子，然后是右孩子，依此类推。与其他树不同，这是一种非常高效的内存结构，因为不需要额外的内存来存储指针。要从父节点到其子节点，我们可以轻松地使用数组的索引。如果父节点是第*i*个节点，其子节点将始终是*2*i + 1*和*2*i + 2*索引。同样，我们可以通过使用*(i – 1) / 2*来获取第*i*个子节点的父节点。我们也可以从前面的图中确认这一点。

现在，让我们看看我们需要在每次插入/删除时保持的不变量（或条件）。第一个要求是立即访问最大元素。为此，我们需要固定其位置，以便每次都可以立即访问。我们将始终将我们的最大元素保持在顶部 - 根位置。为了保持这一点，我们还需要保持另一个不变量 - 父节点必须大于其两个子节点。这样的堆也被称为**最大堆**。

正如你可能猜到的那样，为了快速访问最大元素所需的属性可以很容易地反转，以便快速访问最小元素。我们在执行堆操作时所需要做的就是反转我们的比较函数。这种堆被称为**最小堆**。

### 堆操作

在本节中，我们将看到如何在堆上执行不同的操作。

**向堆中插入元素**

作为插入的第一步，我们将保留最重要的不变量，这为我们提供了一种将此结构表示为数组的方式 - 完整树。这可以很容易地通过在末尾插入新元素来完成，因为它将代表最后一级的元素，就在所有现有元素之后，或者作为新级别中的第一个元素，如果当前的最后一级已满。

现在，我们需要保持另一个不变量 - 所有节点的值必须大于它们的两个子节点的值，如果有的话。假设我们当前的树已经遵循这个不变量，在最后位置插入新元素后，唯一可能违反不变量的元素将是最后一个元素。为了解决这个问题，如果父节点比元素小，我们将元素与其父节点交换。即使父节点已经有另一个元素，它也将小于新元素（新元素 > 父节点 > 子节点）。

因此，通过将新元素视为根创建的子树满足所有不变量。然而，新元素可能仍然大于其新父节点。因此，我们需要不断交换节点，直到整个树的不变量得到满足。由于完整树的高度最多为*O(log n)*，整个操作将最多需要*O(log n)*时间。下图说明了向树中插入元素的操作：

![图 2.15：向具有一个节点的堆中插入元素](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_15.jpg)

###### 图 2.15：向具有一个节点的堆中插入元素

如前图所示，在插入 11 后，树不再具有堆属性。因此，我们将交换 10 和 11 以使其再次成为堆。这个概念在下面的例子中更清晰，该例子有更多级别：

![图 2.16：向具有多个节点的堆中插入元素](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_16.jpg)

###### 图 2.16：向具有多个节点的堆中插入元素

**从堆中删除元素**

首先要注意的是，我们只能删除最大的元素。我们不能直接触摸任何其他元素。最大的元素始终存在于根部。因此，我们将删除根元素。但我们还需要决定谁将接替它的位置。为此，我们首先需要将根与最后一个元素交换，然后删除最后一个元素。这样，我们的根将被删除，但它将打破每个父节点都大于其子节点的不变性。为了解决这个问题，我们将根与它的两个子节点进行比较，并与较大的子节点交换。现在，不变性在一个子树中被破坏。我们继续在整个子树中递归地进行交换过程。这样，不变性的破坏点就会沿着树向下冒泡。就像插入一样，我们一直遵循这个过程，直到满足不变性。所需的最大步数将等于树的高度，即*O(log n)*。下图说明了这个过程：

![图 2.17：删除堆中的一个元素](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_17.jpg)

###### 图 2.17：删除堆中的一个元素

**初始化堆**

现在，让我们看看最重要的一步 - 初始化堆。与向量、列表、双端队列等不同，堆的初始化并不简单，因为我们需要维护堆的不变性。一个简单的解决方案是从一个空堆开始逐个插入所有元素。但是这样需要的时间是*O(n * log(n))*，这并不高效。

然而，有一个`std::make_heap`，它可以接受任何数组或向量迭代器，并将它们转换为堆。

### 练习 10：流式中位数

在这个练习中，我们将解决一个在数据分析相关应用中经常出现的有趣问题，包括机器学习。想象一下，某个来源不断地给我们提供数据（数据流）中的一个元素。我们需要在每次接收到每个元素后找到到目前为止已接收到的元素的中位数。一个简单的方法是每次有新元素进来时对数据进行排序并返回中间元素。但是由于排序的原因，这将具有*O(n log n)*的时间复杂度。根据输入元素的速率，这可能非常消耗资源。然而，我们将通过堆来优化这个问题。让我们开始吧：

1.  首先让我们包括所需的头文件：

```cpp
#include <iostream>
#include <queue>
#include <vector>
```

1.  现在，让我们编写一个容器来存储到目前为止收到的数据。我们将数据存储在两个堆中 - 一个最小堆和一个最大堆。我们将把较小的前半部分元素存储在最大堆中，将较大的或另一半存储在最小堆中。因此，在任何时候，中位数可以使用堆的顶部元素来计算，这些元素很容易访问：

```cpp
struct median
{
    std::priority_queue<int> maxHeap;
    std::priority_queue<int, std::vector<int>, std::greater<int>> minHeap;
```

1.  现在，让我们编写一个`insert`函数，以便我们可以插入新到达的数据：

```cpp
void insert(int data)
{
    // First element
    if(maxHeap.size() == 0)
    {
        maxHeap.push(data);
        return;
    }
    if(maxHeap.size() == minHeap.size())
    {
        if(data <= get())
            maxHeap.push(data);
        else
            minHeap.push(data);
        return;
    }
    if(maxHeap.size() < minHeap.size())
    {
        if(data > get())
        {
            maxHeap.push(minHeap.top());
            minHeap.pop();
            minHeap.push(data);
        }
        else
            maxHeap.push(data);
        return;
    }
    if(data < get())
    {
        minHeap.push(maxHeap.top());
        maxHeap.pop();
        maxHeap.push(data);
    }
    else
        minHeap.push(data);
}
```

1.  现在，让我们编写一个`get`函数，以便我们可以从容器中获取中位数：

```cpp
double get()
{
    if(maxHeap.size() == minHeap.size())
        return (maxHeap.top() + minHeap.top()) / 2.0;
    if(maxHeap.size() < minHeap.size())
        return minHeap.top();
    return maxHeap.top();
}
};
```

1.  现在，让我们编写一个`main`函数，以便我们可以使用这个类：

```cpp
int main()
{
    median med;
    med.insert(1);
    std::cout << "Median after insert 1: " << med.get() << std::endl;
    med.insert(5);
    std::cout << "Median after insert 5: " << med.get() << std::endl;
    med.insert(2);
    std::cout << "Median after insert 2: " << med.get() << std::endl;
    med.insert(10);
    std::cout << "Median after insert 10: " << med.get() << std::endl;
    med.insert(40);
    std::cout << "Median after insert 40: " << med.get() << std::endl;
    return 0;
}
```

上述程序的输出如下：

```cpp
Median after insert 1: 1
Median after insert 5: 3
Median after insert 2: 2
Median after insert 10: 3.5
Median after insert 40: 5
```

这样，我们只需要插入任何新到达的元素，这只需要*O(log n)*的时间复杂度，与如果我们每次有新元素就对元素进行排序的时间复杂度*O(n log n)*相比。

### 活动 5：使用堆进行 K 路合并

考虑一个与遗传学相关的生物医学应用，用于处理大型数据集。它需要对 DNA 的排名进行排序以计算相似性。但由于数据集很大，无法放在一台机器上。因此，它在分布式集群中处理和存储数据，每个节点都有一组排序的值。主处理引擎需要所有数据以排序方式和单个流的形式。因此，基本上，我们需要将多个排序数组合并成一个排序数组。借助向量模拟这种情况。

执行以下步骤来解决这个活动：

1.  最小的数字将出现在所有列表的第一个元素中，因为所有列表已经分别排序。为了更快地获取最小值，我们将构建这些元素的堆。

1.  从堆中获取最小元素后，我们需要将其移除并用它所属列表中的下一个元素替换。

1.  堆节点必须包含关于列表的信息，以便它可以从该列表中找到下一个数字。

#### 注意

此活动的解决方案可在第 495 页找到。

现在，让我们计算前面算法的时间复杂度。如果有*k*个列表可用，我们的堆大小将为*k*，我们所有的堆操作都将是*O(log k)*。构建堆将是*O(k log k)*。之后，我们将不得不为结果中的每个元素执行堆操作。总元素为*n × k*。因此，总复杂度将是*O(nk log k)*。

这个算法的奇妙之处在于，考虑到我们之前描述的现实场景，它实际上并不需要同时存储所有的*n × k*元素；它只需要在任何时刻存储*k*个元素，其中*k*是集群中列表或节点的数量。由于这个原因，*k*的值永远不会太大。借助堆，我们可以一次生成一个数字，然后立即处理该数字，或者将其流式传输到其他地方进行处理，而无需实际存储它。

## 图

尽管树是表示分层数据的一种很好的方式，但我们无法在树中表示循环依赖，因为我们总是有一条单一且唯一的路径可以从一个节点到另一个节点。然而，还有更复杂的情况具有固有的循环结构。例如，考虑一个道路网络。可以有多种方式从一个地点（地点可以表示为节点）到另一个地点。这样的一组情景可以更好地用图来表示。

与树不同，图必须存储节点的数据，以及节点之间的边的数据。例如，在任何道路网络中，对于每个节点（地点），我们都必须存储它连接到哪些其他节点（地点）的信息。这样，我们就可以形成一个包含所有所需节点和边的图。这被称为**无权图**。我们可以为每条边添加*权重*或更多信息。对于我们的道路网络示例，我们可以添加每条边（路径）从一个节点（地点）到另一个节点的距离。这种表示被称为**加权图**，它包含了解决诸如找到两个地点之间最小距离的路径等问题所需的道路网络的所有信息。

图有两种类型 - 无向图和有向图。**无向图**表示边是双向的。双向表示具有双边或可交换属性。对于道路网络示例，点 A 和点 B 之间的双向边意味着我们可以从 A 到 B，也可以从 B 到 A。但假设我们有一些有单向限制的道路 - 我们需要使用**有向图**来表示。在有向图中，每当我们需要指示可以双向行驶时，我们使用两条边 - 从点 A 到 B，以及从 B 到 A。我们主要关注双向图，但我们在这里学到的关于结构和遍历方法的知识对于有向图也是正确的。唯一的变化将是我们如何向图中添加边。

由于图可以具有循环边和从一个节点到另一个节点的多条路径，我们需要唯一标识每个节点。为此，我们可以为每个节点分配一个标识符。为了表示图的数据，我们实际上不需要像在树中那样以编程方式构建类似节点的结构。事实上，我们可以通过组合`std`容器来存储整个图。

### 将图表示为邻接矩阵

以下是理解图的最简单方法之一——考虑一组节点，其中任何节点都可以直接连接到该组中的任何其他节点。这意味着我们可以使用大小为*N×N*的二维数组来表示这一点，其中*N*为节点数。每个单元格中的值将根据单元格的索引指示相应节点之间的边的权重。因此，`data[1][2]`将指示节点 1 和节点 2 之间边的权重。这种方法称为**邻接矩阵**。我们可以使用-1 的权重表示边的缺失。

考虑下图中所示的加权图，它表示了一些主要国际城市之间的航空网络，带有假设的距离：

![图 2.18：一些城市之间的航空网络](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_02_18.jpg)

###### 图 2.18：一些城市之间的航空网络

如前面的图所示，我们可以通过伊斯坦布尔或直接从伦敦到迪拜。从一个地方到另一个地方有多种方式，这在树的情况下是不可能的。此外，我们可以从一个节点遍历到另一个节点，然后通过一些不同的边回到原始节点，这在树中也是不可能的。

让我们实现前面图中所示的图的矩阵表示方法。

### 练习 11：实现图并将其表示为邻接矩阵

在这个练习中，我们将实现一个代表前面图中所示的城市网络的图，并演示如何将其存储为邻接矩阵。让我们开始吧：

1.  首先，让我们包括所需的头文件：

```cpp
#include <iostream>
#include <vector>
```

1.  现在，让我们添加一个`enum`类，以便我们可以存储城市的名称：

```cpp
enum class city: int
{
    LONDON,
    MOSCOW,
    ISTANBUL,
    DUBAI,
    MUMBAI,
    SEATTLE,
    SINGAPORE
};
```

1.  让我们还为`city`枚举添加`<<`运算符：

```cpp
std::ostream& operator<<(std::ostream& os, const city c)
{
    switch(c)
    {
        case city::LONDON:
            os << "LONDON";
            return os;
        case city::MOSCOW:
            os << "MOSCOW";
            return os;
        case city::ISTANBUL:
            os << "ISTANBUL";
            return os;
        case city::DUBAI:
            os << "DUBAI";
            return os;
        case city::MUMBAI:
            os << "MUMBAI";
            return os;
        case city::SEATTLE:
            os << "SEATTLE";
            return os;
        case city::SINGAPORE:
            os << "SINGAPORE";
            return os;
        default:
            return os;
    }
}
```

1.  现在，让我们编写`struct graph`，它将封装我们的数据：

```cpp
struct graph
{
    std::vector<std::vector<int>> data;
```

1.  现在，让我们添加一个构造函数，它将创建一个空图（没有任何边的图）并给定节点数：

```cpp
graph(int n)
{
    data.reserve(n);
    std::vector<int> row(n);
    std::fill(row.begin(), row.end(), -1);
    for(int i = 0; i < n; i++)
    {
        data.push_back(row);
    }
}
```

1.  现在，让我们添加最重要的函数——`addEdge`。它将接受三个参数——要连接的两个城市和边的权重（距离）：

```cpp
void addEdge(const city c1, const city c2, int dis)
{
    std::cout << "ADD: " << c1 << "-" << c2 << "=" << dis << std::endl;
    auto n1 = static_cast<int>(c1);
    auto n2 = static_cast<int>(c2);
    data[n1][n2] = dis;
    data[n2][n1] = dis;
}
```

1.  现在，让我们添加一个函数，这样我们就可以从图中删除一条边：

```cpp
void removeEdge(const city c1, const city c2)
{
    std::cout << "REMOVE: " << c1 << "-" << c2 << std::endl;
    auto n1 = static_cast<int>(c1);
    auto n2 = static_cast<int>(c2);
    data[n1][n2] = -1;
    data[n2][n1] = -1;
}
};
```

1.  现在，让我们编写`main`函数，以便我们可以使用这些函数：

```cpp
int main()
{
    graph g(7);
    g.addEdge(city::LONDON, city::MOSCOW, 900);
    g.addEdge(city::LONDON, city::ISTANBUL, 500);
    g.addEdge(city::LONDON, city::DUBAI, 1000);
    g.addEdge(city::ISTANBUL, city::MOSCOW, 1000);
    g.addEdge(city::ISTANBUL, city::DUBAI, 500);
    g.addEdge(city::DUBAI, city::MUMBAI, 200);
    g.addEdge(city::ISTANBUL, city::SEATTLE, 1500);
    g.addEdge(city::DUBAI, city::SINGAPORE, 500);
    g.addEdge(city::MOSCOW, city::SEATTLE, 1000);
    g.addEdge(city::MUMBAI, city::SINGAPORE, 300);
    g.addEdge(city::SEATTLE, city::SINGAPORE, 700);
    g.addEdge(city::SEATTLE, city::LONDON, 1800);
    g.removeEdge(city::SEATTLE, city::LONDON);
    return 0;
}
```

1.  执行此程序后，我们应该得到以下输出：

```cpp
ADD: LONDON-MOSCOW=900
ADD: LONDON-ISTANBUL=500
ADD: LONDON-DUBAI=1000
ADD: ISTANBUL-MOSCOW=1000
ADD: ISTANBUL-DUBAI=500
ADD: DUBAI-MUMBAI=200
ADD: ISTANBUL-SEATTLE=1500
ADD: DUBAI-SINGAPORE=500
ADD: MOSCOW-SEATTLE=1000
ADD: MUMBAI-SINGAPORE=300
ADD: SEATTLE-SINGAPORE=700
ADD: SEATTLE-LONDON=1800
REMOVE: SEATTLE-LONDON
```

正如我们所看到的，我们正在将数据存储在一个向量的向量中，两个维度都等于节点数。因此，这种表示所需的总空间与*V2*成正比，其中*V*是节点数。

### 将图表示为邻接表

矩阵表示图的一个主要问题是所需的内存量与节点数的平方成正比。可以想象，随着节点数的增加，这会迅速增加。让我们看看如何改进这一点，以便使用更少的内存。

在任何图中，我们将有固定数量的节点，每个节点将有固定数量的连接节点，等于总节点数。在矩阵中，我们必须存储所有节点的所有边，即使两个节点不直接连接。相反，我们只会在每一行中存储节点的 ID，指示哪些节点直接连接到当前节点。这种表示也称为**邻接表**。

让我们看看实现与之前练习的不同之处。

### 练习 12：实现图并将其表示为邻接表

在这个练习中，我们将实现一个代表城市网络的图，如*图 2.18*所示，并演示如何将其存储为邻接表。让我们开始吧：

1.  在这个练习中，我们将实现邻接表表示。让我们像往常一样从头文件开始：

```cpp
#include <iostream>
#include <vector>
#include <algorithm>
```

1.  现在，让我们添加一个`enum`类，以便我们可以存储城市的名称：

```cpp
enum class city: int
{
    MOSCOW,
    LONDON,
    ISTANBUL,
    SEATTLE,
    DUBAI,
    MUMBAI,
    SINGAPORE
};
```

1.  让我们还为`city`枚举添加`<<`运算符：

```cpp
std::ostream& operator<<(std::ostream& os, const city c)
{
    switch(c)
    {
        case city::MOSCOW:
            os << "MOSCOW";
            return os;
        case city::LONDON:
            os << "LONDON";
            return os;
        case city::ISTANBUL:
            os << "ISTANBUL";
            return os;
        case city::SEATTLE:
            os << "SEATTLE";
            return os;
        case city::DUBAI:
            os << "DUBAI";
            return os;
        case city::MUMBAI:
            os << "MUMBAI";
            return os;
        case city::SINGAPORE:
            os << "SINGAPORE";
            return os;
        default:
            return os;
    }
}
```

1.  让我们编写`struct graph`，它将封装我们的数据：

```cpp
struct graph
{
    std::vector<std::vector<std::pair<int, int>>> data;
```

1.  让我们看看我们的构造函数与矩阵表示有何不同：

```cpp
graph(int n)
{
    data = std::vector<std::vector<std::pair<int, int>>>(n, std::vector<std::pair<int, int>>());
}
```

正如我们所看到的，我们正在用 2D 向量初始化数据，但所有行最初都是空的，因为开始时没有边。

1.  让我们为此实现`addEdge`函数：

```cpp
void addEdge(const city c1, const city c2, int dis)
{
    std::cout << "ADD: " << c1 << "-" << c2 << "=" << dis << std::endl;
    auto n1 = static_cast<int>(c1);
    auto n2 = static_cast<int>(c2);
    data[n1].push_back({n2, dis});
    data[n2].push_back({n1, dis});
}
```

1.  现在，让我们编写`removeEdge`，这样我们就可以从图中移除一条边：

```cpp
void removeEdge(const city c1, const city c2)
{
    std::cout << "REMOVE: " << c1 << "-" << c2 << std::endl;
    auto n1 = static_cast<int>(c1);
    auto n2 = static_cast<int>(c2);
    std::remove_if(data[n1].begin(), data[n1].end(), n2
        {
            return pair.first == n2;
        });
    std::remove_if(data[n2].begin(), data[n2].end(), n1
        {
            return pair.first == n1;
        });
}
};
```

1.  现在，让我们编写`main`函数，这样我们就可以使用这些函数：

```cpp
int main()
{
    graph g(7);
    g.addEdge(city::LONDON, city::MOSCOW, 900);
    g.addEdge(city::LONDON, city::ISTANBUL, 500);
    g.addEdge(city::LONDON, city::DUBAI, 1000);
    g.addEdge(city::ISTANBUL, city::MOSCOW, 1000);
    g.addEdge(city::ISTANBUL, city::DUBAI, 500);
    g.addEdge(city::DUBAI, city::MUMBAI, 200);
    g.addEdge(city::ISTANBUL, city::SEATTLE, 1500);
    g.addEdge(city::DUBAI, city::SINGAPORE, 500);
    g.addEdge(city::MOSCOW, city::SEATTLE, 1000);
    g.addEdge(city::MUMBAI, city::SINGAPORE, 300);
    g.addEdge(city::SEATTLE, city::SINGAPORE, 700);
    g.addEdge(city::SEATTLE, city::LONDON, 1800);
    g.removeEdge(city::SEATTLE, city::LONDON);
    return 0;
}
```

执行此程序后，我们应该得到以下输出：

```cpp
ADD: LONDON-MOSCOW=900
ADD: LONDON-ISTANBUL=500
ADD: LONDON-DUBAI=1000
ADD: ISTANBUL-MOSCOW=1000
ADD: ISTANBUL-DUBAI=500
ADD: DUBAI-MUMBAI=200
ADD: ISTANBUL-SEATTLE=1500
ADD: DUBAI-SINGAPORE=500
ADD: MOSCOW-SEATTLE=1000
ADD: MUMBAI-SINGAPORE=300
ADD: SEATTLE-SINGAPORE=700
ADD: SEATTLE-LONDON=1800
REMOVE: SEATTLE-LONDON
```

由于我们为每个节点存储了一个相邻节点的列表，这种方法被称为邻接表。这种方法也使用了一个向量的向量来存储数据，就像前一种方法一样。但内部向量的维度不等于节点的数量；相反，它取决于边的数量。对于图中的每条边，根据我们的`addEdge`函数，我们将有两个条目。这种表示所需的内存将与 E 成正比，其中 E 是边的数量。

到目前为止，我们只看到了如何构建图。我们需要遍历图才能执行任何操作。有两种广泛使用的方法可用——广度优先搜索（BFS）和深度优先搜索（DFS），我们将在*第六章*，*图算法 I*中看到这两种方法。

## 总结

在本章中，我们看了与上一章相比更高级的问题类别，这有助于我们描述更广泛的现实场景。我们看了并实现了两种主要的数据结构——树和图。我们还看了我们可以在不同情况下使用的各种类型的树。然后，我们看了不同的方式来以编程方式表示这些结构的数据。通过本章的帮助，您应该能够应用这些技术来解决类似种类的现实世界问题。

现在我们已经看过线性和非线性数据结构，在下一章中，我们将看一个非常特定但广泛使用的概念，称为查找，目标是将值存储在容器中，以便搜索非常快速。我们还将看一下哈希的基本思想以及如何实现这样的容器。
