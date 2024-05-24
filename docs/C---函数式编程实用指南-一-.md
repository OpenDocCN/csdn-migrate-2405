# C++ 函数式编程实用指南（一）

> 原文：[`annas-archive.org/md5/873bfe33df74385c75906a2f129ca61f`](https://annas-archive.org/md5/873bfe33df74385c75906a2f129ca61f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎来到 C++中的函数式编程实践之旅！这本书讲述了一个古老的概念，即函数式编程，以及一个经典的编程语言，即 C++，最终联合起来。

函数式编程自上世纪 50 年代以来就存在；然而，由于其数学基础，多年来一直对主流软件开发的兴趣有限。随着多核 CPU 和大数据的出现导致需要并行化，以及编程语言设计者对不可变性和 lambda 表达式的兴趣增加，函数式编程概念逐渐被引入到包括 C＃、Java、PHP、JavaScript、Python 和 Ruby 在内的所有主要编程语言中。C++一直与函数式编程息息相关，例如函数指针、函数对象和 STL 中的算法等功能使许多程序员能够利用某些构造。然而，从 C++ 11 开始，我们看到了 lambda 的引入，以及`all_of`、`any_of`和`none_of`等高阶函数的引入。在 C++ 17 中，我们看到了更多的进展，包括`map`（实现为`transform`）。此外，C++ 20 中的功能也非常令人兴奋；例如，允许可组合、轻量级和惰性评估转换的 ranges 库是标准库的一个重要补充。

这就引出了你将从本书中学到的内容。无论您是经验丰富的程序员还是 C++初学者，您都将学习有关函数式编程概念的知识，以及如何在 C++中使用它们，以及它们对管理和改进现有代码库的有用性。每个想法都将通过清晰的代码示例展示，并通过单元测试进行验证；我们强烈建议您拿这些代码示例来自己尝试一下。

我们特别努力确保每个想法都以清晰的方式呈现，并且遵循理解的流程；换句话说，我们一直在优化您的学习体验。为了做到这一点，我们决定夸大使用某些构造。例如，示例代码大量使用 lambda，因为我们想展示它们的用法。我们认为学习函数式编程的最佳方式是充分了解 lambda 和对 lambda 的操作。我们期望读者能够将这种方法与生产方法区分开；事实上，我建议您自己尝试这些概念，然后在生产代码的小部分上进行实验，然后再充分利用那些有前途的概念。为了支持这一目标，我们记录了多种使用函数操作的方法，这样您将拥有足够的工具来在各种情境下使用。

需要注意的是，我们经过深思熟虑决定在大部分书中使用 C++ 17 标准。我们不使用外部库（除了单元测试库），并且坚持使用语言和 STL 的标准功能。重点是函数式编程概念以及如何使用最简化的方法来实现它们。唯一的例外是书的最后一部分，它涉及 C++和 STL 的未来。我们这样做是因为我们认为让您理解这些概念并准备好以最少的工具应用它们比提供多种实现选项更重要。这在大部分书中省略了 ranges 库、Boost 库对函数式编程的支持，以及其他可能的有用库，可以扩展或简化代码。我将把尝试它们的机会留给读者，并让我们知道它们的效果如何。

# 这本书适合谁

这本书适用于已经了解 C++（包括语言语法、STL 容器和模板元素）并希望为自己的工具箱增添更多工具的程序员。您不需要了解任何有关函数式编程的知识来阅读本书；我们已经以清晰实用的方式解释了每个想法。

然而，您需要对来自函数式编程世界的工具集感到好奇。大量的实验将帮助您充分利用本书，因此我鼓励您尝试运行代码，并告诉我们您的发现。

# 本书涵盖的内容

第一章《函数式编程简介》向您介绍了函数式编程的基本思想。

第二章《理解纯函数》教会您函数式编程的基本构建块，即侧重于不变性的函数，以及如何在 C++中编写它们。

第三章《深入了解 Lambda 表达式》侧重于 Lambda 表达式以及如何在 C++中编写它们。

第四章《函数组合的概念》探讨了如何使用高阶操作组合函数。

第五章《部分应用和柯里化》教会您如何在 C++中使用函数的两个基本操作——部分应用和柯里化。

第六章《函数式思维-从数据到数据输出》向您介绍了另一种组织代码的方式，实现以函数为中心的设计。

第七章《使用功能操作消除重复》是对“不要重复自己”（DRY）原则、代码重复和相似性类型以及如何使用功能操作（如组合、部分应用和柯里化）编写更加 DRY 代码的概述。

第八章《使用类改善内聚性》演示了函数如何演变为类，以及如何将类转换为函数。

第九章《函数式编程的测试驱动开发》探讨了如何在函数式编程中使用测试驱动开发（TDD），以及不变性和纯函数如何简化测试。

第十章《性能优化》深入探讨了如何优化以函数为中心设计的性能的具体方法，包括记忆化、尾递归优化和并行执行。

第十一章《基于属性的测试》探讨了函数式编程如何实现编写自动化测试的新范式，通过数据生成增强了基于示例的测试。

第十二章《重构到和通过纯函数》解释了任何现有代码如何被重构为纯函数，然后再次转换为类，而风险最小。它还涉及经典设计模式和一些函数式设计模式。

第十三章《不变性和架构-事件溯源》解释了不变性可以在数据存储级别上移动，介绍了如何使用事件溯源，并讨论了它的优缺点。

第十四章《使用 Ranges 库进行惰性求值》深入研究了强大的 Ranges 库，并演示了如何在 C++ 17 和 C++ 20 中使用它。

第十五章《STL 支持和提案》介绍了 C++ 17 标准中的 STL 功能特性，以及 C++ 20 的一些有趣的补充。

第十六章，*标准语言支持和提案*，总结了函数式编程的基本构建块以及在 C++ 17 标准中使用它们的各种选项。

# 充分利用本书

本书假定您对 C++语法和基本 STL 容器有很好的了解。但是，它并不假定您对函数式编程、函数式构造、范畴论或数学有任何了解。我们已经非常努力地确保每个概念都以清晰的方式从实际的、以程序员为中心的角度进行解释。

我们强烈建议您在阅读章节后玩弄代码，或者在完成章节后尝试复制样本中的代码。更好的是，选择一个编码卡塔（例如，来自[`codingdojo.org/kata/`](http://codingdojo.org/kata/)）问题，并尝试使用本书中的技术来解决它。通过阅读和玩弄代码的结合，您将学到更多，而不仅仅是阅读理论。

本书中的大部分内容需要您以不同的方式思考代码结构，有时这与您习惯的方式相悖。然而，我们认为函数式编程是您工具箱中的另一个工具；它并不与您已经知道的知识相矛盾，而是为您提供了额外的工具来用于生产代码。何时以及如何使用它们是您的决定。

要运行本书中的代码示例，您将需要`g++`和`make`命令。或者，您可以使用支持 C++ 17 的任何编译器运行示例，但您需要手动运行每个文件。所有代码示例都可以使用`make`或`make [specific example]`进行编译和自动运行，并在控制台上提供输出，但有一些注意事项需要遵循。

来自第十章的内存优化示例，*性能优化*，需要使用`make allMemoryLogs`或特定目标运行，需要在每个目标运行后按键盘，将在`out/`文件夹中创建日志文件，显示进程分配内存的演变。这仅适用于 Linux 系统。

来自第十章的反应式编程示例，*性能优化*，需要用户输入。只需输入数字，程序将以反应式方式计算它们是否为质数。即使在计算过程中，程序也应该接收输入。来自第十六章的代码示例，*标准语言支持和提案*，需要支持 C++20 的编译器；目前使用`g++-8`。您需要单独安装`g++-8`。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的以下工具解压或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Functional-Programming-with-Cpp`](https://github.com/PacktPublishing/Hands-On-Functional-Programming-with-Cpp)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 代码实例

访问以下链接以查看代码的执行情况：

[`bit.ly/2ZPw0KH`](http://bit.ly/2ZPw0KH)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。以下是一个例子：“在 STL 中，它是用`find_if`函数实现的。让我们看看它的运行情况。”

一块代码设置如下：

```cpp
class Number{
    public:
        static int zero(){ return 0; }
        static int increment(const int value){ return value + 1; }
}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体设置：

```cpp
First call: 1,367 ns < 16,281 ns
Second call: 58,045 ns < 890,056 ns Third call: 16,167 ns > 939 ns Fourth call: 1,334 ns > 798 ns
```

警告或重要说明看起来像这样。

提示和技巧看起来像这样。


# 第一部分：C++中的函数式编程基本组件

在本节中，我们将学习函数式编程的基本构建块以及如何在 C++中使用它们。首先，我们将了解函数式编程是什么，以及它与面向对象编程（OOP）有何不同和相似之处。然后，我们将深入了解不可变性的基本概念，并学习如何在 C++中编写纯函数——即不改变状态的函数。然后，我们将学习如何使用 lambda 表达式以及如何使用它们编写纯函数。

一旦我们掌握了这些基本组件，我们就可以继续进行函数操作。在函数式编程中，函数就是数据，因此我们可以传递它们并对它们进行操作。我们将学习部分应用和柯里化，这两个基本且密切相关的操作。我们还将看到如何组合函数。这些操作将使我们能够用几行简单的代码将简单的函数转变为非常复杂的函数。

本节将涵盖以下章节：

+   第一章，*函数式编程简介*

+   第二章，*理解纯函数*

+   第三章，*深入了解 Lambda*

+   第四章，*函数组合的概念*

+   第五章，*部分应用和柯里化*


# 第一章：函数式编程简介

为什么函数式编程有用？在过去的十年里，函数式编程构造已经出现在所有主要的编程语言中。程序员们享受了它们的好处——简化循环，更具表现力的代码，以及简单的并行化。但其中还有更多——脱离时间的耦合，提供消除重复、可组合性和更简单的设计的机会。更多人采用函数式编程（包括金融领域大规模采用 Scala）意味着一旦你了解并理解它，就会有更多的机会。虽然我们将在本书中深入探讨函数式编程，帮助你学习，但请记住，函数式编程是你工具箱中的另一个工具，当问题和上下文适合时，你可以选择使用它。

本章将涵盖以下主题：

+   函数式编程简介以及对你已经在使用的函数式构造的检查

+   结构化循环与函数式循环

+   不可变性

+   **面向对象编程**（**OOP**）与函数式设计

+   可组合性和消除重复

# 技术要求

代码适用于 g++ 7.3.0 和 C++ 17；它包括一个`makefile`以方便你使用。你可以在 GitHub 仓库（[`github.com/PacktPublishing/Hands-On-Functional-Programming-with-Cpp`](https://github.com/PacktPublishing/Hands-On-Functional-Programming-with-Cpp)）的`Chapter01`目录中找到它。

# 函数式编程简介

我第一次接触函数式编程是在大学。我是一个 20 岁的极客，对科幻小说、阅读和编程感兴趣；编程是我学术生活的亮点。对我来说，与 C++、Java、MATLAB 以及我们使用的其他一些编程语言有关的一切都很有趣。不幸的是，我不能说同样的话适用于电气工程、电路或编译器理论等学科。我只想写代码！

根据我的兴趣，函数式编程本应该是一门非常有趣的课程。我们的老师非常热情。我们不得不写代码。但出了些问题——我没有理解老师在告诉我们的内容。为什么列表如此有趣？为什么语法如此反向且充满括号？为什么我要使用这些东西，当用 C++写相同的代码要简单得多？最终我试图将我从 BASIC 和 C++中所知的所有编程构造翻译成 Lisp 和 OCaml。这完全错过了函数式编程的要点，但我通过了这门课程，多年来都忘记了它。

我想很多人都能理解这个故事，我对此有一个可能的原因。我现在相信，尽管我的老师非常热情，但采用了错误的方法。今天，我明白了函数式编程在其核心具有一定的优雅，因为它与数学有着密切的关系。但这种优雅需要一种深刻的洞察力，而我 20 岁时并没有，也就是说，我在多年的各种经历后才有幸建立起来的洞察力。现在对我来说很明显，学习函数式编程不应该与读者看到这种优雅的能力有关。

那么，我们可以使用什么方法呢？回想起过去的我，也就是那个只想写代码的极客，只有一种方法——看看代码中的常见问题，并探索函数式编程如何减少或完全消除这些问题。此外，从一开始就开始；你已经看到了函数式编程，已经使用了一些概念和构造，你甚至可能发现它们非常有用。让我们来看看为什么。

# 函数式编程构造随处可见

在我完成大学函数式编程课程大约 10 年后，我和我的朋友 Felix 闲聊。像所有的极客一样，我们很少见面，但多年来，我们一直在即时通讯中讨论各种书呆子话题，当然也包括编程。

不知何故，我们谈到了函数式编程这个话题。Felix 指出我最喜欢和最享受的编程语言之一，LOGO，实际上是一种函数式编程语言。

**LOGO**是一种教育性编程语言，其主要特点是利用所谓的**turtle graphics**。

回顾起来是显而易见的；以下是如何在 LOGO 的 KTurtle 版本中编写一个画正方形的函数：

```cpp
learn square {
    repeat 4 {forward 50 turnright 90}
}
```

结果显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-fp-cpp/img/45f3ee41-d99c-4630-8595-8f4b1e2aadbb.png)

你能看到我们是如何将两行代码传递给 repeat 函数的吗？这就是函数式编程！函数式编程的一个基本原则是，代码只是另一种类型的数据，可以被打包在一个函数中，并传递给其他函数。我在 LOGO 中使用了这个构造数百次，却没有意识到这一点。

这个认识让我想：是否还有其他函数式编程构造是我在不知情中使用的？事实证明，是的，还有。事实上，作为一个 C++程序员，你很可能也使用过它们；让我们看看一些例子：

```cpp
int add(const int base, const int exponent){
   return pow(base, exponent);
}
```

这个函数是推荐的 C++代码的典型例子。我最初是从 Bertrand Meyer 的惊人著作《Effective C++》、《More Effective C++》和《Effective STL》中了解到在任何地方都添加`const`的好处的。这个构造之所以有效有多个原因。首先，它保护了不应该改变的数据成员和参数。其次，它通过消除可能的副作用，使程序员更容易推理出函数中发生的事情。第三，它允许编译器优化函数。

事实证明，这也是不可变性的一个例子。正如我们将在接下来的章节中发现的那样，函数式编程将不可变性置于程序的核心，将所有的副作用移到程序的边缘。我们已经了解了函数式编程的基本构造；说我们使用函数式编程只是意味着我们更广泛地使用它！

以下是 STL 的另一个例子：

```cpp
std::vector aCollection{5, 4, 3, 2, 1};
sort (aCollection.begin(), aCollection.end());
```

STL 算法具有很大的威力；这种威力来自多态性。我使用这个术语的含义比在 OOP 中更基本——这仅仅意味着集合包含什么并不重要，因为只要实现了比较，算法就能正常工作。我必须承认，当我第一次理解它时，我对这个聪明、有效的解决方案印象深刻。

有一种`sort`函数的变体，允许在比较没有实现或者不按我们期望的情况下对元素进行排序；例如，当我们给出一个`Name`结构时，如下所示：

```cpp
using namespace std;

// Parts of code omitted for clarity
struct Name{
     string firstName;
     string lastName;
};
```

如果我们想要按照名字对`vector<Name>`容器进行排序，我们只需要一个`compare`函数：

```cpp
bool compareByFirstName(const Name& first, const Name& second){
     return first.firstName < second.firstName;
}
```

此外，我们需要将其传递给`sort`函数，如下面的代码所示：

```cpp
int main(){
    vector<Name> names = {Name("John", "Smith"), Name("Alex",
    "Bolboaca")};

    sort(names.begin(), names.end(), compareByFirstName);
}
// The names vector now contains "Alex Bolboaca", "John Smith"
```

这构成了一种*高阶函数*。高阶函数是一种使用其他函数作为参数的函数，以允许更高级别的多态性。恭喜——你刚刚使用了第二个函数式编程构造！

我甚至要说 STL 是函数式编程在实践中的一个很好的例子。一旦你了解更多关于函数式编程构造，你会意识到它们在 STL 中随处可见。其中一些，比如函数指针或者仿函数，已经存在于 C++语言中很长时间了。事实上，STL 经受住了时间的考验，那么为什么不在我们的代码中也使用类似的范式呢？

没有比 STL 中的函数式循环更好的例子来支持这个说法了。

# 结构化循环与函数式循环

作为程序员，我们学习的第一件事之一就是如何编写循环。我在 C++中的第一个循环是打印从`1`到`10`的数字：

```cpp
for(int i = 0; i< 10; ++i){
    cout << i << endl;
}
```

作为一个好奇的程序员，我曾经认为这种语法是理所当然的，研究了它的特殊之处和复杂性，然后就使用了它。回想起来，我意识到这种结构有一些不寻常的地方。首先，为什么要从`0`开始？我被告知这是一个惯例，出于历史原因。然后，`for`循环有三个语句——初始化、条件和增量。对于我们想要实现的目标来说，这听起来有点太复杂了。最后，结束条件让我犯了比我愿意承认的更多的偏差错误。

此时，您会意识到 STL 允许您在循环遍历集合时使用迭代器：

```cpp
for (list<int>::iterator it = aList.begin(); it != aList.end(); ++it)
      cout << *it << endl;
```

这绝对比使用游标的`for`循环要好。它避免了偏差错误，也没有`0`的惯例怪事。然而，该操作周围仍然有很多仪式感。更糟糕的是，随着程序复杂性的增加，循环往往会变得越来越大。

有一种简单的方法可以显示这种症状。让我们回顾一下我用循环解决的第一个问题。

让我们考虑一个整数向量并计算它们的总和；朴素的实现将如下所示：

```cpp
int sumWithUsualLoop(const vector<int>& numbers){
    int sum = 0;
    for(auto iterator = numbers.begin(); iterator < numbers.end(); 
    ++iterator){
        sum += *iterator;
    }
    return sum;
}
```

如果生产代码能如此简单就好了！相反，一旦我们实现了这段代码，就会得到一个新的需求。现在我们需要对向量中的偶数进行求和。嗯，这很容易，对吧？让我们看看下面的代码：

```cpp
int sumOfEvenNumbersWithUsualLoop(const vector<int>& numbers){
    int sum = 0;
    for(auto iterator = numbers.begin(); iterator<numbers.end(); 
    ++iterator){
        int number = *iterator;
        if (number % 2 == 0) sum+= number;
    }
    return sum;
}
```

如果你以为这就是结尾，那就错了。我们现在需要对同一个向量进行三次求和——偶数的和、奇数的和和总和。现在让我们添加一些更多的代码，如下所示：

```cpp
struct Sums{
    Sums(): evenSum(0),  oddSum(0), total(0){}
    int evenSum;
    int oddSum;
    int total;
};

const Sums sums(const vector<int>& numbers){
    Sums theTotals;
    for(auto iterator = numbers.begin(); iterator<numbers.end(); 
    ++iterator){
        int number = *iterator;
        if(number % 2 == 0) theTotals.evenSum += number;
        if(number %2 != 0) theTotals.oddSum += number;
        theTotals.total += number;
    }
    return theTotals;
}
```

我们最初相对简单的循环变得越来越复杂。当我开始专业编程时，我们常常责怪用户和客户无法确定完美功能并给出最终的冻结需求。然而，在现实中很少可能；我们的客户每天都从用户与我们编写的程序的互动中学到新的东西。我们有责任使这段代码清晰，而使用函数循环是可能的。

多年后，我学会了 Groovy。Groovy 是一种基于 Java 虚拟机的编程语言，它专注于通过帮助程序员编写更少的代码和避免常见错误来简化程序员的工作。以下是您如何在 Groovy 中编写先前的代码：

```cpp
def isEven(value){return value %2 == 0}
def isOdd(value){return value %2 == 1}
def sums(numbers){
   return [
      evenSum: numbers.filter(isEven).sum(),
      oddSum: numbers.filter(isOdd).sum(),
      total: numbers.sum()
   ]
}
```

让我们比较一下这两种方法。没有循环。代码非常清晰。没有办法犯偏差错误。没有计数器，因此也没有*从*`0`开始的怪异现象。此外，它周围没有支撑结构——我只需写出我想要实现的目标，一个经过训练的读者就可以轻松理解。

虽然 C++版本更冗长，但它允许我们实现相同的目标：

```cpp
const Sums sumsWithFunctionalLoops(const vector<int>& numbers){
    Sums theTotals;
    vector<int> evenNumbers;
    copy_if(numbers.begin(), numbers.end(), 
    back_inserter(evenNumbers), isEven);
    theTotals.evenSum = accumulate(evenNumbers.begin(), 
    evenNumbers.end(), 0);

    vector<int> oddNumbers;
    copy_if(numbers.begin(), numbers.end(), back_inserter(oddNumbers), 
    isOdd);
    theTotals.oddSum= accumulate(oddNumbers.begin(), oddNumbers.end(), 
    0);

    theTotals.total = accumulate(numbers.begin(), numbers.end(), 0);

    return theTotals;
}
```

尽管如此，仪式感仍然很浓重，而且代码相似度太高。因此，让我们摆脱它，如下所示：

```cpp
template<class UnaryPredicate>
const vector<int> filter(const vector<int>& input, UnaryPredicate filterFunction){
    vector<int> filtered;
    copy_if(input.begin(), input.end(), back_inserter(filtered), 
    filterFunction);
    return filtered;
}

const int sum(const vector<int>& input){
    return accumulate(input.begin(), input.end(), 0);
}

const Sums sumsWithFunctionalLoopsSimplified(const vector<int>& numbers){
    Sums theTotals(
        sum(filter(numbers, isEven)),
        sum(filter(numbers, isOdd)),
        sum(numbers)
    ); 
    return theTotals;
}
```

我们刚刚用一些更简单、更易读和可组合的函数替换了一个复杂的`for`循环。

那么，这段代码更好吗？嗯，这取决于你对“更好”的定义。我喜欢用优点和缺点来思考任何实现。函数式循环的优点是简单性、可读性、减少代码重复和可组合性。有什么缺点吗？嗯，我们最初的`for`循环只需要通过向量进行一次遍历，而我们当前的实现需要三次遍历。对于非常大的集合，或者当响应时间和内存使用非常重要时，这可能是一个负担。这绝对值得讨论，我们将在第十章中更详细地研究这个问题，即专注于函数式编程性能优化的*性能优化*。现在，我建议你专注于理解函数式编程的新工具。

为了做到这一点，我们需要重新思考不可变性。

# 不可变性

我们已经了解到，在 C++中，一定程度的不可变性是首选的；常见的例子如下：

```cpp
class ...{
    int add(const int& first, const int& second) const{
        return first + second;
    }
}
```

`const`关键字清楚地传达了代码的一些重要约束，例如以下内容：

+   函数在返回之前不会改变任何参数。

+   函数在其所属的类的任何数据成员之前不会更改。

现在让我们想象一个`add`的另一个版本，如下所示

```cpp
int uglyAdd(int& first, int& second){
    first = first + second;
    aMember = 40;
    return first;
}
```

我之所以称之为`uglyAdd`，是有原因的——我在编程时不容忍这样的代码！这个函数违反了最小惊讶原则，做了太多的事情。阅读函数代码并不能揭示其意图。想象一下调用者的惊讶，如果不小心的话，仅仅通过调用`add`函数，就会有两件事情发生变化——一个是传递的参数，另一个是函数所在的类。

虽然这是一个极端的例子，但它有助于支持不可变性的论点。不可变函数很无聊；它们接收数据，在接收的数据中不做任何改变，在包含它们的类中也不做任何改变，并返回一个值。然而，当涉及长时间维护代码时，无聊是好事。

不可变性是函数式编程中函数的核心属性。当然，你的程序中至少有一部分是不可变的——**输入/输出**（**I/O**）。我们将接受 I/O 的本质，并专注于尽可能增加我们代码的不可变性。

现在，你可能想知道是否你需要完全重新思考编写程序的方式。你是否应该忘记你学到的关于面向对象编程的一切？嗯，并不完全是这样，让我们看看为什么。

# 面向对象编程与函数式设计风格

我的工作的一个重要部分是与程序员合作，帮助他们改善编写代码的方式。为此，我尽力提出简单的解释复杂的想法。我对软件设计有一个这样的解释。对我来说，软件设计是我们构建代码的方式，使其最大程度地优化为业务目的。

我喜欢这个定义，因为它简单明了。但在我开始尝试函数式构造之后，有一件事让我感到困扰；即，函数式编程会导致出现以下代码：

```cpp
const Sums sumsWithFunctionalLoopsSimplified(const vector<int>& numbers){
    Sums theTotals(
        sum(filter(numbers, isEven)),
        sum(filter(numbers, isOdd)),
        sum(numbers)
    );
    return theTotals;
 }
```

在面向对象编程风格中编写类似的代码很可能意味着创建类并使用继承。那么，哪种风格更好？此外，如果软件设计涉及代码结构，那么这两种风格之间是否存在等价性？

首先，让我们看看这两种设计风格真正推广了什么。什么是面向对象编程？多年来，我相信了所有列出以下三个面向对象语言属性的书籍：

+   封装

+   继承

+   多态

作为面向对象编程(OOP)的思想家，Alan Kay 并不完全同意这个列表。对他来说，OOP 是关于许多小对象之间的通信。作为生物学专业的学生，他看到了将程序组织成身体组织细胞的机会，并允许对象像细胞一样进行通信。他更看重对象而不是类，更看重通信而不是通常列出的 OOP 特性。我最好地总结他的立场如下：系统中的动态关系比其静态属性更重要。

这改变了关于 OOP 范式的很多东西。那么，类应该与现实世界匹配吗？并不是真的。它们应该被优化以表示现实世界。我们应该专注于拥有清晰、深思熟虑的类层次结构吗？不，因为这些比对象之间的通信更不重要。我们能想到的最小对象是什么？嗯，要么是数据的组合，要么是函数。

在 Quora 的最近一个回答中（[`www.quora.com/Isnt-getting-rid-of-the-evil-state-like-Haskells-approach-something-every-programmer-should-follow/answer/Alan-Kay-11`](https://www.quora.com/Isnt-getting-rid-of-the-evil-state-like-Haskells-approach-something-every-programmer-should-follow/answer/Alan-Kay-11)），Alan Kay 在回答有关函数式编程的问题时提出了一个有趣的想法。函数式编程源自数学，也是为了模拟现实世界以实现人工智能的努力。这一努力遇到了以下问题——*Alex 在布加勒斯特* 和 *Alex 在伦敦* 都可能是真实的，但发生在不同的时间点。解决这个建模问题的方法是不可变性；也就是说，时间成为函数的一个参数，或者是数据结构中的一个数据成员。在任何程序中，我们可以将数据变化建模为数据的时间限定版本。没有什么能阻止我们将数据建模为小对象，将变化建模为函数。此外，正如我们将在后面看到的那样，我们可以轻松地将函数转换为对象，反之亦然。

因此，总结一下，Alan Kay 所说的 OOP 和函数式编程之间并没有真正的紧张关系。只要我们专注于增加代码的不可变性，并且专注于小对象之间的通信，我们可以一起使用它们，可以互换使用。在接下来的章节中，我们将发现用函数替换类，反之亦然是多么容易。

但是有很多使用 OOP 的方式与 Alan Kay 的愿景不同。我在客户那里看到了很多 C++ 代码，我见过一切——庞大的函数、巨大的类和深层次的继承层次结构。大多数情况下，我被叫来的原因是因为设计太难改变，添加新功能会变得非常缓慢。继承是一种非常强的关系，过度使用会导致强耦合，因此代码难以改变。长方法和长类更难理解和更难改变。当然，有些情况下继承和长类是有意义的，但总的来说，选择松散耦合的小对象能够实现可变性。

但是类可以被重用，对吗？我们能用函数做到吗？让我们下一个讨论这个话题。

# 可组合性和去除重复

我们已经看到了一个存在大量重复的例子：

```cpp
const Sums sumsWithFunctionalLoops(const vector<int>& numbers){
    Sums theTotals;
    vector<int> evenNumbers;
    copy_if(numbers.begin(), numbers.end(), back_inserter(evenNumbers), 
    isEven);
    theTotals.evenSum = accumulate(evenNumbers.begin(), 
    evenNumbers.end(), 0);

    vector<int> oddNumbers;
    copy_if(numbers.begin(), numbers.end(), back_inserter(oddNumbers), 
    isOdd);
    theTotals.oddSum= accumulate(oddNumbers.begin(), oddNumbers.end(), 
    0);

    theTotals.total = accumulate(numbers.begin(), numbers.end(), 0);

    return theTotals;
}
```

我们设法使用函数来减少它，如下面的代码所示：

```cpp
template<class UnaryPredicate>
const vector<int> filter(const vector<int>& input, UnaryPredicate filterFunction){
    vector<int> filtered;
    copy_if(input.begin(), input.end(), back_inserter(filtered), 
    filterFunction);
    return filtered;
}

const int sum(const vector<int>& input){
    return accumulate(input.begin(), input.end(), 0);
}

const Sums sumsWithFunctionalLoopsSimplified(const vector<int>& numbers){
    Sums theTotals(
        sum(filter(numbers, isEven)),
        sum(filter(numbers, isOdd)),
        sum(numbers)
    );

    return theTotals;
}
```

看到函数以各种方式组合是很有趣的；我们两次调用了 `sum(filter())`，并且一次调用了 `sum()`。此外，`filter` 可以与多个谓词一起使用。此外，通过一些工作，我们可以使 `filter` 和 `sum` 成为多态函数：

```cpp
template<class CollectionType, class UnaryPredicate>
const CollectionType filter(const CollectionType& input, UnaryPredicate filterFunction){
    CollectionType filtered;
    copy_if(input.begin(), input.end(), back_inserter(filtered), 
    filterFunction);
    return filtered;
}
template<typename T, template<class> class CollectionType>
const T sum(const CollectionType<T>& input, const T& init = 0){
    return accumulate(input.begin(), input.end(), init);
} 
```

现在很容易使用除了`vector<int>`之外的类型的参数调用`filter`和`sum`。实现并不完美，但它说明了我试图表达的观点，即小的不可变函数可以轻松变成多态和可组合的。当我们可以将函数传递给其他函数时，这种方法特别有效。

# 总结

我们已经涵盖了很多有趣的话题！你刚刚意识到你已经掌握了函数式编程的基础知识。你可以使用`const`关键字在 C++中编写不可变函数。你已经在 STL 中使用了高级函数。此外，你不必忘记面向对象编程的任何内容，而是从不同的角度来看待它。最后，我们发现了小的不可变函数如何组合以提供复杂的功能，并且如何借助 C++模板实现多态。

现在是时候深入了解函数式编程的构建模块，并学习如何在 C++中使用它们了。这包括纯函数、lambda 表达式，以及与函数相关的操作，如函数组合、柯里化或部分函数应用。

# 问题

1.  什么是不可变函数？

1.  如何编写不可变函数？

1.  不可变函数如何支持代码简洁性？

1.  不可变函数如何支持简单设计？

1.  什么是高级函数？

1.  你能从 STL 中举一个高级函数的例子吗？

1.  函数式循环相对于结构化循环有哪些优势？可能的缺点是什么？

1.  从 Alan Kay 的角度来看，面向对象编程是什么？它如何与函数式编程相关？


# 第二章：理解纯函数

纯函数是函数式编程的核心构建模块。它们是不可变的函数，这使它们简单和可预测。在 C++中编写纯函数很容易，但是有一些事情你需要注意。由于 C++中的函数默认是可变的，我们需要学习告诉编译器如何防止变异的语法。我们还将探讨如何将可变代码与不可变代码分开。

本章将涵盖以下主题：

+   理解纯函数是什么

+   在 C++中编写纯函数和使用元组返回多个参数的函数

+   确保 C++纯函数的不可变性

+   理解为什么 I/O 是可变的，需要与纯函数分开

# 技术要求

你需要一个支持 C++ 17 的 C++编译器。我使用的是 GCC 版本 7.3.0。代码示例在 GitHub（[`github.com/PacktPublishing/Hands-On-Functional-Programming-with-Cpp`](https://github.com/PacktPublishing/Hands-On-Functional-Programming-with-Cpp)）的`Chapter02`文件夹中，并且有一个`makefile`文件供您使用。

# 什么是纯函数？

让我们花点时间思考一个简单的日常体验。当你打开灯开关时，会发生两种情况之一：

+   如果灯是开着的，它就会关掉

+   如果灯是关着的，它就会打开

灯开关的行为是非常可预测的。它是如此可预测，以至于当灯不亮时，你立刻认为有什么地方出了问题——可能是灯泡、保险丝或开关本身。

以下是你打开或关闭开关时不希望发生的一些事情：

+   你的冰箱不会关掉

+   你邻居的灯不会亮起

+   你的浴室水槽不会打开

+   你的手机不会重置

当你打开灯开关时为什么会发生所有这些事情？那将是非常混乱的；我们不希望生活中出现混乱，对吧？

然而，程序员经常在代码中遇到这种行为。调用函数通常会导致程序状态的改变；当这种情况发生时，我们说函数具有**副作用**。

函数式编程试图通过广泛使用纯函数来减少状态变化引起的混乱。纯函数是具有两个约束的函数：

+   它们总是对相同的参数值返回相同的输出值。

+   它们没有副作用。

让我们探讨如何编写灯开关的代码。我们假设灯泡是一个我们可以调用的外部实体；把它看作我们程序的**输入/输出**（**I/O**）的输出。结构化/面向对象程序员的自然代码看起来可能是这样的：

```cpp
void switchLight(LightBulb bulb){
    if(switchIsOn) bulb.turnOff();
    else bulb.turnOn();
}
```

这个函数有两个问题。首先，它使用了不属于参数列表的输入，即`switchIsOn`。其次，它直接对灯泡产生了副作用。

那么，纯函数是什么样子的呢？首先，它的所有参数都是可见的：

```cpp
void switchLight(boolean switchIsOn, LightBulb bulb){    if(switchIsOn) 
    bulb.turnOff();
    else bulb.turnOn();
}
```

其次，我们需要消除副作用。我们该如何做呢？让我们将下一个状态的计算与打开或关闭灯泡的动作分开：

```cpp
LightBulbSignal signalForBulb(boolean switchIsOn){
    if(switchIsOn) return LightBulbSignal.TurnOff;
    else return LightBulbSignal.TurnOn;
}
// use the output like this: sendSignalToLightBulb(signalForBulb(switchIsOn))
```

该函数现在是纯的，我们稍后会更详细地讨论这一点；但是，现在让我们简化如下：

```cpp
LightBulbSignal signalForBulb(boolean switchIsOn){
    return switchIsOn ? LightBulbSignal.TurnOff :    
    LightBulbSignal.TurnOn;
}
// use the output like this: sendSignalToLightBulb(signalForBulb(switchIsOn))
```

让我们更清晰一些（我会假设该函数是一个类的一部分）：

```cpp
static LightBulbSignal signalForBulb(const boolean switchIsOn){
    return switchIsOn ? LightBulbSignal.TurnOff :  
    LightBulbSignal.TurnOn;
}
// use the output like this: sendSignalToLightBulb(signalForBulb(switchIsOn))
```

这个函数非常无聊：它非常可预测，易于阅读，而且没有副作用。这听起来就像一个设计良好的灯开关。而且，这正是我们在维护数十年的大量代码时所希望的。

我们现在了解了纯函数是什么以及它为什么有用。我们还演示了如何将纯函数与副作用（通常是 I/O）分离的例子。这是一个有趣的概念，但它能带我们到哪里？我们真的可以使用这样简单的构造来构建复杂的程序吗？我们将在接下来的章节中讨论如何组合纯函数。现在，让我们专注于理解如何在 C++中编写纯函数。

# C++中的纯函数

在前面的例子中，您已经看到了我们在 C++中需要使用的纯函数的基本语法。您只需要记住以下四个想法：

+   纯函数没有副作用；如果它们是类的一部分，它们可以是`static`或`const`。

+   纯函数不改变它们的参数，因此每个参数都必须是`const`、`const&`或`const* const`类型。

+   纯函数总是返回值。从技术上讲，我们可以通过输出参数返回一个值，但通常更简单的是直接返回一个值。这意味着纯函数通常没有 void 返回类型。

+   前面的观点都不能保证没有副作用或不可变性，但它们让我们接近了。例如，数据成员可以标记为可变，`const`方法可以改变它们。

在接下来的章节中，我们将探讨如何编写自由函数和类方法作为纯函数。当我们浏览示例时，请记住我们现在正在探索语法，重点是如何使用编译器尽可能接近纯函数。

# 没有参数的纯函数

让我们从简单的开始。我们可以在没有参数的情况下使用纯函数吗？当然可以。一个例子是当我们需要一个默认值时。让我们考虑以下例子：

```cpp
int zero(){return 0;}
```

这是一个独立的函数。让我们了解如何在类中编写纯函数：

```cpp
class Number{
    public:
        static int zero(){ return 0; }
}
```

现在，`static`告诉我们该函数不会改变任何非静态数据成员。但是，这并不能阻止代码改变`static`数据成员的值：

```cpp
class Number{
    private:
        static int accessCount;
    public:
        static int zero(){++accessCount; return 0;}
        static int getCount() { return accessCount; }
};
int Number::accessCount = 0;
int main(){
Number::zero();
cout << Number::getCount() << endl; // will print 1
}
```

幸运的是，我们会发现我们可以通过恰当使用`const`关键字来解决大多数可变状态问题。以下情况也不例外：

```cpp
static const int accessCount;
```

现在我们已经对如何编写没有参数的纯函数有了一些了解，是时候添加更多参数了。

# 带有一个或多个参数的纯函数

让我们从一个带有一个参数的纯类方法开始，如下面的代码所示：

```cpp
class Number{
    public:
        static int zero(){ return 0; }
        static int increment(const int value){ return value + 1; }
}
```

两个参数呢？当然，让我们考虑以下代码：

```cpp
class Number{
    public:
        static int zero(){ return 0; }
        static int increment(const int value){ return value + 1; }
        static int add(const int first, const int second){ return first  
        + second; }
};
```

我们可以用引用类型做同样的事情，如下所示：

```cpp
class Number{
    public:
        static int zero(){ return 0; }
        static int increment(const int& value){ return value + 1; }
        static int add(const int& first, const int& second){ return 
        first + second; }
};
```

此外，我们可以用指针类型做同样的事情，尽管有点更多的语法糖：

```cpp
class Number{
    public:
        static int incrementValueFromPointer(const int* const value )   
        {return *value + 1;}
};
```

恭喜——您现在知道如何在 C++中编写纯函数了！

嗯，有点；不幸的是，不可变性在 C++中实现起来比我们迄今所见到的要复杂一些。我们需要更深入地研究各种情况。

# 纯函数和不可变性

1995 年的电影《阿波罗 13 号》是我最喜欢的惊悚片之一。它涉及太空、一个真实的故事和多个工程问题。在许多令人难忘的场景中，有一个特别能教给我们很多关于编程的场景。当宇航员团队正在准备一个复杂的程序时，由汤姆·汉克斯扮演的指挥官注意到，他的同事在一个指令开关上贴了一张标签，上面写着“不要按动”。指挥官问他的同事为什么这样做，他的回答大致是“我的头脑不清醒，我害怕我会按动这个开关把你送上太空。所以，我写下这个来提醒自己不要犯这个错误。”

如果这种技术对宇航员有效，那么对程序员也应该有效。幸运的是，我们有编译器告诉我们何时做错了。但是，我们需要告诉编译器我们希望它检查什么。

毕竟，我们可以编写纯函数，而不需要任何`const`或`static`。函数纯度不是语法问题，而是一个概念。正确地放置标签可以防止我们犯错。然而，我们会看到，编译器只能做到这一点。

让我们看看另一种实现我们之前讨论过的递增函数的方法：

```cpp
class Number{
    public:
        int increment(int value){ return ++value; }
};
int main(){
    Number number;
    int output = number.increment(Number::zero());
    cout << output << endl;
 }
```

这不是一个纯函数。你能看出为什么吗？答案就在下一行：

```cpp
 int increment(int value){ return ++value; }
```

`++value`不仅会递增`value`，还会改变输入参数。虽然在这种情况下并不是问题（`value`参数是按值传递的，所以只有它的副本被修改），但这仍然是一个副作用。这显示了在 C++中编写副作用有多容易，或者在任何不默认强制不可变性的语言中。幸运的是，只要我们告诉编译器我们确切地想要什么，编译器就可以帮助我们。

回想一下之前的实现如下：

```cpp
 static int increment(const int value){ return value + 1; }
```

如果你尝试在这个函数的主体中写`++value`或`value++`，编译器会立即告诉你，你试图改变一个`const`输入参数。这真是太好了，不是吗？

那么通过引用传递的参数呢？

# 不可变性和通过引用传递

问题本来可能更糟。想象一下以下函数：

```cpp
 static int increment(int& value){ return ++value; }
```

我们避免了按值传递，这涉及更多的内存字节。但是值会发生什么变化呢？让我们看看以下代码：

```cpp
  int value = Number::zero(); //value is 0
      cout << Number::increment(value) << endl;
      cout << value << endl; // value is now 1
```

`value`参数开始为`0`，但当我们调用函数时，它被递增，所以现在它的`value`是`1`。这就像每次你打开灯时，冰箱门都会打开。幸运的是，如果我们只添加一个小小的`const`关键字，我们会看到以下结果：

```cpp
static int increment(const int& value) {return value + 1; }
```

然后，编译器再次友好地告诉我们，在函数体中不能使用`++value`或`value++`。

这很酷，但指针参数呢？

# 不可变性和指针

在使用指针作为输入参数时，防止不需要的更改变得更加复杂。让我们看看当我们尝试调用这个函数时会发生什么：

```cpp
  static int increment(int* pValue)
```

以下事情可能会改变：

+   `pValue`指向的值可能会改变。

+   指针可能会改变其地址。

`pValue`指向的值在类似条件下可能会改变，就像我们之前发现的那样。例如，考虑以下代码：

```cpp
 static int increment(int* pValue){ return ++*pValue; }
```

这将改变指向的值并返回它。要使其不可更改，我们需要使用一个恰到好处的`const`关键字：

```cpp
 static int increment(int* const pValue){ return *pValue + 1; }
```

指针地址的更改比你期望的要棘手。让我们看一个会以意想不到的方式行为的例子：

```cpp
class Number {
    static int* increment(int* pValue){ return ++pValue; }
}

int main(){
    int* pValue = new int(10);
    cout << "Address: " << pValue << endl;
    cout << "Increment pointer address:" <<   
    Number::incrementPointerAddressImpure(pValue) << endl;
    cout << "Address after increment: " << pValue << endl;
    delete pValue;
}
```

在我的笔记本上运行这个程序会得到以下结果：

```cpp
Address: 0x55cd35098e80
Increment pointer address:0x55cd35098e80
Address after increment: 0x55cd35098e80
Increment pointer value:10
```

地址不会改变，即使我们在函数中使用`++pValue`进行递增。`pValue++`也是如此，但为什么会这样呢？

嗯，指针地址是一个值，它是按值传递的，所以函数体内的任何更改只适用于函数范围。要使地址更改，您需要按引用传递地址，如下所示：

```cpp
 static int* increment(int*& pValue){ return ++pValue; }
```

这告诉我们，幸运的是，编写更改指针地址的函数并不容易。我仍然觉得告诉编译器强制执行这个规则更安全：

```cpp
 static int* increment(int* const& pValue){ return ++pValue; }
```

当然，这并不妨碍你改变指向的值：

```cpp
  static int* incrementPointerAddressAndValue(int* const& pValue){
      (*pValue)++;
      return pValue + 1;
  }
```

为了强制不可变性，无论是值还是地址，你需要使用更多的`const`关键字，如下面的代码所示：

```cpp
  static const int* incrementPointerAddressAndValuePure(const int* 
      const& pValue){
          (*pValue)++;//Compilation error
          return pValue + 1;
  }
```

这涵盖了所有类型的类函数。但是，C++允许我们在类外编写函数。那么在这种情况下，`static`还有效吗？（剧透警告：并不完全如你所期望）。

# 不可变性和非类函数

到目前为止的所有示例都假设函数是类的一部分。C++允许我们编写不属于任何类的函数。例如，我们可以编写以下代码：

```cpp
int zero(){ return 0; }
int increment(int& value){ return ++value; }
const int* incrementPointerAddressAndValuePure(const int* const& pValue){
    return pValue + 1;
}
```

您可能已经注意到我们不再使用`static`了。您可以使用`static`，但需要注意它对类中的函数具有完全不同的含义。应用于独立函数的`static`意味着*您无法从不同的翻译单元中使用它*；因此，如果您在 CPP 文件中编写函数，它将只在该文件中可用，并且链接器会忽略它。

我们已经涵盖了所有类型的类和非类函数。但是对于具有输出参数的函数呢？事实证明，它们需要一些工作。

# 不可变性和输出参数

有时，我们希望函数改变我们传入的数据。在**标准模板库**（**STL**）中有许多例子，其中最简单的一个例子是`sort`：

```cpp
vector<int> values = {324, 454, 12, 45, 54564, 32};
     sort(values.begin(), values.end());
```

然而，这并不符合纯函数的概念；`sort`的纯函数等价物如下：

```cpp
vector<int> sortedValues = pureSort(values);
```

我能听到你在想，“但 STL 实现是为了优化而在原地工作，那么纯函数是否 less optimized 呢？”事实证明，纯函数式编程语言，比如 Haskell 或 Lisp，也会优化这样的操作；`pureSort`的实现只会移动指针，并且只有在指向的值之一发生变化时才会分配更多的内存。然而，这是两种不同的上下文；C++必须支持多种编程范式，而 Haskell 或 Lisp 则优化了不可变性和函数式风格。我们将在第十章中进一步讨论优化，即*性能优化*。现在，让我们来看看如何使这些类型的函数成为纯函数。

我们已经发现了如何处理一个输出参数。但是我们如何编写纯函数，使其具有多个输出参数呢？让我们考虑以下例子：

```cpp
void incrementAll(int& first, int& second){
    ++first;
    ++second;
}
```

解决这个问题的一个简单方法是用`vector<int>`替换这两个参数。但是如果参数具有不同的类型会怎么样？那么，我们可以使用一个结构体。但如果这是我们唯一需要它的时候呢？幸运的是，STL 提供了解决这个问题的方法，即通过元组：

```cpp
const tuple<int, int> incrementAllPure(const int& first, const int&  
    second){
        return make_tuple(first + 1, second + 1);
 }
 int main(){
     auto results = incrementAllPure(1, 2);
     // Can also use a simplified version
     // auto [first, second] = incrementAllPure(1, 2);
     cout << "Incremented pure: " << get<0>(results) << endl;
     cout << "Incremented pure: " << get<1>(results) << endl;
 }
```

元组有许多优点，如下所示：

+   它们可以用于多个值。

+   这些值可以具有不同的数据类型。

+   它们易于构建——只需一个函数调用。

+   它们不需要额外的数据类型。

根据我的经验，当您尝试将具有多个输出参数的函数渲染为纯函数，或者返回值和输出参数时，元组是一个很好的解决方案。但是，我经常在设计完成后尝试将它们重构为命名的*struct*或数据类。尽管如此，使用元组是一个非常有用的技术；只是要适度使用。

到目前为止，我们已经使用了很多`static`函数。但它们不是不好的实践吗？嗯，这取决于很多因素；我们将在接下来更详细地讨论这个问题。

# `static`函数不是不好的实践吗？

到目前为止，您可能会想知道纯函数是否好，因为它们与**面向对象编程**（**OOP**）或干净的代码规则相矛盾，即避免使用`static`。然而，直到现在，我们只编写了`static`函数。那么，它们是好的还是坏的呢？

使用`static`函数有两个反对意见。

对`static`函数的第一个反对意见是它们隐藏了全局状态。由于`static`函数只能访问`static`值，这些值就成为了全局状态。全局状态是不好的，因为很难理解是谁改变了它，当其值出乎意料时也很难调试。

但要记住纯函数的规则——纯函数应该对相同的输入值返回相同的输出值。因此，只有当函数不依赖于全局状态时，函数才是纯的。即使程序有状态，所有必要的值也作为输入参数发送给纯函数。不幸的是，我们无法轻易地通过编译器来强制执行这一点；避免使用任何类型的全局变量并将其转换为参数，这必须成为程序员的实践。

对于这种情况，特别是在使用全局常量时有一个特例。虽然常量是不可变状态，但考虑它们的演变也很重要。例如，考虑以下代码：

```cpp
static const string CURRENCY="EUR";
```

在这里，你应该知道，总会有一个时刻，常量会变成变量，然后你将不得不改变大量的代码来实现新的要求。我的建议是，通常最好也将常量作为参数传递进去。

对`static`函数的第二个反对意见是它们不应该是类的一部分。我们将在接下来的章节中更详细地讨论这一观点；暂且可以说，类应该将具有内聚性的函数分组在一起，有时纯函数应该在类中整齐地组合在一起。将具有内聚性的纯函数分组在一个类中还有另一种选择——只需使用一个命名空间。

幸运的是，我们不一定要在类中使用`static`函数。

# 静态函数的替代方案

我们在前一节中发现了如何通过使用`static`函数在`Number`类中编写纯函数：

```cpp
class Number{
    public:
        static int zero(){ return 0; }
        static int increment(const int& value){ return value + 1; }
        static int add(const int& first, const int& second){ return  
        first + second; }
};
```

然而，还有另一种选择；C++允许我们避免`static`，但保持函数不可变：

```cpp
class Number{
    public:
        int zero() const{ return 0; }
        int increment(const int& value) const{ return value + 1; }
        int add(const int& first, const int& second) const{ return 
        first + second; }
};
```

每个函数签名后面的`const`关键字只告诉我们该函数可以访问`Number`类的数据成员，但永远不能改变它们。

如果我们稍微改变这段代码，我们可以在类的上下文中提出一个有趣的不可变性问题。如果我们用一个值初始化数字，然后总是加上初始值，我们就得到了以下代码：

```cpp
class Number{
    private:
        int initialValue;

    public:
        Number(int initialValue) : initialValue(initialValue){}
        int initial() const{ return initialValue; }
        int addToInitial(const int& first) const{ return first + 
        initialValue; }
};

int main(){
    Number number(10);
    cout << number.addToInitial(20) << endl;
}
```

这里有一个有趣的问题：`addToInitial`函数是纯的吗？让我们按照以下标准来检查：

+   它有副作用吗？不，它没有。

+   它对相同的输入值返回相同的输出值吗？这是一个棘手的问题，因为函数有一个隐藏的参数，即`Number`类或其初始值。然而，没有人可以从`Number`类的外部改变`initialValue`。换句话说，`Number`类是不可变的。因此，该函数将对相同的`Number`实例和相同的参数返回相同的输出值。

+   它改变了参数的值吗？嗯，它只接收一个参数，并且不改变它。

结果是函数实际上是纯的。我们将在下一章中发现它也是*部分应用函数*。

我们之前提到程序中的一切都可以是纯的，除了 I/O。那么，我们对执行 I/O 的代码怎么办？

# 纯函数和 I/O

看一下以下内容，并考虑该函数是否是纯的：

```cpp
void printResults(){
    int* pValue = new int(10);
    cout << "Address: " << pValue << endl;
    cout << "Increment pointer address and value pure:" <<    
    incrementPointerAddressAndValuePure(pValue) << endl;
    cout << "Address after increment: " << pValue << endl;
    cout << "Value after increment: " << *pValue << endl;
    delete pValue;
}
```

好吧，让我们看看——它没有参数，所以值没有改变。但与我们之前的例子相比，有些不对劲，也就是它没有返回值。相反，它调用了一些函数，其中至少有一个是纯的。

那么，它有副作用吗？嗯，几乎每行代码都有一个：

```cpp
cout << ....
```

这行代码在控制台上写了一行字符串，这是一个副作用！`cout`基于可变状态，因此它不是一个纯函数。此外，由于它的外部依赖性，`cout`可能会失败，导致异常。

尽管我们的程序中需要 I/O，但我们可以做什么呢？嗯，很简单——只需将可变部分与不可变部分分开。将副作用与非副作用分开，并尽量减少不纯的函数。

那么，我们如何在这里实现呢？嗯，有一个纯函数等待从这个不纯函数中脱颖而出。关键是从问题开始；所以，让我们将`cout`分离如下：

```cpp
string formatResults(){
    stringstream output;
    int* pValue = new int(500);
    output << "Address: " << pValue << endl;
    output << "Increment pointer address and value pure:" << 
    incrementPointerAddressAndValuePure(pValue) << endl;
    output << "Address after increment: " << pValue << endl;
    output << "Value after increment: " << *pValue << endl;
    delete pValue;
    return output.str();
}

void printSomething(const string& text){
    cout << text;
}

printSomething(formatResults());
```

我们将由`cout`引起的副作用移到另一个函数中，并使初始函数的意图更清晰——即格式化而不是打印。看起来我们很干净地将纯函数与不纯函数分开了。

但是我们真的吗？让我们再次检查`formatResults`。它没有副作用，就像以前一样。我们正在使用`stringstream`，这可能不是纯函数，并且正在分配内存，但所有这些都是函数内部的局部变量。

内存分配是副作用吗？分配内存的函数可以是纯函数吗？毕竟，内存分配可能会失败。但是，在函数中几乎不可能避免某种形式的内存分配。因此，我们将接受一个纯函数可能会在某种内存失败的情况下失败。

那么，它的输出呢？它会改变吗？嗯，它没有输入参数，但它的输出可以根据`new`运算符分配的内存地址而改变。所以，它还不是一个纯函数。我们如何使它成为纯函数呢？这很容易——让我们传入一个参数，`pValue`：

```cpp
string formatResultsPure(const int* pValue){
    stringstream output;
    output << "Address: " << pValue << endl;
    output << "Increment pointer address and value pure:" << 
    incrementPointerAddressAndValuePure(pValue) << endl;
    output << "Address after increment: " << pValue << endl;
    output << "Value after increment: " << *pValue << endl;
    return output.str();
}

int main(){
    int* pValue = new int(500);
    printSomething(formatResultsPure(pValue));
    delete pValue;
}
```

在这里，我们使自己与副作用和可变状态隔离。代码不再依赖 I/O 或`new`运算符。我们的函数是纯的，这带来了额外的好处——它只做一件事，更容易理解它的作用，可预测，并且我们可以很容易地测试它。

关于具有副作用的函数，考虑以下代码：

```cpp
void printSomething(const string& text){
    cout << text;
}
```

我认为我们都可以同意，很容易理解它的作用，只要我们的其他函数都是纯函数，我们可以安全地忽略它。

总之，为了获得更可预测的代码，我们应该尽可能地将纯函数与不纯函数分开，并尽可能将不纯函数推到系统的边界。在某些情况下，这种改变可能很昂贵，拥有不纯函数在代码中也是完全可以的。只要确保你知道哪个是哪个。

# 总结

在本章中，我们探讨了如何在 C++中编写纯函数。由于有一些需要记住的技巧，这里是推荐的语法列表：

+   通过值传递的类函数：

+   `static int increment(const int value)`

+   `int increment(const int value) const`

+   通过引用传递的类函数：

+   `static int increment(const int& value)`

+   `int increment(const int&value) const`

+   通过值传递指针的类函数：

+   `static const int* increment(const int* const value)`

+   `const int* increment(const int* const value) const`

+   通过引用传递的类函数：

+   `static const int* increment(const int* const& value)`

+   `const int* increment(const int* const& value) const`

+   通过值传递的独立函数：`int increment(const int value)`

+   通过引用传递的独立函数：`int increment(const int& value)`

+   通过值传递指针的独立函数：`const int* increment(const int* value)`

+   通过引用传递的独立函数：`const int* increment(const int* const& value)`

我们还发现，虽然编译器有助于减少副作用，但并不总是告诉我们函数是纯函数还是不纯函数。我们始终需要记住编写纯函数时要使用的标准，如下所示：

+   它总是对相同的输入值返回相同的输出值。

+   它没有副作用。

+   它不会改变输入参数的值。

最后，我们看到了如何将通常与 I/O 相关的副作用与我们的纯函数分离。这很容易，通常需要传入值并提取函数。

现在是时候向前迈进了。当我们将函数视为设计的一等公民时，我们可以做更多事情。为此，我们需要学习 lambda 是什么以及它们如何有用。我们将在下一章中学习这个。

# 问题

1.  什么是纯函数？

1.  不可变性与纯函数有什么关系？

1.  你如何告诉编译器防止对按值传递的变量进行更改？

1.  你如何告诉编译器防止对按引用传递的变量进行更改？

1.  你如何告诉编译器防止对按引用传递的指针地址进行更改？

1.  你如何告诉编译器防止对指针指向的值进行更改？


# 第三章：深入了解 Lambda

恭喜！你刚刚掌握了纯函数的力量！现在是时候进入下一个级别——纯函数的超级版本，或者传说中的 lambda。它们存在的时间比对象更长，它们有一个围绕它们的数学理论（如果你喜欢这种东西的话），并且它们非常强大，正如我们将在本章和下一章中发现的那样。

本章将涵盖以下主题：

+   理解 lambda 的概念和历史

+   如何在 C++中编写 lambda

+   纯函数与 lambda 的比较

+   如何在类中使用 lambda

# 技术要求

您将需要一个支持 C++ 17 的 C++编译器。代码可以在 GitHub 存储库（[`github.com/PacktPublishing/Hands-On-Functional-Programming-with-Cpp`](https://github.com/PacktPublishing/Hands-On-Functional-Programming-with-Cpp)）的`Chapter03`文件夹中找到。提供了一个`makefile`文件，以便您更轻松地编译和运行代码。

# 什么是 lambda？

那年是 1936 年。33 岁的数学家阿隆佐·邱奇发表了他关于数学基础的研究。在这样做的过程中，他创造了所谓的**lambda 演算**，这是最近创建的计算领域的模型。在与艾伦·图灵合作后，他随后证明了 lambda 演算等价于图灵机。这一发现的相关性对编程至关重要——这意味着我们可以通过使用 lambda 和利用 lambda 演算来为现代计算机编写任何程序。这就解释了为什么它被称为**lambda**——数学家们长期以来更喜欢用单个希腊字母来表示每个符号。但它到底是什么？

如果你忽略所有的数学符号，lambda 只是一个可以应用于变量或值的**纯函数**。让我们看一个例子。我们将学习如何在 C++中编写 lambda，但是现在我将使用 Groovy 语法，因为这是我知道的最简单的语法：

```cpp
def add = {first, second -> first + second}
add(1,2) //returns 3
```

`add`是一个 lambda。正如你所看到的，它是一个具有两个参数并返回它们的和的函数。由于 Groovy 具有可选类型，我不必指定参数的类型。此外，我不需要使用`return`语句来返回总和；它将自动返回最后一个语句的值。在 C++中，我们不能跳过类型或`return`语句，我们将在下一节中发现。

现在，让我们看一下 lambda 的另一个属性，即从上下文中捕获值的能力：

```cpp
def first = 5
def addToFirst = {second -> first + second}
addToFirst(10) // returns 5 + 10 = 15
```

在这个例子中，`first`不是函数的参数，而是在上下文中定义的变量。lambda *捕获*变量的值并在其主体内使用它。我们可以利用 lambda 的这个属性来简化代码或逐渐重构向不可变性。

我们将在未来的章节中探讨如何使用 lambda；现在，让我们演示如何在 C++中编写它们，如何确保它们是不可变的，以及如何从上下文中捕获值。

# C++中的 lambda

我们探讨了如何在 Groovy 中编写 lambda。那么，我们可以在 C++中使用它们的功能吗？自 C++ 11 以来，引入了特定的语法。让我们看看我们的`add` lambda 在 C++中会是什么样子：

```cpp
int main(){
    auto add = [](int first, int second){ return first + second;};
    cout << add(1,2) << endl; // writes 3
}
```

让我们按照以下方式解释语法：

+   我们的 lambda 以`[]`开始。这个块指定了我们从上下文中捕获的变量，我们将看到如何在一会儿使用它。由于我们没有捕获任何东西，这个块是空的。

+   接下来，我们有参数列表，`(int first, int second)`，就像任何其他 C++函数一样。

+   最后，我们编写 lambda 的主体，使用 return 语句：`{ return first + second; }`。

语法比 Groovy 有点更加正式，但感觉像 C++，这是一件好事；统一性有助于我们记住事情。

或者，我们可以使用箭头语法，如下面的代码所示：

```cpp
    auto add = [](int first, int second) -> int { return first +   
        second;};
```

箭头语法是 lambda 的标志，自从 Alonzo Church 在他的 lambda 演算中使用这种符号以来。除此之外，C++要求在 lambda 主体之前指定返回类型，这可能在涉及类型转换的情况下提供了清晰度。

由于历史原因，箭头语法以某种方式存在于所有函数式编程语言中。在 C++中很少有用，但是如果你想要习惯函数式编程，了解它是很有用的。

现在是时候探索如何从上下文中捕获变量了。正如我们之前提到的，这都在`[]`块中。

# 捕获变量

那么，如果我们想要捕获变量呢？在 Groovy 中，我们只需在 lambda 范围内使用变量。这在 C++中行不通，因为我们需要指定我们要捕获的变量以及捕获它们的方式。因此，如果我们只在`add` lambda 中使用`first`变量，我们将得到以下编译错误：

```cpp
int main(){
    int first = 5;
    auto addToFirst = [](int second){ return first + second;}; 
    // error: variable 'first' cannot be implicitly captured 
    cout << add(10) << endl;
}
```

为了在 C++中捕获变量，我们需要在`[]`块内使用捕获说明符。有多种方法可以做到这一点，具体取决于你的需求。最直观的方法是直接写出我们要捕获的变量的名称。在我们的情况下，由于我们要捕获第一个变量，我们只需要在 lambda 参数前添加`[first]`：

```cpp
int main(){
    int first = 5;
    auto addToFirst = first{ return first + second;};
    cout << addToFirst(10) << endl; // writes 15
}
```

正如我们将看到的，这意味着`first`变量是按值捕获的。由于 C++给程序员提供了很多控制权，我们期望它提供特定的语法来按引用捕获变量。现在，让我们更详细地探讨捕获语法。

# 按值和按引用捕获变量

我们知道按值捕获变量的说明符只是写变量的名称，即`[first]`。这意味着变量被复制，因此我们浪费了一些内存。解决方案是通过引用捕获变量。捕获说明符的语法非常直观——我们可以将变量名作为`[&first]`引用：

```cpp
int main(){
    int first = 5;
    auto addToFirstByReference = &first{ return first + 
        second;};
    cout << addToFirstByReference(10) << endl; // writes 15
}
```

我知道你在想什么：lambda 现在可以修改`first`变量的值吗，因为它是按引用传递的？剧透警告——是的，它可以。我们将在下一节重新讨论不可变性、纯函数和 lambda。现在，还有更多的语法要学习。例如，如果我们想要从上下文中捕获多个变量，我们是否必须在捕获说明符中写出它们所有？事实证明，有一些快捷方式可以帮助你避免这种情况。

# 捕获多个值

那么，如果我们想要捕获多个值呢？让我们探索一下如果我们添加了五个捕获的值，我们的 lambda 会是什么样子：

```cpp
    int second = 6;
    int third = 7;
    int fourth = 8;
    int fifth = 9;

    auto addTheFive = [&first, &second, &third, &fourth, &fifth]()   
    {return first + second + third + fourth + fifth;};
    cout << addTheFive() << endl; // writes 35
```

我们当前的语法有点多余，不是吗？我们可以使用默认捕获说明符。幸运的是，语言设计者也是这么想的；注意 lambda 参数前的`[&]`语法：

```cpp
    auto addTheFiveWithDefaultReferenceCapture = [&](){return first + second + third + fourth + fifth;};
    cout << addTheFiveWithDefaultReferenceCapture() << endl; // writes 35
```

`[&]`语法告诉编译器从上下文中引用所有指定的变量。这是*默认按引用捕获*说明符。

如果我们想要复制它们的值，我们需要使用*默认按值捕获*说明符，你需要记住这是唯一使用这种方式的地方。注意 lambda 参数前的`[=]`语法：

```cpp
auto addTheFiveWithDefaultValueCapture = [=](){return first + 
second + third + fourth + fifth;};
cout << addTheFiveWithDefaultValueCapture() << endl; // writes 35
```

`[=]`语法告诉编译器所有变量都将通过复制它们的值来捕获。至少，默认情况下是这样。如果出于某种原因，你想要除了`first`之外的所有变量都通过值传递，那么你只需将默认与变量说明符结合起来：

```cpp
auto addTheFiveWithDefaultValueCaptureForAllButFirst = [=, &first](){return first + second + third + fourth + fifth;};
cout << addTheFiveWithDefaultValueCaptureForAllButFirst() << endl; // writes 35
```

我们现在知道了如何按值和按引用捕获变量，以及如何使用默认说明符。这使我们留下了一个重要类型的变量——指针。

# 捕获指针值

指针只是简单的值。如果我们想要按值捕获指针变量，我们可以像下面的代码中那样写它的名称：

```cpp
    int* pFirst = new int(5);
    auto addToThePointerValue = pFirst{return *pFirst + 
        second;};
    cout << addToThePointerValue(10) << endl; // writes 15
    delete pFirst;
```

如果我们想要按引用捕获指针变量，捕获语法与捕获任何其他类型的变量相同：

```cpp
auto addToThePointerValue = &pFirst{return *pFirst + 
    second;};
```

默认的限定符的工作方式正如你所期望的那样；也就是说，`[=]`通过值来捕获指针变量：

```cpp
 auto addToThePointerValue = ={return *pFirst + second;};
```

相比之下，`[&]`通过引用来捕获指针变量，如下面的代码所示：

```cpp
    auto addToThePointerValue = &{return *pFirst + 
    second;};
```

我们将探讨通过引用捕获变量对不可变性可能产生的影响。但首先，由于有多种捕获 lambda 变量的方式，我们需要检查我们更喜欢哪一种，以及何时使用它们。

# 我们应该使用什么捕获？

我们已经看到了一些捕获值的选项，如下所示：

+   命名变量以通过值来捕获它；例如，`[aVariable]`

+   命名变量并在前面加上引用限定符以通过引用来捕获它；例如，`[&aVariable]`

+   使用默认值限定符通过值来捕获所有使用的变量；语法是`[=]`

+   使用默认引用限定符通过引用来捕获所有使用的变量；语法是`[&]`

实际上，我发现使用默认值限定符是大多数情况下最好的版本。这可能受到我偏好不改变捕获值的非常小的 lambda 的影响。我相信简单性非常重要；当你有多个选项时，很容易使语法比必要的更复杂。仔细考虑每个上下文，并使用最简单的语法；我的建议是从`[=]`开始，只有在需要时才进行更改。

我们已经探讨了如何在 C++中编写 lambda。我们还没有提到它们是如何实现的。当前的标准将 lambda 实现为一个在堆栈上创建的具有未知类型的 C++对象。就像任何 C++对象一样，它背后有一个类，有一个构造函数，一个析构函数，以及捕获的变量作为数据成员存储。我们可以将 lambda 传递给`function<>`对象，这样`function<>`对象将存储 lambda 的副本。此外，*lambda 使用延迟评估*，不同于`function<>`对象。

Lambda 似乎是编写纯函数的一种更简单的方法；那么，lambda 和纯函数之间的关系是什么？

# Lambda 和纯函数

我们在第二章中学到，纯函数具有三个特征：

+   它们总是对相同的参数值返回相同的值

+   它们没有副作用

+   它们不改变其参数的值

我们还发现在编写纯函数时需要注意不可变性。只要我们记得在哪里放置`const`关键字，这很容易。

那么，lambda 如何处理不可变性？我们需要做一些特殊的事情吗，还是它们只是工作？

# Lambda 的不可变性和通过值传递的参数

让我们从一个非常简单的 lambda 开始，如下所示：

```cpp
auto increment = [](int value) { 
    return ++value;
};
```

在这里，我们通过值传递参数，所以我们在调用 lambda 后不希望值发生任何改变：

```cpp
    int valueToIncrement = 41;
    cout << increment(valueToIncrement) << endl;// prints 42
    cout << valueToIncrement << endl;// prints 41
```

由于我们复制了值，我们可能使用了一些额外的内存字节和额外的赋值。我们可以添加一个`const`关键字来使事情更清晰：

```cpp
auto incrementImmutable = [](const int value) { 
    return value + 1;
};
```

由于`const`限定符，如果 lambda 尝试改变`value`，编译器将会报错。

但我们仍然通过值传递参数；那么通过引用传递呢？

# Lambda 的不可变性和通过引用传递的参数

让我们探讨当我们调用这个 lambda 时对输入参数的影响：

```cpp
auto increment = [](int& value) { 
    return ++value;
};
```

事实证明，这与你所期望的相当接近：

```cpp
int valueToIncrement = 41;
cout << increment(valueToIncrement) << endl;// prints 42
cout << valueToIncrement << endl;// prints 42
```

在这里，lambda 改变了参数的值。这还不够好，所以让我们使其不可变，如下面的代码所示：

```cpp
auto incrementImmutable = [](const int& value){
    return value + 1;
};
```

编译器会再次通过错误消息帮助我们，如果 lambda 尝试改变`value`。

好了，这样更好了；但指针呢？

# Lambda 的不可变性和指针参数

就像我们在第二章中看到的那样，关于指针参数有两个问题，如下所示：

+   lambda 能改变指针地址吗？

+   lambda 能改变指向的值吗？

再次，如果我们按值传递指针，地址不会改变：

```cpp
auto incrementAddress = [](int* value) { 
    return ++value;
};

int main(){
    int* pValue = new int(41);
    cout << "Address before:" << pValue << endl;
    cout << "Address returned by increment address:" <<   
    incrementAddress(pValue) << endl;
    cout << "Address after increment address:" << pValue << endl;
}

Output:
Address before:0x55835628ae70
Address returned by increment address:0x55835628ae74
Address after increment address:0x55835628ae70
```

通过引用传递指针会改变这一点：

```cpp
auto incrementAddressByReference = [](int*& value) { 
    return ++value;
};

void printResultsForIncrementAddressByReference(){
    int* pValue = new int(41);
    int* initialPointer = pValue;
    cout << "Address before:" << pValue << endl;
    cout << "Address returned by increment address:" <<    
    incrementAddressByReference(pValue) << endl;
    cout << "Address after increment address:" << pValue << endl;
    delete initialPointer;
}

Output:
Address before:0x55d0930a2e70
Address returned by increment address:0x55d0930a2e74
Address after increment address:0x55d0930a2e74
```

因此，我们需要再次使用适当的`const`关键字来保护自己免受这种变化的影响：

```cpp
auto incrementAddressByReferenceImmutable = [](int* const& value) { 
    return value + 1;
};

Output:
Address before:0x557160931e80
Address returned by increment address:0x557160931e84
Address after increment address:0x557160931e80
```

让我们也使值不可变。如预期的那样，我们需要另一个`const`关键字：

```cpp
auto incrementPointedValueImmutable = [](const int* const& value) { 
    return *value + 1;
};
```

虽然这样可以工作，但我建议您更倾向于使用更简单的方式传递`[](const int& value)`值，也就是说，只需对指针进行解引用并将实际值传递给 lambda 表达式，这将使参数语法更容易理解和更可重用。

所以，毫不意外！我们可以使用与纯函数相同的语法来确保不可变性。

但是 lambda 表达式能调用可变函数吗，比如 I/O 呢？

# Lambda 表达式和 I/O

测试 lambda 表达式和 I/O 的更好方法是`Hello, world`程序：

```cpp
auto hello = [](){cout << "Hello, world!" << endl;};

int main(){
    hello();
}
```

显然，lambda 表达式无法防止调用可变函数。这并不奇怪，因为我们对纯函数也学到了同样的事情。这意味着，类似于纯函数，程序员需要特别注意将 I/O 与其余可能是不可变的代码分开。

由于我们试图让编译器帮助我们强制实施不可变性，我们能为捕获的值做到这一点吗？

# Lambda 表达式的不可变性和捕获值

我们已经发现 lambda 表达式可以从上下文中捕获变量，无论是按值还是按引用。那么，这是否意味着我们可以改变它们的值呢？让我们来看看：

```cpp
int value = 1;
auto increment = [=](){return ++value;};
```

这段代码立即给出了一个编译错误——*无法对按值捕获的变量赋值*。这比按值传递参数要好，也就是说，不需要使用`const`关键字——它可以按预期工作。

# 按引用捕获的值的不可变性

那么，通过引用捕获的值呢？好吧，我们可以使用默认的引用说明符`[&]`，并在调用我们的`increment` lambda 之前和之后检查变量的值：

```cpp
void captureByReference(){
    int value = 1;
    auto increment = [&](){return ++value;};

    cout << "Value before: " << value << endl;
    cout << "Result of increment:" << increment() << endl;
    cout << "Value after: " << value << endl;
}

Output:
Value before: 1
Result of increment:2
Value after: 2
```

如预期的那样，`value`发生了变化。那么，我们如何防止这种变化呢？

不幸的是，没有简单的方法可以做到这一点。C++假设如果您通过引用捕获变量，您想要修改它们。虽然这是可能的，但它需要更多的语法糖。具体来说，我们需要捕获其转换为`const`类型的内容，而不是变量本身：

```cpp
#include <utility>
using namespace std;
...

    int value = 1;
    auto increment = [&immutableValue = as_const(value)](){return  
        immutableValue + 1;};

Output:
Value before: 1
Result of increment:2
Value after: 1
```

如果可以选择，我更喜欢使用更简单的语法。因此，除非我真的需要优化性能，我宁愿使用按值捕获的语法。

我们已经探讨了如何在捕获值类型时使 lambda 表达式不可变。但是在捕获指针类型时，我们能确保不可变性吗？

# 按值捕获的指针的不可变性

当我们使用指针时，事情变得有趣起来。如果我们按值捕获它们，就无法修改地址：

```cpp
    int* pValue = new int(1);
    auto incrementAddress = [=](){return ++pValue;}; // compilation 
    error
```

然而，我们仍然可以修改指向的值，就像下面的代码所示：

```cpp
    int* pValue = new int(1);
    auto increment= [=](){return ++(*pValue);};

Output:
Value before: 1
Result of increment:2
Value after: 2
```

限制不可变性需要一个`const int*`类型的变量：

```cpp
    const int* pValue = new int(1);
    auto increment= [=](){return ++(*pValue);}; // compilation error
```

然而，有一个更简单的解决方案，那就是只捕获指针的值：

```cpp
 int* pValue = new int(1);
 int value = *pValue;
 auto increment = [=](){return ++value;}; // compilation error
```

# 按引用捕获的指针的不可变性

通过引用捕获指针允许您改变内存地址：

```cpp
 auto increment = [&](){return ++pValue;};
```

我们可以使用与之前相同的技巧来强制内存地址的常量性：

```cpp
 auto increment = [&pImmutable = as_const(pValue)](){return pImmutable 
    + 1;};
```

然而，这变得相当复杂。这样做的唯一原因是由于以下原因：

+   我们希望避免最多复制 64 位

+   编译器不会为我们进行优化

最好还是坚持使用按值传递的值，除非您想在 lambda 表达式中进行指针运算。

现在您知道了 lambda 表达式在不可变性方面的工作原理。但是，在我们的 C++代码中，我们习惯于类。那么，lambda 表达式和类之间有什么关系呢？我们能将它们结合使用吗？

# Lambda 表达式和类

到目前为止，我们已经学习了如何在 C++中编写 lambda 表达式。所有的例子都是在类外部使用 lambda 表达式，要么作为变量，要么作为`main()`函数的一部分。然而，我们的大部分 C++代码都存在于类中。这就引出了一个问题——我们如何在类中使用 lambda 表达式呢？

为了探讨这个问题，我们需要一个简单类的例子。让我们使用一个表示基本虚数的类：

```cpp
class ImaginaryNumber{
    private:
        int real;
        int imaginary;

    public:
        ImaginaryNumber() : real(0), imaginary(0){};
        ImaginaryNumber(int real, int imaginary) : real(real), 
        imaginary(imaginary){};
};
```

我们想要利用我们新发现的 lambda 超能力来编写一个简单的`toString`函数，如下面的代码所示：

```cpp
string toString(){
    return to_string(real) + " + " + to_string(imaginary) + "i";
}
```

那么，我们有哪些选择呢？

嗯，lambda 是简单的变量，所以它们可以成为数据成员。或者，它们可以是`static`变量。也许我们甚至可以将类函数转换为 lambda。让我们接下来探讨这些想法。

# Lambda 作为数据成员

让我们首先尝试将其写为成员变量，如下所示：

```cpp
class ImaginaryNumber{
...
    public:
        auto toStringLambda = [](){
            return to_string(real) + " + " + to_string(imaginary) +  
             "i";
        };
...
}
```

不幸的是，这导致编译错误。如果我们想将其作为非静态数据成员，我们需要指定 lambda 变量的类型。为了使其工作，让我们将我们的 lambda 包装成`function`类型，如下所示：

```cpp
include <functional>
...
    public:
        function<string()> toStringLambda = [](){
            return to_string(real) + " + " + to_string(imaginary) +    
            "i";
        };
```

函数类型有一个特殊的语法，允许我们定义 lambda 类型。`function<string()>`表示函数返回一个`string`值并且不接收任何参数。

然而，这仍然不起作用。我们收到另一个错误，因为我们没有捕获正在使用的变量。我们可以使用到目前为止学到的任何捕获。或者，我们可以捕获`this`：

```cpp
 function<string()> toStringLambda = [this](){
     return to_string(real) + " + " + to_string(imaginary) + 
     "i";
 };
```

因此，这就是我们可以将 lambda 作为类的一部分编写，同时捕获类的数据成员。在重构现有代码时，捕获`this`是一个有用的快捷方式。但是，在更持久的情况下，我会避免使用它。最好直接捕获所需的变量，而不是整个指针。

# Lambda 作为静态变量

我们还可以将我们的 lambda 定义为`static`变量。我们不能再捕获值了，所以我们需要传入一个参数，但我们仍然可以访问`real`和`imaginary`私有数据成员：

```cpp
    static function<string(const ImaginaryNumber&)>   
         toStringLambdaStatic;
...
// after class declaration ends
function<string(const ImaginaryNumber&)> ImaginaryNumber::toStringLambdaStatic = [](const ImaginaryNumber& number){
    return to_string(number.real) + " + " + to_string(number.imaginary)  
        + "i";
};

// Call it
cout << ImaginaryNumber::toStringLambdaStatic(Imaginary(1,1)) << endl;
// prints 1+1i
```

# 将静态函数转换为 lambda

有时，我们需要将`static`函数转换为 lambda 变量。在 C++中，这非常容易，如下面的代码所示：

```cpp
static string toStringStatic(const ImaginaryNumber& number){
    return to_string(number.real) + " + " + to_string(number.imaginary)  
    + "i";
 }
string toStringUsingLambda(){
    auto toStringLambdaLocal = ImaginaryNumber::toStringStatic;
    return toStringLambdaLocal(*this);
}
```

我们可以简单地将一个来自类的函数分配给一个变量，就像在前面的代码中所示的那样：

```cpp
  auto toStringLambdaLocal = ImaginaryNumber::toStringStatic;
```

然后我们可以像使用函数一样使用变量。正如我们将要发现的那样，这是一个非常强大的概念，因为它允许我们在类内部定义函数时组合函数。

# Lambda 和耦合

在 lambda 和类之间的交互方面，我们有很多选择。它们既可以变得令人不知所措，也可以使设计决策变得更加困难。

虽然了解选项是好的，因为它们有助于进行困难的重构，但通过实践，我发现在使用 lambda 时最好遵循一个简单的原则；也就是说，选择减少 lambda 与代码其余部分之间耦合区域的选项是最好的。

例如，我们已经看到我们可以将我们的 lambda 写成类中的`static`变量：

```cpp
function<string(const ImaginaryNumber&)> ImaginaryNumber::toStringLambdaStatic = [](const ImaginaryNumber& number){
    return to_string(number.real) + " + " + to_string(number.imaginary)  
        + "i";
};
```

这个 lambda 的耦合区域与`ImaginaryNumber`类一样大。但它只需要两个值：实部和虚部。我们可以很容易地将它重写为一个纯函数，如下所示：

```cpp
auto toImaginaryString = [](auto real, auto imaginary){
    return to_string(real) + " + " + to_string(imaginary) + "i";
};
```

如果由于某种原因，您决定通过添加成员或方法、删除成员或方法、将其拆分为多个类或更改数据成员类型来更改虚数的表示，这个 lambda 将不需要更改。当然，它需要两个参数而不是一个，但参数类型不再重要，只要`to_string`对它们有效。换句话说，这是一个多态函数，它让您对表示数据结构的选项保持开放。

但我们将在接下来的章节中更多地讨论如何在设计中使用 lambda。

# 总结

你刚刚获得了 lambda 超能力！你不仅可以在 C++中编写简单的 lambda，还知道以下内容：

+   如何从上下文中捕获变量

+   如何指定默认捕获类型——按引用或按值

+   如何在捕获值时编写不可变的 lambda

+   如何在类中使用 lambda

我们还提到了低耦合设计原则以及 lambda 如何帮助实现这一点。在接下来的章节中，我们将继续提到这一原则。

如果我告诉你，lambda 甚至比我们目前所见到的更强大，你会相信吗？好吧，我们将发现通过函数组合，我们可以从简单的 lambda 发展到复杂的 lambda。

# 问题

1.  你能写出最简单的 lambda 吗？

1.  如何编写一个将作为参数传递的两个字符串值连接起来的 lambda？

1.  如果其中一个值是被值捕获的变量会发生什么？

1.  如果其中一个值是被引用捕获的变量会发生什么？

1.  如果其中一个值是被值捕获的指针会发生什么？

1.  如果其中一个值是被引用捕获的指针会发生什么？

1.  如果两个值都使用默认捕获说明符被值捕获会发生什么？

1.  如果两个值都使用默认捕获说明符被引用捕获会发生什么？

1.  如何在一个类的数据成员中写入与两个字符串值作为数据成员相同的 lambda？

1.  如何在同一个类中将相同的 lambda 写为静态变量？


# 第四章：函数组合的概念

在过去的章节中，我们已经学习了如何编写纯函数和 lambda。这些是函数式编程的基本构建模块。现在是时候将它们提升到下一个级别了。

在这一章中，我们将学习如何从现有的函数中获得更多功能，从而从我们迄今为止所看到的简单示例中构建复杂的行为。

本章将涵盖以下主题：

+   在 C++中组合函数

+   具有多个参数的函数的基本分解策略

+   使用函数组合消除重复（或代码相似性）

# 技术要求

您将需要一个支持 C++ 17 的编译器。我使用的是 GCC 7.3.0。

该代码位于 GitHub 上的[`github.com/PacktPublishing/Hands-On-Functional-Programming-with-Cpp`](https://github.com/PacktPublishing/Hands-On-Functional-Programming-with-Cpp)中，位于`Chapter04`文件夹中。它包括并使用`doctest`，这是一个单头开源单元测试库。您可以在其 GitHub 存储库中找到它：[`github.com/onqtam/doctest`](https://github.com/onqtam/doctest)。

# 什么是函数组合？

纯函数和 lambda 是函数式编程的基本组成部分。但到目前为止，我们所看到的所有示例都使用非常简单的函数。在我们的行业中，我们显然处理着更复杂的问题。然而，正如我们所看到的，我们仍然希望我们的基本组成部分非常简单，因为我们希望能够轻松理解和维护它们。那么，我们如何能够从迄今为止所看到的简单 lambda 和纯函数创建复杂的程序呢？函数式编程有一个简单的答案——让我们通过组合我们拥有的简单函数来创建更复杂的函数。在函数式编程中创建复杂函数的基本方法是函数组合。

# 函数组合

从本质上讲，函数组合非常简单。我们将使用一个基本示例来说明它。我们将从我们的`increment`函数开始。从现在开始，我将使用测试用例来展示代码的工作原理。我正在使用`doctest`，这是一个单头开源单元测试库([`github.com/onqtam/doctest`](https://github.com/onqtam/doctest))。

让我们看看我们的`increment`函数及其测试用例：

```cpp
auto increment = [](const int value) { return value + 1; };

TEST_CASE("Increments value"){
    CHECK_EQ(2, increment(1));
}
```

我们还可以说，出于某种原因，我们需要两次增加值。由于我们在思考函数，我们希望重用我们的函数。因此，我们可以调用它两次：

```cpp
TEST_CASE("Increments twice"){
    CHECK_EQ(3, increment(increment(1)));
}
```

如果我们只需要在代码中的一个地方进行双重增量，那么这样做是可以的。如果我们需要在代码中的多个地方进行双重增量，我们将需要一个函数。很容易提取一个执行双重增量的函数：

```cpp
auto incrementTwiceLambda = [](int value){return increment(increment(value));};

TEST_CASE("Increments result of addition with lambda"){
    CHECK_EQ(3, incrementTwiceLambda(1));
}
```

如果我们看`incrementTwiceLambda`，我们可以看到它是由对`increment`的结果调用`increment`形成的。

让我们暂且不谈它，转而讨论另一个情况。我们现在想要计算一个数字的平方，仍然使用函数。这很容易写，再次：

```cpp
auto square = [](int value){ return value * value; };

TEST_CASE("Squares the number"){
    CHECK_EQ(4, square(2));
}
```

我们的下一个要求是计算一个值的增加平方。我们可以再次提取一个 lambda，将`increment`和`square`组合在一起，因为我们需要它们：

```cpp
auto incrementSquareLambda = [](int value) { return increment(square(value));};

TEST_CASE("Increments the squared number"){
    CHECK_EQ(5, incrementSquareLambda(2));
}

```

这很好。然而，我们在代码中有一个隐藏的相似之处。让我们看看`incrementTwiceLambda`和`incrementSquareLambda`函数：

```cpp
auto incrementTwiceLambda = [](int value){ return increment(increment(value)); };
auto incrementSquareLambda = [](int value) { return increment(square(value)); };
```

它们都有相同的模式——我们通过让一个函数`f`调用另一个函数`g`应用于传递给我们的函数`C`的值的结果来创建一个函数`C`。这是一种我们可以期望在使用小的纯函数时经常看到的代码相似性。最好有一个名称，甚至可能有一种方法来实现它，而不需要写太多样板代码。

事实证明，它确实有一个名字——这就是函数组合。一般来说，对于任何具有单个参数的*f*或*g*函数，我们可以按照以下方式获得一个函数*C*：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-fp-cpp/img/332f1ee6-da2c-45e7-8605-58a475e6b52f.png) 意味着对于*x*的每个值，![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-fp-cpp/img/fc102ff6-21a4-45e8-aa49-1b6bf0f9daf7.png)。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-fp-cpp/img/14204b22-3e95-49e7-b99f-9726698eca8d.png)符号是函数组合的数学运算符。

正如你所看到的，我们实际上正在尝试通过对函数本身进行操作来获得其他函数！这是一种使用 lambda 而不是数字的微积分类型，并定义了对 lambda 的操作。Lambda 演算是一个合适的名称，你不觉得吗？

这就是函数组合的概念。下一个问题是-我们能否消除样板代码？

# 在 C++中实现函数组合

如果我们能有一个运算符，允许我们执行函数组合，那就太好了。事实上，其他编程语言提供了一个；例如，在 Groovy 中，我们可以使用`<<`运算符如下：

```cpp
def incrementTwiceLambda = increment << increment
def incrementSquareLambda = increment << square
```

不幸的是，C++（尚）没有标准的函数组合运算符。但是，C++是一种强大的语言，因此应该可以为有限的情况编写自己的执行函数组合的函数。

首先，让我们清楚地定义问题。我们希望有一个`compose`函数，它接收两个 lambda，`f`和`g`，并返回一个调用`value -> f(g(value)`的新 lambda。在 C++中最简单的实现看起来像下面的代码：

```cpp
auto compose(auto f, auto g){
    return f, g{ return f(g(x); };
}

TEST_CASE("Increments twice with composed lambda"){
    auto incrementTwice = compose(increment, increment);
    CHECK_EQ(3, incrementTwice(1));
}
```

不幸的是，这段代码无法编译，因为 C++不允许使用`auto`类型的参数。一种方法是指定函数类型：

```cpp
function<int(int)> compose(function<int(int)> f,  function<int(int)> g){
    return f, g{ return f(g(x); };
}

TEST_CASE("Increments twice with composed lambda"){
    auto incrementTwice = compose(increment, increment);
    CHECK_EQ(3, incrementTwice(1));
}
```

这很好地运行并通过了测试。但现在我们的`compose`函数取决于函数类型。这并不是很有用，因为我们将不得不为我们需要的每种类型的函数重新实现`compose`。虽然比以前的样板代码少了，但仍然远非理想。

但这正是 C++模板解决的问题类型。也许它们可以帮助：

```cpp
template <class F, class G>
auto compose(F f, G g){
    return ={return f(g(value));};
}

TEST_CASE("Increments twice with composed lambda"){
    auto incrementTwice = compose(increment, increment);
    CHECK_EQ(3, incrementTwice(1));
}

TEST_CASE("Increments square with composed lambda"){
    auto incrementSquare = compose(increment, square);
    CHECK_EQ(5, incrementSquare(2));
}
```

事实上，这段代码有效！因此，我们现在知道，尽管 C++中没有函数组合的运算符，但我们可以用一个优雅的函数来实现它。

请注意，compose 返回一个 lambda，它使用惰性评估。因此，我们的函数组合函数也使用惰性评估。这是一个优势，因为组合的 lambda 只有在我们使用它时才会初始化。

# 函数组合不是可交换的

重要的是要意识到函数组合不是可交换的。事实上，当我们说话时很容易理解-“值的增量平方”与“增量值的平方”是不同的。然而，在代码中我们需要小心，因为这两者只是 compose 函数参数顺序不同而已：

```cpp
auto incrementSquare = compose(increment, square);
auto squareIncrement = compose(square, increment);
```

我们已经看到了函数组合是什么，如何在 C++中实现它，以及如何在简单情况下使用它。我敢打赌你现在渴望尝试它，用于更复杂的程序。我们会到那里的，但首先让我们看看更复杂的情况。多参数函数怎么办？

# 复杂的函数组合

我们的 compose 函数有一个问题-它只能与接收一个参数的 lambda 一起使用。那么，如果我们想要组合具有多个参数的函数，我们该怎么办呢？

让我们看下面的例子-给定两个 lambda，`multiply`和`increment`：

```cpp
auto increment = [](const int value) { return value + 1; };
auto multiply = [](const int first, const int second){ return first * second; };
```

我们能否获得一个增加乘法结果的 lambda？

不幸的是，我们不能使用我们的`compose`函数，因为它假定两个函数都有一个参数：

```cpp
template <class F, class G>
auto compose(F f, G g){
    return ={return f(g(value));};
}
```

那么，我们有哪些选择呢？

# 实现更多的组合函数

我们可以实现`compose`函数的变体，它接受一个接收一个参数的函数`f`，和另一个接收两个参数的函数`g`：

```cpp
template <class F1, class G2>
auto compose12(F1 f, G2 g){
    return ={ return f(g(first, second)); };
}

TEST_CASE("Increment result of multiplication"){
    CHECK_EQ(5, compose12(increment, multiply)(2, 2));
}
```

这个解决方案足够简单。但是，如果我们需要获得一个函数，它将增加其参数的值，我们需要另一个`compose`变体：

```cpp
template <class F2, class G1>
auto compose21(F2 f, G1 g){
    return ={ return f(g(first), g(second)); };
}

TEST_CASE("Multiplies two incremented values"){
    CHECK_EQ(4, compose21(multiply, increment)(1, 1));
}
```

如果我们只想增加其中一个参数怎么办？有很多可能的组合，虽然我们可以用多个 compose 变体来覆盖它们，但也值得考虑其他选项。

# 分解具有多个参数的函数

而不是实现更多的 compose 变体，我们可以查看`multiply`函数本身：

```cpp
auto multiply = [](const int first, const int second){ return first *  
    second; };
```

我们可以使用一个技巧将其分解为两个分别接收一个参数的 lambda。关键思想是 lambda 只是一个值，因此它可以被函数返回。我们已经在我们的`compose`函数中看到了这一点；它创建并返回一个新的 lambda：

```cpp
template <class F, class G>
auto compose(F f, G g){
    return ={return f(g(value));};
}
```

因此，我们可以通过返回一个捕获上下文中的`first`参数的单参数 lambda 来分解具有两个参数的函数：

```cpp
auto multiplyDecomposed = [](const int first) { 
    return ={ return first * second; }; 
};

TEST_CASE("Adds using single parameter functions"){
    CHECK_EQ(4, multiplyDecomposed(2)(2));
}
```

让我们解开这段代码，因为它非常复杂：

+   `multiplyDecomposed`接收一个参数`first`，并返回一个 lambda。

+   返回的 lambda 捕获了上下文中的`first`。

+   然后接收一个参数`second`。

+   它返回了`first`和`second`的加法结果。

事实证明，任何具有两个参数的函数都可以像这样分解。因此，我们可以使用模板编写一个通用实现。我们只需要使用相同的技巧——将函数类型指定为模板类型，并继续在我们的分解中使用它：

```cpp
template<class F>
auto decomposeToOneParameter(F f){
    return ={
        return ={
            return f(first, second);
        };
    };
}

TEST_CASE("Multiplies using single parameter functions"){
    CHECK_EQ(4, decomposeToOneParameter(multiply)(2)(2));
}
```

这种方法很有前途；它可能简化我们的函数组合实现。让我们看看它是否有效。

# 增加乘法结果

让我们朝着我们的目标前进。我们能否使用`compose`来获得一个增加乘法结果的函数？现在很容易，因为`add`已经分解成了接收一个参数的 lambda。我们期望只需将`multiplyDecomposed`与`increment`组合起来：

```cpp
TEST_CASE("Increment result of multiplication"){
    int first = 2;
    int second = 2;
    auto incrementResultOfMultiplication = compose(increment, 
        multiplyDecomposed);
    CHECK_EQ(5, incrementResultOfMultiplication(first)(second));
}
```

然而，这不会编译。我们的 compose 函数假设`multiplyDecomposed(first)`的结果可以传递给 increment。但是`multiplyDecompose(first)`返回一个 lambda，而`increment`接收一个整数。

因此，我们需要将`increment`与`multipyDecomposed(first)`组合：

```cpp
TEST_CASE("Increment result of multiplication"){
    int first = 2;
    int second = 2;
    auto incrementResultOfMultiplication = compose(increment, 
        multiplyDecomposed(first));
    CHECK_EQ(5, incrementResultOfMultiplication(second));
}
```

这样做是有效的，但我们还没有实现我们的目标。我们没有获得一个接收两个值的函数；相反，在将其与`increment`函数组合时，第一个值被传递给了`multiplyDecomposed`。

幸运的是，这是使用 lambda 的完美场所，如下面的代码所示：

```cpp
TEST_CASE("Increment result of multiplication final"){
    auto incrementResultOfMultiplication = [](int first, int second) {
        return compose(increment, multiplyDecomposed(first))(second);
    };

    CHECK_EQ(5, incrementResultOfMultiplication(2, 2));
}
```

这绝对有效，我们实现了我们的目标！`incrementResultOfMultiplication` lambda 接收两个参数并返回乘法的增量。不过，如果我们不必重写`multiply`就更好了。幸运的是，我们有我们的`decomposeToOneParameter`函数来帮助我们：

```cpp
TEST_CASE("Increment result of multiplication"){
    auto incrementResultOfMultiplication = [](int first, int second) { 
        return compose(increment, decomposeToOneParameter(multiply) 
            (first)) (second);
 };
    int result = incrementResultOfMultiplication(2, 2);
    CHECK_EQ(5, result);
}
```

现在是时候看看反向组合了——如果我们想要将两个参数的增量相乘呢？

# 乘法增量

我们希望通过使用我们的`compose`函数获得一个将参数的增量相乘的函数。不使用`compose`的最简单的代码如下：

```cpp
TEST_CASE("Multiply incremented values no compose"){
    auto multiplyIncrementedValues = [](int first, int second){
        return multiply(increment(first), increment(second)); 
    };
    int result = multiplyIncrementedValues(2, 2);
    CHECK_EQ(9, result);
}
```

正如我们所见，如果我们想要使用我们的 compose 版本，我们首先需要分解`multiply`lambda：

```cpp
TEST_CASE("Multiply incremented values decompose"){
    auto multiplyIncrementedValues = [](int first, int second){
        return multiplyDecomposed(increment(first))(increment(second)); 
    };
    int result = multiplyIncrementedValues(2, 2);
    CHECK_EQ(9, result);
}
```

现在我们可以看到对`multiplyDecomposed(increment(first))`的调用，这是`multiplyDecomposed`和`increment`之间的组合。我们可以用我们的`compose`函数替换它，如下面的代码所示：

```cpp
TEST_CASE("Multiply incremented values compose simple"){
    auto multiplyIncrementedValues = [](int first, int second){
        return compose(multiplyDecomposed, increment)(first)
            (increment(second)); 
    };

    int result = multiplyIncrementedValues(2, 2);
    CHECK_EQ(9, result);
}
```

再次强调，如果我们不必重写我们的`multiply`函数就好了。但是请记住，我们实现了一个有用的函数，可以将具有两个参数的任何函数分解为具有一个参数的两个函数。我们不必重写`multiply`；我们只需在其上调用我们的分解实用程序：

```cpp
TEST_CASE("Multiply incremented values decompose first"){
    auto multiplyIncrementedValues = [](int first, int second){
        return compose(
                decomposeToOneParameter(multiply), 
                increment
               )(first)(increment(second)); 
    };
    int result = multiplyIncrementedValues(2, 2);
    CHECK_EQ(9, result);
}
```

我们实现了我们的目标！

# 对函数的组合和分解的反思

让我们花点时间来看看结果和我们的工作方法。好消息是，我们在学习如何以函数思维的方式思考方面取得了良好的进展。我们之前的例子只需在代码中操作函数作为一等公民就可以工作，这正是我们在设计应用程序时需要的思维方式。函数的分解和重组非常强大；掌握它，你将能够用很少的代码实现非常复杂的行为。

至于结果代码，它具有一个有趣的属性——我们可以将其泛化以在许多函数组合上重用。

但我们还没有完成！我们可以使用这些函数来从我们的代码中删除某些类型的重复。让我们看看如何做到这一点。

# 使用函数组合来消除重复

到目前为止，我们已经看到了如何以各种方式编写组合 lambda 的函数。但是代码往往会重复，因此我们希望使这种方法更加通用。我们确实可以进一步进行；让我们看几个例子。

# 泛化增量乘法结果

让我们再看看我们的`incrementResultOfMultiplication` lambda：

```cpp
 auto incrementResultOfMultiplication = [](int first, int second) { 
     return compose(increment, decomposeToOneParameter(multiply) 
        (first))(second);
  };
```

这里有一些有趣的东西——它并不特定于“增量”和“乘法”。由于 lambda 只是值，我们可以将它们作为参数传递并获得一个通用的`composeWithTwoParameters`函数：

```cpp
template <class F, class G>
auto composeWithTwoParameters(F f, G g){
    return = { 
        return compose(
                f, 
                decomposeToOneParameter(g)(first)
                )(second);
   };
};

TEST_CASE("Increment result of multiplication"){
    auto incrementResultOfMultiplication =  
    composeWithTwoParameters(increment, multiply);
    int result = incrementResultOfMultiplication(2, 2);
    CHECK_EQ(5, result);
}
```

这个函数允许我们*组合任何其他两个函数*，`f` *和* `g`*，其中* `g` *接受两个参数，* `f` *只接受一个参数*。

让我们再做一些。让我们泛化`multiplyIncrementedValues`。

# 泛化增量乘法结果

同样，我们可以轻松地泛化我们的`multiplyIncrementedValues` lambda，如下面的代码所示：

```cpp
    auto multiplyIncrementedValues = [](int first, int second){
        return compose(
                 decomposeToOneParameter(multiply), 
                 increment
                 )(first)(increment(second)); 
    };
```

同样，我们需要将“乘法”和“增量”lambda 作为参数传递：

```cpp
template<class F, class G>
auto composeWithFunctionCallAllParameters(F f, G g){
    return ={
        return compose(
                decomposeToOneParameter(f), 
                g 
                )(first)(g(second)); 
    };
};

TEST_CASE("Multiply incremented values generalized"){
    auto multiplyIncrementedValues = 
    composeWithFunctionCallAllParameters(multiply, increment);
    int result = multiplyIncrementedValues(2, 2);
    CHECK_EQ(9, result);
}
```

我们可以使用这个新函数来创建一个函数*C*，它实现了`g(f(first), f(second))`，无论`g`和`f`是什么。

我们目前的工作已经完成。

# 总结

如果你认为纯函数和 lambda 很强大，那么现在你将意识到通过组合它们可以做多少事情！在本章中，您学会了什么是函数组合以及如何在 C++中组合函数。

我们还做了一件更重要的事情。在本章中，我们真正开始思考函数。以下是我们学到的一些东西：

+   lambda 只是一个值，所以我们可以有返回 lambda 的函数，或者返回 lambda 的 lambda。

+   此外，我们可以有接收一个或多个 lambda 并返回一个新 lambda 的函数。

+   任何具有多个参数的函数都可以分解为具有单个参数和捕获值的多个 lambda。

+   函数的操作非常复杂。如果你感到头晕，没关系——我们一直在玩强大而抽象的概念。

+   在各种组合函数的方式上立即想出解决方案是非常困难的。最好的方法是一步一步地进行，设定明确的目标和清晰的思路，并使用本章中描述的技术来改进。

+   函数组合可以帮助消除某些类型的重复；例如，当您有多个具有相似签名的不同函数之间的多个组合时。

+   然而，像我们在本章中所做的那样实现 compose 函数族是有成本的——更高的抽象级别。理解对 lambda 执行操作的函数的工作方式非常困难；确实，相信我，我也很难理解结果。但是，一旦您理解了它们的目标，它们就非常容易使用。

经过所有这些努力，让我们花点时间考虑一下结果。想象一下，您已经在代码库中拥有的任何两个函数，或者您使用的库中的任何两个函数，都可以通过一个函数调用组合并表示为变量。此外，这些调用可以堆叠；您获得的函数甚至可以进一步组合。函数组合非常强大；通过非常简单的 lambda 和一些函数操作，我们可以非常快速地实现复杂的行为。

我们已经看到了如何组合两个函数。我们还需要学习函数的另一个操作——通过玩弄参数来获得新函数。

# 问题

1.  什么是函数组合？

1.  函数组合具有通常与数学运算相关联的属性。是什么？

1.  如何将具有两个参数的`add`函数转换为具有一个参数的两个函数？

1.  你如何编写一个包含两个单参数函数的 C++函数？

1.  函数组合的优势是什么？

1.  在函数操作的实施中有哪些潜在的缺点？
