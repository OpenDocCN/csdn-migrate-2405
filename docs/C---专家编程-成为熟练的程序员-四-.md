# C++ 专家编程：成为熟练的程序员（四）

> 原文：[`annas-archive.org/md5/f9404739e16292672f830e964de1c2e4`](https://annas-archive.org/md5/f9404739e16292672f830e964de1c2e4)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：并发和多线程

并发编程可以创建更高效的程序。很长一段时间以来，C++没有内置对并发或多线程的支持。现在它完全支持并发编程、线程、线程同步对象以及本章将讨论的其他功能。

在语言更新以支持线程之前，程序员必须使用第三方库。最流行的多线程解决方案之一是**POSIX**（**可移植操作系统接口**）线程。自 C++11 以来，C++引入了线程支持。这使得语言更加健壮，并适用于更广泛的软件开发领域。对于 C++程序员来说，理解线程有些关键，因为他们倾向于尽可能地压榨程序的每一点，使其运行得更快。线程向我们介绍了一种完全不同的方式，通过并发运行函数来加速程序。在基本水平上学习多线程对于每个 C++程序员来说都是必不可少的。有很多程序在其中无法避免使用多线程，例如网络应用程序、游戏和 GUI 应用程序。本章将向您介绍 C++中的并发和多线程基础知识以及并发代码设计的最佳实践。

本章将涵盖以下主题：

+   理解并发和多线程

+   使用线程

+   管理线程和共享数据

+   设计并发代码

+   使用线程池避免线程创建开销

+   熟悉 C++20 中的协程

# 技术要求

本章中使用`-std=c++2a`选项的 g++编译器来编译示例。您可以在[`github.com/PacktPublishing/Expert-CPP`](https://github.com/PacktPublishing/Expert-CPP)找到本章中使用的源文件。

# 理解并发和多线程

运行程序的最简单形式涉及其指令由**CPU**（**中央处理单元**）逐个执行。正如您已经从之前的章节中了解到的，程序由几个部分组成，其中一个部分包含程序的指令。每个指令都加载到 CPU 寄存器中，以便 CPU 解码和执行。实际上，无论您使用何种编程范式来生成应用程序，结果始终是一样的——可执行文件包含机器代码。

我们提到，诸如 Java 和 C#之类的编程语言使用支持环境。然而，如果在中间删减支持环境（通常是虚拟机），那么最终执行的指令应该具有特定 CPU 熟悉的形式和格式。程序员明显知道，CPU 运行的语句顺序在任何情况下都不会混合。例如，我们可以确定并且可以继续确定以下程序将分别输出`4`，`"hello"`和`5`：

```cpp
int a{4};
std::cout << a << std::endl;
int b{a};
++b;
std::cout << "hello" << std::endl;
b--;
std::cout << (b + 1) << std::endl;
```

我们可以保证在将`a`变量打印到屏幕之前，其值将被初始化。同样，我们可以保证在将`"hello"`字符串打印到屏幕之前，我们会减少`b`的值，并且在将`(b + 1)`的和打印到屏幕之前，该和将被计算。每条指令的执行可能涉及从内存中读取数据或向内存中写入数据。

在第五章中介绍了*内存管理和智能指针*，内存层次结构足够复杂，使我们对程序执行的理解变得更加困难。例如，前面例子中的`int b{a};`这一行假设`a`的值从内存加载到 CPU 的寄存器中，然后将用于写入`b`的内存位置。关键词在于*位置*，因为它对我们来说有一点特殊的解释。更具体地说，我们谈论的是内存位置。并发支持取决于语言的内存模型，即对内存并发访问的一组保证。尽管字节是最小的可寻址内存单元，但 CPU 处理数据时使用的是字。也就是说，字是 CPU 从内存读取或写入的最小单位。例如，我们认为以下两个声明是不同的变量：

```cpp
char one;
char two;
```

如果这些变量分配在同一个字中（假设字的大小大于`char`的大小），读取和写入任何一个变量都涉及读取包含它们两个的字。对变量的并发访问可能导致意外的行为。这就是需要内存模型保证的问题。C++内存模型保证了两个线程可以访问和更新不相互干扰的内存位置。内存位置是标量类型。标量类型是算术类型、指针、枚举或`nullptr_t`。最大的非零长度相邻位字段序列也被认为是内存位置。一个经典的例子是以下结构：

```cpp
struct S
{
  char a;             // location #1
  int b: 5;           // location #2
  unsigned c: 11;
  unsigned :0;        // :0 separates bit fields
  unsigned d: 8;      // location #3
  struct {
    int ee: 8;
  } e;                // location #4 
};
```

对于前面的例子，两个线程访问同一个结构的不同内存位置不会相互干扰。那么，当谈论并发或多线程时，我们应该考虑什么呢？

并发通常与多线程混淆。它们在性质上是相似的，但在细节上是不同的概念。为了简化问题，只需想象并发是两个操作的运行时间交错在一起。如果操作`A`与操作`B`同时运行，它们的开始和结束时间在任何时刻都是交错的，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/5a602270-5f05-4ec9-9d02-5ab13bbf4883.png)

当两个任务同时运行时，并不一定要并行运行。想象一下以下情况：你正在看电视，同时上网冲浪。虽然这不是一个好的做法，但是，让我们想象一下，你有一个不能错过的最爱电视节目，同时，你的朋友让你研究一些关于蜜蜂的资料。你实际上无法专注于这两个任务；在任何固定的时刻，你的注意力都会被你正在观看的节目或者你在网上找到的关于蜜蜂的有趣事实所吸引。你的注意力会不时地从节目转移到蜜蜂身上。

就并发而言，你同时进行两个任务。你的大脑给节目一个时间段：你观看，享受，然后切换到文章，读几句话，然后再切换回节目。这是同时运行任务的简单例子。仅仅因为它们的开始和结束时间交错，并不意味着它们同时运行。另一方面，你在做任何前面提到的任务时都在呼吸。呼吸是在后台进行的；你的大脑不会将你的注意力从节目或文章转移到你的肺部来吸气或呼气。在看节目的同时呼吸是并行运行任务的一个例子。这两个例子都向我们展示了并发的本质。

那么，当您在计算机上运行多个应用程序时会发生什么？它们是否并行运行？可以肯定的是它们是同时运行的，然而，实际的并行性取决于您计算机的硬件。大多数大众市场计算机都只有一个 CPU。正如我们从前面的章节中所知，CPU 的主要工作是逐个运行应用程序的指令。单个 CPU 如何处理同时运行两个应用程序的情况？要理解这一点，我们应该了解进程。

# 进程

进程是内存中运行程序的映像。当我们启动一个程序时，操作系统从硬盘读取程序的内容，将其复制到内存中，并将 CPU 指向程序的起始指令。进程有其私有的虚拟地址空间、堆栈和堆。两个进程不会以任何方式相互干扰。这是操作系统提供的保证。这也使得程序员的工作非常困难，如果他们的目标是**进程间通信**（**IPC**）。我们在本书中不讨论低级硬件特性，但你应该对运行程序时发生的事情有一个基本的了解。这实际上取决于底层硬件，更具体地说，取决于 CPU 的种类和结构。CPU 的数量、CPU 核心的数量、缓存内存的级别以及 CPU 或其核心之间的共享缓存内存——所有这些都会影响操作系统运行和执行程序的方式。

计算机系统中的 CPU 数量定义了真正并行运行的进程数量。这在下图中显示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/249ef5f9-c6a5-43bf-bad3-7648ec848c90.png)

当我们谈论多处理时，我们考虑的是允许多个进程同时运行的环境。这就是棘手的部分。如果进程实际上是同时运行的，那么我们说它们是并行运行的。因此，并发不是并行，而并行意味着并发。

如果系统只有一个 CPU，进程会同时运行但不是并行的。操作系统通过一种称为**上下文切换**的机制来管理这一点。上下文切换意味着暂停进程的工作一会儿，复制进程在当前时间使用的所有寄存器值，并存储进程的所有活动资源和值。当一个进程停止时，另一个进程获得运行的权利。在为第二个进程提供的指定时间段之后，操作系统开始为其进行上下文切换。同样，它复制进程使用的所有资源。然后，之前的进程开始。在启动它之前，操作系统将资源和值复制回第一个进程使用的相应槽位，然后恢复执行此进程。

有趣的是，这些过程甚至没有意识到这样的事情。所描述的过程发生得如此之快，以至于用户实际上无法注意到操作系统中运行的程序实际上并不是同时运行的。下图描述了由单个 CPU 运行的两个进程。当其中一个进程处于*活动*状态时，CPU 按顺序执行其指令，将任何中间数据存储在其寄存器中（你也应该考虑缓存内存，就像在游戏中一样）。另一个进程正在*等待*操作系统提供其运行的时间段：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/a385b09c-4de2-4fd5-8057-8831d0675c61.png)

运行多个进程对操作系统来说是一项复杂的工作。它管理进程的状态，确定哪个进程应该比其他进程占用更多的 CPU 时间等。每个进程在操作系统切换到另一个进程之前都有固定的运行时间。这个时间对于一个进程可能更长，对于另一个进程可能更短。使用优先级表来调度进程。操作系统为优先级更高的进程提供更多的时间，例如，系统进程的优先级高于用户进程。另一个例子可能是，监控网络健康的后台任务的优先级高于计算器应用程序。当提供的时间片用完时，操作系统会启动上下文切换，即，它会存储**进程 A**的状态以便稍后恢复其执行：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/1d6e1429-9787-443b-9ea6-2a591b51de4c.png)

在存储状态之后，如下图所示，它切换到下一个进程来执行：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/9ba4ecae-987c-4b5a-a51c-2790b12a3c5e.png)

显然，如果**进程 B**之前正在运行，它的状态应该被加载回 CPU。同样，当**进程 B**的时间片（或时间量子）用完时，操作系统会存储它的状态，并将**进程 A**的状态加载回 CPU（在被操作系统暂停之前的状态）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/ed451d71-cf02-45f6-8929-484ecb4ed453.png)

进程之间没有任何共同之处，或者至少它们认为是这样。每个运行的进程都表现得好像它是系统中唯一的。它拥有操作系统可以提供的所有资源。实际上，操作系统设法让进程彼此不知晓，因此为每个进程模拟了自由。最后，在将**进程 A**的状态加载回来后，CPU 继续执行它的指令，就好像什么都没有发生过：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/b44e37d7-6d77-4248-ad76-e94dc8ab76f4.png)

**进程 B**被冻结，直到有新的时间片可用于运行它。

一个单 CPU 运行多个进程类似于一位老师检查学生的考卷。老师一次只能检查一份考卷，尽管他们可以通过逐个检查每个考试的答案来引入一些并发性。首先，他们检查一个学生的第一个问题的答案，然后切换到第二个学生的考试的第一个答案，然后再切换回第一个学生的第二个答案，依此类推。每当老师从一份考卷切换到另一份时，他们都会记下他们停下来的问题的编号。这样，当他们回到同一份考卷时，他们就知道从哪里开始。

同样，操作系统在暂停一个进程以恢复另一个进程之前记录下进程的执行点。第二个进程可以（而且很可能会）使用被暂停进程使用的相同寄存器集。这迫使操作系统将第一个进程的寄存器值存储在某个地方，以便稍后恢复。当操作系统暂停第二个进程以恢复第一个进程时，它会将已保存的寄存器值加载回相应的寄存器中。恢复的进程不会注意到任何差异，并将继续工作，就好像它从未被暂停过一样。

前两段描述的一切都与单 CPU 系统有关。在多 CPU 系统中，系统中的每个 CPU 都有自己的寄存器集。此外，每个 CPU 可以独立地执行程序指令，而不受其他 CPU 的影响，这允许进程并行运行而无需暂停和恢复它们。在这个例子中，一位老师和几个助手类似于一个有三个 CPU 的系统。他们每个人都可以检查一份考卷；他们在任何时候都在检查三份不同的考卷。

# 进程的挑战

当进程需要以某种方式相互联系时，困难就会出现。比如，一个进程应该计算某些东西并将值传递给一个完全不同的进程。有几种方法可以实现 IPC，其中一种是使用在进程之间共享的内存段。下图描述了两个进程访问共享内存段的情况：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/ba6aa4ed-83da-4987-b27f-17429fa23ec4.png)

一个进程将计算结果存储到内存中的共享段中，第二个进程从该段中读取。在我们之前的例子中，老师和他们的助手在共享的纸上分享他们的检查结果。另一方面，线程共享进程的地址空间，因为它们在进程的上下文中运行。虽然进程是一个程序，线程是一个函数而不是一个程序。也就是说，一个进程必须至少有一个线程，我们称之为执行线程。线程是在系统中运行的程序的指令容器，而进程封装了线程并为其提供资源。我们大部分的兴趣都在于线程及其编排机制。现在让我们亲自见见它们。

# 线程

线程是进程范围内可以由操作系统调度的代码部分。虽然进程是运行程序的映像，但与利用多线程的项目相比，管理多进程项目以及 IPC 要困难得多，有时也是无用的。程序处理数据，通常是数据集合。访问、处理和更新数据是通过函数来完成的，这些函数要么是对象的方法，要么是组合在一起以实现最终结果的自由函数。在大多数项目中，我们处理成千上万个函数和对象。每个函数代表一堆指令，这些指令以一个合理的名称包装起来，用于被其他函数调用。多线程旨在并发运行函数以实现更好的性能。

例如，一个计算三个不同向量的和并打印它们的程序调用计算第一个向量的和的函数，然后是第二个向量，最后是最后一个。这一切都是顺序进行的。如果处理单个向量需要 A 的时间，那么程序将在`3A`的时间内运行。以下代码演示了这个例子：

```cpp
void process_vector(const std::vector<int>& vec) 
{
 // calculate the sum and print it
}

int main()
{
 std::vector<int> vec1{1, 2, 3, 4, 5};
 std::vector<int> vec2{6, 7, 8, 9, 10};
 std::vector<int> vec3{11, 12, 13, 14, 15};
 process_vector(vec1); // takes A amount of time
 process_vector(vec2); // takes A amount of time
 process_vector(vec3); // takes A amount of time
}
```

如果有一种方法可以同时为三个不同的向量运行相同的函数，那么在前面的例子中整个程序只需要 A 的时间。执行线程，或者说线程，是并发运行任务的确切方式。通过任务，我们通常指的是一个函数，尽管你也应该记住`std::packaged_task`。再次强调，并发不应与并行混淆。当我们谈论线程并发运行时，你应该考虑之前讨论的进程的上下文切换。几乎同样适用于线程。

`std::packaged_task`类似于`std::function`。它包装了一个可调用对象——函数、lambda、函数对象或绑定表达式。与`std::packaged_task`的区别在于它可以异步调用。本章后面会详细介绍这一点。

每个进程都有一个单一的执行线程，有时被称为**主线程**。一个进程可以有多个线程，这时我们称之为**多线程**。线程几乎以与进程相同的方式运行。它们也有上下文切换。

线程彼此独立运行，但因为所有线程都属于同一个进程，它们大部分资源都是共享的。进程占用硬件和软件资源，如 CPU 寄存器和内存段，包括自己的堆栈和堆。虽然进程不与其他进程共享其堆栈或堆，但其线程必须使用进程占用的相同资源。线程的一切生活都发生在进程内部。

然而，线程不共享堆栈。每个线程都有自己的堆栈部分。这种隔离的原因在于，线程只是一个函数，函数本身应该可以访问堆栈来管理其参数和局部变量的生命周期。当我们将相同的函数作为两个（或更多）分别运行的线程运行时，运行时应该以某种方式处理它们的边界。虽然这很容易出错，但你可以通过值或引用将一个变量从一个线程传递到另一个线程。假设我们启动了三个线程，分别运行上面例子中的三个向量的`process_vector()`函数。你应该想象启动一个线程意味着以某种方式*复制*底层函数（它的变量但不是指令）并将其独立地运行。在这种情况下，相同的函数将被复制为三个不同的图像，并且每个图像都将独立于其他图像运行，因此每个图像都应该有自己的堆栈。另一方面，堆在线程之间是共享的。因此，基本上我们得到了以下结论：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/2837ebc0-a491-4359-aa66-f0e737feff43.png)

与进程一样，并发运行的线程不一定是并行运行的。每个线程都会获得一小部分 CPU 时间来运行，而且从一个线程切换到另一个线程也会有开销。每个暂停的线程状态都应该被存储在某个地方，以便在恢复时能够恢复。CPU 的内部结构定义了线程是否能够真正并行运行。CPU 核心的数量定义了可以真正并行运行的线程数量。

C++线程库提供了`hardware_concurrency()`函数，用于查找可以真正并发运行的线程数量。在设计并发代码时，可以参考这个数字。

下图描述了两个 CPU，每个 CPU 都有四个核心。每个核心可以独立地运行一个线程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/82938768-6461-41e2-94dc-454295e6fd96.png)

不仅两个进程并行运行，它们的线程也使用 CPU 核心并行运行。那么，如果我们有几个线程但只有一个单核 CPU，情况会如何改变呢？几乎与我们之前为进程所说明的情况相同。看看下面的图表——它描述了 CPU 如何在某个时间片段内执行**线程 1**：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/43a122ae-5378-4cb0-8770-cfea0b51cad2.png)

当前活动的**进程 A**有两个同时运行的线程。在每个指定的时间点，只有一个线程被执行。当**线程 1**的时间片用完时，**线程 2**被执行。与我们讨论过的进程模型的不同之处在于，线程共享进程的资源，如果我们不关心并发代码设计问题，这会导致不自然的行为。让我们深入了解 C++线程支持，并找出在使用多线程时会出现什么问题。

# 使用线程

当 C++程序启动时，也就是`main()`函数开始执行时，你可以创建并启动新的线程，这些线程将与主线程并发运行。要在 C++中启动一个线程，你应该声明一个线程对象，并将要与主线程并发运行的函数传递给它。以下代码演示了使用`<thread>`中定义的`std::thread`声明和启动线程：

```cpp
#include <thread> #include <iostream>

void foo() { std::cout << "Testing a thread in C++" << std::endl; }

int main() 
{
 std::thread test_thread{foo};
}
```

就是这样。我们可以创建一个更好的例子来展示两个线程如何同时工作。假设我们同时在循环中打印数字，看看哪个线程打印了什么：

```cpp
#include <thread>
#include <iostream>

void print_numbers_in_background() 
{
 auto ix{0};  // Attention: an infinite loop!
 while (true) {
 std::cout << "Background: " << ix++ << std::endl;
 }
}

int main()
{
 std::thread background{print_numbers_in_background};
  auto jx{0};
  while (jx < 1000000) {
    std::cout << "Main: " << jx++ << std::endl;
  }
}
```

上面的例子将打印出带有`Main:`和`Background:`前缀混合在一起的两个输出。输出的摘录可能如下所示：

```cpp
...
Main: 90
Main: 91
Background: 149
Background: 150
Background: 151
Background: 152
Background: 153
Background: 
Main: 92
Main: 93
...
```

当主线程完成其工作（向屏幕打印一百万次）时，程序希望在不等待后台线程完成的情况下结束。这会导致程序终止。让我们看看如何修改之前的例子。

# 等待线程

如果要等待线程完成，`thread`类提供了`join()`函数。以下是等待`background`线程的修改版本的示例：

```cpp
#include <thread>
#include <iostream>

void print_numbers_in_background()
{
  // code omitted for brevity
}

int main()
{
  std::thread background{print_numbers_in_background};
  // the while loop omitted for brevity
 background.join();
}
```

正如我们之前讨论的，`thread`函数作为一个独立的实体运行，独立于其他线程-甚至是启动它的线程。它不会等待它刚刚启动的线程，这就是为什么您应该明确告诉调用函数在自己之前等待它完成。在它完成之前，必须发出信号表明调用线程（主线程）正在等待线程完成。

`join()`函数的对称相反是`detach()`函数。`detach()`函数表示调用者对等待线程完成不感兴趣。在这种情况下，线程可以有独立的生命周期。就像这里显示的（就像它已经 18 岁了）：

```cpp
std::thread t{foo};
t.detach(); 
```

尽管分离线程可能看起来很自然，但有很多情况需要等待线程完成。例如，我们可能会将局部变量传递给正在运行的线程。在这种情况下，我们不能让调用者分离线程，因为调用者可能比线程更早完成其工作。让我们为了清晰起见举个例子。**Thread 1**声明了`loc`变量并将其传递给了从**Thread 1**启动的**Thread 2**：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/8bcd907b-742d-4b19-9484-87822f730a68.png)

如果**Thread 1**在**Thread 2**之前完成其执行，那么通过地址访问`loc`会导致未定义的行为：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/58cea33e-6366-4f28-9ac5-84e785da0452.png)

不再有这样的对象，因此我们可以希望程序最好崩溃。这将导致意外行为，因为运行线程将不再访问调用者的局部变量。您应该加入或分离线程。

我们可以将任何可调用对象传递给`std::thread`。以下示例显示了将 lambda 表达式传递给线程：

```cpp
#include <thread>

int main() {
  std::thread tl{[]{
 std::cout << "A lambda passed to the thread";
 }};
  tl.join();
}
```

此外，我们可以使用可调用对象作为线程参数。看一下以下代码，声明了具有重载的`operator()`函数的`TestTask`类：

```cpp
#include <thread>

class TestTask
{
public:
  TestTask() = default;

 void operator()() {
 state_++;
 }

private:
  int state_ = 0;
};

int main() {
  std::thread t{TestTask()};
  t.join();
}
```

函数对象（具有重载的`operator()`函数的`TestTask`类）的一个优点是它能够存储状态信息。函数对象是命令设计模式的一个美丽实现，我们将在第十一章中讨论，*使用设计模式设计策略游戏*。回到线程，让我们继续讨论语言中的一个新添加，它允许更好地加入线程的方式。

# 使用 std::jthread

C++20 引入了可加入线程`std::jthread`。它提供了与`std::thread`相同的接口，因此我们可以在代码中用 jthreads 替换所有线程。它实际上是对`std::thread`的封装，因此基本上是将操作委托给封装的线程。

如果您的编译器版本不支持`std::jthread`，您可以选择使用**RAII**（**资源获取即初始化**）习惯用法，这对线程非常适用。看一下以下代码：

```cpp
class thread_raii
{
public:
  explicit thread_raii(std::thread& t)
    : thread_(std::move(t))
  {}

  ~thread_raii() {
    thread_.join();  
  }

private:
  std::thread thread_;
};

void foo() {
  std::cout << "Testing thread join";
}

int main() {
 std::thread t{foo};
 thread_raii r{t};
  // will automatically join the thread
}
```

然而，前面的代码缺少了一个额外的检查，因为传递给 RAII 类的线程可能已经被分离。为了查看线程是否可以加入，我们使用`joinable()`函数。这是我们应该如何重写`thread_raii`类的方式：

```cpp
class thread_raii
{
public:
  explicit thread_raii(std::thread& t)
    : thread_(std::move(t))
  {}

 ~thread_raii()
 {
 if (thread_.joinable()) {
 thread_.join();
 }
 }
private:
  std::thread thread_;
};
```

在调用`join()`函数之前，析构函数首先测试线程是否可加入。但是，与其处理习惯用法并担心线程在加入之前是否已经加入，我们更喜欢使用`std::jthread`。以下是如何使用先前声明的`TestTask`函数来做到这一点：

```cpp
std::jthread jt{TestTask()};
```

就是这样——不需要调用`jt.join()`，并且我们使用`std::jthread`内置的新的协作可中断功能。我们说`jthread`是协作可中断的，因为它提供了`request_stop()`函数，它做了它的名字所说的事情——请求线程停止。尽管请求的实现是定义的，但这是一个不必永远等待线程的好方法。回想一下线程在无限循环中打印数字的例子。我们修改了主线程来等待它，这导致永远等待它。下面是我们如何使用`std::jthread`修改线程以利用`request_stop()`函数：

```cpp
int main()
{
 std::jthread background{print_numbers_in_background};
  auto jx{0};
  while (jx < 1000000) {
    std::cout << "Main: " << jx << std::endl;
  }
  // The main thread is about to finish, so we request the background thread to stop
 background.request_stop();
}
```

`print_numbers_in_background()`函数现在接收到一个请求，并可以相应地行为。现在，让我们看看如何将参数传递给线程函数。

# 将参数传递给线程函数

`std::thread`构造函数接受参数并将它们转发给底层的`thread`函数。例如，要将参数`4`和`2`传递给`foo()`函数，我们将参数传递给`std::thread`构造函数：

```cpp
void foo(int one, int two) {
  // do something
}

std::thread t{foo, 4, 2};
```

`4`和`2`参数将作为`foo()`函数的第一个和第二个参数传递。

以下示例说明了通过引用传递参数：

```cpp
class big_object {};

void make_changes(big_object&);

void error_prone()
{
  big_object b;
 std::jthread t{make_changes, b};
  // do something else
}
```

为了理解为什么我们将函数命名为`error_prone`，我们应该知道线程构造函数会复制传递给它的值，然后使用`rvalue`引用将它们传递给线程函数。这是为了处理仅可移动类型。因此，它将尝试使用`rvalue`调用`make_changes()`函数，这将无法编译通过（不能将`rvalue`传递给期望非常量引用的函数）。我们需要在需要引用的参数中使用`std::ref`进行包装。

```cpp
std::thread t{make_changes, std::ref(b)};
```

前面的代码强调了参数应该通过引用传递。处理线程需要更加注意，因为程序中有许多方法可以获得意外结果或未定义的行为。让我们看看如何管理线程以生成更安全的多线程应用程序。

# 管理线程和共享数据

正如之前讨论的，线程的执行涉及暂停和恢复其中一些线程，如果线程数量超过硬件支持的并行运行线程数量。除此之外，线程的创建也有开销。在项目中处理有许多线程的建议做法之一是使用线程池。

线程池的概念在于缓存的概念。我们创建并保留线程在某个容器中以便以后使用。这个容器称为池。例如，以下向量表示一个简单的线程池：

```cpp
#include <thread>
#include <vector>

std::vector<std::thread> pool;
```

每当我们需要一个新线程时，我们不是声明相应的`std::thread`对象，而是使用已在池中创建的线程。当我们完成线程时，我们可以将其推回向量以便以后使用。这在处理 10 个或更多线程时可以节省一些时间。一个合适的例子是一个 Web 服务器。

Web 服务器是一个等待传入客户端连接并为每个客户端创建一个独立连接以独立处理的程序。一个典型的 Web 服务器通常同时处理数千个客户端。每当与某个客户端启动新连接时，Web 服务器都会创建一个新线程并处理客户端请求。以下伪代码演示了 Web 服务器传入连接管理的简单实现：

```cpp
void process_incoming_connections() {
  if (new connection from client) {
    t = create_thread(); // potential overhead
    t.handle_requests(client);
  }
}
while (true) {
  process_incoming_connections();
}
```

使用线程池时，前面的代码将避免每次处理客户端请求时都创建一个线程。创建新线程需要操作系统额外且昂贵的工作。为了节省时间，我们使用一种机制，可以在每个请求时省略创建新线程。为了使线程池更好，让我们用队列替换它的容器。每当我们请求一个线程时，线程池将返回一个空闲线程，每当我们完成一个线程时，我们将其推回线程池。线程池的简单设计如下：

```cpp
#include <queue>
#include <thread>

class ThreadPool
{
public:
  ThreadPool(int number_of_threads = 1000) {
    for (int ix = 0; ix < number_of_threads; ++ix) {
      pool_.push(std::thread());
    }
  }

  std::thread get_free_thread() {
    if (pool_.empty()) {
      throw std::exception("no available thread");
    }
    auto t = pool_.front();
    pool_.pop();
    return t;
  }

  void push_thread(std::thread t) {
    pool_.push(t);
  }

private:
  std::queue<std::thread> pool_;
};
```

构造函数创建并将线程推送到队列。在下面的伪代码中，我们用之前介绍的`ThreadPool`替换了直接创建线程来处理客户端请求：

```cpp
ThreadPool pool;
void process_incoming_connections() {
  if (new connection from client) {
    auto t = pool.get_free_thread();
    t.handle_request(client);
  }
}

while (true) {
  process_incoming_connections();
}
```

假设`handle_request()`函数在完成时将线程推回线程池，那么线程池就像是连接线程的集中存储。虽然前面的片段远未准备好投入生产，但它传达了在密集应用中使用线程池的基本思想。

# 共享数据

竞争条件是多线程程序员害怕并尽量避免的事情。想象一下两个函数同时处理相同的数据，如下所示：

```cpp
int global = 0;

void inc() {
  global = global + 1;
}
...
std::thread t1{inc};
std::thread t2{inc};
```

可能发生竞争条件，因为线程`t1`和`t2`正在用多个步骤修改相同的变量。在单个线程安全步骤中执行的任何操作称为**原子操作**。在这种情况下，即使使用增量运算符，增加变量的值也不是原子操作。

# 使用互斥锁保护共享数据

为了保护共享数据，广泛使用称为**互斥锁**的对象。互斥锁是控制线程运行的对象。想象线程就像人类一样，一次处理数据的交易。当一个线程锁定一个互斥锁时，另一个线程会等待，直到它完成数据并解锁互斥锁。然后另一个线程锁定互斥锁并开始处理数据。以下代码演示了如何使用互斥锁解决竞争条件的问题：

```cpp
#include <mutex>
...
std::mutex locker;
void inc() {
  locker.lock();
  global = global + 1;
  locker.unlock();
}
...
std::thread t1{inc};
std::thread t2{inc};

```

当`t1`开始执行`inc()`时，它锁定一个互斥锁，这样可以避免其他线程访问全局变量，除非原始线程不解锁下一个线程。

C++17 引入了锁保护，允许保护互斥锁，以免忘记解锁它：

```cpp
std::mutex locker;
void inc() {
  std::lock_guard g(locker);
  global = global + 1;
}
```

如果可能的话，最好使用语言提供的保护。

# 避免死锁

互斥锁会带来新的问题，比如**死锁**。死锁是多线程代码的一种情况，当两个或多个线程锁定一个互斥锁并等待另一个解锁时发生。

避免死锁的常见建议是始终以相同的顺序锁定两个或多个互斥锁。C++提供了`std::lock()`函数，用于相同的目的。

以下代码说明了`swap`函数，它接受两个类型为`X`的参数。我们假设`X`有一个名为`mt`的成员，它是一个互斥锁。`swap`函数的实现首先锁定左对象的互斥锁，然后锁定右对象的互斥锁：

```cpp
void swap(X& left, X& right)
{
  std::lock(left.mt, right.mt);
  std::lock_guard<std::mutex> lock1(left.mt, std::adopt_lock);
  std::lock_guard<std::mutex> lock2(right.mt, std::adopt_lock);
  // do the actual swapping
}
```

为了一般地避免死锁，避免嵌套锁。也就是说，如果已经持有一个锁，则不要获取另一个锁。如果不是这种情况，则按固定顺序获取锁。固定顺序将允许您避免死锁。

# 设计并发代码

当并发引入时，项目复杂性会急剧上升。与并发对应的同步代码相比，处理顺序执行的同步代码要容易得多。许多系统通过引入事件驱动开发概念（如事件循环）来避免使用多线程。使用事件循环的目的是引入一种可管理的异步编程方法。进一步想象，任何提供图形用户界面（GUI）的应用程序。每当用户点击任何 GUI 组件，如按钮；在字段中输入；甚至移动鼠标时，应用程序都会接收有关用户操作的所谓事件。无论是`button_press`、`button_release`、`mouse_move`还是其他任何事件，它都代表了应用程序对信息的正确反应。一种流行的方法是将事件循环结合起来，以排队用户交互期间发生的任何事件。

当应用程序忙于当前任务时，由用户操作产生的事件被排队等待在将来的某个时间进行处理。处理涉及调用附加到每个事件的处理程序函数。它们按照它们被放入队列的顺序进行调用。

将多线程引入项目会带来额外的复杂性。现在，您需要关注竞争条件和适当的线程处理，甚至可能使用线程池来重用线程对象。在顺序执行的代码中，您只关心代码。使用多线程，您现在需要更多地关注相同代码的执行方式。例如，一个简单的设计模式，如单例，在多线程环境中的行为会有所不同。单例的经典实现如下：

```cpp
class MySingleton
{
public:
 static MySingleton* get_instance() {
 if (instance_ == nullptr) {
 instance_ = new MySingleton();
 }
 return instance_;
 }

  // code omitted for brevity
private:
  static inline MySingleton* instance_ = nullptr;
};
```

以下代码启动了两个线程，都使用了`MySingleton`类：

```cpp
void create_something_unique() 
{
 MySingleton* inst = MySingleton::get_instance();
  // do something useful
}

void create_something_useful() 
{
  MySingleton* anotherInst = MySingleton::get_instance();
  // do something unique
}  

std::thread t1{create_something_unique};
std::thread t2{create_something_useful};
t1.join();
t2.join();
// some other code
```

线程`t1`和`t2`都调用`MySingleton`类的`get_instance()`静态成员函数。可能`t1`和`t2`都通过了对空实例的检查，并且都执行了新操作符。很明显，这里存在竞争条件。在这种情况下，资源（在本例中是类实例）应该受到保护。以下是使用互斥量的明显解决方案：

```cpp
class MySingleton
{
public:
  static MySingleton* get_instance() {
 std::lock_guard lg{mutex_};
    if (instance_ == nullptr) {
      instance_ = new MySingleton();
    }
    return instance_;
  }

  // code omitted for brevity
private:
 static std::mutex mutex_;
  static MySingleton* instance_;
}
```

使用互斥量可以解决问题，但会使函数的工作速度变慢，因为每次线程请求一个实例时，都会锁定一个互斥量（这涉及操作系统内核的额外操作）。正确的解决方案是使用双重检查锁定模式。它的基本思想是这样的：

1.  在`instance_`检查后锁定互斥量。

1.  在锁定互斥量后再次检查`instance_`，因为另一个线程可能已经通过了第一次检查，并等待互斥量解锁。

有关详细信息，请参阅代码：

```cpp
static MySingleton* get_instance() {
  if (instance_ == nullptr) {
 std::lock_guard lg{mutex_};
 if (instance_ == nullptr) {
 instance_ = new MySingleton();
 }
  }
  return instance_;
}
```

几个线程可能通过第一次检查，其中一个线程将锁定互斥量。只有一个线程可以进行新操作符调用。然而，在解锁互斥量后，通过第一次检查的线程将尝试锁定它并创建实例。第二次检查是为了防止这种情况发生。上述代码使我们能够减少同步代码的性能开销。我们提供的方法是为并发代码设计做好准备的一种方式。

并发代码设计在很大程度上基于语言本身的能力。C++的发展是非常了不起的。在最早的版本中，它没有内置支持多线程。现在，它有一个稳固的线程库，而新的 C++20 标准为我们提供了更强大的工具，如协程。

# 引入协程

在讨论 GUI 应用程序时，我们讨论了异步代码执行的一个例子。GUI 组件通过触发相应的事件来对用户操作做出反应，这些事件被推送到事件队列中。然后，这些队列会通过调用附加的处理程序函数逐个进行处理。所描述的过程在一个循环中发生；这就是为什么我们通常将这个概念称为事件循环。

异步系统在 I/O 操作中非常有用，因为任何输入或输出操作都会在 I/O 调用点阻塞执行。例如，以下伪代码从目录中读取文件，然后在屏幕上打印欢迎消息：

```cpp
auto f = read_file("filename");
cout << "Welcome to the app!";
process_file_contents(f);
```

与同步执行模式相结合，我们知道只有在`read_file()`函数执行完成后才会打印出欢迎来到应用程序！`process_file_contents()`将在`cout`完成后调用。处理异步代码时，我们对代码执行的了解开始表现得像是一些无法识别的东西。以下修改版本的前面的例子使用`read_file_async()`函数异步读取文件内容：

```cpp
auto p = read_file_async("filename");
cout << "Welcome to the app!";
process_file_contents(p); // we shouldn't be able to do this
```

考虑到`read_file_async()`是一个异步函数，欢迎来到应用程序！的消息将比文件内容更早打印出来。异步执行的本质允许我们调用要在后台执行的函数，这为我们提供了非阻塞的输入/输出。

然而，我们对函数的返回值处理方式有一点变化。如果我们处理一个异步函数，它的返回值被视为一种称为**承诺**或**承诺对象**的东西。这是系统在异步函数完成时通知我们的方式。承诺对象有三种状态：

+   挂起

+   拒绝

+   实现

承诺对象在函数完成并且结果准备好被处理时被认为是已实现的。在发生错误时，承诺对象将处于拒绝状态。如果承诺既没有被拒绝也没有被实现，它就处于挂起状态。

C++20 引入了协程作为经典异步函数的补充。协程将代码的后台执行提升到了下一个级别；它们允许函数在必要时暂停和恢复。想象一个读取文件内容并在中途停止的函数，将执行上下文传递给另一个函数，然后恢复文件的读取直到结束。因此，在深入研究之前，将协程视为以下函数：

+   开始

+   暂停

+   恢复

+   完成

要使函数成为协程，您可以使用关键字`co_await`、`co_yield`或`co_return`之一。`co_await`是一个构造，告诉代码等待异步执行的代码。这意味着函数可以在那一点被暂停，并在结果准备好时恢复执行。例如，以下代码使用套接字从网络请求图像：

```cpp
task<void> process_image()
{
  image i = co_await request_image("url");
  // do something useful with the image
}
```

由于网络请求操作也被视为**输入/输出**操作，它可能会阻塞代码的执行。为了防止阻塞，我们使用异步调用。在前面的例子中使用`co_await`的行是函数执行可能被暂停的地方。简单来说，当执行到达带有`co_await`的行时，会发生以下情况：

1.  它暂时退出函数（直到没有准备好的数据）。

1.  它继续执行`process_image()`被调用之前的位置。

1.  然后它再次回来继续执行`process_image()`在它离开的地方。

为了实现这一点，协程（`process_image()`函数是一个协程）在 C++中不像处理常规函数那样处理。协程的一个有趣甚至令人惊讶的特性是它们是**无堆栈的。**我们知道函数不能没有堆栈。这是函数在执行指令之前推送其参数和局部变量的地方。另一方面，协程不是将任何东西推送到堆栈，而是将它们的状态保存在堆中，并在恢复时恢复它们。

这很棘手，因为还有堆栈式协程。堆栈式协程，也称为**纤程**，有一个单独的堆栈。

协程与调用者相连。在前面的例子中，调用`sprocess_image()`的函数将执行转移到协程，协程的暂停（也称为**yielding**）将执行返回给调用者。正如我们所说，堆用于存储协程的状态，但实际的函数特定数据（参数和局部变量）存储在调用者的堆栈上。就是这样——协程与存储在调用函数堆栈上的对象相关联。显然，协程的生存期与其对象一样长。

协程可能会给人一种错误的印象，认为它增加了语言的冗余复杂性，但它们的用例在改进使用异步 I/O 代码（如前面的例子中）或延迟计算的应用程序中非常好。也就是说，当我们不得不发明新的模式或引入复杂性来处理懒惰计算等项目时，现在我们可以通过在 C++中使用协程来改善我们的体验。请注意，异步 I/O 或延迟计算只是协程应用的两个例子。还有更多。

# 摘要

在本章中，我们讨论了并发的概念，并展示了并行之间的区别。我们学习了进程和线程之间的区别，后者引起了我们的兴趣。多线程使我们能够更有效地管理程序，尽管它也带来了额外的复杂性。为了处理数据竞争，我们使用诸如互斥锁之类的同步原语。互斥锁是一种锁定一个线程使用的数据的方式，以避免多个线程同时访问相同数据产生的无效行为。

我们还讨论了输入/输出操作被认为是阻塞的概念，而异步函数是使其非阻塞的方法之一。协程作为代码的异步执行的一部分在 C++20 中被引入。

我们学习了如何创建和启动线程。更重要的是，我们学习了如何在线程之间管理数据。在下一章中，我们将深入研究在并发环境中使用的数据结构。

# 问题

1.  并发是什么？

1.  并发和并行之间的区别是什么？

1.  什么是进程？

1.  进程和线程之间的区别是什么？

1.  编写代码启动一个线程。

1.  如何使单例模式线程安全？

1.  重写`MySingleton`类，使用`std::shared_ptr`返回实例。

1.  什么是协程，`co_await`关键字用于什么？

# 进一步阅读

+   *Anthony Williams，《C++并发实战》，[`www.amazon.com/C-Concurrency-Action-Anthony-Williams/dp/1617294691/`](https://www.amazon.com/C-Concurrency-Action-Anthony-Williams/dp/1617294691/)*


# 第九章：设计并发数据结构

在上一章中，我们简要介绍了 C++中并发和多线程的基础知识。并发代码设计中最大的挑战之一是正确处理数据竞争。线程同步和协调并不是一个容易理解的话题，尽管我们可能认为它是最重要的话题。虽然我们可以在任何我们对数据竞争有丝毫怀疑的地方使用互斥量等同步原语，但这并不是我们建议的最佳实践。

设计并发代码的更好方式是尽量避免使用锁。这不仅会提高应用程序的性能，还会使其比以前更安全。说起来容易做起来难——无锁编程是一个具有挑战性的话题，我们将在本章中介绍。特别是，我们将更深入地了解设计无锁算法和数据结构的基础知识。这是一个由许多杰出的开发人员不断研究的难题。我们将简要介绍无锁编程的基础知识，这将让您了解如何以高效的方式构建代码。阅读完本章后，您将更好地能够理解数据竞争问题，并获得设计并发算法和数据结构所需的基本知识。这也可能有助于您的一般设计技能，以构建容错系统。

本章将涵盖以下主题：

+   理解数据竞争和基于锁的解决方案

+   在 C++代码中使用原子操作

+   设计无锁数据结构

# 技术要求

本章中使用 g++编译器的`-std=c++2a`选项来编译示例。您可以在以下链接找到本章中使用的源文件：[`github.com/PacktPublishing/Expert-CPP`](https://github.com/PacktPublishing/Expert-CPP)。

# 更深入地了解数据竞争

正如已经多次提到的，数据竞争是程序员们尽量避免的情况。在上一章中，我们讨论了死锁及其避免方法。上一章中我们使用的最后一个示例是创建一个线程安全的单例模式。假设我们使用一个类来创建数据库连接（一个经典的例子）。

以下是一个跟踪数据库连接的模式的简单实现。每次需要访问数据库时保持单独的连接并不是一个好的做法。相反，我们可以重用现有的连接来从程序的不同部分查询数据库：

```cpp
namespace Db {
  class ConnectionManager 
  {
  public:
    static std::shared_ptr<ConnectionManager> get_instance()
 {
 if (instance_ == nullptr) {
 instance_.reset(new ConnectionManager());
 }
 return instance_;
 }

    // Database connection related code omitted
  private:
    static std::shared_ptr<ConnectionManager> instance_{nullptr};
  };
}
```

让我们更详细地讨论这个例子。在上一章中，我们加入了锁来保护`get_instance()`函数免受数据竞争的影响。让我们详细说明为什么这样做。为了简化这个例子，以下是我们感兴趣的四行：

```cpp
get_instance()
  if (_instance == nullptr)
    instance_.reset(new)
  return instance_;
```

现在，想象一下我们运行一个访问`get_instance()`函数的线程。我们称它为`线程 A`，它执行的第一行是条件语句，如下所示：

```cpp
get_instance()
  if (_instance == nullptr)   <--- Thread A
    instance_.reset(new)
  return instance_;
```

它将逐行执行指令。我们更感兴趣的是第二个线程（标记为`线程 B`），它开始并发执行`线程 A`的函数。在函数并发执行期间可能出现以下情况：

```cpp
get_instance()
  if (_instance == nullptr)   <--- Thread B (checking)
    instance_.reset(new)      <--- Thread A (already checked)
  return instance_;
```

`线程 B`在将`instance_`与`nullptr`进行比较时得到了一个正结果。`线程 A`已经通过了相同的检查，并将`instance_`设置为一个新对象。从`线程 A`的角度来看，一切都很正常，它刚刚通过了条件检查，重置了`instances`，并将继续执行下一行返回`instance_`。然而，`线程 B`在它的值改变之前就比较了`instance_`。因此，`线程 B`也继续设置`instance_`的值：

```cpp
get_instance()
  if (_instance == nullptr)   
    instance_.reset(new)      <--- Thread B (already checked)
  return instance_;           <--- Thread A (returns)
```

前面的问题是`线程 B`在`instance_`已经被设置之后重置了它。此外，我们将`get_instance()`视为一个单独的操作；它由几条指令组成，每条指令都由一个线程按顺序执行。为了让两个线程不相互干扰，操作不应该包含多于一条指令。

我们关注数据竞争的原因是代码块中的间隙。代码行之间的这个间隙允许线程相互干扰。当你使用互斥锁等同步原语设计解决方案时，你应该考虑你错过的所有间隙，因为解决方案可能不正确。下面的修改使用了在前一章讨论过的互斥锁和`双重检查`锁定模式：

```cpp
static std::shared_ptr<ConnectionManager> get_instance()
{
  if (instance_ == nullptr) {
    // mutex_ is declared in the private section
 std::lock_guard lg{mutex_};
 if (instance_ == nullptr) { // double-checking
 instance_.reset(new ConnectionManager());
 }
  }
  return instance_;
}
```

当两个线程尝试访问`instance_`对象时会发生什么：

```cpp
get_instance()
  if (instance_ == nullptr)     <--- Thread B
    lock mutex                  <--- Thread A (locks the mutex)
    if (instance_ == nullptr)
      instance_.reset(new)
    unlock mutex
  return instance_
```

现在，即使两个线程都通过了第一次检查，其中一个线程也会锁定互斥锁。当一个线程尝试锁定互斥锁时，另一个线程会重置实例。为了确保它尚未设置，我们使用第二次检查（这就是为什么它被称为**双重检查锁定**）：

```cpp
get_instance()
  if (instance_ == nullptr)
    lock mutex                  <--- Thread B (tries to lock, waits)
    if (instance_ == nullptr)   <--- Thread A (double check)
      instance_.reset(new)      
    unlock mutex
  return instance_
```

当`线程 A`完成设置`instance_`后，它会解锁互斥锁，这样`线程 B`就可以继续锁定和重置`instance_`：

```cpp
get_instance()
  if (instance_ == nullptr)
    lock mutex                  <--- Thread B (finally locks the mutex)
    if (instance_ == nullptr)   <--- Thread B (check is not passed)
      instance_.reset(new)      
    unlock mutex                <--- Thread A (unlocked the mutex)
  return instance_              <--- Thread A (returns)  
```

根据经验法则，你应该总是查看代码中的细节。两个语句之间总是有一个间隙，这个间隙会导致两个或更多的线程相互干扰。接下来的部分将详细讨论一个经典的递增数字的例子。

# 同步递增

几乎每本涉及线程同步主题的书都使用递增数字的经典例子作为数据竞争的例子。这本书也不例外。例子如下：

```cpp
#include <thread>

int counter = 0;

void foo()
{
 counter++;
}

int main()
{
  std::jthread A{foo};
  std::jthread B{foo};
  std::jthread C{[]{foo();}};
  std::jthread D{
    []{
      for (int ix = 0; ix < 10; ++ix) { foo(); }
    }
  };
}
```

我们添加了几个线程，使示例变得更加复杂。前面的代码只是使用四个不同的线程递增`counter`变量。乍一看，任何时候只有一个线程递增`counter`。然而，正如我们在前一节中提到的，我们应该注意并寻找代码中的间隙。`foo()`函数似乎缺少一个。递增运算符的行为如下（伪代码）：

```cpp
auto res = counter;
counter = counter + 1;
return res;
```

现在，我们发现了本不应该有的间隙。因此，任何时候只有一个线程执行前面三条指令中的一条。也就是说，类似下面的情况是可能的：

```cpp
auto res = counter;     <--- thread A
counter = counter + 1;  <--- thread B
return res;             <--- thread C
```

例如，`线程 B`可能在`线程 A`读取其先前值时修改`counter`的值。这意味着`线程 A`在`线程 B`已经完成递增`counter`时会给`counter`赋予一个新的递增值。混乱引入了混乱，迟早，我们的大脑会因为尝试理解操作的顺序而爆炸。作为一个经典的例子，我们将继续使用线程锁定机制来解决这个问题。以下是一个常见的解决方案：

```cpp
#include <thread>
#include <mutex>

int counter = 0;
std::mutex m;

void foo()
{
 std::lock_guard g{m};
  counter++;
}

int main()
{
  // code omitted for brevity
}
```

无论哪个线程首先到达`lock_guard`都会锁定`mutex`，如下所示：

```cpp
lock mutex;             <--- thread A, B, D wait for the locked mutex 
auto res = counter;     <--- thread C has locked the mutex
counter = counter + 1;
unlock mutex;           *<--- A, B, D are blocked until C reaches here*
return res;             
```

使用锁定的问题在于性能。理论上，我们使用线程来加快程序执行，更具体地说，是数据处理。在处理大量数据的情况下，使用多个线程可能会极大地提高程序的性能。然而，在多线程环境中，我们首先要处理并发访问，因为使用多个线程访问集合可能会导致其损坏。例如，让我们看一个线程安全的堆栈实现。

# 实现线程安全的堆栈

回想一下来自第六章的栈数据结构适配器，《深入 STL 中的数据结构和算法》。我们将使用锁来实现栈的线程安全版本。栈有两个基本操作，`push`和`pop`。它们都修改容器的状态。正如您所知，栈本身不是一个容器；它是一个包装容器并提供适应接口以进行访问的适配器。我们将在一个新的类中包装`std::stack`，并加入线程安全性。除了构造和销毁函数外，`std::stack`提供以下函数：

+   `top()`: 访问栈顶元素

+   `empty()`: 如果栈为空则返回 true

+   `size()`: 返回栈的当前大小

+   `push()`: 将新项插入栈中（在顶部）

+   `emplace()`: 在栈顶就地构造一个元素

+   `pop()`: 移除栈顶元素

+   `swap()`: 与另一个栈交换内容

我们将保持简单，专注于线程安全的概念，而不是制作功能强大的完整功能栈。这里的主要关注点是修改底层数据结构的函数。我们感兴趣的是`push()`和`pop()`函数。这些函数可能在多个线程相互干扰时破坏数据结构。因此，以下声明是表示线程安全栈的类：

```cpp
template <typename T>
class safe_stack
{
public:
  safe_stack();
  safe_stack(const safe_stack& other);
  void push(T value); // we will std::move it instead of copy-referencing
  void pop();
  T& top();
  bool empty() const;

private:
  std::stack<T> wrappee_;
  mutable std::mutex mutex_;
};
```

请注意，我们将`mutex_`声明为可变的，因为我们在`empty()` const 函数中对其进行了锁定。这可能是一个比去除`empty()`的 const 性更好的设计选择。然而，您现在应该知道，对于任何数据成员使用可变性都意味着我们做出了糟糕的设计选择。无论如何，`safe_stack`的客户端代码不会太关心实现的内部细节；它甚至不知道栈使用互斥锁来同步并发访问。

现在让我们来看一下其成员函数的实现以及简短的描述。让我们从复制构造函数开始：

```cpp
safe_stack::safe_stack(const safe_stack& other)
{
  std::lock_guard<std::mutex> lock(other.mutex_);
  wrappee_ = other.wrappee_;
}
```

请注意，我们锁定了另一个栈的互斥锁。尽管这看起来不公平，但我们需要确保在复制它时，另一个栈的底层数据不会被修改。

接下来，让我们来看一下`push()`函数的实现。显然很简单；我们锁定互斥锁并将数据推入底层栈：

```cpp
void safe_stack::push(T value)
{
  std::lock_guard<std::mutex> lock(mutex_);
  // note how we std::move the value
  wrappee_.push(std::move(value));
}
```

几乎所有函数都以相同的方式包含线程同步：锁定互斥锁，执行任务，然后解锁互斥锁。这确保了一次只有一个线程访问数据。也就是说，为了保护数据免受竞态条件的影响，我们必须确保函数不变量不被破坏。

如果您不喜欢输入长的 C++类型名称，比如`std::lock_guard<std::mutex>`，可以使用`using`关键字为类型创建短别名，例如，使用`locker = std::guard<std::mutex>;`。

现在，让我们来看一下`pop()`函数，我们可以修改类声明，使`pop()`直接返回栈顶的值。我们这样做主要是因为我们不希望有人在另一个线程中访问栈顶（通过引用），然后从中弹出数据。因此，我们将修改`pop()`函数以创建一个共享对象，然后返回栈元素：

```cpp
std::shared_ptr<T> pop()
{
  std::lock_guard<std::mutex> lock(mutex_);
  if (wrappee_.empty()) {
    throw std::exception("The stack is empty");
  }
  std::shared_ptr<T> top_element{std::make_shared<T>(std::move(wrappee_.top()))};
  wrappee_.pop();
  return top_element;
}
```

请注意，`safe_stack`类的声明也应根据`pop()`函数的修改而改变。此外，我们不再需要`top()`。

# 设计无锁数据结构

如果至少有一个线程保证可以取得进展，那么我们称它是无锁函数。与基于锁的函数相比，其中一个线程可以阻塞另一个线程，它们可能都在等待某些条件才能取得进展，无锁状态确保至少一个线程取得进展。我们说使用数据同步原语的算法和数据结构是阻塞的，也就是说，线程被挂起，直到另一个线程执行操作。这意味着线程在解除阻塞之前无法取得进展（通常是解锁互斥锁）。我们感兴趣的是不使用阻塞函数的数据结构和算法。我们称其中一些为无锁，尽管我们应该区分非阻塞算法和数据结构的类型。

# 使用原子类型

在本章的前面，我们介绍了源代码行之间的间隙是数据竞争的原因。每当您有一个由多个指令组成的操作时，您的大脑都应该警惕可能出现的问题。然而，无论您多么努力使操作独立和单一，大多数情况下，您都无法在不将操作分解为涉及多个指令的步骤的情况下取得任何成果。C++通过提供原子类型来拯救我们。

首先，让我们了解为什么使用原子这个词。一般来说，我们理解原子是指不能分解成更小部分的东西。也就是说，原子操作是一个无法半途而废的操作：要么完成了，要么没有。原子操作的一个例子可能是对整数的简单赋值：

```cpp
num = 37;
```

如果两个线程访问这行代码，它们都不可能遇到它是半成品的情况。换句话说，赋值之间没有间隙。当然，如果`num`表示具有用户定义赋值运算符的复杂对象，同一语句可能会有很多间隙。

原子操作是不可分割的操作。

另一方面，非原子操作可能被视为半成品。经典的例子是我们之前讨论过的增量操作。在 C++中，对原子类型的所有操作也是原子的。这意味着我们可以通过使用原子类型来避免行之间的间隙。在使用原子操作之前，我们可以通过使用互斥锁来创建原子操作。例如，我们可能会考虑以下函数是原子的：

```cpp
void foo()
{
  mutex.lock();
  int a{41};
  int b{a + 1};
  mutex.unlock();
}
```

真正的原子操作和我们刚刚制作的假操作之间的区别在于原子操作不需要锁。这实际上是一个很大的区别，因为诸如互斥锁之类的同步机制会带来开销和性能惩罚。更准确地说，原子类型利用低级机制来确保指令的独立和原子执行。标准原子类型在`<atomic>`头文件中定义。然而，标准原子类型可能也使用内部锁。为了确保它们不使用内部锁，标准库中的所有原子类型都公开了`is_lock_free()`函数。

唯一没有`is_lock_free()`成员函数的原子类型是`std::atomic_flag`。对这种类型的操作要求是无锁的。它是一个布尔标志，大多数情况下被用作实现其他无锁类型的基础。

也就是说，如果`obj.is_lock_free()`返回`true`，则表示对`obj`的操作是直接使用原子指令完成的。如果返回 false，则表示使用了内部锁。更重要的是，`static constexpr`函数`is_always_lock_free()`在所有支持的硬件上返回`true`，如果原子类型始终是无锁的。由于该函数是`constexpr`，它允许我们在编译时定义类型是否是无锁的。这是一个重大进步，以良好的方式影响代码的组织和执行。例如，`std::atomic<int>::is_always_lock_free()`返回`true`，因为`std::atomic<int>`很可能始终是无锁的。

在希腊语中，a 意味着不，tomo 意味着切。原子一词源自希腊语 atomos，意思是不可分割的。也就是说，原子意味着不可分割的最小单位。我们使用原子类型和操作来避免指令之间的间隙。

我们使用原子类型的特化，例如 `std::atomic<long>`；但是，您可以参考以下表格以获取更方便的原子类型名称。表格的左列包含原子类型，右列包含其特化：

| **原子类型** | **特化** |
| --- | --- |
| `atomic_bool` | `std::atomic<bool>` |
| `atomic_char` | `std::atomic<char>` |
| `atomic_schar` | `std::atomic<signed char>` |
| `atomic_uchar` | `std::atomic<unsigned char>` |
| `atomic_int` | `std::atomic<int>` |
| `atomic_uint` | `std::atomic<unsigned>` |
| `atomic_short` | `std::atomic<short>` |
| `atomic_ushort` | `std::atomic<unsigned short>` |
| `atomic_long` | `std::atomic<long>` |
| `atomic_ulong` | `std::atomic<unsigned long>` |
| `atomic_llong` | `std::atomic<long long>` |
| `atomic_ullong` | `std::atomic<unsigned long long>` |
| `atomic_char16_t` | `std::atomic<char16_t>` |
| `atomic_char32_t` | `std::atomic<char32_t>` |
| `atomic_wchar_t` | `std::atomic<wchar_t>` |

上表代表了基本的原子类型。常规类型和原子类型之间的根本区别在于我们可以对它们应用的操作类型。现在让我们更详细地讨论原子操作。

# 原子类型的操作

回想一下我们在前一节讨论的间隙。原子类型的目标是要么消除指令之间的间隙，要么提供将多个指令组合在一起作为单个指令执行的操作。以下是原子类型的操作：

+   `load()`

+   `store()`

+   `exchange()`

+   `compare_exchange_weak()`

+   `compare_exchange_strong()`

+   `wait()`

+   `notify_one()`

+   `notify_all()`

`load()` 操作原子地加载并返回原子变量的值。`store()` 原子地用提供的非原子参数替换原子变量的值。

`load()` 和 `store()` 与非原子变量的常规读取和赋值操作类似。每当我们访问对象的值时，我们执行一个读取指令。例如，以下代码打印了 `double` 变量的内容：

```cpp
double d{4.2}; // "store" 4.2 into "d"
std::cout << d; // "read" the contents of "d"
```

对于原子类型，类似的读取操作转换为：

```cpp
atomic_int m;
m.store(42);             // atomically "store" the value
std::cout << m.load();   // atomically "read" the contents 
```

尽管上述代码没有实际意义，但我们包含了这个例子来表示对待原子类型的不同方式。应该通过原子操作来访问原子变量。以下代码表示了 `load()`、`store()` 和 `exchange()` 函数的定义： 

```cpp
T load(std::memory_order order = std::memory_order_seq_cst) const noexcept;
void store(T value, std::memory_order order = 
            std::memory_order_seq_cst) noexcept;
T exchange(T value, std::memory_order order = 
            std::memory_order_seq_cst) noexcept;
```

正如您所见，还有一个名为 `order` 的额外参数，类型为 `std::memory_order`。我们很快会对它进行描述。`exchange()` 函数以一种方式包含了 `store()` 和 `load()` 函数，以便原子地用提供的参数替换值，并原子地获取先前的值。

`compare_exchange_weak()` 和 `compare_exchange_strong()` 函数的工作方式相似。它们的定义如下：

```cpp
bool compare_exchange_weak(T& expected_value, T target_value, 
                           std::memory_order order = 
                            std::memory_order_seq_cst) noexcept;
bool compare_exchange_strong(T& expected_value, T target_value,
                            std::memory_order order =
                             std::memory_order_seq_cst) noexcept;
```

它们将第一个参数（`expected_value`）与原子变量进行比较，如果它们相等，则用第二个参数（`target_value`）替换变量。否则，它们会原子地将值加载到第一个参数中（这就是为什么它是通过引用传递的）。弱交换和强交换之间的区别在于 `compare_exchange_weak()` 允许出现错误（称为**虚假失败**），也就是说，即使 `expected_value` 等于底层值，该函数也会将它们视为不相等。这是因为在某些平台上，这会提高性能。

自 C++20 以来，已添加了`wait()`、`notify_one()`和`notify_all()`函数。`wait()`函数阻塞线程，直到原子对象的值修改。它接受一个参数与原子对象的值进行比较。如果值相等，它会阻塞线程。要手动解除线程阻塞，我们可以调用`notify_one()`或`notify_all()`。它们之间的区别在于`notify_one()`解除至少一个被阻塞的操作，而`notify_all()`解除所有这样的操作。

现在，让我们讨论我们在先前声明的原子类型成员函数中遇到的内存顺序。`std::memory_order`定义了原子操作周围的内存访问顺序。当多个线程同时读取和写入变量时，一个线程可以按照与另一个线程存储它们的顺序不同的顺序读取更改。原子操作的默认顺序是顺序一致的顺序 - 这就是`std::memory_order_seq_cst`的作用。有几种类型的顺序，包括`memory_order_relaxed`、`memory_order_consume`、`memory_order_acquire`、`memory_order_release`、`memory_order_acq_rel`和`memory_order_seq_cst`。在下一节中，我们将设计一个使用默认内存顺序的原子类型的无锁堆栈。

# 设计无锁堆栈

设计堆栈时要牢记的关键事项之一是确保从另一个线程返回的推送值是安全的。同样重要的是确保只有一个线程返回一个值。

在前面的章节中，我们实现了一个基于锁的堆栈，它包装了`std::stack`。我们知道堆栈不是一个真正的数据结构，而是一个适配器。通常，在实现堆栈时，我们选择向量或链表作为其基础数据结构。让我们看一个基于链表的无锁堆栈的例子。将新元素推入堆栈涉及创建一个新的列表节点，将其`next`指针设置为当前的`head`节点，然后将`head`节点设置为指向新插入的节点。

如果您对头指针或下一个指针这些术语感到困惑，请重新阅读第六章《深入 STL 中的数据结构和算法》，在那里我们详细讨论了链表。

在单线程环境中，上述步骤是可以的；但是，如果有多个线程修改堆栈，我们应该开始担心。让我们找出`push()`操作的陷阱。当将新元素推入堆栈时，发生了三个主要步骤：

1.  `node* new_elem = new node(data);`

1.  `new_elem->next = head_;`

1.  `head_ = new_elem;`

在第一步中，我们声明将插入到基础链表中的新节点。第二步描述了我们将其插入到列表的前面 - 这就是为什么新节点的`next`指针指向`head_`。最后，由于`head_`指针表示列表的起始点，我们应该重置其值以指向新添加的节点，就像第 3 步中所做的那样。

节点类型是我们在堆栈中用于表示列表节点的内部结构。以下是它的定义：

```cpp
template <typename T>
class lock_free_stack
{
private:
 struct node {
 T data;
 node* next;
 node(const T& d) : data(d) {}
 }  node* head_;
// the rest of the body is omitted for brevity
};
```

我们建议您首先查找代码中的空白 - 不是在前面的代码中，而是在我们描述将新元素推入堆栈时的步骤中。仔细看看。想象两个线程同时添加节点。一个线程在第 2 步中将新元素的下一个指针设置为指向`head_`。另一个线程使`head_`指向另一个新元素。很明显，这可能导致数据损坏。对于线程来说，在步骤 2 和 3 中有相同的`head_`是至关重要的。为了解决步骤 2 和 3 之间的竞争条件，我们应该使用原子比较/交换操作来保证在读取其值之前`head_`没有被修改。由于我们需要以原子方式访问头指针，这是我们如何修改`lock_free_stack`类中的`head_`成员的方式：

```cpp
template <typename T>
class lock_free_stack
{
private:
  // code omitted for brevity
 std::atomic<node*> head_;  // code omitted for brevity
};
```

这是我们如何在原子`head_`指针周围实现无锁`push（）`的方式：

```cpp
void push(const T& data)
{
  node* new_elem = new node(data);
  new_elem->next = head_.load();
  while (!head_.compare_exchange_weak(new_elem->next, new_elem));
}
```

我们使用`compare_exchange_weak（）`来确保`head_`指针的值与我们存储在`new_elem->next`中的值相同。如果是，我们将其设置为`new_elem`。一旦`compare_exchange_weak（）`成功，我们就可以确定节点已成功插入到列表中。

看看我们如何使用原子操作访问节点。类型为`T`的指针的原子形式-`std::atomic<T*>`-提供相同的接口。除此之外，`std::atomic<T*>`还提供指针的算术操作`fetch_add（）`和`fetch_sub（）`。它们对存储的地址进行原子加法和减法。这是一个例子：

```cpp
struct some_struct {};
any arr[10];
std::atomic<some_struct*> ap(arr);
some_struct* old = ap.fetch_add(2);
// now old is equal to arr
// ap.load() is equal to &arr[2]
```

我们故意将指针命名为`old`，因为`fetch_add（）`将数字添加到指针的地址并返回`old`值。这就是为什么`old`指向与`arr`指向的相同地址。

在下一节中，我们将介绍更多可用于原子类型的操作。现在，让我们回到我们的无锁栈。要`pop（）`一个元素，也就是移除一个节点，我们需要读取`head_`并将其设置为`head_`的下一个元素，如下所示：

```cpp
void pop(T& popped_element)
{
  node* old_head = head_;
  popped_element = old_head->data;
  head_ = head_->next;
  delete old_head;
}
```

现在，好好看看前面的代码。想象几个线程同时执行它。如果两个从堆栈中移除项目的线程读取相同的`head_`值会怎样？这和其他一些竞争条件导致我们采用以下实现：

```cpp
void pop(T& popped_element)
{
  node* old_head = head_.load();
  while (!head_.compare_exchange_weak(old_head, old_head->next));
  popped_element = old_head->data;
}
```

我们在前面的代码中几乎应用了与`push（）`函数相同的逻辑。前面的代码并不完美；它应该得到改进。我们建议您努力修改它以消除内存泄漏。

我们已经看到，无锁实现严重依赖于原子类型和操作。我们在上一节讨论的操作并不是最终的。现在让我们发现一些更多的原子操作。

# 原子操作的更多操作

在上一节中，我们在用户定义类型的指针上使用了`std::atomic<>`。也就是说，我们为列表节点声明了以下结构：

```cpp
// the node struct is internal to 
// the lock_free_stack class defined above
struct node
{
  T data;
  node* next;
};
```

节点结构是用户定义的类型。尽管在上一节中我们实例化了`std::atomic<node*>`，但以同样的方式，我们几乎可以为任何用户定义的类型实例化`std::atomic<>`，也就是`std::atomic<T>`。但是，您应该注意`std::atomic<T>`的接口仅限于以下函数：

+   `load（）`

+   `store（）`

+   `exchange（）`

+   `compare_exchange_weak（）`

+   `compare_exchange_strong（）`

+   `wait（）`

+   `notify_one（）`

+   `notify_all（）`

现在让我们根据底层类型的特定情况来查看原子类型上可用的操作的完整列表。

`std::atomic<>`与整数类型（如整数或指针）实例化具有以下操作，以及我们之前列出的操作：

+   `fetch_add（）`

+   `fetch_sub（）`

+   `fetch_or（）`

+   `fetch_and（）`

+   `fetch_xor（）`

此外，除了增量（`++`）和减量（`--`）之外，还有以下运算符可用：`+=`，`-=`，`|=`，`&=`和`^=`。

最后，有一种特殊的原子类型称为`atomic_flag`，具有两种可用操作：

+   `clear（）`

+   `test_and_set（）`

您应该将`std::atomic_flag`视为具有原子操作的位。`clear（）`函数将其清除，而`test_and_set（）`将值更改为`true`并返回先前的值。

# 总结

在本章中，我们介绍了一个相当简单的设计堆栈的例子。还有更复杂的例子可以研究和遵循。当我们讨论设计并发堆栈时，我们看了两个版本，其中一个代表无锁堆栈。与基于锁的解决方案相比，无锁数据结构和算法是程序员的最终目标，因为它们提供了避免数据竞争的机制，甚至无需同步资源。

我们还介绍了原子类型和操作，您可以在项目中使用它们来确保指令是不可分割的。正如您已经知道的那样，如果一条指令是原子的，就不需要担心它的同步。我们强烈建议您继续研究这个主题，并构建更健壮和复杂的无锁数据结构。在下一章中，我们将看到如何设计面向世界的应用程序。

# 问题

1.  在多线程单例实现中为什么要检查实例两次？

1.  在基于锁的栈的复制构造函数的实现中，为什么要锁定另一个栈的互斥量？

1.  原子类型和原子操作是什么？

1.  为什么对原子类型使用`load()`和`store()`？

1.  `std::atomic<T*>`支持哪些额外操作？

# 进一步阅读

+   《Atul Khot 的并发模式与最佳实践》，网址为[`www.packtpub.com/application-development/concurrent-patterns-and-best-practices`](https://www.packtpub.com/application-development/concurrent-patterns-and-best-practices)

+   《Maya Posch 的 C++多线程编程》,网址为[`www.packtpub.com/application-development/mastering-c-multithreading`](https://www.packtpub.com/application-development/mastering-c-multithreading)


# 第十章：设计面向全球的应用程序

在生产就绪项目中使用编程语言是学习语言本身的一个全新步骤。有时，这本书中的简单示例可能会在实际项目中采用不同的方法或面临许多困难。当理论遇到实践时，你才会学会这门语言。C++也不例外。学习语法、解决一些书中的问题或理解书中的一些简单示例是不同的。在创建真实世界的应用程序时，我们面临着不同范围的挑战，有时书籍缺乏支持实际问题的理论。

在本章中，我们将尝试涵盖使用 C++进行实际编程的基础知识，这将帮助你更好地处理真实世界的应用程序。复杂的项目需要大量的思考和设计。有时，程序员不得不完全重写项目，并从头开始，只是因为他们在开发初期做出了糟糕的设计选择。本章试图尽最大努力阐明软件设计的过程。你将学习更好地为你的项目设计架构的步骤。

我们将在本章中涵盖以下主题：

+   了解项目开发生命周期

+   设计模式及其应用

+   领域驱动设计

+   以亚马逊克隆为例的真实项目设计

# 技术要求

本章中使用`-std=c++2a`选项的 g++编译器来编译示例。你可以在[`github.com/PacktPublishing/Expert-CPP`](https://github.com/PacktPublishing/Expert-CPP)找到本章中使用的源文件。

# 项目开发生命周期

每当你面对一个问题时，你应该仔细考虑需求分析的过程。项目开发中最大的错误之一是在没有对问题本身进行彻底分析的情况下开始编码。

想象一种情况，你被要求创建一个计算器，一个简单的工具，允许用户对数字进行算术计算。假设你神奇地按时完成了项目并发布了程序。现在，用户开始使用你的计算器，迟早会发现他们的计算结果不会超过整数的最大值。当他们抱怨这个问题时，你准备用坚实的编码支持论据来为自己（和你的作品）辩护，比如这是因为在计算中使用了`int`数据类型。对你和你的同行程序员来说，这是完全可以理解的，但最终用户却无法接受你的论点。他们想要一个可以对足够大的数字进行求和的工具，否则他们根本不会使用你的程序。你开始着手下一个版本的计算器，这一次，你使用长整型甚至自定义实现的大数。当你自豪地将程序交付给等待你掌声的用户时，你突然意识到同样的用户抱怨没有功能来找到数字的对数或指数。这似乎令人生畏，因为可能会有越来越多的功能请求和越来越多的抱怨。

尽管这个例子有点简单，但它完全覆盖了真实世界中通常发生的情况。即使你为你的程序实现了所有功能，并考虑着去度一个值得的长假，用户也会开始抱怨程序中的错误。事实证明，有几种情况下，你的计算器表现出乎意料的行为，给出了错误的结果。迟早，你会意识到在将程序发布给大众之前，需要进行适当的测试。

我们将涉及在处理真实世界项目时应考虑的主题。每当你开始一个新项目时，应考虑以下步骤：

1.  需求收集和分析

1.  规格书创建

1.  设计和测试规划

1.  编码

1.  测试和稳定性

1.  发布和维护

前面的步骤并非对每个项目都是硬性规定，尽管它可能被认为是每个软件开发团队应该完成以实现成功产品发布的最低要求。实际上，由于 IT 领域的每个人最缺乏的是时间，大多数步骤都被省略了。但是，强烈建议遵循前面的步骤，因为最终它将在长期节省更多时间。

# 需求收集和分析

这是创建稳定产品的最关键步骤。程序员未能按时完成任务或在代码中留下许多错误的最常见原因之一是对项目的完全理解不足。

领域知识是如此重要，以至于在任何情况下都不应该被忽略。您可能很幸运地开发与您非常了解的内容相关的项目。但是，您应该考虑到并非每个人都像您一样幸运（嗯，您也可能是那么不幸）。

想象一下，您正在开发一个自动化分析和报告某家公司股票交易的项目。现在想象一下，您对股票和股票交易一无所知。您不了解熊市或牛市，交易交易的限制等等。您如何才能成功完成这个项目？

即使您了解股票市场和交易，您可能不了解下一个重大项目领域。如果您被要求设计和实施（有或没有团队）控制您所在城市气象站的项目，您在开始项目时会首先做什么？

您绝对应该从需求收集和分析开始。这只是一个涉及与客户沟通并就项目提出许多问题的过程。如果您没有与任何客户打交道，而是在一家产品公司工作，项目经理应被视为客户。即使项目是您的想法，您是独自工作，您也应该将自己视为客户，并且，尽管这听起来很荒谬，但要问自己很多问题（关于项目）。

假设我们要征服电子商务，并希望发布一个最终能够击败市场上的大鳄的产品。受欢迎和成功的电子商务市场包括亚马逊，eBay，阿里巴巴等。我们应该将问题陈述为“编写我们自己的亚马逊克隆”。我们应该如何收集项目的需求？

首先，我们应该列出所有我们应该实现的功能，然后我们会进行优先排序。例如，对于亚马逊克隆项目，我们可能会列出以下功能清单：

+   创建产品。

+   列出产品。

+   购买产品。

+   编辑产品细节。

+   移除产品。

+   按名称，价格范围和重量搜索产品。

+   偶尔通过电子邮件提醒用户产品的可用性。

功能应尽可能详细地描述；这将为开发人员（在这种情况下是您）解决问题。例如，创建产品应该由项目管理员或任何用户完成。如果用户可以创建产品，那么可能会有限制。可能会有用户错误地在我们的系统中创建数百个产品，以增加他们唯一产品的可见性。

详细信息应在与客户的沟通中说明，讨论和最终确定。如果您独自承担项目并且是项目的客户，则沟通是在项目需求上“为自己思考”的过程。

在获取需求完成后，我们建议对每个功能进行优先排序，并将它们分类为以下类别之一：

+   必须有

+   应该有

+   最好有

经过更多思考并对前述功能进行分类后，我们可以列出以下清单：

+   创建产品[必须有]。

+   列出产品[必须有]。

+   购买产品[必须有]。

+   编辑产品细节[应该有]。

+   移除产品[必须有]。

+   按名称搜索产品[必须有]。

+   按价格范围搜索产品[应该有]。

+   按重量搜索产品[很好有]。

+   偶尔通过电子邮件提醒用户产品的可用性[很好有]。

分类将为您提供一个从哪里开始的基本想法。程序员是贪婪的人；他们想要为他们的产品实现每一个可能的功能。这是通向失败的确定途径。你应该从最基本的功能开始——这就是为什么我们有一些很好的功能。有些人开玩笑地坚持认为，应该将很好的功能重新命名为永远不会有的功能，因为在实践中，它们永远不会被实现。

# 规格创建

并不是每个人都喜欢创建规格。嗯，大多数程序员讨厌这一步，因为这不是编码，而是写作。

在收集项目需求之后，你应该创建一个包含描述你的项目的每个细节的文档。这种规格有许多名称和类型。它可能被称为**项目需求文档**（**PRD**），**功能规格**，**开发规格**等等。认真的程序员和团队会在需求分析的结果中产生一个 PRD。这些认真的人的下一步是创建功能规格以及开发规格等等。我们将所有文档组合在一个名为**规格创建**的单一步骤中。

是否需要之前提到的任何子文档，这取决于你和你的团队。甚至最好有一个产品的视觉表示，而不是一个文本文档。无论你的文档采取什么形式，它都应该仔细地代表你在需求收集步骤中所取得的成就。为了对此有一个基本的理解，让我们试着记录一些我们之前收集到的功能（我们将把我们的项目称为*平台）*

+   创建产品。平台的用户具有管理员特权可以创建产品。

+   平台必须允许创建具有定义特权的用户。在这一点上，应该有两种类型的用户，即普通用户和管理员用户。

+   使用平台的任何用户都必须能够看到可用产品的列表。

+   产品应该有图片、价格、名称、重量和描述。

+   购买产品时，用户提供他们的卡片详细信息以结账和产品装运的详细信息。

+   每个注册用户都应该提供一个送货地址、信用卡详细信息和一个电子邮件账户。

列表可能会很长，实际上应该很长，因为列表越长，开发人员就越了解项目。

# 设计和测试规划

尽管我们坚持认为需求收集步骤是软件开发中最关键的一步，但设计和测试规划也可以被认为是同样关键的一步。如果你曾经在没有先设计项目的情况下开始一个项目，你已经知道它是不可能的。尽管激励性的语录坚持认为没有什么是不可能的，程序员确信至少有一件事是不可能的，那就是在没有先设计项目的情况下成功完成一个项目。

设计的过程是最有趣的一步；它迫使我们思考、绘画、再次思考、清理一切，然后重新开始。在设计项目时，你应该从顶部开始。首先，列出所有在项目中以某种方式涉及的实体和过程。以亚马逊克隆为例，我们可以列出以下实体和过程：

+   用户

+   注册和授权

+   产品

+   交易

+   仓库（包含产品）

+   装运

这是一个高层设计——一个通过最终设计的起点。在这一章中，我们将主要集中在项目的设计上。

# 分解实体

在列出关键实体和流程之后，我们开始将它们分解为更详细的实体，稍后将转换为类。最好还是勾画一下项目的设计。只需绘制包含实体名称的矩形，并用箭头连接它们，如果它们有某种联系或是同一流程的一部分。如果有一个包含或由实体 A 开始的流程，并在实体 B 结束或导致实体 B，你可以从实体 A 开始一个箭头指向实体 B。图画得多好并不重要，这是更好地理解项目的必要步骤。例如，看看下面的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/747174ee-fe32-4e39-930e-9add32033617.png)

将实体和流程分解为类及其相互通信是一种需要耐心和一致性的微妙艺术。例如，让我们尝试为**User**实体添加细节。根据规范创建步骤中所述，注册用户应提供交货地址、电子邮件地址和信用卡详细信息。让我们绘制一个代表用户的类图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/62615d23-0f68-42b3-914a-380356d7ba16.png)

现在出现了一个有趣的问题：我们应该如何处理实体内包含的复杂类型？例如，用户的交货地址是一个复杂类型。它不能只是`string`，因为迟早我们可能需要按照用户的交货地址对用户进行排序，以进行最佳的发货。例如，如果用户的交货地址与包含所购产品的仓库的地址不在同一个国家，那么货运公司可能会花费我们（或用户）一大笔钱。这是一个很好的场景，因为它引入了一个新问题，并更新了我们对项目的理解。原来我们应该处理的情况是，当用户订购的产品分配给一个距离用户物理位置很远的特定仓库时。如果我们有很多仓库，我们应该选择离用户最近的一个，其中包含所需的产品。这些问题不能立即得到答案，但这是设计项目的高质量结果。否则，这些问题将在编码过程中出现，并且我们会陷入其中比我们预想的时间更长的困境中。在任何已知的宇宙中，项目的初始估计都无法满足其完成日期。

那么，如何在`User`类中存储用户地址呢？如下例所示，简单的`std::string`就可以：

```cpp
class User
{
public:
  // code omitted for brevity
private:
  std::string address_;
  // code omitted for brevity
};
```

地址在其组成部分方面是一个复杂的对象。地址可能包括国家名称、国家代码、城市名称和街道名称，甚至可能包含纬度和经度。如果需要找到用户最近的仓库，后者就非常有用。为程序员创建更多类型以使设计更直观也是完全可以的。例如，以下结构可能非常适合表示用户的地址：

```cpp
struct Address
{
  std::string country;
  std::string city;
  std::string street;
  float latitude{};
  float longitude{};
};
```

现在，存储用户地址变得更加简单：

```cpp
class User
{
  // code omitted for brevity
  Address address_;
}; 
```

我们稍后会在本章回到这个例子。

设计项目的过程可能需要回到几个步骤来重新阐明项目需求。在澄清设计步骤之后，我们可以继续将项目分解为更小的组件。创建交互图也是一个不错的选择。

像下面这样的交互图将描述一些操作，比如**用户**进行**购买**产品的交易：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/0fc423b9-d3fb-4643-abb0-aadd1f55632b.png)

测试规划也可以被视为设计的一部分。它包括规划最终应用程序将如何进行测试。例如，之前的步骤包括一个地址的概念，结果发现，地址可以包含国家、城市等。一个合适的测试应该包括检查用户地址中的国家值是否可以成功设置。尽管测试规划通常不被认为是程序员的任务，但为您的项目做测试规划仍然是一种良好的实践。一个合适的测试计划会在设计项目时产生更多有用的信息。大多数输入数据处理和安全检查都是在测试规划中发现的。例如，在进行需求分析或编写功能规范时，可能不会考虑对用户名称或电子邮件地址设置严格限制。测试规划关心这样的情况，并迫使开发人员注意数据检查。然而，大多数程序员都急于达到项目开发的下一步，编码。

# 编码

正如之前所说，编码并不是项目开发的唯一部分。在编码之前，您应该通过利用规范中的所有需求来仔细设计您的项目。在项目开发的前几步彻底完成后，编码会变得更加容易和高效。

一些团队实践**测试驱动开发（TDD）**，这是生产更加稳定的项目发布的好方法。TDD 的主要概念是在项目实现之前编写测试。这对程序员来说是定义项目需求和在开发过程中出现的进一步问题的一个很好的方法。

假设我们正在为`User`类实现 setter。用户对象包含了之前讨论过的 email 字段，这意味着我们应该有一个`set_email()`方法，如下面的代码片段所示：

```cpp
class User
{
public:
  // code omitted for brevity
  void set_email(const std::string&);

private: 
  // code omitted for brevity
  std::string email_;
};
```

TDD 方法建议在实现`set_email()`方法之前编写一个测试函数。假设我们有以下测试函数：

```cpp
void test_set_email()
{
  std::string valid_email = "valid@email.com";
  std::string invalid_email = "112%$";
  User u;
  u.set_email(valid_email);
  u.set_email(invalid_email);
}
```

在上面的代码中，我们声明了两个`string`变量，其中一个包含了一个无效的电子邮件地址值。甚至在运行测试函数之前，我们就知道，在无效数据输入的情况下，`set_email()`方法应该以某种方式做出反应。常见的方法之一是抛出一个指示无效输入的异常。您也可以在`set_email`的实现中忽略无效输入，并返回一个指示操作成功的`boolean`值。错误处理应该在项目中保持一致，并得到所有团队成员的认可。假设我们选择抛出异常，因此，测试函数应该在将无效值传递给方法时期望一个异常。

然后，上述代码应该被重写如下：

```cpp
void test_set_email()
{
  std::string valid_email = "valid@email.com";
  std::string invalid_email = "112%$";

  User u;
  u.set_email(valid_email);
  if (u.get_email() == valid_email) {
    std::cout << "Success: valid email has been set successfully" << std::endl;
  } else {
    std::cout << "Fail: valid email has not been set" << std::endl;
  }

  try {
    u.set_email(invalid_email);
    std::cerr << "Fail: invalid email has not been rejected" << std::endl;
  } catch (std::exception& e) {
    std::cout << "Success: invalid email rejected" << std::endl;
  }
}
```

测试函数看起来已经完成。每当我们运行测试函数时，它会输出`set_email()`方法的当前状态。即使我们还没有实现`set_email()`函数，相应的测试函数也是实现细节的重要一步。我们现在基本上知道了这个函数应该如何对有效和无效的数据输入做出反应。我们可以添加更多种类的数据来确保`set_email()`方法在实现完成时得到充分测试。例如，我们可以用空字符串和长字符串来测试它。

这是`set_email()`方法的初始实现：

```cpp
#include <regex>
#include <stdexcept>

void User::set_email(const std::string& email)
{
  if (!std::regex_match(email, std::regex("(\\w+)(\\.|_)?(\\w*)@(\\w+)(\\.(\\w+))+")) {
    throw std::invalid_argument("Invalid email");
  }

  this->email_ = email;
}
```

在方法的初始实现之后，我们应该再次运行我们的测试函数，以确保实现符合定义的测试用例。

为项目编写测试被认为是一种良好的编码实践。有不同类型的测试，如单元测试、回归测试、冒烟测试等。开发人员应该为他们的项目支持单元测试覆盖率。

编码过程是项目开发生命周期中最混乱的步骤之一。很难估计一个类或其方法的实现需要多长时间，因为大部分问题和困难都是在编码过程中出现的。本章开头描述的项目开发生命周期的前几个步骤往往涵盖了大部分这些问题，并简化了编码过程。

# 测试和稳定

项目完成后，应进行适当的测试。通常，软件开发公司会有**质量保证**（**QA**）工程师，他们会细致地测试项目。

在测试阶段验证的问题会转化为相应的任务分配给程序员来修复。问题可能会影响项目的发布，也可能被归类为次要问题。

程序员的基本任务不是立即修复问题，而是找到问题的根本原因。为了简单起见，让我们看一下`generate_username()`函数，它使用随机数与电子邮件结合生成用户名：

```cpp
std::string generate_username(const std::string& email)
{
  int num = get_random_number();
  std::string local_part = email.substr(0, email.find('@'));
  return local_part + std::to_string(num);
}
```

`generate_username()`函数调用`get_random_number()`将返回的值与电子邮件地址的本地部分组合在一起。本地部分是电子邮件地址中`@`符号之前的部分。

QA 工程师报告说，与电子邮件的本地部分相关联的数字总是相同的。例如，对于电子邮件`john@gmail.com`，生成的用户名是`john42`，对于`amanda@yahoo.com`，是`amanda42`。因此，下次使用电子邮件`amanda@hotmail.com`尝试在系统中注册时，生成的用户名`amanda42`与已存在的用户名冲突。测试人员不了解项目的实现细节是完全可以的，因此他们将其报告为用户名生成功能中的问题。虽然你可能已经猜到真正的问题隐藏在`get_random_number()`函数中，但总会有情况出现，问题被修复而没有找到其根本原因。错误的方法修复问题可能会改变`generate_username()`函数的实现。`generate_random_number()`函数也可能在其他函数中使用，这将使调用`get_random_number()`的所有函数工作不正确。虽然这个例子很简单，但深入思考并找到问题的真正原因至关重要。这种方法将节省大量时间。

# 发布和维护

在修复所有关键和重大问题使项目变得相对稳定之后，可以发布项目。有时公司会在软件上加上**beta**标签，以防用户发现有 bug 时有借口。需要注意的是，很少有软件能够完美无缺地运行。发布后，会出现更多问题。因此，维护阶段就会到来，开发人员会在修复和发布更新时工作。

程序员有时开玩笑说，发布和维护是永远无法实现的步骤。然而，如果你花足够的时间设计项目，发布第一个版本就不会花费太多时间。正如我们在前一节中已经介绍的，设计从需求收集开始。之后，我们花时间定义实体，分解它们，将其分解为更小的组件，编码，测试，最后发布。作为开发人员，我们对设计和编码阶段更感兴趣。正如已经指出的，良好的设计选择对进一步的项目开发有很大的影响。现在让我们更仔细地看一下整个设计过程。

# 深入设计过程

如前所述，项目设计始于列出一般实体，如用户、产品和仓库，当设计电子商务平台时：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/b8991f30-493e-4e8f-84d7-02f1b58ed92e.png)

然后我们将每个实体分解为更小的组件。为了使事情更清晰，将每个实体视为一个单独的类。将实体视为类时，在分解方面更有意义。例如，我们将`user`实体表示为一个类：

```cpp
class User
{
public:
  // constructors and assignment operators are omitted for code brevity
  void set_name(const std::string& name);
  std::string get_name() const;
  void set_email(const std::string&);
  std::string get_email() const;
  // more setters and getters are omitted for code brevity

private:
  std::string name_;
  std::string email_;
  Address address_;
  int age;
};
```

`User`类的类图如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/bd7b14fe-6cee-47bd-be57-e54cd658200b.png)

然而，正如我们已经讨论过的那样，`User`类的地址字段可能被表示为一个单独的类型（`class`或`struct`，目前并不重要）。无论是数据聚合还是复杂类型，类图都会发生以下变化：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/a62f3623-ed77-4cca-9d29-fffe8c9a0bfc.png)

这些实体之间的关系将在设计过程中变得清晰。例如，**Address**不是一个独立的实体，它是**User**的一部分，也就是说，如果没有实例化**User**对象，它就不能有一个实例。然而，由于我们可能希望指向可重用的代码，**Address**类型也可以用于仓库对象。也就是说，**User**和**Address**之间的关系是简单的聚合而不是组合。

在讨论支付选项时，我们可能会对**User**类型提出更多要求。平台的用户应该能够插入支付产品的选项。在决定如何在`User`类中表示支付选项之前，我们应该首先找出这些选项是什么。让我们保持简单，假设支付选项是包含信用卡号、持卡人姓名、到期日和卡的安全码的选项。这听起来像另一个数据聚合，所以让我们将所有这些内容收集到一个单独的结构体中，如下所示：

```cpp
struct PaymentOption
{
  std::string number;
  std::string holder_name;
  std::chrono::year_month expiration_date;
  int code;
};
```

请注意前面结构体中的`std::chrono::year_month`；它表示特定年份的特定月份，是在 C++20 中引入的。大多数支付卡只包含卡的到期月份和年份，因此这个`std::chrono::year_month`函数非常适合`PaymentOption`。

因此，在设计`User`类的过程中，我们提出了一个新类型`PaymentOption`。用户可以拥有多个支付选项，因此`User`和`PaymentOption`之间的关系是一对多的。现在让我们用这个新的聚合更新`User`类的类图（尽管在这种情况下我们使用组合）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/c85c2d3a-0d3f-4143-8879-b5cf71ef29dd.png)

`User`和`PaymentOption`之间的依赖关系在以下代码中表示：

```cpp
class User
{
public:
  // code omitted for brevity
  void add_payment_option(const PaymentOption& po) {
    payment_options_.push_back(op);
  }

  std::vector get_payment_options() const {
    return payment_options_;
  }
private:
  // code omitted for brevity
  std::vector<PaymentOption> payment_options_;
};
```

我们应该注意，即使用户可能设置了多个支付选项，我们也应该将其中一个标记为主要选项。这很棘手，因为我们可以将所有选项存储在一个向量中，但现在我们必须将其中一个设为主要选项。

我们可以使用一对或`tuple`（如果想要花哨一点）将向量中的选项与`boolean`值进行映射，指示它是否是主要选项。以下代码描述了之前引入的`User`类中元组的使用：

```cpp
class User
{
public:
  // code omitted for brevity
  void add_payment_option(const PaymentOption& po, bool is_primary) {
    payment_options_.push_back(std::make_tuple(po, is_primary));
  }

  std::vector<std::tuple<PaymentOption, boolean> > get_payment_options() const {
    return payment_options_;
  }
private:
  // code omitted for brevity
  std::vector<std::tuple<PaymentOption, boolean> > payment_options_;
};
```

我们可以通过以下方式利用类型别名简化代码：

```cpp
class User
{
public:
  // code omitted for brevity
  using PaymentOptionList = std::vector<std::tuple<PaymentOption, boolean> >;

  // add_payment_option is omitted for brevity
  PaymentOptionList get_payment_options() const {
    return payment_options_;
  }

private:
  // code omitted for brevity
  PaymentOptionList payment_options_;
};
```

以下是用户类如何检索用户的主要支付选项的方法：

```cpp
User john = get_current_user(); // consider the function is implemented and works
auto payment_options = john.get_payment_options();
for (const auto& option : payment_options) {
  auto [po, is_primary] = option;
  if (is_primary) {
    // use the po payment option
  }
}
```

在`for`循环中访问元组项时，我们使用了结构化绑定。然而，在学习了关于数据结构和算法的章节之后，您现在意识到搜索主要支付选项是一个线性操作。每次需要检索主要支付选项时循环遍历向量可能被认为是一种不好的做法。

您可能会更改底层数据结构以使事情运行更快。例如，`std::unordered_map`（即哈希表）听起来更好。但是，这并不会使事情变得更快，仅仅因为它可以在常数时间内访问其元素。在这种情况下，我们应该将`boolean`值映射到支付选项。对于除一个之外的所有选项，`boolean`值都是相同的假值。这将导致哈希表中的冲突，这将由将值链接在一起映射到相同哈希值的方式来处理。使用哈希表的唯一好处将是对主要支付选项进行常数时间访问。

最后，我们来到了将主要支付选项单独存储在类中的最简单的解决方案。以下是我们应该如何重写`User`类中处理支付选项的部分：

```cpp
class User
{
public:
  // code omitted for brevity
  using PaymentOptionList = std::vector<PaymentOption>;
  PaymentOption get_primary_payment_option() const {
    return primary_payment_option_;
  }

  PaymentOptionList get_payment_options() const {
    return payment_options_;
  }

  void add_payment_option(const PaymentOption& po, bool is_primary) {
    if (is_primary) {
      // moving current primary option to non-primaries
      add_payment_option(primary_payment_option_, false);
      primary_payment_option_ = po;
      return;
    }
    payment_options_.push_back(po);
  }

private:
  // code omitted for brevity
  PaymentOption primary_payment_option_;
  PaymentOptionList payment_options_;
};
```

到目前为止，我们已经带您了解了存储支付选项的方式的过程，只是为了展示设计伴随编码的过程。尽管我们为支付选项的单一情况创建了许多版本，但这并不是最终版本。在支付选项向量中处理重复值的情况总是存在。每当您将一个支付选项添加为主要选项，然后再添加另一个选项为主要选项时，先前的选项将移至非主要列表。如果我们改变主意并再次将旧的支付选项添加为主要选项，它将不会从非主要列表中移除。

因此，总是有机会深入思考并避免潜在问题。设计和编码是相辅相成的；然而，您不应忘记 TDD。在大多数情况下，在编码之前编写测试将帮助您发现许多用例。

# 使用 SOLID 原则

在项目设计中，您可以使用许多原则和设计方法。保持设计简单总是更好，但是有些原则在一般情况下几乎对所有项目都有用。例如，**SOLID**包括五个原则，其中的一个或全部可以对设计有用。

SOLID 代表以下原则：

+   单一职责

+   开闭原则

+   里氏替换

+   接口隔离

+   依赖反转

让我们通过示例讨论每个原则。

# 单一职责原则

单一职责原则简单地说明了一个对象，一个任务。尽量减少对象的功能和它们的关系复杂性。使每个对象只负责一个任务，即使将复杂对象分解为更小更简单的组件并不总是容易的。单一职责是一个上下文相关的概念。它不是指类中只有一个方法；而是使类或模块负责一个事情。例如，我们之前设计的`User`类只有一个职责：存储用户信息。然而，我们将支付选项添加到`User`类中，并强制它具有添加和删除支付选项的方法。我们还引入了主要支付选项，这涉及**User**方法中的额外逻辑。我们可以朝两个方向发展。

第一个建议将`User`类分解为两个单独的类。每个类将负责一个单一的功能。以下类图描述了这个想法：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/711b0c46-dd8c-438a-904c-c1727528681d.png)

其中一个将仅存储用户的基本信息，下一个将存储用户的支付选项。我们分别命名它们为`UserInfo`和`UserPaymentOptions`。有些人可能会喜欢这种新设计，但我们会坚持旧的设计。原因在于，`User`类既包含用户信息又包含支付选项，后者也代表了一部分信息。我们设置和获取支付选项的方式与设置和获取用户的电子邮件的方式相同。因此，我们保持`User`类不变，因为它已经满足了单一职责原则。当我们在`User`类中添加付款功能时，这将破坏平衡。在这种情况下，`User`类将既存储用户信息又进行付款交易。这在单一职责原则方面是不可接受的，因此我们不会这样做。

单一职责原则也与函数相关。`add_payment_option()`方法有两个职责。如果函数的第二个（默认）参数为 true，则它会添加一个新的主要支付选项。否则，它会将新的支付选项添加到非主要选项列表中。最好为添加主要支付选项单独创建一个方法。这样，每个方法都将有单一职责。

# 开闭原则

开闭原则规定一个类应该对扩展开放，对修改关闭。这意味着每当你需要新的功能时，最好是扩展基本功能而不是修改它。例如，我们设计的电子商务应用程序中的`Product`类。以下是`Product`类的简单图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/7a087189-9c02-4c59-857f-38a419d1299d.png)

每个`Product`对象都有三个属性：**名称**、**价格**和**重量**。现在，想象一下，在设计了`Product`类和整个电子商务平台之后，客户提出了一个新的需求。他们现在想购买数字产品，如电子书、电影和音频录音。一切都很好，除了产品的重量。现在可能会有两种产品类型——有形和数字——我们应该重新思考`Product`使用的逻辑。我们可以像这里的代码中所示那样在`Product`中加入一个新的功能：

```cpp
class Product
{
public:
  // code omitted for brevity
  bool is_digital() const {
    return weight_ == 0.0;
  }

  // code omitted for brevity
};
```

显然，我们修改了类——违反了开闭原则。该原则规定类应该对修改关闭。它应该对扩展开放。我们可以通过重新设计`Product`类并将其制作成所有产品的抽象基类来实现这一点。接下来，我们创建两个更多的类，它们继承`Product`基类：`PhysicalProduct`和`DigitalProduct`。下面的类图描述了新的设计：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/39a14c81-c9c5-4dee-8924-e6cbccf9a257.png)

正如前面的图表所示，我们从`Product`类中删除了`weight_`属性。现在我们有了两个更多的类，`PhysicalProduct`有一个`weight_`属性，而`DigitalProduct`没有。相反，它有一个`file_path_`属性。这种方法满足了开闭原则，因为现在所有的类都可以扩展。我们使用继承来扩展类，而下面的原则与此密切相关。

# 里斯科夫替换原则

里斯科夫替换原则是关于正确继承类型的方式。简单来说，如果有一个函数接受某种类型的参数，那么同一个函数应该接受派生类型的参数。

里斯科夫替换原则是以图灵奖获得者、计算机科学博士芭芭拉·里斯科夫的名字命名的。

一旦你理解了继承和里氏替换原则，就很难忘记它。让我们继续开发`Product`类，并添加一个根据货币类型返回产品价格的新方法。我们可以将价格存储在相同的货币单位中，并提供一个将价格转换为指定货币的函数。以下是该方法的简单实现：

```cpp
enum class Currency { USD, EUR, GBP }; // the list goes further

class Product
{
public:
  // code omitted for brevity
  double convert_price(Currency c) {
    // convert to proper value
  }

  // code omitted for brevity
};
```

过了一段时间，公司决定为所有数字产品引入终身折扣。现在，每个数字产品都将享有 12%的折扣。在短时间内，我们在`DigitalProduct`类中添加了一个单独的函数，该函数通过应用折扣返回转换后的价格。以下是`DigitalProduct`中的实现：

```cpp
class DigitalProduct : public Product
{
public:
  // code omitted for brevity
  double convert_price_with_discount(Currency c) {
    // convert by applying a 12% discount
  } 
};
```

设计中的问题是显而易见的。在`DigitalProduct`实例上调用`convert_price()`将没有效果。更糟糕的是，客户端代码不应该调用它。相反，它应该调用`convert_price_with_discount()`，因为所有数字产品必须以 12%的折扣出售。设计违反了里氏替换原则。

我们不应该破坏类层次结构，而应该记住多态的美妙之处。一个更好的版本将如下所示：

```cpp
class Product
{
public:
  // code omitted for brevity
  virtual double convert_price(Currency c) {
    // default implementation
  }

  // code omitted for brevity
};

class DigitalProduct : public Product
{
public:
  // code omitted for brevity
  double convert_price(Currency c) override {
    // implementation applying a 12% discount
  }

  // code omitted for brevity
};
```

正如您所看到的，我们不再需要`convert_price_with_discount()`函数。而且里氏替换原则得到了遵守。然而，我们应该再次检查设计中的缺陷。让我们通过在基类中引入用于折扣计算的私有虚方法来改进它。以下是`Product`类的更新版本，其中包含一个名为`calculate_discount()`的私有虚成员函数：

```cpp
class Product
{
public:
  // code omitted for brevity
  virtual double convert_price(Currency c) {
    auto final_price = apply_discount();
    // convert the final_price based on the currency
  }

private:
 virtual double apply_discount() {
 return getPrice(); // no discount by default
 }

  // code omitted for brevity
};
```

`convert_price()`函数调用私有的`apply_discount()`函数，该函数返回原价。这里有一个技巧。我们在派生类中重写`apply_discount()`函数，就像下面的`DigitalProduct`实现中所示：

```cpp
class DigitalProduct : public Product
{
public:
  // code omitted for brevity

private:
  double apply_discount() override {
 return getPrice() * 0.12;
 }

  // code omitted for brevity
};
```

我们无法在类外部调用私有函数，但我们可以在派生类中重写它。前面的代码展示了重写私有虚函数的美妙之处。我们修改了实现，但接口保持不变。如果派生类不需要为折扣计算提供自定义功能，则不需要重写它。另一方面，`DigitalProduct`需要在转换之前对价格进行 12%的折扣。不需要修改基类的公共接口。

您应该考虑重新思考`Product`类的设计。直接在`getPrice()`中调用`apply_discount()`似乎更好，因此始终返回最新的有效价格。尽管在某些时候，您应该强迫自己停下来。

设计过程是有创意的，有时也是不感激的。由于意外的新需求，重写所有代码并不罕见。我们使用原则和方法来最小化在实现新功能后可能出现的破坏性变化。SOLID 的下一个原则是最佳实践之一，它将使您的设计更加灵活。

# 接口隔离原则

接口隔离原则建议将复杂的接口分成更简单的接口。这种隔离允许类避免实现它们不使用的接口。

在我们的电子商务应用中，我们应该实现产品发货、替换和过期功能。产品的发货是将产品项目移交给买家。在这一点上，我们不关心发货的细节。产品的替换考虑在向买家发货后替换损坏或丢失的产品。最后，产品的过期意味着处理在到期日期之前未销售的产品。

我们可以在前面介绍的`Product`类中实现所有功能。然而，最终我们会遇到一些产品类型，例如无法运输的产品（例如，很少有人会将房屋运送给买家）。可能有一些产品是不可替代的。例如，原始绘画即使丢失或损坏也无法替换。最后，数字产品永远不会过期。嗯，大多数情况下是这样。

我们不应该强制客户端代码实现它不需要的行为。在这里，客户端指的是实现行为的类。以下示例是违反接口隔离原则的不良实践：

```cpp
class IShippableReplaceableExpirable
{
public:
  virtual void ship() = 0;
  virtual void replace() = 0;
  virtual void expire() = 0;
};
```

现在，`Product`类实现了前面展示的接口。它必须为所有方法提供实现。接口隔离原则建议以下模型：

```cpp
class IShippable
{
public:
  virtual void ship() = 0;
};

class IReplaceable
{
public:
  virtual void replace() = 0;
};

class IExpirable
{
public:
  virtual void expire() = 0;
};
```

现在，`Product`类跳过了实现任何接口。它的派生类从特定类型派生（实现）。以下示例声明了几种产品类的类型，每种类型都支持前面介绍的有限数量的行为。请注意，为了代码简洁起见，我们省略了类的具体内容：

```cpp
class PhysicalProduct : public Product {};

// The book does not expire
class Book : public PhysicalProduct, public IShippable, public IReplaceable
{
};

// A house is not shipped, not replaced, but it can expire 
// if the landlord decided to put it on sell till a specified date
class House : public PhysicalProduct, public IExpirable
{
};

class DigitalProduct : public Product {};

// An audio book is not shippable and it cannot expire. 
// But we implement IReplaceable in case we send a wrong file to the user.
class AudioBook : public DigitalProduct, public IReplaceable
{
};
```

如果要将文件下载包装为货物，可以考虑为`AudioBook`实现`IShippable`。

# 依赖倒置原则

最后，依赖倒置原则规定对象不应该紧密耦合。它允许轻松切换到替代依赖。例如，当用户购买产品时，我们会发送购买收据。从技术上讲，有几种发送收据的方式，即打印并通过邮件发送，通过电子邮件发送，或在平台的用户账户页面上显示收据。对于后者，我们会通过电子邮件或应用程序向用户发送通知，告知收据已准备好查看。看一下以下用于打印收据的接口：

```cpp
class IReceiptSender
{
public:
  virtual void send_receipt() = 0;
};
```

假设我们已经在`Product`类中实现了`purchase()`方法，并在完成后发送了收据。以下代码部分处理了发送收据的过程：

```cpp
class Product
{
public:
  // code omitted for brevity
  void purchase(IReceiptSender* receipt_sender) {
    // purchase logic omitted
    // we send the receipt passing purchase information
 receipt_sender->send(/* purchase-information */);
  }
};
```

我们可以通过添加所需的收据打印选项来扩展应用程序。以下类实现了`IReceiptSender`接口：

```cpp
class MailReceiptSender : public IReceiptSender
{
public:
  // code omitted for brevity
  void send_receipt() override { /* ... */ }
};
```

另外两个类——`EmailReceiptSender`和`InAppReceiptSender`——都实现了`IReceiptSender`。因此，要使用特定的收据，我们只需通过`purchase()`方法将依赖注入到`Product`中，如下所示：

```cpp
IReceiptSender* rs = new EmailReceiptSender();
// consider the get_purchasable_product() is implemented somewhere in the code
auto product = get_purchasable_product();
product.purchase(rs);
```

我们可以进一步通过在`User`类中实现一个方法，返回具体用户所需的收据发送选项。这将使类之间的耦合更少。

在前面讨论的所有 SOLID 原则中，都是组合类的一种自然方式。遵循这些原则并不是强制性的，但如果遵循这些原则，将会改善你的设计。

# 使用领域驱动设计

领域是程序的主题领域。我们正在讨论和设计一个以电子商务为主题概念的电子商务平台，所有附属概念都是该领域的一部分。我们建议您在项目中考虑领域驱动设计。然而，该方法并不是程序设计的万能药。

设计项目时，考虑以下三层三层架构的三个层次是很方便的：

+   演示

+   业务逻辑

+   数据

三层架构适用于客户端-服务器软件，例如我们在本章中设计的软件。表示层向用户提供与产品、购买和货物相关的信息。它通过向客户端输出结果与其他层进行通信。这是客户直接访问的一层，例如，Web 浏览器。

业务逻辑关心应用功能。例如，用户浏览由表示层提供的产品，并决定购买其中的一个。请求的处理是业务层的任务。在领域驱动设计中，我们倾向于将领域级实体与其属性结合起来，以应对应用程序的复杂性。我们将用户视为`User`类的实例，产品视为`Product`类的实例，依此类推。用户购买产品被业务逻辑解释为`User`对象创建一个`Order`对象，而`Order`对象又与`Product`对象相关联。然后，`Order`对象与与购买产品相关的`Transaction`对象相关联。购买的相应结果通过表示层表示。

最后，数据层处理存储和检索数据。从用户认证到产品购买，每个步骤都从系统数据库（或数据库）中检索或记录。

将应用程序分成层可以处理其整体的复杂性。最好协调具有单一责任的对象。领域驱动设计区分实体和没有概念身份的对象。后者被称为值对象。例如，用户不区分每个唯一的交易；他们只关心交易所代表的信息。另一方面，用户对象以`User`类的形式具有概念身份（实体）。

使用其他对象（或不使用）对对象执行的操作称为服务。服务更像是一个不与特定对象绑定的操作。例如，通过`set_name()`方法设置用户的名称是一个不应被视为服务的操作。另一方面，用户购买产品是由服务封装的操作。

最后，领域驱动设计强烈地融合了**存储库**和**工厂**模式。存储库模式负责检索和存储领域对象的方法。工厂模式创建领域对象。使用这些模式允许我们在需要时交换替代实现。现在让我们在电子商务平台的背景下发现设计模式的力量。

# 利用设计模式

设计模式是软件设计中常见问题的架构解决方案。重要的是要注意，设计模式不是方法或算法。它们是提供组织类和它们之间关系的一种架构构造，以实现更好的代码可维护性的方式。即使以前没有使用过设计模式，你很可能已经自己发明了一个。许多问题在软件设计中往往会反复出现。例如，为现有库创建更好的接口是一种称为**facade**的设计模式形式。设计模式有名称，以便程序员在对话或文档中使用它们。与其他程序员使用 facade、factory 等进行闲聊应该是很自然的。

我们之前提到领域驱动设计融合了存储库和工厂模式。现在让我们来了解它们是什么，以及它们如何在我们的设计努力中发挥作用。

# 存储库模式

正如 Martin Fowler 最好地描述的那样，存储库模式“在领域和数据映射层之间使用类似集合的接口来访问领域对象”。

该模式提供了直接的数据操作方法，无需直接使用数据库驱动程序。添加、更新、删除或选择数据自然地适用于应用程序域。

其中一种方法是创建一个提供必要功能的通用存储库类。简单的接口如下所示：

```cpp
class Entity; // new base class

template <typename T, typename = std::enable_if_t<std::is_base_of_v<Entity, T>>>
class Repository
{
public:
 T get_by_id(int);
 void insert(const T&);
 void update(const T&);
 void remove(const T&);
 std::vector<T> get_all(std::function<bool(T)> condition);
};
```

我们在前面引入了一个名为`Entity`的新类。`Repository`类与实体一起工作，并确保每个实体都符合`Entity`的相同接口，它应用`std::enable_if`以及`std::is_base_of_v`到模板参数。

`std::is_base_of_v`是`std::is_base_of<>::value`的简写。此外，`std::enable_if_t`替换了`std::enable_if<>::type`。

`Entity`类的表示如下：

```cpp
class Entity
{
public:
  int get_id() const;
  void set_id(int);
private:
  int id_;
};
```

每个业务对象都是一个`Entity`，因此，前面讨论的类应该更新为从`Entity`继承。例如，`User`类的形式如下：

```cpp
class User : public Entity
{
// code omitted for brevity
};
```

因此，我们可以这样使用存储库：

```cpp
Repository<User> user_repo;
User fetched_user = user_repo.get_by_id(111);
```

前面介绍的存储库模式是对该主题的简单介绍，但是你可以使它更加强大。它类似于外观模式。虽然使用外观模式的重点不是访问数据库，但是最好用数据库访问来解释。外观模式包装了一个复杂的类或类，为客户端提供了一个简单的预定义接口，以便使用底层功能。

# 工厂模式

当程序员谈论工厂模式时，他们可能会混淆工厂方法和抽象工厂。这两者都是提供各种对象创建机制的创建模式。让我们讨论工厂方法。它提供了一个在基类中创建对象的接口，并允许派生类修改将被创建的对象。

现在是处理物流的时候了，工厂方法将在这方面帮助我们。当你开发一个提供产品发货的电子商务平台时，你应该考虑到并非所有用户都住在你的仓库所在的同一地区。因此，从仓库向买家发货时，你应该选择适当的运输类型。自行车、无人机、卡车等等。感兴趣的问题是设计一个灵活的物流管理系统。

不同的交通工具需要不同的实现。然而，它们都符合一个接口。以下是`Transport`接口及其派生的具体交通工具实现的类图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/9440ba69-a862-495f-b00d-4e2a4db2e746.png)

前面图表中的每个具体类都提供了特定的交付实现。

假设我们设计了以下`Logistics`基类，负责与物流相关的操作，包括选择适当的运输方式，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/69a43738-0ce0-4c88-8f17-b5a8d36fec0f.png)

前面应用的工厂方法允许灵活地添加新的运输类型以及新的物流方法。注意`createTransport()`方法返回一个`Transport`指针。派生类覆盖该方法，每个派生类返回`Transport`的子类，从而提供了特定的运输方式。这是可能的，因为子类返回了派生类型，否则在覆盖基类方法时无法返回不同的类型。

`Logistics`中的`createTransport()`如下所示：

```cpp
class Logistics 
{
public:
 Transport* getLogistics() = 0;
  // other functions are omitted for brevity
};
```

`Transport`类代表了`Drone`、`Truck`和`Ship`的基类。这意味着我们可以创建每个实例，并使用`Transport`指针引用它们，如下所示：

```cpp
Transport* ship_transport = new Ship();
```

这是工厂模式的基础，因为例如`RoadLogistics`覆盖了`getLogistics()`，如下所示：

```cpp
class RoadLogistics : public Logistics
{
public: 
  Truck* getLogistics() override {
 return new Truck();
 }
}
```

注意函数的返回类型，它是`Truck`而不是`Transport`。这是因为`Truck`继承自`Transport`。另外，看看对象的创建是如何与对象本身解耦的。创建新对象是通过工厂完成的，这与之前讨论的 SOLID 原则保持一致。

乍一看，利用设计模式似乎会给设计增加额外的复杂性。然而，当实践设计模式时，你应该培养对更好设计的真正感觉，因为它们允许项目整体具有灵活性和可扩展性。

# 总结

软件开发需要细致的规划和设计。我们在本章中学到，项目开发包括以下关键步骤：

+   需求收集和分析：这包括理解项目的领域，讨论和最终确定应该实现的功能。

+   规范创建：这包括记录需求和项目功能。

+   设计和测试规划：这指的是从更大的实体开始设计项目，然后将每个实体分解为一个单独的类，考虑到项目中的其他类。这一步还涉及规划项目的测试方式。

+   编码：这一步涉及编写代码，实现前面步骤中指定的项目。

+   测试和稳定性：这意味着根据预先计划的用例和场景检查项目，以发现问题并加以修复。

+   发布和维护：这是最后一步，将我们带到项目的发布和进一步的维护。

项目设计对程序员来说是一个复杂的任务。他们应该提前考虑，因为部分功能是在开发过程中引入的。

为了使设计灵活而健壮，我们已经讨论了导致更好架构的原则和模式。我们已经学习了设计软件项目及其复杂性的过程。

避免糟糕的设计决策的最佳方法之一是遵循已经设计好的模式和实践。在未来的项目中，你应该考虑使用 SOLID 原则以及经过验证的设计模式。

在下一章中，我们将设计一个策略游戏。我们将熟悉更多的设计模式，并看到它们在游戏开发中的应用。

# 问题

1.  TDD 的好处是什么？

1.  UML 中交互图的目的是什么？

1.  组合和聚合之间有什么区别？

1.  你会如何描述 Liskov 替换原则？

1.  假设你有一个`Animal`类和一个`Monkey`类。后者描述了一种特定的会在树上跳跃的动物。从`Animal`类继承`Monkey`类是否违反了开闭原则？

1.  在本章讨论的`Product`类及其子类上应用工厂方法。

# 进一步阅读

有关更多信息，请参阅：

+   *《面向对象的分析与设计与应用》* by Grady Booch，[`www.amazon.com/Object-Oriented-Analysis-Design-Applications-3rd/dp/020189551X/`](https://www.amazon.com/Object-Oriented-Analysis-Design-Applications-3rd/dp/020189551X/)

+   *《设计模式：可复用面向对象软件的元素》* by Erich Gamma 等人，[`www.amazon.com/Design-Patterns-Elements-Reusable-Object-Oriented/dp/0201633612/`](https://www.amazon.com/Design-Patterns-Elements-Reusable-Object-Oriented/dp/0201633612/)

+   *《代码大全：软件构建的实用手册》* by Steve McConnel，[`www.amazon.com/Code-Complete-Practical-Handbook-Construction/dp/0735619670/`](https://www.amazon.com/Code-Complete-Practical-Handbook-Construction/dp/0735619670/)

+   *《领域驱动设计：软件核心复杂性的应对》* by Eric Evans，[`www.amazon.com/Domain-Driven-Design-Tackling-Complexity-Software/dp/0321125215/`](https://www.amazon.com/Domain-Driven-Design-Tackling-Complexity-Software/dp/0321125215/)
