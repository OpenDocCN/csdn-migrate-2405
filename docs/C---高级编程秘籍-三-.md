# C++ 高级编程秘籍（三）

> 原文：[`annas-archive.org/md5/24e080e694c59b3f8e0220d0902724b0`](https://annas-archive.org/md5/24e080e694c59b3f8e0220d0902724b0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：并发和同步

在本章中，我们将学习如何正确处理 C++中的并发、同步和并行。在这里，您需要对 C++和 C++线程有一般的了解。本章很重要，因为在处理 C++时通常需要使用共享资源，如果没有正确实现线程安全，这些资源很容易变得损坏。我们将首先对`std::mutexes`进行广泛的概述，它提供了一种同步 C++线程的方法。然后我们将研究原子数据类型，它提供了另一种安全处理并行性的机制。

本章包含了演示如何处理 C++线程的不同场景的示例，包括处理`const &`、线程安全包装、阻塞与异步编程以及 C++ promises 和 futures。这是很重要的，因为在处理多个执行线程时，这些知识是至关重要的。

本章涵盖了以下示例：

+   使用互斥锁

+   使用原子数据类型

+   了解在多个线程的上下文中`const &` mutable 的含义

+   使类线程安全

+   同步包装器及其实现方法

+   阻塞操作与异步编程

+   使用 promises 和 futures

# 技术要求

要编译和运行本章中的示例，您必须具有管理权限的计算机运行 Ubuntu 18.04，并具有正常的互联网连接。在运行这些示例之前，您必须安装以下内容：

```cpp
> sudo apt-get install build-essential git cmake
```

如果此软件安装在 Ubuntu 18.04 以外的任何操作系统上，则需要 GCC 7.4 或更高版本和 CMake 3.6 或更高版本。

# 使用互斥锁

在本示例中，我们将学习为什么以及如何在 C++中使用互斥锁。在 C++中使用多个线程时，通常会建立线程之间共享的资源。正如我们将在本示例中演示的那样，尝试同时使用这些共享资源会导致可能损坏资源的竞争条件。

互斥锁（在 C++中写作`std::mutex`）是一个用于保护共享资源的对象，确保多个线程可以以受控的方式访问共享资源。这可以防止资源损坏。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有编译和执行本示例所需的正确工具。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行我们的示例。

# 如何做...

您需要执行以下步骤来尝试此示例：

1.  从新终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter05
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe01_examples
```

1.  源代码编译完成后，您可以通过运行以下命令来执行本示例中的每个示例：

```cpp
> ./recipe01_example01
The answer is: 42
The answer is: 42
The answer is: 42
The
 answer is: 42
The answer is: 42
...

> ./recipe01_example02
The answer is: 42
The answer is: 42
The answer is: 42
The answer is: 42
The answer is: 42
...

> ./recipe01_example03
...

> ./recipe01_example04
The answer is: 42

> ./recipe01_example05
The answer is: 42
The answer is: 42
The answer is: 42
The answer is: 42
The answer is: 42
...

> ./recipe01_example06
The answer is: 42
The answer is: 42

> ./recipe01_example07

> ./recipe01_example08
lock acquired
lock failed
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本示例教授的课程的关系。

# 工作原理...

在本示例中，我们将学习如何使用`std::mutex`来保护共享资源，防止其损坏。首先，让我们首先回顾一下当多个线程同时访问资源时资源如何变得损坏：

```cpp
#include <thread>
#include <string>
#include <iostream>

void foo()
{
    static std::string msg{"The answer is: 42\n"};
    while(true) {
        for (const auto &c : msg) {
            std::clog << c;
        }
    }
}

int main(void)
{
    std::thread t1{foo};
    std::thread t2{foo};

    t1.join();
    t2.join();

    // Never reached
    return 0;
}
```

执行时，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/01192c95-b3c1-4df5-a5a4-b94be4b18090.png)

在上面的示例中，我们创建了一个在无限循环中输出到`stdout`的函数。然后我们创建了两个线程，每个线程执行先前定义的函数。正如您所看到的，当两个线程同时执行时，结果输出变得损坏。这是因为当一个线程正在将其文本输出到`stdout`时，另一个线程同时输出到`stdout`，导致一个线程的输出与另一个线程的输出混合在一起。

要解决这个问题，我们必须确保一旦其中一个线程尝试将其文本输出到`stdout`，在另一个线程能够输出之前，它应该被允许完成输出。换句话说，每个线程必须轮流输出到`stdout`。当一个线程输出时，另一个线程必须等待轮到它。为了做到这一点，我们将利用一个`std::mutex`对象。

# std::mutex

互斥锁是一个用来保护共享资源的对象，以确保对共享资源的使用不会导致损坏。为了实现这一点，`std::mutex`有一个`lock()`函数和一个`unlock()`函数。`lock()`函数*获取*对共享资源的访问（有时称为临界区）。`unlock()`*释放*先前获取的访问。任何尝试在另一个线程已经执行`lock()`之后执行`lock()`函数的操作都将导致线程必须等待，直到执行`unlock()`函数为止。

`std::mutex`的实现取决于 CPU 的架构和操作系统；但是，一般来说，互斥锁可以用一个简单的整数来实现。如果整数为`0`，`lock()`函数将把整数设置为`1`并返回，这告诉互斥锁它已被获取。如果整数为`1`，意味着互斥锁已经被获取，`lock()`函数将等待（即阻塞），直到整数变为`0`，然后它将把整数设置为`1`并返回。如何实现这种等待取决于操作系统。例如，`wait()`函数可以循环直到整数变为`0`，这被称为**自旋锁**，或者它可以执行`sleep()`函数并等待一段时间，允许其他线程和进程在互斥锁被锁定时执行。释放函数总是将整数设置为`0`，这意味着互斥锁不再被获取。确保互斥锁正常工作的诀窍是确保使用原子操作读/写整数。如果使用非原子操作，整数本身将遭受与互斥锁试图防止的相同的共享资源损坏。

例如，考虑以下情况：

```cpp
#include <mutex>
#include <thread>
#include <string>
#include <iostream>

std::mutex m{};

void foo()
{
    static std::string msg{"The answer is: 42\n"};
    while(true) {
        m.lock();
        for (const auto &c : msg) {
            std::clog << c;
        }
        m.unlock();
    }
}

int main(void)
{
    std::thread t1{foo};
    std::thread t2{foo};

    t1.join();
    t2.join();

    // Never reached
    return 0;
}
```

此示例运行时输出以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/a74a32c8-e166-46cc-b84f-774e905f34cb.png)

在前面的例子中，我们创建了一个输出到`stdout`的相同函数。不同之处在于，在我们输出到`stdout`之前，我们通过执行`lock()`函数来获取`std::mutex`。一旦我们完成了对`stdout`的输出，我们通过执行`unlock()`函数来释放互斥锁。在`lock()`和`unlock()`函数之间的代码称为**临界区**。临界区中的任何代码只能由一个线程在任何给定时间执行，确保我们对`stdout`的使用不会变得损坏。

通过控制对共享资源的访问（例如使用互斥锁）来确保共享资源不会变得损坏称为**同步**。尽管大多数需要线程同步的情况并不复杂，但有些情况可能导致需要整个大学课程来覆盖的线程同步方案。因此，线程同步被认为是计算机科学中极其困难的范式，需要正确编程。

在本教程中，我们将涵盖其中一些情况。首先，让我们讨论一下**死锁**。当一个线程在调用`lock()`函数时进入无休止的等待状态时，就会发生死锁。死锁通常非常难以调试，是由于几个原因造成的，包括以下原因：

+   由于程序员错误或获取互斥锁的线程崩溃，导致线程从未调用`unlock()`

+   同一个线程在调用`unlock()`之前多次调用`lock()`函数

+   每个线程以不同的顺序锁定多个互斥锁

为了证明这一点，让我们看一下以下例子：

```cpp
#include <mutex>
#include <thread>

std::mutex m{};

void foo()
{
    m.lock();
}

int main(void)
{
    std::thread t1{foo};
    std::thread t2{foo};

    t1.join();
    t2.join();

    // Never reached
    return 0;
}
```

在前面的例子中，我们创建了两个线程，它们都试图锁定互斥量，但从未调用`unlock()`。结果，第一个线程获取了互斥量，然后返回而没有释放它。当第二个线程尝试获取互斥量时，它被迫等待第一个线程执行`unlock()`，但第一个线程从未执行，导致死锁（即程序永远不会返回）。

在这个例子中，死锁很容易识别和纠正；然而，在现实场景中，识别死锁要复杂得多。让我们看下面的例子：

```cpp
#include <array>
#include <mutex>
#include <thread>
#include <string>
#include <iostream>

std::mutex m{};
std::array<int,6> numbers{4,8,15,16,23,42};

int foo(int index)
{
    m.lock();
    auto element = numbers.at(index);
    m.unlock();

    return element;
}

int main(void)
{
    std::cout << "The answer is: " << foo(5) << '\n';
    return 0;
}
```

在前面的例子中，我们编写了一个函数，根据索引返回数组中的元素。此外，我们获取了保护数组的互斥量，并在返回之前释放了互斥量。挑战在于我们必须在函数可以返回的地方`unlock()`互斥量，这不仅包括从函数返回的每种可能分支，还包括抛出异常的所有可能情况。在前面的例子中，如果提供的索引大于数组大小，`std::array`对象将抛出异常，导致函数在调用`unlock()`之前返回，如果另一个线程正在共享此数组，将导致死锁。

# std::lock_guard

C++提供了`std::lock_guard`对象来简化对`std::mutex`对象的使用，而不是在代码中到处使用`try`/`catch`块来防止死锁，这假设程序员甚至能够确定每种可能发生死锁的情况而不出错。

例如，考虑以下代码：

```cpp
#include <mutex>
#include <thread>
#include <iostream>

std::mutex m{};

void foo()
{
    static std::string msg{"The answer is: 42\n"};

    while(true) {
        std::lock_guard lock(m);
        for (const auto &c : msg) {
            std::clog << c;
        }
    }
}

int main(void)
{
    std::thread t1{foo};
    std::thread t2{foo};

    t1.join();
    t2.join();

    // Never reached
    return 0;
}
```

执行时，我们看到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/948ff65e-fbca-4f22-98f2-85b33fe28cea.png)

如前面的例子所示，当我们通常在互斥量上调用`lock()`时，使用`std::lock_guard`。`std::lock_guard`在创建时调用互斥量的`lock()`函数，然后在销毁时调用互斥量的`unlock()`函数（一种称为**资源获取即初始化**或**RAII**的习惯用法）。无论函数如何返回（无论是正常返回还是异常），互斥量都将被释放，确保死锁不可能发生，避免程序员必须准确确定函数可能返回的每种可能情况。

尽管`std::lock_guard`能够防止在从未调用`unlock()`的情况下发生死锁，但它无法防止在调用`lock()`多次之后再调用`unlock()`之前发生死锁的情况。为了处理这种情况，C++提供了`std::recursive_mutex`。

# std::recursive_mutex

递归互斥量每次同一线程调用`lock()`函数时都会增加互斥量内部存储的整数，而不会导致`lock()`函数等待。例如，如果互斥量被释放（即，互斥量中的整数为`0`），当线程`#1`调用`lock()`函数时，互斥量中的整数被设置为`1`。通常情况下，如果线程`#1`再次调用`lock()`函数，`lock()`函数会看到整数为`1`并进入等待状态，直到整数被设置为`0`。相反，递归互斥量将确定调用`lock()`函数的线程，并且如果获取互斥量的线程与调用`lock()`函数的线程相同，则使用原子操作再次增加互斥量中的整数（现在结果为`2`）。要释放互斥量，线程必须调用`unlock()`，这将使用原子操作递减整数，直到互斥量中的整数为`0`。

递归互斥锁允许同一个线程调用`lock()`函数多次，防止多次调用`lock()`函数并导致死锁，但代价是`lock()`和`unlock()`函数必须包括一个额外的函数调用来获取线程的`id()`实例，以便互斥锁可以确定是哪个线程在调用`lock()`和`unlock()`。

例如，考虑以下代码片段：

```cpp
#include <mutex>
#include <thread>
#include <string>
#include <iostream>

std::recursive_mutex m{};

void foo()
{
    m.lock();
    m.lock();

    std::cout << "The answer is: 42\n";

    m.unlock();
    m.unlock();
}

int main(void)
{
    std::thread t1{foo};
    std::thread t2{foo};

    t1.join();
    t2.join();

    return 0;
}
```

前面的例子会导致以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/fef09e3b-fb6a-479b-a600-6c482d4c8b94.png)

在前面的例子中，我们定义了一个函数，该函数调用递归互斥锁的`lock()`函数两次，输出到`stdout`，然后再调用`unlock()`函数两次。然后我们创建两个执行此函数的线程，结果是`stdout`没有腐败，也没有死锁。

# std::shared_mutex

直到这一点，我们的同步原语已经对共享资源进行了序列化访问。也就是说，每个线程在访问临界区时必须一次执行一个。虽然这确保了腐败是不可能的，但对于某些类型的场景来说效率不高。为了更好地理解这一点，我们必须研究是什么导致了腐败。

让我们考虑一个整数变量，它被两个线程同时增加。增加整数变量的过程如下：`i = i + 1`。

让我们将其写成如下形式：

```cpp
int i = 0;

auto tmp = i;
tmp++;
i = tmp; // i == 1
```

为了防止腐败，我们使用互斥锁来确保两个线程同步地增加整数：

```cpp
auto tmp_thread1 = i;
tmp_thread1++;
i = tmp_thread1; // i == 1

auto tmp_thread2 = i;
tmp_thread2++;
i = tmp_thread2; // i == 2
```

当这些操作混合在一起时（也就是说，当两个操作在不同的线程中同时执行时），就会发生腐败。例如，考虑以下代码：

```cpp
auto tmp_thread1 = i; // 0
auto tmp_thread2 = i; // 0
tmp_thread1++; // 1
tmp_thread2++; // 1
i = tmp_thread1; // i == 1
i = tmp_thread2; // i == 1
```

与整数为`2`不同，它是`1`，因为在第一个增量允许完成之前整数被读取。这种情况是可能的，因为两个线程都试图写入同一个共享资源。我们称这些类型的线程为**生产者**。

然而，如果我们创建了 100 万个同时读取共享资源的线程会发生什么。由于整数永远不会改变，无论线程以什么顺序执行，它们都会读取相同的值，因此腐败是不可能的。我们称这些线程为**消费者**。如果我们只有消费者，我们就不需要线程同步，因为腐败是不可能的。

最后，如果我们有相同的 100 万个消费者，但是我们在其中添加了一个生产者会发生什么？现在，我们必须使用线程同步，因为可能在生产者试图将一个值写入整数的过程中，消费者也试图读取，这将导致腐败的结果。为了防止这种情况发生，我们必须使用互斥锁来保护整数。然而，如果我们使用`std::mutex`，那么所有 100 万个消费者都必须互相等待，即使消费者们自己可以在不担心腐败的情况下同时执行。只有当生产者尝试执行时，我们才需要担心。

为了解决这个明显的性能问题，C++提供了`std::shared_mutex`对象。例如，考虑以下代码：

```cpp
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <iostream>

int count_rw{};
const auto &count_ro = count_rw;

std::shared_mutex m{};

void reader()
{
    while(true) {
        std::shared_lock lock(m);
        if (count_ro >= 42) {
            return;
        }
    }
}

void writer()
{
    while(true) {
        std::unique_lock lock(m);
        if (++count_rw == 100) {
            return;
        }
    }
}

int main(void)
{
    std::thread t1{reader};
    std::thread t2{reader};
    std::thread t3{reader};
    std::thread t4{reader};
    std::thread t5{writer};

    t1.join();
    t2.join();
    t3.join();
    t4.join();
    t5.join();

    return 0;
}
```

在前面的例子中，我们创建了一个生产者函数（称为`reader`函数）和一个消费者函数（称为`writer`函数）。生产者使用`std::unique_lock()`锁定互斥锁，而消费者使用`std::shared_lock()`锁定互斥锁。每当使用`std::unique_lock()`锁定互斥锁时，所有其他线程都必须等待（无论是生产者还是消费者）。然而，如果使用`std::shared_lock()`锁定互斥锁，使用`std::shared_lock()`再次尝试锁定互斥锁不会导致线程等待。

只有在调用`std::unique_lock()`时才需要等待。这允许消费者在不等待彼此的情况下执行。只有当生产者尝试执行时，消费者必须等待，防止消费者相互串行化，最终导致更好的性能（特别是如果消费者的数量是 100 万）。

应该注意，我们使用`const`关键字来确保消费者不是生产者。这个简单的技巧确保程序员不会在不经意间认为他们已经编写了一个消费者，而实际上他们已经创建了一个生产者，因为如果发生这种情况，编译器会警告程序员。

# std::timed_mutex

最后，我们还没有处理线程获取互斥锁后崩溃的情况。在这种情况下，任何尝试获取相同互斥锁的线程都会进入死锁状态，因为崩溃的线程永远没有机会调用`unlock()`。预防这种问题的一种方法是使用`std::timed_mutex`。

例如，考虑以下代码：

```cpp
#include <mutex>
#include <thread>
#include <iostream>

std::timed_mutex m{};

void foo()
{
    using namespace std::chrono;

    if (m.try_lock_for(seconds(1))) {
        std::cout << "lock acquired\n";
    }
    else {
        std::cout << "lock failed\n";
    }
}

int main(void)
{
    std::thread t1{foo};
    std::thread t2{foo};

    t1.join();
    t2.join();

    return 0;
}
```

当执行这个时，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/a606b9bb-6ef7-4885-93e6-344fc3bc06e7.png)

在上面的例子中，我们告诉 C++线程只允许等待 1 秒。如果互斥锁已经被获取，并且在 1 秒后没有被释放，`try_lock_for()`函数将退出并返回 false，允许线程优雅地退出并处理错误，而不会进入死锁状态。

# 使用原子数据类型

在这个食谱中，我们将学习如何在 C++中使用原子数据类型。原子数据类型提供了读写简单数据类型（即布尔值或整数）的能力，而无需线程同步（即使用`std::mutex`和相关工具）。为了实现这一点，原子数据类型使用特殊的 CPU 指令来确保当执行操作时，它是作为单个原子操作执行的。

例如，递增一个整数可以写成如下：

```cpp
int i = 0;

auto tmp = i;
tmp++;
i = tmp; // i == 1
```

原子数据类型确保这个递增是以这样的方式执行的，即没有其他尝试同时递增整数的操作可以交错，并因此导致损坏。CPU 是如何做到这一点的超出了本书的范围。这是因为在现代的超标量、流水线化的 CPU 中，支持在多个核心和插槽上并行、乱序和推测性地执行指令，这是非常复杂的。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有编译和执行此食谱中示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

您需要执行以下步骤来尝试这个食谱：

1.  从一个新的终端，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter05
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe02_examples
```

1.  一旦源代码编译完成，您可以通过运行以下命令来执行这个食谱中的每个示例：

```cpp
> ./recipe02_example01
count: 711
atomic count: 1000
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本食谱中所教授的课程的关系。

# 工作原理...

在这个食谱中，我们将学习如何使用 C++的原子数据类型。原子数据类型仅限于简单的数据类型，如整数，由于这些数据类型非常复杂，只支持简单的操作，如加法、减法、递增和递减。

让我们看一个简单的例子，不仅演示了如何在 C++中使用原子数据类型，还演示了为什么原子数据类型如此重要：

```cpp
#include <atomic>
#include <thread>
#include <iostream>

int count{};
std::atomic<int> atomic_count{};

void foo()
{
    do {
        count++;
        atomic_count++;
    }
    while (atomic_count < 99999);
}

int main(void)
{
    std::thread t1{foo};
    std::thread t2{foo};

    t1.join();
    t2.join();

    std::cout << "count: " << count << '\n';
    std::cout << "atomic count: " << atomic_count << '\n';

    return 0;
}
```

当执行这段代码时，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/216f9a16-1893-4c5f-b259-da1e2d0b4bc0.png)

在上面的示例中，我们有两个整数。第一个整数是普通的 C/C++整数类型，而第二个是原子数据类型（整数类型）。然后，我们定义一个循环，直到原子数据类型为`1000`为止。最后，我们从两个线程中执行这个函数，这意味着我们的全局整数会被两个线程同时增加。

如您所见，这个简单测试的输出显示，简单的 C/C++整数数据类型与原子数据类型的值不同，但两者都增加了相同次数。这个原因可以在这个函数的汇编中看到（在 Intel CPU 上），如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/b1e3de9e-b754-49b6-a53a-d4e0bfd9cc2f.png)

要增加一个整数（未启用优化），编译器必须将内存内容移动到寄存器中，将`1`添加到寄存器中，然后将寄存器的结果写回内存。由于这段代码同时在两个不同的线程中执行，这段代码交错执行，导致损坏。原子数据类型不会遇到这个问题。这是因为增加原子数据类型的过程发生在一个单独的特殊指令中，CPU 确保执行，而不会将其内部状态与其他指令的相同内部状态交错在一起，也不会在其他 CPU 上交错。

原子数据类型通常用于实现同步原语，例如`std::mutex`（尽管在实践中，`std::mutex`是使用测试和设置指令实现的，这些指令使用类似的原理，但通常比原子指令执行得更快）。这些数据类型还可以用于实现称为无锁数据结构的特殊数据结构，这些数据结构能够在多线程环境中运行，而无需`std::mutex`。无锁数据结构的好处是在处理线程同步时没有等待状态，但会增加更复杂的 CPU 硬件和其他类型的性能惩罚（当 CPU 遇到原子指令时，大多数由硬件提供的 CPU 优化必须暂时禁用）。因此，就像计算机科学中的任何东西一样，它们都有其时机和地点。

# 在多线程的上下文中理解 const & mutable 的含义

在这个示例中，我们将学习如何处理被标记为`const`的对象，但包含必须使用`std::mutex`来确保线程同步的对象。这个示例很重要，因为将`std::mutex`存储为类的私有成员是很有用的，但是，一旦你这样做了，将这个对象的实例作为常量引用（即`const &`）传递将导致编译错误。在这个示例中，我们将演示为什么会发生这种情况以及如何克服它。

# 准备工作

在我们开始之前，请确保满足所有的技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有编译和执行本示例中示例的正确工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

您需要执行以下步骤来尝试这个示例：

1.  从一个新的终端中，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter05
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe03_examples
```

1.  源代码编译完成后，您可以通过运行以下命令来执行本示例中的每个示例：

```cpp
> ./recipe03_example01
The answer is: 42

> ./recipe03_example03
The answer is: 42
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 它是如何工作的...

在本示例中，我们将学习如何将`std::mutex`添加到类的私有成员中，同时仍然能够处理`const`情况。一般来说，确保对象是线程安全的有两种方法。第一种方法是将`std::mutex`放在全局级别。这样做可以确保对象可以作为常量引用传递，或者对象本身可以有一个标记为`const`的函数。

为此，请考虑以下代码示例：

```cpp
#include <mutex>
#include <thread>
#include <iostream>

std::mutex m{};

class the_answer
{
public:
    void print() const
    {
        std::lock_guard lock(m);
        std::cout << "The answer is: 42\n";
    }
};

int main(void)
{
    the_answer is;
    is.print();

    return 0;
}
```

在前面的例子中，当执行`print()`函数时，我们创建了一个对象，该对象输出到`stdout`。`print()`函数被标记为`const`，这告诉编译器`print()`函数不会修改任何类成员（即函数是只读的）。由于`std::mutex`是全局的，对象的 const 限定符被维持，代码可以编译和执行而没有问题。

全局`std::mutex`对象的问题在于，对象的每个实例都必须使用相同的`std::mutex`对象。如果用户打算这样做，那没问题，但如果您希望对象的每个实例都有自己的`std::mutex`对象（例如，当对象的相同实例可能被多个线程执行时），该怎么办？

为此，让我们看看如何使用以下示例发生的情况：

```cpp
#include <mutex>
#include <thread>
#include <iostream>

class the_answer
{
    std::mutex m{};

public:
    void print() const
    {
        std::lock_guard lock(m);
        std::cout << "The answer is: 42\n";
    }
};

int main(void)
{
    the_answer is;
    is.print();

    return 0;
}
```

如果我们尝试编译这个，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/944a6bd9-fba1-4f70-b061-5dc7c7c4afba.png)

在前面的例子中，我们所做的只是将前面的例子中的`std::mutex`移动到类内部作为私有成员。结果是，当我们尝试编译类时，我们会得到一个编译器错误。这是因为`print()`函数被标记为`const`，这告诉编译器`print()`函数不会修改类的任何成员。问题在于，当您尝试锁定`std::mutex`时，您必须对其进行修改，从而导致编译器错误。

为了克服这个问题，我们必须告诉编译器忽略这个错误，方法是将`std::mutex`标记为 mutable。将成员标记为 mutable 告诉编译器允许修改该成员，即使对象被作为常量引用传递或对象定义了常量函数。

例如，这是`const`标记为`mutable`的代码示例：

```cpp
#include <mutex>
#include <thread>
#include <iostream>

class the_answer
{
    mutable std::mutex m{};

public:
    void print() const
    {
        std::lock_guard lock(m);
        std::cout << "The answer is: 42\n";
    }
};

int main(void)
{
    the_answer is;
    is.print();

    return 0;
}
```

如前面的例子所示，一旦我们将`std::mutex`标记为 mutable，代码就会像我们期望的那样编译和执行。值得注意的是，`std::mutex`是少数几个可以接受 mutable 使用的例子之一。mutable 关键字很容易被滥用，导致代码无法编译或操作不符合预期。

# 使类线程安全

在本示例中，我们将学习如何使一个类线程安全（即如何确保一个类的公共成员函数可以随时被任意数量的线程同时调用）。大多数类，特别是由 C++标准库提供的类，都不是线程安全的，而是假设用户会根据需要添加线程同步原语，如`std::mutex`对象。这种方法的问题在于，每个对象都有两个实例，必须在代码中进行跟踪：类本身和它的`std::mutex`。用户还必须用自定义版本包装对象的每个函数，以使用`std::mutex`保护类，结果不仅有两个必须管理的对象，还有一堆 C 风格的包装函数。

这个示例很重要，因为它将演示如何通过创建一个线程安全的类来解决代码中的这些问题，将所有内容合并到一个单一的类中。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有编译和执行本示例的正确工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

您需要执行以下步骤来尝试这个教程：

1.  从新的终端中运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter05
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe04_examples
```

1.  源代码编译完成后，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe04_example01
```

在接下来的部分中，我们将逐个介绍这些示例，并解释每个示例程序的作用，以及它们与本教程中所教授的课程的关系。

# 它是如何工作的...

在本教程中，我们将学习如何通过实现自己的线程安全栈来制作一个线程安全的类。C++标准库不提供线程安全的数据结构，因此，如果您希望在多个线程中使用数据结构作为全局资源，您需要手动添加线程安全性。这可以通过实现包装函数或创建包装类来实现。

创建包装函数的优势在于，对于全局对象，通常所需的代码量更少，更容易理解，而线程安全类的优势在于，您可以创建类的多个实例，因为`std::mutex`是自包含的。

可以尝试以下代码示例：

```cpp
#include <mutex>
#include <stack>
#include <iostream>

template<typename T>
class my_stack
{
    std::stack<T> m_stack;
    mutable std::mutex m{};

public:

    template<typename ARG>
    void push(ARG &&arg)
    {
        std::lock_guard lock(m);
        m_stack.push(std::forward<ARG>(arg));
    }

 void pop()
    {
        std::lock_guard lock(m);
        m_stack.pop();
    }

    auto empty() const
    {
        std::lock_guard lock(m);
        return m_stack.empty();
    }
};
```

在前面的示例中，我们实现了自己的栈。这个栈有`std::stack`和`std::mutex`作为成员变量。然后，我们重新实现了`std::stack`提供的一些函数。这些函数中的每一个首先尝试获取`std::mutex`，然后调用`std::stack`中的相关函数。在`push()`函数的情况下，我们利用`std::forward`来确保传递给`push()`函数的参数被保留。

最后，我们可以像使用`std::stack`一样使用我们的自定义栈。例如，看一下以下代码：

```cpp
int main(void)
{
    my_stack<int> s;

    s.push(4);
    s.push(8);
    s.push(15);
    s.push(16);
    s.push(23);
    s.push(42);

    while(s.empty()) {
        s.pop();
    }

    return 0;
}
```

正如您所看到的，`std::stack`和我们的自定义栈之间唯一的区别是我们的栈是线程安全的。

# 同步包装器及其实现方式

在本教程中，我们将学习如何制作线程安全的同步包装器。默认情况下，C++标准库不是线程安全的，因为并非所有应用程序都需要这种功能。确保 C++标准库是线程安全的一种机制是创建一个线程安全类，它将您希望使用的数据结构以及`std::mutex`作为私有成员添加到类中，然后重新实现数据结构的函数以首先获取`std::mutex`，然后转发函数调用到数据结构。这种方法的问题在于，如果数据结构是全局资源，程序中会添加大量额外的代码，使得最终的代码难以阅读和维护。

这个教程很重要，因为它将演示如何通过制作线程安全的同步包装器来解决代码中的这些问题。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有正确的工具来编译和执行本教程中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何操作...

您需要执行以下步骤来尝试这个教程：

1.  从新的终端中运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter05
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe05_examples
```

1.  源代码编译完成后，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe05_example01
```

在接下来的部分中，我们将逐个介绍这些示例，并解释每个示例程序的作用，以及它们与本教程中所教授的课程的关系。

# 它是如何工作的...

在本教程中，我们将学习如何创建线程安全的同步包装器，这允许我们向 C++标准库数据结构添加线程安全性，而默认情况下这些数据结构是不安全的。

为此，我们将为 C++标准库中的每个函数创建包装函数。这些包装函数将首先尝试获取`std::mutex`，然后将相同的函数调用转发到 C++标准库数据结构。

为此，请考虑以下代码示例：

```cpp
#include <mutex>
#include <stack>
#include <iostream>

std::mutex m{};

template<typename S, typename T>
void push(S &s, T &&t)
{
    std::lock_guard lock(m);
    s.push(std::forward<T>(t));
}

template<typename S>
void pop(S &s)
{
    std::lock_guard lock(m);
    s.pop();
}

template<typename S>
auto empty(S &s)
{
    std::lock_guard lock(m);
    return s.empty();
}
```

在前面的例子中，我们为`push()`、`pop()`和`empty()`函数创建了一个包装函数。这些函数在调用数据结构之前会尝试获取我们的全局`std::mutex`对象，这里是一个模板。使用模板创建了一个概念。我们的包装函数可以被实现了`push()`、`pop()`和`empty()`的任何数据结构使用。另外，请注意我们在`push()`函数中使用`std::forward`来确保被推送的参数的 l-valueness 和 CV 限定符保持不变。

最后，我们可以像使用数据结构的函数一样使用我们的包装器，唯一的区别是数据结构作为第一个参数传递。例如，看一下以下代码块：

```cpp
int main(void)
{
    std::stack<int> mystack;

    push(mystack, 4);
    push(mystack, 8);
    push(mystack, 15);
    push(mystack, 16);
    push(mystack, 23);
    push(mystack, 42);

    while(empty(mystack)) {
        pop(mystack);
    }

    return 0;
}
```

正如前面的例子中所示，使用我们的同步包装器是简单的，同时确保我们创建的堆栈现在是线程安全的。

# 阻塞操作与异步编程

在本示例中，我们将学习阻塞操作和异步操作之间的区别。这个示例很重要，因为阻塞操作会使每个操作在单个 CPU 上串行执行。如果每个操作的执行必须按顺序执行，这通常是可以接受的；然而，如果这些操作可以并行执行，异步编程可以是一个有用的优化，确保在一个操作等待时，其他操作仍然可以在同一个 CPU 上执行。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有编译和执行本示例中的示例的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

您需要执行以下步骤来尝试这个示例：

1.  从一个新的终端，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter05
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe06_examples
```

1.  源代码编译后，您可以通过运行以下命令执行本示例中的每个示例：

```cpp
> time ./recipe06_example01
999999
999999
999999
999999

real 0m1.477s
...

> time ./recipe06_example02
999999
999999
999999
999999

real 0m1.058s
...

> time ./recipe06_example03
999999
999999
999998
999999

real 0m1.140s
...
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 工作原理...

阻塞操作是指必须在下一个操作发生之前完成的操作。大多数程序是按顺序编写的，这意味着每个指令必须在下一个指令之前执行。然而，问题在于有些操作可以并行执行（即同时或异步执行）。串行化这些操作在最好的情况下可能会导致性能不佳，并且在某些情况下实际上可能会导致死锁（程序进入无休止的等待状态），如果阻塞的操作正在等待另一个从未有机会执行的操作。

为了演示一个阻塞操作，让我们来看一下以下内容：

```cpp
#include <vector>
#include <iostream>
#include <algorithm>

constexpr auto size = 1000000;

int main(void)
{
    std::vector<int> numbers1(size);
    std::vector<int> numbers2(size);
    std::vector<int> numbers3(size);
    std::vector<int> numbers4(size);
```

前面的代码创建了一个主函数，其中有四个`int`类型的`std::vector`对象。在接下来的步骤中，我们将使用这些向量来演示一个阻塞操作。

1.  首先，我们创建四个可以存储整数的向量：

```cpp
    std::generate(numbers1.begin(), numbers1.end(), []() {
      return rand() % size;
    });
    std::generate(numbers2.begin(), numbers2.end(), []() {
      return rand() % size;
    });
    std::generate(numbers3.begin(), numbers3.end(), []() {
      return rand() % size;
    });
    std::generate(numbers4.begin(), numbers4.end(), []() {
      return rand() % size;
    });
```

1.  接下来，我们使用`std::generate`用随机数填充每个数组，结果是一个带有数字和随机顺序的数组：

```cpp
    std::sort(numbers1.begin(), numbers1.end());
    std::sort(numbers2.begin(), numbers2.end());
    std::sort(numbers3.begin(), numbers3.end());
    std::sort(numbers4.begin(), numbers4.end());
```

1.  接下来，我们对整数数组进行排序，这是本例的主要目标，因为这个操作需要一段时间来执行：

```cpp
    std::cout << numbers1.back() << '\n';
    std::cout << numbers2.back() << '\n';
    std::cout << numbers3.back() << '\n';
    std::cout << numbers4.back() << '\n';

    return 0;
}
```

1.  最后，我们输出每个数组中的最后一个条目，通常会是`999999`（但不一定，因为数字是使用随机数生成器生成的）。

前面示例的问题在于操作可以并行执行，因为每个数组是独立的。为了解决这个问题，我们可以异步执行这些操作，这意味着数组将并行创建、填充、排序和输出。例如，考虑以下代码：

```cpp
#include <future>
#include <thread>
#include <vector>
#include <iostream>
#include <algorithm>

constexpr auto size = 1000000;

int foo()
{
    std::vector<int> numbers(size);
    std::generate(numbers.begin(), numbers.end(), []() {
      return rand() % size;
    });

    std::sort(numbers.begin(), numbers.end());
    return numbers.back();
}
```

我们首先要做的是实现一个名为`foo()`的函数，该函数创建我们的向量，用随机数填充它，对列表进行排序，并返回数组中的最后一个条目（与前面的示例相同，唯一的区别是我们一次只处理一个数组，而不是`4`个）：

```cpp
int main(void)
{
    auto a1 = std::async(std::launch::async, foo);
    auto a2 = std::async(std::launch::async, foo);
    auto a3 = std::async(std::launch::async, foo);
    auto a4 = std::async(std::launch::async, foo);

    std::cout << a1.get() << '\n';
    std::cout << a2.get() << '\n';
    std::cout << a3.get() << '\n';
    std::cout << a4.get() << '\n';

    return 0;
}
```

然后，我们使用`std::async`四次执行这个`foo()`函数，得到与前面示例相同的四个数组。在这个示例中，`std::async()`函数做的事情与手动执行四个线程相同。`std::aync()`的结果是一个`std::future`对象，它在函数执行完成后存储函数的结果。在这个示例中，我们做的最后一件事是使用`get()`函数在函数准备好后返回函数的值。

如果我们计时这些函数的结果，我们会发现异步版本比阻塞版本更快。以下代码显示了这一点（`real`时间是查找时间）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/46ef0e32-b06c-4bc6-9b92-5984d00d7432.png)

`std::async()`函数也可以用来在同一个线程中异步执行我们的数组函数。例如，考虑以下代码：

```cpp
int main(void)
{
    auto a1 = std::async(std::launch::deferred, foo);
    auto a2 = std::async(std::launch::deferred, foo);
    auto a3 = std::async(std::launch::deferred, foo);
    auto a4 = std::async(std::launch::deferred, foo);

    std::cout << a1.get() << '\n';
    std::cout << a2.get() << '\n';
    std::cout << a3.get() << '\n';
    std::cout << a4.get() << '\n';

    return 0;
}
```

如前面的示例所示，我们将操作从`std::launch::async`更改为`std::launch::deferred`，这将导致每个函数在需要函数结果时执行一次（即调用`get()`函数时）。如果不确定函数是否需要执行（即仅在需要时执行函数），这将非常有用，但缺点是程序的执行速度较慢，因为线程通常不用作优化方法。

# 使用承诺和未来

在本配方中，我们将学习如何使用 C++承诺和未来。C++ `promise`是 C++线程的参数，而 C++ `future`是线程的返回值，并且可以用于手动实现`std::async`调用的相同功能。这个配方很重要，因为对`std::aync`的调用要求每个线程停止执行以获取其结果，而手动实现 C++ `promise`和`future`允许用户在线程仍在执行时获取线程的返回值。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有编译和执行本配方中示例所需的适当工具。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行示例。

# 如何做...

您需要执行以下步骤来尝试这个配方：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter05
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe07_examples
```

1.  编译源代码后，可以通过运行以下命令来执行本配方中的每个示例：

```cpp
> ./recipe07_example01
The answer is: 42

> ./recipe07_example02
The answer is: 42
```

在下一节中，我们将逐个介绍每个示例，并解释每个示例程序的作用及其与本配方中所教授的课程的关系。

# 它是如何工作的...

在本配方中，我们将学习如何手动使用 C++ `promise`和`future`来提供一个并行执行带有参数的函数，并获取函数的返回值。首先，让我们演示如何以最简单的形式完成这个操作，使用以下代码：

```cpp
#include <thread>
#include <iostream>
#include <future>

void foo(std::promise<int> promise)
{
    promise.set_value(42);
}

int main(void)
{
    std::promise<int> promise;
    auto future = promise.get_future();

    std::thread t{foo, std::move(promise)};
    t.join();

    std::cout << "The answer is: " << future.get() << '\n';

    return 0;
}
```

执行前面的示例会产生以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/5313a9ee-d6f1-449f-90df-069c182a2a80.png)

正如您在上面的代码中所看到的，C++的`promise`是作为函数的参数进行线程化的。线程通过设置`promise`参数来返回其值，而`promise`又设置了一个 C++的`future`，用户可以从提供给线程的`promise`参数中获取。需要注意的是，我们使用`std::move()`来防止`promise`参数被复制（编译器会禁止，因为 C++的`promise`是一个只能移动的类）。最后，我们使用`get()`函数来获取线程的结果，就像使用`std::async`执行线程的结果一样。

手动使用`promise`和`future`的一个好处是，可以在线程完成之前获取线程的结果，从而允许线程继续工作。例如，看下面的例子：

```cpp
#include <thread>
#include <iostream>
#include <future>

void foo(std::promise<int> promise)
{
    promise.set_value(42);
    while (true);
}

int main(void)
{
    std::promise<int> promise;
    auto future = promise.get_future();

    std::thread t{foo, std::move(promise)};

    future.wait();
    std::cout << "The answer is: " << future.get() << '\n';

    t.join();

    // Never reached
    return 0;
}
```

执行时会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/af9f0ada-0fe3-4d17-9c75-52f61975d425.png)

在上面的例子中，我们创建了相同的线程，但在线程中无限循环，意味着线程永远不会返回。然后我们以相同的方式创建线程，但在 C++的`future`准备好时立即输出结果，我们可以使用`wait()`函数来确定。


# 第六章：为性能优化您的代码

优化代码以提高性能可以确保您的代码充分利用了 C++所能提供的功能。与其他高级语言不同，C++能够提供高级的语法自由，而不会牺牲性能，尽管诚然会增加学习曲线的成本。

本章很重要，因为它将演示更高级的优化代码方法，包括如何在单元级别对软件进行基准测试，如何检查编译器为潜在优化而生成的结果汇编代码，如何减少应用程序使用的内存资源数量，以及为什么编译器提示（如`noexcept`）很重要。阅读完本章后，您将具备编写更高效 C++代码的技能。

在本章中，我们将涵盖以下配方：

+   对代码进行基准测试

+   查看汇编代码

+   减少内存分配的数量

+   声明 noexcept

# 技术要求

要编译和运行本章中的示例，您必须具有管理访问权限，可以访问运行 Ubuntu 18.04 的计算机，并具有功能正常的互联网连接。在运行这些示例之前，您必须安装以下内容：

```cpp
> sudo apt-get install build-essential git cmake valgrind
```

如果这是安装在 Ubuntu 18.04 以外的任何操作系统上，则需要 GCC 7.4 或更高版本和 CMake 3.6 或更高版本。

# 对代码进行基准测试

在本配方中，您将学习如何对源代码进行基准测试和优化。优化源代码将导致更高效的 C++，从而增加电池寿命，提高性能等。这个配方很重要，因为优化源代码的过程始于确定您计划优化的资源，这可能包括速度、内存甚至功耗。没有基准测试工具，要比较解决同一个问题的不同方法是非常困难的。

对于 C++程序员来说，有无数的基准测试工具（任何测量程序的单个属性的工具），包括 Boost、Folly 和 Abseil 等 C++ API，以及诸如 Intel 的 vTune 之类的特定于 CPU 的工具。还有一些性能分析工具（任何帮助您了解程序行为的工具），如 valgrind 和 gprof。在本配方中，我们将重点关注其中的两个：Hayai 和 Valgrind。Hayai 提供了一个微基准测试的简单示例，而 Valgrind 提供了一个更完整、但更复杂的动态分析/性能分析工具的示例。

# 准备工作

在开始之前，请确保已满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git valgrind cmake
```

这将确保您的操作系统具有适当的工具来编译和执行本配方中的示例。完成此操作后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 操作步骤

执行以下步骤完成这个配方：

1.  从新的终端中运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter06
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake -DCMAKE_BUILD_TYPE=Debug .
> make recipe01_examples
```

1.  一旦源代码被编译，您可以通过运行以下命令来执行本配方中的每个示例：

```cpp
> ./recipe01_example01
[==========] Running 2 benchmarks.
[ RUN ] vector.push_back (10 runs, 100 iterations per run)
[ DONE ] vector.push_back (0.200741 ms)
...
[ RUN ] vector.emplace_back (10 runs, 100 iterations per run)
[ DONE ] vector.emplace_back (0.166699 ms)
...

> ./recipe01_example02
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本配方中所教授的课程的关系。

# 工作原理

应用于 C++的最常见优化是执行速度。为了优化 C++的速度，我们必须首先开发不同的方法来解决同一个问题，然后对每个解决方案进行基准测试，以确定哪个解决方案执行速度最快。基准测试工具，如 GitHub 上的基于 C++的基准测试库 Hayai，有助于做出这一决定。为了解释这一点，让我们看一个简单的例子：

```cpp
#include <string>
#include <vector>
#include <hayai.hpp>

std::vector<std::string> data;

BENCHMARK(vector, push_back, 10, 100)
{
    data.push_back("The answer is: 42");
}

BENCHMARK(vector, emplace_back, 10, 100)
{
    data.emplace_back("The answer is: 42");
}
```

当我们执行上述代码时，我们会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/4b7883ec-9592-4fde-bb6f-bcc9465077c4.jpg)

在前面的示例中，我们使用 Hayai 库来基准测试使用`push_back()`和`emplace_back()`向向量添加字符串之间的性能差异。`push_back()`和`emplace_back()`之间的区别在于，`push_back()`创建对象，然后将其复制或移动到向量中，而`emplace_back()`在向量中创建对象本身，而无需临时对象和随后的复制/移动。也就是说，如果使用`push_back()`，必须构造对象，然后将其复制或移动到向量中。如果使用`emplace_back()`，则只需构造对象。如预期的那样，`emplace_back()`优于`push_back()`，这就是为什么诸如 Clang-Tidy 之类的工具建议尽可能使用`emplace_back()`而不是`push_back()`。

基准库，如 Hayai，使用简单，对帮助程序员优化源代码非常有效，并且不仅能够对速度进行基准测试，还能够对资源使用进行基准测试。这些库的问题在于它们更适合在*单元*级别而不是*集成*和*系统*级别进行利用；也就是说，要测试整个可执行文件，这些库不适合帮助程序员，因为随着测试规模的增加，它们的扩展性不佳。为了分析整个可执行文件而不是单个函数，存在诸如 Valgrind 之类的工具，它可以帮助您分析哪些函数在优化方面需要最多的关注。然后，可以使用基准测试工具来分析需要最多关注的函数。

Valgrind 是一种动态分析工具，能够检测内存泄漏并跟踪程序的执行。为了看到这一点，让我们看下面的示例：

```cpp
volatile int data = 0;

void foo()
{
 data++;
}

int main(void)
{
 for (auto i = 0; i < 100000; i++) {
 foo();
 }
}
```

在前面的示例中，我们从名为`foo()`的函数中递增一个全局变量（标记为 volatile 以确保编译器不会优化掉该变量），然后执行这个函数`100,000`次。要分析这个示例，请运行以下命令（使用`callgrind`输出程序中每个函数被调用的次数）：

```cpp
> valgrind --tool=callgrind ./recipe01_example02
> callgrind_annotate callgrind.out.*
```

这导致以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/f6aac4e5-2af5-426e-a176-9da59a0a379b.png)

正如我们所看到的，`foo()`函数在前面的输出中位于最前面（动态链接器的`_dl_lookup_symbol_x()`函数被调用最多，用于在执行之前链接程序）。值得注意的是，程序列表（在左侧）中`foo()`函数的指令总数为`800,000`。这是因为`foo()`函数有`8`条汇编指令，并且被执行了`100,000`次。例如，让我们使用`objdump`（一种能够输出可执行文件编译汇编的工具）来查看`foo()`函数的汇编，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/f3a341c8-cf01-4265-9e74-e2496c465733.png)

使用 Valgrind，可以对可执行文件进行分析，以确定哪些函数执行时间最长。例如，让我们看看`ls`：

```cpp
> valgrind --tool=callgrind ls
> callgrind_annotate callgrind.out.*
```

这导致以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/050bd8f5-9adc-4825-b4db-fc8970010080.png)

正如我们所看到的，`strcmp`函数被频繁调用。这些信息可以与*单元*级别的基准测试 API 相结合，以确定是否可以编写更快的`strcmp`版本（例如，使用手写汇编和特殊的 CPU 指令）。使用诸如 Hayai 和 Valgrind 之类的工具，可以分离出程序中消耗最多 CPU、内存甚至电源的函数，并重写它们以提供更好的性能，同时将精力集中在将提供最佳投资回报的优化上。

# 查看汇编代码

在本教程中，我们将从两种不同的优化中查看生成的汇编：循环展开和传引用参数。这个教程很重要，因为它将教会你如何深入了解编译器是如何将 C++转换为可执行代码的。这些信息将揭示为什么 C++规范（如 C++核心指南）对于优化和性能做出了推荐。当你试图编写更好的 C++代码时，尤其是当你想要优化它时，这通常是至关重要的。

# 准备工作

在开始之前，请确保已满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有正确的工具来编译和执行本教程中的示例。完成这些操作后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做到这一点...

执行以下步骤来完成本教程：

1.  从新的终端中，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter06
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake -DCMAKE_BUILD_TYPE=Debug .
> make recipe02_examples
```

1.  一旦源代码被编译，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe02_example01

> ./recipe02_example02

> ./recipe02_example03

> ./recipe02_example04

> ./recipe02_example05
```

在下一节中，我们将逐个介绍这些例子，并解释每个例子程序的作用以及它与本教程中所教授的课程的关系。

# 它是如何工作的...

学习如何优化 C++代码的最佳方法之一是学习如何分析编译器在编译后生成的汇编代码。在本教程中，我们将学习如何通过查看两个不同的例子来进行这种分析：循环展开和传引用参数。

在我们查看这些例子之前，让我们先看一个简单的例子：

```cpp
int main(void)
{ }
```

在上面的例子中，我们只有一个`main()`函数。我们没有包含任何 C 或 C++库，`main()`函数本身是空的。如果我们编译这个例子，我们会发现生成的二进制文件仍然非常大：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/99ace8d4-1e3a-45be-a24f-c318040b45eb.png)

在这种情况下，这个例子的大小是`22kb`。为了显示编译器为这段代码生成的汇编代码，我们可以这样做：

```cpp
> objdump -d recipe02_example01
```

前面命令的输出结果应该令人惊讶，因为对于一个完全没有任何功能的应用程序来说，代码量很大。

为了更好地了解有多少代码，我们可以通过使用`grep`来细化输出，这是一个让我们从任何命令中过滤文本的工具。让我们看看代码中的所有函数：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/d17573c5-b2e5-4905-a7a5-29b065898a0d.png)

正如我们所看到的，编译器会自动为您添加几个函数。这包括`_init()`、`_fini()`和`_start()`函数。我们还可以查看特定的函数，比如我们的主函数，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/1b25fad2-bea6-4f4c-a87b-adb0e85f399d.png)

在上面的例子中，我们搜索`objdump`的输出，查找`main>:`和`RETQ`。所有函数名都以`>:`结尾，而每个函数的最后一条指令（通常）是在 Intel 64 位系统上的`RETQ`。

以下是生成的汇编：

```cpp
  401106: push %rbp
  401107: mov %rsp,%rbp
```

首先，它将当前的堆栈帧指针（`rbp`）存储到堆栈中，并将堆栈帧指针加载到`main()`函数的堆栈的当前地址（`rsp`）。

这可以在每个函数中看到，并称为函数的前言。`main()`执行的唯一代码是`return 0`，这是编译器自动添加的代码：

```cpp
  40110a: mov $0x0,%eax
```

最后，这个函数中的最后一个汇编包含了函数的结尾，它恢复了堆栈帧指针并返回：

```cpp

  40110f: pop %rbp
  401110: retq
```

现在我们对如何获取和阅读编译后的 C++程序的汇编结果有了更好的理解，让我们来看一个循环展开的例子，循环展开是用其等效的指令版本替换循环指令的过程。为了做到这一点，确保示例是在发布模式下编译的（也就是启用了编译器优化），通过以下命令进行配置：

```cpp
> cmake -DCMAKE_BUILD_TYPE=Release .
> make
```

为了理解循环展开，让我们看一下以下代码：

```cpp
volatile int data[1000];

int main(void)
{
    for (auto i = 0U; i < 1000; i++) {
        data[i] = 42;
    }
}
```

当编译器遇到循环时，生成的汇编代码包含以下代码：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/4414aa74-9275-444b-bf7a-a8a150a4a426.png)

让我们来分解一下：

```cpp
  401020: xor %eax,%eax
  401022: nopw 0x0(%rax,%rax,1)
```

前两条指令属于代码的`for (auto i = 0U;`部分。在这种情况下，`i`变量存储在`EAX`寄存器中，并使用`XOR`指令将其设置为`0`（在 Intel 上，`XOR`指令比`MOV`指令更快地将寄存器设置为 0）。`NOPW`指令可以安全地忽略。

接下来的几条指令是交错的，如下所示：

```cpp
  401028: mov %eax,%edx
  40102a: add $0x1,%eax
  40102d: movl $0x2a,0x404040(,%rdx,4)
```

这些指令代表了`i++;`和`data[i] = 42;`的代码。第一条指令存储了`i`变量的当前值，然后将其加一，然后再将`42`存储到由`i`索引的内存地址中。方便的是，这个汇编结果展示了一个优化的可能机会，因为编译器可以使用以下方式实现相同的功能：

```cpp
 movl $0x2a,0x404040(,%rax,4)
 add $0x1,%eax
```

前面的代码在执行`i++`之前存储了值`42`，因此不再需要以下内容：

```cpp
  mov %eax,%edx
```

存在多种方法来实现这种潜在的优化，包括使用不同的编译器或手写汇编。下一组指令执行我们`for`循环的`i < 1000;`部分：

```cpp
  401038: cmp $0x3e8,%eax
  40103d: jne 401028 <main+0x8>
```

`CMP`指令检查`i`变量是否为`1000`，如果不是，则使用`JNE`指令跳转到函数顶部继续循环。否则，剩下的代码执行：

```cpp
  40103f: xor %eax,%eax
  401041: retq 
```

为了了解循环展开的工作原理，让我们将循环的迭代次数从`1000`改为`4`，如下所示：

```cpp
volatile int data[4];

int main(void)
{
    for (auto i = 0U; i < 4; i++) {
        data[i] = 42;
    }
}
```

我们可以看到，除了循环迭代次数之外，代码是相同的。汇编结果如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/4414aa74-9275-444b-bf7a-a8a150a4a426.png)

我们可以看到，`CMP`和`JNE`指令都不见了。现在，以下代码被编译了（但还有更多！）：

```cpp
    for (auto i = 0U; i < 4; i++) {
        data[i] = 42;
    }
```

编译后的代码转换为以下代码：

```cpp
        data[0] = 42;
        data[1] = 42;
        data[2] = 42;
        data[3] = 42;
```

`return 0;`出现在赋值之间的汇编中。这是允许的，因为函数的返回值与赋值无关（因为赋值指令从不触及`RAX`），这为 CPU 提供了额外的优化（因为它可以并行执行`return 0;`，尽管这是本书范围之外的话题）。值得注意的是，循环展开并不要求使用少量的循环迭代。一些编译器会部分展开循环以实现优化（例如，以`4`个为一组而不是一次执行`1`次循环）。

我们的最后一个例子将研究按引用传递而不是按值传递。首先，在调试模式下重新编译代码：

```cpp
> cmake -DCMAKE_BUILD_TYPE=Debug .
> make
```

让我们看一下以下例子：

```cpp
struct mydata {
    int data[100];
};

void foo(mydata d)
{
    (void) d;
}

int main(void)
{
    mydata d;
    foo(d);
}
```

在这个例子中，我们创建了一个大型结构体，并按值传递给了我们主函数中名为`foo()`的函数。主函数的汇编结果如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/45b46604-3410-4880-b1de-7ed7b6ecbd4b.png)

前面示例中的重要指令如下：

```cpp
  401137: rep movsq %ds:(%rsi),%es:(%rdi)
  40113a: callq 401106 <_Z3foo6mydata>
```

前面的指令将大型结构体复制到堆栈上，然后调用我们的`foo()`函数。复制是因为结构体是按值传递的，这意味着编译器必须执行复制。顺便说一句，如果您想以可读的格式而不是混淆的格式看到输出，可以在选项中添加`C`，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/1e602d6c-13f7-4a30-9494-09b95deb705c.png)

最后，让我们按引用传递来看看结果的改善：

```cpp
struct mydata {
    int data[100];
};

void foo(mydata &d)
{
    (void) d;
}

int main(void)
{
    mydata d;
    foo(d);
}
```

如我们所见，我们通过引用传递结构而不是按值传递。生成的汇编代码如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/60ea97a9-3744-48ce-bc91-000a09a842b0.png)

在这里，代码要少得多，导致可执行文件更快。正如我们所学到的，如果我们希望了解编译器生成了什么，检查编译器生成的内容是有效的，因为这提供了有关您可以进行的潜在更改的更多信息，以编写更有效的 C++代码。

# 减少内存分配的数量

C++在应用程序运行时会一直产生隐藏的内存分配。本教程将教你如何确定 C++何时分配内存以及如何在可能的情况下删除这些分配。了解如何删除内存分配很重要，因为`new()`、`delete()`、`malloc()`和`free()`等函数不仅速度慢，而且它们提供的内存也是有限的。删除不需要的分配不仅可以提高应用程序的整体性能，还有助于减少其整体内存需求。

# 准备工作

开始之前，请确保已满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git valgrind cmake
```

这将确保您的操作系统具有适当的工具来编译和执行本教程中的示例。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行示例。

# 如何做...

执行以下步骤以完成本教程：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter06
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe03_examples
```

1.  源代码编译完成后，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe03_example01

> ./recipe03_example02

> ./recipe03_example03

> ./recipe03_example04

> ./recipe03_example05

> ./recipe03_example06

> ./recipe03_example07
```

在下一节中，我们将逐个步骤地介绍每个示例，并解释每个示例程序的作用以及它与本教程中所教授的课程的关系。

# 它是如何工作的...

在本教程中，我们将学习如何监视应用程序消耗的内存量，以及 C++在幕后分配内存的不同方式。首先，让我们看一个什么都不做的简单应用程序：

```cpp
int main(void)
{
}
```

如我们所见，这个应用程序什么也没做。要查看应用程序使用了多少内存，我们将使用动态分析工具 Valgrind，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/4b394af7-4501-4c48-bfd4-20e1f216d0de.png)

如前面的示例所示，我们的应用程序已经分配了堆内存（即使用`new()`/`delete()`或`malloc()`/`free()`分配的内存）。要确定此分配发生的位置，让我们再次使用 Valgrind，但这次我们将启用一个名为**Massif**的工具，它将跟踪内存分配的来源：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/def07c68-3679-40b0-ae34-b2b5ebb1757c.png)

要查看上述示例的输出，我们必须输出一个为我们自动创建的文件：

```cpp
> cat massif.out.*
```

这导致我们检索到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/2434cd14-83e9-4761-b2d4-a3f3616eb879.png)

如我们所见，动态链接器的`init()`函数正在执行分配，大小为`72,704`字节。为了进一步演示如何使用 Valgrind，让我们看一个简单的例子，其中我们执行自己的分配：

```cpp
int main(void)
{
    auto ptr = new int;
    delete ptr;
}
```

要查看上述源代码的内存分配，我们需要再次运行 Valgrind：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/5ca77107-fafd-479a-8c84-a660ea785dd3.png)

如我们所见，我们已经分配了`72,708`字节。由于我们知道应用程序将自动为我们分配`72,704`字节，我们可以看到 Valgrind 成功检测到我们分配的`4`字节（在运行 Linux 的 Intel 64 位系统上是整数的大小）。要查看此分配发生的位置，让我们再次使用 Massif：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/d1b7826e-721d-44ad-8c3a-dbc55d4cc5e1.png)

正如我们所看到的，我们在命令行选项中添加了`--threshold=0.1`，这告诉 Valgrind 任何占`.1%`分配的分配都应该被记录。让我们`cat`一下结果（`cat`程序只是将文件的内容回显到控制台）：

```cpp
> cat massif.out.*
```

通过这样做，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/8e0189c6-c5a1-44bb-a848-4d752d4bee3a.png)

正如我们所看到的，Valgrind 检测到了`init()`函数和我们的`main()`函数的内存分配。

现在我们知道如何分析应用程序所做的内存分配，让我们看一些不同的 C++ API，看看它们在幕后做了什么类型的内存分配。首先，让我们看一个`std::vector`，如下所示：

```cpp
#include <vector>
std::vector<int> data;

int main(void)
{
    for (auto i = 0; i < 10000; i++) {
        data.push_back(i);
    }
}
```

在这里，我们创建了一个整数的全局向量，然后向向量添加了`10,000`个整数。使用 Valgrind，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/01e29595-e5db-4190-8321-93c0973e49cb.png)

在这里，我们可以看到有`16`次分配，总共`203,772`字节。我们知道应用程序将为我们分配`72,704`字节，所以我们必须从总数中去掉这部分，留下`131,068`字节的内存。我们还知道我们分配了`10,000`个整数，总共`40,000`字节。所以，问题是，其他`91,068`字节来自哪里？

答案在于`std::vector`在幕后的工作方式。`std::vector`必须始终确保内存的连续视图，这意味着当插入发生并且`std::vector`空间不足时，它必须分配一个新的更大的缓冲区，然后将旧缓冲区的内容复制到新缓冲区。问题在于`std::vector`不知道在所有插入完成时缓冲区的总大小，因此当执行第一次插入时，它创建一个小缓冲区以确保不浪费内存，然后以小增量增加`std::vector`的大小，导致多次内存分配和内存复制。

为了防止发生这种分配，C++提供了`reserve()`函数，该函数允许`std::vector`的用户估计他们认为他们将需要多少内存。例如，考虑以下代码：

```cpp
#include <vector>
std::vector<int> data;

int main(void)
{
    data.reserve(10000);  // <--- added optimization 

    for (auto i = 0; i < 10000; i++) {
        data.push_back(i);
    }
}
```

在前面的例子中，代码与之前的例子相同，唯一的区别是我们添加了对`reserve()`函数的调用，该函数告诉`std::vector`我们认为向量将有多大。Valgrind 的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/726ac6f0-8701-40ea-b53e-310902914389.png)

正如我们所看到的，应用程序分配了`112,704`字节。如果我们去掉应用程序默认创建的`72,704`字节，我们剩下`40,000`字节，这正是我们预期的大小（因为我们向向量添加了`10,000`个整数，每个整数的大小为`4`字节）。

数据结构不是 C++标准库 API 的唯一一种执行隐藏分配的类型。让我们看一个`std::any`，如下所示：

```cpp
#include <any>
#include <string>

std::any data;

int main(void)
{
    data = 42;
    data = std::string{"The answer is: 42"};
}
```

在这个例子中，我们创建了一个`std::any`，并将其分配给一个整数和一个`std::string`。让我们看一下 Valgrind 的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/56140dbb-bf2e-4670-82e2-15eb7134ce6d.png)

正如我们所看到的，发生了`3`次分配。第一次分配是默认发生的，而第二次分配是由`std::string`产生的。最后一次分配是由`std::any`产生的。这是因为`std::any`必须调整其内部存储以适应它看到的任何新的随机数据类型。换句话说，为了处理*通用*数据类型，C++必须执行分配。如果我们不断改变数据类型，情况会变得更糟。例如，考虑以下代码：

```cpp
#include <any>
#include <string>

std::any data;

int main(void)
{
    data = 42;
    data = std::string{"The answer is: 42"};
    data = 42;                                 // <--- keep swapping
    data = std::string{"The answer is: 42"};   // <--- keep swapping
    data = 42;                                 // <--- keep swapping
    data = std::string{"The answer is: 42"};   // ...
    data = 42;
    data = std::string{"The answer is: 42"};
}
```

前面的代码与之前的例子相同，唯一的区别是我们在不同的数据类型之间进行了交换。Valgrind 产生了以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/1df2f995-397d-4929-adfd-d6847ce57abf.png)

正如我们所看到的，发生了`9`次分配，而不是`3`次。为了解决这个问题，我们需要使用`std::variant`而不是`std::any`，如下所示：

```cpp
#include <variant>
#include <string>

std::variant<int, std::string> data;

int main(void)
{
    data = 42;
    data = std::string{"The answer is: 42"};
}
```

`std::any`和`std::variant`之间的区别在于，`std::variant`要求用户声明变体必须支持的类型，从而在赋值时消除了动态内存分配的需要。Valgrind 的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/2a8432c6-3aa6-4f3e-9f2d-d83c733ea3d2.png)

现在，我们只有`2`个分配，正如预期的那样（默认分配和从`std::string`分配）。正如本教程所示，包括 C++标准库在内的库可以隐藏内存分配，可能会减慢代码速度并使用比预期更多的内存资源。诸如 Valgrind 之类的工具可以用于识别这些类型的问题，从而使您能够创建更高效的 C++代码。

# 声明 noexcept

C++11 引入了`noexcept`关键字，除了简化异常的一般使用方式外，还包括了更好的 C++异常实现，去除了一些性能损耗。但是，这并不意味着异常不包括*开销*（即性能惩罚）。在本教程中，我们将探讨异常如何给应用程序增加开销，以及`noexcept`关键字如何帮助减少这些惩罚（取决于编译器）。

本教程很重要，因为它将演示如果一个函数不会抛出异常，那么应该标记为`noexcept`，以防止额外的开销影响应用程序的总大小，从而导致应用程序加载更快。

# 准备工作

在开始之前，请确保已满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有适当的工具来编译和执行本教程中的示例。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行我们的示例。

# 操作步骤...

执行以下步骤完成本教程：

1.  在新的终端中，运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter06
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe04_examples
```

1.  源代码编译完成后，可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe04_example01 

> ./recipe04_example02
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本教程所教授的课程的关系。

# 工作原理

在本教程中，我们将学习为什么将函数标记为`noexcept`非常重要，如果它不应该抛出异常。这是因为它去除了对异常支持的额外开销，可以改善执行时间、应用程序大小，甚至加载时间（这取决于编译器、使用的标准库等）。为了证明这一点，让我们创建一个简单的示例：

```cpp
class myclass
{
    int answer;

public:
    ~myclass()
    {
        answer = 42;
    }
};
```

我们需要做的第一件事是创建一个类，在销毁时设置一个`private`成员变量，如下所示：

```cpp
void foo()
{
    throw 42;
}

int main(void) 
{
    myclass c;

    try {
        foo();
    }
    catch (...) {
    }
}
```

现在，我们可以创建两个函数。第一个函数抛出一个异常，而第二个函数是我们的主函数。这个函数创建了我们类的一个实例，并在`try`/`catch`块中调用`foo()`函数。换句话说，`main()`函数在任何时候都不会抛出异常。如果我们查看主函数的汇编代码，我们会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/e8b37484-b6b5-4a42-a49c-ace342254030.png)

正如我们所看到的，我们的主函数调用了`_Unwind_Resume`，这是异常解开器使用的。这额外的逻辑是因为 C++必须在函数末尾添加额外的异常逻辑。为了去除这额外的逻辑，告诉编译器`main()`函数不会抛出异常：

```cpp
int main(void) noexcept
{
    myclass c;

    try {
        foo();
    }
    catch (...) {
    }
}
```

添加`noexcept`告诉编译器不能抛出异常。结果，该函数不再包含处理异常的额外逻辑，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/b17102a6-7e31-4c82-8751-308a935b23f2.png)

正如我们所看到的，取消函数不再存在。值得注意的是，存在对 catch 函数的调用，这是由于`try`/`catch`块而不是异常的开销。
