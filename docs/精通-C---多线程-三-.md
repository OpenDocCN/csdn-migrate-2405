# 精通 C++ 多线程（三）

> 原文：[`annas-archive.org/md5/D8BD7CE4843A1A81E0B93B3CA07CBEC9`](https://annas-archive.org/md5/D8BD7CE4843A1A81E0B93B3CA07CBEC9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：最佳实践

与大多数事物一样，最好是避免犯错误，而不是事后纠正。本章介绍了多线程应用程序中的许多常见错误和设计问题，并展示了避免常见和不太常见问题的方法。

本章的主题包括：

+   常见的多线程问题，如死锁和数据竞争。

+   正确使用互斥锁、锁和陷阱。

+   在使用静态初始化时可能出现的问题。

# 适当的多线程

在前面的章节中，我们已经看到了编写多线程代码时可能出现的各种潜在问题。这些问题从明显的问题，比如两个线程无法同时写入同一位置，到更微妙的问题，比如互斥锁的不正确使用。

还有许多与多线程代码直接相关的元素的问题，但这些问题可能导致看似随机的崩溃和其他令人沮丧的问题。其中一个例子是变量的静态初始化。在接下来的章节中，我们将看到所有这些问题以及更多问题，以及避免不得不处理它们的方法。

就像生活中的许多事情一样，它们是有趣的经历，但通常你不想重复它们。

# 错误的期望-死锁

死锁的描述已经非常简洁了。当两个或更多进程试图访问另一个进程持有的资源，而另一个线程同时正在等待访问它持有的资源时，就会发生死锁。

例如：

1.  线程 1 获得对资源 A 的访问

1.  线程 1 和 2 都想要访问资源 B

1.  线程 2 获胜，现在拥有 B，而线程 1 仍在等待 B

1.  线程 2 现在想要使用 A，并等待访问

1.  线程 1 和 2 都永远等待资源

在这种情况下，我们假设线程最终将能够在某个时刻访问每个资源，而事实正好相反，因为每个线程都持有另一个线程需要的资源。

可视化，这个死锁过程看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00017.jpeg)

这清楚地表明了在防止死锁时有两个基本规则：

+   尽量不要同时持有多个锁。

+   尽快释放任何持有的锁。

在第四章中，我们看到了一个现实生活中的例子，*线程同步和通信*，当我们看了调度程序演示代码时。这段代码涉及两个互斥锁，以保护对两个数据结构的访问：

```cpp
void Dispatcher::addRequest(AbstractRequest* request) {
    workersMutex.lock();
    if (!workers.empty()) {
          Worker* worker = workers.front();
          worker->setRequest(request);
          condition_variable* cv;
          mutex* mtx;
          worker->getCondition(cv);
          worker->getMutex(mtx);
          unique_lock<mutex> lock(*mtx);
          cv->notify_one();
          workers.pop();
          workersMutex.unlock();
    }
    else {
          workersMutex.unlock();
          requestsMutex.lock();
          requests.push(request);
          requestsMutex.unlock();
    }
 } 

```

这里的互斥锁是`workersMutex`和`requestsMutex`变量。我们可以清楚地看到，在尝试获取另一个互斥锁之前，我们从不持有互斥锁。我们明确地在方法的开始处锁定`workersMutex`，以便我们可以安全地检查工作数据结构是否为空。

如果不为空，我们将新请求交给工作线程。然后，当我们完成了工作，数据结构，我们释放了互斥锁。此时，我们保留零个互斥锁。这里没有太复杂的地方，因为我们只使用了一个互斥锁。

有趣的是在 else 语句中，当没有等待的工作线程并且我们需要获取第二个互斥锁时。当我们进入这个范围时，我们保留一个互斥锁。我们可以尝试获取`requestsMutex`并假设它会起作用，但这可能会导致死锁，原因很简单：

```cpp
bool Dispatcher::addWorker(Worker* worker) {
    bool wait = true;
    requestsMutex.lock();
    if (!requests.empty()) {
          AbstractRequest* request = requests.front();
          worker->setRequest(request);
          requests.pop();
          wait = false;
          requestsMutex.unlock();
    }
    else {
          requestsMutex.unlock();
          workersMutex.lock();
          workers.push(worker);
          workersMutex.unlock();
    }
          return wait;
 } 

```

先前的函数的伴随函数也使用了这两个互斥锁。更糟糕的是，这个函数在一个单独的线程中运行。结果，当第一个函数在尝试获取`requestsMutex`时持有`workersMutex`，而第二个函数同时持有后者并尝试获取前者时，我们就会陷入死锁。

然而，在这里看到的函数中，这两条规则都已成功实现；我们从不同时持有多个锁，并且尽快释放我们持有的任何锁。这可以在两个 else 情况中看到，在进入它们时，我们首先释放不再需要的任何锁。

在任何一种情况下，我们都不需要再分别检查工作者或请求数据结构；我们可以在做其他任何事情之前释放相关的锁。这导致了以下可视化效果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00018.jpeg)

当然，我们可能需要使用两个或更多数据结构或变量中包含的数据；这些数据同时被其他线程使用。很难确保在生成的代码中没有死锁的机会。

在这里，人们可能想考虑使用临时变量或类似的东西。通过锁定互斥量，复制相关数据，并立即释放锁，就不会与该互斥量发生死锁的机会。即使必须将结果写回数据结构，也可以在单独的操作中完成。

这在预防死锁方面增加了两条规则：

+   尽量不要同时持有多个锁。

+   尽快释放任何持有的锁。

+   永远不要持有锁的时间超过绝对必要的时间。

+   当持有多个锁时，请注意它们的顺序。

# 粗心大意 - 数据竞争

数据竞争，也称为竞争条件，发生在两个或更多线程试图同时写入同一共享内存时。因此，每个线程执行的指令序列期间和结束时共享内存的状态是非确定性的。

正如我们在第六章中看到的，*调试多线程代码*，数据竞争经常被用于调试多线程应用程序的工具报告。例如：

```cpp
    ==6984== Possible data race during write of size 1 at 0x5CD9260 by thread #1
 ==6984== Locks held: none
 ==6984==    at 0x40362C: Worker::stop() (worker.h:37)
 ==6984==    by 0x403184: Dispatcher::stop() (dispatcher.cpp:50)
 ==6984==    by 0x409163: main (main.cpp:70)
 ==6984== 
 ==6984== This conflicts with a previous read of size 1 by thread #2
 ==6984== Locks held: none
 ==6984==    at 0x401E0E: Worker::run() (worker.cpp:51)
 ==6984==    by 0x408FA4: void std::_Mem_fn_base<void (Worker::*)(), true>::operator()<, void>(Worker*) const (in /media/sf_Projects/Cerflet/dispatcher/dispatcher_demo)
 ==6984==    by 0x408F38: void std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::_M_invoke<0ul>(std::_Index_tuple<0ul>) (functional:1531)
 ==6984==    by 0x408E3F: std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::operator()() (functional:1520)
 ==6984==    by 0x408D47: std::thread::_Impl<std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)> >::_M_run() (thread:115)
 ==6984==    by 0x4EF8C7F: ??? (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
 ==6984==    by 0x4C34DB6: ??? (in /usr/lib/valgrind/vgpreload_helgrind-amd64-linux.so)
 ==6984==    by 0x53DF6B9: start_thread (pthread_create.c:333)
 ==6984==  Address 0x5cd9260 is 96 bytes inside a block of size 104 alloc'd
 ==6984==    at 0x4C2F50F: operator new(unsigned long) (in /usr/lib/valgrind/vgpreload_helgrind-amd64-linux.so)
 ==6984==    by 0x40308F: Dispatcher::init(int) (dispatcher.cpp:38)
 ==6984==    by 0x4090A0: main (main.cpp:51)
 ==6984==  Block was alloc'd by thread #1

```

生成前面警告的代码如下：

```cpp
bool Dispatcher::stop() {
    for (int i = 0; i < allWorkers.size(); ++i) {
          allWorkers[i]->stop();
    }
          cout << "Stopped workers.\n";
          for (int j = 0; j < threads.size(); ++j) {
          threads[j]->join();
                      cout << "Joined threads.\n";
    }
 } 

```

考虑一下`Worker`实例中的这段代码：

```cpp
   void stop() { running = false; } 

```

我们还有：

```cpp
void Worker::run() {
    while (running) {
          if (ready) {
                ready = false;
                request->process();
                request->finish();
          }
                      if (Dispatcher::addWorker(this)) {
                while (!ready && running) {
                      unique_lock<mutex> ulock(mtx);
                      if (cv.wait_for(ulock, chrono::seconds(1)) == cv_status::timeout) {
                      }
                }
          }
    }
 } 

```

在这里，`running`是一个布尔变量，被设置为`false`（从一个线程写入），向工作者线程发出信号，告诉它应该终止其等待循环，其中从不同进程（主线程与工作者线程）读取布尔变量：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00019.jpeg)

这个特定示例的警告是由于一个布尔变量同时被写入和读取。当然，这种特定情况之所以安全，是因为原子性，如在第八章中详细解释的那样，*原子操作 - 与硬件交互*。

即使像这样的操作也存在潜在风险的原因是，读取操作可能发生在变量仍在更新过程中。例如，对于一个 32 位整数，在硬件架构上，更新这个变量可能是一次完成，或者多次完成。在后一种情况下，读取操作可能读取一个具有不可预测结果的中间值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00020.jpeg)

更有趣的情况是，当多个线程写入一个标准输出而不使用，例如，`cout`时。由于这个流不是线程安全的，结果输出流将包含输入流的片段，每当任何一个线程有机会写入时：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00021.jpeg)

因此，预防数据竞争的基本规则是：

+   永远不要对未锁定的、非原子的共享资源进行写入

+   永远不要从未锁定的、非原子的共享资源中读取

这基本上意味着任何写入或读取都必须是线程安全的。如果一个线程写入共享内存，那么其他线程就不能同时写入它。同样，当我们从共享资源中读取时，我们需要确保最多只有其他线程也在读取共享资源。

这种级别的互斥自然是通过互斥实现的，正如我们在前面的章节中看到的那样，读写锁提供了一种改进，允许同时进行读取，同时将写入作为完全互斥的事件。

当然，互斥也有一些陷阱，我们将在接下来的部分中看到。

# 互斥并非魔法

互斥基本上是所有形式的互斥 API 的基础。从本质上讲，它们似乎非常简单，只有一个线程可以拥有一个互斥，其他线程则整齐地排队等待获取互斥的锁。

可以将这个过程想象成下面这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00022.gif)

现实当然没有那么美好，主要是由于硬件对我们施加的实际限制。一个明显的限制是同步原语并不是免费的。即使它们是在硬件中实现的，也需要多次调用才能使它们工作。

在硬件中实现互斥的两种最常见方式是使用**测试和设置**（TAS）或**比较和交换**（CAS）CPU 特性。

测试和设置通常被实现为两个汇编级指令，它们是自主执行的，意味着它们不能被中断。第一条指令测试某个内存区域是否设置为 1 或零。只有当值为零（`false`）时，第二条指令才会执行。这意味着互斥尚未被锁定。第二条指令将内存区域设置为 1，从而锁定互斥。

在伪代码中，这看起来像这样：

```cpp
bool TAS(bool lock) { 
   if (lock) { 
         return true; 
   } 
   else { 
         lock = true; 
         return false; 
   } 
} 

```

比较和交换是对此的一个较少使用的变体，它对内存位置和给定值执行比较操作，只有在前两者匹配时才替换该内存位置的内容：

```cpp
bool CAS(int* p, int old, int new) { 
   if (*p != old) { 
               return false; 
         } 

   *p = new; 
         return true; 
} 

```

在任何情况下，都必须积极重复函数，直到返回正值：

```cpp
volatile bool lock = false; 

 void critical() { 
     while (TAS(&lock) == false); 
     // Critical section 
     lock = 0; 
 } 

```

在这里，使用简单的 while 循环不断轮询内存区域（标记为 volatile 以防止可能有问题的编译器优化）。通常，使用的算法会逐渐减少轮询的频率，以减少对处理器和内存系统的压力。

这清楚地表明互斥的使用并非免费，每个等待互斥锁的线程都会主动使用资源。因此，一般规则是：

+   确保线程等待互斥和类似锁的时间尽可能短。

+   对于较长的等待时间使用条件变量或定时器。

# 锁是花哨的互斥

正如我们在互斥一节中看到的，使用互斥时需要牢记一些问题。当然，这些问题也适用于使用基于互斥的锁和其他机制，即使这些 API 可能会弥补其中一些问题。

当首次使用多线程 API 时，人们可能会困惑的一件事是不同同步类型之间的实际区别。正如我们在本章前面讨论的那样，互斥在几乎所有同步机制中起着基础作用，只是在使用互斥实现所提供功能的方式上有所不同。

重要的是，它们不是独立的同步机制，而只是基本互斥类型的特殊化。无论是使用常规互斥、读/写锁、信号量，甚至像可重入（递归）互斥或锁这样奇特的东西，完全取决于要解决的特定问题。

对于调度器，我们首先在第四章中遇到，*线程同步和通信*，我们使用常规互斥锁来保护包含排队工作线程和请求的数据结构。由于对任何数据结构的访问可能不仅涉及读取操作，还涉及结构的操作，因此在那里使用读/写锁是没有意义的。同样，递归锁也不会对谦虚的互斥锁产生任何作用。

对于每个同步问题，因此必须问以下问题：

+   我有哪些要求？

+   哪种同步机制最适合这些要求？

因此，选择复杂类型是有吸引力的，但通常最好坚持满足所有要求的更简单的类型。当涉及调试自己的实现时，与花哨的实现相比，可以节省宝贵的时间。

# 线程与未来

最近，有人开始建议不要使用线程，而是倡导使用其他异步处理机制，如`promise`。背后的原因是使用线程和涉及的同步是复杂且容易出错的。通常，人们只想并行运行一个任务，而不关心如何获得结果。

对于只运行短暂的简单任务，这当然是有意义的。基于线程的实现的主要优势始终是可以完全定制其行为。使用`promise`，可以发送一个要运行的任务，并在最后从`future`实例中获取结果。这对于简单的任务很方便，但显然不能涵盖很多情况。

这里的最佳方法是首先充分了解线程和同步机制，以及它们的限制。只有在那之后，才真正有意义去考虑是否希望使用 promise、`packaged_task`或完整的线程。

对于这些更复杂的、基于未来的 API，另一个主要考虑因素是它们严重依赖模板，这可能会使调试和解决可能发生的任何问题变得比使用更直接和低级的 API 更不容易。

# 静态初始化顺序

静态变量是只声明一次的变量，基本上存在于全局范围，尽管可能只在特定类的实例之间共享。也可能有完全静态的类：

```cpp
class Foo { 
   static std::map<int, std::string> strings; 
   static std::string oneString; 

public: 
   static void init(int a, std::string b, std::string c) { 
         strings.insert(std::pair<int, std::string>(a, b)); 
         oneString = c; 
   } 
}; 

std::map<int, std::string> Foo::strings; 
std::string Foo::oneString; 

```

正如我们在这里看到的，静态变量以及静态函数似乎是一个非常简单但强大的概念。虽然在其核心是如此，但在静态变量和类的初始化方面，存在一个会让不慎的人陷入困境的主要问题。这是初始化顺序的形式。

想象一下，如果我们希望从另一个类的静态初始化中使用前面的类，就像这样：

```cpp
class Bar { 
   static std::string name; 
   static std::string initName(); 

public: 
   void init(); 
}; 

// Static initializations. 
std::string Bar::name = Bar::initName(); 

std::string Bar::initName() { 
   Foo::init(1, "A", "B"); 
   return "Bar"; 
} 

```

虽然这看起来可能会很好，但向类的映射结构添加第一个字符串作为键意味着这段代码很有可能会崩溃。其原因很简单，没有保证在调用`Foo::init()`时`Foo::string`已经初始化。因此，尝试使用未初始化的映射结构将导致异常。

简而言之，静态变量的初始化顺序基本上是随机的，如果不考虑这一点，就会导致非确定性行为。

这个问题的解决方案相当简单。基本上，目标是使更复杂的静态变量的初始化显式化，而不是像前面的例子中那样隐式化。为此，我们修改 Foo 类：

```cpp
class Foo { 
   static std::map<int, std::string>& strings(); 
   static std::string oneString; 

public: 
   static void init(int a, std::string b, std::string c) { 
         static std::map<int, std::string> stringsStatic = Foo::strings(); 
         stringsStatic.insert(std::pair<int, std::string>(a, b)); 
         oneString = c; 
   } 
}; 

std::string Foo::oneString; 

std::map<int, std::string>& Foo::strings() { 
   static std::map<int, std::string>* stringsStatic = new std::map<int, std::string>(); 
   return *stringsStatic; 
} 

```

从顶部开始，我们看到我们不再直接定义静态地图。相反，我们有一个同名的私有函数。这个函数的实现可以在这个示例代码的底部找到。在其中，我们有一个指向具有熟悉地图定义的地图结构的静态指针。

当调用这个函数时，如果还没有实例，就会创建一个新的地图，因为它是一个静态变量。在修改后的`init()`函数中，我们看到我们调用`strings()`函数来获得对这个实例的引用。这是显式初始化的部分，因为调用函数将始终确保在我们使用它之前初始化地图结构，解决了我们之前遇到的问题。

我们还在这里看到了一个小优化：我们创建的`stringsStatic`变量也是静态的，这意味着我们只会调用一次`strings()`函数。这样做可以避免重复的函数调用，并恢复我们在先前简单但不稳定的实现中所拥有的速度。

因此，静态变量初始化的基本规则是，对于非平凡的静态变量，始终使用显式初始化。

# 总结

在本章中，我们看了一些编写多线程代码时需要牢记的良好实践和规则，以及一些建议。到目前为止，人们应该能够避免一些编写此类代码时的重大陷阱和主要混淆源。

在下一章中，我们将看到如何利用原子操作和 C++11 引入的`<atomics>`头文件来利用底层硬件。


# 第八章：原子操作 - 与硬件一起工作

许多优化和线程安全性取决于对底层硬件的理解：从某些架构上的对齐内存访问，到知道哪些数据大小和因此 C++类型可以安全地进行访问而不会有性能惩罚或需要互斥锁等。

本章将介绍如何利用多个处理器架构的特性，例如防止使用互斥锁，其中原子操作将防止任何访问冲突。还将研究诸如 GCC 中的特定于编译器的扩展。

本章主题包括：

+   原子操作的类型以及如何使用它们

+   如何针对特定的处理器架构

+   基于编译器的原子操作

# 原子操作

简而言之，原子操作是处理器可以用单个指令执行的操作。这使得它在没有任何干扰（除了中断）的情况下是原子的，或者可以更改任何变量或数据。

应用包括保证指令执行顺序，无锁实现以及相关用途，其中指令执行顺序和内存访问保证是重要的。

在 2011 年之前的 C++标准中，对处理器提供的原子操作的访问仅由编译器使用扩展提供。

# Visual C++

对于微软的 MSVC 编译器，有 interlocked 函数，从 MSDN 文档总结而来，从添加功能开始：

| **Interlocked 函数** | **描述** |
| --- | --- |
| `InterlockedAdd` | 对指定的`LONG`值执行原子加法操作。 |
| `InterlockedAddAcquire` | 对指定的`LONG`值执行原子加法操作。该操作使用获取内存排序语义执行。 |
| `InterlockedAddRelease` | 对指定的`LONG`值执行原子加法操作。该操作使用释放内存排序语义执行。 |
| `InterlockedAddNoFence` | 对指定的`LONG`值执行原子加法操作。该操作是原子执行的，但不使用内存屏障（在本章中介绍）。 |

这些是该特性的 32 位版本。API 中还有其他方法的 64 位版本。原子函数往往专注于特定的变量类型，但本摘要中省略了此 API 中的变体，以保持简洁。

我们还可以看到获取和释放的变体。这些提供了保证，即相应的读取或写入访问将受到内存重排序（在硬件级别）的保护，以及任何后续的读取或写入操作。最后，无栅栏变体（也称为内存屏障）执行操作而不使用任何内存屏障。

通常，CPU 执行指令（包括内存读取和写入）是为了优化性能而无序执行的。由于这种行为并不总是理想的，因此添加了内存屏障以防止此指令重排序。

接下来是原子`AND`特性：

| **Interlocked 函数** | **描述** |
| --- | --- |
| `InterlockedAnd` | 对指定的`LONG`值执行原子`AND`操作。 |
| `InterlockedAndAcquire` | 对指定的`LONG`值执行原子`AND`操作。该操作使用获取内存排序语义执行。 |
| `InterlockedAndRelease` | 对指定的`LONG`值执行原子`AND`操作。该操作使用释放内存排序语义执行。 |
| `InterlockedAndNoFence` | 对指定的`LONG`值执行原子`AND`操作。该操作是原子执行的，但不使用内存屏障。 |

位测试功能如下：

| **Interlocked 函数** | **描述** |
| --- | --- |
| `InterlockedBitTestAndComplement` | 测试指定的`LONG`值的指定位并对其进行补码。 |
| `InterlockedBitTestAndResetAcquire` | 测试指定的`LONG`值的指定位，并将其设置为`0`。该操作是`原子`的，并且使用获取内存排序语义执行。 |
| `InterlockedBitTestAndResetRelease` | 测试指定的`LONG`值的指定位，并将其设置为`0`。该操作是`原子`的，并且使用内存释放语义执行。 |
| `InterlockedBitTestAndSetAcquire` | 测试指定的`LONG`值的指定位，并将其设置为`1`。该操作是`原子`的，并且使用获取内存排序语义执行。 |
| `InterlockedBitTestAndSetRelease` | 测试指定的`LONG`值的指定位，并将其设置为`1`。该操作是`原子`的，并且使用释放内存排序语义执行。 |
| `InterlockedBitTestAndReset` | 测试指定的`LONG`值的指定位，并将其设置为`0`。 |
| `InterlockedBitTestAndSet` | 测试指定的`LONG`值的指定位，并将其设置为`1`。 |

比较功能可以列举如下：

| **Interlocked function** | **描述** |
| --- | --- |
| `InterlockedCompareExchange` | 对指定的值执行原子比较和交换操作。该函数比较两个指定的 32 位值，并根据比较的结果与另一个 32 位值进行交换。 |
| `InterlockedCompareExchangeAcquire` | 对指定的值执行原子比较和交换操作。该函数比较两个指定的 32 位值，并根据比较的结果与另一个 32 位值进行交换。操作使用获取内存排序语义执行。 |
| `InterlockedCompareExchangeRelease` | 对指定的值执行原子比较和交换操作。该函数比较两个指定的 32 位值，并根据比较的结果与另一个 32 位值进行交换。交换使用释放内存排序语义执行。 |
| `InterlockedCompareExchangeNoFence` | 对指定的值执行原子比较和交换操作。该函数比较两个指定的 32 位值，并根据比较的结果与另一个 32 位值进行交换。操作是原子的，但不使用内存屏障。 |
| `InterlockedCompareExchangePointer` | 对指定的指针值执行原子比较和交换操作。该函数比较两个指定的指针值，并根据比较的结果与另一个指针值进行交换。 |
| `InterlockedCompareExchangePointerAcquire` | 对指定的指针值执行原子比较和交换操作。该函数比较两个指定的指针值，并根据比较的结果与另一个指针值进行交换。操作使用获取内存排序语义执行。 |
| `InterlockedCompareExchangePointerRelease` | 对指定的指针值执行原子比较和交换操作。该函数比较两个指定的指针值，并根据比较的结果与另一个指针值进行交换。操作使用释放内存排序语义执行。 |
| `InterlockedCompareExchangePointerNoFence` | 对指定的值执行原子比较和交换操作。该函数比较两个指定的指针值，并根据比较的结果与另一个指针值进行交换。操作是原子的，但不使用内存屏障。 |

递减功能如下：

| **Interlocked function** | **描述** |
| --- | --- |
| `InterlockedDecrement` | 递减（减少一个）指定 32 位变量的值作为`原子`操作。 |
| `InterlockedDecrementAcquire` | 递减（减少一个）指定 32 位变量的值作为`原子`操作。操作使用获取内存排序语义执行。 |
| `InterlockedDecrementRelease` | 将指定的 32 位变量的值减 1 作为原子操作。操作使用释放内存排序语义执行。 |
| `InterlockedDecrementNoFence` | 将指定的 32 位变量的值减 1 作为原子操作。操作是原子执行的，但不使用内存屏障。 |

交换（交换）功能包括：

| **Interlocked function** | **描述** |
| --- | --- |
| --- |
| `InterlockedExchange` | 将 32 位变量设置为指定值作为原子操作。 |
| `InterlockedExchangeAcquire` | 将 32 位变量设置为指定值作为原子操作。操作使用获取内存排序语义执行。 |
| `InterlockedExchangeNoFence` | 将 32 位变量设置为指定值作为原子操作。操作是原子执行的，但不使用内存屏障。 |
| `InterlockedExchangePointer` | 原子交换一对指针值。 |
| `InterlockedExchangePointerAcquire` | 原子交换一对指针值。操作使用获取内存排序语义执行。 |
| `InterlockedExchangePointerNoFence` | 原子交换一对地址。操作是原子执行的，但不使用内存屏障。 |
| `InterlockedExchangeSubtract` | 执行两个值的原子减法。 |
| `InterlockedExchangeAdd` | 执行两个 32 位值的原子加法。 |
| `InterlockedExchangeAddAcquire` | 执行两个 32 位值的原子加法。操作使用获取内存排序语义执行。 |
| `InterlockedExchangeAddRelease` | 执行两个 32 位值的原子加法。操作使用释放内存排序语义执行。 |
| `InterlockedExchangeAddNoFence` | 执行两个 32 位值的原子加法。操作是原子执行的，但不使用内存屏障。 |

增量功能包括：

| **Interlocked function** | **描述** |
| --- | --- |
| --- |
| `InterlockedIncrement` | 将指定的 32 位变量的值增加 1 作为原子操作。 |
| `InterlockedIncrementAcquire` | 将指定的 32 位变量的值增加 1 作为原子操作。操作使用获取内存排序语义执行。 |
| `InterlockedIncrementRelease` | 将指定的 32 位变量的值增加 1 作为原子操作。操作使用释放内存排序语义执行。 |
| `InterlockedIncrementNoFence` | 将指定的 32 位变量的值增加 1 作为原子操作。操作是原子执行的，但不使用内存屏障。 |

`OR`功能：

| **Interlocked function** | **描述** |
| --- | --- |
| --- |
| `InterlockedOr` | 对指定的`LONG`值执行原子`OR`操作。 |
| `InterlockedOrAcquire` | 对指定的`LONG`值执行原子`OR`操作。操作使用获取内存排序语义执行。 |
| `InterlockedOrRelease` | 对指定的`LONG`值执行原子`OR`操作。操作使用释放内存排序语义执行。 |
| `InterlockedOrNoFence` | 对指定的`LONG`值执行原子`OR`操作。操作是原子执行的，但不使用内存屏障。 |

最后，独占`OR`（`XOR`）功能包括：

| **Interlocked function** | **描述** |
| --- | --- |
| --- |
| `InterlockedXor` | 对指定的`LONG`值执行原子`XOR`操作。 |
| `InterlockedXorAcquire` | 对指定的`LONG`值执行原子`XOR`操作。操作使用获取内存排序语义执行。 |
| `InterlockedXorRelease` | 对指定的`LONG`值执行原子`XOR`操作。操作使用释放内存排序语义执行。 |
| `InterlockedXorNoFence` | 对指定的`LONG`值执行原子`XOR`操作。操作是原子执行的，但不使用内存屏障。 |

# GCC

与 Visual C++一样，GCC 也带有一组内置的原子函数。这些函数根据 GCC 版本和标准库的底层架构而异。由于 GCC 在许多平台和操作系统上的使用要比 VC++多得多，这在考虑可移植性时绝对是一个重要因素。

例如，在 x86 平台上提供的每个内置原子函数都可能不会在 ARM 上可用，部分原因是由于架构差异，包括特定 ARM 架构的变化。例如，ARMv6、ARMv7 或当前的 ARMv8，以及 Thumb 指令集等。

在 C++11 标准之前，GCC 使用`__sync-prefixed`扩展来进行原子操作：

```cpp
type __sync_fetch_and_add (type *ptr, type value, ...) 
type __sync_fetch_and_sub (type *ptr, type value, ...) 
type __sync_fetch_and_or (type *ptr, type value, ...) 
type __sync_fetch_and_and (type *ptr, type value, ...) 
type __sync_fetch_and_xor (type *ptr, type value, ...) 
type __sync_fetch_and_nand (type *ptr, type value, ...) 

```

这些操作从内存中获取一个值并对其执行指定操作，返回内存中的值。这些操作都使用内存屏障。

```cpp
type __sync_add_and_fetch (type *ptr, type value, ...) 
type __sync_sub_and_fetch (type *ptr, type value, ...) 
type __sync_or_and_fetch (type *ptr, type value, ...) 
type __sync_and_and_fetch (type *ptr, type value, ...) 
type __sync_xor_and_fetch (type *ptr, type value, ...) 
type __sync_nand_and_fetch (type *ptr, type value, ...) 

```

这些操作与第一组类似，只是在指定操作后返回新值。

```cpp
bool __sync_bool_compare_and_swap (type *ptr, type oldval, type newval, ...) 
type __sync_val_compare_and_swap (type *ptr, type oldval, type newval, ...) 

```

如果旧值与提供的值匹配，这些比较操作将写入新值。布尔变体在新值被写入时返回 true。

```cpp
__sync_synchronize (...) 

```

该函数创建一个完整的内存屏障。

```cpp
type __sync_lock_test_and_set (type *ptr, type value, ...) 

```

这种方法实际上是一种交换操作，与名称所示不同。它更新指针值并返回先前的值。这不使用完整的内存屏障，而是使用获取屏障，这意味着它不会释放屏障。

```cpp
void __sync_lock_release (type *ptr, ...) 

```

该函数释放了先前方法获得的屏障。

为了适应 C++11 内存模型，GCC 添加了`__atomic`内置方法，这也大大改变了 API：

```cpp
type __atomic_load_n (type *ptr, int memorder) 
void __atomic_load (type *ptr, type *ret, int memorder) 
void __atomic_store_n (type *ptr, type val, int memorder) 
void __atomic_store (type *ptr, type *val, int memorder) 
type __atomic_exchange_n (type *ptr, type val, int memorder) 
void __atomic_exchange (type *ptr, type *val, type *ret, int memorder) 
bool __atomic_compare_exchange_n (type *ptr, type *expected, type desired, bool weak, int success_memorder, int failure_memorder) 
bool __atomic_compare_exchange (type *ptr, type *expected, type *desired, bool weak, int success_memorder, int failure_memorder) 

```

首先是通用的加载、存储和交换函数。它们都相当容易理解。加载函数读取内存中的值，存储函数将值存储在内存中，交换函数将现有值与新值交换。比较和交换函数使交换有条件。

```cpp
type __atomic_add_fetch (type *ptr, type val, int memorder) 
type __atomic_sub_fetch (type *ptr, type val, int memorder) 
type __atomic_and_fetch (type *ptr, type val, int memorder) 
type __atomic_xor_fetch (type *ptr, type val, int memorder) 
type __atomic_or_fetch (type *ptr, type val, int memorder) 
type __atomic_nand_fetch (type *ptr, type val, int memorder) 

```

这些函数基本上与旧 API 中的函数相同，返回特定操作的结果。

```cpp
type __atomic_fetch_add (type *ptr, type val, int memorder) 
type __atomic_fetch_sub (type *ptr, type val, int memorder) 
type __atomic_fetch_and (type *ptr, type val, int memorder) 
type __atomic_fetch_xor (type *ptr, type val, int memorder) 
type __atomic_fetch_or (type *ptr, type val, int memorder) 
type __atomic_fetch_nand (type *ptr, type val, int memorder) 

```

再次，相同的函数，针对新 API 进行了更新。这些函数返回原始值（在操作之前获取）。

```cpp
bool __atomic_test_and_set (void *ptr, int memorder) 

```

与旧 API 中同名的函数不同，该函数执行的是真正的测试和设置操作，而不是旧 API 函数的交换操作，后者仍然需要在之后释放内存屏障。测试是针对某个定义的值。

```cpp
void __atomic_clear (bool *ptr, int memorder) 

```

该函数清除指针地址，将其设置为`0`。

```cpp
void __atomic_thread_fence (int memorder) 

```

可以使用该函数在线程之间创建同步内存屏障（栅栏）。

```cpp
void __atomic_signal_fence (int memorder) 

```

该函数在线程和同一线程内的信号处理程序之间创建内存屏障。

```cpp
bool __atomic_always_lock_free (size_t size, void *ptr) 

```

该函数检查指定大小的对象是否总是为当前处理器架构创建无锁原子指令。

```cpp
bool __atomic_is_lock_free (size_t size, void *ptr) 

```

这基本上与以前的函数相同。

# 内存顺序

在 C++11 内存模型中，并不总是使用内存屏障（栅栏）进行原子操作。在 GCC 内置的原子 API 中，这反映在其函数中的`memorder`参数中。此参数的可能值直接映射到 C++11 原子 API 中的值：

+   `__ATOMIC_RELAXED`：意味着没有线程间的排序约束。

+   `__ATOMIC_CONSUME`：由于 C++11 对`memory_order_consume`的语义存在缺陷，目前使用更强的`__ATOMIC_ACQUIRE`内存顺序来实现。

+   `__ATOMIC_ACQUIRE`：从释放（或更强）语义存储到此获取加载创建线程间的 happens-before 约束

+   `__ATOMIC_RELEASE`：创建一个线程间 happens-before 约束，以获取（或更强）语义加载，从此发布存储读取

+   `__ATOMIC_ACQ_REL`：结合了 `__ATOMIC_ACQUIRE` 和 `__ATOMIC_RELEASE` 的效果。

+   `__ATOMIC_SEQ_CST`：强制与所有其他 `__ATOMIC_SEQ_CST` 操作进行完全排序。

上述列表是从 GCC 手册的关于 GCC 7.1 版本原子的章节中复制的。连同该章节中的注释，这清楚地表明在实现 C++11 原子支持及编译器实现中都做出了权衡。

由于原子依赖于底层硬件支持，永远不会有一个使用原子的代码可以在各种架构上运行。

# 其他编译器

当然，C/C++ 有很多其他编译器工具链，不仅仅是 VC++ 和 GCC，包括英特尔编译器集合（ICC）和其他通常是专有工具。所有这些都有自己的内置原子函数集。幸运的是，由于 C++11 标准，我们现在在编译器之间有了一个完全可移植的原子标准。一般来说，这意味着除了非常特定的用例（或维护现有代码）之外，人们会使用 C++ 标准而不是特定于编译器的扩展。

# C++11 原子

为了使用本机 C++11 原子特性，所有人只需包含 `<atomic>` 头文件。这样就可以使用 `atomic` 类，它使用模板来使自己适应所需的类型，并具有大量预定义的 typedef：

| **类型定义名称** **完全特化** |
| --- |
| `std::atomic_bool` `std::atomic<bool>` |
| `std::atomic_char` `std::atomic<char>` |
| `std::atomic_schar` `std::atomic<signed char>` |
| `std::atomic_uchar` `std::atomic<unsigned char>` |
| `std::atomic_short` `std::atomic<short>` |
| `std::atomic_ushort` `std::atomic<unsigned short>` |
| `std::atomic_int` `std::atomic<int>` |
| `std::atomic_uint` `std::atomic<unsigned int>` |
| `std::atomic_long` `std::atomic<long>` |
| `std::atomic_ulong` `std::atomic<unsigned long>` |
| `std::atomic_llong` `std::atomic<long long>` |
| `std::atomic_ullong` `std::atomic<unsigned long long>` |
| `std::atomic_char16_t` `std::atomic<char16_t>` |
| `std::atomic_char32_t` `std::atomic<char32_t>` |
| `std::atomic_wchar_t` `std::atomic<wchar_t>` |
| `std::atomic_int8_t` `std::atomic<std::int8_t>` |
| `std::atomic_uint8_t` `std::atomic<std::uint8_t>` |
| `std::atomic_int16_t` `std::atomic<std::int16_t>` |
| `std::atomic_uint16_t` `std::atomic<std::uint16_t>` |
| `std::atomic_int32_t` `std::atomic<std::int32_t>` |
| `std::atomic_uint32_t` `std::atomic<std::uint32_t>` |
| `std::atomic_int64_t` `std::atomic<std::int64_t>` |
| `std::atomic_uint64_t` `std::atomic<std::uint64_t>` |
| `std::atomic_int_least8_t` `std::atomic<std::int_least8_t>` |
| `std::atomic_uint_least8_t` `std::atomic<std::uint_least8_t>` |
| `std::atomic_int_least16_t` `std::atomic<std::int_least16_t>` |
| `std::atomic_uint_least16_t` `std::atomic<std::uint_least16_t>` |
| `std::atomic_int_least32_t` `std::atomic<std::int_least32_t>` |
| `std::atomic_uint_least32_t` `std::atomic<std::uint_least32_t>` |
| `std::atomic_int_least64_t` `std::atomic<std::int_least64_t>` |
| `std::atomic_uint_least64_t` `std::atomic<std::uint_least64_t>` |
| `std::atomic_int_fast8_t` `std::atomic<std::int_fast8_t>` |
| `std::atomic_uint_fast8_t` `std::atomic<std::uint_fast8_t>` |
| `std::atomic_int_fast16_t` `std::atomic<std::int_fast16_t>` |
| `std::atomic_uint_fast16_t` `std::atomic<std::uint_fast16_t>` |
| `std::atomic_int_fast32_t` `std::atomic<std::int_fast32_t>` |
| `std::atomic_uint_fast32_t` `std::atomic<std::uint_fast32_t>` |
| `std::atomic_int_fast64_t` `std::atomic<std::int_fast64_t>` |
| `std::atomic_uint_fast64_t` `std::atomic<std::uint_fast64_t>` |
| `std::atomic_intptr_t` `std::atomic<std::intptr_t>` |
| `std::atomic_uintptr_t` | `std::atomic<std::uintptr_t>` |
| `std::atomic_size_t` | `std::atomic<std::size_t>` |
| `std::atomic_ptrdiff_t` | `std::atomic<std::ptrdiff_t>` |
| `std::atomic_intmax_t` | `std::atomic<std::intmax_t>` |
| `std::atomic_uintmax_t` | `std::atomic<std::uintmax_t>` |

这个`atomic`类定义了以下通用函数：

| **函数** | **描述** |
| --- | --- |
| `operator=` | 将值赋给原子对象。 |
| `is_lock_free` | 如果原子对象是无锁的，则返回 true。 |
| `store` | 用非原子参数原子地替换原子对象的值。 |
| `load` | 原子地获取原子对象的值。 |
| `operator T` | 从原子对象中加载值。 |
| `exchange` | 原子地用新值替换对象的值，并返回旧值。 |
| `compare_exchange_weak``compare_exchange_strong` | 原子地比较对象的值，如果相等则交换值，否则返回当前值。 |

使用 C++17 更新，添加了`is_always_lock_free`常量。这允许我们查询类型是否总是无锁。

最后，我们有专门的`atomic`函数：

| **函数** | **描述** |
| --- | --- |
| `fetch_add` | 原子地将参数添加到存储在`atomic`对象中的值，并返回旧值。 |
| `fetch_sub` | 原子地从存储在`atomic`对象中的值中减去参数并返回旧值。 |
| `fetch_and` | 原子地执行参数和`atomic`对象的值之间的按位`AND`操作，并返回旧值。 |
| `fetch_or` | 原子地执行参数和`atomic`对象的值之间的按位`OR`操作，并返回旧值。 |
| `fetch_xor` | 原子地执行参数和`atomic`对象的值之间的按位`XOR`操作，并返回旧值。 |
| `operator++``operator++(int)``operator--``operator--(int)` | 将原子值增加或减少一。 |
| `operator+=``operator-=``operator&=``operator&#124;=``operator^=` | 增加、减少或执行按位`AND`、`OR`、`XOR`操作与原子值。 |

# 示例

使用`fetch_add`的基本示例如下：

```cpp
#include <iostream> 
#include <thread> 
#include <atomic> 

std::atomic<long long> count; 
void worker() { 
         count.fetch_add(1, std::memory_order_relaxed); 
} 

int main() { 
         std::thread t1(worker); 
         std::thread t2(worker); 
         std::thread t3(worker); 
         std::thread t4(worker); 
         std::thread t5(worker); 

         t1.join(); 
         t2.join(); 
         t3.join(); 
         t4.join(); 
         t5.join(); 

         std::cout << "Count value:" << count << '\n'; 
} 

```

这个示例代码的结果将是`5`。正如我们在这里看到的，我们可以用原子方式实现一个基本的计数器，而不必使用任何互斥锁或类似的东西来提供线程同步。

# 非类函数

除了`atomic`类之外，在`<atomic>`头文件中还定义了许多基于模板的函数，我们可以以更类似于编译器内置的原子函数的方式使用。 

| **函数** | **描述** |
| --- | --- |
| `atomic_is_lock_free` | 检查原子类型的操作是否是无锁的。 |
| `atomic_storeatomic_store_explicit` | 原子地用非原子参数替换`atomic`对象的值。 |
| `atomic_load``atomic_load_explicit` | 原子地获取存储在`atomic`对象中的值。 |
| `atomic_exchange``atomic_exchange_explicit` | 原子地用非原子参数替换`atomic`对象的值，并返回`atomic`的旧值。 |
| `atomic_compare_exchange_weak``atomic_compare_exchange_weak_explicit``atomic_compare_exchange_strong``atomic_compare_exchange_strong_explicit` | 原子地比较`atomic`对象的值与非原子参数，并在相等时执行原子交换，否则执行原子加载。 |
| `atomic_fetch_add``atomic_fetch_add_explicit` | 将非原子值添加到`atomic`对象中并获取`atomic`的先前值。 |
| `atomic_fetch_sub``atomic_fetch_sub_explicit` | 从`atomic`对象中减去非原子值并获取`atomic`的先前值。 |
| `atomic_fetch_and``atomic_fetch_and_explicit` | 用非原子参数的逻辑`AND`结果替换`atomic`对象，并获取原子的先前值。 |
| `atomic_fetch_or``atomic_fetch_or_explicit` | 用非原子参数的逻辑`OR`结果替换`atomic`对象，并获取`atomic`的先前值。 |
| `atomic_fetch_xor``atomic_fetch_xor_explicit` | 用非原子参数的逻辑`XOR`结果替换`atomic`对象，并获取`atomic`的先前值。 |
| `atomic_flag_test_and_set``atomic_flag_test_and_set_explicit` | 原子地将标志设置为`true`并返回其先前的值。 |
| `atomic_flag_clear``atomic_flag_clear_explicit` | 原子地将标志的值设置为`false`。 |
| `atomic_init` | 默认构造的`atomic`对象的非原子初始化。 |
| `kill_dependency` | 从`std::memory_order_consume`依赖树中移除指定的对象。 |
| `atomic_thread_fence` | 通用的内存顺序相关的栅栏同步原语。 |
| `atomic_signal_fence` | 线程和在同一线程中执行的信号处理程序之间的栅栏。 |

常规和显式函数之间的区别在于后者允许设置要使用的内存顺序。前者总是使用`memory_order_seq_cst`作为内存顺序。

# 例子

在这个使用`atomic_fetch_sub`的例子中，一个索引容器被多个线程同时处理，而不使用锁：

```cpp
#include <string> 
#include <thread> 
#include <vector> 
#include <iostream> 
#include <atomic> 
#include <numeric> 

const int N = 10000; 
std::atomic<int> cnt; 
std::vector<int> data(N); 

void reader(int id) { 
         for (;;) { 
               int idx = atomic_fetch_sub_explicit(&cnt, 1, std::memory_order_relaxed); 
               if (idx >= 0) { 
                           std::cout << "reader " << std::to_string(id) << " processed item " 
                                       << std::to_string(data[idx]) << '\n'; 
               }  
         else { 
                           std::cout << "reader " << std::to_string(id) << " done.\n"; 
                           break; 
               } 
         } 
} 

int main() { 
         std::iota(data.begin(), data.end(), 1); 
         cnt = data.size() - 1; 

         std::vector<std::thread> v; 
         for (int n = 0; n < 10; ++n) { 
               v.emplace_back(reader, n); 
         } 

         for (std::thread& t : v) { 
               t.join(); 
         } 
} 

```

这个例子代码使用了一个大小为*N*的整数向量作为数据源，用 1 填充它。原子计数器对象设置为数据向量的大小。之后，创建了 10 个线程（使用向量的`emplace_back` C++11 特性在原地初始化），运行`reader`函数。

在那个函数中，我们使用`atomic_fetch_sub_explicit`函数从内存中读取索引计数器的当前值，这使我们能够使用`memory_order_relaxed`内存顺序。这个函数还从这个旧值中减去我们传递的值，将索引减少 1。

只要我们以这种方式获得的索引号大于或等于零，函数就会继续，否则它将退出。一旦所有线程都完成，应用程序就会退出。

# 原子标志

`std::atomic_flag`是一种原子布尔类型。与`atomic`类的其他特化不同，它保证是无锁的。但它不提供任何加载或存储操作。

相反，它提供了赋值运算符，并提供了清除或`test_and_set`标志的函数。前者将标志设置为`false`，后者将测试并将其设置为`true`。

# 内存顺序

这个属性在`<atomic>`头文件中被定义为一个枚举：

```cpp
enum memory_order { 
    memory_order_relaxed, 
    memory_order_consume, 
    memory_order_acquire, 
    memory_order_release, 
    memory_order_acq_rel, 
    memory_order_seq_cst 
}; 

```

在 GCC 部分，我们已经简要涉及了内存顺序的主题。如前所述，这是底层硬件架构特性的一部分。

基本上，内存顺序决定了如何对原子操作周围的非原子内存访问进行排序（内存访问顺序）。这会影响不同线程在执行其指令时如何看到内存中的数据：

| **枚举** | **描述** |
| --- | --- |
| `memory_order_relaxed` | 松散操作：对其他读取或写入没有同步或排序约束，只保证了这个操作的原子性。 |
| `memory_order_consume` | 具有这个内存顺序的加载操作在受影响的内存位置上执行*consume 操作*：当前加载之前不能对当前线程中依赖当前加载的值的读取或写入进行重新排序。释放相同原子变量的其他线程对数据相关变量的写入在当前线程中可见。在大多数平台上，这只影响编译器优化。 |
| `memory_order_acquire` | 具有这种内存顺序的加载操作在受影响的内存位置上执行*获取操作*：在此加载之前，当前线程中的任何读取或写入都不能被重新排序。释放相同原子变量的其他线程中的所有写入在当前线程中是可见的。 |
| `memory_order_release` | 具有这种内存顺序的存储操作执行*释放操作*：在此存储之后，当前线程中的任何读取或写入都不能被重新排序。当前线程中的所有写入对于获取相同原子变量的其他线程是可见的，并且对原子变量进行依赖的写入对于消费相同原子的其他线程是可见的。 |
| `memory_order_acq_rel` | 具有这种内存顺序的读取-修改-写入操作既是*获取操作*又是*释放操作*。当前线程中的任何内存读取或写入都不能在此存储之前或之后重新排序。释放相同原子变量的其他线程中的所有写入在修改之前可见，并且在获取相同原子变量的其他线程中修改是可见的。 |
| `memory_order_seq_cst` | 具有这种内存顺序的任何操作既是*获取操作*又是*释放操作*，并且存在一个单一的总顺序，所有线程以相同的顺序观察到所有修改。 |

# 松散排序

在松散内存排序中，不对并发内存访问强制执行任何顺序。这种类型的排序仅保证原子性和修改顺序。

这种类型的排序的典型用途是用于计数器，无论是递增还是递减，就像我们在上一节的示例代码中看到的那样。

# 释放-获取排序

如果线程 A 中的原子存储被标记为`memory_order_release`，并且线程 B 中从相同变量的原子加载被标记为`memory_order_acquire`，则从线程 A 的视角来看，所有在原子存储之前发生的内存写入（非原子和松散原子）都会在线程 B 中变为*可见副作用*。也就是说，一旦原子加载完成，线程 B 将保证看到线程 A 写入内存的所有内容。

这种类型的操作在所谓的强排序架构上是自动的，包括 x86、SPARC 和 POWER。弱排序架构，如 ARM、PowerPC 和 Itanium，将需要在这里使用内存屏障。

这种类型的内存排序的典型应用包括互斥机制，如互斥锁或原子自旋锁。

# 释放-获取排序

如果线程 A 中的原子存储被标记为`memory_order_release`，并且线程 B 中从相同变量的原子加载被标记为`memory_order_consume`，则从线程 A 的视角来看，所有在原子存储之前*依赖排序*的内存写入（非原子和松散原子）都会在线程 B 的操作中变为*可见副作用*，这些操作使用了从加载操作中获得的值。也就是说，一旦原子加载完成，线程 B 中使用从加载中获得的值的运算符和函数将保证看到线程 A 写入内存的内容。

这种类型的排序在几乎所有架构上都是自动的。唯一的主要例外是（过时的）Alpha 架构。这种类型排序的典型用例是对很少更改的数据进行读取访问。

截至 C++17，这种内存排序正在进行修订，暂时不鼓励使用`memory_order_consume`。

# 顺序一致性排序

标记为`memory_order_seq_cst`的原子操作不仅以与释放-获取排序相同的方式对内存进行排序（在一个线程中存储之前发生的所有事情都成为*可见副作用*在执行加载的线程中），而且还建立了所有标记为这种方式的原子操作的*单一总修改顺序*。

这种排序可能在所有消费者必须以完全相同的顺序观察其他线程所做的更改的情况下是必要的。这会导致在多核或多 CPU 系统上需要完整的内存屏障。

由于这种复杂的设置，这种排序比其他类型要慢得多。它还要求每个原子操作都必须带有这种类型的内存排序标记，否则顺序排序将会丢失。

# Volatile 关键字

`volatile`关键字对于任何曾经编写过复杂多线程代码的人来说可能非常熟悉。它的基本用途是告诉编译器相关变量应始终从内存中加载，不要对其值进行任何假设。它还确保编译器不会对变量进行任何激进的优化。

对于多线程应用程序来说，它通常是无效的，因此不建议使用。`volatile`关键字的主要问题在于它没有定义多线程内存模型，这意味着这个关键字的结果可能在不同平台、CPU 甚至工具链上都不确定。

在原子操作领域，不需要使用这个关键字，事实上，使用它可能并不会有帮助。为了确保获取在多个 CPU 核心和它们的缓存之间共享的变量的当前版本，必须使用像`atomic_compare_exchange_strong`、`atomic_fetch_add`或`atomic_exchange`这样的操作，让硬件获取正确和当前的值。

对于多线程代码，建议不要使用`volatile`关键字，而是使用原子操作来保证正确的行为。

# 总结

在本章中，我们看了原子操作以及它们是如何被集成到编译器中的，以使代码尽可能地与底层硬件配合。读者现在将熟悉原子操作的类型、内存屏障（fencing）的使用，以及各种内存排序及其影响。

读者现在能够在自己的代码中使用原子操作来实现无锁设计，并正确使用 C++11 内存模型。

在下一章中，我们将把迄今为止学到的一切都放在一起，远离 CPU，转而看看 GPGPU，即在显卡（GPU）上对数据进行通用处理。


# 第九章：多线程与分布式计算

分布式计算是多线程编程的最初应用之一。在每台个人计算机只包含单个处理器和单个核心的时代，政府和研究机构，以及一些公司会拥有多处理器系统，通常是集群的形式。它们可以进行多线程处理；通过在处理器之间分割任务，它们可以加速各种任务，包括模拟、CGI 电影渲染等。

如今，几乎每台桌面级或更高级别的系统都有多个处理器核心，并且使用廉价的以太网布线很容易将多台系统组装成一个集群。结合 OpenMP 和 Open MPI 等框架，很容易将基于 C++（多线程）的应用程序扩展到分布式系统上运行。

本章的主题包括：

+   在多线程 C++应用程序中集成 OpenMP 和 MPI

+   实现分布式、多线程应用程序

+   分布式、多线程编程的常见应用和问题

# 分布式计算，简而言之

当涉及并行处理大型数据集时，如果能够将数据分割成许多小部分，并将其推送到许多线程中，从而显著缩短处理所述数据的总时间，那将是理想的。

分布式计算的理念正是这样：在分布式系统的每个节点上运行我们的应用程序的一个或多个实例，这个应用程序可以是单线程或多线程。由于进程间通信的开销，使用多线程应用程序通常更有效，也由于其他可能的优化--由于资源共享。

如果已经有一个多线程应用程序准备好使用，那么可以直接使用 MPI 使其在分布式系统上运行。否则，OpenMP 是一个编译器扩展（用于 C/C++和 Fortran），可以相对轻松地使应用程序成为多线程，而无需重构。

为了做到这一点，OpenMP 允许标记一个通用的代码段，以便在所有从属线程上执行。主线程创建了一些从属线程，它们将同时处理相同的代码段。一个基本的“Hello World” OpenMP 应用程序看起来像这样：

```cpp
/******************************************************************************
 * FILE: omp_hello.c
 * DESCRIPTION:
 *   OpenMP Example - Hello World - C/C++ Version
 *   In this simple example, the master thread forks a parallel region.
 *   All threads in the team obtain their unique thread number and print it.
 *   The master thread only prints the total number of threads.  Two OpenMP
 *   library routines are used to obtain the number of threads and each
 *   thread's number.
 * AUTHOR: Blaise Barney  5/99
 * LAST REVISED: 04/06/05
 ******************************************************************************/
 #include <omp.h>
 #include <stdio.h>
 #include <stdlib.h>

 int main (int argc, char *argv[])  {
    int nthreads, tid;

    /* Fork a team of threads giving them their own copies of variables */
 #pragma omp parallel private(nthreads, tid) {
          /* Obtain thread number */
          tid = omp_get_thread_num();
          printf("Hello World from thread = %d\n", tid);

          /* Only master thread does this */
          if (tid == 0) {
                nthreads = omp_get_num_threads();
                printf("Number of threads = %d\n", nthreads);
                }

    }  /* All threads join master thread and disband */ 
} 

```

从这个基本示例中可以很容易地看出，OpenMP 通过`<omp.h>`头文件提供了一个基于 C 的 API。我们还可以看到每个线程将执行的部分，由`#pragma omp`预处理宏标记。

与我们在前面章节中看到的多线程代码示例相比，OpenMP 的优势在于可以轻松地将代码部分标记为多线程，而无需进行任何实际的代码更改。这带来的明显限制是，每个线程实例将执行完全相同的代码，并且进一步的优化选项有限。

# MPI

为了在特定节点上安排代码的执行，通常使用**MPI**（消息传递接口）。Open MPI 是这种的免费库实现，被许多高级超级计算机使用。MPICH 是另一个流行的实现。

MPI 本身被定义为并行计算编程的通信协议。它目前处于第三个修订版（MPI-3）。

总之，MPI 提供了以下基本概念：

+   通信器：通信器对象连接了 MPI 会话中的一组进程。它为进程分配唯一标识符，并在有序拓扑中安排进程。

+   点对点操作：这种操作允许特定进程之间直接通信。

+   **集体函数**：这些函数涉及在一个进程组内进行广播通信。它们也可以以相反的方式使用，从一个组中的所有进程获取结果，并且例如在单个节点上对它们进行求和。更有选择性的版本将确保特定的数据项被发送到特定的节点。

+   **派生数据类型**：由于 MPI 集群中的每个节点都不能保证具有相同的定义、字节顺序和数据类型的解释，MPI 要求指定每个数据段的类型，以便 MPI 可以进行数据转换。

+   **单边通信**：这些操作允许在远程内存中写入或读取，或者在多个任务之间执行归约操作，而无需在任务之间进行同步。这对于某些类型的算法非常有用，比如涉及分布式矩阵乘法的算法。

+   **动态进程管理**：这是一个功能，允许 MPI 进程创建新的 MPI 进程，或者与新创建的 MPI 进程建立通信。

+   **并行 I/O**：也称为 MPI-IO，这是分布式系统上 I/O 管理的抽象，包括文件访问，方便与 MPI 一起使用。

其中，MPI-IO、动态进程管理和单边通信是 MPI-2 的特性。从基于 MPI-1 的代码迁移以及动态进程管理与某些设置不兼容，以及许多应用程序不需要 MPI-2 的特性，意味着 MPI-2 的采用相对较慢。

# 实现

MPI 的最初实现是**MPICH**，由**阿贡国家实验室**（**ANL**）和密西西比州立大学开发。它目前是最受欢迎的实现之一，被用作 MPI 实现的基础，包括 IBM（蓝色基因）、英特尔、QLogic、Cray、Myricom、微软、俄亥俄州立大学（MVAPICH）等的 MPI 实现。

另一个非常常见的实现是 Open MPI，它是由三个 MPI 实现合并而成的：

+   FT-MPI（田纳西大学）

+   LA-MPI（洛斯阿拉莫斯国家实验室）

+   LAM/MPI（印第安纳大学）

这些，以及斯图加特大学的 PACX-MPI 团队，是 Open MPI 团队的创始成员。Open MPI 的主要目标之一是创建一个高质量的开源 MPI-3 实现。

MPI 实现必须支持 C 和 Fortran。C/C++和 Fortran 以及汇编支持非常普遍，还有其他语言的绑定。

# 使用 MPI

无论选择哪种实现，最终的 API 都将始终符合官方 MPI 标准，只有选择的库支持的 MPI 版本会有所不同。任何 MPI 实现都应该支持所有 MPI-1（修订版 1.3）的特性。

这意味着规范的 Hello World（例如，在 MPI 教程网站上找到的[`mpitutorial.com/tutorials/mpi-hello-world/`](http://mpitutorial.com/tutorials/mpi-hello-world/)）对于 MPI 应该在选择哪个库时都能工作：

```cpp
#include <mpi.h> 
#include <stdio.h> 

int main(int argc, char** argv) { 
         // Initialize the MPI environment 
         MPI_Init(NULL, NULL); 

         // Get the number of processes 
         int world_size; 
         MPI_Comm_size(MPI_COMM_WORLD, &world_size); 

         // Get the rank of the process 
         int world_rank; 
         MPI_Comm_rank(MPI_COMM_WORLD, &world_rank); 

         // Get the name of the processor 
         char processor_name[MPI_MAX_PROCESSOR_NAME]; 
         int name_len; 
         MPI_Get_processor_name(processor_name, &name_len); 

         // Print off a hello world message 
         printf("Hello world from processor %s, rank %d" 
                     " out of %d processors\n", 
                     processor_name, world_rank, world_size); 

         // Finalize the MPI environment. 
         MPI_Finalize(); 
} 

```

阅读这个基于 MPI 的应用程序的基本示例时，熟悉 MPI 使用的术语非常重要，特别是：

+   **World**：此作业的注册 MPI 进程

+   **通信器**：连接会话中所有 MPI 进程的对象

+   **秩**：通信器内进程的标识符

+   **处理器**：物理 CPU，多核 CPU 的单个核心，或系统的主机名

在这个 Hello World 的例子中，我们可以看到我们包含了`<mpi.h>`头文件。这个 MPI 头文件将始终相同，无论我们使用哪种实现。

初始化 MPI 环境只需要调用一次`MPI_Init()`，这个调用可以有两个参数，但在这一点上都是可选的。

接下来是获取世界的大小（即可用进程数）。这是使用`MPI_Comm_size()`完成的，它接受`MPI_COMM_WORLD`全局变量（由 MPI 定义供我们使用）并使用第二个参数更新该世界中的进程数。

然后我们获得的等级基本上是 MPI 分配给此进程的唯一 ID。获取此 UID 是使用`MPI_Comm_rank()`执行的。同样，这需要`MPI_COMM_WORLD`变量作为第一个参数，并将我们的数字等级作为第二个参数返回。此等级对于自我识别和进程之间的通信很有用。

获取正在运行的特定硬件的名称也可能很有用，特别是用于诊断目的。为此，我们可以调用`MPI_Get_processor_name()`。返回的字符串将具有全局定义的最大长度，并且将以某种方式标识硬件。该字符串的确切格式由实现定义。

最后，我们打印出我们收集的信息，并在终止应用程序之前清理 MPI 环境。

# 编译 MPI 应用程序

为了编译 MPI 应用程序，使用`mpicc`编译器包装器。这个可执行文件应该是已安装的任何 MPI 实现的一部分。

然而，使用它与使用例如 GCC 完全相同：

```cpp
    $ mpicc -o mpi_hello_world mpi_hello_world.c

```

这可以与以下进行比较：

```cpp
    $ gcc mpi_hello_world.c -lmsmpi -o mpi_hello_world

```

这将把我们的 Hello World 示例编译和链接成一个二进制文件，准备执行。然而，执行此二进制文件不是直接启动它，而是使用启动器，如下所示：

```cpp
    $ mpiexec.exe -n 4 mpi_hello_world.exe
    Hello world from processor Generic_PC, rank 0 out of 4 processors
    Hello world from processor Generic_PC, rank 2 out of 4 processors
    Hello world from processor Generic_PC, rank 1 out of 4 processors
    Hello world from processor Generic_PC, rank 3 out of 4 processors

```

前面的输出来自在 Windows 系统上运行的 Bash shell 中的 Open MPI。正如我们所看到的，总共启动了四个进程（4 个等级）。每个进程的处理器名称报告为主机名（“PC”）。

用于启动 MPI 应用程序的二进制文件称为 mpiexec 或 mpirun，或者 orterun。这些是相同二进制文件的同义词，尽管并非所有实现都具有所有同义词。对于 Open MPI，所有三者都存在，可以使用其中任何一个。

# 集群硬件

MPI 基于或类似应用程序将运行的系统由多个独立系统（节点）组成，每个系统都使用某种网络接口连接到其他系统。对于高端应用程序，这些往往是具有高速、低延迟互连的定制节点。在光谱的另一端是所谓的 Beowulf 和类似类型的集群，由标准（台式）计算机组成，通常使用常规以太网连接。

在撰写本文时，根据 TOP500 榜单，最快的超级计算机是中国无锡国家超级计算中心的 Sunway TaihuLight 超级计算机。它使用了总共 40960 个中国设计的 SW26010 多核 RISC 架构 CPU，每个 CPU 有 256 个核心（分为 4 个 64 核心组），以及四个管理核心。术语“多核”是指一种专门的 CPU 设计，它更注重显式并行性，而不是大多数 CPU 核心的单线程和通用重点。这种类型的 CPU 类似于 GPU 架构和矢量处理器。

每个节点都包含一个 SW26010 和 32GB 的 DDR3 内存。它们通过基于 PCIe 3.0 的网络连接，本身由三级层次结构组成：中央交换网络（用于超级节点），超级节点网络（连接超级节点中的所有 256 个节点）和资源网络，提供对 I/O 和其他资源服务的访问。节点之间的网络带宽为 12GB/秒，延迟约为 1 微秒。

以下图表（来自“Sunway TaihuLight 超级计算机：系统和应用”，DOI：10.1007/s11432-016-5588-7）提供了该系统的视觉概述：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00023.jpeg)

对于预算不允许这样一个复杂和高度定制的系统的情况，或者特定任务不需要这样的方法的情况，总是可以采用“Beowulf”方法。Beowulf 集群是指由普通计算机系统构建的分布式计算系统。这些可以是基于 Intel 或 AMD 的 x86 系统，现在也变得流行的是基于 ARM 的处理器。

通常有助于使集群中的每个节点与其他节点大致相同。虽然可能有不对称的集群，但当可以对每个节点进行广泛的假设时，管理和作业调度变得更加容易。

至少，希望匹配处理器架构，具有一定级别的 CPU 扩展，如 SSE2/3，也许还有 AVX 等，这些在所有节点上都是通用的。这样做可以让我们在节点上使用相同的编译二进制文件，以及相同的算法，大大简化作业的部署和代码库的维护。

对于节点之间的网络，以太网是一个非常受欢迎的选择，通信时间以十到几百微秒计，成本只是更快选项的一小部分。通常，每个节点都会连接到一个单独的以太网网络，就像这张图中的情况：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00024.jpeg)

还有一个选择，就是为每个或特定节点添加第二甚至第三个以太网链接，以便它们可以访问文件、I/O 和其他资源，而无需在主要网络层上竞争带宽。对于非常大的集群，可以考虑一种类似于 Sunway TaihuLight 和许多其他超级计算机所使用的方法：将节点分割成超级节点，每个节点都有自己的节点间网络。这将允许通过将流量限制在相关节点上来优化网络流量。

一个优化的 Beowulf 集群的示例如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00025.gif)

很明显，基于 MPI 的集群有各种可能的配置，可以利用定制的、现成的，或两种类型硬件的组合。集群的预期用途通常决定了特定集群的最佳布局，比如运行模拟，或处理大型数据集。每种类型的作业都有自己的一系列限制和要求，这也反映在软件实现中。

# 安装 Open MPI

在本章的其余部分，我们将专注于 Open MPI。为了获得 Open MPI 的工作开发环境，需要安装其头文件和库文件，以及支持工具和二进制文件。

# Linux 和 BSD

在具有软件包管理系统的 Linux 和 BSD 发行版上，这很容易：只需安装 Open MPI 软件包，一切都应该设置和配置好，准备好使用。查阅特定发行版的手册，了解如何搜索和安装特定软件包。

在基于 Debian 的发行版上，可以使用：

```cpp
    $ sudo apt-get install openmpi-bin openmpi-doc libopenmpi-dev

```

上述命令将安装 Open MPI 二进制文件、文档和开发头文件。最后两个软件包可以在计算节点上省略。

# Windows

在 Windows 上情况会稍微复杂一些，主要是因为 Visual C++和相关的编译器工具链的主导地位。如果希望在 Linux 或 BSD 上使用 MinGW 作为开发环境，就需要采取一些额外的步骤。

本章假设使用 GCC 或 MinGW。如果希望在 Visual Studio 环境下开发 MPI 应用程序，请查阅相关文档。

最容易使用和最新的 MinGW 环境是 MSYS2，它提供了一个 Bash shell，以及大多数在 Linux 和 BSD 下熟悉的工具。它还配备了 Pacman 软件包管理器，就像 Linux Arch 发行版中所知的那样。使用这个环境，很容易安装 Open MPI 开发所需的软件包。

从[`msys2.github.io/`](https://msys2.github.io/)安装 MSYS2 环境后，安装 MinGW 工具链：

```cpp
    $ pacman -S base-devel mingw-w64-x86_64-toolchain

```

这假设安装了 64 位版本的 MSYS2。对于 32 位版本，选择 i686 而不是 x86_64。安装这些软件包后，我们将安装 MinGW 和基本开发工具。为了使用它们，使用 MinGW 64 位后缀的名称启动一个新的 shell，可以通过开始菜单中的快捷方式，或者通过 MSYS2 `install`文件夹中的可执行文件来启动。

准备好 MinGW 后，现在是时候安装 MS-MPI 版本 7.x 了。这是微软在 Windows 上使用 MPI 的最简单的方法。它是 MPI-2 规范的实现，与 MPICH2 参考实现大部分兼容。由于 MS-MPI 库在不同版本之间不兼容，我们使用这个特定的版本。

尽管 MS-MPI 的第 7 版已被存档，但仍可以通过 Microsoft 下载中心下载，网址为[`www.microsoft.com/en-us/download/details.aspx?id=49926`](https://www.microsoft.com/en-us/download/details.aspx?id=49926)。

MS-MPI 版本 7 带有两个安装程序，`msmpisdk.msi`和`MSMpiSetup.exe`。都需要安装。之后，我们应该能够打开一个新的 MSYS2 shell，并找到以下环境变量设置：

```cpp
    $ printenv | grep "WIN\|MSMPI"
    MSMPI_INC=D:\Dev\MicrosoftSDKs\MPI\Include\
    MSMPI_LIB32=D:\Dev\MicrosoftSDKs\MPI\Lib\x86\
    MSMPI_LIB64=D:\Dev\MicrosoftSDKs\MPI\Lib\x64\
    WINDIR=C:\Windows

```

printenv 命令的输出显示 MS-MPI SDK 和运行时已正确安装。接下来，我们需要将静态库从 Visual C++ LIB 格式转换为 MinGW A 格式：

```cpp
    $ mkdir ~/msmpi
    $ cd ~/msmpi
    $ cp "$MSMPI_LIB64/msmpi.lib" .
    $ cp "$WINDIR/system32/msmpi.dll" .
    $ gendef msmpi.dll
    $ dlltool -d msmpi.def -D msmpi.dll -l libmsmpi.a
    $ cp libmsmpi.a /mingw64/lib/.

```

首先，我们将原始 LIB 文件复制到我们的主文件夹中的一个新临时文件夹中，以及运行时 DLL。接下来，我们使用 DLL 上的 gendef 工具来创建我们需要的定义，以便将其转换为新格式。

这最后一步是使用 dlltool 完成的，它接受定义文件和 DLL，并输出一个与 MinGW 兼容的静态库文件。然后我们将这个文件复制到 MinGW 在链接时可以找到的位置。

接下来，我们需要复制 MPI 头文件：

```cpp
    $ cp "$MSMPI_INC/mpi.h" .

```

复制完这个头文件后，我们必须打开它并找到以下部分的开头：

```cpp
typedef __int64 MPI_Aint 

```

在那一行的上面，我们需要添加以下行：

```cpp
    #include <stdint.h>

```

这个包含了`__int64`的定义，这是我们在代码中需要为了正确编译。

最后，将头文件复制到 MinGW 的`include`文件夹中：

```cpp
    $ cp mpi.h /mingw64/include

```

现在我们已经准备好了用 MinGW 进行 MPI 开发所需的库和头文件，可以编译和运行之前的 Hello World 示例，并继续本章的其余部分。

# 跨节点分发作业

为了在集群中的节点之间分发 MPI 作业，必须将这些节点作为`mpirun`/`mpiexec`命令的参数指定，或者使用主机文件。这个主机文件包含网络上将用于运行的节点的名称，以及主机上可用插槽的数量。

在远程节点上运行 MPI 应用程序的先决条件是在该节点上安装了 MPI 运行时，并且已为该节点配置了无密码访问。这意味着只要主节点安装了 SSH 密钥，它就可以登录到每个节点上以在其上启动 MPI 应用程序。

# 设置 MPI 节点

在节点上安装 MPI 后，下一步是为主节点设置无密码 SSH 访问。这需要在节点上安装 SSH 服务器（在基于 Debian 的发行版中是*ssh*软件包的一部分）。之后我们需要生成并安装 SSH 密钥。

一个简单的方法是在主节点和其他节点上都有一个共同的用户，并使用 NFS 网络共享或类似的方式在计算节点上挂载主节点上的用户文件夹。这样所有节点都将拥有相同的 SSH 密钥和已知主机文件。这种方法的一个缺点是缺乏安全性。对于连接到互联网的集群，这不是一个很好的方法。

然而，确实很明智的做法是以相同的用户在每个节点上运行作业，以防止可能出现的权限问题，特别是在使用文件和其他资源时。通过在每个节点上创建一个公共用户帐户，并生成 SSH 密钥，我们可以使用以下命令将公钥传输到节点上：

```cpp
    $ ssh-copy-id mpiuser@node1

```

或者，我们可以在设置节点时将公钥复制到节点系统上的`authorized_keys`文件中。如果要创建和配置大量节点，最好使用一个镜像复制到每个节点的系统驱动器上，使用设置脚本，或者可能通过 PXE 引导从镜像引导。

完成了这一步，主节点现在可以登录到每个计算节点上运行作业。

# 创建 MPI 主机文件

如前所述，为了在其他节点上运行作业，我们需要指定这些节点。最简单的方法是创建一个文件，其中包含我们希望使用的计算节点的名称，以及可选参数。

为了让我们能够使用节点的名称而不是 IP 地址，我们首先必须修改操作系统的主机文件：例如，在 Linux 上是`/etc/hosts`：

```cpp
    192.168.0.1 master
    192.168.0.2 node0
    192.168.0.3 node1

```

接下来我们创建一个新文件，这将是用于 MPI 的主机文件：

```cpp
    master
    node0
    node1

```

有了这个配置，作业将在计算节点和主节点上执行。我们可以从这个文件中删除主节点以防止这种情况发生。

如果没有提供任何可选参数，MPI 运行时将使用节点上的所有可用处理器。如果需要，我们可以限制这个数字：

```cpp
    node0 slots=2
    node1 slots=4

```

假设两个节点都是四核 CPU，这意味着只有 node0 上的一半核心会被使用，而 node1 上的所有核心都会被使用。

# 运行作业

在多个 MPI 节点上运行 MPI 作业基本上与仅在本地执行相同，就像本章前面的示例一样：

```cpp
    $ mpirun --hostfile my_hostfile hello_mpi_world

```

这个命令将告诉 MPI 启动器使用一个名为`my_hostfile`的主机文件，并在该主机文件中找到的每个节点的每个处理器上运行指定的 MPI 应用程序的副本。

# 使用集群调度程序

除了使用手动命令和主机文件在特定节点上创建和启动作业之外，还有集群调度程序应用程序。这些通常涉及在每个节点以及主节点上运行一个守护进程。使用提供的工具，可以管理资源和作业，安排分配并跟踪作业状态。

最流行的集群管理调度程序之一是 SLURM，它是 Simple Linux Utility for Resource management 的缩写（尽管现在更名为 Slurm Workload Manager，网站是[`slurm.schedmd.com/`](https://slurm.schedmd.com/)）。它通常被超级计算机以及许多计算机集群使用。其主要功能包括：

+   为特定用户分配对资源（节点）的独占或非独占访问权限，使用时间段

+   在一组节点上启动和监视作业，例如基于 MPI 的应用程序

+   管理挂起作业的队列，以调解对共享资源的争用

设置集群调度程序对于基本的集群操作并不是必需的，但对于更大的集群、同时运行多个作业或希望运行自己的作业的多个用户来说，它可能非常有用。

# MPI 通信

在这一点上，我们有一个功能齐全的 MPI 集群，可以用来并行执行基于 MPI 的应用程序（以及其他应用程序）。虽然对于一些任务来说，只需发送几十个或几百个进程并等待它们完成可能是可以的，但很多时候，这些并行进程能够相互通信是至关重要的。

这就是 MPI（即“消息传递接口”）的真正意义所在。在 MPI 作业创建的层次结构中，进程可以以各种方式进行通信和共享数据。最基本的是，它们可以共享和接收消息。

MPI 消息具有以下属性：

+   一个发送者

+   一个接收者

+   消息标签（ID）

+   消息中的元素计数

+   MPI 数据类型

发送方和接收方应该是相当明显的。消息标签是发送方可以设置的数字 ID，接收方可以使用它来过滤消息，例如，允许对特定消息进行优先处理。数据类型确定消息中包含的信息的类型。

发送和接收函数如下所示：

```cpp
int MPI_Send( 
         void* data, 
         int count, 
         MPI_Datatype datatype, 
         int destination, 
         int tag, 
         MPI_Comm communicator) 

int MPI_Recv( 
         void* data, 
         int count, 
         MPI_Datatype datatype, 
         int source, 
         int tag, 
         MPI_Comm communicator, 
         MPI_Status* status) 

```

这里需要注意的有趣的事情是，发送函数中的计数参数指示函数将发送的元素数，而接收函数中的相同参数指示此线程将接受的最大元素数。

通信器指的是正在使用的 MPI 通信器实例，接收函数包含一个最终参数，可以用来检查 MPI 消息的状态。

# MPI 数据类型

MPI 定义了许多基本类型，可以直接使用：

| **MPI 数据类型** | **C 等效** |
| --- | --- |
| `MPI_SHORT` | short int |
| `MPI_INT` | int |
| `MPI_LONG` | long int |
| `MPI_LONG_LONG` | long long int |
| `MPI_UNSIGNED_CHAR` | unsigned char |
| `MPI_UNSIGNED_SHORT` | unsigned short int |
| `MPI_UNSIGNED` | unsigned int |
| `MPI_UNSIGNED_LONG` | unsigned long int |
| `MPI_UNSIGNED_LONG_LONG` | unsigned long long int |
| `MPI_FLOAT` | float |
| `MPI_DOUBLE` | double |
| `MPI_LONG_DOUBLE` | long double |
| `MPI_BYTE` | char |

MPI 保证使用这些类型时，接收方始终以其期望的格式获取消息数据，而不受字节顺序和其他与平台相关的问题的影响。

# 自定义类型

除了这些基本格式之外，还可以创建新的 MPI 数据类型。这些使用了许多 MPI 函数，包括`MPI_Type_create_struct`：

```cpp
int MPI_Type_create_struct( 
   int count,  
   int array_of_blocklengths[], 
         const MPI_Aint array_of_displacements[],  
   const MPI_Datatype array_of_types[], 
         MPI_Datatype *newtype) 

```

使用此函数，可以创建一个包含结构的 MPI 类型，就像基本的 MPI 数据类型一样：

```cpp
#include <cstdio> 
#include <cstdlib> 
#include <mpi.h> 
#include <cstddef> 

struct car { 
        int shifts; 
        int topSpeed; 
}; 

int main(int argc, char **argv) { 
         const int tag = 13; 
         int size, rank; 

         MPI_Init(&argc, &argv); 
         MPI_Comm_size(MPI_COMM_WORLD, &size); 

         if (size < 2) { 
               fprintf(stderr,"Requires at least two processes.\n"); 
               MPI_Abort(MPI_COMM_WORLD, 1); 
         } 

         const int nitems = 2; 
         int blocklengths[2] = {1,1}; 
   MPI_Datatype types[2] = {MPI_INT, MPI_INT}; 
         MPI_Datatype mpi_car_type; 
         MPI_Aint offsets[2]; 

         offsets[0] = offsetof(car, shifts); 
         offsets[1] = offsetof(car, topSpeed); 

         MPI_Type_create_struct(nitems, blocklengths, offsets, types, &mpi_car_type); 
         MPI_Type_commit(&mpi_car_type); 

         MPI_Comm_rank(MPI_COMM_WORLD, &rank); 
         if (rank == 0) { 
               car send; 
               send.shifts = 4; 
               send.topSpeed = 100; 

               const int dest = 1; 

         MPI_Send(&send, 1, mpi_car_type, dest, tag, MPI_COMM_WORLD); 

               printf("Rank %d: sent structure car\n", rank); 
         } 

   if (rank == 1) { 
               MPI_Status status; 
               const int src = 0; 

         car recv; 

         MPI_Recv(&recv, 1, mpi_car_type, src, tag, MPI_COMM_WORLD, &status); 
         printf("Rank %d: Received: shifts = %d topSpeed = %d\n", rank, recv.shifts, recv.topSpeed); 
    } 

    MPI_Type_free(&mpi_car_type); 
    MPI_Finalize(); 

         return 0; 
} 

```

在这里，我们看到了一个名为`mpi_car_type`的新 MPI 数据类型是如何定义和用于在两个进程之间传递消息的。要创建这样的结构类型，我们需要定义结构中的项目数，每个块中的元素数，它们的字节位移以及它们的基本 MPI 类型。

# 基本通信

MPI 通信的一个简单示例是从一个进程向另一个进程发送单个值。为了做到这一点，需要使用以下列出的代码，并运行编译后的二进制文件，以启动至少两个进程。这些进程是在本地运行还是在两个计算节点上运行都无所谓。

以下代码感谢从[`mpitutorial.com/tutorials/mpi-hello-world/`](http://mpitutorial.com/tutorials/mpi-hello-world/)借用：

```cpp
#include <mpi.h> 
#include <stdio.h> 
#include <stdlib.h> 

int main(int argc, char** argv) { 
   // Initialize the MPI environment. 
   MPI_Init(NULL, NULL); 

   // Find out rank, size. 
   int world_rank; 
   MPI_Comm_rank(MPI_COMM_WORLD, &world_rank); 
   int world_size; 
   MPI_Comm_size(MPI_COMM_WORLD, &world_size); 

   // We are assuming at least 2 processes for this task. 
   if (world_size < 2) { 
               fprintf(stderr, "World size must be greater than 1 for %s.\n", argv[0]); 
               MPI_Abort(MPI_COMM_WORLD, 1); 
   } 

   int number; 
   if (world_rank == 0) { 
         // If we are rank 0, set the number to -1 and send it to process 1\. 
               number = -1; 
               MPI_Send(&number, 1, MPI_INT, 1, 0, MPI_COMM_WORLD); 
   }  
   else if (world_rank == 1) { 
               MPI_Recv(&number, 1, MPI_INT, 0, 0,  
                           MPI_COMM_WORLD,  
                           MPI_STATUS_IGNORE); 
               printf("Process 1 received number %d from process 0.\n", number); 
   } 

   MPI_Finalize(); 
} 

```

这段代码并不复杂。我们通过常规的 MPI 初始化，然后检查确保我们的世界大小至少有两个进程。

然后，等级为 0 的进程将发送一个数据类型为`MPI_INT`且值为`-1`的 MPI 消息。等级为`1`的进程将等待接收此消息。接收进程指定`MPI_Status MPI_STATUS_IGNORE`，表示进程不会检查消息的状态。这是一种有用的优化技术。

最后，预期的输出如下：

```cpp
    $ mpirun -n 2 ./send_recv_demo
    Process 1 received number -1 from process 0

```

在这里，我们使用两个进程开始编译后的演示代码。输出显示第二个进程从第一个进程接收了 MPI 消息，并且值是正确的。

# 高级通信

对于高级 MPI 通信，可以使用`MPI_Status`字段来获取有关消息的更多信息。可以使用`MPI_Probe`在接受`MPI_Recv`之前发现消息的大小。这对于事先不知道消息大小的情况很有用。

# 广播

广播消息意味着世界中的所有进程都将接收到它。这简化了广播函数相对于发送函数：

```cpp
int MPI_Bcast( 
   void *buffer,  
   int count,  
   MPI_Datatype datatype, 
         int root,    
   MPI_Comm comm) 

```

接收进程将简单地使用普通的`MPI_Recv`函数。广播函数所做的一切只是优化使用算法发送多条消息，该算法同时使用多个网络链接，而不仅仅是一个。

# 散射和收集

散射与广播消息非常相似，但有一个非常重要的区别：它不是在每条消息中发送相同的数据，而是将数组的不同部分发送给每个接收者。其函数定义如下：

```cpp
int MPI_Scatter( 
         void* send_data, 
         int send_count, 
         MPI_Datatype send_datatype, 
         void* recv_data, 
         int recv_count, 
         MPI_Datatype recv_datatype, 
         int root, 
         MPI_Comm communicator) 

```

每个接收进程将获得相同的数据类型，但我们可以指定将发送到每个进程的项目数（`send_count`）。这个函数在发送和接收方都会用到，后者只需要定义与接收数据相关的最后一组参数，提供根进程的世界等级和相关的通信器。

收集是散射的反向过程。在这里，多个进程将发送的数据最终到达单个进程，并且这些数据按发送它的进程的等级进行排序。其函数定义如下：

```cpp
int MPI_Gather( 
         void* send_data, 
         int send_count, 
         MPI_Datatype send_datatype, 
         void* recv_data, 
         int recv_count, 
         MPI_Datatype recv_datatype, 
         int root, 
         MPI_Comm communicator) 

```

人们可能会注意到，这个函数看起来与散射函数非常相似。这是因为它基本上是以相同的方式工作，只是这一次发送节点必须填写与发送数据相关的参数，而接收进程必须填写与接收数据相关的参数。

这里需要注意的是，`recv_count`参数与从每个发送进程接收的数据量有关，而不是总大小。

这两个基本函数还有进一步的专业化，但这里不会涉及到。

# MPI 与线程

有人可能会认为，在每个集群节点的单个 CPU 核心上分配一个 MPI 应用程序的实例使用 MPI 可能是最简单的方法，这是正确的。然而，这并不是最快的解决方案。

尽管在跨网络的进程间通信方面，MPI 可能是在这种情况下最佳的选择，在单个系统（单个或多 CPU 系统）中使用多线程是非常有意义的。

这样做的主要原因是线程之间的通信明显比进程间通信快得多，特别是在使用诸如 MPI 之类的通用通信层时。

可以编写一个使用 MPI 在集群网络上进行通信的应用程序，其中为每个 MPI 节点分配一个应用程序实例。应用程序本身将检测该系统上的 CPU 核心数量，并为每个核心创建一个线程。因此，混合 MPI 通常被广泛使用，因为它提供了以下优势：

+   **更快的通信** - 使用快速的线程间通信。

+   **更少的 MPI 消息** - 更少的消息意味着带宽和延迟的减少。

+   **避免数据重复** - 数据可以在线程之间共享，而不是向一系列进程发送相同的消息。

实现这一点可以通过前几章中所见的方式来完成，即使用 C++11 和后续版本中找到的多线程特性。另一个选择是使用 OpenMP，就像我们在本章开头看到的那样。

使用 OpenMP 的明显优势在于它对开发人员的工作量几乎没有要求。如果我们需要运行相同例程的更多实例，只需要对代码进行少量修改，标记用于工作线程的代码即可。

例如：

```cpp
#include <stdio.h>
#include <mpi.h>
#include <omp.h>

int main(int argc, char *argv[]) {
  int numprocs, rank, len;
  char procname[MPI_MAX_PROCESSOR_NAME];
  int tnum = 0, tc = 1;

  MPI_Init(&argc, &argv);
  MPI_Comm_size(MPI_COMM_WORLD, &numprocs);
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Get_processor_name(procname, &len);

  #pragma omp parallel default(shared) private(tnum, tc) {
      np = omp_get_num_threads();
      tnum = omp_get_thread_num();
      printf("Thread %d out of %d from process %d out of %d on %s\n", 
      tnum, tc, rank, numprocs, procname);
  }

  MPI_Finalize();
}

```

上述代码将 OpenMP 应用程序与 MPI 结合起来。要编译它，我们可以运行如下命令：

```cpp
$ mpicc -openmp hellohybrid.c -o hellohybrid

```

接下来，要运行该应用程序，我们将使用 mpirun 或等效工具：

```cpp
$ export OMP_NUM_THREADS=8
$ mpirun -np 2 --hostfile my_hostfile -x OMP_NUM_THREADS ./hellohybrid

```

mpirun 命令将使用 hellohybrid 二进制文件运行两个 MPI 进程，并向每个新进程传递我们使用-x 标志导出的环境变量。然后，OpenMP 运行时将使用该变量中包含的值来创建相应数量的线程。

假设我们的 MPI 主机文件中至少有两个 MPI 节点，我们将在两个节点上分别运行两个 MPI 进程，每个进程运行八个线程，这将适合具有超线程的四核 CPU 或八核 CPU。

# 潜在问题

在编写基于 MPI 的应用程序并在多核 CPU 或集群上执行时，可能会遇到的问题与我们在前几章中遇到的多线程代码问题非常相似。

然而，MPI 的另一个问题是，它依赖于网络资源的可用性。由于用于`MPI_Send`调用的发送缓冲区在网络堆栈处理缓冲区之前无法回收，并且此调用是阻塞类型，因此发送大量小消息可能导致一个进程等待另一个进程，而另一个进程又在等待调用完成。

在设计 MPI 应用程序的消息传递结构时，应该牢记这种死锁类型。例如，可以确保一方没有发送调用积累，这将导致这种情况。提供有关队列深度和类似信息的反馈消息可以用来减轻压力。

MPI 还包含使用所谓的屏障的同步机制。这是用于在 MPI 进程之间进行同步的，例如在任务上。使用 MPI 屏障（`MPI_Barrier`）调用与互斥锁类似，如果 MPI 进程无法实现同步，一切都将在此时挂起。

# 概要

在本章中，我们详细研究了 MPI 标准，以及其中一些实现，特别是 Open MPI，并且我们看到了如何设置集群。我们还看到了如何使用 OpenMP 轻松地为现有代码添加多线程。

此时，读者应该能够建立一个基本的 Beowulf 或类似的集群，为 MPI 进行配置，并在其上运行基本的 MPI 应用程序。应该知道如何在 MPI 进程之间进行通信以及如何定义自定义数据类型。此外，读者将意识到在为 MPI 编程时可能遇到的潜在问题。

在下一章中，我们将把前几章的知识结合起来，看看如何在最后一章中进行通用计算机图形处理器（GPGPU）的计算。


# 第十章：使用 GPGPU 进行多线程处理

最近的一个发展是使用视频卡（GPU）进行通用计算（GPGPU）。使用诸如 CUDA 和 OpenCL 之类的框架，可以加速例如在医疗、军事和科学应用中并行处理大型数据集的处理。在本章中，我们将看看如何使用 C++和 OpenCL 来实现这一点，以及如何将这样的功能集成到 C++中的多线程应用程序中。

本章的主题包括：

+   将 OpenCL 集成到基于 C++的应用程序中

+   在多线程中使用 OpenCL 的挑战

+   延迟和调度对多线程性能的影响

# GPGPU 处理模型

在第九章中，*使用分布式计算进行多线程处理*，我们看到在集群系统中跨多个计算节点运行相同的任务。这样设置的主要目标是以高度并行的方式处理数据，从理论上讲，相对于具有较少 CPU 核心的单个系统，可以加快处理速度。

**GPGPU**（图形处理单元上的通用计算）在某些方面与此类似，但有一个主要区别：虽然只有常规 CPU 的计算集群擅长标量任务--即在一组数据上执行一个任务（SISD）--GPU 是擅长 SIMD（单输入，多数据）任务的矢量处理器。

基本上，这意味着一个人可以将大型数据集发送到 GPU，以及单个任务描述，GPU 将继续在其数百或数千个核上并行执行该数据的部分相同任务。因此，人们可以将 GPU 视为一种非常专业化的集群：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00026.jpeg)

# 实施

当 GPGPU 的概念首次被提出（大约在 2001 年左右），编写 GPGPU 程序的最常见方式是使用 GLSL（OpenGL 着色语言）和类似的着色器语言。由于这些着色器语言已经针对 SIMD 任务（图像和场景数据）进行了优化，因此将它们调整为更通用的任务相对比较简单。

自那时起，出现了许多更专业的实现：

| **名称** | **自** | **所有者** | **备注** |
| --- | --- | --- | --- |
| CUDA | 2006 | NVidia | 这是专有的，仅在 NVidia GPU 上运行 |
| Close to Metal | 2006 | ATi/AMD | 这被放弃，支持 OpenCL |
| DirectCompute | 2008 | Microsoft | 这是随 DX11 发布的，可以在 DX10 GPU 上运行，仅限于 Windows 平台 |
| OpenCL | 2009 | Khronos Group | 这是开放标准，适用于所有主流平台上的 AMD、Intel 和 NVidia GPU，以及移动平台 |

# OpenCL

在各种当前的 GPGPU 实现中，由于没有限制，OpenCL 是迄今为止最有趣的 GPGPU API。它适用于几乎所有主流 GPU 和平台，甚至在某些移动平台上也得到支持。

OpenCL 的另一个显着特点是它不仅限于 GPGPU。作为其名称的一部分（开放计算语言），它将系统抽象为所谓的*计算设备*，每个设备都有自己的功能。GPGPU 是最常见的应用，但这个特性使得在 CPU 上首先进行测试实现变得相当容易，以便进行简单的调试。

OpenCL 的一个可能的缺点是它对内存和硬件细节采用了高度抽象，这可能会对性能产生负面影响，尽管它增加了代码的可移植性。

在本章的其余部分，我们将专注于 OpenCL。

# 常见的 OpenCL 应用

许多程序包括基于 OpenCL 的代码，以加快操作。这些包括旨在进行图形处理的程序，以及 3D 建模和 CAD、音频和视频处理。一些例子包括：

+   Adobe Photoshop

+   GIMP

+   ImageMagick

+   Autodesk Maya

+   Blender

+   Handbrake

+   Vegas Pro

+   OpenCV

+   Libav

+   Final Cut Pro

+   FFmpeg

在办公应用程序中，包括 LibreOffice Calc 和 Microsoft Excel 中，还发现了某些操作的进一步加速。

也许更重要的是，OpenCL 通常用于科学计算和密码学，包括 BOINC 和 GROMACS 以及许多其他库和程序。

# OpenCL 版本

自 2008 年 12 月 8 日发布 OpenCL 规范以来，迄今已经有五次更新，将其升级到 2.2 版本。这些更新中的重要变化如下。

# OpenCL 1.0

首次公开发布是由苹果作为 macOS X Snow Leopard 发布的一部分于 2009 年 8 月 28 日发布。

与此同时，AMD 宣布将支持 OpenCL 并淘汰其自己的 Close to Metal（CtM）框架。 NVidia，RapidMind 和 IBM 还为其自己的框架添加了对 OpenCL 的支持。

# OpenCL 1.1

OpenCL 1.1 规范于 2010 年 6 月 14 日由 Khronos Group 批准。它为并行编程和性能增加了额外的功能，包括以下内容：

+   包括 3 组分向量和额外的图像格式在内的新数据类型

+   处理来自多个主机线程的命令，并在多个设备上处理缓冲区

+   对缓冲区的区域进行操作，包括读取、写入和复制 1D、2D 或 3D 矩形区域

+   增强事件的使用来驱动和控制命令执行

+   额外的 OpenCL 内置 C 函数，如整数夹紧、洗牌和异步步进（不连续，但数据之间有间隙）复制

+   通过有效共享图像和缓冲区来改进 OpenGL 互操作性，通过链接 OpenCL 和 OpenGL 事件

# OpenCL 1.2

OpenCL 1.2 版本于 2011 年 11 月 15 日发布。其最重要的功能包括以下内容：

+   **设备分区：**这使应用程序能够将设备分成子设备，直接控制对特定计算单元的工作分配，为高优先级/延迟敏感任务保留设备的一部分，或有效地使用共享硬件资源，如缓存。

+   **对象的分离编译和链接：**这提供了传统编译器的功能和灵活性，使得可以创建 OpenCL 程序的库，供其他程序链接。

+   **增强的图像支持：**这包括对 1D 图像和 1D 和 2D 图像数组的增强支持。此外，OpenGL 共享扩展现在可以从 OpenGL 1D 纹理和 1D 和 2D 纹理数组创建 OpenCL 图像。

+   **内置内核：**这代表了专门或不可编程硬件及相关固件的功能，如视频编码器/解码器和数字信号处理器，使得这些定制设备可以从 OpenCL 框架中驱动并与之紧密集成。

+   **DX9 媒体表面共享：**这使得 OpenCL 和 DirectX 9 或 DXVA 媒体表面之间的有效共享成为可能。

+   **DX11 表面共享：**实现 OpenCL 和 DirectX 11 表面之间的无缝共享。

# OpenCL 2.0

OpenCL2.0 版本于 2013 年 11 月 18 日发布。此版本具有以下重大变化或增加：

+   **共享虚拟内存：**主机和设备内核可以直接共享复杂的、包含指针的数据结构，如树和链表，提供了重要的编程灵活性，并消除了主机和设备之间昂贵的数据传输。

+   **动态并行性：**设备内核可以在没有主机交互的情况下将内核排队到同一设备，从而实现灵活的工作调度范例，并避免在设备和主机之间传输执行控制和数据，通常显著减轻主机处理器瓶颈。

+   **通用地址空间：**函数可以在不指定参数的命名地址空间的情况下编写，特别适用于声明为指向类型的指针的参数，消除了需要为应用程序中使用的每个命名地址空间编写多个函数的需要。

+   **图像**：改进的图像支持，包括 sRGB 图像和 3D 图像写入，内核可以从同一图像读取和写入，以及从 mip-mapped 或多采样 OpenGL 纹理创建 OpenCL 图像以改进 OpenGL 互操作性。

+   **C11 原子操作**：C11 原子操作和同步操作的子集，可以使一个工作项中的赋值对设备上执行的其他工作项或在设备和主机之间共享数据的工作组可见。

+   **管道**：管道是以 FIFO 形式存储数据的内存对象，OpenCL 2.0 提供了内核读取或写入管道的内置函数，可以直接编程管道数据结构，这可以由 OpenCL 实现者进行高度优化。

+   **Android 可安装客户端驱动扩展**：使得可以在 Android 系统上发现和加载 OpenCL 实现作为共享对象。

# OpenCL 2.1

OpenCL 2.1 标准于 2015 年 11 月 16 日发布，这个版本最显著的特点是引入了 OpenCL C++内核语言，就像 OpenCL 语言最初是基于带有扩展的 C 一样，C++版本是基于 C++14 的子集，同时向后兼容 C 内核语言。

OpenCL API 的更新包括以下内容：

+   **子组**：这些使得对硬件线程的更精细控制现在已经成为核心，还有额外的子组查询操作，以增加灵活性。

+   **内核对象和状态的复制**：clCloneKernel 可以复制内核对象和状态，以安全地实现包装类中的复制构造函数

+   **低延迟设备定时器查询**：这允许在设备和主机代码之间对齐分析数据

+   **运行时的中间 SPIR-V 代码**：

+   LLVM 到 SPIR-V 之间的双向翻译器，以便在工具链中灵活使用这两种中间语言。

+   通过上述翻译生成 SPIR-V 的 OpenCL C 到 LLVM 编译器。

+   SPIR-V 汇编器和反汇编器。

标准可移植中间表示（SPIR）及其后继者 SPIR-V，是为了在 OpenCL 设备上提供设备无关的二进制文件的一种方式。

# OpenCL 2.2

2017 年 5 月 16 日，现在的 OpenCL 版本发布。根据 Khronos Group 的说法，它包括以下更改：

+   OpenCL 2.2 将 OpenCL C++内核语言纳入核心规范，显著增强了并行编程的生产力

+   OpenCL C++内核语言是 C++14 标准的静态子集，包括类、模板、Lambda 表达式、函数重载和许多其他用于通用和元编程的构造

+   利用全面支持 OpenCL C++内核语言的新 Khronos SPIR-V 1.1 中间语言

+   OpenCL 库函数现在可以利用 C++语言来提供更高的安全性和减少未定义行为，同时访问原子操作、迭代器、图像、采样器、管道和设备队列内置类型和地址空间

+   管道存储是 OpenCL 2.2 中的一种新的设备端类型，对于 FPGA 实现非常有用，因为它可以在编译时知道连接大小和类型，并能够在内核之间实现高效的设备范围通信

+   OpenCL 2.2 还包括增强生成代码的功能：应用程序可以在 SPIR-V 编译时提供特化常量的值，新的查询可以检测程序范围全局对象的非平凡构造函数和析构函数，用户回调可以在程序释放时设置

+   可在任何支持 OpenCL 2.0 的硬件上运行（只需要更新驱动程序）

# 设置开发环境

无论您使用哪个平台和 GPU，进行 OpenCL 开发最重要的部分是从制造商那里获取适用于自己 GPU 的 OpenCL 运行时。在这里，AMD、Intel 和 Nvidia 都为所有主流平台提供 SDK。对于 Nvidia，OpenCL 支持包含在 CUDA SDK 中。

除了 GPU 供应商的 SDK 之外，人们还可以在他们的网站上找到有关该 SDK 支持哪些 GPU 的详细信息。

# Linux

在按照提供的说明安装供应商的 GPGPU SDK 后，我们仍然需要下载 OpenCL 头文件。与供应商提供的共享库和运行时文件不同，这些头文件是通用的，可以与任何 OpenCL 实现一起使用。

对于基于 Debian 的发行版，只需执行以下命令行：

```cpp
    $ sudo apt-get install opencl-headers

```

对于其他发行版，软件包可能被称为相同的名称，或者是不同的名称。请查阅发行版的手册，了解如何找到软件包的名称。

安装 SDK 和 OpenCL 头文件后，我们就可以编译我们的第一个 OpenCL 应用程序了。

# Windows

在 Windows 上，我们可以选择使用 Visual Studio（Visual C++）或 Windows 版的 GCC（MinGW）进行开发。为了与 Linux 版本保持一致，我们将使用 MinGW 以及 MSYS2。这意味着我们将拥有相同的编译器工具链、相同的 Bash shell 和实用程序，以及 Pacman 软件包管理器。

在安装供应商的 GPGPU SDK 后，如前所述，只需在 MSYS2 shell 中执行以下命令行，即可安装 OpenCL 头文件：

```cpp
    $ pacman -S mingw64/mingw-w64-x86_64-opencl-headers

```

或者，在使用 32 位 MinGW 版本时，执行以下命令行：

```cpp
    mingw32/mingw-w64-i686-opencl-headers 

```

有了这个，OpenCL 头文件就位了。现在我们只需要确保 MinGW 链接器可以找到 OpenCL 库。使用 NVidia CUDA SDK，您可以使用`CUDA_PATH`环境变量，或浏览 SDK 的安装位置，并将适当的 OpenCL LIB 文件从那里复制到 MinGW lib 文件夹中，确保不要混淆 32 位和 64 位文件。

现在共享库也已经就位，我们可以编译 OpenCL 应用程序。

# OS X/MacOS

从 OS X 10.7 开始，OS 中提供了 OpenCL 运行时。安装 XCode 以获取开发头文件和库后，就可以立即开始 OpenCL 开发。

# 一个基本的 OpenCL 应用程序

一个常见的 GPGPU 应用程序的例子是计算快速傅里叶变换（FFT）。这个算法通常用于音频处理等领域，允许您将例如从时域到频域进行转换，以进行分析。

它的作用是对数据集应用分治法，以计算 DFT（离散傅里叶变换）。它通过将输入序列分成固定的小数量的较小子序列，计算它们的 DFT，并组装这些输出，以组成最终序列。

这是相当高级的数学，但可以说它之所以非常适合 GPGPU，是因为它是一个高度并行的算法，采用数据的分割来加速 DFT 的计算，如图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00027.jpeg)

每个 OpenCL 应用程序至少由两部分组成：设置和配置 OpenCL 实例的 C++代码，以及实际的 OpenCL 代码，也称为内核，例如基于维基百科 FFT 演示示例的这个。

```cpp
// This kernel computes FFT of length 1024\.  
// The 1024 length FFT is decomposed into calls to a radix 16 function,  
// another radix 16 function and then a radix 4 function
 __kernel void fft1D_1024 (__global float2 *in,  
                     __global float2 *out,  
                     __local float *sMemx,  
                     __local float *sMemy) {
          int tid = get_local_id(0);
          int blockIdx = get_group_id(0) * 1024 + tid;
          float2 data[16];

          // starting index of data to/from global memory
          in = in + blockIdx;  out = out + blockIdx;

          globalLoads(data, in, 64); // coalesced global reads
          fftRadix16Pass(data);      // in-place radix-16 pass
          twiddleFactorMul(data, tid, 1024, 0);

          // local shuffle using local memory
          localShuffle(data, sMemx, sMemy, tid, (((tid & 15) * 65) + (tid >> 4)));
          fftRadix16Pass(data);               // in-place radix-16 pass
          twiddleFactorMul(data, tid, 64, 4); // twiddle factor multiplication

          localShuffle(data, sMemx, sMemy, tid, (((tid >> 4) * 64) + (tid & 15)));

          // four radix-4 function calls
          fftRadix4Pass(data);      // radix-4 function number 1
          fftRadix4Pass(data + 4);  // radix-4 function number 2
          fftRadix4Pass(data + 8);  // radix-4 function number 3
          fftRadix4Pass(data + 12); // radix-4 function number 4

          // coalesced global writes
    globalStores(data, out, 64);
 } 

```

这个 OpenCL 内核表明，与 GLSL 着色器语言一样，OpenCL 的内核语言本质上是 C 语言，具有许多扩展。虽然可以使用 OpenCL C++内核语言，但这个语言仅在 OpenCL 2.1（2015 年）之后才可用，因此对它的支持和示例比 C 内核语言更少。

接下来是 C++应用程序，使用它，我们运行前面的 OpenCL 内核：

```cpp
#include <cstdio>
 #include <ctime>
 #include "CL\opencl.h"

 #define NUM_ENTRIES 1024

 int main() { // (int argc, const char * argv[]) {
    const char* KernelSource = "fft1D_1024_kernel_src.cl"; 

```

在这里，我们可以看到，我们只需要包含一个头文件，就可以访问 OpenCL 函数。我们还要指定包含我们 OpenCL 内核源代码的文件的名称。由于每个 OpenCL 设备可能是不同的架构，当我们加载内核时，内核会被编译为目标设备：

```cpp
          const cl_uint num = 1;
    clGetDeviceIDs(0, CL_DEVICE_TYPE_GPU, 0, 0, (cl_uint*) num); 

   cl_device_id devices[1];
    clGetDeviceIDs(0, CL_DEVICE_TYPE_GPU, num, devices, 0);

```

接下来，我们必须获取可以使用的 OpenCL 设备列表，并通过 GPU 进行过滤：

```cpp
    cl_context context = clCreateContextFromType(0, CL_DEVICE_TYPE_GPU,  
                                                   0, 0, 0); 

```

然后，我们使用找到的 GPU 设备创建一个 OpenCL`context`。上下文管理一系列设备上的资源：

```cpp
    clGetDeviceIDs(0, CL_DEVICE_TYPE_DEFAULT, 1, devices, 0);
    cl_command_queue queue = clCreateCommandQueue(context, devices[0], 0, 0); 

```

最后，我们将创建包含要在 OpenCL 设备上执行的命令的命令队列：

```cpp
    cl_mem memobjs[] = { clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(float) * 2 * NUM_ENTRIES, 0, 0),              
   clCreateBuffer(context, CL_MEM_READ_WRITE, sizeof(float) * 2 * NUM_ENTRIES, 0, 0) }; 

```

为了与设备通信，我们需要分配缓冲区对象，这些对象将包含我们将复制到它们的内存中的数据。在这里，我们将分配两个缓冲区，一个用于读取，一个用于写入：

```cpp
    cl_program program = clCreateProgramWithSource(context, 1, (const char **)& KernelSource, 0, 0); 

```

现在我们已经将数据放在设备上，但仍需要在设备上加载内核。为此，我们将使用前面查看的 OpenCL 内核源代码创建一个内核，使用我们之前定义的文件名：

```cpp
    clBuildProgram(program, 0, 0, 0, 0, 0); 

```

接下来，我们将按以下方式编译源代码：

```cpp
   cl_kernel kernel = clCreateKernel(program, "fft1D_1024", 0); 

```

最后，我们将从我们创建的二进制文件中创建实际的内核：

```cpp
    size_t local_work_size[1] = { 256 };

    clSetKernelArg(kernel, 0, sizeof(cl_mem), (void *) &memobjs[0]);
    clSetKernelArg(kernel, 1, sizeof(cl_mem), (void *) &memobjs[1]);
    clSetKernelArg(kernel, 2, sizeof(float) * (local_work_size[0] + 1) * 16, 0);
    clSetKernelArg(kernel, 3, sizeof(float) * (local_work_size[0] + 1) * 16, 0); 

```

为了将参数传递给我们的内核，我们必须在这里设置它们。在这里，我们将添加指向我们缓冲区的指针和工作大小的维度：

```cpp
    size_t global_work_size[1] = { 256 };
          global_work_size[0] = NUM_ENTRIES;
    local_work_size[0]  =  64;  // Nvidia: 192 or 256
    clEnqueueNDRangeKernel(queue, kernel, 1, 0, global_work_size, local_work_size, 0, 0, 0); 

```

现在我们可以设置工作项维度并执行内核。在这里，我们将使用一种内核执行方法，允许我们定义工作组的大小：

```cpp
          cl_mem C = clCreateBuffer(context, CL_MEM_WRITE_ONLY, (size), 0, &ret);
                      cl_int ret = clEnqueueReadBuffer(queue, memobjs[1], CL_TRUE, 0, sizeof(float) * 2 * NUM_ENTRIES, C, 0, 0, 0); 

```

执行内核后，我们希望读取生成的信息。为此，我们告诉 OpenCL 将分配的写缓冲区复制到新分配的缓冲区中。现在我们可以自由地使用这个缓冲区中的数据。

然而，在这个例子中，我们不会使用这些数据：

```cpp
    clReleaseMemObject(memobjs[0]);
    clReleaseMemObject(memobjs[1]); 
   clReleaseCommandQueue(queue); 
   clReleaseKernel(kernel); 
   clReleaseProgram(program); 
   clReleaseContext(context); 
   free(C);
 } 

```

最后，我们释放分配的资源并退出。

# GPU 内存管理

在使用 CPU 时，我们必须处理多层内存层次结构，从主内存（最慢）到 CPU 缓存（更快），再到 CPU 寄存器（最快）。GPU 也是如此，我们必须处理一个可能会显著影响应用程序速度的内存层次结构。

在 GPU 上最快的也是寄存器（或私有）内存，我们拥有的比平均 CPU 多得多。之后是本地内存，这是一种由多个处理单元共享的内存。GPU 本身上最慢的是内存数据缓存，也称为纹理内存。这是卡上的一个内存，通常被称为视频 RAM（VRAM），使用高带宽，但相对高延迟的内存，比如 GDDR5。

绝对最慢的是使用主机系统的内存（系统 RAM），因为这需要通过 PCIe 总线和其他各种子系统传输数据。相对于设备内存系统，主机设备通信最好称为“冰川”。

对于 AMD、Nvidia 和类似的专用 GPU 设备，内存架构可以像这样进行可视化：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00028.jpeg)

由于这种内存布局，建议以大块传输任何数据，并在可能的情况下使用异步传输。理想情况下，内核将在 GPU 核心上运行，并将数据流式传输到它，以避免任何延迟。

# GPGPU 和多线程

将多线程代码与 GPGPU 结合使用要比尝试管理在 MPI 集群上运行的并行应用程序容易得多。这主要是由于以下工作流程：

1.  准备数据：准备要处理的数据，比如大量的图像或单个大图像，将其发送到 GPU 的内存中。

1.  准备内核：加载 OpenCL 内核文件并将其编译为 OpenCL 内核。

1.  执行内核：将内核发送到 GPU 并指示它开始处理数据。

1.  读取数据：一旦我们知道处理已经完成，或者已经达到特定的中间状态，我们将读取我们作为 OpenCL 内核参数传递的缓冲区，以获取我们的结果。

由于这是一个异步过程，可以将其视为一种“发射并忘记”的操作，只需有一个专用线程来监视活动内核的过程。

在多线程和 GPGPU 应用方面最大的挑战不在于基于主机的应用程序，而是在于运行在 GPU 上的 GPGPU 内核或着色器程序，因为它必须在本地和远程处理单元之间协调内存管理和处理，确定根据数据类型使用哪种内存系统，而不会在处理其他地方引起问题。

这是一个需要大量试错、分析和优化的细致过程。一个内存复制优化或使用异步操作而不是同步操作可能会将处理时间从几个小时减少到几分钟。对内存系统的良好理解对于防止数据饥饿和类似问题至关重要。

由于 GPGPU 通常用于加速持续时间显著的任务（几分钟到几小时甚至更长），因此最好从多线程的角度来看待它，尽管存在一些重要的复杂性，主要是延迟的形式。

# 延迟

正如我们在早期关于 GPU 内存管理的部分中提到的，最好首先使用最接近 GPU 处理单元的内存，因为它们是最快的。这里的最快主要意味着它们具有较低的延迟，意味着从内存请求信息到接收响应所花费的时间。

确切的延迟会因 GPU 而异，但以 Nvidia 的 Kepler（Tesla K20）架构为例，可以期望延迟为：

+   **全局**内存：450 个周期。

+   **常量**内存缓存：45-125 个周期。

+   **本地**（**共享**）内存：45 个周期。

这些测量都是在 CPU 本身上进行的。对于 PCIe 总线，一旦开始传输多兆字节的缓冲区，一个传输可能需要几毫秒的时间。例如，填充 GPU 的内存以千兆字节大小的缓冲区可能需要相当长的时间。

对于通过 PCIe 总线的简单往返，延迟可以用微秒来衡量，对于以 1+ GHz 运行的 GPU 核心来说，似乎是一段漫长的时间。这基本上定义了为什么主机和 GPU 之间的通信应该绝对最小化并且高度优化。

# 潜在问题

GPGPU 应用的一个常见错误是在处理完成之前读取结果缓冲区。在将缓冲区传输到设备并执行内核之后，必须插入同步点以通知主机处理已经完成。这些通常应该使用异步方法实现。

正如我们在延迟部分中所介绍的，重要的是要记住请求和响应之间可能存在非常大的延迟，这取决于内存子系统或总线。不这样做可能会导致奇怪的故障、冻结和崩溃，以及数据损坏和似乎永远等待的应用程序。

对于 GPGPU 应用进行分析是至关重要的，以便了解 GPU 利用率如何，以及流程是否接近最佳状态。

# 调试 GPGPU 应用

GPGPU 应用的最大挑战是调试内核。CUDA 出于这个原因带有一个模拟器，它允许在 CPU 上运行和调试内核。OpenCL 允许在 CPU 上运行内核而无需修改，尽管这可能不会得到与在特定 GPU 设备上运行时相同的行为（和错误）。

一个稍微更高级的方法涉及使用专用调试器，例如 Nvidia 的 Nsight，它有适用于 Visual Studio（[`developer.nvidia.com/nvidia-nsight-visual-studio-edition`](https://developer.nvidia.com/nvidia-nsight-visual-studio-edition)）和 Eclipse（[`developer.nvidia.com/nsight-eclipse-edition`](https://developer.nvidia.com/nsight-eclipse-edition)）的版本。

根据 Nsight 网站上的营销宣传：

NVIDIA Nsight Visual Studio Edition 将 GPU 计算引入了 Microsoft Visual Studio（包括 VS2017 的多个实例）。这个 GPU 的应用程序开发环境允许您构建、调试、分析和跟踪使用 CUDA C/C++、OpenCL、DirectCompute、Direct3D、Vulkan API、OpenGL、OpenVR 和 Oculus SDK 构建的异构计算、图形和虚拟现实应用程序。

以下截图显示了一个活跃的 CUDA 调试会话：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00029.jpeg)

这样一个调试工具的一个很大的优势是，它允许用户通过识别瓶颈和潜在问题来监视、分析和优化自己的 GPGPU 应用程序。

# 总结

在本章中，我们看了如何将 GPGPU 处理集成到 C++应用程序中，以 OpenCL 的形式。我们还研究了 GPU 内存层次结构以及这如何影响性能，特别是在主机设备通信方面。

现在你应该熟悉 GPGPU 的实现和概念，以及如何创建一个 OpenCL 应用程序，以及如何编译和运行它。如何避免常见错误也应该是已知的。

作为本书的最后一章，希望所有主要问题都已得到解答，并且前面的章节以及本章在某种程度上都是有益的和有帮助的。

从这本书开始，读者可能对更详细地探究其中任何一个主题感兴趣，而在线和离线都有许多资源可用。多线程和相关领域的主题非常广泛，涉及到许多应用，从商业到科学、艺术和个人应用。

读者可能想要建立自己的 Beowulf 集群，或者专注于 GPGPU，或者将两者结合起来。也许有一个复杂的应用程序他们想要写一段时间了，或者只是想玩编程。
