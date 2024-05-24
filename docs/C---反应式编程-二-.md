# C++ 反应式编程（二）

> 原文：[`annas-archive.org/md5/e4e6a4bd655b0a85e570c3c31e1be9a2`](https://annas-archive.org/md5/e4e6a4bd655b0a85e570c3c31e1be9a2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：C++中的异步和无锁编程

在上一章中，我们看到了现代 C++引入的线程库以及创建、管理和同步线程的各种方法。使用线程编写代码的方式是相当低级的，并且容易出现与并发代码相关的潜在错误(死锁、活锁等)。尽管许多程序员没有注意到，但现代 C++语言提供了一个标准的内存模型，有助于更好地编写并发代码。作为一种并发编程语言，语言必须向开发人员提供有关内存访问和运行时执行顺序的某些保证。如果我们使用诸如互斥锁、条件变量和 futures 来发出信号事件，就不需要了解内存模型。但是了解内存模型及其保证将有助于我们使用无锁编程技术编写更快的并发代码。锁可以使用称为原子操作的东西来模拟，我们将深入研究这种技术。

正如我们在第二章中讨论的，零成本抽象仍然是 C++编程语言最基本的原则之一。C++始终是系统程序员的语言，标准委员会设法在语言支持的高级抽象机制和访问低级资源以编写系统程序的能力之间取得良好的平衡。C++公开了原子类型和一组相关操作，以对程序的执行进行细粒度控制。标准委员会已经发布了内存模型的详细语义，语言还有一组库，帮助程序员利用它们。

在上一章中，我们学习了如何使用条件变量在单独的线程中同步操作。本章讨论了标准库提供的设施，使用*futures*执行基于任务的并行性。在本章中，我们将涵盖：

+   C++中的基于任务的并行性

+   C++内存模型

+   原子类型和原子操作

+   同步操作和内存排序

+   如何编写无锁数据结构

# C++中的基于任务的并行性

任务是一种计算，可以与其他计算同时执行。线程是任务的系统级表示。在上一章中，我们学习了如何通过构造一个`std::thread`对象并将任务作为其构造函数的参数来并发执行任务，同时还可以启动其他任务。任务可以是任何可调用对象，如函数、Lambda 或仿函数。但是使用`std::thread`并发执行函数的方法称为*基于线程的方法*。并发执行的首选选择是*基于任务的方法*，本章将讨论这一点。基于任务的方法优于基于线程的方法的优势在于在任务的(更高)概念级别上操作，而不是直接在线程和锁的较低级别上操作。通过遵循标准库特性实现了基于任务的并行性：

+   用于从与单独线程相关联的任务返回值的 future 和 promise

+   `packaged_task`用于帮助启动任务并提供返回结果的机制

+   `async()`用于启动类似函数调用的任务

# Future 和 promise

C++任务通常表现得像一种数据通道。发送端通常称为 promise，将数据发送到接收端，通常称为**future**。关于 future 和 promise 的重要概念是它们使两个任务之间的值传输无需显式使用锁。值的传输由系统(运行时)本身处理。**future**和**promise**背后的基本概念很简单；当一个任务想要将一个值传递到另一个任务时，它将该值放入一个**promise**中。

标准库确保与此承诺相关联的未来获得此值。另一个任务可以从这个**future**中读取这个值（下面的图表必须从右向左阅读）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-rct-prog/img/8fe6fd77-da39-41be-9e63-f72a5e88eb24.png)

如果调用线程需要等待特定的*一次性事件*，则 future 非常方便。代表此事件的 future 使自身对调用线程可用，并且一旦 future 准备就绪（当值设置为相应的 promise 时），调用线程就可以访问该值。在执行期间，future 可能具有与之关联的数据，也可能没有。一旦事件发生，future 中将可用数据，并且无法重置。

与基于任务的并行性相关的模板类在库头文件`<future>`中声明。标准库中有两种类型的 future：独占 future（`std::future<>`）和共享 future（`std::shared_future<>`）。您可以将这些与智能指针`std::unique_ptr<>`和`std::shared_ptr<>`*相对应。`std::future`实例指的是与关联事件的唯一实例。相反，多个`std::shared_future`实例可能指向同一事件。在`shared_future`的情况下，与共同事件关联的所有实例将同时准备就绪，并且它们可以访问与事件关联的数据。模板参数是关联数据，如果没有与之关联的数据，则应使用`std::future<void>`和`std::shared_future<void>`模板规范。尽管线程之间的数据通信由 future 在内部管理，但 future 对象本身不提供同步访问。如果多个线程需要访问单个`std::future`对象，则必须使用互斥锁或其他同步机制进行保护。

`std::future`和`std::promise`类成对工作，分别用于任务调用和等待结果。对于`std::future<T>`对象`f`，我们可以使用`std::future`类的`get()`函数访问与之关联的值`T`。类似地，对于`std::promise<T>`，它有两个可用的放置操作函数（`set_value()`和`set_exception()`）与之匹配 future 的`get()`。对于 promise 对象，您可以使用`set_value()`给它一个值，或者使用`set_exception()`传递异常给它。例如，以下伪代码帮助您看到如何在 promise 中设置值（在`func1`中），以及在调用`future<T>:: get()`的函数中如何消耗这些值（`func2`）：

```cpp
// promise associated with the task launched 
void func1(std::promise<T>& pr) 
{ 
    try 
    { 
        T val; 
        process_data(val); 
        pr.set_value(val); // Can be retrieved by future<T>::get() 
    } 
    catch(...) 
    { 
        // Can be retrieved by future<T>::get() 
        // At the future level, when we call get(), the  
        // get will propagate the exception  
        pr.set_exception(std::current_exception()); 
    } 
} 
```

在前面的情况下，处理和获取结果后，类型为`T`的*val*被设置为 promise *pr*。如果执行期间发生任何异常，异常也将被设置为 promise。现在，让我们看看如何访问您设置的值：

```cpp
// future corresponding to task already launched 
void func2(std::future<T>& ft) 
{ 
    try 
    { 
        // An exception will be thrown here, if the corresponding  
        // promise had set an exception ..otherwise, retrieve the  
        // value sets by the promise.  
        T result = ft.get() 
    } 
    catch(...)
    { 
        // Handle exception  
    } 
} 
```

在这里，使用作为参数传递的 future 来访问相应承诺中设置的值。与`std::future()`相关联的`get()`函数在任务执行期间检索存储的值。调用`get()`必须准备捕获通过 future 传递的异常并处理它。在解释完`std::packaged_task`之后，我们将展示一个完整的示例，其中 future 和 promise 共同发挥作用。

# std::packaged_task

现在，让我们讨论如何将与 future 关联的返回值引入到需要结果的代码中。`std::packaged_task`是标准库中提供的一个模板类，用于通过 future 和 promise 实现基于任务的并行处理。通过在线程中设置 future 和 promise，它简化了设置任务而无需为共享结果设置显式锁。`packaged_task`实例提供了一个包装器，用于将返回值或捕获的异常放入 promise 中。`std::packaged_task`中的成员函数`get_future()`将为您提供与相应 promise 关联的 future 实例。让我们看一个示例，该示例使用 packaged task 来找到向量中所有元素的总和（promise 的工作深入到`packaged_task`的实现中）：

```cpp
// Function to calculate the sum of elements in an integer vector 
int calc_sum(std::vector<int> v) 
{ 
    int sum = std::accumulate(v.begin(), v.end(), 0); 
    return sum; 
} 

int main() 
{ 
    // Creating a packaged_task encapsulates a function 
    std::packaged_task<int(std::vector<int>)> task(calc_sum); 

    // Fetch associated future from packaged_task 
    std::future<int> result = task.get_future(); 

    std::vector<int> nums{1,2,3,4,5,6,7,8,9,10}; 

    // Pass packaged_task to thread to run asynchronously 
    std::thread t(std::move(task), std::move(nums)); 

    t.join();
    // Fetch the result of packaged_task, the value returned by calc_sum() 
    int sum = result.get(); 

    std::cout << "Sum = " << sum << std::endl; 
    return 0; 
}
```

`packaged_task`对象以任务类型作为其模板参数，并以函数指针（`calc_sum`）作为构造函数参数。通过调用任务对象的`get_future()`函数获得 future 实例。由于`packaged_task`实例无法复制，因此使用显式的`std::move()`。这是因为它是一个资源句柄，并负责其任务可能拥有的任何资源。然后，调用`get()`函数从任务中获取结果并打印它。

现在，让我们看看`packaged_task`如何与 Lambda 一起使用：

```cpp
    std::packaged_task<int(std::vector<int>)> task([](std::vector<int> 
    v) { 
        return std::accumulate(v.begin(), v.end(), 0); 
    }); 
```

在这里，`packaged_task`的构造函数中传递了一个 Lambda，而不是函数指针。正如您在之前的章节中已经看到的，对于并发运行的小代码块，Lambda 非常方便。future 的主要概念是能够获得结果，而不必担心通信管理的机制。此外，这两个操作在两个不同的线程中运行，因此是并行的。

# `std::async`

现代 C++提供了一种执行任务的机制，就像执行可能或可能不会并行执行的函数一样。在这里，我们指的是`std::async`，它在内部管理线程细节。`std::async`以可调用对象作为其参数，并返回一个`std::future`，该对象将存储已启动任务的结果或异常。让我们重新编写我们之前的示例，使用`std::async`计算向量中所有元素的总和：

```cpp
// Function to calculate the sum of elements in a vector 
int calc_sum(std::vector<int> v) 
{ 
   int sum = std::accumulate(v.begin(), v.end(), 0); 
   return sum; 
} 

int main() 
{ 
   std::vector<int> nums{1,2,3,4,5,6,7,8,9,10}; 

   // task launch using std::async 
   std::future<int> result(std::async(std::launch::async, calc_sum,    std::move(nums))); 

   // Fetch the result of async, the value returned by calc_sum() 
   int sum = result.get(); 

   std::cout << "Sum = " << sum << std::endl; 
   return 0; 
} 
```

主要是，当使用`std::async`进行基于任务的并行处理时，任务的启动和从任务中获取结果遵循直观的语法，并且与任务执行分开。在前面的代码中，`std::async`接受三个参数：

+   `async`标志确定了`async`任务的启动策略，`std::launch::async`表示`async`在新的执行线程上执行任务。`std::launch::deferred`标志不会生成新线程，但会执行*延迟评估*。如果两个标志都设置为`std::launch::async`和`std::launch::deferred`，则由实现决定是执行异步执行还是延迟评估。如果您没有显式地传递任何启动策略到`std::async`中，那么再次由实现选择执行方法。

+   `std::async`的第二个参数是可调用对象，可以是函数指针、函数对象或 Lambda。在这个例子中，`calc_sum`函数是在单独的线程中执行的任务。

+   第三个参数是任务的输入参数。通常，这是一个可变参数，可以传递任务可调用对象所需的参数数量。

现在，让我们看看`async`和 Lambda 如何一起用于相同的示例：

```cpp
// Fetch associated future from async
std::future<int> result( async([](std::vector<int> v) {
return std::accumulate(v.begin(), v.end(), 0); 
}, std::move(nums))); 
```

在这个例子中，可调用对象参数中包含一个 Lambda 函数，该函数返回`std::accumulate()`的结果。与往常一样，Lambda 与简单操作一起美化了代码的整体外观并提高了可读性。

使用`async`，你不必考虑线程和锁。只需考虑异步执行计算的任务，你不知道会使用多少线程，因为这取决于内部实现根据调用时可用的系统资源来决定。它在决定使用多少线程之前会检查可用的空闲核心（处理器）。这指出了`async`的明显局限性，即需要用于共享资源并需要锁的任务。

# C++内存模型

经典的 C++本质上是一种单线程语言。即使人们在 C++中编写多线程程序，他们也是使用各自平台的线程设施来编写它们。现代 C++可以被认为是一种并发编程语言。语言标准提供了一个标准的线程和任务机制（正如我们已经看到的），借助于标准库。由于它是标准库的一部分，语言规范已经定义了在平台上如何精确地行为。在程序运行时实现一致的平台无关行为对于线程、任务等是一个巨大的挑战，标准委员会处理得非常好。委员会设计并指定了一个标准内存模型，以实现一致的行为。内存模型包括两个方面：

+   **结构**方面，涉及数据在内存中的布局。

+   **并发**方面，涉及内存的并发访问

对于 C++程序，所有数据都由*对象*组成。语言将对象定义为*存储区域*，它以其类型和生命周期进行定义。对象可以是基本类型的实例，如 int 或 double，也可以是用户定义类型的实例。一些对象可能有子对象，但其他对象则没有。关键点是每个变量都是一个对象，包括其他对象的成员对象，每个对象都至少占用一些内存位置。现在，让我们看看这与并发有什么关系。

# 内存访问和并发

对于多线程应用程序，一切都取决于那些内存位置。如果多个线程访问不同的内存位置，一切都正常。但如果两个线程访问相同的内存位置，那么你必须非常小心。正如你在第三章中看到的那样，*C++中的语言级并发和并行性*，多个线程尝试从相同的内存位置读取不会引起问题，但只要任何一个线程尝试修改共同的内存位置中的数据，就会出现*竞争条件*的可能性。

问题性的竞争条件只能通过在多个线程之间强制排序访问来避免。如[第三章](https://cdp.packtpub.com/c___reactive_programming/wp-admin/post.php?post=48&action=edit#post_40)中所讨论的，*C++中的语言级并发和并行性*，使用互斥锁进行基于锁的内存访问是一种流行的选择。另一种方法是利用*原子操作*的同步属性，通过在两个线程之间强制排序访问。在本章的后面部分，你将看到使用原子操作来强制排序的示例。

原子操作在并发编程中对系统的其余部分是立即发生的，不会被中断（在原子操作期间不会发生任务切换）。原子性是对中断、信号、并发进程和线程的隔离的保证。关于这个主题可以在维基百科的文章[`en.wikipedia.org/wiki/Linearizability`](https://en.wikipedia.org/wiki/Linearizability)中阅读更多内容。

如果没有强制规定从不同线程对单个内存位置进行多次访问之间的顺序，其中一个或两个访问都不是原子的。如果涉及写操作，那么它可能会导致数据竞争，并可能导致未定义的行为。数据竞争是一个严重的错误，必须尽一切努力避免。原子操作可以避免未定义的行为，但不能防止竞争情况。原子操作确保在操作进行时不会发生线程切换。这是对内存交错访问的保证。原子操作保证了交错内存访问的排除（串行顺序），但不能防止竞争条件（因为有可能覆盖更新）。

# 修改合同

在程序或进程执行时，系统中的所有线程都应同意修改顺序（对于内存）。每个程序都在一个环境中执行，其中包括指令流、内存、寄存器、堆、栈、缓存、虚拟内存等等。这种修改顺序是程序员和系统之间的合同，由内存模型定义。系统由将程序转换为可执行代码的编译器（和链接器）、执行指定流中指定的指令集的处理器、缓存和程序的相关状态组成。合同要求程序员遵守某些规则，这些规则使系统能够生成一个完全优化的程序。程序员在编写访问内存的代码时必须遵守的一组规则（或启发式）是通过标准库中引入的原子类型和原子操作来实现的。

这些操作不仅是原子的，而且会在程序执行中创建同步和顺序约束。与[第三章](https://cdp.packtpub.com/c___reactive_programming/wp-admin/post.php?post=48&action=edit#post_40)中讨论的更高级别的基于锁的同步原语（互斥锁和条件变量）相比，《C++中的语言级并发和并行性》，您可以根据自己的需要定制同步和顺序约束。从 C++内存模型中重要的收获是：尽管语言采用了许多现代编程习惯和语言特性，但作为系统程序员的语言，C++为您的内存资源提供了更低级别的控制，以便根据您的需求优化代码。

# C++中的原子操作和类型

通常，非原子操作可能被其他线程视为半成品。正如在[第三章](https://cdp.packtpub.com/c___reactive_programming/wp-admin/post.php?post=48&action=edit#post_40)中所讨论的那样，《C++中的语言级并发和并行性》，在这种情况下，与共享数据结构相关的不变性将被破坏。当修改共享数据结构需要修改多个值时，就会发生这种情况。最好的例子是二叉树的部分移除节点。如果另一个线程同时尝试从这个数据结构中读取，不变性将被破坏，并可能导致未定义的行为。

使用*原子操作*，您无法从系统中的任何线程观察到半成品的操作，因为原子操作是不可分割的。如果与对象相关联的任何操作（例如读取）是原子的，那么对对象的所有修改也是原子的。C++提供了原子类型，以便您可以根据需要使用原子性。

# 原子类型

标准库定义的所有原子类型都可以在`<atomic>`头文件库中找到。系统保证这些类型的原子性以及与这些类型相关的所有操作。某些操作可能不是原子的，但在这种情况下，系统会产生原子性的幻觉。标准原子类型使用一个成员函数`is_lock_free()`，允许用户确定给定类型的操作是直接使用原子指令进行的（`is_lock_free()`返回`true`），还是使用编译器和库内部锁进行的（`is_lock_free()`返回`false`）。

`std::atomic_flag`在所有原子类型中是不同的。这种类型上的操作需要按照标准是原子的。因此，它不提供`is_lock_free()`成员函数。这是一种非常简单的类型，具有一组允许的最小操作，例如`test_and_set()`（可以查询或设置）或`clear()`（清除值）。

其余的原子类型遵循`std::atomic<>`类模板的规范。与`std::atomic_flag`相比，这些类型更加全面，但并非所有操作都是原子的。操作的原子性也高度取决于平台。在流行的平台上，内置类型的原子变体确实是无锁的，但这并不是在所有地方都能保证的。

不使用`std::atomic<>`模板类，可以使用实现提供的直接类型，如下表所示：

| **原子类型** | **对应的特化** |
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

除了所有这些基本的原子类型之外，C++标准库还提供了一组与标准库中的`typedefs`相比的原子类型的`typedefs`。有一个简单的模式来识别`typedefs`的对应原子版本：对于任何标准`typedef T`，使用`atomic_`前缀：`atomic_T`。以下表格列出了标准原子`typedefs`及其对应的内置`typedefs`：

| **原子** `typedef` | **标准库** `typedef` |
| --- | --- |
| `atomic_size_t` | `size_t` |
| `atomic_intptr_t` | `intptr_t` |
| `atomic_uintptr_t` | `uintptr_t` |
| `atomic_ptrdiff_t` | `ptrdiff_t` |
| `atomic_intmax_t` | `intmax_t` |
| `atomic_uintmax_t` | `uintmax_t` |
| `atomic_int_least8_t` | `int_least8_t` |
| `atomic_uint_least8_t` | `uint_least8_t` |
| `atomic_int_least16_t` | `int_least16_t` |
| `atomic_uint_least16_t` | `uint_least16_t` |
| `atomic_int_least32_t` | `int_least32_t` |
| `atomic_uint_least32_t` | `uint_least32_t` |
| `atomic_int_least64_t` | `int_least64_t` |
| `atomic_uint_least64_t` | `uint_least64_t` |
| `atomic_int_fast8_t` | `int_fast8_t` |
| `atomic_uint_fast8_t` | `uint_fast8_t` |
| `atomic_int_fast16_t` | `int_fast16_t` |
| `atomic_uint_fast16_t` | `uint_fast16_t` |
| `atomic_int_fast32_t` | `int_fast32_t` |
| `atomic_uint_fast32_t` | `uint_fast32_t` |
| `atomic_int_fast64_t` | `int_fast64_t` |
| `atomic_uint_fast64_t` | `uint_fast64_t` |

`std::atomic<>`类模板不仅仅是一组特化；它们有一个主模板来扩展用户定义类型的原子变体。作为一个通用模板类，支持的操作仅限于`load()`、`store()`、`exchange()`、`compare_exchange_weak()`和`compare_exchange_strong()`。原子类型的每个操作都有一个可选参数，用于指定所需的内存排序语义。内存排序的概念将在本章的后面部分详细介绍。现在，只需记住所有原子操作可以分为三类：

+   **存储操作：**这些操作可以具有`memory_order_relaxed`、`memory_order_release`或`memory_order_seq_cst`排序

+   **加载操作：**这些可以具有`memory_order_relaxed`、`memory_order_consume`、`memory_order_acquire`或`memory_order_seq_cst`排序

+   **读-修改-写操作：**这些操作可以具有`memory_order_relaxed`、`memory_order_consume`、`memory_order_acquire`、`memory_order_release`、`memory_order_acq_rel`或`memory_order_seq_cst`排序

所有原子操作的默认内存排序都是`memory_order_seq_cst`。

与传统的标准 C++类型相比，标准原子类型不可*复制*或*赋值*。这意味着它们没有复制构造函数或复制赋值运算符。除了直接成员函数外，它们还支持从和到相应的内置类型的隐式转换。原子类型的所有操作都被定义为原子操作，赋值和复制构造涉及两个对象。涉及两个不同对象的操作不能是原子的。在这两个操作中，值必须从一个对象读取并写入另一个对象。因此，这些操作不能被视为原子操作。

现在，让我们看看您可以在每种标准原子类型上执行的操作，从`std::atomic_flag`开始。

# std::atomic_flag

`std::atomic_flag`表示一个布尔标志，它是标准库中所有原子类型中最简单的。这是唯一一个在每个平台上所有操作都需要是*无锁*的类型。这种类型非常基础，因此只用作构建块。

`std::atomic_flag`对象必须始终使用`ATOMIC_FLAG_INIT`进行初始化，以将状态设置为*clear*：

```cpp
std::atomic_flag flg = ATOMIC_FLAG_INIT;
```

这是唯一需要这种初始化的原子类型，无论其声明的范围如何。一旦初始化，只有三种操作可以使用这种类型：销毁它，清除它，或者设置一个查询以获取先前的值。这分别对应于析构函数、`clear()`成员函数和`test_and_set()`成员函数。`clear()`是一个*存储*操作，而`test_and_set()`是一个读-修改-写操作，正如前一节中所讨论的：

```cpp
flg.clear()
bool val = flg.test_and_set(std::memory_order_relaxed);
```

在上述代码片段中，`clear()`函数调用请求使用默认内存顺序清除标志，即`std::memory_order_seq_cst`，而`test_and_set()`的调用使用了松散的语义（更多信息请参阅*松散排序*），这些语义明确用于设置标志和检索旧值。

`std::atomic_flag`的原始实现使其成为自旋锁互斥量的理想选择。让我们看一个自旋锁的例子：

```cpp
class spin_lock
{
    std::atomic_flag flg;
    public:
    spin_lock() : flg(ATOMIC_FLAG_INIT){}
    void lock() {
        // simulates a lock here... and spin
        while (flg.test_and_set(std::memory_order_acquire));
        //----- Do some action here
        //----- Often , the code to be guarded will be sequenced as
        // sp.lock() ...... Action_to_Guard() .....sp.unlock()
    }
    void unlock() {
        //------ End of Section to be guarded
        flg.clear(std::memory_order_release); // release lock
    }
};
```

在上述代码片段中，实例变量`flg`（类型为`std::atomic_flag`）最初被清除。在锁定方法中，它尝试通过测试`flg`来设置标志，以查看值是否被清除。

如果值被清除，值将被设置，我们将退出循环。只有当`unlock()`方法清除标志时，标志中的值才会被重置。换句话说，这种实现通过在`lock()`中进行忙等待来实现互斥排他。

由于其限制，`std::atomic_flag`不能用作布尔原子类型，并且不支持任何*非修改查询*操作。因此，让我们研究`std::atomic<bool>`来弥补原子布尔标志的要求。

# std::atomic<bool>

与`std::atomic_flag`相比，`std::atomic<bool>`是一个功能齐全的原子布尔类型。但是，这种类型既不能进行复制构造，也不能进行赋值。`std::atomic<bool>`对象的值最初可以是`true`或`false`。此类型的对象可以从非原子`bool`构造或赋值：

```cpp
std::atomic<bool> flg(true);
flg = false;
```

关于原子类型的赋值运算符需要注意一点，即该运算符返回非原子类型的值，而不是返回引用，这与传统方案不同。如果返回引用而不是值，那么会出现这样一种情况，即赋值的结果会得到另一个线程的修改结果，即如果它依赖于赋值运算符的结果。通过将赋值运算符的结果作为非原子值返回，可以避免这种额外的加载，并且您可以推断得到的值是实际存储的值。

现在，让我们继续讨论`std::atomic<bool>`支持的操作。首先，`store()`成员函数可用于`std::atomic<bool>`的写操作（`true`或`false`），它取代了`std::atomic_flag`的相应的限制性`clear()`函数。此外，`store()`函数是一个原子存储操作。类似地，`test_and_set()`函数已经被更通用的`exchange()`成员函数有效地取代，它允许您用选择的新值替换存储的值并检索原始值。这是一个原子的*读-修改-写*操作。然后，`std::atomic<bool>`支持通过显式调用`load()`进行简单的非修改查询值的操作，这是一个原子加载操作：

```cpp
std::atomic<bool> flg;
flg.store(true);
bool val = flg.load(std::memory_order_acquire);
val = flg.exchange(false, std::memory_order_acq_rel);
```

除了`exchange()`之外，`std::atomic<bool>`还引入了一个执行流行的原子**比较和交换**（**CAS**）指令的操作来执行*读-修改-写*操作。此操作在当前值等于期望值时存储新值。这称为比较/交换操作。标准库原子类型中有两种实现此操作的方式：`compare_exchange_weak()`和`compare_exchange_strong()`。此操作将原子变量的值与提供的期望值进行比较，并在它们相等时存储提供的值。如果这些值不相等，则更新期望值为原子变量的实际值。比较/交换函数的返回类型是*bool*，如果执行了存储，则为`true`；否则为`false`。

对于`compare_exchange_weak()`，即使期望值和原始值相等，存储也可能不成功。在这种情况下，值的交换不会发生，函数将返回`false`。这在缺乏单个比较和交换指令的平台上最常见，这意味着处理器无法保证操作将被原子执行。在这样的机器上，执行操作的线程可能在执行与操作相关的指令序列的一半时被切换出去，并且操作系统会以更多线程运行而不是可用处理器数量的条件安排另一个线程代替它。这种情况被称为**虚假失败**。

由于`compare_exchange_weak()`可能导致虚假失败，应该在循环中使用：

```cpp
bool expected = false;
atomic<bool> flg;
...
while(!flg.compare_exchange_weak(expected, true));
```

在上述代码中，只要 expected 为`false`，循环就会继续迭代，并且它表示`compare_exchange_weak()`调用发生了虚假失败。相反，如果实际值不等于期望值，`compare_exchange_strong()`保证返回`false`。这可以避免在以前的情况下需要循环来了解变量状态与运行线程的情况。

比较/交换函数可以接受两个内存排序参数，以允许在成功和失败的情况下内存排序语义不同。这些内存排序语义仅对存储操作有效，不能用于失败情况，因为存储操作不会发生：

```cpp
bool expected;
std::atomic<bool> flg;
b.compare_exchange_weak(expected, true, std::memory_order_acq_rel, std::memory_order_acquire);
b.compare_exchange_weak(expected, true, std::memory_order_release);
```

如果您不指定任何内存排序语义，对于成功和失败的情况都将采用默认的`memory_order_seq_cst`。如果您不为失败指定任何排序，那么假定与成功的排序相同，只是省略了排序的释放部分。`memory_order_acq_rel`变为`memory_order_acquire`，`memory_order_release`变为`memory_order_relaxed`。

内存排序的规范和后果将在本章的*内存排序*部分详细讨论。现在，让我们看看原子整数类型作为一组的用法。

# 标准原子整数类型

与`std::atomic<bool>`类似，标准原子整数类型既不能进行复制构造，也不能进行复制赋值。但是，它们可以从相应的非原子标准变体构造和赋值。除了强制的`is_lock_free()`成员函数之外，标准原子整数类型，比如`std::atomic<int>`或`std::atomic<unsigned long long>`，还有`load()`、`store()`、`exchange()`、`compare_exchange_weak()`和`compare_exchange_strong()`成员函数，其语义与`std::atomic<bool>`的类似。

原子类型的整数变体支持数学运算，比如`fetch_add()`、`fetch_sub()`、`fetch_and()`、`fetch_or()`和`fetch_xor()`，复合赋值运算符(`+=`、`-=`、`&=`、`|=`和`^=`)，以及`++`和`--`的前置和后置递增和递减运算符。

命名函数，比如`fetch_add()`和`fetch_sub()`，会原子地执行它们的操作并返回旧值，但复合赋值运算符会返回新值。前置和后置递增/递减按照通常的 C/C++约定工作：后置递增/递减执行操作，但返回旧值，而前置递增/递减运算符执行操作并返回新值。下面的简单示例可以很容易地演示这些操作的规范：

```cpp
int main() 
{ 
std::atomic<int> value; 

std::cout << "Result returned from Operation: " << value.fetch_add(5) << 'n'; 
std::cout << "Result after Operation: " << value << 'n'; 

std::cout << "Result returned from Operation: " << value.fetch_sub(3) << 'n'; 
std::cout << "Result after Operation: " << value << 'n'; 

std::cout << "Result returned from Operation: " << value++ << 'n'; 
std::cout << "Result after Operation: " << value << 'n'; 

std::cout << "Result returned from Operation: " << ++value << 'n'; 
std::cout << "Result after Operation: " << value << 'n'; 

value += 1; 
std::cout << "Result after Operation: " << value << 'n'; 

value -= 1; 
std::cout << "Result after Operation: " << value << 'n'; 
} 
```

此代码的输出应如下所示：

```cpp
Result returned from Operation: 0 
Result after Operation: 5 
Result returned from Operation: 5 
Result after Operation: 2 
Result returned from Operation: 2 
Result after Operation: 3 
Result returned from Operation: 4 
Result after Operation: 4 
Result after Operation: 5 
Result after Operation: 4 
```

除了`std::atomic_flag`和`std::atomic<bool>`之外，第一张表中列出的所有其他原子类型都是原子整数类型。现在，让我们来看一下原子指针特化，`std::atomic<T*>`。

# std::atomic<T*> – 指针算术

除了通常的操作，比如`load()`、`store()`、`exchange()`、`compare_exchange_weak()`和`compare_exchange_strong()`之外，原子指针类型还加载了指针算术操作。成员函数`fetch_add()`和`fetch_sub()`提供了对类型进行原子加法和减法的操作支持，运算符`+=`和`-=`，以及前置和后置递增/递减，使用`++`和`--`运算符。

运算符的工作方式与标准的非原子指针算术运算相同。如果`obj`是`std::atomic<some_class*>`，则对象指向`some_class`对象数组的第一个条目。`obj+=2`将其更改为指向数组中的第三个元素，并返回一个指向数组中第三个元素的`some_class*`的原始指针。如*标准原子整数类型*部分所讨论的，诸如`fetch_add()`和`fetch_sub`之类的命名函数在原子类型上执行操作，但返回数组中第一个元素的指针。

原子操作的函数形式还允许在函数调用的附加参数中指定内存排序语义：

```cpp
obj.fetch_add(3, std::memory_order_release);
```

由于`fetch_add()`和`fetch_sub`都是读取-修改-写操作，它们可以在标准原子库中使用任何内存排序语义。但是，对于操作符形式，无法指定内存排序，因此这些操作符将始终具有`memory_order_seq_cst`语义。

# std::atomic<>主类模板

标准库中的主要类模板允许用户创建**用户定义类型**（**UDT**）的原子变体。要将用户定义类型用作原子类型，您必须在实现类之前遵循一些标准。对于用户定义类 UDT，如果该类型具有平凡的复制赋值运算符，则`std::atomic<UDT>`是可能的。这意味着用户定义类不应包含任何虚函数或虚基类，并且必须使用编译器生成的默认复制赋值运算符。此外，用户定义类的每个基类和非静态数据成员必须具有平凡的复制赋值运算符。这使得编译器可以执行`memcpy()`或等效的操作以进行赋值操作，因为没有用户编写的代码需要执行。

除了赋值运算符的要求之外，用户定义类型必须是*位相等可比*的。这意味着您必须能够使用`memcmp()`比较实例是否相等。这个保证是必需的，以确保比较/交换操作能够正常工作。

对于具有用户定义类型`T`的标准原子类型的实例，即`std::atomic<T>`，接口仅限于`std::atomic<bool>`可用的操作：`load()`，`store()`，`exchange()`，`compare_exchange_weak()`，`compare_exchange_strong()`和对类型`T`的实例的赋值和转换。

# 内存排序

我们已经了解了标准库中可用的原子类型和原子操作。在对原子类型执行操作时，我们需要为某些操作指定内存排序。现在，我们将讨论不同内存排序语义的重要性和用例。原子操作背后的关键思想是在多个线程之间提供数据访问的同步，并通过强制执行执行顺序来实现这一点。例如，如果写入数据发生在读取数据之前，那么一切都会很好。否则，你就麻烦了！标准库提供了六种内存排序选项，可应用于原子类型的操作：`memory_order_relaxed`，`memory_order_consume`，`memory_order_acquire`，`memory_order_release`，`memory_order_acq_rel`和`memory_order_seq_cst`。对于所有原子类型的原子操作，`memory_order_seq_cst`是默认的内存顺序，除非您指定其他内容。

这六个选项可以分为三类：

+   顺序一致排序：`memory_order_seq_cst`

+   **获取-释放排序**：`memory_order_consume`，`memory_order_release`，`memory_order_acquire`和`memory_order_acq_rel`

+   **松散排序**：`memory_order_relaxed`

执行成本因不同的 CPU 和不同的内存排序模型而异。不同的内存排序模型的可用性允许专家利用比阻塞顺序一致排序更精细的排序关系来提高性能，但是要选择适当的内存模型，就应该了解这些选项如何影响程序的行为。让我们首先看看顺序一致性模型。

# 顺序一致性

顺序一致性的概念是由 Leslie Lamport 在 1979 年定义的。顺序一致性在程序执行中提供了两个保证。首先，程序的指令的内存排序按照源代码顺序执行，或者编译器将保证源代码顺序的幻觉。然后，所有线程中所有原子操作的全局顺序。

对于程序员来说，顺序一致性的全局排序行为，即所有线程中的所有操作都在全局时钟中发生，是一个有趣的高地，但也是一个缺点。

关于顺序一致性的有趣之处在于，代码按照我们对多个并发线程的直觉工作，但系统需要做大量的后台工作。以下程序是一个简单的示例，让我们了解顺序一致性：

```cpp
std::string result; 
std::atomic<bool> ready(false); 

void thread1() 
{ 
    while(!ready.load(std::memory_order_seq_cst)); 
    result += "consistency"; 
} 

void thread2() 
{ 
    result = "sequential "; 
    ready=true; 
} 

int main() 
{ 
    std::thread t1(thread1); 
    std::thread t2(thread2); 
    t1.join(); 
    t2.join(); 

    std::cout << "Result : " << result << 'n'; 
} 

```

前面的程序使用顺序一致性来同步线程`thread1`和`thread2`。由于顺序一致性，执行是完全*确定*的，因此该程序的输出始终如下：

```cpp
Result : sequential consistency 
```

在这里，`thread1`在 while 循环中等待，直到原子变量`ready`为`true`。一旦`thread2`中的*ready*变为`true`，`thread1`就会继续执行，因此结果总是以相同的顺序更新字符串。顺序一致性的使用允许两个线程以相同的顺序看到其他线程的操作，因此两个线程都遵循相同的全局时钟。循环语句还有助于保持两个线程的同步的时间时钟。

*获取-释放语义*的细节将在下一节中介绍。

# 获取-释放排序

现在，让我们深入研究 C++标准库提供的内存排序语义。这是程序员对多线程代码中排序的直觉开始消失的地方，因为在原子操作的获取-释放语义中，线程之间没有全局同步。这些语义只允许在同一原子变量上的原子操作之间进行同步。简而言之，一个线程上的原子变量的加载操作可以与另一个线程上同一原子变量的存储操作进行同步。程序员必须提取这个特性，建立原子变量之间的*happen-before*关系，以实现线程之间的同步。这使得使用获取-释放模型有点困难，但同时也更加刺激。获取-释放语义缩短了通向无锁编程的道路，因为你不需要担心线程的同步，但需要思考的是不同线程中相同原子变量的同步。

正如我们之前解释的，获取-释放语义的关键思想是在同一原子变量上的释放操作与获取操作之间的同步，并建立一个*ordering constant*。现在，顾名思义，获取操作涉及获取锁，其中包括用于读取原子变量的操作，如`load()`和`test_and_set()`函数。因此，释放锁是一个释放操作，其中包括`store()`和`clear()`等原子操作。

换句话说，*mutex*的锁是一个获取操作，而解锁是一个释放操作。因此，在*临界区*中，对变量的操作不能在任何方向上进行。但是，变量可以从外部移入临界区，因为变量从一个未受保护的区域移动到了一个受保护的区域。这在下图中表示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-rct-prog/img/688c368f-57ff-42a4-b55c-54a8feabee4b.png)

临界区包含单向屏障：获取屏障和释放屏障。相同的推理也可以应用于启动线程和在线程上放置 join 调用，以及标准库中提供的所有其他同步原语相关的操作。

由于同步是在原子变量级别而不是线程级别进行的，让我们重新审视一下使用`std::atomic_flag`实现的自旋锁：

```cpp
class spin_lock 
{ 
    std::atomic_flag flg; 

public: 
    spin_lock() : flg(ATOMIC_FLAG_INIT) 
    {} 

    void lock() 
    { 
        // acquire lock and spin 
        while (flg.test_and_set(std::memory_order_acquire)); 
    } 

    void unlock() 
    { 
        // release lock 
        flg.clear(std::memory_order_release); 
    } 
}; 
```

在这段代码中，`lock()`函数是一个`acquire`操作。现在不再使用前一个示例中使用的默认顺序一致的内存排序，而是现在使用了显式的 acquire 内存排序标志。此外，`unlock()`函数，也是一个释放操作，之前也是使用默认的内存顺序，现在已经被替换为显式的释放语义。因此，两个线程的顺序一致的重量级同步被轻量级和高性能的 acquire-release 语义所取代。

当使用`spin_lock`的线程数量超过两个时，使用`std::memory_order_acquire`的一般获取语义将不足够，因为锁方法变成了一个获取-释放操作。因此，内存模型必须更改为`std::memory_order_acq_rel`。

到目前为止，我们已经看到顺序一致的排序确保了线程之间的同步，而获取-释放排序在多个线程上确立了对同一原子变量的读写操作的顺序。现在，让我们看一下松散内存排序的规范。

# 松散排序

使用标签`std::memory_order_relaxed`进行松散内存排序的原子类型的操作不是同步操作。与标准库中提供的其他排序选项相比，它们不会对并发内存访问施加顺序。松散内存排序语义只保证同一线程内相同原子类型的操作不能被重新排序，这个保证被称为**修改顺序一致性**。事实上，松散排序只保证了原子性和修改顺序一致性。因此，其他线程可以以不同的顺序看到这些操作。

松散内存排序可以有效地用于不需要同步或排序的地方，并且原子性可以成为性能提升的一个优势。一个典型的例子是增加计数器，比如**std::shared_ptr**的引用计数器，它们只需要原子性。但是减少引用计数需要与这个模板类的析构函数进行获取-释放同步。

让我们看一个简单的例子来计算使用松散排序生成的线程数量：

```cpp
std::atomic<int> count = {0}; 

void func() 
{ 
    count.fetch_add(1, std::memory_order_relaxed); 
} 

int main() 
{ 
    std::vector<std::thread> v; 
    for (int n = 0; n < 10; ++n) 
    { 
        v.emplace_back(func); 
    } 
    for (auto& t : v) 
    { 
        t.join(); 
    } 

    std::cout << "Number of spawned threads : " << count << 'n'; 
} 
```

在这段代码中，从`main()`函数生成了十个线程，每个线程都使用线程函数`func()`，在每个线程上，使用原子操作`fetch_add()`将原子整数值增加一。与`std::atomic<int>`提供的复合赋值运算符和后置和前置递增运算符相反，`fetch_add()`函数可以接受内存排序参数，它是`std::memory_order_relaxed`。

程序打印出程序中生成的线程数量如下：

```cpp
Number of spawned threads : 10 
```

程序的输出对于任何其他相关的内存排序标签都是相同的，但是松散的内存排序确保了原子性，从而提高了性能。

到目前为止，我们已经讨论了不同内存模型的级别，以及它们对原子和非原子操作的影响。现在，让我们深入研究使用原子操作实现无锁数据结构。

# 无锁数据结构队列

正如我们已经知道的，实际系统中的数据通常以数据结构的形式表示，当涉及到数据结构的并发操作时，性能是一个大问题。在[第三章](https://cdp.packtpub.com/c___reactive_programming/wp-admin/post.php?post=48&action=edit#post_40)中，*C++中的语言级并发和并行性*，我们学习了如何编写一个线程安全的栈。然而，我们使用了锁和条件变量来实现它。为了解释如何编写一个无锁数据结构，让我们使用生产者/消费者范式来编写一个非常基本的队列系统，而不使用锁或条件变量。这肯定会提高代码的性能。我们不使用标准数据类型的包装器，而是从头开始编写。我们假设在这种情况下有一个生产者和一个消费者：

```cpp
template<typename T> 
class Lock_free_Queue 
{ 
private: 
    struct Node 
    { 
        std::shared_ptr<T> my_data; 
        Node* my_next_node; 
        Node() : my_next_node(nullptr) 
        {} 
    }; 

    std::atomic<Node*> my_head_node; 
    std::atomic<Node*> my_tail_node; 

    Node* pop_head_node() 
    { 
        Node* const old_head_node = my_head_node.load(); 
        if(old_head_node == my_tail_node.load()) 
        { 
            return nullptr; 
        } 
        my_head_node.store(old_head_node->my_next_node); 
        return old_head_node; 
    } 
```

`Lock_free_stack`类包含一个用于表示队列节点的结构（命名为`Node`），其中包含用于表示节点数据（`my_data`）和指向下一个节点的指针的数据成员。然后，该类包含两个原子指针实例，指向用户定义的结构`Node`，该结构已在类内部定义。一个实例存储队列头节点的指针，而另一个指向尾节点。最后，使用`private pop_head_node()`函数通过调用原子*store*操作来检索队列的头节点，但仅当队列包含至少一个元素时。在这里，原子操作遵循默认的顺序一致的内存排序语义：

```cpp
public: 
Lock_free_Queue() : my_head_node(new Node), my_tail_node(my_head_node.load()) 
    {} 
    Lock_free_Queue(const Lock_free_Queue& other) = delete; 
    Lock_free_Queue& operator= (const Lock_free_Queue& other) = delete; 

    ~Lock_free_Queue() 
    { 
        while(Node* const old_head_node = my_head_node.load()) 
        { 
            my_head_node.store(old_head_node->my_next_node); 
            delete old_head_node; 
        } 
    }
```

头节点在队列对象构造时被实例化，并且尾部指向该内存。复制构造函数和复制赋值运算符被标记为删除，以防止它们被使用。在析构函数内，队列中的所有元素都被迭代删除：

```cpp
    std::shared_ptr<T> dequeue() 
    { 
        Node* old_head_node = pop_head_node(); 
        if(!old_head_node) 
        { 
            return std::shared_ptr<T>(); 
        } 
        std::shared_ptr<T> const result(old_head_node->my_data); 
        delete old_head_node; 
        return result; 
    } 

    void enqueue(T new_value) 
    { 
        std::shared_ptr<T> new_data(std::make_shared<T>(new_value)); 
        Node* p = new Node; 
        Node* const old_tail_node = my_tail_node.load(); 
        old_tail_node->my_data.swap(new_data); 
        old_tail_node->my_next_node = p; 
        my_tail_node.store(p); 
    } 
}; 
```

前面的代码片段实现了标准队列操作，即 Enqueue 和 Dequeue。在这里，我们使用了 swap 和 store 原子操作，确保 Enqueue 和 Dequeue 之间存在*happens before*关系。

# 摘要

在本章中，我们讨论了标准库提供的用于编写基于任务的并行性的工具。我们看到了如何使用`std::packaged_task`和`std::async`与 futures 和 promises。我们讨论了现代 C++语言提供的新的多线程感知内存模型。之后，我们讨论了原子类型及其相关操作。我们学到的最重要的事情是语言的各种内存排序语义。简而言之，这一章和前一章将使我们能够推理响应式编程模型的并发方面。

在接下来的章节中，我们将把注意力从语言和并发转移到响应式编程模型的标准接口。我们将介绍 Observables！


# 第五章：Observables 的介绍

在最后三章中，我们学习了现代 C++的语言特性：多线程、无锁编程模型等。那里涵盖的主题可以被视为开始学习响应式编程模型的先决条件。响应式编程模型需要掌握函数式编程、并发编程、调度器、对象/函数式编程、设计模式和事件流处理等技能。我们已经在上一章中涵盖或涉及了函数式编程、对象/函数式编程以及与调度相关的一些主题。这次，我们将涵盖设计模式的精彩世界，以理解响应式编程的要点以及特别是 Observables。在下一章中，我们将在跳入 RxCpp 库之前处理事件流编程的主题。设计模式运动随着一本名为*设计模式：可复用面向对象软件的元素*的书籍的出版而达到了临界质量，这本书由**四人帮**（**GoF**）编写，其中列出了一组分为创建型、结构型和行为型家族的 23 种模式。GoF 目录将观察者模式定义为行为模式的一种。我们想要在这里传达的一个关键信息是，通过了解可敬的 GoF 模式，可以理解响应式编程模型。在本章中，我们将涵盖：

+   GoF 观察者模式

+   GoF 观察者模式的局限性

+   对设计模式和 Observables 进行全面审视

+   使用复合设计模式对建模现实世界的层次结构

+   使用访问者对复合物进行行为处理

+   将复合物扁平化并通过迭代器模式进行导航

+   通过改变视角，从迭代器转换为 Observable/Observer！

# GoF 观察者模式

GoF 观察者模式在 GoF 书中也被称为*发布-订阅模式*。这个想法很简单。`EventSource`（发出事件的类）将与事件接收器（监听事件通知的类）建立一对多的关系。每个`EventSource`都将有一个机制，让事件接收器订阅以获取不同类型的通知。单个`EventSource`可能会发出多个事件。当`EventSource`的状态发生变化或其领域发生重大事件时，它可以向成千上万的订阅者（事件接收器或监听器）发送通知。`EventSource`将遍历订阅者列表并逐个通知它们。GoF 书是在世界大多数时间都在进行顺序编程的时候编写的。诸如并发性之类的主题大多与特定于平台的库或`POSIX`线程库相关。我们将编写一个简单的 C++程序来演示观察者模式的整个思想。目的是快速理解观察者模式，鲁棒性等想法被次要地给予了优先级。这个清单是自包含的并且容易理解的：

```cpp
//-------------------- Observer.cpp 
#include <iostream> 
#include  <vector> 
#include <memory> 
using namespace std; 
//---- Forward declaration of event sink 
template<class T> 
class EventSourceValueObserver; 
//----------A toy implementation of EventSource
template<class T> 
class EventSourceValueSubject{ 
   vector<EventSourceValueObserver<T> *> sinks;  
   T State; // T is expected to be a value type 
  public: 
   EventSourceValueSubject() { State = 0; } 
   ~EventSourceValueSubject() { 
       sinks.clear(); 
   } 
   bool Subscribe( EventSourceValueObserver<T> *sink ) { sinks.push_back(sink);} 
   void NotifyAll() { for (auto sink : sinks) { sink->Update(State); }} 
   T GetState() { return State; } 
   void SetState(T pstate) { State = pstate; NotifyAll(); } 
};
```

上面的代码片段实现了一个微不足道的`EventSource`，它可以潜在地存储一个整数值作为状态。在现代 C++中，我们可以使用类型特征来检测消费者是否已经用整数类型实例化了这个类。由于我们的重点是阐明，我们没有添加与类型约束相关的断言。在下一个 C++标准中，有一个称为**concept**（在其他语言中称为约束）的概念，将有助于直接强制执行这一点（而不需要类型特征）。在现实生活中，`EventSource`可能存储大量变量或值流。对它们的任何更改都将广播给所有订阅者。在`SetState`方法中，当`EventSource`类的消费者（事件接收器本身是这个类中的消费者）改变状态时，`NotifyAll()`方法将被触发。`NotifyAll()`方法通过接收器列表工作，并调用`Update()`方法。然后，事件接收器可以执行特定于其上下文的任务。我们没有实现取消订阅等方法，以便专注于核心问题：

```cpp
//--------------------- An event sink class for the preceding EventSources 
template <class T> 
class EventSourceValueObserver{ 
    T OldState; 
  public: 
    EventSourceValueObserver() { OldState = 0; } 
    virtual ~EventSorceValueObserver() {} 
    virtual void Update( T State ) { 
       cout << "Old State " << OldState << endl; 
       OldState = State; 
       cout << "Current State " << State << endl;  
    } 
}; 
```

`EventSourceValueObserver`类已经实现了`Update`方法来执行与其上下文相关的任务。在这里，它只是将旧状态和当前状态的值打印到控制台上。在现实生活中，接收器可能会修改 UX 元素或通过通知将状态的传播传递给其他对象。让我们再写一个事件接收器，它将继承自`EventSourceValueObserver`：

```cpp
//------------ A simple specialized Observe 
class AnotherObserver : public EventSourceValueObserver<double> { 
  public: 
    AnotherObserver():EventSourceValueObserver() {} 
    virtual ~AnotherObserver() {} 
    virtual void Update( double State )  
    { cout << " Specialized Observer" << State <<  endl; } 
};
```

我们为演示目的实现了观察者的专门版本。这样做是为了表明我们可以有两个类的实例（可以从`EventSourceObserver<T>`继承）作为订阅者。在这里，当我们从`EventSource`收到通知时，我们也不做太多事情：

```cpp
int main() { 
   unique_ptr<EventSourceValueSubject<double>> 
                 evsrc(new EventSourceValueSubject<double>()); 
    //---- Create Two instance of Observer and Subscribe 
   unique_ptr<AnotherObserver> evobs( new AnotherObserver());
   unique_ptr<EventSourceValueObserver<double>> 
               evobs2( new EventSourceValueObserver<double>());
   evsrc->Subscribe( evobs.get() );
   evsrc->Subscribe( evobs2.get());
   //------ Change the State of the EventSource 
   //------ This should trigger call to Update of the Sink 
   evsrc->SetState(100); 
} 
```

上面的代码片段实例化了一个`EventSource`对象并添加了两个订阅者。当我们改变`EventSource`的状态时，订阅者将收到通知。这是观察者模式的关键。在普通的面向对象编程程序中，对象的消费是以以下方式进行的：

1.  实例化对象

1.  调用方法计算某个值或改变状态

1.  根据返回值或状态变化执行有用的操作

在这里，在观察者的情况下，我们已经做了以下工作：

1.  实例化对象（`EventSource`）

1.  通过实现观察者（用于事件监听）进行通知订阅

1.  当`EventSource`发生变化时，您将收到通知

1.  对通过通知接收到的值执行某些操作

这里概述的`Method`函数有助于关注点的分离，并实现了模块化。这是实现事件驱动代码的良好机制。与其轮询事件，不如要求被通知。大多数 GUI 工具包今天都使用类似的范例。

# GoF 观察者模式的局限性

GoF 模式书是在世界真正进行顺序编程的时候编写的。从当前的编程模型世界观来看，观察者模式实现的架构有很多异常。以下是其中一些：

+   主题和观察者之间的紧密耦合。

+   `EventSource`的生命周期由观察者控制。

+   观察者（接收器）可以阻塞`EventSource`。

+   实现不是线程安全的。

+   事件过滤是在接收器级别进行的。理想情况下，数据应该在数据所在的地方（在通知之前的主题级别）进行过滤。

+   大多数时候，观察者并不做太多事情，CPU 周期将被浪费。

+   `EventSource`理想上应该将值发布到环境中。环境应该通知所有订阅者。这种间接层次可以促进诸如事件聚合、事件转换、事件过滤和规范化事件数据等技术。

随着不可变变量、函数式组合、函数式风格转换、无锁并发编程等功能编程技术的出现，我们可以规避经典 Observer 模式的限制。行业提出的解决方案是 Observables 的概念。

在经典 Observer 模式中，一个勤奋的读者可能已经看到了异步编程模型被整合的潜力。`EventSource`可以对订阅者方法进行异步调用，而不是顺序循环订阅者。通过使用一种“发射并忘记”的机制，我们可以将`EventSource`与其接收器解耦。调用可以从后台线程、异步任务或打包任务，或适合上下文的合适机制进行。通知方法的异步调用具有额外的优势，即如果任何客户端阻塞（进入无限循环或崩溃），其他客户端仍然可以收到通知。异步方法遵循以下模式：

1.  定义处理数据、异常和数据结束的方法（在事件接收器方面）

1.  Observer（事件接收器）接口应该有`OnData`、`OnError`和`OnCompleted`方法

1.  每个事件接收器应该实现 Observer 接口

1.  每个`EventSource`（Observable）应该有订阅和取消订阅的方法

1.  事件接收器应该通过订阅方法订阅 Observable 的实例

1.  当事件发生时，Observable 会通知 Observer

这些事情有些已经在第一章中提到过，*响应式编程模型-概述和历史*。当时我们没有涉及异步部分。在本章中，我们将重新审视这些想法。根据作者们在技术演示和与开发人员的互动中积累的经验，直接跳入编程的 Observable/Observer 模型并不能帮助理解。大多数开发人员对 Observable/Observer 感到困惑，因为他们不知道这种模式解决了什么特定的问题。这里给出的经典 GoF Observer 实现是为了为 Observable Streams 的讨论设定背景。

# 对 GoF 模式的整体观察

设计模式运动始于一个时期，当时世界正在努力应对面向对象软件设计方法的复杂性。GoF 书籍和相关的模式目录为开发人员提供了一套设计大型系统的技术。诸如并发和并行性之类的主题并不在设计目录的设计者们的考虑之中。（至少，他们的工作没有反映出这一点！）

我们已经看到，通过经典 Observer 模式进行事件处理存在一些局限性，这在某些情况下可能是个问题。有什么办法？我们需要重新审视事件处理的问题，退一步。我们将稍微涉及一些哲学的主题，以不同的视角看待响应式编程模型（使用 Observable Streams 进行编程！）试图解决的问题。我们的旅程将帮助我们从 GOF 模式过渡到使用函数式编程构造的响应式编程世界。

本节中的内容有些抽象，并且是为了提供一个概念性背景，从这个背景中，本书的作者们接触了本章涵盖的主题。我们解释 Observables 的方法是从 GoF Composite/Visitor 模式开始，逐步达到 Observables 的主题。这种方法的想法来自一本关于阿德瓦伊塔·维丹塔（Advaita Vedanta）的书，这是一种起源于印度的神秘哲学传统。这个主题已经用西方哲学术语解释过。如果某个问题看起来有点抽象，可以随意忽略它。

Nataraja Guru（1895-1973）是一位印度哲学家，他是阿德瓦伊塔维达塔哲学的倡导者，这是一所基于至高力量的非二元论的印度哲学学派。根据这个哲学学派，我们周围所看到的一切，无论是人类、动物还是植物，都是绝对（梵文中称为婆罗门）的表现，它唯一的积极肯定是 SAT-CHIT-ANAND（维达塔哲学使用否定和反证来描述婆罗门）。这可以被翻译成英语为存在、本质和幸福（这里幸福的隐含含义是“好”）。在 DK Print World 出版的一本名为《统一哲学》的书中，他将 SAT-CHIT-ANAND 映射到本体论、认识论和价值论（哲学的三个主要分支）。以下表格给出了 SAT-CHIT-ANAND 可能与其他意义相近的实体的映射。

| **SAT** | **CHIT** | **ANAND** |
| --- | --- | --- |
| 存在 | 本质 | 幸福 |
| 本体论 | 认识论 | 价值论 |
| 我是谁？ | 我能知道什么？ | 我应该做什么？ |
| 结构 | 行为 | 功能 |

在 Vedanta（阿德瓦伊塔学派）哲学中，整个世界被视为存在、本质和幸福。从表中，我们将软件设计世界中的问题映射为结构、行为和功能的问题。世界上的每个系统都可以从结构、行为和功能的角度来看待。面向对象程序的规范结构是层次结构。我们将感兴趣的世界建模为层次结构，并以规范的方式处理它们。GOF 模式目录中有组合模式（结构）用于建模层次结构和访问者模式（行为）用于处理它们。

# 面向对象编程模型和层次结构

这一部分在概念上有些复杂，那些没有涉足过 GoF 设计模式的人可能会觉得有些困难。最好的策略可能是跳过这一部分，专注于运行示例。一旦理解了运行示例，就可以重新访问这一部分。

面向对象编程非常擅长建模层次结构。事实上，层次结构可以被认为是面向对象数据处理的规范数据模型。在 GoF 模式世界中，我们使用组合模式来建模层次结构。组合模式被归类为结构模式。每当使用组合模式时，访问者模式也将成为系统的一部分。访问者模式适用于处理组合以向结构添加行为。访问者/组合模式在现实生活中成对出现。当然，组合的一个实例可以由不同的访问者处理。在编译器项目中，**抽象语法树**（**AST**）将被建模为一个组合，并且将有访问者实现用于类型检查、代码优化、代码生成和静态分析等。

访问者模式的问题之一是它必须对组合的结构有一定的概念才能进行处理。此外，在需要处理组合层次结构中可用数据的筛选子集的上下文中，它将导致代码膨胀。我们可能需要为每个过滤条件使用不同的访问者。GoF 模式目录中还有另一个属于行为类别的模式，称为 Iterator，这是每个 C++程序员都熟悉的东西。Iterator 模式擅长以结构无关的方式处理数据。任何层次结构都必须被线性化或扁平化，以便被 Iterator 处理。例如，树可以使用 BFS Iterator 或 DFS Iterator 进行处理。对于应用程序员来说，树突然变成了线性结构。我们需要将层次结构扁平化，使其处于适合 Iterator 处理的状态。这个过程将由实现 API 的人来实现。Iterator 模式也有一些局限性（它是基于拉的），我们将通过一种称为 Observable/Observer 的模式将系统改为基于推的。这一部分有点抽象，但在阅读整个章节后，你可以回来理解发生了什么。简而言之，我们可以总结整个过程如下：

+   我们可以使用组合模式来建模层次结构

+   我们可以使用 Visitor 模式处理组合

+   我们可以通过 Iterator 来展开或线性化组合

+   Iterators 遵循拉取方法，我们需要为基于推的方案逆转视线

+   现在，我们已经成功地实现了 Observable/Observer 的方式来实现事物

+   Observables 和 Iterators 是二进制对立的（一个人的推是另一个人的拉！）

我们将实现所有前述观点，以对 Observables 有牢固的基础。

# 用于表达式处理的组合/访问者模式

为了演示从 GoF 模式目录到 Observables 的过程，我们将模拟一个四则运算计算器作为一个运行示例。由于表达式树或 AST 本质上是层次结构的，它们将是一个很好的例子，可以作为组合模式的模型。我们故意省略了编写解析器，以保持代码清单的简洁：

```cpp
#include <iostream> 
#include <memory> 
#include <list> 
#include <stack> 
#include <functional> 
#include <thread> 
#include <future> 
#include <random> 
#include "FuncCompose.h" // available int the code base 
using namespace std; 
//---------------------List of operators supported by the evaluator 
enum class OPERATOR{ ILLEGAL,PLUS,MINUS,MUL,DIV,UNARY_PLUS,UNARY_MINUS };  
```

我们定义了一个枚举类型来表示四个二元运算符（`+`，`-`，`*`，`/`）和两个一元运算符（`+`，`-`）。除了标准的 C++头文件，我们还包含了一个自定义头文件（`FuncCompose.h`），它可以在与本书相关的 GitHub 存储库中找到。它包含了 Compose 函数和管道运算符（`|`）的代码，用于函数组合。我们可以使用 Unix 管道风格的组合来将一系列转换联系在一起：

```cpp
//------------ forward declarations for the Composites  
class Number;  //----- Stores IEEE double precision floating point number  
class BinaryExpr; //--- Node for Binary Expression 
class UnaryExpr;  //--- Node for Unary Expression 
class IExprVisitor; //---- Interface for the Visitor  
//---- Every node in the expression tree will inherit from the Expr class 
class Expr { 
  public: 
   //---- The standard Visitor double dispatch method 
   //---- Normally return value of accept method are void.... and Concrete
   //---- classes store the result which can be retrieved later
   virtual double accept(IExprVisitor& expr_vis) = 0; 
   virtual ~Expr() {} 
}; 
//----- The Visitor interface contains methods for each of the concrete node  
//----- Normal practice is to use 
struct IExprVisitor{ 
   virtual  double Visit(Number& num) = 0; 
   virtual  double Visit(BinaryExpr& bin) = 0; 
   virtual  double Visit(UnaryExpr& un)=0 ; 
}; 
```

Expr 类将作为表达式树中所有节点的基类。由于我们的目的是演示组合/访问者 GoF 模式，我们只支持常数、二元表达式和一元表达式。Expr 类中的 accept 方法接受一个 Visitor 引用作为参数，方法的主体对所有节点都是相同的。该方法将把调用重定向到 Visitor 实现上的适当处理程序。为了更深入地了解本节涵盖的整个主题，通过使用您喜欢的搜索引擎搜索*双重分派*和*Visitor 模式*。

Visitor 接口（`IExprVisitor`）包含处理层次结构支持的所有节点类型的方法。在我们的情况下，有处理常数、二元运算符和一元运算符的方法。让我们看看节点类型的代码。我们从 Number 类开始：

```cpp
//---------A class to represent IEEE 754 interface 
class Number : public Expr { 
   double NUM; 
  public: 
   double getNUM() { return NUM;}    
   void setNUM(double num)   { NUM = num; } 
   Number(double n) { this->NUM = n; } 
   ~Number() {} 
   double accept(IExprVisitor& expr_vis){ return expr_vis.Visit(*this);} 
}; 
```

Number 类封装了 IEEE 双精度浮点数。代码很明显，我们需要关心的只是`accept`方法的内容。该方法接收一个`visitor`类型的参数（`IExprVisitor&`）。该例程只是将调用反映到访问者实现的适当节点上。在这种情况下，它将在`IExpressionVisitor`上调用`Visit(Number&)`：

```cpp
//-------------- Modeling Binary Expresison  
class BinaryExpr : public Expr { 
   Expr* left; Expr* right; OPERATOR OP; 
  public: 
   BinaryExpr(Expr* l,Expr* r , OPERATOR op ) { left = l; right = r; OP = op;} 
   OPERATOR getOP() { return OP; } 
   Expr& getLeft() { return *left; } 
   Expr& getRight() { return *right; } 
   ~BinaryExpr() { delete left; delete right;left =0; right=0; } 
   double accept(IExprVisitor& expr_vis) { return expr_vis.Visit(*this);} 
};  
```

`BinaryExpr`类模拟了具有左右操作数的二元运算。操作数可以是层次结构中的任何类。候选类包括`Number`、`BinaryExpr`和`UnaryExpr`。这可以到任意深度。在我们的情况下，终端节点是 Number。先前的代码支持四个二元运算符：

```cpp
//-----------------Modeling Unary Expression 
class UnaryExpr : public Expr { 
   Expr * right; OPERATOR op; 
  public: 
   UnaryExpr( Expr *operand , OPERATOR op ) { right = operand;this-> op = op;} 
   Expr& getRight( ) { return *right; } 
   OPERATOR getOP() { return op; } 
   virtual ~UnaryExpr() { delete right; right = 0; } 
   double accept(IExprVisitor& expr_vis){ return expr_vis.Visit(*this);} 
};  
```

`UnaryExpr`方法模拟了带有运算符和右侧表达式的一元表达式。我们支持一元加和一元减。右侧表达式可以是`UnaryExpr`、`BinaryExpr`或`Number`。现在我们已经为所有支持的节点类型编写了实现，让我们专注于访问者接口的实现。我们将编写一个树遍历器和评估器来计算表达式的值：

```cpp
//--------An Evaluator for Expression Composite using Visitor Pattern  
class TreeEvaluatorVisitor : public IExprVisitor{ 
  public: 
   double Visit(Number& num){ return num.getNUM();} 
   double Visit(BinaryExpr& bin) { 
     OPERATOR temp = bin.getOP(); double lval = bin.getLeft().accept(*this); 
     double rval = bin.getRight().accept(*this); 
     return (temp == OPERATOR::PLUS) ? lval + rval: (temp == OPERATOR::MUL) ?  
         lval*rval : (temp == OPERATOR::DIV)? lval/rval : lval-rval;   
   } 
   double Visit(UnaryExpr& un) { 
     OPERATOR temp = un.getOP(); double rval = un.getRight().accept(*this); 
     return (temp == OPERATOR::UNARY_PLUS)  ? +rval : -rval; 
   } 
};
```

这将对 AST 进行深度优先遍历，并递归评估节点。让我们编写一个表达式处理器（`IExprVisitor`的实现），它将以**逆波兰表示法**（**RPN**）形式将表达式树打印到控制台上：

```cpp
//------------A Visitor to Print Expression in RPN
class ReversePolishEvaluator : public IExprVisitor {
    public:
    double Visit(Number& num){cout << num.getNUM() << " " << endl; return 42;}
    double Visit(BinaryExpr& bin){
        bin.getLeft().accept(*this); bin.getRight().accept(*this);
        OPERATOR temp = bin.getOP();
        cout << ( (temp==OPERATOR::PLUS) ? " + " :(temp==OPERATOR::MUL) ?
        " * " : (temp == OPERATOR::DIV) ? " / ": " - " ) ; return 42;
    }
    double Visit(UnaryExpr& un){
        OPERATOR temp = un.getOP();un.getRight().accept(*this);
        cout << (temp == OPERATOR::UNARY_PLUS) ?" (+) " : " (-) "; return 42;
    }
};
```

RPN 表示法也称为后缀表示法，其中运算符位于操作数之后。它们适合使用评估堆栈进行处理。它们构成了 Java 虚拟机和.NET CLR 所利用的基于堆栈的虚拟机架构的基础。现在，让我们编写一个主函数将所有内容整合在一起：

```cpp
int main( int argc, char **argv ){ 
     unique_ptr<Expr>   
            a(new BinaryExpr( new Number(10) , new Number(20) , OPERATOR::PLUS)); 
     unique_ptr<IExprVisitor> eval( new TreeEvaluatorVisitor()); 
     double result = a->accept(*eval); 
     cout << "Output is => " << result << endl; 
     unique_ptr<IExprVisitor>  exp(new ReversePolishEvaluator()); 
     a->accept(*exp); 
}
```

此代码片段创建了一个组合的实例（`BinaryExpr`的一个实例），并实例化了`TreeEvaluatorVisitor`和`ReversePolshEvaluator`的实例。然后，调用 Expr 的`accept`方法开始处理。我们将在控制台上看到表达式的值和表达式的 RPN 等价形式。在本节中，我们学习了如何创建一个组合，并使用访问者接口处理组合。组合/访问者的其他潜在示例包括存储目录内容及其遍历、XML 处理、文档处理等。普遍观点认为，如果您了解组合/访问者二者，那么您已经很好地理解了 GoF 模式目录。

我们已经看到，组合模式和访问者模式作为一对来处理系统的结构和行为方面，并提供一些功能。访问者必须以一种假定了组合结构的认知方式编写。从抽象的角度来看，这可能是一个潜在的问题。层次结构的实现者可以提供一种将层次结构展平为列表的机制（在大多数情况下是可能的）。这将使 API 实现者能够提供基于迭代器的 API。基于迭代器的 API 也适用于函数式处理。让我们看看它是如何工作的。

# 展平组合以进行迭代处理

我们已经了解到，访问者模式必须了解复合体的结构，以便有人编写访问者接口的实例。这可能会产生一个称为*抽象泄漏*的异常。GoF 模式目录中有一个模式，将帮助我们以结构不可知的方式导航树的内容。是的，你可能已经猜对了：迭代器模式是候选者！为了使迭代器发挥作用，复合体必须被扁平化为列表序列或流。让我们编写一些代码来扁平化我们在上一节中建模的表达式树。在编写扁平化复合体的逻辑之前，让我们创建一个数据结构，将 AST 的内容作为列表存储。列表中的每个节点必须存储操作符或值，具体取决于我们是否需要存储操作符或操作数。我们为此描述了一个名为`EXPR_ITEM`的数据结构：

```cpp
//////////////////////////// 
// A enum to store discriminator -> Operator or a Value? 
enum class ExprKind{  ILLEGAL_EXP,  OPERATOR , VALUE }; 
// A Data structure to store the Expression node. 
// A node will either be a Operator or Value 
struct EXPR_ITEM { 
    ExprKind knd; double Value; OPERATOR op; 
    EXPR_ITEM():op(OPERATOR::ILLEGAL),Value(0),knd(ExprKind::ILLEGAL_EXP){} 
    bool SetOperator( OPERATOR op ) 
    {  this->op = op;this->knd = ExprKind::OPERATOR; return true; } 
    bool SetValue(double value)  
    {  this->knd = ExprKind::VALUE;this->Value = value;return true;} 
    string toString() {DumpContents();return "";} 
   private: 
      void DumpContents() { //---- Code omitted for brevity } 
}; 
```

`list<EXPR_ITEM>`数据结构将以线性结构存储复合的内容。让我们编写一个类来扁平化复合体：

```cpp
//---- A Flattener for Expressions 
class FlattenVisitor : public IExprVisitor { 
        list<EXPR_ITEM>  ils; 
        EXPR_ITEM MakeListItem(double num) 
        { EXPR_ITEM temp; temp.SetValue(num); return temp; } 
        EXPR_ITEM MakeListItem(OPERATOR op) 
        { EXPR_ITEM temp;temp.SetOperator(op); return temp;} 
        public: 
        list<EXPR_ITEM> FlattenedExpr(){ return ils;} 
        FlattenVisitor(){} 
        double Visit(Number& num){ 
           ils.push_back(MakeListItem(num.getNUM()));return 42; 
        } 
        double Visit(BinaryExpr& bin) { 
            bin.getLeft().accept(*this);bin.getRight().accept(*this); 
            ils.push_back(MakeListItem(bin.getOP()));return 42; 
        } 
         double Visit(UnaryExpr& un){ 
            un.getRight().accept(*this); 
            ils.push_back(MakeListItem(un.getOP())); return 42; 
        } 
};  
```

`FlattenerVistor`类将复合`Expr`节点扁平化为`EXPR_ITEM`列表。一旦复合体被线性化，就可以使用迭代器模式处理项目。让我们编写一个小的全局函数，将`Expr`树转换为`list<EXPR_ITEM>`：

```cpp
list<EXPR_ITEM> ExprList(Expr* r) { 
   unique_ptr<FlattenVisitor> fl(new FlattenVisitor()); 
    r->accept(*fl); 
    list<EXPR_ITEM> ret = fl->FlattenedExpr();return ret; 
 }
```

全局子例程`ExprList`将扁平化一个任意表达式树的`EXPR_ITEM`列表。一旦我们扁平化了复合体，我们可以使用迭代器来处理内容。在将结构线性化为列表后，我们可以使用堆栈数据结构来评估表达式数据以产生输出：

```cpp
//-------- A minimal stack to evaluate RPN expression 
class DoubleStack : public stack<double> { 
   public: 
    DoubleStack() { } 
    void Push( double a ) { this->push(a);} 
    double Pop() { double a = this->top(); this->pop(); return a; } 
};  
```

`DoubleStack`是 STL 堆栈容器的包装器。这可以被视为一种帮助程序，以保持清单的简洁。让我们为扁平化表达式编写一个求值器。我们将遍历列表`<EXPR_ITEM>`并将值推送到堆栈中，如果遇到值的话。如果遇到操作符，我们将从堆栈中弹出值并应用操作。结果再次推入堆栈。在迭代结束时，堆栈中现有的元素将是与表达式相关联的值：

```cpp
//------Iterator through eachn element of Expression list 
double Evaluate( list<EXPR_ITEM> ls) { 
   DoubleStack stk; double n; 
   for( EXPR_ITEM s : ls ) { 
     if (s.knd == ExprKind::VALUE) { stk.Push(s.Value); } 
     else if ( s.op == OPERATOR::PLUS) { stk.Push(stk.Pop() + stk.Pop());} 
     else if (s.op == OPERATOR::MINUS ) { stk.Push(stk.Pop() - stk.Pop());} 
     else if ( s.op ==  OPERATOR::DIV) { n = stk.Pop(); stk.Push(stk.Pop() / n);} 
     else if (s.op == OPERATOR::MUL) { stk.Push(stk.Pop() * stk.Pop()); } 
     else if ( s.op == OPERATOR::UNARY_MINUS) { stk.Push(-stk.Pop()); } 
    } 
   return stk.Pop(); 
} 
//-----  Global Function Evaluate an Expression Tree 
double Evaluate( Expr* r ) { return Evaluate(ExprList(r)); } 
```

让我们编写一个主程序，调用这个函数来评估表达式。求值器中的代码清单易于理解，因为我们正在减少一个列表。在基于树的解释器中，事情并不明显：

```cpp
int main( int argc, char **argv ){      
     unique_ptr<Expr>
         a(new BinaryExpr( new Number(10) , new Number(20) , OPERATOR::PLUS)); 
     double result = Evaluate( &(*a)); 
     cout << result << endl; 
} 
```

# 列表上的 Map 和 Filter 操作

Map 是一个功能操作符，其中一个函数将被应用于列表。Filter 将对列表应用谓词并返回另一个列表。它们是任何功能处理管道的基石。它们也被称为高阶函数。我们可以编写一个通用的 Map 函数，使用`std::transform`用于`std::list`和`std::vector`：

```cpp
template <typename R, typename F> 
R Map(R r , F&& fn) { 
      std::transform(std::begin(r), std::end(r), std::begin(r), 
         std::forward<F>(fn)); 
      return r; 
} 
```

让我们还编写一个函数来过滤`std::list`（我们假设只会传递一个列表）。相同的方法也适用于`std::vector`。我们可以使用管道操作符来组合一个高阶函数。复合函数也可以作为谓词传递：

```cpp
template <typename R, typename F> 
R Filter( R r , F&& fn ) { 
   R ret(r.size()); 
   auto first = std::begin(r), last = std::end(r) , result = std::begin(ret);  
   bool inserted = false; 
   while (first!=last) { 
    if (fn(*first)) { *result = *first; inserted = true; ++result; }  
    ++first; 
   } 
   if ( !inserted ) { ret.clear(); ret.resize(0); } 
   return ret; 
}
```

在这个 Filter 的实现中，由于`std::copy_if`的限制，我们被迫自己编写迭代逻辑。通常建议使用 STL 函数的实现来编写包装器。对于这种特殊情况，我们需要检测列表是否为空：

```cpp
//------------------ Global Function to Iterate through the list  
void Iterate( list<EXPR_ITEM>& s ){ 
    for (auto n : s ) { std::cout << n.toString()  << 'n';} 
} 
```

让我们编写一个主函数将所有内容组合在一起。代码将演示如何在应用程序代码中使用`Map`和`Filter`。功能组合和管道操作符的逻辑在`FuncCompose.h`中可用：

```cpp
int main( int argc, char **argv ){ 
     unique_ptr<Expr>   
        a(new BinaryExpr( new Number(10.0) , new Number(20.0) , OPERATOR::PLUS)); 
      //------ExprList(Expr *) will flatten the list and Filter will by applied 
      auto cd = Filter( ExprList(&(*a)) , 
            [](auto as) {  return as.knd !=   ExprKind::OPERATOR;} ); 
      //-----  Square the Value and Multiply by 3... used | as composition Operator 
      //---------- See FuncCompose.h for details 
      auto cdr = Map( cd, [] (auto s ) {  s.Value *=3; return s; } |  
                  [] (auto s ) { s.Value *= s.Value; return s; } ); 
      Iterate(cdr);  
} 
```

`Filter`例程创建一个新的`list<Expr>`，其中只包含表达式中使用的值或操作数。`Map`例程在值列表上应用复合函数以返回一个新列表。

# 逆转注视可观察性！

我们已经学会了如何将复合转换为列表，并通过迭代器遍历它们。迭代器模式从数据源中提取数据，并在消费者级别操纵结果。我们面临的最重要的问题之一是我们正在耦合`EventSource`和事件接收器。GoF 观察者模式在这里也没有帮助。

让我们编写一个可以充当事件中心的类，事件接收器将订阅该类。通过拥有事件中心，我们现在将有一个对象，它将充当`EventSource`和事件接收器之间的中介。这种间接的一个优点很容易明显，即我们的类可以在到达消费者之前聚合、转换和过滤事件。消费者甚至可以在事件中心级别设置转换和过滤条件：

```cpp
//----------------- OBSERVER interface 
struct  OBSERVER { 
    int id; 
    std::function<void(const double)> ondata; 
    std::function<void()> oncompleted; 
    std::function<void(const std::exception &)> onexception; 
}; 
//--------------- Interface to be implemented by EventSource 
struct OBSERVABLE { 
   virtual bool Subscribe( OBSERVER * obs ) = 0; 
    // did not implement unsuscribe  
}; 
```

我们已经在[第一章](https://cdp.packtpub.com/c___reactive_programming/wp-admin/post.php?post=53&action=edit#post_26)中介绍了`OBSERVABLE`和`OBSERVER`，*响应式编程模型-概述和历史*和第二章，*现代 C++及其关键习惯的概览*。`EventSource`实现了`OBSERVABLE`，事件接收器实现了`OBSERVER`接口。从`OBSERVER`派生的类将实现以下方法：

+   `ondata`（用于接收数据）

+   `onexception`（异常处理）

+   `oncompleted`（数据结束）

`EventSource`类将从`OBSERVABLE`派生，并且必须实现：

+   Subscribe（订阅通知）

+   Unsubscribe（在我们的情况下未实现）

```cpp
//------------------A toy implementation of EventSource 
template<class T,class F,class M, class Marg, class Farg > 
class EventSourceValueSubject : public OBSERVABLE { 
   vector<OBSERVER> sinks;  
   T *State;  
   std::function<bool(Farg)> filter_func; 
   std::function<Marg(Marg)> map_func;
```

`map_func`和`filter_func`是可以帮助我们在将值异步分派给订阅者之前转换和过滤值的函数。在实例化`EventSource`类时，我们将这些值作为参数给出。目前，我们已经根据假设编写了代码，即只有`Expr`对象将存储在`EventSource`中。我们可以有一个表达式的列表或向量，并将值流式传输给订阅者。为此，实现可以将标量值推送到监听器：

```cpp
  public: 
   EventSourceValueSubject(Expr *n,F&& filter, M&& mapper) { 
       State = n; map_func = mapper; filter_func = filter; NotifyAll();  
   } 
   ~EventSourceValueSubject() {  sinks.clear(); } 
   //------ used Raw Pointer ...In real life, a shared_ptr<T>
   //------ is more apt here
   virtual  bool Subscribe( OBSERVER  *sink ) { sinks.push_back(*sink); return true;} 
```

我们做出了一些假设，即`Expr`对象将由调用者拥有。我们还省略了取消订阅方法的实现。构造函数接受一个`Expr`对象，一个`Filter`谓词（可以是使用|运算符的复合函数），以及一个`Mapping`函数（可以是使用`|`运算符的复合函数）：

```cpp
   void NotifyAll() { 
      double ret = Evaluate(State); 
      list<double> ls; ls.push_back(ret); 
      auto result = Map( ls, map_func);; // Apply Mapping Logic 
      auto resulttr = Filter( result,filter_func); //Apply Filter 
      if (resulttr.size() == 0 ) { return; } 
```

在评估表达式后，标量值将放入 STL 列表中。然后，将在列表上应用 Map 函数以转换值。将来，我们将处理一系列值。一旦我们映射或转换了值，我们将对列表应用过滤器。如果列表中没有值，则方法将返回而不通知订阅者：

```cpp
      double dispatch_number = resulttr.front(); 
      for (auto sink : sinks) {  
           std::packaged_task<int()> task([&]()  
           { sink.ondata(dispatch_number); return 1;  }); 
           std::future<int> result = task.get_future();task(); 
           double dresult = result.get(); 
         } 
     }
```

在此代码中，我们将调用`packaged_task`将数据分派到事件接收器。工业级库使用称为调度器的代码片段来执行此任务的一部分。由于我们使用的是 fire and forget，接收器将无法阻止`EventSource`。这是 Observables 的最重要用例之一：

```cpp
      T* GetState() { return State; } 
      void SetState(T *pstate) { State = pstate; NotifyAll(); } 
}; 
```

现在，让我们编写一个方法，根据现代 C++随机数生成器发出随机表达式，具有均匀概率分布。选择这种分布是相当任意的。我们也可以尝试其他分布，以查看不同的结果：

```cpp
Expr *getRandomExpr(int start, int end) { 
    std::random_device rd; 
    std::default_random_engine reng(rd()); 
    std::uniform_int_distribution<int> uniform_dist(start, end); 
    double mean = uniform_dist(reng); 
    return  new  
          BinaryExpr( new Number(mean*1.0) , new Number(mean*2.0) , OPERATOR::PLUS); 
} 
```

现在，让我们编写一个主函数将所有内容组合在一起。我们将使用`Expr`、`Filter`和`Mapper`实例化`EventSourceValueSubject`类：

```cpp
int main( int argc, char **argv ){ 
     unique_ptr<Expr>   
         a(new BinaryExpr( new Number(10) , new Number(20) , OPERATOR::PLUS)); 
     EventSourceValueSubject<Expr,std::function<bool(double)>, 
                    std::function<double(double)>,double,double>  
                    temp(&(*a),[] (auto s ) {   return s > 40.0;  }, 
                    []  (auto s ) { return s+ s ; }  | 
                    []  (auto s ) { return s*2;} ); 
```

在实例化对象时，我们使用管道运算符来组合两个 Lambda。这是为了演示我们可以组合任意数量的函数以形成复合函数。当我们编写 RxCpp 程序时，我们将大量利用这种技术。

```cpp
     OBSERVER obs_one ;     OBSERVER obs_two ; 
     obs_one.ondata = [](const double  r) {  cout << "*Final Value " <<  r << endl;}; 
     obs_two.ondata = [] ( const double r ){ cout << "**Final Value " << r << endl;};
```

在这段代码中，我们实例化了两个`OBSERVER`对象，并使用 Lambda 函数将它们分配给 ondata 成员。我们没有实现其他方法。这仅用于演示目的：

```cpp
     temp.Subscribe(&obs_one); temp.Subscribe(&obs_two);   
```

我们订阅了使用`OBSERVER`实例的事件通知。我们只实现了 ondata 方法。实现`onexception`和`oncompleted`是微不足道的任务：

```cpp
     Expr *expr = 0; 
     for( int i= 0; i < 10; ++i ) { 
           cout << "--------------------------" <<  i << " "<< endl; 
           expr = getRandomExpr(i*2, i*3 ); temp.SetState(expr); 
           std::this_thread::sleep_for(2s); delete expr; 
     } 
} 
```

我们通过将表达式设置为`EventSource`对象来评估一系列随机表达式。经过转换和过滤，如果还有值剩下，该值将通知给`OBSERVER`，并打印到控制台。通过这种方式，我们成功地使用`packaged_taks`编写了一个非阻塞的`EventSource`。在本章中，我们演示了以下内容：

+   使用复合对表达树进行建模

+   通过 Visitor 接口处理复合

+   将表达树展平为列表，并通过迭代器进行处理（拉）

+   从`EventSource`到事件接收端（推送）的凝视反转

# 总结

在本章中，我们涵盖了很多内容，朝着响应式编程模型迈进。我们了解了 GoF Observer 模式并理解了它的缺点。然后，我们偏离了哲学，以了解从结构、行为和功能的角度看世界的方法。我们在表达树建模的背景下学习了 GoF Composite/Visitor 模式。我们学会了如何将层次结构展平为列表，并通过迭代器对其进行导航。最后，我们稍微改变了事物的方案，以达到 Observables。通常，Observables 与 Streams 一起工作，但在我们的情况下，它是一个标量值。在下一章中，我们将学习有关事件流处理，以完成学习响应式编程的先决条件。


# 第六章：使用 C++介绍事件流编程

本章将是使用 C++编程反应性系统所需的先决章节系列的最后一章。我们需要经历许多概念的原因是，反应式编程模型统一了许多计算概念，实现了其强大的编程模型。要开始以反应式方式思考，程序员必须熟悉面向对象编程、函数式编程、语言级并发、无锁编程、异步编程模型、设计模式、调度算法、数据流编程模型、声明式编程风格，甚至一点图论！我们从书中窥探了各种 GUI 系统的事件驱动编程模型以及围绕它们构建代码的方式。我们涵盖了现代 C++的核心要点第二章，*现代 C++及其关键习语之旅*。在第三章中，*C++中的语言级并发和并行性*，以及第四章，*C++中的异步和无锁编程*，我们分别介绍了 C++语言支持的语言级并发和无锁编程。在第五章中，*可观察对象简介*，我们重点介绍了如何将反应式编程模型放入 GOF 模式的背景中处理。剩下的是事件流编程。现在我们将专注于处理事件流或事件流编程。在本章中，我们将讨论以下内容：

+   什么是流编程模型？

+   流编程模型的优势

+   使用 C++和公共领域库进行流编程

+   使用 Streamulus 进行流编程

+   事件流编程

# 什么是流编程模型？

在我们深入讨论流编程模型之前，我们将退一步，看看与 POSIX shell 编程模型的相似之处。在典型的命令行 shell 程序中，每个命令都是一个程序，每个程序都是一个命令。在实现计算目标或任务后，我们可以将一个程序的输出传递给另一个程序。实际上，我们可以链接一系列命令来实现更大的计算任务。我们可以将其视为一系列数据通过一系列过滤器或转换以获取输出。我们也可以称之为*命令组合*。有现实情况下，巨大的程序被少量的 shell 代码使用*命令组合*替代。同样的过程可以在 C++程序中实现，将函数的输入视为流、序列或列表。数据可以从一个函数或函数对象（也称为函数对象）传递到另一个函数，作为标准数据容器。

传奇计算机科学家和斯坦福大学教授唐纳德·克努斯博士被要求编写一个程序：

+   读取文本文件并确定*n*个常用单词

+   打印出一个按单词频率排序的单词列表

Knuth 的解决方案是一个十页的 Pascal 程序！Doug McIlroy 只用以下 shell 脚本就实现了相同的功能：

`tr -cs A-Za-z ' n ' | tr A-Z a-z | sor t | uniq -c | sor t -rn | sed ${1}q`命令组合的威力就是这样了。

# 流编程模型的优势

传统的 OOP 程序很好地模拟了层次结构，处理层次结构大多比处理线性集合更困难。在流编程模型中，我们可以将输入视为放入容器的实体流，将输出视为实体的集合，而不修改输入数据流。使用 C++通用编程技术，我们可以编写与容器无关的代码来处理流。这种模型的一些优势包括：

+   流编程简化了程序逻辑

+   流可以支持惰性评估和函数式转换

+   流更适合并发编程模型（源流是不可变的）

+   我们可以组合函数来创建高阶函数来处理它们

+   流促进了声明式编程模型

+   它们可以从不同的源聚合、过滤和转换数据

+   它们解耦了数据源和处理数据的实体

+   它们提高了代码的可读性（开发人员可以更快地理解代码）

+   它们可以利用数据并行性和任务并行性

+   我们可以利用数百个定义良好的流操作符（算法）来处理数据

# 使用 Streams 库进行应用流编程

在本节中，我们将介绍使用`Streams`库进行流编程的主题，这是由 Jonah Scheinerman 编写的一个公共领域库。该库托管在[`github.com/jscheiny/Streams`](https://github.com/jscheiny/Streams)，API 文档可从[`jscheiny.github.io/Streams/api.html#`](http://jscheiny.github.io/Streams/api.html)获取。以下是一个介绍（摘自库的 GitHub 页面）：

`Streams`是一个 C++库，提供了对数据的惰性评估和函数式转换，以便更轻松地使用 C++标准库的容器和算法。`Streams`支持许多常见的函数操作，如 map、filter 和 reduce，以及其他各种有用的操作，如各种集合操作（并集、交集、差集）、部分和、相邻差分，以及其他许多操作。

我们可以看到，熟悉标准模板库（STL）的程序员将会对这个库感到非常舒适。STL 容器被视为流数据源，STL 算法可以被视为对流数据源的转换。该库使用现代 C++支持的函数式编程习语，并且支持惰性评估。在这里，惰性评估的概念非常重要，因为它是函数式编程模型和 Rx 编程模型的基石。

# 惰性评估

在编程语言中，有两种突出的评估函数参数的方法，它们如下：

+   应用程序顺序评估（AO）

+   正常顺序评估（NO）

在 AO 的情况下，参数在调用上下文中被评估，然后传递给被调用者。大多数传统的编程语言都遵循这种方法。在 NO 的情况下，变量的评估被推迟，直到在被调用者的上下文中需要计算结果。一些函数式编程语言，如 Haskell、F#和 ML，遵循 NO 模型。在函数式编程语言中，大部分函数的评估是引用透明的（函数的调用不会产生副作用）；我们只需要对表达式进行一次评估（对于特定值作为参数），并且结果可以在再次执行相同函数相同参数的评估时共享。这被称为惰性评估。因此，惰性评估可以被认为是 NO 与先前计算结果的共享相结合。C++编程语言默认不支持函数参数的惰性评估，但可以使用不同的技术来模拟，例如可变模板和表达式模板。

# 一个简单的流程序

要开始使用`Streams`库，让我们编写一个小程序来生成一个数字流并计算前十个数字的平方：

```cpp
//--------- Streams_First.cpp 
#include "Stream.h" 
using namespace std; 
using namespace Stream; 
using namespace Stream::op; 
int main(){ 
  //-------- counter(n) - Generate a series of value 
  //-------- Map (Apply a Lambda) 
  //-------- limit(n) -- Take first ten items 
  //-------- Sum -- aggregate 
  int total = MakeStream::counter(1) 
    | map_([] (int x) { return x * x; } // Apply square on each elements 
    | limit(10) //take first ten elements
   | sum();  // sum the Stream contents Streams::op::sum 
   //----------- print the result 
   cout << total << endl; 
} 
```

前面的代码片段生成了一个值列表（使用`MakeStream::counter(1)`），生成的值将使用 map 函数进行转换（在这种情况下，计算平方）。当在流中组装了十个元素（`limit(10)`）时，我们在流上调用 sum 操作符。

# 使用流范式聚合值

现在我们了解了 Stream 库所设想的流编程的基础知识，让我们编写一段代码，计算存储在`std::vector`容器中的数字的平均值：

```cpp
//--------------- Streams_Second.cpp 
// g++ -I./Streams-master/sources Streams_Second.cpp 
// 
#include "Stream.h" 
#include <ioStream> 
#include <vector> 
#include <algorithm> 
#include <functional> 
using namespace std; 
using namespace Stream; 
using namespace Stream::op; 
int main() { 
  std::vector<double> a = { 10,20,30,40,50 }; 
  //------------ Make a Stream and reduce  
  auto val =  MakeStream::from(a)  | reduce(std::plus<void>()); 
  //------ Compute the arithematic average 
  cout << val/a.size() << endl; 
} 
```

前面的代码片段从`std::vector`创建了一个流，并使用`std::plus`函数对象进行了归约处理。这等同于对流中的值进行聚合。最后，我们将聚合值除以`std::vector`中的元素数量。

# STL 和流范式

`Streams`库可以与 STL 容器无缝配合。以下代码片段将在流上映射一个函数，并将结果数据转换为一个向量容器：

```cpp
//--------------- Streams_Third.cpp 
// g++ -I./Streams-master/sources Streams_Third.cpp 
// 
#include "Stream.h" 
#include <ioStream> 
#include <vector> 
#include <algorithm> 
#include <functional> 
#include <cmath> 
using namespace std; 
using namespace Stream; 
using namespace Stream::op; 
double square( double a ) { return a*a; } 
int main() { 
  std::vector<double> values = { 1,2,3,4,5 }; 
  std::vector<double> outputs = MakeStream::from(values) 
               | map_([] (double a ) { return a*a;})  
               | to_vector(); 
  for(auto pn : outputs ) 
  { cout << pn << endl; } 
} 
```

前面的代码片段将`std::vector<double>`转换为一个流，应用平方函数，然后将结果转换回`std:::vector<double>`。之后，对向量进行迭代以打印内容。`Streams`库的文档非常详尽，包含许多代码示例，可以用来编写生产质量的应用程序。请参阅 API 文档，网址为[`jscheiny.github.io/Streams/api.html`](http://jscheiny.github.io/Streams/api.html)。

# 关于 Streams 库

`Streams`库是一个设计良好的软件，具有直观的编程模型。任何曾经使用过函数式编程和流编程的程序员都会在几个小时内真正感到舒适。熟悉 STL 的人也会觉得这个库非常直观。从编程模型的角度来看，API 可以分为：

+   核心方法（流初始化）

+   生成器（流创建者）

+   有状态的中间操作符（函数式不可变转换）

+   无状态的中间操作符

+   终端操作符

前面提到的库文档阐明了这个出色库的各个方面。

# 事件流编程

我们对流编程模型的工作有了一定的了解。当我们将事件作为流处理时，可以将其归类为事件流编程。在编程社区中，事件驱动架构被认为是打造现代程序的更好模型。一个依赖于事件流编程的软件的绝佳例子是版本控制系统。在版本控制系统中，一切都被视为事件。典型的例子包括检出代码、提交、回滚和分支。

# 事件流编程的优势

将事件作为流聚合并在下游系统中处理与传统的事件编程模型相比有许多优势。一些关键优势包括：

+   事件源和事件接收器没有耦合

+   事件接收器可以处理事件而不必理会事件源

+   我们可以应用流处理操作符来处理和过滤流

+   转换和过滤可以在聚合级别进行处理

+   事件可以通过流处理网络传播

+   事件处理可以很容易地并行化（声明式并行）

# Streamulus 库及其编程模型

Streamulus 库，来自 Irit Katiel，是一个库，通过实现**特定领域嵌入式语言**（**DSEL**）的编程模型，使事件流的编程更加容易。为了理解编程模型，让我们检查一个将数据流入聚合接收到的数据的类的程序：

```cpp
#include "Streamulus.h" 
#include <ioStream> 
using namespace std; 
using namespace Streamulus; 
struct print {     
    static double temp; 
    print() { } 
    template<typename T> 
    T operator()(const T& value) const {  
        print::temp += value; 
        std::cout << print::temp << std::endl;  return value; 
     } 
}; 
double print::temp = 0; 
```

前面的函数对象只是将传递的值累积到静态变量中。对于每次由`Streamify`模板（`Streamify<print>(s)`）调用的函数，到目前为止累积的值将被打印到控制台。通过查看以下清单，可以更好地理解这一点：

```cpp
void hello_Stream() { 
    using namespace Streamulus; 
    // Define an input Stream of strings, whose name is "Input Stream" 
    InputStream<double> s = 
             NewInputStream<double>("Input Stream", true /* verbose */); 
    // Construct a Streamulus instance 
    Streamulus Streamulus_engine;   

```

我们使用 `NewInputStream<T>` 模板方法创建一个流。该函数期望一个参数，用于确定是否应将日志打印到控制台。通过将第二个参数设置为 `false`，我们可以关闭详细模式。我们需要创建一个 Streamulus 引擎的实例来协调数据流。Streamulus 引擎对流表达式进行拓扑排序，以确定变化传播顺序：

```cpp
    // For each element of the Stream:  
    //     aggregate the received value into a running sum
    //     print it  
    Streamulus_engine.Subscribe(Streamify<print>( s));    
```

我们使用 `Streamify<f>` strop（流操作符）来序列化刚刚创建的打印函子的调用。我们可以创建自己的流操作符，通常 Streamify 对我们来说就足够了。Streamfiy 创建一个单事件函子和一个 strop：

```cpp
    // Insert data to the input Stream 
    InputStreamPut<double>(s, 10); 
    InputStreamPut<double>(s, 20); 
    InputStreamPut<double>(s, 30);     
} 
int main() {  hello_Stream();  return 0; } 
```

先前的代码片段将一些值发射到流中。我们将能够在控制台上看到累积和打印三次。在主函数中，我们调用 `hello_Stream` 函数来触发所有操作。

现在我们已经学会了 Streamulus 系统如何与简单程序一起工作，让我们编写一个更好地阐明库语义的程序。以下程序通过一系列单参数函子流数据，以演示库的功能。我们还在列表中大量使用流表达式：

```cpp
/////////////////////////// 
//  g++ -I"./Streamulus-master/src"  -I<PathToBoost>s Streamulus_second.cpp 
#include "Streamulus.h" 
#include <ioStream> 
using namespace std; 
using namespace Streamulus; 
//-------  Functors for doubling/negating and halfving values 
struct twice {     
    template<typename T> 
    T operator()(const T& value) const {return value*2;} 
}; 
struct neg {     
    template<typename T> 
    T operator()(const T& value) const{ return -value; } 
}; 
struct half{     
    template<typename T> 
    T operator()(const T& value) const { return 0.5*value;} 
};
```

前面一组函子在性质上是算术的。`twice` 函子将参数加倍，`neg` 函子翻转参数的符号，`half` 函子将值缩放 0.5 以减半参数的值：

```cpp
struct print{     
    template<typename T> 
    T operator()(const T& value) const{  
        std::cout << value << std::endl; 
        return value; 
    } 
}; 
struct as_string  { 
    template<typename T> 
    std::string operator()(const T& value) const {  
        std::stringStream ss; 
        ss << value; 
        return ss.str(); 
    } 
};
```

前面两个函数对象的工作方式是显而易见的——第一个（print）只是将值输出到控制台。`as_string` 使用 `std::stringStream` 类将参数转换为字符串：

```cpp
void DataFlowGraph(){ 
    // Define an input Stream of strings, whose name is "Input Stream" 
    InputStream<double> s = 
          NewInputStream<double>("Input Stream", false /* verbose */); 
    // Construct a Streamulus instance 
    Streamulus Streamulus_engine;             
    // Define a Data Flow Graph for Stream based computation  
    Subscription<double>::type val2 =  Streamulus_engine.Subscribe(Streamify<neg> 
                         (Streamify<neg>(Streamify<half>(2*s)))); 
    Subscription<double>::type val3 = Streamulus_engine.Subscribe( 
                                      Streamify<twice>(val2*0.5)); 
    Streamulus_engine.Subscribe(Streamify<print>(Streamify<as_string>(val3*2))); 
    //------------------ Ingest data into the Stream 
    for (int i=0; i<5; i++) 
        InputStreamPut(s, (double)i); 
}
```

`DataFlowGraph()` 创建了 `InputStream<T>` 来处理双值流。在实例化 `Streamulus` 对象（引擎）之后，我们通过 `Streamify<f>` 流操作符将一系列函子连接起来。该操作可以被视为一种具有单参数函数的函数组合。设置机制后，我们使用 `InputStreamPut` 函数向流中注入数据：

```cpp
int main(){ 
    DataFlowGraph(); //Trigger all action 
    return 0; 
} 
```

# Streamulus 库 - 其内部的一瞥

`Streamulus` 库基本上创建了一个变化传播图，以简化流处理。我们可以将图的节点视为计算，将边视为从一个节点到另一个节点的缓冲区。几乎所有数据流系统都遵循相同的语义。`Streamulus` 库帮助我们构建一个依赖变量的图，这有助于我们将更改传播到子节点。应该更新变量的顺序将通过对图进行拓扑排序来定义。

图是一种数据结构，其中一组依赖实体表示为节点（或顶点），它们之间的关系（作为边）表示为边。在计算机科学中，特别是在调度和分析依赖关系时，有一种特定版本的图，称为有向无环图，因其独特的特性而受到青睐。DAG 是一个没有循环的有向图。我们可以执行称为拓扑排序的操作来确定实体的线性依赖顺序。拓扑排序只能在 DAG 上执行，它们不是唯一的。在下图中，我们可以找到多个拓扑排序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-rct-prog/img/2b411853-e46e-490e-b720-cf0c6e626342.png)

# Streamulus 库 - 表达式处理的一瞥

我们将看看 `Streamulus` 如何使用简单的流表达式处理表达式：

```cpp
InputStream<int>::type x = NewInputStream<int>("X"); 
Engine.Subscribe( -(x+1)); 
```

`- (x+1)` 流表达式将产生以下图表。术语 strop 代表流操作符，每个节点都组织为一个 strop：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-rct-prog/img/bc54a6ad-64ad-4387-be8a-641b1f3cc85c.png)

一旦节点被正确标记，将对图进行拓扑排序以确定执行顺序。下图显示了一个拓扑排序（可以有多个拓扑排序）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-rct-prog/img/e5e60556-9541-400f-8cc2-210cfa39479f.png)

Streamulus 引擎遍历图表，找出在数据传播过程中必须应用流操作符的顺序。**TO**标签代表**拓扑顺序**。拓扑排序后，将产生一个按拓扑顺序排名的流操作符的线性列表。执行引擎将按照拓扑顺序执行代码。

Streamulus 引擎使用 boost proto 库执行其魔术。后者管理 Streamulus 库的表达式树。要真正查看库的源代码，您需要熟悉模板元编程，特别是表达式模板。元编程是一种我们编写代码来生成或转换源代码的技术。1994 年，Erwin Unruh 发现 C++模板机制是图灵完备的。

# 电子表格库-变更传播引擎

电子表格经常被吹捧为反应系统的典型示例。在电子表格中，页面被组织为单元格矩阵。当单元格发生变化时，所有依赖单元格将重新计算以反映变化。这对每个单元格都是如此。实际上，如果您有诸如 Streamulus 之类的库，对电子表格进行建模是很容易的。幸运的是，该库的设计者本身编写了另一个依赖于 Streamulus 进行变更传播的库。

电子表格是一个 C++库，可以实现电子表格编程，即设置变量（单元格），其中每个单元格都被分配一个可能包含其他单元格值的表达式。更改将传播到所有依赖单元格，就像在电子表格中一样。电子表格是为了演示 Streamulus 的使用而开发的。电子表格是一个仅包含头文件的库。它使用 boost 和 Streamulus。因此，请将这三个库放在您的包含路径中。该库的详细信息可以在[`github.com/iritkatriel/spreadsheet`](https://github.com/iritkatriel/spreadsheet)上找到。

我们将介绍一个利用“电子表格”库的示例程序，该库包含在项目的 GitHub 存储库（`main.cpp`）中：

```cpp
#include "spreadsheet.hpp" 
#include <ioStream> 
int main (int argc, const char * argv[]) {  
    using namespace spreadsheet; 
    Spreadsheet sheet; 
    Cell<double> a = sheet.NewCell<double>(); 
    Cell<double> b = sheet.NewCell<double>(); 
    Cell<double> c = sheet.NewCell<double>(); 
    Cell<double> d = sheet.NewCell<double>(); 
    Cell<double> e = sheet.NewCell<double>(); 
    Cell<double> f = sheet.NewCell<double>();
```

前面的代码片段创建了一组单元格，作为 IEEE 双精度浮点数的容器。初始化单元格后，我们将开始使用以下一组表达式改变单元格的值：

```cpp
    c.Set(SQRT(a()*a() + b()*b())); 
    a.Set(3.0); 
    b.Set(4.0); 
    d.Set(c()+b()); 
    e.Set(d()+c()); 
```

现在，我们将使用前述表达式改变值。通过`Set`方法进行每次赋值后，将通过单元格触发计算传递。`Streamulus`库管理底层流：

```cpp
    std::cout << " a=" << a.Value()  
              << " b=" << b.Value()  
              << " c=" << c.Value()  
              << " d=" << d.Value()  
              << " e=" << e.Value()  
              << std::endl;
```

前面的代码片段将单元格的值打印到控制台。我们将再次更改单元格的表达式以触发计算流图：

```cpp
    c.Set(2*(a()+b())); 
    c.Set(4*(a()+b())); 
    c.Set(5*(a()+b())); 
    c.Set(6*(a()+b())); 
    c.Set(7*(a()+b())); 
    c.Set(8*(a()+b())); 
    c.Set(a()); 
    std::cout << " a=" << a.Value()  
              << " b=" << b.Value()  
              << " c=" << c.Value()  
              << " d=" << d.Value()  
              << " e=" << e.Value()  
              << std::endl;     
    std::cout << "Goodbye!n"; 
    return 0; 
} 
```

可以查看库的源代码以了解库的内部工作原理。电子表格是 Streamulus 库如何被利用来编写健壮软件的绝佳示例。

# RaftLib-另一个流处理库

RaftLib 是一个值得检查的库，适用于任何对并行编程或基于流的编程感兴趣的人（开发人员）。该库可在[`github.com/RaftLib/RaftLib`](https://github.com/RaftLib/RaftLib)上找到。前述网站提供了以下描述

RaftLib 是一个用于实现流/数据流并行计算的 C++库。使用简单的右移操作符（就像您用于字符串操作的 C++流一样），您可以将并行计算内核链接在一起。使用 RaftLib，我们摆脱了显式使用 pthread、std.thread、OpenMP 或任何其他并行线程库。这些通常被误用，导致非确定性行为。RaftLib 的模型允许无锁 FIFO 样式访问连接每个计算内核的通信通道。整个系统具有许多自动并行化、优化和便利功能，可以相对简单地编写高性能应用程序。

由于空间限制，本书不会详细介绍`RaftLib`。该库的作者 Jonathan Beard 有一次精彩的演讲，可在[`www.youtube.com/watch?v=IiQ787fJgmU`](https://www.youtube.com/watch?v=IiQ787fJgmU)观看。让我们来看一个代码片段，展示了这个库的工作原理：

```cpp
#include <raft> 
#include <raftio> 
#include <cstdlib> 
#include <string> 

class hi : public raft::kernel 
{ 
public: 
    hi() : raft::kernel(){ output.addPort< std::string >( "0" ); } 
    virtual raft::kstatus run(){ 
        output[ "0" ].push( std::string( "Hello Worldn" ) ); 
        return( raft::stop );  
    } 
}; 

int main( int argc, char **argv ) { 
    /** instantiate print kernel **/ 
    raft::print< std::string > p; 
    /** instantiate hello world kernel **/ 
    hi hello; 
    /** make a map object **/ 
    raft::map m; 
    /** add kernels to map, both hello and p are executed concurrently **/ 
    m += hello >> p; 
    /** execute the map **/ 
    m.exe(); 
    return( EXIT_SUCCESS ); 
} 
```

作为程序员，您应该为自定义计算定义一个内核，并使用`>>`运算符来流式传输数据。在前面的代码中，`hi`类就是这样一个内核。请查阅`Raftlib`文档（可在前面的 RaftLib URL 找到）和源代码示例，以了解更多关于这个精彩库的信息。

# 这些东西与 Rx 编程有什么关系？

基本上，响应式编程模型将事件视为通过变化传播图传播的数据流。为了实现这一点，我们需要将事件元素聚合到基于容器的数据结构中，并从中创建一个流。有时，如果数据很多，我们甚至会应用统计技术来对事件进行采样。生成的流可以在源级别使用函数转换进行过滤和转换，然后通知等待通知的观察者。事件源应该采取一种点火并忘记的方式来分发事件流，以避免事件源汇和事件汇之间的耦合。何时分派事件数据将由调度软件确定，该软件以异步方式运行函数转换管道。因此，响应式编程的关键元素是：

+   Observables（其他人感兴趣的数据流）

+   观察者（对 Observable 感兴趣并订阅通知的实体）

+   调度器（确定流何时应该在网络上传播）

+   功能操作符（事件过滤和转换）

简而言之，`调度器`（Rx 引擎的一部分）会异步地对`Observable`进行过滤和转换，然后再通知订阅者，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-rct-prog/img/410323d7-7640-424d-b00e-07089e08888d.png)

# 摘要

在本章中，我们涵盖了事件流编程的主题。将事件视为流在许多方面优于传统的事件处理模型。我们从`Streams`库开始，了解了它的编程模型。我们还编写了一些程序，以熟悉该库及其语义。`Streams`库有很好的文档，您应该查阅其文档以了解更多信息。在 Streams 库之后，我们看了一下 Streamulus 库，它提供了一种 DSEL 方法来操作事件流。我们编写了一些程序，还学习了一些附带`Streamulus`库的示例程序。我们还提到了`Raftlib`库，这是流处理的另一种选择。通过对事件流编程模型的覆盖，我们现在已经完成了理解响应式编程一般和 RxCpp 库特别的先决条件。在下一章中，我们将开始使用 RxCpp 库，进入响应式系统设计的编程模型。


# 第七章：数据流计算和 RxCpp 库的介绍

从这一章开始，我们将深入了解响应式编程模型的核心。你可以把之前的章节看作是理解响应式编程模型的先决条件，更具体地说是使用 C++ 编程语言进行响应式编程的先决条件。回顾一下，我们已经涵盖了必要的先决条件，其中包括以下内容：

+   各种 GUI 平台上的事件编程模型

+   现代 C++ 语言的快速介绍（包括函数式编程）

+   C++ 中的语言级并发，以实现更好的并发系统

+   无锁编程模型（作为朝向声明式编程的一步）

+   高级设计模式和 Observables 的概念

+   使用 C++ 进行事件流编程

所有这些主题在**函数式响应式编程**（**FRP**）的情况下以系统化的方式结合在一起。在这里，FRP 缩写被用于使用函数式编程构造来编程响应式系统的宽泛意义上。

简而言之，响应式编程无非就是使用异步数据流进行编程。通过对流应用各种操作，我们可以实现不同的计算目标。在响应式程序中的主要任务是将数据转换为流，无论数据的来源是什么。事件流通常被称为**Observables**，事件流的订阅者被称为**Observers**。在 Observables 和 Observers 之间，有流操作符（过滤器/转换器）。

由于默认假设数据源在数据通过操作符时不会被改变，我们可以在 Observables 和 Observers 之间有多个操作符路径。不可变性为乱序执行提供了选项，并且调度可以委托给一个名为调度器的特殊软件。因此，Observables、Observers、流操作符和调度器构成了响应式编程模型的支柱。

在本章中，我们将涵盖以下主题：

+   关于数据流计算范式的简要讨论

+   介绍 RxCpp 库及其编程模型

+   一些基本的 RxCpp 程序来入门

+   Rx 流操作符

+   弹珠图

+   调度

+   `flatmap`/`concatmap` 的奇特之处

+   附加的 Rx 操作符

# 数据流计算范式

传统上，程序员以控制流的形式编码计算机程序。这意味着我们将程序编码为一系列小语句（顺序、分支、迭代）或函数（包括递归），以及它们关联的状态。我们使用诸如选择（`if`/`else`）、迭代（`while`/`for`）和函数（递归函数也包括在内）等构造来编码我们的计算。处理这些类型的程序的并发和状态管理真的很困难，并且在管理可变的状态信息时会导致微妙的错误。我们需要在共享的可变状态周围放置锁和其他同步原语。在编译器级别，语言编译器将解析源代码以生成**抽象语法树**（**AST**），进行类型分析和代码生成。实际上，AST 是一个信息流图，你可以在其中执行数据流分析（用于数据/寄存器级优化）和控制流分析，以利用处理器级别的代码管道优化。尽管程序员以控制流的形式编码程序，但编译器（至少部分）也试图以数据流的形式看待程序。这里的关键是，每个计算机程序中都存在一个潜在的隐式数据流图。

数据流计算将计算组织为一个显式图，其中节点是计算，边是数据在节点之间流动的路径。如果我们对计算图中的节点上的计算施加一些限制，例如通过在输入数据的副本上工作来保留数据状态（避免原地算法），我们可以利用并行性的机会。调度器将通过对图数据结构进行拓扑排序来找到并行性的机会。我们将使用流（`Path`）和流操作（`Node`）构建图数据结构。这可以以声明方式完成，因为操作符可以被编码为 lambda，对节点进行一些本地计算。有一组原始标准（函数/流）操作符，如`map`、`reduce`、`filter`、`take`等，被函数式编程社区确定，可以在流上工作。在每个数据流计算框架中，都有一种将数据转换为流的方法。用于机器学习的 TensorFlow 库就是一个使用数据流范式的库。尽管图的创建过程不是完全显式的，RxCpp 库也可以被视为一个数据流计算库。由于函数式编程构造支持惰性评估，当我们使用异步数据流和操作构建流水线时，我们实际上正在创建一个计算流图。这些图由调度子系统执行。

# RxCpp 库简介

我们将在本书的其余部分中使用 RxCpp 库来编写我们的响应式程序。RxCpp 库是一个仅包含头文件的 C++库，可以从 GitHub 仓库下载：[`reactive-extensions.github.io/RxCpp/`](http://reactive-extensions.github.io/RxCpp/)。RxCpp 库依赖于现代 C++构造，如语言级并发、lambda 函数/表达式、函数式组合/转换和运算符重载，以实现响应式编程构造。RxCpp 库的结构类似于`Rx.net`和`Rxjava`等库。与任何其他响应式编程框架一样，在编写第一行代码之前，每个人都应该了解一些关键构造。它们是：

+   Observables（Observable Streams）

+   观察者（订阅 Observables 的人）

+   操作符（例如，过滤器、转换和减少）

+   调度器

RxCpp 是一个仅包含头文件的库，大部分计算都基于 Observables 的概念。该库提供了许多原语，用于从各种数据源创建 Observable Streams。数据源可以是数组、C++范围、STL 容器等。我们可以在 Observables 和它们的消费者（被称为 Observers）之间放置 Operators。由于函数式编程支持函数的组合，我们可以将一系列操作符作为一个单一实体放置在 Observables 和订阅流的 Observers 之间。与库相关的调度器将确保当 Observable Streams 中有数据可用时，它将通过一系列 Operators 传递，并向订阅者发出通知。观察者将通过 on_next、on_completed 或 on_error lambda 收到通知，每当管道中发生重要事件时。因此，观察者可以专注于它们主要负责的任务，因为数据将通过通知到达它们。

# RxCpp 库及其编程模型

在这一部分，我们将编写一些程序，帮助读者理解 RxCpp 库的编程模型。这些程序的目的是阐明 Rx 概念，它们大多是微不足道的。代码将足以让程序员在进行轻微调整后将其纳入生产实现。在这一部分，数据生产者及其 Observables 将基于 C++范围、STL 容器等，以使清单足够简单，以便理解这里概述的核心概念。

# 一个简单的 Observable/Observer 交互

让我们编写一个简单的程序，帮助我们理解 RxCpp 库的编程模型。在这个特定的程序中，我们将有一个 Observable Stream 和一个订阅该 Stream 的 Observer。我们将使用一个范围对象从 1 到 12 生成一系列数字。在创建值的范围和一个 Observable 之后，我们将它们连接在一起。当我们执行程序时，它将在控制台上打印一系列数字。最后，一个字面字符串（"Oncompleted"）也将打印在控制台上。

```cpp
////////// 
// First.cpp 
// g++ -I<PathToRxCpplibfoldersrc> First.cpp 
#include "rxcpp/rx.hpp" 
#include <ioStream> 
int main() { 
 //------------- Create an Observable.. a Stream of numbers 
 //------------- Range will produce a sequence from 1 to 12 
 auto observable = rxcpp::observable<>::range(1, 12);
 //------------ Subscribe (only OnNext and OnCompleted Lambda given 
 observable.Subscribe(  
    [](int v){printf("OnNext: %dn", v);}, 
    [](){printf("OnCompleted\n");}); 
} 
```

前面的程序将在控制台上显示数字，并且字面字符串"`OnCompleted`"也将显示在控制台上。这个程序演示了如何创建一个 Observable Stream，并使用 subscribe 方法将 Observer 连接到创建的 Observable Stream。

# 使用 Observables 进行过滤和转换

以下程序将帮助我们理解过滤和`map`操作符的工作原理，以及使用 subscribe 方法将 Observer 连接到 Observable Streams 的通常机制。filter 方法对流的每个项目进行谓词评估，如果评估产生积极断言，该项目将出现在输出流中。`map`操作符对其输入流的每个元素应用一个 lambda 表达式，并在每次产生一个输出值（可以通过管道传播）时帮助产生一个输出值：

```cpp
/////////////////////////////////////// 
// Second.cpp 
#include "rxcpp/rx.hpp" 
#include <ioStream> 
int main() { 
  auto values = rxcpp::observable<>::range(1, 12). 
      filter([](int v){ return v % 2 ==0 ;}). 
      map([](int x) {return x*x;});  
  values.subscribe( 
           [](int v){printf("OnNext: %dn", v);}, 
           [](){printf("OnCompleted\n");}); 
} 
```

前面的程序生成一系列数字（作为 Observable），并通过一个 filter 函数传递流的内容。`filter`函数尝试检测数字是否为偶数。如果谓词为真，则数据将传递给`map`函数，该函数将对其输入进行平方。最终，流的内容将显示在控制台上。

# 从 C++容器中流出值

STL 容器中的数据被视为存在于空间中的数据（已经捕获的数据）。尽管 Rx 流用于处理随时间变化的数据（动态数据），我们可以将 STL 容器转换为 Rx 流。我们需要使用 Iterate 操作符进行转换。这在某些时候可能很方便，并且有助于集成使用 STL 的代码库中的代码。

```cpp
// STLContainerStream.cpp
#include "rxcpp/rx.hpp"
#include <ioStream>
#include <array>
int main() {
    std::array< int, 3 > a={{1, 2, 3}};
    auto values = rxcpp::observable<>::iterate(a);
    values.subscribe([](int v){printf("OnNext: %dn", v);},
    [](){printf("OnCompleted\n");});
}
```

# 从头开始创建 Observables

到目前为止，我们已经编写了代码，从一个范围对象或 STL 容器创建了一个 Observable Stream。让我们看看如何可以从头开始创建一个 Observable Stream。嗯，几乎：

```cpp
// ObserverFromScratch.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
int main() { 
      auto ints = rxcpp::observable<>::create<int>( 
                  [](rxcpp::subscriber<int> s){ 
                       s.on_next(1); 
                       s.on_next(4); 
                       s.on_next(9); 
                       s.on_completed(); 
                 }); 
    ints.subscribe( [](int v){printf("OnNext: %dn", v);}, 
                             [](){printf("OnCompletedn");}); 
} 
```

前面的程序调用`on_ext`方法来发出一系列完全平方数。这些数字（1,4,9）将被打印到控制台上。

# 连接 Observable Streams

我们可以连接两个流来形成一个新的流，在某些情况下这可能很方便。让我们通过编写一个简单的程序来看看这是如何工作的：

```cpp
//------------- Concactatenate.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
int main() { 
 auto values = rxcpp::observable<>::range(1);  
 auto s1 = values.take(3).map([](int prime) { return 2*prime;);}); 
 auto s2 = values.take(3).map([](int prime) { return prime*prime);}); 
 s1.concat(s2).subscribe(rxcpp::util::apply_to( 
            []( int p) { printf(" %dn", p);})); 
} 
```

concat 操作符通过保持顺序，将组成的 Observable Streams 的内容依次附加在一起。在前面的代码中，在创建一个 Observable（values）之后，我们创建了另外两个 Observables（s1 和 s2），并附加了第二个 Observable Stream（s2）生成的内容，以产生一个组合的 Observable Stream（s1.concat(s2)）。最后，我们订阅了组合的 Observable。

# 取消订阅 Observable Streams

以下程序展示了如何订阅 Observable 并在需要时停止订阅。在某些程序的情况下，这个选项非常有用。请参阅 Rxcpp 文档，了解更多关于订阅以及如何有效使用它们的信息。与此同时，以下程序将演示如何取消订阅 Observable。

```cpp
//---------------- Unsubscribe.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <iostream> 
int main() { 
    auto subs = rxcpp::composite_subscription(); 
    auto values = rxcpp::observable<>::range(1, 10); 
    values.subscribe( 
        subs,&subs{ 
            printf("OnNext: %dn", v); 
            if (v == 6) 
                subs.unsubscribe(); //-- Stop recieving events 
        }, 
        [](){printf("OnCompletedn");}); 
}

```

在上面的程序中，当发出的值达到阈值时，我们调用取消订阅（subs.unsubscribe()）方法。

# 关于大理石图表的视觉表示的介绍

很难将 Rx Streams 可视化，因为数据是异步流动的。Rx 系统的设计者创建了一组名为**大理石图表**的可视化线索：让我们编写一个小程序，并将 map 操作符的逻辑描述为大理石图表。

```cpp
//------------------ Map.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <ioStream> 
#include <array> 
int main() { 
    auto ints = rxcpp::observable<>::range(1,10). 
                 map( [] ( int n  ) {return n*n; }); 
    ints.subscribe( 
            [](int v){printf("OnNext: %dn", v);}, 
            [](){printf("OnCompletedn");}); 
} 
```

与其描述大理石图表，不如看一个描述 `map` 操作符的大理石图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-rct-prog/img/d4c71177-6c60-4fa9-aae4-f57b3c7d3b83.png)

大理石图表的顶部显示了一个时间线，其中显示了一系列值（表示为圆圈）。每个值将通过一个 map 操作符，该操作符以 lambda 作为参数。lambda 将应用于流的每个元素，以产生输出流（在图表的底部部分显示为菱形）。

# RxCpp（流）操作符

流导向处理的主要优势之一是我们可以在其上应用函数式编程原语。在 RxCpp 术语中，处理是使用操作符完成的。它们只是对流的过滤、转换、聚合和减少。我们已经看到了 `map`、`filter` 和 `take` 操作符在之前的示例中是如何工作的。让我们进一步探索它们。

# 平均值操作符

`average` 操作符计算来自 Observable Streams 的值的算术平均值。其他支持的统计操作符包括：

+   Min

+   Max

+   计数

+   Sum

以下程序只是演示了 `average` 操作符。在前面的列表中，其他操作符的模式是相同的：

```cpp
//----------- Average.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <ioStream> 
int main() { 
    auto values = rxcpp::observable<>::range(1, 20).average(); 
    values.subscribe( 
            [](double v){printf("average: %lfn", v);}, 
            [](){printf("OnCompletedn");}); 
} 
```

# 扫描操作符

`scan` 操作符对流的每个元素依次应用函数，并将值累积到种子值中。以下程序在值累积时产生一系列数字的平均值：

```cpp
//----------- Scan.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <ioStream> 
int main() { 
    int count = 0; 
    auto values = rxcpp::observable<>::range(1, 20). 
        scan( 0,&count{ 
                count++; 
                return seed + v; 
            }); 
    values.subscribe( 
        &{printf("Average through Scan: %fn", (double)v/count);}, 
        [](){printf("OnCompletedn");}); 
} 
```

运行平均值将打印到控制台。在调用 `OnCompleted` 之前，`OnNext functor` 将被调用二十次。

# 通过管道操作符组合操作符

RxCpp 库允许开发者链式或组合操作符以启用操作符组合。该库允许您使用 `pipe` (`|`) 操作符来组合操作符（而不是使用 "." 的通常流畅接口），程序员可以将一个操作符的输出管道传递给另一个，就像在 UNIX shell 的命令行中一样。这有助于理解（代码的作用是什么）。以下程序使用 `|` 操作符来映射一个范围。RxCpp 示例包含许多使用管道函数的示例：

```cpp
//------------------ Map_With_Pipe.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
namespace Rx { 
using namespace rxcpp; 
using namespace rxcpp::sources; 
using namespace rxcpp::operators; 
using namespace rxcpp::util; 
} 
using namespace Rx; 
#include <ioStream> 
int main() { 
    //---------- chain map to the range using the pipe operator 
    //----------- avoids the use of . notation. 
    auto ints = rxcpp::observable<>::range(1,10) |  
                 map( [] ( int n  ) {return n*n; }); 
    ints.subscribe( 
            [](int v){printf("OnNext: %dn", v);}, 
            [](){printf("OnCompletedn");}); 
}
```

# 使用调度器

我们已经在上面的部分学习了 Observables、Operators 和 Observers。我们现在知道，在 Observables 和 Observers 之间，我们可以应用标准的 Rx 操作符来过滤和转换流。在函数式编程的情况下，我们编写不可变的函数（没有副作用的函数），不可变性的结果是可能出现无序执行。如果我们可以保证操作符的输入永远不会被修改，那么执行函数/函子的顺序就不重要了。由于 Rx 程序将操作多个 Observables 和 Observers，我们可以将选择执行顺序的任务委托给调度程序模块。默认情况下，Rxcpp 是单线程的。RxCpp 将在我们调用`subscribe`方法的线程中安排操作符的执行。可以使用`observe_on`和`subscribe_on`操作符指定不同的线程。此外，一些 Observable 操作符以调度程序作为参数，执行可以在调度程序管理的线程中进行。

RxCpp 库支持以下两种调度程序类型：

+   `ImmediateScheduler`

+   `EventLoopScheduler`

RxCpp 库默认是单线程的。但是你可以使用特定的操作符来配置它在多个线程中运行：

```cpp
//----------ObserveOn.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <ioStream> 
#include <thread> 
int main(){ 
 //---------------- Generate a range of values 
 //---------------- Apply Square function 
 auto values = rxcpp::observable<>::range(1,4). 
               map([](int v){ return v*v;}); 
 //------------- Emit the current thread details 
 std::cout  << "Main Thread id => "  
            << std::this_thread::get_id()  
            << std::endl; 
 //---------- observe_on another thread.... 
 //---------- make it blocking to  
 //--------- Consult the Rxcpp documentation on observe_on and schedulers
 values.observe_on(rxcpp::synchronize_new_thread()).as_blocking(). 
 subscribe( [](int v){  
                   std::cout << "Observable Thread id => "  
                             << std::this_thread::get_id()  
                             << "  " << v << std::endl ;}, 
                  [](){ std::cout << "OnCompleted" << std::endl; }); 
 //------------------ Print the main thread details 
 std::cout << "Main Thread id => "  
           << std::this_thread::get_id()  
           << std::endl;   
} 
```

前面的程序将产生以下输出。我们将使用 STD C++线程 ID 来帮助我们区分在新线程中安排的项目（其中一个与主线程不同）：

```cpp
Main Thread id => 1 
Observable Thread id => 2  1 
Observable Thread id => 2  4 
Observable Thread id => 2  9 
Observable Thread id => 2  16 
OnCompleted 
Main Thread id => 1 
```

以下程序将演示`subscribe_on`方法的用法。在行为上，`observe_on`和`subscribe_on`方法之间存在微妙的差异。以下列表的目的是展示声明式调度的选项：

```cpp
//---------- SubscribeOn.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <ioStream> 
#include <thread> 
#include <mutex> 
//------ A global mutex for output synch. 
std::mutex console_mutex; 
//------ Print the Current Thread details 
void CTDetails() { 
   console_mutex.lock(); 
   std::cout << "Current Thread id => "  
           << std::this_thread::get_id()  << std::endl;  
   console_mutex.unlock();  
} 
//---------- a function to Yield control to other threads 
void Yield( bool y ) { 
   if (y) { std::this_thread::yield(); } 

} 
int main(){ 
    auto threads = rxcpp::observe_on_event_loop(); 
    auto values = rxcpp::observable<>::range(1); 
    //------------- Schedule it in another thread 
    auto s1 = values.subscribe_on(threads). 
        map([](int prime) {  
             CTDetails(); Yield(true); return std::make_tuple("1:", prime);}); 
    //-------- Schedule it in Yet another theread 
    auto s2 = values. subscribe_on(threads).  
        map([](int prime) { 
           CTDetails(); Yield(true) ; return std::make_tuple("2:", prime);}); 

    s1.merge(s2). take(6).as_blocking().subscribe(rxcpp::util::apply_to( 
            [](const char* s, int p) { 
                CTDetails(); 
                console_mutex.lock(); 
                printf("%s %dn", s, p); 
                console_mutex.unlock(); 
            })); 
} 
```

# 两个操作符的故事- flatmap 与 concatmap

开发人员经常围绕 flatmap 和`concatmap`操作符产生困惑。它们的区别非常重要，我们将在本节中进行介绍。让我们看一下 flatmap 操作符以及它的工作原理：

```cpp
//----------- Flatmap.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <ioStream> 
namespace rxu=rxcpp::util; 
#include <array> 
int main() { 
     std::array< std::string,4 > a={{"Praseed", "Peter", "Sanjay","Raju"}}; 
     //---------- Apply Flatmap on the array of names 
     //---------- Flatmap returns an Observable<T> ( map returns T ) 
     //---------- The First lamda creates a new Observable<T> 
     //---------- The Second Lambda manipulates primary Observable and  
     //---------- Flatmapped Observable 
     auto values = rxcpp::observable<>::iterate(a).flat_map( 
              [] (std::string v ) { 
                   std::array<std::string,3> salutation= 
                       { { "Mr." ,  "Monsieur" , "Sri" }}; 
                   return rxcpp::observable<>::iterate(salutation); 
              }, 
              [] ( std::string f , std::string s ) {return s + " " +f;}); 
     //-------- As usual subscribe  
     //-------- Here the value will be interleaved as flat_map merges the  
     //-------- Two Streams 
     values.subscribe(  
              [] (std::string f) { std::cout << f <<  std::endl; } ,  
              [] () {std::cout << "Hello World.." << std::endl;} ); 
      } 
```

前面的程序产生了不可预测的输出序列。程序的一次运行的输出如下所示。这不一定是再次运行时得到的结果。这种行为的原因与映射操作后的流的后处理有关：flatmap 使用 merge 操作符对流进行后处理。

```cpp
Mr. Praseed 
Monsieur Praseed 
Mr. Peter 
Sri Praseed 
Monsieur Peter 
Mr. Sanjay 
Sri Peter 
Monsieur Sanjay 
Mr. Raju 
Sri Sanjay 
Monsieur Raju 
Sri Raju 
Hello World.. 
```

以下的弹珠图显示了操作的模式。`flat_map`对 Observable Stream 应用 lambda 并产生一个新的 Observable Stream。产生的流被合并在一起以提供输出。在图中，红色的球被转换成一对红色的菱形，而绿色和蓝色的球的输出在新创建的 Observable 中产生交错的菱形：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-rct-prog/img/343fddd9-d86e-484b-97e8-15b35584ee34.png)

让我们通过以下列表来看一下`concat_map`操作符。程序列表与之前的程序相同。唯一的变化是用`concat_map`替换了`flat_map`。尽管列表中没有实际区别，但输出行为上有明显的不同。也许`concat_map`产生的输出更适合程序员的同步心理模型：

```cpp
//----------- ConcatMap.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <ioStream> 
namespace rxu=rxcpp::util; 

#include <array> 
int main() { 

     std::array< std::string,4 > a={{"Praseed", "Peter", "Sanjay","Raju"}}; 
     //---------- Apply Concat map on the array of names 
     //---------- Concat Map returns an Observable<T> ( oncat returns T ) 
     //---------- The First lamda creates a new Observable<T> 
     //---------- The Second Lambda manipulates primary Observable and  
     //---------- Concatenated Observable 
     auto values = rxcpp::observable<>::iterate(a).flat_map( 
              [] (std::string v ) { 
                   std::array<std::string,3> salutation= 
                       { { "Mr." ,  "Monsieur" , "Sri" }}; 
                   return rxcpp::observable<>::iterate(salutation); 
              }, 
              [] ( std::string f , std::string s ) {return s + " " +f;}); 

     //-------- As usual subscribe  
     //-------- Here the value will be interleaved as concat_map concats the  
     //-------- Two Streams 
     values.subscribe(  
              [] (std::string f) { std::cout << f <<  std::endl; } ,  
              [] () {std::cout << "Hello World.." << std::endl;} ); 
 } 
```

输出将如下所示：

```cpp
Mr. Praseed 
Monsieur Praseed 
Sri Praseed 
Mr. Peter 
Monsieur Peter 
Sri Peter 
Mr. Sanjay 
Monsieur Sanjay 
Sri Sanjay 
Mr. Raju 
Monsieur Raju 
Sri Raju 
Hello World.. 
```

以下的弹珠图显示了`concat_map`的操作。与 Flatmap 弹珠图不同，输出是同步的（红色、绿色和蓝色的球按照输入处理的顺序产生相同颜色的输出）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-rct-prog/img/0fc73749-7bc0-4da9-bfc4-95c0a87e3b28.png)

在`flat_map`的情况下，我们以交错的方式得到了输出。但在`concat_map`的情况下，我们按照预期的顺序得到了值。这里真正的区别是什么？为了澄清区别，让我们看看两个操作符：`concat`和`merge`。让我们看看流的连接方式。它基本上是将流的内容一个接一个地附加，保持顺序：

```cpp
//---------------- Concat.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <ioStream> 
#include <array> 
int main() { 
    auto o1 = rxcpp::observable<>::range(1, 3); 
    auto o3 = rxcpp::observable<>::from(4, 6); 
    auto values = o1.concat(o2); 
    values.subscribe( 
            [](int v){printf("OnNext: %dn", v);},[](){printf("OnCompletedn");}); 
} 
```

以下弹珠图清楚地显示了当`concat`操作符应用于两个流时会发生什么。我们通过将第二个流的内容附加到第一个流的内容来创建一个新流。这保留了顺序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-rct-prog/img/c2d0a75b-de50-4890-9735-f63cb41d2227.png)

现在，让我们看看当两个流合并时会发生什么。以下代码显示了如何合并两个流：

```cpp
//------------ Merge.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <ioStream> 
#include <array> 
int main() { 
    auto o1 = rxcpp::observable<>::range(1, 3); 
    auto o2 = rxcpp::observable<>::range(4, 6); 
    auto values = o1.merge(o2); 
    values.subscribe( 
            [](int v){printf("OnNext: %dn", v);}, 
             [](){printf("OnCompletedn");}); 
} 
```

以下弹珠图清楚地显示了当我们合并两个 Observable 流时会发生什么。输出流的内容将是两个流的交错组合：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-rct-prog/img/b4d9457c-159e-44d7-9893-64b195484549.png)

`flat_map`和`concat_map`基本上做相同的操作。区别在于值的组合方式。`flat_map`使用`merge`操作符，而`concact_map`使用`concact`操作符进行结果的后处理。在`merge`的情况下，顺序并不重要。`concat`操作符将 Observable 一个接一个地附加。这就是为什么使用`concat_map`会得到同步的输出，而`flat_map`会产生无序的结果。

# 其他重要操作符

我们现在理解了响应式编程模型的要点，因为我们涵盖了诸如 Observables、Observers、Operators 和 Schedulers 等基本主题。还有一些我们应该了解以更好地编写逻辑的操作符。在本节中，我们将介绍`tap`、`defer`和`buffer`操作符。我们将首先探讨`tap`操作符，它可以帮助查看流的内容：

```cpp
//----------- TapExample.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <ioStream> 
int main() { 
    //---- Create a mapped Observable 
     auto ints = rxcpp::observable<>::range(1,3). 
                 map( [] ( int n  ) {return n*n; }); 
     //---- Apply the tap operator...The Operator  
     //---- will act as a filter/debug operator 
     auto values = ints.tap( 
          [](int v)  {printf("Tap -       OnNext: %dn", v);}, 
          [](){printf("Tap -       OnCompletedn"); 
     }); 
     //------- Do some action 
     values.subscribe( 
          [](int v){printf("Subscribe - OnNext: %dn", v);}, 
          [](){printf("Subscribe - OnCompletedn");}); 
 } 
```

现在，让我们看看`defer`操作符。`defer`操作符将 Observable 工厂作为参数，为每个订阅它的客户端创建一个 Observable。在下面的程序中，当有人尝试连接到指定的 Observable 时，我们调用`observable_factory` lambda：

```cpp
//----------- DeferExample.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <ioStream> 
int main() { 
    auto observable_factory = [](){ 
         return rxcpp::observable<>::range(1,3). 
                 map( [] ( int n  ) {return n*n; }); 
    }; 
    auto ints = rxcpp::observable<>::defer(observable_factory); 
    ints.subscribe([](int v){printf("OnNext: %dn", v);}, 
            [](){printf("OnCompletedn");}); 
    ints.subscribe( 
            [](int v){printf("2nd OnNext: %dn", v);}, 
            [](){printf("2nd OnCompletedn");}); 
} 
```

`buffer`操作符发出一个 Observable，其中包含 Observable 的非重叠内容，每个 Observable 最多包含由 count 参数指定的项目数。这将帮助我们以适合内容的方式处理项目：

```cpp
//----------- BufferExample.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <ioStream> 
int main() { 
   auto values = rxcpp::observable<>::range(1, 10).buffer(2); 
   values.subscribe( [](std::vector<int> v){ 
                printf("OnNext:{"); 
                std::for_each(v.begin(), v.end(), [](int a){ 
                    printf(" %d", a); 
                }); 
                printf("}n"); 
            }, 
            [](){printf("OnCompletedn");}); 
} 
```

`timer`操作符发出一个 Observable，以间隔周期作为参数。有一个选项可以指定`Scheduler`对象作为参数。库中有这个函数的各种版本；我们在下面的代码中展示了其中一个：

```cpp
//----------- TimerExample.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <ioStream> 
int main() { 
     auto Scheduler = rxcpp::observe_on_new_thread(); 
     auto period = std::chrono::milliseconds(1); 
     auto values = rxcpp::observable<>::timer(period, Scheduler). 
            finally([](){ 
            printf("The final actionn"); 
        });     
      values.as_blocking().subscribe( 
         [](int v){printf("OnNext: %dn", v);}, 
         [](){printf("OnCompletedn");}); 
} 
```

# 我们尚未涵盖的事物一瞥

Rx 编程模型可以被认为是以下内容的汇合：

+   数据流计算

+   声明式并发

+   函数式编程

+   流处理（事件）

+   设计模式和习语

要全面了解整个学科，您需要广泛地使用编程模型。最初，事情不会有太多意义。在某个时候，您会达到一个*点燃点*，一切都会开始有意义。到目前为止，我们已经涵盖了以下主题：

+   Observables 和 Observers

+   基本和中级操作符

+   基本和中级调度

这只是一个开始，我们需要涵盖更多的主题，以熟悉编程模型。它们是：

+   热和冷 Observables（第八章，*RxCpp - 关键元素*）

+   Rx 组件的详细探索（[第八章](https://cdp.packtpub.com/c___reactive_programming/wp-admin/post.php?post=79&action=edit#post_86)，*RxCpp - 关键元素*）

+   高级调度（[第八章](https://cdp.packtpub.com/c___reactive_programming/wp-admin/post.php?post=79&action=edit#post_86)，*RxCpp - 关键元素*）

+   编程 GUI 系统（[第九章](https://cdp.packtpub.com/c___reactive_programming/wp-admin/post.php?post=79&action=edit#post_86)，*使用 Qt/C++进行响应式 GUI 编程*）

+   高级操作符（[第十章](https://cdp.packtpub.com/c___reactive_programming/wp-admin/post.php?post=79&action=edit#post_86)，在 RxCpp 中创建自定义操作符）

+   响应式设计模式（第十一章，*C++ Rx 编程的设计模式和习语*）

+   编程的健壮性（第十三章，*高级流和错误处理*）

# 总结

在本章中，我们在理解 Rx 编程模型和 RxCpp 库方面涵盖了相当多的内容。我们从数据流计算范式的概念概述开始，迅速转向编写一些基本的 RxCpp 程序。在介绍 Rx 弹珠图后，我们了解了 RxCpp 库支持的一组操作符。我们还介绍了调度器这一重要主题，最后讨论了`flatmap`和`concatmap`操作符之间的区别。在下一章中，我们将涵盖`hot`和`cold`可观察对象，高级调度以及一些本章未涵盖的主题。
