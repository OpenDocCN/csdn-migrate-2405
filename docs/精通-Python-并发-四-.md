# 精通 Python 并发（四）

> 原文：[`zh.annas-archive.org/md5/9D7D3F09D4C6183257545C104A0CAC2A`](https://zh.annas-archive.org/md5/9D7D3F09D4C6183257545C104A0CAC2A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十六章：设计基于锁和无互斥锁的并发数据结构

在本章中，我们将分析设计和实现并发编程中两种常见类型的数据结构的详细过程：基于锁和无互斥锁。将讨论这两种数据结构之间的主要区别，以及它们在并发编程中的使用。在整个章节中，还提供了并发程序准确性和速度之间的权衡分析。通过这种分析，读者将能够为自己的并发应用程序应用相同的权衡分析。

本章将涵盖以下主题：

+   基于锁数据结构的常见问题，以及如何解决这些问题

+   如何实现基于锁的数据结构的详细分析

+   无互斥锁数据结构的理念，以及与基于锁数据结构相比的优缺点

+   如何实现无互斥锁数据结构的详细分析

# 技术要求

以下是本章的先决条件列表：

+   确保您的计算机上已安装 Python 3

+   在[`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python)上下载 GitHub 存储库

+   在本章中，我们将使用名为`Chapter16`的子文件夹进行工作

+   查看以下视频以查看代码实际运行情况：[`bit.ly/2QhT3MS`](http://bit.ly/2QhT3MS)

# Python 中基于锁的并发数据结构

在前几章中，我们讨论了锁的使用，您了解到锁并不会锁住任何东西；在数据结构上实现的不牢固的锁定机制实际上并不能阻止外部程序同时访问数据结构，因为它们可以简单地绕过所施加的锁。解决这个问题的一个方法是将锁嵌入到数据结构中，这样外部实体就无法忽略锁。

在本章的第一部分中，我们将考虑锁和基于锁的数据结构的特定使用背后的理论。具体来说，我们将分析设计一个可以由不同线程安全执行的并发计数器的过程，使用锁（或互斥锁）作为同步机制。

# LocklessCounter 和竞争条件

首先，让我们模拟在并发程序中使用一个天真的、无锁实现的计数器类遇到的问题。如果您已经从 GitHub 页面下载了本书的代码，请转到`Chapter16`文件夹。

让我们来看一下`Chapter16/example1.py`文件，特别是`LocklessCounter`类的实现：

```py
# Chapter16/example1.py

import time

class LocklessCounter:
    def __init__(self):
        self.value = 0

    def increment(self, x):
        new_value = self.value + x
        time.sleep(0.001) # creating a delay
        self.value = new_value

    def get_value(self):
        return self.value
```

这是一个简单的计数器，具有名为`value`的属性，其中包含计数器的当前值，在计数器实例首次初始化时赋值为`0`。该类的`increment()`方法接受一个参数`x`，并将调用`LocklessCounter`对象的当前值增加`x`。请注意，在`increment()`函数内部我们创建了一个小延迟，用于计算计数器的新值和将该新值分配给计数器对象的过程之间。该类还有一个名为`get_value()`的方法，返回调用计数器的当前值。

很明显，这种`LocklessCounter`类的实现在并发程序中可能会导致竞争条件：当一个线程正在增加共享计数器时，另一个线程也可能访问计数器来执行`increment()`方法，并且第一个线程对计数器值的更改可能会被第二个线程所覆盖。

作为复习，以下图表显示了在多个进程或线程同时访问和改变共享资源的情况下竞争条件如何发生：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/c9c5bd97-d645-4f09-ac3e-f925f29357b6.png)

竞争条件的图示

为了模拟这种竞争条件，在我们的主程序中，我们包括了共计三个线程，将共享计数器增加 300 次：

```py
# Chapter16/example1.py

from concurrent.futures import ThreadPoolExecutor

counter = LocklessCounter()
with ThreadPoolExecutor(max_workers=3) as executor:
    executor.map(counter.increment, [1 for i in range(300)])

print(f'Final counter: {counter.get_value()}.')
print('Finished.')
```

`concurrent.futures`模块为我们提供了一种简单且高级的方式，通过线程池调度任务。具体来说，在初始化共享计数器对象后，我们将变量`executor`声明为一个包含三个线程的线程池（使用上下文管理器），并且该执行器调用共享计数器的`increment()`方法 300 次，每次将计数器的值增加`1`。

这些任务将在线程池中的三个线程之间执行，使用`ThreadPoolExecutor`类的`map()`方法。在程序结束时，我们只需打印出计数器对象的最终值。运行脚本后，以下代码显示了我的输出：

```py
> python3 example1.py
Final counter: 101.
Finished.
```

虽然在您自己的系统上执行脚本可能会获得计数器的不同值，但计数器的最终值实际上是 300，这是正确的值，这种情况极不可能发生。此外，如果您一遍又一遍地运行脚本，可能会获得计数器的不同值，说明程序的非确定性。同样，由于一些线程覆盖了其他线程所做的更改，一些增量在执行过程中丢失了，导致计数器在这种情况下只成功增加了`101`次。

# 在计数器的数据结构中嵌入锁

良好的基于锁的并发数据结构的目标是在其类属性和方法内部实现其锁，以便外部函数和程序无法绕过这些锁并同时访问共享的并发对象。对于我们的计数器数据结构，我们将为该类添加一个额外的属性，该属性将保存与计数器的值对应的`lock`对象。考虑在`Chapter16/example2.py`文件中的数据结构的以下新实现：

```py
# Chapter16/example2.py

import threading
import time

class LockedCounter:
    def __init__(self):
        self.value = 0
        self.lock = threading.Lock()

    def increment(self, x):
        with self.lock:
            new_value = self.value + x
            time.sleep(0.001) # creating a delay
            self.value = new_value

    def get_value(self):
        with self.lock:
            value = self.value

        return value
```

在我们的计数器数据结构实现中，还初始化了一个`lock`对象作为`LockedCounter`实例的属性，当初始化该实例时。此外，每当线程访问计数器的值时，无论是读取（`get_value()`方法）还是更新（`increment()`方法），都必须获取该`lock`属性，以确保没有其他线程也在访问它。这是通过使用`lock`属性的上下文管理器来实现的。

理论上，这种实现应该为我们解决竞争条件的问题。在我们的主程序中，我们正在实现与上一个示例中使用的相同的线程池。将创建一个共享计数器，并且它将在三个不同的线程中被增加 300 次（每次增加一个单位）：

```py
# Chapter16/example2.py

from concurrent.futures import ThreadPoolExecutor

counter = LockedCounter()
with ThreadPoolExecutor(max_workers=3) as executor:
    executor.map(counter.increment, [1 for i in range(300)])

print(f'Final counter: {counter.get_value()}.')
print('Finished.')
```

运行脚本，程序产生的输出应与以下类似：

```py
> python3 example2.py
Final counter: 300.
Finished.
```

如您所见，竞争条件的问题已经成功解决：计数器的最终值为`300`，完全对应于执行的增量数量。此外，无论程序运行多少次，计数器的值始终保持为`300`。我们目前拥有的是一个可并发计数器的工作正确的数据结构。

# 可扩展性的概念

编程中一个重要的方面是**可扩展性**。可扩展性指的是当程序要处理的任务数量增加时，性能的变化。Software Performance and Scalability Consulting, LLC 的创始人兼总裁 Andre B. Bondi 将可扩展性定义为<q>*“系统、网络或进程处理不断增长的工作量的能力，或者其扩大以适应这种增长的潜力。”*</q>

在并发编程中，可伸缩性是一个重要的概念，总是需要考虑；在并发编程中增长的工作量通常是要执行的任务数量，以及执行这些任务的活动进程和线程的数量。例如，并发应用程序的设计、实现和测试阶段通常涉及相当少量的工作，以促进高效和快速的开发。这意味着典型的并发应用程序在实际情况下将处理比在开发阶段更多的工作。这就是为什么可伸缩性分析在设计良好的并发应用程序中至关重要。

由于进程或线程的执行是独立于另一个进程的执行的，只要单个进程/线程负责的工作量保持不变，我们希望进程/线程数量的变化不会影响程序的性能。这种特性称为**完美的可伸缩性**，是并发程序的理想特性；如果给定的完全可伸缩的并发程序的工作量增加，程序可以简单地创建更多的活动进程或线程，以吸收增加的工作量。其性能可以保持稳定。

然而，由于创建线程和进程的开销，完美的可伸缩性在大多数情况下几乎是不可能实现的。也就是说，如果并发程序的性能随着活动进程或线程数量的增加而没有明显恶化，那么我们可以接受可伸缩性。**明显恶化**这个术语在很大程度上取决于并发程序负责执行的任务类型，以及允许程序性能下降的程度有多大。

在这种分析中，我们将考虑一个二维图表，表示给定并发程序的可伸缩性。*x*轴表示活动线程或进程的数量（每个线程或进程负责在整个程序中执行固定数量的工作）；*y*轴表示程序的速度，具有不同数量的活动线程或进程。所考虑的图表将具有一般上升的趋势；程序拥有的进程/线程越多，程序执行所需的时间（很可能）就越长。另一方面，完美的可伸缩性将转化为水平线，因为增加线程/进程数量时不需要额外的时间。

以下图表是可伸缩性分析的示例：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/719e2141-ce98-4fb4-9b03-912088d34e31.png)

可伸缩性分析示例（来源：stackoverflow.com/questions/10660990/c-sharp-server-scalability-issue-on-linux）

在前面的图表中，*x*轴表示执行线程/进程的数量，*y*轴表示运行时间（在这种情况下为秒）。不同的图表表示特定设置的可伸缩性（操作系统与多个核心的组合）。

图表的斜率越陡，相应的并发模型随着线程/进程数量的增加而扩展得越差。例如，水平线（在这种情况下为深蓝色和最低的图表）表示完美的可伸缩性，而黄色（最上面的）图表表示不良的可伸缩性。

# 对计数器数据结构的可伸缩性分析

现在，让我们考虑我们当前计数器数据结构的可扩展性——具体来说，是随着活动线程数量的变化。我们有三个线程为共享计数器增加了总共 300 次；因此，在我们的可扩展性分析中，我们将使每个活动线程为共享计数器增加 100 次，同时改变程序中的活动线程数量。根据前述的可扩展性规范，我们将看看在线程数量增加时使用计数器数据结构的程序的性能（速度）如何变化。

考虑`Chapter16/example3.py`文件，如下所示：

```py
# Chapter16/example3.py

import threading
from concurrent.futures import ThreadPoolExecutor
import time
import matplotlib.pyplot as plt

class LockedCounter:
    def __init__(self):
        self.value = 0
        self.lock = threading.Lock()

    def increment(self, x):
        with self.lock:
            new_value = self.value + x
            time.sleep(0.001) # creating a delay
            self.value = new_value

    def get_value(self):
        with self.lock:
            value = self.value

        return value

n_threads = []
times = []
for n_workers in range(1, 11):
    n_threads.append(n_workers)

    counter = LockedCounter()

    start = time.time()

    with ThreadPoolExecutor(max_workers=n_workers) as executor:
        executor.map(counter.increment, 
                     [1 for i in range(100 * n_workers)])

    times.append(time.time() - start)

    print(f'Number of threads: {n_workers}')
    print(f'Final counter: {counter.get_value()}.')
    print(f'Time taken: {times[-1] : .2f} seconds.')
    print('-' * 40)

plt.plot(n_threads, times)
plt.xlabel('Number of threads'); plt.ylabel('Time in seconds')
plt.show()
```

在前面的脚本中，我们仍然使用了在上一个示例中使用的`LockedCounter`类的相同实现。在我们的主程序中，我们正在测试这个类针对各种数量的活动线程；具体来说，我们正在迭代一个`for`循环，使活动线程的数量从 1 增加到 10。在每次迭代中，我们初始化一个共享计数器，并创建一个线程池来处理适当数量的任务——在这种情况下，为每个线程增加共享计数器 100 次。

我们还跟踪活动线程的数量，以及线程池完成任务所花费的时间。这是我们进行可扩展性分析的数据。我们将打印出这些数据，并绘制一个类似于前面示例图中的可扩展性图表。

以下代码显示了我运行脚本的输出：

```py
> python3 example3.py
Number of threads: 1
Final counter: 100.
Time taken: 0.15 seconds.
----------------------------------------
Number of threads: 2
Final counter: 200.
Time taken: 0.28 seconds.
----------------------------------------
Number of threads: 3
Final counter: 300.
Time taken: 0.45 seconds.
----------------------------------------
Number of threads: 4
Final counter: 400.
Time taken: 0.59 seconds.
----------------------------------------
Number of threads: 5
Final counter: 500.
Time taken: 0.75 seconds.
----------------------------------------
Number of threads: 6
Final counter: 600.
Time taken: 0.87 seconds.
----------------------------------------
Number of threads: 7
Final counter: 700.
Time taken: 1.01 seconds.
----------------------------------------
Number of threads: 8
Final counter: 800.
Time taken: 1.18 seconds.
----------------------------------------
Number of threads: 9
Final counter: 900.
Time taken: 1.29 seconds.
----------------------------------------
Number of threads: 10
Final counter: 1000.
Time taken: 1.49 seconds.
----------------------------------------
```

此外，我得到的可扩展性图如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/e4a205f0-bac9-43e2-9c13-a4599f1d02a5.png)

基于锁的计数器数据结构的可扩展性

即使您自己的输出在每次迭代的具体持续时间上有所不同，可扩展性趋势应该是相对相同的；换句话说，您的可扩展性图应该与前面的图表具有相同的斜率。从我们所拥有的输出类型中可以看出，尽管每次迭代中计数器的值都是正确的，但我们当前的计数器数据结构的可扩展性非常不理想：随着程序添加更多线程来执行更多任务，程序的性能几乎是线性下降的。请记住，理想的完美可扩展性要求性能在不同数量的线程/进程之间保持稳定。我们的计数器数据结构通过与活动线程数量的增加成比例地增加程序的执行时间。

直观地，这种可扩展性的限制是由我们的锁定机制造成的：由于在任何给定时间只有一个线程可以访问和增加共享计数器，程序需要执行的增量越多，完成所有增量任务所需的时间就越长。使用锁作为同步机制的最大缺点之一是：锁可以执行并发程序（再次强调，第一个缺点是锁实际上并没有锁定任何东西）。

# 近似计数器作为可扩展性的解决方案

考虑到设计和实现正确但快速的基于锁的并发数据结构的复杂性，开发高效可扩展的锁定机制是计算机科学研究中的热门话题，提出了许多解决我们面临问题的方法。在本节中，我们将讨论其中之一：**近似计数器**。

# 近似计数器背后的思想

让我们回顾一下我们当前的程序以及锁阻止我们在速度方面获得良好性能的原因：我们程序中的所有活动线程都与相同的共享计数器交互，这只能一次与一个线程交互。解决这个问题的方法是隔离与单独线程计数器的交互。具体来说，我们跟踪的计数器的值将不再仅由单个共享计数器对象表示；相反，我们将使用许多**本地计数器**，每个线程/进程一个，以及我们最初拥有的共享**全局计数器**。

这种方法背后的基本思想是将工作（递增共享全局计数器）分布到其他低级计数器中。当一个活动线程执行并想要递增全局计数器时，首先它必须递增其对应的本地计数器。与单个共享计数器进行交互不同，与各个本地计数器进行交互具有高度可扩展性，因为只有一个线程访问和更新每个本地计数器；换句话说，不同线程之间在与各个本地计数器交互时不会发生争用。

每个线程与其对应的本地计数器交互时，本地计数器必须与全局计数器交互。具体来说，每个本地计数器将定期获取全局计数器的锁，并根据其当前值递增它；例如，如果一个值为六的本地计数器想要递增全局计数器，它将以六个单位递增，并将自己的值设为零。这是因为从本地计数器报告的所有递增都是相对于全局计数器的值的，这意味着如果一个本地计数器持有值*x*，全局计数器应该将其值递增*x*。

您可以将这种设计看作是一个简单的网络，全局计数器位于中心节点，每个本地计数器都是一个后端节点。每个后端节点通过将其值发送到中心节点与中心节点交互，随后将其值重置为零。以下图示进一步说明了这种设计：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/abc0fe6d-7219-4f13-8299-0dad44854165.png)

四线程近似计数器的图示

如前所述，如果所有活动线程都与相同的基于锁的计数器交互，那么无法从使程序并发化中获得额外的速度，因为不同线程之间的执行无法重叠。现在，对于每个线程有一个单独的计数器对象，线程可以独立和同时更新其对应的本地计数器，从而创建重叠，这将导致程序的速度性能更好，使程序更具可扩展性。

**近似计数器**这个技术的名称来源于全局计数器的值仅仅是正确值的近似。具体来说，全局计数器的值仅通过本地计数器的值计算，每次全局计数器被本地计数器之一递增时，它就变得更加准确。

然而，这种设计中有一个值得深思的规范。本地计数器应该多久与全局计数器交互并更新其值？当然不能是每次递增的速率（每次递增本地计数器时递增全局计数器），因为那将等同于使用一个共享锁，甚至有更多的开销（来自本地计数器）。

阈值 S 是用来表示所讨论的频率的数量；具体来说，阈值 S 被定义为本地计数器值的上限。因此，如果本地计数器被递增，使其值大于阈值 S，它应该更新全局计数器并将其值重置为零。阈值 S 越小，本地计数器更新全局计数器的频率就越高，我们的程序的可伸缩性就越低，但全局计数器的值将更加及时。相反，阈值 S 越大，全局计数器的值更新频率就越低，但程序的性能就会更好。

因此，近似计数对象的准确性和使用该数据结构的并发程序的可伸缩性之间存在权衡。与计算机科学和编程中的其他常见权衡类似，只有通过个人实验和测试，才能确定适合自己的近似计数数据结构的最佳阈值 S。在下一节中，当我们为近似计数数据结构实现我们自己的设计时，我们将任意将阈值 S 的值设置为 10。

# 在 Python 中实现近似计数器

在考虑近似计数器的概念时，让我们尝试在 Python 中实现这个数据结构，建立在我们之前基于锁的计数器的设计之上。考虑以下`Chapter16/example4.py`文件，特别是`LockedCounter`类和`ApproximateCounter`类：

```py
# Chapter16/example4.py

import threading
import time

class LockedCounter:
    def __init__(self):
        self.value = 0
        self.lock = threading.Lock()

    def increment(self, x):
        with self.lock:
            new_value = self.value + x
            time.sleep(0.001) # creating a delay
            self.value = new_value

    def get_value(self):
        with self.lock:
            value = self.value

        return value

class ApproximateCounter:
    def __init__(self, global_counter):
        self.value = 0
        self.lock = threading.Lock()
        self.global_counter = global_counter
        self.threshold = 10

    def increment(self, x):
        with self.lock:
            new_value = self.value + x
            time.sleep(0.001) # creating a delay
            self.value = new_value

            if self.value >= self.threshold:
                self.global_counter.increment(self.value)
                self.value = 0

    def get_value(self):
        with self.lock:
            value = self.value

        return value
```

虽然`LockedCounter`类与之前的示例中保持不变（该类将用于实现我们的全局计数器对象），但`ApproximateCounter`类却很有意思，它包含了我们之前讨论的近似计数逻辑的实现。一个新初始化的`ApproximateCounter`对象将被赋予一个起始值为`0`，它也将有一个锁，因为它也是一个基于锁的数据结构。`ApproximateCounter`对象的重要属性是它需要报告给的全局计数器和指定它报告给相应全局计数器的速率的阈值。如前所述，这里我们只是随意选择`10`作为阈值的值。

在`ApproximateCounter`类的`increment()`方法中，我们还可以看到相同的递增逻辑：该方法接受一个名为`x`的参数，并在保持调用近似计数器对象的锁的情况下递增计数器的值。此外，该方法还必须检查计数器的新递增值是否超过了它的阈值；如果是，它将增加其全局计数器的值，增加的数量等于本地计数器的当前值，并将本地计数器的值设置回`0`。在这个类中用于返回计数器当前值的`get_value()`方法与我们之前看到的是一样的。

现在，让我们在主程序中测试和比较新数据结构的可伸缩性。首先，我们将重新生成旧的单锁计数器数据结构的可伸缩性数据：

```py
# Chapter16/example4.py

from concurrent.futures import ThreadPoolExecutor

# Previous single-lock counter

single_counter_n_threads = []
single_counter_times = []
for n_workers in range(1, 11):
    single_counter_n_threads.append(n_workers)

    counter = LockedCounter()

    start = time.time()

    with ThreadPoolExecutor(max_workers=n_workers) as executor:
        executor.map(counter.increment, 
                     [1 for i in range(100 * n_workers)])

    single_counter_times.append(time.time() - start)
```

就像在我们之前的示例中一样，我们使用`ThreadPoolExecutor`对象来并发处理任务，在单独的线程中跟踪每次迭代完成所花费的时间；这里没有什么令人惊讶的。接下来，我们将使用`for`循环的迭代中相应数量的活动线程生成相同的数据，如下所示：

```py
# New approximate counters

def thread_increment(counter):
    counter.increment(1)

approx_counter_n_threads = []
approx_counter_times = []
for n_workers in range(1, 11):
    approx_counter_n_threads.append(n_workers)

    global_counter = LockedCounter()

    start = time.time()

    local_counters = [ApproximateCounter(global_counter) for i in range(n_workers)]
    with ThreadPoolExecutor(max_workers=n_workers) as executor:
        for i in range(100):
            executor.map(thread_increment, local_counters)

    approx_counter_times.append(time.time() - start)

    print(f'Number of threads: {n_workers}')
    print(f'Final counter: {global_counter.get_value()}.')
    print('-' * 40)
```

让我们花一些时间来分析上述代码。首先，我们有一个外部的`thread_increment()`函数，它接受一个计数器并将其递增 1；稍后，这个函数将被用作重构后的代码，以单独递增我们的本地计数器。

同样，我们将通过`for`循环来迭代分析这种新数据结构在不同数量的活动线程下的性能。在每次迭代中，我们首先初始化一个`LockedCounter`对象作为我们的全局计数器，以及一个本地计数器列表，这些本地计数器是`ApproximateCounter`类的实例。它们都与同一个全局计数器相关联（在初始化方法中传递），因为它们需要报告给同一个计数器。

接下来，类似于我们一直在为多个线程安排任务所做的，我们使用上下文管理器创建一个线程池，在其中通过嵌套的`for`循环分发任务（增加本地计数器）。我们循环另一个`for`循环是为了模拟与我们在上一个示例中实现的任务数量一致，并将这些任务同时分配到所有本地计数器上。我们还在每次迭代中打印出全局计数器的最终值，以确保我们的新数据结构正常工作。

最后，在我们的主程序中，我们将绘制从两个`for`循环生成的数据点，以比较两种数据结构的可伸缩性及其各自的性能：

```py
# Chapter16/example4.py
import matplotlib.pyplot as plt

# Plotting

single_counter_line, = plt.plot(
    single_counter_n_threads,
    single_counter_times,
    c = 'blue',
    label = 'Single counter'
)
approx_counter_line, = plt.plot(
    approx_counter_n_threads,
    approx_counter_times,
    c = 'red',
    label = 'Approximate counter'
)
plt.legend(handles=[single_counter_line, approx_counter_line], loc=2)
plt.xlabel('Number of threads'); plt.ylabel('Time in seconds')
plt.show()
```

运行脚本，您将收到的第一个输出将包括我们第二个`for`循环中全局计数器的最终值，如下所示：

```py
> python3 example4.py
Number of threads: 1
Final counter: 100.
----------------------------------------
Number of threads: 2
Final counter: 200.
----------------------------------------
Number of threads: 3
Final counter: 300.
----------------------------------------
Number of threads: 4
Final counter: 400.
----------------------------------------
Number of threads: 5
Final counter: 500.
----------------------------------------
Number of threads: 6
Final counter: 600.
----------------------------------------
Number of threads: 7
Final counter: 700.
----------------------------------------
Number of threads: 8
Final counter: 800.
----------------------------------------
Number of threads: 9
Final counter: 900.
----------------------------------------
Number of threads: 10
Final counter: 1000.
----------------------------------------
```

正如您所看到的，我们从全局计数器获得的最终值都是正确的，证明我们的数据结构按预期工作。此外，您将获得类似以下的图表：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/d0be6423-ae92-4f2a-96fa-b5ad1ab64ea7.png)

单锁计数器和近似计数器的可伸缩性

蓝线表示单锁计数器数据结构速度的变化，而红线表示近似计数器数据结构的变化。正如您所看到的，即使随着线程数量的增加，近似计数器的性能略有下降（由于创建单独的本地计数器和分发增加的任务数量等开销），我们的新数据结构仍然具有很高的可伸缩性，特别是与以前的单锁计数器数据结构相比。

# 关于近似计数器设计的一些考虑

您可能已经注意到的一件事是，即使只有一个线程与一个本地计数器交互，数据结构在初始化时仍然具有`lock`属性。这是因为实际上多个线程可以共享相同的本地计数器。有时创建每个活动线程的本地计数器是低效的，因此开发人员可以让两个或更多线程共享相同的本地计数器，而个别计数器仍然可以报告给相同的全局计数器。

例如，假设有 20 个线程在并发计数器程序中执行；我们只能让 10 个本地计数器报告给一个全局计数器。从我们所见，这种设置的可伸缩性将低于为每个线程使用单独的本地计数器的设置，但这种方法的优势在于它使用更少的内存空间，并避免了创建更多本地计数器的开销。

程序中使用近似计数器的方式还有另一种可能的变化。除了只有一层本地计数器之外，我们还可以实现半全局计数器，本地计数器报告给它，然后它再报告给比自己高一级的全局计数器。在使用近似计数器数据结构时，开发人员不仅需要像之前讨论的那样找到适当的报告阈值，还需要优化与一个单个本地计数器相关联的线程数量，以及我们设计中的层数。

# Python 中无互斥锁的并发数据结构

前一小节总结了我们在 Python 中设计基于锁的并发数据结构以及其中涉及的复杂性的讨论。我们现在将转向一种理论上设计无互斥锁并发数据结构的方法。

并发数据结构中的“无互斥锁”一词表示缺乏保护数据结构完整性的锁定机制。这并不意味着数据结构简单地忽视了其数据的保护；相反，数据结构必须使用其他同步机制。在本节中，我们将分析一种这样的机制，称为“读-复制-更新”，并讨论如何将其应用到 Python 数据结构中。

# 在 Python 中无法实现无锁

基于锁的数据结构的对立面是无锁数据结构。在这里，我们将讨论其定义以及为什么在 Python 中实际上无法实现无锁的特性，以及我们能够接近的最近的是无互斥锁。

与基于锁的数据结构不同，无锁数据结构不仅不使用任何锁定机制（如无互斥锁数据结构），而且要求任何给定的线程或进程不能无限期地等待执行。这意味着，如果成功实现了无锁数据结构，使用该数据结构的应用程序将永远不会遇到死锁和饥饿问题。因此，无锁数据结构被广泛认为是并发编程中更高级的技术，因此它们要难得多地实现。

然而，无锁的特性实际上是无法在 Python（或者更具体地说，在 CPython 解释器中）中实现的。您可能已经猜到，这是由于 GIL 的存在，它阻止多个线程在任何给定时间在 CPU 中执行。要了解有关 GIL 的更多信息，请转到第十五章，“全局解释器锁”，并阅读有关 GIL 的深入分析，如果您还没有阅读的话。总的来说，在 CPython 中实现纯粹的无锁数据结构是一个逻辑上的不可能。

然而，这并不意味着 Python 中的并发程序不能从设计无锁数据结构中受益。如前所述，无互斥锁的 Python 数据结构（可以被视为无锁数据结构的子集）是完全可以实现的。事实上，无互斥锁的数据结构仍然可以成功避免死锁和饥饿问题。然而，它们无法充分利用纯粹的无锁执行，这将导致更快的速度。

在接下来的小节中，我们将研究 Python 中的自定义数据结构，分析如果同时使用会引发的问题，并尝试将无互斥锁的逻辑应用到底层数据结构中。

# 网络数据结构介绍

我们正在实现的数据结构类似于一个节点网络，其中一个节点是主节点。此外，每个节点都包含一个键和一个节点的值。您可以将这个数据结构看作是一个 Python 字典（换句话说，一组键和值分别配对在一起），但其中一个键和值对被称为网络的主节点。

一个很好的方式来可视化这种数据结构是分析使用该数据结构的情况。假设您被要求实现一个流行网站的请求处理逻辑，这个网站也不幸地是**拒绝服务（DoS）**攻击的常见目标。由于网站很可能会经常被关闭，尽管网络安全团队的努力，您可以采取的一种方法是在服务器上保留除主网站之外的多个工作副本，以确保网站的客户仍然能够访问它。

这些副本在每个方面等同于主网站，因此主网站可以随时完全被任何副本替换。现在，如果主网站被 DoS 攻击关闭，作为服务器管理员，您可以简单地允许主网站关闭并将新主网站的地址切换到您准备好的任何一个副本。因此，网站的客户在访问网站数据时不会遇到任何困难或不一致，因为副本与被关闭的主网站相同。另一方面，不实现此机制的服务器很可能需要花费一些时间来从 DoS 攻击中恢复（隔离攻击，重建中断或损坏的数据等）。

此时，可以建立这种网站管理方法与上述网络数据结构之间的联系。实际上，网络数据结构本质上是该方法的高级抽象；数据结构是一组节点或值对（在前面的情况下是网站地址和数据），同时跟踪一个主节点，也可以被任何其他节点替换（当主网站受到攻击时，访问网站的客户被引导到新网站）。我们将称这个处理为我们数据结构中的**刷新主要**，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/5091dce0-bb4e-424e-a79b-4e1ab81f7030.png)

网络主要刷新的图表

在上图中，我们的网络数据结构中有三个独立的数据节点（可视化为字典，用一对大括号表示）：键**A**，指向某些数据；键**B**，指向其自己的数据；最后，键**C**，也指向其自己的数据。此外，我们有一个指针指示我们字典网络的主键，指向键**A**。随着主要刷新过程的进行，我们将停止跟踪键**A**（即主键）及其自身，然后将主指针指向网络中的另一个节点（在本例中为键**B**）。

# 在 Python 中实现一个简单的网络数据结构和竞争条件

让我们考虑 Python 中这种数据结构的起始实现。按照以下方式导航到`Chapter16/network.py`文件：

```py
# Chapter16/network.py

import time
from random import choice

class Network:
    def __init__(self, primary_key, primary_value):
        self.primary_key = primary_key
        self.data = {primary_key: primary_value}

    def __str__(self):
        result = '{\n'
        for key in self.data:
            result += f'\t{key}: {self.data[key]};\n'

        return result + '}'

    def add_node(self, key, value):
        if key not in self.data:
            self.data[key] = value
            return True

        return False

    # precondition: the object has more than one node left
    def refresh_primary(self):
        del self.data[self.primary_key]
        self.primary_key = choice(list(self.data))

    def get_primary_value(self):
        primary_key = self.primary_key
        time.sleep(1) # creating a delay
        return self.data[primary_key]
```

这个文件包含了`Network`类，它实现了我们之前讨论过的逻辑。在初始化时，这个类的每个实例在其网络中至少有一个节点（存储在`data`属性中），这是它的主节点；我们还使用 Python 的字典数据结构来实现这个网络设计。每个对象还必须跟踪其主要数据的键，存储在其`primary_key`属性中。

在这个类中，我们还有一个`add_node()`方法，用于向网络对象添加新的数据节点；请注意，每个节点都必须有一个键和一个值。回想一下我们的网络管理示例——这对应于一个互联网地址和网站所拥有的数据。该类还有一个`refresh_primary()`方法，用于模拟刷新主要过程（删除对先前主要数据的引用，并从剩余节点中伪随机选择一个新的主节点）。请记住，这个方法的前提是调用网络对象必须至少还有两个节点。

最后，我们有一个叫做`get_primary_value()`的访问方法，它返回调用网络对象的主键指向的值。在这里，我们在方法的执行中添加了轻微的延迟，以模拟使用这种天真的数据结构会发生的竞争条件。（另外，我们正在重写默认的`__str__()`方法，以便进行简单的调试。）

现在，让我们把注意力转向`Chapter16/example5.py`文件，在这里我们导入这个数据结构并在一个并发程序中使用它：

```py
# Chapter16/example5.py

from network import Network
import threading

def print_network_primary_value():
    global my_network

    print(f'Current primary value: {my_network.get_primary_value()}.')

my_network = Network('A', 1)
print(f'Initial network: {my_network}')
print()

my_network.add_node('B', 1)
my_network.add_node('C', 1)
print(f'Full network: {my_network}')
print()

thread1 = threading.Thread(target=print_network_primary_value)
thread2 = threading.Thread(target=my_network.refresh_primary)

thread1.start()
thread2.start()

thread1.join()
thread2.join()

print(f'Final network: {my_network}')
print()

print('Finished.')
```

首先，我们实现了一个名为`print_network_primary_value()`的函数，它使用前面提到的`get_primary_value()`方法访问和获取网络对象的主要数据，这也是一个全局变量。在我们的主程序中，我们使用起始节点初始化了一个网络对象，`A`作为节点键，`1`作为节点数据（这个节点也自动成为主节点）。然后我们向这个网络添加了另外两个节点：`B`指向`1`，`C`也指向`1`。

现在，初始化并启动了两个线程，第一个调用`print_network_primary_value()`函数打印出网络的当前主要数据。第二个调用网络对象的`refresh_primary()`方法。我们还在程序的各个点打印出网络对象的当前状态。

很容易发现这里可能会发生竞争条件：因为第一个线程正在尝试访问主要数据，而第二个线程正在尝试刷新网络的数据（实质上，在那个时候删除当前的主要数据），第一个线程很可能会在执行过程中引发错误。具体来说，运行脚本后，以下是我的输出：

```py
> python3 example5.py
Initial network: {
 A: 1;
}

Full network: {
 A: 1;
 B: 1;
 C: 1;
}

Exception in thread Thread-1:
Traceback (most recent call last):
 File "/Library/Frameworks/Python.framework/Versions/3.7/lib/python3.7/threading.py", line 917, in _bootstrap_inner
 self.run()
 File "/Library/Frameworks/Python.framework/Versions/3.7/lib/python3.7/threading.py", line 865, in run
 self._target(*self._args, **self._kwargs)
 File "example5.py", line 7, in print_network_primary_value
 print(f'Current primary value: {my_network.get_primary_value()}.')
 File "/Users/quannguyen/Documents/python/mastering_concurrency/ch16/network.py", line 30, in get_primary_value
 return self.data[primary_key]
KeyError: 'A'

Final network: {
 B: 1;
 C: 1;
}

Finished.
```

就像我们讨论过的那样，我们遇到了一个`KeyError`，这是因为第一个线程获取主键的时候，该键和主要数据已经被第二个线程的执行从数据结构中删除了。下面的图表进一步说明了这一点：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/f7229d9b-ab3e-4217-bd3b-0b9a75781c70.png)

网络数据结构的竞争条件

正如你在之前的章节中看到的，我们在数据结构的源代码中使用了`time.sleep()`函数，以确保竞争条件会发生。大多数情况下，执行速度会足够快，不会出现错误，但竞争条件仍然存在，这是我们当前数据结构中需要解决的问题。

# RCU 作为解决方案

我们遇到的竞争条件的根源是，我们知道，我们正在使用的网络对象在不同的线程之间共享，这些线程同时对数据结构进行变异和读取数据。具体来说，我们程序中的第二个线程正在变异数据（通过调用`refresh_primary()`方法），而第一个线程正在从相同的数据中读取。

显然，我们可以简单地将锁定应用为该数据结构的同步机制。然而，我们知道获取和释放锁的任务涉及一些成本，随着数据结构在系统中被广泛使用，这些成本将变得相当可观。由于流行的网站和系统（即 MongoDB）使用此抽象来设计和构造其服务器，因此高水平的流量将使使用锁的成本显而易见，并导致性能下降。实现近似数据结构的变体可能有助于解决此问题，但实现的复杂性可能会被证明难以跟进。

因此，我们的目标是使用无互斥量的方法作为我们的同步机制——在这种情况下是**读-复制-更新**（**RCU**）。为了保护数据结构的完整性，RCU 本质上是一种同步机制，当线程或进程请求读取或写入访问时，它会创建并维护数据结构的另一个版本。通过在单独的副本中隔离数据结构和线程/进程之间的交互，RCU 确保不会发生冲突的数据。当线程或进程改变了其分配的数据结构副本中的信息时，该更新可以报告给原始数据结构。

简而言之，当共享数据结构有线程或进程请求访问它（读取过程）时，它需要返回自身的副本，而不是让线程/进程访问其自己的数据（复制过程）；最后，如果副本中的数据结构发生任何更改，它们将需要更新回共享数据结构（更新过程）。

RCU 对于需要同时处理单个更新程序和多个读取程序的数据结构特别有用，这是我们之前讨论的服务器网络的典型情况（多个客户端不断访问和请求数据，但只有偶尔的定期攻击）。但是这如何应用到我们当前的网络数据结构呢？理论上，我们的数据结构的访问器方法（`get_primary_value()`方法）需要在从线程读取数据之前创建数据结构的副本。这个规范在访问器方法中实现，在`Chapter16/concurrent_network.py`文件中，如下：

```py
# Chapter16/concurrent_network.py

from copy import deepcopy
import time

class Network:
    [...]

    def get_primary_value(self):
        copy_network = deepcopy(self)

        primary_key = copy_network.primary_key
        time.sleep(1) # creating a delay
        return copy_network.data[primary_key]
```

在这里，我们使用了 copy 模块中的内置`deepcopy`方法，它返回网络的不同内存位置的副本。然后，我们只从这个网络对象的副本中读取数据，而不是原始对象本身。这个过程在下面的图表中说明：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/9a43e409-4c9d-4035-bdd4-a834e1d80192.png)

RCU 解决竞争条件

在前面的图表中，我们可以看到在数据方面不会发生冲突，因为两个线程现在处理的是数据结构的不同副本。让我们在`Chapter16/example6.py`文件中看到这个实现的实际操作，该文件包含与之前的`example5.py`文件相同的指令（初始化网络对象，同时调用两个线程——一个用于访问网络的主要数据，另一个用于刷新相同的主要数据），只是现在程序正在使用我们从`concurrent_network.py`文件中获取的新数据结构。

在运行脚本之后，您的输出应该与以下内容相同：

```py
> python3 example6.py
Initial network: {
 A: 1;
}

Full network: {
 A: 1;
 B: 1;
 C: 1;
}

Current primary value: 1.
Final network: {
 B: 1;
 C: 1;
}

Finished.
```

正如您所看到的，程序不仅在第一个线程中获取了主要数据的正确值而没有引发任何错误，而且在程序结束时也保持了正确的网络（没有之前删除的节点，带有键`A`）。 RCU 方法确实解决了竞争条件的问题，而没有使用任何锁定机制。

您可能还注意到的一件事是，在前一节中，RCU 也可以应用于我们的计数器示例。事实上，RCU 和近似计数器都是解决计数器问题的合理方法，哪种方法对于特定的并发问题更好的问题只能通过可扩展性分析等经验性的实践分析来回答。

# 基于简单数据结构

在本章中，我们使用了许多简单的并发数据结构，如计数器和网络。因此，我们真正深入地了解了在使用这些数据结构的并发程序中遇到的问题，并能够深入分析如何改进它们的结构和设计。

当您在工作和项目中处理更复杂的并发数据结构时，您会发现它们的设计和结构以及伴随它们的问题实际上与我们分析的数据结构中看到的问题基本相似。通过真正理解数据结构的基本架构以及使用它们的程序可能出现的问题的根源，您可以在此基础上构建更复杂但逻辑上等效的数据结构。

# 总结

在本章中，我们研究了基于锁和无互斥锁数据结构之间的理论差异：基于锁的数据结构使用锁定机制来保护其数据的完整性，而无互斥锁的数据结构则不使用。我们分析了在设计不良的数据结构中可能出现的竞争条件问题，并探讨了如何在这两种情况下解决这个问题。

在我们的并发基于锁的计数器数据结构示例中，我们考虑了近似计数器的设计，以及设计可以提供的改进可扩展性。在我们对并发网络数据结构的分析中，我们研究了 RCU 技术，该技术将读取指令与更新指令隔离开来，目的是保持并发数据结构的完整性。

在下一章中，我们将研究 Python 并发编程中的另一组高级概念：内存模型和对原子类型的操作。您将更多地了解 Python 内存管理，以及原子类型的定义和用途。

# 问题

+   解决锁不锁任何东西的主要方法是什么？

+   在并发编程的背景下描述可扩展性的概念

+   天真的锁定机制如何影响并发程序的可扩展性？

+   近似计数器是什么，它如何帮助解决并发编程中的可扩展性问题？

+   Python 中是否可能存在无锁数据结构？为什么？

+   什么是无互斥锁并发数据结构，它与并发基于锁的数据结构有何不同？

+   RCU 技术是什么，以及它如何解决无互斥锁并发数据结构的问题？

# 进一步阅读

有关更多信息，您可以参考以下链接：

+   操作系统：三个简单部分。第 151 卷。威斯康星州：Arpaci-Dusseau Books，2014 年，作者：Arpaci-Dusseau，Remzi H.和 Andrea C. Arpaci-Dusseau

+   并发数据结构的秘密生活（[addthis.com/blog/2013/04/25/the-secret-life-of-concurrent-data-structures/](https://www.addthis.com/blog/2013/04/25/the-secret-life-of-concurrent-data-structures/#.W7onwBNKiAw)），作者：Michael Spiegel

+   RCU 在本质上是什么？Linux 周刊新闻（LWN.net）（2007），作者：McKenney，Paul E.和 Jonathan Walpole

+   黄蜂窝：Python 中的读-复制-更新模式（[emptysqua.re/blog/wasps-nest-read-copy-update-python/](https://emptysqua.re/blog/wasps-nest-read-copy-update-python/)），作者：Davis，A. Jesse Jiryu

+   可扩展性的特征及其对性能的影响，第二届国际软件和性能研讨会（WOSP）'00。第 195 页，André B


# 第十七章：内存模型和原子类型的操作

并发编程过程中需要考虑的问题以及随之而来的问题，都与 Python 管理其内存的方式有关。因此，对 Python 中变量和值的存储和引用方式有深入的了解，不仅有助于找出导致并发程序故障的低级错误，还有助于优化并发代码。在本章中，我们将深入研究 Python 内存模型以及其原子类型，特别是它们在 Python 并发生态系统中的位置。

本章将涵盖以下主题：

+   Python 内存模型，支持不同层次上的内存分配的组件，以及在 Python 中管理内存的一般理念

+   原子操作的定义，它们在并发编程中的作用，以及如何在 Python 中使用它们

# 技术要求

本章的技术要求如下：

+   在计算机上安装 Python 3

+   在[`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python)下载 GitHub 存储库

+   在本章中，我们将使用名为`Chapter17`的子文件夹进行工作

+   查看以下视频以查看代码实际操作：[`bit.ly/2AiToVy`](http://bit.ly/2AiToVy)

# Python 内存模型

你可能还记得在《全局解释器锁》第十五章中对 Python 内存管理方法的简要讨论。在本节中，我们将通过将其内存管理机制与 Java 和 C++的内存管理机制进行比较，并讨论它与 Python 并发编程实践的关系，更深入地了解 Python 内存模型。

# Python 内存管理器的组件

Python 中的数据以特定方式存储在内存中。为了深入了解并发程序中数据的处理方式，我们首先需要深入了解 Python 内存分配的理论结构。在本节中，我们将讨论数据如何在私有堆中分配，以及通过**Python 内存管理器**处理这些数据——这是一个确保数据完整性的总体实体。

Python 内存管理器由许多组件组成，这些组件与不同的实体进行交互并支持不同的功能。例如，一个组件通过与 Python 运行的操作系统的内存管理器进行交互，处理低级内存的分配；它被称为**原始内存分配器**。

在更高的层次上，还有许多其他内存分配器与前述的对象和值的私有堆进行交互。Python 内存管理器的这些组件处理特定于对象的分配，执行特定于给定数据和对象类型的内存操作：整数必须由不同的分配器处理和管理，以便处理字符串的分配器或处理字典或元组的分配器。由于这些数据类型之间的存储和读取指令不同，因此实现了这些不同的特定于对象的内存分配器，以获得额外的速度，同时牺牲一些处理空间。

在前述原始内存分配器的下一步是来自标准 C 库的系统分配器（假设考虑的 Python 解释器是 CPython）。有时被称为通用分配器，这些用 C 语言编写的实体负责帮助原始内存分配器与操作系统的内存管理器进行交互。

前面描述的 Python 内存管理器的整个模型可以用以下图示表示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/24811f24-5c55-448f-bea1-fecc4ca01cc0.png)

Python 内存管理器组件

# 内存模型作为一个带标签的有向图

我们已经了解了 Python 中的内存分配的一般过程，因此在本节中，让我们思考 Python 中数据是如何存储和引用的。许多程序员经常将 Python 中的内存模型想象为一个带有每个节点标签的对象图，边是有向的——简而言之，它是一个带标签的有向对象图。这种内存模型最初是在第二古老的计算机编程语言**Lisp**（以前称为 LISP）中使用的。

它通常被认为是一个有向图，因为它的内存模型通过指针来跟踪其数据和变量：每个变量的值都是一个指针，这个指针可以指向一个符号、一个数字或一个子程序。因此，这些指针是对象图中的有向边，而实际值（符号、数字、子程序）是图中的节点。以下图表是 Lisp 内存模型早期阶段的简化：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/09d714f4-5438-4c69-9731-f4a2c5b29b54.png)

Lisp 内存模型作为对象图

这种对象图内存模型带来了许多有利的内存管理特性。首先，该模型在可重用性方面提供了相当大的灵活性；可以编写一个数据结构或一组指令，用于一种数据类型或对象，然后在其他类型上重用它是可能的，而且实际上相当容易。相比之下，C 是一种利用不同内存模型的编程语言，不提供这种灵活性，其程序员通常需要花费大量时间为不同类型的数据结构和算法重写相同的代码。

这种内存模型提供的另一种灵活性是，每个对象可以被任意数量的指针（或最终变量）引用，因此可以被任何一个变量改变。我们已经在第十五章中的一个 Python 程序示例中看到了这种特性的影响，《全局解释器锁》，如果两个变量引用相同的（可变）对象（通过将一个变量赋值给另一个变量实现），并且一个成功通过其引用改变了对象，那么这种改变也将通过第二个变量的引用反映出来。

正如在第十五章中讨论的那样，《全局解释器锁》，这与 C++中的内存管理不同。例如，当一个变量（不是指针或引用）被赋予特定值时，编程语言将该特定值复制到包含原始变量的内存位置。此外，当一个变量被赋予另一个变量时，后者的内存位置将被复制到前者的内存位置；在赋值后，这两个变量之间不再保持任何连接。

然而，有人认为这实际上可能是编程中的一个缺点，特别是在并发编程中，因为未经协调的尝试去改变共享对象可能导致不良结果。作为经验丰富的 Python 程序员，你可能也注意到在 Python 编程中类型错误（当一个变量期望是一个特定类型，但引用了一个不同的、不兼容类型的对象）是相当常见的。这也是这种内存模型的直接结果，因为引用指针可以指向任何东西。

# 在并发的背景下

在考虑 Python 内存模型的理论基础时，我们可以期待它如何影响 Python 并发编程的生态系统？幸运的是，Python 内存模型在某种程度上有利于并发编程，因为它允许更容易和更直观地思考和推理并发。具体来说，Python 实现了其内存模型，并以我们通常期望的方式执行其程序指令。

为了理解 Python 具有的这一优势，让我们首先考虑 Java 编程语言中的并发。为了在并发程序（特别是多线程程序）中获得更好的性能，Java 允许 CPU 重新排列 Java 代码中包含的给定操作的执行顺序。然而，重新排列是以任意的方式进行的，因此我们不能仅通过代码的顺序来推断多个线程执行时的执行顺序。这导致了如果 Java 中的并发程序以意外的方式执行，开发人员需要花费大量时间确定程序的执行顺序，以找出程序中的错误。

与 Java 不同，Python 的内存模型结构化，保持了其指令的顺序一致性。这意味着 Python 代码中指令的排列顺序指定了它们的执行顺序——没有代码的任意重新排列，因此并发程序不会出现意外行为。然而，由于 Java 并发中的重新排列是为了提高程序的速度，这意味着 Python 为了保持其执行更简单和更直观而牺牲了性能。

# Python 中的原子操作

关于内存管理的另一个重要主题是原子操作。在本小节中，我们将探讨编程中原子性的定义，原子操作在并发编程上下文中的作用，以及如何在 Python 程序中使用原子操作。

# 什么是原子性？

首先让我们来检查原子性的实际特征。如果在并发程序中，一个操作是原子的，那么在其执行过程中不能被程序中的其他实体中断；原子操作也可以被称为可线性化、不可分割或不可中断的。鉴于竞争条件的性质以及它们在并发程序中的普遍存在，很容易得出原子性是程序的一个理想特征，因为它保证了共享数据的完整性，并保护它免受不协调的变化。

"原子"一词指的是原子操作对于其所在的程序来说是瞬时的。这意味着操作必须以连续、不间断的方式执行。实现原子性的最常见方法，你可能已经猜到了，是通过互斥或锁。正如我们所见，锁需要一个线程或进程一次与共享资源进行交互，从而保护这些线程/进程的交互不会被其他竞争的线程或进程中断和潜在地破坏。

如果程序员允许其并发程序中的一些操作是非原子的，他们还需要允许这些操作足够小心和灵活（在与数据交互和变异的意义上），以便它们不会因为被其他操作中断而产生错误。然而，如果这些操作在执行过程中出现不规则和错误的行为，程序员将很难重现和调试这些行为。

# GIL 重新考虑

在 Python 原子操作的上下文中，一个主要元素当然是 GIL；此外还存在一些关于 GIL 在原子操作中扮演的角色的常见误解和复杂性。

例如，关于原子操作的定义，有些人倾向于认为 Python 中的所有操作实际上都是原子的，因为 GIL 实际上要求线程以协调的方式执行，每次只能有一个线程能够运行。事实上，这是一个错误的说法。GIL 要求只有一个线程可以在任何给定时间执行 Python 代码，并不意味着所有 Python 操作都是原子的；一个操作仍然可以被另一个操作中断，并且错误仍然可能由于对共享数据的错误处理和破坏而导致。

在更低的层面上，Python 解释器处理 Python 并发程序中的线程切换。这个过程是根据字节码指令进行的，这些字节码指令是可解释和可执行的 Python 代码。具体来说，Python 维护一个固定的频率，指定解释器应该多久切换一次活动线程到另一个线程，这个频率可以使用内置的`sys.setswitchinterval()`方法进行设置。任何非原子操作都可以在执行过程中被线程切换事件中断。

在 Python 2 中，这个频率的默认值是 1,000 个字节码指令，这意味着在一个线程成功执行了 1,000 个字节码指令后，Python 解释器将寻找其他等待执行的活动线程。如果至少有一个其他等待的线程，解释器将要求当前运行的线程释放 GIL，并让等待的线程获取它，从而开始执行后者的线程。

在 Python 3 中，频率基本上是不同的。现在，频率的单位是基于时间的，具体来说是以秒为单位。默认值为 15 毫秒，这个频率指定如果一个线程至少执行了等于阈值的时间量，那么线程切换事件（以及 GIL 的释放和获取）将在线程完成当前字节码指令的执行后立即发生。

# Python 中的固有原子性

如前所述，如果执行操作的线程已经超过了执行限制（例如，在 Python 3 中默认为 15 毫秒），则操作在执行过程中可以被中断，此时操作必须完成当前的字节码指令，并将 GIL 交还给另一个等待的线程。这意味着线程切换事件只会发生在字节码指令之间。

Python 中有一些操作可以在一个单一的字节码指令中执行，因此在没有外部机制的帮助下是原子性的，比如互斥。具体来说，如果线程中的操作在一个单一的字节码中完成执行，它就不能被线程切换事件中断，因为事件只会在当前字节码指令完成后才会发生。这种固有原子性的特征非常有用，因为它允许具有这种特性的操作自由地执行其指令，即使没有使用同步方法，同时仍然保证它们不会被中断并且数据不会被破坏。

# 原子与非原子

重要的是要注意，对程序员来说，了解 Python 中哪些操作是原子的，哪些不是，可能会令人惊讶。有些人可能会认为，由于简单操作所需的字节码比复杂操作少，因此操作越简单，就越有可能是固有原子的。然而，事实并非如此，确定哪些操作在本质上是原子的唯一方法是进行进一步的分析。

根据 Python 3 的文档（可以通过此链接找到：[docs.python.org/3/faq/library.html#what-kinds-of-global-value-mutation-are-thread-safe](https://docs.python.org/3/faq/library.html#what-kinds-of-global-value-mutation-are-thread-safe)），一些天生的原子操作的例子包括以下内容：

+   将预定义对象附加到列表

+   用另一个列表扩展列表

+   从列表中获取元素

+   从列表中“弹出”

+   对列表进行排序

+   将变量分配给另一个变量

+   将变量分配给对象的属性

+   为字典创建一个新条目

+   用另一个字典更新字典

一些不是天生原子的操作包括以下内容：

+   递增整数，包括使用`+=`

+   通过引用列表中的另一个元素更新列表中的元素

+   通过引用字典中的另一个条目更新字典中的条目

# Python 中的模拟

让我们分析实际 Python 并发程序中原子操作和非原子操作之间的区别。如果您已经从 GitHub 页面下载了本书的代码，请转到`Chapter17`文件夹。对于本例，我们考虑`Chapter17/example1.py`文件：

```py
# Chapter17/example1.py

import sys; sys.setswitchinterval(.000001)
import threading

def foo():
    global n
    n += 1

n = 0

threads = []
for i in range(1000):
    thread = threading.Thread(target=foo)
    threads.append(thread)

for thread in threads:
    thread.start()

for thread in threads:
    thread.join()

print(f'Final value: {n}.')

print('Finished.')
```

首先，我们将 Python 解释器的线程切换频率重置为 0.000001 秒——这是为了使线程切换事件比平常更频繁，从而放大我们程序中可能存在的任何竞争条件。

程序的要点是使用 1,000 个单独的线程递增一个简单的全局计数器（`n`），每个线程通过`foo()`函数递增一次计数器。由于计数器最初被初始化为`0`，如果程序正确执行，我们将在程序结束时得到计数器的值为 1,000。然而，我们知道我们在`foo()`函数中使用的递增运算符（`+=`）不是原子操作，这意味着当应用于全局变量时，它可能会被线程切换事件中断。

在多次运行脚本后，我们可以观察到实际上存在我们代码中的竞争条件。这可以通过计数器的不正确值小于 1,000 来说明。例如，以下是我得到的一个输出：

```py
> python3 example1.py
Final value: 998.
Finished.
```

这与我们之前讨论的一致，即，由于`+=`运算符不是原子的，它需要其他同步机制来确保它与多个线程同时交互的数据的完整性。现在让我们用我们知道是原子的操作来模拟相同的实验，具体来说是**将预定义对象附加到列表**。

在`Chapter17/example2.py`文件中，我们有以下代码：

```py
# Chapter17/example2.py

import sys; sys.setswitchinterval(.000001)
import threading

def foo():
    global my_list
    my_list.append(1)

my_list = []

threads = []
for i in range(1000):
    thread = threading.Thread(target=foo)
    threads.append(thread)

for thread in threads:
    thread.start()

for thread in threads:
    thread.join()

print(f'Final list length: {len(my_list)}.')

print('Finished.')
```

现在我们不再有一个全局计数器，而是一个最初为空的全局列表。新的`foo()`函数现在获取这个全局列表并将整数`1`附加到它上。在程序的其余部分，我们仍然创建和运行 1,000 个单独的线程，每个线程调用`foo()`函数一次。在程序结束时，我们将打印出全局列表的长度，以查看列表是否成功地变异了 1,000 次。具体来说，如果列表的长度小于 1,000，我们将知道我们的代码中存在竞争条件，类似于我们在上一个例子中看到的情况。

由于`list.append()`方法是一个原子操作，因此，当线程调用`foo()`函数并与全局列表交互时，可以保证没有竞争条件。这可以通过程序结束时列表的长度来说明。无论我们运行程序多少次，列表的长度始终为 1,000：

```py
> python3 example2.py
Final list length: 1000.
Finished.
```

尽管 Python 中有一些本质上是原子的操作，但很难判断一个给定的操作是否本身是原子的。由于在共享数据上应用非原子操作可能导致竞争条件和错误的结果，因此建议程序员始终利用同步机制来确保并发程序中共享数据的完整性。

# 总结

在这一章中，我们已经研究了 Python 内存模型的基本结构，以及语言在并发编程环境中如何管理其值和变量。鉴于 Python 中内存管理的结构和实现方式，与其他编程语言相比，理解并发程序的行为可能会更容易得多。然而，在 Python 中理解和调试并发程序的便利性也伴随着性能的降低。

原子操作是在执行过程中不能被中断的指令。原子性是并发操作的一个理想特征，因为它保证了在不同线程之间共享的数据的安全性。虽然 Python 中有一些本质上是原子的操作，但始终建议使用锁定等同步机制来保证给定操作的原子性。

在下一章中，我们将学习如何从头开始构建一个并发服务器。通过这个过程，我们将更多地了解如何实现通信协议以及将并发应用到现有的 Python 应用程序中。

# 问题

+   Python 内存管理器的主要组成部分是什么？

+   Python 内存模型如何类似于带标签的有向图？

+   就 Python 内存模型在开发 Python 并发应用程序方面的优缺点是什么？

+   什么是原子操作，为什么在并发编程中是可取的？

+   给出 Python 中本质上是原子操作的三个例子。

# 进一步阅读

有关更多信息，您可以参考以下链接：

+   *支持编程语言的内存模型* ([`canonical.org/~kragen/memory-models/`](http://canonical.org/~kragen/memory-models/)), K. J. Sitaker

+   *理解 GIL：如何编写快速和线程安全的 Python* ([opensource.com/article/17/4/grok-gil](https://opensource.com/article/17/4/grok-gil)), A. Jesse Jiryu Davis

+   *Python 中的线程同步机制* ([`effbot.org/zone/thread-synchronization.htm#atomic-operations`](http://effbot.org/zone/thread-synchronization.htm#atomic-operations)), Fredrik Lundh

+   *内存* *管理* ([`docs.python.org/3/c-api/memory.html`](https://docs.python.org/3/c-api/memory.html)), Python 文档

+   *并发* ([jython.org/jythonbook/en/1.0/Concurrency](http://www.jython.org/jythonbook/en/1.0/Concurrency.html)), Jython 文档

+   *Python 内存管理* ([anubnair.wordpress.com/2014/09/30/memory-management-in-python/](https://anubnair.wordpress.com/2014/09/30/memory-management-in-python/)), Anu B Nair


# 第十八章：从头开始构建服务器

在本章中，我们将分析并发编程的更高级应用：从头开始构建一个工作的非阻塞服务器。我们将涵盖`socket`模块的复杂用法，例如将用户业务逻辑与回调隔离，并使用内联生成器编写回调逻辑，这两个实例都设计为并发运行。我们还将讨论使用`await`和`yield`关键字，使用一个示例。

本章将涵盖以下主题：

+   使用`socket`模块的全面 API 从头开始构建服务器

+   关于 Python 生成器和异步生成器的基本信息

+   如何使用`await`和`yield`关键字与内联生成器将阻塞服务器转换为非阻塞服务器

# 技术要求

以下是本章的先决条件列表：

+   确保您的计算机上安装了 Python 3

+   确保您的计算机上安装了`telnet`

+   在[`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python)下载 GitHub 存储库

+   在本章中，我们将使用名为`Chapter18`的子文件夹

+   查看以下视频以查看代码的实际操作：[`bit.ly/2KrgWwh`](http://bit.ly/2KrgWwh)

# 通过 socket 模块进行低级网络编程

在本章中，我们将使用 Python 中的内置库`socket`模块来构建我们的工作服务器。`socket`模块是最常用于实现低级通信协议的模块之一，同时提供直观的选项来控制这些协议。在本节中，我们将介绍实现服务器的底层架构的过程，以及模块中将在后面的示例中使用的关键方法和功能。

请注意，为了成功地跟随本章中的示例，您需要在系统上安装 telnet 程序。Telnet 是一个提供终端命令以促进双向交互式基于文本的通信协议的程序。我们在第十一章中介绍了 telnet 的安装，*使用 asyncio 构建通信通道*；如果您的系统上尚未安装 Telnet，请简单地转到（并按照）该章节中的说明。

请注意，macOS 系统有一个名为 Netcat 的预安装替代 Telnet 的程序。如果您不想在 macOS 计算机上安装 Telnet，请在以下示例中使用命令`nc`而不是`telnet`，您将获得相同的效果。

# 服务器端通信理论

在第十一章中，*使用 asyncio 构建通信通道*，您遇到了使用`aiohttp`模块在更高级别实现异步通信通道的简要示例。在本节中，我们将深入探讨服务器端通信通道的编程结构，以及它如何以高效的方式与其客户端进行交互。

在网络编程领域，**套接字**被定义为特定计算机网络节点内的理论端点。套接字负责从其所在的节点接收或发送数据。套接字仅对拥有它的节点可用的事实意味着同一计算机网络中的其他节点在理论上无法与套接字交互。换句话说，套接字仅对其对应的节点可用。

要从服务器端打开通信通道，网络程序员必须首先创建一个套接字并将其绑定到特定地址。该地址通常是一对值，包含有关主机和服务器端口的信息。然后，通过套接字，服务器开始监听网络中由其客户端创建的任何潜在通信请求。因此，客户端对服务器的任何连接请求都需要通过创建的套接字。

在收到潜在客户端的连接请求后，服务器可以决定是否接受该请求。然后两个系统之间将建立连接，这意味着它们可以开始通信并共享数据。当客户端通过通信通道向服务器发送消息时，服务器会处理消息，最终通过相同的通道向客户端发送响应；这个过程会持续，直到它们之间的连接结束，要么是其中一个退出连接通道，要么是通过一些外部因素。

上述是创建服务器并与潜在客户端建立连接的基本过程。在整个过程的每个阶段都实施了多种安全措施，尽管它们不是我们关心的内容，也不会在这里讨论。下面的图表也描述了刚刚描述的过程：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/ce7cc28e-53e8-4f2d-bf59-3d8220b2b9c0.png)

使用套接字进行网络编程

请注意，为了创建连接到服务器的请求，潜在客户端还必须初始化自己的通信通道套接字（如前面的图表所示）。再次强调，我们只关注这个过程的服务器端理论，因此在这里不讨论客户端方面的元素。

# 套接字模块的 API

在本节中，我们将探讨`socket`模块提供的关键 API，以实现先前描述过程中的相同功能。正如我们已经提到的，`socket`模块内置在任何 Python 3 发行版中，因此我们可以简单地将模块导入到我们的程序中，而无需运行安装命令。

要创建套接字，我们将使用`socket.socket()`方法，该方法返回一个套接字对象。这个对象是我们在实现各种通信协议的过程中将要使用的。此外，套接字方法还具有以下方法，帮助我们控制通信协议：

+   `socket.bind()`: 此方法将调用套接字绑定到传递给方法的地址。在我们的示例中，我们将传递一个包含主机地址和通信通道端口的元组。

+   `socket.listen()`: 此方法允许我们创建的服务器接受潜在客户端的连接。还可以传递另一个可选的正整数参数给方法，以指定服务器拒绝新连接之前允许的未接受连接的数量。在我们后面的示例中，我们将使用`5`作为此方法的任意数量。

+   `socket.accept()`: 此方法如其名称所示，接受调用套接字对象的特定连接。首先，调用对象必须绑定到地址并监听连接，才能调用此方法。换句话说，这个方法要在前两个方法之后调用。该方法还返回一对值`(conn, address)`，其中`conn`是已接受连接的新套接字对象，能够发送和接收数据，`address`是连接另一端的地址（客户端地址）。

+   `socket.makefile()`: 此方法返回与调用`socket`对象关联的`file`对象。我们将使用此方法创建一个包含来自服务器接受的客户端数据的文件。这个`file`对象也需要适当地关闭，使用`close()`方法。

+   `socket.sendall()`: 这个方法将传递给调用`socket`对象的数据发送出去。我们将使用这个方法将数据发送回连接到我们服务器的客户端。请注意，这个方法接收字节数据，所以在我们的示例中将向这个方法传递字节字符串。

+   `socket.close()`: 这个方法将调用`socket`对象标记为关闭。在此之后，对`socket`对象的所有操作都将失败。这在我们终止服务器时使用。

# 构建一个简单的回显服务器

真正理解先前描述的方法和函数的使用方式的最佳方法是在示例程序中看到它们的运行。在本节中，我们将构建一个回显服务器作为我们的起始示例。这个服务器，正如术语所示，会将从每个客户端接收到的内容发送回客户端。通过这个示例，您将学习如何设置一个功能齐全的服务器，以及如何处理来自客户端的连接和数据，并且我们将在后面的部分构建更复杂的服务器。

然而，在我们进入代码之前，让我们讨论一下将为该服务器实现通信逻辑的程序结构。首先，我们将有所谓的**反应器**，它设置服务器本身并在潜在客户端请求新连接时提供逻辑。具体来说，一旦服务器设置好，这个反应器将进入一个无限循环，并处理服务器接收到的所有连接请求。

如果您已经阅读了关于异步编程的前几章，也可以将这个反应器看作是一个事件循环。这个事件循环会处理所有要处理的事件（在这种情况下，它们是请求），并使用事件处理程序逐个处理它们。以下图表进一步说明了这个过程：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/0bee377e-3e65-4b5a-bc8e-acf4e81269b6.png)

网络编程中的事件循环

然后，我们程序的第二部分是事件循环类比中的事件处理程序，其中包含用户业务逻辑：如何处理从客户端接收的数据，以及向每个客户端发送什么。对于我们当前的示例，由于它是一个回显服务器，我们只会将每个客户端发送到服务器的任何内容发送回去（如果数据有效）。

有了这个结构，让我们继续实现这个服务器。从 GitHub 页面下载本章的代码，然后转到`Chapter18`文件夹。我们感兴趣的脚本在`Chapter18/example1.py`文件中，如下所示：

```py
# Chapter18/example1.py

import socket

# Main event loop
def reactor(host, port):
    sock = socket.socket()
    sock.bind((host, port))
    sock.listen(5)
    print(f'Server up, running, and waiting for call on {host} {port}')

    try:
        while True:
            conn, cli_address = sock.accept()
            process_request(conn, cli_address)

    finally:
        sock.close()

def process_request(conn, cli_address):
    file = conn.makefile()

    print(f'Received connection from {cli_address}')

    try:
        while True:
            line = file.readline()
            if line:
                line = line.rstrip()
                if line == 'quit':
                    conn.sendall(b'connection closed\r\n')
                    return

                print(f'{cli_address} --> {line}')
                conn.sendall(b'Echoed: %a\r\n' % line)
    finally:
        print(f'{cli_address} quit')
        file.close()
        conn.close()

if __name__ == '__main__':
    reactor('localhost', 8080)
```

程序的结构与我们之前讨论的方式相同：一个反应器和一个用户业务逻辑处理程序（`process_request()`函数）。首先，反应器设置服务器（通过创建套接字，将其绑定到参数主机和端口地址，并调用`listen()`方法）。然后进入一个无限循环，并促进与客户端的任何潜在连接，首先通过在`socket`对象上调用`accept()`方法接受连接，然后调用`process_request()`函数。如果在前面的过程中发生错误，反应器还负责关闭`socket`对象。

另一方面，`process_request()`函数将首先创建一个与传递给它的套接字相关联的`file`对象。同样，这个`file`对象被我们的服务器用来从通过该特定套接字连接的客户端读取数据。具体来说，在制作了`file`对象之后，该函数将进入另一个无限循环，不断从`file`对象中读取数据，使用`readline()`函数。如果从文件中读取的数据是有效的，我们将使用`sendall()`方法将相同的数据发送回去。

我们还打印出服务器从每个客户端接收到的内容作为服务器输出，包括`print(f'{cli_address} --> {line}')`这一行。另一个规定是，如果从文件中读取的数据等于字符串`quit`，那么我们将关闭与该特定客户端的连接。连接关闭后，我们需要仔细处理`socket`对象本身以及与其关联的`file`对象，使用`close()`方法关闭两者。

最后，在我们的程序末尾，我们只需调用`reactor()`函数并向其传递有关我们服务器的信息。在这种情况下，我们只是使用服务器的回环接口，端口为`8080`。现在，我们将执行脚本以初始化我们的本地服务器。您的输出应该类似于以下内容：

```py
> python3 example1.py
Server up, running, and waiting for call on localhost 8080
```

此时，我们的服务器已经启动并运行（如输出所示）。现在，我们想为这个服务器创建一些客户端。为此，打开另一个终端窗口，并使用 Telnet 程序连接到运行中的服务器，运行`telnet localhost 8080`。您的输出应该类似于以下内容：

```py
> telnet localhost 8080
Trying 127.0.0.1...
Connected to localhost.
```

这个输出意味着 Telnet 客户端已成功连接到我们创建的服务器。现在，我们可以测试服务器是否可以按照我们的意图处理其请求。具体来说，输入一些数据并按*return*或*Enter*发送到服务器，您将看到客户端将从服务器接收到一个回显消息，就像我们在前面的`process_request()`函数中实现的那样。同样，客户端可以通过向服务器发送字符串`quit`来停止与该服务器的连接。

在输入几个不同的短语时，以下代码显示了我的输出：

```py
> telnet localhost 8080
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
hello
Echoed: 'hello'
nice
Echoed: 'nice'
fdkgsnas
Echoed: 'fdkgsnas'
quit
connection closed
Connection closed by foreign host.
```

查看我们服务器的输出，您还可以看到在此连接期间发生了什么：

```py
> python3 example1.py
Server up, running, and waiting for call on localhost 8080
Received connection from ('127.0.0.1', 59778)
('127.0.0.1', 59778) --> hello
('127.0.0.1', 59778) --> nice
('127.0.0.1', 59778) --> fdkgsnas
('127.0.0.1', 59778) quit
```

如上所述，服务器被设计为在反应器中作为事件循环永远运行，可以通过`KeyboardInterrupt`异常停止。

我们已经成功实现了我们的第一个回显服务器，使用了`socket`模块提供的低级方法。在下一节中，我们将为我们的服务器实现更高级的功能，并分析将其转换为可以同时处理多个客户端的非阻塞服务器的过程。

# 使用 socket 模块构建一个计算器服务器

我们试图实现的功能是具有一个简单的请求处理程序，用于计算整数列表的和或乘积，并将其包含在从客户端发送的数据中。具体来说，如果客户端向我们的服务器发送字符串`1`，`2`，`4`，那么服务器应该返回`7`（如果要计算总和）或`8`（如果要计算乘积）。

每个服务器都实现了某种形式的数据处理，除了处理来自客户端的请求并将数据处理任务的结果发送给这些客户端。因此，这个原型将作为更复杂功能的更广泛服务器的第一个构建块。

# 底层计算逻辑

我们将使用 Python 字符串的`split()`方法来提取由字符串中的特定字符分隔的元素。因此，我们要求来自客户端的所有数据都以这种方式格式化（用逗号分隔的整数），如果客户端发送的内容不符合这种格式，我们将简单地发送回一个错误消息，并要求他们发送一个新的消息。

基本的计算逻辑包含在`Chapter18/example2.py`文件中，如下所示：

```py
# Chapter18/example2.py

from operator import mul
from functools import reduce

try:
    while True:
        line = input('Please enter a list of integer, separated by commas: ')
        try:
            nums = list(map(int, line.split(',')))
        except ValueError:
            print('ERROR. Enter only integers separated by commas')
            continue

        print('Sum of input integers', sum(nums))
        print('Product of input integers', reduce(mul, nums, 1))

except KeyboardInterrupt:
    print('\nFinished.')
```

同样，我们使用`split()`方法，带有`,`参数，来提取特定字符串中的各个数字。`sum()`函数用于计算参数列表中数字的和。要计算聚合乘积，我们需要从`operator`模块导入`mul()`方法（用于乘法），以及从`functools`模块导入`reduce()`方法，以在考虑的数字列表中的每个元素上应用乘法。

顺便说一句，传递给`reduce()`方法的第三个参数（数字`1`）是减少过程的起始值。如果您还没有这样做，可以阅读第七章，*进程中的减少运算符*，以了解更多关于减少操作的信息。

至于我们的实际服务器，我们还将跟踪**计算模式**。计算模式的默认值是执行求和，它决定服务器是否应对输入数字列表执行求和和乘法。该模式也是每个客户端连接的唯一模式，并且可以由该客户端切换。具体来说，如果特定客户端发送的数据是字符串`sum`，那么我们将切换计算模式为求和，对于字符串`product`也是一样。

# 实现计算器服务器

现在，让我们来看一下`Chapter18/example3.py`文件中这个服务器的完整实现：

```py
# Chapter18/example3.py

import socket
from operator import mul
from functools import reduce

# Main event loop
def reactor(host, port):
    sock = socket.socket()
    sock.bind((host, port))
    sock.listen(5)
    print(f'Server up, running, and waiting for call on {host} {port}')

    try:
        while True:
            conn, cli_address = sock.accept()
            process_request(conn, cli_address)

    finally:
        sock.close()

def process_request(conn, cli_address):
    file = conn.makefile()

    print(f'Received connection from {cli_address}')
    mode = 'sum'

    try:
        conn.sendall(b'<welcome: starting in sum mode>\n')
        while True:
            line = file.readline()
            if line:
                line = line.rstrip()
                if line == 'quit':
                    conn.sendall(b'connection closed\r\n')
                    return

                if line == 'sum':
                    conn.sendall(b'<switching to sum mode>\r\n')
                    mode = 'sum'
                    continue
                if line == 'product':
                    conn.sendall(b'<switching to product mode>\r\n')
                    mode = 'product'
                    continue

                print(f'{cli_address} --> {line}')
                try:
                    nums = list(map(int, line.split(',')))
                except ValueError:
                    conn.sendall(
                        b'ERROR. 
                        Enter only integers separated by commas\n')
                    continue

                if mode == 'sum':
                    conn.sendall(b'Sum of input numbers: %a\r\n'
                        % str(sum(nums)))
                else:
                    conn.sendall(b'Product of input numbers: %a\r\n'
                        % str(reduce(mul, nums, 1)))
    finally:
        print(f'{cli_address} quit')
        file.close()
        conn.close()

if __name__ == '__main__':
    reactor('localhost', 8080)
```

我们服务器的反应器组件与之前的示例相同，因为事件循环处理相同类型的逻辑。在我们的用户业务逻辑部分（`process_request()`函数）中，我们仍然使用从`makefile()`方法返回的`file`对象来获取服务器客户端发送的数据。如果客户端发送字符串`quit`，则该客户端与服务器之间的连接仍将被停止。

该程序中的第一个新事物是`process_request()`函数中的本地变量`mode`。该变量指定了我们之前讨论过的计算模式，并且默认值为字符串`sum`。正如你所看到的，在`process_request()`函数的`try`块的最后，该变量决定了要发送回当前客户端的数据类型：

```py
if mode == 'sum':
    conn.sendall(b'Sum of input numbers: %a\r\n'
        % str(sum(nums)))
else:
    conn.sendall(b'Product of input numbers: %a\r\n'
        % str(reduce(mul, nums, 1)))
```

此外，如果从客户端发送的数据等于字符串`sum`，那么`mode`变量将被设置为`sum`，对于字符串`product`也是一样。客户端还将收到一条消息，宣布计算模式已更改。这一逻辑包含在以下代码部分中：

```py
if line == 'sum':
    conn.sendall(b'<switching to sum mode>\r\n')
    mode = 'sum'
    continue
if line == 'product':
    conn.sendall(b'<switching to product mode>\r\n')
    mode = 'product'
    continue
```

现在，让我们看看这个服务器在实际实验中的表现。执行程序运行服务器，你会看到类似于之前示例的输出：

```py
> python3 example3.py
Server up, running, and waiting for call on localhost 8080
```

我们将再次使用 Telnet 来为该服务器创建客户端。当你通过 Telnet 客户端连接到服务器时，请尝试输入一些数据来测试我们实现的服务器逻辑。以下代码显示了我使用各种类型的输入所获得的结果：

```py
> telnet localhost 8080
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
<welcome: starting in sum mode>
1,2
Sum of input numbers: '3'
4,9
Sum of input numbers: '13'
product
<switching to product mode>
0,-3
Product of input numbers: '0'
5,-9,10
Product of input numbers: '-450'
hello
ERROR. Enter only integers separated by commas
a,1
ERROR. Enter only integers separated by commas
quit
connection closed
Connection closed by foreign host.
```

您可以看到我们的服务器可以按我们的意图处理请求。具体来说，它可以计算给定正确格式的输入字符串的和和乘积；它可以适当地切换计算模式；如果输入字符串格式不正确，它可以向客户端发送错误消息。同样，这个长时间运行的服务器可以通过`KeyboardInterrupt`异常停止。

# 构建非阻塞服务器

我们将发现的一件事是，我们当前的服务器是阻塞的。换句话说，它无法同时处理多个客户端。在本节中，您将学习如何在当前服务器的基础上构建非阻塞服务器，使用 Python 关键字来促进并发编程，以及`socket`模块的低级功能。

# 分析服务器的并发性

我们现在将说明我们目前的服务器无法同时处理多个客户端。首先，执行`Chapter18/example3.py`文件再次运行服务器，如下所示：

```py
> python3 example3.py
Server up, running, and waiting for call on localhost 8080
```

与之前的示例类似，现在让我们打开另一个终端并使用 Telnet 连接到正在运行的服务器：

```py
> telnet localhost 8080
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
<welcome: starting in sum mode>
```

要为此服务器创建第二个客户端，请打开另一个终端并输入相同的`telnet`命令，如下所示：

```py
> telnet localhost 8080
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
```

在这里，我们已经看到服务器没有正确处理这第二个客户端：它没有将欢迎消息(`<welcome: starting in sum mode>`)发送给这个客户端。如果我们查看服务器的输出，我们还可以看到它只注册了一个客户端，具体来说，是两个客户端中的第一个：

```py
> python3 example3.py
Server up, running, and waiting for call on localhost 8080
Received connection from ('127.0.0.1', 61099)
```

接下来，我们将尝试从每个客户端输入。我们会发现服务器只成功处理来自第一个客户端的请求。具体来说，以下是来自第一个客户端的输出，包括各种类型的输入：

```py
> telnet localhost 8080
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
<welcome: starting in sum mode>
hello
ERROR. Enter only integers separated by commas
1,5
Sum of input numbers: '6'
product
<switching to product mode>
6,7
Product of input numbers: '42'
```

现在，第一个客户端仍然与服务器保持连接，切换到第二个客户端的终端并尝试输入自己的输入。你会发现，与第一个客户端不同，这个客户端没有从服务器那里收到任何消息：

```py
> telnet localhost 8080
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
hello
1,5
product
6,7
```

如果我们查看服务器的输出，我们会发现服务器只处理来自第一个客户端的请求：

```py
> python3 example3.py
Server up, running, and waiting for call on localhost 8080
Received connection from ('127.0.0.1', 61099)
('127.0.0.1', 61099) --> hello
('127.0.0.1', 61099) --> 1,5
('127.0.0.1', 61099) --> 6,7
```

第二个客户端能够与服务器交互的唯一方法是第一个客户端断开与服务器的连接，换句话说，当我们停止第一个客户端与服务器之间的连接时：

```py
> telnet localhost 8080
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
<welcome: starting in sum mode>
hello
ERROR. Enter only integers separated by commas
1,5
Sum of input numbers: '6'
product
<switching to product mode>
6,7
Product of input numbers: '42'
quit
connection closed
Connection closed by foreign host.
```

现在，如果你切换到第二个客户端的终端，你会发现客户端将被服务器之前应该接收的消息刷屏：

```py
> telnet localhost 8080
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
hello
1,5
product
6,7
<welcome: starting in sum mode>
ERROR. Enter only integers separated by commas
Sum of input numbers: '6'
<switching to product mode>
Product of input numbers: '42'
```

服务器的所有适当回复现在都存在，但它们一次性发送，而不是在每个输入消息之后。相同的信息激增也在我们服务器终端的输出中得到了体现：

```py
> python3 example3.py
Server up, running, and waiting for call on localhost 8080
Received connection from ('127.0.0.1', 61099)
('127.0.0.1', 61099) --> hello
('127.0.0.1', 61099) --> 1,5
('127.0.0.1', 61099) --> 6,7
('127.0.0.1', 61099) quit
Received connection from ('127.0.0.1', 61100)
('127.0.0.1', 61100) --> hello
('127.0.0.1', 61100) --> 1,5
('127.0.0.1', 61100) --> 6,7
```

这个输出让人觉得服务器只在第一个客户端退出后才收到了来自第二个客户端的连接，但实际上，我们创建了两个客户端，并让它们同时与服务器通信。这是因为我们目前的服务器只能一次处理一个客户端，只有在当前客户端退出后，它才能继续处理请求通信通道的下一个客户端。我们称之为阻塞服务器。

# Python 中的生成器

在下一节中，我们将讨论如何将我们目前拥有的阻塞服务器转换为非阻塞服务器，同时保留计算功能。为了做到这一点，我们首先需要了解 Python 编程中的另一个概念，称为**生成器**。你可能已经使用过 Python 生成器，但为了复习，我们将在本节中介绍生成器的关键特性。

生成器是返回迭代器并可以动态暂停和恢复的函数。生成器的返回值通常与列表对象进行比较，因为生成器迭代器是**惰性**的，只有在明确要求时才会产生结果。因此，当涉及大量数据时，生成器迭代器在内存管理方面更有效，因此通常比列表更受青睐。

每个生成器都被定义为一个函数，但是在函数块内部不使用关键字`return`，而是使用`yield`，这是为了表示返回值只是临时的，整个生成器本身在获得返回值后仍然可以恢复。让我们看看 Python 生成器在`Chapter18/example4.py`文件中的示例：

```py
# Chapter18/example4.py

def read_data():
    for i in range(5):
        print('Inside the inner for loop...')
        yield i * 2

result = read_data()
for i in range(6):
    print('Inside the outer for loop...')
    print(next(result))

print('Finished.')
```

在这里，我们有一个名为`read_data()`的生成器，它以懒惰的方式返回从 0 到 8 的 2 的倍数。这是通过关键字`yield`来实现的，该关键字放在否则正常函数中的返回值`i * 2`的前面。请注意，`yield`关键字放在迭代器中应该发送回的**单个**元素的前面，这有助于懒惰生成。

现在，在我们的主程序中，我们正在获取整个迭代器并将其存储在变量`result`中。然后，我们使用`next()`函数循环遍历该迭代器六次（显然，返回传入的迭代器中的下一个元素）。执行代码后，您的输出应该类似于以下内容：

```py
> python3 example4.py
Inside the outer for loop...
Inside the inner for loop...
0
Inside the outer for loop...
Inside the inner for loop...
2
Inside the outer for loop...
Inside the inner for loop...
4
Inside the outer for loop...
Inside the inner for loop...
6
Inside the outer for loop...
Inside the inner for loop...
8
Inside the outer for loop...
Traceback (most recent call last):
 File "example4.py", line 11, in <module>
 print(next(result))
StopIteration
```

您可以看到，即使在我们循环遍历迭代器之前，迭代器是从`read_data()`生成器中生成并返回的，但是生成器内部的实际指令只有在我们尝试从迭代器中获取更多项目时才会执行。

这可以通过输出中的打印语句交替放置来说明（来自外部`for`循环和内部`for`循环的一个打印语句交替出现）：执行流程首先进入外部`for`循环，尝试访问迭代器中的下一个项目，进入生成器，然后进入自己的`for`循环。一旦执行流程到达`yield`关键字，它就会回到主程序。这个过程会一直持续，直到其中一个`for`循环终止；在我们的例子中，生成器中的`for`循环首先停止，因此在最后遇到了`StopIteration`错误。

迭代器的生成懒惰性来自于生成器在到达`yield`关键字时停止执行，并且只在外部指令要求时（在这种情况下是通过`next()`函数）才继续执行。再次强调，这种形式的数据生成在内存管理方面比简单生成可能需要迭代的所有内容（如列表）要高效得多。

# 异步生成器和发送方法

生成器与我们构建异步服务器的目的有何关联？我们当前的服务器无法处理多个客户端的原因是，我们在用户业务逻辑部分使用的`readline()`函数是一个阻塞函数，只要当前的`file`对象仍然打开，就会阻止执行流程转向其他潜在的客户端。这就是为什么当当前客户端与服务器断开连接时，下一个客户端立即收到我们之前看到的大量信息的原因。

如果我们能够将这个函数重写为一个异步函数，允许执行流程在所有连接到服务器的不同客户端之间切换，那么该服务器将变成非阻塞的。我们将使用异步生成器来同时从潜在的多个客户端并发生成数据，以供我们的服务器使用。

为了看到我们将用于服务器的异步生成器的基本结构，让我们首先考虑`Chapter18/example5.py`文件，如下所示：

```py
# Chapter18/example5.py

import types

@types.coroutine
def read_data():
    def inner(n):
        try:
            print(f'Printing from read_data(): {n}')
            callback = gen.send(n * 2)
        except StopIteration:
            pass

    data = yield inner
    return data

async def process():
    try:
        while True:
            data = await read_data()
            print(f'Printing from process(): {data}')
    finally:
        print('Processing done.')

gen = process()
callback = gen.send(None)

def main():
    for i in range(5):
        print(f'Printing from main(): {i}')
        callback(i)

if __name__ == '__main__':
    main()
```

我们仍在考虑打印出 0 到 8 之间的 2 的倍数的任务。在这个例子中，`process()`函数是我们的异步生成器。您可以看到，实际上在生成器内部没有`yield`关键字；这是因为我们使用了`await`关键字。这个异步生成器负责打印出由另一个生成器`read_data()`计算的 2 的倍数。

`@types.coroutine`装饰器用于将生成器`read_data()`转换为一个返回基于生成器的协程的协程函数，这个协程函数仍然可以像常规生成器一样使用，但也可以被等待。这个基于生成器的协程是将我们的阻塞服务器转换为非阻塞服务器的关键。协程使用`send()`方法进行计算，这是一种向生成器提供输入的方法（在这种情况下，我们向`process()`生成器提供 2 的倍数）。

这个协程返回一个回调函数，稍后可以被我们的主程序调用。这就是为什么在主程序中循环`range(5)`之前，我们需要跟踪`process()`生成器本身（存储在变量`gen`中）和返回的回调（存储在变量`callback`中）。具体来说，回调是`gen.send(None)`的返回值，用于启动`process()`生成器的执行。最后，我们简单地循环遍历上述的`range`对象，并使用适当的输入调用`callback`对象。

关于使用异步生成器的理论已经有很多讨论。现在，让我们看看它的实际应用。执行程序，你应该会得到以下输出：

```py
> python3 example5.py
Printing from main(): 0
Printing from read_data(): 0
Printing from process(): 0
Printing from main(): 1
Printing from read_data(): 1
Printing from process(): 2
Printing from main(): 2
Printing from read_data(): 2
Printing from process(): 4
Printing from main(): 3
Printing from read_data(): 3
Printing from process(): 6
Printing from main(): 4
Printing from read_data(): 4
Printing from process(): 8
Processing done.
```

在输出中（具体来说，是打印语句），我们仍然可以观察到任务切换事件，这对于之前章节中讨论的异步编程和产生输出的生成器来说是至关重要的。基本上，我们实现了与之前示例相同的目标（打印 2 的倍数），但在这里，我们使用了异步生成器（使用`async`和`await`关键字）来促进任务切换事件，并且我们还能够通过使用回调向生成器传递特定参数。这些技术的结合形成了将应用于我们当前阻塞服务器的基本结构。

# 使服务器非阻塞

最后，我们将再次考虑实现非阻塞服务器的问题。在这里，我们将之前讨论过的异步生成器应用于服务器的客户端接收数据的异步读取和处理。服务器的实际代码包含在`Chapter18/example6.py`文件中；我们将逐步介绍其中的各个部分，因为这是一个相对较长的程序。让我们先关注一下这个程序中将会有的全局变量：

```py
# Chapter18/example6.py

from collections import namedtuple

###########################################################################
# Reactor

Session = namedtuple('Session', ['address', 'file'])

sessions = {}         # { csocket : Session(address, file)}
callback = {}         # { csocket : callback(client, line) }
generators = {}       # { csocket : inline callback generator }
```

为了成功地为多个客户端同时提供服务，我们将允许服务器同时拥有多个会话（每个客户端一个），因此，我们需要跟踪多个字典，每个字典将保存关于当前会话的特定信息。

具体来说，`sessions`字典将客户端套接字连接映射到一个`Session`对象，这是一个 Python 的`namedtuple`对象，其中包含客户端的地址和与该客户端连接关联的`file`对象。`callback`字典将客户端套接字连接映射到一个回调函数，这个回调函数是我们稍后将实现的异步生成器的返回值；每个这样的回调函数都以其对应的客户端套接字连接和从该客户端读取的数据作为参数。最后，`generators`字典将客户端套接字连接映射到其对应的异步生成器。

现在，让我们来看一下`reactor`函数：

```py
# Chapter18/example6.py

import socket, select

# Main event loop
def reactor(host, port):
    sock = socket.socket()
    sock.bind((host, port))
    sock.listen(5)
    sock.setblocking(0) # Make asynchronous

    sessions[sock] = None
    print(f'Server up, running, and waiting for call on {host} {port}')

    try:
        while True:
            # Serve existing clients only if they already have data ready
            ready_to_read, _, _ = select.select(sessions, [], [], 0.1)
            for conn in ready_to_read:
                if conn is sock:
                    conn, cli_address = sock.accept()
                    connect(conn, cli_address)
                    continue

                line = sessions[conn].file.readline()
                if line:
                    callbackconn)
                else:
                    disconnect(conn)
    finally:
        sock.close()
```

除了我们之前阻塞服务器中已经有的内容，我们还添加了一些指令：我们使用`socket`模块中的`setblocking()`方法来潜在地使我们的服务器异步或非阻塞；因为我们正在启动一个服务器，我们还将特定的套接字注册到`sessions`字典中，暂时使用`None`值。

在我们的无限`while`循环（事件循环）中是我们试图实现的新的非阻塞特性的一部分。首先，我们使用`select`模块的`select()`方法来单独选择`sessions`字典中准备好被读取的套接字（换句话说，具有可用数据的套接字）。由于该方法的第一个参数是要读取的数据，第二个是要写入的数据，第三个是异常数据，我们只在第一个参数中传入`sessions`字典。第四个参数指定了方法的超时时间（以秒为单位）；如果未指定，该方法将无限期地阻塞，直到`sessions`中至少有一项可用，这对于我们的非阻塞服务器来说是不合适的。

接下来，对于每个准备被读取的客户端套接字连接，如果连接对应于我们原始的服务器套接字，我们将接受该连接并调用`connect()`函数（我们将很快看到）。在这个`for`循环中，我们还将处理回调方法。具体来说，我们将访问当前套接字连接的会话的`file`属性（回想一下，每个会话都有一个`address`属性和一个`file`属性），并将使用`readline()`方法从中读取数据。现在，如果我们读到的是有效数据，那么我们将把它（连同当前客户端连接）传递给相应的回调；否则，我们将结束连接。

请注意，尽管我们的服务器通过将套接字设置为非阻塞而变成了异步的，但前面的`readline()`方法仍然是一个阻塞函数。`readline()`函数在输入数据中遇到回车符（ASCII 中的`'\r'`字符）时返回。这意味着，如果客户端发送的数据不包含回车符，那么`readline()`函数将无法返回。然而，由于服务器仍然是非阻塞的，将会引发错误异常，以便其他客户端不会被阻塞。

现在，让我们来看看我们的新辅助函数：

```py
# Chapter18/example6.py

def connect(conn, cli_address):
    sessions[conn] = Session(cli_address, conn.makefile())

    gen = process_request(conn)
    generators[conn] = gen
    callback[conn] = gen.send(None) # Start the generator

def disconnect(conn):
    gen = generators.pop(conn)
    gen.close()
    sessions[conn].file.close()
    conn.close()

    del sessions[conn]
    del callback[conn]
```

`connect()`函数在客户端连接有准备好被读取的数据时将被调用，它将在与客户端的有效连接开始时启动指令。首先，它初始化与该特定客户端连接相关联的`namedtuple`对象（我们仍然在这里使用`makefile()`方法来创建`file`对象）。函数的其余部分是我们之前讨论过的异步生成器的用法模式：我们将客户端连接传递给现在是异步生成器的`process_request()`，将其注册到`generators`字典中；让它调用`send(None)`来启动生成器；并将返回值存储到`callback`字典中，以便稍后调用（具体来说，在我们刚刚看到的反应器中的事件循环的最后部分）。

另一方面，`disconnect()`函数在与客户端的连接停止时提供各种清理指令。它从`generators`字典中移除与客户端连接相关联的生成器，并关闭`sessions`字典中存储的`file`对象以及客户端连接本身。最后，它从剩余的字典中删除与客户端连接对应的键。

让我们把注意力转向现在是异步生成器的新`process_request()`函数：

```py
# Chapter18/example6.py

from operator import mul
from functools import reduce

###########################################################################
# User's Business Logic

async def process_request(conn):
    print(f'Received connection from {sessions[conn].address}')
    mode = 'sum'

    try:
        conn.sendall(b'<welcome: starting in sum mode>\n')
        while True:
            line = await readline(conn)
            if line == 'quit':
                conn.sendall(b'connection closed\r\n')
                return
            if line == 'sum':
                conn.sendall(b'<switching to sum mode>\r\n')
                mode = 'sum'
                continue
            if line == 'product':
                conn.sendall(b'<switching to product mode>\r\n')
                mode = 'product'
                continue

            print(f'{sessions[conn].address} --> {line}')
            try:
                nums = list(map(int, line.split(',')))
            except ValueError:
                conn.sendall(
                    b'ERROR. Enter only integers separated by commas\n')
                continue

            if mode == 'sum':
                conn.sendall(b'Sum of input integers: %a\r\n'
                    % str(sum(nums)))
            else:
                conn.sendall(b'Product of input integers: %a\r\n'
                    % str(reduce(mul, nums, 1)))
    finally:
        print(f'{sessions[conn].address} quit')
```

处理客户端数据并执行计算的逻辑保持不变，这个新函数的唯一区别是`async`关键字（放在`def`关键字前面）和与新的`readline()`函数一起使用的`await`关键字。这些区别本质上将我们的`process_request()`函数转换为一个非阻塞函数，条件是新的`readline()`函数也是非阻塞的。

```py
# Chapter18/example6.py

import types

@types.coroutine
def readline(conn):
    def inner(conn, line):
        gen = generators[conn]
        try:
            callback[conn] = gen.send(line) # Continue the generator
        except StopIteration:
            disconnect(conn)

    line = yield inner
    return line
```

类似于我们在前面的例子中看到的，我们从 Python 中导入`types`模块，并使用`@types.coroutine`装饰器将`readline()`函数变成基于生成器的协程，这是非阻塞的。每次调用回调函数（接受客户端连接和一行数据）时，执行流程将进入这个协程内部的`inner()`函数并执行指令。

具体来说，它将数据行发送到生成器，生成器将使`process_request()`中的指令异步处理并将返回值存储到适当的回调中，除非已经到达生成器的末尾，在这种情况下将调用`disconnect()`函数。

我们的最后一个任务是测试这个服务器是否真的能够同时处理多个客户端。为此，首先执行以下脚本：

```py
> python3 example6.py
Server up, running, and waiting for call on localhost 8080
```

类似于您之前看到的，打开两个额外的终端并使用 Telnet 连接到正在运行的服务器：

```py
> telnet localhost 8080
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
<welcome: starting in sum mode>
```

正如您所看到的，两个客户端都被正确处理：两者都能够连接，并且都收到了欢迎消息。这也可以通过服务器输出来说明，如下所示：

```py
> python3 example6.py
Server up, running, and waiting for call on localhost 8080
Received connection from ('127.0.0.1', 63855)
Received connection from ('127.0.0.1', 63856)
```

进一步的测试可能涉及同时向服务器发送消息，它仍然可以处理。服务器还可以跟踪独立于各个客户端的独特计算模式（换句话说，假设每个客户端都有一个单独的计算模式）。我们已经成功地从头开始构建了一个非阻塞的并发服务器。

# 总结

往往，低级网络编程涉及套接字的操作和处理（在特定计算机网络的节点内定义为理论端点，负责从它们所在的节点接收或发送数据）。服务器端通信的架构包括多个涉及套接字处理的步骤，如绑定、监听、接受、读取和写入。`socket`模块提供了一个直观的 API，便于进行这些步骤。

要使用`socket`模块创建非阻塞服务器，需要实现异步生成器，以便执行流程在任务和数据之间切换。这个过程还涉及使用回调，可以在以后执行流程运行。这两个元素允许服务器同时读取和处理来自多个客户端的数据，使服务器成为非阻塞。

我们将在下一章中结束我们的书，介绍设计和实现并发程序的实用技术。具体来说，我们将讨论如何系统地和有效地测试、调试和安排并发应用程序。

# 问题

+   什么是套接字？它与网络编程有什么关系？

+   当潜在客户端请求连接时，服务器端通信的程序是什么？

+   `socket`模块提供了哪些方法来便于服务器端的低级网络编程？

+   什么是生成器？它们相对于 Python 列表的优势是什么？

+   什么是异步生成器？它们如何应用于构建非阻塞服务器？

# 进一步阅读

要获取更多信息，您可以参考以下链接：

+   *并发演讲*，PyBay 2017，Raymond Hettinger ([`pybay.com/site_media/slides/raymond2017-keynote/async_examples.html`](https://pybay.com/site_media/slides/raymond2017-keynote/async_examples.html)) [](https://pybay.com/site_media/slides/raymond2017-keynote/async_examples.html)

+   *一个简单的 Python Web 服务器*，Stephen C. Phillips ([blog.scphillips.com/posts/2012/12/a-simple-python-webserver/](http://blog.scphillips.com/posts/2012/12/a-simple-python-webserver/))

+   *如何在 Python 中使用 TCP 套接字*，Alexander Stepanov ([steelkiwi.com/blog/working-tcp-sockets/](https://steelkiwi.com/blog/working-tcp-sockets/))

+   Python 中的套接字编程，Nathan Jennings（realpython.com/python-sockets/#multi-connection-client-and-server）

+   Python 生成器简介（realpython.com/introduction-to-python-generators/）


# 第十九章：测试、调试和并发应用程序的调度

在本章中，我们将讨论在更高层次上使用并发 Python 程序的过程。首先，您将学习如何安排 Python 程序在以后同时运行，无论是一次还是定期。我们将分析 APScheduler，这是一个允许我们在跨平台基础上做到这一点的 Python 库。此外，我们将讨论测试和调试，这是编程中必不可少但经常被忽视的组成部分。鉴于并发编程的复杂性，测试和调试甚至比传统应用程序更加困难。本章将涵盖一些有效测试和调试并发程序的策略。

本章将涵盖以下主题：

+   APScheduler 库及其在并发调度 Python 应用程序中的使用

+   Python 程序的不同测试技术

+   Python 编程中的调试实践，以及并发特定的调试技术

# 技术要求

本章的先决条件如下：

+   确保您的计算机上安装了 Python 3

+   确保您的 Python 发行版中安装了`apscheduler`和`concurrencytest`库

+   在[`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python)下载 GitHub 存储库

+   在本章中，我们将使用名为`Chapter19`的子文件夹进行工作

+   查看以下视频以查看代码的实际操作：[`bit.ly/2OZdOZc`](http://bit.ly/2OZdOZc)

# 使用 APScheduler 进行调度

**APScheduler**（**Advanced Python Scheduler**的缩写）是一个外部 Python 库，支持安排 Python 代码以便稍后执行，无论是一次还是定期。该库为我们提供了高级选项，以动态地向作业列表中添加/删除作业，以便安排和执行，以及决定如何将这些作业分配给不同的线程和进程。

有些人可能会认为 Celery（[`www.celeryproject.org/`](http://www.celeryproject.org/)）是 Python 的首选调度工具。然而，虽然 Celery 是一个具有基本调度功能的分布式任务队列，但 APScheduler 恰恰相反：它是一个具有基本任务排队选项和高级调度功能的调度程序。此外，两种工具的用户都报告说 APScheduler 更容易设置和实现。

# 安装 APScheduler

与大多数常见的 Python 外部库一样，可以通过包管理器`pip`来安装 APScheduler，只需在终端中运行以下命令：

```py
pip install apscheduler
```

如果`pip`命令不起作用，另一种安装此库的方法是从 PyPI 手动下载源代码，网址为[pypi.org/project/APScheduler/](https://pypi.org/project/APScheduler/)。然后可以通过运行以下命令来提取和安装下载的文件：

```py
python setup.py install
```

与往常一样，要测试您的 APScheduler 发行版是否已正确安装，请打开 Python 解释器并尝试导入库，如下所示：

```py
>>> import apscheduler
```

如果没有返回错误，这意味着库已经完全安装并准备好使用。

# 不是调度服务

由于术语“调度程序”可能会对特定开发人员群体产生误导，让我们澄清 APScheduler 提供的功能，以及它不提供的功能。首先，该库可以用作跨平台调度程序，也可以是特定于应用程序的，而不是更常见的特定于平台的调度程序，比如 cron 守护程序（用于 Linux 系统）或 Windows 任务调度程序。

值得注意的是，APScheduler 本身并不是一个具有预构建 GUI 或命令行界面的调度服务。它仍然是一个必须在现有应用程序中导入和利用的 Python 库（这就是为什么它是特定于应用程序的）。然而，正如您将在后面了解到的，APScheduler 具有许多功能，可以利用来构建实际的调度服务。

例如，现在对于 Web 应用程序来说，调度作业（特别是后台作业）的能力是至关重要的，因为它们可以包括不同但重要的功能，如发送电子邮件或备份和同步数据。在这种情况下，APScheduler 可以说是调度云应用程序任务的最常见工具，这些任务涉及 Python 指令，如 Heroku 和 PythonAnywhere。

# APScheduler 功能

让我们探索 APScheduler 库提供的一些最常见功能。在执行方面，它提供了三种不同的调度机制，这样我们就可以选择最适合自己应用程序的机制（有时也称为事件触发器）：

+   **Cron 风格调度**：此机制允许作业具有预定的开始和结束时间

+   **基于间隔的执行**：此机制以均匀的间隔运行作业（例如，每两分钟、每天），并可选择开始和结束时间

+   **延迟执行**：此机制允许应用程序在执行作业列表中的项目之前等待特定的时间段

此外，APScheduler 允许我们将要在各种后端系统中执行的作业存储在常规内存、MongoDB、Redis、RethinkDB、SPLAlchemy 或 ZooKeeper 等系统中。无论是桌面程序、Web 应用程序还是简单的 Python 脚本，APScheduler 都很可能能够处理定时作业的存储方式。

除此之外，该库还可以与常见的 Python 并发框架（如 AsyncIO、Gevent、Tornado 和 Twisted）无缝配合工作。这意味着 APScheduler 库中包含的低级代码包含了可以协调安排和执行这些框架中实现的函数和程序的指令，使得该库更加动态。

最后，APScheduler 提供了不同的选项来实际执行计划代码，通过指定适当的执行器。具体来说，可以简单地以阻塞方式或后台方式执行作业。我们还可以选择使用线程或进程池以并发方式分发工作。稍后，我们将看一个示例，其中我们利用进程池来执行定时作业。

以下图表显示了 APScheduler 中包含的所有主要类和功能：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/d409ecad-f11f-446f-831b-fbcbcc1cc188.png)

APScheduler-主要类和功能

# APScheduler API

在本节中，我们将看看如何将 APScheduler 实际集成到现有的 Python 程序中，分析库提供的不同类和方法。当我们利用并发执行器运行我们的定时作业时，我们还将看看作业如何分布在不同的线程和进程中。

# 调度器类

首先，让我们看看我们的主调度器可用的选项，这是安排任务在以后执行过程中最重要的组件：

+   `BlockingScheduler`：当调度程序打算是进程中唯一运行的任务时，应使用此类。顾名思义，此类的实例将阻止同一进程中的任何其他指令。

+   `BackgroundScheduler`：与`BlockingScheduler`相反，此类允许在现有应用程序内后台执行定时作业。

此外，如果您的应用程序使用特定的并发框架，则还有调度器类可供使用：`AsyncIOScheduler`用于`asyncio`模块；`GeventScheduler`用于 Gevent；`TornadoScheduler`用于 Tornado 应用程序；`TwistedScheduler`用于 Twisted 应用程序；等等。

# 执行器类

在安排将来执行的作业的过程中，另一个重要的选择是：哪个执行器应该运行这些作业？通常建议使用默认执行器`ThreadPoolExecutor`，它在同一进程中的不同线程之间分配工作。然而，正如您所了解的，如果预定的作业包含利用 CPU 密集型操作的指令，则工作负载应该分布在多个 CPU 核心上，并且应该使用`ProcessPoolExecutor`。

重要的是要注意，这两个执行器类与我们在早期章节中讨论的`concurrent.futures`模块进行交互，以便实现并发执行。这两个执行器类的默认最大工作线程数为`10`，可以在初始化时进行更改。

# 触发关键字

在构建调度器的过程中的最后一个决定是如何在将来执行预定的作业；这是我们之前提到的事件触发选项。APScheduler 提供了三种不同的触发机制；以下关键字应作为参数传递给调度器初始化程序，以指定事件触发类型：

+   `'日期'`: 当工作需要在将来的特定时间点运行一次时使用此关键字。

+   `'间隔'`: 当工作需要定期以固定时间间隔运行时使用此关键字。我们稍后在示例中将使用此关键字。

+   `'cron'`: 当作业需要在一天的特定时间定期运行时使用此关键字。

此外，可以混合和匹配多种类型的触发器。我们还可以选择在所有注册的触发器都指定时执行预定的作业，或者在至少一个触发器指定时执行。

# 常见的调度器方法

最后，让我们考虑在声明调度器时常用的方法，以及前面提到的类和关键字。具体来说，以下方法由`scheduler`对象调用：

+   `add_executor()`: 调用此方法来注册一个执行器以在将来运行作业。通常，我们将字符串`'processpool'`传递给此方法，以便将作业分布在多个进程中。否则，如前所述，默认执行器将使用线程池。此方法还返回一个可以进一步操作的执行器对象。

+   `remove_executor()`: 此方法用于在执行器对象上移除它。

+   `add_job()`: 此方法可用于将额外的作业添加到作业列表中，以便稍后执行。该方法首先接受一个可调用对象，该对象是作业列表中的新作业，以及用于指定作业应如何预定和执行的各种其他参数。与`add_executor()`类似，此方法可以返回一个可以在方法外部操作的`job`对象。

+   `remove_job()`: 类似地，此方法可以用于`job`对象，以将其从调度器中移除。

+   `start()`: 此方法启动预定的作业以及已实现的执行器，并开始处理作业列表。

+   `shutdown()`: 此方法停止调用调度器对象，以及其作业列表和已实现的执行器。如果在当前有作业运行时调用它，这些作业将不会被中断。

# Python 示例

在本小节中，我们将看看我们讨论的一些 API 在示例 Python 程序中的使用方式。从 GitHub 页面下载本书的代码，然后转到`Chapter19`文件夹。

# 阻塞调度器

首先，让我们看一个阻塞调度器的示例，在`Chapter19/example1.py`文件中：

```py
# Chapter19/example1.py

from datetime import datetime

from apscheduler.schedulers.background import BlockingScheduler

def tick():
    print(f'Tick! The time is: {datetime.now()}')

if __name__ == '__main__':
    scheduler = BlockingScheduler()
    scheduler.add_job(tick, 'interval', seconds=3)

    try:
        scheduler.start()
        print('Printing in the main thread.')
    except KeyboardInterrupt:
        pass

scheduler.shutdown()
```

在这个例子中，我们正在为前面代码中指定的`tick()`函数实现一个调度程序，该函数简单地打印出执行时的当前时间。在我们的主函数中，我们使用了从 APScheduler 导入的`BlockingScheduler`类的实例作为本程序的调度程序。除此之外，上述的`add_job()`方法被用来注册`tick()`作为稍后要执行的作业。具体来说，它应该定期执行，以均匀的间隔（由传入的`'interval'`字符串指定）——特别是每三秒钟（由参数`seconds=3`指定）。

请记住，阻塞调度程序将阻止在其运行的同一进程中的所有其他指令。为了测试这一点，我们还在启动调度程序后插入了一个`print`语句，以查看它是否会被执行。运行脚本后，您的输出应该类似于以下内容（除了正在打印的具体时间）：

```py
> python3 example1.py
Tick! The time is: 2018-10-31 17:25:01.758714
Tick! The time is: 2018-10-31 17:25:04.760088
Tick! The time is: 2018-10-31 17:25:07.762981
```

请注意，该调度程序将永远运行，除非它被`KeyboardInterrupt`事件或其他潜在异常停止，并且我们放在主程序末尾附近的打印语句将永远不会被执行。因此，只有在打算在其进程中运行的唯一任务时，才应该使用`BlockingScheduler`类。

# 后台调度程序

在这个例子中，我们将看看是否使用`BackgroundScheduler`类会有所帮助，如果我们想要在后台并发地执行我们的调度程序。此示例的代码包含在`Chapter19/example2.py`文件中，如下所示：

```py
# Chapter19/example2.py

from datetime import datetime
import time

from apscheduler.schedulers.background import BackgroundScheduler

def tick():
    print(f'Tick! The time is: {datetime.now()}')

if __name__ == '__main__':
    scheduler = BackgroundScheduler()
    scheduler.add_job(tick, 'interval', seconds=3)
    scheduler.start()

    try:
        while True:
            time.sleep(2)
            print('Printing in the main thread.')
    except KeyboardInterrupt:
        pass

scheduler.shutdown()
```

这个例子中的代码几乎与我们之前的代码相同。然而，在这里，我们使用了后台调度程序的类，并且每两秒钟在一个无限的`while`循环中从主程序中打印出消息。理论上，如果`scheduler`对象确实可以在后台运行计划的作业，我们的输出将由主程序和`tick()`函数中的打印语句的组合组成。

执行脚本后，以下是我的输出：

```py
> python3 example2.py
Printing in the main thread.
Tick! The time is: 2018-10-31 17:36:35.231531
Printing in the main thread.
Tick! The time is: 2018-10-31 17:36:38.231900
Printing in the main thread.
Printing in the main thread.
Tick! The time is: 2018-10-31 17:36:41.231846
Printing in the main thread.
```

同样，调度程序将一直继续下去，直到从键盘中产生中断。在这里，我们可以看到我们期望看到的东西：主程序和计划的作业的打印语句同时产生，表明调度程序确实在后台运行。

# 执行器池

APScheduler 提供的另一个功能是能够将计划的作业分发到多个 CPU 核心（或进程）上执行。在这个例子中，您将学习如何使用后台调度程序来实现这一点。转到`Chapter19/example3.py`文件并检查包含的代码，如下所示：

```py
# Chapter19/example3.py

from datetime import datetime
import time
import os

from apscheduler.schedulers.background import BackgroundScheduler

def task():
    print(f'From process {os.getpid()}: The time is {datetime.now()}')
    print(f'Starting job inside {os.getpid()}')
    time.sleep(4)
    print(f'Ending job inside {os.getpid()}')

if __name__ == '__main__':
    scheduler = BackgroundScheduler()
    scheduler.add_executor('processpool')
    scheduler.add_job(task, 'interval', seconds=3, max_instances=3)
    scheduler.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

scheduler.shutdown()
```

在这个程序中，我们想要调度的作业（`task()`函数）在每次调用时打印出运行它的进程的标识符（使用`os.getpid()`方法），并且设计为持续约四秒钟。在主程序中，我们使用了上一个示例中使用的相同后台调度程序，但我们指定了计划的作业应该在一个进程池中执行：

```py
scheduler.add_executor('processpool')
```

请记住，此进程池中进程数量的默认值为 10，可以更改为不同的值。接下来，当我们将作业添加到调度程序时，我们还必须指定此作业可以在多个进程实例中执行（在本例中为三个实例）；这允许我们的进程池执行程序得到充分和高效地利用：

```py
scheduler.add_job(task, 'interval', seconds=3, max_instances=3)
```

运行程序后，我的输出的前几行如下：

```py
> python3 example3.py
From process 1213: The time is 2018-11-01 10:18:00.559319
Starting job inside 1213
From process 1214: The time is 2018-11-01 10:18:03.563195
Starting job inside 1214
Ending job inside 1213
From process 1215: The time is 2018-11-01 10:18:06.531825
Starting job inside 1215
Ending job inside 1214
From process 1216: The time is 2018-11-01 10:18:09.531439
Starting job inside 1216
Ending job inside 1215
From process 1217: The time is 2018-11-01 10:18:12.531940
Starting job inside 1217
Ending job inside 1216
From process 1218: The time is 2018-11-01 10:18:15.533720
Starting job inside 1218
Ending job inside 1217
From process 1219: The time is 2018-11-01 10:18:18.532843
Starting job inside 1219
Ending job inside 1218
From process 1220: The time is 2018-11-01 10:18:21.533668
Starting job inside 1220
Ending job inside 1219
From process 1221: The time is 2018-11-01 10:18:24.535861
Starting job inside 1221
Ending job inside 1220
From process 1222: The time is 2018-11-01 10:18:27.531543
Starting job inside 1222
Ending job inside 1221
From process 1213: The time is 2018-11-01 10:18:30.532626
Starting job inside 1213
Ending job inside 1222
From process 1214: The time is 2018-11-01 10:18:33.534703
Starting job inside 1214
Ending job inside 1213
```

从打印的进程标识中可以看出，计划任务是在不同的进程中执行的。您还会注意到第一个进程的 ID 是`1213`，而当我们的调度器开始使用 ID 为`1222`的进程时，它又切换回`1213`进程（请注意前面输出的最后几行）。这是因为我们的进程池包含 10 个工作进程，而`1222`进程是池的最后一个元素。

# 在云上运行

早些时候，我们提到了托管 Python 代码的云服务，如 Heroku 和 PythonAnywhere，是应用 APScheduler 功能的最常见的地方之一。在本小节中，我们将看一下 Heroku 网站用户指南中的一个示例，该示例可以在`Chapter19/example4.py`文件中找到：

```py
# ch19/example4.py
# Copied from: http://devcenter.heroku.com/articles/clock-processes-python

from apscheduler.schedulers.blocking import BlockingScheduler

scheduler = BlockingScheduler()

@scheduler.scheduled_job('interval', minutes=3)
def timed_job():
    print('This job is run every three minutes.')

@scheduler.scheduled_job('cron', day_of_week='mon-fri', hour=17)
def scheduled_job():
    print('This job is run every weekday at 5pm.')

scheduler.start()
```

您可以看到，该程序使用装饰器为调度器注册了计划任务。具体来说，当`scheduled_job()`方法由`scheduler`对象调用时，整个指令可以作为函数的装饰器，将其转换为该调度器的调度任务。您还可以在前面的代码中看到一个`cron`计划的作业的示例，它可以在一天中的特定时间执行（在这种情况下，是每个工作日下午 5:00）。

最后关于 APScheduler 的一点说明，我们已经看到利用库 API 的指令也是 Python 代码，而不是一个独立的服务。然而，考虑到该库在提供不同的调度选项方面有多么灵活，以及在与外部服务（如基于云的服务）合作方面有多么可插拔，APScheduler 是调度 Python 应用程序的有价值的工具。

# Python 中的测试和并发

如前所述，测试是软件开发特别是编程中一个重要的（但经常被忽视的）组成部分。测试的目标是引发错误，这些错误会表明我们程序中存在 bug。这与调试的过程相对，调试用于识别 bug 本身；我们将在下一节讨论调试的主题。

在最一般的意义上，测试是关于确定特定的功能和方法是否能够执行并产生我们期望的结果；通常是通过比较产生的结果来完成的。换句话说，测试是收集关于程序正确性的证据。

然而，测试不能确保在考虑中的程序中所有潜在的缺陷和 bug 都会被识别出来。此外，测试结果只有测试本身那么好，如果测试没有涵盖一些特定的潜在 bug，那么这些 bug 在测试过程中很可能不会被检测到。

# 测试并发程序

在本章中，我们将考虑与并发相关的测试的两个不同主题：**测试并发程序**和**同时测试程序**。当涉及测试并发程序时，一般的共识是这是极其严格和难以正确完成的。正如您在前几章中看到的，诸如死锁或竞争条件之类的 bug 在并发程序中可能相当微妙，并且可能以多种方式表现出来。

此外，并发的一个显著特点是非确定性，这意味着并发 bug 可能在一个测试运行中被检测到，而在另一个测试运行中变得不可见。这是因为并发编程的一个重要组成部分是任务的调度，就像并发程序中执行不同任务的顺序一样，并发 bug 可能以不可预测的方式显示和隐藏自己。我们称这些测试为不可重现的，表示我们无法以一致的方式可靠地通过或失败这些测试来测试程序。

有一些通用策略可以帮助我们在测试并发程序的过程中进行导航。在接下来的部分中，我们将探讨各种工具，这些工具可以帮助我们针对测试并发程序的特定策略进行辅助。

# 单元测试

我们将考虑的第一种策略是单元测试。该术语表示一种测试程序考虑的各个单元的方法，其中单元是程序的最小可测试部分。因此，单元测试不适用于测试完整的并发系统。具体来说，建议您不要将并发程序作为一个整体进行测试，而是将程序分解为较小的组件并分别测试它们。

通常情况下，Python 提供了提供直观 API 来解决编程中最常见问题的库；在这种情况下，它是`unittest`模块。该模块最初受到了 Java 编程语言 JUnit 的单元测试框架的启发；它还提供了其他语言中常见的单元测试功能。让我们考虑一个快速示例，演示如何使用`unittest`来测试`Chapter19/example5.py`文件中的 Python 函数：

```py
# Chapter19/example5.py

import unittest

def fib(i):
    if i in [0, 1]:
        return i

    return fib(i - 1) + fib(i - 2)

class FibTest(unittest.TestCase):
    def test_start_values(self):
        self.assertEqual(fib(0), 0)
        self.assertEqual(fib(1), 1)

    def test_other_values(self):
        self.assertEqual(fib(10), 55)

if __name__ == '__main__':
    unittest.main()
```

在这个例子中，我们想要测试`fib()`函数，该函数生成斐波那契数列中的特定元素（其中一个元素是其前两个元素的和），其起始值分别为`0`和`1`。

现在，让我们把注意力集中在`FibTest`类上，该类扩展了`unittest`模块中的`TestCase`类。这个类包含了测试`fib()`函数返回的特定结果的不同方法。具体来说，我们有一个方法来查看这个函数的边界情况，即序列的前两个元素，还有一个方法来测试序列中的任意值。

在运行上述脚本之后，您的输出应该类似于以下内容：

```py
> python3 unit_test.py
..
----------------------------------------------------------------------
Ran 2 tests in 0.000s

OK
```

输出表明我们的测试通过了，没有任何错误。另外，正如类名所示，这个类是一个单独的测试用例，是测试的一个单元。您可以将不同的测试用例扩展为**测试套件**，它被定义为测试用例、测试套件或两者的集合。测试套件通常用于组合您想要一起运行的测试。

# 静态代码分析

识别并发程序中潜在错误和漏洞的另一种可行方法是进行静态代码分析。这种方法寻找代码本身的模式，而不是执行代码的一部分（或全部）。换句话说，静态代码分析通过视觉检查程序的结构、变量和指令的使用以及程序的不同部分如何相互交互来检查程序。

使用静态代码分析的主要优势在于，我们不仅依赖于程序的执行和在该过程中产生的结果（换句话说，动态测试）来确定程序是否设计正确。这种方法可以检测在实施测试中不会表现出来的错误和漏洞。因此，静态代码分析应该与其他测试方法结合使用，例如单元测试，以创建一个全面的测试过程。

静态代码分析通常用于识别微妙的错误或漏洞，例如未使用的变量、空的 catch 块，甚至不必要的对象创建。在并发编程方面，该方法可用于分析程序中使用的同步技术。具体来说，静态代码分析可以查找程序中共享资源的原子性，然后揭示任何不协调使用非原子资源的情况，这可能会产生有害的竞争条件。

Python 程序的静态代码分析有各种工具可用，其中一个比较常见的是 PMD（[`github.com/pmd/pmd`](https://github.com/pmd/pmd)）。话虽如此，这些工具的具体使用超出了本书的范围，我们不会进一步讨论它们。

# 并发测试程序。

结合测试和并发编程的另一个方面是以并发方式执行测试。这方面的测试比测试并发程序本身更直接和直观。在本小节中，我们将探索一个可以帮助我们简化这个过程的库`concurrencytest`，它可以与前面的`unittest`模块实现的测试用例无缝配合。

`concurrencytest`被设计为`testtools`的扩展，用于在运行测试套件时实现并发。可以通过 PyPI 使用`pip`安装它，如下所示：

```py
pip install concurrencytest
```

另外，`concurrencytest`依赖于`testtools`（[pypi.org/project/testtools/](https://pypi.org/project/testtools/)）和`python-subunit`（[pypi.org/project/python-subunit/](https://pypi.org/project/python-subunit/)）库，它们分别是测试扩展框架和测试结果的流程协议。这些库也可以通过`pip`安装，如下所示：

```py
pip install testtools
pip install python-subunit
```

和往常一样，要验证你的安装，尝试在 Python 解释器中导入库：

```py
>>> import concurrencytest
```

没有打印错误意味着库及其依赖项已成功安装。现在，让我们看看这个库如何帮助我们提高测试速度。转到`Chapter19/example6.py`文件并考虑以下代码：

```py
# Chapter19/example6.py

import unittest

def fib(i):
    if i in [0, 1]:
        return i

    a, b = 0, 1
    n = 1
    while n < i:
        a, b = b, a + b
        n += 1

    return b

class FibTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(FibTest, self).__init__(*args, **kwargs)
        self.mod = 10 ** 10

    def test_start_values(self):
        self.assertEqual(fib(0), 0)
        self.assertEqual(fib(1), 1)

    def test_big_value_v1(self):
        self.assertEqual(fib(499990) % self.mod, 9998843695)

    def test_big_value_v2(self):
        self.assertEqual(fib(499995) % self.mod, 1798328130)

    def test_big_value_v3(self):
        self.assertEqual(fib(500000) % self.mod, 9780453125)

if __name__ == '__main__':
    unittest.main()
```

本节示例的主要目标是测试生成斐波那契数列中具有大索引的数字的函数。我们拥有的`fib()`函数与之前的示例类似，尽管这个函数是迭代执行计算的，而不是使用递归。

在我们的测试用例中，除了两个起始值外，我们现在还在测试索引为 499,990、499,995 和 500,000 的数字。由于结果数字非常大，我们只测试每个数字的最后十位数（这是通过测试类的初始化方法中指定的`mod`属性完成的）。这个测试过程将在一个进程中以顺序方式执行。

运行程序，你的输出应该类似于以下内容：

```py
> python3 example6.py
....
----------------------------------------------------------------------
Ran 4 tests in 8.809s

OK
```

再次强调，输出中指定的时间可能因系统而异。话虽如此，记住程序所花费的时间，以便与我们稍后考虑的其他程序的速度进行比较。

现在，让我们看看如何使用`concurrencytest`在多个进程中分发测试工作负载。考虑以下`Chapter19/example7.py`文件：

```py
# Chapter19/example7.py

import unittest
from concurrencytest import ConcurrentTestSuite, fork_for_tests

def fib(i):
    if i in [0, 1]:
        return i

    a, b = 0, 1
    n = 1
    while n < i:
        a, b = b, a + b
        n += 1

    return b

class FibTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(FibTest, self).__init__(*args, **kwargs)
        self.mod = 10 ** 10

    def test_start_values(self):
        self.assertEqual(fib(0), 0)
        self.assertEqual(fib(1), 1)

    def test_big_value_v1(self):
        self.assertEqual(fib(499990) % self.mod, 9998843695)

    def test_big_value_v2(self):
        self.assertEqual(fib(499995) % self.mod, 1798328130)

    def test_big_value_v3(self):
        self.assertEqual(fib(500000) % self.mod, 9780453125)

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(FibTest)
    concurrent_suite = ConcurrentTestSuite(suite, fork_for_tests(4))
    runner.run(concurrent_suite)
```

这个程序版本正在检查相同的`fib()`函数，使用相同的测试用例。然而，在主程序中，我们正在初始化`concurrencytest`库的`ConcurrentTestSuite`类的一个实例。这个实例接受一个测试套件，该测试套件是使用`unittest`模块的`TestLoader()`API 创建的，并使用`fork_for_tests()`函数，参数为`4`，以指定我们要利用四个独立进程来分发测试过程。

现在，让我们运行这个程序，并将其速度与之前的测试进行比较：

```py
> python3 example7.py
....
----------------------------------------------------------------------
Ran 4 tests in 4.363s

OK
```

你可以看到，通过这种多进程方法，速度有了显著的提高。然而，这种改进并不完全达到了完美的可扩展性（在第十六章中讨论过，*设计基于锁和无互斥的并发数据结构*）；这是因为创建可以在多个进程中执行的并发测试套件会产生相当大的开销。

我们还应该提到的一点是，通过使用我们在前几章讨论过的传统并发编程工具，如`concurrent.futures`或`multiprocessing`，完全可以实现与我们在这里实现的相同的多进程设置。尽管如此，正如我们所看到的，`concurrencytest`库能够消除大量样板代码，因此提供了一个简单快速的 API。

# 调试并发程序

在最后一节中，我们将讨论各种高级调试策略，这些策略可以单独使用，也可以结合使用，以便检测和定位程序中的错误。

我们将讨论的策略包括一般的调试策略，以及调试并发应用程序中使用的特定技术。系统地应用这些策略将提高调试过程的效率和速度。

# 调试工具和技术

首先，让我们简要地看一下一些可以在 Python 中促进调试过程的常见技术和工具：

+   **打印调试**：这可能是最基本和直观的调试方法。这种方法涉及在考虑的程序执行过程中的各个点插入打印语句，以输出变量的值或函数的状态。这样做可以让我们跟踪这些值和状态在程序中如何相互作用和改变，从而让我们了解特定错误或异常是如何引发的。

+   **日志记录**：在计算机科学领域，日志记录是记录特定程序执行过程中发生的各种事件的过程。实质上，日志记录可能与打印调试非常相似；然而，前者通常会写入一个可以稍后查看的日志文件。Python 提供了出色的日志记录功能，包含在内置的`logging`模块中。用户可以指定日志记录过程的重要性级别；例如，通常情况下，可以仅记录重要事件和操作，但在调试期间将记录所有内容。

+   **跟踪**：这是另一种跟踪程序执行的形式。跟踪遵循程序执行的实际低级细节，而不仅仅是变量和函数的变化。跟踪功能可以通过 Python 中的`sys.settrace()`方法实现。

+   **使用调试器**：有时，最强大的调试选项可以通过自动调试器实现。Python 语言中最流行的调试器是 Python 调试器：`pdb`。该模块提供了一个交互式调试环境，实现了诸如断点、逐步执行源代码或检查堆栈等有用功能。

同样，上述策略适用于传统程序和并发程序，结合其中的一个或多个策略可以帮助程序员在调试过程中获得有价值的信息。

# 调试和并发

与测试并发程序的问题类似，调试并发时可能变得越来越复杂和困难。这是因为共享资源可以与（并且可以被）多个代理同时交互和改变。尽管如此，仍然有一些策略可以使调试并发程序的过程更加简单。这些策略包括以下内容：

+   **最小化**：并发应用通常在复杂和相互连接的系统中实现。当发生错误时，调试整个系统可能会令人望而生畏，并且并不可行。策略是将系统的不同部分隔离成单独的、较小的程序，并识别与大型系统相同方式失败的部分。在这里，我们希望将一个大型程序分割成越来越小的部分，直到它们无法再分割。然后可以轻松地识别原始错误并有效地修复。

+   **单线程和处理**：这种方法类似于最小化，但专注于并发编程的一个方面：不同线程/进程之间的交互。通过消除并发编程中最大的方面，可以将错误隔离到程序逻辑本身（即使按顺序运行时也可能导致错误）或线程/进程之间的交互（这可能是由我们在前几章中讨论的常见并发错误导致的）。

+   **操纵调度以放大潜在错误**：我们实际上在前几章中看到了这种方法的应用。如果我们程序中实现的线程/进程没有按特定方式调度执行，一些并发错误可能不经常显现。例如，如果共享资源与其他代理之间的交互发生得如此之快，以至于它们不经常重叠，那么现有的竞争条件可能不会影响共享资源。这导致测试可能不会揭示竞争条件，即使它实际上存在于程序中。

可以在 Python 中实现各种方法，以放大并发错误导致的不正确值和操作。其中最常见的两种是模糊化，通过在线程/进程指令中的命令之间插入休眠函数来实现，以及最小化系统线程切换间隔，通过使用`sys.setcheckinterval()`方法（在第十七章中讨论，*内存模型和原子类型上的操作*）。这些方法以不同的方式干扰 Python 中线程和进程执行的常规调度协议，并可以有效地揭示隐藏的并发错误。

# 总结

在本章中，我们通过调度、测试和调试对 Python 中的并发程序进行了高层次的分析。可以通过 APScheduler 模块在 Python 中进行调度，该模块提供了强大而灵活的功能，以指定将来如何执行预定作业。此外，该模块允许预定的作业在不同的线程和进程中分布和执行，提供了测试速度的并发改进。

并发还在测试和调试方面引入了复杂的问题，这是由程序中代理之间的同时和并行交互导致的。然而，这些问题可以通过有条理的解决方案和适当的工具有效地解决。

这个主题标志着我们通过《Python 并发编程大师》的旅程结束。在整本书中，我们深入考虑和分析了使用 Python 语言进行并发编程的各种元素，如线程、多进程和异步编程。此外，还讨论了涉及并发性的强大应用，如上下文管理、减少操作、图像处理和网络编程，以及在 Python 中处理并发性的程序员面临的常见问题。

从最一般的意义上讲，这本书是对并发的一些更高级概念的指南；我希望通过阅读这本书，你有机会对并发编程的主题有所了解。

# 问题

+   APScheduler 是什么？为什么它不是一个调度服务？

+   APScheduler 的主要调度功能是什么？

+   APScheduler 与 Python 中另一个调度工具 Celery 之间有什么区别？

+   编程中测试的目的是什么？在并发编程中有何不同？

+   本章讨论了哪些测试方法？

+   调试在编程中的目的是什么？在并发编程中有何不同？

+   本章讨论了哪些调试方法？

# 进一步阅读

有关更多信息，您可以参考以下链接：

+   *高级 Python 调度器* ([apscheduler.readthedocs.io/en/latest/index](https://apscheduler.readthedocs.io/en/latest/index.html))

+   *使用 APScheduler 在 Python 中进行定时作业* ([devcenter.heroku.com/articles/clock-processes-python](https://devcenter.heroku.com/articles/clock-processes-python))

+   *APScheduler 的架构*，Ju Lin ([enqueuezero.com/apscheduler](https://enqueuezero.com/apscheduler.html))

+   , Alex. *APScheduler 3.0 发布*，Alex Grönholm ([alextechrants.blogspot.com/2014/08/apscheduler-30-released](http://alextechrants.blogspot.com/2014/08/apscheduler-30-released.html))

+   *测试您的代码* (*Python 之旅者指南*), Kenneth Reitz

+   *Python – concurrencytest: 运行并发测试*，Corey Goldberg ([coreygoldberg.blogspot.com/2013/06/python-concurrencytest-running](http://coreygoldberg.blogspot.com/2013/06/python-concurrencytest-running.html))

+   *Python 测试入门*，Anthony Shaw ([realpython.com/python-testing/](https://realpython.com/python-testing/))

+   *跟踪 Python 代码*，Andrew Dalke ([dalkescientific.com/writings/diary/archive/2005/04/20/tracing_python_code](http://www.dalkescientific.com/writings/diary/archive/2005/04/20/tracing_python_code.html))
