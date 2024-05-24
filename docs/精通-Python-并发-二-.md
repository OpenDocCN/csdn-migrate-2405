# 精通 Python 并发（二）

> 原文：[`zh.annas-archive.org/md5/9D7D3F09D4C6183257545C104A0CAC2A`](https://zh.annas-archive.org/md5/9D7D3F09D4C6183257545C104A0CAC2A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：在 Python 中处理进程

本章是关于在 Python 中使用多进程编程进行并发的三章中的第一章。我们已经看到了在并发和并行编程中使用进程的各种示例。在本章中，您将了解进程的正式定义，以及 Python 中的`multiprocessing`模块。本章将介绍使用`multiprocessing`模块的 API 与进程一起工作的一些最常见的方法，例如`Process`类，`Pool`类和诸如`Queue`类之类的进程间通信工具。本章还将研究并发编程中多线程和多进程之间的主要区别。

本章将涵盖以下主题：

+   在计算机科学中并发编程的上下文中的进程概念

+   Python 中`multiprocessing`模块的基本 API

+   如何与进程交互以及`multiprocessing`模块提供的高级功能

+   `multiprocessing`模块如何支持进程间通信

+   并发编程中多进程和多线程之间的主要区别

# 技术要求

以下是本章的先决条件列表：

+   在计算机上安装 Python 3

+   在[`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python)下载 GitHub 存储库

+   确保您可以访问名为`Chapter06`的子文件夹

+   查看以下视频以查看代码的运行情况：[`bit.ly/2BtwlJw`](http://bit.ly/2BtwlJw)

# 进程的概念

在计算机科学领域，**执行过程**是操作系统正在执行的特定计算机程序或软件的实例。进程包含程序代码及其当前的活动和与其他实体的交互。根据操作系统的不同，进程的实现可以由多个执行线程组成，这些线程可以并发或并行执行指令。

重要的是要注意，进程不等同于计算机程序。虽然程序只是一组静态指令（程序代码），但进程实际上是这些指令的实际执行。这也意味着相同的程序可以通过生成多个进程并发地运行。这些进程执行来自父程序的相同代码。

例如，互联网浏览器 Google Chrome 通常会管理一个名为**Google Chrome Helper**的进程，以便为其主程序提供网页浏览和其他进程的便利，以协助各种目的。查看系统正在运行和管理的不同进程的简单方法包括使用 Windows 的任务管理器，iOS 的活动监视器和 Linux 操作系统的系统监视器。

以下是我的活动监视器的屏幕截图。在列表中可以看到多个名为 Google Chrome Helper 的进程。`PID`列（代表**进程 ID**）报告了每个进程的唯一 ID：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/3acd51e5-d3a6-475d-bd2d-ea66d49e35d8.png)

进程的示例列表

# 进程与线程

在开发并发和并行应用程序时，程序员经常犯的一个常见错误是混淆进程和线程的结构和功能。正如我们从第三章中所看到的，*在 Python 中使用线程*，线程是编程代码的最小单位，通常是进程的组成部分。此外，可以在同一进程中实现多个线程以访问和共享内存或其他资源，而不同的进程不以这种方式进行交互。这种关系如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/8da2ba25-b5b5-4225-beb9-e94d2eb3beec.png)

两个线程在一个进程中执行的图表

由于进程是比线程更大的编程单元，因此它也更复杂，包含更多的编程组件。因此，进程也需要更多的资源，而线程则不需要，有时被称为轻量级进程。在典型的计算机系统进程中，有许多主要资源，如下列表所示：

+   从父程序执行的代码的图像（或副本）。

+   与程序实例相关联的内存。这可能包括特定进程的可执行代码、输入和输出、用于管理程序特定事件的调用堆栈，或者包含生成的计算数据并在运行时由进程使用的堆。

+   由操作系统分配给特定进程的资源的描述符。我们已经在第四章中看到了这些资源的示例——文件描述符——*在线程中使用 with 语句*。

+   特定进程的安全组件，即进程的所有者及其权限和允许的操作。

+   处理器状态，也称为进程上下文。进程的上下文数据通常位于处理器寄存器、进程使用的内存或操作系统用于管理进程的控制寄存器中。

由于每个进程都有专门的状态，进程比线程保存更多的状态信息；进程内的多个线程又共享进程状态、内存和其他各种资源。出于类似的原因，进程只能通过系统提供的进程间通信方法与其他进程进行交互，而线程可以通过共享资源轻松地相互通信。

此外，上下文切换——保存进程或线程的状态数据以中断任务的执行并在以后恢复它的行为——在不同进程之间所需的时间比在同一进程内的不同线程之间所需的时间更长。然而，尽管我们已经看到线程之间的通信需要仔细的内存同步以确保正确的数据处理，由于不同进程之间的通信较少，进程几乎不需要或不需要内存同步。

# 多处理

计算机科学中的一个常见概念是多任务处理。在多任务处理时，操作系统会以高速在不同进程之间切换，从而使这些进程看起来像是同时执行，尽管通常情况下只有一个进程在任何给定时间内在一个单独的中央处理单元（CPU）上执行。相比之下，多处理是使用多个 CPU 来执行任务的方法。

虽然术语多处理有许多不同的用法，但在并发性和并行性的上下文中，多处理指的是在操作系统中执行多个并发进程，其中每个进程在单独的 CPU 上执行，而不是在任何给定时间内执行单个进程。由于进程的性质，操作系统需要有两个或更多个 CPU 才能实现多处理任务，因为它需要同时支持多个处理器并适当地分配任务。

此关系显示在以下图表中：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/269f5c8c-8758-47e1-86b2-b9838cf3a8b5.png)

多处理使用两个 CPU 核心的示例图

我们在第三章中看到，多线程与多处理有相似的定义。多线程意味着只有一个处理器被利用，并且系统在该处理器内的任务之间进行切换（也称为时间片切割），而多处理通常表示使用多个处理器实际并发/并行执行多个进程。

多进程应用在并发和并行编程领域享有显著的流行度。一些原因如下所列：

+   **更快的执行时间**：我们知道，正确的并发总是能够为程序提供额外的加速，前提是它们的某些部分可以独立执行。

+   **无需同步**：由于在多进程应用中，独立的进程不会共享资源，开发人员很少需要花时间协调这些资源的共享和同步，不像多线程应用程序，需要努力确保数据被正确操作。

+   **免于崩溃**：由于进程在计算过程和输入/输出方面是相互独立的，多进程程序中一个进程的失败不会影响另一个进程的执行，如果处理正确的话。这意味着程序员可以承担产生更多进程（系统仍然可以处理的）的风险，而整个应用程序崩溃的机会不会增加。

话虽如此，使用多进程也有一些值得注意的缺点，如下列表所示：

+   **需要多个处理器**：再次强调，多进程需要操作系统拥有多个 CPU。尽管多处理器如今对计算机系统来说相当普遍，但如果你的系统没有多个处理器，那么多进程的实现将是不可能的。

+   处理时间和空间：如前所述，实现一个进程及其资源涉及许多复杂的组件。因此，与使用线程相比，生成和管理进程需要大量的计算时间和计算能力。

# Python 中的入门示例

为了说明在一个操作系统上运行多个进程的概念，让我们看一个 Python 的快速示例。让我们看一下`Chapter06/example1.py`文件，如下面的代码所示：

```py
# Chapter06/example1.py

from multiprocessing import Process
import time

def count_down(name, delay):
    print('Process %s starting...' % name)

    counter = 5

    while counter:
        time.sleep(delay)
        print('Process %s counting down: %i...' % (name, counter))
        counter -= 1

    print('Process %s exiting...' % name)

if __name__ == '__main__':
    process1 = Process(target=count_down, args=('A', 0.5))
    process2 = Process(target=count_down, args=('B', 0.5))

    process1.start()
    process2.start()

    process1.join()
    process2.join()

    print('Done.')
```

在这个文件中，我们回到了在第三章中看到的倒计时示例，*在 Python 中使用线程*，同时我们也看一下线程的概念。我们的`count_down()`函数接受一个字符串作为进程标识符和一个延迟时间范围。然后它将从 5 倒数到 1，同时在每次迭代之间睡眠，睡眠时间由`delay`参数指定。该函数还在每次迭代时打印出带有进程标识符的消息。

正如我们在第三章中所看到的，*在 Python 中使用线程*，这个倒计时的例子的目的是展示同时运行不同进程的并发性质，这次是通过使用`multiprocessing`模块中的`Process`类来实现的。在我们的主程序中，我们同时初始化两个进程来同时实现两个独立的基于时间的倒计时。与两个独立的线程一样，我们的两个进程将同时进行它们自己的倒计时。

运行 Python 脚本后，你的输出应该类似于以下内容：

```py
> python example1.py
Process A starting...
Process B starting...
Process B counting down: 5...
Process A counting down: 5...
Process B counting down: 4...
Process A counting down: 4...
Process B counting down: 3...
Process A counting down: 3...
Process B counting down: 2...
Process A counting down: 2...
Process A counting down: 1...
Process B counting down: 1...
Process A exiting...
Process B exiting...
Done.
```

正如我们所预期的，输出告诉我们，两个独立进程的倒计时是同时执行的；程序并不是先完成第一个进程的倒计时，然后再开始第二个进程的，而是几乎同时运行了两个倒计时。尽管进程比线程更昂贵，包含更多的开销，但多进程也允许程序的速度提高一倍，就像前面的例子一样。

请记住，在多线程中，我们看到一个现象，即程序的不同运行之间打印输出的顺序发生了变化。具体来说，有时进程 B 在倒计时期间超过进程 A 并在进程 A 之前完成，尽管它是后初始化的。这又一次是由于几乎同时执行相同函数的两个进程的实现和启动的直接结果。通过多次执行脚本，您会发现在计数和倒计时完成的顺序方面，您很可能会获得不断变化的输出。

# 多进程模块概述

`multiprocessing`模块是 Python 中最常用的多进程编程实现之一。它提供了一种类似于`threading`模块的 API，用于生成和与进程交互（就像我们在前面的示例中看到的`start()`和`join()`方法）。根据其文档网站，该模块允许本地和远程并发，并通过使用子进程而不是线程有效地避免了 Python 中的全局解释器锁（GIL）（我们将在第十五章中更详细地讨论这一点，*全局解释器锁*）。

# 进程类

在`multiprocessing`模块中，进程通常通过`Process`类生成和管理。每个`Process`对象代表在单独进程中执行的活动。方便的是，`Process`类具有与`threading.Thread`类中的等效方法和 API。

具体来说，利用面向对象的编程方法，`multiprocessing`中的`Process`类提供以下资源：

+   `run()`：当初始化并启动新进程时执行此方法

+   `start()`：此方法通过调用`run()`方法启动初始化的调用`Process`对象

+   `join()`：此方法在继续执行程序的其余部分之前等待调用`Process`对象终止

+   `isAlive()`：此方法返回一个布尔值，指示调用的`Process`对象当前是否正在执行

+   `name`：此属性包含调用`Process`对象的名称

+   `pid`：此属性包含调用`Process`对象的进程 ID

+   `terminate()`：此方法终止调用的`Process`对象

正如您可以从我们之前的示例中看到的，初始化`Process`对象时，我们可以通过指定`target`（目标函数）和`args`（目标函数参数）参数向函数传递参数，并在单独的进程中执行它。请注意，也可以重写默认的`Process()`构造函数并实现自己的`run()`函数。

由于它是`multiprocessing`模块和 Python 中并发的主要组成部分，我们将在下一节再次查看`Process`类。

# 池类

在`multiprocessing`模块中，`Pool`类主要用于实现一组进程，每个进程将执行提交给`Pool`对象的任务。通常，`Pool`类比`Process`类更方便，特别是如果并发应用程序返回的结果应该是有序的。

具体来说，我们已经看到，当通过函数并发地运行程序时，列表中不同项目的完成顺序很可能会发生变化。这导致在重新排序程序的输出时，难以根据产生它们的输入的顺序进行排序。其中一个可能的解决方案是创建进程和它们的输出的元组，并按进程 ID 对它们进行排序。

`Pool`类解决了这个问题：`Pool.map()`和`Pool.apply()`方法遵循 Python 传统`map()`和`apply()`方法的约定，确保返回的值按照输入的顺序排序。然而，这些方法会阻塞主程序，直到进程完成处理。因此，`Pool`类还具有`map_async()`和`apply_async()`函数，以更好地支持并发和并行。

# 确定当前进程、等待和终止进程

`Process`类提供了一些在并发程序中轻松与进程交互的方法。在本节中，我们将探讨通过确定当前进程、等待和终止进程来管理不同进程的选项。

# 确定当前进程

处理进程有时会相当困难，因此需要进行重大调试。调试多进程程序的一种方法是识别遇到错误的进程。作为复习，在前面的倒计时示例中，我们向`count_down()`函数传递了一个`name`参数，以确定倒计时期间每个进程的位置。

然而，这是不必要的，因为每个`Process`对象都有一个`name`参数（带有默认值），可以进行更改。给进程命名是跟踪运行进程的更好方法，而不是将标识符传递给目标函数本身（就像我们之前做的那样），特别是在同时运行不同类型进程的应用程序中。`multiprocessing`模块提供的一个强大功能是`current_process()`方法，它将返回当前正在运行的`Process`对象。这是另一种有效而轻松地跟踪运行进程的方法。

让我们通过一个例子更详细地看一下。转到`Chapter06/example2.py`文件，如下所示的代码：

```py
# Chapter06/example2.py

from multiprocessing import Process, current_process
import time

def f1():
    pname = current_process().name
    print('Starting process %s...' % pname)
    time.sleep(2)
    print('Exiting process %s...' % pname)

def f2():
    pname = current_process().name
    print('Starting process %s...' % pname)
    time.sleep(4)
    print('Exiting process %s...' % pname)

if __name__ == '__main__':
    p1 = Process(name='Worker 1', target=f1)
    p2 = Process(name='Worker 2', target=f2)
    p3 = Process(target=f1)

    p1.start()
    p2.start()
    p3.start()

    p1.join()
    p2.join()
    p3.join()
```

在这个例子中，我们有两个虚拟函数`f1()`和`f2()`，每个函数在睡眠一段指定的时间后打印执行该函数的进程的名称。在我们的主程序中，我们初始化了三个单独的进程。前两个我们分别命名为`Worker 1`和`Worker 2`，最后一个我们故意留空，以给它的名称默认值（即`'Process-3'`）。运行脚本后，您应该会得到类似以下的输出：

```py
> python example2.py
Starting process Worker 1...
Starting process Worker 2...
Starting process Process-3...
Exiting process Worker 1...
Exiting process Process-3...
Exiting process Worker 2...
```

我们可以看到`current_process()`成功帮助我们访问运行每个函数的正确进程，并且第三个进程默认分配了名称`Process-3`。在程序中跟踪运行进程的另一种方法是使用`os`模块查看各个进程的 ID。让我们看一个修改后的例子，在`Chapter06/example3.py`文件中，如下所示的代码：

```py
# Chapter06/example3.py

from multiprocessing import Process, current_process
import time
import os

def print_info(title):
    print(title)

    if hasattr(os, 'getppid'):
        print('Parent process ID: %s.' % str(os.getppid()))

    print('Current Process ID: %s.\n' % str(os.getpid()))

def f():
    print_info('Function f')

    pname = current_process().name
    print('Starting process %s...' % pname)
    time.sleep(1)
    print('Exiting process %s...' % pname)

if __name__ == '__main__':
    print_info('Main program')

    p = Process(target=f)
    p.start()
    p.join()

    print('Done.')
```

我们这个例子的主要焦点是`print_info()`函数，它使用`os.getpid()`和`os.getppid()`函数来使用进程 ID 标识当前进程。具体来说，`os.getpid()`返回当前进程的进程 ID，而`os.getppid()`（仅在 Unix 系统上可用）返回父进程的 ID。在运行脚本后，以下是我的输入：

```py
> python example3.py
Main program
Parent process ID: 14806.
Current Process ID: 29010.

Function f
Parent process ID: 29010.
Current Process ID: 29012.

Starting process Process-1...
Exiting process Process-1...
Done.
```

进程 ID 可能因系统而异，但它们的相对关系应该是相同的。特别是对于我的输出，我们可以看到，主 Python 程序的 ID 是`29010`，其父进程的 ID 是`14806`。使用**Activity Monitor**，我交叉检查了这个 ID，并将其连接到我的 Terminal 和 Bash 配置文件，这是有道理的，因为我是从我的 Terminal 运行这个 Python 脚本的。您可以在以下截图中看到 Activity Monitor 中显示的结果：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/392bb757-d08e-43ad-9287-211bd4750295.png)

使用 Activity Monitor 交叉检查 PID 的截图

除了主 Python 程序外，我们还在`f()`函数内调用了`print_info()`，其进程 ID 为`29012`。我们还可以看到运行`f()`函数的进程的父进程实际上是我们的主进程，其 ID 为`29010`。

# 等待进程

通常，我们希望在移动到程序的新部分之前等待所有并发进程完成执行。如前所述，`multiprocessing`模块中的`Process`类提供了`join()`方法，以实现等待进程完成任务并退出的方法。

然而，有时开发人员希望实现在后台运行并且不阻止主程序退出的进程。当主程序没有简单的方法告诉它是否适合在任何给定时间中断进程，或者在退出主程序而不完成工作进程不会影响最终结果时，通常会使用这个规范。

这些进程被称为**守护进程**。`Process`类还提供了一个简单的选项来通过`daemon`属性指定进程是否是守护进程，该属性接受一个布尔值。`daemon`属性的默认值是`False`，因此将其设置为`True`将使给定进程成为守护进程。让我们通过`Chapter06/example4.py`文件中的示例更详细地了解一下，如下所示：

```py
# Chapter06/example4.py

from multiprocessing import Process, current_process
import time

def f1():
    p = current_process()
    print('Starting process %s, ID %s...' % (p.name, p.pid))
    time.sleep(4)
    print('Exiting process %s, ID %s...' % (p.name, p.pid))

def f2():
    p = current_process()
    print('Starting process %s, ID %s...' % (p.name, p.pid))
    time.sleep(2)
    print('Exiting process %s, ID %s...' % (p.name, p.pid))

if __name__ == '__main__':
    p1 = Process(name='Worker 1', target=f1)
    p1.daemon = True
    p2 = Process(name='Worker 2', target=f2)

    p1.start()
    time.sleep(1)
    p2.start()
```

在这个例子中，我们有一个长时间运行的函数（由`f1()`表示，其中有 4 秒的休眠时间）和一个更快的函数（由`f2()`表示，其中只有 2 秒的休眠时间）。我们还有两个单独的进程，如下列表所示：

+   `p1`进程是一个守护进程，负责运行`f1()`。

+   `p2`进程是一个常规进程，负责运行`f2()`

在我们的主程序中，我们启动了这两个进程，但在程序结束时没有调用`join()`方法。由于`p1`是一个长时间运行的进程，它很可能在`p2`（两者中更快的进程）完成之前不会执行完。我们也知道`p1`是一个守护进程，所以我们的程序应该在它执行完之前退出。运行 Python 脚本后，你的输出应该类似于以下代码：

```py
> python example4.py
Starting process Worker 1, ID 33784...
Starting process Worker 2, ID 33788...
Exiting process Worker 2, ID 33788...
```

再次强调，即使当您自己运行脚本时，进程 ID 可能会有所不同，但输出的一般格式应该是相同的。正如我们所看到的，输出与我们讨论的内容一致：我们的主程序初始化并启动了`p1`和`p2`进程，并且在非守护进程退出后立即终止了程序，而不等待守护进程完成。

能够在不等待守护进程处理特定任务的情况下终止主程序的能力确实非常有用。然而，有时我们可能希望在退出之前等待守护进程一段指定的时间；这样，如果程序的规格允许等待进程执行一段时间，我们可以完成一些潜在的守护进程，而不是过早地终止它们。

守护进程和`multiprocessing`模块中的`join()`方法的结合可以帮助我们实现这种架构，特别是考虑到，虽然`join()`方法会无限期地阻塞程序执行（或者至少直到任务完成），但也可以传递一个超时参数来指定在退出之前等待进程的秒数。让我们考虑`Chapter06/example5.py`中前一个例子的修改版本。使用相同的`f1()`和`f2()`函数，在下面的脚本中，我们改变了主程序中处理守护进程的方式：

```py
# Chapter06/example5.py

if __name__ == '__main__':
    p1 = Process(name='Worker 1', target=f1)
    p1.daemon = True
    p2 = Process(name='Worker 2', target=f2)

    p1.start()
    time.sleep(1)
    p2.start()

    p1.join(1)
    print('Whether Worker 1 is still alive:', p1.is_alive())
    p2.join()
```

在这个例子中，我们不是在等待守护进程而是调用了`join()`方法来等待两个进程：我们允许`p1`在一秒内完成，同时阻塞主程序直到`p2`完成。如果`p1`在一秒后仍未执行完，主程序将继续执行其余部分并退出，这时我们会看到`p1`—或`Worker 1`—仍然活着。运行 Python 脚本后，你的输出应该类似于以下内容：

```py
> python example5.py
Starting process Worker 1, ID 36027...
Starting process Worker 2, ID 36030...
Whether Worker 1 is still alive: True
Exiting process Worker 2, ID 36030...
```

我们看到`p1`在等待一秒后确实还活着。

# 终止进程

`multiprocessing.Process`类中的`terminate()`方法提供了一种快速终止进程的方式。当调用该方法时，`Process`类或重写类中指定的退出处理程序、最终原因或类似资源将不会被执行。然而，终止进程的后代进程不会被终止。这些进程被称为**孤立进程**。

虽然有时终止进程会受到指责，但有时是必要的，因为某些进程与进程间通信资源（如锁、信号量、管道或队列）交互，强行停止这些进程可能导致这些资源变得损坏或对其他进程不可用。然而，如果程序中的进程从未与上述资源交互，`terminate()`方法是非常有用的，特别是如果一个进程看起来无响应或死锁。

使用`terminate()`方法时需要注意的一点是，即使在调用该方法后`Process`对象被有效地终止，也很重要的是你也要在对象上调用`join()`。由于`Process`对象的`alive`状态有时在`terminate()`方法后不会立即更新，这种做法给了后台系统一个机会来实现更新以反映进程的终止。

# 进程间通信

虽然锁是用于线程间通信的最常见的同步原语之一，但管道和队列是不同进程之间通信的主要方式。具体来说，它们提供了消息传递选项，以促进进程之间的通信——管道用于连接两个进程，队列用于多个生产者和消费者。

在本节中，我们将探讨队列的使用，特别是`multiprocessing`模块中的`Queue`类。`Queue`类的实现实际上既是线程安全的，也是进程安全的，我们已经在第三章中看到了队列的使用，*在 Python 中使用线程*。Python 中的所有可 pickle 对象都可以通过`Queue`对象传递；在本节中，我们将使用队列在进程之间来回传递消息。

使用消息队列进行进程间通信比使用共享资源更可取，因为如果某些进程在共享资源时处理不当并损坏了共享内存和资源，那么将会产生许多不良和不可预测的后果。然而，如果一个进程未能正确处理其消息，队列中的其他项目将保持完好。以下图表示了使用消息队列和共享资源（特别是内存）进行进程间通信的架构之间的差异：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/3b772c12-bf68-40c0-8b74-7c116d85794a.png)

使用消息队列和共享资源进行进程间通信的架构

# 单个工作进程的消息传递

在我们深入讨论 Python 中的示例代码之前，首先我们需要具体讨论如何在我们的多进程应用程序中使用`Queue`对象。假设我们有一个执行大量计算且不需要大量资源共享和通信的`worker`类。然而，这些工作者实例仍然需要能够在执行过程中不时接收信息。

这就是队列的使用方式：当我们将所有工作者放入队列时。同时，我们还将有一些初始化的进程，每个进程都将遍历该队列并处理一个工作者。如果一个进程已经执行完一个工作者，并且队列中仍有其他工作者，它将继续执行另一个工作者。回顾之前的图表，我们可以看到有两个单独的进程不断地从队列中取出并执行消息。

从`Queue`对象中，我们将使用以下列表中显示的两种主要方法：

+   `get()`: 这个方法返回调用的`Queue`对象中的下一个项目

+   `put()`: 这个方法将传递给它的参数作为额外项目添加到调用的`Queue`对象中

让我们看一个示例脚本，展示了在 Python 中使用队列。转到并打开`Chapter06/example6.py`文件，如下面的代码所示：

```py
# Chapter06/example6.py

import multiprocessing

class MyWorker():
    def __init__(self, x):
        self.x = x

    def process(self):
        pname = multiprocessing.current_process().name
        print('Starting process %s for number %i...' % (pname, self.x))

def work(q):
    worker = q.get()
    worker.process()

if __name__ == '__main__':
    my_queue = multiprocessing.Queue()

    p = multiprocessing.Process(target=work, args=(my_queue,))
    p.start()

    my_queue.put(MyWorker(10))

    my_queue.close()
    my_queue.join_thread()
    p.join()

    print('Done.')
```

在此脚本中，我们有一个`MyWorker`类，它接受一个`x`参数并对其进行计算（目前只会打印出数字）。在我们的主函数中，我们从`multiprocessing`模块初始化了一个`Queue`对象，并添加了一个带有数字`10`的`MyWorker`对象。我们还有`work()`函数，当被调用时，将从队列中获取第一个项目并处理它。最后，我们有一个任务是调用`work()`函数的进程。

该结构旨在将消息传递给一个单一进程，即一个`MyWorker`对象。然后主程序等待进程完成执行。运行脚本后，您的输出应类似于以下内容：

```py
> python example6.py
Starting process Process-1 for number 10...
Done.
```

# 多个工作者之间的消息传递

如前所述，我们的目标是有一个结构，其中有几个进程不断地执行队列中的工作者，并且如果一个进程完成执行一个工作者，那么它将继续执行另一个。为此，我们将利用`Queue`的一个子类`JoinableQueue`，它将提供额外的`task_done()`和`join()`方法，如下列表所述：

+   `task_done()`: 这个方法告诉程序调用的`JoinableQueue`对象已经完成

+   `join()`: 这个方法阻塞，直到调用的`JoinableQueue`对象中的所有项目都已被处理

现在，这里的目标是有一个`JoinableQueue`对象，其中包含所有要执行的任务，我们将其称为任务队列，并且有一些进程。只要任务队列中有项目（消息），进程就会轮流执行这些项目。我们还将有一个`Queue`对象来存储从进程返回的所有结果，我们将其称为结果队列。

转到`Chapter06/example7.py`文件，并查看`Consumer`类和`Task`类，如下面的代码所示：

```py
# Chapter06/example7.py

from math import sqrt
import multiprocessing

class Consumer(multiprocessing.Process):

    def __init__(self, task_queue, result_queue):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue

    def run(self):
        pname = self.name

        while not self.task_queue.empty():

            temp_task = self.task_queue.get()

            print('%s processing task: %s' % (pname, temp_task))

            answer = temp_task.process()
            self.task_queue.task_done()
            self.result_queue.put(answer)

class Task():
    def __init__(self, x):
        self.x = x

    def process(self):
        if self.x < 2:
            return '%i is not a prime number.' % self.x

        if self.x == 2:
            return '%i is a prime number.' % self.x

        if self.x % 2 == 0:
            return '%i is not a prime number.' % self.x

        limit = int(sqrt(self.x)) + 1
        for i in range(3, limit, 2):
            if self.x % i == 0:
                return '%i is not a prime number.' % self.x

        return '%i is a prime number.' % self.x

    def __str__(self):
        return 'Checking if %i is a prime or not.' % self.x
```

`Consumer`类是`multiprocessing.Process`类的一个重写子类，是我们的处理逻辑，它接受一个任务队列和一个结果队列。每个`Consumer`对象启动时，将获取其任务队列中的下一个项目，执行它，最后调用`task_done()`并将返回的结果放入其结果队列。任务队列中的每个项目依次由`Task`类表示，其主要功能是对其`x`参数进行素数检查。当`Consumer`类的一个实例与`Task`类的一个实例交互时，它还会打印出一个帮助消息，以便我们轻松跟踪哪个消费者正在执行哪个任务。

让我们继续考虑我们的主程序，如下面的代码所示：

```py
# Chapter06/example7.py

if __name__ == '__main__':
    tasks = multiprocessing.JoinableQueue()
    results = multiprocessing.Queue()

    # spawning consumers with respect to the
    # number cores available in the system
    n_consumers = multiprocessing.cpu_count()
    print('Spawning %i consumers...' % n_consumers)
    consumers = [Consumer(tasks, results) for i in range(n_consumers)]
    for consumer in consumers:
        consumer.start()

    # enqueueing jobs
    my_input = [2, 36, 101, 193, 323, 513, 1327, 100000, 9999999, 433785907]
    for item in my_input:
        tasks.put(Task(item))

    tasks.join()

    for i in range(len(my_input)):
        temp_result = results.get()
        print('Result:', temp_result)

    print('Done.')
```

正如我们之前所说，我们在主程序中创建了一个任务队列和一个结果队列。我们还创建了一个`Consumer`对象的列表，并启动了它们所有；创建的进程数量与系统中可用的 CPU 数量相对应。接下来，从一个需要从`Task`类中进行大量计算的输入列表中，我们用每个输入初始化一个`Task`对象，并将它们全部放入任务队列。此时，我们的进程——我们的`Consumer`对象——将开始执行这些任务。

最后，在我们的主程序的末尾，我们调用`join()`在我们的任务队列上，以确保所有项目都已执行，并通过循环遍历我们的结果队列打印出结果。运行脚本后，你的输出应该类似于以下内容：

```py
> python example7.py
Spawning 4 consumers...
Consumer-3 processing task: Checking if 2 is a prime or not.
Consumer-2 processing task: Checking if 36 is a prime or not.
Consumer-3 processing task: Checking if 101 is a prime or not.
Consumer-2 processing task: Checking if 193 is a prime or not.
Consumer-3 processing task: Checking if 323 is a prime or not.
Consumer-2 processing task: Checking if 1327 is a prime or not.
Consumer-3 processing task: Checking if 100000 is a prime or not.
Consumer-4 processing task: Checking if 513 is a prime or not.
Consumer-3 processing task: Checking if 9999999 is a prime or not.
Consumer-2 processing task: Checking if 433785907 is a prime or not.
Result: 2 is a prime number.
Result: 36 is not a prime number.
Result: 193 is a prime number.
Result: 101 is a prime number.
Result: 323 is not a prime number.
Result: 1327 is a prime number.
Result: 100000 is not a prime number.
Result: 9999999 is not a prime number.
Result: 513 is not a prime number.
Result: 433785907 is a prime number.
Done.
```

一切似乎都在运行，但是如果我们仔细看一下我们的进程打印出来的消息，我们会注意到大多数任务是由`Consumer-2`或`Consumer-3`执行的，而`Consumer-4`只执行了一个任务，而`Consumer-1`则未执行任何任务。这里发生了什么？

基本上，当我们的一个消费者——比如`Consumer-3`——完成执行一个任务后，它会立即尝试寻找另一个任务来执行。大多数情况下，它会优先于其他消费者，因为它已经被主程序运行。因此，虽然`Consumer-2`和`Consumer-3`不断完成它们的任务执行并拾取其他任务来执行，`Consumer-4`只能“挤”自己进来一次，而`Consumer-1`则根本无法做到这一点。

当一遍又一遍地运行脚本时，你会注意到一个类似的趋势：大多数任务只由一个或两个消费者执行，而其他消费者未能做到这一点。对我们来说，这种情况是不可取的，因为程序没有利用在程序开始时创建的所有可用进程。

为了解决这个问题，已经开发了一种技术，用于阻止消费者立即从任务队列中取下下一个项目，称为**毒丸**。其想法是，在设置任务队列中的真实任务之后，我们还添加包含“停止”值的虚拟任务，并且当前消费者将保持并允许其他消费者先获取任务队列中的下一个项目；因此得名“毒丸”。

为了实现这一技术，我们需要在主程序的特殊对象中添加我们的`tasks`值，每个消费者一个。此外，在我们的`Consumer`类中，还需要实现处理这些特殊对象的逻辑。让我们看一下`example8.py`文件（前一个示例的修改版本，包含毒丸技术的实现），特别是`Consumer`类和主程序，如下面的代码所示：

```py
# Chapter06/example8.py

class Consumer(multiprocessing.Process):

    def __init__(self, task_queue, result_queue):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue

    def run(self):
        pname = self.name

        while True:
            temp_task = self.task_queue.get()

            if temp_task is None:
                print('Exiting %s...' % pname)
                self.task_queue.task_done()
                break

            print('%s processing task: %s' % (pname, temp_task))

            answer = temp_task.process()
            self.task_queue.task_done()
            self.result_queue.put(answer)

class Task():
    def __init__(self, x):
        self.x = x

    def process(self):
        if self.x < 2:
            return '%i is not a prime number.' % self.x

        if self.x == 2:
            return '%i is a prime number.' % self.x

        if self.x % 2 == 0:
            return '%i is not a prime number.' % self.x

        limit = int(sqrt(self.x)) + 1
        for i in range(3, limit, 2):
            if self.x % i == 0:
                return '%i is not a prime number.' % self.x

        return '%i is a prime number.' % self.x

    def __str__(self):
        return 'Checking if %i is a prime or not.' % self.x

if __name__ == '__main__':

    tasks = multiprocessing.JoinableQueue()
    results = multiprocessing.Queue()

    # spawning consumers with respect to the
    # number cores available in the system
    n_consumers = multiprocessing.cpu_count()
    print('Spawning %i consumers...' % n_consumers)
    consumers = [Consumer(tasks, results) for i in range(n_consumers)]
    for consumer in consumers:
        consumer.start()

    # enqueueing jobs
    my_input = [2, 36, 101, 193, 323, 513, 1327, 100000, 9999999, 433785907]
    for item in my_input:
        tasks.put(Task(item))

    for i in range(n_consumers):
        tasks.put(None)

    tasks.join()

    for i in range(len(my_input)):
        temp_result = results.get()
        print('Result:', temp_result)

    print('Done.')
```

`Task`类与我们之前的示例相同。我们可以看到我们的毒丸是`None`值：在主程序中，我们向任务队列中添加了与我们生成的消费者数量相等的`None`值；在`Consumer`类中，如果要执行的当前任务包含值`None`，那么该类对象将打印出指示毒丸的消息，调用`task_done()`并退出。

运行脚本；你的输出应该类似于以下内容：

```py
> python example8.py
Spawning 4 consumers...
Consumer-1 processing task: Checking if 2 is a prime or not.
Consumer-2 processing task: Checking if 36 is a prime or not.
Consumer-3 processing task: Checking if 101 is a prime or not.
Consumer-4 processing task: Checking if 193 is a prime or not.
Consumer-1 processing task: Checking if 323 is a prime or not.
Consumer-2 processing task: Checking if 513 is a prime or not.
Consumer-3 processing task: Checking if 1327 is a prime or not.
Consumer-1 processing task: Checking if 100000 is a prime or not.
Consumer-2 processing task: Checking if 9999999 is a prime or not.
Consumer-3 processing task: Checking if 433785907 is a prime or not.
Exiting Consumer-1...
Exiting Consumer-2...
Exiting Consumer-4...
Exiting Consumer-3...
Result: 2 is a prime number.
Result: 36 is not a prime number.
Result: 323 is not a prime number.
Result: 101 is a prime number.
Result: 513 is not a prime number.
Result: 1327 is a prime number.
Result: 100000 is not a prime number.
Result: 9999999 is not a prime number.
Result: 193 is a prime number.
Result: 433785907 is a prime number.
Done.
```

这一次，除了看到毒丸消息被打印出来之外，输出还显示了在哪个消费者执行了哪个任务方面的显着改善分布。

# 摘要

在计算机科学领域，进程是操作系统正在执行的特定计算机程序或软件的实例。进程包含程序代码及其当前活动和与其他实体的交互。在同一个进程中可以实现多个线程来访问和共享内存或其他资源，而不同的进程不以这种方式进行交互。

在并发和并行的背景下，多进程指的是从操作系统中执行多个并发进程，其中每个进程在单独的 CPU 上执行，而不是在任何给定时间执行单个进程。Python 中的`multiprocessing`模块提供了一个强大而灵活的 API，用于生成和管理多进程应用程序。它还允许通过`Queue`类进行复杂的进程间通信技术。

在下一章中，我们将讨论 Python 的更高级功能——归约操作——以及它在多进程编程中的支持。

# 问题

+   什么是进程？进程和线程之间的核心区别是什么？

+   什么是多进程？多进程和多线程之间的核心区别是什么？

+   `multiprocessing`模块提供了哪些 API 选项？

+   `Process`类和`Pool`类在`multiprocessing`模块中的核心区别是什么？

+   在 Python 程序中确定当前进程的选项有哪些？

+   在多进程程序中，守护进程是什么？它们在等待进程方面有什么目的？

+   如何终止一个进程？为什么有时终止进程是可以接受的？

+   在 Python 中促进进程间通信的一种方式是什么？

# 进一步阅读

有关更多信息，您可以参考以下链接：

+   *Python 并行编程食谱*，作者 Giancarlo Zaccone，Packt Publishing Ltd（2015 年）。

+   “学习 Python 并发：构建高效、健壮和并发的应用程序”，Elliot Forbes（2017 年）。

+   Python 本周模块。“进程间通信”（[pymotw.com/2/multiprocessing/communication.html](https://pymotw.com/2/multiprocessing/communication.html)）。这包含了您可以用来识别当前进程的函数。


# 第七章：进程中的减少运算符

减少运算符的概念——其中数组的许多或所有元素被减少为一个单一结果——与并发和并行编程密切相关。具体来说，由于运算符的结合和交换性质，可以应用并发和并行性来大大提高它们的执行时间。

本章讨论了从程序员和开发人员的角度设计和编写减少运算符的理论并发方法。从这里开始，本章还将建立与可以以类似方式使用并发性解决的类似问题的联系。

本章将涵盖以下主题：

+   计算机科学中的减少运算符的概念

+   减少运算符的交换和结合属性，以及并发可以应用的原因

+   如何识别与减少运算符等价的问题，以及如何在这种情况下应用并发编程

# 技术要求

以下是本章的先决条件列表：

+   您的计算机必须安装 Python 3

+   从[`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python)下载 GitHub 存储库

+   在本章中，我们将使用名为`Chapter07`的子文件夹

+   查看以下视频以查看代码实际运行情况：[`bit.ly/2TD5odl`](http://bit.ly/2TD5odl)

# 减少运算符的概念

作为经验丰富的程序员，您无疑遇到过需要计算数组中所有数字的和或乘积，或者计算将`AND`运算符应用于数组的所有布尔元素以查看该数组中是否存在任何假值的情况。这些被称为**减少运算符**，它们接受一组或一个元素数组，并执行某种形式的计算，以返回一个单一的结果。

# 减少运算符的属性

并非每个数学或计算机科学运算符都是减少运算符。事实上，即使一个运算符能够将一个元素数组减少为一个单一值，也不能保证它是一个减少运算符。如果运算符满足以下条件，则运算符是减少运算符：

+   操作员可以将一个元素数组减少为一个标量值

+   最终结果（标量值）必须通过创建和计算部分任务来获得

第一个条件表明了“减少运算符”这个短语，因为输入数组的所有元素都必须被组合并减少为一个单一的值。然而，第二个条件本质上是关于并发和并行性。它要求任何减少运算符的计算都能够被分解为较小的部分计算。

首先，让我们考虑最常见的减少运算符之一：加法。例如，考虑输入数组`[1, 4, 8, 3, 2, 5]`的元素之和如下：

```py
1 + 4 + 8 + 3 + 2 + 5
= ((((1 + 4) + 8) + 3) + 2) + 5
= (((5 + 8) + 3) + 2) + 5
= ((13 + 3) + 2) + 5
= (16 + 2) + 5
= 18 + 5
= 23
```

在前面的计算中，我们按顺序将数组中的数字减少到它们的总和`23`。换句话说，我们从数组的开头到结尾遍历了每个元素，并添加了当前的总和。现在，我们知道加法是一个可交换和可结合的运算符，这意味着：*a + b = b + a* 和 *(a + b) + c = a + (b + c)*。

因此，我们可以通过将前面的计算分解为更高效的方式来进行更高效的计算：

```py
1 + 4 + 8 + 3 + 2 + 5
= ((1 + 4) + (8 + 3)) + (2 + 5)
= (5 + 11) + 7
= 16 + 7
= 23
```

这种技术是应用并发和并行（特别是多进程）到减少运算符的核心。通过将整个任务分解为较小的子任务，多个进程可以同时执行这些小计算，整个系统可以更快地得出结果。

出于同样的原因，交换性和结合性属性被认为等同于我们之前讨论的减法运算符的要求。换句话说，运算符 ![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/bbe67805-00e5-4140-b1f5-532e3c676f83.png) 是一个具有交换性和结合性的减法运算符。具体如下：

+   交换性：*a ![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/1f978d15-59d3-4b54-90f2-d6e8fb68d558.png) b = b ![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/4d6c15e7-49c7-4ce9-9c36-f989c275b760.png) a*

+   结合性：*(a ![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/8ad90b0c-03cd-429a-8561-f8a1b19082a7.png) b) ![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/a00626a1-0076-4aa4-94a7-e01e50e9e8ad.png) c = a ![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/bd4efb4b-bd8a-4177-8b48-0bb94835babb.png) (b ![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/f73dbfc9-7675-46b9-9b07-ae58721000a3.png) c)*

这里的 *a*，*b* 和 *c* 是输入数组的元素。

因此，如果一个运算符是减法运算符，它必须是交换性和结合性的，因此具有将大任务分解为更小、更易管理的子任务的能力，可以使用多进程以更有效的方式进行计算。

# 示例和非示例

到目前为止，我们已经看到加法是减法运算符的一个例子。要将加法作为减法运算符执行，我们首先将输入数组的元素分成两组，每组都是我们的子任务之一。然后我们对每组进行加法运算，取得每组的加法结果，再将它们分成两组。

这个过程一直持续到得到一个单一的数字。这个过程遵循一个叫做二叉树减法的模型，它利用两个元素组成子任务：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/7cad13ee-22a1-4512-8731-75e2c3dbaa52.png)

二叉树减法加法图

在前面的例子中，对数组 [1, 4, 8, 3, 2, 5] 进行分组（1 和 4，8 和 3，2 和 5），我们使用三个独立的过程将数字对相加。然后我们得到数组 [5, 11, 7]，我们用一个过程得到 [16, 7]，再用另一个过程最终得到 23。因此，使用三个或更多个 CPU，六个元素的加法运算可以在 log[2]6 = 3 步内完成，而不是顺序加法的五步。

其他常见的减法运算符示例包括乘法和逻辑 AND。例如，使用乘法作为减法运算符对相同的数字数组 [1, 4, 8, 3, 2, 5] 进行减法运算如下：

```py
1 x 4 x 8 x 3 x 2 x 5
= ((1 x 4) x (8 x 3)) x (2 x 5)
= (4 x 24) x 10
= 96 x 10
= 960
```

例如，对布尔值数组进行减法（`True`，`False`，`False`，`True`），使用逻辑 `AND` 运算符，我们可以这样做：

```py
True AND False AND False AND True
= (True AND False) AND (False AND True)
= False AND False
= False
```

减法运算符的非示例是幂函数，因为改变计算顺序会改变最终结果（即，该函数不是交换性的）。例如，顺序减法数组 `[2, 1, 2]` 将给出以下结果：

```py
2 ^ 1 ^ 2 = 2 ^ (1 ^ 2) = 2 ^ 1 = 2
```

如果我们改变操作顺序如下：

```py
(2 ^ 1) ^ 2 = 2 ^ 2 = 4
```

我们将得到一个不同的值。因此，幂函数不是一个减法运算。

# Python 中的示例实现

正如我们之前提到的，由于它们的交换性和结合性属性，减法运算符可以独立创建和处理它们的部分任务，这就是并发可以应用的地方。要真正理解减法运算符如何利用并发，让我们尝试从头开始实现一个并发的多进程减法运算符，具体来说是加法运算符。

与前一章中看到的类似，在这个例子中，我们将使用任务队列和结果队列来促进进程间通信。具体来说，程序将把输入数组中的所有数字存储在任务队列中作为单独的任务。每当我们的消费者（单独的进程）执行时，它将在任务队列上调用 `get()` **两次** 来获取两个任务数字（除了一些边缘情况，任务队列中没有或只剩下一个数字），将它们相加，并将结果放入结果队列。

与在上一节中所做的一样，通过迭代任务队列一次并将添加的任务数字对放入结果队列后，输入数组中的元素数量将减少一半。例如，输入数组`[1, 4, 8, 3, 2, 5]`将变为`[5, 11, 7]`。

现在，我们的程序将把新的任务队列分配为结果队列（因此，在这个例子中，`[5, 11, 7]`现在是新的任务队列），我们的进程将继续遍历它并将数字对相加以生成新的结果队列，这将成为下一个任务队列。这个过程重复进行，直到结果队列只包含一个元素，因为我们知道这个单个数字是原始输入数组中数字的总和。

下面的图表显示了处理输入数组`[1, 4, 8, 3, 2, 5]`的每次迭代中任务队列和结果队列的变化；当结果队列只包含一个数字（`23`）时，进程停止：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/56cfb844-7f33-473a-9489-38b1f4cb11cd.png)

多进程加法运算符的示例图表

让我们来看一下`Chapter07/example1.py`文件中的`ReductionConsumer`类：

```py
# Chapter07/example1.py

class ReductionConsumer(multiprocessing.Process):

    def __init__(self, task_queue, result_queue):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue

    def run(self):
        pname = self.name
        print('Using process %s...' % pname)

        while True:
            num1 = self.task_queue.get()
            if num1 is None:
                print('Exiting process %s.' % pname)
                self.task_queue.task_done()
                break

            self.task_queue.task_done()
            num2 = self.task_queue.get()
            if num2 is None:
                print('Reaching the end with process %s and number 
                      %i.' % (pname, num1))
                self.task_queue.task_done()
                self.result_queue.put(num1)
                break

            print('Running process %s on numbers %i and %i.' % (
                    pname, num1, num2))
            self.task_queue.task_done()
            self.result_queue.put(num1 + num2)
```

我们通过重写`multiprocessing.Process`类来实现`ReductionConsumer`类。这个消费者类在初始化时接受一个任务队列和一个结果队列，并处理程序的消费者进程逻辑，调用任务队列上的`get()`两次来从队列中获取两个数字，并将它们的和添加到结果队列中。

在执行这个过程的同时，`ReductionConsumer`类还处理了任务队列中没有或只剩下一个数字的情况（也就是说，当`num1`或`num2`变量为`None`时，这是我们在上一章中知道的用来表示毒丸的方式）。

另外，回想一下，`multiprocessing`模块的`JoinableQueue`类用于实现我们的任务队列，并且在每次调用`get()`函数后需要调用`task_done()`函数，否则我们稍后将在任务队列上调用的`join()`函数将无限期地阻塞。因此，在消费者进程调用`get()`两次的情况下，重要的是在当前任务队列上调用两次`task_done()`，而当我们只调用一次`get()`（当第一个数字是毒丸时），那么我们应该只调用一次`task_done()`。这是在处理多进程通信的程序时需要考虑的更复杂的问题之一。

为了处理和协调不同的消费者进程，以及在每次迭代后操作任务队列和结果队列，我们有一个名为`reduce_sum()`的单独函数：

```py
def reduce_sum(array):
    tasks = multiprocessing.JoinableQueue()
    results = multiprocessing.JoinableQueue()
    result_size = len(array)

    n_consumers = multiprocessing.cpu_count()

    for item in array:
        results.put(item)

    while result_size > 1:
        tasks = results
        results = multiprocessing.JoinableQueue()

        consumers = [ReductionConsumer(tasks, results) 
                     for i in range(n_consumers)]
        for consumer in consumers:
            consumer.start()

        for i in range(n_consumers):
            tasks.put(None)

        tasks.join()
        result_size = result_size // 2 + (result_size % 2)
        #print('-' * 40)

    return results.get()
```

这个函数接受一个 Python 数字列表来计算其元素的总和。除了任务队列和结果队列之外，该函数还跟踪另一个名为`result_size`的变量，该变量表示当前结果队列中的元素数量。

在初始化其基本变量之后，该函数在一个 while 循环中生成其消费者进程以减少当前任务队列。正如我们之前讨论的，在 while 循环的每次迭代中，任务队列中的元素会成对相加，然后将添加的结果存储在结果队列中。之后，任务队列将接管该结果队列的元素，并向队列中添加额外的`None`值以实现毒丸技术。

在每次迭代中，还会初始化一个新的空结果队列作为`JoinableQueue`对象——这与我们在上一章中用于结果队列的`multiprocessing.Queue`类不同，因为我们将在下一次迭代开始时分配`tasks = results`，任务队列需要是一个`JoinableQueue`对象。

我们还在每次迭代结束时更新`result_size`的值，通过`result_size = result_size // 2 + (result_size % 2)`。这里需要注意的是，虽然`JoinableQueue`类的`qsize()`方法是跟踪其对象的长度（即`JoinableQueue`对象中的元素数量）的一种潜在方法，但由于各种原因，这种方法通常被认为是不可靠的，甚至在 Unix 操作系统中也没有实现。

由于我们可以轻松预测输入数组中剩余数字的数量在每次迭代后的变化（如果是偶数，则减半，否则通过整数除法减半，然后加`1`到结果），我们可以使用一个名为`result_size`的单独变量来跟踪该数字。

至于我们这个例子的主程序，我们只需将 Python 列表传递给`reduce_sum()`函数。在这里，我们正在将 0 到 19 的数字相加：

```py
my_array = [i for i in range(20)]

result = reduce_sum(my_array)
print('Final result: %i.' % result)
```

运行脚本后，您的输出应该类似于以下内容：

```py
> python example1.py
Using process ReductionConsumer-1...
Running process ReductionConsumer-1 on numbers 0 and 1.
Using process ReductionConsumer-2...
Running process ReductionConsumer-2 on numbers 2 and 3.
Using process ReductionConsumer-3...

[...Truncated for readability..]

Exiting process ReductionConsumer-17.
Exiting process ReductionConsumer-18.
Exiting process ReductionConsumer-19.
Using process ReductionConsumer-20...
Exiting process ReductionConsumer-20.
Final result: 190.
```

# 并发缩减运算符的现实应用

缩减运算符处理其数据的交际和结合性质使得运算符的子任务能够独立处理，并且与并发和并行性高度相关。因此，并发编程中的各种主题可以与缩减运算符相关，并且通过应用缩减运算符的相同原则，可以使涉及这些主题的问题更加直观和高效。

正如我们所见，加法和乘法运算符都是缩减运算符。更一般地说，通常涉及交际和结合运算符的数值计算问题是应用并发和并行性的主要候选对象。这实际上是 Python 中最著名的、可能是最常用的模块之一—NumPy 的真实情况，其代码被实现为尽可能可并行化。

此外，将逻辑运算符 AND、OR 或 XOR 应用于布尔值数组的方式与缩减运算符的工作方式相同。一些并发位缩减运算符的真实应用包括以下内容：

+   有限状态机通常在处理逻辑门时利用逻辑运算符。有限状态机可以在硬件结构和软件设计中找到。

+   跨套接字/端口的通信通常涉及奇偶校验位和停止位来检查数据错误，或者流控制算法。这些技术利用单个字节的逻辑值通过逻辑运算符处理信息。

+   压缩和加密技术严重依赖于位算法。

# 总结

在 Python 中实现多进程缩减运算符时需要仔细考虑，特别是如果程序利用任务队列和结果队列来促进消费者进程之间的通信。

各种现实世界问题的操作类似于缩减运算符，并且对于这些问题使用并发和并行性可以极大地提高程序处理它们的效率和生产力。因此，重要的是能够识别这些问题，并与缩减运算符的概念联系起来来实现它们的解决方案。

在下一章中，我们将讨论 Python 中多进程程序的一个特定的现实应用：图像处理。我们将介绍图像处理背后的基本思想，以及并发（特别是多进程）如何应用于图像处理应用程序。

# 问题

+   什么是缩减运算符？必须满足什么条件才能使运算符成为缩减运算符？

+   缩减运算符具有与所需条件等价的什么属性？

+   缩减运算符与并发编程之间的联系是什么？

+   在使用 Python 进行进程间通信的多处理程序中，必须考虑哪些因素？

+   并发减少运算符的一些真实应用是什么？

# 进一步阅读

更多信息，请参考以下链接：

+   *Python 并行编程食谱*，Giancarlo Zaccone，Packt Publishing Ltd，2015

+   *学习 Python 并发：构建高效、健壮和并发的应用程序*，Elliot Forbes (2017)

+   *OpenMP 中的并行编程*，Morgan Kaufmann，Chandra, Rohit (2001)

+   *并行多核架构基础*，Yan Solihin (2016)，CRC Press


# 第八章：并发图像处理

本章分析了通过并发编程，特别是多进程处理图像的处理和操作过程。由于图像是相互独立处理的，因此并发编程可以显著加快图像处理的速度。本章讨论了图像处理技术背后的基础知识，说明了并发编程提供的改进，并最终总结了图像处理应用中使用的一些最佳实践。

本章将涵盖以下主题：

+   图像处理背后的理念和一些基本的图像处理技术

+   如何将并发应用于图像处理，以及如何分析它提供的改进

+   并发图像处理的最佳实践

# 技术要求

以下是本章的先决条件列表：

+   你必须在计算机上安装 Python 3

+   您必须为您的 Python 3 发行版安装 OpenCV 和 NumPy

+   从[`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python)下载 GitHub 存储库

+   在本章中，我们将使用名为`Chapter08`的子文件夹

+   查看以下视频以查看代码实际运行情况：[`bit.ly/2R8ydN8`](http://bit.ly/2R8ydN8)

# 图像处理基础知识

数字/计算图像处理（我们将在此后简称为图像处理）在现代时代变得如此受欢迎，以至于它存在于我们日常生活的许多方面。当您使用不同的滤镜使用相机或手机拍照时，涉及图像处理和操作，或者使用 Adobe Photoshop 等高级图像编辑软件时，甚至只是使用 Microsoft Paint 编辑图像时。

图像处理中使用的许多技术和算法是在 1960 年代初为各种目的开发的，如医学成像、卫星图像分析、字符识别等。然而，这些图像处理技术需要大量的计算能力，当时可用的计算机设备无法满足快速计算的需求，这减缓了图像处理的使用。

快进到未来，在那里拥有快速、多核处理器的强大计算机被开发出来，图像处理技术因此变得更加易于访问，并且图像处理的研究显著增加。如今，正在积极开发和研究许多图像处理应用，包括模式识别、分类、特征提取等。利用并发和并行编程的特定图像处理技术，否则将极其耗时的包括隐马尔可夫模型、独立成分分析，甚至新兴的神经网络模型：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/619ce7a1-3a6b-467e-ba32-3488783b8719.png)

图像处理的一个示例用途：灰度处理

# Python 作为图像处理工具

正如我们在本书中多次提到的，Python 编程语言正在成为最受欢迎的编程语言。这在计算图像处理领域尤其如此，大多数时候需要快速原型设计和设计，以及显著的自动化能力。

正如我们将在下一节中发现的那样，数字图像以二维和三维矩阵表示，以便计算机可以轻松处理它们。因此，大多数时候，数字图像处理涉及矩阵计算。多个 Python 库和模块不仅提供了高效的矩阵计算选项，而且与处理图像读取/写入的其他库无缝交互。

正如我们已经知道的，自动化任务并使其并发都是 Python 的强项。这使得 Python 成为实现图像处理应用程序的首选候选。在本章中，我们将使用两个主要的 Python 库：**OpenCV**（代表**开源计算机视觉**），这是一个提供 C++、Java 和 Python 图像处理和计算机视觉选项的库，以及 NumPy，正如我们所知，它是最受欢迎的 Python 模块之一，可以执行高效和可并行化的数值计算。

# 安装 OpenCV 和 NumPy

要使用`pip`软件包管理器为您的 Python 发行版安装 NumPy，请运行以下命令：

```py
pip install numpy
```

然而，如果您使用 Anaconda/Miniconda 来管理您的软件包，请运行以下命令：

```py
conda install numpy
```

安装 OpenCV 可能更复杂，这取决于您的操作系统。最简单的选择是使用 Anaconda 处理安装过程，按照此指南进行操作（[`anaconda.org/conda-forge/opencv`](https://anaconda.org/conda-forge/opencv)），在安装 Anaconda（[`www.anaconda.com/download/`](https://www.anaconda.com/download/)）后作为您的主要 Python 包管理器。然而，如果您没有使用 Anaconda，安装 OpenCV 的主要选项是按照其官方文档指南进行操作，该指南可以在[`docs.opencv.org/master/df/d65/tutorial_table_of_content_introduction.html`](https://docs.opencv.org/master/df/d65/tutorial_table_of_content_introduction.html)找到。成功安装 OpenCV 后，打开 Python 解释器并尝试导入库，如下所示：

```py
>>> import cv2
>>> print(cv2.__version__)
3.1.0
```

我们使用名称`cv2`导入 OpenCV，这是 Python 中 OpenCV 的库别名。成功消息表示已下载的 OpenCV 库版本（3.1.0）。

# 计算机图像基础

在我们开始处理和操作数字图像文件之前，我们首先需要讨论这些文件的基础知识，以及计算机如何解释其中的数据。具体来说，我们需要了解图像文件中单个像素的颜色和坐标数据是如何表示的，以及如何使用 Python 提取它。

# RGB 值

RGB 值是数字表示颜色的基础。**红**、**绿**和**蓝**代表**RGB**值，这是因为所有颜色都可以通过红、绿和蓝的特定组合生成。因此，RGB 值是由三个整数构成的元组，每个整数的取值范围从 0（表示没有颜色）到 255（表示该特定颜色的最深色调）。

例如，红色对应元组（255, 0, 0）；在元组中，只有红色的最高值，其他颜色没有值，因此整个元组代表纯红色。类似地，蓝色由（0, 0, 255）表示，绿色由（0, 255, 0）表示。黄色是将红色和绿色混合相等量得到的结果，因此由（255, 255, 0）表示（最大量的红色和绿色，没有蓝色）。白色是三种颜色的组合，为（255, 255, 255），而黑色是白色的相反，因此缺乏所有颜色，表示为（0, 0, 0）。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/0bd643f3-32bd-4e8f-8171-1e753e515611.png)

RGB 值基础

# 像素和图像文件

因此，RGB 值表示特定颜色，但我们如何将其与计算机图像连接起来呢？如果我们在计算机上查看图像并尝试尽可能放大，我们会观察到随着放大的深入，图像将开始分解为越来越可辨认的彩色方块——这些方块称为像素，在计算机显示器或数字图像中是最小的颜色单位：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/1f25d8d5-f3a4-46df-a447-c33daa714174.png)

数字图像中的像素示例

以表格格式排列的一组不同像素（像素的行和列）组成了一幅计算机图像。每个像素，反过来，是一个 RGB 值；换句话说，一个像素是一个由三个整数组成的元组。这意味着计算机图像只是一个由元组组成的二维数组，其大小对应于图像的尺寸。例如，一个 128 x 128 的图像有 128 行和 128 列的 RGB 元组作为其数据。

# 图像内的坐标

与二维数组的索引类似，数字图像像素的坐标是一对整数，表示该像素的*x*和*y*坐标；*x*坐标表示像素沿水平轴从左侧开始的位置，*y*坐标表示像素沿垂直轴从顶部开始的位置。

在这里，我们可以看到在图像处理时通常涉及到大量的计算数值过程，因为每个图像都是一个整数元组的矩阵。这也表明，借助 NumPy 库和并发编程，我们可以在 Python 图像处理应用程序的执行时间上实现显著的改进。

遵循 NumPy 中对二维数组进行索引的惯例，像素的位置仍然是一对整数，但第一个数字表示包含像素的行的索引，对应于*y*坐标，同样，第二个数字表示像素的*x*坐标。

# OpenCV API

在 Python 中有许多方法来读取、处理图像和显示数字图像文件。然而，OpenCV 提供了一些最简单和最直观的 API 来实现这一点。关于 OpenCV 的一个重要事项是，当解释其图像时，它实际上将 RGB 值反转为 BGR 值，因此在图像矩阵中，元组将表示蓝色、绿色和红色，而不是红色、绿色和蓝色。

让我们看一个在 Python 中与 OpenCV 交互的例子。让我们来看一下`Chapter08/example1.py`文件：

```py
# Chapter08/example1.py

import cv2

im = cv2.imread('input/ship.jpg')
cv2.imshow('Test', im)
cv2.waitKey(0) # press any key to move forward here

print(im)
print('Type:', type(im))
print('Shape:', im.shape)
print('Top-left pixel:', im[0, 0])

print('Done.')
```

在这个脚本中使用了一些 OpenCV 的方法，我们需要讨论一下：

+   `cv2.imread()`: 这个方法接受一个图像文件的路径（常见的文件扩展名包括`.jpeg`、`.jpg`、`.png`等），并返回一个图像对象，正如我们后面将看到的，它由一个 NumPy 数组表示。

+   `cv2.imshow()`: 这个方法接受一个字符串和一个图像对象，并在一个单独的窗口中显示它。窗口的标题由传入的字符串指定。该方法应始终跟随`cv2.waitKey()`方法。

+   `cv2.waitKey()`: 这个方法接受一个数字，并阻塞程序相应的毫秒数，除非传入数字`0`，在这种情况下，它将无限期地阻塞，直到用户在键盘上按下一个键。该方法应始终跟随`cv2.imshow()`方法。

在`input`子文件夹中调用`cv2.imshow()`来显示`ship.jpg`文件，程序将停止，直到按下一个键，此时它将执行程序的其余部分。如果成功运行，脚本将显示以下图像：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/1d32e99b-39a0-4c78-a822-9f9650519bbc.png)

在关闭显示的图片后，按下任意键后，您还应该获得主程序的其余部分的以下输出：

```py
> python example1.py
[[[199 136 86]
 [199 136 86]
 [199 136 86]
 ..., 
 [198 140 81]
 [197 139 80]
 [201 143 84]]

[...Truncated for readability...]

 [[ 56 23 4]
 [ 59 26 7]
 [ 60 27 7]
 ..., 
 [ 79 43 7]
 [ 80 44 8]
 [ 75 39 3]]]
Type: <class 'numpy.ndarray'>
Shape: (1118, 1577, 3)
Top-left pixel: [199 136 86]
Done.
```

输出确认了我们之前讨论的一些事项：

+   首先，当打印出从`cv2.imread()`函数返回的图像对象时，我们得到了一个数字矩阵。

+   使用 Python 的`type()`方法，我们发现这个矩阵的类确实是一个 NumPy 数组：`numpy.ndarray`。

+   调用数组的`shape`属性，我们可以看到图像是一个形状为（`1118`，`1577`，`3`）的三维矩阵，对应于一个具有`1118`行和`1577`列的表，其中每个元素都是一个像素（三个数字的元组）。行和列的数字也对应于图像的大小。

+   聚焦矩阵中的左上角像素（第一行的第一个像素，即`im[0, 0]`），我们得到了（`199`，`136`，`86`）的 BGR 值——`199`蓝色，`136`绿色，`86`红色。通过任何在线转换器查找这个 BGR 值，我们可以看到这是一种浅蓝色，对应于图像的上部分天空。

# 图像处理技术

我们已经看到了一些由 OpenCV 提供的 Python API，用于从图像文件中读取数据。在我们可以使用 OpenCV 执行各种图像处理任务之前，让我们讨论一些常用的图像处理技术的理论基础。

# 灰度处理

我们在本章前面看到了一个灰度处理的例子。可以说，灰度处理是最常用的图像处理技术之一，它是通过仅考虑每个像素的强度信息（由光的数量表示）来减少图像像素矩阵的维度。

因此，灰度图像的像素不再包含三维信息（红色、绿色和蓝色），而只包含一维的黑白数据。这些图像完全由灰度色调组成，黑色表示最弱的光强度，白色表示最强的光强度。

灰度处理在图像处理中有许多重要用途。首先，正如前面提到的，它通过将传统的三维颜色数据映射到一维灰度数据，减少了图像像素矩阵的维度。因此，图像处理程序只需要处理灰度图像的三分之一的工作，而不是分析和处理三层颜色数据。此外，通过仅使用一个光谱表示颜色，图像中的重要模式更有可能在黑白数据中被识别出来。

有多种算法可以将彩色转换为灰度：色度转换、亮度编码、单通道等。幸运的是，我们不必自己实现一个，因为 OpenCV 库提供了一个一行代码的方法，将普通图像转换为灰度图像。仍然使用上一个例子中的船的图像，让我们看一下`Chapter08/example2.py`文件：

```py
# Chapter08/example2.py

import cv2

im = cv2.imread('input/ship.jpg')
gray_im = cv2.cvtColor(im, cv2.COLOR_BGR2GRAY)

cv2.imshow('Grayscale', gray_im)
cv2.waitKey(0) # press any key to move forward here

print(gray_im)
print('Type:', type(gray_im))
print('Shape:', gray_im.shape)
cv2.imwrite('output/gray_ship.jpg', gray_im)

print('Done.')
```

在这个例子中，我们使用 OpenCV 的`cvtColor()`方法将原始图像转换为灰度图像。运行此脚本后，您的计算机上应该显示以下图像：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/a394341f-5f55-45df-8dab-9b16b10cc36e.png)

灰度处理的输出

按任意键解除程序阻塞，您应该获得以下输出：

```py
> python example2.py
[[128 128 128 ..., 129 128 132]
 [125 125 125 ..., 129 128 130]
 [124 125 125 ..., 129 129 130]
 ..., 
 [ 20 21 20 ..., 38 39 37]
 [ 19 22 21 ..., 41 42 37]
 [ 21 24 25 ..., 36 37 32]]
Type: <class 'numpy.ndarray'>
Shape: (1118, 1577)
Done.
```

我们可以看到，灰度图像对象的结构与我们原始图像对象所见的不同。尽管它仍然由 NumPy 数组表示，但现在它是一个二维整数数组，每个整数的范围从 0（黑色）到 255（白色）。然而，像素表仍然由`1118`行和`1577`列组成。

在这个例子中，我们还使用了`cv2.imwrite()`方法，它将图像对象保存到您的本地计算机上。因此，灰度图像可以在本章文件夹的输出子文件夹中找到，如我们的代码中指定的那样。

# 阈值处理

图像处理中的另一个重要技术是阈值处理。目标是将数字图像中的每个像素分类到不同的组中（也称为图像分割），阈值处理提供了一种快速直观的方法来创建二值图像（只有黑色和白色像素）。

阈值化的思想是，如果像素的强度大于先前指定的阈值，则用白色像素替换图像中的每个像素，如果像素的强度小于该阈值，则用黑色像素替换。与灰度化的目标类似，阈值化放大了高强度和低强度像素之间的差异，从而可以识别和提取图像中的重要特征和模式。

回想一下，灰度化将完全彩色的图像转换为只有不同灰度的版本；在这种情况下，每个像素的值是从 0 到 255 的整数。从灰度图像，阈值化可以将其转换为完全的黑白图像，其中每个像素现在只是 0（黑色）或 255（白色）。因此，在图像上执行阈值化后，该图像的每个像素只能保持两个可能的值，也显著减少了图像数据的复杂性。

因此，有效阈值处理的关键是找到一个适当的阈值，使图像中的像素以一种方式分割，使图像中的不同区域变得更加明显。最简单的阈值处理形式是使用一个常数阈值来处理整个图像中的所有像素。让我们在`Chapter08/example3.py`文件中考虑这种方法的一个例子。

```py
# Chapter08/example3.py

import cv2

im = cv2.imread('input/ship.jpg')
gray_im = cv2.cvtColor(im, cv2.COLOR_BGR2GRAY)

ret, custom_thresh_im = cv2.threshold(gray_im, 127, 255, cv2.THRESH_BINARY)
cv2.imwrite('output/custom_thresh_ship.jpg', custom_thresh_im)

print('Done.')
```

在这个例子中，将我们一直在使用的船的图像转换为灰度图像后，我们从 OpenCV 调用`threshold(src, thresh, maxval, type)`函数，该函数接受以下参数：

+   `src`：此参数接受输入/源图像。

+   `thresh`：要在整个图像中使用的常数阈值。在这里，我们使用`127`，因为它只是 0 和 255 之间的中间点。

+   `maxval`：原始值大于常数阈值的像素在阈值处理后将采用此值。我们传入 255 来指定这些像素应该完全是白色的。

+   `type`：此值指示 OpenCV 使用的阈值类型。我们执行简单的二进制阈值处理，因此我们传入`cv2.THRESH_BINARY`。

运行脚本后，您应该能够在输出中找到以下图像，名称为`custom_thresh_ship.jpg`：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/2370035f-c8e1-449c-a7ae-aa3daa1f3118.png)

简单阈值输出

我们可以看到，通过简单的阈值（`127`），我们得到了一个突出显示图像的不同区域的图像：天空、船和海洋。然而，这种简单阈值方法存在一些问题，其中最常见的问题是找到适当的常数阈值。由于不同的图像具有不同的色调、光照条件等，使用静态值作为它们的阈值跨不同图像是不可取的。

这个问题通过自适应阈值方法来解决，这些方法计算图像的小区域的动态阈值。这个过程允许阈值根据输入图像调整，而不仅仅依赖于静态值。让我们考虑这些自适应阈值方法的两个例子，即自适应均值阈值和自适应高斯阈值。导航到`Chapter08/example4.py`文件：

```py
# Chapter08/example4.py

import cv2

im = cv2.imread('input/ship.jpg')
im = cv2.cvtColor(im, cv2.COLOR_BGR2GRAY)

mean_thresh_im = cv2.adaptiveThreshold(im, 255, cv2.ADAPTIVE_THRESH_MEAN_C, cv2.THRESH_BINARY, 11, 2)
cv2.imwrite('output/mean_thresh_ship.jpg', mean_thresh_im)

gauss_thresh_im = cv2.adaptiveThreshold(im, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
cv2.imwrite('output/gauss_thresh_ship.jpg', gauss_thresh_im)

print('Done.')
```

类似于我们之前使用`cv2.threshold()`方法所做的，这里我们再次将原始图像转换为其灰度版本，然后将其传递给 OpenCV 的`adaptiveThreshold()`方法。该方法接受与`cv2.threshold()`方法类似的参数，只是它不是接受一个常数作为阈值，而是接受一个自适应方法的参数。我们分别使用了`cv2.ADAPTIVE_THRESH_MEAN_C`和`cv2.ADAPTIVE_THRESH_GAUSSIAN_C`。

倒数第二个参数指定了执行阈值处理的窗口大小；这个数字必须是奇数正整数。具体来说，在我们的例子中，我们使用了 11，因此对于图像中的每个像素，算法将考虑相邻像素（在原始像素周围的 11 x 11 方形中）。最后一个参数指定了要对最终输出中的每个像素进行的调整。这两个参数再次帮助定位图像不同区域的阈值，从而使阈值处理过程更加动态，并且正如名称所示，是自适应的。

运行脚本后，您应该能够找到以下图像作为输出，名称为`mean_thresh_ship.jpg`和`gauss_thresh_ship.jpg`。`mean_thresh_ship.jpg`的输出如下：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/d12ef19b-305b-49f5-ad48-c133b5e6f301.png)

均值阈值处理的输出

`gauss_thresh_ship.jpg`的输出如下：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/83cc9bc7-d419-44f5-a28b-bdf674724dc5.png)

高斯阈值处理的输出

我们可以看到，使用自适应阈值处理，特定区域的细节将在最终输出图像中进行阈值处理并突出显示。当我们需要识别图像中的小细节时，这些技术非常有用，而简单的阈值处理在我们只想提取图像的大区域时非常有用。 

# 将并发应用于图像处理

我们已经讨论了图像处理的基础知识和一些常见的图像处理技术。我们也知道为什么图像处理是一个繁重的数值计算任务，以及并发和并行编程可以应用于加速独立处理任务。在本节中，我们将看一个具体的例子，介绍如何实现一个并发图像处理应用程序，可以处理大量的输入图像。

首先，转到本章代码的当前文件夹。在`input`文件夹内，有一个名为`large_input`的子文件夹，其中包含我们将在此示例中使用的 400 张图像。这些图片是原始船舶图像中的不同区域，使用 NumPy 提供的数组索引和切片选项从中裁剪出来的。如果您想知道这些图像是如何生成的，请查看`Chapter08/generate_input.py`文件。

本节的目标是实现一个程序，可以同时处理这些图像并进行阈值处理。为此，让我们看一下`example5.py`文件：

```py
from multiprocessing import Pool
import cv2

import sys
from timeit import default_timer as timer

THRESH_METHOD = cv2.ADAPTIVE_THRESH_GAUSSIAN_C
INPUT_PATH = 'input/large_input/'
OUTPUT_PATH = 'output/large_output/'

n = 20
names = ['ship_%i_%i.jpg' % (i, j) for i in range(n) for j in range(n)]

def process_threshold(im, output_name, thresh_method):
    gray_im = cv2.cvtColor(im, cv2.COLOR_BGR2GRAY)
    thresh_im = cv2.adaptiveThreshold(gray_im, 255, thresh_method, 
                cv2.THRESH_BINARY, 11, 2)

    cv2.imwrite(OUTPUT_PATH + output_name, thresh_im)

if __name__ == '__main__':

    for n_processes in range(1, 7):
        start = timer()

        with Pool(n_processes) as p:
            p.starmap(process_threshold, [(
                cv2.imread(INPUT_PATH + name),
                name,
                THRESH_METHOD
            ) for name in names])

        print('Took %.4f seconds with %i process(es).
              ' % (timer() - start, n_processes))

    print('Done.')
```

在这个例子中，我们使用`multiprocessing`模块中的`Pool`类来管理我们的进程。作为复习，`Pool`对象提供了方便的选项，可以使用`Pool.map()`方法将一系列输入映射到单独的进程。然而，在我们的例子中，我们使用了`Pool.starmap()`方法，以便将多个参数传递给目标函数。

在程序的开头，我们进行了一些基本的赋值：在处理图像时执行自适应阈值处理的方法，输入和输出文件夹的路径，以及要处理的图像的名称。`process_threshold()`函数是我们用来实际处理图像的函数；它接受一个图像对象，图像的处理版本的名称，以及要使用的阈值处理方法。这也是为什么我们需要使用`Pool.starmap()`方法而不是传统的`Pool.map()`方法。

在主程序中，为了演示顺序和多进程图像处理之间的差异，我们希望以不同数量的进程运行我们的程序，具体来说，从一个单一进程到六个不同进程。在`for`循环的每次迭代中，我们初始化一个`Pool`对象，并将每个图像的必要参数映射到`process_threshold()`函数，同时跟踪处理和保存所有图像所需的时间。

运行脚本后，处理后的图像可以在当前章节文件夹中的`output/large_output/`子文件夹中找到。您应该获得类似以下的输出：

```py
> python example5.py
Took 0.6590 seconds with 1 process(es).
Took 0.3190 seconds with 2 process(es).
Took 0.3227 seconds with 3 process(es).
Took 0.3360 seconds with 4 process(es).
Took 0.3338 seconds with 5 process(es).
Took 0.3319 seconds with 6 process(es).
Done.
```

当我们从一个单一进程转到两个独立的进程时，执行时间有很大的差异。然而，当从两个进程转到更多的进程时，速度几乎没有或甚至是负的加速。一般来说，这是因为实现大量独立进程的重大开销，与相对较低数量的输入相比。尽管出于简单起见，我们没有实施这种比较，但随着输入数量的增加，我们会看到来自大量工作进程的更好的改进。

到目前为止，我们已经看到并发编程可以为图像处理应用程序提供显著的加速。然而，如果我们看一下我们之前的程序，我们会发现有其他调整可以进一步提高执行时间。具体来说，在我们之前的程序中，我们通过使用列表推导式顺序读取图像：

```py
with Pool(n_processes) as p:
    p.starmap(process_threshold, [(
        cv2.imread(INPUT_PATH + name),
        name,
        THRESH_METHOD
    ) for name in names])
```

从理论上讲，如果我们将不同图像文件的读取过程并发进行，我们也可以通过我们的程序获得额外的加速。这在处理大型输入文件的图像处理应用程序中尤其如此，在那里大量时间花在等待输入读取上。考虑到这一点，让我们考虑以下示例，在其中我们将实现并发输入/输出处理。导航到`example6.py`文件：

```py
from multiprocessing import Pool
import cv2

import sys
from functools import partial
from timeit import default_timer as timer

THRESH_METHOD = cv2.ADAPTIVE_THRESH_GAUSSIAN_C
INPUT_PATH = 'input/large_input/'
OUTPUT_PATH = 'output/large_output/'

n = 20
names = ['ship_%i_%i.jpg' % (i, j) for i in range(n) for j in range(n)]

def process_threshold(name, thresh_method):
    im = cv2.imread(INPUT_PATH + name)
    gray_im = cv2.cvtColor(im, cv2.COLOR_BGR2GRAY)
    thresh_im = cv2.adaptiveThreshold(gray_im, 255, thresh_method, cv2.THRESH_BINARY, 11, 2)

    cv2.imwrite(OUTPUT_PATH + name, thresh_im)

if __name__ == '__main__':

    for n_processes in range(1, 7):
        start = timer()

        with Pool(n_processes) as p:
            p.map(partial(process_threshold, thresh_method=THRESH_METHOD), names)

        print('Took %.4f seconds with %i process(es).' % (timer() - start, n_processes))

    print('Done.')
```

这个程序的结构与上一个程序类似。然而，我们不是准备要处理的必要图像和其他相关的输入信息，而是将它们实现在`process_threshold()`函数中，现在只需要输入图像的名称并处理读取图像本身。

作为一个旁注，我们在主程序中使用 Python 的内置`functools.partial()`方法传递一个部分参数（因此得名），具体是`thresh_method`，传递给`process_threshold()`函数，因为这个参数在所有图像和进程中都是固定的。有关此工具的更多信息可以在[`docs.python.org/3/library/functools.html`](https://docs.python.org/3/library/functools.html)找到。

运行脚本后，您应该获得类似以下的输出：

```py
> python example6.py
Took 0.5300 seconds with 1 process(es).
Took 0.4133 seconds with 2 process(es).
Took 0.2154 seconds with 3 process(es).
Took 0.2147 seconds with 4 process(es).
Took 0.2213 seconds with 5 process(es).
Took 0.2329 seconds with 6 process(es).
Done.
```

与我们上次的输出相比，这个应用程序的实现确实给我们带来了显著更好的执行时间。

# 良好的并发图像处理实践

到目前为止，您很可能已经意识到图像处理是一个相当复杂的过程，在图像处理应用程序中实现并发和并行编程可能会给我们的工作增加更多的复杂性。然而，有一些良好的实践将指导我们朝着正确的方向发展我们的图像处理应用程序。接下来的部分讨论了我们应该牢记的一些最常见的实践。

# 选择正确的方式（其中有很多）

当我们学习阈值处理时，我们已经简要提到了这种实践。图像处理应用程序如何处理和处理其图像数据在很大程度上取决于它应该解决的问题，以及将要提供给它的数据的类型。因此，在处理图像时选择特定参数时存在显著的变异性。

例如，正如我们之前所看到的，有各种方法可以对图像进行阈值处理，每种方法都会产生非常不同的输出：如果您只想关注图像的大的、明显的区域，简单的常数阈值处理将比自适应阈值处理更有益；然而，如果您想突出图像细节中的小变化，自适应阈值处理将更好。

让我们考虑另一个例子，我们将看到调整图像处理函数的特定参数如何产生更好的输出。在这个例子中，我们使用一个简单的 Haar 级联模型来检测图像中的面部。我们不会深入讨论模型如何处理和处理其数据，因为它已经内置在 OpenCV 中；同样，我们只是在高层次上使用这个模型，改变它的参数以获得不同的结果。

在本章的文件夹中导航到`example7.py`文件。该脚本旨在检测我们输入文件夹中的`obama1.jpeg`和`obama2.jpg`图像中的面部：

```py
import cv2

face_cascade = cv2.CascadeClassifier('input/haarcascade_frontalface_default.xml')

for filename in ['obama1.jpeg', 'obama2.jpg']:
    im = cv2.imread('input/' + filename)
    gray_im = cv2.cvtColor(im, cv2.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(im)

    for (x, y, w, h) in faces:
        cv2.rectangle(im, (x, y), (x + w, y + h), (0, 255, 0), 2)

    cv2.imshow('%i face(s) found' % len(faces), im)
    cv2.waitKey(0)

print('Done.')
```

首先，程序使用`cv2.CascadeClassifier`类从`input`文件夹中加载预训练的 Haar 级联模型。对于每个输入图像，脚本将其转换为灰度并将其输入到预训练模型中。然后脚本在图像中找到的每张脸周围画一个绿色的矩形，最后在一个单独的窗口中显示它。

运行程序，你会看到以下带有标题`5 个面部被发现`的图像：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/77c174ea-ffc8-46e8-824b-1756d783fa58.png)

正确的面部检测

看起来我们的程序到目前为止工作得很好。按任意键继续，你应该会看到以下带有标题`7 个面部被发现`的图像：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/1048508c-d9f8-4da4-8fff-73ca7f8639a6.png)

错误的面部检测

现在，我们的程序将一些其他物体误认为是真正的面部，导致了两个误报。这背后的原因涉及到预训练模型的创建方式。具体来说，Haar 级联模型使用了一个训练数据集，其中包含特定（像素）大小的图像，当输入图像包含不同大小的面部时——这在一张集体照片中很常见，有些人离相机很近，而其他人离得很远——将输入到该模型中，会导致输出中出现误报。

`cv2.CascadeClassifier`类的`detectMultiScale`方法中的`scaleFactor`参数解决了这个问题。该参数将在尝试预测这些区域是否包含面部之前，将输入图像的不同区域缩小。这样做可以消除面部大小的潜在差异。为了实现这一点，将我们传递输入图像到模型的那一行更改为以下内容，以指定`scaleFactor`参数为`1.2`：

```py
faces = face_cascade.detectMultiScale(im, scaleFactor=1.2)
```

运行程序，你会看到这次我们的应用能够正确检测输入图像中的所有面部，而不会产生任何误报。

从这个例子中，我们可以看到了解输入图像对你的图像处理应用程序在执行中可能带来的潜在挑战是很重要的，并尝试在处理的一个方法中使用不同的方法或参数来获得最佳结果。

# 生成适当数量的进程

我们在并发图像处理的例子中注意到的一个问题是生成进程的任务需要相当长的时间。由于这个原因，如果可用于分析数据的进程数量与输入量相比太高，那么从增加工作进程数量中获得的执行时间改善将会减少，有时甚至会变得负面。

然而，除非我们也考虑到其输入图像，否则没有一个具体的方法可以确定一个程序是否需要适当数量的独立进程。例如，如果输入图像是相对较大的文件，并且程序从存储中加载它们需要相当长的时间，那么拥有更多的进程可能是有益的；当一些进程在等待它们的图像加载时，其他进程可以继续对它们的图像进行处理。换句话说，拥有更多的进程将允许加载和处理时间之间的一些重叠，这将导致更好的加速。

简而言之，重要的是测试图像处理应用程序中可用的不同进程，以查看可扩展性的最佳数字是多少。

# 同时处理输入/输出

我们发现，以顺序方式加载输入图像可能会对图像处理应用程序的执行时间产生负面影响，而不是允许单独的进程加载它们自己的输入。如果图像文件非常大，那么在单独的进程中加载时间可能会与其他进程中的加载/处理时间重叠，这一点尤为真实。对于将输出图像写入文件也是如此。

# 总结

图像处理是分析和操作数字图像文件以创建图像的新版本或从中提取重要数据的任务。这些数字图像由像素表表示，这些像素表是 RGB 值，或者本质上是数字元组。因此，数字图像只是数字的多维矩阵，这导致图像处理任务通常归结为大量的数字计算。

由于图像可以在图像处理应用程序中独立地进行分析和处理，因此并发和并行编程 – 特别是多进程 – 提供了一种实现应用程序执行时间显着改进的方法。此外，在实现自己的并发图像处理程序时，有许多良好的实践方法可遵循。

到目前为止，在本书中，我们已经涵盖了并发编程的两种主要形式：多线程和多进程。在下一章中，我们将转向异步 I/O 的主题，这也是并发和并行的关键要素之一。

# 问题

+   什么是图像处理任务？

+   数字成像的最小单位是什么？它在计算机中是如何表示的？

+   什么是灰度处理？这种技术有什么作用？

+   什么是阈值处理？这种技术有什么作用？

+   为什么图像处理应该并发进行？

+   并发图像处理的一些良好实践是什么？

# 进一步阅读

有关更多信息，您可以参考以下链接：

+   用 Python 自动化无聊的事情：初学者的实用编程，Al Sweigart，No Starch Press，2015

+   *使用 OpenCV 学习图像处理*，Garcia，Gloria Bueno 等人，Packt Publishing Ltd，2015

+   数字图像处理的计算介绍，Alasdair McAndrew，Chapman and Hall/CRC，2015

+   豪斯，J.，P. Joshi 和 M. Beyeler。OpenCV：*Python 计算机视觉项目*。Packt Publishing Ltd，2016


# 第九章：异步编程介绍

在本章中，我们将向读者介绍异步编程的正式定义。我们将讨论异步处理背后的基本思想，异步编程与我们所见过的其他编程模型之间的区别，以及为什么异步编程在并发中如此重要。

本章将涵盖以下主题：

+   异步编程的概念

+   异步编程与其他编程模型之间的关键区别

# 技术要求

以下是本章的先决条件列表：

+   你的计算机上必须安装 Python 3

+   从[`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python)下载 GitHub 存储库

+   在本章中，我们将使用名为`Chapter09`的子文件夹，所以确保你已经准备好了它

+   查看以下视频以查看代码实际运行情况：[`bit.ly/2DF700L`](http://bit.ly/2DF700L)

# 一个快速的类比

异步编程是一种专注于协调应用程序中不同任务的编程模型。它的目标是确保应用程序在最短的时间内完成执行这些任务。从这个角度来看，异步编程是关于在适当时刻从一个任务切换到另一个任务，以创建等待和处理时间之间的重叠，并从而缩短完成整个程序所需的总时间。

为了理解异步编程的基本思想，让我们考虑一个快速的现实生活类比。想象一下，你正在烹饪一顿包括以下菜肴的三道菜：

+   需要 2 分钟准备和 3 分钟烹饪/等待的开胃菜

+   需要 5 分钟准备和 10 分钟烹饪/等待的主菜

+   需要 3 分钟准备和 5 分钟烹饪/等待的甜点

现在，考虑菜肴完成烹饪的顺序，你的目标是确定生产三道菜所需的最短时间。例如，如果我们按顺序烹饪菜肴，我们将首先完成开胃菜，需要 5 分钟，然后我们将转向主菜，需要 15 分钟，最后是甜点，需要 8 分钟。总共，整顿饭需要 28 分钟完成。

找到更快的方法的关键是**重叠**一个菜的烹饪/等待时间与另一个菜的准备时间。由于在等待已经准备好烹饪的食物时你不会被占用，这段时间可以通过准备另一道菜的食物来节省。例如，可以通过以下步骤实现改进：

+   准备开胃菜：2 分钟。

+   在等待开胃菜烹饪时准备主菜：5 分钟。在这一步中，开胃菜将完成。

+   在等待主菜烹饪时准备和烹饪甜点：8 分钟。在这一步骤中，甜点将完成，主菜还有 2 分钟的烹饪时间。

+   等待主菜烹饪完成：2 分钟。在这一步中，主菜将烹饪完成。

通过重叠时间，我们节省了大量烹饪三餐的时间，现在总共只需要 17 分钟，而如果按顺序进行的话，需要 28 分钟。然而，显然有多种方式来决定我们应该先开始哪道菜，哪道菜应该第二个和最后一个烹饪。烹饪顺序的另一个变化可能如下：

+   准备主菜：5 分钟。

+   在等待主菜烹饪时准备开胃菜：2 分钟。主菜还有 8 分钟的烹饪时间。

+   在等待开胃菜和主菜烹饪的时候准备甜点：3 分钟。在这一步骤中，开胃菜将已经完成，主菜还有 5 分钟的烹饪时间。

+   等待主菜和甜点烹饪完成：5 分钟。在这一步骤中，主菜和甜点都已经完成。

这次，制作整顿饭只需要 15 分钟。我们可以看到，不同的烹饪顺序可能导致不同的总烹饪时间。找到在程序中执行和切换任务的最佳顺序是异步编程的主要思想：而不是以顺序方式执行该程序的所有指令，我们协调这些指令，以便我们可以创建重叠的等待和处理时间，并最终实现更好的执行时间。

# 异步与其他编程模型

异步编程是并发特别是编程的一个重要概念，但它是一个相当复杂的概念，有时我们很难将其与其他编程模型区分开来。在本节中，我们将比较异步编程与同步编程以及我们已经看到的其他并发编程模型（即线程和多进程）。

# 异步与同步编程

再次，异步编程与同步编程在本质上是不同的，因为它具有任务切换的特性。在同步编程中，程序的指令是按顺序执行的：一个任务必须在下一个任务开始处理之前执行完毕。而在异步编程中，如果当前任务需要花费很长时间才能完成，您可以选择在任务执行期间指定一个时间，将执行切换到另一个任务。正如我们所观察到的，这样做可能会导致整个程序的执行时间有所改善。

异步编程的一个常见示例是服务器和客户端在 HTTP 请求期间的交互。如果 HTTP 请求是同步的，客户端将不得不在发出请求后等待，直到从服务器接收到响应。想象一下，每次您转到新链接或开始播放视频时，浏览器都会挂起，直到实际数据从服务器返回。这对 HTTP 通信来说将是极其不便和低效的。

更好的方法是异步通信，客户端可以自由继续工作，当来自服务器的请求数据返回时，客户端将收到通知并继续处理数据。异步编程在 Web 开发中非常常见，一个名为**AJAX**（**异步 JavaScript 和 XML**的缩写）的整个编程模型现在几乎在每个网站上都在使用。此外，如果您使用过 JavaScript 中的常见库，如 jQuery 或 Node.js，那么您可能已经使用过或至少听说过**回调**这个术语，它简单地意味着可以传递给另一个函数以便将来执行的函数。在函数执行之间来回切换是异步编程的主要思想，我们将在第十八章中实际分析回调使用的高级示例，*从头开始构建服务器*。

以下图表进一步说明了同步和异步客户端-服务器通信之间的区别。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/2ba8b96a-5449-47e6-9f20-5680fb42a540.png)

同步和异步 HTTP 请求之间的区别

当然，异步编程不仅限于 HTTP 请求。涉及一般网络通信、软件数据处理、与数据库交互等任务都可以利用异步编程。与同步编程相反，异步编程通过防止程序在等待数据时挂起来为用户提供响应性。因此，它是在处理大量数据的程序中实现的一个很好的工具。

# 异步与线程和多进程

虽然异步编程在某种程度上提供了与线程和多进程相似的好处，但它在 Python 编程语言中与这两种编程模型有根本的不同。

众所周知，在多进程中，我们的主程序的多个副本连同其指令和变量被创建并独立地在不同的核心上执行。线程，也被称为轻量级进程，也是基于同样的原理：虽然代码不是在单独的核心中执行，但在单独的线程中执行的独立部分也不会相互交互。

另一方面，异步编程将程序的所有指令都保留在同一个线程和进程中。异步编程的主要思想是，如果从一个任务切换到另一个任务更有效（从执行时间的角度来看），那么就简单地等待第一个任务的同时处理第二个任务。这意味着异步编程不会利用系统可能具有的多个核心。

# Python 中的一个例子

虽然我们将更深入地讨论如何在 Python 中实现异步编程以及我们将使用的主要工具，包括`asyncio`模块，让我们考虑一下异步编程如何改善我们的 Python 程序的执行时间。

让我们看一下`Chapter09/example1.py`文件：

```py
# Chapter09/example1.py

from math import sqrt

def is_prime(x):
    print('Processing %i...' % x)

    if x < 2:
        print('%i is not a prime number.' % x)

    elif x == 2:
        print('%i is a prime number.' % x)

    elif x % 2 == 0:
        print('%i is not a prime number.' % x)

    else:
        limit = int(sqrt(x)) + 1
        for i in range(3, limit, 2):
            if x % i == 0:
                print('%i is not a prime number.' % x)
                return

        print('%i is a prime number.' % x)

if __name__ == '__main__':

    is_prime(9637529763296797)
    is_prime(427920331)
    is_prime(157)
```

在这里，我们有我们熟悉的质数检查“is_prime（）”函数，它接受一个整数并打印出一个消息，指示该输入是否是质数。在我们的主程序中，我们对三个不同的数字调用“is_prime（）”。我们还跟踪了程序处理所有三个数字所花费的时间。

一旦您执行脚本，您的输出应该类似于以下内容：

```py
> python example1.py
Processing 9637529763296797...
9637529763296797 is a prime number.
Processing 427920331...
427920331 is a prime number.
Processing 157...
157 is a prime number.
```

您可能已经注意到，程序花了相当长的时间来处理第一个输入。由于“is_prime（）”函数的实现方式，如果输入的质数很大，那么“is_prime（）”处理它的时间就会更长。因此，由于我们的第一个输入是一个很大的质数，我们的 Python 程序在打印输出之前将会 hang 一段时间。这通常会给我们的程序带来一种不响应的感觉，这在软件工程和 Web 开发中都是不可取的。

为了改善程序的响应性，我们将利用`asyncio`模块，该模块已经在`Chapter09/example2.py`文件中实现：

```py
# Chapter09/example2.py

from math import sqrt

import asyncio

async def is_prime(x):
    print('Processing %i...' % x)

    if x < 2:
        print('%i is not a prime number.' % x)

    elif x == 2:
        print('%i is a prime number.' % x)

    elif x % 2 == 0:
        print('%i is not a prime number.' % x)

    else:
        limit = int(sqrt(x)) + 1
        for i in range(3, limit, 2):
            if x % i == 0:
                print('%i is not a prime number.' % x)
                return
            elif i % 100000 == 1:
                #print('Here!')
                await asyncio.sleep(0)

        print('%i is a prime number.' % x)

async def main():

    task1 = loop.create_task(is_prime(9637529763296797))
    task2 = loop.create_task(is_prime(427920331))
    task3 = loop.create_task(is_prime(157))

    await asyncio.wait([task1, task2, task3])

if __name__ == '__main__':
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
    except Exception as e:
        print('There was a problem:')
        print(str(e))
    finally:
        loop.close()
```

我们将在下一章详细介绍这段代码。现在，只需运行脚本，您将看到打印输出的响应性有所改善：

```py
> python example2.py
Processing 9637529763296797...
Processing 427920331...
427920331 is a prime number.
Processing 157...
157 is a prime number.
9637529763296797 is a prime number.
```

具体来说，当处理`9637529763296797`（我们的最大输入）时，程序决定切换到下一个输入。因此，在它之前返回了`427920331`和`157`的结果，从而提高了程序的响应性。

# 总结

异步编程是一种基于任务协调和任务切换的编程模型。它与传统的顺序（或同步）编程不同，因为它在处理和等待时间之间创建了重叠，从而提高了速度。异步编程也不同于线程和多进程，因为它只发生在一个单一线程和一个单一进程中。

异步编程主要用于改善程序的响应性。当一个大输入需要花费大量时间来处理时，顺序版本的程序会出现挂起的情况，而异步程序会转移到其他较轻的任务。这允许小输入先完成执行，并帮助程序更具响应性。

在下一章中，我们将学习异步程序的主要结构，并更详细地了解`asyncio`模块及其功能。

# 问题

+   异步编程背后的理念是什么？

+   异步编程与同步编程有何不同？

+   异步编程与线程和多进程有何不同？

# 进一步阅读

欲了解更多信息，您可以参考以下链接：

+   《使用 Python 进行并行编程》，作者 Jan Palach，Packt Publishing Ltd，2014

+   《Python 并行编程食谱》，作者 Giancarlo Zaccone，Packt Publishing Ltd，2015

+   《RabbitMQ Cookbook》，作者 Sigismondo Boschi 和 Gabriele Santomaggio，Packt Publishing Ltd，2013


# 第十章：在 Python 中实现异步编程

本章将向您介绍 Python 中的`asyncio`模块。它将涵盖这个新并发模块背后的理念，该模块利用事件循环和协程，并提供了一个与同步代码一样可读的 API。在本章中，我们还将讨论异步编程的实现，以及通过`concurrent.futures`模块进行线程和多进程处理。在此过程中，我们将涵盖通过`asyncio`的最常见用法来应用异步编程，包括异步输入/输出和避免阻塞任务。

本章将涵盖以下主题：

+   使用`asyncio`实现异步编程的基本要素

+   `asyncio`提供的异步编程框架

+   `concurrent.futures`模块及其在`asyncio`中的使用

# 技术要求

以下是本章的先决条件列表：

+   确保您的计算机上安装了 Python 3

+   在[`github.com/PacktPublishing/Mastering-Concurrency-in-Python`](https://github.com/PacktPublishing/Mastering-Concurrency-in-Python)下载 GitHub 存储库

+   在本章中，我们将使用名为`Chapter10`的子文件夹进行工作

+   查看以下视频以查看代码实际运行情况：[`bit.ly/2TAtTrA`](http://bit.ly/2TAtTrA)

# `asyncio`模块

正如您在上一章中看到的，`asyncio`模块提供了一种将顺序程序转换为异步程序的简单方法。在本节中，我们将讨论异步程序的一般结构，以及如何在 Python 中实现从顺序到异步程序的转换。

# 协程、事件循环和 futures

大多数异步程序都具有一些常见的元素，协程、事件循环和 futures 就是其中的三个元素。它们的定义如下：

+   **事件循环**是异步程序中任务的主要协调者。事件循环跟踪所有要异步运行的任务，并决定在特定时刻执行哪些任务。换句话说，事件循环处理异步编程的任务切换方面（或执行流程）。

+   **协程**是一种特殊类型的函数，它包装特定任务，以便可以异步执行。为了指定函数中应该发生任务切换的位置，需要协程；换句话说，它们指定函数应该何时将执行流程交还给事件循环。协程的任务通常存储在任务队列中或在事件循环中创建。

+   **Futures**是从协程返回的结果的占位符。这些 future 对象在协程在事件循环中启动时创建，因此 futures 可以表示实际结果、待定结果（如果协程尚未执行完毕）或异常（如果协程将返回异常）。

事件循环、协程及其对应的 futures 是异步编程过程的核心元素。首先启动事件循环并与其任务队列交互，以获取第一个任务。然后创建该任务的协程及其对应的 future。当需要在该协程内进行任务切换时，协程将暂停，并调用下一个协程；同时也保存了第一个协程的所有数据和上下文。

现在，如果该协程是阻塞的（例如，输入/输出处理或休眠），执行流程将被释放回事件循环，事件循环将继续执行任务队列中的下一个项目。事件循环将在切换回第一个协程之前启动任务队列中的最后一个项目，并将从上次暂停的地方继续执行。

当每个任务执行完成时，它将从任务队列中出列，其协程将被终止，并且相应的 future 将注册来自协程的返回结果。这个过程将一直持续，直到任务队列中的所有任务都被完全执行。下面的图表进一步说明了前面描述的异步过程的一般结构：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/8e37c350-e34c-4f29-9459-8084491a0a3e.png)

异步编程过程

# 异步 IO API

在考虑异步程序的一般结构时，让我们考虑一下`asyncio`模块和 Python 为实现异步程序提供的特定 API。这个 API 的第一个基础是添加到 Python 3.5 中的`async`和`await`关键字。这些关键字用于向 Python 指定异步程序的主要元素。

具体来说，当声明一个函数时，`async`通常放在`def`关键字的前面。在带有`async`关键字的函数前面声明的函数将被 Python 解释为协程。正如我们讨论过的，每个协程内部都必须有关于何时进行任务切换事件的规定。然后，`await`关键字用于指定何时何地将执行流返回给事件循环；这通常是通过等待另一个协程产生结果（`await coroutine`）或通过`asyncio`模块的辅助函数，如`asyncio.sleep()`和`asyncio.wait()`函数来实现的。

重要的是要注意，`async`和`await`关键字实际上是由 Python 提供的，而不是由`asyncio`模块管理的。这意味着异步编程实际上可以在没有`asyncio`的情况下实现，但是，正如你将看到的，`asyncio`提供了一个框架和基础设施来简化这个过程，因此是 Python 中实现异步编程的主要工具。

具体来说，`asyncio`模块中最常用的 API 是事件循环管理功能。使用`asyncio`，你可以通过直观和简单的函数调用开始操纵你的任务和事件循环，而不需要大量的样板代码。其中包括以下内容：

+   `asyncio.get_event_loop()`: 这个方法返回当前上下文的事件循环，它是一个`AbstractEventLoop`对象。大多数情况下，我们不需要担心这个类，因为`asyncio`模块已经提供了一个高级 API 来管理我们的事件循环。

+   `AbstractEventLoop.create_task()`: 这个方法由事件循环调用。它将其输入添加到调用事件循环的当前任务队列中；输入通常是一个协程（即带有`async`关键字的函数）。

+   `AbstractEventLoop.run_until_complete()`: 这个方法也是由事件循环调用的。它接受异步程序的主协程，并执行它，直到协程的相应 future 被返回。虽然这个方法启动了事件循环的执行，但它也会阻塞其后的所有代码，直到所有的 future 都完成。

+   `AbstractEventLoop.run_forever()`: 这个方法与`AbstractEventLoop.run_until_complete()`有些相似，不同之处在于，正如方法名所示，调用事件循环将永远运行，除非调用`AbstractEventLoop.stop()`方法。因此，循环不会退出，即使获得了返回的 future。

+   `AbstractEventLoop.stop()`: 这个方法会导致调用事件循环停止执行，并在最近的适当机会退出，而不会导致整个程序崩溃。

除了这些方法之外，我们使用了许多非阻塞函数来促进任务切换事件。其中包括以下内容：

+   `asyncio.sleep()`: 虽然本身是一个协程，但这个函数创建一个在给定时间后（由输入的秒数指定）完成的额外协程。通常用作`asyncio.sleep(0)`，以引起立即的任务切换事件。

+   `asyncio.wait()`: 这个函数也是一个协程，因此可以用来切换任务。它接受一个序列（通常是一个列表）的 futures，并等待它们完成执行。

# 异步框架的实际应用

正如您所见，`asyncio`提供了一种简单直观的方法来使用 Python 的异步编程关键字实现异步程序的框架。有了这个，让我们考虑将提供的框架应用于 Python 中的同步应用程序，并将其转换为异步应用程序。

# 异步倒计时

让我们看一下`Chapter10/example1.py`文件，如下所示：

```py
# Chapter10/example1.py

import time

def count_down(name, delay):
    indents = (ord(name) - ord('A')) * '\t'

    n = 3
    while n:
        time.sleep(delay)

        duration = time.perf_counter() - start
        print('-' * 40)
        print('%.4f \t%s%s = %i' % (duration, indents, name, n))

        n -= 1

start = time.perf_counter()

count_down('A', 1)
count_down('B', 0.8)
count_down('C', 0.5)

print('-' * 40)
print('Done.')
```

这个例子的目标是说明重叠处理和独立任务等待时间的异步特性。为了做到这一点，我们将分析一个倒计时函数（`count_down()`），它接受一个字符串和一个延迟时间。然后它将从三倒数到一，以秒为单位，同时打印出从函数执行开始到输入字符串（带有当前倒计时数字）的经过的时间。

在我们的主程序中，我们将在字母`A`、`B`和`C`上调用`count_down()`函数，延迟时间不同。运行脚本后，您的输出应该类似于以下内容：

```py
> python example1.py
----------------------------------------
1.0006 A = 3
----------------------------------------
2.0041 A = 2
----------------------------------------
3.0055 A = 1
----------------------------------------
3.8065         B = 3
----------------------------------------
4.6070         B = 2
----------------------------------------
5.4075         B = 1
----------------------------------------
5.9081                 C = 3
----------------------------------------
6.4105                 C = 2
----------------------------------------
6.9107                 C = 1
----------------------------------------
Done.
```

行首的数字表示从程序开始经过的总秒数。您可以看到程序首先为字母`A`倒数，间隔一秒，然后转移到字母`B`，间隔 0.8 秒，最后转移到字母`C`，间隔 0.5 秒。这是一个纯粹的顺序同步程序，因为处理和等待时间之间没有重叠。此外，运行程序大约需要 6.9 秒，这是所有三个字母倒计时时间的总和：

```py
1 second x 3 (for A) + 0.8 seconds x 3 (for B) + 0.5 seconds x 3 (for C) = 6.9 seconds
```

牢记异步编程背后的思想，我们可以看到实际上我们可以将这个程序转换为异步程序。具体来说，假设在程序的第一秒钟，当我们等待倒数字母`A`时，我们可以切换任务以移动到其他字母。事实上，我们将为`count_down()`函数中的所有字母实现这个设置（换句话说，我们将`count_down()`变成一个协程）。

从理论上讲，现在所有倒计时任务都是异步程序中的协程，我们应该能够获得更好的执行时间和响应性。由于所有三个任务都是独立处理的，倒计时消息应该是无序打印出来的（在不同的字母之间跳跃），而异步程序应该只需要与最大任务所需的时间大致相同（即字母`A`需要三秒）。

但首先，让我们将程序变成异步的。为了做到这一点，我们首先需要将`count_down()`变成一个协程，并指定函数内的某一点为任务切换事件。换句话说，我们将在函数前面添加关键字`async`，而不是使用`time.sleep()`函数，我们将使用`asyncio.sleep()`函数以及`await`关键字；函数的其余部分应保持不变。我们的`count_down()`协程现在应该如下所示：

```py
# Chapter10/example2.py

async def count_down(name, delay):
    indents = (ord(name) - ord('A')) * '\t'

    n = 3
    while n:
        await asyncio.sleep(delay)

        duration = time.perf_counter() - start
        print('-' * 40)
        print('%.4f \t%s%s = %i' % (duration, indents, name, n))

        n -= 1
```

至于我们的主程序，我们需要初始化和管理一个事件循环。具体来说，我们将使用`asyncio.get_event_loop()`方法创建一个空的事件循环，使用`AbstractEventLoop.create_task()`将所有三个倒计时任务添加到任务队列中，并最后使用`AbstractEventLoop.run_until_complete()`开始运行事件循环。我们的主程序应该如下所示：

```py
# Chapter10/example2.py

loop = asyncio.get_event_loop()
tasks = [
    loop.create_task(count_down('A', 1)),
    loop.create_task(count_down('B', 0.8)),
    loop.create_task(count_down('C', 0.5))
]

start = time.perf_counter()
loop.run_until_complete(asyncio.wait(tasks))

print('-' * 40)
print('Done.')
```

完整的脚本也可以在书的代码存储库中找到，在`Chapter10`子文件夹中，名为`example2.py`。运行脚本后，您的输出应该类似于以下内容：

```py
> python example2.py
----------------------------------------
0.5029                 C = 3
----------------------------------------
0.8008         B = 3
----------------------------------------
1.0049 A = 3
----------------------------------------
1.0050                 C = 2
----------------------------------------
1.5070                 C = 1
----------------------------------------
1.6011         B = 2
----------------------------------------
2.0090 A = 2
----------------------------------------
2.4068         B = 1
----------------------------------------
3.0147 A = 1
----------------------------------------
Done.
```

现在，您可以看到异步程序如何可以提高程序的执行时间和响应性。我们的程序不再按顺序执行单个任务，而是在不同的倒计时之间切换，并重叠它们的处理/等待时间。正如我们讨论过的，这导致不同的字母在彼此之间或同时被打印出来。

在程序开始时，程序不再等待整整一秒才打印出第一条消息`A = 3`，而是切换到任务队列中的下一个任务（在这种情况下，它等待 0.8 秒来打印字母`B`）。这个过程一直持续，直到过去了 0.5 秒，打印出`C = 3`，再过 0.3 秒（在 0.8 秒时），打印出`B = 3`。这都发生在打印出`A = 3`之前。

我们的异步程序的这种任务切换属性使其更具响应性。在打印第一条消息之前不再等待一秒，程序现在只需要 0.5 秒（最短的等待时间）就可以打印出第一条消息。至于执行时间，您可以看到这一次，整个程序只需要三秒的时间来执行（而不是 6.9 秒）。这符合我们的推测：执行时间将会接近执行最大任务所需的时间。

# 关于阻塞函数的说明

正如您所见，我们必须用`asyncio`模块中的等效函数替换我们原始的`time.sleep()`函数。这是因为`time.sleep()`本质上是一个阻塞函数，这意味着它不能用于实现任务切换事件。为了测试这一点，在我们的`Chapter10/example2.py`文件（我们的异步程序）中，我们将替换以下代码行：

```py
await asyncio.sleep(delay)
```

先前的代码将被替换为以下代码：

```py
time.sleep(delay)
```

运行这个新脚本后，您的输出将与我们原始的顺序同步程序的输出相同。因此，用`time.sleep()`替换`await asyncio.sleep()`实际上将我们的程序重新转换为同步，忽略了我们实现的事件循环。发生的情况是，当我们的程序继续执行`count_down()`函数中的那行时，`time.sleep()`实际上阻塞并阻止了执行流的释放，从根本上使整个程序再次变成同步。将`time.sleep()`恢复为`await asyncio.sleep()`以解决这个问题。

以下图表说明了阻塞和非阻塞文件处理之间执行时间差异的示例：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-ccr-py/img/14eb98aa-5364-4486-8fba-75e4434c5293.png)

阻塞与非阻塞

这种现象引发了一个有趣的问题：如果一个耗时长的任务是阻塞的，那么使用该任务作为协程实现异步编程就是不可能的。因此，如果我们真的想要在异步应用程序中实现阻塞函数返回的内容，我们需要实现该阻塞函数的另一个版本，该版本可以成为协程，并允许在函数内至少有一个点进行任务切换。

幸运的是，在将`asyncio`作为 Python 的官方功能之一后，Python 核心开发人员一直在努力制作最常用的 Python 阻塞函数的协程版本。这意味着，如果您发现阻塞函数阻止您的程序真正实现异步，您很可能能够找到这些函数的协程版本来在您的程序中实现。

然而，Python 中传统阻塞函数的异步版本具有潜在不同的 API，这意味着您需要熟悉来自单独函数的这些 API。处理阻塞函数的另一种方法，而无需实现它们的协程版本，是使用执行器在单独的线程或单独的进程中运行函数，以避免阻塞主事件循环的线程。

# 异步素数检查

从我们开始的倒计时例子中继续，让我们重新考虑上一章的例子。作为一个复习，以下是程序同步版本的代码：

```py
# Chapter09/example1.py

from math import sqrt

def is_prime(x):
    print('Processing %i...' % x)

    if x < 2:
        print('%i is not a prime number.' % x)

    elif x == 2:
        print('%i is a prime number.' % x)

    elif x % 2 == 0:
        print('%i is not a prime number.' % x)

    else:
        limit = int(sqrt(x)) + 1
        for i in range(3, limit, 2):
            if x % i == 0:
                print('%i is not a prime number.' % x)
                return

        print('%i is a prime number.' % x)

if __name__ == '__main__':

    is_prime(9637529763296797)
    is_prime(427920331)
    is_prime(157)
```

正如我们在上一章讨论的那样，这里我们有一个简单的素数检查函数`is_prime(x)`，它打印出消息，指示它接收的输入整数`x`是否是素数。在我们的主程序中，我们按照递减的顺序依次对三个素数调用`is_prime()`。这种设置再次在处理大输入时创建了一个显著的时间段，导致程序在处理大输入时出现停顿，从而降低了程序的响应性。

程序产生的输出将类似于以下内容：

```py
Processing 9637529763296797...
9637529763296797 is a prime number.
Processing 427920331...
427920331 is a prime number.
Processing 157...
157 is a prime number.
```

要为此脚本实现异步编程，首先，我们将不得不创建我们的第一个主要组件：事件循环。为此，我们将其转换为一个单独的函数，而不是使用`'__main__'`范围。这个函数和我们的`is_prime()`素数检查函数将成为我们最终异步程序中的协程。

现在，我们需要将`is_prime()`和`main()`函数都转换为协程；同样，这意味着在`def`关键字前面加上`async`关键字，并在每个函数内部使用`await`关键字来指定任务切换事件。对于`main()`，我们只需在等待任务队列时实现该事件，使用`aysncio.wait()`，如下所示：

```py
# Chapter09/example2.py

async def main():

    task1 = loop.create_task(is_prime(9637529763296797))
    task2 = loop.create_task(is_prime(427920331))
    task3 = loop.create_task(is_prime(157))

    await asyncio.wait([task1, task2, task3])
```

`is_prime()`函数中的情况更加复杂，因为在执行流程应该释放回事件循环的时间点不明确，就像我们之前倒计时的例子一样。回想一下，异步编程的目标是实现更好的执行时间和响应性，为了实现这一点，任务切换事件应该发生在一个繁重且长时间运行的任务中。然而，这一要求取决于您的程序的具体情况，特别是协程、程序的任务队列和队列中的各个任务。

例如，我们程序的任务队列包括三个数字：`9637529763296797`、`427920331`和`157`；按顺序，我们可以将它们视为一个大任务、一个中等任务和一个小任务。为了提高响应性，我们希望在大任务期间切换任务，而不是在小任务期间。这种设置将允许在执行大任务时启动、处理和可能完成中等和小任务，即使大任务在程序的任务队列中处于前列。

然后，我们将考虑我们的`is_prime()`协程。在检查一些特定边界情况后，它通过`for`循环遍历输入整数平方根下的每个奇数，并测试输入与当前奇数的可除性。在这个长时间运行的`for`循环中，是切换任务的完美位置——即释放执行流程回事件循环。

然而，我们仍然需要决定在`for`循环中的哪些具体点实现任务切换事件。再次考虑任务队列中的各个任务，我们正在寻找一个在大任务中相当常见，在中等任务中不太常见，并且在小任务中不存在的点。我决定这一点是每 1,00,000 个数字周期，这满足我们的要求，我使用了`await asyncio.sleep(0)`命令来促进任务切换事件，如下所示：

```py
# Chapter09/example2.py

from math import sqrt
import asyncio

async def is_prime(x):
    print('Processing %i...' % x)

    if x < 2:
        print('%i is not a prime number.' % x)

    elif x == 2:
        print('%i is a prime number.' % x)

    elif x % 2 == 0:
        print('%i is not a prime number.' % x)

    else:
        limit = int(sqrt(x)) + 1
        for i in range(3, limit, 2):
            if x % i == 0:
                print('%i is not a prime number.' % x)
                return
            elif i % 100000 == 1:
                await asyncio.sleep(0)

        print('%i is a prime number.' % x)
```

最后，在我们的主程序（不要与`main()`协程混淆），我们创建事件循环并使用它来运行我们的`main()`协程，直到它完成执行：

```py
try:
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
except Exception as e:
    print('There was a problem:')
    print(str(e))
finally:
    loop.close()
```

正如您在上一章中看到的，通过脚本的这种异步版本实现了更好的响应性。具体来说，我们的程序现在在处理第一个大任务时不会像挂起一样，而是在完成执行大任务之前，会打印出其他较小任务的输出消息。我们的最终结果将类似于以下内容：

```py
Processing 9637529763296797...
Processing 427920331...
427920331 is a prime number.
Processing 157...
157 is a prime number.
9637529763296797 is a prime number.
```

# Python 3.7 的改进

截至 2018 年，Python 3.7 刚刚发布，带来了几个重大的新功能，例如数据类、有序字典、更好的时间精度等。异步编程和`asyncio`模块也得到了一些重要的改进。

首先，`async`和`await`现在在 Python 中是正式保留的关键字。虽然我们一直称它们为关键字，但事实上，Python 直到现在都没有将这些词视为保留关键字。这意味着在 Python 程序中既不能使用`async`也不能使用`await`来命名变量或函数。如果您正在使用 Python 3.7，请启动 Python 解释器并尝试使用这些关键字作为变量或函数名称，您应该会收到以下错误消息：

```py
>>> def async():
 File "<stdin>", line 1
 def async():
 ^
SyntaxError: invalid syntax
>>> await = 0
 File "<stdin>", line 1
 await = 0
 ^
SyntaxError: invalid syntax
```

Python 3.7 的一个重大改进是`asyncio`模块。具体来说，您可能已经注意到从我们之前的例子中，主程序通常包含大量样板代码来初始化和运行事件循环，这在所有异步程序中可能都是相同的：

```py
loop = asyncio.get_event_loop()
asyncio.run_until_complete(main())
```

在我们的程序中，`main()`是一个协程，`asyncio`允许我们使用`asyncio.run()`方法在事件循环中简单地运行它。这消除了 Python 异步编程中的重要样板代码。

因此，我们可以将前面的代码转换为 Python 3.7 中更简化的版本，如下所示：

```py
asyncio.run(main())
```

关于异步编程，Python 3.7 还实现了性能和使用便利方面的其他改进；但是，在本书中我们将不会讨论它们。

# 固有阻塞任务

在本章的第一个例子中，您看到异步编程可以为我们的 Python 程序提供更好的执行时间，但并非总是如此。仅有异步编程本身只能在所有处理任务都是非阻塞的情况下提供速度上的改进。然而，类似于并发和编程任务中固有的顺序性之间的比较，Python 中的一些计算任务是固有阻塞的，因此无法利用异步编程。

这意味着如果您的异步编程在某些协程中具有固有的阻塞任务，程序将无法从异步架构中获得额外的速度改进。虽然这些程序仍然会发生任务切换事件，从而提高程序的响应性，但指令不会重叠，因此也不会获得额外的速度。事实上，由于 Python 中异步编程的实现存在相当大的开销，我们的程序甚至可能需要更长的时间来完成执行，而不是原始的同步程序。

例如，让我们来比较一下我们的素数检查程序的两个版本在速度上的差异。由于程序的主要处理部分是`is_prime()`协程，它完全由数字计算组成，我们知道这个协程包含阻塞任务。因此，预期异步版本的运行速度会比同步版本慢。

转到代码存储库的`Chapter10`子文件夹，查看`example3.py`和`example4.py`文件。这些文件包含我们一直在看的同步和异步素数检查程序的相同代码，但额外添加了跟踪运行各自程序所需时间的功能。以下是我运行`synchronous`程序`example3.py`后的输出：

```py
> python example3.py
Processing 9637529763296797...
9637529763296797 is a prime number.
Processing 427920331...
427920331 is a prime number.
Processing 157...
157 is a prime number.
Took 5.60 seconds.
```

以下代码显示了我运行`asynchronous`程序`example4.py`后的输出：

```py
> python example4.py
Processing 9637529763296797...
Processing 427920331...
427920331 is a prime number.
Processing 157...
157 is a prime number.
9637529763296797 is a prime number.
Took 7.89 seconds.
```

虽然您收到的输出在运行每个程序所需的具体时间上可能有所不同，但应该是异步程序实际上比同步（顺序）程序运行时间更长。再次强调，这是因为我们的`is_prime()`协程中的数字计算任务是阻塞的，而我们的异步程序在执行时只是在这些任务之间切换，而不是重叠这些任务以获得额外的速度。在这种情况下，异步编程只能实现响应性。

然而，这并不意味着如果您的程序包含阻塞函数，异步编程就不可能。如前所述，如果未另行指定，异步程序中的所有执行都完全在同一线程和进程中进行，阻塞的 CPU 绑定任务可以阻止程序指令重叠。但是，如果任务分布到单独的线程/进程中，情况就不同了。换句话说，线程和多进程可以帮助具有阻塞指令的异步程序实现更好的执行时间。

# `concurrent.futures`作为解决阻塞任务的解决方案。

在本节中，我们将考虑另一种实现线程/多进程的方法：`concurrent.futures`模块，它被设计为实现异步任务的高级接口。具体来说，`concurrent.futures`模块与`asyncio`模块无缝配合，此外，它还提供了一个名为`Executor`的抽象类，其中包含实现异步线程和多进程的两个主要类的骨架（根据它们的名称建议）：`ThreadPoolExecutor`和`ProcessPoolExecutor`。

# 框架的变化

在我们深入讨论`concurrent.futures`的 API 之前，让我们先讨论一下异步线程/多进程的理论基础，以及它如何融入`asyncio`提供的异步编程框架。

提醒一下，我们的异步编程生态系统中有三个主要元素：事件循环、协程和它们对应的 future。在利用线程/多进程时，我们仍然需要事件循环来协调任务并处理它们返回的结果（future），因此这些元素通常与单线程异步编程保持一致。

至于协程，由于将异步编程与线程和多进程相结合的想法涉及通过在单独的线程和进程中执行它们来避免协程中的阻塞任务，因此协程不再必须被 Python 解释为实际的协程。相反，它们可以简单地成为传统的 Python 函数。

我们将需要实现的一个新元素是执行器，它可以促进线程或多进程；这可以是`ThreadPoolExecutor`类或`ProcessPoolExecutor`类的实例。现在，每当我们在事件循环中向任务队列添加任务时，我们还需要引用这个执行器，这样分离的任务将在不同的线程/进程中执行。这是通过`AbstractEventLoop.run_in_executor()`方法完成的，该方法接受一个执行器、一个协程（尽管它不必是一个真正的协程），以及要在单独的线程/进程中执行的协程的参数。我们将在下一节中看到这个 API 的示例。

# Python 示例

让我们看一下`concurrent.futures`模块的具体实现。回想一下，在本章的第一个示例（倒计时示例）中，阻塞的`time.sleep()`函数阻止了我们的异步程序真正成为异步，必须用其非阻塞版本`asyncio.sleep()`替换。现在，我们在单独的线程或进程中执行各自的倒计时，这意味着阻塞的`time.sleep()`函数不会在执行我们的程序异步方面造成任何问题。

导航到`Chapter10/example5.py`文件，如下所示：

```py
# Chapter10/example5.py

from concurrent.futures import ThreadPoolExecutor
import asyncio
import time

def count_down(name, delay):
    indents = (ord(name) - ord('A')) * '\t'

    n = 3
    while n:
        time.sleep(delay)

        duration = time.perf_counter() - start
        print('-' * 40)
        print('%.4f \t%s%s = %i' % (duration, indents, name, n))

        n -= 1

async def main():
    futures = [loop.run_in_executor(
        executor,
        count_down,
        *args
    ) for args in [('A', 1), ('B', 0.8), ('C', 0.5)]]

    await asyncio.gather(*futures)

    print('-' * 40)
    print('Done.')

start = time.perf_counter()
executor = ThreadPoolExecutor(max_workers=3)
loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```

注意`count_down()`被声明为一个典型的非协程 Python 函数。在`main()`中，仍然是一个协程，我们为事件循环声明了我们的任务队列。同样，在这个过程中，我们使用`run_in_executor()`方法，而不是在单线程异步编程中使用的`create_task()`方法。在我们的主程序中，我们还需要初始化一个执行器，这种情况下，它是来自`concurrent.futures`模块的`ThreadPoolExecutor`类的实例。

使用线程和多进程的决定，正如我们在之前的章节中讨论的那样，取决于程序的性质。在这里，我们需要在单独的协程之间共享`start`变量（保存程序开始执行的时间），以便它们可以执行倒计时的动作；因此，选择了多线程而不是多进程。

运行脚本后，您的输出应该类似于以下内容：

```py
> python example5.py
----------------------------------------
0.5033                 C = 3
----------------------------------------
0.8052         B = 3
----------------------------------------
1.0052 A = 3
----------------------------------------
1.0079                 C = 2
----------------------------------------
1.5103                 C = 1
----------------------------------------
1.6064         B = 2
----------------------------------------
2.0093 A = 2
----------------------------------------
2.4072         B = 1
----------------------------------------
3.0143 A = 1
----------------------------------------
Done.
```

这个输出与我们从纯`asyncio`支持的异步程序中获得的输出是相同的。因此，即使有一个阻塞处理函数，我们也能够使我们的程序的执行异步化，通过`concurrent.futures`模块实现了线程。

现在让我们将相同的概念应用到我们的素数检查问题上。我们首先将我们的`is_prime()`协程转换为其原始的非协程形式，并再次在单独的进程中执行它（这比线程更可取，因为`is_prime()`函数是一个密集的数值计算任务）。使用原始版本的`is_prime()`的另一个好处是，我们不必执行我们在单线程异步程序中的任务切换条件的检查。

```py
elif i % 100000 == 1:
    await asyncio.sleep(0)
```

这也将为我们提供显著的加速。让我们看一下`Chapter10/example6.py`文件，如下所示：

```py
# Chapter10/example6.py

from math import sqrt
import asyncio
from concurrent.futures import ProcessPoolExecutor
from timeit import default_timer as timer

#async def is_prime(x):
def is_prime(x):
    print('Processing %i...' % x)

    if x < 2:
        print('%i is not a prime number.' % x)

    elif x == 2:
        print('%i is a prime number.' % x)

    elif x % 2 == 0:
        print('%i is not a prime number.' % x)

    else:
        limit = int(sqrt(x)) + 1
        for i in range(3, limit, 2):
            if x % i == 0:
                print('%i is not a prime number.' % x)
                return

        print('%i is a prime number.' % x)

async def main():

    task1 = loop.run_in_executor(executor, is_prime, 9637529763296797)
    task2 = loop.run_in_executor(executor, is_prime, 427920331)
    task3 = loop.run_in_executor(executor, is_prime, 157)

    await asyncio.gather(*[task1, task2, task3])

if __name__ == '__main__':
    try:
        start = timer()

        executor = ProcessPoolExecutor(max_workers=3)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())

        print('Took %.2f seconds.' % (timer() - start))

    except Exception as e:
        print('There was a problem:')
        print(str(e))

    finally:
        loop.close()
```

运行脚本后，我得到了以下输出：

```py
> python example6.py
Processing 9637529763296797...
Processing 427920331...
Processing 157...
157 is a prime number.
427920331 is a prime number.
9637529763296797 is a prime number.
Took 5.26 seconds.
```

再次强调，您的执行时间很可能与我的不同，尽管我们的原始、同步版本所花费的时间应该始终与单线程异步版本和多进程异步版本的比较一致：原始的同步版本所花费的时间少于单线程异步版本，但多于多进程异步版本。换句话说，通过将多进程与异步编程结合起来，我们既得到了异步编程的一致响应性，又得到了多进程的速度提升。

# 总结

在本章中，您了解了异步编程，这是一种利用协调计算任务以重叠等待和处理时间的编程模型。异步程序有三个主要组件：事件循环、协程和期货。事件循环负责使用其任务队列调度和管理协程。协程是要异步执行的计算任务；每个协程都必须在其函数内部指定它将在何处将执行流返回给事件循环（即任务切换事件）。期货是包含从协程获得的结果的占位符对象。

`asyncio`模块与 Python 关键字`async`和`await`一起，提供了易于使用的 API 和直观的框架来实现异步程序；此外，该框架使异步代码与同步代码一样易读，这在异步编程中通常是相当罕见的。然而，我们不能仅使用`asyncio`模块在阻塞计算任务上应用单线程异步编程。解决此问题的方法是`concurrent.futures`模块，它提供了一个高级 API 来实现异步线程和多进程，并且可以与`asyncio`模块一起使用。

在下一章中，我们将讨论异步编程的最常见应用之一，即**传输控制协议**（**TCP**），作为服务器-客户端通信的手段。您将了解概念的基础，它如何利用异步编程，并如何在 Python 中实现它。

# 问题

+   什么是异步编程？它提供了哪些优势？

+   异步程序中的主要元素是什么？它们如何相互交互？

+   `async`和`await`关键字是什么？它们有什么作用？

+   `asyncio`模块在实现异步编程方面提供了哪些选项？

+   Python 3.7 中关于异步编程的改进是什么？

+   什么是阻塞函数？它们为传统的异步编程带来了什么问题？

+   `concurrent.futures`如何为异步编程中的阻塞函数提供解决方案？它提供了哪些选项？

# 进一步阅读

有关更多信息，您可以参考以下链接：

+   Zaccone, Giancarlo. *Python Parallel Programming Cookbook*. Packt Publishing Ltd, 2015

+   *使用 asyncio 在 Python 中进行异步编程的指南* ([medium.freecodecamp.org/a-guide-to-asynchronous-programming-in-python-with-asyncio](https://medium.freecodecamp.org/a-guide-to-asynchronous-programming-in-python-with-asyncio-232e2afa44f6)), Mariia Yakimova

+   *AsyncIO for the Working Python Developer* ([hackernoon.com/asyncio-for-the-working-python-developer](https://hackernoon.com/asyncio-for-the-working-python-developer-5c468e6e2e8e)), Yeray Diaz

+   Python 文档。任务和协程。[docs.python.org/3/library/asyncio](https://docs.python.org/3/library/asyncio.html)

+   *Modern Concurrency*, ([speakerdeck.com/pybay/2017-luciano-ramalho-modern-concurrency](https://speakerdeck.com/pybay/2017-luciano-ramalho-modern-concurrency)), PyBay 2017
