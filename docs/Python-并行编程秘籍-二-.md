# Python 并行编程秘籍（二）

> 原文：[`zh.annas-archive.org/md5/e472b7edae31215ac8e4e5f1e5748012`](https://zh.annas-archive.org/md5/e472b7edae31215ac8e4e5f1e5748012)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：基于进程的并行处理

在上一章中，我们学习了如何使用线程来实现并发应用程序。本章将讨论我们在第一章中介绍的基于进程的方法，*使用并行计算和 Python 入门*。特别是，本章的重点是 Python 的`multiprocessing`模块。

Python 的`multiprocessing`模块是语言标准库的一部分，实现了共享内存编程范式，即一个或多个处理器可以访问共享内存的系统的编程。

在本章中，我们将涵盖以下内容：

+   理解 Python 的`multiprocessing`模块

+   生成一个进程

+   给进程命名

+   在后台运行进程

+   杀死进程

+   在子类中定义一个进程

+   使用队列交换对象

+   使用管道交换对象

+   同步进程

+   管理进程之间的状态

+   使用进程池

# 理解 Python 的多进程模块

Python 的`multiprocessing`文档（[`docs.python.org/2.7/library/multiprocessing.html#introduction`](https://docs.python.org/2.7/library/multiprocessing.html#introduction)）清楚地提到，这个包中的所有功能都需要`main`模块对子模块可导入（[`docs.python.org/3.3/library/multiprocessing.html`](https://docs.python.org/3.3/library/multiprocessing.html)）。

`__main__`模块在 IDLE 中对子模块不可导入，即使你在 IDLE 中以文件形式运行脚本。为了得到正确的结果，我们将从命令提示符中运行所有的例子：

```py
> python multiprocessing_example.py
```

这里，`multiprocessing_example.py`是脚本的名称。

# 生成一个进程

生成进程是从*父进程*创建*子进程*。后者会异步地继续执行或等待子进程结束。

# 准备就绪

`multiprocessing`库允许通过以下步骤生成进程：

1.  *定义*`process`对象。

1.  *调用*进程的`start()`方法来运行它。

1.  *调用*进程的`join()`方法。它会等待直到进程完成工作然后退出。

# 如何做...

让我们看看以下步骤：

1.  要创建一个进程，我们需要使用以下命令导入`multiprocessing`模块：

```py
import multiprocessing
```

1.  每个进程都与`myFunc(i)`函数相关联。这个函数输出从`0`到`i`的数字，其中`i`是与进程编号相关联的 ID： 

```py
def myFunc(i):
 print ('calling myFunc from process n°: %s' %i)
 for j in range (0,i):
 print('output from myFunc is :%s' %j)

```

1.  然后，我们用`myFunc`作为`target`函数定义`process`对象：

```py
if __name__ == '__main__':
 for i in range(6):
 process = multiprocessing.Process(target=myFunc, args=(i,))
```

1.  最后，我们在创建的进程上调用`start`和`join`方法：

```py
 process.start()
 process.join()
```

没有`join`方法，子进程不会结束，必须手动杀死。

# 工作原理...

在本节中，我们看到了如何从父进程开始创建进程。这个特性被称为*生成进程*。

Python 的`multiprocessing`库通过以下三个简单步骤轻松管理进程。第一步是通过`multiprocessing`类方法`Process`定义进程：

```py
process = multiprocessing.Process(target=myFunc, args=(i,))
```

`Process`方法有一个要生成的函数`myFunc`和函数本身的任何参数作为参数。

以下两个步骤是执行和退出进程所必需的：

```py
 process.start()
 process.join()
```

要运行进程并显示结果，让我们打开命令提示符，最好是在包含示例文件（`spawning_processes.py`）的相同文件夹中，然后输入以下命令：

```py
> python spawning_processes.py
```

对于每个创建的进程（总共有六个），显示目标函数的输出。记住这只是一个从`0`到进程 ID 的索引的简单计数器：

```py
calling myFunc from process n°: 0
calling myFunc from process n°: 1
output from myFunc is :0
calling myFunc from process n°: 2
output from myFunc is :0
output from myFunc is :1
calling myFunc from process n°: 3
output from myFunc is :0
output from myFunc is :1
output from myFunc is :2
calling myFunc from process n°: 4
output from myFunc is :0
output from myFunc is :1
output from myFunc is :2
output from myFunc is :3
calling myFunc from process n°: 5
output from myFunc is :0
output from myFunc is :1
output from myFunc is :2
output from myFunc is :3
output from myFunc is :4
```

# 还有更多...

这再次提醒我们在主要部分内实例化`Process`对象的重要性：这是因为创建的子进程导入包含`target`函数的脚本文件。然后，通过在此块内实例化`process`对象，我们防止了这种实例化的无限递归调用。

使用有效的解决方法在不同的脚本中定义`target`函数，即`myFunc.py`：

```py
def myFunc(i):
 print ('calling myFunc from process n°: %s' %i)
 for j in range (0,i):
 print('output from myFunc is :%s' %j)
 return
```

包含进程实例的`main`程序在第二个文件（`spawning_processes_namespace.py`）中定义：

```py
import multiprocessing
from myFunc import myFunc

if __name__ == '__main__':
 for i in range(6):
 process = multiprocessing.Process(target=myFunc, args=(i,))
 process.start()
 process.join()
```

要运行此示例，请输入以下命令：

```py
> python spawning_processes_names.py
```

输出与上一个示例相同。

# 另请参阅

`multiprocessing`库的官方指南可以在[`docs.python.org/3/`](https://docs.python.org/3/)找到。

# 给进程命名

在前面的示例中，我们确定了进程以及如何将变量传递给目标函数。然而，将进程与名称关联起来非常有用，因为调试应用程序需要对进程进行良好标记和识别。

# 准备就绪

在代码的某个时刻，了解当前正在执行的进程可能是至关重要的。为此，`multiprocessing`库提供了`current_process()`方法，该方法使用`name`属性来标识当前正在运行的进程。在接下来的部分中，我们将学习这个主题。

# 如何做...

让我们执行以下步骤：

1.  两个进程的`target`函数都是`myFunc`函数。它通过评估`multiprocessing.current_process().name`方法输出进程名称：

```py
import multiprocessing
import time

def myFunc():
 name = multiprocessing.current_process().name
 print ("Starting process name = %s \n" %name)
 time.sleep(3)
 print ("Exiting process name = %s \n" %name)
```

1.  然后，我们通过实例化`name`参数和`process_with_default_name`来创建`process_with_name`：

```py
if __name__ == '__main__':
 process_with_name = multiprocessing.Process\
 (name='myFunc process',\
 target=myFunc)

 process_with_default_name = multiprocessing.Process\
 (target=myFunc)
```

1.  最后，启动进程，然后加入：

```py
 process_with_name.start()
 process_with_default_name.start()
 process_with_name.join()
 process_with_default_name.join()
```

# 它是如何工作的...

在`main`程序中，使用相同的目标函数`myFunc`创建进程。这个函数只是简单地打印进程名称。

要运行示例，请打开命令提示符并输入以下命令：

```py
> python naming_processes.py
```

输出如下：

```py
Starting process name = myFunc process
Starting process name = Process-2

Exiting process name = Process-2
Exiting process name = myFunc process
```

# 还有更多...

主 Python 进程是`multiprocessing.process._MainProcess`，而子进程是`multiprocessing.process.Process`。可以通过简单地输入以下内容进行测试：

```py
>>> import multiprocessing
>>> multiprocessing.current_process().name
'MainProcess'
```

# 另请参阅

有关此主题的更多信息，请访问[`doughellmann.com/blog/2012/04/30/determining-the-name-of-a-process-from-python/`](https://doughellmann.com/blog/2012/04/30/determining-the-name-of-a-process-from-python/)。

# 在后台运行进程

在后台运行是一种典型的执行模式，适用于一些不需要用户存在或干预的程序，并且可能与其他程序的执行同时进行（因此，只有在多任务系统中才可能），导致用户对此毫不知情。后台程序通常执行长时间或耗时的任务，如点对点文件共享程序或文件系统的碎片整理。许多操作系统进程也在后台运行。

在 Windows 中，以这种模式运行的程序（如扫描防病毒软件或操作系统更新）通常会在系统托盘（桌面旁边的系统时钟区域）放置一个图标，以便通知它们的活动，并采取减少资源使用的行为，以免干扰用户的交互活动，如减慢或引起中断。在 Unix 和类 Unix 系统中，运行在后台的进程称为**守护进程**。使用任务管理器可以突出显示所有运行的程序，包括后台程序。

# 准备就绪

`multiprocessing`模块允许通过守护选项运行后台进程。在以下示例中，定义了两个进程：

+   `background_process`，其`daemon`参数设置为`True`

+   `NO_background_process`，其`daemon`参数设置为`False`

# 如何做...

在下面的例子中，我们实现了一个目标函数，即`foo`，它显示从`0`到`4`的数字**如果**子进程在**后台**；否则，它打印从`5`到`9`的数字：

1.  让我们导入相关的库：

```py
import multiprocessing
import time
```

1.  然后，我们定义`foo()`函数。如前所述，打印的数字取决于`name`参数的值：

```py
def foo():
 name = multiprocessing.current_process().name
 print ("Starting %s \n" %name)
 if name == 'background_process':
 for i in range(0,5):
 print('---> %d \n' %i)
 time.sleep(1)
 else:
 for i in range(5,10):
 print('---> %d \n' %i)
 time.sleep(1)
 print ("Exiting %s \n" %name)
```

1.  最后，我们定义以下进程：`background_process`和`NO_background_process`。注意，`daemon`参数设置为这两个进程：

```py
if __name__ == '__main__':
 background_process = multiprocessing.Process\
 (name='background_process',\
 target=foo)
 background_process.daemon = True

 NO_background_process = multiprocessing.Process\
 (name='NO_background_process',\
 target=foo)

 NO_background_process.daemon = False

 background_process.start()
 NO_background_process.start()
```

# 它是如何工作的...

注意，进程的`daemon`参数定义了进程是否应该在后台运行。要运行这个例子，输入以下命令：

```py
> python run_background_processes.py
```

输出清楚地只报告了`NO_background_process`的输出：

```py
Starting NO_background_process
---> 5

---> 6

---> 7

---> 8

---> 9
Exiting NO_background_process
```

更改`background_process`的`daemon`参数设置为`False`：

```py
background_process.daemon = False
```

要运行这个例子，输入以下内容：

```py
C:\>python run_background_processes_no_daemons.py
```

输出报告了`background_process`和`NO_background_process`进程的执行：

```py
Starting NO_background_process
Starting background_process
---> 5

---> 0
---> 6

---> 1
---> 7

---> 2
---> 8

---> 3
---> 9

---> 4

Exiting NO_background_process
Exiting background_process
```

# 另请参阅

可以在[`janakiev.com/til/python-background/`](https://janakiev.com/til/python-background/)找到有关如何在 Linux 中后台运行 Python 脚本的代码片段。

# 终止进程

没有完美的软件，即使在最好的应用程序中，也可能存在导致阻塞应用程序的错误，这就是为什么现代操作系统开发了几种方法来终止应用程序的进程，以释放系统资源并允许用户尽快将其用于其他操作。本节将向您展示如何在多进程应用程序中终止进程。

# 准备工作

可以使用`terminate`方法立即终止一个进程。此外，我们使用`is_alive`方法来跟踪进程是否存活。

# 如何做...

以下步骤允许我们执行该过程：

1.  让我们导入相关的库：

```py
import multiprocessing
import time
```

1.  然后，实现一个简单的`target`函数。在这个例子中，`target`函数`foo()`打印前`10`个数字：

```py
def foo():
 print ('Starting function')
 for i in range(0,10):
 print('-->%d\n' %i)
 time.sleep(1)
 print ('Finished function')
```

1.  在`main`程序中，我们创建一个进程，通过`is_alive`方法监视其生命周期；然后，我们通过调用`terminate`结束它：

```py
if __name__ == '__main__':
 p = multiprocessing.Process(target=foo)
 print ('Process before execution:', p, p.is_alive())
 p.start()
 print ('Process running:', p, p.is_alive())
 p.terminate()
 print ('Process terminated:', p, p.is_alive())
 p.join()
 print ('Process joined:', p, p.is_alive())
```

1.  然后，当进程完成时，我们验证状态码并读取`ExitCode`进程的属性：

```py
 print ('Process exit code:', p.exitcode)
```

1.  `ExitCode`的可能值如下：

+   `== 0`：没有产生错误。

+   `> 0`：进程出现错误并退出该代码。

+   `< 0`：进程被`-1 * ExitCode`的信号终止。

# 它是如何工作的...

示例代码由一个目标函数`foo()`组成，其任务是在屏幕上打印出前`10`个整数。在`main`程序中，执行该进程，然后通过`terminate`指令终止它。然后加入该进程并确定`ExitCode`。

要运行代码，请输入以下命令：

```py
> python killing_processes.py
```

然后，我们得到了以下输出：

```py
Process before execution: <Process(Process-1, initial)> False
Process running: <Process(Process-1, started)> True
Process terminated: <Process(Process-1, started)> True
Process joined: <Process(Process-1, stopped[SIGTERM])> False
Process exit code: -15
```

注意，`ExitCode`代码的输出值等于`**-**15`。`-15`的负值表示子进程被中断信号终止，该信号由数字`15`标识。

# 另请参阅

在 Linux 机器上，可以通过以下教程简单地识别并终止 Python 进程：[`www.cagrimmett.com/til/2016/05/06/killing-rogue-python-processes.html`](http://www.cagrimmett.com/til/2016/05/06/killing-rogue-python-processes.html)。

# 在子类中定义进程

`multiprocessing`模块提供了对进程管理功能的访问。在本节中，我们将学习如何在`multiprocessing.Process`类的子类中定义一个进程。

# 准备工作

要实现一个多进程的自定义子类，我们需要做以下几件事：

+   *定义*`multiprocessing.Process`类的子类，重新定义`run()`方法。

+   *覆盖*`_init__(self [,args])`方法以添加额外的参数，如果需要的话。

+   *覆盖*`run(self [,args])`方法来实现`Process`在启动时应该做什么。

一旦你创建了新的`Process`子类，你可以创建它的一个实例，然后通过调用`start`方法来启动，这将依次调用`run`方法。

# 如何做...

只需考虑一个非常简单的例子，如下所示：

1.  首先导入相关的库：

```py
import multiprocessing
```

1.  然后，定义一个子类`MyProcess`，只覆盖`run`方法，该方法返回进程的名称：

```py
class MyProcess(multiprocessing.Process):

 def run(self):
 print ('called run method by %s' %self.name)
 return
```

1.  在`main`程序中，我们定义了`10`个进程的子类：

```py
if __name__ == '__main__':
 for i in range(10):
 process = MyProcess()
 process.start()
 process.join()
```

# 工作原理...

每个过程子类由扩展`Process`类并覆盖`run()`方法的类表示。这个方法是`Process`的起点：

```py
class MyProcess (multiprocessing.Process):
 def run(self):
 print ('called run method in process: %s' %self.name)
 return
```

在`main`程序中，我们创建了`MyProcess()`类型的几个对象。当调用`start()`方法时，线程的执行就开始了：

```py
p = MyProcess()
p.start()
```

`join()`命令只处理进程的终止。要从命令提示符运行脚本，请输入以下命令：

```py
> python process_in_subclass.py
```

输出如下所示：

```py
called run method by MyProcess-1
called run method by MyProcess-2
called run method by MyProcess-3
called run method by MyProcess-4
called run method by MyProcess-5
called run method by MyProcess-6
called run method by MyProcess-7
called run method by MyProcess-8
called run method by MyProcess-9
called run method by MyProcess-10
```

# 还有更多...

在面向对象编程中，子类是继承自超类的所有属性的类，无论它们是对象还是方法。子类的另一个名称是*派生类*。*继承*是指示子类或派生类继承父类或超类属性的特定术语。

你可以把子类看作是其超类的一个特定类型；事实上，它可以使用方法和/或属性，并通过*覆盖*重新定义它们。

# 另请参阅

有关类定义技术的更多信息可以在[`buildingskills.itmaybeahack.com/book/python-2.6/html/p03/p03c02_adv_class.html`](http://buildingskills.itmaybeahack.com/book/python-2.6/html/p03/p03c02_adv_class.html)找到。

# 使用队列交换数据

*队列*是一种**先进先出**（**FIFO**）类型的数据结构（第一个输入是第一个退出）。一个实际的例子是排队等待服务，如在超市付款，或者在理发店理发。理想情况下，你会按照你的出现顺序被服务。这正是 FIFO 队列的工作原理。

# 准备就绪

在本节中，我们将向您展示如何使用队列解决*生产者-消费者*问题，这是*进程同步*的一个经典例子。

**生产者-消费者**问题描述了两个*进程*：一个是*生产者*，另一个是*消费者*，它们共享一个**固定大小**的**公共缓冲区**。

*生产者*的任务是不断生成数据并将其存入缓冲区。与此同时，*消费者*将使用生成的数据，不时地从缓冲区中移除。问题在于确保如果缓冲区已满，生产者不会处理新数据，如果缓冲区为空，消费者不会寻找数据。生产者的解决方案是在缓冲区已满时暂停执行。

一旦消费者从缓冲区中取出一个项目，生产者就会醒来并开始重新填充缓冲区。同样，如果缓冲区为空，消费者将暂停。一旦生产者将数据下载到缓冲区中，消费者就会醒来。

# 如何做...

这个解决方案可以通过进程之间的通信策略、共享内存或消息传递来实现。一个不正确的解决方案可能导致死锁，即两个进程都在等待被唤醒：

```py
import multiprocessing
import random
import time
```

让我们按照以下步骤执行：

1.  `producer`类负责使用`put`方法在队列中输入`10`个项目：

```py
class producer(multiprocessing.Process):
 def __init__(self, queue):
 multiprocessing.Process.__init__(self)
 self.queue = queue

 def run(self) :
 for i in range(10):
 item = random.randint(0, 256)
 self.queue.put(item) 
 print ("Process Producer : item %d appended \
 to queue %s"\
 % (item,self.name))
 time.sleep(1)
 print ("The size of queue is %s"\
 % self.queue.qsize())
```

1.  `consumer`类的任务是从队列中移除项目（使用`get`方法）并验证队列不为空。如果发生这种情况，那么`while`循环内的流程将以`break`语句结束：

```py
class consumer(multiprocessing.Process):
 def __init__(self, queue):
 multiprocessing.Process.__init__(self)
 self.queue = queue

 def run(self):
 while True:
 if (self.queue.empty()):
 print("the queue is empty")
 break
 else :
 time.sleep(2)
 item = self.queue.get()
 print ('Process Consumer : item %d popped \
 from by %s \n'\
 % (item, self.name))
 time.sleep(1)
```

1.  `multiprocessing`类在`main`程序中实例化了它的`queue`对象：

```py
if __name__ == '__main__':
 queue = multiprocessing.Queue()
 process_producer = producer(queue)
 process_consumer = consumer(queue)
 process_producer.start()
 process_consumer.start()
 process_producer.join()
 process_consumer.join()
```

# 工作原理...

在`main`程序中，我们使用`multiprocessing.Queue`对象定义队列。然后，将其作为参数传递给`producer`和`consumer`进程：

```py
 queue = multiprocessing.Queue()
 process_producer = producer(queue)
 process_consumer = consumer(queue)
```

在`producer`类中，使用`queue.put`方法将新项目附加到队列中：

```py
self.queue.put(item) 
```

在`consumer`类中，使用`queue.get`方法弹出项目：

```py
self.queue.get()
```

通过输入以下命令来执行代码：

```py
> python communicating_with_queue.py
```

以下输出报告了生产者和消费者之间的交互：

```py
Process Producer : item 79 appended to queue producer-1
The size of queue is 1
Process Producer : item 50 appended to queue producer-1
The size of queue is 2
Process Consumer : item 79 popped from by consumer-2
Process Producer : item 33 appended to queue producer-1
The size of queue is 2
Process Producer : item 57 appended to queue producer-1
The size of queue is 3
Process Producer : item 227 appended to queue producer-1
Process Consumer : item 50 popped from by consumer-2
The size of queue is 3
Process Producer : item 98 appended to queue producer-1
The size of queue is 4
Process Producer : item 64 appended to queue producer-1
The size of queue is 5
Process Producer : item 182 appended to queue producer-1
Process Consumer : item 33 popped from by consumer-2
The size of queue is 5
Process Producer : item 206 appended to queue producer-1
The size of queue is 6
Process Producer : item 214 appended to queue producer-1
The size of queue is 7
Process Consumer : item 57 popped from by consumer-2
Process Consumer : item 227 popped from by consumer-2
Process Consumer : item 98 popped from by consumer-2
Process Consumer : item 64 popped from by consumer-2
Process Consumer : item 182 popped from by consumer-2
Process Consumer : item 206 popped from by consumer-2
Process Consumer : item 214 popped from by consumer-2
the queue is empty
```

# 还有更多...

队列有`JoinableQueue`子类。这提供了以下方法：

+   `task_done()`: 此方法表示任务已完成，例如，在使用`get()`方法从队列中获取项目后。因此，`task_done()`只能由队列消费者使用。

+   `join()`: 此方法阻塞进程，直到队列中的所有项目都已完成并被处理。

# 另请参阅

有一个关于如何使用队列的好教程，可以在[`www.pythoncentral.io/use-queue-beginners-guide/`](https://www.pythoncentral.io/use-queue-beginners-guide/)找到。

# 使用管道交换对象

*管道*执行以下操作：

+   它返回一对由管道连接的连接对象。

+   每个连接对象都必须有发送/接收方法来在进程之间进行通信。

# 准备工作

`multiprocessing`库允许您使用`multiprocessing.Pipe(duplex)`函数实现管道数据结构。这将返回一对对象，`(conn1, conn2)`，它们代表管道的端点。

`duplex`参数确定了最后一种情况的管道是双向的（即`duplex = True`）还是单向的（即`duplex = False`）。`conn1`只能用于接收消息，`conn2`只能用于发送消息。

现在，让我们看看如何使用管道交换对象。

# 如何做...

这是一个管道的简单示例。我们有一个进程管道，输出从`0`到`9`的数字，还有一个进程管道，接收这些数字并对其进行平方处理：

1.  让我们导入`multiprocessing`库：

```py
import multiprocessing
```

1.  `pipe`函数返回一对由*双向*管道连接的连接对象。在示例中，`out_pipe`包含了由`create_items`的`target`函数生成的从`0`到`9`的数字：

```py
def create_items(pipe):
 output_pipe, _ = pipe
 for item in range(10):
 output_pipe.send(item)
 output_pipe.close()
```

1.  `multiply_items`函数基于两个管道`pipe_1`和`pipe_2`：

```py
 def multiply_items(pipe_1, pipe_2):
 close, input_pipe = pipe_1
 close.close()
 output_pipe, _ = pipe_2
 try:
 while True:
 item = input_pipe.recv()
```

1.  此函数返回每个管道元素的乘积：

```py
 output_pipe.send(item * item)
 except EOFError:
 output_pipe.close()
```

1.  在`main`程序中，定义了`pipe_1`和`pipe_2`：

```py
if __name__== '__main__':
```

1.  首先，处理从`0`到`9`的数字的`pipe_1`：

```py
 pipe_1 = multiprocessing.Pipe(True)
 process_pipe_1 = \
 multiprocessing.Process\
 (target=create_items, args=(pipe_1,))
 process_pipe_1.start()
```

1.  然后，处理`pipe_2`，它从`pipe_1`中取出数字并对其进行平方处理：

```py
 pipe_2 = multiprocessing.Pipe(True)
 process_pipe_2 = \
 multiprocessing.Process\
 (target=multiply_items, args=(pipe_1, pipe_2,))
 process_pipe_2.start()
```

1.  关闭进程：

```py
 pipe_1[0].close()
 pipe_2[0].close()
```

1.  打印出结果：

```py
 try:
 while True:
 print (pipe_2[1].recv())
 except EOFError:
 print("End")
```

# 工作原理...

基本上，两个管道`pipe_1`和`pipe_2`是由`multiprocessing.Pipe(True)`语句创建的：

```py
pipe_1 = multiprocessing.Pipe(True)
pipe_2 = multiprocessing.Pipe(True)
```

第一个管道`pipe_1`只是创建了一个从`0`到`9`的整数列表，而第二个管道`pipe_2`则处理了`pipe_1`创建的列表的每个元素，计算了每个元素的平方值：

```py
process_pipe_2 = \
 multiprocessing.Process\
 (target=multiply_items, args=(pipe_1, pipe_2,))
```

因此，两个进程都已关闭：

```py
pipe_1[0].close()
pipe_2[0].close()
```

最终结果被打印出来：

```py
print (pipe_2[1].recv())
```

通过输入以下命令来执行代码：

```py
> python communicating_with_pipe.py
```

以下结果显示了前`9`个数字的平方：

```py
0
1
4
9
16
25
36
49
64
81
```

# 还有更多...

如果您需要超过两个点进行通信，则使用`Queue()`方法。但是，如果您需要绝对的性能，则`Pipe()`方法要快得多，因为`Queue()`是建立在`Pipe()`之上的**。**

# 另请参阅

有关 Python 和管道的更多信息，请访问[`www.python-course.eu/pipes.php`](https://www.python-course.eu/pipes.php%0d)。

# 同步进程

多个进程可以共同执行给定的任务。通常，它们共享数据。重要的是，各个进程对共享数据的访问不会产生不一致的数据。因此，通过共享数据合作的进程必须以有序的方式行事，以便该数据可被访问。同步原语与库和线程中遇到的非常相似。

同步原语如下：

+   **锁**：此对象可以处于锁定或解锁状态。锁定对象有两种方法，`acquire()`和`release()`，用于管理对共享资源的访问。

+   **事件**：此对象实现进程之间的简单通信；一个进程发出信号，其他进程等待它。事件对象有两种方法，`set()`和`clear()`，用于管理自己的内部标志。

+   **条件**：此对象用于在顺序或并行进程中同步工作流的部分。它有两种基本方法：`wait()`用于等待条件，`notify_all()`用于通知应用的条件。

+   **信号量**：用于共享公共资源，例如支持固定数量的同时连接。

+   **RLock**：这定义了*递归锁*对象。RLock 的方法和功能与`threading`模块相同。

+   **Barrier**：这将程序分为阶段，因为它要求所有进程在继续之前都要到达屏障。在屏障之后执行的代码不能与屏障之前执行的代码并发。

# 准备就绪

Python 中的*Barrier*对象用于等待固定数量的线程执行完毕，然后给定线程才能继续执行程序。

以下示例显示了如何使用`barrier()`对象同步同时进行的任务。

# 如何做...

让我们考虑四个进程，其中进程`p1`和进程`p2`由一个屏障语句管理，而进程`p3`和进程`p4`没有同步指令。

为了做到这一点，请执行以下步骤：

1.  导入相关库：

```py
import multiprocessing
from multiprocessing import Barrier, Lock, Process
from time import time
from datetime import datetime
```

1.  `test_with_barrier`函数执行屏障的**`wait()`**方法：

```py
def test_with_barrier(synchronizer, serializer):
 name = multiprocessing.current_process().name
 synchronizer.wait()
 now = time()
```

1.  当两个进程调用`wait()`方法时，它们会同时被释放：

```py
with serializer:
 print("process %s ----> %s" \
 %(name,datetime.fromtimestamp(now)))

def test_without_barrier():
 name = multiprocessing.current_process().name
 now = time()
 print("process %s ----> %s" \
 %(name ,datetime.fromtimestamp(now)))
```

1.  在`main`程序中，我们创建了四个进程。但是，我们还需要一个屏障和锁原语。`Barrier`语句中的`2`参数代表要管理的进程总数：

```py
if __name__ == '__main__':
 synchronizer = Barrier(2)
 serializer = Lock()
 Process(name='p1 - test_with_barrier'\
 ,target=test_with_barrier,\
 args=(synchronizer,serializer)).start()
 Process(name='p2 - test_with_barrier'\
 ,target=test_with_barrier,\
 args=(synchronizer,serializer)).start()
 Process(name='p3 - test_without_barrier'\
 ,target=test_without_barrier).start()
 Process(name='p4 - test_without_barrier'\
 ,target=test_without_barrier).start()
```

# 工作原理...

`Barrier`对象提供了 Python 同步技术之一，单个或多个线程在一组活动中等待，然后一起取得进展。

在`main`程序中，通过以下语句定义了`Barrier`对象（即`synchronizer`）：

```py
synchronizer = Barrier(2)
```

请注意，括号内的数字`2`表示屏障应该等待的进程数。

然后，我们实现了一组四个进程，但只针对`p1`和`p2`进程。请注意，`synchronizer`作为参数传递：

```py
Process(name='p1 - test_with_barrier'\
 ,target=test_with_barrier,\
 args=(synchronizer,serializer)).start()
Process(name='p2 - test_with_barrier'\
 ,target=test_with_barrier,\
 args=(synchronizer,serializer)).start()
```

实际上，在`test_with_barrier`函数的主体中，使用了屏障的`wait()`方法来同步进程：

```py
synchronizer.wait()
```

通过运行脚本，我们可以看到`p1`和`p2`进程按预期打印出相同的时间戳：

```py
> python processes_barrier.py
process p4 - test_without_barrier ----> 2019-03-03 08:58:06.159882
process p3 - test_without_barrier ----> 2019-03-03 08:58:06.144257
process p1 - test_with_barrier ----> 2019-03-03 08:58:06.175505
process p2 - test_with_barrier ----> 2019-03-03 08:58:06.175505
```

# 还有更多...

以下图表显示了屏障如何与两个进程一起工作：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/f9077bdf-036b-4f0e-90ea-0ddfd80fc58f.png)

使用屏障进行进程管理

# 另请参阅

请阅读[`pymotw.com/2/multiprocessing/communication.html`](https://pymotw.com/2/multiprocessing/communication.html)以获取更多进程同步示例。

# 使用进程池

进程池机制允许在多个输入值上执行函数，实现并行化，将输入数据在进程之间分发。因此，进程池允许实现所谓的**数据并行性**，即基于在并行处理数据的不同进程之间分发数据。

# 准备就绪

`multiprocessing`库提供了`Pool`类来进行简单的并行处理任务。

`Pool`类有以下方法：

+   `apply()`: 这会阻塞，直到结果准备就绪。

+   `apply_async()`: 这是`apply()`方法的变体，返回一个结果对象。这是一个异步操作，直到所有子类都执行完毕才会锁定主线程。

+   `map()`: 这是内置`map()`的并行等价物（[`docs.python.org/2/library/functions.html#map`](https://docs.python.org/2/library/functions.html#map)）。这会阻塞，直到结果准备好，并且它会将可迭代数据分成多个块，作为单独的任务提交给进程池。

+   `map_async()`: 这是`map()`的一个变体（[`docs.python.org/2/library/multiprocessing.html?highlight=pool%20class#multiprocessing.pool.multiprocessing.Pool.map`](https://docs.python.org/2/library/multiprocessing.html?highlight=pool%20class#multiprocessing.pool.multiprocessing.Pool.map)），它返回一个`result`对象。如果指定了回调函数，则应该是可调用的，接受一个参数。当结果准备好时，将应用回调函数（除非调用失败）。回调函数应立即完成；否则，处理结果的线程将被阻塞。

# 如何做…

这个例子向你展示了如何实现一个进程池来执行并行应用。我们创建了一个包含四个进程的进程池，然后使用进程池的`map`方法执行一个简单的函数：

1.  导入`multiprocessing`库：

```py
import multiprocessing
```

1.  `Pool`方法将`function_square`应用于输入元素以执行简单的计算：

```py
def function_square(data):
 result = data*data
 return result

if __name__ == '__main__':
```

1.  参数输入是一个从`0`到`100`的整数列表：

```py
 inputs = list(range(0,100))
```

1.  并行进程的总数为`4`：

```py
 pool = multiprocessing.Pool(processes=4)
```

1.  `pool.map`方法将作为单独的任务提交给进程池：

```py
 pool_outputs = pool.map(function_square, inputs)
 pool.close() 
 pool.join() 
```

1.  计算结果存储在`pool_outputs`中：

```py
 print ('Pool    :', pool_outputs)
```

重要的是要注意，`pool.map()`方法的结果等同于 Python 内置的`map()`函数，只是进程是并行运行的。

# 工作原理…

在这里，我们使用以下语句创建了一个包含四个进程的进程池：

```py
 pool = multiprocessing.Pool(processes=4)
```

每个进程都有一个整数列表作为输入。在这里，`pool.map`的工作方式与 map 相同，但使用了多个进程，其数量为四，在创建 pool 时事先定义好了：

```py
 pool_outputs = pool.map(function_square, inputs)
```

要终止进程池的计算，通常使用`close`和`join`函数：

```py
 pool.close() 
 pool.join() 
```

要执行此操作，请输入以下命令：

```py
> python process_pool.py
```

这是我们在完成计算后得到的结果：

```py
Pool : [0, 1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144, 169, 196, 225, 256, 289, 324, 361, 400, 441, 484, 529, 576, 625, 676, 729, 784, 841, 900, 961, 1024, 1089, 1156, 1225, 1296, 1369, 1444, 1521, 1600, 1681, 1764, 1849, 1936, 2025, 2116, 2209, 2304, 2401, 2500, 2601, 2704, 2809, 2916, 3025, 3136, 3249, 3364, 3481, 3600, 3721, 3844, 3969, 4096, 4225, 4356, 4489, 4624, 4761, 4900, 5041, 5184, 5329, 5476, 5625, 5776, 5929, 6084, 6241, 6400, 6561, 6724, 6889, 7056, 7225, 7396, 7569, 7744, 7921, 8100, 8281, 8464, 8649, 8836, 9025, 9216, 9409, 9604, 9801]
```

# 还有更多…

在前面的例子中，我们看到`Pool`还提供了`map`方法，它允许我们将函数应用于不同的数据集。特别是，在输入的元素上并行执行相同操作的情况被称为*数据并行*。

在下面的例子中，我们使用`Pool`和`map`，创建了一个有`5`个工作进程的`pool`，并通过`map`方法，将一个函数`f`应用于一个包含`10`个元素的列表：

```py
from multiprocessing import Pool

def f(x):
 return x+10

if __name__ == '__main__':
 p=Pool(processes=5)
 print(p.map(f, [1, 2, 3,5,6,7,8,9,10]))
```

输出如下：

```py
11 12 13 14 15 16 17 18 19 20
```

# 另请参阅

要了解更多关于进程池的信息，请使用以下链接：[`www.tutorialspoint.com/concurrency_in_python/concurrency_in_python_pool_of_processes.htm`](https://www.tutorialspoint.com/concurrency_in_python/concurrency_in_python_pool_of_processes.htm)。


# 第四章：消息传递

本章将简要介绍**消息传递接口**（**MPI**），这是一种消息交换规范。MPI 的主要目标是建立一种高效、灵活和可移植的消息交换通信标准。

主要是展示库的函数，包括同步和异步通信原语，如（发送/接收）和（广播/全对全），计算的部分结果的组合操作（gather/reduce），最后是进程之间的同步原语（屏障）。

此外，通过定义拓扑来介绍通信网络的控制函数。

在本章中，我们将介绍以下内容：

+   使用`mpi4py` Python 模块

+   实现点对点通信

+   避免死锁问题

+   使用广播进行集体通信

+   使用`scatter`函数进行集体通信

+   使用`gather`函数进行集体通信

+   使用`Alltoall`进行集体通信

+   减少操作

+   优化通信

# 技术要求

本章需要`mpich`和`mpi4py`库。

`mpich`库是 MPI 的可移植实现。它是免费软件，适用于各种 Unix 版本（包括 Linux 和 macOS）和 Microsoft Windows。

要安装`mpich`，请使用从下载页面下载的安装程序（[`www.mpich.org/static/downloads/1.4.1p1/`](http://www.mpich.org/static/downloads/1.4.1p1/)）。此外，请确保选择 32 位或 64 位版本，以获取适合您的计算机的正确版本。

`mpi4py` Python 模块为 MPI（[`www.mpi-forum.org`](https://www.mpi-forum.org)）标准提供了 Python 绑定。它是基于 MPI-1/2/3 规范实现的，并公开了基于标准 MPI-2 C++绑定的 API。

在 Windows 机器上安装`mpi4py`的过程如下：

```py
C:>pip install mpi4py
```

Anaconda 用户必须输入以下内容：

```py
C:>conda install mpi4py
```

请注意，在本章的所有示例中，我们使用了通过`pip`安装的`mpi4py`

这意味着运行`mpi4py`示例所使用的表示法如下：

```py
C:>mpiexec -n x python mpi4py_script_name.py 
```

`mpiexec`命令是启动并行作业的典型方式：`x`是要使用的进程总数，而`mpi4py_script_name.py`是要执行的脚本的名称。

# 了解 MPI 结构

MPI 标准定义了虚拟拓扑、同步和进程之间通信的原语。有几种 MPI 实现，它们在支持的标准版本和功能上有所不同。

我们将通过 Python 的`mpi4py`库介绍 MPI 标准。

在 20 世纪 90 年代之前，为不同架构编写并行应用程序比今天更加困难。许多库简化了这个过程，但没有标准的方法来做。那时，大多数并行应用程序都是为科学研究环境而设计的。

各种库最常采用的模型是消息传递模型，其中进程之间的通信通过交换消息进行，而不使用共享资源。例如，主进程可以通过发送描述要完成的工作的消息来简单地将工作分配给从进程。这里还有一个非常简单的例子，即执行合并排序的并行应用程序。数据在进程本地排序，然后将结果传递给其他处理合并的进程。

由于这些库大部分使用了相同的模型，尽管彼此之间存在细微差异，各个库的作者在 1992 年会面，以定义消息交换的标准接口，从而诞生了 MPI。这个接口必须允许程序员在大多数并行架构上编写可移植的并行应用程序，使用他们已经习惯的相同特性和模型。

最初，MPI 是为分布式内存架构设计的，20 年前开始流行：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/c5eade1c-0ee1-4194-a00c-d8686149c550.png)

分布式内存架构图

随着时间的推移，分布式内存系统开始相互结合，创建了具有分布式/共享内存的混合系统：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/0ac1b93c-4e24-4612-b1d7-1935c8f0a661.png)

混合系统架构图

今天，MPI 在分布式内存、共享内存和混合系统上运行。然而，编程模型仍然是分布式内存，尽管计算执行的真正架构可能不同。

MPI 的优势可以总结如下：

+   **标准化**：它受到所有**高性能计算**（**HPC**）平台的支持。

+   **可移植性**：对源代码的更改很小，这在您决定在支持相同标准的不同平台上使用应用程序时非常有用。

+   **性能**：制造商可以创建针对特定类型硬件进行优化的实现，并获得更好的性能。

+   **功能性**：MPI-3 中定义了超过 440 个例程，但许多并行程序可以使用少于甚至 10 个例程来编写。

在接下来的章节中，我们将研究消息传递的主要 Python 库：`mpi4py`库。

# 使用 mpi4py Python 模块

Python 编程语言提供了几个 MPI 模块来编写并行程序。其中最有趣的是`mpi4py`库。它是基于 MPI-1/2 规范构建的，并提供了一个面向对象的接口，紧密遵循 MPI-2 C++绑定。C MPI 用户可以在不学习新接口的情况下使用此模块。因此，它被广泛用作 Python 中几乎完整的 MPI 库包。

模块的主要应用，将在本章中描述，如下：

+   点对点通信

+   集体通信

+   拓扑结构

# 如何做...

让我们通过检查一个经典程序的代码来开始我们对 MPI 库的旅程，该程序在每个实例化的进程上打印短语`Hello, world!`：

1.  导入`mpi4py`库：

```py
from mpi4py import MPI 
```

在 MPI 中，执行并行程序的进程由一系列非负整数称为**排名**来标识。

1.  如果我们有一个程序运行的进程数（*p*个进程），那么这些进程将有一个从*0*到*p*-1 的`rank`。特别是，为了评估每个进程的`rank`，我们必须使用特定的`COMM_WORLD` MPI 函数。这个函数被称为**通信器**，因为它定义了自己的所有可以一起通信的进程集：

```py
 comm = MPI.COMM_WORLD 
```

1.  最后，以下`Get_rank()`函数返回调用它的进程的`rank`：

```py
rank = comm.Get_rank() 
```

1.  一旦评估，`rank`就会被打印出来：

```py
print ("hello world from process ", rank) 
```

# 它是如何工作的...

根据 MPI 执行模型，我们的应用程序由*N*（在本例中为 5）个自治进程组成，每个进程都有自己的本地内存，能够通过消息交换来通信数据。

通信器定义了可以相互通信的一组进程。这里使用的`MPI_COMM_WORLD`是默认通信器，包括所有进程。

进程的标识是基于`rank`的。每个进程为其所属的每个通信器分配一个`rank`。`rank`是一个从零开始分配的整数，用于在特定通信器的上下文中标识每个单独的进程。通常做法是将全局`rank`为*0*的进程定义为主进程。通过`rank`，开发人员可以指定发送进程和接收进程。

值得注意的是，仅用于说明目的，`stdout`输出不总是有序的，因为多个进程可以同时在屏幕上写入，操作系统会任意选择顺序。因此，我们做好了一个基本观察的准备：MPI 执行中涉及的每个进程都运行相同的编译二进制文件，因此每个进程都接收相同的指令来执行。

要执行代码，请输入以下命令行：

```py
C:>mpiexec -n 5 python helloworld_MPI.py 
```

这是执行此代码后我们将得到的结果（注意进程执行顺序*不是顺序的*）：

```py
hello world from process  1 
hello world from process  0 
hello world from process  2 
hello world from process  3
hello world from process  4
```

值得注意的是，要使用的进程数量严格依赖于程序必须运行的机器的特性。

# 还有更多...

MPI 属于**单程序多数据**（**SPMD**）编程技术。

SPMD 是一种编程技术，所有进程执行相同的程序，但每个进程操作不同的数据。不同进程之间的执行区别在于基于进程的本地`rank`来区分程序的流程。

SPMD 是一种编程技术，其中单个程序同时由多个进程执行，但每个进程可以操作不同的数据。同时，进程可以执行相同的指令和不同的指令。显然，程序将包含适当的指令，允许仅执行代码的部分和/或对数据的子集进行操作。这可以使用不同的编程模型来实现，所有可执行文件同时启动。

# 另请参阅

`mpi4py`库的完整参考资料可以在[`mpi4py.readthedocs.io/en/stable/`](https://mpi4py.readthedocs.io/en/stable/)找到。

# 实现点对点通信

点对点操作包括在两个进程之间交换消息。在理想情况下，每个发送操作都将与相应的接收操作完全同步。显然，这并非总是如此，当发送方和接收方进程不同步时，MPI 实现必须能够保留发送的数据。通常，这是通过一个对开发人员透明且完全由`mpi4py`库管理的缓冲区来实现的。

`mpi4py` Python 模块通过两个函数实现点对点通信：

+   `Comm.Send(data, process_destination)`: 此函数将数据发送到通过其在通信器组中的`rank`进行标识的目标进程。

+   `Comm.Recv(process_source)`: 此函数从源进程接收数据，源进程也通过其在通信器组中的`rank`进行标识。

`Comm`参数，简称*通信器*，定义了可以通过消息传递进行通信的进程组，使用`comm = MPI.COMM_WORLD`。

# 如何做...

在以下示例中，我们将利用`comm.send`和`comm.recv`指令在不同进程之间交换消息：

1.  导入相关的`mpi4py`库：

```py
from mpi4py import MPI
```

1.  然后，我们通过`MPI.COMM_WORLD`语句定义通信器参数，即`comm`：

```py
comm=MPI.COMM_WORLD 
```

1.  `rank`参数用于标识进程本身：

```py
rank = comm.rank 
```

1.  打印出进程的`rank`是有用的：

```py
print("my rank is : " , rank) 
```

1.  然后，我们开始考虑进程的`rank`。在这种情况下，对于`rank`等于`0`的进程，我们设置`destination_process`和`data`（在这种情况下`data = 10000000`）要发送的：

```py
if rank==0: 
    data= 10000000 
    destination_process = 4 
```

1.  然后，通过使用`comm.send`语句，将先前设置的数据发送到目标进程：

```py
 comm.send(data,dest=destination_process) 
    print ("sending data %s " %data + \  
           "to process %d" %destination_process) 
```

1.  对于`rank`等于`1`的进程，`destination_process`值为`8`，要发送的数据是`"hello"`字符串：

```py
if rank==1: 
    destination_process = 8 
    data= "hello" 
    comm.send(data,dest=destination_process) 
    print ("sending data %s :" %data + \  
           "to process %d" %destination_process) 
```

1.  `rank`等于`4`的进程是接收进程。实际上，在`comm.recv`语句的参数中设置了源进程（即`rank`等于`0`的进程）：

```py
if rank==4: 
    data=comm.recv(source=0) 
```

1.  现在，使用以下代码，必须显示来自进程`0`的数据接收：

```py
 print ("data received is = %s" %data) 
```

1.  最后要设置的进程是编号为`9`的进程。在这里，我们在`comm.recv`语句中将`rank`等于`1`的源进程定义为参数：

```py
if rank==8: 
    data1=comm.recv(source=1) 
```

1.  然后打印`data1`的值：

```py
 print ("data1 received is = %s" %data1) 
```

# 它是如何工作的...

我们使用总进程数等于`9`来运行示例。因此，在`comm`通信器组中，我们有九个可以相互通信的任务：

```py
comm=MPI.COMM_WORLD 
```

此外，为了识别组内的任务或进程，我们使用它们的`rank`值：

```py
rank = comm.rank 
```

我们有两个发送进程和两个接收进程。`rank`等于`0`的进程向`rank`等于`4`的接收进程发送数值数据：

```py
if rank==0: 
    data= 10000000 
    destination_process = 4 
    comm.send(data,dest=destination_process) 
```

同样，我们必须指定`rank`等于`4`的接收进程。我们还注意到`comm.recv`语句必须包含发送进程的 rank 作为参数：

```py
if rank==4: 
    data=comm.recv(source=0) 
```

对于其他发送和接收进程（`rank`等于`1`的进程和`rank`等于`8`的进程），情况是相同的，唯一的区别是数据类型。

在这种情况下，对于发送进程，我们有一个要发送的字符串：

```py
if rank==1: 
    destination_process = 8 
    data= "hello" 
    comm.send(data,dest=destination_process) 
```

对于`rank`等于`8`的接收进程，指出了发送进程的 rank：

```py
if rank==8: 
    data1=comm.recv(source=1) 
```

以下图表总结了`mpi4py`中的点对点通信协议：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/c92bb67f-1f34-4624-9dd7-9907f38c32e1.png)发送/接收传输协议

正如您所看到的，它描述了一个两步过程，包括从一个任务（*发送者*）发送一些**数据**到另一个任务（*接收者*）接收这些数据。发送任务必须指定要发送的数据及其目的地（*接收者*进程），而接收任务必须指定要接收的消息的*源*。

要运行脚本，我们将使用`9`个进程：

```py
C:>mpiexec -n 9 python pointToPointCommunication.py 
```

这是运行脚本后将获得的输出：

```py
my rank is : 7
my rank is : 5
my rank is : 2
my rank is : 6
my rank is : 3
my rank is : 1
sending data hello :to process 8
my rank is : 0
sending data 10000000 to process 4
my rank is : 4
data received is = 10000000
my rank is : 8
data1 received is = hello 
```

# 还有更多...

`comm.send()`和`comm.recv()`函数是阻塞函数，这意味着它们会阻塞调用者，直到涉及的缓冲数据可以安全使用。此外，在 MPI 中，有两种发送和接收消息的管理方法：

+   **缓冲模式**：当要发送的数据已被复制到缓冲区时，流控制会立即返回到程序。这并不意味着消息已发送或接收。

+   **同步模式**：当相应的`receive`函数开始接收消息时，该函数才终止。

# 另请参阅

关于这个主题的有趣教程可以在[`github.com/antolonappan/MPI_tutorial`](https://github.com/antolonappan/MPI_tutorial)找到。

# 避免死锁问题

我们面临的一个常见问题是死锁。这是一种情况，其中两个（或更多）进程相互阻塞，并等待另一个执行某个为另一个服务的动作，反之亦然。`mpi4py`模块没有提供解决死锁问题的特定功能，但开发人员必须遵循一些措施以避免死锁问题。

# 如何做到...

让我们首先分析以下 Python 代码，它将介绍一个典型的死锁问题。我们有两个进程——`rank`等于`1`和`rank`等于`5`——它们相互通信，并且都具有数据发送者和数据接收者功能：

1.  导入`mpi4py`库：

```py
from mpi4py import MPI 
```

1.  将通信器定义为`comm`和`rank`参数：

```py
comm=MPI.COMM_WORLD 
rank = comm.rank 
print("my rank is %i" % (rank)) 
```

1.  `rank`等于`1`的进程向`rank`等于`5`的进程发送和接收数据：

```py
if rank==1: 
    data_send= "a" 
    destination_process = 5 
    source_process = 5 
    data_received=comm.recv(source=source_process) 
    comm.send(data_send,dest=destination_process) 
    print ("sending data %s " %data_send + \ 
           "to process %d" %destination_process) 
    print ("data received is = %s" %data_received) 
```

1.  同样，在这里，我们定义`rank`等于`5`的进程：

```py
if rank==5: 
    data_send= "b" 
```

1.  目标和发送进程都等于`1`：

```py
 destination_process = 1 
    source_process = 1  
    comm.send(data_send,dest=destination_process) 
    data_received=comm.recv(source=source_process) 
    print ("sending data %s :" %data_send + \ 
           "to process %d" %destination_process) 
    print ("data received is = %s" %data_received) 
```

# 它是如何工作的...

如果我们尝试运行这个程序（只用两个进程执行它是有意义的），那么我们会发现两个进程都无法继续：

```py
C:\>mpiexec -n 9 python deadLockProblems.py

my rank is : 8
my rank is : 6
my rank is : 7
my rank is : 2
my rank is : 4
my rank is : 3
my rank is : 0
my rank is : 1
sending data a to process 5
data received is = b
my rank is : 5
sending data b :to process 1
data received is = a
```

两个进程都准备从另一个进程接收消息，并在那里被阻塞。这是因为`comm.recv()`MPI 函数和`comm.send()`MPI 阻塞了它们。这意味着调用进程等待它们的完成。至于`comm.send()`MPI，完成发生在数据已发送并且可以被覆盖而不修改消息时。

`comm.recv()`MPI 的完成发生在数据已接收并且可以使用时。为了解决这个问题，第一个想法是将`comm.recv()`MPI 与`comm.send()`MPI 颠倒，如下所示：

```py
if rank==1: 
    data_send= "a" 
    destination_process = 5 
    source_process = 5 
    comm.send(data_send,dest=destination_process) 
    data_received=comm.recv(source=source_process) 

 print ("sending data %s " %data_send + \
 "to process %d" %destination_process)
 print ("data received is = %s" %data_received)

if rank==5: 
    data_send= "b" 
    destination_process = 1 
    source_process = 1 
    data_received=comm.recv(source=source_process) 
    comm.send(data_send,dest=destination_process) 

 print ("sending data %s :" %data_send + \
 "to process %d" %destination_process)
 print ("data received is = %s" %data_received)
```

即使这个解决方案是正确的，也不能保证我们会避免死锁。事实上，通信是通过带有`comm.send()`指令的缓冲区执行的。

MPI 复制要发送的数据。这种模式可以无问题地工作，但前提是缓冲区能够容纳所有数据。如果不能容纳，就会发生死锁：发送者无法完成发送数据，因为缓冲区正忙，接收者无法接收数据，因为被`comm.send()`MPI 调用阻塞，而这个调用还没有完成。

在这一点上，允许我们避免死锁的解决方案是交换发送和接收函数，使它们不对称：

```py
if rank==1: 
    data_send= "a" 
    destination_process = 5 
    source_process = 5 
    comm.send(data_send,dest=destination_process) 
    data_received=comm.recv(source=source_process) 

if rank==5: 
    data_send= "b" 
    destination_process = 1 
    source_process = 1 
    comm.send(data_send,dest=destination_process) 
    data_received=comm.recv(source=source_process) 
```

最后，我们得到了正确的输出：

```py
C:\>mpiexec -n 9 python deadLockProblems.py 

my rank is : 4
my rank is : 0
my rank is : 3
my rank is : 8
my rank is : 6
my rank is : 7
my rank is : 2
my rank is : 1
sending data a to process 5
data received is = b
my rank is : 5
sending data b :to process 1
data received is = a 
```

# 还有更多...

解决死锁的方案不是唯一的解决方案。

例如，有一个函数可以统一发送消息到给定进程并接收来自另一个进程的消息的单个调用。这个函数叫做`Sendrecv`：

```py
Sendrecv(self, sendbuf, int dest=0, int sendtag=0, recvbuf=None, int source=0, int recvtag=0, Status status=None) 
```

如您所见，所需的参数与`comm.send()`和`comm.recv()`MPI 相同（在这种情况下，函数也会阻塞）。然而，`Sendrecv`提供了一个优势，即让通信子系统负责检查发送和接收之间的依赖关系，从而避免死锁。

这样，上一个示例的代码变成了以下内容：

```py
if rank==1: 
    data_send= "a" 
    destination_process = 5 
    source_process = 5 
    data_received=comm.sendrecv(data_send,dest=\
                                destination_process,\ 
                                source =source_process) 
if rank==5: 
    data_send= "b" 
    destination_process = 1 
    source_process = 1 
    data_received=comm.sendrecv(data_send,dest=\ 
                                destination_process,\ 
                                source=source_process) 
```

# 另请参阅

关于并行编程由于死锁管理而变得困难的有趣分析可以在[`codewithoutrules.com/2017/08/16/concurrency-python/`](https://codewithoutrules.com/2017/08/16/concurrency-python/)找到。

# 使用广播进行集体通信

在并行代码的开发过程中，我们经常发现自己处于这样一种情况：我们必须在多个进程之间共享某个变量的值或每个进程提供的变量的某些操作（可能具有不同的值）。

为了解决这类情况，使用通信树（例如，进程 0 将数据发送到进程 1 和 2，它们将分别负责将数据发送到进程 3、4、5、6 等）。

相反，MPI 库提供了一些函数，这些函数非常适合于信息交换或明显针对在其上执行的机器进行了优化的多个进程的使用：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/48fa28e4-27d9-4ee6-981e-3c72d22b1c27.png)从进程 0 广播数据到进程 1、2、3 和 4

涉及到属于一个通信器的所有进程的通信方法称为集体通信。因此，集体通信通常涉及多于两个进程。然而，我们将这种集体通信称为广播，其中一个单独的进程将相同的数据发送给任何其他进程。

# 做好准备

`mpi4py`提供了以下方法的广播功能：

```py
buf = comm.bcast(data_to_share, rank_of_root_process) 
```

这个函数将消息进程根中包含的信息发送到属于`comm`通信器的每个其他进程。

# 如何做...

现在让我们看一个使用`broadcast`函数的例子。我们有一个`rank`等于`0`的根进程，它与通信器组中定义的其他进程共享自己的数据`variable_to_share`：

1.  让我们导入`mpi4py`库：

```py
from mpi4py import MPI 
```

1.  现在，让我们定义通信器和`rank`参数：

```py
comm = MPI.COMM_WORLD 
rank = comm.Get_rank() 
```

1.  就`rank`等于`0`的进程而言，我们定义变量在其他进程之间共享：

```py
if rank == 0: 
    variable_to_share = 100      
else: 
    variable_to_share = None 
```

1.  最后，我们定义一个广播，将`rank`进程等于零作为其`root`：

```py
variable_to_share = comm.bcast(variable_to_share, root=0) 
print("process = %d" %rank + " variable shared  = %d " \   
                               %variable_to_share) 
```

# 它是如何工作的...

`rank`等于`0`的根进程实例化一个变量`variable_to_share`，其值为`100`。这个变量将与通信组的其他进程共享：

```py
if rank == 0: 
   variable_to_share = 100 
```

为了执行这个操作，我们还引入了广播通信语句：

```py
variable_to_share = comm.bcast(variable_to_share, root=0) 
```

在这里，函数中的参数如下：

+   要共享的数据（`variable_to_share`）。

+   根进程，即`rank`等于 0 的进程（`root=0`）。

运行代码，我们有一个由 10 个进程组成的通信组，`variable_to_share`在组中的其他进程之间共享。最后，`print`语句可视化运行进程的等级及其变量的值：

```py
print("process = %d" %rank + " variable shared  = %d " \   
                     %variable_to_share) 
```

设置`10`个进程后，获得的输出如下：

```py
C:\>mpiexec -n 10 python broadcast.py 
process = 0 
variable shared = 100 
process = 8 
variable shared = 100 
process = 2 variable 
shared = 100 
process = 3 
variable shared = 100 
process = 4 
variable shared = 100 
process = 5 
variable shared = 100 
process = 9 
variable shared = 100 
process = 6 
variable shared = 100 
process = 1 
variable shared = 100 
process = 7 
variable shared = 100 
```

# 还有更多...

集体通信允许在组中的多个进程之间进行同时数据传输。`mpi4py`库提供了集体通信，但只有在阻塞版本中（即它阻塞调用者方法，直到涉及的缓冲数据可以安全使用）。

最常用的集体通信操作如下：

+   跨组的进程进行屏障同步

+   通信功能：

+   从一个进程广播数据到组中的所有进程

+   从所有进程中收集数据到一个进程

+   从一个进程分发数据到所有进程

+   减少操作

# 另请参阅

请参阅此链接([`nyu-cds.github.io/python-mpi/`](https://nyu-cds.github.io/python-mpi/))，以找到 Python 和 MPI 的完整介绍。

# 使用 scatter 功能的集体通信

scatter 功能与 scatter 广播非常相似，但有一个主要区别：虽然`comm.bcast`将相同的数据发送到所有监听进程，但`comm.scatter`可以将数组中的数据块发送到不同的进程。

以下图示说明了 scatter 功能：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/7a6e8b54-06df-43d5-ad30-aa1221ae3f85.png)

从进程 0 到进程 1、2、3 和 4 中分发数据

**`comm.scatter`**函数获取数组的元素并根据它们的等级将它们分发给进程，第一个元素将发送到进程 0，第二个元素将发送到进程 1，依此类推。**`mpi4py`**中实现的函数如下：

```py
recvbuf  = comm.scatter(sendbuf, rank_of_root_process) 
```

# 如何做...

在下面的示例中，我们将看到如何使用`scatter`功能将数据分发给不同的进程：

1.  导入`mpi4py`库：

```py
from mpi4py import MPI 
```

1.  接下来，我们以通常的方式定义`comm`和`rank`参数：

```py
comm = MPI.COMM_WORLD 
rank = comm.Get_rank() 
```

1.  对于`rank`等于`0`的进程，将分发以下数组：

```py
if rank == 0: 
    array_to_share = [1, 2, 3, 4 ,5 ,6 ,7, 8 ,9 ,10] 
else: 
 array_to_share = None 
```

1.  然后，设置`recvbuf`。`root`进程是`rank`等于`0`的进程：

```py
recvbuf = comm.scatter(array_to_share, root=0) 
print("process = %d" %rank + " recvbuf = %d " %recvbuf) 
```

# 它是如何工作的...

`rank`等于`0`的进程将`array_to_share`数据结构分发给其他进程：

```py
array_to_share = [1, 2, 3, 4 ,5 ,6 ,7, 8 ,9 ,10] 
```

`recvbuf`参数指示将通过`comm.scatter`语句发送到进程的第*i*个变量的值：

```py
recvbuf = comm.scatter(array_to_share, root=0)
```

输出如下：

```py
C:\>mpiexec -n 10 python scatter.py 
process = 0 variable shared  = 1 
process = 4 variable shared  = 5 
process = 6 variable shared  = 7 
process = 2 variable shared  = 3 
process = 5 variable shared  = 6 
process = 3 variable shared  = 4 
process = 7 variable shared  = 8 
process = 1 variable shared  = 2 
process = 8 variable shared  = 9 
process = 9 variable shared  = 10 
```

我们还要注意`comm.scatter`的限制之一是，您可以在执行语句中指定的处理器数量中分散多少元素。实际上，如果您尝试分散比指定的处理器（在本例中为 3）更多的元素，那么您将收到类似以下的错误：

```py
C:\> mpiexec -n 3 python scatter.py 
Traceback (most recent call last): 
  File "scatter.py", line 13, in <module> 
    recvbuf = comm.scatter(array_to_share, root=0) 
  File "Comm.pyx", line 874, in mpi4py.MPI.Comm.scatter 
 (c:\users\utente\appdata\local\temp\pip-build-h14iaj\mpi4py\
 src\mpi4py.MPI.c:73400) 
  File "pickled.pxi", line 658, in mpi4py.MPI.PyMPI_scatter 
 (c:\users\utente\appdata\local\temp\pip-build-h14iaj\mpi4py\src\
 mpi4py.MPI.c:34035) 
  File "pickled.pxi", line 129, in mpi4py.MPI._p_Pickle.dumpv 
 (c:\users\utente\appdata\local\temp\pip-build-h14iaj\mpi4py
 \src\mpi4py.MPI.c:28325) 
 ValueError: expecting 3 items, got 10 
  mpiexec aborting job... job aborted: 
rank: node: exit code[: error message] 
0: Utente-PC: 123: mpiexec aborting job 
1: Utente-PC: 123 
2: Utente-PC: 123 
```

# 还有更多...

`mpi4py`库提供了另外两个用于分发数据的函数：

+   `comm.scatter(sendbuf, recvbuf, root=0)`：此函数将数据从一个进程发送到通信器中的所有其他进程。

+   `comm.scatterv(sendbuf, recvbuf, root=0)`：此函数将数据从一个进程散布到给定组中的所有其他进程，在发送端提供不同数量的数据和位移。

`sendbuf`和`recvbuf`参数必须以列表的形式给出（就像`comm.send`点对点函数中一样）：

```py
buf = [data, data_size, data_type] 
```

在这里，`data`必须是`data_size`大小的类似缓冲区的对象，并且是`data_type`类型。

# 另请参阅

有关 MPI 广播的有趣教程，请访问[`pythonprogramming.net/mpi-broadcast-tutorial-mpi4py/`](https://pythonprogramming.net/mpi-broadcast-tutorial-mpi4py/)。

# 使用 gather 函数进行集体通信

`gather`函数执行`scatter`函数的逆操作。在这种情况下，所有进程都将数据发送到收集接收到的数据的根进程。

# 准备好

在`mpi4py`中实现的`gather`函数如下：

```py
recvbuf  = comm.gather(sendbuf, rank_of_root_process) 
```

在这里，`sendbuf`是发送的数据，`rank_of_root_process`表示所有数据的接收处理：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/3fc357c4-5541-4c15-94f4-2dd7bee64b9b.png)从进程 1、2、3 和 4 收集数据

# 如何做到...

在以下示例中，我们将表示前图中显示的条件，其中每个进程构建其自己的数据，这些数据将被发送到用`rank`零标识的根进程：

1.  键入必要的导入：

```py
from mpi4py import MPI 
```

1.  接下来，我们定义以下三个参数。`comm`参数是通信器，`rank`提供进程的等级，`size`是进程的总数：

```py
comm = MPI.COMM_WORLD 
size = comm.Get_size() 
rank = comm.Get_rank() 
```

1.  在这里，我们定义了要从`rank`为零的进程中收集的数据：

```py
data = (rank+1)**2 
```

1.  最后，通过`comm.gather`函数提供收集。还要注意，根进程（从其他进程收集数据的进程）是零级进程：

```py
data = comm.gather(data, root=0) 
```

1.  对于`rank`等于`0`的进程，收集的数据和发送的进程将被打印出来：

```py
if rank == 0: 
    print ("rank = %s " %rank +\ 
          "...receiving data to other process") 
   for i in range(1,size): 
       value = data[i] 
       print(" process %s receiving %s from process %s"\ 
            %(rank , value , i)) 
```

# 它是如何工作的...

`0`的根进程从其他四个进程接收数据，如前图所示。

我们设置*n（= 5）*个进程发送它们的数据：

```py
 data = (rank+1)**2 
```

如果进程的`rank`为`0`，那么数据将被收集到一个数组中：

```py
if rank == 0: 
    for i in range(1,size): 
        value = data[i] 
```

数据的收集是通过以下函数给出的：

```py
data = comm.gather(data, root=0) 
```

最后，我们运行代码，将进程组设置为`5`：

```py
C:\>mpiexec -n 5 python gather.py
rank = 0 ...receiving data to other process
process 0 receiving 4 from process 1
process 0 receiving 9 from process 2
process 0 receiving 16 from process 3
process 0 receiving 25 from process 4 
```

# 还有更多...

要收集数据，`mpi4py`提供了以下函数：

+   收集到一个任务*：*`comm.Gather`，`comm.Gatherv`和`comm.gather`

+   收集到所有任务：`comm.Allgather`，`comm.Allgatherv`和`comm.allgather`

# 另请参阅

有关`mpi4py`的更多信息，请访问[`www.ceci-hpc.be/assets/training/mpi4py.pdf`](http://www.ceci-hpc.be/assets/training/mpi4py.pdf)。

# 使用 Alltoall 进行集体通信

`Alltoall`集体通信结合了`scatter`和`gather`的功能。

# 如何做到...

在以下示例中，我们将看到`comm.Alltoall`的`mpi4py`实现。我们将考虑一个通信器，其中每个进程从组中定义的其他进程发送和接收数值数据的数组：

1.  对于此示例，必须导入相关的`mpi4py`和`numpy`库：

```py
from mpi4py import MPI 
import numpy 
```

1.  与前面的示例一样，我们需要设置相同的参数，`comm`，`size`和`rank`：

```py
comm = MPI.COMM_WORLD 
size = comm.Get_size() 
rank = comm.Get_rank() 
```

1.  因此，我们必须定义每个进程将从其他进程发送的数据（`senddata`）和同时接收的数据（`recvdata`）：

```py
senddata = (rank+1)*numpy.arange(size,dtype=int) 
recvdata = numpy.empty(size,dtype=int) 
```

1.  最后，执行`Alltoall`函数：

```py
comm.Alltoall(senddata,recvdata) 
```

1.  显示每个进程发送和接收的数据：

```py
print(" process %s sending %s receiving %s"\ 
      %(rank , senddata , recvdata)) 
```

# 它是如何工作的...

`comm.alltoall`方法从任务`j`的`sendbuf`参数中获取第*i^(th)*个对象，并将其复制到任务`i`的`recvbuf`参数的第*j^(th)*对象中。

如果我们运行具有`5`个进程的通信器组的代码，那么输出如下：

```py
C:\>mpiexec -n 5 python alltoall.py 
process 0 sending [0 1 2 3 4] receiving [0 0 0 0 0] 
process 1 sending [0 2 4 6 8] receiving [1 2 3 4 5] 
process 2 sending [ 0 3 6 9 12] receiving [ 2 4 6 8 10] 
process 3 sending [ 0 4 8 12 16] receiving [ 3 6 9 12 15] 
process 4 sending [ 0 5 10 15 20] receiving [ 4 8 12 16 20] 
```

我们还可以通过以下模式弄清楚发生了什么：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/ae2c13f2-c674-4f5e-a05b-bf8982a010bd.png)Alltoall 集体通信

我们关于模式的观察如下：

+   *P0* 进程包含 [**0 1 2 3 4**] 数据数组，其中它将 0 分配给自己，1 分配给 *P1* 进程，2 分配给 *P2* 进程，3 分配给 *P3* 进程，4 分配给 *P4* 进程；

+   *P1* 进程包含 [**0 2 4 6 8**] 数据数组，其中它将 0 分配给 *P0* 进程，2 分配给自己，4 分配给 *P2* 进程，6 分配给 *P3* 进程，8 分配给 *P4* 进程；

+   *P2* 进程包含 [**0 3 6 9 12**] 数据数组，其中它将 0 分配给 *P0* 进程，3 分配给 *P1* 进程，6 分配给自己，9 分配给 *P3* 进程，12 分配给 *P4* 进程；

+   *P3* 进程包含 [**0 4 8 12 16**] 数据数组，其中它将 0 分配给 *P0* 进程，4 分配给 *P1* 进程，8 分配给 *P2* 进程，12 分配给自己，16 分配给 *P4* 进程；

+   *P4* 进程包含 [**0 5 10 15 20**] 数据数组，其中它将 0 分配给 *P0* 进程，5 分配给 *P1* 进程，10 分配给 *P2* 进程，15 分配给 *P3* 进程，20 分配给自己。

# 还有更多...

`Alltoall` 个性化通信也被称为总交换。这个操作在各种并行算法中使用，比如快速傅立叶变换、矩阵转置、样本排序和一些并行数据库连接操作。

在 `mpi4py` 中，有 *三种类型* 的 `Alltoall` 集体通信：

+   `comm.Alltoall(sendbuf, recvbuf)`: `Alltoall` 散列/聚集从组中的所有进程发送数据到所有进程。

+   `comm.Alltoallv(sendbuf, recvbuf)`: `Alltoall` 散列/聚集向组中的所有进程发送数据，提供不同数量的数据和位移。

+   `comm.Alltoallw(sendbuf, recvbuf)`: 广义的 `Alltoall` 通信允许每个伙伴的不同计数、位移和数据类型。

# 另请参阅

可以从[`www.duo.uio.no/bitstream/handle/10852/10848/WenjingLinThesis.pdf`](https://www.duo.uio.no/bitstream/handle/10852/10848/WenjingLinThesis.pdf)下载 MPI Python 模块的有趣分析。

# 减少操作

与 `comm.gather` 类似，`comm.reduce` 接受每个进程中输入元素的数组，并将输出元素数组返回给根进程。输出元素包含减少的结果。

# 准备工作

在 `mpi4py` 中，我们通过以下语句定义减少操作：

```py
comm.Reduce(sendbuf, recvbuf, rank_of_root_process, op = type_of_reduction_operation) 
```

我们必须注意，与 `comm.gather` 语句的不同之处在于 `op` 参数，它是您希望应用于数据的操作，而 `mpi4py` 模块包含一组可以使用的减少操作。

# 如何做...

现在，我们将看到如何使用减少功能实现对元素数组的和的 `MPI.SUM` 减少操作。

对于数组操作，我们使用 `numpy` Python 模块提供的函数：

1.  在这里，导入相关的库 `mpi4py` 和 `numpy`：

```py
import numpy 
from mpi4py import MPI 
```

1.  定义 `comm`、`size` 和 `rank` 参数：

```py
comm = MPI.COMM_WORLD  
size = comm.size  
rank = comm.rank 
```

1.  然后，设置数组的大小（`array_size`）：

```py
array_size = 10 
```

1.  定义要发送和接收的数据：

```py
recvdata = numpy.zeros(array_size,dtype=numpy.int) 
senddata = (rank+1)*numpy.arange(array_size,dtype=numpy.int) 
```

1.  打印出进程发送者和发送的数据：

```py
print(" process %s sending %s " %(rank , senddata)) 
```

1.  最后，执行 `Reduce` 操作。请注意，`root` 进程设置为 `0`，`op` 参数设置为 `MPI.SUM`：

```py
comm.Reduce(senddata,recvdata,root=0,op=MPI.SUM) 
```

1.  然后显示减少操作的输出，如下所示：

```py
print ('on task',rank,'after Reduce:    data = ',recvdata) 
```

# 它是如何工作的...

为执行减少求和，我们使用 `comm.Reduce` 语句。此外，我们将标识为 `rank` 为零，这是将包含计算最终结果的 `recvbuf` 的 `root` 进程：

```py
comm.Reduce(senddata,recvdata,root=0,op=MPI.SUM) 
```

以 `10` 个进程的通信器组运行代码是有意义的，因为这是被操作数组的大小。

输出如下所示：

```py
C:\>mpiexec -n 10 python reduction.py 
  process 1 sending [ 0 2 4 6 8 10 12 14 16 18]
on task 1 after Reduce: data = [0 0 0 0 0 0 0 0 0 0]
 process 5 sending [ 0 6 12 18 24 30 36 42 48 54]
on task 5 after Reduce: data = [0 0 0 0 0 0 0 0 0 0]
 process 7 sending [ 0 8 16 24 32 40 48 56 64 72]
on task 7 after Reduce: data = [0 0 0 0 0 0 0 0 0 0]
 process 3 sending [ 0 4 8 12 16 20 24 28 32 36]
on task 3 after Reduce: data = [0 0 0 0 0 0 0 0 0 0]
 process 9 sending [ 0 10 20 30 40 50 60 70 80 90]
on task 9 after Reduce: data = [0 0 0 0 0 0 0 0 0 0]
 process 6 sending [ 0 7 14 21 28 35 42 49 56 63]
on task 6 after Reduce: data = [0 0 0 0 0 0 0 0 0 0]
 process 2 sending [ 0 3 6 9 12 15 18 21 24 27]
on task 2 after Reduce: data = [0 0 0 0 0 0 0 0 0 0]
 process 8 sending [ 0 9 18 27 36 45 54 63 72 81]
on task 8 after Reduce: data = [0 0 0 0 0 0 0 0 0 0]
 process 4 sending [ 0 5 10 15 20 25 30 35 40 45]
on task 4 after Reduce: data = [0 0 0 0 0 0 0 0 0 0]
 process 0 sending [0 1 2 3 4 5 6 7 8 9]
on task 0 after Reduce: data = [ 0 55 110 165 220 275 330 385 440 495] 
```

# 还有更多...

请注意，使用`op=MPI.SUM`选项，我们对列数组的所有元素应用求和操作。为了更好地理解减少操作的运行方式，让我们看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/aa28bcc1-08cf-4699-b559-9f4f1e6e948c.png)

集体通信中的减少

发送操作如下：

+   **P0**进程发送[**0 1 2**]数据数组。

+   **P1**进程发送[**0 2 4**]数据数组。

+   **P2**进程发送[**0 3 6**]数据数组。

减少操作对每个任务的第*i*个元素求和，然后将结果放入**P0**根进程数组的第*i*个元素中。对于接收操作，**P0**进程接收[**0 6 12**]数据数组。

MPI 定义的一些减少操作如下：

+   `MPI.MAX`：返回最大元素。

+   `MPI.MIN`：返回最小元素。

+   `MPI.SUM`：对元素求和。

+   `MPI.PROD`：将所有元素相乘。

+   `MPI.LAND`：对元素执行 AND 逻辑操作。

+   `MPI.MAXLOC`：返回最大值及其所属进程的等级。

+   `MPI.MINLOC`：返回最小值及其所属进程的等级。

# 另见

在[`mpitutorial.com/tutorials/mpi-reduce-and-allreduce/`](http://mpitutorial.com/tutorials/mpi-reduce-and-allreduce/)，您可以找到有关此主题的良好教程以及更多内容。

# 优化通信

MPI 提供的一个有趣功能是虚拟拓扑。如前所述，所有通信函数（点对点或集体）都涉及一组进程。我们一直使用包括所有进程的`MPI_COMM_WORLD`组。它为每个属于大小为*n*的通信器的进程分配了*0*到*n-1*的等级。

然而，MPI 允许我们为通信器分配虚拟拓扑。它定义了对不同进程的标签分配：通过构建虚拟拓扑，每个节点将只与其虚拟邻居通信，提高性能，因为它减少了执行时间。

例如，如果等级是随机分配的，那么消息可能被迫传递到达目的地之前经过许多其他节点。除了性能问题，虚拟拓扑确保代码更清晰、更易读。

MPI 提供两种构建拓扑的方法。第一种构建创建笛卡尔拓扑，而后者创建任何类型的拓扑。具体来说，在第二种情况下，我们必须提供要构建的图的邻接矩阵。我们只处理笛卡尔拓扑，通过它可以构建广泛使用的几种结构，如网格、环和环面。

用于创建笛卡尔拓扑的`mpi4py`函数如下：

```py
comm.Create_cart((number_of_rows,number_of_columns))
```

在这里，`number_of_rows`和`number_of_columns`指定要创建的网格的行和列。

# 如何做...

在以下示例中，我们看到如何实现大小为*M×N*的笛卡尔拓扑。此外，我们定义一组坐标以了解所有进程的位置：

1.  导入所有相关库：

```py
from mpi4py import MPI 
import numpy as np 
```

1.  定义以下参数以沿着拓扑移动：

```py
UP = 0 
DOWN = 1 
LEFT = 2 
RIGHT = 3 
```

1.  对于每个进程，以下数组定义了邻近进程：

```py
neighbour_processes = [0,0,0,0] 
```

1.  在`main`程序中，然后定义了`comm.rank`和`size`参数：

```py
if __name__ == "__main__": 
    comm = MPI.COMM_WORLD 
    rank = comm.rank 
    size = comm.size 
```

1.  现在，让我们构建拓扑：

```py
 grid_rows = int(np.floor(np.sqrt(comm.size))) 
    grid_column = comm.size // grid_rows 
```

1.  以下条件确保进程始终在拓扑结构内：

```py
 if grid_rows*grid_column > size: 
        grid_column -= 1 
    if grid_rows*grid_column > size: 
        grid_rows -= 1
```

1.  `rank`等于`0`的进程开始拓扑构建：

```py
 if (rank == 0) : 
        print("Building a %d x %d grid topology:"\ 
              % (grid_rows, grid_column) ) 

    cartesian_communicator = \ 
                           comm.Create_cart( \ 
                               (grid_rows, grid_column), \ 
                               periods=(False, False), \
 reorder=True) 
    my_mpi_row, my_mpi_col = \ 
                cartesian_communicator.Get_coords\ 
                ( cartesian_communicator.rank )  

    neighbour_processes[UP], neighbour_processes[DOWN]\ 
                             = cartesian_communicator.Shift(0, 1) 
    neighbour_processes[LEFT],  \ 
                               neighbour_processes[RIGHT]  = \ 
                               cartesian_communicator.Shift(1, 1) 
    print ("Process = %s
 \row = %s\n \ 
    column = %s ----> neighbour_processes[UP] = %s \ 
    neighbour_processes[DOWN] = %s \ 
    neighbour_processes[LEFT] =%s neighbour_processes[RIGHT]=%s" \ 
             %(rank, my_mpi_row, \ 
             my_mpi_col,neighbour_processes[UP], \ 
             neighbour_processes[DOWN], \ 
             neighbour_processes[LEFT] , \ 
             neighbour_processes[RIGHT])) 
```

# 工作原理...

对于每个进程，输出应该如下所示：如果`neighbour_processes = -1`，则它没有拓扑接近性，否则，`neighbour_processes`显示接近进程的等级。

生成的拓扑是*2*×*2*的网格（参考前面的图表以获取网格表示），其大小等于输入中的进程数，即四个：

```py
grid_row = int(np.floor(np.sqrt(comm.size))) 
grid_column = comm.size // grid_row 
if grid_row*grid_column > size: 
    grid_column -= 1 
if grid_row*grid_column > size: 
    grid_rows -= 1
```

然后，使用`comm.Create_cart`函数构建笛卡尔拓扑结构（还要注意参数`periods = (False,False)`）：

```py
cartesian_communicator = comm.Create_cart( \  
    (grid_row, grid_column), periods=(False, False), reorder=True) 
```

要知道进程的位置，我们使用以下形式的`Get_coords()`方法：

```py
my_mpi_row, my_mpi_col =\ 
                cartesian_communicator.Get_coords(cartesian_communicator.rank ) 
```

对于进程，除了获取它们的坐标外，我们还必须计算并找出哪些进程在拓扑上更接近。为此，我们使用`comm.Shift (rank_source,rank_dest)`函数：

```py

neighbour_processes[UP], neighbour_processes[DOWN] =\ 
 cartesian_communicator.Shift(0, 1) 

neighbour_processes[LEFT],  neighbour_processes[RIGHT] = \ 
 cartesian_communicator.Shift(1, 1) 
```

获得的拓扑结构如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/f716b5dc-9c4c-4e31-9fc3-b128b439f010.png)虚拟网格 2x2 拓扑结构

如图所示，*P0*进程与**P1**（`RIGHT`）和**P2**（`DOWN`）进程链接。**P1**进程与**P3**（`DOWN`）和**P0**（`LEFT`）进程链接，**P3**进程与**P1**（`UP`）和**P2**（`LEFT`）进程链接，**P2**进程与**P3**（`RIGHT`）和**P0**（`UP`）进程链接。

最后，通过运行脚本，我们获得以下结果：

```py
C:\>mpiexec -n 4 python virtualTopology.py
Building a 2 x 2 grid topology:
Process = 0 row = 0 column = 0
 ---->
neighbour_processes[UP] = -1
neighbour_processes[DOWN] = 2
neighbour_processes[LEFT] =-1
neighbour_processes[RIGHT]=1

Process = 2 row = 1 column = 0
 ---->
neighbour_processes[UP] = 0
neighbour_processes[DOWN] = -1
neighbour_processes[LEFT] =-1
neighbour_processes[RIGHT]=3

Process = 1 row = 0 column = 1
 ---->
neighbour_processes[UP] = -1
neighbour_processes[DOWN] = 3
neighbour_processes[LEFT] =0
neighbour_processes[RIGHT]=-1

Process = 3 row = 1 column = 1
 ---->
neighbour_processes[UP] = 1
neighbour_processes[DOWN] = -1
neighbour_processes[LEFT] =2
neighbour_processes[RIGHT]=-1

```

# 还有更多...

要获得大小为*M*×*N*的环面拓扑结构，让我们再次使用`comm.Create_cart`，但是这次，让我们将`periods`参数设置为`periods=(True,True)`：

```py
cartesian_communicator = comm.Create_cart( (grid_row, grid_column),\ 
                                 periods=(True, True), reorder=True) 
```

获得以下输出：

```py
C:\>mpiexec -n 4 python virtualTopology.py
Process = 3 row = 1 column = 1
---->
neighbour_processes[UP] = 1
neighbour_processes[DOWN] = 1
neighbour_processes[LEFT] =2
neighbour_processes[RIGHT]=2

Process = 1 row = 0 column = 1
---->
neighbour_processes[UP] = 3
neighbour_processes[DOWN] = 3
neighbour_processes[LEFT] =0
neighbour_processes[RIGHT]=0

Building a 2 x 2 grid topology:
Process = 0 row = 0 column = 0
---->
neighbour_processes[UP] = 2
neighbour_processes[DOWN] = 2
neighbour_processes[LEFT] =1
neighbour_processes[RIGHT]=1

Process = 2 row = 1 column = 0
---->
neighbour_processes[UP] = 0
neighbour_processes[DOWN] = 0
neighbour_processes[LEFT] =3
neighbour_processes[RIGHT]=3 
```

输出涵盖了此处表示的拓扑结构：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/0de01d9b-fe04-43f0-9700-68e7955534b8.png)虚拟环面 2x2 拓扑结构

前面图表中表示的拓扑结构表明，**P0**进程与**P1**（`RIGHT`和`LEFT`）和**P2**（`UP`和`DOWN`）进程链接，**P1**进程与**P3**（`UP`和`DOWN`）和**P0**（`RIGHT`和`LEFT`）进程链接，**P3**进程与**P1**（`UP`和`DOWN`）和**P2**（`RIGHT`和`LEFT`）进程链接，**P2**进程与**P3**（`LEFT`和`RIGHT`）和**P0**（`UP`和`DOWN`）进程链接。

# 另请参阅

有关 MPI 的更多信息可以在[`pages.tacc.utexas.edu/~eijkhout/pcse/html/mpi-topo.html`](http://pages.tacc.utexas.edu/~eijkhout/pcse/html/mpi-topo.html)找到。
