# Python 并行编程秘籍（三）

> 原文：[`zh.annas-archive.org/md5/e472b7edae31215ac8e4e5f1e5748012`](https://zh.annas-archive.org/md5/e472b7edae31215ac8e4e5f1e5748012)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：异步编程

除了顺序和并行执行模型之外，还有一个与事件编程概念一起具有基本重要性的第三个模型：*异步模型*。

异步任务的执行模型可以通过单一的主控制流来实现，无论是在单处理器系统还是多处理器系统中。在并发异步执行模型中，各种任务的执行在时间线上交叉，并且一切都发生在单一控制流（单线程）的作用下。一旦开始，任务的执行可以随时间暂停然后恢复，与存在的其他当前任务的执行交替进行。

异步模型的代码开发与多线程编程的代码开发完全不同。并发多线程并行模型和单线程并发异步模型之间的一个重要区别在于，在第一种情况下，如果我们暂停一个线程的活动并启动另一个线程，操作系统会决定时间表。

这与异步模型不同，它保持在编码者的控制之外。任务的执行或终止会持续进行，只要明确要求。

这种编程类型的最重要特征是代码不是在多个线程上执行，而是在单个线程上执行，与经典的并发编程不同。因此，两个任务并不是真正同时执行，而是根据这种方法，它们几乎同时执行。

特别是，我们将描述 Python 3.4 中引入的`asyncio`模块。这使我们能够使用协程和未来来更轻松地编写异步代码，并使其更易读。

在本章中，我们将涵盖以下内容：

+   使用`concurrent.futures` Python 模块

+   使用`asyncio`管理事件循环

+   使用`asyncio`处理协程

+   使用`asyncio`操纵任务

+   处理`asyncio`和未来

# 使用`concurrent.futures` Python 模块

`concurrent.futures`模块是 Python 标准库的一部分，通过将线程建模为异步函数，提供了对线程的抽象层次。

该模块由两个主要类构建：

+   `concurrent.futures.Executor`：这是一个抽象类，提供异步执行调用的方法。

+   `concurrent.futures.Future`：这封装了可调用的异步执行。`Future`对象是通过将任务（具有可选参数的函数）提交给`Executors`来实例化的。

以下是该模块的一些主要方法：

+   `submit(function,argument)`：这会安排在参数上执行可调用函数。

+   **`map(function,argument)`**：这以异步模式执行参数的函数。

+   `shutdown(Wait=True)`：这表示执行器释放任何资源。

执行器通过它们的子类访问：`ThreadPoolExecutor`或`ProcessPoolExecutor`。因为实例化线程和进程是一个资源密集型的任务，最好将这些资源池化并将它们用作可重复启动器或执行器（因此是`Executors`概念）以用于并行或并发任务。

我们在这里采取的方法涉及使用池执行器。我们将资产提交到池（线程和进程）并获得未来，这些未来将来会对我们可用。当然，我们可以等待所有未来变成真正的结果。

线程或进程池（也称为*池化*）表示正在用于优化和简化程序中线程和/或进程的使用的管理软件。通过池化，您可以将任务（或任务）提交给池执行。

池配备有一个待处理任务的内部队列和多个线程*或*执行它们的进程。池中的一个经常出现的概念是重用：一个线程（或进程）在其生命周期内多次用于不同的任务。这减少了创建新线程或进程的开销，并提高了程序的性能。

重用*不是一个规则*，但它是导致编码人员在他们的应用程序中使用池的主要原因之一。

# 准备就绪

`concurrent.futures`模块提供了`Executor`类的两个子类，它们可以异步地操作一个线程池和一个进程池。这两个子类如下：

+   `concurrent.futures.ThreadPoolExecutor(max_workers)`

+   `concurrent.futures.ProcessPoolExecutor(max_workers)`

`max_workers`参数标识着异步执行调用的最大工作线程数。

# 如何做...

这是线程和进程池使用的一个例子，我们将比较执行时间与顺序执行所需的时间。

要执行的任务如下：我们有一个包含 10 个元素的列表。列表的每个元素都被计数到 100,000,000（只是为了浪费时间），然后最后一个数字乘以列表的第*i*个元素。特别是，我们正在评估以下情况：

+   **顺序执行**

+   **具有五个工作线程的线程池**

+   **使用五个工作线程的进程池**

现在，让我们看看如何做：

1.  导入相关的库：

```py
import concurrent.futures
import time
```

1.  定义从`1`到`10`的数字列表：

```py
number_list = list(range(1, 11))
```

1.  `count(number)`函数计算从`1`到`100000000`的数字，然后返回`number` × 100,000,000 的乘积：

```py
def count(number):
 for i in range(0,100000000):
 i += 1
 return i*number
```

1.  `evaluate(item)`函数评估`item`参数上的`count`函数。它打印出`item`值和`count(item)`的结果：

```py
def evaluate(item):
 result_item = count(item)
 print('Item %s, result %s' % (item, result_item))
```

1.  在`__main__`中，执行顺序执行、线程池和进程池：

```py
if __name__ == '__main__':
```

1.  对于顺序执行，对`number_list`的每个项目执行`evaluate`函数。然后，打印出执行时间：

```py
 start_time = time.clock()
 for item in number_list:
 evaluate(item)
 print('Sequential Execution in %s seconds' % (time.clock() -\ 
 start_time))
```

1.  关于线程和进程池的执行，使用相同数量的工作线程（`max_workers=5`）。当然，对于两个池，执行时间都会显示出来：

```py
 start_time = time.clock()
 with concurrent.futures.ThreadPoolExecutor(max_workers=5) as\ 
 executor:
 for item in number_list:
 executor.submit(evaluate, item)
 print('Thread Pool Execution in %s seconds' % (time.clock() -\ 
 start_time))
 start_time = time.clock()
 with concurrent.futures.ProcessPoolExecutor(max_workers=5) as\ 
 executor:
 for item in number_list:
 executor.submit(evaluate, item)
 print('Process Pool Execution in %s seconds' % (time.clock() -\ 
 start_time))
```

# 它是如何工作的...

我们构建一个存储在`number_list`中的数字列表：

```py
number_list = list(range(1, 11))
```

对于列表中的每个元素，我们对计数过程进行操作，直到达到`100000000`次迭代，然后将得到的值乘以`100000000`：

```py
def count(number) : 
 for i in range(0, 100000000):
 i=i+1
 return i*number

def evaluate_item(x):
 result_item = count(x)
```

在`main`程序中，我们以顺序模式执行相同的任务：

```py
if __name__ == "__main__":
 for item in number_list:
 evaluate_item(item)
```

然后，以并行模式使用`concurrent.futures`的线程池功能：

```py
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
 for item in number_list:
 executor.submit(evaluate, item)
```

然后对进程池执行相同的操作：

```py
with concurrent.futures.ProcessPoolExecutor(max_workers=5) as executor:
 for item in number_list:
 executor.submit(evaluate, item)
```

请注意，线程池和进程池都设置为`max_workers=5`；此外，如果`max_workers`等于`None`，它将默认为机器上的处理器数量。

要运行此示例，打开命令提示符，并在包含示例的相同文件夹中输入以下内容：

```py
> python concurrent_futures_pooling.py
```

通过执行上述例子，我们可以看到三种执行模型的执行时间：

```py
Item 1, result 10000000
Item 2, result 20000000
Item 3, result 30000000
Item 4, result 40000000
Item 5, result 50000000
Item 6, result 60000000
Item 7, result 70000000
Item 8, result 80000000
Item 9, result 90000000
Item 10, result 100000000
Sequential Execution in 6.8109448 seconds
Item 2, result 20000000
Item 1, result 10000000
Item 4, result 40000000
Item 5, result 50000000
Item 3, result 30000000
Item 8, result 80000000
Item 7, result 70000000
Item 6, result 60000000
Item 10, result 100000000
Item 9, result 90000000
Thread Pool Execution in 6.805766899999999 seconds
Item 1, result 10000000
Item 4, result 40000000
Item 2, result 20000000
Item 3, result 30000000
Item 5, result 50000000
Item 6, result 60000000
Item 7, result 70000000
Item 9, result 90000000
Item 8, result 80000000
Item 10, result 100000000
Process Pool Execution in 4.166398899999999 seconds
```

需要注意的是，尽管这个例子在计算方面不算昂贵，但是顺序执行和线程池执行在时间上是可比的。使用进程池可以获得最快的执行时间。

然后，池将进程（在本例中为五个进程）以**FIFO**（先进先出）模式分配给可用的核心（对于本例，使用了一个有四个核心的机器）。

因此，对于每个核心，分配的进程按顺序运行。只有在执行 I/O 操作后，池才会安排执行另一个进程。当然，如果使用线程池，执行机制是相同的。

在进程池的情况下，计算时间较短，这要归因于 I/O 操作不重要的事实。这使得进程池可以更快，因为与线程不同，它们不需要任何同步机制（如在*并行计算和 Python 入门*的*介绍并行编程*中所解释的）。

# 还有更多...

池技术广泛用于服务器应用程序，因为需要处理来自任意数量客户端的多个同时请求。

然而，许多其他应用程序要求每个活动立即执行，或者您对运行它的线程有更多控制：在这种情况下，池不是最佳选择。

# 另请参阅

在这里可以找到有关`concurrent.futures`的有趣教程：[`masnun.com/2016/03/29/python-a-quick-introduction-to-the-concurrent-futures-module.html`](http://masnun.com/2016/03/29/python-a-quick-introduction-to-the-concurrent-futures-module.html)。

# 使用 asyncio 管理事件循环

`asyncio` Python 模块提供了管理事件、协程、任务以及线程和同步原语以编写并发代码的便利设施。

该模块的主要组件如下：

+   **事件循环**：`asyncio`模块允许每个进程一个事件循环。这是处理和分配执行不同任务的实体。特别是，它注册任务并通过从一个任务切换控制流来管理它们。

+   **协程**：这是子例程概念的泛化。此外，协程可以在执行期间暂停以等待外部处理（I/O 中的某个例程）并在外部处理完成时从停止的点返回。

+   **Futures**：这与`concurrent.futures`模块完全相同。它表示*尚未完成的计算*。

+   **任务**：这是`asyncio`的一个子类，用于以并行模式封装和管理协程。

在这个配方中，重点是软件程序中的事件和事件管理（即事件循环）的概念。

# 理解事件循环

在计算机科学中，*事件*是程序拦截并可以由程序本身管理的操作。例如，事件可以是用户在与图形界面交互期间虚拟按键的压力，物理键盘上的按键压力，外部中断信号，或者更抽象地说，通过网络接收数据。但更一般地，任何其他形式的事件发生都可以以某种方式被检测和管理。

在系统内，可以生成事件的实体称为*事件源*，而处理发生的事件的实体称为事件处理程序。

*事件循环*编程构造实现了程序内部事件的管理功能。更确切地说，事件循环在整个程序执行期间循环执行，跟踪发生的事件并将其排队，然后通过调用事件处理程序逐个处理它们，如果主线程空闲。

事件循环管理器的伪代码如下所示：

```py
while (1) {
 events = getEvents()
 for (e in events)
 processEvent(e)
}
```

所有输入`while`循环的事件都被捕获，然后由事件处理程序处理。处理事件的处理程序是系统中唯一正在进行的活动。处理程序结束后，控制权转移到下一个计划的事件。

`asyncio`提供以下方法来管理事件循环：

+   `loop = get_event_loop()`: 这获取当前上下文的事件循环。

+   `loop.call_later(time_delay,callback,argument)`: 这安排在给定的`time_delay`后调用回调，单位为秒。

+   `loop.call_soon(callback, argument)`: 这安排一个回调尽快被调用。当控制返回到事件循环时，`call_soon()`（[`docs.python.org/3/library/asyncio-eventloop.html`](https://docs.python.org/3/library/asyncio-eventloop.html)）返回后调用回调。

+   `loop.time()`: 这将根据事件循环的内部时钟返回当前时间作为`float`值（[`docs.python.org/3/library/functions.html`](https://docs.python.org/3/library/functions.html)）。

+   `asyncio.set_event_loop()`: 这将当前上下文的事件循环设置为`loop`。

+   `asyncio.new_event_loop()`: 这根据此策略的规则创建并返回一个新的事件循环对象。

+   `loop.run_forever()`: 这将一直运行，直到调用`stop()`（[`docs.python.org/3/library/asyncio-eventloop.html`](https://docs.python.org/3/library/asyncio-eventloop.html)）。

# 如何做到这一点...

在这个例子中，我们看一下如何使用`asyncio`库提供的事件循环语句，以便构建一个以异步模式工作的应用程序。

在这个例子中，我们定义了三个任务。每个任务的执行时间由一个随机时间参数确定。一旦执行完成，**Task A**调用**Task B**，**Task B**调用**Task C**，**Task C**调用**Task A**。

事件循环将持续进行，直到满足终止条件。正如我们可以想象的那样，这个例子遵循这个异步模式：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/49fee3e4-437a-47a5-b656-1ecf755cf488.png)

异步编程模型

让我们看看以下步骤：

1.  让我们从导入我们实现所需的库开始：

```py
import asyncio
import time
import random
```

1.  然后，我们定义了`task_A`，其执行时间是随机确定的，可以从`1`到`5`秒不等。在执行结束时，如果终止条件没有满足，那么计算就会转到`task_B`：

```py
def task_A(end_time, loop):
 print ("task_A called")
 time.sleep(random.randint(0, 5))
 if (loop.time() + 1.0) < end_time:
 loop.call_later(1, task_B, end_time, loop)
 else:
 loop.stop()
```

1.  在这里，定义了`task_B`。它的执行时间是随机确定的，可以从`4`到`7`秒不等。在执行结束时，如果终止条件没有满足，那么计算就会转到`task_B`：

```py
def task_B(end_time, loop):
 print ("task_B called ")
 time.sleep(random.randint(3, 7))
 if (loop.time() + 1.0) < end_time:
 loop.call_later(1, task_C, end_time, loop)
 else:
 loop.stop()
```

1.  然后，实现`task_C`。它的执行时间是随机确定的，可以从`6`到`10`秒不等。在执行结束时，如果终止条件没有满足，那么计算就会回到`task_A`：

```py
def task_C(end_time, loop):
 print ("task_C called")
 time.sleep(random.randint(5, 10))
 if (loop.time() + 1.0) < end_time:
 loop.call_later(1, task_A, end_time, loop)
 else:
 loop.stop()
```

1.  下一个语句定义了`loop`参数，它只是获取当前事件循环：

```py
loop = asyncio.get_event_loop()
```

1.  `end_loop`值定义了终止条件。这个例子代码的执行时间必须为`60`秒：

```py
end_loop = loop.time() + 60
```

1.  然后，让我们请求执行`task_A`：

```py
loop.call_soon(task_A, end_loop, loop)
```

1.  现在，我们设置一个长时间循环，直到停止响应事件为止：

```py
loop.run_forever()
```

1.  现在，关闭事件循环：

```py
loop.close()
```

# 它是如何工作的...

为了管理三个任务`task_A`、`task_B`和`task_C`的执行，我们需要捕获事件循环：

```py
loop = asyncio.get_event_loop()
```

然后，我们使用`call_soon`构造安排第一次调用`task_A`：

```py
end_loop = loop.time() + 60
loop.call_soon(function_1, end_loop, loop)
```

让我们注意`task_A`的定义：

```py
def task_A(end_time, loop):
 print ("task_A called")
 time.sleep(random.randint(0, 5))
 if (loop.time() + 1.0) < end_time:
 loop.call_later(1, task_B, end_time, loop)
 else:
 loop.stop()
```

应用程序的异步行为由以下参数确定：

+   `time.sleep(random.randint(0, 5))`: 这定义了任务执行的持续时间。

+   `end_time`: 这定义了`task_A`中的上限时间，并通过`call_later`方法调用`task_B`。

+   `loop`: 这是之前使用`get_event_loop()`方法捕获的事件循环。

在执行任务后，将`loop.time`与`end_time`进行比较。如果执行时间在最大时间（60 秒）内，那么通过调用`task_B`继续计算，否则，计算结束，关闭事件循环：

```py
 if (loop.time() + 1.0) < end_time:
 loop.call_later(1, task_B, end_time, loop)
 else:
 loop.stop()
```

对于另外两个任务，操作几乎相同，只是执行时间和对下一个任务的调用不同。

现在，让我总结一下情况：

1.  `task_A`以 1 到 5 秒之间的随机执行时间调用`task_B`。

1.  `task_B`以 4 到 7 秒之间的随机执行时间调用`task_C`。

1.  `task_C`以 6 到 10 秒之间的随机执行时间调用`task_A`。

当运行时间到期时，事件循环必须结束：

```py
loop.run_forever()
loop.close()
```

此示例的可能输出如下：

```py
task_A called
task_B called 
task_C called
task_A called
task_B called 
task_C called
task_A called
task_B called 
task_C called
task_A called
task_B called 
task_C called
task_A called
task_B called 
task_C called
```

# 还有更多...

异步事件编程取代了一种并发编程，其中程序的几个部分由具有对同一内存中数据的访问权限的不同线程同时执行，从而产生了关键运行的问题。与此同时，能够利用现代 CPU 的不同核心已经变得至关重要，因为在某些领域，单核处理器已经无法实现类似于后者提供的性能。

# 另请参阅

这是一个关于`asyncio`的很好的介绍：[`hackernoon.com/a-simple-introduction-to-pythons-asyncio-595d9c9ecf8c`](https://hackernoon.com/a-simple-introduction-to-pythons-asyncio-595d9c9ecf8c)。

# 使用 asyncio 处理协程

在我们所呈现的各种示例中，我们已经看到，当程序变得非常长和复杂时，将其分成子程序是方便的，每个子程序实现一个特定的任务。但是，子程序不能独立执行，而只能在主程序的请求下执行，主程序负责协调子程序的使用。

在这一部分，我们介绍了子程序概念的一个泛化，称为协程：就像子程序一样，协程计算单个计算步骤，但与子程序不同的是，没有“主”程序来协调结果。协程将自己链接在一起，形成一个管道，没有任何监督功能负责按特定顺序调用它们。

在协程中，执行点可以被暂停并稍后恢复，因为协程跟踪执行状态。拥有一组协程后，可以交错计算：第一个运行直到*将控制权让出*，然后第二个运行并继续下去。

交错由事件循环管理，该事件循环在*使用 asyncio 管理事件循环*配方中进行了描述。它跟踪所有协程，并安排它们何时执行。

协程的其他重要方面如下：

+   协程允许多个入口点，可以多次产生。

+   协程可以将执行转移到任何其他协程。

在这里，术语*yield*用于描述协程暂停并将控制流传递给另一个协程。

# 准备就绪

我们将使用以下表示法来处理协程：

```py
import asyncio 

@asyncio.coroutine
def coroutine_function(function_arguments):
 ............
 DO_SOMETHING
 ............ 
```

协程使用 PEP 380 中引入的`yield from`语法（在[`www.python.org/dev/peps/pep-0380/`](https://www.python.org/dev/peps/pep-0380/)中阅读更多）来停止当前计算的执行并挂起协程的内部状态。

特别是在`yield from future`的情况下，协程被挂起，直到`future`完成，然后将传播`future`的结果（或引发异常）；在`yield from coroutine`的情况下，协程等待另一个协程产生结果，该结果将被传播（或引发异常）。

正如我们将在下一个示例中看到的，其中协程将用于模拟有限状态机，我们将使用`yield from coroutine`表示法。

有关使用`asyncio`的协程的更多信息，请访问[`docs.python.org/3.5/library/asyncio-task.html`](https://docs.python.org/3.5/library/asyncio-task.html)。

# 如何做...

在这个示例中，我们看到如何使用协程来模拟具有五个状态的有限状态机。

**有限状态机**或**有限状态自动机**是一种在工程学科中广泛使用的数学模型，也在数学和计算机科学等科学中使用。

我们想要使用协程模拟行为的自动机如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/11c82c0c-3add-446c-8ca7-ba4f599bc622.png)

有限状态机

系统的状态为**S0**、**S1**、**S2**、**S3**和**S4**，其中**0**和**1**是自动机可以从一个状态过渡到下一个状态的值（这个操作称为*过渡*）。例如，状态**S0**可以过渡到状态**S1**，但只能为值**1**，**S0**可以过渡到状态**S2**，但只能为值**0**。

以下 Python 代码模拟了自动机从状态**S0**（起始状态）到状态**S4**（结束状态）的过渡：

1.  首先要做的是导入相关的库：

```py
import asyncio
import time
from random import randint
```

1.  然后，我们定义了相对于`start_state`的协程。`input_value`参数是随机评估的；它可以是`0`或`1`。如果是`0`，则控制转移到协程`state2`；否则，它会改变为协程`state1`：

```py
@asyncio.coroutine
def start_state():
 print('Start State called\n')
 input_value = randint(0, 1)
 time.sleep(1)
 if input_value == 0:
 result = yield from state2(input_value)
 else:
 result = yield from state1(input_value)
 print('Resume of the Transition:\nStart State calling'+ result)
```

1.  这是`state1`的协程。`input_value`参数是随机评估的；它可以是`0`或`1`。如果是`0`，则控制转移到`state2`；否则，它会改变为`state1`：

```py
@asyncio.coroutine
def state1(transition_value):
 output_value ='State 1 with transition value = %s\n'% \
 transition_value
 input_value = randint(0, 1)
 time.sleep(1)
 print('...evaluating...')
 if input_value == 0:
 result = yield from state3(input_value)
 else:
 result = yield from state2(input_value)
 return output_value + 'State 1 calling %s' % result
```

1.  `state1`的协程具有允许状态过渡的`transition_value`参数。同样，在这种情况下，`input_value`是随机评估的。如果是`0`，则状态转换到`state3`；否则，控制转移到`state2`：

```py
@asyncio.coroutine
def state2(transition_value):
 output_value = 'State 2 with transition value = %s\n' %\
 transition_value
 input_value = randint(0, 1)
 time.sleep(1)
 print('...evaluating...')
 if input_value == 0:
 result = yield from state1(input_value)
 else:
 result = yield from state3(input_value)
 return output_value + 'State 2 calling %s' % result
```

1.  `state3`的协程具有`transition_value`参数，允许状态过渡。`input_value`是随机评估的。如果是`0`，则状态转换到`state1`；否则，控制转移到`end_state`：

```py
@asyncio.coroutine
def state3(transition_value):
 output_value = 'State 3 with transition value = %s\n' %\
 transition_value
 input_value = randint(0, 1)
 time.sleep(1)
 print('...evaluating...')
 if input_value == 0:
 result = yield from state1(input_value)
 else:
 result = yield from end_state(input_value)
 return output_value + 'State 3 calling %s' % result
```

1.  `end_state`打印出允许状态过渡的`transition_value`参数，然后停止计算：

```py
@asyncio.coroutine
def end_state(transition_value):
 output_value = 'End State with transition value = %s\n'%\
 transition_value
 print('...stop computation...')
 return output_value
```

1.  在`__main__`函数中，获取事件循环，然后我们开始模拟有限状态机，调用自动机的`start_state`：

```py
if __name__ == '__main__':
 print('Finite State Machine simulation with Asyncio Coroutine')
 loop = asyncio.get_event_loop()
 loop.run_until_complete(start_state())
```

# 它是如何工作的...

自动机的每个状态都是通过装饰器定义的：

```py
 @asyncio.coroutine
```

例如，状态**S0**在这里被定义：

```py
@asyncio.coroutine
def StartState():
 print ("Start State called \n")
 input_value = randint(0,1)
 time.sleep(1)
 if (input_value == 0):
 result = yield from State2(input_value)
 else :
 result = yield from State1(input_value)
```

下一个状态的过渡由`input_value`决定，它由 Python 的`random`模块的`randint (0,1)`函数定义。这个函数随机提供`0`或`1`的值。

这样，`randint`随机确定有限状态机将过渡到的状态：

```py
input_value = randint(0,1)
```

确定要传递的值后，协程使用`yield from`命令调用下一个协程：

```py
if (input_value == 0):
 result = yield from State2(input_value)
 else :
 result = yield from State1(input_value)
```

`result`变量是每个协程返回的值。它是一个字符串，在计算结束时，我们可以重构从自动机的初始状态`start_state`到`end_state`的过渡。

`main`程序在事件循环内开始评估：

```py
if __name__ == "__main__":
 print("Finite State Machine simulation with Asyncio Coroutine")
 loop = asyncio.get_event_loop()
 loop.run_until_complete(StartState())
```

运行代码，我们有以下输出：

```py
Finite State Machine simulation with Asyncio Coroutine
Start State called
...evaluating...
...evaluating...
...evaluating...
...evaluating...
...stop computation...
Resume of the Transition : 
Start State calling State 1 with transition value = 1
State 1 calling State 2 with transition value = 1
State 2 calling State 1 with transition value = 0
State 1 calling State 3 with transition value = 0
State 3 calling End State with transition value = 1
```

# 还有更多...

在 Python 3.5 发布之前，`asyncio`模块使用生成器来模拟异步调用，因此与 Python 3.5 的当前版本有不同的语法。

Python 3.5 引入了`async`和`await`关键字。请注意，在`await func()`调用周围没有括号。

以下是一个使用 Python 3.5+引入的新语法和`asyncio`的`"Hello, world!"`的示例：

```py
import asyncio

async def main():
 print(await func())

async def func():
 # Do time intensive stuff...
 return "Hello, world!"

if __name__ == "__main__":
 loop = asyncio.get_event_loop()
 loop.run_until_complete(main())
```

# 另请参阅

Python 中的协程在这里有很好的描述：[`www.geeksforgeeks.org/coroutine-in-python/`](https://www.geeksforgeeks.org/coroutine-in-python/)。

# 使用 asyncio 操纵任务

`asyncio`模块旨在处理异步进程和事件循环上的并发任务执行。它还提供了`asyncio.Task()`类，用于将协程包装在任务中（[`docs.python.org/3/library/asyncio-task.html`](https://docs.python.org/3/library/asyncio-task.html)）。它的用途是允许独立运行的任务与同一事件循环上的其他任务并发运行。

当一个协程被包装在一个任务中时，它将`Task`连接到事件循环，然后在循环启动时自动运行，从而提供了自动驱动协程的机制。

`asyncio`模块提供了`asyncio.Task(coroutine)`方法来处理任务的计算；此外，`asyncio.Task(coroutine)`安排了协程的执行（[`docs.python.org/3/library/asyncio-task.html`](https://docs.python.org/3/library/asyncio-task.html)）。

一个任务负责在*事件循环*中执行一个协程对象。

如果包装的协程使用`yields from future`表示法，如*使用 asyncio 处理协程*部分中已经描述的那样，那么任务将暂停包装的协程的执行并等待未来的完成。

当未来完成时，包装的协程的执行将重新开始，使用未来的结果或异常。此外，必须注意，事件循环一次只运行一个任务。如果其他事件循环在不同的线程中运行，则其他任务可以并行运行。

当任务等待未来的完成时，事件循环执行一个新任务。

# 如何做到这一点...

在这个例子中，我们展示了如何通过`asyncio.Task()`语句同时执行三个数学函数：

1.  当然，让我们首先导入`asyncio`库：

```py
import asyncio
```

1.  在第一个协程中，定义了`factorial`函数：

```py
@asyncio.coroutine
def factorial(number):
 f = 1
 for i in range(2, number + 1):
 print("Asyncio.Task: Compute factorial(%s)" % (i))
 yield from asyncio.sleep(1)
 f *= i
 print("Asyncio.Task - factorial(%s) = %s" % (number, f))
```

1.  之后，定义第二个函数——`fibonacci`函数：

```py
@asyncio.coroutine
def fibonacci(number):
 a, b = 0, 1
 for i in range(number):
 print("Asyncio.Task: Compute fibonacci (%s)" % (i))
 yield from asyncio.sleep(1)
 a, b = b, a + b
 print("Asyncio.Task - fibonacci(%s) = %s" % (number, a))
```

1.  最后并行执行的函数是二项式系数：

```py
@asyncio.coroutine
def binomial_coefficient(n, k):
 result = 1
 for i in range(1, k + 1):
 result = result * (n - i + 1) / i
 print("Asyncio.Task: Compute binomial_coefficient (%s)" % 
 (i))
 yield from asyncio.sleep(1)
 print("Asyncio.Task - binomial_coefficient(%s , %s) = %s" % 
 (n,k,result))
```

1.  在`__main__`函数中，`task_list`包含了必须使用`asyncio.Task`函数并行执行的函数：

```py
if __name__ == '__main__':
 task_list = [asyncio.Task(factorial(10)),
 asyncio.Task(fibonacci(10)),
 asyncio.Task(binomial_coefficient(20, 10))]
```

1.  最后，我们获取事件循环并开始计算：

```py
 loop = asyncio.get_event_loop()
 loop.run_until_complete(asyncio.wait(task_list))
 loop.close()
```

# 它是如何工作的...

每个协程都由`@asyncio.coroutine`注释（称为*装饰器*）定义：

```py
@asyncio.coroutine
def function (args):
 do something
```

为了并行运行，每个函数都是`asyncio.Task`模块的参数，因此它们包含在`task_list`中：

```py
if __name__ == '__main__':
 task_list = [asyncio.Task(factorial(10)),
 asyncio.Task(fibonacci(10)),
 asyncio.Task(binomial_coefficient(20, 10))]
```

然后，我们得到了事件循环：

```py
 loop = asyncio.get_event_loop()
```

最后，我们将`task_list`的执行添加到事件循环中：

```py
 loop.run_until_complete(asyncio.wait(task_list))
 loop.close()
```

请注意，`asyncio.wait(task_list)`语句等待给定的协程完成。

上述代码的输出如下：

```py
Asyncio.Task: Compute factorial(2)
Asyncio.Task: Compute fibonacci(0)
Asyncio.Task: Compute binomial_coefficient(1)
Asyncio.Task: Compute factorial(3)
Asyncio.Task: Compute fibonacci(1)
Asyncio.Task: Compute binomial_coefficient(2)
Asyncio.Task: Compute factorial(4)
Asyncio.Task: Compute fibonacci(2)
Asyncio.Task: Compute binomial_coefficient(3)
Asyncio.Task: Compute factorial(5)
Asyncio.Task: Compute fibonacci(3)
Asyncio.Task: Compute binomial_coefficient(4)
Asyncio.Task: Compute factorial(6)
Asyncio.Task: Compute fibonacci(4)
Asyncio.Task: Compute binomial_coefficient(5)
Asyncio.Task: Compute factorial(7)
Asyncio.Task: Compute fibonacci(5)
Asyncio.Task: Compute binomial_coefficient(6)
Asyncio.Task: Compute factorial(8)
Asyncio.Task: Compute fibonacci(6)
Asyncio.Task: Compute binomial_coefficient(7)
Asyncio.Task: Compute factorial(9)
Asyncio.Task: Compute fibonacci(7)
Asyncio.Task: Compute binomial_coefficient(8)
Asyncio.Task: Compute factorial(10)
Asyncio.Task: Compute fibonacci(8)
Asyncio.Task: Compute binomial_coefficient(9)
Asyncio.Task - factorial(10) = 3628800
Asyncio.Task: Compute fibonacci(9)
Asyncio.Task: Compute binomial_coefficient(10)
Asyncio.Task - fibonacci(10) = 55
Asyncio.Task - binomial_coefficient(20, 10) = 184756.0
```

# 还有更多...

`asyncio`提供了使用`ensure_future()`或`AbstractEventLoop.create_task()`方法调度任务的其他方法，两者都接受一个协程对象。

# 另请参阅

关于`asyncio`和任务的更多信息可以在这里找到：[`tutorialedge.net/python/concurrency/asyncio-tasks-tutorial/`](https://tutorialedge.net/python/concurrency/asyncio-tasks-tutorial/)。

# 处理 asyncio 和 futures

`asyncio`模块的另一个关键组件是`asyncio.Future`类。它与`concurrent.Futures`非常相似，但当然，它适应了`asyncio`的主要机制：事件循环。

`asyncio.Future`类代表尚不可用的结果（但也可以是异常）。

因此，它代表了一些尚未实现的东西的抽象。必须注意的是，必须处理任何结果的回调实际上是添加到这个类的实例中。

# 准备工作

要定义一个`future`对象，必须使用以下语法：

```py
future = asyncio.Future
```

管理此对象的主要方法如下：

+   `cancel()`: 这将取消`future`对象并安排回调。

+   `result()`: 返回此`future`代表的结果。

+   `exception()`: 返回在此`future`上设置的异常。

+   `add_done_callback(fn)`: 这将在`future`完成时添加一个回调来运行。

+   `remove_done_callback(fn)`: 这将从完成时的调用中删除所有回调的实例。

+   `set_result(result)`: 这标记`future`为完成并设置其结果。

+   `set_exception(exception)`: 这标记`future`为完成并设置异常。

# 如何做到这一点...

以下示例显示了如何使用`asyncio.Future`类来管理两个协程：`first_coroutine`和`second_coroutine`，它们执行以下任务。`first_coroutine`执行前*N*个整数的和，`second_coroutine`执行 N 的阶乘：

1.  现在，让我们导入相关的库：

```py
import asyncio
import sys
```

1.  `first_coroutine`实现了前*N*个整数的`sum`函数：

```py
@asyncio.coroutine
def first_coroutine(future, num):
 count = 0
 for i in range(1, num + 1):
 count += i
 yield from asyncio.sleep(1)
 future.set_result('First coroutine (sum of N integers)\
 result = %s' % count)
```

1.  在`second_coroutine`中，我们仍然实现`factorial`函数：

```py
@asyncio.coroutine
def second_coroutine(future, num):
 count = 1
 for i in range(2, num + 1):
 count *= i
 yield from asyncio.sleep(2)
 future.set_result('Second coroutine (factorial) result = %s' %\ 
 count)
```

1.  使用`got_result`函数，我们打印计算的输出：

```py
def got_result(future):
 print(future.result())
```

1.  在`main`函数中，`num1`和`num2`参数必须由用户设置。它们将作为第一个和第二个协程实现的函数的参数：

```py
if __name__ == "__main__":
 num1 = int(sys.argv[1])
 num2 = int(sys.argv[2])
```

1.  现在，让我们来看事件循环：

```py
 loop = asyncio.get_event_loop()
```

1.  这里，期货由`asyncio.future`函数定义：

```py
 future1 = asyncio.Future()
 future2 = asyncio.Future()
```

1.  `tasks`列表中包含的两个协程`first_couroutine`和`second_couroutine`分别具有`future1`和`future2`期货、用户定义的参数以及`num1`和`num2`参数：

```py
tasks = [first_coroutine(future1, num1),
 second_coroutine(future2, num2)]
```

1.  期货已添加回调：

```py
 future1.add_done_callback(got_result)
 future2.add_done_callback(got_result)
```

1.  然后，将`tasks`列表添加到事件循环中，以便开始计算：

```py
 loop.run_until_complete(asyncio.wait(tasks))
 loop.close()
```

# 工作原理...

在`main`程序中，我们分别使用`asyncio.Future()`指令定义`future`对象`future1`和`future2`：

```py
if __name__ == "__main__":
 future1 = asyncio.Future()
 future2 = asyncio.Future()
```

在定义任务时，我们将`future`对象作为两个协程`first_couroutine`和`second_couroutine`的参数传递：

```py
tasks = [first_coroutine(future1,num1), 
 second_coroutine(future2,num2)]
```

最后，我们添加一个回调函数，当`future`完成时运行：

```py
future1.add_done_callback(got_result)
future2.add_done_callback(got_result)
```

这里，`got_result`是一个打印`future`结果的函数：

```py
def got_result(future):
 print(future.result())
```

在协程中，我们将`future`对象作为参数传递。计算后，我们为第一个协程设置 3 秒的睡眠时间，第二个协程设置 4 秒的睡眠时间：

```py
yield from asyncio.sleep(sleep_time)
```

通过使用不同的值执行命令可以获得以下输出：

```py
> python asyncio_and_futures.py 1 1
First coroutine (sum of N integers) result = 1
Second coroutine (factorial) result = 1

> python asyncio_and_futures.py 2 2
First coroutine (sum of N integers) result = 2 Second coroutine (factorial) result = 2

> python asyncio_and_futures.py 3 3
First coroutine (sum of N integers) result = 6
Second coroutine (factorial) result = 6

> python asyncio_and_futures.py 5 5
First coroutine (sum of N integers) result = 15
Second coroutine (factorial) result = 120
 > python asyncio_and_futures.py 50 50
First coroutine (sum of N integers) result = 1275
Second coroutine (factorial) result = 30414093201713378043612608166064768844377641568960512000000000000 
First coroutine (sum of N integers) result = 1275 
```

# 还有更多...

我们可以颠倒输出结果，即通过简单地交换协程之间的睡眠时间来先输出`second_coroutine`的输出，即在`first_coroutine`定义中使用`yield from asyncio.sleep(2)`，在`second_coroutine`定义中使用`yield from asyncio.sleep(1)`。以下示例可以说明这一点：

```py
> python asyncio_and_future.py 1 10
second coroutine (factorial) result = 3628800
first coroutine (sum of N integers) result = 1
```

# 参见

更多关于`asyncio`和期货的示例可以在[`www.programcreek.com/python/example/102763/asyncio.futures`](https://www.programcreek.com/python/example/102763/asyncio.futures)找到。


# 第六章：分布式 Python

本章将介绍一些重要的 Python 模块，用于分布式计算。特别是，我们将描述`socket`模块，它允许您通过客户端-服务器模型实现简单的分布式应用程序。

然后，我们将介绍 Celery 模块，这是一个强大的 Python 框架，用于管理分布式任务。最后，我们将描述`Pyro4`模块，它允许您调用在不同进程中使用的方法，可能在不同的机器上。

在本章中，我们将介绍以下内容：

+   介绍分布式计算

+   使用 Python 的 socket 模块

+   使用 Celery 进行分布式任务管理

+   使用`Pyro4`进行远程方法调用（RMI）

# 介绍分布式计算

*并行*和*分布式计算*是类似的技术，旨在增加特定任务的处理能力。通常，这些方法用于解决需要大量计算能力的问题。

当问题被分成许多小部分时，问题的各个部分可以同时由许多处理器计算。这允许问题上的处理能力比单个处理器提供的要多。

并行处理和分布式处理的主要区别在于，并行配置在单个系统内包含许多处理器，而分布式配置利用许多计算机的处理能力。

让我们看看其他的区别：

| **并行处理** | **分布式处理** |
| --- | --- |
| 并行处理具有提供可靠处理能力并具有非常低延迟的优势。 | 分布式处理在处理器的基础上并不是非常高效，因为数据必须通过网络传输，而不是通过单个系统的内部连接传输。 |
| 通过将所有处理能力集中在一个系统中，可以最大程度地减少由于数据传输而导致的速度损失。 | 由于数据传输会产生限制处理能力的瓶颈，因此每个处理器提供的处理能力远远低于并行系统中的任何处理器。 |
| 唯一的真正限制是系统中集成的处理器数量。 | 由于分布式系统中处理器数量没有实际上限，因此系统几乎可以无限扩展。 |

然而，在计算机应用的背景下，习惯上区分本地架构和分布式架构：

| **本地架构** | **分布式架构** |
| --- | --- |
| 所有组件都在同一台机器上。 | 应用程序和组件可以驻留在由网络连接的不同节点上。 |

使用分布式计算的优势主要在于程序的并发使用、数据的集中化以及处理负载的分布，但这些优势都伴随着更大的复杂性，特别是在各个组件之间的通信方面。

# 分布式应用程序的类型

分布式应用程序可以根据分布程度进行分类：

+   **客户端-服务器应用程序**

+   **多级应用程序**

# 客户端-服务器应用程序

只有两个级别，操作完全在服务器上进行。例如，我们可以提到经典的静态或动态网站。实现这些类型应用的工具是网络套接字，可以用多种语言进行编程，包括 C、C++、Java，当然还有 Python。

术语*客户端-服务器系统*指的是一个网络架构，其中客户端计算机或客户端终端通常连接到服务器以使用某项服务；例如，与其他客户端共享某些硬件/软件资源，或依赖底层协议架构。

# 客户端-服务器架构

客户端-服务器架构是一个实现处理和数据分布的系统。架构的中心元素是服务器。服务器可以从逻辑和物理角度来考虑。从物理角度来看，服务器是专门用于运行软件服务器的机器。

从逻辑上看，服务器是软件。服务器作为逻辑进程，为扮演请求者或客户端角色的其他进程提供服务。通常情况下，服务器直到客户端请求结果之前不会将结果发送给请求者。

区分客户端和服务器的一个特征是客户端可以与服务器启动事务，而服务器永远不能主动与客户端启动事务：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/f9df2fb0-1a78-4826-b494-5e3b43effbf0.png)

客户端-服务器架构

事实上，客户端的具体任务是启动事务，请求特定服务，通知服务完成，并从服务器接收结果，如前图所示。

# 客户端-服务器通信

客户端和服务器之间的通信可以使用各种机制——从地理网络到本地网络，直到操作系统级别的应用程序之间的通信服务。此外，客户端-服务器架构必须独立于客户端和服务器之间存在的物理连接方法。

还应该注意的是，客户端-服务器进程不必驻留在物理上分离的系统上。事实上，服务器进程和客户端进程可以驻留在同一计算平台上。

在数据管理的背景下，客户端-服务器架构的主要目标是允许客户端应用程序访问服务器管理的数据。服务器（在逻辑上理解为软件）通常运行在远程系统上（例如，在另一个城市或本地网络上）。

因此，客户端-服务器应用程序通常与分布式处理相关联。

# TCP/IP 客户端-服务器架构

TCP/IP 连接在两个应用程序之间建立了点对点的连接。这种连接的两端由 IP 地址标记，IP 地址标识了工作站，而端口号使得可以在同一工作站上连接到独立应用程序的多个连接。

一旦连接建立，协议可以在其上交换数据，底层的 TCP/IP 协议负责将这些数据分成数据包，从连接的一端发送到另一端。特别是，TCP 协议负责组装和拆卸数据包，以及管理握手来保证连接的可靠性，而 IP 协议负责传输单个数据包和选择最佳的路由来沿着网络传输数据包。

这种机制是 TCP/IP 协议稳健性的基础，而 TCP/IP 协议的发展又是军事领域（ARPANET）发展的原因之一。

各种现有的标准应用程序（如 Web 浏览、文件传输和电子邮件）使用标准化的应用程序协议，如 HTTP、FTP、POP3、IMAP 和 SMTP。

每个特定的客户端-服务器应用程序必须定义和应用自己的专有应用程序协议。这可能涉及以固定大小的数据块交换数据（这是最简单的解决方案）。

# 多级应用程序

有更多级别可以减轻服务器的处理负载。实际上，被细分的是服务器端的功能，而客户端部分的特性基本保持不变，其任务是托管应用程序界面。这种架构的一个例子是三层模型，其结构分为三层或级别：

+   前端或演示层或界面

+   中间层或应用逻辑

+   后端或数据层或持久数据管理

这种命名方式通常用于 Web 应用程序。更一般地，可以将任何软件应用程序分为三个级别，如下所示：

+   **表示层**（**PL**）：这是数据的可视化部分（例如用户界面所需的模块和输入控件）。

+   **业务逻辑层**（**BLL**）：这是应用程序的主要部分，独立于用户可用的演示方法并保存在档案中，定义了各种实体及其关系。

+   **数据访问层**（**DAL**）：其中包含管理持久数据所需的一切（基本上是数据库管理系统）。

本章将介绍 Python 提出的一些分布式架构的解决方案。我们将首先描述`socket`模块，然后使用它来实现一些基本的客户端-服务器模型的示例。

# 使用 Python 套接字模块

套接字是一种软件对象，允许在远程主机（通过网络）或本地进程之间发送和接收数据，例如**进程间通信**（**IPC**）。

套接字是在伯克利作为**BSD Unix**项目的一部分发明的。它们基于 Unix 文件的输入和输出管理模型。事实上，打开、读取、写入和关闭套接字的操作与 Unix 文件的管理方式相同，但需要考虑的区别是用于通信的有用参数，如地址、端口号和协议。

套接字技术的成功和传播与互联网的发展息息相关。事实上，套接字与互联网的结合使得任何类型的机器之间的通信以及分散在世界各地的机器之间的通信变得非常容易（至少与其他系统相比是如此）。

# 准备就绪

Python 套接字模块公开了用于使用**BSD**（**Berkeley Software Distribution**的缩写）套接字接口进行网络通信的低级 C API。

该模块包括`Socket`类，其中包括管理以下任务的主要方法：

+   `socket([family [, type [, protocol]]])`: 使用以下参数构建套接字：

+   `family`地址，可以是`AF_INET（默认）`，`AF_INET6`，或`AF_UNIX`

+   `type`套接字，可以是`SOCK_STREAM（默认）`，`SOCK_DGRAM`，或者其他`"SOCK_"`常量之一

+   `protocol`号码（通常为零）

+   `gethostname()`: 返回机器的当前 IP 地址。

+   `accept()`: 返回以下一对值（`conn`和`address`），其中`conn`是套接字类型对象（用于在连接上发送/接收数据），而`address`是连接到连接的另一端的套接字的地址。

+   `bind(address)`: 将套接字与服务器的`address`关联。

该方法历史上接受`AF_INET`地址的一对参数，而不是单个元组。

+   `close()`: 提供选项，一旦与客户端的通信结束，就可以清理连接。套接字被关闭并由垃圾收集器收集。

+   `connect(address)`: 将远程套接字连接到地址。`address`格式取决于地址族。

# 如何做到...

在下面的示例中，服务器正在监听默认端口，并通过 TCP/IP 连接，客户端向服务器发送连接建立的日期和时间。

以下是`server.py`的服务器实现：

1.  导入相关的 Python 模块：

```py
import socket
import time
```

1.  使用给定的地址、套接字类型和协议号创建新的套接字：

```py
serversocket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
```

1.  获取本地机器名称（`host`）：

```py
host=socket.gethostname()
```

1.  设置`port`号码：

```py
port=9999
```

1.  将套接字连接（绑定）到`host`和`port`：

```py
serversocket.bind((host,port))
```

1.  监听套接字的连接。`5`的参数指定了队列中的最大连接数。最大值取决于系统（通常为`5`），最小值始终为`0`：

```py
serversocket.listen(5)
```

1.  建立连接：

```py
while True:
```

1.  然后，接受连接。返回值是一对（`conn`，`address`），其中`conn`是用于发送和接收数据的新`socket`对象，`address`是与套接字关联的地址。一旦接受，将创建一个新的套接字，并且它将有自己的标识符。这个新的套接字只用于这个特定的客户端：

```py
clientsocket,addr=serversocket.accept()
```

1.  打印连接的地址和端口：

```py
print ("Connected with[addr],[port]%s"%str(addr))
```

1.  评估`currentTime`：

```py
currentTime=time.ctime(time.time())+"\r\n"
```

1.  以下语句将数据发送到套接字，并返回发送的字节数：

```py
clientsocket.send(currentTime.encode('ascii'))
```

1.  以下语句表示套接字关闭（即通信通道）；套接字上的所有后续操作都将失败。当套接字被拒绝时，它们会自动关闭，但始终建议使用`close()`操作关闭它们：

```py
clientsocket.close()
```

客户端（`client.py`）的代码如下：

1.  导入`socket`库：

```py
import socket
```

1.  然后创建`socket`对象：

```py
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
```

1.  获取本地机器名称（`host`）：

```py
host=socket.gethostname()
```

1.  设置`port`号码：

```py
port=9999
```

1.  建立到`host`和`port`的连接：

```py
s.connect((host,port))
```

可以接收的最大字节数不超过 1024 字节：（`tm=s.recv(1024)`）。

1.  现在，关闭连接并最终打印连接到服务器的连接时间：

```py
s.close()
print ("Time connection server:%s"%tm.decode('ascii'))
```

# 工作原理...

客户端和服务器分别创建它们的套接字，并在一个端口上监听它们。客户端向服务器发出连接请求。应该注意，我们可以有两个不同的端口号，因为一个可能只专用于出站流量，另一个可能只专用于入站流量。这取决于主机配置。

实际上，客户端的本地端口不一定与服务器的远程端口相符。服务器接收请求，如果接受，将创建一个新连接。现在，客户端和服务器通过专门为数据套接字连接的数据流创建的虚拟通道进行通信。

与第一阶段提到的一致，服务器创建数据套接字，因为第一个套接字专门用于处理请求。因此，可能有许多客户端使用服务器为它们创建的数据套接字与服务器进行通信。TCP 协议是面向连接的，这意味着当不再需要通信时，客户端会将此通知服务器，并关闭连接。

要运行示例，请执行服务器：

```py
C:\>python server.py 
```

然后，在不同的 Windows 终端中执行客户端：

```py
C:\>python client.py
```

客户端端的结果应报告地址（`addr`）并报告`port`已连接：

```py
Connected with[addr],port
```

但是，在服务器端，结果应该如下：

```py
Time connection server:Sun Mar 31 20:59:38 2019
```

# 还有更多...

通过对先前的代码进行小改动，我们可以创建一个简单的客户端-服务器应用程序进行文件传输。服务器实例化套接字并等待来自客户端的连接实例。一旦连接到服务器，客户端开始数据传输。

要传输的数据在`mytext.txt`文件中，按字节复制并通过调用`conn.send`函数发送到服务器。服务器然后接收数据并将其写入第二个文件`received.txt`。

`client2.py`的源代码如下：

```py
import socket
s =socket.socket()
host=socket.gethostname()
port=60000
s.connect((host,port))
s.send('HelloServer!'.encode())
with open('received.txt','wb') as f:
 print ('file opened')
 while True :
 print ('receiving data...')
 data=s.recv(1024)
 if not data:
 break
 print ('Data=>',data.decode())
 f.write(data)
f.close()
print ('Successfully get the file')
s.close()
print ('connection closed')
```

以下是`client.py`的源代码：

```py
import socket
port=60000
s =socket.socket()
host=socket.gethostname()
s.bind((host,port))
s.listen(15)
print('Server listening....')
while True :
 conn,addr=s.accept()
 print ('Got connection from',addr)
 data=conn.recv(1024)
 print ('Server received',repr(data.decode()))
 filename='mytext.txt'
 f =open(filename,'rb')
 l =f.read(1024)
 while True:
 conn.send(l)
 print ('Sent',repr(l.decode()))
 l =f.read(1024)
 f.close()
 print ('Done sending')
 conn.send('->Thank you for connecting'.encode())
 conn.close()
```

# 套接字类型

我们可以区分以下三种套接字类型，其特点是连接模式：

+   **流套接字**：这些是面向连接的套接字，它们基于可靠的协议，如 TCP 或 SCTP。

+   **数据报套接字**：这些套接字不是面向连接的（无连接）套接字，而是基于快速但不可靠的 UDP 协议。

+   **原始套接字**（原始 IP）：传输层被绕过，头部在应用层可访问。

# 流套接字

我们将只看到这种类型的套接字。由于它们基于 TCP 等传输层协议，它们保证可靠、全双工和面向连接的通信，具有可变长度的字节流。

通过这个套接字进行通信包括以下阶段：

1.  **套接字的创建**：客户端和服务器创建各自的套接字，并且服务器在端口上监听它们。由于服务器可以与不同客户端（但也可能是同一个客户端）创建多个连接，因此它需要一个队列来处理各种请求。

1.  **连接请求**：客户端请求与服务器建立连接。请注意，我们可以有不同的端口号，因为一个可能只分配给出站流量，另一个只分配给入站流量。这取决于主机配置。基本上，客户端的本地端口不一定与服务器的远程端口相符。服务器接收请求，如果接受，将创建一个新连接。在图中，客户端套接字的端口是`8080`，而服务器套接字的端口是`80`。

1.  **通信**：现在，客户端和服务器通过一个虚拟通道进行通信，介于客户端套接字和一个新的套接字（服务器端）之间，专门为此连接的数据流创建：一个数据套接字。正如在第一阶段中提到的，服务器创建数据套接字，因为第一个数据套接字专门用于处理请求。因此，可能有许多客户端与服务器通信，每个客户端都有服务器专门为其创建的数据套接字。

1.  **连接的关闭**：由于 TCP 是一种面向连接的协议，当不再需要通信时，客户端会通知服务器，服务器会释放数据套接字。

通过流套接字进行通信的阶段如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/4a04807a-ed49-44eb-9f21-2346ea59f835.png)

流套接字阶段

# 另请参阅

有关 Python 套接字的更多信息，请访问[`docs.python.org/3/howto/sockets.html`](https://docs.python.org/3/howto/sockets.html)。

# 使用 Celery 进行分布式任务管理

*Celery*是一个 Python 框架，通过遵循面向对象的中间件方法来管理分布式任务。其主要特点是处理许多小任务并将它们分发到许多计算节点上。最终，每个任务的结果将被重新处理，以组成整体解决方案。

要使用 Celery，需要一个消息代理。这是一个独立的（与 Celery 无关）软件组件，具有中间件的功能，用于向分布式任务工作者发送和接收消息。

事实上，消息代理（也称为消息中间件）处理通信网络中消息的交换：这种中间件的寻址方案不再是点对点类型，而是面向消息的寻址。

消息代理的参考架构，用于管理消息的交换，基于所谓的发布/订阅范式，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/081ba83c-57b4-44c6-aaa5-89f6d9e0989c.png)

消息代理架构

Celery 支持许多类型的代理。但是，更完整的是 RabbitMQ 和 Redis。

# 准备就绪

要安装 Celery，请使用`pip`安装程序，如下所示：

```py
C:\>pip install celery
```

然后，必须安装消息代理。有几种选择可用，但是对于我们的示例，建议从以下链接安装 RabbitMQ：[`www.rabbitmq.com/download.html`](http://www.rabbitmq.com/download.html)。

RabbitMQ 是一个实现 **高级消息队列协议** (**AMQP**) 的消息导向中间件。RabbitMQ 服务器是用 Erlang 编程语言编写的，因此在安装它之前，您需要从 [`www.erlang.org/download.html`](http://www.erlang.org/download.html) 下载并安装 Erlang。涉及的步骤如下：

1.  要检查 `celery` 的安装，首先启动消息代理（例如 RabbitMQ）。然后，输入以下内容：

```py
C:\>celery --version
```

1.  以下输出表示 `celery` 版本：

```py
4.2.2 (Windowlicker)
```

接下来，让我们了解如何使用 `celery` 模块创建和调用任务。

`celery` 提供以下两种方法来调用任务：

+   `apply_async(args[, kwargs[, ...]])`：这发送一个任务消息。

+   `delay(*args, **kwargs)`：这是发送任务消息的快捷方式，但不支持执行选项。

`delay` 方法更容易使用，因为它被调用为**常规函数**：`task.delay(arg1, arg2, kwarg1='x', kwarg2='y')`。然而，对于 `apply_async`，语法是 `task.apply_async (args=[arg1,arg2] kwargs={'kwarg1':'x','kwarg2': 'y'})`。

# Windows 设置

要在 Windows 环境中使用 Celery，必须执行以下过程：

1.  转到系统属性 | 环境变量 | 用户或系统变量 | 新建。

1.  设置以下值：

+   变量名：`FORKED_BY_MULTIPROCESSING`

+   变量值：`1`

进行此设置的原因是因为 Celery 依赖于 `billiard` 包 ([`github.com/celery/billiard`](https://github.com/celery/billiard))，它使用 `FORKED_BY_MULTIPROCESSING` 变量。

有关 Celery 在 Windows 上的设置的更多信息，请阅读 [`www.distributedpython.com/2018/08/21/celery-4-windows/`](https://www.distributedpython.com/2018/08/21/celery-4-windows/)。

# 如何做...

这里的任务是两个数字的和。为了执行这个简单的任务，我们必须组成 `addTask.py` 和 `addTask_main.py` 脚本文件：

1.  对于 `addTask.py`，开始导入 Celery 框架如下：

```py
from celery import Celery
```

1.  然后，定义任务。在我们的示例中，任务是两个数字的和：

```py
app = Celery('tasks', broker='amqp://guest@localhost//')
@app.task
def add(x, y):
 return x + y
```

1.  现在，导入之前定义的 `addTask.py` 文件到 `addtask_main.py` 中：

```py
import addTask
```

1.  然后，调用 `addTask.py` 执行两个数字的和：

```py
if __name__ == '__main__':
 result = addTask.add.delay(5,5)
```

# 工作原理...

要使用 Celery，首先要做的是运行 RabbitMQ 服务，然后执行 Celery 工作者服务器（即 `addTask.py` 文件脚本），方法是输入以下内容：

```py
C:\>celery -A addTask worker --loglevel=info
```

输出如下：

```py
Microsoft Windows [Versione 10.0.17134.648]
(c) 2018 Microsoft Corporation. Tutti i diritti sono riservati.

C:\Users\Giancarlo>cd C:\Users\Giancarlo\Desktop\Python Parallel Programming CookBook 2nd edition\Python Parallel Programming NEW BOOK\chapter_6 - Distributed Python\esempi

C:\Users\Giancarlo\Desktop\Python Parallel Programming CookBook 2nd edition\Python Parallel Programming NEW BOOK\chapter_6 - Distributed Python\esempi>celery -A addTask worker --loglevel=info

 -------------- celery@pc-giancarlo v4.2.2 (windowlicker)
---- **** -----
--- * *** * -- Windows-10.0.17134 2019-04-01 21:32:37
-- * - **** ---
- ** ---------- [config]
- ** ---------- .> app: tasks:0x1deb8f46940
- ** ---------- .> transport: amqp://guest:**@localhost:5672//
- ** ---------- .> results: disabled://
- *** --- * --- .> concurrency: 4 (prefork)
-- ******* ---- .> task events: OFF (enable -E to monitor tasks in this worker)
--- ***** -----
 -------------- [queues]
 .> celery exchange=celery(direct) key=celery
[tasks]
 . addTask.add

[2019-04-01 21:32:37,650: INFO/MainProcess] Connected to amqp://guest:**@127.0.0.1:5672//
[2019-04-01 21:32:37,745: INFO/MainProcess] mingle: searching for neighbors
[2019-04-01 21:32:39,353: INFO/MainProcess] mingle: all alone
[2019-04-01 21:32:39,479: INFO/SpawnPoolWorker-2] child process 10712 calling self.run()
[2019-04-01 21:32:39,512: INFO/SpawnPoolWorker-3] child process 10696 calling self.run()
[2019-04-01 21:32:39,536: INFO/MainProcess] celery@pc-giancarlo ready.
[2019-04-01 21:32:39,551: INFO/SpawnPoolWorker-1] child process 6084 calling self.run()
[2019-04-01 21:32:39,615: INFO/SpawnPoolWorker-4] child process 2080 calling self.run()
```

然后，使用 Python 启动第二个脚本：

```py
C:\>python addTask_main.py
```

最后，在第一个命令提示符中，结果应该如下所示：

```py
[2019-04-01 21:33:00,451: INFO/MainProcess] Received task: addTask.add[6fc350a9-e925-486c-bc41-c239ebd96041]
[2019-04-01 21:33:00,452: INFO/SpawnPoolWorker-2] Task addTask.add[6fc350a9-e925-486c-bc41-c239ebd96041] succeeded in 0.0s: 10
```

正如您所看到的，结果是 `10`。让我们专注于第一个脚本 `addTask.py`：在代码的前两行中，我们创建了一个使用 RabbitMQ 服务代理的 `Celery` 应用实例：

```py
from celery import Celery
app = Celery('addTask', broker='amqp://guest@localhost//')
```

`Celery` 函数的第一个参数是当前模块的名称（`addTask.py`），第二个是代理键盘参数；这表示用于连接代理（RabbitMQ）的 URL。

现在，让我们介绍要完成的任务。

每个任务必须使用 `@app.task` 注释（即装饰器）添加；装饰器帮助 `Celery` 确定哪些函数可以在任务队列中调度。

在装饰器之后，我们创建工作者可以执行的任务：这将是一个执行两个数字之和的简单函数：

```py
@app.task
def add(x, y):
 return x + y
```

在第二个脚本 `addTask_main.py` 中，我们使用 `delay()` 方法调用我们的任务：

```py
if __name__ == '__main__':
 result = addTask.add.delay(5,5)
```

让我们记住，这种方法是 `apply_async()` 方法的快捷方式，它可以更好地控制任务的执行。

# 还有更多...

Celery 的使用非常简单。可以通过以下命令执行：

```py
Usage: celery <command> [options]
```

这里，选项如下：

```py
positional arguments:
 args

optional arguments:
 -h, --help             show this help message and exit
 --version              show program's version number and exit

Global Options:
 -A APP, --app APP
 -b BROKER, --broker BROKER
 --result-backend RESULT_BACKEND
 --loader LOADER
 --config CONFIG
 --workdir WORKDIR
 --no-color, -C
 --quiet, -q
```

主要命令如下：

```py
+ Main:
| celery worker
| celery events
| celery beat
| celery shell
| celery multi
| celery amqp

+ Remote Control:
| celery status

| celery inspect --help
| celery inspect active
| celery inspect active_queues
| celery inspect clock
| celery inspect conf [include_defaults=False]
| celery inspect memdump [n_samples=10]
| celery inspect memsample
| celery inspect objgraph [object_type=Request] [num=200 [max_depth=10]]
| celery inspect ping
| celery inspect query_task [id1 [id2 [... [idN]]]]
| celery inspect registered [attr1 [attr2 [... [attrN]]]]
| celery inspect report
| celery inspect reserved
| celery inspect revoked
| celery inspect scheduled
| celery inspect stats

| celery control --help
| celery control add_consumer <queue> [exchange [type [routing_key]]]
| celery control autoscale [max [min]]
| celery control cancel_consumer <queue>
| celery control disable_events
| celery control election
| celery control enable_events
| celery control heartbeat
| celery control pool_grow [N=1]
| celery control pool_restart
| celery control pool_shrink [N=1]
| celery control rate_limit <task_name> <rate_limit (e.g., 5/s | 5/m | 
5/h)>
| celery control revoke [id1 [id2 [... [idN]]]]
| celery control shutdown
| celery control terminate <signal> [id1 [id2 [... [idN]]]]
| celery control time_limit <task_name> <soft_secs> [hard_secs]

+ Utils:
| celery purge
| celery list
| celery call
| celery result
| celery migrate
| celery graph
| celery upgrade

+ Debugging:
| celery report
| celery logtool

+ Extensions:
| celery flower
-------------------------------------------------------------
```

Celery 协议可以通过使用 Webhooks（[`developer.github.com/webhooks/`](https://developer.github.com/webhooks/)）在任何语言中实现。

# 另请参阅

+   有关 Celery 的更多信息，请访问[`www.celeryproject.org/`](http://www.celeryproject.org/)。

+   推荐的消息代理（[`en.wikipedia.org/wiki/Message_broker`](https://en.wikipedia.org/wiki/Message_broker)）是 RabbitMQ（[`en.wikipedia.org/wiki/RabbitMQ`](https://en.wikipedia.org/wiki/RabbitMQ)）或 Redis（[`en.wikipedia.org/wiki/Redis`](https://en.wikipedia.org/wiki/Redis)）。此外，还有 MongoDB（[`en.wikipedia.org/wiki/MongoDB`](https://en.wikipedia.org/wiki/MongoDB)）、Beanstalk、Amazon SQS（[`en.wikipedia.org/wiki/Amazon_Simple_Queue_Service`](https://en.wikipedia.org/wiki/Amazon_Simple_Queue_Service)）、CouchDB（[`en.wikipedia.org/wiki/Apache_CouchDB`](https://en.wikipedia.org/wiki/Apache_CouchDB)）和 IronMQ（[`www.iron.io/mq`](https://www.iron.io/mq)）。

# 使用 Pyro4 的 RMI

**Pyro**是**Python Remote Objects**的缩写。它的工作原理与 Java 的**RMI**（远程方法调用）完全相同，允许调用远程对象的方法（属于不同进程），就像对象是本地的一样（属于调用运行的同一进程）。

在面向对象的系统中使用 RMI 机制，可以在项目中获得统一性和对称性的重要优势，因为这种机制使得可以使用相同的概念工具对分布式进程之间的交互进行建模。

从下图中可以看出，`Pyro4`使对象以客户端/服务器的方式分布；这意味着`Pyro4`系统的主要部分可以从客户端调用者切换到远程对象，后者被调用来执行一个函数：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/1782750b-b3f5-4ac1-8274-f01d46cff0ec.png)

RMI

需要注意的是，在远程调用过程中，始终存在两个不同的部分：一个客户端和一个接受并执行客户端调用的服务器。

# 准备工作

管理这种分布式方式的整个方法由`Pyro4`提供。要安装最新版本的`Pyro4`，请使用`pip`安装程序（这里使用 Windows 安装），并添加以下命令：

```py
C:\>pip install Pyro4
```

我们将使用`pyro_server.py`和`pyro_client.py`代码来完成这个示例。

# 如何做...

在这个例子中，我们将看到如何使用`Pyro4`中间件构建和使用简单的客户端-服务器通信。客户端的代码是`pyro_server.py`：

1.  导入`Pyro4`库：

```py
import Pyro4
```

1.  定义包含`welcomeMessage()`方法的`Server`类：

```py
class Server(object):
 @Pyro4.expose
 def welcomeMessage(self, name):
 return ("Hi welcome " + str (name))
```

请注意，装饰器`@Pyro4.expose`表示前面的方法将是远程可访问的。

1.  `startServer`函数包含了启动服务器所使用的所有指令：

```py
def startServer():
```

1.  接下来，构建`Server`类的`server`实例：

```py
server = Server()
```

1.  然后，定义`Pyro4`守护程序：

```py
daemon = Pyro4.Daemon()
```

1.  要执行此脚本，我们必须运行一个`Pyro4`语句来定位名字服务器：

```py
ns = Pyro4.locateNS()
```

1.  将对象服务器注册为*Pyro 对象*；它只会在 Pyro 守护程序内部知道：

```py
uri = daemon.register(server)
```

1.  现在，我们可以在名字服务器中注册对象服务器的名称：

```py
ns.register("server", uri)
```

1.  该函数以调用守护进程的`requestLoop`方法结束。这启动了服务器的事件循环，并等待调用：

```py
print("Ready. Object uri =", uri)
daemon.requestLoop()
```

1.  最后，通过`main`程序调用`startServer`：

```py
if __name__ == "__main__":
 startServer()
```

以下是客户端的代码（`pyro_client.py`）：

1.  导入`Pyro4`库：

```py
import Pyro4
```

1.  `Pyro4` API 使开发人员能够以透明的方式分发对象。在这个例子中，客户端脚本发送请求到服务器程序，以执行`welcomeMessage()`方法：

```py
uri = input("What is the Pyro uri of the greeting object? ").strip()
name = input("What is your name? ").strip()
```

1.  然后，创建远程调用：

```py
server = Pyro4.Proxy("PYRONAME:server")
```

1.  最后，客户端调用服务器，打印一条消息：

```py
print(server.welcomeMessage(name))
```

# 它是如何工作的...

上述示例由两个主要函数组成：`pyro_server.py`和`pyro_client.py`。

在`pyro_server.py`中，`Server`类对象提供`welcomeMessage()`方法，返回与客户端会话中插入的名称相等的字符串：

```py
class Server(object):
 @Pyro4.expose
 def welcomeMessage(self, name):
 return ("Hi welcome " + str (name))
```

`Pyro4`使用守护对象将传入调用分派给适当的对象。服务器必须创建一个管理其所有实例的守护进程。每个服务器都有一个守护进程，它知道服务器提供的所有 Pyro 对象：

```py
 daemon = Pyro4.Daemon()
```

至于`pyro_client.py`函数，首先执行远程调用并创建一个`Proxy`对象。特别是，`Pyro4`客户端使用代理对象将方法调用转发到远程对象，然后将结果传递回调用代码：

```py
server = Pyro4.Proxy("PYRONAME:server")
```

为了执行客户端-服务器连接，我们需要运行一个`Pyro4`名称服务器。在命令提示符中，输入以下内容：

```py
C:\>python -m Pyro4.naming
```

之后，您将看到以下消息：

```py
Not starting broadcast server for localhost.
NS running on localhost:9090 (127.0.0.1)
Warning: HMAC key not set. Anyone can connect to this server!
URI = PYRO:Pyro.NameServer@localhost:9090
```

前面的消息意味着名称服务器正在您的网络中运行。最后，我们可以在两个单独的 Windows 控制台中启动服务器和客户端脚本：

1.  要运行`pyro_server.py`，只需输入以下内容：

```py
C:\>python pyro_server.py
```

1.  之后，您将看到类似于这样的内容：

```py
Ready. Object uri = PYRO:obj_76046e1c9d734ad5b1b4f6a61ee77425@localhost:63269
```

1.  然后，输入以下内容运行客户端：

```py
C:\>python pyro_client.py
```

1.  将打印出以下消息：

```py
What is your name? 
```

1.  插入一个名称（例如，`Ruvika`）：

```py
What is your name? Ruvika
```

1.  将显示以下欢迎消息：

```py
Hi welcome Ruvika
```

# 还有更多...

`Pyro4`的功能之一是创建对象拓扑。例如，假设我们想要构建一个遵循链式拓扑结构的分布式架构，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/7f93a4ab-70f7-4ecb-8a0b-f5633c11bad1.png)

使用 Pyro4 链接对象

客户端向**服务器 1**发出请求，然后将请求转发到**服务器 2**，然后调用**服务器 3**。当**服务器 3**调用**服务器 1**时，链式调用结束。

# 实现链式拓扑

使用`Pyro4`实现链式拓扑，我们需要实现一个`chain`对象和`client`和`server`对象。`Chain`类允许通过处理输入消息并重建请求应该发送到的服务器地址来将调用重定向到下一个服务器。

还要注意，在这种情况下，`@Pyro4.expose`装饰器允许公开类（`chainTopology.py`）的所有方法：

```py
import Pyro4

@Pyro4.expose
class Chain(object):
 def __init__(self, name, next_server):
 self.name = name
 self.next_serverName = next_server
 self.next_server = None

 def process(self, message):
 if self.next_server is None:
 self.next_server = Pyro4.core.Proxy("PYRONAME:example.\
 chainTopology." + self.next_serverName)
```

如果链路关闭（最后一次调用是从`server_chain_3.py`到`server_chain_1.py`），则会打印出关闭消息：

```py
 if self.name in message:
 print("Back at %s;the chain is closed!" % self.name)
 return ["complete at " + self.name]
```

如果链中有下一个元素，则会打印出转发消息：

```py
 else:
 print("%s forwarding the message to the object %s" %\ 
 (self.name, self.next_serverName))
 message.append(self.name)
 result = self.next_server.process(message)
 result.insert(0, "passed on from " + self.name)
 return result
```

接下来是客户端的源代码（`client_chain.py`）：

```py
import Pyro4

obj = Pyro4.core.Proxy("PYRONAME:example.chainTopology.1")
print("Result=%s" % obj.process(["hello"]))
```

接下来是链中第一个服务器的源代码（即`server_1`），它是从客户端（`server_chain_1.py`）调用的。在这里，导入了相关的库。请注意，之前描述的`chainTopology.py`文件的导入：

```py
import Pyro4
import chainTopology
```

还要注意，服务器的源代码只有当前链和下一个链服务器的定义不同：

```py
current_server= "1"
next_server = "2"
```

其余代码行定义了与链中下一个元素的通信：

```py
servername = "example.chainTopology." + current_server
daemon = Pyro4.core.Daemon()
obj = chainTopology.Chain(current_server, next_server)
uri = daemon.register(obj)
ns = Pyro4.locateNS()
ns.register(servername, uri)
print("server_%s started " % current_server)
daemon.requestLoop()
```

要执行此示例，首先运行`Pyro4`名称服务器：

```py
C:\>python -m Pyro4.naming
Not starting broadcast server for localhost.
NS running on localhost:9090 (127.0.0.1)
Warning: HMAC key not set. Anyone can connect to this server!
URI = PYRO:Pyro.NameServer@localhost:9090
```

在三个不同的终端中运行三个服务器，分别输入它们（这里使用 Windows 终端）：

第一个服务器（`server_chain_1.py`）在第一个终端中：

```py
C:\>python server_chain_1.py
```

然后是第二个服务器（`server_chain_2.py`）在第二个终端中：

```py
C:\>python server_chain_2.py
```

最后，第三个服务器（`server_chain_3.py`）在第三个终端中：

```py
C:\>python server_chain_3.py
```

然后，从另一个终端运行`client_chain.py`脚本：

```py
C:\>python client_chain.py
```

这是在命令提示符中显示的输出：

```py
Result=['passed on from 1','passed on from 2','passed on from 3','complete at 1']
```

在返回任务完成的三个服务器之间传递转发请求后，将显示前面的消息。

此外，我们可以关注对象服务器在请求转发到链中的下一个对象时的行为（参见开始消息下方的消息）：

1.  **`server_1`**已启动，并将以下消息转发到**`server_2`**：

```py
server_1 started
1 forwarding the message to the object 2
```

1.  `server_2`将以下消息转发到`server_3`：

```py
server_2 started
2 forwarding the message to the object 3
```

1.  `server_3`将以下消息转发给`server_1`：

```py
server_3 started
3 forwarding the message to the object 1
```

1.  最后，消息返回到起始点（也就是`server_1`），链路关闭：

```py
server_1 started
1 forwarding the message to the object 2
Back at 1; the chain is closed!
```

# 另请参阅

`Pyro4`文档可在[`buildmedia.readthedocs.org/media/pdf/pyro4/stable/pyro4.pdf`](https://buildmedia.readthedocs.org/media/pdf/pyro4/stable/pyro4.pdf)上找到。

其中包含了 4.75 版本的描述和一些应用示例。
