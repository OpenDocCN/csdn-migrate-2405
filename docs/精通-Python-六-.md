# 精通 Python（六）

> 原文：[`zh.annas-archive.org/md5/37ba6447e713c9bd5373842650e2e5f3`](https://zh.annas-archive.org/md5/37ba6447e713c9bd5373842650e2e5f3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：多进程-当单个 CPU 核心不够用时

在上一章中，我们讨论了影响性能的因素以及一些提高性能的方法。这一章实际上可以看作是性能提示列表的扩展。在本章中，我们将讨论多进程模块，这是一个使您的代码非常容易在多个 CPU 核心甚至多台机器上运行的模块。这是一个绕过前一章中讨论的**全局解释器锁**（**GIL**）的简单方法。

总之，本章将涵盖：

+   本地多进程

+   远程多进程

+   进程之间的数据共享和同步

# 多线程与多进程

在本书中，我们还没有真正涵盖多线程，但您可能以前看到过多线程代码。多线程和多进程之间的最大区别在于，多线程中的所有内容仍然在单个进程中执行。这实际上将性能限制在单个 CPU 核心。它实际上甚至限制了您的性能，因为代码必须处理 CPython 的 GIL 限制。

### 注意

GIL 是 Python 用于安全内存访问的全局锁。关于性能，它在第十二章中有更详细的讨论，*性能-跟踪和减少内存和 CPU 使用情况*。

为了说明多线程代码并不总是有助于性能，并且实际上可能比单线程代码稍慢，请看这个例子：

```py
import datetime
import threading

def busy_wait(n):
    while n > 0:
        n -= 1

if __name__ == '__main__':
    n = 10000000
    start = datetime.datetime.now()
    for _ in range(4):
        busy_wait(n)
    end = datetime.datetime.now()
    print('The single threaded loops took: %s' % (end - start))

    start = datetime.datetime.now()
    threads = []
    for _ in range(4):
        thread = threading.Thread(target=busy_wait, args=(n,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    end = datetime.datetime.now()
    print('The multithreaded loops took: %s' % (end - start))
```

使用 Python 3.5，它具有新的改进的 GIL 实现（在 Python 3.2 中引入），性能相当可比，但没有改进：

```py
# python3 test_multithreading.py
The single threaded loops took: 0:00:02.623443
The multithreaded loops took: 0:00:02.597900

```

使用仍然具有旧 GIL 的 Python 2.7，单线程变体的性能要好得多：

```py
# python2 test_multithreading.py
The single threaded loops took: 0:00:02.010967
The multithreaded loops took: 0:00:03.924950

```

从这个测试中，我们可以得出结论，Python 2 在某些情况下更快，而 Python 3 在其他情况下更快。你应该从中得出的结论是，没有性能原因特别选择 Python 2 还是 Python 3。只需注意，Python 3 在大多数情况下至少与 Python 2 一样快，如果不是这种情况，很快就会得到解决。

无论如何，对于 CPU 绑定的操作，线程不提供任何性能优势，因为它在单个处理器核心上执行。但是对于 I/O 绑定的操作，`threading`库确实提供了明显的好处，但在这种情况下，我建议尝试`asyncio`。`threading`的最大问题是，如果其中一个线程阻塞，主进程也会阻塞。

`multiprocessing`库提供了一个与`threading`库非常相似的 API，但是利用多个进程而不是多个线程。优点是 GIL 不再是问题，可以利用多个处理器核心甚至多台机器进行处理。

为了说明性能差异，让我们重复使用`multiprocessing`模块而不是`threading`进行测试：

```py
import datetime
import multiprocessing

def busy_wait(n):
    while n > 0:
        n -= 1

if __name__ == '__main__':
    n = 10000000
    start = datetime.datetime.now()

    processes = []
    for _ in range(4):
        process = multiprocessing.Process(
            target=busy_wait, args=(n,))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()

    end = datetime.datetime.now()
    print('The multiprocessed loops took: %s' % (end - start))
```

运行时，我们看到了巨大的改进：

```py
# python3 test_multiprocessing.py
The multiprocessed loops took: 0:00:00.671249

```

请注意，这是在四核处理器上运行的，这就是为什么我选择了四个进程。`multiprocessing`库默认为`multiprocessing.cpu_count()`，它计算可用的 CPU 核心数，但该方法未考虑 CPU 超线程。这意味着在我的情况下它会返回 8，这就是为什么我将其硬编码为 4 的原因。

### 注意

重要的是要注意，因为`multiprocessing`库使用多个进程，代码需要从子进程中导入。结果是`multiprocessing`库无法在 Python 或 IPython shell 中工作。正如我们将在本章后面看到的那样，IPython 有自己的多进程处理方式。

# 超线程与物理 CPU 核心

在大多数情况下，超线程非常有用并提高了性能，但当您真正最大化 CPU 使用率时，通常最好只使用物理处理器数量。为了演示这如何影响性能，我们将再次运行上一节中的测试。这次使用 1、2、4、8 和 16 个进程来演示它如何影响性能。幸运的是，`multiprocessing`库有一个很好的`Pool`类来为我们管理进程：

```py
import sys
import datetime
import multiprocessing

def busy_wait(n):
    while n > 0:
        n -= 1

if __name__ == '__main__':
    n = 10000000
    start = datetime.datetime.now()
    if sys.argv[-1].isdigit():
        processes = int(sys.argv[-1])
    else:
        print('Please specify the number of processes')
        print('Example: %s 4' % ' '.join(sys.argv))
        sys.exit(1)

    with multiprocessing.Pool(processes=processes) as pool:
        # Execute the busy_wait function 8 times with parameter n
        pool.map(busy_wait, [n for _ in range(8)])

    end = datetime.datetime.now()
    print('The multithreaded loops took: %s' % (end - start))
```

池代码使得启动一组工作进程和处理队列变得更加简单。在这种情况下，我们使用了`map`，但还有其他几个选项，如`imap`，`map_async`，`imap_unordered`，`apply`，`apply_async`，`starmap`和`starmap_async`。由于这些方法与同名的`itertools`方法工作方式非常相似，因此不会为所有这些方法提供具体示例。

但现在，测试不同数量的进程：

```py
# python3 test_multiprocessing.py 1
The multithreaded loops took: 0:00:05.297707
# python3 test_multiprocessing.py 2
The multithreaded loops took: 0:00:02.701344
# python3 test_multiprocessing.py 4
The multithreaded loops took: 0:00:01.477845
# python3 test_multiprocessing.py 8
The multithreaded loops took: 0:00:01.579218
# python3 test_multiprocessing.py 16
The multithreaded loops took: 0:00:01.595239

```

您可能没有预料到这些结果，但这正是超线程的问题所在。一旦单个进程实际上使用了 CPU 核心的 100%，进程之间的任务切换实际上会降低性能。由于只有`4`个物理核心，其他`4`个核心必须争夺处理器核心上的任务。这场争斗需要时间，这就是为什么`4`个进程版本比`8`个进程版本稍快的原因。此外，调度效果也可以在使用`1`和`2`个核心的运行中看到。如果我们看单核版本，我们会发现它花了`5.3`秒，这意味着`4`个核心应该在`5.3 / 4 = 1.325`秒内完成，而实际上花了`1.48`秒。`2`核版本也有类似的效果，`2.7 / 2 = 1.35`秒，仍然比`4`核版本快。

如果您真的需要处理 CPU 绑定问题的性能，那么匹配物理 CPU 核心是最佳解决方案。如果您不希望始终最大化所有核心的使用，那么我建议将其保留为默认设置，因为超线程在其他情况下确实具有一些性能优势。

但这一切取决于您的用例，确切的方法是测试您特定情况的唯一方法：

+   磁盘 I/O 绑定？单个进程很可能是您最好的选择。

+   CPU 绑定？物理 CPU 核心数量是您最好的选择。

+   网络 I/O 绑定？从默认值开始，如果需要，进行调整。

+   没有明显的限制，但需要许多并行进程？也许您应该尝试`asyncio`而不是`multiprocessing`。

请注意，创建多个进程在内存和打开文件方面并不是免费的，而您可以拥有几乎无限数量的协程，但对于进程来说并非如此。根据您的操作系统配置，它可能在您甚至达到一百之前就达到最大值，即使您达到这些数字，CPU 调度也将成为瓶颈。

# 创建一个工作进程池

创建一个工作进程的处理池通常是一个困难的任务。您需要注意调度作业，处理队列，处理进程，以及最困难的部分是在进程之间处理同步而不会产生太多开销。

然而，使用`multiprocessing`，这些问题已经得到解决。您只需创建一个具有给定进程数的进程池，并在需要时添加任务即可。以下是`map`操作符的多进程版本的示例，并演示了处理不会使应用程序停滞：

```py
import time
import multiprocessing

def busy_wait(n):
    while n > 0:
        n -= 1

if __name__ == '__main__':
    n = 10000000
    items = [n for _ in range(8)]
    with multiprocessing.Pool() as pool:
        results = []
        start = time.time()
        print('Start processing...')
        for _ in range(5):
            results.append(pool.map_async(busy_wait, items))
        print('Still processing %.3f' % (time.time() - start))
        for result in results:
            result.wait()
            print('Result done %.3f' % (time.time() - start))
        print('Done processing: %.3f' % (time.time() - start))
```

处理本身非常简单。关键是池保持可用，您不需要等待它。只需在需要时添加作业，并在异步结果可用时使用它们：

```py
# python3 test_pool.py
Start processing...
Still processing 0.000
Result done 1.513
Result done 2.984
Result done 4.463
Result done 5.978
Result done 7.388
Done processing: 7.388

```

# 在进程之间共享数据

这确实是多进程、多线程和分布式编程中最困难的部分——要传递哪些数据，要跳过哪些数据。然而，理论上非常简单：尽可能不传输任何数据，不共享任何东西，保持一切本地。本质上是函数式编程范式，这就是为什么函数式编程与多进程非常搭配。不幸的是，在实践中，这并不总是可能的。`multiprocessing`库有几种共享数据的选项：`Pipe`、`Namespace`、`Queue`和其他一些选项。所有这些选项可能会诱使您一直在进程之间共享数据。这确实是可能的，但在许多情况下，性能影响要比分布式计算提供的额外性能更大。所有数据共享选项都需要在所有处理内核之间进行同步，这需要很长时间。特别是在分布式选项中，这些同步可能需要几毫秒，或者如果在全局范围内执行，可能会导致数百毫秒的延迟。

多进程命名空间的行为与常规对象的工作方式相同，只是有一个小差异，即所有操作都对多进程是安全的。有了这么多功能，命名空间仍然非常容易使用：

```py
import multiprocessing
manager = multiprocessing.Manager()
namespace = manager.Namespace()
namespace.spam = 123
namespace.eggs = 456
```

管道也没有那么有趣。它只是一个双向通信端点，允许读和写。在这方面，它只是为您提供了一个读取器和一个写入器，因此您可以组合多个进程/端点。在同步数据时，您必须始终记住的唯一一件事是，锁定需要时间。为了设置适当的锁，所有参与方都需要同意数据已被锁定，这是一个需要时间的过程。这个简单的事实比大多数人预期的要慢得多。

在常规硬盘设置上，由于锁定和磁盘延迟，数据库服务器无法处理同一行上超过大约 10 个事务每秒。使用延迟文件同步、固态硬盘和带电池备份的 RAID 缓存，该性能可以增加到，也许，每秒处理同一行上的 100 个事务。这些都是简单的硬件限制，因为您有多个进程尝试写入单个目标，您需要在进程之间同步操作，这需要很长时间。

### 注意

“数据库服务器”统计数据是所有提供安全和一致数据存储的数据库服务器的常见统计数据。

即使使用最快的硬件，同步也可能锁定所有进程并导致巨大的减速，因此如果可能的话，尽量避免在多个进程之间共享数据。简而言之，如果所有进程都从/向同一对象读取和写入，通常使用单个进程会更快。

# 远程进程

到目前为止，我们只在多个本地处理器上执行了我们的脚本，但实际上我们可以进一步扩展。使用`multiprocessing`库，实际上非常容易在远程服务器上执行作业，但文档目前仍然有点晦涩。实际上有几种以分布式方式执行进程的方法，但最明显的方法并不是最容易的方法。`multiprocessing.connection`模块具有`Client`和`Listener`类，可以以简单的方式促进客户端和服务器之间的安全通信。然而，通信并不同于进程管理和队列管理，这些功能需要额外的努力。在这方面，多进程库仍然有点简陋，但鉴于一些不同的进程，这是完全可能的。

## 使用多进程进行分布式处理

首先，我们将从一个包含一些常量的模块开始，这些常量应该在所有客户端和服务器之间共享，因此所有人都可以使用服务器的秘密密码和主机名。除此之外，我们将添加我们的质数计算函数，稍后我们将使用它们。以下模块中的导入将期望将此文件存储为`constants.py`，但是只要您修改导入和引用，可以随意将其命名为任何您喜欢的名称：

```py
host = 'localhost'
port = 12345
password = b'some secret password'

def primes(n):
    for i, prime in enumerate(prime_generator()):
        if i == n:
            return prime

def prime_generator():
    n = 2
    primes = set()
    while True:
        for p in primes:
            if n % p == 0:
                break
        else:
            primes.add(n)
            yield n
        n += 1
```

现在是时候创建实际的服务器，将函数和作业队列链接起来了。

```py
import constants
import multiprocessing
from multiprocessing import managers

queue = multiprocessing.Queue()
manager = managers.BaseManager(address=('', constants.port),
                               authkey=constants.password)

manager.register('queue', callable=lambda: queue)
manager.register('primes', callable=constants.primes)

server = manager.get_server()
server.serve_forever()
```

创建服务器后，我们需要一个发送作业的脚本，实际上将是一个常规客户端。这真的很简单，一个常规客户端也可以作为处理器，但为了保持事情合理，我们将它们用作单独的脚本。以下脚本将将 0 添加到 999 以进行处理：

```py
from multiprocessing import managers
import functions

manager = managers.BaseManager(
    address=(functions.host, functions.port),
    authkey=functions.password)
manager.register('queue')
manager.connect()

queue = manager.queue()
for i in range(1000):
    queue.put(i)
```

最后，我们需要创建一个客户端来实际处理队列：

```py
from multiprocessing import managers
import functions

manager = managers.BaseManager(
    address=(functions.host, functions.port),
    authkey=functions.password)
manager.register('queue')
manager.register('primes')
manager.connect()

queue = manager.queue()
while not queue.empty():
    print(manager.primes(queue.get()))
```

从前面的代码中，您可以看到我们如何传递函数；管理器允许注册可以从客户端调用的函数和类。通过这样，我们可以传递一个队列，从多进程类中，这对多线程和多进程都是安全的。现在我们需要启动进程本身。首先是保持运行的服务器：

```py
# python3 multiprocessing_server.py

```

之后，运行生产者生成质数生成请求：

```py
# python3 multiprocessing_producer.py

```

现在我们可以在多台机器上运行多个客户端，以获得前 1000 个质数。由于这些客户端现在打印出前 1000 个质数，输出有点太长，无法在这里显示，但您可以简单地在多台机器上并行运行此操作以生成您的输出：

```py
# python3 multiprocessing_client.py

```

您可以使用队列或管道将输出发送到不同的进程，而不是打印。但是，正如您所看到的，要并行处理事物仍然需要一些工作，并且需要一些代码同步才能正常工作。还有一些可用的替代方案，例如**ØMQ**、**Celery**和**IPyparallel**。哪种是最好和最合适的取决于您的用例。如果您只是想在多个 CPU 上处理任务，那么多进程和 IPyparallel 可能是您最好的选择。如果您正在寻找后台处理和/或轻松地将任务卸载到多台机器上，那么ØMQ 和 Celery 是更好的选择。

## 使用 IPyparallel 进行分布式处理

IPyparallel 模块（以前是 IPython Parallel）是一个模块，使得在多台计算机上同时处理代码变得非常容易。该库支持的功能比您可能需要的要多，但了解基本用法非常重要，以防您需要进行可以从多台计算机中受益的大量计算。首先，让我们从安装最新的 IPyparallel 包和所有 IPython 组件开始：

```py
pip install -U ipython[all] ipyparallel

```

### 注意

特别是在 Windows 上，使用 Anaconda 安装 IPython 可能更容易，因为它包含了许多科学、数学、工程和数据分析软件包的二进制文件。为了获得一致的安装，Anaconda 安装程序也适用于 OS X 和 Linux 系统。

其次，我们需要一个集群配置。从技术上讲，这是可选的，但由于我们将创建一个分布式 IPython 集群，使用特定配置来配置一切会更方便：

```py
# ipython profile create --parallel --profile=mastering_python
[ProfileCreate] Generating default config file: '~/.ipython/profile_mastering_python/ipython_config.py'
[ProfileCreate] Generating default config file: '~/.ipython/profile_mastering_python/ipython_kernel_config.py'
[ProfileCreate] Generating default config file: '~/.ipython/profile_mastering_python/ipcontroller_config.py'
[ProfileCreate] Generating default config file: '~/.ipython/profile_mastering_python/ipengine_config.py'
[ProfileCreate] Generating default config file: '~/.ipython/profile_mastering_python/ipcluster_config.py'

```

这些配置文件包含大量的选项，因此我建议搜索特定部分而不是逐个浏览它们。快速列出给我总共约 2500 行配置，分布在这五个文件中。文件名已经提供了关于配置文件目的的提示，但由于它们仍然有点令人困惑，我们将更详细地解释它们。

### ipython_config.py

这是通用的 IPython 配置文件；您可以在这里自定义关于您的 IPython shell 的几乎所有内容。它定义了您的 shell 应该如何显示，哪些模块应该默认加载，是否加载 GUI 等等。对于本章的目的并不是很重要，但如果您要经常使用 IPython，那么它绝对值得一看。您可以在这里配置的一件事是自动加载扩展，比如在上一章中讨论的`line_profiler`和`memory_profiler`。

```py
c.InteractiveShellApp.extensions = [
    'line_profiler',
    'memory_profiler',
]
```

### ipython_kernel_config.py

这个文件配置了您的 IPython 内核，并允许您覆盖/扩展`ipython_config.py`。要理解它的目的，重要的是要知道什么是 IPython 内核。在这个上下文中，内核是运行和审查代码的程序。默认情况下，这是`IPyKernel`，它是一个常规的 Python 解释器，但也有其他选项，如`IRuby`或`IJavascript`分别运行 Ruby 或 JavaScript。

其中一个更有用的选项是配置内核的监听端口和 IP 地址的可能性。默认情况下，端口都设置为使用随机数，但重要的是要注意，如果其他人在您运行内核时访问同一台机器，他们将能够连接到您的 IPython 内核，这在共享机器上可能是危险的。

### ipcontroller_config.py

`ipcontroller`是您的 IPython 集群的主进程。它控制引擎和任务的分发，并负责诸如日志记录之类的任务。

在性能方面最重要的参数是`TaskScheduler`设置。默认情况下，`c.TaskScheduler.scheme_name`设置为使用 Python LRU 调度程序，但根据您的工作负载，其他调度程序如`leastload`和`weighted`可能更好。如果您必须在如此大的集群上处理如此多的任务，以至于调度程序成为瓶颈，那么还有`plainrandom`调度程序，如果您的所有计算机具有类似的规格并且任务具有类似的持续时间，它会出奇地有效。

为了我们的测试目的，我们将控制器的 IP 设置为*，这意味着将接受**所有**IP 地址，并且将接受每个网络连接。如果您处于不安全的环境/网络，并且/或者没有任何允许您有选择地启用某些 IP 地址的防火墙，那么**不建议**使用这种方法！在这种情况下，我建议通过更安全的选项启动，例如`SSHEngineSetLauncher`或`WindowsHPCEngineSetLauncher`。

但是，假设您的网络确实是安全的，将工厂 IP 设置为所有本地地址：

```py
c.HubFactory.client_ip = '*'
c.RegistrationFactory.ip = '*'
```

现在启动控制器：

```py
# ipcontroller --profile=mastering_python
[IPControllerApp] Hub listening on tcp://*:58412 for registration.
[IPControllerApp] Hub listening on tcp://127.0.0.1:58412 for registration.
[IPControllerApp] Hub using DB backend: 'NoDB'
[IPControllerApp] hub::created hub
[IPControllerApp] writing connection info to ~/.ipython/profile_mastering_python/security/ipcontroller-client.json
[IPControllerApp] writing connection info to ~/.ipython/profile_mastering_python/security/ipcontroller-engine.json
[IPControllerApp] task::using Python leastload Task scheduler
[IPControllerApp] Heartmonitor started
[IPControllerApp] Creating pid file: .ipython/profile_mastering_python/pid/ipcontroller.pid
[scheduler] Scheduler started [leastload]
[IPControllerApp] client::client b'\x00\x80\x00A\xa7' requested 'connection_request'
[IPControllerApp] client::client [b'\x00\x80\x00A\xa7'] connected

```

注意已写入配置文件目录的安全目录中的文件。它包含了`ipengine`用于找到`ipcontroller`的身份验证信息。它包含端口、加密密钥和 IP 地址。

### ipengine_config.py

`ipengine`是实际的工作进程。这些进程运行实际的计算，因此为了加快处理速度，您需要在尽可能多的计算机上运行这些进程。您可能不需要更改此文件，但如果您想配置集中式日志记录或需要更改工作目录，则可能会有用。通常情况下，您不希望手动启动`ipengine`进程，因为您很可能希望在每台计算机上启动多个进程。这就是我们下一个命令`ipcluster`的用处。

### ipcluster_config.py

`ipcluster`命令实际上只是一个简单的快捷方式，可以同时启动`ipcontroller`和`ipengine`的组合。对于简单的本地处理集群，我建议使用这个，但是在启动分布式集群时，单独使用`ipcontroller`和`ipengine`可以很有用。在大多数情况下，该命令提供了足够的选项，因此您可能不需要单独的命令。

最重要的配置选项是`c.IPClusterEngines.engine_launcher_class`，因为它控制了引擎和控制器之间的通信方法。除此之外，它也是安全通信的最重要组件。默认情况下，它设置为`ipyparallel.apps.launcher.LocalControllerLauncher`，适用于本地进程，但如果您想要使用 SSH 与客户端通信，也可以选择`ipyparallel.apps.launcher.SSHEngineSetLauncher`。或者对于 Windows HPC，可以选择`ipyparallel.apps.launcher.WindowsHPCEngineSetLauncher`。

在所有机器上创建集群之前，我们需要传输配置文件。您可以选择传输所有文件，也可以选择仅传输 IPython 配置文件的`security`目录中的文件。

现在是时候启动集群了，因为我们已经单独启动了`ipcontroller`，所以我们只需要启动引擎。在本地机器上，我们只需要启动它，但其他机器还没有配置。一种选择是复制整个 IPython 配置文件目录，但实际上只需要复制`security/ipcontroller-engine.json`文件。在使用配置文件创建命令创建配置文件之后。因此，除非您打算复制整个 IPython 配置文件目录，否则需要再次执行配置文件创建命令：

```py
# ipython profile create --parallel --profile=mastering_python

```

之后，只需复制`ipcontroller-engine.json`文件，就完成了。现在我们可以启动实际的引擎了：

```py
# ipcluster engines --profile=mastering_python -n 4
[IPClusterEngines] IPython cluster: started
[IPClusterEngines] Starting engines with [daemon=False]
[IPClusterEngines] Starting 4 Engines with LocalEngineSetLauncher

```

请注意，这里的`4`是为四核处理器选择的，但任何数字都可以。默认情况下将使用逻辑处理器核心的数量，但根据工作负载，最好匹配物理处理器核心的数量。

现在我们可以从 IPython shell 运行一些并行代码。为了演示性能差异，我们将使用从 0 加到 10,000,000 的所有数字的简单总和。虽然不是非常繁重的任务，但连续执行 10 次时，常规的 Python 解释器需要一段时间：

```py
In [1]: %timeit for _ in range(10): sum(range(10000000))
1 loops, best of 3: 2.27 s per loop
```

然而，这一次，为了说明差异，我们将运行 100 次以演示分布式集群有多快。请注意，这只是一个三台机器集群，但速度仍然相当快：

```py
In [1]: import ipyparallel

In [2]: client = ipyparallel.Client(profile='mastering_python')

In [3]: view = client.load_balanced_view()

In [4]: %timeit view.map(lambda _: sum(range(10000000)), range(100)).wait()
1 loop, best of 3: 909 ms per loop
```

然而，更有趣的是在 IPyParallel 中定义并行函数。只需一个简单的装饰器，一个函数就被标记为并行：

```py
In [1]: import ipyparallel

In [2]: client = ipyparallel.Client(profile='mastering_python')

In [3]: view = client.load_balanced_view()

In [4]: @view.parallel()
   ...: def loop():
   ...:     return sum(range(10000000))
   ...:

In [5]: loop.map(range(10))
Out[5]: <AsyncMapResult: loop>
```

IPyParallel 库提供了许多其他有用的功能，但这超出了本书的范围。尽管 IPyParallel 是 Jupyter/IPython 的独立实体，但它与之整合良好，这使得它们很容易结合起来。

使用 IPyParallel 最方便的方法之一是通过 Jupyter/IPython 笔记本。为了演示，我们首先必须确保在 Jupyter Notebook 中启用并行处理，因为 IPython 笔记本默认情况下是单线程执行的：

```py
ipcluster nbextension enable

```

之后，我们可以启动`notebook`，看看它是怎么回事：

```py
# jupyter notebook
Unrecognized JSON config file version, assuming version 1
Loading IPython parallel extension
Serving notebooks from local directory: ./
0 active kernels
The Jupyter Notebook is running at: http://localhost:8888/
Use Control-C to stop this server and shut down all kernels (twice to skip confirmation).

```

使用 Jupyter Notebook，您可以在 Web 浏览器中创建脚本，稍后可以轻松与他人共享。这对于共享脚本和调试代码非常有用，特别是因为 Web 页面（与命令行环境相反）可以轻松显示图像。这对于绘制数据有很大帮助。这是我们笔记本的屏幕截图：

![ipcluster_config.py](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-py/img/4711_13_01.jpg)

# 总结

本章向我们展示了多进程的工作原理，我们如何可以汇集大量的工作，并且我们应该如何在多个进程之间共享数据。但更有趣的是，它还展示了我们如何可以在多台机器之间分发处理，这在加速繁重的计算方面非常有帮助。

您可以从本章中学到的最重要的一课是，您应该尽量避免在多个进程或服务器之间共享数据和同步，因为这样做会很慢，从而大大减慢应用程序的速度。在可能的情况下，保持计算和数据本地。

在下一章中，我们将学习如何在 C/C++中创建扩展，以提高性能并允许对内存和其他硬件资源进行低级访问。虽然 Python 通常会保护您免受愚蠢的错误，但 C 和 C++肯定不会。

|   | “C 使得自己踩到脚趾头很容易；C++让这变得更难，但一旦你踩到了，它会把整条腿都炸掉。” |   |
| --- | --- | --- |
|   | --*Bjarne Stroustrup（C++的创造者）* |


# 第十四章：C/C++扩展，系统调用和 C/C++库

现在我们对性能和多处理有了更多了解，我们将解释另一个至少与性能有关的主题——使用 C 和/或 C++扩展。

有多个原因需要考虑 C/C++扩展。拥有现有库可用是一个重要原因，但实际上，最重要的原因是性能。在第十二章中，*性能-跟踪和减少内存和 CPU 使用情况*，我们看到`cProfile`模块大约比`profile`模块快 10 倍，这表明至少一些 C 扩展比它们的纯 Python 等效快。然而，本章不会太注重性能。这里的目标是与非 Python 库的交互。任何性能改进只会是一个完全无意的副作用。

在本章中，我们将讨论以下选项：

+   用于处理 Python 中的外部（C/C++）函数和数据的 Ctypes

+   **CFFI**（**C Foreign Function Interface**的缩写），类似于`ctypes`但是有稍微不同的方法

+   使用本机 C/C++扩展 Python

# 介绍

在开始本章之前，重要的是要注意，本章将需要一个与你的 Python 解释器良好配合的工作编译器。不幸的是，这些因平台而异。虽然对于大多数 Linux 发行版来说通常很容易，但在 Windows 上可能是一个很大的挑战。对于 OS X 来说，通常很容易，只要你安装了正确的工具。

通用的构建说明始终可以在 Python 手册中找到：

[`docs.python.org/3.5/extending/building.html`](https://docs.python.org/3.5/extending/building.html)

## 你需要 C/C++模块吗？

在几乎所有情况下，我倾向于说你不需要 C/C++模块。如果你真的需要最佳性能，那么几乎总是有高度优化的库可用来满足你的目的。有一些情况下，需要本机 C/C++（或者只是“不是 Python”）。如果你需要直接与具有特定时间的硬件通信，那么 Python 可能对你来说行不通。然而，一般来说，这种通信应该留给负责特定时间的驱动程序。无论如何，即使你永远不会自己编写这些模块之一，当你调试项目时，你可能仍然需要知道它们的工作原理。

## Windows

对于 Windows，一般建议使用 Visual Studio。具体的版本取决于你的 Python 版本：

+   Python 3.2 及更低版本：Microsoft Visual Studio 2008

+   Python 3.3 和 3.4：Microsoft Visual Studio 2010

+   Python 3.5 和 3.6：Microsoft Visual Studio 2015

安装 Visual Studio 和编译 Python 模块的具体细节有点超出了本书的范围。幸运的是，Python 文档中有一些文档可以帮助你入门：

[`docs.python.org/3.5/extending/windows.html`](https://docs.python.org/3.5/extending/windows.html)

## OS X

对于 Mac，这个过程大多是直接的，但是有一些特定于 OS X 的技巧。

首先，通过 Mac App Store 安装 Xcode。一旦你这样做了，你应该能够运行以下命令：

```py
xcode-select --install

```

接下来是有趣的部分。因为 OS X 带有捆绑的 Python 版本（通常已过时），我建议通过 Homebrew 安装一个新的 Python 版本。安装 Homebrew 的最新说明可以在 Homebrew 主页上找到（[`brew.sh/`](http://brew.sh/)），但安装 Homebrew 的要点是这个命令：

```py
# /usr/bin/ruby -e "$(curl -fsSL \
 **https://raw.githubusercontent.com/Homebrew/install/master/install)"

```

之后，确保使用`doctor`命令检查一切是否设置正确：

```py
# brew doctor

```

当所有这些都完成时，只需通过 Homebrew 安装 Python，并确保在执行脚本时使用该 Python 版本：

```py
# brew install python3
# python3 –version
Python 3.5.1
which python3
/usr/local/bin/python3

```

还要确保 Python 进程在`/usr/local/bin`中，也就是自制版本。常规的 OS X 版本将在`/usr/bin/`中。

## Linux/Unix

Linux/Unix 系统的安装在很大程度上取决于发行版，但通常很简单。

对于使用`yum`作为软件包管理器的 Fedora、Red Hat、Centos 和其他系统，请使用以下命令：

```py
# sudo yum install yum-utils
# sudo yum-builddep python3

```

对于使用`apt`作为软件包管理器的 Debian、Ubuntu 和其他系统，请使用以下命令：

```py
# sudo apt-get build-dep python3.5

```

请注意，Python 3.5 并不是随处都可用的，所以您可能需要使用 Python 3.4。

### 提示

对于大多数系统，要获取安装帮助，可以通过类似`<操作系统> python.h`的网页搜索来解决问题。

# 使用 ctypes 调用 C/C++

`ctypes`库使得从 C 库调用函数变得非常容易，但您需要小心内存访问和数据类型。Python 在内存分配和类型转换方面通常非常宽容；C 则绝对不是那么宽容。

## 特定于平台的库

尽管所有平台都将在某个地方提供标准的 C 库，但其位置和调用方法因平台而异。为了拥有一个对大多数人来说易于访问的简单环境，我将假设使用 Ubuntu（虚拟）机器。如果您没有本机 Ubuntu 可用，您可以在 Windows、Linux 和 OS X 上通过 VirtualBox 轻松运行它。

由于您通常希望在本机系统上运行示例，我们将首先展示从标准 C 库中加载`printf`的基础知识。

### Windows

从 Python 调用 C 函数的一个问题是默认库是特定于平台的。虽然以下示例在 Windows 系统上可以正常运行，但在其他平台上则无法运行：

```py
>>> import ctypes
>>> ctypes.cdll
<ctypes.LibraryLoader object at 0x...>
>>> libc = ctypes.cdll.msvcrt
>>> libc
<CDLL 'msvcrt', handle ... at ...>
>>> libc.printf
<_FuncPtr object at 0x...>

```

由于这些限制，不是所有示例都可以在每个 Python 版本和发行版上工作，而不需要手动编译。从外部库调用函数的基本前提是简单地将它们的名称作为`ctypes`导入的属性来访问。然而，有一个区别；在 Windows 上，模块通常会自动加载，而在 Linux/Unix 系统上，您需要手动加载它们。

### Linux/Unix

从 Linux/Unix 调用标准系统库确实需要手动加载，但幸运的是这并不太复杂。从标准 C 库中获取`printf`函数非常简单：

```py
>>> import ctypes
>>> ctypes.cdll
<ctypes.LibraryLoader object at 0x...>
>>> libc = ctypes.cdll.LoadLibrary('libc.so.6')
>>> libc
<CDLL 'libc.so.6', handle ... at ...>
>>> libc.printf
<_FuncPtr object at 0x...>

```

### OS X

对于 OS X，也需要显式加载，但除此之外，它与常规 Linux/Unix 系统上的所有工作方式非常相似：

```py
>>> import ctypes
>>> libc = ctypes.cdll.LoadLibrary('libc.dylib')
>>> libc
<CDLL 'libc.dylib', handle ... at 0x...>
>>> libc.printf
<_FuncPtr object at 0x...>

```

### 使其变得简单

除了加载库的方式不同之外，还有更多的差异，但这些示例至少给出了标准的 C 库。它允许您直接从 C 实现中调用诸如`printf`之类的函数。如果由于某种原因，您在加载正确的库时遇到问题，总是可以使用`ctypes.util.find_library`函数。我始终建议显式声明而不是隐式声明，但使用这个函数可以使事情变得更容易。让我们在 OS X 系统上进行一次运行：

```py
>>> from ctypes import util
>>> from ctypes import cdll
>>> libc = cdll.LoadLibrary(util.find_library('libc'))
>>> libc
<CDLL '/usr/lib/libc.dylib', handle ... at 0x...>

```

## 调用函数和本机类型

通过`ctypes`调用函数几乎和调用本机 Python 函数一样简单。显著的区别在于参数和返回语句。这些应该转换为本机 C 变量：

### 注意

这些示例将假定您在前几段中的一个示例中已经将`libc`纳入了范围。

```py
>>> spam = ctypes.create_string_buffer(b'spam')
>>> ctypes.sizeof(spam)
5
>>> spam.raw
b'spam\x00'
>>> spam.value
b'spam'
>>> libc.printf(spam)
4
spam>>>

```

正如您所看到的，要调用`printf`函数，您*必须*——我无法再次强调这一点——将您的值从 Python 显式转换为 C。虽然最初可能看起来可以工作，但实际上并不行：

```py
>>> libc.printf(123)
segmentation fault (core dumped)  python3

```

### 注意

请记住使用第十一章中的`faulthandler`模块，*调试-解决错误*来调试段错误。

从这个例子中需要注意的另一件事是 `ctypes.sizeof(spam)` 返回 `5` 而不是 `4`。这是由 C 字符串所需的尾随空字符引起的。这在 C 字符串的原始属性中是可见的。如果没有它，`printf` 函数就不知道字符串在哪里结束。

要将其他类型（如整数）传递给 `libc` 函数，我们也必须进行一些转换。在某些情况下，这是可选的：

```py
>>> format_string = ctypes.create_string_buffer(b'Number: %d\n')
>>> libc.printf(format_string, 123)
Number: 123
12
>>> x = ctypes.c_int(123)
>>> libc.printf(format_string, x)
Number: 123
12

```

但并非所有情况都是如此，因此强烈建议您在所有情况下明确转换您的值：

```py
>>> format_string = ctypes.create_string_buffer(b'Number: %.3f\n')
>>> libc.printf(format_string, 123.45)
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
ctypes.ArgumentError: argument 2: <class 'TypeError'>: Don't know how to convert parameter 2
>>> x = ctypes.c_double(123.45)
>>> libc.printf(format_string, x)
Number: 123.450
16

```

重要的是要注意，即使这些值可以用作本机 C 类型，它们仍然可以通过 `value` 属性进行更改：

```py
>>> x = ctypes.c_double(123.45)
>>> x.value
123.45
>>> x.value = 456
>>> x
c_double(456.0)

```

然而，如果原始对象是不可变的，情况就不同了，这是一个非常重要的区别。`create_string_buffer` 对象创建一个可变的字符串对象，而 `c_wchar_p`、`c_char_p` 和 `c_void_p` 创建对实际 Python 字符串的引用。由于字符串在 Python 中是不可变的，这些值也是不可变的。你仍然可以更改 `value` 属性，但它只会分配一个新的字符串。实际上，将其中一个传递给会改变内部值的 C 函数会导致问题。

应该毫无问题地转换为 C 的唯一值是整数、字符串和字节，但我个人建议你始终转换所有的值，这样你就可以确定你将得到哪种类型以及如何处理它。

## 复杂的数据结构

我们已经看到，我们不能简单地将 Python 值传递给 C，但如果我们需要更复杂的对象呢？也就是说，不仅仅是直接可转换为 C 的裸值，而是包含多个值的复杂对象。幸运的是，我们可以很容易地使用 `ctypes` 创建（和访问）C 结构：

```py
>>> class Spam(ctypes.Structure):
...     _fields_ = [
...         ('spam', ctypes.c_int),
...         ('eggs', ctypes.c_double),
...     ]
...>>> spam = Spam(123, 456.789)
>>> spam.spam
123
>>> spam.eggs
456.789

```

## 数组

在 Python 中，我们通常使用列表来表示对象的集合。这些非常方便，因为你可以很容易地添加和删除值。在 C 中，默认的集合对象是数组，它只是一个具有固定大小的内存块。

以字节为单位的块的大小是通过将项数乘以类型的大小来决定的。在 `char` 的情况下，这是 `8` 位，所以如果你想存储 `100` 个字符，你将有 `100 * 8 位 = 800 位 = 100 字节`。

这实际上就是一个内存块，C 给你的唯一引用是指向内存块起始地址的指针。由于指针有类型，在这种情况下是 `char*`，C 就知道在尝试访问不同项时需要跳过多少字节。实际上，在尝试访问 `char` 数组中的第 25 项时，你只需要执行 `array_pointer + 25 * sizeof(char)`。这有一个方便的快捷方式：`array_pointer[25]`。

请注意，C 不会存储数组中的项数，因此即使我们的数组只有 100 项，我们也可以执行 `array_pointer[1000]` 并读取其他（随机）内存。

如果你考虑了所有这些，它绝对是可用的，但错误很快就会发生，而且 C 是不可原谅的。没有警告，只有崩溃和奇怪的行为代码。除此之外，让我们看看我们如何使用 `ctypes` 轻松地声明一个数组：

```py
>>> TenNumbers = 10 * ctypes.c_double
>>> numbers = TenNumbers()
>>> numbers[0]
0.0

```

正如你所看到的，由于固定的大小和在使用之前声明类型的要求，它的使用略显笨拙。然而，它确实像你期望的那样运行，并且这些值默认初始化为零。显然，这也可以与先前讨论的结构相结合：

```py
>>> Spams = 5 * Spam
>>> spams = Spams()
>>> spams[0].eggs = 123.456
>>> spams
<__main__.Spam_Array_5 object at 0x...>
>>> spams[0]
<__main__.Spam object at 0x...>
>>> spams[0].eggs
123.456
>>> spams[0].spam
0

```

尽管你不能简单地追加这些数组来调整它们的大小，但它们实际上是可调整大小的，有一些限制。首先，新数组的大小需要大于原始数组。其次，大小需要以字节为单位指定，而不是项数。举个例子，我们有这个例子：

```py
>>> TenNumbers = 10 * ctypes.c_double
>>> numbers = TenNumbers()
>>> ctypes.resize(numbers, 11 * ctypes.sizeof(ctypes.c_double))
>>> ctypes.resize(numbers, 10 * ctypes.sizeof(ctypes.c_double))
>>> ctypes.resize(numbers, 9 * ctypes.sizeof(ctypes.c_double))
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
ValueError: minimum size is 80
>>> numbers[:5] = range(5)
>>> numbers[:]
[0.0, 1.0, 2.0, 3.0, 4.0, 0.0, 0.0, 0.0, 0.0, 0.0]

```

## 内存管理的注意事项

除了明显的内存分配问题和混合可变和不可变对象之外，还有一个奇怪的内存可变性问题：

```py
>>> class Point(ctypes.Structure):
...     _fields_ = ('x', ctypes.c_int), ('y', ctypes.c_int)
...
>>> class Vertex(ctypes.Structure):
...     _fields_ = ('a', Point), ('b', Point), ('c', Point)
...
>>> v = Vertex()
>>> v.a = Point(0, 1)
>>> v.b = Point(2, 3)
>>> v.c = Point(4, 5)
>>> v.a.x, v.a.y, v.b.x, v.b.y, v.c.x, v.c.y
(0, 1, 2, 3, 4, 5)
>>> v.a, v.b, v.c = v.b, v.c, v.a
>>> v.a.x, v.a.y, v.b.x, v.b.y, v.c.x, v.c.y
(2, 3, 4, 5, 2, 3)
>>> v.a.x = 123
>>> v.a.x, v.a.y, v.b.x, v.b.y, v.c.x, v.c.y
(123, 3, 4, 5, 2, 3)

```

为什么我们没有得到`2, 3, 4, 5, 0, 1`？问题在于这些对象被复制到一个临时缓冲变量中。与此同时，该对象的值正在发生变化，因为它在内部包含了单独的对象。之后，对象被传回，但值已经改变，导致了不正确的结果。

# CFFI

`CFFI`库提供了与`ctypes`非常相似的选项，但它更直接一些。与`ctypes`库不同，C 编译器对于`CFFI`来说确实是必需的。它带来了直接以非常简单的方式调用你的 C 编译器的机会：

```py
>>> import cffi
>>> ffi = cffi.FFI()
>>> ffi.cdef('int printf(const char* format, ...);')
>>> libc = ffi.dlopen(None)
>>> arg = ffi.new('char[]', b'spam')
>>> libc.printf(arg)
4
spam>>>

```

好吧...看起来有点奇怪对吧？我们不得不定义`printf`函数的外观，并用有效的 C 类型声明指定`printf`的参数。然而，回到声明，而不是`None`到`ffi.dlopen`，你也可以指定你希望加载的库。如果你记得`ctypes.util.find_library`函数，你可以在这种情况下再次使用它：

```py
>>> from ctypes import util
>>> import cffi
>>> libc = ffi.dlopen(util.find_library('libc'))
>>> ffi.printf
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
AttributeError: 'FFI' object has no attribute 'printf'

```

但它仍然不会为你提供其定义。函数定义仍然是必需的，以确保一切都按照你希望的方式工作。

## 复杂的数据结构

`CFFI`的定义与`ctypes`的定义有些相似，但不是让 Python 模拟 C，而是直接从 Python 访问纯 C。实际上，这只是一个小的语法差异。而`ctypes`是一个用于从 Python 访问 C 的库，同时尽可能接近 Python 语法，`CFFI`使用纯 C 语法来访问 C 系统，这实际上消除了一些对于熟悉 C 的人的困惑。我个人发现`CFFI`更容易使用，因为我知道实际发生了什么，而对于`ctypes`，我并不总是 100%确定。让我们用 CFFI 重复`Vertex`和`Point`的例子：

```py
>>> import cffi
>>> ffi = cffi.FFI()
>>> ffi.cdef('''
... typedef struct {
...     int x;
...     int y;
... } point;
...
... typedef struct {
...     point a;
...     point b;
...     point c;
... } vertex;
... ''')
>>> vertices = ffi.new('vertex[]', 5)
>>> v = vertices[0]
>>> v.a.x = 1
>>> v.a.y = 2
>>> v.b.x = 3
>>> v.b.y = 4
>>> v.c.x = 5
>>> v.c.y = 6
>>> v.a.x, v.a.y, v.b.x, v.b.y, v.c.x, v.c.y
(1, 2, 3, 4, 5, 6)
v.a, v.b, v.c = v.b, v.c, v.a
v.a.x, v.a.y, v.b.x, v.b.y, v.c.x, v.c.y
>>> v.a, v.b, v.c = v.b, v.c, v.a
>>> v.a.x, v.a.y, v.b.x, v.b.y, v.c.x, v.c.y
(3, 4, 5, 6, 3, 4)

```

你可以看到，可变变量问题仍然存在，但代码仍然是可以使用的。

## 数组

使用`CFFI`为新变量分配内存几乎是微不足道的。前面的段落向你展示了数组分配的一个例子；现在让我们看看数组定义的可能性：

```py
>>> import cffi
>>> ffi = cffi.FFI()
>>> x = ffi.new('int[10]')
>>> y = ffi.new('int[]', 10)
>>> x[0:10] = range(10)
>>> y[0:10] = range(10, 0, -1)
>>> list(x)
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
>>> list(y)
[10, 9, 8, 7, 6, 5, 4, 3, 2, 1]

```

在这种情况下，你可能会想知道为什么切片包括起始和结束。这实际上是`CFFI`的要求。并不总是有问题，但仍然有点烦人。然而，目前，这是不可避免的。

## ABI 还是 API？

像往常一样，还有一些注意事项——不幸的是。到目前为止的例子部分使用了 ABI，它从库中加载二进制结构。对于标准 C 库，这通常是安全的；对于其他库，通常不是。API 和 ABI 之间的区别在于后者在二进制级别调用函数，直接寻址内存，直接调用内存位置，并期望它们是函数。实际上，这是`ffi.dlopen`和`ffi.cdef`之间的区别。在这里，`dlopen`并不总是安全的，但`cdef`是安全的，因为它传递了一个编译器，而不仅仅是猜测如何调用一个方法。

## CFFI 还是 ctypes？

这实际上取决于你在寻找什么。如果你有一个 C 库，只需要调用而且不需要任何特殊的东西，那么`ctypes`很可能是更好的选择。如果你实际上正在编写自己的 C 库并尝试链接它，那么`CFFI`可能是一个更方便的选择。如果你不熟悉 C 编程语言，那么我肯定会推荐`ctypes`。或者，你会发现`CFFI`是一个更方便的选择。

# 本地 C/C++扩展

到目前为止，我们使用的库只是向我们展示了如何在我们的 Python 代码中访问 C/C++库。现在我们将看看故事的另一面——实际上是如何编写 Python 中的 C/C++函数/模块以及如何创建`cPickle`和`cProfile`等模块。

## 一个基本的例子

在我们实际开始编写和使用本地 C/C++扩展之前，我们有一些先决条件。首先，我们需要编译器和 Python 头文件；本章开头的说明应该已经为我们处理了这些。之后，我们需要告诉 Python 要编译什么。`setuptools`包大部分会处理这个问题，但我们确实需要创建一个`setup.py`文件：

```py
import setuptools

spam = setuptools.Extension('spam', sources=['spam.c'])

setuptools.setup(
    name='Spam',
    version='1.0',
    ext_modules=[spam],
)
```

这告诉 Python 我们有一个名为`Spam`的`Extension`对象，它将基于`spam.c`。

现在，让我们在 C 中编写一个函数，它将对给定数字之前的所有完全平方数（`2*2`，`3*3`等）进行求和。Python 代码将如下所示：

```py
def sum_of_squares(n):
    sum = 0

    for i in range(n):
        if i * i < n:
            sum += i * i
        else:
            break

    return sum
```

这段代码的原始 C 版本看起来像这样：

```py
long sum_of_squares(long n){
    long sum = 0;

    /* The actual summing code */
    for(int i=0; i<n; i++){
        if((i * i) < n){
            sum += i * i;
        }else{
            break;
        }
    }

    return sum;
}
```

Python C 版本看起来像这样：

```py
#include <Python.h>

static PyObject* spam_sum_of_squares(PyObject *self, PyObject
        *args){
    /* Declare the variables */
    int n;
    int sum = 0;

    /* Parse the arguments */
    if(!PyArg_ParseTuple(args, "i", &n)){
        return NULL;
    }

    /* The actual summing code */
    for(int i=0; i<n; i++){
        if((i * i) < n){
            sum += i * i;
        }else{
            break;
        }
    }

    /* Return the number but convert it to a Python object first
     */
    return PyLong_FromLong(sum);
}

static PyMethodDef spam_methods[] = {
    /* Register the function */
    {"sum_of_squares", spam_sum_of_squares, METH_VARARGS,
     "Sum the perfect squares below n"},
    /* Indicate the end of the list */
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef spam_module = {
    PyModuleDef_HEAD_INIT,
    "spam", /* Module name */
    NULL, /* Module documentation */
    -1, /* Module state, -1 means global. This parameter is
           for sub-interpreters */
    spam_methods,
};

/* Initialize the module */
PyMODINIT_FUNC PyInit_spam(void){
    return PyModule_Create(&spam_module);
}
```

看起来很复杂，但实际上并不难。在这种情况下，只是有很多额外的开销，因为我们只有一个函数。通常情况下，你会有几个函数，这种情况下你只需要扩展`spam_methods`数组并创建函数。下一段将更详细地解释代码，但首先让我们看一下如何运行我们的第一个示例。我们需要构建并安装模块：

```py
# python setup.py build install
running build
running build_ext
running install
running install_lib
running install_egg_info
Removing lib/python3.5/site-packages/Spam-1.0-py3.5.egg-info
Writing lib/python3.5/site-packages/Spam-1.0-py3.5.egg-info

```

现在，让我们创建一个小的测试脚本来测试 Python 版本和 C 版本之间的差异：

```py
import sys
import spam
import timeit

def sum_of_squares(n):
    sum = 0

    for i in range(n):
        if i * i < n:
            sum += i * i
        else:
            break

    return sum

if __name__ == '__main__':
    c = int(sys.argv[1])
    n = int(sys.argv[2])
    print('%d executions with n: %d' % (c, n))
    print('C sum of squares: %d took %.3f seconds' % (
        spam.sum_of_squares(n),
        timeit.timeit('spam.sum_of_squares(n)', number=c,
                      globals=globals()),
    ))
    print('Python sum of squares: %d took %.3f seconds' % (
        sum_of_squares(n),
        timeit.timeit('sum_of_squares(n)', number=c,
                      globals=globals()),
    ))
```

现在让我们执行它：

```py
# python3 test_spam.py 10000 1000000
10000 executions with n: 1000000
C sum of squares: 332833500 took 0.008 seconds
Python sum of squares: 332833500 took 1.778 seconds

```

太棒了！完全相同的结果，但速度快了 200 多倍！

## C 不是 Python-大小很重要

Python 语言使编程变得如此简单，以至于你有时可能会忘记底层数据结构；而在 C 中，你不能这样做。只需拿我们上一章的示例，但使用不同的参数：

```py
# python3 test_spam.py 1000 10000000
1000 executions with n: 10000000
C sum of squares: 1953214233 took 0.002 seconds
Python sum of squares: 10543148825 took 0.558 seconds

```

它仍然非常快，但数字发生了什么？Python 和 C 版本给出了不同的结果，`1953214233`与`10543148825`。这是由 C 中的整数溢出引起的。而 Python 数字基本上可以有任何大小，而 C 中，常规数字有固定的大小。你得到多少取决于你使用的类型（`int`，`long`等）和你的架构（32 位，64 位等），但这绝对是需要小心的事情。在某些情况下，它可能快上数百倍，但如果结果不正确，那就毫无意义了。

当然，我们可以稍微增加一点大小。这样会更好：

```py
static PyObject* spam_sum_of_squares(PyObject *self, PyObject *args){
    /* Declare the variables */
    unsigned long long int n;
    unsigned long long int sum = 0;

    /* Parse the arguments */
    if(!PyArg_ParseTuple(args, "K", &n)){
        return NULL;
    }

    /* The actual summing code */
    for(unsigned long long int i=0; i<n; i++){
        if((i * i) < n){
            sum += i * i;
        }else{
            break;
        }
    }

    /* Return the number but convert it to a Python object first */
    return PyLong_FromUnsignedLongLong(sum);
}
```

如果我们现在测试它，我们会发现它运行得很好：

```py
# python3 test_spam.py 1000 100000001000 executions with n: 10000000
C sum of squares: 10543148825 took 0.002 seconds
Python sum of squares: 10543148825 took 0.635 seconds

```

除非我们使数字更大：

```py
# python3 test_spam.py 1 100000000000000 ~/Dropbox/Mastering Python/code/h14
1 executions with n: 100000000000000
C sum of squares: 1291890006563070912 took 0.006 seconds
Python sum of squares: 333333283333335000000 took 2.081 seconds

```

那么你该如何解决这个问题呢？简单的答案是你不能。复杂的答案是，如果你使用不同的数据类型来存储你的数据，你是可以的。C 语言本身并没有 Python 所具有的“大数支持”。Python 通过在实际内存中组合几个常规数字来支持无限大的数字。在 C 中，没有常见的这种支持，因此没有简单的方法来使其工作。但我们可以检查错误：

```py
static unsigned long long int get_number_from_object(int* overflow, PyObject* some_very_large_number){
    return PyLong_AsLongLongAndOverflow(sum, overflow);
}
```

请注意，这仅适用于`PyObject*`，这意味着它不适用于内部 C 溢出。但你当然可以保留原始的 Python 长整型并对其执行操作。因此，你可以在 C 中轻松获得大数支持。

## 示例解释

我们已经看到了我们示例的结果，但如果你不熟悉 Python C API，你可能会对为什么函数参数看起来像这样感到困惑。`spam_sum_of_squares`中的基本计算与常规 C`sum_of_squares`函数是相同的，但有一些小的不同。首先，使用 Python C API 定义函数的类型应该看起来像这样：

```py
static PyObject* spam_sum_of_squares(PyObject *self, PyObject
 ***args)

```

### 静态

这意味着函数是`static`。静态函数只能从编译器内的同一翻译单元中调用。这实际上导致了一个函数，不能从其他模块链接，这允许编译器进一步优化。由于 C 中的函数默认是全局的，这可以非常有用地防止冲突。但为了确保，我们已经在函数名前加上了`spam_`前缀，以表明这个函数来自`spam`模块。

要小心，不要将此处的`static`与变量前面的`static`混淆。它们是完全不同的东西。`static`变量意味着该变量将存在于整个程序的运行时间，而不仅仅是函数的运行时间。

### PyObject*

`PyObject`类型是 Python 数据类型的基本类型，这意味着所有 Python 对象都可以转换为`PyObject*`（`PyObject`指针）。实际上，它只告诉编译器期望的属性类型，这些属性可以在以后用于类型识别和内存管理。而不是直接访问`PyObject*`，通常最好使用可用的宏，例如`Py_TYPE(some_object)`。在内部，这会扩展为`(((PyObject*)(o))->ob_type)`，这就是为什么宏通常是一个更好的主意。除了难以阅读之外，很容易出现拼写错误。

属性列表很长，且在很大程度上取决于对象的类型。对于这些，我想参考 Python 文档：

[`docs.python.org/3/c-api/typeobj.html`](https://docs.python.org/3/c-api/typeobj.html)

整个 Python C API 可以填满一本书，但幸运的是在 Python 手册中有很好的文档。然而，使用可能不太明显。

### 解析参数

使用常规的 C 和 Python，您需要明确指定参数，因为使用 C 处理可变大小的参数有点棘手。这是因为它们需要被单独解析。`PyObject* args`是包含实际值的对象的引用。要解析这些，您需要知道期望的变量数量和类型。在示例中，我们使用了`PyArg_ParseTuple`函数，它只解析位置参数，但很容易使用`PyArg_ParseTupleAndKeywords`或`PyArg_VaParseTupleAndKeywords`解析命名参数。最后两者之间的区别在于第一个使用可变数量的参数来指定目的地，而后者使用`va_list`来设置值。但首先，让我们分析一下实际示例中的代码：

```py
if(!PyArg_ParseTuple(args, "i", &n)){
    return NULL;
}
```

我们知道`args`是包含对实际参数的引用的对象。`"i"`是一个格式字符串，在这种情况下将尝试解析一个整数。`&n`告诉函数将值存储在`n`变量的内存地址。

格式字符串在这里是重要的部分。根据字符的不同，您会得到不同的数据类型，但有很多；`i`指定一个常规整数，`s`将您的变量转换为 c 字符串（实际上是一个`char*`，它是一个以空字符结尾的字符数组）。值得注意的是，这个函数很幸运地足够聪明，可以考虑到溢出。

解析多个参数非常类似；您只需要向格式字符串添加多个字符和多个目标变量：

```py
PyObject* callback;
int n;

/* Parse the arguments */
if(!PyArg_ParseTuple(args, "Oi", &callback, &n)){
    return NULL;
}
```

带有关键字参数的版本类似，但需要进行一些代码更改，因为方法列表需要被告知函数接受关键字参数。否则，`kwargs`参数将永远不会到达：

```py
static PyObject* function(
        PyObject *self,
        PyObject *args,
        PyObject *kwargs){
    /* Declare the variables */
    int sum = 0;

    PyObject* callback;
    int n;

    static char* keywords[] = {"callback", "n", NULL};

    /* Parse the arguments */
    if(!PyArg_ParseTupleAndKeywords(args, kwargs, "Oi", keywords,
                &callback, &n)){
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyMethodDef methods[] = {
    /* Register the function with kwargs */
    {"function", function, METH_VARARGS | METH_KEYWORDS,
     "Some kwargs function"},
    /* Indicate the end of the list */
    {NULL, NULL, 0, NULL},
};
```

请注意，这仍然支持普通参数，但现在也支持关键字参数。

## C 不是 Python-错误是沉默的或致命的

正如我们在前面的例子中看到的，整数溢出通常不容易注意到，而且不幸的是，没有很好的跨平台方法来捕获它们。然而，这些通常是更容易处理的错误；最糟糕的错误通常是内存管理。使用 Python，如果出现错误，您将得到一个可以捕获的异常。但是在 C 中，您实际上无法优雅地处理它。例如，以零除：

```py
# python3 -c '1/0'
Traceback (most recent call last):
 **File "<string>", line 1, in <module>
ZeroDivisionError: division by zero

```

这很容易通过`try: ... except ZeroDivisionError: ...`捕获。另一方面，对于 C 来说，如果出现严重错误，它将终止整个进程。但是，调试 C 代码是 C 编译器具有调试器的功能，为了找到错误的原因，您可以使用第十一章中讨论的`faulthandler`模块，*调试-解决错误*。现在，让我们看看如何可以正确地从 C 中抛出错误。让我们使用之前的`spam`模块，但为了简洁起见，我们将省略其余的 C 代码：

```py
static PyObject* spam_eggs(PyObject *self, PyObject *args){
    PyErr_SetString(PyExc_RuntimeError, "Too many eggs!");
    return NULL;
}

static PyMethodDef spam_methods[] = {
    /* Register the function */
    {"eggs", spam_eggs, METH_VARARGS,
     "Count the eggs"},
    /* Indicate the end of the list */
    {NULL, NULL, 0, NULL},
};
```

这是执行过程：

```py
# python3 setup.py clean build install
...
# python3 -c 'import spam; spam.eggs()'
Traceback (most recent call last):
 **File "<string>", line 1, in <module>
RuntimeError: Too many eggs!

```

语法略有不同——`PyErr_SetString`而不是`raise`——但基本原理是相同的，幸运的是。

## 从 C 调用 Python-处理复杂类型

我们已经看到如何从 Python 调用 C 函数，但现在让我们尝试从 C 返回 Python。我们将构建一个自己的回调函数，并处理任何类型的可迭代对象，而不是使用现成的`sum`函数。虽然这听起来足够简单，但实际上确实需要一些类型干涉，因为你只能期望`PyObject*`作为参数。这与简单类型相反，例如整数、字符和字符串，它们会立即转换为本机 Python 版本：

```py
static PyObject* spam_sum(PyObject* self, PyObject* args){
    /* Declare all variables, note that the values for sum and
     * callback are defaults in the case these arguments are not
     * specified */
    long long int sum = 0;
    int overflow = 0;
    PyObject* iterator;
    PyObject* iterable;
    PyObject* callback = NULL;
    PyObject* value;
    PyObject* item;

    /* Now we parse a PyObject* followed by, optionally
     * (the | character), a PyObject* and a long long int */
    if(!PyArg_ParseTuple(args, "O|OL", &iterable, &callback,
                &sum)){
        return NULL;
    }

    /* See if we can create an iterator from the iterable. This is
     * effectively the same as doing iter(iterable) in Python */
    iterator = PyObject_GetIter(iterable);
    if(iterator == NULL){
        PyErr_SetString(PyExc_TypeError,
                "Argument is not iterable");
        return NULL;
    }

    /* Check if the callback exists or wasn't specified. If it was
     * specified check whether it's callable or not */
    if(callback != NULL && !PyCallable_Check(callback)){
        PyErr_SetString(PyExc_TypeError,
                "Callback is not callable");
        return NULL;
    }

    /* Loop through all items of the iterable */
    while((item = PyIter_Next(iterator))){
        /* If we have a callback available, call it. Otherwise
         * just return the item as the value */
        if(callback == NULL){
            value = item;
        }else{
            value = PyObject_CallFunction(callback, "O", item);
        }

        /* Add the value to sum and check for overflows */
        sum += PyLong_AsLongLongAndOverflow(value, &overflow);
        if(overflow > 0){
            PyErr_SetString(PyExc_RuntimeError,
                    "Integer overflow");
            return NULL;
        }else if(overflow < 0){
            PyErr_SetString(PyExc_RuntimeError,
                    "Integer underflow");
            return NULL;
        }

        /* If we were indeed using the callback, decrease the
         * reference count to the value because it is a separate
         * object now */
        if(callback != NULL){
            Py_DECREF(value);
        }
        Py_DECREF(item);
    }
    Py_DECREF(iterator);

    return PyLong_FromLongLong(sum);
}
```

确保您注意`PyDECREF`调用，这样可以确保您不会泄漏这些对象。如果没有它们，对象将继续使用，Python 解释器将无法清除它们。

这个函数可以以三种不同的方式调用：

```py
>>> import spam
>>> x = range(10)
>>> spam.sum(x)
45
>>> spam.sum(x, lambda y: y + 5)
95
>>> spam.sum(x, lambda y: y + 5, 5)
100

```

另一个重要问题是，即使我们在转换为`long long int`时捕获了溢出错误，这段代码仍然不安全。如果我们甚至对两个非常大的数字求和（接近`long long int`限制），我们仍然会发生溢出：

```py
>>> import spam
>>> n = (2 ** 63) - 1
>>> x = n,
>>> spam.sum(x)
9223372036854775807
>>> x = n, n
>>> spam.sum(x)
-2

```

# 总结

在本章中，您学习了使用`ctypes`、`CFFI`编写代码以及如何使用本机 C 扩展 Python 功能的最重要方面。这些主题本身就足够广泛，可以填满一本书，但是现在您应该掌握了最重要的主题。即使您现在能够创建 C/C++扩展，我仍然建议您尽量避免这样做。这是因为不够小心很容易出现错误。实际上，至少本章中的一些示例在内存管理方面可能存在错误，并且在给出错误输入时可能会使您的 Python 解释器崩溃。不幸的是，这是 C 的副作用。一个小错误可能会产生巨大的影响。

在构建本章中的示例时，您可能已经注意到我们使用了一个`setup.py`文件，并从`setuptools`库导入。下一章将涵盖这一点——将您的代码打包成可安装的 Python 库，并在 Python 软件包索引上进行分发。


# 第十五章：包装-创建您自己的库或应用程序

到目前为止，这些章节已经涵盖了如何编写、测试和调试 Python 代码。有了这一切，只剩下一件事，那就是打包和分发您的 Python 库/和应用程序。为了创建可安装的包，我们将使用 Python 这些天捆绑的`setuptools`包。如果您以前创建过包，您可能还记得`distribute`和`distutils2`，但非常重要的是要记住，这些都已经被`setuptools`和`distutils`取代，您不应该再使用它们！

我们可以使用`setuptools`打包哪些类型的程序？我们将向您展示几种情况：

+   常规包

+   带有数据的包

+   安装可执行文件和自定义`setuptools`命令

+   在包上运行测试

+   包含 C/C++扩展的包

# 安装包

在我们真正开始之前，重要的是要知道如何正确安装包。至少有四种不同的选项可以安装包。第一种最明显的方法是使用普通的`pip`命令：

```py
pip install package

```

这也可以通过直接使用`setup.py`来实现：

```py
cd package
python setup.py install

```

这将在您的 Python 环境中安装包，如果您使用它，可能是`virtualenv`/`venv`，否则是全局环境。

然而，对于开发来说，这是不推荐的。要测试您的代码，您需要为每个测试重新安装包，或者修改 Python 的`site-packages`目录中的文件，这意味着它将位于您的修订控制系统之外。这就是开发安装的用途；它们不是将包文件复制到 Python 包目录中，而是在`site-packages`目录中安装到实际包位置的路径的链接。这使您可以修改代码，并立即在运行的脚本和应用程序中看到结果，而无需在每次更改后重新安装代码。

与常规安装一样，`pip`和`setup.py`版本都可用：

```py
pip install –e package_directory

```

以及`setup.py`版本：

```py
cd package_directory
python setup.py develop

```

# 设置参数

之前的章节实际上已经向我们展示了一些示例，但让我们重申和回顾最重要的部分实际上是做什么。在整个本章中，您将使用的核心功能是`setuptools.setup`。

### 注意

对于最简单的包，Python 捆绑的`distutils`包将足够，但无论如何我推荐`setuptools`。`setuptools`包具有许多`distutils`缺乏的出色功能，并且几乎所有 Python 环境都会有`setuptools`可用。

在继续之前，请确保您拥有最新版本的`pip`和`setuptools`：

```py
pip install -U pip setuptools

```

### 注意

`setuptools`和`distutils`包在过去几年中发生了重大变化，2014 年之前编写的文档/示例很可能已经过时。小心不要实现已弃用的示例，并跳过使用`distutils`的任何文档/示例。

既然我们已经具备了所有先决条件，让我们创建一个包含最重要字段的示例，并附带内联文档：

```py
import setuptools

if __name__ == '__main__':
    setuptools.setup(
        name='Name',
        version='0.1',

        # This automatically detects the packages in the specified
        # (or current directory if no directory is given).
        packages=setuptools.find_packages(),

        # The entry points are the big difference between
        # setuptools and distutils, the entry points make it
        # possible to extend setuptools and make it smarter and/or
        # add custom commands.
        entry_points={

            # The following would add: python setup.py
            # command_name
            'distutils.commands': [
                'command_name = your_package:YourClass',
            ],

            # The following would make these functions callable as
            # standalone scripts. In this case it would add the
            # spam command to run in your shell.
            'console_scripts': [
                'spam = your_package:SpamClass',
            ],
        },

        # Packages required to use this one, it is possible to
        # specify simply the application name, a specific version
        # or a version range. The syntax is the same as pip
        # accepts.
        install_requires=['docutils>=0.3'],

        # Extra requirements are another amazing feature of
        # setuptools, it allows people to install extra
        # dependencies if you are interested. In this example
        # doing a "pip install name[all]" would install the
        # python-utils package as well.
        extras_requires={
            'all': ['python-utils'],
        },

        # Packages required to install this package, not just for
        # running it but for the actual install. These will not be
        # installed but only downloaded so they can be used during
        # the install. The pytest-runner is a useful example:
        setup_requires=['pytest-runner'],

        # The requirements for the test command. Regular testing
        # is possible through: python setup.py test The Pytest
        # module installs a different command though: python
        # setup.py pytest
        tests_require=['pytest'],

        # The package_data, include_package_data and
        # exclude_package_data arguments are used to specify which
        # non-python files should be included in the package. An
        # example would be documentation files.  More about this
        # in the next paragraph
        package_data={
            # Include (restructured text) documentation files from
            # any directory
            '': ['*.rst'],
            # Include text files from the eggs package:
            'eggs': ['*.txt'],
        },

        # If a package is zip_safe the package will be installed
        # as a zip file. This can be faster but it generally
        # doesn't make too much of a difference and breaks
        # packages if they need access to either the source or the
        # data files. When this flag is omitted setuptools will
        # try to autodetect based on the existance of datafiles
        # and C extensions. If either exists it will not install
        # the package as a zip. Generally omitting this parameter
        # is the best option but if you have strange problems with
        # missing files, try disabling zip_safe.
        zip_safe=False,

        # All of the following fileds are PyPI metadata fields.
        # When registering a package at PyPI this is used as
        # information on the package page.
        author='Rick van Hattem',
        author_email='wolph@wol.ph',

        # This should be a short description (one line) for the
        # package
        description='Description for the name package',

        # For this parameter I would recommend including the
        # README.rst

        long_description='A very long description',
        # The license should be one of the standard open source
        # licenses: https://opensource.org/licenses/alphabetical
        license='BSD',

        # Homepage url for the package
        url='https://wol.ph/',
    )
```

这是相当多的代码和注释，但它涵盖了您在现实生活中可能遇到的大多数选项。这里讨论的最有趣和多功能的参数将在接下来的各个部分中单独介绍。

附加文档可以在`pip`和`setuptools`文档以及 Python 包装用户指南中找到：

+   [`pythonhosted.org/setuptools/`](http://pythonhosted.org/setuptools/)

+   [`pip.pypa.io/en/stable/`](https://pip.pypa.io/en/stable/)

+   [`python-packaging-user-guide.readthedocs.org/en/latest/`](http://python-packaging-user-guide.readthedocs.org/en/latest/)

# 包

在我们的例子中，我们只是使用`packages=setuptools.find_packages()`。在大多数情况下，这将工作得很好，但重要的是要理解它的作用。`find_packages`函数会查找给定目录中的所有目录，并在其中有`__init__.py`文件的情况下将其添加到列表中。因此，你通常可以使用`['your_package']`代替`find_packages()`。然而，如果你有多个包，那么这往往会变得乏味。这就是`find_packages()`有用的地方；只需指定一些包含参数（第二个参数）或一些排除参数（第三个参数），你就可以在项目中拥有所有相关的包。例如：

```py
packages = find_packages(exclude=['tests', 'docs'])

```

# 入口点

`entry_points`参数可以说是`setuptools`最有用的功能。它允许你向`setuptools`中的许多东西添加钩子，但最有用的两个是添加命令行和 GUI 命令的可能性，以及扩展`setuptools`命令。命令行和 GUI 命令甚至会在 Windows 上转换为可执行文件。第一节中的例子已经演示了这两个功能：

```py
entry_points={
    'distutils.commands': [
        'command_name = your_package:YourClass',
    ],
    'console_scripts': [
        'spam = your_package:SpamClass',
    ],
},
```

这个演示只是展示了如何调用函数，但没有展示实际的函数。

## 创建全局命令

第一个，一个简单的例子，没有什么特别的；只是一个作为常规`main`函数被调用的函数，在这里你需要自己指定`sys.argv`（或者更好的是使用`argparse`）。这是`setup.py`文件：

```py
import setuptools

if __name__ == '__main__':
    setuptools.setup(
        name='Our little project',
        entry_points={
            'console_scripts': [
                'spam = spam.main:main',
            ],
        },
    )
```

当然，这里有`spam/main.py`文件：

```py
import sys

def main():
    print('Args:', sys.argv)
```

一定不要忘记创建一个`spam/__init__.py`文件。它可以是空的，但它需要存在，以便 Python 知道它是一个包。

现在，让我们试着安装这个包：

```py
# pip install -e .
Installing collected packages: Our-little-project
 **Running setup.py develop for Our-little-project
Successfully installed Our-little-project
# spam 123 abc
Args: ['~/envs/mastering_python/bin/spam', '123', 'abc']

```

看，创建一个在常规命令行 shell 中安装的`spam`命令是多么简单！在 Windows 上，它实际上会给你一个可执行文件，该文件将被添加到你的路径中，但无论在哪个平台上，它都将作为一个可调用的独立可执行文件。

## 自定义 setup.py 命令

编写自定义的`setup.py`命令非常有用。一个例子是`sphinx-pypi-upload-2`，我在所有的包中都使用它，它是我维护的`unmaintained sphinx-pypi-upload`包的分支。这是一个使构建和上传 Sphinx 文档到 Python 包索引变得非常简单的包，当分发你的包时非常有用。使用`sphinx-pypi-upload-2`包，你可以做以下操作（我在分发我维护的任何包时都会这样做）：

```py
python setup.py sdist bdist_wheel upload build_sphinx upload_sphinx

```

这个命令会构建你的包并将其上传到 PyPI，并构建 Sphinx 文档并将其上传到 PyPI。

但你当然想看看这是如何工作的。首先，这是我们`spam`命令的`setup.py`：

```py
import setuptools

if __name__ == '__main__':
    setuptools.setup(
        name='Our little project',
        entry_points={
            'distutils.commands': [
                'spam = spam.command:SpamCommand',
            ],
        },
    )
```

其次，`SpamCommand`类。基本要点是继承`setuptools.Command`并确保实现所有需要的方法。请注意，所有这些方法都需要实现，但如果需要，可以留空。这是`spam/command.py`文件：

```py
import setuptools

class SpamCommand(setuptools.Command):
    description = 'Make some spam!'
# Specify the commandline arguments for this command here. This
# parameter uses the getopt module for parsing'
    user_options = [
        ('spam=', 's', 'Set the amount of spams'),
    ]

    def initialize_options(self):
# This method can be used to set default values for the
# options. These defaults can be overridden by
# command-line, configuration files and the setup script
# itself.
        self.spam = 3

    def finalize_options(self):
# This method allows you to override the values for the
# options, useful for automatically disabling
# incompatible options and for validation.
        self.spam = max(0, int(self.spam))

    def run(self):
        # The actual running of the command.
        print('spam' * self.spam)
```

执行它非常简单：

```py
# pip install -e .
Installing collected packages: Our-little-project
 **Running setup.py develop for Our-little-project
Successfully installed Our-little-project-0.0.0
# python setup.py --help-commands
[...]
Extra commands:
 **[...]
 **spam              Make some spam!
 **test              run unit tests after in-place build
 **[...]

usage: setup.py [global_opts] cmd1 [cmd1_opts] [cmd2 [cmd2_opts] ...]
 **or: setup.py --help [cmd1 cmd2 ...]
 **or: setup.py --help-commands
 **or: setup.py cmd –help

# python setup.py --help spam
Common commands: (see '--help-commands' for more)

[...]

Options for 'SpamCommand' command:
 **--spam (-s)  Set the amount of spams

usage: setup.py [global_opts] cmd1 [cmd1_opts] [cmd2 [cmd2_opts] ...]
 **or: setup.py --help [cmd1 cmd2 ...]
 **or: setup.py --help-commands
 **or: setup.py cmd --help

# python setup.py spam
running spam
spamspamspam
# python setup.py spam -s 5
running spam
spamspamspamspamspam

```

实际上只有很少的情况下你会需要自定义的`setup.py`命令，但这个例子仍然很有用，因为它目前是`setuptools`的一个未记录的部分。

# 包数据

在大多数情况下，你可能不需要包含包数据，但在需要数据与你的包一起的情况下，有一些不同的选项。首先，重要的是要知道默认情况下包含在你的包中的文件有哪些：

+   包目录中的 Python 源文件递归

+   `setup.py`和`setup.cfg`文件

+   测试：`test/test*.py`

+   在`examples`目录中的所有`*.txt`和`*.py`文件

+   在根目录中的所有`*.txt`文件

所以在默认值之后，我们有了第一个解决方案：`setup`函数的`package_data`参数。它的语法非常简单，一个字典，其中键是包，值是要包含的模式：

```py
package_data = {
    'docs': ['*.rst'],
}
```

第二种解决方案是使用`MANIFEST.in`文件。该文件包含要包括、排除和其他的模式。`include`和`exclude`命令使用模式进行匹配。这些模式是通配符样式的模式（请参阅`glob`模块的文档：[`docs.python.org/3/library/glob.html`](https://docs.python.org/3/library/glob.html)），并且对于包括和排除命令都有三种变体：

+   `include`/`exclude`: 这些命令仅适用于给定的路径，而不适用于其他任何内容

+   `recursive-include`/`recursive-exclude`: 这些命令类似于`include`/`exclude`命令，但是递归处理给定的路径

+   `global-include`/`global-exclude`: 对于这些命令要非常小心，它们将在源树中的任何位置包含或排除这些文件

除了`include`/`exclude`命令之外，还有另外两个命令；`graft`和`prune`命令，它们包括或排除包括给定目录下的所有文件的目录。这对于测试和文档可能很有用，因为它们可以包括非标准文件。除了这些例子之外，几乎总是最好明确包括您需要的文件并忽略所有其他文件。这是一个`MANIFEST.in`的例子：

```py
# Comments can be added with a hash tag
include LICENSE CHANGES AUTHORS

# Include the docs, tests and examples completely
graft docs
graft tests
graft examples

# Always exclude compiled python files
global-exclude *.py[co]

# Remove documentation builds
prune docs/_build
```

# 测试软件包

在第十章，“测试和日志-为错误做准备”，测试章节中，我们看到了 Python 的许多测试系统。正如您可能怀疑的那样，至少其中一些已经集成到了`setup.py`中。

## Unittest

在开始之前，我们应该为我们的包创建一个测试脚本。对于实际的测试，请参阅第十章，“测试和日志-为错误做准备”，测试章节。在这种情况下，我们将只使用一个无操作测试，`test.py`：

```py
import unittest

class Test(unittest.TestCase):

    def test(self):
        pass
```

标准的`python setup.py test`命令将运行常规的`unittest`命令：

```py
# python setup.py -v test
running test
running "unittest --verbose"
running egg_info
writing Our_little_project.egg-info/PKG-INFO
writing dependency_links to Our_little_project.egg-info/dependency_links.txt
writing top-level names to Our_little_project.egg-info/top_level.txt
writing entry points to Our_little_project.egg-info/entry_points.txt
reading manifest file 'Our_little_project.egg-info/SOURCES.txt'
writing manifest file 'Our_little_project.egg-info/SOURCES.txt'
running build_ext
test (test.Test) ... ok

----------------------------------------------------------------------
Ran 1 test in 0.000s

OK

```

可以通过使用`--test-module`、`--test-suite`或`--test-runner`参数告诉`setup.py`使用不同的测试。虽然这些很容易使用，但我建议跳过常规的`test`命令，而是尝试使用`nose`或`py.test`。

## py.test

`py.test`软件包有几种集成方法：`pytest-runner`，您自己的测试命令，以及生成`runtests.py`脚本进行测试的已弃用方法。如果您的软件包中仍在使用`runtests.py`，我强烈建议切换到其他选项之一。

但在讨论其他选项之前，让我们确保我们有一些测试。所以让我们在我们的包中创建一个测试。我们将把它存储在`test_pytest.py`中：

```py
def test_a():
    pass

def test_b():
    pass
```

现在，其他测试选项。由于自定义命令实际上并没有增加太多内容，而且实际上使事情变得更加复杂，我们将跳过它。如果您想自定义测试的运行方式，请改用`pytest.ini`和`setup.cfg`文件。最好的选项是`pytest-runner`，它使运行测试变得非常简单：

```py
# pip install pytest-runner
Collecting pytest-runner
 **Using cached pytest_runner-2.7-py2.py3-none-any.whl
Installing collected packages: pytest-runner
Successfully installed pytest-runner-2.7
# python setup.py pytest
running pytest
running egg_info
writing top-level names to Our_little_project.egg-info/top_level.txt
writing dependency_links to Our_little_project.egg-info/dependency_links.txt
writing entry points to Our_little_project.egg-info/entry_points.txt
writing Our_little_project.egg-info/PKG-INFO
reading manifest file 'Our_little_project.egg-info/SOURCES.txt'
writing manifest file 'Our_little_project.egg-info/SOURCES.txt'
running build_ext
======================== test session starts =========================
platform darwin -- Python 3.5.1, pytest-2.8.7, py-1.4.31, pluggy-0.3.1
rootdir: h15, inifile: pytest.ini
collected 2 items

test_pytest.py ..

====================== 2 passed in 0.01 seconds ======================

```

为了正确地集成这种方法，我们应该对`setup.py`脚本进行一些更改。它们并不是严格需要的，但对于使用您的软件包的其他人来说，这会使事情变得更加方便，可能不知道您正在使用`py.test`，例如。首先，我们确保标准的`python setup.py test`命令实际上运行`pytest`命令，而不是通过修改`setup.cfg`来运行：

```py
[aliases]
test=pytest
```

其次，我们要确保`setup.py`命令安装我们运行`py.test`测试所需的软件包。为此，我们还需要修改`setup.py`：

```py
import setuptools

if __name__ == '__main__':
    setuptools.setup(
        name='Our little project',
        entry_points={
            'distutils.commands': [
                'spam = spam.command:SpamCommand',
            ],
        },
        setup_requires=['pytest-runner'],
        tests_require=['pytest'],
    )
```

这种方法的美妙之处在于常规的`python setup.py test`命令可以工作，并且在运行测试之前会自动安装所有所需的要求。但是，由于`pytest`要求仅在`tests_require`部分中，如果未运行测试命令，则它们将不会被安装。唯一始终会被安装的软件包是`pytest-runner`软件包，这是一个非常轻量级的软件包，因此安装和运行起来非常轻便。

## Nosetests

`nose`包只处理安装，并且与`py.test`略有不同。唯一的区别是`py.test`有一个单独的`pytest-runner`包用于测试运行器，而 nose 包有一个内置的`nosetests`命令。因此，以下是 nose 版本：

```py
# pip install nose
Collecting nose
 **Using cached nose-1.3.7-py3-none-any.whl
Installing collected packages: nose
Successfully installed nose-1.3.7
# python setup.py nosetests
running nosetests
running egg_info
writing top-level names to Our_little_project.egg-info/top_level.txt
writing entry points to Our_little_project.egg-info/entry_points.txt
writing Our_little_project.egg-info/PKG-INFO
writing dependency_links to Our_little_project.egg-info/dependency_lin
ks.txt
reading manifest file 'Our_little_project.egg-info/SOURCES.txt'
writing manifest file 'Our_little_project.egg-info/SOURCES.txt'
..
----------------------------------------------------------------------
Ran 2 tests in 0.006s

OK

```

# C/C++扩展

前一章已经在一定程度上涵盖了这一点，因为编译 C/C++文件是必需的。但是那一章并没有解释在这种情况下`setup.py`在做什么以及如何做。

为了方便起见，我们将重复`setup.py`文件：

```py
import setuptools

spam = setuptools.Extension('spam', sources=['spam.c'])

setuptools.setup(
    name='Spam',
    version='1.0',
    ext_modules=[spam],
)
```

在开始使用这些扩展之前，你应该学习以下命令：

+   `build`：这实际上不是一个特定于 C/C++的构建函数（尝试`build_clib`），而是一个组合构建函数，用于在`setup.py`中构建所有内容。

+   `clean`：这会清理`build`命令的结果。通常情况下不需要，但有时重新编译工作的文件检测是不正确的。因此，如果遇到奇怪或意外的问题，请尝试先清理项目。

## 常规扩展

`setuptools.Extension`类告诉`setuptools`一个名为`spam`的模块使用源文件`spam.c`。这只是一个扩展的最简单版本，一个名称和一个源列表，但在许多情况下，你需要的不仅仅是简单的情况。

一个例子是`pillow`库，它会检测系统上可用的库，并根据此添加扩展。但是因为这些扩展包括库，所以需要一些额外的编译标志。基本的 PIL 模块本身似乎并不太复杂，但是库实际上都是包含了所有自动检测到的库和匹配的宏定义：

```py
exts = [(Extension("PIL._imaging", files, libraries=libs,
                   define_macros=defs))]
```

`freetype`扩展有类似的东西：

```py
if feature.freetype:
    exts.append(Extension(
        "PIL._imagingft", ["_imagingft.c"], libraries=["freetype"]))
```

## Cython 扩展

`setuptools`库在处理扩展时实际上比常规的`distutils`库要聪明一些。它实际上向`Extension`类添加了一个小技巧。还记得第十二章中对性能的简要介绍吗？`setuptools`库使得编译这些变得更加方便。`Cython`手册建议你使用类似以下代码的东西：

```py
from distutils.core import setup
from Cython.Build import cythonize

setup(
    ext_modules = cythonize("eggs.pyx")
)
```

这里的`eggs.pyx`包含：

```py
def make_eggs(int n):
    print('Making %d eggs: %s' % (n, n * 'eggs '))
```

这种方法的问题是，除非你安装了`Cython`，否则`setup.py`会出现问题：

```py
# python setup.py build
Traceback (most recent call last):
 **File "setup.py", line 2, in <module>
 **import Cython
ImportError: No module named 'Cython'

```

为了防止这个问题，我们只需要让`setuptools`处理这个问题：

```py
import setuptools

eggs = setuptools.Extension('eggs', sources=['eggs.pyx'])

setuptools.setup(
    name='Eggs',
    version='1.0',
    ext_modules=[eggs],
    setup_requires=['Cython'],
)
```

现在，如果需要，`Cython`将被自动安装，并且代码将正常工作：

```py
# python setup.py build
running build
running build_ext
cythoning eggs.pyx to eggs.c
building 'eggs' extension
...
# python setup.py develop
running develop
running egg_info
creating Eggs.egg-info
writing dependency_links to Eggs.egg-info/dependency_links.txt
writing top-level names to Eggs.egg-info/top_level.txt
writing Eggs.egg-info/PKG-INFO
writing manifest file 'Eggs.egg-info/SOURCES.txt'
reading manifest file 'Eggs.egg-info/SOURCES.txt'
writing manifest file 'Eggs.egg-info/SOURCES.txt'
running build_ext
skipping 'eggs.c' Cython extension (up-to-date)
copying build/... ->
Creating Eggs.egg-link (link to .)
Adding Eggs 1.0 to easy-install.pth file

Installed Eggs
Processing dependencies for Eggs==1.0
Finished processing dependencies for Eggs==1.0
# python -c 'import eggs; eggs.make_eggs(3)'
Making 3 eggs: eggs eggs eggs

```

然而，为了开发目的，`Cython`还提供了一种不需要手动构建的更简单的方法。首先，为了确保我们实际上正在使用这种方法，让我们安装`Cython`，并彻底卸载和清理`eggs`：

```py
# pip uninstall eggs -y
Uninstalling Eggs-1.0:
 **Successfully uninstalled Eggs-1.0
# pip uninstall eggs -y
Cannot uninstall requirement eggs, not installed
# python setup.py clean
# pip install cython

```

现在让我们尝试运行我们的`eggs.pyx`模块：

```py
>>> import pyximport
>>> pyximport.install()
(None, <pyximport.pyximport.PyxImporter object at 0x...>)
>>> import eggs
>>> eggs.make_eggs(3)
Making 3 eggs: eggs eggs eggs

```

这就是在没有显式编译的情况下运行`pyx`文件的简单方法。

# Wheels - 新的 eggs

对于纯 Python 包，`sdist`（源分发）命令一直足够了。但是对于 C/C++包来说，通常并不那么方便。C/C++包的问题在于，除非使用二进制包，否则需要进行编译。传统上，这些通常是`.egg`文件，但它们从未真正解决了问题。这就是为什么引入了`wheel`格式（PEP 0427），这是一种包含源代码和二进制代码的二进制包格式，可以在 Windows 和 OS X 上安装，而无需编译器。作为额外的奖励，它也可以更快地安装纯 Python 包。

实现起来幸运的是很简单。首先，安装`wheel`包：

```py
# pip install wheel

```

现在你可以使用`bdist_wheel`命令来构建你的包。唯一的小问题是，默认情况下 Python 3 创建的包只能在 Python 3 上运行，因此 Python 2 安装将退回到`sdist`文件。为了解决这个问题，你可以将以下内容添加到你的`setup.cfg`文件中：

```py
[bdist_wheel]
universal = 1
```

这里唯一需要注意的重要事项是，在 C 扩展的情况下，可能会出错。Python 3 的二进制 C 扩展与 Python 2 的不兼容。因此，如果您有一个纯 Python 软件包，并且同时针对 Python 2 和 3，启用该标志。否则，就将其保持为默认值。

## 分发到 Python Package Index

一旦您的一切都正常运行，经过测试和记录，就是时候将项目实际推送到**Python Package Index**（**PyPI**）了。在将软件包推送到 PyPI 之前，我们需要确保一切都井井有条。

首先，让我们检查`setup.py`文件是否有问题：

```py
# python setup.py check
running check
warning: check: missing required meta-data: url

warning: check: missing meta-data: either (author and author_email) or (maintainer and maintainer_email) must be supplied

```

看起来我们忘记了指定`url`和`author`或`maintainer`信息。让我们填写这些：

```py
import setuptools

eggs = setuptools.Extension('eggs', sources=['eggs.pyx'])

setuptools.setup(
    name='Eggs',
    version='1.0',
    ext_modules=[eggs],
    setup_requires=['Cython'],
    url='https://wol.ph/',
    author='Rick van Hattem (Wolph)',
    author_email='wolph@wol.ph',
)
```

现在让我们再次检查：

```py
# python setup.py check
running check

```

完美！没有错误，一切看起来都很好。

现在我们的`setup.py`已经井井有条了，让我们来尝试测试。由于我们的小测试项目几乎没有测试，这将几乎是空的。但是如果您正在启动一个新项目，我建议从一开始就尽量保持 100%的测试覆盖率。稍后实施所有测试通常更加困难，而在工作时进行测试通常会让您更多地考虑代码的设计决策。运行测试非常容易：

```py
# python setup.py test
running test
running egg_info
writing dependency_links to Eggs.egg-info/dependency_links.txt
writing Eggs.egg-info/PKG-INFO
writing top-level names to Eggs.egg-info/top_level.txt
reading manifest file 'Eggs.egg-info/SOURCES.txt'
writing manifest file 'Eggs.egg-info/SOURCES.txt'
running build_ext
skipping 'eggs.c' Cython extension (up-to-date)
copying build/... ->

---------------------------------------------------------------------
Ran 0 tests in 0.000s

OK

```

现在我们已经检查完毕，下一步是构建文档。如前所述，`sphinx`和`sphinx-pypi-upload-2`软件包可以在这方面提供帮助：

```py
# python setup.py build_sphinx
running build_sphinx
Running Sphinx v1.3.5
...

```

一旦我们确定一切都正确，我们就可以构建软件包并将其上传到 PyPI。对于纯 Python 版本的发布，您可以使用`sdist`（源分发）命令。对于使用本机安装程序的软件包，有一些选项可用，例如`bdist_wininst`和`bdist_rpm`。我个人几乎在所有我的软件包中使用以下命令：

```py
# python setup.py build_sphinx upload_sphinx sdist bdist_wheel upload

```

这将自动构建 Sphinx 文档，将文档上传到 PyPI，使用源构建软件包，并使用源上传软件包。

显然，只有在您是特定软件包的所有者并且被 PyPI 授权时，才能成功完成此操作。

### 注意

在上传软件包之前，您需要在 PyPI 上注册软件包。这可以使用`register`命令来完成，但由于这会立即在 PyPI 服务器上注册软件包，因此在测试时不应使用。

# 总结

阅读完本章后，您应该能够创建包含不仅是纯 Python 文件，还包括额外数据、编译的 C/C++扩展、文档和测试的 Python 软件包。有了这些工具，您现在可以制作高质量的 Python 软件包，这些软件包可以轻松地在其他项目和软件包中重复使用。

Python 基础设施使得创建新软件包并将项目拆分为多个子项目变得非常容易。这使您能够创建简单且可重用的软件包，因为一切都很容易进行测试。虽然您不应该过度拆分软件包，但是如果脚本或模块具有自己的目的，那么它就是可以单独打包的候选项。

通过本章，我们已经完成了本书。我真诚地希望您喜欢阅读，并了解了新颖有趣的主题。非常感谢您的任何反馈，所以请随时通过我的网站[`wol.ph/`](https://wol.ph/)与我联系。
