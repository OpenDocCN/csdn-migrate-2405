# Python 函数式编程（四）

> 原文：[`zh.annas-archive.org/md5/0A7865EB133E2D9D03688623C60BD998`](https://zh.annas-archive.org/md5/0A7865EB133E2D9D03688623C60BD998)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：多进程和线程模块

当我们消除复杂的共享状态并设计非严格处理时，我们可以利用并行性来提高性能。在本章中，我们将研究可用于我们的多进程和多线程技术。Python 库包在应用于允许惰性评估的算法时尤其有帮助。

这里的核心思想是在一个进程内或跨多个进程中分发一个函数式程序。如果我们创建了一个合理的函数式设计，我们就不会有应用程序组件之间的复杂交互；我们有接受参数值并产生结果的函数。这是进程或线程的理想结构。

我们将专注于“多进程”和`concurrent.futures`模块。这些模块允许多种并行执行技术。

我们还将专注于进程级并行而不是多线程。进程并行的理念使我们能够忽略 Python 的全局解释器锁（GIL），实现出色的性能。

有关 Python 的 GIL 的更多信息，请参阅[`docs.python.org/3.3/c-api/init.html#thread-state-and-the-global-interpreter-lock`](https://docs.python.org/3.3/c-api/init.html#thread-state-and-the-global-interpreter-lock)。

我们不会强调“线程”模块的特性。这经常用于并行处理。如果我们的函数式编程设计得当，那么由多线程写访问引起的任何问题都应该被最小化。然而，GIL 的存在意味着在 CPython 中，多线程应用程序会受到一些小限制的影响。由于等待 I/O 不涉及 GIL，一些 I/O 绑定的程序可能具有异常良好的性能。

最有效的并行处理发生在正在执行的任务之间没有依赖关系的情况下。通过一些精心设计，我们可以将并行编程视为一种理想的处理技术。开发并行程序的最大困难在于协调对共享资源的更新。

在遵循函数式设计模式并避免有状态的程序时，我们还可以最小化对共享对象的并发更新。如果我们能够设计出中心是惰性、非严格评估的软件，我们也可以设计出可以进行并发评估的软件。

程序总是会有一些严格的依赖关系，其中操作的顺序很重要。在`2*(3+a)`表达式中，`(3+a)`子表达式必须首先进行评估。然而，在处理集合时，我们经常遇到集合中项目的处理顺序并不重要的情况。

考虑以下两个例子：

```py
x = list(func(item) for item in y)
x = list(reversed([func(item) for item in y[::-1]]))

```

尽管项目以相反的顺序进行评估，但这两个命令都会产生相同的结果。

事实上，即使是以下命令片段也会产生相同的结果：

```py
import random
indices= list(range(len(y)))
random.shuffle(indices)
x = [None]*len(y)
for k in indices:
 **x[k] = func(y[k])

```

评估顺序是随机的。由于每个项目的评估是独立的，评估顺序并不重要。许多允许非严格评估的算法都是如此。

# 并发真正意味着什么

在一台小型计算机上，只有一个处理器和一个核心，所有评估都是通过处理器的核心进行串行化的。操作系统将通过巧妙的时间切片安排交错执行多个进程和多个线程。

在具有多个 CPU 或单个 CPU 中的多个核心的计算机上，可以对 CPU 指令进行一些实际的并发处理。所有其他并发都是通过操作系统级别的时间切片模拟的。Mac OS X 笔记本电脑可以有 200 个共享 CPU 的并发进程；这比可用核心数多得多。由此可见，操作系统的时间切片负责大部分表面上的并发行为。

# 边界条件

让我们考虑一个假设的算法，其中有![边界条件](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_12_01.jpg)。假设有一个涉及 1000 字节 Python 代码的内部循环。在处理 10000 个对象时，我们执行了 1000 亿次 Python 操作。这是基本的处理预算。我们可以尝试分配尽可能多的进程和线程，但处理预算是不能改变的。

单个 CPython 字节码没有简单的执行时间。然而，在 Mac OS X 笔记本上的长期平均值显示，我们可以预期每秒执行大约 60MB 的代码。这意味着我们的 1000 亿字节码操作将需要大约 1666 秒，或 28 分钟。

如果我们有一台双处理器、四核的计算机，那么我们可能将经过时间缩短到原始总时间的 25%：7 分钟。这假设我们可以将工作分成四个（或更多）独立的操作系统进程。

这里的重要考虑因素是我们的 1000 亿字节码的预算是不能改变的。并行性不会神奇地减少工作量。它只能改变时间表，也许可以减少经过时间。

切换到一个更好的算法可以将工作量减少到 132MB 的操作。以 60MBps 的速度，这个工作量要小得多。并行性不会像算法改变那样带来戏剧性的改进。

# 与进程或线程共享资源

操作系统确保进程之间几乎没有交互。要使两个进程交互，必须显式共享一些公共的操作系统资源。这可以是一个共享文件，一个特定的共享内存对象，或者是进程之间共享状态的信号量。进程本质上是独立的，交互是例外。

另一方面，多个线程是单个进程的一部分；进程的所有线程共享操作系统资源。我们可以例外地获得一些线程本地内存，可以自由写入而不受其他线程干扰。除了线程本地内存，写入内存的操作可能以潜在的不可预测顺序设置进程的内部状态。必须使用显式锁定来避免这些有状态更新的问题。正如之前所指出的，指令执行的整体顺序很少是严格并发的。并发线程和进程的指令通常以不可预测的顺序交错执行。使用线程会带来对共享变量的破坏性更新的可能性，需要仔细的锁定。并行处理会带来操作系统级进程调度的开销。

事实上，即使在硬件级别，也存在一些复杂的内存写入情况。有关内存写入问题的更多信息，请访问[`en.wikipedia.org/wiki/Memory_disambiguation`](http://en.wikipedia.org/wiki/Memory_disambiguation)。

并发对象更新的存在是设计多线程应用程序时所面临的困难。锁定是避免对共享对象进行并发写入的一种方法。避免共享对象是另一种可行的设计技术。这更适用于函数式编程。

在 CPython 中，GIL 用于确保操作系统线程调度不会干扰对 Python 数据结构的更新。实际上，GIL 将调度的粒度从机器指令改变为 Python 虚拟机操作。没有 GIL，内部数据结构可能会被竞争线程的交错交互所破坏。

# 利益将会产生的地方

一个进行大量计算而相对较少 I/O 的程序不会从并发处理中获得太多好处。如果一个计算有 28 分钟的计算时间，那么以不同的方式交错操作不会产生太大影响。从严格到非严格评估 1000 亿个字节码不会缩短经过的执行时间。

然而，如果一个计算涉及大量 I/O，那么交错 CPU 处理和 I/O 请求可能会影响性能。理想情况下，我们希望在等待操作系统完成下一批数据输入时对一些数据进行计算。

我们有两种交错计算和 I/O 的方法。它们如下：

+   我们可以尝试将 I/O 和计算整体问题交错进行。我们可以创建一个包含读取、计算和写入操作的处理流水线。这个想法是让单独的数据对象从一个阶段流向下一个阶段。每个阶段可以并行操作。

+   我们可以将问题分解成可以并行处理的独立部分，从头到尾进行处理。

这些方法之间的差异并不明显；有一个模糊的中间区域，不太清楚是哪一个。例如，多个并行流水线是两种设计的混合体。有一些形式化方法可以更容易地设计并发程序。**通信顺序进程**（**CSP**）范式可以帮助设计消息传递应用程序。像`pycsp`这样的包可以用来向 Python 添加 CSP 形式化方法。

I/O 密集型程序通常受益于并发处理。这个想法是交错 I/O 和处理。CPU 密集型程序很少受益于尝试并发处理。

# 使用多处理池和任务

为了在更大的上下文中使用非严格评估，`multiprocessing`包引入了`Pool`对象的概念。我们可以创建一个并发工作进程的`Pool`对象，将任务分配给它们，并期望任务并发执行。正如之前所述，这个创建并不实际意味着同时创建`Pool`对象。这意味着顺序很难预测，因为我们允许操作系统调度交错执行多个进程。对于一些应用程序，这允许在更少的经过时间内完成更多的工作。

为了充分利用这一能力，我们需要将应用程序分解成组件，对于这些组件，非严格并发执行是有益的。我们希望定义可以以不确定顺序处理的离散任务。

通过网络抓取从互联网收集数据的应用程序通常通过并行处理进行优化。我们可以创建几个相同的网站抓取器的`Pool`对象。任务是由池化进程分析的 URL。

分析多个日志文件的应用程序也是并行化的一个很好的候选。我们可以创建一个分析进程的`Pool`对象。我们可以将每个日志文件分配给一个分析器；这允许在`Pool`对象的各个工作进程之间并行进行读取和分析。每个单独的工作进程将涉及串行 I/O 和计算。然而，一个工作进程可以在其他工作进程等待 I/O 完成时分析计算。

## 处理许多大文件

这是一个多处理应用程序的例子。我们将在网络日志文件中抓取**通用日志格式**（**CLF**）行。这是访问日志的通用格式。这些行往往很长，但在书的边距处包装时看起来像下面这样：

```py
99.49.32.197 - - [01/Jun/2012:22:17:54 -0400] "GET /favicon.ico HTTP/1.1" 200 894 "-" "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.52 Safari/536.5"
```

我们经常有大量大文件需要分析。许多独立文件的存在意味着并发对我们的抓取过程有一些好处。

我们将分解分析为两个广泛的功能领域。任何处理的第一阶段都是解析日志文件以收集相关信息的基本阶段。我们将这分解为四个阶段。它们如下：

1.  读取来自多个源日志文件的所有行。

1.  然后，从文件集合中的日志条目的行创建简单的命名元组。

1.  更复杂字段的细节，如日期和 URL，被解析。

1.  日志中的无趣路径被拒绝；我们也可以认为这是只传递有趣的路径。

一旦过了解析阶段，我们就可以执行大量的分析。为了演示`multiprocessing`模块，我们将进行一个简单的分析，计算特定路径的出现次数。

从源文件中读取的第一部分涉及最多的输入处理。Python 对文件迭代器的使用将转换为更低级别的 OS 请求来缓冲数据。每个 OS 请求意味着进程必须等待数据变得可用。

显然，我们希望交错进行其他操作，以便它们不必等待 I/O 完成。我们可以沿着从单个行到整个文件的光谱交错操作。我们将首先查看交错整个文件，因为这相对简单实现。

解析 Apache CLF 文件的功能设计可以如下所示：

```py
data = path_filter(access_detail_iter(access_iter(local_gzip(filename))))

```

我们已经将更大的解析问题分解为将处理解析问题的各部分的多个函数。`local_gzip()`函数从本地缓存的 GZIP 文件中读取行。`access_iter()`函数为访问日志中的每一行创建一个简单的`namedtuple`对象。`access_detail_iter()`函数将扩展一些更难解析的字段。最后，`path_filter()`函数将丢弃一些分析价值不高的路径和文件扩展名。

## 解析日志文件-收集行

这是解析大量文件的第一阶段：读取每个文件并生成一系列简单的行。由于日志文件以`.gzip`格式保存，我们需要使用`gzip.open()`函数而不是`io.open()`函数或`__builtins__.open()`函数来打开每个文件。

`local_gzip()`函数从本地缓存的文件中读取行，如下命令片段所示：

```py
def local_gzip(pattern):
 **zip_logs= glob.glob(pattern)
 **for zip_file in zip_logs:
 **with gzip.open(zip_file, "rb") as log:
 **yield (line.decode('us-ascii').rstrip() for line in log)

```

前面的函数遍历所有文件。对于每个文件，生成的值是一个生成器函数，它将遍历该文件中的所有行。我们封装了一些东西，包括通配符文件匹配、打开以`.gzip`格式压缩的日志文件的细节，以及将文件分解为一系列不带任何尾随`\n`字符的行。

这里的基本设计模式是产生每个文件的生成器表达式的值。前面的函数可以重新表述为一个函数和一个将该函数应用于每个文件的映射。

还有其他几种方法可以产生类似的输出。例如，以下是前面示例中内部`for`循环的另一种替代版本。`line_iter()`函数还将发出给定文件的行：

```py
 **def line_iter(zip_file):
 **log= gzip.open(zip_file, "rb")
 **return (line.decode('us-ascii').rstrip() for line in log)

```

`line_iter()`函数应用`gzip.open()`函数和一些行清理。我们可以使用映射将`line_iter()`函数应用于符合模式的所有文件，如下所示：

```py
map(line_iter, glob.glob(pattern))

```

虽然这种替代映射很简洁，但它的缺点是在没有更多引用时，会留下等待被正确垃圾回收的打开文件对象。处理大量文件时，这似乎是一种不必要的开销。因此，我们将专注于先前显示的`local_gzip()`函数。

先前的替代映射具有与“多进程”模块配合良好的明显优势。我们可以创建一个工作进程池，并将任务（如文件读取）映射到进程池中。如果这样做，我们可以并行读取这些文件；打开的文件对象将成为单独的进程的一部分。

对这种设计的扩展将包括第二个函数，用于使用 FTP 从 Web 主机传输文件。当从 Web 服务器收集文件时，可以使用`local_gzip()`函数对其进行分析。

`local_gzip()`函数的结果被`access_iter()`函数使用，为源文件中描述文件访问的每一行创建命名元组。

## 将日志行解析为命名元组

一旦我们可以访问每个日志文件的所有行，我们就可以提取描述的访问的详细信息。我们将使用正则表达式来分解行。从那里，我们可以构建一个`namedtuple`对象。

以下是解析 CLF 文件中行的正则表达式：

```py
format_pat= re.compile(
    r"(?P<host>[\d\.]+)\s+"
    r"(?P<identity>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"\[(?P<time>.+?)\]\s+"
    r'"(?P<request>.+?)"\s+'
    r"(?P<status>\d+)\s+"
    r"(?P<bytes>\S+)\s+"
    r'"(?P<referer>.*?)"\s+' # [SIC]
    r'"(?P<user_agent>.+?)"\s*'
)** 

```

我们可以使用这个正则表达式将每一行分解为九个单独的数据元素的字典。使用`[]`和`"`来界定复杂字段（如`time`、`request`、`referrer`和`user_agent`参数）的方式由命名元组模式优雅地处理。

每个单独的访问可以总结为一个`namedtuple()`函数，如下所示：

```py
Access = namedtuple('Access', ['host', 'identity', 'user', 'time', 'request', 'status', 'bytes', 'referrer', 'user_agent'])

```

### 注意

我们已经费心确保`namedtuple`函数的字段与`(?P<name>)`构造中每条记录的正则表达式组名匹配。通过确保名称匹配，我们可以非常容易地将解析的字典转换为元组以进行进一步处理。

以下是`access_iter()`函数，它要求每个文件都表示为文件行的迭代器：

```py
def access_iter(source_iter):
 **for log in source_iter:
 **for line in log:
 **match= format_pat.match(line)
 **if match:
 **yield Access(**match.groupdict())

```

`local_gzip()`函数的输出是一个序列的序列。外部序列由单独的日志文件组成。对于每个文件，都有一个可迭代的行序列。如果行与给定模式匹配，它就是某种文件访问。我们可以从`match`字典中创建一个`Access`命名元组。

这里的基本设计模式是从解析函数的结果构建静态对象。在这种情况下，解析函数是一个正则表达式匹配器。

有一些替代方法可以做到这一点。例如，我们可以修改`map()`函数的使用如下：

```py
 **def access_builder(line):
 **match= format_pat.match(line)
 **if match:
 **return Access(**match.groupdict())

```

先前的替代函数仅包含基本的解析和构建`Access`对象的处理。它将返回一个`Access`或`None`对象。这与上面的版本不同，后者还过滤了不匹配正则表达式的项目。

以下是我们如何使用此函数将日志文件展平为`Access`对象的单个流：

```py
 **map(access_builder, (line for log in source_iter for line in log))

```

这显示了我们如何将`local_gzip()`函数的输出转换为`Access`实例的序列。在这种情况下，我们将`access_builder()`函数应用于从读取文件集合中产生的嵌套迭代器的可迭代结构。

我们的重点在于展示我们有许多解析文件的功能样式。在第四章中，*与集合一起工作*，我们展示了非常简单的解析。在这里，我们正在执行更复杂的解析，使用各种技术。

## 解析访问对象的其他字段

先前创建的初始`Access`对象并没有分解组成访问日志行的九个字段中的一些内部元素。我们将这些项目分别从整体分解成高级字段。如果我们将这个分解成单独的解析操作，可以使解析正则表达式变得更简单。

结果对象是一个`namedtuple`对象，它将包装原始的`Access`元组。它将具有一些额外的字段，用于单独解析的细节：

```py
AccessDetails = namedtuple('AccessDetails', ['access', 'time', 'method', 'url', 'protocol', 'referrer', 'agent'])

```

`access`属性是原始的`Access`对象。`time`属性是解析的`access.time`字符串。`method`、`url`和`protocol`属性来自分解`access.request`字段。`referrer`属性是解析的 URL。`agent`属性也可以分解为细粒度字段。以下是组成代理详情的字段：

```py
AgentDetails= namedtuple('AgentDetails', ['product', 'system', 'platform_details_extensions'])

```

这些字段反映了代理描述的最常见语法。在这个领域有相当大的变化，但这个特定的值子集似乎是相当常见的。

我们将三个详细的解析器函数合并成一个整体解析函数。这是第一部分，包括各种详细解析器：

```py
def access_detail_iter(iterable):
 **def parse_request(request):
 **words = request.split()
 **return words[0], ' '.join(words[1:-1]), words[-1]
 **def parse_time(ts):
 **return datetime.datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
 **agent_pat= re.compile(r"(?P<product>\S*?)\s+"
 **r"\((?P<system>.*?)\)\s*"
 **r"(?P<platform_details_extensions>.*)")
 **def parse_agent(user_agent):
 **agent_match= agent_pat.match(user_agent)
 **if agent_match:
 **return AgentDetails(**agent_match.groupdict())

```

我们已经为 HTTP 请求、时间戳和用户代理信息编写了三个解析器。请求通常是一个包含三个单词的字符串，例如`GET /some/path HTTP/1.1`。 “parse_request（）”函数提取这三个以空格分隔的值。如果路径中有空格，我们将提取第一个单词和最后一个单词作为方法和协议；其余所有单词都是路径的一部分。

时间解析委托给`datetime`模块。我们在“parse_time（）”函数中提供了正确的格式。

解析用户代理是具有挑战性的。有许多变化；我们为“parse_agent（）”函数选择了一个常见的变体。如果用户代理与给定的正则表达式匹配，我们将拥有`AgentDetails`命名元组的属性。如果用户代理信息不匹配正则表达式，我们将简单地使用`None`值。

我们将使用这三个解析器从给定的“访问”对象构建`AccessDetails`实例。 “access_detail_iter（）”函数的主体如下：

```py
 **for access in iterable:
 **try:
 **meth, uri, protocol = parse_request(access.request)
 **yield AccessDetails(
                access= access,
                time= parse_time(access.time),
                method= meth,
                url= urllib.parse.urlparse(uri),
                protocol= protocol,
                referrer = urllib.parse.urlparse(access.referer),
                agent= parse_agent(access.user_agent)** 
 **except ValueError as e:
 **print(e, repr(access))

```

我们已经使用了与之前的“access_iter（）”函数类似的设计模式。从解析某个输入对象的结果构建了一个新对象。新的`AccessDetails`对象将包装先前的`Access`对象。这种技术允许我们使用不可变对象，但仍然包含更精细的信息。

这个函数本质上是从`Access`对象到`AccessDetails`对象的映射。我们可以想象改变设计以使用“map（）”如下：

```py
def access_detail_iter2(iterable):
 **def access_detail_builder(access):
 **try:
 **meth, uri, protocol = parse_request(access.request)
 **return AccessDetails(access= access,time= parse_time(access.time),method= meth,url= urllib.parse.urlparse(uri),protocol= protocol,referrer = urllib.parse.urlparse(access.referer),agent= parse_agent(access.user_agent))
 **except ValueError as e:
 **print(e, repr(access))
 **return filter(None, map(access_detail_builder, iterable))

```

我们已经更改了`AccessDetails`对象的构造方式，使其成为返回单个值的函数。我们可以将该函数映射到`Access`对象的可迭代输入流。这也与`multiprocessing`模块的工作方式非常匹配。

在面向对象的编程环境中，这些额外的解析器可能是类定义的方法函数或属性。这种设计的优点是，除非需要，否则不会解析项目。这种特定的功能设计解析了一切，假设它将被使用。

不同的函数设计可能依赖于三个解析器函数，根据需要从给定的`Access`对象中提取和解析各个元素。我们将使用“parse_time（access.time）”参数，而不是使用`details.time`属性。语法更长，但只有在需要时才解析属性。

## 过滤访问细节

我们将查看`AccessDetails`对象的几个过滤器。第一个是一组过滤器，拒绝了许多很少有趣的开销文件。第二个过滤器将成为分析函数的一部分，我们稍后会看到。

“path_filter（）”函数是三个函数的组合：

1.  排除空路径。

1.  排除一些特定的文件名。

1.  排除具有特定扩展名的文件。

“path_filter（）”函数的优化版本如下：

```py
def path_filter(access_details_iter):
 **name_exclude = {'favicon.ico', 'robots.txt', 'humans.txt', 'crossdomain.xml' ,'_images', 'search.html', 'genindex.html', 'searchindex.js', 'modindex.html', 'py-modindex.html',}
 **ext_exclude = { '.png', '.js', '.css', }
 **for detail in access_details_iter:
 **path = detail.url.path.split('/')
 **if not any(path):
 **continue
 **if any(p in name_exclude for p in path):
 **continue
 **final= path[-1]
 **if any(final.endswith(ext) for ext in ext_exclude):
 **continue
 **yield detail

```

对于每个单独的`AccessDetails`对象，我们将应用三个过滤测试。如果路径基本为空，或者部分包括被排除的名称之一，或者路径的最终名称具有被排除的扩展名，该项目将被静默地忽略。如果路径不符合这些标准之一，它可能是有趣的，并且是`path_filter()`函数产生的结果的一部分。

这是一个优化，因为所有的测试都是使用命令式风格的`for`循环体应用的。

设计始于每个测试作为一个单独的一流过滤器风格函数。例如，我们可能有一个处理空路径的函数如下：

```py
 **def non_empty_path(detail):
 **path = detail.url.path.split('/')
 **return any(path)

```

这个函数只是确保路径包含一个名称。我们可以使用`filter()`函数如下：

```py
filter(non_empty_path, access_details_iter)

```

我们可以为`non_excluded_names()`和`non_excluded_ext()`函数编写类似的测试。整个`filter()`函数序列将如下所示：

```py
filter(non_excluded_ext,
    filter(non_excluded_names,
        filter(non_empty_path, access_details_iter)))** 

```

这将每个`filter()`函数应用于前一个`filter()`函数的结果。空路径将被拒绝；从这个子集中，被排除的名称和被排除的扩展名也将被拒绝。我们也可以将前面的示例陈述为一系列赋值语句如下：

```py
 **ne= filter(non_empty_path, access_details_iter)
 **nx_name= filter(non_excluded_names, ne)
 **nx_ext= filter(non_excluded_ext, nx_name)
 **return nx_ext

```

这个版本的优点是在添加新的过滤条件时稍微更容易扩展。

### 注意

使用生成器函数（如`filter()`函数）意味着我们不会创建大型的中间对象。每个中间变量`ne`、`nx_name`和`nx_ext`都是适当的惰性生成器函数；直到数据被客户端进程消耗之前，都不会进行处理。

虽然优雅，但这会导致一些小的低效，因为每个函数都需要解析`AccessDetails`对象中的路径。为了使这更有效，我们需要使用`lru_cache`属性包装`path.split('/')`函数。

## 分析访问细节

我们将看看两个分析函数，我们可以用来过滤和分析单个`AccessDetails`对象。第一个函数，一个`filter()`函数，将只传递特定的路径。第二个函数将总结每个不同路径的出现次数。

我们将`filter()`函数定义为一个小函数，并将其与内置的`filter()`函数结合起来，将该函数应用于细节。这是复合`filter()`函数：

```py
def book_filter(access_details_iter):
 **def book_in_path(detail):
 **path = tuple(l for l in detail.url.path.split('/') if l)
 **return path[0] == 'book' and len(path) > 1
 **return filter(book_in_path, access_details_iter)

```

我们定义了一个规则，即`book_in_path()`属性，我们将应用于每个`AccessDetails`对象。如果路径不为空，并且路径的第一级属性是`book`，那么我们对这些对象感兴趣。所有其他`AccessDetails`对象可以被静默地拒绝。

这是我们感兴趣的最终减少：

```py
from collections import Counter
def reduce_book_total(access_details_iter):
 **counts= Counter()
 **for detail in access_details_iter:
 **counts[detail.url.path] += 1
 **return counts

```

这个函数将产生一个`Counter()`对象，显示了`AccessDetails`对象中每个路径的频率。为了专注于特定的路径集，我们将使用`reduce_total(book_filter(details))`方法。这提供了一个仅显示通过给定过滤器的项目的摘要。

## 完整的分析过程

这是消化日志文件集合的复合`analysis()`函数：

```py
def analysis(filename):
 **details= path_filter(access_detail_iter(access_iter(local_gzip(filename))))
 **books= book_filter(details)
 **totals= reduce_book_total(books)
 **return totals

```

前面的命令片段将适用于单个文件名或文件模式。它将一组标准的解析函数`path_filter()`、`access_detail_iter()`、`access_iter()`和`local_gzip()`应用于文件名或文件模式，并返回`AccessDetails`对象的可迭代序列。然后，它将我们的分析过滤器和减少器应用于`AccessDetails`对象的这个序列。结果是一个`Counter`对象，显示了某些路径的访问频率。

一组特定的保存为`.gzip`格式的日志文件总共约 51MB。使用这个函数串行处理文件需要超过 140 秒。我们能否使用并发处理做得更好？

# 使用多进程池进行并发处理

使用`multiprocessing`模块的一个优雅的方法是创建一个处理`Pool`对象，并将工作分配给该池中的各个进程。我们将使用操作系统在各个进程之间交错执行。如果每个进程都有 I/O 和计算的混合，我们应该能够确保我们的处理器非常忙碌。当进程等待 I/O 完成时，其他进程可以进行计算。当 I/O 完成时，一个进程将准备好运行，并且可以与其他进程竞争处理时间。

将工作映射到单独的进程的方法如下：

```py
 **import multiprocessing
 **with multiprocessing.Pool(4) as workers:
 **workers.map(analysis, glob.glob(pattern))

```

我们创建了一个具有四个独立进程的`Pool`对象，并将该`Pool`对象分配给`workers`变量。然后，我们将一个名为`analysis`的函数映射到要执行的工作的可迭代队列上，使用进程池。`workers`池中的每个进程将被分配来自可迭代队列的项目。在这种情况下，队列是`glob.glob(pattern)`属性的结果，它是文件名的序列。

由于`analysis()`函数返回一个结果，创建`Pool`对象的父进程可以收集这些结果。这使我们能够创建几个并发构建的`Counter`对象，并将它们合并成一个单一的复合结果。

如果我们在池中启动*p*个进程，我们的整个应用程序将包括*p+1*个进程。将有一个父进程和*p*个子进程。这通常效果很好，因为在子进程池启动后，父进程将几乎没有什么要做。通常情况下，工作进程将被分配到单独的 CPU（或核心），而父进程将与`Pool`对象中的一个子进程共享一个 CPU。

### 注意

由该模块创建的子进程遵循普通的 Linux 父/子进程规则。如果父进程在没有正确收集子进程的最终状态的情况下崩溃，那么可能会留下“僵尸”进程在运行。因此，进程`Pool`对象是一个上下文管理器。当我们通过`with`语句使用进程池时，在上下文结束时，子进程会被正确终止。

默认情况下，`Pool`对象将具有基于`multiprocessing.cpu_count()`函数值的工作进程数。这个数字通常是最佳的，只需使用`with multiprocessing.Pool() as workers:`属性可能就足够了。

在某些情况下，有时比 CPU 更多的工作进程可能会有所帮助。当每个工作进程都有 I/O 密集型处理时，这可能是真的。有许多工作进程等待 I/O 完成可以改善应用程序的运行时间。

如果给定的`Pool`对象有*p*个工作进程，这种映射可以将处理时间减少到几乎处理所有日志的时间的![使用多进程池进行并发处理](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_12_03.jpg)。实际上，在`Pool`对象中父进程和子进程之间的通信涉及一些开销。因此，一个四核处理器可能只能将处理时间减少一半。

多进程`Pool`对象有四种类似 map 的方法来分配工作给进程池：`map()`、`imap()`、`imap_unordered()`和`starmap()`。每个方法都是将函数映射到进程池的变体。它们在分配工作和收集结果的细节上有所不同。

`map(function, iterable)`方法将可迭代对象中的项目分配给池中的每个工作进程。完成的结果按照它们分配给`Pool`对象的顺序进行收集，以保持顺序。

`imap(function, iterable)` 方法被描述为比 map 方法“更懒”。默认情况下，它会将可迭代对象中的每个单独项目发送给下一个可用的工作进程。这可能涉及更多的通信开销。因此建议使用大于 1 的块大小。

`imap_unordered(function, iterable)`方法类似于`imap()`方法，但结果的顺序不被保留。允许映射无序处理意味着每个进程完成时结果都被收集。否则，结果必须按顺序收集。

`starmap(function, iterable)`方法类似于`itertools.starmap()`函数。可迭代对象中的每个项目必须是一个元组；使用`*`修饰符将元组传递给函数，以便元组的每个值成为位置参数值。实际上，它执行`function(*iterable[0])`，`function(*iterable[1])`等等。

以下是前述映射主题的一个变体：

```py
 **import multiprocessing
 **pattern = "*.gz"
 **combined= Counter()
 **with multiprocessing.Pool() as workers:
 **for result in workers.imap_unordered(analysis, glob.glob(pattern)):
 **combined.update(result)

```

我们创建了一个`Counter()`函数，用于整合池中每个工作进程的结果。我们根据可用 CPU 的数量创建了一个子进程池，并使用`Pool`对象作为上下文管理器。然后我们将我们的`analysis()`函数映射到我们文件匹配模式中的每个文件上。来自`analysis()`函数的结果`Counter`对象被合并成一个单一的计数器。

这大约需要 68 秒。使用多个并发进程，分析日志的时间减少了一半。

我们使用`multiprocessing`模块的`Pool.map()`函数创建了一个两层的 map-reduce 过程。第一层是`analysis()`函数，它对单个日志文件执行了 map-reduce。然后我们在更高级别的 reduce 操作中 consolide 这些减少。

## 使用 apply()来发出单个请求

除了`map()`函数的变体外，池还有一个`apply(function, *args, **kw)`方法，我们可以使用它来将一个值传递给工作池。我们可以看到`map()`方法实际上只是一个包装在`apply()`方法周围的`for`循环，例如，我们可以使用以下命令：

```py
list(workers.apply(analysis, f) for f in glob.glob(pattern))

```

对于我们的目的来说，这并不明显是一个重大的改进。我们几乎可以把所有需要做的事情都表达为一个`map()`函数。

## 使用 map_async()，starmap_async()和 apply_async()

`map()`，`starmap()`和`apply()`函数的行为是将工作分配给`Pool`对象中的子进程，然后在子进程准备好响应时收集响应。这可能导致子进程等待父进程收集结果。`_async()`函数的变体不会等待子进程完成。这些函数返回一个对象，可以查询该对象以获取子进程的单个结果。

以下是使用`map_async()`方法的变体：

```py
 **import multiprocessing
 **pattern = "*.gz"
 **combined= Counter()
 **with multiprocessing.Pool() as workers:
 **results = workers.map_async(analysis, glob.glob(pattern))
 **data= results.get()
 **for c in data:
 **combined.update(c)

```

我们创建了一个`Counter()`函数，用于整合池中每个工作进程的结果。我们根据可用 CPU 的数量创建了一个子进程池，并将这个`Pool`对象用作上下文管理器。然后我们将我们的`analysis()`函数映射到我们文件匹配模式中的每个文件上。`map_async()`函数的响应是一个`MapResult`对象；我们可以查询这个对象以获取池中工作进程的结果和整体状态。在这种情况下，我们使用`get()`方法获取`Counter`对象的序列。

来自`analysis()`函数的结果`Counter`对象被合并成一个单一的`Counter`对象。这个聚合给我们提供了多个日志文件的总体摘要。这个处理并没有比之前的例子更快。使用`map_async()`函数允许父进程在等待子进程完成时做额外的工作。

## 更复杂的多进程架构

`multiprocessing`包支持各种各样的架构。我们可以轻松创建跨多个服务器的多进程结构，并提供正式的身份验证技术，以创建必要的安全级别。我们可以使用队列和管道在进程之间传递对象。我们可以在进程之间共享内存。我们还可以在进程之间共享较低级别的锁，以同步对共享资源（如文件）的访问。

大多数这些架构都涉及显式管理多个工作进程之间的状态。特别是使用锁和共享内存，这是必要的，但与函数式编程方法不太匹配。

我们可以通过一些小心处理，以函数式方式处理队列和管道。我们的目标是将设计分解为生产者和消费者函数。生产者可以创建对象并将它们插入队列。消费者将从队列中取出对象并处理它们，可能将中间结果放入另一个队列。这样就创建了一个并发处理器网络，工作负载分布在这些不同的进程之间。使用`pycsp`包可以简化进程之间基于队列的消息交换。欲了解更多信息，请访问[`pypi.python.org/pypi/pycsp`](https://pypi.python.org/pypi/pycsp)。

在设计复杂的应用服务器时，这种设计技术有一些优势。各个子进程可以存在于服务器的整个生命周期中，同时处理各个请求。

## 使用`concurrent.futures`模块

除了`multiprocessing`包，我们还可以使用`concurrent.futures`模块。这也提供了一种将数据映射到并发线程或进程池的方法。模块 API 相对简单，并且在许多方面类似于`multiprocessing.Pool()`函数的接口。

以下是一个示例，展示它们有多相似：

```py
 **import concurrent.futures
 **pool_size= 4
 **pattern = "*.gz"
 **combined= Counter()
 **with concurrent.futures.ProcessPoolExecutor(max_workers=pool_size) as workers:
 **for result in workers.map(analysis, glob.glob(pattern)):
 **combined.update(result)

```

前面示例和之前的示例之间最显著的变化是，我们使用了`concurrent.futures.ProcessPoolExecutor`对象的实例，而不是`multiprocessing.Pool`方法。基本的设计模式是使用可用工作进程池将`analysis()`函数映射到文件名列表。生成的`Counter`对象被合并以创建最终结果。

`concurrent.futures`模块的性能几乎与`multiprocessing`模块相同。

## 使用`concurrent.futures`线程池

`concurrent.futures`模块提供了第二种我们可以在应用程序中使用的执行器。我们可以使用`concurrent.futures.ProcessPoolExecutor`对象，也可以使用`ThreadPoolExecutor`对象。这将在单个进程中创建一个线程池。

语法与使用`ProcessPoolExecutor`对象完全相同。然而，性能却有显著不同。日志文件处理受 I/O 控制。一个进程中的所有线程共享相同的操作系统调度约束。因此，多线程日志文件分析的整体性能与串行处理日志文件的性能大致相同。

使用示例日志文件和运行 Mac OS X 的小型四核笔记本电脑，以下是表明共享 I/O 资源的线程和进程之间差异的结果类型：

+   使用`concurrent.futures`线程池，经过的时间是 168 秒

+   使用进程池，经过的时间是 68 秒

在这两种情况下，`Pool`对象的大小都是 4。目前尚不清楚哪种应用程序受益于多线程方法。一般来说，多进程似乎对 Python 应用程序最有利。

## 使用线程和队列模块

Python 的`threading`包涉及一些有助于构建命令式应用程序的构造。这个模块不专注于编写函数式应用程序。我们可以利用`queue`模块中的线程安全队列，在线程之间传递对象。

`threading`模块没有一种简单的方法来将工作分配给各个线程。API 并不理想地适用于函数式编程。

与`multiprocessing`模块的更原始特性一样，我们可以尝试隐藏锁和队列的有状态和命令性本质。然而，似乎更容易利用`concurrent.futures`模块中的`ThreadPoolExecutor`方法。`ProcessPoolExecutor.map（）`方法为我们提供了一个非常愉快的界面，用于并发处理集合的元素。

使用`map（）`函数原语来分配工作似乎与我们的函数式编程期望很好地契合。因此，最好专注于`concurrent.futures`模块作为编写并发函数程序的最可访问的方式。

## 设计并发处理

从函数式编程的角度来看，我们已经看到了三种并发应用`map（）`函数概念的方法。我们可以使用以下任何一种：

+   `multiprocessing.Pool`

+   `concurrent.futures.ProcessPoolExecutor`

+   `concurrent.futures.ThreadPoolExecutor`

它们在与它们交互的方式上几乎是相同的；所有三个都有一个`map（）`方法，它将一个函数应用于可迭代集合的项。这与其他函数式编程技术非常优雅地契合。性能有所不同，因为并发线程与并发进程的性质不同。

当我们逐步设计时，我们的日志分析应用程序分解为两个整体领域：

+   解析的下层：这是通用解析，几乎可以被任何日志分析应用程序使用

+   更高级别的分析应用程序：这更具体的过滤和减少专注于我们的应用需求

下层解析可以分解为四个阶段：

+   从多个源日志文件中读取所有行。这是从文件名到行序列的`local_gzip（）`映射。

+   从文件集合中的日志条目的行创建简单的命名元组。这是从文本行到 Access 对象的`access_iter（）`映射。

+   解析更复杂字段的细节，如日期和 URL。这是从`Access`对象到`AccessDetails`对象的`access_detail_iter（）`映射。

+   从日志中拒绝不感兴趣的路径。我们也可以认为这只传递有趣的路径。这更像是一个过滤器而不是一个映射操作。这是捆绑到`path_filter（）`函数中的一系列过滤器。

我们定义了一个总体的`analysis（）`函数，它解析和分析给定的日志文件。它将更高级别的过滤和减少应用于下层解析的结果。它也可以处理通配符文件集合。

考虑到涉及的映射数量，我们可以看到将这个问题分解为可以映射到线程或进程池中的工作的几种方法。以下是一些我们可以考虑的设计替代方案：

+   将`analysis（）`函数映射到单个文件。我们在本章中始终使用这个作为一个一致的例子。

+   将`local_gzip（）`函数重构为总体`analysis（）`函数之外。现在我们可以将修订后的`analysis（）`函数映射到`local_gzip（）`函数的结果。

+   将`access_iter（local_gzip（pattern））`函数重构为总体`analysis（）`函数之外。我们可以将这个修订后的`analysis（）`函数映射到`Access`对象的可迭代序列。

+   将`access_detail_iter（access-iter（local_gzip（pattern）））`函数重构为一个单独的可迭代对象。然后我们将对`AccessDetail`对象的可迭代序列进行`path_filter（）`函数和更高级别的过滤和减少映射。

+   我们还可以将下层解析重构为与更高级别分析分开的函数。我们可以将分析过滤器和减少映射到下层解析的输出。

所有这些都是对示例应用程序相对简单的重组。使用函数式编程技术的好处在于整个过程的每个部分都可以定义为一个映射。这使得考虑不同的架构来找到最佳设计变得实际可行。

在这种情况下，我们需要将 I/O 处理分配到尽可能多的 CPU 或核心。大多数潜在的重构将在父进程中执行所有 I/O；这些重构只会将计算分配给多个并发进程，但效益很小。然后，我们希望专注于映射，因为这些可以将 I/O 分配到尽可能多的核心。

最小化从一个进程传递到另一个进程的数据量通常很重要。在这个例子中，我们只向每个工作进程提供了短文件名字符串。结果的`Counter`对象比每个日志文件中 10MB 压缩详细数据要小得多。我们可以通过消除仅出现一次的项目来进一步减少每个`Counter`对象的大小；或者我们可以将我们的应用程序限制为仅使用最受欢迎的 20 个项目。

我们可以自由重新组织这个应用程序的设计，并不意味着我们应该重新组织设计。我们可以运行一些基准实验来确认我们的怀疑，即日志文件解析主要受到读取文件所需的时间的影响。

# 总结

在本章中，我们已经看到了支持多个数据并发处理的两种方法：

+   `multiprocessing`模块：具体来说，`Pool`类和可用于工作池的各种映射。

+   `concurrent.futures`模块：具体来说，`ProcessPoolExecutor`和`ThreadPoolExecutor`类。这些类还支持一种映射，可以在线程或进程之间分配工作。

我们还注意到了一些似乎不太适合函数式编程的替代方案。`multiprocessing`模块还有许多其他特性，但它们与函数式设计不太匹配。同样，`threading`和`queue`模块可以用于构建多线程应用，但这些特性与函数式程序不太匹配。

在下一章中，我们将介绍`operator`模块。这可以用来简化某些类型的算法。我们可以使用内置的操作函数，而不是定义 lambda 形式。我们还将探讨一些灵活决策设计的技巧，并允许表达式以非严格顺序进行评估。


# 第十三章.条件表达式和操作模块

函数式编程强调操作的惰性或非严格顺序。其思想是允许编译器或运行时尽可能少地计算答案。Python 倾向于对评估施加严格顺序。

例如，我们使用了 Python 的`if`、`elif`和`else`语句。它们清晰易读，但暗示了对条件评估的严格顺序。在这里，我们可以在一定程度上摆脱严格的顺序，并开发一种有限的非严格条件语句。目前还不清楚这是否有帮助，但它展示了一些以函数式风格表达算法的替代方式。

本章的第一部分将探讨我们可以实现非严格评估的方法。这是一个有趣的工具，因为它可以导致性能优化。

在前几章中，我们看了一些高阶函数。在某些情况下，我们使用这些高阶函数将相当复杂的函数应用于数据集合。在其他情况下，我们将简单的函数应用于数据集合。

实际上，在许多情况下，我们编写了微小的`lambda`对象来将单个 Python 运算符应用于函数。例如，我们可以使用以下内容来定义`prod()`函数：

```py
>>> prod= lambda iterable: functools.reduce(lambda x, y: x*y, iterable, 1)
>>> prod((1,2,3))
6

```

使用`lambda x,y: x*y`参数似乎有点冗长，用于乘法。毕竟，我们只想使用乘法运算符`*`。我们能简化语法吗？答案是肯定的；`operator`模块为我们提供了内置运算符的定义。

`operator`模块的一些特性导致了一些简化和潜在的澄清，以创建高阶函数。尽管在概念上很重要，但`operator`模块并不像最初看起来那么有趣。

# 评估条件表达式

Python 对表达式施加了相对严格的顺序；显著的例外是短路运算符`and`和`or`。它对语句评估施加了非常严格的顺序。这使得寻找避免这种严格评估的不同方式变得具有挑战性。

事实证明，评估条件表达式是我们可以尝试非严格顺序语句的一种方式。我们将研究一些重构`if`和`else`语句的方法，以探索 Python 中这种非严格评估的方面。

Python 的`if`、`elif`和`else`语句是按从头到尾的严格顺序进行评估的。理想情况下，一种语言可能会放松这个规则，以便优化编译器可以找到更快的顺序来评估条件表达式。这个想法是让我们按照读者理解的顺序编写表达式，即使实际的评估顺序是非严格的。

缺乏优化编译器，这个概念对 Python 来说有点牵强。尽管如此，我们确实有替代的方式来表达涉及函数评估而不是执行命令式语句的条件。这可以让您在运行时进行一些重新排列。

Python 确实有条件`if`和`else`表达式。当只有一个条件时，可以使用这种表达式形式。然而，当有多个条件时，可能会变得非常复杂：我们必须小心地嵌套子表达式。我们可能最终会得到一个命令，如下所示，这是相当难以理解的：

```py
(x if n==1 else (y if n==2 else z))

```

我们可以使用字典键和`lambda`对象来创建一组非常复杂的条件。以下是一种表达阶乘函数的方法：

```py
def fact(n):
 **f= { n == 0: lambda n: 1,
 **n == 1: lambda n: 1,
 **n == 2: lambda n: 2,
 **n > 2: lambda n: fact(n-1)*n }[True]
 **return f(n)

```

这将传统的`if`、`elif`、`elif`和`else`语句序列重写为单个表达式。我们将其分解为两个步骤，以使发生的事情稍微清晰一些。

在第一步中，我们将评估各种条件。给定条件中的一个将评估为`True`，其他条件应该都评估为`False`。生成的字典中将有两个项目：一个具有`True`键和一个`lambda`对象，另一个具有`False`键和一个`lambda`对象。我们将选择`True`项目并将其分配给变量`f`。

我们在此映射中使用 lambda 作为值，以便在构建字典时不评估值表达式。我们只想评估一个值表达式。`return`语句评估与`True`条件相关联的一个表达式。

## 利用非严格的字典规则

字典的键没有顺序。如果我们尝试创建一个具有共同键值的多个项目的字典，那么在生成的`dict`对象中只会有一个项目。不清楚哪个重复的键值将被保留，也不重要。

这是一个明确不关心哪个重复键被保留的情况。我们将看一个`max()`函数的退化情况，它只是选择两个值中的最大值：

```py
def max(a, b):
 **f = {a >= b: lambda: a, b >= a: lambda: b}[True]
 **return f()

```

在`a == b`的情况下，字典中的两个项目都将具有`True`条件的键。实际上只有两者中的一个会被保留。由于答案是相同的，保留哪个并将哪个视为重复并覆盖并不重要。

## 过滤真条件表达式

我们有多种方法来确定哪个表达式是`True`。在前面的示例中，我们将键加载到字典中。由于字典的加载方式，只有一个值将保留具有`True`键的值。

这是使用`filter()`函数编写的这个主题的另一个变体：

```py
def semifact(n):
 **alternatives= [(n == 0, lambda n: 1),
 **(n == 1, lambda n: 1),
 **(n == 2, lambda n: 2),
 **(n > 2, lambda n: semifact(n-2)*n)]
 **c, f= next(filter(itemgetter(0), alternatives))
 **return f(n)

```

我们将替代方案定义为`condition`和`function`对的序列。当我们使用`filter()`函数并使用`itemgetter(0)`参数时，我们将选择那些具有`True`条件的对。在那些`True`的对中，我们将选择`filter()`函数创建的可迭代对象中的第一个项目。所选条件分配给变量`c`，所选函数分配给变量`f`。我们可以忽略条件（它将是`True`），并且可以评估`filter()`函数。

与前面的示例一样，我们使用 lambda 来推迟对函数的评估，直到条件被评估之后。

这个`semifact()`函数也被称为**双阶乘**。半阶乘的定义类似于阶乘的定义。重要的区别是它是交替数字的乘积而不是所有数字的乘积。例如，看一下以下公式：

![过滤真条件表达式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_13_01.jpg)和![过滤真条件表达式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_13_02.jpg)

# 使用`operator`模块而不是 lambda

在使用`max()`、`min()`和`sorted()`函数时，我们有一个可选的`key=`参数。作为参数值提供的函数修改了高阶函数的行为。在许多情况下，我们使用简单的 lambda 形式来从元组中选择项目。以下是我们严重依赖的两个示例：

```py
fst = lambda x: x[0]
snd = lambda x: x[1]

```

这些与其他函数式编程语言中的内置函数相匹配。

我们实际上不需要编写这些函数。`operator`模块中有一个版本描述了这些函数。

以下是一些我们可以使用的示例数据：

```py
>>> year_cheese = [(2000, 29.87), (2001, 30.12), (2002, 30.6), (2003, 30.66), (2004, 31.33), (2005, 32.62), (2006, 32.73), (2007, 33.5), (2008, 32.84), (2009, 33.02), (2010, 32.92)]

```

这是年度奶酪消费量。我们在第二章和第九章中使用了这个示例，*介绍一些功能特性*和*更多的迭代工具技术*。

我们可以使用以下命令找到具有最小奶酪的数据点：

```py
>>> min(year_cheese, key=snd)
(2000, 29.87)

```

`operator`模块为我们提供了从元组中选择特定元素的替代方法。这样可以避免使用`lambda`变量来选择第二个项目。

我们可以使用`itemgetter(0)`和`itemgetter(1)`参数，而不是定义自己的`fst()`和`snd()`函数，如下所示：

```py
>>> from operator import *
>>> max( year_cheese, key=itemgetter(1))
(2007, 33.5)

```

`itemgetter()`函数依赖于特殊方法`__getitem__()`，根据它们的索引位置从元组（或列表）中挑选项目。

## 在使用高阶函数时获取命名属性

让我们来看一下稍微不同的数据集合。假设我们使用的是命名元组而不是匿名元组。我们有两种方法来定位奶酪消耗量的范围，如下所示：

```py
>>> from collections import namedtuple
>>> YearCheese = namedtuple("YearCheese", ("year", "cheese"))
>>> year_cheese_2 = list(YearCheese(*yc) for yc in year_cheese)
>>> year_cheese_2
[YearCheese(year=2000, cheese=29.87), YearCheese(year=2001, cheese=30.12), YearCheese(year=2002, cheese=30.6), YearCheese(year=2003, cheese=30.66), YearCheese(year=2004, cheese=31.33), YearCheese(year=2005, cheese=32.62), YearCheese(year=2006, cheese=32.73), YearCheese(year=2007, cheese=33.5), YearCheese(year=2008, cheese=32.84), YearCheese(year=2009, cheese=33.02), YearCheese(year=2010, cheese=32.92)]

```

我们可以使用 lambda 形式，也可以使用`attrgetter()`函数，如下所示：

```py
>>> min(year_cheese_2, key=attrgetter('cheese'))
YearCheese(year=2000, cheese=29.87)
>>> max(year_cheese_2, key=lambda x: x.cheese)
YearCheese(year=2007, cheese=33.5)

```

这里重要的是，使用`lambda`对象时，属性名称在代码中表示为一个标记。而使用`attrgetter()`函数时，属性名称是一个字符串。这可以是一个参数，这使我们可以相当灵活。

# 使用运算符的星形映射

`itertools.starmap()`函数可以应用于运算符和一系列值对。这里有一个例子：

```py
>>> d= starmap(pow, zip_longest([], range(4), fillvalue=60))

```

`itertools.zip_longest()`函数将创建一对序列，如下所示：

```py
[(60, 0), (60, 1), (60, 2), (60, 3)]

```

它之所以这样做，是因为我们提供了两个序列：`[]`括号和`range(4)`参数。当较短的序列用尽数据时，`fillvalue`参数将被使用。

当我们使用`starmap()`函数时，每对都成为给定函数的参数。在这种情况下，我们提供了`operator.pow()`函数，即`**`运算符。我们计算了`[60**0, 60**1, 60**2, 60**3]`的值。变量`d`的值是`[1, 60, 3600, 216000]`。

`starmap()`函数在我们有一系列元组时非常有用。`map(f, x, y)`和`starmap(f, zip(x,y))`函数之间有一个整洁的等价关系。

这是`itertools.starmap()`函数的前面例子的延续：

```py
>>> p = (3, 8, 29, 44)
>>> pi = sum(starmap(truediv, zip(p, d)))

```

我们将两个四个值的序列压缩在一起。我们使用了`starmap()`函数和`operator.truediv()`函数，即`/`运算符。这将计算出一个我们求和的分数序列。总和实际上是![Starmapping with operators](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_13_03.jpg)的近似值。

这是一个更简单的版本，它使用`map(f, x, y)`函数，而不是`starmap(f, zip(x,y))`函数：

```py
>>> pi = sum(map(truediv, p, d))
>>> pi
3.1415925925925925

```

在这个例子中，我们有效地将一个基数为`60`的分数值转换为基数为`10`。变量`d`中的值是适当的分母。可以使用类似本节前面解释的技术来转换其他基数。

一些近似涉及潜在无限的和（或积）。可以使用本节前面解释的类似技术来评估这些近似。我们可以利用`itertools`模块中的`count()`函数来生成近似中任意数量的项。然后我们可以使用`takewhile()`函数，只使用对答案有用精度水平的值。

这是一个潜在无限序列的例子：

```py
>>> num= map(fact, count())
>>> den= map(semifact, (2*n+1 for n in count()))
>>> terms= takewhile(lambda t: t > 1E-10, map(truediv, num, den))
>>> 2*sum(terms)
3.1415926533011587

```

`num`变量是一个基于阶乘函数的潜在无限序列的分子。`den`变量是一个基于半阶乘（有时称为双阶乘）函数的潜在无限序列的分母。

为了创建项，我们使用`map()`函数将`operators.truediv()`函数（即`/`运算符）应用于每对值。我们将其包装在`takewhile()`函数中，这样我们只取值，而分数大于某个相对较小的值；在这种情况下，![Starmapping with operators](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_13_05.jpg)。

这是基于 4 arctan(1)=![Starmapping with operators](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_13_03.jpg)的级数展开。展开式是![Starmapping with operators](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_13_04.jpg)

系列展开主题的一个有趣变化是用`fractions.Fraction()`函数替换`operator.truediv()`函数。这将创建精确的有理值，不会受到浮点近似的限制。

`operators`模块中包含所有 Python 运算符。这包括所有位操作运算符以及比较运算符。在某些情况下，生成器表达式可能比看起来相当复杂的`starmap()`函数与表示运算符的函数更简洁或更表达。

问题在于`operator`模块只提供了一个运算符，基本上是`lambda`的简写。我们可以使用`operator.add`方法代替`add=lambda a,b: a+b`方法。如果我们有更复杂的表达式，那么`lambda`对象是编写它们的唯一方法。

# 使用运算符进行缩减

我们将看一种我们可能尝试使用运算符定义的方式。我们可以将它们与内置的`functools.reduce()`函数一起使用。例如，`sum()`函数可以定义如下：

```py
sum= functools.partial(functools.reduce, operator.add)

```

我们创建了一个部分求值版本的`reduce()`函数，并提供了第一个参数。在这种情况下，它是`+`运算符，通过`operator.add()`函数实现。

如果我们需要一个类似的计算乘积的函数，我们可以这样定义：

```py
prod= functools.partial(functools.reduce, operator.mul)

```

这遵循了前面示例中所示的模式。我们有一个部分求值的`reduce()`函数，第一个参数是`*`运算符，由`operator.mul()`函数实现。

目前尚不清楚我们是否可以对其他运算符进行类似的操作。我们可能也能够找到`operator.concat()`函数以及`operator.and()`和`operator.or()`函数的用途。

### 注意

`and()`和`or()`函数是位运算符`&`和`/`。如果我们想要正确的布尔运算符，我们必须使用`all()`和`any()`函数，而不是`reduce()`函数。

一旦我们有了`prod()`函数，这意味着阶乘可以定义如下：

```py
fact= lambda n: 1 if n < 2 else n*prod(range(1,n))

```

这有一个简洁的优势：它提供了一个阶乘的单行定义。它还有一个优势，不依赖于递归，但有可能触发 Python 的堆栈限制。

目前尚不清楚这是否比我们在 Python 中拥有的许多替代方案具有明显优势。从原始部分构建复杂函数的概念，如`partial()`和`reduce()`函数以及`operator`模块非常优雅。然而，在大多数情况下，`operator`模块中的简单函数并不是很有用；我们几乎总是希望使用更复杂的 lambda。

# 总结

在本章中，我们探讨了替代`if`、`elif`和`else`语句序列的方法。理想情况下，使用条件表达式可以进行一些优化。从实用的角度来看，Python 并不进行优化，因此处理条件的更奇特方式几乎没有实质性的好处。

我们还看了如何使用`operator`模块与`max()`、`min()`、`sorted()`和`reduce()`等高阶函数。使用运算符可以避免我们创建许多小的 lambda 函数。

在下一章中，我们将研究`PyMonad`库，直接在 Python 中表达函数式编程概念。通常情况下，我们不需要单子，因为 Python 在底层是一种命令式编程语言。

一些算法可能通过单子比通过有状态的变量赋值更清晰地表达。我们将看一个例子，其中单子导致对一组相当复杂的规则进行简洁的表达。最重要的是，`operator`模块展示了许多函数式编程技术。


# 第十四章：PyMonad 库

单子允许我们在一个否则宽松的语言中对表达式的评估施加顺序。我们可以使用单子来坚持要求像*a + b + c*这样的表达式按从左到右的顺序进行评估。一般来说，单子似乎没有什么意义。然而，当我们希望文件按特定顺序读取或写入其内容时，单子是一种确保`read()`和`write()`函数按特定顺序进行评估的便捷方式。

宽松且具有优化编译器的语言受益于单子，以对表达式的评估施加顺序。Python 在大多数情况下是严格的，不进行优化。我们对单子几乎没有实际用途。

然而，PyMonad 模块不仅仅是单子。它具有许多具有独特实现的函数式编程特性。在某些情况下，PyMonad 模块可以导致比仅使用标准库模块编写的程序更简洁和表达力更强。

# 下载和安装

PyMonad 模块可在**Python Package Index**（**PyPi**）上找到。为了将 PyMonad 添加到您的环境中，您需要使用 pip 或 Easy Install。以下是一些典型情况：

+   如果您使用的是 Python 3.4 或更高版本，您将拥有这两个安装包工具

+   如果您使用的是 Python 3.x，可能已经有了其中一个必要的安装程序，因为您已经添加了包

+   如果你使用的是 Python 2.x，你应该考虑升级到 Python 3.4

+   如果你没有 pip 或 Easy Install，你需要先安装它们；考虑升级到 Python 3.4 以获取这些安装工具

访问[`pypi.python.org/pypi/PyMonad/`](https://pypi.python.org/pypi/PyMonad/)获取更多信息。

对于 Mac OS 和 Linux 开发人员，必须使用`sudo`命令运行命令`pip install PyMonad`或`easy_install-3.3 pymonad`。当运行诸如`sudo easy_install-3.3 pymonad`的命令时，系统会提示您输入密码，以确保您具有进行安装所需的管理权限。对于 Windows 开发人员，`sudo`命令不相关，但您需要具有管理权限。

安装了`pymonad`包后，可以使用以下命令进行确认：

```py
>>> import pymonad
>>> help(pymonad)

```

这将显示`docstring`模块，并确认事情确实安装正确。

# 函数组合和柯里化

一些函数式语言通过将多参数函数语法转换为一组单参数函数来工作。这个过程称为**柯里化**——它是以逻辑学家 Haskell Curry 的名字命名的，他从早期概念中发展出了这个理论。

柯里化是一种将多参数函数转换为高阶单参数函数的技术。在简单情况下，我们有一个函数![函数组合和柯里化](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_01.jpg)；给定两个参数*x*和*y*，这将返回一些结果值*z*。我们可以将其柯里化为两个函数：![函数组合和柯里化](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_02.jpg)和![函数组合和柯里化](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_03.jpg)。给定第一个参数值*x*，函数返回一个新的单参数函数，![函数组合和柯里化](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_04.jpg)返回一个新的单参数函数，![函数组合和柯里化](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_09.jpg)。第二个函数可以给定一个参数*y*，并返回结果值*z*。

我们可以在 Python 中评估柯里化函数，如下所示：`f_c(2)(3)`。我们将柯里化函数应用于第一个参数值`2`，创建一个新函数。然后，我们将该新函数应用于第二个参数值`3`。

这适用于任何复杂度的函数。如果我们从一个函数开始![Functional composition and currying](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_10.jpg)，我们将其柯里化为一个函数![Functional composition and currying](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_11.jpg)。这是递归完成的。首先，![Functional composition and currying](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_12.jpg)函数返回一个带有 b 和 c 参数的新函数，![Functional composition and currying](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_13.jpg)。然后，我们可以对返回的两参数函数进行柯里化，创建![Functional composition and currying](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_14.jpg)。

我们可以使用`g_c(1)(2)(3)`来评估这个柯里化函数。当我们将![Functional composition and currying](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_15.jpg)应用于参数 1 时，我们得到一个函数；当我们将返回的函数应用于 2 时，我们得到另一个函数。当我们将最终函数应用于 3 时，我们得到预期的结果。显然，正式的语法很臃肿，因此我们使用一些语法糖将`g_c(1)(2)(3)`减少到更容易接受的形式，如`g(1,2,3)`。

让我们以 Python 中的一个具体例子为例，例如，我们有一个如下所示的函数：

```py
from pymonad import curry
@curry
def systolic_bp(bmi, age, gender_male, treatment):
 **return 68.15+0.58*bmi+0.65*age+0.94*gender_male+6.44*treatment

```

这是一个基于多元回归的简单模型，用于预测收缩压。这从**体重指数**（**BMI**）、年龄、性别（1 表示男性）和先前治疗历史（1 表示先前治疗）预测血压。有关模型及其推导方式的更多信息，请访问[`sphweb.bumc.bu.edu/otlt/MPH-Modules/BS/BS704_Multivariable/BS704_Multivariable7.html`](http://sphweb.bumc.bu.edu/otlt/MPH-Modules/BS/BS704_Multivariable/BS704_Multivariable7.html)。

我们可以使用带有所有四个参数的`systolic_bp()`函数，如下所示：

```py
>>> systolic_bp(25, 50, 1, 0)
116.09
>>> systolic_bp(25, 50, 0, 1)
121.59

```

一个 BMI 为 25、年龄为 50、没有先前治疗历史的男性可能会有 116 的血压。第二个例子展示了一个类似的女性，她有治疗史，可能会有 121 的血压。

因为我们使用了`@curry`装饰器，我们可以创建类似于部分应用函数的中间结果。看一下以下命令片段：

```py
>>> treated= systolic_bp(25, 50, 0)
>>> treated(0)
115.15
>>> treated(1)
121.59

```

在前面的例子中，我们评估了`systolic_bp(25, 50, 0)`方法来创建一个柯里化函数，并将其分配给变量`treatment`。BMI、年龄和性别值通常不会改变。我们现在可以将新函数`treatment`应用于剩余的参数，根据患者的历史得到不同的血压期望。

在某些方面，这与`functools.partial()`函数类似。重要的区别在于柯里化创建了一个可以以多种方式工作的函数。`functools.partial()`函数创建了一个更专门的函数，只能与给定的一组绑定值一起使用。

这是创建一些额外柯里化函数的示例：

```py
>>> g_t= systolic_bp(25, 50)
>>> g_t(1, 0)
116.09
>>> g_t(0, 1)
121.59

```

这是基于我们初始模型的基于性别的治疗函数。我们必须提供性别和治疗值才能从模型中得到最终值。

## 使用柯里化的高阶函数

虽然柯里化在使用普通函数时很容易进行可视化，但当我们将柯里化应用于高阶函数时，其真正价值就显现出来了。在理想情况下，`functools.reduce()`函数将是“可柯里化的”，这样我们就可以这样做：

```py
sum= reduce(operator.add)
prod= reduce(operator.mul)

```

然而，`pymonad`库无法对`reduce()`函数进行柯里化，因此这实际上不起作用。然而，如果我们定义自己的`reduce()`函数，我们可以像之前展示的那样对其进行柯里化。以下是一个可以像之前展示的那样使用的自制`reduce()`函数的示例：

```py
import collections.abc
from pymonad import curry
@curry
def myreduce(function, iterable_or_sequence):
 **if isinstance(iterable_or_sequence, collections.abc.Sequence):
 **iterator= iter(iterable_or_sequence)
 **else:
 **iterator= iterable_or_sequence
 **s = next(iterator)
 **for v in iterator:
 **s = function(s,v)
 **return s

```

`myreduce()`函数将表现得像内置的`reduce()`函数。`myreduce()`函数适用于可迭代对象或序列对象。给定一个序列，我们将创建一个迭代器；给定一个可迭代对象，我们将简单地使用它。我们将结果初始化为迭代器中的第一项。我们将函数应用于正在进行的总和（或乘积）和每个后续项。

### 注意

也可以包装内置的`reduce()`函数以创建一个可柯里化的版本。这只需要两行代码；这是留给你的一个练习。

由于`myreduce()`函数是一个柯里化函数，我们现在可以使用它来基于我们的高阶函数`myreduce()`创建函数：

```py
>>> from operator import *
>>> sum= myreduce(add)
>>> sum([1,2,3])
6
>>> max= myreduce(lambda x,y: x if x > y else y)
>>> max([2,5,3])
5

```

我们使用柯里化的 reduce 应用于`add`运算符定义了我们自己版本的`sum()`函数。我们还使用`lambda`对象定义了我们自己版本的默认`max()`函数，它选择两个值中较大的一个。

这种方式不能轻松地创建`max()`函数的更一般形式，因为柯里化侧重于位置参数。尝试使用`key=`关键字参数会增加太多复杂性，使得这种技术无法朝着我们简洁和表达式丰富的函数程序的总体目标发展。

要创建`max()`函数的更一般化版本，我们需要跳出`key=`关键字参数范例，这些函数如`max()`、`min()`和`sorted()`依赖于。我们必须接受高阶函数作为第一个参数，就像`filter()`、`map()`和`reduce()`函数一样。我们还可以创建我们自己的更一致的高阶柯里化函数库。这些函数将完全依赖于位置参数。高阶函数将首先提供，以便我们自己的柯里化`max(function, iterable)`方法遵循`map()`、`filter()`和`functools.reduce()`函数设定的模式。

## 艰难的柯里化

我们可以手动创建柯里化函数，而不使用`pymonad`库中的装饰器；其中一种方法是执行以下命令：

```py
def f(x, *args):
 **def f1(y, *args):
 **def f2(z):
 **return (x+y)*z
 **if args:
 **return f2(*args)
 **return f2
 **if args:
 **return f1(*args)
 **return f1

```

这将一个函数柯里化成一个函数`f(x)`，它返回一个函数。在概念上，我们然后对中间函数进行柯里化，创建`f1(y)`和`f2(z)`函数。

当我们评估`f(x)`函数时，我们将得到一个新的函数`f1`作为结果。如果提供了额外的参数，这些参数将传递给`f1`函数进行评估，要么产生最终值，要么产生另一个函数。

显然，这可能会出现错误。然而，它确实有助于定义柯里化的真正含义以及它在 Python 中的实现方式。

# 函数组合和 PyMonad 乘法运算符

柯里化函数的一个重要价值在于能够通过函数组合来结合它们。我们在第五章和第十一章中讨论了函数组合，*高阶函数*和*装饰器设计技术*。

当我们创建了一个柯里化函数，我们可以轻松地执行函数组合，创建一个新的、更复杂的柯里化函数。在这种情况下，PyMonad 包为组合两个函数定义了`*`运算符。为了展示这是如何工作的，我们将定义两个可以组合的柯里化函数。首先，我们将定义一个计算乘积的函数，然后我们将定义一个计算特定值范围的函数。

这是我们计算乘积的第一个函数：

```py
import  operator
prod = myreduce(operator.mul)

```

这是基于我们之前定义的柯里化`myreduce()`函数。它使用`operator.mul()`函数来计算可迭代对象的“乘法减少”：我们可以称一个乘积为序列的 a 次减少。

这是我们的第二个柯里化函数，它将产生一系列值：

```py
@curry
def alt_range(n):
 **if n == 0: return range(1,2) # Only 1
 **if n % 2 == 0:
 **return range(2,n+1,2)
 **else:
 **return range(1,n+1,2)

```

`alt_range()`函数的结果将是偶数值或奇数值。如果`n`是奇数，它将只有值直到（包括）`n`。如果`n`是偶数，它将只有偶数值直到`n`。这些序列对于实现半阶乘或双阶乘函数很重要。

以下是如何将 `prod()` 和 `alt_range()` 函数组合成一个新的柯里化函数：

```py
>>> semi_fact= prod * alt_range
>>> semi_fact(9)
945

```

这里的 PyMonad `*` 运算符将两个函数组合成一个名为 `semi_fact` 的复合函数。`alt_range()` 函数被应用到参数上。然后，`prod()` 函数被应用到 `alt_range` 函数的结果上。

通过在 Python 中手动执行这些操作，实际上是在创建一个新的 `lambda` 对象：

```py
semi_fact= lambda x: prod(alt_range(x))

```

柯里化函数的组合涉及的语法比创建一个新的 `lambda` 对象要少一些。

理想情况下，我们希望像这样使用函数组合和柯里化函数：

```py
sumwhile= sum * takewhile(lambda x: x > 1E-7)

```

这将定义一个可以处理无限序列的 `sum()` 函数版本，在达到阈值时停止生成值。这似乎行不通，因为 `pymonad` 库似乎无法像处理内部的 `List` 对象一样处理无限可迭代对象。

# 函子和应用函子

函子的概念是简单数据的函数表示。数字 3.14 的函子版本是一个零参数函数，返回这个值。考虑以下示例：

```py
pi= lambda : 3.14

```

我们创建了一个具有简单值的零参数 `lambda` 对象。

当我们将柯里化函数应用于函子时，我们正在创建一个新的柯里化函子。这通过使用函数来表示参数、值和函数本身来概括了“应用函数到参数以获得值”的概念。

一旦我们的程序中的所有内容都是函数，那么所有处理都只是函数组合的变体。柯里化函数的参数和结果可以是函子。在某个时候，我们将对一个 `functor` 对象应用 `getValue()` 方法，以获得一个可以在非柯里化代码中使用的 Python 友好的简单类型。

由于我们所做的只是函数组合，直到我们使用 `getValue()` 方法要求值时才需要进行计算。我们的程序不是执行大量计算，而是定义了一个复杂的对象，可以在需要时产生值。原则上，这种组合可以通过聪明的编译器或运行时系统进行优化。

当我们将一个函数应用到一个 `functor` 对象时，我们将使用类似于 `map()` 的方法，该方法实现为 `*` 运算符。我们可以将 `function * functor` 或 `map(function, functor)` 方法看作是理解函子在表达式中扮演的角色的一种方式。

为了礼貌地处理具有多个参数的函数，我们将使用 `&` 运算符构建复合函子。我们经常会看到 `functor & functor` 方法来构建一个 `functor` 对象。

我们可以用 `Maybe` 函子的子类来包装 Python 的简单类型。`Maybe` 函子很有趣，因为它为我们提供了一种优雅地处理缺失数据的方法。我们在第十一章中使用的方法是装饰内置函数，使其具有 `None` 意识。PyMonad 库采用的方法是装饰数据，使其能够优雅地拒绝被操作。

`Maybe` 函子有两个子类：

+   `Nothing`

+   `Just(some simple value)`

我们使用 `Nothing` 作为简单 Python 值 `None` 的替代。这是我们表示缺失数据的方式。我们使用 `Just(some simple value)` 来包装所有其他 Python 对象。这些函子是常量值的函数式表示。

我们可以使用这些 `Maybe` 对象的柯里化函数来优雅地处理缺失的数据。以下是一个简短的示例：

```py
>>> x1= systolic_bp * Just(25) & Just(50) & Just(1) & Just(0)
>>> x1.getValue()
116.09
>>> x2= systolic_bp * Just(25) & Just(50) & Just(1) & Nothing
>>> x2.getValue() is None
True

```

`*` 运算符是函数组合：我们正在将 `systolic_bp()` 函数与一个参数复合。`&` 运算符构建一个复合函子，可以作为多参数柯里化函数的参数传递。

这向我们表明，我们得到了一个答案，而不是`TypeError`异常。在处理大型复杂数据集时，数据可能缺失或无效，这非常方便。这比不得不装饰所有函数以使它们具有`None`感知性要好得多。

这对于柯里化函数非常有效。我们不能在未柯里化的 Python 代码中操作`Maybe`函子，因为函子的方法非常少。

### 注意

我们必须使用`getValue()`方法来提取未柯里化的 Python 代码的简单 Python 值。

## 使用惰性 List()函子

`List()`函子一开始可能会让人困惑。它非常懒惰，不像 Python 的内置`list`类型。当我们评估内置`list(range(10))`方法时，`list()`函数将评估`range()`对象以创建一个包含 10 个项目的列表。然而，PyMonad 的`List()`函子太懒惰了，甚至不会进行这种评估。

这是比较：

```py
>>> list(range(10))
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
>>> List(range(10))
[range(0, 10)]

```

`List()`函子没有评估`range()`对象，它只是保留了它而没有被评估。`PyMonad.List()`函数用于收集函数而不对其进行评估。我们可以根据需要稍后对其进行评估：

```py
>>> x= List(range(10))
>>> x
[range(0, 10)]
>>> list(x[0])
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

```

我们创建了一个带有`range()`对象的惰性`List`对象。然后我们提取并评估了该列表中位置`0`处的`range()`对象。

`List`对象不会评估生成器函数或`range()`对象；它将任何可迭代参数视为单个迭代器对象。但是，我们可以使用`*`运算符来展开生成器或`range()`对象的值。

### 注意

请注意，`*`运算符有几种含义：它是内置的数学乘法运算符，是由 PyMonad 定义的函数组合运算符，以及在调用函数时用于将单个序列对象绑定为函数的所有位置参数的内置修饰符。我们将使用`*`运算符的第三个含义来将一个序列分配给多个位置参数。

这是`range()`函数的柯里化版本。它的下限是 1 而不是 0。对于某些数学工作很方便，因为它允许我们避免内置`range()`函数中的位置参数的复杂性。

```py
@curry
def range1n(n):
 **if n == 0: return range(1,2) # Only 1
 **return range(1,n+1)

```

我们简单地包装了内置的`range()`函数，使其可以由 PyMonad 包进行柯里化。

由于`List`对象是一个函子，我们可以将函数映射到`List`对象。该函数应用于`List`对象中的每个项目。这是一个例子：

```py
>>> fact= prod * range1n
>>> seq1 = List(*range(20))
>>> f1 = fact * seq1
>>> f1[:10]
[1, 1, 2, 6, 24, 120, 720, 5040, 40320, 362880]

```

我们定义了一个复合函数`fact()`，它是从先前显示的`prod()`和`range1n()`函数构建的。这是阶乘函数，![Using the lazy List() functor](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_16.jpg)。我们创建了一个`List()`函子`seq1`，它是一个包含 20 个值的序列。我们将`fact()`函数映射到`seq1`函子，从而创建了一个阶乘值的序列`f1`。我们之前展示了其中的前 10 个值。

### 注意

函数的组合和函数与函子的组合之间存在相似之处。`prod*range1n`和`fact*seq1`都使用函数组合：一个组合明显是函数的东西，另一个组合是函数和函子。

这是另一个我们将用来扩展此示例的小函数：

```py
@curry
def n21(n):
 **return 2*n+1

```

这个小的`n21()`函数执行简单的计算。但是，它是柯里化的，因此我们可以将其应用于像`List()`函数这样的函子。这是前面示例的下一部分：

```py
>>> semi_fact= prod * alt_range
>>> f2 = semi_fact * n21 * seq1
>>> f2[:10]
[1, 3, 15, 105, 945, 10395, 135135, 2027025, 34459425, 654729075]

```

我们从先前显示的`prod()`和`alt_range()`函数定义了一个复合函数。函数`f2`是半阶乘或双阶乘，![Using the lazy List() functor](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_07.jpg)。函数`f2`的值是通过将我们的小`n21()`函数应用于`seq1`序列来构建的。这创建了一个新序列。然后我们将`semi_fact`函数应用于这个新序列，以创建一个![Using the lazy List() functor](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_17.jpg)值的序列，与![Using the lazy List() functor](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_16.jpg)值的序列相对应。

现在我们可以将`/`运算符映射到`map()`和`operator.truediv`并行函子：

```py
>>> 2*sum(map(operator.truediv, f1, f2))
3.1415919276751456

```

`map()`函数将给定的运算符应用于两个函子，产生一系列分数，我们可以将它们相加。

### 注意

`f1 & f2`方法将创建两个`List`对象的所有值的组合。这是`List`对象的一个重要特性：它们可以很容易地枚举所有的组合，允许一个简单的算法计算所有的替代方案，并过滤适当的子集。这是我们不想要的；这就是为什么我们使用`map()`函数而不是`operator.truediv * f1 & f2`方法。

我们使用了一些函数组合技术和一个函子类定义来定义了一个相当复杂的计算。这是这个计算的完整定义：

![使用惰性 List()函子](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_14_08.jpg)

理想情况下，我们不希望使用固定大小的`List`对象。我们更希望有一个惰性的、潜在无限的整数值序列。然后我们可以使用`sum()`和`takewhile()`函数的柯里化版本来找到序列中值的和，直到这些值对结果没有贡献。这将需要一个更懒惰的`List()`对象的版本，它可以与`itertools.counter()`函数一起使用。在 PyMonad 1.3 中，我们没有这个潜在无限的列表；我们只能使用固定大小的`List()`对象。

# 单子概念、bind()函数和二进制右移运算符

PyMonad 库的名称来自函数式编程概念中的**单子**，即具有严格顺序的函数。函数式编程的基本假设是函数求值是自由的：它可以根据需要进行优化或重新排列。单子提供了一个例外，强加了严格的从左到右的顺序。

正如我们所见，Python 是严格的。它不需要单子。然而，在可以帮助澄清复杂算法的地方，我们仍然可以应用这个概念。

强制求值的技术是单子和将返回一个单子的函数之间的绑定。一个*扁平*表达式将变成嵌套的绑定，不能被优化编译器重新排序。`bind()`函数映射到`>>`运算符，允许我们编写这样的表达式：

```py
Just(some file) >> read header >> read next >> read next

```

前面的表达式将转换为以下形式：

```py
bind(bind(bind(Just(some file), read header), read next), read next)

```

`bind()`函数确保在对这个表达式进行求值时施加了严格的从左到右的顺序。另外，注意前面的表达式是函数组合的一个例子。当我们使用`>>`运算符创建一个单子时，我们正在创建一个复杂的对象，当我们最终使用`getValue()`方法时，它将被求值。

`Just()`子类用于创建一个简单的单子兼容对象，它包装了一个简单的 Python 对象。

单子概念对于表达严格的求值顺序是至关重要的——在一个经过高度优化和宽松的语言中。Python 不需要单子，因为它使用从左到右的严格求值。这使得单子很难展示，因为在 Python 环境中它并没有真正做一些全新的事情。事实上，单子多余地陈述了 Python 遵循的典型严格规则。

在其他语言中，比如 Haskell，单子对于需要严格顺序的文件输入和输出至关重要。Python 的命令式模式很像 Haskell 的`do`块，它有一个隐式的 Haskell `>>=`运算符来强制语句按顺序求值。（PyMonad 使用`bind()`函数和 Haskell 的`>>`运算符来执行 Haskell 的`>>=`操作。）

# 使用单子实现模拟

单子被期望通过一种“管道”传递：一个单子将作为参数传递给一个函数，类似的单子将作为函数的值返回。这些函数必须设计为接受和返回类似的结构。

我们将看一下一个简单的流水线，用于模拟一个过程。这种模拟可能是蒙特卡洛模拟的一个正式部分。我们将直接进行蒙特卡洛模拟，并模拟一个赌场骰子游戏——Craps。这涉及到对相当复杂的模拟进行状态规则的模拟。

涉及了很多非常奇怪的赌博术语。我们无法提供有关各种术语的背景信息。在某些情况下，这些术语的起源已经迷失在历史中。

Craps 涉及有人掷骰子（射击者）和额外的赌徒。游戏的进行方式如下：

第一次投掷被称为“come out”投掷。有三种情况：

1.  如果骰子总数为 7 或 11，则射击者获胜。任何在“pass”线上下注的人都将被支付为赢家，而所有其他赌注都将输掉。游戏结束，射击者可以再玩一次。

1.  如果骰子总数为 2、3 或 12，射击者输掉。任何在“don't pass”线上下注的人都会赢，而所有其他赌注都会输掉。游戏结束，射击者必须将骰子传递给另一个射击者。

1.  任何其他总数（即 4、5、6、8、9 或 10）都会建立一个“point”。游戏从“come out”投掷状态转变为“point”投掷状态。游戏继续进行。

如果已经建立了一个点，每个“point”投掷都会根据三个条件进行评估：

+   如果骰子总数为 7，射击者输掉。实际上，几乎所有的赌注都是输家，除了“don't pass”赌注和一个特殊的提议赌注。由于射击者输了，骰子被传递给另一个射击者。

+   如果骰子总数等于最初的点数，射击者获胜。任何在 pass 线上下注的人都将被支付为赢家，而所有其他赌注都将输掉。游戏结束，射击者可以再玩一次。

+   任何其他总数都会使游戏继续进行，没有解决。

规则涉及一种状态变化。我们可以将其视为一系列操作，而不是状态变化。有一个必须首先使用的函数。之后使用另一个递归函数。这样，它很好地符合单子设计模式。

实际上，赌场在游戏过程中允许进行许多相当复杂的副注。我们可以将这些与游戏的基本规则分开进行评估。其中许多赌注（提议、场地赌注和购买数字）是玩家在游戏的“point roll”阶段简单下注的赌注。还有一个额外的“come”和“don't come”一对赌注，建立了一个嵌套游戏中的点。我们将在以下示例中坚持游戏的基本轮廓。

我们需要一个随机数源：

```py
import random
def rng():
 **return (random.randint(1,6), random.randint(1,6))

```

前面的函数将为我们生成一对骰子。

以下是我们对整个游戏的期望：

```py
def craps():
 **outcome= Just(("",0, []) ) >> come_out_roll(rng) >> point_roll(rng)
 **print(outcome.getValue())

```

我们创建一个初始单子，`Just(("",0, []))`，来定义我们要处理的基本类型。游戏将产生一个三元组，其中包含结果、点数和一系列投掷。最初，它是一个默认的三元组，用于定义我们要处理的类型。

我们将这个单子传递给另外两个函数。这将创建一个结果单子，`outcome`，其中包含游戏的结果。我们使用`>>`运算符按特定顺序连接函数，以便它们按顺序执行。在优化语言中，这将防止表达式被重新排列。

我们使用`getValue()`方法在最后获取单子的值。由于单子对象是惰性的，这个请求会触发对各种单子的评估，以创建所需的输出。

`come_out_roll()`函数将`rng()`函数作为第一个参数柯里化。单子将成为这个函数的第二个参数。`come_out_roll()`函数可以掷骰子，并应用开局规则来确定我们是赢了、输了还是建立了一个点。

`point_roll()`函数也将`rng()`函数作为第一个参数柯里化。单子将成为第二个参数。然后`point_roll()`函数可以掷骰子来查看赌注是否解决。如果赌注没有解决，这个函数将递归操作继续寻找解决方案。

`come_out_roll()`函数看起来像这样：

```py
@curry
def come_out_roll(dice, status):
 **d= dice()
 **if sum(d) in (7, 11):
 **return Just(("win", sum(d), [d]))
 **elif sum(d) in (2, 3, 12):
 **return Just(("lose", sum(d), [d]))
 **else:
 **return Just(("point", sum(d), [d]))

```

我们掷骰子一次，以确定我们是首次投掷赢，输，还是点数。我们返回一个适当的单子值，其中包括结果，点数值和骰子的投掷。立即赢得和立即输掉的点数值并不真正有意义。我们可以合理地在这里返回`0`，因为实际上并没有建立点数。

`point_roll()`函数看起来像这样：

```py
@curry
def point_roll(dice, status):
 **prev, point, so_far = status
 **if prev != "point":
 **return Just(status)
 **d = dice()
 **if sum(d) == 7:
 **return Just(("craps", point, so_far+[d]))
 **elif sum(d) == point:
 **return Just(("win", point, so_far+[d]))
 **else:
 **return Just(("point", point, so_far+[d])) >> point_roll(dice)

```

我们将`status`单子分解为元组的三个单独值。我们可以使用小的`lambda`对象来提取第一个，第二个和第三个值。我们也可以使用`operator.itemgetter()`函数来提取元组的项目。相反，我们使用了多重赋值。

如果没有建立点数，先前的状态将是“赢”或“输”。游戏在一次投掷中解决，这个函数只是返回`status`单子。

如果建立了一个点数，就会掷骰子并应用规则到新的投掷。如果投掷是 7，游戏就输了，并返回最终的单子。如果投掷是点数，游戏就赢了，并返回适当的单子。否则，一个稍微修改的单子被传递给`point_roll()`函数。修改后的`status`单子包括这次投掷在投掷历史中。

典型的输出看起来像这样：

```py
>>> craps()
('craps', 5, [(2, 3), (1, 3), (1, 5), (1, 6)])

```

最终的单子有一个显示结果的字符串。它有建立的点数和骰子投掷的顺序。每个结果都有一个特定的赔付，我们可以用来确定投注者赌注的总波动。

我们可以使用模拟来检查不同的投注策略。我们可能正在寻找一种方法来击败游戏内置的庄家优势。

### 附注

游戏基本规则存在一些小的不对称性。11 作为立即赢家与 3 作为立即输家平衡。2 和 12 也是输家的事实是这个游戏中庄家优势的基础，为 5.5%（*1/18 = 5.5*）。想法是确定哪些额外的投注机会会削弱这个优势。

一些简单的、功能性的设计技术可以构建出许多巧妙的蒙特卡洛模拟。特别是单子可以帮助结构化这些类型的计算，当存在复杂的订单或内部状态时。

# 附加的 PyMonad 功能

PyMonad 的另一个特性是令人困惑地命名为**monoid**。这直接来自数学，它指的是一组具有运算符、单位元素，并且对于该运算符是封闭的数据元素。当我们考虑自然数、`add`运算符和单位元素`0`时，这是一个合适的单子。对于正整数，使用运算符`*`和单位值`1`，我们也有一个单子；使用`|`作为运算符和空字符串作为单位元素的字符串也符合条件。

PyMonad 包括许多预定义的单子类。我们可以扩展这个来添加我们自己的`monoid`类。目的是限制编译器对某些类型的优化。我们还可以使用单子类来创建累积复杂值的数据结构，可能包括以前操作的历史。

其中许多内容提供了对函数式编程的见解。总结文档，这是一个学习函数式编程的简单方法，在可能稍微宽容的环境中。与其学习整个语言和工具集来编译和运行函数式程序，我们可以只是用交互式 Python 进行实验。

从实用的角度来看，我们不需要太多这些功能，因为 Python 已经是有状态的，并且提供了表达式的严格评估。在 Python 中引入有状态的对象或严格排序的评估没有实际理由。我们可以通过将函数式概念与 Python 的命令式实现相结合来编写有用的程序。因此，我们不会深入研究 PyMonad。

# 总结

在本章中，我们看了如何使用 PyMonad 库直接在 Python 中表达一些函数式编程概念。该模块展示了许多重要的函数式编程技术。

我们看了柯里化的概念，这是一种允许组合参数的函数，以创建新函数的方法。柯里化函数还允许我们使用函数组合，从简单的部分创建更复杂的函数。我们看了一下函子，它们包装简单的数据对象，使它们成为可以与函数组合一起使用的函数。

单子是一种在使用优化编译器和惰性评估规则时强加严格评估顺序的方法。在 Python 中，我们没有单子的一个很好的用例，因为 Python 在底层是一种命令式编程语言。在某些情况下，命令式 Python 可能比单子构造更具表现力和简洁。

在下一章中，我们将看看如何应用函数式编程技术来构建 Web 服务应用程序。HTTP 的概念可以总结为`response = httpd(request)`。理想情况下，HTTP 是无状态的，这使其与函数式设计完美匹配。然而，大多数网站将保持状态，使用 cookie 来跟踪会话状态。


# 第十五章：面向 Web 服务的功能性方法

我们将远离探索性数据分析，而是仔细研究 Web 服务器和 Web 服务。在某种程度上，这些都是一系列函数。我们可以将许多函数设计模式应用于呈现 Web 内容的问题上。我们的目标是探索我们可以使用**表述状态转移**（**REST**）的方式。我们希望使用函数设计模式构建 RESTful Web 服务。

我们不需要再发明另一个 Python Web 框架；有很多框架可供选择。我们将避免创建一个庞大的通用解决方案。

我们不想在可用的框架中进行选择。每个框架都有不同的特性和优势。

我们将提出一些可以应用于大多数可用框架的原则。我们应该能够利用功能设计模式来呈现 Web 内容。这将使我们能够构建具有功能设计优势的基于 Web 的应用程序。

例如，当我们查看极大的数据集或极复杂的数据集时，我们可能需要一个支持子集或搜索的 Web 服务。我们可能需要一个能够以各种格式下载子集的网站。在这种情况下，我们可能需要使用功能设计来创建支持这些更复杂要求的 RESTful Web 服务。

最复杂的 Web 应用程序通常具有使网站更易于使用的有状态会话。会话信息通过 HTML 表单提供的数据更新，或者从数据库中获取，或者从以前的交互的缓存中获取。虽然整体交互涉及状态更改，但应用程序编程可以在很大程度上是功能性的。一些应用程序函数在使用请求数据、缓存数据和数据库对象时可能是非严格的。

为了避免特定 Web 框架的细节，我们将专注于**Web 服务器网关接口**（**WSGI**）设计模式。这将使我们能够实现一个简单的 Web 服务器。以下链接提供了大量信息：

[`wsgi.readthedocs.org/en/latest/`](http://wsgi.readthedocs.org/en/latest/)

有关 WSGI 的一些重要背景信息可以在以下链接找到：

[`www.python.org/dev/peps/pep-0333/`](https://www.python.org/dev/peps/pep-0333/)

我们将从 HTTP 协议开始。然后，我们可以考虑诸如 Apache httpd 之类的服务器来实现此协议，并了解`mod_wsgi`如何成为基本服务器的合理扩展。有了这些背景，我们可以看看 WSGI 的功能性质以及如何利用功能设计来实现复杂的 Web 搜索和检索工具。

# HTTP 请求-响应模型

基本的 HTTP 协议理想上是无状态的。用户代理或客户端可以从功能性的角度看待协议。我们可以使用`http.client`或`urllib`库构建客户端。HTTP 用户代理基本上执行类似于以下内容的操作：

```py
import urllib.request
with urllib.request.urlopen(""http://slott-softwarearchitect.blogspot.com"") as response:
 **print(response.read())

```

像**wget**或**curl**这样的程序在命令行上执行此操作；URL 是从参数中获取的。浏览器响应用户的指向和点击执行此操作；URL 是从用户的操作中获取的，特别是点击链接文本或图像的操作。

然而，互联网协议的实际考虑导致了一些有状态的实现细节。一些 HTTP 状态代码表明用户代理需要额外的操作。

3xx 范围内的许多状态代码表示所请求的资源已经移动。然后，用户代理需要根据`Location`头部中发送的信息请求新的位置。401 状态代码表示需要进行身份验证；用户代理可以响应一个包含访问服务器的凭据的授权头部。`urllib`库的实现处理这种有状态的开销。`http.client`库不会自动遐射 3xx 重定向状态代码。

用户代理处理 3xx 和 401 代码的技术并不是深度有状态的。可以使用简单的递归。如果状态不表示重定向，那么它是基本情况，函数有一个结果。如果需要重定向，可以使用重定向地址递归调用函数。

在协议的另一端，静态内容服务器也应该是无状态的。HTTP 协议有两个层次：TCP/IP 套接字机制和依赖于较低级别套接字的更高级别的 HTTP 结构。较低级别的细节由`scoketserver`库处理。Python 的`http.server`库是提供更高级别实现的库之一。

我们可以使用`http.server`库如下：

```py
from http.server import HTTPServer, SimpleHTTPRequestHandler
running = True
httpd = HTTPServer(('localhost',8080), SimpleHTTPRequestHandler)
while running:
 **httpd.handle_request()
httpd.shutdown()

```

我们创建了一个服务器对象，并将其分配给`httpd`变量。我们提供了地址和端口号，以便监听连接请求。TCP/IP 协议将在一个单独的端口上生成一个连接。HTTP 协议将从这个其他端口读取请求并创建一个处理程序的实例。

在这个例子中，我们提供了`SimpleHTTPRequestHandler`作为每个请求实例化的类。这个类必须实现一个最小的接口，它将发送头部，然后将响应的主体发送给客户端。这个特定的类将从本地目录中提供文件。如果我们希望自定义这个，我们可以创建一个子类，实现`do_GET()`和`do_POST()`等方法来改变行为。

通常，我们使用`serve_forever()`方法而不是编写自己的循环。我们在这里展示循环是为了澄清服务器通常必须崩溃。如果我们想要礼貌地关闭服务器，我们将需要一些方法来改变`shutdown`变量的值。例如，*Ctrl + C*信号通常用于这个目的。

## 通过 cookie 注入状态

添加 cookie 改变了客户端和服务器之间的整体关系，使其变得有状态。有趣的是，这并没有改变 HTTP 协议本身。状态信息通过请求和回复的头部进行通信。用户代理将在请求头中发送与主机和路径匹配的 cookie。服务器将在响应头中向用户代理发送 cookie。

因此，用户代理或浏览器必须保留 cookie 值的缓存，并在每个请求中包含适当的 cookie。Web 服务器必须接受请求头中的 cookie，并在响应头中发送 cookie。Web 服务器不需要缓存 cookie。服务器仅仅将 cookie 作为请求中的附加参数和响应中的附加细节。

虽然 cookie 原则上可以包含几乎任何内容，但是 cookie 的使用已经迅速发展为仅包含会话状态对象的标识符。服务器可以使用 cookie 信息来定位某种持久存储中的会话状态。这意味着服务器还可以根据用户代理请求更新会话状态。这也意味着服务器可以丢弃旧的会话。

“会话”的概念存在于 HTTP 协议之外。它通常被定义为具有相同会话 cookie 的一系列请求。当进行初始请求时，没有 cookie 可用，会创建一个新的会话。随后的每个请求都将包括该 cookie。该 cookie 将标识服务器上的会话状态对象；该对象将具有服务器提供一致的 Web 内容所需的信息。

然而，REST 方法对 Web 服务不依赖于 cookie。每个 REST 请求都是独立的，不适用于整体会话框架。这使得它比使用 cookie 简化用户交互的交互式站点不那么“用户友好”。

这也意味着每个单独的 REST 请求原则上是单独进行身份验证的。在许多情况下，服务器会生成一个简单的令牌，以避免客户端在每个请求中发送更复杂的凭据。这导致 REST 流量使用**安全套接字层**（**SSL**）协议进行安全处理；然后使用`https`方案而不是`http`。在本章中，我们将统称这两种方案为 HTTP。

## 考虑具有功能设计的服务器

HTTP 的一个核心理念是守护程序的响应是请求的函数。从概念上讲，一个 Web 服务应该有一个可以总结如下的顶层实现：

```py
response = httpd(request)

```

然而，这是不切实际的。事实证明，HTTP 请求并不是一个简单的、整体的数据结构。它实际上有一些必需的部分和一些可选的部分。一个请求可能有头部，有一个方法和一个路径，还可能有附件。附件可能包括表单或上传的文件或两者都有。

让事情变得更加复杂的是，浏览器的表单数据可以作为一个查询字符串发送到`GET`请求的路径中。或者，它可以作为`POST`请求的附件发送。虽然存在混淆的可能性，但大多数 Web 应用程序框架将创建 HTML 表单标签，通过`<form>`标签中的"`method=POST`"语句提供它们的数据；然后表单数据将成为一个附件。

## 更深入地观察功能视图

HTTP 响应和请求都有头部和正文。请求可以有一些附加的表单数据。因此，我们可以将 Web 服务器看作是这样的：

```py
headers, content = httpd(headers, request, [uploads])

```

请求头可能包括 cookie 值，这可以被视为添加更多参数。此外，Web 服务器通常依赖于其运行的操作系统环境。这个操作系统环境数据可以被视为作为请求的一部分提供的更多参数。

内容有一个大而相当明确定义的范围。**多用途互联网邮件扩展**（**MIME**）类型定义了 Web 服务可能返回的内容类型。这可以包括纯文本、HTML、JSON、XML，或者网站可能提供的各种非文本媒体。

当我们更仔细地观察构建对 HTTP 请求的响应所需的处理时，我们会看到一些我们想要重用的共同特征。可重用元素的这一理念导致了从简单到复杂的 Web 服务框架的创建。功能设计允许我们重用函数的方式表明，功能方法似乎非常适合构建 Web 服务。

我们将通过嵌套请求处理的各种元素来创建服务响应的管道，来研究 Web 服务的功能设计。我们将通过嵌套请求处理的各种元素来创建服务响应的管道，这样内部元素就可以摆脱外部元素提供的通用开销。这也允许外部元素充当过滤器：无效的请求可以产生错误响应，从而使内部函数可以专注于应用程序处理。

## 嵌套服务

我们可以将 Web 请求处理视为许多嵌套上下文。例如，外部上下文可能涵盖会话管理：检查请求以确定这是现有会话中的另一个请求还是新会话。内部上下文可能提供用于表单处理的令牌，可以检测**跨站点请求伪造**（**CSRF**）。另一个上下文可能处理会话中的用户身份验证。

先前解释的函数的概念视图大致如下：

```py
response= content(authentication(csrf(session(headers, request, [forms]))))

```

这里的想法是每个函数都可以建立在前一个函数的结果之上。每个函数要么丰富请求，要么拒绝请求，因为它是无效的。例如，`session`函数可以使用标头来确定这是一个现有会话还是一个新会话。`csrf`函数将检查表单输入，以确保使用了正确的令牌。CSRF 处理需要一个有效的会话。`authentication`函数可以为缺乏有效凭据的会话返回错误响应；当存在有效凭据时，它可以丰富请求的用户信息。

`content`函数不必担心会话、伪造和非经过身份验证的用户。它可以专注于解析路径，以确定应提供什么类型的内容。在更复杂的应用程序中，`content`函数可能包括从路径元素到确定适当内容的函数的相当复杂的映射。

然而，嵌套函数视图仍然不太对。问题在于每个嵌套上下文可能还需要调整响应，而不是或者除了调整请求之外。

我们真的希望更像这样：

```py
def session(headers, request, forms):
 **pre-process: determine session
 **content= csrf(headers, request, forms)
 **post-processes the content
 **return the content
def csrf(headers, request, forms):
 **pre-process: validate csrf tokens
 **content=  authenticate(headers, request, forms)
 **post-processes the content
 **return the content

```

这个概念指向了通过一系列嵌套的函数来创建丰富输入或丰富输出或两者的功能设计。通过一点巧妙，我们应该能够定义一个简单的标准接口，各种函数可以使用。一旦我们标准化了接口，我们就可以以不同的方式组合函数并添加功能。我们应该能够满足我们的函数式编程目标，编写简洁而富有表现力的程序，提供 Web 内容。

# WSGI 标准

**Web 服务器网关接口**（**WSGI**）为创建对 Web 请求的响应定义了一个相对简单的标准化设计模式。Python 库的`wsgiref`包包括了 WSGI 的一个参考实现。

每个 WSGI“应用程序”都具有相同的接口：

```py
def some_app(environ, start_response):
 **return content

```

`environ`是一个包含请求参数的字典，具有统一的结构。标头、请求方法、路径、表单或文件上传的任何附件都将在环境中。除此之外，还提供了操作系统级别的上下文以及一些属于 WSGI 请求处理的项目。

`start_response`是一个必须用于发送响应状态和标头的函数。负责构建响应的 WSGI 服务器的部分将使用`start_response`函数来发送标头和状态，以及构建响应文本。对于某些应用程序，可能需要使用高阶函数包装此函数，以便向响应添加额外的标头。

返回值是一个字符串序列或类似字符串的文件包装器，将返回给用户代理。如果使用 HTML 模板工具，则序列可能只有一个项目。在某些情况下，比如**Jinja2**模板，模板可以作为文本块序列进行延迟渲染，将模板填充与向用户代理下载交错进行。

由于它们的嵌套方式，WSGI 应用程序也可以被视为一个链。每个应用程序要么返回错误，要么将请求交给另一个应用程序来确定结果。

这是一个非常简单的路由应用程序：

```py
SCRIPT_MAP = {
 **""demo"": demo_app,
 **""static"": static_app,
 **"""": welcome_app,
}
def routing(environ, start_response):
 **top_level= wsgiref.util.shift_path_info(environ)
 **app= SCRIPT_MAP.get(top_level, SCRIPT_MAP[''])
 **content= app(environ, start_response)
 **return content

```

此应用程序将使用`wsgiref.util.shift_path_info()`函数来调整环境。这将对请求路径中的项目进行“头/尾拆分”，可在`environ['PATH_INFO']`字典中找到。路径的头部——直到第一个“拆分`”——将被移动到环境中的`SCRIPT_NAME`项目中；`PATH_INFO`项目将被更新为路径的尾部。返回值也将是路径的头部。在没有要解析的路径的情况下，返回值是`None`，不会进行环境更新。

`routing()`函数使用路径上的第一项来定位`SCRIPT_MAP`字典中的应用程序。我们使用`SCRIPT_MAP['']`字典作为默认值，以防所请求的路径不符合映射。这似乎比 HTTP `404 NOT FOUND`错误好一点。

这个 WSGI 应用程序是一个选择多个其他函数的函数。它是一个高阶函数，因为它评估数据结构中定义的函数。

很容易看出，一个框架可以使用正则表达式来概括路径匹配过程。我们可以想象使用一系列正则表达式（REs）和 WSGI 应用程序来配置`routing()`函数，而不是从字符串到 WSGI 应用程序的映射。增强的`routing()`函数应用程序将评估每个 RE 以寻找匹配项。在匹配的情况下，可以使用任何`match.groups()`函数来在调用请求的应用程序之前更新环境。

## 在 WSGI 处理过程中抛出异常

WSGI 应用程序的一个中心特点是，沿着链的每个阶段都负责过滤请求。其想法是尽可能早地拒绝有错误的请求。Python 的异常处理使得这变得特别简单。

我们可以定义一个 WSGI 应用程序，提供静态内容如下：

```py
def static_app(environ, start_response):
 **try:
 **with open(CONTENT_HOME+environ['PATH_INFO']) as static:
 **content= static.read().encode(""utf-8"")
 **headers= [
 **(""Content-Type"",'text/plain; charset=""utf-8""'),(""Content-Length"",str(len(content))),]
 **start_response('200 OK', headers)
 **return [content]
 **except IsADirectoryError as e:
 **return index_app(environ, start_response)
 **except FileNotFoundError as e:
 **start_response('404 NOT FOUND', [])
 **return([repr(e).encode(""utf-8"")])

```

在这种情况下，我们只是尝试打开所请求的路径作为文本文件。我们无法打开给定文件的两个常见原因，这两种情况都作为异常处理：

+   如果文件是一个目录，我们将使用不同的应用程序来呈现目录内容

+   如果文件根本找不到，我们将返回一个 HTTP 404 NOT FOUND 响应

此 WSGI 应用程序引发的任何其他异常都不会被捕获。调用此应用程序的应用程序应设计有一些通用的错误响应能力。如果它不处理异常，将使用通用的 WSGI 失败响应。

### 注意

我们的处理涉及严格的操作顺序。我们必须读取整个文件，以便我们可以创建一个适当的 HTTP `Content-Length`头。

此外，我们必须以字节形式提供内容。这意味着 Python 字符串必须被正确编码，并且我们必须向用户代理提供编码信息。甚至错误消息`repr(e)`在下载之前也要被正确编码。

## 务实的 WSGI 应用程序

WSGI 标准的目的不是定义一个完整的 Web 框架；目的是定义一组最低限度的标准，允许 Web 相关处理的灵活互操作。一个框架可以采用与内部架构完全不同的方法来提供 Web 服务。但是，它的最外层接口应与 WSGI 兼容，以便可以在各种上下文中使用。

诸如**Apache httpd**和**Nginx**之类的 Web 服务器有适配器，它们提供了从 Web 服务器到 Python 应用程序的 WSGI 兼容接口。有关 WSGI 实现的更多信息，请访问

[`wiki.python.org/moin/WSGIImplementations`](https://wiki.python.org/moin/WSGIImplementations)。

将我们的应用程序嵌入到一个更大的服务器中，可以让我们有一个整洁的关注分离。我们可以使用 Apache httpd 来提供完全静态的内容，比如.css、.js 和图像文件。但是对于 HTML 页面，我们可以使用 Apache 的`mod_wsgi`接口将请求转交给一个单独的 Python 进程，该进程只处理网页内容的有趣部分。

这意味着我们必须要么创建一个单独的媒体服务器，要么定义我们的网站有两组路径。如果我们采取第二种方法，一些路径将有完全静态的内容，可以由 Apache httpd 处理。其他路径将有动态内容，将由 Python 处理。

在使用 WSGI 函数时，重要的是要注意我们不能以任何方式修改或扩展 WSGI 接口。例如，提供一个附加参数，其中包含定义处理链的函数序列，似乎是一个好主意。每个阶段都会从列表中弹出第一个项目作为处理的下一步。这样的附加参数可能是函数设计的典型，但接口的改变违背了 WSGI 的目的。

WSGI 定义的一个后果是配置要么使用全局变量，要么使用请求环境，要么使用一个函数，该函数从缓存中获取一些全局配置对象。使用模块级全局变量适用于小例子。对于更复杂的应用程序，可能需要一个配置缓存。可能还有必要有一个 WSGI 应用程序，它仅仅更新`environ`字典中的配置参数，并将控制权传递给另一个 WSGI 应用程序。

# 将 web 服务定义为函数

我们将研究一个 RESTful web 服务，它可以“切割和切块”数据源，并提供 JSON、XML 或 CSV 文件的下载。我们将提供一个整体的 WSGI 兼容包装器，但是应用程序的“真正工作”的函数不会被狭窄地限制在 WSGI 中。

我们将使用一个简单的数据集，其中包括四个子集合：安斯康姆四重奏。我们在第三章“函数、迭代器和生成器”中讨论了读取和解析这些数据的方法。这是一个小数据集，但可以用来展示 RESTful web 服务的原则。

我们将把我们的应用程序分成两个层次：一个是 web 层，它将是一个简单的 WSGI 应用程序，另一个是其余的处理，它将是更典型的函数式编程。我们首先看看 web 层，这样我们就可以专注于提供有意义的结果的函数式方法。

我们需要向 web 服务提供两个信息：

+   我们想要的四重奏——这是一个“切割和切块”的操作。在这个例子中，它主要是一个“切片”。

+   我们想要的输出格式。

数据选择通常通过请求路径完成。我们可以请求`/anscombe/I/`或`/anscombe/II/`来从四重奏中选择特定的数据集。这个想法是 URL 定义了一个资源，而且没有好的理由让 URL 发生变化。在这种情况下，数据集选择器不依赖于日期，或者一些组织批准状态或其他外部因素。URL 是永恒和绝对的。

输出格式不是 URL 的一部分。它只是一个序列化格式，而不是数据本身。在某些情况下，格式是通过 HTTP“接受”头请求的。这在浏览器中很难使用，但在使用 RESTful API 的应用程序中很容易使用。从浏览器中提取数据时，通常使用查询字符串来指定输出格式。我们将在路径的末尾使用`?form=json`方法来指定 JSON 输出格式。

我们可以使用的 URL 看起来像这样：

```py
http://localhost:8080/anscombe/III/?form=csv

```

这将请求第三个数据集的 CSV 下载。

## 创建 WSGI 应用程序

首先，我们将使用一个简单的 URL 模式匹配表达式来定义我们应用程序中唯一的路由。在一个更大或更复杂的应用程序中，我们可能会有多个这样的模式：

```py
import re
path_pat= re.compile(r""^/anscombe/(?P<dataset>.*?)/?$"")

```

这种模式允许我们在路径的顶层定义一个整体的 WSGI 意义上的“脚本”。在这种情况下，脚本是“anscombe”。我们将路径的下一个级别作为要从 Anscombe Quartet 中选择的数据集。数据集值应该是`I`、`II`、`III`或`IV`中的一个。

我们对选择条件使用了一个命名参数。在许多情况下，RESTful API 使用以下语法进行描述：

```py
/anscombe/{dataset}/

```

我们将这种理想化的模式转化为一个适当的正则表达式，并在路径中保留了数据集选择器的名称。

这是演示这种模式如何工作的单元测试的一种类型：

```py
test_pattern= """"""
>>> m1= path_pat.match(""/anscombe/I"")
>>> m1.groupdict()
{'dataset': 'I'}
>>> m2= path_pat.match(""/anscombe/II/"")
>>> m2.groupdict()
{'dataset': 'II'}
>>> m3= path_pat.match(""/anscombe/"")
>>> m3.groupdict()
{'dataset': ''}
""""""

```

我们可以使用以下命令将三个先前提到的示例包含在整个 doctest 中：

```py
__test__ = {
 **""test_pattern"": test_pattern,
}

```

这将确保我们的路由按预期工作。能够从 WSGI 应用程序的其余部分单独测试这一点非常重要。测试完整的 Web 服务器意味着启动服务器进程，然后尝试使用浏览器或测试工具（如 Postman 或 Selenium）进行连接。访问[`www.getpostman.com`](http://www.getpostman.com)或[`www.seleniumhq.org`](http://www.seleniumhq.org)以获取有关 Postman 和 Selenium 用法的更多信息。我们更喜欢单独测试每个功能。

以下是整个 WSGI 应用程序，其中突出显示了两行命令：

```py
import traceback
import urllib
def anscombe_app(environ, start_response):
 **log= environ['wsgi.errors']
 **try:
 **match= path_pat.match(environ['PATH_INFO'])
 **set_id= match.group('dataset').upper()
 **query= urllib.parse.parse_qs(environ['QUERY_STRING'])
 **print(environ['PATH_INFO'], environ['QUERY_STRING'],match.groupdict(), file=log)
 **log.flush()
 **dataset= anscombe_filter(set_id, raw_data())
 **content, mime= serialize(query['form'][0], set_id, dataset)
 **headers= [
 **('Content-Type', mime),('Content-Length', str(len(content))),        ]
 **start_response(""200 OK"", headers)
 **return [content]
 **except Exception as e:
 **traceback.print_exc(file=log)
 **tb= traceback.format_exc()
 **page= error_page.substitute(title=""Error"", message=repr(e), traceback=tb)
 **content= page.encode(""utf-8"")
 **headers = [
 **('Content-Type', ""text/html""),('Content-Length', str(len(content))),]
 **start_response(""404 NOT FOUND"", headers)
 **return [content]

```

此应用程序将从请求中提取两个信息：`PATH_INFO`和`QUERY_STRING`方法。`PATH_INFO`请求将定义要提取的集合。`QUERY_STRING`请求将指定输出格式。

应用程序处理分为三个函数。`raw_data()`函数从文件中读取原始数据。结果是一个带有`Pair`对象列表的字典。`anscombe_filter()`函数接受选择字符串和原始数据的字典，并返回一个`Pair`对象的列表。然后，将成对的列表通过`serialize()`函数序列化为字节。序列化器应该生成字节，然后可以与适当的头部打包并返回。

我们选择生成一个 HTTP`Content-Length`头。这并不是必需的，但对于大型下载来说是礼貌的。因为我们决定发出这个头部，我们被迫实现序列化的结果，以便我们可以计算字节数。

如果我们选择省略`Content-Length`头部，我们可以大幅改变此应用程序的结构。每个序列化器可以更改为生成器函数，该函数将按照生成的顺序产生字节。对于大型数据集，这可能是一个有用的优化。但是，对于观看下载的用户来说，这可能并不那么愉快，因为浏览器无法显示下载的完成进度。

所有错误都被视为`404 NOT FOUND`错误。这可能会产生误导，因为可能会出现许多个别问题。更复杂的错误处理将提供更多的`try:/except:`块，以提供更多信息反馈。

出于调试目的，我们在生成的网页中提供了一个 Python 堆栈跟踪。在调试的上下文之外，这是一个非常糟糕的主意。来自 API 的反馈应该足够修复请求，什么都不多。堆栈跟踪为潜在的恶意用户提供了太多信息。

## 获取原始数据

`raw_data()`函数在很大程度上是从第三章*函数，迭代器和生成器*中复制的。我们包含了一些重要的更改。以下是我们用于此应用程序的内容：

```py
from Chapter_3.ch03_ex5 import series, head_map_filter, row_iter, Pair
def raw_data():
 **""""""
 **>>> raw_data()['I'] #doctest: +ELLIPSIS
 **(Pair(x=10.0, y=8.04), Pair(x=8.0, y=6.95), ...
 **""""""
 **with open(""Anscombe.txt"") as source:
 **data = tuple(head_map_filter(row_iter(source)))
 **mapping = dict((id_str, tuple(series(id_num,data)))
 **for id_num, id_str in enumerate(['I', 'II', 'III', 'IV'])
 **)
 **return mapping

```

我们打开了本地数据文件，并应用了一个简单的`row_iter()`函数，以将文件的每一行解析为一个单独的行。我们应用了`head_map_filter()`函数来从文件中删除标题。结果创建了一个包含所有数据的元组结构。

我们通过从源数据中选择特定系列，将元组转换为更有用的`dict()`函数。每个系列将是一对列。对于系列`"I`,`"`，它是列 0 和 1。对于系列`"II`,`"`，它是列 2 和 3。

我们使用`dict()`函数与生成器表达式保持一致，与`list()`和`tuple()`函数一样。虽然这并非必要，但有时看到这三种数据结构及其使用生成器表达式的相似之处是有帮助的。

`series()`函数为数据集中的每个*x*，*y*对创建了单独的`Pair`对象。回顾一下，我们可以看到修改这个函数后的输出值，使得生成的`namedtuple`类是这个函数的参数，而不是函数的隐式特性。我们更希望看到`series(id_num,Pair,data)`方法，以查看`Pair`对象是如何创建的。这个扩展需要重写第三章中的一些示例，*函数、迭代器和生成器*。我们将把这留给读者作为练习。

这里的重要变化是，我们展示了正式的`doctest`测试用例。正如我们之前指出的，作为一个整体，Web 应用程序很难测试。必须启动 Web 服务器，然后必须使用 Web 客户端来运行测试用例。然后必须通过阅读 Web 日志来解决问题，这可能很困难，除非显示完整的回溯。最好尽可能多地使用普通的`doctest`和`unittest`测试技术来调试 Web 应用程序。

## 应用过滤器

在这个应用程序中，我们使用了一个非常简单的过滤器。整个过滤过程体现在下面的函数中：

```py
def anscombe_filter(set_id, raw_data):
 **""""""
 **>>> anscombe_filter(""II"", raw_data()) #doctest: +ELLIPSIS
 **(Pair(x=10.0, y=9.14), Pair(x=8.0, y=8.14), Pair(x=13.0, y=8.74), ...
 **""""""
 **return raw_data[set_id]

```

我们将这个微不足道的表达式转换成一个函数有三个原因：

+   函数表示法略微更一致，比下标表达式更灵活

+   我们可以很容易地扩展过滤功能

+   我们可以在此函数的文档字符串中包含单独的单元测试

虽然简单的 lambda 可以工作，但测试起来可能不太方便。

对于错误处理，我们什么也没做。我们专注于有时被称为“快乐路径”的内容：理想的事件序列。在这个函数中出现的任何问题都将引发异常。WSGI 包装函数应该捕获所有异常并返回适当的状态消息和错误响应内容。

例如，`set_id`方法可能在某些方面是错误的。与其过分关注它可能出错的所有方式，我们宁愿让 Python 抛出异常。事实上，这个函数遵循了 Python I 的建议，“最好是寻求宽恕，而不是征求许可”。这个建议在代码中体现为避免“征求许可”：没有寻求将参数限定为有效的准备性`if`语句。只有“宽恕”处理：异常将被引发并在 WSGI 包装函数中处理。这个基本建议适用于前面的原始数据和我们现在将看到的序列化。

## 序列化结果

序列化是将 Python 数据转换为适合传输的字节流的过程。每种格式最好由一个简单的函数来描述，该函数只序列化这一种格式。然后，顶层通用序列化程序可以从特定序列化程序列表中进行选择。序列化程序的选择导致以下一系列函数：

```py
serializers = {
 **'xml': ('application/xml', serialize_xml),
 **'html': ('text/html', serialize_html),
 **'json': ('application/json', serialize_json),
 **'csv': ('text/csv', serialize_csv),
}
def serialize(format, title, data):
 **""""""json/xml/csv/html serialization.
 **>>> data = [Pair(2,3), Pair(5,7)]
 **>>> serialize(""json"", ""test"", data)
 **(b'[{""x"": 2, ""y"": 3}, {""x"": 5, ""y"": 7}]', 'application/json')
 **""""""
 **mime, function = serializers.get(format.lower(), ('text/html', serialize_html))
 **return function(title, data), mime

```

整体`serialize()`函数找到必须在响应中使用的特定序列化程序和特定 MIME 类型。然后调用其中一个特定的序列化程序。我们还在这里展示了一个`doctest`测试用例。我们没有耐心测试每个序列化程序，因为显示一个工作似乎就足够了。

我们将分别查看序列化器。我们将看到序列化器分为两组：产生字符串的序列化器和产生字节的序列化器。产生字符串的序列化器将需要将字符串编码为字节。产生字节的序列化器不需要进一步处理。

对于生成字符串的序列化器，我们需要使用标准的转换为字节的函数组合。我们可以使用装饰器进行函数组合。以下是我们如何将转换为字节标准化：

```py
from functools import wraps
def to_bytes(function):
 **@wraps(function)
 **def decorated(*args, **kw):
 **text= function(*args, **kw)
 **return text.encode(""utf-8"")
 **return decorated

```

我们创建了一个名为`@to_bytes`的小装饰器。这将评估给定的函数，然后使用 UTF-8 对结果进行编码以获得字节。我们将展示如何将其与 JSON、CSV 和 HTML 序列化器一起使用。XML 序列化器直接产生字节，不需要与此额外函数组合。

我们还可以在`serializers`映射的初始化中进行函数组合。我们可以装饰函数定义的引用，而不是装饰函数对象的引用。

```py
serializers = {
 **'xml': ('application/xml', serialize_xml),
 **'html': ('text/html', to_bytes(serialize_html)),
 **'json': ('application/json', to_bytes(serialize_json)),
 **'csv': ('text/csv', to_bytes(serialize_csv)),
}

```

虽然这是可能的，但这似乎并不有用。产生字符串和产生字节的序列化器之间的区别并不是配置的重要部分。

## 将数据序列化为 JSON 或 CSV 格式

JSON 和 CSV 序列化器是类似的函数，因为两者都依赖于 Python 的库进行序列化。这些库本质上是命令式的，因此函数体是严格的语句序列。

这是 JSON 序列化器：

```py
import json
@to_bytes
def serialize_json(series, data):
 **""""""
 **>>> data = [Pair(2,3), Pair(5,7)]
 **>>> serialize_json(""test"", data)
 **b'[{""x"": 2, ""y"": 3}, {""x"": 5, ""y"": 7}]'
 **""""""
 **obj= [dict(x=r.x, y=r.y) for r in data]
 **text= json.dumps(obj, sort_keys=True)
 **return text

```

我们创建了一个字典结构的列表，并使用`json.dumps()`函数创建了一个字符串表示。JSON 模块需要一个具体化的`list`对象；我们不能提供一个惰性生成器函数。`sort_keys=True`参数值对于单元测试是必不可少的。但对于应用程序并不是必需的，而且代表了一些额外的开销。

这是 CSV 序列化器：

```py
import csv, io
@to_bytes
def serialize_csv(series, data):
 **""""""

 **>>> data = [Pair(2,3), Pair(5,7)]
 **>>> serialize_csv(""test"", data)
 **b'x,y\\r\\n2,3\\r\\n5,7\\r\\n'
 **""""""
 **buffer= io.StringIO()
 **wtr= csv.DictWriter(buffer, Pair._fields)
 **wtr.writeheader()
 **wtr.writerows(r._asdict() for r in data)
 **return buffer.getvalue()

```

CSV 模块的读取器和写入器是命令式和函数式元素的混合。我们必须创建写入器，并严格按顺序创建标题。我们使用了`Pair`命名元组的`_fields`属性来确定写入器的列标题。

写入器的`writerows()`方法将接受一个惰性生成器函数。在这种情况下，我们使用了每个`Pair`对象的`_asdict()`方法返回适用于 CSV 写入器的字典。

## 将数据序列化为 XML

我们将使用内置库来看一种 XML 序列化的方法。这将从单个标签构建文档。一个常见的替代方法是使用 Python 内省来检查和映射 Python 对象和类名到 XML 标签和属性。

这是我们的 XML 序列化：

```py
import xml.etree.ElementTree as XML
def serialize_xml(series, data):
 **""""""
 **>>> data = [Pair(2,3), Pair(5,7)]
 **>>> serialize_xml(""test"", data)
 **b'<series name=""test""><row><x>2</x><y>3</y></row><row><x>5</x><y>7</y></row></series>'
 **""""""
 **doc= XML.Element(""series"", name=series)
 **for row in data:
 **row_xml= XML.SubElement(doc, ""row"")
 **x= XML.SubElement(row_xml, ""x"")
 **x.text= str(row.x)
 **y= XML.SubElement(row_xml, ""y"")
 **y.text= str(row.y)
 **return XML.tostring(doc, encoding='utf-8')

```

我们创建了一个顶级元素`<series>`，并将`<row>`子元素放在该顶级元素下面。在每个`<row>`子元素中，我们创建了`<x>`和`<y>`标签，并为每个标签分配了文本内容。

使用 ElementTree 库构建 XML 文档的接口往往是非常命令式的。这使得它不适合于否则功能设计。除了命令式风格之外，注意我们没有创建 DTD 或 XSD。我们没有为标签正确分配命名空间。我们还省略了通常是 XML 文档中的第一项的`<?xml version=""1.0""?>`处理指令。

更复杂的序列化库将是有帮助的。有许多选择。访问[`wiki.python.org/moin/PythonXml`](https://wiki.python.org/moin/PythonXml)获取备选列表。

## 将数据序列化为 HTML

在我们最后一个序列化示例中，我们将看到创建 HTML 文档的复杂性。复杂性的原因是在 HTML 中，我们需要提供一个带有一些上下文信息的整个网页。以下是解决这个 HTML 问题的一种方法：

```py
import string
data_page = string.Template(""""""<html><head><title>Series ${title}</title></head><body><h1>Series ${title}</h1><table><thead><tr><td>x</td><td>y</td></tr></thead><tbody>${rows}</tbody></table></body></html>"""""")
@to_bytes
def serialize_html(series, data):
 **"""""">>> data = [Pair(2,3), Pair(5,7)]>>> serialize_html(""test"", data) #doctest: +ELLIPSISb'<html>...<tr><td>2</td><td>3</td></tr>\\n<tr><td>5</td><td>7</td></tr>...""""""
 **text= data_page.substitute(title=series,rows=""\n"".join(
 **""<tr><td>{0.x}</td><td>{0.y}</td></tr>"".format(row)
 **for row in data)
 **)
 **return text

```

我们的序列化函数有两个部分。第一部分是一个`string.Template()`函数，其中包含了基本的 HTML 页面。它有两个占位符，可以将数据插入模板中。`${title}`方法显示了标题信息可以插入的位置，`${rows}`方法显示了数据行可以插入的位置。

该函数使用简单的格式字符串创建单独的数据行。然后将它们连接成一个较长的字符串，然后替换到模板中。

虽然对于像前面的例子这样简单的情况来说是可行的，但对于更复杂的结果集来说并不理想。有许多更复杂的模板工具可以创建 HTML 页面。其中一些包括在模板中嵌入循环的能力，与初始化序列化的功能分开。访问[`wiki.python.org/moin/Templating`](https://wiki.python.org/moin/Templating)获取备选列表。

# 跟踪使用情况

许多公开可用的 API 需要使用"API 密钥"。API 的供应商要求您注册并提供电子邮件地址或其他联系信息。作为交换，他们提供一个激活 API 的 API 密钥。

API 密钥用于验证访问。它也可以用于授权特定功能。最后，它还用于跟踪使用情况。这可能包括在给定时间段内过于频繁地使用 API 密钥时限制请求。

商业模式的变化是多种多样的。例如，使用 API 密钥是一个计费事件，会产生费用。对于其他企业来说，流量必须达到一定阈值才需要付款。

重要的是对 API 的使用进行不可否认。这反过来意味着创建可以作为用户身份验证凭据的 API 密钥。密钥必须难以伪造，相对容易验证。

创建 API 密钥的一种简单方法是使用加密随机数来生成难以预测的密钥字符串。像下面这样的一个小函数应该足够好：

```py
import random
rng= random.SystemRandom()
import base64
def make_key_1(rng=rng, size=1):
 **key_bytes= bytes(rng.randrange(0,256) for i in range(18*size))
 **key_string= base64.urlsafe_b64encode(key_bytes)
 **return key_string

```

我们使用了`random.SystemRandom`类作为我们安全随机数生成器的类。这将使用`os.urandom()`字节来初始化生成器，确保了一个可靠的不可预测的种子值。我们单独创建了这个对象，以便每次请求密钥时都可以重复使用。最佳做法是使用单个随机种子从生成器获取多个密钥。

给定一些随机字节，我们使用了 base 64 编码来创建一系列字符。在初始随机字节序列中使用三的倍数，可以避免在 base 64 编码中出现任何尾随的"`=`"符号。我们使用了 URL 安全的 base 64 编码，这不会在结果字符串中包含"`/`"或"`+`"字符，如果作为 URL 或查询字符串的一部分使用可能会引起混淆。

### 注意

更复杂的方法不会导致更多的随机数据。使用`random.SystemRandom`可以确保没有人可以伪造分配给另一个用户的密钥。我们使用了*18×8*个随机位，给我们大量的随机密钥。

有多少随机密钥？看一下以下命令及其输出：

```py
>>> 2**(18*8)
22300745198530623141535718272648361505980416

```

成功伪造其他人的密钥的几率很小。

另一种选择是使用`uuid.uuid4()`来创建一个随机的**通用唯一标识符**（**UUID**）。这将是一个 36 个字符的字符串，其中包含 32 个十六进制数字和四个"-"标点符号。随机 UUID 也难以伪造。包含用户名或主机 IP 地址等数据的 UUID 是一个坏主意，因为这会编码信息，可以被解码并用于伪造密钥。使用加密随机数生成器的原因是避免编码任何信息。

RESTful Web 服务器然后将需要一个带有有效密钥和可能一些客户联系信息的小型数据库。如果 API 请求包括数据库中的密钥，相关用户将负责该请求。如果 API 请求不包括已知密钥，则可以用简单的`401 未经授权`响应拒绝该请求。由于密钥本身是一个 24 个字符的字符串，数据库将非常小，并且可以很容易地缓存在内存中。

普通的日志抓取可能足以显示给定密钥的使用情况。更复杂的应用程序可能会将 API 请求记录在单独的日志文件或数据库中，以简化分析。

# 总结

在本章中，我们探讨了如何将功能设计应用于使用基于 REST 的 Web 服务提供内容的问题。我们看了一下 WSGI 标准导致了总体上有点功能性的应用程序的方式。我们还看了一下如何通过从请求中提取元素来将更功能性的设计嵌入到 WSGI 上下文中，以供我们的应用程序函数使用。

对于简单的服务，问题通常可以分解为三个不同的操作：获取数据，搜索或过滤，然后序列化结果。我们用三个函数解决了这个问题：`raw_data()`，`anscombe_filter()`和`serialize()`。我们将这些函数封装在一个简单的 WSGI 兼容应用程序中，以将 Web 服务与围绕提取和过滤数据的“真实”处理分离。

我们还看了 Web 服务函数可以专注于“快乐路径”，并假设所有输入都是有效的方式。如果输入无效，普通的 Python 异常处理将引发异常。WSGI 包装函数将捕获错误并返回适当的状态代码和错误内容。

我们避免了与上传数据或接受来自表单的数据以更新持久数据存储相关的更复杂的问题。这些问题与获取数据和序列化结果并没有显著的复杂性。它们已经以更好的方式得到解决。

对于简单的查询和数据共享，小型 Web 服务应用程序可能会有所帮助。我们可以应用功能设计模式，并确保网站代码简洁而富有表现力。对于更复杂的 Web 应用程序，我们应考虑使用一个能够正确处理细节的框架。

在下一章中，我们将看一些可用于我们的优化技术。我们将扩展来自第十章*Functools 模块*的`@lru_cache`装饰器。我们还将研究一些其他优化技术，这些技术在第六章*递归和归约*中提出。
