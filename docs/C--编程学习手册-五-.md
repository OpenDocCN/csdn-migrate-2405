# C# 编程学习手册（五）

> 原文：[`zh.annas-archive.org/md5/43CC9F8096F66361F01960142D9E6C0F`](https://zh.annas-archive.org/md5/43CC9F8096F66361F01960142D9E6C0F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：多线程和异步编程

自第一台个人电脑以来，我们已经受益于 CPU 功率的持续增加-这一现象严重影响了开发人员对工具、语言和应用程序设计的选择，而在历史上并没有花费太多精力来编写利用多线程的程序。

在硬件方面，摩尔定律的预测是处理器中晶体管的密度应该每 2 年翻一番，从而提供更多的计算能力，这个预测在一些十年内有效，但我们已经可以观察到它放缓了。即使 CPU 制造商大约 20 年前开始生产多核 CPU，执行代码的能力主要由操作系统（OSes）用于使执行多个进程更加流畅。

这并不意味着代码无法利用并发的力量，而只是只有少量的应用程序完全拥抱了*多线程范式*。这主要是因为我们编写的所有代码都是从操作系统基础设施提供的单个线程顺序执行，除非我们明确请求创建其他线程并编排它们的执行。

这种趋势主要是因为许多编程语言没有提供构造来自动生成多线程代码。这是因为很难提供适合任何用例并有效利用现代 CPU 提供的并发处理能力的语义。

另一方面，有时我们并不真正需要并发执行应用程序代码，但我们无法继续执行，因为需要等待一些未完成的 I/O 操作。同时，阻塞代码执行也是不可接受的，因此需要采用不同的策略。这类问题领域被归类为*异步编程*，需要稍微不同的工具。

在本章中，我们将学习多线程和异步编程的基础知识，并具体了解以下内容：

+   什么是线程？

+   在.NET 中创建线程

+   理解同步原语

+   任务范式

在本章结束时，您将熟悉多线程技术，使用原语来同步代码执行、任务、继续和取消标记。您还将了解潜在的危险操作以及在多个线程之间共享资源时避免问题的基本模式。

我们现在将开始熟悉操作多线程和异步编程所需的基本概念。

# 什么是线程？

每个操作系统都提供抽象来允许多个程序共享相同的硬件资源，如 CPU、内存和输入输出设备。进程是这些抽象之一，提供了一个保留的虚拟地址空间，其运行代码无法逃离。这种基本的沙盒避免了进程代码干扰其他进程，为平衡生态系统奠定了基础。进程与代码执行无关，主要与内存有关。

负责代码执行的抽象是**线程**。每个进程至少有一个线程，但任何进程代码都可以请求创建更多的线程，它们都将共享相同的虚拟地址空间，由所属进程限定。在单个进程中运行多个线程大致相当于一组木工朋友共同完成同一个项目-他们需要协调，关注彼此的进展，并注意不要阻塞彼此的活动。

所有现代操作系统都提供抢占式多任务处理策略，而不是合作式多任务处理。这意味着操作系统的一个特殊组件安排每个线程可以运行的时间，而无需从正在运行的代码中获得任何合作。

提示

早期版本的 Windows，如 Windows 3.x 和 Windows 9x，使用协作式多任务处理，这意味着任何应用程序都可以通过简单的无限循环挂起整个操作系统。这主要是因为 CPU 功率和能力的限制。所有后来的操作系统，如从最初的**NT 3.1 高级服务器**开始的 Windows 版本和所有类 Unix 的操作系统，一直都使用抢占式多任务处理，使操作系统更加健壮，并提供更好的用户体验。

您可以使用任务管理器、Process Explorer 或 Process Hacker 工具查看每个运行进程中使用的线程数。您会立即注意到，许多应用程序，包括所有.NET 应用程序，都使用不止一个线程。这些信息并不能告诉我们太多关于应用程序的设计，因为现代运行时（如.NET CLR）使用后台线程进行内部处理，例如**垃圾回收器**、**终结队列**等。

提示

要查看运行进程使用的线程数，请打开**任务管理器**（*Ctrl* + *Shift* + *Esc*），单击**详细信息**选项卡，并添加**线程**列。可以通过右键单击其中一个网格标题，选择**选择列**菜单项，最后勾选**线程**选项来添加列。

以下屏幕截图显示了一个 C++控制台应用程序，用户的代码使用一个线程，而其他三个线程是由 C++运行时创建的：

![图 12.1 - 任务管理器显示具有四个线程的 NativeConsole.exe 进程](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_12.1_B12346.jpg)

图 12.1 - 任务管理器显示具有四个线程的 NativeConsole.exe 进程

包含处理线程的基元的命名空间是`System.Threading`，但在本章后面，我们还将介绍`System.Threading.Tasks`命名空间。

当.NET 应用程序启动时，.NET 运行时会准备我们的进程，分配内存并创建一些线程，包括将从`Main`入口点开始执行我们的代码的线程。

以下控制台应用程序访问当前线程并在屏幕上打印当前线程的`Id`：

```cs
static void Main(string[] args)
{
    Console.WriteLine($"Current Thread Id: {Thread.CurrentThread.ManagedThreadId}");
    Console.ReadKey();
}
```

`ManagedThreadId`属性在诊断多线程代码时很重要，因为它将某些代码的执行与特定线程相关联。

此`Id`只能在运行的进程中使用，并且与操作系统线程标识符不同。如果您需要访问本机标识符，您需要使用互操作性，如下面的仅限 Windows 的代码片段所示：

```cs
[DllImport("Kernel32.dll")]
private static extern int GetCurrentThreadId();
static void Main(string[] args)
{
    Console.WriteLine($"Current Thread Id: {Thread.CurrentThread.ManagedThreadId}");
    Console.WriteLine($"Current Native Thread Id: {GetCurrentThreadId()}");
    Console.ReadKey();
}
```

本机`Id`是您可以在**Process Explorer**和**Process Hacker**工具中看到的`Id`，这是与其他本机 API 进行交互所需的`Id`。在下面的屏幕截图中，您可以看到左侧控制台中打印的结果，右侧是 Process Hacker 线程窗口：

![图 12.2 - 控制台应用程序与 Process Hacker 并排显示相同的本机线程 Id](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_12.2_B12346.jpg)

图 12.2 - 控制台应用程序与 Process Hacker 并排显示相同的本机线程 Id

线程也可以由操作系统、.NET 运行时或某个库创建，而无需我们的代码明确请求。例如，以下类展示了`FileSystemWatcher`类的使用情况，并为每个文件系统操作打印了`ManagedThreadId`属性：`Run`方法打印与主线程关联的 ID，而`Wacher_Deleted`和`Watcher_Created`方法是由操作系统或基础架构创建的线程执行的：

```cs
public class FileWatcher
{
    private FileSystemWatcher _watcher;
    public void Run()
    {
        var path = Path.GetFullPath(".");
        Console.WriteLine($"Observing changes in path: {path}");
        _watcher = new FileSystemWatcher(path, "*.txt");
        _watcher.Created += Watcher_Created;
        _watcher.Deleted += Watcher_Deleted;
        Console.WriteLine($"TID: {Thread.CurrentThread.ManagedThreadId}");
        _watcher.EnableRaisingEvents = true;
    }
    private void Watcher_Deleted(object sender, FileSystemEventArgs e)
    {
        Console.WriteLine($"Deleted occurred in TID: {Thread.CurrentThread.ManagedThreadId}");
    }
    private void Watcher_Created(object sender, FileSystemEventArgs e)
    {
        Console.WriteLine($"Created occurred in TID: {Thread.CurrentThread.ManagedThreadId}");
    }
} 
```

您可以通过创建控制台应用程序并将以下代码添加到`Main`方法来尝试此代码：

```cs
var fw = new FileWatcher();
fw.Run();
Console.ReadKey();
```

现在，如果您开始在控制台文件夹中创建和删除一些`.txt`文件，您将看到类似于这样的东西：

```cs
Observing changes in path: C:\projects\Watch\bin\Debug\netcoreapp3.1
TID: 1
Created occurred in TID: 5
Created occurred in TID: 7
Deleted occurred in TID: 5
Deleted occurred in TID: 5
```

您看到的`TID`号码可能会在每次重新运行应用程序时发生变化：它们既不可预测，也不按相同顺序使用。

我们现在将看到如何创建一个新线程，同时执行一些代码，并检查线程的主要特征。

# 在.NET 中创建线程

创建原始线程在大多数情况下只有在有长时间运行的操作且仅依赖于 CPU 时才有意义。例如，假设我们想计算质数，而不真正关心可能的优化：

```cs
public class Primes : IEnumerable<long>
{
	public Primes(long Max = long.MaxValue)
	{
		this.Max = Max;
	}
	public long Max { get; private set; }
	IEnumerator IEnumerable.GetEnumerator() => ((IEnumerable<long>)this).GetEnumerator();
	public IEnumerator<long> GetEnumerator()
	{
		yield return 1;
		bool bFlag;
		long start = 2;
		while (start < Max)
		{
			bFlag = false;
			var number = start;
			for (int i = 2; i < number; i++)
			{
				if (number % i == 0)
				{
					bFlag = true;
					break;
				}
			}
			if (!bFlag)
			{
				yield return number;
			}
			start++;
		}
	}
}
```

`Primes`类实现了`IEnumerable<long>`，这样我们可以轻松枚举质数，`Max`参数用于限制结果序列，否则将受`long.MaxValue`的限制。

调用上述代码非常容易，但是由于计算可能需要很长时间，它会完全阻塞执行线程：

```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
// namespace and class declaration omitted for clarity
Console.WriteLine("Start primes");
foreach (var n in new Primes(1000000))   {  /* ...  */ }
Console.WriteLine("End primes"); // the wait is too long!
```

这里发生的情况是主线程正在忙于计算质数。由于抢占式多任务处理，这个线程将被操作系统调度程序中断，以便让其他进程的线程有机会运行它们的代码。然而，由于我们的应用程序没有其他线程执行应用程序代码，我们只能等待。

在任何桌面应用程序中，无论是控制台还是 GUI，用户体验都会很糟糕，因为鼠标和键盘的任何交互都会*被阻塞*。更糟糕的是，GUI 甚至无法重新绘制屏幕内容，因为唯一的线程被质数计算占用了。

第一步是将阻塞代码移到一个单独的方法中，这样我们就可以在一个新的独立线程中执行它：

```cs
private void Worker(object param)
{
    PrintThreadInfo(Thread.CurrentThread);
    foreach (var n in new Primes(1000000))
    {
        Thread.Sleep(100);
    }
    Console.WriteLine("Computation ended!");
}
```

`Thread.Sleep`方法仅用于观察 CPU 使用情况。然后，`Sleep`告诉操作系统暂停当前线程的执行一段时间，以*毫秒*为单位。通常，不建议在生产代码中调用`Sleep`，因为它会阻止线程被重用。在本章后面，我们将发现更好的方法来在我们的代码中插入延迟。

`Worker`方法没有什么特别之处，它可能会选择性地获取一个对象参数，该参数可用于初始化局部变量。我们不直接调用它，而是要求基础设施在新线程的上下文中调用它：

```cs
Console.WriteLine("Start primes");
PrintThreadInfo(Thread.CurrentThread);
var t1 = new Thread(Worker);
//t1.IsBackground = true; // try with/without this line
t1.Start();
Console.WriteLine("Primes calculation is happening in background");
```

从上述代码中可以看出，创建了`Thread`对象，但线程尚未启动。我们必须显式调用`Start`方法才能启动它。这很重要，因为`Thread`类还有其他重要的属性，只能在线程启动之前设置。

最后，使用`PrintThreadInfo`方法打印主线程的详细信息。请注意，有些属性并不总是可用。因此，我们必须在打印`Priority`或`IsBackground`之前检查线程是否正在运行。由于`ThreadState`枚举具有`Flags`属性，而`Running`状态为零，官方文档（https://docs.microsoft.com/en-us/dotnet/api/system.threading.threadstate?view=netframework-4.8#remarks）提醒我们要检查`Stopped`和`Unstarted`位是否未设置：

```cs
private void PrintThreadInfo(Thread t)
{
    var sb = new StringBuilder();
    var state = t.ThreadState;
    sb.Append($"Id:{t.ManagedThreadId} Name:{t.Name} State:{state} ");
    if ((state & (ThreadState.Stopped | ThreadState.Unstarted)) == 0)
    {
        sb.Append($"Priority:{t.Priority} IsBackground:{t.IsBackground}");
    }
    Console.WriteLine(sb.ToString());
}
```

执行上述代码的结果如下：

```cs
Start primes
Id:1 Name: State:Running Priority:Normal IsBackground:False
Primes calculation is happening in background
Id:5 Name: State:Running Priority:Normal IsBackground:False
```

即使这是一个微不足道的例子，我们还是必须观察一些事情：

+   首先，我们无法保证关于`Primes calculation …`和`Id:5 …`行的*输出顺序*。它们可能以*相反的顺序*出现。为了获得*确定性行为*，您需要应用我们将在*理解同步原语*部分讨论的同步技术。

+   另一个重要的考虑是*CPU 使用率*。如果你打开**任务管理器**，在**性能**选项卡下，你可以设置查看每个逻辑 CPU 的单独图表。在下面的截图中，你可以看到一个四核 CPU，有八个逻辑核心（多亏了英特尔超线程技术！）。你可能还想显示内核时间（以较深的颜色显示），因为内核模式只执行操作系统和驱动程序的代码，而用户模式（以较浅的颜色显示）只执行我们编写的代码。这种区别将使你立即看到哪个应用程序代码正在执行：

![图 12.3 - 任务管理器显示所有逻辑处理器](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_12.3_B12346.jpg)

图 12.3 - 任务管理器显示所有逻辑处理器

如果我们现在执行我们的代码而没有`Sleep`调用，我们会发现其中一个 CPU 将显示更高的 CPU 使用率，因为一个线程一直在消耗操作系统分配的全部执行时间。这个单个线程会影响总共（100%）CPU 时间的*100% / 8 个 CPU = 12.5%*。事实上，在计算过程中，**任务管理器**的**详细信息**选项卡将显示你的进程大约消耗了 CPU 的 12%：

![图 12.4 - 任务管理器显示分布在所有可用逻辑 CPU 上的执行时间](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_12.4_B12346.jpg)

图 12.4 - 任务管理器显示分布在所有可用逻辑 CPU 上的执行时间

线程计算在多个逻辑 CPU 上*分布*。每当操作系统中断线程，安排另一个进程的其他工作，然后回到我们的线程时，线程可能在任何其他逻辑 CPU 上执行。

只是作为一个实验，你可以通过在`Worker`方法的开头添加以下代码来强制执行在特定的逻辑 CPU 上进行：

```cs
var threads = System.Diagnostics.Process.GetCurrentProcess().Threads;
var processThread = threads
    .OfType<System.Diagnostics.ProcessThread>()
    .Where(pt => pt.Id == GetCurrentThreadId())
    .Single();
processThread.ProcessorAffinity = (IntPtr)2; // CPU 2
```

这段代码需要在类内部进行以下声明：

```cs
[DllImport("Kernel32.dll")]
private static extern int GetCurrentThreadId();
```

这些新的代码行检索了我们进程的所有`ProcessThread`对象的列表，然后过滤出与正在执行的本机 ID 匹配的`ProcessThread`对象。

设置`ProcessorAffinity`后，新的执行将完全加载逻辑 CPU `2`，如下面的截图所示（CPU `2`的浅蓝色部分完全填满了矩形）：

![图 12.5 - 任务管理器显示 CPU 2 完全加载了示例代码的执行](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_12.5_B12346.jpg)

图 12.5 - 任务管理器显示 CPU 2 完全加载了示例代码的执行

在启动线程之前，我们有可能通过设置一个或多个这些属性来塑造线程的特性：

+   `Priority`属性是由操作系统调度程序使用的，用于决定线程可以运行的时间段。给予它高优先级将减少线程挂起的时间。

+   `Name`属性在调试时很有用，因为你可以在 Visual Studio 线程窗口中看到它。

+   我们简要讨论了`ThreadState`属性，它可以有许多不同的值。其中之一——`WaitSleepJoin`——代表一个正在`Wait`方法中或正在睡眠的线程。

+   `CurrentCulture`和`CurrentUICulture`属性由某些依赖于*区域*的 API 读取。例如，当你将数字或日期转换为字符串（使用`ToString`方法）或使用相反的转换的`Parse`静态方法时，当前的区域设置将被使用。

+   `IsBackground`属性指定线程是否应该在仍然活动时阻止进程终止。当为 true 时，进程将不会等待线程完成工作。在我们的示例中，如果你将其设置为 true，那么你可以通过按任意键来结束进程。

你可能已经注意到`Thread`类有`Abort`方法。它不应该被使用，因为它可能会破坏内存状态或阻止托管资源的正确处理。

终止线程的正确方法是从最初启动的方法中正常退出。在我们的情况下，这是`Worker`方法。你只需要一个简单的`return`语句。

我们已经看到了如何手动创建线程，但还有一种更方便的方法可以在单独的线程中运行一些代码——`ThreadPool`类。

## 使用 ThreadPool 类

我们花了一些时间研究线程的特性，这确实非常有用，因为线程是基本的代码执行构建块。手动创建线程是正确的，只要它执行与 CPU 相关且运行时间长的代码。无论如何，由于线程的成本取决于操作系统，因此最好创建适量的线程并重用它们。它们的数量非常依赖于可用的逻辑 CPU 和其他因素，这就是为什么最好使用`ThreadPool`抽象的原因。

静态的`ThreadPool`类提供了一个线程池，可以用来运行一些并发计算。一旦代码终止，线程就会回到池中，可以在不需要销毁和重新创建的情况下，为将来的操作提供可用性。

提示

请注意不要修改从`ThreadPool`中选择的线程的任何属性。例如，如果修改了`ProcessorAffinity`，即使线程被重用于不同的目的，此设置仍将有效。如果需要修改线程的属性，手动创建仍然是最佳选择。

使用`ThreadPool`类运行我们的`Worker`非常简单：

```cs
Console.WriteLine("Start primes");
PrintThreadInfo(Thread.CurrentThread);
ThreadPool.QueueUserWorkItem(Worker);
Console.WriteLine("Primes calculation is happening in background");
```

请注意，`Thread`类构造函数和`QueueUserWorkItem`接受的委托参数是不同的，但接受对象参数的委托对两者都兼容。

我们已经看到了如何启动并行计算，但我们仍然无法编排它们的执行。如果算法应在不同的线程上运行，我们需要知道它的终止以及如何访问结果。

提示

`ThreadPool`被许多流行的库使用，包括随.NET 运行时一起提供的基类库。每当需要访问需要 I/O 操作的资源，而这些操作可能需要一段时间才能成功或失败时，大多数情况下会使用`ThreadPool`。这些资源包括数据库、文件系统对象或可以通过网络访问的任何资源。

每当需要并发访问资源时，无论是通过 I/O 操作检索的资源还是内存中的对象实例，都可能需要同步其访问。在下一节中，我们将看到如何同步线程执行。

# 理解同步原语

每当编写单线程代码时，任何方法执行都是顺序进行的，开发人员无需采取特殊操作。另一方面，当一些代码在单独的线程上执行时，需要同步以确保避免两种危险的并发条件——**竞争**和**死锁**。这些问题的类别在设计时必须小心避免，因为它们的检测很困难，而且可能偶尔发生。

**竞争条件**是指两个或多个线程访问未受保护的共享资源，或者线程的执行根据时间和底层进程架构的不同而表现不同的情况。

*死锁条件*发生在两个或多个线程之间存在循环依赖以访问资源的情况。

编写可能从多个线程执行的代码时，一般建议如下：

+   尽量避免共享资源。它们的访问必须通过锁进行同步，这会影响执行性能。

+   栈是你的朋友。每当调用一个方法时，局部栈是私有的，确保局部变量不会与其他调用者和线程共享。

+   每当您需要在多个线程之间共享资源时，请使用文档验证它是否是线程安全的。每当它不是线程安全的时候，锁必须保护资源或代码序列。

+   即使共享资源是线程安全的，您也必须考虑是否需要原子地执行一些语句，以保证它们的可靠性。

线程库有许多可用于保护资源的原语，但我们将更多地关注那些更有可能在异步上下文中使用的原语，这是本章将涵盖的最重要的主题。

有两组同步原语：

+   由操作系统在*内核模式*中实现的原语

+   由.NET 类库提供的*用户模式*中的同步原语

这种区别非常重要，因为每当您通过系统调用转换到内核模式时，操作系统都必须保存本地调用和堆栈，这将在操作的性能上产生影响。内核模式原语的优势在于能够为它们命名并使它们跨进程共享，提供强大的机器级同步机制。

以下示例显示了来自`ThreadPool`的两个线程打印`Ping`和`Pong`。每个线程通过等待匹配的`ManualResetEventSlim`来与另一个线程同步：

```cs
public void PingPong()
{
    bool quit = false;
    var ping = new ManualResetEventSlim(false);
    var pong = new ManualResetEventSlim(false);
    ThreadPool.QueueUserWorkItem(_ =>
    {
        Console.WriteLine($"Ping thread: {Thread.CurrentThread.ManagedThreadId}");
        while (!quit)
        {
            pong.Wait();
            pong.Reset();
            Console.WriteLine("Ping");
            Thread.Sleep(1000);
            ping.Set();
        }
    });
    ThreadPool.QueueUserWorkItem(_ =>
    {
        Console.WriteLine($"Pong thread: {Thread.CurrentThread.ManagedThreadId}");
        while (!quit)
        {
            ping.Wait();
            ping.Reset();
            Console.WriteLine("Pong");
            Thread.Sleep(1000);
            pong.Set();
        }
    });
    pong.Set();
    Console.ReadKey();
    quit = true;
}
```

创建了两个事件之后，两个线程被运行并打印它们正在运行的线程的 ID。在这些线程内部，每次执行都会在`Wait`方法中暂停，这样可以避免线程消耗任何 CPU 资源。在清单的末尾，`pong.Set`方法启动游戏并解除第一个线程的阻塞。由于事件是*手动*的，它们必须被重置为未发信号状态以供下一次使用。此时，会打印一条消息，延迟模拟一些艰苦的工作，最后，另一个事件被发信号，这将导致第二个线程解除阻塞。

或者，我们可以使用`ManualResetEvent`内核事件，其使用方法非常相似。例如，它具有`WaitOne`方法，而不是`Wait`。但是，如果我们在高性能同步算法中使用这些事件，将会有很大的差异。以下表格显示了使用流行的 Benchmark.NET 微基准库测量的两种同步原语的比较。这两个测试只是调用`Set()`，然后调用`Reset()`方法：

```cs
|          Method |        Mean |     Error |    StdDev |
|---------------- |------------:|----------:|----------:|
| KernelModeEvent | 1,892.11 ns | 24.463 ns | 22.883 ns |
|   UserModeEvent |    25.67 ns |  0.320 ns |  0.283 ns |
```

这两者之间存在大约两个数量级的差异，这绝对不可忽视。

除了能够使用内核事件来同步在不同进程中运行的代码之外，它们还可以与强大的`WaitHandle.WaitAny`和`WaitAll`方法结合使用，如下例所示：

```cs
public void WaitMultiple()
{
    var one = new ManualResetEvent(false);
    var two = new ManualResetEvent(false);
    ThreadPool.QueueUserWorkItem(_ =>
    {
        Thread.Sleep(3000);
        one.Set();
    });
    ThreadPool.QueueUserWorkItem(_ =>
    {
        Thread.Sleep(2000);
        two.Set();
    });
    int signaled = WaitHandle.WaitAny(
        new WaitHandle[] { one, two }, 500);
    switch(signaled)
    {
        case 0:
            Console.WriteLine("One was set");
            break;
        case 1:
            Console.WriteLine("Two was set");
            break;
        case WaitHandle.WaitTimeout:
            Console.WriteLine("Time expired");
            break;
    }
}
```

您可以通过以毫秒为单位表示的三个超时时间来查看不同的结果。主要思想是尽快退出等待，只要任何事件或超时到期，以先到者为准。

提示

Windows 操作系统的内核对象可以在等待原语中全部使用。例如，如果您想等待多个进程退出，您可以使用前面代码块中显示的`WaitHandle`原语与进程句柄一起使用。

我们只是刚刚触及了表面，但官方文档中有许多示例展示了各种同步对象的使用。相反，我们将继续专注于对本书更为相关的内容，例如从多个线程访问共享资源。

在以下示例中，我们有一个名为`_shared`的共享变量，一个用于同时启动所有线程的`ManualResetEvent`对象，以及一个简单的对象。`Shared`属性利用`Thread.Sleep`，在 setter 上引起了显式的线程上下文切换。当操作系统调度程序在系统中将控制权预先交给另一个线程时，这种切换通常会发生。这不是一个技巧；它只是增加了 getter 和 setter 不会被每个线程连续执行的概率：

```cs
int _shared;
int Shared
{
    get => _shared;
    set { Thread.Sleep(1); _shared = value; }
}
ManualResetEvent evt = new ManualResetEvent(false);
object sync = new object();
```

以下方法将共享变量初始化为`0`并创建 10 个线程，所有线程都执行相同的 lambda 中的代码：

```cs
public void SharedResource()
{
    Shared = 0;
    var loop = 100;
    var threads = new List<Thread>();
    for (int i = 0; i < loop; i++)
    {
        var t = new Thread(() =>
        {
            evt.WaitOne();
            //lock (sync)
            {
                Shared++;
            }
        });
        t.Start();
        threads.Add(t);
    }
    evt.Set(); // make all threads start together
    foreach (var t in threads)
        t.Join();   // wait for the thread to finish
    Console.WriteLine($"actual:{Shared}, expected:{loop}");
}
```

所有线程立即启动并阻塞在`WaitOne`事件中，该事件由`Set`方法解除阻塞。这为许多线程以相同的时间执行 lambda 中的代码提供了更多机会。最后，我们调用`Join`等待每个线程的执行结束并打印结果。

这段代码的同步问题存在于线程将读取一个值，将数字增加到 CPU 寄存器中，并将结果写回变量。由于许多线程将读取相同的值，写回变量的值是旧的，其真实的*当前*值丢失了。

通过取消注释锁定语句，我们指示编译器用**关键部分**包围大括号中的语句，这是最快的用户模式同步对象。这将导致对该代码的访问进行序列化，对性能产生非常显著的影响，这是必要且不可避免的。

我们在开始时创建的空对象实例不应更改；否则，不同的线程将等待不同的临界区。请注意，`lock`参数可以是任何引用类型。例如，如果您需要保护一个集合，可以直接锁定它，而无需外部对象的帮助。无论如何，在我们的示例中，`Shared`是一个值类型，必须借助一个单独的引用类型来保护它。

如果您用一个简单的字段替换`Shared`属性，问题发生的可能性将会降低。此外，编译器配置（调试与发布）将产生很大的差异，因为*内联*和其他优化使得在访问字段或简单属性时更有可能发生线程上下文切换。物理硬件配置和 CPU 架构是可能会极大影响这些测试结果的其他变量。

提示

单元测试*不适合*确保不存在竞争条件或死锁等问题。此外，请注意，虚拟机是最不适合测试并发代码的环境，因为调度程序比在物理硬件上运行的操作系统更可预测。

我们已经看到了如何确保一系列语句被原子地执行，没有干扰。但如果只是为了确保底层`_shared`字段的原子增量，有一个更方便的工具——`Interlocked`类。

`Interlocked`是一个静态类，公开了一些有用的方法来确保某些操作的原子性。例如，我们可以使用以下代码而不是`lock`语句，这样做会更快，即使只限于`Interlocked`公开的操作。以下代码显示了如何原子地增加`_shared`变量：

```cs
Interlocked.Increment(ref _shared);
```

除其他事项外，我们可以用它来原子地写入变量并获取旧值（`Exchange`方法），或者读取大小大于可用本机寄存器的变量（`Read`方法）。

我们已经看到了为什么需要同步以及我们可以用来防止这些并发访问问题的主要工具。但现在，是时候引入一个抽象，这将使每个开发人员的生活更轻松——任务范式。

# 任务范式

并发主要是关于设计具有非常松散耦合的工作单元的算法，这通常是不可能的，或者会使复杂性超出任何可能的好处。

异步编程与操作系统和设备的异步性相关，无论是因为它们触发事件还是因为完成所请求的操作需要时间。每当用户移动鼠标、在键盘上输入键或从互联网检索一些数据时，操作系统都会在一个单独的线程中向我们的进程呈现数据，我们的代码必须准备好消费它。

最简单的例子之一是从磁盘加载文本文件并计算字符串长度，这可能与文件长度不同，这取决于编码：

```cs
public int ReadLength(string filename)
{
    string content = File.ReadAllText(filename);
    return content.Length;
}
```

一旦调用此方法，调用线程将被阻塞，直到操作系统和库完成读取。该操作可能非常快速，也可能非常缓慢，这取决于其大小和技术。文本文件可能位于网络附加存储（NAS）、本地磁盘、损坏的 USB 键或通过虚拟专用网络（VPN）访问的远程服务器上。

在桌面应用程序的上下文中，任何阻塞线程都会导致不愉快的用户体验，因为主线程已经负责重绘用户界面并响应来自输入设备的事件。

服务器应用程序也不例外，因为任何阻塞线程都是一种资源，无法有效地与其他请求一起使用，从而阻止应用程序扩展并为其他用户提供服务。

几十年来，解决这个问题的方法是通过手动创建一个单独的线程来执行长时间运行的代码，但是最近，.NET 运行时引入了任务范式，C#语言引入了`async`和`await`关键字。从那时起，整个.NET 库已经进行了修订，以拥抱这种范式，提供返回基于任务的操作的方法。

任务库，位于`System.Threading.Tasks`命名空间中，以及语言集成提供了一个抽象，大大简化了异步操作的管理。任务代表了执行明确定义的工作单元。无论您处理并发性还是异步事件，任务都定义了给定的工作及其生命周期，从创建到完成，其选项包括成功、失败或取消。

通过定义其他任务应该在给定操作之后立即执行来组合任务。这个链接的任务称为**延续**，并且通过**任务调度程序**从库中自动安排。

默认情况下，任务库提供了一个默认实现（`TaskScheduler.Default`静态属性），大多数开发人员永远不需要深入研究。默认实现使用`ThreadPool`来编排任务的执行，并使用*工作窃取*技术将任务队列重新分配到多个线程上，以提供负载平衡，并防止任务被阻塞太长时间。请注意，这个默认实现足够聪明，最终会决定直接在主线程上安排任务的执行，而不是从池中选择一个。勇敢的人可以尝试创建自定义调度程序来改变调度策略，但这并不是很多开发人员真正需要做的事情。

稍后，在*同步上下文*部分，我们将讨论**同步上下文**，它允许延续在调用线程中执行，并避免使用前一节中描述的同步原语的需要。

让我们从读取文本文件的异步版本开始研究任务：

```cs
Task<string> content = File.ReadAllTextAsync(filename);
```

这个方法的新版本*立即完成*，而不是返回文件的内容，而是返回表示*正在进行*操作的对象。

由于我们刚刚启动了尚未完成的操作，管理完成所需的步骤如下：

1.  将异步操作后面的代码（获取字符串长度）重构为一个单独的方法。这个方法相当于旧式的回调，不能在异步操作完成之前调用。

1.  监视正在进行的任务，并在完成或失败时提供通知。

1.  完成后，检索结果并在主线程上同步执行（通过**同步上下文**），或者如果出现问题则抛出异常。如果我们不想搞乱潜在的竞争条件，这一步是至关重要的。

1.  调用我们在第一个点重构出来的回调。

当然，我们不必手动管理所有这些机制。任务库的第一个有趣的优势是它支持继续，这允许开发人员指定任务成功完成后要执行的代码：

```cs
public Task<int> ReadLengthAsync(string filename)
{
    Task<int> lengthTask = File.ReadAllTextAsync(filename)
        .ContinueWith(t => t.Result.Length);
    return lengthTask;
}
```

这个新版本比创建线程和手动编写同步代码要好，即使它还可以进一步改进。`ContinueWith`方法包含了确定其他代码在文件成功读取后立即执行的代码。

`t`变量包含任务，该任务要么失败，要么成功完成。如果成功，`t.Result`包含从`ReadAllTextAsync`方法获取的字符串内容。

无论如何，我们仍然没有长度；我们只是表达了如何在*将来*检索`ReadAllTextAsync`的结果后检索长度。这就是为什么`lengthTask`变量是`Task<int>`，即整数的承诺。

我强烈建议尝试使用任务和继续，因为有时它们需要直接管理。

但 C#语言还引入了两个宝贵的关键字，进一步简化了我们需要编写的代码。`await`关键字用于指示操作的结果以及其后的所有内容都是一个继续的一部分。

由于`await`关键字，编译器重构并生成新的**中间语言**（**IL**）代码，以提供适当的异步操作和继续的管理。最终的代码以异步方式加载文件内容并返回字符串长度如下：

```cs
public async Task<int> ReadLengthAsync(string filename)
{
    string content = await File.ReadAllTextAsync(filename);
    return content.Length;
}
```

编译器重构的代码部分不仅仅是一个继续。编译器生成一个*类*来负责监视任务进度的状态机，并生成一个调用适当代码或抛出异常的方法，一旦任务状态发生变化。

提示

如果您想深入了解生成的代码的更多细节，可以使用**ILSpy**工具（https://github.com/icsharpcode/ILSpy/releases）并查看生成的 IL 代码。

显然，编译器可以摆脱承诺，让我们处理返回的内容，对吗？实际上不是 - 这段代码被重构了，我们编写的代码是表达我们的期望，而不是方法中通常和顺序发生的事情。

事实上，前面的代码看起来矛盾，因为`content.Length`整数只会在将来可用，但我们直接从返回类型为`Task<int>`的方法中返回它。

这就是`async`关键字发挥作用的地方：

+   `async`关键字是一个修饰符，每次我们想在方法内部使用`await`时都必须指定。

+   `async`关键字告诉我们，`return`语句指定了一个未来的对象或值。在我们的情况下，我们返回`int`，但`async`告诉我们它实际上是一个`Task<int>`。

+   如果一个`async`方法返回`void`，返回类型变成了非泛型的`Task`。

我们现在有一个异步处理文件的方法，但我们不得不将签名从`int`改为`Task<int>`。

当您在 lambda 中使用`await`关键字时，也需要使用`async`关键字。例如，让我们看一下以下代码：

```cs
Func<int, int, Task<int>> adder = 
    async (a, b) => await AddAsync(a, b);
```

在方法上使用`async`意味着所有调用者也必须采用任务范式，否则他们可能无法知道操作何时完成。

## 异步方法的同步实现

我们已经看到了任务范例如何影响方法签名，我们知道方法签名有多重要。当它出现在公共 API 或接口中时，它是一个合同，大多数情况下我们不能更改。从设计的角度来看，对于预期可能使用任务实现的方法的可能性，这可能非常有价值，但也有一些不需要异步性的情况。

对于这些情况，`Task`类公开了一个静态方法，允许我们直接构建一个带有或不带结果的已完成任务。在下面的示例中，异步方法同步返回一个已完成的任务：

```cs
public Task WriteEmptyJsonObjectAsync(string filename)
{
    File.WriteAllText(filename, "{}");
    return Task.CompletedTask;
}
```

`CompletedTask`属性仅为整个应用程序域创建一次；因此，它非常轻量级，不应引起性能方面的担忧。

如果需要返回一个值，我们可以使用静态的`FromResult`方法，它在每次调用时内部创建一个新的已完成`Task`：

```cs
public Task<int> AddAsync(int a, int b)
{
    return Task.FromResult(a + b);
}
```

每次我们添加两个数字时创建一个对象绝对是性能问题，因为它直接影响垃圾收集器需要做的工作量。因此，最近，微软引入了`ValueTask`类。

## 偶尔的异步方法

`ValueTask`不可变结构是对同步结果或`Task`的便捷包装。这种进一步的抽象旨在简化那些需要方法具有异步签名，但其实现只是偶尔异步的情况。

我们在上一节中使用任务定义的`AddAsync`方法可以很容易地转换为使用`ValueTask`结构：

```cs
public ValueTask<int> AddAsync(int a, int b)
{
    return new ValueTask<int>(a + b);
}
```

对于微不足道的总和使用`Task`的开销是明显的；因此，每当在热路径（一些性能关键代码）中应该调用这样的方法时，肯定会引起性能问题。

无论如何，有些情况下，您可能需要将`ValueTask`转换为`Task`，以便从本章剩余部分讨论的所有实用工具中受益。转换可通过`AsTask`方法实现，该方法返回包装的任务（如果有），或者如果没有，则创建一个全新的`Task`。

## 中断任务链 - 阻塞线程

给定一个任务，如果调用`Wait`方法或访问`Result`获取器属性，它们将阻塞线程执行，直到任务完成或取消。任务范例背后的理念是避免阻塞线程，以便它们可以被重用于其他目的。但是阻塞也可能引发非常严重的副作用。

由于异步编程的默认线程来源是`ThreadPool`（如果耗尽其线程），任何进一步的请求都将自动阻塞。这种现象被称为**线程饥饿**。

一般建议是避免等待，而是使用`await`关键字或延续来完成一些工作。

## 手动创建任务

有时库不提供异步行为，但您不希望保持当前线程忙碌太长时间。在这种情况下，您可以使用`Task.Run`方法，该方法安排执行 lambda，这很可能会发生在一个单独的线程中。下面的示例展示了如何读取文件的长度，如果我们之前使用的异步`ReadAllTextAsync`方法不可用：

```cs
public Task<int> ReadLengthAsync(string filename)
{
    return Task.Run<int>(() =>
    {
        var content = File.ReadAllText(filename);
        return content.Length;
    });
}
```

您应该始终优先使用提供的异步版本，而不是使用`Run`方法，因为安排此任务的线程将一直阻塞，直到同步执行结束。

现在，我们将看看在任务内部有大量工作要做时，采取的最佳行动方案是什么。

## 长时间运行的任务

即使您不阻塞线程，当异步堆栈从不等待并成为长时间运行的作业时，仍然存在饥饿的风险，使线程保持忙碌。

这些情况可以用两种不同的策略来处理：

+   第一种是手动“创建线程”，这是我们在本章开头已经讨论过的。当你需要更多控制或需要修改线程属性时，这是最好的策略。

+   第二种可能性是*通知任务调度程序*任务将要运行很长时间。这样，调度程序将采取不同的策略，完全避免`ThreadPool`。以下代码显示了如何运行一个长时间运行的任务：

```cs
var t = new Task(() => Thread.Sleep(30000),
    TaskCreationOptions.LongRunning);
t.Start();
```

基本建议是尝试将长时间的工作拆分成可以轻松转换为任务的较小工作单元。

## 打破任务链 - 火而忘

我们已经看到，拥抱任务范式需要修改整个调用链。但有时这是不可能的，也不可取。例如，在桌面 WPF 应用程序的上下文中，您可能需要在按钮点击事件处理程序中写入文件：

```cs
void Button_Click(object sender, RoutedEventArgs e) { ... }
```

我们不能改变它的签名来返回一个`Task`；而且，出于两个原因，这也没有意义：

+   调用库在任务之前设计过，它将无法管理任务的进度。

+   这是设计为**火而忘**操作之一，意味着你并不真的在乎它们会花多长时间或者它们将计算出什么结果。

对于这些情况，你可以拥抱`async`/`await`关键字，同时根本不使用返回的`Task`：

```cs
async void Button_Click(object sender, RoutedEventArgs e)
{
    await File.WriteAllTextAsync("log.txt", "something");
    // ... other code
}
```

但请记住，当你打破任务链时，你失去了知道操作是否会完成或失败的可能性。

信息框

每当你在你的代码中看到`async void`时，你应该想知道它是否可能是一个潜在的错误，或者只是你真的不想知道最终会发生什么。多年来，使用`async void`而不是`async Task`的习惯一直是异步代码中错误的主要来源。

同样，如果你只是调用一个异步方法而不等待它（或使用`ContinueWith`方法之一），你将失去对调用的控制，获得相同的*火而忘*行为，因为异步方法在启动异步操作后立即返回。此外，不等待异步操作之后的所有代码将同时执行，存在竞争条件或访问尚不可用的数据的风险：

```cs
void Button_Click(object sender, RoutedEventArgs e)
{
    File.WriteAllTextAsync("log.txt", "something");
}
```

我们已经看到了当一切顺利完成时管理异步操作是多么简单，但代码可能会抛出异常，我们需要适当地捕获它们。

## 任务和异常

当出现问题时，有两种异常可能发生。第一种是在调用任何异步方法之前发生的，而第二种与异步代码中发生的异常有关。

以下示例展示了这两种情况：

```cs
public Task<int> CrashBeforeAsync()
{
    throw new Exception("Boom");
}
public Task<int> CrashAfterAsync()
{
    return Task.FromResult(0)
        .ContinueWith<int>(t => throw new Exception("Boom"));
}
```

在第一种情况下，我们告诉调用者我们将返回一个`Task<int>`，但还没有开始任何异步操作。这种情况与同步方法中发生的情况完全相同，可以相应地捕获：

```cs
public Task<int> HandleCrashBeforeAsync()
{
    Task<int> resultTask;
    try
    {
        resultTask = CrashBeforeAsync();
    }
    catch (Exception) { throw; }
    return resultTask;
}
```

另一方面，如果异常发生在继续执行中，异常不会立即发生；它只会在任务被“消耗”时发生：

```cs
public async Task<int> HandleCrashAfterAsync()
{
    Task<int> resultTask = CrashAfterAsync();
    int result;
    try
    {
        result = await resultTask;
    }
    catch (Exception) { throw; }
    return result;
}
```

一旦`resultTask`完成为*故障*，异常已经发生，但是编译器生成的代码捕获了它并将其分配给`Task.Exception`属性。由于在`Task`内可能同时发生多个异常，生成的代码将所有捕获的异常封装在单个`AggregateException`中。`AggregateException`中的`InnerException`和`InnerExceptions`属性包含原始异常。

每当你想要处理异常并立即解决它们时，你可能希望使用继续而不是`await`关键字：

```cs
public Task<int> HandleCrashAfter2Async()
{
    Task<int> resultTask = CrashAfterAsync();
    try
    {
        return resultTask.ContinueWith<int>(t =>
        {
           if (t.IsCompletedSuccessfully) return t.Result;
           if(t.Exception.InnerException is OverflowException)
               return -1;
           throw t.Exception.InnerException;
        });                
    }
    catch (Exception) { throw; }
}
```

正如我们之前提到的，在*faulted*任务中的异常会在结果被*消耗*时立即抛出，我们之前在使用`await`的情况下提到过。然而，当访问`t.Result`属性时，这也可能发生。

提示

`Task`类公开了`GetAwaiter`方法，该方法返回表示异步操作的内部结构。你可以使用`task.GetAwaiter().GetResult()`来获取异步操作的结果，以及`task.Result`，但两者有一点不同。实际上，在发生异常时，前者返回原始异常，而后者返回包含原始异常的`AggregateException`。

最后，值得一提的是，我们可以使用静态的`Task.FromException<T>`方法来重写`CrashAfterAsync`方法：

```cs
public Task<int> CrashAfterAsync() =>
    Task.FromException<int>(new Exception("Boom"));
```

与我们在`FromResult<T>`中看到的类似，创建了一个新的`Task`，但这次，它的状态被初始化为*faulted*，并包含所需的异常。

前面的例子相当抽象，但足够简洁，让你了解如何根据抛出异常的时间来正确处理异常。有许多常见的情况会发生这种情况。这种二元性的一个真实例子是，在准备 JSON 参数时发生序列化异常，或者在 HTTP rest 调用期间由于网络故障而发生异常。

除了转换为故障状态，任务也可以被取消，这要归功于任务范例提供的内置标准机制。

## 取消任务

与故障不同，取消是由调用者请求来中断一个或多个任务的执行。取消可以是强制性的，也可以是超时，当给定任务不应该花费超过一定时间时，这是非常有用的。

从调用者的角度来看，取消模式源自`CancellationTokenSource`类，它提供了三种不同的构造函数：

+   当你愿意通过强制调用`Cancel`方法来取消任务时，使用默认构造函数。

+   其他构造函数接受`int`或`TimeSpan`，它们确定在触发取消之前的最长时间，除非任务在此之前完成。

在下面的例子中，我们将使用从定时`CancellationTokenSource`获得的`CancellationToken`来取消三个工作方法中的一个：

```cs
public async Task CancellingTask()
{
    CancellationTokenSource cts2 = new
        CancellationTokenSource(TimeSpan.FromSeconds(2));
    var tok2 = cts2.Token;
    try
    {
        await WorkForever1Async(tok2);
        //await WorkForever2Async(tok2);
        //await WorkForever3Async(tok2);
        Console.WriteLine("let's continue");
    }
    catch (TaskCanceledException err)
    {
        Console.WriteLine(err.Message);
    }
}
```

`Token`属性返回一个只读结构，可以被多个消费者使用，而不会影响垃圾收集器，甚至不会被复制，因为它是不可变的。

这里正在检查的第一个消费者接受`CancellationToken`，并将其正确传播给任何其他接受取消的方法。在我们的例子中，只有`Task.Delay`，这是一个非常方便的方法，用于指示基础设施在 5 秒后触发继续执行：

```cs
public async Task WorkForever1Async(
    CancellationToken ct = default(CancellationToken))
{
    while (true)
    {
        await Task.Delay(5000, ct);
    }
}
```

前面代码的执行结果是任务被取消，这通过从`await`关键字生成的代码转换为`TaskCanceledException`：

```cs
A task was canceled.
```

另一种可能性是，当工作程序只执行*同步*代码并且仍然需要被取消时：

```cs
public Task WorkForever2Async(
    CancellationToken ct = default(CancellationToken))
{
    while (true)
    {
        Thread.Sleep(5000);
        if (ct.IsCancellationRequested)
            return Task.FromCanceled(ct);
    }
}
```

请注意使用`Thread.Sleep`而不是`Delay`方法，这是因为我们需要同步实现。

`Thread.Sleep`方法非常不同，因为它完全阻塞线程，并防止线程在其他任何地方被重用，而`Task.Delay`会生成一个请求，在指定的时间过去后立即调用以下代码作为继续执行。

更有趣的部分是测试`IsCancellationRequested`布尔属性，以允许协作取消任务。通过显式检查该属性来进行协作是必要的，因为在释放某些资源之前，你可能不需要中断执行，无论是在数据库上还是其他地方。

再次执行前面的方法的结果将如下：

```cs
A task was canceled.
```

第三种情况是当你不想抛出任何异常，而只是从执行中返回：

```cs
public async Task WorkForever3Async(
    CancellationToken ct = default(CancellationToken))
{
    while (true)
    {
        await Task.Delay(5000);
        if (ct.IsCancellationRequested) return;
    }
}
```

在这种情况下，我们小心地避免将`CancellationToken`传播到底层调用，因为使用`await`会触发异常。

这个最终的`WorkForever3Async`方法的执行不会引发任何异常，并让执行继续正常进行：

```cs
let's continue
```

这种实现的缺点是取消可能不会立即发生。`Task.Delay`将需要完成，而不管取消，这在最坏的情况下可能在 5 秒之前无法发生。

我们已经看到任务范式如何使运行异步操作变得极其容易，但我们如何同时运行多个异步请求呢？它们可能会并行运行，以避免无用的等待。

## 监视任务的进度

用户开始长时间运行操作后，提供反馈非常重要，以避免用户变得沮丧。当你控制正在发生的事情时，比如一些耗时的算法，这是可能的。然而，当长时间运行的操作依赖于对外部库的调用时，监视进度是不可能的。

任务库没有专门支持监视进度，但.NET 库提供了`IProgress<T>`，可以轻松实现这一目标。这个接口只提供一个成员——`void Report(T value)`——这给了实现细节完全的自由。在最简单的情况下，`T`将是一个表示进度的整数值，表示为百分比。

例如，加载操作可以实现如下：

```cs
public async Task Load(IProgress<int> progress = null)
{
    var steps = 30;
    for (int i = 0; i < steps; i++)
    {
        await Task.Delay(300);
        progress?.Report((i + 1) * 100 / steps);
    }
}
```

在我们的情况下，这个方法通过调用`Task.Delay`来模拟异步操作，必须预测与进度的 100%相关的总步数。在每一步之后，调用`Report`方法来通知我们当前的百分比，但要确保代码受到保护，以防进度为空，因为消费者可能对接收这样的反馈不感兴趣。

在消费者端，首先要做的是创建进度提供程序，这只是一个实现`IProgress<int>`的类：

```cs
public class ConsoleProgress : IProgress<int>
{
    void IProgress<int>.Report(int value) =>
        Console.Write($"{value}%  ");
}
```

最后，调用者只需将提供程序实例传递给`Load`方法：

```cs
await test.Load(new ConsoleProgress());
```

正如你所期望的那样，输出如下：

```cs
3%  6%  10%  13%  16%  20%  23%  26%  30%  33%  36%  40%  43%  46%  50%  53%  56%  60%  63%  66%  70%  73%  76%  80%  83%  86%  90%  93%  96%  100%
```

`IProgress<T>`的通用参数可能被用来暂停执行或触发更复杂的逻辑，比如暂停/恢复行为。

## 并行化任务

一个常见的编程任务是从互联网上检索一些资源。例如，通过 HTTP 下载资源的基本代码如下：

```cs
public async Task<byte[]> GetResourceAsync(string uri)
{
    using var client = new HttpClient();
    using var response = await client.GetAsync(uri);
    response.EnsureSuccessStatusCode();
    return await response.Content.ReadAsByteArrayAsync();
}
```

由于`EnsureSuccessStatusCode`，任何失败都会触发异常，将捕获的责任留给调用者。此外，我们甚至没有设置任何标头，但对我们的目的来说已经足够了。

我们已经知道如何调用这个异步方法来下载图像，但现在的挑战是选择正确的策略来下载许多图像：

+   第一个问题是：*我们如何并行下载多个图像？* 如果我们需要下载 10 张图像，我们不想将下载每张图像所需的时间相加。无论如何，我们不会讨论如果我们需要下载数百万张图像时可以扩展多少。这超出了关于异步机制的讨论范围。

+   第二个问题是：*我们需要同时使用它们吗？* 在这种情况下，我们可以使用`Task.WhenAll`辅助方法，它接受一个任务数组，并返回一个表示整体操作的单个任务。

对于这些示例，我们将使用名为*Lorem PicSum*（[`picsum.photos/`](https://picsum.photos/)）的在线免费服务。每次你向代码中看到的 URI 发出请求时，都会检索到一个新的不同大小为 200 x 200 的图像。当然，你可以使用你选择的任何 URI：

```cs
public async Task NeedAll()
{
    var uri = "https://picsum.photos/200";
    Task<byte[]>[] tasks = Enumerable.Range(0, 10)
        .Select(_ => GetResourceAsync(uri))
        .ToArray();
    Task allTask = Task.WhenAll(tasks);
    try
    {
        await allTask;
    }
    catch (Exception)
    {
        Console.WriteLine("One or more downloads failed");
    }
    foreach (var completedTask in tasks)
        Console.WriteLine(
            $"New image: {completedTask.Result.Length}");
}
```

使用`Enumerable.Range`是一种很好的方式，可以重复执行给定次数的操作。实际上，我们并不关心生成的数字；事实上，我们在`Select`方法中使用了`discard (_)`标记而不是变量。

`Select` lambda 只是启动下载操作，返回相应的任务，我们还没有等待。相反，我们要求`WhenAll`方法创建一个新的`Task`，一旦所有任务都成功完成，就会发出信号。如果任何任务失败，从`await`关键字生成的代码将导致抛出异常。

从`WhenAll`方法获得的任务不能用于检索结果，但它保证我们可以访问所有任务的`Result`属性。因此，在等待`allTask`之后，我们迭代`tasks`数组，检索所有已下载图像的`byte[]`数组。以下是同时等待所有下载的输出：

```cs
New image: 6909
New image: 3846
New image: 8413
New image: 9000
New image: 7057
New image: 8565
New image: 6617
New image: 8720
New image: 4107
New image: 6763
```

在许多情况下，这是一个很好的策略，因为我们可能需要在继续之前获取所有资源。另一种选择是等待第一次下载，这样我们就可以开始处理它，但我们仍然希望同时下载它们以节省时间。

这种替代策略可以借助`WaitAny`方法来实现。在下面的示例中，开始下载没有什么不同。我们只是添加了一个`Stopwatch`类，以显示下载结束时花费的毫秒数：

```cs
public async Task NeedAny()
{
    var sw = new Stopwatch();
    sw.Start();
    var uri = "https://picsum.photos/200";
    Task<byte[]>[] tasks = Enumerable.Range(0, 10)
        .Select(_ => GetResourceAsync(uri))
        .ToArray();
    while (tasks.Length > 0)
    {
        await Task.WhenAny(tasks);
        var elapsed = sw.ElapsedMilliseconds;
        var completed = tasks.Where(t => t.IsCompleted).ToArray();
        foreach (var completedTask in completed)
            Console.WriteLine($"{elapsed} New image: {completedTask.Result.Length}");
        tasks = tasks.Where(t => !t.IsCompletedSuccessfully).ToArray();
    }
}
```

`while`循环用于处理所有未完成的任务。最初，`tasks`数组包含所有任务，但每次`WhenAny`完成时，至少一个任务已完成。已完成的任务立即在屏幕上打印出来，并显示自操作开始以来经过的毫秒数。其他任务被重新分配给`tasks`变量，这样我们就可以循环回去处理已完成的任务，直到最后一个任务。这种新方法的输出如下：

```cs
368 New image: 9915
368 New image: 6032
419 New image: 6486
452 New image: 9810
471 New image: 7030
514 New image: 10009
514 New image: 10660
593 New image: 6871
658 New image: 2738
12850 New image: 6072
The last image took a lot of time to download, probably because the online service throttles the requests. Using WhenAll, we would have to wait about 13 seconds before getting them all. Instead, we could start processing as soon as each image was available.
```

当然，你可以将这两种方法结合起来。例如，如果你想在不超过 100 毫秒的时间内尽可能多地获取已下载的图像，只需用以下一行替换`WhenAny`行：

```cs
await Task.WhenAll(Task.Delay(100), Task.WhenAny(tasks));
```

换句话说，我们要求等待任何任务（至少一个），但不超过 100 毫秒。`while`循环将重复操作，就像我们之前所做的那样，消耗所有剩余的任务：

```cs
345 New image: 8416
345 New image: 7315
345 New image: 8237
345 New image: 6391
345 New image: 5477
457 New image: 9592
457 New image: 3922
457 New image: 8870
563 New image: 3695
```

在测试这些代码片段时，一定要在循环中运行它们，因为第一次运行可能会受到**即时**编译器的严重影响。

我们已经看到`Task`类提供了一个非常强大的构建块来消耗异步操作，但这需要提供异步行为的库。在下一节中，我们将看到如何暴露手动任务并触发其完成。

## 使用`TaskCompletionSource`对象发出任务信号

回到本章开头*什么是线程？*部分的文件监视器示例中，你可能还记得`FileSystemWatcher`暴露了事件，而没有采用任务范例。你可能会想知道我们是否编写了某种适配器来利用任务库提供的所有好工具的能力，答案是*是*。

`TaskCompletionSource`对象提供了一个重要的构建块，我们可以用它来暴露异步行为。它在生产者端创建和使用，以信号操作的完成，无论是成功还是失败。它通过`Task`属性提供了任务对象，客户端必须使用它来等待通知。

以下类使用`FileSystemWatcher`来监视当前文件夹中的文件系统。`Deleted`事件停止通知并通知完成源文件成功删除。类似地，`Error`事件设置了最终将在`await`语句的消费方触发的异常：

```cs
public class DeletionNotifier : IDisposable
{
   private TaskCompletionSource<FileSystemEventArgs> _tcs;
   private FileSystemWatcher _watcher;
   public DeletionNotifier()
   {
      var path = Path.GetFullPath(".");
      Console.WriteLine($"Observing changes in path: {path}");
      _watcher = new FileSystemWatcher(path, "*.txt");
      _watcher.Deleted += (s, e) =>
      {
         _watcher.EnableRaisingEvents = false;
         _tcs.SetResult(e);
      };
      _watcher.Error += (s, e) =>
      {
         _watcher.EnableRaisingEvents = false;
         _tcs.SetException(e.GetException());
      };
  }
  public Task<FileSystemEventArgs> WhenDeleted()
  {
    _tcs = new TaskCompletionSource<FileSystemEventArgs>();
    _watcher.EnableRaisingEvents = true;
    return _tcs.Task;
  }
  public void Dispose() => _watcher.Dispose();
}
```

每当调用`WhenDeleted`方法时，都会创建一个新的完成源，启动文件监视器，并将负责通知的`Task`返回给客户端。

从消费者的角度来看，这个解决方案很棒，因为它消除了任何复杂性：

```cs
var dn = new DeletionNotifier();
var deleted = await dn.WhenDeleted();
Console.WriteLine($"Deleted: {deleted.Name}");
```

这种解决方案的缺点是一次只能检测到一个删除。

此外，由于`Deleted`事件中的代码关闭了通知，循环内调用`WhenDeleted`方法可能会导致删除事件丢失。

但我们可以解决这个问题！稍微复杂一点的解决方案是将事件缓冲在一个线程安全的队列中，并通过出队可用事件的方式改变`WhenDeleted`方法的策略，如果有的话。

以下是修改后的代码：

```cs
public class DeletionNotifier : IDisposable
{
  private TaskCompletionSource<FileSystemEventArgs> _tcs;
  private FileSystemWatcher _watcher;
  private ConcurrentQueue<FileSystemEventArgs> _queue;
  private Exception _error;
  public DeletionNotifier()
  {
    var path = Path.GetFullPath(".");
    Console.WriteLine($"Observing changes in path: {path}");
    _queue = new ConcurrentQueue<FileSystemEventArgs>();
    _watcher = new FileSystemWatcher(path, "*.txt");
    _watcher.Deleted += (s, e) =>
    {
      _queue.Enqueue(e);
      _tcs.TrySetResult(e);
    };
    _watcher.Error += (s, e) =>
    {
      _watcher.EnableRaisingEvents = false;
      _error = e.GetException();
      _tcs.TrySetException(_error);
    };
    _watcher.EnableRaisingEvents = true;
  }
  public Task<FileSystemEventArgs> WhenDeleted()
  {
    if (_queue.TryDequeue(out FileSystemEventArgs fsea))
      return Task.FromResult(fsea);
    if (_error != null)
      return Task.FromException<FileSystemEventArgs>(_error);
    _tcs = new TaskCompletionSource<FileSystemEventArgs>();
    return _tcs.Task;
  }
  public void Dispose() => _watcher.Dispose();
}
```

再一次，我们可以仅使用任务库工具来解决问题。根据用例，这种策略需要每次重新创建一个新的`TaskCompletionSource<T>`，并且由于它是一个引用类型，可能会影响性能，受到垃圾回收的影响。如果我们需要重用相同的通知对象，我们可以通过创建一个自定义通知对象来实现。

实际上，`await`关键字只需要一个实现了名为`GetAwaiter`的方法的对象，返回一个实现了`INotifyCompletion`接口的对象。这个对象又必须实现一个`IsCompleted`属性和模拟`TaskCompletionSource`行为的所有必需机制。

在*进一步阅读*部分，你会发现一篇有趣的文章，名为*await anything*，来自微软官方博客，深入探讨了这个主题。

## 同步上下文

根据我们正在编写的应用程序，不是所有的线程都是平等的。桌面应用程序有一个主线程，只允许在屏幕上绘制和处理图形控件。GUI 库围绕着消息队列的概念工作，每个请求都被发布。主线程负责出队这些消息，并将它们分派到实现所需行为的用户定义处理程序中。

每当在 UI 线程之外的线程上发生某些事件时，必须进行编组操作，这将导致消息被发布到主线程管理的队列中。在 UI 线程中编组消息的两个常见示例是 Windows Forms 应用程序中的`Control.Invoke`和 Windows Presentation Foundation 中的`Dispatcher.Invoke`。

信息框

WPF 的第一个预发布版本是多线程的。但是，代码复杂性要求用户处理多线程，并且用户代码中可能出现的 bug 提高了门槛。甚至许多 C++库，如 DirectX 和 OpenGL，大多数都是单线程的，以减少复杂性。

在服务器端，ASP.NET 应用程序也有主线程的上下文，但实际上不只有一个——事实上，每个用户的请求都有自己的主线程。

`SynchronizationContext`是一个抽象的基类，定义了一种在*特殊*线程上执行一些代码的标准方式。这并不是魔术；事实上，正在执行的代码是在一个 lambda 中定义的，并且被发布到一个队列中。在主线程上，基础设施提供的一些代码会出队 lambda，并在其上下文中执行它。

这种自动编组是基本的，因为在执行任何异步方法之后，比如从互联网下载图像，你希望避免调用`Invoke`方法，该方法需要将结果编组回主线程，这是为了使用返回的数据更新用户界面所必需的。

每当你等待某个异步操作时，生成的代码会负责*捕获*当前的`SynchronizationContext`，并确保继续在特定线程上执行。基本上，你不需要做任何事情，因为基础设施已经为你做了。

我们完成了吗？实际上并没有，因为有时情况并非如此。根据我们所说，以下示例中的三个 ID 应该都是相同的：

```cs
public async Task AsyncTest1()
{
    Console.WriteLine($"Id: {Thread.CurrentThread.ManagedThreadId}");
    await Task.Delay(100);
    Console.WriteLine($"Id: {Thread.CurrentThread.ManagedThreadId}");
    await Task.Delay(100);
    Console.WriteLine($"Id: {Thread.CurrentThread.ManagedThreadId}");
}
```

这不是因为它是一个默认情况下不设置任何同步上下文的控制台应用程序。这是因为在 Microsoft 的`Console`类的文档中有原因。您会在文档页面的末尾看到*线程安全*部分，其中指出*此类型是线程安全的*。换句话说，没有理由返回到原始线程。

如果您创建一个新的 Windows Forms 应用程序，并在按钮单击处理程序中调用该代码，您会发现 ID 始终相同，这要归功于`SynchronizationContext`。

始终重要的是要了解异步代码在线程方面发生了什么，因为有时将结果返回到主线程不是理想的，因为返回有性能影响。例如，库开发人员在编写异步代码时必须非常小心，因为他们无法知道他们的代码是否会在有同步上下文或没有同步上下文的情况下执行。

一个明显的例子是库开发人员正在处理来自网络的数据块。每个块都是通过异步 HTTP 请求检索的，块的数量可能非常多，就像以下示例中一样：

```cs
public async Task AsyncLoop()
{
    Console.WriteLine($"Id: {Thread.CurrentThread.ManagedThreadId}");
    byte[] data;
    while((data = await GetNextAsync()).Length > 0)
    {
        Console.WriteLine($"Id: {Thread.CurrentThread.ManagedThreadId}");
        // process data
    }
}
```

除非处理代码将与 UI（或与主线程相关的任何内容）交互，禁用同步上下文绝对是性能的提升，并且非常容易实现：

```cs
public async Task AsyncLoop()
{
    Console.WriteLine($"Id: {Thread.CurrentThread.ManagedThreadId}");
    byte[] data;
    while((data = await GetNextAsync().ConfigureAwait(false)).Length > 0)
    {
        Console.WriteLine($"Id: {Thread.CurrentThread.ManagedThreadId}");
        // process data
    }
} 
```

通过将`ConfigureAwait`方法应用于异步方法，操作的结果将不会发布回主线程，并且生成的继续将在辅助线程上执行（无论异步操作是否计划在不同的线程上）。

这种修改后的行为有两个后果：

+   将消息发布到主线程队列会产生*性能影响*。例如，库开发人员可能希望在进行一些内部工作时将`ConfigureAwait`设置为`false`以提高性能。

+   每当您决定使用`Wait`方法或`Result`属性同步执行异步方法时，您可能会遇到*死锁*。这可能是因为同步上下文将执行返回到繁忙的主线程。虽然应该通过永远不使用`Wait`和`Result`来避免这种情况，但另一种方法是通过将`ConfigureAwait`设置为`false`，使调用在辅助线程上完成执行。

请注意，如果您真的希望在辅助线程上继续执行，确保对所有后续调用应用`ConfigureAwait`。事实上，第一个异步调用在没有使用`ConfigureAwait`的情况下执行将导致执行返回到主线程。

由于`ConfigureAwait`后面的代码在辅助线程上执行，记得手动返回到主线程，以避免竞争条件。例如，要更新 UI，您必须调用相关的*Windows Forms*或*WPF* `Invoke`方法。

任务范式是编程语言中的一场革命，如果没有新语言关键字和编译器生成的魔法，它是无法存在的。这一新特性在其他语言中也引起了很大的共鸣。例如，ECMAScript 2017 通过提供承诺和 async/await 关键字支持来采纳了这些概念。

在这一漫长的章节中，我们学到了异步编程的重要性，以及任务库如何使异步代码直观且易于编写，同时又不会让我们过多地去关注隐含的复杂性。除了获得对这些工具的一般理解之外，现在重要的是要进行实验并深入研究每个方面，以掌握这些技术。

# 总结

在本章中，我们讨论了任何开发人员都可以利用的最重要的工具，以利用多线程和异步编程技术。

构建块是基本的抽象，允许代码在不同的执行上下文中运行，而不管它们当前运行在哪个操作系统上。这些原语必须以智慧使用，但与本地语言和库相比，这并不以任何方式限制开发人员的可能性。

除此之外，当涉及到与那些本质是异步的事件交互时，任务范式提供了一种自然的方法。`System.Threading.Tasks`命名空间提供了与异步现象交互所需的所有抽象。

该库已经被广泛重组和扩展以支持任务范式。最重要的是，该语言提供了`async`和`await`关键字来分解复杂性，并使异步世界流畅地进行，就像是过程性代码一样。

在下一章中，我们将学习文件、文件流和序列化的概念。

# 测试你所学到的东西

1.  如果你有一个非常消耗 CPU、持续时间很长的算法要运行，你会采用手动创建线程、使用任务库还是使用线程池中的哪种策略？

1.  命名一个可以用来写文件并增加内存中整数值的高效同步技术。

1.  你应该使用什么方法来暂停执行 100 毫秒，为什么？

1.  你应该怎么做来等待多个异步操作产生的结果？

1.  你如何创建一个等待 CLR 事件的任务？

1.  当一个方法的签名中有`Task`但没有使用任何异步方法时，你应该返回什么？

1.  你如何创建一个长时间运行的任务？

1.  一个按钮点击处理程序正在异步访问互联网以加载一些数据。你应该使用`Control.Invoke`来更新屏幕上的结果吗？为什么？

1.  在一个`Task`上评估使用`ConfigureAwait`方法的原因是什么？

1.  在使用了`ConfigureAwait(false)`之后，你能直接更新 UI 吗？

# 进一步阅读

+   一个非常强大的库，可以用来测量一些代码的性能是 Benchmark.NET ([`benchmarkdotnet.org/articles/overview.html`](https://benchmarkdotnet.org/articles/overview.html))，这也被微软内部用来对运行时和核心库进行优化。

+   如果你想构建自己的*awaitable*对象，你不能错过微软团队的这篇文章，描述了基础架构的工作原理：[`devblogs.microsoft.com/pfxteam/await-anything/`](https://devblogs.microsoft.com/pfxteam/await-anything/)。

+   要深入了解同步上下文和`ConfigureAwait`，你可以阅读以下文章：[`devblogs.microsoft.com/dotnet/configureawait-faq/`](https://devblogs.microsoft.com/dotnet/configureawait-faq/)。


# 第十三章：文件、流和序列化

编程主要涉及处理可能来自各种来源的数据，例如本地内存、磁盘文件或通过网络从远程服务器获取的数据。大多数数据必须被持久化，以供长时间或无限期使用。它必须在不同应用程序重新启动之间可用，或在多个应用程序之间共享。无论存储是纯文本文件还是各种类型的数据库，无论它们是本地的、来自网络的还是云端的，无论物理位置是硬盘驱动器、固态驱动器还是 USB 存储设备，所有数据都保存在文件系统中。不同的平台具有不同类型的文件系统，但它们都使用相同的抽象：路径、文件和目录。

在本章中，我们将探讨.NET 为处理文件系统提供的功能。本章将涵盖的主要主题如下：

+   System.IO 命名空间概述

+   处理路径

+   处理文件和目录

+   处理流

+   序列化和反序列化 XML

+   序列化和反序列化 JSON

通过本章的学习，您将学会如何创建、修改和删除文件和目录。您还将学会如何读取和写入不同类型的数据文件（包括二进制和文本）。最后，您将学会如何将对象序列化为 XML 和 JSON。

让我们从探索`System.IO`命名空间开始。

# System.IO 命名空间概述

.NET 框架提供了类以及其他辅助类型，如枚举、接口和委托，帮助我们在基类库中使用`System.IO`命名空间。类型的完整列表相当长，但以下表格显示了其中最重要的类型，分成几个类别。

用于处理*文件系统对象*的最重要的类如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_01_01.jpg)

用于处理*流*的最重要的类如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_02_01.jpg)

如前表所示，此列表中的具体类是成对出现的：一个读取器和一个写入器。通常，它们的使用方式如下：

+   `BinaryReader`和`BinaryWriter`用于显式地将原始数据类型序列化和反序列化到二进制文件中。

+   `StreamReader`和`StreamWriter`用于处理来自文本文件的具有不同编码的基于字符的数据。

+   `StringReader`和`StringWriter`具有与前一对类似的接口和目的，尽管它们在字符串和字符串缓冲区上工作，而不是流。

前表中类之间的关系如下简化的类图所示：

![图 13.1 - 流类和先前提到的读取器和写入器类的类图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_13.1_B12346.jpg)

图 13.1 - 流类以及先前提到的读取器和写入器类的类图

从这个图表中，您可以看到只有`FileStream`和`MemoryStream`实际上是流类。`BinaryReader`和`StreamReader`是适配器，从流中读取数据，而`BinaryWriter`和`StreamWriter`向流中写入数据。所有这些类都需要一个流来创建实例（流作为参数传递给构造函数）。另一方面，`StringReader`和`StringWriter`根本不使用流；相反，它们从字符串或字符串缓冲区中读取和写入。

文件系统对象或流的大多数操作在发生错误时会抛出异常。其中最重要的异常如下所列：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_03_01.jpg)

在本章的后续部分，我们将详细介绍其中一些类。现在，我们将从`Path`类开始。

# 处理路径

`System.IO.Path`是一个静态类，对表示文件系统对象（文件或目录）的路径执行操作。该类的方法都不验证字符串是否表示有效文件或目录的路径。但是，接受输入路径的成员会验证路径是否格式良好；否则，它们会抛出异常。该类可以处理不同平台的路径。路径的格式，如根元素的存在或路径分隔符，取决于平台，并由应用程序运行的平台确定。

路径可以是*相对的*或*绝对的*。绝对路径是完全指定位置的路径。另一方面，相对路径是由当前位置确定的部分位置，可以通过调用`Directory.GetCurrentDirector()`方法检索。

`Path`类的所有成员都是静态的。最重要的成员列在下表中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_04_01.jpg)

为了了解这是如何工作的，我们可以考虑以下示例，其中我们使用`Path`类的各种方法打印有关`c:\Windows\System32\mmc.exe`路径的信息：

```cs
var path = @"c:\Windows\System32\mmc.exe";
Console.WriteLine(Path.HasExtension(path));
Console.WriteLine(Path.IsPathFullyQualified(path));
Console.WriteLine(Path.IsPathRooted(path));
Console.WriteLine(Path.GetPathRoot(path));
Console.WriteLine(Path.GetDirectoryName(path));
Console.WriteLine(Path.GetFileName(path));
Console.WriteLine(Path.GetFileNameWithoutExtension(path));
Console.WriteLine(Path.GetExtension(path));
Console.WriteLine(Path.ChangeExtension(path, ".dll"));
```

该程序的输出如下屏幕截图所示：

图 13.2 - 执行前面示例的屏幕截图，打印有关路径的信息

](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_13.2_B12346.jpg)

图 13.2 - 执行前面示例的屏幕截图，打印有关路径的信息

`Path`类包含一个名为`Combine()`的方法，建议使用它来从两个或多个路径组合新路径。该方法有四个重载；这些重载接受两个、三个、四个路径或路径数组作为输入参数。为了理解这是如何工作的，我们将看一下以下示例，其中我们正在连接两个路径：

```cs
var path1 = Path.Combine(@"c:\temp", @"sub\data.txt");
Console.WriteLine(path1); // c:\temp\sub\data.txt 
var path2 = Path.Combine(@"c:\temp\sub", @"..\", "log.txt");
Console.WriteLine(path2); // c:\temp\sub\..\log.txt
```

在第一个例子中，连接的结果是`c:\temp\sub\data.txt`，这在`temp`和`sub`之间正确地包括了路径分隔符，而这两个输入路径中都没有。在第二个例子中，连接三个路径的结果是`c:\temp\sub\..\log.txt`。请注意，路径被正确组合，但未解析为实际路径，即`c:\temp\log.txt`。

除了前面列出的方法之外，`Path`类中还有几个其他静态方法，其中一些用于处理临时文件。这些在这里列出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_05_01.jpg)

让我们看一个处理临时路径的例子：

```cs
var temp = Path.GetTempPath();
var name = Path.GetRandomFileName();
var path1 = Path.Combine(temp, name);
Console.WriteLine(path1);
var path2 = Path.GetTempFileName();
Console.WriteLine(path2);
File.Delete(path2);
```

如下屏幕截图所示，`path1`将包含一个路径，例如`C:\Users\Marius\AppData\Local\Temp\w22fbbqw.y34`，尽管文件名（包括扩展名）会随着每次执行而改变。此外，这个路径不会在磁盘上创建，不像第二个例子，其中`C:\Users\Marius\AppData\Local\Temp\tmp8D5A.tmp`路径实际上代表一个新创建的文件：

图 13.3 - 屏幕截图，演示了使用 GetRandomFileName()方法

](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_13.3_B12346.jpg)

图 13.3 - 屏幕截图，演示了使用 GetRandomFileName()和 GetTempFileName()方法

这两个临时路径之间有两个重要的区别——第一个使用了加密强大的方法来生成名称，而第二个使用了一个更简单的算法。另一方面，`GetRandomFileName()`返回一个带有随机扩展名的名称，而`GetTempFileName()`总是返回一个带有`.TMP`扩展名的文件名。

要验证路径是否存在并执行创建、移动、删除或打开目录或文件等操作，我们必须使用`System.IO`命名空间中的其他类。我们将在下一节中看到这些类。

# 处理文件和目录

`System.IO`命名空间包含两个用于处理目录的类（`Directory`和`DirectoryInfo`），以及两个用于处理文件的类（`File`和`FileInfo`）。`Directory`和`File`是`DirectoryInfo`和`FileInfo`。

后两者都是从`FileSystemInfo`基类派生的，该基类提供了对文件和目录进行操作的常用成员。其中最重要的成员是以下表中列出的属性：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_06_01.jpg)

`DirectoryInfo`类的最重要成员（不包括在前面的表中列出的从基类继承的成员）如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_07_01.jpg)

同样，`FileInfo`类的最重要成员（不包括从基类继承的成员）如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_08_01.jpg)![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_08_02.jpg)

现在我们已经看过了用于处理文件系统对象及其最重要成员的类，让我们看一些使用它们的示例。

在第一个示例中，我们将使用`DirectoryInfo`的实例来打印有关目录（在本例中为`C:\Program Files (x86)\Microsoft SDKs\Windows\`）的信息，如名称、父级、根、创建时间和属性，以及所有子目录的名称：

```cs
var dir = new DirectoryInfo(@"C:\Program Files (x86)\Microsoft SDKs\Windows\");
Console.WriteLine($"Full name : {dir.FullName}");
Console.WriteLine($"Name      : {dir.Name}");
Console.WriteLine($"Parent    : {dir.Parent}");
Console.WriteLine($"Root      : {dir.Root}");
Console.WriteLine($"Created   : {dir.CreationTime}");
Console.WriteLine($"Attribute : {dir.Attributes}");
foreach(var subdir in dir.EnumerateDirectories())
{
    Console.WriteLine(subdir.Name);
}
```

执行此代码的输出如下（请注意，每台执行代码的机器都会有所不同）：

![图 13.4 - 屏幕截图显示先前示例的目录信息](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_13.4_B12346.jpg)

图 13.4 - 屏幕截图显示先前示例的目录信息

`DirectoryInfo`还允许我们创建和删除目录，这是我们将在下一个示例中做的事情。首先，我们创建`C:\Temp\Dir\Sub`目录。其次，我们相对于先前的目录创建子目录层次结构`sub1\sub2\sub3`。最后，我们从`C:\Temp\Dir\Sub\sub1\sub2`目录中删除最内部的目录`sub3`：

```cs
var dir = new DirectoryInfo(@"C:\Temp\Dir\Sub");
Console.WriteLine($"Exists: {dir.Exists}");
dir.Create();
var sub = dir.CreateSubdirectory(@"sub1\sub2\sub3");
Console.WriteLine(sub.FullName);
sub.Delete();
```

请注意，`CreateSubdirectory()`方法返回一个表示创建的最内部子目录的`DirectoryInfo`实例，在这种情况下是`C:\Temp\Dir\Sub\sub1\sub2\sub3`。因此，在此实例上调用`Delete()`时，只会删除`sub3`子目录。

我们可以使用`Directory`静态类及其`CreateDirectory()`和`Delete()`方法来编写相同的功能，如下面的代码所示：

```cs
var path = @"C:\Temp\Dir\Sub";
Console.WriteLine($"Exists: {Directory.Exists(path)}");
Directory.CreateDirectory(path);
var sub = Path.Combine(path, @"sub1\sub2\sub3");
Directory.CreateDirectory(sub);
Directory.Delete(sub);
Directory.Delete(path, true);
```

第一次调用`Delete()`将删除`C:\Temp\Dir\Sub\sub1\sub2\sub3`子目录，但仅当它为空时。第二次调用将以递归方式删除`C:\Temp\Dir\Sub`子目录及其所有内容（文件和子目录）。

在下一个示例中，我们将列出从给定目录（在本例中为`C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\`）开始以字母`T`开头的所有可执行文件。为此，我们将使用`GetFiles()`方法提供适当的过滤器。该方法返回一个`FileInfo`对象数组，我们使用该类的不同属性打印有关文件的信息：

```cs
var dir = new DirectoryInfo(@"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\");
foreach(var file in dir.GetFiles("t*.exe"))
{
    Console.WriteLine(
      $"{file.Name} [{file.Length}] 
    [{file.Attributes}]");}
```

执行此代码示例的输出可能如下所示：

![图 13.5 - 屏幕截图显示从给定目录中以字母 T 开头的可执行文件列表](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_13.5_B12346.jpg)

图 13.5 - 屏幕截图显示从给定目录中以字母 T 开头的可执行文件列表

为了打印有关文件的信息，我们使用了之前提到的`FileInfo`类。`Name`、`Length`和`Attributes`只是该类提供的一些属性。其他包括扩展名和文件时间。下面的代码片段显示了使用它们的示例：

```cs
var file = new FileInfo(@"C:\Windows\explorer.exe");
Console.WriteLine($"Name: {file.Name}");
Console.WriteLine($"Extension: {file.Extension}");
Console.WriteLine($"Full name: {file.FullName}");
Console.WriteLine($"Length: {file.Length}");
Console.WriteLine($"Attributes: {file.Attributes}");
Console.WriteLine($"Creation: {file.CreationTime}");
Console.WriteLine($"Last access:{file.LastAccessTime}");
Console.WriteLine($"Last write: {file.LastWriteTime}");
```

尽管输出在每台机器上会有所不同，但应如下所示：

![图 13.6 - 利用 FileInfo 类显示详细文件信息](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_13.6_B12346.jpg)

图 13.6 - 使用 FileInfo 类显示的详细文件信息

我们可以利用到目前为止学到的知识来创建一个函数，将目录的内容递归地写入控制台，并在这样做的同时，随着在目录层次结构中的深入导航，也缩进文件和目录的名称。这样的函数可能如下所示：

```cs
void PrintContent(string path, string indent = null)
{
    try
    {
        foreach(var file in Directory.EnumerateFiles(path))
        {
            var fi = new FileInfo(file);
            Console.WriteLine($"{indent}{fi.Name}");
        }
       foreach(var dir in Directory.EnumerateDirectories(path))
        {
            var di = new DirectoryInfo(dir);
            Console.WriteLine($"{indent}[{di.Name}]");
            PrintContent(dir, indent + " ");
        }
    }
    catch(Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
    }
}
```

当以项目目录的路径作为输入执行时，它会将以下输出打印到控制台（以下截图是完整输出的一部分）：

![图 13.7 - 打印指定目录内容的程序的部分输出](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_13.7_B12346.jpg)

图 13.7 - 打印指定目录内容的程序的部分输出

您可能已经注意到，我们同时使用了`GetFiles()`和`EnumerateFile()`，以及`EnumerateDirectories()`。这两组方法，以`Get`和`Enumerate`为前缀的方法，在返回文件或目录的集合方面是相似的。

然而，它们在一个关键方面有所不同——`Get`方法返回一个对象数组，而`Enumerate`方法返回一个`IEnumerable<T>`，允许客户端在检索到所有文件系统对象之前开始迭代，并且只消耗他们想要的。因此，在许多情况下，这些方法可能是一个更好的选择。

到目前为止，大多数示例都集中在获取文件和目录信息上，尽管我们确实创建和删除了目录。我们可以使用`File`和`FileInfo`类来创建和删除文件。例如，我们可以使用`File.Create()`来创建一个新文件或打开并覆盖现有文件，如下例所示：

```cs
using (var file = new StreamWriter(
   File.Create(@"C:\Temp\Dir\demo.txt")))
{
    file.Write("This is a demo");
}
```

`File.Create()`返回一个`FileStream`，在这个例子中，然后用它来创建一个`StreamWriter`，允许我们向文件写入文本`This is a demo`。然后流被处理，文件句柄被正确关闭。

如果您只对写入文本或二进制数据感兴趣，可以使用`File`类的静态成员，如`WriteAllText()`、`WriteAllLines()`或`WriteAllBytes()`。这些方法有多个重载，允许您指定文本编码，例如。还有异步对应方法，`WriteAllTextAsync()`、`WriteAllLinesAsync()`和`WriteAllBytesAsync()`。所有这些方法都会覆盖文件的当前内容（如果文件已经存在）。如果您希望保留内容并追加到文件的末尾，那么可以使用`AppendAllText()`和`AppendAllLines()`方法及其异步对应方法`AppendAllTextAsync()`和`AppendAllLinesAsync()`。

以下示例显示了如何使用这里提到的一些方法向现有文件写入和追加文本：

```cs
var path = @"C:\Temp\Dir\demo.txt";
File.WriteAllText(path, "This is a demo");
File.AppendAllText(path, "1st line");
File.AppendAllLines(path, new string[]{ 
   "2nd line", "3rd line"});
```

第一次调用`WriteAllText()`将`This is a demo`写入文件，覆盖任何内容。第二次调用`AppendAllText()`将`1st line`追加到文件中，而不添加任何新行。第三次调用`AppendAllLines()`将每个字符串写入文件，并在每个字符串后添加一个新行。因此，执行此代码后，文件的内容将如下所示：

```cs
This is a demo1st line2nd line
3rd line
```

与向文件写入内容类似，使用`File`类及其`ReadAllText()`、`ReadAllLines()`和`ReadAllBytes()`方法也可以进行读取。与写入方法一样，还有异步版本，`ReadAllTextAsync()`、`ReadAllLinesAsync()`和`ReadAllBytesAsync()`。下面的代码示例展示了如何使用其中一些方法：

```cs
var path = @"C:\Temp\Dir\demo.txt";
string text = File.ReadAllText(path);
string[] lines = File.ReadAllLines(path);
```

执行此代码后，`text`变量将包含从文件中读取的整个文本。另一方面，`lines`将是一个包含两个元素的数组，第一个是`This is a demo1st line2nd line`，第二个是`3rd line`。

纯文本并不是我们通常会写入文件的唯一类型的数据，文件也不是数据的唯一存储系统。有时，我们可能对从管道、网络、本地内存或其他地方读取和写入感兴趣。为了处理所有这些，.NET 提供了*流*，这是下一节的主题。

# 处理流

`Stream`，提供了对流进行读取和写入的支持。另一方面，流在概念上分为三类：

+   `FileStream`、`MemoryStream`和`NetworkStream`来实现后备存储。

+   `BufferedStream`、`CryptoStream`、`DeflateStream`和`GZipStream`。

+   `bool`、`int`、`double`等）、文本、XML 数据等。.NET 提供的适配器包括`BinaryReader`和`BinaryWriter`、`StreamReader`和`StreamWriter`，以及`XmlReader`和`XmlWriter`。

以下图表概念上展示了流架构：

![图 13.8 - 流架构的概念图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_13.8_B12346.jpg)

图 13.8 - 流架构的概念图

讨论前面图中显示的所有流类超出了本书的范围。然而，在本节中，我们将重点关注`BinaryReader`/`BinaryWriter`和`StreamReader`/`StreamWriter`适配器，以及`FileStream`和`MemoryStream`后备存储流。

## 流类的概述

正如我之前提到的，所有流类的基类是`System.IO.Stream`类。这是一个提供从流中读取和写入的方法和属性的抽象类。其中许多是抽象的，并且在派生类中实现。以下是该类的最重要的方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_09_01.jpg)

列出的一些操作有异步伴侣，其后缀为`Async`（例如`ReadAsync()`或`WriteAsync()`）。读取和写入操作会使指示当前流位置的指针前进读取或写入的字节数。

`Stream`类还提供了几个有用的属性，列在下表中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_10_01.jpg)

代表文件的后备存储流的类称为`FileStream`。这个类是从抽象的`Stream`类派生而来的，并实现了抽象成员。它支持同步和异步操作，并且不仅可以用于打开、读取、写入和关闭磁盘文件，还可以用于其他操作系统对象，比如管道和标准输入和输出。异步方法对于执行耗时操作而不阻塞主线程非常有用。

`FileStream`类支持对文件的随机访问。`Seek()`方法允许我们在流内移动当前指针的位置进行读取/写入。在改变位置时，必须指定一个字节偏移量和一个查找原点。字节偏移量是相对于查找原点的，查找原点可以是流的开头、当前位置或者末尾。

该类提供了许多构造函数来创建类的实例。您可以以各种组合提供文件句柄（作为`IntPtr`或`SafeFileHandle`）、文件路径、文件模式（确定文件应该如何打开）、文件访问（确定文件应该如何访问 - 读取、写入或两者）、以及文件共享（确定其他文件流如何访问相同的文件）。在这里列出所有这些构造函数是不切实际的，但我们将在本章中看到几个示例。

表示内存备份存储的类称为`MemoryStream`，也是从`Stream`派生而来的。该类的大多数成员都是基类的抽象成员的实现。但是，该类具有几个构造函数，允许我们创建**可调整大小的流**（初始为空或具有指定容量）或从字节数组创建**不可调整大小的流**。从字节数组创建的内存流不能扩展或收缩，可以是可写的或只读的。

## 使用文件流

`FileStream`类允许我们从文件中读取和写入一系列字节。它可以操作原始数据，如`byte[]`、`Span<byte>`或`Memory<byte>`。我们可以使用`File`类的静态方法或`FileInfo`类的非静态方法来获取`FileStream`对象：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_11_01.jpg)

我们可以通过以下示例看到这是如何工作的，我们将四个字节写入到位于`C:\Temp\data.raw`的文件中，然后读取文件的整个内容并将其打印到控制台上：

```cs
var path = @"C:\Temp\data.raw";
var data = new byte[] { 0xBA, 0xAD, 0xF0, 0x0D};
using(FileStream wr = File.Create(path))
{
    wr.Write(data, 0, data.Length);
}
using(FileStream rd = File.OpenRead(path))
{
    var buffer = new byte[rd.Length];
    rd.Read(buffer, 0, buffer.Length);
    Console.WriteLine(
       string.Join(" ", buffer.Select(
                   e => $"{e:X02}")));
}
```

在第一部分中，我们使用`File.Create()`打开一个文件进行写入。如果文件不存在，则会创建文件。如果文件存在，则其内容将被覆盖。使用`FileStream.Write()`方法将字节数组的内容写入文件。当`FileStream`对象在`using`语句结束时被处理时，流将被刷新到文件，并关闭文件句柄。

在第二部分中，我们使用`File.OpenRead()`打开先前写入的文件，但这次是用于读取。我们分配了一个足够大的数组来接收文件的整个内容，并使用`FileStream.Read()`来读取其内容。这段代码的输出如下：

![图 13.9 - 显示在控制台上创建的二进制文件的内容](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_13.9_B12346.jpg)

图 13.9 - 显示在控制台上创建的二进制文件的内容

处理原始数据可能很麻烦。因此，.NET 提供了流适配器，允许我们处理更高级别的数据。第一对适配器是`BinaryReader`和`BinaryWriter`，它们提供了对二进制格式中的原始类型和字符串的读取和写入支持。以下是使用这两个适配器的示例：

```cs
var path = @"C:\Temp\data.bin";
using (var wr = new BinaryWriter(File.Create(path)))
{
    wr.Write(true);
    wr.Write('x');
    wr.Write(42);
    wr.Write(19.99);
    wr.Write(49.99M);
    wr.Write("text");
}
using(var rd = new BinaryReader(File.OpenRead(path)))
{
    Console.WriteLine(rd.ReadBoolean()); // True
    Console.WriteLine(rd.ReadChar());    // x
    Console.WriteLine(rd.ReadInt32());   // 42
    Console.WriteLine(rd.ReadDouble());  // 19.99
    Console.WriteLine(rd.ReadDecimal()); // 49.99
    Console.WriteLine(rd.ReadString());  // text
} 
```

我们首先使用`File.Create()`打开一个文件，返回`FileStream`。这个流被用作`BinaryWriter`流适配器的构造函数的参数。`Write()`方法对所有原始类型（`char`、`bool`、`sbyte`、`byte`、`short`、`ushort`、`int`、`uint`、`long`、`ulong`、`float`、`double`和`decimal`）以及`byte[]`、`char[]`和`string`进行了重载。

其次，我们重新打开相同的文件，但这次是用于读取，使用`File.OpenRead()`。这个方法返回的`FileStream`对象被用作`BinaryReader`流适配器的构造函数的参数。该类有一组读取方法，每种原始类型都有一个，比如`ReadBoolean()`、`ReadChar()`、`ReadInt16()`、`ReadInt32()`、`ReadDouble()`和`ReadDecimal()`，以及用于读取`byte[]`的方法 - `ReadBytes()`，`char[]` - `ReadChars()`，和字符串 - `ReadString()`。你可以在前面的示例中看到其中一些方法的使用。

默认情况下，`BinaryReader`和`BinaryWriter`都使用*UTF-8 编码*处理字符串。但是，它们都有重载的构造函数，允许我们使用`System.Text.Encoding`类指定另一种编码。

尽管这两个适配器可以用于处理字符串，但由于缺乏对诸如行处理之类的功能的支持，因此使用它们来读写文本文件可能会很麻烦。为了处理文本文件，应该使用`StreamReader`和`StreamWriter`适配器。默认情况下，它们将文本处理为 UTF-8 编码，但它们的构造函数允许我们指定不同的编码。在以下示例中，我们将文本写入文件，然后将其读取并打印到控制台：

```cs
var path = @"C:\Temp\data.txt";
using(StreamWriter wr = File.CreateText(path))
{
    wr.WriteLine("1st line");
    wr.WriteLine("2nd line");
}
using(StreamReader rd = File.OpenText(path))
{
    while(!rd.EndOfStream)
        Console.WriteLine(rd.ReadLine());
}
```

`File.CreateText()`方法打开一个文件进行写入（创建或覆盖），并返回一个使用 UTF-8 编码的`StreamWriter`类的实例。`WriteLine()`方法将字符串写入文件，然后添加一个新行。`WriteLine()`有重载版本，还有重载的`Write()`方法，可以在不添加新行的情况下写入`char`、`char[]`或`string`。

在第二部分中，我们使用`File.OpenText()`方法打开先前写入的文本文件进行读取。这会返回一个读取 UTF-8 文本的`StreamReader`对象。`ReadLine()`方法用于在循环中逐行读取内容，直到流的末尾。`EndOfStream`属性用于检查当前流位置是否达到流的末尾。

我们可以使用`File.Open()`方法，而不是使用`File.OpenText()`方法，这允许我们指定打开模式、文件访问和共享。我们可以将之前显示的读取部分重写如下：

```cs
using(var rd = new StreamReader(
  File.Open(path, FileMode.Open,
         FileAccess.Read, 
         FileShare.Read)))
{
    while (!rd.EndOfStream)
        Console.WriteLine(rd.ReadLine());
}
```

有时，我们需要一个流来处理临时数据。使用文件可能很麻烦，也会给 I/O 操作增加不必要的开销。为此，内存流是最合适的。

## 使用内存流

**内存流**是本地内存的后备存储。这样的流在需要临时存储转换数据时非常有用。示例可以包括 XML 序列化或数据压缩和解压缩。我们将在接下来的代码中看到这两个操作。

下面的代码中显示的静态`Serializer<T>`类包含两个方法——`Serialize()`和`Deserialize()`。前者接受一个`T`对象，使用`XmlSerializer`生成其 XML 表示，并将 XML 数据作为字符串返回。后者接受包含 XML 数据的字符串，并使用`XmlSerializer`读取它并从中创建一个新的`T`类型对象。以下是代码：

```cs
public static class Serializer<T>
{
    static readonly XmlSerializer _serializer =
       new XmlSerializer(typeof(T));
    static readonly Encoding _encoding = Encoding.UTF8;
    public static string Serialize(T value)
    {
        using (var ms = new MemoryStream())
        {
            _serializer.Serialize(ms, value);
            return _encoding.GetString(ms.ToArray());
        }
    }
    public static T Deserialize(string value)
    {
        using (var ms = new MemoryStream(
           _encoding.GetBytes(value)))
        {
            return (T)_serializer.Deserialize(ms);
        }
    }
}
```

在`Serialize()`方法中创建的内存流是可调整大小的。它最初是空的，根据需要增长。然而，在`Deserialize()`方法中创建的内存流是不可调整大小的，因为它是从字节数组初始化的。这个流用于只读目的。

`MemoryStream`类实现了`IDisposable`接口，因为它继承自`Stream`，而`Stream`实现了`IDisposable`。然而，`MemoryStream`没有需要处理的资源，因此`Dispose()`方法什么也不做。显式调用对流没有影响。因此，不需要像前面的例子中那样将内存流变量包装在`using`语句中。

让我们考虑一个`Employee`类的以下实现：

```cs
public class Employee
{
    public int EmployeeId { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public override string ToString() => 
        $"[{EmployeeId}] {LastName}, {FirstName}";
}
```

我们可以按照以下方式对这个类的实例进行序列化和反序列化：

```cs
var employee = new Employee
{
    EmployeeId = 42,
    FirstName = "John",
    LastName = "Doe"
};
var text = Serializer<Employee>.Serialize(employee);
var result = Serializer<Employee>.Deserialize(text);
Console.WriteLine(employee);
Console.WriteLine(text);
Console.WriteLine(result);
```

执行此代码的结果显示在以下屏幕截图中：

![图 13.10 – 在控制台上显示的 XML 序列化的 Employee 对象](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_13.10_B12346.jpg)

图 13.10 – 在控制台上显示的 XML 序列化的 Employee 对象

我们提到的另一个内存流很方便的例子是*数据的压缩和解压缩*。`System.IO.Compression`命名空间中的`GZipStream`类是一个流装饰器，支持使用 GZip 数据格式规范对流进行压缩和解压缩。`MemoryStream`对象被用作`GZipStream`装饰器的后备存储。这里显示的静态`Compression`类提供了压缩和解压缩字节数组的两个方法：

```cs
public static class Compression
{
    public static byte[] Compress(byte[] data)
    {
        if (data == null) return null;
        if (data.Length == 0) return new byte[] { };
        using var ms = new MemoryStream();
        using var gzips =
           new GZipStream(ms,
        CompressionMode.Compress);
        gzips.Write(data, 0, data.Length);
        gzips.Close();
        return ms.ToArray();
    }
    public static byte[] Decompress(byte[] data)
    {
        if (data == null) return null;
        if (data.Length == 0) return new byte[] { };

        using var source = new MemoryStream(data);
        using var gzips =
           new GZipStream(source,
        CompressionMode.Decompress);
        using var target = new MemoryStream(data.Length * 2);
        gzips.CopyTo(target);
        return target.ToArray();
    }
}
```

我们可以使用这个辅助类将字符串压缩为字节数组，然后将其解压缩为字符串。以下代码显示了这样一个例子：

```cs
var text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
var data = Encoding.UTF8.GetBytes(text);
var compressed = Compression.Compress(data);
var decompressed = Compression.Decompress(compressed);
var result = Encoding.UTF8.GetString(decompressed);
Console.WriteLine($"Text size: {text.Length}");
Console.WriteLine($"Compressed: {compressed.Length}");
Console.WriteLine($"Decompressed: {decompressed.Length}");
Console.WriteLine(result);
if (text == result)
    Console.WriteLine("Decompression successful!");
```

执行此示例代码的输出显示在以下屏幕截图中：

![图 13.11 – 一个屏幕截图，显示了压缩和解压文本的结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_13.11_B12346.jpg)

图 13.11 – 一个屏幕截图，显示了压缩和解压文本的结果

在本节中，我们已经看到了如何简单地序列化和反序列化 XML。我们将在下一节详细介绍这个主题。

# 序列化和反序列化 XML

在前一节中，我们已经看到了如何使用`System.Xml.Serialization`命名空间中的`XmlSerializer`类对数据进行序列化和反序列化。这个类对于将对象序列化为 XML 和将 XML 反序列化为对象非常方便。尽管在前面的示例中，我们使用了内存流进行序列化，但它实际上可以与任何流一起使用；此外，它还可以与`TextWriter`和`XmlWriter`适配器一起使用。

以下示例显示了一个修改后的`Serializer<T>`类，其中我们指定了要将 XML 文档写入或从中读取的文件的路径：

```cs
public static class Serializer<T>
{
    static readonly XmlSerializer _serializer = 
        new XmlSerializer(typeof(T));
    public static void Serialize(T value, string path)
    {
        using var ms = File.CreateText(path);
        _serializer.Serialize(ms, value);
    }
    public static T Deserialize(string path)
    {
        using var ms = File.OpenText(path);
        return (T)_serializer.Deserialize(ms);
    }
}
```

我们可以像下面这样使用这个新的实现：

```cs
var employee = new Employee
{
    EmployeeId = 42,
    FirstName = "John",
    LastName = "Doe"
};
var path = Path.Combine(Path.GetTempPath(), "employee1.xml");
Serializer<Employee>.Serialize(employee, path);
var result = Serializer<Employee>.Deserialize(path);
```

使用此代码进行 XML 序列化的结果是具有以下内容的文档：

```cs
<?xml version="1.0" encoding="utf-8"?>
<Employee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <EmployeeId>42</EmployeeId>
  <FirstName>John</FirstName>
  <LastName>Doe</LastName>
</Employee>
```

`XmlSerializer`通过将类型的所有公共属性和字段序列化为 XML 来工作。它使用一些默认设置，例如类型变为节点，属性和字段变为元素。类型、属性或字段的名称成为节点或元素的名称，字段或属性的值成为其文本。它还添加了默认命名空间（您可以在前面的代码中看到）。但是，可以使用类型和成员上的属性来控制序列化的方式。下面的代码示例中显示了这样一个示例：

```cs
[XmlType("employee")]
public class Employee
{
    [XmlAttribute("id")]
    public int EmployeeId { get; set; }
    [XmlElement(ElementName = "firstName")]
    public string FirstName { get; set; }
    [XmlElement(ElementName = "lastName")]
    public string LastName { get; set; }
    public override string ToString() => 
        $"[{EmployeeId}] {LastName}, {FirstName}";
}
```

对这个`Employee`类实现的实例进行序列化将产生以下 XML 文档：

```cs
<?xml version="1.0" encoding="utf-8"?>
<employee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" id="42">
  <firstName>John</firstName>
  <lastName>Doe</lastName>
</employee>
```

我们在这里使用了几个属性，`XmlType`、`XmlAttribute`和`XmlElement`，但列表很长。以下表列出了最重要的 XML 属性及其作用。这些属性位于`System.Xml.Serialization`命名空间中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_12_01.jpg)

`XmlSerializer`类的工作方式是，在运行时，每次应用程序运行时，为临时序列化程序集中的每种类型生成序列化代码。在某些情况下，这可能是一个性能问题，可以通过预先生成这些程序集来避免。`Sgen.exe`可以用来生成这些程序集。如果包含序列化代码的程序集称为`MyAssembly.dll`，则生成的序列化程序集将被称为`MyAssembly.XmlSerializer.dll`。该工具作为 Windows SDK 的一部分部署。

您还可以使用`xsd.exe`从类生成 XML 模式（XSD 文档）或从现有 XML 模式生成类。该工具作为 Windows SDK 的一部分或与 Visual Studio 一起分发。

`XmlSerializer`可能存在的问题是，它将单个.NET 对象序列化为 XML 文档（当然，该对象可以是复杂的，并包含其他对象和对象数组）。如果您有两个要写入同一文档的单独对象，则无法正常工作。假设我们还有以下类，表示公司中的一个部门：

```cs
public class Department
{
    [XmlAttribute]
    public int Id { get; set; }

    public string Name { get; set; }
}
```

我们可能希望编写一个包含员工和部门的 XML 文档。使用`XmlSerializer`将无法正常工作。这在以下示例中显示：

```cs
public static class Serializer<T>
{
    static readonly XmlSerializer _serializer = 
        new XmlSerializer(typeof(T));
    public static void Serialize(T value, StreamWriter stream)
    {
        _serializer.Serialize(stream, value);
    }
    public static T Deserialize(StreamReader stream)
    {
        return (T)_serializer.Deserialize(stream);
    }
}
```

我们可以尝试使用以下代码将员工和部门序列化到同一个 XML 文档中：

```cs
var employee = new Employee
{
    EmployeeId = 42,
    FirstName = "John",
    LastName = "Doe"
};
var department = new Department
{
    Id = 102, 
    Name = "IT"
};
var path = Path.Combine(Path.GetTempPath(), "employee.xml");
using (var wr = File.CreateText(path))
{
    Serializer<Employee>.Serialize(employee, wr);
    wr.WriteLine();
    Serializer<Department>.Serialize(department, wr);
}
```

生成到磁盘文件的 XML 文档将具有以下代码中显示的内容。这不是有效的 XML，因为它具有多个文档声明，并且没有单个根元素：

```cs
<?xml version="1.0" encoding="utf-8"?>
<employee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" id="42">
   <firstName>John</firstName>
   <lastName>Doe</lastName>
</employee>
<?xml version="1.0" encoding="utf-8"?>
<Department xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Id="102">
   <Name>IT</Name>
</Department>
```

要使其工作，我们必须创建一个额外的类型，该类型将包含一个员工和一个部门，并且我们必须序列化此类型的实例。此额外对象将作为 XML 文档的根元素进行序列化。我们将通过以下示例进行演示（请注意，这里有一个额外的名为`Version`的属性）：

```cs
public class Data
{
    [XmlAttribute]
    public int Version { get; set; }
    public Employee Employee { get; set; }
    public Department Department { get; set; }
}
var data = new Data()
{
    Version = 1,
    Employee = new Employee {
        EmployeeId = 42,
        FirstName = "John",
        LastName = "Doe"
    },
    Department = new Department {
        Id = 102,
        Name = "IT"
    }
};
var path = Path.Combine(Path.GetTempPath(), "employee.xml");
using (var wr = File.CreateText(path))
{
    Serializer<Data>.Serialize(data, wr);
}
```

这次，输出是一个格式良好的 XML 文档，列在以下代码中：

```cs
<?xml version="1.0" encoding="utf-8"?>
<Data xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Version="1">
  <Employee id="42">
    <firstName>John</firstName>
    <lastName>Doe</lastName>
  </Employee>
  <Department Id="102">
    <Name>IT</Name>
  </Department>
</Data>
```

为了进一步控制读取和写入 XML，.NET 基类库包含两个名为`XmlReader`和`XmlWriter`的类，它们提供了一种快速、非缓存、仅向前的方式来从流或文件读取或生成 XML 数据。

`XmlWriter`类可用于将 XML 数据写入流、文件、文本读取器或字符串。它提供了以下功能：

+   验证字符和 XML 名称

+   验证 XML 文档是否格式良好

+   支持 CLR 类型，这样您就不需要手动将所有内容转换为字符串

+   用于在 XML 文档中写入二进制数据的 Base64 和 BaseHex 编码

`XmlWriter`类包含许多方法；其中一些方法列在下表中。尽管此列表仅包括同步方法，但它们都有异步伴侣，比如`WriteElementStringAsync()`对应于`WriteElementString()`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_13_01.jpg)

在使用`XmlWriter`时，可以指定各种设置，如编码、缩进、属性应该如何写入（在新行上还是同一行上）、省略 XML 声明等。这些设置由`XmlWriterSettings`类控制。

以下清单显示了使用`XmlWriter`创建包含员工和部门的 XML 文档的示例，作为名为`Data`的根元素的一部分。实际上，结果与前一个示例相同，只是没有创建命名空间：

```cs
var employee = new Employee
{
    EmployeeId = 42,
    FirstName = "John",
    LastName = "Doe"
};
var department = new Department
{
    Id = 102,
    Name = "IT"
};
var path = Path.Combine(Path.GetTempPath(), "employee.xml");
var settings = new XmlWriterSettings 
{ 
    Encoding = Encoding.UTF8, 
    Indent = true 
};
var namespaces = new XmlSerializerNamespaces();
namespaces.Add(string.Empty, string.Empty);
using (var wr = XmlWriter.Create(path, settings))
{
    wr.WriteStartDocument();
    wr.WriteStartElement("Data");
    wr.WriteStartAttribute("Version");
    wr.WriteValue(1);
    wr.WriteEndAttribute();
    var employeeSerializer = 
      new XmlSerializer(typeof(Employee));
    employeeSerializer.Serialize(wr, employee, namespaces);
    var depSerializer = new XmlSerializer(typeof(Department));
    depSerializer.Serialize(wr, department, namespaces);
    wr.WriteEndElement();
    wr.WriteEndDocument();
}
```

在这个例子中，我们使用了以下组件：

+   `XmlWriterSettings`的一个实例，用于将编码设置为 UTF-8 并启用输出的缩进。

+   `XmlWriter.Create()`用于创建`XmlWriter`类的实现的实例。

+   `XmlWriter`类的各种方法来写入 XML 数据。

+   `XmlSerializerNamespaces`的实例，用于控制生成的命名空间。在这个例子中，我们添加了一个空的方案和命名空间，这导致 XML 文档中没有命名空间。

+   `XmlSerializer`类的实例，用于简化`Employee`和`Department`对象到 XML 文档的序列化。这是可能的，因为`Serialize()`方法可以将`XmlWriter`作为生成的 XML 文档的目的地。

`XmlWriter`的伴侣类是`XmlReader`。这个类允许我们在 XML 数据中移动并读取其内容，但是以一种只能向前的方式，这意味着您不能从给定点返回。`XmlReader`类是一个抽象类，就像`XmlWriter`一样，有具体的实现，比如`XmlTextReader`、`XmlNodeReader`或`XmlValidatingReader`。

然而，对于大多数情况，您应该使用`XmlReader`。要创建它的实例，请使用静态的`XmlReader.Create()`方法。该类包含一长串的方法和属性，以下表格列出了其中的一些。就像在`XmlWriter`的情况下一样，`XmlReader`也有同步和异步方法。这里只列出了一些同步方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_14_01.jpg)![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_14_02.jpg)

在创建`XmlReader`的实例时，您可以指定要启用的一组功能，例如应使用的模式、忽略注释或空格、类型分配的验证等。`XmlReaderSettings`类用于此目的。

在下面的示例中，我们使用`XmlReader`来读取先前写入的 XML 文档的内容，并在控制台上显示其内容的表示：

```cs
var rdsettings = new XmlReaderSettings()
{
    IgnoreComments = true,
    IgnoreWhitespace = true
};
using (var rd = XmlReader.Create(path, rdsettings))
{
    string indent = string.Empty;
    while(rd.Read())
    {
        switch(rd.NodeType)
        {
            case XmlNodeType.Element:
                Console.Write(
                  $"{indent}{{ {rd.Name} : ");
                indent = indent + " ";
                while (rd.MoveToNextAttribute())
                {
                    Console.WriteLine();
                    Console.WriteLine($"{indent}{{{rd.Name}:{rd.Value}}}");
                } 
                break;
            case XmlNodeType.Text:
                Console.Write(rd.Value);
                break;
            case XmlNodeType.EndElement:
                indent = indent.Remove(0, 2);
                Console.WriteLine($"{indent}}}");
                break;
            default:
                Console.WriteLine($"[{rd.Name} {rd.Value}]");
                break;
        }
    }
}
```

执行此代码的输出如下：

![图 13.12 - 从磁盘读取的 XML 文档内容的屏幕截图并显示在控制台上](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_13.12_B12346.jpg)

图 13.12 - 从磁盘读取的 XML 文档内容的屏幕截图并显示在控制台上

以下是此示例的几个关键点：

+   我们创建了一个`XmlReaderSettings`的实例，告诉`XmlReader`忽略注释和空格。

+   我们使用`XmlReader.Create()`创建了一个新的`XmlReader`实现的实例，用于从指定路径的文件中读取 XML 数据。

+   `Read()`方法用于循环读取 XML 文档的每个节点。

+   我们使用属性，如`NodeType`，`Name`和`Value`来检查每个节点的类型，名称和值。

有关使用`XmlReader`和`XmlWriter`处理 XML 数据以及使用`XmlSerializer`进行序列化的许多细节。在这里讨论所有这些内容将花费太多时间。我们建议您使用其他资源，如官方文档，来了解更多关于这些类的信息。

现在我们已经看到了如何处理 XML 数据，让我们来看看 JSON。

# 序列化和反序列化 JSON

近年来，**JavaScript 对象表示法（JSON）**已成为数据序列化的事实标准，不仅用于 Web 和移动端，也用于桌面端。.NET 没有提供适当的库来序列化和反序列化 JSON；因此，开发人员转而使用第三方库。其中一个库是**Json.NET**（也称为**Newtonsoft.Json**，以其创建者 Newton-King 命名）。这已成为大多数.NET 开发人员的首选库，并且是 ASP.NET Core 的依赖项。然而，随着.NET Core 3.0 的发布，微软提供了自己的 JSON 序列化器，称为**System.Text.Json**，根据其可用的命名空间命名。在本章的最后部分，我们将看看这两个库，并了解它们的一些功能以及它们之间的比较。

## 使用 Json.NET

Json.NET 目前是最广泛使用的.NET 库，用于 JSON 序列化和反序列化。它是一个高性能、易于使用的开源库，可作为名为**Newtonsoft.Json**的 NuGet 包使用。事实上，这是迄今为止在 NuGet 上下载量最大的包。它提供的一些功能列在这里：

+   大多数常见序列化和反序列化场景的简单 API，使用`JsonConvert`，它是`JsonSerializer`的包装器。

+   使用`JsonSerializer`对序列化/反序列化过程进行更精细的控制。该类可以通过`JsonTextWriter`和`JsonTextReader`直接向流中写入文本或从流中读取文本。

+   使用`JObject`，`JArray`和`JValue`创建，修改，解析和查询 JSON 的可能性。

+   在 XML 和 JSON 之间进行转换的可能性。

+   使用 JSON Path 查询 JSON 的可能性，这是一种类似于 XPath 的查询语言。

+   使用 JSON 模式验证 JSON。

+   支持`BsonReader`和`BsonWriter`。这是一种类似于 JSON 的文档的二进制编码序列化。

在本节中，我们将使用以下`Employee`类的实现来探索几种常见的序列化和反序列化场景：

```cs
public enum EmployeeStatus { Active, Inactive }
public class Employee
{
    public int EmployeeId { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public DateTime? HireDate { get; set; }
    public List<string> Telephones { get; set; }
    public bool IsOnLeave { get; set; }   

    [JsonConverter(typeof(StringEnumConverter))]
    public EmployeeStatus Status { get; set; }
    [JsonIgnore]
    public DateTime LastModified { get; set; }
    public override string ToString() => 
        $"[{EmployeeId}] {LastName}, {FirstName}";
}
```

尽管该库功能丰富，但在这里涵盖所有功能超出了本书的范围。我们建议阅读 Json.NET 的在线文档，网址为 https://www.newt](https://www.newtonsoft.com/json)onsoft.com/json。

获取包含`Employee`对象的 JSON 序列化的字符串非常简单，如下例所示：

```cs
var employee = new Employee
{
    EmployeeId = 42,
    FirstName = "John",
    LastName = "Doe"
};
var text = JsonConvert.SerializeObject(employee);
```

默认情况下，`JsonConvert.SerializeObject()`将生成缩小的 JSON，不包含缩进和空格。上述代码的结果是以下 JSON：

```cs
{"EmployeeId":42,"FirstName":"John","LastName":"Doe",
"HireDate":null,"Telephones":null,"IsOnLeave":false,
"Status":"Active"}
```

尽管这适用于在网络上传输数据，比如与 web 服务通信时，因为大小较小，它更难以被人类阅读。如果您希望 JSON 文档可读性强，应该使用缩进。这可以通过提供格式选项来指定，该选项可用于`Formatting`枚举。这里显示了一个示例：

```cs
var text = JsonConvert.SerializeObject(
    employee, Formatting.Indented);
```

这次，结果如下：

```cs
{
  "EmployeeId": 42,
  "FirstName": "John",
  "LastName": "Doe",
  "HireDate": null,
  "Telephones": null,
  "IsOnLeave": false,
  "Status": "Active"
}
```

缩进不是我们可以指定的唯一序列化选项。实际上，您可以使用`JsonSerializerSettings`类设置许多选项，该类可以作为`SerializeObject()`方法的参数提供。例如，我们可能希望跳过序列化引用的属性或字段，或者将设置为`null`的可空类型。例如，`HireDate`和`Telephones`分别是`DateTime?`和`List<string>`类型。可以按以下方式完成：

```cs
var text = JsonConvert.SerializeObject(
    employee,
    Formatting.Indented,
    new JsonSerializerSettings()
    {
        NullValueHandling = NullValueHandling.Ignore,
    });
```

在前面的示例中，我们使用的`employee`对象序列化的结果如下所示。您会注意到`HireDate`和`Telephones`不再出现在生成的 JSON 中：

```cs
{
  "EmployeeId": 42,
  "FirstName": "John",
  "LastName": "Doe",
  "IsOnLeave": false,
  "Status": "Active"
}
```

可以为序列化指定的另一个选项控制默认值的处理方式。`DefaultValueHandling`是一个枚举，指定了默认值的成员应该如何被序列化或反序列化。通过指定`Ignore`，您可以使序列化器跳过输出中值与其类型的默认值相同的成员（对于数字类型为`0`，对于`bool`为`false`，对于引用和可空类型为`null`）。实际上可以使用一个名为`DefaultValueAttribute`的属性来更改被忽略的默认值，该属性被指定在成员上。让我们考虑以下示例：

```cs
var text = JsonConvert.SerializeObject(
    employee,
    Formatting.Indented,
    new JsonSerializerSettings()
    {
        NullValueHandling = NullValueHandling.Ignore,
        DefaultValueHandling = DefaultValueHandling.Ignore
    });
```

这次，生成的 JSON 更加简单，如下所示。这是因为`IsOnLeave`和`Status`属性分别设置为它们的默认值，即`false`和`EmployeeStatus.Active`：

```cs
{
  "EmployeeId": 42,
  "FirstName": "John",
  "LastName": "Doe"
}
```

我们之前提到了一个叫做`DefaultValueAttribute`的属性。您可能已经注意到在`Employee`类的声明中使用了另外两个属性，`JsonIgnoreAttribute`和`JsonConverterAttribute`。序列化可以通过属性进行控制，该库支持标准的.NET 序列化属性（如`SerializableAttribute`、`DataContractAttribute`、`DataMemberAttribute`和`NonSerializedAttributes`）和内置的 Json.NET 属性。当两者同时存在时，内置的 Json.NET 属性优先于其他属性。内置的 Json.NET 属性如下表所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_15_01.jpg)

在这些属性中，我们使用了`JsonIgnoreAttribute`来指示`Employee`类的`LastModified`属性不应该被序列化，并使用了`JsonConverterAttribute`来指示`Status`属性应该使用`StringEnumConverter`类进行序列化。结果是该属性将被序列化为一个字符串（值为`Active`或`Inactive`），而不是一个数字（值为`0`或`1`）。

`JsonConvert.SerializeObject()`方法返回一个字符串。可以使用流（如文件或内存流）进行序列化和反序列化。但是，为此我们必须使用`JsonSerializer`类。该类具有重载的`Serialize()`和`Deserialize()`方法，以及一系列属性，允许我们自定义序列化。以下示例显示了如何使用该类将迄今为止使用的员工对象序列化到磁盘上的文本文件中：

```cs
var path = Path.Combine(Path.GetTempPath() + "employee.json");
var serializer = new JsonSerializer()
{
    Formatting = Formatting.Indented,
    NullValueHandling = NullValueHandling.Ignore,
    DefaultValueHandling = DefaultValueHandling.Ignore
};
using (var sw = File.CreateText(path))
using (var jw = new JsonTextWriter(sw))
{
    serializer.Serialize(jw, employee);
}
```

我们指定了我们想要使用缩进并跳过`null`或具有类型默认值的成员。序列化的结果是一个文本文件，内容如下：

```cs
{
  "EmployeeId": 42,
  "FirstName": "John",
  "LastName": "Doe"
}
```

反序列化的相反过程也是直接的。使用`JsonSerializer`，我们可以从之前创建的文本文件中读取。为此，我们使用`JsonTextReader`，这是`JsonTextWriter`的伴侣类：

```cs
using (var sr = File.OpenText(path))
using (var jr = new JsonTextReader(sr))
{
    var result = serializer.Deserialize<Employee>(jr);
    Console.WriteLine(result);
}
```

从字符串反序列化也是可能且直接的，使用`JsonConvert`类。为此目的使用了重载的`DeserializeObject()`方法，如下所示：

```cs
var json = @"{
    ""EmployeeId"": 42,
    ""FirstName"": ""John"",
    ""LastName"": ""Doe""
}";
var result = JsonConvert.DeserializeObject<Employee>(json);
```

尽管被广泛使用，Json.NET 库也有一些缺点：

+   .NET 的`string`类型使用 UTF-16 编码，然而大多数网络协议，包括 HTTP，使用 UTF-8。Json.NET 在这两者之间进行转换，这会影响性能。

+   作为第三方库，而不是基类库（或基础类库）的组件，您可能有依赖于不同版本的项目。ASP.NET Core 使用 Json.NET 作为依赖项，这有时会导致版本冲突。

+   它没有利用新的.NET 类型，比如`Span<T>`，这些类型旨在增加某些情况下的性能，比如解析文本时。

为了克服这些问题，微软提供了自己的 JSON 序列化程序的实现，我们将在下一节中看到。

## 使用 System.Text.Json

这是.NET Core 随附的新 JSON 序列化程序。它取代了 ASP.NET Core 中的 Json.NET，现在提供了一个集成包。如果您的目标是.NET Framework 或.NET Standard，您仍然可以使用**System.Text.Json**，它作为一个 NuGet 包可用，也称为**System.Text.Json**。

新的序列化程序的性能优于 Json.NET，主要有两个原因：它使用`Span<T>`和 UTF-8 本地化（因此避免了 UTF-8 和 UTF-16 之间的转码）。根据微软的说法，这个序列化程序在不同情况下可以提供 1.3 倍到 5 倍的加速。

然而，这些 API 受到了 Json.NET 的启发，对于简单的情况，如我们在本章的前一节中看到的情况，从 Json.NET 过渡是无缝的。以下示例显示了如何将`Employee`对象序列化为`string`：

```cs
var employee = new Employee
{
    EmployeeId = 42,
    FirstName = "John",
    LastName = "Doe"
};
var text = JsonSerializer.Serialize(employee);
```

这看起来与 Json.NET 非常相似，它也生成了压缩的 JSON，您可以在以下代码中看到：

```cs
{"EmployeeId":42,"FirstName":"John","LastName":"Doe",
"HireDate":null,"Telephones":null,"IsOnLeave":false,
"Status":"Active"}
```

然而，可以通过提供各种选项来自定义序列化，例如缩进、处理空值、命名策略、尾随逗号、忽略只读属性等。这些选项由`JsonSerializerOptions`类提供。这里展示了一个缩进和跳过空值的示例：

```cs
var text = JsonSerializer.Serialize(
    employee,
    new JsonSerializerOptions()
    {
        WriteIndented = true,
        IgnoreNullValues = true 
    });
```

在这种情况下，输出如下：

```cs
{
  "EmployeeId": 42,
  "FirstName": "John",
  "LastName": "Doe",
  "IsOnLeave": false,
  "Status": "Active"
}
```

在这些示例中使用的`Employee`类的实现几乎与上一节中的实现相同。让我们看一下以下代码，试着找出区别：

```cs
public class Employee
{
    public int EmployeeId { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public DateTime? HireDate { get; set; }
    public List<string> Telephones { get; set; }
    public bool IsOnLeave { get; set; }
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public EmployeeStatus Status { get; set; }
    [JsonIgnore]
    public DateTime LastModified { get; set; }
    public override string ToString() => 
        $"[{EmployeeId}] {LastName}, {FirstName}";
}
```

我们再次使用了`JsonIgnoreAttribute`和`JsonConverterAttribute`属性，指定`LastModified`属性应该被跳过，`Status`属性应该被序列化为字符串而不是数字。唯一的区别是我们在这里使用的转换器类型，称为`JsonStringEnumConverter`（而在 Json.NET 中称为`StringEnumConverter`）。然而，这些都不是`System.Text.Json.Serialization`命名空间。这些属性列在下表中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_13_Table_16_01.jpg)

从这个表中，我们可以看到**System.Text.Json**序列化程序不支持序列化和反序列化字段，这是 Json.NET 支持的功能。如果这是您需要的功能，您必须将字段更改为属性，为字段提供属性，或者使用支持字段的序列化程序。

如果您想对写入或读取的内容有更多控制，可以使用`Utf8JsonWriter`和`Utf8JsonReader`类。这些类提供了高性能的 API，用于仅向前、无缓存的写入或只读读取 UTF-8 编码的 JSON 文本。在下面的示例中，我们将使用`Utf8JsonWriter`将 JSON 文档写入到磁盘上的文件中，其中包含一个员工：

```cs
var path = Path.Combine(Path.GetTempPath() + "employee.json");
var options = new JsonWriterOptions()
{
    Indented = true
};
using (var sw = File.CreateText(path))
using (var jw = new Utf8JsonWriter(sw.BaseStream, options))
{
    jw.WriteStartObject();
    jw.WriteNumber("EmployeeId", 42);
    jw.WriteString("FirstName", "John");
    jw.WriteString("LastName", "Doe");
    jw.WriteBoolean("IsOnLeave", false);
    jw.WriteString("Status", EmployeeStatus.Active.ToString());
    jw.WriteEndObject();
}
```

执行此代码的结果是一个文本文件，内容如下：

```cs
{
  "EmployeeId": 42,
  "FirstName": "John",
  "LastName": "Doe",
  "IsOnLeave": false,
  "Status": "Active"
}
```

要读取此处生成的 JSON 文档，我们可以使用`Utf8JsonReader`。但是，这个阅读器不适用于流，而是适用于原始数据的视图，以`ReadOnlySpan<byte>`或`ReadOnlySequence<byte>`的形式。这个阅读器允许我们逐个令牌地读取数据并相应地处理它。下面的代码段中显示了一个示例：

```cs
byte[] data = Encoding.UTF8.GetBytes(text);
Utf8JsonReader reader = new Utf8JsonReader(data, true,
                                           default);
while (reader.Read())
{
    switch (reader.TokenType)
    {
        case JsonTokenType.PropertyName:
            Console.Write($@"""{reader.GetString()}"" : ");
            break;
        case JsonTokenType.String:
            Console.WriteLine($"{reader.GetString()},");
            break;
        case JsonTokenType.Number:
            Console.WriteLine($"{reader.GetInt32()},");
            break;
        case JsonTokenType.False:
        case JsonTokenType.True:
            Console.WriteLine($"{reader.GetBoolean()},");
            break;
    }
}
```

执行此代码的输出如下：

```cs
"EmployeeId" : 42,
"FirstName" : John,
"LastName" : Doe,
"IsOnLeave" : False,
"Status" : Active,
```

**System.Text.Json**序列化器比这里的示例所展示的要复杂。我们建议您阅读在线文档，以更好地熟悉其 API。

**Json.NET**和**System.Text.Json**并不是.NET 中唯一的 JSON 序列化器，也不是性能最好的。如果 JSON 性能对您的应用程序很重要，您可能希望使用**Utf8Json**（可在[`github.com/neuecc/Utf8`](https://github.com/neuecc/Utf8Json)Json）或**Jil**（可在[`github.com/kevin-montrose`](https://github.com/kevin-montrose/Jil)/Jil）这两个序列化器，它们的性能优于本章中介绍的两个序列化器。

# 摘要

我们从`System.IO`命名空间的概述开始本章，并了解了它为处理文件系统提供的功能。然后我们学习了处理路径和文件系统对象。我们看到了如何创建、编辑、移动、删除或枚举文件和目录。

我们还学习了如何使用流从磁盘文件读取和写入数据。我们研究了不同类型的流，并学习了如何使用不同的流适配器向文件和内存流写入和读取数据。

在本章的最后部分，我们学习了数据序列化，学会了如何序列化和反序列化 XML 和 JSON。对于后者，我们探讨了 Json.NET 序列化器，这是最流行的.NET JSON 库，以及`System.Text.Json`，这是新的.NET JSON 库。

在下一章中，我们将讨论一个名为错误处理的不同主题。您将学习有关错误代码和异常以及处理错误的最佳实践。

# 测试你所学到的知识

1.  `System.IO`命名空间中用于处理文件系统对象的最重要的类是什么？

1.  什么是连接路径的推荐方法？

1.  如何获取当前用户临时文件夹的路径？

1.  `File`和`FileInfo`类之间有什么区别？`Directory`和`DirectoryInfo`之间的区别呢？

1.  您可以使用哪些方法来创建目录？枚举目录呢？

1.  .NET 中流的三个类别是什么？

1.  .NET 中流类的基类是什么，它提供了哪些功能？

1.  `BinaryReader`和`BinaryWriter`默认假定使用什么编码来处理字符串？如何更改这个设置？

1.  如何将`T`类型的对象序列化为 XML？

1.  .NET Core 附带的 JSON 序列化器是什么，如何使用它来序列化`T`类型的对象？
