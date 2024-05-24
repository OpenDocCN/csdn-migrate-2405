# C#8 和 .NET Core3 并行编程实用指南（四）

> 原文：[`zh.annas-archive.org/md5/BE48315910DEF416E754F7470D0341EA`](https://zh.annas-archive.org/md5/BE48315910DEF416E754F7470D0341EA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五部分：.NET Core 中并行编程功能的新增内容

在这一部分，您将熟悉.NET Core 中支持并行编程的新突破。

本节包括以下章节：

+   第十二章，*ASP.NET Core 中的 IIS 和 Kestrel*

+   第十三章，*并行编程中的模式*

+   第十四章，*分布式内存管理*


# 第十二章：ASP.NET Core 中的 IIS 和 Kestrel

在上一章中，我们讨论了为并行和异步代码编写单元测试用例。我们还讨论了在 Visual Studio 中可用的三个单元测试框架：MSUnit、NUnit 和 xUnit。

在本章中，我们将介绍线程模型如何与**Internet Information Services**（**IIS**）和 Kestrel 一起工作。我们还将看看我们可以做出哪些各种调整，以充分利用服务器上的资源。我们将介绍 Kestrel 的工作模型，以及在创建微服务时如何利用并行编程技术。

在本章中，我们将涵盖以下主题：

+   IIS 线程模型和内部结构

+   Kestrel 线程模型和内部结构

+   在微服务中线程的最佳实践介绍

+   在 ASP.NET MVC Core 中介绍异步

+   异步流（在.NET Core 3.0 中新增）

让我们开始吧。

# 技术要求

需要对服务器工作原理有很好的理解，这样你才能理解本章。在开始本章之前，你还应该了解线程模型。本章的源代码可在 GitHub 上找到：[`github.com/PacktPublishing/-Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter12`](https://github.com/PacktPublishing/-Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter12)。

# IIS 线程模型和内部结构

顾名思义，这些是在 Windows 系统上使用的服务，用于通过互联网连接您的 Web 应用程序与其他系统，使用 HTTP、TCP、Web 套接字等一系列协议。

在本节中，我们将讨论**IIS 线程模型**的工作原理。IIS 的核心是**CLR 线程池**。要理解 IIS 如何服务用户请求，了解 CLR 线程池如何添加和删除线程是非常重要的。

部署到 IIS 的每个应用程序都被分配一个唯一的工作进程。每个工作进程都有两个线程池：**工作线程池**和**IOCP**（即**I/O 完成端口**）线程池：

+   每当我们使用传统的`ThreadPool.QueueUserWorkItem`或**TPL**创建新的线程池线程时，ASP.NET 运行时都会利用工作线程进行处理。

+   每当进行任何 I/O 操作，即数据库调用、文件读写或对另一个 Web 服务的网络调用时，ASP.NET 运行时都会利用 IOCP 线程。

默认情况下，每个处理器都有一个工作线程和一个 IOCP 线程。因此，双核 CPU 默认情况下会有两个工作线程和两个 IOCP 线程。`ThreadPool`会根据负载和需求不断添加和删除线程。IIS 为每个接收到的请求分配一个线程。这使得每个请求在与服务器同时到达的其他请求的情况下都有不同的上下文。线程的责任是满足请求，并生成并将响应发送回客户端。

如果可用的线程池线程数量少于服务器在任何时间接收到的请求数，那么这些请求将开始排队。稍后，线程池将使用两种重要的算法之一生成线程，这两种算法分别称为*爬坡*和*避免饥饿*。线程的创建不是瞬间完成的，通常需要从`ThreadPool`知道线程短缺开始到 500 毫秒。让我们试着理解`ThreadPool`用来生成线程的这两种算法。

# 避免饥饿

在这个算法中，`ThreadPool`不断监视队列，如果没有进展，它就会不断地将新线程加入队列。

# 爬坡

在这个算法中，`ThreadPool`试图最大限度地利用尽可能少的线程来实现吞吐量。

使用默认设置运行 IIS 将对性能产生重大影响，因为默认情况下，每个处理器只有一个工作线程可用。我们可以通过修改`machine.config`文件中的配置元素来增加此设置。

```cs
<configuration>  
    <system.web>     
        <processModel minWorkerThreads="25" minIoThreads="25" />  
    </system.web> 
</configuration>
```

如您所见，我们将最小工作线程和 IOCP 线程增加到了 25。随着更多请求的到来，将创建额外的线程。这里需要注意的一点是，由于每个请求都分配了一个唯一的线程，我们应该避免编写阻塞代码。有了阻塞代码，就不会有空闲线程。一旦线程池耗尽，请求将开始排队。IIS 每个应用程序池只能排队最多 1,000 个请求。我们可以通过更改`machine.config`文件中的`requestQueueLimit`应用程序设置来修改这一点。

要修改所有应用程序池的设置，我们需要添加`applicationPool`元素并设置所需的值：

```cs
<system.web>
  <applicationPool
    maxConcurrentRequestPerCPU="5000"
    maxConcurrentThreadsPerCPU="0"
    requestQueueLimit="5000" />
</system.web>
```

要修改单个应用程序池的设置，我们需要在 IIS 中导航到特定应用程序池的高级设置。如下截图所示，我们可以更改队列长度属性以修改每个应用程序池可以排队的请求数量：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/804457ce-c889-4d44-a876-1cfc35f55cc6.png)

作为开发人员的良好编码实践，为了减少争用问题并避免服务器上的队列，我们应该尝试对任何阻塞 I/O 代码使用`async`/`await`关键字。这将减少服务器上的争用问题，因为线程不会被阻塞，并返回到线程池以服务其他请求。

# Kestrel 线程模型和内部

IIS 一直是托管.NET 应用程序的最流行服务器，但它与 Windows 操作系统绑定在一起。随着越来越多的云提供商出现和非 Windows 云托管选项变得更加便宜，需要一个跨平台托管服务器。微软推出了 Kestrel 作为托管 ASP.NET Core 应用程序的跨平台 Web 服务器。如果我们创建和运行 ASP.NET Core 应用程序，Kestrel 是默认的 Web 服务器。Kestrel 是开源的，使用基于事件驱动的异步 I/O 服务器。Kestrel 不是一个完整的 Web 服务器，建议在 IIS 和 Nginx 等功能齐全的 Web 服务器后面使用。

当 Kestrel 最初推出时，它是基于`libuv`库的，这个库也是开源的。在.NET 中使用`libuv`并不是什么新鲜事，可以追溯到 ASP.NET 5。`libuv`专门为异步 I/O 操作构建，并使用单线程事件循环模型。该库还支持在 Windows、macOS 和 Linux 上进行跨平台异步套接字操作。您可以在 GitHub 上查看其进展并下载`libuv`的源代码以进行自定义实现。

`libuv`在 Kestrel 中仅用于支持异步 I/O。除 I/O 操作外，Kestrel 中进行的所有其他工作仍然由.NET 工作线程使用托管代码完成。创建 Kestrel 的核心思想是提高服务器的性能。该堆栈非常强大且可扩展。Kestrel 中的`libuv`仅用作传输层，并且由于出色的抽象，它也可以被其他网络实现替换。Kestrel 还支持运行多个事件循环，因此比 Node.js 更可靠。使用的事件循环数量取决于计算机上的逻辑处理器数量，以及一个线程运行一个事件循环。我们还可以在创建主机时通过代码配置此数字。

以下是`Program.cs`文件的摘录，该文件存在于所有 ASP.NET Core 项目中：

```cs
public class Program
{
    public static void Main(string[] args)
    {
        CreateWebHostBuilder(args).Build().Run();
    }
    public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>    
     WebHost.CreateDefaultBuilder(args).UseStartup<Startup>();
    }
```

正如您将看到的，Kestrel 服务器基于构建器模式，并且可以使用适当的包和扩展方法添加功能。在接下来的部分中，我们将学习如何修改不同版本的.NET Core 的 Kestrel 设置。

# ASP.NET Core 1.x

我们可以使用名为`UseLibuv`的扩展方法来设置线程计数。我们可以通过设置`ThreadCount`属性来实现，如下面的代码所示：

```cs
public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
            .UseLibuv(opts => opts.ThreadCount = 4)
            .UseStartup<Startup>();
```

`WebHost`已在.NET Core 3.0 中被通用主机所取代。以下是 ASP.NET Core 3.0 的代码片段：

```cs
public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
```

# ASP.NET Core 2.x

从 ASP.NET 2.1 开始，Kestrel 已经替换了`libuv`的默认传输方式，改为了托管套接字。因此，如果您将项目从 ASP.NET Core 升级到 ASP.NET 2.x 或 3.x，并且仍然想使用`libuv`，则需要添加`Microsoft.AspNetCore.Server.Kestrel.Transport.Libuv` NuGet 包以使代码正常工作。

Kestrel 目前支持以下场景：

+   HTTPS

+   不透明升级，用于启用 Web 套接字（[`github.com/aspnet/websockets`](https://github.com/aspnet/websockets)）

+   Nginx 后面的 Unix 套接字用于高性能

+   HTTP/2（目前在 macOS 上不受支持）

由于 Kestrel 是基于套接字构建的，您可以使用`Host`上的`ConfigureLimits`方法来配置它们的连接限制：

```cs
Host.CreateDefaultBuilder(args)
.ConfigureKestrel((context, options) =>
{
    options.Limits.MaxConcurrentConnections = 100;
    options.Limits.MaxConcurrentUpgradedConnections = 100;
}
```

如果我们将`MaxConcurrentConnections`设置为 null，则默认连接限制是无限的。

# 引入微服务中线程的最佳实践

微服务是用于创建非常高性能和可扩展的后端服务的最流行的软件设计模式。与为整个应用程序构建一个服务不同，创建了多个松散耦合的服务，每个服务负责一个功能。根据功能的负载，可以单独扩展或缩减每个服务。因此，在设计微服务时，您使用的线程模型的选择变得非常重要。

微服务可以是无状态的或有状态的。无状态和有状态之间的选择对性能有影响。对于无状态服务，请求可以以任何顺序进行处理，而不考虑当前请求之前或之后发生了什么，而对于有状态服务，所有请求都应按特定顺序进行处理，如队列。这可能会对性能产生影响。由于微服务是异步的，我们需要编写一些逻辑来确保请求按正确的顺序和状态进行处理，并且在每个请求之后与下一个消息进行通信。微服务也可以是单线程或多线程的，这种选择与状态结合起来可以真正改善或降低性能，并且在规划服务时应该经过深思熟虑。

微服务设计方法可以分为以下几类：

+   单线程-单进程微服务

+   单线程-多进程微服务

+   多线程-单进程微服务

我们将在接下来的部分中更详细地了解这些设计方法。

# 单线程-单进程微服务

这是微服务的最基本设计。微服务在单个 CPU 核心的单个线程上运行。对于来自客户端的每个新请求，都会创建一个新线程，从而生成一个新进程。这会带走连接池缓存的好处。在与数据库一起工作时，每个新进程都会创建一个新的连接池。此外，由于一次只能创建一个进程，因此只能为一个客户端提供服务。

单线程-单进程微服务的缺点包括资源浪费以及在负载增加时服务的吞吐量不会增加。

# 单线程-多进程微服务

微服务在单个线程上运行，但可以生成多个进程，从而提高它们的吞吐量。由于为每个客户端创建了一个新进程，我们无法在连接到数据库时利用连接池。有一些第三方环境，如 Zend、OpCache 和 APC，提供跨进程的操作码缓存。

单线程-多进程微服务方法的优点是在负载上提高了吞吐量，但请注意我们无法利用连接池。

# 多线程-单进程

微服务在多个线程上运行，有一个长期运行的单个进程。使用相同的数据库，我们可以利用连接池，并在需要时限制连接的数量。单进程的问题在于所有线程将使用共享资源，并可能出现资源争用问题。

多线程-单进程方法的优点是提高了无状态服务的性能，而缺点是在共享资源时可能会出现同步问题。

# 异步服务

通过解耦微服务之间的通信，我们可以避免与各种应用组件集成时的性能问题。必须通过设计异步创建微服务才能实现这种解耦。

# 专用线程池

如果应用程序流程要求我们连接到各种微服务，那么为这些任务创建专用线程池更有意义。使用单个线程池，如果一个服务开始出现问题，那么池中的所有线程都可能耗尽。这可能会影响微服务的性能。这种模式也被称为**Bulkheads**模式。下图显示了两个使用共享连接池的微服务。如您所见，两个微服务都使用了共享连接池：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/7775bc70-bd55-45fd-adc5-a2549b9067b5.png)

下图显示了两个使用专用线程池的微服务：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/4e7cde3f-7af7-493f-97a4-4f1028f7eb21.png)

在下一节中，我们将介绍如何在 ASP.NET MVC 核心中使用异步。

# 在 ASP.NET MVC 核心中引入异步

`async`和`await`是代码标记，帮助我们使用 TPL 编写异步代码。它们有助于保持代码结构，并使其在后台异步处理代码的同时看起来同步。

我们在第九章中介绍了`async`和`await`，*异步、等待和基于任务的异步编程基础*。

现在，让我们使用 ASP.NET Core 3.0 和 VS 2019 预览创建一个异步 Web API。该 API 将从服务器读取文件：

1.  打开 Visual Studio 2019，将呈现以下屏幕。在 VS 2019 中创建一个新的 ASP.NET Core Web 应用程序项目，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/6af4da68-75e4-42f2-b4cb-2ed6c9f106dc.png)

1.  给项目取一个名字，并指定想要创建的位置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/2b29b76f-9f1c-42ad-836c-cb80ee916aee.png)

1.  选择项目类型，在我们的情况下是 API，然后点击创建：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/5bbfee2e-3a88-4f7a-9a0c-9a02bd5c088d.png)

1.  现在，在我们的项目中创建一个名为`Files`的新文件夹，并添加一个名为`data.txt`的文件，其中包含以下内容：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/3baa8323-ae99-45b4-9e78-c32b367b58aa.png)

1.  接下来，我们将修改`ValuesController.cs`中的`Get`方法，如下所示：

```cs
[HttpGet]
public ActionResult<IEnumerable<string>> Get()
{
    var filePath = System.IO.Path.Combine(
     HostingEnvironment.ContentRootPath,"Files","data.txt");
    var text = System.IO.File.ReadAllText(filePath);
    return Content(text);
}
```

这是一个从服务器读取文件并将内容作为字符串返回给用户的简单方法。这段代码的问题在于，当调用`File.ReadAllText`时，调用线程将被阻塞，直到文件完全读取。现在我们知道，我们的服务器响应将是进行异步调用，如下所示：

```cs
[HttpGet]
public async Task<ActionResult<IEnumerable<string>>> GetAsync()
{
    var filePath = System.IO.Path.Combine(
      HostingEnvironment.ContentRootPath, "Files", "data.txt");
    var text = await System.IO.File.ReadAllTextAsync(filePath);
    return Content(text);
}
```

ASP.NET Core Web API 支持并行编程的所有新特性，包括异步，正如我们从前面的代码示例中看到的。

# 异步流

.NET Core 3.0 还引入了异步流支持。`IAsyncEnumerable<T>`是`IEnumerable<T>`的异步版本。这一新功能允许开发人员在`IAsyncEnumerable<T>`上等待`foreach`循环以消耗流中的元素，并使用`yield`返回流以产生元素。

这在我们想要异步迭代元素并对迭代的元素执行一些计算操作的场景中非常重要。随着现在更加注重大数据（作为流式输出可用），选择支持高数据量的*异步*流更有意义，同时通过有效地利用线程使服务器响应。

已添加了两个新接口来支持异步流**：**

```cs
public interface IAsyncEnumerable<T>
{
  public IAsyncEnumerator<T> GetEnumerator();
}
public interface IAsyncEnumerator<out T>
{
  public T Current { get; }
  public Task<bool> MoveNextAsync();
}
```

从`IAsyncEnumerator`的定义中可以看出，`MoveNext`已经变成了异步的。这有两个好处：

+   很容易在`Task<bool>`上缓存`Task<T>`，这样就会减少内存分配

+   现有的集合只需要添加一个额外的方法来支持异步行为

让我们尝试使用一些示例代码来异步枚举奇数索引的数字，以便理解这一点。

这是一个自定义的枚举器：

```cs
class OddIndexEnumerator : IAsyncEnumerator<int>
{
    List<int> _numbers;
    int _currentIndex = 1;
    public OddIndexEnumerator(IEnumerable<int> numbers)
    {
        _numbers = numbers.ToList();
    }
    public int Current
    {
        get
        {
            Task.Delay(2000);
            return _numbers[_currentIndex];
        }
    }
    public ValueTask DisposeAsync()
    {
        return new ValueTask(Task.CompletedTask);
    }
    public ValueTask<bool> MoveNextAsync()
    {
        Task.Delay(2000);
        if (_currentIndex < _numbers.Count() - 2)
        {
            _currentIndex += 2;
            return new ValueTask<bool>(Task.FromResult<bool>(true));
        }
        return new ValueTask<bool>(Task.FromResult<bool>(false));
    }
}
```

从我们在前面的代码中定义的`MoveNextAsync()`方法中可以看出，这个方法从奇数索引（即索引 1）开始，并持续读取奇数索引的项目。

以下是我们的集合，它使用我们之前创建的自定义枚举逻辑，并实现了`IAsyncEnumerable<T>`接口的`GetAsyncEnumerator()`方法，以返回我们创建的`OddIndexEnumerator`枚举器：

```cs
class CustomAsyncIntegerCollection : IAsyncEnumerable<int>
{
    List<int> _numbers;
    public CustomAsyncIntegerCollection(IEnumerable<int> numbers)
    {
        _numbers = numbers.ToList();
    }
    public IAsyncEnumerator<int> GetAsyncEnumerator(
     CancellationToken cancellationToken = default)
    {
        return new OddIndexEnumerator(_numbers);
    }
}
```

这是我们的魔术扩展方法，它将我们的自定义集合转换为`AsyncEnumerable`。正如你所看到的，它适用于任何实现`IEnumerable<int>`的集合，并使用`CustomAsyncIntegerCollection`包装底层集合，而`CustomAsyncIntegerCollection`又实现了`IAsyncEnumerable<T>`：

```cs
public static class CollectionExtensions
{
    public static IAsyncEnumerable<int> AsEnumerable(this 
     IEnumerable<int> source) => new CustomAsyncIntegerCollection(source);
}
```

一旦所有部分就位，我们就可以创建一个返回异步流的方法。我们可以通过使用`yield`关键字来查看项目是如何生成的：

```cs
static async IAsyncEnumerable<int> GetBigResultsAsync()
{
    var list = Enumerable.Range(1, 20);
    await foreach (var item in list.AsEnumerable())
    {
        yield return item;
    }
}
```

以下代码调用了流。在这里，我们调用了`GetBigResultsAsync()`方法，该方法在`foreach`循环内返回`IAsyncEnumerable<int>`，然后异步迭代它：

```cs
async static Task Main(string[] args)
{
    await foreach (var dataPoint in GetBigResultsAsync())
    {
        Console.WriteLine(dataPoint);
    }
    Console.WriteLine("Hello World!");
}
```

以下是前面代码的输出。如你所见，它在集合中生成了奇数索引的数字**：**

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/a4c7c02d-65c0-4032-95d3-5e245be1555f.png)

在本节中，我们介绍了异步流，这使得我们能够在不阻塞调用线程的情况下并行迭代集合，这是自 TPL 引入以来一直缺少的功能。

现在，让我们看看本章涵盖了什么。

# 总结

在本章中，我们讨论了 IIS 线程模型，并通过从.NET Core 2.0 使用`libuv`到.NET Core 2.1 开始管理套接字来对.NET Core 服务器的实现进行更改。我们还讨论了改进 IIS、Kestrel 以及一些线程池算法（如饥饿避免和爬坡）的方法。我们介绍了微服务的概念以及在微服务中使用的各种线程模式，如单线程-单进程微服务、单线程-多进程微服务和多线程-单进程微服务。

我们还讨论了在 ASP.NET MVC Core 3.0 中使用异步的过程，并介绍了.NET Core 3.0 中异步流的新概念及其用法。异步流在大数据场景中非常方便，因为由于数据的快速涌入，服务器的负载可能会很大。

在下一章中，我们将学习一些常用的并行和异步编程模式。这些模式将增强我们对并行编程的理解。

# 问题

1.  哪一个用于托管 Web 应用程序？

1.  `IWebHostBuilder`

1.  `IHostBuilder`

1.  以下哪种`ThreadPool`算法试图最大化吞吐量，同时尽量使用较少的线程？

1.  爬山

1.  饥饿避免

1.  哪种不是有效的微服务设计方法？

1.  单线程-单进程

1.  单线程-多进程

1.  多线程-单进程

1.  多线程-多进程

1.  在新版本的.NET Core 中，我们可以等待`foreach`循环。

1.  真

1.  假


# 第十三章：并行编程中的模式

在上一章中，我们介绍了 IIS 和 Kestrel 中的线程模型，以及如何优化它们以提高性能，以及.NET Core 3.0 中一些新的异步特性支持。

在本章中，我们将介绍并行编程模式，并专注于理解并行代码问题场景以及使用并行编程/异步技术解决这些问题。

尽管并行编程技术中使用了许多模式，但我们将限制自己解释最重要的模式。

本章中，我们将涵盖以下主题：

+   `MapReduce`

+   聚合

+   分支/合并

+   推测处理

+   懒惰

+   共享状态

# 技术要求

为了理解本章内容，需要具备 C#和并行编程的知识。本章的源代码可以在 GitHub 上找到：[`github.com/PacktPublishing/-Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter13`](https://github.com/PacktPublishing/-Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter13)。

# MapReduce 模式

`MapReduce`模式是为了处理大数据问题而引入的，例如跨服务器集群的大规模计算需求。该模式也可以在单核机器上使用。

`MapReduce`程序由两个任务组成：**map**和**reduce**。`MapReduce`程序的输入作为一组键值对传递，输出也以此形式接收。

要实现这种模式，我们需要首先编写一个`map`函数，该函数以数据（键/值对）作为单个输入值，并将其转换为另一组中间数据（键/值对）。然后用户编写一个`reduce`函数，该函数以`map`函数的输出（键/值对）作为输入，并将数据与包含任意行数据的较小数据集组合。

让我们看看如何使用 LINQ 实现基本的`MapReduce`模式，并将其转换为基于 PLINQ 的实现。

# 使用 LINQ 实现 MapReduce

以下是`MapReduce`模式的典型图形表示。输入经过各种映射函数，每个函数返回一组映射值作为输出。然后，这些值被`Reduce()`函数分组和合并以创建最终输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/ce927cbb-692b-46c2-919b-d261f96b84f5.png)

按照以下步骤使用 LINQ 实现`MapReduce`模式：

1.  首先，我们需要编写一个`map`函数，它以单个输入值返回一组映射值。我们可以使用 LINQ 的`SelectMany`函数来实现这一点。

1.  然后，我们需要根据中间键对数据进行分组。我们可以使用 LINQ 的`GroupBy`方法来实现这一点。

1.  最后，我们需要一个`reduce`方法，它将以中间键作为输入。它还将采用相应的值集合并产生输出。我们可以使用`SelectMany`来实现这一点。

1.  我们的最终`MapReduce`模式现在将如下所示：

```cs
public static IEnumerable<TResult> MapReduce<TSource, TMapped, TKey, TResult>(
this IEnumerable<TSource> source,
Func<TSource, IEnumerable<TMapped>> map,
Func<TMapped, TKey> keySelector,
Func<IGrouping<TKey, TMapped>, IEnumerable<TResult>> reduce)
{
return source.SelectMany(map) .GroupBy(keySelector) .SelectMany(reduce); }
```

1.  现在，我们可以改变输入和输出，使其适用于`ParallelQuery<T>`而不是`IEnumerable<T>`，如下所示：

```cs
public static ParallelQuery<TResult> MapReduce<TSource, TMapped, TKey, TResult>(
this ParallelQuery<TSource> source,
Func<TSource, IEnumerable<TMapped>> map,
Func<TMapped, TKey> keySelector,
Func<IGrouping<TKey, TMapped>, IEnumerable<TResult>> reduce)
{
return source.SelectMany(map)
.GroupBy(keySelector)
.SelectMany(reduce);
}
```

以下是在.NET Core 中使用自定义实现的`MapReduce`的示例。程序在范围内生成一些正数和负数的随机数。然后，它应用一个 map 来过滤掉任何正数，并按数字对它们进行分组。最后，它应用`reduce`函数返回一个数字列表，以及它们的计数：

```cs
private static void MapReduceTest()
{
    //Maps only positive number from list
    Func<int, IEnumerable<int>> mapPositiveNumbers = number =>
    {
        IList<int> positiveNumbers = new List<int>();
        if (number > 0)
            positiveNumbers.Add( number);
            return positiveNumbers;
    };
    // Group results together
    Func<int, int> groupNumbers = value => value;
    //Reduce function that counts the occurrence of each number
    Func<IGrouping<int, int>,IEnumerable<KeyValuePair<int, int>>> 
     reduceNumbers =  grouping => new[] {                                 
        new KeyValuePair<int, int>( grouping.Key, grouping.Count()) 
    };
    // Generate a list of random numbers between -10 and 10
    IList<int> sourceData = new List<int>();
    var rand = new Random();
    for (int i = 0; i < 1000; i++)
    {
        sourceData.Add(rand.Next(-10, 10));
    }
    // Use MapReduce function
    var result = sourceData.AsParallel().MapReduce(mapPositiveNumbers,
                                                    groupNumbers,
                                                    reduceNumbers);
    // process the results
    foreach (var item in result)
    {
       Console.WriteLine($"{item.Key} came {item.Value} times" );
    }
}
```

以下是我们在 Visual Studio 中运行上述程序代码后收到的输出摘录。如您所见，它迭代提供的列表并找到数字出现的次数：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/2e6c38af-ca3a-4de2-89ee-c6de40ac3d90.png)

在下一节中，我们将讨论另一个常见且重要的并行设计模式，称为聚合。而`MapReduce`模式充当过滤器，聚合只是将输入的所有数据组合在一起，并以另一种格式放置。

# 聚合

聚合是并行应用程序中常用的设计模式。在并行程序中，数据被分成单元，以便可以通过多个线程在多个核心上处理。在某些时候，需要从所有相关来源组合数据，然后才能呈现给用户。这就是聚合的作用。

现在，让我们探讨聚合的需求以及 PLINQ 提供的内容。

聚合的一个常见用例如下。在这里，我们尝试迭代一组值，执行一些操作，并将结果返回给调用者：

```cs
var output = new List<int>();
var input = Enumerable.Range(1, 50);
Func<int,int> action = (i) => i * i;
foreach (var item in input)
{
    var result = action(item);
    output.Add(result);
}
```

上述代码的问题是输出不是线程安全的。因此，为了避免跨线程问题，我们需要使用同步原语：

```cs
var output = new List<int>();
var input = Enumerable.Range(1, 50);
Func<int, int> action = (i) => i * i;
Parallel.ForEach(input, item =>
{
    var result = action(item);
    lock (output) 
        output.Add(result);
});
```

上面的代码在每个项目的计算量较小时运行良好。然而，随着每个项目的计算量增加，获取和释放锁的成本也会增加。这会导致性能下降。在这里，我们讨论的并发集合在这里发挥了作用。使用并发集合，我们不必担心同步。以下代码片段使用并发集合：

```cs
var input = Enumerable.Range(1, 50);
Func<int, int> action = (i) => i * i;
var output = new ConcurrentBag<int>();
Parallel.ForEach(input, item =>
{
    var result = action(item);
    output.Add(result);
});
```

PLINQ 还定义了帮助聚合和处理同步的方法。其中一些方法是 `ToArray`、`ToList`、`ToDictionary` 和 `ToLookup`：

```cs
var input = Enumerable.Range(1, 50);
Func<int, int> action = (i) => i * i;
var output = input.AsParallel()
             .Select(item => action(item))
             .ToList();
```

在上面的代码中，`ToList()` 方法负责聚合所有数据，同时处理同步。TPL 中有一些实现模式，并内置在编程语言中。其中之一是 fork/join 模式，我们将在下面讨论。

# fork/join 模式

在 fork/join 模式中，工作被 *forked*（分割）成一组可以异步执行的任务。稍后，分叉的工作按照要求和并行化的范围以相同顺序或不同顺序进行合并。在本书中，当我们讨论愉快的并行循环时，已经看到了一些 fork/join 模式的常见示例。fork/join 的一些实现如下：

+   `Parallel.For`

+   `Parallel.ForEach`

+   `Parallel.Invoke`

+   `System.Threading.CountdownEvent`

利用这些框架提供的方法有助于更快地开发，而开发人员无需担心同步开销。这些模式导致高吞吐量。为了实现高吞吐量和减少延迟，另一个称为推测处理的模式被广泛使用。

# 推测处理模式

推测处理模式是另一种并行编程模式，依赖于高吞吐量来减少延迟。这在存在多种执行任务的方式但用户不知道哪种方式会最快返回结果的情况下非常有用。这种方法为每种可能的方法创建一个任务，然后在处理器上执行。首先完成的任务被用作输出，忽略其他任务（它们可能仍然成功完成，但速度较慢）。

以下是典型的 `SpeculativeInvoke` 表示。它接受 `Func<T>` 数组作为参数，并并行执行它们，直到其中一个返回：

```cs
public static T SpeculativeInvoke<T>(params Func<T>[] functions)
{
    return SpeculativeForEach(functions, function => function());
}
```

以下方法并行执行传递给它的每个操作，并通过调用 `ParallelLoopState.Stop()` 方法来跳出并行循环，一旦任何被调用的实现成功执行：

```cs
public static TResult SpeculativeForEach<TSource, TResult>(
                        IEnumerable<TSource> source,
                        Func<TSource, TResult> body)
{
    object result = null;
    Parallel.ForEach(source, (item, loopState) =>
    {
        result = body(item);
        loopState.Stop();
    });
    return (TResult)result;
}
```

以下代码使用两种不同的逻辑来计算 5 的平方。我们将两种方法都传递给 `SpeculativeInvoke` 方法，并尽快打印 `result`：

```cs
Func<string> Square = () => {
                Console.WriteLine("Square Called");
                return $"Result From Square is {5 * 5}";
                };
Func<string> Square2 = () =>
             {
                 Console.WriteLine("Square2 Called");
                 var square = 0;
                 for (int j = 0; j < 5; j++)
                 {
                     square += 5;
                 }
                 return $"Result From Square2 is {square}";
             };
string result = SpeculativeInvoke(Square, Square2);
Console.WriteLine(result);
```

以下是上述代码的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/54d8ada1-e36c-45c0-8c92-fc3f760b2e44.png)

正如你将看到的，两种方法都会完成，但只有第一个完成的执行的输出会返回给调用者。创建太多任务可能会对系统内存产生不利影响，因为需要分配和保留更多的变量在内存中。因此，只有在实际需要时分配对象变得非常重要。我们的下一个模式可以帮助我们实现这一点。

# 懒惰模式

懒惰是应用程序开发人员用来提高应用程序性能的另一种编程模式。懒惰是指延迟计算直到实际需要。在最佳情况下，可能根本不需要计算，这有助于不浪费计算资源，从而提高整个系统的性能。懒惰评估在计算机领域并不新鲜，LINQ 大量使用*延迟加载*。LINQ 遵循延迟执行模型，在这个模型中，查询直到我们使用一些迭代器函数调用`MoveNext()`时才被执行。

以下是一个线程安全的懒惰单例模式的示例，它利用一些繁重的计算操作进行创建，因此是延迟的：

```cs
public class LazySingleton<T> where T : class
    {
        static object _syncObj = new object();
        static T _value;
        private LazySingleton()
        {
        }
        public static T Value
        {
            get
            {
                if (_value == null)
                {
                    lock (_syncObj)
                    {
                        if (_value == null)
                            _value = SomeHeavyCompute();
                    }
                }
                return _value;
            }
        }
        private static T SomeHeavyCompute() { return default(T); }
    }
```

通过调用`LazySingleton<T>`类的`Value`属性来创建一个懒惰对象。懒惰保证对象直到调用`Value`属性时才被创建。一旦创建，单例实现确保在后续调用时返回相同的对象。对`_value`的空值检查避免在后续调用时创建锁，从而节省一些内存 I/O 操作并提高性能。

我们可以通过使用`System.Lazy<T>`来避免编写太多的代码，如下面的代码示例所示：

```cs
public class MyLazySingleton<T>
{
    //Declare a Lazy<T> instance with initialization 
    //function (SomeHeavyCompute) 
    static Lazy<T> _value = new Lazy<T>();
    //Value property to return value of Lazy instance when 
    //actually required by code
    public T Value { get { return _value.Value; } }
    //Initialization function
    private static T SomeHeavyCompute() 
    { 
        return default(T); 
    }
}
```

在使用异步编程时，我们可以结合`Lazy<T>`和 TPL 的力量来取得显著的结果。

以下是使用`Lazy<T>`和`Task<T>`来实现懒惰和异步行为的示例：

```cs
var data = new Lazy<Task<T>>(() => Task<T>.Factory.StartNew(SomeHeavyCompute));
```

我们可以通过`data.Value`属性访问底层的`Task`。底层的懒惰实现将确保每次调用`data.Value`属性时返回相同的任务实例。这在你不想启动许多线程，只想启动一个可能执行一些异步处理的单个线程的情况下非常有用。

考虑以下代码片段，它从服务中获取数据，并将其保存到 Excel 或 CSV 文件中，使用两种不同的线程实现：

```cs
public static string GetDataFromService()
{
    Console.WriteLine("Service called");
    return "Some Dummy Data";
}
```

以下是两个示例方法，其中的逻辑可以保存为文本或 CSV 格式：

```cs
public static void SaveToText(string data)
{
    Console.WriteLine("Save to Text called");
    //Save to Text
}
public static void SaveToCsv(string data)
{
    Console.WriteLine("Save to CSV called");
    //Save to CSV
}
```

以下代码显示了我们如何将服务调用包装在`lazy`中，并确保只有在需要时才进行一次服务调用，而输出可以异步使用。正如你所看到的，我们已经将延迟初始化方法包装为一个任务，使用`Task.Factory.StartNew(GetDataFromService)`：

```cs
 //
 Lazy<Task<string>> lazy = new Lazy<Task<string>>(
  Task.Factory.StartNew(GetDataFromService));
  lazy.Value.ContinueWith((s)=> SaveToText(s.Result));
  lazy.Value.ContinueWith((s) => SaveToCsv(s.Result));
```

以下是前述代码的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/c4b012ec-745d-4df6-ae05-ad40382ceb23.png)

正如你所看到的，服务只被调用了一次。每当需要创建对象时，懒惰模式对开发人员来说是一个值得考虑的建议。当我们创建多个任务时，我们面临与资源同步相关的问题。在这些情况下，对共享状态模式的理解非常有用。

# 共享状态模式

我们在第五章中介绍了这些模式的实现，*同步原语*。

并行应用程序必须不断处理共享状态问题。应用程序将具有一些数据成员，在多线程环境中访问时需要受到保护。处理共享状态问题有许多方法，例如使用`同步`、`隔离`和`不可变性`。同步可以使用.NET Framework 提供的同步原语来实现，并且还可以对共享数据成员提供互斥。不可变性保证数据成员只有一个状态，永远不会改变。因此，相同的状态可以在线程之间共享而不会出现任何问题。隔离处理每个线程都有自己的数据成员副本。

现在，让我们总结一下本章学到的内容。

# 总结

在本章中，我们介绍了并行编程的各种模式，并提供了每种模式的示例。虽然不是详尽无遗的列表，但这些模式可以成为并行应用程序编程开发人员的良好起点。

简而言之，我们讨论了`MapReduce`模式、推测处理模式、懒惰模式和聚合模式。我们还介绍了一些实现模式，比如分支/合并和共享状态模式，这两种模式都在.NET Framework 库中用于并行编程。

在下一章中，我们将介绍分布式内存管理，并重点了解共享内存模型以及分布式内存模型。我们还将讨论各种类型的通信网络及其具有示例实现的属性。

# 问题

1.  以下哪个不是分支/合并模式的实现？

1.  `System.Threading.Barrier`

1.  `System.Threading.Countdown`

1.  `Parallel.For`

1.  `Parallel.ForEach`

1.  以下哪个是 TPL 中懒惰模式的实现？

1.  `Lazy<T>`

1.  懒惰单例

1.  `LazyInitializer`

1.  哪种模式依赖于实现高吞吐量以减少延迟？

1.  懒惰

1.  共享状态

1.  推测处理

1.  如果您需要从列表中过滤数据并返回单个输出，可以使用哪种模式？

1.  聚合

1.  `MapReduce`


# 第十四章：分布式内存管理

在过去的二十年中，行业已经看到了一个向大数据和机器学习架构的转变，这些架构涉及尽可能快地处理 TB / PB 级别的数据。随着计算能力变得更加便宜，需要使用多个处理器来加速处理规模更大的数据。这导致了分布式计算。分布式计算是指通过某种网络/分发中间件连接的计算机系统的安排。所有连接的系统共享资源，并通过中间件协调它们的活动，以便它们以最终用户感知为单个系统的方式工作。由于现代应用程序的巨大容量和吞吐量要求，需要分布式计算。一些典型的示例场景，其中单个系统无法满足计算需求，需要在计算机网格上分布的情况如下：

+   谷歌每年至少进行 1500 亿次搜索。

+   物联网设备向事件中心发送多个 TB 的数据。

+   数据仓库在最短的时间内接收和计算 TB 级别的记录。

在本章中，我们将讨论分布式内存管理和分布式计算的需求。我们还将了解分布式系统中如何通过通信网络传递消息，以及各种类型的通信网络。

本章将涵盖以下主题：

+   分布式系统的优势

+   共享内存模型与分布式内存模型

+   通信网络的类型

+   通信网络的属性

+   探索拓扑结构

+   使用消息传递编程来编程分布式内存机器

+   集合

# 技术要求

要完成本章，您需要了解在 C 和 C# Windows 平台 API 调用编程中的编程知识。

# 分布式系统简介

我们已经在本书中讨论了分布式计算的工作原理。在本节中，我们将尝试通过一个在数组上工作的小例子来理解分布式计算。

假设我们有一个包含 1040 个元素的数组，我们想找出所有数字的总和：

```cs
a = [1,2,3, 4...., n]
```

如果将数字相加所需的总时间为 x（假设所有数字都很大），并且我们希望尽快计算它们，我们可以利用分布式计算。我们将数组分成多个数组（假设有四个数组），每个数组包含原始元素数量的 25％，并将每个数组发送到不同的处理器以计算总和，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/b7f7894c-f365-49da-af19-6ef8f87398a9.png)

在这种安排中，将所有数字相加所需的总时间减少到（x/4 + d）或（x/处理器数量 + d），其中 d 是从所有处理器收集总和并将它们相加以获得最终结果所需的时间。

分布式系统的一些优势如下：

+   系统可以在没有任何硬件限制的情况下扩展到任何级别

+   没有单点故障，使它们更具容错性

+   高度可用

+   处理大数据问题时非常高效

分布式系统经常与并行系统混淆，但它们之间有微妙的区别。**并行系统**是一种多处理器的排列，它们大多放置在单个容器中，但有时也放置在多个容器中。**分布式系统**则由多个处理器组成（每个处理器都有自己的内存和 I/O 设备），它们通过网络连接在一起，实现数据交换。

# 共享与分布式内存模型

为了实现高性能，多处理器和多计算机架构已经发展。使用多处理器架构，多个处理器共享一个公共内存，并通过读/写共享内存进行通信。使用多计算机，多台不共享单个物理内存的计算机通过传递消息进行通信。**分布式共享内存**（**DSM**）处理在物理、非共享（分布式）架构中共享内存。

让我们分别看看它们，并谈论它们的区别。

# 共享内存模型

在共享内存模型的情况下，多个处理器共享单个公共内存空间。由于多个处理器共享内存空间，需要一些同步措施来避免数据损坏和竞争条件。正如我们在本书中所看到的，同步会带来性能开销。以下是共享内存模型的示例表示。如您所见，排列中有**n**个处理器，所有这些处理器都可以访问一个共享的内存块：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/eb451b6f-2779-413e-bc9a-455b1f0052fc.png)

共享内存模型的特点如下：

+   所有处理器都可以访问整个内存块。内存块可以是由内存模块组成的单个内存块，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/7287eb33-3361-43f9-93b4-a602c63f4f90.png)

+   处理器通过在主内存中创建共享变量来相互通信。

+   并行化的效率在很大程度上取决于服务总线的速度。

+   由于服务总线的速度，系统只能扩展到 n 个处理器。

共享内存模型也被称为**对称多处理**（**SMP**）模型，因为所有处理器都可以访问所有可用的内存块。

# 分布式内存模型

在分布式内存模型的情况下，内存空间不再跨处理器共享。事实上，处理器不共享共同的物理位置；相反，它们可以远程放置。每个处理器都有自己的私有内存空间和 I/O 设备。数据存储在处理器之间而不是单个内存中。每个处理器可以处理自己的本地数据，但要访问存储在其他处理器内存中的数据，它们需要通过通信网络连接。数据通过**消息传递**在处理器之间传递，使用*发送消息*和*接收消息*指令。以下是分布式内存模型的图示表示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/b9184ffd-8815-494e-984a-75466e0d829b.png)

上图描述了每个处理器及其自己的内存空间，并通过 I/O 接口与**通信网络**进行交互。让我们试着了解分布式系统中可以使用的各种通信网络类型。

# 通信网络的类型

通信网络是连接典型计算机网络中的两个或多个节点的链路。通信网络分为两类：

+   静态通信网络

+   动态通信网络

让我们来看看两者。

# 静态通信网络

静态通信网络包含链接，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/dd8b6d89-e3e9-42dd-9add-60e7da9f3c9a.png)

链接用于连接节点，从而创建一个完整的通信网络，其中任何节点都可以与任何其他节点通信。

# 动态通信网络

动态通信网络具有链接和交换机，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/747dae92-c2d8-4f26-b3f1-bf16ee8c33ae.png)

交换机是具有输入/输出端口的设备，并将输入数据重定向到输出端口。这意味着路径是动态的。如果一个处理器想要向另一个处理器发送数据，就需要通过交换机进行，如前图所示。

# 通信网络的属性

在设计通信网络时，我们需要考虑以下特性：

+   拓扑

+   路由算法

+   交换策略

+   流量控制

让我们更详细地看看这些特性。

# 拓扑

拓扑指的是节点（桥接器、交换机和基础设备）的连接方式。一些常见的拓扑包括交叉开关、环形、2D 网格、3D 网格、更高维网格、2D 环、3D 环、更高维环、超立方体、树、蝴蝶、完美洗牌和蜻蜓。

在交叉开关拓扑的情况下，网络中的每个节点都连接到每个其他节点（尽管它们可能不是直接连接的）。因此，消息可以通过多条路由传递，以避免任何冲突。以下是一个典型的交叉开关拓扑：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/72c0ae88-b930-4d0e-ac5c-3b30d31f49e2.png)

在网状拓扑或者常被称为网状网络的情况下，节点直接连接到彼此，而不依赖于网络中的其他节点。这样，所有节点都可以独立地中继信息。网状可以是部分连接或完全连接的。以下是一个典型的完全连接的网状：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/8ba15fd5-ddef-42d3-ba5d-1a63f576c968.png)

我们将在本章后面更详细地讨论拓扑，在*探索拓扑*部分。

# 路由算法

路由是通过网络发送信息包以使其到达预定节点的过程。路由可以是自适应的，即它通过不断从相邻节点获取信息来响应网络拓扑的变化，也可以是非自适应的，即它们是静态的，并且在网络引导时将路由信息下载到节点。需要选择路由算法以确保没有死锁。例如，在 2D 环中，所有路径都从东到西和从北到南，以避免任何死锁情况。我们将在本章后面更详细地讨论 2D 环。

# 交换策略

选择适当的交换策略可以提高网络的性能。最突出的两种交换策略如下：

+   **电路交换**：在电路交换中，整个消息的完整路径被保留，比如电话。在电话网络上开始通话时，需要在呼叫方和被呼叫方之间建立专用电路，并且在整个通话期间电路保持不变。

+   **分组交换**：在分组交换中，消息被分成单独路由的数据包，比如互联网。在成本效益方面，它比电路交换要好得多，因为链路的成本是由用户共享的。分组交换主要用于异步场景，比如发送电子邮件或文件传输。

# 流量控制

流量控制是网络确保数据包在发送方和接收方之间高效、无误地传输的过程。在网络拓扑的情况下，发送方和接收方的速度可能不同，这可能导致瓶颈或在某些情况下丢失数据包。通过流量控制，我们可以在网络拥塞时做出决策。一些策略包括临时将数据存储到缓冲区中、将数据重新路由到其他节点、指示源节点暂停传输、丢弃数据等。以下是一些常见的流量控制算法：

+   **停止等待**：整个消息被分成部分。发送方将一部分发送给接收方，并等待在特定时间段（超时）内收到确认。一旦发送方收到确认，就发送消息的下一部分。

+   **滑动窗口**：接收方为发送方分配一个传输窗口来发送消息。当窗口已满时，发送方必须停止传输，以便接收方可以处理消息并通知下一个传输窗口。当接收方将数据存储在缓冲区中并且只能接收缓冲区容量时，这种方法效果最好。

# 探索拓扑

到目前为止，我们已经看过一些完整的通信网络，其中每个处理器都可以直接与其他处理器通信，而不需要任何交换机。当处理器数量较少时，这种排列效果很好，但如果需要增加处理器数量，就会变得非常麻烦。还有其他各种性能拓扑可供使用。在测量拓扑中的图的性能时有两个重要方面：

+   **图的直径**：节点之间的最长路径。

+   **二分带宽**：将网络分成两个相等的部分的最小切割的带宽。这对于每个处理器都需要与其他处理器通信的网络非常重要。

以下是一些网络拓扑的示例。

# 线性和环形拓扑

这些拓扑结构与 1D 数组配合得很好。在线性拓扑的情况下，所有处理器都按线性排列，有一个输入和输出流，而在环形拓扑的情况下，处理器形成一个回路返回到起始处理器。

让我们更详细地看一下它们。

# 线性数组

所有处理器都按线性排列，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/9152fa9a-b82e-455c-842d-3151c377c2bd.png)

这种排列将具有以下直径和二分带宽的值：

+   直径= n-1，其中 n 是处理器的数量

+   二分带宽= 1

# 环形或环面

所有处理器都处于环形排列中，信息从一个处理器流向另一个处理器，然后回到起始处理器。然后，这形成一个环，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/ae99c2b1-8be7-4553-9c32-36af39d9a9ab.png)

这种排列将具有以下直径和二分带宽的值：

+   直径= n/2，其中 n 是处理器的数量

+   二分带宽= 2

# 网格和环形

这些拓扑结构与 2D 和 3D 数组配合得很好。让我们更详细地看一下它们。

# 2D 网格

在网格的情况下，节点直接连接到彼此，而不依赖于网络中的其他节点。所有节点都处于 2D 网格排列中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/34161c13-68fb-401a-9714-63d04dfba3bf.png)

这种排列将具有以下直径和二分带宽的值：

+   直径= 2 * ( sqrt ( n ) – 1 )，其中 n 是处理器的数量

+   二分带宽= sqrt( n )

# 2D 环面

所有处理器都按 2D 环排列，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/52becade-ebc1-4083-b14f-fb61aef07e7c.png)

这种排列将具有以下直径和二分带宽的值：

+   直径= sqrt( n )，其中 n 是处理器的数量

+   二分带宽= 2 * sqrt(n)

# 使用消息传递编程分布式内存机器

在本节中，我们将讨论如何使用 Microsoft 的消息传递接口（MPI）编程分布式内存机器。

MPI 是一个标准的、可移植的系统，专为分布式和并行系统开发。它定义了一组基本函数，这些函数由并行硬件供应商用于支持分布式内存通信。在接下来的章节中，我们将讨论使用 MPI 相对于旧的消息传递库的优势，并解释如何安装和运行一个简单的 MPI 程序。

# 为什么使用 MPI？

MPI 的一个优点是 MPI 例程可以从各种语言中调用，如 C、C++、C#、Java、Python 等。与旧的消息传递库相比，MPI 具有高度的可移植性，MPI 例程针对它们应该运行的每一块硬件进行了速度优化。

# 在 Windows 上安装 MPI

MPI 可以从[`www.open-mpi.org/software/ompi/v1.10/`](https://www.open-mpi.org/software/ompi/v1.10/)下载并安装为 ZIP 文件。

或者，您可以从[`github.com/Microsoft/Microsoft-MPI/releases`](https://github.com/Microsoft/Microsoft-MPI/releases)下载 Microsoft 版本的 MPI。

# 使用 MPI 的示例程序

以下是一个简单的`HelloWorld`程序，我们可以使用 MPI 来运行。该程序在延迟两秒后打印代码正在执行的处理器编号。相同的代码可以在多个处理器上运行（我们可以指定处理器数量）。

让我们在 Visual Studio 中创建一个新的控制台应用程序项目，并在`Program.cs`文件中编写以下代码：

```cs
[DllImport("Kernel32.dll"), SuppressUnmanagedCodeSecurity]
public static extern int GetCurrentProcessorNumber();

static void Main(string[] args)
{
    Thread.Sleep(2000);
    Console.WriteLine($"Hello {GetCurrentProcessorNumber()} Id");
}
```

`GetCurrentProcessorNumber()`是一个实用函数，可以给出我们的代码正在执行的处理器编号。正如您从前面的代码中看到的，这并没有什么神奇之处-它作为一个单线程运行，并打印`Hello`和当前处理器编号。

我们将从*在 Windows 上安装 MPI*部分提供的 Microsoft MPI 链接中安装`msmpisetup.exe`。安装完成后，我们需要从命令提示符中执行以下命令：

```cs
C:\Program Files\Microsoft MPI\Bin>mpiexec.exe -n 5 “path to executable “
```

在这里，`n`表示我们希望程序在其上运行的处理器数量。

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/48ac4d96-b03a-4576-9e1f-1cb7510007ca.png)

正如您所看到的，我们可以使用 MPI 在多个处理器上运行相同的程序。

# 基本的发送/接收使用

MPI 是一个 C++实现，微软网站上的大部分文档只能用 C++访问。然而，很容易创建一个.NET 编译包装器并在我们的任何项目中使用它。也有一些第三方.NET 实现可用于 MPI，但遗憾的是，目前还没有.NET Core 实现的支持。

以下是`MPI_Send`函数的语法，它将一个数据缓冲区发送到另一个处理器：

```cs
int MPIAPI MPI_Send(
  _In_opt_ void         *buf, //pointer to buffer containing Data to send
           int          count, //Number of elements in buffer
           MPI_Datatype datatype,//Datatype of element in buffer
           int          dest, //rank of destination process
           int          tag, //tag to distinguish between messages
           MPI_Comm     comm //Handle to communicator
);
```

当缓冲区可以安全重用时，该方法将返回。

以下是`MPU_Recv`函数的语法，它将从另一个处理器接收一个数据缓冲区：

```cs
int MPIAPI MPI_Recv(
  _In_opt_ void         *buf,
           int          count,
           MPI_Datatype datatype,
           int          source,
           int          tag,
           MPI_Comm     comm,
  _Out_    MPI_Status   *status //Returns MPI_SUCCESS  or the error code.
);
```

该方法在缓冲区被接收之前不会返回。

以下是使用发送和接收函数的典型示例：

```cs
#include “mpi.h”
#include <iostream> int main( int argc, char *argv[]) { int rank, buffer; MPI::Init(argv, argc); rank = MPI::COMM_WORLD.Get_rank(); // Process 0 sends data as buffer and Process 1 receives data as buffer if (rank == 0) { buffer = 999999; MPI::COMM_WORLD.Send( &buffer, 1, MPI::INT, 1, 0 ); } else if (rank == 1) { MPI::COMM_WORLD.Recv( &buffer, 1, MPI::INT, 0, 0 ); std::cout << “Data Received “ << buf << “\n”; } MPI::Finalize(); return 0; }
```

通过 MPI 运行时，通信器将发送数据，该数据将由另一个处理器中的接收函数接收。

# 集合

集合，顾名思义，是一种通信方法，其中通信器中的所有处理器都参与其中。集合帮助我们完成这些任务。用于此目的的两种主要使用的集合方法如下：

+   `MPI_BCAST`：这个函数将数据从一个（根）进程分发到通信器中的另一个处理器

+   `MPI_REDUCE`：这个函数将从通信器中的所有处理器中合并数据，并将其返回给根进程

现在我们了解了集合，我们已经到达了本章的结尾，也是本书的结尾。现在，是时候看看我们学到了什么了！

# 总结

在本章中，我们讨论了分布式内存管理实现。我们学习了分布式内存管理模型，如共享内存和分布式内存处理器，以及它们的实现。最后，我们讨论了 MPI 是什么以及如何利用它。我们还讨论了通信网络和实现高效网络的各种设计考虑。现在，您应该对网络拓扑、路由算法、交换策略和流量控制有很好的理解。

在本书中，我们已经涵盖了.NET Core 3.1 中可用的各种编程构造，以实现并行编程。如果正确使用，并行编程可以极大地提高应用程序的性能和响应能力。.NET Core 3.1 中可用的新功能和语法确实使编写/调试和维护并行代码变得更加容易。我们还讨论了在 TPL 出现之前我们如何编写多线程代码，以进行比较。

通过新的异步编程构造（async 和 await），我们学习了如何充分利用非阻塞 I/O，同时程序流程是同步的。然后，我们讨论了诸如异步流和异步主方法之类的新功能，这些功能可以帮助我们更轻松地编写异步代码。我们还讨论了 Visual Studio 中的并行工具支持，可以帮助我们更好地调试代码。最后，我们讨论了如何为并行代码编写单元测试用例，以使我们的代码更加健壮。

然后，我们通过介绍分布式编程技术以及如何在.NET Core 中使用它们来结束了这本书。

# 问题

1.  ____________ 是将多处理器放置在单个容器中，但有时也放置在彼此紧邻的多个容器中的一种安排。

1.  在动态通信网络的情况下，任何节点都可以向任何其他节点发送数据。

1.  真

1.  假

1.  以下哪些是通信网络的特征？

1.  拓扑

1.  切换策略

1.  流量控制

1.  共享内存

1.  在分布式内存模型的情况下，内存空间在处理器之间共享。

1.  真

1.  假

1.  电路切换可以用于异步场景。

1.  真

1.  假


# 第十五章：评估

# 第一章-并行编程简介

1.  2

1.  2

1.  2

1.  2

1.  2

# 第三章-实现数据并行性

1.  2

1.  1

1.  2

1.  2

1.  2

# 第四章-使用 PLINQ

1.  2

1.  1

1.  2

1.  2

1.  1

# 第五章-同步原语

1.  3

1.  4

1.  3

1.  1

1.  1

# 第六章-使用并发集合

1.  4

1.  1

1.  1

1.  4

# 第七章-使用延迟初始化提高性能

1.  2

1.  1

1.  2

1.  3

# 第八章-异步编程简介

1.  1

1.  1，2，3

1.  1，2

1.  1

# 第九章-异步，等待和基于任务的异步编程基础

1.  2

1.  1，2，3

1.  1

1.  1

1.  1

1.  2

# 第十章-使用 Visual Studio 调试任务

1.  3

1.  1

1.  2

1.  2

1.  3

# 第十一章-为并行和异步代码编写单元测试用例

1.  1

1.  2

1.  1

1.  3

1.  2

# 第十二章-ASP.NET Core 中的 IIS 和 Kestrel

1.  1

1.  1

1.  4

1.  1

# 第十三章-并行编程中的模式

1.  1

1.  2

1.  3

1.  2

# 第十四章-分布式内存管理

1.  并行系统

1.  2

1.  4

1.  2
