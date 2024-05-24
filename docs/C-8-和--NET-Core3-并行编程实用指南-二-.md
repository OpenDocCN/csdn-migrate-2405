# C#8 和 .NET Core3 并行编程实用指南（二）

> 原文：[`zh.annas-archive.org/md5/BE48315910DEF416E754F7470D0341EA`](https://zh.annas-archive.org/md5/BE48315910DEF416E754F7470D0341EA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 PLINQ

PLINQ 是**Language Integrate Query**（LINQ）的并行实现。PLINQ 首次在.NET Framework 4.0 中引入，此后已经变得功能丰富。在 LINQ 之前，开发人员很难从各种数据源（如 XML 或数据库）中获取数据，因为每个源都需要不同的技能。LINQ 是一种语言语法，依赖于.NET 委托和内置方法来查询或修改数据，而无需担心学习低级任务。

在本章中，我们将首先了解.NET 中的 LINQ 提供程序。随着 PLINQ 成为程序员的首选，我们将涵盖其各种编程方面，以及与之相关的一些缺点。最后，我们将了解影响 PLINQ 性能的因素。

我们将涵盖以下主题：

+   .NET 中的 LINQ 提供程序

+   编写 PLINQ 查询

+   在 PLINQ 中保持顺序

+   PLINQ 中的合并选项

+   在 PLINQ 中处理异常

+   组合并行和顺序查询

+   PLINQ 的缺点

+   PLINQ 中的加速

# 技术要求

要完成本章，您应该对 TPL 和 C#有很好的了解。本章的源代码可在 GitHub 上找到[`github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter04`](https://github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter04)。

# .NET 中的 LINQ 提供程序

LINQ 是一组 API，帮助我们更轻松地处理 XML、对象和数据库。LINQ 有许多提供程序，包括以下常用的：

+   对象的 LINQ：LINQ 到对象允许开发人员查询内存中的对象，如数组、集合、泛型类型等。它返回一个`IEnumerable`，支持排序、过滤、分组、排序和聚合函数等功能。其功能在`System.Linq`命名空间中定义。

+   LINQ 到 XML：LINQ 到 XML 允许开发人员查询或修改 XML 数据源。它在`System.Xml.Linq`命名空间中定义。

+   LINQ 到 ADO.NET：LINQ 到 ADO.NET 不是一个技术，而是一组技术，允许开发人员查询或修改关系数据源，如 SQL Server、MySQL 或 Oracle。

+   LINQ 到 SQL：也称为 DLINQ。DLINQ 使用对象关系映射（ORM），是微软支持但不再增强的传统技术。它仅适用于 SQL Server，并允许用户将数据库表映射到.NET 类。它还有一个适配器，类似于开发人员接口到数据库。

+   LINQ 到数据集：这允许开发人员查询或修改内存中的数据集。它与 ADO.NET 支持的任何数据库一起工作。

+   实体的 LINQ：这是最先进和最受追捧的技术。它允许开发人员使用任何关系数据库，包括 SQL Server、Oracle、IBM Db2 和 MySQL。LINQ to entities 还支持 ORM。

+   PLINQ：也称为 PLINQ。PLINQ 是对象的 LINQ 的并行实现。LINQ 查询是顺序执行的，对于大量计算操作来说可能非常慢。PLINQ 通过在多个线程上调度任务，并且可选地在多个核心上运行，支持查询的并行执行。

.NET 支持使用`AsParallel()`方法将 LINQ 无缝转换为 PLINQ。PLINQ 是进行大量计算操作的非常好的选择。它通过将源数据分成块，然后由运行在多个核心上的不同线程执行来工作。PLINQ 还支持 XLINQ 和 LINQ 到对象。

# 编写 PLINQ 查询

要理解 PLINQ 查询，我们需要先了解`ParallelEnumerable`类。一旦我们了解了`ParallelEnumerable`类，我们将学习如何编写并行查询。

# 介绍 ParallelEnumerable 类

`ParallelEnumerable`类位于`System.Linq`命名空间和`System.Core`程序集中。

除了支持 LINQ 定义的大多数标准查询操作符之外，`ParallelEnumerable`类还支持许多额外的支持并行执行的方法：

+   `AsParallel()`: 这是并行化所需的种子方法。

+   `AsSequential()`:通过改变并行行为，启用并行查询的顺序执行。

+   `AsOrdered()`: 默认情况下，PLINQ 不保留任务执行和结果返回的顺序。我们可以通过调用`AsOrdered()`方法来保留这个顺序。

+   `AsUnordered()`:这是`ParallelQuery`的默认行为，可以通过`AsOrdered()`方法覆盖。我们可以通过调用这个方法将行为从有序改为无序。

+   `ForAll()`:启用并行执行查询。

+   `Aggregate()`: 这个方法可以用来聚合并行查询中各个线程本地分区的结果。

+   `WithDegreesOfParallelism()`:使用这个方法，我们可以指定用于并行化查询执行的最大处理器数量。

+   `WithParallelOption()`:使用这个方法，我们可以缓冲并行查询产生的结果。

+   `WithExecutionMode()`:使用这个方法，我们可以强制查询的并行执行，或者让 PLINQ 决定查询是否需要以顺序或并行方式执行。

我们将通过代码示例在本章后面学习更多关于这些方法的内容。这里值得一提的是一个非常方便的工具叫做 LINQPad。LINQPad 帮助我们学习关于 LINQ/PLINQ 查询，因为它有 500 多个可用的示例和连接到各种数据源的能力。您可以从[`www.linqpad.net/`](https://www.linqpad.net/)下载它。

# 我们的第一个 PLINQ 查询

假设我们想要找到所有可以被三整除的数字。

首先，我们定义一个范围为 100,000 的数字：

```cs
var range = Enumerable.Range(1, 100000);
```

要顺序找到所有可以被三整除的数字，使用以下 LINQ 查询：

```cs
var resultList = range.Where(i => i % 3 == 0).ToList();
```

以下是使用`AsParallel`方法的相同查询的并行版本，但使用方法语法：

```cs
 var resultList = range.AsParallel().Where(i => i % 3 == 0).ToList();

```

以下是在 LINQ 中使用查询语法选项的相同版本：

```cs
var resultList = (from i in range.AsParallel()
                  where i % 3 == 0
                  select i).ToList();
```

以下是完整的代码：

```cs
var range = Enumerable.Range(1, 100000);
//Here is sequential version
var resultList = range.Where(i => i % 3 == 0).ToList();
Console.WriteLine($"Sequential: Total items are {resultList.Count}");
//Here is Parallel Version using .AsParallel method
resultList = range.AsParallel().Where(i => i % 3 == 0).ToList();
resultList = (from i in range.AsParallel()
 where i % 3 == 0
 select i).ToList();
 Console.WriteLine($"Parallel: Total items are {resultList.Count}" ); 
Console.WriteLine($"Parallel: Total items are {resultList.Count}");

```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/0c9852c6-5fe8-414a-91aa-388584a16007.png)

# 在进行并行执行时保留 PLINQ 中的顺序

PLINQ 并行执行工作项，并且默认情况下不关心保留项目的顺序以提高并行查询的性能。然而，有时重要的是项目按照它们在源集合中的顺序执行。例如，想象一下，您正在向服务器发送多个请求以按块下载文件，然后在客户端合并这些块以重新创建文件。由于文件是分部分下载的，每个部分都需要按正确的顺序下载和合并。在并行执行项目时保留顺序对性能有直接影响，因为我们需要在整个分区中保留原始顺序，并在合并项目时确保顺序一致。

我们可以通过在源集合上使用`AsOrdered()`方法来覆盖默认行为并打开顺序保留。如果在任何时候，我们想要关闭顺序保留，我们可以调用`AsUnOrdered()`方法。

让我们看一个例子：

```cs
var range = Enumerable.Range(1, 10);
Console.WriteLine("Sequential Ordered"); 
range.ToList().ForEach(i => Console.Write(i + "-"));
```

这段代码是顺序的，所以当我们运行它时，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/7ee9fa01-fe43-4286-a5e7-2da1ac67513f.png)

我们可以使用`AsParallel()`方法制作一个并行版本：

```cs
Console.WriteLine("Parallel Unordered");
var unordered = range.AsParallel().Select(i => i).ToList();
unordered.ForEach(i => Console.WriteLine(i));
```

上面的代码是并行执行的，但是顺序全乱了：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/109be61b-ab59-478d-82cf-ebd3186a4600.png)

为了兼顾并行执行和顺序，我们可以修改代码如下：

```cs
var range = Enumerable.Range(1, 10);
Console.WriteLine("Parallel Ordered");
var ordered = range.AsParallel().AsOrdered().Select(i => i).ToList();                            ordered.ForEach(i => Console.WriteLine(i));
```

以下是输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/a62a7b42-bb90-4a57-8585-453ebf546d32.png)

如您所见，当我们调用`AsOrdered()`方法时，它会并行执行所有工作项，同时保留原始顺序，而在默认情况下，顺序未被保留。使用`AsOrdered()`方法的性能影响巨大，因为顺序在执行的每个步骤中都得到恢复。

# 使用 AsUnOrdered()方法进行顺序执行

一旦我们在 PLINQ 上调用了`AsOrdered`，查询将会顺序执行。可能会有一些情况，我们希望在一定时间内按顺序执行查询，但之后改为无序以获得性能。

假设我们想要生成前 100 个数字的平方，我们可以并行执行如下：

```cs
  var range = Enumerable.Range(100, 10000);
  var ordered = range.AsParallel().AsOrdered().Take(100).Select(i => i * i);
```

我们需要`AsOrdered()`来获取前 100 个数字。问题在于`Select`查询也将按顺序执行。我们可以通过结合`AsOrdered()`和`AsUnOrdered()`来提高性能：

```cs
var range = Enumerable.Range(100, 10000);
var ordered = range.AsParallel().AsOrdered().Take(100).AsUnordered().Select(i => i * i).ToList();
```

现在，前 100 个项目将并行按顺序检索。之后，查询将在不保留任何顺序的情况下执行。

# PLINQ 中的合并选项

正如我们之前提到的，当我们创建并行查询时，源集合被分区，以便多个任务可以同时处理部分。一旦查询完成，结果就需要合并，以便它们可以提供给消费线程。根据查询运算符，可以指定如何显式合并结果，使用`ParallelMergeOperation`枚举和`WithMergeOption()`扩展方法。

让我们看看我们可以使用的各种合并选项。

# 使用 NotBuffered 合并选项

并发任务的结果不会被缓冲。一旦任何任务完成，它们就会将结果返回给消费线程：

```cs
var range = ParallelEnumerable.Range(1, 100);
Stopwatch watch = null;
ParallelQuery<int> notBufferedQuery = range.WithMergeOptions(ParallelMergeOptions.NotBuffered)
                                           .Where(i => i % 10 == 0)
                                           .Select(x => {
                                                     Thread.SpinWait(1000);
                                                     return x;
                                                        });
watch = Stopwatch.StartNew();
foreach (var item in notBufferedQuery)
{
    Console.WriteLine( $"{item}:{watch.ElapsedMilliseconds}");
}
Console.WriteLine($"\nNotBuffered Full Result returned in {watch.ElapsedMilliseconds} ms");
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/f57d286b-cd53-4c1e-a6a8-4ce2c49db628.png)

# 使用 AutoBuffered 合并选项

并发任务的结果被缓冲，并且缓冲区定期提供给消费线程。根据集合的大小，可能会返回多个缓冲区。使用此选项，消费线程需要等待更长时间才能获得第一个结果。这也是默认选项。

考虑以下代码：

```cs
var range = ParallelEnumerable.Range(1, 100);
Stopwatch watch = null;
ParallelQuery<int> query = range.WithMergeOptions(ParallelMergeOptions.AutoBuffered)
                                .Where(i => i % 10 == 0)
                                .Select(x => {
                                             Thread.SpinWait(1000);
                                             return x;
                                             });
watch = Stopwatch.StartNew();
foreach (var item in query)
{
    Console.WriteLine($"{item}:{watch.ElapsedMilliseconds}");
}
Console.WriteLine($"\nAutoBuffered Full Result returned in {watch.ElapsedMilliseconds} ms");
watch.Stop();
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/a4ff17e0-f114-4331-96ef-0cdfc05fb90d.png)

# 使用 FullyBuffered 合并选项

并发任务的结果在提供给消费线程之前完全缓冲。这提高了整体性能，尽管获得第一个结果所需的时间会更长：

```cs
var range = ParallelEnumerable.Range(1, 100);
Stopwatch watch = null;
ParallelQuery<int> fullyBufferedQuery = range.WithMergeOptions(ParallelMergeOptions.FullyBuffered)
                                .Where(i => i % 10 == 0)
                                .Select(x => {
                                              Thread.SpinWait(1000);
                                              return x;
                                              });
watch = Stopwatch.StartNew();
foreach (var item in fullyBufferedQuery)
{
    Console.WriteLine($"{item}:{watch.ElapsedMilliseconds}");
}
Console.WriteLine($"\nFullyBuffered Full Result returned in {watch.ElapsedMilliseconds} ms");
watch.Stop();
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/3438d1bb-7fa1-4d8a-b73f-7bb47658899f.png)

并非所有查询运算符都支持所有合并模式。以下是一些运算符及其限制的列表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/e4778fae-b79c-4ac2-9f71-ae424eea9626.png)

此信息可在[`msdn.microsoft.com/en-us/library/dd997424(v=vs.110).aspx`](http://msdn.microsoft.com/en-us/library/dd997424(v=vs.110).aspx)找到。

除了前面的运算符外，`ForAll()`始终为`NotBuffered`，`OrderBy`始终为`FullyBuffered`。如果在这些运算符上指定了任何自定义合并选项，则它们将被忽略。

# 使用 PLINQ 抛出和处理异常

与其他并行原语一样，每当 PLINQ 遇到异常时，都会抛出`System.AggregateException`。异常处理在很大程度上取决于您的设计。您可能希望程序尽快失败，或者您可能希望所有异常都返回给调用者。

在以下示例中，我们将在`try`-`catch`块中包装一个并行查询。当查询引发异常时，它将传播回调用者，包装在`System.AggregateException`中：

```cs
var range = ParallelEnumerable.Range(1, 20);
ParallelQuery<int> query= range.Select(i => i / (i - 10)).WithDegreeOfParallelism(2);
try
{
    query.ForAll(i => Console.WriteLine(i));
}
catch (AggregateException aggregateException)
{
    foreach (var ex in aggregateException.InnerExceptions)
    {
        Console.WriteLine(ex.Message);
        if (ex is DivideByZeroException)
            Console.WriteLine("Attempt to divide by zero. Query 
             stopped.");
    }
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/c8c67d50-21a0-4685-a992-5ed7d2be1a04.png)

我们还可以在委托内部指定一个`try`-`catch`块，这样可以尽快通知我们有关错误条件。它还可以用于一种情况，即我们只想记录异常并通过在异常情况下提供默认值作为查询结果来继续查询的执行：

```cs
var range = ParallelEnumerable.Range(1, 20);
Func<int, int> selectDivision = (i) =>
{
    try
    {
        return  i / (i - 10);
    }
    catch (DivideByZeroException ex)
    {
        Console.WriteLine($"Divide by zero exception for {i}");
        return -1;
    }
};
ParallelQuery<int> query = range.Select(i => selectDivision(i)).WithDegreeOfParallelism(2);
try
{
    query.ForAll(i => Console.WriteLine(i));
}
catch (AggregateException aggregateException)
{
    foreach (var ex in aggregateException.InnerExceptions)
    {
        Console.WriteLine(ex.Message);
        if (ex is DivideByZeroException)
            Console.WriteLine("Attempt to divide by zero. Query stopped.");
    }
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/a11c41a4-91fe-4229-a8ad-03dd5941f418.png)

异常处理对于维护应用程序中的正确流程以及通知用户应用程序中的错误条件非常重要。通过适当的异常处理和日志记录，我们可以在生产环境中排除应用程序错误。在下一节中，我们将讨论如何合并并行和顺序查询。

# 合并并行和顺序 LINQ 查询

我们已经讨论了使用`AsParallel()`创建并行查询的用法。有时，我们可能希望按顺序执行操作。我们可以使用`AsSequential()`方法强制 PLINQ 按顺序操作。一旦这个方法应用到任何并行查询中，后续的操作将按顺序执行。考虑以下代码：

```cs
var range = Enumerable.Range(1, 1000);
range.AsParallel().Where(i => i % 2 == 0).AsSequential().Where(i => i % 8 == 0).AsParallel().OrderBy(i => i);
```

这里，第一个`Where`类，`Where(i => i % 2 == 0)`，将并行执行。然而，第二个`Where`类，`Where(i => i % 8 == 0)`，将顺序执行。`OrderBy`也将切换到并行执行模式。

如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/7a54d9fe-386b-409d-891c-fb7feebc4132.png)

现在，我们应该对如何合并同步和并行 LINQ 查询有了一个很好的了解。在下一节中，我们将学习如何取消 PLINQ 查询以节省 CPU 资源。

# 取消 PLINQ 查询

我们可以使用`CancellationTokenSource`和`CancellationToken`类取消 PLINQ 查询。取消令牌通过`WithCancellation`子句传递给 PLINQ 查询，然后我们可以调用`CancellationToken.Cancel`来取消查询操作。当查询被取消时，会抛出`OperationCancelledException`。

操作如下：

1.  创建一个取消令牌源：

```cs
CancellationTokenSource cs = new CancellationTokenSource();
Create a task that starts immediately and cancel the token after 4 seconds
     Task cancellationTask = Task.Factory.StartNew(() =>
            {
                Thread.Sleep(4000);
                cs.Cancel();
            });
```

1.  将 PLINQ 查询包装在`try`块内：

```cs
try
       {
           var result = range.AsParallel()
             .WithCancellation(cs.Token)
             .Select(number => number)
             .ToList();
       }
```

1.  添加两个`catch`块；一个用于捕获`OperationCanceledException`，另一个用于捕获`AggregateException`：

```cs
     catch (OperationCanceledException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (AggregateException ex)
            {
                foreach (var inner in ex.InnerExceptions)
                {
                    Console.WriteLine(inner.Message);
                }
            }
```

1.  将范围设置为一个非常大的值，需要超过四秒才能执行：

```cs
            var range = Enumerable.Range(1,1000000);
```

1.  运行代码。四秒后，我们将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/b9611cf2-ff56-446a-b1ec-eb8ca922b462.png)

并行编程有其自己的注意事项。在下一节中，我们将介绍使用 PLINQ 编写并行代码的缺点。

# 使用 PLINQ 的并行编程的缺点

在大多数情况下，PLINQ 的性能要比其非并行对应的 LINQ 快得多。然而，与将 LINQ 并行化相关的分区和合并会带来一些性能开销。在使用 PLINQ 时，我们需要考虑以下一些事项：

1.  **并不总是并行更快**：并行化是一种开销。除非你的源集合很大或者它有计算密集型操作，否则按顺序执行操作更有意义。始终测量顺序和并行查询的性能，以做出明智的决定。

1.  **避免涉及原子性的 I/O 操作**：所有涉及写入文件系统、数据库、网络或共享内存位置的 I/O 操作都应该避免在 PLINQ 内部进行。这是因为这些方法不是线程安全的，因此使用它们可能会导致异常。一个解决方案是使用同步原语，但这也会严重降低性能。

1.  **你的查询可能并不总是并行运行**：在 PLINQ 中进行并行化是 CLR 做出的决定。即使我们在查询中调用了`AsParallel()`方法，也不能保证它会采用并行路径，可能会顺序运行。

# 了解影响 PLINQ 性能的因素（加速）

PLINQ 的主要目的是通过将任务拆分并并行执行来加速查询执行。然而，有许多因素可能会影响 PLINQ 的性能。这些因素包括与分块和分区相关的同步开销，以及来自线程的调度和收集结果的开销。PLINQ 在*令人愉快地并行*的场景中表现最佳，其中线程不必共享状态，也不必担心执行顺序。*令人愉快地并行*是理想的，但由于工作的性质，不一定总是可行的。让我们试着了解可能影响 PLINQ 性能的因素。

# 并行度

有了更多的核心可供我们使用，我们可以实现显著的性能提升，因为 TPL 确保多个任务可以在多个核心上并发执行。性能的提升可能不是指数级的，因此在调整性能时，我们应该尝试在具有多个核心的不同系统上运行并比较结果。

# 合并选项

我们可以在结果经常变化且用户希望尽快看到结果而不必等待的情况下显著改善用户体验。PLINQ 的默认选项是缓冲结果，然后合并并将其返回给用户。我们可以通过选择适当的合并选项来修改此行为。

# 分区类型

我们应该始终检查我们的工作项是平衡的还是不平衡的。对于不平衡的工作项场景，可以引入自定义分区器来提高性能。

# 决定何时使用 PLINQ 保持顺序

我们应该始终计算每个工作项和整个操作的计算成本，以便决定是保持顺序还是转移到并行。并行查询可能并不总是快速的，因为存在分区、调度等额外开销：

*计算成本 = 执行 1 个工作项的成本 * 总工作项数*

并行查询可以在每个项目的计算成本增加时提供显著的性能提升。然而，如果性能提升非常低，那么按顺序执行查询是有意义的。

PLINQ 决定是按顺序还是并行执行取决于查询中操作符的组合。简单来说，如果查询中有以下任何一个操作符，PLINQ 可能决定按顺序运行查询：

+   `Take`、`TakeWhile`、`Skip`、`SkipWhile`、`First`、`Last`、`Concat`、`Zip`或`ElementAt`

+   索引的`Where`和`Select`，它们分别是`Where`和`Select`的重载

以下代码演示了使用索引的`Where`和`Select`：

```cs
IEnumerable<int> query =
    numbers.AsQueryable()
    .Where((number, index) => number <= index * 10);
IEnumerable<bool> query =
    range.AsQueryable()
    .Select((number, index) => number <= index * 10);
```

# 操作顺序

与无序集合相比，PLINQ 在性能上提供了更好的表现，因为使集合按顺序执行会带来性能成本。这种性能成本包括分区、调度和收集结果，以及调用`GroupJoin`和过滤器。作为开发人员，您应该考虑何时使用`AsOrdered()`。

# ForAll 与调用 ToArray()或 ToList()的区别

当我们调用`ToList()`或`ToArray()`或在循环中枚举结果时，我们强制 PLINQ 将所有并行线程的结果合并为单个数据结构。这是一种性能开销。如果我们只是想对一组项目执行一些操作，最好使用`ForAll()`方法。

# 强制并行

PLINQ 并不保证每次都进行并行执行。它可能决定按顺序执行，这取决于查询的类型。我们可以使用`WithExecutionMode`方法来控制这一点。`WithExecutionMode`是一个作用于`ParallelQuery`类型对象的扩展方法。它以`ParallelExecutionMode`作为参数，这是一个枚举。`ParallelExecutionMode`的默认值让 PLINQ 决定最佳的执行模式。我们可以使用`ForceParallelism`选项强制执行模式为并行：

```cs
var range = Enumerable.Range(1, 10);
var squares = range.AsParallel().WithExecutionMode
(ParallelExecutionMode.ForceParallelism).Select(i => i * i);
squares.ToList().ForEach(i => Console.Write(i + "-"));
```

# 生成序列

在整本书中，我们使用`Enumerable.Range()`方法来生成一系列数字。我们也可以使用`ParallelEnumerable`类来并行生成数字。让我们对`Enumerable`和`ParallelEnumerable`类进行一个简单的测试比较：

```cs
Stopwatch watch = Stopwatch.StartNew();
IEnumerable<int> parallelRange = ParallelEnumerable.Range(0, 5000).Select(i => i);
watch.Stop();
Console.WriteLine($"Time elapsed {watch.ElapsedMilliseconds}");
Stopwatch watch2 = Stopwatch.StartNew();
IEnumerable<int> range = Enumerable.Range(0, 5000);
watch2.Stop();
Console.WriteLine($"Time elapsed {watch2.ElapsedMilliseconds}");
Console.ReadLine();
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/b9290369-ab08-4566-9f7f-87ed4670f5c2.png)

如你所见，`ParallelEnumerable`比`Enumerable`更快地创建了一个范围。

在类似的情况下，我们可能希望生成一定数量的数字。我们可以使用`ParallelEnumerable.Repeat()`方法来实现这种情况，如下所示：

```cs
IEnumerable<int> rangeRepeat = ParallelEnumerable.Repeat(1, 5000);
```

现在我们已经了解了影响 PLINQ 性能的因素，我们已经到达了本章的结尾。现在，让我们总结一下我们学到的东西。

# 摘要

在本章中，我们讨论了 LINQ 的基础知识，然后继续了解如何使用 PLINQ 编写并行查询。我们了解到 PLINQ 可以很好地提高整个应用程序的性能，但重要的是要记住它的缺点。作为程序员，通过编写 LINQ 和 PLINQ 查询并比较它们的性能，权衡你的选择总是一个好主意。

在下一章中，我们将学习如何使用同步原语来保持数据的一致性和状态，当数据在多个线程之间共享时。

# 问题

1.  哪个 LINQ 提供程序对关系对象有更好的支持？

1.  LINQ 到 SQL

1.  实体的 LINQ

1.  我们可以通过使用`AsParallel()`轻松将 LINQ 转换为并行 LINQ。

1.  真

1.  假

1.  在 PLINQ 中无法在有序和无序执行之间切换。

1.  真

1.  假

1.  其中一个允许并发任务的结果被缓冲并定期提供给消费线程？

1.  完全缓冲

1.  自动缓冲

1.  非缓冲

1.  如果在任务内执行以下代码，将抛出哪个异常？

```cs
int i=5;
i = i/i -5;
```

1.  1.  `AggregateException`

1.  `DivideByZeroException`


# 第二部分：.NET Core 中支持并行性的数据结构

在本节中，您将更深入地了解支持并行性、并发性和同步的语言和框架构造。

本节包括以下章节：

+   第五章，*同步原语*

+   第六章，*使用并发集合*

+   第七章，*使用延迟初始化提高性能*


# 第五章：同步原语

在上一章中，我们讨论了并行编程的潜在缺陷之一是同步开销。当我们将工作分解为由多个工作项处理的任务时，就会出现需要同步每个线程的结果的情况。我们讨论了线程本地存储和分区本地存储的概念，可以在一定程度上解决这个同步问题。然而，仍然需要同步线程，以便我们可以将数据写入共享内存位置，并执行 I/O 操作。

在本章中，我们将讨论.NET Framework 和 TPL 提供的同步原语。

在本章中，我们将涵盖以下主题：

+   同步原语

+   原子操作

+   锁原语

+   信号原语

+   轻量级同步原语

+   屏障和倒计时事件

通过本章结束时，您将对.NET Framework 提供的各种锁定和信号原语有很好的理解，包括一些轻量级同步原语，应尽可能在需要同步的地方使用。

# 技术要求

要完成本章，您应该对 TPL 有很好的理解，主要是并行循环。本章的源代码可在 GitHub 上找到：[`github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter05`](https://github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter05)。

# 什么是同步原语？

在理解同步原语之前，我们需要了解临界区。临界区是线程执行路径的一部分，必须受到保护，以维护一些不变量。临界区本身不是同步原语，但依赖于同步原语。

同步原语是由底层平台（操作系统）提供的简单软件机制。它们有助于在内核中进行多线程处理。同步原语内部使用低级原子操作和内存屏障。这意味着同步原语的用户不必担心自己实现锁和内存屏障。一些常见的同步原语示例包括锁、互斥锁、条件变量和信号量。监视器是一种更高级的同步工具，它在内部使用其他同步原语。

.NET Framework 提供了一系列同步原语，用于处理线程之间的交互，以及避免潜在的竞争条件。同步原语可以大致分为五类：

+   原子操作

+   锁定

+   信号

+   轻量级同步类型

+   `SpinWait`

在接下来的章节中，我们将讨论每个类别及其各自的低级原语。

# 原子操作

Interlocked 类封装了同步原语，并用于为跨线程共享的变量提供原子操作。它提供了`Increment`、`Decrement`、`Add`、`Exchange`和`CompareExchange`等方法。

考虑以下代码，它尝试在并行循环中递增一个计数器：

```cs
Parallel.For(1, 1000, i =>
       {
           Thread.Sleep(100);
           _counter++;
       });
       Console.WriteLine($"Value for counter should be 999 and 
        is {_counter}");
```

如果我们运行此代码，将会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/02d70e3d-6df9-4fb4-824e-222489691f08.png)

如您所见，预期值和实际值不匹配。这是因为线程之间存在竞争条件，这是因为线程想要从一个变量中读取一个值，而该值尚未被提交。

我们可以使用`Interlocked`类修改上述代码，使其线程安全，如下所示：

```cs
Parallel.For(1, 1000, i =>
       {
           Thread.Sleep(100);
           Interlocked.Increment(ref _counter);
       });
       Console.WriteLine($"Value for counter should be 999 and 
        is {_counter}");
```

预期输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/a3406d7f-f496-46c5-a762-0cc384cd4b01.png)

同样，我们可以使用`Interlocked.Decrement(ref _counter)`以线程安全的方式减少值。

以下代码显示了完整的操作列表：

```cs
 //_counter becomes 1
Interlocked.Increment(ref _counter);
// _counter becomes 0
Interlocked.Decrement(ref _counter);
// Add: _counter becomes 2 
Interlocked.Add(ref _counter, 2);
//Subtract: _counter becomes 0
Interlocked.Add(ref _counter, -2);
// Reads 64 bit field 
Console.WriteLine(Interlocked.Read(ref _counter)); 
// Swaps _counter value with 10 
Console.WriteLine(Interlocked.Exchange(ref _counter, 10));
//Checks if _counter is 10 and if yes replace with 100 
Console.WriteLine(Interlocked.CompareExchange(ref _counter, 100, 10)); 
// _counter becomes 100
```

除了前面的方法，.NET Framework 4.5 中还添加了两个新方法：`Interlocked.MemoryBarrier()`和`Interlocked.MemoryBarrierProcessWide()`。

在下一节中，我们将学习更多关于.NET 中的内存屏障。

# .NET 中的内存屏障

单核处理器和多核处理器上的线程模型工作方式不同。在单核处理器上，只有一个线程获得 CPU 时间片，而其他线程则等待它们的轮次。这确保了每当一个线程访问内存（用于加载和存储）时，它都是按正确的顺序进行的。这个模型也被称为**顺序一致性模型**。在多核处理器系统中，多个线程同时运行。在这些系统中，无法保证顺序一致性，因为硬件或**即时**（**JIT**）编译器可能会重新排序内存指令以提高性能。内存指令也可能会因为缓存、加载推测或延迟存储操作而进行重新排序以提高性能。

加载推测的示例如下：

```cs
a=b;
```

存储操作的示例如下：

```cs
c=1;
```

当编译器遇到加载和存储语句时，并不总是按照它们被编写的顺序执行。编译器会进行一些重新排序以获得性能上的好处。让我们试着更多地了解重新排序。

# 什么是重新排序？

对于给定的代码语句序列，编译器可以选择按照接收到的顺序执行它们，或者重新排序它们以提高性能，如果多个线程正在处理相同的代码。例如，看一下以下代码：

```cs
a = b;
c = 1;
```

前面的代码可以被重新排序并以以下顺序执行给另一个线程：

```cs
c = 1;
a = b;
```

对于具有弱内存模型的多核处理器（如英特尔 Itanium 处理器），代码重新排序是一个问题。然而，对于单核处理器来说，由于顺序一致性模型，它没有影响。代码被重组，以便另一个线程可以利用或存储已经在内存中的指令。代码重新排序可以由硬件或 JIT 编译器来完成。为了保证代码重新排序，我们需要某种**内存屏障**。

# 内存屏障的类型

内存屏障确保屏障上方或下方的任何代码语句都不会越过屏障，从而强制执行代码的顺序。有三种类型的内存屏障：

+   **存储（写入）内存屏障：**存储内存屏障确保不允许存储操作越过屏障。它对加载操作没有影响；这些操作仍然可以被重新排序。实现此效果的等效 CPU 指令是**SFENCE**：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/d03a60bd-ad17-46a1-afdc-8157aeae929d.png)

+   **加载（读取）内存屏障：**加载屏障确保不允许加载操作越过屏障，但对存储操作不做任何强制。实现此效果的等效 CPU 指令是**LFENCE**：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/6ad7473e-6976-40c6-8282-08b4300a9bf5.png)

+   **完整内存屏障：**完整内存屏障通过不允许存储或加载操作越过内存屏障来确保顺序。实现此效果的等效 CPU 指令是**MFENCE**。完整内存屏障的行为通常由.NET 同步构造实现，例如以下内容：

+   `Task.Start`、`Task.Wait`和`Task.Continuation`

+   `Thread.Sleep`、`Thread.Join`、`Thread.SpinWait`、`Thread.VolatileRead`和`Thread.VolatileWrite`

+   `Thread.MemoryBarrier`

+   `Lock`、`Monitor.Enter`和`Monitor.Exit`

+   `Interlocked`类的操作

`Volatile`关键字和`Volatile`类方法提供了半屏障。.NET Framework 提供了一些内置模式，使用类中的`Volatile`字段，如`Lazy<T>`和`LazyInitializer`。我们将在第七章中进一步讨论这些，*使用延迟初始化提高性能*。

# 使用构造避免代码重排序

我们可以使用`Thread.MemoryBarrier`避免重排序，如下面的代码所示：

```cs
static int a = 1, b = 2, c = 0;
private static void BarrierUsingTheadBarrier()
{
    b = c;
    Thread.MemoryBarrier();
    a = 1;
}
```

`Thread.MemoryBarrier`创建一个不允许加载或存储操作通过的完整屏障。它已经包装在`Interlocked.MemoryBarrier`中，因此可以将相同的代码编写如下：

```cs
private static void BarrierUsingInterlockedBarrier()
       {
           b = c;
           Interlocked.MemoryBarrier();
           a = 1;
       }
```

如果我们想创建一个进程范围和系统范围的屏障，我们可以使用.NET Core 2.0 中引入的`Interlocked.MemoryBarrierProcessWide`。这是对`FlushProcessWriteBuffer` Windows API 或 Linux 内核上的`sys_membarrier`的包装：

```cs
private static void BarrierUsingInterlockedProcessWideBarrier()
{
    b = c;
    Interlocked.MemoryBarrierProcessWide();
    a = 1;
}
```

前面的例子向我们展示了如何创建一个进程范围的屏障。现在，让我们来看看锁定原语是什么。

# 锁定原语简介

锁可以用来限制对受保护资源的访问，只允许单个线程或一组线程。为了能够有效地实现锁定，我们需要识别可以通过锁定原语保护的适当的临界区。

# 锁定的工作原理

当我们对共享资源应用锁时，执行以下步骤：

1.  一个线程或一组线程通过获取锁来访问共享资源。

1.  无法访问锁定的其他线程进入等待状态。

1.  一旦锁被一个线程释放，另一个线程就会获取它，并开始执行。

要理解锁定原语，我们需要了解各种线程状态，以及阻塞和自旋等概念。

# 线程状态

在线程的生命周期的任何时刻，我们都可以使用线程的`ThreadState`属性查询线程状态。线程可以处于以下任一状态：

+   `未启动`：线程已被 CLR 创建，但尚未调用`System.Threading.Thread.Start`方法。

+   `运行`：线程已通过调用`Thread.Start`启动。它不在等待任何未决操作。

+   `WaitSleepJoin`：由于调用`Wait()`、`Sleep()`或`Join()`方法，线程处于阻塞状态。

+   `停止请求`：线程已被请求停止。

+   `已停止`：线程已停止执行。

+   `中止请求`：在线程上调用了`Abort()`方法，但线程尚未被中止，因为它正在等待`ThreadAbortException`来尝试终止它。

+   `中止`：线程已被中止。

+   `暂停请求`：由于调用`Suspend`方法，线程被请求暂停。

+   `已暂停`：线程已被暂停。

+   `后台`：线程在后台执行。

让我们尝试探索线程从初始状态`未启动`到最终状态`已停止`的过程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/77801852-0e65-4a02-853e-ac10b7ad47c4.png)

当 CLR 创建线程时，它处于`未启动`状态。当外部线程调用`Thread.Start()`方法时，它从`未启动`状态转换到`运行`状态。从`运行`状态，线程可以转换到以下状态：

+   `WaitSleepJoin`

+   `中止请求`

+   `已停止`

当线程处于`WaitSleepJoin`状态时，就说它被阻塞了。被阻塞的线程的执行被暂停，因为它正在等待一些外部条件的满足，这可能是一些 CPU 绑定的 I/O 操作或其他线程的结果。一旦被阻塞，线程立即放弃 CPU 时间片，并且在满足阻塞条件之前不使用处理器时间片。在这一点上，线程被解除阻塞。阻塞和解除阻塞构成了性能开销，因为这需要 CPU 进行上下文切换。

线程可以在以下事件中解除阻塞：

+   如果满足阻塞条件

+   通过在被阻塞的线程上调用`Thread.Interrupt`

+   通过使用`Thread.Abort`中止线程

+   当达到指定的超时时间

# 阻塞与自旋

阻塞的线程放弃处理器时间片段一段时间。这通过使其可用于其他线程来提高性能，但会产生上下文切换的开销。在线程必须被阻塞一段时间的情况下，这是很好的。如果等待时间较短，选择自旋而不放弃处理器时间片段是有意义的。例如，以下代码简单地无限循环：

```cs
while(!done);
```

这只是一个空的`while`循环，检查一个布尔变量。当等待结束时，变量将被设置为 false，循环可以中断。虽然这会浪费处理器时间，但如果等待时间不是很长，它可以显著提高性能。.NET Framework 提供了一些特殊的构造，我们将在本章后面讨论，比如`SpinWait`和`SpinLock`。

让我们尝试通过代码示例了解一些锁定原语。

# 锁，互斥锁和信号量

锁和互斥锁是锁定构造，只允许一个线程访问受保护的资源。锁是一个使用另一个更高级别的同步类`Monitor`的快捷实现。

信号量是一种锁定构造，允许指定数量的线程访问受保护的资源。锁只能在进程内部同步访问，但如果我们需要访问系统级资源或共享内存，我们实际上需要跨多个进程同步访问。互斥锁允许我们通过提供内核级别的锁来跨进程同步访问资源。

以下表格提供了这些构造的功能比较：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/3333def0-bb0b-4805-b86c-ca1607865494.png)

正如我们所看到的，**Lock**和**Mutex**只允许单线程访问共享资源，而**Semaphore**和**SemaphoreSlim**可以用于允许多个线程共享的资源。此外，**Lock**和**SemaphoreSlim**只能在进程内部工作，而**Mutex**和**Semaphore**具有进程范围的锁。

# 锁

让我们考虑以下代码，试图将一个数字写入文本文件：

```cs
var range = Enumerable.Range(1, 1000);
Stopwatch watch = Stopwatch.StartNew();
       for (int i = 0; i < range.Count(); i++)
       {
           Thread.Sleep(10);
           File.AppendAllText("test.txt", i.ToString());
       }
       watch.Stop();
       Console.WriteLine($"Total time to write file is 
        {watch.ElapsedMilliseconds}");
```

当我们运行上述代码时，输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/e55e8a1f-df02-483a-80bc-a2ae13ed28d3.png)

正如你所看到的，任务由 1,000 个工作项组成，每个工作项大约需要 10 毫秒来执行。任务所花费的时间是 1,000 乘以 10，即 10,000 毫秒。我们还需要考虑执行 I/O 所花费的时间，因此总时间为 11,949。

让我们尝试使用`AsParallel()`和`AsOrdered()`子句并行化这个任务，如下所示：

```cs
range.AsParallel().AsOrdered().ForAll(i =>
{
    Thread.Sleep(10);
    File.AppendAllText ("test.txt", i.ToString());
});
```

当我们尝试运行这段代码时，我们会得到以下错误信息：`System.IO.IOException**:** 'The process cannot access the file …\test.txt' because it is being used by another process.'`。

实际发生的情况是，文件是一个共享资源，具有临界区，因此只允许原子操作。在并行代码中，我们有多个线程实际上尝试写入文件并导致异常的情况。我们需要确保代码尽可能快地并行运行，但在写入文件时也保持原子性。我们需要使用锁语句修改上述代码。

首先，声明一个`static`引用类型变量。在我们的例子中，我们使用`object`类型的变量。我们需要一个引用类型变量，因为锁只能应用于堆内存：

```cs
static object _locker = new object ();
```

接下来，我们修改`ForAll()`方法内的代码，包括一个`lock`：

```cs
range.AsParallel().AsOrdered().ForAll(i =>
       {
           lock (_locker)
           {
               Thread.Sleep(10);
               File.WriteAllText("test.txt", i.ToString());
           }
       });
```

现在，当我们运行这段代码时，不会出现任何异常，但任务所花费的时间实际上比顺序执行的时间更长：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/ae6f865f-a773-43e8-80d5-9907b0703fd5.png)

这里出了什么问题？锁通过确保只有一个线程被允许访问易受攻击的代码来确保原子性，但这会带来阻塞等待锁被释放的线程的开销。我们称之为愚蠢的锁。我们可以稍微修改程序，只锁定关键部分以提高性能，同时保持原子性，如下所示：

```cs
range.AsParallel().AsOrdered().ForAll(i =>
       {
           Thread.Sleep(10);
           lock (_locker)
           {
               File.WriteAllText("test.txt", i.ToString());
           }
       });
```

以下是上述代码的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/63589a04-4827-411e-a907-dd302daa543f.png)

正如你所看到的，通过混合同步和并行化，我们取得了显著的收益。我们可以使用另一个锁原语来实现类似的结果，即`Monitor`类。

锁实际上是一种简写语法，用于在`try`-`catch`块中包装`Monitor.Enter()`和`Monitor.Exit()`以实现原子性。因此，可以将相同的代码编写如下：

```cs
range.AsParallel().AsOrdered().ForAll(i =>
{
    Thread.Sleep(10);
    Monitor.Enter(_locker);
    try
    {
        File.WriteAllText("test.txt", i.ToString());
    }
    finally
    {
        Monitor.Exit(_locker);
    }
});
```

此代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/5da8d712-da99-4097-804c-d9174d3951ae.png)

# 互斥体

上述代码适用于单个实例应用程序，因为任务在进程内运行，锁实际上锁定了进程内的内存屏障。如果我们运行应用程序的多个实例，两个应用程序将拥有自己的静态数据成员的副本，因此将锁定自己的内存屏障。这将允许每个进程中的一个线程实际进入临界区并尝试写入文件。这将导致以下`System.IO.IOException**:** 'The process cannot access the file …\test.txt' because it is being used by another process.'`。

为了能够将锁应用于共享资源，我们可以使用`mutex`类在内核级别应用锁。与锁类似，互斥体只允许一个线程访问受保护的资源，但也可以跨进程工作，因此只允许系统中的一个线程访问受保护的资源，而不管执行的进程数量如何。

互斥体可以是命名的或未命名的。未命名的互斥体的工作方式类似于锁，不能跨进程工作。

首先，我们将创建一个未命名的`Mutex`：

```cs
private static Mutex mutex = new Mutex();
```

然后，我们将修改前面的并行代码，以便我们可以像使用锁一样使用`Mutex`：

```cs
range.AsParallel().AsOrdered().ForAll(i =>
       {
           Thread.Sleep(10);
           mutex.WaitOne();
           File.AppendAllText("test.txt", i.ToString());
           mutex.ReleaseMutex(); 
       });
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/063ee14e-1885-46c5-b045-59ecacdb5a61.png)

使用`Mutex`类，我们可以调用`WaitHandle.WaitOne()`方法来锁定临界区，并使用`ReleaseMutex()`来解锁临界区。关闭或处理互斥体会自动释放它。

上述程序运行良好，但如果我们尝试在多个实例上运行它，它将抛出一个`IOException`。为此，我们可以创建一个`namedMutex`，如下所示：

```cs
private static Mutex namedMutex = new Mutex(false,"ShaktiSinghTanwar");
```

在调用`WaitOne()`时，我们可以选择指定一个超时，以便在等待一定时间内等待信号，然后解除阻塞。下面是一个示例：

```cs
namedMutex.WaitOne(3000);
```

如果未收到信号，上述互斥体将在三秒后解除阻塞。

锁和互斥体只能从获取它们的线程中释放。

# 信号量

锁，互斥体和监视器只允许一个线程访问受保护的资源。然而，有时我们需要允许多个线程能够访问共享资源。这些情况包括资源池化场景和限流场景。与锁或互斥体不同，`semaphore`是线程不可知的，这意味着任何线程都可以调用`semaphore`的释放。就像互斥体一样，它也可以跨进程工作。

典型的`semaphore`构造函数如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/c903a4bf-5953-4af1-a3f2-7d0ae9503f5f.png)

如你所见，它接受两个参数：`initialCount`，指定最初允许进入的线程数，以及`maximumCount`，指定可以进入的总线程数。

假设我们有一个远程服务，每个客户端只允许三个并发连接，并且需要一秒来处理一个请求，如下所示：

```cs
private static void DummyService(int i)
       {
           Thread.Sleep(1000);
       }
```

我们有一个方法，其中有 1,000 个工作项需要使用参数调用服务。我们需要并行处理一个任务，但也要确保在任何时候最多只有三次对服务的调用。我们可以通过创建一个最大计数为`3`的`信号量`来实现这一点：

```cs
Semaphore semaphore = new Semaphore(3,3);
```

现在，我们可以编写一些代码，可以模拟并行进行 1,000 次请求，但每次只能进行三次，使用以下`信号量`：

```cs
   range.AsParallel().AsOrdered().ForAll(i =>
            {
                semaphore.WaitOne();
                Console.WriteLine($"Index {i} making service call using 
                 Task {Task.CurrentId}" );
                //Simulate Http call
                CallService(i);
                Console.WriteLine($"Index {i} releasing semaphore using 
                  Task {Task.CurrentId}");
                semaphore.Release();
            });
```

这的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/34020bb8-f6f0-4ee6-8496-f03b46823fb5.png)

正如您所看到的，三个线程进入并调用服务，而其他线程则等待锁被释放。一旦一个线程释放锁，另一个线程进入，但只有在任何时候有三个线程在临界区内。

信号量有两种类型：本地和全局。我们将在下面讨论这些。

# 本地信号量

本地`信号量`是在使用的应用程序中本地的。任何没有名称创建的`信号量`都将被创建为本地`信号量`，如下所示：

```cs
Semaphore semaphore = new Semaphore(1,10);
```

# 全局信号量

全局`信号量`是全局的，因为它应用于内核或系统级别的锁原语。任何使用名称创建的`信号量`都将被创建为全局`信号量`，如下所示：

```cs
Semaphore semaphore = new Semaphore(1,10,”Globalsemaphore”);
```

如果创建一个只有一个线程的`信号量`，它将起到锁的作用。

# 读写锁

`ReaderWriterLock`类定义了一个支持多个读取器和一次写入器的锁。这在共享资源经常被许多线程读取但不经常更新的情况下非常方便。.NET Framework 提供了两个读写锁类：`ReaderWriterLock`和`ReaderWriterLockSlim`。`ReaderWriterLock`现在几乎已经过时，因为它可能会导致潜在的死锁、降低性能、复杂的递归规则以及锁的升级或降级。我们将在本章后面更详细地讨论`ReaderWriterLockSlim`。

# 信号量原语介绍

并行编程的一个重要方面是任务协调。在创建任务时，您可能会遇到生产者/消费者场景，其中一个线程（消费者）正在等待另一个线程（生产者）更新共享资源。由于消费者不知道生产者何时会更新共享资源，它不断轮询共享资源，这可能导致竞争条件。轮询在处理这些情况时效率非常低。最好使用.NET Framework 提供的信号量原语。使用信号量原语，消费者线程暂停，直到它收到来自生产者线程的信号。让我们讨论一些常见的信号量原语，如`Thread.Join`，`WaitHandles`和`EventWaitHandlers`。

# 线程加入

这是我们可以使一个线程等待另一个线程的信号的最简单方法。`Thread.Join`是阻塞的，这意味着调用线程会被阻塞，直到加入的线程完成。可选地，我们可以指定一个超时，一旦超时到达，允许被阻塞的线程退出其阻塞状态。

在下面的代码中，我们将创建一个模拟长时间运行任务的子线程。完成后，它将更新名为`result`的本地变量的输出。程序应该在控制台上打印结果`10`。让我们尝试运行代码：

```cs
int result = 0;
Thread childThread = new Thread(() =>
{
    Thread.Sleep(5000);
    result = 10;
});
childThread.Start();
Console.WriteLine($"Result is {result}");
```

前面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/f5be7850-e091-49c4-8be9-8d495b974ed5.png)

我们期望的结果是`10`，但实际上是`0`。这是因为主线程在子线程完成执行之前就已经运行，我们可以通过在子线程上调用`Join()`来阻塞主线程，从而实现期望的行为，如下所示：

```cs
int result = 0;
Thread childThread = new Thread(() =>
{
    Thread.Sleep(5000);
    result = 10;
});
childThread.Start();
childThread.Join();
Console.WriteLine($"Result is {result}");
```

如果现在再次运行代码，我们将在等待五秒钟后看到期望的输出，主线程在此期间被阻塞：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/29f82897-6ec0-4906-b64e-f59cccc732df.png)

# EventWaitHandle

`System.Threading.EventWaitHandle`类表示线程的同步事件。它作为`AutoResetEvent`和`ManualResetEvent`类的基类。我们可以通过调用`Set()`或`SignalAndWait()`来发出`EventWaitHandle`的信号。`EventWaitHandle`类没有任何线程关联性，因此可以被任何线程发出信号。让我们更多地了解`AutoResetEvent`和`ManualResetEvent`。

# AutoResetEvent

这是指自动重置的`WaitHandle`类。一旦它们被重置，它们允许一个线程通过创建的屏障。一旦线程通过，它们会再次被设置，从而阻塞线程直到下一个信号。

在以下示例中，我们试图以线程安全的方式找出 10 个数字的总和，而不使用锁。

首先，创建一个初始状态为非信号或`false`的`AutoResetEvent`。这意味着所有线程都应该等待直到收到信号。如果将初始状态设置为信号或`true`，第一个线程将通过，而其他线程将等待信号：

```cs
AutoResetEvent autoResetEvent = new AutoResetEvent(false);
```

接下来，创建一个发出信号的任务，使用`autoResetEvent.Set()`方法每秒发出 10 次信号：

```cs
Task signallingTask = Task.Factory.StartNew(() => {
    for (int i = 0; i < 10; i++)
    {
        Thread.Sleep(1000);
        autoResetEvent.Set();
    }
});
```

声明一个变量 sum 并将其初始化为`0`：

```cs
int sum = 0;
```

创建一个并行的`for`循环，创建 10 个任务。每个任务将立即开始并等待一个信号进入，因此在`autoResetEvent.WaitOne()`语句处阻塞。每秒钟，一个信号将被发送，一个线程将进入并更新`sum`：

```cs
 Parallel.For(1, 10, (i) => {
     Console.WriteLine($"Task with id {Task.CurrentId} waiting for 
      signal to enter");
     autoResetEvent.WaitOne();
     Console.WriteLine($"Task with id {Task.CurrentId} received 
      signal to enter");
     sum += i;
 });
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/3369c0d3-6e1a-4209-a1d0-a27351c60e85.png)

如您所见，所有 10 个任务最初都被阻塞，每秒接收到信号后释放一个。

# ManualResetEvent

这是指需要手动重置的等待句柄。与`AutoResetEvent`不同，它只允许一个线程通过每个信号，`ManualResetEvent`允许线程继续通过，直到再次设置。让我们尝试使用一个简单的例子来理解这一点。

在以下示例中，我们需要并行地以每批 5 个的方式进行 15 次服务调用，每批之间延迟 2 秒。在进行服务调用时，我们需要确保系统连接到网络。为了模拟网络状态，我们将创建两个任务：一个信号网络关闭，一个信号网络开启。

首先，我们将创建一个初始状态为*关闭*的手动重置事件：

```cs
ManualResetEvent manualResetEvent = new ManualResetEvent(false);
```

接下来，我们将创建两个任务，通过每两秒触发一次网络*关闭*事件（阻塞所有网络调用）和每五秒触发一次网络*开启*事件（允许所有网络调用通过）来模拟网络的开启和关闭：

```cs
Task signalOffTask = Task.Factory.StartNew(() => {
           while (true)
           {
               Thread.Sleep(2000);
               Console.WriteLine("Network is down");
               manualResetEvent.Reset();
           }
       });
       Task signalOnTask = Task.Factory.StartNew(() => {
           while (true)
           {
               Thread.Sleep(5000);
               Console.WriteLine("Network is Up");
               manualResetEvent.Set();
           }
       });
```

如您从前面的代码中看到的，我们每五秒发出一次手动重置事件的信号，使用`manualResetEvent.Set()`。我们每两秒关闭一次它，使用`manualResetEvent.Reset()`。以下代码进行实际的服务调用：

```cs
for (int i = 0; i < 3; i++)
       {
           Parallel.For(0, 5, (j) => {
               Console.WriteLine($"Task with id {Task.CurrentId} waiting 
                for network to be up");
               manualResetEvent.WaitOne();
               Console.WriteLine($"Task with id {Task.CurrentId} making 
                service call");
               DummyServiceCall();
           });
           Thread.Sleep(2000);
       }
```

如您从前面的代码中看到的，我们创建了一个`for`循环，每次迭代创建五个任务，两次迭代之间的休眠间隔为两秒。

在进行服务调用之前，我们通过调用`manualResetEvent.WaitOne();`等待网络启动。

如果我们运行上述代码，将收到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/3bab3114-6be3-4e91-8980-4779dac5779e.png)

如您所见，五个任务立即启动并立即阻塞等待网络启动。五秒后，当网络启动时，我们使用`Set()`方法发出信号，所有五个线程通过进行服务调用。这将在`for`循环的每次迭代中重复。

# WaitHandles

`System.Threading.WaitHandle`是从`MarshalByRefObject`类继承的类，用于同步运行在应用程序中的线程。使用等待句柄来阻塞和发出信号以同步线程。线程可以通过调用`WaitHandle`类的任何方法来阻塞。它们根据所选的信号构造的类型而被释放。`WaitHandle`类的方法如下：

+   `WaitOne`：阻塞调用线程，直到它从等待的等待句柄接收到信号。

+   `WaitAll`：阻塞调用线程，直到它从等待的所有等待句柄接收到信号。

以下是一个示例，向我们展示了`WaitAll`的工作原理：

```cs
public static bool WaitAll (System.Threading.WaitHandle[] waitHandles, TimeSpan timeout, bool exitContext);
```

以下是一个示例，利用两个线程模拟两个不同的服务调用。两个线程将并行执行，但在打印总和到控制台之前将在`WaitHandle.WaitAll(waitHandles)`处等待：

```cs
static int _dataFromService1 = 0;
static int _dataFromService2 = 0;
private static void WaitAll()
{
    List<WaitHandle> waitHandles = new List<WaitHandle>
       {
            new AutoResetEvent(false),
            new AutoResetEvent(false)
       };
    ThreadPool.QueueUserWorkItem(new WaitCallback
     (FetchDataFromService1), waitHandles.First());
    ThreadPool.QueueUserWorkItem(new WaitCallback
     (FetchDataFromService2), waitHandles.Last());
    //Waits for all the threads (waitHandles) to call the .Set() 
    //method 
    //i.e. wait for data to be returned from both service
    WaitHandle.WaitAll(waitHandles.ToArray());
    Console.WriteLine($"The Sum is 
     {_dataFromService1 + _dataFromService2}");
}
private static void FetchDataFromService1(object state)
{
    Thread.Sleep(1000);
    _dataFromService1 = 890;
    var autoResetEvent = state as AutoResetEvent;
    autoResetEvent.Set();
}
private static void FetchDataFromService2(object state)
{
    Thread.Sleep(1000);
    _dataFromService2 = 3;
    var autoResetEvent = state as AutoResetEvent;
    autoResetEvent.Set();
}
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/e8381fd4-8d56-4b68-aeca-cd815f15d19e.png)

+   `WaitAny`：阻塞调用线程，直到它从等待的任何等待句柄接收到信号。

以下是`WaitAny`方法的签名：

```cs
public static int WaitAny (System.Threading.WaitHandle[] waitHandles);
```

以下是一个示例，利用两个线程执行项目搜索。两个线程将并行执行，并且程序在`WaitHandle.WaitAny(waitHandles)`方法中等待任何一个线程完成执行，然后将项目索引打印到控制台。

我们有两种方法，二分搜索和线性搜索，使用二进制和线性算法执行搜索。我们希望尽快从这两种方法中获得结果。我们可以通过使用`AutoResetEvent`进行信号传递，并将结果存储在`findIndex`和`winnerAlgo`全局变量中：

```cs
 static int findIndex = -1;
 static string winnerAlgo = string.Empty; 
 private static void BinarySearch(object state)
 {
     dynamic data = state;
     int[] x = data.Range;
     int valueToFind = data.ItemToFind;
     AutoResetEvent autoResetEvent = data.WaitHandle 
      as AutoResetEvent;
     //Search for item using .NET framework built in Binary Search
     int foundIndex = Array.BinarySearch(x, valueToFind);
     //store the result globally
     Interlocked.CompareExchange(ref findIndex, foundIndex, -1);
     Interlocked.CompareExchange(ref winnerAlgo, "BinarySearch", 
      string.Empty);
     //Signal event
     autoResetEvent.Set();
 }

 public static void LinearSearch( object state)
 {
     dynamic data = state;
     int[] x = data.Range;
     int valueToFind = data.ItemToFind;
     AutoResetEvent autoResetEvent = data.WaitHandle as AutoResetEvent;
     int foundIndex = -1;
     //Search for item linearly using for loop
     for (int i = 0; i < x.Length; i++)
     {
         if (valueToFind == x[i])
         {
             foundIndex = i;
         }
     }
     //store the result globally
     Interlocked.CompareExchange(ref findIndex, foundIndex, -1); 
     Interlocked.CompareExchange(ref winnerAlgo, "LinearSearch", 
       string.Empty); 
     //Signal event
     autoResetEvent.Set();
 }

```

以下代码使用`ThreadPool`并行调用两种算法：

```cs
 private static void AlgoSolverWaitAny()
 {
     WaitHandle[] waitHandles = new WaitHandle[]
     {
     new AutoResetEvent(false),
     new AutoResetEvent(false)
     };
     var itemToSearch = 15000;
     var range = Enumerable.Range(1, 100000).ToArray(); 
     ThreadPool.QueueUserWorkItem(new WaitCallback    
      (LinearSearch),new {Range = range,ItemToFind =           
      itemToSearch, WaitHandle= waitHandles[0] });
     ThreadPool.QueueUserWorkItem(new WaitCallback(BinarySearch), 
      new { Range = range, ItemToFind =         
      itemToSearch, WaitHandle = waitHandles[1] });
     WaitHandle.WaitAny(waitHandles);
     Console.WriteLine($"Item found at index {findIndex} and faster 
      algo is {winnerAlgo}" );
 }
```

+   SignalAndWait：此方法用于在等待句柄上调用`Set()`并为另一个等待句柄调用`WaitOne`。在多线程环境中，此方法可用于释放一个线程，然后重置以等待下一个线程：

```cs
public static bool SignalAndWait (System.Threading.WaitHandle toSignal, System.Threading.WaitHandle toWaitOn);
```

# 轻量级同步原语

.NET Framework 还提供了轻量级的同步原语，其性能优于其对应物。它们尽可能避免依赖内核对象，如等待句柄，因此只在进程内工作。当线程的等待时间较短时，应使用这些原语。我们可以将它们分为两类，在本节中我们将介绍这两类。

# Slim 锁

Slim 锁是传统同步原语的精简实现，可以通过减少开销来提高性能。

以下表格显示了传统同步原语及其精简对应物：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/254c3dd1-bfc8-4e51-b3fd-0d025205ff9a.png)

让我们尝试更多地了解 Slim 锁。

# ReaderWriterLockSlim

`ReaderWriterLockSlim`是`ReaderWriterLock`的轻量级实现。它表示一个锁，可用于以允许多个线程共享读取访问的方式管理受保护的资源，同时只允许一个线程写入访问。

以下示例使用`ReaderWriterLockSlim`来保护由三个读取线程和一个写入线程共享的列表上的访问：

```cs
static ReaderWriterLockSlim _readerWriterLockSlim = new ReaderWriterLockSlim();
static List<int> _list = new List<int>();
private static void ReaderWriteLockSlim()
{
    Task writerTask = Task.Factory.StartNew( WriterTask);
    for (int i = 0; i < 3; i++)
    {
        Task readerTask = Task.Factory.StartNew(ReaderTask);
    }
}
static void WriterTask()
{
    for (int i = 0; i < 4; i++)
    {
        try 
            {
            _readerWriterLockSlim.EnterWriteLock();
            Console.WriteLine($"Entered WriteLock on Task {Task.CurrentId}");
            int random = new Random().Next(1, 10);
            _list.Add(random);
            Console.WriteLine($"Added {random} to list on Task {Task.CurrentId}");
            Console.WriteLine($"Exiting WriteLock on Task {Task.CurrentId}");
            }
        finally
            {
             _readerWriterLockSlim.ExitWriteLock();
            }

        Thread.Sleep(1000);
    }
}
static void ReaderTask()
{
    for (int i = 0; i < 2; i++)
    {
       _readerWriterLockSlim.EnterReadLock();
       Console.WriteLine($"Entered ReadLock on Task {Task.CurrentId}"); 
       Console.WriteLine($"Items: {_list.Select(j=>j.ToString ()).Aggregate((a, b) => 
       a + "," + b)} on Task {Task.CurrentId}"); 
       Console.WriteLine($"Exiting ReadLock on Task {Task.CurrentId}"); 
        _readerWriterLockSlim.ExitReadLock();
        Thread.Sleep(1000);
    }
}
```

此代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/c8c8ea67-cbde-4075-92ef-5fba32c0e226.png)

# SemaphoreSlim

`SemaphoreSlim`是`semaphore`的轻量级实现。它限制对受保护资源的访问，以供多个线程使用。

以下是本章前面展示的`semaphore`程序的精简版本：

```cs
 private static void ThrottlerUsingSemaphoreSlim()
        {
            var range = Enumerable.Range(1, 12);
            SemaphoreSlim semaphore = new SemaphoreSlim(3, 3);
            range.AsParallel().AsOrdered().ForAll(i =>
            {
                try
                {
                    semaphore.Wait();
                    Console.WriteLine($"Index {i} making service call using Task {Task.CurrentId}");
                    //Simulate Http call
                    CallService(i);
                    Console.WriteLine($"Index {i} releasing semaphore using Task {Task.CurrentId}");
                }
                finally
                {
                    semaphore.Release();
                }
            });
        }
        private static void CallService(int i)
        {
            Thread.Sleep(1000);
        }
```

我们可以看到这里的区别，除了用`SemaphoreSlim`替换`Semaphore`类之外，我们现在有了`Wait()`方法，而不是`WaitOne()`。这样做更有意义，因为我们允许多个线程通过。

另一个重要的区别是`SemaphoreSlim`总是作为本地`semaphore`创建，而`semaphore`可以全局创建。

# 手动重置事件 Slim

`ManualResetEventSlim`是`ManualResetEvent`的轻量级实现。它比`ManualResetEvent`具有更好的性能和更少的开销。

我们可以按照以下语法创建对象，就像`ManualResetEvent`一样：

```cs
ManualResetEventSlim manualResetEvent = new ManualResetEventSlim(false);
```

就像其他 slim 对应物一样，这里的一个主要区别是我们用`Wait()`替换了`WaitOne()`方法。

您可以尝试运行一些`ManualResetEvent`演示代码，通过进行上述更改并查看是否有效。

# 屏障和倒计时事件

.NET Framework 具有一些内置的信号原语，可以帮助我们同步多个线程，而无需编写大量的同步逻辑。所有同步都由提供的数据结构在内部处理。在本节中，让我们讨论两个非常重要的信号原语：`CountDownEvent`和`Barrier`：

+   **CountDownEvent**：`System.Threading.CountDownEvent`类指的是当其计数变为 0 时被触发的事件。

+   **屏障**：`Barrier`类允许多个线程在没有主线程控制它们的情况下运行。它创建了一个障碍，参与的线程必须在其中等待，直到所有线程都到达。`Barrier`非常适用于需要并行和分阶段进行工作的情况。

# 使用 Barrier 和 CountDownEvent 的案例研究

举个例子，假设我们需要从动态托管的两个服务中获取数据。在从服务一获取数据之前，我们需要托管它。一旦数据被获取，就需要关闭它。只有在服务一关闭后，我们才能启动服务二并从中获取数据。需要尽快获取数据。让我们创建一些代码来满足这种情况的要求。

创建一个有`5`个参与者的`Barrier`：

```cs
static Barrier serviceBarrier = new Barrier(5);
```

创建两个`CountdownEvents`，当六个线程通过它时将触发服务的启动或关闭。五个工作任务将参与其中，还有一个任务将管理服务的启动或关闭：

```cs
static CountdownEvent serviceHost1CountdownEvent = new CountdownEvent(6);
static CountdownEvent serviceHost2CountdownEvent = new CountdownEvent(6);
```

最后，创建另一个计数为`5`的`CountdownEvent`。这指的是在事件被触发之前可以通过的线程数。当所有工作任务执行完成时，`CountdownEvent`将被触发：

```cs
static CountdownEvent finishCountdownEvent = new CountdownEvent(5);
```

这是我们的`serviceManagerTask`实现：

```cs
     Task serviceManager = Task.Factory.StartNew(() =>
            {
                //Block until service name is set by any of thread
                while (string.IsNullOrEmpty(_serviceName))
                    Thread.Sleep(1000);
                string serviceName = _serviceName;
                HostService(serviceName);
                //Now signal other threads to proceed making calls to service1
                serviceHost1CountdownEvent.Signal();
                //Wait for worker tasks to finish service1 calls                                    
                serviceHost1CountdownEvent.Wait();
                //Block until service name is set by any of thread
                while (_serviceName != "Service2")
                    Thread.Sleep(1000);
                Console.WriteLine($"All tasks completed for service {serviceName}.");
                //Close current service and start the other service
                CloseService(serviceName);
                HostService(_serviceName);
                //Now signal other threads to proceed making calls to service2
                serviceHost2CountdownEvent.Signal();
                serviceHost2CountdownEvent.Wait();
                //Wait for worker tasks to finish service2 calls
                finishCountdownEvent.Wait();
                CloseService(_serviceName);
                Console.WriteLine($"All tasks completed for service {_serviceName}.");
            });
```

这是工作任务执行的方法：

```cs
        private static void GetDataFromService1And2(int j)
        {
            _serviceName = "Service1";
            serviceHost1CountdownEvent.Signal();
            Console.WriteLine($"Task with id {Task.CurrentId} signalled countdown event and waiting for   
            service to start");
            //Waiting for service to start
            serviceHost1CountdownEvent.Wait();
            Console.WriteLine($"Task with id {Task.CurrentId} fetching data from service ");
            serviceBarrier.SignalAndWait();
            //change servicename
            _serviceName = "Service2";
            //Signal Countdown event
            serviceHost2CountdownEvent.Signal();
            Console.WriteLine($"Task with id {Task.CurrentId} signalled countdown event and waiting for 
            service to start");
            serviceHost2CountdownEvent.Wait();
            Console.WriteLine($"Task with id {Task.CurrentId} fetching data from service ");
            serviceBarrier.SignalAndWait();
            //Signal Countdown event
            finishCountdownEvent.Signal();
        }
    //Finally make worker tasks
     for (int i = 0; i < 5; ++i)
            {
                int j = i;
                tasks[j] = Task.Factory.StartNew(() =>
                {
                    GetDataFromService1And2(j);
                });
            }
            Task.WaitAll(tasks);
            Console.WriteLine("Fetch completed");
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/67c1de2f-4302-412d-817c-3fad0b113ae1.png)

在本节中，我们已经看了一些内置的信号原语，这些原语可以帮助我们更轻松地进行代码同步，而无需作为开发人员锁定自己。阻塞仍然会带来性能成本，因为它涉及上下文切换。在下一节中，我们将看一些旋转技术，可以帮助消除上下文切换的开销。

# SpinWait

在本章的开头，我们提到对于较小的等待时间，旋转比阻塞更有效。旋转具有较少的与上下文切换和转换相关的内核开销。

我们可以按照以下方式创建`SpinWait`对象：

```cs
var spin = new SpinWait();
```

然后，无论我们需要进行`spin`，我们都可以调用以下命令：

```cs
spin.SpinOnce();
```

# SpinLock

如果获取锁的等待时间非常短，锁和互锁原语可能会显著降低性能。`SpinLock`提供了一种轻量级、低级别的替代锁定方法。`SpinLock`是一个值类型，因此如果我们想在多个地方使用相同的对象，我们需要通过引用传递它。出于性能原因，即使`SpinLock`甚至还没有获取锁，它也会让出线程的时间片，以便垃圾收集器可以有效工作。默认情况下，`SpinLock`不支持线程跟踪，这意味着确定哪个线程已经获取了锁。但是，这个特性可以被打开。这只建议用于调试，而不是用于生产，因为它会降低性能。

创建一个`SpinLock`对象如下：

```cs
 static SpinLock _spinLock = new SpinLock();
```

创建一个将被各个线程调用并更新全局静态列表的方法：

```cs
 static List<int> _itemsList = new List<int>();
        private static void SpinLock(int number)
        {
            bool lockTaken = false;
            try
            {
                Console.WriteLine($"Task {Task.CurrentId} Waiting for lock");                                
 _spinLock.Enter(ref lockTaken);                Console.WriteLine($"Task {Task.CurrentId} Updating list");
                _itemsList.Add(number);
            }
            finally
            {
                if (lockTaken)
                {
                    Console.WriteLine($"Task {Task.CurrentId} Exiting Update");
                    _spinLock.Exit(false);
                }
            }
        }
```

正如你所看到的，锁是使用`_spinLock.Enter(ref lockTaken)`获取的，并且通过`_spinLock.Exit(false)`释放。在这两个语句之间的所有内容将在所有线程之间同步执行。

让我们在一个并行循环中调用这个方法：

```cs
Parallel.For(1, 5, (i) => SpinLock(i));
```

如果我们使用锁定原语，这里是同步的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/66d8c9c2-ca57-40d0-bd38-97c542db9ed7.png)

作为一个经验法则，如果我们有小任务，可以通过自旋完全避免上下文切换。

# 摘要

在本章中，我们已经了解了.NET Core 提供的同步原语。如果要编写并行代码并确保其正确性，同步原语是必不可少的，即使多个线程在处理它。同步原语会带来性能开销，建议尽可能使用它们的精简版本。

我们还学习了信号原语，当线程需要处理一些外部事件时，这些原语非常有用。我们还讨论了屏障和倒计时事件，它们帮助我们避免代码同步问题，而无需编写额外的逻辑。最后，我们介绍了一些自旋技术，它们消除了由阻塞代码引起的性能开销，即`SpinLock`和`SpinWait`。

在下一章中，我们将了解.NET Core 提供的各种数据结构。这些数据结构是自动同步的，同时也是并行的。

# 问题

1.  这些中哪个可以用于跨进程同步？

1.  锁

1.  `Interlocked.Increment`

1.  `Interlocked.MemoryBarrierProcessWide`

1.  以下哪个不是有效的内存屏障？

1.  读取内存屏障

1.  半内存屏障

1.  完整内存屏障

1.  读取和执行内存屏障

1.  我们不能从以下哪种状态恢复线程？

1.  等待、休眠、加入

1.  暂停

1.  `中止`

1.  一个无名的`信号量`可以提供同步的地方？

1.  进程内部

1.  跨进程

1.  这些结构中哪个支持跟踪线程？

1.  `SpinWait`

1.  `SpinLock`


# 第六章：使用并发集合

在上一章中，我们看到了一些并行编程的实现，其中需要保护资源免受多个线程的并发访问。同步原语很难实现。通常，共享资源是一个需要多个线程读写的集合。由于集合可以以各种方式访问（例如使用`Enumerate`、`Read`、`Write`、`Sort`或`Filter`），因此使用原语编写具有受控同步的自定义集合变得棘手。因此，一直存在着对线程安全集合的需求。

在本章中，我们将学习 C#中可用的各种编程构造，这些构造有助于并行开发。以下是本章将涵盖的高级主题：

+   并发集合简介

+   多生产者/消费者场景

# 技术要求

您应该对 TPL 和 C#有很好的理解。本章的源代码可在 GitHub 上找到：[`github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter06`](https://github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter06)。

# 并发集合简介

从.NET Framework 4 开始，.NET 中添加了许多线程安全的集合。还添加了一个新的命名空间`System.Threading.Concurrent`。其中包括以下构造：

+   `IProducerConsumerCollection<T>`

+   `BlockingCollection<T>`

+   `ConcurrentDictionary<TKey,TValue>`

在使用上述结构时，不需要任何额外的同步，读取和更新都可以原子地完成。

在集合方面，线程安全并不是一个全新的概念。即使在旧的集合中，如`ArrayList`和`Hashtable`，也暴露了`Synchronized`属性，这使得可以以线程安全的方式访问这些集合。然而，这会带来性能损失，因为为了使集合线程安全，每次读取或更新操作都会将整个集合包装在锁内。

并发集合包装了轻量级、精简的同步原语，如`SpinLock`、`SpinWait`、`SemaphoreSlim`和`CountDownEvent`，因此使它们对核心的负担较轻。正如我们已经知道的，对于较短的等待时间，自旋比阻塞更有效。此外，如果等待时间增加，内置算法会将较轻的锁转换为内核锁。

# 引入 IProducerConsumerCollection<T>

生产者和消费者集合是提供了高效的无锁替代品的集合，例如`Stack<T>`和`Queue<T>`。任何生产者或消费者集合都必须允许用户添加和删除项目。.NET Framework 提供了`IProducerConsumerCollection<T>`接口，表示线程安全的堆栈、队列和包。以下是实现该接口的类：

+   `ConcurrentQueue<T>`

+   `ConcurrentStack<T>`

+   `ConcurrentBag<T>`

接口提供了两个重要的方法：`TryAdd`和`TryTake`。`TryAdd`的语法如下：

```cs
bool TryAdd (T item); 
```

`TryAdd`方法添加一个项目并返回`true`。如果添加项目时出现任何问题，它将返回`false`。

`TryTake`的语法如下：

```cs
bool TryTake (out T item);
```

`TryTake`方法移除一个项目并返回`true`。如果移除项目时出现任何问题，它将返回`false`。

# 使用 ConcurrentQueue<T>

并发队列可用于解决应用程序编程中的生产者/消费者场景。在生产者/消费者编程模式中，一个或多个线程生成数据，一个或多个线程消费数据。这会导致线程之间的竞争条件。我们可以通过以下方法解决这个问题：

+   使用队列

+   使用`ConcurrentQueue<T>`

根据哪个线程（生产者/消费者）负责添加/消费数据，生产者-消费者模式可以分为以下几种：

+   **纯生产者-消费者**，一个线程只能生产数据或只能消费数据，但不能两者兼而有之

+   **混合生产者-消费者**，任何线程都可以同时生产或消费数据

让我们首先尝试使用队列解决生产者-消费者问题。

# 使用队列解决生产者-消费者问题

在这个例子中，我们将使用`System.Collections`命名空间中定义的队列来创建生产者和消费者场景。将有多个任务尝试读取或写入队列，我们需要确保读取和写入是原子的：

1.  让我们首先创建`queue`并用一些数据填充它：

```cs
Queue<int> queue = new Queue<int>();
for (int i = 0; i < 500; i++) 
{
    queue.Enqueue(i);
}
```

1.  声明一个变量来保存最终结果：

```cs
int sum = 0;
```

1.  接下来，我们将创建一个并行循环，使用多个任务从队列中读取项目，并以线程安全的方式将总和添加到之前声明的 sum 变量中：

```cs
Parallel.For(0, 500, (i) =>
{
    int localSum = 0;
    int localValue;
    while (queue.TryDequeue(out localValue))
    {
        Thread.Sleep(10);
        localSum += localValue;
    }
    Interlocked.Add(ref sum, localSum);
});  
Console.WriteLine($"Calculated Sum is {sum} and should be {Enumerable.Range(0, 500).Sum()}");
```

如果我们运行程序，将得到以下输出。正如你所看到的，由于任务在尝试并发读取时发生了竞争条件，这不是预期的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/50f765c8-c081-4b67-a8cf-6bc432dc2dc2.png)

为了使前面的程序线程安全，我们可以通过修改并行循环代码来锁定关键部分，如下所示：

```cs
Parallel.For(0, 500, (i) =>
{
    int localSum = 0;
    int localValue;
    Monitor.Enter(_locker);
    while (cq.TryDequeue(out localValue))
    {
       Thread.Sleep(10);
       localSum += localValue;
    }
    Monitor.Exit(_locker);
    Interlocked.Add(ref sum, localSum);
});
```

同样，在更复杂的情况下，我们需要同步对并行代码中暴露给队列的所有读/写点。如果我们运行前面的代码，将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/d129a15a-2e1e-4b32-b3ca-acb5c8983295.png)

正如你所看到的，一切都如预期的那样工作，尽管在频繁读取或写入的情况下，会有额外的同步开销，可能导致死锁。

# 使用并发队列解决问题

我们可以通过使用`System.Collections.Concurrent.ConcurrentQueue`类来解决生产者-消费者问题，这是一个线程安全的队列版本。让我们通过使用并发队列修改前面的代码，如下所示：

```cs
private static void ProducerConsumerUsingConcurrentQueues()
{
    // Create a Queue.
    ConcurrentQueue<int> cq = new ConcurrentQueue<int>();
    // Populate the queue.
    for (int i = 0; i < 500; i++){
        cq.Enqueue(i);
    }
    int sum = 0;
    Parallel.For(0, 500, (i) =>
    {
        int localSum = 0;
        int localValue;
        while (cq.TryDequeue(out localValue))
        {
            Thread.Sleep(10);
            localSum += localValue;
        }
        Interlocked.Add(ref sum, localSum);
    });
    Console.WriteLine($"outerSum = {sum}, should be {Enumerable.Range(0, 500).Sum()}");
}
```

正如你所看到的，我们刚刚在我们之前编写的代码中用`ConcurrentQueue<int>`替换了`Queue<int>`，这带来了同步开销。使用`ConcurrentQueue`，我们不必担心其他同步原语。

如果我们运行前面的代码，将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/676c49ca-488e-48da-9016-96a9dd59dfc5.png)

就像`Queue<T>`一样，`ConcurrentQueue<T>`也以**先进先出**（**FIFO**）模式工作。

# 性能考虑 - Queue<T>与 ConcurrentQueue<T>

我们应该在以下情况下使用`ConcurrentQueue`，在这些情况下它比队列具有轻微或非常大的性能优势：

+   在纯生产者-消费者场景中，每个项目的处理时间非常低

+   在纯生产者-消费者场景中，只有一个专用生产者线程和一个专用消费者线程的情况

+   在纯生产者-消费者场景以及混合生产者-消费者场景中，处理时间为 500 **FLOPS**（**每秒浮点运算次数**）或更多

在混合生产者-消费者场景中，每个项目的处理时间较低时，我们应该使用队列而不是并发队列，以获得更好的性能。

# 使用 ConcurrentStack<T>

`ConcurrentStack<T>`是`Stack<T>`的并发版本，并实现了`IProducerConsumerCollection<T>`接口。我们可以从栈中推送或弹出项目，它以**后进先出**（**LIFO**）格式工作。它不涉及内核级锁定，而是依赖于自旋和比较和交换操作来消除任何争用。

以下是`ConcurrentStack<T>`类的一些重要方法：

+   `Clear`：从集合中移除所有元素

+   `Count`：返回集合中的元素数

+   `IsEmpty`：如果集合为空，则返回`true`

+   `Push (T item)`：向集合中添加一个元素

+   `TryPop (out T result)`:从集合中移除一个元素，并在移除项目时返回`true`；否则返回`false`

+   `PushRange (T [] items)`:原子性地向集合中添加一系列项目

+   `TryPopRange (T [] items)`:从集合中移除一系列项目

让我们看看如何创建一个并发堆栈实例。

# 创建一个并发堆栈

我们可以创建一个并发堆栈实例，并按以下方式添加项目：

```cs
ConcurrentStack<int> concurrentStack = new ConcurrentStack<int>();
concurrentStack.Push (1);
concurrentStack.PushRange(new[] { 1,2,3,4,5});
```

我们可以按以下方式从堆栈中获取项目：

```cs
int localValue;
concurrentStack.TryPop(out localValue)
concurrentStack.TryPopRange (new[] { 1,2,3,4,5});
```

以下是创建并发堆栈、添加项目并并行迭代项目的完整代码：

```cs
private static void ProducerConsumerUsingConcurrentStack()
{
    // Create a Queue.
    ConcurrentStack<int> concurrentStack = new ConcurrentStack<int>();
    // Populate the queue.
    for (int i = 0; i < 500; i++){
        concurrentStack.Push(i);
    }
    concurrentStack.PushRange(new[] { 1,2,3,4,5});
    int sum = 0;
    Parallel.For(0, 500, (i) =>
    {
        int localSum = 0;
        int localValue;
        while (concurrentStack.TryPop(out localValue))
        {
            Thread.Sleep(10);
            localSum += localValue;
        }
        Interlocked.Add(ref sum, localSum);
    });
    Console.WriteLine($"outerSum = {sum}, should be 124765");
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/d7564b63-881e-4bc9-bbea-ccd465825517.png)

# 使用 ConcurrentBag<T>

`ConcurrentBag<T>`是一个无序集合，不像`ConcurrentStack`和`ConcurrentQueues`，它在存储和检索项目时会对项目进行排序。`ConcurrentBag<T>`针对同一线程既作为生产者又作为消费者的场景进行了优化。`ConcurrentBag`支持工作窃取算法，并为每个线程维护一个本地队列。

以下代码创建`ConcurrentBag`并向其中添加或获取项目：

```cs
ConcurrentBag<int> concurrentBag = new ConcurrentBag<int>();
//Add item to bag
concurrentBag.Add(10);
int item;
//Getting items from Bag
concurrentBag.TryTake(out item)
```

完整代码如下：

```cs
static ConcurrentBag<int> concurrentBag = new ConcurrentBag<int>();
private static void ConcurrentBackDemo()
{
    ManualResetEventSlim manualResetEvent = new ManualResetEventSlim(false);
    Task producerAndConsumerTask = Task.Factory.StartNew(() =>
    {
        for (int i = 1; i <= 3; ++i)
        {
            concurrentBag.Add(i);
        }
        //Allow second thread to add items
        manualResetEvent.Wait();
        while (concurrentBag.IsEmpty == false)
        {
            int item;
            if (concurrentBag.TryTake(out item))
            {
                Console.WriteLine($"Item is {item}");
            }
        }
    });
    Task producerTask = Task.Factory.StartNew(() =>
    {
        for (int i = 4; i <= 6; ++i)
        {
            concurrentBag.Add(i);
        }
        manualResetEvent.Set();
    });
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/125e306d-f7dc-4872-a5b9-2029132f9595.png)

正如您所知，每个线程都有一个线程本地队列。项目 1、2 和 3 被添加到`producerAndConsumerTask`的本地队列中，项目 4、5 和 6 被添加到`producerTask`的本地队列中。当`producerAndConsumerTask`添加了项目后，我们等待`producerTask`完成推送其项目。一旦所有项目都被推送，`producerAndConsumerTask`开始检索项目。由于它已经推送了 1、2 和 3，这些项目在本地队列中，它将首先处理这些项目，然后再移动到`producerTask`的本地队列。

# 使用 BlockingCollection<T>

`BlockingCollection<T>`类是一个线程安全的集合，实现了`IProduceConsumerCollection<T>`接口。我们可以同时向集合中添加或移除项目，而不必担心同步问题，因为这些问题会被自动处理。会有两个线程：生产者和消费者。生产者线程将生成数据，我们可以限制生产者线程在进入休眠模式并被阻塞之前可以生产的最大项目数。消费者线程将消耗数据，并在集合为空时被阻塞。当生产者线程解除阻塞并消费者线程从集合中移除一些项目时，消费者线程将被解除阻塞。当生产者线程向集合中添加一些数据时，消费者线程将被解除阻塞。

阻塞集合有两个重要方面：

+   **边界**：这意味着我们可以将集合限制为最大值，之后不再能添加新对象，生产者线程进入休眠模式。

+   **阻塞**：这意味着当集合为空时，我们可以阻塞消费者线程。

让我们看看如何创建阻塞集合。

# 创建 BlockingCollection<T>

以下代码创建一个新的`BlockingCollection`，在创建 10 个项目后，它进入阻塞状态，然后由消费者线程消耗项目：

```cs
BlockingCollection<int> blockingCollection = new BlockingCollection<int>(10);
```

可以按以下方式向集合中添加项目：

```cs
blockingCollection.Add(1);
blockingCollection.TryAdd(3, TimeSpan.FromSeconds(1))
```

可以按以下方式从集合中移除项目：

```cs
int item = blockingCollection.Take();
blockingCollection.TryTake(out item, TimeSpan.FromSeconds(1))
```

当没有更多项目可添加时，生产者线程调用`CompleteAdding()`方法。这个方法会将集合的`IsAddingComplete`属性设置为`true`。

当集合为空且`IsAddingComplete`也为`true`时，消费者线程使用`IsCompleted`属性。这表明所有项目都已被处理，生产者将不再添加任何项目。

完整代码如下：

```cs
BlockingCollection<int> blockingCollection = new BlockingCollection<int>(10);
Task producerTask = Task.Factory.StartNew(() =>
{
    for (int i = 0; i < 5; ++i)
    {
        blockingCollection.Add(i);
    }
    blockingCollection.CompleteAdding();
});
Task consumerTask = Task.Factory.StartNew(() =>
{
    while (!blockingCollection.IsCompleted)
    {
        int item = blockingCollection.Take();
        Console.WriteLine($"Item retrieved is {item}");
    }
});
Task.WaitAll(producerTask, consumerTask);
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/4f457b50-74d7-4398-b66c-af844ec7018e.png)

现在，在介绍了并发集合之后，在下一节中，我们将尝试将生产者-消费者场景推进，并了解如何处理多个生产者/消费者。

# 多个生产者-消费者场景

在本节中，我们将看到当存在多个生产者和消费者线程时，阻塞集合是如何工作的。为了理解，我们将创建两个生产者和一个消费者。生产者线程将生产项目。一旦所有生产者线程都调用了`CompleteAdding`，消费者将开始从集合中读取项目：

1.  让我们从创建一个带有多个生产者的阻塞集合开始：

```cs
BlockingCollection<int>[] produceCollections = new BlockingCollection<int>[2];
produceCollections[0] = new BlockingCollection<int>(5);
produceCollections[1] = new BlockingCollection<int>(5);
```

1.  接下来，我们将创建两个生产者任务，它们将向生产者添加项目：

```cs
Task producerTask1 = Task.Factory.StartNew(() =>
{
    for (int i = 1; i <= 5; ++i)
    {
        produceCollections[0].Add(i);
        Thread.Sleep(100);
    }
    produceCollections[0].CompleteAdding();
});
Task producerTask2 = Task.Factory.StartNew(() =>
{
    for (int i = 6; i <= 10; ++i)
    {
        produceCollections[1].Add(i);
        Thread.Sleep(200);
    }
    produceCollections[1].CompleteAdding();
});
```

1.  最后，我们将编写消费者逻辑，尝试从两个生产者集合中消费项目，一旦项目可用即开始：

```cs
while (!produceCollections[0].IsCompleted || !produceCollections[1].IsCompleted)
{
 int item;
 BlockingCollection<int>.TryTakeFromAny(produceCollections, out item, TimeSpan.FromSeconds(1));
 if (item != default(int))
 {
 Console.WriteLine($"Item fetched is {item}");
 }
}
```

从前面的代码方法中可以看出，`TryTakeFromAny`尝试从多个生产者中读取项目，并在项目可用时返回。

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/4166e62b-2d21-485d-bfc2-406d81970ecb.png)

在编程中，我们经常遇到需要并发存储数据作为键值对的情况。为此，`ConcurrentDictionary`集合非常方便，我们将在下一节介绍它。

# 使用 ConcurrentDictionary<TKey,TValue>

`ConcurrentDictionary<TKey,TValue>`表示线程安全的字典。它用于以线程安全的方式保存可以读取或写入的键值对。

`ConcurrentDictionary`可以按以下方式创建：

```cs
ConcurrentDictionary<int, int> concurrentDictionary = new ConcurrentDictionary<int, int>();
```

可以按以下方式向字典中添加项目：

```cs
concurrentDictionary.TryAdd(i, i * i);
string value = (i * i).ToString();
// Add item if not exist or else update
concurrentDictionary.AddOrUpdate(i, value,(key, val) => (key * key).ToString()); 
//Fetches item with key 5 or if not exist than add key 5 with value 25
concurrentDictionary.GetOrAdd(5, "25");
```

可以按以下方式从字典中移除项目：

```cs
string value;
concurrentDictionary.TryRemove(5, out value);
```

可以按以下方式更新字典中的项目：

```cs
//If a key with a value of 25 is found, it will be updated to have a value of 30      concurrentDictionary.TryUpdate(5, "30","25");
```

在下面的代码中，我们将创建两个生产者线程，它们将向字典中添加项目。生产者将创建一些重复的项目，字典将确保它们以线程安全的方式添加，而不会抛出重复键错误。生产者线程完成后，消费者将使用`keys`或`values`属性读取所有项目：

```cs
ConcurrentDictionary<int, string> concurrentDictionary = new ConcurrentDictionary<int, string>();
Task producerTask1 = Task.Factory.StartNew(() => 
{
    for (int i = 0; i < 20; i++)
    {
        Thread.Sleep(100);
        concurrentDictionary.TryAdd(i, (i * i).ToString());
    }
});
Task producerTask2 = Task.Factory.StartNew(() => 
{
    for (int i = 10; i < 25; i++)
    {
        concurrentDictionary.TryAdd(i, (i * i).ToString());
    }
});
Task producerTask3 = Task.Factory.StartNew(() => 
{
    for (int i = 15; i < 20; i++)
    {
        Thread.Sleep(100);
        concurrentDictionary.AddOrUpdate(i, (i * i).ToString(),(key, value) 
         => (key * key).ToString());
    }
});
Task.WaitAll(producerTask1, producerTask2);            
Console.WriteLine("Keys are {0} ", string.Join(",", concurrentDictionary.Keys.Select(c => c.ToString()).ToArray()));
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/1435d511-3d3f-4889-91a0-923a42be2541.png)

在本节中，我们了解了并发集合在生产者-消费者场景中是非常方便的。使用并发集合，代码可以正确地处理多个任务，而无需自定义同步开销。

# 摘要

在本章中，我们讨论了.NET Framework 中的线程安全集合。并发集合位于`System.Collection.Concurrent`命名空间中，用于编程中的各种用例提供了各种集合。一些常见的用例需要包括字典、列表、包等的集合。

我们还讨论了生产者和消费者场景，其中一些线程生产数据，同时其他线程消费数据。通常，在这些场景中存在竞争条件，但并发集合可以有效地处理它们。

在下一章中，我们将学习通过延迟初始化模式来提高并行代码的性能。

# 问题

1.  以下哪个不是并发集合？

1.  `ConcurrentQueue<T>`

1.  `ConcurrentBag<T>`

1.  `ConcurrentStack<T>`

1.  `ConcurrentList<T>`

1.  当一个线程只能生产数据，另一个线程只能消费数据，而不能同时进行时，这种安排是什么？

1.  纯生产者-消费者

1.  混合生产者-消费者

1.  在纯生产者-消费者场景中，如果项目的处理时间较短，队列的性能将最佳。

1.  真

1.  假

1.  哪个不是`ConcurrentStack`的成员？

1.  `Push`

1.  `TryPop`

1.  `TryPopRange`

1.  `TryPush`
