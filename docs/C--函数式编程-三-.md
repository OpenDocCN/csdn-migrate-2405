# C# 函数式编程（三）

> 原文：[`zh.annas-archive.org/md5/BA6B40D466733162BD57D5FED41DF818`](https://zh.annas-archive.org/md5/BA6B40D466733162BD57D5FED41DF818)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用异步编程增强功能程序的响应性

响应式应用程序在今天的编程方法中是必不可少的。它们可以提高应用程序本身的性能，并使我们的应用程序具有用户友好的界面。我们需要在程序中异步运行代码执行过程，以实现响应式应用程序。为了实现这一目标，在本章中，我们将讨论以下主题：

+   使用线程和线程池构建响应式应用程序

+   学习异步编程模型模式

+   学习基于任务的异步模式

+   使用 async 和 await 关键字构建异步编程

+   在功能方法中应用异步方法

# 构建响应式应用程序

.NET Framework 首次发布时，程序的流程是按顺序执行的。这种执行流程的缺点是我们的应用程序必须等待操作完成才能执行下一个操作。这将冻结我们的应用程序，这将是一个不愉快的用户体验。

为了最小化这个问题，.NET Framework 引入了线程，这是操作的最小单位，可以由操作系统独立调度。而异步编程意味着在单独的线程上运行一段代码，释放原始线程并在任务完成时做其他事情。

## 同步运行程序

让我们从创建一个运行所有操作的程序开始同步运行。以下是演示我们可以在`SynchronousOperation.csproj`项目中找到的同步操作的代码：

```cs
public partial class Program 
{ 
  public static void SynchronousProcess() 
  { 
    Stopwatch sw = Stopwatch.StartNew(); 
    Console.WriteLine( 
      "Start synchronous process now..."); 
    int iResult = RunSynchronousProcess(); 
    Console.WriteLine( 
      "The Result = {0}",iResult); 
    Console.WriteLine( 
      "Total Time = {0} second(s)!", 
      sw.ElapsedMilliseconds/1000); 
  } 
  public static int RunSynchronousProcess() 
  { 
    int iReturn = 0; 
    iReturn += LongProcess1(); 
    iReturn += LongProcess2(); 
    return iReturn; 
  } 
  public static int LongProcess1() 
  { 
    Thread.Sleep(5000); 
    return 5; 
  } 
  public static int LongProcess2() 
  { 
    Thread.Sleep(7000); 
    return 7; 
  } 
} 

```

如前面的代码所示，`RunSynchronousProcess()`方法执行两种方法；它们是`LongProcess1()`和`LongProcess2()`方法。现在让我们调用前面的`RunSynchronousProcess()`方法，我们将在控制台上得到以下输出：

![同步运行程序](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00072.jpg)

这两种方法，`LongProcess1()`和`LongProcess2()`，是独立的，每种方法都需要一定的时间来完成。由于它是同步执行的，完成这两种方法需要 12 秒。`LongProcess1()`方法需要 5 秒完成，`LongProcess2()`方法需要 7 秒完成。

## 在程序中应用线程

我们可以改进先前的代码，使其成为响应式程序，通过重构一些代码并向代码添加线程。重构后的代码如下，在`ApplyingThreads.csproj`项目中可以找到：

```cs
public partial class Program 
{ 
  public static void AsynchronousProcess() 
  { 
    Stopwatch sw = Stopwatch.StartNew(); 
    Console.WriteLine( 
      "Start asynchronous process now..."); 
    int iResult = RunAsynchronousProcess(); 
    Console.WriteLine( 
      "The Result = {0}", 
      iResult); 
    Console.WriteLine( 
      "Total Time = {0} second(s)!", 
      sw.ElapsedMilliseconds / 1000); 
  } 
  public static int RunAsynchronousProcess() 
  { 
    int iResult1 = 0; 
    // Creating thread for LongProcess1() 
    Thread thread = new Thread( 
      () => iResult1 = LongProcess1()); 
    // Starting the thread 
    thread.Start(); 
    // Running LongProcess2() 
    int iResult2 = LongProcess2(); 
    // Waiting for the thread to finish 
    thread.Join(); 
    // Return the the total result 
    return iResult1 + iResult2; 
  } 
  public static int LongProcess1() 
  { 
    Thread.Sleep(5000); 
    return 5; 
  } 
  public static int LongProcess2() 
  { 
    Thread.Sleep(7000); 
    return 7; 
  } 
} 

```

如我们所见，我们将先前的代码中的`RunSynchronousProcess()`方法重构为`RunAsynchronousProcess()`方法。如果我们运行`RunAsynchronousProcess()`方法，我们将在控制台上得到以下输出：

![在程序中应用线程](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00073.jpg)

与`RunSynchronousProcess()`方法相比，我们现在在`RunAsynchronousProcess()`方法中有一个更快的进程。我们创建一个新的线程来运行`LongProcess1()`方法。线程将在使用`Start()`方法启动之后才会运行。看一下以下代码片段，其中我们创建并运行线程：

```cs
// Creating thread for LongProcess1() 
Thread thread = new Thread( 
  () => 
  iResult1 = LongProcess1()); 
// Starting the thread 
thread.Start(); 

```

线程运行后，我们可以运行其他操作，这种情况下是`LongProcess2()`方法。当此操作完成时，我们必须等待线程完成，然后使用线程实例的`Join()`方法。以下代码片段将解释这一点：

```cs
// Running LongProcess2() 
int iResult2 = LongProcess2(); 
// Waiting for the thread to finish 
thread.Join(); 

```

`Join()`方法将阻塞当前线程，直到正在执行的其他线程完成。在其他线程完成后，`Join()`方法将返回，然后当前线程将被解除阻塞。

## 使用线程池创建线程

除了使用线程本身，我们还可以使用`System.Threading.ThreadPool`类预先创建一些线程。如果需要从线程池中使用线程，我们可以使用这个类。在使用线程池时，您更有可能只使用`QueueUserWorkItem()`方法。该方法将向线程池队列中添加执行请求。如果线程池中有可用线程，请求将立即执行。让我们看一下以下代码，以演示线程池的使用，可以在`UsingThreadPool.csproj`项目中找到：

```cs
public partial class Program 
{ 
  public static void ThreadPoolProcess() 
  { 
    Stopwatch sw = Stopwatch.StartNew(); 
    Console.WriteLine( 
      "Start ThreadPool process now..."); 
    int iResult = RunInThreadPool(); 
    Console.WriteLine("The Result = {0}", 
      iResult); 
    Console.WriteLine("Total Time = {0} second(s)!", 
      sw.ElapsedMilliseconds / 1000); 
  } 
  public static int RunInThreadPool() 
  { 
    int iResult1 = 0; 
    // Assignin work LongProcess1() to idle thread  
    // in the thread pool  
    ThreadPool.QueueUserWorkItem((t) => 
      iResult1 = LongProcess1()); 
    // Running LongProcess2() 
    int iResult2 = LongProcess2(); 
    // Waiting the thread to be finished 
    // then returning the result 
    return iResult1 + iResult2; 
  } 
    public static int LongProcess1() 
  { 
    Thread.Sleep(5000); 
    return 5; 
  } 
  public static int LongProcess2() 
  { 
    Thread.Sleep(7000); 
    return 7; 
  } 
} 

```

在线程池中，我们可以调用`QueueUserWorkItem()`方法将新的工作项放入队列中，当我们需要运行长时间运行的进程而不是创建新线程时，线程池会管理该队列。当我们将工作发送到线程池时，有三种可能性来处理工作；它们如下：

+   线程池中有一个或多个可用线程在空闲，因此工作可以由空闲线程处理并立即运行。

+   没有可用的线程，但`MaxThreads`属性尚未达到，因此线程池将创建一个新线程，分配工作，并立即运行工作。

+   线程池中没有可用线程，并且线程池中的线程总数已达到`MaxThreads`。在这种情况下，工作项将在队列中等待第一个可用线程。

现在，让我们运行`ThreadPoolProcess()`方法，我们将在控制台上得到以下输出：

![使用线程池创建线程](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00074.jpg)

正如我们在前面的截图中所看到的，当我们应用前面部分讨论的新线程时，我们得到了相似的处理时间相同的结果。

# 异步编程模型模式

**异步编程模型**（**APM**）是一种使用`IAsyncResult`接口作为设计模式的异步操作。它也被称为`IAsyncResult`模式。为此，框架提供了名为`BeginXx`和`EndXx`的方法，其中`Xx`是操作名称，例如，`FileStream`类提供的`BeginRead`和`EndRead`用于异步从文件中读取字节。

同步的`Read()`方法与`BeginRead()`和`EndRead()`的区别可以从方法的声明中识别，如下所示：

```cs
public int Read( 
  byte[] array, 
  int offset, 
  int count 
) 
public IAsyncResult BeginRead( 
  byte[] array, 
  int offset, 
  int numBytes, 
  AsyncCallback userCallback, 
  object stateObject 
) 
public int EndRead( 
  IAsyncResult asyncResult 
) 

```

在同步的`Read()`方法中，我们需要三个参数；它们是`array`，`offset`和`numBytes`。在`BeginRead()`方法中，还有两个参数添加；它们是`userCallback`，即在异步读取操作完成时将被调用的方法，以及`stateObject`，用户提供的用于区分异步读取请求和其他请求的对象。

## 使用同步的 Read()方法

现在，让我们看一下以下代码，在`APM.csproj`项目中可以找到，以便更清楚地区分异步的`BeginRead()`方法和同步的`Read()`方法：

```cs
public partial class Program 
{ 
  public static void ReadFile() 
  { 
    FileStream fs = 
      File.OpenRead( 
        @"..\..\..\LoremIpsum.txt"); 
    byte[] buffer = new byte[fs.Length]; 
    int totalBytes = 
      fs.Read(buffer, 0, (int)fs.Length); 
    Console.WriteLine("Read {0} bytes.", totalBytes); 
    fs.Dispose(); 
  } 
} 

```

上述代码将同步读取`LoremIpsum.txt`文件（包含在`APM.csproj`项目中），这意味着在执行下一个进程之前，读取过程必须完成。如果我们运行上述的`ReadFile()`方法，我们将在控制台上得到以下输出：

![使用同步的 Read()方法](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00075.jpg)

## 使用 BeginRead()和 EndRead()方法

现在，让我们比较使用`Read()`方法进行同步读取过程与使用`BeginRead()`和`EndRead()`方法进行异步读取过程的以下代码：

```cs
public partial class Program 
{ 
  public static void ReadAsyncFile() 
  { 
    FileStream fs =  
      File.OpenRead( 
        @"..\..\..\LoremIpsum.txt"); 
    byte[] buffer = new byte[fs.Length]; 
    IAsyncResult result = fs.BeginRead(buffer, 0, (int)fs.Length,
      OnReadComplete, fs); 
    //do other work while file is read 
    int i = 0; 
    do 
    { 
      Console.WriteLine("Timer Counter: {0}", ++i); 
    } 
    while (!result.IsCompleted); 
    fs.Dispose(); 
  } 
  private static void OnReadComplete(IAsyncResult result) 
  { 
    FileStream fStream = (FileStream)result.AsyncState;
    int totalBytes = fStream.EndRead(result);
    Console.WriteLine("Read {0} bytes.", totalBytes);fStream.Dispose(); 
  } 
} 

```

如我们所见，我们有两个名为`ReadAsyncFile()`和`OnReadComplete()`的方法。`ReadAsyncFile()`方法将异步读取`LoremIpsum.txt`文件，然后在完成文件读取后立即调用`OnReadComplete()`方法。我们有额外的代码来确保使用以下`do-while`循环代码片段正确运行异步操作：

```cs
//do other work while file is read 
int i = 0; 
do 
{ 
  Console.WriteLine("Timer Counter: {0}", ++i); 
} 
while (!result.IsCompleted); 

```

上述`do-while`循环将迭代，直到异步操作完成，如`IAsyncResult`的`IsComplete`属性所示。当调用`BeginRead()`方法时，异步操作开始，如下面的代码片段所示：

```cs
IAsyncResult result = 
  fs.BeginRead( 
    buffer, 0, (int)fs.Length, OnReadComplete, fs); 

```

之后，它将在读取文件的同时继续下一个过程。当读取过程完成时，将调用`OnReadComplete()`方法，由于`OnReadComplete()`方法的实现将`IsFinish`变量设置为 true，它将停止我们的`do-while`循环。

通过运行`ReadAsyncFile()`方法，我们将得到以下输出：

![使用 BeginRead()和 EndRead()方法](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00076.jpg)

从上述输出的截图中，我们可以看到在运行读取过程时，`do-while`循环的迭代成功执行。读取过程在`do-while`循环的第 64 次迭代中完成。

## 在 BeginRead()方法调用中添加 LINQ

我们还可以使用 LINQ 来定义`OnReadComplete()`方法，以便我们可以使用匿名方法替换该方法，如下所示：

```cs
public partial class Program 
{ 
  public static void ReadAsyncFileAnonymousMethod() 
  { 
    FileStream fs = 
      File.OpenRead( 
        @"..\..\..\LoremIpsum.txt"); 
    byte[] buffer = new byte[fs.Length]; 
    IAsyncResult result = fs.BeginRead(buffer, 0, (int)fs.Length,
      asyncResult => { int totalBytes = fs.EndRead(asyncResult); 
    Console.WriteLine("Read {0} bytes.", totalBytes); 
      }, null); 
    //do other work while file is read 
    int i = 0; 
    do 
    { 
      Console.WriteLine("Timer Counter: {0}", ++i); 
    } 
    while (!result.IsCompleted); 
    fs.Dispose(); 
  } 
} 

```

如我们所见，我们用以下代码片段替换了对`BeginRead()`方法的调用：

```cs
IAsyncResult result = 
  fs.BeginRead( 
    buffer, 
    0, 
    (int)fs.Length, 
    asyncResult => 
    { 
      int totalBytes = 
        fs.EndRead(asyncResult); 
      Console.WriteLine("Read {0} bytes.", totalBytes); 
    }, 
  null); 

```

从上述代码中，我们可以看到我们不再有`OnReadComplete()`方法，因为它已被匿名方法代替。我们在回调中删除了`FileStream`实例，因为 lambda 中的匿名方法将使用闭包访问它。如果我们调用`ReadAsyncFileAnonymousMethod()`方法，我们将得到与`ReadAsyncFile()`方法完全相同的输出，除了迭代次数，因为它取决于 CPU 速度。

除了`IsCompleted`属性用于获取指示异步操作是否完成的值外，处理`IAsyncResult`时还有三个属性可用，它们如下：

+   `AsyncState`：用于检索由用户定义的对象，该对象限定或包含有关异步操作的信息

+   `AsyncWaitHandle`：用于检索`WaitHandle`（来自操作系统的等待对共享资源的独占访问的对象），指示异步操作的完成情况

+   `CompletedSynchronously`：用于检索指示异步操作是否同步完成的值

不幸的是，应用 APM 时存在一些缺点，例如无法取消操作。这意味着我们无法取消异步操作，因为从调用`BeginRead`到触发回调时，没有办法取消后台进程。如果`LoremIpsum.txt`是一个千兆字节的文件，我们必须等待异步操作完成，而不能取消操作。

### 注意

由于其过时的技术，不再建议在新开发中使用 APM 模式。

# 基于任务的异步模式

基于任务的异步模式（TAP）是一种用于表示任意异步操作的模式。这种模式的概念是在一个方法中表示异步操作，并结合操作的状态和用于与这些操作交互的 API，使它们成为一个单一对象。这些对象是`System.Threading.Tasks`命名空间中的`Task`和`Task<TResult>`类型。

## 介绍 Task 和 Task<TResult>类

`.NET Framework 4.0`中宣布了`Task`和`Task<TResult>`类，以表示异步操作。它使用存储在线程池中的线程，但提供了任务创建的灵活性。当我们需要将方法作为任务运行但不需要返回值时，我们使用`Task`类；否则，当我们需要获取返回值时，我们使用`Task<TResult>`类。

### 注意

我们可以在 MSDN 网站上找到`Task`和`Task<TResult>`的完整参考，包括方法和属性，网址为[`msdn.microsoft.com/en-us/library/dd321424(v=vs.110).aspx`](https://msdn.microsoft.com/en-us/library/dd321424(v=vs.110).aspx)。

## 应用简单的 TAP 模型

让我们通过创建以下代码来开始讨论 TAP，我们可以在`TAP.csproj`项目中找到它，并使用它来异步读取文件：

```cs
public partial class Program 
{ 
  public static void ReadFileTask() 
  { 
    bool IsFinish = false; 
    FileStream fs = File.OpenRead( 
      @"..\..\..\LoremIpsum.txt"); 
    byte[] readBuffer = new byte[fs.Length]; 
    fs.ReadAsync(readBuffer,  0,  (int)fs.Length) 
      .ContinueWith(task => { 
      if (task.Status ==  
        TaskStatus.RanToCompletion) 
        { 
          IsFinish = true; 
          Console.WriteLine( 
          "Read {0} bytes.", 
          task.Result); 
        } 
        fs.Dispose();}); 
    //do other work while file is read 
    int i = 0; 
    do 
    { 
      Console.WriteLine("Timer Counter: {0}", ++i); 
    } 
    while (!IsFinish); 
    Console.WriteLine("End of ReadFileTask() method"); 
  } 
} 

```

如上述代码所示，`FileStream`类中的`ReadAsync()`方法将返回`Task<int>`，在这种情况下，它将指示从文件中读取的字节数。在调用`ReadAsync()`方法后，我们使用方法链接调用`ContinueWith()`扩展方法，如第一章中讨论的，*在 C#中品尝函数式类型*。它允许我们指定`Action<Task<T>>`，该操作将在异步操作完成后运行。

通过在任务完成后调用`ContinueWith()`方法，委托将立即以同步操作运行。如果我们运行前面的`ReadFileTask()`方法，我们将在控制台上得到以下输出：

![应用简单的 TAP 模型](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00077.jpg)

## 使用 WhenAll()扩展方法

我们在前面的部分成功应用了简单的 TAP。现在，我们将继续通过异步读取两个文件，然后仅在两个读取操作都完成后处理其他操作。让我们看一下以下代码，它将演示我们的需求：

```cs
public partial class Program 
{ 
  public static void ReadTwoFileTask() 
  { 
    bool IsFinish = false; 
    Task readFile1 = 
      ReadFileAsync( 
      @"..\..\..\LoremIpsum.txt"); 
    Task readFile2 = 
      ReadFileAsync( 
      @"..\..\..\LoremIpsum2.txt"); 
    Task.WhenAll(readFile1, readFile2) 
      .ContinueWith(task => 
      { 
        IsFinish = true; 
        Console.WriteLine( 
        "All files have been read successfully."); 
      }); 
      //do other work while file is read 
      int i = 0; 
      do 
      { 
        Console.WriteLine("Timer Counter: {0}", ++i); 
      } 
      while (!IsFinish); 
      Console.WriteLine("End of ReadTwoFileTask() method"); 
    } 
    public static Task<int> ReadFileAsync(string filePath) 
    { 
      FileStream fs = File.OpenRead(filePath); 
      byte[] readBuffer = new byte[fs.Length]; 
      Task<int> readTask = 
        fs.ReadAsync( 
        readBuffer, 
        0, 
        (int)fs.Length); 
      readTask.ContinueWith(task => 
      { 
        if (task.Status == TaskStatus.RanToCompletion) 
        Console.WriteLine( 
          "Read {0} bytes from file {1}", 
          task.Result, 
          filePath); 
        fs.Dispose(); 
      }); 
      return readTask; 
    } 
} 

```

我们使用`Task.WhenAll()`方法将作为参数传递的两个任务包装成一个更大的异步操作。然后返回一个代表这两个异步操作组合的任务。我们不需要等待两个文件的读取操作完成，但它会在这两个文件成功读取后添加一个继续操作。

如果我们运行前面的`ReadTwoFileTask()`方法，我们将在控制台上得到以下输出：

![使用 WhenAll()扩展方法](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00078.jpg)

正如我们之前讨论过的，APM 模式的缺点是我们无法取消后台进程，现在让我们尝试通过重构我们之前的代码来取消 TAP 中的任务列表。完整的代码将变成以下样子：

```cs
public partial class Program 
{ 
  public static void ReadTwoFileTaskWithCancellation() 
  { 
    bool IsFinish = false; 

    // Define the cancellation token. 
    CancellationTokenSource source = 
      new CancellationTokenSource(); 
    CancellationToken token = source.Token; 

    Task readFile1 = 
      ReadFileAsync( 
      @"..\..\..\LoremIpsum.txt"); 
    Task readFile2 = 
      ReadFileAsync( 
      @"..\..\..\LoremIpsum2.txt"); 

    Task.WhenAll(readFile1, readFile2) 
      .ContinueWith(task => 
      { 
        IsFinish = true; 
        Console.WriteLine( 
          "All files have been read successfully."); 
      } 
      , token 
    ); 

    //do other work while file is read 
    int i = 0; 
    do 
    { 
      Console.WriteLine("Timer Counter: {0}", ++i); 
      if (i > 10) 
      { 
        source.Cancel(); 
        Console.WriteLine( 
          "All tasks are cancelled at i = " + i); 
         break; 
       } 
     } 
     while (!IsFinish); 

     Console.WriteLine( 
       "End of ReadTwoFileTaskWithCancellation() method"); 
    } 
} 

```

如上述代码所示，我们添加了`CancellationTokenSource`和`CancellationToken`来通知取消过程。然后我们将令牌传递给`Task.WhenAll()`函数。任务运行后，我们可以使用`source.Cancel()`方法取消任务。

如果我们运行上述代码，我们将在控制台上得到以下输出：

![使用 WhenAll()扩展方法](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00079.jpg)

上述输出告诉我们，任务在第 11 个计数器中成功取消，因为计数器已经超过了 10。

## 将 APM 包装成 TAP 模型

如果框架没有为异步操作提供 TAP 模型，我们可以将 APM 的`BeginXx`和`EndXx`方法包装成 TAP 模型，使用`Task.FromAsync`方法。让我们看一下以下代码，以演示包装过程：

```cs
public partial class Program 
{ 
  public static bool IsFinish; 
  public static void WrapApmIntoTap() 
  { 
    IsFinish = false; 
    ReadFileAsync( 
      @"..\..\..\LoremIpsum.txt"); 
      //do other work while file is read 
      int i = 0; 
    do 
    { 
      Console.WriteLine("Timer Counter: {0}", ++i); 
    } 
    while (!IsFinish); 
    Console.WriteLine( 
      "End of WrapApmIntoTap() method"); 
  } 
  private static Task<int> ReadFileAsync(string filePath) 
  { 
    FileStream fs = File.OpenRead(filePath); 
    byte[] readBuffer = new Byte[fs.Length]; 
    Task<int> readTask = 
      Task.Factory.FromAsync( 
      (Func<byte[], 
      int, 
      int, 
      AsyncCallback, 
      object, 
      IAsyncResult>) 
    fs.BeginRead, 
    (Func<IAsyncResult, int>) 
    fs.EndRead, 
    readBuffer, 
    0, 
    (int)fs.Length, 
    null); 
    readTask.ContinueWith(task => 
    { 
      if (task.Status == TaskStatus.RanToCompletion) 
      { 
        IsFinish = true; 
        Console.WriteLine( 
          "Read {0} bytes from file {1}", 
          task.Result, 
          filePath); 
      } 
      fs.Dispose(); 
    }); 
    return readTask; 
  } 
} 

```

从上述代码中，我们可以看到我们使用了`BeginRead()`和`EndRead()`方法，实际上是 APM 模式，但我们在 TAP 模型中使用它们，如下面的代码片段所示：

```cs
Task<int> readTask = 
  Task.Factory.FromAsync( 
    (Func<byte[], 
    int, 
    int, 
    AsyncCallback, 
    object, 
    IAsyncResult>) 
    fs.BeginRead, 
    (Func<IAsyncResult, int>) 
    fs.EndRead, 
    readBuffer, 
    0, 
    (int)fs.Length, 
  null); 

```

如果我们运行前面的`WrapApmIntoTap()`方法，我们将在控制台上得到以下输出：

将 APM 包装成 TAP 模型

正如我们在输出结果的截图中所看到的，我们成功地使用了包装到 TAP 模型中的`BeginRead()`和`EndRead()`方法来读取`LoremIpsum.txt`文件。

# 使用`async`和`await`关键字进行异步编程

`async`和`await`关键字是在 C# 5.0 中宣布的，并成为 C#异步编程中的最新和最伟大的东西。从 TAP 模式发展而来，C#将这两个关键字整合到语言本身中，使其变得简单易读。使用这两个关键字，`Task`和`Task<TResult>`类仍然成为异步编程的核心构建块。我们仍然会使用`Task.Run()`方法构建一个新的`Task`或`Task<TResult>`数据类型，就像在前一节中讨论的那样。

现在让我们看一下下面的代码，它演示了`async`和`await`关键字，我们可以在`AsyncAwait.csproj`项目中找到：

```cs
public partial class Program 
{ 
  static bool IsFinish; 
  public static void AsyncAwaitReadFile() 
  { 
    IsFinish = false; 
    ReadFileAsync(); 
    //do other work while file is read 
    int i = 0; 
    do 
    { 
      Console.WriteLine("Timer Counter: {0}", ++i); 
    } 
    while (!IsFinish); 
    Console.WriteLine("End of AsyncAwaitReadFile() method"); 
  } 
  public static async void ReadFileAsync() 
  { 
    FileStream fs = 
      File.OpenRead( 
      @"..\..\..\LoremIpsum.txt"); 
    byte[] buffer = new byte[fs.Length]; 
    int totalBytes = 
      await fs.ReadAsync( 
      buffer, 
      0, 
      (int)fs.Length); 
    Console.WriteLine("Read {0} bytes.", totalBytes); 
    IsFinish = true; 
    fs.Dispose(); 
  } 
} 

```

正如我们在上面的代码中所看到的，我们通过在读取文件流时添加`await`关键字来重构了我们上一个主题的代码，如下面的代码片段所示：

```cs
int totalBytes = 
  await fs.ReadAsync( 
    buffer, 
    0, 
    (int)fs.Length); 

```

此外，我们在方法名前面使用`async`关键字，如下面的代码片段所示：

```cs
public static async void ReadFileAsync() 
{ 
  // Implementation 
} 

```

从前两个代码片段中，我们可以看到`await`关键字只能在标记有`async`关键字的方法内部调用。当达到`await`时--在这种情况下是在`await fs.ReadAsync()`中--调用方法的线程将跳出方法并继续执行其他操作。然后异步代码将在一个单独的线程上执行（就像我们使用`Task.Run()`方法一样）。然而，`await`之后的所有内容都将在任务完成时被调度执行。如果我们运行上述的`AsyncAwaitReadFile()`方法，将在控制台上得到以下输出：

使用`async`和`await`关键字进行异步编程

与 TAP 模型一样，我们在这里也获得了异步结果。

# 函数式编程中的异步函数

现在，使用链接方法，我们将在函数式编程中使用`async`和`await`关键字。假设我们有三个任务，如下面的代码片段所示，并且我们需要将它们链接在一起：

```cs
public async static Task<int> FunctionA( 
  int a) => await Task.FromResult(a * 1); 
public async static Task<int> FunctionB( 
  int b) => await Task.FromResult(b * 2); 
public async static Task<int> FunctionC( 
  int c) => await Task.FromResult(c * 3); 

```

为此，我们必须为`Task<T>`创建一个名为`MapAsync`的新扩展方法，具体实现如下：

```cs
public static class ExtensionMethod 
{ 
  public static async Task<TResult> MapAsync<TSource, TResult>( 
    this Task<TSource> @this, 
    Func<TSource, Task<TResult>> fn) => await fn(await @this); 
} 

```

`MapAsync()`方法允许我们将方法定义为`async`，接受从`async`方法返回的任务，并`await`委托的调用。以下是我们用于链接`AsyncChain.csproj`项目中的三个任务的完整代码：

```cs
public partial class Program 
{ 
  public async static Task<int> FunctionA( 
    int a) => await Task.FromResult(a * 1); 
  public async static Task<int> FunctionB( 
    int b) => await Task.FromResult(b * 2); 
  public async static Task<int> FunctionC( 
    int c) => await Task.FromResult(c * 3); 
  public async static void AsyncChain() 
  { 
    int i = await FunctionC(10) 
    .MapAsync(FunctionB) 
    .MapAsync(FunctionA); 
    Console.WriteLine("The result = {0}", i); 
  } 
} 

```

如果我们运行上述的`AsyncChain()`方法，将在控制台上得到以下输出：

函数式编程中的异步函数

# 总结

异步编程是一种我们可以用来开发响应式应用程序的方式，我们成功地应用了`Thread`和`ThreadPool`来实现这一目标。我们可以创建一个新线程来运行工作，或者我们可以重用线程池中的可用线程。

我们还学习了异步编程模型模式，这是一种使用`IAsyncResult`接口作为设计模式的异步操作。在这种模式中，我们使用了以`Begin`和`End`开头的两种方法；例如，在我们的讨论中，这些方法是`BeginRead()`和`EndRead()`。`BeginRead()`方法在调用时启动了异步操作，然后`EndRead()`方法停止了操作，以便我们可以获取操作的返回值。

除了异步编程模型模式，.NET Framework 还有基于任务的异步模式来运行异步操作。这种模式的概念是在一个方法中表示异步操作，并将操作的状态和用于与这些操作交互的 API 结合成一个单一对象。我们在这种模式中使用的对象是`Task`和`Task<TResult>`，可以在`System.Threading.Tasks`命名空间中找到。在这种模式中，我们还可以取消作为后台进程运行的活动任务。

接着，C#宣布了`async`和`await`来完成异步技术，我们可以选择使用。它是从基于任务的异步模式发展而来的，其中`Task`和`Task<TResult>`类成为了异步编程的核心构建模块。本章我们做的最后一件事是尝试使用基于`async`和`await`关键字的扩展方法来链接这三个任务。

在下一章中，我们将讨论在函数式编程中有用的递归，以简化代码。我们将学习递归的用法，以及如何基于递归减少代码行数。


# 第七章：学习递归

在函数式编程的首次公告中，许多函数式语言没有循环功能来迭代序列。我们所要做的就是构建递归过程来迭代序列。尽管 C#具有诸如`for`和`while`之类的迭代功能，但最好还是在函数式方法中讨论递归。递归也将简化我们的代码。因此，在本章中，我们将讨论以下主题：

+   理解递归例程的工作方式

+   将迭代重构为递归

+   区分尾递归和累加器传递风格与续传风格

+   理解间接递归和直接递归

+   使用 Aggregate LINQ 运算符在函数式方法中应用递归

# 探索递归

递归函数是调用自身的函数。与迭代循环（例如`while`和`for`循环）一样，它用于逐步解决复杂的任务并组合结果。但是，`for`循环和`while`循环之间存在区别。迭代将持续重复直到任务完成，而递归将将任务分解成较小的部分以解决更大的问题，然后组合结果。在函数式方法中，递归更接近数学方法，因为它通常比迭代更短，尽管在设计和测试上可能更难一些。

在第一章中，*在 C#中品尝函数式风格*，我们在讨论函数式编程的概念时熟悉了递归函数。在那里，我们分析了命名为`GetFactorial()`的阶乘函数在命令式和函数式方法中的实现。为了提醒我们，以下是`GetFactorial()`函数的实现，我们可以在`SimpleRecursion.csproj`项目中找到：

```cs
public partial class Program 
{ 
  private static int GetFactorial(int intNumber) 
  { 
    if (intNumber == 0) 
    { 
      return 1; 
    } 
    return intNumber * GetFactorial(intNumber - 1); 
  } 
} 

```

在我们在第一章的讨论中，*在 C#中品尝函数式风格*，我们知道非负整数`N`的阶乘是小于或等于`N`的所有正整数的乘积。因此，假设我们有以下函数来计算五的阶乘：

```cs
private static void GetFactorialOfFive() 
{ 
  int i = GetFactorial(5); 
  Console.WriteLine("5! is {0}",i); 
} 

```

正如我们可以预测的那样，如果我们调用前面的`GetFactorialOfFive()`方法，我们将在控制台上得到以下输出：

![探索递归](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00083.jpg)

回到`GetFactorial()`方法，我们可以看到在该方法的实现中有结束递归的代码，如下面的代码片段所示：

```cs
if (intNumber == 0) 
{ 
  return 1; 
} 

```

我们可以看到前面的代码是递归的基本情况，递归通常有基本情况。这个基本情况将定义递归链的结束，因为在这种情况下，每次运行递归时方法都会改变`intNumber`的状态，并且如果`intNumber`为零，链条将停止。

## 递归例程的工作方式

为了理解递归例程的工作方式，让我们检查一下程序的流程，看看如果我们找到五的阶乘时`intNumber`的状态是怎样的：

```cs
int i = GetFactorial(5) 
  (intNumber = 5) != 0 
  return (5 * GetFactorial(4)) 
    (intNumber = 4) != 0 
    return (4 * GetFactorial(3)) 
      (intNumber = 3) != 0 
      return (3 * GetFactorial(2)) 
        (intNumber = 2) != 0 
        return (2 * GetFactorial(1)) 
          (intNumber = 1) != 0 
          return (1 * GetFactorial(0)) 
            (intNumber = 0) == 0 
            return 1 
          return (1 * 1 = 1) 
        return (2 * 1 = 2) 
      return (3 * 2 = 6) 
    return (4 * 6 = 24) 
  return (5 * 24 = 120) 
i = 120 

```

使用前述流程，递归的工作方式变得更清晰。我们定义的基本情况定义了递归链的结束。编程语言编译器将特定情况的递归转换为迭代，因为基于循环的实现通过消除对函数调用的需求而变得更有效率。

### 提示

在编写程序逻辑时应谨慎应用递归。如果您错过了基本情况或给出了错误的值，可能会陷入无限递归。例如，在前面的`GetFactorial()`方法中，如果我们传递`intNumber < 0`，那么我们的程序将永远不会结束。

## 将迭代重构为递归

递归使我们的程序更易读，并且在函数式编程方法中是必不可少的。在这里，我们将把 for 循环迭代重构为递归方法。让我们来看看以下代码，我们可以在`RefactoringIterationToRecursion.csproj`项目中找到：

```cs
public partial class Program 
{ 
  public static int FindMaxIteration( 
     int[] intArray) 
  { 
    int iMax = 0; 
    for (int i = 0; i < intArray.Length; i++) 
    { 
      if (intArray[i] > iMax) 
      { 
        iMax = intArray[i]; 
      } 
    } 
    return iMax; 
  } 
} 

```

上述的`FindMaxIteration()`方法用于选择数组中的最大数。考虑到我们有以下代码来运行`FindMaxIteration()`方法：

```cs
public partial class Program 
{ 
  static void Main(string[] args) 
  { 
    int[] intDataArray =  
       {8, 10, 24, -1, 98, 47, -101, 39 }; 
    int iMaxNumber = FindMaxIteration(intDataArray); 
    Console.WriteLine( 
       "Max Number (using FindMaxRecursive) = " + 
         iMaxNumber); 
  } 
} 

```

正如我们所期望的，我们将在控制台窗口中得到以下输出：

![将迭代重构为递归](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00084.jpg)

现在，让我们将`FindMaxIteration()`方法重构为递归函数。以下是`FindMaxRecursive()`方法的实现，它是`FindMaxIteration()`方法的递归版本：

```cs
public partial class Program 
{ 
  public static int FindMaxRecursive( 
     int[] intArray,  
      int iStartIndex = 0) 
  { 
    if (iStartIndex == intArray.Length - 1) 
    { 
      return intArray[iStartIndex]; 
    } 
    else 
    { 
      return Math.Max(intArray[iStartIndex],
        FindMaxRecursive(intArray,iStartIndex + 1)); 
    } 
  } 
} 

```

我们可以使用与`FindMaxIteration()`方法相同的代码来调用上述的`FindMaxRecursive()`方法，如下所示：

```cs
public partial class Program 
{ 
  static void Main(string[] args) 
  { 
    int[] intDataArray = {8, 10, 24, -1, 98, 47, -101, 39 }; 
    int iMaxNumber = FindMaxRecursive(intDataArray); 
    Console.WriteLine"Max Number(using FindMaxRecursive) = " +
        iMaxNumber); 
  } 
} 

```

正如我们在上面的方法中所看到的，我们有以下基本情况来定义递归链的结束：

```cs
if (iStartIndex == intArray.Length - 1) 
{ 
  return intArray[iStartIndex]; 
} 

```

如果我们运行上述代码，我们将得到与之前方法中得到的相同结果，如下面的控制台截图所示：

![将迭代重构为递归](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00085.jpg)

现在，让我们来看一下以下流程，了解我们如何在使用递归函数时得到这个结果：

```cs
Array = { 8, 10, 24, -1, 98, 47, -101, 39 }; 
Array.Length - 1 = 7 
int iMaxNumber = FindMaxRecursive(Array, 0) 
  (iStartIndex = 0) != 7 
  return Max(8, FindMaxRecursive(Array, 1)) 
    (iStartIndex = 1) != 7 
    return Max(10, FindMaxRecursive(Array, 2)) 
      (iStartIndex = 2) != 7 
      return Max(24, FindMaxRecursive(Array, 3)) 
        (iStartIndex = 3) != 7 
        return Max(-1, FindMaxRecursive(Array, 4)) 
          (iStartIndex = 4) != 7 
           return Max(98, FindMaxRecursive(Array, 5)) 
            (iStartIndex = 5) != 7 
            return Max(47, FindMaxRecursive(Array, 6)) 
              (iStartIndex = 6) != 7 
              return Max(-101, FindMaxRecursive(Array, 7)) 
                (iStartIndex = 7) == 7 
                return 39 
              return Max(-101, 39) = 39 
            return Max(47, 39) = 47 
          return Max(98, 47) = 98 
        return Max(-1, 98) = 98 
      return Max(24, 98) = 98 
    return Max(10, 98) = 98 
  return Max(8, 98) = 98 
iMaxNumber = 98 

```

使用上述流程，我们可以区分每次调用`FindMaxRecursive()`方法时得到的最大数的每个状态变化。然后，我们可以证明给定数组中的最大数是`98`。

# 使用尾递归

在我们之前讨论的`GetFactorial()`方法中，使用传统递归来计算阶乘数。这种递归模型首先执行递归调用并返回值，然后计算结果。使用这种递归模型，我们在递归调用完成之前不会得到结果。

除了传统的递归模型，我们还有另一种称为尾递归的递归。尾调用成为函数中的最后一件事，并且在递归之后不执行任何操作。让我们来看看以下代码，我们可以在`TailRecursion.csproj`项目中找到：

```cs
public partial class Program 
{ 
  public static void TailCall(int iTotalRecursion) 
  { 
    Console.WriteLine("Value: " + iTotalRecursion); 
    if (iTotalRecursion == 0) 
    { 
      Console.WriteLine("The tail is executed"); 
      return; 
    } 
    TailCall(iTotalRecursion - 1); 
  } 
} 

```

从上面的代码中，当`iTotalRecursion`达到`0`时，尾部被执行，如下面的代码片段所示：

```cs
if (iTotalRecursion == 0) 
{ 
  Console.WriteLine("The tail is executed"); 
  return; 
} 

```

如果我们运行上述的`TailCall()`方法，并为`iTotalRecursion`参数传递`5`，我们将在控制台上得到以下输出：

![使用尾递归](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00086.jpg)

现在，让我们来看看在这段代码中每次递归调用时状态的变化：

```cs
TailCall(5) 
  (iTotalRecursion = 5) != 0 
  TailCall(4) 
    (iTotalRecursion = 4) != 0 
    TailCall(3) 
      iTotalRecursion = 3) != 0 
      TailCall(2) 
        iTotalRecursion = 2) != 0 
        TailCall(1) 
          iTotalRecursion = 1) != 0 
          TailCall(0) 
            iTotalRecursion = 0) == 0 
            Execute the process in tail 
        TailCall(1) => nothing happens 
      TailCall(2) => nothing happens 
    TailCall(3) => nothing happens 
  TailCall(4) => nothing happens 
TailCall(5) => nothing happens 

```

从递归的流程中，该过程仅在最后的递归调用中运行。之后，其他递归调用不会发生任何事情。换句话说，我们可以得出以下流程：

```cs
TailCall(5) 
   (iTotalRecursion = 5) != 0 
  TailCall(4) 
    (iTotalRecursion = 4) != 0 
    TailCall(3) 
      iTotalRecursion = 3) != 0 
      TailCall(2) 
        iTotalRecursion = 2) != 0 
        TailCall(1) 
          iTotalRecursion = 1) != 0 
          TailCall(0) 
            iTotalRecursion = 0) == 0 
            Execute the process in tail 
Finish! 

```

现在，我们的尾递归流程显而易见。尾递归的思想是尽量减少堆栈的使用，因为堆栈有时是我们拥有的昂贵资源。使用尾递归，代码不需要记住上次返回时必须返回的状态，因为在这种情况下，它在累加器参数中有临时结果。接下来的主题是遵循尾递归的两种风格；它们是**累加器传递风格**（**APS**）和**续传风格**（**CPS**）。

## 累加器传递风格

在**累加器传递风格**（**APS**）中，递归首先执行计算，执行递归调用，然后将当前步骤的结果传递给下一个递归步骤。让我们来看看我们从`GetFactorial()`方法重构的尾递归代码的累加器传递风格，我们可以在`AccumulatorPassingStyle.csproj`项目中找到：

```cs
public partial class Program 
{ 
  public static int GetFactorialAPS(int intNumber, 
    int accumulator = 1) 
  { 
    if (intNumber == 0) 
    { 
      return accumulator; 
    } 
    return GetFactorialAPS(intNumber - 1, 
       intNumber * accumulator); 
  } 
} 

```

与`GetFactorial()`方法相比，`GetFactorialAPS()`方法现在有一个名为 accumulator 的第二个参数。由于阶乘`0`的结果是`1`，我们将默认值 1 赋给 accumulator 参数。现在它不仅返回一个值，而且每次调用递归函数时都返回阶乘的计算结果。为了证明这一点，考虑我们有以下代码来调用`GetFactorialAPS()`方法：

```cs
public partial class Program 
{ 
  private static void GetFactorialOfFiveUsingAPS() 
  { 
    int i = GetFactorialAPS(5); 
    Console.WriteLine( 
       "5! (using GetFactorialAPS) is {0}",i); 
  } 
} 

```

如果我们运行上述方法，我们将在控制台上得到以下输出：

![累加器传递风格](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00087.jpg)

现在，让我们检查`GetFactorialAPS()`方法的每个调用，以查看程序的以下流程中方法内部的状态变化：

```cs
int i = GetFactorialAPS(5, 1) 
  accumulator = 1 
  (intNumber = 5) != 0 
  return GetFactorialAPS(4, 5 * 1) 
    accumulator = 5 * 1 = 5 
    (intNumber = 4) != 0 
    return GetFactorialAPS(3, 4 * 5) 
      accumulator = 4 * 5 = 20 
      (intNumber = 3) != 0 
      return GetFactorialAPS(2, 3 * 20) 
        accumulator = 3 * 20 = 60 
        (intNumber = 2) != 0 
        return GetFactorialAPS(1, 2 * 60) 
          accumulator = 2 * 60 = 120 
          (intNumber = 1) != 0 
          return GetFactorialAPS(0, 1 * 120) 
            accumulator = 1 * 120 = 120 
            (intNumber = 0) == 0 
            return accumulator 
          return 120 
        return 120 
      return 120 
    return 120 
  return 120 
i = 120 

```

从上述流程中可以看出，由于每次调用时都执行计算，我们现在在函数的最后一次调用中得到了计算的结果，当`intNumber`参数达到`0`时，如下面的代码片段所示：

```cs
return GetFactorialTailRecursion(0, 1 * 120) 
  accumulator = 1 * 120 = 120 
  (intNumber = 0) == 0 
  return accumulator 
return 120 

```

我们还可以将上述的`GetFactorialAPS()`方法重构为`GetFactorialAPS2()`方法，以便不返回任何值，这样尾递归的 APS 将变得更明显。代码将如下所示：

```cs
public partial class Program 
{ 
  public static void GetFactorialAPS2( 
      int intNumber,int accumulator = 1) 
  { 
    if (intNumber == 0) 
    { 
      Console.WriteLine("The result is " + accumulator); 
      return; 
    } 
    GetFactorialAPS2(intNumber - 1, intNumber * accumulator); 
  } 
} 

```

假设我们有以下`GetFactorialOfFiveUsingAPS2()`方法来调用`GetFactorialAPS2()`方法：

```cs
public partial class Program 
{ 
  private static void GetFactorialOfFiveUsingAPS2() 
  { 
    Console.WriteLine("5! (using GetFactorialAPS2)"); 
    GetFactorialAPS2(5); 
  } 
} 

```

因此，如果我们调用上述的`GetFactorialOfFiveUsingAPS2()`方法，我们将在控制台上得到以下输出：

![累加器传递风格](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00088.jpg)

现在，`GetFactorialAPS2()`方法的流程变得更清晰，如下面的程序流程所示：

```cs
GetFactorialAPS2(5, 1) 
  accumulator = 1 
  (intNumber = 5) != 0 
  GetFactorialAPS2(4, 5 * 1) 
    accumulator = 5 * 1 = 5 
    (intNumber = 4) != 0 
    GetFactorialAPS2(3, 4 * 5) 
      accumulator = 4 * 5 = 20 
      (intNumber = 3) != 0 
      GetFactorialAPS2(2, 3 * 20) 
        accumulator = 3 * 20 = 60 
        (intNumber = 2) != 0 
        GetFactorialAPS2(1, 2 * 60) 
          accumulator = 2 * 60 = 120 
          (intNumber = 1) != 0 
          GetFactorialAPS2(0, 1 * 120) 
            accumulator = 1 * 120 = 120 
            (intNumber = 0) == 0 
            Show the accumulator value 
Finish! 

```

从上述流程中，我们可以看到每次调用`GetFactorialAPS2()`方法时都会计算 accumulator。这种递归类型的结果是，我们不再需要使用堆栈，因为函数在调用自身时不需要记住其起始位置。

## 继续传递风格

**继续传递风格**（**CPS**）与 APS 具有相同的目的，即使用尾调用实现递归函数，但在处理操作时具有显式的继续。CPS 函数的返回值将传递给继续函数。

现在，让我们将`GetFactorial()`方法重构为以下`GetFactorialCPS()`方法，我们可以在`ContinuationPassingStyle.csproj`项目中找到它：

```cs
public partial class Program 
{ 
  public static void GetFactorialCPS(int intNumber, Action<int> 
         actCont) 
  { 
    if (intNumber == 0) 
      actCont(1); 
    else 
      GetFactorialCPS(intNumber - 1,x => actCont(intNumber * x)); 
  } 
} 

```

正如我们所看到的，与`GetFactorialAPS()`方法中使用 accumulator 不同，我们现在使用`Action<T>`来委托一个匿名方法，这个方法作为继续使用。假设我们有以下代码来调用`GetFactorialCPS()`方法：

```cs
public partial class Program 
{ 
  private static void GetFactorialOfFiveUsingCPS() 
  { 
    Console.Write("5! (using GetFactorialCPS) is "); 
    GetFactorialCPS(5,  x => Console.WriteLine(x)); 
  } 
} 

```

如果我们运行上述的`GetFactorialOfFiveUsingCPS()`方法，我们将在控制台上得到以下输出：

![继续传递风格](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00089.jpg)

实际上，与`GetFactorial()`方法或`GetFactorialAPS2()`方法相比，我们得到了相同的结果。然而，递归的流程现在变得有点不同，如下面的解释所示：

```cs
GetFactorialCPS(5, Console.WriteLine(x)) 
  (intNumber = 5) != 0 
  GetFactorialCPS(4, (5 * x)) 
    (intNumber = 4) != 0 
    GetFactorialCPS(3, (4 * x)) 
      (intNumber = 3) != 0 
      GetFactorialCPS(2, (3 * x)) 
        (intNumber = 2) != 0 
        GetFactorialCPS(1, (2 * x)) 
          (intNumber = 1) != 0 
          GetFactorialCPS(0, (1 * x)) 
            (intNumber = 0) != 0 
            GetFactorialCPS(0, (1 * 1)) 
          (1 * 1 = 1) 
        (2 * 1 = 2) 
      (3 * 2 = 6) 
    (4 * 6 = 24) 
  (5 * 24 = 120) 
Console.WriteLine(120) 

```

现在，每次递归的返回值都传递给继续过程，即`Console.WriteLine()`函数。

## 间接递归比直接递归

我们之前讨论过递归方法。实际上，在我们之前的讨论中，我们应用了直接递归，因为我们只处理了一个单一的方法，并且一遍又一遍地调用它，直到基本情况被执行。然而，还有另一种递归类型，称为间接递归。间接递归涉及至少两个函数，例如函数 A 和函数 B。在间接递归的应用中，函数 A 调用函数 B，然后函数 B 再次调用函数 A。这被认为是递归，因为当方法 B 调用方法 A 时，函数 A 实际上是活动的，当它再次调用函数 B 时。换句话说，当函数 B 再次调用函数 A 时，函数 A 的调用尚未完成。让我们来看看下面的代码，它演示了我们可以在`IndirectRecursion.csproj`项目中找到的间接递归：

```cs
public partial class Program 
{ 
  private static bool IsOdd(int targetNumber) 
  { 
    if (targetNumber == 0) 
    { 
      return false; 
    } 
    else 
    { 
      return IsEven(targetNumber - 1); 
    } 
  } 
  private static bool IsEven(int targetNumber) 
  { 
    if (targetNumber == 0) 
    { 
      return true; 
    } 
    else 
    { 
      return IsOdd(targetNumber - 1); 
    } 
  } 
} 

```

在上面的代码中，我们有两个函数：`IsOdd()`和`IsEven()`。每个函数在比较结果为`false`时都会调用另一个函数。当`targetNumber`不为零时，`IsOdd()`函数将调用`IsEven()`，`IsEven()`函数也是如此。每个函数的逻辑都很简单。例如，`IsOdd()`方法通过调查前一个数字`targetNumber - 1`是否为偶数来决定`targetNumber`是否为奇数。同样，`IsEven()`方法通过调查前一个数字是否为奇数来决定`targetNumber`是否为偶数。它们都将`targetNumber`减一，直到它变为零，由于零是一个偶数，现在很容易确定`targetNumber`是奇数还是偶数。现在，我们添加以下代码来检查数字`5`是偶数还是奇数：

```cs
public partial class Program 
{ 
  private static void CheckNumberFive() 
  { 
    Console.WriteLine("Is 5 even number? {0}", IsEven(5)); 
  } 
} 

```

如果我们运行上述的`CheckNumberFive()`方法，将在控制台上得到以下输出：

![间接递归与直接递归](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00090.jpg)

现在，为了更清楚地理解，让我们来看看涉及`IsOdd()`和`IsEven()`方法的以下间接递归流程：

```cs
IsEven(5) 
  (targetNumber = 5) != 0 
  IsOdd(4) 
    (targetNumber = 4) != 0 
    IsEven(3) 
      (targetNumber = 3) != 0 
      IsOdd(2) 
        (targetNumber = 2) != 0 
        IsEven(1) 
          (targetNumber = 1) != 0 
            IsOdd(0) 
            (targetNumber = 0) == 0 
              Result = False 

```

从上面的流程中，我们可以看到，当我们检查数字 5 是偶数还是奇数时，我们向下移动到数字 4 并检查它是否为奇数。然后我们检查数字 3，依此类推，直到我们达到 0。通过达到 0，我们可以很容易地确定它是奇数还是偶数。

# 使用 LINQ Aggregate 进行函数式递归

当我们处理阶乘公式时，我们可以使用 LINQ Aggregate 将我们的递归函数重构为函数式方法。LINQ Aggregate 将累积给定的序列，然后我们将从累加器中得到递归的结果。在第一章中，我们已经进行了这种重构。让我们借用该章节的代码来分析`Aggregate`方法的使用。下面的代码将使用`Aggregate`方法，我们可以在`RecursionUsingAggregate.csproj`项目中找到：

```cs
public partial class Program 
{ 
  private static void GetFactorialAggregate(int intNumber) 
  { 
    IEnumerable<int> ints =  
       Enumerable.Range(1, intNumber); 
    int factorialNumber =  
       ints.Aggregate((f, s) => f * s); 
    Console.WriteLine("{0}! (using Aggregate) is {1}",
       intNumber, factorialNumber); 
  } 
} 

```

如果我们运行上述的`GetFactorialAggregate()`方法，并将`5`作为参数传递，将在控制台上得到以下输出：

![使用 LINQ Aggregate 进行函数式递归](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00091.jpg)

正如我们在上面的控制台截图中所看到的，与非累积递归相比，我们得到了完全相同的结果。

## 深入研究 Aggregate 方法

正如我们之前讨论的，`Aggregate`方法将累积给定的序列。让我们来看看下面的代码，我们可以在`AggregateExample.csproj`项目文件中找到，以演示`Aggregate`方法的工作原理：

```cs
public partial class Program 
{ 
  private static void AggregateInt() 
  { 
    List<int> listInt = new List<int>() { 1, 2, 3, 4, 5, 6 }; 
    int addition = listInt.Aggregate( 
       (sum, i) => sum + i); 
    Console.WriteLine("The sum of listInt is " + addition); 
  } 
} 

```

从上面的代码中，我们可以看到我们有一个`int`数据类型的列表，其中包含从 1 到 6 的数字。然后我们调用`Aggregate`方法来求和`listInt`的成员。以下是上述代码的流程：

```cs
(sum, i) => sum + i 
sum = 1 
sum = 1 + 2 
sum = 3 + 3 
sum = 6 + 4 
sum = 10 + 5 
sum = 15 + 6 
sum = 21 
addition = sum 

```

如果我们运行上述的`AggregateInt()`方法，将在控制台上得到以下输出：

![深入研究 Aggregate 方法](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00092.jpg)

实际上，`Aggregate`方法不仅可以添加数字，还可以添加字符串。让我们来看下面的代码，演示了使用`Aggregate`方法来添加字符串序列：

```cs
public partial class Program 
{ 
  private static void AggregateString() 
  { 
    List<string> listString = new List<string>()
      {"The", "quick", "brown", "fox", "jumps", "over",
              "the", "lazy", "dog"};
    string stringAggregate = listString.Aggregate((strAll, str) => 
              strAll + " " + str); 
    Console.WriteLine(stringAggregate); 
  } 
} 

```

如果我们运行前面的`AggregateString()`方法，我们将在控制台上得到以下输出：

深入研究 Aggregate 方法

以下是我们可以在 MSDN 中找到的`Aggregate`方法的声明：

```cs
public static TSource Aggregate<TSource>( 
  this IEnumerable<TSource> source, 
  Func<TSource, TSource, TSource> func 
) 

```

以下是基于先前声明的`AggregateUsage()`方法的流程：

```cs
(strAll, str) => strAll + " " + str 
strAll = "The" 
strAll = strAll + " " + str 
strAll = "The" + " " + "quick" 
strAll = "The quick" + " " + "brown" 
strAll = "The quick brown" + " " + "fox" 
strAll = "The quick brown fox" + " " + "jumps" 
strAll = "The quick brown fox jumps" + " " + "over" 
strAll = "The quick brown fox jumps over" + " " + "the" 
strAll = "The quick brown fox jumps over the" + " " + "lazy" 
strAll = "The quick brown fox jumps over the lazy" + " " + "dog" 
strAll = "The quick brown fox jumps over the lazy dog" 
stringAggregate = str 

```

从前面的流程中，我们可以使用`Aggregate`方法连接`listString`中的所有字符串。这证明不仅可以处理`int`数据类型，还可以处理字符串数据类型。

# 摘要

虽然 C#有一个使用`for`或`while`循环迭代序列的功能，但最好我们使用递归来迭代序列来接触函数式编程。我们已经讨论了递归例程的工作原理，并将迭代重构为递归。我们知道在递归中，我们有一个将定义递归链结束的基本情况。

在传统的递归模型中，递归调用首先执行，然后返回值，然后计算结果。结果直到递归调用完成后才会显示。而尾递归在递归之后根本不做任何事情。尾递归有两种风格；它们是 APS 和 CPS。

除了直接递归，我们还讨论了间接递归。间接递归涉及至少两个函数。然后，我们将递归应用到使用 Aggregrate LINQ 运算符的函数方法中。我们还深入研究了 Aggregate 运算符以及它的工作原理。

在下一章中，我们将讨论优化技术，使我们的代码更加高效。我们将使用懒惰思维，这样代码将在完美的时间执行，还将使用缓存技术，这样代码不需要每次都执行。


# 第八章：使用懒惰和缓存技术优化代码

我们在上一章中讨论了递归，它帮助我们轻松地迭代序列。此外，我们需要讨论优化代码，因为这是一个必要的技术，如果我们想要开发一个好的程序。在函数方法中，我们可以使用懒惰和缓存技术来使我们的代码更有效，从而使其运行更快。通过讨论懒惰和缓存技术，我们将能够开发出高效的代码。在本章中，我们将讨论以下主题以了解更多关于懒惰和缓存技术的知识：

+   在我们的代码中实现懒惰：懒惰枚举、懒惰评估、非严格评估和懒惰初始化

+   懒惰的好处

+   使用预计算和记忆化缓存昂贵的资源

# 懒惰的介绍

当我们谈论日常活动中的懒惰时，我们可能会想到一些我们不做但实际上必须做的事情。或者，我们可能因为懒惰而推迟做某事。在函数式编程中，懒惰类似于我们在日常活动中的懒惰。由于懒惰思维的概念，特定代码的执行被推迟。在第五章中，*使用 LINQ 轻松查询任何集合*，我们提到 LINQ 在查询数据时实现了延迟执行。

查询只有在枚举时才会执行。现在，让我们讨论一下我们可以在函数方法中使用的懒惰概念。

## 懒惰枚举

在.NET 框架中，有一些枚举数据集合的技术，例如数组和`List<T>`。然而，从内在上来说，它们是急切的评估，因为在数组中，我们必须先定义其大小，然后填充分配的内存，然后再使用它。`List<T>`与数组相比具有类似的概念。它采用了数组机制。这两种枚举技术之间的区别在于我们可以很容易地扩展`List<T>`的大小，而不是数组。

相反，.NET 框架有`IEnumerable<T>`来枚举数据集合，并且幸运的是，它将被懒惰地评估。实际上，数组和`List<T>`实现了`IEnumerable<T>`接口，但由于它必须由数据填充，因此必须急切地评估。在第五章中，*使用 LINQ 轻松查询任何集合*，我们在处理 LINQ 时使用了这个`IEnumerable<T>`接口。

`IEnumerable<T>`接口实现了`IEnumerable`接口，其定义如下：

```cs
public interface IEnumerable<out T> : IEnumerable 

```

`IEnumerable<T>`接口只有一个方法：`GetEnumerator()`。该方法的定义与下面的代码中所示的类似：

```cs
IEnumerator<T> GetEnumerator() 

```

正如你所看到的，`GetEnumerator()`方法返回`IEnumerator<T>`数据类型。该类型只有三种方法和一个属性。以下是它具有的方法和属性：

+   `Current`：这是一个存储枚举器当前位置的集合元素的属性。

+   `Reset()`：这是一个将枚举器设置为初始位置的方法，即在集合的第一个元素之前。初始位置的索引通常是*-1*（减一）。

+   `MoveNext()`：这是一个将枚举器移动到下一个集合元素的方法。

+   `Dispose()`：这是一个释放、释放或重置非托管资源的方法。它是从`IDisposable`接口继承而来的。

现在，让我们玩玩斐波那契算法，它将生成无限的数字。该算法将通过添加前两个元素来生成序列。在数学术语中，该公式可以定义如下：

```cs
Fn = Fn-1 + Fn-2 

```

该算法的计算的前两个数字可以是 0 和 1 或 1 和 1。

使用这个算法，我们将证明`IEnumerable`接口是一种惰性求值。因此，我们创建了一个名为`FibonacciNumbers`的类，它实现了`IEnumerable<Int64>`接口，我们可以在`LazyEnumeration.csproj`项目中找到，如下面的代码所示：

```cs
public partial class Program 
{ 
  public class FibonacciNumbers 
    : IEnumerable<Int64> 
  { 
    public IEnumerator<Int64> GetEnumerator() 
    { 
      return new FibEnumerator(); 
    } 
    IEnumerator IEnumerable.GetEnumerator() 
    { 
      return GetEnumerator(); 
    } 
  } 
} 

```

由于`FibonacciNumbers`类实现了`IEnumerable<T>`接口，它具有我们之前讨论过的`GetEnumerator()`方法来枚举数据集合。并且因为`IEnumerable<T>`接口实现了`IEnumerator<T>`接口，我们创建了`FibEnumerator`类，如下面的代码所示：

```cs
public partial class Program 
{ 
  public class FibEnumerator 
    : IEnumerator<Int64> 
  { 
    public FibEnumerator() 
    { 
      Reset(); 
    } 
    // To get the current element 
    public Int64 Current { get; private set; } 
    // To get the last element 
    Int64 Last { get; set; } 
    object IEnumerator.Current 
    { 
      get 
      { 
        return Current; 
      } 
    } 
    public void Dispose() 
    { 
      ; // Do Nothing 
    } 
    public bool MoveNext() 
    { 
      if (Current == -1) 
      { 
        // Fibonacci algorithm 
        // F0 = 0 
        Current = 0; 
      } 
      else if (Current == 0) 
      { 
        // Fibonacci algorithm 
        // F1 = 1 
        Current = 1; 
      } 
      else 
      { 
        // Fibonacci algorithm 
        // Fn = F(n-1) + F(n-2) 
        Int64 next = Current + Last; 
        Last = Current; 
        Current = next; 
      } 
      // It's never ending sequence, 
      // so the MoveNext() always TRUE 
      return true; 
    } 
    public void Reset() 
    { 
      // Back to before first element 
      // which is -1 
      Current = -1; 
    } 
  } 
} 

```

现在，我们有了实现`IEnumerator<T>`接口的`FibEnumerator`类。由于该类实现了`IEnumerator<T>`，它具有我们已经讨论过的`Reset()`、`MoveNext()`和`Dispose()`方法。它还具有从`IEnumerator<T>`接口的实现中添加的`Current`属性。我们添加了`Last`属性来保存最后一个当前数字。

现在，是时候创建调用者来实例化`FibonacciNumbers`类了。我们可以创建`GetFibonnacciNumbers()`函数，其实现类似于以下代码所示：

```cs
public partial class Program 
{ 
  private static void GetFibonnacciNumbers( 
    int totalNumber) 
  { 
    FibonacciNumbers fibNumbers = 
      new FibonacciNumbers(); 
    foreach (Int64 number in 
      fibNumbers.Take(totalNumber)) 
    { 
      Console.Write(number); 
      Console.Write("\t"); 
    } 
    Console.WriteLine(); 
  } 
} 

```

因为`FibonacciNumbers`类将枚举无限数字，我们必须使用`Take()`方法，如下面的代码片段所示，以免创建无限循环：

```cs
foreach (Int64 number in 
  fibNumbers.Take(totalNumber)) 

```

假设我们需要从序列中枚举 40 个数字；我们可以将 40 作为参数传递给`GetFibonnacciNumbers()`函数，如下所示：

```cs
GetFibonnacciNumbers(40) 

```

如果我们运行上述函数，将在控制台上获得以下输出：

![惰性枚举](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00094.jpg)

我们可以在控制台上获得前面的输出，因为`IEnumerable`是一种惰性求值。这是因为只有在要求时才会调用`MoveNext()`方法来计算结果。想象一下，如果它不是惰性的并且总是被调用；那么，我们之前的代码将会旋转并导致无限循环。

## 惰性求值

我们在惰性求值中的一个简单例子是当我们处理两个布尔语句并需要比较它们时。让我们看一下以下代码，它演示了我们可以在`SimpleLazyEvaluation.csproj`项目中找到的惰性求值：

```cs
public partial class Program 
{ 
  private static MemberData GetMember() 
  { 
    MemberData member = null; 
    try 
    { 
      if (member != null || member.Age > 50) 
      { 
        Console.WriteLine("IF Statement is TRUE"); 
        return member; 
      } 
      else 
      { 
        Console.WriteLine("IF Statement is FALSE"); 
        return null; 
      } 
    } 
    catch (Exception e) 
    { 
      Console.WriteLine("ERROR: " + e.Message); 
      return null; 
    } 
  } 
} 

```

这是我们在前面代码中使用的`MemberData`类：

```cs
public class MemberData 
{ 
  public string Name { get; set; } 
  public string Gender { get; set; } 
  public int Age { get; set; } 
} 

```

如果我们运行前面的`GetMember()`方法，将在控制台上获得以下输出：

![惰性求值](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00095.jpg)

我们知道，在布尔表达式中使用`||`（OR）运算符时，如果至少有一个表达式为`TRUE`，则结果为`TRUE`。现在看一下以下代码片段：

```cs
if (member != null || member.Age > 50) 

```

在前面的例子中，当编译器发现成员`!= null`为`FALSE`时，它会评估另一个表达式，即`member.Age > 50`。由于成员为空，它没有`Age`属性；因此，当我们尝试访问此属性时，它将抛出异常。

现在，让我们将前面的代码片段重构为以下代码，使用`&&`（AND）运算符：

```cs
if (member != null && member.Age > 50) 

```

名为`GetMemberANDOperator()`的完整方法将如下所示：

```cs
public partial class Program 
{ 
  private static MemberData GetMemberANDOperator() 
  { 
    MemberData member = null; 
    try 
    { 
      if (member != null && member.Age > 50) 
      { 
        Console.WriteLine("IF Statement is TRUE"); 
        return member; 
      } 
      else 
      { 
        Console.WriteLine("IF Statement is FALSE"); 
        return null; 
      } 
    } 
    catch (Exception e) 
    { 
      Console.WriteLine("ERROR: " + e.Message); 
      return null; 
    } 
  } 
} 

```

如果我们运行前面的`GetMemberANDOperator()`方法，将在控制台上获得以下输出：

![惰性求值](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00096.jpg)

现在，`if`语句已成功执行，并在评估后得出`FALSE`。然而，在这种情况下，`member.Age > 50`表达式从未被评估，因此不会抛出异常。`member.Age > 50`表达式不被评估的原因是编译器太懒了，因为第一个表达式`member != null`为`FALSE`，而这个`&&`逻辑操作的结果将始终为`FALSE`，而不管其他表达式的结果如何。现在我们可以说，懒惰是在可以仅使用一个表达式决定结果时忽略另一个表达式。

## 非严格求值

有些人可能认为惰性评估与非严格评估是同义词。然而，实际上并不是同义词，因为在惰性评估中，如果不需要特定表达式的评估，它将被忽略，而在非严格评估中将应用评估的简化。让我们看一下下面的代码，以区分严格和非严格评估，我们可以在`NonStrictEvaluation.csproj`项目中找到：

```cs
public partial class Program 
{ 
  private static int OuterFormula(int x, int yz) 
  { 
    Console.WriteLine( 
      String.Format( 
        "Calculate {0} + InnerFormula({1})", 
        x, 
        yz)); 
    return x * yz; 
  } 
  private static int InnerFormula(int y, int z) 
  { 
    Console.WriteLine( 
      String.Format( 
        "Calculate {0} * {1}", 
        y, 
        z 
        )); 
    return y * z; 
  } 
} 

```

在前面的代码中，我们将计算`x + (y * z)`的公式。`InnerFormula()`函数将计算`y`和`z`的乘法，而`OuterFormula()`函数将计算`x`和`y * z`的结果的加法。在严格评估中评估公式时，我们首先计算`(y * z)`表达式以检索值，然后将结果添加到`x`。代码将如下`StrictEvaluation()`函数所示：

```cs
public partial class Program 
{ 
  private static void StrictEvaluation() 
  { 
    int x = 4; 
    int y = 3; 
    int z = 2; 
    Console.WriteLine("Strict Evaluation"); 
    Console.WriteLine( 
      String.Format( 
        "Calculate {0} + ({1} * {2})",x, y, z)); 
    int result = OuterFormula(x, InnerFormula(y, z)); 
    Console.WriteLine( 
      String.Format( 
        "{0} + ({1} * {2}) = {3}",x, y, z, result)); 
    Console.WriteLine(); 
  } 
} 

```

正如您在前面的代码片段中所看到的，我们调用`OuterFormula()`函数如下所示：

```cs
int result = OuterFormula(x, InnerFormula(y, z)); 

```

对于我们之前讨论的严格评估，我们在控制台上得到的输出将如下所示：

![非严格评估](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00097.jpg)

正如您在前面的图中所看到的，当我们计算`4 + (3 * 2)`时，我们首先计算`(3 * 2)`的结果，然后在获得结果后，将其添加到`4`。

现在，让我们与非严格评估进行比较。在非严格评估中，`+`运算符首先被简化，然后我们简化内部公式`(y * z)`。我们将看到评估将从外到内开始。现在让我们将前面的`OuterFormula()`函数重构为`OuterFormulaNonStrict()`函数，如下面的代码所示：

```cs
public partial class Program 
{ 
  private static int OuterFormulaNonStrict( 
    int x, 
    Func<int, int, int> yzFunc) 
  { 
    int y = 3; 
    int z = 2; 
    Console.WriteLine( 
      String.Format( 
        "Calculate {0} + InnerFormula ({1})", 
        x, 
        y * z 
        )); 
    return x * yzFunc(3, 2); 
  } 
} 

```

正如您所看到的，我们将函数的第二个参数修改为`Func<int, int, int>`委托。我们将从`NonStrictEvaluation()`函数中调用`OuterFormulaNonStrict()`，如下所示：

```cs
public partial class Program 
{ 
  private static void NonStrictEvaluation() 
  { 
    int x = 4; 
    int y = 3; 
    int z = 2; 
    Console.WriteLine("Non-Strict Evaluation"); 
    Console.WriteLine( 
      String.Format( 
        "Calculate {0} + ({1} * {2})",x, y, z)); 
    int result = OuterFormulaNonStrict(x, InnerFormula); 
    Console.WriteLine( 
      String.Format( 
        "{0} + ({1} * {2}) = {3}",x, y, z, result)); 
    Console.WriteLine(); 
  } 
} 

```

在前面的代码中，我们可以看到我们将`InnerFormula()`函数传递给了`OuterFormulaNonStrict()`函数的第二个参数，如下面的代码片段所示：

```cs
int result = OuterFormulaNonStrict(x, InnerFormula); 

```

在前面的代码片段中，将使用非严格评估来评估表达式。为了证明这一点，让我们运行`NonStrictEvaluation()`函数，我们将在控制台上得到以下输出：

![非严格评估](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00098.jpg)

我们可以看到，我们的表达式是从外到内进行评估的。即使尚未检索到`InnerFormula()`函数的结果，也会首先运行`OuterFormulaNonStrict()`函数。如果我们连续运行`OuterFormula()`函数和`OuterFormulaNonStrict()`函数，我们将会清楚地看到评估顺序的不同，如下面的输出截图所示：

![非严格评估](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00099.jpg)

现在，我们可以比较一下。在严格评估中，首先运行`(3 * 2)`的计算，然后将其输入到`(4 + InnerFormula())`表达式中，而在非严格评估中，先运行`(4 + InnerFormula())`表达式，然后再计算`(3 * 2)`。

## 惰性初始化

延迟初始化是一种优化技术，其中对象的创建被推迟直到使用它。这意味着我们可以定义一个对象，但如果尚未访问对象的成员，则不会初始化该对象。C#在 C# 4.0 中引入了`Lazy<T>`类，我们可以使用它来延迟初始化对象。现在，让我们看一下下面的代码，以演示我们可以在`LazyInitialization.csproj`项目中找到的延迟初始化：

```cs
public partial class Program 
{ 
  private static void LazyInitName(string NameOfPerson) 
  { 
    Lazy<PersonName> pn = 
      new Lazy<PersonName>( 
        () => 
          new PersonName(NameOfPerson)); 
    Console.WriteLine( 
      "Status: PersonName has been defined."); 
    if (pn.IsValueCreated) 
    { 
      Console.WriteLine( 
        "Status: PersonName has been initialized."); 
    } 
    else 
    { 
      Console.WriteLine( 
        "Status: PersonName hasn't been initialized."); 
    } 
    Console.WriteLine( 
      String.Format( 
        "Status: PersonName.Name = {0}", 
        (pn.Value as PersonName).Name)); 
    if (pn.IsValueCreated) 
    { 
      Console.WriteLine( 
        "Status: PersonName has been initialized."); 
    } 
    else 
    { 
      Console.WriteLine( 
        "Status: PersonName hasn't been initialized."); 
    } 
  } 
} 

```

我们定义`PersonName`类如下：

```cs
public class PersonName 
{ 
  public string Name { get; set; } 
  public PersonName(string name) 
  { 
    Name = name; 
    Console.WriteLine( 
      "Status: PersonName constructor has been called." 
      ); 
  } 
} 

```

正如您在前面的`LazyInitName()`函数实现中所看到的，我们使用`Lazy<T>`类来延迟初始化`PersonName`对象，如下面的代码片段所示：

```cs
Lazy<PersonName> pn = 
  new Lazy<PersonName>( 
    () => 
      new PersonName(NameOfPerson)); 

```

通过这样做，`PersonName`在定义`pn`变量后实际上并没有初始化，就像我们直接使用以下代码定义类时通常得到的那样：

```cs
PersonName pn = 
  new PersonName( 
    NameOfPerson); 

```

相反，使用延迟初始化，我们访问对象的成员以初始化它，如前所述。`Lazy<T>`有一个名为`Value`的属性，用于获取`Lazy<T>`实例的值。它还有一个`IsValueCreated`属性，用于指示是否已为此`Lazy<T>`实例创建了值。在`LazyInitName()`函数中，我们使用`Value`属性，如下所示：

```cs
Console.WriteLine( 
  String.Format( 
    "Status: PersonName.Name = {0}", 
    (pn.Value as PersonName).Name)); 

```

我们使用`(pn.Value as PersonName).Name`来访问`pn`变量实例化的`PersonName`类的`Name`属性。我们使用`IsValueCreated`属性来证明`PersonName`类是否已经初始化，如下所示：

```cs
if (pn.IsValueCreated) 
{ 
  Console.WriteLine( 
    "Status: PersonName has been initialized."); 
} 
else 
{ 
  Console.WriteLine( 
    "Status: PersonName hasn't been initialized."); 
} 

```

现在让我们运行`LazyInitName()`函数，并将`Matthew Maxwell`作为其参数传递，如下所示：

```cs
LazyInitName("Matthew Maxwell"); 

```

我们将在控制台上获得以下输出：

![延迟初始化](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00100.jpg)

从前面的截图中，我们获得了五行信息。我们得到的第一行是在定义`PersonName`时。然后我们检查`IsValueCreated`属性的值，以找出`PersonName`是否已经初始化。我们得到了`FALSE`的结果，这意味着它还没有初始化；所以我们在控制台上得到了第二行信息。接下来的两行是我们从延迟初始化中得到的有趣的东西。当我们访问`Lazy<T>`类的`Value`属性以检索`PersonName`实例的`Name`属性时，代码在访问`PersonName`类的`Name`属性之前调用`PersonName`的构造函数。这就是为什么我们在前面的控制台上有第 3 行和第 4 行。在我们再次检查`IsValueCreated`属性之后，我们发现`PersonName`现在已经初始化，并且`pn`变量具有`PersonName`的实例。

## 懒惰的优缺点

到目前为止，我们已经了解了懒惰。我们还可以详细说明懒惰的优点，比如：

+   我们不需要为我们不使用的功能支付初始化时间

+   程序执行变得更加高效，因为有时，在功能性方法中，执行顺序与命令式方法相比并不重要

+   懒惰会使程序员通过编写高效的代码来编写更好的代码

除了优点之外，懒惰也有缺点，比如：

+   应用程序的流程很难预测，有时我们会失去对应用程序的控制

+   懒惰中的代码复杂性可能会导致簿记开销

# 缓存昂贵的资源

有时，我们必须在程序中创建昂贵的资源。如果我们只做一次，这不是问题。如果我们为同一个函数一遍又一遍地做同样的事情，那将是一个大问题。幸运的是，在功能性方法中，如果我们传递相同的输入或参数，我们将获得相同的输出。然后，我们可以缓存这些昂贵的资源，并在传递相同的参数时再次使用它。现在我们将讨论预计算和记忆化以缓存资源。

## 执行初始计算

我们拥有的缓存技术之一是预计算，它执行初始计算以创建查找表。当执行特定过程时，该查找表用于避免重复计算。现在我们将创建代码来比较使用和不使用预计算的过程中的差异。让我们看一下以下代码，在`Precomputation.csproj`项目中可以找到：

```cs
public partial class Program 
{ 
  private static void WithoutPrecomputation() 
  { 
    Console.WriteLine("WithoutPrecomputation()"); 
    Console.Write( 
      "Choose number from 0 to 99 twice "); 
    Console.WriteLine( 
      "to find the power of two result: "); 
    Console.Write("First Number: "); 
    int iInput1 = Convert.ToInt32(Console.ReadLine()); 
    Console.Write("Second Number: "); 
    int iInput2 = Convert.ToInt32(Console.ReadLine()); 
    int iOutput1 = (int) Math.Pow(iInput1, 2); 
    int iOutput2 = (int)Math.Pow(iInput2, 2); 
    Console.WriteLine( 
      "2 the power of {0} is {1}", 
      iInput1, 
      iOutput1); 
    Console.WriteLine( 
      "2 the power of {0} is {1}", 
      iInput2, 
      iOutput2); 
  } 
} 

```

前面简单的`WithoutPrecomputation()`函数将计算我们从 0 到 99 输入的两个数字的平方。假设我们要计算数字`19`和`85`，我们将在控制台窗口上获得以下输出：

![执行初始计算](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00101.jpg)

如您所见，该函数已经很好地完成了其工作。它使用以下代码片段向用户请求两个输入数字：

```cs
Console.Write("First Number: "); 
int iInput1 =Convert.ToInt32(Console.ReadLine()); 
Console.Write("Second Number: "); 
int iInput2 = Convert.ToInt32(Console.ReadLine()); 

```

它使用`System`命名空间中的“Math.Pow（）”方法来得到 n 的幂，如下面的代码片段所示：

```cs
int iOutput1 = (int) Math.Pow(iInput1, 2); 
int iOutput2 = (int)Math.Pow(iInput2, 2); 

```

我们可以重构“WithoutPrecomputation（）”函数，以使用预计算技术，这样每当用户要求计算相同数字的平方时，它就不需要重复计算。我们将要得到的函数如下：

```cs
public partial class Program 
{ 
  private static void WithPrecomputation() 
  { 
    int[]powerOfTwos = new int[100]; 
    for (int i = 0; i < 100; i++) 
    { 
      powerOfTwos[i] = (int)Math.Pow(i, 2); 
    } 
    Console.WriteLine("WithPrecomputation()"); 
    Console.Write( 
      "Choose number from 0 to 99 twice "); 
    Console.WriteLine( 
      "to find the power of two result: "); 
    Console.Write("First Number: "); 
    int iInput1 = Convert.ToInt32(Console.ReadLine()); 
    Console.Write("Second Number: "); 
    int iInput2 = Convert.ToInt32(Console.ReadLine()); 
    int iOutput1 = FindThePowerOfTwo(powerOfTwos, iInput1); 
    int iOutput2 = FindThePowerOfTwo(powerOfTwos, iInput2); 
    Console.WriteLine( 
      "2 the power of {0} is {1}", 
      iInput1, 
      iOutput1); 
    Console.WriteLine( 
      "2 the power of {0} is {1}", 
      iInput2, 
      iOutput2); 
  } 
} 

```

如前面的代码中所示，我们在函数开头创建了一个名为`powerOfTwos`的查找表，如下面的代码片段所示：

```cs
int[] powerOfTwos = new int[100]; 
for (int i = 0; i < 100; i++) 
{ 
  powerOfTwos[i] = (int)Math.Pow(i, 2); 
} 

```

由于我们要求用户输入 0 到 99 之间的数字，查找表将存储来自范围数字的两个数字的幂的数据库。此外，“WithPrecomputation（）”函数和“WithoutPrecomputation（）”函数之间的区别在于我们有了两个结果的集合。现在我们使用“FindThePowerOfTwo（）”函数，如下面的代码片段所示：

```cs
int iOutput1 = FindThePowerOfTwo(squares, iInput1); 
int iOutput2 = FindThePowerOfTwo(squares, iInput2); 

```

“FindThePowerOfTwo（）”函数将在查找表中查找所选数字，本例中为`powerOfTwos`。而“FindThePowerOfTwo（）”函数的实现将如下所示：

```cs
public partial class Program 
{ 
  private static int FindThePowerOfTwo ( 
    int[] precomputeData, 
    int baseNumber) 
  { 
    return precomputeData[baseNumber]; 
  } 
} 

```

如您所见，“FindThePowerOfTwo（）”函数返回我们用`baseNumber`参数指定的查找表的值。如果我们运行“WithPrecomputation（）”函数，我们将在控制台上获得以下输出：

![执行初始计算](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00102.jpg)

再次计算`19`和`85`的平方，确实，我们得到的结果与运行“WithoutPrecomputation（）”函数时得到的完全相同。现在，我们有了一个从 0 到 99 的平方数查找表。我们程序中的优势更加有效，因为每次我们要求计算相同的数字（`19`和`85`）时，它都不需要运行计算，而是会在查找表中查找结果。

然而，我们之前探讨的预计算代码并不是一种功能性方法，因为每次调用“FindThePowerOfTwo（）”函数时，它都会再次迭代平方。我们可以重构它，使其在使用柯里化的幂的情况下变得功能性，这是一种通过顺序更改结构参数的技术，我们在第一章中讨论过，*在 C#中品尝函数式风格*。现在让我们看一下以下代码：

```cs
public partial class Program 
{ 
  private static void WithPrecomputationFunctional() 
  { 
    int[]powerOfTwos = new int[100]; 
    for (int i = 0; i < 100; i++) 
    { 
      powerOfTwos[i] = (int) Math.Pow(i, 2); 
    } 
    Console.WriteLine("WithPrecomputationFunctional()"); 
    Console.Write( 
      "Choose number from 0 to 99 twice "); 
    Console.WriteLine( 
      "to find the power of two result: "); 
    Console.Write("First Number: "); 
    int iInput1 = Convert.ToInt32(Console.ReadLine()); 
    Console.Write("Second Number: "); 
    int iInput2 = Convert.ToInt32(Console.ReadLine()); 
    var curried = CurriedPowerOfTwo(powerOfTwos); 
    int iOutput1 = curried(iInput1); 
    int iOutput2 = curried(iInput2); 
    Console.WriteLine( 
      "2 the power of {0} is {1}", 
      iInput1, 
      iOutput1); 
    Console.WriteLine( 
      "2 the power of {0} is {1}", 
      iInput2, 
      iOutput2); 
  } 
} 

```

如果我们将前面的“WithPrecomputationFunctional（）”函数与“WithPrecomputation（）”函数进行比较，我们可以看到它现在使用了“CurriedPowerOfTwo（）”函数，如下面的代码片段所示：

```cs
var curried = CurriedSquare(squares); 
int iOutput1 = curried(iInput1); 
int iOutput2 = curried(iInput2); 

```

使用“CurriedPowerOfTwo（）”函数，我们分割函数参数，以便柯里化变量现在可以处理查找表，并且我们可以随意调用“WithPrecomputationFunctional（）”函数，而无需再次迭代查找表。以下代码中可以找到“CurriedPowerOfTwo（）”函数的实现：

```cs
public partial class Program 
{ 
  public static Func<int, int> 
  CurriedPowerOfTwo(int[] intArray) 
      => i => intArray[i]; 
} 

```

如果我们运行“WithPrecomputationFunctional（）”函数，我们的控制台窗口将显示以下输出：

![执行初始计算](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00103.jpg)

再次，与我们之前的函数“WithoutPrecomputation（）”函数和“WithPrecomputation（）”函数相比，我们得到了完全相同的输出。我们已成功重构了函数，并且在这种预计算技术中已实现了功能性方法。

## 备忘录化

除了执行预计算技术来优化代码之外，我们还可以使用记忆化技术使我们的代码更加优化。记忆化是记住具有特定输入的函数的结果的过程。每次我们用特定的输入参数执行特定的函数时，代码都会记住结果。因此，每次我们再次使用完全相同的输入参数调用函数时，代码就不需要运行代码了；相反。它将从存储结果的位置获取结果。

让我们借用我们在第五章中讨论的重复的`GetFactorial()`函数，*使用 LINQ 轻松查询任何集合*，然后重构它以使用记忆化技术。正如我们所知，`GetFactorial()`函数的实现如下：

```cs
public partial class Program 
{ 
  private static int GetFactorial(int intNumber) 
  { 
    if (intNumber == 0) 
    { 
      return 1; 
    } 
    return intNumber * GetFactorial(intNumber - 1); 
  } 
} 

```

要使`GetFactorial()`函数使用记忆化，我们必须在`GetFactorial()`函数返回值时保存结果。前面的`GetFactorial()`函数的重构代码将如下所示，并且我们可以在`Memoization.csproj`项目中找到它：

```cs
public partial class Program 
{ 
  private static Dictionary<int, int> 
    memoizeDict = new Dictionary<int, int>(); 
  private static int GetFactorialMemoization(int intNumber) 
  { 
    if (intNumber == 0) 
    { 
      return 1; 
    } 
    if (memoizeDict.ContainsKey(intNumber)) 
    { 
      return memoizeDict[intNumber]; 
    } 
    int i = intNumber * GetFactorialMemoization( 
      intNumber - 1); 
    memoizeDict.Add(intNumber, i); 
    return i; 
  } 
} 

```

正如您所看到的，我们有一个名为`memoizeDict`的`Dictionary`类，用于存储当特定参数传递给`GetFactorialMemoization()`函数时的所有结果。该字典的定义如下代码片段所示：

```cs
private static Dictionary<int, int> 
  memoizeDict = new Dictionary<int, int>(); 

```

与`GetFactorial()`函数相比，`GetFactorialMemoization()`函数的另一个区别是，当迄今为止已调用具有特定参数的`GetFactorialMemoization()`函数时，它现在保存结果。以下代码片段显示了此算法的代码：

```cs
private static int GetFactorialMemoization(int intNumber) 
{ 
  if (intNumber == 0) 
  { 
    return 1; 
  } 
  if (memoizeDict.ContainsKey(intNumber)) 
  { 
    return memoizeDict[intNumber]; 
  } 
  int i = intNumber * GetFactorialMemoization( 
    intNumber - 1); 
  memoizeDict.Add(intNumber, i); 
  return i; 
} 

```

首先，我们检查特定参数是否已传递给函数。如果是，它就不需要运行函数；相反，它只需从字典中检索结果。如果参数尚未传递，函数将运行，并且我们将结果保存在字典中。使用记忆化，我们可以优化代码，因为如果参数完全相同，我们就不需要一遍又一遍地运行函数。假设我们将 10 传递给`GetFactorialMemoization()`函数。如果我们再次运行函数并再次传递 10，处理速度将增加，因为它不需要运行重复的`GetFactorialMemoization()`函数。幸运的是，通过将 10 传递给函数参数，它还将使用 1-9 参数运行函数，因为它是一个递归函数。这 10 个项目的调用效果和结果将保存在目录中，并且使用这些参数调用函数将更快。

现在让我们比较`GetFactorial()`函数与`GetFactorialMemoization()`函数的性能。我们将传递`9216`作为参数，并运行它们。以下是用于调用`GetFactorial()`函数的`RunFactorial()`函数：

```cs
public partial class Program 
{ 
  private static void RunFactorial() 
  { 
    Stopwatch sw = new Stopwatch(); 
    int factorialResult = 0; 
    Console.WriteLine( 
      "RunFactorial() function is called"); 
    Console.WriteLine( 
      "Get factorial of 9216"); 
    for (int i = 1; i <= 5; i++) 
    { 
      sw.Restart(); 
      factorialResult = GetFactorial(9216); 
      sw.Stop(); 
      Console.WriteLine( 
        "Time elapsed ({0}): {1,8} ns", 
        i, 
        sw.ElapsedTicks * 
          1000000000 / 
          Stopwatch.Frequency); 
    } 
  } 
} 

```

如果我们运行`RunFactorial()`函数，我们将在控制台上得到以下输出：

![Memoization](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00104.jpg)

从输出中可以看出，在第一次调用`GetFactorial()`函数时，我们需要`281461 ns`，而在剩下的调用中需要大约 75,000-98,000 纳秒。由于递归的`GetFactorial()`函数每次都被调用，所有调用的进程速度几乎相同。现在让我们继续执行以下`RunFactorialMemoization()`函数，以调用`GetFactorialMemoization()`函数：

```cs
public partial class Program 
{ 
  private static void RunFactorialMemoization() 
  { 
    Stopwatch sw = new Stopwatch(); 
    int factorialResult = 0; 
    Console.WriteLine( 
      "RunFactorialMemoization() function is called"); 
    Console.WriteLine( 
      "Get factorial of 9216"); 
    for (int i = 1; i <= 5; i++) 
    { 
      sw.Restart(); 
      factorialResult = GetFactorialMemoization(9216); 
      sw.Stop(); 
      Console.WriteLine( 
        "Time elapsed ({0}): {1,8} ns", 
        i, 
        sw.ElapsedTicks * 
          1000000000 / 
          Stopwatch.Frequency); 
    } 
  } 
} 

```

如果我们运行`RunFactorialMemoization()`函数，我们将在控制台上得到以下输出：

![Memoization](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00105.jpg)

现在我们可以看到，通过使用记忆化，进程速度已经大大提高。即使在第一次调用`GetFactorialMemoization()`时需要额外的时间，在第 3 到 5 次调用时，进程变得更快。

# 摘要

我们讨论了通过懒惰可以创建高效的代码。懒惰枚举在需要迭代无限循环时非常有用，这样就不会溢出，因为`IEnumerator`中的`MoveNext()`方法只有在被要求时才会运行。此外，懒惰评估使我们的代码运行更快，因为编译器不需要检查所有布尔表达式，如果其中一个已经给出结果。

在非严格评估中，我们将编程中的函数视为数学函数。使用这种评估技术，我们使用函数方法来解决函数。

我们还熟悉了`Lazy<T>`类提供的延迟初始化，这意味着我们可以定义一个对象，但如果尚未访问对象的成员，则不会初始化该对象。

为了优化我们的代码，我们讨论了使用预计算和记忆化的缓存技术。在预计算中，我们准备了类似查找表的东西，这样我们就不需要用精确的参数运行函数；相反，我们只需要从表中获取结果。我们还有记忆化，以记住具有特定输入的函数的结果。使用记忆化，每次我们再次使用完全相同的输入参数调用函数时，代码就不需要再次运行代码；相反，它将从存储结果的地方获取结果。

在下一章中，我们将讨论单子及其在函数式编程中的使用。
