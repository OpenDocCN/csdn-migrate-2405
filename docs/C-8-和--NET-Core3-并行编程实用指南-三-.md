# C#8 和 .NET Core3 并行编程实用指南（三）

> 原文：[`zh.annas-archive.org/md5/BE48315910DEF416E754F7470D0341EA`](https://zh.annas-archive.org/md5/BE48315910DEF416E754F7470D0341EA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用懒惰初始化提高性能

在上一章中，我们讨论了 C#中线程安全的并发集合。并发集合有助于提高并行代码的性能，而不需要开发人员担心同步开销。

在本章中，我们将讨论一些更多的概念，这些概念有助于改善代码的性能，既可以使用自定义实现，也可以使用内置结构。以下是本章将讨论的主题：

+   懒惰初始化概念介绍

+   介绍`System.Lazy<T>`

+   如何处理懒惰模式下的异常

+   使用线程本地存储进行懒惰初始化

+   通过懒惰初始化减少开销

让我们通过引入懒惰初始化模式开始。

# 技术要求

读者应该对 TPL 和 C#有很好的理解。本章的源代码可在 GitHub 上找到：[`github.com/PacktPublishing/-Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter07`](https://github.com/PacktPublishing/-Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter07)。

# 介绍懒惰初始化概念

懒加载是应用程序编程中常用的设计模式，其中我们推迟对象的创建，直到在应用程序中实际需要它。正确使用懒加载模式可以显著提高应用程序的性能。

这种模式的常见用法之一可以在缓存旁路模式中看到。我们使用缓存旁路模式来创建对象，这些对象的创建在资源或内存方面都很昂贵。我们不是多次创建它们，而是创建一次并将它们缓存以供将来使用。当对象的初始化从构造函数移动到方法或属性时，这种模式就成为可能。只有在代码首次调用方法或属性时，对象才会被初始化。然后它将被缓存以供后续调用。看一下以下代码示例，它在构造函数中初始化底层数据成员：

```cs
 class _1Eager
 {
     //Declare a private variable to hold data
     Data _cachedData;
     public _1Eager()
     {
         //Load data as soon as object is created
         _cachedData = GetDataFromDatabase();
     }
     public Data GetOrCreate()
     {
         return _cachedData;
     }
     //Create a dummy data object every time this method gets called
     private Data GetDataFromDatabase()
     {
         //Dummy Delay
         Thread.Sleep(5000);
         return new Data();
     }
 }

```

前面的代码问题在于，即使只有通过调用`GetOrCreate()`方法才能访问底层对象，但底层数据在对象创建时就被初始化了。在某些情况下，程序甚至可能不会调用该方法，因此会浪费内存。

懒加载可以完全使用自定义代码实现，如下面的代码示例所示：

```cs
 class _2SimpleLazy
 {
    //Declare a private variable to hold data
     Data _cachedData;

     public _2SimpleLazy()
     {
         //Removed initialization logic from constructor
         Console.WriteLine("Constructor called");
     }

     public Data GetOrCreate()
     {
         //Check is data is null else create and store for later use
         if (_cachedData == null)
         {
             Console.WriteLine("Initializing object");
             _cachedData = GetDataFromDatabase();
         }        
         Console.WriteLine("Data returned from cache");
         //Returns cached data
         return _cachedData;
     }

     private Data GetDataFromDatabase()
     {
         //Dummy Delay
         Thread.Sleep(5000);
         return new Data();
     }
 }
```

从前面的代码中可以看出，我们将初始化逻辑从构造函数移出到`GetOrCreate()`方法中，该方法在返回给调用者之前检查项目是否在缓存中。如果缓存中不存在，数据将被初始化。

以下是调用前面方法的代码：

```cs
public static void Main(){
    _2SimpleLazy lazy = new _2SimpleLazy();
     var data = lazy.GetOrCreate();
     data = lazy.GetOrCreate();
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/faf9b818-9c45-4d43-934f-72ff2a95e511.png)

前面的代码虽然懒惰，但可能存在多重加载的问题。这意味着如果多个线程同时调用`GetOrCreate()`方法，数据库的调用可能会运行多次。

可以通过引入锁定来改进，如下面的代码示例所示。对于缓存旁路模式，使用另一种模式，双重检查锁定，是有意义的：

```cs
 class _2ThreadSafeSimpleLazy
 {
     Data _cachedData;
     static object _locker = new object();

     public Data GetOrCreate()
     {
         //Try to Load cached data
         var data = _cachedData;
         //If data not created yet
         if (data == null)
         {
             //Lock the shared resource
             lock (_locker)
             {
                 //Second try to load data from cache as it might have been 
                 //populate by another thread while current thread was 
                 // waiting for lock
                 data = _cachedData;
                 //If Data not cached yet
                 if (data == null)
                 {
                     //Load data from database and cache for later use
                     data = GetDataFromDatabase();
                     _cachedData = data;
                 }
             }
         }
         return _cachedData;
     }

     private Data GetDataFromDatabase()
     {
         //Dummy Delay
         Thread.Sleep(5000);
         return new Data();
     }
     public void ResetCache()
     {
         _cachedData = null;
     }
 }

```

前面的代码是自解释的。我们可以看到从头开始创建懒惰模式是复杂的。幸运的是，.NET Framework 提供了懒惰模式的数据结构。

# 引入 System.Lazy<T>

.NET Framework 提供了`System.Lazy<T>`类，具有懒惰初始化的所有好处，而无需担心同步开销。使用`System.Lazy<T>`创建的对象直到首次访问时才被延迟创建。通过前面部分解释的自定义懒惰代码，我们可以看到，我们将初始化部分从构造函数移动到方法/属性以支持懒惰初始化。使用`Lazy<T>`，我们不需要修改任何代码。

在 C#中有多种实现延迟初始化模式的方法。其中包括以下内容：

+   封装在构造函数中的构造逻辑

+   将构造逻辑作为委托传递给`Lazy<T>`

在接下来的部分，我们将深入了解这些情景。

# 封装在构造函数中的构造逻辑

让我们首先尝试使用封装构造逻辑的类来实现延迟初始化模式。假设我们有一个`Data`类：

```cs
 class DataWrapper
 {
     public DataWrapper()
     {
         CachedData = GetDataFromDatabase();
         Console.WriteLine("Object initialized");
     }
     public Data CachedData { get; set; }
     private Data GetDataFromDatabase()
     {
         //Dummy Delay
         Thread.Sleep(5000);
         return new Data();
     }
 }
```

如您所见，初始化发生在构造函数内部。如果我们正常使用这个类，使用以下代码，对象在创建`DataWrapper`对象时被初始化：

```cs
 DataWrapper dataWrapper = new DataWrapper();

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/10b3be2a-9ff6-4517-b948-a390238f9752.png)

可以使用`Lazy<T>`将上述代码转换如下：

```cs
 Console.WriteLine("Creating Lazy object");
 Lazy<DataWrapper> lazyDataWrapper = new Lazy<DataWrapper>();
 Console.WriteLine("Lazy Object Created");
 Console.WriteLine("Now we want to access data");
 var data = lazyDataWrapper.Value.CachedData;
 Console.WriteLine("Finishing up");
```

如您所见，我们将对象包装在延迟类中，而不是直接创建对象。在访问`Lazy`对象的`Value`属性之前，构造函数不会被调用，如下面的输出所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/c95f76e1-5465-41e6-b32b-742810896655.png)

# 将构造逻辑作为委托传递给 Lazy<T>

对象通常不包含构造逻辑，因为它们只是简单的数据模型。我们需要在首次访问延迟对象时获取数据，同时还要传递获取数据的逻辑。这可以通过`System.Lazy<T>`的另一个重载来实现，如下所示：

```cs
 class _5LazyUsingDelegate
 {
     public Data CachedData { get; set; }
     static Data GetDataFromDatabase()
     {
         Console.WriteLine("Fetching data");
         //Dummy Delay
         Thread.Sleep(5000);
         return new Data();
     }
 }
```

在以下代码中，我们通过传递`Func<Data>`委托来创建一个`Lazy<Data>`对象：

```cs
 Console.WriteLine("Creating Lazy object");
 Func<Data> dataFetchLogic = new Func<Data>(()=> GetDataFromDatabase());
 Lazy<Data> lazyDataWrapper = new Lazy<Data>(dataFetchLogic);
 Console.WriteLine("Lazy Object Created");
 Console.WriteLine("Now we want to access data");
 var data = lazyDataWrapper.Value;
 Console.WriteLine("Finishing up");
```

从上面的代码中可以看出，我们将`Func<T>`传递给`Lazy<T>`构造函数。逻辑在第一次访问`Lazy<T>`实例的`Value`属性时被调用，如下面的输出所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/b0b1007b-a213-4b55-93ed-3b66ef79176e.png)

除了对.NET 中的延迟对象进行构造和使用有一个好的理解之外，我们还需要了解如何处理延迟初始化模式中的异常！让我们看看下一节。

# 使用延迟初始化模式处理异常

Lazy 对象是不可变的。这意味着它们总是返回与初始化时相同的实例。我们已经看到可以将初始化逻辑传递给`Lazy<T>`，并且可以在底层对象的构造函数中有初始化逻辑。如果构造/初始化逻辑有错误并抛出异常会发生什么？在这种情况下，`Lazy<T>`的行为取决于`LazyThreadSafetyMode`枚举的值和您选择的`Lazy<T>`构造函数。在使用延迟模式时，有许多处理异常的方法。其中一些如下：

+   在初始化过程中不会发生异常

+   在异常缓存的情况下进行初始化时发生随机异常

+   不缓存异常

在接下来的部分，我们将深入了解这些情景。

# 在初始化过程中不会发生异常

初始化逻辑只运行一次，并且对象被缓存以便在后续访问`Value`属性时返回。我们在前面的部分已经看到了这种行为，解释了`Lazy<T>`。

# 在异常缓存的情况下进行初始化时发生随机异常

在这种情况下，由于底层对象没有被创建，所以初始化逻辑将在每次调用`Value`属性时运行。这在构造逻辑依赖于外部因素（如调用外部服务时的互联网连接）的情况下非常有用。如果互联网暂时中断，那么初始化调用将失败，但后续调用可以返回数据。默认情况下，`Lazy<T>`将为所有带参数的构造函数实现缓存异常，但不会为不带参数的构造函数实现缓存异常。

让我们尝试理解当`Lazy<T>`初始化逻辑抛出随机异常时会发生什么：

1.  首先，我们使用`GetDataFromDatabase()`函数提供的初始化逻辑创建`Lazy<Data>`，如下所示：

```cs
Func<Data> dataFetchLogic = new Func<Data>(() => GetDataFromDatabase());
Lazy<Data> lazyDataWrapper = new Lazy<Data>(dataFetchLogic);
```

1.  接下来，我们访问`Lazy<Data>`的`Value`属性，这将执行初始化逻辑并抛出异常，因为计数器的值为`0`：

```cs
 try
 {
     data = lazyDataWrapper.Value;
     Console.WriteLine("Data Fetched on Attempt 1");
 }
 catch (Exception)
 {
     Console.WriteLine("Exception 1");
 }
```

1.  接下来，我们将计数器加一，然后再次尝试访问`Value`属性。根据逻辑，这次应该返回`Data`对象，但我们看到代码再次抛出异常：

```cs
 class _6_1_ExceptionsWithLazyWithCaching
 {
     static int counter = 0;
     public Data CachedData { get; set; }
     static Data GetDataFromDatabase()
     {
         if ( counter == 0)
         {
             Console.WriteLine("Throwing exception");
             throw new Exception("Some Error has occurred");
         }
         else
         {
             return new Data();
         }
     }

     public static void Main()
     {
         Console.WriteLine("Creating Lazy object");
         Func<Data> dataFetchLogic = new Func<Data>(() => 
          GetDataFromDatabase());
         Lazy<Data> lazyDataWrapper = new 
          Lazy<Data>(dataFetchLogic);
         Console.WriteLine("Lazy Object Created");
         Console.WriteLine("Now we want to access data");
         Data data = null;
         try
         {
             data = lazyDataWrapper.Value;
             Console.WriteLine("Data Fetched on Attempt 1");
         }
         catch (Exception)
         {
             Console.WriteLine("Exception 1");
         }
         try
         {
             counter++;
             data = lazyDataWrapper.Value;
             Console.WriteLine("Data Fetched on Attempt 1");
         }
         catch (Exception)
         {
             Console.WriteLine("Exception 2");
             // throw;
         }
         Console.WriteLine("Finishing up");
         Console.ReadLine();
     }
 }
```

如您所见，即使我们将计数器增加了一次，异常仍然被抛出第二次。这是因为异常值被缓存，并在下次访问`Value`属性时返回。输出如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/1dd3d59a-bef7-47ac-8e3c-522c395924db.png)

上述行为与通过将`System.Threading.LazyThreadSafetyMode.None`作为第二个参数创建`Lazy<T>`相同：

```cs
Lazy<Data> lazyDataWrapper = new Lazy<Data>(dataFetchLogic,System.Threading.LazyThreadSafetyMode.None);
```

# 不缓存异常

让我们将上述代码中`Lazy<Data>`的初始化更改为以下内容：

```cs
Lazy<Data> lazyDataWrapper = new Lazy<Data>(dataFetchLogic,System.Threading.LazyThreadSafetyMode.PublicationOnly);

```

这将允许初始化逻辑在不同线程中多次运行，直到其中一个线程成功运行初始化而没有任何错误。如果在多线程场景中的初始化过程中任何线程抛出错误，则由已完成的线程创建的基础对象的所有实例都将被丢弃，并且异常将传播到`Value`属性。在单线程的情况下，当再次访问`Value`属性时，初始化逻辑重新运行时会返回异常。异常不会被缓存。

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/4570a390-8e22-42d4-945b-8f097b577765.png)

在了解了延迟初始化模式处理异常的方法之后，现在让我们学习一下使用线程本地存储进行延迟初始化。

# 使用线程本地存储进行延迟初始化

在多线程编程中，我们经常希望创建一个局部于线程的变量，这意味着每个线程都将拥有数据的自己的副本。这对于所有局部变量都成立，但全局变量始终在各个线程之间共享。在旧版本的.NET 中，我们使用`ThreadStatic`属性使静态变量表现为线程本地变量。然而，这并不是绝对可靠的，并且在初始化方面效果不佳。如果我们初始化一个`ThreadStatic`变量，那么只有第一个线程获得初始化的值，而其余线程获得变量的默认值，在整数的情况下为 0。可以使用以下代码进行演示：

```cs
 [ThreadStatic]
 static int counter = 1;
 public static void Main()
 {
     for (int i = 0; i < 10; i++)
     {
         Task.Factory.StartNew(() => Console.WriteLine(counter));
     }
     Console.ReadLine();
 }

```

在上面的代码中，我们使用值为`1`的静态`counter`变量进行初始化，并将其线程静态化，以便每个线程都可以拥有自己的副本。为了演示目的，我们创建了 10 个任务，打印计数器的值。根据逻辑，所有线程应该打印 1，但如下输出所示，只有一个线程打印 1，其余线程打印 0：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/dcd89412-e4cb-4589-b82e-fc44809811c3.png)

.NET Framework 4 提供了`System.Threading.ThreadLocal<T>`作为`ThreadStatic`的替代方案，并且更像`Lazy<T>`。使用`ThreadLocal<T>`，我们可以创建一个可以通过传递初始化函数进行初始化的线程本地变量，如下所示：

```cs
 static ThreadLocal<int> counter = new ThreadLocal<int>(() => 1);
 public static void Main()
 {
     for (int i = 0; i < 10; i++)
     {
         Task.Factory.StartNew(() => Console.WriteLine($"Thread with 
          id {Task.CurrentId} has counter value as {counter.Value}"));
     }
     Console.ReadLine();
 }
```

输出如预期的那样：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/9dcdd5eb-679d-4f1a-a805-70f919680586.png)

`Lazy<T>`和`ThreadLocal<T>`之间的区别如下：

+   每个线程都使用自己的私有数据初始化`ThreadLocal`变量，而在`Lazy<T>`的情况下，初始化逻辑只运行一次。

+   与`Lazy<T>`不同，`ThreadLocal<T>`中的`Value`属性是可读/写的。

+   在没有任何初始化逻辑的情况下，默认值`T`将被分配给`ThreadLocal`变量。

# 通过延迟初始化减少开销

`Lazy<T>`通过包装底层对象使用了一定程度的间接性。这可能会导致计算和内存问题。为了避免包装对象，我们可以使用`Lazy<T>`类的静态变体，即`LazyInitializer`类。

我们可以使用`LazyInitializer.EnsureInitialized`来初始化通过引用传递的数据成员以及初始化函数，就像我们使用`Lazy<T>`一样。

该方法可以通过多个线程调用，但一旦值被初始化，它将作为所有线程的结果使用。为了演示起见，我在初始化逻辑中添加了一行到控制台。虽然循环运行 10 次，但初始化将仅在单线程执行一次：

```cs
 static Data _data;
 public static void Main()
 {
     for (int i = 0; i < 10; i++)
     {
         Console.WriteLine($"Iteration {i}");
         // Lazily initialize _data
         LazyInitializer.EnsureInitialized(ref _data, () =>
         {
             Console.WriteLine("Initializing data");
             // Returns value that will be assigned in the ref parameter.
             return new Data();
         });
     }
     Console.ReadLine();
 }
```

以下是输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/d3ec9d21-2259-45d7-9a8b-bfb5f6bf8355.png)

这对于顺序执行是很好的。让我们尝试修改代码并通过多个线程运行它：

```cs
static Data _data;
static void Initializer()
{
     LazyInitializer.EnsureInitialized(ref _data, () =>
     {
         Console.WriteLine($"Task with id {Task.CurrentId} is 
          Initializing data");
         // Returns value that will be assigned in the ref parameter.
         return new Data();
     });

    public static void Main()
     {
         Parallel.For(0, 10, (i) => Initializer());
         Console.ReadLine();
     }
}
```

以下是输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/6585d753-f0d7-47f2-a557-44db26b953d8.png)

如您所见，使用多个线程会出现竞争条件，所有线程最终都会初始化数据。我们可以通过修改程序来避免这种竞争条件：

```cs
 static Data _data;
 static bool _initialized;
 static object _locker = new object();
 static void Initializer()
 {
     Console.WriteLine("Task with id {0}", Task.CurrentId);
     LazyInitializer.EnsureInitialized(ref _data,ref _initialized, 
      ref _locker, () =>
     {
         Console.WriteLine($"Task with id {Task.CurrentId} is 
          Initializing data");
         // Returns value that will be assigned in the ref parameter.
         return new Data();
     });
 }
 public static void Main()
 {
     Parallel.For(0, 10, (i) => Initializer());
     Console.ReadLine();
 }
```

从上面的代码中可以看出，我们使用了`EnsureInitialized`方法的一个重载，并传递了一个布尔变量和一个`SyncLock`对象作为参数。这将确保初始化逻辑只能由一个线程执行，如下面的输出所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/ca623fb2-493a-4413-b709-f6e1202bd876.png)

在本节中，我们讨论了如何通过利用另一个内置的静态变体`Lazy<T>`，即`LazyInitializer`类，来解决与`Lazy<T>`相关的开销问题。

# 总结

在本章中，我们讨论了延迟加载的各个方面，以及.NET Framework 提供的数据结构，使延迟加载更容易实现。

延迟加载可以通过减少内存占用和节省计算资源来显著提高应用程序的性能，因为它可以阻止重复初始化。我们可以选择使用`Lazy<T>`从头开始创建延迟加载，也可以使用静态的`LazyInitializer`类来避免复杂性。通过最佳的线程存储使用和良好的异常处理逻辑，这些工具对开发人员来说确实是很好的工具。

在下一章中，我们将开始讨论 C#中可用的异步编程方法。

# 问题

1.  延迟初始化总是涉及在构造函数中创建对象。

1.  True

1.  False

1.  在延迟初始化模式中，对象的创建被推迟，直到实际需要它。

1.  True

1.  False

1.  哪个选项可以用来创建不缓存异常的延迟对象？

1.  `LazyThreadSafetyMode.DoNotCacheException`

1.  `LazyThreadSafetyMode.PublicationOnly`

1.  哪个属性可以用来创建一个只对线程本地的变量？

1.  `ThreadLocal`

1.  `ThreadStatic`

1.  两者


# 第三部分：使用 C#进行异步编程

在本节中，您将了解到另一个重要的方面，即如何使用异步编程技术制作高性能程序，同时关注早期版本与新的`async`和`await`构造方式的差异。

本节包括以下章节：

+   第八章，*异步编程简介*

+   第九章，*异步、等待和基于任务的异步编程基础*


# 第八章：异步编程简介

在之前的章节中，我们已经看到并行编程是如何工作的。并行性是关于创建称为工作单元的小任务，可以由一个或多个应用程序线程同时执行。由于线程在应用程序进程内运行，它们在使用委托通知调用线程完成后通知调用线程。

在本章中，我们将首先介绍同步代码和异步代码之间的区别。然后，我们将讨论何时使用异步代码以及何时避免使用它。我们还将讨论异步模式如何随时间演变。最后，我们将看到并行编程中的新特性如何帮助我们解决异步代码的复杂性。

在本章中，我们将涵盖以下主题：

+   同步与异步代码

+   何时使用异步编程

+   何时避免异步编程

+   使用异步代码可以解决的问题

+   C#早期版本中的异步模式

# 技术要求

要完成本章，您应该对 TPL 和 C#有很好的理解。本章的源代码可在 GitHub 上找到[`github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter08`](https://github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter08)。

# 程序执行的类型

在任何时刻，程序流程可以是同步的，也可以是异步的。同步代码编写和维护更容易，但会带来性能开销和 UI 响应性问题。异步代码可以提高整个应用程序的性能和响应性，但反过来，编写、调试和维护都更加困难。

我们将在以下子章节中详细了解程序执行的同步和异步方式。

# 理解同步程序执行

在同步执行的情况下，控制永远不会移出调用线程。代码一次执行一行，当调用函数时，调用线程会等待函数执行完成后再执行下一行代码。同步编程是最常用的编程方法，由于过去几年 CPU 性能的提高，它运行良好。随着处理器速度更快，代码完成得更快。

通过并行编程，我们已经看到可以创建多个可以并发运行的线程。我们可以启动许多线程，但也可以通过调用`Thread.Join`和`Task.Wait`等结构使主程序流程同步。让我们看一个同步代码的例子：

1.  我们通过调用`M1()`方法启动应用程序线程。

1.  在第 3 行，`M1()`同步调用`M3()`。

1.  调用`M2()`方法的时刻，控制执行转移到`M1()`方法。

1.  一旦被调用的方法（`M2`）完成，控制返回到主线程，执行`M1()`中的其余代码，即第 4 和第 5 行。

1.  在第 5 行对`M2`的调用也是同样的情况。当`M2`完成时，第 6 行执行。

以下是同步代码执行的图解表示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/f5a8b41e-6fed-47f0-a470-48987bd9688d.png)

在接下来的部分，我们将尝试更多地了解编写异步代码，这将帮助我们比较两种程序流程。

# 理解异步程序执行

异步模型允许我们同时执行多个任务。如果我们异步调用一个方法，该方法将在后台执行，而调用的线程立即返回并执行下一行代码。异步方法可能会创建线程，也可能不会，这取决于我们处理的任务类型。当异步方法完成时，它通过回调将结果返回给程序。异步方法可以是 void，这种情况下我们不需要指定回调。

以下是一个图表，显示了一个调用者线程执行`M1()`方法，该方法调用了一个名为`M2()`的异步方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/79ed2091-8666-497a-b56e-5f3c30bb189a.png)

与以前的方法相反，在这里，调用者线程不等待`M2()`完成。如果需要利用`M2()`的任何输出，需要将其放入其他方法，比如`M3()`。这是发生的事情：

1.  在执行`M1()`时，调用者线程对`M2()`进行异步调用。

1.  调用者线程在调用`M2()`时提供回调函数，比如`M3()`。

1.  调用者线程不等待`M2()`完成，而是完成`M1()`中的其余代码（如果有的话）。

1.  `M2()`将由 CPU 立即在一个单独的线程中执行，或者在以后的某个日期执行。

1.  一旦`M2()`完成，将调用`M3()`，`M3()`接收来自`M2()`的输出并对其进行处理。

正如您所看到的，理解同步程序的执行很容易，而异步代码则带有代码分支。我们将学习如何使用`async`和`await`关键字在第九章中减轻这种复杂性，*异步、等待和基于任务的异步编程基础*。

# 何时使用异步编程

有许多情况下会使用**直接内存访问**（**DMA**）来访问主机系统或进行 I/O 操作（如文件、数据库或网络访问），这是 CPU 而不是应用程序线程进行处理。在前面的情况下，调用线程调用 I/O API 并等待任务完成，从而进入阻塞状态。当 CPU 完成任务时，线程将解除阻塞并完成方法的其余部分。

使用异步方法，我们可以提高应用程序的性能和响应能力。我们还可以通过不同的线程执行一个方法。

# 编写异步代码

异步编程对 C#来说并不是什么新鲜事。我们过去在较早版本的 C#中使用`Delegate`类的`BeginInvoke`方法以及使用`IAsyncResult`接口实现来编写异步代码。随着 TPL 的引入，我们开始使用`Task`类编写异步代码。从 C# 5.0 开始，开发人员编写异步代码的首选选择是使用`async`和`await`关键字。

我们可以以以下方式编写异步代码：

+   使用`Delegate.BeginInvoke()`方法

+   使用`Task`类

+   使用`IAsyncResult`接口

+   使用`async`和`await`关键字

在接下来的章节中，我们将通过代码示例详细讨论每个内容，除了`async`和`await`关键字 - 第九章专门讨论它们！

# 使用 Delegate 类的 BeginInvoke 方法

在.NET Core 中不再支持使用`Delegate.BeginInvoke`，但是我们将在这里讨论它，以便与较早版本的.NET 向后兼容。

我们可以使用`Delegate.BeginInvoke`方法异步调用任何方法。如果需要将一些任务从 UI 线程移动到后台以提高 UI 的性能，可以这样做。

让我们以`Log`方法为例。以下代码以同步方式工作并写入日志。为了演示，日志记录代码已被删除，并替换为一个虚拟的 5 秒延迟，之后`Log`方法将在控制台打印一行：

这是一个虚拟的`Log`方法，需要 5 秒才能完成：

```cs
private static void Log(string message)
{
    //Simulate long running method
    Thread.Sleep(5000);
    //Log to file or database
    Console.WriteLine("Logging done");
}
```

这是从`Main`方法调用`Log`方法：

```cs
  static void Main(string[] args)
  {
     Console.WriteLine("Starting program");
     Log("this information need to be logged");
     Console.WriteLine("Press any key to exit");
     Console.ReadLine();
  }       
```

很明显，写日志需要 5 秒的延迟太长了。由于我们不希望从`Log`方法中得到任何输出（将控制台输出仅用于演示目的），因此将其异步调用并立即将响应返回给调用者是有意义的。

以下是当前程序的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/39f2ec02-f68d-4499-82f1-483b85baf2ca.png)

我们可以在前面的方法中添加一个`Log`方法调用。然后，我们可以将`Log`方法调用包装在一个委托中，并在委托上调用`BeginInvoke`方法，如下所示：

```cs
//Log("this information need to be logged");
Action logAction = new Action(()=> Log("this information need to be logged"));                 logAction.BeginInvoke(null,null);
```

这次，当我们执行代码时，我们将在较早版本的.NET 中看到异步行为。然而，在.NET Core 中，代码在运行时会出现以下错误消息：

`System.PlatformNotSupportedException: 'Operation is not supported on this platform.'`

在.NET Core 中，不再支持将同步方法包装成异步委托，原因有两个：

+   异步委托使用基于`IAsyncResult`的异步模式，这在.NET Core 基类库中不受支持。

+   在.NET Core 中，没有`System.Runtime.Remoting`，因此无法使用异步委托。

# 使用 Task 类

在.NET Core 中实现异步编程的另一种方法是使用`System.Threading.Tasks.Task`类，正如我们之前提到的。前面的代码可以改为以下内容：

```cs
// Log("this information need to be logged");
Task.Factory.StartNew(()=> Log("this information need to be logged"));
```

这将为我们提供所需的输出，而不会改变当前代码流的太多内容：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/414f388a-a105-4677-b001-ec47d471dbe8.png)

我们在第二章中讨论了`Task`，*任务并行性*。`Task`类为我们提供了一种非常强大的实现基于任务的异步模式的方法。

# 使用 IAsyncResult 接口

`IAsyncResult`接口已经被用来在早期版本的 C#中实现异步编程。以下是一些在较早版本的.NET 中运行良好的示例代码：

1.  首先，我们创建一个`AsyncCallback`，当异步方法完成时将执行它。

```cs
AsyncCallback callback = new AsyncCallback(MyCallback);
```

1.  然后，我们创建一个委托，该委托将使用传递的参数执行`Add`方法。完成后，它将执行由`AsyncCallBack`包装的回调方法：

```cs
SumDelegate d = new SumDelegate(Add);
d.BeginInvoke(100, 200, callback, state);
```

1.  当调用`MyCallBack`方法时，它会返回`IAsyncResult`实例。要获取底层结果、状态和回调，我们需要将`IAsyncResult`实例转换为`AsyncResult`：

```cs
AsyncResult ar = (AsyncResult)result;
```

1.  一旦我们有了`AsyncResult`，我们就可以调用`EndInvoke`来获取`Add`方法返回的值：

```cs
int i = d.EndInvoke(result);
```

以下是完整的代码：

```cs
using System.Runtime.Remoting.Messaging;
public delegate int SumDelegate(int x, int y);

static void Main(string[] args)
{
    AsyncCallback callback = new AsyncCallback(MyCallback);
    int state = 1000;
    SumDelegate d = new SumDelegate(Add);
    d.BeginInvoke(100, 200, callback, state);
    Console.WriteLine("Press any key to exit");
    Console.ReadLine();
}
public static int Add(int a, int b)
{
    return a + b;
}
public static void MyCallback(IAsyncResult result)
{
    AsyncResult ar = (AsyncResult)result;
    SumDelegate d = (SumDelegate)ar.AsyncDelegate;
    int state = (int)ar.AsyncState;
    int i = d.EndInvoke(result);
    Console.WriteLine(i);
    Console.WriteLine(state);
    Console.ReadLine();
}
```

不幸的是，.NET Core 不支持`System.Runtime.Remoting`，因此前面的代码在.NET Core 中不起作用。我们只能对所有`IAsyncResult`场景使用基于任务的异步模式：

```cs
FileInfo fi = new FileInfo("test.txt");
            byte[] data = new byte[fi.Length];
            FileStream fs = new FileStream("test.txt", FileMode.Open, FileAccess.Read, FileShare.Read, data.Length, true);
            // We still pass null for the last parameter because
            // the state variable is visible to the continuation delegate.
            Task<int> task = Task<int>.Factory.FromAsync(
                    fs.BeginRead, fs.EndRead, data, 0, data.Length, null);
            int result = task.Result;
            Console.WriteLine(result);
```

前面的代码使用`FileStream`类从文件中读取数据。`FileStream`实现了`IAsyncResult`，因此支持`BeginRead`和`EndRead`方法。然后，我们使用`Task.Factory.FromAsync`方法来包装`IAsyncResult`并返回数据。

# 何时不使用异步编程

异步编程在创建响应式 UI 和提高应用程序性能方面非常有益。然而，有些情况下应避免使用异步编程，因为它可能降低性能并增加代码的复杂性。在接下来的小节中，我们将讨论一些最好不要使用异步编程的情况。

# 在单个没有连接池的数据库中

在只有一个没有启用连接池的数据库服务器的情况下，异步编程将没有任何好处。无论是同步还是异步调用，长时间的连接和多个请求都会导致性能瓶颈。

# 当代码易于阅读和维护很重要时

在使用`IAsyncResult`接口时，我们必须将源方法分解为两个方法：`BeginMethodName`和`EndMethodName`。以这种方式改变逻辑可能需要很多时间和精力，并且会使代码难以阅读、调试和维护。

# 用于简单和短暂的操作

我们需要考虑代码在同步运行时所花费的时间。如果时间不长，保持代码同步是有意义的，因为将代码改为异步会带来一些性能损失，对于小的收益来说并不划算。

# 对于有大量共享资源的应用程序

如果您的应用程序使用大量共享资源，例如全局变量或系统文件，保持代码同步是有意义的；否则，我们将减少性能的好处。与共享资源一样，我们需要应用可以减少多线程性能的同步原语。有时，单线程应用程序可能比多线程应用程序更高效。

# 您可以使用异步代码解决的问题

让我们看看一些情况，异步编程可以帮助改善应用程序的响应性和应用程序和服务器的性能。一些情况如下：

+   日志记录和审计：日志记录和审计是应用程序的横切关注点。如果您自己编写日志记录和审计的代码，那么对服务器的调用会变慢，因为它们需要写回日志。我们可以使日志记录和审计异步化，并且在可能的情况下应该使实现无状态。这将确保回调可以在静态上下文中返回，以便在响应返回到浏览器时调用可以继续执行。

+   服务调用：Web 服务调用和数据库调用可以是异步的，因为一旦我们调用服务/数据库，控制权就离开当前应用程序并转到 CPU，进行网络调用。调用线程进入阻塞状态。一旦服务调用的响应返回，CPU 接收并触发一个事件。调用线程解除阻塞并开始进一步执行。作为一种模式，您可能已经看到所有服务代理都返回异步方法。

+   创建响应式 UI：在程序中可能存在这样的情况，用户点击按钮保存数据。保存数据可能涉及多个小任务：从 UI 读取数据到模型，连接到数据库，并调用数据库更新数据。这可能需要很长时间，如果这些调用在 UI 线程上进行，那么线程将被阻塞直到完成。这意味着用户在调用返回之前无法在 UI 上执行任何操作。通过进行异步调用，我们可以改善用户体验。

+   CPU 密集型应用程序：随着.NET 中新技术和支持的出现，我们现在可以在.NET 中编写机器学习、ETL 处理和加密货币挖掘代码。这些任务对 CPU 要求很高，因此将这些程序设置为异步是有意义的。

**C#早期版本中的异步模式** 在.NET 的早期版本中，支持了两种模式来执行 I/O 密集型和计算密集型操作：

+   **异步编程模型**（**APM**）

+   **基于事件的异步模式**（**EAP**）

我们在第二章中详细讨论了这两种方法，*任务并行性*。我们还学习了如何将这些传统实现转换为基于任务的异步模式。

现在，让我们回顾一下本章涵盖的内容。

# 总结

在本章中，我们讨论了什么是异步编程，以及为什么编写异步代码是有意义的。我们还讨论了可以实现异步编程的场景以及应该避免的场景。最后，我们介绍了在 TPL 中实现的各种异步模式。

如果正确使用，异步编程可以通过有效利用线程来显著提高服务器端应用程序的性能。它还可以提高桌面/移动应用程序的响应性。

在下一章中，我们将讨论.NET Framework 提供的异步编程原语。

# 问题

1.  ________ 代码更容易编写、调试和维护。

1.  同步

1.  异步

1.  在什么场景下应该使用异步编程？

1.  文件 I/O

1.  带有连接池的数据库

1.  网络 I/O

1.  没有连接池的数据库

1.  哪种方法可以用来编写异步代码？

1.  Delegate.BeginInvoke

1.  任务

1.  IAsyncResult

1.  以下哪种不能用于在.NET Core 中编写异步代码？

1.  IAsyncResult

1.  任务


# 第九章：异步、等待和基于任务的异步编程基础

在上一章中，我们介绍了 C#中可用的异步编程实践和解决方案，甚至在.NET Core 之前。我们还讨论了异步编程可以派上用场的场景，以及应该避免使用的场景。

在本章中，我们将更深入地探讨异步编程，并介绍两个使编写异步代码变得非常容易的关键字。本章将涵盖以下主题：

+   介绍`async`和`await`

+   异步委托和 lambda 表达式

+   **基于任务的异步模式**（**TAP**）

+   异步代码中的异常处理

+   使用 PLINQ 进行异步

+   测量异步代码性能

+   使用异步代码的指南

让我们从介绍`async`和`await`关键字开始，这两个关键字首次在 C# 5.0 中引入，并在.NET Core 中也被采用。

# 技术要求

读者应该对**任务并行库**（**TPL**）和 C#有很好的理解。本章的源代码可在 GitHub 上找到：[`github.com/PacktPublishing/-Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter09`](https://github.com/PacktPublishing/-Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter09)。

# 介绍异步和 await

`async`和`await`是.NET Core 开发人员中非常流行的两个关键字，用于在调用.NET Framework 提供的新异步 API 时标记代码。在上一章中，我们讨论了将同步方法转换为异步方法的挑战。以前，我们通过将方法分解为两个方法`BeginMethodName`和`EndMethodName`来实现异步调用。这种方法使代码变得笨拙，难以编写、调试和维护。然而，使用`async`和`await`关键字，代码可以保持与同步实现相同，只需要进行少量的更改。将方法分解、执行异步方法以及将响应返回给程序的所有困难工作都由编译器完成。

.NET Framework 提供的所有新 I/O API 都支持基于任务的异步性，我们在上一章中已经讨论过。现在让我们尝试理解一些涉及 I/O 操作的场景，我们可以利用`async`和`await`关键字。假设我们想从返回 JSON 格式数据的公共 API 中下载数据。在较旧版本的 C#中，我们可以使用`System.Net`命名空间中提供的`WebClient`类编写同步代码，如下所示。

首先，添加对`System.Net`程序集的引用：

```cs
WebClient client = new WebClient();
string reply = client.DownloadString("http://www.aspnet.com"); 
Console.WriteLine(reply);
```

接下来，创建一个`WebClient`类的对象，并通过传递要下载的页面的 URL 来调用`DownloadString`方法。该方法将同步运行，并且调用线程将被阻塞，直到下载操作完成。这可能会影响服务器的性能（如果在服务器端代码中使用）和应用程序的响应性（如果在 Windows 应用程序代码中使用）。

为了提高性能和响应性，我们可以使用稍后引入的`DownloadString`方法的异步版本。

以下是一个创建远程资源`http://www.aspnet.com`的下载请求并订阅`DownloadStringCompleted`事件的方法，而不是等待下载完成的方法：

```cs
private static void DownloadAsynchronously()
 {
     WebClient client = new WebClient(); 
     client.DownloadStringCompleted += new 
     DownloadStringCompletedEventHandler(DownloadComplete); 
     client.DownloadStringAsync(new Uri("http://www.aspnet.com"));
 }
```

以下是`DownloadComplete`事件处理程序，当下载完成时触发：

```cs
private static void DownloadComplete(object sender, DownloadStringCompletedEventArgs e)
{
     if (e.Error != null)
     {
         Console.WriteLine("Some error has occurred.");
         return;
     }
     Console.WriteLine(e.Result);
     Console.ReadLine();
 }
```

在上述代码中，我们使用了**基于事件的异步模式**（**EAP**）。正如您所看到的，我们已经订阅了`DownloadCompleted`事件，该事件将在`WebClient`类完成下载后被触发。然后，我们调用了`DownloadStringAsync`方法，该方法将异步调用代码并立即返回，避免了阻塞线程的需要。当后台下载完成时，将调用`DownloadComplete`方法，我们可以使用`DownloadStringCompletedEventArgs`的`e.Error`属性接收错误，或使用`e.Result`属性接收数据。

如果我们在 Windows 应用程序中运行上述代码，结果将如预期那样，但响应将始终由工作线程（在后台执行）接收，而不是由主线程接收。作为 Windows 应用程序开发人员，我们需要注意的是，我们不能从`DownloadComplete`方法更新 UI 控件，所有这样的调用都需要使用经典 Windows Forms 中的 Invoke 或 WPF 中的 Dispatcher 等技术委托回主 UI 线程。使用 Invoke/Dispatcher 方法的最大好处是主线程永远不会被阻塞，因此整个应用程序更加响应。

在本书附带的代码示例中，我们包括了 Windows Forms 和 WPF 的场景，尽管.NET Core 目前尚不支持 Windows 应用程序或 WPF。预计这种支持将在下一个版本的 Visual Studio，即 VS 2019 中引入。

让我们尝试在.NET Core 控制台应用程序的主线程中运行上述代码，如下所示：

```cs
 public static void Main()
        {
         DownloadAsynchronously();   
        }
```

我们可以通过在`DownloadComplete`方法中添加`Console.WriteLine`语句来修改它，如下所示：

```cs
private static void DownloadComplete(object sender, DownloadStringCompletedEventArgs e)
        {
            …
            …
            …
            Console.ReadLine() ;//Added this line
        }
```

根据逻辑，程序应该异步下载页面，打印输出，并在终止之前等待用户输入。当我们运行上述代码时，会发现程序在不打印任何内容且不等待用户输入的情况下终止了。为什么会发生这种情况呢？

正如前面所述，一旦主线程调用`DownloadStringAsync`方法，它就会被解除阻塞。主线程不会等待回调函数执行。这是设计上的考虑，异步方法预期以这种方式行为。然而，由于主线程没有其他事情可做，而且已经完成了它预期要做的事情，即调用方法，应用程序终止了。

作为 Web 应用程序开发人员，如果在使用 Web Forms 或 ASP.NET MVC 的服务器端应用程序中使用上述代码，可能会遇到类似的问题。如果您以异步方式调用了该方法，执行您的请求的 IIS 线程将立即返回，而不会等待下载完成。因此，结果将不如预期。我们不希望代码在 Web 应用程序中将输出打印到控制台，当在 Web 应用程序代码中运行时，`Console.WriteLine`语句会被简单地忽略。假设您的逻辑是将网页作为响应返回给客户端请求。我们可以使用 ASP.NET MVC 中的`WebClient`类同步实现这一点，如下例所示：

```cs
public IActionResult Index()
{
    WebClient client = new WebClient();
    string content = client.DownloadString(new 
     Uri("http://www.aspnet.com"));
    return Content(content,"text/html");
}
```

这里的问题是，上述代码将阻塞线程，这可能会影响服务器的性能，并导致自我发起的**拒绝服务**（**DoS**）攻击，当许多用户同时访问应用程序的某一部分时会发生。随着越来越多的线程被命中并被阻塞，将会有一个点，服务器将没有任何空闲线程来处理客户端请求，并开始排队请求。一旦达到队列限制，服务器将开始抛出 503 错误：服务不可用。

由于一旦调用`DownloadStringAsync`方法，线程将立即向客户端返回响应，而不等待`DownloadComplete`完成，因此我们无法使用该方法。我们需要一种方法使服务器线程等待而不阻塞它。在这种情况下，`async`和`await`来拯救我们。除了帮助我们实现我们的目标外，它们还帮助我们编写、调试和维护清晰的代码。

为了演示`async`和`await`，我们可以使用.NET Core 的另一个重要类`HttpClient`，它位于`System.Net.Http`命名空间中。应该使用`HttpClient`而不是`WebClient`，因为它完全支持基于任务的异步操作，具有大大改进的性能，并支持 GET、POST、PUT 和 DELETE 等 HTTP 方法。

以下是使用`HttpClient`类和引入`async`和`await`关键字的前面代码的异步版本：

```cs
public async Task<IActionResult> Index()
        {
            HttpClient client = new HttpClient();
            HttpResponseMessage response = await 
             client.GetAsync("http://www.aspnet.com");
            string content = await response.Content.ReadAsStringAsync();
            return Content(content,"text/html");
        }
```

首先，我们需要更改方法签名以包含`async`关键字。这是对编译器的指示，表明该方法将根据需要异步执行。然后，我们将方法的返回类型包装在`Task<T>`中。这很重要，因为.NET Framework 支持基于任务的异步操作，所有异步方法必须返回`Task`。

我们需要创建`HttpClient`类的一个实例，并调用`GetAsync()`方法，传递要下载的资源的 URL。与依赖于回调的 EAP 模式不同，我们只需在调用时写上`await`关键字。这确保了以下情况：

+   该方法异步执行。

+   调用线程被解除阻塞，以便它可以返回线程池并处理其他客户端请求，从而使服务器响应。

+   当下载完成时，`ThreadPool`从处理器接收到中断信号，并从`ThreadPool`中取出一个空闲线程，可以是正在处理请求的相同线程，也可以是不同的线程。

+   `ThreadPool`线程接收到响应并开始执行方法的其余部分。

当下载完成时，我们可以使用另一个异步操作`ReadAsStringAsync()`来读取下载的内容。本节已经表明，编写类似于同步方法的异步方法非常容易，使它们的逻辑也很直接。

# 异步方法的返回类型

在上面的示例中，我们将方法的返回类型从`IAsyncResult`更改为`Task<IAsyncResult>`。异步方法可以有三种返回类型：

+   `void`

+   `Task`

+   `Task<T>`

所有异步方法必须返回一个`Task`以便被等待（使用`await`关键字）。这是因为一旦调用它们，它们不会立即返回，而是异步执行一个长时间运行的任务。在这样做的过程中，调用线程也可能在上下文中切换。

`void`可以与调用线程不想等待的异步方法一起使用。这些方法可以是后台发生的任何操作，不是返回给用户的响应的一部分。例如，日志记录和审计可以是异步的。这意味着它们可以包装在异步的`void`方法中。调用操作时，调用线程将立即返回，日志记录和审计操作将稍后进行。因此，强烈建议从异步方法返回`Task`而不是`void`。

# 异步委托和 lambda 表达式

我们也可以使用`async`关键字创建异步委托和 lambda 表达式。

以下是返回数字的平方的同步委托：

```cs
Func<int, int> square = (x) => {return x * x;};
```

我们可以通过添加`async`关键字使前面的委托异步化，如下所示：

```cs
Func<int, Task<int>> square =async (x) => {return x * x;};
```

类似地，lambda 表达式可以转换如下：

```cs
Func<int, Task<int>> square =async (x) => x * x;
```

异步方法在一个链条中工作。一旦你将任何一个方法变成异步方法，那么调用该方法的所有方法也需要被转换为异步方法，从而创建一个长链的异步方法。

# 基于任务的异步模式

在第二章中，*任务并行性*，我们讨论了如何使用`Task`类实现 TAP。有两种实现这种模式的方法：

+   编译器方法，使用`async`关键字

+   手动方法

让我们在后续章节中看看这些方法是如何操作的。

# 编译器方法，使用 async 关键字

当我们使用`async`关键字使任何方法成为异步方法时，编译器会进行必要的优化，使用 TAP 在内部异步执行该方法。异步方法必须返回`System.Threading.Task`或`System.Threading.Task<T>`。编译器负责异步执行方法并将结果或异常返回给调用者。

# 手动实现 TAP

我们已经展示了如何在 EAP 和**异步编程模型**（**APM**）中手动实现 TAP。实现这种模式可以让我们更好地控制方法的整体实现。我们可以创建一个`TaskCompletionSource<TResult>`类，然后执行一个异步操作。当异步操作完成时，我们可以通过调用`TaskCompletionSource<TResult>`类的`SetResult`、`SetException`或`SetCanceled`方法将结果返回给调用者，如下面的代码所示：

```cs
public static Task<int> ReadFromFileTask(this FileStream stream, byte[] buffer, int offset, int count, object state)
{
    var taskCompletionSource = new TaskCompletionSource<int>();
    stream.BeginRead(buffer, offset, count, ar =>
    {
         try 
         { 
               taskCompletionSource.SetResult(stream.EndRead(ar));
         }
         catch (Exception exc) 
         { 
               taskCompletionSource.SetException(exc); 
         }
     }, state);
     return taskCompletionSource.Task;
}
```

在上面的代码中，我们创建了一个返回`Task<int>`的方法，可以作为扩展方法在任何`System.IO.FileStream`对象上工作。在方法内部，我们创建了一个`TaskCompletionSource<int>`对象，然后调用`FileStream`类提供的异步操作将文件读入字节数组。如果读取操作成功完成，我们使用`SetResult`方法将结果返回给调用者；否则，我们使用`SetException`方法返回异常。最后，该方法将从`TaskCompletionSource<int>`对象返回底层任务给调用者。

# 异步代码的异常处理

在同步代码的情况下，所有异常都会传播到堆栈的顶部，直到它们被 try-catch 块处理或作为未处理的异常抛出。当我们在任何异步方法上等待时，调用堆栈将不会相同，因为线程已经从方法转换到线程池，并且现在正在返回。然而，C#通过改变异步方法的异常行为，使我们更容易进行异常处理。所有异步方法都返回`Task`或`void`。让我们尝试用例子理解这两种情况，并看看程序的行为。

# 返回 Task 并抛出异常的方法

假设我们有以下方法，它是`void`。作为最佳实践，我们从中返回`Task`：

```cs
 private static Task DoSomethingFaulty()
 {
      Task.Delay(2000);
      throw new Exception("This is custom exception.");
 }
```

该方法在延迟两秒后抛出异常。

我们将尝试使用各种方法调用此方法，以尝试理解异步方法的异常处理行为。本节将讨论以下场景：

+   在 try-catch 块外部调用异步方法，没有使用`await`关键字

+   在 try-catch 块内部调用异步方法，没有使用`await`关键字

+   在 try-catch 块外部使用 await 关键字调用异步方法

+   返回`void`的方法

我们将在后续章节中详细介绍这些方法。

# 在 try-catch 块外部调用异步方法，没有使用 await 关键字

以下是一个返回`Task`的示例异步方法。该方法调用另一个方法`DoSomethingFaulty()`，该方法会抛出异常。

这是我们的`DoSomethingFaulty()`方法实现：

```cs
  private static Task DoSomethingFaulty()
  {
      Task.Delay(2000);
      throw new Exception("This is custom exception.");
  }
```

以下是`AsyncReturningTaskExample()`方法的代码：

```cs
private async static Task AsyncReturningTaskExample()
 {
      Task<string> task = DoSomethingFaulty();
      Console.WriteLine("This should not execute");
      try
      {
           task.ContinueWith((s) =>
           {
             Console.WriteLine(s);
           });
      }
      catch (Exception ex)
      {
       Console.WriteLine(ex.Message);
       Console.WriteLine(ex.StackTrace);
      }
  }
```

这是从`Main()`方法调用的：

```cs
 public static void Main()
 {
     Console.WriteLine("Main Method Starts");
     var task = AsyncReturningTaskExample();
     Console.WriteLine("In Main Method After calling method");
     Console.ReadLine();
 }
```

异步主方法是 C# 7.1 版本以后的一个方便的补充。它在 7.2 版本中出现了问题，但在.NET Core 3.0 中得到了修复。

如您所见，程序调用了异步方法——即`AsyncReturningTaskExample()`——而没有使用`await`关键字。`AsyncReturningTaskExample()`方法进一步调用了`DoSomethingFaulty()`方法，该方法抛出异常。当我们运行此代码时，将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/88073eb0-9010-45f1-838e-1239ced84266.png)

在同步编程的情况下，程序会导致未处理的异常，并且会崩溃。但在这里，程序会继续进行，就好像什么都没有发生一样。这是由于框架处理`Task`对象的方式。在这种情况下，任务将以故障状态返回给调用者，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/27e57487-af51-4fc0-94a8-7c5a17059fa6.png)

更好的代码应该是检查任务状态并在有异常时获取所有异常：

```cs
var task = AsyncReturningTaskExample();
if (task.IsFaulted)
    Console.WriteLine(task.Exception.Flatten().Message.ToString());
```

正如我们在第二章中看到的*任务并行性*，这个任务返回一个`AggregateExceptions`的实例。要获取所有抛出的内部异常，我们可以使用`Flatten()`方法，就像在前面的截图中演示的那样。

# 在 try-catch 块内部没有使用 await 关键字的异步方法

让我们将调用异步方法`GetSomethingFaulty()`的方法移动到 try-catch 块内，并从`Main()`方法调用。

这是`Main`方法：

```cs
public static void Main()
{
    Console.WriteLine("Main Method Started");
    var task = Scenario2CallAsyncWithoutAwaitFromInsideTryCatch();
    if (task.IsFaulted)
        Console.WriteLine(task.Exception.Flatten().Message.ToString());
    Console.WriteLine("In Main Method After calling method");
    Console.ReadLine();
}       
```

这里是`Scenario2CallAsyncWithoutAwaitFromInsideTryCatch()`方法：

```cs
private async static Task Scenario2CallAsyncWithoutAwaitFromInsideTryCatch()
{
     try
     {
         var task = DoSomethingFaulty();
         Console.WriteLine("This should not execute"); 
         task.ContinueWith((s) =>
         {
             Console.WriteLine(s);
         });
     }
     catch (Exception ex)
     {
         Console.WriteLine(ex.Message);
         Console.WriteLine(ex.StackTrace);
     }
}
```

这次，我们看到异常将被抛出并被 catch 块接收，之后程序将正常恢复。

值得一看的是`Main`方法中`Task`对象的值：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/e97dd4ef-dfcd-4677-b88d-d4e855a6c81b.png)

如您所见，如果任务创建不在 try-catch 块内进行，异常将不会被观察到。这可能会导致问题，因为逻辑可能不会按预期工作。最佳实践是始终将任务创建包装在 try-catch 块内。

如您所见，由于异常已被处理，执行从异步方法正常返回。返回任务的状态变为`RanToCompletion`。

# 使用 await 关键字从 try-catch 块外部调用异步方法

以下代码块显示了调用有错误的方法`DoSomethingFaulty()`并等待方法完成的方法的代码，使用`await`关键字：

```cs
private async static Task Scenario3CallAsyncWithAwaitFromOutsideTryCatch()
{
    await DoSomethingFaulty();
    Console.WriteLine("This should not execute"); 
}
```

这是从`Main`方法调用的：

```cs
public static void Main()
{
      Console.WriteLine("Main Method Starts");
      var task = Scenario3CallAsyncWithAwaitFromOutsideTryCatch();
      if (task.IsFaulted)
          Console.WriteLine(task.Exception.Flatten().Message.ToString());
      Console.WriteLine("In Main Method After calling method");
      Console.ReadLine();
}
```

在这种情况下，程序的行为将与第一个场景相同。

# 返回 void 的方法

如果方法返回`void`而不是`Task`，程序将崩溃。您可以尝试运行以下代码。

这是一个返回`void`而不是`Task`的方法：

```cs
private async static void Scenario4CallAsyncWithoutAwaitFromOutsideTryCatch()
{
    Task task = DoSomethingFaulty();
    Console.WriteLine("This should not execute");
}
```

这是从`Main`方法调用的：

```cs
public static void Main()
{
    Console.WriteLine("Main Method Started"); 
    Scenario4CallAsyncWithoutAwaitFromOutsideTryCatch();
    Console.WriteLine("In Main Method After calling method"); 
    Console.ReadLine();
}
```

不会有输出，因为程序会崩溃。

虽然从异步方法中返回`void`是没有意义的，但错误确实会发生。我们应该编写代码，使其永远不会崩溃，或者在记录异常后优雅地崩溃。

我们可以通过订阅两个全局事件处理程序来全局处理这个问题，如下所示：

```cs
AppDomain.CurrentDomain.UnhandledException += (s, e) => Console.WriteLine("Program Crashed", "Unhandled Exception Occurred");
TaskScheduler.UnobservedTaskException += (s, e) => Console.WriteLine("Program Crashed", "Unhandled Exception Occurred");
```

前面的代码将处理程序中的所有未处理异常，并考虑了异常管理中的良好实践。程序不应该随机崩溃，如果需要崩溃，那么应该记录信息并清理所有资源。

# 使用 PLINQ 进行异步

PLINQ 是开发人员非常方便的工具，可以通过并行执行一组任务来提高应用程序的性能。创建多个任务可以提高性能，但是，如果任务具有阻塞性质，那么应用程序最终将创建大量阻塞线程，并且在某些时候会变得无响应。特别是如果任务正在执行一些 I/O 操作。以下是一个需要尽快从网络下载 100 页的方法：

```cs
 public async static void Main()
        {
            var urls =  Enumerable.Repeat("http://www.dummyurl.com", 100);
            foreach (var url in urls)
            {
                HttpClient client = new HttpClient();
                HttpResponseMessage response = await 
                 client.GetAsync("http://www.aspnet.com");
                string content = await 
                  response.Content.ReadAsStringAsync();
                Console.WriteLine();
            }
```

如您所见，上述代码是同步的，具有*O(n)*的复杂度。如果一个请求需要一秒钟才能完成，那么该方法至少需要 100 秒（n = 100）。

为了加快下载速度（假设我们有一个能够处理此负载的良好服务器配置，乘以应用程序想要支持的用户数量），我们需要并行执行此方法。我们可以使用`Parallel.ForEach`来实现：

```cs
     Parallel.ForEach(urls, url =>
            {
                HttpClient client = new HttpClient();
                HttpResponseMessage response = await 
                 client.GetAsync("http://www.aspnet.com");
                string content = await 
                 response.Content.ReadAsStringAsync();
            });
```

突然，代码开始抱怨：

*'await'运算符只能在异步 lambda 表达式中使用。考虑使用'async'修饰符标记此 lambda 表达式。*

这是因为我们使用了 lambda 表达式，它也需要被标记为 async，如下面的代码所示：

```cs
Parallel.ForEach(urls,async url =>
            {
                HttpClient client = new HttpClient();
                HttpResponseMessage response = await 
                 client.GetAsync("http://www.aspnet.com");
                string content = await 
                 response.Content.ReadAsStringAsync();
            });
```

现在代码将会编译并按预期工作，性能得到了大幅提升。在下一节中，我们将更深入地讨论异步代码性能的测量方法。

# 测量异步代码的性能

异步代码可以提高应用程序的性能和响应性，但也存在一些权衡。在基于 GUI 的应用程序（如 Windows Forms 或 WPF）中，如果一个方法花费了很长时间，将其标记为异步是有意义的。然而，对于服务器应用程序，您需要权衡受阻线程所使用的额外内存和使方法异步所需的额外处理器开销之间的权衡。

考虑以下代码，它创建了三个任务。每个任务都是异步运行的，一个接一个地执行。当一个方法完成时，它会继续异步执行另一个任务。使用`Stopwatch`可以计算完成方法所需的总时间：

```cs
public static void Main(string[] args)
{
    MainAsync(args).GetAwaiter().GetResult();
    Console.ReadLine();
}
public static async Task MainAsync(string[] args)
{
    Stopwatch stopwatch = Stopwatch.StartNew();
    var value1 = await Task1();
    var value2 = await Task2();
    var value3 = await Task3();
    stopwatch.Stop();
    Console.WriteLine($"Total time taken is 
     {stopwatch.ElapsedMilliseconds}");
}
public static async Task<int> Task1()
{
    await Task.Delay(2000);
    return 100;
}
public static async Task<int> Task2()
{
    await Task.Delay(2000);
    return 200;
}
public static async Task<int> Task3()
{
    await Task.Delay(2000);
    return 300;
}
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/c0d8cd2f-b74e-4b8c-ba02-0640678401d6.png)

这与编写同步代码一样好。好处是线程不会被阻塞，但应用程序的整体性能较差，因为所有代码现在都是同步运行的。我们可以改变上述代码以提高性能，如下所示：

```cs
Stopwatch stopwatch = Stopwatch.StartNew();
       await Task.WhenAll(Task1(), Task2(), Task3());
       stopwatch.Stop();
       Console.WriteLine($"Total time taken is {stopwatch.ElapsedMilliseconds}");
```

如您所见，这是更好地使用并行和异步以获得更好的性能：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/f7c04eec-fc9f-43ca-8fe3-a329e7f7046b.png)

为了更好地理解异步，我们还需要了解哪个线程运行我们的代码。由于新的异步 API 与`Task`类一起工作，所有调用都由`ThreadPool`线程执行。当我们进行异步调用时，比如从网络获取数据，控制权会转移到由操作系统管理的 I/O 完成端口线程。通常，这只是一个线程，跨所有网络请求共享。当 I/O 请求完成时，操作系统会触发中断信号，将作业添加到 I/O 完成端口的队列中。在通常以**多线程公寓**（**MTA**）模式工作的服务器端应用程序中，任何线程都可以启动异步请求，任何其他线程都可以接收它。

在 Windows 应用程序的情况下（包括 WinForms 和 WPF），它们以**单线程公寓**（STA）模式工作，因此异步调用返回到启动它的同一线程（通常是 UI 线程）变得很重要。Windows 应用程序中的每个 UI 线程都有一个`SynchronizationContext`，它确保代码始终由正确的线程执行。这对于控件所有权很重要。为了避免跨线程问题，只有所有者线程才能更改控件的值。`SynchronizationContext`类的最重要方法是`Post`，它可以使委托在正确的上下文中运行，从而避免跨线程问题。

每当我们等待一个任务时，当前的`SynchronizationContext`都会被捕获。然后，当方法需要恢复时，`await`关键字在内部使用`Post`方法在捕获的`SynchronizationContext`中恢复方法。然而，调用`Post`方法非常昂贵，但框架提供了内置的性能优化。如果捕获的`SynchronizationContext`与返回线程的当前`SynchronizationContext`相同，则不会调用`Post`方法。

如果我们正在编写一个类库，并且我们并不真的关心调用将返回到哪个`SynchronizationContext`，我们可以完全关闭`Post`方法。我们可以通过在返回的任务上调用`ConfigureAwait()`方法来实现这一点，如下所示：

```cs
HttpClient client = new HttpClient();
HttpResponseMessage response = await client.GetAsync(url).ConfigureAwait(false);
```

到目前为止，我们已经学习了异步编程的重要方面。现在我们需要了解在编程时使用异步代码的指南！

# 使用异步代码的指南

在编写异步代码时的一些建议/最佳实践如下：

+   避免使用异步 void。

+   异步链一直延续。

+   在可能的情况下使用`ConfigureAwait`。

我们将在接下来的部分中了解更多。

# 避免使用异步 void

我们已经看到从异步方法返回`void`实际上会影响异常处理。异步方法应该返回`Task`或`Task<T>`，以便可以观察异常并且不会变成未处理的异常。

# 异步链一直延续

混合异步和阻塞方法会影响性能。一旦决定将方法设置为异步，从该方法调用的整个方法链也应该设置为异步。不这样做有时会导致死锁，如下面的代码示例所示：

```cs
private async Task DelayAsync()
{
    await Task.Delay(2000);
}
public void Deadlock()
{
    var task = DelayAsync();
    task.Wait();
}
```

如果我们从任何 ASP.NET 或基于 GUI 的应用程序中调用`Deadlock()`方法，它将创建死锁，尽管相同的代码在控制台应用程序中可以正常运行。当我们调用`DelayAsync()`方法时，它会捕获当前的`SynchronizationContext`，或者如果`SynchronizationContext`为 null，则捕获当前的`TaskScheduler`。当等待的任务完成时，它会尝试使用捕获的上下文执行方法的其余部分。问题在于已经有一个线程在同步等待异步方法完成。在这种情况下，两个线程都将等待另一个线程完成，从而导致死锁。这个问题只会在基于 GUI 或 ASP.NET 的应用程序中出现，因为它们依赖于只能一次执行一块代码的`SynchronizationContext`。另一方面，控制台应用程序使用`ThreadPool`而不是`SynchronizationContext`。当等待完成时，挂起的异步方法部分被安排在`ThreadPool`线程上。该方法在单独的线程上完成并将任务返回给调用者，因此不会发生死锁。

永远不要在控制台应用程序中尝试创建示例`async`/`await`代码，然后将其复制粘贴到 GUI 或 ASP.NET 应用程序中，因为它们有不同的执行异步代码的模型。

# 在可能的情况下使用 ConfigureAwait

我们可以通过完全跳过使用`SynchronizationContext`来避免前面代码示例中的死锁：

```cs
private async Task DelayAsync()
{
await Task.Delay(2000);
}
public void Deadlock()
{
var task = DelayAsync().ConfigureAwait(false);
task.Wait();
}
```

当我们使用`ConfigureAwait(false)`时，该方法会被等待。当等待完成时，处理器会尝试在线程池上下文中执行剩余的异步方法。由于没有阻塞上下文，该方法能够顺利完成。该方法完成了其返回的任务，没有死锁。

我们已经到达了本章的结尾。现在让我们看看我们学到了什么！

# 摘要

在本章中，我们讨论了两个非常重要的构造，使得编写异步代码变得非常容易。当我们使用这些关键字时，所有繁重的工作都是由编译器完成的，代码看起来与其同步对应物非常相似。我们还讨论了当我们使方法异步化时，代码运行在哪个线程上，以及利用`SynchronizationContext`会带来的性能损失。最后，我们看了如何完全关闭`SynchronizationContext`以提高性能。

在下一章中，我们将介绍使用 Visual Studio 进行并行调试技术。我们还将学习 Visual Studio 中可用的工具，以帮助并行代码调试。

# 问题

1.  在异步方法中，用什么关键字来解除线程阻塞？

1.  `异步`

1.  `await`

1.  `Thread.Sleep`

1.  `Task`

1.  以下哪些是异步方法的有效返回类型？

1.  `无`

1.  `Task`

1.  `Task<T>`

1.  `IAsyncResult`

1.  `TaskCompletionSource<T>`可以用来手动实现基于任务的异步模式。

1.  真

1.  假

1.  我们可以将`Main`方法写成异步的吗？

1.  是

1.  不

1.  `Task`类的哪个属性可以用来检查异步方法是否抛出了异常？

1.  `IsException`

1.  `IsFaulted`

1.  我们应该总是将`void`作为异步方法的返回类型使用。

1.  真

1.  假


# 第四部分：异步代码的调试、诊断和单元测试

在本节中，我们将解释适用于 Visual Studio 用户的调试技术和工具。主要重点将放在理解 IDE 功能，如并行任务窗口、线程窗口、并行堆栈窗口和并发可视化工具上。我们还将介绍如何为使用 TPL 和异步编程的代码编写单元测试用例，如何为测试用例编写模拟和存根，以及一些技巧和窍门，确保我们为 ORM 编写的测试用例不会失败。

本节包括以下章节：

+   第十章，*使用 Visual Studio 调试任务*

+   第十一章，*编写并行和异步代码的单元测试用例*


# 第十章：使用 Visual Studio 调试任务

并行编程可以提高应用程序的性能和响应能力，但有时结果并不如预期。与并行/异步代码相关的常见问题是性能和正确性。

性能意味着执行结果很慢。正确性意味着结果不如预期（这可能是由于竞争条件）。处理多个并发任务时的另一个重大问题是死锁。调试多线程代码始终是一个挑战，因为在调试时线程会不断切换。在处理基于 GUI 的应用程序时，找出运行我们代码的线程也很重要。

在本章中，我们将解释如何使用 Visual Studio 中可用的工具来调试线程，包括“线程”窗口、“任务”窗口和并发可视化器。

本章将涵盖以下主题：

+   使用 VS 2019 进行调试

+   如何调试线程

+   使用并行任务窗口

+   使用并行堆栈窗口进行调试

+   使用并发可视化器

# 技术要求

在开始本章之前，需要先了解线程、任务、Visual Studio 和并行编程。

您可以在 GitHub 的以下链接中检查相关源代码：[`github.com/PacktPublishing/-Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter10`](https://github.com/PacktPublishing/-Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter10)。

# 使用 VS 2019 进行调试

Visual Studio 提供了许多内置工具，以帮助解决上述的调试和故障排除问题。本章将讨论以下一些工具：

+   线程窗口

+   并行堆栈窗口

+   并行监视窗口

+   调试位置工具栏

+   并发可视化器（截至撰写本文时仅适用于 VS 2017）

+   GPU 线程窗口

在接下来的章节中，我们将尝试深入了解所有这些工具。

# 如何调试线程

在使用多个线程时，找出在特定时间执行的线程变得很重要。这使我们能够解决跨线程问题以及竞争条件。使用“线程”窗口，我们可以在调试时检查和处理线程。在 Visual Studio IDE 中调试代码时，当您触发断点时，线程窗口提供一个包含有关活动线程信息的表格。

现在，让我们探讨如何使用 Visual Studio 调试线程：

1.  在 Visual Studio 中编写以下代码：

```cs
for (int i = 0; i < 10; i++) 
           {
               Task task = new TaskFactory().StartNew(() =>
                {
                 Console.WriteLine($"Thread with Id 
                  {Thread.CurrentThread.ManagedThreadId}");
                });
           }
```

1.  通过在`Console.Writeline`语句上按下*F9*来创建断点。

1.  通过按下*F5*以调试模式运行应用程序。应用程序将创建线程并开始执行。当触发断点时，我们将从工具栏的调试|窗口|线程窗口中打开线程窗口：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/155f0014-8b54-4083-9c66-17855f669651.png)

.NET 环境捕获了许多关于线程的信息，这些信息以列的形式显示。黄色箭头标识了当前正在执行的线程。

一些列包括以下内容：

+   **标记**：如果我们想跟踪特定线程，可以对其进行标记。这可以通过点击旗标图标来完成。

+   ID：显示为每个线程分配的唯一标识号。

+   托管 ID：显示为每个线程分配的托管标识号。

+   类别：每个线程被分配一个唯一的类别，这有助于我们确定它是 GUI 线程（主线程）还是工作线程。

+   名称：显示每个线程的名称，或显示为<无名称>。

+   位置：这有助于确定线程的执行位置。我们可以深入了解完整的调用堆栈。

我们可以通过点击旗标图标来标记我们想要监视的线程。要仅查看已标记的线程，可以在线程窗口中点击“仅显示已标记的线程”选项：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/3e92eedb-469a-47c7-b5fa-4a7fb5659124.png)

线程窗口的另一个很酷的功能是，我们可以冻结我们认为在调试过程中可能引起问题的线程，以监视应用程序的行为。即使系统有足够的资源可用，冻结后，线程也不会开始执行冻结的线程。冻结后，线程进入暂停状态：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/81458ecd-958d-4a8d-8eaf-5cdbfaca27b2.png)

在调试过程中，我们还可以通过右键单击线程窗口中的线程或双击线程来切换执行到另一个线程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/c136a204-8d8b-4f98-b882-f50a5e71041d.png)

Visual Studio 还支持使用并行堆栈窗口调试任务。我们将在下一节中看看这个。

# 使用并行堆栈窗口

并行堆栈窗口是调试线程和任务的一个很好的工具，这是在 Visual Studio 的较新版本中引入的。我们可以通过导航到调试|窗口|并行堆栈来在调试时打开并行堆栈窗口。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/031f99a8-0724-4485-b449-1f9e6c1e79cf.png)

从前面的截图中可以看出，在并行堆栈窗口上有各种视图，我们可以在这些视图上切换。我们将在下一个主题中学习如何使用并行堆栈窗口和这些视图进行调试。

# 使用并行堆栈窗口进行调试

并行堆栈窗口有一个下拉菜单，有两个选项。我们可以在这些选项之间切换，以在并行堆栈窗口中获得几个视图。这些视图包括以下内容：

+   线程视图

+   任务视图

让我们在接下来的部分详细检查这些视图。

# 线程视图

线程视图显示了在调试应用程序时运行的所有线程的调用堆栈：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/ea22ccb9-4c0b-4bac-a5b9-897cb63ec33c.png)

黄色箭头显示了代码当前执行的位置。悬停在并行堆栈窗口中的任何方法上会打开带有有关当前正在执行的线程信息的线程窗口：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/f462501f-0139-4c9d-af35-75e74a3a1790.png)

我们可以通过双击它切换到任何其他方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/4935cbee-90c0-4d42-aeb3-84678f412331.png)

我们还可以切换到方法视图以查看完整的调用堆栈：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/ffd48e2f-51fe-4ed0-b50b-251cd280037d.png)

方法视图非常适用于调试调用堆栈，以查找在任何时间点传递给方法的值。

# 任务视图

如果我们在代码中使用任务并行库创建`System.Threading.Tasks.Task`对象，我们应该使用任务视图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/3d7406d4-8e16-454e-a154-b53080dc26e2.png)

如下截图所示，当前有 10 个正在执行的任务，每个任务都显示了当前的执行行。

通过悬停在任何方法上，可以看到所有运行任务的状态：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/2e011cbb-a479-477a-a1f6-37f32a3799a0.png)

任务窗口帮助我们分析应用程序中由于方法调用缓慢或死锁而引起的性能问题。

# 使用并行监视窗口进行调试

当我们想要在不同的线程上查看变量的值时，我们可以使用并行监视窗口。考虑以下代码：

```cs
for (int i = 0; i < 10; i++)
{
    Task task = new Task(() =>
     {
         for (int j = 0; j < 100; j++)
         {
             Thread.Sleep(100);
         }
         Console.WriteLine($"Thread with Id 
          {Thread.CurrentThread.ManagedThreadId}");
     });
    task.Start();
}
```

此代码创建多个任务，每个任务运行 100 次迭代的`for`循环。在每次迭代中，线程休眠 100 毫秒。我们允许代码运行一段时间，然后触发断点。我们可以使用并行监视窗口看到所有这些操作。我们可以从调试|窗口|并行监视中打开并行监视窗口。我们可以打开四个这样的窗口，每个窗口一次只能监视一个变量值在不同任务上的值：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/2aa59640-50d8-47ec-ae8f-c45cefea0358.png)

从前面的代码中可以看出，我们想要监视 j 的值。因此，我们在第三列的标题中写入 j 并按*Enter*键。这将 j 添加到此处显示的监视窗口中，我们可以看到所有线程/任务上的 j 的值。

# 使用并发可视化器

并发可视化器是 Visual Studio 工具集合中非常方便的一个补充。它不会默认随 Visual Studio 一起发布，但可以从 Visual Studio Marketplace 下载：[`marketplace.visualstudio.com`](https://marketplace.visualstudio.com)。

这是一个非常高级的工具，可以用于排除复杂的线程问题，比如性能瓶颈、线程争用问题、检查 CPU 利用率、跨核心线程迁移以及重叠 I/O 的区域。

并发可视化器仅支持 Windows/console 项目，不适用于 Web 项目。让我们考虑在控制台应用程序中的以下代码：

```cs
Action computeAction = () =>
{
int i = 0;
    while (true)
    {
        i = 1 * 1;
    }
};
Task.Run(() => computeAction());
Task.Run(() => computeAction());
Task.Run(() => computeAction());
Task.Run(() => computeAction());
```

在上述代码中，我们创建了四个任务，这些任务会无限期地运行计算任务，比如 1*1。然后我们会在`while`循环内设置断点并打开并发可视化器。

现在，我们将从 Visual Studio 运行上述代码，并在代码运行时，单击“附加到进程...”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/193721e2-bfcb-468a-a793-5871a25f28b5.png)

您首先需要为您的 Visual Studio 版本安装并发可视化器。Visual Studio 2017 的并发可视化器可以在这里找到：[`marketplace.visualstudio.com/items?itemName=VisualStudioProductTeam.ConcurrencyVisualizer2017#overview`](https://marketplace.visualstudio.com/items?itemName=VisualStudioProductTeam.ConcurrencyVisualizer2017#overview)。

一旦附加，并发可视化器将停止分析。我们将让应用程序运行一段时间，以便它可以收集足够的数据进行审查，然后停止分析器生成视图。

默认情况下，这将打开利用视图，这是并发可视化器中存在的三个视图之一。另外两个是线程和核心视图。我们将在下一节中探索利用视图。

# 利用视图

利用视图显示了所有处理器上的系统活动。这是并发分析器停止分析时的快照：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/3b4edc2d-78ac-477b-a15b-34dcd42de015.png)

正如您在上图中所看到的，有四个核心的 CPU 负载达到了 100%。这由绿色表示。这个视图通常用于获得并发状态的高级概述。

# 线程视图

线程视图提供了对当前系统状态的非常详细的分析。通过这个视图，我们可以确定线程是在执行还是在因 I/O 和同步等问题而阻塞：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/fe634fe0-30d4-4624-875c-63f3402e3a28.png)

这个视图在识别和修复系统中的性能瓶颈方面非常有帮助。因此，我们可以清楚地识别实际执行所花费的时间以及处理同步问题所花费的时间。

# 核心视图

核心视图可用于识别线程执行核心切换的次数：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/54c81a5c-71a2-4f56-8c7d-d1c69529ee7e.png)

正如您在上图中所看到的，我们的四个线程（ID 为 12112、1604、16928 和 4928）几乎 60%的时间在核心之间进行上下文切换。

掌握了并发可视化器中存在的所有三个视图的理解，我们已经结束了本章。现在，让我们总结一下我们学到的东西。

# 摘要

在本章中，我们讨论了如何使用线程窗口调试多线程应用程序，以监视.NET 环境捕获的无数信息。我们还学习了如何通过使用标志线程、在线程之间切换、在并行堆栈窗口中打开线程和任务视图、打开多个并行观察窗口以及观察一次多个任务上的单变量值来更好地了解应用程序。

除此之外，我们还探索了并发可视化器，这是一个用于排除仅支持 Windows/console 项目的复杂线程问题的高级工具。

在下一章中，我们将学习如何为并行和异步代码编写单元测试用例，以及与此相关的问题。此外，我们还将了解设置模拟对象涉及的挑战以及如何解决这些问题。

# 问题

1.  在 Visual Studio 中调试线程时，哪个不是有效窗口？

1.  并行线程

1.  并行堆栈

1.  GPU 线程

1.  并行监视

1.  我们可以通过标记来跟踪调试特定的线程。

1.  正确

1.  错误

1.  并行监视窗口中哪个不是有效视图？

1.  任务

1.  进程

1.  线程

1.  我们如何检查线程的调用堆栈？

1.  方法视图

1.  任务视图

1.  以下哪个不是并发可视化器的有效视图？

1.  线程视图

1.  核心视图

1.  进程视图

# 进一步阅读

您可以在以下链接中阅读有关并行编程和调试技术的信息：

+   [`www.packtpub.com/application-development/c-multithreaded-and-parallel-programming`](https://www.packtpub.com/application-development/c-multithreaded-and-parallel-programming)

+   [`www.packtpub.com/application-development/net-45-parallel-extensions-cookbook`](https://www.packtpub.com/application-development/net-45-parallel-extensions-cookbook)


# 第十一章：为并行和异步代码编写单元测试用例

在本章中，我们将介绍如何为并行和异步代码编写单元测试用例。编写单元测试用例是编写健壮代码的重要方面，当你与大型团队合作时，这样的代码更易于维护。

有了新的 CI/CD 平台，使运行单元测试用例成为构建过程的一部分变得更容易。这有助于在非常早期发现问题。编写集成测试也是有意义的，这样我们可以评估不同组件是否正确地一起工作。虽然在 Visual Studio 的社区和专业版本中会发现更多功能，但只有 Visual Studio 企业版支持分析单元测试用例的代码覆盖率。

在本章中，我们将涵盖以下主题：

+   了解为异步代码编写单元测试用例的问题

+   为并行和异步代码编写单元测试用例

+   使用 Moq 模拟异步代码的设置

+   使用测试工具

# 技术要求

学习如何使用 Visual Studio 支持的框架编写单元测试用例需要对单元测试和 C#有基本的了解。本章的源代码可以在 GitHub 上找到：[`github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter11`](https://github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter11)。

# 使用.NET Core 进行单元测试

.NET Core 支持三种编写单元测试的框架，即 MSTest、NUnit 和 xUnit，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/5237ca31-885c-432b-9361-5d3ae572ecec.png)

最初，编写测试用例的首选框架是 NUnit。然后，MSTest 被添加到 Visual Studio 中，然后 xUnit 被引入到.NET Core 中。与 NUnit 相比，xUnit 是一个非常精简的版本，并帮助用户编写干净的测试并利用新功能。xUnit 的一些好处如下：

+   它很轻量级。

+   它使用了新功能。

+   它改进了测试隔离。

+   xUnit 的创建者也来自微软，是微软内部使用的工具。

+   `Setup`和`TearDown`属性已被构造函数和`System.IDisposable`取代，从而迫使开发人员编写干净的代码。

单元测试用例只是一个简单的返回`void`的函数，用于测试函数逻辑并根据预定义的一组输入验证输出。为了使函数被识别为测试用例，必须使用`[Fact]`属性进行修饰，如下所示：

```cs
[Fact]
public void SomeFunctionWillReturn5AsWeUseResultToLetItFinish()
{
    var result = SomeFunction().Result;
    Assert.Equal(5, result);
}
```

要运行此测试用例，我们需要右键单击代码中的函数，然后单击“运行测试”或“调试测试”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/481b8095-a846-48c1-95e7-9ec15d692b72.png)

测试用例的执行输出可以在测试资源管理器窗口中看到：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/0c2e553e-e26e-4527-9f74-14522d4b2cb1.png)

虽然这相当简单，但为并行和异步代码编写单元测试用例是具有挑战性的。我们将在下一节中详细讨论这个问题。

# 了解为异步代码编写单元测试用例的问题

异步方法返回一个需要等待以获得结果的`Task`。如果不等待，方法将立即返回，而不会等待异步任务完成。考虑以下方法，我们将使用它来编写一个使用 xUnit 的单元测试用例：

```cs
private async Task<int> SomeFunction()
{
    int result =await Task.Run(() =>
    {
        Thread.Sleep(1000);
        return 5;
    });           
    return result;
}
```

该方法在延迟 1 秒后返回一个常量值 5。由于该方法使用了`Task`，我们使用了`async`和`await`关键字来获得预期的结果。以下是一个非常简单的测试用例，我们可以使用 MSTest 来测试这个方法：

```cs
[TestMethod]
public async void SomeFunctionShouldFailAsExpectedValueShouldBe5AndNot3()
{
    var result = await SomeFunction();
    Assert.AreEqual(3, result);
 }
```

如您所见，该方法应该失败，因为预期的返回值是 3，而方法返回的是 5。然而，当我们运行这个测试时，它通过了：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/83e88031-cd3f-4584-be32-5e41af5e4369.png)

这里发生的情况是，由于该方法标记为异步，当遇到`await`关键字时立即返回。当返回一个任务时，它被视为在将来的某个时间点运行，但由于测试用例没有失败而返回，测试框架将其标记为通过。这是一个重大问题，因为这意味着即使任务抛出异常，测试也会通过。

可以稍微不同地编写前面的测试用例以使其在 MSTest 中运行：

```cs
[TestMethod]
public void SomeFunctionWillReturn5AsWeUseResultToLetItFinish()
{
    var result = SomeFunction().Result;
    Assert.AreEqual(3, result);
}
```

可以使用 xUnit 编写相同的单元测试用例如下：

```cs
[Fact]
public void SomeFunctionWillReturn5AsWeUseResultToLetItFinish()
{
    var result = SomeFunction().Result;
    Assert.Equal(5, result);
}
```

当我们运行前面的 xUnit 测试用例时，它会成功运行。但是，这段代码的问题在于它是一个阻塞测试用例，这可能会对我们的测试套件的性能产生重大影响。更好的单元测试用例如下所示：

```cs
[Fact]
public async void SomeFunctionWillReturn5AsCallIsAwaited()
{
    var result = await SomeFunction();
    Assert.Equal(5, result);
}
```

最初，并非每个单元测试框架都支持异步单元测试用例，正如我们在 MSTest 的情况下所见。但是，它们受到 xUnit 和 NUnit 的支持。前面的测试用例再次返回成功。

可以使用 NUnit 编写上述单元测试用例如下：

```cs
[Test]
public async void SomeFunctionWillReturn5AsCallIsAwaited()
{
    var result = await SomeFunction();
    Assert.AreEqual(3, result);
}
```

与前面的代码相比，这里有一些区别。`[Fact]`属性被`[Test]`替换，而`Assert.Equal`被`Assert.AreEqual`替换。然而，当您尝试在 Visual Studio 中运行前面的测试用例时，您将看到一个错误：`"消息：异步测试方法必须具有非 void 返回类型"`。因此，对于 NUnit，方法需要更改如下：

```cs
[Test]
public async Task SomeFunctionWillReturn5AsCallIsAwaited()
{
    var result = await SomeFunction();
    Assert.AreEqual(3, result);
}
```

唯一的区别是`void`被`Task`替换。

在本节中，我们已经看到了在使用为单元测试提供的各种框架时可能会遇到的问题。现在，让我们看看如何编写更好的单元测试用例。

# 编写并行和异步代码的单元测试用例

在上一节中，我们学习了如何为异步代码编写单元测试用例。在本节中，我们将讨论为异常情况编写单元测试用例。考虑以下方法：

```cs
private async Task<float> GetDivisionAsync(int number , int divisor)
{
    if (divisor == 0)
    {
        throw new DivideByZeroException();
    }
    int result = await Task.Run(() =>
    {
        Thread.Sleep(1000);
        return number / divisor;
    });
    return result;
}
```

前面的方法以异步方式返回两个数字的除法结果。如果除数为 0，则该方法会抛出`DivideByZero`异常。我们需要两种类型的测试用例来覆盖这两种情况：

+   检查成功的结果

+   当除数为 0 时检查异常结果

# 检查成功的结果

测试用例如下所示：

```cs
[Test]
public async Task GetDivisionAsyncShouldReturnSuccessIfDivisorIsNotZero()
{
    int number = 20;
    int divisor = 4;
    var result = await GetDivisionAsync(number, divisor);
    Assert.AreEqual(result, 5);
}
```

如您所见，预期结果是`5`。当我们运行测试时，它将在测试资源管理器中显示为成功。

# 当除数为 0 时检查异常结果

我们可以使用`Assert.ThrowsAsync<>`方法为抛出异常的方法编写测试用例：

```cs
[Test]
public void GetDivisionAsyncShouldCheckForExceptionIfDivisorIsNotZero()
{
    int number = 20;
    int divisor = 0;
    Assert.ThrowsAsync<DivideByZeroException>(async () => 
     await GetDivisionAsync(number, divisor));
}
```

如您所见，我们在异步调用`GetDivisionAsync`方法时使用`Assert.ThrowsAsync<DivideByZeroException>`进行断言。由于我们将`divisor`传递为`0`，该方法将抛出异常，断言将保持为真。

# 使用 Moq 模拟异步代码的设置

模拟对象是单元测试的一个非常重要的方面。您可能知道，单元测试是关于一次测试一个模块；任何外部依赖都被假定为正常工作。

有许多可用于.NET 的模拟框架，包括以下内容：

+   NSubstitute（在.NET Core 中不受支持）

+   Rhino Mocks（在.NET Core 中不受支持）

+   Moq（在.NET Core 中受支持）

+   NMock3（在.NET Core 中不受支持）

为了演示，我们将使用 Moq 来模拟我们的服务组件。

在本节中，我们将创建一个包含异步方法的简单服务。然后，我们将尝试为调用该服务的方法编写单元测试用例。让我们考虑一个服务接口：

```cs
public interface IService
{
    Task<string> GetDataAsync();
}
```

正如我们所见，接口有一个`GetDataAsync()`方法，以异步方式获取数据。以下代码片段显示了一个控制器类，该类利用一些依赖注入框架来访问服务实例：

```cs
class Controller
{
    public Controller (IService service)
    {
        Service = service;
    }
    public IService Service { get; }
    public async Task DisplayData()
    {
        var data =await Service.GetDataAsync();
        Console.WriteLine(data);
    }
}
```

前面的`Controller`类还公开了一个名为`DisplayData()`的异步方法，该方法从服务中获取数据并将其写入控制台。当我们尝试为前述方法编写单元测试用例时，我们将遇到的第一个问题是，在没有任何具体实现的情况下，我们无法创建服务实例。即使我们有具体的实现，我们也应该避免调用实际的服务方法，因为这更适合集成测试用例而不是单元测试用例。在这里，Mocking 来拯救我们。

让我们尝试使用 Moq 为前述方法编写一个单元测试用例：

1.  我们需要安装`Moq`作为 NuGet 包。

1.  添加其命名空间如下：

```cs
using Moq;
```

1.  创建一个模拟对象，如下所示：

```cs
var serviceMock = new Mock<IService>();
```

1.  设置返回虚拟数据的模拟对象。可以使用`Task.FromResult`方法来实现，如下所示：

```cs
serviceMock.Setup(s => s.GetDataAsync()).Returns(
                Task.FromResult("Some Dummy Value"));
```

1.  接下来，我们需要通过传递刚刚创建的模拟对象来创建一个控制器对象：

```cs
var controller = new Controller(serviceMock.Object);
```

以下是`DisplayData()`方法的一个简单测试用例：

```cs
 [Test]
        public async System.Threading.Tasks.Task DisplayDataTestAsync()
        {
            var serviceMock = new Mock<IService>();
            serviceMock.Setup(s => s.GetDataAsync()).Returns(
                Task.FromResult("Some Dummy Value"));
            var controller = new Controller(serviceMock.Object);
            await controller.DisplayData();
        }
```

上述代码显示了我们如何为模拟对象设置数据。为模拟对象设置数据的另一种方法是通过`TaskCompletionSource`类，如下所示：

```cs
[Test]
public async Task DisplayDataTestAsyncUsingTaskCompletionSource()
{
    // Create a mock service
    var serviceMock = new Mock<IService>();
    string data = "Some Dummy Value";
    //Create task completion source
    var tcs = new TaskCompletionSource<string>();
    //Setup completion source to return test data
    tcs.SetResult(data);
    //Setup mock service object to return Task underlined by tcs 
    //when GetDataAsync method of service is called
    serviceMock.Setup(s => s.GetDataAsync()).Returns(tcs.Task);
    //Pass mock service instance to Controller
    var controller = new Controller(serviceMock.Object);
    //Call DisplayData method of controller asynchronously
    await controller.DisplayData();
}
```

由于企业项目中测试用例的数量可能会大幅增长，因此需要能够查找和执行测试用例。在下一节中，我们将讨论一些在 Visual Studio 中可以帮助我们管理测试用例执行过程的常见测试工具。

# 测试工具

在 Visual Studio 中运行测试或查看测试执行结果的最重要工具之一是 Test Explorer。我们在本章开头简要介绍了 Test Explorer。Test Explorer 的一个关键特性是能够并行运行测试用例。如果您的系统有多个核心，您可以轻松利用并行性来更快地运行测试用例。这可以通过在 Test Explorer 中点击“Run Tests in parallel”工具栏按钮来实现：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/1d4af856-f5cb-4377-858c-7b492f84903d.png)

根据您的 Visual Studio 版本，Microsoft 还提供了一些额外的支持。一个有用的工具是使用**Intellitest**自动生成单元测试用例的选项。Intellitest 分析您的源代码并自动生成测试用例、测试数据和测试套件。尽管 Intellitest 尚不支持.NET Core，但它适用于.NET Framework 的其他版本。它很可能会在未来的 Visual Studio 升级中得到支持。

# 摘要

在本章中，我们学习了为异步方法编写单元测试用例，这有助于实现健壮的代码，支持大型团队，并适应新的 CI/CD 平台，有助于在非常早期发现问题。我们首先介绍了在编写并行和异步代码的单元测试用例时可能遇到的一些问题，以及如何使用正确的编码实践来减轻这些问题。然后，我们继续学习了 Mocking，这是单元测试的一个非常重要的方面。

我们了解到 Moq 支持.NET Core，并且.NET Core 发展非常迅速；很快将支持所有主要的模拟框架。还解释了编写测试用例的所有步骤，包括安装 Moq 作为 NuGet 包和为模拟对象设置数据。最后，我们探讨了一个重要的测试工具 Test Explorer 的功能，我们可以使用它来编写更干净的测试用例，并且如何并行运行单元测试用例以加快执行速度。

在下一章中，我们将介绍 IIS 和 Kestrel 在.NET Core Web 应用程序开发环境中的概念和角色。

# 问题

1.  以下哪个不是 Visual Studio 中支持的单元测试框架？

1.  JUnit

1.  NUnit

1.  xUnit

1.  MSTest

1.  我们如何检查单元测试用例的输出？

1.  通过使用 Task Explorer 窗口

1.  通过使用 Test Explorer 窗口

1.  当测试框架是 xUnit 时，您可以将哪些属性应用于测试方法？

1.  事实

1.  TestMethod

1.  测试

1.  您如何验证抛出异常的测试用例的成功？

1.  `Assert.AreEqual(ex, typeof(Exception)`

1.  `Assert.IsException`

1.  `Assert.ThrowAsync<T>`

1.  这些模拟框架中哪些受到.NET Core 的支持？

1.  NSubstitute

1.  Moq

1.  Rhino Mocks

1.  NMock

# 进一步阅读

您可以在以下网页上了解并行编程和单元测试技术：

+   [`www.packtpub.com/application-development/c-multithreaded-and-parallel-programming`](https://www.packtpub.com/application-development/c-multithreaded-and-parallel-programming)

+   [`www.packtpub.com/application-development/net-45-parallel-extensions-cookbook`](https://www.packtpub.com/application-development/net-45-parallel-extensions-cookbook)
