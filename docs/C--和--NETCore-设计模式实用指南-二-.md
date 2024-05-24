# C# 和 .NETCore 设计模式实用指南（二）

> 原文：[`zh.annas-archive.org/md5/99BBE5B6F8F1801CD147129EA46FD82D`](https://zh.annas-archive.org/md5/99BBE5B6F8F1801CD147129EA46FD82D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：实施设计模式 - 基础知识第二部分

在上一章中，我们介绍了 FlixOne 以及新库存管理应用程序的初始开发。开发团队使用了多种模式，从旨在限制交付范围的模式（如**最小可行产品**（**MVP**））到辅助项目开发的模式（如**测试驱动开发**（**TDD**））。还应用了**四人帮**（**GoF**）的几种模式，作为解决方案，以利用他人过去解决类似问题的经验，以免重复常见错误。应用了单一责任原则、开闭原则、里氏替换原则、接口隔离原则和依赖反转原则（SOLID 原则），以确保我们正在创建一个稳定的代码库，将有助于管理和未来开发我们的应用程序。

本章将继续解释通过合并更多模式来构建 FlixOne 库存管理应用程序。将使用更多的 GoF 模式，包括单例模式和工厂模式。将使用单例模式来说明用于维护 FlixOne 图书收藏的存储库模式。工厂模式将进一步理解**依赖注入**（**DI**）。最后，我们将使用.NET Core 框架来促进**控制反转**（**IoC**）容器，该容器将用于完成初始库存管理控制台应用程序。

本章将涵盖以下主题：

+   单例模式

+   工厂模式

+   .NET Core 的特性

+   控制台应用程序

# 技术要求

本章包含各种代码示例，以解释这些概念。代码保持简单，仅用于演示目的。大多数示例涉及使用 C#编写的.NET Core 控制台应用程序。

要运行和执行代码，您需要以下内容：

+   Visual Studio 2019（您也可以使用 Visual Studio 2017 版本 3 或更高版本运行应用程序）

+   .NET Core

+   SQL Server（本章使用 Express Edition）

# 安装 Visual Studio

要运行这些代码示例，您需要安装 Visual Studio 或更高版本。您可以使用您喜欢的集成开发环境。要做到这一点，请按照以下说明进行操作：

1.  从以下链接下载 Visual Studio：[`docs.microsoft.com/en-us/visualstudio/install/install-visual-studio`](https://docs.microsoft.com/en-us/visualstudio/install/install-visual-studio)。

1.  按照包含的安装说明进行操作。安装 Visual Studio 有多个版本可供选择；在本章中，我们使用的是 Windows 版的 Visual Studio。

# .NET Core 的设置

如果您尚未安装.NET Core，则需要按照以下说明进行操作：

1.  从以下链接下载.NET Core：[`www.microsoft.com/net/download/windows`](https://www.microsoft.com/net/download/windows)。

1.  按照相关库的安装说明进行操作：[`dotnet.microsoft.com/download/dotnet-core/2.2`](https://dotnet.microsoft.com/download/dotnet-core/2.2)。

完整的源代码可在 GitHub 上找到。本章中显示的源代码可能不完整，因此建议您检索源代码以运行示例（[`github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter4`](https://github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter4)）。

# 单例模式

单例模式是另一个 GoF 设计模式，用于限制类的实例化为一个对象。它用于需要协调系统内的操作或限制对数据的访问的情况。例如，如果需要在应用程序内将对文件的访问限制为单个写入者，则可以使用单例模式防止多个对象同时尝试向文件写入。在我们的场景中，我们将使用单例模式来维护书籍及其库存的集合。

单例模式的价值在使用示例时更加明显。本节将从一个基本类开始，然后继续识别单例模式所解决的不同问题。这些问题将被识别出来，然后通过单元测试进行更新和验证。

单例模式应仅在必要时使用，因为它可能为应用程序引入潜在的瓶颈。有时，该模式被视为反模式，因为它引入了全局状态。全局状态会引入应用程序中的未知依赖关系，因此不清楚有多少类型可能依赖于该信息。此外，许多框架和存储库已经在需要时限制了访问，因此引入额外的机制可能会不必要地限制性能。

.NET Core 支持许多讨论的模式。在下一章中，我们将利用`ServiceCollection`类对工厂方法和单例模式的支持。

在我们的场景中，单例模式将用于保存包含书籍集合的内存存储库。单例将防止多个线程同时更新书籍集合。这将要求我们*锁定*代码的一部分，以防止不可预测的更新。

将单例引入应用程序的复杂性可能是微妙的；因此，为了对该模式有一个坚实的理解，我们将涵盖以下主题：

+   .Net Framework 对进程和线程的处理

+   存储库模式

+   竞争条件

+   单元测试以识别竞争条件

# 进程和线程

要理解单例模式，我们需要提供一些背景。在.Net Framework 中，一个应用程序将由称为应用程序域的轻量级托管子进程组成，这些子进程可以包含一个或多个托管线程。为了理解单例模式，让我们将其定义为包含一个或多个同时运行的线程的多线程应用程序。从技术上讲，这些线程实际上并不是同时运行的，而是通过在线程之间分配可用处理器时间来实现的，因此每个线程将执行一小段时间，然后该线程将暂停活动，从而允许另一个线程执行。

回到单例模式，在多线程应用程序中，需要特别注意确保对单例的访问受限，以便只有一个线程同时进入特定逻辑区域。由于线程的同步，一个线程可以检索值并更新它，然后在存储之前，另一个线程也更新该值。

多个线程可能访问相同的共享数据并以不可预测的结果进行更新，这可能被称为**竞争条件**。

为了避免数据被错误更新，需要一些限制，以防止多个线程同时执行相同的逻辑块。在.Net Framework 中支持几种机制，在单例模式中，使用`lock`关键字。在下面的代码中，演示了`lock`关键字，以表明一次只有一个线程可以执行突出显示的代码，而所有其他线程将被阻塞：

```cs
public class Inventory
{
   int _quantity;
    private Object _lock = new Object();

    public void RemoveQuantity(int amount)
    {
        lock (_lock)
        {
            if (_quantity - amount < 0)
 {
 throw new Exception("Cannot remove more than we have!");
 }
 _quantity -= amount;
        }
    }
}
```

锁是限制代码段访问的简单方法，可以应用于对象实例，就像我们之前的例子所示的那样，也可以应用于标记为静态的代码段。

# 存储库模式

引入到项目中的单例模式应用于用于维护库存书籍集合的类。单例将防止多个线程访问被错误处理，另一个模式存储库模式将用于创建一个外观，用于管理的数据。

存储库模式提供了一个存储库的抽象，以在应用程序的业务逻辑和底层数据之间提供一层。这提供了几个优势。通过进行清晰的分离，我们的业务逻辑可以独立于底层数据进行维护和单元测试。通常，相同的存储库模式类可以被多个业务对象重用。一个例子是`GetInventoryCommand`、`AddInventoryCommand`和`UpdateInventoryCommand`对象；所有这些对象都使用相同的存储库类。这使我们能够在不受存储库影响的情况下测试这些命令中的逻辑。该模式的另一个优势是，它使得更容易实现集中的数据相关策略，比如缓存。

首先，让我们考虑以下描述存储库将实现的方法的接口；它包含了检索书籍、添加书籍和更新书籍数量的方法：

```cs
internal interface IInventoryContext
{
    Book[] GetBooks();
    bool AddBook(string name);
    bool UpdateQuantity(string name, int quantity);
}
```

存储库的初始版本如下：

```cs
internal class InventoryContext : IInventoryContext
{ 
    public InventoryContext()
    {
        _books = new Dictionary<string, Book>();
    }

    private readonly IDictionary<string, Book> _books; 

    public Book[] GetBooks()
    {
        return _books.Values.ToArray();
    }

    public bool AddBook(string name)
    {
        _books.Add(name, new Book { Name = name });
        return true;
    }

    public bool UpdateQuantity(string name, int quantity)
    {
        _books[name].Quantity += quantity;
        return true;
    }
}
```

在本章中，书籍集合以内存缓存的形式进行维护，而在后续章节中，这将被移动到提供持久数据的存储库中。当然，这种实现并不理想，因为一旦应用程序结束，所有数据都将丢失。但是，它用来说明单例模式。

# 单元测试

为了说明单例模式解决的问题，让我们从一个简单的单元测试开始，向存储库添加 30 本书，更新不同书籍的数量，然后验证结果。以下代码显示了整体单元测试，我们将逐个解释每个步骤：

```cs
 [TestClass]
public class InventoryContextTests
{ 
    [TestMethod]
    public void MaintainBooks_Successful()
    { 
        var context = new InventoryContext();

        // add thirty books
        ...

        // let's update the quantity of the books by adding 1, 2, 3, 4, 5 ...
        ...

        // let's update the quantity of the books by subtracting 1, 2, 3, 4, 5 ...
        ...

        // all quantities should be 0
        ...
    } 
}
```

为了添加 30 本书，使用`context`实例从`Book_1`到`Book_30`添加书籍：

```cs
        // add thirty books
        foreach(var id in Enumerable.Range(1, 30))
        {
            context.AddBook($"Book_{id}"); 
        }
```

接下来的部分通过将数字`1`到`10`添加到每本书的数量来更新书籍数量：

```cs
        // let's update the quantity of the books by adding 1, 2, 3, 4, 5 ...
        foreach (var quantity in Enumerable.Range(1, 10))
        {
            foreach (var id in Enumerable.Range(1, 30))
            {
                context.UpdateQuantity($"Book_{id}", quantity);
            }
        }
```

然后，在下一部分，我们将从每本书的数量中减去数字`1`到`10`：

```cs
        foreach (var quantity in Enumerable.Range(1, 10))
        {
            foreach (var id in Enumerable.Range(1, 30))
            {
                context.UpdateQuantity($"Book_{id}", -quantity);
            }
        }
```

由于我们为每本书添加和移除了相同的数量，所以我们测试的最后部分将验证最终数量是否为`0`：

```cs
        // all quantities should be 0
        foreach (var book in context.GetBooks())
        {
            Assert.AreEqual(0, book.Quantity);
        }
```

运行测试后，我们可以看到测试通过了：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/9597d7f3-ef49-419f-b295-077228d9471e.png)

因此，当测试在单个进程中运行时，存储库将按预期工作。但是，如果更新请求在单独的线程中执行会怎样呢？为了测试这一点，单元测试将被重构为在单独的线程中对`InventoryContext`类进行调用。

书籍的添加被移动到一个执行添加书籍的方法中（即在自己的线程中）：

```cs
public Task AddBook(string book)
{
    return Task.Run(() =>
    {
        var context = new InventoryContext();
        Assert.IsTrue(context.AddBook(book));
    });
}
```

此外，更新数量步骤被移动到另一个具有类似方法的方法中：

```cs
public Task UpdateQuantity(string book, int quantity)
{
    return Task.Run(() =>
    {
        var context = new InventoryContext();
        Assert.IsTrue(context.UpdateQuantity(book, quantity));
    });
}
```

然后更新单元测试以调用新方法。值得注意的是，单元测试将等待所有书籍添加完成后再更新数量。

`添加三十本书`部分现在如下所示：

```cs
    // add thirty books
    foreach (var id in Enumerable.Range(1, 30))
    {
        tasks.Add(AddBook($"Book_{id}"));
    }

    Task.WaitAll(tasks.ToArray());
    tasks.Clear();
```

同样，更新数量被更改为在任务中调用`Add`和`subtract`方法：

```cs
    // let's update the quantity of the books by adding 1, 2, 3, 4, 5 ...
    foreach (var quantity in Enumerable.Range(1, 10))
    {
        foreach (var id in Enumerable.Range(1, 30))
        {
            tasks.Add(UpdateQuantity($"Book_{id}", quantity));
        }
    }

    // let's update the quantity of the books by subtractin 1, 2, 3, 4, 5 ...
    foreach (var quantity in Enumerable.Range(1, 10))
    {
        foreach (var id in Enumerable.Range(1, 30))
        {
            tasks.Add(UpdateQuantity($"Book_{id}", -quantity));
        }
    }

    // wait for all adds and subtracts to finish
    Task.WaitAll(tasks.ToArray());
```

重构后，单元测试不再成功完成，当单元测试现在运行时，会报告错误，指示在集合中找不到书籍。这将报告为“字典中未找到给定的键”。这是因为每次实例化上下文时，都会创建一个新的书籍集合。第一步是限制上下文的创建。这是通过更改构造函数的访问权限来完成的，以便该类不再可以直接实例化。相反，添加一个新的公共`static`属性，只支持`get`操作。该属性将返回`InventoryContext`类的底层`static`实例，并且如果实例丢失，将创建它：

```cs
internal class InventoryContext : IInventoryContext
{ 
    protected InventoryContext()
    {
        _books = new Dictionary<string, Book>();
    }

    private static InventoryContext _context;
    public static InventoryContext Singleton
    {
        get
        {
            if (_context == null)
            {
                _context = new InventoryContext();
            }

            return _context;
        }
    }
    ...
}    
```

这仍然不足以修复损坏的单元测试，但这是由于不同的原因。为了确定问题，单元测试在调试模式下运行，并在`UpdateQuantity`方法中设置断点。第一次运行时，我们可以看到已经创建了 28 本书并加载到书籍集合中，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/c1515640-71e6-43e4-a1f1-d0d8f21d063c.png)

在单元测试的这一点上，我们期望有 30 本书；然而，在我们开始调查之前，让我们再次运行单元测试。这一次，当我们尝试访问书籍集合以添加新书时，我们遇到了一个“对象引用未设置为对象的实例”错误，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/268b58d4-cbbe-4b12-9b77-df3b31df45db.png)

此外，当单元测试第三次运行时，不再遇到“对象引用未设置为对象的实例”错误，但我们的集合中只有 27 本书，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/46a4b8bc-48e9-4586-b1af-c64784920993.png)

这种不可预测的行为是竞争条件的典型特征，并且表明共享资源，即`InventoryContext`单例，正在被多个线程处理而没有同步访问。静态对象的构造仍然允许创建多个`InventoryContext`单例的实例：

```cs
public static InventoryContext Singleton
{
    get
    {
        if (_context == null)
        {
            _context = new InventoryContext();
        }

        return _context;
    }
}
```

竞争条件是多个线程评估`if`语句为真，并且它们都尝试构造`_context`对象。所有线程都会成功，但它们会通过这样做覆盖先前构造的值。当然，这是低效的，特别是当构造函数是昂贵的操作时，但单元测试发现的问题是`_context`对象实际上是由一个线程在另一个线程或多个线程更新书籍集合之后构造的。这就是为什么书籍集合`_books`在运行之间具有不同数量的元素。

为了防止这个问题，该模式在构造函数周围使用锁定，如下所示：

```cs
private static object _lock = new object();
public static InventoryContext Singleton
{
    get
    { 
        if (_context == null)
        {
 lock (_lock)
            {
                _context = new InventoryContext();
            }
        }

        return _context;
    }
}
```

不幸的是，单元测试仍然失败。这是因为虽然一次只有一个线程可以进入锁定，但所有被阻塞的实例仍然会在阻塞线程完成后进入锁定。该模式通过在锁定内部进行额外检查来处理这种情况，以防构造已经完成：

```cs
public static InventoryContext Singleton
{
    get
    { 
        if (_context == null)
        {
            lock (_lock)
            {
 if (_context == null)
                {
                    _context = new InventoryContext();
                }
            }
        }

        return _context;
    }
}
```

前面的锁定是必不可少的，因为它防止静态的`InventoryContext`对象被多次实例化。不幸的是，我们的测试仍然没有始终通过；随着每次更改，单元测试越来越接近通过。一些单元测试运行将在没有错误的情况下完成，但偶尔，测试将以失败的结果完成，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/8cf03f40-50e7-4459-8209-60388b3b9a71.png)

我们的静态存储库实例现在是线程安全的，但我们对书籍集合的访问不是。需要注意的一点是，所使用的`Dictionary`类不是线程安全的。幸运的是，.Net Framework 中有线程安全的集合可用。这些类确保了对集合的**添加和删除**是为多线程进程编写的。需要注意的是，只有添加和删除是线程安全的，因为这将在稍后变得重要。更新后的构造函数如下所示：

```cs
protected InventoryContext()
{
    _books = new ConcurrentDictionary<string, Book>();
}
```

微软建议在目标为.Net Framework 1.1 或更早版本的应用程序中，使用`System.Collections.Concurrent`中的线程安全集合，而不是`System.Collections`中对应的集合。

再次运行单元测试后，引入`ConcurrentDictionary`类仍然不足以防止书籍的错误维护。单元测试仍然失败。并发字典可以防止多个线程不可预测地添加和删除，但对集合中的项目本身没有任何保护。这意味着对集合中的对象的更新不是线程安全的。

让我们更仔细地看一下多线程环境中的竞争条件，以了解为什么会出现这种情况。

# 竞争条件示例

以下一系列图表描述了两个线程**ThreadA**和**ThreadB**之间概念上发生的情况。第一个图表显示了两个线程都没有从集合中获取任何值：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/fe27049f-ade1-485f-a255-bcd56290bbc6.png)

下图显示了两个线程都从名称为`Chester`的书籍集合中读取：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/b2b80704-df53-4c39-b3c5-e7176a6c2467.png)

下图显示了**ThreadA**通过增加`4`来更新书籍的数量，而**ThreadB**通过增加`3`来更新书籍的数量：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/b5a8650f-1f3d-4414-9109-f15046958d42.png)

然后，当更新后的书籍被持久化回集合时，我们得到了一个未知数量的结果，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/f4a99992-46d0-4eb7-a464-d82126476461.png)

为了避免这种竞争条件，我们需要在更新操作进行时阻止其他线程。在`InventoryContext`中，阻止其他线程的方法是在更新书籍数量时进行锁定：

```cs
public bool UpdateQuantity(string name, int quantity)
{
    lock (_lock)
    {
        _books[name].Quantity += quantity;
    }

    return true;
}
```

单元测试现在可以顺利完成，因为额外的锁定防止了不可预测的竞争条件。

`InventoryContext`类仍然不完整，因为它只是完成了足够的部分来说明单例和存储库模式。在后面的章节中，`InventoryContext`类将被改进以使用 Entity Framework，这是一个**对象关系映射**（**ORM**）框架。此时，`InventoryContext`类将被改进以支持额外的功能。

# AddInventoryCommand

有了我们的存储库后，三个`InventoryCommand`类可以完成。首先是`AddInventoryCommand`，如下所示：

```cs
internal class AddInventoryCommand : NonTerminatingCommand, IParameterisedCommand
{
    private readonly IInventoryContext _context;

    internal AddInventoryCommand(IUserInterface userInterface, IInventoryContext context) 
                                                            : base(userInterface)
    {
        _context = context;
    }

    public string InventoryName { get; private set; }

    /// <summary>
    /// AddInventoryCommand requires name
    /// </summary>
    /// <returns></returns>
    public bool GetParameters()
    {
        if (string.IsNullOrWhiteSpace(InventoryName))
            InventoryName = GetParameter("name");

        return !string.IsNullOrWhiteSpace(InventoryName);
    }

    protected override bool InternalCommand()
    {
        return _context.AddBook(InventoryName); 
    }
}
```

首先要注意的是，存储库`IInventoryContext`在构造函数中与前一章描述的`IUserInterface`接口一起被注入。命令还需要提供一个参数，即`name`*，*这在实现了前一章中也涵盖的`IParameterisedCommand`接口的`GetParameters`方法中被检索。然后在`InternalCommand`方法中运行命令，该方法简单地在存储库上执行`AddBook`方法，并返回一个指示命令是否成功执行的布尔值。

# TestInventoryContext

与上一章中使用的`TestUserInterface`类类似，`TestInventoryContext`类将用于模拟我们的存储库的行为，实现`IInventoryContext`接口。该类将支持接口的三种方法，以及支持在单元测试期间添加到集合中的两种附加方法和更新的书籍。

为了支持`TestInventoryContext`类，将使用两个集合：

```cs
private readonly IDictionary<string, Book> _seedDictionary;
private readonly IDictionary<string, Book> _books;
```

第一个用于存储书籍的起始集合，而第二个用于存储书籍的最终集合。构造函数如下所示；请注意字典是彼此的副本：

```cs
public TestInventoryContext(IDictionary<string, Book> books)
{
    _seedDictionary = books.ToDictionary(book => book.Key,
                                         book => new Book { Id = book.Value.Id, 
                                                            Name = book.Value.Name, 
                                                            Quantity = book.Value.Quantity });
    _books = books;
}
```

`IInventoryContext`方法被编写为更新和返回集合中的一本书，如下所示：

```cs
public Book[] GetBooks()
{
    return _books.Values.ToArray();
}

public bool AddBook(string name)
{
    _books.Add(name, new Book() { Name = name });

    return true;
}

public bool UpdateQuantity(string name, int quantity)
{
    _books[name].Quantity += quantity;

    return true;
}
```

在单元测试结束时，可以使用剩余的两种方法来确定起始和结束集合之间的差异：

```cs
public Book[] GetAddedBooks()
{
    return _books.Where(book => !_seedDictionary.ContainsKey(book.Key))
                                                    .Select(book => book.Value).ToArray();
}

public Book[] GetUpdatedBooks()
{ 
    return _books.Where(book => _seedDictionary[book.Key].Quantity != book.Value.Quantity)
                                                    .Select(book => book.Value).ToArray();
}
```

在软件行业中，关于模拟、存根、伪造和其他用于识别和/或分类测试中使用的类型或服务的差异存在一些混淆，这些类型或服务不适用于生产，但对于单元测试是必要的。这些依赖项可能具有与其*真实*对应项不同、缺失和/或相同的功能。

例如，`TestUserInterface`类可以被称为模拟，因为它提供了对单元测试的一些期望（例如，断言语句），而`TestInventoryContext`类将是伪造的，因为它提供了一个工作实现。在本书中，我们不会严格遵循这些分类。

# AddInventoryCommandTest

团队已经更新了`AddInventoryCommandTest`来验证`AddInventoryCommand`的功能。此测试将验证向现有库存中添加一本书。测试的第一部分是定义接口的预期，这只是一个单独的提示，用于接收新书名（请记住`TestUserInterface`类需要三个参数：预期输入、预期消息和预期警告）：

```cs
const string expectedBookName = "AddInventoryUnitTest";
var expectedInterface = new Helpers.TestUserInterface(
    new List<Tuple<string, string>>
    {
        new Tuple<string, string>("Enter name:", expectedBookName)
    },
    new List<string>(),
    new List<string>()
);
```

`TestInventoryContext`类将初始化为模拟现有书籍集合中的一本书：

```cs
var context = new TestInventoryContext(new Dictionary<string, Book>
{
    { "Gremlins", new Book { Id = 1, Name = "Gremlins", Quantity = 7 } }
});
```

以下代码片段显示了`AddInventoryCommand`的创建、命令的运行以及用于验证命令成功运行的断言语句：

```cs
// create an instance of the command
var command = new AddInventoryCommand(expectedInterface, context);

// add a new book with parameter "name"
var result = command.RunCommand();

Assert.IsFalse(result.shouldQuit, "AddInventory is not a terminating command.");
Assert.IsTrue(result.wasSuccessful, "AddInventory did not complete Successfully.");

// verify the book was added with the given name with 0 quantity
Assert.AreEqual(1, context.GetAddedBooks().Length, "AddInventory should have added one new book.");

var newBook = context.GetAddedBooks().First();
Assert.AreEqual(expectedBookName, newBook.Name, "AddInventory did not add book successfully."); 
```

命令运行后，将验证结果是否无错误运行，并且命令不是终止命令。`Assert`语句的其余部分验证了预期只添加了一本带有预期名称的书。

# UpdateQuantityCommand

`UpdateQuantityCommand`与`AddInventoryCommand`非常相似，其源代码如下：

```cs
internal class UpdateQuantityCommand : NonTerminatingCommand, IParameterisedCommand
{
    private readonly IInventoryContext _context; 

    internal UpdateQuantityCommand(IUserInterface userInterface, IInventoryContext context) 
                                                                            : base(userInterface)
    {
        _context = context;
    }

    internal string InventoryName { get; private set; }

    private int _quantity;
    internal int Quantity { get => _quantity; private set => _quantity = value; }

    ...
}
```

与`AddInventoryCommand`一样，`UpdateInventoryCommand`命令是一个带参数的非终止命令。因此，它扩展了`NonTerminatingCommand`基类，并实现了`IParameterisedCommand`接口。同样，`IUserInterface`和`IInventoryContext`的依赖项在构造函数中注入：

```cs
    /// <summary>
    /// UpdateQuantity requires name and an integer value
    /// </summary>
    /// <returns></returns>
    public bool GetParameters()
    {
        if (string.IsNullOrWhiteSpace(InventoryName))
            InventoryName = GetParameter("name");

        if (Quantity == 0)
            int.TryParse(GetParameter("quantity"), out _quantity);

        return !string.IsNullOrWhiteSpace(InventoryName) && Quantity != 0;
    }   
```

`UpdateQuantityCommand`类确实具有一个额外的参数*quantity*，该参数是作为`GetParameters`方法的一部分确定的。

最后，通过存储库的`InternalCommand`重写方法，更新书的数量：

```cs
    protected override bool InternalCommand()
    {
        return _context.UpdateQuantity(InventoryName, Quantity);
    }
```

现在`UpdateQuantityCommand`类已经定义，接下来的部分将添加一个单元测试来验证该命令。

# UpdateQuantityCommandTest

`UpdateQuantityCommandTest`包含一个测试，用于验证在现有集合中更新书籍的情景。预期接口和现有集合的创建如下代码所示（请注意，测试涉及将`6`添加到现有书的数量）：

```cs
const string expectedBookName = "UpdateQuantityUnitTest";
var expectedInterface = new Helpers.TestUserInterface(
    new List<Tuple<string, string>>
    {
        new Tuple<string, string>("Enter name:", expectedBookName),
        new Tuple<string, string>("Enter quantity:", "6")
    },
    new List<string>(),
    new List<string>()
);

var context = new TestInventoryContext(new Dictionary<string, Book>
{
    { "Beavers", new Book { Id = 1, Name = "Beavers", Quantity = 3 } },
    { expectedBookName, new Book { Id = 2, Name = expectedBookName, Quantity = 7 } },
    { "Ducks", new Book { Id = 3, Name = "Ducks", Quantity = 12 } }
});
```

下面的代码块显示了命令的运行以及非终止命令成功运行的初始验证：

```cs
// create an instance of the command
var command = new UpdateQuantityCommand(expectedInterface, context);

var result = command.RunCommand();

Assert.IsFalse(result.shouldQuit, "UpdateQuantity is not a terminating command.");
Assert.IsTrue(result.wasSuccessful, "UpdateQuantity did not complete Successfully.");
```

测试的期望是不会添加新书籍，并且现有书籍的数量为 7，将增加 6，结果为新数量为 13：

```cs
Assert.AreEqual(0, context.GetAddedBooks().Length, 
                    "UpdateQuantity should not have added one new book.");

var updatedBooks = context.GetUpdatedBooks();
Assert.AreEqual(1, updatedBooks.Length, 
                    "UpdateQuantity should have updated one new book.");
Assert.AreEqual(expectedBookName, updatedBooks.First().Name, 
                    "UpdateQuantity did not update the correct book.");
Assert.AreEqual(13, updatedBooks.First().Quantity, 
                    "UpdateQuantity did not update book quantity successfully.");
```

添加了 `UpdateQuantityCommand` 类后，将在下一节中添加检索库存的能力。

# GetInventoryCommand

`GetInventoryCommand` 命令与前两个命令不同，因为它不需要任何参数。它使用 `IUserInterface` 依赖项和 `IInventoryContext` 依赖项来写入集合的内容。如下所示：

```cs
internal class GetInventoryCommand : NonTerminatingCommand
{
    private readonly IInventoryContext _context;
    internal GetInventoryCommand(IUserInterface userInterface, IInventoryContext context) 
                                                           : base(userInterface)
    {
        _context = context;
    }

    protected override bool InternalCommand()
    {
        foreach (var book in _context.GetBooks())
        {
            Interface.WriteMessage($"{book.Name,-30}\tQuantity:{book.Quantity}"); 
        }

        return true;
    }
}
```

实现了 `GetInventoryCommand` 命令后，下一步是添加一个新的测试。

# GetInventoryCommandTest

`GetInventoryCommandTest` 涵盖了当使用 `GetInventoryCommand` 命令检索书籍集合时的场景。测试将定义预期的消息（记住，第一个参数是用于参数，第二个参数是用于消息，第三个参数是用于警告），这些消息将在测试用户界面时发生：

```cs
var expectedInterface = new Helpers.TestUserInterface(
    new List<Tuple<string, string>>(),
    new List<string>
    {
        "Gremlins                      \tQuantity:7",
        "Willowsong                    \tQuantity:3",
    },
    new List<string>()
);
```

这些消息将对应于模拟存储库，如下所示：

```cs
var context = new TestInventoryContext(new Dictionary<string, Book>
{
    { "Gremlins", new Book { Id = 1, Name = "Gremlins", Quantity = 7 } },
    { "Willowsong", new Book { Id = 2, Name = "Willowsong", Quantity = 3 } },
});
```

单元测试使用模拟依赖项运行命令。它验证命令是否无错误执行，并且命令不是终止命令：

```cs
// create an instance of the command
var command = new GetInventoryCommand(expectedInterface, context); 
var result = command.RunCommand();

Assert.IsFalse(result.shouldQuit, "GetInventory is not a terminating command.");
```

预期的消息在 `TestUserInterface` 中进行验证，因此单元测试剩下的唯一任务就是确保命令没有神秘地添加或更新书籍：

```cs
Assert.AreEqual(0, context.GetAddedBooks().Length, "GetInventory should not have added any books.");
Assert.AreEqual(0, context.GetUpdatedBooks().Length, "GetInventory should not have updated any books.");
```

现在已经添加了适合 `GetInventoryCommand` 类的单元测试，我们将引入工厂模式来管理特定命令的创建。

# 工厂模式

团队应用的下一个模式是 GoF 工厂模式。该模式引入了一个**创建者**，其责任是实例化特定类型的实现。它的目的是封装围绕构造类型的复杂性。工厂模式允许更灵活地应对应用程序的变化，通过限制所需更改的数量，而不是在调用类中进行构造。这是因为构造的复杂性在一个位置，而不是分布在应用程序的多个位置。

在 FlixOne 示例中，`InventoryCommandFactory` 实现了该模式，并屏蔽了构造每个不同的 `InventoryCommand` 实例的细节。在这种情况下，从控制台应用程序接收到的输入将用于确定要返回的 `InventoryCommand` 的具体实现。重要的是要注意返回类型是 `InventoryCommand` 抽象类，因此屏蔽了调用类对具体类的细节。

`InventoryCommandFactory` 在下面的代码块中显示。但是，现在专注于 `GetCommand` 方法，因为它实现了工厂模式：

```cs
public class InventoryCommandFactory : IInventoryCommandFactory
{
    private readonly IUserInterface _userInterface;
    private readonly IInventoryContext _context = InventoryContext.Instance;

    public InventoryCommandFactory(IUserInterface userInterface)
    {
        _userInterface = userInterface;
    }

    ...
}
```

`GetCommand` 使用给定的字符串来确定要返回的 `InventoryCommand` 的特定实现：

```cs
public InventoryCommand GetCommand(string input)
{
    switch (input)
    {
        case "q":
        case "quit":
            return new QuitCommand(_userInterface);
        case "a":
        case "addinventory":
            return new AddInventoryCommand(_userInterface, _context);
        case "g":
        case "getinventory":
            return new GetInventoryCommand(_userInterface, _context);
        case "u":
        case "updatequantity":
            return new UpdateQuantityCommand(_userInterface, _context);
        case "?":
            return new HelpCommand(_userInterface);
        default:
            return new UnknownCommand(_userInterface);
    }
}
```

所有命令都需要提供 `IUserInterface`，但有些还需要访问存储库。这些将使用 `IInventoryContext` 的单例实例提供。

工厂模式通常与接口一起使用作为返回类型。在这里，它被说明为 `InventoryCommand` 基类。

# 单元测试

乍一看，为这样一个简单的类构建单元测试似乎是团队时间的浪费。通过构建单元测试，发现了两个重要问题，这些问题可能会被忽略。

# 问题一 - UnknownCommand

第一个问题是当接收到一个不匹配任何已定义的 `InventoryCommand` 输入的命令时该怎么办。在审查要求后，团队注意到他们错过了这个要求，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/2609a169-37d7-4a74-8aac-65d25b8c1a77.png)

团队决定引入一个新的`InventoryCommand`类，`UnknownCommand`，来处理这种情况。 `UnknownCommand`类应该通过`IUserInterface`的`WriteWarning`方法向控制台打印警告消息，不应导致应用程序结束，并且应返回 false 以指示命令未成功运行。 实现细节如下所示：

```cs
internal class UnknownCommand : NonTerminatingCommand
{ 
    internal UnknownCommand(IUserInterface userInterface) : base(userInterface)
    {
    }

    protected override bool InternalCommand()
    { 
        Interface.WriteWarning("Unable to determine the desired command."); 

        return false;
    }
}
```

为`UnknownCommand`创建的单元测试将测试警告消息以及`InternalCommand`方法返回的两个布尔值：

```cs
[TestClass]
public class UnknownCommandTests
{
    [TestMethod]
    public void UnknownCommand_Successful()
    {
        var expectedInterface = new Helpers.TestUserInterface(
            new List<Tuple<string, string>>(),
            new List<string>(),
            new List<string>
            {
                "Unable to determine the desired command."
            }
        ); 

        // create an instance of the command
        var command = new UnknownCommand(expectedInterface);

        var result = command.RunCommand();

        Assert.IsFalse(result.shouldQuit, "Unknown is not a terminating command.");
        Assert.IsFalse(result.wasSuccessful, "Unknown should not complete Successfully.");
    }
}
```

`UnknownCommandTests`覆盖了需要测试的命令。 接下来，将实现围绕`InventoryCommandFactory`的测试。

# InventoryCommandFactoryTests

`InventoryCommandFactoryTests`包含与`InventoryCommandFactory`相关的单元测试。 因为每个测试都将具有类似的模式，即构造`InventoryCommandFactory`及其`IUserInterface`依赖项，然后运行`GetCommand`方法，因此创建了一个共享方法，该方法将在测试初始化时运行：

```cs
[TestInitialize]
public void Initialize()
{
    var expectedInterface = new Helpers.TestUserInterface(
        new List<Tuple<string, string>>(),
        new List<string>(),
        new List<string>()
    ); 

    Factory = new InventoryCommandFactory(expectedInterface);
}
```

`Initialize`方法构造了一个存根`IUserInterface`并设置了`Factory`属性。 然后，各个单元测试采用简单的形式，验证返回的对象是否是正确的类型。 首先，当用户输入`"q"`或`"quit"`时，应返回`QuitCommand`类的实例，如下所示：

```cs
[TestMethod]
public void QuitCommand_Successful()
{ 
    Assert.IsInstanceOfType(Factory.GetCommand("q"), typeof(QuitCommand), 
                                                            "q should be QuitCommand");
    Assert.IsInstanceOfType(Factory.GetCommand("quit"), typeof(QuitCommand), 
                                                            "quit should be QuitCommand");
}
```

`QuitCommand_Successful`测试方法验证了当运行`InventoryCommandFactory`方法`GetCommand`时，返回的对象是`QuitCommand`类型的特定实例。 当提交`"?"`时，`HelpCommand`才可用：

```cs
[TestMethod]
public void HelpCommand_Successful()
{
    Assert.IsInstanceOfType(Factory.GetCommand("?"), typeof(HelpCommand), "h should be HelpCommand"); 
}
```

团队确实添加了一个针对`UnknownCommand`的测试，验证了当给出与现有命令不匹配的值时，`InventoryCommand`将如何响应：

```cs
[TestMethod]
public void UnknownCommand_Successful()
{
    Assert.IsInstanceOfType(Factory.GetCommand("add"), typeof(UnknownCommand), 
                                                        "unmatched command should be UnknownCommand");
    Assert.IsInstanceOfType(Factory.GetCommand("addinventry"), typeof(UnknownCommand), 
                                                        "unmatched command should be UnknownCommand");
    Assert.IsInstanceOfType(Factory.GetCommand("h"), typeof(UnknownCommand), 
                                                        "unmatched command should be UnknownCommand");
    Assert.IsInstanceOfType(Factory.GetCommand("help"), typeof(UnknownCommand), 
                                                        "unmatched command should be UnknownCommand");
}
```

有了测试方法，现在我们可以涵盖一种情况，即在应用程序中给出一个不匹配已知命令的命令。

# 问题二 - 不区分大小写的文本命令

第二个问题是在再次审查要求时发现的，即命令不应区分大小写：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/10cf9ef0-f9f0-459d-969c-1ded9e9e093e.png)

通过对`UpdateInventoryCommand`的测试，发现`InventoryCommandFactory`在以下测试中是区分大小写的：

```cs
[TestMethod]
public void UpdateQuantityCommand_Successful()
{
    Assert.IsInstanceOfType(Factory.GetCommand("u"), 
                            typeof(UpdateQuantityCommand), 
                            "u should be UpdateQuantityCommand");
    Assert.IsInstanceOfType(Factory.GetCommand("updatequantity"), 
                            typeof(UpdateQuantityCommand), 
                            "updatequantity should be UpdateQuantityCommand");
    Assert.IsInstanceOfType(Factory.GetCommand("UpdaTEQuantity"), 
                            typeof(UpdateQuantityCommand), 
                            "UpdaTEQuantity should be UpdateQuantityCommand");
}
```

幸运的是，通过在确定命令之前对输入应用`ToLower()`方法，这个测试很容易解决，如下所示：

```cs
public InventoryCommand GetCommand(string input)
{
    switch (input.ToLower())
    {
        ...
    }
}
```

这种情况突出了`Factory`方法的价值以及利用单元测试来帮助验证开发过程中的需求的价值，而不是依赖用户测试。

# .NET Core 中的功能

第三章，*实现设计模式 - 基础部分 1*，以及本章的第一部分已经演示了 GoF 模式，而没有使用任何框架。 有必要覆盖这一点，因为有时针对特定模式可能没有可用的框架，或者在特定场景中不适用。 此外，了解框架提供的功能是很重要的，以便知道何时应该使用某种模式。 本章的其余部分将介绍.NET Core 提供的一些功能，支持我们迄今为止已经涵盖的一些模式。

# IServiceCollection

.NET Core 设计时内置了**依赖注入**（**DI**）。 通常，.NET Core 应用程序的启动包含为应用程序设置 DI 的过程，主要包括创建服务集合。 框架在应用程序需要时使用这些服务来提供依赖项。 这些服务为强大的**控制反转**（**IoC**）框架奠定了基础，并且可以说是.NET Core 最酷的功能之一。 本节将完成控制台应用程序，并演示.NET Core 如何基于`IServiceCollection`接口支持构建复杂的 IoC 框架。

`IServiceCollection`接口用于定义容器中可用的服务，该容器实现了`IServiceProvider`接口。这些服务本身是在应用程序需要时在运行时注入的类型。例如，之前定义的`ConsoleUserInterface`接口将在运行时作为服务注入。这在下面的代码中显示：

```cs
IServiceCollection services = new ServiceCollection();
services.AddTransient<IUserInterface, ConsoleUserInterface>();
```

在上述代码中，`ConsoleUserInterface`接口被添加为实现`IUserInterface`接口的服务。如果 DI 提供了另一种需要`IUserInterface`接口依赖的类型，那么将使用`ConsoleUserInterface`接口。例如，`InventoryCommandFactory`也被添加到服务中，如下面的代码所示：

```cs
services.AddTransient<IInventoryCommandFactory, InventoryCommandFactory>();
```

`InventoryCommandFactory`有一个需要`IUserInterface`接口实现的构造函数：

```cs
public class InventoryCommandFactory : IInventoryCommandFactory
{
    private readonly IUserInterface _userInterface;

    public InventoryCommandFactory(IUserInterface userInterface)
    {
        _userInterface = userInterface;
    }
    ...
}
```

稍后，请求一个`InventoryCommandFactory`的实例，如下所示：

```cs
IServiceProvider serviceProvider = services.BuildServiceProvider();
var service = serviceProvider.GetService<IInventoryCommandFactory>();
service.GetCommand("a");
```

然后，`IUserInterface`的一个实例（在这个应用程序中是注册的`ConsoleUserInterface`）被实例化并提供给`InventoryCommandFactory`的构造函数。

在注册服务时可以指定不同类型的服务*生命周期*。生命周期规定了类型将如何实例化，包括瞬态、作用域和单例。瞬态意味着每次请求时都会创建服务。作用域将在后面讨论，特别是在查看与网站相关的模式时，服务是按照网页请求创建的。单例的行为类似于我们之前讨论的单例模式，并且将在本章后面进行讨论。

# CatalogService

`CatalogService`接口代表团队正在构建的控制台应用程序，并被描述为具有一个`Run`方法，如`ICatalogService`接口中所示：

```cs
interface ICatalogService
{
    void Run();
}
```

该服务有两个依赖项，`IUserInterface`和`IInventoryCommandFactory`，它们将被注入到构造函数中并存储为局部变量：

```cs
public class CatalogService : ICatalogService
{
    private readonly IUserInterface _userInterface;
    private readonly IInventoryCommandFactory _commandFactory;

    public CatalogService(IUserInterface userInterface, IInventoryCommandFactory commandFactory)
    {
        _userInterface = userInterface;
        _commandFactory = commandFactory;
    }
    ...
}
```

`Run`方法基于团队在第三章中展示的早期设计。它打印一个问候语，然后循环，直到用户输入退出库存命令为止。每次循环都会执行命令，如果命令不成功，它将打印一个帮助消息：

```cs
public void Run()
{
    Greeting();

    var response = _commandFactory.GetCommand("?").RunCommand();

    while (!response.shouldQuit)
    {
        // look at this mistake with the ToLower()
        var input = _userInterface.ReadValue("> ").ToLower();
        var command = _commandFactory.GetCommand(input);

        response = command.RunCommand();

        if (!response.wasSuccessful)
        {
            _userInterface.WriteMessage("Enter ? to view options.");
        }
    }
}
```

现在我们已经准备好了`CatalogService`接口，下一步将是把所有东西放在一起。下一节将使用.NET Core 来完成这一点。

# IServiceProvider

有了`CatalogService`定义，团队最终能够在.NET Core 中将所有东西放在一起。所有应用程序的开始，即 EXE 程序，都是`Main`方法，.NET Core 也不例外。程序如下所示：

```cs
class Program
{
    private static void Main(string[] args)
    {
        IServiceCollection services = new ServiceCollection();
        ConfigureServices(services);
        IServiceProvider serviceProvider = services.BuildServiceProvider();

        var service = serviceProvider.GetService<ICatalogService>();
        service.Run();

        Console.WriteLine("CatalogService has completed.");
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        // Add application services.
        services.AddTransient<IUserInterface, ConsoleUserInterface>(); 
        services.AddTransient<ICatalogService, CatalogService>();
        services.AddTransient<IInventoryCommandFactory, InventoryCommandFactory>(); 
    }
}
```

在`ConfigureServices`方法中，不同类型被添加到 IoC 容器中，包括`ConsoleUserInterface`、`CatalogService`和`InventoryCommandFactory`类。`ConsoleUserInterface`和`InventoryCommandFactory`类将根据需要注入，而`CatalogService`类将从`ServiceCollection`对象中包含的添加类型构建的`IServiceProvider`接口中显式检索出来。程序将一直运行，直到`CatalogService`的`Run`方法完成。

在第五章中，*实现设计模式-.NET Core*，将重新讨论单例模式，使用.NET Core 内置的能力，通过使用`IServiceCollection`的`AddSingleton`方法来控制`InventoryContext`实例。

# 控制台应用程序

控制台应用程序在命令行中运行时很简单，但它是一个遵循 SOLID 原则的良好设计代码的基础，这些原则在第三章中讨论过，*实现设计模式-基础部分 1*。运行时，应用程序提供一个简单的问候，并显示一个帮助消息，包括命令的支持和示例：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/2b227f12-9b64-4501-9190-7385cf1f6d34.png)

然后应用程序循环执行命令，直到收到退出命令。以下屏幕截图说明了其功能：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/23375dec-001c-4064-9278-19da5d745827.png)

这并不是最令人印象深刻的控制台应用程序，但它用来说明了许多原则和模式。

# 摘要

与第三章类似，*实现设计模式-基础部分 1*，本章继续描述了为 FlixOne 构建库存管理控制台应用程序，以展示使用面向对象编程（OOP）设计模式的实际示例。在本章中，GoF 的单例模式和工厂模式是重点。这两种模式在.NET Core 应用程序中起着特别重要的作用，并将在接下来的章节中经常使用。本章还介绍了使用内置框架提供 IoC 容器的方法。

本章以一个符合第三章 *实现设计模式-基础部分 1*中确定的要求的工作库存管理控制台应用程序结束。这些要求是两章中创建的单元测试的基础，并用于说明 TDD。通过拥有一套验证本开发阶段所需功能的测试，团队对应用程序能够通过用户验收测试（UAT）有更高的信心。

在下一章中，我们将继续描述构建库存管理应用程序。重点将从基本的面向对象编程模式转移到使用.NET Core 框架来实现不同的模式。例如，本章介绍的单例模式将被重构以利用`IServiceCollection`的能力来创建单例，我们还将更仔细地研究其依赖注入能力。此外，该应用程序将扩展以支持使用各种日志提供程序进行日志记录。

# 问题

以下问题将帮助您巩固本章中包含的信息：

1.  提供一个例子，说明为什么使用单例模式不是限制访问共享资源的好机制。

1.  以下陈述是否正确？为什么？`ConcurrentDictionary`可以防止集合中的项目被多个线程同时更新。

1.  什么是竞态条件，为什么应该避免？

1.  工厂模式如何帮助简化代码？

1.  .NET Core 应用程序需要第三方 IoC 容器吗？


# 第五章：实现设计模式-.NET Core

上一章继续构建 FlixOne 库存管理应用程序，同时还包括其他模式。使用了更多的四人帮模式，包括 Singleton 和 Factory 模式。Singleton 模式用于说明用于维护 FlixOne 图书集合的 Repository 模式。Factory 模式用于进一步探索**依赖注入**（**DI**）。使用.NET Core 框架完成了初始库存管理控制台应用程序，以便实现**控制反转**（**IoC**）容器。

本章将继续构建库存管理控制台应用程序，同时还将探索.NET Core 的特性。将重新访问并创建上一章中介绍的 Singleton 模式，使用内置于.NET Core 框架中的 Singleton 服务生命周期。将展示使用框架的 DI 的配置模式，以及使用不同示例解释**构造函数注入（CI）**。

本章将涵盖以下主题：

+   .Net Core 服务生命周期

+   实现工厂

# 技术要求

本章包含用于解释概念的各种代码示例。代码保持简单，仅用于演示目的。大多数示例涉及使用 C#编写的.NET Core 控制台应用程序。

要运行和执行代码，您需要以下内容：

+   Visual Studio 2019（您也可以使用 Visual Studio 2017 版本 3 或更高版本运行应用程序）。

+   设置.NET Core。

+   SQL Server（本章中使用的是 Express 版本）。

# 安装 Visual Studio

要运行这些代码示例，您需要安装 Visual Studio 2010 或更高版本。您可以使用您喜欢的 IDE。要做到这一点，请按照以下说明进行操作：

1.  从以下链接下载 Visual Studio：[`docs.microsoft.com/en-us/visualstudio/install/install-visual-studio`](https://docs.microsoft.com/en-us/visualstudio/install/install-visual-studio)。

1.  按照包含的安装说明进行操作。Visual Studio 有多个版本可供安装。在本章中，我们使用的是 Windows 版的 Visual Studio。

# 设置.NET Core

如果您没有安装.NET Core，则需要按照以下说明进行操作：

1.  从以下链接下载.NET Core：[`www.microsoft.com/net/download/windows`](https://www.microsoft.com/net/download/windows)。

1.  安装说明和相关库可以在以下链接找到：[`dotnet.microsoft.com/download/dotnet-core/2.2`](https://dotnet.microsoft.com/download/dotnet-core/2.2)。

完整的源代码可在 GitHub 存储库中找到。本章中显示的源代码可能不完整，因此建议检索源代码以运行示例。请参阅[`github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter5.`](https://github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter5)

# .Net Core 服务生命周期

在使用.NET Core 的 DI 时，理解服务生命周期是一个基本概念。服务生命周期定义了依赖项的管理方式，以及它被创建的频率。作为这一过程的说明，将 DI 视为管理依赖项的容器。依赖项只是 DI 知道的一个类，因为该类已经与它*注册*。对于.NET Core 的 DI，可以使用`IServiceCollection`的以下三种方法来完成这一过程：

+   `AddTransient<TService, TImplementation>()`

+   `AddScoped<TService, TImplementation>()`

+   `AddSingleton<TService, TImplementation>()`

`IServiceCollection`接口是已注册的服务描述的集合，基本上包含依赖项以及 DI 应该何时提供依赖项。例如，当请求`TService`时，会提供`TImplementation`（也就是注入）。

在本节中，我们将查看三种服务生命周期，并通过单元测试提供不同生命周期的示例。我们还将看看如何使用实现工厂来创建依赖项的实例。

# 瞬态

`瞬态`依赖项意味着每次 DI 接收到对依赖项的请求时，将创建依赖项的新实例。在大多数情况下，这是最合理使用的服务生命周期，因为大多数类应设计为轻量级、无状态的服务。在需要在引用之间保持状态和/或在实例化新实例方面需要大量工作的情况下，可能会更合理地使用另一种服务生命周期。

# 作用域

在.Net Core 中，有一个作用域的概念，可以将其视为执行过程的上下文或边界。在某些.Net Core 实现中，作用域是隐式定义的，因此您可能不知道它已经被放置。例如，在 ASP.Net Core 中，为接收到的每个 Web 请求创建一个作用域。这意味着，如果一个依赖项具有作用域生命周期，那么它将仅在每个 Web 请求中构造一次，因此，如果相同的依赖项在同一 Web 请求中多次使用，它将被共享。

在本章后面，我们将明确创建一个范围，以说明作用域生命周期，相同的概念也适用于单元测试，就像在 ASP.Net Core 应用程序中一样。

# 单例

在.Net Core 中，Singleton 模式的实现方式是依赖只被实例化一次，就像在上一章中实现的 Singleton 模式一样。与上一章中的 Singleton 模式类似，`singleton`类需要是线程安全的，只有用于创建单例类的工厂方法才能保证只被单个线程调用一次。

# 回到 FlixOne

为了说明.Net Core 的 DI，我们需要对 FlixOne 库存管理应用程序进行一些修改。首先要做的是更新之前定义的`InventoryContext`类，以便不再实现 Singleton 模式（因为我们将使用.Net Core 的 DI 来实现）：

```cs
public class InventoryContext : IInventoryContext
{
    public InventoryContext()
    {
       _books = new ConcurrentDictionary<string, Book>();
    }

    private readonly static object _lock = new object(); 

    private readonly IDictionary<string, Book> _books;

    public Book[] GetBooks()
    {
        return _books.Values.ToArray();
    }

    ...
}
```

`AddBook`和`UpdateQuantity`方法的详细信息如下所示：

```cs
public bool AddBook(string name)
{
    _books.Add(name, new Book {Name = name});
    return true;
}

public bool UpdateQuantity(string name, int quantity)
{
    lock (_lock)
    {
        _books[name].Quantity += quantity;
    }

    return true;
}
```

有几件事情需要注意。构造函数已从受保护更改为公共。这将允许类在类外部被实例化。还要注意，静态`Instance`属性和私有静态`_instance`字段已被删除，而私有`_lock`字段仍然存在。与上一章中定义的 Singleton 模式类似，这只保证了类的实例化方式；它并不阻止方法被并行访问。

`IInventoryContext`接口和`InventoryContext`和`Book`类都被设为公共，因为我们的 DI 是在外部项目中定义的。

随后，用于返回命令的`InventoryCommandFactory`类已更新，以便在其构造函数中注入`InventoryContext`的实例：

```cs
public class InventoryCommandFactory : IInventoryCommandFactory
{
    private readonly IUserInterface _userInterface;
    private readonly IInventoryContext _context;

    public InventoryCommandFactory(IUserInterface userInterface, IInventoryContext context)
    {
        _userInterface = userInterface;
        _context = context;
    }

    // GetCommand()
    ...
}
```

`GetCommand`方法使用提供的输入来确定特定的命令：

```cs
public InventoryCommand GetCommand(string input)
{
    switch (input.ToLower())
    {
        case "q":
        case "quit":
            return new QuitCommand(_userInterface);
        case "a":
        case "addinventory":
            return new AddInventoryCommand(_userInterface, _context);
        case "g":
        case "getinventory":
            return new GetInventoryCommand(_userInterface, _context);
        case "u":
        case "updatequantity":
            return new UpdateQuantityCommand(_userInterface, _context);
        case "?":
            return new HelpCommand(_userInterface);
        default:
            return new UnknownCommand(_userInterface);
    }
}
```

如前所述，`IInventoryContext`接口现在将由客户端项目中定义的 DI 容器提供。控制台应用程序现在有一个额外的行来使用`InventoryContext`类创建`IInventoryContext`接口的单例：

```cs
class Program
{
    private static void Main(string[] args)
    {
        IServiceCollection services = new ServiceCollection();
        ConfigureServices(services);
        IServiceProvider serviceProvider = services.BuildServiceProvider();

        var service = serviceProvider.GetService<ICatalogService>();
        service.Run();

        Console.WriteLine("CatalogService has completed.");
        Console.ReadLine();
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        // Add application services.
        services.AddTransient<IUserInterface, ConsoleUserInterface>(); 
        services.AddTransient<ICatalogService, CatalogService>();
        services.AddTransient<IInventoryCommandFactory, InventoryCommandFactory>();

 services.AddSingleton<IInventoryContext, InventoryContext>();
    }
}
```

控制台应用程序现在可以使用与上一章中执行的手动测试相同的方式运行，但是单元测试是了解使用.Net Core 的 DI 实现的成果的好方法。

本章提供的示例代码显示了完成的项目。接下来的部分集中在`InventoryContext`测试上。`InventoryCommandFactory`测试也进行了修改，但由于更改是微不足道的，因此不会在此处进行介绍。

# 单元测试

随着对`InventoryContext`类的更改，我们不再有一个方便的属性来获取该类的唯一实例。这意味着`InventoryContext.Instance`需要被替换，首先，让我们创建一个方法来返回`InventoryContext`的新实例，并使用`GetInventoryContext()`代替`InventoryContext.Instance`：

```cs
private IInventoryContext GetInventoryContext()
{
    return new InventoryContext();
}
```

如预期的那样，单元测试失败，并显示错误消息：*给定的键在字典中不存在*：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/270f856b-e1dc-475a-8a82-22e9288276cb.png)

正如我们在上一章中看到的，这是因为每次创建`InventoryContext`类时，书籍的列表都是空的。这就是为什么我们需要使用 Singleton 创建一个上下文的原因。

让我们更新`GetInventoryContext()`方法，现在使用.Net Core 的 DI 来提供`IInventoryContext`接口的实例：

```cs
private IInventoryContext GetInventoryContext()
{
    IServiceCollection services = new ServiceCollection();
    services.AddSingleton<IInventoryContext, InventoryContext>();
    var provider = services.BuildServiceProvider();

    return provider.GetService<IInventoryContext>();
}
```

在更新的方法中，创建了`ServiceCollection`类的一个实例，用于包含所有注册的依赖项。`InventoryContext`类被注册为 Singleton，以便在请求`IInventoryContext`依赖项时提供。然后生成了一个`ServiceProvider`实例，它将根据`IServiceCollection`接口中的注册执行 DI。最后一步是在请求`IInventoryContext`接口时提供`InventoryContext`类。

`Microsoft.Extensions.DependencyInjection`库需要添加到`InventoryManagementTests`项目中，以便能够引用.Net Core DI 组件。

很不幸，单元测试仍然无法通过，并且导致相同的错误：*给定的键在字典中不存在。*这是因为每次请求`IInventoryContext`时，我们都会创建一个新的 DI 框架实例。这意味着，即使我们的依赖是一个 Singleton，每个`ServiceProvider`实例都会提供一个新的`InventoryContext`类的实例。为了解决这个问题，我们将在测试启动时创建`IServiceCollection`，然后在测试期间使用相同的引用：

```cs
ServiceProvider Services { get; set; }

[TestInitialize]
public void Startup()
{
    IServiceCollection services = new ServiceCollection();
    services.AddSingleton<IInventoryContext, InventoryContext>();
    Services = services.BuildServiceProvider();
}
```

使用`TestInitialize`属性是在`TestClass`类中分离多个`TestMethod`测试所需的功能的好方法。该方法将在每次测试运行之前运行。

现在有了对同一个`ServiceProvider`实例的引用，我们可以更新以检索依赖项。以下说明了`AddBook()`方法的更新方式：

```cs
public Task AddBook(string book)
{
    return Task.Run(() =>
    {
        Assert.IsTrue(Services.GetService<IInventoryContext>().AddBook(book));
    });
}
```

我们的单元测试现在成功通过，因为在测试执行期间只创建了一个`InventoryContext`类的实例：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/1c92dd81-8d8c-466a-982e-ab7862dcab15.png)

使用内置的 DI 相对容易实现 Singleton 模式，就像本节中所示。了解何时使用该模式是一个重要的概念。下一节将更详细地探讨作用域的概念，以便更深入地理解服务的生命周期。

# 作用域

在同时执行多个进程的应用程序中，了解服务生命周期对功能和非功能需求都非常重要。正如在上一个单元测试中所示，如果没有正确的服务生命周期，`InventoryContext`就无法按预期工作，并导致了一个无效的情况。同样，错误使用服务生命周期可能导致应用程序无法良好扩展。一般来说，在多进程解决方案中应避免使用锁和共享状态。 

为了说明这个概念，想象一下 FlixOne 库存管理应用程序被提供给多个员工。现在的挑战是如何在多个应用程序之间执行锁定，以及如何拥有一个单一的收集状态。在我们的术语中，这将是多个应用程序共享的单个`InventoryContext`类。当然，这就是我们改变解决方案以使用共享存储库（例如数据库）或改变解决方案以使用 Web 应用程序的地方。我们将在后面的章节中涵盖数据库和 Web 应用程序模式，但是，由于我们正在讨论服务生命周期，现在更详细地描述这些内容是有意义的。

以下图示了一个 Web 应用程序接收两个请求：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/a28f0bf1-4c7f-43ab-9cc4-3de7694fdf4c.png)

在服务生命周期方面，单例服务生命周期将对两个请求都可用，而每个请求都会接收到自己的作用域生命周期。需要注意的重要事情是垃圾回收。使用瞬态服务生命周期创建的依赖项在对象不再被引用时标记为释放，而使用作用域服务生命周期创建的依赖项在 Web 请求完成之前不会被标记为释放。而使用单例服务生命周期创建的依赖项直到应用程序结束才会被标记为释放。

此外，如下图所示，重要的是要记住，在.Net Core 中，依赖项在 Web 园或 Web 农场中的服务器实例之间不共享：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/13d3bc5b-0273-488b-9db0-f87daf198604.png)

在接下来的章节中，将展示共享状态的不同方法，包括使用共享缓存、数据库和其他形式的存储库。

# 实现工厂

.Net Core DI 支持在注册依赖项时指定*实现工厂*的能力。这允许对由提供的服务提供的依赖项的创建进行控制。在注册时使用`IServiceCollection`接口的以下扩展来完成：

```cs
public static IServiceCollection AddSingleton<TService, TImplementation>(this IServiceCollection services,     Func<IServiceProvider, TImplementation> implementationFactory)
                where TService : class
                where TImplementation : class, TService;
```

`AddSingleton`扩展接收要注册的类以及在需要依赖项时要提供的类。值得注意的是，.Net Core DI 框架将维护已注册的服务，并在请求时提供实现，或作为依赖项之一的实例化的一部分。这种自动实例化称为**构造函数注入**（**CI**）。我们将在以下章节中看到这两种的例子。

# IInventoryContext

举个例子，让我们重新审视一下用于管理书籍库存的`InventoryContext`类，通过将对书籍集合的读取和写入操作进行分离。`IInventoryContext`被分成了`IInventoryReadContext`和`IInventoryWriteContext`：

```cs
using FlixOne.InventoryManagement.Models;

namespace FlixOne.InventoryManagement.Repository
{
    public interface IInventoryContext : IInventoryReadContext, IInventoryWriteContext { }

    public interface IInventoryReadContext
    {
        Book[] GetBooks();
    }

    public interface IInventoryWriteContext
    {
        bool AddBook(string name);
        bool UpdateQuantity(string name, int quantity);
    }
}
```

# IInventoryReadContext

`IInventoryReadContext`接口包含读取书籍的操作，而`IInventoryWriteContext`包含修改书籍集合的操作。最初创建`IInventoryContext`接口是为了方便一个类需要两种依赖类型时。

在后面的章节中，我们将涵盖利用分割上下文的模式，包括**命令和** **查询责任分离**（**CQRS**）模式。

通过这种重构，需要进行一些更改。首先，只需要读取书籍集合的类将其构造函数更新为`IInventoryReadContext`接口，如`GetInventoryCommand`类所示：

```cs
internal class GetInventoryCommand : NonTerminatingCommand
{
    private readonly IInventoryReadContext _context;
    internal GetInventoryCommand(IUserInterface userInterface, IInventoryReadContext context) : base(userInterface)
    {
        _context = context;
    }

    protected override bool InternalCommand()
    {
        foreach (var book in _context.GetBooks())
        {
            Interface.WriteMessage($"{book.Name,-30}\tQuantity:{book.Quantity}"); 
        }

        return true;
    }
}
```

# IInventoryWriteContext

同样，需要修改书籍集合的类将其更新为`IInventoryWriteContext`接口，如`AddInventoryCommand`所示：

```cs
internal class AddInventoryCommand : NonTerminatingCommand, IParameterisedCommand
{
    private readonly IInventoryWriteContext _context;

    internal AddInventoryCommand(IUserInterface userInterface, IInventoryWriteContext context) : base(userInterface)
    {
        _context = context;
    }

    public string InventoryName { get; private set; }

    ...
}
```

以下显示了`GetParameters`和`InternalCommand`方法的详细信息：

```cs
/// <summary>
/// AddInventoryCommand requires name
/// </summary>
/// <returns></returns>
public bool GetParameters()
{
    if (string.IsNullOrWhiteSpace(InventoryName))
        InventoryName = GetParameter("name");
    return !string.IsNullOrWhiteSpace(InventoryName);
}

protected override bool InternalCommand()
{
    return _context.AddBook(InventoryName); 
}
```

请注意 `InternalCommand` 方法，其中将带有 `InventoryName` 参数中保存的书名添加到库存中。

接下来，我们将看看库存命令的工厂。

# InventoryCommandFactory

`InventoryCommandFactory` 类是使用 .Net 类实现工厂模式的一个实现，需要对书籍集合进行读取和写入：

```cs
public class InventoryCommandFactory : IInventoryCommandFactory
{
    private readonly IUserInterface _userInterface;
    private readonly IInventoryContext _context; 

    public InventoryCommandFactory(IUserInterface userInterface, IInventoryContext context)
    {
        _userInterface = userInterface;
        _context = context; 
    }

    public InventoryCommand GetCommand(string input)
    {
        switch (input.ToLower())
        {
            case "q":
            case "quit":
                return new QuitCommand(_userInterface);
            case "a":
            case "addinventory":
                return new AddInventoryCommand(_userInterface, _context);
            case "g":
            case "getinventory":
                return new GetInventoryCommand(_userInterface, _context);
            case "u":
            case "updatequantity":
                return new UpdateQuantityCommand(_userInterface, _context);
            case "?":
                return new HelpCommand(_userInterface);
            default:
                return new UnknownCommand(_userInterface);
        }
    }
}
```

值得注意的是，这个类实际上不需要修改前一章版本的内容，因为多态性处理了从 `IInventoryContext` 到 `IInventoryReadContext` 和 `IInventoryWriteContext` 接口的转换。

有了这些变化，我们需要改变与 `InventoryContext` 相关的依赖项的注册，以使用实现工厂：

```cs
private static void ConfigureServices(IServiceCollection services)
{
    // Add application services.
    ...            

    var context = new InventoryContext();
 services.AddSingleton<IInventoryReadContext, InventoryContext>(p => context);
 services.AddSingleton<IInventoryWriteContext, InventoryContext>(p => context);
 services.AddSingleton<IInventoryContext, InventoryContext>(p => context);
}
```

对于所有三个接口，将使用相同的 `InventoryContext` 实例，并且这是使用实现工厂扩展一次实例化的。当请求 `IInventoryReadContext`、`IInventoryWriteContext` 或 `IInventoryContext` 依赖项时提供。

# InventoryCommand

`InventoryCommandFactory` 在展示如何使用 .Net 实现工厂模式时非常有用，但现在让我们重新审视一下，因为我们现在正在使用 .Net Core 框架。我们的要求是给定一个字符串值；我们希望返回 `InventoryCommand` 的特定实现。这可以通过几种方式实现，在本节中将给出三个示例：

+   使用函数的实现工厂

+   使用服务

+   使用第三方容器

# 使用函数的实现工厂

`GetService()` 方法的实现工厂可以用于确定要返回的 `InventoryCommand` 类型。对于这个示例，在 `InventoryCommand` 类中创建了一个新的静态方法：

```cs
public static Func<IServiceProvider, Func<string, InventoryCommand>> GetInventoryCommand => 
                                                                            provider => input =>
{
    switch (input.ToLower())
    {
        case "q":
        case "quit":
            return new QuitCommand(provider.GetService<IUserInterface>());
        case "a":
        case "addinventory":
            return new AddInventoryCommand(provider.GetService<IUserInterface>(), provider.GetService<IInventoryWriteContext>());
        case "g":
        case "getinventory":
            return new GetInventoryCommand(provider.GetService<IUserInterface>(), provider.GetService<IInventoryReadContext>());
        case "u":
        case "updatequantity":
            return new UpdateQuantityCommand(provider.GetService<IUserInterface>(), provider.GetService<IInventoryWriteContext>());
        case "?":
            return new HelpCommand(provider.GetService<IUserInterface>());
        default:
            return new UnknownCommand(provider.GetService<IUserInterface>());
    }
};
```

如果您不熟悉 lambda 表达式体，这可能有点难以阅读，因此我们将详细解释一下代码。首先，让我们重新审视一下 `AddSingleton` 的语法：

```cs
public static IServiceCollection AddSingleton<TService, TImplementation>(this IServiceCollection services, Func<IServiceProvider, TImplementation> implementationFactory)
            where TService : class
            where TImplementation : class, TService;
```

这表明 `AddSingleton` 扩展的参数是一个函数：

```cs
Func<IServiceProvider, TImplementation> implementationFactory
```

这意味着以下代码是等价的：

```cs
services.AddSingleton<IInventoryContext, InventoryContext>(provider => new InventoryContext());

services.AddSingleton<IInventoryContext, InventoryContext>(GetInventoryContext);
```

`GetInventoryContext` 方法定义如下：

```cs
static Func<IServiceProvider, InventoryContext> GetInventoryContext => provider =>
{
    return new InventoryContext();
};
```

在我们的特定示例中，特定的 `InventoryCommand` 类型已被标记为 `FlixOne.InventoryManagement` 项目的内部，因此 `FlixOne.InventoryManagementClient` 项目无法直接访问它们。这就是为什么在 `FlixOne.InventoryManagement.InventoryCommand` 类中创建了一个新的静态方法，返回以下类型：

```cs
Func<IServiceProvider, Func<string, InventoryCommand>>
```

这意味着当请求服务时，将提供一个字符串来确定具体的类型。由于依赖项发生了变化，这意味着 `CatalogService` 构造函数需要更新：

```cs
public CatalogService(IUserInterface userInterface, Func<string, InventoryCommand> commandFactory)
{
    _userInterface = userInterface;
    _commandFactory = commandFactory;
}
```

当请求服务时，将提供一个字符串来确定具体的类型。由于依赖项发生了变化，`CatalogueService` 构造函数需要更新：

现在，当用户输入的字符串被提供给 `CommandFactory` 依赖项时，将提供正确的命令：

```cs
while (!response.shouldQuit)
{
    // look at this mistake with the ToLower()
    var input = _userInterface.ReadValue("> ").ToLower();
    var command = _commandFactory(input);

    response = command.RunCommand();

    if (!response.wasSuccessful)
    {
        _userInterface.WriteMessage("Enter ? to view options.");
    }
}
```

与命令工厂相关的单元测试也进行了更新。作为对比，从现有的 `InventoryCommandFactoryTests` 类创建了一个新的 `test` 类，并命名为 `InventoryCommandFunctionTests`。初始化步骤如下所示，其中突出显示了更改：

```cs
ServiceProvider Services { get; set; }

[TestInitialize]
public void Startup()
{
    var expectedInterface = new Helpers.TestUserInterface(
        new List<Tuple<string, string>>(),
        new List<string>(),
        new List<string>()
    );

    IServiceCollection services = new ServiceCollection();
    services.AddSingleton<IInventoryContext, InventoryContext>();
 services.AddTransient<Func<string, InventoryCommand>>(InventoryCommand.GetInventoryCommand);

    Services = services.BuildServiceProvider();
}
```

还更新了各个测试，以在 `QuitCommand` 中提供字符串作为获取服务调用的一部分，如下所示：

```cs
[TestMethod]
public void QuitCommand_Successful()
{
    Assert.IsInstanceOfType(Services.GetService<Func<string, InventoryCommand>>().Invoke("q"),             
                            typeof(QuitCommand), 
                            "q should be QuitCommand");

    Assert.IsInstanceOfType(Services.GetService<Func<string, InventoryCommand>>().Invoke("quit"),
                            typeof(QuitCommand), 
                            "quit should be QuitCommand");
}
```

这两个测试验证了当服务提供程序提供 `"q"` 或 `"quit"` 时，返回的服务类型是 `QuitCommand`。

# 使用服务

`ServiceProvider`类提供了一个`Services`方法，可以用来确定适当的服务，当同一类型有多个依赖项注册时。这个例子将采用不同的方法处理`InventoryCommands`，由于重构的范围，这将通过新创建的类来完成，以说明这种方法。

在单元测试项目中，创建了一个新的文件夹`ImplementationFactoryTests`，用于包含本节的类。在这个文件夹中，创建了一个新的`InventoryCommand`基类：

```cs
public abstract class InventoryCommand
{
    protected abstract string[] CommandStrings { get; }
    public virtual bool IsCommandFor(string input)
    {
        return CommandStrings.Contains(input.ToLower());
    } 
}
```

这个新类背后的概念是，子类将定义它们要响应的字符串。例如，`QuitCommand`将响应`"q"`和`"quit"`字符串：

```cs
public class QuitCommand : InventoryCommand
{
    protected override string[] CommandStrings => new[] { "q", "quit" };
}
```

以下显示了`GetInventoryCommand`、`AddInventoryCommand`、`UpdateQuantityCommand`和`HelpCommand`类，它们采用了类似的方法：

```cs
public class GetInventoryCommand : InventoryCommand
{
    protected override string[] CommandStrings => new[] { "g", "getinventory" };
}

public class AddInventoryCommand : InventoryCommand
{
    protected override string[] CommandStrings => new[] { "a", "addinventory" };
}

public class UpdateQuantityCommand : InventoryCommand
{
    protected override string[] CommandStrings => new[] { "u", "updatequantity" };
}

public class HelpCommand : InventoryCommand
{
    protected override string[] CommandStrings => new[] { "?" };
}
```

然而，`UnknownCommand`类将被用作默认值，因此它将始终通过重写`IsCommandFor`方法来评估为 true：

```cs
public class UnknownCommand : InventoryCommand
{
    protected override string[] CommandStrings => new string[0];

    public override bool IsCommandFor(string input)
    {
        return true;
    }
}
```

由于`UnknownCommand`类被视为默认值，注册的顺序很重要，在单元测试类的初始化中如下所示：

```cs
[TestInitialize]
public void Startup()
{
    var expectedInterface = new Helpers.TestUserInterface(
        new List<Tuple<string, string>>(),
        new List<string>(),
        new List<string>()
    );

    IServiceCollection services = new ServiceCollection(); 
    services.AddTransient<InventoryCommand, QuitCommand>();
    services.AddTransient<InventoryCommand, HelpCommand>(); 
    services.AddTransient<InventoryCommand, AddInventoryCommand>();
    services.AddTransient<InventoryCommand, GetInventoryCommand>();
    services.AddTransient<InventoryCommand, UpdateQuantityCommand>();
    // UnknownCommand should be the last registered
 services.AddTransient<InventoryCommand, UnknownCommand>();

    Services = services.BuildServiceProvider();
}
```

为了方便起见，创建了一个新的方法，以便在给定匹配输入字符串时返回`InventoryCommand`类的实例：

```cs
public InventoryCommand GetCommand(string input)
{
    return Services.GetServices<InventoryCommand>().First(svc => svc.IsCommandFor(input));
}
```

这个方法将遍历为`InventoryCommand`服务注册的依赖项集合，直到使用`IsCommandFor()`方法找到匹配项。

然后，单元测试使用`GetCommand()`方法来确定依赖项，如下所示，用于`UpdateQuantityCommand`：

```cs
[TestMethod]
public void UpdateQuantityCommand_Successful()
{
    Assert.IsInstanceOfType(GetCommand("u"), 
                            typeof(UpdateQuantityCommand), 
                            "u should be UpdateQuantityCommand");

    Assert.IsInstanceOfType(GetCommand("updatequantity"), 
                            typeof(UpdateQuantityCommand), 
                            "updatequantity should be UpdateQuantityCommand");

    Assert.IsInstanceOfType(GetCommand("UpdaTEQuantity"), 
                            typeof(UpdateQuantityCommand), 
                            "UpdaTEQuantity should be UpdateQuantityCommand");
}
```

# 使用第三方容器

.Net Core 框架提供了很大的灵活性和功能，但可能不支持一些功能，第三方容器可能是更合适的选择。幸运的是，.Net Core 是可扩展的，允许用第三方容器替换内置的服务容器。为了举例，我们将使用`Autofac`作为.Net Core DI 的 IoC 容器。

`Autofac`有很多很棒的功能，在这里作为一个例子展示出来；当然，还有其他 IoC 容器可以使用。例如，Castle Windsor 和 Unit 都是很好的替代方案，也应该考虑使用。

第一步是将所需的`Autofac`包添加到项目中。使用包管理器控制台，使用以下命令添加包（仅在测试项目中需要）：

```cs
install-package autofac
```

这个例子将再次通过使用`Autofac`的命名注册依赖项的功能来支持我们的`InventoryCommand`工厂。这些命名的依赖项将用于根据提供的输入来检索正确的`InventoryCommand`实例。

与之前的例子类似，依赖项的注册将在`TestInitialize`方法中完成。注册将根据将用于确定命令的命令命名。以下显示了创建`ContainerBuilder`对象的`Startup`方法结构，该对象将构建`Container`实例：

```cs
[TestInitialize]
public void Startup()
{
    IServiceCollection services = new ServiceCollection();

    var builder = new ContainerBuilder(); 

    // commands
    ...

    Container = builder.Build(); 
}
```

命令的注册如下：

```cs
// commands
builder.RegisterType<QuitCommand>().Named<InventoryCommand>("q");
builder.RegisterType<QuitCommand>().Named<InventoryCommand>("quit");
builder.RegisterType<UpdateQuantityCommand>().Named<InventoryCommand>("u");
builder.RegisterType<UpdateQuantityCommand>().Named<InventoryCommand>("updatequantity");
builder.RegisterType<HelpCommand>().Named<InventoryCommand>("?");
builder.RegisterType<AddInventoryCommand>().Named<InventoryCommand>("a");
builder.RegisterType<AddInventoryCommand>().Named<InventoryCommand>("addinventory");
builder.RegisterType<GetInventoryCommand>().Named<InventoryCommand>("g");
builder.RegisterType<GetInventoryCommand>().Named<InventoryCommand>("getinventory");
builder.RegisterType<UpdateQuantityCommand>().Named<InventoryCommand>("u");
builder.RegisterType<UpdateQuantityCommand>().Named<InventoryCommand>("u");
builder.RegisterType<UnknownCommand>().As<InventoryCommand>();
```

与之前的例子不同，生成的容器是`Autofac.IContainer`的实例。这将用于检索每个注册的依赖项。例如，`QuitCommand`将被命名为`"q"`和`"quit"`，这表示可以用于执行命令的两个命令。另外，注意最后注册的类型没有命名，并属于`UnknownCommand`。如果没有找到命令，则这将充当默认值。

为了确定一个依赖项，将使用一个新方法来按名称检索依赖项：

```cs
public InventoryCommand GetCommand(string input)
{
    return Container.ResolveOptionalNamed<InventoryCommand>(input.ToLower()) ?? 
           Container.Resolve<InventoryCommand>();
}
```

`Autofac.IContainer`接口具有`ResolveOptionalNamed<*T*>(*string*)`方法名称，该方法将返回具有给定名称的依赖项，如果找不到匹配的注册，则返回 null。如果未使用给定名称注册依赖项，则将返回`UnknownCommand`类的实例。这是通过使用空值合并操作`??`和`IContainer.Resolve<*T*>`方法来实现的。

如果依赖项解析失败，`Autofac.IContainer.ResolveNamed<*T*>(*string*)`将抛出`ComponentNotRegisteredException`异常。

为了确保正确解析命令，为每个命令编写了一个测试方法。再次以`QuitCommand`为例，我们可以看到以下内容：

```cs
[TestMethod]
public void QuitCommand_Successful()
{
    Assert.IsInstanceOfType(GetCommand("q"), typeof(QuitCommand), "q should be QuitCommand");
    Assert.IsInstanceOfType(GetCommand("quit"), typeof(QuitCommand), "quit should be QuitCommand");
}
```

请查看源代码中的`InventoryCommandAutofacTests`类，以获取其他`InventoryCommand`示例。

# 总结

本章的目标是更详细地探索.Net Core 框架，特别是.Net Core DI。支持三种类型的服务生命周期：瞬态（Transient）、作用域（Scoped）和单例（Singleton）。瞬态服务将为每个请求创建一个已注册依赖项的新实例。作用域服务将在定义的范围内生成一次，而单例服务将在 DI 服务集合的生命周期内执行一次。

由于.Net Core DI 对于自信地构建.Net Core 应用程序至关重要，因此了解其能力和局限性非常重要。重要的是要有效地使用 DI，同时避免重复使用已提供的功能。同样重要的是，了解.Net Core DI 框架的限制，以及其他 DI 框架的优势，以便在替换基本的.Net Core DI 框架为第三方 DI 框架可能对应用程序有益的情况下，能够明智地做出选择。

下一章将在前几章的基础上构建，并探索.Net Core ASP.Net Web 应用程序中的常见模式。

# 问题

以下问题将帮助您巩固本章中包含的信息：

1.  如果不确定要使用哪种类型的服务生命周期，最好将类注册为哪种类型？为什么？

1.  在.Net Core ASP.Net 解决方案中，作用域是按照每个 web 请求定义的，还是按照每个会话定义的？

1.  在.Net Core DI 框架中将类注册为单例是否会使其线程安全？

1.  .Net Core DI 框架只能被其他由微软提供的 DI 框架替换吗？


# 第六章：为网络应用程序实施设计模式-第一部分

在本章中，我们将继续构建**FlixOne**库存管理应用程序（参见第三章，*实施设计模式基础-第一部分*），并讨论将控制台应用程序转换为网络应用程序。网络应用程序应该更吸引用户，而不是控制台应用程序；在这里，我们还将讨论为什么要进行这种改变。

本章将涵盖以下主题：

+   创建一个.NET Core 网络应用程序

+   制作一个网络应用程序

+   实施 CRUD 页面

如果您尚未查看早期章节，请注意**FlixOne Inventory Management**网络应用程序是一个虚构的产品。我们创建这个应用程序来讨论网络项目中所需的各种设计模式。

# 技术要求

本章包含各种代码示例来解释概念。代码保持简单，仅用于演示目的。大多数示例涉及使用 C#编写的**.NET Core**控制台应用程序。

要运行和执行代码，您需要以下内容：

+   Visual Studio 2019（您也可以使用 Visual Studio 2017 更新 3 或更高版本来运行应用程序）

+   .NET Core 的环境设置

+   SQL Server（本章使用 Express 版本）

# 安装 Visual Studio

要运行这些代码示例，您需要安装 Visual Studio（2017）或更新版本，如 2019（或您可以使用您喜欢的 IDE）。要做到这一点，请按照以下步骤操作：

1.  从以下网址下载 Visual Studio：[`docs.microsoft.com/en-us/visualstudio/install/install-visual-studio`](https://docs.microsoft.com/en-us/visualstudio/install/install-visual-studio)。

1.  按照包含的安装说明进行操作。Visual Studio 有多个版本可供安装。在本章中，我们使用的是 Windows 版的 Visual Studio。

# 设置.NET Core

如果您尚未安装.NET Core，则需要按照以下步骤操作：

1.  从以下网址下载.NET Core：[`www.microsoft.com/net/download/windows`](https://www.microsoft.com/net/download/windows)。

1.  按照安装说明并关注相关库：[`dotnet.microsoft.com/download/dotnet-core/2.2`](https://dotnet.microsoft.com/download/dotnet-core/2.2)。

# 安装 SQL Server

如果您尚未安装 SQL Server，则需要按照以下说明操作：

1.  从以下网址下载 SQL Server：[`www.microsoft.com/en-in/download/details.aspx?id=1695`](https://www.microsoft.com/en-in/download/details.aspx?id=1695)。

1.  您可以在以下网址找到安装说明：[`docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017`](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017)。

有关故障排除和更多信息，请参阅：[`www.blackbaud.com/files/support/infinityinstaller/content/installermaster/tkinstallsqlserver2008r2.htm`](https://www.blackbaud.com/files/support/infinityinstaller/content/installermaster/tkinstallsqlserver2008r2.htm)。

本节旨在提供开始使用网络应用程序的先决条件信息。我们将在后续章节中详细了解更多细节。在本章中，我们将使用代码示例来详细解释各种术语和部分。

完整的源代码可在以下网址找到：[`github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter6`](https://github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter6)。

# 创建一个.Net Core 网络应用程序

在本章的开头，我们讨论了我们基于 FlixOne 控制台的应用程序，并且业务团队确定了采用 Web 应用程序的各种原因。现在是时候对应用程序进行更改了。在本节中，我们将开始创建一个新的 UI，给我们现有的 FlixOne 应用程序一个新的外观和感觉。我们还将讨论所有的需求和初始化。

# 启动项目

在我们现有的 FlixOne 控制台应用程序的基础上，管理层决定对我们的 FlixOne 库存控制台应用程序进行大幅改进，增加了许多功能。管理层得出结论，我们必须将现有的控制台应用程序转换为基于 Web 的解决方案。

技术团队和业务团队一起坐下来，确定了废弃当前控制台应用程序的各种原因：

+   界面不具有交互性。

+   该应用程序并非随处可用。

+   维护复杂。

+   不断增长的业务需要一个可扩展的系统，具有更高的性能和适应性。

# 开发需求

以下的需求清单是讨论的结果。确定的高级需求如下：

+   产品分类

+   产品添加

+   产品更新

+   产品删除

业务要求实际上落在开发人员身上。这些技术需求包括以下内容：

+   **一个登陆或主页**：这应该是一个包含各种小部件的仪表板，并且应该显示商店的摘要。

+   **产品页面**：这应该具有添加、更新和删除产品和类别的功能。

# 打造 Web 应用程序

根据刚刚讨论的需求，我们的主要目标是将现有的控制台应用程序转换为 Web 应用程序。在这个转换过程中，我们将讨论 Web 应用程序的各种设计模式，以及这些设计模式在 Web 应用程序的背景下的重要性。

# 网络应用程序及其工作原理

Web 应用程序是客户端-服务器架构的最佳实现之一。Web 应用程序可以是一小段代码、一个程序，或者是一个解决问题或业务场景的完整解决方案，用户可以通过浏览器相互交互或与服务器交互。Web 应用程序主要通过浏览器提供请求和响应，主要通过**超文本传输协议**（**HTTP**）。

每当客户端和服务器之间发生通信时，都会发生两件事：客户端发起请求，服务器生成响应。这种通信由 HTTP 请求和 HTTP 响应组成。有关更多信息，请参阅文档：[`www.w3schools.com/whatis/whatis_http.asp`](https://www.w3schools.com/whatis/whatis_http.asp)。

在下图中，你可以看到 Web 应用程序的概述和工作原理：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/a6f3af7f-d494-4645-afd7-0f7b4f81254d.png)

从这个图表中，你可以很容易地看到，通过使用浏览器（作为客户端），你为数百万用户打开了可以从世界各地访问网站并与你作为用户交互的大门。通过 Web 应用程序，你和你的客户可以轻松地进行沟通。通常，只有在你捕获并存储了业务和用户所需的所有必要信息的数据时，才能实现有效的参与。然后这些信息被处理，结果呈现给你的用户。

一般来说，Web 应用程序使用服务器端代码来处理信息的存储和检索，以及客户端脚本来向用户呈现信息。

Web 应用程序需要 Web 服务器（如**IIS**或**Apache**）来管理来自客户端的请求（从浏览器中可以看到）。还需要应用程序服务器（如 IIS 或 Apache Tomcat）来执行请求的任务。有时还需要数据库来存储信息。

简而言之，Web 服务器和应用程序服务器都旨在提供 HTTP 内容，但具有一定的差异。Web 服务器提供静态 HTTP 内容，如 HTML 页面。应用程序服务器除了提供静态 HTTP 内容外，还可以使用不同的编程语言提供动态内容。有关更多信息，请参阅[`stackoverflow.com/questions/936197/what-is-the-difference-between-application-server-and-web-server`](https://stackoverflow.com/questions/936197/what-is-the-difference-between-application-server-and-web-server)。

我们可以详细说明 Web 应用程序的工作流程如下。这些被称为 Web 应用程序的五个工作过程：

1.  客户端（浏览器）通过互联网使用 HTTP（在大多数情况下）触发请求到 Web 服务器。这通常通过 Web 浏览器或应用程序的用户界面完成。

1.  请求在 Web 服务器处发出，Web 服务器将请求转发给应用程序服务器（对于不同的请求，将有不同的应用程序服务器）。

1.  在应用程序服务器中，完成了请求的任务。这可能涉及查询数据库服务器，从数据库中检索信息，处理信息和构建结果。

1.  生成的结果（请求的信息或处理的数据）被发送到 Web 服务器。

1.  最后，响应将从 Web 服务器发送回请求者（客户端），并显示在用户的显示器上。

以下图表显示了这五个步骤的图解概述：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/195177cd-d19e-474a-a84a-242a3be32cb4.png)

在接下来的几节中，我将描述使用**模型-视图-控制器**（**MVC**）模式的 Web 应用程序的工作过程。

# 编写 Web 应用程序

到目前为止，我们已经了解了要求并查看了我们的目标，即将控制台应用程序转换为基于 Web 的平台或应用程序。在本节中，我们将使用 Visual Studio 开发实际的 Web 应用程序。

执行以下步骤，使用 Visual Studio 创建 Web 应用程序：

1.  打开 Visual Studio 实例。

1.  单击文件|新建|项目或按*Ctrl + Shift + N*，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/111a9983-9056-44db-a155-8f0a4352373e.png)

1.  从“新建项目”窗口中，选择 Web|.NET Core|ASP.NET Core Web 应用程序。

1.  命名它（例如`FlixOne.Web`），选择位置，然后您可以更新解决方案名称。默认情况下，解决方案名称将与项目名称相同。选中“为解决方案创建目录”复选框。您还可以选择选中“创建新的 Git 存储库”复选框（如果要为此创建新存储库，您需要有效的 Git 帐户）。

以下截图显示了创建新项目的过程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/d8703640-dbe5-4058-9740-1905a9b25e98.png)

1.  下一步是为您的 Web 应用程序选择适当的模板和.NET Core 版本。我们不打算为此项目启用 Docker 支持，因为我们不打算使用 Docker 作为容器部署我们的应用程序。我们将仅使用 HTTP 协议，而不是 HTTPS。因此，应保持未选中“启用 Docker 支持”和“配置 HTTPs”复选框，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/e62d22ed-9dc7-4f16-a021-994702496622.png)

现在，我们拥有一个完整的项目，其中包含我们的模板和示例代码，使用 MVC 框架。以下截图显示了我们目前的解决方案：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/6af17baa-1c2c-4b81-8653-5bfa980d6f69.png)

架构模式是在用户界面和应用程序设计中实施最佳实践的一种方式。它们为我们提供了常见问题的可重用解决方案。这些模式还允许我们轻松实现关注点的分离。

最流行的架构模式如下：

+   **模型-视图-控制器**（**MVC**）

+   **模型-视图-展示者**（**MVP**）

+   **模型-视图-视图模型**（**MVVM**）

您可以尝试通过按下*F5*来运行应用程序。以下屏幕截图显示了 Web 应用程序的默认主页：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/3a4a7a9a-9dd8-47c7-8ad0-f19344748448.png)

在接下来的章节中，我将讨论 MVC 模式，并创建**CRUD**（**创建**，**更新**和**删除**）页面与用户交互。

# 实现 CRUD 页面

在本节中，我们将开始创建功能页面来创建、更新和删除产品。要开始，请打开您的`FlixOne`解决方案，并将以下类添加到指定的文件夹中：

**`Models`**：在解决方案的`Models`文件夹中添加以下文件：

+   `Product.cs`：`Product`类的代码片段如下：

```cs
public class Product
{
   public Guid Id { get; set; }
   public string Name { get; set; }
   public string Description { get; set; }
   public string Image { get; set; }
   public decimal Price { get; set; }
   public Guid CategoryId { get; set; }
   public virtual Category Category { get; set; }
}
```

`Product`类几乎代表了产品的所有元素。它有一个`Name`，一个完整的`Description`，一个`Image`，一个`Price`，以及一个唯一的`ID`，以便我们的系统识别它。`Product`类还有一个`Category ID`，表示该产品所属的类别。它还包括对`Category`的完整定义。

**为什么我们应该定义一个`virtual`属性？**

在我们的`Product`类中，我们定义了一个`virtual`属性。这是因为在**Entity Framework**（**EF**）中，此属性有助于为虚拟属性创建代理。这样，属性可以支持延迟加载和更高效的更改跟踪。这意味着数据是按需可用的。当您请求使用`Category`属性时，EF 会加载数据。

+   `Category.cs`：`Category`类的代码片段如下：

```cs
public class Category
{
    public Category()
    {
        Products = new List<Product>();
    }

    public Guid Id { get; set; }
    public string Name { get; set; }
    public string Description { get; set; }
    public virtual IEnumerable<Product> Products { get; set; }
}
```

我们的`Category`类代表产品的实际类别。类别具有唯一的`ID`，一个`Name`，一个完整的`Description`，以及属于该类别的`Products`集合。每当我们初始化我们的`Category`类时，它也会初始化我们的`Product`类。

+   `ProductViewModel.cs`：`ProductViewModel`类的代码片段如下：

```cs
public class ProductViewModel
{
    public Guid ProductId { get; set; }
    public string ProductName { get; set; }
    public string ProductDescription { get; set; }
    public string ProductImage { get; set; }
    public decimal ProductPrice { get; set; }
    public Guid CategoryId { get; set; }
    public string CategoryName { get; set; }
    public string CategoryDescription { get; set; }
}
```

我们的`ProductViewModel`类代表了一个完整的`Product`，具有唯一的`ProductId`，一个`ProductName`，一个完整的`ProductDescription`，一个`ProductImage`，一个`ProductPrice`，一个唯一的`CategoryId`，一个`CategoryName`，以及一个完整的`CategoryDescription`。

`Controllers`：在解决方案的`Controllers`文件夹中添加以下文件：

+   `ProductController`负责与产品相关的所有操作。让我们看看在此控制器中我们试图实现的代码和操作：

```cs
public class ProductController : Controller
{
    private readonly IInventoryRepositry _repositry;
    public ProductController(IInventoryRepositry inventoryRepositry) => _repositry = inventoryRepositry;

...
}
```

在这里，我们定义了继承自`Controller`类的`ProductController`。我们使用了内置于 ASP.NET Core MVC 框架的**依赖注入**。

我们在第五章中详细讨论了控制反转；`Controller`是 MVC 控制器的基类。有关更多信息，请参阅：[`docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.controller`](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.controller)。

我们已经创建了我们的主控制器`ProductController`。现在让我们开始为我们的 CRUD 操作添加功能。

以下代码只是一个`Read`或`Get`操作，请求存储库（`_``inventoryRepository`）列出所有可用产品，然后将此产品列表转换为`ProductViewModel`类型并返回`Index`视图：

```cs
   public IActionResult Index() => View(_repositry.GetProducts().ToProductvm());
   public IActionResult Details(Guid id) => View(_repositry.GetProduct(id).ToProductvm());
```

在上面的代码片段中，`Details`方法根据其唯一的`Id`返回特定`Product`的详细信息。这也是一个类似于我们的`Index`方法的`Get`操作，但它提供单个对象而不是列表。

**MVC 控制器**的方法也称为**操作方法**，并且具有`ActionResult`的返回类型。在这种情况下，我们使用`IActionResult`。一般来说，可以说`IActionResult`是`ActionResult`类的一个接口。它还为我们提供了返回许多东西的方法，包括以下内容：

+   `EmptyResult`

+   `FileResult`

+   `HttpStatusCodeResult`

+   `ContentResult`

+   `JsonResult`

+   `RedirectToRouteResult`

+   `RedirectResult`

我们不打算详细讨论所有这些，因为这超出了本书的范围。要了解有关返回类型的更多信息，请参阅：[`docs.microsoft.com/en-us/aspnet/core/web-api/action-return-types`](https://docs.microsoft.com/en-us/aspnet/core/web-api/action-return-types)。

在下面的代码中，我们正在创建一个新产品。下面的代码片段有两个操作方法。一个有`[HttpPost]`属性，另一个没有属性：

```cs
public IActionResult Create() => View();
[HttpPost]
[ValidateAntiForgeryToken]
public IActionResult Create([FromBody] Product product)
{
    try
    {
        _repositry.AddProduct(product);
        return RedirectToAction(nameof(Index));
    }
    catch
    {
        return View();
    }
}
```

第一个方法只是返回一个`View`。这将返回一个`Create.cshtml`页面。

如果**MVC 框架**中的任何操作方法没有任何属性，它将默认使用`[HttpGet]`属性。在其他视图中，默认情况下，操作方法是`Get`请求。每当用户查看页面时，我们使用`[HttpGet]`，或者`Get`请求。每当用户提交表单或执行操作时，我们使用`[HttpPost]`，或者`Post`请求。

如果我们在操作方法中没有明确提到视图名称，那么 MVC 框架会以这种格式查找视图名称：`actionmethodname.cshtml`或`actionmethodname.vbhtml`。在我们的情况下，视图名称是`Create.cshtml`，因为我们使用的是 C#语言。如果我们使用 Visual Basic，它将是`vbhtml`。它首先在与控制器文件夹名称相似的文件夹中查找文件。如果在这个文件夹中找不到文件，它会在`shared`文件夹中查找。

上面代码片段中的第二个操作方法使用了`[HttpPost]`属性，这意味着它处理`Post`请求。这个操作方法只是通过调用`_repository`的`AddProduct`方法来添加产品。在这个操作方法中，我们使用了`[ValidateAntiForgeryToken]`属性和`[FromBody]`，这是一个模型绑定器。

MVC 框架通过提供`[ValidateAntiForgeryToken]`属性为我们的应用程序提供了很多安全性，以保护我们免受**跨站脚本**/**跨站请求伪造**（**XSS/CSRF**）攻击。这种类型的攻击通常包括一些危险的客户端脚本代码。

MVC 中的模型绑定将数据从`HTTP`请求映射到操作方法参数。与操作方法一起经常使用的模型绑定属性如下：

+   `[FromHeader]`

+   ``[FromQuery]``

+   `[FromRoute]`

+   `[FromForm]`

我们不打算详细讨论这些，因为这超出了本书的范围。但是，您可以在官方文档中找到完整的详细信息：[`docs.microsoft.com/en-us/aspnet/core/mvc/models/model-binding`](https://docs.microsoft.com/en-us/aspnet/core/mvc/models/model-binding)。

在上面的代码片段中，我们讨论了`Create`和`Read`操作。现在是时候为`Update`操作编写代码了。在下面的代码中，我们有两个操作方法：一个是`Get`，另一个是`Post`请求：

```cs
public IActionResult Edit(Guid id) => View(_repositry.GetProduct(id));

[HttpPost]
[ValidateAntiForgeryToken]
public IActionResult Edit(Guid id, [FromBody] Product product)
{
    try
    {
        _repositry.UpdateProduct(product);
        return RedirectToAction(nameof(Index));
    }
    catch
    {
        return View();
    }
}
```

上面代码的第一个操作方法根据`ID`获取`Product`并返回一个`View`。第二个操作方法从视图中获取数据并根据其 ID 更新请求的`Product`：

```cs
public IActionResult Delete(Guid id) => View(_repositry.GetProduct(id));

[HttpPost]
[ValidateAntiForgeryToken]
public IActionResult Delete(Guid id, [FromBody] Product product)
{
    try
    {
        _repositry.RemoveProduct(product);
        return RedirectToAction(nameof(Index));
    }
    catch
    {
        return View();
    }
}
```

最后，上面的代码表示了我们的`CRUD`操作中的`Delete`操作。它还有两个操作方法；一个从存储库中检索数据并将其提供给视图，另一个获取数据请求并根据其 ID 删除特定的`Product`。

`CategoryController`负责`Product`类别的所有操作。将以下代码添加到控制器中，它表示`CategoryController`，我们在其中使用依赖注入来初始化我们的`IInventoryRepository`：

```cs
public class CategoryController: Controller
{
  private readonly IInventoryRepositry _inventoryRepositry;
  public CategoryController(IInventoryRepositry inventoryRepositry) => _inventoryRepositry = inventoryRepositry;
 //code omitted
}
```

以下代码包含两个操作方法。第一个获取类别列表，第二个是根据其唯一 ID 获取特定类别：

```cs
public IActionResult Index() => View(_inventoryRepositry.GetCategories());
public IActionResult Details(Guid id) => View(_inventoryRepositry.GetCategory(id));
```

以下代码是用于在系统中创建新类别的`Get`和`Post`请求：

```cs
public IActionResult Create() => View();
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Create([FromBody] Category category)
    {
        try
        {
            _inventoryRepositry.AddCategory(category);

            return RedirectToAction(nameof(Index));
        }
        catch
        {
            return View();
        }
    }
```

在以下代码中，我们正在更新我们现有的类别。代码包含了带有`Get`和`Post`请求的`Edit`操作方法：

```cs
public IActionResult Edit(Guid id) => View(_inventoryRepositry.GetCategory(id));
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Edit(Guid id, [FromBody]Category category)
    {
        try
        {
            _inventoryRepositry.UpdateCategory(category);

            return RedirectToAction(nameof(Index));
        }
        catch
        {
            return View();
        }
    }
```

最后，我们有一个`Delete`操作方法。这是我们`Category`删除的`CRUD`页面的最终操作，如下所示：

```cs
public IActionResult Delete(Guid id) => View(_inventoryRepositry.GetCategory(id));

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Delete(Guid id, [FromBody] Category category)
    {
        try
        {
            _inventoryRepositry.RemoveCategory(category);

            return RedirectToAction(nameof(Index));
        }
        catch
        {
            return View();
        }
    }
```

`Views`：将以下视图添加到各自的文件夹中：

+   `Index.cshtml`

+   `Create.cshtml`

+   `Edit.cshtml`

+   `Delete.cshtml`

+   `Details.cshtml`

`Contexts`：将`InventoryContext.cs`文件添加到`Contexts`文件夹，并使用以下代码：

```cs
public class InventoryContext : DbContext
{
    public InventoryContext(DbContextOptions<InventoryContext> options)
        : base(options)
    {
    }

    public InventoryContext()
    {
    }

    public DbSet<Product> Products { get; set; }
    public DbSet<Category> Categories { get; set; }
}
```

上述代码提供了使用 EF 与数据库交互所需的各种方法。在运行代码时，您可能会遇到以下异常：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/09846618-7502-478b-ae84-e203b2782913.png)

要解决此异常，您应该在`Startup.cs`文件中映射到`IInventoryRepository`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/f418bdc3-b1ce-46c5-a0b7-41d831833606.png)

我们现在已经为我们的 Web 应用程序添加了各种功能，我们的解决方案现在如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/73cc1b91-de98-4cbb-b856-17e25a46a91b.png)

有关本章的 GitHub 存储库，请参阅[`github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter6`](https://github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter6)。

如果我们要可视化 MVC 模型，那么它将按照以下图表所示的方式工作：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/6b34db05-1e93-4888-b96c-87eec3c74beb.png)

上述图像改编自[`commons.wikimedia.org/wiki/File:MVC-Process.svg`](https://commons.wikimedia.org/wiki/File:MVC-Process.svg)

如前图所示，每当用户发出请求时，它都会传递到控制器并触发操作方法进行进一步操作或更新，如果需要的话，传递到模型，然后向用户提供视图。

在我们的情况下，每当用户请求`/Product`时，请求会传递到`ProductController`的`Index`操作方法，并在获取产品列表后提供`Index.cshtml`视图。您将会得到如下截图所示的产品列表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/2fdb3ea4-40db-49a3-852d-d682bc005bcb.png)

上述截图是一个简单的产品列表，它代表了`CRUD`操作的`Read`部分。在此屏幕上，应用程序显示了总共可用的产品及其类别。

以下图表描述了我们的应用程序如何交互：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/d2db4ee2-a842-4379-8522-3b31f80147af.png)

它显示了我们应用程序流程的图形概述。`InventoryRepository`依赖于`InventoryContext`进行数据库操作，并与我们的模型类`Category`和`Product`进行交互。我们的`Product`和`Category`控制器使用`IInventoryRepository`接口与存储库进行 CRUD 操作的交互。

# 总结

本章的主要目标是启动一个基本的 Web 应用程序。

我们通过讨论业务需求开始了本章，解释了为什么需要 Web 应用程序以及为什么要升级我们的控制台应用程序。然后，我们使用 Visual Studio 在 MVC 模式中逐步创建了 Web 应用程序。我们还讨论了 Web 应用程序如何作为客户端-服务器模型工作，并且研究了用户界面模式。我们还开始构建 CRUD 页面。

在下一章中，我们将继续讨论 Web 应用程序，并讨论更多 Web 应用程序的设计模式。

# 问题

以下问题将帮助您巩固本章中包含的信息：

1.  什么是 Web 应用程序？

1.  精心打造一个您选择的 Web 应用程序，并描述其工作原理。

1.  控制反转是什么？

1.  在本章中我们涵盖了哪些架构模式？您喜欢哪一种，为什么？

# 进一步阅读

恭喜！您已完成本章内容。我们涵盖了与身份验证、授权和测试项目相关的许多内容。这并不是您学习的终点；这只是一个开始，还有更多书籍可以供您参考，以增进您的理解。以下书籍深入探讨了 RESTful Web 服务和测试驱动开发：

+   *使用.NET Core 构建 RESTful Web 服务*，作者为*Gaurav Aroraa*，*Tadit Dash*，出版社为*Packt Publishing*，网址：[`www.packtpub.com/application-development/building-restful-web-services-net-core`](https://www.packtpub.com/application-development/building-restful-web-services-net-core)

+   *C#和.NET Core 测试驱动开发*，作者为*Ayobami Adewole*，出版社为*Packt Publishing*，网址：[`www.packtpub.com/application-development/c-and-net-core-test-driven-development`](https://www.packtpub.com/application-development/c-and-net-core-test-driven-development)
