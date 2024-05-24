# C# 编程学习手册（四）

> 原文：[`zh.annas-archive.org/md5/43CC9F8096F66361F01960142D9E6C0F`](https://zh.annas-archive.org/md5/43CC9F8096F66361F01960142D9E6C0F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：资源管理

在之前的章节中，我们讨论并使用了值类型和引用类型，并且也看到了它们的不同之处。我们也简要讨论了运行时如何管理分配的内存。

在本章中，我们将更详细地讨论这个主题，并查看管理内存和资源的语言特性和最佳实践。

本章将讨论以下主题：

+   垃圾回收

+   终结器

+   IDisposable 接口

+   `using`语句

+   平台调用

+   不安全的代码

在本章结束时，您将学会如何实现可处理的类型以及在不再需要时如何处理对象。您还将学会如何调用本机 API 并编写不安全的代码。

# 垃圾回收

**公共语言运行时**（**CLR**）负责管理对象的生命周期，并在不再使用时释放内存，以便在进程内分配新对象。它通过一个名为**垃圾收集器**（**GC**）的组件来实现这一点，该组件以高效的方式在托管堆上分配对象，并通过回收不再使用的对象来清除内存。垃圾收集器使得开发应用程序更容易，因为您不必担心手动释放内存。这就是使为.NET 编写的应用程序被称为*托管*的原因。

在我们讨论所有这些是如何发生之前，你需要理解**栈**和**堆**之间的区别，以及**类型**、**对象**和**引用**之间的区别。

类型（无论是在 C#中使用`class`还是`struct`关键字引入的）是构造对象的蓝图。它在源代码中使用语言特性描述。对象是类型的实例化，并存在于内存中。引用是一种句柄（基本上是一个存储位置），指向一个对象。

现在，让我们讨论内存。栈是编译器分配的一个相对较小的内存段，用于跟踪运行应用程序所需的内存。栈具有**后进先出（LIFO）**语义，并且随着程序执行调用函数或从函数返回而增长和缩小。另一方面，堆是程序可能在运行时分配内存的一个大内存段，在.NET 中由 CLR 管理。

值类型的对象可以存储在多个位置。它们通常存储在栈上，但也可以存储在 CPU 寄存器上。作为引用类型的值类型存储在堆上作为*封闭对象*的一部分。引用类型的对象总是存储在堆上，但对象的引用存储在栈或 CPU 寄存器上。

为了更好地理解这一点，让我们考虑下面的短程序，其中`Point2D`是一个值类型，`Engine`是一个引用类型：

```cs
class Program
{
    static void Main(string[] args)
    {
        var i = 42;
        var pt = new Point2D(1, 2); // value type
        var engine = new Engine();  // reference type
    }
}
```

在概念上（因为这是一个非常简单的表示），栈和堆将包含以下值：

![图 9.1 - 在上述程序执行期间栈和堆内容的概念表示](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_9.1_B12346.jpg)

图 9.1 - 在上述程序执行期间栈和堆内容的概念表示

栈由编译器管理，本章的其余部分我们将讨论堆以及运行时如何管理它。.NET 运行时将对象分为两组：

+   **大型**：这些对象是大于 85 KB 的对象；多维对象也包括在此类别中。

+   **小型**：这些对象是所有其他对象。

堆由称为**代**的几个内存段组成。内存有三代 - **0**，**1**和**2**：

+   第 0 代包含*小*，通常是*短寿命的对象*，比如局部变量或在函数调用的生命周期内实例化的对象。

+   第一代包含*小对象*，它们在对第 0 代内存进行垃圾收集后幸存下来。

+   第 2 代包含*长寿命的小对象*，它们在对第 1 代内存进行垃圾收集后幸存下来，以及大对象（总是分配在这个段上）。

当运行时需要在托管堆上分配对象而内存不足时，它会触发垃圾收集。垃圾收集有三个阶段：

+   首先，垃圾收集器构建了所有活动对象的图形，以便弄清楚什么仍在使用，什么可以被删除。

+   第二，更新将被压缩的对象的引用。

+   第三，死对象被移除，幸存对象被压缩。通常，包含大对象的大对象堆不会被压缩，因为移动大块数据会产生性能成本。

当垃圾收集开始时，所有托管线程都被暂停，除了启动收集的线程。当垃圾收集结束时，线程会恢复。垃圾收集的第一阶段从所谓的**应用根**开始，这些是包含对堆上对象引用的存储位置。应用根包括对全局对象、静态对象、字段、局部对象、作为函数参数传递的对象、等待终结的对象以及包含对堆上对象引用的 CPU 寄存器的引用。

CLR 构建了可达堆对象的图形；所有不可达的对象将被删除。如果所有第 0 代对象都已经被评估，但释放的内存还不够，垃圾收集将继续评估第 1 代。如果之后需要更多内存，垃圾收集将继续评估第 2 代。

幸存下来的第 0 代垃圾收集的对象被分配到第 1 代，幸存下来的第 1 代对象被分配到第 2 代。然而，幸存下来的第 2 代垃圾收集的对象仍然留在第 2 代。如果垃圾收集过程结束后，在大对象堆上没有足够的内存（总是属于第 2 代）来分配所请求的内存，CLR 会抛出`OutOfMemoryException`类型的异常。这并不一定意味着没有更多的内存，而是这个段上未压缩的内存不包含足够大的块来存放新对象。

基类库包含一个名为`System.GC`的类，它使我们能够与垃圾收集器交互。然而，除了在本章后面将看到的*IDisposable 接口*部分中实现的可释放模式之外，这很少发生。这个类有几个成员：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_09_Table_1_01.png)

以下程序使用`System.GC`类来显示`Engine`对象的当前代数，以及调用时托管堆的估计大小：

```cs
class Program
{
    static void Main(string[] args)
    {
        var engine = new Engine("M270 Turbo", 1600, 75.0);
        Console.WriteLine(
          $"Generation of engine: 
        {GC.GetGeneration(engine)}"); 
        Console.WriteLine(
          $"Estimated heap size: {GC.
        GetTotalMemory(false)}"); 
    }
}
```

程序的输出如下：

![图 9.2 – 一个控制台截图显示了前面程序的输出](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_9.2_B12346.jpg)

图 9.2 – 一个控制台截图显示了前面程序的输出

我们将在下一节学习终结器。

# 终结器

垃圾收集器提供了托管资源的自动释放。然而，有些情况下你必须处理非托管资源，比如原始文件句柄、窗口或其他通过**平台调用服务**（**P/Invoke**）调用检索的操作系统资源，以及一些高级场景中的 COM 对象引用。这些资源在对象被垃圾收集器销毁之前必须显式释放，否则会发生资源泄漏。

每个对象都有一个特殊的方法，称为`System.Object`类有一个虚拟的受保护成员叫做`Finalize()`，带有一个空的实现。下面的代码展示了这一点：

```cs
class Object
{
    protected virtual void Finalize() {}
}
```

尽管这是一个虚方法，但你实际上不能直接重写它。相反，C#语言提供了一个与 C++中析构函数相同的语法来创建一个终结器并重写`System.Object`方法。然而，这只对引用类型实现是可能的；值类型不能有终结器，因为它们不会被垃圾收集。以下代码展示了这一点：

```cs
class ResourceWrapper
{
    // constructor
    ResourceWrapper() 
    {
        // construct the object
    }
    // finalizer
    ~ResourceWrapper()
    {
        // release unmanaged resources
    }
}
```

你不能显式重写`Finalize()`方法的原因是，C#编译器会添加额外的代码来确保在终结时实际上调用基类的实现（这意味着在继承链中的所有实例上都调用`Finalize()`方法）。因此，编译器用以下代码替换了之前显示的终结器：

```cs
class ResourceWrapper
{
    protected override void Finalize()
    {
        try
        {
            // release unmanaged resources
        }
        finally
        {
            base.Finalize();
        }
    }
}
```

尽管一个类可能有多个构造函数，但它只能有*一个终结器*。因此，终结器不能被重载或具有修饰符和参数；它们也不能被继承。终结器不会被直接调用，而是由垃圾收集器调用。

垃圾收集器调用终结器的方式如下。当创建一个具有终结器的对象时，垃圾收集器将其引用添加到一个名为*终结队列*的内部结构中。在收集对象时，垃圾收集器调用终结队列中所有对象的终结器，除非它们已经通过调用`GC.SupressFinalize()`免除了终结。这也是在应用程序域被卸载时进行的操作，但仅适用于.NET Framework；对于.NET Core 来说，情况并非如此。终结器的调用仍然是不确定的。调用的确切时刻以及调用发生的线程都是未定义的。此外，即使两个对象的终结器相互引用，也不能保证以任何特定顺序发生。

信息框

由于终结器会导致性能损失，请确保不要创建空的终结器。只有在对象必须处理未托管资源时才实现终结器。

以下代码中显示的`HandleWrapper`类是一个本机句柄的包装器。实际的实现可能更复杂；这只是为教学目的而显示的。原始句柄可能是在本机代码中创建并传递给托管应用程序。这个类拥有句柄的所有权，因此在对象不再需要时需要释放它。这是通过使用*P/Invoke*调用`CloseHandle()`系统 API 来完成的。该类定义了一个终结器来实现这一点。让我们看一下以下代码：

```cs
public class HandleWrapper
{
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr hHandle);
    public IntPtr Handle { get; private set; }

    public HandleWrapper(IntPtr ptr)
    {
        Handle = ptr;
    }

    ~HandleWrapper()
    {
        if(Handle != default)
            CloseHandle(Handle);
    } 
}
```

很少有情况下你实际上需要创建一个终结器。对于前面提到的情景，有系统包装器可用于处理未托管资源。你应该使用以下安全句柄之一：

+   `SafeFileHandle`：文件句柄的包装器

+   `SafeMemoryMappedFileHandle`，内存映射文件句柄的包装器

+   `SafeMemoryMappedViewHandle`，一个对未托管内存块的指针的包装器

+   `SafeNCryptKeyHandle`，`SafeNCryptProviderHandle`和`SafeNCryptSecretHandle`，加密句柄的包装器

+   `SafePipeHandle`，管道句柄的包装器

+   `SafeRegistryHandle`，对注册表键句柄的包装器

+   `SafeWaitHandle`，等待句柄的包装器

如前所述，终结器仍然是不确定的。为了确保资源的确定性释放，无论是托管的还是未托管的，一个类型应该提供一个`Close()`方法或实现`IDisposable`接口。在这种情况下，终结器只能用于在未调用`Dispose()`方法时释放未托管资源。

我们将在下一节学习`IDisposable`接口。

# `IDisposable`接口

资源的确定性处理可以通过实现`System.IDisposable`接口来完成。这个接口有一个叫做`Dispose()`的方法，当一个对象不再被使用并且它的资源可以被处理时，用户可以显式调用这个方法。然而，你只应该在以下情况下实现这个接口：

+   这个类拥有*非托管资源*

+   这个类拥有*托管资源*，它们本身是可处理的

这个接口应该如何实现取决于这个类是否拥有非托管资源。当你既有托管资源又有非托管资源时，通常的模式如下：

```cs
public class MyResource : IDisposable
{
    private bool disposed = false;
    protected virtual void Dispose(bool disposing)
    {
        if (!disposed)
        {
            if (disposing)
            {
                // dispose managed objects
            }
            // free unmanaged resources
            // set large fields to null.
            disposed = true;
        }
    }
    ~MyResource()
    {
        Dispose(false);
    }
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}
```

从`IDisposable`接口的`Dispose()`方法中，我们调用一个受保护的虚拟方法，方法名相同（尽管可以有任何名字），并且有一个参数指定对象正在被销毁。为了确保资源的处理只发生一次，使用了一个布尔字段（这里叫做`disposed`）。重载的`Dispose()`方法的布尔参数指示这个方法是由用户以确定性方式调用的，还是由垃圾收集器在对象终结时以非确定性方式调用的。

在前一种情况下，托管和非托管资源都应该被处理，并且对象的终结应该被抑制，通过调用`GC.SupressFinalize()`。在后一种情况下，只有非托管资源必须被处理，因为处理不是由用户调用的，而是由垃圾收集器调用的。这个函数是虚拟的和受保护的原因是，派生类应该能够重写它，但不应该能够直接从类外部调用它。

让我们看看如何为不同的情况实现这个。首先，我们将考虑这样一个情况，即类只有可处理的托管资源。在下面的例子中，`Engine`类实现了`IDisposable`。它具体做什么，管理什么资源，以及如何处理它们并不重要。然而，`Car`类拥有对`Engine`对象的拥有引用，这个引用应该在`Car`对象被销毁时立即销毁。此外，这应该以确定性的方式进行，当`Car`不再需要时。在这种情况下，`Car`类必须按照以下方式实现`IDisposable`接口：

```cs
public class Engine : IDisposable {}
public class Car : IDisposable
{
    private Engine engine;
    public Car(Engine e)
    {
        engine = e;
    }
    #region IDisposable Support
    private bool disposed = false;
    protected virtual void Dispose(bool disposing)
    {
        if (!disposed)
        {
            if (disposing)
            {
                engine?.Dispose();
            }
            disposed = true;
        }
    }
    public void Dispose()
    {
        Dispose(true);
    }
    #endregion
}
```

由于这个类没有终结器，重载的`Dispose()`方法在这里用处不大，代码可以进一步简化。然而，派生类可以重写它并处理更多的资源。

在前一节中，我们实现了一个叫做`HandleWrapper`的类，它有一个终结器来关闭它拥有的系统句柄。在下面的清单中，你可以看到这个类的修改版本，它实现了`IDisposable`接口：

```cs
public class HandleWrapper : IDisposable
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hHandle);
    public IntPtr Handle { get; private set; }
    public HandleWrapper(IntPtr ptr)
    {
        Handle = ptr;
    }
    private bool disposed = false; // To detect redundant calls
    protected virtual void Dispose(bool disposing)
    {
        if (!disposed)
        {
            if (disposing)
            {
                // nothing to dispose
            }
            if (Handle != default)
                CloseHandle(Handle);
            disposed = true;
        }
    }
    ~HandleWrapper()
    {
        Dispose(false);
    }
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}
```

这个类既有一个`Dispose()`方法（可以被用户调用），又有一个终结器（在用户没有调用`Dispose()`方法的情况下，由垃圾收集器调用）。在这个例子中没有托管资源需要释放，所以重载的`Dispose()`方法的布尔参数基本上是没有用的。

语言为我们提供了一种自动处理实现`IDisposable`接口的对象的方式，当它们不再需要时。我们将在下一节中了解这个。

# using 语句

在我们介绍`using`语句之前，让我们看看如何以正确的方式进行显式资源管理。这将帮助你更好地理解`using`语句的需要和工作原理。

我们在前一节中看到的`Car`类可以这样使用：

```cs
Car car = null;
try
{
    car = new Car(new Engine());
    // use the car here
}
finally
{
    car?.Dispose();
}
```

应该使用`try-catch-finally`块（尽管这里没有明确显示`catch`）来确保在不再需要对象时正确处理对象。然而，C#语言提供了一个方便的语法来确保使用`using`语句正确处理对象的释放。它的形式如下：

```cs
using (ResourceType resource = expression) statement
```

编译器将其转换为以下代码：

```cs
{
    ResourceType resource = expression;
    try {
        statement;
    }
    finally {
        resource.Dispose();
    }
}
```

`using`语句引入了一个变量的作用域，并确保在退出作用域之前正确处理对象。实际的处理取决于资源是值类型、可空值类型、引用类型还是动态类型。之前对`resource.Dispose()`的调用实际上是以下之一：

```cs
// value types
((IDisposable)resource).Dispose();
// nullable value types or reference types
if (resource != null) 
    ((IDisposable)resource).Dispose();
// dynamic
if (((IDisposable)resource) != null) 
    ((IDisposable)resource).Dispose();
```

对于汽车示例，我们可以如下使用它：

```cs
using (Car car = new Car(new Engine()))
{
    // use the car here
}
```

多个对象可以实例化到同一个`using`语句中，如下例所示：

```cs
using (Car car1 = new Car(new Engine()),
           car2 = new Car(new Engine()))
{
    // use car1 and car2 here
}
```

另一方面，多个`using`语句可以链接在一起，如下所示，这等效于前面的代码：

```cs
using (var car1 = new Car(new Engine()))
using (var car2 = new Car(new Engine()))
{
    // use car1 and car2 here
}
```

在 C# 8 中，`using`语句可以写成如下形式：

```cs
using Car car = new Car(new Engine());
// use the car here
```

有关更多信息，请参阅*第十五章*，*C# 8 的新功能*。

# 平台调用

在本章的早些时候，我们实现了一个句柄包装类，该类使用 Windows API 函数`CloseHandle()`在对象被处理时删除系统句柄。C#程序可以调用 Windows API，也可以调用从本机**动态链接库（DLL）**导出的任何函数，都是通过**平台调用服务**，也称为**平台调用**或**P/Invoke**。

P/Invoke 定位并调用导出的函数，并在托管和非托管边界之间进行参数传递。为了能够使用 P/Invoke 调用函数，您必须知道函数的名称和签名，以及它所在的 DLL 的名称。然后，您必须创建非托管函数的托管定义。为了理解这是如何工作的，我们将看一个`user32.dll`中可用的`MessageBox()`函数的示例。函数签名如下：

```cs
int MessageBox(HWND hWnd, LPCTSTR lpText,
               LPCTSTR lpCaption, UINT uType);
```

我们可以为函数创建以下托管定义：

```cs
static class WindowsAPI
{
    [DllImport("user32.dll")]
    public static extern int MessageBox(IntPtr hWnd, 
                                        string lpText, 
                                        string lpCaption, 
                                        uint uType);
}
```

这里有几件事情需要注意：

+   托管定义的签名必须与本机定义匹配，使用等效的托管类型作为参数。

+   函数必须定义为`static`和`extern`。

+   函数必须用`DllImportAttribute`修饰。此属性为运行时调用本机函数定义了必要的信息。

`DllImportAttribute`至少需要指定从中导出本机函数的 DLL 的名称。您可以省略 DLL 中入口点的名称，此时将使用托管函数的名称来标识它。但是，您也可以使用属性的`EntryPoint`显式指定它。您可以指定的其他属性如下：

+   `BestFitMapping`：一个布尔标志，指示是否启用最佳匹配映射。在从 Unicode 到 ANSI 字符的转换时使用。最佳匹配映射使得互操作编组器在不存在精确匹配时使用最接近的字符（例如，版权字符被替换为*c*）。

+   `CallingConvention`：入口点的调用约定。默认值为`Winapi`，默认为`StdCall`。

+   `CharSet`：指定字符串参数的编组行为。它还用于指定要调用的入口点名称。例如，对于消息框示例，Windows 实际上有两个函数—`MessageBoxA()`和`MessageBoxW()`。`CharSet`参数的值使运行时能够在其中选择一个；更准确地说，以`CharSet.Ansi`结尾的名称用于`CharSet.Ansi`（这是 C#的默认值），以`CharSet.Unicode`结尾的名称用于`CharSet.Unicode`。

+   `EntryPoint`：入口点名称或序数。

+   `ExactSpelling`：指示`CharSet`字段是否确定 CLR 搜索非托管 DLL 以查找除已指定的之外的入口点名称。

+   `PreserveSig`：一个布尔标志，指示`HRESULT`或`retval`值是直接翻译（如果为`true`）还是自动转换为异常（如果为`false）。默认值为`true`。

+   `SetLastError`：如果为`true`，则表示被调用者在返回之前调用`SetLastError()`。在这种情况下，CLR 调用`GetLastError()`并缓存该值，以防止被其他 Windows API 调用覆盖和丢失。要检索该值，可以调用`Marshal.GetLastWin32Error()`。

+   `ThrowOnUnmappableChar`：指示（当为`true`时）编组器在将 Unicode 字符转换为 ANSI '`?`'时是否应抛出错误。默认值为`false`。

以下表格显示了 Windows API 和 C 风格函数中的数据类型，以及它们对应的 C#或.NET Framework 类型：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_09_Table_2_01.jpg)

重要提示

[1] 在`string`参数上使用`CharSet.Ansi`修饰或使用`[MarshalAs(UnmanagedType.LPStr)]`属性。

[2] 在`string`参数上使用`CharSet.Unicode`修饰或使用`[MarshalAs(UnmanagedType.LPWStr)]`属性。

为了能够正确调用我们之前定义的`MessageBox()`函数，我们还应该为可能的参数和返回值定义常量。下面是一个片段：

```cs
static class WindowsAPI
{
    public static class MessageButtons
    {
        public const int MB_OK = 0;
        public const int MB_OKCANCEL = 1;
        public const int MB_YESNOCANCEL = 3;
        public const int MB_YESNO = 4; 
    }

    public static class MessageIcons
    {
        public const int MB_ICONERROR = 0x10;
        public const int MB_ICONQUESTION = 0x20;
        public const int MB_ICONWARNING = 0x30;
        public const int MB_ICONINFORMATION = 0x40;
    }

    public static class MessageResult
    {
        public const int IDOK = 1;
        public const int IDYES = 6;
        public const int IDNO = 7;
    }
}
```

设置好这一切后，我们可以调用`MessageBox()`函数，如下所示：

```cs
class Program
{
    static void Main(string[] args)
    {
        var result = WindowsAPI.MessageBox(
            IntPtr.Zero, 
            "Is this book helpful?",
            "Question",
            WindowsAPI.MessageButtons.MB_YESNO | 
            WindowsAPI.MessageIcons.MB_ICONQUESTION);

        if(result == WindowsAPI.MessageResult.IDYES)
        {
            // time to learn more
        }
    }
}
```

许多 Windows API 需要使用缓冲区来返回数据。例如，`advapi32.dll`中的`GetUserName()`函数返回与当前执行线程关联的用户的名称。函数签名如下：

```cs
BOOL GetUserName(LPSTR lpBuffer, LPDWORD pcbBuffer);
```

第一个参数是一个指向字符数组的指针，用于接收用户的名称，而第二个参数是一个指向无符号整数的指针，用于指定缓冲区的大小。缓冲区需要足够大以接收用户名。否则，函数将返回`false`，在`pcbBuffer`参数中设置所需的大小，并将最后的错误设置为`ERROR_INSUFFICIENT_BUFFER`。

虽然您可以分配一个足够大的缓冲区来容纳结果（一些函数对返回值的大小施加限制），但您并不总是能确定。因此，通常，您会调用这样的函数两次：

+   首先，使用一个空缓冲区来获取实际所需的缓冲区大小

+   然后，分配必要的内存后，再次调用，使用足够大的缓冲区来接收结果

为了看到这是如何工作的，我们将 P/Invoke`GetUserName()`函数，其托管定义如下：

```cs
[DllImport("advapi32.dll", SetLastError = true,
           CharSet = CharSet.Unicode)]
public static extern bool GetUserName(StringBuilder lpBuffer,
                                      ref uint nSize);
```

请注意，我们在缓冲区参数中使用`StringBuilder`。虽然这可以增长到任何容量，但我们需要知道要指定的大小。而不是指定一个随机的大尺寸，我们调用函数两次，如下所示：

```cs
uint size = 0;
var result = WindowsAPI.GetUserName(null, ref size);
if(!result &&
   Marshal.GetLastWin32Error() ==
       WindowsAPI.ErrorCodes.ERROR_INSUFFICIENT_BUFFER)
{
    Console.WriteLine($"Requires buffer size: {size}");
    StringBuilder buffer = new StringBuilder((int)size);
    result = WindowsAPI.GetUserName(buffer, ref size);
    if(result)
    {
        Console.WriteLine($"User name: {buffer.ToString()}");
    }
}
```

在这个例子中，`StringBuffer`对象是用初始容量创建的，尽管这并不是真正必要的。您不必指定其容量；它将增长到所需的容量并接收正确的结果。

让我们总结一下平台调用服务，使用以下几点：

+   允许调用从本地 DLL 导出的函数。

+   您必须为函数创建一个托管定义，具有相同的签名和本机类型的等效托管类型。

+   在定义托管函数时，您必须至少指定函数入口点和导出 DLL 的名称。

使用 P/Invoke 时存在一些缺点，因此您应该牢记以下几点：

+   如果您使用 P/Invoke 调用 Windows API 中的函数，则您的应用程序将仅在 Windows 上运行。如果您不打算使其跨平台，这不是问题。否则，您必须完全避免这种情况。

+   如果您需要调用 C++库中的函数，您必须在导入声明中指定装饰名称，这可能会很麻烦。如果您还要编写 C++库，可以导出具有`extern "C"`链接的函数，以防止链接器对名称进行装饰。

+   在托管类型和非托管类型之间进行编组会有一些轻微的开销。

+   有时这可能不太直观；例如，指针和句柄使用什么类型。

在本章的最后一节中，我们将讨论不安全的代码和指针类型，这是 C#中的第三类类型。

# 不安全的代码

当我们讨论.NET Framework 和 C#语言支持的类型时，我们指的是值类型（结构）和引用类型（类）。然而，还有一种类型得到了支持，那就是**指针类型**。如果你不熟悉 C 或 C++编程语言，特别是指针，那么你应该知道指针就像*引用*——它们是包含对象地址的存储位置。引用基本上是由 CLR 管理的*安全指针*。

要使用指针类型，你必须建立所谓的*不安全上下文*。在 CLR 术语中，这被称为*不可验证的代码*，因为 CLR 无法验证其安全性。不安全的代码不一定是危险的，但你完全有责任确保你不会引入指针错误或安全风险。

事实上，在 C#中，有很少的情况下你实际上需要在不安全的上下文中使用指针。有两种常见的情况可能会出现这种情况：

+   调用从本机 DLL 或 COM 服务器导出的需要指针类型作为参数的函数。然而，在大多数情况下，你仍然可以使用`System.IntPtr`和`System.Runtime.InteropServices.Marshal`类型的成员来使用安全代码。

+   优化特定算法，性能至关重要。

你可以使用`unsafe`关键字定义不安全的上下文。这可以应用于以下情况：

+   类型（类、结构、接口、委托），在这种情况下，整个类型的文本上下文被视为不安全：

```cs
unsafe struct Node
{
    public int value;
    public Node* left;
    public Node* right;
}
```

+   方法、字段、属性、事件、索引器、运算符、实例和静态构造函数以及析构函数，在这种情况下，成员的整个文本上下文被视为不安全：

```cs
struct Node
{
    public int Value;
    public unsafe Node* Left;
    public unsafe Node* Right;
}
unsafe void Increment(int* value)
{
    *value += 1;
}
```

+   一个语句（块），在这种情况下，整个块的文本上下文被视为不安全：

```cs
static void Main(string[] args)
{
    int value = 42;
    unsafe
    {
        int* p = &value;
        *p += 1;
    }
    Console.WriteLine(value); // prints 43
 }
```

然而，为了能够编译使用不安全上下文的代码，你必须显式地使用`/unsafe`编译器开关。在 Visual Studio 中，你可以在**项目属性** | **构建**下的**常规**部分中勾选**允许不安全代码**选项，如下截图所示：

![图 9.3 – Visual Studio 的项目属性页面，允许启用不安全代码选项](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_9.3_B12346.jpg)

图 9.3 – Visual Studio 的项目属性页面，允许启用不安全代码选项

不安全的代码只能从另一个不安全的上下文中执行。例如，如果你有一个声明为`unsafe`的方法，你只能从不安全的上下文中调用它。这在下面的例子中得到了展示，其中不安全的`Increment()`方法（之前介绍过）从一个`unsafe`上下文中被调用。在安全的上下文中尝试这样做会导致编译错误：

```cs
static void Main(string[] args)
{
    int value = 42;
    Increment(&value);     // error
    unsafe
    {
        Increment(&value); // OK
    }
 }
```

如果你熟悉 C 或 C++，你会知道指针符号（`*`）可以放在类型旁边、变量旁边或者中间。在 C/C++中，以下都是等价的：

```cs
int* a;
int * a;
int *a;
int* a, *b; // define two variables of type pointer to int
```

然而，在 C#中，你总是在类型旁边放上`*`，就像下面的例子一样：

```cs
int* a, b; // define two variables of type pointer to int
```

变量可以是两种类型——**固定的**和**可移动的**。可移动的变量驻留在由垃圾收集器控制的存储位置中，因此可以移动或收集。固定的变量驻留在不受垃圾收集器操作影响的存储位置中。

在不安全的代码中，你可以使用`&`运算符无限制地获取固定变量的地址。然而，你只能使用固定语句来处理可移动变量。固定语句是用`fixed`关键字引入的，在许多方面类似于`using`语句。

以下是使用固定语句的一个例子：

```cs
class Color
{
    public byte Alpha;
    public byte Red;
    public byte Green;
    public byte Blue;
    public Color(byte a, byte r, byte g, byte b)
    {
        Alpha = a;
        Red = r;
        Green = g;
        Blue = b;
    }
}
static void SetTransparency(Color color, double value)
{
    unsafe
    {
        fixed (byte* alpha = &color.Alpha)
        {
            *alpha = (byte)(value * 255);
        }
    }
}
```

`SetTransparency()`函数使用指向`Alpha`字段的指针来更改`Color`对象的 alpha 值。尽管这是值类型的`byte`类型，但它位于托管堆上，因为它是引用类型的一部分。垃圾回收器可能会在访问`Alpha`字段之前移动或收集`Color`对象。因此，检索其地址的唯一可能方法是使用`fixed`语句。这基本上固定了托管对象，以便垃圾回收器不会移动或收集它。

除了`usafe`和`fixed`，还有两个关键字可以在不安全的上下文中使用：

+   `stackalloc`用于声明在调用堆栈上分配内存的变量（类似于 C 中的`_alloca()`）：

```cs
static unsafe void AllocArrayExample(int size)
{
    int* arr = stackalloc int[size];
    for (int i = 1; i <= size; ++i)
    arr[i] = i;
}
```

+   `sizeof`用于获取值类型的字节大小。对于原始类型和枚举类型，`sizeof`运算符实际上也可以在安全的上下文中调用：

```cs
static void SizeOfExample()
{
    unsafe
    {
        Console.WriteLine(
          $"Pointer size: {sizeof(int*)}");
    }
}
```

让我们通过查看以下关键点来总结不安全代码：

+   它只能在不安全的上下文中执行，使用`unsafe`关键字在使用`/unsafe`开关编译时引入。

+   类型、成员和代码块可以是不安全的上下文。

+   它引入了安全性和稳定性风险，你需要对此负责。

+   只有极少数情况下需要使用它。

# 总结

本章重点介绍了运行时（通过垃圾回收器）如何管理对象和资源的生命周期。我们学习了垃圾回收器的工作原理，以及如何编写终结器来处理本机资源。我们已经看到了如何正确实现`IDisposable`接口和`using`语句的模式，以确定性地释放对象。我们还研究了平台调用服务，它使我们能够从托管代码中进行本机调用，以及编写不安全的代码——这是 CLR 无法验证安全性的代码。

在本书的下一章中，我们将研究不同的编程范式，函数式编程，并了解它在 C#中的关键概念以及它们能够让我们做什么。

# 测试你学到的东西

1.  栈和堆是什么？每个上面分配了什么？

1.  堆的内存段是什么，每个上面分配了什么？

1.  垃圾回收是如何工作的？

1.  终结器是什么？处理和终结之间有什么区别？

1.  `GC.SupressFinalize()`方法是做什么的？

1.  `IDisposable`是什么，何时应该使用它？

1.  `using`语句是什么？

1.  你如何在 C#中从本机 DLL 调用函数？

1.  不安全代码是什么，它通常在哪些场景中使用？

1.  你可以声明哪些程序元素为不安全？

# 进一步阅读

+   *垃圾回收：Microsoft .NET Framework 中的自动内存管理*，Jeffrey Richter – MSDN Magazine: [`docs.microsoft.com/en-us/archive/msdn-magazine/2000/november/garbage-collection-automatic-memory-management-in-the-microsoft-net-framework`](https://docs.microsoft.com/en-us/archive/msdn-magazine/2000/november/garbage-collection-automatic-memory-management-in-the-microsoft-net-framework)

+   *垃圾回收：第二部分：Microsoft .NET Framework 中的自动内存管理*，Jeffrey Richter – MSDN Magazine: [`docs.microsoft.com/en-us/archive/msdn-magazine/2000/december/garbage-collection-part-2-automatic-memory-management-in-the-microsoft-net-framework`](https://docs.microsoft.com/en-us/archive/msdn-magazine/2000/december/garbage-collection-part-2-automatic-memory-management-in-the-microsoft-net-framework)


# 第十章：Lambda、LINQ 和函数式编程

尽管 C#在其核心是一种面向对象的编程语言，但它实际上是一种*多范式语言*。到目前为止，在本书中，我们已经讨论了命令式编程、面向对象编程和泛型编程。然而，C#也支持函数式编程特性。在*第七章*、*集合*和*第八章*、*高级主题*中，我们已经使用了其中一些，比如 lambda 和**语言集成查询（LINQ）**。

在本章中，我们将从功能编程的角度详细讨论这些内容。学习函数式编程技术将帮助您以声明性的方式编写代码，通常比等效的命令式代码更简单、更容易理解。

本章将涵盖以下主题：

+   函数式编程

+   函数作为一等公民

+   Lambda 表达式

+   LINQ

+   更多函数式编程概念

通过本章的学习，您将能够详细了解 lambda 表达式，并能够与 LINQ 一起查询各种来源的数据。此外，您将熟悉函数式编程的概念和技术，如高阶函数、闭包、单子和幺半群。

让我们从功能编程及其核心原则的概述开始这一章。

# 函数式编程

C#是一种通用的多范式编程语言。然而，到目前为止，在本书中，我们只涵盖了命令式编程范式，它使用语句来改变程序状态，并且专注于描述程序的操作方式。在命令式编程中，函数可能具有副作用，因此在执行时改变程序状态。或者，函数的执行可能取决于程序状态。

相反的范式是函数式编程，它关注描述程序做什么而不是如何做。函数式编程将计算视为函数的评估；它使用不可变数据并避免改变状态。函数式编程是一种声明性的编程范式，其中使用表达式而不是语句。函数不再具有副作用，而是幂等的。这意味着使用相同参数调用函数每次都会产生相同的结果。

函数式编程提供了几个优势，包括以下内容：

+   由于函数不改变状态，只依赖于它们接收的参数，代码更容易理解和维护。

+   由于数据是不可变的，函数没有副作用，因此更容易测试代码。

+   由于数据是不可变的，函数没有副作用，实现并发更简单高效，这避免了数据竞争。

`Rectangle`（这也可以是一个类）代表一个矩形：

```cs
struct Rectangle
{
    public int Left;
    public int Right;
    public int Top;
    public int Bottom;
    public int Width { get { return Right - Left; } }
    public int Height { get { return Bottom - Top; } }
    public Rectangle(int l, int t, int r, int b)
    {
        Left = l;
        Top = t;
        Right = r;
        Bottom = b;
    }
}
```

我们可以实例化这种类型并改变它的属性。例如，如果我们想要将矩形的宽度增加 10 个单位，每个方向都相等，我们可以这样做：

```cs
var r = new Rectangle(10, 10, 30, 20);
r.Left -= 5;
r.Right += 5;
r.Top -= 5;
r.Bottom += 5;
```

我们还可以编写一个我们可以调用的函数。这可以是一个*成员函数*，如下所示：

```cs
public void Inflate(int l, int t, int r, int b)
{
    Left -= l;
    Right += r;
    Top -= t;
    Bottom += b;
}
// invoked as
r.Inflate(5, 0, 5, 0);
```

这也可以是一个*非成员函数*，如下面的代码所示。两者之间的区别只是设计上的问题。如果我们无法修改源代码，将其编写为扩展方法是唯一的选择：

```cs
static void Inflate(ref Rectangle rect, 
                    int l, int t, int r, int b)
{
    rect.Left -= l;
    rect.Right += r;
    rect.Top -= t;
    rect.Bottom += b;
}
// invoked as
Inflate(ref r, 5, 0, 5, 0);
```

`Rectangle`数据类型是可变的，因为它的状态可以改变。`Inflate()`方法具有副作用，因为它改变了矩形的状态。在函数式编程中，`Rectangle`应该是不可变的。可能的实现如下所示：

```cs
struct Rectangle
{
    public readonly int Left;
    public readonly int Right;
    public readonly int Top;
    public readonly int Bottom;
    public int Width { get { return Right - Left; } }
    public int Height { get { return Bottom - Top; } }
    public Rectangle(int l, int t, int r, int b)
    {
        Left = l;
        Top = t;
        Right = r;
        Bottom = b;
    }
}
```

`Inflate()`方法的纯函数版本不会产生副作用。它的行为仅取决于参数，结果将是相同的，无论调用多少次具有相同参数。这样的实现示例如下：

```cs
static Rectangle Inflate(Rectangle rect, 
                         int l, int t, int r, int b)
{
    return new Rectangle(rect.Left - l, rect.Top - t,
                         rect.Right + r, rect.Bottom + b);
}
```

现在可以像下面的例子一样使用它们：

```cs
var r = new Rectangle(10, 10, 30, 20);
r = Inflate(r, 5, 0, 5, 0);
```

函数式编程源自λ演算（由阿隆佐·邱奇开发），它是一个基于函数抽象和应用的计算表达的框架或数学系统，使用变量绑定和替换。一些编程语言，比如 Haskell，是纯函数式的。其他的，比如 C#，支持多种范式，不是纯函数式的。

前面的例子展示了一个变量`r`，它被初始化为一个值，然后被改变。在纯函数式编程中，这是不可能的。一旦初始化，变量就不能改变值；而是必须分配一个新的变量。这使得表达式可以被它们的值替换，这是**引用透明性**的一个特性。

C#使我们能够使用函数式编程的概念和习语来编写代码。所有这些的核心都是 lambda 表达式，我们将很快深入研究。在那之前，我们需要探索另一个函数式编程的支柱，那就是将函数视为*一等公民*。

# 函数作为一等公民

在*第八章*《高级主题》中，我们学习了关于委托和事件。委托看起来像一个函数，但它是一种保存与委托定义匹配的函数引用的类型。委托实例可以作为函数参数传递。让我们看一个例子，其中有一个委托接受两个`int`参数并返回一个`int`值：

```cs
public delegate int Combine(int a, int b);
```

然后我们有不同的函数，比如`Add()`，它可以将两个整数相加并返回和，`Sub()`，它可以将两个整数相减并返回差，或者`Mul()`，它可以将两个整数相乘并返回积。它们的签名与委托匹配，因此`Combine`委托的实例可以保存对所有这些函数的引用。这些函数如下所示：

```cs
class Math
{
    public static int Add(int a, int b) { return a + b; }
    public static int Sub(int a, int b) { return a - b; }
    public static int Mul(int a, int b) { return a * b; }
}
```

我们可以编写一个通用函数，可以将其中一个函数应用于两个参数。这样的函数可能如下所示：

```cs
int Apply(int a, int b, Combine f)
{
    return f(a, b);
}
```

调用它很简单——我们传递参数和我们想要调用的实际函数的引用：

```cs
var s = Apply(2, 3, Math.Add);
var d = Apply(2, 3, Math.Sub);
var p = Apply(2, 3, Math.Mul);
```

为了方便，.NET 定义了一组名为`Func`的通用委托，以避免一直定义自己的委托。这些定义在`System`命名空间中，如下所示：

```cs
public delegate TResult Func<out TResult>();
public delegate TResult Func<in T,out TResult>(T arg);
public delegate TResult Func<in T1,in T2,out TResult>(T1 arg1, T2 arg2);
...
public delegate TResult Func<in T1,in T2,in T3,in T4,in T5,in T6,in T7,in T8,in T9,in T10,in T11,in T12,in T13,in T14,in T15,in T16,out TResult>(T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7, T8 arg8, T9 arg9, T10 arg10, T11 arg11, T12 arg12, T13 arg13, T14 arg14, T15 arg15, T16 arg16);
```

这是一组有 17 个重载的函数，可以接受 0、1 或多达 16 个参数（可能是不同类型的），并返回一个值。使用这些系统委托，我们可以将`Apply`函数重写如下：

```cs
T Apply<T>(T a, T b, Func<T, T, T> f)
{
    return f(a, b);
}
```

这个版本的函数是通用的，因此它可以用其他类型的参数来调用，而不仅仅是整数。在前面的例子中调用函数的方式并没有改变。

这些委托返回一个值，因此不能用于没有返回值的函数。在`System`命名空间中有一组类似的重载，称为`Action`，定义如下：

```cs
public delegate void Action();
public delegate void Action<in T>(T obj);
public delegate void Action<in T1,in T2>(T1 arg1, T2 arg2);
...
public delegate void Action<in T1,in T2,in T3,in T4,in T5,in T6,in T7,in T8,in T9,in T10,in T11,in T12,in T13,in T14,in T15,in T16>(T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7, T8 arg8, T9 arg9, T10 arg10, T11 arg11, T12 arg12, T13 arg13, T14 arg14, T15 arg15, T16 arg16);
```

这些委托与我们之前看到的`Func`委托认非常相似。唯一的区别是它们不返回值。仍然有 17 个重载，可以接受 0、1 或多达 16 个输入参数。

在下面的例子中，`Apply`函数被重载，以便它还接受`Action<string>`类型的参数，这是一个具有`string`类型的单个参数并且不返回任何值的函数。在应用函数之后，但在返回结果之前，将调用此操作，并传递描述实际操作的字符串：

```cs
T Apply<T>(T a, T b, Func<T, T, T> f, Action<string> log)
{
    var r = f(a, b);
    log?.Invoke($"{f.Method.Name}({a},{b}) = {r}");
    return r;
}
```

我们可以通过将`Console.WriteLine`作为最后一个参数传递来调用这个新的重载，这样操作就会被记录到控制台上：

```cs
var s = Apply(2, 3, Math.Add, Console.WriteLine);
var p = Apply(2, 3, Math.Mul, Console.WriteLine);
```

`Apply`函数被称为*高阶函数*。高阶函数是一个接受一个或多个函数作为参数、返回一个函数或两者都有的函数。其他所有的函数都被称为*一阶函数*。

有许多高阶函数可能会在没有意识到的情况下使用。例如，`List<T>.Sort (Comparison<T> comparison)`就是这样一个函数。LINQ 中的大多数查询谓词（我们将在本章的*LINQ*部分中探讨）都是高阶函数。

高阶函数的一个例子是返回另一个函数的函数，如下面的代码片段所示。`ApplyReverse()`接受一个函数作为参数，并返回另一个函数，该函数以两个参数调用参数函数，但顺序相反：

```cs
Func<T, T, T> ApplyReverse<T>(Func<T, T, T> f)
{
    return delegate(T a, T b) { return f(b, a); };
}
```

这个函数被调用如下：

```cs
var s = ApplyReverse<int>(Math.Add)(2, 3);
var d = ApplyReverse<int>(Math.Sub)(2, 3);
```

到目前为止，我们所看到的是在 C#中将函数作为参数传递，从函数中返回函数，将函数分配给变量，将它们存储在数据结构中，或者定义匿名函数（即没有名称的函数）的可能性。还可以嵌套函数并测试函数的引用是否相等。一个能做到这些的编程语言被称为将函数视为一等公民，并且它的函数是一等公民。因此，C#就是这样一种语言。

回到之前的例子，调用`Apply()`方法的另一种更简单的方法如下：

```cs
var s = Apply(2, 3, (a, b) => a + b);
var d = Apply(2, 3, (a, b) => a - b);
var p = Apply(2, 3, (a, b) => a * b);
```

在这里，`Math`类的方法已被替换为诸如`(a, b) => a + b`这样的 lambda 表达式。我们甚至可以将`Apply()`函数定义为 lambda 表达式并相应地调用它：

```cs
Func<int, int, Func<int, int, int>, int> apply = 
   (a, b, f) => f(a, b);
var s = apply(2, 3, (a, b) => a + b);
var d = apply(2, 3, (a, b) => a - b);
var p = apply(2, 3, (a, b) => a * b);
```

我们将在下一节深入研究 lambda 表达式。

# Lambda 表达式

Lambda 表达式是一种方便的写匿名函数的方式。它们是一段代码，可以是一个表达式或一个或多个语句，表现得像一个函数，并且可以被分配给一个委托。因此，lambda 表达式可以作为参数传递给函数或从函数中返回。它们是编写 LINQ 查询、将函数传递给高阶函数（包括应该由`Task.Run()`异步执行的代码）以及创建表达式树的一种方便方式。

表达式树是一种以树状数据结构表示代码的方式，其中节点是表达式（如方法调用或二进制操作）。这些表达式树可以被编译和执行，从而使可执行代码能够进行动态更改。表达式树用于实现各种数据源的 LINQ 提供程序以及 DLR 中的.NET Framework 和动态语言之间的互操作性。

让我们从一个简单的例子开始，我们有一个整数列表，我们想要从中删除所有的奇数。可以写成如下形式（注意`IsOdd()`函数可以是类方法，也可以是本地函数）：

```cs
bool IsOdd(int n) { return n % 2 == 1; }
var list = new List<int>() { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
list.RemoveAll(IsOdd);
```

这段代码实际上可以用匿名方法来简化，允许我们将代码传递给委托，而无需定义单独的`IsOdd()`函数：

```cs
var list = new List<int>() { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
list.RemoveAll(delegate (int n) { return n % 2 == 1; });
```

Lambda 表达式允许我们使用更简单的语法进一步简化代码，编译器将其转换为类似于前面代码的内容：

```cs
var list = new List<int>() { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
list.RemoveAll(n => n % 2 == 1);
```

我们在这里看到的 lambda 表达式（`n => n % 2 == 1`）有两部分，由`=>`分隔，这是**lambda 声明运算符**：

+   表达式的左部是*参数列表*（如果有多个参数，则用逗号分隔并括在括号中）。

+   表达式的右部要么是*表达式，要么是语句*。如果右部是表达式（就像前面的例子中），lambda 被称为**表达式 lambda**。如果右部是一个语句，lambda 被称为**语句 lambda**。

语句总是用大括号`{}`括起来。任何表达式 lambda 实际上都可以写成一个语句 lambda。表达式 lambda 是语句 lambda 的简化版本。前面的例子使用表达式 lambda 可以写成以下形式的语句 lambda：

```cs
var list = new List<int>() { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
list.RemoveAll(n => { return n % 2 == 1; });
```

有几个 lambda 表达式的例子：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_10_Table_1_01.jpg)

lambda 没有自己的类型。相反，它的类型要么是分配给它的委托的类型，要么是当 lambda 用于构建表达式树时的`System.Expression`类型。不返回值的 lambda 对应于`System.Action`委托（并且可以分配给一个）。返回值的 lambda 对应于`System.Func`委托。

当你写一个 lambda 表达式时，你不需要写参数的类型，因为这些类型是由编译器推断的。类型推断的规则如下：

+   lambda 必须具有与其分配的委托相同数量的参数。

+   lambda 的每个参数必须隐式转换为它所分配的委托的对应参数。

+   如果 lambda 有返回值，它的类型必须隐式转换为它所分配的委托的返回类型。

Lambda 表达式可以是异步的。这样的 lambda 前面要加上`async`关键字，并且必须包含至少一个`await`表达式。下面的例子展示了一个 Windows Forms 表单上按钮的`Click`事件的异步处理程序：

```cs
public partial class MyForm : Form
{
    public MyForm()
    {
        InitializeComponent();

        myButton.Click += async (sender, e) =>
        {
            await ExampleMethodAsync();
        };
    }
    private async Task ExampleMethodAsync()
    {
        // a time-consuming action
        await Task.Delay(1000);
    }
}
```

在这个例子中，`MyForm`是一个表单类，在它的构造函数中，我们注册了一个`Click`事件的处理程序。这是使用 lambda 表达式完成的，但 lambda 是异步的（它调用一个异步函数），因此需要在前面加上`async`。

lambda 可以使用在方法或包含 lambda 表达式的类型范围内的变量。当变量在 lambda 中使用时，它被捕获，以便即使超出范围也可以使用。这些变量在 lambda 中使用之前必须被明确赋值。在下面的例子中，lambda 表达式捕获了两个变量——`value`函数参数和`Data`类成员：

```cs
class Foo
{
    public int Data { get; private set; }
    public Foo(int value)
    {
        Data = value;
    }
    public void Scramble(int value, int iterations)
    {
        Func<int, int> apply = (i) => Data ^ i + value;
        for(int i = 0; i < iterations; ++i)
           Data = apply(i);
    }
}
```

以下是 lambda 表达式中变量作用域的规则：

+   lambda 表达式中引入的变量在 lambda 之外是不可见的（例如，在封闭方法中）。

+   lambda 不能捕获封闭方法的`in`、`ref`或`out`参数。

+   被 lambda 表达式捕获的变量不会被垃圾回收，即使它们本来会超出范围，直到 lambda 分配的委托被垃圾回收。

+   lambda 表达式的返回语句仅指代 lambda 所代表的匿名方法，并不会导致封闭方法返回。

lambda 表达式最常见的用例是编写 LINQ 查询表达式。我们将在下一节中看到这一点。

# LINQ

LINQ 是一组技术，使开发人员能够以一致的方式查询多种数据源。通常，您会使用不同的语言和技术来查询不同类型的数据，比如关系数据库使用 SQL，XML 使用 XPath。SQL 查询是以字符串形式编写的，这使得它们无法在编译时进行验证，并增加了运行时错误的可能性。

LINQ 定义了一组操作符和用于查询数据的内置语言语法。LINQ 查询是强类型的，因此在编译时进行验证。LINQ 还提供了一个框架，用于构建自己的 LINQ 提供程序，这些提供程序是将查询转换为特定于特定数据源的 API 的组件。该框架提供了对查询对象（.NET 中的任何集合）、关系数据库和 XML 的内置支持。第三方已经为许多数据源编写了 LINQ 提供程序，比如 Web 服务。

LINQ 使开发人员能够专注于要做什么，而不太关心如何做。为了更好地理解这是如何工作的，让我们看一个例子，我们有一个整数数组，我们想找到所有奇数的和。通常，您会写类似以下的内容：

```cs
int[] arr = { 1, 1, 3, 5, 8, 13, 21, 34};
int sum = 0;
for(int i = 0; i < arr.Length; ++i)
{
    if (arr[i] % 2 == 1)
    sum += arr[i];
}
```

使用 LINQ，可以将所有这些冗长的代码简化为以下一行：

```cs
int sum = arr.Where(x => x % 2 == 1).Sum();
```

在这里，我们使用了 LINQ 标准查询操作符，它们是作用于序列的扩展方法，提供了包括过滤、投影、聚合、排序等在内的查询功能。然而，许多这些查询操作符在 LINQ 查询语法中都有直接的支持，这是一种非常类似于 SQL 的查询语言。使用查询语言，解决问题的方案可以写成如下形式：

```cs
int sum = (from x in arr
           where x % 2 == 1
           select x).Sum();
```

正如你在这个例子中所看到的，不是每个查询操作符都有查询语法中的等价物。`Sum()`和所有其他聚合操作符都没有等价物。在接下来的章节中，我们将更详细地研究这两种 LINQ 的用法。

## 标准查询操作符

LINQ 标准查询操作符是一组作用于实现`IEnumerable<T>`或`IQueryable<T>`的序列的扩展方法。前者导出一个允许对序列进行迭代的枚举器。后者是一个特定于 LINQ 的接口，它继承自`IEnumerable<T>`并为我们提供了对特定数据源进行查询的功能。标准查询操作符被定义为作用于`Enumerable`或`Queryable`类的扩展方法，具体取决于它们操作的序列的类型。作为扩展方法，它们可以使用静态方法语法或实例方法语法进行调用。

大多数查询操作符可能返回多个值。这些方法返回`IEnumerable<T>`或`IQueryable<T>`，这使得它们可以链接在一起。它们返回的可枚举对象上的实际查询在迭代时被推迟到数据源上。另一方面，返回单个值的标准查询操作符（如`Sum()`或`Count()`）不推迟执行并立即执行。

以下表格包含了所有 LINQ 标准查询操作符的名称：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_10_Table_2_01.jpg)

标准查询操作符的数量很大。讨论它们中的每一个超出了本书的范围。你应该阅读官方文档或其他资源，以熟悉它们所有。

为了更加熟悉 LINQ，我们将看几个例子。在第一个例子中，我们想要计算句子中的单词数量。我们将句子以句号（`.`）、逗号（`,`）和空格作为分隔符。我们将字符串分割成部分，然后过滤掉所有非空的部分并计数它们。使用 LINQ，这就像下面这样简单：

```cs
var text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
var count = text.Split(new char[] { ' ', ',', '.' })
                .Where(w => !string.IsNullOrEmpty(w))
                .Count();
```

然而，如果我们想要根据它们的长度对所有单词进行分组并将它们打印到控制台上，问题就变得有点复杂了。我们需要以单词长度为键创建分组，以单词本身为元素，过滤掉长度为零的分组，并根据单词长度按升序排序剩下的部分：

```cs
var groups = text.Split(new char[] { ' ', ',', '.' })
                 .GroupBy(w => w.Length, w => w.ToLower())
                 .Select(g => new { Length =g.Key, Words = g })
                 .Where(g => g.Length > 0)
                 .OrderBy(g => g.Length);
foreach (var group in groups)
{
    Console.WriteLine($"Length={group.Length}");
    foreach (var word in group.Words)
    {
        Console.WriteLine($" {word}");
    }
}
```

前一个查询在调用`Count()`时执行，而这个查询的执行被推迟到我们实际迭代它时。

到目前为止，我们看到的例子并不是太复杂。然而，使用 LINQ，你可以构建更复杂的查询。为了说明这一点，让我们考虑一个处理客户订单的系统。该系统使用`Customer`、`Article`、`OrderLine`和`Order`等实体，这里以非常简化的形式显示：

```cs
class Customer
{
    public long Id { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string Email { get; set; }
}
class Article
{
    public long Id { get; set; }
    public string EAN13 { get; set; }
    public string Name { get; set; }
    public double Price { get; set; }
}
class OrderLine
{
    public long Id { get; set; }
    public long OrderId { get; set; }
    public long ArticleId { get; set; }
    public double Quantity { get; set; }
    public double Discount { get; set; }
}
class Order
{
    public long Id { get; set; }
    public DateTime Date { get; set; }
    public long CustomerId { get; set; }
    public double Discount { get; set; }
}
```

让我们也考虑一下我们有这些类型的序列，如下所示（为简单起见，每种类型只显示了一些记录，但你可以在本书附带的源代码中找到完整的例子）：

```cs
var articles = new List<Article>()
{
     new Article(){ Id = 1, EAN13 = "5901234123457", 
                    Name = "paper", Price = 100.0},
     new Article(){ Id = 2, EAN13 = "5901234123466", 
                    Name = "pen", Price = 200.0},
     /* more */
};
var customers = new List<Customer>()
{
     new Customer() { Id = 101, FirstName = "John", 
               LastName = "Doe", Email = "john.doe@email.com"},
     new Customer() { Id = 102, FirstName = "Jane", 
               LastName = "Doe", Email = "jane.doe@email.com"},
     /* more */
};
var orders = new List<Order>()
{
     new Order() { Id = 1001, Date = new DateTime(2020, 3, 12),
                   CustomerId = customers[0].Id },
     new Order() { Id = 1002, Date = new DateTime(2020, 4, 23),
                   CustomerId = customers[1].Id },
     /* more */
};
var orderlines = new List<OrderLine>()
{
    new OrderLine(){ Id = 1, OrderId=orders[0].Id, 
                     ArticleId = articles[0].Id, Quantity=2},
    new OrderLine(){ Id = 2, OrderId=orders[0].Id, 
                     ArticleId = articles[1].Id, Quantity=1},
    /* more */
};
```

我们想要找到答案的问题是，*一个特定客户自从某一天以来购买的所有文章的名称是什么？*使用命令式方法编写这个问题可能会很麻烦，但是使用 LINQ，可以表达如下：

```cs
var query = 
    orders.Join(orderlines,
                o => o.Id,
                ol => ol.OrderId,
                (o, ol) => new { Order = o, Line = ol })
          .Join(customers,
                o => o.Order.CustomerId,
                c => c.Id,
                (o, c) => new { o.Order, o.Line, Customer = c})
          .Join(articles,
                o => o.Line.ArticleId,
                a => a.Id,
                (o, a) => new { o.Order, o.Line, 
                               o.Customer, Article = a})
        .Where(o => o.Order.Date >= new DateTime(2020, 4, 1) &&
                    o.Customer.FirstName == "John")
          .OrderBy(o => o.Article.Name) 
          .Select(o => o.Article.Name);
```

在这个例子中，我们将订单与订单行和客户进行了连接，并将订单行与文章进行了连接，并且只保留了 2020 年 4 月 1 日后由名为 John 的客户下的订单。然后，我们按文章名称的字典顺序对它们进行了排序，并只选择了文章名称进行投影。

有几个`Join()`操作，语法可能看起来更难理解。让我们使用以下例子来解释一下：

```cs
orders.Join(orderlines,
            o => o.Id,
            ol => ol.OrderId,
            (o, ol) => new { Order = o, Line = ol })
```

在这里，`orders`被称为*外部序列*，`orderlines`被称为*内部序列*。`Join()`的第二个参数，即`o => o.Id`，被称为*外部序列的键选择器*。我们用它来选择订单。`Join()`的第三个参数，即`ol => ol.OrderId`，被称为*内部序列的键选择器*。我们用它来选择订单行。

基本上，这两个 lambda 表达式帮助匹配具有`OrderId`等于订单 ID 的订单行。最后一个参数`(o, ol) => new { Order = o, Line = ol }`是连接操作的投影。我们正在创建一个具有名为`Order`和`Line`的两个属性的新对象。

一些标准查询操作更容易使用，而其他一些可能更复杂，可能需要一些练习才能理解得很好。然而，对于其中许多操作，存在一个更简单的替代方案——LINQ 查询语法，我们将在下一节中探讨。

## 查询语法

LINQ 查询语法基本上是标准查询操作的语法糖（即，设计成更容易编写和理解的简化语法）。编译器将使用查询语法编写的查询转换为使用标准查询操作的查询。查询语法比标准查询操作更简单、更易读，但它们在语义上是等价的。然而，正如前面提到的，不是所有的标准查询操作在查询语法中都有等价物。

为了看到标准查询操作的方法语法和查询语法的比较，让我们使用查询语法重写上一节中的例子。

首先，让我们看一下在一段文本中计算单词数的问题。使用查询语法，查询变成了以下形式。请注意，`Count()`在查询语法中没有等价物：

```cs
var count = (from w in text.Split(new char[] { ' ', ',', '.' })
             where !string.IsNullOrEmpty(w)
             select w).Count();
```

另一方面，第二个问题可以完全使用查询语法来编写，如下所示：

```cs
var groups = from w in text.Split(new char[] { ' ', ',', '.' })
             group w.ToLower() by w.Length into g
             where g.Key > 0
             orderby g.Key
             select new { Length = g.Key, Words = g };
foreach (var group in groups)
{
    Console.Write($"Length={group.Length}: ");
    Console.WriteLine(string.Join(',', group.Words));
}
```

打印文本有点不同。单词以逗号分隔的形式显示在一行上。为了组成逗号分隔的单词文本，我们使用了`string.Join()`静态方法，它接受一个分隔符和一系列值，并将它们连接成一个字符串。这个程序的输出如下：

```cs
Length=2: do,ut,et
Length=3: sit,sed
Length=4: amet,elit
Length=5: lorem,ipsum,dolor,magna
Length=6: tempor,labore,dolore,aliqua
Length=7: eiusmod
Length=10: adipiscing,incididunt
Length=11: consectetur
```

我们将重写的最后一个问题是与客户订单相关的例子。这个查询可以非常简洁地表达，如下面的代码所示。这段代码类似于 SQL，`join`操作的写法确实更简单，更易读，更易理解：

```cs
var query = from o in orders
            join ol in orderlines on o.Id equals ol.OrderId
            join c in customers on o.CustomerId equals c.Id
            join a in articles on ol.ArticleId equals a.Id
            where o.Date >= new DateTime(2019, 4, 1) &&
                  c.FirstName == "John"
            orderby a.Name
            select a.Name;
```

从这些例子中可以看出，LINQ 帮助以比传统的命令式编程更简单的方式构建查询。不同性质的数据源可以以类似 SQL 的语言一致地进行查询。查询是强类型的，并且在编译时进行验证，这有助于解决许多潜在的错误。

现在，让我们来看一些更多的函数式编程概念：部分函数应用、柯里化、闭包、幺半群和单子。

# 更多的函数式编程概念

在本章的开头，我们看了一般的函数式编程概念，主要是高阶函数和不可变性。在本节中，我们将探讨几个更多的函数式编程概念和技术——部分函数应用、柯里化、闭包、幺半群和单子。

## 部分函数应用

部分函数应用是将具有*N 个参数*和*一个参数*的函数进行处理，并在将参数固定为函数的一个参数后返回具有*N-1 个参数*的另一个函数的过程。当然，也可能会使用多个参数进行调用，比如*M*，在这种情况下返回的函数将具有*N-M*个参数。

要理解这是如何工作的，让我们从一个具有多个参数并返回一个字符串（包含参数值）的函数开始：

```cs
string AsString(int a, double b, string c)
{
    return $"a={a}, b={b}, c={c}";
}
```

如果我们将这个函数作为`AsString(42, 43.5, "44")`调用，结果将是字符串`"a=42, b=43.5, c=44"`。然而，如果我们有一个函数（让我们称之为`Apply()`）可以将一个参数绑定到这个函数的第一个参数，那么我们可以用相同的结果来调用它：

```cs
var f1 = Apply<int, double, string, string>(AsString, 42);
var result = f1(43.5, "44");
```

实现这样一个`Apply()`函数的方法如下：

```cs
Func<T2, T3, TResult>
Apply<T1, T2, T3, TResult>(Func<T1, T2, T3, TResult> f, T1 arg)
{
    return (b, c) => f(arg, b, c);
}
```

这个高阶函数接受另一个函数和一个值作为参数，并返回另一个参数少一个的高阶函数。这个函数解析为使用`f`参数函数和`arg`参数值以及其他参数。

也可能继续将函数减少到另一个参数少一个的函数，直到我们有一个没有参数的函数，如下所示：

```cs
var f1 = Apply<int, double, string, string>(AsString, 42);
var f2 = Apply(f1, 43.5);
var f3 = Apply(f2, "44");
string result = f3();
```

然而，要实现这一点，我们需要`Apply()`函数的额外重载，以及相应数量的参数。对于这里显示的情况，我们需要以下内容（实际上，如果你有超过三个参数的函数，你需要更多的重载来考虑所有可能的参数数量）：

```cs
Func<T2, TResult> Apply<T1, T2, TResult>(Func<T1, T2, TResult> f, T1 arg)
{
    return b => f(arg, b);
}
Func<TResult> Apply<T1, TResult>(Func<T1, TResult> f, T1 arg)
{
    return () => f(arg);
}
```

在这个例子中，重要的是要注意，只有当所有参数都提供时，才会实际调用`AsString()`函数；也就是说，当我们调用`f3()`时。

你可能想知道部分函数应用何时有用。典型情况是当你多次（或多次）调用一个函数，而一些参数是相同的。在这种情况下，有几种替代方案，包括以下几种：

+   在定义函数时为函数参数提供默认值。然而，由于不同的原因，这可能是不可能的。也许默认值只在某些情况下有意义，或者你实际上并不拥有这段代码，所以无法提供默认值。

+   在多次调用函数的类中，可以编写一个带有较少参数的`helper`函数，以使用正确的默认值调用函数。

部分函数应用可能是（在许多情况下）更简单的解决方案。

## 柯里化

**柯里化**是将具有*N*个参数的函数分解为*接受一个*参数的*N*个函数的过程。这种技术得名于数学家和逻辑学家 Haskell Curry，函数式编程语言**Haskell**也是以他的名字命名的。

柯里化使得能够在只能使用一个参数的情况下使用具有多个参数的函数。数学中的分析技术就是一个例子，它只能应用于具有单个参数的函数。

考虑到上一节中的`AsString()`函数，对这个函数进行柯里化将会做如下操作：

+   返回一个函数`f1`。

+   当使用参数`a`调用时，它将返回一个函数`f2`。

+   当使用参数`b`调用时，它将返回一个函数`f3`。

+   当使用参数`c`调用时，它将调用`AsString(a, b, c)`。

将这些放入代码中，看起来如下：

```cs
var f1 = Curry<int, double, string, string>(AsString);
var f2 = f1(42);
var f3 = f2(43.5);
string result = f3("44");
```

在这里看到的通用`Curry()`函数类似于上一节中的`Apply()`函数。但是，它返回的不是具有*N-1*个参数的函数，而是具有一个参数的函数：

```cs
Func<T1, Func<T2, Func<T3, TResult>>> 
Curry<T1, T2, T3, TResult>(Func<T1, T2, T3, TResult> f)
{
    return a => b => c => f(a, b, c);
}
```

这个函数可以用于柯里化具有三个参数的函数。如果你需要对具有其他参数数量的函数进行柯里化，那么你需要适当的重载（就像在`Apply()`的情况下一样）。

您应该注意，您不一定需要将`AsString()`函数分解为三个不同的函数，就像之前的`f1`，`f2`和`f3`一样。您可以跳过中间函数，并通过适当调用函数来实现相同的结果，如下面的代码所示：

```cs
var f = Curry<int, double, string, string>(AsString);
string result = f(42)(43.5)("44");
```

函数编程中的另一个重要概念是闭包。我们将在下一节学习有关闭包的知识。

## 闭包

**闭包**被定义为在具有头等函数的语言中实现词法范围名称绑定的技术。词法或静态作用域是将变量的作用域设置为定义它的块，因此只能在该作用域内通过其名称引用它。

信息框

C#中的作用域称为**静态**或**词法**，可以在编译时查看。相反的是*动态作用域*，它只在运行时解析，但在 C#中不支持这种作用域。

正如我们在本章前面看到的，C#是一种具有头等函数的语言，因为您可以将函数分配给变量，传递它们并调用它们。然而，这种对闭包的定义可能更难理解，因此我们将使用一个示例逐步解释它。

让我们考虑以下示例：

```cs
class Program
{
    static Func<int, int> Increment()
    {
        int step = 1;
        return x => x + step;
    }
    static void Main(string[] args)
    {
        var inc = Increment();
        Console.WriteLine(inc(42));
    }
}
```

在这里，我们有一个名为`Increment()`的函数，它返回另一个函数，该函数使用一个值递增其参数。然而，该值既不作为参数传递给 lambda，也不在 lambda 中定义为局部变量。相反，它是从外部范围捕获的。因此，在 lambda 的范围内，step 变量被称为`step`变量；如果在那里找不到它，它会查找封闭范围，这种情况下是`Increment()`函数。如果那里也找不到它，它将进一步查找类范围，依此类推。

接下来发生的是，我们将从`Increment()`函数返回的值（另一个函数）分配给`inc`变量，然后使用值`42`调用它。结果是将值`43`打印到控制台。

问题是，*这是如何工作的？* `step`变量实际上是一个局部函数变量，应该在调用`Increment()`后立即超出范围。然而，在调用从`Increment()`返回的函数时，它的值是已知的。这是因为 lambda 表达式`x => x + step`被认为是*闭合*在自由变量`step`上，从而定义了一个闭包。lambda 表达式和`step`一起传递（作为闭包的一部分），以便变量通常会超出范围，但在调用闭包时仍然存在。

闭包经常被使用，而我们甚至没有意识到。考虑以下示例，我们有一个引擎列表，我们想要搜索具有最小功率和容量的引擎。您通常会使用 lambda 表达式编写如下内容：

```cs
var list = new List<Engine>();
var minp = 75.0;
var minc = 1600;
var engine = list.Find(e => e.Power >= minp && 
                       e.Capacity >= minc);
```

但这实际上创建了一个闭包，因为 lambda 闭合了`minp`和`minc`自由变量。如果语言不支持闭包，编写相同功能的代码将会很麻烦。你基本上需要编写一个捕获这些变量值的类，并且有一个方法，该方法接受一个`Engine`对象并将其属性与这些值进行比较。在这种情况下，代码可能如下所示：

```cs
sealed class EngineFinder
{
    public EngineFinder(double minPower, int minCapacity)
    {
        this.minPower = minPower;
        this.minCapacity = minCapacity;
    }
    public double minPower;
    public int minCapacity;
    public bool IsMatch(Engine engine)
    {
        return engine.Power >= minPower && 
            engine.Capacity >= minCapacity;
    }
}
var engine = list.Find(new EngineFinder(minp, minc).IsMatch);
```

这与编译器在遇到闭包时所做的事情非常相似，但这是你不必担心的细节。

您还应该注意，lambda 中捕获的自由变量的值可以改变。我们通过以下示例来说明这一点，其中`GetNextId()`函数定义了一个闭包，该闭包在每次调用时递增捕获的自由变量`id`的值：

```cs
Func<int> GetNextId()
{
    int id = 1;
    return () => id++;
}
var nextId = GetNextId();
Console.WriteLine(nextId()); // prints 1
Console.WriteLine(nextId()); // prints 2
Console.WriteLine(nextId()); // prints 3
```

我们将在下一节学习有关单子的知识。

## 单子

**单子**是一种具有单一可结合二元操作和单位元的代数结构。任何具有这两个元素的 C#类型都是单子。单子对于定义概念和重用代码非常有用。它们帮助我们从简单的组件构建复杂的行为，而无需在我们的代码中引入新的概念。让我们看看如何在 C#中创建和使用单子。

我们可以在 C#中定义一个通用接口来表示单子，如下所示：

```cs
interface IMonoid<T>
{
    T Combine(T a, T b);
    T Identity { get; }
}
```

单子确保结合性和左右单位性，以便对于任何值`a`、`b`和`c`，我们有以下内容：

+   `Combine((Combine(a, b), c) == Combine(a, Combine(b, c))`

+   `Combine(Identify, a) == a`

+   `Combine(a, Identity) == a`

连接字符串或列表是一个可结合的二元操作的例子。提供该函数的类型，以及一个单位元（在这些情况下是一个空字符串或一个空列表），就是一个单子。因此，我们实际上可以在 C#中实现这些功能，如下所示：

```cs
struct ConcatList<T> : IMonoid<List<T>>
{
    public List<T> Identity => new List<T> { };
    public List<T> Combine(List<T> a, List<T> b)
    {
        var l = new List<T>(a);
        l.AddRange(b);
        return l;
    }
}
struct ConcatString : IMonoid<string>
{
    public string Identity => string.Empty;
    public string Combine(string a, string b)
    {
        return a + b;
    }
}
```

`ConcatList`和`ConcatString`都是单子的例子。后者可以如下使用：

```cs
var m = new ConcatString();
var text = m.Combine("Learning", m.Combine(" ", "C# 8"));
Console.WriteLine(text);
```

这将在控制台上打印`Learning C# 8`。然而，这段代码有点繁琐。我们可以通过创建一个带有静态方法`Concat()`的辅助类来简化它，该方法接受一个单子和一系列元素，并使用单子的二元操作和其初始值的单位元将它们组合在一起：

```cs
static class Monoid
{
    public static T Concat<MT, T>(IEnumerable<T> seq)
        where MT : struct, IMonoid<T>
    {
       var result = default(MT).Identity;
       foreach (var e in seq)
           result = default(MT).Combine(result, e);
       return result;
    }
}
```

有了这个辅助类，我们可以编写以下简化的代码：

```cs
var text = Monoid.Concat<ConcatString, string>(
              new[] { "Learning", " ", "C# 8"});
Console.WriteLine(text);
var list = Monoid.Concat<ConcatList<int>, List<int>>(
    new[] { new List<int>{ 1,2,3},
    new List<int> { 4, 5 },
    new List<int> { } });
Console.WriteLine(string.Join(",", list));
```

在这个例子的第一部分中，我们将一系列字符串连接成一个单一的字符串并打印到控制台。在第二部分中，我们将一系列整数的列表连接成一个单一的整数列表，然后也打印到控制台。

在接下来的部分，我们将看看单子。

## 单子

这通常是一个更难解释，也许更难理解的概念，尽管已经有很多文献写过它。在这本书中，我们将尝试用简单的术语来解释它，但我们建议您阅读其他资源。

简而言之，单子是一个封装了一些功能的容器，它包裹在它的值之上。我们经常在 C#中使用单子而没有意识到。`Nullable<T>`是一个定义了特殊功能的单子，即*可空性*，这意味着一个值可能存在，也可能不存在。带有`await`的`Task<T>`是一个定义了特殊功能的单子，即*异步性*，这意味着一个值可以在实际计算之前被使用。带有 LINQ 查询`SelectMany()`操作符的`IEnumerable<T>`也是一个单子。

单子有两个操作：

+   一个将值`v`转换为包装它的容器（`v -> C(v)`）的函数。在函数式编程中，这个函数被称为**return**。

+   一个将两个容器扁平化为一个单一容器的函数（`C(C(v)) -> C(v)`）。在函数式编程中，这被称为**bind**。

让我们看下面的例子：

```cs
var numbers = new int[][]{ new[]{ 1, 2, 3},
                           new[]{ 4, 5 },
                           new[]{ 6, 7} };
IEnumerable<int> odds = numbers.SelectMany(
                           n => n.Where(x => x % 2 == 1));
```

在这里，`numbers`是一个整数数组的数组。`SelectMany()`用于选择奇数的子序列。然而，这将结果扁平化为`IEnumerable<int>`而不是`IEnumerable<IEnumerable<int>>`。正如我们之前提到的，带有`SelectMany()`的`IEnumerable<T>`是一个单子。

但是你如何在 C#中实现一个单子呢？最简单的形式如下：

```cs
class Monad<T>
{
    public Monad(T value) => Value = value;
    public T Value { get; }
    public Monad<U> Bind<U>(Func<T, Monad<U>> f) => f(Value);
}
```

实际上被称为`x => x`，你将得到初始单子：

```cs
var m = new Monad<int>(42);
var mm = new Monad<Monad<int>>(m);
var r = mm.Bind(x => x); // r equals m
```

这个单子如何使用的另一个例子在下面的代码中展示：

```cs
var m = new Monad<int>(21);
var r = m.Bind(x => new Monad<int>(x * 2))
         .Bind(x => new Monad<string>($"x={x}"));
Console.WriteLine(r.Value); // prints x=42
```

在这个例子中，`m`是一个包装整数值`21`的单子。我们使用一个返回新单子的函数进行绑定，该单子的值是初始值的两倍。我们可以再次使用一个将整数转换为字符串的函数对这个单子进行绑定。

从这个例子中，你可以看到这些绑定操作可以链接在一起。这就是流畅接口提供的功能——通过链接方法来编写类似书面散文的代码。这可以通过以下示例进一步说明——假设一个企业有客户，客户下订单，订单可以包含一个或多个商品，你需要找出一个特定企业所有客户购买的所有不同商品。

为简单起见，让我们考虑以下类：

```cs
class Business
{
    public IEnumerable<Customer> GetCustomers() { 
      return /* … */; }
}
class Customer
{
    public IEnumerable<Order> GetOrders() { return /* … */; }
}
class Order
{
    public IEnumerable<Article> GetArticles() { return /* … */; }
}
class Article { }
```

在典型的命令式风格中，你可以按照以下方式实现解决方案：

```cs
IEnumerable<Article> GetArticlesSoldBy(Business business)
{
    var articles = new HashSet<Article>();
    foreach (var customer in business.GetCustomers())
    {
        foreach (var order in customer.GetOrders())
        {
            foreach (var article in order.GetArticles())
            {
                articles.Add(article);
            }
        }
    }
    return articles;
}
```

然而，通过使用 LINQ 和`IEnumerable<T>`和“SelectMany（）”单子，这可以更简化。函数式编程风格的实现可能如下所示：

```cs
IEnumerable<Article> GetArticlesSoldBy(Business business)
{
    return business.GetCustomers()
                   .SelectMany(c => c.GetOrders())
                   .SelectMany(o => o.GetArticles())
                   .Distinct()
                   .ToList();
}
```

这使用了流畅接口模式，结果是更简洁的代码，也更容易理解。

# 总结

这一章是对 C#命令式编程特性的一次离开，因为我们探讨了内置到语言中的函数式编程概念和技术。我们研究了高阶函数、lambda 表达式、部分函数应用、柯里化、闭包、幺半群和单子。我们还介绍了 LINQ 及其两种风格：方法语法和查询语法。这些大多数主题都比本书的建议范围复杂和更高级。因此，我们建议您使用其他资源来掌握它们。

在下一章中，我们将研究.NET 中可用的反射服务以及 C#的动态编程能力。

# 测试你学到了什么

1.  函数式编程的主要特征是什么？它提供了什么优势？

1.  什么是高阶函数？

1.  是什么让函数在 C#语言中成为一等公民？

1.  什么是 lambda 表达式？写 lambda 表达式的语法是什么？

1.  lambda 表达式中变量作用域适用的规则是什么？

1.  什么是 LINQ？标准查询操作符是什么？查询语法是什么？

1.  “Select（）”和“SelectMany（）”之间有什么区别？

1.  什么是部分函数应用，它与柯里化有什么不同？

1.  什么是幺半群？

1.  什么是单子？


# 第十一章：反射和动态编程

在上一章中，我们讨论了函数式编程、lambda 表达式以及它们所支持的功能，比如**语言集成查询（LINQ）**。本章侧重于反射服务和动态编程。您将学习什么是反射，以及如何在运行时获取有关类型的信息，以及代码和资源如何存储在程序集中，以及如何在运行时动态加载它们，无论是用于反射还是代码执行。

这对于构建支持插件或附加组件形式的扩展的应用程序至关重要。我们将看到属性是什么，以及它们在反射中扮演的角色。本章中我们将讨论的另一个重要主题是动态编程和**动态语言运行时**，它使动态语言能够在**公共语言运行时（CLR）**上运行，并为静态类型语言添加动态特性。

本章我们将讨论以下主题：

+   理解反射

+   动态加载程序集

+   理解后期绑定

+   使用`dynamic`类型

+   属性

在本章结束时，您将对反射、属性及其在反射中的使用，以及程序集加载和代码执行有很好的理解。另一方面，您还将学习关于`dynamic`类型，并能够与动态语言进行交互。

# 理解反射

.NET 中的部署单元是程序集。程序集是一个文件（可以是可执行文件或动态链接库），其中包含`ildasm.exe`（`ilspy.exe`（一个开源项目）；或其他允许您查看程序集内容的工具。以下是`ildasm.exe`的屏幕截图，显示了本书源代码中提供的`chapter_11_01.dll`程序集：

![图 11.1 - chapter 11 程序集的反汇编源代码。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_11.1_B12346.jpg)

图 11.1 - chapter_11_01 程序集的反汇编源代码

**反射**是在运行时发现类型并对其进行更改的过程。这意味着我们可以在运行时检索有关类型、其成员和属性的信息。这带来了一些重要的好处：

+   在运行时动态加载程序集（后期绑定）、检查类型和执行代码的能力使得构建可扩展应用程序变得容易。应用程序可以通过接口和基类定义功能，然后在单独的模块（插件或附加组件）中实现或扩展这些功能，并根据各种条件在运行时加载和执行它们。

+   属性，我们稍后将在本章中看到，使得以声明方式提供有关类型、方法、属性和其他内容的元信息成为可能。通过能够在运行时读取这些属性，系统可以改变它们的行为。例如，工具可以警告某个方法的使用方式与预期不同（比如过时方法的情况），或以特定方式执行它们。测试框架（我们将在最后一章中看到一些）广泛使用了这种功能。

+   它提供了执行私有或其他访问级别的类型和成员的能力，否则这些类型和成员将无法访问。这对于测试框架来说非常方便。

+   它允许在运行时修改现有类型或创建全新类型，并使用它们执行代码。

反射也有一些缺点：

+   它会产生一个可能降低性能的开销。在运行时加载、发现和执行代码会更慢，可能会阻止优化。

+   它暴露了类型的内部，因为它允许对所有类型和成员进行内省，而不考虑它们的访问级别。

.NET 反射服务允许您使用`System.Reflection`命名空间中的 API 发现与前面提到的工具中看到的相同的信息。这个过程的关键是名为`System.Type`的类型，其中包含公开所有类型元数据的成员。这是通过`System.Reflection`命名空间中的其他类型的帮助完成的，其中一些列在以下表中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_11_Table_1_01.jpg)

`System.Type`类的一些最重要的成员列在以下表中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_11_Table_2_01.jpg)

有几种方法可以在运行时检索`System.Type`的实例以访问类型元数据；以下是其中的一些：

+   使用`System.Object`类型的`GetType()`方法。由于这是所有值类型和引用类型的基类，您可以使用任何类型的实例调用：

```cs
var engine = new Engine();
var type = engine.GetType();
```

+   使用`System.Type`的`GetType()`静态方法。有许多重载，允许您指定名称和各种参数：

```cs
var type = Type.GetType("Engine");
```

+   使用 C#的`typeof`运算符：

```cs
var type = typeof(Engine);
```

让我们看看如何通过查看一个实际的例子来使用反射。我们将考虑以下`Engine`类型，它具有几个属性、一个构造函数和一对改变引擎状态（启动或停止）的方法：

```cs
public enum EngineStatus { Stopped, Started }
public class Engine
{
    public string Name { get; }
    public int Capacity { get; }
    public double Power { get; }
    public EngineStatus Status { get; private set; }
    public Engine(string name, int capacity, double power)
    {
        Name = name;
        Capacity = capacity;
        Power = power;
        Status = EngineStatus.Stopped;
    }
    public void Start()
    {
        Status = EngineStatus.Started;
    }
    public void Stop()
    {
        Status = EngineStatus.Stopped;
    }
}
```

我们将构建一个小程序，它将在运行时读取有关`Engine`类型的元数据，并将以下内容打印到控制台：

+   *类型*的名称

+   所有*属性*的名称以及它们的类型的名称

+   所有*声明的方法*的名称（不包括继承的方法）

+   它们的*返回类型*的名称

+   每个参数的名称和类型

以下是用于在运行时读取和打印有关`Engine`类型的元数据的程序：

```cs
static void Main(string[] args)
{
    var type = typeof(Engine);
    Console.WriteLine(type.Name);
    var properties = type.GetProperties();
    foreach(var p in properties)
    {
        Console.WriteLine($"{p.Name} ({p.PropertyType.Name})");
    }
    var methods = type.GetMethods(BindingFlags.Public |
                                  BindingFlags.Instance |
                                  BindingFlags.DeclaredOnly);
    foreach(var m in methods)
    {
        var parameters = string.Join(
            ',',
            m.GetParameters()
             .Select(p => $"{p.ParameterType.Name} {p.Name}"));
        Console.WriteLine(
          $"{m.ReturnType.Name} {m.Name} ({parameters})");
   }
}
```

在这个例子中，我们使用`typeof`运算符检索`System.Type`类型的实例，以发现`Engine`类型的元数据。为了检索属性，我们使用了没有参数的`GetProperties()`重载，它返回当前类型的所有公共属性。然而，对于方法，我们使用了`GetMethod()`方法的重载，它以一个由一个或多个`BindingFlags`值组成的位掩码作为参数。

`BindingFlags`类型是一个枚举，其中的标志控制绑定和在反射期间执行类型和方法搜索的方式。在我们的例子中，我们使用`Public`、`Instance`和`DeclareOnly`来指定仅在此类型中声明的公共非静态方法，并排除继承的方法。这个程序的输出如下：

```cs
Engine
Name (String)
Capacity (Int32)
Power (Double)
Status (EngineStatus)
String get_Name ()
Int32 get_Capacity ()
Double get_Power ()
EngineStatus get_Status ()
Void Start ()
Void Stop ()
```

`Engine`类型位于执行反射代码的程序集中。但是，您也可以反射来自其他程序集的类型，无论它们是从执行程序集引用还是在运行时加载的，这是我们将在下一节中看到的。

# 动态加载程序集

反射服务允许您在运行时加载程序集。这是使用`System.Reflection.Assembly`类型完成的，它提供了各种加载程序集的方法。

程序集可以是*公共*（也称为*共享*）或*私有*。共享程序集旨在供多个应用程序使用，并且通常位于**全局程序集缓存（GAC）**下，这是程序集的系统存储库。私有程序集旨在供单个应用程序使用，并存储在应用程序目录或其子目录中。共享程序集必须具有强名称并强制执行版本约束；对于私有程序集，这些要求是不必要的。

程序集可以在三个上下文中之一加载，也可以不加载：

+   *加载上下文*，其中包含从 GAC、应用程序目录（应用程序域的`ApplicationBase`）或其私有程序集的子目录（应用程序域的`PrivateBinPath`）加载的程序集

+   *加载上下文*，其中包含从除了程序集加载程序探测的路径加载的程序集

+   *仅反射上下文*，其中包含仅用于反射目的加载的程序集，不能用于执行代码

+   *无上下文*，在某些特殊情况下使用，例如从字节数组加载的程序集

用于加载程序集的最重要的方法列在下表中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_11_Table_3_01.jpg)

我们将看几个动态加载程序集的例子。

在第一个例子中，我们使用`Assembly.Load()`从应用程序目录加载名为`EngineLib`的程序集：

```cs
var assembly = Assembly.Load("EngineLib");
```

在这里，我们只指定了程序集的名称，但我们也可以指定显示名称，该名称不仅由名称组成，还包括版本、文化和用于签名程序集的公钥标记。对于没有强名称的程序集，这是`null`。在下面的行中，我们使用显示名称，与先前使用的行等效：

```cs
var assembly = Assembly.Load(@"EngineLib, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null");
```

可以使用`AssemblyName`类以类型安全的方式创建显示名称。该类具有各种属性和方法，允许您构建显示名称。可以按照以下方式完成：

```cs
var assemblyName = new AssemblyName()
{
    Name = "EngineLib",
    Version = new Version(1,0,0,0),
    CultureInfo = null,
};
var assembly = Assembly.Load(assemblyName);
```

公共（或共享）程序集必须具有强名称。这有助于唯一标识程序集，从而避免可能的冲突。签名是使用公共-私钥完成的；私钥用于签名，公钥与程序集一起分发并用于验证签名。

可以使用与 Visual Studio 一起分发的`sn.exe`工具生成这样的加密对；此工具也可用于验证签名。对于强名称程序集，必须指定`PublicKeyToken`，否则加载将失败。以下示例显示了如何从 GAC 加载`WindowsBase.dll`：

```cs
var assembly = Assembly.Load(@"WindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35");
```

使用程序集名称加载程序集的替代方法是使用其实际路径。但是，在这种情况下，您必须使用`LoadFrom()`的一个重载之一。这对于必须加载既不在 GAC 中也不在应用程序文件夹下的程序集的情况非常有用。一个例子可以是一个可扩展的系统，可以加载可能安装在某个自定义目录中的插件：

```cs
var assembly = Assembly.LoadFrom(@"c:\learningc#8\chapter_11_02\bin\Debug\netcoreapp2.1\EngineLib.dll");
```

`Assembly`类具有提供有关程序集本身信息的成员，以及提供有关其包含的类型信息的成员。以下是一些最重要的成员：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_11_Table_4_01.jpg)

在下面的例子中，使用先前显示的方法之一加载程序集后，我们列出程序集名称和程序集清单中的文件，以及引用程序集的名称。之后，我们搜索`EngineLib.Engine`类型并打印其所有属性的名称和类型：

```cs
if (assembly != null)
{
    Console.WriteLine(
$@"Name: {assembly.GetName().FullName}
Files: {string.Join(',', 
                    assembly.GetFiles().Select(
                        s=>Path.GetFileName(s.Name)))}
Refs:  {string.Join(',', 
                    assembly.GetReferencedAssemblies().Select(
                        n=>n.Name))}");
    var type = assembly.GetType("EngineLib.Engine");
    if (type != null)
    {
        var properties = type.GetProperties();
        foreach (var p in properties)
        {
            Console.WriteLine(
              $"{p.Name} ({p.PropertyType.Name})");
        }
    }
}
```

除了查询有关程序集及其内容的信息之外，还可以在运行时从中执行代码。这是我们将在下一节中讨论的内容。

# 理解后期绑定

在编译时引用程序集时，编译器可以完全访问该程序集中可用的类型。这称为**早期绑定**。但是，如果程序集仅在运行时加载，编译器将无法访问该程序集的内容。这称为**后期绑定**，是构建可扩展应用程序的关键。使用后期绑定，您不仅可以加载和查询程序集，还可以执行代码。我们将在下面的例子中看到。

假设先前显示的`Engine`类在名为`EngineLib`的程序集中可用。可以使用`Assembly.Load()`或`Assembly.LoadFrom()`加载该程序集。加载后，我们可以使用`Assembly.GetType()`和`Type`的类方法获取有关`Engine`类型的信息。但是，使用`Assembly.CreateInstance()`，我们可以实例化该类的对象：

```cs
var assembly = Assembly.LoadFrom("EngineLib.dll");
if (assembly != null)
{
    var type = assembly.GetType("EngineLib.Engine");
    object engine = assembly.CreateInstance(
        "EngineLib.Engine",
        true,
        BindingFlags.CreateInstance,
        null,
        new object[] { "M270 Turbo", 1600, 75.0 },
        null,
        null);
    var pi = type.GetProperty("Status");
    if (pi != null)
        Console.WriteLine(pi.GetValue(engine));
    var mi = type.GetMethod("Start");
    if (mi != null)
        mi.Invoke(engine, null);
    if (pi != null)
        Console.WriteLine(pi.GetValue(engine));
}
```

`Assembly.CreateInstance()`方法有许多参数，但其中三个最重要：

+   第一个参数`string typeName`，表示程序集的名称。

+   第三个参数，`BindingFlags bindingAttr`，表示绑定标志。

+   第五个参数，`object[]` `args`，表示用于调用构造函数的参数数组；对于默认构造函数，这个对象可以是`null`。

在创建类型的实例之后，我们可以使用`PropertyInfo`、`MethodInfo`等的实例来调用其成员。例如，在前面的示例中，我们首先检索了名为`Status`的属性的`PropertyInfo`实例，然后通过调用`GetValue()`并传递引擎对象来获取属性的值。

同样地，我们使用`GetMethod()`来检索一个名为`Start()`的方法的`MethodInfo`实例，然后通过调用`Invoke()`来调用它。这个方法接受一个对象的引用和一个表示参数的对象数组；由于`Start()`方法没有参数，在这里使用了`null`。

`Assembly.CreateInstance()`方法有很多参数，使用起来可能很麻烦。作为替代，`System.Activator`类提供了在运行时创建类型实例的更简单的方法。它有一个重载的`CreateInstance()`方法。实际上，`Assembly.CreateInstance()`在内部实际上就是使用了它。在最简单的形式中，它只需要`Type`和一个表示构造函数参数的对象数组，并实例化该类型的对象。示例如下：

```cs
object engine = Activator.CreateInstance(
    type,
    new object[] { "M270 Turbo", 1600, 75.0 });
```

`Activator.CreateInstance()`不仅更简单易用，而且在某些情况下可以提供一些好处。例如，它可以在其他应用程序域或另一台服务器上使用远程调用来创建对象。另一方面，`Assembly.CreateIntance()`如果尚未加载程序集，则不会尝试加载程序集，而`System.Activator`会将程序集加载到当前应用程序域中。

使用晚期绑定和以前展示的方式调用代码并不一定实用。在实践中，当构建一个可扩展的系统时，您可能会有一个或多个包含接口和公共类型的程序集，这些插件（或插件，取决于您希望如何称呼它们）依赖于这些基本程序集。您将对这些基本程序集进行早期绑定，然后使用插件进行晚期绑定。

为了更好地理解这一点，我们将通过以下示例进行演示。`EngineLibBase`是一个定义了名为`IEngine`和`EngineStatus`枚举的接口的程序集：

```cs
namespace EngineLibBase
{
    public enum EngineStatus { Stopped, Started }
    public interface IEngine
    {
        EngineStatus Status { get; }
        void Start();
        void Stop();
    }
}
```

这个程序集直接被`EngineLib`程序集引用，它提供了实现`IEngine`接口的`Engine`类。示例如下：

```cs
using EngineLibBase;
namespace EngineLib
{ 
    public class Engine : IEngine
    {
        public string Name { get; }
        public int Capacity { get; }
        public double Power { get; }
        public EngineStatus Status { get; private set; }
        public Engine(string name, int capacity, double power)
        {
            Name = name;
            Capacity = capacity;
            Power = power;
            Status = EngineStatus.Stopped;
        }
        public void Start()
        {
            Status = EngineStatus.Started;
        }
        public void Stop()
        {
            Status = EngineStatus.Stopped;
        }
    }
}
```

在我们的应用程序中，我们再次引用了`EngineLibBase`程序集，以便我们可以使用`IEngine`接口。在运行时加载`EngineLib`程序集后，我们实例化了`Engine`类的对象，并将其转换为`IEngine`接口，这样即使在编译时实际实例未知的情况下，也可以访问接口的成员。代码如下所示：

```cs
var assembly = Assembly.LoadFrom("EngineLib.dll");
if (assembly != null)
{
    var type = assembly.GetType("EngineLib.Engine");
    var engine = (IEngine)Activator.CreateInstance(
        type,
        new object[] { "M270 Turbo", 1600, 75.0 });
    Console.WriteLine(engine.Status);
    engine.Start();
    Console.WriteLine(engine.Status);
}
```

正如我们将在本章后面看到的那样，这并不是使用晚期绑定和在运行时动态执行代码的唯一方法。另一种可能性是使用 DLR 和`dynamic`类型。我们将在下一节中看到这一点。

# 使用动态类型

在本书中，我们已经谈到了**CLR**。.NET Framework，然而，还包含了另一个组件，称为**动态语言运行时（DLR）**。这是另一个运行时环境，它在 CLR 之上添加了一组服务，使动态语言能够在 CLR 上运行，并为静态类型语言添加动态特性。C#和 Visual Basic 是静态类型语言。相比之下，诸如 JavaScript、Python、Ruby、PHP、Smalltalk、Lua 等语言是动态语言。这些语言的关键特征是它们在运行时识别对象的类型，而不是在编译时像静态类型语言那样。

DLR 为 C#（和 Visual Basic）提供了动态特性，使它们能够以简单的方式与动态语言进行互操作。如前所述，DLR 为 CLR 添加了一组服务。这些服务如下：

+   表达式树用于表示语言语义。这些是与 LINQ 一起使用的相同表达式树，但扩展到包括控制流、赋值和其他内容。

+   调用站点缓存是一个缓存有关操作和对象（如对象的类型）的信息的服务，这样当再次执行相同的操作时，它可以被快速分派。

+   `IDynamicMetaObjectProvider`、`DynamicMetaObject`、`DynamicObject`和`ExpandoObject`。

DLR 为 C# 4 引入的`dynamic`类型提供了基础设施。这是一个静态类型，这意味着在编译时为该类型的变量分配了`dynamic`类型。但是，它们绕过了静态类型检查。这意味着对象的实际类型只在运行时知道，编译器无法知道并且无法强制执行对该类型对象执行的任何检查。您实际上可以调用任何带有任何参数的方法，编译器不会检查和抱怨；但是，如果操作无效，运行时将抛出异常。

以下代码显示了`dynamic`类型的几个变量的示例。请注意，`s`是一个字符串，`l`是`List<int>`。调用`l.Add()`是有效的操作，因为`List<T>`包含这样的方法。但是，调用`s.Add()`是无效的，因为`string`类型没有这样的方法。因此，对于此调用，在运行时会抛出`RuntimeBinderException`类型的异常：

```cs
dynamic i = 42;
dynamic s = "42";
dynamic d = 42.0;
dynamic l = new List<int> { 42 };
l.Add(43); // OK
try
{
   s.Add(44); /* RuntimeBinderException:
            'string' does not contain a definition for 'Add' */
}
catch (Exception ex)
{
    Console.WriteLine(ex.Message);
}
```

`dynamic`类型使得在编译时不知道对象类型的情况下轻松消耗对象变得容易。考虑前一段中的第一个例子，在那里我们使用反射加载了一个程序集，实例化了一个`Engine`类型的对象并调用了它的方法和属性。可以用`dynamic`类型以更简单的方式重写该示例，如下所示：

```cs
var assembly = Assembly.LoadFrom("EngineLib.dll");
if (assembly != null)
{
    var type = assembly.GetType("EngineLib.Engine");
    dynamic engine = Activator.CreateInstance(
        type,
        new object[] { "M270 Turbo", 1600, 75.0 });
    Console.WriteLine(engine.Status);
    engine.Start();
    Console.WriteLine(engine.Status);
}
```

`dynamic`类型的对象在许多情况下的行为就像它具有`object`类型一样（除了没有编译时检查）。但是，对象值的实际来源是无关紧要的。它可以是.NET 对象、COM 对象、HTML DOM 对象、通过反射创建的对象，例如前面的示例等。

动态操作的结果类型也是`dynamic`，除了从`dynamic`到另一种类型的转换和包括`dynamic`类型参数的构造函数调用。从静态类型到`dynamic`的隐式转换以及相反的转换都会执行。代码块中显示了这一点：

```cs
dynamic d = "42";
string s = d;
```

对于静态类型，编译器执行重载解析以找出对函数调用的最佳匹配。因为在编译时没有关于`dynamic`类型的信息，所以对于至少有一个参数是`dynamic`类型的方法，同样的操作在运行时执行。

`dynamic`类型通常用于简化在互操作程序集不可用时消耗 COM 对象。以下是一个创建带有一些虚拟数据的 Excel 文档的示例：

```cs
dynamic excel = Activator.CreateInstance(
    Type.GetTypeFromProgID("Excel.Application.16")); 
if (excel != null)
{
    excel.Visible = true;

    dynamic workBook = excel.Workbooks.Add();
    dynamic workSheet = excel.ActiveWorkbook.ActiveSheet;
    workSheet.Cells[1, 1] = "ID";
    workSheet.Cells[1, 2] = "Name";
    workSheet.Cells[2, 1] = "1";
    workSheet.Cells[2, 2] = "One";
    workSheet.Cells[3, 1] = "2";
    workSheet.Cells[3, 2] = "Two";
    workBook.SaveAs("d:\\demo.xls", 
        Excel.XlFileFormat.xlWorkbookNormal, 
        AccessMode : Excel.XlSaveAsAccessMode.xlExclusive);
    workBook.Close(true);
    excel.Quit();
}
```

这段代码的作用如下：

+   它检索由程序标识符`Excel.Application.16`标识的 COM 对象的`System.Type`，并创建其实例。

+   它将 Excel 应用程序的`Visible`属性设置为`true`，这样您就可以看到窗口。

+   它创建一个工作簿并向其活动工作表添加一些数据。

+   它将文档保存在名为`demo.xls`的文件中。

+   它关闭工作簿并退出 Excel 应用程序。

在本章的最后一节中，我们将看看如何在反射服务中使用属性。

# 属性

属性提供有关程序集、类型和成员的元信息。编译器、CLR 或使用反射服务读取它们的工具会消耗这些元信息。属性实际上是从`System.Attribute`抽象类派生的类型。.NET 框架提供了大量的属性，但用户也可以定义自己的属性。

属性在方括号中指定，例如`[SerializableAttribute]`。属性的命名约定是类型名称总是以`Attribute`一词结尾。C#语言提供了一种语法快捷方式，允许在不带后缀`Attribute`的情况下指定属性的名称，例如`[Serializable]`。但是，只有在类型名称根据此约定正确后缀时才可能。

我们将在下一节首先介绍一些广泛使用的系统属性。

## 系统属性

.NET Framework 在不同的程序集和命名空间中提供了数百个属性。枚举它们不仅几乎不可能，而且也没有多大意义。然而，以下表格列出了一些经常使用的属性；其中一些我们在本书中已经见过：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_11_Table_5_01.jpg)

另一方面，通常需要或有用的是创建自己的属性类。在下一节中，我们将看看用户定义的属性。

## 用户定义的属性

您可以创建自己的属性来标记程序元素。您需要从`System.Attribute`派生，并遵循将类型后缀命名为`Attribute`的命名约定。以下是一个名为`Description`的属性，其中包含一个名为`Text`的属性：

```cs
class DescriptionAttribute : Attribute
{
    public string Text { get; private set; }
    public DescriptionAttribute(string description)
    {
        Text = description;
    }
}
```

此属性可用于装饰任何程序元素。在下面的示例中，我们可以看到这个属性用在了一个类、属性和方法参数上：

```cs
[Description("Main component of the car")]
class Engine
{
    public string Name { get; }
    [Description("cm³")]
    public int Capacity { get; }
    [Description("kW")]
    public double Power { get; }
    public Engine([Description("The name")] string name, 
                  [Description("The capacity")] int capacity, 
                  [Description("The power")] double power)
    {
        Name = name;
        Capacity = capacity;
        Power = power;
    }
}
```

属性可以有*位置*和*命名*参数：

+   位置参数由公共实例构造函数的参数定义。每个这样的构造函数的参数定义了一组命名参数。

+   另一方面，每个非静态公共字段和可读写属性定义了一个命名参数。

以下示例显示了早期介绍的`Description`属性，修改后可以使用一个名为`Required`的公共属性：

```cs
class DescriptionAttribute : Attribute
{
    public string Text { get; private set; }
    public bool Required { get; set; }
    public DescriptionAttribute(string description)
    {
        Text = description;
    }
}
```

此属性可以在程序元素上的属性声明中用作命名参数。如下例所示：

```cs
[Description("Main component of the car", Required = true)]
class Engine
{
}
```

让我们在下一节中学习如何使用属性。

## 如何使用属性？

程序元素可以标记多个属性。有两种等效的方法可以实现这一点：

+   第一种方法（因为它最具描述性和清晰，所以被广泛使用）是在一对方括号内分别声明每个属性。以下示例显示了如何完成此操作：

```cs
[Serializable]
[Description("Main component of the car")]
[ComVisible(false)]
class Engine
{
}
```

+   另一种方法是在同一对方括号内声明多个属性，用逗号分隔。以下代码等同于之前的代码：

```cs
[Serializable, 
 Description("Main component of the car"), 
 ComVisible(false)]
class Engine
{
}
```

让我们在下一节中看看如何指定属性的目标。

## 属性目标

默认情况下，属性应用于它前面的任何程序元素。但是，可以指定目标，比如类型、方法等。这是通过使用另一个名为`AttributeUsage`的属性标记属性类型来完成的。除了指定目标外，此属性还允许指定新定义的属性是否可以多次应用以及是否可以继承。

以下修改后的`DescriptionAttribute`版本指示它只能用于类、结构、方法、属性和字段。此外，它指定了该属性被派生类继承，并且可以在同一元素上多次使用：

```cs
[AttributeUsage(AttributeTargets.Class|
                AttributeTargets.Struct|
                AttributeTargets.Method|
                AttributeTargets.Property|
                AttributeTargets.Field,
                AllowMultiple = true,
                Inherited = true)]
class DescriptionAttribute : Attribute
{
    public string Text { get; private set; }
    public bool Required { get; set; }
    public DescriptionAttribute(string description)
    {
        Text = description;
    }
}
```

由于这些变化，这个属性不能再用于方法参数，就像之前的例子中所示的那样。那将导致编译器错误。

到目前为止，我们使用的属性针对程序元素，如类型和方法。但是也可以使用程序集级属性。我们将在下一节中看到这些。

## 程序集属性

有一些属性可以针对程序集并指定有关程序集的信息。这些信息可以是程序集的标识（即名称、版本和文化）、清单信息、强名称或其他信息。这些属性使用语法`[assembly: attribute]`指定。这些属性通常可以在为每个.NET Framework 项目生成的`AssemblyInfo.cs`文件中找到。以下是这些属性的一个示例：

```cs
[assembly: AssemblyTitle("project_name")]
[assembly: AssemblyDescription("")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("")]
[assembly: AssemblyProduct("project_name")]
[assembly: AssemblyCopyright("Copyright © 2019")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
```

属性用于反射服务。既然我们已经看到了如何创建和使用属性，让我们看看如何在反射中使用它们。

## 反射中的属性

属性本身没有太大的价值，直到有人反映它们并根据属性的含义和值执行特定的操作。`System.Type`类型以及`System.Reflection`命名空间中的其他类型都有一个名为`GetCustomAttributes()`的重载方法，用于检索特定程序元素标记的属性。其中一个重载采用属性的类型，因此它只返回该类型的实例；另一个不是，返回所有属性。

以下示例从`Engine`类型中首先检索所有`Description`属性的实例，然后从类型的所有属性中检索并在控制台中显示描述文本：

```cs
var e = new Engine("M270 Turbo", 1600, 75.0);
var type = e.GetType();
var attributes = type.GetCustomAttributes(typeof(DescriptionAttribute), 
                                          true);
if (attributes != null)
{
    foreach (DescriptionAttribute attr in attributes)
    {
        Console.WriteLine(attr.Text);
    }
}
var properties = type.GetProperties();
foreach (var property in properties)
{
    var pattributes = 
      property.GetCustomAttributes(
         typeof(DescriptionAttribute), false);
    if (attributes != null)
    {
        foreach (DescriptionAttribute attr in pattributes)
        {
            Console.WriteLine(
              $"{property.Name} [{attr.Text}]");
        }
    }
}
```

该程序的输出如下：

```cs
Main component of the car
Capacity [cm3]
Power [kW]
```

# 摘要

在本章中，我们看了反射服务，如何在运行时加载程序集，并查询关于类型的元信息。我们还学习了如何使用系统反射和 DLR 以及动态类型来动态执行代码。DLR 为 C#提供了动态特性，并以简单的方式实现了与动态语言的互操作性。本章最后涵盖的主题是属性。我们学习了常见的系统属性是什么，以及如何创建自己的类型以及如何在反射中使用它们。

在下一章中，我们将专注于并发和并行性。

# 测试你学到的东西

1.  .NET 中的部署单位是什么，它包含什么？

1.  什么是反射？它提供了什么好处？

1.  .NET 类型暴露了关于类型的元数据？你如何创建这种类型的实例？

1.  公共程序集和私有程序集之间有什么区别？

1.  在.NET Framework 中，程序集可以在什么上下文中被加载？

1.  什么是早期绑定？晚期绑定呢？后者提供了什么好处？

1.  什么是动态语言运行时？

1.  动态类型是什么，它通常在哪些场景中使用？

1.  属性是什么，你如何在代码中指定它们？

1.  你如何创建用户定义的属性？
