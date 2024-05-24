# C#7 和 .NET Core 秘籍（四）

> 原文：[`zh.annas-archive.org/md5/FFE2E66D9C939D110BF0079B0B5B3BA8`](https://zh.annas-archive.org/md5/FFE2E66D9C939D110BF0079B0B5B3BA8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：使用反应式扩展来组合基于事件的程序

本章涉及**反应式扩展**（**Rx**）。为了理解 Rx，我们将涵盖以下内容：

+   安装 Rx

+   事件与可观察对象

+   使用 LINQ 执行查询

+   在 Rx 中使用调度程序

+   调试 lambda 表达式

# 介绍

在日常处理 C# 应用程序开发中，您经常需要使用异步编程。您可能还需要处理许多数据源。想象一下返回当前汇率的 Web 服务，返回相关数据流的 Twitter 搜索，甚至多台计算机生成的不同事件。Rx 通过 `IObserver<T>` 接口提供了一个优雅的解决方案。

您使用 `IObserver<T>` 接口订阅事件。然后，维护 `IObserver<T>` 接口列表的 `IObservable<T>` 接口将通知它们状态的变化。实质上，Rx 将多个数据源（社交媒体、RSS 订阅、UI 事件等）粘合在一起生成数据。因此，Rx 将这些数据源汇集在一个接口中。事实上，Rx 可以被认为由三个部分组成：

+   **可观察对象**：将所有这些数据流汇集并表示的接口

+   **语言集成查询**（**LINQ**）：使用 LINQ 查询这些多个数据流的能力

+   **调度程序**：使用调度程序参数化并发

许多人心中的疑问可能是为什么开发人员应该使用（或找到使用）Rx。以下是一些 Rx 真正有用的例子。

+   创建具有自动完成功能的搜索。您不希望代码对搜索区域中输入的每个值执行搜索。Rx 允许您对搜索进行节流。

+   使应用程序的用户界面更具响应性。

+   在数据发生变化时得到通知，而不是必须轮询数据以查看变化。想象实时股票价格。

要了解 Rx 的最新信息，您可以查看 [`github.com/Reactive-Extensions/Rx.NET`](https://github.com/Reactive-Extensions/Rx.NET)  GitHub 页面[.](https://github.com/Reactive-Extensions/Rx.NET)

# 安装 Rx

在我们开始探索 Rx 之前，我们需要安装它。最简单的方法是使用 NuGet。

# 准备工作

在 Rx 的这一章中，我们不会创建一个单独的类。所有的代码都将在控制台应用程序中编写。

# 如何做...

1.  创建一个控制台应用程序，然后右键单击解决方案，从上下文菜单中选择“管理解决方案的 NuGet 包...”。

1.  在随后显示的窗口中，在搜索文本框中键入 `System.Reactive` 并搜索 NuGet 安装程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_01.png)

1.  在撰写本书时，最新的稳定版本是 3.1.1。如果您有多个项目，请选择要在其上安装 Rx 的项目。鉴于我们只有一个单独的控制台应用程序，只需选择为整个项目安装 Rx。

1.  接下来显示的屏幕是一个确认对话框，询问您确认对项目的更改。它将显示对每个项目将要进行的更改的预览。如果您对更改满意，请单击“确定”按钮。

1.  在最后的对话框屏幕上可能会向您呈现许可协议，您需要接受。要继续，请单击“我接受”按钮。

1.  安装完成后，您将在项目的引用节点下看到 Rx 添加的引用。具体如下：

+   `System.Reactive.Core`

+   `System.Reactive.Interfaces`

+   `System.Reactive.Linq`

+   `System.Reactive.PlatformServices`

# 它是如何工作的...

NuGet 绝对是向项目添加附加组件的最简单方式。从添加的引用中可以看出，`System.Reactive`是主要程序集。要更好地了解`System.Reactive`，请查看对象浏览器中的程序集。要做到这一点，请双击项目的引用选项中的任何程序集。这将显示对象浏览器：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_02.png)

`System.Reactive.Linq`包含 Rx 中的所有查询功能。您还会注意到`System.Reactive.Concurrency`包含所有调度程序。

# 事件与可观察对象

作为开发人员，我们应该都对事件非常熟悉。自从我们开始编写代码以来，大多数开发人员一直在创建事件。事实上，如果您在窗体上放置了一个按钮控件并双击按钮以创建处理按钮点击的方法，那么您已经创建了一个事件。在.NET 中，我们可以使用`event`关键字声明事件，通过调用它来发布事件，并通过向事件添加处理程序来订阅该事件。因此，我们有以下操作：

+   声明

+   发布

+   订阅

使用 Rx，我们有一个类似的结构，我们声明一个数据流，将数据发布到该流中，并订阅它。

# 准备就绪

首先，我们将看看 C#中事件的工作原理。然后，我们将看到使用 Rx 的事件的工作方式，并在此过程中突出显示差异。

# 如何做...

1.  在您的控制台应用程序中，添加一个名为`DotNet`的新类。在这个类中，添加一个名为`AvailableDatatype`的属性：

```cs
        public class DotNet 
        { 
          public string  AvailableDatatype { get; set; } 
        }

```

1.  在主程序类中，添加一个名为`types`的新静态动作事件。基本上，这只是一个委托，将接收一些值；在我们的情况下，是可用的.NET 数据类型：

```cs
        class Program 
        { 
          // Static action event 
          static event Action<string> types; 

          static void Main(string[] args) 
          { 

          } 
        }

```

1.  在`void Main`内，创建一个名为`lstTypes`的`List<DotNet>`类。在这个列表中，添加几个`DotNet`类的值。在这里，我们将只添加一些.NET 中的数据类型的硬编码数据：

```cs
        List<DotNet> lstTypes = new List<DotNet>(); 
        DotNet blnTypes = new DotNet(); 
        blnTypes.AvailableDatatype = "bool"; 
        lstTypes.Add(blnTypes); 

        DotNet strTypes = new DotNet(); 
        strTypes.AvailableDatatype = "string"; 
        lstTypes.Add(strTypes); 

        DotNet intTypes = new DotNet(); 
        intTypes.AvailableDatatype = "int"; 
        lstTypes.Add(intTypes); 

        DotNet decTypes = new DotNet(); 
        decTypes.AvailableDatatype = "decimal"; 
        lstTypes.Add(decTypes);

```

1.  我们的下一个任务是订阅此事件，使用一个简单地将*x*的值输出到控制台窗口的事件处理程序。然后，每次我们通过`lstTypes`列表循环时，通过添加`types(lstTypes[i].AvailableDatatype);`来触发事件：

```cs
        types += x => 
        { 
          Console.WriteLine(x); 
        }; 

        for (int i = 0; i <= lstTypes.Count - 1; i++) 
        { 
          types(lstTypes[i].AvailableDatatype); 
        } 

        Console.ReadLine();

```

实际上，在触发事件之前，我们应该始终检查事件是否为 null。只有在此检查之后，我们才应该触发事件。为简洁起见，我们在触发事件之前没有添加此检查。

1.  当您将步骤 1 到步骤 4 的所有代码添加到控制台应用程序中时，它应该看起来像这样：

```cs
        class Program 
        { 
          // Static action event 
          static event Action<string> types; 

          static void Main(string[] args) 
          { 
            List<DotNet> lstTypes = new List<DotNet>(); 
            DotNet blnTypes = new DotNet(); 
            blnTypes.AvailableDatatype = "bool"; 
            lstTypes.Add(blnTypes); 

            DotNet strTypes = new DotNet(); 
            strTypes.AvailableDatatype = "string"; 
            lstTypes.Add(strTypes); 

            DotNet intTypes = new DotNet(); 
            intTypes.AvailableDatatype = "int"; 
            lstTypes.Add(intTypes); 

          DotNet decTypes = new DotNet(); 
            decTypes.AvailableDatatype = "decimal"; 
            lstTypes.Add(decTypes); 

            types += x => 
            { 
              Console.WriteLine(x); 
            }; 

            for (int i = 0; i <= lstTypes.Count - 1; i++) 
            { 
              types(lstTypes[i].AvailableDatatype); 
            } 

            Console.ReadLine(); 
          } 
        }

```

1.  运行应用程序将使用值设置我们的列表，然后触发创建的事件以将列表的值输出到控制台窗口：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_03.png)

1.  让我们看看使用 Rx 的事件的工作方式。添加一个静态的`string`的`Subject`。您可能还需要将`System.Reactive.Subjects`命名空间添加到您的项目中，因为`Subjects`位于这个单独的命名空间中：

```cs
        class Program 
        { 

            static Subject<string> obsTypes = new Subject<string>(); 

         static void Main(string[] args) 
          { 

          } 
        }

```

1.  在创建`DotNet`列表的代码之后，我们使用`+=`来连接事件处理程序。这一次，我们将使用`Subscribe`。这是代码的`IObservable`部分。添加完这个之后，使用`OnNext`关键字触发事件。这是代码的`IObserver`部分。因此，当我们循环遍历我们的列表时，我们将调用`OnNext`来将值输出到订阅的`IObservable`接口：

```cs
        // IObservable 
        obsTypes.Subscribe(x => 
        { 
          Console.WriteLine(x); 
        }); 

        // IObserver 
        for (int i = 0; i <= lstTypes.Count - 1; i++) 
        { 
          obsTypes.OnNext(lstTypes[i].AvailableDatatype); 
        } 

        Console.ReadLine();

```

1.  当您完成添加所有代码后，您的应用程序应该看起来像这样：

```cs
        class Program 
        {      
          static Subject<string> obsTypes = new Subject<string>(); 

          static void Main(string[] args) 
          { 
            List<DotNet> lstTypes = new List<DotNet>(); 
            DotNet blnTypes = new DotNet(); 
            blnTypes.AvailableDatatype = "bool"; 
            lstTypes.Add(blnTypes); 

            DotNet strTypes = new DotNet(); 
            strTypes.AvailableDatatype = "string"; 
            lstTypes.Add(strTypes); 

            DotNet intTypes = new DotNet(); 
            intTypes.AvailableDatatype = "int"; 
            lstTypes.Add(intTypes); 

            DotNet decTypes = new DotNet(); 
            decTypes.AvailableDatatype = "decimal"; 
            lstTypes.Add(decTypes); 

            // IObservable 
            obsTypes.Subscribe(x => 
            { 
              Console.WriteLine(x); 
            }); 

            // IObserver 
            for (int i = 0; i <= lstTypes.Count - 1; i++) 
            { 
              obsTypes.OnNext(lstTypes[i].AvailableDatatype); 
            } 

            Console.ReadLine(); 
          } 
        }

```

1.  运行应用程序时，您将看到与之前相同的项目输出到控制台窗口。

# 它是如何工作的...

在 Rx 中，我们可以使用`Subject`关键字声明事件流。因此，我们有一个事件源，我们可以使用`OnNext`发布到该事件源。为了在控制台窗口中看到这些值，我们使用`Subscribe`订阅了事件流。

Rx 允许您拥有仅为发布者或仅为订阅者的对象。这是因为`IObservable`和`IObserver`接口实际上是分开的。另外，请注意，在 Rx 中，observables 可以作为参数传递，作为结果返回，并存储在变量中，这使它们成为一流。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_04.png)

Rx 还允许您指定事件流已完成或发生错误。这确实使 Rx 与.NET 中的事件有所不同。另外，重要的是要注意，在项目中包括`System.Reactive.Linq`命名空间允许开发人员对`Subject`类型编写查询，因为`Subject`是`IObservable`接口：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_05.png)

这是 Rx 与.NET 中的事件有所不同的另一个功能。

# 使用 LINQ 执行查询

Rx 允许开发人员使用`IObservable`接口，该接口表示同步数据流，以使用 LINQ 编写查询。简而言之，Rx 可以被认为由三个部分组成：

+   **Observables**：将所有这些数据流汇集并表示的接口

+   **语言集成查询**（**LINQ**）：使用 LINQ 查询这些多个数据流的能力

+   **调度程序**：使用调度程序参数化并发

在本示例中，我们将更详细地查看 Rx 的 LINQ 功能。

# 准备就绪

由于 observables 只是数据流，我们可以使用 LINQ 对它们进行查询。在以下示例中，我们将根据 LINQ 查询将文本输出到屏幕上。

# 如何做...

1.  首先向解决方案添加一个新的 Windows 表单项目。

1.  将项目命名为`winformRx`，然后单击“确定”按钮：

1.  在工具箱中，搜索 TextBox 控件并将其添加到您的表单中。

1.  最后，在表单中添加一个标签控件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_06.png)

1.  右键单击`winformRx`项目，然后从上下文菜单中选择“管理 NuGet 包...”。

1.  在搜索文本框中，输入`System.Reactive`以搜索 NuGet 包，然后单击“安装”按钮。

1.  Visual Studio 将要求您审查即将对项目进行的更改。单击“确定”按钮。

1.  在安装开始之前，您可能需要点击“我接受”按钮接受许可协议。

1.  安装完成后，如果展开项目的引用，您应该会看到新添加的引用`winformRx`项目：

1.  最后，右键单击项目，并通过单击上下文菜单中的“设置为启动项目”将`winformRx`设置为启动项目。

1.  通过双击 Windows 表单上的任何位置创建表单加载事件处理程序。向此表单添加`Observable`关键字。您会注意到该关键字立即被下划线标记。这是因为您缺少对`System.Reactive`的 LINQ 程序集的引用。

1.  要添加此功能，请按*Ctrl* + *.*（句号）以显示可能的建议以解决问题。选择将`using System.Reactive.Linq`命名空间添加到您的项目。

1.  继续将以下代码添加到您的表单加载事件中。基本上，您正在使用 LINQ 并告诉编译器您要从称为`textBox1`的表单上的文本更改事件匹配的事件模式中选择文本。完成后，添加一个订阅变量并告诉它将在表单上的标签`label1`中输出找到的任何文本：

```cs
        private void Form1_Load(object sender, EventArgs e) 
        { 
          var searchTerm = Observable.FromEventPattern<EventArgs>(
            textBox1, "TextChanged").Select(x => ((TextBox)x.Sender).Text); 

          searchTerm.Subscribe(trm => label1.Text = trm); 
        }

```

当我们向表单添加文本框和标签时，我们将控件名称保留为默认值。但是，如果您更改了默认名称，则需要指定表单上控件的名称而不是`textBox1`和`label1`。

1.  单击运行按钮以运行应用程序。Windows 表单将显示文本框和标签。

1.  注意，当您输入时，文本将输出到表单上的标签上：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_07.png)

1.  让我们通过在 LINQ 语句中添加`Where`条件来增加一些乐趣。我们将指定`text`字符串只有在以句号结尾时才能选择文本。这意味着文本只会在每个完整句子之后显示在标签上。正如您所看到的，我们在这里并没有做任何特别的事情。我们只是使用标准的 LINQ 来查询我们的数据流，并将结果返回给我们的`searchTerm`变量：

```cs
        private void Form1_Load(object sender, EventArgs e) 
        { 
          var searchTerm = Observable.FromEventPattern<EventArgs>(
            textBox1, "TextChanged").Select(x => ((TextBox)x.Sender)
            .Text).Where(text => text.EndsWith(".")); 

          searchTerm.Subscribe(trm => label1.Text = trm); 
        }

```

1.  运行您的应用程序并开始输入一行文本。您会发现在您输入时标签控件没有输出任何内容，就像在我们添加`Where`条件之前的上一个示例中一样：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_08.png)

1.  在文本后加上一个句号并开始添加第二行文本：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_09.png)

1.  您会发现只有在每个句号之后，输入的文本才会添加到标签上。因此，我们的`Where`条件完美地发挥作用：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_10-1.png)

# 它是如何工作的...

Rx 的 LINQ 方面允许开发人员构建可观察序列。以下是一些示例：

+   `Observable.Empty<>`: 这将返回一个空的可观察序列

+   `Observable.Return<>`: 这将返回一个包含单个元素的可观察序列

+   `Observable.Throw<>`: 这将返回一个以异常终止的可观察序列

+   `Observable.Never<>`: 这将返回一个持续时间无限的非终止可观察序列

在 Rx 中使用 LINQ 允许开发人员操纵和过滤数据流，以返回他们需要的内容。

# 在 Rx 中使用调度程序

有时，我们需要在特定时间运行`IObservable`订阅。想象一下需要在不同地理区域和时区的服务器之间同步事件。您可能还需要从队列中读取数据，同时保留事件发生顺序。另一个例子是执行可能需要一些时间才能完成的某种 I/O 任务。在这些情况下，调度程序非常有用。

# 准备工作

此外，您可以考虑在 MSDN 上阅读更多关于使用调度程序的内容。请查看[`msdn.microsoft.com/en-us/library/hh242963(v=vs.103).aspx.`](https://msdn.microsoft.com/en-us/library/hh242963(v=vs.103).aspx)

# 如何做...

1.  如果您还没有这样做，请创建一个新的 Windows 表单应用程序并将其命名为`winformRx`。打开表单设计器，在工具箱中搜索 TextBox 控件并将其添加到您的表单中。

1.  接下来，在您的表单中添加一个标签控件。

1.  双击您的 Windows 表单设计器以创建 onload 事件处理程序。在此处理程序中，添加一些代码来读取输入到文本框中的文本，并在用户停止输入 5 秒后仅显示该文本。这是使用`Throttle`关键字实现的。向`searchTerm`变量添加一个订阅，将文本输入的结果写入标签控件的文本属性：

```cs
        private void Form1_Load(object sender, EventArgs e) 
        { 
          var searchTerm = Observable.FromEventPattern<EventArgs>(
            textBox1, "TextChanged").Select(x => ((TextBox)x.Sender)
            .Text).Throttle(TimeSpan.FromMilliseconds(5000)); 

          searchTerm.Subscribe(trm => label1.Text = trm); 
        }

```

请注意，您可能需要在您的`using`语句中添加`System.Reactive.Linq`。

1.  运行您的应用程序并开始在文本框中输入一些文本。立即，我们将收到一个异常。这是一个跨线程违规。当尝试从后台线程更新 UI 时会发生这种情况。`Observable`接口正在从`System.Threading`运行一个计时器，这与 UI 不在同一线程上。幸运的是，有一种简单的方法可以克服这个问题。事实证明，UI 线程能力位于不同的程序集中，我们最容易通过包管理器控制台获取：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_11.png)

1.  导航到视图 | 其他窗口 | 包管理器控制台以访问包管理器控制台。

1.  输入以下命令：

```cs
      PM> Install-Package System.Reactive.Windows.Forms

```

这将向您的`winformRx`项目添加 System.Reactive.Windows.Forms.3.1.1。因此，您应该在输出中看到以下内容：成功安装'System.Reactive.Windows.Forms 3.1.1'到 winformRx

请注意，您需要确保在包管理器控制台中将默认项目选择设置为`winformRx`。如果您没有看到此选项，请调整包管理器控制台屏幕的宽度，直到显示该选项。这样您就可以确保该包已添加到正确的项目中。

1.  安装完成后，在`onload`事件处理程序中修改您的代码，并将执行订阅的`searchTerm.Subscribe(trm => label1.Text = trm);`更改为以下内容：

```cs
        searchTerm.ObserveOn(new ControlScheduler(this)).Subscribe(trm => label1.Text = trm);

```

您会注意到我们在这里使用了`ObserveOn`方法。这基本上告诉编译器的是`new ControlScheduler(this)`中的`this`关键字实际上是指我们的 Windows 表单。因此，`ControlScheduler`将使用 Windows 表单计时器来创建更新我们的 UI 的间隔。消息发生在正确的线程上，我们不再有跨线程违规。

1.  如果您还没有将`System.Reactive.Concurrency`命名空间添加到您的项目中，Visual Studio 将用波浪线下划线标出代码中的`ControlScheduler`行。按下*Ctrl* + *.*（句号）将允许您添加缺少的命名空间。

1.  这意味着`System.Reactive.Concurrency`包含一个可以与 Windows 表单控件通信的调度程序，以便进行调度。再次运行应用程序，并开始在文本框中输入一些文本：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_12.png)

1.  在我们停止输入大约 5 秒钟后，节流条件得到满足，文本被输出到我们的标签上：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_13.png)

# 工作原理... 

我们需要记住的是，从我们创建的代码中，有`ObserveOn`和`Subscribe`。您不应该混淆这两者。在大多数情况下，处理调度程序时，您将使用`ObserveOn`。`ObserveOn`方法允许您参数化`OnNext`、`OnCompleted`和`OnError`消息的运行位置。而`Subscribe`，我们参数化实际的订阅和取消订阅代码的运行位置。

我们还需要记住，Rx 默认使用线程计时器（`System.Threading.Timer`），这就是为什么我们之前遇到跨线程违规的原因。不过，正如您所看到的，我们使用调度程序来参数化使用哪个计时器。调度程序执行此操作的方式是通过公开三个组件。它们如下：

+   调度程序执行某些操作的能力

+   执行操作或工作的顺序

+   允许调度程序具有时间概念的时钟

使用时钟的重要性在于它允许开发人员在远程计算机上使用定时器；例如（在您和他们之间可能存在时间差的地方），告诉他们在特定时间执行某个操作。

# 调试 lambda 表达式

自 Visual Studio 2015 以来，调试 lambda 表达式的能力一直存在。这是我们最喜欢的 IDE 功能的一个很棒的补充。它允许我们实时检查 lambda 表达式的结果并修改表达式以测试不同的场景。

# 准备就绪

我们将创建一个非常基本的 lambda 表达式，并在监视窗口中更改它以产生不同的值。

# 如何做...

1.  创建一个控制台应用程序，并在控制台应用程序中添加一个名为`LambdaExample`的类。在这个类中添加一个名为`FavThings`的属性：

```cs
        public class LambdaExample
        {
          public string FavThings { get; set; }
        }

```

1.  在控制台应用程序中，创建一个`List<LambdaExample>`对象，并将一些您喜欢的事物添加到此列表中：

```cs
        List<LambdaExample> MyFavoriteThings = new List<LambdaExample>();
        LambdaExample thing1 = new LambdaExample();
        thing1.FavThings = "Ice-cream";
        MyFavoriteThings.Add(thing1);

        LambdaExample thing2 = new LambdaExample();
        thing2.FavThings = "Summer Rain";
        MyFavoriteThings.Add(thing2);

        LambdaExample thing3 = new LambdaExample();
        thing3.FavThings = "Sunday morning snooze";
        MyFavoriteThings.Add(thing3);

```

1.  然后，创建一个表达式，仅返回以字符串`"Sum"`开头的事物。在这里，我们显然希望看到`Summer Rain`作为结果：

```cs
        var filteredStuff = MyFavoriteThings.Where(feature =>         feature.FavThings.StartsWith("Sum"));

```

1.  在表达式上设置断点并运行应用程序。当代码在断点处停止时，您可以复制 lambda 表达式：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_14.png)

1.  将 lambda 表达式`MyFavoriteThings.Where(feature => feature.FavThings.StartsWith("Sum"))`粘贴到监视窗口中，并将`StartsWith`方法中的字符串从`Sum`更改为`Ice`。您会看到结果已经改变，现在显示一个`Ice-cream`字符串：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_10_15.png)

请注意，如果您正在使用 Visual Studio 2017 RC，调试 lambda 表达式可能不起作用。您可能会收到从表达式评估器中的内部错误到包含 lambda 表达式的消息的任何内容。

# 工作原理是这样的…

通过这种方式，我们能够轻松地更改和调试 lambda 表达式。这在 Visual Studio 2015 之前的旧版本中是不可能的。显然，在处理这些表达式时，了解这个技巧非常重要。

另一个要注意的重点是，您可以在 Visual Studio 2017 的 Immediate 窗口中执行相同的操作，以及从 lambda 表达式中固定变量。


# 第十章：探索.NET Core 1.1

本章将探讨.NET Core 1.1。我们将看看.NET Core 是什么，以及您可以用它做什么。我们将重点关注：

+   在 Mac 上创建一个简单的.NET Core 应用程序并运行它

+   创建您的第一个 ASP.NET Core 应用程序

+   发布您的 ASP.NET Core 应用程序

# 介绍

最近.NET Core 引起了很多关注。有很多文章解释了.NET Core 是什么以及它的作用。简而言之，.NET Core 允许您创建在 Windows、Linux 和 macOS 上运行的跨平台应用程序。它通过利用一个.NET 标准库来实现，该库以完全相同的代码针对所有这些平台。因此，您可以使用您熟悉的语言和工具来创建应用程序。它支持 C#、VB 和 F#，甚至允许使用泛型、异步支持和 LINQ 等构造。有关.NET Core 的更多信息和文档，请访问[`www.microsoft.com/net/core`](https://www.microsoft.com/net/core)。

# 在 Mac 上创建一个简单的.NET Core 应用程序并运行它

我们将看看如何在 Windows 上使用 Visual Studio 2017 创建一个应用程序，然后在 Mac 上运行该应用程序。以前这种应用程序开发是不可能的，因为您无法在 Mac 上运行为 Windows 编译的代码。.NET Core 改变了这一切。

# 准备工作

您需要访问 Mac 才能运行您创建的应用程序。我使用的是 Mac mini（2012 年底）配备 2.5 GHz Intel Core i5 CPU，运行 macOS Sierra，内存为 4GB。

为了在 Mac 上使用您的.NET Core 应用程序，您需要做一些准备工作：

1.  我们需要安装 Homebrew，用于获取最新版本的 OpenSSL。通过在 Spotlight 搜索中键入`Terminal`来打开 Mac 上的终端：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_01-2.png)

也可以通过转到[`www.microsoft.com/net/core#macos`](https://www.microsoft.com/net/core#macos) 在 Mac 上执行以下步骤。

1.  将以下内容粘贴到终端提示符处，然后按*Enter*：

```cs
        /usr/bin/ruby -e "$(curl -fsSL         https://raw.githubusercontent.com/Homebrew/install/master/install)"

```

1.  如果终端要求您输入密码，请输入密码并按*Enter*。您在输入时将看不到任何内容。这是正常的。只需输入密码并按*Enter*继续。

安装 Homebrew 的要求是 Intel CPU、OS X 10.10 或更高版本、Xcode 的**命令行工具**（**CLT**）以及用于安装的 Bourne 兼容 shell，如 bash 或 zsh。因此终端非常适合。

根据您的互联网连接速度以及是否已安装 Xcode 的 CLT，安装 Homebrew 的过程可能需要一些时间才能完成。完成后，终端应如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_02.png)

输入`brew help`将显示一些有用的命令：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_03.png)

在终端中依次运行以下命令：

+   `brew update`

+   `brew install openssl`

+   `mkdir -p /usr/local/lib`

+   `ln -s /usr/local/opt/openssl/lib/libcrypto.1.0.0.dylib /usr/local/lib/`

+   `ln -s /usr/local/opt/openssl/lib/libssl.1.0.0.dylib /usr/local/lib/`

然后我们需要安装.NET Code SDK。从 URL [`www.microsoft.com/net/core#macos`](https://www.microsoft.com/net/core#macos) 点击下载.NET Core SDK 按钮。下载完成后，点击下载的`.pkg`文件。点击继续按钮安装.NET Core 1.1.0 SDK：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_04.png)

# 如何做...

1.  我们将在 Visual Studio 2017 中创建一个.NET Core 控制台应用程序。在 Visual C#模板下，选择.NET Core 和一个 Console App (.NET Core)项目：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_05.png)

1.  创建控制台应用程序时，代码如下：

```cs
        using System;

        class Program
        {
          static void Main(string[] args)
          {
            Console.WriteLine("Hello World!");
          }
        }

```

1.  修改代码如下：

```cs
        static void Main(string[] args)
        {
          Console.WriteLine("I can run on Windows, Linux and macOS");
          GetSystemInfo();
          Console.ReadLine();
        }

        private static void GetSystemInfo()
        {
          var osInfo = System.Runtime.InteropServices.RuntimeInformation.OSDescription;
          Console.WriteLine($"Current OS is: {osInfo}");
        }

```

1.  方法`GetSystemInfo()`只是返回当前操作系统，控制台应用程序当前运行的操作系统。我的应用程序的`csproj`文件如下：

```cs
        <Project ToolsVersion="15.0"           >
          <Import Project="$(MSBuildExtensionsPath)$(MSBuildToolsVersion)
            Microsoft.Common.props" />
            <PropertyGroup>
              <OutputType>Exe</OutputType>
              <TargetFramework>netcoreapp1.1</TargetFramework>
            </PropertyGroup>
            <ItemGroup>
              <Compile Include="***.cs" />
              <EmbeddedResource Include="***.resx" />
            </ItemGroup>
            <ItemGroup>
              <PackageReference Include="Microsoft.NETCore.App">
                <Version>1.1.0</Version>
              </PackageReference>
              <PackageReference Include="Microsoft.NET.Sdk">
                <Version>1.0.0-alpha-20161104-2</Version>
                <PrivateAssets>All</PrivateAssets>
              </PackageReference>
            </ItemGroup>
          <Import Project="$(MSBuildToolsPath)Microsoft.CSharp.targets" />
        </Project>

```

`<version>`被定义为`1.1.0`。

如果你仍在运行 Visual Studio 2017 RC，最好检查你安装的 NuGet 包，看看是否有.NET Core 版本从.NET Core 1.0 到.NET Core 1.1 的更新。

# 它是如何工作的...

按下*F5*来运行你的控制台应用程序。你会看到操作系统显示在输出中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_06.png)

转到你的控制台应用程序的`bin`文件夹，并将文件复制到 Mac 桌面上的一个文件夹中。将该文件夹命名为`consoleApp`。在终端中，导航到复制文件的文件夹。你可以通过输入命令`cd ./Desktop`来做到这一点，然后输入`ls`来列出你的桌面的内容。检查你创建的文件夹是否被列出，如果是的话，在终端中输入`cd ./consoleApp`。再次通过输入`ls`来列出`consoleApp`文件夹的内容。在我的情况下，DLL 被称为`NetCoreConsole.dll`。要运行你之前编写的代码，输入`dotnet NetCoreConsole.dll`并按*Enter*：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_07.png)

你可以看到代码正在运行，并在终端中输出文本。

如果你在安装了.NET Core SDK 后尝试运行`dotnet`命令时出现`command not found`的错误，请尝试以下操作。在终端中输入以下内容并按 Enter 键：`ln -s /usr/local/share/dotnet/dotnet /usr/local/bin/`，这将添加一个符号链接。这之后运行`dotnet`命令应该可以正常工作。

# 创建你的第一个 ASP.NET Core 应用程序

让我们来看看如何构建你的第一个 ASP.NET Core 应用程序。在这个教程中，我们将只创建一个非常基本的 ASP.NET Core 应用程序，并简要讨论`Startup`类。关于这个主题的进一步阅读是必要的，不包括在这个对 ASP.NET Core 的简要介绍中。

# 准备工作

首先在 Visual Studio 2017 中创建一个新项目。在 Visual C#下，选择.NET Core 节点，然后点击 ASP.NET Core Web Application.... 点击 OK：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_08.png)

然后你将看到项目模板选择。你可以选择创建一个空应用程序，一个 Web API（允许你创建基于 HTTP 的 API），或者一个完整的 Web 应用程序。选择空模板，确保在云中主机未被选中，然后点击 OK：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_09.png)

注意模板窗口允许你启用 Docker 支持。Docker 允许你在包含完整文件系统和运行应用程序所需的其他所有内容的容器中开发应用程序。这意味着你的软件无论在什么环境中都会始终以相同的方式运行。有关 Docker 的更多信息，请访问[www.docker.com](https://www.docker.com/)。

当你创建了 ASP.NET Core 应用程序后，你的解决方案资源管理器将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_10-1.png)

如果你正在运行 Visual Studio 2017 RC，你需要点击工具，NuGet 包管理器，管理解决方案的 NuGet 包...，看看是否有.NET Core 的更新。如果你使用的是.NET Core 1.01，那么应该可以通过 NuGet 获得.NET Core 1.1 的更新。让 NuGet 为你更新项目的依赖关系。在这样做之后，你必须浏览[`www.microsoft.com/net/download/core#/current`](https://www.microsoft.com/net/download/core#/current)，确保你已经在所有下载选项下选择了当前选项。下载当前的.NET Core SDK 安装程序并安装它。

此时，你可以按下*Ctrl* + *F5*来启动而不是调试，并启动你的 ASP.NET Core 应用程序。这将启动 IIS Express，这是 ASP.NET Core 应用程序的默认主机。它现在所做的唯一的事情就是显示文本 Hello World!。你已经成功创建并运行了一个 ASP.NET Core 应用程序。不要关闭你的浏览器。保持它打开：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_11.png)

请注意浏览器 URL 中的端口号 25608 是一个随机选择的端口。你看到的端口号很可能与书中的不同。

# 如何做...

1.  在您的解决方案资源管理器中右键单击解决方案，然后单击在文件资源管理器中打开文件夹。您会注意到有一个名为`src`的文件夹。点击进入这个文件夹，然后点击其中的`AspNetCore`子文件夹：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_12.png)

1.  比较 Visual Studio 中`AspNetCore`文件夹和解决方案资源管理器中的内容将向您展示它们几乎相同。这是因为在 ASP.NET Core 中，Windows 文件系统确定了 Visual Studio 中的解决方案：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_13-2.png)

1.  在 Windows 文件资源管理器中，右键单击`Startup.cs`文件并在记事本中编辑。您将在记事本中看到以下代码：

```cs
        using System;
        using System.Collections.Generic;
        using System.Linq;
        using System.Threading.Tasks;
        using Microsoft.AspNetCore.Builder;
        using Microsoft.AspNetCore.Hosting;
        using Microsoft.AspNetCore.Http;
        using Microsoft.Extensions.DependencyInjection;
        using Microsoft.Extensions.Logging;

        namespace AspNetCore
        {
          public class Startup
          {
            // This method gets called by the runtime. Use this method 
               to add services to the container.
            // For more information on how to configure your application, 
               visit https://go.microsoft.com/fwlink/?LinkID=398940
            public void ConfigureServices(IServiceCollection services)
            {
            }

            // This method gets called by the runtime. Use this method 
               to configure the HTTP request pipeline.
            public void Configure(IApplicationBuilder app, 
              IHostingEnvironment env, ILoggerFactory loggerFactory)
            {
              loggerFactory.AddConsole();

              if (env.IsDevelopment())
              {
                app.UseDeveloperExceptionPage();
              }

              app.Run(async (context) =>
              {
                await context.Response.WriteAsync("Hello World!");
              });
            }
          }
        }

```

1.  仍然在记事本中，编辑读取`await context.Response.WriteAsync("Hello World!");`的行，并将其更改为`await context.Response.WriteAsync($"The date is {DateTime.Now.ToString("dd MMM yyyy")}");`。在记事本中保存文件，然后转到浏览器并刷新。您会看到更改已在浏览器中显示，而无需我在 Visual Studio 中进行任何编辑。这是因为（如前所述）Visual Studio 使用文件系统来确定项目结构，ASP.NET Core 检测到对`Startup.cs`文件的更改，并自动在运行时重新编译它：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_14.png)

1.  更详细地查看解决方案资源管理器，我想要强调项目中的一些文件。`wwwroot`文件夹将代表托管时网站的根目录。您将在这里放置静态文件，如图像、JavaScript 和 CSS 样式表文件。另一个感兴趣的文件是`Startup.cs`文件，它基本上取代了`Global.asax`文件。在`Startup.cs`文件中，您可以编写在 ASP.NET Core 应用程序启动时执行的代码：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_15-1.png)

# 工作原理

`Startup.cs`文件包含`Startup`类。ASP.NET Core 需要一个`Startup`类，并且默认情况下将查找此类。按照惯例，`Startup`类称为`Startup`，但如果您愿意，也可以将其命名为其他名称。如果需要重命名它，则还需要确保修改`Program.cs`文件，以便`WebHostBuilder()`指定正确的类名用于`.UseStartup`。

```cs
public static void Main(string[] args)
{
   var host = new WebHostBuilder()
       .UseKestrel()
       .UseContentRoot(Directory.GetCurrentDirectory())
       .UseIISIntegration()
       .UseStartup<Startup>()
       .Build();

   host.Run();
}

```

回到`Startup.cs`文件中的`Startup`类，当您查看此类时，您将看到两种方法。这些方法是`Configure()`和`ConfigureServices()`。从`Configure()`方法的注释中可以看出，它用于*配置 HTTP 请求管道*。基本上，应用程序在此处处理传入的请求，而我们的应用程序目前所做的就是为每个传入的请求显示当前日期。`ConfigureServices()`方法在`Configure()`之前调用，是可选的。它的显式目的是添加应用程序所需的任何服务。ASP.NET Core 原生支持依赖注入。这意味着我可以通过将服务注入到`Startup`类中的方法中来利用服务。有关 DI 的更多信息，请确保阅读[`docs.microsoft.com/en-us/aspnet/core/fundamentals/dependency-injection`](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/dependency-injection)。

# 发布您的 ASP.NET Core 应用程序

发布 ASP.NET Core 应用程序非常简单。我们将通过命令提示符（以管理员身份运行）发布应用程序，然后将 ASP.NET Core 应用程序发布到 Windows 服务器上的 IIS。

# 做好准备

您需要设置 IIS 才能执行此操作。启动“程序和功能”，然后单击“程序和功能”表单左侧的“打开或关闭 Windows 功能”。确保选择了 Internet 信息服务。选择 IIS 后，单击“确定”以打开该功能：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_31.png)

您还需要确保已安装了.NET Core Windows 服务器托管包，它将在 IIS 和 Kestrel 服务器之间创建反向代理。

在撰写本文时，.NET Core Windows Server Hosting 包可在以下链接找到：

[`docs.microsoft.com/en-us/aspnet/core/publishing/iis#install-the-net-core-windows-server-hosting-bundle`](https://docs.microsoft.com/en-us/aspnet/core/publishing/iis#install-the-net-core-windows-server-hosting-bundle)

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_25.png)

安装.NET Core Windows Server Hosting 包后，您需要重新启动 IIS：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_26.png)

以管理员身份打开命令提示符，输入`iisreset`，然后按*Enter*。这将停止然后启动 IIS：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_27.png)

# 如何操作...

1.  通过以管理员身份运行命令提示符来打开命令提示符。在命令提示符中，转到项目的`src\AspNetCore`目录。确保您的计算机`C:\`驱动器的`temp`文件夹中有一个名为`publish`的文件夹，然后输入以下命令，按*Enter*。这将构建和发布您的项目：

```cs
        dotnet publish --output "c:temppublish" --configuration release

```

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_16.png)

根据您的 ASP.NET Core 应用程序的名称，您的`src`文件夹下的文件夹名称将与我的不同。

1.  应用程序发布后，您将在输出文件夹中看到发布文件以及它们的所有依赖项：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_17.png)

1.  回到命令提示符，输入`dotnet AspNetCore.dll`来运行应用程序。请注意，如果您的 ASP.NET Core 应用程序名称不同，您将运行的 DLL 将与书中的示例不同。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_18.png)

现在，您可以打开浏览器，输入`http://localhost:5000`。这将为您显示 ASP.NET Core 应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_32.png)

1.  您可以通过将发布文件复制到文件夹并在终端中输入`dotnet AspNetCore.dll`来在 macOS 上执行相同的操作：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_19.png)

然后在 Mac 上的 Safari 中，输入`http://localhost:5000`，然后按*Enter*。这将在 Safari 中加载站点：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_33.png)

虽然我刚刚展示了在 macOS 上运行 Safari 作为替代方案，但 ASP.NET Core 应用程序也可以在 Linux 上运行。

1.  将应用程序发布到 IIS 也很容易。在 Visual Studio 中，右键单击解决方案资源管理器中的项目，然后从上下文菜单中单击“发布...”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_20.png)

1.  然后，您需要选择一个发布目标。有几个选项可供选择，但在本示例中，您需要选择“文件系统”选项，然后单击“确定”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_21.png)

1.  在发布屏幕中，您可以通过单击“目标位置”路径旁边的“设置...”来修改其他设置。在这里，您需要选择以发布模式进行发布。最后，单击“发布”按钮。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_22.png)

1.  应用程序发布后，Visual Studio 将在输出窗口中显示结果以及您选择的发布位置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_23.png)

1.  在浏览器中，如果输入`http://localhost`，您将看到 IIS 的默认页面。这意味着 IIS 已经设置好了：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_24.png)

1.  在 Windows 资源管理器中，浏览到`C:\inetpub\wwwroot`，并创建一个名为`netcore`的新文件夹。将 ASP.NET Core 应用程序的发布文件复制到您创建的新文件夹中。在 IIS 中，通过右键单击`Sites`文件夹并选择添加网站来添加一个新网站。为网站命名，并选择在物理路径设置中复制发布文件的路径。最后，将端口更改为`86`，因为端口`80`被默认网站使用，然后单击“确定”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_28.png)

1.  您将在 IIS 的 Sites 文件夹中看到已添加您的网站。在 IIS 管理器右侧面板的“浏览网站”标题下，单击“浏览*.86 (http)”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_29.png)

1.  这将在您的默认浏览器中启动 ASP.NET Core 应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_11_30.png)

# 操作原理...

在 Windows 上创建一个 ASP.NET Core 应用程序可以让我们在 Windows、macOS 和 Linux 上运行该应用程序。在 Windows 命令提示符或 macOS 终端中，可以轻松地通过`dotnet`命令独立运行它。这就是.NET Core 对应用程序开发未来如此强大的原因。您可以使用您习惯的 IDE 来开发跨平台的应用程序。关于.NET Core 还有很多需要了解的内容，您真的需要深入了解概念并了解它的能力。


# 第十一章：ASP.NET Core 上的 MVC 框架

本章将探讨使用 MVC 框架创建 ASP.NET Core 应用程序。上一章向您介绍了 ASP.NET Core，并且我们从本章所需的基础知识开始。如果您对 ASP.NET Core 不熟悉，请看看第十章，*探索.NET Core 1.1*提供了什么。我们将会看到：

+   包括中间件及其有用之处

+   创建控制器并使用路由

+   呈现视图

# 介绍

MVC 框架的命名是根据其遵循的 MVC 设计模式而来的。MVC 代表**M**odel-**V**iew-**C**ontroller。HTTP 请求被发送到一个控制器，然后映射到*Controller*类中的一个方法。在该方法内，控制器决定如何处理 HTTP 请求。然后构造一个对控制器和请求不可知的*模型*。模型将包含控制器需要的所有信息的逻辑。然后使用*视图*来显示模型中包含的信息，以构建一个 HTML 页面，该页面将在 HTTP 响应中发送回请求的客户端。

MVC 框架允许我们通过让框架的每个组件专注于一个特定的事物来分离逻辑：

+   控制器接收 HTTP 请求并构建模型

+   模型包含我们请求的数据并将其发送到视图

+   视图然后从模型中包含的数据创建 HTML 页面

# 包括中间件及其有用之处

这个教程将向您展示如何在 ASP.NET Core 应用程序中设置中间件。ASP.NET 中间件定义了我们的应用程序如何响应接收到的任何 HTTP 请求。它还有助于控制我们的应用程序如何响应用户身份验证或错误。它还可以执行有关传入请求的日志操作。

# 准备工作

我们需要修改`Startup`类的`Configure()`方法中包含的代码。在 ASP.NET Core 应用程序中设置中间件就是在这里。在第十章，*探索.NET Core 1.1*中，我们看到我们的`Configure()`方法已经包含了两个中间件。第一个是一个中间件，当捕获到未处理的异常时，将显示开发人员异常页面。代码如下所示：

```cs
if (env.IsDevelopment())
{
   app.UseDeveloperExceptionPage();
}

```

这将显示任何错误消息，对于调试应用程序很有用。通常，此页面将包含诸如堆栈跟踪之类的信息。仅在应用程序处于开发模式时才安装。当您首次创建 ASP.NET Core 应用程序时，它处于开发模式。

第二个中间件是`app.Run()`，并且将始终存在于您的应用程序中。在第十章，*探索.NET Core 1.1*中，它将始终响应当前日期。将中间件视为门卫。所有进入应用程序的 HTTP 请求都必须通过您的中间件。

还要知道，您添加中间件的顺序很重要。在`app.Run()`中间件中，我们执行了`context.Response.WriteAsync()`。之后添加的任何中间件都不会被执行，因为处理管道在`app.Run()`中终止。随着我们的学习，这一点将变得更加清晰。

# 如何做...

1.  您当前的 ASP.NET Core 应用程序应包含一个如下所示的`Configure()`方法：

```cs
        public void Configure(IApplicationBuilder app, 
          IHostingEnvironment env, 
          ILoggerFactory loggerFactory)
        {
          loggerFactory.AddConsole();

          if (env.IsDevelopment())
          {
            app.UseDeveloperExceptionPage();
          }

         app.Run(async (context) =>
         {
           await context.Response.WriteAsync($"The date is 
             {DateTime.Now.ToString("dd MMM yyyy")}");
         });
       }

```

1.  从调试菜单中，单击“开始调试”或按*Ctrl* + *F5*。您将看到日期显示如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_12_01.jpg)

1.  返回您的代码，并告诉您的应用程序显示欢迎页面中间件。您可以通过在`app.Run()`之前添加`app.UseWelcomePage();`来实现这一点。您的代码需要如下所示：

```cs
        if (env.IsDevelopment())
        {
          app.UseDeveloperExceptionPage();
        }

        app.UseWelcomePage();

        app.Run(async (context) =>
        {
          await context.Response.WriteAsync($"The date is 
            {DateTime.Now.ToString("dd MMM yyyy")}"); 
        });

```

1.  保存您的`Startup.cs`文件并刷新您的浏览器。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_12_02.jpg)

1.  现在你再也看不到屏幕上显示的日期了。这是因为欢迎页面是终止中间件，任何 HTTP 请求都不会通过它。继续修改欢迎页面中间件如下：

```cs
        app.UseWelcomePage("/hello");

```

1.  如果你保存文件并刷新浏览器，你会再次在浏览器中看到日期显示。发生了什么？嗯，你刚刚告诉欢迎页面中间件只响应`/hello`页面的请求。

1.  在浏览器中更改 URL 如下`http://localhost:25860/hello`，然后按*Enter*。欢迎页面再次显示。

1.  让我们来看看`UseDeveloperExceptionPage()`中间件。修改`app.Run()`如下：

```cs
        app.Run(async (context) =>
        {
          throw new Exception("Error in app.Run()");
          await context.Response.WriteAsync($"The date is 
            {DateTime.Now.ToString("dd MMM yyyy")}"); 
        });

```

1.  保存你的更改并刷新浏览器。你会看到浏览器现在显示了一个开发人员会发现非常有用的页面。它显示了堆栈信息、传入的查询、任何 cookie 以及头信息。它甚至告诉我们异常发生的行数（在`Startup.cs`文件的第 36 行）。`UseDeveloperExceptionPage()`中间件允许请求通过它传递到较低的中间件。如果发生异常，这将允许`UseDeveloperExceptionPage()`中间件执行其工作。正如前面提到的，中间件的放置很重要。如果我们将`UseDeveloperExceptionPage()`中间件放在页面的末尾，它将无法捕获任何未处理的异常。因此，在你的`Configure()`方法的顶部放置这个中间件是一个好主意：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_12_03.jpg)

1.  让我们进一步探讨这个概念。当我们处于生产环境时，通常不希望用户看到异常页面。假设他们需要被引导到一个友好的错误页面。首先在你的应用程序的 wwwroot 中添加一个静态 HTML 页面。右键单击 wwwroot，然后从上下文菜单中选择添加、新项目：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_12_04.jpg)

wwwroot 是你可以提供静态页面的地方，比如 JavaScript 文件、CSS 文件、图片或静态 HTML 页面。

1.  选择一个 HTML 页面，命名为`friendlyError.html`，然后点击添加。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_12_05.jpg)

1.  修改`friendlyError.html`的 HTML 如下：

```cs
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="utf-8" />
            <title>Friendly Error</title>
          </head>
          <body>
            Something went wrong. Support has been notified.
          </body>
        </html>

```

1.  接下来我们需要向我们的应用程序添加一个 NuGet 包，以便我们可以提供静态文件。在**NuGet 包管理器**中，搜索 Microsoft.AspNetCore.StaticFiles 并将其添加到应用程序中。

1.  现在，我们需要稍微修改代码，模拟它在生产环境中运行。我们通过设置`IHostingEnvironment`接口的`EnvironmaneName`属性来实现这一点：`env.EnvironmentName = EnvironmentName.Production;`。

1.  然后我们需要在`if (env.IsDevelopment())`条件下添加一个`else`语句，并编写调用我们自定义静态错误页面的代码。在这里，我们将`friendlyError.html`文件添加到我们的`DefaultFileNames()`集合中，并告诉我们的应用程序我们希望在生产环境中的任何异常中使用此错误文件。最后，我们需要调用`UseStaticFiles()`方法告诉我们的应用程序使用静态文件。完成后，你的代码应该如下所示：

```cs
        env.EnvironmentName = EnvironmentName.Production;
        if (env.IsDevelopment())
        {
          app.UseDeveloperExceptionPage();
        }
        else
        {
          DefaultFilesOptions options = new DefaultFilesOptions();
          options.DefaultFileNames.Add("friendlyError.html");
          app.UseDefaultFiles(options);

          app.UseExceptionHandler("/friendlyError"); 
        }

        app.UseStaticFiles();

```

# 它是如何工作的...

再次按*Ctrl* + *F5*重新启动 IIS Express 并启动我们的应用程序。你会看到我们的自定义错误页面已经显示在浏览器中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_12_06.jpg)

实际上，我们可能会使用控制器来做这种事情。我想在这里说明的是添加自定义默认页面的用法，并在生产环境中发生异常时显示该页面。

正如你所看到的，ASP.NET Core 中的中间件非常有用。关于这个主题有很多文档，我鼓励你在这个主题上进行进一步阅读。从微软文档开始[`docs.microsoft.com/en-us/aspnet/core/fundamentals/middleware`](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/middleware)。

# 创建控制器并使用路由

在 MVC 框架内，控制器、模型和视图需要共同工作，形成 HTTP 请求和响应循环。然而，基本的起点是根据接收到的 HTTP 请求调用正确的控制器。如果没有这样做，我们建立在 MVC 框架上的应用程序将无法工作。在 MVC 框架中，调用正确的控制器以处理 HTTP 请求的过程称为路由。

# 准备工作

我们可以通过查看应用程序中间件中包含的路由信息来将 HTTP 请求路由到正确的控制器。然后，中间件使用这些路由信息来查看 HTTP 请求是否需要发送到控制器。中间件将查看传入的 URL，并将其与我们提供的配置信息进行匹配。我们可以在`Startup`类中使用两种路由方法之一来定义这些路由信息，即：

+   基于约定的路由

+   基于属性的路由

本教程将探讨这些路由方法。在我们开始之前，我们需要将 ASP.NET MVC NuGet 包添加到我们的应用程序中。您现在应该对向应用程序添加 NuGet 包相当熟悉。在 NuGet 包管理器中，浏览并安装`Microsoft.AspNetCore.Mvc`NuGet 包。这将为我们的应用程序提供新的中间件，其中之一是`app.UseMvc();`。这用于将 HTTP 请求映射到我们的控制器中的一个方法。修改您的`Configure()`方法中的代码如下：

```cs
loggerFactory.AddConsole();

if (env.IsDevelopment())
{
   app.UseDeveloperExceptionPage();
}
else
{
   DefaultFilesOptions options = new DefaultFilesOptions();
   options.DefaultFileNames.Add("friendlyError.html");
   app.UseDefaultFiles(options);

   app.UseExceptionHandler("/friendlyError"); 
}

app.UseStaticFiles();
app.UseMvc();

```

接下来，我们需要注册 MVC 框架所需的 MVC 服务。在`ConfigureServices()`中添加以下内容：

```cs
public void ConfigureServices(IServiceCollection services)
{
   services.AddMvc();
}

```

完成后，我们已经设置了 MVC 的基本功能。

# 如何做...

1.  在应用程序中添加一个名为`Controllers`的新文件夹：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_12_07.jpg)

1.  在`Controllers`文件夹中，添加一个名为`StudentController`的新类。在`StudentController`中，添加一个名为`Find()`的方法。完成后，您的类将如下所示：

```cs
        public class StudentController
        {
          public string Find()
          {
            return "Found students";
          }
        }

```

1.  回到`Startup`类，在其中添加一个名为`FindController()`的`private void`方法，该方法接受一个`IRouteBuilder`类型的参数。确保还将`using Microsoft.AspNetCore.Routing;`命名空间添加到您的类中。您的方法应如下所示：

```cs
        private void FindController(IRouteBuilder route)
        {

        }

```

1.  在`Configure()`方法中，将`app.UseMvc();`更改为`app.UseMvc(FindController);`。

1.  现在，我们需要告诉我们的应用程序如何查看 URL 以确定要调用哪个控制器。我们将在这里使用基于约定的路由，它使用我们定义的模板来确定要调用哪个控制器。考虑以下模板`{controller}/{action}`。然后，我们的应用程序将使用此模板来拆分 URL，并确定 URL 的哪一部分是控制器部分，URL 的哪一部分是操作部分。使用我们的`StudentController`类，方法`Find()`是模板所指的操作。因此，当应用程序接收到一个带有 URL`/Student/Find`的传入 HTTP 请求时，它将知道要查找`StudentController`类，并转到该控制器中的`Find()`方法。

我们不需要将 URL 明确命名为`/StudentController/Find`，因为 MVC 框架会根据约定，自动将模板中的`{controller}`部分中的单词`Student`应用`Controller`，以识别要查找的控制器的名称。

1.  将路由映射添加到`FindController()`方法中。这告诉应用程序模板名称为默认，并且模板需要在 URL 中查找`{controller}/{action}`模板。您的代码现在应如下所示：

```cs
        private void FindController(IRouteBuilder route)
        {
          route.MapRoute("Default", "{controller}/{action}");
        }

```

1.  将所有内容放在一起，您的`Startup`类将如下所示：

```cs
        public void ConfigureServices(IServiceCollection services)
        {
          services.AddMvc();
        }

        public void Configure(IApplicationBuilder app, 
          IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
          loggerFactory.AddConsole();

          if (env.IsDevelopment())
         {
           app.UseDeveloperExceptionPage();
         }
         else
         {
           DefaultFilesOptions options = new DefaultFilesOptions();
           options.DefaultFileNames.Add("friendlyError.html");
           app.UseDefaultFiles(options);

           app.UseExceptionHandler("/friendlyError"); 
         }

         app.UseStaticFiles();
         app.UseMvc(FindController);
       }

       private void FindController(IRouteBuilder route)
       {
         route.MapRoute("Default", "{controller}/{action}");
       }

```

1.  保存您的代码并在浏览器中的 URL 末尾输入以下内容：`/student/find`。我的 URL 如下，但您的可能会有所不同，因为端口号很可能与我的不同：`http://localhost:25860/student/find`。在浏览器中输入这个将把传入的 HTTP 请求路由到正确的控制器。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_12_08.jpg)

1.  然而，如果 URL 格式不正确或找不到控制器，我们应该怎么办呢？这就是我们可以向我们的模板添加默认值的地方。删除 URL 中的`/student/find`部分并输入。现在您应该在浏览器中看到错误 404。这是因为应用程序无法根据我们的 URL 找到控制器。在我们的`Controllers`文件夹中添加另一个类。将此类命名为`ErrorController`。然后，在此控制器内创建一个名为`Support()`的方法。您的代码应如下所示：

```cs
        public class ErrorController
        {
          public string Support()
          {
            return "Content not found. Contact Support";
          }
        }

```

1.  回到`Startup`类，在`FindController()`方法中修改模板。它应如下所示：

```cs
        route.MapRoute("Default", "{controller=Error}/{action=Support}");

```

1.  这样做的作用是告诉我们的应用程序，如果找不到控制器，它应默认到`ErrorController`类并执行该类中的`Support()`方法。保存您的代码并刷新浏览器，以查看应用程序默认到`ErrorController`。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_12_09.jpg)

1.  正如您所看到的，ASP.NET MVC 中的路由非常灵活。前面列出的步骤讨论了我们所谓的基于约定的路由。还有另一种称为基于属性的路由的路由方法，它在我们的控制器上使用属性。转到`ErrorController`类并向类添加`using Microsoft.AspNetCore.Mvc;`命名空间。然后，在类名上添加属性`[Route("Error")]`，在方法上添加属性`[Route("Support")]`。您的代码应如下所示：

```cs
        [Route("Error")]
        public class ErrorController
        {
          [Route("Support")]
          public string Support()
          {
            return "Content not found. Contact Support";
          }
        }

```

1.  在`Startup`类中的`FindController()`方法中，注释掉`route.MapRoute("Default", "{controller=Error}/{action=Support}");`这一行。在浏览器中，在 URL 末尾添加文本`/Error/Support`并输入。您会看到应用程序根据`ErrorController`类中定义的属性正确匹配`ErrorController`。

# 工作原理...

MVC 框架内的路由是一种非常灵活的方法，可以根据 HTTP 请求访问特定的控制器。如果您需要对访问的控制器有更多控制权，则基于属性的路由可能比基于约定的路由更合适。也就是说，在使用基于属性的路由时，您可以做一些额外的事情。看看在使用基于属性的路由时作为开发人员可用的内容。

# 渲染视图

到目前为止，我们一直在使用普通的 C#类作为控制器，但更常见的是让您的控制器从 MVC 框架提供的`Controller`基类继承。这使开发人员能够从他们的控制器中返回复杂的对象，例如我们的学生。这些复杂的返回类型以实现`IActionResult`接口的结果返回。因此，我们可以返回 JSON、XML，甚至 HTML 以返回给客户端。接下来，我们将看一下这个用法以及创建视图。

# 准备工作

打开`StudentController`类并修改它以包含基于属性的路由。确保在`StudentController`类中添加`using Microsoft.AspNetCore.Mvc;`命名空间。还要从`Controller`基类继承。

```cs
[Route("Student")]
public class StudentController : Controller
{
   [Route("Find")]
   public string Find()
   {
      return "Found students";
   }
}

```

然后，在您的项目中添加一个名为`Models`的文件夹。在`Models`文件夹中，添加一个名为`Student`的类，因为我们的应用程序将返回学生信息。这将是一个简单的类，其中包含学生编号、名和姓的属性。您的`Student`类应如下所示：

```cs
public class Student
{
   public int StudentNumber { get; set; }
   public string FirstName { get; set; }
   public string LastName { get; set; }
}

```

回到`StudentController`，我们想要实例化我们的`Student`模型并给它一些数据。然后，将`Find()`方法的返回类型从`string`更改为`IActionResult`。同时，将`using AspNetCore.Models;`命名空间添加到你的`StudentController`类中。

注意，如果你的项目不叫`AspNetCore`，你的命名空间会相应地改变：

`using [projectname].Models;`

你的代码现在应该如下所示：

```cs
[Route("Find")]
public IActionResult Find()
{
   var studentModel = new Student
   {
      StudentNumber = 123
      , FirstName = "Dirk"
      , LastName = 'Strauss"
   };
   return View(studentModel);
}

```

最终，我们希望从我们的`StudentController`返回一个视图结果。我们现在已经准备好进行下一步了。

# 操作步骤...

1.  在你的项目中添加一个名为`Views`的新文件夹。在该文件夹内，再添加一个名为`Student`的文件夹。在`Student`文件夹内，通过右键单击`Student`文件夹并从上下文菜单中选择“新建项...”来添加一个新项。在“添加新项”对话框中搜索 MVC 视图页面模板，并将其命名为`Find.cshtml`。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_12_10.jpg)

1.  你应该开始注意到`Views`文件夹、子文件夹和视图遵循非常特定的命名约定。这是因为 MVC 框架遵循非常特定的约定，当你查看`StudentController`时，这个约定就会变得清晰。`Views`文件夹包括`Views`、`Student`、`Find`，而`StudentController`包含类名中的`Student`和一个名为`Find()`的方法。

你也可以在`Views`文件夹中创建一个`Shared`文件夹。这是你放置所有控制器共享的视图的地方，控制器会默认在`Shared`文件夹中查找。

1.  回到`Find.cshtml` Razor 视图，删除当前存在的代码，并用以下代码替换：

```cs
        <html >
          <head>
            <title></title>
          </head>
          <body>
          </body>
        </html>

```

你也可以使用 HTML 代码片段。输入`html`并按两次*Tab*键，将 HTML 代码的样板插入到 Find 视图中。

1.  使用 Razor 视图的关键在于你可以直接在`Find.cshtml`文件中编写 C#表达式。然而，在这之前，我们需要设置我们将要引入视图的模型类型。我们使用以下指令来实现：`@model AspNetCore.Models.Student`。现在我们可以在 Razor 视图中直接引用我们的`Student`模型，并且拥有完整的智能感知支持。这是通过使用大写的`M`来实现的`@Model`。看一下 Razor 视图的变化：

```cs
        @model AspNetCore.Models.Student
        <html >
          <head>
            <title>Student</title>
          </head>
          <body>
            <div>
              <h1>Student Information</h1>
              <strong>Student number:</strong>@Model.StudentNumber<br />
              <strong>First name: </strong>@Model.FirstName<br />
              <strong>First name: </strong>@Model.LastName<br />
            </div>
          </body>
        </html>

```

# 工作原理...

保存你的代码并刷新你的浏览器。你的 URL 应该是`http://localhost:[your port number]/student/find`，这样才能正常工作。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_12_11.jpg)

HTTP 请求被路由到`StudentController`，然后填充并返回包含我们需要的数据的`Student`模型，并将其发送到 Find Razor 视图。这就是 MVC 框架的本质。当涉及到 MVC 框架和 ASP.NET Core 时，还有很多内容需要涵盖，但本章只涉及这些主题的基本介绍。

作为开发人员，我们不断面临着跟上最新技术的挑战。我们渴望学习更多，变得更加优秀。你正在阅读这本书本身就是对这一点的证明。然而，就本章而言，.NET Core 和 MVC 框架是绝对需要更多学习的领域。在一章中不可能涵盖所有内容。开发人员可以找到各种在线资源。我发现微软虚拟学院[`mva.microsoft.com`](https://mva.microsoft.com)是学习新技术的最佳（免费）资源之一。微软专家提供免费的微软培训。

希望这足以引起你的兴趣，并鼓励你进一步研究这些主题。


# 第十二章：选择和使用源代码控制策略

源代码控制是每个开发人员工具包的重要组成部分。无论您是业余爱好者还是专业程序员，当您离开办公桌回家时，您最好确保您的代码是安全的。在本章中，我们将讨论选择和使用源代码控制策略。我们将讨论一些主题，比如：

+   设置 Visual Studio 帐户管理并确定哪种源代码控制解决方案最适合您

+   设置 Visual Studio GitHub 集成，首次检入代码，以及检入更改

+   使用 GitHub 作为团队合作，处理和解决代码冲突

# 介绍

在我的职业生涯中，我使用过 Visual SourceSafe、SVN、VSTS、Bitbucket 和 GitHub。重要的不是你如何对待它，而是你保持你的源代码安全和版本化。当我开始使用源代码控制时，我所在的公司使用了 Visual SourceSafe。如果您对这个软件不熟悉，可以搜索一下。你会看到一些包含“讨厌”、“不愉快”、“糟糕”和“微软的源代码破坏系统”的结果。你懂的。

我们有一个员工离开了他独占的文件，之后他辞职并移民到另一个国家。我开始怀疑公司强制使用 SourceSafe 的政策是否是他移民的原因。但开玩笑的，这给我们带来了无尽的问题。在一个大型项目上使用 SourceSafe，可能会导致灾难。然而，如今，开发人员有很好的选择。

显而易见的两个是 Microsoft Team Services 和 GitHub。它们都有免费的层级，但使用其中一个而不是另一个的决定完全取决于您的独特情况。

# 设置 Visual Studio 帐户管理并确定哪种源代码控制解决方案最适合您

Visual Studio 允许开发人员创建帐户并登录。如果您经常在不同的机器上工作（比如工作和家用 PC），那么这将特别有益，因为 Visual Studio 将自动在您登录的机器之间同步您的设置。

# 准备工作

本教程将假设您刚刚在您的计算机上安装了 Visual Studio 2017。无论您安装的是试用版还是授权版的 Visual Studio 2017 都无所谓。

# 如何做...

1.  安装完成后，打开 Visual Studio。

1.  在 Visual Studio 的右上方，您会看到一个“登录”链接：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_01.png)

1.  单击“登录”链接，您将被允许在此输入您的电子邮件地址。我发现直接使用我的 Outlook 电子邮件地址很有用。在我看来，这是最好的网络电子邮件之一。

请注意，我之所以推荐 Outlook 并不是因为其他原因，而是因为我真的认为它是一个很棒的产品。我还有一个 Gmail 帐户和一个 iCloud 电子邮件帐户。

1.  添加完您的电子邮件帐户后，Visual Studio 将重定向您到登录页面。

1.  因为我已经有一个 Outlook 帐户，所以 Visual Studio 只允许我使用它登录。但是，如果您需要创建一个帐户，可以在“登录到 Visual Studio”表单上的注册链接上这样做：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_02-1.png)

1.  Visual Studio 现在将重定向您到一个注册页面，您可以在那里创建一个帐户：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_03.png)

1.  创建完您的帐户后，您将被提示返回 Visual Studio 进行登录。登录后，Visual Studio 将在 IDE 的右上角显示您的详细信息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_04.png)

1.  单击您的帐户名称旁边的向下箭头，您可以查看您的帐户设置....

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_05.png)

1.  这将向您显示您的帐户摘要，您可以在其中进一步个性化您的帐户：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_06.png)

# 它是如何工作的...

源代码控制的选择是每个开发人员都有强烈意见的话题。不幸的是，如果您为老板工作，这个决定可能甚至不取决于您。许多公司已经按照他们喜欢的方式设置了他们的源代码控制系统，您需要遵守公司的程序。这就是现实。然而，作为独立开发人员，了解可用的选项是很好的。

所有优秀的开发人员也应该在自己的时间里编写代码。您不仅在工作时才是开发人员。我们吃饭、呼吸、睡觉，生活中都离不开代码。这是我们是谁以及我们是什么的一部分。我会说，为了成为更好的开发人员，您必须在自己的时间里玩弄代码。开始一个小项目，召集一些朋友，决定一起编写一些软件。这不仅会让您们都变得更好，而且您们会互相学到很多东西。

如果您是一名远程开发人员，不需要每天通勤到办公室工作，您仍然可以与开发人员社区联系。开发人员有很多资源可用，开发人员社区也乐意围绕新手提供帮助。如果您不致力于保护您的代码，开始一个独立或小项目是没有意义的。而要做到这一点，您也不必花一分钱。**Visual Studio Online**（现在称为**团队服务**）和 GitHub 为开发人员提供了一个绝佳的平台来保护您的代码。

让我们首先看看团队服务。可以通过将浏览器指向[`www.visualstudio.com/team-services/`](https://www.visualstudio.com/team-services/)来找到该网站。

在这里，您将看到微软为开发人员提供了使用团队服务的绝佳机会。最多可免费使用五个用户。这意味着您和您的伙伴可以共同致力于下一个大项目，同时确保您的代码保持安全。注册非常简单，只需点击“免费开始”链接：

有关定价信息，请访问以下链接：

[`www.visualstudio.com/team-services/pricing/`](https://www.visualstudio.com/team-services/pricing/)

第二个优秀的选择是 GitHub。它在免费提供方面略有不同，要求开发人员在免费账户上使用公共存储库。如果您不介意您的代码基本上是开源的，那么 GitHub 是一个很好的选择。不过，使用 GitHub，您可以拥有无限的合作者和公共存储库：

有关定价信息，请访问以下链接：

[`github.com/pricing`](https://github.com/pricing)

源代码控制的选择基本上取决于您的代码的开放性。如果您可以让其他开发人员看到并下载您的代码，那么 GitHub 是一个很好的选择。如果您需要您的代码保持私密，并且只在特定人员之间共享，那么付费的 GitHub 账户会更适合您。如果您还不想花钱，那么团队服务将是您最好的选择。

# 设置 Visual Studio GitHub 集成，首次提交代码，以及提交更改

多年来，GitHub 一直是一股强大的力量。有开发人员对它赞不绝口。事实上，使用 Apple 的 Xcode IDE 时，它是默认选项。无论出于何种原因，您决定使用 GitHub，可以放心，您和您的代码都在安全的手中。

# 做好准备

以下步骤将假定您已经注册了 GitHub 账户，并且已启用了双因素身份验证。如果您还没有注册 GitHub 账户，可以访问[`github.com/`](https://github.com/)注册一个新账户。要在 GitHub 账户上启用双因素身份验证（我个人强烈建议这样做），请执行以下操作：

1.  点击个人资料图片旁边的向下箭头，然后选择设置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_07.png)

1.  从下一个网页左侧出现的个人设置菜单中，选择安全性：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_08.png)

1.  安全页面的第一部分将是您的双因素身份验证状态。要开始设置它，请单击“设置双因素身份验证”按钮。

1.  然后，您将看到什么是双因素身份验证的简要概述，并可以选择使用应用程序进行设置（我推荐的）或使用短信进行设置。使用应用程序是最简单的方法，如果您有智能手机或平板电脑，可以从适用的应用商店下载身份验证器应用程序。然后，按照 GitHub 给出的提示完成双因素身份验证设置。

1.  完成设置后，您的双因素身份验证将被打开。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_09.png)

# 如何做到的...

1.  将 GitHub 扩展添加到 Visual Studio 很容易，只需从以下链接下载 visx 并安装：[`visualstudio.github.com/downloads/GitHub.VisualStudio.vsix`](https://visualstudio.github.com/downloads/GitHub.VisualStudio.vsix)。

1.  假设您有要添加到 GitHub 的现有应用程序，那么将其添加到新存储库的过程非常简单。我只是创建了一个仅包含模板代码的控制台应用程序，但您可以将任何项目类型和大小添加到 GitHub。

1.  在 Visual Studio 2017 的“视图”菜单中，选择“Team Explorer”选项。

1.  在托管服务提供程序部分，您将看到两个选项。现在，我们将选择 GitHub，并且，因为我们已经有一个帐户，我们将单击“连接”...

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_10.png)

1.  现在，您将看到 GitHub 登录页面。如果您没有现有的 GitHub 帐户，您也可以从这里注册：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_11.png)

1.  因为我在 GitHub 帐户上设置了双因素身份验证，所以我被提示使用我的身份验证器应用程序输入生成的身份验证代码并进行身份验证：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_12.png)

1.  认证后，您将返回到“管理连接”屏幕。如果您的项目未显示在本地 Git 存储库下，可以添加它：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_13.png)

1.  接下来，您将要单击主页图标，即 Team Explorer 窗口顶部的小房子图标。从主屏幕，单击“同步”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_14.png)

1.  这将向您显示发布窗口。在 GitHub 下，单击“发布到 GitHub”按钮。这将把您的项目发布到 GitHub 的新存储库中。

请记住，如果您使用的是免费的 GitHub，那么您的所有存储库都是公开的。如果您正在编写不能公开的代码（不是开源的），那么请注册一个包括私人存储库的付费 GitHub 帐户。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_15.png)

1.  GitHub 随后会提示您添加此发布的详细信息。因为您之前连接到了 GitHub，所以您的用户名将已在下拉菜单中选择。准备好后，单击“发布”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_16.png)

1.  项目发布到 GitHub 后，您将自动返回到主屏幕：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_17.png)

1.  查看您的 GitHub 帐户在线，您将看到项目已添加：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_18.png)

1.  接下来，让我们去对`GitHubDemo`应用程序进行一些更改。只需添加一个新类到您的项目中。我称我的为`NewClass.cs`，但您可以随意命名。

1.  您会注意到，一旦对项目进行更改，解决方案将用红色勾标记更改的项目。您的类将用绿色加号标记：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_19.png)

1.  要将更改添加到 GitHub 存储库，您可以选择两种方法。第一种选择是转到 Team Explorer - 主页窗口，然后单击“更改”按钮。

1.  第二种（我认为更方便的）选择是在“解决方案资源管理器”中右键单击解决方案，然后从上下文菜单中单击“提交...”菜单项。

1.  第一次执行提交时，GitHub 可能会要求您提供用户信息。

1.  在允许提交更改之前，您必须填写所需的提交消息。在真实的团队项目中，在提交消息中尽可能详细地描述。考虑使用任务项代码（或积压代码）来唯一标识所添加的代码。这将在未来的某个时候为您（或其他开发人员）节省时间，我保证：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_20.png)

1.  需要注意的一件重要事情是，如果单击“提交所有”按钮旁边的向下箭头，您将有三个提交选项可供选择。提交所有按钮将仅记录您在本地机器上进行的更改。换句话说，更改不会反映在远程存储库中。提交所有并推送按钮将记录本地机器上的更改，并将这些更改推送到您的远程 GitHub 存储库。提交所有并同步按钮将记录本地机器上的更改，然后将从远程存储库中拉取任何更改，最后进行推送。如果您正在团队中工作，您将希望这样做。但是，对于本教程，我将只进行提交所有并推送，因为我是唯一在这个存储库上工作的开发人员：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_21.png)

1.  当提交完成后，团队资源管理器 - 同步窗口将通知您提交成功：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_22.png)

1.  转到 GitHub 在线，您将看到新推送的更改反映在您的 GitHub 存储库中，以及提交消息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_23.png)

1.  GitHub 是任何开发人员的绝佳源代码控制解决方案。考虑创建一个开源项目。它比您想象的更有益。

如今，越来越多的潜在雇主在考虑开发人员职位申请者时会审查他们的 GitHub 存储库。请记住这一点，因为 GitHub 存储库本身就是一份简历。

# 它是如何工作的...

免费的 GitHub 帐户允许您创建公共存储库。这意味着任何人都可以从 GitHub 搜索、查看和克隆您的项目到他们自己的桌面。这是 GitHub 的核心理念。这显然是独立开发人员和不想花钱的公司的关键因素。公司可以承受比独立开发人员更多的费用，但我认为一些公司更喜欢自己动手，而不是使用云中托管的服务提供商。这意味着他们更喜欢通过在自己的公司服务器上设置源代码控制系统来保持对源代码控制的控制。对于独立开发人员来说，GitHub 作为一个选择是一个很棒的解决方案。对于那些需要私有存储库的人来说，费用也不是一个障碍。

# 使用 GitHub 作为团队合作，处理和解决代码冲突

在团队中工作时，GitHub 和 Team Services 真的发挥了作用。协作努力的效果非常强大。不过，有时可能会有些挑战。让我们看看如何使用 GitHub 在团队设置中工作。

# 准备工作

我们将使用已经检入 GitHub 的现有`GitHubDemo`应用程序。假设一个新的开发人员（我们称之为约翰）加入了团队。在您允许他将代码推送到您的分支之前，您需要将他添加为合作者。要做到这一点，请登录 GitHub，然后单击`GitHubDemo`存储库中的设置选项卡。单击左侧菜单中的合作者。

然后，您可以通过输入他们的 GitHub 用户名、全名或电子邮件地址来搜索要添加的合作者：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_24.png)

完成后，单击“添加合作者”按钮将约翰添加为项目的合作者：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_25.png)

约翰将收到一封电子邮件，并首先需要回复您的合作邀请。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_26.png)

# 如何做...

1.  约翰开始设置他的 Visual Studio 环境，包括通过单击菜单中的团队并单击管理连接来连接到 GitHub....

1.  他用电子邮件地址和密码登录 GitHub。

请注意，如果您刚刚注册 GitHub，您需要单击发送到注册时指定的电子邮件地址的验证电子邮件。如果未验证您的电子邮件地址，您将无法从 Visual Studio 登录。

1.  连接后，约翰看到他的 GitHub 详细信息已加载：

1.  他现在想要在 GitHub 上工作`GitHubDemo`应用程序，并通过名称搜索在 GitHub 上找到它：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_27.png)

1.  他现在从克隆或下载按钮的“使用 HTTPS”文本框中复制 URL：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_28.png)

1.  回到 Visual Studio，约翰展开本地 Git 存储库并单击克隆。他将复制的 URL 粘贴到 Git 存储库路径，并指定代码应克隆到他的硬盘上的位置。然后单击克隆：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_29.png)

1.  当代码被克隆时，它将在约翰之前指定的文件夹路径中。

1.  是时候对代码进行一些更改了。他像往常一样在 Visual Studio 中打开项目。约翰决定在`NewClass`类上工作，并添加一个返回倒计时整数的新函数：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_30-1.png)

1.  代码更改完成后，约翰准备提交他刚刚添加到`GitHubDemo`项目的代码。

1.  添加提交消息后，然后单击“提交所有”和“同步”。

一个重要的事情要注意的是，如果您单击“提交所有”按钮旁边的向下箭头，您将有三个提交选项可供选择。此按钮将仅记录您在本地计算机上进行的更改。换句话说，更改不会反映在远程存储库中。 “提交所有并推送”按钮将记录本地计算机上的更改，并将这些更改推送到远程 GitHub 存储库。 “提交所有并同步”按钮将记录本地计算机上的更改，然后将从远程存储库中拉取任何更改，最后将进行推送。

1.  约翰的更改已提交到 GitHub 存储库：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_31.png)

1.  在办公室的另一边，我正在处理相同的一小部分代码。唯一的问题是我已经添加了相同的方法，并使用了自己的`CountDown`逻辑实现：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_32.png)

1.  我准备好并提交我的更改到 GitHub：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_33.png)

1.  GitHub 立即阻止我这样做。这是因为如果我的代码被推送，John 之前的提交将会丢失。GitHub 在 GitHub 帮助中有关于这个主题的很好的帮助文件[`help.github.com/articles/dealing-with-non-fast-forward-errors/`](https://help.github.com/articles/dealing-with-non-fast-forward-errors/)。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_34.png)

输出窗口包含更详细的错误消息：

<q>推送到远程存储库时遇到错误：被拒绝的更新，因为远程包含您本地没有的工作。这通常是由另一个存储库推送到相同的引用引起的。您可能需要在再次推送之前先集成远程更改。</q>

1.  要解决此问题，请单击“拉取”以获取约翰最新的提交。然后您的代码将处于冲突状态。听起来很糟糕，但实际上并不是。这让您控制决定使用哪些代码。您可以看到拉取显示有冲突的文件，还有约翰添加的传入提交消息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_35.png)

1.  要查看冲突，请点击消息弹出窗口中的解决冲突链接：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_36.png)

1.  然后您将看到解决冲突屏幕，列出了冲突的文件。单击文件将其展开为简短摘要和操作选项屏幕。始终明智地单击“比较文件”链接以查看冲突文件之间的差异：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_37.png)

1.  代码上的差异立即显而易见。从这里开始，你们团队的工作流程取决于你们如何合作。通常，冲突可能会非常复杂，因此与相关开发人员讨论未来的方向总是一个好主意：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_38.png)

1.  在这种情况下，约翰和我决定他的代码更好、更简洁。因此，决定只需点击“接受远程”并使用约翰的代码。当你点击链接后，需要点击“提交合并”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_39.png)

1.  添加提交消息后，你可以将代码推送到仓库。在这种情况下，我只是用约翰的代码替换了我的所有代码，但可能会出现一些情况，你需要使用一些你的代码和另一位开发者的代码。GitHub 允许我们轻松处理这些冲突。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_40.png)

1.  将代码推送到远程后，GitHub 会通知你代码已成功同步：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_13_41.png)

# 它是如何工作的...

GitHub 简化了提交、解决冲突和合并代码的痛苦。毫无疑问，它是任何开发者工具包中的必备工具，也是开发团队的必备工具。即使你不是专业使用它，为自己创建一个仓库也是一个好主意。开始使用它来检查你在下班后工作的宠物项目。将你的知识扩展到日常工作之外，这将使你成为一个更好的开发者。


# 第十三章：在 Visual Studio 中创建移动应用程序

Visual Studio 是**集成开发环境**（**IDEs**）的**强大工具**。毫无疑问。作为开发人员，您可以通过为各种平台创建应用程序来尽情发挥您的多才多艺。其中之一就是移动开发。开发人员开始创建移动应用程序，但不想使用不同的 IDE。使用 Visual Studio，您不必这样做。它将允许您创建 Android 和（现在还有**Xamarin**）iOS 和 Mac 应用程序。

因此，本章将讨论以下概念：

+   在您的 Windows PC 和 Mac 上安装 Xamarin 和其他所需组件

+   在 Visual Studio 中使用 Apache Cordova 创建移动应用程序

+   使用 Xamarin.Forms 和 Visual Studio for Mac 创建 iOS 应用程序

# 介绍

如果您还没有听说过 Xamarin，我们鼓励您搜索一下这个工具。传统上，开发人员需要使用**Xcode**或**NetBeans**来创建 iOS 和 Android 应用程序。对开发人员来说，挑战在于这意味着需要学习一种新的编程语言。例如，如果您创建了一个要部署到 iOS、Android 和 Windows 的应用程序，您需要了解 Objective-C 或 Swift、Java 和.NET 语言。

这也为开发带来了额外的挑战，因为这意味着必须维护多个代码库。如果在应用程序的 Windows 版本中进行更改，还必须对 iOS 和 Android 代码库进行更改。有时公司会为每个平台管理不同的开发团队。您可以想象在多个团队和多个平台上管理变更所涉及的复杂性。如果您正在处理一个庞大的代码库，这一点尤为真实。

Xamarin 通过允许.NET 开发人员使用标准.NET 库在 Visual Studio 中创建 iOS 和 Android 应用程序来解决了这个问题。作为.NET 开发人员，您现在可以使用您已经拥有的技能来完成这个任务。简而言之，您将为您的应用程序创建一个共享库，然后为不同的平台创建不同的外观。第二个选择是使用 Xamarin.Forms 创建一个 Visual Studio 项目并针对所有三个平台。这使得开发人员很容易地针对多个平台进行开发。

# 在您的 Windows PC 和 Mac 上安装 Xamarin 和其他所需组件

Xamarin 到底是如何工作的？看起来确实像魔术，对吧？我的意思是，在 Visual Studio 中编写 C#并在另一端编译成本地的 iOS、Mac 或 Android 应用程序确实看起来像魔术。许多技术已经投入到让开发人员有能力做到这一点。对于 iOS 和 Mac 应用程序，这个过程有点复杂。如果您想要针对 iOS 或 Mac，需要使用 Mac 来构建您的 iOS 应用程序。有一些服务可以让 Mac 远程测试和编译（例如 MacinCloud，[`www.macincloud.com/`](http://www.macincloud.com/)）。然而，这些服务会产生月费。当 Xamarin 编译您的 C#代码时，它会针对 Mono 框架的一个特殊子集进行编译。

Mono 由微软赞助，是.NET Framework 的开源实现。这是基于**C#**和**公共语言运行时**的 ECMA 标准。有关 Mono 框架的更多信息，请查看[`www.mono-project.com/`](http://www.mono-project.com/)。

特别是针对 iOS，这个特殊子集包括允许访问 iOS 平台特定功能的库。Xamarin.iOS 编译器将接受您的 C#代码并将其编译成一种称为 ECMA CIL 的中间语言。然后，这个**通用中间语言**（**CIL**）会再次编译成 iPhone 或 iPad 可以运行的本地 iOS 代码。然后您还可以将其部署到模拟器进行测试。

现在，您可能会想为什么需要 Mac 来编译您的应用程序？为什么不能在 Visual Studio 内部完成所有操作？嗯，这是由于苹果对 iOS 内核生成代码的能力施加了（相当巧妙的）限制。它根本不允许这种情况发生。正如您所知道的（这是极其简化的解释），当您的 C#源代码编译进行测试时，它被编译成中间语言。**即时**（**JIT**）编译器然后将中间语言编译成适合您所针对的架构的汇编代码。由于 iOS 内核不允许 JIT 编译器进行按需编译，代码是使用**提前编译**（**AOT**）编译进行静态编译的。

要查看 Xamarin.iOS 的限制，请参阅以下链接：

[`developer.xamarin.com/guides/ios/advanced_topics/limitations/`](https://developer.xamarin.com/guides/ios/advanced_topics/limitations/) 查看 Xamarin.iOS、Xamarin.Mac 和 Xamarin.Android 中可用程序集的列表，请参阅以下支持文档：

[`developer.xamarin.com/guides/cross-platform/advanced/available-assemblies/.`](https://developer.xamarin.com/guides/cross-platform/advanced/available-assemblies/)

这背后的技术非常令人印象深刻。难怪微软收购了 Xamarin 并将其作为 Visual Studio 的一部分。为跨平台开发提供开发者这样一系列选择正是微软的目标：赋予开发者创造世界一流应用程序的能力。

# 准备工作

在本教程中，我们将介绍如何在运行 Visual Studio 2017 的 Windows PC 上安装 Xamarin。Xamarin 可以作为工作负载的一部分在安装 Visual Studio 2017 时安装。现在，让我们假设 Xamarin 尚未安装，并且您需要在安装 Visual Studio 后立即进行安装。转到 Visual Studio 网站[`www.visualstudio.com/`](https://www.visualstudio.com/)，并下载您安装的 Visual Studio 版本的安装程序。

您还可以在 Visual Studio 2017 的“新建项目”对话框屏幕上运行安装程序。如果您折叠已安装的模板，您将看到一个允许您打开 Visual Studio 安装程序的部分。

您还需要安装 Xcode，这是苹果的开发环境。您可以从 Mac App Store 免费下载。

请注意，您需要有 iTunes 登录才能下载 Xcode 并完成 Mac 的设置。如果您有 Mac，那么您很可能也有 iTunes 登录。

# 如何操作...

1.  双击从 Visual Studio 网站下载的安装程序。您将看到显示您的 Visual Studio 2017 版本，并且会出现一个“修改”按钮。点击“修改”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_01.png)

1.  这将显示可用的工作负载。在“移动和游戏”部分下，确保选择“使用.NET 进行移动开发”。然后，点击右下角的“修改”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_02.png)

1.  如果我们想要使用 Xamarin 来针对 iOS 应用程序，还有第二步需要采取。我们必须在 Mac 上安装所需的软件。在 Mac 上访问 Xamarin 的网站。网址是[`www.xamarin.com/`](https://www.xamarin.com/)。点击“产品”下拉菜单，从列表中选择 Xamarin 平台：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_03.png)

1.  您还可以通过访问[`www.xamarin.com/platform`](https://www.xamarin.com/platform)来访问所需的页面。单击“立即免费下载”按钮将在您的 Mac 上安装一个名为**Xamarin Studio Community**的东西。您需要知道的是，当在 Mac 上安装时，Xamarin Studio 无法创建 Windows 应用程序。它只允许您在 Mac 上创建 iOS 和 Android 应用程序。除了 Xamarin Studio，您还将获得 Xamarin Mac 代理（以前称为 Xamarin 构建主机）。这是一个必需的组件，以便您可以将您的 PC 链接到 Mac，以构建您的 iOS 应用程序。最后，PC 和 Mac 还必须能够通过网络相互连接（稍后会详细介绍）。

1.  在 Mac 上下载安装程序后，安装过程很简单。您会注意到在安装屏幕上有一些选项可供选择：Xamarin.Android、Xamarin.iOS、Xamarin.Mac 和 Xamarin Workbooks & Inspector。如果您想要以 Android 作为平台，您将安装 Xamarin.Android。要针对 iOS（iPhone 或 iPad），您需要选择 Xamarin.iOS。要创建完全本机的 Mac 应用程序，您必须选择 Xamarin.Mac。最后，Xamarin Workbooks & Inspector 为开发人员提供了一个与应用程序调试集成的交互式 C#控制台，以帮助开发人员检查运行中的应用程序。目前，我们只对 Xamarin.iOS 感兴趣。只需按照屏幕提示完成安装。根据您的选择，安装程序将下载所需的依赖项并将其安装在您的 Mac 上。根据您的互联网连接，您可能想去喝杯咖啡：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_04.png)

1.  最后，如果您尚未从 Mac App Store 安装 Xcode，请在继续之前立即这样做：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_05.png)

# 它是如何工作的...

我们之前安装 Xamarin 时所采取的步骤将使我们能够在开发跨平台时针对 Mac、iOS 和 Android（如果我们选择了 Xamarin.Android）平台进行开发。以前（在 Visual Studio 2015 之前），开发人员必须学习一个新的集成开发环境，以便提升自己的技能，以创建其他平台的应用程序。就我个人而言，我发现 Xcode（用于创建本机 iOS 和 Mac 应用程序的苹果开发人员集成开发环境）有点学习曲线。这不是因为它太复杂，而是因为它显然与我在 Visual Studio 中习惯的方式不同。如果您真的想学习另一种编程语言，并且想要选择 Xcode 的路线，请看看 Swift。这是一种出色的语言，我发现它比 Objective-C 更容易与 C#相关联。

然而，如果您宁愿坚持您所知道并且熟悉的内容，那么 Xamarin 是您开发跨平台应用程序的最佳选择。您也不必去购买 MacBook 来编译您的应用程序。当您想要开始为 iOS 和 Mac 开发时，Mac mini 已经足够了。这是对您的开发工具集的一种投资，将使您受益匪浅。作为开发人员，您还可以选择云选项（例如 MacinCloud）。使用 Xamarin，您可以坚持使用 C#并在您熟悉的环境中开发。

开发人员还有第三种最终选择，这是我们将在本章的最后一个配方中进行讨论的。本配方中的步骤是用于在 Windows PC 上创建应用程序并在 Mac 或 MacinCloud 解决方案上编译它们的情况。

# 使用 Apache Cordova 创建移动应用程序

使用 Apache Cordova 创建移动应用程序一点也不复杂。如果您熟悉 Web 开发，那么这对您来说会感觉非常自然。对于那些以前没有开发过 Web 应用程序的人来说，这将帮助您熟悉这个过程。这是因为 Cordova 的本质是一个 Web 应用程序。您引用诸如 JS 文件和 CSS 文件之类的文件，并且您可以在浏览器中调试`index.html`文件。

Cordova 应用程序为您提供了针对 iOS、Android 或 Windows 应用程序的灵活性。这个教程将演示一个简单的应用程序，当用户在应用程序中点击按钮时，它会显示当前日期。

# 准备工作

您需要在 Visual Studio 2017 安装过程中安装 JavaScript 工作负载。现在，让我们假设您在安装 Visual Studio 2017 时没有安装它，现在需要再次运行安装程序。

您还可以在 Visual Studio 2017 的新项目对话框屏幕中运行安装程序。如果折叠已安装的模板，您将看到一个允许您打开 Visual Studio 安装程序的部分。

转到 Visual Studio 网站[`www.visualstudio.com/`](https://www.visualstudio.com/)，并下载您安装的 Visual Studio 版本的安装程序。还要注意，您需要在计算机上安装 Google Chrome，以便启动 Cordova 应用程序模拟器。

# 如何做到这一点...

1.  双击从 Visual Studio 网站下载的安装程序。这将启动安装程序，并列出安装在您的计算机上的 Visual Studio 2017 版本，并显示一个修改按钮。点击修改按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_06.png)

1.  从“移动和游戏”组中，选择 JavaScript 工作负载的移动开发。然后，点击修改按钮。根据您的具体要求，可能会安装其他组件，例如**Android SDK**和**Google Android 模拟器**的支持：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_07.png)

1.  Apache Cordova 使用诸如 HTML、CSS 和 JavaScript 之类的 Web 技术来构建可在 Android、iOS 和 Windows 设备上运行的移动应用程序。从 Visual Studio 创建一个新应用程序，并从其他语言模板中选择 JavaScript。然后选择空白应用程序（Apache Cordova）模板。这只是一个使用 Apache Cordova 构建 Android、iOS 和**通用 Windows 平台**（**UWP**）的空白项目。我只是把我的应用叫做 MyCordovaApp。

1.  一旦 Visual Studio 创建了您的应用程序，您会注意到它有一个非常特定的文件夹结构：

+   `merges`：展开`merges`文件夹，您会注意到有三个名为`android`、`ios`和`windows`的子文件夹。开发人员可以使用这些文件夹根据他们正在针对的移动平台提供不同的内容。

+   `www`：这是您的大部分开发将发生的地方。`index.html`文件将成为 Cordova 应用程序的主要入口点。当启动您的移动应用程序时，Cordova 将查找这个索引文件并首先加载它。您还会注意到`www`文件夹下面有子文件夹。把它们想象成一个常规的 Web 应用程序文件夹结构，因为它们确实就是。`css`子文件夹将包含您需要使用的任何样式表。

您需要在移动应用程序中使用的任何图像都将存储在`images`子文件夹中。最后，您将在`scripts`子文件夹中添加任何移动（Web）应用程序使用的 JavaScript 文件。如果展开`scripts`子文件夹，您会注意到一个名为`platformOverrides.js`的 JavaScript 文件。这与`merges`文件夹一起使用，根据您正在针对的移动平台提供特定的 JavaScript 代码。

+   `res`：`res`文件夹将用于存储可能被不同原生移动应用程序使用的非 Web 应用程序资源。这些资源可以是启动画面、图片、图标、签名证书等等：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_08.png)

您还会注意到几个配置文件。这些是`bower.json`、`build.json`、`config.xml`和`package.json`。虽然我不会详细介绍这些配置文件中的每一个，但我想简要提一下`config.xml`和`package.json`文件。在撰写本书时，`package.json`文件目前未被 Cordova 使用。它旨在最终取代`config.xml`文件。目前，`config.xml`文件包含特定于您的移动应用程序的设置。双击此文件以查看 Cordova 应用程序的自定义编辑器。自定义编辑器通过提供一个标准的 Windows 表单，避免了直接编辑 XML 文件的复杂性，您可以在其中输入特定于应用程序的设置。作为开发人员，您可以使用的设置包括应用程序名称、作者名称、应用程序描述、设备方向、插件配置等等。

非常重要的是，不要删除`config.xml`文件。这样做将破坏您的解决方案，Cordova SDK 将无法构建和部署您的移动应用程序。

1.  此时，您可以从调试下拉菜单中选择一个设备并运行您的移动应用程序。如果您必须选择在浏览器中模拟 - Nexus 7（平板电脑），Visual Studio 将启动 Google Chrome 并显示默认的 Cordova 应用程序。这是每个 Cordova 应用程序的默认设置，实际上并不包含任何功能。它只是让您知道您的 Cordova 应用程序已经正确启动。不过有趣的是，您会看到一个新的选项卡在 Visual Studio 中打开，同时您的模拟器被启动。它被称为 Cordova 插件模拟，并默认为地理位置插件。这允许开发人员与插件进行交互，并在应用程序在模拟器中运行时触发特定事件。向您的 Cordova 应用程序添加新插件将在 Cordova 插件模拟中公开额外的窗格：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_09.png)

1.  接下来，将 jQuery.mobile NuGet 包添加到您的解决方案中。NuGet 将会向您的解决方案安装 jQuery.1.8.0 和 jquery.mobile.1.4.5。在撰写本书时，建议不将 jQuery.1.8.0 升级到最新版本，因为存在兼容性原因：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_10.png)

1.  在您的解决方案中，NuGet 将向您的项目的`Scripts`文件夹添加几个 JS 文件。将所有这些 JS 文件拖到您的`www/scripts`文件夹中。对于项目的`Content`文件夹也是一样。将所有 CSS 文件和`images`子文件夹拖到`www/css`文件夹中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_11.png)

1.  返回并打开您的`index.html`文件。您将在`<body></body>`标签之间看到以下内容：

```cs
        <div class="app">
          <h1>Apache Cordova</h1>
          <div id="deviceready" class="blink">
            <p class="event listening">Connecting to Device</p>
            <p class="event received">Device is Ready</p>
          </div>
        </div>

```

这是模板添加的默认样板代码，我们将不使用它。将其替换为以下代码，并在其他脚本引用的底部部分添加`<script src="img/jquery-1.8.0.min.js"></script>`和`<script src="img/jquery.mobile-1.4.5.min.js"></script>`。

请注意，您的 JS 文件版本可能与之前引用的版本不同。

完成后，您的`<body></body>`部分应如下所示：

```cs
        <body>
          <div role="main" class="ui-content">
            <form>
              <label id="current-date">The date is:</label>
              <button id="get-date-btn" data-role="button" 
                data-icon="search">
                Get Current Date</button>
            </form>
          </div>
          <script src="img/jquery-1.8.0.min.js"></script>
          <script src="img/jquery.mobile-1.4.5.min.js"></script>
          <script src="img/cordova.js"></script>
          <script type="text/javascript" src="img/cordova.js"></script>
          <script type="text/javascript" src=
            "scripts/platformOverrides.js"></script>
          <script type="text/javascript" src="img/index.js"></script>
        </body>

```

1.  然后，在`<head></head>`标签之间，添加上述`<link rel="stylesheet" href="css/jquery.mobile-1.4.5.min.css" />`样式引用，放在现有的`<link rel="stylesheet" type="text/css" href="css/index.css">`引用之上。

请注意，您的 CSS 文件版本可能与之前引用的版本不同。

完成后，您的代码应该类似于以下内容：

```cs
        <head>
          <!--
            Meta references omitted for brevity
          -->
          <link href="css/jquery.mobile-1.4.5.min.css" rel="stylesheet" />
          <link rel="stylesheet" type="text/css" href="css/index.css">
          <title>MyCordovaApp</title>
        </head>

```

1.  您的应用程序现在包括所需的 jQuery 库，这将使您的移动应用程序移动和触摸优化。您的移动应用程序现在也对其将显示在的设备具有响应性。现在我们需要为应用程序添加一些基本样式。打开`index.html`文件中`<head></head>`部分引用的`index.css`文件。这应该在`www/css/index.css`中。用以下代码替换内容。`#get-date-btn`只是引用我们表单上的按钮，并将字体大小设置为 22 像素。`form`被设计为在底部包含 1 像素宽的实线边框：

```cs
        form {
          border-bottom: 1px solid #ddd;
          padding-bottom: 5px;
        }

        #get-date-btn {
          font-size: 22px;
        }

```

1.  现在我们需要为用户点击“获取当前日期”按钮时添加一个点击事件。为此，打开位于`www/scripts/index.js`的`index.js`文件。找到`onDeviceReady()`方法，并修改代码如下：

```cs
        function onDeviceReady() {
          // Handle the Cordova pause and resume events
          document.addEventListener( 'pause', onPause.bind(
            this ), false );
          document.addEventListener( 'resume', onResume.bind(
            this ), false );

          $('#get-date-btn').click(getCurrentDate);
        };

```

1.  将此代码视为`get-date-btn`按钮的事件处理程序。实际上，它正在向按钮添加一个点击监听器，每当用户点击按钮时，它将调用`getCurrentDate`函数。现在可能是时候提到包含`onDeviceReady()`函数的`(function () { ... })();`函数了。这被称为**匿名自调用函数**，实际上只是您可以将其视为表单加载事件。您会注意到它为`onDeviceReady()`方法添加了一个事件处理程序。

1.  最后，将`getCurrentDate()`函数添加到`index.js`文件中。

为了本教程的目的，我将保持简单，并将`getCurrentDate()`函数添加到`index.js`文件中，因为代码并不是非常复杂。对于更复杂的代码，最好创建一个单独的 JS 文件，并在`index.html`页面中引用该 JS 文件（在`<body></body>`部分的底部）以及其他 JS 文件引用。

`getCurrentDate()`函数并不特别。它只是获取日期并将其格式化为`yyyy/MM/dd`格式，并在`index.html`页面的标签中显示它。您的函数应该如下所示：

```cs
        function getCurrentDate()
        {
          var d = new Date();
          var day = d.getDate();
          var month = d.getMonth();
          var year = d.getFullYear();
          $('#current-date').text("The date is: " + year + "/"
            + month + "/" + day);
        }

```

# 它是如何工作的...

您现在可以开始调试您的应用程序。让我们在 Visual Studio 中选择不同的模拟器。选择在浏览器中模拟 - LG G5 并按*F5*：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_12.png)

Chrome 将启动并显示您的 Cordova 应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_13.png)

单击“获取当前日期”按钮，当前日期将显示在您刚刚单击的按钮上方：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_14.png)

当您的模拟器打开时，打开您添加了`getCurrentDate()`函数的`index.js`文件，并在读取`$('#current-date').text("The date is: " + year + "/" + month + "/" + day);`的行上设置断点。然后再次单击“获取当前日期”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_15.png)

您会注意到您的断点被触发，现在您可以逐步检查变量并调试您的应用程序，就像您习惯做的那样。您甚至可以设置条件断点。这简直太棒了。

使用 Cordova 开发应用程序还有很多要学习的。Web 开发人员会发现这个过程很熟悉，并且应该很容易掌握。现在您可以将此应用程序在任何平台上运行，因为它完全跨平台。接下来，您可以尝试使用其中一个可用的 Android 模拟器来运行您的 Cordova 应用程序。尝试一下这个示例，并添加一些更多的功能代码。尝试访问 Web 服务以检索值，或者尝试玩一下样式。

能够使用 Visual Studio 从单个解决方案针对不同的移动设备，使开发人员有自由进行实验，并找到最适合他们和他们开发风格的解决方案。Cordova 站出来为那些不使用 Xamarin 等解决方案的开发人员提供了一个奇妙的解决方案。

# 使用 Xamarin.Forms 和 Visual Studio for Mac 创建 iOS 应用程序

许多开发人员想要尝试编写 iOS 应用程序。一直以来的一个大缺点是需要学习一种新的编程语言和一个新的集成开发环境。对于一些人来说，这可能不是问题，因为他们想要学习新的东西。但对于许多.NET 开发人员来说，能够坚持使用他们熟悉的集成开发环境和编程语言是非常有力量的。这正是 Xamarin.Forms 和 Visual Studio 所实现的。

请注意，我在这里没有考虑 Xamarin.Android。我纯粹专注于编写原生的 iOS 和 Mac 应用程序。

Xamarin 为.NET 开发人员提供了使用 Visual Studio 编写跨平台应用程序的能力，而无需为每个平台单独创建代码库。因此，您可以为应用程序拥有一个单一的代码库，该代码库将在 Windows、iOS/macOS 和 Android 上运行。如果您想要开始开发原生的 iOS/macOS 应用程序，您基本上有四个可行的选择（在我看来）。它们如下：

+   购买一台 Mac 并自学 Xcode、Swift 和/或 Objective-C。

+   购买一台 Mac 并安装 Parallels，在其中您可以安装 Windows、Visual Studio 和其他基于 Windows 的软件（Mac 不仅仅用于开发）。您可以在我几年前创建的**Developer Community** YouTube 频道上观看一个视频（[`www.youtube.com/developercommunity`](https://www.youtube.com/developercommunity)）。在那个视频中，我向您展示了如何使用 Parallels 在 Mac 上安装 Visual Studio 2013。

+   购买一台 Mac 并下载**Visual Studio for Mac**（目前仍处于预览阶段），然后在 Mac 上安装该软件（Mac 专门用于开发 Android 和 iOS/macOS 应用程序）。

+   购买一台 Mac 并使用它来编译在运行 Visual Studio 的 Windows PC 上开发的 iOS/macOS 应用程序。如果您需要创建仍然可以针对基于 Windows 的平台以及 Android 和 iOS/macOS 的应用程序，那么可以这样做。

如果您要使用**Visual Studio for Mac**和 Xamarin.Forms，那么您将无法在 macOS 上创建 Xamarin.Forms 项目，因为这些项目无法在 macOS 上构建。还要注意的是，我没有在这里考虑 MacinCloud，因为在开发过程中的某个阶段，我认为拥有一台实体的苹果 Mac 设备是非常有益的。

从前面列出的要点可以清楚地看出，您需要一台 Mac。虽然在 Windows PC 上安装 Visual Studio 并在本地网络上连接到 Xamarin Mac 代理是完全可能的，但当您需要尝试远程访问 Mac 时（例如从您的工作办公室），这可能会有些不便。理论上，这应该是可能的，但您需要做一些工作才能使这一切正常运行。首先，您可能需要在路由器上添加某种端口转发，以允许远程连接到您的 Mac。您还需要为您的 Mac 分配一个静态 IP 地址（甚至为您的路由器购买一个静态 IP 地址），这样，如果在您远程工作时发生断电重启，您仍然能够访问您的 Mac 进行 Visual Studio 构建。

在 Mac 上安装 Parallels 非常方便，当您需要使用其他基于 Windows 的软件时，它将非常有用。如果您（像我一样）将 Mac 专门用于开发目的，那么 Parallels 可能不是一个可行的解决方案。这就留下了**Visual Studio for Mac**，如果您只计划开发 iOS/macOS 和 Android 应用程序，那么这是一个很好的选择。

要下载 Visual Studio for Mac，请前往[`developer.xamarin.com/visual-studio-mac/`](https://developer.xamarin.com/visual-studio-mac/)并单击下载链接。安装过程与本章第一个配方中的安装过程有些类似。不同之处在于实际的 Visual Studio 应用程序将安装在 Mac 上，而不是在同一网络上的 Windows PC 上。

# 准备工作

下载 Visual Studio for Mac 后，开始安装过程。这与第一个配方中概述的过程非常相似。完成可能需要一些时间，所以再次，去喝杯咖啡。使用 Visual Studio for Mac 创建应用程序对于从 Visual Studio for Windows 转到.NET 开发人员来说是一种熟悉的体验。

Visual Studio for Mac 的核心是用于重构和智能感知的 Roslyn 编译器。构建引擎是 MSBuild，调试器引擎与 Xamarin 和.NET Core 应用程序相同。Xamarin 开发和 Visual Studio for Mac 的软件要求如下：

+   您需要运行 OS X El Capitan（10.11）或 macOS Sierra 的 Mac。

+   需要 iOS 10 SDK，该 SDK 随 Xcode 8 一起提供。只要您拥有有效的 iTunes 帐户，就可以免费下载 Xcode。

+   Visual Studio for Mac 需要.NET Core，可以按照[`www.microsoft.com/net/core#macos`](https://www.microsoft.com/net/core#macos)中概述的步骤进行下载。您必须完成列出的所有步骤，以确保.NET Core 正确安装。当您在那里时，请注意观看 Kendra Havens 的一些 Channel 9 视频，了解如何开始使用.NET Core，网址是[`channel9.msdn.com/`](https://channel9.msdn.com/)。顺便说一句，还可以看看 Channel 9 上其他精彩的内容。

+   如果您计划将应用程序提交到 Apple 应用商店，则需要购买开发者许可证，目前价格为每年 99 美元。但是，您可以在不购买开发者许可证的情况下开发您的应用程序。

请注意，如果您计划在 Xamarin Studio 旁边安装 Visual Studio for Mac，则需要知道 Visual Studio for Mac 需要 Mono 4.8。安装 Xamarin Studio 将会将 Mono 降级到旧版本。为了解决这个问题，您需要在 Xamarin Studio 更新屏幕上选择退出 Mono 4.6 的选择。

有了这个相当详细的要求清单，让我们准备好创建一个 iOS 应用程序。

# 如何做...

1.  启动 Visual Studio for Mac，并使用您的 Microsoft 帐户详细信息登录。您会注意到“入门”部分，其中列出了许多有用的文章，帮助开发人员开始使用 Visual Studio for Mac：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_16-1.png)

1.  接下来，点击“新建项目...”，并在多平台应用程序模板中的 Xamarin.Forms 组中选择 Forms App 项目。然后，点击“下一步”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_17-1.png)

1.  然后，我们需要为我们的应用程序命名和添加组织标识符。我只是将我的应用程序命名为`HelloWorld`，然后在“目标平台”下只选择了 iOS。点击“下一步”继续：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_18-2.png)

1.  最后，决定是否要配置项目以使用 Git 进行版本控制和 Xamarin Test Cloud。当您配置好所需的内容后，点击“创建”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_19-1.png)

1.  创建项目后，您会注意到可以通过单击“调试”按钮旁边的向下箭头来选择要模拟的设备：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_20.png)

1.  这将列出不同的模拟器可供您使用，以及连接到您的 Mac 的任何设备（在本例中是我的 iPhone）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_21.png)

1.  点击“运行”按钮将启动所选设备的模拟器，并显示创建 Xamarin.Forms iOS 应用程序时为您创建的默认应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_22.png)

1.  模拟器中的应用程序是完全可用的，您可以与其交互以了解模拟器的工作原理。如前所述，如果您的 Mac 上连接了 iOS 设备，甚至可以在设备上启动应用程序进行测试。例如，点击“关于”选项卡将显示“关于”页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_23.png)

1.  在 Visual Studio for Mac 中点击停止按钮，返回到您的解决方案。展开`ViewModels`和`Views`文件夹。您会看到一个非常熟悉的结构：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_24.png)

1.  在`ViewModels`文件夹中，打开`AboutViewModel.cs`文件。在构造函数`AboutViewModel()`中，您将看到以下代码：

```cs
        public AboutViewModel()
        {
          Title = "About";
          OpenWebCommand = new Command(() => Device.OpenUri(new 
            Uri("https://xamarin.com/platform")));
        }

```

1.  现在，为了说明 C#的使用，将此处的代码更改为以下代码清单的样子。您注意到了第一行代码吗？`var titleText =`后面的部分是一个插值字符串`$"Hello World - The date is {DateTime.Now.ToString("MMMM dd yyyy")}";`。插值字符串是在 C# 6.0 中引入的。点击播放按钮在模拟器中启动应用程序：

```cs
        public AboutViewModel()
        {
          var titleText = $"Hello World - The date is {
            DateTime.Now.ToString("MMMM dd yyyy")}";
          Title = titleText;
          OpenWebCommand = new Command(() => Device.OpenUri(new 
            Uri("https://xamarin.com/platform")));
        }

```

1.  现在，再次点击“关于”选项卡，查看标题。标题已更改为显示“Hello World”和当前日期：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_14_25.png)

# 工作原理...

好吧，我将首先承认，我们编写的代码并没有什么了不起的。实际上，我们基本上是在现有的应用程序上进行了一些修改，只是修改了一点代码来显示“Hello World”和当前日期。然而，需要记住的一件事是，我们编写了 C#代码并将其编译为本机 iOS 应用程序。

还有很多东西要学习。我们甚至还没有涉及使用 Visual Studio for Mac、Xamarin.Forms 和跨平台 C#应用程序现在提供的所有内容。Xamarin 有非常好的文档，将在您使用 Xamarin 开发应用程序的新途径时为您提供帮助。一个很好的案例研究是 Tasky 案例研究，可以在[`developer.xamarin.com/guides/cross-platform/application_fundamentals/building_cross_platform_applications/case_study-tasky/`](https://developer.xamarin.com/guides/cross-platform/application_fundamentals/building_cross_platform_applications/case_study-tasky/)找到。这将让您对使用 Xamarin 开发跨平台应用程序涉及的内容有一个很好的了解。

为什么不试着再玩一下我们刚刚创建的应用程序呢？看看有什么可能性，以及在处理数据库逻辑和读取用户输入方面有什么不同。Visual Studio for Mac 为开发人员打开了一个新世界，使得开发本机 iOS 应用程序比以往任何时候都更容易。
