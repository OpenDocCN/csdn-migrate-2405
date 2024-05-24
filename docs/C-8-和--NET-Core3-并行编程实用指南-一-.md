# C#8 和 .NET Core3 并行编程实用指南（一）

> 原文：[`zh.annas-archive.org/md5/BE48315910DEF416E754F7470D0341EA`](https://zh.annas-archive.org/md5/BE48315910DEF416E754F7470D0341EA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Packt 几乎一年前首次联系我撰写这本书。这是一段漫长的旅程，有时比我预期的更艰难，我学到了很多。你现在拥有的这本书是许多漫长日子的结晶，我很自豪能最终呈现它。

撰写这本关于 C#的书对我意义重大，因为我一直梦想着写关于我职业生涯起步的语言。自从首次推出以来，C#确实有了长足的发展。.NET Core 实际上增强了 C#在开发者社区中的力量和声誉。

为了使这本书对广大读者有意义，我们将涵盖经典线程模型和**任务并行库**（**TPL**），并使用代码来解释它们。我们将首先研究使编写多线程代码成为可能的操作系统的基本概念。然后我们将仔细研究经典线程和 TPL 之间的区别。

在这本书中，我特别注意以现代最佳编程实践的背景来处理并行编程。示例被保持简短和简单，以便于您的理解。这些章节的写作方式使得即使您对它们没有太多先前的了解，也很容易学习这些主题。

希望您阅读这本书时能像我写作时一样享受。

# 这本书适合谁

这本书适用于希望学习多线程和并行编程概念，并希望在使用.NET Core 构建的企业应用程序中使用它们的 C#程序员。它还适用于希望了解现代硬件如何与并行编程配合的学生和专业人士。

假设您已经对 C#编程语言有一定了解，并且对操作系统的工作原理有一些基本知识。

# 这本书涵盖了什么

第一章，*并行编程简介*，介绍了多线程和并行编程的重要概念。本章包括操作系统如何发展以支持现代并行编程构造的内容。

第二章，*任务并行性*，演示了如何将程序分解为任务，以有效利用 CPU 资源和实现高性能。

第三章，*实现数据并行性*，侧重于使用并行循环实现数据并行性。本章还涵盖了扩展方法，以帮助实现并行性，以及分区策略。

第四章，*使用 PLINQ*，解释了如何利用 PLINQ 支持。这包括查询排序和取消查询，以及使用 PLINQ 的陷阱。

第五章，*同步原语*，介绍了 C#中用于处理多线程代码中共享资源的同步构造。

第六章，*使用并发集合*，描述了如何利用.NET Core 中可用的并发集合，而无需担心手动同步编码的工作。

第七章，*使用延迟初始化提高性能*，探讨了如何实现利用延迟模式的内置构造。

第八章，*异步编程简介*，探讨了如何在较早版本的.NET 中编写异步代码。

第九章，*异步、等待和基于任务的异步编程基础*，介绍了如何利用.NET Core 中的新构造来实现异步代码。

第十章，*使用 Visual Studio 调试任务*，着重介绍了 Visual Studio 2019 中可用的各种工具，使并行任务的调试更加容易。

第十一章，*编写并行和异步代码的单元测试用例*，介绍了在 Visual Studio 和.NET Core 中编写单元测试用例的各种方法。

第十二章，*ASP.NET Core 中的 IIS 和 Kestrel*，介绍了 IIS 和 Kestrel 的概念。本章还介绍了对异步流的支持。

第十三章，*并行编程中的模式*，解释了 C#语言中已经实现的各种模式。这还包括自定义模式实现。

第十四章，*分布式内存管理*，探讨了内存在分布式程序中的共享方式。

# 充分利用本书

您需要在系统上安装 Visual Studio 2019 以及.NET Core 3.1。同时也建议具备 C#和操作系统概念的基本知识。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](https://www.packtpub.com/support)注册并直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)登录或注册。

1.  选择支持选项卡。

1.  点击代码下载。

1.  在搜索框中输入书名并按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的解压缩或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3`](https://github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码包，可以在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上查看！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`static.packt-cdn.com/downloads/9781789132410_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781789132410_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```cs
private static void PrintNumber10Times()
{
   for (int i = 0; i < 10; i++)
     {
     Console.Write(1);
     }
   Console.WriteLine();
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cs
private static void PrintNumber10Times()
{
   for (int i = 0; i < 10; i++)
     {
     Console.Write(1);
     }
   Console.WriteLine();
}
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。这是一个例子：“与其自己找到最佳线程数，

我们可以把它留给**公共语言运行时**。

警告或重要说明会出现在这样的形式中。

提示和技巧会以这种形式出现。


# 第一部分：线程、多任务和异步性的基础

在本节中，您将熟悉线程、多任务和异步编程的概念。

本节包括以下章节：

+   第一章，*并行编程简介*

+   第二章，*任务并行性*

+   第三章，*实现数据并行性*

+   第四章，*使用 PLINQ*


# 第一章：并行编程简介

自.NET 开始就支持并行编程，并自.NET 框架 4.0 引入**任务并行库**（**TPL**）以来，它已经获得了牢固的基础。

多线程是并行编程的一个子集，也是编程中最不被理解的方面之一；许多新开发人员很难理解。C#自诞生以来已经发生了很大的变化。它不仅对多线程有很强的支持，还对异步编程有很强的支持。C#的多线程可以追溯到 C# 1.0。C#主要是同步的，但从 C# 5.0 开始增加了强大的异步支持，使其成为应用程序程序员的首选。而多线程只涉及如何在进程内并行化，而并行编程还涉及进程间通信的场景。

在 TPL 引入之前，我们依赖于`Thread`、`BackgroundWorker`和`ThreadPool`来提供多线程能力。在 C# v1.0 时，它依赖于线程来分割工作并释放**用户界面**（**UI**），从而使用户能够开发响应式应用程序。这个模型现在被称为经典线程。随着时间的推移，这个模型为另一个编程模型让路，称为 TPL，它依赖于任务，并且在内部仍然使用线程。

在本章中，我们将学习各种概念，这些概念将帮助您从头开始学习编写多线程代码。

我们将涵盖以下主题：

+   多核计算的基本概念，从介绍与**操作系统**（**OS**）相关的概念和进程开始。

+   线程以及多线程和多任务之间的区别

+   编写并行代码的优缺点以及并行编程有用的场景

# 技术要求

本书中演示的所有示例都是在使用 C# 8 的 Visual Studio 2019 中创建的。所有源代码都可以在 GitHub 上找到：[`github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter01`](https://github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter01)。

# 为多核计算做准备

在本节中，我们将介绍操作系统的核心概念，从进程开始，线程所在和运行的地方。然后，我们将考虑随着硬件能力的引入，多任务处理是如何演变的，这使得并行编程成为可能。之后，我们将尝试理解使用代码创建线程的不同方式。

# 进程

通俗地说，*进程*一词指的是正在执行的程序。然而，在操作系统方面，进程是内存中的地址空间。无论是 Windows、Web 还是移动应用程序，每个应用程序都需要进程来运行。进程为程序提供安全性，防止其他在同一系统上运行的程序意外访问分配给另一个程序的数据。它们还提供隔离，使得程序可以独立于其他程序和底层操作系统启动和停止。

# 有关操作系统的更多信息

应用程序的性能在很大程度上取决于硬件的质量和配置。这包括以下内容：

+   CPU 速度

+   RAM 的数量

+   硬盘速度（5400/7200 RPM）

+   磁盘类型，即 HDD 或 SSD

在过去的几十年里，我们已经看到了硬件技术的巨大飞跃。例如，微处理器过去只有一个核心，即一个**中央处理单元**（**CPU**）的芯片。到了世纪之交，我们看到了多核处理器的出现，这是具有两个或更多处理器的芯片，每个处理器都有自己的缓存。

# 多任务处理

多任务处理是指计算机系统同时运行多个进程（应用程序）的能力。系统可以运行的进程数量与系统中的核心数量成正比。因此，单核处理器一次只能运行一个任务，双核处理器一次可以运行两个任务，四核处理器一次可以运行四个任务。如果我们将 CPU 调度的概念加入其中，我们可以看到 CPU 通过基于 CPU 调度算法进行调度或切换来同时运行更多应用程序。

# 超线程

**超线程**（**HT**）技术是英特尔开发的专有技术，它改进了在 x86 处理器上执行的计算的并行化。它首次在 2002 年的至强服务器处理器中引入。HT 启用的单处理器芯片运行具有两个虚拟（逻辑）核心，并且能够同时执行两个任务。以下图表显示了单核和多核芯片之间的区别：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/0bf4dc71-2221-42f3-b90f-ffaccf0bbd82.png)

以下是一些处理器配置的示例以及它们可以执行的任务数量：

+   **单核芯片的单处理器**：一次一个任务

+   **HT 启用的单核芯片的单处理器**：一次两个任务

+   **双核芯片的单处理器**：一次两个任务

+   **HT 启用的双核芯片的单处理器**：一次四个任务

+   **四核芯片的单处理器**：一次四个任务

+   **HT 启用的四核芯片的单处理器**：一次八个任务

以下是 HT 启用的四核处理器系统的 CPU 资源监视器的屏幕截图。在右侧，您可以看到有八个可用的 CPU：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/47af0d87-7dcb-4f51-843d-dcba28bb0ab6.png)

您可能想知道，仅通过从单核处理器转换到多核处理器，您可以提高计算机的性能多少。在撰写本文时，大多数最快的超级计算机都是基于**多指令，多数据**（**MIMD**）架构构建的，这是迈克尔·J·弗林在 1966 年提出的计算机架构分类之一。

让我们试着理解这个分类。

# 弗林的分类

弗林根据并发指令（或控制）流和数据流的数量将计算机架构分为四类：

+   **单指令，单数据（SISD）**：在这种模型中，有一个单一的控制单元和一个单一的指令流。这些系统只能一次执行一个指令，没有任何并行处理。所有单核处理器机器都基于 SISD 架构。

+   **单指令，多数据（SIMD）**：在这种模型中，我们有一个单一的指令流和多个数据流。相同的指令流并行应用于多个数据流。这在猜测性方法的场景中很方便，其中我们有多个数据的多个算法，我们不知道哪一个会更快。它为所有算法提供相同的输入，并在多个处理器上并行运行它们。

+   **多指令，单数据（MISD）**：在这种模型中，多个指令在一个数据流上操作。因此，可以并行地在相同的数据源上应用多个操作。这通常用于容错和航天飞行控制计算机。

+   **多指令，多数据（MIMD）**：在这种模型中，正如名称所示，我们有多个指令流和多个数据流。因此，我们可以实现真正的并行，其中每个处理器可以在不同的数据流上运行不同的指令。如今，大多数计算机系统都使用这种架构。

现在我们已经介绍了基础知识，让我们把讨论转移到线程上。

# 线程

线程是进程内的执行单元。在任何时候，程序可能由一个或多个线程组成，以获得更好的性能。基于 GUI 的 Windows 应用程序，如传统的**Windows Forms**（**WinForms**）或**Windows Presentation Foundation**（**WPF**），都有一个专用线程来管理 UI 和处理用户操作。这个线程也被称为 UI 线程或**前台线程**。它拥有所有作为 UI 一部分创建的控件。

# 线程的类型

有两种不同类型的托管线程，即前台线程和后台线程。它们之间的区别如下：

+   **前台线程：**对应用程序的生命周期有直接影响。只要有前台线程存在，应用程序就会继续运行。

+   **后台线程：**对应用程序的生命周期没有影响。应用程序退出时，所有后台线程都会被终止。

一个应用程序可以包含任意数量的前台或后台线程。在活动状态下，前台线程保持应用程序运行；也就是说，应用程序的生命周期取决于前台线程。当最后一个前台线程停止或中止时，应用程序将完全停止。应用程序退出时，系统会停止所有后台线程。

# 公寓状态

理解线程的另一个重要方面是公寓状态。这是线程内部的一个区域，**组件对象模型**（**COM**）对象驻留在其中。

COM 是一个面向对象的系统，用于创建用户可以交互的二进制软件，并且是分布式和跨平台的。COM 已被用于创建 Microsoft OLE 和 ActiveX 技术。

你可能知道，所有的 Windows 窗体控件都是基于 COM 对象封装的。每当你创建一个.NET WinForms 应用程序时，实际上是在托管 COM 组件。线程公寓是应用程序进程内的一个独立区域，用于创建 COM 对象。以下图表展示了线程公寓和 COM 对象之间的关系：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/91fa5328-4ca2-4cde-8046-b3246100b68a.png)

正如你从前面的图表中所看到的，每个线程都有线程公寓，COM 对象驻留在其中。

一个线程可以属于两种公寓状态之一：

+   **单线程公寓**（**STA**）：底层 COM 对象只能通过单个线程访问

+   **多线程公寓**（**MTA**）：底层 COM 对象可以同时通过多个线程访问

以下列表突出了关于线程公寓状态的一些重要点：

+   进程可以有多个线程，可以是前台或后台。

+   每个线程可以有一个公寓，可以是 STA 或 MTA。

+   每个公寓都有一个并发模型，可以是单线程或多线程的。我们也可以通过编程方式改变线程状态。

+   一个应用程序可能有多个 STA，但最多只能有一个 MTA。

+   STA 应用程序的一个示例是 Windows 应用程序，MTA 应用程序的一个示例是 Web 应用程序。

+   COM 对象是在公寓中创建的。一个 COM 对象只能存在于一个线程公寓中，公寓不能共享。

通过在主方法上使用`STAThread`属性，可以强制应用程序以 STA 模式启动。以下是一个传统 WinForm 的`Main`方法的示例：

```cs
static class Program
{
    /// <summary>
    /// The main entry point for the application.
    /// </summary>
    [STAThread]
    static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new Form1());
    }
}
```

`STAThread`属性也存在于 WPF 中，但对用户隐藏。以下是编译后的`App.g.cs`类的代码，可以在 WPF 项目编译后的`obj/Debug`目录中找到：

```cs
/// <summary>
    /// App
    /// </summary>
    public partial class App : System.Windows.Application {

        /// <summary>
        /// InitializeComponent
        /// </summary>
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute(
         "PresentationBuildTasks", "4.0.0.0")]
        public void InitializeComponent() {

            #line 5 "..\..\App.xaml"
            this.StartupUri = new System.Uri("MainWindow.xaml", 
             System.UriKind.Relative);

            #line default
            #line hidden
        }

        /// <summary>
        /// Application Entry Point.
        /// </summary>
        [System.STAThreadAttribute()]
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute(
         "PresentationBuildTasks", "4.0.0.0")]
        public static void Main() {
            WpfApp1.App app = new WpfApp1.App();
            app.InitializeComponent();
            app.Run();
        }
    }
```

正如你所看到的，`Main`方法被`STAThread`属性修饰。

# 多线程

在.NET 中实现代码的并行执行是通过多线程实现的。一个进程（或应用程序）可以利用任意数量的线程，取决于其硬件能力。每个应用程序，包括控制台、传统的 WinForms、WPF，甚至 Web 应用程序，默认情况下都是由单个线程启动的。我们可以通过在需要时以编程方式创建更多线程来轻松实现多线程。

多线程通常使用称为**线程调度器**的调度组件来运行，该组件跟踪线程何时应该在进程内运行。创建的每个线程都被分配一个`System.Threading.ThreadPriority`，可以具有以下有效值之一。`Normal`是分配给任何线程的默认优先级：

+   `最高`

+   `AboveNormal`

+   `Normal`

+   `BelowNormal`

+   `Lowest`

在进程内运行的每个线程都根据线程优先级调度算法由操作系统分配一个时间片。每个操作系统可以有不同的运行线程的调度算法，因此在不同的操作系统中执行顺序可能会有所不同。这使得更难以排除线程错误。最常见的调度算法如下：

1.  找到具有最高优先级的线程并安排它们运行。

1.  如果有多个具有最高优先级的线程，则每个线程被分配固定的时间片段来执行。

1.  一旦最高优先级的线程执行完毕，低优先级线程开始被分配时间片，可以开始执行。

1.  如果创建了一个新的最高优先级线程，则低优先级线程将再次被推迟。

时间片切换是指在活动线程之间切换执行。它可以根据硬件配置而变化。单核处理器机器一次只能运行一个线程，因此线程调度器执行时间片切换。时间片的大小很大程度上取决于 CPU 的时钟速度，但在这种系统中仍然无法通过多线程获得很多性能提升。此外，上下文切换会带来性能开销。如果分配给线程的工作跨越多个时间片，那么线程需要在内存中切换进出。每次切换出时，它都需要捆绑和保存其状态（数据），并在切换回时重新加载。

**并发**是一个主要用于多核处理器的概念。多核处理器具有更多可用的 CPU，因此不同的线程可以同时在不同的 CPU 上运行。更多的处理器意味着更高的并发度。

程序中可以有多种方式创建线程。这些包括以下内容：

+   线程类

+   线程池类

+   `BackgroundWorker`类

+   异步委托

+   TPL

我们将在本书的过程中深入介绍异步委托和 TPL，但在本章中，我们将解释剩下的三种方法。

# 线程类

创建线程的最简单和最简单的方法是通过`Thread`类，该类定义在`System.Threading`命名空间中。这种方法自.NET 1.0 版本以来一直在使用，并且在.NET 核心中也可以使用。要创建一个线程，我们需要传递一个线程需要执行的方法。该方法可以是无参数或带参数的。框架提供了两个委托来包装这些函数：

+   `System.Threading.ThreadStart`

+   `System.Threading.ParameterizedThreadStart`

我们将通过示例学习这两个概念。在向您展示如何创建线程之前，我将尝试解释同步程序的工作原理。之后，我们将介绍多线程，以便了解异步执行的方式。创建线程的示例如下：

```cs
using System;
namespace Ch01
{
    class _1Synchronous
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Start Execution!!!");

            PrintNumber10Times();
            Console.WriteLine("Finish Execution");
            Console.ReadLine();
        }
        private static void PrintNumber10Times()
        {
            for (int i = 0; i < 10; i++)
            {
                Console.Write(1);
            }
            Console.WriteLine();
        }
    }
}
```

在上述代码中，一切都在主线程中运行。我们从`Main`方法中调用了`PrintNumber10Times`方法，由于`Main`方法是由主 GUI 线程调用的，代码是同步运行的。如果代码运行时间很长，这可能会导致无响应的行为，因为主线程在执行期间将会很忙。

代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/74b9065b-8199-44b6-85ed-09d87800ba86.png)

在以下时间表中，我们可以看到一切都发生在**主线程**中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/850babff-8666-46f4-b77e-93d4daf8b18e.png)

前面的图表显示了在`Main`线程上的顺序代码执行。

现在，我们可以通过创建一个线程来使程序成为多线程。主线程打印在`Main`方法中编写的语句：

```cs
using System;
namespace Ch01
{
    class _2ThreadStart
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Start Execution!!!");

            //Using Thread without parameter
            CreateThreadUsingThreadClassWithoutParameter();
            Console.WriteLine("Finish Execution");
            Console.ReadLine();
        }
        private static void CreateThreadUsingThreadClassWithoutParameter()
        {
            System.Threading.Thread thread;
            thread = new System.Threading.Thread(new 
             System.Threading.ThreadStart(PrintNumber10Times));
            thread.Start();
        }
        private static void PrintNumber10Times()
        {
            for (int i = 0; i < 10; i++)
            {
                Console.Write(1);
            }
            Console.WriteLine();
        }
    }
}            
```

在上述代码中，我们已经将`PrintNumber10Times()`的执行委托给了通过`Thread`类创建的新线程。`Main`方法中的`Console.WriteLine`语句仍然通过主线程执行，但`PrintNumber10Times`不是通过子线程调用的。

代码的输出如下**：**

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/4d9fdc64-b6d5-4c8d-bb76-34205f269081.png)

此过程的时间表如下。您可以看到`Console.WriteLine`在**主线程**上执行，而循环在**子线程**上执行：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/bf617bfc-229f-469d-896c-c5b883ffd3c0.png)

前面的图表是多线程执行的一个示例。

如果我们比较输出，我们可以看到程序在主线程中完成所有操作，然后开始打印数字 10 次。在这个例子中，操作非常小，因此以确定的方式工作。然而，如果在**完成执行**被打印之前，主线程中有耗时的语句，结果可能会有所不同。我们将在本章后面详细了解多线程的工作原理以及它与 CPU 速度和数字的关系，以充分理解这个概念。

以下是另一个示例，向您展示如何使用`System.Threading.ParameterizedThreadStart`委托将数据传递给线程：

```cs
using System;
namespace Ch01
{
    class _3ParameterizedThreadStart
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Start Execution!!!");
            //Using Thread with parameter
            CreateThreadUsingThreadClassWithParameter();
            Console.WriteLine("Finish Execution");
            Console.ReadLine();
        }
        private static void CreateThreadUsingThreadClassWithParameter()
        {
            System.Threading.Thread thread;
            thread = new System.Threading.Thread(new        
             System.Threading.ParameterizedThreadStart(PrintNumberNTimes));
            thread.Start(10);
        }
        private static void PrintNumberNTimes(object times)
        {
            int n = Convert.ToInt32(times);
            for (int i = 0; i < n; i++)
            {
                Console.Write(1);
            }
            Console.WriteLine();
        }
    }
}
```

上述代码的输出如下**：**

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/ca3f74e9-6fa1-47f9-9920-7544030afeb1.png)

使用`Thread`类有一些优点和缺点。让我们试着理解它们。

# 线程的优缺点

`Thread`类具有以下优点：

+   线程可用于释放主线程。

+   线程可用于将任务分解为可以并发执行的较小单元。

`Thread`类具有以下缺点：

+   使用更多线程，代码变得难以调试和维护。

+   线程创建会在内存和 CPU 资源方面对系统造成负担。

+   我们需要在工作方法内部进行异常处理，因为任何未处理的异常都可能导致程序崩溃。

# 线程池类

线程创建在内存和 CPU 资源方面是昂贵的操作。平均而言，每个线程消耗大约 1 MB 的内存和几百微秒的 CPU 时间。应用程序性能是一个相对的概念，因此通过创建大量线程不一定会提高性能。相反，创建大量线程有时可能会严重降低应用程序性能。我们应该始终根据目标系统的 CPU 负载，即系统上运行的其他程序，来创建一个最佳数量的线程。这是因为每个程序都会获得 CPU 的时间片，然后将其分配给应用程序内部的线程。如果创建了太多线程，它们可能无法在被换出内存之前完成任何有益的工作，以便将时间片给其他具有相似优先级的线程。

找到最佳线程数可能会很棘手，因为它可能因系统配置和同时在系统上运行的应用程序数量而异。在一个系统上可能是最佳数量的东西可能会对另一个系统产生负面影响。与其自己找到最佳线程数，不如将其留给**公共语言运行时**（**CLR**）。CLR 有一个算法来确定基于任何时间点的 CPU 负载的最佳数量。它维护一个线程池，称为`ThreadPool`。`ThreadPool`驻留在一个进程中，每个应用程序都有自己的线程池。线程池的优势在于它维护了一个最佳数量的线程，并将它们分配给一个任务。当工作完成时，线程将返回到池中，可以分配给下一个工作项，从而避免创建和销毁线程的成本。

以下是在`ThreadPool`中可以创建的不同框架内的最佳线程数列表：

+   .NET Framework 2.0 中每核 25 个

+   .NET Framework 3.5 中每核 250 个

+   在 32 位环境中的.NET Framework 4.0 中为 1,023

+   .NET Framework 4.0 及以后版本中每核 32,768 个，以及 64 位环境中的.NET core

在与投资银行合作时，我们遇到了一个场景，一个交易流程几乎需要 1,800 秒来同步预订近 1,000 笔交易。在尝试了各种最佳数量后，我们最终切换到`ThreadPool`并使流程多线程化。使用.NET Framework 2.0 版本，应用程序在接近 72 秒内完成。使用 3.5 版本，同一应用程序在几秒内完成。这是一个典型的例子，使用提供的框架而不是重新发明轮子。通过更新框架，您可以获得所需的性能提升。

我们可以通过调用`ThreadPool.QueueUserWorkItem`来通过`ThreadPool`创建一个线程，如下例所示。

这是我们想要并行调用的方法：

```cs
private static void PrintNumber10Times(object state)
{
    for (int i = 0; i < 10; i++)
    {
        Console.Write(1);
    }
    Console.WriteLine();
}
```

以下是我们如何使用`ThreadPool.QueueUserWorkItem`创建一个线程，同时传递`WaitCallback`委托：

```cs
private static void CreateThreadUsingThreadPool()
{
    ThreadPool.QueueUserWorkItem(new WaitCallback(PrintNumber10Times));
}
```

这是`Main`方法中的一个调用：

```cs
using System;
using System.Threading;

namespace Ch01
{
    class _4ThreadPool
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Start Execution!!!");
            CreateThreadUsingThreadPool();
            Console.WriteLine("Finish Execution");
            Console.ReadLine();
        }
    }
}
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/e4f970e1-5ed9-4167-8849-cdd81c5faf05.png)

每个线程池都维护最小和最大线程数。可以通过调用以下静态方法来修改这些值：

+   `ThreadPool.SetMinThreads`

+   `ThreadPool.SetMaxThreads`

通过`System.Threading`创建一个线程。`Thread`类不属于`ThreadPool`。

让我们看看使用`ThreadPool`类的优点和缺点以及何时避免使用它。

# 优点、缺点以及何时避免使用 ThreadPool

`ThreadPool`的优点如下：

+   线程可以用来释放主线程。

+   线程由 CLR 以最佳方式创建和维护。

`ThreadPool`的缺点如下：

+   随着线程数量的增加，代码变得难以调试和维护。

+   我们需要在工作方法内部进行异常处理，因为任何未处理的异常都可能导致程序崩溃。

+   需要从头开始编写进度报告、取消和完成逻辑。

以下是我们应该避免使用`ThreadPool`的原因：

+   当我们需要一个前台线程时。

+   当我们需要为线程设置显式优先级时。

+   当我们有长时间运行或阻塞的任务时。在池中有大量阻塞的线程将阻止新任务启动，因为`ThreadPool`中每个进程可用的线程数量有限。

+   如果我们需要 STA 线程，因为`ThreadPool`线程默认为 MTA。

+   如果我们需要为任务分配一个独特的标识来专门提供一个线程，因为我们无法为`ThreadPool`线程命名。

# BackgroundWorker

`BackgroundWorker`是.NET 提供的一个构造，用于从`ThreadPool`创建更可管理的线程。在解释基于 GUI 的应用程序时，我们看到`Main`方法被装饰了`STAThread`属性。这个属性保证了控件的安全性，因为控件是在线程所拥有的单元中创建的，不能与其他线程共享。在 Windows 应用程序中，有一个主执行线程，它拥有 UI 和控件，这在应用程序启动时创建。它负责接受用户输入，并根据用户的操作来绘制或重新绘制 UI。为了获得良好的用户体验，我们应该尽量使 UI 不受线程的影响，并将所有耗时的任务委托给工作线程。通常分配给工作线程的一些常见任务如下：

+   从服务器下载图像

+   与数据库交互

+   与文件系统交互

+   与 Web 服务交互

+   复杂的本地计算

正如您所看到的，这些大多数是**输入/输出**（**I/O**）操作。I/O 操作由 CPU 执行。当我们调用封装 I/O 操作的代码时，执行从线程传递到 CPU，CPU 执行任务。当任务完成时，操作的结果将返回给调用线程。这段时间从传递权杖到接收结果是线程的无活动期，因为它只需等待操作完成。如果这发生在主线程中，应用程序将变得无响应。因此，将这些任务委托给工作线程是有意义的。在响应式应用程序方面仍然有一些挑战需要克服。让我们看一个例子。

**案例研究**：

我们需要从流数据的服务中获取数据。我们希望更新用户工作完成的百分比。一旦工作完成，我们需要向用户更新所有数据。

**挑战**：

服务调用需要时间，因此我们需要将调用委托给工作线程，以避免 UI 冻结。

**解决方案**：

`BackgroundWorker`是`System.ComponentModel`中提供的一个类，可以用来创建一个利用`ThreadPool`的工作线程，正如我们之前讨论的那样。这意味着它以一种高效的方式工作。`BackgroundWorker`还支持进度报告和取消，除了通知操作的结果。

这种情况可以通过以下代码进一步解释：

```cs
using System;
using System.ComponentModel;
using System.Text;
using System.Threading;

namespace Ch01
{
    class _5BackgroundWorker
    {
        static void Main(string[] args)
        {
            var backgroundWorker = new BackgroundWorker();
            backgroundWorker.WorkerReportsProgress = true;
            backgroundWorker.WorkerSupportsCancellation = true;
            backgroundWorker.DoWork += SimulateServiceCall;
            backgroundWorker.ProgressChanged += ProgressChanged;
            backgroundWorker.RunWorkerCompleted += 
              RunWorkerCompleted;
            backgroundWorker.RunWorkerAsync();
            Console.WriteLine("To Cancel Worker Thread Press C.");
            while (backgroundWorker.IsBusy)
            {
                if (Console.ReadKey(true).KeyChar == 'C')
                {
                    backgroundWorker.CancelAsync();
                }
            }
        }
        // This method executes when the background worker finishes 
        // execution
        private static void RunWorkerCompleted(object sender, 
          RunWorkerCompletedEventArgs e)
        {
            if (e.Error != null)
            {
                Console.WriteLine(e.Error.Message);
            }
            else
                Console.WriteLine($"Result from service call 
                 is {e.Result}");
        }

        // This method is called when background worker want to 
        // report progress to caller
        private static void ProgressChanged(object sender, 
          ProgressChangedEventArgs e)
        {
            Console.WriteLine($"{e.ProgressPercentage}% completed");
        }

        // Service call we are trying to simulate
        private static void SimulateServiceCall(object sender, 
          DoWorkEventArgs e)
        {
            var worker = sender as BackgroundWorker;
            StringBuilder data = new StringBuilder();
            //Simulate a streaming service call which gets data and 
            //store it to return back to caller
            for (int i = 1; i <= 100; i++)
            {
                //worker.CancellationPending will be true if user 
                //press C
                if (!worker.CancellationPending)
                {
                    data.Append(i);
                    worker.ReportProgress(i);
                    Thread.Sleep(100);
                    //Try to uncomment and throw error
                    //throw new Exception("Some Error has occurred");
                }
               else
                {
                    //Cancels the execution of worker
                    worker.CancelAsync();
                }
            }
            e.Result = data;
        }
    }
}
```

`BackgroundWorker`提供了对原始线程的抽象，为用户提供了更多的控制和选项。使用`BackgroundWorker`的最好之处在于它使用了**基于事件的异步模式**（**EAP**），这意味着它能够比原始线程更有效地与代码交互。代码多多少少是不言自明的。为了引发进度报告和取消事件，您需要将以下属性设置为`true`：

```cs
backgroundWorker.WorkerReportsProgress = true;
backgroundWorker.WorkerSupportsCancellation = true;
```

您需要订阅`ProgressChanged`事件以接收进度，`DoWork`事件以传递需要由线程调用的方法，以及`RunWorkerCompleted`事件以接收线程执行的最终结果或任何错误消息：

```cs
backgroundWorker.DoWork += SimulateServiceCall;
backgroundWorker.ProgressChanged += ProgressChanged;
backgroundWorker.RunWorkerCompleted += RunWorkerCompleted;
```

设置好这些之后，您可以通过调用以下命令来调用工作线程：

```cs
backgroundWorker.RunWorkerAsync();
```

在任何时候，您都可以通过调用`backgroundWorker.CancelAsync()`方法来取消线程的执行，这会在工作线程上设置`CancellationPending`属性。我们需要编写一些代码来不断检查这个标志，并优雅地退出。

如果没有异常，线程执行的结果可以通过设置以下内容返回给调用者：

```cs
e.Result = data;
```

如果程序中有任何未处理的异常，它们会被优雅地返回给调用者。我们可以通过将其包装成`RunWorkerCompletedEventArgs`并将其作为参数传递给`RunWorkerCompleted`事件处理程序来实现这一点。

我们将在下一节讨论使用`BackgroundWorker`的优缺点。

# 使用 BackgroundWorker 的优缺点

使用`BackgroundWorker`的优点如下：

+   线程可以用来释放主线程。

+   线程由`ThreadPool`类的 CLR 以最佳方式创建和维护。

+   优雅和自动的异常处理。

+   使用事件支持进度报告、取消和完成逻辑。

使用`BackgroundWorker`的缺点是，使用更多线程后，代码变得难以调试和维护。

# 多线程与多任务处理

我们已经看到了多线程和多任务处理的工作原理。两者都有优缺点，您可以根据具体的用例选择使用。以下是一些多线程可能有用的示例：

+   **如果您需要一个易于设置和终止的系统**：当您有一个具有大量开销的进程时，多线程可能很有用。使用线程，您只需复制线程堆栈。然而，创建一个重复的进程意味着在单独的内存空间中重新创建整个数据过程。

+   **如果您需要快速任务切换**：在进程中，CPU 缓存和程序上下文可以在线程之间轻松维护。然而，如果必须将 CPU 切换到另一个进程，它必须重新加载。

+   **如果您需要与其他线程共享数据**：进程内的所有线程共享相同的内存池，这使它们更容易共享数据以比较进程。如果进程想要共享数据，它们需要 I/O 操作和传输协议，这是昂贵的。

在本节中，我们讨论了多线程和多任务处理的基础知识，以及在较早版本的.NET 中用于创建线程的各种方法。在下一节中，我们将尝试了解一些可以利用并行编程技术的场景。

# 并行编程可能有用的场景

以下是并行编程可能有用的场景：

+   **为基于 GUI 的应用程序创建响应式 UI**：我们可以将所有繁重和耗时的任务委托给工作线程，从而允许 UI 线程处理用户交互和 UI 重绘任务。

+   **处理同时请求**：在服务器端编程场景中，我们需要处理大量并发用户。我们可以创建一个单独的线程来处理每个请求。例如，我们可以使用`ThreadPool`和为命中服务器的每个请求分配一个线程的 ASP.NET 请求模型。然后，线程负责处理请求并向客户端返回响应。在客户端场景中，我们可以通过多线程调用多个互斥的 API 调用来节省时间。

+   **充分利用 CPU 资源**：使用多核处理器时，如果不使用多线程，通常只有一个核被利用，而且负担过重。通过创建多个线程，每个线程在单独的 CPU 上运行，我们可以充分利用 CPU 资源。以这种方式分享负担会提高性能。这对于长时间运行和复杂计算非常有用，可以通过分而治之的策略更快地执行。

+   **推测性方法**：涉及多个算法的场景，例如对一组数字进行排序，我们希望尽快获得排序好的集合。唯一的方法是将输入传递给所有算法并并行运行它们，先完成的算法被接受，而其余的被取消。

# 并行编程的优缺点

多线程导致并行性，具有自己的编程和缺陷。现在我们已经掌握了并行编程的基本概念，了解其优缺点非常重要。

并行编程的好处：

+   **性能提升**：由于任务分布在并行运行的线程中，我们可以实现更好的性能。

+   **改进的 GUI 响应性**：由于任务执行非阻塞 I/O，这意味着 GUI 线程始终空闲以接受用户输入。这会导致更好的响应性。

+   **任务的同时和并行发生**：由于任务并行运行，我们可以同时运行不同的编程逻辑。

+   通过利用资源更好地使用缓存存储和更好地利用 CPU 资源。任务可以在不同的核心上运行，从而确保最大化吞吐量。

并行编程也有以下缺点：

+   **复杂的调试和测试过程**：没有良好的多线程工具支持，调试线程不容易，因为不同的线程并行运行。

+   **上下文切换开销**：每个线程都在分配给它的时间片上工作。一旦时间片到期，就会发生上下文切换，这也会浪费资源。

+   **死锁发生的机会很高**：如果多个线程在共享资源上工作，我们需要应用锁来实现线程安全。如果多个线程同时锁定并等待共享资源，这可能导致死锁。

+   **编程困难**：与同步版本相比，使用代码分支，并行程序可能更难编写。

+   **结果不可预测**：由于并行编程依赖于 CPU 核心，因此在不同配置的机器上可能会得到不同的结果。

我们应该始终明白并行编程是一个相对的概念，对别人有效的方法未必对你有效。建议你实施这种方法并自行验证。

# 总结

在本章中，我们讨论了并行编程的场景、好处和陷阱。计算机系统在过去几十年里从单核处理器发展到多核处理器。芯片中的硬件已经启用了 HT，从而提高了现代系统的性能。

在开始并行编程之前，了解与操作系统相关的基本概念，如进程、任务以及多线程和多任务之间的区别，是一个好主意。

在下一章中，我们将完全专注于 TPL 及其相关实现的讨论。然而，在现实世界中，仍然有很多依赖于旧构造的遗留代码，因此对这些代码的了解将会很有用。

# 问题

1.  多线程是并行编程的一个超集。

1.  正确

1.  错误

1.  在启用超线程的单处理器双核机器上会有多少个核心？

1.  2

1.  4

1.  8

1.  当应用程序退出时，所有前台线程也会被终止。在应用程序退出时不需要单独的逻辑来关闭前台线程。

1.  正确

1.  错误

1.  当线程尝试访问它没有拥有/创建的控件时会抛出哪个异常？

1.  `ObjectDisposedException`

1.  `InvalidOperationException`

1.  `CrossThreadException`

1.  哪个提供了取消支持和进度报告？

1.  `线程`

1.  `BackgroundWorker`

1.  `ThreadPool`


# 第二章：任务并行性

在上一章中，我们介绍了并行编程的概念。在本章中，我们将继续讨论 TPL 和任务并行性。

.NET 作为一个编程框架的主要目标之一是通过将所有常见的任务封装为 API 来使开发人员的生活更轻松。正如我们已经看到的，线程自.NET 的早期版本以来就存在，但最初它们非常复杂，并且伴随着很多开销。微软引入了许多新的并行原语，使得从头开始编写、调试和维护并行程序变得更加容易，而无需处理与传统线程相关的复杂性。

本章将涵盖以下主题：

+   创建和启动任务

+   从已完成的任务获取结果

+   如何取消任务

+   如何等待运行任务

+   处理任务异常

+   将**异步编程模型**（**APM**）模式转换为任务

+   将**基于事件的异步模式**（**EAPs**）转换为任务

+   更多关于任务的内容：

+   继续任务

+   父任务和子任务

+   本地和全局队列和存储

+   工作窃取队列

# 技术要求

要完成本章，您应该对 C#和一些高级概念（如委托）有很好的理解。

本章的源代码可在 GitHub 上找到：[`github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter02`](https://github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter02)。

# 任务

**任务**是.NET 中提供异步单元的抽象，就像 JavaScript 中的 promise 一样。在.NET 的初始版本中，我们只能依赖于线程，这些线程是直接创建或使用`ThreadPool`类创建的。`ThreadPool`类提供了对线程的托管抽象层，但开发人员仍然依赖于`Thread`类来获得更好的控制。通过使用`Thread`类创建线程，我们可以获得底层对象，可以等待、取消或移动到前台或后台。然而，在实时中，我们需要线程持续执行工作。这要求我们编写大量难以维护的代码。`Thread`类也是不受管理的，这对内存和 CPU 都造成了很大的负担。我们需要两全其美，这就是任务的用武之地。任务只是通过`ThreadPool`创建的线程的包装器。任务提供了等待、取消和继续等功能，这些功能在任务完成后运行。

任务具有以下重要特点：

+   任务由`TaskScheduler`执行，默认调度程序简单地在`ThreadPool`上运行。

+   我们可以从任务中返回值。

+   任务让您知道它们何时完成，不像`ThreadPool`或线程。

+   可以使用`ContinueWith()`构造来运行任务的后续任务。

+   我们可以通过调用`Task.Wait()`来等待任务。这会阻塞调用线程，直到任务完成为止。

+   与传统线程或`ThreadPool`相比，任务使代码更易读。它们还为引入 C# 5.0 中的异步编程构造铺平了道路。

+   当一个任务从另一个任务启动时，我们可以建立父/子关系。

+   我们可以将子任务的异常传播到父任务。

+   可以使用`CancellationToken`类取消任务。

# 创建和启动任务

我们可以使用 TPL 的许多方法来创建和运行任务。在本节中，我们将尝试理解所有这些方法，并在可能的情况下进行比较分析。首先，您需要向`System.Threading.Tasks`命名空间添加引用：

```cs
using System.Threading.Tasks;
```

我们将尝试使用以下方法创建任务：

+   `System.Threading.Tasks.Task`类

+   `System.Threading.Tasks.Task.Factory.StartNew` 方法

+   `System.Threading.Tasks.Task.Run` 方法

+   `System.Threading.Tasks.Task.Delay`

+   `System.Threading.Tasks.Task.Yield`

+   `System.Threading.Tasks.Task.FromResult<T>方法`

+   `System.Threading.Tasks.Task.FromException`和`Task.FromException<T>`

+   `System.Threading.Tasks.Task.FromCancelled`和`Task.FromCancelled<T>`

# System.Threading.Tasks.Task 类

任务类是一种以`ThreadPool`线程异步执行工作的方式，它基于**基于任务的异步模式**（**TAP**）。非泛型的`Task`类不返回结果，所以每当我们需要从任务中返回值时，我们需要使用泛型版本`Task<T>`。通过`Task`类创建的任务直到我们调用`Start`方法才被安排运行。

我们可以通过`Task`类的各种方式创建一个任务，所有这些方式我们将在以下小节中讨论。

# 使用 lambda 表达式语法

在以下代码中，我们通过调用`Task`构造函数并传递包含我们要执行的方法的 lambda 表达式来创建一个任务：

```cs
Task task = new Task (() => PrintNumber10Times ());
task.Start();
```

# 使用 Action delegate

在以下代码中，我们通过调用`Task`构造函数并传递包含我们要执行的方法的 delegate 来创建一个任务：

```cs
Task task = new Task (new Action (PrintNumber10Times));
task.Start();
```

# 使用 delegate

在以下代码中，我们通过调用`Task`构造函数并传递包含我们要执行的方法的匿名`delegate`来创建一个`task`对象：

```cs
Task task = new Task (delegate {PrintNumber10Times ();});
task.Start();
```

在所有这些情况下，输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/40ef715e-dff5-40e9-a0a0-acafb3317b7c.png)

所有前面的方法都是做同样的事情 - 它们只是有不同的语法。

我们只能对以前未运行过的任务调用`Start`方法。如果您需要重新运行已经完成的任务，您需要创建一个新的任务并在其上调用`Start`方法。

# System.Threading.Tasks.Task.Factory.StartNew 方法

我们也可以使用`TaskFactory`类的`StartNew`方法创建一个任务，如下所示。在这种方法中，任务被创建并安排在`ThreadPool`内执行，并将该任务的引用返回给调用者。

我们可以使用`Task.Factory.StartNew`方法创建一个任务。我们将在以下小节中讨论这个问题。

# 使用 lambda 表达式语法

在以下代码中，我们通过在`TaskFactory`上调用`StartNew()`方法并传递包含我们要执行的方法的 lambda 表达式来创建一个`Task`：

```cs
Task.Factory.StartNew(() => PrintNumber10Times());          
```

# 使用 Action delegate

在以下代码中，我们通过在`TaskFactory`上调用`StartNew()`方法并传递包装我们要执行的方法的 delegate 来创建一个`Task`：

```cs
Task.Factory.StartNew(new Action( PrintNumber10Times));
```

# 使用 delegate

在以下代码中，我们通过在`TaskFactory`上调用`StartNew()`方法并传递我们要执行的`delegate`包装方法来创建一个`Task`：

```cs
 Task.Factory.StartNew(delegate { PrintNumber10Times(); });
```

所有前面的方法都是做同样的事情 - 它们只是有不同的语法。

# System.Threading.Tasks.Task.Run 方法

我们也可以使用`Task.Run`方法创建一个任务。这与`StartNew`方法的工作方式相同，并返回一个`ThreadPool`线程。

我们可以通过以下方式使用`Task.Run`方法创建一个`Task`，所有这些方式将在以下小节中讨论。

# 使用 lambda 表达式语法

在以下代码中，我们通过在`Task`上调用静态的`Run()`方法并传递包含我们要执行的方法的 lambda 表达式来创建一个`Task`：

```cs
Task.Run(() => PrintNumber10Times ());
```

# 使用 Action delegate

在以下代码中，我们通过在`Task`上调用静态的`Run()`方法并传递包含我们要执行的方法的 delegate 来创建一个`Task`：

```cs
Task.Run(new Action (PrintNumber10Times));
```

# 使用 delegate

在以下代码中，我们通过在`Task`上调用静态的`Run()`方法并传递包含我们要执行的方法的 delegate 来创建一个`Task`：

```cs
Task.Run(delegate {PrintNumber10Times ();});
```

# System.Threading.Tasks.Task.Delay 方法

我们可以创建一个在指定时间间隔后完成或可以随时被用户取消的任务，使用`CancellationToken`类。过去，我们使用`Thread`类的`Thread.Sleep()`方法创建阻塞构造以等待其他任务。然而，这种方法的问题是它仍然使用 CPU 资源并且同步运行。`Task.Delay`提供了一个更好的等待任务的替代方法，而不利用 CPU 周期。它也是异步运行的：

```cs
Console.WriteLine("What is the output of 20/2\. We will show result in 2 seconds.");
Task.Delay(2000);
Console.WriteLine("After 2 seconds delay");
Console.WriteLine("The output is 10");
```

前面的代码询问用户一个问题，然后等待两秒钟才呈现答案。在这两秒钟内，主线程不必等待，但必须执行其他任务以改善用户体验。代码在系统时钟上异步运行，一旦时间到期，其余代码就会被执行。

前面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/e92b0ddd-683c-4c1f-92e9-6d9092ff30b0.png)

在查看我们可以用来创建任务的其他方法之前，我们将看一下在 C# 5.0 中引入的两个异步编程构造：`async`和`await`关键字。

`async`和`await`是代码标记，使我们更容易编写异步程序。我们将在第九章中深入学习这些关键字，*异步、等待和基于任务的异步编程基础*。顾名思义，我们可以使用`await`关键字等待任何异步调用。一旦执行线程在方法内遇到`await`关键字，它就返回到`ThreadPool`，将方法的其余部分标记为继续委托，并开始执行其他排队的任务。一旦异步任务完成，`ThreadPool`中的任何可用线程都会完成方法的其余部分。

# System.Threading.Tasks.Task.Yield 方法

这是创建`await`任务的另一种方式。底层任务对调用者不直接可访问，但在涉及与程序执行相关的异步编程的某些场景中使用。它更像是一个承诺而不是一个任务。使用`Task.Yield`，我们可以强制我们的方法是异步的，并将控制返回给操作系统。当方法的其余部分在以后的时间点执行时，它可能仍然作为异步代码运行。我们可以使用以下代码实现相同的效果：

```cs
await Task.Factory.StartNew(() => {},
    CancellationToken.None,
    TaskCreationOptions.None,
    SynchronizationContext.Current != null?
    TaskScheduler.FromCurrentSynchronizationContext():
    TaskScheduler.Current);
```

这种方法可以通过在长时间运行的任务中不时地将控制权交给 UI 线程来使 UI 应用程序响应。然而，这不是 UI 应用程序的首选方法。有更好的替代方法，例如 WinForms 中的`Application.DoEvents()`和 WPF 中的`Dispatcher.Yield(DispatcherPriority.ApplicationIdle)`：

```cs
private async static void TaskYield()
{
     for (int i = 0; i < 100000; i++)
     {
        Console.WriteLine(i);
        if (i % 1000 == 0)
        await Task.Yield();
     }
}
```

在控制台或 Web 应用程序的情况下，当我们运行代码并在任务的 yield 上应用断点时，我们会看到随机线程池线程切换上下文来运行代码。以下截图描述了各个阶段控制执行的各个线程。

以下截图显示了程序流中所有线程同时执行。我们可以看到当前线程 ID 为 1664：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/5a633f20-226e-49d4-aa64-3d7f3ca6092d.png)

如果我们按下*F5*并允许断点命中`i`的另一个值，我们会看到代码现在由 ID 为 10244 的另一个线程执行：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/e7dd5bc6-0a11-4692-8ade-63a6fef19e9d.png)

我们将在第十一章中学习更多关于线程窗口和调试技术，*为并行和异步代码编写单元测试用例*。

# System.Threading.Tasks.Task.FromResult<T>方法

这种方法是最近在.NET 框架 4.5 中引入的，它非常被低估。我们可以通过这种方法返回带有结果的完成任务，如下所示：

```cs
static void Main(string[] args)
{
    StaticTaskFromResultUsingLambda();
}
private static void StaticTaskFromResultUsingLambda()
{
    Task<int> resultTask = Task.FromResult<int>( Sum(10));
    Console.WriteLine(resultTask.Result);
}
private static int Sum (int n)
{
    int sum=0;
    for (int i = 0; i < 10; i++)
    {
        sum += i;
    }
    return sum;
}
```

如前面的代码所示，我们实际上将同步的`Sum`方法转换为使用`Task.FromResult<int>`类以异步方式返回结果。这种方法经常用于 TDD 中模拟异步方法，以及在异步方法内根据条件返回默认值。我们将在第十一章中进一步解释这些方法，*编写并行和异步代码的单元测试用例**.*

# System.Threading.Tasks.Task.FromException 和 System.Threading.Tasks.Task.FromException<T>方法

这些方法创建了由预定义异常完成的任务，并用于从异步任务中抛出异常，以及在 TDD 中。我们将在第十一章中进一步解释这种方法，*编写并行和异步代码的单元测试用例**.*

```cs
return Task.FromException<long>(
new FileNotFoundException("Invalid File name."));
```

正如你在前面的代码中看到的，我们将`FileNotFoundException`包装为一个任务并将其返回给调用者。

# System.Threading.Tasks.Task.FromCanceled 和 System.Threading.Tasks.Task.FromCanceled<T>方法

这些方法用于创建由取消令牌导致完成的任务：

```cs
CancellationTokenSource source = new CancellationTokenSource();
var token = source.Token;
source.Cancel();
Task task = Task.FromCanceled(token);
Task<int> canceledTask = Task.FromCanceled<int>(token);
```

如前面的代码所示，我们使用`CancellationTokenSource`类创建了一个取消令牌。然后，我们从该令牌创建了一个任务。这里需要考虑的重要事情是，在我们可以使用`Task.FromCanceled`方法之前，令牌需要被取消。

如果我们想要从异步方法中返回值，以及在 TDD 中，这种方法是有用的。

# 从已完成的任务中获取结果

为了从任务中返回值，TPL 提供了我们之前定义的所有类的泛型变体：

+   `Task<T>`

+   `Task.Factory.StartNew<T>`

+   `Task.Run<T>`

任务完成后，我们应该能够通过访问`Task.Result`属性来获取结果。让我们尝试使用一些代码示例来理解这一点。我们将创建各种任务，并在完成后尝试返回值：

```cs
using System;
using System.Threading.Tasks;
namespace Ch02
{
    class _2GettingResultFromTasks
    {
        static void Main(string[] args)
        {
            GetResultsFromTasks();
            Console.ReadLine();
        }
        private static void GetResultsFromTasks()
        {
            var sumTaskViaTaskOfInt = new Task<int>(() => Sum(5));
            sumTaskViaTaskOfInt.Start();
            Console.WriteLine($"Result from sumTask is
             {sumTaskViaTaskOfInt.Result}" );
            var sumTaskViaFactory = Task.Factory.StartNew<int>(() => 
             Sum(5));
            Console.WriteLine($"Result from sumTask is 
             {sumTaskViaFactory.Result}");
            var sumTaskViaTaskRun = Task.Run<int>(() => Sum(5));
            Console.WriteLine($"Result from sumTask is 
             {sumTaskViaTaskRun.Result}");
            var sumTaskViaTaskResult = Task.FromResult<int>(Sum(5));
            Console.WriteLine($"Result from sumTask is 
             {sumTaskViaTaskResult.Result}");
        }
        private static int Sum(int n)
        {
            int sum = 0;
            for (int i = 0; i < n; i++)
            {
                sum += i;
            }
            return sum;
        }
    }
}
```

如前面的代码所示，我们使用了泛型变体创建了任务。一旦它们完成，我们就能够使用结果属性获取结果：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/bc4ef585-380d-4bed-82c2-49d3ea97a72a.png)

在下一节中，我们将学习如何取消任务。

# 如何取消任务

TPL 的另一个重要功能是为开发人员提供现成的数据结构来取消运行中的任务。那些有经典线程背景的人会意识到，以前要使线程支持取消是多么困难，需要使用自定义的逻辑，但现在不再是这样。.NET Framework 提供了两个类来支持任务取消：

+   `CancellationTokenSource`**: **这个类负责创建取消令牌，并将取消请求传递给通过该源创建的所有令牌

+   `CancellationToken`**: **这个类被监听器用来监视请求的当前状态

要创建可以取消的任务，我们需要执行以下步骤：

1.  创建`System.Threading.CancellationTokenSource`类的实例，该类通过`Token Property`进一步提供`System.Threading.CancellationToken`。

1.  在创建任务时传递令牌。

1.  在需要时，调用`Cancel()`方法取消`CancellationTokenSource`上的任务。

让我们试着理解如何创建一个令牌并将其传递给任务。

# 创建令牌

可以使用以下代码创建令牌：

```cs
CancellationTokenSource tokenSource = new CancellationTokenSource();
CancellationToken token = tokenSource.Token;
```

首先，我们使用`CancellationTokenSource`构造函数创建了一个`tokenSource`。然后，我们使用**`tokenSource`**的 token 属性获取了我们的令牌。

# 使用令牌创建任务

我们可以通过将`CancellationToken`作为任务构造函数的第二个参数来创建任务，如下所示：

```cs
var sumTaskViaTaskOfInt = new Task<int>(() => Sum(5), token);
var sumTaskViaFactory = Task.Factory.StartNew<int>(() => Sum(5), token);
var sumTaskViaTaskRun = Task.Run<int>(() => Sum(5), token);
```

在经典的线程模型中，我们曾经在非确定性的线程上调用`Abort()`方法。这会突然停止线程，从而导致资源未受管理时内存泄漏。使用 TPL，我们可以调用`Cancel`方法，这是一个取消令牌源，将进而在令牌上设置`IsCancellationRequested`属性。任务执行的底层方法应该监视此属性，并且如果设置了，应该优雅地退出。

有各种方法可以监视令牌源是否请求了取消：

+   通过轮询令牌的`IsCancellationRequested`属性的状态

+   注册请求取消回调

# 通过轮询令牌的状态来检查`IsCancellationRequested`属性

这种方法在涉及递归方法或包含通过循环进行长时间计算逻辑的方法的场景中非常有用。在我们的方法或循环中，我们编写代码以在某些最佳间隔时轮询`IsCancellationRequested`。如果设置了，它通过调用`token`类的`ThrowIfCancellationRequested`方法来中断循环。

以下代码是通过轮询令牌来取消任务的示例：

```cs
        private static void CancelTaskViaPoll()
        {
            CancellationTokenSource cancellationTokenSource = 
             new CancellationTokenSource();
            CancellationToken token = cancellationTokenSource.Token;
            var sumTaskViaTaskOfInt = new Task(() => 
             LongRunningSum(token), token);
            sumTaskViaTaskOfInt.Start();
            //Wait for user to press key to cancel task
            Console.ReadLine();
            cancellationTokenSource.Cancel();
        }
        private static void LongRunningSum(CancellationToken token)
        {
            for (int i = 0; i < 1000; i++)
            {
                //Simulate long running operation
                Task.Delay(100);
                if (token.IsCancellationRequested)
                    token.ThrowIfCancellationRequested();
            }
        }
```

在前面的代码中，我们通过`CancellationTokenSource`类创建了一个取消令牌。然后，我们通过传递令牌创建了一个任务。该任务执行一个长时间运行的方法`LongRunningSum`（模拟），该方法不断轮询令牌的`IsCancellationRequested`属性。如果用户在方法完成之前调用了`cancellationTokenSource.Cancel()`，它会抛出异常。

轮询不会带来任何显著的性能开销，并且可以根据您的需求使用。当您对任务执行的工作有完全控制时使用它，例如如果它是您自己编写的核心逻辑。

# 使用回调委托注册请求取消

这种方法利用了一个`Callback`委托，当底层令牌请求取消时会被调用。我们应该将其与那些以一种使得无法以常规方式检查`CancellationToken`值的方式阻塞的操作一起使用。

让我们看一下以下代码，它从远程 URL 下载文件：

```cs
private static void DownloadFileWithoutToken()
{
    WebClient webClient = new WebClient();
    webClient.DownloadStringAsync(new 
     Uri("http://www.google.com"));
    webClient.DownloadStringCompleted += (sender, e) => 
     {
        if (!e.Cancelled)
          Console.WriteLine("Download Complete.");
        else
          Console.WriteLine("Download Cancelled.");
     };
}
```

从前面的方法中可以看到，一旦我们调用`WebClient`的`DownloadStringAsync`方法，控制权就离开了用户。虽然`WebClient`类允许我们通过`webClient.CancelAsync()`方法取消任务，但我们无法控制何时调用它。

前面的代码可以修改为使用`Callback`委托，以便更好地控制任务取消，如下所示：

```cs
static void Main(string[] args)
{
    CancellationTokenSource cancellationTokenSource = new 
     CancellationTokenSource();
    CancellationToken token = cancellationTokenSource.Token;
    DownloadFileWithToken(token);
    //Random delay before we cancel token
    Task.Delay(2000);
    cancellationTokenSource.Cancel();
    Console.ReadLine();
 }
private static void DownloadFileWithToken(CancellationToken token)
{    
    WebClient webClient = new WebClient();
    //Here we are registering callback delegate that will get called 
    //as soon as user cancels token
    token.Register(() => webClient.CancelAsync());
    webClient.DownloadStringAsync(new 
     Uri("http://www.google.com"));
    webClient.DownloadStringCompleted += (sender, e) => {
    //Wait for 3 seconds so we have enough time to cancel task
    Task.Delay(3000);
    if (!e.Cancelled)
        Console.WriteLine("Download Complete.");
    else
    Console.WriteLine("Download Cancelled.");};
}
```

如您所见，在这个修改后的版本中，我们传递了一个取消令牌，并通过`Register`方法订阅了取消回调。

一旦用户调用`cancellationTokenSource.Cancel()`方法，它将通过调用`webClient.CancelAsync()`取消下载操作。

`CancellationTokenSource`也可以与传统的`ThreadPool.QueueUserWorkItem`很好地配合使用。

以下是创建`CancellationTokenSource`的代码，可以传递给`ThreadPool`以支持取消：

```cs
// Create the token source.
CancellationTokenSource cts = new CancellationTokenSource();
// Pass the token to the cancellable operation.
ThreadPool.QueueUserWorkItem(new WaitCallback(DoSomething), cts.Token);
```

在本节中，我们讨论了取消任务的各种方法。取消任务可以在任务可能变得多余的情况下节省大量 CPU 时间。例如，假设我们创建了多个任务，使用不同的算法对一组数字进行排序。虽然所有算法都会返回相同的结果（一组排序好的数字），但我们希望尽快获得结果。我们将接受第一个（最快的）算法的结果，并取消其余的任务以提高系统性能。在下一节中，我们将讨论如何等待运行中的任务。

# 如何等待运行中的任务

在之前的示例中，我们调用了`Task.Result`属性来从已完成的任务中获取结果。这会阻塞调用线程，直到结果可用。TPL 为我们提供了另一种等待一个或多个任务的方法。

TPL 中有各种 API 可供我们等待一个或多个任务。这些包括：

+   `Task.Wait`

+   `Task.WaitAll`

+   `Task.WaitAny`

+   `Task.WhenAll`

+   `Task.WhenAny`

这些 API 将在以下子节中定义。

# Task.Wait

这是一个实例方法，用于等待单个任务。我们可以指定调用者等待任务完成的最长时间，然后在超时异常中解除阻塞。我们还可以通过向方法传递取消令牌来完全控制已取消的监视事件。调用方法将被阻塞，直到线程完成、取消或抛出异常：

```cs
var task = Task.Factory.StartNew(() => Console.WriteLine("Inside Thread"));
//Blocks the current thread until task finishes.
task.Wait();
```

`Wait`方法有五个重载版本：

+   `Wait()`:无限期地等待任务完成。调用线程将被阻塞，直到子线程完成。

+   `Wait(CancellationToken)`:等待任务无限期地执行或取消令牌被取消时。

+   `Wait(int)`:在指定的时间段内等待任务完成执行，以毫秒为单位。

+   `Wait(TimeSpan)`:在指定的时间间隔内等待任务完成执行。

+   `Wait(int, CancellationToken)`:在指定的时间段内等待任务完成执行，以毫秒为单位，或者取消令牌被取消时。

# Task.WaitAll

这是`Task`类中定义的静态方法，用于等待多个任务。任务作为数组传递给方法，调用者将被阻塞，直到所有任务完成。该方法还支持超时和取消令牌。使用此方法的一些示例代码如下：

```cs
    Task taskA = Task.Factory.StartNew(() => 
     Console.WriteLine("TaskA finished"));
    Task taskB = Task.Factory.StartNew(() => 
     Console.WriteLine("TaskB finished"));
    Task.WaitAll(taskA, taskB);
    Console.WriteLine("Calling method finishes");
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/d8f72c1c-e31b-45b7-a3f7-083ea597cfa8.png)

正如您所看到的，当两个任务都完成执行时，调用方法完成语句被执行。

该方法的一个示例用例可能是当我们需要来自多个来源的数据（我们为每个来源都有一个任务），并且我们希望将所有任务的数据组合起来，以便在 UI 上显示。

# Task.WaitAny

这是`Task`类中定义的另一个静态方法。就像`WaitAll`一样，`WaitAny`用于等待多个任务，但只要传递给方法的任何任务完成执行，调用者就会解除阻塞。与其他方法一样，`WaitAny`支持超时和取消令牌。使用此方法的一些示例代码如下：

```cs
Task taskA = Task.Factory.StartNew(() => 
 Console.WriteLine("TaskA finished"));
Task taskB = Task.Factory.StartNew(() => 
 Console.WriteLine("TaskB finished"));
Task.WaitAny(taskA, taskB);
Console.WriteLine("Calling method finishes");
```

在上面的代码中，我们启动了两个任务，并使用`WaitAny`等待它们。这个方法会阻塞当前线程。一旦任何一个任务完成，调用线程就会解除阻塞。

该方法的一个示例用例可能是当我们需要的数据来自不同的来源并且我们需要尽快获取它时。在这里，我们创建了请求不同来源的任务。一旦任何一个任务完成，我们将解除调用线程的阻塞并从完成的任务中获取结果。

# Task.WhenAll

这是`WaitAll`方法的非阻塞变体。它返回一个代表所有指定任务的等待操作的任务。与阻塞调用线程的`WaitAll`不同，`WhenAll`可以在异步方法中等待，从而释放调用线程以执行其他操作。使用此方法的一些示例代码如下：

```cs
Task taskA = Task.Factory.StartNew(() => 
 Console.WriteLine("TaskA finished"));
Task taskB = Task.Factory.StartNew(() => 
 Console.WriteLine("TaskB finished"));
Task.WhenAll(taskA, taskB);
Console.WriteLine("Calling method finishes");
```

这段代码的工作方式与`Task.WaitAll`相同，除了调用线程返回到`ThreadPool`而不是被阻塞。

# Task.WhenAny

这是`WaitAny`的非阻塞变体。它返回一个封装了对单个基础任务的等待操作的任务。与`WaitAny`不同，它不会阻塞调用线程。调用线程可以在异步方法内调用 await。使用此方法的一些示例代码如下：

```cs
Task taskA = Task.Factory.StartNew(() => 
 Console.WriteLine("TaskA finished"));
Task taskB = Task.Factory.StartNew(() => 
 Console.WriteLine("TaskB finished"));
Task.WhenAny(taskA, taskB);
Console.WriteLine("Calling method finishes");
```

这段代码的工作方式与`Task.WaitAny`相同，除了调用线程返回到`ThreadPool`而不是被阻塞。

在本节中，我们讨论了如何在处理多个线程时编写高效的代码，而不需要代码分支。代码流看起来是同步的，尽管在需要的地方是并行的。在下一节中，我们将学习任务如何处理异常。

# 处理任务异常

异常处理是并行编程中最重要的方面之一。所有良好的干净代码从业者都专注于高效处理异常。这在并行编程中变得更加重要，因为线程或任务中的任何未处理异常都可能导致应用程序突然崩溃。幸运的是，TPL 提供了一个很好的、高效的设计来处理和管理异常。在任务中发生的任何未处理异常都会被延迟，然后传播到一个观察任务异常的加入线程。

任何在任务内部发生的异常都会被包装在`AggregateException`类下，并返回给观察异常的调用者。如果调用者正在等待单个任务，`AggregateException`类的内部异常属性将返回原始异常。然而，如果调用者正在等待多个任务，比如`Task.WaitAll`、`Task.WhenAll`、`Task.WaitAny`或`Task.WhenAny`，所有来自任务的异常都将作为集合返回给调用者。它们可以通过`InnerExceptions`属性访问。

现在，让我们看看在任务内部处理异常的各种方法。

# 从单个任务处理异常

在下面的代码中，我们创建了一个简单的任务，试图将一个数字除以 0，从而引发`DivideByZeroException`。异常被返回给调用者，并在 catch 块内处理。由于它是一个单一任务，异常对象被包装在`AggregateException`对象的`InnerException`属性下：

```cs
class _4HandlingExceptions
{
    static void Main(string[] args)
    {
        Task task = null;
         try
           {
                task = Task.Factory.StartNew(() =>
                {
                    int num = 0, num2 = 25;
                    var result = num2 / num;
                });
            task.Wait();
        }
        catch (AggregateException ex)
        {
            Console.WriteLine($"Task has finished with 
             exception {ex.InnerException.Message}");
        }
        Console.ReadLine();
    }
}
```

当我们运行上述代码时，输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/f806dff4-80eb-4d19-88da-254dbe97be32.png)

# 从多个任务处理异常

现在，我们将创建多个任务，然后尝试从中抛出异常。然后，我们将学习如何从调用者列出来自不同任务的不同异常：

```cs
static void Main(string[] args)
{
    Task taskA = Task.Factory.StartNew(()=> throw 
     new DivideByZeroException());
    Task taskB = Task.Factory.StartNew(()=> throw 
     new ArithmeticException());
    Task taskC = Task.Factory.StartNew(()=> throw 
     new NullReferenceException());
    try
    {
        Task.WaitAll(taskA, taskB, taskC);
    }
    catch (AggregateException ex)
    {
        foreach (Exception innerException in ex.InnerExceptions)
        {
            Console.WriteLine(innerException.Message);
        }
    }
    Console.ReadLine();
}
```

当我们运行上述代码时，输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/e1465881-0a19-42c5-979e-243cdf7845c6.png)

在上述代码中，我们创建了三个抛出不同异常的任务，并使用`Task.WaitAll`等待所有线程。正如你所看到的，通过调用`WaitAll`观察异常，而不仅仅是启动任务，这就是为什么我们将`WaitAll`包装在`try`块中。`WaitAll`方法将在所有传递给它的任务都通过抛出异常而故障，并执行相应的`catch`块时返回。我们可以通过迭代`AggregateException`类的`InnerExceptions`属性找到所有任务产生的异常。

# 使用回调函数处理任务异常

找出这些异常的另一个选项是使用回调函数来访问和处理来自任务的异常：

```cs
static void Main(string[] args)
      {
         Task taskA = Task.Factory.StartNew(() => throw 
          new DivideByZeroException());    
         Task taskB = Task.Factory.StartNew(() => throw 
          new ArithmeticException());                       
         Task taskC = Task.Factory.StartNew(() => throw 
          new NullReferenceException()); 
         try
         {
             Task.WaitAll(taskA, taskB, taskC);
         }
         catch (AggregateException ex)
         {
              ex.Handle(innerException =>
              {
                 Console.WriteLine(innerException.Message);
                 return true; 
              });
          }
          Console.ReadLine();
        }
```

在 Visual Studio 中运行上述代码时，输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/68deb400-78ae-4c72-9467-8a6008210a12.png)

如前面的代码所示，我们订阅了`AggregateException`上的处理回调函数，而不是整合`InnerExceptions`。这对所有抛出异常的任务都会触发，我们可以返回`true`，表示异常已经得到了优雅处理。

# 将 APM 模式转换为任务

传统的 APM 方法使用`IAsyncResult`接口来创建使用两种方法设计模式的异步方法：`BeginMethodName`和`EndMethodName`。让我们试着理解程序从同步到 APM 再到任务的过程。

以下是一个从文本文件中读取数据的同步方法：

```cs
private static void ReadFileSynchronously()        
{            
    string path = @"Test.txt";
    //Open the stream and read content.
    using (FileStream fs = File.OpenRead(path))
    {
         byte[] b = new byte[1024];
         UTF8Encoding encoder = new UTF8Encoding(true);
         fs.Read(b, 0, b.Length);
         Console.WriteLine(encoder.GetString(b));
     }
 }
```

在前面的代码中没有什么花哨的。首先，我们创建了一个`FileStream`对象并调用了`Read`方法，该方法将文件从磁盘同步读入缓冲区，然后将缓冲区写入控制台。我们使用`UTF8Encoding`类将缓冲区转换为字符串。然而，这种方法的问题在于一旦调用`Read`，线程就会被阻塞，直到读取操作完成。I/O 操作由 CPU 使用 CPU 周期来管理，因此没有必要让线程等待 I/O 操作完成。让我们试着理解 APM 的做法：

```cs
private static void ReadFileUsingAPMAsyncWithoutCallback()
        {
            string filePath = @"Test.txt";
            //Open the stream and read content.
            using (FileStream fs = new FileStream(filePath, 
             FileMode.Open, FileAccess.Read, FileShare.Read, 
             1024, FileOptions.Asynchronous))
            {
                byte[] buffer = new byte[1024];
                UTF8Encoding encoder = new UTF8Encoding(true);
                IAsyncResult result = fs.BeginRead(buffer, 0, 
                 buffer.Length, null, null);
                Console.WriteLine("Do Something here");
                int numBytes = fs.EndRead(result);
                fs.Close();
                Console.WriteLine(encoder.GetString(buffer));
            }
        }
```

如前面的代码所示，我们用异步版本替换了同步的`Read`方法，即`BeginRead`。一旦编译器遇到`BeginRead`，就会向 CPU 发送指令开始读取文件，并解除线程阻塞。我们可以在同一方法中执行其他任务，然后通过调用`EndRead`再次阻塞线程，等待`Read`操作完成并收集结果。这是一个简单而有效的方法，以便制作响应式应用程序，尽管我们也在阻塞线程以获取结果。我们可以使用`Overload`而不是在同一方法中调用`EndRead`，它接受一个回调方法，当读取操作完成时会自动调用，以避免阻塞线程。该方法的签名如下：

```cs
public override IAsyncResult BeginRead(
        byte[] array,
        int offset,
        int numBytes,
        AsyncCallback userCallback,
        object stateObject)
```

在这里，我们已经看到了我们是如何从同步方法转换为 APM 的。现在，我们将把 APM 实现转换为一个任务。这在以下代码中进行了演示：

```cs
private static void ReadFileUsingTask()
        {
            string filePath = @"Test.txt";
            //Open the stream and read content.
            using (FileStream fs = new FileStream(filePath, FileMode.Open, 
             FileAccess.Read, FileShare.Read, 1024, 
             FileOptions.Asynchronous))
            {
                byte[] buffer = new byte[1024];
                UTF8Encoding encoder = new UTF8Encoding(true);
                //Start task that will read file asynchronously
                var task = Task<int>.Factory.FromAsync(fs.BeginRead, 
                 fs.EndRead, buffer, 0, buffer.Length,null);
                Console.WriteLine("Do Something while file is read 
                  asynchronously");
                //Wait for task to finish
                task.Wait();
                Console.WriteLine(encoder.GetString(buffer));
            }
        }
```

如前面的代码所示，我们用`Task<int>.Factory.FromAsync`替换了`BeginRead`方法。这是一种实现 TAP 的方法。该方法返回一个任务，在我们在同一方法中继续做其他工作的同时在后台运行，然后通过`task.Wait()`再次阻塞线程以获取结果。这就是你可以轻松地将任何 APM 代码转换为 TAP 的方法。

# 将 EAP 转换为任务

EAP 用于创建包装昂贵和耗时操作的组件。因此，它们需要被异步化。这种模式已经被用于.NET Framework 中创建诸如`BackgroundWorker`和`WebClient`等组件。

实现这种模式的方法在后台异步执行长时间运行的任务，但通过事件不断通知用户它们的进度和状态，这就是为什么它们被称为基于事件的。

以下代码显示了一个使用 EAP 的组件的实现：

```cs
  private static void EAPImplementation()
        {
            var webClient = new WebClient();
            webClient.DownloadStringCompleted += (s, e) =>
            {
                if (e.Error != null)
                    Console.WriteLine(e.Error.Message);
                else if (e.Cancelled)
                    Console.WriteLine("Download Cancel");
                else
                    Console.WriteLine(e.Result);
            };
            webClient.DownloadStringAsync(new 
             Uri("http://www.someurl.com"));
        }
```

在前面的代码中，我们订阅了`DownloadStringCompleted`事件，一旦`webClient`从 URL 下载文件，该事件就会触发。正如你所看到的，我们尝试使用 if-else 结构来读取各种结果选项，如异常、取消和结果。与 APM 相比，将 EAP 转换为 TAP 更加棘手，因为它需要对 EAP 组件的内部性质有很好的理解，因为我们需要将新代码插入到正确的事件中使其工作。让我们来看一下转换后的实现：

```cs
private static Task<string> EAPToTask()
        {
            var taskCompletionSource = new TaskCompletionSource<string>();
            var webClient = new WebClient();
            webClient.DownloadStringCompleted += (s, e) =>
            {
                if (e.Error != null)
                    taskCompletionSource.TrySetException(e.Error);
                else if (e.Cancelled)
                    taskCompletionSource.TrySetCanceled();
                else
                    taskCompletionSource.TrySetResult(e.Result);
            };
            webClient.DownloadStringAsync(new 
             Uri("http://www.someurl.com"));
            return taskCompletionSource.Task;
        }
```

将 EAP 转换为 TAP 的最简单方法是使用`TaskCompletionSource`类。我们已经插入了所有的情景，并将结果、异常或取消结果设置为`TaskCompletionSource`类的实例。然后，我们将包装的实现作为任务返回给用户。

# 更多关于任务

现在，让我们学习一些关于任务的更重要的概念，这可能会派上用场。到目前为止，我们创建的任务是独立的。然而，为了创建更复杂的解决方案，有时我们需要在任务之间定义关系。我们可以创建子任务、子任务以及继续任务来做到这一点。让我们通过例子来理解每一个。在本节的后面，我们将学习有关线程存储和队列的知识。

# 继续任务

继续任务更像是承诺。当我们需要链接多个任务时，我们可以利用它们。第二个任务在第一个任务完成时开始，并且第一个任务的结果或异常被传递给子任务。我们可以链式地创建多个任务，也可以使用 TPL 提供的方法创建选择性的继续链。TPL 提供了以下任务继续构造：

+   `Task.ContinueWith`

+   `Task.Factory.ContinueWhenAll`

+   `Task.Factory.ContinueWhenAll<T>`

+   `Task.Factory.ContinueWhenAny`

+   `Task.Factory.ContinueWhenAny<T>`

# 使用 Task.ContinueWith 方法继续任务

通过 TPL 提供的`ContinueWith`方法可以轻松实现任务的继续。

让我们通过一个例子来理解简单的链接：

```cs
var task = Task.Factory.StartNew<DataTable>(() =>
       {
           Console.WriteLine("Fetching Data");
           return FetchData();
       }).ContinueWith(
           (e) => {
               var firstRow = e.Result.Rows[0];
               Console.WriteLine("Id is {0} and Name is {0}", 
                firstRow["Id"], firstRow["Name"]);
       });
```

在上面的例子中，我们需要获取并显示数据。**主任务**调用`FetchData`方法。当它完成时，结果作为输入传递给**继续任务**，负责打印数据。输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/7f9e4067-d9cf-4c5d-8f73-8e08028d1cf7.png)

我们也可以链式地创建多个任务，从而创建一系列任务，如下所示：

```cs
 var task = Task.Factory.StartNew<int>(() => GetData()).
             .ContinueWith((i) => GetMoreData(i.Result)).
             .ContinueWith((j) => DisplayData(j.Result)));
```

我们可以通过将`System.Threading.Tasks.TaskContinuationOptions`枚举作为参数传递来控制继续任务何时运行，该枚举具有以下选项：

+   `None`: 这是默认选项。当主任务完成时，继续任务将运行。

+   `OnlyOnRanToCompletion`: 当主任务成功完成时，继续任务将运行，这意味着它未被取消或出现故障。

+   `NotOnRanToCompletion`: 当主任务已被取消或出现故障时，继续任务将运行。

+   `OnlyOnFaulted`: 当主任务出现故障时，继续任务将运行。

+   `NotOnFaulted`: 当主任务未出现故障时，继续任务将运行。

+   `OnlyOnCancelled`: 当主任务已被取消时，继续任务将运行。

+   `NotOnCancelled`: 当主任务未被取消时，继续任务将运行。

# 使用 Task.Factory.ContinueWhenAll 和 Task.Factory.ContinueWhenAll<T>继续任务

我们可以等待多个任务，并链式地继续代码，只有当所有任务都成功完成时才会运行。让我们看一个例子：

```cs
 private async static void ContinueWhenAll()
        {
            int a = 2, b = 3;
            Task<int> taskA = Task.Factory.StartNew<int>(() => a * a);
            Task<int> taskB = Task.Factory.StartNew<int>(() => b * b);
            Task<int> taskC = Task.Factory.StartNew<int>(() => 2 * a * b);
            var sum = await Task.Factory.ContinueWhenAll<int>(new Task[] 
              { taskA, taskB, taskC }, (tasks)     
              =>tasks.Sum(t => (t as Task<int>).Result));
            Console.WriteLine(sum);
        }
```

在上面的代码中，我们想要计算`a*a + b*b +2 *a *b`。我们将任务分解为三个单元：`a*a`、`b*b`和`2*a*b`。每个单元由三个不同的线程执行：`taskA`、`taskB`和`taskC`。然后，我们等待所有任务完成，并将它们作为第一个参数传递给`ContinueWhenAll`方法。当所有线程完成执行时，由`ContinueWhenAll`方法的第二个参数指定的继续委托执行。继续委托对所有线程执行的结果进行求和，并将其返回给调用者，然后在下一行打印出来。

# 使用 Task.Factory.ContinueWhenAny 和 Task.Factory.ContinueWhenAny<T>继续任务

我们可以等待多个任务，并链式地继续代码，只有当任何一个任务成功完成时才会运行：

```cs
private static void ContinueWhenAny()
      {
          int number = 13;
          Task<bool> taskA = Task.Factory.StartNew<bool>(() => 
           number / 2 != 0);
          Task<bool> taskB = Task.Factory.StartNew<bool>(() => 
           (number / 2) * 2 != number);
          Task<bool> taskC = Task.Factory.StartNew<bool>(() => 
           (number & 1) != 0);
          Task.Factory.ContinueWhenAny<bool>(new Task<bool>[] 
           { taskA, taskB, taskC }, (task) =>
          {
              Console.WriteLine((task as Task<bool>).Result);
          }
        ); 
      }
```

如前面的代码所示，我们有三种不同的逻辑来判断一个数字是否为奇数。假设我们不知道哪种逻辑会最快。为了计算结果，我们创建了三个任务，每个任务封装了不同的奇数查找逻辑，并并发运行它们。由于一个数字同时可以是奇数或偶数，所有线程的结果将是相同的，但在执行速度上会有所不同。因此，只需获取第一个结果并丢弃其余结果是有意义的。这就是我们使用`ContinueWhenAny`方法实现的。

# 父任务和子任务

线程之间可能发生的另一种关系是父子关系。子任务作为父任务主体内的嵌套任务创建。子任务可以作为附加或分离创建。默认情况下，创建的任务是分离的。我们可以通过将任务的`AttachedToParent`属性设置为`true`来创建附加任务。您可能希望在以下情况之一中考虑创建附加任务：

+   所有在子任务中抛出的异常都需要传播到父任务

+   父任务的状态取决于子任务

+   父任务需要等待子任务完成

# 创建一个分离的任务

创建分离类的代码如下：

```cs
Task parentTask = Task.Factory.StartNew(() =>
 {
           Console.WriteLine(" Parent task started");
           Task childTask = Task.Factory.StartNew(() => {
               Console.WriteLine(" Child task started");
           });
           Console.WriteLine(" Parent task Finish");
       });
       //Wait for parent to finish
       parentTask.Wait();
       Console.WriteLine("Work Finished");
```

如您所见，我们在一个任务的主体内创建了另一个任务。默认情况下，子任务或嵌套任务是作为分离的创建的。我们通过调用`parentTask.Wait()`等待父任务完成。在以下输出中，您可以看到父任务不等待子任务完成，先完成，然后是子任务的开始：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/3b1d53c7-a4a2-40a7-8dcd-ef1160ffd33d.png)

# 创建一个附加任务

附加任务的创建方式与分离任务类似。唯一的区别是我们将任务的`AttachedParent`属性设置为`true`。这在以下代码片段中得到了演示：

```cs
     Task parentTask = Task.Factory.StartNew(() =>
            {
                Console.WriteLine("Parent task started");
                Task childTask = Task.Factory.StartNew(() => {
                    Console.WriteLine("Child task started");
                },TaskCreationOptions.AttachedToParent);
                Console.WriteLine("Parent task Finish");
            });
            //Wait for parent to finish
            parentTask.Wait();
            Console.WriteLine("Work Finished");
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/3d5d2a16-4cbe-48c5-8ecd-66c57980b423.png)

在这里，您可以看到父任务直到子任务执行完成才结束。

在本节中，我们讨论了任务的高级方面，包括创建任务之间的关系。在下一节中，我们将更深入地了解任务内部的工作，理解工作队列的概念以及任务如何处理它们。

# 工作窃取队列

工作窃取是线程池的性能优化技术。每个线程池维护一个任务的全局队列，这些任务是在进程内创建的。在第一章中，*并行编程简介*，我们了解到线程池维护了一定数量的工作线程来处理任务。`ThreadPool`还维护一个线程全局队列，在这里它将所有工作项排队，然后才能分配给可用线程。由于这是一个单一队列，并且我们在多线程场景中工作，我们需要使用同步原语来实现线程安全。由于存在单一全局队列，同步会导致性能损失。

.NET Framework 通过引入本地队列的概念来解决这种性能损失，本地队列由线程管理。每个线程都可以访问全局队列，并且还维护自己的线程本地队列来存储工作项。父任务可以在全局队列中调度。当任务执行并且需要创建子任务时，它们可以堆叠在本地队列上，并且在线程执行完成后立即使用 FIFO 算法进行处理。

下图描述了全局队列、本地队列、线程和`Threadpool`之间的关系：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/f8426a23-055d-4869-ba04-97bc06d88270.png)

假设主线程创建了一组任务。所有这些任务都排队到全局队列中，以便根据线程池中线程的可用性稍后执行。以下图表描述了带有所有排队任务的全局队列：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/df6416be-11a8-4b46-9021-b2016fb2b9e9.png)

假设**任务 1**被安排在**线程 1**上，**任务 2**被安排在**线程 2**上，依此类推，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/6dd8f4d1-e506-4240-9917-bf715c603c82.png)

如果**任务 1**和**任务 2**生成更多的任务，新任务将被存储在线程本地队列中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/d08e9c26-4b93-413a-8a96-3f403a3877a3.png)

同样，如果这些子任务创建了更多的任务，它们将进入本地队列而不是全局队列。一旦**线程 1**完成了**任务 1**，它将查看其本地队列并选择最后一个任务（LIFO）。最后一个任务可能仍然在缓存中，因此不需要重新加载。这再次提高了性能。

一旦线程（T1）耗尽了其本地队列，它将在全局队列中搜索。如果全局队列中没有项目，它将在其他线程（比如 T2）的本地队列中搜索。这种技术称为工作窃取，是一种优化技术。这次，它不会从 T2 中选择最后一个任务（LIFO），因为最后一个项目可能仍然在 T2 线程的缓存中。相反，它选择第一个任务（FIFO），因为线程已经移出了 T2 的缓存，这样可以提高性能。这种技术通过使缓存任务可用于本地线程和使缓存之外的任务可用于其他线程来提高性能。

# 总结

在本章中，我们讨论了如何将任务分解为更小的单元，以便每个单元可以由一个线程独立处理。我们还学习了利用`ThreadPool`创建任务的各种方法。我们介绍了与任务的内部工作相关的各种技术，包括工作窃取和任务创建或取消的概念。我们将在本书的其余部分利用本章中获得的知识。

在下一章中，我们将介绍数据并行性的概念。这将包括使用并行循环和处理其中的异常。


# 第三章：实现数据并行性

到目前为止，我们已经了解了并行编程、任务和任务并行性的基础知识。在本章中，我们将涵盖并行编程的另一个重要方面，即处理数据的并行执行：数据并行性。虽然任务并行性为每个参与线程创建了一个单独的工作单元，但数据并行性创建了一个由源集合中的每个参与线程执行的共同任务。这个源集合被分区，以便多个线程可以同时对其进行处理。因此，了解数据并行性对于从循环/集合中获得最大性能至关重要。

在本章中，我们将讨论以下主题：

+   在并行循环中处理异常

+   在并行循环中创建自定义分区策略

+   取消循环

+   理解并行循环中的线程存储

# 技术要求

要完成本章，您应该对 TPL 和 C#有很好的理解。本章的源代码可在 GitHub 上找到：[`github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter03`](https://github.com/PacktPublishing/Hands-On-Parallel-Programming-with-C-8-and-.NET-Core-3/tree/master/Chapter03)。

# 从顺序循环转换为并行循环

TPL 通过`System.Threading.Tasks.Parallel`类支持数据并行性，该类提供了`For`和`Foreach`循环的并行实现。作为开发人员，您不需要担心同步或创建任务，因为这由并行类处理。这种语法糖使您可以轻松地编写并行循环，方式类似于您一直在编写顺序循环。

以下是一个顺序`for`循环的示例，它通过将交易对象发布到服务器来预订交易：

```cs
foreach (var trade in trades)
{
    Book(trade);
}
```

由于循环是顺序的，完成循环所需的总时间是预订一笔交易所需的时间乘以交易的总数。这意味着随着交易数量的增加，循环会变慢，尽管交易预订时间保持不变。在这里，我们处理的是大量数据。由于我们将在服务器上预订交易，并且所有服务器都支持多个请求，将这个循环从顺序循环转换为并行循环是有意义的，因为这将给我们带来显著的性能提升。

可以将先前的代码转换为并行代码，如下所示：

```cs
Parallel.ForEach(trades, trade => Book(trade));
```

在运行并行循环时，TPL 对源集合进行分区，以便循环可以同时在多个部分上执行。任务的分区是由`TaskScheduler`类完成的，该类在创建分区时考虑系统资源和负载。我们还可以创建一个**自定义分区器**或**调度器**，正如我们将在本章的*创建自定义分区策略*部分中看到的。

数据并行性表现更好，如果分区单元是独立的。通过一种称为减少的技术，我们还可以创建依赖分区单元，以最小的性能开销将一系列操作减少为标量值。有三种方法可以将顺序代码转换为并行代码：

+   使用`Parallel.Invoke`方法

+   使用`Parallel.For`方法

+   使用`Parallel.ForEach`方法

让我们试着了解`Parallel`类可以用于展示数据并行性的各种方式。

# 使用 Parallel.Invoke 方法

这是以并行方式执行一组操作的最基本方式，也是并行`for`和`foreach`循环的基础。`Parallel.Invoke`方法接受一个操作数组作为参数并执行它们，尽管它不能保证操作将并行执行。在使用`Parallel.Invoke`时有一些重要的要点需要记住：

+   并行性不能保证。操作是并行执行还是按顺序执行将取决于`TaskScheduler`。

+   `Parallel.Invoke`不能保证传递的操作的顺序。

+   它会阻塞调用线程，直到所有的动作都完成。

`Parallel.Invoke`的语法如下：

```cs
public static void Invoke(
  params Action[] actions
)
```

我们可以传递一个动作或一个 lambda 表达式，如下例所示：

```cs
try
{
    Parallel.Invoke(() => Console.WriteLine("Action 1"),
    new Action(() => Console.WriteLine("Action 2")));
}
catch(AggregateException aggregateException)
{
    foreach (var ex in aggregateException.InnerExceptions)
    {
        Console.WriteLine(ex.Message);
    }
}
Console.WriteLine("Unblocked");
Console.ReadLine();         
```

`Invoke`方法的行为就像一个附加的子任务，因为它被阻塞，直到所有的动作都完成。所有的异常都被堆叠在`System.AggregateException`中，并抛出给调用者。在前面的代码中，由于没有异常，我们将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/66a69638-847b-4d6a-b800-164e267cc832.png)

我们可以使用`Task`类来实现类似的效果，尽管与`Parallel.Invoke`的工作方式相比，这可能看起来非常复杂：

```cs
Task.Factory.StartNew(() => {
     Task.Factory.StartNew(() => Console.WriteLine("Action 1"),        
     TaskCreationOptions.AttachedToParent);
     Task.Factory.StartNew(new Action(() => Console.WriteLine("Action 2"))
                        , TaskCreationOptions.AttachedToParent);
                        });
```

`Invoke`方法的行为就像一个附加的子任务，因为它被阻塞，直到所有的动作都完成。所有的异常都被堆叠在`System.AggregateException`中，并抛出给调用者。

# 使用 Parallel.For 方法

`Parallel.For`是顺序`for`循环的一个变体，不同之处在于迭代是并行运行的。`Parallel.For`返回`ParallelLoopResult`类的一个实例，一旦循环执行完成，它提供了循环完成状态。我们还可以检查`ParallelLoopResult`的`IsCompleted`和`LowestBreakIteration`属性，以找出方法是否已完成或取消，或者用户是否已调用了 break。以下是可能的情况：

| `IsCompleted` | `LowestBreakIteration` | **原因** |
| --- | --- | --- |
| True | N/A | 运行完成 |
| False | Null | 循环在匹配前停止 |
| False | 非空整数值 | 在循环中调用 Break |

`Parallel.For`方法的基本语法如下：

```cs
public static ParallelLoopResult For
{
    Int fromIncalme,
    Int toExclusiveme,            
    Action<int> action
}
```

这个例子如下所示：

```cs
Parallel.For (1, 100, (i) => Console.WriteLine(i));
```

如果你不想取消、中断或维护任何线程本地状态，并且执行顺序不重要，这种方法可能很有用。例如，想象一下我们想要计算今天在一个目录中创建的文件的数量。代码如下：

```cs
int totalFiles = 0;
var files = Directory.GetFiles("C:\\");
Parallel.For(0, files.Length, (i) =>
     {
       FileInfo fileInfo = new FileInfo(files[i]);
       if (fileInfo.CreationTime.Day == DateTime.Now.Day)                                                                          
        Interlocked.Increment(ref totalFiles);
     });
Console.WriteLine($"Total number of files in C: drive are {files.Count()} and  {totalFiles} files were created today.");
```

这段代码迭代了`C:`驱动器中的所有文件，并计算了今天创建的文件的数量。以下是我机器上的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/92b7e1f0-42cb-4454-a9c3-934b0957916c.png)

在下一节中，我们将尝试理解`Parallel.ForEach`方法，它提供了`ForEach`循环的并行变体。

对于一些集合，根据循环的语法和正在进行的工作的类型，顺序执行可能更快。

# 使用 Parallel.ForEach 方法

这是`ForEach`循环的一个变体，其中迭代可以并行运行。源集合被分区，然后工作被安排在多个线程上运行。`Parallel.ForEach`适用于通用集合，并且像`for`循环一样返回`ParallelLoopResult`。

`Parallel.ForEach`循环的基本语法如下：

```cs
Parallel.ForEach<TSource>(
    IEnumerable<TSource> Source,                                     
    Action<TSource> body
)
```

这个例子如下所示。我们有一个需要监视的端口列表。我们还需要更新它们的状态：

```cs
List<string> urls = new List<string>() {"www.google.com" , "www.yahoo.com","www.bing.com" };
Parallel.ForEach(urls, url =>
{
    Ping pinger = new Ping();
     Console.WriteLine($"Ping Url {url} status is {pinger.Send(url).Status} 
      by Task {Task.CurrentId}");
});
```

在前面的代码中，我们使用了`System.Net.NetworkInformation.Ping`类来 ping 一个部分，并在控制台上显示状态。由于这些部分是独立的，如果代码并行执行并且顺序也不重要，我们可以实现很好的性能。

以下屏幕截图显示了前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/2c68ea2f-feb9-4743-b703-c664e1ecca89.png)

并行性可能会使单核处理器上的应用程序变慢。我们可以通过使用并行度来控制并行操作中可以利用多少核心，接下来我们将介绍这个。

# 理解并行度

到目前为止，我们已经学习了数据并行性如何使我们能够在系统的多个核心上并行运行循环，从而有效利用可用的 CPU 资源。您应该知道还有另一个重要的概念，可以用来控制您想要在循环中创建多少任务。这个概念叫做并行度。这是一个指定可以由并行循环创建的最大任务数的数字。您可以通过一个名为`MaxDegreeOfParallelism`的属性来设置并行度，这是`ParallelOptions`类的一部分。以下是`Parallel.For`的语法，您可以通过它传递`ParallelOptions`实例：

```cs
public static ParallelLoopResult For(
        int fromInclusive,
        int toExclusive,
        ParallelOptions parallelOptions,
        Action<int> body
)
```

以下是`Parallel.For`和`Parallel.ForEach`方法的语法，您可以通过它传递`ParallelOptions`实例：

```cs
public static ParallelLoopResult ForEach<TSource>(
        IEnumerable<TSource> source,
        ParallelOptions parallelOptions,
        Action<TSource> body
)
```

并行度的默认值为 64，这意味着并行循环可以通过创建这么多任务来利用系统中多达 64 个处理器。我们可以修改这个值来限制任务的数量。让我们通过一些例子来理解这个概念。

让我们看一个`MaxDegreeOfParallelism`设置为`4`的`Parallel.For`循环的例子：

```cs
Parallel.For(1, 20, new ParallelOptions { MaxDegreeOfParallelism = 4 }, index =>
             {
                 Console.WriteLine($"Index {index} executing on Task Id 
                  {Task.CurrentId}");
             });
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/474f3ac2-6330-44fa-b6e1-4560c509c1de.png)

正如您所看到的，循环由四个任务执行，分别用任务 ID 1、2、3 和 4 表示。

这是一个`MaxDegreeOfParallelism`设置为`4`的`Parallel.ForEach`循环的例子：

```cs
var items = Enumerable.Range(1, 20); 
Parallel.ForEach(items, new ParallelOptions { MaxDegreeOfParallelism = 4 }, item =>
           {
               Console.WriteLine($"Index {item} executing on Task Id 
                {Task.CurrentId}");
           });
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/8dcc5f47-7a0e-481d-b2f2-c6247b60d8ba.png)

正如您所看到的，这个循环由四个任务执行，分别用任务 ID 1、2、3 和 4 表示。

我们应该修改这个设置以适应高级场景，例如我们知道运行的算法不能跨越超过一定数量的处理器。如果我们同时运行多个算法并且希望限制每个算法只利用一定数量的处理器，我们也应该修改这个设置。接下来，我们将学习如何通过引入分区策略的概念在集合中创建自定义分区。

# 创建自定义分区策略

分区是数据并行性中的另一个重要概念。为了在源集合中实现并行性，它需要被分割成称为范围或块的较小部分，这些部分可以被各个线程同时访问。没有分区，循环将串行执行。分区器可以分为两类，我们也可以创建自定义分区器。这些类别如下：

+   范围分区

+   块分区

让我们详细讨论这些。

# 范围分区

这种类型的分区主要用于长度预先已知的集合。顾名思义，每个线程都会得到一系列元素来处理，或者源集合的起始和结束索引。这是分区的最简单形式，在某种程度上非常高效，因为每个线程都会执行其范围而不会覆盖其他线程。虽然在创建范围时会有一些性能损失，但没有同步开销。这种类型的分区在每个范围中的元素数量相同时效果最佳，这样它们将花费相似的时间来完成。对于不同数量的元素，一些任务可能会提前完成并处于空闲状态，而其他任务可能在范围内有很多待处理的元素。

# 块分区

这种类型的分区主要用于`LinkedList`等集合，其中长度事先不知道。分块分区在您有不均匀的集合的情况下提供更多的负载平衡。每个线程都会挑选一块元素进行处理，然后再回来挑选其他线程尚未挑选的另一块。块的大小取决于分区器的实现，并且有同步开销来确保分配给两个线程的块不包含重复项。

我们可以更改`Parallel.ForEach`循环的默认分区策略，以执行自定义的分块分区，如下例所示：

```cs
var source = Enumerable.Range(1, 100).ToList();
OrderablePartitioner<Tuple<int,int>> orderablePartitioner= Partitioner.Create(1, 100);
Parallel.ForEach(orderablePartitioner, (range, state) =>
            {
              var startIndex = range.Item1;
              var endIndex = range.Item2;
              Console.WriteLine($"Range execution finished on task 
               {Task.CurrentId} with range 
               {startRange}-{endRange}");
            });
```

在前面的代码中，我们使用`OrderablePartitioner`类在一系列项目（这里是从`1`到`100`）上创建了分块分区器。我们将分区器传递给`ForEach`循环，其中每个块都传递给一个线程并执行。输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/966e964a-5049-40d9-8b2e-8721b689bf52.png)

到目前为止，我们对并行循环的工作原理有了很好的理解。现在，我们需要讨论一些高级概念，以便更多地了解如何控制循环执行；也就是说，如何根据需要停止循环。

# 取消循环

我们在顺序循环中使用了`break`和`continue`等结构；`break`用于通过完成当前迭代并跳过其余部分来跳出循环，而`continue`则跳过当前迭代并移动到其余的迭代。这些结构可以使用，因为顺序循环由单个线程执行。在并行循环的情况下，我们不能使用`break`和`continue`关键字，因为它们在多个线程或任务上运行。要中断并行循环，我们需要使用`ParallelLoopState`类。要取消循环，我们需要使用`CancellationToken`和`ParallelOptions`类。

在本节中，我们将讨论取消循环所需的选项：

+   `Parallel.Break`

+   `ParallelLoopState.Stop`

+   `CancellationToken`

让我们开始吧！

# 使用 Parallel.Break 方法

`Parallel.Break`试图模仿顺序执行的结果。让我们看看如何从并行循环中`break`。在以下代码中，我们需要搜索一个数字列表以查找特定数字。当找到匹配项时，我们需要中断循环的执行：

```cs
     var numbers = Enumerable.Range(1, 1000);
     int numToFind = 2;
     Parallel.ForEach(numbers, (number, parallelLoopState) =>
     {
           Console.Write(number + "-");
           if (number == numToFind)
           {
                Console.WriteLine($"Calling Break at {number}");
                parallelLoopState.Break();
           }
      });       
```

如前面的代码所示，循环应该在找到数字`2`之前运行。使用顺序循环，它将在第二次迭代时精确中断。对于并行循环，由于迭代在多个任务上运行，实际上会打印出大于 2 的值，如下面的输出所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/91ed685a-4c48-476c-a30b-ec96de9ba817.png)

为了跳出循环，我们调用了`parallelLoopState.Break()`，它试图模仿顺序循环中实际`break`关键字的行为。当任何一个核心遇到`Break()`方法时，它将在**`ParallelLoopState`**对象的`LowestBreakIteration`属性中设置一个迭代号。这成为可以执行的最大数字或最后一个迭代。所有其他任务将继续迭代，直到达到这个数字。

通过并行运行迭代来连续调用`Break`方法，进一步减少`LowestBreakIteration`，如下面的代码所示：

```cs
            var numbers = Enumerable.Range(1, 1000);
            Parallel.ForEach(numbers, (i, parallelLoopState) =>
            {
                Console.WriteLine($"For i={i} LowestBreakIteration =     
                  {parallelLoopState.LowestBreakIteration} and 
                  Task id ={Task.CurrentId}");
                if (i >= 10)
                {
                    parallelLoopState.Break();
                }
            });
```

当我们在 Visual Studio 中运行前面的代码时，我们会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/e418c044-fbe9-43ae-ac1a-6fff50149ec2.png)

在这里，我们在多核处理器上运行代码。正如您所看到的，许多迭代得到了`LowestBreakIteration`的空值，因为代码是在多个核上执行的。在第 17 次迭代时，一个核心调用了`Break()`方法，并将`LowestBreakIteration`的值设置为 17。在第 10 次迭代时，另一个核心调用`Break()`并进一步将数字减少到 10。后来，在第 9 次迭代时，另一个核心调用了`Break()`，并进一步将数字减少到 9。

# 使用 ParallelLoopState.Stop

如果你不想模仿顺序循环的结果，而是想尽快退出循环，你可以调用`ParallelLoopState.Stop`。就像我们用`Break()`方法一样，所有并行运行的迭代在循环退出之前都会完成：

```cs
var numbers = Enumerable.Range(1, 1000);
Parallel.ForEach(numbers, (i, parallelLoopState) =>
         {
                Console.Write(i + " ");
                if (i % 4 == 0)
                {
                    Console.WriteLine($"Loop Stopped on {i}");
                    parallelLoopState.Stop();
                }
         });
```

在 Visual Studio 中运行上述代码时，输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/1b495524-49e8-4c5e-8298-8080775a6477.png)

正如你所看到的，一个核心在第 4 次迭代时调用了`Stop`，另一个核心在第 8 次迭代时调用了`Stop`，第三个核心在第 12 次迭代时调用了`Stop`。迭代 3 和 10 仍然执行，因为它们已经被安排执行。

# 使用 CancellationToken 取消循环

与普通任务一样，我们可以使用`CancellationToken`类来取消`Parallel.For`和`Parallel.ForEach`循环。当我们取消令牌时，循环将完成当前可能并行运行的迭代，但不会开始新的迭代。一旦现有的迭代完成，并行循环会抛出`OperationCanceledException`。

让我们举个例子来看看。首先，我们将创建一个取消令牌源：

```cs
CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
```

然后，我们将创建一个在五秒后取消令牌的任务：

```cs
Task.Factory.StartNew(() =>
{
    Thread.Sleep(5000);
    cancellationTokenSource.Cancel();
    Console.WriteLine("Token has been cancelled");
});
```

之后，我们将通过传递取消令牌来创建一个并行选项对象：

```cs
ParallelOptions loopOptions = new ParallelOptions()
{
    CancellationToken = cancellationTokenSource.Token
};
```

接下来，我们将运行一个持续时间超过五秒的操作：

```cs
try
{
    Parallel.For(0, Int64.MaxValue, loopOptions, index =>
    {
        Thread.Sleep(3000);
        double result = Math.Sqrt(index);
        Console.WriteLine($"Index {index}, result {result}");
    });
}
catch (OperationCanceledException)
{
    Console.WriteLine("Cancellation exception caught!");
}
```

在 Visual Studio 中运行上述代码时，输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/4ee931bb-5b0f-4c54-9af4-599b99d77aec.png)

正如你所看到的，即使取消令牌已被调用，预定的迭代仍然会执行。希望这能让你对我们如何根据程序要求取消循环有一个很好的理解。并行编程的另一个重要方面是存储的概念。我们将在下一节讨论这个问题。

# 理解并行循环中的线程存储

默认情况下，所有并行循环都可以访问全局变量。然而，访问全局变量会带来同步开销，因此在可能的情况下，最好使用线程范围的变量。我们可以创建一个**线程本地**或**分区本地**变量来在并行循环中使用。

# 线程本地变量

线程本地变量就像特定任务的全局变量。它们的生命周期跨越循环要执行的迭代次数。

在下面的例子中，我们将使用`for`循环来查看线程本地变量。在`Parallel.For`循环的情况下，会创建多个任务来运行迭代。假设我们需要通过并行循环找出 60 个数字的总和。

举个例子，假设有四个任务，每个任务有 15 次迭代。实现这一点的一种方法是创建一个全局变量。每次迭代后，运行的任务都应该更新全局变量。这将需要同步开销。对于四个任务，将会有四个对每个任务私有的线程本地变量。任务将更新变量，并且最后更新的值可以返回给调用程序，然后可以用来更新全局变量。

以下是要遵循的步骤：

1.  创建一个包含 60 个数字的集合，其中每个项目的值都等于索引：

```cs
var numbers = Enumerable.Range(1, 60);
```

1.  创建一个完成的操作，一旦任务完成了所有分配的迭代，就会执行。该方法将接收线程本地变量的最终结果，并将其添加到全局变量`sumOfNumbers`中：

```cs
long sumOfNumbers = 0;
Action<long> taskFinishedMethod = (taskResult) => 
{
    Console.WriteLine($"Sum at the end of all task iterations for task 
     {Task.CurrentId} is {taskResult}");
    Interlocked.Add(ref sumOfNumbers, taskResult);
};
```

1.  创建一个`For`循环。前两个参数是`startIndex`和`endIndex`。第三个参数是一个委托，为线程本地变量提供种子值。这是一个需要任务执行的操作。在我们的例子中，我们只是将索引分配给`subtotal`，这是我们的线程本地变量。

假设有一个任务*TaskA*，它获取索引从 1 到 5 的迭代。*TaskA*将这些迭代相加为 1+2+3+4+5。这等于 15，将作为任务的结果返回，并作为参数传递给`taskFinishedMethod`：

```cs
Parallel.For(0,numbers.Count(), 
                         () => 0,
                         (j, loop, subtotal) =>
                         {
                              subtotal += j;
                              return subtotal;
                         },
                         taskFinishedMethod
);
Console.WriteLine($"The total of 60 numbers is {sumOfNumbers}");
```

在 Visual Studio 中运行上述代码时，输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-prl-prog-cs8-dncore3/img/bb6fdaca-40ff-4b89-864b-d7d9465f0e1d.png)

请记住，输出可能因可用核心数量不同而在不同的机器上有所不同。

# 分区本地变量

这类似于线程本地变量，但适用于分区。正如您所知，`ForEach`循环将源集合分成多个分区。每个分区将有其自己的分区本地变量副本。对于线程本地变量，每个线程只有一个变量副本。然而，在这里，由于单个线程上可以运行多个分区，因此每个线程可以有多个副本。

首先，我们需要创建一个`ForEach`循环。第一个参数是源集合，即数字。第二个参数是为线程本地变量提供种子值的委托。第三个参数是任务需要执行的操作。在我们的情况下，我们只是将索引分配给`subtotal`，这是我们的线程本地变量。

为了理解，假设有一个任务*TaskA*，它获取索引从 1 到 5 的迭代。*TaskA*将这些迭代相加，即 1+2+3+4+5。这等于 15，将作为任务的结果返回，并作为参数传递给`taskFinishedMethod`。

以下是代码：

```cs
Parallel.ForEach<int, long>(numbers,
    () => 0, // method to initialize the local variable
    (j, loop, subtotal) => // Action performed on each iteration
    {
        subtotal += j; //Subtotal is Thread local variable
        return subtotal; // value to be passed to next iteration
    },
    taskFinishedMethod);
Console.WriteLine($"The total of 60 numbers is {sumOfNumbers}");
```

同样，在这种情况下，输出将因可用核心数量不同而在不同的机器上有所不同。

# 总结

在本章中，我们详细介绍了使用 TPL 实现任务并行性。我们首先介绍了如何使用 TPL 提供的一些内置方法，如`Parallel.Invoke`、`Parallel.For`和`Parallel.ForEach`，将顺序循环转换为并行循环。接下来，我们讨论了如何通过了解并行度和分区策略来充分利用可用的 CPU 资源。然后，我们讨论了如何使用内置构造（如取消标记、`Parallel.Break`和`ParallelLoopState.Stop`）取消并跳出并行循环。在本章末尾，我们讨论了 TPL 中可用的各种线程存储选项。

TPL 提供了一些非常令人兴奋的选项，我们可以通过`For`和`ForEach`循环的并行实现来实现数据并行性。除了`ParallelOptions`和`ParallelLoopState`等功能外，我们还可以在不丢失太多同步开销的情况下实现显著的性能优势和控制。

在下一章中，我们将看到并行库的另一个令人兴奋的特性，称为**PLINQ**。

# 问题

1.  以下哪个不是 TPL 中提供`for`循环的正确方法？

1.  `Parallel.Invoke`

1.  `Parallel.While`

1.  `Parallel.For`

1.  `Parallel.ForEach`

1.  哪个不是默认的分区策略？

1.  批量分区

1.  范围分区

1.  块分区

1.  并行度的默认值是多少？

1.  1

1.  64

1.  `Parallel.Break`保证一旦执行就立即返回。

1.  真

1.  假

1.  一个线程能看到另一个线程的线程本地或分区本地值吗？

1.  是

1.  不
