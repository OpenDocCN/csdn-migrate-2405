# C# 代码整洁指南（五）

> 原文：[`zh.annas-archive.org/md5/0768F2F2E3C709CF4014BAB4C5A2161B`](https://zh.annas-archive.org/md5/0768F2F2E3C709CF4014BAB4C5A2161B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：使用工具来提高代码质量

作为程序员，提高代码质量是您的主要关注点之一。提高代码质量需要利用各种工具。旨在改进代码并加快开发速度的工具包括代码度量衡、快速操作、JetBrains dotTrace 分析器、JetBrains ReSharper 和 Telerik JustDecompile。

这是本章的主要内容，包括以下主题：

+   定义高质量的代码

+   执行代码清理和计算代码度量衡

+   执行代码分析

+   使用快速操作

+   使用 JetBrains dotTrace 分析器

+   使用 JetBrains ReSharper

+   使用 Telerik JustDecompile

通过本章结束时，您将掌握以下技能：

+   使用代码度量衡来衡量软件复杂性和可维护性

+   使用快速操作进行更改

+   使用 JetBrains dotTrace 对代码进行分析和瓶颈分析

+   使用 JetBrains ReSharper 重构代码

+   使用 Telerik JustDecompile 对代码进行反编译和生成解决方案

# 技术要求

+   本书的源代码：[`github.com/PacktPublishing/Clean-Code-in-C-`](https://github.com/PacktPublishing/Clean-Code-in-C-)

+   Visual Studio 2019 社区版或更高版本：[`visualstudio.microsoft.com/downloads/`](https://visualstudio.microsoft.com/downloads/)

+   Telerik JustDecompile：[`www.telerik.com/products/decompiler.aspx`](https://www.telerik.com/products/decompiler.aspx)

+   JetBrains ReSharper Ultimate：[`www.jetbrains.com/resharper/download/#section=resharper-installer`](https://www.jetbrains.com/resharper/download/#section=resharper-installer)

# 定义高质量的代码

良好的代码质量是一种重要的软件属性。低质量的代码可能导致财务损失、时间和精力浪费，甚至死亡。高标准的代码将具有性能、可用性、安全性、可扩展性、可维护性、可访问性、可部署性和可扩展性（PASSMADE）的特质。

高性能的代码体积小，只做必要的事情，并且非常快。高性能的代码不会导致系统崩溃。导致系统崩溃的因素包括文件输入/输出（I/O）操作、内存使用和中央处理单元（CPU）使用。性能低下的代码适合重构。

可用性指的是软件在所需性能水平上持续可用。可用性是软件功能时间（tsf）与预期功能总时间（ttef）之比，例如，tsf=700；ttef=744。700 / 744 = 0.9409 = 94.09%的可用性。

安全的代码是指正确验证输入以防止无效数据格式、无效范围数据和恶意攻击，并完全验证和授权其用户的代码。安全的代码也是容错的代码。例如，如果正在从一个账户转账到另一个账户，系统崩溃了，操作应确保数据保持完整，不会从相关账户中取走任何钱。

可扩展的代码是指能够安全处理系统用户数量呈指数增长，而不会导致系统崩溃的代码。因此，无论软件每小时处理一个请求还是一百万个请求，代码的性能都不会下降，也不会因过载而导致停机。

可维护性指的是修复错误和添加新功能的难易程度。可维护的代码应该组织良好，易于阅读。应该低耦合，高内聚，以便代码可以轻松维护和扩展。

可访问的代码是指残障人士可以轻松修改和根据自己的需求使用的代码。例如，具有高对比度的用户界面，为诵读困难和盲人提供的叙述者等。

可部署性关注软件的用户——用户是独立的、远程访问的还是本地网络用户？无论用户类型如何，软件都应该非常容易部署，没有任何问题。

可扩展性指的是通过向应用程序添加新功能来扩展应用程序的容易程度。意大利面代码和高度耦合的代码与低内聚度使这变得非常困难且容易出错。这样的代码很难阅读和维护，也不容易扩展。因此，可扩展的代码是易于阅读、易于维护的代码，因此也易于添加新功能。

从优质代码的 PASSMADE 要求中，您可以轻松推断出未能满足这些要求可能导致的问题。未能满足这些要求将导致性能不佳的代码变得令人沮丧和无法使用。客户会因增加的停机时间而感到恼火。黑客可以利用不安全的代码中的漏洞。随着更多用户加入系统，软件会呈指数级下降。代码将难以修复或扩展，在某些情况下甚至无法修复或扩展。能力有限的用户将无法修改其限制周围的软件，并且部署将成为配置噩梦。

代码度量来拯救。代码度量使开发人员能够衡量代码复杂性和可维护性，从而帮助我们识别需要重构的代码。

使用快速操作，您可以使用单个命令重构 C#代码，例如将代码提取到自己的方法中。JetBrains dotTrace 允许您分析代码并找到性能瓶颈。此外，JetBrains ReSharper 是 Visual Studio 的生产力扩展，使您能够分析代码质量、检测代码异味、强制执行编码标准并重构代码。而 Telerik JustDecompile 则帮助您反编译现有代码进行故障排除，并从中创建中间语言（IL）、C#和 VB.NET 项目。如果您不再拥有源代码并且需要维护或扩展已编译的代码，这将非常有用。您甚至可以为编译后的代码生成调试符号。

让我们深入了解一下提到的工具，首先是代码度量。

# 执行代码清理和计算代码度量

在我们看如何收集代码度量之前，我们首先需要知道它们是什么，以及它们对我们有何用处。代码度量主要涉及软件复杂性和可维护性。它们帮助我们看到如何改进源代码的可维护性并减少源代码的复杂性。

Visual Studio 2019 为您计算的代码度量包括以下内容：

+   可维护性指数：代码可维护性是“应用生命周期管理”（ALM）的重要组成部分。在软件达到寿命终点之前，必须对其进行维护。代码基础越难以维护，源代码在完全替换之前的寿命就越短。与维护现有系统相比，编写新软件以替换不健康的系统需要更多的工作，也更昂贵。代码可维护性的度量称为可维护性指数。该值是 0 到 100 之间的整数值。以下是可维护性指数的评级、颜色和含义：

+   20 及以上的任何值都具有良好可维护性的绿色评级。

+   可维护性一般的代码在 10 到 19 之间，评级为黄色。

+   任何低于 10 的值都具有红色评级，意味着它很难维护。

+   圈复杂度：代码复杂度，也称为圈复杂度，指的是软件中的各种代码路径。路径越多，软件就越复杂。软件越复杂，测试和维护就越困难。复杂的代码可能导致更容易出错的软件发布，并且可能使软件的维护和扩展变得困难。因此，建议将代码复杂度保持在最低限度。

+   继承深度：继承深度和类耦合度受到了一种流行的编程范式的影响，称为面向对象编程（OOP）。在 OOP 中，类能够从其他类继承。被继承的类称为基类。从基类继承的类称为子类。每个类相互继承的数量度量被称为继承深度。

继承层次越深，如果基类中的某些内容发生变化，派生类中出现错误的可能性就越大。理想的继承深度是 1。

+   类耦合：面向对象编程允许类耦合。当一个类被参数、局部变量、返回类型、方法调用、泛型或模板实例化、基类、接口实现、在额外类型上定义的字段和属性装饰直接引用时，就会产生类耦合。

类耦合代码度量确定了类之间的耦合程度。为了使代码更易于维护和扩展，类耦合应该尽量减少。在面向对象编程中，实现这一点的一种方法是使用基于接口的编程。这样，您可以避免直接访问类。这种编程方法的好处是，只要它们实现相同的接口，您就可以随意替换类。质量低劣的代码具有高耦合和低内聚，而高质量的代码具有低耦合和高内聚。

理想情况下，软件应该具有高内聚性和低耦合性，因为这样可以使程序更容易测试、维护和扩展。

+   源代码行数：源代码的完整行数，包括空行，由源代码行数度量。

+   可执行代码行数：可执行代码中的操作数量由可执行代码行数度量。

现在，您已经了解了代码度量是什么，以及 Visual Studio 2019 版本 16.4 及更高版本中提供了哪些度量，现在是时候看到它们的实际效果了：

1.  在 Visual Studio 中打开任何您喜欢的项目。

1.  右键单击项目。

1.  选择分析和代码清理|运行代码清理（Profile 1），如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/3084d347-1840-4623-b317-93e84e4a3333.png)

1.  现在，选择计算代码度量。

1.  您应该看到代码度量结果窗口出现，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/0072829c-42dd-4d15-bdb7-62df99180ec1.png)

如截图所示，我们所有的类、接口和方法都标有绿色指示器。这意味着所选的项目是可维护的。如果其中任何一行标记为黄色或红色，那么您需要解决它们并重构它们以使其变为绿色。好了，我们已经介绍了代码度量，因此自然而然地，我们继续介绍代码分析。

# 执行代码分析

为了帮助开发人员识别其源代码的潜在问题，微软提供了 Visual Studio 的代码分析工具。代码分析执行静态源代码分析。该工具将识别设计缺陷、全球化问题、安全问题、性能问题和互操作性问题。

打开书中的解决方案，并选择 CH11_AddressingCrossCuttingConcerns 项目。然后，从项目菜单中选择项目|CH11_AddressingCrossCuttingConcerns |属性。在项目的属性页面上，选择代码分析，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/845a8cb0-51c3-4c8c-86aa-227357896190.png)

如上面的截图所示，如果您发现推荐的分析器包未安装，请单击“安装”进行安装。安装后，版本号将显示在已安装版本框中。对我来说，它是版本 2.9.6。默认情况下，活动规则是 Microsoft 托管推荐规则。如描述中所示，此规则集的位置是 C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Team Tools\Static Analysis Tools\Rule Sets\MinimumRecommendedRules.ruleset。打开文件。它将作为 Visual Studio 工具窗口打开，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/6e77dab0-0c68-4f3b-9cb3-e2c4c151e744.png)

如上面的截图所示，您可以选择和取消选择规则。关闭窗口时，将提示您保存任何更改。要运行代码分析，转到分析和代码清理|代码分析。要查看结果，需要打开错误列表窗口。您可以从“视图”菜单中打开它。

一旦您运行了代码分析，您将看到错误、警告和消息的列表。您可以处理每一个，以提高软件的整体质量。以下截图显示了其中一些示例：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/ce41fac1-0f57-4161-bdce-80454882fa47.png)

从上面的截图中，您可以看到`CH10_AddressingCrossCuttingConcerns`项目有*32 个警告和 13 个消息*。如果我们处理这些警告和消息，就可以将它们减少到 0 个消息和 0 个警告。因此，现在您已经知道如何使用代码度量来查看软件的可维护性，并对其进行分析以了解您可以做出哪些改进，现在是时候看看快速操作了。

# 使用快速操作

另一个我喜欢使用的方便工具是快速操作工具。在代码行上显示为螺丝刀![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/879fde26-23f4-46ce-a945-b990c87ea7b2.png)，灯泡![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/e1db92fb-dc9b-4b31-8ab6-869d769ee72d.png)，或错误灯泡![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/006b25b8-4e48-4dbb-9c13-708d087aa336.png)，快速操作使您能够使用单个命令生成代码，重构代码，抑制警告，执行代码修复，并添加`using`语句。

由于`CH10_AddressingCrossCuttingConcerns`项目有 32 个警告和 13 个消息，我们可以使用该项目来查看快速操作的效果。看看下面的截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/edbf7964-0014-4776-bd6c-5f535045eb67.png)

看看上面的截图，我们看到第 10 行的灯泡。如果我们点击灯泡，将弹出以下菜单：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/022c0406-d6cc-41eb-abaf-27bd8f8fe633.png)

如果我们点击“添加 readonly 修饰符”，`readonly`访问修饰符将放置在私有访问修饰符之后。尝试使用快速操作修改代码。一旦掌握了，这是相当简单的。一旦您尝试了快速操作，就可以继续查看 JetBrains dotTrace 分析工具。

# 使用 JetBrains dotTrace 分析工具

JetBrains dotTrace 分析工具是 JetBrains ReSharper Ultimate 许可的一部分。因为我们将同时查看这两个工具，我建议您在继续之前下载并安装 JetBrains ReSharper Ultimate。

如果您还没有拥有副本，JetBrains 确实有试用版本可用。Windows、macOS 和 Linux 都有可用的版本。

JetBrains dotTrace 分析工具适用于 Mono、.NET Framework 和.NET Core。分析工具支持所有应用程序类型，您可以使用分析工具分析和跟踪代码库的性能问题。分析工具将帮助您解决导致 CPU 使用率达到 100%、磁盘 I/O 达到 100%、内存达到最大或遇到溢出异常等问题。

许多应用程序执行超文本传输协议（HTTP）请求。性能分析器将分析应用程序如何处理这些请求，并对数据库上的结构化查询语言（SQL）查询进行相同的分析。还可以对静态方法和单元测试进行性能分析，并可以在 Visual Studio 中查看结果。还有一个独立版本供您使用。

有四种基本的性能分析选项——Sampling、Tracing、Line-by-Line 和 Timeline。第一次开始查看应用程序的性能时，您可能决定使用 Sampling，它提供了准确的调用时间测量。Tracing 和 Line-by-Line 提供了更详细的性能分析，但会给被分析的程序增加更多开销（内存和 CPU 使用）。Timeline 类似于 Sampling，并会随时间收集应用程序事件。在它们之间，没有无法追踪和解决的问题。

高级性能分析选项包括实时性能计数器、线程时间、实时 CPU 指令和线程周期时间。实时性能计数器测量方法进入和退出之间的时间。线程时间测量线程运行时间。基于 CPU 寄存器，实时 CPU 指令提供了方法进入和退出的准确时间。

性能分析器可以附加到正在运行的.NET Framework 4.0（或更高版本）或.NET Core 3.0（或更高版本）应用程序和进程，对本地应用程序和远程应用程序进行性能分析。这些包括独立应用程序；.NET Core 应用程序；Internet 信息服务（IIS）托管的 Web 应用程序；IIS Express 托管的应用程序；.NET Windows 服务；Windows 通信基础（WCF）服务；Windows 商店和通用 Windows 平台（UWP）应用程序；任何.NET 进程（在运行性能分析会话后启动）；基于 Mono 的桌面或控制台应用程序；以及 Unity 编辑器或独立的 Unity 应用程序。

要在 Visual Studio 2019 中从菜单中访问性能分析器，请选择 Extensions | ReSharper | Profile | Show Performance Profiler。在下面的截图中，您可以看到尚未进行性能分析。当前选择要进行性能分析的项目设置为 Basic CH3，并且性能分析类型设置为 Timeline。我们将使用 Sampling 对 CH3 进行性能分析，通过展开时间轴下拉功能并选择 Sampling，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/8647fbeb-0249-480f-b79c-7d4c03df2f1d.png)

如果要对不同的项目进行采样，请展开项目下拉列表并选择要进行性能分析的项目。项目将被构建，并启动性能分析器。然后您的项目将运行并关闭。结果将显示在 dotTrace 性能分析应用程序中，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/38f49eb2-a59e-4ae7-a6cb-90c767ffd1e4.png)

从上面的截图中，您可以看到四个线程中的第一个线程。这是我们程序的线程。其他线程是支持进程的线程，这些支持进程使我们的程序能够运行，还有负责退出程序并清理系统资源的 finalizer 线程。

左侧的所有调用菜单项包括以下内容：

+   线程树

+   调用树

+   普通列表

+   热点

当前选项选择了线程树。让我们来看看下面截图中展开的调用树：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/97e6fb4a-a0e3-435d-a26d-d78c0396b512.png)

性能分析器为您的代码显示完整的调用树，包括系统代码和您自己的代码。您可以看到调用所花费的时间百分比。这使您能够识别任何运行时间较长的方法并加以解决。

现在，我们来看看普通列表。如下面截图中的普通列表视图所示，我们可以根据以下标准对其进行分组：

+   无

+   类

+   命名空间

+   程序集

您可以在下面的屏幕截图中看到前面的标准：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/5cb7c40f-d8ac-4ced-9ae4-e0ddb8135d41.png)

当您点击列表中的项目时，您可以查看包含该方法的类的源代码。这很有用，因为您可以看到问题所在的代码以及需要做什么。我们将看到的最后一个采样配置文件屏幕是热点视图，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/e71a1ce2-79bd-485e-aedd-b7e3686de601.png)

性能分析器显示，主线程（我们代码的起点）只占用了 4.59%的处理时间。如果您点击根，我们的用户代码占了 18%的代码，系统代码占了 72%的代码，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/bba028e6-5545-492f-9e35-34bf7eb90b1a.png)

我们只是用这个性能分析工具触及到了表面。还有更多内容，我鼓励您自己尝试一下。本章的主要目的是向您介绍可用的工具。

有关如何使用 JetBrains dotTrace 的更多信息，我建议您参考他们的在线学习材料，网址为[`www.jetbrains.com/profiler/documentation/documentation.html`](https://www.jetbrains.com/profiler/documentation/documentation.html)。

接下来，我们来看看 JetBrains ReSharper。

# 使用 JetBrains ReSharper

在这一部分，我们将看看 JetBrains ReSharper 如何帮助您改进您的代码。 ReSharper 是一个非常广泛的工具，就像性能分析器一样，它是 ReSharper 的旗舰版的一部分，我们只会触及到表面，但您希望能够欣赏到这个工具是什么，以及它如何帮助您改进您的 Visual Studio 编码体验。以下是使用 ReSharper 的一些好处：

+   使用 ReSharper，您可以对代码质量进行分析。

+   它将提供改进代码、消除代码异味和修复编码问题的选项。

+   通过导航系统，您可以完全遍历您的解决方案并跳转到任何感兴趣的项目。您有许多不同的辅助工具，包括扩展的智能感知、代码重组等。

+   ReSharper 的重构功能可以是局部的，也可以是整个解决方案的。

+   您还可以使用 ReSharper 生成源代码，例如基类和超类，以及内联方法。

+   在这里，可以根据公司的编码政策清理代码，以消除未使用的导入和其他未使用的代码。

您可以从 Visual Studio 2019 扩展菜单中访问 ReSharper 菜单。在代码编辑器中，右键单击代码片段将显示上下文菜单，其中包含适当的菜单项。上下文菜单中的 ReSharper 菜单项是 Refactor This...，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/62d9b26f-b6e6-45f3-8575-106fddc2b60e.png)

现在，从 Visual Studio 2019 菜单中运行扩展 | ReSharper | 检查 | 解决方案中的代码问题。 ReSharper 将处理解决方案，然后显示检查结果窗口，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/884a6f64-3229-4167-9489-7634b96632d4.png)

如前面的屏幕截图所示，ReSharper 发现了我们代码中的 527 个问题，其中 436 个正在显示。这些问题包括常见做法和代码改进、编译器警告、约束违规、语言使用机会、潜在的代码质量问题、代码冗余、符号声明冗余、拼写问题和语法风格。

如果我们展开编译器警告，我们会看到有三个问题，如下所示：

+   `_name`字段从未被赋值。

+   `nre`本地变量从未被使用。

+   这个`async`方法缺少`await`操作符，将以同步方式运行。使用`await`操作符等待非阻塞的**应用程序编程接口**（**API**）调用，或者使用`await TaskEx.Run(...)`在后台线程上执行 CPU 绑定的工作。

这些问题是声明的变量没有被赋值或使用，以及一个缺少`await`运算符的`async`方法将以同步方式运行。如果单击第一个警告，它将带您到从未分配的代码行。查看类，您会发现字符串已声明并使用，但从未分配。由于我们检查字符串是否包含`string.Empty`，我们可以将该值分配给声明。因此，更新后的行将如下所示：

```cs
private string _name = string.Empty;
```

由于`_name`变量仍然突出显示，我们可以将鼠标悬停在上面，看看问题是什么。快速操作通知我们，`_name`变量可以标记为只读。让我们添加`readonly`修饰符。所以，现在这行变成了这样：

```cs
private readonly string _name = string.Empty;
```

如果单击刷新按钮![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/39fdfd96-ae8b-4036-a5f8-76f71c793546.png)，我们将发现发现的问题数量现在是 526。然而，我们解决了两个问题。所以，问题数量应该是 525 吗？好吧，不是。我们解决的第二个问题不是 ReSharper 检测到的问题，而是 Visual Studio 快速操作检测到的改进。因此，ReSharper 显示了它检测到的正确问题数量。

让我们看看`LooseCouplingB`类的潜在代码质量问题。ReSharper 报告了这个方法内可能的`System.NullReferenceException`。让我们先看看代码，如下所示：

```cs
public LooseCouplingB()
{
    LooseCouplingA lca = new LooseCouplingA();
   lca = null;
    Debug.WriteLine($"Name is {lca.Name}");
}
```

果然，我们面对着`System.NullReferenceException`。我们将查看`LooseCouplingA`类，以确认应将哪些成员设置为`null`。另外，要设置的成员是`_name`，如下面的代码片段所示：

```cs
public string Name
{
    get => _name.Equals(string.Empty) ? StringIsEmpty : _name;

    set
    {
        if (value.Equals(string.Empty))
            Debug.WriteLine("Exception: String length must be greater than zero.");
    }
}
```

然而，`_name`正在被检查是否为空。所以，实际上，代码应该将`_name`设置为`string.Empty`。因此，我们在`LooseCouplingB`中修复的构造函数如下：

```cs
public LooseCouplingB()
{
    var lca = new LooseCouplingA
    {
        Name = string.Empty
    };
    Debug.WriteLine($"Name is {lca.Name}");
}
```

现在，如果我们刷新 Inspection Results 窗口，我们的问题列表将减少五个，因为除了正确分配`Name`属性之外，我们利用了语言使用机会来简化我们的实例化和初始化，这是由 ReSharper 检测到的。玩一下这个工具，消除检查结果窗口中发现的问题。

ReSharper 还可以生成*依赖关系图*。要为我们的解决方案生成依赖关系图，请选择 Extensions | ReSharper | Architecture | Show Project Dependency Diagram。这将显示我们解决方案的项目依赖关系图。称为`CH06`的黑色容器框是命名空间，以`CH06_`为前缀的灰色/蓝色框是项目，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/4dcecdbe-cc72-4c4b-b6ca-aeb80473c813.png)

从`CH06`命名空间的项目依赖关系图中可以看出，`CH06_SpecFlow`和`CH06_SpecFlow.Implementation`之间存在项目依赖关系。同样，您还可以使用 ReSharper 生成类型依赖关系图。选择 Extensions | ReSharper | Architecture | Type Dependencies Diagram。

如果我们为`CH10_AddressingCrossCuttingConcerns`项目中的`ConcreteClass`生成图表，那么图表将被生成，但只有`ConcreteComponent`类将被最初显示。右键单击图表上的`ConcreteComponent`框，然后选择 Add All Referenced Types。您将看到`ExceptionAttribute`类和`IComponent`接口的添加。右键单击`ExceptionAttribute`类，然后选择 Add All Referenced Types，您将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/ea8e50b2-0ab3-4b5c-8110-b7ed7648b6ee.png)

这个工具真正美妙的地方在于你可以按命名空间对图表元素进行排序。对于有多个大型项目和深度嵌套命名空间的庞大解决方案来说，这真的非常有用。虽然我们可以右键单击代码并转到项目声明，但是以可视化的方式看到你正在工作的项目的情况是无可替代的，这就是为什么这个工具非常有用。以下是一个按命名空间组织的类型依赖关系图的示例：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/99ae67ae-8f3b-437b-9112-a5cf9be0fae3.png)

在日常工作中，我真的经常需要这样的图表。这个图表是技术文档，将帮助开发人员了解复杂解决方案。他们将能够看到哪些命名空间是可用的，以及一切是如何相互关联的。这将使开发人员具备正确的知识，知道在进行新开发时应该把新类、枚举和接口放在哪里，但也知道在进行维护时应该在哪里找到对象。这个图表也很适合查找重复的命名空间、接口和对象名称。

现在让我们来看看覆盖率。操作如下：

1.  选择扩展 | ReSharper | 覆盖 | 覆盖应用程序。

1.  覆盖配置对话框将被显示，并且默认选择的选项将是独立运行。

1.  选择你的可执行文件。

1.  你可以从`bin`文件夹中选择一个.NET 应用程序。

1.  以下截图显示了覆盖配置对话框：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/3ad944a8-2edf-4546-8a32-e657aa46605f.png)

1.  点击运行按钮启动应用程序并收集分析数据。ReSharper 将显示以下对话框：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/351aa848-072c-4355-8d75-fb92db9e3815.png)

应用程序将会运行。当应用程序运行时，覆盖分析器将会收集数据。我们选择的可执行文件是一个控制台应用程序，显示如下数据：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/34e40597-803e-4918-bb75-59127613b600.png)

1.  点击控制台窗口，然后按任意键退出。覆盖对话框将消失，然后存储将被初始化。最后，覆盖结果浏览器窗口将显示，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/d6678fcf-fbbc-47b2-872c-d69eec9cdf46.png)

这个窗口包含了非常有用的信息。它提供了代码未被调用的视觉指示，用红色标记。执行的代码用绿色标记。使用这些信息，你可以看到代码是否是可以删除的死代码，或者由于系统路径而未被执行但仍然需要，或者由于测试目的而被注释掉，或者仅仅是因为开发人员忘记在正确的位置添加调用或者条件检查错误而未被调用。

要转到感兴趣的项目，你只需要双击该项目，然后你将被带到你感兴趣的具体代码。我们的`Program`类只覆盖了 33%的代码。所以，让我们双击`Program`，看看问题出在哪里。结果输出如下代码块所示：

```cs
static void Main(string[] args)
{
    LoggingServices.DefaultBackend = new ConsoleLoggingBackend();
    AuditServices.RecordPublished += AuditServices_RecordPublished;
    DecoratorPatternExample();
    //ProxyPatternExample();
    //SecurityExample();

    //ExceptionHandlingAttributeExample();

    //SuccessfulMethod();
    //FailedMethod();

    Console.ReadKey();
}
```

从代码中可以看出，我们的一些代码之所以没有被覆盖是因为调用代码的地方被注释掉了，用于测试目的。我们可以保留代码不变（在这种情况下我们会这样做）。然而，你也可以通过去掉注释来删除死代码或者恢复代码。现在，你知道代码为什么没有被覆盖了。

好了，现在你已经了解了 ReSharper 并且看了一下辅助你编写良好、干净的 C#代码的工具，是时候看看我们的下一个工具了，叫做 Telerik JustDecompile。

# 使用 Telerik JustDecompile

我曾多次使用 Telerik JustDecompile，比如追踪第三方库中的 bug，恢复丢失的项目源代码，检查程序集混淆的强度，以及学习目的。这是一个我强烈推荐的工具，多年来它已经证明了它的价值很多次。

反编译引擎是开源的，你可以从[`github.com/telerik/justdecompileengine`](https://github.com/telerik/justdecompileengine)获取源代码，因此你可以自由地为项目做出贡献并为其编写自己的扩展。你可以从 Telerik 网站下载 Windows 安装程序，网址是[`www.telerik.com/products/decompiler.aspx`](https://www.telerik.com/products/decompiler.aspx)。所有源代码都可以完全导航。反编译器可作为独立应用程序或 Visual Studio 扩展使用。你可以从反编译的程序集创建 VB.NET 或 C#项目，并提取和保存反编译的程序集中的资源。

下载并安装 Telerik JustDecompile。然后我们将进行反编译过程，并从程序集生成一个 C#项目。在安装过程中可能会提示你安装其他工具，但你可以取消选择 Telerik 提供的其他产品。

运行 Telerik JustDecompile 独立应用程序。找到一个.NET 程序集，然后将其拖入 Telerik JustDecompile 的左窗格中。它将对代码进行反编译，并在左侧显示代码树。如果你在左侧选择一个项目，右侧将显示代码，就像屏幕截图中所示的那样：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/a3aff607-0a76-4f69-a3c5-4aa285e08091.png)

你可以看到，反编译过程非常快速，并且在大多数情况下，它都能很好地完成反编译工作。按照以下步骤进行：

1.  在“插件”菜单项右侧的下拉菜单中，选择 C#。

1.  然后，点击“工具”|“创建项目”。

1.  有时会提示你选择要针对的.NET 版本；有时则不会。

1.  然后，你将被要求保存项目的位置。

1.  项目将会被写入该位置。

然后你可以在 Visual Studio 中打开项目并对其进行操作。如果遇到任何问题，Telerik 会在你的代码中记录问题并提供电子邮件。你可以随时通过电子邮件联系他们。他们擅长回应和解决问题。

好了，我们已经完成了本章中工具的介绍，现在，让我们总结一下我们学到的东西。

# 总结

在本章中，你已经看到代码度量提供了代码质量的几个衡量标准，以及生成这些衡量标准有多么容易。代码度量包括行数（包括空行）与可执行代码行数的比例，圈复杂度，内聚性和耦合性水平，以及代码的可维护性。重构的颜色代码是绿色表示良好，黄色表示理想情况下需要重构，红色表示绝对需要重构。

然后你看到了提供项目的静态代码分析以及查看结果有多么容易。还涵盖了查看和修改规则集，规定了哪些内容会被分析，哪些不会被分析。然后，你体验了快速操作，并看到了如何通过单个命令进行错误修复，添加 using 语句，并重构代码。

然后，我们使用 JetBrains dotTrace 性能分析工具来测量我们应用程序的性能，找出瓶颈，并识别占用大部分处理时间的方法。接下来我们看了 JetBrains ReSharper，它使我们能够检查代码中的各种问题和潜在改进。我们确定了一些问题并进行了必要的更改，看到了使用这个工具改进代码有多么容易。然后，我们看了如何创建依赖关系和类型依赖的架构图。

最后，我们看了 Telerik JustDecompile，这是一个非常有用的工具，可以用来反编译程序集并从中生成 C#或 VB.NET 项目。当遇到错误或需要扩展程序，但无法访问现有源代码时，这将非常有用。

在接下来的章节中，我们将主要关注代码，以及我们如何重构它。但现在，用以下问题测试你的知识，并通过“进一步阅读”部分提供的链接进一步阅读。

# 问题

1.  代码度量是什么，为什么我们应该使用它们？

1.  列举六个代码度量测量。

1.  什么是代码分析，为什么它有用？

1.  什么是快速操作？

1.  JetBrains dotTrace 用于什么？

1.  JetBrains ReSharper 用于什么？

1.  为什么要使用 Telerik JustDecompile 来反编译程序集？

# 进一步阅读

+   官方微软文档关于代码度量：[`docs.microsoft.com/en-us/visualstudio/code-quality/code-metrics-values?view=vs-2019`](https://docs.microsoft.com/en-us/visualstudio/code-quality/code-metrics-values?view=vs-2019)

+   官方微软文档关于快速操作：[`docs.microsoft.com/en-us/visualstudio/ide/quick-actions?view=vs-2019`](https://docs.microsoft.com/en-us/visualstudio/ide/quick-actions?view=vs-2019)

+   JetBrains dotTrace 性能分析器：[`www.jetbrains.com/profiler/`](https://www.jetbrains.com/profiler/)


# 第十三章：重构 C# 代码 - 识别代码异味

在这一章中，我们将看看问题代码以及如何重构它。在行业中，问题代码通常被称为**代码异味**。它是编译、运行并完成其预期功能的代码。问题代码之所以成为问题是因为它变得难以阅读，具有复杂的性质，并使得代码库难以维护和进一步扩展。这样的代码应该在可行的情况下尽快重构。这是技术债务，在长期来看，如果你不处理它，它将使项目陷入困境。当这种情况发生时，你将面临昂贵的重新设计和从头开始编码应用程序。

那么什么是重构？重构是将现有的工作代码重写，使得代码变得干净的过程。正如你已经发现的那样，干净的代码易于阅读、易于维护和易于扩展。

在这一章中，我们将涵盖以下主题：

+   识别应用级别的代码异味以及我们如何解决它们

+   识别类级别的代码异味以及我们如何解决它们

+   识别方法级别的代码异味以及我们如何解决它们

通过本章的学习，您将获得以下技能：

+   识别不同类型的代码异味

+   理解为什么代码被归类为代码异味

+   重构代码异味，使其成为干净的代码

我们将从应用级别的代码异味开始看重构代码异味。

# 技术要求

您需要本章的以下先决条件：

+   Visual Studio 2019

+   PostSharp

对于本章的代码文件，您可以使用以下链接：[`github.com/PacktPublishing/Clean-Code-in-C-/tree/master/CH13`](https://github.com/PacktPublishing/Clean-Code-in-C-/tree/master/CH13)。

# 应用级别的代码异味

应用级别的代码异味是散布在应用程序中的问题代码，影响每一层。无论您身处软件的哪一层，您都会看到相同的问题代码一遍又一遍地出现。如果您现在不解决这些问题，那么您将发现您的软件将开始缓慢而痛苦地死去。

在这一部分，我们将看看应用级别的代码异味以及我们如何去除它们。让我们从布尔盲目开始。

## 布尔盲目

布尔数据盲目指的是由处理布尔值的函数确定的信息丢失。使用更好的结构提供更好的接口和类来保存数据，使得在处理数据时更加愉快。

让我们通过这段代码示例来看看布尔盲目的问题：

```cs
public void BookConcert(string concert, bool standing)
{
    if (standing)
   {
        // Issue standing ticket.
    }
    else
    {
        // Issue sitting ticket.
    }
}
```

这个方法接受音乐会名称的字符串和一个布尔值，指示人是站立还是坐着。现在，我们将如下调用代码：

```cs
private void BooleanBlindnessConcertBooking()
{
    var booking = new ProblemCode.ConcertBooking();
    booking.BookConcert("Solitary Experiments", true);
}
```

如果一个新手看到`BooleanBlindnessConcertBooking()`方法，你认为他们会本能地知道`true`代表什么吗？我认为不会。他们对它的含义会一无所知。所以他们要么使用智能感知，要么找到被引用的方法来找到含义。他们是布尔盲目的。那么我们如何治愈他们的盲目呢？

嗯，一个简单的解决方案是用枚举替换布尔值。让我们首先添加我们的名为`TicketType`的枚举：

```cs
[Flags]
internal enum TicketType
{
    Seated,
    Standing
}
```

我们的枚举标识了两种类型的票。这些是`Seated`和`Standing`。现在让我们添加我们的`ConcertBooking()`方法：

```cs
internal void BookConcert(string concert, TicketType ticketType)
{
    if (ticketType == TicketType.Seated)
    {
        // Issue seated ticket.
    }
    else
    {
        // Issue standing ticket.
    }
}
```

以下代码显示了如何调用新重构的代码：

```cs
private void ClearSightedConcertBooking()
{
    var booking = new RefactoredCode.ConcertBooking();
    booking.BookConcert("Chrom", TicketType.Seated);
}
```

现在，如果有新人来看这段代码，他们会看到我们正在预订一场音乐会，看`Chrom`乐队，并且我们想要座位票。

## 组合爆炸

组合爆炸是同一段代码使用不同参数组合执行相同操作的副产品。让我们看一个添加数字的例子：

```cs
public int Add(int x, int y)
{
    return x + y;
}

public double Add(double x, double y)
{
    return x + y;
}

public float Add(float x, float y)
{
    return x + y;
}
```

这里，我们有三种方法都是对数字进行加法。返回类型和参数都不同。有更好的方法吗？有，通过使用泛型。通过使用泛型，你可以有一个单一的方法，能够处理不同类型的工作。因此，我们将使用泛型来解决我们的加法问题。这将允许我们有一个单一的加法方法，可以接受整数、双精度或浮点数。让我们来看看我们的新方法：

```cs
public T Add<T>(T x, T y)
{
    dynamic a = x;
    dynamic b = y;
    return a + b;
}
```

这个泛型方法被调用时，为`T`分配了特定类型。它执行加法并返回结果。只需要一个版本的方法来处理可以相加的不同.NET 类型。要调用`int`、`double`和`float`值的代码，我们将这样做：

```cs
var addition = new RefactoredCode.Maths();
addition.Add<int>(1, 2);
addition.Add<double>(1.2, 3.4);
addition.Add<float>(5.6f, 7.8f);
```

我们刚刚消除了三种方法，并用一个执行相同任务的单一方法替代了它们。

## 人为复杂

当你可以用简单的架构开发代码，但却实现了一个先进而相当复杂的架构时，这被称为**人为复杂**。不幸的是，我曾经不得不在这样的系统上工作，这是一种真正的痛苦和压力来源。你会发现这样的系统往往有很高的员工流动率。它们缺乏文档，似乎没有人知道系统或者有能力回答接受培训的人的问题——那些不得不学习系统来维护和扩展它的可怜人。

对所有超级智能软件架构师的建议是，当涉及软件时，**保持简单，愚蠢**（**KISS**）。记住，永久就业和终身工作似乎已经成为过去的事情。通常情况下，程序员更多地追逐金钱，而不是对企业的终身忠诚。因此，由于企业依赖软件来获取收入，你需要一个易于理解、接纳新员工、维护和扩展的系统。问问自己这个问题：如果你负责的系统突然经历了你和所有分配给它们的员工离职并找到新机会，接管的新员工能立即上手吗？还是他们会感到压力重重，摸不着头脑？

还要记住，如果团队中只有一个人了解该系统，而他们去世、搬到新地方或退休了，那么你和团队的其他人会怎么样？甚至更重要的是，这对企业意味着什么？

我无法再强调你真的要简单了。创建复杂系统并不记录它们并分享架构知识的唯一原因是为了让企业束手就擒，让他们留住你并榨干他们。不要这样做。根据我的经验，系统越复杂，死亡速度越快，必须重写。

在第十二章中，*使用工具提高代码质量*，你学会了如何使用 Visual Studio 2019 工具来发现*圈复杂度*和*继承深度*。你还学会了如何使用 ReSharper 生成依赖关系图。使用这些工具来发现代码中的问题区域，然后专注于这些区域。将圈复杂度降至 10 或更低。并将所有对象的继承深度降至不超过 1。

然后，确保所有类只执行它们的本职任务。力求使方法简短。一个很好的经验法则是每个方法不超过大约 10 行代码。对于方法参数，用参数对象替换长参数列表。在有很多`out`参数的地方，重构方法以返回元组或对象。识别任何多线程，并确保被访问的代码是线程安全的。你已经在第九章中看到了如何用不可变对象替换可变对象来提高线程安全性。

此外，寻找快速提示图标。它们通常会建议单击重构所突出显示的代码行。我建议你使用它们。这些在第十二章中提到过，*使用工具提高代码质量*。

考虑的下一个代码异味是数据团。

## 数据团

**数据团**是指在不同的类和参数列表中看到相同字段一起出现。它们的名称通常遵循相同的模式。这通常是系统中缺少一个类的迹象。通过识别缺失的类并将其概括，可以减少系统复杂性。不要被这个类可能很小的事实吓到，也永远不要认为一个类不重要。如果需要一个类来简化代码，那就添加它。

## 除臭注释

当注释使用美好的词语来为糟糕的代码开脱时，这被称为**除臭注释**。如果代码糟糕，那就重构它使之变好，并删除注释。如果你不知道如何重构使之变好，那就寻求帮助。如果没有人可以帮助你，请在 Stack Overflow 上发布你的代码。那个网站上有一些非常优秀的程序员，他们可以真正帮助你。只要确保在发布时遵守规则！

## 重复代码

**重复代码**是指出现多次的代码。重复代码带来的问题包括每次重复增加的维护成本。当开发人员修复一段代码时，这会花费企业的时间和金钱。修复一个错误就是 *技术债务（程序员的工资） x 1*。但如果有 10 个代码重复，那就是 *技术债务 x 10*。因此，代码重复的次数越多，维护成本就越高。此外，还有在多个位置修复相同问题的无聊因素。还有重复可能被进行错误修复的程序员忽视的事实。

最好重构重复代码，使之只存在一份。通常，最简单的方法是将其添加到当前项目中的一个新的可重用类中，并将其放在一个类库中。将可重用代码放入类库的好处是其他项目可以使用相同的文件。

在当今，最好使用.NET 标准类库来构建可重用的代码。原因在于.NET 标准库可以在 Windows、Linux、macOS、iOS 和 Android 上的所有 C#项目类型中访问。

另一个消除样板代码的选择是使用**面向方面的编程（AOP）**。我们在上一章中看过 AOP。你可以将样板代码移入一个方面。然后，该方面装饰应用于的方法。当方法被编译时，样板代码就被编织到位。这使你只需在方法内编写满足业务需求的代码。应用于方法的方面隐藏了必要但不属于业务要求的代码。这种编码技术既美观又干净，而且效果非常好。

你也可以使用装饰者模式编写装饰器，就像你在上一章中看到的那样。装饰器以一种可以添加新代码而不影响代码预期操作的方式包装具体类操作。一个简单的例子是将操作包装在一个`try`/`catch`块中，就像你之前在第十一章中看到的那样，*解决横切关注点*。

## 失去意图

如果你无法轻松理解源代码的意图，那它就失去了意图。

首先要做的是查看命名空间和类名。它们应该指示类的目的。然后，检查类的内容，寻找看起来不合适的代码。一旦你识别出这样的代码，就重构代码并将其放在正确的位置。

接下来要做的是看每个方法。它们只做一件事还是做多件事不太好？如果是的话，就重构它们。对于大型方法，寻找可以提取到方法中的代码。目标是使类的代码读起来像一本书。不断重构代码，直到意图清晰，类中只需要的东西才在类中。

不要忘记运用你在第十二章中学会的工具来提高代码质量。变量的变异是我们接下来要看的代码异味。

## 变量的变异

变量的变异意味着它们很难理解和推理。这使得它们很难重构。

可变变量是指被不同操作多次更改的变量。这使得理解值的原因更加困难。不仅如此，因为变量是从不同操作中变异的，这使得将代码片段提取到其他小而更易读的方法中变得困难。可变变量还可能需要更多的检查，增加了代码的复杂性。

试着重构代码的小部分，将它们提取到方法中。如果有很多分支和循环，请看看是否有更简单的方法来做事情，以消除复杂性。如果你使用多个`out`值，请考虑返回一个对象或元组。目标是消除变量的可变性，使其更容易理解，并知道它的值是什么，以及它是从哪里设置的。记住，持有变量的方法越小，确定变量设置位置和原因就越容易。

看下面的例子：

```cs
[InstrumentationAspect]
public class Mutant
{
    public int IntegerSquaredSum(List<int> integers)
    {
        var squaredSum = 0;
        foreach (var integer in integers)
        {
            squaredSum += integer * integer;
        }
        return squaredSum;
    }
}
```

该方法接受一个整数列表。然后它循环遍历整数，对它们进行平方，然后将它们添加到在方法退出时返回的`squaredSum`变量中。注意迭代次数，以及本地变量在每次迭代中的更新。我们可以使用 LINQ 来改进这一点。以下代码显示了改进后的重构版本：

```cs
[InstrumentationAspect]
public class Function
{
    public int IntegerSquaredSum(List<int> integers)
    {
            return integers.Sum(integer => integer * integer);
    }
}
```

在我们的新版本中，我们使用了 LINQ。正如你在前面的章节中所了解的，LINQ 采用了函数式编程。正如你在这里看到的，这里没有循环，也没有本地变量被变异。

编译并运行程序，你会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/ef28bf84-6935-4be5-8510-a00d02d8009e.png)

代码的两个版本都产生了相同的输出。

你会注意到代码的两个版本都应用了`[InstrumentationAspect]`。我们在第十二章中将这个方面添加到了我们的可重用库中，*解决横切关注点*。当你运行代码时，你会在`Debug`文件夹中找到一个`Logs`文件夹。在记事本中打开`Profile.log`文件，你会看到以下输出：

```cs
Method: IntegerSquaredSum, Start Time: 01/07/2020 11:41:43
Method: IntegerSquaredSum, Stop Time: 01/07/2020 11:41:43, Duration: 00:00:00.0005489
Method: IntegerSquaredSum, Start Time: 01/07/2020 11:41:43
Method: IntegerSquaredSum, Stop Time: 01/07/2020 11:41:43, Duration: 00:00:00.0000027
```

输出显示`ProblemCode.IntegerSquaredSum()`方法是最慢的版本，运行时间为**548.9**纳秒。而`RefactoredCode.IntegerSquaredSum()`方法要快得多，只需要**2.7**纳秒。

通过重构循环使用 LINQ，我们避免了对本地变量的变异。我们还减少了处理计算所需的时间**546.2**纳秒。这样微小的改进对人眼来说并不明显。但如果你在大数据上执行这样的计算，那么你会体验到明显的差异。

现在我们来讨论奇异解决方案。

## 奇异解决方案

当你在源代码中看到以不同方式解决问题时，这被称为**奇异解决方案**。这可能是因为不同的程序员有他们自己的编程风格，没有制定标准。也可能是由于对系统的无知，即程序员没有意识到已经存在一个解决方案。

重构奇怪的解决方案的一种方法是编写一个新类，其中包含以不同方式重复的行为。以最高效的方式将行为添加到类中。然后，用新重构的行为替换奇怪的解决方案。

您还可以使用**适配器模式**来统一不同的系统接口：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/4139a381-b2cd-40a3-a22f-c7ec6fd8ad68.png)

`Target`类是由`Client`使用的特定于域的接口。需要适应的现有接口称为`Adaptee`。`Adapter`类将`Adaptee`类适配到`Target`类。最后，`Client`类通信符合`Target`接口的对象。让我们实现适配器模式。添加一个名为`Adaptee`的新类：

```cs
public class Adaptee
{
    public void AdapteeOperation()
    {
        Console.WriteLine($"AdapteeOperation() has just executed.");
    }
}
```

`Adaptee`类非常简单。它包含一个名为`AdapteeOperation()`的方法，该方法将消息打印到控制台。现在添加`Target`类：

```cs
public class Target
{
    public virtual void Operation()
    {
        Console.WriteLine("Target.Operation() has executed.");
    }
}
```

`Target`类也非常简单，包含一个名为`Operation()`的虚方法，该方法将消息打印到控制台。现在我们将添加将`Target`和`Adaptee`连接在一起的`Adapter`类：

```cs
public class Adapter : Target
{
    private readonly Adaptee _adaptee = new Adaptee();

    public override void Operation()
    {
        _adaptee.AdapteeOperation();
    }
}
```

`Adapter`类继承了`Target`类。然后我们创建一个成员变量来保存我们的`Adaptee`对象并对其进行初始化。然后我们有一个单一方法，即`Target`类的重写`Operation()`方法。最后，我们将添加我们的`Client`类：

```cs
    public class Client
    {
        public void Operation()
        {
            Target target = new Adapter();
            target.Operation();
        }
    }
```

`Client`类有一个名为`Operation()`的方法。此方法创建一个新的`Adapter`对象并将其分配给`Target`变量。然后调用`Target`变量上的`Operation()`方法。如果调用`new Client().Operation()`方法并运行代码，您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/37077c85-28de-4054-bffa-13dd96722844.png)

您可以从屏幕截图中看到执行的方法是`Adaptee.AdapteeOperation()`方法。现在您已成功学会了如何实现适配器模式来解决奇怪的解决方案，我们将继续看散弹手术。

## 散弹手术

进行单个更改需要对多个类进行更改被称为**散弹手术**。这有时是由于代码过多重构导致遇到不同变化而产生的。这种代码异味增加了引入错误的倾向，例如由于错过机会而导致的错误。您还增加了合并冲突的可能性，因为代码需要在许多领域进行更改，程序员最终会互相干扰。代码如此复杂，以至于会导致程序员的认知负荷过重。新程序员由于软件的性质而面临陡峭的学习曲线。

版本控制历史将提供随时间对软件所做更改的历史记录。这可以帮助您识别每次添加新功能或遇到错误时所更改的所有区域。一旦确定了这些区域，那么您可以考虑将更改移动到代码库的更局部的区域。这样，当需要进行更改时，您只需专注于程序的一个区域，而不是许多区域。这使得项目的维护变得更加容易。

重复的代码是重构为一个适当命名的单个类的良好候选，并放置在正确的命名空间中。还要考虑应用程序的所有不同层。它们真的有必要吗？事情可以简化吗？在基于数据库的应用程序中，真的有必要拥有 DTO、DAO、领域对象等吗？数据库访问可以以任何方式简化吗？这些只是一些减少代码库大小的想法，从而减少必须修改以实现更改的区域数量。

其他要考虑的是耦合度和内聚度。耦合度需要保持在绝对最低限度。实现这一点的一种方法是通过构造函数、属性和方法注入依赖项。注入的依赖项将是特定接口类型。我们将编写一个简单的示例。添加一个名为`IService`的接口：

```cs
public interface IService
{
    void Operation();
}
```

接口包含一个名为`Operation()`的方法。现在，添加一个实现`IService`的类`Dependency`：

```cs
public class Dependency : IService
{
    public void Operation()
    {
        Console.WriteLine("Dependency.Operation() has executed.");
    }
}
```

`Dependency`类实现了`IService`接口。在`Operation()`方法中，向控制台打印了一条消息。现在让我们添加`LooselyCoupled`类：

```cs
public class LooselyCoupled
{
    private readonly IService _service;

    public LooselyCoupled(IService service)
    {
        _service = service;
    }

    public void DoWork()
    {
        _service.Operation();
    }
}
```

如您所见，构造函数接受`IService`类型并将其存储在成员变量中。对`DoWork()`的调用调用`IService`类型内的`Operation()`方法。`LooselyCoupled`类就是松耦合的，很容易测试。

通过减少耦合度，使类更容易测试。通过删除不属于类的代码并将其放在应该属于的地方，可以提高应用程序的可读性、可维护性和可扩展性。您减少了任何新人上手的学习曲线，并且在进行维护或新开发时减少了引入错误的机会。

现在让我们来看一下解决方案扩散。

## 解决方案扩散

在不同方法、类甚至库中实现的单一责任会导致解决方案扩散。这会使代码变得非常难以阅读和理解。结果是代码变得更难维护和扩展。

为了解决问题，将单一责任的实现移入同一类中。这样，代码就只在一个位置，做它需要做的事情。这样做使得代码易于阅读和理解。结果是代码可以很容易地维护和扩展。

## 不受控制的副作用

不受控制的副作用是那些在生产中出现的问题，因为质量保证测试无法捕捉到它们。当遇到这些问题时，您唯一的选择就是重构代码，使其完全可测试，并且在调试期间可以查看变量，以确保它们被适当设置。

一个例子是通过引用传递值。想象两个线程通过引用将一个人的对象传递给修改人的对象的方法。一个副作用是，除非有适当的锁定机制，否则每个线程都可以修改另一个线程的人的对象，使数据无效。您在第八章中看到了可变对象的一个例子，*线程和并发*。

这就结束了我们对应用级代码异味的讨论。现在，我们将继续看一下类级代码异味。

# 类级代码异味

类级代码异味是与所讨论的类有关的局部问题。可能困扰类的问题包括圈复杂度和继承深度、高耦合度和低内聚度。编写类时的目标是保持其小而功能齐全。类中的方法应该确实存在，并且应该很小。在类中只做需要做的事情 - 不多，也不少。努力消除类的依赖性，并使您的类可测试。将应该放在其他地方的代码移除到它应该属于的地方。在本节中，我们将解决类级代码异味以及如何重构它们，从圈复杂度开始。

## 圈复杂度

当一个类有大量的分支和循环时，它的圈复杂度会增加。 理想情况下，代码的圈复杂度值应该在*1 到 10 之间*。 这样的代码简单且没有风险。 圈复杂度为 11-20 的代码复杂但风险较低。 当代码的圈复杂度在 21-50 之间时，代码需要关注，因为它太复杂并对项目构成中等风险。 如果代码的圈复杂度超过 50，则这样的代码是高风险的，无法进行测试。 圈复杂度超过 50 的代码必须立即进行重构。

重构的目标是将圈复杂度值降低到 1-10 之间。 首先，通过替换`switch`语句后跟`if`表达式来开始。

### 用工厂模式替换`switch`语句

在本节中，您将看到如何用工厂模式替换`switch`语句。 首先，我们需要一个报告枚举：

```cs
[Flags]
public enum Report
{
    StaffShiftPattern,
    EndofMonthSalaryRun,
    HrStarters,
    HrLeavers,
    EndofMonthSalesFigures,
    YearToDateSalesFigures
}
```

`[Flags]`属性使我们能够提取枚举的名称。 `Report`枚举提供了报告列表。 现在让我们添加我们的`switch`语句：

```cs
public void RunReport(Report report)
{
    switch (report)
    {
        case Report.EndofMonthSalaryRun:
            Console.WriteLine("Running End of Month Salary Run Report.");
            break;
        case Report.EndofMonthSalesFigures:
            Console.WriteLine("Running End of Month Sales Figures Report.");
            break;
        case Report.HrLeavers:
            Console.WriteLine("Running HR Leavers Report.");
            break;
        case Report.HrStarters:
            Console.WriteLine("Running HR Starters Report.");
            break;
        case Report.StaffShiftPattern:
            Console.WriteLine("Running Staff Shift Pattern Report.");
            break;
        case Report.YearToDateSalesFigures:
            Console.WriteLine("Running Year to Date Sales Figures Report.");
            break;
        default:
            Console.WriteLine("Report unrecognized.");
            break;
    }
}
```

我们的方法接受一个报告，然后决定执行什么报告。 当我 1999 年作为初级 VB6 程序员开始时，我负责为 Thomas Cook，ANZ，BNZ，Vodafone 和其他一些大公司构建了一个报告生成器。 有很多报告，我负责编写一个庞大的 case 语句，使得这个 case 语句相形见绌。 但我的系统运行得非常好。 但是，按照今天的标准，有更好的方法来执行相同的代码，我会做一些非常不同的事情。

让我们使用工厂方法来运行我们的报告，而不使用`switch`语句。 添加一个名为`IReportFactory`的文件，如下所示：

```cs
public interface IReportFactory
{
    void Run();
}
```

`IReportFactory`接口只有一个名为`Run()`的方法。 实现类将使用此方法来运行其报告。 我们只添加一个名为`StaffShiftPatternReport`的报告类，它实现了`IReportFactory`：

```cs
public class StaffShiftPatternReport : IReportFactory
{
    public void Run()
    {
        Console.WriteLine("Running Staff Shift Pattern Report.");
    }
}
```

`StaffShiftPatternReport`类实现了`IReportFactory`接口。 实现的`Run()`方法在屏幕上打印一条消息。 添加一个名为`ReportRunner`的报告：

```cs
public class ReportRunner
{
    public void RunReport(Report report)
    {
        var reportName = $"CH13_CodeRefactoring.RefactoredCode.{report}Report, CH13_CodeRefactoring";
        var factory = Activator.CreateInstance(
            Type.GetType(reportName) ?? throw new InvalidOperationException()
        ) as IReportFactory;
        factory?.Run();
    }
}
```

`ReportRunner`类有一个名为`RunReport`的方法。 它接受一个类型为`Report`的参数。 由于`Report`是带有`[Flags]`属性的枚举，我们可以获取`report`枚举的名称。 我们使用这个名称来构建报告的名称。 然后，我们使用`Activator`类来创建报告的实例。 如果在获取类型时`reportName`返回 null，则抛出`InvalidOperationException`。 工厂被转换为`IReportFactory`类型。 然后我们调用工厂上的`Run`方法来生成报告。

这段代码绝对比一个非常长的`switch`语句要好得多。 我们需要知道如何提高`if`语句中条件检查的可读性。 我们接下来会看一下。

### 提高`if`语句中条件检查的可读性

`if`语句可能会违反单一职责和开闭原则。 请参阅以下示例：

```cs
public string GetHrReport(string reportName)
{
    if (reportName.Equals("Staff Joiners Report"))
        return "Staff Joiners Report";
    else if (reportName.Equals("Staff Leavers Report"))
        return "Staff Leavers Report";
    else if (reportName.Equals("Balance Sheet Report"))
        return "Balance Sheet Report";
}
```

`GetReport()`类有三个职责：员工入职报告，员工离职报告和资产负债表报告。 这违反了 SRP，因为该方法应该只关心 HR 报告，但它返回 HR 和财务报告。 就开闭原则而言，每次需要新报告时，我们都必须扩展此方法。 让我们重构该方法，以便不再需要`if`语句。 添加一个名为`ReportBase`的新类：

```cs
public abstract class ReportBase
{
    public abstract void Print();
}
```

`ReportBase`类是一个带有抽象`Print()`方法的抽象类。 我们将添加`NewStartersReport`类，它继承了`ReportBase`类：

```cs
    internal class NewStartersReport : ReportBase
    {
        public override void Print()
        {
            Console.WriteLine("Printing New Starters Report.");
        }
    }
```

`NewStartersReport`类继承了`ReportBase`类并重写了`Print()`方法。 `Print()`方法在屏幕上打印一条消息。 现在，我们将添加`LeaversReport`类，它几乎相同：

```cs
    public class LeaversReport : ReportBase
    {
        public override void Print()
        {
            Console.WriteLine("Printing Leavers Report.");
        }
    }
```

`LeaversReport`继承了`ReportBase`类并重写了`Print()`方法。`Print()`方法向屏幕打印一条消息。现在我们可以这样调用报告：

```cs
ReportBase newStarters = new NewStartersReport();
newStarters.Print();

ReportBase leavers = new LeaversReport();
leavers.Print();
```

两个报告都继承了`ReportBase`类，因此可以被实例化并分配给`ReportBase`变量。然后可以在变量上调用`Print()`方法，并且将执行正确的`Print()`方法。现在的代码遵循了单一责任原则和开闭原则。

接下来，我们将看一看分歧变化代码异味。

## 分歧变化

当您需要在一个位置进行更改，并发现自己不得不更改许多不相关的方法时，这被称为**分歧变化**。分歧变化发生在单个类中，是糟糕的类结构的结果。复制和粘贴代码是导致此问题出现的另一个原因。

为了解决问题，将导致问题的代码移动到自己的类中。如果行为和状态在类之间共享，则考虑使用适当的基类和子类来实现继承。

修复分歧变化相关问题的好处包括更容易的维护，因为更改将位于单个位置。这使得支持应用程序变得更加容易。它还从系统中删除了重复的代码，这恰好是我们接下来将讨论的内容。

## 向下转型

当基类被转换为其子类之一时，这被称为**向下转型**。这显然是一种代码异味，因为基类不应该知道继承它的类。例如，考虑`Animal`基类。任何类型的动物都可以继承基类。但动物只能是一种类型。例如，猫科动物是猫科动物，犬科动物是犬科动物。将猫科动物转换为犬科动物，反之亦然，是荒谬的。

将动物向下转型为其子类型甚至更加荒谬。这就像说猴子和骆驼是一样的，非常擅长通过沙漠长距离运输人类和货物。这是毫无意义的。因此，您永远不应该进行向下转型。将各种动物（如猴子和骆驼）向上转型为类型`Animal`是有效的，因为猫科动物、犬科动物、猴子和骆驼都是动物的类型。

## 过度使用文字

在使用文字时，很容易引入编码错误。一个例子是字符串文字中的拼写错误。最好将文字文字分配给常量变量。字符串文字应放在资源文件中以进行本地化。特别是如果您计划将软件部署到世界各地的不同位置。

## 特征嫉妒

当一个方法在除了它自己所在的类之外的其他类中花费更多时间处理源代码时，这被称为**特征嫉妒**。我们将在我们的“授权”类中看到这样的例子。但在我们这样做之前，让我们来看看我们的“认证”类：

```cs
public class Authentication
{
    private bool _isAuthenticated = false;

    public void Login(ICredentials credentials)
    {
        _isAuthenticated = true;
    }

    public void Logout()
    {
        _isAuthenticated = false;
    }

    public bool IsAuthenticated()
    {
        return _isAuthenticated;
    }
}
```

我们的“认证”类负责登录和注销用户，以及确定他们是否经过身份验证。添加我们的“授权”类：

```cs
public class Authorization
{
    private Authentication _authentication;

    public Authorization(Authentication authentication)
    {
        _authentication = authentication;
    }

    public void Login(ICredentials credentials)
    {
        _authentication.Login(credentials);
    }

    public void Logout()
    {
        _authentication.Logout();
    }

    public bool IsAuthenticated()
    {
        return _authentication.IsAuthenticated();
    }

    public bool IsAuthorized(string role)
    {
        return IsAuthenticated && role.Contains("Administrator");
    }
}
```

正如您在我们的“授权”类中所看到的，它所做的事情远远超出了它应该做的范围。有一个方法用于验证用户是否被授权承担某个角色。传入的角色将被检查，以确定它是否是管理员角色。如果是，那么该人被授权。但如果角色不是管理员角色，那么该人就没有被授权。

然而，如果您看一下其他方法，它们所做的不过是调用“认证”类中的相同方法。因此，在这个类的上下文中，认证方法是特征嫉妒的一个例子。让我们从“授权”类中移除特征嫉妒：

```cs
public class Authorization
{
    private ProblemCode.Authentication _authentication;

    public Authorization(ProblemCode.Authentication authentication)
    {
        _authentication = authentication;
    }

    public bool IsAuthorized(string role)
    {
        return _authentication.IsAuthenticated() && role.Contains("Administrator");
    }
}
```

您会发现“授权”类现在要小得多，只做了它需要做的事情。不再有特征嫉妒。

接下来，我们将看一看不适当的亲密关系代码异味。

## 不适当的亲密关系

当一个类依赖于另一个类中保存的实现细节时，它就会参与不恰当的亲密关系。这种依赖的类真的需要存在吗？它能否与它所依赖的类合并？或者有没有共享功能最好被提取到自己的类中？

类不应该相互依赖，因为这会导致耦合，并且也会影响内聚性。一个类理想上应该是自包含的。类应该尽可能少地了解彼此。

## 不检点的暴露

当一个类暴露其内部细节时，这被称为**不检点的暴露**。这违反了面向对象编程的**封装**原则。只有应该是公共的才应该是公共的。所有不需要公开的实现都应该通过适当的访问修饰符进行隐藏。

数据值不应该是公共的。它们应该是私有的，只能通过构造函数、方法和属性进行修改。它们只能通过属性进行检索。

## 大类（又名上帝对象）

大类，也被称为“上帝”对象，对系统的所有部分都是一切。它是一个庞大而笨重的类，做了太多的事情。当你尝试阅读对象时，当你读到类名并看到它所在的命名空间时，代码的意图可能是清晰的，但当你来看代码时，代码的意图可能会变得模糊。

一个写得好的类应该有其意图的名称，并且应该放在适当的命名空间中。类的内容应该遵循公司的编码标准。方法应该尽可能保持小，方法参数应该尽可能保持绝对最少。只有属于类的方法应该在类中。不属于类的成员变量、属性和方法应该被移除，并放在正确的文件和正确的命名空间中。

为了保持类的小型和专注，如果没有必要，就不要继承类。如果有一个类有五个方法，而你只会使用其中一个，那么是否可能将该方法移出到自己可重用的类中？记住单一职责原则。一个类应该只有一个职责。例如，文件类应该只处理与文件相关的操作和行为。文件类不应该执行数据库操作。你明白了。

当编写一个类时，你的目标是使它尽可能小，干净和可读。

## 懒惰类（又名搭便车和懒惰对象）

一个**搭便车**的类几乎没有任何用处。当你遇到这样的类时，你可以将它们的内容与具有相同意图的其他类合并。

你也可以尝试折叠继承层次结构。记住，理想的继承深度是*1*。因此，如果你的类的继承深度较大，那么它们是将向上移动继承树的良好候选者。你可能还想考虑使用内联类来处理非常小的类。

## 中间人类

中间人类只是将功能委托给其他对象。在这种情况下，你可以摆脱中间人，直接处理负责的对象。

还要记住，你需要保持继承深度。所以如果你不能摆脱这个类，就要考虑将它与现有的类合并。看看代码区域的整体设计。是否可以以某种方式重构所有代码，以减少代码量和不同类的数量？

## 变量和常量的孤立类

拥有一个独立的类来保存应用程序多个不同部分的变量和常量并不是一个好的做法。当你遇到这种情况时，变量可能很难有任何真正的含义，它们的上下文可能会丢失。最好将常量和变量移动到使用它们的地方。如果常量和变量将被多个类使用，那么它们应该分配给命名空间根目录中的一个文件。

## 原始偏执

源代码使用原始值而不是对象来执行某些任务，比如范围值和格式化字符串，比如信用卡、邮政编码和电话号码，这就是原始偏执。其他迹象包括用于字段名称的常量，以及不适当存储在常量中的信息。

## 拒绝遗赠

当一个类继承自另一个类，但不使用其所有方法时，这被称为**拒绝遗赠**。发生这种情况的常见原因是子类与基类完全不同。例如，一个`building`基类被不同的建筑类型使用，但然后一个`car`对象继承`building`，因为它具有与窗户和门相关的属性和方法。这显然是错误的。

当你遇到这种情况时，考虑是否需要一个基类。如果需要，那么创建一个，然后从中继承。否则，将功能添加到从错误类型继承的类中。

## 投机泛化

一个类被编程为具有现在不需要但将来可能需要的功能，这就是投机泛化。这样的代码是死代码，会增加维护开销和代码膨胀。最好在发现这些类时将其删除。

## 告诉，不要问

*告诉，不要问*软件原则告诉我们作为程序员，我们应该将数据与将操作该数据的方法捆绑在一起。我们的对象不应该要求数据然后对其进行操作！它们必须告诉对象的逻辑在对象的数据上执行特定任务。

如果你发现包含逻辑并要求其他对象提供数据来执行其操作的对象，那么将逻辑和数据合并到一个类中。

## 临时字段

临时字段是不需要在对象的整个生命周期中的成员变量。

你可以通过将临时字段和操作它们的方法移除到它们自己的类中来进行重构。你最终会得到更清晰、更有组织的代码。

# 方法级别的异味

方法级别的代码异味是方法本身的问题。方法是使软件功能良好或糟糕的工作马。它们应该组织良好，只做它们预期要做的事情——不多也不少。了解由于构造不良的方法可能出现的问题和问题的种类是很重要的。我们将讨论在方法级别的代码异味方面要注意的问题，以及我们可以做些什么来解决它们。我们将首先从黑羊方法开始。

## 黑羊方法

在类中的所有方法中，黑羊方法将明显不同。当你遇到黑羊方法时，你必须客观地考虑这个方法。它的名字是什么？方法的意图是什么？当你回答了这些问题，然后你可以决定删除这个方法，并将它放在它真正属于的地方。

## 圈复杂度

当一个方法有太多的循环和分支时，这被称为圈复杂度。这种代码异味也是一个类级别的代码异味，我们已经看到了如何在替换`switch`和`if`语句时可以减少分支的问题。至于循环，它们可以被替换为 LINQ 语句。LINQ 语句的额外好处是它是一个函数式代码，因为 LINQ 是一个函数式查询语言。

## 人为复杂

当一个方法不必要地复杂并且可以简化时，这种复杂性被称为人为复杂性。简化方法以确保其内容是人类可读和可理解的。然后，尝试重构方法并将其大小减小到实际可行的最小行数。

## 死代码

当存在但未被使用的方法时，这被称为死代码。构造函数、属性、参数和变量也是如此。它们应该被识别并移除。

## 过多的数据返回

当一个方法返回的数据比每个调用它的客户端所需的数据更多时，这种代码异味被称为过多的数据返回。应该只返回所需的数据。如果发现有不同要求的对象组，那么可能需要考虑编写不同的方法，以满足两组的需求，并且只返回对这些组有必要的数据。

## 特性嫉妒

特性嫉妒的方法花费更多时间访问其他对象中的数据，而不是在自己的对象中。当我们在类级别代码异味中看到特性嫉妒时，我们已经看到了这一点。

方法应该保持小巧，最重要的是，其主要功能应该局限于该方法。如果它在其他方法中做的事情比自己的方法还多，那么就有可能将一些代码从该方法中移出并放入自己的方法中。

## 标识符大小

标识符可能太短或太长。标识符应该具有描述性和简洁性。在命名变量时要考虑的主要因素是上下文和位置。在局部循环中，一个字母可能是合适的。但如果标识符在类级别，那么它将需要一个人能理解的名称来给它上下文。避免使用缺乏上下文、模糊或引起混淆的名称。

## 不恰当的亲密性

过于依赖其他方法或类中的实现细节的方法显示出不恰当的亲密性。这些方法需要被重构，甚至可能被移除。要牢记的主要事情是这些方法使用另一个类的内部字段和方法。

要进行重构，您可以将方法和字段移动到实际需要使用它们的地方。或者，您可以将字段和方法提取到它们自己的类中。当子类与超类亲密关联时，继承可以取代委托。

## 长行（又称上帝行）

长行代码很难阅读和解释。这使得程序员很难调试和重构这样的代码。在可能的情况下，可以格式化该行，使得任何句点和逗号后的代码出现在新行上。但这样的代码也应该被重构成更小的代码。

## 懒惰的方法

懒惰的方法是指做很少工作的方法。它可能将工作委托给其他方法，也可能只是调用另一个类的方法来完成它应该完成的工作。如果有任何这些情况，那么可能需要摆脱这些方法，并将代码放在需要的方法中。例如，您可以使用内联函数，比如 lambda。

## 长方法（又称上帝方法）

长方法是指已经超出自身范围的方法。这样的方法可能会失去其意图，并执行比预期更多的任务。您可以使用 IDE 选择方法的部分，然后选择提取方法或提取类，将方法的部分移动到自己的方法甚至自己的类中。方法应该只负责执行单一任务。

## 长参数列表（又称参数过多）

三个或更多参数被归类为长参数列表代码异味。您可以通过用方法调用替换参数来解决这个问题。另一种方法是用参数对象替换参数。

## 消息链

当一个方法调用一个对象，该对象调用另一个对象，依此类推时，就会出现消息链。之前，我们在看到迪米特法则时已经了解了如何处理消息链。消息链违反了这个法则，因为一个类只应该与其最近的邻居通信。重构类，将所需的状态和行为移动到需要它的地方。

## 中间人方法

当一个方法的全部工作只是委托给其他人完成时，它就是一个中间人方法，可以进行重构和删除。但如果有功能无法删除，那么将其合并到使用它的区域。

## 古怪解决方案

当看到多个方法做同样的事情但以不同的方式时，这就是一个古怪的解决方案。选择最好实现任务的方法，然后将对其他方法的调用替换为对最佳方法的调用。然后，删除其他方法。这将只留下一个方法和一种可以重复使用的实现任务的方法。

## 推测性泛化

一个在代码中没有被使用的方法被称为推测性泛化代码异味。它本质上是死代码，所有死代码都应该从系统中删除。这样的代码会增加维护成本，也会提供不必要的代码膨胀。

# 总结

在本章中，您已经了解了各种代码异味以及如何通过重构来消除它们。我们已经指出，有应用级别的代码异味渗透到应用程序的所有层，类级别的代码异味贯穿整个类，方法级别的代码异味影响个别方法。

首先，我们讨论了应用级别的代码异味，其中包括布尔盲目、组合爆炸、人为复杂、数据团、除臭剂注释、重复代码、意图丢失、变量突变、古怪解决方案、散弹手术、解决方案蔓延和不受控制的副作用。

然后，我们继续查看类级别的代码异味，包括圈复杂度、分歧变更、向下转型、过多的文字使用、特性嫉妒、不当亲密、不检狂露和大对象，也称为上帝对象。我们还涵盖了懒惰类，也称为吃白食者和懒惰对象；中间人；变量和常量的孤立类；原始偏执；拒绝继承；推测性泛化；告诉，不要问；和临时字段。

最后，我们转向了方法级别的代码异味。我们讨论了黑羊；圈复杂度；人为复杂；死代码；特性嫉妒；标识符大小；不当亲密；长行，也称为上帝行；懒惰方法；长方法，也称为上帝方法；长参数列表，也称为参数过多；消息链；中间人；古怪解决方案；和推测性泛化。

在下一章中，我们将继续使用 ReSharper 来查看代码重构。

# 问题

1.  代码异味的三个主要类别是什么？

1.  命名不同类型的应用级代码异味。

1.  命名不同类型的类级别代码异味。

1.  命名不同类型的方法级代码异味。

1.  您可以执行哪些重构以清理各种代码异味？

1.  什么是圈复杂度？

1.  我们如何克服圈复杂度？

1.  什么是人为复杂？

1.  我们如何克服人为复杂？

1.  什么是组合爆炸？

1.  我们如何克服组合爆炸？

1.  当发现除臭剂注释时，你应该怎么办？

1.  如果你有糟糕的代码但不知道如何修复，你应该怎么办？

1.  在处理编程问题时，哪里是提问和获取答案的好地方？

1.  如何减少长参数列表？

1.  如何重构一个大方法？

1.  一个干净方法的最大长度是多少？

1.  您的程序的圈复杂度应该在什么范围内？

1.  继承深度的理想值是多少？

1.  什么是投机泛化，以及你应该怎么做？

1.  如果你遇到一个奇怪的解决方案，你应该采取什么行动？

1.  如果你遇到一个临时字段，你会进行哪些重构？

1.  什么是数据团，以及你应该怎么做？

1.  解释拒绝遗赠的代码异味。

1.  消息链违反了什么法则？

1.  消息链应该如何重构？

1.  什么是特征嫉妒？

1.  你如何消除特征嫉妒？

1.  你可以使用什么模式来替换返回对象的`switch`语句？

1.  我们如何替换返回对象的`if`语句？

1.  什么是解决方案蔓延，以及可以采取什么措施来解决它？

1.  解释“告诉，不要问！”原则。

1.  “告诉，不要问！”原则是如何被打破的？

1.  霰弹手术的症状是什么，应该如何解决？

1.  解释失去意图以及可以采取的措施。

1.  循环可以如何重构，重构会带来什么好处？

1.  什么是分歧变化，你会如何重构它？

# 进一步阅读

+   *重构-改善现有代码的设计* by Martin Fowler and Kent Beck.

+   [`refactoring.guru/refactoring`](https://refactoring.guru/refactoring)：一个关于设计模式和代码异味的好网站。

+   [`www.dofactory.com/net/design-patterns`](https://www.dofactory.com/net/design-patterns)：一个关于各种设计模式的非常好的基于 C#的网站。


# 第十四章：重构 C#代码——实现设计模式

编写清晰代码的一半战斗在于正确实现和使用设计模式。设计模式本身也可能成为代码异味。当用于过度设计某些相当简单的东西时，设计模式就会成为代码异味。

在本书的前几章中，你已经看到了设计模式在编写清晰代码和重构代码中的应用。具体来说，我们已经实现了适配器模式、装饰器模式和代理模式。这些模式都是以正确的方式实现以完成手头的任务。它们保持简单，绝对不会使代码复杂。因此，当用于其适当的目的时，设计模式在消除代码异味方面确实非常有用，从而使你的代码变得清晰、干净和新鲜。

在这一章中，我们将讨论**四人帮（GoF）**的创建、结构和行为设计模式。设计模式并非一成不变，你不必严格按照它们的实现方式。但是有代码示例可以帮助你从仅仅拥有理论知识过渡到具备正确实现和使用设计模式所需的实际技能。

在本章中，我们将涵盖以下主题：

+   实现创建型设计模式

+   实现结构设计模式

+   行为设计模式的概述

在本章结束时，你将具备以下技能：

+   理解、描述和编程不同的创建型设计模式的能力

+   理解、描述和编程不同的结构设计模式的能力

+   理解行为设计模式的概述

我们将通过讨论创建型设计模式来开始我们对 GoF 设计模式的概述。

# 技术要求

+   Visual Studio 2019

+   一个 Visual Studio 2019 .NET Framework 控制台应用作为你的工作项目

+   本章的完整源代码：[`github.com/PacktPublishing/Clean-Code-in-C-/tree/master/CH14/CH14_DesignPatterns`](https://github.com/PacktPublishing/Clean-Code-in-C-/tree/master/CH14/CH14_DesignPatterns)

# 实现创建型设计模式

从程序员的角度来看，当我们执行对象创建时，我们使用创建型设计模式。模式是根据手头的任务选择的。有五种创建型设计模式：

+   **单例模式**：单例模式确保应用程序级别只存在一个对象实例。

+   **工厂方法**：工厂模式用于创建对象而不使用要使用的类。

+   **抽象工厂**：在不指定其具体类的情况下，抽象工厂实例化相关或依赖的对象组。

+   **原型**：指定要创建的原型的类型，然后创建原型的副本。

+   **建造者**：将对象的构建与其表示分离。

我们现在将开始实现这些模式，从单例设计模式开始。

## 实现单例模式

单例设计模式只允许一个类的一个实例，并且可以全局访问。当系统内的所有操作必须由一个对象协调时，使用单例模式：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/94e2597c-471b-48e0-ae30-ec3f69fa8d9c.png)

这个模式中的参与者是**单例**——一个负责管理自己实例的类，并确保在整个系统中只有一个实例在运行。

我们现在将实现单例设计模式：

1.  在`CreationalDesignPatterns`文件夹中添加一个名为`Singleton`的文件夹。然后，添加一个名为`Singleton`的类：

```cs
public class Singleton {
    private static Singleton _instance;

    protected Singleton() { }

    public static Singleton Instance() {
        return _instance ?? (_instance = new Singleton());
    }
}
```

1.  `Singleton`类存储了自身实例的静态副本。您无法实例化该类，因为构造函数被标记为受保护。`Instance()`方法是静态的。它检查`Singleton`类的实例是否存在。如果存在，则返回该实例。如果不存在，则创建并返回该实例。现在，我们将添加调用它的代码：

```cs
var instance1 = Singleton.Instance();
var instance2 = Singleton.Instance();

if (instance1.Equals(instance2))
    Console.WriteLine("Instance 1 and instance 2 are the same instance of Singleton.");
```

1.  我们声明了`Singleton`类的两个实例，然后将它们进行比较，以查看它们是否是同一个实例。您可以在以下截图中看到输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/691d45a9-3c14-4bd6-8f99-46e4e9f5c5e3.png)

正如你所看到的，我们有一个实现了单例设计模式的工作类。接下来，我们将着手实现工厂方法设计模式。

## 实现工厂方法模式

工厂方法设计模式创建对象，让它们的子类实现自己的对象创建逻辑。当您想要将对象实例化保持在一个地方并且需要生成特定组相关对象时，请使用此设计模式：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/93b0c1b5-6908-4e09-b537-4d396424bf78.png)

该项目的参与者如下：

+   `产品`**：** 工厂方法创建的抽象产品

+   `ConcreteProduct`：继承抽象产品

+   `创建者`：一个带有抽象工厂方法的抽象类

+   `Concrete Creator`**：** 继承抽象创建者并重写工厂方法

我们现在将实现工厂方法：

1.  在`CreationalDesignPatterns`文件夹中添加一个名为`FactoryMethod`的文件夹。然后，添加`Product`类：

```cs
public abstract class Product {}
```

1.  `Product`类定义了由工厂方法创建的对象。添加`ConcreteProduct`类：

```cs
public class ConcreteProduct : Product {}
```

1.  `ConcreteProduct`类继承了`Product`类。添加`Creator`类：

```cs
public abstract class Creator {
    public abstract Product FactoryMethod();
}
```

1.  `Creator`类将被`ConcreteFactory`类继承，后者将实现`FactoryMethod()`。添加`ConcreteCreator`类：

```cs
public class ConcreteCreator : Creator {
    public override Product FactoryMethod() {
        return new ConcreteProduct();
    }
}
```

1.  `ConcreteCreator`类继承了`Creator`类并重写了`FactoryMethod()`。该方法返回一个新的`ConcreteProduct`类。以下代码演示了工厂方法的使用：

```cs
var creator = new ConcreteCreator();
var product = creator.FactoryMethod();
Console.WriteLine($"Product Type: {product.GetType().Name}");
```

我们已经创建了`ConcreteCreator`类的一个新实例。然后，我们调用`FactoryMethod()`来创建一个新产品。由工厂方法创建的产品的名称随后输出到控制台窗口，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/daa493a5-07aa-4d8f-8e20-a97708956825.png)

现在我们知道如何实现工厂方法设计模式，我们将继续实现抽象工厂设计模式。

## 实现抽象工厂模式

在没有具体类的情况下，相关或依赖的对象组，称为家族，使用抽象工厂设计模式进行实例化：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/d57e611f-4941-4627-abfb-f991728fed2f.png)

该模式的参与者如下：

+   `AbstractFactory`：由具体工厂实现的抽象工厂

+   `ConcreteFactory`：创建具体产品

+   `AbstractProduct`：具体产品将继承的抽象产品

+   `Product`：继承`AbstractProduct`并由具体工厂创建

我们现在将开始实现该模式：

1.  在项目中添加一个名为`CreationalDesignPatterns`的文件夹。

1.  在`CreationalDesignPatterns`文件夹中添加一个名为`AbstractFactory`的文件夹。

1.  在`AbstractFactory`文件夹中，添加`AbstractFactory`类：

```cs
public abstract class AbstractFactory {
    public abstract AbstractProductA CreateProductA();
    public abstract AbstractProductB CreateProductB();
}
```

1.  `AbstractFactory`包含两个创建抽象产品的抽象方法。添加`AbstractProductA`类：

```cs
public abstract class AbstractProductA {
    public abstract void Operation(AbstractProductB productB);
}
```

1.  `AbstractProductA`类有一个单一的抽象方法，该方法对`AbstractProductB`执行操作。现在，添加`AbstractProductB`类：

```cs
public abstract class AbstractProductB {
    public abstract void Operation(AbstractProductA productA);
}
```

1.  `AbstractProductB`类有一个单一的抽象方法，该方法对`AbstractProductA`执行操作。添加`ProductA`类：

```cs
public class ProductA : AbstractProductA {
    public override void Operation(AbstractProductB productB) {
        Console.WriteLine("ProductA.Operation(ProductB)");
    }
}
```

1.  `ProductA`继承了`AbstractProductA`并重写了`Operation()`方法，该方法与`AbstractProductB`进行交互。在这个例子中，`Operation()`方法打印出控制台消息。对`ProductB`类也做同样的操作：

```cs
public class ProductB : AbstractProductB {
    public override void Operation(AbstractProductA productA) {
        Console.WriteLine("ProductB.Operation(ProductA)");
    }
}
```

1.  `ProductB`继承了`AbstractProductB`并重写了`Operation()`方法，该方法与`AbstractProductA`进行交互。在这个例子中，`Operation()`方法打印出控制台消息。添加`ConcreteFactory`类：

```cs
public class ConcreteProduct : AbstractFactory {
    public override AbstractProductA CreateProductA() {
        return new ProductA();
    }

    public override AbstractProductB CreateProductB() {
        return new ProductB();
    }
}
```

1.  `ConcreteFactory`继承了`AbstractFactory`类，并重写了两个产品创建方法。每个方法返回一个具体类。添加`Client`类：

```cs
public class Client
{
    private readonly AbstractProductA _abstractProductA;
    private readonly AbstractProductB _abstractProductB;

    public Client(AbstractFactory factory) {
        _abstractProductA = factory.CreateProductA();
        _abstractProductB = factory.CreateProductB();
    }

    public void Run() {
        _abstractProductA.Operation(_abstractProductB);
        _abstractProductB.Operation(_abstractProductA);
    }
}
```

1.  `Client`类声明了两个抽象产品。它的构造函数接受一个`AbstractFactory`类。在构造函数内部，工厂为两个声明的抽象产品分配了它们各自的具体产品。`Run()`方法执行了两个产品上的`Operation()`。以下代码执行了我们的抽象工厂示例：

```cs
AbstractFactory factory = new ConcreteProduct();
Client client = new Client(factory);
client.Run();
```

1.  运行代码，你会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/bb3f9ac2-15db-4b09-92ce-fa278c42e5c6.png)

抽象工厂的一个很好的参考实现是 ADO.NET 2.0 的`DbProviderFactory`抽象类。一篇名为*ADO.NET 2.0 中的抽象工厂设计模式*的文章，作者是 Moses Soliman，发布在 C# Corner 上，对`DbProviderFactory`的抽象工厂设计模式的实现进行了很好的描述。这是链接：

[`www.c-sharpcorner.com/article/abstract-factory-design-pattern-in-ado-net-2-0/`](https://www.c-sharpcorner.com/article/abstract-factory-design-pattern-in-ado-net-2-0/).

我们已成功实现了抽象工厂设计模式。现在，我们将实现原型模式。

## 实现原型模式

原型设计模式用于创建原型的实例，然后通过克隆原型来创建新对象。当直接创建对象的成本昂贵时，使用此模式。通过此模式，可以缓存对象，并在需要时返回克隆：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/6a9b4467-fc5b-4ff3-9143-0f951db7651a.png)

原型设计模式中的参与者如下：

+   `Prototype`：提供克隆自身的方法的抽象类

+   `ConcretePrototype`：继承原型并重写`Clone()`方法以返回原型的成员克隆

+   `Client`：请求原型的新克隆

我们现在将实现原型设计模式：

1.  在`CreationalDesignPatterns`文件夹中添加一个名为`Prototype`的文件夹，然后添加`Prototype`类：

```cs
public abstract class Prototype {
    public string Id { get; private set; }

    public Prototype(string id) {
        Id = id;
    }

    public abstract Prototype Clone();
}
```

1.  我们的`Prototype`类必须被继承。它的构造函数需要传入一个标识字符串，该字符串存储在类级别。提供了一个`Clone()`方法，子类将对其进行重写。现在，添加`ConcretePrototype`类：

```cs
public class ConcretePrototype : Prototype {
    public ConcretePrototype(string id) : base(id) { }

    public override Prototype Clone() {
        return (Prototype) this.MemberwiseClone();
    }
}
```

1.  `ConcretePrototype`类继承自`Prototype`类。它的构造函数接受一个标识字符串，并将该字符串传递给基类的构造函数。然后，它重写了克隆方法，通过调用`MemberwiseClone()`方法提供当前对象的浅拷贝，并返回转换为`Prototype`类型的克隆。现在，我们来演示原型设计模式的代码：

```cs
var prototype = new ConcretePrototype("Clone 1");
var clone = (ConcretePrototype)prototype.Clone();
Console.WriteLine($"Clone Id: {clone.Id}");
```

我们的代码创建了一个带有标识符`"Clone 1"`的`ConcretePrototype`类的新实例。然后，我们克隆原型并将其转换为`ConcretePrototype`类型。然后，我们将克隆的标识符打印到控制台窗口，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/dfb6a75d-50e6-40db-b4e9-8d379bb5a8cc.png)

我们可以看到，克隆的标识符与其克隆自的原型相同。

对于一个真实世界示例的非常详细的文章，请参考一篇名为*具有真实场景的原型设计模式*的优秀文章，作者是 Akshay Patel，文章发布在 C# Corner 上。这是链接：[`www.c-sharpcorner.com/UploadFile/db2972/prototype-design-pattern-with-real-world-scenario624/`](https://www.c-sharpcorner.com/UploadFile/db2972/prototype-design-pattern-with-real-world-scenario624/)。

我们现在将实现我们的最终创建型设计模式，即建造者设计模式。

## 实现建造者模式

建造者设计模式将对象的构建与其表示分离。因此，您可以使用相同的构建方法来创建对象的不同表示。当您有一个需要逐步构建和连接的复杂对象时，请使用建造者设计模式：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/721f8a0f-4d08-4857-a7b3-68407de21f3e.png)

建造者设计模式的参与者如下：

+   `Director`：一个类，通过其构造函数接收一个构建者，然后在构建者对象上调用每个构建方法

+   **`Builder`**：一个抽象类，提供抽象构建方法和一个用于返回构建对象的抽象方法

+   `ConcreteBuilder`：一个具体类，继承`Builder`类，重写构建方法以实际构建对象，并重写结果方法以返回完全构建的对象

让我们开始实现我们的最终创建型设计模式——建造者设计模式：

1.  首先，在`CreationalDesignPatterns`文件夹中添加一个名为`Builder`的文件夹。然后，添加`Product`类：

```cs
public class Product {
    private List<string> _parts;

    public Product() {
        _parts = new List<string>();
    }

    public void Add(string part) {
        _parts.Add(part);
    }

    public void PrintPartsList() {
        var sb = new StringBuilder();
        sb.AppendLine("Parts Listing:");
        foreach (var part in _parts)
            sb.AppendLine($"- {part}");
        Console.WriteLine(sb.ToString());
    }
}
```

1.  在我们的示例中，`Product`类保留了一个部件列表。这些部件是字符串。列表在构造函数中初始化。通过`Add()`方法添加部件，当对象完全构建时，我们可以调用`PrintPartsList()`方法将构成对象的部件列表打印到控制台窗口。现在，添加`Builder`类：

```cs
public abstract class Builder
{
    public abstract void BuildSection1();
    public abstract void BuildSection2();
    public abstract Product GetProduct();
}
```

1.  我们的`Builder`类将被具体类继承，这些具体类将重写其抽象方法以构建对象并返回它。我们现在将添加`ConcreteBuilder`类：

```cs
public class ConcreteBuilder : Builder {
    private Product _product;

    public ConcreteBuilder() {
        _product = new Product();
    }

    public override void BuildSection1() {
        _product.Add("Section 1");
    }

    public override void BuildSection2() {
        _product.Add(("Section 2"));
    }

    public override Product GetProduct() {
        return _product;
    }
}
```

1.  我们的`ConcreteBuilder`类继承了`Builder`类。该类存储要构建的对象的实例。构建方法被重写，并通过产品的`Add()`方法向产品添加部件。产品通过`GetProduct()`方法调用返回给客户端。添加`Director`类：

```cs
public class Director
{
    public void Build(Builder builder)
    {
        builder.BuildSection1();
        builder.BuildSection2();
    }
}
```

1.  `Director`类是一个具体类，通过其`Build()`方法接收一个`Builder`对象，并调用`Builder`对象上的构建方法来构建对象。现在我们需要的是演示建造者设计模式的代码：

```cs
var director = new Director();
var builder = new ConcreteBuilder();
director.Build(builder);
var product = builder.GetProduct();
product.PrintPartsList();
```

1.  我们创建一个导演和一个构建者。然后，导演构建产品。然后分配产品，并将其部件列表打印到控制台窗口，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/97d6673e-dcdf-4ede-8c17-06af4f20b39c.png)

一切都按预期运行。

在.NET Framework 中，`System.Text.StringBuilder`类是现实世界中建造者设计模式的一个例子。使用加号（`+`）运算符进行字符串连接比使用`StringBuilder`类在连接五行或更多行时要慢。当连接少于五行时，使用`+`运算符的字符串连接速度比`StringBuilder`快，但当连接超过五行时，速度比`StringBuilder`慢。原因是每次使用`+`运算符创建字符串时，都会重新创建字符串，因为字符串在堆上是不可变的。但`StringBuilder`在堆上分配缓冲区空间，然后将字符写入缓冲区空间。对于少量行，由于使用字符串构建器时创建缓冲区的开销，`+`运算符更快。但当超过五行时，使用`StringBuilder`时会有明显的差异。在大数据项目中，可能会进行数十万甚至数百万次字符串连接，您决定采用的字符串连接策略将决定其性能快慢。让我们创建一个简单的演示。创建一个名为`StringConcatenation`的新类，然后添加以下代码：

```cs
private static DateTime _startTime;
private static long _durationPlus;
private static long _durationSb;
```

`_startTime` 变量保存方法执行的当前开始时间。`_durationPlus` 变量保存使用 `+` 运算符进行连接时的方法执行持续时间的滴答声数量，`_durationSb` 保存使用 `StringBuilder` 连接的操作的持续时间作为滴答声数量。将 `UsingThePlusOperator()` 方法添加到类中：

```cs
public static void UsingThePlusOperator()
{
    _startTime = DateTime.Now;
    var text = string.Empty;
    for (var x = 1; x <= 10000; x++)
    {
        text += $"Line: {x}, I must not be a lazy programmer, and should continually develop myself!\n";
    }
    _durationPlus = (DateTime.Now - _startTime).Ticks;
    Console.WriteLine($"Duration (Ticks) Using Plus Operator: {_durationPlus}");
}
```

`UsingThePlusOperator()` 方法演示了使用 `+` 运算符连接 10,000 个字符串时所花费的时间。处理字符串连接所花费的时间以触发的滴答声数量存储。每毫秒有 10,000 个滴答声。现在，添加 `UsingTheStringBuilder()` 方法：

```cs
public static void UsingTheStringBuilder()
{
    _startTime = DateTime.Now;
    var sb = new StringBuilder();
    for (var x = 1; x <= 10000; x++)
    {
        sb.AppendLine(
            $"Line: {x}, I must not be a lazy programmer, and should continually develop myself!"
        );
    }
    _durationSb = (DateTime.Now - _startTime).Ticks;
    Console.WriteLine($"Duration (Ticks) Using StringBuilder: {_durationSb}");
}
```

这个方法与前一个方法相同，只是我们使用 `StringBuilder` 类执行字符串连接。现在我们将添加代码来打印时间差异，称为 `PrintTimeDifference()`：

```cs
public static void PrintTimeDifference()
{
    var difference = _durationPlus - _durationSb;
    Console.WriteLine($"That's a time difference of {difference} ticks.");
    Console.WriteLine($"{difference} ticks = {TimeSpan.FromTicks(difference)} seconds.\n\n");
}
```

`PrintTimeDifference()` 方法通过从 `StringBuilder` 的滴答声中减去 `+` 的滴答声来计算时间差。然后将滴答声的差异打印到控制台，然后是将滴答声转换为秒的行。以下是用于测试我们的方法的代码，以便我们可以看到两种连接方法之间的时间差异：

```cs
StringConcatenation.UsingThePlusOperator();
StringConcatenation.UsingTheStringBuilder();
StringConcatenation.PrintTimeDifference();
```

当您运行代码时，您将在控制台窗口中看到时间和时间差异，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/8b2cac85-45bb-4abf-a951-4d54785decff.png)

从屏幕截图中可以看出，`StringBuilder` 要快得多。对于少量数据，肉眼几乎看不出差异。但是当处理的数据行数量大大增加时，肉眼可以看到差异。

另一个我想到的使用生成器模式的例子是报告构建。如果您考虑分段报告，那么各个段基本上是需要从各种来源构建起来的部分。因此，您可以有主要部分，然后每个子报告作为不同的部分。最终报告将是这些各种部分的融合。因此，您可以像以下代码一样构建报告：

```cs
var report = new Report();
report.AddHeader();
report.AddLastYearsSalesTotalsForAllRegions();
report.AddLastYearsSalesTotalsByRegion();
report.AddFooter();
report.GenerateOutput();
```

在这里，我们正在创建一个新的报告。我们首先添加标题。然后，我们添加去年所有地区的销售额，然后是去年按地区细分的销售额。然后我们为报告添加页脚，并通过生成报告输出完成整个过程。

所以，您已经从 UML 图表中看到了生成器模式的默认实现。然后，您使用 `StringBuilder` 类实现了字符串连接，这有助于以高性能的方式构建字符串。最后，您了解了生成器模式如何在构建报告的各个部分并生成其输出时有用。

好了，这就结束了我们对创建设计模式的实现。现在我们将继续实现一些结构设计模式。

# 实施结构设计模式

作为程序员，我们使用结构模式来改进代码的整体结构。因此，当遇到缺乏结构且不够清晰的代码时，我们可以使用本节中提到的模式来重构代码并使其变得清晰。有七种结构设计模式：

+   **适配器**：使用此模式使具有不兼容接口的类能够干净地一起工作。

+   **桥接**：使用此模式通过将抽象与其实现解耦来松散地耦合代码。

+   **组合**：使用此模式聚合对象并提供一种统一的方式来处理单个和对象组合。

+   **装饰者**：使用此模式保持接口相同，同时动态添加新功能到对象。

+   **外观**：使用此模式简化更大更复杂的接口。

+   **享元**：使用此模式节省内存并在对象之间传递共享数据。

+   **代理**：在客户端和 API 之间使用此模式拦截客户端和 API 之间的调用。

我们已经在之前的章节中提到了适配器、装饰器和代理模式，所以本章不会再涉及它们。现在，我们将开始实现我们的结构设计模式，首先是桥接模式。

## 实现桥接模式

我们使用桥接模式来解耦抽象和实现，使它们在编译时不受限制。抽象和实现都可以在不影响客户端的情况下变化。

如果您需要在实现之间进行运行时绑定，或者在多个对象之间共享实现，如果一些类由于接口耦合和各种实现而存在，或者需要将正交类层次结构映射到一起，则使用桥接设计模式：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/0574df48-c539-4718-9969-5c743b1edccb.png)

桥接设计模式的参与者如下：

+   `Abstraction`：包含抽象操作的抽象类

+   `RefinedAbstraction`：继承`Abstraction`类并重写`Operation()`方法

+   `Implementor`：一个带有抽象`Operation()`方法的抽象类

+   `ConcreteImplementor`：继承`Implementor`类并重写`Operation()`方法

现在我们将实现桥接设计模式：

1.  首先将`StructuralDesignPatterns`文件夹添加到项目中，然后在该文件夹中添加`Bridge`文件夹。然后，添加`Implementor`类：

```cs
public abstract class Implementor {
    public abstract void Operation();
}
```

1.  `Implementor`类只有一个名为`Operation()`的抽象方法。添加`Abstraction`类：

```cs
public class Abstraction {
    protected Implementor implementor;

    public Implementor Implementor {
        set => implementor = value;
    }

    public virtual void Operation() {
        implementor.Operation();
    }
}
```

1.  `Abstraction`类有一个受保护的字段，保存着`Implementor`对象，该对象是通过`Implementor`属性设置的。一个名为`Operation()`的虚方法调用了实现者的`Operation()`方法。添加`RefinedAbstraction`类：

```cs
public class RefinedAbstraction : Abstraction {
    public override void Operation() {
        implementor.Operation();
    }
}
```

1.  `RefinedAbstraction`类继承了`Abstraction`类，并重写了`Operation()`方法以调用实现者的`Operation()`方法。现在，添加`ConcreteImplementor`类：

```cs
public class ConcreteImplementor : Implementor {
    public override void Operation() {
        Console.WriteLine("Concrete operation executed.");
    }
}
```

1.  `ConcreteImplementor`类继承了`Implementor`类，并重写了`Operation()`方法以在控制台打印消息。运行桥接设计模式示例的代码如下：

```cs
var abstraction = new RefinedAbstraction();
abstraction.Implementor = new ConcreteImplementor();
abstraction.Operation();
```

我们创建一个新的`RefinedAbstraction`实例，然后将其实现者设置为`ConcreteImplementor`的新实例。然后，我们调用`Operation()`方法。我们示例桥接实现的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/efd18efa-a5c2-4060-8e20-6848a4a241b0.png)

正如您所看到的，我们成功地在具体实现者类中执行了具体操作。我们接下来要看的模式是组合设计模式。

## 实现组合模式

使用组合设计模式，对象由树结构组成，以表示部分-整体的层次结构。这种模式使您能够以统一的方式处理单个对象和对象的组合。

当您需要忽略单个对象和对象组合之间的差异，需要树结构来表示层次结构，以及需要在整个结构中具有通用功能时，请使用此模式：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/049f16d8-1fd9-4029-98a0-6619358ea800.png)

组合设计模式的参与者如下：

+   `Component`：组合对象接口

+   `Leaf`：组合中没有子节点的叶子

+   `Composite`：存储子组件并执行操作

+   `Client`：通过组件接口操纵组合和叶子

现在是时候实现组合模式了：

1.  在`StructuralDesignPatterns`类中添加一个名为`Composite`的新文件夹。然后，添加`IComponent`接口：

```cs
public interface IComponent {
    void PrintName();
}
```

1.  `IComponent`接口有一个方法，将由叶子和组合实现。添加`Leaf`类：

```cs
public class Leaf : IComponent {
    private readonly string _name;

    public Leaf(string name) {
        _name = name;
    }

    public void PrintName() {
        Console.WriteLine($"Leaf Name: {_name}");
    }
}
```

1.  `Leaf`类实现了`IComponent`接口。它的构造函数接受一个名称并存储它，`PrintName()`方法将叶子的名称打印到控制台窗口。添加`Composite`类：

```cs
public class Composite : IComponent {
    private readonly string _name;
    private readonly List<IComponent> _components;

    public Composite(string name) {
        _name = name;
        _components = new List<IComponent>();
    }

    public void Add(IComponent component) {
        _components.Add(component);
    }

    public void PrintName() {
        Console.WriteLine($"Composite Name: {_name}");
        foreach (var component in _components) {
            component.PrintName();
        }
    }
}
```

1.  `Composite`类以与叶子相同的方式实现`IComponent`接口。此外，`Composite`通过`Add()`方法存储添加的组件列表。它的`PrintName()`方法打印出自己的名称，然后是列表中每个组件的名称。现在，我们将添加代码来测试我们的组合设计模式实现：

```cs
var root = new Composite("Classification of Animals");
var invertebrates = new Composite("+ Invertebrates");
var vertebrates = new Composite("+ Vertebrates");

var warmBlooded = new Leaf("-- Warm-Blooded");
var coldBlooded = new Leaf("-- Cold-Blooded");
var withJointedLegs = new Leaf("-- With Jointed-Legs");
var withoutLegs = new Leaf("-- Without Legs");

invertebrates.Add(withJointedLegs);
invertebrates.Add(withoutLegs);

vertebrates.Add(warmBlooded);
vertebrates.Add(coldBlooded);

root.Add(invertebrates);
root.Add(vertebrates);

root.PrintName();
```

1.  如您所见，我们创建了我们的组合，然后创建了我们的叶子。然后，我们将叶子添加到适当的组合中。然后，我们将我们的组合添加到根组合中。最后，我们调用根组合的`PrintName()`方法，它将打印根的名称，以及层次结构中所有组件和叶子的名称。您可以看到输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/574321bd-979c-4a81-b744-ebd47516e20a.png)

我们的组合实现符合预期。我们将实现的下一个模式是外观设计模式。

## 实现外观模式

外观模式旨在使使用 API 子系统更容易。使用此模式将大型复杂系统隐藏在更简单的接口后，以供客户端使用。程序员实现此模式的主要原因是，他们必须使用或处理的系统过于复杂且非常难以理解。

采用此模式的其他原因包括如果太多类相互依赖，或者仅仅是因为程序员无法访问源代码：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/0060eca7-5fe5-47b2-830c-c9c350bf01b9.png)

外观模式中的参与者如下：

+   `Facade`：简单的接口，充当客户端和子系统更复杂系统之间的*中间人*

+   `子系统类`：子系统类直接从客户端访问中移除，并且由外观直接访问

现在我们将实现外观设计模式：

1.  在`StructuralDesignPatterns`文件夹中添加一个名为`Facade`的文件夹。然后，添加`SubsystemOne`和`SubsystemTwo`类：

```cs
public class SubsystemOne {
    public void PrintName() {
        Console.WriteLine("SubsystemOne.PrintName()");
    }
}

public class SubsystemOne {
    public void PrintName() {
        Console.WriteLine("SubsystemOne.PrintName()");
    }
}
```

1.  这些类有一个单一的方法，将类名和方法名打印到控制台窗口。现在，让我们添加`Facade`类：

```cs
public class Facade {
    private SubsystemOne _subsystemOne = new SubsystemOne();
    private SubsystemTwo _subsystemTwo = new SubsystemTwo();

    public void SubsystemOneDoWork() {
        _subsystemOne.PrintName();
    }

    public void SubsystemTwoDoWork() {
        _subsystemTwo.PrintName();
    }
}
```

1.  `Facade`类为其了解的每个系统创建成员变量。然后，它提供一系列方法，当请求时将访问各个子系统的各个部分。我们将添加代码来测试我们的实现：

```cs
var facade = new Facade();
facade.SubsystemOneDoWork();
facade.SubsystemTwoDoWork();
```

1.  我们只需创建一个`Facade`变量，然后我们可以调用执行子系统中的方法调用的方法。您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/b3286287-919d-4e74-876f-339c5ff907a8.png)

现在是时候看看我们最后的结构模式，即享元模式。

## 实现享元模式

享元设计模式用于通过减少总体对象数量来高效处理大量细粒度对象。使用此模式可以通过减少创建的对象数量来提高性能并减少内存占用：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/41f36825-87f9-43d4-a806-4ce797c3c5e4.png)

享元设计模式中的参与者如下：

+   `Flyweight`：为享元提供接口，以便它们可以接收外在状态并对其进行操作

+   `ConcreteFlyweight`：可共享的对象，为内在状态添加存储

+   `UnsharedConcreteFlyweight`：当享元不需要共享时使用

+   `FlyweightFactory`：正确管理享元对象并适当共享它们

+   `Client`：维护享元引用并计算或存储享元的外在状态

**外在状态**意味着它不是对象的基本特性的一部分，它是外部产生的。**内在状态**意味着状态属于对象并且对对象是必不可少的。

让我们实现享元设计模式：

1.  首先在`StructuralDesignPatters`文件夹中添加`Flyweight`文件夹。现在，添加`Flyweight`类：

```cs
public abstract class Flyweight {
    public abstract void Operation(string extrinsicState);
}
```

1.  这个类是抽象的，并包含一个名为`Operation()`的抽象方法，该方法传入了享元的外部状态：

```cs
public class ConcreteFlyweight : Flyweight
{
    public override void Operation(string extrinsicState)
    {
        Console.WriteLine($"ConcreteFlyweight: {extrinsicState}");
    }
}
```

1.  `ConcreteFlyweight`类继承了`Flyweight`类并重写了`Operation()`方法。该方法输出方法名及其外部状态。现在，添加`FlyweightFactory`类：

```cs
public class FlyweightFactory {
    private readonly Hashtable _flyweights = new Hashtable();

    public FlyweightFactory()
    {
        _flyweights.Add("FlyweightOne", new ConcreteFlyweight());
        _flyweights.Add("FlyweightTwo", new ConcreteFlyweight());
        _flyweights.Add("FlyweightThree", new ConcreteFlyweight());
    }

    public Flyweight GetFlyweight(string key) {
        return ((Flyweight)_flyweights[key]);
    }
}
```

1.  在我们特定的享元示例中，我们将享元对象存储在*哈希表*中。在我们的构造函数中创建了三个享元对象。我们的`GetFlyweight()`方法从哈希表中返回指定键的享元。现在，添加客户端：

```cs
public class Client
{
    private const string ExtrinsicState = "Arbitary state can be anything you require!";

    private readonly FlyweightFactory _flyweightFactory = new FlyweightFactory();

    public void ProcessFlyweights()
    {
        var flyweightOne = _flyweightFactory.GetFlyweight("FlyweightOne");
        flyweightOne.Operation(ExtrinsicState);

        var flyweightTwo = _flyweightFactory.GetFlyweight("FlyweightTwo");
        flyweightTwo.Operation(ExtrinsicState);

        var flyweightThree = _flyweightFactory.GetFlyweight("FlyweightThree");
        flyweightThree.Operation(ExtrinsicState);
    }
}
```

1.  外部状态可以是任何你需要的东西。在我们的示例中，我们使用了一个字符串。我们声明了一个新的享元工厂，添加了三个享元，并对每个享元执行了操作。让我们添加代码来测试我们对享元设计模式的实现：

```cs
var flyweightClient = new StructuralDesignPatterns.Flyweight.Client();
flyweightClient.ProcessFlyweights();
```

1.  该代码创建了一个新的`Client`实例，然后调用了`ProcessFlyweights()`方法。您应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/d3ff3dd7-d9c1-4bfb-a08c-110456c3d3b9.png)

好了，结构模式就介绍到这里。现在是时候来看看如何实现行为设计模式了。

# 行为设计模式概述

作为程序员，您在团队中的行为受您的沟通和与其他团队成员的互动方式的影响。我们编程的对象也是如此。作为程序员，我们通过使用行为模式来确定对象的行为和与其他对象的通信方式。这些行为模式如下：

+   **责任链**：一系列处理传入请求的对象管道。

+   **命令**：封装了将在对象内部某个时间点用于调用方法的所有信息。

+   **解释器**：提供对给定语法的解释。

+   **迭代器**：使用此模式按顺序访问聚合对象的元素，而不暴露其底层表示。

+   **中介者**：使用此模式让对象通过中介进行通信。

+   **备忘录**：使用此模式来捕获和保存对象的状态。

+   **观察者**：使用此模式来观察并被通知被观察对象状态的变化。

+   **状态**：使用此模式在对象状态改变时改变对象的行为。

+   **策略**：使用此模式来定义一系列可互换的封装算法。

+   **模板方法**：使用此模式来定义一个算法和可以在子类中重写的步骤。

+   **访问者**：使用此模式向现有对象添加新操作而无需修改它们。

由于本书的限制，我们没有足够的页面来涵盖行为设计模式。鉴于此，我将指导您阅读以下书籍，以进一步了解设计模式。第一本书名为《C#设计模式：实例指南》，作者是 Vaskaring Sarcar，由 Apress 出版。第二本书名为《.NET 设计模式：C#和 F#中的可重用方法》，作者是 Dmitri Nesteruk，也由 Apress 出版。第三本书名为《使用 C#和.NET Core 的设计模式实战》，作者是 Gaurav Aroraa 和 Jeffrey Chilberto，由 Packt 出版。

在这些书籍中，您不仅将了解所有的模式，还将获得真实世界示例的经验，这将帮助您从仅仅拥有理论知识转变为具有实际技能，能够在自己的项目中以可重用的方式使用设计模式。

这就是我们对设计模式实现的介绍。在总结我们所学到的知识之前，我将给您一些关于清晰代码和重构的最终思考。

# 最后的思考

软件开发有两种类型——**brownfield 开发**和**greenfield 开发**。我们职业生涯中大部分时间都在进行 brownfield 开发，即维护和扩展现有软件，而 greenfield 开发则是新软件的开发、维护和扩展。在 greenfield 软件开发中，你有机会从一开始就编写清晰的代码，我鼓励你这样做。

确保在开始工作之前对项目进行适当规划。然后，利用可用的工具自信地开发清晰的代码。在进行 brownfield 开发时，最好花时间彻底了解系统，然后再进行维护或扩展。不幸的是，你可能并不总能有这样的时间。因此，有时你会开始编写你需要的代码，却没有意识到已经存在可以执行你正在实现的任务的代码。保持你编写的代码清晰和结构良好，将使项目后期的重构更加容易。

无论你正在进行的项目是 brownfield 还是 greenfield 项目，你都要确保遵循公司的程序。这些程序存在是有充分理由的，即开发团队之间的和谐以及清晰的代码库。当你在代码库中遇到不清晰的代码时，应立即考虑进行重构。

如果代码太复杂而无法立即更改，且需要跨层进行太多更改，那么这些更改必须被记录为项目中的技术债务，待适当规划后再进行处理。

在一天结束时，无论你自称自己是软件架构师、软件工程师、软件开发人员，或者其他任何称谓，你的**编程技能**才是你的生计。糟糕的编程可能对你目前的职位有害，甚至可能对你找到新职位产生负面影响。因此，尽一切资源确保你当前的代码给人留下持久的良好印象，展现你的能力水平。我曾听人说过以下话：

*"你的最后一个编程任务决定了你的水平！"*

在架构系统时，不要过于聪明，不要构建过于复杂的系统。将程序的继承深度控制在 1 以内，并尽力通过利用 LINQ 等函数式编程技术来减少循环。

你在第十三章中看到了，*重构 C#代码——识别代码异味*，LINQ 比`foreach`循环更高效。尽量减少软件的复杂性，限制计算机程序从开始到结束的路径数量。通过在编译时移除可以编织到代码中的样板代码，减少样板代码的数量。这样可以将方法中的行数减少到仅包含必要业务逻辑的行数。保持类小而专注于单一职责。同时，保持方法的代码行数不超过 10 行。类和方法必须只执行单一职责。

学会保持你编写的代码简单，以便易于阅读和理解。理解你所编写的代码。如果你能轻松理解自己的代码，那就没问题。现在，问问自己：*在另一个项目上工作后回到这个项目，你是否仍能轻松理解代码？*当代码难以理解时，就必须进行重构和简化。

不这样做可能会导致一个臃肿的系统，最终慢慢而痛苦地死去。使用文档注释来记录公开可访问的代码。对于隐藏的代码，只有在代码本身无法充分解释时才使用简洁而有意义的注释。对于经常重复的常见代码，使用模式以避免重复（DRY）。Visual Studio 2019 中的缩进是自动的，但默认的缩进在不同的文档类型中并不相同。因此，确保所有文档类型具有相同级别的缩进是一个好主意。使用微软建议的标准命名规范。

给自己一些编程挑战，不要复制粘贴他人的源代码。使用基准测试（性能分析）来重写相同的代码，以减少处理时间。经常测试你的代码，确保它表现正常并完成了它应该完成的任务。最后，练习，练习，然后再练习。

我们都会随着时间改变自己的编程风格。如果在一个采用了许多不良实践的团队中，一些程序员的代码会随着时间的推移而恶化。而另一些程序员的代码会随着时间的推移而改善，如果他们在一个采用了许多最佳实践的团队中。不要忘记，仅仅因为代码能编译并且能够完成其预期功能，并不一定意味着它是最清晰或者最高效的代码。

作为一名计算机程序员，你的目标是编写清晰高效的代码，易于阅读、理解、维护和扩展。练习实施 TDD 和 BDD，以及 KISS、SOLID、YAGNI 和 DRY 的软件范式。

考虑从 GitHub 上检出一些旧的代码，作为将旧的.NET 版本迁移到新的.NET 版本的培训机会，并重构代码以使其清晰高效，并添加文档注释以为开发团队生成 API 文档。这对磨练个人计算机编程技能是一个很好的实践。通过这样做，你经常会遇到一些相当聪明的代码，可以从中学习。有时，你可能会想知道程序员当时在想什么！但无论如何，利用每一个机会来提高你的清晰编码技能只会使你变得更强大、更优秀的程序员。

我相信编程领域的另一句话是：

“要成为真正的专业计算机程序员，你必须超越目前的能力。”

因此，无论你或你的同行认为你有多么专业，永远记住你可以做得更好。因此，不断前进，提高自己的水平。然后，当你退休时，你可以以一名计算机程序员的辉煌成就为荣，回顾你的职业生涯！

现在让我们总结一下我们在本章学到的内容。

# 总结

在本章中，我们涵盖了几种创建型、结构型和行为型设计模式。你利用本章学到的知识来查看遗留代码并理解其目标。然后，你使用本章学到的模式来重构现有代码，使其更易于阅读、理解、维护和扩展。通过使用本书中的模式以及其他可用的模式，你可以重构现有代码并从一开始编写清晰的代码。

你还使用了创建型设计模式来解决现实世界的问题，并提高了代码的效率。使用结构型设计模式来改善代码的整体结构和对象之间的关系。此外，使用行为设计模式来改善对象之间的通信，同时保持这些对象的解耦。

好吧，这是本章的结束，我感谢你抽出时间阅读这本书并通过代码示例进行学习。记住，软件应该是一种愉悦的工作。因此，我们不需要不洁净的代码给我们的业务、开发和支持团队以及软件的客户带来问题。因此，请考虑你正在编写的代码，并始终努力成为比今天更好的程序员——无论你在这个行业已经工作了多少年。有一句古话：*无论你有多优秀，你总是可以做得更好*！

让我们测试一下你对本章内容的了解，然后我会给你一些进一步阅读的建议。祝你在 C#中编写干净的代码！

# 问题

1.  GoF 模式是什么，为什么我们要使用它们？

1.  解释创建设计模式的用途并列举它们。

1.  解释结构设计模式的用途并列举它们。

1.  解释行为设计模式的用途并列举它们。

1.  是否可能过度使用设计模式并称之为代码异味？

1.  描述单例设计模式以及何时使用它。

1.  为什么我们要使用工厂方法？

1.  你会使用什么设计模式来隐藏一个庞大且难以使用的系统的复杂性？

1.  如何最小化内存使用并在对象之间共享公共数据？

1.  用于将抽象与其实现解耦的模式是什么？

1.  如何构建同一复杂对象的多个表示？

1.  如果你有一个需要经过多个阶段的操作才能将其转换为所需状态的项目，你会使用什么模式，为什么？

# 进一步阅读

+   *重构：改善现有代码的设计*，作者：Martin Fowler

+   *规模化的重构*，作者：Maude Lemaire

+   *软件开发、设计和编码：使用模式、调试、单元测试和重构*，作者：John F. Dooley

+   *软件设计异味的重构*，作者：Girish Suryanarayana, Ganesh Samarthyam 和 Tushar Sharma

+   *重构数据库：演进式数据库设计*，作者：Scott W. Ambler 和 Pramod J. Sadalage

+   *重构到模式*，作者：Joshua Kerievsky

+   *C#7 和.NET Core 2.0 高性能*，作者：Ovais Mehboob Ahmed Khan

+   *提高你的 C#技能*，作者：Ovais Mehboob Ahmed Khan, John Callaway, Clayton Hunt 和 Rod Stephens

+   *企业应用架构模式*，作者：Martin Fowler

+   *与遗留代码的有效工作*，作者：Michael C. Feathers

+   [`www.dofactory.com/products/dofactory-net`](https://www.dofactory.com/products/dofactory-net)：dofactory 提供的用于 RAD 的 C#设计模式框架

+   *使用 C#和.NET Core 的设计模式实践*，作者：Gaurav Aroraa 和 Jeffrey Chilberto

+   *使用 C#和.NET Core 的设计模式*，作者：Dimitris Loukas

+   *C#中的设计模式：实际示例指南*，作者：Vaskaring Sarcar
