# C# 面向对象编程实用指南（三）

> 原文：[`zh.annas-archive.org/md5/ADAC00B29224B3ED5BF1EE522FE998CB`](https://zh.annas-archive.org/md5/ADAC00B29224B3ED5BF1EE522FE998CB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：Visual Studio 和相关工具

Visual Studio 是微软的**集成开发环境**（**IDE**）。它是一种计算机软件，可以用来编写、调试和执行代码。Visual Studio 是行业中最受欢迎的 IDE 之一，主要用于.NET 应用程序。由于它来自微软，因此使.NET 开发变得非常简单和顺畅。您可以使用 Visual Studio 进行其他编程语言，但我不能保证它会是最有用的选择；然而，对于像我这样的 C#开发人员来说，这是最好的 IDE。作为开发人员，我大部分时间都在 Visual Studio 中度过。

在撰写本书时，Visual Studio 的最新版本是 Visual Studio 2017。微软推出了不同版本的 Visual Studio。其中之一是社区版，是免费的。还有另外两个版本：Visual Studio 专业版和 Visual Studio 企业版。专业版和企业版是收费的，更适合大型项目。在本书中，我们将探讨社区版的功能，因为它是免费的，并且具有足够的功能来满足本书的目的。

在本章中，我们将学习 Visual Studio 的特性。我们将涵盖以下主题：

+   Visual Studio 项目类型和模板

+   Visual Studio 编辑器和不同的窗口

+   调试窗口

+   断点、调用堆栈跟踪和监视

+   Visual Studio 中的 Git

+   重构和代码优化技术

# Visual Studio 项目类型和模板

Visual Studio 是与微软相关技术堆栈的最佳 IDE。无论您是计划为 Windows 开发桌面应用程序还是为 Windows Server 开发 Web 应用程序，都可以使用 Visual Studio。使用 Visual Studio 的最佳部分是，如果您没有使用它，IDE 将帮助您完成许多常见任务，否则您将不得不手动执行这些任务。例如，如果您计划使用 ASP.NET **Model-View-Controller**（**MVC**）创建 Web 应用程序，Visual Studio 可以为您提供 MVC 应用程序的模板。您可以从模板开始，并根据您的要求进行修改。如果没有这个，您将不得不下载包，创建文件夹，并为应用程序设置 Web 配置。要充分利用 Visual Studio，您必须了解它提供的不同项目和模板，以便加快开发过程。

让我们来看看 Visual Studio 提供的不同项目类型。打开 Visual Studio 后，如果单击“新建项目”，将弹出以下窗口：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/6483b062-3e94-4810-82fd-024b9d769227.png)

在左侧，我们可以看到项目的主要类别：最近、已安装和在线。在“最近”选项卡中，您可以看到最近使用过的项目类型，因此您不必每次都搜索常用的项目类型。在“已安装”选项卡中，您将找到已经安装在计算机上的项目类型。安装 Visual Studio 时，您可以选择要安装哪些工作负载。

在安装 Visual Studio 时会出现的工作负载窗口如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/fc58e654-17d5-4442-acd0-74c2eac96931.png)

您选择的工作负载选项与安装的项目类型直接相关。在“在线”选项卡下，您将找到在安装 Visual Studio 时未安装的项目。Visual Studio 提供了许多项目模板，这就是为什么它们不会一次全部安装的原因。

现在，如果我们展开“已安装”选项卡，我们将看到不同的编程语言显示为子选项卡：Visual C#、Visual Basic、Visual C++等。由于本书涉及 C#，我们将只关注 Visual C#区域，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/2c7b657b-5369-4009-b4e3-6991495163e5.png)

如果我们展开 Visual C#选项卡，我们将看到与更具体类型的项目相关的更多选项卡，例如 Windows 桌面、Web、.NET Core、测试等。但是，如果我们专注于窗口的中间部分，我们将看到不同的项目模板，例如 Windows 窗体应用程序（.NET Framework）、控制台应用程序（.NET Core）、控制台应用程序（.NET Framework）、类库（.NET 标准）、类库（.NET Framework）、ASP .NET Core Web 应用程序、ASP.NET Web 应用程序（.NET Framework）等。在窗口的右侧，我们可以看到您在中间窗格中选择的项目模板的简短描述，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/446af09c-d6c1-472b-9b81-d871430bcbd5.png)

让我们来看一下 Visual Studio 2017 中提供的一些最常见的项目模板：

+   **控制台应用程序：** 用于创建命令行应用程序的项目。这种类型的项目有两种不同的类型：一个用于.NET Core，另一个用于.NET Framework。

+   **类库：** 如果您正在开发可以用作另一个项目的扩展代码的类库项目，则可以使用此模板。在 Visual Studio 2017 中，您再次获得两个选项：一个用于.NET 标准，另一个用于.NET Framework。

+   **ASP.NET Core Web 应用程序：** 用于使用.NET Core 的 Web 应用程序。您可以使用此类型的项目创建 MVC、Web API 和 SPA 应用程序。

+   **ASP.NET Web 应用程序（.NET Framework）：** 此项目模板用于使用.NET Framework 开发 Web 应用程序。与 ASP.NET Core Web 应用程序模板类似，使用此项目模板，您可以选择 MVC、Web API 或 SPA 项目。

+   **WCF 服务器应用程序：** 您可以使用此项目类型来创建**Windows 通信基础**（**WCF**）服务。

+   **WPF 应用程序（.NET Framework）：** 如果您正在创建**Windows 演示基础**（**WPF**）项目，可以选择此模板。

+   **单元测试项目（.NET Framework）：** 这是一个用于单元测试的项目。如果您创建此项目，您将获得一个预制的测试类，并且您可以使用它来编写您的单元测试。

还有许多其他可供.NET 开发人员使用的项目模板。如果您确定应用程序的目的，最好从项目模板开始，而不是从空白模板开始。

# Visual Studio 编辑器和不同的窗口

Visual Studio 不像简单的文本编辑器。它有许多工具和功能，因此可能有点压倒性。但是，要开始，您不需要了解每个工具和功能：您只需要基础知识。随着您对其了解的增加，您可以充分利用其功能，使您的生活更轻松，提高您的生产力。在本章的后面，我们还将学习一些非常有用的键盘快捷键。我们首先来看一下基础知识。

# 编辑器窗口

在 Visual Studio 中创建或打开项目后，您将看到一个屏幕，看起来像下面的截图所示，除非您有不同的环境设置。在左侧，显示代码的窗口称为**编辑器窗口**。这是您将编写代码的窗口。这个编辑器窗口非常智能；当文件在编辑器中打开时，它会出现在左上角。如果有多个文件打开，活动文件将具有蓝色背景，而非活动文件将是黑色，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/2d7482e4-5b5b-4a40-a144-0fffee700eed.png)

行号显示在每行代码的左侧，代码以不同的颜色表示。蓝色的单词是 C#中的保留关键字，白色的文本是您的活动可修改的代码，绿色的文本表示类名，橙色的文本表示字符串文本。Visual Studio 中还有一些其他颜色、下划线标记和符号可帮助您更好地理解代码。如果您正在阅读本书的黑白副本，我建议您打开 Visual Studio 并编写代码以检查颜色表示。例如，看看以下屏幕截图中的`using`语句。除了`System`命名空间外，所有其他命名空间都是较暗的颜色，这意味着这些命名空间在此文件中尚未使用。`System`命名空间是明亮的白色，因为我们在代码中使用了`Console.WriteLine()`方法，该方法属于`System`命名空间。您还可以看到代码左侧带有-符号的方框，下面有一条水平线。这显示了代码折叠选项。

您可以轻松折叠代码以更清晰地查看特定代码：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/e7c57821-4827-41bd-93bb-21403ba9dba0.png)

从左花括号到右花括号的虚线显示了括号覆盖的区域。因此，即使您没有将左右花括号放在同一垂直线上，您也能够看到这些花括号覆盖的行，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/c0d23a18-60a4-4b3e-8af1-970a6873e9d4.png)

编辑器窗口还有一些其他有用的功能，如**智能感知**和**重构**。智能感知在编写代码时建议其他选项或组件的更多细节，包括代码完成、有关代码的信息、代码的使用和代码要求。例如，如果您正在编写`Console`，它将建议您可能想要编写的不同选项，并告诉您该特定代码的作用以及如何使用它，如下面的屏幕截图所示。在学习不同方法及其用法时，这非常有帮助：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/8c158fc2-814e-419c-8260-a649408ab38e.png)

不同的控制台方法

重构意味着改进代码而不改变其功能。本章后面，我们将详细讨论重构。

编辑器窗口中另一个非常有趣的功能是快速操作，它是所选代码行左侧的灯泡。它建议 Visual Studio 认为您应该更改有关该特定代码行的内容。您还可以使用此功能重构代码。例如，如果我们在编写`Console`的过程中停下来看看灯泡，它将在灯泡底部显示一个红色叉，这意味着这行代码无效，Visual Studio 有一些建议。让我们看看它推荐了什么，以及我们是否可以使用它来修复我们的代码。

如果我们点击气泡，它将显示您在以下屏幕截图中可以看到的选项。从那里，将“Conso”更改为“Console”是我们要执行的选项。如果我们点击它，Visual Studio 将为您修复代码：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/d62855e5-8bc6-4d96-a1ba-a61fe8156509.png)

让我们看看如何使用快速操作重构我们的代码。如果我们尝试创建一个在代码库中不存在的类的对象，它会显示一个带有红色叉的气泡。如果您查看选项，您会看到 Visual Studio 正在询问是否应该为您创建一个类，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/283980d1-e39b-41ed-9e7a-5e432825cc8a.png)

编辑器窗口中还有许多其他功能可使您作为开发人员的生活更加高效。我建议您尝试更多这些功能，并阅读更多文档以了解更多。

# 解决方案资源管理器

如果您看一下 Visual Studio 右侧，您将看到一个名为 Solution Explorer 的窗口。这是 Visual Studio 中非常重要的窗口；它显示了您正在工作的解决方案中的文件和文件夹。在 Visual Studio 中，解决方案就像是不同项目的包装器。这个术语可能有点令人困惑，因为我们通常会使用“项目”这个词来标识特定的工作。在 Visual Studio 中，解决方案被创建为包装器，项目被创建在解决方案中。一个解决方案中可以有多个项目。这种分解有助于创建模块化应用程序。在这个 Solution Explorer 窗口中，您可以看到解决方案中有哪些项目，项目中有哪些文件。

您可以展开或最小化项目和文件夹以获得更好的视图，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/24dcd239-c11b-4fd1-8d12-77ee6818bf64.png)

在上面的屏幕截图中，您可以看到我们有一个名为 ExploreVS 的解决方案，里面有一个名为 ExploreVS 的项目。这里项目和解决方案的名称相同，因为在创建解决方案时，我们选择使用相同的名称。如果需要，您可以为解决方案和项目使用不同的名称。

在 Solution Explorer 窗口中，您可以右键单击解决方案并轻松添加另一个项目。如果要将文件或文件夹添加到项目中，可以右键单击并添加。在下面的屏幕截图中，您可以看到我们已经将另一个名为 TestApp 的项目添加到解决方案中，以及在 ExploreVS 项目中添加了一个名为 Person 的类。您还可以看到解决方案名称旁边包含的项目数量。Solution Explorer 中还有一个搜索选项，可以在大型解决方案中轻松搜索文件，以及一些其他功能隐藏在顶部的图标后面。圆形箭头刷新 Solution Explorer。其旁边的堆叠框折叠项目以获得解决方案的高级视图。之后，具有三个文档的图标显示 Solution Explorer 中的所有文档。这是必要的，因为并非每个文件都始终可供查看，Visual Studio 给我们提供了将文件从解决方案中排除的选项。这不会从文件系统中删除文件，而只是在解决方案中忽略它。然后，在该图标旁边，我们有一个查看代码的图标，它将在代码编辑器中打开代码。我们还有一个属性图标，它将显示文件或项目的属性。

在左侧，我们有主页图标，它将带您到主页面板。旁边是解决方案和文件夹切换器。如果单击它，您将看到文件系统的文件夹，而不是解决方案，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/78586a30-1204-4649-ac5d-e8b55aecf29f.png)

# 输出窗口

输出窗口对于开发人员来说是非常重要的窗口，因为所有构建和调试的日志和输出都可以在这里查看。如果构建应用程序失败，您可以使用输出窗口找出问题所在并解决问题。如果构建成功运行，您将在输出窗口中收到构建成功的消息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/253dec8c-d80e-4788-a7a2-3ba946d64784.png)

您可以在此窗口中查看不同类型的日志，例如版本控制日志。要更改选项，请转到“显示输出来源”旁边的下拉菜单，并查看特定输出的日志。您可以通过单击具有水平线和红色叉的图标来清除日志，并使用下一个图标切换换行功能。 

# 调试窗口

调试是软件开发的非常重要的部分。当您编写一些代码时，很有可能您的代码不会第一次构建。即使它构建了，您可能也得不到预期的结果。这就是调试派上用场的地方。如果您使用文本编辑器，调试一些代码可能会很困难，因为普通的文本编辑器不提供任何调试工具，因此您可能需要使用控制台。然而，Visual Studio 为调试提供了一些出色的工具和功能，这可以让您的工作效率大大提高。要找到这些工具，请从 Visual Studio 菜单栏中转到“调试”菜单，然后单击“窗口”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/dc13ed4e-43a9-4e82-adf6-685b9b6f9a09.png)

从此列表中，我们可以看到不同的窗口如下：

+   断点

+   异常设置

+   输出

+   显示诊断工具

+   立即

+   Python 调试交互

# 断点窗口

断点窗口列出了您在代码库中放置的断点。它显示有关标签、条件、过滤器、文件名、函数名和代码库中的其他属性的信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/4c7c2741-8b3e-40a3-85b6-9ef2f79fc0b2.png)

如果您不了解断点的标签、条件和操作，让我们简要地看一下它们的列表：

+   标签：您可以为断点命名或给断点添加标签，以便轻松识别其目的。您可以右键单击断点，然后选择“编辑标签”以添加标签或从以前的标签中选择，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/22cb45ce-fabd-410f-8339-18ac61100562.png)

+   条件：您可以在断点上设置条件。这意味着只有在这些条件为真时，断点才会停止。要向断点添加条件，请右键单击断点，然后单击“条件”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/dbd6d9f3-8c03-4975-9f4d-5e5f667630cd.png)

+   操作：与条件一样，您可以向断点添加操作。操作的一个示例可能是在日志系统或控制台中写入。

断点窗口还具有一些其他功能。您可以删除解决方案的所有断点，禁用或启用断点，导入或导出断点，转到断点的代码位置，或搜索断点。

# 异常设置

异常设置窗口显示可用的不同异常。如果打开窗口，您将看到异常列表和每个项目旁边的复选框。如果要在 Visual Studio 中使调试器中断该异常，请选中复选框，如下面的代码所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/8277ec5e-fada-45cb-b03c-ab91ed53d129.png)

# 输出

我们已经在前一节讨论了输出窗口。您可以在输出窗口中输出不同的值，以检查它们是否正确。您可以在输出窗口中读取有关异常的信息，以了解更多关于异常的信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/e565d9c7-d4e6-4a52-b145-b40b22f5d4bb.png)

# 诊断工具

诊断工具窗口将显示应用程序的性能。您可以检查它使用了多少内存和 CPU，以及其他一些与性能相关的数字，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/5efa7440-f6e9-4d0b-89c2-00f578681136.png)

# 立即窗口

立即窗口可帮助您在运行应用程序时调试变量、方法和其他代码短语的值。您可以手动检查运行程序的某一点上不同变量的值。您可以通过在此窗口中执行方法来检查方法的返回值。在下面的屏幕截图中，您可以看到我们将值`1`设置为名为`x`的`int`变量。然后，我们执行一个名为`Add(x,5)`的方法，该方法返回两个数字的和。在这里，我们将`x`和`5`作为参数传递，并得到`6`作为返回值：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/effbdc86-7652-41ed-8747-d3337657d0bf.png)

# Python 调试器窗口

使用 Python 调试器窗口，您可以在 Visual Studio 中运行您正在工作的应用程序上的 Python 脚本。由于本书与 Python 编程语言无关，我们不会详细讨论此窗口。

# 断点、调用堆栈跟踪和监视

在前一节中，我们看了在 Visual Studio 中用于调试的窗口。现在我们将详细看一些很酷的功能——断点、调用堆栈跟踪和监视。

# 断点

**断点**不是 C#编程语言的功能，而是 Visual Studio 自带的调试器的功能。断点是您想要暂停调试器以检查代码的代码中的一个位置。在 Visual Studio 中，断点可以在代码编辑器窗口的左侧窗格中找到。要添加断点，请单击适当的代码行，将出现一个代表断点的红色球。您还可以使用*F9*键（或功能 9 键）作为切换断点的键盘快捷键。

下面的屏幕截图显示了 Visual Studio 中断点的外观：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/393a9fca-e239-448b-98c2-e3b53d05b0df.png)

在您设置断点之后，调试器将在该位置暂停，并为您提供查看数据的选项。当调试器在断点处暂停时，您可以选择 Step Into、Step Over 或 Step Out 来浏览代码，如顶部栏中的箭头所示。在圆圈中，您将看到一个箭头指示调试器当前指向的位置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/bd343ee9-3ac2-4a96-b837-312cb2cb99a7.png)

断点的主要目的是检查数据，并查看特定代码在运行时的反应。Visual Studio 提供了一种非常简单的方法来使用断点调试代码。

# 调用堆栈跟踪

调用堆栈是调试应用程序时非常有用的窗口。它显示应用程序的流程，并告诉您已调用哪些方法以达到某一点。例如，如果您有一个可以由两个不同来源调用的方法，那么通过查看调用堆栈，您可以轻松地确定哪个来源调用了该方法，并更好地了解程序流程。

# 监视窗口

监视窗口是 Visual Studio 中调试的另一个非常有用的功能。在您的代码库中，您可能会遇到需要检查特定变量值的情况。每次悬停查看值都很耗时。相反，您可以将这些变量添加到监视列表中，并在 Visual Studio 中保持监视窗口打开，以查看这些变量在那一刻的值。

在下面的屏幕截图中，您可以看到监视窗口是如何用来监视变量值的：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/b599bad8-7b1f-4baa-af0f-388bb74d1cfe.png)

# Visual Studio 中的 Git

版本控制现在是软件开发的必要部分。无论项目大小如何，版本控制对每个软件应用程序都是必不可少的。有许多版本控制系统可用，但 Git 是最流行的。对于远程存储库，您可以使用 Microsoft Team Foundation Server、Microsoft Azure、GitHub 或任何其他远程存储库。由于 GitHub 也是最受欢迎的远程存储库，我们将在本节中看一下如何将其与 Visual Studio 集成。

目前，默认情况下，Visual Studio 没有与 GitHub 连接的功能，因此您必须使用扩展。要获取扩展，转到工具|扩展和更新。然后，在在线类别中搜索 GitHub。您将看到一个名为 Github Extension for Visual Studio 的扩展，如下面的屏幕截图所示。安装扩展并重新启动 Visual Studio：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/73ced821-35da-402d-9b90-8449e7be13c3.png)

现在，如果你打开 Team Explorer 窗口，你可以看到 GitHub 的一个部分。输入你的 GitHub 凭据并连接，如下截图所示。连接确认后，你就可以通过 Visual Studio 与 GitHub 进行通信了：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/e3fa6855-10aa-4fb3-9921-be0c44b3b242.png)

你可以从 Visual Studio 创建或克隆存储库，并继续提交代码并将其推送到 GitHub 的远程存储库。你还可以在 Visual Studio 中执行所有主要的 Git 任务。你可以创建分支，推送和拉取代码，并发送拉取请求。

下面的截图显示了 Visual Studio Team Explorer 窗口中的 Git 面板：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/9c55d594-504c-41d6-847a-682e0c3ed057.png)

能够使用 IDE 处理版本控制而无需使用任何外部软件非常有用。你也不需要使用 CLI 进行版本控制。

# 重构和代码优化技术

如果你不了解重构的概念，我建议你进行进一步的研究；这是一个非常有趣的话题，对于软件开发的质量至关重要。基本上，重构是指修改现有代码以改进代码而不改变其功能的过程。

Visual Studio 提供了一些出色的重构功能和工具。我们将在接下来的部分中看一些这些功能。

# 重命名

你可以使用 Visual Studio 的重命名功能来更改方法、字段、属性、类或其他任何内容的名称，如下截图所示。要做到这一点，选中实体，然后按两次*Ctrl + R*。或者，转到编辑|重构|重命名。通过这种方式更改名称后，它将在使用的任何地方更新。这个简单的重构步骤允许你随时更改名称：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/07a47997-91f1-4024-8902-fd67981215cd.png)

# 更改方法签名

假设你有一个在解决方案中多处使用的方法。现在，如果你更改该方法的参数，你的代码将在你修复每处使用该方法之前都会出错。手动操作这样做很耗时，而且很可能会产生错误。Visual Studio 提供了一个重构功能，可以用来在代码中使用的地方重构方法签名，如下截图所示。

如果你想要更改方法中的参数顺序，你可以使用*Ctrl + R*和*Ctrl + O*，或者点击编辑|重构|重新排序参数。要从方法中删除参数，你可以使用*Ctrl + R*和*Ctrl + V*，或者点击编辑|重构|删除参数：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/ff97c12e-9cea-4bae-8abe-4ea81c4492aa.png)

建议始终使用 Visual Studio 重构工具，而不是手动重构。

# 封装字段

你可以使用 Visual Studio 重构工具将字段转换为属性，而不是手动操作。选中字段，然后按*Ctrl + R*和*Ctrl + E*，或者转到编辑|重构|封装字段。

这将更改代码中使用变量的所有位置，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/0bd343d1-a5f0-4f0f-bd02-9264bf9eb64e.png)

# 提取方法

如果你看到一段代码，认为它应该在一个方法中，你可以使用提取方法重构来提取选定的代码，并为其创建一个新的方法，如下截图所示。重构工具非常智能，它还可以确定方法是否应该返回特定的值。要做到这一点，选择要提取到方法中的代码，然后按下*Ctrl + R*和*Ctrl + M*，或者转到编辑|重构|提取方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/41d2dce3-771a-41d1-82cf-e39cf35c7071.png)

Visual Studio 中还有许多其他重构功能。这里不可能覆盖所有内容；我建议你查看 Visual Studio 文档以获取更多信息。

# 摘要

Visual Studio 是 C#开发人员的必备工具；正确理解它将提高您的生产力。在本章中，我们讨论了与 Visual Studio 相关的各种概念，包括其项目和模板，不同的编辑器和窗口，以及其调试功能。我们还研究了断点、调用堆栈跟踪和监视窗口，以及如何利用这些来优化调试过程。之后，我们探讨了 Git 和 GitHub 与 Visual Studio 的集成。最后，我们谈到了 Visual Studio 中可用的不同重构功能。在一本书的一章中很难涵盖与这样一个非凡的集成开发环境相关的所有概念；我建议您尝试使用它并进一步探索，以便学会如何以最佳方式使用它。在下一章中，我们将讨论数据库和 ADO.NET。


# 第十章：使用示例探索 ADO.NET

如果您有任何与 Web 开发的经验，您可能听说过 ASP.NET，这是一个用于 Web 开发的框架。同样，如果您以前在.NET 项目中使用过数据库，您应该听说过或使用过 ADO.NET。ADO.NET 是一个类似于 ASP.NET 的框架，但是与 Web 开发不同，这个框架用于与数据库相关的工作。**ActiveX Data Object**（**ADO**）是微软创建的一个旧技术，但是演变为 ADO.NET 是非凡的。ADO.NET 包含可以用于轻松与数据库管理系统（如 SQL Server 或 Oracle）建立连接的类和方法。不仅如此，它还提供了帮助在数据库中执行命令的方法和对象，比如 select、insert、update 和 delete。

我们需要一个单独的框架来进行数据库连接和活动，因为在开发应用程序时可以使用许多不同的数据库系统。数据库是应用程序的一个非常重要的部分；应用程序需要数据，数据需要存储在数据库中。由于数据库如此重要且有如此多的数据库可用，开发人员要编写所有必要的代码将会非常困难。当我们可以编写可重用的代码时，写入单独的代码片段是不值得的。这就是为什么微软推出了 ADO.NET 框架。这个框架有不同的数据提供程序、数据集、数据适配器和与数据库相关的各种其他东西。

本章将涵盖以下主题：

+   ADO.NET 的基础知识

+   `DataProvider`、`Connection`、Command、`DataReader`和`DataAdapter`

+   连接 SQL Server 数据库和 Oracle 数据库

+   存储过程

+   实体框架

+   SQL 中的事务

# ADO.NET 的基础知识

要了解 ADO.NET，我们需要知道应用程序如何与数据库交互。然后，我们需要了解 ADO.NET 如何支持这个过程。让我们先学习一些重要的概念。

# 数据提供程序

ADO.NET 中有不同类型的数据提供程序。最流行的数据提供程序是 SQL Server、**Open Database Connectivity**（**ODBC**）、**Object Linking and Embedding Database**（**OLE DB**）和**Java Database Connectivity**（**JDBC**）。这些数据提供程序具有非常相似的代码结构，这使得开发人员的生活变得更加轻松。如果您以前使用过其中一个，您将能够在不太困难的情况下使用其他任何一个。这些数据提供程序可以分为不同的组件：连接、命令、DataReader 和 DataAdapter。

# 连接对象

连接是一个组件，用于与数据库建立连接以在数据库上执行命令。无论您想连接哪个数据库，都可以使用 ADO.NET。即使没有特定的数据提供程序用于特定的数据库，您也可以使用 OLE DB 数据提供程序与任何数据库连接。这个连接对象有一个名为`connectionstring`的属性。这是连接的最重要的元素之一。`connection`字符串是一个包含数据的键值对的字符串。例如，`connection`字符串包含有关数据库所在服务器、数据库名称、用户凭据以及一些其他信息。如果数据库在同一台计算机上，您必须使用`localhost`作为服务器。`ConnectionString`包含数据库名称和授权数据，例如访问数据库所需的用户名和密码。让我们看一个 SQL Server 的`connectionString`的例子：

```cs
SqlConnection con = new SqlConnection();
Con.connectionString = "Data Source=localhost; database=testdb; Integrated Security=SSPI";
```

在这里，`Data Source`是服务器名称，因为数据库位于同一台计算机中。`connection`字符串中的`database`关键字保存了数据库的名称，在这个例子中是`testdb`。您会在一些`connection`字符串中看到`Initial Catalog`而不是`connection`字符串中的`database`关键字用于存储数据库的名称。您可以在`connection`字符串中使用`Initial Catalog`或`database`来指定数据库的名称。我们在这里的`connectionString`属性的最后一部分是`Integrated Security`，它用作身份验证。如果将其设置为`TRUE`或`SSPI`，这意味着您正在指示程序使用 Windows 身份验证来访问数据库。如果您有特定的数据库用户要使用，您可以通过在`connection`字符串中添加`user`关键字和`password`关键字来指定。您还可以提供一些其他数据，包括连接超时和连接超时。这个`connection`字符串包含了所需的最少信息。

# Command 对象

Command 对象用于向数据库发出指令。每个数据提供程序都有其自己的`command`对象，该对象继承自`DbCommand`对象。SQL 数据提供程序中的`command`对象是`SqlCommand`，而 OLE DB 提供程序具有`OleDbCommand`对象。命令对象用于执行任何类型的 SQL 语句，如`SELECT`，`UPDATE`，`INSERT`或`DELETE`。命令对象还可以执行存储过程。稍后在*使用存储过程*部分，我们将看看如何做到这一点。它们还有一些方法，用于让编译器知道我们正在执行的命令类型。例如，`ExecuteReader`方法在数据库中查询并返回一个`DataReader`对象：

```cs
using System.Data.SqlClient;
using System;
using System.Data;

public class Program
{
    public static void Main()
    {
        string connectionString = "Data source = localhost;Initial Catalog=  TestDBForBook;Integrated Security = SSPI;";
        SqlConnection conn = new SqlConnection(connectionString);
        string sql = "SELECT * FROM Person";
        SqlCommand command = new SqlCommand(sql, conn);
        conn.Open();
        SqlDataReader reader = command.ExecuteReader();
        while (reader.Read())
        {
            Console.WriteLine("FirstName " + reader[1] + " LastName " +  reader[2]);
        }
        conn.Close();
    }
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/6f96dd52-b7d0-43c7-b7e0-2f3fee8e016c.png)

数据库表如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/ebac9153-a68e-4396-a835-8fd820be2ee0.png)

`ExecuteNonQuery`是另一个主要用于执行非查询方法的方法，例如`INSERT`，`UPDATE`和`DELETE`。当您向数据库中插入一些数据时，您不会在数据库中查询任何内容，您只是想要插入数据。更新和删除也是一样。`ExecuteNonQuery`方法返回一个`INT`值，表示命令影响了数据库中多少行。例如，如果您在`Person`表中插入一个人，您将在表中插入一行新数据，因此只有一行受到影响。该方法将因此向您返回`1`。

让我们看看`ExecuteNonQuery()`方法的示例代码：

```cs
using System.Data.SqlClient;
using System;
using System.Data;
public class Program
{
    public static void Main()
    {
        string connectionString = "Data source = localhost;Initial Catalog=  TestDBForBook;Integrated Security = SSPI;";
        SqlConnection conn = new SqlConnection(connectionString);
        string sql = "INSERT INTO Person (FirstName, LastName, Age) VALUES  ('John', 'Nash', 34)";
        SqlCommand command = new SqlCommand(sql, conn);
        conn.Open();
        int rowsAffected = command.ExecuteNonQuery();
        conn.Close();
        Console.WriteLine("Number of rows inserted: " + rowsAffected);
    }
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/3f35418b-b946-4445-ae17-8ee44902ed6c.png)

假设您想要更新 John Nash 先生的`Age`。当您执行`UPDATE`查询时，它将只影响表的一行，因此它将返回`1`。但是，例如，如果您执行一个条件匹配多个不同行的查询，它将更新所有行并返回受影响的总行数。看看以下示例。在这里，我们有一个`Food`表，其中有不同的食物项目。每个项目都有一个类别：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/9f6d39da-42f7-4e37-ad95-9bdc5224b034.png)

在这里，我们可以看到任何食物项目都没有折扣。假设我们现在想要在每个早餐项目上打 5%的折扣。要更改`Discount`值，您将需要执行`UPDATE`命令来更新所有行。从表中，我们可以看到表中有两个早餐项目。如果我们运行一个带有条件的`UPDATE`命令，该条件仅适用于`Category= 'Breakfast'`，它应该影响两行。让我们看看这个过程的 C#代码。我们将在这里使用`ExecuteNonQuery`命令：

```cs
using System.Data.SqlClient;
using System;
using System.Data;
public class Program
{
    public static void Main()
    {
        string connectionString = "Data source = localhost;Initial Catalog=  TestDBForBook;Integrated Security = SSPI;";
        SqlConnection conn = new SqlConnection(connectionString);
        string sql = "UPDATE Food SET Discount = 5 WHERE Category = 'Breakfast'";
        SqlCommand command = new SqlCommand(sql, conn);
        conn.Open();
        int rowsAffected = command.ExecuteNonQuery();
        conn.Close();
        Console.WriteLine("Number of rows inserted: " + rowsAffected);
    }
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/5c24b2fb-f033-42d2-9852-6161247fb734.png)

从输出中我们可以看到影响了`2`行。现在，让我们看看数据库表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/c81a6489-b638-46c0-be38-ab3ab8e8bf1c.png)

我们可以看到有两行被更改了。

如果您使用`ExecuteNonQuery`方法执行`DELETE`命令，它将返回受影响的行数。如果结果为`0`，这意味着您的命令未成功执行。

`SQLCommand`对象中还有许多其他方法。`ExecuteScalar`从查询中返回一个标量值。`ExecuteXMLReader`返回一个`XmlReader`对象。还有其他以异步方式工作的方法。所有这些方法的工作方式都类似于这里显示的示例。

命令对象中有一个名为`CommandType`的属性。`CommandType`是一个枚举类型，表示命令的提供方式。枚举值为`Text`，`StoredProcedure`和`TableDirect`。如果选择文本，SQL 命令将直接在数据源中执行为 SQL 查询。在`StoredProcedure`中，您可以设置参数并执行`storedprocedures`以在数据库中执行命令。默认情况下，值设置为`TEXT`。这就是为什么在之前的示例中，我们没有设置`CommandType`的值。

# DataReader 对象

DataReader 对象提供了一种从数据库中读取仅向前流的行的方法。与其他对象一样，DataReader 是数据提供程序的对象。每个数据提供程序都有不同的 DataReader 对象，这些对象继承自`DbDataReader`。当您执行`ExecuteReader`命令时，它会返回一个`DataReader`对象。您可以处理此`DataReader`对象以收集您查询的数据。如果您正在使用 SQL Server 作为您的数据库，您应该使用`SqlDataReader`对象。`SqlDataReader`有一个名为`Read()`的方法，当您在`DataReader`对象中有可用数据时，它将返回`true`。如果`SqlDataReader`对象中没有数据，`Read()`方法将返回`false`。首先检查`Read()`方法是否为`true`，然后读取数据是一种常见的做法。以下示例显示了如何使用`SqlDataReader`：

```cs
using System.Data.SqlClient;
using System;
using System.Data;

public class Program
{
    public static void Main()
    {
        string connectionString = "Data source = localhost;Initial Catalog=  TestDBForBook;Integrated Security = SSPI;";
        SqlConnection conn = new SqlConnection(connectionString);
        string sql = "SELECT * FROM Person";
        SqlCommand command = new SqlCommand(sql, conn);
        conn.Open();
        SqlDataReader reader = command.ExecuteReader();
        while (reader.Read())
        {
            Console.WriteLine("FirstName " + reader[1] + " LastName " +  reader[2]);
        }
        conn.Close();
    }
}
```

在这里，`command.ExecuteReader()`方法返回一个`SqlDataReader`对象，它保存了查询的结果：

```cs
SELECT * FROM Person
```

首先，我们将返回的对象保存在一个名为**reader**的变量中，它是`SqlDataReader`类型。然后，我们检查它的`Read()`方法是否为`true`。如果是，我们执行以下语句：

```cs
Console.WriteLine("FirstName " + reader[1] + " LastName " +  reader[2]);
```

在这里，读取器作为一个数组在工作，并且我们按顺序从索引中获取数据库表列的值。正如我们从数据库中的以下表结构中看到的那样，它有四列，Id，FirstName，LastName 和 Age：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/e7a7aba8-e697-45b4-8491-53aeafdc4e76.png)

这些列将依次映射。`reader[0]`指的是 Id 列，`reader[1]`指的是 FirstName 列，依此类推。

我们写的语句将打印出 FirstName 列的值，在那里它会找到`reader[1]`。然后它将打印出 LastName 列的值，在那里它会找到`reader[2]`。

如果这个数组索引对您来说很困惑，如果您想要更可读性，可以自由地使用命名索引而不是数字：

```cs
Console.WriteLine("FirstName " + reader["FirstName"] + " LastName " +  reader["LastName"])
```

这将打印相同的内容。我们没有使用`reader[1]`，而是写成了`reader["FirstName"]`，这样更清楚地表明我们正在访问哪一列。如果您使用这种方法，请确保名称拼写正确。

# DataAdapter

`DataAdapter`是从数据源读取和使用数据的另一种方式。DataAdapter 为您提供了一种直接将数据存储到数据集中的简单方法。您还可以使用 DataAdapter 将数据从数据集写回数据源。每个提供程序都有自己的 DataAdapter。例如，SQL 数据提供程序有`SqlDataAdapter`。

# 连接到各种数据库

让我们看一些使用 ADO.NET 连接到不同数据库的示例。如果使用 ADO.NET，您最有可能使用的数据库系统是 SQL Server 数据库，因为在使用 Microsoft 堆栈时这是最佳匹配。但是，如果使用其他源，也不会降低性能或遇到问题。让我们看看如何使用 ADO.NET 连接到其他数据库。

# SQL Server

要连接到 SQL Server，我们需要在 ADO.NET 中使用 SQL Server 提供程序。看一下以下代码：

```cs
using System.Data.SqlClient;
using System;
using System.Data;
public class Program
{
    public static void Main()
    {
        string connectionString = "Data source = localhost;Initial Catalog= TestDBForBook;Integrated Security = SSPI;";
        SqlConnection conn = new SqlConnection(connectionString);
        string sql = "SELECT * FROM Person";
        SqlCommand command = new SqlCommand(sql, conn);
        conn.Open();
        SqlDataReader reader = command.ExecuteReader();
        while (reader.Read())
        {
            Console.WriteLine("FirstName " + reader["FirstName"] + " LastName " +  reader["LastName"]);
        }
        conn.Close();
    }
}
```

# Oracle 数据库

要连接到 Oracle 数据库，我们需要在 ADO.NET 中使用 ODBC 提供程序。看一下以下代码：

```cs
using System.Data.SqlClient;
using System;
using System.Data;
using System.Data.Odbc;
public class Program
{
    public static void Main()
    {
        string connectionString = "Data Source=Oracle9i;User ID=*****;Password=*****;";
        OdbcConnection odbcConnection = new OdbcConnection(connectionString);
        string sql = "SELECT * FROM Person";
        OdbcCommand odbcCommand = new OdbcCommand(sql, odbcConnection);
        odbcConnection.Open();
        OdbcDataReader odbcReader = odbcCommand.ExecuteReader();
        while (odbcReader.Read())
        {
            Console.WriteLine("FirstName " + odbcReader["FirstName"] + " LastName  " + odbcReader["LastName"]);
        }
        odbcConnection.Close();
    }
}
```

# 使用 DataReaders 和 DataAdapters

`DataReaders`和`DataAdapter`是数据提供程序的核心对象。这些是 ADO.NET 提供的一些最重要的功能。让我们看看如何使用这些对象。

# DataReaders

每个提供程序都有数据读取器。在底层，所有类都执行相同的操作。`SqlDataReader`，`OdbcDataReader`和`OleDbDataReader`都实现了`IDataReader`接口。DataReader 的主要用途是在数据来自流时从数据源读取数据。让我们看看数据读取器具有的不同属性：

| **属性** | **描述** |
| --- | --- |
| `Depth` | 行的嵌套深度 |
| `FieldCount` | 返回行中的列数 |
| `IsClosed` | 如果`DataReader`已关闭，则返回`TRUE` |
| `Item` | 返回列的值 |
| `RecordsAffected` | 受影响的行数 |

DataReader 具有以下方法：

| **方法** | **描述** |
| --- | --- |
| `Close` | 此方法将关闭`DataReader`对象。 |
| `Read` | 此方法将读取`DataReader`中的下一个数据片段。 |
| `NextResult` | 此方法将将头移动到下一个结果。 |
| `GetString`，`GetChar`等 | `GetString`方法将以字符串格式返回值。`GetChar`将以`Char`格式返回值。还有其他方法将以特定类型返回值。 |

以下代码片段显示了`DataReader`的示例：

```cs
using System;
using System.Collections.Generic;
using System.Text;
using System.Data.SqlClient;
namespace CommandTypeEnumeration
{
    class Program
    {
        static void Main(string[] args)
        {
            // Create a connection string
            string ConnectionString = "Integrated Security = SSPI; " +
            "Initial Catalog= Northwind; " + " Data source = localhost; ";
            string SQL = "SELECT * FROM Customers";
            // create a connection object
            SqlConnection conn = new SqlConnection(ConnectionString);
            // Create a command object
            SqlCommand cmd = new SqlCommand(SQL, conn);
            conn.Open();
            // Call ExecuteReader to return a DataReader
            SqlDataReader reader = cmd.ExecuteReader();
            Console.WriteLine("customer ID, Contact Name, " + "Contact Title, Address ");
            Console.WriteLine("=============================");
            while (reader.Read())
            {
                Console.Write(reader["CustomerID"].ToString() + ", ");
                Console.Write(reader["ContactName"].ToString() + ", ");
                Console.Write(reader["ContactTitle"].ToString() + ", ");
                Console.WriteLine(reader["Address"].ToString() + ", ");
            }
            //Release resources
            reader.Close();
            conn.Close();
        }
    }
}

```

# DataAdapters

DataAdapters 的工作原理类似于断开连接的 ADO.NET 对象和数据源之间的桥梁。这意味着它们帮助建立连接并在数据库中执行命令。它们还将查询结果映射回断开连接的 ADO.NET 对象。Data Adapters 使用`DataSet`或`DataTable`在从数据源检索数据后存储数据。`DataAdapter`有一个名为`Fill()`的方法，它从数据源收集数据并填充`DataSet`或`DataTable`。如果要检索模式信息，可以使用另一个名为`FillSchema()`的方法。另一个名为`Update()`的方法将`DataSet`或`DataTable`中所做的所有更改传输到数据源。

使用数据适配器的好处之一是不会将有关连接、数据库、表、列或与数据源相关的任何其他信息传递给断开连接的对象。因此，在向外部源传递值时使用是安全的。

# 使用存储过程

**存储过程**是存储在数据库中以便重用的 SQL 语句批处理。ADO.NET 支持存储过程，这意味着我们可以使用 ADO.NET 调用数据库中的存储过程并从中获取结果。向存储过程传递参数（可以是输入或输出参数）是非常常见的做法。ADO.NET 命令对象具有参数，这些参数是参数类型的对象。根据提供程序的不同，参数对象会发生变化，但它们都遵循相同的基本原则。让我们看看如何在 ADO.NET 中使用存储过程而不是普通的 SQL 语句。

要使用存储过程，应在`SQLCommand`中传递的 SQL 字符串应为存储过程的名称：

```cs
string ConnectionString = "Integrated Security = SSPI;Initial Catalog=Northwind;Data source=localhost;";
SqlConnection conn = new SqlConnection(ConnectionString);
String sql = “InsertPerson”;
SqlCommand command = new SqlCommand(sql, conn);
```

我们通常按以下方式向存储过程传递参数：

```cs
using System.Data.SqlClient;
using System;
using System.Data;

public class Program
{
    public static void Main()
    {
        string ConnectionString = "Integrated Security = SSPI; Initial Catalog= Northwind; Data source = localhost; ";
        SqlConnection conn = new SqlConnection(ConnectionString);
 String sql = "InsertPerson";
 SqlCommand command = new SqlCommand(sql, conn);
 command.CommandType = CommandType.StoredProcedure;
 SqlParameter param = command.Parameters.Add("@FirstName", SqlDbType.NVarChar, 11);
 param.Value = "Raihan";
 param = command.Parameters.Add("@LastName", SqlDbType.NVarChar, 11);
 param.Value = "Taher";
 conn.Open();
 int rowsAffected = command.ExecuteNonQuery();
 conn.Close();
```

```cs

 Console.WriteLine(rowsAffected);
    }
}
```

现在让我们看一下存储过程，以了解参数的使用方式：

```cs
CREATE procedure InsertPerson (
@FirstName nvarchar (11),
@LastName nvarchar (11)
)
AS
INSERT INTO Person (FirstName, LastName) VALUES (@FirstName, @LastName);
GO
```

# 使用 Entity Framework

**Entity Framework**（**EF**）是由 Microsoft 开发的**对象关系映射器**（**ORM**）框架。它是为.NET 开发人员开发的，以便使用实体对象轻松地与数据库一起工作。它位于后端代码或业务逻辑与数据库之间。它允许开发人员使用应用程序语言 C#编写代码与数据库交互。这意味着不需要手动使用和编写 ADO.NET 代码，而我们在前面的部分中所做的。EF 具有不同类型的命令，用于普通 SQL 命令。EF 命令看起来非常类似于 C#代码，将使用后台的 SQL 与数据库通信。它可以与任何类型的数据源通信，因此您无需担心为每个 DBMS 设置或编写不同的代码。

# 在 Entity Framework 中，什么是实体？

实体是应用程序域中的一个类，也包括在派生的`DbContext`类中作为`DbSet`属性。实体在执行时被转换为表，实体的属性被转换为列：

```cs
public class Student{
}

public class StudentClass{
}

public class Teacher{
}

public class SchoolContext : DbContext {
    public SchoolContext(){}
    public DbSet<Student> Students { get; set; }
    public DbSet<StudentClass> StudentClasses { get; set; }
    public DbSet<Teacher> Teachers { get; set; }
}
```

# 不同类型的实体属性

让我们看看实体可以具有哪些不同类型的属性：

+   标量属性

+   导航属性。这些包括以下内容：

+   引用导航属性

+   集合导航属性

# 标量属性

这些属性直接在数据库中用作列。它们用于在数据库中保存和查询。让我们看一个这些属性的示例：

```cs
public class Student{
    public int StudentID { get; set; }
    public string StudentName { get; set; }
    public DateTime? DateOfBirth { get; set; }
    public byte[]  Photo { get; set; }
    public decimal Height { get; set; }
    public float Weight { get; set; }

    public StudentAddress StudentAddress { get; set; }
    public Grade Grade { get; set; }
}
```

以下属性是标量属性：

```cs
public int StudentID { get; set; }
public string StudentName { get; set; }
public DateTime? DateOfBirth { get; set; }
public byte[]  Photo { get; set; }
public decimal Height { get; set; }
public float Weight { get; set; }
```

# 导航属性

这种类型的属性表示实体之间的关系。它们与特定列没有直接关联。导航属性有两种类型：

+   **引用导航属性：**如果另一个实体类型用作属性，则称为引用导航属性

+   **集合导航属性：**如果实体被包括为集合类型，则称为集合导航属性

导航属性的一个示例如下：

```cs
public Student Student { get; set; }
public ICollection<Student> Students { get; set; }
```

在这里，`Student`是一个引用导航属性，`Students`是一个集合导航属性。

现在让我们看看使用 EF 的两种方法：**代码优先方法**和**数据库优先方法**。

# 代码优先方法

这可以被认为类似于领域驱动设计。在这种方法中，您编写实体对象和域，然后使用域使用 EF 生成数据库。使用实体对象中的不同属性，EF 可以理解要对数据库执行的操作以及如何执行。例如，如果您希望模型中的特定属性被视为主键，可以使用数据注释或流畅 API 指示 EF 在创建数据库中的表时将此列视为主键。

# 数据库优先方法

在这种方法中，您首先创建数据库，然后要求 EF 为您生成实体。您在数据库级别进行所有更改，而不是在后端应用程序中的实体中进行更改。在这里，EF 的工作方式与代码优先方法不同。在数据库优先方法中，EF 通过数据库表和列生成 C#类模型，其中每个列都被视为属性。EF 还负责不同数据库表之间的关系，并在生成的模型中创建相同类型的关系。

# 使用 Entity Framework

这两种方法都有其好处，但代码优先方法在开发人员中更受欢迎，因为您不必过多处理数据库，而是更多地在 C#中工作。

EF 不会默认随.NET 框架一起提供。您必须从 NuGet 软件包管理器下载库并将其安装在您正在使用的项目中。要下载和安装实体框架，您可以打开 Nuget 软件包管理器控制台并编写以下命令：

```cs
Install-Package EntityFramework
```

此命令将在您的项目中下载并安装 Entity Framework：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/b6bbdf13-aa11-4bf5-835c-2fd98bb06f76.png)

如果您不熟悉**包管理器控制台**，也可以使用 GUI 的**解决方案包管理器**窗口来安装实体框架。转到**浏览**选项卡，搜索**Entity Framework**。您将在搜索结果的顶部看到它。单击它并在您的项目中安装它。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/9f3940da-0cc2-4ff0-8fa3-76fa73a0036e.png)

使用 Nuget 包管理器安装 Entity Framework

在本书中，我们更专注于 C#，因此我们将更仔细地看一下代码优先方法，而不是数据库优先方法。在代码优先方法中，由于我们不会触及数据库代码，因此我们需要以一种可以在创建数据库时遵循的方式创建我们的实体对象。在创建了数据库表之后，如果我们想要更新表或更改表，我们需要使用迁移。数据库迁移会创建数据库的新实例，并在新实例中应用新的更改。通过使用迁移，更容易操作数据库。

现在让我们更多地了解一下 EF 的历史和流程。它首次发布于 2008 年，与.NET 3.5 一起。在撰写本书时，EF 的最新版本是版本 6。EF 还有一个称为**Entity Framework Core**的.NET Core 版本。这两个框架都是开源的。当您在项目中安装实体框架并编写**POCO**类（**Plain Old CLR Object**）时，该 POCO 类将被实体框架使用。首先，EF 从中创建**Entity Data Model**（**EDM**）。稍后将使用此 EDM 来保存和查询数据库。**语言集成查询**（**LINQs**）和 SQL 都可以用来向 EF 发出指令。当一个实体对象在 EDM 中使用时，它会被跟踪。当它被更新时，数据库也会被更新。

我们可以使用`SaveChanges()`方法来执行数据库中的插入、更新和删除操作。对于异步编程，使用`SaveChangesAsync()`方法。为了获得更好的查询体验，EF 具有一级缓存，因此当执行重复查询时，EF 会从缓存中返回结果，而不是去数据库中收集相同的结果。

EF API 主要做四件事：

+   将类映射到数据库模式

+   将 LINQ 转换为实体查询到 SQL 并执行它们

+   跟踪更改

+   在数据库中保存更改

EF 将实体对象和上下文类转换为 EDM，并且 EDM 在数据库中使用。例如，假设我们有以下类：

```cs
public class Person {
    public int PersonId { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
}
```

EF 将其转换为 EDM，如下所示：

```cs
Table Name: Person
PersonId(PK,int,not null)
FirstName (nvarchar(50),null)
LastName (nvarchar(50),null)
```

然后，这个 EDM 将用于创建或更新`Person`数据库表。

# SQL 中的交易

事务是一个单独的工作单元，要么完成整个工作，要么回滚到其先前的状态。事务不能在工作的中间停止。这是一个非常重要的特性，用于处理敏感数据。事务的最佳用途之一是处理转账过程。当一个人向另一个人的账户转账一些钱时，如果在过程中发生任何错误，整个过程应该被取消或回滚。

SQL 中交易的四个属性：**原子、一致、隔离和持久**（**ACID**）。

# 原子

原子意味着组中的所有语句必须被执行。如果组中的语句之一没有被执行，那么没有一个语句应该被执行。整个语句组应该作为一个单一单元工作。

# 一致

当执行事务时，数据库应该从一个状态达到另一个状态。我们称初始点为起点，执行后的点为终点。在事务中，起点和终点应该是清晰的。如果事务成功，数据库状态应该在终点，否则应该在起点。保持这种一致性就是这个属性的作用。

# 隔离

作为事务一部分的一组语句应该与另一个事务或手动语句中的其他语句隔离开来。当一个事务正在运行时，如果另一个语句改变了特定的数据，整个事务将产生错误的数据。当一个事务运行时，所有其他外部语句都不被允许在数据库中运行在特定的数据上。

# 持久

一组语句执行后，结果需要存储在一个永久的位置。如果在事务中间发生错误，这些语句可以被回滚，数据库回到之前的位置。

事务在 SQL 中扮演着非常重要的角色，因此 SQL 数据提供程序提供了`SQLTransaction`类，可以用于使用 ADO.NET 执行事务。

# 总结

数据是软件应用程序的一个非常重要的部分。为了维护数据，我们需要一种数据库来以结构化的方式存储数据，以便可以轻松地检索、保存、更新和删除数据。我们的软件能够与数据源通信以使用数据是至关重要的。ADO.NET 框架为.NET 开发人员提供了这种功能。学习和理解 ADO.NET 是任何.NET 开发人员的基本要求之一。在本章中，我们涵盖了 ADO.NET 元素的基础知识，如`DataProvider`、`Connection`、`Command`、`DataReader`和`DataAdapter`。我们还学习了如何使用 ADO.NET 连接到 SQL Server 数据库和 Oracle 数据库。我们讨论了存储过程，并解释了实体框架是什么以及如何使用它。

在下一章中，我们将讨论一个非常有趣的话题：反射。


# 第十一章：C# 8 的新功能

几十年来，我们见证了各种各样的编程语言的发展。有些现在几乎已经消亡，有些被少数公司使用，而其他一些在市场上占据主导地位多年。C#属于第三类。C#的第一个版本发布于 2000 年。当 C#发布时，许多人说它是 Java 的克隆。然而，随着时间的推移，C#变得更加成熟，并开始占据市场主导地位。这尤其适用于微软技术栈，C#无疑是第一编程语言。随着每一个新版本的发布，微软都引入了令人惊叹的功能，使语言变得非常强大。

在 2018 年底，微软宣布了一些令人兴奋的功能将在 C# 8 中可用。在我写作本书时，C# 8 仍未正式发布，因此我无法保证所有这些功能将在最终版本中可用。然而，这些功能很有可能在最终版本中可用。在本章中，我们将看看这些功能，并试图理解语言如何演变成一个非凡的编程语言。让我们来看看我们将要讨论的功能：

+   可空引用类型

+   异步流

+   范围和索引

+   接口成员的默认实现

+   Switch 表达式

+   目标类型的新表达式

# 环境设置

要执行本章的代码，你需要**Visual Studio 2019**。在我写作本书时，Visual Studio 2019 尚未正式发布。然而，预览版本已经可用，要执行本章的代码，你至少需要 Visual Studio 2019 预览版。另一件需要记住的事情是，在测试本章的代码时，要创建**.NET Core**控制台应用程序项目。

要下载 Visual Studio 2019 预览版，请访问此链接：[`visualstudio.microsoft.com/vs/preview/`](https://visualstudio.microsoft.com/vs/preview/)。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/ca22bf53-4019-4a40-82e3-002f198c086b.png)

Visual Studio 2019 预览下载页面

# 可空引用类型

如果你在编写 C#代码时曾遇到异常，很可能是空引用异常。空引用异常是程序员在开发应用程序时最常见的异常之一，因此 C#语言开发团队努力使其更易于理解。

在 C#中，有两种类型的数据：**值类型**和**引用类型**。当你创建值类型时，它们通常有默认值，而引用类型默认为 null。Null 意味着内存地址不指向任何其他内存地址。当程序试图查找引用但找不到时，会抛出异常。作为开发人员，我们希望发布无异常的软件，因此我们尽量在代码中处理所有异常；然而，有时在开发应用程序时很难找到空引用异常。

在 C# 8 中，语言开发团队提出了可空引用类型的概念，这意味着你可以使引用类型可空。如果这样做，编译器将不允许你将 null 赋给非可空引用变量。如果你使用 Visual Studio，当你尝试将 null 值赋给非可空引用变量时，你也会收到警告。

由于这是一个新功能，不在旧版本的 C#中可用。C#编程语言团队提出了通过编写一小段代码来启用该功能的想法，以便旧系统不会崩溃。你可以为整个项目或单个文件启用此功能。

要在代码文件中启用可空引用类型，你必须在源代码顶部放置以下代码：

```cs
#nullable enable

```

让我们看一个可空引用类型的例子：

```cs
class Hello {
    public string name;
    name = null;
    Console.WriteLine($"Hello {name}");
}
```

如果你运行上面的代码，当尝试打印该语句时会得到一个异常。尝试使用以下代码启用可空引用类型：

```cs
#nullable enable

class Hello {
    public string name;
    name = null;
    Console.WriteLine($"Hello {name}");
}
```

上面的代码会显示一个警告，指出名称不能为空。为了使其可行，你必须将代码更改如下：

```cs
#nullable enable

class Hello {
    public string? name;
    name = null;
    Console.WriteLine($"Hello {name}");
}
```

通过将字符串名称更改为`nullable`，你告诉编译器可以将该字段设置为可空。

# 异步流

如果你在 C#中使用异步方法，你可能会注意到返回流是不可能的，或者很难通过现有的特性实现。然而，这将是一个有用的特性，可以使开发任务变得更简单。这就是为什么 C# 8 引入了一个新的接口叫做`IAsyncEnumerable`。通过这个新的接口，可以返回异步数据流。让我再详细解释一下。

在异步流之前，在 C#编程语言中，异步方法不能返回数据流，它只能返回单个值。

让我们看一个不使用异步流的代码示例：

```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace ExploreVS
{
 class Program
 {
 public static void Main(string[] args)
 {
 var numbers = GetNumbersAsync();
 foreach(var n in GetSumOfNums(numbers))
 {
 Console.WriteLine(n);
 }
 Console.ReadKey();
 }
 public static IEnumerable<int> GetNumbersAsync()
 {
 List<int> a = new List<int>();
 a.Add(1);
 a.Add(2);
 a.Add(3);
 a.Add(4);
 return a;
 }
 public static IEnumerable<int> GetSumOfNums(IEnumerable<int> nums)
 {
 var sum = 0;
 foreach(var num in nums)
 {
 sum += num;
 yield return sum;
 }
 }

 }
}
```

通过异步流，现在可以使用`IAsyncEnumerable`返回数据流。让我们看一下下面的代码：

```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace ExploreVS
{
 class Program
 {
 public static async void Main(string[] args)
 {
 var numbers = GetNumbersAsync();
 await foreach(var n in GetSumOfNums(numbers))
 {
 Console.WriteLine(n);
 }
 Console.ReadKey();
 }
 public static IEnumerable<int> GetNumbersAsync()
 {
 List<int> a = new List<int>();
 a.Add(1);
 a.Add(2);
 a.Add(3);
 a.Add(4);
 return a;
 }
 public static async IAsyncEnumerable<int> GetSumOfNums(IAsyncEnumerable<int> nums)
 {
 var sum = 0;
 await foreach(var num in nums)
 {
 sum += num;
 yield return sum;
 }
 }

 }
}
```

从上面的例子中，我们可以看到如何使用 C#的这个新特性来返回异步流。

# 范围和索引

C# 8 带来了范围，它允许你获取数组或字符串的一部分。在此之前，如果你想要获取数组的前三个数字，你必须遍历数组并使用条件来找出你想要使用的值。让我们看一个例子：

```cs
using System;
namespace ConsoleApp6
{
    class Program
    {
        static void Main(string[] args)
        {
            var numbers = new int[] { 1, 2, 3, 4, 5 };
            foreach (var n in numbers)
            {
                if(numbers[3] == n) { break; } 
                Console.WriteLine(n);
            }
            Console.ReadKey();
        }
    }
}
```

通过范围，你可以轻松地切片数组并获取你想要的值，就像下面的代码所示：

```cs
using System;
namespace ConsoleApp6
{
 class Program
 {
 static void Main(string[] args)
 {
 var numbers = new int[] { 1, 2, 3, 4, 5 };
 foreach (var n in numbers[0..3])
 {
 Console.WriteLine(n);
 }
 Console.ReadKey();
 }
 }
}
```

在上面的例子中，我们可以看到在`foreach`循环中给出了一个范围(`[0..3]`)。这意味着我们应该只取数组中索引 0 到索引 3 的值。

还有其他切片数组的方法。你可以使用`^`来表示索引应该向后取值。例如，如果你想要获取从第二个元素到倒数第二个元素的值，你可以使用`[1..¹]`。如果你应用这个范围，你将得到`2, 3, 4`。

让我们看一下下面的代码中范围的使用：

```cs
using System;
namespace ConsoleApp6
{
 class Program
 {
 static void Main(string[] args)
 {
 var numbers = new int[] { 1, 2, 3, 4, 5 };
 foreach (var n in numbers[1..¹])
 {
 Console.WriteLine(n);
 }
 Console.ReadKey();
 }
 }
}
```

当运行上面的代码时，你需要在你的项目中使用一个特殊的 Nuget 包。这个包的名称是`Sdcb.System.Range`。要安装这个包，你可以在 Visual Studio 中的 Nuget 包管理器中安装它。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/370d0040-10f3-44d9-9554-5c12e0028656.png)

安装 Sdcb.System.Range Nuget 包

如果你仍然遇到构建错误，有可能是你的项目仍在使用 C# 7，要升级到 C# 8，你可以将鼠标悬停在被红色下划线标记的地方，然后点击弹出的灯泡。然后，Visual Studio 会询问你是否要在你的项目中使用 C# 8。你需要点击“将此项目升级到 C#语言版本'8.0 *beta*'”。这将把你的项目从 C# 7 升级到 C# 8，然后你就可以运行你的代码了。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/188d10ee-9070-4d8c-848e-9f1dff400cb2.png)

图：将项目升级到 C# 8

# 接口成员的默认实现

我们都知道，在 C#中，接口没有任何方法实现；它们只包含方法签名。然而，在 C# 8 中，接口允许有实现的方法。如果需要，这些方法可以被类重写。接口方法也可以访问修饰符，比如 public、virtual、protected 或 internal。默认情况下，访问级别被设置为 virtual，除非它被固定为 sealed 或 private。

还有一件重要的事情要注意。接口中还不允许使用属性或字段。这意味着接口方法不能在方法中使用任何实例字段。接口方法可以接受参数作为输入并使用它们，但不能使用实例变量。让我们看一个接口方法的例子：

```cs
using System;
namespace ConsoleApp7
{
 class Program
 {
 static void Main(string[] args)
 {
 IPerson person = new Person();
 person.PrintName("John", "Nash");
 Console.ReadKey();
 }
 }
 public class Person : IPerson
 {
 }
 public interface IPerson
 {
 public void PrintName(string FirstName, string LastName)
 {
 Console.WriteLine($"{FirstName} {LastName}");
 }
 }
}
```

在撰写本书时，这个功能在 C# 8 预览版本中还不可用。这仍然被标记为一个拟议的功能，但希望它会在最终发布中实现。因此，即使您使用 Visual Studio 2019 预览版本，上面给出的代码可能也无法工作。

# Switch 表达式

多年来，我们一直在使用 switch 语句。每当我们想到或听到 switch 时，我们会想到 case 和 break。然而，C# 8 将通过引入 switch 表达式来迫使我们改变这种思维方式。这意味着 switch 语句将不再与过去一样。

让我们看看我们以前的`switch`语句是什么样子的：

```cs
using System;
namespace ConsoleApp7
{
    class Program
    {
        static void Main(string[] args)
        {
            string person = "nash";
            switch (person)
            {
                case "john":
                    Console.WriteLine("Hi from john!");
                    break;
                case "smith":
                    Console.WriteLine("Hi from smith!");
                    break;
                case "nash":
                    Console.WriteLine("Hi from nash!");
                    break;
                case "harrold":
                    Console.WriteLine("Hi from harrold!");
                    break;
                default:
                    Console.WriteLine("Hi from None!");
                    break;
            }
            Console.ReadKey();
        }
    }
}
```

通过新的方法，我们不会在`switch`后面将`person`放在括号中，而是将`switch`放在`person`变量的右侧，不需要`case`关键字。让我们看看我们如何以新的方式使用`switch`表达式：

```cs
{
 "john" j => Console.WriteLine("Hi from john!"),
 "smith" s => Console.WriteLine("Hi from smith!"),
 "nash" n => Console.WriteLine("Hi from nash!"),
 "harrold" h => Console.WriteLine("Hi from harrold!"),
 _ => Console.WriteLine("Hi from None!")
};
```

在这里，我们还可以看到，对于默认情况，我们只使用下划线(`_`)。

# 目标类型的新表达式

在 C# 8 中，另一个新功能是目标类型的新表达式。这个功能将使代码赋值更加清晰。让我们从一个示例代码开始，我们在其中创建了一个带有值的字典：

```cs
person switch
Dictionary<string, List<int>> student = new Dictionary<string, List<int>> {
   { "john", new List<int>() { 98, 75 } }
};
```

有了目标类型的新表达式，前面的代码可以这样写：

```cs
Dictionary<string, List<int>> student = new() {
   { "john", new() { 98, 75 } }
};
```

当您放置`new()`时，变量将采用左侧的类型并创建一个新的实例。

# 总结

每当微软宣布推出新版本的 C#编程语言时，我都会对他们带来了什么感到兴奋，而每一次，我都对结果感到印象深刻。C# 8 也不例外。特别是可空引用类型是一个令人惊叹的功能，因为它可以防止一个非常常见的异常。异步流是另一个很棒的功能，特别适用于物联网的开发。范围、接口成员、switch 表达式以及其他所有的新增功能都是朝着重大进步迈出的小步。这些新功能使开发人员的生活变得更加轻松，并通过减少软件崩溃为企业带来了好处。在下一章中，我们将讨论设计原则和不同的设计模式。


# 第十二章：理解设计模式和原则

多年来，软件变得越来越复杂。现在，软件不仅用于数学计算或简单的**创建、读取、更新和删除**（CRUD）操作：我们正在使用它来执行复杂的任务，如控制火箭发动机或每天管理大量数据。来自各行各业的企业已经开始采用软件系统，包括银行、保险公司、研究机构、教育机构和政府机构。对软件的需求越高，越多的人开始在软件开发领域建立职业。从汇编语言编程开始，经过过程式编程，然后引入了面向对象编程（OOP）时代，尽管出现了其他类型的编程，如函数式编程，但 OOP 仍然是最受欢迎的模型。OOP 帮助开发人员编写良好的、模块化的软件，易于维护和扩展。在本章中，我们将讨论一些最重要的设计原则和模式，这些原则和模式被成千上万的开发人员遵循，我们将涵盖以下主题：

+   软件开发中的设计原则

+   软件开发中的不同设计模式

+   创建设计模式

+   行为设计模式

+   结构设计模式

+   **模型-视图-控制器**（MVC）模式

# 设计原则

在我们开始讨论设计原则之前，让我们思考一下在软件开发中我们所说的**设计原则**是什么意思。当我们开发软件时，我们首先设计其架构，然后开始编写其代码。我们希望以这样的方式编写我们的代码，使其不会产生错误，或者如果有错误，很容易找到。当我们阅读代码时，我们也希望代码易于理解，并且希望它的结构能够在以后需要时进行更改。虽然编写最佳代码是困难的，但有许多在软件开发中由经验丰富的计算机科学家制定的原则。使用这些原则，开发人员可以编写非常干净的代码。

软件开发人员罗伯特·C·马丁，也被称为 Uncle Bob，提出了五个软件设计原则。这些原则对开发人员非常有效和有帮助，以至于它们已经成为软件行业的一种规范。它们统称为 SOLID 原则，代表以下不同的定义：

+   **S **代表**单一职责原则**

+   **O **代表**开闭原则**

+   **L **代表**里氏替换原则**

+   **I **代表**接口隔离原则**

+   **D **代表**依赖反转原则**

让我们逐一讨论这些原则。

# 单一职责原则

"一个类应该只有一个改变的原因。"

– *罗伯特·C·马丁*

这意味着当我们编写一个类时，我们应该以只有一个职责的方式设计它。你应该只需要为一个原因更改类。如果你有多个原因更改类，那么它违反了单一职责原则。

如果一个类有多个职责，并且你对一段代码进行了更改，这可能会破坏另一段代码，因为它们在同一个类中并共享一些依赖关系。你的代码可能并不是非常解耦的。

# 开闭原则

代码需要以这样的方式编写，即在软件实体（如类、模块或函数）中添加新内容是好的，但不应允许修改实体本身。这减少了产生错误的可能性。

# 里氏替换原则

"派生类型必须完全可替代其基本类型。"

– *芭芭拉·里斯科夫*

这个原则规定，当你编写一个类时，如果它是从另一个类派生的，它应该可以被基类替换。否则，你的代码将非常脆弱和耦合。这个原则是由芭芭拉·利斯科夫首次发现的，因此以她的名字命名。

# 接口隔离原则

有时，开发人员会创建包含过多信息的大接口。许多类可能会使用这个接口，但它们可能并不需要其中的所有内容。这就是你应该避免的，以便遵循这个原则。这个原则支持小接口而不是大接口，如果必要，一个类可以继承多个适用于该类的小接口。

# 依赖反转原则

"高层模块不应该依赖于低层模块；两者都应该依赖于抽象。抽象不应该依赖于细节。细节应该依赖于抽象"

- *罗伯特·C·马丁*

我们知道，在软件开发中，我们使用层。为了使这些层解耦，我们必须以这样一种方式设计这些层的依赖关系，即这些层不应该相互依赖，而应该依赖于抽象。因此，如果你改变高层模块或低层模块中的某些东西，它不会伤害系统。当我们创建这些抽象时，我们必须以这样一种方式设计它们，即它们不依赖于实现细节。这些抽象应该是独立的，而实现这些接口或抽象类的类应该依赖于这些抽象。

# 创建型设计模式

在面向对象编程中，所有的东西都被视为对象，跟踪对象的创建和管理方式非常重要。如果开发人员不太关注这个话题，软件的对象可能会使软件变得脆弱和耦合。保持对象适当地以保持应用程序易于扩展非常重要。创建型设计模式是帮助以避免对象创建方面的最常见问题的模式。

在创建型设计模式中存在两个主要概念：

+   封装关于系统使用的具体类的知识

+   隐藏创建和组合具体类的实例

创建型设计模式分为对象创建模式和类创建模式，其中**对象创建模式**处理对象的创建，**类创建模式**处理类的发现。

行业中有五种主要的创建型设计模式：

+   抽象工厂模式

+   建造者模式

+   工厂方法模式

+   原型模式

+   单例模式

# 抽象工厂模式

《设计模式：可复用面向对象软件的元素》一书中对这个模式的定义是提供一种组合来构建类似或相关对象族，而不指定它们的具体类。

这个模式提供的最重要的东西是对象创建的分离或抽象。如果你不遵循任何模式，当你创建一个对象时，最简单的方法就是在需要的地方使用`new`关键字创建一个对象。例如，如果我在我的`Bank`类中需要一个`Person`对象，最简单的方法就是在`Bank`类中使用`new`关键字实例化一个`Person`对象。然而，使用这种方法有时会使软件变得复杂。为了避免这种情况，我们可以使用抽象工厂模式。

抽象工厂模式主要用于具有相同家族的对象，或者以某种方式相关或依赖的情况。其思想是创建工厂类来执行对象的创建工作。如果一个对象 A 需要另一个对象 B 的实例，对象 A 应该要求对象 B 的工厂创建一个 B 对象并将其传递给对象 A。这样，对象 A 独立于对象 B 的创建。在抽象工厂模式中，还有另一层抽象。工厂类也被抽象化了。这意味着对象 A 不会直接调用对象 B 的工厂，而是使用一个抽象。应该有一个机制来确定需要调用哪个工厂类。这意味着对象 A 不依赖于另一个对象的任何特定工厂。

# 建造者模式

将复杂对象的计划与其实现分离是建造者模式的主要思想。在面向对象的软件开发中，我们有时需要创建相当复杂的对象。例如，我们可能创建一个使用其他对象的对象，而这些对象又使用其他对象。当你只需要该对象执行另一种工作时，创建或实例化这种对象可能会很困难。这也可能使代码更复杂，降低其可读性。

让我们想想一个例子。想象一下，你正在制作一些汉堡包，其中一些是鸡肉汉堡，另一些是牛肉汉堡。在创建鸡肉汉堡对象时，每次都必须创建鸡肉汉堡肉饼对象、番茄酱对象、奶酪对象和面包对象，这导致代码混乱。创建牛肉汉堡对象时也必须遵循相同的过程。这是一种处理和创建这些对象的非常复杂的方式。

建造者模式提供了一种解决这种复杂性的好方法。使用这种模式，我们创建一个称为 Builder 的类，其主要任务是创建复杂对象并返回新创建的对象。使用建造者模式，我们使用另一种类型的类，通常称为 director 类。这个类的任务是调用 Builder 类并从中获取对象。

让我们回到我们的汉堡例子。我们可以有一个 ChickenBurgerBuilder 类和一个 BeefBurgerBuilder 类。它们将在类中设置汉堡肉饼、面包、番茄酱和奶酪。当 BurgerDirector 类想要创建一个鸡肉汉堡时，它将调用 ChickenBurgerBuilder。要创建一个牛肉汉堡，它将调用 BeefBurgerBuilder。创建汉堡肉饼和其他配料的复杂性将由 Builder 类处理。

# 工厂方法模式

工厂方法模式与抽象工厂模式非常相似。不同之处在于，在工厂方法模式中，工厂层不是抽象的。使用这种模式意味着你将创建一个处理实现相同抽象的类的创建的工厂类。这意味着，如果有一个由许多子类定义的接口，Factory 类可以根据传递给 Factory 的逻辑创建任何这些子类中的任何一个。

让我们想一个例子。我们将使用工厂方法模式来解决我们在“生成器模式”示例中提到的制作汉堡的问题。我们将创建一个名为`BurgerFactory`的`Factory`，它将接受一个输入，比如`typeOfBurger`（鸡肉或牛肉）。然后，`BurgerFactory`将决定应该创建哪种`Burger`类型的对象。假设我们有一个名为`Burger`的接口，`ChickenBurger`和`BeefBurger`都实现了这个接口。这意味着`BurgerFactory`将返回一个`Burger`类型的对象。客户端将不知道将创建和返回哪个`Burger`对象。通过使用这种模式，我们将客户端与特定对象隔离开来，从而增加了代码的灵活性。

# 原型模式

当您想要避免使用传统的对象创建机制（如 new 关键字）创建相同类型或子类型的新类时，可以使用这种设计模式。简而言之，这种模式规定我们应该克隆一个对象，然后使用克隆的对象作为另一个新创建的对象。这样就避免了传统的对象创建方法。

# 单例模式

单例模式是一种非常简单的设计模式。它涉及在整个应用程序中只创建一个类的对象。**单例对象**是一个不能有多个实例的对象。每当一段代码需要使用这个单例对象时，它不会创建一个新对象；相反，它将使用已经存在的旧对象。

这种设计模式适用于当您只想处理来自一个来源的一些信息时。使用单例模式的最佳示例是在数据库连接字符串中。在应用程序中，如果使用多个数据库连接，数据库可能会损坏并导致应用程序异常。在这种情况下，最好将连接字符串设置为单例对象，这意味着所有通信都只使用一个实例。这减少了出现差异的机会。

# 结构设计模式

在软件开发中可用的一些设计模式与代码结构有关。这些模式可以帮助您以一种避免常见结构问题的方式设计代码。在《设计模式：可复用面向对象软件的元素》一书中，Gang of Four 提出了七种结构设计模式。在本节中，我们将讨论其中的四种，分别是：

+   适配器模式

+   装饰器模式

+   外观模式

+   代理模式

如果您想了解其他三种模式的更多信息，请参阅 Gang of Four 的《设计模式：可复用面向对象软件的元素》一书。起初，开始使用这些模式可能会有点困惑，但随着经验的增加，识别哪种模式适合哪种情况将变得更容易。

# 适配器模式

通常，当我们想到适配器这个词时，我们会想到一个小设备，它可以帮助我们将电子设备插入具有不同接口的电源插座。适配器设计模式实际上在软件代码中也是这样的。这种设计模式规定，如果软件的两个模块想要相互通信，但一个模块期望的接口与另一个模块具有的接口不同，那么应该使用适配器，而不是改变一个接口以匹配另一个接口。这样做的好处是，将来如果您希望您的代码与另一个接口进行通信，您不必更改您的代码，只需使用另一个适配器。

例如，想象一下你有一个接口`A`，但你想要与之交流的代码需要另一个接口`B`。你可以使用一个适配器将接口`A`转换为接口`B`，而不是将接口`A`更改为接口`B`。这样，使用接口`A`的代码不会出错，你将能够与要求接口`B`的代码进行通信。

# 装饰者模式

装饰者模式允许我们动态地向对象添加新的行为。当这种新行为被添加到一个对象时，它不应该影响该对象上已经存在的任何其他行为。当你需要在运行时向对象添加新的行为时，这种模式提供了一个解决方案。它还消除了创建子类只是为了向任务添加行为的需要。

# 外观模式

有时，如果你有复杂的对象关系，很难将它们全部映射并在代码中使用。外观模式表明，你应该使用一个中间对象来处理对象关系问题，并给客户端一个简单的接触点。让我们想想一个例子：当你去餐厅点餐时，你实际上不会去找厨师或厨房里的人收集食物，然后自己做饭；你告诉服务员你想要什么食物。你不知道食物将如何准备或谁会准备它。你无法控制食物的制作，你只知道你会得到你要的东西。在这里，接受订单的人就是一个外观。他们接受你的订单，并要求不同的人准备你要的东西。

假设你点了一份牛肉汉堡。你调用一个`GetBeefBurger()`方法，外观实际上会调用以下内容：

```cs
Bread.GetBread()
Sauce.PutSauceOnBread(Bread)
SliceTomato()
PutTomatoOnBread()
Beef.FryBeefPatty()
PutBeefPattyOnBread()
WrapTheBurger()
ServeTheBurger()
```

上述方法并不是真正的方法。我只是想给你一个概念，即外观的工作实际上是为了隐藏客户端的复杂性。

# 代理模式

这种模式与我们讨论过的其他结构设计模式非常相似。如果有一种情况，代码不应该直接调用另一段代码，无论出于什么原因，都可以使用代理模式。代理模式在代码没有权限调用另一段代码或直接调用一段代码在资源方面昂贵时特别有用。我们可能想使用代理模式的一个例子是，如果我们想在应用程序中使用第三方库，但出于安全原因，我们不希望我们的代码直接调用该库。在这种情况下，我们可以创建一个代理，让它与第三方代码进行通信。

# 行为设计模式

行为设计模式是处理对象之间通信的设计模式。这些设计模式允许你的对象以一种避免开发人员面临的与对象行为相关的常见问题的方式进行通信。在这个类别中有许多模式：

+   责任链模式

+   命令模式

+   解释器模式

+   迭代器模式

+   中介者模式

+   备忘录模式

+   观察者模式

+   状态模式

+   策略模式

+   模板方法模式

+   访问者模式

然而，在这本书中，我们只会讨论以下行为设计模式：

+   命令模式

+   观察者模式

+   策略模式

如果你想了解更多，请参考我们之前提到的《设计模式：可复用面向对象软件的元素》一书，作者是四人组。

# 命令模式

这种模式规定，当一个对象想要通知另一个对象或调用另一个对象的方法时，应该使用另一个对象而不是直接这样做。建立通信的对象被称为命令对象。命令将封装持有要调用的方法、要调用的方法名以及要传递的参数（如果有的话）的对象。命令模式有助于解耦调用者和接收者之间的关系。

# 观察者模式

**观察者模式**是解决一个问题的解决方案，即许多对象需要知道特定对象何时发生变化，因为它们可能需要更新其端上的数据。一种方法是，所有对象或观察者都应该询问对象或可观察对象数据是否发生了变化。如果可观察对象中的数据发生了变化，观察者将执行其工作。然而，如果这样做，观察者必须经常询问可观察对象关于数据变化，以避免减慢应用程序的速度。这需要大量的资源。

观察者模式表示可观察对象应该知道想要了解主题中数据变化的观察者列表，并在主题中的数据发生变化时通知每个观察者。这可以通过调用观察者的方法来实现。这种模式的一个很好的应用是 C#中的事件和委托。

# 策略模式

让我们来看一下《设计模式：可复用面向对象软件的元素》一书中四人帮对策略模式的定义：

例如，一个方法可以根据使用它的类的不同类型有不同的实现。因此，这个定义意味着我们需要使这些不同的算法实现一个基类或接口，以便它们属于同一个家族，并可以被客户端互换使用。定义的最后一部分意味着这种模式将允许客户端使用不同的算法而不影响其他客户端。

假设我们有一个名为`Animal`的类，它具有一些常见属性，如`eat`、`walk`和`noise`。现在，假设你想添加另一个属性，比如`fly`。你的类中的大多数动物都会飞，但有一些不会。你可以将`Animal`类分成两个不同的类，比如`AnimalWhichCanFly`和`AnimalWhichCantFly`。然而，将`Animal`类分成两个可能会使事情变得过于复杂，因为这些动物可能还有其他不同的属性。因此，你可以使用组合而不是继承，在`Animal`类中添加一个名为`fly`的属性，并用它来指示这种行为。

策略模式规定，我们应该使用接口（如`IFly`）而不是固定类型`fly`作为属性类型，然后创建实现`IFly`并具有不同算法的`子类`。然后，我们可以利用多态性，在创建`Animal`类的子类时在运行时分配特定的子类。

让我们尝试在前面的例子中应用这一点。在`Animal`类中，我们将使用`IFly`而不是`Fly`属性，然后实现实现`IFly`的不同类。例如，我们创建`CanFly：IFly`和`CannotFly：IFly`类。`CanFly`和`CannotFly`将有不同的`Fly`方法实现。如果我们创建一个实现`Animal`类的`Dog`类，我们将把`Fly`属性设置为`CannotFly`类。如果我们创建一个`Bird`类，我们将创建`CanFly`的实例并将其分配给`Fly`属性。通过应用这种模式，我们实现了一个不那么复杂的对象结构和易于更改的算法。

# MVC 模式

MVC 模式是行业中最流行的设计模式之一。即使你是行业的新手，你可能已经听说过它。这种模式在 web 开发中被广泛使用。许多流行的 web 开发框架都使用这种设计模式。一些使用 MVC 模式的流行框架如下：

+   C#: ASP.NET MVC Web Framework

+   **Java:** Spring 框架

+   **PHP:** Laravel 框架，Codeigniter 框架

+   **Ruby:** Rails 框架

MVC 设计模式规定我们应该将 web 应用程序分为三个部分：

+   模型

+   视图

+   控制器

**模型** 是将保存数据模型或对象并用于数据库事务的部分。**视图** 指的是应用程序的前端，用户或客户所看到的部分。最后，**控制器** 是处理应用程序所有业务逻辑的部分。所有逻辑和决策部分都将在控制器中。

MVC 模式的好处是你的应用程序是解耦的。你的视图独立于你的业务逻辑，你的业务逻辑独立于你的数据源。这样，你可以轻松地更改应用程序的一部分而不影响应用程序的其他部分。

# 总结

软件开发很有趣，因为它一直在变化。你可以用许多方式来开发、设计或编写某些东西。这些方式都不能被归类为最好的方式，因为你的代码可能需要根据情况进行更改。然而，因为软件开发是一种工程类型，有各种规则可以使你的软件更加强大和可靠。软件设计原则和设计模式就是这些规则的例子。了解这些概念并将它们应用到你自己的情况中将会让你作为开发者的生活变得更加容易。

本章节希望给你一个设计模式基础的概念，并告诉你在哪里可以寻找更多信息。在下一章中，我们将了解一个非常强大和有趣的软件，叫做 Git。Git 是一个版本控制系统，可以帮助跟踪软件代码的变化。


# 第十三章：Git - 版本控制系统

如今，软件开发已经达到了一个新的水平。它不再仅仅涉及编写代码——软件开发人员现在还必须熟悉一系列重要的工具。没有这些工具，要在团队中工作或高效工作就变得非常困难。版本控制就是其中之一。在众多可用的版本控制系统中，Git 是最流行和强大的。Git 版本控制已经在行业中存在了相当长的时间，但最近已经成为几乎所有软件公司的一部分。了解 Git 现在对开发人员来说是必不可少的。在本章中，我们将学习关于 Git 版本控制系统的知识。让我们来看看我们将要涵盖的主题：

+   什么是版本控制系统？

+   Git 的工作原理

+   在 Windows 中安装 Git

+   Git 的基础知识

+   Git 中的分支

# 什么是版本控制？

版本控制系统是一种在开发过程中跟踪软件代码变化的系统或应用程序。软件开发人员过去通过将代码复制到另一个文件夹或机器中来备份他们的代码。如果开发人员或生产机器崩溃，他们可以从备份中取出代码并运行。然而，手动保留和维护备份是麻烦的，容易出错，备份系统容易受损。因此，开发人员开始寻找一个能够保护他们代码的系统或应用程序。

版本控制在多个程序员共同开发项目的情况下也很有用。过去，程序员不得不要么在不同的文件上工作以避免冲突，要么在一段时间后仔细地合并代码。手动合并代码是非常危险和耗时的。

在版本控制系统中，代码文件的每一次更改实际上都是代码的一个新版本。在软件行业中，有许多版本控制系统可用，包括 Git、Subversion、Mercurial 和 Perforce。Git 是最流行和强大的版本控制系统，由软件开发人员 Linus Torvalds 开发。它是一个非常出色的应用程序，现在几乎在世界上每家软件公司中都在使用。

# Git 是如何工作的

Git 的主要任务是跟踪代码版本并允许开发人员在必要时返回到任何先前的状态。这是通过对每个版本进行快照并将其保存在本地文件存储系统中来实现的。与其他系统不同，Git 使用本地文件存储来存储快照，这意味着即使没有互联网连接，也可以在本地使用 Git。有了 Git 的本地版本，你几乎可以做任何你可以用互联网连接版本的 Git 做的事情。

安装 Git 后，你可以选择将文件系统中的哪个目录纳入 Git 版本控制。通常，Git 中的一个实体——项目或目录——被称为**存储库**。存储库可能包含不同的项目、一个项目或只是一些项目文件，具体取决于你想在 Git 版本控制中保留什么。你可以有两种方式在本地机器上拥有一个 Git 存储库。你可以自己初始化一个 Git 存储库，或者你可以从远程服务器克隆一个存储库。无论哪种方式，你都会在创建或克隆存储库的同一个文件夹中创建一个名为`.git`的文件夹。这个`.git`文件是本地存储文件，所有与该存储库相关的信息都将存储在那里。Git 以非常高效的方式存储数据，所以即使有大量的快照，文件也不会变得很大。

Git 有三种主要状态，我们将在接下来的部分中探讨：

+   修改

+   暂存

+   提交

# 修改

当您初始化了一个 Git 仓库，然后添加一个新文件或编辑一个现有文件时，该文件将在 Git 中标记为 Modified。这意味着该文件包含了与 Git 在其本地存储/数据库中已存储的快照的一些更改。例如，如果您在 Git 仓库中创建一个 C#控制台应用程序项目，那么该解决方案的所有文件都将被标记为 Modified，因为它们都不在 Git 仓库历史记录中。

# Staged

在 Git 中，Staged 指的是准备提交的文件。为了防止意外提交不需要的文件到 Git 仓库，Git 在 Modified 和 Committed 之间引入了这一步骤。当您将文件标记为 Staged 时，这意味着您希望这些文件在下一次提交中被提交。这也给了您编辑文件并不使它们成为 Staged 的选项，这样更改就不会保存在仓库中。如果您想在本地机器上应用一些配置，但不希望这些更改出现在仓库中，这个功能非常方便。

# 已提交

Committed 状态是指文件的一个版本已保存在本地数据库中。这意味着已经拍摄了一个快照，并将其存储在 Git 历史记录中以供将来参考。在远程使用仓库时，您将推送的代码实际上只是已提交的代码。

让我们看一下以下图表，以了解这些状态之间的流程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/b1dcec2a-3c29-49cb-a6ba-66f479de78ce.png)

# 在 Windows 上安装 Git

Git 最初是为基于 Linux 或 Unix 的操作系统开发的。当它在 Windows 用户中变得流行并开始要求 Git 时，Git for Windows 应运而生。在 Windows 上安装 Git 现在是一个非常简单的过程。要安装 Git，请转到[`git-scm.com/download/win`](https://git-scm.com/download/win)。

您将被带到以下截图所示的页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/e9c46f12-f598-401c-b98f-be26af4608c6.png)

Git for Windows 应该会自动开始下载。如果没有开始，您可以点击网站上提供的链接。下载文件将是一个可执行文件，所以要开始安装，执行可执行文件。在安装过程中，如果不确定要选择什么，最好的选择是保持一切默认。

以下截图显示了您可以安装哪些组件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/ad9369d6-e2e5-4c3a-9228-8f271256a146.png)

有一个部分可以选择用于 Git 的默认编辑器。选择的默认编辑器是 Vim，如下面的截图所示。如果您不习惯使用 Vim，可以将其更改为您喜欢的编辑器：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/414ae3e5-f6db-4317-88ed-8c6832b39bfb.png)

按照步骤。安装 Git 后，要测试安装是否成功，请转到命令行或 PowerShell，然后输入以下内容：

```cs
git --version
```

您应该会看到类似以下内容的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/bcab6f8b-19bd-42a5-8411-ff126aa10c0c.png)

如果您能看到版本号，这意味着安装成功了。

# Git 的基础知识

如前所述，Git 最初是为 Linux 系统开发的，这就是为什么使用这个工具的主要方式是通过命令行。在 Windows 上，我们不像 Linux 或 Unix 用户那样经常使用命令行，但使用它可以让您访问 Git 的所有功能。对于 Windows，有一些 GUI 工具可以用于 Git 操作，但它们通常有一些限制。由于命令行是 Git 的首选方法，因此我们将在本书中只涵盖命令行命令。 

# Git config

`git config`命令是用来配置 Git 设置的命令。Git 的最小设置是设置用户名和电子邮件地址。您可以为每个 Git 仓库单独配置，也可以全局配置设置。如果您全局设置配置，您就不必每次初始化 Git 仓库时都配置电子邮件地址和用户名。如果有必要，您可以在每个仓库中覆盖这些设置。

要配置您的电子邮件地址和用户名，请运行以下命令：

```cs
git config user.name = "john"
git config user.email = "john@example.com"
```

如果要全局设置配置，需要添加`--global`关键字，如下所示：

```cs
git config --global user.name = "john"
git config --global user.email = "john@example.com"
```

如果要查看其他全局配置设置可用的内容，可以使用以下命令：

```cs
git config --list
```

然后，您可以更改您想要更改的设置。

# Git init

如果您有一个当前未使用 Git 版本控制的项目，可以使用以下命令初始化项目：

```cs
git init
```

当您运行上述命令时，您在计算机上安装的 Git 程序将在项目目录中创建一个`.git`目录，并开始跟踪该项目的源代码。在新项目中初始化 Git 后，所有文件都显示为已修改，您必须将这些文件暂存以提交这些更改。

# Git clone

如果要使用位于远程服务器上的项目，必须克隆该项目。要克隆项目，必须使用以下命令：

```cs
git clone [repo-url]
```

例如，如果要克隆 Angular 项目，必须键入以下内容：

```cs
git clone https://github.com/angular/angular.git
```

当您将存储库克隆到本地环境时，将下载`.git`文件夹。这包括提交历史记录，分支，标签和远程服务器中包含的所有其他信息。基本上是远程服务器版本的副本。如果您在本地副本中提交更改，然后将其推送到远程存储库，则本地副本将与远程副本同步。

# Git status

在工作时，您会想要检查当前代码的状态。这意味着找出哪些文件已修改，哪些文件已暂存。您可以使用以下命令获取所有这些信息：

```cs
git status
```

让我们看一个例子。如果我们向我们的项目中添加一个名为`hello.txt`的新文件，并且该文件已被 Git 跟踪，并检查其状态，我们将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/f99a31f5-fdff-4be7-98c6-d58b8ab02b59.png)

在这里，我们可以看到一个名为`hello.txt`的文件位于`Untracked`文件下，这意味着此文件尚未被 Git 跟踪。`git status`命令还会告诉您当前所在的分支。在这种情况下，我们在`master`分支中。

# Git add

`git add`命令是一个将已修改的文件/文件夹添加到 Git 跟踪系统的命令。这意味着文件和文件夹将被暂存。命令如下所示：

```cs
git add <file-name/folder-name>
```

让我们继续我们的示例，看看当我们在 Git 中添加`hello.txt`文件时会发生什么。为此，我们将执行以下命令：

```cs
git add hello.txt
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/8032b4ee-0843-4aeb-b19b-a149a140fa86.png)

在这里，我们看到了关于**换行符**（**LF**）和**回车**，换行符**（**CR+LF**）的警告，这些都是某种格式。替换的原因是我们在这里使用的是 Windows 操作系统，但目前我们不需要担心这个问题。这里的主要问题是文件已经被正确暂存。现在，如果我们检查状态，我们将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/1a59cee9-dde1-42e9-a8ce-930e2605be3f.png)

在这里，我们可以看到`hello.txt`文件被放置在`Changes to be committed`部分。这意味着该文件已被暂存。

在真实项目中，您可能会在暂存文件之前同时处理多个不同的文件。逐个添加文件或甚至用逗号分隔文件名可能非常繁琐。如果要将所有修改的文件暂存，可以使用以下命令将所有文件添加到暂存区域中：

```cs
git add *
```

# Git commit

当您想要将代码提交到 Git 历史记录时，使用`git commit`命令。这意味着对代码库进行快照，并将其存储在 Git 数据库中以供将来参考。要提交文件/文件夹，您必须使用以下命令：

```cs
git commit
```

如果执行上述代码，Git 设置的默认编辑器将打开并要求您输入提交的消息。还有一种更简洁的方法。如果要直接输入提交的消息，可以运行以下命令：

```cs
git commit -m "your message"
```

现在让我们提交我们的`hello.txt`文件到 Git 存储库。为此，我们将运行以下命令：

```cs
git commit -m "committing the hello.txt file with hello message" 
```

输出应该如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/d6f675f4-c355-4775-9caf-5b231eb7ebee.png)

成功提交后，我们将看到`1 file changed, 1 insertion(+)`。如果再次检查状态，将看到没有要提交的内容，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/06f99414-18c3-4c4d-9563-e8e392f14451.png)

# Git log

要检查在存储库中进行了哪些提交，可以使用以下命令：

```cs
git log
```

输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/91189c17-7afe-4f05-8189-a4e5fc5facaa.png)

从日志中，我们可以看到到目前为止只进行了一次提交。我们可以看到提交的哈希值，即紧跟在`commit`单词旁边的数字。我们可以看到`commit`是由`Raihan Taher`在`master`分支上进行的。我们还可以在日志中看到`commit`消息。这是一个非常有用的命令，可以检查已提交了什么。

# Git remote

`git remote`命令用于查看是否与远程存储库建立了连接。如果运行以下命令，它将显示远程存储库的名称。通常，远程名称设置为`Origin`。您可以有多个远程存储库。让我们看一下这个命令：

```cs
git remote
```

如果执行此命令，我们将看不到任何内容，因为还没有远程存储库，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/af4087a5-badb-455e-9239-cc7b52d4179d.png)

让我们添加一个远程存储库。我们将使用 GitHub 作为我们的远程服务器。在 GitHub 上创建存储库后，我复制了该存储库的 URL。我们将把它添加到我们的本地存储库。为此，我们使用以下命令：

```cs
git remote add <remote-name> <repository-link-remote>
```

在我们的示例中，命令如下：

```cs
git remote add origin https://github.com/raihantaher/bookgitexample.git
```

在添加了远程存储库后，如果执行`git remote`，我们将看到`origin`被列为远程存储库，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/75dade12-09c0-4fab-9c49-18cc47759a1b.png)

如果要查看有关远程存储库的更多详细信息，可以执行以下命令：

```cs
git remote -v
```

这将显示您添加的远程存储库的 URL，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/b198c049-5136-47e6-bb2c-2365a95d3337.png)

# Git push

当您想要将本地提交上传或推送到远程服务器时，可以使用以下命令：

```cs
git push <remote-repo-name> <local-branch-name>
```

以下是如何使用此命令的示例：

```cs
git push origin master
```

执行此命令后，如果推送成功，将看到以下消息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/ed93b671-65e1-4fe7-bc73-be880541f6d1.png)

# Git pull

`git pull`命令用于从远程存储库获取最新代码。由于 Git 是一个分布式版本控制系统，多人可以在一个项目上工作，有可能其他人已经使用最新代码更新了远程服务器。要访问最新代码，请运行以下命令：

```cs
git pull <remote-repo-name> <local-branch-name>
```

以下是如何使用此代码的示例：

```cs
git pull origin master
```

如果运行此代码，弹出的消息如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/e561a54b-2ebf-496b-a114-8ebf58e41f9f.png)

这意味着我们的本地存储库已经与远程存储库同步。如果远程存储库中有新的提交，`git pull`命令将把这些更改拉到我们的本地存储库，并指示已拉取更改。

# Git fetch

`git fetch`命令是一个与`git pull`非常相似的命令，但是当你使用`git fetch`时，代码将从远程仓库获取到本地仓库，但不会与你的代码合并。在检查了远程代码后，如果你觉得想要将其与本地代码合并，你必须显式运行`git merge`命令。执行此命令如下：

```cs
git fetch <remote-repo>
```

如果运行上述命令，将更新来自远程仓库的所有分支。如果指定一个本地分支，只会更新该分支：

```cs
git fetch <remote-repo> <local-branch>
```

让我们尝试在我们的示例代码中执行`git fetch`命令：

```cs
git fetch origin master
```

你会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/032f5867-815b-48f5-be9d-d4d7a5048c59.png)

# Git 中的分支

分支经常被认为是 Git 最好的特性之一。分支使 Git 与所有其他版本控制系统不同。它非常强大且易于使用。在我们学习不同的分支命令之前，让我简要解释一下 Git 如何处理提交，因为这将帮助你理解 Git 分支。在 Git 中，我们已经知道每个提交都有一个唯一的哈希值，并且该哈希值存储在 Git 数据库中。使用哈希值，每个提交都存储了先前提交的哈希值，这被称为该提交的父提交。除此之外，还存储了另一个哈希值，该哈希值存储了在该提交上暂存的文件，以及提交消息和有关提交者和作者的信息。对于存储库的第一个提交，父提交为空。

以下图表显示了 Git 中哈希的示例：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/3dcb22af-ba87-4a31-a293-9ac6079c582c.png)

我们称提交中的所有信息为快照。如果我们做了三次提交，我们可以说我们有**快照 A**，**快照 B**和**快照 C**，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/3df485a8-2ee2-4921-8b23-a4fde0b38713.png)

默认情况下，当你初始化一个本地 Git 仓库时，会创建一个名为`master`的分支。这是大多数开发人员将其视为 Git 树中的主分支的分支。这是可选的；你可以将任何分支视为你的主分支或生产分支，因为所有分支具有相同的能力和权限。如果你从**快照 C**（**提交 3**或**C3**简称）创建一个名为`feature`的分支，一个分支将从**C3**（**提交 3**）开始，测试分支上的下一个提交将把 C3 视为父提交。

以下图表显示了分支情况：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/ce4743a5-97e8-4c76-aa3f-7a4ec0caaf3e.png)

**HEAD**是一个指针，指向活动的提交或分支。这是开发人员和 Git 版本控制的指示器。当你做一个新的提交时，HEAD 会移动到最新的提交，因为这是将作为下一个提交的父提交的快照。

# 创建分支

让我们现在来看一下在 Git 中创建分支的命令。创建分支非常容易，因为它不会将整个代码库复制到一个新的位置，而是只保持与 Git 树的关系。有几种创建分支的方法，但最常见的方法如下：

```cs
git branch feature
```

在命令行上应该如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/b2404d53-01bc-4c4d-9803-5381da16d2b9.png)

# 查看可用的分支

要查看本地 Git 仓库中有哪些分支可用，可以输入以下命令：

```cs
git branch
```

执行上述代码后，你应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/fcca175f-04b5-490c-b504-b81c3b9a8ecc.png)

我们可以看到我们的本地仓库中有两个分支。一个是`master`分支，另一个是`feature`分支。`*`字符表示 HEAD 指向的位置。

# 切换分支

在前面的例子中，我们看到，即使创建了 feature 分支，HEAD 仍然指向 master。切换到另一个分支的命令如下：

```cs
git checkout <branch-name>
```

在我们的例子中，如果我们想从`master`切换到`feature`分支，我们必须输入以下命令：

```cs
git checkout feature
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/a5034adf-dd2e-4103-afde-9d72df501e53.png)

运行命令后，我们可以看到 Git 已经切换到了`feature`分支。现在我们可以再次运行`git` `branch`命令来查看 HEAD 指向的位置，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/a7e605d1-aa7c-48ae-a8a9-4296f745c73f.png)

很可能的情况是，当您创建一个分支时，您会希望立即在该分支上工作，因此有一个快捷方式可以创建一个分支，然后切换到它，如下面的代码所示：

```cs
git checkout -b newFeature
```

# 删除分支

要删除一个分支，您必须执行以下命令：

```cs
git branch -d feature
```

如果分支成功删除，您应该会看到类似于以下截图中显示的消息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/575435ef-b9ac-40f5-b244-bf367d2abe0c.png)

# 在 Git 中合并

要将一个分支与另一个分支合并，您必须使用`merge`命令。请记住，您需要在要将代码合并的分支上，而不是将要合并的分支或任何其他分支上。命令如下：

```cs
git merge newFeature
```

输出应该如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/34f6e505-44e1-4d6d-b5f0-18bf24f25099.png)

# 总结

在本章中，我们学习了一个与 C#编程语言不直接相关，但对于 C#开发人员来说仍然是一个必不可少的工具的概念。微软最近收购了 GitHub，这是基于 Git 的最大远程代码存储库网站，并将大多数 Microsoft 的 IDEs/编辑器与之集成，包括最新的代码编辑器 Visual Code。这显示了 Git 对我们行业有多么重要。我相信每个开发人员，无论是新手还是资深人员，都应该为他们的代码使用版本控制。如果您不使用 Git，您可以使用市场上的任何其他版本控制系统。然而，Git 是最好的，即使您在工作中没有使用 Git，我也建议您在个人项目中使用它。Git 命令非常简单，所以您只需要练习几次就能完全理解它。

下一章有点不同。我们将看一些在求职面试中常被问到的问题。


# 第十四章：为面试做好准备-面试和未来

这是一本**面向对象编程**（**OOP**）书中不同寻常的一章。面试是软件开发人员职业生涯的重要组成部分。面试就像对你知识的一次考验。它让你了解自己的知识水平和你应该学习更多的内容。这也是向其他公司的经验丰富的开发人员学习的一种方式。

本章的主要目的是让你了解在工作面试中会问到哪些类型的问题，以及你如何为此做好准备。请记住，工作面试问题取决于你申请的职位、公司、面试官的知识以及公司正在使用的技术栈。虽然不是所有这些问题都会被问到，但有可能会问到其中一些，因为这些问题决定了你的基本面向对象编程和 C#知识。

让我们回顾一下本章将涵盖的主题：

+   面试问题

+   面试和职业建议

+   接下来要学习的东西

+   阅读的重要性

# 面试问题

在本节中，我们将讨论一些初学者到中级开发人员最常见的面试问题。由于本书是关于 C#的，我们还将提出与 C#编程语言直接相关的问题。

# 面向对象编程的基本原则是什么？

面向对象编程有四个基本原则：

+   继承

+   封装

+   抽象

+   多态

# 什么是继承？

**继承**意味着一个类可以继承另一个类的属性和方法。例如，`Dog`是一个类，但它也是`Animal`的子类。`Animal`类是一个更一般的类，具有所有动物都具有的基本属性和方法。由于狗也是一种动物，`Dog`类可以继承`Animal`类，因此`Animal`类的所有属性和方法也可以在`Dog`类中使用。

# 什么是封装？

**封装**意味着隐藏类的数据。C#中的访问修饰符主要用于封装的目的。如果我们将一个方法或字段设置为私有，那么该方法或字段在类外部是不可访问的。这意味着我们将数据隐藏在外部世界之外。封装的主要原因是我们希望隐藏更复杂的实现，只向外部世界展示简单的接口以便于使用。

# 什么是抽象？

**抽象**是一个概念，不是真实的东西。**抽象**意味着向外界提供某个对象的概念，但不提供其实现。接口和抽象类是抽象的例子。当我们创建一个接口时，我们不在其中实现方法，但当一个类实现接口时，它也必须实现该方法。这意味着接口实际上给出了类的抽象印象。

# 什么是多态？

**多态**意味着多种形式。在面向对象编程中，我们应该有创建一种东西的多种形式的选项。例如，您可以有一个`addition`方法，它可能具有不同的实现，具体取决于它接收的输入。一个接收两个整数并返回这些整数的和的`addition`方法可能是一种实现。还可能有另一种形式的`addition`方法，它可能接受两个双精度值并返回这些双精度值的和。

# 什么是接口？

**接口**是 C#编程语言中用于在程序中应用抽象的实体或特性。它就像类和接口本身之间的合同。合同是，将继承接口的类必须实现接口本身内部的方法签名。接口不能被实例化，它只能被类或结构实现。

# 什么是抽象类？

**抽象类**是一种特殊的类，不能被初始化。不能从抽象类创建对象。抽象类可以有具体方法和非具体方法。如果一个类实现了一个抽象类，那么这个类必须实现抽象方法。如果需要的话，它可以重写非抽象方法。

# 什么是密封类？

**密封类**是一个不能被继承的类。它主要用于阻止 C#中的继承特性。

# 什么是部分类？

**部分类**是源代码分布在不同文件中的类。通常，一个类的所有字段和方法都在同一个文件中。在部分类中，你可以将类代码分开放在不同的文件中。编译时，所有来自不同文件的代码都被视为单个类。

# 接口和抽象类之间有什么区别？

接口和抽象类之间的主要区别如下：

+   一个类可以实现任意数量的接口，但只能实现一个抽象类。

+   抽象类既可以有抽象方法，也可以有非抽象方法，而接口不能有非抽象方法。

+   在抽象类中，数据成员默认为私有，而在接口中，所有数据成员都是公共的，这是无法更改的。

+   在抽象类中，我们需要使用`abstract`关键字使方法抽象，而在接口中不需要。

# 方法重载和方法重写之间有什么区别？

**方法重载**是指具有相同名称但具有不同输入参数的方法。例如，假设我们有一个名为`Sum`的方法，它接受两个整数类型的输入并返回一个整数类型的输出。`Sum`的重载方法可以接受两个双精度类型的输入并返回一个双精度输出。

**方法重写**是指在子类中实现具有相同名称、相同参数和相同返回类型的方法，用于不同的实现。例如，假设我们在一个名为`Sales`的类中有一个名为`Discount`的方法，其中折扣按照总购买额的 2%计算。如果我们有`Sales`的另一个子类称为`NewYearSales`，其中折扣按照 5%计算，使用方法重写，`NewYearSales`类可以轻松应用新的实现。

# 访问修饰符是什么？

**访问修饰符**用于设置编程语言中不同实体的安全级别。通过设置访问修饰符，我们可以为不同级别的类隐藏数据。

在 C#中，有六种类型的访问修饰符：

+   公共

+   私有

+   受保护的

+   内部

+   受保护的内部

+   私有受保护

# 什么是装箱和拆箱？

**装箱**是将值类型转换为对象的过程。**拆箱**是从对象中提取值类型的过程。装箱可以隐式进行，但拆箱必须在代码中显式进行。

# 结构体和类之间有什么区别？

结构体和类是非常相似的概念，但有一些区别：

+   结构体是值类型，类是引用类型。

+   结构体通常用于小量数据，而类用于大量数据。

+   结构体不能被其他类型继承，而类可以被其他类继承。

+   结构体不能是抽象的，而类可以是抽象的。

# C#中的扩展方法是什么，我们如何使用它？

扩展方法是一种方法，它被添加到现有类型中，而不创建新的派生类型或编译或更改现有类型。它的工作原理类似于扩展。例如，默认情况下，我们从.NET 框架中获得字符串类型。如果我们想要向这个字符串类型添加另一个方法，要么我们必须创建一个扩展这个字符串类型并在那里放置方法的派生类型，要么我们在.NET 框架中添加代码并编译和重建库。然而，使用扩展方法，我们可以轻松地扩展现有类型中的方法。为此，我们必须创建一个静态类，然后创建一个静态的扩展方法。这个方法应该以类型作为参数，但是在字符串之前应该放置`this`关键字。现在这个方法将作为该类型的扩展方法工作。

# 什么是托管代码和非托管代码？

在.NET 框架中开发的代码称为托管代码。**公共语言运行时**（**CLR**）可以直接执行这段代码。非托管代码不是在.NET 框架中开发的。

# C#中的虚方法是什么？

**虚方法**是在基类中实现的方法，但也可以在子类中重写的方法。虚方法不能是抽象的、静态的、私有的或重写的。

# 你对 C#.NET 中的值类型和引用类型有什么理解？

在 C#中，有两种类型的数据。一种称为值类型，另一种称为引用类型。**值类型**是直接在内存位置中保存值的类型。如果值被复制，新的内存位置保存相同的值，两者相互独立。**引用类型**是指值不直接放置在内存位置中，而是设置对该值的引用。值类型和引用类型之间的另一个主要区别是值类型位于堆栈中，而引用类型位于堆中。值类型的例子是`int`，而引用类型的例子是`string`。

# 什么是设计原则？

有五个设计原则组成了缩写**SOLID**：

+   单一责任原则

+   开闭原则

+   里氏替换原则

+   接口隔离原则

+   依赖反转原则

# 单一责任原则是什么？

<q>*"一个类应该有一个，只有一个改变的理由。"*</q>

- *罗伯特·C·马丁*

这意味着一个类应该只有一个责任。如果一个类做了多件事情，这就违反了**单一责任原则**（**SRP**）。例如，如果我们有一个名为`Student`的类，它应该只负责与学生相关的数据。如果`Student`类需要在`Teacher`类中更改任何内容时进行修改，`Student`类就违反了 SRP。

# 开闭原则是什么？

软件组件应该对扩展开放，但对修改关闭。这意味着组件应该设计成这样，如果需要添加新的规则或功能，就不需要修改现有的代码。如果必须修改现有的代码来添加新功能，这意味着组件违反了**开闭原则**。

# 什么是里氏替换原则？

派生类型必须完全可替代其基类型。这意味着如果在某个地方使用了基类的实例，应该能够用该基类的子类实例替换基类实例而不会破坏任何功能。例如，如果有一个名为`Animal`的基类和一个名为`Dog`的子类，应该能够用`Dog`类的实例替换`Animal`类的实例而不会破坏任何功能。

# 接口隔离原则是什么？

客户不应该被迫依赖他们不使用的接口。有时，接口包含了许多可能不被实现它们的类使用的信息。**接口隔离原则**建议你保持接口的小型化。类不应该实现一个大接口，而应该实现多个小接口，其中类中的所有方法都是需要的。

# 依赖反转原则是什么？

高级模块不应该依赖低级模块；两者都应该依赖抽象。这意味着，当你开发模块化软件代码时，高级模块不应该直接依赖低级模块，而应该依赖低级模块实现的接口或抽象类。通过这样做，系统中的模块是独立的，将来如果你用另一个模块替换低级模块，高级模块不会受到影响。

这个原则的另一个部分是*抽象不应该依赖细节，细节应该依赖抽象*。这意味着接口或抽象类不应该依赖类，而实现接口和抽象类的类应该依赖接口或抽象类。

# 面试和职业技巧

既然我们已经涵盖了一些面试中可能被问到的最常见的问题，我还有一些提示，可以帮助你在面试和职业生涯中表现更好。

# 提高你的沟通技巧

人们普遍认为软件开发人员不合群，沟通能力不强。然而，现实情况却截然不同。所有成功的开发人员都必须具备良好的沟通能力。

作为软件开发人员，你会有时候需要向非技术人员解释技术理念或情况。为了能够做到这一点，你必须以一种使信息对每个人都易于访问和理解的方式进行沟通。这可能包括口头（会议或讨论）和书面沟通（文档或电子邮件）。

在你职业生涯的开始阶段，你可能并不一定理解沟通的重要性，因为你只是被分配任务来完成。然而，随着你的经验积累和职业发展，你会意识到有效沟通的重要性。

作为一名高级开发人员，你可能需要与初级开发人员沟通，解释问题或解决方案，或者与业务团队沟通，以确保你充分理解业务需求。你可能还需要进行技术培训以分享知识。

因此，请确保你与人们保持互动，并阅读能帮助你有效沟通并教你如何应对听众的资源。良好的沟通技巧不仅会帮助你在面试中脱颖而出，而且在整个职业生涯中也会对你有价值。

# 继续练习

虽然没有完美的软件开发人员，但通过定期练习，你可以成为一个知识渊博、经验丰富的软件开发人员。

计算机编程是一门艺术。通过犯错误，你会培养出对错与对的感觉。你编写的代码越多，你就会经历更多不同的情况。这些情况将帮助你积累经验，因为你很可能在未来的项目中再次遇到它们。

学习或掌握编程的最佳方法是*实践*。

尝试将你在本书中学到的概念应用到你的实际项目中。如果在你当前的项目中不可能这样做，那就创建演示项目并在那里应用它们。技术概念非常实用；如果你进行实际实现，这些概念将变得非常清晰。

# 接下来要学习的东西

阅读完这本书后，你应该对面向对象编程和 C#编程语言有更好的理解。然而，这还不够。你必须努力学习更多关于软件开发的知识。你应该学习 C#的其他语言特性，以及如何使用它们来完成工作。你还应该学习数据结构和算法以应对专业工作。在下面的列表中，我建议了一些接下来可以研究的主题和技术：

+   C#编程语言特性，如运算符、控制语句、数组、列表、运算符重载、Lambda 表达式、LINQ、字符串格式化和线程

+   诸如链表、二叉树、排序和搜索算法之类的数据结构和算法

+   诸如 ASP.NET MVC、ASP.NET Web API、WPF 和 WCF 之类的 Web/桌面框架

+   前端技术，如 HTML、CSS 和 JavaScript，以及 JavaScript 框架，如 reactjs/angular

+   诸如 MS SQL Server、Oracle 和 MySQL 之类的数据库技术

+   设计模式及其影响

+   软件架构和设计

+   代码整洁、代码重构和代码优化

还有许多其他要学习的东西，但我已经涵盖了我认为每个软件开发人员都应该了解的主题。这个列表相当长，主题相当技术，所以要仔细规划你的学习。

# 养成阅读的习惯

我最后的建议是成为一个热心的读者。阅读对于软件开发人员非常重要。信息通常通过文本或语音分发给人们。虽然视频教程是学习的好方法，但阅读可以给你时间思考，并为你提供数以百万计的资源。

以下是我必读的一些书籍：

+   《实用程序员：从学徒到大师》作者安德鲁·亨特和大卫·托马斯

+   《代码整洁之道》作者罗伯特·塞西尔·马丁

+   《代码大全 2》作者史蒂夫·麦康奈尔

+   《重构》作者马丁·福勒和肯特·贝克

+   《算法导论》作者查尔斯·E·莱斯森、克利福德·斯坦、罗纳德·李维斯特和托马斯·H·科尔门

+   《设计模式：可复用面向对象软件的元素》四人组合著

+   《C# 7.0 权威指南》作者约瑟夫·阿尔巴哈里

+   《深入 C#》作者乔恩·斯基特

# 总结

软件开发是一个非常有趣的领域。你可以开发能够改变世界的惊人应用。像 Facebook 和 Maps 这样的应用，以及谷歌和 Windows 等数字巨头的众多产品，对我们的生活产生了重大影响。程序可以通过提高生产力来让人们的生活更加便利。

作为一名软件开发人员，我请求你写出优秀的代码并开发出惊人的应用。如果你有正确的意图、对软件开发有激情和强烈的职业道德，你一定会在你的职业生涯中取得成功。

让我们通过创建能够促进人类文明进步的惊人软件，让这个世界变得更美好。
