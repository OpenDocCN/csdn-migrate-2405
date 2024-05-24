# C#10 和 .NET6 代码跨平台开发（一）

> 原文：[`zh.annas-archive.org/md5/B053DEF9CB8C4C14E67E73C1EC2319CF`](https://zh.annas-archive.org/md5/B053DEF9CB8C4C14E67E73C1EC2319CF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

有些编程书籍长达数千页，旨在成为 C#语言、.NET 库、网站、服务和桌面及移动应用等应用模型的全面参考。

本书与众不同，它简洁明了，旨在成为一本轻松愉快的读物，充满每个主题的实用动手演练。虽然整体叙述的广度牺牲了一些深度，但你会发现许多标志指引你进一步探索，如果你愿意的话。

本书既是一本学习现代 C#实践的逐步指南，使用跨平台的.NET，也是对主要实用应用程序类型的简要介绍，这些应用程序可以用它们构建。本书最适合 C#和.NET 的初学者，或者那些在过去使用过 C#但感觉被过去几年变化所落后的程序员。

如果你已有 C#旧版本的经验，那么在*第二章*的*第一节*，*说 C#*中，你可以查看新语言特性的表格并直接跳转到它们。

如果你已有.NET 库旧版本的经验，那么在*第七章*的*第一节*，*打包和分发.NET 类型*中，你可以查看新库特性的表格并直接跳转到它们。

我将指出 C#和.NET 的酷炫角落和陷阱，让你能给同事留下深刻印象并快速提高生产力。与其放慢速度并让一些读者感到无聊，通过解释每一个小细节，我会假设你足够聪明，能够通过谷歌搜索解释与主题相关但不必包含在印刷书籍有限空间内的初学者到中级指南中。

# 代码解决方案的获取位置

你可以在以下链接的 GitHub 仓库中下载逐步指导任务和练习的解决方案：[`github.com/markjprice/cs10dotnet6`](https://github.com/markjprice/cs10dotnet6)。

如果你不知道如何操作，我会在*第一章*，*你好，C#！欢迎，.NET！*的末尾提供操作指南。

# 本书内容涵盖

*第一章*，*你好，C#！欢迎，.NET！*，是关于设置你的开发环境，并使用 Visual Studio 或 Visual Studio Code 创建最简单的 C#和.NET 应用程序。对于简化的控制台应用，你将看到 C# 9 引入的顶级程序特性的使用。为了学习如何编写简单的语言结构和库特性，你将看到.NET 交互式笔记本的使用。你还将了解一些寻求帮助的好地方，以及通过 GitHub 仓库与我联系以获取解决问题或提供反馈以改进本书和未来版本的方法。

*第二章*，*说 C#*，介绍了 C#的版本，并提供了表格显示哪些版本引入了新特性。我解释了日常编写应用程序源代码所需的语法和词汇。特别是，你将学习如何声明和操作不同类型的变量。

*第三章*，*控制流程、类型转换和异常处理*，涵盖了使用运算符对变量执行简单操作，包括比较，编写决策代码，C# 7 到 C# 10 中的模式匹配，重复语句块，以及类型之间的转换。它还涵盖了编写防御性代码以处理不可避免发生的异常。

*第四章*，*编写、调试和测试函数*，是关于遵循**不要重复自己**（**DRY**）原则，通过使用命令式和函数式实现风格编写可重用函数。你还将学习如何使用调试工具来追踪和消除错误，监控代码执行以诊断问题，并严格测试代码以消除错误，确保在部署到生产环境之前的稳定性和可靠性。

*第五章*，*使用面向对象编程构建自己的类型*，讨论了类型可以拥有的所有不同类别的成员，包括用于存储数据的字段和用于执行操作的方法。你将运用**面向对象编程**（**OOP**）的概念，如聚合和封装。你将了解诸如元组语法支持、`out`变量、默认字面量和推断元组名称等语言特性，以及如何使用 C# 9 中引入的`record`关键字、仅初始化属性以及`with`表达式定义和操作不可变类型。

*第六章*，*实现接口和继承类*，解释了使用 OOP 从现有类型派生新类型。你将学习如何定义运算符和局部函数、委托和事件，如何实现关于基类和派生类的接口，如何重写类型的成员，如何使用多态性，如何创建扩展方法，如何在继承层次结构中进行类之间的转换，以及 C# 8 中引入可空引用类型的大变化。

*第七章*，*打包和分发.NET 类型*，介绍了.NET 的版本，并提供了表格显示哪些版本引入了新的库特性，然后介绍了符合.NET 标准的.NET 类型以及它们与 C#的关系。你将学习如何在支持的操作系统（Windows、macOS 和 Linux 变体）上编写和编译代码。你将学习如何打包、部署和分发你自己的应用程序和库。

*第八章*，*使用常见的.NET 类型*，讨论了使你的代码能够执行常见实际任务的类型，例如操作数字和文本、日期和时间、在集合中存储项目、处理网络和操作图像，以及实现国际化。

*第九章*，*使用文件、流和序列化*，涵盖了与文件系统交互、读写文件和流、文本编码以及 JSON 和 XML 等序列化格式，包括`System.Text.Json`类增强的功能和性能。

*第十章*，*使用 Entity Framework Core 处理数据*，讲解了如何使用名为**实体框架核心**（**EF Core**）的**对象关系映射**（**ORM**）技术读写关系数据库，如 Microsoft SQL Server 和 SQLite。你将学习如何定义映射到数据库中现有表的实体模型，以及如何定义可以在运行时创建表和数据库的 Code First 模型。

*第十一章*，*使用 LINQ 查询和操作数据*，教授你关于**语言集成查询**（**LINQ**）——这些语言扩展增加了处理项目序列、过滤、排序并将它们投射到不同输出的能力。你将了解**并行 LINQ**（**PLINQ**）和 LINQ to XML 的特殊功能。

*第十二章*，*使用多任务提高性能和可扩展性*，讨论了允许同时发生多个动作以提高性能、可扩展性和用户生产率的方法。你将学习`async Main`特性以及如何使用`System.Diagnostics`命名空间中的类型来监控你的代码，以衡量性能和效率。

*第十三章*，*介绍 C#和.NET 的实际应用*，向你介绍了可以使用 C#和.NET 构建的跨平台应用程序类型。你还将构建一个 EF Core 模型来表示 Northwind 数据库，该数据库将在本书的其余章节中使用。

*第十四章*，*使用 ASP.NET Core Razor Pages 构建网站*，讲述了如何利用现代 HTTP 架构在服务器端使用 ASP.NET Core 学习网站构建的基础知识。你将学习如何实现 ASP.NET Core 的 Razor Pages 特性，该特性简化了为小型网站创建动态网页的过程，以及构建 HTTP 请求和响应管道的知识。

*第十五章*，*使用模型-视图-控制器模式构建网站*，讲述了如何使用 ASP.NET Core MVC 以易于单元测试和管理团队编程的方式构建大型复杂网站。你将学习启动配置、认证、路由、模型、视图和控制器。

*第十六章*，*构建和消费 Web 服务*，解释了使用 ASP.NET Core Web API 构建后端 REST 架构的 Web 服务以及如何正确使用工厂实例化的 HTTP 客户端消费它们。

*第十七章*，*使用 Blazor 构建用户界面*，介绍如何使用 Blazor 构建可在服务器端或客户端 Web 浏览器内执行的 Web 用户界面组件。您将了解 Blazor Server 和 Blazor WebAssembly 之间的差异，以及如何构建易于在这两种托管模型之间切换的组件。

三篇在线附加章节为本版增色不少。您可以在[`static.packt-cdn.com/downloads/9781801077361_Bonus_Content.pdf`](https://static.packt-cdn.com/downloads/9781801077361_Bonus_Content.pdf)阅读以下章节及附录：

*第十八章*，*构建和消费专业化服务*，向您介绍使用 gRPC 构建服务，使用 SignalR 实现服务器与客户端之间的实时通信，通过 OData 公开 EF Core 模型，以及在云中托管响应触发器的函数使用 Azure Functions。

*第十九章*，*使用.NET MAUI 构建移动和桌面应用*，向您介绍如何为 Android、iOS、macOS 和 Windows 构建跨平台的移动和桌面应用。您将学习 XAML 的基础知识，这是一种用于定义图形应用用户界面的语言。

*第二十章*，*保护您的数据和应用*，涉及使用加密保护数据不被恶意用户查看，使用哈希和签名防止数据被篡改或损坏。您还将学习认证和授权以保护应用免受未授权用户的侵害。

*附录*，*测试题答案*，提供了每章末尾测试题的答案。

# 本书所需条件

您可以在包括 Windows、macOS 和多种 Linux 在内的多个平台上使用 Visual Studio Code 开发和部署 C#和.NET 应用。

除了一个章节外，您只需一个支持 Visual Studio Code 的操作系统和互联网连接即可完成所有章节。

如果您更喜欢使用 Windows 或 macOS 上的 Visual Studio，或是第三方工具如 JetBrains Rider，那么您可以这么做。

您需要 macOS 来构建*第十九章*，*使用.NET MAUI 构建移动和桌面应用*中的 iOS 应用，因为编译 iOS 应用必须要有 macOS 和 Xcode。

## 下载本书的彩色图像

我们还为您提供了一个包含本书中使用的屏幕截图和图表的彩色图像的 PDF 文件。彩色图像将帮助您更好地理解输出的变化。

您可以从[`static.packt-cdn.com/downloads/9781801077361_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781801077361_ColorImages.pdf)下载此文件。

## 约定

在本书中，您会发现多种文本样式用于区分不同类型的信息。以下是这些样式的示例及其含义的解释。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如；“`Controllers`、`Models`和`Views`文件夹包含 ASP.NET Core 类以及服务器上执行的`.cshtml`文件。”

代码块的设置如下：

```cs
// storing items at index positions 
names[0] = "Kate";
names[1] = "Jack"; 
names[2] = "Rebecca"; 
names[3] = "Tom"; 
```

当我们希望引起您对代码块特定部分的注意时，相关行或项会突出显示：

```cs
// storing items at index positions 
names[0] = "Kate";
**names[****1****] =** **"Jack"****;** 
names[2] = "Rebecca"; 
names[3] = "Tom"; 
```

命令行输入或输出的书写格式如下：

```cs
dotnet new console 
```

**粗体**：表示一个新**术语**、一个重要**单词**或您在屏幕上看到的单词，例如在菜单或对话框中。例如：“点击**下一步**按钮将您带到下一个屏幕。”

重要提示和指向外部进一步阅读资源的链接以这种框的形式出现。

**良好实践**：专家编程建议以这种方式出现。


# 第一章：你好，C#！欢迎，.NET！

在本章中，目标包括设置开发环境，理解现代.NET、.NET Core、.NET Framework、Mono、Xamarin 和.NET Standard 之间的异同，使用 C# 10 和.NET 6 以及各种代码编辑器创建最简单的应用程序，然后找到寻求帮助的好地方。

本书的 GitHub 仓库提供了所有代码任务的完整应用程序项目解决方案，并在可能的情况下提供笔记本：

[`github.com/markjprice/cs10dotnet6`](https://github.com/markjprice/cs10dotnet6)

只需按下.（点）键或在上述链接中将`.com`更改为`.dev`，即可将 GitHub 仓库转换为使用 Visual Studio Code for the Web 的实时编辑器，如*图 1.1*所示：

![图形用户界面，文字，应用程序 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_01.png)

*图 1.1：* Visual Studio Code for the Web 正在实时编辑本书的 GitHub 仓库

这非常适合在你阅读本书并完成编程任务时与你的首选代码编辑器并行使用。你可以将自己的代码与解决方案代码进行比较，并在需要时轻松复制和粘贴部分代码。

本书中，我使用术语**现代.NET**来指代.NET 6 及其前身，如.NET 5 等源自.NET Core 的版本。而术语**传统.NET**则用来指代.NET Framework、Mono、Xamarin 和.NET Standard。现代.NET 是对这些传统平台和标准的统一。

本章之后，本书可分为三个部分：首先是 C#语言的语法和词汇；其次是.NET 中用于构建应用特性的类型；最后是使用 C#和.NET 构建的常见跨平台应用示例。

大多数人通过模仿和重复来最好地学习复杂主题，而不是通过阅读详细的理论解释；因此，本书不会用每一步的详细解释来让你负担过重。目的是让你动手编写代码并看到运行结果。

你不需要立即了解所有细节。随着你构建自己的应用程序并超越任何书籍所能教授的内容，这些知识将会逐渐积累。

正如 1755 年编写英语词典的塞缪尔·约翰逊所言，我已犯下“一些野蛮的错误和可笑的荒谬，任何如此繁多的作品都无法免俗。”我对此负全责，并希望你能欣赏我试图通过撰写关于 C#和.NET 等快速发展的技术以及使用它们构建的应用程序的书籍来挑战风车的尝试。

本章涵盖以下主题：

+   设置开发环境

+   理解.NET

+   使用 Visual Studio 2022 构建控制台应用程序

+   使用 Visual Studio Code 构建控制台应用程序

+   使用.NET 交互式笔记本探索代码

+   审查项目文件夹和文件

+   充分利用本书的 GitHub 仓库

+   寻求帮助

# 设置你的开发环境

在你开始编程之前，你需要一个 C#代码编辑器。微软有一系列代码编辑器和**集成开发环境**（**IDEs**），其中包括：

+   Visual Studio 2022 for Windows

+   Visual Studio 2022 for Mac

+   Visual Studio Code for Windows, Mac, or Linux

+   GitHub Codespaces

第三方已经创建了自己的 C#代码编辑器，例如，JetBrains Rider。

## 选择适合学习的工具和应用程序类型

学习 C#和.NET 的最佳工具和应用程序类型是什么？

在学习时，最好的工具是帮助你编写代码和配置但不隐藏实际发生的事情的工具。IDE 提供了友好的图形用户界面，但它们在背后为你做了什么？一个更基础的代码编辑器，在提供帮助编写代码的同时更接近操作，在你学习时更为合适。

话虽如此，你可以认为最好的工具是你已经熟悉的工具，或者是你或你的团队将作为日常开发工具使用的工具。因此，我希望你能够自由选择任何 C#代码编辑器或 IDE 来完成本书中的编码任务，包括 Visual Studio Code、Windows 的 Visual Studio、Mac 的 Visual Studio，甚至是 JetBrains Rider。

在本书第三版中，我为所有编码任务提供了针对 Windows 的 Visual Studio 和适用于所有平台的 Visual Studio Code 的详细分步指导。不幸的是，这很快就变得杂乱无章。在第六版中，我仅在*第一章*中提供了关于如何在 Windows 的 Visual Studio 2022 和 Visual Studio Code 中创建多个项目的详细分步指导。之后，我会给出项目名称和适用于所有工具的一般指导，以便你可以使用你偏好的任何工具。

学习 C#语言结构和许多.NET 库的最佳应用程序类型是不被不必要的应用程序代码分散注意力的类型。例如，没有必要为了学习如何编写一个`switch`语句而创建一个完整的 Windows 桌面应用程序或网站。

因此，我相信学习*第一章*到*第十二章*中 C#和.NET 主题的最佳方法是构建控制台应用程序。然后，从*第十三章*到*第十九章*开始，你将构建网站、服务以及图形桌面和移动应用。

### .NET Interactive Notebooks 扩展的优缺点

Visual Studio Code 的另一个好处是.NET Interactive Notebooks 扩展。这个扩展提供了一个简单且安全的地方来编写简单的代码片段。它允许你创建一个单一的笔记本文件，其中混合了 Markdown（格式丰富的文本）和使用 C#及其他相关语言（如 PowerShell、F#和 SQL（用于数据库））的代码“单元格”。

然而，.NET Interactive Notebooks 确实有一些限制：

+   它们无法从用户那里读取输入，例如，你不能使用`ReadLine`或`ReadKey`。

+   它们不能接受参数传递。

+   它们不允许你定义自己的命名空间。

+   它们没有任何调试工具（但未来将会提供）。

### 使用 Visual Studio Code 进行跨平台开发

最现代且轻量级的代码编辑器选择，也是微软唯一一款跨平台的编辑器，是 Microsoft Visual Studio Code。它可以在所有常见的操作系统上运行，包括 Windows、macOS 以及多种 Linux 发行版，如 Red Hat Enterprise Linux（RHEL）和 Ubuntu。

Visual Studio Code 是现代跨平台开发的不错选择，因为它拥有一个庞大且不断增长的扩展集合，支持多种语言，而不仅仅是 C#。

由于其跨平台和轻量级的特性，它可以安装在所有你的应用将要部署到的平台上，以便快速修复错误等。选择 Visual Studio Code 意味着开发者可以使用一个跨平台的代码编辑器来开发跨平台的应用。

Visual Studio Code 对 Web 开发有强大的支持，尽管目前对移动和桌面开发的支持较弱。

Visual Studio Code 支持 ARM 处理器，因此你可以在 Apple Silicon 计算机和 Raspberry Pi 上进行开发。

Visual Studio Code 是目前最受欢迎的集成开发环境，根据 Stack Overflow 2021 调查，超过 70%的专业开发者选择了它。

### 使用 GitHub Codespaces 进行云端开发

GitHub Codespaces 是一个基于 Visual Studio Code 的完全配置的开发环境，可以在云端托管的环境中启动，并通过任何网络浏览器访问。它支持 Git 仓库、扩展和内置的命令行界面，因此你可以从任何设备进行编辑、运行和测试。

### 使用 Visual Studio for Mac 进行常规开发

Microsoft Visual Studio 2022 for Mac 可以创建大多数类型的应用程序，包括控制台应用、网站、Web 服务、桌面和移动应用。

要为苹果操作系统如 iOS 编译应用，使其能在 iPhone 和 iPad 等设备上运行，你必须拥有 Xcode，而它仅能在 macOS 上运行。

### 使用 Visual Studio for Windows 进行常规开发

Microsoft Visual Studio 2022 for Windows 可以创建大多数类型的应用程序，包括控制台应用、网站、Web 服务、桌面和移动应用。尽管你可以使用 Visual Studio 2022 for Windows 配合其 Xamarin 扩展来编写跨平台移动应用，但你仍然需要 macOS 和 Xcode 来编译它。

它仅能在 Windows 上运行，版本需为 7 SP1 或更高。你必须在 Windows 10 或 Windows 11 上运行它，以创建**通用 Windows 平台**（**UWP**）应用，这些应用通过 Microsoft Store 安装，并在沙盒环境中运行以保护你的计算机。

### 我所使用的

为了编写和测试本书的代码，我使用了以下硬件：

+   HP Spectre（Intel）笔记本电脑

+   Apple Silicon Mac mini（M1）台式机

+   Raspberry Pi 400（ARM v8）台式机

我还使用了以下软件：

+   Visual Studio Code 运行于：

    +   在搭载 Apple Silicon M1 芯片的 Mac mini 台式机上运行的 macOS

    +   Windows 10 系统下的 HP Spectre（Intel）笔记本电脑

    +   Raspberry Pi 400 上的 Ubuntu 64

+   Visual Studio 2022 for Windows 适用于：

    +   HP Spectre（Intel）笔记本电脑上的 Windows 10

+   Visual Studio 2022 for Mac 适用于：

    +   Apple Silicon Mac mini（M1）桌面上的 macOS

我希望您也能接触到各种硬件和软件，因为观察不同平台之间的差异能加深您对开发挑战的理解，尽管上述任何一种组合都足以学习 C#和.NET 的基础知识，以及如何构建实用的应用程序和网站。

**更多信息**：您可以通过阅读我撰写的一篇额外文章，了解如何使用 Raspberry Pi 400 和 Ubuntu Desktop 64 位编写 C#和.NET 代码，链接如下：[`github.com/markjprice/cs9dotnet5-extras/blob/main/raspberry-pi-ubuntu64/README.md`](https://github.com/markjprice/cs9dotnet5-extras/blob/main/raspberry-pi-ubuntu64/README.md).

## 跨平台部署

您选择的代码编辑器和操作系统不会限制代码的部署位置。

.NET 6 支持以下平台进行部署：

+   **Windows**: Windows 7 SP1 或更高版本。Windows 10 版本 1607 或更高版本，包括 Windows 11。Windows Server 2012 R2 SP1 或更高版本。Nano Server 版本 1809 或更高版本。

+   **Mac**: macOS Mojave（版本 10.14）或更高版本。

+   **Linux**: Alpine Linux 3.13 或更高版本。CentOS 7 或更高版本。Debian 10 或更高版本。Fedora 32 或更高版本。openSUSE 15 或更高版本。Red Hat Enterprise Linux（RHEL）7 或更高版本。SUSE Enterprise Linux 12 SP2 或更高版本。Ubuntu 16.04、18.04、20.04 或更高版本。

+   **Android**: API 21 或更高版本。

+   **iOS**: 10 或更高版本。

.NET 5 及更高版本中的 Windows ARM64 支持意味着您可以在 Windows ARM 设备（如 Microsoft Surface Pro X）上进行开发和部署。但在 Apple M1 Mac 上使用 Parallels 和 Windows 10 ARM 虚拟机进行开发显然速度快两倍！

## 下载并安装 Windows 版 Visual Studio 2022

许多专业的微软开发人员在其日常开发工作中使用 Windows 版 Visual Studio 2022。即使您选择使用 Visual Studio Code 完成本书中的编码任务，您也可能希望熟悉 Windows 版 Visual Studio 2022。

如果您没有 Windows 计算机，则可以跳过此部分，继续到下一部分，在那里您将下载并安装 macOS 或 Linux 上的 Visual Studio Code。

自 2014 年 10 月以来，微软为学生、开源贡献者和个人免费提供了一款专业质量的 Windows 版 Visual Studio。它被称为社区版。本书中任何版本都适用。如果您尚未安装，现在就让我们安装它：

1.  从以下链接下载适用于 Windows 的 Microsoft Visual Studio 2022 版本 17.0 或更高版本：[`visualstudio.microsoft.com/downloads/`](https://visualstudio.microsoft.com/downloads/).

1.  启动安装程序。

1.  在**工作负载**选项卡上，选择以下内容：

    +   **ASP.NET 和 Web 开发**

    +   **Azure 开发**

    +   **.NET 桌面开发**

    +   **使用 C++进行桌面开发**

    +   **通用 Windows 平台开发**

    +   **使用.NET 进行移动开发**

1.  在**单个组件**标签页的**代码工具**部分，选择以下内容：

    +   **类设计器**

    +   **Git for Windows**

    +   **PreEmptive Protection - Dotfuscator**

1.  点击**安装**，等待安装程序获取所选软件并完成安装。

1.  安装完成后，点击**启动**。

1.  首次运行 Visual Studio 时，系统会提示您登录。如果您已有 Microsoft 账户，可直接使用该账户登录。若没有，请通过以下链接注册新账户：[`signup.live.com/`](https://signup.live.com/)。

1.  首次运行 Visual Studio 时，系统会提示您配置环境。对于**开发设置**，选择**Visual C#**。至于颜色主题，我选择了**蓝色**，但您可以根据个人喜好选择。

1.  如需自定义键盘快捷键，请导航至**工具** | **选项…**，然后选择**键盘**部分。

### Microsoft Visual Studio for Windows 键盘快捷键

本书中，我将避免展示键盘快捷键，因为它们常被定制。在跨代码编辑器且常用的情况下，我会尽量展示。如需识别和定制您的键盘快捷键，可参考以下链接：[`docs.microsoft.com/en-us/visualstudio/ide/identifying-and-customizing-keyboard-shortcuts-in-visual-studio`](https://docs.microsoft.com/en-us/visualstudio/ide/identifying-and-customizing-keyboard-shortcuts-in-visual-studio)。

## 下载并安装 Visual Studio Code

Visual Studio Code 在过去几年中迅速改进，其受欢迎程度令微软感到惊喜。如果您勇于尝试且喜欢前沿体验，那么 Insiders 版（即下一版本的每日构建版）将是您的选择。

即使您计划仅使用 Visual Studio 2022 for Windows 进行开发，我也建议您下载并安装 Visual Studio Code，尝试本章中的编码任务，然后决定是否仅使用 Visual Studio 2022 完成本书剩余内容。

现在，让我们下载并安装 Visual Studio Code、.NET SDK 以及 C#和.NET Interactive Notebooks 扩展：

1.  从以下链接下载并安装 Visual Studio Code 的稳定版或 Insiders 版：[`code.visualstudio.com/`](https://code.visualstudio.com/)。

    **更多信息**：如需更多帮助以安装 Visual Studio Code，可阅读官方安装指南，链接如下：[`code.visualstudio.com/docs/setup/setup-overview`](https://code.visualstudio.com/docs/setup/setup-overview)。

1.  从以下链接下载并安装.NET SDK 的 3.1、5.0 和 6.0 版本：[`www.microsoft.com/net/download`](https://www.microsoft.com/net/download)。

    要全面学习如何控制.NET SDK，我们需要安装多个版本。.NET Core 3.1、.NET 5.0 和.NET 6.0 是目前支持的三个版本。您可以安全地并行安装多个版本。您将在本书中学习如何针对所需版本进行操作。

1.  要安装 C#扩展，您必须首先启动 Visual Studio Code 应用程序。

1.  在 Visual Studio Code 中，点击**扩展**图标或导航至**视图** | **扩展**。

1.  C#是最受欢迎的扩展之一，因此您应该在列表顶部看到它，或者您可以在搜索框中输入`C#`。

1.  点击**安装**并等待支持包下载和安装。

1.  在搜索框中输入`.NET Interactive`以查找**.NET 交互式笔记本**扩展。

1.  点击**安装**并等待其安装。

### 安装其他扩展

在本书的后续章节中，您将使用更多扩展。如果您想现在安装它们，我们将使用的所有扩展如下表所示：

| 扩展名称及标识符 | 描述 |
| --- | --- |
| 适用于 Visual Studio Code 的 C#（由 OmniSharp 提供支持）`ms-dotnettools.csharp` | C#编辑支持，包括语法高亮、IntelliSense、转到定义、查找所有引用、.NET 调试支持以及 Windows、macOS 和 Linux 上的`csproj`项目支持。 |
| .NET 交互式笔记本`ms-dotnettools.dotnet-interactive-vscode` | 此扩展为在 Visual Studio Code 笔记本中使用.NET 交互式提供支持。它依赖于 Jupyter 扩展(`ms-toolsai.jupyter`)。 |
| MSBuild 项目工具`tinytoy.msbuild-project-tools` | 为 MSBuild 项目文件提供 IntelliSense，包括`<PackageReference>`元素的自动完成。 |
| REST 客户端`humao.rest-client` | 在 Visual Studio Code 中直接发送 HTTP 请求并查看响应。 |
| ILSpy .NET 反编译器`icsharpcode.ilspy-vscode` | 反编译 MSIL 程序集——支持现代.NET、.NET 框架、.NET Core 和.NET 标准。 |
| Azure Functions for Visual Studio Code`ms-azuretools.vscode-azurefunctions` | 直接从 VS Code 创建、调试、管理和部署无服务器应用。它依赖于 Azure 账户(`ms-vscode.azure-account`)和 Azure 资源(`ms-azuretools.vscode-azureresourcegroups`)扩展。 |
| GitHub 仓库`github.remotehub` | 直接在 Visual Studio Code 中浏览、搜索、编辑和提交到任何远程 GitHub 仓库。 |
| 适用于 Visual Studio Code 的 SQL Server (mssql) `ms-mssql.mssql` | 为 Microsoft SQL Server、Azure SQL 数据库和 SQL 数据仓库的开发提供丰富的功能集，随时随地可用。 |
| Protobuf 3 支持 Visual Studio Code`zxh404.vscode-proto3` | 语法高亮、语法验证、代码片段、代码补全、代码格式化、括号匹配和行与块注释。 |

### 了解 Microsoft Visual Studio Code 版本

微软几乎每月都会发布一个新的 Visual Studio Code 功能版本，错误修复版本则更频繁。例如：

+   版本 1.59，2021 年 8 月功能发布

+   版本 1.59.1，2021 年 8 月错误修复版本

本书使用的版本是 1.59，但微软 Visual Studio Code 的版本不如您安装的 C# for Visual Studio Code 扩展的版本重要。

虽然 C#扩展不是必需的，但它提供了您输入时的 IntelliSense、代码导航和调试功能，因此安装并保持更新以支持最新的 C#语言特性是非常方便的。

### 微软 Visual Studio Code 键盘快捷键

本书中，我将避免展示用于创建新文件等任务的键盘快捷键，因为它们在不同操作系统上往往不同。我展示键盘快捷键的情况是，当您需要重复按下某个键时，例如在调试过程中。这些快捷键也更有可能在不同操作系统间保持一致。

如果您想为 Visual Studio Code 自定义键盘快捷键，那么您可以按照以下链接所示进行操作：[`code.visualstudio.com/docs/getstarted/keybindings`](https://code.visualstudio.com/docs/getstarted/keybindings)。

我建议您从以下列表中下载适用于您操作系统的键盘快捷键 PDF：

+   **Windows**: [`code.visualstudio.com/shortcuts/keyboard-shortcuts-windows.pdf`](https://code.visualstudio.com/shortcuts/keyboard-shortcuts-windows.pdf)

+   **macOS**: [`code.visualstudio.com/shortcuts/keyboard-shortcuts-macos.pdf`](https://code.visualstudio.com/shortcuts/keyboard-shortcuts-macos.pdf)

+   **Linux**: [`code.visualstudio.com/shortcuts/keyboard-shortcuts-linux.pdf`](https://code.visualstudio.com/shortcuts/keyboard-shortcuts-linux.pdf)

# 理解.NET

.NET 6、.NET Core、.NET Framework 和 Xamarin 是开发者用于构建应用程序和服务的相关且重叠的平台。在本节中，我将向您介绍这些.NET 概念。

## 理解.NET Framework

.NET Framework 是一个开发平台，包括**公共语言运行时**（**CLR**），负责代码的执行管理，以及**基础类库**（**BCL**），提供丰富的类库以构建应用程序。

微软最初设计.NET Framework 时考虑到了跨平台的可能性，但微软将其实施努力集中在使其在 Windows 上运行最佳。

自.NET Framework 4.5.2 起，它已成为 Windows 操作系统的官方组件。组件与其父产品享有相同的支持，因此 4.5.2 及更高版本遵循其安装的 Windows OS 的生命周期政策。.NET Framework 已安装在超过十亿台计算机上，因此它必须尽可能少地更改。即使是错误修复也可能导致问题，因此它更新不频繁。

对于 .NET Framework 4.0 或更高版本，计算机上为 .NET Framework 编写的所有应用共享同一版本的 CLR 和库，这些库存储在 **全局程序集缓存** (**GAC**) 中，如果某些应用需要特定版本以确保兼容性，这可能会导致问题。

**良好实践**：实际上，.NET Framework 是仅限 Windows 的遗留平台。不要使用它创建新应用。

## 理解 Mono、Xamarin 和 Unity 项目

第三方开发了一个名为 **Mono** 项目的 .NET Framework 实现。Mono 是跨平台的，但它远远落后于官方的 .NET Framework 实现。

Mono 已找到自己的定位，作为 **Xamarin** 移动平台以及 **Unity** 等跨平台游戏开发平台的基础。

微软于 2016 年收购了 Xamarin，现在将曾经昂贵的 Xamarin 扩展免费提供给 Visual Studio。微软将仅能创建移动应用的 Xamarin Studio 开发工具更名为 Visual Studio for Mac，并赋予其创建控制台应用和 Web 服务等其他类型项目的能力。随着 Visual Studio 2022 for Mac 的推出，微软用 Visual Studio 2022 for Windows 的部分组件替换了 Xamarin Studio 编辑器中的部分，以提供更接近的体验和性能对等。Visual Studio 2022 for Mac 也进行了重写，使其成为真正的 macOS 原生 UI 应用，以提高可靠性并兼容 macOS 内置的辅助技术。

## 理解 .NET Core

如今，我们生活在一个真正的跨平台世界中，现代移动和云开发使得 Windows 作为操作系统的重要性大大降低。因此，微软一直在努力将 .NET 与其紧密的 Windows 联系解耦。在将 .NET Framework 重写为真正跨平台的过程中，他们抓住机会重构并移除了不再被视为核心的重大部分。

这一新产品被命名为 .NET Core，包括一个名为 CoreCLR 的跨平台 CLR 实现和一个名为 CoreFX 的精简 BCL。

微软 .NET 合作伙伴项目经理 Scott Hunter 表示：“我们 40% 的 .NET Core 客户是平台的新开发者，这正是我们希望看到的。我们希望吸引新的人才。”

.NET Core 发展迅速，由于它可以与应用并行部署，因此可以频繁更改，知道这些更改不会影响同一机器上的其他 .NET Core 应用。微软对 .NET Core 和现代 .NET 的大多数改进无法轻松添加到 .NET Framework 中。

## 理解通往统一 .NET 的旅程

2020 年 5 月的微软 Build 开发者大会上，.NET 团队宣布其.NET 统一计划的实施有所延迟。他们表示，.NET 5 将于 2020 年 11 月 10 日发布，该版本将统一除移动平台外的所有.NET 平台。直到 2021 年 11 月的.NET 6，统一.NET 平台才会支持移动设备。

.NET Core 已更名为.NET，主要版本号跳过了数字四，以避免与.NET Framework 4.x 混淆。微软计划每年 11 月发布主要版本，类似于苹果每年 9 月发布 iOS 的主要版本号。

下表显示了现代.NET 的关键版本何时发布，未来版本的计划时间，以及本书各版本使用的版本：

| 版本 | 发布日期 | 版本 | 发布日期 |
| --- | --- | --- | --- |
| .NET Core RC1 | 2015 年 11 月 | 第一版 | 2016 年 3 月 |
| .NET Core 1.0 | 2016 年 6 月 |  |  |
| .NET Core 1.1 | 2016 年 11 月 |  |  |
| .NET Core 1.0.4 和 .NET Core 1.1.1 | 2017 年 3 月 | 第二版 | 2017 年 3 月 |
| .NET Core 2.0 | 2017 年 8 月 |  |  |
| .NET Core for UWP in Windows 10 Fall Creators Update | 2017 年 10 月 | 第三版 | 2017 年 11 月 |
| .NET Core 2.1 (LTS) | 2018 年 5 月 |  |  |
| .NET Core 2.2 (当前) | 2018 年 12 月 |  |  |
| .NET Core 3.0 (当前) | 2019 年 9 月 | 第四版 | 2019 年 10 月 |
| .NET Core 3.1 (LTS) | 2019 年 12 月 |  |  |
| Blazor WebAssembly 3.2 (当前) | 2020 年 5 月 |  |  |
| .NET 5.0 (当前) | 2020 年 11 月 | 第五版 | 2020 年 11 月 |
| .NET 6.0 (LTS) | 2021 年 11 月 | 第六版 | 2021 年 11 月 |
| .NET 7.0 (当前) | 2022 年 11 月 | 第七版 | 2022 年 11 月 |
| .NET 8.0 (LTS) | 2023 年 11 月 | 第八版 | 2023 年 11 月 |

.NET Core 3.1 包含了用于构建 Web 组件的 Blazor Server。微软原本计划在该版本中包含 Blazor WebAssembly，但该计划被推迟了。Blazor WebAssembly 后来作为.NET Core 3.1 的可选附加组件发布。我将其列入上表，因为它被版本化为 3.2，以将其排除在.NET Core 3.1 的 LTS 之外。

## 理解.NET 支持

.NET 版本要么是**长期支持**（**LTS**），要么是**当前**，如下表所述：

+   **LTS**版本稳定，在其生命周期内需要的更新较少。这些版本非常适合您不打算频繁更新的应用程序。LTS 版本将在普遍可用性后支持 3 年，或者在下一个 LTS 版本发布后支持 1 年，以较长者为准。

+   **当前**版本包含的功能可能会根据反馈进行更改。这些版本非常适合您正在积极开发的应用程序，因为它们提供了最新的改进。在 6 个月的维护期后，或者在普遍可用性后的 18 个月后，之前的次要版本将不再受支持。

两者在其生命周期内都会收到安全性和可靠性的关键修复。您必须保持最新补丁以获得支持。例如，如果系统运行的是 1.0，而 1.0.1 已发布，则需要安装 1.0.1 以获得支持。

为了更好地理解当前版本和 LTS 版本的选择，通过可视化方式查看是有帮助的，LTS 版本用 3 年长的黑色条表示，当前版本用长度可变的灰色条表示，并在新的大版本或小版本发布后的 6 个月内保留支持，如*图 1.2*所示：

![文字描述自动生成，置信度低](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_04.png)

图 1.2：对各种版本的支持

例如，如果您使用.NET Core 3.0 创建了一个项目，那么当 Microsoft 在 2019 年 12 月发布.NET Core 3.1 时，您必须在 2020 年 3 月之前将您的项目升级到.NET Core 3.1。（在.NET 5 之前，当前版本的维护期仅为三个月。）

如果您需要来自 Microsoft 的长期支持，那么今天选择.NET 6.0 并坚持使用它直到.NET 8.0，即使 Microsoft 发布了.NET 7.0。这是因为.NET 7.0 将是当前版本，因此它将在.NET 6.0 之前失去支持。请记住，即使是 LTS 版本，您也必须升级到错误修复版本，如 6.0.1。

除了以下列表中所示的版本外，所有.NET Core 和现代.NET 版本均已达到其生命周期结束：

+   .NET 5.0 将于 2022 年 5 月达到生命周期结束。

+   .NET Core 3.1 将于 2022 年 12 月 3 日达到生命周期结束。

+   .NET 6.0 将于 2024 年 11 月达到生命周期结束。

### 理解.NET 运行时和.NET SDK 版本

.NET 运行时版本遵循语义版本控制，即，主版本增量表示重大更改，次版本增量表示新功能，补丁增量表示错误修复。

.NET SDK 版本号并不遵循语义版本控制。主版本号和次版本号与对应的运行时版本绑定。补丁号遵循一个约定，指示 SDK 的主版本和次版本。

您可以在以下表格中看到一个示例：

| 变更 | 运行时 | SDK |
| --- | --- | --- |
| 初始发布 | 6.0.0 | 6.0.100 |
| SDK 错误修复 | 6.0.0 | 6.0.101 |
| 运行时和 SDK 错误修复 | 6.0.1 | 6.0.102 |
| SDK 新特性 | 6.0.1 | 6.0.200 |

### 移除旧版本的.NET

.NET 运行时更新与主版本（如 6.x）兼容，.NET SDK 的更新版本保持了构建针对先前运行时版本的应用程序的能力，这使得可以安全地移除旧版本。

您可以使用以下命令查看当前安装的 SDK 和运行时：

+   `dotnet --list-sdks`

+   `dotnet --list-runtimes`

在 Windows 上，使用**应用和功能**部分来移除.NET SDK。在 macOS 或 Windows 上，使用`dotnet-core-uninstall`工具。此工具默认不安装。

例如，在编写第四版时，我每月都会使用以下命令：

```cs
dotnet-core-uninstall remove --all-previews-but-latest --sdk 
```

## 现代 .NET 有何不同？

与遗留的 .NET Framework 相比，现代 .NET 是模块化的。它是开源的，微软在公开场合做出改进和变更的决定。微软特别注重提升现代 .NET 的性能。

由于移除了遗留和非跨平台技术，它比上一个版本的 .NET Framework 更小。例如，Windows Forms 和 **Windows Presentation Foundation** (**WPF**) 可用于构建 **图形用户界面** (**GUI**) 应用，但它们与 Windows 生态紧密绑定，因此不包含在 macOS 和 Linux 上的 .NET 中。

### 窗口开发

现代 .NET 的特性之一是支持运行旧的 Windows Forms 和 WPF 应用，这得益于包含在 .NET Core 3.1 或更高版本的 Windows 版中的 Windows Desktop Pack，这也是它比 macOS 和 Linux 的 SDK 大的原因。如有必要，你可以对你的遗留 Windows 应用进行一些小改动，然后将其重新构建为 .NET 6，以利用新特性和性能提升。

### 网页开发

ASP.NET Web Forms 和 Windows Communication Foundation (WCF) 是旧的网页应用和服务技术，如今较少开发者选择用于新开发项目，因此它们也已从现代 .NET 中移除。取而代之，开发者更倾向于使用 ASP.NET MVC、ASP.NET Web API、SignalR 和 gRPC。这些技术经过重构并整合成一个运行在现代 .NET 上的平台，名为 ASP.NET Core。你将在*第十四章*、*使用 ASP.NET Core Razor Pages 构建网站*、*第十五章*、*使用模型-视图-控制器模式构建网站*、*第十六章*、*构建和消费网络服务*以及*第十八章*、*构建和消费专用服务*中了解这些技术。

**更多信息**：一些 .NET Framework 开发者对 ASP.NET Web Forms、WCF 和 Windows Workflow (WF) 在现代 .NET 中的缺失感到不满，并希望微软改变主意。有开源项目旨在使 WCF 和 WF 迁移到现代 .NET。你可以在以下链接了解更多信息：[`devblogs.microsoft.com/dotnet/supporting-the-community-with-wf-and-wcf-oss-projects/`](https://devblogs.microsoft.com/dotnet/supporting-the-community-with-wf-and-wcf-oss-projects/)。有一个关于 Blazor Web Forms 组件的开源项目，链接如下：[`github.com/FritzAndFriends/BlazorWebFormsComponents`](https://github.com/FritzAndFriends/BlazorWebFormsComponents)。

### 数据库开发

**Entity Framework**（**EF**）6 是一种对象关系映射技术，设计用于处理存储在 Oracle 和 Microsoft SQL Server 等关系数据库中的数据。多年来，它积累了许多功能，因此跨平台 API 已经精简，增加了对 Microsoft Azure Cosmos DB 等非关系数据库的支持，并更名为 Entity Framework Core。你将在*第十章*，*使用 Entity Framework Core 处理数据*中学习到它。

如果你现有的应用使用旧的 EF，那么 6.3 版本在.NET Core 3.0 或更高版本上得到支持。

## 现代.NET 的主题

微软创建了一个使用 Blazor 的网站，展示了现代.NET 的主要主题：[`themesof.net/`](https://themesof.net/)。

## 理解.NET Standard

2019 年.NET 的情况是，有三个由微软控制的.NET 平台分支，如下列所示：

+   **.NET Core**：适用于跨平台和新应用

+   **.NET Framework**：适用于遗留应用

+   **Xamarin**：适用于移动应用

每种平台都有其优缺点，因为它们都是为不同场景设计的。这导致了一个问题，开发者必须学习三种平台，每种都有令人烦恼的特性和限制。

因此，微软定义了.NET Standard——一套所有.NET 平台都可以实现的 API 规范，以表明它们具有何种程度的兼容性。例如，基本支持通过平台符合.NET Standard 1.4 来表示。

通过.NET Standard 2.0 及更高版本，微软使所有三种平台都向现代最低标准靠拢，这使得开发者更容易在任何类型的.NET 之间共享代码。

对于.NET Core 2.0 及更高版本，这一更新添加了开发者将旧代码从.NET Framework 移植到跨平台的.NET Core 所需的大部分缺失 API。然而，某些 API 虽已实现，但会抛出异常以提示开发者不应实际使用它们！这通常是由于运行.NET 的操作系统之间的差异所致。你将在*第二章*，*C#语言*中学习如何处理这些异常。

重要的是要理解，.NET Standard 只是一个标准。你不能像安装 HTML5 那样安装.NET Standard。要使用 HTML5，你必须安装一个实现 HTML5 标准的网络浏览器。

要使用.NET Standard，你必须安装一个实现.NET Standard 规范的.NET 平台。最后一个.NET Standard 版本 2.1 由.NET Core 3.0、Mono 和 Xamarin 实现。C# 8.0 的一些特性需要.NET Standard 2.1。.NET Standard 2.1 未被.NET Framework 4.8 实现，因此我们应该将.NET Framework 视为遗留技术。

随着 2021 年 11 月.NET 6 的发布，对.NET Standard 的需求大幅减少，因为现在有了一个适用于所有平台的单一.NET，包括移动平台。.NET 6 拥有一个统一的 BCL 和两个 CLR：CoreCLR 针对服务器或桌面场景（如网站和 Windows 桌面应用）进行了优化，而 Mono 运行时则针对资源有限的移动和 Web 浏览器应用进行了优化。

即使在现在，为.NET Framework 创建的应用和网站仍需得到支持，因此理解您可以创建向后兼容旧.NET 平台的.NET Standard 2.0 类库这一点很重要。

## .NET 平台和工具在本书各版中的使用情况

对于本书的第一版，写于 2016 年 3 月，我专注于.NET Core 功能，但在.NET Core 尚未实现重要或有用特性时使用.NET Framework，因为那时.NET Core 1.0 的最终版本还未发布。大多数示例使用 Visual Studio 2015，而 Visual Studio Code 仅简短展示。

第二版几乎完全清除了所有.NET Framework 代码示例，以便读者能够专注于真正跨平台的.NET Core 示例。

第三版完成了转换。它被重写，使得所有代码都是纯.NET Core。但为所有任务同时提供 Visual Studio Code 和 Visual Studio 2017 的逐步指导增加了复杂性。

第四版延续了这一趋势，除了最后两章外，所有代码示例都仅使用 Visual Studio Code 展示。在*第二十章*，*构建 Windows 桌面应用*中，使用了运行在 Windows 10 上的 Visual Studio，而在*第二十一章*，*构建跨平台移动应用*中，使用了 Mac 版的 Visual Studio。

在第五版中，*第二十章*，*构建 Windows 桌面应用*，被移至*附录 B*，以便为新的*第二十章*，*使用 Blazor 构建 Web 用户界面*腾出空间。Blazor 项目可以使用 Visual Studio Code 创建。

在本第六版中，*第十九章*，*使用.NET MAUI 构建移动和桌面应用*，更新了内容，展示了如何使用 Visual Studio 2022 和**.NET MAUI**（**多平台应用 UI**）创建移动和桌面跨平台应用。

到了第七版及.NET 7 发布时，Visual Studio Code 将有一个扩展来支持.NET MAUI。届时，读者将能够使用 Visual Studio Code 来运行本书中的所有示例。

## 理解中间语言

C#编译器（名为**Roslyn**），由`dotnet` CLI 工具使用，将您的 C#源代码转换成**中间语言**（**IL**）代码，并将 IL 存储在**程序集**（DLL 或 EXE 文件）中。IL 代码语句类似于汇编语言指令，由.NET 的虚拟机 CoreCLR 执行。

在运行时，CoreCLR 从程序集中加载 IL 代码，**即时**（**JIT**）编译器将其编译成原生 CPU 指令，然后由您机器上的 CPU 执行。

这种两步编译过程的好处是微软可以为 Linux 和 macOS 以及 Windows 创建 CLR。由于第二步编译，相同的 IL 代码在所有地方运行，该步骤为本地操作系统和 CPU 指令集生成代码。

无论源代码是用哪种语言编写的，例如 C#、Visual Basic 或 F#，所有.NET 应用程序都使用 IL 代码作为其指令存储在程序集中。微软和其他公司提供了反编译工具，可以打开程序集并显示此 IL 代码，例如 ILSpy .NET 反编译器扩展。

## 比较.NET 技术

我们可以总结并比较当今的.NET 技术，如下表所示：

| 技术 | 描述 | 宿主操作系统 |
| --- | --- | --- |
| 现代.NET | 现代功能集，完全支持 C# 8、9 和 10，用于移植现有应用或创建新的桌面、移动和 Web 应用及服务 | Windows、macOS、Linux、Android、iOS |
| .NET Framework | 遗留功能集，有限的 C# 8 支持，不支持 C# 9 或 10，仅用于维护现有应用 | 仅限 Windows |
| Xamarin | 仅限移动和桌面应用 | Android、iOS、macOS |

# 使用 Visual Studio 2022 构建控制台应用

本节的目标是展示如何使用 Visual Studio 2022 为 Windows 构建控制台应用。

如果你没有 Windows 电脑或者你想使用 Visual Studio Code，那么你可以跳过这一节，因为代码将保持不变，只是工具体验不同。

## 使用 Visual Studio 2022 管理多个项目

Visual Studio 2022 有一个名为**解决方案**的概念，允许你同时打开和管理多个项目。我们将使用一个解决方案来管理你将在本章中创建的两个项目。

## 使用 Visual Studio 2022 编写代码

让我们开始编写代码吧！

1.  启动 Visual Studio 2022。

1.  在启动窗口中，点击**创建新项目**。

1.  在**创建新项目**对话框中，在**搜索模板**框中输入`console`，并选择**控制台应用程序**，确保你选择了 C#项目模板而不是其他语言，如 F#或 Visual Basic，如*图 1.3*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_05.png)

    *图 1.3*：选择控制台应用程序项目模板

1.  点击**下一步**。

1.  在**配置新项目**对话框中，为项目名称输入`HelloCS`，为位置输入`C:\Code`，为解决方案名称输入`Chapter01`，如*图 1.4*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_06.png)

    *图 1.4*：为你的新项目配置名称和位置

1.  点击**下一步**。

    我们故意使用.NET 5.0 的旧项目模板来查看完整的控制台应用程序是什么样的。在下一节中，你将使用.NET 6.0 创建一个控制台应用程序，并查看有哪些变化。

1.  在**附加信息**对话框中，在**目标框架**下拉列表中，注意当前和长期支持版本的.NET 的选项，然后选择**.NET 5.0（当前）**并点击**创建**。

1.  在**解决方案资源管理器**中，双击打开名为`Program.cs`的文件，并注意**解决方案资源管理器**显示了**HelloCS**项目，如图*1.5*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_07.png)

    图 1.5：在 Visual Studio 2022 中编辑 Program.cs

1.  在`Program.cs`中，修改第 9 行，使得写入控制台的文本显示为`Hello, C#!`

## 使用 Visual Studio 编译和运行代码

接下来的任务是编译和运行代码。

1.  在 Visual Studio 中，导航到**调试** | **开始不调试**。

1.  控制台窗口的输出将显示应用程序运行的结果，如图*1.6*所示：![图形用户界面，文本，应用程序 自动生成描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_08.png)

    图 1.6：在 Windows 上运行控制台应用程序

1.  按任意键关闭控制台窗口并返回 Visual Studio。

1.  选择**HelloCS**项目，然后在**解决方案资源管理器**工具栏上，切换**显示所有文件**按钮，并注意编译器生成的`bin`和`obj`文件夹可见，如图*1.7*所示：![图形用户界面，文本，应用程序，电子邮件 自动生成描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_09.png)

    图 1.7：显示编译器生成的文件夹和文件

### 理解编译器生成的文件夹和文件

编译器生成了两个文件夹，名为`obj`和`bin`。您无需查看这些文件夹或理解其中的文件。只需知道编译器需要创建临时文件夹和文件来完成其工作。您可以删除这些文件夹及其文件，它们稍后可以重新创建。开发者经常这样做来“清理”项目。Visual Studio 甚至在**构建**菜单上有一个名为**清理解决方案**的命令，用于删除其中一些临时文件。Visual Studio Code 中的等效命令是`dotnet clean`。

+   `obj`文件夹包含每个源代码文件的一个编译*对象*文件。这些对象尚未链接成最终的可执行文件。

+   `bin`文件夹包含应用程序或类库的*二进制*可执行文件。我们将在*第七章*，*打包和分发.NET 类型*中更详细地探讨这一点。

## 编写顶级程序

您可能会认为，仅仅为了输出`Hello, C#!`就写了这么多代码。

虽然样板代码由项目模板为您编写，但有没有更简单的方法呢？

嗯，在 C# 9 或更高版本中，确实有，它被称为**顶级程序**。

让我们比较一下项目模板创建的控制台应用程序，如下所示：

```cs
using System;
namespace HelloCS
{
  class Program
  {
    static void Main(string[] args)
    {
      Console.WriteLine("Hello World!");
    }
  }
} 
```

对于新的顶级程序最小控制台应用程序，如下所示：

```cs
using System;
Console.WriteLine("Hello World!"); 
```

这简单多了，对吧？如果您必须从一个空白文件开始并自己编写所有语句，这是更好的。但它是如何工作的呢？

在编译期间，所有定义命名空间、`Program`类及其`Main`方法的样板代码都会生成并围绕你编写的语句进行包装。

关于顶层程序的关键点包括以下列表：

+   任何`using`语句仍必须位于文件顶部。

+   一个项目中只能有一个这样的文件。

`using System;`语句位于文件顶部，导入了`System`命名空间。这使得`Console.WriteLine`语句能够工作。你将在下一章了解更多关于命名空间的内容。

## 使用 Visual Studio 2022 添加第二个项目

让我们向解决方案中添加第二个项目以探索顶层程序：

1.  在 Visual Studio 中，导航至**文件** | **添加** | **新项目**。

1.  在**添加新项目**对话框中，在**最近的项目模板**里，选择**控制台应用程序[C#]**，然后点击**下一步**。

1.  在**配置新项目**对话框中，对于**项目名称**，输入`TopLevelProgram`，保持位置为`C:\Code\Chapter01`，然后点击**下一步**。

1.  在**附加信息**对话框中，选择**.NET 6.0（长期支持）**，然后点击**创建**。

1.  在**解决方案资源管理器**中，在`TopLevelProgram`项目里，双击`Program.cs`以打开它。

1.  在`Program.cs`中，注意代码仅由一个注释和一个语句组成，因为它使用了 C# 9 引入的顶层程序特性，如下所示：

    ```cs
    // See https://aka.ms/new-console-template for more information
    Console.WriteLine("Hello, World!"); 
    ```

但当我之前介绍顶层程序概念时，我们需要一个`using System;`语句。为什么这里不需要呢？

### 隐式导入的命名空间

诀窍在于我们仍然需要导入`System`命名空间，但现在它通过 C# 10 引入的特性为我们完成了。让我们看看是如何实现的：

1.  在**解决方案资源管理器**中，选择`TopLevelProgram`项目并启用**显示所有文件**按钮，注意编译器生成的`bin`和`obj`文件夹可见。

1.  展开`obj`文件夹，再展开`Debug`文件夹，接着展开`net6.0`文件夹，并打开名为`TopLevelProgram.GlobalUsings.g.cs`的文件。

1.  请注意，此文件是由针对.NET 6 的项目编译器自动创建的，并且它使用了 C# 10 引入的**全局导入**特性，该特性导入了一些常用命名空间，如`System`，以便在所有代码文件中使用，如下所示：

    ```cs
    // <autogenerated />
    global using global::System;
    global using global::System.Collections.Generic;
    global using global::System.IO;
    global using global::System.Linq;
    global using global::System.Net.Http;
    global using global::System.Threading;
    global using global::System.Threading.Tasks; 
    ```

    我将在下一章详细解释这一特性。目前，只需注意.NET 5 和.NET 6 之间的一个显著变化是，许多项目模板，如控制台应用程序的模板，使用新的语言特性来隐藏实际发生的事情。

1.  在`TopLevelProgram`项目中，在`Program.cs`里，修改语句以输出不同的消息和操作系统版本，如下所示：

    ```cs
    Console.WriteLine("Hello from a Top Level Program!");
    Console.WriteLine(Environment.OSVersion.VersionString); 
    ```

1.  在**解决方案资源管理器**中，右键点击**Chapter01**解决方案，选择**设置启动项目…**，设置**当前选择**，然后点击**确定**。

1.  在**解决方案资源管理器**中，点击**TopLevelProgram**项目（或其中的任何文件或文件夹），并注意 Visual Studio 通过将项目名称加粗来指示**TopLevelProgram**现在是启动项目。

1.  导航至**调试** | **启动但不调试**以运行**TopLevelProgram**项目，并注意结果，如图*1.8*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_10.png)

    图 1.8：在 Windows 上的 Visual Studio 解决方案中运行顶级程序，该解决方案包含两个项目

# 使用 Visual Studio Code 构建控制台应用

本节的目标是展示如何使用 Visual Studio Code 构建控制台应用。

如果你不想尝试 Visual Studio Code 或.NET Interactive Notebooks，那么请随意跳过本节和下一节，然后继续阅读*审查项目文件夹和文件*部分。

本节中的说明和截图适用于 Windows，但相同的操作在 macOS 和 Linux 上的 Visual Studio Code 中同样适用。

主要区别在于原生命令行操作，例如删除文件：命令和路径在 Windows、macOS 和 Linux 上可能不同。幸运的是，`dotnet`命令行工具在所有平台上都是相同的。

## 使用 Visual Studio Code 管理多个项目

Visual Studio Code 有一个名为**工作区**的概念，允许你同时打开和管理多个项目。我们将使用工作区来管理本章中你将创建的两个项目。

## 使用 Visual Studio Code 编写代码

让我们开始编写代码吧！

1.  启动 Visual Studio Code。

1.  确保没有打开任何文件、文件夹或工作区。

1.  导航至**文件** | **将工作区另存为…**。

1.  在对话框中，导航至 macOS 上的用户文件夹（我的名为`markjprice`），Windows 上的`文档`文件夹，或你希望保存项目的任何目录或驱动器。

1.  点击**新建文件夹**按钮并命名文件夹为`Code`。（如果你完成了 Visual Studio 2022 部分，则此文件夹已存在。）

1.  在`Code`文件夹中，创建一个名为`Chapter01-vscode`的新文件夹。

1.  在`Chapter01-vscode`文件夹中，将工作区保存为`Chapter01.code-workspace`。

1.  导航至**文件** | **向工作区添加文件夹…**或点击**添加文件夹**按钮。

1.  在`Chapter01-vscode`文件夹中，创建一个名为`HelloCS`的新文件夹。

1.  选择`HelloCS`文件夹并点击**添加**按钮。

1.  导航至**视图** | **终端**。

    我们特意使用较旧的.NET 5.0 项目模板来查看完整的控制台应用程序是什么样的。在下一节中，你将使用.NET 6.0 创建控制台应用程序，并查看发生了哪些变化。

1.  在**终端**中，确保你位于`HelloCS`文件夹中，然后使用`dotnet`命令行工具创建一个新的面向.NET 5.0 的控制台应用，如以下命令所示：

    ```cs
    dotnet new console -f net5.0 
    ```

1.  你将看到`dotnet`命令行工具在当前文件夹中为你创建一个新的**控制台应用程序**项目，并且**资源管理器**窗口显示创建的两个文件`HelloCS.csproj`和`Program.cs`，以及`obj`文件夹，如图 1.9 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_12.png)

    图 1.9：资源管理器窗口将显示已创建两个文件和一个文件夹

1.  在**资源管理器**中，点击名为`Program.cs`的文件以在编辑器窗口中打开它。首次执行此操作时，如果 Visual Studio Code 未在安装 C#扩展时下载并安装 C#依赖项（如 OmniSharp、.NET Core 调试器和 Razor 语言服务器），或者它们需要更新，则可能需要下载并安装。Visual Studio Code 将在**输出**窗口中显示进度，并最终显示消息`完成`，如下所示：

    ```cs
    Installing C# dependencies...
    Platform: win32, x86_64
    Downloading package 'OmniSharp for Windows (.NET 4.6 / x64)' (36150 KB).................... Done!
    Validating download...
    Integrity Check succeeded.
    Installing package 'OmniSharp for Windows (.NET 4.6 / x64)'
    Downloading package '.NET Core Debugger (Windows / x64)' (45048 KB).................... Done!
    Validating download...
    Integrity Check succeeded.
    Installing package '.NET Core Debugger (Windows / x64)'
    Downloading package 'Razor Language Server (Windows / x64)' (52344 KB).................... Done!
    Installing package 'Razor Language Server (Windows / x64)'
    Finished 
    ```

    上述输出来自 Windows 上的 Visual Studio Code。在 macOS 或 Linux 上运行时，输出会略有不同，但会为你的操作系统下载并安装相应的组件。

1.  名为`obj`和`bin`的文件夹将被创建，当你看到提示说缺少必需的资源时，请点击**是**，如图 1.10 所示：![图形用户界面，文本，应用程序，电子邮件 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_13.png)

    图 1.10：添加所需构建和调试资产的警告信息

1.  如果通知在你能与之交互之前消失，则可以点击状态栏最右侧的铃铛图标再次显示它。

1.  几秒钟后，将创建另一个名为`.vscode`的文件夹，其中包含一些文件，这些文件由 Visual Studio Code 用于在调试期间提供功能，如 IntelliSense，你将在*第四章*，*编写、调试和测试函数*中了解更多信息。

1.  在`Program.cs`中，修改第 9 行，使得写入控制台的文本为`Hello, C#!`

    **最佳实践**：导航至**文件** | **自动保存**。此切换将省去每次重建应用程序前记得保存的烦恼。

## 使用 dotnet CLI 编译和运行代码

接下来的任务是编译和运行代码：

1.  导航至**视图** | **终端**并输入以下命令：

    ```cs
    dotnet run 
    ```

1.  在**终端**窗口中的输出将显示运行你的应用程序的结果，如图 1.11 所示：![图形用户界面，文本，应用程序，电子邮件 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_14.png)

图 1.11：运行你的第一个控制台应用程序的输出

## 使用 Visual Studio Code 添加第二个项目

让我们向工作区添加第二个项目以探索顶级程序：

1.  在 Visual Studio Code 中，导航至**文件** | **将文件夹添加到工作区…**。

1.  在`Chapter01-vscode`文件夹中，使用**新建文件夹**按钮创建一个名为`TopLevelProgram`的新文件夹，选中它，然后点击**添加**。

1.  导航至 **Terminal** | **New Terminal**，并在出现的下拉列表中选择 **TopLevelProgram**。或者，在 **EXPLORER** 中，右键点击 `TopLevelProgram` 文件夹，然后选择 **Open in Integrated Terminal**。

1.  在 **TERMINAL** 中，确认你位于 `TopLevelProgram` 文件夹中，然后输入创建新控制台应用程序的命令，如下所示：

    ```cs
    dotnet new console 
    ```

    **最佳实践**：在使用工作区时，在 **TERMINAL** 中输入命令时要小心。确保你位于正确的文件夹中，再输入可能具有破坏性的命令！这就是为什么我在发出创建新控制台应用的命令之前，让你为 `TopLevelProgram` 创建一个新终端的原因。

1.  导航至 **View** | **Command Palette**。

1.  输入 `omni`，然后在出现的下拉列表中选择 **OmniSharp: Select Project**。

1.  在两个项目的下拉列表中，选择 **TopLevelProgram** 项目，并在提示时点击 **Yes** 以添加调试所需的资产。

    **最佳实践**：为了启用调试和其他有用的功能，如代码格式化和“转到定义”，你必须告诉 OmniSharp 你在 Visual Studio Code 中正在积极处理哪个项目。你可以通过点击状态栏左侧火焰图标右侧的项目/文件夹快速切换活动项目。

1.  在 **EXPLORER** 中，在 `TopLevelProgram` 文件夹中，选择 `Program.cs`，然后将现有语句更改为输出不同的消息并输出操作系统版本字符串，如下所示：

    ```cs
    Console.WriteLine("Hello from a Top Level Program!");
    Console.WriteLine(Environment.OSVersion.VersionString); 
    ```

1.  在 **TERMINAL** 中，输入运行程序的命令，如下所示：

    ```cs
    dotnet run 
    ```

1.  注意 **TERMINAL** 窗口中的输出，如图 *1.12* 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_15.png)

    图 1.12：在 Windows 上的 Visual Studio Code 工作区中运行顶级程序，该工作区包含两个项目

如果你要在 macOS Big Sur 上运行该程序，环境操作系统将有所不同，如下所示：

```cs
Hello from a Top Level Program!
Unix 11.2.3 
```

## 使用 Visual Studio Code 管理多个文件

如果你有多个文件需要同时处理，那么你可以将它们并排编辑：

1.  在 **EXPLORER** 中展开两个项目。

1.  打开两个项目中的 `Program.cs` 文件。

1.  点击、按住并拖动其中一个打开文件的编辑窗口标签，以便你可以同时看到两个文件。

# 使用 .NET Interactive Notebooks 探索代码

.NET Interactive Notebooks 使得编写代码比顶级程序更加简便。它需要 Visual Studio Code，因此如果你之前未安装，请现在安装。

## 创建笔记本

首先，我们需要创建一个笔记本：

1.  在 Visual Studio Code 中，关闭任何已打开的工作区或文件夹。

1.  导航至 **View** | **Command Palette**。

1.  输入 `.net inter`，然后选择 **.NET Interactive: Create new blank notebook**，如图 *1.13* 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_16.png)

    图 1.13：创建一个新的空白 .NET 笔记本

1.  当提示选择文件扩展名时，选择 **创建为 '.dib'**。

    `.dib` 是微软定义的一种实验性文件格式，旨在避免与 Python 交互式笔记本使用的 `.ipynb` 格式产生混淆和兼容性问题。文件扩展名历史上仅用于可以包含数据、Python 代码（PY）和输出混合的 Jupyter 笔记本文件（NB）。随着 .NET 交互式笔记本的出现，这一概念已扩展到允许混合使用 C#、F#、SQL、HTML、JavaScript、Markdown 和其他语言。`.dib` 是多语言兼容的，意味着它支持混合语言。支持 `.dib` 和 `.ipynb` 文件格式之间的转换。

1.  为笔记本中的代码单元格选择默认语言**C#**。

1.  如果可用的 .NET 交互式版本更新，您可能需要等待它卸载旧版本并安装新版本。导航至**视图** | **输出**，并在下拉列表中选择 **.NET 交互式 : 诊断**。请耐心等待。笔记本可能需要几分钟才能出现，因为它必须启动一个托管 .NET 的环境。如果几分钟后没有任何反应，请关闭 Visual Studio Code 并重新启动它。

1.  一旦 .NET 交互式笔记本扩展下载并安装完成，**输出**窗口的诊断将显示内核进程已启动（您的进程和端口号将与下面的输出不同），如下面的输出所示，已编辑以节省空间：

    ```cs
    Extension started for VS Code Stable.
    ...
    Kernel process 12516 Port 59565 is using tunnel uri http://localhost:59565/ 
    ```

## 在笔记本中编写和运行代码

接下来，我们可以在笔记本单元格中编写代码：

1.  第一个单元格应已设置为 **C# (.NET 交互式)**，但如果设置为其他任何内容，请点击代码单元格右下角的语言选择器，然后选择 **C# (.NET 交互式)** 作为该单元格的语言模式，并注意代码单元格的其他语言选择，如图 *1.14* 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_17.png)

    图 1.14：在 .NET 交互式笔记本中更改代码单元格的语言

1.  在 **C# (.NET 交互式)** 代码单元格中，输入一条输出消息到控制台的语句，并注意您不需要像在完整应用程序中那样在语句末尾加上分号，如下面的代码所示：

    ```cs
    Console.WriteLine("Hello, .NET Interactive!") 
    ```

1.  点击代码单元格左侧的 **执行单元格** 按钮，并注意代码单元格下方灰色框中出现的输出，如图 *1.15* 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_18.png)

    图 1.15：在笔记本中运行代码并在下方看到输出

## 保存笔记本

与其他文件一样，我们应该在继续之前保存笔记本：

1.  导航至**文件** | **另存为…**。

1.  切换到 `Chapter01-vscode` 文件夹，并将笔记本保存为 `Chapter01.dib`。

1.  关闭 `Chapter01.dib` 编辑器标签页。

## 向笔记本添加 Markdown 和特殊命令

我们可以混合使用包含 Markdown 和代码的单元格，并使用特殊命令：

1.  导航至**文件** | **打开文件…**，并选择 `Chapter01.dib` 文件。

1.  如果提示`您信任这些文件的作者吗？`，点击**打开**。

1.  将鼠标悬停在代码块上方并点击**+标记**以添加 Markdown 单元格。

1.  输入一级标题，如下所示的 Markdown：

    ```cs
    # Chapter 1 - Hello, C#! Welcome, .NET!
    Mixing *rich* **text** and code is cool! 
    ```

1.  点击单元格右上角的勾选标记以停止编辑单元格并查看处理后的 Markdown。

    如果单元格顺序错误，可以拖放以重新排列。

1.  在 Markdown 单元格和代码单元格之间悬停并点击**+代码**。

1.  输入特殊命令以输出.NET Interactive 的版本信息，如下所示：

    ```cs
    #!about 
    ```

1.  点击**执行单元格**按钮并注意输出，如*图 1.16*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_19.png)

    *图 1.16*：在.NET Interactive 笔记本中混合 Markdown、代码和特殊命令

## 在多个单元格中执行代码

当笔记本中有多个代码单元格时，必须在后续代码单元格的上下文可用之前执行前面的代码单元格：

1.  在笔记本底部，添加一个新的代码单元格，然后输入一个语句以声明变量并赋值整数值，如下所示：

    ```cs
    int number = 8; 
    ```

1.  在笔记本底部，添加一个新的代码单元格，然后输入一个语句以输出`number`变量，如下所示：

    ```cs
    Console.WriteLine(number); 
    ```

1.  注意第二个代码单元格不知道`number`变量，因为它是在另一个代码单元格（即上下文）中定义和赋值的，如*图 1.17*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_20.png)

    *图 1.17*：当前单元格或上下文中不存在`number`变量

1.  在第一个单元格中，点击**执行单元格**按钮声明并赋值给变量，然后在第二个单元格中，点击**执行单元格**按钮输出`number`变量，并注意这有效。（或者，在第一个单元格中，你可以点击**执行当前及以下单元格**按钮。）

    **最佳实践**：如果相关代码分布在两个单元格中，请记住在执行后续单元格之前执行前面的单元格。在笔记本顶部，有以下按钮 – **清除输出**和**全部运行**。这些非常方便，因为你可以点击一个，然后另一个，以确保所有代码单元格都按正确顺序执行。

## 本书代码使用.NET Interactive Notebooks

在其余章节中，我将不会给出使用笔记本的具体说明，但本书的 GitHub 仓库在适当时候提供了解决方案笔记本。我预计许多读者会希望运行我预先创建的笔记本，以查看*第二章*至*第十二章*中涵盖的语言和库特性，并学习它们，而无需编写完整的应用程序，即使只是一个控制台应用：

[`github.com/markjprice/cs10dotnet6/tree/main/notebooks`](https://github.com/markjprice/cs10dotnet6/tree/main/notebooks)

# 查看项目文件夹和文件

本章中，你创建了两个名为`HelloCS`和`TopLevelProgram`的项目。

Visual Studio Code 使用工作区文件管理多个项目。Visual Studio 2022 使用解决方案文件管理多个项目。你还创建了一个.NET Interactive 笔记本。

结果是一个文件夹结构和文件，将在后续章节中重复出现，尽管不仅仅是两个项目，如图*1.18*所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_21.png)

图 1.18：本章中两个项目的文件夹结构和文件

## 理解常见文件夹和文件

尽管`.code-workspace`和`.sln`文件不同，但项目文件夹和文件（如`HelloCS`和`TopLevelProgram`）对于 Visual Studio 2022 和 Visual Studio Code 是相同的。这意味着你可以根据喜好在这两个代码编辑器之间混合搭配：

+   在 Visual Studio 2022 中，打开解决方案后，导航至**文件** | **添加现有项目…**，以添加由另一工具创建的项目文件。

+   在 Visual Studio Code 中，打开工作区后，导航至**文件** | **向工作区添加文件夹…**，以添加由另一工具创建的项目文件夹。

    **最佳实践**：尽管源代码，如`.csproj`和`.cs`文件，是相同的，但由编译器自动生成的`bin`和`obj`文件夹可能存在版本不匹配，导致错误。如果你想在 Visual Studio 2022 和 Visual Studio Code 中打开同一项目，请在另一个代码编辑器中打开项目之前删除临时的`bin`和`obj`文件夹。这就是为什么本章要求你为 Visual Studio Code 解决方案创建一个不同文件夹的原因。

## 理解 GitHub 上的解决方案代码

本书 GitHub 仓库中的解决方案代码包括为 Visual Studio Code、Visual Studio 2022 和.NET Interactive 笔记本文件设置的独立文件夹，如下所示：

+   Visual Studio 2022 解决方案：[`github.com/markjprice/cs10dotnet6/tree/main/vs4win`](https://github.com/markjprice/cs10dotnet6/tree/main/vs4win)

+   Visual Studio Code 解决方案：[`github.com/markjprice/cs10dotnet6/tree/main/vscode`](https://github.com/markjprice/cs10dotnet6/tree/main/vscode)

+   .NET Interactive 笔记本解决方案：[`github.com/markjprice/cs10dotnet6/tree/main/notebooks`](https://github.com/markjprice/cs10dotnet6/tree/main/notebooks)

    **最佳实践**：如有需要，请返回本章以提醒自己如何在所选代码编辑器中创建和管理多个项目。GitHub 仓库提供了四个代码编辑器（Windows 版 Visual Studio 2022、Visual Studio Code、Mac 版 Visual Studio 2022 和 JetBrains Rider）的详细步骤说明，以及额外的截图：[`github.com/markjprice/cs10dotnet6/blob/main/docs/code-editors/`](https://github.com/markjprice/cs10dotnet6/blob/main/docs/code-editors/)。

# 充分利用本书的 GitHub 仓库

Git 是一个常用的源代码管理系统。GitHub 是一家公司、网站和桌面应用程序，使其更易于管理 Git。微软于 2018 年收购了 GitHub，因此它将继续与微软工具实现更紧密的集成。

我为此书创建了一个 GitHub 仓库，用于以下目的：

+   存储本书的解决方案代码，以便在印刷出版日期之后进行维护。

+   提供扩展书籍的额外材料，如勘误修正、小改进、有用链接列表以及无法放入印刷书籍的长篇文章。

+   为读者提供一个与我联系的地方，如果他们在阅读本书时遇到问题。

## 提出关于本书的问题

如果您在遵循本书中的任何指令时遇到困难，或者您在文本或解决方案代码中发现错误，请在 GitHub 仓库中提出问题：

1.  使用您喜欢的浏览器导航至以下链接：[`github.com/markjprice/cs10dotnet6/issues`](https://github.com/markjprice/cs10dotnet6/issues)。

1.  点击**新建问题**。

1.  尽可能详细地提供有助于我诊断问题的信息。例如：

    1.  您的操作系统，例如，Windows 11 64 位，或 macOS Big Sur 版本 11.2.3。

    1.  您的硬件配置，例如，Intel、Apple Silicon 或 ARM CPU。

    1.  您的代码编辑器，例如，Visual Studio 2022、Visual Studio Code 或其他，包括版本号。

    1.  您认为相关且必要的尽可能多的代码和配置。

    1.  描述预期的行为和实际体验到的行为。

    1.  截图（如有可能）。

撰写这本书对我来说是一项副业。我有一份全职工作，所以主要在周末编写这本书。这意味着我不能总是立即回复问题。但我希望所有读者都能通过我的书取得成功，所以如果我能不太麻烦地帮助您（和其他人），我会很乐意这么做。

## 给我反馈

如果您想就本书提供更一般的反馈，GitHub 仓库的`README.md`页面有一些调查链接。您可以匿名提供反馈，或者如果您希望得到我的回复，可以提供电子邮件地址。我将仅使用此电子邮件地址来回复您的反馈。

我喜欢听到读者对我书籍的喜爱之处，以及改进建议和他们如何使用 C#和.NET，所以请不要害羞。请与我联系！

提前感谢您深思熟虑且建设性的反馈。

## 从 GitHub 仓库下载解决方案代码

我使用 GitHub 存储所有章节中涉及的动手实践编码示例的解决方案，以及每章末尾的实际练习。您可以在以下链接找到仓库：[`github.com/markjprice/cs10dotnet6`](https://github.com/markjprice/cs10dotnet6)。

如果你只想下载所有解决方案文件而不使用 Git，点击绿色的**代码**按钮，然后选择**下载 ZIP**，如*图 1.19*所示：

![表 自动生成描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_22.png)

图 1.19：将仓库下载为 ZIP 文件

我建议你将上述链接添加到你的收藏夹书签中，因为我也会使用本书的 GitHub 仓库发布勘误（更正）和其他有用链接。

## 使用 Git 与 Visual Studio Code 和命令行

Visual Studio Code 支持 Git，但它将使用你的操作系统上的 Git 安装，因此你必须先安装 Git 2.0 或更高版本才能使用这些功能。

你可以从以下链接安装 Git：[`git-scm.com/download`](https://git-scm.com/download)。

如果你喜欢使用图形界面，可以从以下链接下载 GitHub Desktop：[`desktop.github.com`](https://desktop.github.com)。

### 克隆本书解决方案代码仓库

让我们克隆本书解决方案代码仓库。在接下来的步骤中，你将使用 Visual Studio Code 终端，但你也可以在任何命令提示符或终端窗口中输入这些命令：

1.  在你的用户目录或`文档`目录下，或者你想存放 Git 仓库的任何地方，创建一个名为`Repos-vscode`的文件夹。

1.  在 Visual Studio Code 中，打开`Repos-vscode`文件夹。

1.  导航至**视图** | **终端**，并输入以下命令：

    ```cs
    git clone https://github.com/markjprice/cs10dotnet6.git 
    ```

1.  请注意，克隆所有章节的解决方案文件需要大约一分钟，如*图 1.20*所示：![图形用户界面，文本，应用程序，电子邮件 自动生成描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_23.png)

    图 1.20：使用 Visual Studio Code 克隆本书解决方案代码

# 寻求帮助

本节将介绍如何在网络上找到关于编程的高质量信息。

## 阅读微软文档

获取微软开发者工具和平台帮助的权威资源是微软文档，你可以在以下链接找到它：[`docs.microsoft.com/`](https://docs.microsoft.com/)。

## 获取 dotnet 工具的帮助

在命令行中，你可以向`dotnet`工具请求其命令的帮助：

1.  要在浏览器窗口中打开`dotnet new`命令的官方文档，在命令行或 Visual Studio Code 终端中输入以下内容：

    ```cs
    dotnet help new 
    ```

1.  要在命令行获取帮助输出，使用`-h`或`--help`标志，如下所示：

    ```cs
    dotnet new console -h 
    ```

1.  你将看到以下部分输出：

    ```cs
    Console Application (C#)
    Author: Microsoft
    Description: A project for creating a command-line application that can run on .NET Core on Windows, Linux and macOS
    Options:
      -f|--framework. The target framework for the project.
                          net6.0           - Target net6.0
                          net5.0           - Target net5.0
                          netcoreapp3.1\.   - Target netcoreapp3.1
                          netcoreapp3.0\.   - Target netcoreapp3.0
                      Default: net6.0
    --langVersion    Sets langVersion in the created project file text – Optional 
    ```

## 获取类型及其成员的定义

代码编辑器最有用的功能之一是**转到定义**。它在 Visual Studio Code 和 Visual Studio 2022 中都可用。它将通过读取编译程序集中的元数据来显示类型或成员的公共定义。

一些工具，如 ILSpy .NET 反编译器，甚至能从元数据和 IL 代码反向工程回 C#代码。

让我们看看如何使用**转到定义**功能：

1.  在 Visual Studio 2022 或 Visual Studio Code 中，打开名为`Chapter01`的解决方案/工作区。

1.  在`HelloCS`项目中，在`Program.cs`中，在`Main`中，输入以下语句以声明名为`z`的整数变量：

    ```cs
    int z; 
    ```

1.  点击`int`内部，然后右键单击并选择**转到定义**。

1.  在出现的代码窗口中，你可以看到`int`数据类型是如何定义的，如图*1.21*所示：![图形用户界面，文本，应用程序 描述自动生成](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_24.png)

    图 1.21：int 数据类型元数据

    你可以看到`int`：

    +   使用`struct`关键字定义

    +   位于`System.Runtime`程序集中

    +   位于`System`命名空间中

    +   名为`Int32`

    +   因此是`System.Int32`类型的别名

    +   实现接口，如`IComparable`

    +   具有其最大和最小值的常量值

    +   具有诸如`Parse`等方法

    **良好实践**：当你尝试在 Visual Studio Code 中使用**转到定义**功能时，有时会看到错误提示**未找到定义**。这是因为 C#扩展不了解当前项目。要解决此问题，请导航至**视图** | **命令面板**，输入`omni`，选择**OmniSharp: 选择项目**，然后选择你想要工作的项目。

    目前，**转到定义**功能对你来说并不那么有用，因为你还不完全了解这些信息意味着什么。

    在本书的第一部分结束时，即*第二章*至*第六章*，教你关于 C#的内容，你将对此功能变得非常熟悉。

1.  在代码编辑器窗口中，向下滚动找到第 106 行带有单个`string`参数的`Parse`方法，以及第 86 至 105 行记录它的注释，如图*1.22*所示：![图形用户界面，文本，应用程序 描述自动生成](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_25.png)

    图 1.22：带有字符串参数的 Parse 方法的注释

在注释中，你会看到微软已经记录了以下内容：

+   描述该方法的摘要。

+   可以传递给该方法的参数，如`string`值。

+   方法的返回值，包括其数据类型。

+   如果你调用此方法，可能会发生的三种异常，包括`ArgumentNullException`、`FormatException`和`OverflowException`。现在我们知道，我们可以选择在`try`语句中包装对此方法的调用，并知道要捕获哪些异常。

希望你已经迫不及待想要了解这一切意味着什么！

再耐心等待一会儿。你即将完成本章，下一章你将深入探讨 C#语言的细节。但首先，让我们看看还可以在哪里寻求帮助。

## 在 Stack Overflow 上寻找答案

Stack Overflow 是最受欢迎的第三方网站，用于获取编程难题的答案。它如此受欢迎，以至于搜索引擎如 DuckDuckGo 有一种特殊方式来编写查询以搜索该站点：

1.  打开你最喜欢的网页浏览器。

1.  导航至[DuckDuckGo.com](https://duckduckgo.com/)，输入以下查询，并注意搜索结果，这些结果也显示在*图 1.23*中：

    ```cs
     !so securestring 
    ```

    ![图形用户界面，文本，应用程序 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_01_26.png)

    图 1.23：Stack Overflow 关于 securestring 的搜索结果

## 使用 Google 搜索答案

你可以使用 Google 的高级搜索选项来增加找到所需内容的可能性：

1.  导航至 Google。

1.  使用简单的 Google 查询搜索有关`垃圾收集`的信息，并注意你可能会在看到计算机科学中垃圾收集的维基百科定义之前，看到许多本地垃圾收集服务的广告。

1.  通过限制搜索到有用的网站，如 Stack Overflow，并移除我们可能不关心的语言，如 C++、Rust 和 Python，或明确添加 C#和.NET，如下面的搜索查询所示，来改进搜索：

    ```cs
    garbage collection site:stackoverflow.com +C# -Java 
    ```

## 订阅官方.NET 博客

为了跟上.NET 的最新动态，订阅官方.NET 博客是一个很好的选择，该博客由.NET 工程团队撰写，你可以在以下链接找到它：[`devblogs.microsoft.com/dotnet/`](https://devblogs.microsoft.com/dotnet/)。

## 观看 Scott Hanselman 的视频

Microsoft 的 Scott Hanselman 有一个关于计算机知识的优秀 YouTube 频道，这些知识他们没有教过你：[`computerstufftheydidntteachyou.com/`](http://computerstufftheydidntteachyou.com/)。

我向所有从事计算机工作的人推荐它。

# 实践和探索

现在让我们通过尝试回答一些问题，进行一些实践练习，并深入探讨本章涵盖的主题，来测试你的知识和理解。

## 练习 1.1 – 测试你的知识

尝试回答以下问题，记住虽然大多数答案可以在本章找到，但你应该进行一些在线研究或编写代码来回答其他问题：

1.  Visual Studio 2022 是否优于 Visual Studio Code？

1.  .NET 6 是否优于.NET Framework？

1.  什么是.NET 标准，为什么它仍然重要？

1.  为什么程序员可以使用不同的语言，例如 C#和 F#，来编写运行在.NET 上的应用程序？

1.  什么是.NET 控制台应用程序的入口点方法的名称，以及它应该如何声明？

1.  什么是顶级程序，以及如何访问命令行参数？

1.  在提示符下输入什么来构建并执行 C#源代码？

1.  使用.NET Interactive Notebooks 编写 C#代码有哪些好处？

1.  你会在哪里寻求 C#关键字的帮助？

1.  你会在哪里寻找常见编程问题的解决方案？

    *附录*，*测试你的知识问题的答案*，可从 GitHub 仓库的 README 中的链接下载：[`github.com/markjprice/cs10dotnet6`](https://github.com/markjprice/cs10dotnet6)。

## 练习 1.2 – 随处练习 C#

你不需要 Visual Studio Code，甚至不需要 Windows 或 Mac 版的 Visual Studio 2022 来编写 C#。你可以访问.NET Fiddle – [`dotnetfiddle.net/`](https://dotnetfiddle.net/) – 并开始在线编码。

## 练习 1.3 – 探索主题

书籍是一种精心策划的体验。我试图找到在印刷书籍中包含的主题的正确平衡。我在 GitHub 仓库中为本书所写的其他内容也可以找到。

我相信这本书涵盖了 C#和.NET 开发者应该具备或了解的所有基础知识和技能。一些较长的示例最好作为链接包含到微软文档或第三方文章作者的内容中。

使用以下页面上的链接，以了解更多关于本章涵盖的主题的详细信息：

[第一章 - 你好 C#，欢迎来到.NET](https://github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-1---hello-c-welcome-net)

# 总结

在本章中，我们：

+   设置你的开发环境。

+   讨论了现代.NET、.NET Core、.NET Framework、Xamarin 和.NET Standard 之间的相似之处和差异。

+   使用 Visual Studio Code 与.NET SDK 和 Windows 版的 Visual Studio 2022 创建了一些简单的控制台应用程序。

+   使用.NET Interactive Notebooks 执行代码片段以供学习。

+   学习了如何从 GitHub 仓库下载本书的解决方案代码。

+   而且，最重要的是，学会了如何寻求帮助。

在下一章中，你将学习如何“说”C#。


# 第二章：说 C#

本章全是关于 C#编程语言基础的。在这一章中，你将学习如何使用 C#的语法编写语句，并介绍一些你每天都会用到的常用词汇。此外，到本章结束时，你将自信地知道如何暂时存储和处理计算机内存中的信息。

本章涵盖以下主题：

+   介绍 C#语言

+   理解 C#语法和词汇

+   使用变量

+   深入探讨控制台应用程序

# 介绍 C#语言

本书的这一部分是关于 C#语言的——你每天用来编写应用程序源代码的语法和词汇。

编程语言与人类语言有许多相似之处，不同之处在于编程语言中，你可以创造自己的词汇，就像苏斯博士那样！

在 1950 年苏斯博士所著的《如果我经营动物园》一书中，他这样说道：

> "然后，只是为了展示给他们看，我将航行到卡特鲁，并带回一个伊特卡奇、一个普里普、一个普鲁，一个内克尔、一个书呆子和一个条纹薄棉布！"

## 理解语言版本和特性

本书的这一部分涵盖了 C#编程语言，主要面向初学者，因此涵盖了所有开发者需要了解的基础主题，从声明变量到存储数据，再到如何定义自己的自定义数据类型。

本书涵盖了 C#语言从 1.0 版本到最新 10.0 版本的所有特性。

如果你已经对旧版本的 C#有所了解，并且对最新版本中的新特性感到兴奋，我通过列出语言版本及其重要的新特性，以及学习它们的章节号和主题标题，使你更容易跳转。

### C# 1.0

C# 1.0 于 2002 年发布，包含了静态类型、面向对象现代语言的所有重要特性，正如您将在*第二章*至*第六章*中所见。

### C# 2.0

C# 2.0 于 2005 年发布，重点是使用泛型实现强类型化，以提高代码性能并减少类型错误，包括以下表格中列出的主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| 可空值类型 | 6 | 使值类型可空 |
| 泛型 | 6 | 通过泛型使类型更可重用 |

### C# 3.0

C# 3.0 于 2007 年发布，重点是启用声明式编码，包括**语言集成查询**（**LINQ**）及相关特性，如匿名类型和 lambda 表达式，包括以下表格中列出的主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| 隐式类型局部变量 | 2 | 推断局部变量的类型 |
| LINQ | 11 | *第十一章*，*使用 LINQ 查询和操作数据*中的所有主题 |

### C# 4.0

C# 4.0 于 2010 年发布，专注于提高与 F#和 Python 等动态语言的互操作性，包括下表所列主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| 动态类型 | 2 | 存储动态类型 |
| 命名/可选参数 | 5 | 可选参数和命名参数 |

### C# 5.0

C# 5.0 于 2012 年发布，专注于通过自动实现复杂的状态机来简化异步操作支持，同时编写看似同步的语句，包括下表所列主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| 简化的异步任务 | 12 | 理解异步和等待 |

### C# 6.0

C# 6.0 于 2015 年发布，专注于对语言进行小幅优化，包括下表所列主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| `static` 导入 | 2 | 简化控制台使用 |
| 内插字符串 | 2 | 向用户显示输出 |
| 表达式主体成员 | 5 | 定义只读属性 |

### C# 7.0

C# 7.0 于 2017 年 3 月发布，专注于添加元组和模式匹配等函数式语言特性，以及对语言进行小幅优化，包括下表所列主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| 二进制字面量和数字分隔符 | 2 | 存储整数 |
| 模式匹配 | 3 | 使用`if`语句进行模式匹配 |
| `out` 变量 | 5 | 控制参数传递方式 |
| 元组 | 5 | 使用元组组合多个值 |
| 局部函数 | 6 | 定义局部函数 |

### C# 7.1

C# 7.1 于 2017 年 8 月发布，专注于对语言进行小幅优化，包括下表所列主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| 默认字面量表达式 | 5 | 使用默认字面量设置字段 |
| 推断元组元素名称 | 5 | 推断元组名称 |
| `async` 主方法 | 12 | 提高控制台应用的响应性 |

### C# 7.2

C# 7.2 于 2017 年 11 月发布，专注于对语言进行小幅优化，包括下表所列主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| 数值字面量中的前导下划线 | 2 | 存储整数 |
| 非尾随命名参数 | 5 | 可选参数和命名参数 |
| `private protected` 访问修饰符 | 5 | 理解访问修饰符 |
| 可对元组类型进行`==`和`!=`测试 | 5 | 元组比较 |

### C# 7.3

C# 7.3 于 2018 年 5 月发布，专注于提高`ref`变量、指针和`stackalloc`的性能导向安全代码。这些特性对于大多数开发者来说较为高级且不常用，因此本书未涉及。

### C# 8

C# 8 于 2019 年 9 月发布，专注于与空处理相关的主要语言变更，包括下表所列主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| 可空引用类型 | 6 | 使引用类型可空 |
| 开关表达式 | 3 | 使用开关表达式简化`switch`语句 |
| 默认接口方法 | 6 | 理解默认接口方法 |

### C# 9

C# 9 于 2020 年 11 月发布，专注于记录类型、模式匹配的改进以及最小代码控制台应用，包括下表列出的主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| 最小代码控制台应用 | 1 | 顶层程序 |
| 目标类型的新 | 2 | 使用目标类型的新实例化对象 |
| 增强的模式匹配 | 5 | 对象的模式匹配 |
| 记录 | 5 | 使用记录 |

### C# 10

C# 10 于 2021 年 11 月发布，专注于减少常见场景中所需代码量的特性，包括下表列出的主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| 全局命名空间导入 | 2 | 导入命名空间 |
| 常量字符串字面量 | 2 | 使用插值字符串格式化 |
| 文件作用域命名空间 | 5 | 简化命名空间声明 |
| 必需属性 | 5 | 实例化时要求属性设置 |
| 记录结构 | 6 | 使用记录结构类型 |
| 空参数检查 | 6 | 方法参数中的空值检查 |

## 理解 C#标准

多年来，微软已向标准机构提交了几个版本的 C#，如下表所示：

| C#版本 | ECMA 标准 | ISO/IEC 标准 |
| --- | --- | --- |
| 1.0 | ECMA-334:2003 | ISO/IEC 23270:2003 |
| 2.0 | ECMA-334:2006 | ISO/IEC 23270:2006 |
| 5.0 | ECMA-334:2017 | ISO/IEC 23270:2018 |

C# 6 的标准仍处于草案阶段，而添加 C# 7 特性的工作正在推进中。微软于 2014 年将 C#开源。

目前，为了尽可能开放地进行 C#及相关技术的工作，有三个公开的 GitHub 仓库，如下表所示：

| 描述 | 链接 |
| --- | --- |
| C#语言设计 | [`github.com/dotnet/csharplang`](https://github.com/dotnet/csharplang) |
| 编译器实现 | [`github.com/dotnet/roslyn`](https://github.com/dotnet/roslyn) |
| 描述语言的标准 | [`github.com/dotnet/csharpstandard`](https://github.com/dotnet/csharpstandard) |

## 发现您的 C#编译器版本

.NET 语言编译器，包括 C#和 Visual Basic（也称为 Roslyn），以及一个独立的 F#编译器，作为.NET SDK 的一部分分发。要使用特定版本的 C#，您必须安装至少该版本的.NET SDK，如下表所示：

| .NET SDK | Roslyn 编译器 | 默认 C#语言 |
| --- | --- | --- |
| 1.0.4 | 2.0 - 2.2 | 7.0 |
| 1.1.4 | 2.3 - 2.4 | 7.1 |
| 2.1.2 | 2.6 - 2.7 | 7.2 |
| 2.1.200 | 2.8 - 2.10 | 7.3 |
| 3.0 | 3.0 - 3.4 | 8.0 |
| 5.0 | 3.8 | 9.0 |
| 6.0 | 3.9 - 3.10 | 10.0 |

当您创建类库时，可以选择面向.NET Standard 以及现代.NET 的版本。它们有默认的 C#语言版本，如下表所示：

| .NET Standard | C# |
| --- | --- |
| 2.0 | 7.3 |
| 2.1 | 8.0 |

### 如何输出 SDK 版本

让我们看看您可用的.NET SDK 和 C#语言编译器版本：

1.  在 macOS 上，启动 **终端**。在 Windows 上，启动 **命令提示符**。

1.  要确定您可用的.NET SDK 版本，请输入以下命令：

    ```cs
    dotnet --version 
    ```

1.  注意，撰写本文时的版本是 6.0.100，表明这是 SDK 的初始版本，尚未有任何错误修复或新功能，如下输出所示：

    ```cs
    6.0.100 
    ```

### 启用特定语言版本编译器

像 Visual Studio 和 `dotnet` 命令行接口这样的开发工具默认假设您想使用 C#语言编译器的最新主版本。在 C# 8.0 发布之前，C# 7.0 是默认使用的最新主版本。要使用 C#点版本（如 7.1、7.2 或 7.3）的改进，您必须在项目文件中添加 `<LangVersion>` 配置元素，如下所示：

```cs
<LangVersion>7.3</LangVersion> 
```

C# 10.0 随.NET 6.0 发布后，如果微软发布了 C# 10.1 编译器，并且您想使用其新语言特性，则必须在项目文件中添加配置元素，如下所示：

```cs
<LangVersion>10.1</LangVersion> 
```

以下表格展示了 `<LangVersion>` 的可能值：

| LangVersion | 描述 |
| --- | --- |
| 7, 7.1, 7.2, 7.38, 9, 10 | 输入特定版本号将使用已安装的该编译器。 |
| latestmajor | 使用最高的主版本号，例如，2019 年 8 月的 7.0，2019 年 10 月的 8.0，2020 年 11 月的 9.0，2021 年 11 月的 10.0。 |
| `latest` | 使用最高的主版本和次版本号，例如，2017 年的 7.2，2018 年的 7.3，2019 年的 8，以及 2022 年初可能的 10.1。 |
| `preview` | 使用可用的最高预览版本，例如，2021 年 7 月安装了.NET 6.0 Preview 6 的 10.0。 |

创建新项目后，您可以编辑 `.csproj` 文件并添加 `<LangVersion>` 元素，如下所示高亮显示：

```cs
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
 **<LangVersion>preview</LangVersion>**
  </PropertyGroup>
</Project> 
```

您的项目必须针对 `net6.0` 以使用 C# 10 的全部功能。

**良好实践**：如果您正在使用 Visual Studio Code 且尚未安装，请安装名为 **MSBuild 项目工具** 的 Visual Studio Code 扩展。这将为您在编辑 `.csproj` 文件时提供 IntelliSense，包括轻松添加带有适当值的 `<LangVersion>` 元素。

# 理解 C#语法和词汇

要学习简单的 C#语言特性，您可以使用.NET 交互式笔记本，这消除了创建任何类型应用程序的需要。

要学习其他一些 C#语言特性，您需要创建一个应用程序。最简单的应用程序类型是控制台应用程序。

让我们从 C#语法和词汇的基础开始。在本章中，您将创建多个控制台应用程序，每个都展示 C#语言的相关特性。

## 显示编译器版本

我们将首先编写显示编译器版本的代码：

1.  如果你已经完成了*第一章*，*你好，C#！欢迎，.NET！*，那么你将已经拥有一个`Code`文件夹。如果没有，那么你需要创建它。

1.  使用你喜欢的代码编辑器创建一个新的控制台应用，如下表所示：

    1.  项目模板：**控制台应用程序[C#]** / `console`

    1.  工作区/解决方案文件和文件夹：`Chapter02`

    1.  项目文件和文件夹：`Vocabulary`

        **最佳实践**：如果你忘记了如何操作，或者没有完成前一章，那么*第一章*，*你好，C#！欢迎，.NET！*中给出了创建包含多个项目的工作区/解决方案的分步说明。

1.  打开`Program.cs`文件，在注释下方，添加一个语句以显示 C#版本作为错误，如下面的代码所示：

    ```cs
    #error version 
    ```

1.  运行控制台应用程序：

    1.  在 Visual Studio Code 中，在终端输入命令`dotnet run`。

    1.  在 Visual Studio 中，导航到**调试** | **开始不调试**。当提示继续并运行上次成功的构建时，点击**否**。

1.  注意编译器版本和语言版本显示为编译器错误消息编号`CS8304`，如图 2.1 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_02_01.png)

    图 2.1：显示 C#语言版本的编译器错误

1.  在 Visual Studio Code 的**问题**窗口或 Visual Studio 的**错误列表**窗口中的错误消息显示`编译器版本：'4.0.0...'`，语言版本为`10.0`。

1.  注释掉导致错误的语句，如下面的代码所示：

    ```cs
    // #error version 
    ```

1.  注意编译器错误消息消失了。

## 理解 C#语法

C#的语法包括语句和块。要记录你的代码，你可以使用注释。

**最佳实践**：注释不应该是你唯一用来记录代码的方式。为变量和函数选择合理的名称、编写单元测试以及创建实际文档是其他记录代码的方式。

## 语句

在英语中，我们用句号表示句子的结束。一个句子可以由多个单词和短语组成，单词的顺序是语法的一部分。例如，在英语中，我们说“the black cat”。

形容词*black*位于名词*cat*之前。而法语语法则不同；形容词位于名词之后：“le chat noir”。重要的是要记住，顺序很重要。

C#使用分号表示**语句**的结束。一个语句可以由多个**变量**和**表达式**组成。例如，在以下语句中，`totalPrice`是一个变量，`subtotal + salesTax`是一个表达式：

```cs
var totalPrice = subtotal + salesTax; 
```

该表达式由一个名为`subtotal`的操作数、一个运算符`+`和另一个名为`salesTax`的操作数组成。操作数和运算符的顺序很重要。

## 注释

编写代码时，你可以使用双斜杠`//`添加注释来解释你的代码。通过插入`//`，编译器将忽略`//`之后的所有内容，直到该行结束，如下面的代码所示：

```cs
// sales tax must be added to the subtotal
var totalPrice = subtotal + salesTax; 
```

要编写多行注释，请在注释的开头使用`/*`，在结尾使用`*/`，如下列代码所示：

```cs
/*
This is a multi-line comment.
*/ 
```

**最佳实践**：设计良好的代码，包括具有良好命名参数的函数签名和类封装，可以一定程度上自我说明。当你发现自己需要在代码中添加过多注释和解释时，问问自己：我能否通过重写（即重构）这段代码，使其在不依赖长篇注释的情况下更易于理解？

您的代码编辑器具有命令，使得添加和删除注释字符更加容易，如下表所示：

+   **Windows 版 Visual Studio 2022**：导航至**编辑** | **高级** | **注释选择** 或 **取消注释选择**

+   **Visual Studio Code**：导航至**编辑** | **切换行注释** 或 **切换块注释**

    **最佳实践**：您通过在代码语句上方或后方添加描述性文本来**注释**代码。您通过在语句前或周围添加注释字符来**注释掉**代码，使其失效。**取消注释**意味着移除注释字符。

## 块

在英语中，我们通过换行来表示新段落的开始。C# 使用花括号`{ }`来表示**代码块**。

块以声明开始，用以指示定义的内容。例如，一个块可以定义包括命名空间、类、方法或`foreach`等语句在内的多种语言结构的开始和结束。

您将在本章及后续章节中了解更多关于命名空间、类和方法的知识，但现在简要介绍一些概念：

+   **命名空间**包含类等类型，用于将它们组合在一起。

+   **类**包含对象的成员，包括方法。

+   **方法**包含实现对象可执行动作的语句。

## 语句和块的示例

在面向 .NET 5.0 的控制台应用程序项目模板中，请注意，项目模板已为您编写了 C# 语法的示例。我已对语句和块添加了一些注释，如下列代码所示：

```cs
using System; // a semicolon indicates the end of a statement
namespace Basics
{ // an open brace indicates the start of a block
  class Program
  {
    static void Main(string[] args)
    {
      Console.WriteLine("Hello World!"); // a statement
    }
  }
} // a close brace indicates the end of a block 
```

## 理解 C# 词汇

C# 词汇由**关键字**、**符号字符**和**类型**组成。

本书中您将看到的一些预定义保留关键字包括`using`、`namespace`、`class`、`static`、`int`、`string`、`double`、`bool`、`if`、`switch`、`break`、`while`、`do`、`for`、`foreach`、`and`、`or`、`not`、`record`和`init`。

您将看到的一些符号字符包括`"`, `'`, `+`, `-`, `*`, `/`, `%`, `@`, 和 `$`。

还有其他只在特定上下文中具有特殊意义的上下文关键字。

然而，这仍然意味着 C# 语言中只有大约 100 个实际的关键字。

## 将编程语言与人类语言进行比较

英语有超过 25 万个不同的单词，那么 C#是如何仅用大约 100 个关键字就做到的呢？此外，如果 C#只有英语单词数量的 0.0416%，为什么它还这么难学呢？

人类语言和编程语言之间的一个关键区别是，开发者需要能够定义具有新含义的新“单词”。除了 C#语言中的大约 100 个关键字外，本书还将教你了解其他开发者定义的数十万个“单词”，同时你还将学习如何定义自己的“单词”。

世界各地的程序员都必须学习英语，因为大多数编程语言使用英语单词，如 namespace 和 class。有些编程语言使用其他人类语言，如阿拉伯语，但这些语言较为罕见。如果你对此感兴趣，这个 YouTube 视频展示了一种阿拉伯编程语言的演示：[`youtu.be/dkO8cdwf6v8`](https://youtu.be/dkO8cdwf6v8)。

## 更改 C#语法的颜色方案

默认情况下，Visual Studio Code 和 Visual Studio 将 C#关键字显示为蓝色，以便更容易与其他代码区分开来。这两个工具都允许您自定义颜色方案：

1.  在 Visual Studio Code 中，导航至**代码** | **首选项** | **颜色主题**（在 Windows 上的**文件**菜单中）。

1.  选择一个颜色主题。作为参考，我将使用**Light+（默认浅色）**颜色主题，以便截图在印刷书籍中看起来效果良好。

1.  在 Visual Studio 中，导航至**工具** | **选项**。

1.  在**选项**对话框中，选择**字体和颜色**，然后选择您希望自定义的显示项。

## 帮助编写正确的代码

像记事本这样的纯文本编辑器不会帮助你书写正确的英语。同样，记事本也不会帮助你编写正确的 C#代码。

Microsoft Word 可以通过用红色波浪线标记拼写错误来帮助你书写英语，例如 Word 会提示"icecream"应为 ice-cream 或 ice cream，并用蓝色波浪线标记语法错误，例如句子应以大写字母开头。

同样，Visual Studio Code 的 C#扩展程序和 Visual Studio 通过标记拼写错误（例如方法名应为`WriteLine`，其中 L 为大写）和语法错误（例如语句必须以分号结尾）来帮助你编写 C#代码。

C#扩展程序会不断监视你输入的内容，并通过用彩色波浪线标记问题来给予你反馈，类似于 Microsoft Word。

让我们看看它的实际应用：

1.  在`Program.cs`中，将`WriteLine`方法中的`L`改为小写。

1.  删除语句末尾的分号。

1.  在 Visual Studio Code 中，导航至**视图** | **问题**，或在 Visual Studio 中导航至**视图** | **错误列表**，并注意代码错误下方会出现红色波浪线，并且会显示详细信息，如*图 2.2*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_02_02.png)

    图 2.2：错误列表窗口显示两个编译错误

1.  修复这两个编码错误。

## 导入命名空间

`System`是一个命名空间，类似于类型的地址。为了精确地引用某人的位置，您可能会使用`Oxford.HighStreet.BobSmith`，这告诉我们需要在牛津市的高街上寻找一个名叫 Bob Smith 的人。

`System.Console.WriteLine`指示编译器在一个名为`Console`的类型中查找名为`WriteLine`的方法，该类型位于名为`System`的命名空间中。为了简化我们的代码，在.NET 6.0 之前的每个版本的**控制台应用程序**项目模板中，都会在代码文件顶部添加一个语句，告诉编译器始终在`System`命名空间中查找未带命名空间前缀的类型，如下列代码所示：

```cs
using System; // import the System namespace 
```

我们称之为*导入命名空间*。导入命名空间的效果是，该命名空间中的所有可用类型将无需输入命名空间前缀即可供您的程序使用，并在编写代码时在 IntelliSense 中可见。

.NET Interactive 笔记本会自动导入大多数命名空间。

### 隐式和全局导入命名空间

传统上，每个需要导入命名空间的`.cs`文件都必须以`using`语句开始导入那些命名空间。几乎所有`.cs`文件都需要命名空间，如`System`和`System.Linq`，因此每个`.cs`文件的前几行通常至少包含几个`using`语句，如下列代码所示：

```cs
using System;
using System.Linq;
using System.Collections.Generic; 
```

在使用 ASP.NET Core 创建网站和服务时，每个文件通常需要导入数十个命名空间。

C# 10 引入了一些简化导入命名空间的新特性。

首先，`global using`语句意味着您只需在一个`.cs`文件中导入一个命名空间，它将在所有`.cs`文件中可用。您可以将`global using`语句放在`Program.cs`文件中，但我建议为这些语句创建一个单独的文件，命名为类似`GlobalUsings.cs`或`GlobalNamespaces.cs`，如下列代码所示：

```cs
global using System;
global using System.Linq;
global using System.Collections.Generic; 
```

**最佳实践**：随着开发者逐渐习惯这一新的 C#特性，我预计该文件的一种命名约定将成为标准。

其次，任何面向.NET 6.0 的项目，因此使用 C# 10 编译器，会在`obj`文件夹中生成一个`.cs`文件，以隐式全局导入一些常见命名空间，如`System`。隐式导入的命名空间列表取决于您所针对的 SDK，如下表所示：

| SDK | 隐式导入的命名空间 |
| --- | --- |
| `Microsoft.NET.Sdk` | `System``System.Collections.Generic``System.IO``System.Linq``System.Net.Http``System.Threading``System.Threading.Tasks` |
| `Microsoft.NET.Sdk.Web` | 与`Microsoft.NET.Sdk`相同，并包括：`System.Net.Http.Json``Microsoft.AspNetCore.Builder``Microsoft.AspNetCore.Hosting``Microsoft.AspNetCore.Http``Microsoft.AspNetCore.Routing``Microsoft.Extensions.Configuration``Microsoft.Extensions.DependencyInjection``Microsoft.Extensions.Hosting``Microsoft.Extensions.Logging` |
| `Microsoft.NET.Sdk.Worker` | 与`Microsoft.NET.Sdk`相同，并包括：`Microsoft.Extensions.Configuration``Microsoft.Extensions.DependencyInjection``Microsoft.Extensions.Hosting``Microsoft.Extensions.Logging` |

让我们看看当前自动生成的隐式导入文件：

1.  在**解决方案资源管理器**中，选择`词汇`项目，打开**显示所有文件**按钮，并注意编译器生成的`bin`和`obj`文件夹可见。

1.  展开`obj`文件夹，展开`Debug`文件夹，展开`net6.0`文件夹，并打开名为`Vocabulary.GlobalUsings.g.cs`的文件。

1.  注意此文件是由编译器为面向.NET 6.0 的项目自动创建的，并且它导入一些常用命名空间，包括`System.Threading`，如下所示的代码：

    ```cs
    // <autogenerated />
    global using global::System;
    global using global::System.Collections.Generic;
    global using global::System.IO;
    global using global::System.Linq;
    global using global::System.Net.Http;
    global using global::System.Threading;
    global using global::System.Threading.Tasks; 
    ```

1.  关闭`Vocabulary.GlobalUsings.g.cs`文件。

1.  在**解决方案资源管理器**中，选择项目，然后向项目文件添加额外的条目以控制哪些命名空间被隐式导入，如下所示高亮显示的标记：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <OutputType>Exe</OutputType>
        <TargetFramework>net6.0</TargetFramework>
        <Nullable>enable</Nullable>
        <ImplicitUsings>enable</ImplicitUsings>
      </PropertyGroup>
     **<ItemGroup>**
     **<Using Remove=****"System.Threading"** **/>**
     **<Using Include=****"System.Numerics"** **/>**
     **</ItemGroup>**
    </Project> 
    ```

1.  保存对项目文件的更改。

1.  展开`obj`文件夹，展开`Debug`文件夹，展开`net6.0`文件夹，并打开名为`Vocabulary.GlobalUsings.g.cs`的文件。

1.  注意此文件现在导入`System.Numerics`而不是`System.Threading`，如下所示高亮显示的代码：

    ```cs
    // <autogenerated />
    global using global::System;
    global using global::System.Collections.Generic;
    global using global::System.IO;
    global using global::System.Linq;
    global using global::System.Net.Http;
    global using global::System.Threading.Tasks;
    **global****using****global****::System.Numerics;** 
    ```

1.  关闭`Vocabulary.GlobalUsings.g.cs`文件。

您可以通过从项目文件中删除一个条目来禁用所有 SDK 的隐式导入命名空间功能，如下所示的标记：

```cs
<ImplicitUsings>enable</ImplicitUsings> 
```

## 动词是方法

在英语中，动词是表示动作或行为的词，如跑和跳。在 C#中，表示动作或行为的词被称为**方法**。C#中有数十万个方法可供使用。在英语中，动词根据动作发生的时间改变其书写方式。例如，Amir *过去在跳*，Beth *现在跳*，他们*过去跳*，Charlie *将来会跳*。

在 C#中，像`WriteLine`这样的方法会根据具体操作的细节改变其调用或执行方式。这称为重载，我们将在*第五章*，*使用面向对象编程构建自己的类型*中详细介绍。但现在，请考虑以下示例：

```cs
// outputs the current line terminator string
// by default, this is a carriage-return and line feed
Console.WriteLine();
// outputs the greeting and the current line terminator string
Console.WriteLine("Hello Ahmed");
// outputs a formatted number and date and the current line terminator string
Console.WriteLine("Temperature on {0:D} is {1}°C.", 
  DateTime.Today, 23.4); 
```

一个不同的比喻是，有些单词拼写相同，但根据上下文有不同的含义。

## 名词是类型、变量、字段和属性

在英语中，名词是用来指代事物的名称。例如，Fido 是一条狗的名字。单词“狗”告诉我们 Fido 是什么类型的事物，因此为了让 Fido 去取球，我们会使用他的名字。

在 C#中，它们的等价物是**类型**、**变量**、**字段**和**属性**。例如：

+   `Animal`和`Car`是类型；它们是用于分类事物的名词。

+   `Head`和`Engine`可能是字段或属性；属于`Animal`和`Car`的名词。

+   `Fido`和`Bob`是变量；用于指代特定对象的名词。

C#可用的类型有数以万计，尽管你注意到我没有说“C#中有数以万计的类型”吗？这种区别微妙但重要。C#语言只有几个类型的关键字，如`string`和`int`，严格来说，C#并没有定义任何类型。看起来像类型的关键字，如`string`，是**别名**，它们代表 C#运行的平台上提供的类型。

重要的是要知道 C#不能独立存在；毕竟，它是一种运行在.NET 变体上的语言。理论上，有人可以为 C#编写一个使用不同平台的编译器，具有不同的底层类型。实际上，C#的平台是.NET，它为 C#提供了数以万计的类型，包括`System.Int32`，这是 C#关键字别名`int`映射到的，以及许多更复杂的类型，如`System.Xml.Linq.XDocument`。

值得注意的是，术语**类型**经常与**类**混淆。你玩过*二十个问题*这个聚会游戏吗，也称为*动物、植物或矿物*？在游戏中，一切都可以归类为动物、植物或矿物。在 C#中，每个**类型**都可以归类为`class`、`struct`、`enum`、`interface`或`delegate`。您将在*第六章*，*实现接口和继承类*中学习这些含义。例如，C#关键字`string`是一个`class`，但`int`是一个`struct`。因此，最好使用术语**类型**来指代两者。

## 揭示 C#词汇的范围

我们知道 C#中有超过 100 个关键字，但有多少种类型呢？让我们编写一些代码来找出在我们的简单控制台应用程序中 C#可用的类型（及其方法）的数量。

现在不必担心这段代码是如何工作的，但要知道它使用了一种称为**反射**的技术：

1.  我们将首先在`Program.cs`文件顶部导入`System.Reflection`命名空间，如下所示：

    ```cs
    using System.Reflection; 
    ```

1.  删除写入`Hello World!`的语句，并用以下代码替换：

    ```cs
    Assembly? assembly = Assembly.GetEntryAssembly();
    if (assembly == null) return;
    // loop through the assemblies that this app references
    foreach (AssemblyName name in assembly.GetReferencedAssemblies())
    {
      // load the assembly so we can read its details
      Assembly a = Assembly.Load(name);
      // declare a variable to count the number of methods
      int methodCount = 0;
      // loop through all the types in the assembly
      foreach (TypeInfo t in a.DefinedTypes)
      {
        // add up the counts of methods
        methodCount += t.GetMethods().Count();
      }
      // output the count of types and their methods
      Console.WriteLine(
        "{0:N0} types with {1:N0} methods in {2} assembly.",
        arg0: a.DefinedTypes.Count(),
        arg1: methodCount, arg2: name.Name);
    } 
    ```

1.  运行代码。您将看到在您的操作系统上运行最简单的应用程序时，实际可用的类型和方法的数量。显示的类型和方法的数量将根据您使用的操作系统而有所不同，如下所示：

    ```cs
    // Output on Windows
    0 types with 0 methods in System.Runtime assembly.
    106 types with 1,126 methods in System.Linq assembly.
    44 types with 645 methods in System.Console assembly.
    // Output on macOS
    0 types with 0 methods in System.Runtime assembly.
    103 types with 1,094 methods in System.Linq assembly.
    57 types with 701 methods in System.Console assembly. 
    ```

    为什么`System.Runtime`程序集中不包含任何类型？这个程序集很特殊，因为它只包含**类型转发器**而不是实际类型。类型转发器表示已在外部.NET 或其他高级原因中实现的一种类型。

1.  在导入命名空间后，在文件顶部添加语句以声明一些变量，如下面的代码中突出显示的那样：

    ```cs
    using System.Reflection;
    **// declare some unused variables using types**
    **// in additional assemblies**
    **System.Data.DataSet ds;**
    **HttpClient client;** 
    ```

    通过声明使用其他程序集中的类型的变量，这些程序集会随我们的应用程序一起加载，这使得我们的代码能够看到其中的所有类型和方法。编译器会警告你有未使用的变量，但这不会阻止你的代码运行。

1.  再次运行控制台应用程序并查看结果，结果应该类似于以下输出：

    ```cs
    // Output on Windows
    0 types with 0 methods in System.Runtime assembly.
    383 types with 6,854 methods in System.Data.Common assembly.
    456 types with 4,590 methods in System.Net.Http assembly.
    106 types with 1,126 methods in System.Linq assembly.
    44 types with 645 methods in System.Console assembly.
    // Output on macOS
    0 types with 0 methods in System.Runtime assembly.
    376 types with 6,763 methods in System.Data.Common assembly.
    522 types with 5,141 methods in System.Net.Http assembly.
    103 types with 1,094 methods in System.Linq assembly.
    57 types with 701 methods in System.Console assembly. 
    ```

现在，你更清楚为什么学习 C#是一项挑战，因为有如此多的类型和方法需要学习。方法仅是类型可以拥有的成员类别之一，而你和其他程序员不断定义新的类型和成员！

# 处理变量

所有应用程序都处理数据。数据进来，数据被处理，然后数据出去。

数据通常从文件、数据库或用户输入进入我们的程序，并可以暂时存储在变量中，这些变量将存储在运行程序的内存中。当程序结束时，内存中的数据就会丢失。数据通常输出到文件和数据库，或输出到屏幕或打印机。使用变量时，首先应考虑变量在内存中占用多少空间，其次应考虑处理速度有多快。

我们通过选择适当的类型来控制这一点。你可以将`int`和`double`等简单常见类型视为不同大小的存储箱，其中较小的箱子占用较少的内存，但处理速度可能不那么快；例如，在 64 位操作系统上，添加 16 位数字可能不如添加 64 位数字快。其中一些箱子可能堆放在附近，而有些可能被扔进更远的堆中。

## 命名事物和赋值

事物有命名规范，遵循这些规范是良好的实践，如下表所示：

| 命名规范 | 示例 | 用途 |
| --- | --- | --- |
| 驼峰式 | `cost`, `orderDetail`, `dateOfBirth` | 局部变量，私有字段 |
| 标题式（也称为帕斯卡式） | `String`, `Int32`, `Cost`, `DateOfBirth`, `Run` | 类型，非私有字段，以及其他成员如方法 |

**良好实践**：遵循一致的命名规范将使你的代码易于被其他开发者（以及未来的你自己）理解。

下面的代码块展示了一个声明命名局部变量并使用`=`符号为其赋值的示例。你应该注意到，可以使用 C# 6.0 引入的关键字`nameof`输出变量的名称：

```cs
// let the heightInMetres variable become equal to the value 1.88
double heightInMetres = 1.88;
Console.WriteLine($"The variable {nameof(heightInMetres)} has the value
{heightInMetres}."); 
```

前面代码中双引号内的消息因为打印页面的宽度太窄而换到第二行。在你的代码编辑器中输入这样的语句时，请将其全部输入在同一行。

## 字面值

当你给变量赋值时，你通常，但并非总是，赋一个**字面**值。但什么是字面值呢？字面值是一种表示固定值的符号。数据类型有不同的字面值表示法，在接下来的几节中，你将看到使用字面值表示法给变量赋值的示例。

## 存储文本

对于文本，单个字母，如`A`，存储为`char`类型。

**最佳实践**：实际上，这可能比那更复杂。埃及象形文字 A002（U+13001）需要两个`System.Char`值（称为代理对）来表示它：`\uD80C`和`\uDC01`。不要总是假设一个`char`等于一个字母，否则你可能在你的代码中引入奇怪的错误。

使用单引号将字面值括起来，或赋值给一个虚构函数调用的返回值，来给`char`赋值，如下代码所示：

```cs
char letter = 'A'; // assigning literal characters
char digit = '1'; 
char symbol = '$';
char userChoice = GetSomeKeystroke(); // assigning from a fictitious function 
```

对于文本，多个字母，如`Bob`，存储为`string`类型，并使用双引号将字面值括起来，或赋值给函数调用的返回值，如下代码所示：

```cs
string firstName = "Bob"; // assigning literal strings
string lastName = "Smith";
string phoneNumber = "(215) 555-4256";
// assigning a string returned from a fictitious function
string address = GetAddressFromDatabase(id: 563); 
```

### 理解逐字字符串

当在`string`变量中存储文本时，你可以包含转义序列，这些序列使用反斜杠表示特殊字符，如制表符和新行，如下代码所示：

```cs
string fullNameWithTabSeparator = "Bob\tSmith"; 
```

但如果你要存储 Windows 上的文件路径，其中一个文件夹名以`T`开头，如下代码所示，该怎么办？

```cs
string filePath = "C:\televisions\sony\bravia.txt"; 
```

编译器会将`\t`转换为制表符，你将会得到错误！

你必须以前缀`@`符号使用逐字字面`string`，如下代码所示：

```cs
string filePath = @"C:\televisions\sony\bravia.txt"; 
```

总结如下：

+   **字面字符串**：用双引号括起来的字符。它们可以使用转义字符，如`\t`表示制表符。要表示反斜杠，使用两个：`\\`。

+   **逐字字符串**：以`@`为前缀的字面字符串，用于禁用转义字符，使得反斜杠就是反斜杠。它还允许`string`值跨越多行，因为空白字符被视为其本身，而不是编译器的指令。

+   **内插字符串**：以`$`为前缀的字面字符串，用于启用嵌入格式化变量。你将在本章后面了解更多关于这方面的内容。

## 存储数字

数字是我们想要进行算术计算的数据，例如乘法。电话号码不是数字。要决定一个变量是否应存储为数字，请问自己是否需要对该数字执行算术运算，或者该数字是否包含非数字字符，如括号或连字符来格式化数字，例如(414) 555-1234。在这种情况下，该数字是一串字符，因此应将其存储为`string`。

数字可以是自然数，如 42，用于计数（也称为整数）；它们也可以是负数，如-42（称为整数）；或者，它们可以是实数，如 3.9（带有小数部分），在计算中称为单精度或双精度浮点数。

让我们探索数字：

1.  使用您偏好的代码编辑器，在`Chapter02`工作区/解决方案中添加一个名为`Numbers`的**控制台应用程序**。

    1.  在 Visual Studio Code 中，选择`Numbers`作为活动的 OmniSharp 项目。当看到弹出警告消息提示缺少必需资产时，点击**是**以添加它们。

    1.  在 Visual Studio 中，将启动项目设置为当前选择。

1.  在`Program.cs`中，删除现有代码，然后输入语句以声明一些使用各种数据类型的数字变量，如下列代码所示：

    ```cs
    // unsigned integer means positive whole number or 0
    uint naturalNumber = 23;
    // integer means negative or positive whole number or 0
    int integerNumber = -23;
    // float means single-precision floating point
    // F suffix makes it a float literal
    float realNumber = 2.3F;
    // double means double-precision floating point
    double anotherRealNumber = 2.3; // double literal 
    ```

### 存储整数

您可能知道计算机将所有内容存储为位。位的值要么是 0，要么是 1。这称为**二进制数系统**。人类使用**十进制数系统**。

十进制数系统，又称基数 10，其**基数**为 10，意味着有十个数字，从 0 到 9。尽管它是人类文明中最常用的数基，但科学、工程和计算领域中其他数基系统也很流行。二进制数系统，又称基数 2，其基数为 2，意味着有两个数字，0 和 1。

下表展示了计算机如何存储十进制数 10。请注意 8 和 2 列中值为 1 的位；8 + 2 = 10：

| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 0 | 0 | 0 | 1 | 0 | 1 | 0 |

因此，十进制中的`10`在二进制中是`00001010`。

#### 通过使用数字分隔符提高可读性

C# 7.0 及更高版本中的两项改进是使用下划线字符`_`作为数字分隔符，以及支持二进制字面量。

您可以在数字字面量的任何位置插入下划线，包括十进制、二进制或十六进制表示法，以提高可读性。

例如，您可以将 100 万在十进制表示法（即基数 10）中写为`1_000_000`。

您甚至可以使用印度常见的 2/3 分组：`10_00_000`。

#### 使用二进制表示法

要使用二进制表示法，即基数 2，仅使用 1 和 0，请以`0b`开始数字字面量。要使用十六进制表示法，即基数 16，使用 0 到 9 和 A 到 F，请以`0x`开始数字字面量。

### 探索整数

让我们输入一些代码来查看一些示例：

1.  在`Program.cs`中，输入语句以声明一些使用下划线分隔符的数字变量，如下列代码所示：

    ```cs
    // three variables that store the number 2 million
    int decimalNotation = 2_000_000;
    int binaryNotation = 0b_0001_1110_1000_0100_1000_0000; 
    int hexadecimalNotation = 0x_001E_8480;
    // check the three variables have the same value
    // both statements output true 
    Console.WriteLine($"{decimalNotation == binaryNotation}"); 
    Console.WriteLine(
      $"{decimalNotation == hexadecimalNotation}"); 
    ```

1.  运行代码并注意结果是所有三个数字都相同，如下列输出所示：

    ```cs
    True
    True 
    ```

计算机总能使用`int`类型或其同类类型（如`long`和`short`）精确表示整数。

## 存储实数

计算机不能总是精确地表示实数，即小数或非整数。`float`和`double`类型使用单精度和双精度浮点来存储实数。

大多数编程语言都实现了 IEEE 浮点算术标准。IEEE 754 是由**电气和电子工程师协会**（**IEEE**）于 1985 年制定的浮点算术技术标准。

下表简化了计算机如何用二进制表示数字`12.75`。注意 8、4、½和¼列中值为`1`的位。

8 + 4 + ½ + ¼ = 12¾ = 12.75。

| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 | . | ½ | ¼ | 1/8 | 1/16 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | . | 1 | 1 | 0 | 0 |

因此，十进制的`12.75`在二进制中是`00001100.1100`。如你所见，数字`12.75`可以用位精确表示。然而，有些数字则不能，我们很快就会探讨这一点。

### 编写代码以探索数字大小

C# 有一个名为`sizeof()`的运算符，它返回一个类型在内存中使用的字节数。某些类型具有名为`MinValue`和`MaxValue`的成员，这些成员返回可以存储在该类型的变量中的最小和最大值。我们现在将使用这些特性来创建一个控制台应用程序以探索数字类型：

1.  在`Program.cs`中，输入语句以显示三种数字数据类型的大小，如下面的代码所示：

    ```cs
    Console.WriteLine($"int uses {sizeof(int)} bytes and can store numbers in the range {int.MinValue:N0} to {int.MaxValue:N0}."); 
    Console.WriteLine($"double uses {sizeof(double)} bytes and can store numbers in the range {double.MinValue:N0} to {double.MaxValue:N0}."); 
    Console.WriteLine($"decimal uses {sizeof(decimal)} bytes and can store numbers in the range {decimal.MinValue:N0} to {decimal.MaxValue:N0}."); 
    ```

    本书中打印页面的宽度使得`string`值（用双引号括起来）跨越多行。你必须在一行内输入它们，否则会遇到编译错误。

1.  运行代码并查看输出，如*图 2.3*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_02_03.png)

    *图 2.3*：常见数字数据类型的大小和范围信息

`int`变量使用四个字节的内存，并可以存储大约 20 亿以内的正负数。`double`变量使用八个字节的内存，可以存储更大的值！`decimal`变量使用 16 个字节的内存，可以存储大数字，但不如`double`类型那么大。

但你可能在想，为什么`double`变量能够存储比`decimal`变量更大的数字，而在内存中只占用一半的空间？那么，现在就让我们来找出答案吧！

### 比较`double`和`decimal`类型

接下来，你将编写一些代码来比较`double`和`decimal`值。尽管不难理解，但不必担心现在就掌握语法：

1.  输入语句以声明两个`double`变量，将它们相加并与预期结果进行比较，然后将结果写入控制台，如下面的代码所示：

    ```cs
    Console.WriteLine("Using doubles:"); 
    double a = 0.1;
    double b = 0.2;
    if (a + b == 0.3)
    {
      Console.WriteLine($"{a} + {b} equals {0.3}");
    }
    else
    {
      Console.WriteLine($"{a} + {b} does NOT equal {0.3}");
    } 
    ```

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Using doubles:
    0.1 + 0.2 does NOT equal 0.3 
    ```

在使用逗号作为小数分隔符的地区，结果会略有不同，如下面的输出所示：

```cs
0,1 + 0,2 does NOT equal 0,3 
```

`double`类型不能保证精确，因为像`0.1`这样的数字实际上无法用浮点值表示。

一般来说，只有当精确度，尤其是比较两个数的相等性不重要时，才应使用`double`。例如，当你测量一个人的身高，并且只会使用大于或小于进行比较，而永远不会使用等于时，就可能属于这种情况。

前面代码的问题在于计算机如何存储数字`0.1`，或其倍数。为了在二进制中表示`0.1`，计算机在 1/16 列存储 1，在 1/32 列存储 1，在 1/256 列存储 1，在 1/512 列存储 1，等等。

`0.1`在十进制中是二进制的`0.00011001100110011`…，无限重复：

| 4 | 2 | 1 | . | ½ | ¼ | 1/8 | 1/16 | 1/32 | 1/64 | 1/128 | 1/256 | 1/512 | 1/1024 | 1/2048 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 0 | 0 | . | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 1 | 1 | 0 | 0 |

**良好实践**：切勿使用`==`比较`double`值。在第一次海湾战争期间，美国爱国者导弹电池在其计算中使用了`double`值。这种不准确性导致它未能跟踪并拦截来袭的伊拉克飞毛腿导弹，导致 28 名士兵丧生；你可以在[`www.ima.umn.edu/~arnold/disasters/patriot.html`](https://www.ima.umn.edu/~arnold/disasters/patriot.html)阅读有关此事件的信息。

1.  复制并粘贴你之前写的（使用了`double`变量的）语句。

1.  修改语句以使用`decimal`，并将变量重命名为`c`和`d`，如下所示：

    ```cs
    Console.WriteLine("Using decimals:");
    decimal c = 0.1M; // M suffix means a decimal literal value
    decimal d = 0.2M;
    if (c + d == 0.3M)
    {
      Console.WriteLine($"{c} + {d} equals {0.3M}");
    }
    else
    {
      Console.WriteLine($"{c} + {d} does NOT equal {0.3M}");
    } 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Using decimals:
    0.1 + 0.2 equals 0.3 
    ```

`decimal`类型之所以精确，是因为它将数字存储为一个大整数并移动小数点。例如，`0.1`存储为`1`，并注明将小数点向左移动一位。`12.75`存储为`1275`，并注明将小数点向左移动两位。

**良好实践**：使用`int`表示整数。使用`double`表示不会与其他值比较相等性的实数；比较`double`值是否小于或大于等是可以的。使用`decimal`表示货币、CAD 图纸、通用工程以及任何对实数的精确性很重要的地方。

`double`类型有一些有用的特殊值：`double.NaN`表示非数字（例如，除以零的结果），`double.Epsilon`表示`double`中可以存储的最小的正数，`double.PositiveInfinity`和`double.NegativeInfinity`表示无限大的正负值。

## 存储布尔值

布尔值只能包含`true`或`false`这两个文字值之一，如下所示：

```cs
bool happy = true; 
bool sad = false; 
```

它们最常用于分支和循环。你不需要完全理解它们，因为它们在*第三章*，*控制流程、转换类型和处理异常*中会有更详细的介绍。

## 存储任何类型的对象

有一个名为`object`的特殊类型，可以存储任何类型的数据，但其灵活性是以代码更混乱和可能的性能下降为代价的。由于这两个原因，应尽可能避免使用它。以下步骤展示了如果需要使用对象类型时如何操作：

1.  使用您喜欢的代码编辑器，在`Chapter02`工作区/解决方案中添加一个新的**控制台应用程序**，命名为`Variables`。

1.  在 Visual Studio Code 中，选择`Variables`作为活动 OmniSharp 项目。当看到弹出警告消息提示缺少必需资产时，点击**是**以添加它们。

1.  在`Program.cs`中，键入语句以声明和使用一些使用`object`类型的变量，如下所示：

    ```cs
    object height = 1.88; // storing a double in an object 
    object name = "Amir"; // storing a string in an object
    Console.WriteLine($"{name} is {height} metres tall.");
    int length1 = name.Length; // gives compile error!
    int length2 = ((string)name).Length; // tell compiler it is a string
    Console.WriteLine($"{name} has {length2} characters."); 
    ```

1.  运行代码并注意第四条语句无法编译，因为`name`变量的数据类型编译器未知，如图 2.4 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_02_04.png)

    图 2.4：对象类型没有 Length 属性

1.  在语句开头添加双斜杠注释，以“注释掉”无法编译的语句，使其无效。

1.  再次运行代码并注意，如果程序员明确告诉编译器`object`变量包含一个`string`，通过前缀加上类型转换表达式如`(string)`，编译器可以访问`string`的长度，如下所示：

    ```cs
    Amir is 1.88 metres tall. 
    Amir has 4 characters. 
    ```

`object`类型自 C#的第一个版本起就可用，但 C# 2.0 及更高版本有一个更好的替代方案，称为**泛型**，我们将在*第六章*，*实现接口和继承类*中介绍，它将为我们提供所需的灵活性，而不会带来性能开销。

## 存储动态类型

还有一个名为`dynamic`的特殊类型，也可以存储任何类型的数据，但其灵活性甚至超过了`object`，同样以性能为代价。`dynamic`关键字是在 C# 4.0 中引入的。然而，与`object`不同，存储在变量中的值可以在没有显式类型转换的情况下调用其成员。让我们利用`dynamic`类型：

1.  添加语句以声明一个`dynamic`变量，然后分配一个`string`字面值，接着是一个整数值，最后是一个整数数组，如下所示：

    ```cs
    // storing a string in a dynamic object
    // string has a Length property
    dynamic something = "Ahmed";
    // int does not have a Length property
    // something = 12;
    // an array of any type has a Length property
    // something = new[] { 3, 5, 7 }; 
    ```

1.  添加一个语句以输出`dynamic`变量的长度，如下所示：

    ```cs
    // this compiles but would throw an exception at run-time
    // if you later store a data type that does not have a
    // property named Length
    Console.WriteLine($"Length is {something.Length}"); 
    ```

1.  运行代码并注意它有效，因为`string`值确实具有`Length`属性，如下所示：

    ```cs
    Length is 5 
    ```

1.  取消注释分配`int`值的语句。

1.  运行代码并注意运行时错误，因为`int`没有`Length`属性，如下所示：

    ```cs
    Unhandled exception. Microsoft.CSharp.RuntimeBinder.RuntimeBinderException: 'int' does not contain a definition for 'Length' 
    ```

1.  取消注释分配数组的语句。

1.  运行代码并注意输出，因为一个包含三个`int`值的数组确实具有`Length`属性，如下所示：

    ```cs
    Length is 3 
    ```

`动态`的一个限制是代码编辑器无法显示 IntelliSense 来帮助你编写代码。这是因为编译器在构建时无法检查类型是什么。相反，CLR 在运行时检查成员，并在缺失时抛出异常。

异常是一种指示运行时出现问题的方式。你将在*第三章*，*控制流程、转换类型和处理异常*中了解更多关于它们以及如何处理它们的信息。

## 声明局部变量

局部变量在方法内部声明，它们仅在方法执行期间存在，一旦方法返回，分配给任何局部变量的内存就会被释放。

严格来说，值类型会被立即释放，而引用类型必须等待垃圾回收。你将在*第六章*，*实现接口和继承类*中了解值类型和引用类型之间的区别。

### 指定局部变量的类型

让我们探讨使用特定类型和类型推断声明的局部变量：

1.  使用特定类型声明并赋值给一些局部变量的类型语句，如下列代码所示：

    ```cs
    int population = 66_000_000; // 66 million in UK
    double weight = 1.88; // in kilograms
    decimal price = 4.99M; // in pounds sterling
    string fruit = "Apples"; // strings use double-quotes
    char letter = 'Z'; // chars use single-quotes
    bool happy = true; // Booleans have value of true or false 
    ```

根据你的代码编辑器和配色方案，它会在每个变量名下显示绿色波浪线，并将其文本颜色变浅，以警告你该变量已被赋值但从未使用过。

### 推断局部变量的类型

你可以使用`var`关键字来声明局部变量。编译器将从赋值运算符`=`后分配的值推断出类型。

没有小数点的字面数字默认推断为`整数`变量，除非你添加后缀，如下列列表所述：

+   `L`：推断为`长整型`

+   `UL`：推断为`无符号长整型`

+   `M`：推断为`小数`

+   `D`：推断为`双精度浮点数`

+   `F`：推断为`单精度浮点数`

带有小数点的字面数字默认推断为`双精度浮点数`，除非你添加`M`后缀，在这种情况下，它推断为`小数`变量，或者添加`F`后缀，在这种情况下，它推断为`单精度浮点数`变量。

双引号表示`字符串`变量，单引号表示`字符`变量，而`真`和`假`值则暗示了`布尔`类型：

1.  修改前述语句以使用`var`，如下列代码所示：

    ```cs
    var population = 66_000_000; // 66 million in UK
    var weight = 1.88; // in kilograms
    var price = 4.99M; // in pounds sterling
    var fruit = "Apples"; // strings use double-quotes
    var letter = 'Z'; // chars use single-quotes
    var happy = true; // Booleans have value of true or false 
    ```

1.  将鼠标悬停在每个`var`关键字上，并注意你的代码编辑器会显示一个带有关于已推断类型信息的工具提示。

1.  在类文件顶部，导入用于处理 XML 的命名空间，以便我们能够声明一些使用该命名空间中类型的变量，如下列代码所示：

    ```cs
    using System.Xml; 
    ```

    **良好实践**：如果你正在使用.NET 交互式笔记本，那么请在上层代码单元格中添加`using`语句，并在编写主代码的代码单元格上方。然后点击**执行单元格**以确保命名空间被导入。它们随后将在后续代码单元格中可用。

1.  在前述语句下方，添加语句以创建一些新对象，如下列代码所示：

    ```cs
    // good use of var because it avoids the repeated type
    // as shown in the more verbose second statement
    var xml1 = new XmlDocument(); 
    XmlDocument xml2 = new XmlDocument();
    // bad use of var because we cannot tell the type, so we
    // should use a specific type declaration as shown in
    // the second statement
    var file1 = File.CreateText("something1.txt"); 
    StreamWriter file2 = File.CreateText("something2.txt"); 
    ```

    **最佳实践**：尽管使用`var`很方便，但一些开发者避免使用它，以便代码读者更容易理解正在使用的类型。就我个人而言，我只在使用类型明显时使用它。例如，在前面的代码语句中，第一条语句与第二条一样清晰地说明了`xml`变量的类型，但更短。然而，第三条语句并不清楚地显示`file`变量的类型，所以第四条更好，因为它显示了类型是`StreamWriter`。如果有疑问，就明确写出类型！

### 使用目标类型的新来实例化对象

使用 C# 9，微软引入了一种称为**目标类型的新**的实例化对象的语法。在实例化对象时，你可以先指定类型，然后使用`new`而不重复类型，如下面的代码所示：

```cs
XmlDocument xml3 = new(); // target-typed new in C# 9 or later 
```

如果你有一个需要设置字段或属性的类型，则可以推断类型，如下面的代码所示：

```cs
class Person
{
  public DateTime BirthDate;
}
Person kim = new();
kim.BirthDate = new(1967, 12, 26); // instead of: new DateTime(1967, 12, 26) 
```

**最佳实践**：除非必须使用版本 9 之前的 C#编译器，否则请使用目标类型的新来实例化对象。我在本书的其余部分都使用了目标类型的新。如果你发现我遗漏了任何情况，请告诉我！

## 获取和设置类型的默认值

除了`string`之外的大多数基本类型都是**值类型**，这意味着它们必须有一个值。你可以通过使用`default()`运算符并传递类型作为参数来确定类型的默认值。你可以使用`default`关键字来赋予类型默认值。

`string`类型是**引用类型**。这意味着`string`变量包含值的内存地址，而不是值本身。引用类型变量可以具有`null`值，这是一个指示变量未引用任何内容（尚未）的字面量。`null`是所有引用类型的默认值。

你将在*第六章*，*实现接口和继承类*中了解更多关于值类型和引用类型的信息。

让我们探索默认值：

1.  添加语句以显示`int`、`bool`、`DateTime`和`string`的默认值，如下面的代码所示：

    ```cs
    Console.WriteLine($"default(int) = {default(int)}"); 
    Console.WriteLine($"default(bool) = {default(bool)}"); 
    Console.WriteLine($"default(DateTime) = {default(DateTime)}"); 
    Console.WriteLine($"default(string) = {default(string)}"); 
    ```

1.  运行代码并查看结果，注意如果你的输出日期和时间格式与英国不同，以及`null`值输出为空`string`，如下面的输出所示：

    ```cs
    default(int) = 0 
    default(bool) = False
    default(DateTime) = 01/01/0001 00:00:00 
    default(string) = 
    ```

1.  添加语句以声明一个数字，赋予一个值，然后将其重置为其默认值，如下面的代码所示：

    ```cs
    int number = 13;
    Console.WriteLine($"number has been set to: {number}");
    number = default;
    Console.WriteLine($"number has been reset to its default: {number}"); 
    ```

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    number has been set to: 13
    number has been reset to its default: 0 
    ```

## 在数组中存储多个值

当你需要存储同一类型的多个值时，你可以声明一个**数组**。例如，当你需要在`string`数组中存储四个名字时，你可能会这样做。

接下来你将编写的代码将为存储四个`string`值的数组分配内存。然后，它将在索引位置 0 到 3 处存储`string`值（数组通常的下界为零，因此最后一项的索引比数组长度小一）。

**良好实践**：不要假设所有数组都从零开始计数。.NET 中最常见的数组类型是**szArray**，一种单维零索引数组，它们使用正常的`[]`语法。但.NET 也有**mdArray**，多维数组，它们不必具有零的下界。这些很少使用，但你应该知道它们存在。

最后，它将使用`for`语句遍历数组中的每个项，我们将在*第三章*，*控制流程、转换类型和处理异常*中更详细地介绍这一点。

让我们看看如何使用数组：

1.  输入语句以声明和使用`string`值的数组，如下面的代码所示：

    ```cs
    string[] names; // can reference any size array of strings
    // allocating memory for four strings in an array
    names = new string[4];
    // storing items at index positions
    names[0] = "Kate";
    names[1] = "Jack"; 
    names[2] = "Rebecca"; 
    names[3] = "Tom";
    // looping through the names
    for (int i = 0; i < names.Length; i++)
    {
      // output the item at index position i
      Console.WriteLine(names[i]);
    } 
    ```

1.  运行代码并记录结果，如下面的输出所示：

    ```cs
    Kate 
    Jack 
    Rebecca 
    Tom 
    ```

数组在内存分配时总是具有固定大小，因此在实例化之前，你需要决定要存储多少项。

除了上述三个步骤定义数组的替代方法是使用数组初始化器语法，如下面的代码所示：

```cs
string[] names2 = new[] { "Kate", "Jack", "Rebecca", "Tom" }; 
```

当你使用`new[]`语法为数组分配内存时，你必须在大括号中至少包含一个项，以便编译器可以推断数据类型。

数组适用于临时存储多个项，但当需要动态添加和删除项时，集合是更灵活的选择。目前你不需要担心集合，因为我们在*第八章*，*使用常见的.NET 类型*中会涉及它们。

# 深入探索控制台应用程序

我们已经创建并使用了基本的控制台应用程序，但现在我们应该更深入地研究它们。

控制台应用程序是基于文本的，并在命令行上运行。它们通常执行需要脚本的简单任务，例如编译文件或加密配置文件的一部分。

同样，它们也可以接受参数来控制其行为。

一个例子是使用指定的名称而不是当前文件夹的名称创建一个新的控制台应用程序，如下面的命令行所示：

```cs
dotnet new console -lang "F#" --name "ExploringConsole" 
```

## 向用户显示输出

控制台应用程序最常见的两个任务是写入和读取数据。我们已经一直在使用`WriteLine`方法输出，但如果我们不希望在行尾有回车，我们可以使用`Write`方法。

### 使用编号的位置参数进行格式化

生成格式化字符串的一种方法是使用编号的位置参数。

此功能受到`Write`和`WriteLine`等方法的支持，对于不支持此功能的方法，可以使用`string`的`Format`方法对`string`参数进行格式化。

本节的前几个代码示例将与.NET Interactive 笔记本一起工作，因为它们是关于输出到控制台的。在本节后面，你将学习通过控制台获取输入，遗憾的是笔记本不支持这一点。

让我们开始格式化：

1.  使用你偏好的代码编辑器，在`Chapter02`工作区/解决方案中添加一个新的**控制台应用程序**，命名为`Formatting`。

1.  在 Visual Studio Code 中，选择`Formatting`作为活动的 OmniSharp 项目。

1.  在`Program.cs`中，输入语句以声明一些数字变量并将它们写入控制台，如下所示：

    ```cs
    int numberOfApples = 12; 
    decimal pricePerApple = 0.35M;
    Console.WriteLine(
      format: "{0} apples costs {1:C}", 
      arg0: numberOfApples,
      arg1: pricePerApple * numberOfApples);
    string formatted = string.Format(
      format: "{0} apples costs {1:C}",
      arg0: numberOfApples,
      arg1: pricePerApple * numberOfApples);
    //WriteToFile(formatted); // writes the string into a file 
    ```

`WriteToFile`方法是一个不存在的用于说明概念的方法。

**良好实践**：一旦你对格式化字符串更加熟悉，你应该停止命名参数，例如，停止使用`format:`、`arg0:`和`arg1:`。前面的代码使用了非规范的风格来显示`0`和`1`的来源，而你正在学习。

### 使用插值字符串进行格式化

C# 6.0 及更高版本有一个名为**插值字符串**的便捷功能。以`$`为前缀的`字符串`可以使用大括号包围变量或表达式的名称，以在该`字符串`中的该位置输出该变量或表达式的当前值，如下所示：

1.  在`Program.cs`文件底部输入如下所示的语句：

    ```cs
    Console.WriteLine($"{numberOfApples} apples costs {pricePerApple * numberOfApples:C}"); 
    ```

1.  运行代码并查看结果，如下面的部分输出所示：

    ```cs
     12 apples costs £4.20 
    ```

对于简短的格式化`字符串`值，插值`字符串`可能更容易让人阅读。但在书籍中的代码示例中，由于行需要跨越多行，这可能很棘手。对于本书中的许多代码示例，我将使用编号的位置参数。

避免使用插值字符串的另一个原因是它们不能从资源文件中读取以进行本地化。

在 C# 10 之前，字符串常量只能通过连接来组合，如下所示：

```cs
private const string firstname = "Omar";
private const string lastname = "Rudberg";
private const string fullname = firstname + " " + lastname; 
```

使用 C# 10，现在可以使用插值字符串，如下所示：

```cs
private const string fullname = "{firstname} {lastname}"; 
```

这只适用于组合字符串常量值。它不能与其他类型（如数字）一起工作，这些类型需要运行时数据类型转换。

### 理解格式字符串

变量或表达式可以在逗号或冒号后使用格式字符串进行格式化。

`N0`格式字符串表示带有千位分隔符且没有小数位的数字，而`C`格式字符串表示货币。货币格式将由当前线程决定。

例如，如果你在英国的 PC 上运行这段代码，你会得到以逗号作为千位分隔符的英镑，但如果你在德国的 PC 上运行这段代码，你将得到以点作为千位分隔符的欧元。

格式项的完整语法是：

```cs
{ index [, alignment ] [ : formatString ] } 
```

每个格式项都可以有一个对齐方式，这在输出值表时很有用，其中一些可能需要在字符宽度内左对齐或右对齐。对齐值是整数。正整数表示右对齐，负整数表示左对齐。

例如，要输出一个水果及其数量的表格，我们可能希望在 10 个字符宽的列内左对齐名称，并在 6 个字符宽的列内右对齐格式化为无小数点的数字计数：

1.  在`Program.cs`底部，输入以下语句：

    ```cs
    string applesText = "Apples"; 
    int applesCount = 1234;
    string bananasText = "Bananas"; 
    int bananasCount = 56789;
    Console.WriteLine(
      format: "{0,-10} {1,6:N0}",
      arg0: "Name",
      arg1: "Count");
    Console.WriteLine(
      format: "{0,-10} {1,6:N0}",
      arg0: applesText,
      arg1: applesCount);
    Console.WriteLine(
      format: "{0,-10} {1,6:N0}",
      arg0: bananasText,
      arg1: bananasCount); 
    ```

1.  运行代码并注意对齐和数字格式的效果，如下所示：

    ```cs
    Name          Count
    Apples        1,234
    Bananas      56,789 
    ```

## 从用户获取文本输入

我们可以使用`ReadLine`方法从用户获取文本输入。该方法等待用户输入一些文本，一旦用户按下 Enter 键，用户输入的任何内容都会作为`string`值返回。

**良好实践**：如果你在本节使用.NET Interactive 笔记本，请注意它不支持使用`Console.ReadLine()`从控制台读取输入。相反，你必须设置文字值，如下所示：`string? firstName = "Gary";`。这通常更快，因为你可以简单地更改文字`string`值并点击**执行单元格**按钮，而不必每次想输入不同`string`值时都重启控制台应用。

让我们获取用户输入：

1.  输入语句以询问用户的姓名和年龄，然后输出他们输入的内容，如下所示：

    ```cs
    Console.Write("Type your first name and press ENTER: "); 
    string? firstName = Console.ReadLine();
    Console.Write("Type your age and press ENTER: "); 
    string? age = Console.ReadLine();
    Console.WriteLine(
      $"Hello {firstName}, you look good for {age}."); 
    ```

1.  运行代码，然后输入姓名和年龄，如下所示：

    ```cs
    Type your name and press ENTER: Gary 
    Type your age and press ENTER: 34 
    Hello Gary, you look good for 34. 
    ```

在`string?`数据类型声明末尾的问号表示我们承认从`ReadLine`调用可能返回`null`（空）值。你将在*第六章*，*实现接口和继承类*中了解更多关于这方面的内容。

## 简化控制台的使用

在 C# 6.0 及更高版本中，`using`语句不仅可以用于导入命名空间，还可以通过导入静态类进一步简化我们的代码。然后，我们就不需要在代码中输入`Console`类型名称。你可以使用代码编辑器的查找和替换功能来删除我们之前写过的`Console`：

1.  在`Program.cs`文件顶部，添加一个语句以**静态导入**`System.Console`类，如下所示：

    ```cs
    using static System.Console; 
    ```

1.  选择代码中的第一个`Console.`，确保也选中了`Console`单词后的点。

1.  在 Visual Studio 中，导航至**编辑** | **查找和替换** | **快速替换**，或在 Visual Studio Code 中，导航至**编辑** | **替换**，并注意一个覆盖对话框出现，准备让你输入你想替换**Console.**的内容，如*图 2.5*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_02_05.png)

    图 2.5：在 Visual Studio 中使用替换功能简化代码

1.  将替换框留空，点击**全部替换**按钮（替换框右侧两个按钮中的第二个），然后通过点击替换框右上角的叉号关闭替换框。

## 从用户获取按键输入

我们可以使用`ReadKey`方法从用户获取按键输入。此方法等待用户按下键或键组合，然后将其作为`ConsoleKeyInfo`值返回。

在.NET Interactive 笔记本中，你将无法执行对`ReadKey`方法的调用，但如果你创建了一个控制台应用程序，那么让我们来探索读取按键操作：

1.  输入语句以要求用户按下任何键组合，然后输出有关它的信息，如下列代码所示：

    ```cs
    Write("Press any key combination: "); 
    ConsoleKeyInfo key = ReadKey(); 
    WriteLine();
    WriteLine("Key: {0}, Char: {1}, Modifiers: {2}",
      arg0: key.Key, 
      arg1: key.KeyChar,
      arg2: key.Modifiers); 
    ```

1.  运行代码，按下 K 键，注意结果，如下列输出所示：

    ```cs
    Press any key combination: k 
    Key: K, Char: k, Modifiers: 0 
    ```

1.  运行代码，按住 Shift 键并按下 K 键，注意结果，如下列输出所示：

    ```cs
    Press any key combination: K  
    Key: K, Char: K, Modifiers: Shift 
    ```

1.  运行代码，按下 F12 键，注意结果，如下列输出所示：

    ```cs
    Press any key combination: 
    Key: F12, Char: , Modifiers: 0 
    ```

在 Visual Studio Code 内的终端中运行控制台应用程序时，某些键盘组合会在你的应用程序处理之前被代码编辑器或操作系统捕获。

## 向控制台应用程序传递参数

你可能一直在思考如何获取可能传递给控制台应用程序的任何参数。

在.NET 的每个版本中，直到 6.0 之前，控制台应用程序项目模板都显而易见，如下列代码所示：

```cs
using System;
namespace Arguments
{
  class Program
  {
    static void Main(string[] args)
    {
      Console.WriteLine("Hello World!");
    }
  }
} 
```

`string[] args`参数在`Program`类的`Main`方法中声明并传递。它们是一个数组，用于向控制台应用程序传递参数。但在.NET 6.0 及更高版本中使用的顶级程序中，`Program`类及其`Main`方法，连同`args`字符串数组的声明都被隐藏了。诀窍在于你必须知道它仍然存在。

命令行参数由空格分隔。其他字符如连字符和冒号被视为参数值的一部分。

要在参数值中包含空格，请用单引号或双引号将参数值括起来。

假设我们希望能够在命令行输入一些前景色和背景色的名称，以及终端窗口的尺寸。我们可以通过从始终传递给`Main`方法（即控制台应用程序的入口点）的`args`数组中读取这些颜色和数字来实现。

1.  使用你偏好的代码编辑器，在`Chapter02`工作区/解决方案中添加一个新的**控制台应用程序**，命名为`Arguments`。由于无法向笔记本传递参数，因此你不能使用.NET Interactive 笔记本。

1.  在 Visual Studio Code 中，选择`Arguments`作为活动的 OmniSharp 项目。

1.  添加一条语句以静态导入`System.Console`类型，并添加一条语句以输出传递给应用程序的参数数量，如下列代码所示：

    ```cs
    using static System.Console;
    WriteLine($"There are {args.Length} arguments."); 
    ```

    **良好实践**：记住在所有未来的项目中静态导入`System.Console`类型，以简化您的代码，因为这些说明不会每次都重复。

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    There are 0 arguments. 
    ```

1.  如果您使用的是 Visual Studio，那么导航到**项目** | **属性** **参数**，选择**调试**选项卡，在**应用程序参数**框中输入一些参数，保存更改，然后运行控制台应用程序，如图*2.6*所示：![图形用户界面，文本，应用程序 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_02_06.png)

    图 2.6：在 Visual Studio 项目属性中输入应用程序参数

1.  如果您使用的是 Visual Studio Code，那么在终端中，在`dotnet run`命令后输入一些参数，如下面的命令行所示：

    ```cs
    dotnet run firstarg second-arg third:arg "fourth arg" 
    ```

1.  注意结果显示了四个参数，如下面的输出所示：

    ```cs
    There are 4 arguments. 
    ```

1.  要枚举或迭代（即循环遍历）这四个参数的值，请在输出数组长度后添加以下语句：

    ```cs
    foreach (string arg in args)
    {
      WriteLine(arg);
    } 
    ```

1.  再次运行代码，并注意结果显示了四个参数的详细信息，如下面的输出所示：

    ```cs
    There are 4 arguments. 
    firstarg
    second-arg 
    third:arg 
    fourth arg 
    ```

## 使用参数设置选项

现在我们将使用这些参数让用户为输出窗口的背景、前景和光标大小选择颜色。光标大小可以是 1 到 100 的整数值，1 表示光标单元格底部的线条，100 表示光标单元格高度的百分比。

`System`命名空间已经导入，以便编译器知道`ConsoleColor`和`Enum`类型：

1.  添加语句以警告用户，如果他们没有输入三个参数，然后解析这些参数并使用它们来设置控制台窗口的颜色和尺寸，如下面的代码所示：

    ```cs
    if (args.Length < 3)
    {
      WriteLine("You must specify two colors and cursor size, e.g.");
      WriteLine("dotnet run red yellow 50");
      return; // stop running
    }
    ForegroundColor = (ConsoleColor)Enum.Parse(
      enumType: typeof(ConsoleColor),
      value: args[0],
      ignoreCase: true);
    BackgroundColor = (ConsoleColor)Enum.Parse(
      enumType: typeof(ConsoleColor),
      value: args[1],
      ignoreCase: true);
    CursorSize = int.Parse(args[2]); 
    ```

    设置`CursorSize`仅在 Windows 上支持。

1.  在 Visual Studio 中，导航到**项目** | **属性参数**，并将参数更改为：`red yellow 50`，运行控制台应用程序，并注意光标大小减半，窗口中的颜色已更改，如图*2.7*所示：![图形用户界面，应用程序，网站 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_02_07.png)

    图 2.7：在 Windows 上设置颜色和光标大小

1.  在 Visual Studio Code 中，使用参数运行代码，将前景色设置为红色，背景色设置为黄色，光标大小设置为 50%，如下面的命令所示：

    ```cs
    dotnet run red yellow 50 
    ```

    在 macOS 上，您会看到一个未处理的异常，如图*2.8*所示：

    ![图形用户界面，文本，应用程序 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_02_08.png)

图 2.8：在不受支持的 macOS 上出现未处理的异常

尽管编译器没有给出错误或警告，但在某些平台上运行时，某些 API 调用可能会失败。虽然 Windows 上的控制台应用程序可以更改光标大小，但在 macOS 上却无法实现，并且尝试时会报错。

## 处理不支持 API 的平台

那么我们该如何解决这个问题呢？我们可以通过使用异常处理器来解决。你将在*第三章*，*控制流程、类型转换和异常处理*中了解更多关于`try-catch`语句的细节，所以现在只需输入代码：

1.  修改代码，将更改光标大小的行包裹在`try`语句中，如下所示：

    ```cs
    try
    {
      CursorSize = int.Parse(args[2]);
    }
    catch (PlatformNotSupportedException)
    {
      WriteLine("The current platform does not support changing the size of the cursor.");
    } 
    ```

1.  如果你在 macOS 上运行这段代码，你会看到异常被捕获，并向用户显示一个更友好的消息。

另一种处理操作系统差异的方法是使用`System`命名空间中的`OperatingSystem`类，如下所示：

```cs
if (OperatingSystem.IsWindows())
{
  // execute code that only works on Windows
}
else if (OperatingSystem.IsWindowsVersionAtLeast(major: 10))
{
  // execute code that only works on Windows 10 or later
}
else if (OperatingSystem.IsIOSVersionAtLeast(major: 14, minor: 5))
{
  // execute code that only works on iOS 14.5 or later
}
else if (OperatingSystem.IsBrowser())
{
  // execute code that only works in the browser with Blazor
} 
```

`OperatingSystem`类为其他常见操作系统（如 Android、iOS、Linux、macOS，甚至是浏览器）提供了等效方法，这对于 Blazor Web 组件非常有用。

处理不同平台的第三种方法是使用条件编译语句。

有四个预处理器指令控制条件编译：`#if`、`#elif`、`#else`和`#endif`。

你使用`#define`定义符号，如下所示：

```cs
#define MYSYMBOL 
```

许多符号会自动为你定义，如下表所示：

| 目标框架 | 符号 |
| --- | --- |
| .NET 标准 | `NETSTANDARD2_0`、`NETSTANDARD2_1`等 |
| 现代.NET | `NET6_0`、`NET6_0_ANDROID`、`NET6_0_IOS`、`NET6_0_WINDOWS`等 |

然后你可以编写仅针对指定平台编译的语句，如下所示：

```cs
#if NET6_0_ANDROID
// compile statements that only works on Android
#elif NET6_0_IOS
// compile statements that only works on iOS
#else
// compile statements that work everywhere else
#endif 
```

# 实践与探索

通过回答一些问题来测试你的知识和理解，进行一些实践练习，并深入研究本章涵盖的主题。

## 练习 2.1 – 测试你的知识

为了得到这些问题的最佳答案，你需要进行自己的研究。我希望你能“跳出书本思考”，因此我故意没有在书中提供所有答案。

我想鼓励你养成在其他地方寻求帮助的好习惯，遵循“授人以渔”的原则。

1.  你可以在 C#文件中输入什么语句来发现编译器和语言版本？

1.  在 C#中有哪两种类型的注释？

1.  逐字字符串和插值字符串之间有什么区别？

1.  为什么在使用`float`和`double`值时要小心？

1.  如何确定像`double`这样的类型在内存中占用多少字节？

1.  何时应该使用`var`关键字？

1.  创建`XmlDocument`类实例的最新方法是什么？

1.  为什么在使用`dynamic`类型时要小心？

1.  如何右对齐格式字符串？

1.  控制台应用程序的参数之间用什么字符分隔？

    *附录*，*测试你的知识问题的答案*可从 GitHub 仓库的 README 中的链接下载：[`github.com/markjprice/cs10dotnet6`](https://github.com/markjprice/cs10dotnet6)。

## 练习 2.2 – 测试你对数字类型的知识

你会为以下“数字”选择什么类型？

1.  一个人的电话号码

1.  一个人的身高

1.  一个人的年龄

1.  一个人的薪水

1.  一本书的 ISBN

1.  一本书的价格

1.  一本书的运送重量

1.  一个国家的人口

1.  宇宙中的恒星数量

1.  英国中小型企业中每个企业的员工数量（每个企业最多约 50,000 名员工）

## 练习 2.3 – 实践数字大小和范围

在`Chapter02`解决方案/工作区中，创建一个名为`Exercise02`的控制台应用程序项目，输出以下每种数字类型在内存中占用的字节数及其最小和最大值：`sbyte`、`byte`、`short`、`ushort`、`int`、`uint`、`long`、`ulong`、`float`、`double`和`decimal`。

运行你的控制台应用程序的结果应该类似于*图 2.9*：

![自动生成的文本描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_02_09.png)

图 2.9：输出数字类型大小的结果

所有练习的代码解决方案都可以从以下链接下载或克隆 GitHub 仓库：[`github.com/markjprice/cs10dotnet6`](https://github.com/markjprice/cs10dotnet6)。

## 练习 2.4 – 探索主题

使用以下页面上的链接来了解本章涵盖的主题的更多细节：

[`github.com/markjprice/cs10dotnet6/blob/main/book-links.md#第二章-使用 C#进行编程`](https://github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-2---speaking-c)

# 总结

在本章中，你学会了如何：

+   声明具有指定或推断类型的变量。

+   使用一些内置的数字、文本和布尔类型。

+   选择数字类型

+   控制控制台应用程序的输出格式。

在下一章中，你将学习运算符、分支、循环、类型转换以及如何处理异常。
