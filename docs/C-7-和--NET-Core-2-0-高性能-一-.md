# C#7 和 .NET Core 2.0 高性能（一）

> 原文：[`zh.annas-archive.org/md5/7B34F69B3C37FC27C73A3C065B05D042`](https://zh.annas-archive.org/md5/7B34F69B3C37FC27C73A3C065B05D042)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书首先介绍了 C# 7 和.NET Core 2.0 的新功能，以及它们如何帮助提高应用程序的性能。然后，本书将帮助您了解.NET Core 的核心内部，包括编译过程、垃圾回收、利用 CPU 的多个核心来开发高性能应用程序，以及使用强大的基准测试应用程序库 BenchmarkDotNet 来测量性能。我们将学习使用多线程和异步编程来开发应用程序和程序，以及如何利用这些概念构建高效的应用程序以实现更快的执行。接下来，您将了解数据结构优化的重要性以及如何有效地使用它。我们将继续讨论在.NET Core 中设计应用程序时使用的模式和最佳实践，以及如何有效地利用内存并避免内存泄漏。之后，我们将讨论在.NET Core 应用程序中实现安全性和弹性，并使用 Polly 框架来实现断路器、重试和回退模式，以及某些中间件来加固 HTTP 管道。我们还将使用 Identity 框架实现授权和身份验证等安全性。接下来，我们将学习微服务架构，以及如何使用它创建模块化、高度可扩展和独立部署的应用程序。最后，我们将学习如何使用 App Metrics 来监控应用程序的性能。

# 这本书适合谁

这本书适合.NET 开发人员，他们希望提高应用程序代码的速度，或者只是想将自己的技能提升到下一个水平，从而开发和生产不仅性能优越，而且符合行业最佳实践的高质量应用程序。假定具有基本的 C#知识。

# 本书涵盖的内容

第一章，*在.NET Core 2 和 C# 7 中的新功能*，讨论了.NET Core 框架，并涵盖了.NET Core 2.0 引入的一些改进。我们还将了解 C# 7 的新功能，以及如何编写更干净的代码和简化语法表达。最后，我们将涵盖编写高质量代码的主题。我们将看到如何利用 Visual Studio 2017 的代码分析功能向我们的项目添加分析器并改进代码质量。

第二章，*了解.NET Core 内部和测量性能*，讨论了.NET Core 的核心概念，包括编译过程、垃圾回收、利用 CPU 的多个核心来构建高性能的.NET Core 应用程序，以及使用发布版本构建发布应用程序。我们还将探讨用于代码优化的基准测试工具，并提供特定于内存对象的结果。

第三章，*在.NET Core 中进行多线程和异步编程*，探讨了多线程和异步编程的核心基础知识。本章从多线程和异步编程之间的基本区别开始，并引导您了解核心概念。它探讨了 API 以及在编写多线程应用程序时如何使用它们。我们将学习如何使用任务编程库来执行异步操作，以及如何实现任务异步模式。最后，我们将探讨并行编程技术以及一些最佳的设计模式。

第四章，“C#中的数据结构和编写优化代码”，概述了数据结构的核心概念、数据结构的类型以及它们的优缺点，然后介绍了每种数据结构适用的最佳场景。我们还将学习大 O 符号，这是编写代码时需要考虑的核心主题之一，有助于开发人员检查代码质量和性能。最后，我们将探讨一些最佳实践，并涵盖诸如装箱和拆箱、字符串连接、异常处理、`for`和`foreach`以及委托等主题。

第五章，“.NET Core 应用程序性能设计指南”，展示了一些使应用程序代码看起来整洁且易于理解的编码原则。如果代码整洁，它可以让其他开发人员完全理解，并在许多其他方面有所帮助。我们将学习一些基本的设计原则，这些原则被认为是设计应用程序时的核心原则的一部分。像 KISS、YAGNI、DRY、关注点分离和 SOLID 这样的原则在软件设计中非常重要，缓存和选择正确的数据结构对性能有重大影响，如果使用得当，可以提高性能。最后，我们将学习在处理通信、资源管理和并发时应考虑的一些最佳实践。

第六章，“.NET Core 中的内存管理技术”，概述了.NET 中内存管理的基本过程。我们将探索调试工具，开发人员可以使用它来调查堆上对象的内存分配。我们还将了解内存碎片化、终结器以及如何通过实现`IDisposable`接口来实现处理模式以清理资源。

第七章，“在.NET Core 应用程序中实现安全和弹性”，带您了解弹性，这是在.NET Core 中开发高性能应用程序时非常重要的因素。我们将学习不同的策略，并使用 Polly 框架在.NET Core 中使用这些策略。我们还将了解安全存储机制以及如何在开发环境中使用它们，以便将敏感信息与项目存储库分开。在本章末尾，我们将学习一些安全基础知识，包括 SSL、CSRF、CORS、安全标头和 ASP.NET Core 身份框架，以保护 ASP.NET Core 应用程序。

第八章，“微服务架构”，着眼于基于微服务的快速发展的软件架构，用于开发云端高性能和可扩展的应用程序。我们将学习微服务架构的一些核心基础知识、其优势以及在设计架构时使用的模式和实践。我们将讨论将企业应用程序分解为微服务架构风格时面临的挑战，并学习诸如 API 组合和 CQRS 之类的模式以解决这些挑战。在本章后期，我们将在.NET Core 中开发一个基本应用程序，并讨论解决方案的结构和微服务的组件。然后我们将开发身份和供应商服务。

第九章，*使用工具监视应用程序性能*，深入探讨了监视应用程序性能所必需的关键性能指标。我们将探索并设置 App Metrics，这是一个跨平台的免费工具，提供各种扩展，可用于实现广泛的报告。我们将逐步指南地介绍如何配置和设置 App Metrics 及相关组件，如 InfluxDb 和 Grafana，用于在 Grafana 基于 Web 的工具中存储和查看遥测，并将其与 ASP.NET Core 应用程序集成。

# 为了充分利用本书

读者应具备以下环境配置：

1.  **开发环境**：Visual Studio 2015/2017 社区版

1.  **执行环境**：.NET Core

1.  **操作系统环境**：Windows 或 Linux

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)注册，直接将文件通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的以下工具解压或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/C-Sharp-7-and-NET-Core-2-High-Performance/`](https://github.com/PacktPublishing/C-Sharp-7-and-NET-Core-2-High-Performance/)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在此处下载：[`www.packtpub.com/sites/default/files/downloads/CSharp7andNETCore2HighPerformance_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/CSharp7andNETCore2HighPerformance_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。例如：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统上的另一个磁盘。”

代码块设置如下：

```cs
public static IWebHost BuildWebHost(string[] args) => 
  WebHost.CreateDefaultBuilder(args) 
    .UseMetrics() 
    .UseStartup<Startup>() 
    .Build(); 
```

任何命令行输入或输出都以以下形式书写：

```cs
Install-Package App.Metrics 
Install-Pacakge App.Metrics.AspnetCore.Mvc 
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。例如：“从管理面板中选择系统信息。”

警告或重要说明会以这种形式出现。

提示和技巧会以这种形式出现。


# 第一章：.NET Core 2 和 C# 7 中的新功能是什么？

.NET Core 是微软的一个跨平台开发平台，由微软和 GitHub 社区维护。由于其性能和平台可移植性，它是开发社区中最新兴和最受欢迎的框架。它面向每个开发人员，可以为包括 Web、云、移动、嵌入式和物联网在内的任何平台开发任何应用程序。

使用.NET Core，我们可以使用 C#、F#，现在也可以使用 VB.NET。然而，C#是开发人员中最广泛使用的语言。

在本章中，您将学习以下主题：

+   .NET Core 2.0 中的性能改进

+   从.NET Core 1.x 升级到 2.0 的路径

+   .NET 标准 2.0

+   ASP.NET Core 2.0 带来了什么

+   C# 7.0 中的新功能

# .NET 的演变

在 2002 年初，当微软首次推出.NET Framework 时，它面向的是那些在经典 ASP 或 VB 6 平台上工作的开发人员，因为他们没有任何引人注目的框架来开发企业级应用程序。随着.NET Framework 的发布，开发人员有了一个可以选择 VB.NET、C#和 F#中的任何一种语言来开发应用程序的平台。无论选择哪种语言，代码都是可互操作的，开发人员可以创建一个 VB.NET 项目并在其 C#或 F#项目中引用它，反之亦然。

.NET Framework 的核心组件包括**公共语言运行时**（**CLR**）、**框架类库**（**FCL**）、**基类库**（**BCL**）和一组应用程序模型。随着新版本的.NET Framework 的推出，新功能和补丁也随之引入，这些新功能和补丁通常随着 Windows 的新版本一起发布，开发人员必须等待一年左右才能获得这些改进。微软的每个团队都在不同的应用程序模型上工作，每个团队都必须等待新框架发布的日期来移植他们的修复和改进。当时主要使用的应用程序模型是 Windows Forms 和 Web Forms。

当 Web Forms 首次推出时，它是一个突破，吸引了既在经典 ASP 上工作的 Web 开发人员，又在 Visual Basic 6.0 上工作的桌面应用程序开发人员。开发人员体验非常吸引人，并提供了一套不错的控件，可以轻松地拖放到屏幕上，然后跟随它们的事件和属性，这些属性可以通过视图文件（`.aspx`）或代码后台文件进行设置。后来，微软推出了**模型视图控制器**（**MVC**）应用程序模型，实现了关注点分离设计原则，因此视图、模型和控制器是独立的实体。视图是呈现模型的用户界面，模型代表业务实体并保存数据，控制器处理请求并更新模型，并将其注入视图。MVC 是一个突破，让开发人员编写更干净的代码，并使用模型绑定将其模型与 HTML 控件绑定。随着时间的推移，添加了更多功能，核心.NET web 程序集`System.Web`变得非常庞大，包含了许多包和 API，这些 API 并不总是在每种类型的应用程序中都有用。然而，随着.NET 的推出，引入了一些重大变化，`System.Web`被拆分为 NuGet 包，可以根据需求引用和单独添加。

.NET Core（代号.NET vNext）首次在 2014 年推出，以下是使用.NET Core 的核心优势：

| **好处** | **描述** |
| --- | --- |
| **跨平台** | .NET Core 可以在 Windows、Linux 和 macOS 上运行 |
| **主机无关** | .NET Core 在服务器端不依赖于 IIS，并且可以作为控制台应用程序进行自托管，并且可以通过反向代理选项与成熟的服务器（如 IIS、Apache 等）结合使用，还有两个轻量级服务器*Kestrel*和*WebListener* |
| **模块化** | 以 NuGet 包的形式发布 |
| **开源** | 整个源代码通过.NET 基金会作为开源发布 |
| **CLI 工具** | 用于从命令行创建、构建和运行项目的命令行工具 |

.NET Core 是一个跨平台的开源框架，实现了.NET 标准。它提供了一个称为.NET Core CLR 的运行时，框架类库，即称为*CoreFX*的基本库，以及类似于.NET Framework 的 API，但依赖较少（对其他程序集的依赖较少）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00005.jpeg)

.NET Core 提供了以下灵活的部署选项：

+   **基于框架的部署（FDD）**：需要在机器上安装.NET Core SDK

+   **自包含部署（SCD）**：在机器上不需要安装.NET Core SDK，.NET Core CLR 和框架类库是应用程序包的一部分

要安装.NET Core 2.0，您可以转到以下链接[`www.microsoft.com/net/core`](https://www.microsoft.com/net/core)并查看在 Windows、Linux、MAC 和 Docker 上安装的选项。

# .NET Core 2.0 的新改进

最新版本的.NET Core，2.0，带来了许多改进。.NET Core 2.0 是有史以来最快的版本，可以在包括各种 Linux 发行版、macOS（操作系统）和 Windows 在内的多个平台上运行。

Distros 代表 Linux 发行版（通常缩写为 distro），它是基于 Linux 内核和通常是一个软件集合的操作系统。

# 性能改进

.NET Core 更加健壮和高性能，并且由于其开源，微软团队与其他社区成员正在带来更多的改进。

以下是.NET Core 2.0 的改进部分。

# .NET Core 中的 RyuJIT 编译器

RyuJIT 是一种全新的 JIT 编译器，是对**即时**（**JIT**）编译器的完全重写，并生成更高效的本机机器代码。它比之前的 64 位编译器快两倍，并提供 30%更快的编译速度。最初，它只在 X64 架构上运行，但现在也支持 X86，开发人员可以同时为 X64 和 X86 使用 RyuJIT 编译器。.NET Core 2.0 在 X86 和 X64 平台上都使用 RyuJIT。

# 基于配置文件的优化

**基于配置文件的优化**（**PGO**）是 C++编译器使用的一种编译技术，用于生成优化的代码。它适用于运行时和 JIT 的内部本机编译组件。它分两步进行编译，如下所示：

1.  它记录了有关代码执行的信息。

1.  根据这些信息，它生成了更好的代码。

以下图表描述了代码的编译生命周期：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00006.gif)

在.NET Core 1.1 中，微软已经为 Windows X64 架构发布了 PGO，但在.NET Core 2.0 中，这已经添加到了 Windows X64 和 X86 架构。此外，根据观察结果，实际的启动时间主要由 Windows 的`coreclr.dll`和`clrjit.dll`占用。而在 Linux 上，分别是`libcoreclr.so`和`libclrjit.so`。

将 RyuJIT 与旧的 JIT 编译器 JIT32 进行比较，RyuJIT 在代码生成方面更加高效。JIT32 的启动时间比 RyuJIT 快，但代码效率不高。为了克服 RyuJIT 编译器的初始启动时间，微软使用了 PGO，这使得性能接近 JIT32 的性能，并在启动时实现了高效的代码和性能。

对于 Linux，每个发行版的编译器工具链都不同，微软正在开发一个单独的 Linux 版本的.NET，该版本使用适用于所有发行版的 PGO 优化。

# 简化的打包

使用.NET Core，我们可以从 NuGet 向我们的项目添加库。所有框架和第三方库都可以作为 NuGet 包添加。对于引用了许多库的大型应用程序，逐个添加每个库是一个繁琐的过程。.NET Core 2.0 简化了打包机制，并引入了可以作为一个单一包添加的元包，其中包含了所有与之链接的程序集。

例如，如果你想在.NET Core 2.0 中使用 ASP.NET Core，你只需要添加一个单一的包`Microsoft.AspNetCore.All`，使用 NuGet。

以下是将此包安装到你的项目中的命令：

```cs
Install-Package Microsoft.AspNetCore.All -Version 2.0.0
```

# 从.NET Core 1.x 升级到 2.0 的路径

.NET Core 2.0 带来了许多改进，这是人们想要将他们现有的.NET Core 应用程序从 1.x 迁移到 2.0 的主要原因。然而，在这个主题中，我们将通过一个清单来确保平稳迁移。

# 1\. 安装.NET Core 2.0

首先，在你的机器上安装.NET Core 2.0 SDK。它将在你的机器上安装最新的程序集，这将帮助你执行后续步骤。

# 2\. 升级 TargetFramework

这是最重要的一步，也是需要在.NET Core 项目文件中升级不同版本的地方。由于我们知道，对于`.csproj`类型，我们没有`project.json`，要修改框架和其他依赖项，我们可以使用任何 Visual Studio 编辑器编辑现有项目并修改 XML。

需要更改的 XML 节点是`TargetFramework`。对于.NET Core 2.0，我们需要将`TargetFramework`修改为`netcoreapp2.0`，如下所示：

```cs
<TargetFramework>netcoreapp2.0</TargetFramework>
```

接下来，你可以开始构建项目，这将升级.NET Core 依赖项到 2.0。然而，仍然有一些可能仍然引用旧版本的依赖项，需要使用 NuGet 包管理器显式地进行升级。

# 3\. 更新.NET Core SDK 版本

如果你的项目中已经添加了`global.json`，你需要将 SDK 版本更新为`2.0.0`，如下所示：

```cs
{ 
  "sdk": { 
    "version": "2.0.0" 
  } 
} 
```

# 4\. 更新.NET Core CLI

.NET Core CLI 也是你的.NET Core 项目文件中的一个重要部分。在迁移时，你需要将`DotNetCliToolReference`的版本升级到`2.0.0`，如下所示：

```cs
<ItemGroup> 
  <DotNetCliToolReference Include=
  "Microsoft.VisualStudio.Web.CodeGeneration.Tools" Version="2.0.0" /> 
</ItemGroup> 
```

根据你是否使用 Entity Framework Core、User Secrets 等，可能会添加更多的工具。你需要更新它们的版本。

# ASP.NET Core Identity 的更改

ASP.NET Core Identity 模型已经进行了一些改进和更改。一些类已经更名，你可以在以下链接找到它们：[`docs.microsoft.com/en-us/aspnet/core/migration`](http://docs.microsoft.com/en-us/aspnet/core/migration)。

# 探索.NET Core CLI 和新项目模板

**命令行界面**（**CLI**）是一个非常流行的工具，几乎在所有流行的框架中都有，比如 Yeoman Generator，Angular 等。它使开发人员能够执行命令来创建、构建和运行项目，恢复包等。

.NET CLI 提供了一组命令，可以从命令行界面执行，用于创建.NET Core 项目，恢复依赖项，构建和运行项目。在幕后，Visual Studio 2015/2017 和 Visual Studio Code 甚至使用这个工具来执行开发人员从他们的 IDE 中采取的不同选项；例如，要使用.NET CLI 创建一个新项目，我们可以运行以下命令：

```cs
dotnet new 
```

它将列出可用的模板和在创建项目时可以使用的简称。

以下是包含可以使用.NET Core CLI 创建/脚手架项目的项目模板列表的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00007.gif)

通过运行以下命令，将创建一个新的 ASP.NET Core MVC 应用程序：

```cs
dotnet new mvc 
```

以下屏幕截图显示了在运行上述命令后新的 MVC 项目的配置。它在运行命令的同一目录中创建项目并恢复所有依赖项：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00008.gif)

要安装 .NET Core CLI 工具集，有一些适用于 Windows、Linux 和 macOS 的本机安装程序可用。这些安装程序可以在您的计算机上安装和设置 .NET CLI 工具，并且开发人员可以从 CLI 运行命令。

以下是提供在 .NET Core CLI 中的命令及其描述的列表：

| **命令** | **描述** | **示例** |
| --- | --- | --- |
| `new` | 根据所选模板创建新项目 | `dotnet new razor` |
| `restore` | 恢复项目中定义的所有依赖项 | `dotnet restore` |
| `build` | 构建项目 | `dotnet build` |
| `run` | 在不进行任何额外编译的情况下运行源代码 | `dotnet run` |
| `publish` | 将应用程序文件打包到一个文件夹中以进行部署 | `dotnet publish` |
| `test` | 用于执行单元测试 | `dotnet test` |
| `vstest` | 执行指定文件中的单元测试 | `dotnet vstest [<TEST_FILE_NAMES>]` |
| `pack` | 将代码打包成 NuGet 包 | `dotnet pack` |
| `migrate` | 将 .NET Core 预览 2 迁移到 .NET Core 1.0 | `dotnet migrate` |
| `clean` | 清理项目的输出 | `dotnet clean` |
| `sln` | 修改 .NET Core 解决方案 | `dotnet sln` |
| `help` | 显示可通过 .NET CLI 执行的命令列表 | `dotnet help` |
| `store` | 将指定的程序集存储在运行时包存储中 | `dotnet store` |

以下是一些项目级别的命令，可用于添加新的 NuGet 包、删除现有的 NuGet 包、列出引用等： 

| **命令** | **描述** | **示例** |
| --- | --- | --- |
| `add package` | 向项目添加包引用 | `dotnet add package Newtonsoft.Json` |
| `remove package` | 从项目中删除包引用 | `dotnet remove package Newtonsoft.Json` |
| `add reference` | 向项目添加项目引用 | `dotnet add reference chapter1/proj1.csproj` |
| `remove reference` | 从项目中删除项目引用 | `dotnet remove reference chapter1/proj1.csproj` |
| `list reference` | 列出项目中的所有项目引用 | `dotnet list reference` |

以下是一些常见的 Entity Framework Core 命令，可用于添加迁移、删除迁移、更新数据库等。

| **命令** | **描述** | **示例** |
| --- | --- | --- |
| `dotnet ef migrations add` | 添加新的迁移 | `dotnet ef migrations add Initial`- `Initial` 是迁移的名称 |
| `dotnet ef migrations list` | 列出可用的迁移 | `dotnet ef migrations list` |
| `dotnet ef migrations remove` | 删除特定的迁移 | `dotnet ef migrations remove Initial`- `Initial` 是迁移的名称 |
| `dotnet ef database update` | 将数据库更新到指定的迁移 | `dotnet ef database update Initial`- `Initial` 是迁移的名称 |
| `dotnet ef database drop` | 删除数据库 | `dotnet ef database drop` |

以下是一些服务器级别的命令，可用于从机器中删除 NuGet 包的实际源存储库，将 NuGet 包添加到机器上的实际源存储库等：

| **命令** | **描述** | **示例** |
| --- | --- | --- |
| `nuget delete` | 从服务器中删除包 | `dotnet nuget delete Microsoft.AspNetCore.App 2.0` |
| `nuget push` | 将包推送到服务器并发布 | `dotnet nuget push foo.nupkg` |
| `nuget locals` | 列出本地 NuGet 资源 | `dotnet nuget locals -l all` |
| `msbuild` | 构建项目及其所有依赖项 | `dotnet msbuild` |
| `dotnet install script` | 用于安装 .NET CLI 工具和共享运行时的脚本 | `./dotnet-install.ps1 -Channel LTS` |

要运行上述命令，我们可以使用命令行中的名为 dotnet 的工具，并指定实际命令，然后跟随其后。当安装了.NET Core CLI 时，它会设置到 Windows OS 的 PATH 变量中，并且可以从任何文件夹访问。因此，例如，如果您在项目根文件夹中并且想要恢复依赖关系，您只需调用以下命令，它将恢复在项目文件中定义的所有依赖项：

```cs
dotnet restore 
```

上述命令将开始恢复项目文件中定义的依赖项或特定于项目的工具。工具和依赖项的恢复是并行进行的：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00009.gif)

我们还可以使用`--packages`参数设置包的恢复路径。但是，如果未指定此参数，则使用系统用户文件夹下的`.nuget/packages`文件夹。例如，Windows OS 的默认 NuGet 文件夹是`{systemdrive}:\Users\{user}\.nuget\packages`，Linux OS 分别是`/home/{user}`。

# 理解.NET 标准

在.NET 生态系统中，有许多运行时。我们有.NET Framework，这是安装在 Windows 操作系统上的全面机器范围框架，并为**Windows Presentation Foundation**（**WPF**）、Windows Forms 和 ASP.NET 提供应用程序模型。然后，我们有.NET Core，它针对跨平台操作系统和设备，并提供 ASP.NET Core、**Universal Windows Platform**（**UWP**）和针对 Xamarin 应用程序的 Mono 运行时，开发人员可以使用 Mono 运行时在 Xamarin 上开发应用程序，并在 iOS、Android 和 Windows OS 上运行。

以下图表描述了.NET 标准库如何提供.NET Framework、.NET Core 和 Xamarin 的公共构建块的抽象：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00010.jpeg)

所有这些运行时都实现了一个名为.NET 标准的接口，其中.NET 标准是每个运行时的.NET API 规范的实现。这使得您的代码可以在不同的平台上移植。这意味着为一个运行时创建的代码也可以由另一个运行时执行。.NET 标准是我们之前使用的**可移植类库**（**PCL**）的下一代。简而言之，PCL 是一个针对.NET 的一个或多个框架的类库。创建 PCL 时，我们可以选择需要使用该库的目标框架，并最小化程序集并仅使用所有框架通用的程序集。

.NET 标准不是可以下载或安装的 API 或可执行文件。它是一个规范，定义了每个平台实现的 API。每个运行时版本实现特定的.NET 标准版本。以下表格显示了每个平台实现的.NET 标准版本：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00011.jpeg)

我们可以看到.NET Core 2.0 实现了.NET 标准 2.0，而.NET Framework 4.5 实现了.NET 标准 1.1。因此，例如，如果我们有一个在.NET Framework 4.5 上开发的类库，这可以很容易地添加到.NET Core 项目中，因为它实现了一个更高版本的.NET 标准。另一方面，如果我们想要将.NET Core 程序集引用到.NET Framework 4.5 中，我们可以通过将.NET 标准版本更改为 1.1 来实现，而无需重新编译和构建我们的项目。

正如我们所了解的，.NET 标准的基本理念是在不同的运行时之间共享代码，但它与 PCL 的不同之处如下所示：

| **可移植类库（PCL）** | **.NET 标准** |
| --- | --- |
| 代表着微软平台并针对一组有限的平台 | 不受平台限制 |
| API 由您所针对的平台定义 | 精选的 API 集 |
| 它们不是线性版本 | 线性版本 |

.NET 标准也映射到 PCL，因此如果您有一个现有的 PCL 库，希望将其转换为.NET 标准，可以参考以下表格：

| **PCL 配置文件** | **.NET 标准** | **PCL 平台** |
| --- | --- | --- |
| 7 | 1.1 | .NET Framework 4.5, Windows 8 |
| 31 | 1.0 | Windows 8.1, Windows Phone Silverlight 8.1 |
| 32 | 1.2 | Windows 8.1, Windows Phone 8.1 |
| 44 | 1.2 | .NET Framework 4.5.1, Windows 8.1 |
| 49 | 1.0 | .NET Framework 4.5, Windows Phone Silverlight 8 |
| 78 | 1.0 | .NET Framework 4.5, Windows 8, Windows Phone Silverlight 8 |
| 84 | 1.0 | Windows Phone 8.1, Windows Phone Silverlight 8.1 |
| 111 | 1.1 | .NET Framework 4.5, Windows 8, Windows Phone 8.1 |
| 151 | 1.2 | .NET Framework 4.5.1, Windows 8.1, Windows Phone 8.1 |
| 157 | 1.0 | Windows 8.1, Windows Phone 8.1, Windows Phone Silverlight 8.1 |
| 259 | 1.0 | .NET Framework 4.5, Windows 8, Windows Phone 8.1, Windows Phone Silverlight 8 |

考虑到前面的表格，如果我们有一个 PCL，它的目标是.NET Framework 4.5.1、Windows 8.1 和 Windows Phone 8.1，PCL 配置文件设置为 151，它可以转换为版本 1.2 的.NET 标准库。

# .NET 标准的版本控制

与 PCL 不同，每个.NET 标准版本都是线性版本化的，并包含了以前版本的 API 等。一旦版本发布，它就被冻结，不能更改，并且应用程序可以轻松地针对该版本。

以下图表是.NET 标准版本化的表示。版本越高，可用的 API 就越多，而版本越低，可用的平台就越多：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00012.jpeg)

# .NET 标准 2.0 的新改进

.NET Core 2.0 针对.NET 标准 2.0，并提供了两个主要好处。这包括从上一个版本提供的 API 数量的增加以及其兼容模式，我们将在本章进一步讨论。

# .NET 标准 2.0 中的更多 API

.NET 标准 2.0 中添加了更多的 API，数量几乎是上一个.NET 标准 1.0 的两倍。此外，像 DataSet、集合、二进制序列化、XML 模式等 API 现在都是.NET 标准 2.0 规范的一部分。这增加了从.NET Framework 到.NET Core 的代码可移植性。

以下图表描述了每个领域中添加的 API 的分类视图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00013.gif)

# 兼容模式

尽管已经将超过 33K 个 API 添加到.NET 标准 2.0 中，但许多 NuGet 包仍然针对.NET Framework，并且将它们移动到.NET 标准是不可能的，因为它们的依赖项仍然没有针对.NET 标准。但是，使用.NET 标准 2.0，我们仍然可以添加显示警告但不会阻止将这些包添加到我们的.NET 标准库中的包。

在底层，.NET 标准 2.0 使用兼容性 shim，解决了第三方库的兼容性问题，并且在引用这些库时变得更加容易。在 CLR 世界中，程序集的标识是类型标识的一部分。这意味着当我们在.NET Framework 中说`System.Object`时，我们引用的是`[mscorlib]System.Object`，而在.NET 标准中，我们引用的是`[netstandard]System.Object`，因此，如果我们引用任何.NET Framework 的程序集，它不能轻松地在.NET 标准上运行，因此会出现兼容性问题。为了解决这个问题，他们使用了类型转发，提供了一个虚假的`mscorlib`程序集，该程序集将所有类型转发到.NET 标准实现。

以下是.NET Framework 库如何在任何.NET 标准实现中使用类型转发方法运行的表示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00014.jpeg)

另一方面，如果我们有一个.NET Framework 库，并且想要引用一个.NET 标准库，它将添加`netstandard`虚假程序集，并通过使用.NET Framework 实现对所有类型进行类型转发：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00015.jpeg)

为了抑制警告，我们可以为特定的 NuGet 包添加 NU1701，这些包的依赖项没有针对.NET 标准。

# 创建.NET 标准库

要创建.NET Standard 库，可以使用 Visual Studio 或.NET Core CLI 工具集。从 Visual Studio，我们只需点击如下屏幕截图中显示的.NET Standard 选项，然后选择 Class Library (.NET Standard)。

创建.NET Standard 库后，我们可以将其引用到任何项目，并根据需要更改版本，具体取决于我们要引用的平台。版本可以从属性面板更改，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00016.jpeg)

# ASP.NET Core 2.0 的新功能

ASP.NET Core 是开发云就绪和企业 Web 应用程序的最强大平台之一，可跨平台运行。Microsoft 在 ASP.NET Core 2.0 中添加了许多功能，包括新的项目模板、Razor 页面、简化的 Application Insights 配置、连接池等。

以下是 ASP.NET Core 2.0 的一些新改进。

# ASP.NET Core Razor 页面

ASP.NET Core 中引入了基于 Razor 语法的页面。现在，开发人员可以在 HTML 上开发应用程序并写语法，而无需放置控制器。相反，有一个代码后台文件，可以在其中处理其他事件和逻辑。后端页面类继承自`PageModel`类，可以使用 Razor 语法中的`Model`对象访问其成员变量和方法。以下是一个简单的示例，其中包含在`code-behind`类中定义的`GetTitle`方法，并在视图页面中使用：

```cs
public class IndexModel : PageModel 
{ 
  public string GetTitle() => "Home Page"; 
}
```

这是`Index.cshtml`文件，通过调用`GetCurrentDate`方法显示日期：

```cs
@page 
@model IndexModel 
@{ 
  ViewData["Title"] = Model.GetTitle(); 
} 
```

# 发布时自动页面和视图编译

在发布 ASP.NET Core Razor 页面项目时，所有视图都会编译成一个单一的程序集，发布文件夹的大小相对较小。如果我们希望在发布过程中生成视图和所有`.cshtml`文件，我们必须添加一个条目，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00017.gif)

# Razor 对 C# 7.1 的支持

现在，我们可以使用 C# 7.1 功能，如推断的元组名称、泛型模式匹配和表达式。为了添加此支持，我们必须在项目文件中添加一个 XML 标记，如下所示：

```cs
<LangVersion>latest</LangVersion>
```

# Application Insights 的简化配置

使用 ASP.NET Core 2.0，您可以通过单击一次启用 Application Insights。用户只需右键单击项目，然后单击添加 | Application Insights Telemetry，然后通过简单的向导即可启用 Application Insights。这允许您监视应用程序，并提供来自 Azure Application Insights 的完整诊断信息。

我们还可以从 Visual Studio 2017 IDE 的 Application Insights 搜索窗口查看完整的遥测，并从 Application Insights 趋势监视趋势。这两个窗口都可以从 View | Other Windows 菜单中打开。

# 在 Entity Framework Core 2.0 中池化连接

最近发布的 Entity Framework Core 2.0 中，我们可以使用`Startup`类中的`AddDbContextPool`方法来池化连接。正如我们已经知道的，在 ASP.NET Core 中，我们必须使用**依赖注入**（**DI**）在`Startup`类的`ConfigureServices`方法中添加`DbContext`对象，并在控制器中使用时，会注入`DbContext`对象的新实例。为了优化性能，Microsoft 提供了这个`AddDbContextPool`方法，它首先检查可用的数据库上下文实例，并在需要时注入它。另一方面，如果数据库上下文实例不可用，则会创建并注入一个新实例。

以下代码显示了如何在`Startup`类的`ConfigureServices`方法中添加`AddDbContext`：

```cs
services.AddDbContextPool<SampleDbContext>( 
  options => options.UseSqlServer(connectionString)); 
```

Owned Types、表拆分、数据库标量函数映射和字符串插值等功能已添加了一些新特性，您可以从以下链接中查看：[`docs.microsoft.com/en-us/ef/core/what-is-new/`](https://docs.microsoft.com/en-us/ef/core/what-is-new/)。

# C# 7.0 中的新功能

C#是.NET 生态系统中最流行的语言，最早是在 2002 年与.NET Framework 一起推出的。C#的当前稳定版本是 7。以下图表显示了 C# 7.0 的进展情况以及不同年份引入的版本：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00018.jpeg)

以下是 C# 7.0 引入的一些新功能：

+   元组

+   模式匹配

+   引用返回

+   异常作为表达式

+   本地函数

+   输出变量文字

+   异步主函数

# 元组

元组解决了从方法返回多个值的问题。传统上，我们可以使用引用变量的输出变量，如果它们从调用方法中修改，则值会更改。但是，没有参数，存在一些限制，例如不能与`async`方法一起使用，不建议与外部服务一起使用。

元组具有以下特点：

+   它们是值类型。

+   它们可以转换为其他元组。

+   元组元素是公共且可变的。

元组表示为`System.Tuple<T>`，其中`T`可以是任何类型。以下示例显示了如何使用元组与方法以及如何调用值：

```cs
static void Main(string[] args) 
{ 
  var person = GetPerson(); 
  Console.WriteLine($"ID : {person.Item1}, 
  Name : {person.Item2}, DOB : {person.Item3}");       
} 
static (int, string, DateTime) GetPerson() 
{ 
  return (1, "Mark Thompson", new DateTime(1970, 8, 11)); 
}
```

正如你可能已经注意到的，项目是动态命名的，第一个项目被命名为`Item1`，第二个为`Item2`，依此类推。另一方面，我们也可以为项目命名，以便调用方了解值，这可以通过为元组中的每个参数添加参数名来实现，如下所示：

```cs
static void Main(string[] args) 
{ 
  var person = GetPerson(); 
  Console.WriteLine($"ID : {person.id}, Name : {person.name}, 
  DOB : {person.dob}");  
} 
static (int id, string name, DateTime dob) GetPerson() 
{ 
  return (1, "Mark Thompson", new DateTime(1970, 8, 11)); 
} 
```

要了解更多关于元组的信息，请查看以下链接：

[`docs.microsoft.com/en-us/dotnet/csharp/tuples`](https://docs.microsoft.com/en-us/dotnet/csharp/tuples)。

# 模式

模式匹配是执行语法测试的过程，以验证值是否与某个模型匹配。有三种类型的模式：

+   常量模式。

+   类型模式。

+   Var 模式。

# 常量模式

常量模式是检查常量值的简单模式。考虑以下示例：如果`Person`对象为空，则返回并退出`body`方法。

`Person`类如下：

```cs
class Person 
{ 
  public int ID { set; get; } 
  public string Name { get; set; } 

  public DateTime DOB { get; set; } 
} 
Person class that contains three properties, namely ID, Name, and DOB (Date of Birth).
```

以下语句检查`person`对象是否具有空常量值，并在对象为空时返回它：

```cs
if (person is null) return; 
```

# 类型模式

类型模式可用于对象，以验证它是否与类型匹配或是否满足基于指定条件的表达式。假设我们需要检查`PersonID`是否为`int`；将该`ID`分配给另一个变量`i`，并在程序中使用它，否则`return`：

```cs
if (!(person.ID is int i)) return; 

Console.WriteLine($"Person ID is {i}"); 
```

我们还可以使用多个逻辑运算符来评估更多条件，如下所示：

```cs
if (!(person.ID is int i) && !(person.DOB>DateTime.Now.AddYears(-20))) return;   
```

前面的语句检查`Person.ID`是否为空，以及人是否年龄大于 20。

# Var 模式

var 模式检查`var`是否等于某种类型。以下示例显示了如何使用`var`模式来检查类型并打印`Type`名称：

```cs
if (person is var Person) Console.WriteLine($"It is a person object and type is {person.GetType()}"); 
```

要了解更多关于模式的信息，可以参考以下链接：[`docs.microsoft.com/en-us/dotnet/csharp/whats-new/csharp-7#pattern-matching`](https://docs.microsoft.com/en-us/dotnet/csharp/whats-new/csharp-7#pattern-matching)。

# 引用返回

引用返回允许方法返回一个对象的引用，而不是它的值。我们可以通过在方法签名中的类型前添加`ref`关键字来定义引用返回值，并在方法本身返回对象时返回它。

以下是允许引用返回的方法的签名：

```cs
public ref Person GetPersonInformation(int ID); 

Following is the implementation of the GetPersonInformation method that uses the ref keyword while returning the person's object.  

Person _person; 
public ref Person GetPersonInformation(int ID) 
{ 
  _person = CallPersonHttpService(); 
  return ref _person; 
} 
```

# 表达式体成员扩展

表达式体成员是在 C# 6.0 中引入的，其中方法的语法表达可以以更简单的方式编写。在 C# 7.0 中，我们可以在构造函数、析构函数、异常等中使用此功能。

以下示例显示了如何使用表达式体成员简化构造函数和析构函数的语法表达：

```cs
public class PersonManager 
{ 
  //Member Variable 
  Person _person; 

  //Constructor 
  PersonManager(Person person) => _person = person; 

  //Destructor 
  ~PersonManager() => _person = null; 
} 
```

有了属性，我们还可以简化语法表达，以下是如何编写的基本示例：

```cs
private String _name; 
public String Name 
{ 
  get => _name; 
  set => _name = value; 
} 
```

我们还可以使用表达式体语法表达异常并简化表达式，如下所示：

```cs
private String _name; 
public String Name 
{ 
  get => _name; 
  set => _name = value ?? throw new ArgumentNullException(); 
} 
```

在前面的例子中，如果值为 null，将抛出一个新的`ArgumentNullException`。

# 创建局部函数

在函数内部创建的函数称为局部函数。这些主要用于定义必须在函数本身范围内的辅助函数。以下示例显示了如何通过编写局部函数并递归调用它来获得数字的阶乘：

```cs
static void Main(string[] args) 
{ 
  Console.WriteLine(ExecuteFactorial(4));          
} 

static long ExecuteFactorial(int n) 
{ 
  if (n < 0) throw new ArgumentException("Must be non negative", 
  nameof(n)); 

  else return CheckFactorial(n); 

  long CheckFactorial(int x) 
  { 
    if (x == 0) return 1; 
    return x * CheckFactorial(x - 1); 
  } 
}
```

# 输出变量

在 C# 7.0 中，当使用`out`变量时，我们可以编写更清晰的代码。正如我们所知，要使用`out`变量，我们必须首先声明它们。通过新的语言增强，我们现在可以只需将`out`作为前缀写入，并指定我们需要将该值分配给的变量的名称。

为了澄清这个概念，我们首先看一下传统的方法，如下所示：

```cs
public void GetPerson() 
{ 
  int year; 
  int month; 
  int day; 
  GetPersonDOB(out year, out month, out day); 
} 

public void GetPersonDOB(out int year, out int month, out int day ) 
{ 
  year = 1980; 
  month = 11; 
  day = 3; 
} 
```

在 C# 7.0 中，我们可以简化前面的`GetPerson`方法，如下所示：

```cs
public void GetPerson() 
{ 
  GetPersonDOB(out int year, out int month, out int day); 
} 
```

# Async Main

正如我们已经知道的，在.NET Framework 中，`Main`方法是应用程序/程序由操作系统执行的主要入口点。例如，在 ASP.NET Core 中，`Program.cs`是定义`Main`方法的主要类，它创建一个`WebHost`对象，运行 Kestrel 服务器，并根据`Startup`类中配置的方式加载 HTTP 管道。

在以前的 C#版本中，`Main`方法具有以下签名：

```cs
public static void Main();
public static void Main(string[] args);
public static int Main();
public static int Main(string[] args);
```

在 C# 7.0 中，我们可以使用 Async Main 执行异步操作。Async/Await 功能最初是在.NET Framework 4.5 中发布的，以便异步执行方法。如今，许多 API 提供了 Async/Await 方法来执行异步操作。

以下是使用 C# 7.1 添加的`Main`方法的一些附加签名：

```cs
public static Task Main();
public static Task Main(string[] args);
public static Task<int> Main();
public static Task<int> Main(string[] args);
```

由于前面的异步签名，现在我们可以从`Main`入口点本身调用`async`方法，并使用 await 执行异步操作。以下是调用`RunAsync`方法而不是`Run`的 ASP.NET Core 的简单示例：

```cs
public class Program
{
  public static async Task Main(string[] args)
  {
    await BuildWebHost(args).RunAsync();
  }
  public static IWebHost BuildWebHost(string[] args) =>
    WebHost.CreateDefaultBuilder(args)
    .UseStartup<Startup>()
    .Build();
}
```

Async Main 是 C# 7.1 的一个特性，要在 Visual Studio 2017 中启用此功能，可以转到项目属性，单击 Advance 按钮，并将语言版本设置为 C#最新的次要版本（latest），如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00019.gif)

# 编写优质代码

对于每个性能高效的应用程序，代码质量都起着重要作用。正如我们已经知道的，Visual Studio 是开发.NET 应用程序最流行的**集成开发环境**（**IDE**），由于 Roslyn（.NET 编译器 SDK）公开了编译器平台作为 API，许多功能已经被引入，不仅扩展了 Visual Studio 的功能，而且增强了开发体验。

实时静态代码分析是 Visual Studio 中可以用于开发.NET 应用程序的核心功能之一，它在编写代码时提供代码分析。由于此功能使用 Roslyn API，许多其他第三方公司也引入了一套可以使用的分析器。我们还可以为特定需求开发自己的分析器，这并不是一个非常复杂的过程。让我们快速介绍一下如何在我们的.NET Core 项目中使用实时静态代码分析以及它如何通过分析代码并提供警告、错误和潜在修复来增强开发体验。

我们可以将分析器作为 NuGet 包添加。在 NuGet.org 上有许多可用的分析器，一旦我们将任何分析器添加到我们的项目中，它就会在项目的*Dependencies*部分添加一个新的*Analyzer*节点。然后我们可以自定义规则，抑制警告或错误等。

让我们在我们的.NET Core 项目中从 Visual Studio 添加一个新的分析器。如果你不知道要添加哪个分析器，你可以在 NuGet 包管理器窗口中只需输入*analyzers*，它就会为你列出所有的分析器。我们将只添加`Microsoft.CodeQuality.Analyzers`分析器，其中包含一些不错的规则：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00020.jpeg)

一旦选择的分析器被添加，一个新的`Analyzers`节点将被添加到我们的项目中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00021.jpeg)

在上图中，我们可以看到`Analyzers`节点已经添加了三个节点，要查看/管理规则，我们可以展开子节点`Microsoft.CodeQuality.Analyzers`和`Microsoft.CodeQuality.CSharp.Analyzers`，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00022.jpeg)

此外，我们还可以通过右键单击规则并选择严重性来更改规则的严重性，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00023.jpeg)

在上图中，规则 CA1008 指出枚举应该有一个值为零。让我们测试一下，看看它是如何工作的。

创建一个简单的`Enum`并指定值，如下所示：

```cs
public enum Status 
{ 
  Create =1, 
  Update =2, 
  Delete =3, 
} 
```

当你编写这段代码时，你会立刻看到以下错误，并提供潜在的修复方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00024.jpeg)

最后，这是我们可以应用的修复方法，错误将消失：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00025.jpeg)

你还可以使用一个名为 Roslynator 的流行的 Visual Studio 扩展程序，可以从以下链接下载。它包含了超过 190 个适用于基于 C#的项目的分析器和重构工具：[`marketplace.visualstudio.com/items?itemName=josefpihrt.Roslynator`](https://marketplace.visualstudio.com/items?itemName=josefpihrt.Roslynator)。

实时静态代码分析是一个很棒的功能，它帮助开发人员编写符合最佳准则和实践的高质量代码。

# 总结

在本章中，我们了解了.NET Core 框架以及.NET Core 2.0 引入的一些新改进。我们还研究了 C# 7 的新功能，以及如何编写更干净的代码和简化语法表达。最后，我们讨论了编写高质量代码的主题，以及如何利用 Visual Studio 2017 提供的代码分析功能来添加满足我们需求的分析器到我们的项目中。下一章将是一个关于.NET Core 的深入章节，将涵盖.NET Core 内部和性能改进的主题。


# 第二章：理解.NET Core 内部和性能测量

在开发应用程序架构时，了解.NET 框架的内部工作原理对确保应用程序性能的质量起着至关重要的作用。在本章中，我们将重点关注.NET Core 的内部机制，这可以帮助我们为任何应用程序编写高质量的代码和架构。本章将涵盖.NET Core 内部的一些核心概念，包括编译过程、垃圾回收和 Framework Class Library（FCL）。我们将通过使用 BenchmarkDotNet 工具来完成本章，该工具主要用于测量代码性能，并且强烈推荐用于在应用程序中对代码片段进行基准测试。

在本章中，您将学习以下主题：

+   .NET Core 内部

+   利用 CPU 的多个核心实现高性能

+   发布构建如何提高性能

+   对.NET Core 2.0 应用程序进行基准测试

# .NET Core 内部

.NET Core 包含两个核心组件——运行时 CoreCLR 和基类库 CoreFX。在本节中，我们将涵盖以下主题：

+   CoreFX

+   CoreCLR

+   理解 MSIL、CLI、CTS 和 CLS

+   CLR 的工作原理

+   从编译到执行——在幕后

+   垃圾回收

+   .NET 本机和 JIT 编译

# CoreFX

CoreFX 是.NET Core 一组库的代号。它包含所有以 Microsoft.*或 System.*开头的库，并包含集合、I/O、字符串操作、反射、安全性等许多功能。

CoreFX 是与运行时无关的，可以在任何平台上运行，而不管它支持哪些 API。

要了解每个程序集的更多信息，您可以参考.NET Core 源浏览器[`source.dot.net`](https://source.dot.net)。

# CoreCLR

CoreCLR 为.NET Core 应用程序提供了公共语言运行时环境，并管理完整应用程序生命周期的执行。在程序运行时，它执行各种操作。CoreCLR 的操作包括内存分配、垃圾回收、异常处理、类型安全、线程管理和安全性。

.NET Core 的运行时提供与.NET Framework 相同的垃圾回收（GC）和一个新的更优化的即时编译器（JIT），代号为 RyuJIT。当.NET Core 首次发布时，它仅支持 64 位平台，但随着.NET Core 2.0 的发布，现在也可用于 32 位平台。但是，32 位版本仅受 Windows 操作系统支持。

# 理解 MSIL、CLI、CTS 和 CLS

当我们构建项目时，代码被编译为中间语言（IL），也称为 Microsoft 中间语言（MSIL）。MSIL 符合公共语言基础设施（CLI），其中 CLI 是提供公共类型系统和语言规范的标准，分别称为公共类型系统（CTS）和公共语言规范（CLS）。

CTS 提供了一个公共类型系统，并将语言特定类型编译为符合规范的数据类型。它将所有.NET 语言的数据类型标准化为语言互操作的公共数据类型。例如，如果代码是用 C#编写的，它将被转换为特定的 CTS。

假设我们有两个变量，在以下使用 C#定义的代码片段中：

```cs
class Program 
{ 
  static void Main(string[] args) 
  { 
    int minNo = 1; 
    long maxThroughput = 99999; 
  } 
} 
```

在编译时，编译器将 MSIL 生成为一个程序集，通过 CoreCLR 可执行 JIT 并将其转换为本机机器代码。请注意，`int`和`long`类型分别转换为`int32`和`int64`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00026.jpeg)

并不是每种语言都必须完全符合 CTS，并且它也可以支持 CTS 的较小印记。例如，当 VB.NET 首次发布在.NET Framework 中时，它只支持有符号整数数据类型，并且没有使用无符号整数的规定。通过.NET Framework 的后续版本，现在通过.NET Core 2.0，我们可以使用所有托管语言，如 C#、F#和 VB.NET，来开发应用程序，并轻松引用任何项目的程序集。

# CLR 的工作原理

CLR 实现为一组在进程中加载的内部库，并在应用程序进程的上下文中运行。在下图中，我们有两个运行的.NET Core 应用程序，名为 App1.exe 和 App2.exe*.*每个黑色方框代表应用程序进程地址空间，其中应用程序 App1.exe 和 App2.exe 并行运行其自己的 CLR 版本：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00027.gif)

在打包.NET Core 应用程序时，我们可以将其发布为**依赖框架部署**（**FDDs**）或**自包含部署**（**SCDs**）。在 FDDs 中，发布的包不包含.NET Core 运行时，并期望目标/托管系统上存在.NET Core。对于 SCDs，所有组件，如.NET Core 运行时和.NET Core 库，都包含在发布的包中，并且目标系统上不需要.NET Core 安装。

要了解有关 FDDs 或 SCDs 的更多信息，请参阅[`docs.microsoft.com/en-us/dotnet/core/deploying/`](https://docs.microsoft.com/en-us/dotnet/core/deploying/)。

# 从编译到执行-底层

.NET Core 编译过程类似于.NET Framework 使用的过程。项目构建时，MSBuild 系统调用内部.NET CLI 命令，构建项目并生成程序集（`.dll`）或可执行文件（`.exe`）。该程序集包含包含程序集元数据的清单，包括版本号、文化、类型引用信息、有关引用程序集的信息以及程序集中其他文件及其关联的列表。该程序集清单存储在 MSIL 代码中或独立的**可移植可执行文件**（**PE**）中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00028.gif)

现在，当可执行文件运行时，会启动一个新进程并引导.NET Core 运行时，然后初始化执行环境，设置堆和线程池，并将程序集加载到进程地址空间中。根据程序，然后执行主入口方法（`Main`）并进行 JIT 编译。从这里开始，代码开始执行，对象开始在堆上分配内存，原始类型存储在堆栈上。对于每个方法，都会进行 JIT 编译，并生成本机机器代码。

当 JIT 编译完成，并在生成本机机器代码之前，它还执行一些验证。这些验证包括以下内容：

+   验证，在构建过程中生成了 MSIL

+   验证，在 JIT 编译过程中是否修改了任何代码或添加了新类型

+   验证，已生成了针对目标机器的优化代码

# 垃圾收集

CLR 最重要的功能之一是垃圾收集器。由于.NET Core 应用程序是托管应用程序，大部分垃圾收集都是由 CLR 自动完成的。CLR 有效地在内存中分配对象。CLR 不仅会定期调整虚拟内存资源，还会减少底层虚拟内存的碎片，使其在空间方面更加高效。

当程序运行时，对象开始在堆上分配内存，并且每个对象的地址都存储在堆栈上。这个过程会一直持续，直到内存达到最大限制。然后 GC 开始起作用，通过移除未使用的托管对象并分配新对象来回收内存。这一切都是由 GC 自动完成的，但也可以通过调用`GC.Collect`方法来调用 GC 执行垃圾收集。

让我们举一个例子，我们在`Main`方法中有一个名为`c`的`Car`对象。当函数被执行时，CLR 将`Car`对象分配到堆内存中，并且将指向堆上`Car`对象的引用存储在堆栈地址中。当垃圾收集器运行时，它会从堆中回收内存，并从堆栈中移除引用：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00029.gif)

需要注意的一些重要点是，垃圾收集是由 GC 自动处理托管对象的，如果有任何非托管对象，比如数据库连接、I/O 操作等，它们需要显式地进行垃圾收集。否则，GC 会高效地处理托管对象，并确保应用程序在进行 GC 时不会出现性能下降。

# GC 中的世代

垃圾收集中有三种世代，分别为第零代、第一代和第二代。在本节中，我们将看一下世代的概念以及它对垃圾收集器性能的影响。

假设我们运行一个创建了三个名为 Object1、Object2 和 Object3 的对象的应用程序。这些对象将在第零代中分配内存：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00030.gif)

现在，当垃圾收集器运行时（这是一个自动过程，除非你从代码中显式调用垃圾收集器），它会检查应用程序不需要的对象，并且在程序中没有引用。它将简单地移除这些对象。例如，如果 Object1 的范围在任何地方都没有被引用，那么这个对象的内存将被回收。然而，另外两个对象 Object1 和 Object2 仍然在程序中被引用，并且将被移动到第一代。

现在，假设我们创建了两个名为 Object4 和 Object5 的对象。我们将它们存储在第零代槽中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00031.gif)

当垃圾收集再次运行时，它将在第零代找到两个名为 Object4 和 Object5 的对象，并且在第一代找到两个名为 Object2 和 Object3 的对象。垃圾收集器将首先检查第零代中这些对象的引用，如果它们没有被应用程序使用，它们将被移除。对于第一代的对象也是一样。例如，如果 Object3 仍然被引用，它将被移动到第二代，而 Object2 将从第一代中被移除，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00032.gif)

这种世代的概念实际上优化了 GC 的性能，存储在第二代的对象更有可能被存储更长时间。GC 执行更少的访问，而不是一遍又一遍地检查每个对象。第一代也是如此，它也不太可能回收空间，而不像第零代。

# .NET 本机和 JIT 编译

JIT 编译主要在运行时进行，它将 MSIL 代码转换为本机机器代码。这是代码第一次运行时进行的，比其后的运行需要更多的时间。如今，在.NET Core 中，我们正在为 CPU 资源和内存有限的移动设备和手持设备开发应用程序。目前，**Universal Windows Platform**（**UWP**）和 Xamarin 平台运行在.NET Core 上。使用这些平台，.NET Core 会在编译时或生成特定平台包时自动生成本机程序集。虽然这不需要在运行时进行 JIT 编译过程，但最终会增加应用程序的启动时间。这种本机编译是通过一个名为.NET Native 的组件完成的。

.NET Native 在语言特定编译器完成编译过程后开始编译过程。.NET Native 工具链读取语言编译器生成的 MSIL，并执行以下操作：

+   它从 MSIL 中消除了元数据。

+   在比较字段值时，它用静态本机代码替换依赖反射和元数据的代码。

+   它检查应用程序调用的代码，并只在最终程序集中包含那些代码。

+   它用不带 JIT 编译器的重构运行时替换了完整的 CLR。重构后的运行时与应用程序一起，并包含在名为`mrt100_app.dll`的程序集中。

# 利用 CPU 的多个核心实现高性能

如今，应用程序的性质更加注重连接性，有时它们的操作需要更长的执行时间。我们也知道，现在所有的计算机都配备了多核处理器，有效地利用这些核心可以提高应用程序的性能。诸如网络/IO 之类的操作存在延迟问题，应用程序的同步执行往往会导致长时间的等待。如果长时间运行的任务在单独的线程中或以异步方式执行，结果操作将花费更少的时间并提高响应性。另一个好处是性能，它实际上利用了处理器的多个核心并同时执行任务。在.NET 世界中，我们可以通过将任务分割成多个线程并使用经典的多线程编程 API，或者更简化和先进的模型，即**任务编程库**（**TPL**）来实现响应性和性能。TPL 现在在.NET Core 2.0 中得到支持，我们很快将探讨如何使用它在多个核心上执行任务。

TPL 编程模型是基于任务的。任务是工作单元，是正在进行的操作的对象表示。

可以通过编写以下代码来创建一个简单的任务：

```cs
static void Main(string[] args) 
{ 
  Task t = new Task(execute); 
  t.Start(); 
  t.Wait(); 
} 

private static void Execute() { 
  for (int i = 0; i < 100; i++) 
  { 
    Console.WriteLine(i); 
  } 
}
```

在上述代码中，任务可以使用`Task`对象进行初始化，其中`Execute`是在调用`Start`方法时执行的计算方法。`Start`方法告诉.NET Core 任务可以开始并立即返回。它将程序执行分成两个同时运行的线程。第一个线程是实际的应用程序线程，第二个线程是执行`execute`方法的线程。我们使用了`t.Wait`方法来等待工作任务在控制台上显示结果。否则，一旦程序退出`Main`方法下的代码块，应用程序就会结束。

并行编程的目标是有效地利用多个核心。例如，我们在单核处理器上运行上述代码。这两个线程将运行并共享同一个处理器。然而，如果相同的程序可以在多核处理器上运行，它可以通过分别利用每个核心在多个核心上运行，从而提高性能并实现真正的并行性：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00033.jpeg)

与 TPL 不同，经典的`Thread`对象不能保证您的线程将在 CPU 的不同核心上运行。然而，使用 TPL，它保证每个线程将在不同的线程上运行，除非它达到了与 CPU 一样多的任务数量并共享核心。

要了解 TPL 提供的更多信息，请参阅

[`docs.microsoft.com/en-us/dotnet/standard/parallel-programming/task-parallel-library-tpl`](https://docs.microsoft.com/en-us/dotnet/standard/parallel-programming/task-parallel-library-tpl)。

# 发布构建如何提高性能

.NET 应用程序提供了发布和调试两种构建模式。调试模式在编写代码或解决错误时通常使用，而发布构建模式通常在打包应用程序以部署到生产服务器时使用。在开发部署包时，开发人员经常忘记将构建模式更新为发布构建，然后在部署应用程序时遇到性能问题：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00034.jpeg)

以下表格显示了调试模式和发布模式之间的一些区别：

| 调试 | 发布 |
| --- | --- |
| 编译器不对代码进行优化 | 使用发布模式构建时，代码会被优化和缩小 |
| 在异常发生时捕获并抛出堆栈跟踪 | 不捕获堆栈跟踪 |
| 调试符号被存储 | 所有在#debug 指令下的代码和调试符号都被移除 |
| 源代码在运行时使用更多内存 | 源代码在运行时使用更少内存 |

# 对.NET Core 2.0 应用程序进行基准测试

基准测试应用程序是评估和比较与约定标准的工件的过程。要对.NET Core 2.0 应用程序代码进行基准测试，我们可以使用`BenchmarkDotNet`工具，该工具提供了一个非常简单的 API 来评估应用程序中代码的性能。通常，在微观级别进行基准测试，例如使用类和方法，不是一件容易的事，需要相当大的努力来衡量性能，而`BenchmarkDotNet`则完成了所有与基准测试解决方案相关的低级管道和复杂工作。

# 探索`BenchmarkDotNet`

在本节中，我们将探索`BenchmarkDotNet`并学习如何有效地使用它来衡量应用程序性能。

可以简单地通过 NuGet 包管理器控制台窗口或通过项目引用部分来安装`BenchmarkDotNet`。要安装`BenchmarkDotNet`，执行以下命令：

```cs
Install-Package BenchmarkDotNet 
```

上述命令从`NuGet.org`添加了一个`BenchmarkDotNet`包。

为了测试`BenchmarkDotNet`工具，我们将创建一个简单的类，其中包含两种方法来生成一个包含`10`个数字的斐波那契数列。斐波那契数列可以用多种方式实现，这就是为什么我们使用它来衡量哪个代码片段更快，更高效。

这是第一个以迭代方式生成斐波那契数列的方法：

```cs
public class TestBenchmark 
{ 
  int len= 10; 
  [Benchmark] 
  public  void Fibonacci() 
  { 
    int a = 0, b = 1, c = 0; 
    Console.Write("{0} {1}", a, b); 

    for (int i = 2; i < len; i++) 
    { 
      c = a + b; 
      Console.Write(" {0}", c); 
      a = b; 
      b = c; 
    } 
  } 
} 
```

这是另一种使用递归方法生成斐波那契数列的方法：

```cs

[Benchmark] 
public  void FibonacciRecursive() 
{ 
  int len= 10; 
  Fibonacci_Recursive(0, 1, 1, len); 
} 

private void Fibonacci_Recursive(int a, int b, int counter, int len) 
{ 
  if (counter <= len) 
  { 
    Console.Write("{0} ", a); 
    Fibonacci_Recursive(b, a + b, counter + 1, len); 
  } 
}  
```

请注意，斐波那契数列的两个主要方法都包含`Benchmark`属性。这实际上告诉`BenchmarkRunner`要测量包含此属性的方法。最后，我们可以从应用程序的主入口点调用`BenchmarkRunner`，该入口点测量性能并生成报告，如下面的代码所示：

```cs
static void Main(string[] args)
{
  BenchmarkRunner.Run<TestBenchmark>();
  Console.Read();
}
```

一旦运行基准测试，我们将得到以下报告：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00035.jpeg)

此外，它还在运行`BenchmarkRunner`的应用程序的根文件夹中生成文件。这是包含有关`BenchmarkDotNet`版本和操作系统、处理器、频率、分辨率和计时器详细信息、.NET 版本（在我们的情况下是.NET Core SDK 2.0.0）、主机等信息的.html 文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00036.jpeg)

表格包含四列。但是，我们可以添加更多列，默认情况下是可选的。我们也可以添加自定义列。Method 是包含基准属性的方法的名称，Mean 是所有测量所需的平均时间（us 为微秒），Error 是处理错误所需的时间，StdDev 是测量的标准偏差。

比较两种方法后，`FibonacciRecursive`方法更有效，因为平均值、错误和 StdDev 值都小于`Fibonacci`方法。

除了 HTML 之外，还创建了两个文件，一个**逗号分隔值**（CSV）文件和一个**Markdown 文档**（MD）文件，其中包含相同的信息。

# 它是如何工作的

基准为每个基准方法在运行时生成一个项目，并以发布模式构建它。它尝试多种组合来测量方法的性能，通过多次启动该方法。运行多个周期后，将生成报告，其中包含有关基准的文件和信息。

# 设置参数

在上一个示例中，我们只测试了一个值的方法。实际上，在测试企业应用程序时，我们希望使用不同的值来估计方法的性能。

```cs
TestBenchmark class:
```

```cs
public class TestBenchmark 
{ 

  [Params(10,20,30)] 
  public int Len { get; set; } 

  [Benchmark] 
  public  void Fibonacci() 
  { 
    int a = 0, b = 1, c = 0; 
    Console.Write("{0} {1}", a, b); 

    for (int i = 2; i < Len; i++) 
    { 
      c = a + b; 
      Console.Write(" {0}", c); 
      a = b; 
      b = c; 
    } 
  } 

  [Benchmark] 
  public  void FibonacciRecursive() 
  { 
    Fibonacci_Recursive(0, 1, 1, Len); 
  } 

  private void Fibonacci_Recursive(int a, int b, int counter, int len) 
  { 
    if (counter <= len) 
    { 
      Console.Write("{0} ", a); 
      Fibonacci_Recursive(b, a + b, counter + 1, len); 
    } 
  } 
}
```

运行 Benchmark 后，将生成以下报告：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00037.jpeg)

# 使用 BenchmarkDotnet 进行内存诊断

使用`BenchmarkDotnet`，我们还可以诊断内存问题，并测量分配的字节数和垃圾回收。

可以使用`MemoryDiagnoser`属性在类级别实现。首先，让我们在上一个示例中创建的`TestBenchmark`类中添加`MemoryDiagnoser`属性：

```cs
[MemoryDiagnoser] 
public class TestBenchmark {} 
```

重新运行应用程序。现在它将收集其他内存分配和垃圾回收信息，并相应地生成日志：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00038.jpeg)

在上表中，Gen 0 和 Gen 1 列分别包含每 1,000 次操作的特定代数的数量。如果值为 1，则表示在 1,000 次操作后进行了垃圾回收。但是，请注意，在第一行中，值为*0.1984*，这意味着在*198.4*秒后进行了垃圾回收，而该行的 Gen 1 中没有进行垃圾回收。Allocated 表示在调用该方法时分配的内存大小。它不包括 Stackalloc/堆本机分配。

# 添加配置

可以通过创建自定义类并从`ManualConfig`类继承来定义基准配置。以下是我们之前创建的`TestBenchmark`类的示例，其中包含一些基准方法：

```cs
[Config(typeof(Config))] 
public class TestBenchmark 
{ 
  private class Config : ManualConfig 
  { 
    // We will benchmark ONLY method with names with names (which 
    // contains "A" OR "1") AND (have length < 3) 
    public Config() 
    { 
      Add(new DisjunctionFilter( 
        new NameFilter(name => name.Contains("Recursive")) 
      ));  

    } 
  } 

  [Params(10,20,30)] 
  public int Len { get; set; } 

  [Benchmark] 
  public  void Fibonacci() 
  { 
    int a = 0, b = 1, c = 0; 
    Console.Write("{0} {1}", a, b); 

    for (int i = 2; i < Len; i++) 
    { 
      c = a + b; 
      Console.Write(" {0}", c); 
      a = b; 
      b = c; 
    } 
  } 

  [Benchmark] 
  public  void FibonacciRecursive() 
  { 
    Fibonacci_Recursive(0, 1, 1, Len); 
  } 

  private void Fibonacci_Recursive(int a, int b, int counter, int len) 
  { 
    if (counter <= len) 
    { 
      Console.Write("{0} ", a); 
      Fibonacci_Recursive(b, a + b, counter + 1, len); 
    } 
  } 
} 
```

在上述代码中，我们定义了`Config`类，该类继承了基准框架中提供的`ManualConfig`类。规则可以在`Config`构造函数内定义。在上面的示例中，有一个规则规定只有包含`Recursive`的基准方法才会被执行。在我们的情况下，只有一个方法`FibonacciRecursive`会被执行，并且我们将测量其性能。

另一种方法是通过流畅的 API，我们可以跳过创建`Config`类，并实现以下内容：

```cs
static void Main(string[] args) 
{ 
  var config = ManualConfig.Create(DefaultConfig.Instance); 
  config.Add(new DisjunctionFilter(new NameFilter(
    name => name.Contains("Recursive")))); 
  BenchmarkRunner.Run<TestBenchmark>(config); 
}
```

要了解有关`BenchmarkDotNet`的更多信息，请参阅[`benchmarkdotnet.org/Configs.htm`](http://benchmarkdotnet.org/Configs.htm)。

# 摘要

在本章中，我们已经了解了.NET Core 的核心概念，包括编译过程、垃圾回收、如何利用 CPU 的多个核心开发高性能的.NET Core 应用程序，以及使用发布构建发布应用程序。我们还探讨了用于代码优化的基准工具，并提供了特定于类对象的结果。

在下一章中，我们将学习.NET Core 中的多线程和并发编程。


# 第三章：.NET Core 中的多线程和异步编程

多线程和异步编程是两种重要的技术，可以促进高度可扩展和高性能应用程序的开发。如果应用程序不响应，会影响用户体验并增加不满的程度。另一方面，它还会增加服务器端或应用程序运行位置的资源使用，并增加内存大小和/或 CPU 使用率。如今，硬件非常便宜，每台机器都配备了多个 CPU 核心。实现多线程和使用异步编程技术不仅可以提高应用程序的性能，还可以使应用程序具有更高的响应性。

本章将探讨多线程和异步编程模型的核心概念，以帮助您在项目中使用它们，并提高应用程序的整体性能。

以下是本章将学习的主题列表：

+   多线程与异步编程

+   .NET Core 中的多线程

+   .NET Core 中的线程

+   线程同步

+   任务并行库（TPL）

+   使用 TPL 创建任务

+   基于任务的异步模式

+   并行编程的设计模式

I/O 绑定操作是依赖于外部资源的代码。例如访问文件系统，访问网络等。

# 多线程与异步编程

如果正确实现，多线程和异步编程可以提高应用程序的性能。多线程是指同时执行多个线程以并行执行多个操作或任务的实践。通常有一个主线程和几个后台线程，通常称为工作线程，同时并行运行，同时执行多个任务，而同步和异步操作都可以在单线程或多线程环境中运行。

在单线程同步操作中，只有一个线程按照定义的顺序执行所有任务，并依次执行它们。在单线程异步操作中，只有一个线程执行任务，但它会分配一个时间片来运行每个任务。时间片结束后，它会保存该任务的状态并开始执行下一个任务。在内部，处理器在每个任务之间执行上下文切换，并分配一个时间片来运行它们。

在多线程同步操作中，有多个线程并行运行任务。与异步操作中的上下文切换不同，任务之间没有上下文切换。一个线程负责执行分配给它的任务，然后开始另一个任务，而在多线程异步操作中，多个线程运行多个任务，任务可以由单个或多个线程提供和执行。

以下图表描述了单线程和多线程同步和异步操作之间的区别：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00039.gif)

上图显示了四种操作类型。在单线程同步操作中，有一个线程按顺序运行五个任务。一旦**任务 1**完成，就执行**任务 2**，依此类推。在单线程异步操作中，有一个线程，但每个任务都会在执行下一个任务之前获得一个时间片来执行，依此类推。每个任务将被执行多次，并从暂停的地方恢复。在多线程同步操作中，有三个线程并行运行三个任务**任务 1**，**任务 2**和**任务 3**。最后，在多线程异步操作中，有三个任务**任务 1**，**任务 2**和**任务 3**由三个线程运行，但每个线程根据分配给每个任务的时间片进行一些上下文切换。

在异步编程中，并不总是每个异步操作都会在新线程上运行。`Async`/`Await`是一个没有创建额外线程的好例子。`*async*`操作在主线程的当前同步上下文中执行，并将异步操作排队在分配的时间片中执行。

# .NET Core 中的多线程

在 CPU 和/或 I/O 密集型应用程序中使用多线程有许多好处。它通常用于长时间运行的进程，这些进程具有更长或无限的生命周期，作为后台任务工作，保持主线程可用以管理或处理用户请求。然而，不必要的使用可能会完全降低应用程序的性能。有些情况下，创建太多线程并不是一个好的架构实践。

以下是一些多线程适用的示例：

+   I/O 操作

+   运行长时间的后台任务

+   数据库操作

+   通过网络进行通信

# 多线程注意事项

尽管多线程有许多好处，但在编写多线程应用程序时需要彻底解决一些注意事项。如果计算机是单核或双核计算机，并且应用程序创建了大量线程，则这些线程之间的上下文切换将减慢性能：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00040.jpeg)

上图描述了在单处理器机器上运行的程序。第一个任务是同步执行的，比在单处理器上运行的三个线程快得多。系统执行第一个线程，然后等待一段时间再执行第二个线程，依此类推。这增加了在线程之间切换的不必要开销，从而延迟了整体操作。在线程领域，这被称为上下文切换。每个线程之间的框表示在每个上下文切换之间发生的延迟。

就开发人员的经验而言，调试和测试是创建多线程应用程序时对开发人员具有挑战性的另外两个问题。

# .NET Core 中的线程

.NET 中的每个应用程序都从一个单线程开始，这是主线程。线程是操作系统用来分配处理器时间的基本单位。每个线程都有一个优先级、异常处理程序和保存在自己的线程上下文中的数据结构。如果发生异常，它是在线程的上下文中抛出的，其他线程不受其影响。线程上下文包含一些关于 CPU 寄存器、线程的主机进程的地址空间等低级信息。

如果应用程序在单处理器上运行多个线程，则每个线程将被分配一段处理器时间，并依次执行。时间片通常很小，这使得看起来好像线程在同时执行。一旦分配的时间结束，处理器就会移动到另一个线程，之前的线程等待处理器再次可用并根据分配的时间片执行。另一方面，如果线程在多个 CPU 上运行，则它们可能同时执行，但如果有其他进程和线程在运行，则时间片将被分配并相应地执行。

# 在.NET Core 中创建线程

在.NET Core 中，线程 API 与完整的.NET Framework 版本相同。可以通过创建`Thread`类对象并将`ThreadStart`或`ParameterizedThreadStart`委托作为参数来创建新线程。`ThreadStart`和`ParameterizedThreadStart`包装了在启动新线程时调用的方法。`ParameterizedThreadStart`用于包含参数的方法。

以下是一个基本示例，该示例在单独的线程上运行`ExecuteLongRunningOperation`方法：

```cs
static void Main(string[] args) 
{ 
  new Thread(new ThreadStart(ExecuteLongRunningOperation)).Start(); 
} 
static void ExecuteLongRunningOperation() 
{ 
  Thread.Sleep(100000); 
  Console.WriteLine("Operation completed successfully"); 
} 
```

在启动线程时，我们还可以传递参数并使用`ParameterizedThreadStart`委托：

```cs
static void Main(string[] args) 
{ 
  new Thread(new ParameterizedThreadStart
  (ExecuteLongRunningOperation)).Start(100000); 
} 

static void ExecuteLongRunningOperation(object milliseconds) 
{ 
  Thread.Sleep((int)milliseconds); 
  Console.WriteLine("Operation completed successfully"); 
} 
```

`ParameterizedThreadStart`委托接受一个对象作为参数。因此，如果要传递多个参数，可以通过创建自定义类并添加以下属性来实现：

```cs
public interface IService 
{ 
  string Name { get; set; } 
  void Execute(); 
} 

public class EmailService : IService 
{ 
  public string Name { get; set; } 
  public void Execute() => throw new NotImplementedException(); 

  public EmailService(string name) 
  { 
    this.Name = name; 
  } 
} 

static void Main(string[] args) 
{ 
  IService service = new EmailService("Email"); 
  new Thread(new ParameterizedThreadStart
  (RunBackgroundService)).Start(service); 
} 

static void RunBackgroundService(Object service) 
{ 
  ((IService)service).Execute(); //Long running task 
} 
```

每个线程都有一个线程优先级。当线程被创建时，其优先级被设置为正常。优先级影响线程的执行。优先级越高，线程将被赋予的优先级就越高。线程优先级可以在线程对象上定义，如下所示：

```cs
static void RunBackgroundService(Object service) 
{ 
  Thread.CurrentThread.Priority = ThreadPriority.Highest;      
  ((IService)service).Execute(); //Long running task
}
```

`RunBackgroundService`是在单独的线程中执行的方法，可以使用`ThreadPriority`枚举设置优先级，并通过调用`Thread.CurrentThread`引用当前线程对象，如上面的代码片段所示。

# 线程生命周期

线程的生命周期取决于在该线程中执行的方法。一旦方法执行完毕，CLR 将释放线程占用的内存并进行处理。另一方面，也可以通过调用`Interrupt`或`Abort`方法显式地处理线程。

另一个非常重要的因素是异常。如果异常在线程内部没有得到适当处理，它们将传播到`调用`方法，依此类推，直到它们到达调用堆栈中的`根`方法。当它达到这一点时，如果没有得到处理，CLR 将关闭线程。

对于持续或长时间运行的线程，关闭过程应该被正确定义。平滑关闭线程的最佳方法之一是使用`volatile bool`变量：

```cs
class Program 
{ 

  static volatile bool isActive = true;  
  static void Main(string[] args) 
  { 
    new Thread(new ParameterizedThreadStart
    (ExecuteLongRunningOperation)).Start(1000); 
  } 

  static void ExecuteLongRunningOperation(object milliseconds) 
  { 
    while (isActive) 
    { 
      //Do some other operation 
      Console.WriteLine("Operation completed successfully"); 
    } 
  } 
} 
```

在上面的代码中，我们使用了`volatile bool`变量`isActive`，它决定了`while`循环是否执行。

`volatile`关键字表示一个字段可能会被多个同时执行的线程修改。声明为 volatile 的字段不受编译器优化的影响，假设只有一个线程访问。这确保了字段中始终存在最新的值。要了解更多关于 volatile 的信息，请参考以下 URL：

[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/volatile`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/volatile)

# .NET 中的线程池

CLR 提供了一个单独的线程池，其中包含要用于异步执行任务的线程列表。每个进程都有自己特定的线程池。CLR 向线程池中添加和移除线程。

使用`ThreadPool`来运行线程，我们可以使用`ThreadPool.QueueUserWorkItem`，如下面的代码所示：

```cs
class Program 
{ 
  static void Main(string[] args) 
  { 
    ThreadPool.QueueUserWorkItem(ExecuteLongRunningOperation, 1000); 
    Console.Read(); 
  } 
  static void ExecuteLongRunningOperation(object milliseconds) 
  { 

    Thread.Sleep((int)milliseconds); 
    Console.WriteLine("Thread is executed"); 
  } 
} 
```

`QueueUserWorkItem`将任务排队，由 CLR 在线程池中可用的线程中执行。任务队列按照**先进先出**（**FIFO**）的顺序进行维护。但是，根据线程的可用性和任务本身，任务完成可能会延迟。

# 线程同步

在多线程应用程序中，我们有共享资源，可以被多个线程同时访问。资源在多个线程之间共享的区域称为临界区。为了保护这些资源并提供线程安全的访问，有一些技术将在本节中讨论。

让我们举一个例子，我们有一个用于将消息记录到文件系统的单例类。单例，根据定义，表示应该只有一个实例在多次调用之间共享。以下是一个基本的单例模式实现，它不是线程安全的：

```cs
public class Logger 
{ 
  static Logger _instance; 

  private Logger() { } 

  public Logger GetInstance() 
  { 
    _instance = (_instance == null ? new Logger() : _instance); 
    return _instance; 
  } 

  public void LogMessage(string str) 
  { 
    //Log message into file system 
  } 

} 
```

上面的代码是一个懒惰初始化的单例模式，它在第一次调用`GetInstance`方法时创建一个实例。`GetInstance`是临界区，不是线程安全的。如果多个线程进入临界区，将创建多个实例，并发条件将发生。

竞争条件是多线程编程中出现的问题，当结果取决于事件的时间时。当两个或多个并行任务访问共享对象时，就会出现竞争条件。

要实现线程安全的单例，我们可以使用锁定模式。锁定确保只有一个线程可以进入临界区，如果另一个线程尝试进入，它将等待直到线程被释放。以下是一个修改后的版本，使单例线程安全：

```cs
public class Logger 
{ 

  private static object syncRoot = new object(); 
  static Logger _instance; 

  private Logger() { } 

  public Logger GetInstance() 
  { 
    if (_instance == null) 
    { 
      lock (syncRoot) 
      { 
        if (_instance == null) 
        _instance = new Logger(); 
      } 
    } 
    return _instance; 
  } 

  public void LogMessage(string str) 
  { 
    //Log message into file system 
  } 
} 
```

# 监视器

监视器用于提供对资源的线程安全访问。它适用于多线程编程，在那里有多个线程需要同时访问资源。当多个线程尝试进入`monitor`以访问任何资源时，CLR 只允许一个线程一次进入，其他线程被阻塞。当线程退出监视器时，下一个等待的线程进入，依此类推。

如果我们查看`Monitor`类，所有方法如`Monitor.Enter`和`Monitor.Exit`都是在对象引用上操作的。与`lock`类似，`Monitor`也提供对资源的门控访问；但是，开发人员在 API 方面会有更大的控制。

以下是在.NET Core 中使用`Monitor`的基本示例：

```cs
public class Job 
{ 

  int _jobDone; 
  object _lock = new object(); 

  public void IncrementJobCounter(int number) 
  { 
    Monitor.Enter(_lock); 
    // access to this field is synchronous
    _jobDone += number; 
    Monitor.Exit(_lock); 
  } 

} 
IncrementJobCounter method to increment the _jobDone counter.
```

在某些情况下，关键部分必须等待资源可用。一旦它们可用，我们希望激活等待块以执行。

为了帮助我们理解，让我们举一个运行`Job`的例子，其任务是运行多个线程添加的作业。如果没有作业存在，它应该等待线程推送并立即开始执行它们。

```cs
JobExecutor: 
```

```cs
public class JobExecutor 
{ 
  const int _waitTimeInMillis = 10 * 60 * 1000; 
  private ArrayList _jobs = null; 
  private static JobExecutor _instance = null; 
  private static object _syncRoot = new object(); 

  //Singleton implementation of JobExecutor
  public static JobExecutor Instance 
  { 
    get{ 
    lock (_syncRoot) 
    { 
      if (_instance == null) 
      _instance = new JobExecutor(); 
    } 
    return _instance; 
  } 
} 

private JobExecutor() 
{ 
  IsIdle = true; 
  IsAlive = true; 
  _jobs = new ArrayList(); 
} 

private Boolean IsIdle { get; set; } 
public Boolean IsAlive { get; set; } 

//Callers can use this method to add list of jobs
public void AddJobItems(List<Job> jobList) 
{ 
  //Added lock to provide synchronous access. 
  //Alternatively we can also use Monitor.Enter and Monitor.Exit
  lock (_jobs) 
  { 
    foreach (Job job in jobList) 
    { 
      _jobs.Add(job); 
    } 
    //Release the waiting thread to start executing the //jobs
    Monitor.PulseAll(_jobs); 
  } 
} 

/*Check for jobs count and if the count is 0, then wait for 10 minutes by calling Monitor.Wait. Meanwhile, if new jobs are added to the list, Monitor.PulseAll will be called that releases the waiting thread. Once the waiting is over it checks the count of jobs and if the jobs are there in the list, start executing. Otherwise, wait for the new jobs */
public void CheckandExecuteJobBatch() 
{ 
  lock (_jobs) 
  { 
    while (IsAlive) 
    { 
      if (_jobs == null || _jobs.Count <= 0) 
      { 
        IsIdle = true; 
        Console.WriteLine("Now waiting for new jobs"); 
        //Waiting for 10 minutes 
        Monitor.Wait(_jobs, _waitTimeInMillis); 
      } 
      else 
      { 
        IsIdle = false; 
        ExecuteJob(); 
      } 
    } 
  } 
} 

//Execute the job
private void ExecuteJob() 
{ 
  for(int i=0;i< _jobs.Count;i++) 
  { 
    Job job = (Job)_jobs[i]; 
    //Execute the job; 
    job.DoSomething(); 
    //Remove the Job from the Jobs list 
    _jobs.Remove(job); 
    i--; 
  } 
} 
} 
```

这是一个单例类，其他线程可以使用静态的`Instance`属性访问`JobExecutor`实例，并调用`AddJobsItems`方法将要执行的作业列表添加到其中。`CheckandExecuteJobBatch`方法持续运行并每 10 分钟检查列表中的新作业。或者，如果通过调用`Monitor.PulseAll`方法中断了`AddJobsItems`方法，它将立即转移到`while`语句并检查项目计数。如果项目存在，`CheckandExecuteJobBatch`方法调用`ExecuteJob`方法来运行该作业。

```cs
Job class containing two properties, namely JobID and JobName, and the DoSomething method that will print the JobID on the console:
```

```cs
public class Job 
{ 
  // Properties to set and get Job ID and Name
  public int JobID { get; set; } 
  public string JobName { get; set; } 

  //Do some task based on Job ID as set through the JobID        
  //property
  public void DoSomething() 
  { 
    //Do some task based on Job ID  
    Console.WriteLine("Executed job " + JobID);  
  } 
} 
```

最后，在主`Program`类上，我们可以调用三个工作线程和一个`JobExecutor`线程，如下所示：

```cs
class Program 
{ 
  static void Main(string[] args) 
  { 
    Thread jobThread = new Thread(new ThreadStart(ExecuteJobExecutor)); 
    jobThread.Start(); 

    //Starting three Threads add jobs time to time; 
    Thread thread1 = new Thread(new ThreadStart(ExecuteThread1)); 
    Thread thread2 = new Thread(new ThreadStart(ExecuteThread2)); 
    Thread thread3 = new Thread(new ThreadStart(ExecuteThread3)); 
    Thread1.Start(); 
    Thread2.Start(); 
    thread3.Start(); 

    Console.Read(); 
  } 

  //Implementation of ExecuteThread 1 that is adding three 
  //jobs in the list and calling AddJobItems of a singleton 
  //JobExecutor instance
  private static void ExecuteThread1() 
  { 
    Thread.Sleep(5000); 
    List<Job> jobs = new List<Job>(); 
    jobs.Add(new Job() { JobID = 11, JobName = "Thread 1 Job 1" }); 
    jobs.Add(new Job() { JobID = 12, JobName = "Thread 1 Job 2" }); 
    jobs.Add(new Job() { JobID = 13, JobName = "Thread 1 Job 3" }); 
    JobExecutor.Instance.AddJobItems(jobs); 
  } 

  //Implementation of ExecuteThread2 method that is also adding 
  //three jobs and calling AddJobItems method of singleton 
  //JobExecutor instance 
  private static void ExecuteThread2() 
  { 
    Thread.Sleep(5000); 
    List<Job> jobs = new List<Job>(); 
    jobs.Add(new Job() { JobID = 21, JobName = "Thread 2 Job 1" }); 
    jobs.Add(new Job() { JobID = 22, JobName = "Thread 2 Job 2" }); 
    jobs.Add(new Job() { JobID = 23, JobName = "Thread 2 Job 3" }); 
    JobExecutor.Instance.AddJobItems(jobs); 
  } 

  //Implementation of ExecuteThread3 method that is again 
  // adding 3 jobs instances into the list and 
  //calling AddJobItems to add those items into the list to execute
  private static void ExecuteThread3() 
  { 
    Thread.Sleep(5000); 
    List<Job> jobs = new List<Job>(); 
    jobs.Add(new Job() { JobID = 31, JobName = "Thread 3 Job 1" }); 
    jobs.Add(new Job() { JobID = 32, JobName = "Thread 3 Job 2" }); 
    jobs.Add(new Job() { JobID = 33, JobName = "Thread 3 Job 3" }); 
    JobExecutor.Instance.AddJobItems(jobs); 
  } 

  //Implementation of ExecuteJobExecutor that calls the 
  //CheckAndExecuteJobBatch to run the jobs
  public static void ExecuteJobExecutor() 
  { 
    JobExecutor.Instance.IsAlive = true; 
    JobExecutor.Instance.CheckandExecuteJobBatch(); 
  } 
} 
```

以下是运行此代码的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00041.gif)

# 任务并行库（TPL）

到目前为止，我们已经学习了一些关于多线程的核心概念，并使用线程执行多个任务。与.NET 中的经典线程模型相比，TPL 最小化了使用线程的复杂性，并通过一组 API 提供了抽象，帮助开发人员更多地专注于应用程序程序，而不是专注于如何提供线程以及其他事项。

使用 TPL 而不是线程有几个好处：

+   它将并发自动扩展到多核级别

+   它将 LINQ 查询自动扩展到多核级别

+   它处理工作的分区并在需要时使用`ThreadPool`

+   它易于使用，并减少了直接使用线程的复杂性

# 使用 TPL 创建任务

TPL API 可在`System.Threading`和`System.Threading.Tasks`命名空间中使用。它们围绕任务工作，任务是异步运行的程序或代码块。可以通过调用`Task.Run`或`TaskFactory.StartNew`方法来运行异步任务。当我们创建一个任务时，我们提供一个命名委托、匿名方法或 lambda 表达式，任务执行它。

```cs
ExecuteLongRunningTasksmethod using Task.Run:
```

```cs
class Program 
{ 
  static void Main(string[] args) 
  { 
    Task t = Task.Run(()=>ExecuteLongRunningTask(5000)); 
    t.Wait(); 
  } 

  public static void ExecuteLongRunningTask(int millis) 
  { 
    Thread.Sleep(millis); 
    Console.WriteLine("Hello World"); 

  } 
} 
ExecuteLongRunningTask method asynchronously using the Task.Run method. The Task.Run method returns the Task object that can be used to further wait for the asynchronous piece of code to be executed completely before the program ends. To wait for the task, we have used the Wait method.
```

或者，我们也可以使用`Task.Factory.StartNew`方法，这是更高级的并提供更多选项。在调用`Task.Factory.StartNew`方法时，我们可以指定`CancellationToken`、`TaskCreationOptions`和`TaskScheduler`来设置状态、指定其他选项和安排任务。

TPL 默认使用 CPU 的多个核心。当使用 TPL API 执行任务时，它会自动将任务分割成一个或多个线程，并利用多个处理器（如果可用）。创建多少个线程的决定是由 CLR 在运行时计算的。而线程只有一个处理器的亲和性，要在多个处理器上运行任何任务需要适当的手动实现。

# 基于任务的异步模式（TAP）

在开发任何软件时，总是要在设计其架构时实现最佳实践。基于任务的异步模式是在使用 TPL 时可以使用的推荐模式之一。然而，在实现 TAP 时有一些需要牢记的事情。

# 命名约定

异步执行的方法应该以`Async`作为命名后缀。例如，如果方法名以`ExecuteLongRunningOperation`开头，它应该有后缀`Async`，结果名称为`ExecuteLongRunningOperationAsync`。

# 返回类型

方法签名应该返回`System.Threading.Tasks.Task`或`System.Threading.Tasks.Task<TResult>`。任务的返回类型等同于返回`void`的方法，而`TResult`是数据类型。

# 参数

`out`和`ref`参数不允许作为方法签名中的参数。如果需要返回多个值，可以使用元组或自定义数据结构。方法应该始终返回`Task`或`Task<TResult>`，如前面所讨论的。

以下是同步和异步方法的一些签名：

| **同步方法** | **异步方法** |
| --- | --- |
| `Void Execute();` | `Task ExecuteAsync();` |
| `List<string> GetCountries();` | `Task<List<string>> GetCountriesAsync();` |
| `Tuple<int, string> GetState(int stateID);` | `Task<Tuple<int, string>> GetStateAsync(int stateID);` |
| `Person GetPerson(int personID);` | `Task<Person> GetPersonAsync(int personID);` |

# 异常

异步方法应该总是抛出分配给返回任务的异常。然而，使用错误，比如将空参数传递给异步方法，应该得到适当处理。

假设我们想根据预定义的模板列表动态生成多个文档，其中每个模板都使用动态值填充占位符并将其写入文件系统。我们假设这个操作将花费足够长的时间来为每个模板生成一个文档。下面是一个代码片段，显示了如何处理异常：

```cs
static void Main(string[] args) 
{ 
  List<Template> templates = GetTemplates(); 
  IEnumerable<Task> asyncDocs = from template in templates select 
  GenerateDocumentAsync(template); 
  try 
  { 
    Task.WaitAll(asyncDocs.ToArray()); 

  }catch(Exception ex) 
  { 
    Console.WriteLine(ex); 
  } 
  Console.Read(); 
} 

private static async Task<int> GenerateDocumentAsync(Template template) 
{ 
  //To automate long running operation 
  Thread.Sleep(3000); 
  //Throwing exception intentionally 
  throw new Exception(); 
}
```

在上面的代码中，我们有一个`GenerateDocumentAsync`方法，执行长时间运行的操作，比如从数据库中读取模板，填充占位符，并将文档写入文件系统。为了自动化这个过程，我们使用`Thread.Sleep`来让线程休眠三秒，然后抛出一个异常，这个异常将传播到调用方法。`Main`方法循环遍历模板列表，并为每个模板调用`GenerateDocumentAsync`方法。每个`GenerateDocumentAsync`方法都返回一个任务。在调用异步方法时，异常实际上是隐藏的，直到调用`Wait`、`WaitAll`、`WhenAll`和其他方法。在上面的例子中，一旦调用`Task.WaitAll`方法，异常将被抛出，并在控制台上记录异常。

# 任务状态

任务对象提供了`TaskStatus`，用于了解任务是否正在执行方法运行，已完成方法，遇到故障，或者是否发生了其他情况。使用`Task.Run`初始化的任务最初具有`Created`状态，但当调用`Start`方法时，其状态会更改为`Running`。在应用 TAP 模式时，所有方法都返回`Task`对象，无论它们是否在方法体内使用`Task.Run`，方法体都应该被激活。这意味着状态应该是除了`Created`之外的任何状态。TAP 模式确保消费者任务已激活，并且不需要启动任务。

# 任务取消

取消对于基于 TAP 的异步方法是可选的。如果方法接受`CancellationToken`作为参数，调用方可以使用它来取消任务。但是，对于 TAP，取消应该得到适当处理。这是一个基本示例，显示了如何实现取消：

```cs
static void Main(string[] args) 
{ 
  CancellationTokenSource tokenSource = new CancellationTokenSource(); 
  CancellationToken token = tokenSource.Token; 
  Task.Factory.StartNew(() => SaveFileAsync(path, bytes, token)); 
} 

static Task<int> SaveFileAsync(string path, byte[] fileBytes, CancellationToken cancellationToken) 
{ 
  if (cancellationToken.IsCancellationRequested) 
  { 
    Console.WriteLine("Cancellation is requested..."); 
    cancellationToken.ThrowIfCancellationRequested      
  } 
  //Do some file save operation 
  File.WriteAllBytes(path, fileBytes); 
  return Task.FromResult<int>(0); 
} 
```

在前面的代码中，我们有一个`SaveFileAsync`方法，它接受`byte`数组和`CancellationToken`作为参数。在`Main`方法中，我们初始化了`CancellationTokenSource`，可以在程序后面用于取消异步操作。为了测试取消场景，我们将在`Task.Factory.StartNew`方法之后调用`tokenSource`的`Cancel`方法，操作将被取消。此外，当任务被取消时，其状态设置为`Cancelled`，`IsCompleted`属性设置为`true`。

# 任务进度报告

使用 TPL，我们可以使用`IProgress<T>`接口从异步操作中获取实时进度通知。这可以用于需要更新用户界面或控制台应用程序的异步操作的场景。在定义基于 TAP 的异步方法时，在参数中定义`IProgress<T>`是可选的。我们可以有重载的方法，可以帮助消费者在特定需要的情况下使用。但是，它们只能在异步方法支持它们的情况下使用。这是修改后的`SaveFileAsync`，用于向用户更新实际进度：

```cs
static void Main(string[] args) 
{ 
  var progressHandler = new Progress<string>(value => 
  { 
    Console.WriteLine(value); 
  }); 

  var progress = progressHandler as IProgress<string>; 

  CancellationTokenSource tokenSource = new CancellationTokenSource(); 
  CancellationToken token = tokenSource.Token; 

  Task.Factory.StartNew(() => SaveFileAsync(path, bytes, 
  token, progress)); 
  Console.Read(); 

} 
static Task<int> SaveFileAsync(string path, byte[] fileBytes, CancellationToken cancellationToken, IProgress<string> progress) 
{ 
  if (cancellationToken.IsCancellationRequested) 
  { 
    progress.Report("Cancellation is called"); 
    Console.WriteLine("Cancellation is requested..."); 
  } 

  progress.Report("Saving File"); 
  File.WriteAllBytes(path, fileBytes);   
  progress.Report("File Saved"); 
  return Task.FromResult<int>(0); 

} 
```

# 使用编译器实现 TAP

任何使用`async`关键字（对于 C＃）或`Async`（对于 Visual Basic）标记的方法都称为异步方法。`async`关键字可以应用于方法、匿名方法或 Lambda 表达式，语言编译器可以异步执行该任务。

这是使用编译器方法的 TAP 方法的简单实现：

```cs
static void Main(string[] args) 
{ 
  var t = ExecuteLongRunningOperationAsync(100000); 
  Console.WriteLine("Called ExecuteLongRunningOperationAsync method, 
  now waiting for it to complete"); 
  t.Wait(); 
  Console.Read(); 
}   

public static async Task<int> ExecuteLongRunningOperationAsync(int millis) 
{ 
  Task t = Task.Factory.StartNew(() => RunLoopAsync(millis)); 
  await t; 
  Console.WriteLine("Executed RunLoopAsync method"); 
  return 0; 
} 

public static void RunLoopAsync(int millis) 
{ 
  Console.WriteLine("Inside RunLoopAsync method"); 
  for(int i=0;i< millis; i++) 
  { 
    Debug.WriteLine($"Counter = {i}"); 
  } 
  Console.WriteLine("Exiting RunLoopAsync method"); 
} 
```

在前面的代码中，我们有`ExecuteLongRunningOperationAsync`方法，它是根据编译器方法实现的。它调用`RunLoopAsync`，该方法执行一个传递的毫秒数的循环。`ExecuteLongRunningOperationAsync`方法上的`async`关键字实际上告诉编译器该方法必须异步执行，一旦达到`await`语句，该方法返回到`Main`方法，在控制台上写一行并等待任务完成。一旦`RunLoopAsync`执行，控制权回到`await`，并开始执行`ExecuteLongRunningOperationAsync`方法中的下一个语句。

# 实现对任务的更大控制的 TAP

我们知道，TPL 以`Task`和`Task<TResult>`对象为中心。我们可以通过调用`Task.Run`方法执行异步任务，并异步执行`delegate`方法或一段代码，并在该任务上使用`Wait`或其他方法。然而，这种方法并不总是适当，有些情况下我们可能有不同的方法来执行异步操作，我们可能会使用**基于事件的异步模式**（EAP）或**异步编程模型**（APM）。为了在这里实现 TAP 原则，并以不同的模型执行异步操作，我们可以使用`TaskCompletionSource<TResult>`对象。

`TaskCompletionSource<TResult>`对象用于创建执行异步操作的任务。异步操作完成后，我们可以使用`TaskCompletionSource<TResult>`对象设置任务的结果、异常或状态。

这是一个基本示例，执行`ExecuteTask`方法返回`Task`，其中`ExecuteTask`方法使用`TaskCompletionSource<TResult>`对象将响应包装为`Task`，并通过`Task.StartNew`方法执行`ExecuteLongRunningTask`：

```cs
static void Main(string[] args) 
{ 
  var t = ExecuteTask(); 
  t.Wait(); 
  Console.Read(); 
} 

public static Task<int> ExecuteTask() 
{ 
  var tcs = new TaskCompletionSource<int>(); 
  Task<int> t1 = tcs.Task; 
  Task.Factory.StartNew(() => 
  { 
    try 
    { 
      ExecuteLongRunningTask(10000); 
      tcs.SetResult(1); 
    }catch(Exception ex) 
    { 
      tcs.SetException(ex); 
    } 
  }); 
  return tcs.Task; 

} 

public static void ExecuteLongRunningTask(int millis) 
{ 
  Thread.Sleep(millis); 
  Console.WriteLine("Executed"); 
} 
```

# 并行编程的设计模式

任务可以以各种方式设计并行运行。在本节中，我们将学习 TPL 中使用的一些顶级设计模式：

+   管道模式

+   数据流模式

+   生产者-消费者模式

+   Parallel.ForEach

+   并行 LINQ（PLINQ）

# 管道模式

管道模式通常用于需要按顺序执行异步任务的场景：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00042.jpeg)

考虑一个任务，我们需要首先创建一个用户记录，然后启动工作流并发送电子邮件。要实现这种情况，我们可以使用 TPL 的`ContinueWith`方法。以下是一个完整的示例：

```cs
static void Main(string[] args) 
{ 

  Task<int> t1 = Task.Factory.StartNew(() =>  
  { return CreateUser(); }); 

  var t2=t1.ContinueWith((antecedent) => 
  { return InitiateWorkflow(antecedent.Result); }); 
  var t3 = t2.ContinueWith((antecedant) => 
  { return SendEmail(antecedant.Result); }); 

  Console.Read(); 

} 

public static int CreateUser() 
{ 
  //Create user, passing hardcoded user ID as 1 
  Thread.Sleep(1000); 
  Console.WriteLine("User created"); 
  return 1; 
} 

public static int InitiateWorkflow(int userId) 
{ 
  //Initiate Workflow 
  Thread.Sleep(1000); 
  Console.WriteLine("Workflow initiates"); 

  return userId; 
} 

public static int SendEmail(int userId) 
{ 
  //Send email 
  Thread.Sleep(1000); 
  Console.WriteLine("Email sent"); 

  return userId; 
}  
```

# 数据流模式

数据流模式是一种具有一对多和多对一关系的通用模式。例如，以下图表表示两个任务**任务 1**和**任务 2**并行执行，第三个任务**任务 3**只有在前两个任务都完成后才会开始。一旦**任务 3**完成，**任务 4**和**任务 5**将并行执行：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00043.jpeg)

我们可以使用以下代码实现上述示例：

```cs
static void Main(string[] args) 
{ 
  //Creating two tasks t1 and t2 and starting them at the same //time
  Task<int> t1 = Task.Factory.StartNew(() => { return Task1(); }); 
  Task<int> t2 = Task.Factory.StartNew(() => { return Task2(); }); 

  //Creating task 3 and used ContinueWhenAll that runs when both the 
  //tasks T1 and T2 will be completed
  Task<int> t3 = Task.Factory.ContinueWhenAll(
  new[] { t1, t2 }, (tasks) => { return Task3(); }); 

  //Task 4 and Task 5 will be started when Task 3 will be completed. 
  //ContinueWith actually creates a continuation of executing tasks 
  //T4 and T5 asynchronously when the task T3 is completed
  Task<int> t4 = t3.ContinueWith((antecendent) => { return Task4(); }); 
  Task<int> t5 = t3.ContinueWith((antecendent) => { return Task5(); }); 
  Console.Read(); 
} 
//Implementation of Task1
public static int Task1() 
{ 
  Thread.Sleep(1000); 
  Console.WriteLine("Task 1 is executed"); 
  return 1; 
} 

//Implementation of Task2 
public static int Task2() 
{ 
  Thread.Sleep(1000); 
  Console.WriteLine("Task 2 is executed"); 
  return 1; 
} 
//Implementation of Task3 
public static int Task3() 
{ 
  Thread.Sleep(1000); 
  Console.WriteLine("Task 3 is executed"); 
  return 1; 
} 
Implementation of Task4
public static int Task4() 
{ 
  Thread.Sleep(1000); 
  Console.WriteLine("Task 4 is executed"); 
  return 1; 
} 

//Implementation of Task5
public static int Task5() 
{ 
  Thread.Sleep(1000); 
  Console.WriteLine("Task 5 is executed"); 
  return 1; 
} 
```

# 生产者/消费者模式

执行长时间运行操作的最佳模式之一是生产者/消费者模式。在这种模式中，有生产者和消费者，一个或多个生产者通过共享的数据结构`BlockingCollection`连接到一个或多个消费者。`BlockingCollection`是并行编程中使用的固定大小的集合。如果集合已满，生产者将被阻塞，如果集合为空，则不应再添加更多的消费者：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00044.jpeg)

在现实世界的例子中，生产者可以是从数据库中读取图像的组件，消费者可以是处理该图像并将其保存到文件系统的组件：

```cs
static void Main(string[] args) 
{ 
  int maxColl = 10; 
  var blockingCollection = new BlockingCollection<int>(maxColl); 
  var taskFactory = new TaskFactory(TaskCreationOptions.LongRunning, 
  TaskContinuationOptions.None); 

  Task producer = taskFactory.StartNew(() => 
  { 
    if (blockingCollection.Count <= maxColl) 
    { 
      int imageID = ReadImageFromDB(); 
      blockingCollection.Add(imageID); 
      blockingCollection.CompleteAdding(); 
    } 
  }); 

  Task consumer = taskFactory.StartNew(() => 
  { 
    while (!blockingCollection.IsCompleted) 
    { 
      try 
      { 
        int imageID = blockingCollection.Take(); 
        ProcessImage(imageID); 
      } 
      catch (Exception ex) 
      { 
        //Log exception 
      } 
    } 
  }); 

  Console.Read(); 

} 

public static int ReadImageFromDB() 
{ 
  Thread.Sleep(1000); 
  Console.WriteLine("Image is read"); 
  return 1; 
} 

public static void ProcessImage(int imageID) 
{ 
  Thread.Sleep(1000); 
  Console.WriteLine("Image is processed"); 

} 
```

在上面的示例中，我们初始化了通用的`BlockingCollection<int>`来存储由生产者添加并通过消费者处理的`imageID`。我们将集合的最大大小设置为 10。然后，我们添加了一个`Producer`项，它从数据库中读取图像并调用`Add`方法将`imageID`添加到阻塞集合中，消费者可以进一步提取并处理。消费者任务只需检查集合中是否有可用项目并对其进行处理。

要了解有关并行编程可用的数据结构，请参阅[`docs.microsoft.com/en-us/dotnet/standard/parallel-programming/data-structures-for-parallel-programming`](https://docs.microsoft.com/en-us/dotnet/standard/parallel-programming/data-structures-for-parallel-programming)。

# Parallel.ForEach

`Parallel.ForEach`是经典`foreach`循环的多线程版本。`foreach`循环在单个线程上运行，而`Parallel.ForEach`在多个线程上运行，并利用 CPU 的多个核心（如果可用）。

以下是一个基本示例，使用`Parallel.ForEach`处理需要处理的文档列表，并包含 I/O 绑定操作：

```cs
static void Main(string[] args) 
{ 
  List<Document> docs = GetUserDocuments(); 
  Parallel.ForEach(docs, (doc) => 
  { 
    ManageDocument(doc); 
  }); 
} 
private static void ManageDocument(Document doc) => Thread.Sleep(1000); 
```

为了复制 I/O 绑定的操作，我们只是在`ManageDocument`方法中添加了 1 秒的延迟。如果您使用`foreach`循环执行相同的方法，差异将是明显的。

# 并行 LINQ（PLINQ）

并行 LINQ 是 LINQ 的一个版本，它在多核 CPU 上并行执行查询。它包含完整的标准 LINQ 查询操作符以及一些用于并行操作的附加操作符。强烈建议您在长时间运行的任务中使用此功能，尽管不正确的使用可能会降低应用程序的性能。并行 LINQ 操作集合，如`List`，`List<T>`，`IEnumerable`，`IEnumerable<T>`等。在底层，它将列表分割成段，并在 CPU 的不同处理器上运行每个段。

以下是上一个示例的修改版本，使用`Parallel.ForEach`而不是 PLINQ 操作：

```cs
static void Main(string[] args) 
{ 
  List<Document> docs = GetUserDocuments(); 

  var query = from doc in docs.AsParallel() 
  select ManageDocument(doc); 
} 

private static Document ManageDocument(Document doc) 
{ 
  Thread.Sleep(1000); 
  return doc; 
} 
```

# 摘要

在本章中，我们学习了多线程和异步编程的核心基础知识。本章从两者之间的基本区别开始，并介绍了一些关于多线程的核心概念，可用的 API 以及如何编写多线程应用程序。我们还看了任务编程库如何用于提供异步操作以及如何实现任务异步模式。最后，我们探讨了并行编程技术以及用于这些技术的一些最佳设计模式。

在下一章中，我们将探讨数据结构的类型及其对性能的影响，如何编写优化的代码以及一些最佳实践。
