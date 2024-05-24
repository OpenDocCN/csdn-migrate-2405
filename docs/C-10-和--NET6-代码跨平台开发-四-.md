# C#10 和 .NET6 代码跨平台开发（四）

> 原文：[`zh.annas-archive.org/md5/B053DEF9CB8C4C14E67E73C1EC2319CF`](https://zh.annas-archive.org/md5/B053DEF9CB8C4C14E67E73C1EC2319CF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：打包和分发 .NET 类型

本章探讨 C# 关键字与 .NET 类型之间的关系，以及命名空间与程序集之间的关系。你还将熟悉如何打包和发布你的 .NET 应用和库以供跨平台使用，如何在 .NET 库中使用遗留的 .NET Framework 库，以及将遗留的 .NET Framework 代码库移植到现代 .NET 的可能性。

本章涵盖以下主题：

+   通往 .NET 6 之路

+   理解 .NET 组件

+   发布应用程序以供部署

+   反编译 .NET 程序集

+   为 NuGet 分发打包你的库

+   从 .NET Framework 迁移到现代 .NET

+   使用预览功能

# 通往 .NET 6 之路

本书的这一部分关于 **基类库** (**BCL**) API 提供的功能，以及如何使用 .NET Standard 在所有不同的 .NET 平台上重用功能。

首先，我们将回顾到达此点的路径，并理解过去为何重要。

.NET Core 2.0 及更高版本对 .NET Standard 2.0 的最小支持至关重要，因为它提供了 .NET Core 初版中缺失的许多 API。.NET Framework 开发者过去 15 年可用的、与现代开发相关的库和应用程序现已迁移至 .NET，并能在 macOS、Linux 变种以及 Windows 上跨平台运行。

.NET Standard 2.1 新增约 3,000 个新 API。其中一些 API 需要运行时变更，这会破坏向后兼容性，因此 .NET Framework 4.8 仅实现 .NET Standard 2.0。.NET Core 3.0、Xamarin、Mono 和 Unity 实现 .NET Standard 2.1。

.NET 6 消除了对 .NET Standard 的需求，前提是所有项目都能使用 .NET 6。由于你可能仍需为遗留的 .NET Framework 项目或遗留的 Xamarin 移动应用创建类库，因此仍需创建 .NET Standard 2.0 和 2.1 类库。2021 年 3 月，我调查了专业开发者，其中一半仍需创建符合 .NET Standard 2.0 的类库。

随着 .NET 6 的发布，预览支持使用 .NET MAUI 构建的移动和桌面应用，对 .NET Standard 的需求进一步减少。

为了总结 .NET 在过去五年中的进展，我已将主要的 .NET Core 和现代 .NET 版本与相应的 .NET Framework 版本进行了比较，如下所示：

+   **.NET Core 1.x**：相较于 2016 年 3 月当时的当前版本 .NET Framework 4.6.1，API 规模小得多。

+   **.NET Core 2.x**：与 .NET Framework 4.7.1 实现了现代 API 的 API 对等，因为它们都实现了 .NET Standard 2.0。

+   **.NET Core 3.x**：相较于 .NET Framework，提供了更大的现代 API 集合，因为 .NET Framework 4.8 不实现 .NET Standard 2.1。

+   **.NET 5**：相较于 .NET Framework 4.8，提供了更大的现代 API 集合，性能显著提升。

+   **.NET 6**：最终统一，支持.NET MAUI 中的移动应用，预计于 2022 年 5 月实现。

## .NET Core 1.0

.NET Core 1.0 于 2016 年 6 月发布，重点在于实现适合构建现代跨平台应用的 API，包括为 Linux 使用 ASP.NET Core 构建的 Web 和云应用及服务。

## .NET Core 1.1

.NET Core 1.1 于 2016 年 11 月发布，主要关注于修复错误、增加支持的 Linux 发行版数量、支持.NET Standard 1.6，以及提升性能，特别是在使用 ASP.NET Core 构建的 Web 应用和服务方面。

## .NET Core 2.0

.NET Core 2.0 于 2017 年 8 月发布，重点在于实现.NET Standard 2.0，能够引用.NET Framework 库，以及更多的性能改进。

（本书）第三版于 2017 年 11 月出版，涵盖至.NET Core 2.0 及用于**通用 Windows 平台** (**UWP**) 应用的.NET Core。

## .NET Core 2.1

.NET Core 2.1 于 2018 年 5 月发布，重点在于可扩展的工具系统，新增类型如`Span<T>`，加密和压缩的新 API，包含额外 20,000 个 API 的 Windows 兼容包以帮助移植旧 Windows 应用，Entity Framework Core 值转换，LINQ `GroupBy` 转换，数据播种，查询类型，以及更多的性能改进，包括下表中列出的主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| 跨度 | 8 | 处理跨度、索引和范围 |
| Brotli 压缩 | 9 | 使用 Brotli 算法进行压缩 |
| 加密学 | 20 | 加密学有哪些新内容？ |
| EF Core 延迟加载 | 10 | 启用延迟加载 |
| EF Core 数据播种 | 10 | 理解数据播种 |

## .NET Core 2.2

.NET Core 2.2 于 2018 年 12 月发布，重点在于运行时诊断改进、可选的分层编译，以及为 ASP.NET Core 和 Entity Framework Core 添加新功能，如使用**NetTopologySuite** (**NTS**) 库类型的空间数据支持、查询标签和拥有的实体集合。

## .NET Core 3.0

.NET Core 3.0 于 2019 年 9 月发布，重点在于增加对使用 Windows Forms (2001)、**Windows Presentation Foundation** (**WPF**; 2006) 和 Entity Framework 6.3 构建 Windows 桌面应用的支持，支持并行和应用本地部署，快速的 JSON 阅读器，串口访问和其他引脚访问，用于**物联网** (**IoT**) 解决方案，以及默认的分层编译，包括下表中列出的主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| 应用内嵌.NET | 7 | 发布您的应用程序以供部署 |
| `Index` 和 `Range` | 8 | 处理跨度、索引和范围 |
| `System.Text.Json` | 9 | 高性能 JSON 处理 |
| 异步流 | 12 | 处理异步流 |

（本书）第四版于 2019 年 10 月出版，因此涵盖了后续版本中添加的一些新 API，直至.NET Core 3.0。

## .NET Core 3.1

.NET Core 3.1 于 2019 年 12 月发布，专注于 bug 修复和优化，以便成为 **长期支持** (**LTS**) 版本，直至 2022 年 12 月才停止支持。

## .NET 5.0

.NET 5.0 于 2020 年 11 月发布，专注于统一除移动平台外的各种 .NET 平台，优化平台，并提升性能，包括下表所列主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| `Half` 类型 | 8 | 数值操作 |
| 正则表达式性能提升 | 8 | 正则表达式性能提升 |
| `System.Text.Json` 性能改进 | 9 | 高效处理 JSON |
| EF Core 生成的 SQL | 10 | 获取生成的 SQL |
| EF Core 筛选包含 | 10 | 筛选包含的实体 |
| EF Core Scaffold-DbContext 现使用 Humanizer 进行单数化 | 10 | 基于现有数据库生成模型 |

## .NET 6.0

.NET 6.0 于 2021 年 11 月发布，重点在于与移动平台统一，为 EF Core 的数据管理添加更多功能，并提升性能，包括下表所列主题：

| 特性 | 章节 | 主题 |
| --- | --- | --- |
| 检查 .NET SDK 状态 | 7 | 检查 .NET SDK 更新 |
| 对 Apple Silicon 的支持 | 7 | 创建控制台应用程序发布 |
| 默认链接修剪模式 | 7 | 使用应用修剪减小应用大小 |
| `DateOnly` 和 `TimeOnly` | 8 | 指定日期和时间值 |
| `List<T>` 的 `EnsureCapacity` | 8 | 通过确保集合容量提升性能 |
| EF Core 配置约定 | 10 | 配置预约定模型 |
| 新增 LINQ 方法 | 11 | 使用 Enumerable 类构建 LINQ 表达式 |

## 从 .NET Core 2.0 到 .NET 5 的性能提升

微软在过去几年中对性能进行了重大改进。您可以在以下链接阅读详细博客文章：[`devblogs.microsoft.com/dotnet/performance-improvements-in-net-5/`](https://devblogs.microsoft.com/dotnet/performance-improvements-in-net-5/)。

## 检查 .NET SDK 更新

使用 .NET 6，微软添加了一个命令来检查已安装的 .NET SDK 和运行时版本，并在需要更新时发出警告。例如，您输入以下命令：

```cs
dotnet sdk check 
```

随后，您将看到包括可用更新状态在内的结果，如下所示的部分输出：

```cs
.NET SDKs:
Version                         Status
-----------------------------------------------------------------------------
3.1.412                         Up to date.
5.0.202                         Patch 5.0.206 is available.
... 
```

# 理解 .NET 组件

.NET 由多个部分组成，如下所示：

+   **语言编译器**：这些编译器将使用 C#、F# 和 Visual Basic 等语言编写的源代码转换为 **中间语言** (**IL**) 代码，存储在程序集中。使用 C# 6.0 及更高版本，微软转向了名为 Roslyn 的开源重写编译器，该编译器也用于 Visual Basic。

+   **公共语言运行时（CoreCLR）**：此运行时加载程序集，将存储在其中的 IL 代码编译为计算机 CPU 的本地代码指令，并在管理线程和内存等资源的环境中执行代码。

+   **基类库（BCL 或 CoreFX）**：这些是预构建的类型集合，通过 NuGet 打包和分发，用于在构建应用程序时执行常见任务。你可以使用它们快速构建任何你想要的东西，就像组合乐高™积木一样。.NET Core 2.0 实现了.NET 标准 2.0，它是所有先前版本的.NET 标准的超集，并将.NET Core 提升到与.NET Framework 和 Xamarin 平齐。.NET Core 3.0 实现了.NET 标准 2.1，增加了新的功能，并实现了在.NET Framework 中不可用的性能改进。.NET 6 在所有类型的应用程序中实现了一个统一的 BCL，包括移动应用。

## 理解程序集、NuGet 包和命名空间

**程序集**是类型在文件系统中存储的位置。程序集是一种部署代码的机制。例如，`System.Data.dll`程序集包含管理数据的类型。要使用其他程序集中的类型，必须引用它们。程序集可以是静态的（预先创建的）或动态的（在运行时生成的）。动态程序集是一个高级特性，本书中不会涉及。程序集可以编译成单个文件，作为 DLL（类库）或 EXE（控制台应用）。

程序集作为**NuGet 包**分发，这些是可以从公共在线源下载的文件，可以包含多个程序集和其他资源。你还会听到关于**项目 SDK**、**工作负载**和**平台**的说法，这些都是 NuGet 包的组合。

Microsoft 的 NuGet 源在这里：[`www.nuget.org/`](https://www.nuget.org/)。

### 什么是命名空间？

命名空间是类型的地址。命名空间是一种机制，通过要求完整的地址而不是简短的名称来唯一标识类型。在现实世界中，*34 号梧桐街的鲍勃*与*12 号柳树道的鲍勃*是不同的。

在.NET 中，`System.Web.Mvc`命名空间中的`IActionFilter`接口与`System.Web.Http.Filters`命名空间中的`IActionFilter`接口不同。

### 理解依赖的程序集

如果一个程序集被编译为类库并提供类型供其他程序集使用，那么它具有文件扩展名`.dll`（**动态链接库**），并且不能独立执行。

同样，如果一个程序集被编译为应用程序，那么它具有文件扩展名`.exe`（**可执行文件**），并且可以独立执行。在.NET Core 3.0 之前，控制台应用被编译为`.dll`文件，必须通过`dotnet run`命令或宿主可执行文件来执行。

任何程序集都可以引用一个或多个类库程序集作为依赖项，但不能有循环引用。因此，如果程序集*A*已经引用程序集*B*，则程序集*B*不能引用程序集*A*。如果您尝试添加会导致循环引用的依赖项引用，编译器会警告您。循环引用通常是代码设计不良的警告信号。如果您确定需要循环引用，则使用接口来解决它。

## 理解 Microsoft .NET 项目 SDKs

默认情况下，控制台应用程序对 Microsoft .NET 项目 SDK 有依赖引用。该平台包含数千种类型，几乎所有应用程序都需要这些类型，例如`System.Int32`和`System.String`类型。

在使用.NET 时，您在项目文件中引用应用程序所需的依赖程序集、NuGet 包和平台。

让我们探讨程序集和命名空间之间的关系：

1.  使用您偏好的代码编辑器创建一个名为`Chapter07`的新解决方案/工作区。

1.  添加一个控制台应用项目，如下表所定义：

    1.  项目模板：**控制台应用程序** / `console`

    1.  工作区/解决方案文件和文件夹：`Chapter07`

    1.  项目文件和文件夹：`AssembliesAndNamespaces`

1.  打开`AssembliesAndNamespaces.csproj`并注意，它是一个典型的.NET 6 应用程序项目文件，如下所示：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <OutputType>Exe</OutputType>
        <TargetFramework>net6.0</TargetFramework>
        <Nullable>enable</Nullable>
        <ImplicitUsings>enable</ImplicitUsings>
      </PropertyGroup>
    </Project> 
    ```

## 理解程序集中的命名空间和类型

许多常见的.NET 类型位于`System.Runtime.dll`程序集中。程序集和命名空间之间并不总是存在一对一的映射。单个程序集可以包含多个命名空间，一个命名空间也可以在多个程序集中定义。您可以查看一些程序集与其提供的类型的命名空间之间的关系，如下表所示：

| 程序集 | 示例命名空间 | 示例类型 |
| --- | --- | --- |
| `System.Runtime.dll` | `System`, `System.Collections`, `System.Collections.Generic` | `Int32`, `String`, `IEnumerable<T>` |
| `System.Console.dll` | `System` | `Console` |
| `System.Threading.dll` | `System.Threading` | `Interlocked`, `Monitor`, `Mutex` |
| `System.Xml.XDocument.dll` | `System.Xml.Linq` | `XDocument`, `XElement`, `XNode` |

## 理解 NuGet 包

.NET 被拆分为一组包，使用名为 NuGet 的微软支持的包管理技术进行分发。这些包中的每一个都代表一个同名的单一程序集。例如，`System.Collections`包包含`System.Collections.dll`程序集。

以下是包的好处：

+   包可以轻松地在公共源中分发。

+   包可以重复使用。

+   包可以按照自己的时间表发货。

+   包可以独立于其他包进行测试。

+   通过包含为不同操作系统和 CPU 构建的同一程序集的多个版本，包可以支持不同的操作系统（OSes）和 CPU。

+   包可以有仅针对一个库的特定依赖项。

+   应用体积更小，因为未引用的包不包含在分发中。下表列出了一些较重要的包及其重要类型：

| 包 | 重要类型 |
| --- | --- |
| `System.Runtime` | `Object`，`String`，`Int32`，`Array` |
| `System.Collections` | `List<T>`，`Dictionary<TKey, TValue>` |
| `System.Net.Http` | `HttpClient`，`HttpResponseMessage` |
| `System.IO.FileSystem` | `File`，`Directory` |
| `System.Reflection` | `Assembly`，`TypeInfo`，`MethodInfo` |

## 理解框架

框架与包之间存在双向关系。包定义 API，而框架则整合包。一个没有任何包的框架不会定义任何 API。

.NET 包各自支持一组框架。例如，`System.IO.FileSystem`包版本 4.3.0 支持以下框架：

+   .NET Standard，版本 1.3 或更高。

+   .NET Framework，版本 4.6 或更高。

+   六个 Mono 和 Xamarin 平台（例如，Xamarin.iOS 1.0）。

    **更多信息**：你可以在以下链接阅读详细信息：[`www.nuget.org/packages/System.IO.FileSystem/`](https://www.nuget.org/packages/System.IO.FileSystem/)。

## 导入命名空间以使用类型

让我们探讨命名空间与程序集和类型之间的关系：

1.  在`AssembliesAndNamespaces`项目中，在`Program.cs`文件里，输入以下代码：

    ```cs
    XDocument doc = new(); 
    ```

1.  构建项目并注意编译器错误信息，如下所示：

    ```cs
    The type or namespace name 'XDocument' could not be found (are you missing a using directive or an assembly reference?) 
    ```

    `XDocument`类型未被识别，因为我们没有告诉编译器该类型的命名空间是什么。尽管此项目已有一个指向包含该类型的程序集的引用，我们还需通过在其类型名前加上命名空间或导入命名空间来解决。

1.  点击`XDocument`类名内部。你的代码编辑器会显示一个灯泡图标，表明它识别了该类型，并能自动为你修复问题。

1.  点击灯泡图标，并从菜单中选择`using System.Xml.Linq;`。

这将*通过在文件顶部添加`using`语句来导入命名空间*。一旦在代码文件顶部导入了命名空间，那么该命名空间内的所有类型在该代码文件中只需输入其名称即可使用，无需通过在其名称前加上命名空间来完全限定类型名。

有时我喜欢在导入命名空间后添加一个带有类型名的注释，以提醒我为何需要导入该命名空间，如下所示：

```cs
using System.Xml.Linq; // XDocument 
```

## 将 C#关键字关联到.NET 类型

我常从初学 C#的程序员那里得到的一个常见问题是：“`string`（小写 s）和`String`（大写 S）之间有什么区别？”

简短的答案是：没有区别。详细的答案是，所有 C#类型关键字，如`string`或`int`，都是.NET 类库程序集中某个类型的别名。

当你使用`string`关键字时，编译器将其识别为`System.String`类型。当你使用`int`类型时，编译器将其识别为`System.Int32`类型。

让我们通过一些代码来实际看看：

1.  在`Program.cs`中，声明两个变量以保存`string`值，一个使用小写的`string`，另一个使用大写的`String`，如下列代码所示：

    ```cs
    string s1 = "Hello"; 
    String s2 = "World";
    WriteLine($"{s1} {s2}"); 
    ```

1.  运行代码，并注意目前它们两者工作效果相同，实际上意味着相同的事情。

1.  在`AssembliesAndNamespaces.csproj`中，添加条目以防止全局导入`System`命名空间，如下列标记所示：

    ```cs
    <ItemGroup>
      <Using Remove="System" />
    </ItemGroup> 
    ```

1.  在`Program.cs`中注意编译器错误消息，如下列输出所示：

    ```cs
    The type or namespace name 'String' could not be found (are you missing a using directive or an assembly reference?) 
    ```

1.  在`Program.cs`顶部，使用`using`语句导入`System`命名空间以修复错误，如下列代码所示：

    ```cs
    using System; // String 
    ```

**最佳实践**：当有选择时，使用 C# 关键字而非实际类型，因为关键字不需要导入命名空间。

### C# 别名映射到 .NET 类型

下表显示了 18 个 C# 类型关键字及其对应的实际 .NET 类型：

| 关键字 | .NET 类型 | 关键字 | .NET 类型 |
| --- | --- | --- | --- |
| `string` | `System.String` | `char` | `System.Char` |
| `sbyte` | `System.SByte` | `byte` | `System.Byte` |
| `short` | `System.Int16` | `ushort` | `System.UInt16` |
| `int` | `System.Int32` | `uint` | `System.UInt32` |
| `long` | `System.Int64` | `ulong` | `System.UInt64` |
| `nint` | `System.IntPtr` | `nuint` | `System.UIntPtr` |
| `float` | `System.Single` | `double` | `System.Double` |
| `decimal` | `System.Decimal` | `bool` | `System.Boolean` |
| `object` | `System.Object` | `dynamic` | `System.Dynamic.DynamicObject` |

其他 .NET 编程语言编译器也能做到同样的事情。例如，Visual Basic .NET 语言有一个名为`Integer`的类型，它是`System.Int32`的别名。

#### 理解原生大小整数

C# 9 引入了`nint`和`nuint`关键字别名，用于**原生大小整数**，意味着整数值的存储大小是平台特定的。它们在 32 位进程中存储 32 位整数，`sizeof()`返回 4 字节；在 64 位进程中存储 64 位整数，`sizeof()`返回 8 字节。这些别名代表内存中整数值的指针，这就是为什么它们的 .NET 名称是`IntPtr`和`UIntPtr`。实际存储类型将根据进程是`System.Int32`还是`System.Int64`。

在 64 位进程中，下列代码：

```cs
WriteLine($"int.MaxValue = {int.MaxValue:N0}");
WriteLine($"nint.MaxValue = {nint.MaxValue:N0}"); 
```

产生此输出：

```cs
int.MaxValue = 2,147,483,647
nint.MaxValue = 9,223,372,036,854,775,807 
```

### 揭示类型的位置

代码编辑器为 .NET 类型提供内置文档。我们来探索一下：

1.  在`XDocument`内部右键单击并选择**转到定义**。

1.  导航到代码文件顶部，并注意程序集文件名为`System.Xml.XDocument.dll`，但类位于`System.Xml.Linq`命名空间中，如*图 7.1*所示：![图形用户界面，文本，应用程序，电子邮件 描述自动生成](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_07_01.png)

    图 7.1：包含 XDocument 类型的程序集和命名空间

1.  关闭**XDocument [来自元数据]**选项卡。

1.  在`string`或`String`内部右键单击并选择**转到定义**。

1.  导航至代码文件顶部，注意程序集文件名为`System.Runtime.dll`，但类位于`System`命名空间中。

实际上，你的代码编辑器在技术上对你撒了谎。如果你还记得我们在*第二章*，*讲 C#*中编写代码时，当我们揭示 C#词汇的范围时，我们发现`System.Runtime.dll`程序集中不包含任何类型。

它包含的是类型转发器。这些特殊类型看似存在于一个程序集中，但实际上在别处实现。在这种情况下，它们在.NET 运行时内部深处使用高度优化的代码实现。

## 使用.NET Standard 与遗留平台共享代码

.NET Standard 出现之前，有**便携式类库**（**PCLs**）。使用 PCLs，你可以创建一个代码库，并明确指定希望该库支持的平台，如 Xamarin、Silverlight 和 Windows 8。你的库随后可以使用这些指定平台所支持的 API 交集。

微软意识到这是不可持续的，因此他们创建了.NET Standard——一个所有未来.NET 平台都将支持的单一 API。有较早版本的.NET Standard，但.NET Standard 2.0 试图统一所有重要的近期.NET 平台。.NET Standard 2.1 于 2019 年底发布，但只有.NET Core 3.0 和当年版本的 Xamarin 支持其新特性。在本书的其余部分，我将使用.NET Standard 来指代.NET Standard 2.0。

.NET Standard 类似于 HTML5，它们都是平台应支持的标准。正如谷歌的 Chrome 浏览器和微软的 Edge 浏览器实现 HTML5 标准一样，.NET Core、.NET Framework 和 Xamarin 都实现.NET Standard。如果你想创建一个能在遗留.NET 各变体间工作的类型库，最简便的方法就是使用.NET Standard。

**最佳实践**：由于.NET Standard 2.1 中的许多 API 新增内容需要运行时变更，而.NET Framework 作为微软的遗留平台，需要尽可能保持不变，因此.NET Framework 4.8 仍停留在.NET Standard 2.0，并未实现.NET Standard 2.1。若需支持.NET Framework 用户，则应基于.NET Standard 2.0 创建类库，尽管它不是最新版本，也不支持所有近期的语言和 BCL 新特性。

选择针对哪个.NET Standard 版本，取决于在最大化平台支持和可用功能之间的权衡。较低版本支持更多平台，但 API 集较小；较高版本支持的平台较少，但 API 集更大。通常，应选择支持所需所有 API 的最低版本。

## 理解不同 SDK 下类库的默认设置

当使用`dotnet` SDK 工具创建类库时，了解默认使用的目标框架可能会有所帮助，如下表所示：

| SDK | 新类库的默认目标框架 |
| --- | --- |
| .NET Core 3.1 | `netstandard2.0` |
| .NET 5 | `net5.0` |
| .NET 6 | `net6.0` |

当然，仅仅因为类库默认面向特定版本的 .NET，并不意味着在创建使用默认模板的类库项目后不能更改它。

您可以手动将目标框架设置为支持需要引用该库的项目的值，如下表所示：

| 类库目标框架 | 可用于面向以下版本的项目 |
| --- | --- |
| `netstandard2.0` | .NET Framework 4.6.1 或更高版本，.NET Core 2.0 或更高版本，.NET 5.0 或更高版本，Mono 5.4 或更高版本，Xamarin.Android 8.0 或更高版本，Xamarin.iOS 10.14 或更高版本 |
| `netstandard2.1` | .NET Core 3.0 或更高版本，.NET 5.0 或更高版本，Mono 6.4 或更高版本，Xamarin.Android 10.0 或更高版本，Xamarin.iOS 12.16 或更高版本 |
| `net5.0` | .NET 5.0 或更高版本 |
| `net6.0` | .NET 6.0 或更高版本 |

**最佳实践**：始终检查类库的目标框架，并在必要时手动将其更改为更合适的选项。要有意识地决定它应该是什么，而不是接受默认值。

## 创建 .NET Standard 2.0 类库

我们将创建一个使用 .NET Standard 2.0 的类库，以便它可以在所有重要的 .NET 遗留平台上以及在 Windows、macOS 和 Linux 操作系统上跨平台使用，同时还可以访问广泛的 .NET API 集：

1.  使用您喜欢的代码编辑器向 `Chapter07` 解决方案/工作区添加一个名为 `SharedLibrary` 的新类库。

1.  如果您使用的是 Visual Studio 2022，当提示选择**目标框架**时，请选择 **.NET Standard 2.0**，然后将解决方案的启动项目设置为当前选择。

1.  如果您使用的是 Visual Studio Code，请包含一个目标为 .NET Standard 2.0 的开关，如下面的命令所示：

    ```cs
    dotnet new classlib -f netstandard2.0 
    ```

1.  如果您使用的是 Visual Studio Code，请选择 `SharedLibrary` 作为活动的 OmniSharp 项目。

**最佳实践**：如果您需要创建使用 .NET 6.0 新功能的类型，以及仅使用 .NET Standard 2.0 功能的类型，那么您可以创建两个单独的类库：一个面向 .NET Standard 2.0，另一个面向 .NET 6.0。您将在*第十章*，*使用 Entity Framework Core 处理数据*中看到这一操作。

手动创建两个类库的替代方法是创建一个支持多目标的类库。如果您希望我在下一版中添加关于多目标的章节，请告诉我。您可以在这里阅读关于多目标的信息：[`docs.microsoft.com/en-us/dotnet/standard/library-guidance/cross-platform-targeting#multi-targeting`](https://docs.microsoft.com/en-us/dotnet/standard/library-guidance/cross-platform-targeting#multi-targeting)。

## 控制 .NET SDK

默认情况下，执行 `dotnet` 命令使用最新安装的 .NET SDK。有时您可能希望控制使用哪个 SDK。

例如，第四版的某位读者希望其体验与书中使用.NET Core 3.1 SDK 的步骤相匹配。但他们也安装了.NET 5.0 SDK，并且默认使用的是这个版本。如前一节所述，创建新类库时的行为已更改为针对.NET 5.0 而非.NET Standard 2.0，这让读者感到困惑。

通过使用`global.json`文件，你可以控制默认使用的.NET SDK。`dotnet`命令会在当前文件夹及其祖先文件夹中搜索`global.json`文件。

1.  在`Chapter07`文件夹中创建一个名为`ControlSDK`的子目录/文件夹。

1.  在 Windows 上，启动**命令提示符**或**Windows 终端**。在 macOS 上，启动**终端**。如果你使用的是 Visual Studio Code，则可以使用集成终端。

1.  在`ControlSDK`文件夹中，在命令提示符或终端下，输入创建强制使用最新.NET Core 3.1 SDK 的`global.json`文件的命令，如下所示：

    ```cs
    dotnet new globaljson --sdk-version 3.1.412 
    ```

1.  打开`global.json`文件并审查其内容，如下所示：

    ```cs
    {
      "sdk": {
        "version": "3.1.412"
      }
    } 
    ```

    你可以在以下链接的表格中找到最新.NET SDK 的版本号：[`dotnet.microsoft.com/download/visual-studio-sdks`](https://dotnet.microsoft.com/download/visual-studio-sdks)

1.  在`ControlSDK`文件夹中，在命令提示符或终端下，输入创建类库项目的命令，如下所示：

    ```cs
    dotnet new classlib 
    ```

1.  如果你未安装.NET Core 3.1 SDK，则会看到如下所示的错误：

    ```cs
    Could not execute because the application was not found or a compatible .NET SDK is not installed. 
    ```

1.  如果你已安装.NET Core 3.1 SDK，则默认将创建一个针对.NET Standard 2.0 的类库项目。

你无需完成上述步骤，但如果你想尝试且尚未安装.NET Core 3.1 SDK，则可以从以下链接安装：

[`dotnet.microsoft.com/download/dotnet/3.1`](https://dotnet.microsoft.com/download/dotnet/3.1)

# 发布你的代码以供部署

如果你写了一部小说并希望其他人阅读，你必须将其出版。

大多数开发者编写代码供其他开发者在他们的代码中使用，或者供用户作为应用程序运行。为此，你必须将你的代码发布为打包的类库或可执行应用程序。

发布和部署.NET 应用程序有三种方式，它们是：

1.  **依赖框架的部署**（**FDD**）。

1.  **依赖框架的可执行文件**（**FDEs**）。

1.  自包含。

如果你选择部署应用程序及其包依赖项，但不包括.NET 本身，那么你依赖于目标计算机上已有的.NET。这对于部署到服务器的 Web 应用程序非常有效，因为.NET 和其他许多 Web 应用程序可能已经在服务器上。

**框架依赖部署**（**FDD**）意味着您部署的是必须由`dotnet`命令行工具执行的 DLL。**框架依赖可执行文件**（**FDE**）意味着您部署的是可以直接从命令行运行的 EXE。两者都要求系统上已安装.NET。

有时，您希望能够在 USB 闪存驱动器上提供您的应用程序，并确保它能在他人的计算机上执行。您希望进行自包含部署。虽然部署文件的大小会更大，但您可以确信它将能够运行。

## 创建一个控制台应用程序以发布

让我们探索如何发布一个控制台应用程序：

1.  使用您偏好的代码编辑器，在`Chapter07`解决方案/工作区中添加一个名为`DotNetEverywhere`的新控制台应用。

1.  在 Visual Studio Code 中，选择`DotNetEverywhere`作为活动的 OmniSharp 项目。当看到弹出警告消息提示缺少必需资产时，点击**是**以添加它们。

1.  在`Program.cs`中，删除注释并静态导入`Console`类。

1.  在`Program.cs`中，添加一条语句，输出一条消息，表明控制台应用可在任何地方运行，并提供一些关于操作系统的信息，如下所示：

    ```cs
    WriteLine("I can run everywhere!");
    WriteLine($"OS Version is {Environment.OSVersion}.");
    if (OperatingSystem.IsMacOS())
    {
      WriteLine("I am macOS.");
    }
    else if (OperatingSystem.IsWindowsVersionAtLeast(major: 10))
    {
      WriteLine("I am Windows 10 or 11.");
    }
    else
    {
      WriteLine("I am some other mysterious OS.");
    }
    WriteLine("Press ENTER to stop me.");
    ReadLine(); 
    ```

1.  打开`DotNetEverywhere.csproj`文件，并在`<PropertyGroup>`元素内添加运行时标识符，以针对三个操作系统进行目标设定，如下所示的高亮标记：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <OutputType>Exe</OutputType>
        <TargetFramework>net6.0</TargetFramework>
        <Nullable>enable</Nullable>
        <ImplicitUsings>enable</ImplicitUsings>
     **<RuntimeIdentifiers>**
     **win10-x64;osx-x64;osx****.11.0****-arm64;linux-x64;linux-arm64**
     **</RuntimeIdentifiers>**
      </PropertyGroup>
    </Project> 
    ```

    +   `win10-x64` RID 值表示 Windows 10 或 Windows Server 2016 的 64 位版本。您也可以使用`win10-arm64` RID 值来部署到 Microsoft Surface Pro X。

    +   `osx-x64` RID 值表示 macOS Sierra 10.12 或更高版本。您也可以指定特定版本的 RID 值，如`osx.10.15-x64`（Catalina）、`osx.11.0-x64`（Intel 上的 Big Sur）或`osx.11.0-arm64`（Apple Silicon 上的 Big Sur）。

    +   `linux-x64` RID 值适用于大多数桌面 Linux 发行版，如 Ubuntu、CentOS、Debian 或 Fedora。使用`linux-arm`适用于 Raspbian 或 Raspberry Pi OS 的 32 位版本。使用`linux-arm64`适用于运行 Ubuntu 64 位的 Raspberry Pi。

## 理解 dotnet 命令

安装.NET SDK 时，它会包含一个名为`dotnet`的**命令行界面(CLI)**。

### 创建新项目

.NET CLI 拥有在当前文件夹上工作的命令，用于使用模板创建新项目：

1.  在 Windows 上，启动**命令提示符**或**Windows 终端**。在 macOS 上，启动**终端**。如果您使用的是 Visual Studio Code，则可以使用集成终端。

1.  输入`dotnet new --list`或`dotnet new -l`命令，列出您当前安装的模板，如*图 7.2*所示：![图 7.2：已安装的 dotnet new 项目模板列表](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_07_02.png)

*图 7.2：已安装的 dotnet new 项目模板列表*

大多数`dotnet`命令行开关都有长版和短版。例如，`--list`或`-l`。短版输入更快，但更容易被您或其他人类误解。有时，多输入一些字符会更清晰。

## 获取有关.NET 及其环境的信息

查看当前安装的 .NET SDK 和运行时以及操作系统信息非常有用，如下所示：

```cs
dotnet --info 
```

注意结果，如下所示：

```cs
.NET SDK (reflecting any global.json):
 Version:   6.0.100
 Commit:    22d70b47bc
Runtime Environment:
 OS Name:     Windows
 OS Version:  10.0.19043
 OS Platform: Windows
 RID:         win10-x64
 Base Path:   C:\Program Files\dotnet\sdk\6.0.100\
Host (useful for support):
  Version: 6.0.0
  Commit:  91ba01788d
.NET SDKs installed:
  3.1.412 [C:\Program Files\dotnet\sdk]
  5.0.400 [C:\Program Files\dotnet\sdk]
  6.0.100 [C:\Program Files\dotnet\sdk]
.NET runtimes installed:
  Microsoft.AspNetCore.All 2.1.29 [...\dotnet\shared\Microsoft.AspNetCore.All]
... 
```

## 项目管理

.NET CLI 提供了以下命令，用于管理当前文件夹中的项目：

+   `dotnet restore`: 此命令下载项目的依赖项。

+   `dotnet build`: 此命令构建（即编译）项目。

+   `dotnet test`: 此命令构建项目并随后运行单元测试。

+   `dotnet run`: 此命令构建项目并随后运行。

+   `dotnet pack`: 此命令为项目创建 NuGet 包。

+   `dotnet publish`: 此命令构建并发布项目，无论是包含依赖项还是作为自包含应用程序。

+   `dotnet add`: 此命令向项目添加对包或类库的引用。

+   `dotnet remove`: 此命令从项目中移除对包或类库的引用。

+   `dotnet list`: 此命令列出项目对包或类库的引用。

## 发布自包含应用

既然你已经看到了一些 `dotnet` 工具命令的示例，我们可以发布我们的跨平台控制台应用：

1.  在命令行中，确保你位于 `DotNetEverywhere` 文件夹中。

1.  输入以下命令以构建并发布适用于 Windows 10 的控制台应用程序的发布版本：

    ```cs
    dotnet publish -c Release -r win10-x64 
    ```

1.  注意，构建引擎会恢复任何需要的包，将项目源代码编译成程序集 DLL，并创建一个 `publish` 文件夹，如下所示：

    ```cs
    Microsoft (R) Build Engine version 17.0.0+073022eb4 for .NET
    Copyright (C) Microsoft Corporation. All rights reserved.
      Determining projects to restore...
      Restored C:\Code\Chapter07\DotNetEverywhere\DotNetEverywhere.csproj (in 46.89 sec).
      DotNetEverywhere -> C:\Code\Chapter07\DotNetEverywhere\bin\Release\net6.0\win10-x64\DotNetEverywhere.dll
      DotNetEverywhere -> C:\Code\Chapter07\DotNetEverywhere\bin\Release\net6.0\win10-x64\publish\ 
    ```

1.  输入以下命令以构建并发布适用于 macOS 和 Linux 变体的发布版本：

    ```cs
    dotnet publish -c Release -r osx-x64
    dotnet publish -c Release -r osx.11.0-arm64
    dotnet publish -c Release -r linux-x64
    dotnet publish -c Release -r linux-arm64 
    ```

    **最佳实践**：你可以使用 PowerShell 等脚本语言自动化这些命令，并通过跨平台的 PowerShell Core 在任何操作系统上执行。只需创建一个扩展名为 `.ps1` 的文件，其中包含这五个命令。然后执行该文件。更多关于 PowerShell 的信息，请访问以下链接：[`github.com/markjprice/cs10dotnet6/tree/main/docs/powershell`](https://github.com/markjprice/cs10dotnet6/tree/main/docs/powershell)

1.  打开 macOS **Finder** 窗口或 Windows **文件资源管理器**，导航至 `DotNetEverywhere\bin\Release\net6.0`，并注意针对不同操作系统的输出文件夹。

1.  在 `win10-x64` 文件夹中，选择 `publish` 文件夹，注意所有支持程序集，如 `Microsoft.CSharp.dll`。

1.  选择 `DotNetEverywhere` 可执行文件，并注意其大小为 161 KB，如图 *7.3* 所示：![图形用户界面 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_07_03.png)

    图 7.3：适用于 Windows 10 64 位的 DotNetEverywhere 可执行文件

1.  如果你使用的是 Windows，则双击执行程序并注意结果，如下所示：

    ```cs
    I can run everywhere!
    OS Version is Microsoft Windows NT 10.0.19042.0.
    I am Windows 10.
    Press ENTER to stop me. 
    ```

1.  注意，`publish` 文件夹及其所有文件的总大小为 64.8 MB。

1.  在`osx.11.0-arm64`文件夹中，选择`publish`文件夹，注意所有支持的程序集，然后选择`DotNetEverywhere`可执行文件，并注意可执行文件为 126 KB，而`publish`文件夹为 71.8 MB。

如果你将任何`publish`文件夹复制到相应的操作系统，控制台应用程序将运行；这是因为它是自包含的可部署.NET 应用程序。例如，在配备 Intel 芯片的 macOS 上，如下所示：

```cs
I can run everywhere!
OS Version is Unix 11.2.3
I am macOS.
Press ENTER to stop me. 
```

本例使用的是控制台应用程序，但你同样可以轻松创建一个 ASP.NET Core 网站或 Web 服务，或是 Windows Forms 或 WPF 应用程序。当然，你只能将 Windows 桌面应用程序部署到 Windows 计算机上，不能部署到 Linux 或 macOS。

## 发布单文件应用程序

要发布为“单个”文件，你可以在发布时指定标志。在.NET 5 中，单文件应用程序主要关注 Linux，因为 Windows 和 macOS 都存在限制，这意味着真正的单文件发布在技术上是不可能的。在.NET 6 中，你现在可以在 Windows 上创建真正的单文件应用程序。

如果你能假设目标计算机上已安装.NET 6，那么在发布应用程序时，你可以使用额外的标志来表明它不需要自包含，并且你希望将其发布为单个文件（如果可能），如下所示（该命令必须在一行内输入）：

```cs
dotnet publish -r win10-x64 -c Release --self-contained=false
/p:PublishSingleFile=true 
```

这将生成两个文件：`DotNetEverywhere.exe`和`DotNetEverywhere.pdb`。`.exe`是可执行文件，而`.pdb`文件是**程序调试数据库**文件，存储调试信息。

macOS 上发布的应用程序没有`.exe`文件扩展名，因此如果你在上面的命令中使用`osx-x64`，文件名将不会有扩展名。

如果你希望将`.pdb`文件嵌入到`.exe`文件中，那么请在你的`.csproj`文件中的`<PropertyGroup>`元素内添加一个`<DebugType>`元素，并将其设置为`embedded`，如下所示：

```cs
<PropertyGroup>
  <OutputType>Exe</OutputType>
  <TargetFramework>net6.0</TargetFramework>
  <Nullable>enable</Nullable>
  <ImplicitUsings>enable</ImplicitUsings>
  <RuntimeIdentifiers>
    win10-x64;osx-x64;osx.11.0-arm64;linux-x64;linux-arm64
  </RuntimeIdentifiers>
 **<DebugType>embedded</DebugType>**
</PropertyGroup> 
```

如果你不能假设目标计算机上已安装.NET 6，那么在 Linux 上虽然也只生成两个文件，但 Windows 上还需额外生成以下文件：`coreclr.dll`、`clrjit.dll`、`clrcompression.dll`和`mscordaccore.dll`。

让我们看一个 Windows 的示例：

1.  在命令行中，输入构建 Windows 10 控制台应用程序的发布版本的命令，如下所示：

    ```cs
    dotnet publish -c Release -r win10-x64 /p:PublishSingleFile=true 
    ```

1.  导航到`DotNetEverywhere\bin\Release\net6.0\win10-x64\publish`文件夹，选择`DotNetEverywhere`可执行文件，并注意可执行文件现在为 58.3 MB，还有一个 10 KB 的`.pdb`文件。你系统上的大小可能会有所不同。

## 通过应用程序修剪减小应用程序大小

将.NET 应用程序部署为自包含应用程序的一个问题是.NET 库占用了大量空间。其中，对减小体积需求最大的就是 Blazor WebAssembly 组件，因为所有.NET 库都需要下载到浏览器中。

幸运的是，您可以通过不在部署中打包未使用的程序集来减少此大小。随着.NET Core 3.0 的引入，应用修剪系统可以识别您的代码所需的程序集并移除不需要的那些。

随着.NET 5，修剪更进一步，通过移除单个类型，甚至是程序集内未使用的方法等成员。例如，使用 Hello World 控制台应用，`System.Console.dll`程序集从 61.5 KB 修剪到 31.5 KB。对于.NET 5，这是一个实验性功能，因此默认情况下是禁用的。

随着.NET 6，微软在其库中添加了注解，以指示它们如何可以安全地修剪，因此类型和成员的修剪被设为默认。这被称为**链接修剪模式**。

关键在于修剪如何准确识别未使用的程序集、类型和成员。如果您的代码是动态的，可能使用反射，那么它可能无法正常工作，因此微软也允许手动控制。

### 启用程序集级别修剪

有两种方法可以启用程序集级别修剪。

第一种方法是在项目文件中添加一个元素，如下面的标记所示：

```cs
<PublishTrimmed>true</PublishTrimmed> 
```

第二种方法是在发布时添加一个标志，如下面的命令中突出显示的那样：

```cs
dotnet publish ... **-p:PublishTrimmed=True** 
```

### 启用类型级别和成员级别修剪

有两种方法可以启用类型级别和成员级别修剪。

第一种方法是在项目文件中添加两个元素，如下面的标记所示：

```cs
<PublishTrimmed>true</PublishTrimmed>
<TrimMode>Link</TrimMode> 
```

第二种方法是在发布时添加两个标志，如下面的命令中突出显示的那样：

```cs
dotnet publish ... **-p:PublishTrimmed=True -p:TrimMode=Link** 
```

对于.NET 6，链接修剪模式是默认的，因此您只需在想要设置如`copyused`等替代修剪模式时指定开关，这意味着程序集级别修剪。

# 反编译.NET 程序集

学习如何为.NET 编码的最佳方法之一是观察专业人士如何操作。

**良好实践**：您可以出于非学习目的反编译他人的程序集，例如复制他们的代码以用于您自己的生产库或应用程序，但请记住您正在查看他们的知识产权，因此请予以尊重。

## 使用 Visual Studio 2022 的 ILSpy 扩展进行反编译

出于学习目的，您可以使用 ILSpy 等工具反编译任何.NET 程序集。

1.  在 Windows 上的 Visual Studio 2022 中，导航至**扩展** | **管理扩展**。

1.  在搜索框中输入`ilspy`。

1.  对于**ILSpy**扩展，点击**下载**。

1.  点击**关闭**。

1.  关闭 Visual Studio 以允许扩展安装。

1.  重启 Visual Studio 并重新打开`Chapter07`解决方案。

1.  在**解决方案资源管理器**中，右键点击**DotNetEverywhere**项目并选择**在 ILSpy 中打开输出**。

1.  导航至**文件** | **打开…**。

1.  导航至以下文件夹：

    ```cs
    Code/Chapter07/DotNetEverywhere/bin/Release/net6.0/linux-x64 
    ```

1.  选择`System.IO.FileSystem.dll`程序集并点击**打开**。

1.  在**程序集**树中，展开**System.IO.FileSystem**程序集，展开**System.IO**命名空间，选择**Directory**类，并等待其反编译。

1.  在 `Directory` 类中，点击 **[+]** 展开 `GetParent` 方法，如图 *7.4* 所示：![图形用户界面，文本，应用程序 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_07_04.png)

    图 7.4：Windows 上 Directory 类的反编译 GetParent 方法

1.  注意检查 `path` 参数的良好实践，如果为 `null` 则抛出 `ArgumentNullException`，如果长度为零则抛出 `ArgumentException`。

1.  关闭 ILSpy。

## 使用 ILSpy 扩展进行反编译

类似的功能作为 Visual Studio Code 的扩展在跨平台上可用。

1.  如果您尚未安装 **ILSpy .NET Decompiler** 扩展，请搜索并安装它。

1.  在 macOS 或 Linux 上，该扩展依赖于 Mono，因此您还需要从以下链接安装 Mono：[`www.mono-project.com/download/stable/`](https://www.mono-project.com/download/stable/)。

1.  在 Visual Studio Code 中，导航到 **View** | **Command Palette…**。

1.  输入 `ilspy` 然后选择 **ILSpy: Decompile IL Assembly (pick file)**。

1.  导航到以下文件夹：

    ```cs
    Code/Chapter07/DotNetEverywhere/bin/Release/net6.0/linux-x64 
    ```

1.  选择 `System.IO.FileSystem.dll` 程序集并点击 **Select assembly**。看似无事发生，但您可以通过查看 **Output** 窗口，在下拉列表中选择 **ilspy-vscode**，并查看处理过程来确认 ILSpy 是否在工作，如图 *7.5* 所示：![图形用户界面，文本，应用程序，电子邮件 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_07_05.png)

    图 7.5：选择要反编译的程序集时 ILSpy 扩展的输出

1.  在 **EXPLORER** 中，展开 **ILSPY DECOMPILED MEMBERS**，选择程序集，关闭 **Output** 窗口，并注意打开的两个编辑窗口，它们显示使用 C# 代码的程序集属性和使用 IL 代码的外部 DLL 和程序集引用，如图 *7.6* 所示：![图形用户界面，文本，应用程序 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_07_06.png)

    图 7.6：展开 ILSPY DECOMPILED MEMBERS

1.  在右侧的 IL 代码中，注意对 `System.Runtime` 程序集的引用，包括版本号，如下所示：

    ```cs
    .module extern libSystem.Native
    .assembly extern System.Runtime
    {
      .publickeytoken = (
        b0 3f 5f 7f 11 d5 0a 3a
      )
      .ver 6:0:0:0
    } 
    ```

    `.module extern libSystem.Native` 表示此程序集像预期那样调用了 Linux 系统 API，这些代码与文件系统交互。如果我们反编译此程序集的 Windows 版本，它将使用 `.module extern kernel32.dll` 代替，这是一个 Win32 API。

1.  在 **EXPLORER** 中，在 **ILSPY DECOMPILED MEMBERS** 中，展开程序集，展开 **System.IO** 命名空间，选择 **Directory**，并注意打开的两个编辑窗口，它们显示使用 C# 代码的反编译 `Directory` 类在左侧，IL 代码在右侧，如图 *7.7* 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_07_07.png)

    图 7.7：C# 和 IL 代码中的反编译 Directory 类

1.  比较以下代码中 `GetParent` 方法的 C# 源代码：

    ```cs
    public static DirectoryInfo? GetParent(string path)
    {
      if (path == null)
      {
        throw new ArgumentNullException("path");
      }
      if (path.Length == 0)
      {
        throw new ArgumentException(SR.Argument_PathEmpty, "path");
      }
      string fullPath = Path.GetFullPath(path);
      string directoryName = Path.GetDirectoryName(fullPath);
      if (directoryName == null)
      {
        return null;
      }
      return new DirectoryInfo(directoryName);
    } 
    ```

1.  使用 `GetParent` 方法的等效 IL 源代码，如下所示：

    ```cs
    .method /* 06000067 */ public hidebysig static 
      class System.IO.DirectoryInfo GetParent (
        string path
      ) cil managed
    {
      .param [0]
        .custom instance void System.Runtime.CompilerServices
        .NullableAttribute::.ctor(uint8) = ( 
          01 00 02 00 00
        )
      // Method begins at RVA 0x62d4
      // Code size 64 (0x40)
      .maxstack 2
      .locals /* 1100000E */ (
        [0] string,
        [1] string
      )
      IL_0000: ldarg.0
      IL_0001: brtrue.s IL_000e
      IL_0003: ldstr "path" /* 700005CB */
      IL_0008: newobj instance void [System.Runtime]
        System.ArgumentNullException::.ctor(string) /* 0A000035 */
      IL_000d: throw
      IL_000e: ldarg.0
      IL_000f: callvirt instance int32 [System.Runtime]
        System.String::get_Length() /* 0A000022 */
      IL_0014: brtrue.s IL_0026
      IL_0016: call string System.SR::get_Argument_PathEmpty() /* 0600004C */
      IL_001b: ldstr "path" /* 700005CB */
      IL_0020: newobj instance void [System.Runtime]
        System.ArgumentException::.ctor(string, string) /* 0A000036 */
      IL_0025: throw IL_0026: ldarg.0
      IL_0027: call string [System.Runtime.Extensions]
        System.IO.Path::GetFullPath(string) /* 0A000037 */
      IL_002c: stloc.0 IL_002d: ldloc.0
      IL_002e: call string [System.Runtime.Extensions]
        System.IO.Path::GetDirectoryName(string) /* 0A000038 */
      IL_0033: stloc.1
      IL_0034: ldloc.1
      IL_0035: brtrue.s IL_0039 IL_0037: ldnull
      IL_0038: ret IL_0039: ldloc.1
      IL_003a: newobj instance void 
        System.IO.DirectoryInfo::.ctor(string) /* 06000097 */
      IL_003f: ret
    } // end of method Directory::GetParent 
    ```

    **最佳实践**：IL 代码编辑窗口在深入了解 C# 和 .NET 开发之前并不是特别有用，此时了解 C# 编译器如何将源代码转换为 IL 代码非常重要。更有用的编辑窗口包含由微软专家编写的等效 C# 源代码。通过观察专业人士如何实现类型，你可以学到很多好的做法。例如，`GetParent` 方法展示了如何检查参数是否为 `null` 及其他参数异常。

1.  关闭编辑窗口而不保存更改。

1.  在**资源管理器**中，在**ILSPY 反编译成员**中，右键单击程序集并选择**卸载程序集**。

## **不**，从技术上讲，你无法阻止反编译。

有时会有人问我是否有办法保护编译后的代码以防止反编译。简短的回答是**没有**，如果你仔细想想，就会明白为什么必须如此。你可以使用**Dotfuscator**等混淆工具使其变得更难，但最终你无法完全阻止反编译。

所有编译后的应用程序都包含针对运行平台的指令、操作系统和硬件。这些指令必须与原始源代码功能相同，只是对人类来说更难阅读。这些指令必须可读才能执行你的代码；因此，它们必须可读才能被反编译。如果你使用某种自定义技术保护代码免受反编译，那么你也会阻止代码运行！

虚拟机模拟硬件，因此可以捕获运行应用程序与它认为正在运行的软件和硬件之间的所有交互。

如果你能保护你的代码，那么你也会阻止使用调试器附加到它并逐步执行。如果编译后的应用程序有 `pdb` 文件，那么你可以附加一个调试器并逐行执行语句。即使没有 `pdb` 文件，你仍然可以附加一个调试器并大致了解代码的工作原理。

这对所有编程语言都是如此。不仅仅是 .NET 语言，如 C#、Visual Basic 和 F#，还有 C、C++、Delphi、汇编语言：所有这些都可以附加到调试器中，或者被反汇编或反编译。以下表格展示了一些专业人士使用的工具：

| 类型 | 产品 | 描述 |
| --- | --- | --- |
| 虚拟机 | VMware | 专业人士如恶意软件分析师总是在虚拟机中运行软件。 |
| 调试器 | SoftICE | 通常在虚拟机中运行于操作系统之下。 |
| 调试器 | WinDbg | 由于它比其他调试器更了解 Windows 数据结构，因此对于理解 Windows 内部机制非常有用。 |
| 反汇编器 | IDA Pro | 专业恶意软件分析师使用。 |
| 反编译器 | HexRays | 反编译 C 应用程序。IDA Pro 的插件。 |
| 反编译器 | DeDe | 反编译 Delphi 应用程序。 |
| 反编译器 | dotPeek | JetBrains 出品的 .NET 反编译器。 |

**最佳实践**：调试、反汇编和反编译他人软件很可能违反其许可协议，并且在许多司法管辖区是非法的。与其试图通过技术手段保护你的知识产权，法律有时是你唯一的救济途径。

# 为 NuGet 分发打包你的库

在我们学习如何创建和打包自己的库之前，我们将回顾一个项目如何使用现有包。

## 引用 NuGet 包

假设你想添加一个由第三方开发者创建的包，例如，`Newtonsoft.Json`，这是一个流行的用于处理 JavaScript 对象表示法（JSON）序列化格式的包：

1.  在`AssembliesAndNamespaces`项目中，添加对`Newtonsoft.Json`NuGet 包的引用，可以使用 Visual Studio 2022 的 GUI 或 Visual Studio Code 的`dotnet add package`命令。

1.  打开`AssembliesAndNamespaces.csproj`文件，并注意到已添加了一个包引用，如下面的标记所示：

    ```cs
    <ItemGroup>
      <PackageReference Include="newtonsoft.json" Version="13.0.1" />
    </ItemGroup> 
    ```

如果你有更新的`newtonsoft.json`包版本，那么自本章编写以来它已被更新。

### 修复依赖关系

为了始终恢复包并编写可靠的代码，重要的是你**修复依赖关系**。修复依赖关系意味着你正在使用为.NET 的特定版本发布的同一套包，例如，SQLite for .NET 6.0，如下面的标记中突出显示所示：

```cs
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
 **<PackageReference**
 **Include=****"Microsoft.EntityFrameworkCore.Sqlite"**
 **Version=****"6.0.0"** **/>**
  </ItemGroup>
</Project> 
```

为了修复依赖关系，每个包应该只有一个版本，没有额外的限定词。额外的限定词包括测试版（`beta1`）、发布候选版（`rc4`）和通配符（`*`）。

通配符允许自动引用和使用未来版本，因为它们始终代表最新发布。但通配符因此具有危险性，因为它们可能导致使用未来不兼容的包，从而破坏你的代码。

在编写书籍时，这可能值得冒险，因为每月都会发布新的预览版本，你不想不断更新包引用，正如我在 2021 年所做的，如下面的标记所示：

```cs
<PackageReference
  Include="Microsoft.EntityFrameworkCore.Sqlite" 
  Version="6.0.0-preview.*" /> 
```

如果你使用`dotnet add package`命令，或者 Visual Studio 的**管理 NuGet 包**，那么它将默认使用包的最新特定版本。但如果你从博客文章复制粘贴配置或手动添加引用，你可能会包含通配符限定词。

以下依赖关系是 NuGet 包引用的示例，它们*未*固定，因此除非你知道其含义，否则应避免使用：

```cs
<PackageReference Include="System.Net.Http" Version="4.1.0-*" />
<PackageReference Include="Newtonsoft.Json" Version="12.0.3-beta1" /> 
```

**最佳实践**：微软保证，如果你将依赖关系固定到.NET 的特定版本随附的内容，例如 6.0.0，那么这些包都将协同工作。几乎总是固定你的依赖关系。

## 为 NuGet 打包一个库

现在，让我们打包你之前创建的`SharedLibrary`项目：

1.  在`SharedLibrary`项目中，将`Class1.cs`文件重命名为`StringExtensions.cs`。

1.  修改其内容，以提供一些使用正则表达式验证各种文本值的有用扩展方法，如下列代码所示：

    ```cs
    using System.Text.RegularExpressions;
    namespace Packt.Shared
    {
      public static class StringExtensions
      {
        public static bool IsValidXmlTag(this string input)
        {
          return Regex.IsMatch(input,
            @"^<([a-z]+)([^<]+)*(?:>(.*)<\/\1>|\s+\/>)$");
        }
        public static bool IsValidPassword(this string input)
        {
          // minimum of eight valid characters
          return Regex.IsMatch(input, "^[a-zA-Z0-9_-]{8,}$");
        }
        public static bool IsValidHex(this string input)
        {
          // three or six valid hex number characters
          return Regex.IsMatch(input,
            "^#?([a-fA-F0-9]{3}|[a-fA-F0-9]{6})$");
        }
      }
    } 
    ```

    您将在*第八章*，*使用常见的.NET 类型*中学习如何编写正则表达式。

1.  在`SharedLibrary.csproj`中，修改其内容，如下列标记中突出显示所示，并注意以下事项：

    +   `PackageId`必须全局唯一，因此如果您希望将此 NuGet 包发布到[`www.nuget.org/`](https://www.nuget.org/)公共源供他人引用和下载，则必须使用不同的值。

    +   `PackageLicenseExpression`必须是从以下链接获取的值：[`spdx.org/licenses/`](https://spdx.org/licenses/)，或者您可以指定一个自定义许可证。

    +   其他元素不言自明：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <TargetFramework>netstandard2.0</TargetFramework>
     **<GeneratePackageOnBuild>****true****</GeneratePackageOnBuild>**
     **<PackageId>Packt.CSdotnet.SharedLibrary</PackageId>**
     **<PackageVersion>****6.0.0.0****</PackageVersion>**
     **<Title>C****# 10 and .NET 6 Shared Library</Title>**
     **<Authors>Mark J Price</Authors>**
     **<PackageLicenseExpression>**
     **MS-PL**
     **</PackageLicenseExpression>**
     **<PackageProjectUrl>**
     **https:****//github.com/markjprice/cs10dotnet6**
     **</PackageProjectUrl>**
     **<PackageIcon>packt-csdotnet-sharedlibrary.png</PackageIcon>**
     **<PackageRequireLicenseAcceptance>****true****</PackageRequireLicenseAcceptance>**
     **<PackageReleaseNotes>**
     **Example shared library packaged** **for** **NuGet.**
     **</PackageReleaseNotes>**
     **<Description>**
     **Three extension methods to validate a** **string****value****.**
     **</Description>**
     **<Copyright>**
     **Copyright ©** **2016-2021** **Packt Publishing Limited**
     **</Copyright>**
     **<PackageTags>****string** **extensions packt csharp dotnet</PackageTags>**
      </PropertyGroup>
     **<ItemGroup>**
     **<None Include=****"packt-csdotnet-sharedlibrary.png"****>**
     **<Pack>True</Pack>**
     **<PackagePath></PackagePath>**
     **</None>**
     **</ItemGroup>**
    </Project> 
    ```

    **最佳实践**：配置属性值如果是`true`或`false`值，则不能包含任何空格，因此`<PackageRequireLicenseAcceptance>`条目不能像前面标记中那样包含回车和缩进。

1.  从以下链接下载图标文件并保存到`SharedLibrary`文件夹：[`github.com/markjprice/cs10dotnet6/blob/main/vs4win/Chapter07/SharedLibrary/packt-csdotnet-sharedlibrary.png`](https://github.com/markjprice/cs10dotnet6/blob/main/vs4win/Chapter07/SharedLibrary/packt-csdotnet-sharedlibrary.png)。

1.  构建发布程序集：

    1.  在 Visual Studio 中，从工具栏选择**发布**，然后导航至**构建** | **构建 SharedLibrary**。

    1.  在 Visual Studio Code 中，在**终端**中输入`dotnet build -c Release`

1.  如果我们未在项目文件中将`<GeneratePackageOnBuild>`设置为`true`，则需要按照以下额外步骤手动创建 NuGet 包：

    1.  在 Visual Studio 中，导航至**构建** | **打包 SharedLibrary**。

    1.  在 Visual Studio Code 中，在**终端**中输入`dotnet pack -c Release`。

### 将包发布到公共 NuGet 源

如果您希望所有人都能下载并使用您的 NuGet 包，则必须将其上传到公共 NuGet 源，例如 Microsoft 的：

1.  打开您喜欢的浏览器并导航至以下链接：[`www.nuget.org/packages/manage/upload`](https://www.nuget.org/packages/manage/upload)。

1.  如果您希望上传 NuGet 包供其他开发者作为依赖包引用，则需要在[`www.nuget.org/`](https://www.nuget.org/)使用 Microsoft 账户登录。

1.  点击**浏览...**并选择由生成 NuGet 包创建的`.nupkg`文件。文件夹路径应为`Code\Chapter07\SharedLibrary\bin\Release`，文件名为`Packt.CSdotnet.SharedLibrary.6.0.0.nupkg`。

1.  确认您在`SharedLibrary.csproj`文件中输入的信息已正确填写，然后点击**提交**。

1.  稍等片刻，您将看到一条成功消息，显示您的包已上传，如*图 7.8*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_07_08.png)

*图 7.8*：NuGet 包上传消息

**最佳实践**：如果遇到错误，请检查项目文件中的错误，或阅读有关`PackageReference`格式的更多信息，网址为[`docs.microsoft.com/en-us/nuget/reference/msbuild-targets`](https://docs.microsoft.com/en-us/nuget/reference/msbuild-targets)。

### 将包发布到私有 NuGet 源

组织可以托管自己的私有 NuGet 源。这对许多开发团队来说是一种便捷的共享工作方式。你可以在以下链接了解更多信息：

[`docs.microsoft.com/en-us/nuget/hosting-packages/overview`](https://docs.microsoft.com/en-us/nuget/hosting-packages/overview)

## 使用工具探索 NuGet 包

一个名为**NuGet Package Explorer**的便捷工具，由 Uno Platform 创建，用于打开并查看 NuGet 包的更多详细信息。它不仅是一个网站，还可以作为跨平台应用安装。让我们看看它能做什么：

1.  打开你最喜欢的浏览器并导航至以下链接：[`nuget.info`](https://nuget.info)。

1.  在搜索框中输入`Packt.CSdotnet.SharedLibrary`。

1.  选择由**Mark J Price**发布的**v6.0.0**包，然后点击**打开**按钮。

1.  在**目录**部分，展开**lib**文件夹和**netstandard2.0**文件夹。

1.  选择**SharedLibrary.dll**，并注意详细信息，如*图 7.9*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_07_09.png)

    *图 7.9*：使用 Uno Platform 的 NuGet Package Explorer 探索我的包

1.  如果你想将来在本地使用此工具，请在你的浏览器中点击安装按钮。

1.  关闭浏览器。

并非所有浏览器都支持安装此类网络应用。我推荐使用 Chrome 进行测试和开发。

## 测试你的类库包

现在你将通过在`AssembliesAndNamespaces`项目中引用它来测试你上传的包：

1.  在`AssembliesAndNamespaces`项目中，添加对你（或我）的包的引用，如下所示高亮显示：

    ```cs
    <ItemGroup>
      <PackageReference Include="newtonsoft.json" Version="13.0.1" />
     **<PackageReference Include=****"packt.csdotnet.sharedlibrary"**
     **Version=****"6.0.0"** **/>**
    </ItemGroup> 
    ```

1.  构建控制台应用。

1.  在`Program.cs`中，导入`Packt.Shared`命名空间。

1.  在`Program.cs`中，提示用户输入一些`string`值，然后使用包中的扩展方法进行验证，如下所示：

    ```cs
    Write("Enter a color value in hex: "); 
    string? hex = ReadLine(); // or "00ffc8"
    WriteLine("Is {0} a valid color value? {1}",
      arg0: hex, arg1: hex.IsValidHex());
    Write("Enter a XML element: "); 
    string? xmlTag = ReadLine(); // or "<h1 class=\"<\" />"
    WriteLine("Is {0} a valid XML element? {1}", 
      arg0: xmlTag, arg1: xmlTag.IsValidXmlTag());
    Write("Enter a password: "); 
    string? password = ReadLine(); // or "secretsauce"
    WriteLine("Is {0} a valid password? {1}",
      arg0: password, arg1: password.IsValidPassword()); 
    ```

1.  运行代码，按提示输入一些值，并查看结果，如下所示：

    ```cs
    Enter a color value in hex: 00ffc8 
    Is 00ffc8 a valid color value? True
    Enter an XML element: <h1 class="<" />
    Is <h1 class="<" /> a valid XML element? False 
    Enter a password: secretsauce
    Is secretsauce a valid password? True 
    ```

# 从.NET Framework 迁移到现代.NET

如果你是现有的.NET Framework 开发者，那么你可能拥有一些你认为应该迁移到现代.NET 的应用程序。但你应该仔细考虑迁移是否是你的代码的正确选择，因为有时候，最好的选择是不迁移。

例如，您可能有一个复杂的网站项目，运行在 .NET Framework 4.8 上，但只有少数用户访问。如果它运行良好，并且能够在最少的硬件上处理访问者流量，那么可能花费数月时间将其移植到 .NET 6 可能是浪费时间。但如果该网站目前需要许多昂贵的 Windows 服务器，那么移植的成本最终可能会得到回报，如果您能迁移到更少、成本更低的 Linux 服务器。

## 您能移植吗？

现代 .NET 对 Windows、macOS 和 Linux 上的以下类型的应用程序有很好的支持，因此它们是很好的移植候选：

+   **ASP.NET Core MVC** 网站。

+   **ASP.NET Core Web API** 网络服务（REST/HTTP）。

+   **ASP.NET Core SignalR** 服务。

+   **控制台应用程序** 命令行界面。

现代 .NET 对 Windows 上的以下类型的应用程序有不错的支持，因此它们是潜在的移植候选：

+   **Windows Forms** 应用程序。

+   **Windows Presentation Foundation** (**WPF**) 应用程序。

现代 .NET 对跨平台桌面和移动设备上的以下类型的应用程序有良好的支持：

+   **Xamarin** 移动 iOS 和 Android 应用。

+   **.NET MAUI** 用于桌面 Windows 和 macOS，或移动 iOS 和 Android。

现代 .NET 不支持以下类型的遗留 Microsoft 项目：

+   **ASP.NET Web Forms** 网站。这些可能最好使用 **ASP.NET Core Razor Pages** 或 **Blazor** 重新实现。

+   **Windows Communication Foundation** (**WCF**) 服务（但有一个名为 **CoreWCF** 的开源项目，您可能可以根据需求使用）。WCF 服务可能最好使用 **ASP.NET Core gRPC** 服务重新实现。

+   **Silverlight** 应用程序。这些可能最好使用 **.NET MAUI** 重新实现。

Silverlight 和 ASP.NET Web Forms 应用程序将永远无法移植到现代 .NET，但现有的 Windows Forms 和 WPF 应用程序可以移植到 Windows 上的 .NET，以便利用新的 API 和更快的性能。

遗留的 ASP.NET MVC 网络应用程序和当前在 .NET Framework 上的 ASP.NET Web API 网络服务可以移植到现代 .NET，然后托管在 Windows、Linux 或 macOS 上。

## 您应该移植吗？

即使您 *能* 移植，您 *应该* 移植吗？您能获得什么好处？一些常见的好处包括以下几点：

+   **部署到 Linux、Docker 或 Kubernetes 的网站和网络服务**：这些操作系统作为网站和网络服务平台轻量且成本效益高，尤其是与更昂贵的 Windows Server 相比。

+   **移除对 IIS 和 System.Web.dll 的依赖**：即使您继续部署到 Windows Server，ASP.NET Core 也可以托管在轻量级、高性能的 Kestrel（或其他）Web 服务器上。

+   **命令行工具**：开发人员和管理员用于自动化任务的工具通常构建为控制台应用程序。能够在跨平台上运行单个工具非常有用。

## .NET Framework 与现代 .NET 之间的差异

有三个关键差异，如下表所示：

| 现代 .NET | .NET Framework |
| --- | --- |
| 作为 NuGet 包分发，因此每个应用程序都可以部署其所需的 .NET 版本的本地副本。 | 作为系统范围的共享程序集集（实际上，在全局程序集缓存 (GAC) 中）分发。 |
| 拆分为小的、分层的组件，以便可以执行最小部署。 | 单一的、整体的部署。 |
| 移除旧技术，如 ASP.NET Web Forms，以及非跨平台特性，如 AppDomains、.NET Remoting 和二进制序列化。 | 以及一些与现代 .NET 中类似的技术，如 ASP.NET Core MVC，它还保留了一些旧技术，如 ASP.NET Web Forms。 |

## 理解 .NET Portability Analyzer

Microsoft 有一个有用的工具，你可以针对现有应用程序运行它来生成移植报告。你可以在以下链接观看该工具的演示：[`channel9.msdn.com/Blogs/Seth-Juarez/A-Brief-Look-at-the-NET-Portability-Analyzer`](https://channel9.msdn.com/Blogs/Seth-Juarez/A-Brief-Look-at-the-NET-Portability-Analyzer)。

## 理解 .NET Upgrade Assistant

Microsoft 最新推出的用于将遗留项目升级到现代 .NET 的工具是 .NET Upgrade Assistant。

在我的日常工作中，我为一家名为 Optimizely 的公司工作。我们有一个基于 .NET Framework 的企业级数字体验平台 (DXP)，包括内容管理系统 (CMS) 和构建数字商务网站。Microsoft 需要一个具有挑战性的迁移项目来设计和测试 .NET Upgrade Assistant，因此我们与他们合作构建了一个出色的工具。

目前，它支持以下 .NET Framework 项目类型，未来还将添加更多：

+   ASP.NET MVC

+   Windows Forms

+   WPF

+   Console Application

+   Class Library

它作为全局 `dotnet` 工具安装，如下面的命令所示：

```cs
dotnet tool install -g upgrade-assistant 
```

你可以在以下链接中了解更多关于此工具及其使用方法的信息：

[`docs.microsoft.com/en-us/dotnet/core/porting/upgrade-assistant-overview`](https://docs.microsoft.com/en-us/dotnet/core/porting/upgrade-assistant-overview)

## 使用非 .NET Standard 库

大多数现有的 NuGet 包都可以与现代 .NET 配合使用，即使它们不是为 .NET Standard 或类似 .NET 6 这样的现代版本编译的。如果你发现一个包在其 [nuget.org](https://www.nuget.org/) 网页上并未正式支持 .NET Standard，你不必放弃。你应该尝试一下，看看它是否能正常工作。

例如，Dialect Software LLC 创建了一个处理矩阵的自定义集合包，其文档链接如下：

[`www.nuget.org/packages/DialectSoftware.Collections.Matrix/`](https://www.nuget.org/packages/DialectSoftware.Collections.Matrix/)

这个包最后一次更新是在 2013 年，远在.NET Core 或.NET 6 出现之前，所以这个包是为.NET Framework 构建的。只要像这样的程序集包仅使用.NET Standard 中可用的 API，它就可以用于现代.NET 项目。

我们来尝试使用它，看看是否有效：

1.  在`AssembliesAndNamespaces`项目中，添加对 Dialect Software 包的包引用，如下所示：

    ```cs
    <PackageReference
      Include="dialectsoftware.collections.matrix"
      Version="1.0.0" /> 
    ```

1.  构建`AssembliesAndNamespaces`项目以恢复包。

1.  在`Program.cs`中，添加语句以导入`DialectSoftware.Collections`和`DialectSoftware.Collections.Generics`命名空间。

1.  添加语句以创建`Axis`和`Matrix<T>`的实例，填充它们并输出它们，如下所示：

    ```cs
    Axis x = new("x", 0, 10, 1);
    Axis y = new("y", 0, 4, 1);
    Matrix<long> matrix = new(new[] { x, y });
    for (int i = 0; i < matrix.Axes[0].Points.Length; i++)
    {
      matrix.Axes[0].Points[i].Label = "x" + i.ToString();
    }
    for (int i = 0; i < matrix.Axes[1].Points.Length; i++)
    {
      matrix.Axes[1].Points[i].Label = "y" + i.ToString();
    }
    foreach (long[] c in matrix)
    {
      matrix[c] = c[0] + c[1];
    }
    foreach (long[] c in matrix)
    {
      WriteLine("{0},{1} ({2},{3}) = {4}",
        matrix.Axes[0].Points[c[0]].Label,
        matrix.Axes[1].Points[c[1]].Label,
        c[0], c[1], matrix[c]);
    } 
    ```

1.  运行代码，注意警告信息和结果，如下所示：

    ```cs
    warning NU1701: Package 'DialectSoftware.Collections.Matrix
    1.0.0' was restored using '.NETFramework,Version=v4.6.1,
    .NETFramework,Version=v4.6.2, .NETFramework,Version=v4.7,
    .NETFramework,Version=v4.7.1, .NETFramework,Version=v4.7.2,
    .NETFramework,Version=v4.8' instead of the project target framework 'net6.0'. This package may not be fully compatible with your project.
    x0,y0 (0,0) = 0
    x0,y1 (0,1) = 1
    x0,y2 (0,2) = 2
    x0,y3 (0,3) = 3
    ... 
    ```

尽管这个包是在.NET 6 出现之前创建的，编译器和运行时无法知道它是否会工作，因此显示警告，但由于它恰好只调用与.NET Standard 兼容的 API，它能够工作。

# 使用预览功能

对于微软来说，提供一些具有跨领域影响的全新功能是一项挑战，这些功能涉及.NET 的许多部分，如运行时、语言编译器和 API 库。这是一个经典的先有鸡还是先有蛋的问题。你首先应该做什么？

从实际角度来看，这意味着尽管微软可能已经完成了大部分所需工作，但整个功能可能要到.NET 年度发布周期的后期才能准备就绪，那时已太晚，无法在“野外”进行适当的测试。

因此，从.NET 6 开始，微软将在**正式发布**（**GA**）版本中包含预览功能。开发者可以选择加入这些预览功能并向微软提供反馈。在后续的 GA 版本中，这些功能可以为所有人启用。

**最佳实践**：预览功能不支持在生产代码中使用。预览功能在最终发布前可能会发生重大变更。启用预览功能需自行承担风险。

## 需要预览功能

`[RequiresPreviewFeatures]`属性用于标识使用预览功能并因此需要关于预览功能的警告的程序集、类型或成员。代码分析器随后扫描此程序集，并在必要时生成警告。如果您的代码未使用任何预览功能，您将不会看到任何警告。如果您使用了任何预览功能，那么您的代码应该警告使用您代码的消费者，您使用了预览功能。

## 启用预览功能

让我们来看一个.NET 6 中可用的预览功能示例，即定义一个带有静态抽象方法的接口的能力：

1.  使用您偏好的代码编辑器，在`Chapter07`解决方案/工作区中添加一个名为`UsingPreviewFeatures`的新控制台应用程序。

1.  在 Visual Studio Code 中，选择`UsingPreviewFeatures`作为活动的 OmniSharp 项目。当看到弹出警告消息提示缺少必需资产时，点击**是**以添加它们。

1.  在项目文件中，添加一个元素以启用预览功能，并添加一个元素以启用预览语言功能，如以下标记中突出显示的那样：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <OutputType>Exe</OutputType>
        <TargetFramework>net6.0</TargetFramework>
        <Nullable>enable</Nullable>
        <ImplicitUsings>enable</ImplicitUsings>
     **<EnablePreviewFeatures>****true****</EnablePreviewFeatures>**
     **<LangVersion>preview</LangVersion>**
      </PropertyGroup>
    </Project> 
    ```

1.  在`Program.cs`中，删除注释并静态导入`Console`类。

1.  添加语句以定义具有静态抽象方法的接口、实现该接口的类，然后在顶层程序中调用该方法，如下面的代码所示：

    ```cs
    using static System.Console;
    Doer.DoSomething();
    public interface IWithStaticAbstract
    {
      static abstract void DoSomething();
    }
    public class Doer : IWithStaticAbstract
    {
      public static void DoSomething()
      {
        WriteLine("I am an implementation of a static abstract method.");
      }
    } 
    ```

1.  运行控制台应用并注意其输出是否正确。

## 泛型数学

为什么微软增加了定义静态抽象方法的能力？它们有何用途？

长期以来，开发者一直要求微软提供在泛型类型上使用*等运算符的能力。这将使开发者能够定义数学方法，对任何泛型类型执行加法、平均值等操作，而不必为所有想要支持的数值类型创建数十个重载方法。接口中对静态抽象方法的支持是一个基础特性，它将使泛型数学成为可能。

如果你对此感兴趣，可以在以下链接中阅读更多信息：

[`devblogs.microsoft.com/dotnet/preview-features-in-net-6-generic-math/`](https://devblogs.microsoft.com/dotnet/preview-features-in-net-6-generic-math/)

# 实践与探索

通过回答一些问题、获得一些实践经验以及深入研究本章主题，测试你的知识和理解。

## 练习 7.1 – 测试你的知识

回答以下问题：

1.  命名空间与程序集之间有何区别？

1.  如何在`.csproj`文件中引用另一个项目？

1.  像 ILSpy 这样的工具有什么好处？

1.  C#中的`float`别名代表哪种.NET 类型？

1.  在将应用程序从.NET Framework 迁移到.NET 6 之前，应该运行什么工具，以及可以使用什么工具来执行大部分迁移工作？

1.  .NET 应用程序的框架依赖部署和自包含部署之间有何区别？

1.  什么是 RID？

1.  `dotnet pack`和`dotnet publish`命令之间有何区别？

1.  哪些类型的.NET Framework 应用程序可以迁移到现代.NET？

1.  能否使用为.NET Framework 编写的包与现代.NET 兼容？

## 练习 7.2 – 探索主题

使用以下页面上的链接，深入了解本章涵盖的主题：

[`github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-7---understanding-and-packaging-net-types`](https://github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-7---understanding-and-packaging-net-types)

## 练习 7.3 – 探索 PowerShell

PowerShell 是微软为在每个操作系统上自动化任务而设计的脚本语言。微软推荐使用带有 PowerShell 扩展的 Visual Studio Code 来编写 PowerShell 脚本。

由于 PowerShell 是一种广泛的语言，本书中没有足够的篇幅来涵盖它。因此，我在书籍的 GitHub 仓库中创建了一些补充页面，向您介绍一些关键概念并展示一些示例：

[`github.com/markjprice/cs10dotnet6/tree/main/docs/powershell`](https://github.com/markjprice/cs10dotnet6/tree/main/docs/powershell)

# 总结

本章中，我们回顾了通往.NET 6 的旅程，探讨了程序集与命名空间之间的关系，了解了将应用程序发布到多个操作系统的选项，打包并分发了一个类库，并讨论了移植现有.NET Framework 代码库的选项。

在下一章中，您将学习到现代.NET 中包含的一些常见基类库类型。


# 第八章：使用常见的 .NET 类型

本章介绍了一些随 .NET 一起提供的常见类型。这些类型包括用于操作数字、文本、集合、网络访问、反射和属性的类型；改进与跨度、索引和范围的工作；处理图像；以及国际化。

本章涵盖以下主题：

+   处理数字

+   处理文本

+   处理日期和时间

+   使用正则表达式进行模式匹配

+   在集合中存储多个对象

+   处理跨度、索引和范围

+   处理网络资源

+   使用反射和属性

+   处理图像

+   国际化你的代码

# 处理数字

最常见的数据类型之一是数字。.NET 中处理数字的最常见类型如下表所示：

| 命名空间 | 示例类型 | 描述 |
| --- | --- | --- |
| `System` | `SByte`, `Int16`, `Int32`, `Int64` | 整数；即零和正负整数 |
| `System` | `Byte`, `UInt16`, `UInt32`, `UInt64` | 基数；即零和正整数 |
| `System` | `Half`, `Single`, `Double` | 实数；即浮点数 |
| `System` | `Decimal` | 精确实数；即用于科学、工程或金融场景 |
| `System.Numerics` | `BigInteger`, `Complex`, `Quaternion` | 任意大整数、复数和四元数 |

.NET 自 .NET Framework 1.0 起就拥有 32 位浮点数和 64 位双精度类型。IEEE 754 标准还定义了一个 16 位浮点标准。机器学习和其他算法将从这种更小、精度更低的数字类型中受益，因此微软在 .NET 5 及更高版本中引入了 `System.Half` 类型。

目前，C# 语言未定义 `half` 别名，因此必须使用 .NET 类型 `System.Half`。未来可能会发生变化。

## 处理大整数

.NET 类型中能用 C# 别名表示的最大整数大约是十八万五千亿，存储在无符号 `long` 整数中。但如果需要存储更大的数字呢？

让我们探索数字：

1.  使用您喜欢的代码编辑器创建一个名为 `Chapter08` 的新解决方案/工作区。

1.  添加一个控制台应用程序项目，如下表所示：

    1.  项目模板：**控制台应用程序** / `console`

    1.  工作区/解决方案文件和文件夹：`Chapter08`

    1.  项目文件和文件夹：`WorkingWithNumbers`

1.  在`Program.cs`中，删除现有语句并添加一条语句以导入`System.Numerics`，如下所示：

    ```cs
    using System.Numerics; 
    ```

1.  添加语句以输出 `ulong` 类型的最大值，以及使用 `BigInteger` 表示的具有 30 位数字的数，如下所示：

    ```cs
    WriteLine("Working with large integers:");
    WriteLine("-----------------------------------");
    ulong big = ulong.MaxValue;
    WriteLine($"{big,40:N0}");
    BigInteger bigger =
      BigInteger.Parse("123456789012345678901234567890");
    WriteLine($"{bigger,40:N0}"); 
    ```

    格式代码中的 `40` 表示右对齐 40 个字符，因此两个数字都排列在右侧边缘。`N0` 表示使用千位分隔符且小数点后为零。

1.  运行代码并查看结果，如下所示：

    ```cs
    Working with large integers:
    ----------------------------------------
                  18,446,744,073,709,551,615
     123,456,789,012,345,678,901,234,567,890 
    ```

## 处理复数

复数可以表示为*a + bi*，其中*a*和*b*是实数，*i*是虚数单位，其中*i*² *= −1*。如果实部*a*为零，则它是纯虚数。如果虚部*b*为零，则它是实数。

复数在许多**STEM**（**科学、技术、工程和数学**）研究领域具有实际应用。此外，它们是通过分别添加被加数的实部和虚部来相加的；考虑这一点：

```cs
(a + bi) + (c + di) = (a + c) + (b + d)i 
```

让我们探索复数：

1.  在`Program.cs`中，添加语句以添加两个复数，如下列代码所示：

    ```cs
    WriteLine("Working with complex numbers:");
    Complex c1 = new(real: 4, imaginary: 2);
    Complex c2 = new(real: 3, imaginary: 7);
    Complex c3 = c1 + c2;
    // output using default ToString implementation
    WriteLine($"{c1} added to {c2} is {c3}");
    // output using custom format
    WriteLine("{0} + {1}i added to {2} + {3}i is {4} + {5}i",
      c1.Real, c1.Imaginary, 
      c2.Real, c2.Imaginary,
      c3.Real, c3.Imaginary); 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    Working with complex numbers:
    (4, 2) added to (3, 7) is (7, 9)
    4 + 2i added to 3 + 7i is 7 + 9i 
    ```

## 理解四元数

四元数是一种扩展复数系统的数字系统。它们构成了一个四维的关联范数除法代数，覆盖实数，因此也是一个域。

嗯？是的，我知道。我也不明白。别担心，我们不会用它们来编写任何代码！可以说，它们擅长描述空间旋转，因此视频游戏引擎使用它们，许多计算机模拟和飞行控制系统也是如此。

# 处理文本

变量的另一种最常见类型是文本。.NET 中最常见的处理文本的类型如下表所示：

| 命名空间 | 类型 | 描述 |
| --- | --- | --- |
| `System` | `Char` | 存储单个文本字符 |
| `System` | `String` | 存储多个文本字符 |
| `System.Text` | `StringBuilder` | 高效地操作字符串 |
| `System.Text.RegularExpressions` | `Regex` | 高效地匹配字符串模式 |

## 获取字符串长度

让我们探讨一下处理文本时的一些常见任务；例如，有时您需要找出存储在`string`变量中的文本片段的长度：

1.  使用您偏好的代码编辑器，在`Chapter08`解决方案/工作区中添加一个名为`WorkingWithText`的新控制台应用：

    1.  在 Visual Studio 中，将解决方案的启动项目设置为当前选择。

    1.  在 Visual Studio Code 中，选择`WorkingWithText`作为活动的 OmniSharp 项目。

1.  在`WorkingWithText`项目中，在`Program.cs`文件里，添加语句定义一个变量来存储城市伦敦的名称，然后将其名称和长度写入控制台，如下列代码所示：

    ```cs
    string city = "London";
    WriteLine($"{city} is {city.Length} characters long."); 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    London is 6 characters long. 
    ```

## 获取字符串的字符

`string`类内部使用`char`数组来存储文本。它还有一个索引器，这意味着我们可以使用数组语法来读取其字符。数组索引从零开始，因此第三个字符将在索引 2 处。

让我们看看这如何实际操作：

1.  添加一条语句，以写出`string`变量中第一和第三位置的字符，如下列代码所示：

    ```cs
    WriteLine($"First char is {city[0]} and third is {city[2]}."); 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    First char is L and third is n. 
    ```

## 分割字符串

有时，您需要根据某个字符（如逗号）分割文本：

1.  添加语句以定义一个包含逗号分隔的城市名称的单个`字符串`变量，然后使用`Split`方法并指定你希望将逗号作为分隔符，接着枚举返回的`字符串`值数组，如下所示：

    ```cs
    string cities = "Paris,Tehran,Chennai,Sydney,New York,Medellín"; 
    string[] citiesArray = cities.Split(',');
    WriteLine($"There are {citiesArray.Length} items in the array.");
    foreach (string item in citiesArray)
    {
      WriteLine(item);
    } 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    There are 6 items in the array.
    Paris 
    Tehran 
    Chennai
    Sydney
    New York
    Medellín 
    ```

本章稍后，你将学习如何处理更复杂的场景。

## 获取字符串的一部分

有时，你需要获取文本的一部分。`IndexOf`方法有九个重载，它们返回指定`字符`或`字符串`在`字符串`中的索引位置。`Substring`方法有两个重载，如下所示：

+   `Substring(startIndex, length)`：返回从`startIndex`开始并包含接下来`length`个字符的子字符串。

+   `Substring(startIndex)`：返回从`startIndex`开始并包含所有字符直到字符串末尾的子字符串。

让我们来看一个简单的例子：

1.  添加语句以在`字符串`变量中存储一个人的全名，其中名字和姓氏之间有一个空格字符，找到空格的位置，然后提取名字和姓氏作为两个部分，以便它们可以以不同的顺序重新组合，如下所示：

    ```cs
    string fullName = "Alan Jones";
    int indexOfTheSpace = fullName.IndexOf(' ');
    string firstName = fullName.Substring(
      startIndex: 0, length: indexOfTheSpace);
    string lastName = fullName.Substring(
      startIndex: indexOfTheSpace + 1);
    WriteLine($"Original: {fullName}");
    WriteLine($"Swapped: {lastName}, {firstName}"); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Original: Alan Jones
    Swapped: Jones, Alan 
    ```

如果初始全名的格式不同，例如`"姓氏, 名字"`，那么代码将需要有所不同。作为可选练习，尝试编写一些语句，将输入`"Jones, Alan"`转换为`"Alan Jones"`。

## 检查字符串内容

有时，你需要检查一段文本是否以某些字符开始或结束，或者是否包含某些字符。你可以使用名为`StartsWith`、`EndsWith`和`Contains`的方法来实现这一点：

1.  添加语句以存储一个`字符串`值，然后检查它是否以或包含几个不同的`字符串`值，如下所示：

    ```cs
    string company = "Microsoft";
    bool startsWithM = company.StartsWith("M"); 
    bool containsN = company.Contains("N");
    WriteLine($"Text: {company}");
    WriteLine($"Starts with M: {startsWithM}, contains an N: {containsN}"); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Text: Microsoft
    Starts with M: True, contains an N: False 
    ```

## 连接、格式化及其他字符串成员

还有许多其他的`字符串`成员，如下表所示：

| 成员 | 描述 |
| --- | --- |
| `修剪`，`TrimStart`，`TrimEnd` | 这些方法从开头和/或结尾修剪空格、制表符和回车等空白字符。 |
| `ToUpper`，`ToLower` | 这些方法将所有字符转换为大写或小写。 |
| `插入`，`移除` | 这些方法用于插入或移除某些文本。 |
| `替换` | 这会将某些文本替换为其他文本。 |
| `string.Empty` | 这可以用来代替每次使用空的双引号(`""`)字面量`字符串`值时分配内存。 |
| `string.Concat` | 这会将两个`字符串`变量连接起来。当在`字符串`操作数之间使用时，+ 运算符执行等效操作。 |
| `string.Join` | 这会将一个或多个`字符串`变量与每个变量之间的字符连接起来。 |
| `string.IsNullOrEmpty` | 这检查`字符串`变量是否为`null`或空。 |
| `string.IsNullOrWhitespace` | 这检查`字符串`变量是否为`null`或空白；即，任意数量的水平和垂直空白字符的混合，例如，制表符、空格、回车、换行等。 |
| `string.Format` | 输出格式化`字符串`值的另一种方法，使用定位参数而不是命名参数。 |

前面提到的一些方法是静态方法。这意味着该方法只能从类型调用，而不能从变量实例调用。在前面的表格中，我通过在它们前面加上`string.`来指示静态方法，例如`string.Format`。

让我们探索一些这些方法：

1.  添加语句以使用`Join`方法将字符串值数组重新组合成带有分隔符的单个字符串变量，如下所示：

    ```cs
    string recombined = string.Join(" => ", citiesArray); 
    WriteLine(recombined); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Paris => Tehran => Chennai => Sydney => New York => Medellín 
    ```

1.  添加语句以使用定位参数和插值字符串格式化语法来输出相同的三个变量两次，如下所示：

    ```cs
    string fruit = "Apples"; 
    decimal price =  0.39M; 
    DateTime when = DateTime.Today;
    WriteLine($"Interpolated:  {fruit} cost {price:C} on {when:dddd}."); 
    WriteLine(string.Format("string.Format: {0} cost {1:C} on {2:dddd}.",
      arg0: fruit, arg1: price, arg2: when)); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Interpolated:  Apples cost £0.39 on Thursday. 
    string.Format: Apples cost £0.39 on Thursday. 
    ```

请注意，我们可以简化第二条语句，因为`WriteLine`支持与`string.Format`相同的格式代码，如下所示：

```cs
WriteLine("WriteLine: {0} cost {1:C} on {2:dddd}.",
  arg0: fruit, arg1: price, arg2: when); 
```

## 高效构建字符串

您可以使用`String.Concat`方法或简单的`+`运算符将两个字符串连接起来以创建新的`字符串`。但这两种选择都是不良实践，因为.NET 必须在内存中创建一个全新的`字符串`。

如果您只是添加两个`字符串`值，这可能不明显，但如果您在循环中进行连接，并且迭代次数很多，它可能会对性能和内存使用产生显著的负面影响。在*第十二章*，*使用多任务提高性能和可扩展性*中，您将学习如何使用`StringBuilder`类型高效地连接`字符串`变量。

# 处理日期和时间

在数字和文本之后，接下来最常处理的数据类型是日期和时间。这两种主要类型如下：

+   `DateTime`：表示一个固定时间点的日期和时间值。

+   `TimeSpan`：表示一段时间。

这两种类型通常一起使用。例如，如果您从一个`DateTime`值中减去另一个，结果是一个`TimeSpan`。如果您将一个`TimeSpan`添加到`DateTime`，则结果是一个`DateTime`值。

## 指定日期和时间值

创建日期和时间值的常见方法是分别为日期和时间组件（如日和小时）指定单独的值，如下表所述：

| 日期/时间参数 | 值范围 |
| --- | --- |
| `年` | 1 到 9999 |
| `月` | 1 到 12 |
| `日` | 1 到该月的天数 |
| `小时` | 0 到 23 |
| `分钟` | 0 到 59 |
| `秒` | 0 到 59 |

另一种方法是提供一个`string`值进行解析，但这可能会根据线程的默认文化被误解。例如，在英国，日期指定为日/月/年，而在美国，日期指定为月/日/年。

让我们看看你可能想要如何处理日期和时间：

1.  使用你偏好的代码编辑器，在`Chapter08`解决方案/工作区中添加一个名为`WorkingWithTime`的新控制台应用。

1.  在 Visual Studio Code 中，选择`WorkingWithTime`作为活动 OmniSharp 项目。

1.  在`Program.cs`中，删除现有语句，然后添加语句以初始化一些特殊的日期/时间值，如以下代码所示：

    ```cs
    WriteLine("Earliest date/time value is: {0}",
      arg0: DateTime.MinValue);
    WriteLine("UNIX epoch date/time value is: {0}",
      arg0: DateTime.UnixEpoch);
    WriteLine("Date/time value Now is: {0}",
      arg0: DateTime.Now);
    WriteLine("Date/time value Today is: {0}",
      arg0: DateTime.Today); 
    ```

1.  运行代码并记录结果，如以下输出所示：

    ```cs
    Earliest date/time value is: 01/01/0001 00:00:00
    UNIX epoch date/time value is: 01/01/1970 00:00:00
    Date/time value Now is: 23/04/2021 14:14:54
    Date/time value Today is: 23/04/2021 00:00:00 
    ```

1.  添加语句以定义 2021 年的圣诞节（如果这已过去，则使用未来的一年），并以多种方式展示，如以下代码所示：

    ```cs
    DateTime christmas = new(year: 2021, month: 12, day: 25);
    WriteLine("Christmas: {0}",
      arg0: christmas); // default format
    WriteLine("Christmas: {0:dddd, dd MMMM yyyy}",
      arg0: christmas); // custom format
    WriteLine("Christmas is in month {0} of the year.",
      arg0: christmas.Month);
    WriteLine("Christmas is day {0} of the year.",
      arg0: christmas.DayOfYear);
    WriteLine("Christmas {0} is on a {1}.",
      arg0: christmas.Year,
      arg1: christmas.DayOfWeek); 
    ```

1.  运行代码并记录结果，如以下输出所示：

    ```cs
    Christmas: 25/12/2021 00:00:00
    Christmas: Saturday, 25 December 2021
    Christmas is in month 12 of the year.
    Christmas is day 359 of the year.
    Christmas 2021 is on a Saturday. 
    ```

1.  添加语句以执行与圣诞节相关的加法和减法，如以下代码所示：

    ```cs
    DateTime beforeXmas = christmas.Subtract(TimeSpan.FromDays(12));
    DateTime afterXmas = christmas.AddDays(12);
    WriteLine("12 days before Christmas is: {0}",
      arg0: beforeXmas);
    WriteLine("12 days after Christmas is: {0}",
      arg0: afterXmas);
    TimeSpan untilChristmas = christmas - DateTime.Now;
    WriteLine("There are {0} days and {1} hours until Christmas.",
      arg0: untilChristmas.Days,
      arg1: untilChristmas.Hours);
    WriteLine("There are {0:N0} hours until Christmas.",
      arg0: untilChristmas.TotalHours); 
    ```

1.  运行代码并记录结果，如以下输出所示：

    ```cs
    12 days before Christmas is: 13/12/2021 00:00:00
    12 days after Christmas is: 06/01/2022 00:00:00
    There are 245 days and 9 hours until Christmas.
    There are 5,890 hours until Christmas. 
    ```

1.  添加语句以定义圣诞节那天你的孩子们可能醒来打开礼物的时刻，并以多种方式展示，如以下代码所示：

    ```cs
    DateTime kidsWakeUp = new(
      year: 2021, month: 12, day: 25, 
      hour: 6, minute: 30, second: 0);
    WriteLine("Kids wake up on Christmas: {0}",
      arg0: kidsWakeUp);
    WriteLine("The kids woke me up at {0}",
      arg0: kidsWakeUp.ToShortTimeString()); 
    ```

1.  运行代码并记录结果，如以下输出所示：

    ```cs
    Kids wake up on Christmas: 25/12/2021 06:30:00
    The kids woke me up at 06:30 
    ```

## 全球化与日期和时间

当前文化控制日期和时间的解析方式：

1.  在`Program.cs`顶部，导入`System.Globalization`命名空间。

1.  添加语句以显示用于显示日期和时间值的当前文化，然后解析美国独立日并以多种方式展示，如以下代码所示：

    ```cs
    WriteLine("Current culture is: {0}",
      arg0: CultureInfo.CurrentCulture.Name);
    string textDate = "4 July 2021";
    DateTime independenceDay = DateTime.Parse(textDate);
    WriteLine("Text: {0}, DateTime: {1:d MMMM}",
      arg0: textDate,
      arg1: independenceDay);
    textDate = "7/4/2021";
    independenceDay = DateTime.Parse(textDate);
    WriteLine("Text: {0}, DateTime: {1:d MMMM}",
      arg0: textDate,
      arg1: independenceDay);
    independenceDay = DateTime.Parse(textDate,
      provider: CultureInfo.GetCultureInfo("en-US"));
    WriteLine("Text: {0}, DateTime: {1:d MMMM}",
      arg0: textDate,
      arg1: independenceDay); 
    ```

1.  运行代码并记录结果，如以下输出所示：

    ```cs
    Current culture is: en-GB
    Text: 4 July 2021, DateTime: 4 July
    Text: 7/4/2021, DateTime: 7 April
    Text: 7/4/2021, DateTime: 4 July 
    ```

    在我的电脑上，当前文化是英式英语。如果给定日期为 2021 年 7 月 4 日，则无论当前文化是英式还是美式，都能正确解析。但如果日期给定为 7/4/2021，则会被错误解析为 4 月 7 日。你可以通过在解析时指定正确的文化作为提供者来覆盖当前文化，如上文第三个示例所示。

1.  添加语句以循环从 2020 年到 2025 年，显示该年是否为闰年以及二月有多少天，然后展示圣诞节和独立日是否在夏令时期间，如以下代码所示：

    ```cs
    for (int year = 2020; year < 2026; year++)
    {
      Write($"{year} is a leap year: {DateTime.IsLeapYear(year)}. ");
      WriteLine("There are {0} days in February {1}.",
        arg0: DateTime.DaysInMonth(year: year, month: 2), arg1: year);
    }
    WriteLine("Is Christmas daylight saving time? {0}",
      arg0: christmas.IsDaylightSavingTime());
    WriteLine("Is July 4th daylight saving time? {0}",
      arg0: independenceDay.IsDaylightSavingTime()); 
    ```

1.  运行代码并记录结果，如以下输出所示：

    ```cs
    2020 is a leap year: True. There are 29 days in February 2020.
    2021 is a leap year: False. There are 28 days in February 2021.
    2022 is a leap year: False. There are 28 days in February 2022.
    2023 is a leap year: False. There are 28 days in February 2023.
    2024 is a leap year: True. There are 29 days in February 2024.
    2025 is a leap year: False. There are 28 days in February 2025.
    Is Christmas daylight saving time? False
    Is July 4th daylight saving time? True 
    ```

## 仅处理日期或时间

.NET 6 引入了一些新类型，用于仅处理日期值或时间值，分别名为 `DateOnly` 和 `TimeOnly`。这些类型比使用时间部分为零的 `DateTime` 值来存储仅日期值更好，因为它们类型安全且避免了误用。`DateOnly` 也更适合映射到数据库列类型，例如 SQL Server 中的 `date` 列。`TimeOnly` 适合设置闹钟和安排定期会议或活动，并映射到 SQL Server 中的 `time` 列。

让我们用它们来为英国女王策划一场派对：

1.  添加语句以定义女王的生日及派对开始时间，然后将这两个值合并以创建日历条目，以免错过她的派对，如下列代码所示：

    ```cs
    DateOnly queensBirthday = new(year: 2022, month: 4, day: 21);
    WriteLine($"The Queen's next birthday is on {queensBirthday}.");
    TimeOnly partyStarts = new(hour: 20, minute: 30);
    WriteLine($"The Queen's party starts at {partyStarts}.");
    DateTime calendarEntry = queensBirthday.ToDateTime(partyStarts);
    WriteLine($"Add to your calendar: {calendarEntry}."); 
    ```

1.  运行代码并注意结果，如下列输出所示：

    ```cs
    The Queen's next birthday is on 21/04/2022.
    The Queen's party starts at 20:30.
    Add to your calendar: 21/04/2022 20:30:00. 
    ```

# 正则表达式模式匹配

正则表达式对于验证用户输入非常有用。它们功能强大且可能非常复杂。几乎所有编程语言都支持正则表达式，并使用一组通用的特殊字符来定义它们。

让我们尝试一些正则表达式的示例：

1.  使用您偏好的代码编辑器，在 `Chapter08` 解决方案/工作区中添加一个名为 `WorkingWithRegularExpressions` 的新控制台应用。

1.  在 Visual Studio Code 中，选择 `WorkingWithRegularExpressions` 作为活动 OmniSharp 项目。

1.  在 `Program.cs` 中，导入以下命名空间：

    ```cs
    using System.Text.RegularExpressions; 
    ```

## 检查作为文本输入的数字

我们将从实现验证数字输入的常见示例开始：

1.  添加语句提示用户输入年龄，然后使用正则表达式检查其有效性，该正则表达式查找数字字符，如下列代码所示：

    ```cs
    Write("Enter your age: "); 
    string? input = ReadLine();
    Regex ageChecker = new(@"\d"); 
    if (ageChecker.IsMatch(input))
    {
      WriteLine("Thank you!");
    }
    else
    {
      WriteLine($"This is not a valid age: {input}");
    } 
    ```

    注意以下关于代码的内容：

    +   `@` 字符关闭了在字符串中使用转义字符的能力。转义字符以前缀反斜杠表示。例如，`\t` 表示制表符，`\n` 表示新行。在编写正则表达式时，我们需要禁用此功能。借用电视剧《白宫风云》中的一句话，“让反斜杠就是反斜杠。”

    +   一旦使用 `@` 禁用了转义字符，它们就可以被正则表达式解释。例如，`\d` 表示数字。在本主题后面，您将学习更多以反斜杠为前缀的正则表达式。

1.  运行代码，输入一个整数如 `34` 作为年龄，并查看结果，如下列输出所示：

    ```cs
    Enter your age: 34 
    Thank you! 
    ```

1.  再次运行代码，输入 `carrots`，并查看结果，如下列输出所示：

    ```cs
    Enter your age: carrots
    This is not a valid age: carrots 
    ```

1.  再次运行代码，输入 `bob30smith`，并查看结果，如下列输出所示：

    ```cs
    Enter your age: bob30smith 
    Thank you! 
    ```

    我们使用的正则表达式是 `\d`，表示*一个数字*。然而，它并未指定在该数字之前和之后可以输入什么。这个正则表达式可以用英语描述为“输入任何你想要的字符，只要你至少输入一个数字字符。”

    在正则表达式中，您使用插入符号`^`符号表示某些输入的开始，使用美元`$`符号表示某些输入的结束。让我们使用这些符号来表示我们期望在输入的开始和结束之间除了数字外没有任何其他内容。

1.  将正则表达式更改为`^\d$`，如下面的代码中突出显示：

    ```cs
    Regex ageChecker = new(@"^**\d$"**); 
    ```

1.  再次运行代码并注意它拒绝除单个数字外的任何输入。我们希望允许一个或多个数字。为此，我们在`\d`表达式后添加一个`+`，以修改其含义为一个或多个。

1.  更改正则表达式，如下面的代码中突出显示：

    ```cs
    Regex ageChecker = new(@"^**\d+$"**); 
    ```

1.  再次运行代码并注意正则表达式仅允许长度为零或正整数的任何长度的数字。

## 正则表达式性能改进

.NET 中用于处理正则表达式的类型被广泛应用于.NET 平台及其构建的许多应用程序中。因此，它们对性能有重大影响，但直到现在，它们还没有得到微软太多的优化关注。

在.NET 5 及更高版本中，`System.Text.RegularExpressions`命名空间已重写内部以挤出最大性能。使用`IsMatch`等方法的常见正则表达式基准测试现在快了五倍。最好的事情是，您无需更改代码即可获得这些好处！

## 理解正则表达式的语法

以下是一些您可以在正则表达式中使用的常见正则表达式符号：

| 符号 | 含义 | 符号 | 含义 |
| --- | --- | --- | --- |
| `^` | 输入开始 | `$` | 输入结束 |
| `\d` | 单个数字 | `\D` | 单个非数字 |
| `\s` | 空白 | `\S` | 非空白 |
| `\w` | 单词字符 | `\W` | 非单词字符 |
| `[A-Za-z0-9]` | 字符范围 | `\^` | ^（插入符号）字符 |
| `[aeiou]` | 字符集 | `[^aeiou]` | 不在字符集中 |
| `.` | 任何单个字符 | `\.` | .（点）字符 |

此外，以下是一些影响正则表达式中前述符号的正则表达式量词：

| 符号 | 含义 | 符号 | 含义 |
| --- | --- | --- | --- |
| `+` | 一个或多个 | `?` | 一个或无 |
| `{3}` | 恰好三个 | `{3,5}` | 三个到五个 |
| `{3,}` | 至少三个 | `{,3}` | 最多三个 |

## 正则表达式示例

以下是一些带有其含义描述的正则表达式示例：

| 表达式 | 含义 |
| --- | --- |
| `\d` | 输入中某处的单个数字 |
| `a` | 输入中某处的字符*a* |
| `Bob` | 输入中某处的单词*Bob* |
| `^Bob` | 输入开头的单词*Bob* |
| `Bob$` | 输入末尾的单词*Bob* |
| `^\d{2}$` | 恰好两个数字 |
| `^[0-9]{2}$` | 恰好两个数字 |
| `^[A-Z]{4,}$` | ASCII 字符集中仅包含至少四个大写英文字母 |
| `^[A-Za-z]{4,}$` | ASCII 字符集中仅包含至少四个大写或小写英文字母 |
| `^[A-Z]{2}\d{3}$` | ASCII 字符集中仅包含两个大写英文字母和三个数字 |
| `^[A-Za-z\u00c0-\u017e]+$` | 至少一个 ASCII 字符集中的大写或小写英文字母，或 Unicode 字符集中的欧洲字母，如下表所示：ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿıŒœŠšŸ Žž |
| `^d.g$` | 字母*d*，然后是任何字符，然后是字母*g*，因此它会匹配*dig*和*dog*或*d*和*g*之间的任何单个字符 |
| `^d\.g$` | 字母*d*，然后是一个点（.），然后是字母*g*，因此它只会匹配*d.g* |

**良好实践**：使用正则表达式验证用户输入。相同的正则表达式可以在 JavaScript 和 Python 等其他语言中重复使用。

## 分割复杂的逗号分隔字符串

本章前面，你学习了如何分割一个简单的逗号分隔的字符串变量。但电影标题的以下示例呢？

```cs
"Monsters, Inc.","I, Tonya","Lock, Stock and Two Smoking Barrels" 
```

字符串值使用双引号围绕每个电影标题。我们可以利用这些来判断是否需要在逗号处分割（或不分割）。`Split`方法不够强大，因此我们可以使用正则表达式代替。

**良好实践**：你可以在 Stack Overflow 文章中找到更详细的解释，该文章启发了此任务，链接如下：[`stackoverflow.com/questions/18144431/regex-to-split-a-csv`](https://stackoverflow.com/questions/18144431/regex-to-split-a-csv)

要在`string`值中包含双引号，我们可以在它们前面加上反斜杠：

1.  添加语句以存储一个复杂的逗号分隔的`string`变量，然后使用`Split`方法以一种笨拙的方式分割它，如下面的代码所示：

    ```cs
    string films = "\"Monsters, Inc.\",\"I, Tonya\",\"Lock, Stock and Two Smoking Barrels\"";
    WriteLine($"Films to split: {films}");
    string[] filmsDumb = films.Split(',');
    WriteLine("Splitting with string.Split method:"); 
    foreach (string film in filmsDumb)
    {
      WriteLine(film);
    } 
    ```

1.  添加语句以定义一个正则表达式，用于智能地分割并写出电影标题，如下面的代码所示：

    ```cs
    WriteLine();
    Regex csv = new(
      "(?:^|,)(?=[^\"]|(\")?)\"?((?(1)[^\"]*|[^,\"]*))\"?(?=,|$)");
    MatchCollection filmsSmart = csv.Matches(films);
    WriteLine("Splitting with regular expression:"); 
    foreach (Match film in filmsSmart)
    {
      WriteLine(film.Groups[2].Value);
    } 
    ```

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Splitting with string.Split method: 
    "Monsters
     Inc." 
    "I
     Tonya" 
    "Lock
     Stock and Two Smoking Barrels" 
    Splitting with regular expression: 
    Monsters, Inc.
    I, Tonya
    Lock, Stock and Two Smoking Barrels 
    ```

# 在集合中存储多个对象

另一种最常见的数据类型是集合。如果你需要在变量中存储多个值，那么你可以使用集合。

集合是一种内存中的数据结构，可以以不同方式管理多个项目，尽管所有集合都具有一些共享功能。

.NET 中用于处理集合的最常见类型如下表所示：

| 命名空间 | 示例类型 | 描述 |
| --- | --- | --- |
| `System .Collections` | `IEnumerable`, `IEnumerable<T>` | 集合使用的接口和基类。 |
| `System .Collections .Generic` | `List<T>`, `Dictionary<T>`, `Queue<T>`, `Stack<T>` | 在 C# 2.0 和.NET Framework 2.0 中引入，这些集合允许你使用泛型类型参数指定要存储的类型（更安全、更快、更高效）。 |
| `System .Collections .Concurrent` | `BlockingCollection`, `ConcurrentDictionary`, `ConcurrentQueue` | 这些集合在多线程场景中使用是安全的。 |
| `System.Collections.Immutable` | `ImmutableArray`、`ImmutableDictionary`、`ImmutableList`、`ImmutableQueue` | 设计用于原始集合内容永远不会改变的场景，尽管它们可以创建作为新实例的修改后的集合。 |

## 所有集合的共同特点

所有集合都实现了`ICollection`接口；这意味着它们必须有一个`Count`属性来告诉你其中有多少对象，如下面的代码所示：

```cs
namespace System.Collections
{
  public interface ICollection : IEnumerable
  {
    int Count { get; }
    bool IsSynchronized { get; }
    object SyncRoot { get; }
    void CopyTo(Array array, int index);
  }
} 
```

例如，如果我们有一个名为`passengers`的集合，我们可以这样做：

```cs
int howMany = passengers.Count; 
```

所有集合都实现了`IEnumerable`接口，这意味着它们可以使用`foreach`语句进行迭代。它们必须有一个`GetEnumerator`方法，该方法返回一个实现了`IEnumerator`的对象；这意味着返回的`对象`必须具有`MoveNext`和`Reset`方法来遍历集合，以及一个包含集合中当前项的`Current`属性，如下面的代码所示：

```cs
namespace System.Collections
{
  public interface IEnumerable
  {
    IEnumerator GetEnumerator();
  }
}
namespace System.Collections
{
  public interface IEnumerator
  {
    object Current { get; }
    bool MoveNext();
    void Reset();
  }
} 
```

例如，要对`passengers`集合中的每个对象执行一个操作，我们可以编写以下代码：

```cs
foreach (Passenger p in passengers)
{
  // perform an action on each passenger
} 
```

除了基于`object`的集合接口外，还有泛型接口和类，其中泛型类型定义了集合中存储的类型，如下面的代码所示：

```cs
namespace System.Collections.Generic
{
  public interface ICollection<T> : IEnumerable<T>, IEnumerable
  {
    int Count { get; }
    bool IsReadOnly { get; }
    void Add(T item);
    void Clear();
    bool Contains(T item);
    void CopyTo(T[] array, int index);
    bool Remove(T item);
  }
} 
```

## 通过确保集合的容量来提高性能

自.NET 1.1 以来，像`StringBuilder`这样的类型就有一个名为`EnsureCapacity`的方法，可以预先设置其内部存储数组到预期的最终大小。这提高了性能，因为它不需要在添加更多字符时反复增加数组的大小。

自.NET Core 2.1 以来，像`Dictionary<T>`和`HashSet<T>`这样的类型也有了`EnsureCapacity`。

在.NET 6 及更高版本中，像`List<T>`、`Queue<T>`和`Stack<T>`这样的集合现在也有了一个`EnsureCapacity`方法，如下面的代码所示：

```cs
List<string> names = new();
names.EnsureCapacity(10_000);
// load ten thousand names into the list 
```

## 理解集合选择

有几种不同的集合选择，你可以根据不同的目的使用：列表、字典、栈、队列、集合，以及许多其他更专业的集合。

### 列表

列表，即实现`IList<T>`的类型，是**有序集合**，如下面的代码所示：

```cs
namespace System.Collections.Generic
{
  [DefaultMember("Item")] // aka this indexer
  public interface IList<T> : ICollection<T>, IEnumerable<T>, IEnumerable
  {
    T this[int index] { get; set; }
    int IndexOf(T item);
    void Insert(int index, T item);
    void RemoveAt(int index);
  }
} 
```

`IList<T>`继承自`ICollection<T>`，因此它具有一个`Count`属性，以及一个`Add`方法，用于在集合末尾添加一个项，以及一个`Insert`方法，用于在列表中指定位置插入一个项，以及`RemoveAt`方法，用于在指定位置删除一个项。

当你想要手动控制集合中项目的顺序时，列表是一个好的选择。列表中的每个项目都有一个自动分配的唯一索引（或位置）。项目可以是`T`定义的任何类型，并且项目可以重复。索引是`int`类型，从`0`开始，因此列表中的第一个项目位于索引`0`处，如下表所示：

| 索引 | 项 |
| --- | --- |
| 0 | 伦敦 |
| 1 | 巴黎 |
| 2 | 伦敦 |
| 3 | 悉尼 |

如果一个新项（例如，圣地亚哥）被插入到伦敦和悉尼之间，那么悉尼的索引会自动增加。因此，你必须意识到，在插入或删除项后，项的索引可能会改变，如下表所示：

| 索引 | 项 |
| --- | --- |
| 0 | 伦敦 |
| 1 | 巴黎 |
| 2 | 伦敦 |
| 3 | 圣地亚哥 |
| 4 | 悉尼 |

### 字典

当每个**值**（或对象）有一个唯一的子值（或自定义值）可以用作**键**，以便稍后在集合中快速找到一个值时，字典是一个好选择。键必须是唯一的。例如，如果你正在存储一个人员列表，你可以选择使用政府颁发的身份证号码作为键。

将键想象成现实世界词典中的索引条目。它允许你快速找到一个词的定义，因为词（例如，键）是按顺序排列的，如果我们知道要查找*海牛*的定义，我们会跳到词典中间开始查找，因为字母*M*位于字母表的中间。

编程中的字典在查找内容时同样智能。它们必须实现接口`IDictionary<TKey, TValue>`，如下面的代码所示：

```cs
namespace System.Collections.Generic
{
  [DefaultMember("Item")] // aka this indexer
  public interface IDictionary<TKey, TValue>
    : ICollection<KeyValuePair<TKey, TValue>>,
      IEnumerable<KeyValuePair<TKey, TValue>>, IEnumerable
  {
    TValue this[TKey key] { get; set; }
    ICollection<TKey> Keys { get; }
    ICollection<TValue> Values { get; }
    void Add(TKey key, TValue value);
    bool ContainsKey(TKey key);
    bool Remove(TKey key);
    bool TryGetValue(TKey key, [MaybeNullWhen(false)] out TValue value);
  }
} 
```

字典中的项是`struct`的实例，也就是值类型`KeyValuePair<TKey, TValue>`，其中`TKey`是键的类型，`TValue`是值的类型，如下面的代码所示：

```cs
namespace System.Collections.Generic
{
  public readonly struct KeyValuePair<TKey, TValue>
  {
    public KeyValuePair(TKey key, TValue value);
    public TKey Key { get; }
    public TValue Value { get; }
    [EditorBrowsable(EditorBrowsableState.Never)]
    public void Deconstruct(out TKey key, out TValue value);
    public override string ToString();
  }
} 
```

一个示例`Dictionary<string, Person>`使用`string`作为键，`Person`实例作为值。`Dictionary<string, string>`对两者都使用`string`值，如下表所示：

| 键 | 值 |
| --- | --- |
| BSA | 鲍勃·史密斯 |
| MW | 马克斯·威廉姆斯 |
| BSB | 鲍勃·史密斯 |
| AM | 阿米尔·穆罕默德 |

### 栈

当你想要实现**后进先出**（**LIFO**）行为时，栈是一个好选择。使用栈，你只能直接访问或移除栈顶的项，尽管你可以枚举来读取整个栈的项。例如，你不能直接访问栈中的第二个项。

例如，文字处理器使用栈来记住你最近执行的操作顺序，然后当你按下 Ctrl + Z 时，它会撤销栈中的最后一个操作，然后是倒数第二个操作，依此类推。

### 队列

当你想要实现**先进先出**（**FIFO**）行为时，队列是一个好选择。使用队列，你只能直接访问或移除队列前端的项，尽管你可以枚举来读取整个队列的项。例如，你不能直接访问队列中的第二个项。

例如，后台进程使用队列按到达顺序处理工作项，就像人们在邮局排队一样。

.NET 6 引入了`PriorityQueue`，其中队列中的每个项都有一个优先级值以及它们在队列中的位置。

### 集合

当你想要在两个集合之间执行集合操作时，集合是一个好的选择。例如，你可能有两个城市名称的集合，并且你想要知道哪些名称同时出现在两个集合中（这被称为集合之间的*交集*）。集合中的项必须是唯一的。

### 集合方法总结

每种集合都有一套不同的添加和移除项的方法，如下表所示：

| 集合 | 添加方法 | 移除方法 | 描述 |
| --- | --- | --- | --- |
| 列表 | `添加`，`插入` | `移除`，`移除位置` | 列表是有序的，因此项具有整数索引位置。`添加`将在列表末尾添加一个新项。`插入`将在指定的索引位置添加一个新项。 |
| 字典 | `添加` | `移除` | 字典是无序的，因此项没有整数索引位置。你可以通过调用`ContainsKey`方法来检查一个键是否已被使用。 |
| 栈 | `压栈` | `弹栈` | 栈总是使用`压栈`方法在栈顶添加一个新项。第一个项位于栈底。总是使用`弹栈`方法从栈顶移除项。调用`Peek`方法可以查看此值而不移除它。 |
| 队列 | `入队` | `出队` | 队列总是使用`入队`方法在队列末尾添加一个新项。第一个项位于队列前端。总是使用`出队`方法从队列前端移除项。调用`Peek`方法可以查看此值而不移除它。 |

## 使用列表

让我们探索列表：

1.  使用你偏好的代码编辑器，在`Chapter08`解决方案/工作区中添加一个名为`WorkingWithCollections`的新控制台应用。

1.  在 Visual Studio Code 中，选择`WorkingWithCollections`作为活动的 OmniSharp 项目。

1.  在`Program.cs`中，删除现有语句，然后定义一个函数，输出带有标题的`string`值集合，如下所示：

    ```cs
    static void Output(string title, IEnumerable<string> collection)
    {
      WriteLine(title);
      foreach (string item in collection)
      {
        WriteLine($"  {item}");
      }
    } 
    ```

1.  定义一个名为`WorkingWithLists`的静态方法，以展示一些定义和使用列表的常见方式，如下所示：

    ```cs
    static void WorkingWithLists()
    {
      // Simple syntax for creating a list and adding three items
      List<string> cities = new(); 
      cities.Add("London"); 
      cities.Add("Paris"); 
      cities.Add("Milan");
      /* Alternative syntax that is converted by the compiler into
         the three Add method calls above
      List<string> cities = new()
        { "London", "Paris", "Milan" };
      */
      /* Alternative syntax that passes an 
         array of string values to AddRange method
      List<string> cities = new(); 
      cities.AddRange(new[] { "London", "Paris", "Milan" });
      */
      Output("Initial list", cities);
      WriteLine($"The first city is {cities[0]}."); 
      WriteLine($"The last city is {cities[cities.Count - 1]}.");
      cities.Insert(0, "Sydney");
      Output("After inserting Sydney at index 0", cities); 
      cities.RemoveAt(1); 
      cities.Remove("Milan");
      Output("After removing two cities", cities);
    } 
    ```

1.  在`Program.cs`顶部，在命名空间导入之后，调用`WorkingWithLists`方法，如下所示：

    ```cs
    WorkingWithLists(); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Initial list
      London
      Paris
      Milan
    The first city is London. 
    The last city is Milan.
    After inserting Sydney at index 0
      Sydney
      London
      Paris
      Milan
    After removing two cities
      Sydney
      Paris 
    ```

## 使用字典

让我们探索字典：

1.  在`Program.cs`中，定义一个名为`WorkingWithDictionaries`的静态方法，以展示一些使用字典的常见方式，例如，查找单词定义，如下所示：

    ```cs
    static void WorkingWithDictionaries()
    {
      Dictionary<string, string> keywords = new();
      // add using named parameters
      keywords.Add(key: "int", value: "32-bit integer data type");
      // add using positional parameters
      keywords.Add("long", "64-bit integer data type"); 
      keywords.Add("float", "Single precision floating point number");
      /* Alternative syntax; compiler converts this to calls to Add method
      Dictionary<string, string> keywords = new()
      {
        { "int", "32-bit integer data type" },
        { "long", "64-bit integer data type" },
        { "float", "Single precision floating point number" },
      }; */
      /* Alternative syntax; compiler converts this to calls to Add method
      Dictionary<string, string> keywords = new()
      {
        ["int"] = "32-bit integer data type",
        ["long"] = "64-bit integer data type",
        ["float"] = "Single precision floating point number", // last comma is optional
      }; */
      Output("Dictionary keys:", keywords.Keys);
      Output("Dictionary values:", keywords.Values);
      WriteLine("Keywords and their definitions");
      foreach (KeyValuePair<string, string> item in keywords)
      {
        WriteLine($"  {item.Key}: {item.Value}");
      }
      // lookup a value using a key
      string key = "long";
      WriteLine($"The definition of {key} is {keywords[key]}");
    } 
    ```

1.  在`Program.cs`顶部，注释掉之前的方法调用，然后调用`WorkingWithDictionaries`方法，如下所示：

    ```cs
    // WorkingWithLists();
    WorkingWithDictionaries(); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Dictionary keys:
      int
      long
      float
    Dictionary values:
      32-bit integer data type
      64-bit integer data type
      Single precision floating point number
    Keywords and their definitions
      int: 32-bit integer data type
      long: 64-bit integer data type
      float: Single precision floating point number
    The definition of long is 64-bit integer data type 
    ```

## 使用队列

让我们探索队列：

1.  在`Program.cs`中，定义一个名为`WorkingWithQueues`的静态方法，以展示一些使用队列的常见方式，例如，处理排队购买咖啡的顾客，如下所示：

    ```cs
    static void WorkingWithQueues()
    {
      Queue<string> coffee = new();
      coffee.Enqueue("Damir"); // front of queue
      coffee.Enqueue("Andrea");
      coffee.Enqueue("Ronald");
      coffee.Enqueue("Amin");
      coffee.Enqueue("Irina"); // back of queue
      Output("Initial queue from front to back", coffee);
      // server handles next person in queue
      string served = coffee.Dequeue();
      WriteLine($"Served: {served}.");
      // server handles next person in queue
      served = coffee.Dequeue();
      WriteLine($"Served: {served}.");
      Output("Current queue from front to back", coffee);
      WriteLine($"{coffee.Peek()} is next in line.");
      Output("Current queue from front to back", coffee);
    } 
    ```

1.  在`Program.cs`顶部，注释掉之前的方法调用，并调用`WorkingWithQueues`方法。

1.  运行代码并查看结果，如下所示：

    ```cs
    Initial queue from front to back
      Damir
      Andrea
      Ronald
      Amin
      Irina
    Served: Damir.
    Served: Andrea.
    Current queue from front to back
      Ronald
      Amin
      Irina
    Ronald is next in line.
    Current queue from front to back
      Ronald
      Amin
      Irina 
    ```

1.  定义一个名为`OutputPQ`的静态方法，如下所示：

    ```cs
    static void OutputPQ<TElement, TPriority>(string title,
      IEnumerable<(TElement Element, TPriority Priority)> collection)
    {
      WriteLine(title);
      foreach ((TElement, TPriority) item in collection)
      {
        WriteLine($"  {item.Item1}: {item.Item2}");
      }
    } 
    ```

    请注意，`OutputPQ`方法是泛型的。你可以指定作为`collection`传递的元组中使用的两个类型。

1.  定义一个名为`WorkingWithPriorityQueues`的静态方法，如下所示：

    ```cs
    static void WorkingWithPriorityQueues()
    {
      PriorityQueue<string, int> vaccine = new();
      // add some people
      // 1 = high priority people in their 70s or poor health
      // 2 = medium priority e.g. middle aged
      // 3 = low priority e.g. teens and twenties
      vaccine.Enqueue("Pamela", 1);  // my mum (70s)
      vaccine.Enqueue("Rebecca", 3); // my niece (teens)
      vaccine.Enqueue("Juliet", 2);  // my sister (40s)
      vaccine.Enqueue("Ian", 1);     // my dad (70s)
      OutputPQ("Current queue for vaccination:", vaccine.UnorderedItems);
      WriteLine($"{vaccine.Dequeue()} has been vaccinated.");
      WriteLine($"{vaccine.Dequeue()} has been vaccinated.");
      OutputPQ("Current queue for vaccination:", vaccine.UnorderedItems);
      WriteLine($"{vaccine.Dequeue()} has been vaccinated.");
      vaccine.Enqueue("Mark", 2); // me (40s)
      WriteLine($"{vaccine.Peek()} will be next to be vaccinated.");
      OutputPQ("Current queue for vaccination:", vaccine.UnorderedItems);
    } 
    ```

1.  在`Program.cs`顶部，注释掉之前的方法调用，并调用`WorkingWithPriorityQueues`方法。

1.  运行代码并查看结果，如下所示：

    ```cs
    Current queue for vaccination:
      Pamela: 1
      Rebecca: 3
      Juliet: 2
      Ian: 1
    Pamela has been vaccinated.
    Ian has been vaccinated.
    Current queue for vaccination:
      Juliet: 2
      Rebecca: 3
    Juliet has been vaccinated.
    Mark will be next to be vaccinated.
    Current queue for vaccination:
      Mark: 2
      Rebecca: 3 
    ```

## 排序集合

`List<T>`类可以通过手动调用其`Sort`方法进行排序（但请记住，每个项的索引会改变）。手动对`string`值或其他内置类型的列表进行排序无需额外努力，但如果你创建了自己的类型的集合，则该类型必须实现名为`IComparable`的接口。你在《第六章：实现接口和继承类》中学过如何做到这一点。

`Stack<T>`或`Queue<T>`集合无法排序，因为你通常不需要这种功能；例如，你可能永远不会对入住酒店的客人队列进行排序。但有时，你可能想要对字典或集合进行排序。

有时拥有一个自动排序的集合会很有用，即在添加和删除项时保持项的排序顺序。

有多种自动排序集合可供选择。这些排序集合之间的差异通常很微妙，但可能会影响应用程序的内存需求和性能，因此值得努力选择最适合你需求的选项。

一些常见的自动排序集合如下表所示：

| 集合 | 描述 |
| --- | --- |
| `SortedDictionary<TKey, TValue>` | 这表示一个按键排序的键/值对集合。 |
| `SortedList<TKey, TValue>` | 这表示一个按键排序的键/值对集合。 |
| `SortedSet<T>` | 这表示一个唯一的对象集合，这些对象按排序顺序维护。 |

## 更专业的集合

还有其他一些用于特殊情况的集合。

### 使用紧凑的位值数组

`System.Collections.BitArray`集合管理一个紧凑的位值数组，这些位值表示为布尔值，其中`true`表示位已打开（值为 1），`false`表示位已关闭（值为 0）。

### 高效地使用列表

`System.Collections.Generics.LinkedList<T>`集合表示一个双向链表，其中每个项都有对其前一个和下一个项的引用。与`List<T>`相比，在频繁从列表中间插入和删除项的场景中，它们提供了更好的性能。在`LinkedList<T>`中，项无需在内存中重新排列。

## 使用不可变集合

有时你需要使集合不可变，这意味着其成员不可更改；即，你不能添加或删除它们。

如果你导入了`System.Collections.Immutable`命名空间，那么任何实现`IEnumerable<T>`的集合都会获得六个扩展方法，用于将其转换为不可变列表、字典、哈希集等。

让我们看一个简单的例子：

1.  在`WorkingWithCollections`项目中，在`Program.cs`中，导入`System.Collections.Immutable`命名空间。

1.  在`WorkingWithLists`方法中，在方法末尾添加语句，将`cities`列表转换为不可变列表，然后向其添加一个新城市，如下代码所示：

    ```cs
    ImmutableList<string> immutableCities = cities.ToImmutableList();
    ImmutableList<string> newList = immutableCities.Add("Rio");
    Output("Immutable list of cities:", immutableCities); 
    Output("New list of cities:", newList); 
    ```

1.  在`Program.cs`顶部，注释掉之前的方法调用，并取消对`WorkingWithLists`方法调用的注释。

1.  运行代码，查看结果，并注意当对不可变城市列表调用`Add`方法时，该列表并未被修改；相反，它返回了一个包含新添加城市的新列表，如下输出所示：

    ```cs
    Immutable list of cities:
      Sydney
      Paris
    New list of cities:
      Sydney
      Paris
      Rio 
    ```

**良好实践**：为了提高性能，许多应用程序在中央缓存中存储了常用对象的共享副本。为了安全地允许多个线程使用这些对象，同时确保它们不会被更改，你应该使它们不可变，或者使用并发集合类型，你可以在以下链接中了解相关信息：[`docs.microsoft.com/en-us/dotnet/api/system.collections.concurrent`](https://docs.microsoft.com/en-us/dotnet/api/system.collections.concurrent)

## 集合的良好实践

假设你需要创建一个处理集合的方法。为了最大程度地灵活，你可以声明输入参数为`IEnumerable<T>`，并使方法泛型化，如下代码所示：

```cs
void ProcessCollection<T>(IEnumerable<T> collection)
{
  // process the items in the collection,
  // perhaps using a foreach statement
} 
```

我可以将数组、列表、队列、栈或任何其他实现`IEnumerable<T>`的集合传递给此方法，它将处理这些项。然而，将任何集合传递给此方法的灵活性是以性能为代价的。

`IEnumerable<T>`的一个性能问题同时也是其优点之一：延迟执行，亦称为懒加载。实现此接口的类型并非必须实现延迟执行，但许多类型确实如此。

但`IEnumerable<T>`最糟糕的性能问题是迭代时必须在堆上分配一个对象。为了避免这种内存分配，你应该使用具体类型定义你的方法，如下代码中突出显示的部分所示：

```cs
void ProcessCollection<T>(**List<T>** collection)
{
  // process the items in the collection,
  // perhaps using a foreach statement
} 
```

这将使用 `List<T>.Enumerator GetEnumerator()` 方法，该方法返回一个 `struct`，而不是返回引用类型的 `IEnumerator<T> GetEnumerator()` 方法。您的代码将快两到三倍，并且需要更少的内存。与所有与性能相关的建议一样，您应该通过在产品环境中运行实际代码的性能测试来确认好处。您将在*第十二章*，*使用多任务提高性能和可扩展性*中学习如何做到这一点。

# 处理跨度、索引和范围

Microsoft 在 .NET Core 2.1 中的目标之一是提高性能和资源使用率。实现这一目标的关键 .NET 特性是 `Span<T>` 类型。

## 使用跨度高效利用内存

在操作数组时，您通常会创建现有子集的新副本，以便仅处理该子集。这样做效率不高，因为必须在内存中创建重复对象。

如果您需要处理数组的子集，请使用**跨度**，因为它就像原始数组的窗口。这在内存使用方面更有效，并提高了性能。跨度仅适用于数组，不适用于集合，因为内存必须是连续的。

在我们更详细地了解跨度之前，我们需要了解一些相关对象：索引和范围。

## 使用 Index 类型识别位置

C# 8.0 引入了两个特性，用于识别数组中项的索引以及使用两个索引的范围。

您在上一主题中学到，可以通过将整数传递给其索引器来访问列表中的对象，如下所示：

```cs
int index = 3;
Person p = people[index]; // fourth person in array
char letter = name[index]; // fourth letter in name 
```

`Index` 值类型是一种更正式的识别位置的方式，并支持从末尾计数，如下所示：

```cs
// two ways to define the same index, 3 in from the start 
Index i1 = new(value: 3); // counts from the start 
Index i2 = 3; // using implicit int conversion operator
// two ways to define the same index, 5 in from the end
Index i3 = new(value: 5, fromEnd: true); 
Index i4 = ⁵; // using the caret operator 
```

## 使用 Range 类型识别范围

`Range` 值类型使用 `Index` 值来指示其范围的起始和结束，使用其构造函数、C# 语法或其静态方法，如下所示：

```cs
Range r1 = new(start: new Index(3), end: new Index(7));
Range r2 = new(start: 3, end: 7); // using implicit int conversion
Range r3 = 3..7; // using C# 8.0 or later syntax
Range r4 = Range.StartAt(3); // from index 3 to last index
Range r5 = 3..; // from index 3 to last index
Range r6 = Range.EndAt(3); // from index 0 to index 3
Range r7 = ..3; // from index 0 to index 3 
```

已向 `string` 值（内部使用 `char` 数组）、`int` 数组和跨度添加了扩展方法，以使范围更易于使用。这些扩展方法接受一个范围作为参数并返回一个 `Span<T>`。这使得它们非常节省内存。

## 使用索引、范围和跨度

让我们探索使用索引和范围来返回跨度：

1.  使用您喜欢的代码编辑器将名为 `WorkingWithRanges` 的新控制台应用程序添加到 `Chapter08` 解决方案/工作区。

1.  在 Visual Studio Code 中，选择 `WorkingWithRanges` 作为活动 OmniSharp 项目。

1.  在 `Program.cs` 中，键入语句以使用 `string` 类型的 `Substring` 方法使用范围来提取某人姓名的部分，如下所示：

    ```cs
    string name = "Samantha Jones";
    // Using Substring
    int lengthOfFirst = name.IndexOf(' ');
    int lengthOfLast = name.Length - lengthOfFirst - 1;
    string firstName = name.Substring(
      startIndex: 0,
      length: lengthOfFirst);
    string lastName = name.Substring(
      startIndex: name.Length - lengthOfLast,
      length: lengthOfLast);
    WriteLine($"First name: {firstName}, Last name: {lastName}");
    // Using spans
    ReadOnlySpan<char> nameAsSpan = name.AsSpan();
    ReadOnlySpan<char> firstNameSpan = nameAsSpan[0..lengthOfFirst]; 
    ReadOnlySpan<char> lastNameSpan = nameAsSpan[^lengthOfLast..⁰];
    WriteLine("First name: {0}, Last name: {1}", 
      arg0: firstNameSpan.ToString(),
      arg1: lastNameSpan.ToString()); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    First name: Samantha, Last name: Jones 
    First name: Samantha, Last name: Jones 
    ```

# 处理网络资源

有时您需要处理网络资源。.NET 中用于处理网络资源的最常见类型如下表所示：

| 命名空间 | 示例类型 | 描述 |
| --- | --- | --- |
| `System.Net` | `Dns`, `Uri`, `Cookie`, `WebClient`, `IPAddress` | 这些用于处理 DNS 服务器、URI、IP 地址等。 |
| `System.Net` | `FtpStatusCode`, `FtpWebRequest`, `FtpWebResponse` | 这些用于与 FTP 服务器进行交互。 |
| `System.Net` | `HttpStatusCode`, `HttpWebRequest`, `HttpWebResponse` | 这些用于与 HTTP 服务器进行交互；即网站和服务。来自`System.Net.Http`的类型更容易使用。 |
| `System.Net.Http` | `HttpClient`, `HttpMethod`, `HttpRequestMessage`, `HttpResponseMessage` | 这些用于与 HTTP 服务器（即网站和服务）进行交互。你将在*第十六章*，*构建和消费 Web 服务*中学习如何使用这些。 |
| `System.Net.Mail` | `Attachment`, `MailAddress`, `MailMessage`, `SmtpClient` | 这些用于处理 SMTP 服务器；即发送电子邮件。 |
| `System.Net.NetworkInformation` | `IPStatus`, `NetworkChange`, `Ping`, `TcpStatistics` | 这些用于处理低级网络协议。 |

## 处理 URI、DNS 和 IP 地址

让我们探索一些用于处理网络资源的常见类型：

1.  使用你偏好的代码编辑器，在`Chapter08`解决方案/工作区中添加一个名为`WorkingWithNetworkResources`的新控制台应用。

1.  在 Visual Studio Code 中，选择`WorkingWithNetworkResources`作为活动 OmniSharp 项目。

1.  在`Program.cs`顶部，导入用于处理网络的命名空间，如下所示：

    ```cs
    using System.Net; // IPHostEntry, Dns, IPAddress 
    ```

1.  输入语句以提示用户输入网站地址，然后使用`Uri`类型将其分解为其组成部分，包括方案（HTTP、FTP 等）、端口号和主机，如下所示：

    ```cs
    Write("Enter a valid web address: "); 
    string? url = ReadLine();
    if (string.IsNullOrWhiteSpace(url))
    {
      url = "https://stackoverflow.com/search?q=securestring";
    }
    Uri uri = new(url);
    WriteLine($"URL: {url}"); 
    WriteLine($"Scheme: {uri.Scheme}"); 
    WriteLine($"Port: {uri.Port}"); 
    WriteLine($"Host: {uri.Host}"); 
    WriteLine($"Path: {uri.AbsolutePath}"); 
    WriteLine($"Query: {uri.Query}"); 
    ```

    为了方便，代码还允许用户按下 ENTER 键使用示例 URL。

1.  运行代码，输入有效的网站地址或按下 ENTER 键，查看结果，如下所示：

    ```cs
    Enter a valid web address:
    URL: https://stackoverflow.com/search?q=securestring 
    Scheme: https
    Port: 443
    Host: stackoverflow.com 
    Path: /search
    Query: ?q=securestring 
    ```

1.  添加语句以获取输入网站的 IP 地址，如下所示：

    ```cs
    IPHostEntry entry = Dns.GetHostEntry(uri.Host); 
    WriteLine($"{entry.HostName} has the following IP addresses:"); 
    foreach (IPAddress address in entry.AddressList)
    {
      WriteLine($"  {address} ({address.AddressFamily})");
    } 
    ```

1.  运行代码，输入有效的网站地址或按下 ENTER 键，查看结果，如下所示：

    ```cs
    stackoverflow.com has the following IP addresses: 
      151.101.193.69 (InterNetwork)
      151.101.129.69 (InterNetwork)
      151.101.1.69 (InterNetwork)
      151.101.65.69 (InterNetwork) 
    ```

## ping 服务器

现在你将添加代码以 ping 一个 Web 服务器以检查其健康状况：

1.  导入命名空间以获取更多网络信息，如下所示：

    ```cs
    using System.Net.NetworkInformation; // Ping, PingReply, IPStatus 
    ```

1.  添加语句以 ping 输入的网站，如下所示：

    ```cs
    try
    {
      Ping ping = new();
      WriteLine("Pinging server. Please wait...");
      PingReply reply = ping.Send(uri.Host);
      WriteLine($"{uri.Host} was pinged and replied: {reply.Status}.");
      if (reply.Status == IPStatus.Success)
      {
        WriteLine("Reply from {0} took {1:N0}ms", 
          arg0: reply.Address,
          arg1: reply.RoundtripTime);
      }
    }
    catch (Exception ex)
    {
      WriteLine($"{ex.GetType().ToString()} says {ex.Message}");
    } 
    ```

1.  运行代码，按下 ENTER 键，查看结果，如下所示在 macOS 上的输出：

    ```cs
    Pinging server. Please wait...
    stackoverflow.com was pinged and replied: Success.
    Reply from 151.101.193.69 took 18ms took 136ms 
    ```

1.  再次运行代码，但这次输入[`google.com`](http://google.com)，如下所示：

    ```cs
    Enter a valid web address: http://google.com
    URL: http://google.com
    Scheme: http
    Port: 80
    Host: google.com
    Path: /
    Query: 
    google.com has the following IP addresses:
      2a00:1450:4009:807::200e (InterNetworkV6)
      216.58.204.238 (InterNetwork)
    Pinging server. Please wait...
    google.com was pinged and replied: Success.
    Reply from 2a00:1450:4009:807::200e took 24ms 
    ```

# 处理反射和属性

**反射**是一种编程特性，允许代码理解和操作自身。一个程序集由最多四个部分组成：

+   **程序集元数据和清单**：名称、程序集和文件版本、引用的程序集等。

+   **类型元数据**：关于类型、其成员等的信息。

+   **IL 代码**：方法、属性、构造函数等的实现。

+   **嵌入资源**（可选）：图像、字符串、JavaScript 等。

元数据包含有关您的代码的信息项。元数据自动从您的代码生成（例如，关于类型和成员的信息）或使用属性应用于您的代码。

属性可以应用于多个级别：程序集、类型及其成员，如下列代码所示：

```cs
// an assembly-level attribute
[assembly: AssemblyTitle("Working with Reflection")]
// a type-level attribute
[Serializable] 
public class Person
{
  // a member-level attribute 
  [Obsolete("Deprecated: use Run instead.")] 
  public void Walk()
  {
... 
```

基于属性的编程在 ASP.NET Core 等应用程序模型中大量使用，以启用路由、安全性、缓存等功能。

## 程序集版本控制

.NET 中的版本号是三个数字的组合，带有两个可选的附加项。如果遵循语义版本规则，这三个数字表示以下内容：

+   **主要**：破坏性更改。

+   **次要**：非破坏性更改，包括新功能，通常还包括错误修复。

+   **补丁**：非破坏性错误修复。

**良好实践**：在更新您已在项目中使用的 NuGet 包时，为了安全起见，您应该指定一个可选标志，以确保您仅升级到最高次要版本以避免破坏性更改，或者如果您特别谨慎并且只想接收错误修复，则升级到最高补丁，如下列命令所示：`Update-Package Newtonsoft.Json -ToHighestMinor` 或 `Update-Package Newtonsoft.Json -ToHighestPatch`。

可选地，版本可以包括这些：

+   **预发布**：不支持的预览版本。

+   **构建编号**：每日构建。

**良好实践**：遵循语义版本规则，详情请参见以下链接：[`semver.org`](http://semver.org)

## 读取程序集元数据

让我们探索属性操作：

1.  使用您喜欢的代码编辑器，在`Chapter08`解决方案/工作区中添加一个名为`WorkingWithReflection`的新控制台应用程序。

1.  在 Visual Studio Code 中，选择`WorkingWithReflection`作为活动 OmniSharp 项目。

1.  在`Program.cs`顶部，导入反射命名空间，如下列代码所示：

    ```cs
    using System.Reflection; // Assembly 
    ```

1.  添加语句以获取控制台应用程序的程序集，输出其名称和位置，并获取所有程序集级属性并输出它们的类型，如下列代码所示：

    ```cs
    WriteLine("Assembly metadata:");
    Assembly? assembly = Assembly.GetEntryAssembly();
    if (assembly is null)
    {
      WriteLine("Failed to get entry assembly.");
      return;
    }
    WriteLine($"  Full name: {assembly.FullName}"); 
    WriteLine($"  Location: {assembly.Location}");
    IEnumerable<Attribute> attributes = assembly.GetCustomAttributes(); 
    WriteLine($"  Assembly-level attributes:");
    foreach (Attribute a in attributes)
    {
      WriteLine($"   {a.GetType()}");
    } 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    Assembly metadata:
      Full name: WorkingWithReflection, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
      Location: /Users/markjprice/Code/Chapter08/WorkingWithReflection/bin/Debug/net6.0/WorkingWithReflection.dll
      Assembly-level attributes:
        System.Runtime.CompilerServices.CompilationRelaxationsAttribute
        System.Runtime.CompilerServices.RuntimeCompatibilityAttribute
        System.Diagnostics.DebuggableAttribute
        System.Runtime.Versioning.TargetFrameworkAttribute
        System.Reflection.AssemblyCompanyAttribute
        System.Reflection.AssemblyConfigurationAttribute
        System.Reflection.AssemblyFileVersionAttribute
        System.Reflection.AssemblyInformationalVersionAttribute
        System.Reflection.AssemblyProductAttribute
        System.Reflection.AssemblyTitleAttribute 
    ```

    请注意，因为程序集的全名必须唯一标识程序集，所以它是以下内容的组合：

    +   **名称**，例如，`WorkingWithReflection`

    +   **版本**，例如，`1.0.0.0`

    +   **文化**，例如，`neutral`

    +   **公钥标记**，尽管这可以是`null`

    既然我们已经了解了一些装饰程序集的属性，我们可以专门请求它们。

1.  添加语句以获取`AssemblyInformationalVersionAttribute`和`AssemblyCompanyAttribute`类，然后输出它们的值，如下列代码所示：

    ```cs
    AssemblyInformationalVersionAttribute? version = assembly
      .GetCustomAttribute<AssemblyInformationalVersionAttribute>(); 
    WriteLine($"  Version: {version?.InformationalVersion}");
    AssemblyCompanyAttribute? company = assembly
      .GetCustomAttribute<AssemblyCompanyAttribute>();
    WriteLine($"  Company: {company?.Company}"); 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
     Version: 1.0.0
      Company: WorkingWithReflection 
    ```

    嗯，除非设置版本，否则默认值为 1.0.0，除非设置公司，否则默认值为程序集名称。让我们明确设置这些信息。在旧版.NET Framework 中设置这些值的方法是在 C#源代码文件中添加属性，如下所示：

    ```cs
    [assembly: AssemblyCompany("Packt Publishing")] 
    [assembly: AssemblyInformationalVersion("1.3.0")] 
    ```

    .NET 使用的 Roslyn 编译器会自动设置这些属性，因此我们不能采用旧方法。相反，必须在项目文件中设置它们。

1.  编辑`WorkingWithReflection.csproj`项目文件，添加版本和公司元素，如下所示高亮显示：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <OutputType>Exe</OutputType>
        <TargetFramework>net6.0</TargetFramework>
        <Nullable>enable</Nullable>
        <ImplicitUsings>enable</ImplicitUsings>
     **<Version>****6.3.12****</Version>**
     **<Company>Packt Publishing</Company>**
      </PropertyGroup>
    </Project> 
    ```

1.  运行代码并查看结果，如下所示输出：

    ```cs
     Version: 6.3.12
      Company: Packt Publishing 
    ```

## 创建自定义属性

你可以通过继承`Attribute`类来定义自己的属性：

1.  向项目中添加一个名为`CoderAttribute.cs`的类文件。

1.  定义一个属性类，该类可以装饰类或方法，并存储程序员姓名和上次修改代码的日期这两个属性，如下所示：

    ```cs
    namespace Packt.Shared;
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, 
      AllowMultiple = true)]
    public class CoderAttribute : Attribute
    {
      public string Coder { get; set; }
      public DateTime LastModified { get; set; }
      public CoderAttribute(string coder, string lastModified)
      {
        Coder = coder;
        LastModified = DateTime.Parse(lastModified);
      }
    } 
    ```

1.  在`Program.cs`中，导入一些命名空间，如下所示：

    ```cs
    using System.Runtime.CompilerServices; // CompilerGeneratedAttribute
    using Packt.Shared; // CoderAttribute 
    ```

1.  在`Program.cs`底部，添加一个带有方法的类，并用包含两位程序员信息的`Coder`属性装饰该方法，如下所示：

    ```cs
    class Animal
    {
      [Coder("Mark Price", "22 August 2021")]
      [Coder("Johnni Rasmussen", "13 September 2021")] 
      public void Speak()
      {
        WriteLine("Woof...");
      }
    } 
    ```

1.  在`Program.cs`中，在`Animal`类上方，添加代码以获取类型，枚举其成员，读取这些成员上的任何`Coder`属性，并输出信息，如下所示：

    ```cs
    WriteLine(); 
    WriteLine($"* Types:");
    Type[] types = assembly.GetTypes();
    foreach (Type type in types)
    {
      WriteLine();
      WriteLine($"Type: {type.FullName}"); 
      MemberInfo[] members = type.GetMembers();
      foreach (MemberInfo member in members)
      {
        WriteLine("{0}: {1} ({2})",
          arg0: member.MemberType,
          arg1: member.Name,
          arg2: member.DeclaringType?.Name);
        IOrderedEnumerable<CoderAttribute> coders = 
          member.GetCustomAttributes<CoderAttribute>()
          .OrderByDescending(c => c.LastModified);
        foreach (CoderAttribute coder in coders)
        {
          WriteLine("-> Modified by {0} on {1}",
            coder.Coder, coder.LastModified.ToShortDateString());
        }
      }
    } 
    ```

1.  运行代码并查看结果，如下所示部分输出：

    ```cs
    * Types:
    ...
    Type: Animal
    Method: Speak (Animal)
    -> Modified by Johnni Rasmussen on 13/09/2021
    -> Modified by Mark Price on 22/08/2021
    Method: GetType (Object)
    Method: ToString (Object)
    Method: Equals (Object)
    Method: GetHashCode (Object)
    Constructor: .ctor (Program)
    ...
    Type: <Program>$+<>c
    Method: GetType (Object)
    Method: ToString (Object)
    Method: Equals (Object)
    Method: GetHashCode (Object)
    Constructor: .ctor (<>c)
    Field: <>9 (<>c)
    Field: <>9__0_0 (<>c) 
    ```

`<Program>$+<>c`类型是什么？

这是一个编译器生成的**显示类**。`<>`表示编译器生成，`c`表示显示类。它们是编译器的未记录实现细节，可能会随时更改。你可以忽略它们，因此作为一个可选挑战，向你的控制台应用程序添加语句，通过跳过带有`CompilerGeneratedAttribute`装饰的类型来过滤编译器生成的类型。

## 利用反射实现更多功能

这只是反射所能实现功能的一个尝鲜。我们仅使用反射从代码中读取元数据。反射还能执行以下操作：

+   **动态加载当前未引用的程序集**：[`docs.microsoft.com/en-us/dotnet/standard/assembly/unloadability`](https://docs.microsoft.com/en-us/dotnet/standard/assembly/unloadability)

+   **动态执行代码**：[`docs.microsoft.com/en-us/dotnet/api/system.reflection.methodbase.invoke`](https://docs.microsoft.com/en-us/dotnet/api/system.reflection.methodbase.invoke)

+   **动态生成新代码和程序集**：[`docs.microsoft.com/en-us/dotnet/api/system.reflection.emit.assemblybuilder`](https://docs.microsoft.com/en-us/dotnet/api/system.reflection.emit.assemblybuilder)

# 处理图像

ImageSharp 是一个第三方跨平台 2D 图形库。当.NET Core 1.0 正在开发时，社区对缺少用于处理 2D 图像的`System.Drawing`命名空间有负面反馈。

**ImageSharp**项目正是为了填补现代.NET 应用中的这一空白而启动的。

微软在其官方文档中关于`System.Drawing`的部分指出：“由于不支持在 Windows 或 ASP.NET 服务中使用，且不支持跨平台，`System.Drawing`命名空间不建议用于新开发。推荐使用 ImageSharp 和 SkiaSharp 作为替代。”

让我们看看 ImageSharp 能实现什么：

1.  使用您偏好的代码编辑器，向`Chapter08`解决方案/工作区添加一个名为`WorkingWithImages`的新控制台应用。

1.  在 Visual Studio Code 中，选择`WorkingWithImages`作为活动 OmniSharp 项目。

1.  创建一个`images`目录，并从以下链接下载九张图片：[`github.com/markjprice/cs10dotnet6/tree/master/Assets/Categories`](https://github.com/markjprice/cs10dotnet6/tree/master/Assets/Categories)

1.  添加对`SixLabors.ImageSharp`的包引用，如下所示：

    ```cs
    <ItemGroup>
      <PackageReference Include="SixLabors.ImageSharp" Version="1.0.3" />
    </ItemGroup> 
    ```

1.  构建`WorkingWithImages`项目。

1.  在`Program.cs`顶部，导入一些用于处理图像的命名空间，如下所示：

    ```cs
    using SixLabors.ImageSharp;
    using SixLabors.ImageSharp.Processing; 
    ```

1.  在`Program.cs`中，输入语句将`images`文件夹中的所有文件转换为灰度缩略图，大小为原图的十分之一，如下所示：

    ```cs
    string imagesFolder = Path.Combine(
      Environment.CurrentDirectory, "images");
    IEnumerable<string> images =
      Directory.EnumerateFiles(imagesFolder);
    foreach (string imagePath in images)
    {
      string thumbnailPath = Path.Combine(
        Environment.CurrentDirectory, "images",   
        Path.GetFileNameWithoutExtension(imagePath)
        + "-thumbnail" + Path.GetExtension(imagePath));
      using (Image image = Image.Load(imagePath))
      {
        image.Mutate(x => x.Resize(image.Width / 10, image.Height / 10));   
        image.Mutate(x => x.Grayscale());
        image.Save(thumbnailPath);
      }
    }
    WriteLine("Image processing complete. View the images folder."); 
    ```

1.  运行代码。

1.  在文件系统中，打开`images`文件夹，注意字节数显著减少的灰度缩略图，如图*8.1*所示：![应用程序图片 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_08_01.png)

    图 8.1：处理后的图像

ImageSharp 还提供了用于程序化绘制图像和处理网络图像的 NuGet 包，如下表所示：

+   `SixLabors.ImageSharp.Drawing`

+   `SixLabors.ImageSharp.Web`

# 国际化您的代码

国际化是使代码在全球范围内正确运行的过程。它包括两个部分：**全球化**和**本地化**。

全球化意味着编写代码时要考虑多种语言和地区组合。语言与地区的组合被称为文化。代码需要了解语言和地区，因为例如魁北克和巴黎虽然都使用法语，但日期和货币格式却不同。

所有文化组合都有**国际标准化组织**（**ISO**）代码。例如，代码`da-DK`中，`da`代表丹麦语，`DK`代表丹麦地区；而在代码`fr-CA`中，`fr`代表法语，`CA`代表加拿大地区。

ISO 并非缩写。ISO 是对希腊语单词*isos*（意为相等）的引用。

本地化是关于定制用户界面以支持一种语言，例如，将按钮的标签更改为关闭（`en`）或 Fermer（`fr`）。由于本地化更多地涉及语言，因此它并不总是需要了解区域，尽管具有讽刺意味的是，标准化（`en-US`）和标准化（`en-GB`）暗示了相反的情况。

## 检测和更改当前文化

国际化是一个庞大的主题，已有数千页的书籍专门论述。在本节中，你将通过`System.Globalization`命名空间中的`CultureInfo`类型简要了解基础知识。

让我们写一些代码：

1.  使用你偏好的代码编辑器，在`Chapter08`解决方案/工作区中添加一个名为`Internationalization`的新控制台应用。

1.  在 Visual Studio Code 中，选择`Internationalization`作为活动的 OmniSharp 项目。

1.  在`Program.cs`的顶部，导入用于使用全球化类型的命名空间，如下面的代码所示：

    ```cs
    using System.Globalization; // CultureInfo 
    ```

1.  添加语句以获取当前的全球化文化和本地化文化，并输出有关它们的一些信息，然后提示用户输入新的文化代码，并展示这如何影响常见值（如日期和货币）的格式化，如下面的代码所示：

    ```cs
    CultureInfo globalization = CultureInfo.CurrentCulture; 
    CultureInfo localization = CultureInfo.CurrentUICulture;
    WriteLine("The current globalization culture is {0}: {1}",
      globalization.Name, globalization.DisplayName);
    WriteLine("The current localization culture is {0}: {1}",
      localization.Name, localization.DisplayName);
    WriteLine();
    WriteLine("en-US: English (United States)"); 
    WriteLine("da-DK: Danish (Denmark)"); 
    WriteLine("fr-CA: French (Canada)"); 
    Write("Enter an ISO culture code: ");  
    string? newCulture = ReadLine();
    if (!string.IsNullOrEmpty(newCulture))
    {
      CultureInfo ci = new(newCulture); 
      // change the current cultures
      CultureInfo.CurrentCulture = ci;
      CultureInfo.CurrentUICulture = ci;
    }
    WriteLine();
    Write("Enter your name: "); 
    string? name = ReadLine();
    Write("Enter your date of birth: "); 
    string? dob = ReadLine();
    Write("Enter your salary: "); 
    string? salary = ReadLine();
    DateTime date = DateTime.Parse(dob);
    int minutes = (int)DateTime.Today.Subtract(date).TotalMinutes; 
    decimal earns = decimal.Parse(salary);
    WriteLine(
      "{0} was born on a {1:dddd}, is {2:N0} minutes old, and earns {3:C}",
      name, date, minutes, earns); 
    ```

    当你运行一个应用程序时，它会自动将其线程设置为使用操作系统的文化。我在英国伦敦运行我的代码，因此线程被设置为英语（英国）。

    代码提示用户输入替代的 ISO 代码。这允许你的应用程序在运行时替换默认文化。

    应用程序然后使用标准格式代码输出星期几，使用格式代码`dddd`；使用千位分隔符的分钟数，使用格式代码`N0`；以及带有货币符号的薪水。这些会根据线程的文化自动调整。

1.  运行代码并输入`en-GB`作为 ISO 代码，然后输入一些样本数据，包括英国英语中有效的日期格式，如下面的输出所示：

    ```cs
    Enter an ISO culture code: en-GB 
    Enter your name: Alice
    Enter your date of birth: 30/3/1967 
    Enter your salary: 23500
    Alice was born on a Thursday, is 25,469,280 minutes old, and earns
    £23,500.00 
    ```

    如果你输入`en-US`而不是`en-GB`，则必须使用月/日/年的格式输入日期。

1.  重新运行代码并尝试不同的文化，例如丹麦的丹麦语，如下面的输出所示：

    ```cs
    Enter an ISO culture code: da-DK 
    Enter your name: Mikkel
    Enter your date of birth: 12/3/1980 
    Enter your salary: 340000
    Mikkel was born on a onsdag, is 18.656.640 minutes old, and earns 340.000,00 kr. 
    ```

在此示例中，只有日期和薪水被全球化为丹麦语。其余文本硬编码为英语。本书目前不包括如何将文本从一种语言翻译成另一种语言。如果你希望我在下一版中包含这一点，请告诉我。

**良好实践**：考虑你的应用程序是否需要国际化，并在开始编码之前为此做好计划！写下用户界面中需要本地化的所有文本片段。考虑所有需要全球化的数据（日期格式、数字格式和排序文本行为）。

# 实践和探索

通过回答一些问题来测试您的知识和理解，进行一些实践练习，并深入研究本章的主题。

## 练习 8.1 – 测试您的知识

使用网络回答以下问题：

1.  一个`string`变量中最多可以存储多少个字符？

1.  何时以及为何应使用`SecureString`类型？

1.  何时适合使用`StringBuilder`类？

1.  何时应使用`LinkedList<T>`类？

1.  何时应使用`SortedDictionary<T>`类而非`SortedList<T>`类？

1.  威尔士的 ISO 文化代码是什么？

1.  本地化、全球化与国际化之间有何区别？

1.  在正则表达式中，`$`是什么意思？

1.  在正则表达式中，如何表示数字？

1.  为何不应使用电子邮件地址的官方标准来创建正则表达式以验证用户的电子邮件地址？

## 练习 8.2 – 练习正则表达式

在`Chapter08`解决方案/工作区中，创建一个名为`Exercise02`的控制台应用程序，提示用户输入正则表达式，然后提示用户输入一些输入，并比较两者是否匹配，直到用户按下*Esc*，如下所示：

```cs
The default regular expression checks for at least one digit.
Enter a regular expression (or press ENTER to use the default): ^[a-z]+$ 
Enter some input: apples
apples matches ^[a-z]+$? True
Press ESC to end or any key to try again.
Enter a regular expression (or press ENTER to use the default): ^[a-z]+$ 
Enter some input: abc123xyz
abc123xyz matches ^[a-z]+$? False
Press ESC to end or any key to try again. 
```

## 练习 8.3 – 练习编写扩展方法

在`Chapter08`解决方案/工作区中，创建一个名为`Exercise03`的类库，该库定义了扩展数字类型（如`BigInteger`和`int`）的扩展方法，该方法名为`ToWords`，返回一个描述数字的`string`；例如，`18,000,000`将是“一千八百万”，而`18,456,002,032,011,000,007`将是“一千八百五十六万万亿，二万亿，三十二亿，一千一百万，七”。

您可以在以下链接中阅读更多关于大数名称的信息：[`en.wikipedia.org/wiki/Names_of_large_numbers`](https://en.wikipedia.org/wiki/Names_of_large_numbers)

## 练习 8.4 – 探索主题

请使用以下页面上的链接，以了解更多关于本章所涵盖主题的详细信息：

[`github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-8---working-with-common-net-types`](https://github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-8---working-with-common-net-types)

# 总结

在本章中，您探索了用于存储和操作数字、日期和时间以及文本（包括正则表达式）的类型选择，以及用于存储多个项目的集合；处理了索引、范围和跨度；使用了某些网络资源；反思了代码和属性；使用微软推荐的第三方库操作图像；并学习了如何国际化您的代码。

下一章，我们将管理文件和流，编码和解码文本，并执行序列化。
