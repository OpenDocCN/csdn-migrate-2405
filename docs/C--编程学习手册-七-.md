# C# 编程学习手册（七）

> 原文：[`zh.annas-archive.org/md5/43CC9F8096F66361F01960142D9E6C0F`](https://zh.annas-archive.org/md5/43CC9F8096F66361F01960142D9E6C0F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十六章：使用.NET Core 3 中的 C#

C#编程语言是我们用来将想法转化为可运行代码的媒介。在编译时，整套规则、语法、约束和语义都被转换为中间语言——一种用于指导公共语言运行时（CLR）的高级汇编语言，后者提供运行代码所需的必要服务。

为了执行一些代码，像 C、C++和 Rust 这样的本地语言需要一个轻量级的运行时库来与操作系统（OS）交互，并执行*程序加载*、*构造函数*和*析构函数*等抽象。另一方面，像 C#和 Java 这样的高级语言需要一个更复杂的运行时引擎来提供其他基本服务，如*垃圾回收*、*即时编译*和*异常管理*。

当.NET Framework 首次创建时，CLR 被设计为仅在 Windows 上运行，但后来，许多其他运行时（实现相同的 ECMA 规范）出现，对市场起着重要作用。例如，Mono 运行时是第一个在 Linux 平台上运行的社区驱动项目，而微软的 Silverlight 项目在所有主要平台的浏览器中都取得了短暂的成功。其他运行时，如用于微控制器的.NET Micro Framework，用于针对嵌入式 Windows CE 操作系统的.NET Compact Framework，以及在 Windows Phone 和通用 Windows 平台上运行的更近期的运行时的例子，都展示了.NET 实现的多样性，这些实现能够运行我们今天仍在使用的相同一组指令。

这些运行时都是根据当时的历史背景所规定的一系列要求构建的，没有例外。在大约 20 年前诞生时，.NET Framework 旨在满足不断增长的基于 Windows 的个人电脑生态系统，其 CPU 功率、内存和存储空间随着时间的推移而增长。多年来，大多数这些运行时成功地转向了更受限制的硬件规格，仍然提供大致相同的功能集。例如，即使现代手机具有非常强大的微处理器，代码效率对于保护这些设备的电池寿命仍然至关重要，这是.NET Framework 最初设计时不相关的要求。

尽管这些运行时使用的.NET 规范仍然相同，但存在差异，使得每个开发人员在尝试设计能够在多个运行时上运行的应用程序时变得困难，特别是当要求它能够跨平台和/或跨设备运行时。

.NET Core 3 运行时诞生于解决这些问题，通过提供满足所有现代要求的新运行时。在本章中，我们将研究开发 C#应用程序时与运行时相关的因素：

+   使用.NET 命令行界面（CLI）

+   在 Linux 发行版上开发

+   .NET 标准是什么以及它如何帮助应用程序设计

+   消费 NuGet 包

+   迁移使用.NET Framework 设计的应用程序

+   发布应用程序

到本章结束时，您将更熟悉允许您编译和发布应用程序的.NET Core 工具，以便您可以设计一个库，与在.NET Core 或其他运行时版本上运行的其他应用程序共享代码。此外，如果您已经有一个基于.NET Framework 的应用程序，您将学习迁移它以充分利用.NET Core 运行时的主要步骤。

# 使用.NET 命令行界面（CLI）

**命令行界面**（**CLI**）是.NET 生态系统中的一个新但战略性的工具，它可以在所有平台上以相同的方式使用，实现现代的开发方法。乍一看，基于旧控制台的工具定义为“现代”可能看起来很奇怪，但在现代开发世界中，脚本化构建过程以支持**持续集成**和**持续交付**/**部署**（**CI**/**CD**）策略对于提供更快和更高质量的开发生命周期至关重要。

安装.NET Core SDK（参见[`dotnet.microsoft.com/`](https://dotnet.microsoft.com/)）后，可以通过 Linux 终端或 Windows 命令提示符使用.NET CLI。在 Windows 上的一个很好的替代品是新的**Windows 终端**应用程序，可以通过 Windows 商店下载，并提供了传统命令提示符以及**PowerShell**终端的很好替代。

.NET CLI 具有丰富的命令列表，可以完成整个开发生命周期的一整套操作。通过将`––help`字符串添加为最后一个参数，可以获得每个命令的详细和上下文帮助。最相关的命令如下：

+   `dotnet new`：`new`命令基于预定义的模板创建一个新的应用程序项目或解决方案的文件夹，这些模板可以很容易地安装在默认模板之外。仅输入此命令将列出所有可用的模板。

+   `dotnet restore`：`restore`命令从 NuGet 服务器还原引用的库（在默认的`nuget.org`互联网软件包存储库之外，用户可以创建一个`nuget.config`文件来指定其他位置，如 GitHub，甚至是本地文件夹）。

+   `dotnet run`：`run`命令在一个步骤中构建，还原和运行项目。

+   `dotnet test`：`test`命令运行指定项目的测试。

+   `dotnet publish`：`publish`命令创建可部署的二进制文件，我们将在*发布应用程序*部分讨论。

除了这些命令之外，.NET CLI 还可以用于调用其他工具。其中一些是预安装的。例如，`dotnet dev-certs`是一个用于管理本地机器上的 HTTPS 证书的工具。提供的预安装工具的另一个例子是`dotnet watch`，它观察项目中对源文件所做的更改，并在发生任何更改时自动重新运行应用程序。

`dotnet tool`命令是扩展 CLI 功能的入口，因为它允许我们通过配置的 NuGet 服务器下载和安装附加工具。在撰写本文时，尚无法在[`nuget.org`](https://nuget.org)上过滤包含.NET 工具的软件包；因此，您最好的选择是阅读文章或其他用户的建议。

在创建新项目（使用 CLI）时，您可能希望首先决定运行时版本。`dotnet ––info`命令返回所有已安装的运行时和 SDK 的列表。默认情况下，CLI 使用最近安装的`global.json`。此文件中的设置将影响包含该文件的文件夹下的所有操作所使用的.NET CLI（也被 Visual Studio 使用）：

```cs
C:\Projects>dotnet new globaljson
The template "global.json file" was created successfully.
```

现在，您可以使用您喜欢的编辑器编辑文件，并将 SDK 版本更改为先前列出的值之一：

```cs
{
    "sdk": {
        "version": "3.0.100"
    }
}
```

小心选择`info`参数。

这个过程对于将应用程序绑定到特定的 SDK 而不是自动继承最新安装的 SDK 是有用的。话虽如此，现在是时候创建一个新的空解决方案了，这是一个一个或多个项目的无代码容器。创建解决方案是可选的，但在需要创建多个交叉引用的项目时非常有用：

```cs
C:\Projects>dotnet new sln -o HelloSolution
The template "Solution File" was created successfully.
```

现在是在解决方案文件夹下创建一个新的控制台项目的时候了。由于文件夹中只有一个解决方案，因此可以在`sln add`命令中省略解决方案名称：

```cs
cd HelloSolution
dotnet new console -o Hello
dotnet sln add Hello
```

最后，我们可以构建和运行项目：

```cs
cd Hello
C:\Projects\HelloSolution\Hello>dotnet run
Hello World!
```

或者，我们可以使用`watch`命令在任何文件更改时重新运行项目：

```cs
C:\Projects\HelloSolution\Hello>dotnet watch run
watch : Started
Hello World!
watch : Exited
watch : Waiting for a file to change before restarting dotnet...
watch : Started
Hello Raf!
watch : Exited
watch : Waiting for a file to change before restarting dotnet...
```

当控制台上打印出第一个`等待文件更改后重新启动 dotnet...`消息时，我使用 Visual Studio Code 编辑器修改并保存了`Program.cs`文件。该文件的更改自动触发了构建过程，并且二进制文件像往常一样在`bin`文件夹中创建，其树结构已经从.NET Framework 中略有改变。

仍然有`Debug`或`Release`文件夹，其中包含一个名为框架的新子文件夹；在这种情况下，是`netcoreapp3.0`。新的项目系统支持多目标，并且可以根据项目文件中指定的框架、运行时和位数生成不同的二进制文件。该文件夹的内容如下：

+   `Hello.dll`。这是包含编译器生成的`IL`代码的程序集。

+   `Hello.exe`：`.exe`文件是一个托管应用程序，用于引导您的应用程序。稍后，我们将讨论使用更多选项发布/部署应用程序。

+   `Hello.pdb`：`.pdb`文件包含允许调试器将`IL`代码与源文件进行交叉引用的符号，以及符号（即变量、方法或类）名称与实际代码进行交叉引用。

+   `Hello.deps.json`：此文件以 JSON 格式包含完整的依赖树。它用于在编译期间检索所需的库，并且是发现不需要的依赖项或在混合不同版本的相同程序集时出现问题的非常有效的方法。

+   `Hello.runtimeconfig.json`和`Hello.runtimeconfig.dev.json`：这些文件由运行时使用，以了解应该使用哪个共享运行时来运行应用程序。`.dev`文件包含在环境指定应用程序应在开发环境中运行时使用的配置。

我们刚刚创建了一个非常基本的应用程序，但这些步骤就是创建一个由几个库组成并使用其他更复杂模板的复杂应用程序所需的全部步骤。有趣的是，可以在*Linux 终端*上执行相同的步骤以获得相同的结果。

# 在 Linux 发行版上开发

开发人员所感受到的需求革命并没有随着移动市场而停止，今天仍在持续进行。例如，跨多个操作系统运行的需求比以往任何时候都更为重要，因为云时代开始了。许多应用程序开始从本地部署转移到云架构，从虚拟机转移到容器，从面向服务的架构转移到微服务。这种转变如此之大，以至于即使微软的 CEO 也自豪地庆祝了 Azure 上 Linux 操作系统的普及，这清楚地表明了创建跨平台应用程序的重要性。

毫无疑问，.NET Core 在不同的操作系统、设备和 CPU 架构上运行的能力至关重要，但它带来了令人惊叹的抽象水平，最大程度地减少了开发人员的工作量，隐藏了大部分差异。例如，Linux 景观提供了多种发行版，但你不需要担心，因为抽象不会影响应用程序的性能。

IT 行业学到的教训是，当前推动云增长的技术并不是最终目的地，而只是一个过渡。在撰写本文时，一种名为**Web Assembly System Interface (WASI)**的技术正在标准化，作为一个强大的抽象，用于隔离小的代码单元，提供安全隔离，可以用于运行不仅是 Web 应用程序（已经通过**WebAssembly**在每个浏览器中可用），而且还可以运行云或经典的独立应用程序。

我们仍然不知道 WASI 是否会成功，但毫无疑问，现代运行时必须准备好迎接这一浪潮，这意味着要拥抱快速发展和变异的灵活性，一旦新的需求敲门。

## 准备开发环境

在创建 Linux 上的开发环境时，有多种选择。第一种是在物理机器上安装 Linux，这在整个开发生命周期中都具有性能优势。主要操作系统的选择非常主观，虽然 Windows 和 macOS 目前提供更好的桌面体验，但选择主要取决于您需要的应用程序生态系统。

另一个经过充分测试的方案是在虚拟机内进行开发。在这种情况下，您可以在 Mac 上使用*Windows Hyper-V*或*Parallels Desktop*。如果您没有选择的发行版，我强烈建议您开始安装 Ubuntu 桌面版。

在 Windows 上，您会发现使用名为**Windows 子系统 Linux（WSL）**的集成 Linux 支持非常有用，它可以作为 Windows 10 的附加组件进行安装。在撰写本文时，当前成熟的版本是**WSL 1**，它在 Windows 内核上运行 Linux 发行版。在这个解决方案中，Linux 系统调用会自动重新映射到 Windows 内核模式的实现。

在这种配置中安装的发行版是一个真正的 Linux 发行版，其中一些系统调用无法被翻译，而其他一些，如文件系统操作，由于它们的翻译不是微不足道的，因此速度较慢。使用**WSL 1**，大多数.NET Core 代码将无缝运行；因此，它是快速在 Windows 桌面和真正的 Linux 环境之间切换的好选择。

WSL 的未来已经在最新的 Windows 预览版中可用，并将很快完全发布。在这种配置中，完整的 Linux 内核安装在 Windows 上，并与 Windows 内核共存，消除了以前的任何限制，并提供接近本机速度。一旦它完全可用，我强烈推荐这个开发环境。

准备好 Linux 机器后，您有三个选择：

+   安装.NET Core **SDK**，因为您希望从 Linux 内部管理开发人员生命周期。

+   安装.NET Core 运行时，因为您只想在 Linux 上运行应用程序和/或其测试，以验证跨平台开发是否按预期工作。

+   不要安装这两者中的任何一个，因为您希望将应用程序作为独立部署进行测试。我们将在*发布应用程序*部分稍后调查这个选项。

SDK 或运行时所需的先决条件和软件包不断变化；因此，最好参考官方下载页面[`dot.net`](https://dot.net)。安装后，从终端运行`dotnet ––info`，将显示以下信息：

```cs
The runtime and sdk versions listed by this command may be different from the ones on Windows. You should consider the opportunity to create a global.json outside the sources repository in order to avoid mismatches when cloning a repository on different operating systems.
```

如果您决定使用虚拟机或 WSL，现在应该安装**SSH 守护程序**，以便您可以从主机机器与 Linux 通信。您应该参考特定于 Linux 发行版的说明，但通常来说，**openssh**软件包是最受欢迎的选择：

```cs
sudo apt-get install openssh-server
(eventually configure the configuration file /etc/ssh/sshd_config)
systemctl start ssh
```

现在，Linux 机器可以通过主机名（如果它已自动注册到您的 DNS）或 IP 地址进行联系。您可以通过输入以下内容获取这两个信息：

+   `ip address`

+   `hostname`

在 Windows 中有各种免费的`ssh`命令行工具：

```cs
ssh username@machinenameORipaddress
```

如果由于配置问题而无法工作，则典型的故障排除路径是恢复配置文件的默认权限：

```cs
Install-Module -Force OpenSSHUtils -Scope AllUsers
Repair-UserSshConfigPermission ~/.ssh/config
Get-ChildItem ~\.ssh\* -Include "id_rsa","id_dsa" -ErrorAction SilentlyContinue | % {
    Repair-UserKeyPermission -FilePath $_.FullName @psBoundParameters
}
```

当然，Linux 有许多可选工具，但在这里值得一提的是其中一些：

+   **Net-tools**：这是一个包含许多与网络相关的工具的软件包，用于诊断网络协议，如*arp*、*hostname*、*netstat*和*route*。一些发行版已经包含它们；否则，您可以使用您喜欢的软件包管理器进行安装，例如 Ubuntu 上的**apt-get**。

+   **LLDB**：这是一个 Linux 本地调试器。微软提供了 LLDB 的 SOS 扩展，其中包含与更受欢迎的 WinDbg 的 SOS 相同的一组命令。此扩展提供了许多.NET 特定的命令，用于诊断泄漏，遍历对象图，调查异常，并且它们也可以用于崩溃转储。

+   **Build-essential**：这是一个包含许多开发工具的软件包，包括 C/C++编译器和相关库，用于开发本地代码。如果您希望创建本地代码，并希望使用**PInvoke**从.NET 调用它们，这将非常有用。

+   底层的`ssh`工具是*Remote - SSH*和*Remote - WSL*。SSH 扩展允许我们通过 SSH 在远程 Linux 机器上开发，而 WSL 允许我们在本地 WSL 子系统上开发。

您可以按照最新的扩展说明来配置远程机器（详尽的文档可以在本章末尾的*进一步阅读*部分的安装链接中找到）。安装完成后，通过按下*F1*，您可以访问 Visual Studio Code 命令。然后，输入`Remote-SSH`，点击**添加新的 SSH 主机**，最后重复并选择**连接到主机**：

![图 16.1 - 通过 SSH 从 Visual Studio Code 连接到远程主机](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_16.1_B12346.jpg)

图 16.1 - 通过 SSH 从 Visual Studio Code 连接到远程主机

这第一次连接将在 Linux 上远程安装所需的工具，以启用**远程开发**场景，其中所有编译和运行任务都是在远程完成，而不是在您输入代码的机器上完成。

即使您可以部署二进制文件并远程运行它们，但这种配置对于测试在 Linux 上运行时显示异常的代码非常有用。在 Visual Studio Code 中，您可以使用**查看** | **终端**菜单打开终端窗口。集成的终端窗口可用于创建解决方案和项目，并观察源代码以在以前相同的方式自动重新运行应用程序。

## 编写跨平台感知的代码

.NET Core 提供的抽象让您忘记了许多存在并在不同操作系统上工作方式不同的特殊性，但在开发代码时仍然有一些必须仔细考虑的事情。这些看似微不足道的细节大多应成为开发人员的最佳实践，以避免在不同系统上运行应用程序时出现问题。

### 文件系统大小写

最常见的错误是不考虑文件系统的大小写。在 Linux 上，文件和文件夹的名称是*区分大小写*的；因此，发现由于路径包含文件或文件夹名称的错误大小写而导致问题并不罕见。

### 主目录

在 Windows 和 Linux 中，用户配置文件的结构是不同的，而且更重要的是，在使用`sudo`（管理员）权限运行应用程序时，主目录与当前登录用户不同。

### 路径分隔符

我们都知道 Linux 和 Windows 使用正斜杠和反斜杠字符来分隔文件和文件夹。这就是为什么`System.IO.Path`类通过一些属性公开可用的分隔符。更好的是，根本不要使用分隔符。例如，要组成一个文件夹，应优先选择以下语句：

```cs
Path.Combine("..", "..", "..", "..", "Test",
    "bin", "Debug", "netcoreapp3.0", "test.exe");
```

最后，要将相对路径转换为完整路径，请使用`Path.GetFullPath`方法。

### 行尾分隔符

处理文本文件时，Windows 的行尾分隔符是`\r\n`（`0x0D`，`0x0A`），而在 Linux 上，我们只使用`\r`（`0x0D`）。至于`Path`类，分隔符可以在运行时通过`Environment.NewLine`检索，但大多数情况下，您可以通过让`System.IO.TextReader.ReadLine`和`System.IO.TextWriter.WriteLine`抽象来处理这个区别。

### 数字证书

虽然 Windows 有一个标准的数字证书中央存储库，但 Linux 没有，开发人员需要决定是依赖于证书文件还是特定于发行版的解决方案。当您需要存储证书时，包括私钥，必须加以保护，因为私钥是绝对不能泄露的秘密。提供适当的限制以保护这些证书是开发人员的责任。

### 特定于平台的 API

每个特定于平台的 API，例如`NotImplementedException`。在 Windows 上，注册表历来用于存储与应用程序相关的每个用户甚至全局设置。Linux 没有等价物；因此，在现代开发中，最好完全摆脱注册表。另一个流行的 API 是**Windows 管理仪器（WMI）**，它仅在 Windows 上可用，在 Linux 上没有等价物。

### 安全

与 Windows 帐户相关的所有内容仅在 Windows 上可用。在 Linux 上修改文件系统安全标志的最简单方法是生成一个新进程，运行带有适当参数的标准`chmod`命令行工具。

### 环境变量

所有平台中非常强大且常见的共同点是环境变量的可用性。Windows 开发人员通常不经常使用它们，而它们在 Linux 上非常受欢迎。例如，ASP.NET Core 使用它们在开发、暂存和生产之间切换配置，但也可以用于检索标准变量，例如 Linux 上的`HOME`和 Windows 上的`HOMEPATH`，它们都代表当前用户配置文件的根文件夹。

### 您可能只在运行时发现的差距

有时您可能需要在运行时检测代码正在运行的操作系统或 CPU 架构。为此，`System.Runtime.InteropServices.RuntimeInformation`类提供了许多有趣的信息：

+   `OSDescription` 属性返回描述应用程序正在运行的操作系统的字符串。

+   `OSArchitecture` 属性返回带有 OS 架构的字符串。例如，*X64*值代表 Intel 64 位架构。

+   `FrameworkDescription` 属性返回描述当前框架的字符串，例如*.NET Core 3.0.1*。而短字符串*3.0.1*则可通过`Environment.Version`属性获得。

+   `ProcessArchitecture` 属性返回处理器架构。这种区别存在是因为 Windows 可以在其 64 位版本上创建 32 位进程。

+   `GetRuntimeDirectory` 方法返回指向应用程序使用的运行时的完整路径。

+   最后，`RuntimeInformation.IsOSPlatform` 方法返回一个布尔值，可以用于执行特定于平台的代码：

```cs
if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
    Console.WriteLine("Linux!");
else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    Console.WriteLine("Windows!");
else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
    Console.WriteLine("MacOS!");
else if (RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD))
    Console.WriteLine("FreeBSD!");
else
    Console.WriteLine("Unknown :(");
```

您应该始终评估是否使用此技术来采用特定于平台的决策，或者创建一个包含每个平台的一个 DLL 的 NuGet 包。后一种解决方案更易于维护，但本书未对此进行讨论。

# 什么是.NET Standard，它如何帮助应用程序设计

虽然.NET Core 是在几乎所有地方运行代码的最佳选择，但也是事实，我们目前可能需要在不同的运行时上运行我们的代码，例如.NET Framework 用于现有的 Windows 应用程序，Xamarin 用于开发移动应用程序，以及 Blazor 用于在 WebAssembly 沙箱中运行代码或在其他较旧的运行时上运行。

在多个运行时之间共享编译库的第一次尝试是使用**可移植类库**，开发人员只能使用所有选定运行时中可用的 API。由于将可用 API 的数量限制为仅限于公共 API 太过限制，因此得到的交集是不切实际的。.NET Standard 倡议诞生于解决此问题，通过为许多知名 API 创建版本化的 API 定义集来解决此问题。为了符合.NET Standard，任何运行时都必须保证实现该完整的 API 集。将.NET Standard 视为一种包含所有包含的 API 的巨大接口。此外，每个新版本的.NET Standard 都会向以前的版本添加新的 API。

提示

即使 API 是.NET Standard 合同的一部分，它也可以通过抛出`NotImplementedException`在某些平台上实现。允许这种解决方案是为了简化将旧应用程序迁移到.NET Standard，并且在使用.NET Standard 库时必须考虑这一点。

.NET Standard 版本 1.0 定义了一个非常小的 API 集，以满足几乎所有过去的可用运行时，例如**Silverlight**和**Windows Phone 8**。版本之后，定义的 API 数量变得更多，排除了旧的运行时，但也为开发人员提供了更多的 API。例如，版本 1.5 在 API 数量方面提供了一个很好的折衷，因为它支持非常流行的.NET Framework 4.6.2。在 GitHub 上的.NET Standard 存储库（[`github.com/dotnet/standard/tree/master/docs/versions`](https://github.com/dotnet/standard/tree/master/docs/versions)），您可以找到版本和支持的 API 集的完整列表。

在撰写本文时，您应该只关心.NET Standard 版本作为库作者。如果您查看 NuGet 上非常流行的`Newtonsoft.Json`包，您会发现它符合.NET Standard 1.0。这是非常合理的，因为它允许该库被几乎整个.NET 生态系统使用。简单的规则是库开发人员应该支持最低可能的版本。

从应用程序开发人员的角度来看，问题是不同的，因为您可能希望使用尽可能高的数字，以便拥有最多的 API。如果您的目标是仅为.NET Framework 和.NET Core 开发应用程序（在迁移到新运行时时非常常见），您的选择将是版本 2.0，因为这是.NET Framework 支持的最后一个.NET Standard 合同版本。

在撰写本文时，最新版本的.NET Standard 是 2.1，其中包括诸如`Span<T>`之类的 API，以及许多新的方法重载，这些方法采用`Span<T>`而不是数组，从而提供更好的性能结果。

## 创建.NET Standard 库

创建.NET Standard 库非常简单。在 Visual Studio 中，有一个特定的模板，而从命令行中，以下命令将创建一个默认版本为 2.0 的.NET Standard 库。您可以通过在以下命令的末尾添加`--help`来列出其他选择，或者您可以保持`netstandard2.0`并创建库项目：

```cs
C:\Projects\HelloSolution>dotnet new classlib -o MyLibrary
```

创建后，可以使用此命令将库添加到以前的解决方案中：

```cs
dotnet sln add MyLibrary
```

最后，您可以使用另一个命令将`MyLibrary`引用添加到`Hello`项目中：

```cs
C:\Projects\HelloSolution>dotnet add Hello reference MyLibrary
Reference `..\MyLibrary\MyLibrary.csproj` added to the project.
```

生成的程序集是一个类库，可以从所有针对运行时并支持该.NET Standard 版本的项目中引用。

### 在.NET Standard 和.NET Core 库之间做出决定

每当您需要在多个运行时之间共享一些代码时，最好的选择是尽可能将其放入.NET Standard 库中。

我们已经说过，库的作者应该针对最低可能的版本号，但当然，如果你是唯一的库使用者，你可能决定采用.NET Standard 2.0 来共享代码，例如，在.NET Framework、.NET Core Mono 5.4 和 Unity 2018.1 之间。

每当你的库将被专门用于.NET Core 应用程序时，你可能希望创建一个.NET Core 类库，因为它不限制你在应用程序中可以使用的 API 集：

```cs
C:\Projects\HelloSolution>dotnet new classlib -f netcoreapp3.0 -o NetCoreLibrary
C:\Projects\HelloSolution>dotnet add Hello reference NetCoreLibrary
```

在前面的例子中，已经创建了一个新的.NET Core 类库（`NetCoreLibrary`）并将其添加到`Hello`项目的引用中。

# 使用 NuGet 包

包在现代应用程序开发中扮演着非常重要的角色，因为它们定义了一个独立的代码单元，可以用作构建更大应用程序的基石。

过去，这个定义也适用于由单个`.dll`文件组成的库，但现代开发通常需要更多的文件来构建一个适当独立的代码单元。最简单的例子是当一个包包含了库以及它的依赖项，但另一个更复杂的例子是编写一个需要对本地 API 进行平台调用的库。

`RuntimeInformation`类，但通常为了性能和维护的考虑，最好将代码分割成每个操作系统和 CPU 架构的一个库。打包平台相关库的优势在于它让.NET Core 构建工具在发布时将相关库复制到输出文件夹中。除了与本地代码的互操作性之外，还有其他情况，比如根据运行时（例如.NET Core、.NET Framework、Mono 等）提供不同的实现。

## 向项目添加包

有多种方法可以向项目添加包引用；这主要取决于你选择的 IDE。Visual Studio 通过打开**解决方案资源管理器**（这是显示解决方案和项目层次结构的窗口），展开项目树，右键单击**依赖项**节点，并选择**管理 NuGet 包**菜单项来提供完整的可视化支持。以下是一个典型的 NuGet 窗口，列出了可以从**nuget.org**添加到你的项目中的包：

![图 16.2–NuGet 包管理器窗口](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_16.2_B12346.jpg)

图 16.2–NuGet 包管理器窗口

NuGet 窗口允许你添加、删除或更新项目包的不同版本：

+   在右侧，**包源**组合框显示了提供包的网站或本地文件夹的列表。点击附近的齿轮图标可以配置列表。

+   在左侧，`author:microsoft`。

+   **已安装**选项卡只显示已安装在项目中的包。

+   **更新**选项卡显示了已安装包的新版本，这些新版本来自所选源。

+   一旦你在选项卡的右侧选择了一个包，你就可以选择所需的版本，然后它将根据你从哪个选项卡开始进行安装、卸载或更新。

当一个解决方案由多个项目组成时，保持版本包的一致性非常重要。因此，Visual Studio 提供了**管理解决方案的 NuGet 包**的功能，这是一个右键单击**解决方案**节点可用的菜单项。这个窗口类似，但有一个额外的选项卡叫做**整合**，显示了在多个项目中安装了不同版本的包。理想情况下，这个选项卡不应该显示任何包：

![图 16.3–解决方案的 NuGet 包管理器，整合选项卡](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_16.3_B12346.jpg)

图 16.3–解决方案的 NuGet 包管理器，整合选项卡

搜索包的另一种方法是直接到源头。在下面的截图中，你可以看到[`nuget.org`](http://nuget.org/)网站，这是.NET 包的主要存储库：

![图 16.4-在 NuGet 库网站上搜索](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_16.4_B12346.jpg)

图 16.4-在 NuGet 库网站上搜索

这个网页显示了您选择的每个包的重要细节：

+   右侧的**源代码库**链接在可用时跳转到源代码库。

+   **依赖项**部分可以展开，显示它依赖的其他包。

+   **GitHub 使用**部分充当了包的声誉，显示了有多少开源项目依赖于它。一个包被社区使用的次数越多，它被支持和可靠的机会就越大。

在页面的上部，包部分显示了将包添加到项目的不同方法：

+   **包管理器**显示您可以从 Visual Studio 中同名窗口执行的手动命令。

+   **.NET CLI**显示.NET CLI 命令。

+   `.csproj`直接。

+   **Paket CLI**是.NET CLI 的另一种 CLI 工具。

通过 CLI 添加包是很简单的，因为`nuget.org`已经为我们提供了要在控制台终端中输入的确切命令字符串。记得先进入项目文件夹，然后输入命令。例如，以下是从命令行添加对`Newtonsoft.Json`包的引用的命令：

```cs
dotnet add package Newtonsoft.Json --version 12.0.3
```

无论操作系统如何，如果您使用 Visual Studio Code，它都提供了一个方便的终端窗口，您可以在其中输入任何.NET CLI 命令。

另一个经常使用的添加包引用的方法是直接编辑`.csproj`文件。使用.NET Core，项目文件结构得到了大幅简化，摆脱了过去的所有标签，并且还提供了在 Visual Studio 中编辑和更新文件的能力，而无需关闭或卸载项目。

以下是一个`.csproj`文件的相关部分，您可以手动添加`PackageReference`标签：

```cs
<Project Sdk="Microsoft.NET.Sdk">
 …
  <ItemGroup>
     …
  </ItemGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.3" />
  </ItemGroup>
</Project>
```

正如您所看到的，`ItemGroup`元素可以多次重复，并且每个元素可能包含多个`PackageReference`标签。

# 从.NET Framework 迁移到.NET Core

我认为.NET Core 运行时最重要的新功能是它能够与任何其他.NET Core 版本并行部署，确保任何未来的发布都不会影响旧的运行时或库，因此也不会影响应用程序。阻止微软现代化和改进.NET Framework 性能的主要原因是.NET 运行时和基类库的共享性质。因此，对这些库的最小更改可能会导致已部署的数亿个安装出现不可接受的破坏性变化。

.NET Core 新的并行部署策略的明显后果是**全局程序集缓存（GAC）**的完全消失，它提供了一个中央存储库，可以将系统或用户库部署到其中。运行时现在完全与系统的其余部分隔离，这个决定使得能够将应用程序部署到所谓的**自包含部署**中，其中所有所需的代码，包括运行时和系统库，以及应用程序代码，都被复制到一个文件夹中。我们将在*发布应用程序*部分深入探讨部署选项。

在所有可用的运行时中，.NET Framework 一直是基准，在撰写本文时，它仍然是一个有效的生态系统，将在未来很长一段时间内得到微软的支持，因为它与 Windows 客户端和服务器操作系统一起重新分发。尽管如此，作为明智的开发人员，我们不能忽视.NET Core 3 的发布，微软发表了两个重要声明：

+   .NET Framework 4.8 将是这个运行时和库的*最后一个版本*。

+   .NET 5 将是 2020 年底发布的.NET Core 的新*简称*。

毫无疑问，.NET Core 3 标志着.NET 运行时历史上的一个转折点，因为它提供了以前由.NET Framework 支持的所有工作负载。从.NET Core 3 开始，您现在可以创建服务器和 Windows 桌面应用程序，利用机器学习的力量，或开发云应用程序。这也是对所有相关开发人员的强烈建议，他们被邀请使用.NET Core 创建全新的应用程序，因为它提供了最先进的运行时、库、编译器和工具技术。

## 分析您的架构

在开始任何迁移步骤之前，重要的是要验证技术、框架和第三方库是否在.NET Core 上可用。

旧的.NET Framework 基类库已完全移植，微软和其他第三方撰写的大多数最受欢迎的 NuGet 包也已移植，这使我们所有人都有很高的机会找到与.NET Core 兼容的更新版本。如果这些依赖项可用作.NET Standard 2.0 或更低版本（请记住，.NET Standard 2.1 不受.NET Framework 支持），那么它们就可以使用。但正如我们之前所见，NuGet 包可能包含针对不同运行时的多个库，因此验证库在供应商页面上的兼容性非常重要。

如果您的项目严重依赖于 Windows，因为它们需要 Windows API，您可能需要查看**Windows 兼容性包 NuGet**包，其中包含约 20,000 个 API。

信息框

即使一个库只兼容.NET Framework，在大多数情况下，由于*shim 机制*的存在，它也可以被.NET Core 引用。在这种情况下，Visual Studio 会在构建日志中显示一个黄色三角形，表示警告。潜在的不兼容性应该经过仔细测试，以验证应用程序的正确性。

尽管.NET Core 支持绝大多数过去的工作负载，但其中一些不可用，其他一些已经被重写，使得迁移过程有点困难，但同时也带来了其他优势。

### 迁移 ASP.NET Web Forms 应用程序

这项技术非常古老，被认为已经过时，因为今天的网络与过去的网络技术相比已经演变出非常不同的范式。迁移此代码的最佳途径是使用**Blazor 模板**，这使我们能够在浏览器中运行 C#代码，这要归功于*WebAssembly*支持，现在在任何现代浏览器中都可用。虽然这个解决方案并不是真正的移植，而是重写，但它允许我们在服务器和大部分客户端代码上都使用 C#。

### Windows 通信基础（WCF）

在.NET Core 上，**Windows 通信基础**（**WCF**）仅适用于客户端，这意味着只能消费 WCF 服务。如今，有更高性能和更简单的技术可用，例如**gRPC**（需要 HTTP2）和**REST**（Web API）。对于仍然需要创建基于 SOAP 的 Web 服务的人来说，一个名为**CoreWCF**的社区驱动的开源项目在 GitHub 上可用。在开始使用此库迁移旧代码之前，您应该验证项目中使用的所有 WCF 选项在 CoreWCF 上是否也可用。

在撰写本文时，无论是.NET Core 还是 CoreWCF 都不支持**WS-***标准。

### Windows 工作流基础

工作流基础并未移植，但另一个名为**CoreWF**的开源项目在 GitHub 上可用。正如我们先前提到的 WCF 一样，您应该首先验证项目中使用的功能的完全可用性。

### Entity Framework

**Entity Framework 6（EF6）**也可以在.NET Core 上使用，你在迁移这个项目时不应该遇到任何问题，但值得一提的是，这项技术被微软认为是*功能完备*的，现在只开发**Entity Framework Core（EF Core）**。根据你的存储库访问结构，包括模型图和项目中使用的提供程序，你可能希望考虑将你的访问代码迁移到 EF Core。在这种情况下，要注意的是，在.NET Core 3 中，支持多对多关系，但需要在模型中描述中间实体类。EF Core 中的 API 与之前非常不同，但另一方面，它们提供了许多新的功能。.NET 5（这是.NET Core 的新名称）的路线图包括许多你可能想要考虑的新功能。

基于上述所有原因，你可能会发现首先使用 EF6 进行迁移，然后再迁移到 EF Core 会更容易。这个决定非常依赖于项目本身。

### ASP.NET MVC

ASP.NET MVC 框架已经完全重写为 ASP.NET Core，但它仍然提供相同的关键功能。除非你深度定制和扩展基础设施，否则迁移肯定是直接的，但仍然需要对代码进行一些小的重写，因为命名空间和类型发生了变化。

### 代码访问安全 API

所有的**代码访问安全（CAS）**API 都已经从.NET Core 中移除，因为唯一可信的边界是由托管代码的进程本身提供的。如果你仍在使用 CAS，强烈建议摆脱它，无论你的.NET Core 迁移如何。

### AppDomains 和远程 API

在.NET Core 中，每个进程始终只有一个 AppDomain。因此，你会发现大多数 AppDomain API 都已经消失并且不可用。如果你曾经使用 AppDomains 来隔离和卸载某些程序集，你应该看看`AssemblyLoadContext`，这是.NET Core 3 中的一个新 API，它可以以强大的方式解决这个问题，而不需要远程通信，因为远程通信也已经从.NET Core 中移除了。

## 准备迁移过程

从.NET Framework 迁移到.NET Core 的迁移过程中，一个常见的步骤是将.NET Framework 更新至至少 4.7.2 版本。

4.7.2 版本是一个特殊的版本，因为它是第一个完全支持.NET 标准二进制契约的版本，避免了需要填补空白的外部 NuGet 包的要求。这一步不应该引起任何问题，你可以继续使用这个最新版本的.NET Framework 部署当前的项目，而不必担心。根据解决方案的复杂性，你可能希望在仍然在.NET Framework 上运行生产代码的同时进行迁移，直到一切都经过充分测试。

在这一点上，分析应该集中在外部依赖上，比如来自第三方的 NuGet 包，这些包是你无法控制的。一旦你确定了更新的包，更新它们，这样你的.NET Framework 解决方案就可以在更新的版本上运行。即使你没有改变任何代码，你仍然有一个可部署的解决方案，它以与.NET Core 兼容的一些部分开始。

### 可移植性分析器工具

**API Port 工具**在 GitHub 上可用，网址是[`github.com/microsoft/dotnet-apiport`](https://github.com/microsoft/dotnet-apiport)，它为我们提供了创建一个详细报告的能力，列出了.NET 应用程序中使用的所有 API 以及它们在其他平台上是否可用。该工具既可以作为 Visual Studio 扩展，也可以通过 CLI 使用，这样你就可以根据需要自动化这个过程。该工具提供的最终报告是一个 Excel 电子表格，其中包含所有 API 的交叉引用，让你可以在迁移过程中进行规划，而不会在过程中遇到任何不良的意外。

## 迁移库

我们终于可以开始更新解决方案中的库项目了。重要的是要清楚地了解整个解决方案和包的依赖树。如果项目非常庞大，您可能希望利用外部工具的强大功能，比如流行的**NDepend**。在依赖树上，您应该识别出树底部没有其他外部包依赖的库，它们是最好的起点。

在大多数情况下，迁移没有依赖关系的库（或者库依赖于可以在两个框架上运行的包）是直接的。没有自动化支持，因此您应该创建一个**.NET Standard 2.0**项目。

提示

在撰写本文时，[`github.com/dotnet/try-convert/releases`](https://github.com/dotnet/try-convert/releases)存储库包含了一个工具的预览，该工具能够将项目转换为.NET Core。正如`try-convert`这个名字所暗示的，它无法处理所有类型的项目，但仍然可以作为迁移的起点。

迁移到新的`.csproj`项目结构可以通过以下两种方式之一完成：

+   创建新项目并将源文件移动到其中

+   修改旧项目的`.csproj`文件

第一种策略更简单，但缺点是会改变项目名称，这也意味着要更改默认的命名空间和程序集名称。这些可以通过对`.csproj`文件进行以下更改来重命名：

```cs
<PropertyGroup>
    ...
  <AssemblyName>MyLibrary2</AssemblyName>
 <RootNamespace>MyLibrary2</RootNamespace>
</PropertyGroup>
```

请记住，创建新项目也意味着修复所有依赖项目的引用。

第二种策略包括替换`.csproj`文件的内容，这要求您在单独的项目上测试了这些更改之前。在迁移包引用时，请注意新的.NET Core 项目会忽略`packages.config`文件，并要求所有引用都在`PackageReference`标签中指定，就像在*使用 NuGet 包*部分中提到的那样。

### 查找缺失的 API

在迁移过程中，您可能会发现一些缺失的 API。对于这种特定情况，微软创建了[`apisof.net/`](https://apisof.net/)网站，该网站对基类库和 NuGet 可用的 70 万多个 API 进行了分类。由于其搜索功能，您可以搜索任何类、方法、属性或事件，并发现其用法以及支持它的平台和版本。

## 迁移测试

一旦您迁移了较低级别的依赖库，最好创建测试项目，以便对任何迁移的代码在两个框架上进行测试。测试项目本身实际上不应该被迁移，因为您可能希望在两个框架上测试代码。因此，您可能希望在**共享项目**（在 Visual Studio 的以下屏幕中可用的模板）中共享测试代码，这是一个不会产生任何二进制文件的特殊项目：

![图 16.5 - 添加新项目的 Visual Studio 对话框](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_16.5_B12346.jpg)

图 16.5 - 添加新项目的 Visual Studio 对话框

所有引用共享项目的项目都继承了其源代码，就好像它们直接包含在其中一样。所有主要的测试框架（xUnit、NUnit 和 MSTest）都已经移植到.NET Core，但在支持的测试 API 方面可能会有一些差异；因此，任何使用测试 API 的基础设施代码都应该首先进行验证。

最后，如果测试代码使用 AppDomains 来卸载某些程序集，请记住要使用更强大的`AssemblyLoadContext` API 进行重写。现在应该继续迁移，迭代移植库和它们的测试，直到所有基础设施都已经迁移并在两个框架上运行。

## 迁移桌面项目

WPF 和 Windows Forms 工作负载可在.NET Core 3 上使用，它们的迁移应该是直接的。在撰写本文时，Windows Forms 设计器作为预览可用，但您仍然可以在之前提到的共享项目中共享设计器代码，以继续使用.NET Framework 设计器。

.NET Core 3.1 上，一些 Windows Forms 控件已被移除，但它们可以被具有相同功能的新控件替代：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_16_Table.jpg)

另一个缺失的功能是**ClickOnce**，这是许多公司内广泛使用的部署系统。微软建议将部署包迁移到更新的**MSIX**技术。

## 迁移 ASP.NET 项目

迁移 ASP.NET MVC 项目是唯一需要更多手动工作和代码更改的工作负载，但也带来了许多明显的优势，因为新编写的 ASP.NET Core 框架在性能和简化方面，如**MVC**和**WebAPI**世界的统一`Controller`层次结构。

提示

在开始之前，我强烈建议熟悉*ASP.NET Core MVC*框架，特别关注依赖注入、身份验证、授权、配置和日志记录，这些细节远远超出了本书的范围。

要迁移 ASP.NET Web 项目，最好始于新的 ASP.NET Core MVC 模板，而不是调整旧的`.csproj`，因为代码不会原样运行，总是需要一些更改。

与 ASP.NET 基础设施相关的任何代码都是您可能想要迁移的第一项。例如，`Global.asax`通常包含初始化代码，而**HTTP 模块**和**处理程序**是旨在拦截请求和响应的基础代码。迁移此代码的一般规则如下：

+   静态结构或全局助手应转换为**依赖注入（DI）**单例服务。

+   任何旨在拦截、读取或修改 HTTP 请求和响应的代码都应成为中间件，并在`Startup`类中进行配置。

+   识别`Controller`逻辑之外的任何代码，确定其生命周期，并通过`Controller`构造函数使其可用，考虑创建一个工厂，然后通过`Controller`提供工厂。

在旧的 MVC 框架中，大多数基础设施定制是为了向控制器提供外部服务。这不再需要，因为**DI**允许控制器随时需要任何服务。

第二个关键步骤是确定身份框架基础设施需求。新模板提供了许多增强功能，以及对法律*GDPR 要求*的基本支持。在大多数情况下，最好从新基础设施开始，并迁移数据库，而不仅仅是移植旧代码。在 NuGet 上，您会发现许多提供程序的支持，从 OAuth 通用提供程序到社交身份提供程序，OpenID 规范提供程序等等。还可以利用流行的开源项目**Identity Server**，这是.NET 基金会的一部分。

授权框架也发生了变化，并带来了两个重要的关键功能。第一个是基于声明的。与旧的基于角色的安全性相比，这带来了许多优势（它有一些限制）。 `Claims`也可以用作角色，每当您的检查只是布尔值时，但它们允许更复杂的逻辑结构化为 ASP.NET Core 中的`Policies`，这绝对值得采用。

一旦所有基础设施都已移植或转换，应用程序逻辑最终可以移至新的控制器。正如我们之前提到的，现在有一个单一的`Controller`基类，用于 MVC 和 Web API 控制器。通过路由机制匹配请求的控制器。在 ASP.NET Core 中，路由是通过`Controller`类中的属性进行配置的。

每个控制器可能公开一个或多个“操作”，可以使用定义它们所限制的 HTTP 动词的属性进行标记，例如`HttpGet`和`HttpPost`。与 HTTP`GET`动词相关的操作不接受任何输入参数，而其他动词（如`POST`和`PUT`）可以受益于*模型绑定*功能，该功能会自动将请求传递的值映射到输入参数。您可以在官方文档[`docs.microsoft.com/en-us/aspnet/core/mvc/models/model-binding`](https://docs.microsoft.com/en-us/aspnet/core/mvc/models/model-binding)中找到有关模型绑定的更多信息。

HTTP 往返的响应当然取决于其 HTTP 动词。操作的典型返回类型如下：

+   代表要返回给 HTTP 客户端的响应值的对象。它将根据客户端在接受标头中指定的类型进行基础设施序列化。

+   `Task<T>`，其中`T`是前述中指定的响应值。每当内容检索需要一些“慢速”访问时，例如访问文件系统或数据库时，应使用任务。

+   实现`IActionResult`的对象，例如由`ControllerBase`类中同名方法创建的`OkResult`和`NotFoundResult`，该类是任何控制器的基类。它们用于完全控制状态代码和响应标头。准备好使用的`IActionResult`类型的完整列表在`Microsoft.AspNetCore.MVC`命名空间中定义。其中一些对象具有构造函数，接受要返回的对象，例如`OkObjectResult`，它将对象作为内容返回，并将 HTTP 状态代码设置为 200。

+   实现`Task<IActionResult>`的对象，这是前一种情况的异步版本。

+   最后一种情况是返回`void`，这样基础设施将返回没有任何内容的默认响应。

一旦代码已经迁移，您必须考虑托管环境。ASP.NET Core 应用程序的 Web 服务器称为`web.config`文件，应该在新的`appsettings.json`配置文件中进行修订，或者直接在`Program.cs`文件中进行 Kestrel 配置的代码中进行修订。

请注意，仍然可以使用 IIS，但这只能用作反向代理，并且需要使用官方的 ASP.NET Core IIS 模块，该模块将所有 HTTP 流量转发到 Kestrel Web 服务器。

这个解决方案为 ASP.NET Core 带来了一个出色的、改进的、跨平台的解决方案，但如果您仍然希望在 IIS 上托管项目，通过在托管服务器上安装官方的**ASP.NET Core IIS 模块**，这是完全可能的。该模块将所有 HTTP 请求和响应转发到 Kestrel Web 服务器，因此 IIS 中的大多数设置都可以安全地忽略。

## 总结迁移步骤

规划迁移肯定并不总是容易的，但有一条明确的路径可以应用于任何一组项目。以下一些步骤可能更难或更容易，这取决于它们所实施的技术，而其他一些步骤非常直接，只需要提前练习，但从.NET Core 版本 3 开始，可用的 API 数量使得整个过程变得更加容易。迁移应用程序的大致步骤如下：

1.  确保您正在使用.NET Core 中可用的技术。当它们不可用时，您可能需要考虑进行替换，但要仔细分析对应用程序架构的影响。

1.  一旦决定开始迁移，首先将所有项目升级到最新的.NET Framework。

1.  确保所有第三方依赖项都可用作.NET Standard，并将您当前的.NET Framework 项目迁移到使用它们。

1.  使用可移植性分析器工具分析您的项目，或验证 API 的可用性 https://apisof.net/。

1.  每次将单个.NET Framework 库项目迁移到.NET Standard 时，应用程序都有可能合并回主分支并部署到生产环境。

1.  通过从没有依赖关系的项目开始导航依赖树，一直到引用已经迁移的项目的应用程序，来迁移项目。

乍一看，迁移可能看起来有点可怕，但一旦应用程序开始在.NET Core 上运行，您将会欣赏到许多优势。其中，部署提供了新的、令人兴奋的、强大的功能，我们将在下一节中讨论。

# 发布应用程序

使应用程序在开发者机器之外可用的最后一个关键步骤是**发布**。有两种部署方式：依赖框架和自包含。

**Framework-dependent deployment (FDD)**会创建一个包含在任何安装了相同操作系统和.NET 运行时的计算机上运行应用程序所需的所有必需二进制文件的文件夹。FDD 部署有几个优点：

+   这降低了部署文件夹的大小。

+   这使得安全更新易于由 IT 管理员安装，而无需重新部署它们。

+   在 Docker 容器中部署时，您可以从预先构建的镜像开始，这些镜像已经包含您所需的.NET 运行时版本。

另一个发布选项是**自包含部署（SCD）**，它会创建/复制运行应用程序所需的所有文件，包括运行时和所有基类库。SCD 的主要优势在于它消除了对托管目标的任何要求，使得您可以通过复制文件夹来运行应用程序。

提示

在 Linux 上，某些基本库可能需要在某些非常受限制的发行版上。在[`dot`](https://dot.net/)上，您可以找到关于这些要求的更新信息。

另一方面，自包含部署方案也有一些缺点：

+   应用程序必须发布到特定的操作系统和 CPU 架构。

+   每次.NET Core 运行时获得安全更新时，您都应立即响应安全公告。在这种情况下，在将更新应用到开发者机器后，您将不得不重新构建和部署应用程序。

+   总部署大小要大得多。

从.NET Core 2.2 开始，FDD 会自动生成可执行文件，而不仅仅是主项目的`.dll`文件，而在过去，FDD 应用程序需要通过`dotnet run`命令运行。现在，它们被创建为可执行文件，也被称为**Framework Dependent Executables (FDE)**，这是使用.NET Core 3 **SDK**发布应用程序时的默认设置。

## 作为 FDD 发布

如果您希望保持部署大小紧凑，只需确保目标机器上安装了您选择的.NET Core 运行时版本，并将应用程序发布为**FDD**。从命令行发布应用程序作为**FDD**很简单；首先，进入项目文件夹，然后输入以下命令：

```cs
C:\Projects\HelloSolution\Hello>dotnet publish -c Release
```

CLI 将构建和发布项目，并在屏幕上打印发布文件夹的路径：

```cs
  Hello -> C:\Projects\HelloSolution\Hello\bin\Release\netcoreapp3.0\publish\
```

可以通过在上一个命令中添加`-o`参数来更改目标文件夹：

```cs
C:\Projects\HelloSolution\Hello>dotnet publish -c Release -o myfolder
```

在这种情况下，输出文件夹将如下所示：

```cs
  Hello -> C:\Projects\HelloSolution\Hello\myfolder\
```

发布命令还可以指定所请求的运行时，接受**Runtime Identifier (RID)**（[`docs.microsoft.com/en-us/dotnet/core/rid-catalog`](https://docs.microsoft.com/en-us/dotnet/core/rid-catalog)）。例如，使用以下命令在 64 位架构的 Linux 上发布应用程序：

```cs
dotnet publish -c Release -r linux-x64 --no-self-contained
```

除非您还指定了输出文件夹，否则这将反映指定的 RID：

```cs
  Hello -> C:\Projects\HelloSolution\Hello\bin\Release\netcoreapp3.0\linux-x64\publish\
```

需要`--no-self-contained`参数，因为默认情况下，如果指定了运行时标识符，应用程序将作为自包含发布。

## 作为 SCD 发布

使用 SCD 意味着摆脱任何已安装的运行时依赖关系。因此，当您决定以 SCD 方式发布时，还必须指定运行时标识符（目标操作系统和 CPU 架构），以便所有必需的运行时依赖项与应用程序一起发布。

作为 SCD 发布只需要添加`--self-contained`和`-r`选项，后面跟着运行时标识符。较短的版本只需指定`-r`选项，因为默认情况下，这也会打开自包含选项。例如，为 Windows 的 64 位版本发布自包含应用程序的命令如下：

```cs
dotnet publish -c Release -r win-x64
```

在这种情况下，输出文件夹将如下所示，由命令行的输出消息指定：

```cs
  Hello -> C:\Projects\HelloSolution\Hello\bin\Release\netcoreapp3.0\win-x64\publish\
```

在发布时，是否依赖于运行时安装只是其中一个选项。现在，我们将研究其他有趣的可能性。

## 了解其他发布选项

从.NET Core 3 开始，可以在发布时指定许多有趣的选项。这些选项可以在命令行上指定，甚至可以在`.csproj`文件中强制执行，使其成为`PropertyGroup`标签内项目的默认选项。

### 单文件发布

将应用程序发布为单个文件是一个非常方便的功能，它为所有项目文件创建一个单个文件。拥有一个单独的可执行文件使得可以通过 USB 键或下载轻松移动应用程序。唯一无法嵌入可执行文件的文件是配置文件和 Web 静态文件（例如 HTML）。

以下是用于将应用程序发布为单个文件的命令行。单文件发布与 FDD 兼容；在这种情况下，您可以在命令行中附加`--no-self-contained`：

```cs
dotnet publish -r win-x64 -o folder -p:PublishSingleFile=true
```

或者，您可以在`.csproj`文件中打开单文件发布选项：

```cs
<PublishSingleFile>true</PublishSingleFile>
<RuntimeIdentifier>win-x64</RuntimeIdentifier>
```

您会立即注意到二进制文件的大小特别大，因为它包含所有的依赖代码，甚至是您不需要的程序集部分。如果我们可以摆脱所有未使用的方法、属性或类，那该多好啊？解决方案来自**IL 修剪**。

### IL 修剪

修剪是从部署二进制文件中删除所有未使用代码的能力。这个功能来自**Mono** **IL 链接器**代码库。此设置要求部署为自包含，这又要求指定运行时标识符。

在命令行上发布时，可以打开**PublishTrimmed**工厂：

```cs
dotnet publish -c Release -r win-x64 -p:PublishTrimmed=true
```

否则，可以在**csproj**文件中指定：

```cs
<PublishTrimmed>true</PublishTrimmed>
```

当大量使用反射时，修剪器失去了理解哪些库和成员是必需的能力。例如，如果动态组合成员名称，修剪器无法知道要保留还是丢弃的成员。在这种情况下，还有另外两个选项，`TrimmerRootAssembly`和`TrimmerRootDescription`，可以用来指定不应被修剪的代码。

### 提前编译（AOT）编译

AOT 编译允许我们通过在开发者机器上生成几乎所有本机 CPU 汇编代码来预编译应用程序。如果你从未听说过.NET Framework 中的**ngen**工具，它是用于在目标机器上生成本机汇编代码的，使应用程序的引导性能更快，因为不再需要**即时**（**JIT**）编译器。AOT 编译器具有相同的目标，但使用不同的策略：实际上，编译是在开发者机器上完成的，因此生成的代码质量较低。这是因为编译器无法对将运行代码的 CPU 做出假设。

为了平衡较低质量的代码，.NET Core 3 默认启用了**TieredCompilation**。每当一个应用程序方法被调用超过 30 次时，它被视为“热点”，并安排在远程线程上重新从**JIT 编译器**进行重新编译，从而提供更好的性能。

在发布时，可以通过以下命令行启用**AOT**编译：

```cs
dotnet publish -c Release -r win-x64 -p:PublishReadyToRun=true
```

或者，您可以修改`.csproj`文件以使此设置持久化：

```cs
<PublishReadyToRun>true</PublishReadyToRun>
```

AOT 编译提供了更好的启动，但也需要指定运行时标识符，这意味着为特定的操作系统和 CPU 架构进行编译。这种设置消除了 IL 代码部署在多个平台上的优势。

### 快速 JIT

每当您担心需要预生成本机编译，但仍需要提供快速的应用程序引导时，您可以启用**QuickJIT**，这是一个更快的**JIT**编译器，缺点是生成的代码性能较差。再次，分层编译平衡了代码质量的缺点，并在其符合热路径条件时重新编译代码。

从命令行启用 Quick JIT 与其他选项没有区别：

```cs
dotnet publish -c Release -p:TieredCompilationQuickJit=true
```

在**csproj**文件中启用 Quick JIT 也是类似的：

```cs
<TieredCompilationQuickJit>false</TieredCompilationQuickJit>
```

需要注意的是，AOT 编译器无法将对外部库的调用编译为目标机器上的本机代码，因为库可能会被新版本替换，从而使生成的代码失效。每当有些代码无法编译为本机代码时，它将在目标机器上使用**JIT**进行编译。因此，完全有意义同时启用**AOT**和**QuickJIT**。

提示

.NET Framework 的**ngen**编译器能够为程序集中的所有 IL 生成汇编代码，但一旦任何依赖的程序集被替换，所有本机代码都将失效，需要 JIT 重新编译所有代码。

无论您的应用程序需要自包含、单文件还是预编译，.NET Core 都提供了多种部署选项，使您的应用程序在各种情况下都能发光，现在您可以选择您喜欢的选项。

# 总结

在本章中，我们经历了构建使用.NET Core 运行时的新应用程序所需遵循的所有基本步骤，该运行时伴随着增加的 API 数量。我们首先看了一下新的强大的命令行，它提供了控制应用程序开发生命周期的所有命令。命令行的可扩展性消除了任何限制，允许任何人向生态系统中添加本地和全局工具。

我们还看到了当在 Linux 操作系统上开发时，命令行命令与在 Windows 上开发时完全相同，可以直接或通过 Windows 使用作为开发工具。事实上，Visual Studio Code 远程扩展允许您从 Windows 在 Linux 机器上开发和调试代码。

但我们也看到，.NET Core 3 并不是单向旅程，因为.NET 标准库使我们能够与所有最新的运行时共享代码，使代码重用变得更加容易。除此之外，NuGet 包的非常丰富的生态系统使得消费库变得简单直接。

采用新的运行时并不难：一些应用程序可以通过简单地转换项目文件来迁移，而其他应用程序则需要更多的编码，但最终的应用程序将受益于新的生态系统。

在最后一节中，我们研究了发布应用程序时的完整可能性，这是应用程序开发过程的顶点。在这一点上，您可以将想法和算法转化为运行中的应用程序，可能在最流行的操作系统上运行。

在下一章中，我们将讨论单元测试，这是非常重要的实践，可以保证代码质量并提供证据，证明未来的开发迭代不会引入破坏性变化或退化。

# 测试你所学到的东西

1.  安装了五个不同的 SDK 后，如何告诉 CLI 在整个解决方案中使用特定版本？

1.  如何将一些路径连接起来，以便它们在 Windows 和 Linux 上都能正确工作？

1.  如何在基于.NET Framework、.NET Core 3 和 Xamarin 的三个不同应用程序之间共享一些代码？

1.  为新的库项目添加与现有项目完全相同的引用的最快方法是什么？

1.  在迁移复杂解决方案时，我们应该从哪里开始？

1.  哪些部署选项可以保证更快的应用程序启动时间？

# 进一步阅读

Visual Studio Code 扩展可以在远程 Linux 或 WSL 会话上编译和调试项目，可以在以下链接找到：

+   [`marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-ssh`](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-ssh)

+   [`marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-wsl`](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-wsl)

描述了创建包含多个二进制文件的 NuGet 包的能力，每个二进制文件都针对不同的 CPU 架构或框架版本，可以在以下链接找到：[`docs.microsoft.com/en-us/nuget/create-packages/supporting-multiple-target-frameworks`](https://docs.microsoft.com/en-us/nuget/create-packages/supporting-multiple-target-frameworks)。


# 第十七章：单元测试

在整本书中，您已经学会了使用 C#语言进行编程所需的一切——从语句到类，从泛型到函数式编程，从反射到并发等等。我们还涵盖了许多与.NET Framework 和.NET Core 相关的主题，包括集合、正则表达式、文件和流、资源管理以及**语言集成查询**（**LINQ**）。

然而，编程的一个关键方面是确保代码的行为符合预期。没有经过适当测试的代码容易出现意外错误。有各种类型和级别的测试，但通常由开发人员在开发过程中执行的是*单元测试*。这是本书最后一章涵盖的主题。在本章中，您将学习什么是单元测试，以及用于编写 C#单元测试的内置工具。然后，我们将详细了解如何利用这些工具来对我们的 C#代码进行单元测试。

在本章中，我们将重点关注以下主题：

+   什么是单元测试？

+   微软的单元测试工具有哪些？

+   创建 C#单元测试项目

+   编写单元测试

+   编写数据驱动的单元测试

让我们从单元测试的概述开始。

# 什么是单元测试？

单元测试是一种软件测试类型，其中测试单个代码单元以验证它们是否按设计工作。单元测试是软件测试的第一级，其他级别包括集成测试、系统测试和验收测试。讨论这些测试类型超出了本书的范围。单元测试通常由软件开发人员执行。

执行单元测试具有重要的好处：

+   它有助于在开发周期的早期识别和修复错误，从而有助于节省时间和金钱。

+   它有助于开发人员更好地理解代码，并允许他们快速更改代码库。

+   它通过要求更模块化来帮助代码重用。

+   它可以作为项目文档。

+   它有助于加快开发速度，因为使用开发人员手动测试的各种方法来识别错误的工作量大于编写单元测试所花费的时间。

+   它简化了调试，因为当测试失败时，只需要查看和调试最新的更改。

测试的单元可能不同。它可以是一个*函数*（通常是在命令式编程中）或一个*类*（在面向对象编程中）。单元是单独和独立地进行测试的。这要求单元被设计为松散耦合，但也需要使用替代品，如存根、模拟和伪造。虽然这些概念的定义可能有所不同，但存根是作为其他函数的替代品，模拟它们的行为。示例可能包括用于从 Web 服务检索数据的函数的存根，或者用于稍后添加的功能的临时替代品。模拟是模拟其他对象行为的对象，通常是复杂的，不适合用于单元测试。术语**伪造**可能指的是*存根*或*模拟*，用于指示一个不真实的实体。

除了使用替代品，单元测试通常需要使用测试工具。测试工具是一种自动化测试框架，通过支持测试的创建、执行测试和生成报告来实现测试的自动化。

代码库被单元测试覆盖的程度被称为**代码覆盖率**。代码覆盖率通过提供定量度量来指示代码库已经经过测试的程度。代码覆盖率帮助我们识别程序中未经充分测试的部分，并允许我们创建更多的测试来增加覆盖率。

# 微软的单元测试工具有哪些？

如果您正在使用 Visual Studio，有几个工具可以帮助您为您的 C#代码编写单元测试。这些工具包括以下内容：

+   **Test Explorer**：这是 IDE 的一个组件，允许您查看单元测试，运行它们并查看它们的结果。**Test Explorer**不仅适用于 MSTest（Microsoft 的测试单元框架）。它有一个可扩展的 API，允许为第三方框架开发适配器。一些提供**Test Explorer**适配器的框架包括**NUnit**和**xUnit**。

+   **Microsoft 托管代码单元测试框架或 MSTest**：这是与 Visual Studio 一起安装的，也可以作为 NuGet 包使用。还有一个类似功能的本地代码单元测试框架。

+   **代码覆盖工具**：它们允许您确定单元测试覆盖的代码量。

+   **Microsoft Fakes 隔离框架**：这允许您为类和方法创建替代品。目前，这仅适用于.NET Framework 和 Visual Studio Enterprise。目前，不支持.NET 标准项目。

在撰写本书时，使用 Microsoft 测试框架进行.NET Framework 和.NET Core 的测试体验有些不同，因为.NET Core 测试项目没有单元测试模板。这意味着您需要手动创建测试类和方法，并使用适当的属性进行修饰，我们很快就会看到。

# 创建一个 C#单元测试项目

在本节中，我们将一起看一下如何在 Visual Studio 2019 中创建一个单元测试项目。当您打开**文件**|**新建项目**菜单时，您可以在各种测试项目之间进行选择：

![图 17.1 - Visual Studio 2019 单元测试项目模板](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_17.1_B12346.jpg)

图 17.1 - Visual Studio 2019 单元测试项目模板

如果您需要测试一个.NET Framework 项目，那么您选择**Unit Test Project (.NET Framework)**。

一个项目会为您创建一个包含以下内容的单元测试文件：

```cs
using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
namespace UnitTestDemo
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
        }
    }
}
```

在这里，`UnitTest1`是一个包含测试方法的类。这个类被标记为`TestClassAttribute`属性。另一个属性`TestMethodAttribute`被用来标记`TestMethod1()`方法。这些属性被测试框架用来识别包含测试的类和方法。然后它们会显示在**Test Explorer**中，您可以在那里运行或调试它们并查看它们的结果，就像您在下面的截图中看到的那样：

![图 17.2 - Visual Studio 中的 Test Explorer 显示了从所选模板创建的空单元测试的执行结果。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_17.2_B12346.jpg)

图 17.2 - Visual Studio 中的 Test Explorer 显示了从所选模板创建的空单元测试的执行结果

您可以通过手动方式或使用 Visual Studio 中可用的测试模板来添加更多的单元测试类，就像下面的截图所示：

![图 17.3 - Visual Studio 中的添加新项对话框，其中包含一些单元测试项目。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_17.3_B12346.jpg)

图 17.3 - Visual Studio 中的添加新项对话框，其中包含一些单元测试项目

如果您正在测试一个.NET Core 项目，那么在创建测试项目时，您应该选择名为**MSTest Test Project (.NET Core)**的模板（参考本节开头的截图）。结果是一个包含单个文件和之前显示的相同内容的项目。然而，使用向导添加更多的单元测试项目是不可能的，您必须手动创建一切。目前，MSTest 对.NET Core 没有可用的项目模板。

在本章的其余部分，我们将专注于测试.NET Core 项目。

# 编写单元测试

在本节中，我们将看一下如何为您的 C#代码编写单元测试。为此，我们将考虑一个矩形的以下实现：

```cs
public struct Rectangle
{
    public readonly int Left;
    public readonly int Top;
    public readonly int Right;
    public readonly int Bottom;
    public int Width => Right - Left;
    public int Height => Bottom - Top;
    public int Area => Width * Height;
    public Rectangle(int left, int top, int right, int bottom)
    {
        Left = left;
        Top = top;
        Right = right;
        Bottom = bottom;
    }
    public static Rectangle Empty => new Rectangle(0, 0, 0, 0); 
}
```

这个实现应该是直接的，不需要进一步的解释。这是一个简单的类，关于矩形并没有提供太多的功能。我们可以通过扩展方法提供更多功能。以下清单显示了增加和减少矩形大小的扩展，以及检查两个矩形是否相交，并确定它们相交的结果矩形：

```cs
public static class RectangleExtensions
{
    public static Rectangle Inflate(this Rectangle r, 
                                    int left, int top, 
                                    int right, int bottom) =>
        new Rectangle(r.Left + left, r.Top + top, 
                      r.Right + right, r.Bottom + bottom);
    public static Rectangle Deflate(this Rectangle r, 
                                    int left, int top, 
                                    int right, int bottom) =>
        new Rectangle(r.Left - left, r.Top - top, 
                      r.Right - right, r.Bottom - bottom);
    public static Rectangle Interset(
      this Rectangle a, Rectangle b)
    {
        int l = Math.Max(a.Left, b.Left);
        int r = Math.Min(a.Right, b.Right);
        int t = Math.Max(a.Top, b.Top);
        int bt = Math.Min(a.Bottom, b.Bottom);
        if (r >= l && bt >= t)
            return new Rectangle(l, t, r, bt);
        return Rectangle.Empty;
    }
    public static bool IntersectsWith(
       this Rectangle a, Rectangle b) =>
        ((b.Left < a.Right) && (a.Left < b.Right)) &&
        ((b.Top < a.Bottom) && (a.Top < b.Bottom));
}
```

我们将从测试`Rectangle`结构开始，为此，我们将不得不创建一个单元测试项目，如前一节所述。创建项目后，我们可以编辑生成的存根，使用以下代码：

```cs
[TestClass]
public class RectangleTests
{
    [TestMethod]
    public void TestEmpty()
    {
        var rectangle = Rectangle.Empty;
        Assert.AreEqual(0, rectangle.Left);
        Assert.AreEqual(0, rectangle.Top);
        Assert.AreEqual(0, rectangle.Right);
        Assert.AreEqual(0, rectangle.Bottom);
    }
    [TestMethod]
    public void TestConstructor()
    {
        var rectangle = new Rectangle(1, 2, 3, 4);
        Assert.AreEqual(1, rectangle.Left);
        Assert.AreEqual(2, rectangle.Top);
        Assert.AreEqual(3, rectangle.Right);
        Assert.AreEqual(4, rectangle.Bottom);
    }
    [TestMethod]
    public void TestProperties()
    {
      var rectangle = new Rectangle(1, 2, 3, 4);
      Assert.AreEqual(2, rectangle.Width, "With must be 2");
      Assert.AreEqual(2, rectangle.Height, "Height must be 2");
      Assert.AreEqual(4, rectangle.Area, "Area must be 4"); 
    }
    [TestMethod]
    public void TestPropertiesMore()
    {
        var rectangle = new Rectangle(1, 2, -3, -4);
        Assert.IsTrue(rectangle.Width < 0,
                      "Width should be negative");
        Assert.IsFalse(rectangle.Height > 0,
                       "Height should be negative");
    }
}
```

在此列表中，我们有一个名为`RectangleTests`的测试类，其中包含几个测试方法：

+   `TestEmpty()`

+   `TestConstructor()`

+   `TestProperties()`

+   `TestPropertiesMore()`

这些方法中的每一个都测试了`Rectangle`类的一部分。为此，我们使用了`Microsoft.VisualStudio.TestTools.UnitTesting`中的`Assert`类。该类包含一系列静态方法，帮助我们执行测试。当测试失败时，将引发异常，并且测试方法的执行将停止，并继续下一个测试方法。

在下一个截图中，我们可以看到执行我们之前编写的测试方法的结果。您可以看到所有测试都已成功执行：

![图 17.4 - 测试资源管理器显示先前编写的测试方法成功执行。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_17.4_B12346.jpg)

图 17.4 - 测试资源管理器显示先前编写的测试方法成功执行

当测试失败时，它将显示为红色的圆点，您可以检查`TestProperties()`方法，看看以下不正确的测试：

```cs
Assert.AreEqual(6, rectangle.Area, "Area must be 6");
```

这将导致`TestProperties()`测试方法失败，如下一个截图所示：

![图 17.5 - 测试资源管理器显示测试方法执行失败的 TestProperties()方法。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_17.5_B12346.jpg)

图 17.5 - 测试资源管理器显示 TestProperties()方法执行失败的测试方法

失败的原因在**测试详细摘要**窗格中有详细说明，如下一个截图所示。单击失败的测试时，将显示此窗格：

![图 17.6 - 测试资源管理器的测试详细摘要窗格显示了有关失败测试的详细信息。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_17.6_B12346.jpg)

图 17.6 - 测试资源管理器的测试详细摘要窗格显示了有关失败测试的详细信息

从此窗格中的报告中，我们可以看到`RectangleTests.cs`中`第 30 行`的`Assert.AreEqual()`失败，因为期望的结果是`6`，但实际值是`4`。我们还得到了我们提供给`Assert.AreEqual()`方法的消息。前一个截图中的整个文本消息如下：

```cs
TestProperties
   Source: RectangleTests.cs line 30
   Duration: 29 ms
  Message: 
    Assert.AreEqual failed. Expected:<6>. Actual:<4>. Area must be 6
  Stack Trace: 
    RectangleTests.TestProperties() line 35
```

到目前为止编写的测试代码中，我们使用了几种断言方法——`AreEqual()`、`IsTrue()`和`IsFalse()`。然而，这些并不是唯一可用的断言方法；还有很多。以下表格显示了一些最常用的断言方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_17_Table_1_01.jpg)

此表中列出的所有方法实际上都是重载方法。您可以通过在线文档获得完整的参考资料。

## 分析代码覆盖率

当我们创建`Rectangle`类时，还为其创建了几个扩展方法，因此我们应该编写更多的单元测试来覆盖这两个。我们可以将这些测试放入另一个测试类中。尽管附带本书的源代码包含更多的单元测试，但为简洁起见，我们在这里只列出了其中一些：

```cs
[TestClass]
public class RectangleExtensionsTests
{
    [TestMethod]
    public void TestInflate()
    {
        var rectangle1 = Rectangle.Empty.Inflate(1, 2, 3, 4);
        Assert.AreEqual(1, rectangle1.Left);
        Assert.AreEqual(2, rectangle1.Top);
        Assert.AreEqual(3, rectangle1.Right);
        Assert.AreEqual(4, rectangle1.Bottom);
    }
    [TestMethod]
    public void TestDeflate()
    {
        var rectangle1 = Rectangle.Empty.Deflate(1, 2, 3, 4);
        Assert.AreEqual(-1, rectangle1.Left);
        Assert.AreEqual(-2, rectangle1.Top);
        Assert.AreEqual(-3, rectangle1.Right);
        Assert.AreEqual(-4, rectangle1.Bottom);
    }
    [TestMethod]
    public void TestIntersectsWith()
    {
        var rectangle = new Rectangle(1, 2, 10, 12);
        var rectangle1 = new Rectangle(3, 4, 5, 6);
        var rectangle2 = new Rectangle(5, 10, 20, 13);
        var rectangle3 = new Rectangle(11, 13, 15, 16);
        Assert.IsTrue(rectangle.IntersectsWith(rectangle1));
        Assert.IsTrue(rectangle.IntersectsWith(rectangle2));
        Assert.IsFalse(rectangle.IntersectsWith(rectangle3));
    }
    [TestMethod]
    public void TestIntersect()
    {
        var rectangle = new Rectangle(1, 2, 10, 12);
        var rectangle1 = new Rectangle(3, 4, 5, 6);
        var rectangle3 = new Rectangle(11, 13, 15, 16);
        var intersection1 = rectangle.Intersect(rectangle1);
        var intersection3 = rectangle.Intersect(rectangle3);
        Assert.AreEqual(3, intersection1.Left);
        Assert.AreEqual(4, intersection1.Top);
        Assert.AreEqual(5, intersection1.Right);
        Assert.AreEqual(6, intersection1.Bottom);
        Assert.AreEqual(0, intersection3.Left);
        Assert.AreEqual(0, intersection3.Top);
        Assert.AreEqual(0, intersection3.Right);
        Assert.AreEqual(0, intersection3.Bottom);
    }
}
```

编译单元测试项目后，新的单元测试类和方法将出现在**测试资源管理器**中，因此您可以运行或调试它们。以下截图显示了所有测试方法的成功执行：

![图 17.7 - 测试资源管理器窗口显示了所有单元测试的成功执行，包括为矩形扩展方法编写的单元测试。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_17.7_B12346.jpg)

图 17.7 - 测试资源管理器窗口显示了所有单元测试的成功执行，包括为矩形扩展方法编写的单元测试

我们还可以根据您编写的单元测试来获取代码覆盖率。您可以从**测试资源管理器**或**测试**顶级菜单触发代码覆盖。根据我们目前所见的单元测试，我们得到以下覆盖范围：

![图 17.8 - Visual Studio 中显示我们单元测试代码覆盖率的代码覆盖结果窗格。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_17.8_B12346.jpg)

图 17.8 - Visual Studio 中显示我们单元测试代码覆盖率的代码覆盖结果窗格

在这里，我们可以看到`Rectangle`类完全被单元测试覆盖。然而，包含扩展的静态类只覆盖了`IntersectsWith()`，有一个八分之一的代码块没有被我们编写的单元测试覆盖。我们可以使用这份报告来识别代码中未被测试覆盖的部分，以便您可以编写更多测试。

## 测试的解剖学

到目前为止，我们编写的测试中，我们已经看到了测试类和测试方法。然而，测试类可能具有在不同阶段执行的其他方法。下面的代码显示了一个完整的示例：

```cs
[TestClass]
public class YourUnitTests
{
   [AssemblyInitialize]
   public static void AssemblyInit(TestContext context) { }
   [AssemblyCleanup]
   public static void AssemblyCleanup() { }
   [ClassInitialize]
   public static void TestFixtureSetup(TestContext context) { }
   [ClassCleanup]
   public static void TestFixtureTearDown() { }
   [TestInitialize]
   public void Setup() { }
   [TestCleanup]
   public void TearDown() { }

   [TestMethod]
   public void TestMethod1() { }
   TestMethod]
   public void TestMethod2() { }
}
```

这些方法的名称是无关紧要的。这里重要的是用于标记它们的属性。这些属性由测试框架反映，并确定方法被调用的顺序。对于这个特定的例子，顺序如下：

```cs
AssemblyInit()          // once per assembly
  TestFixtureSetup()    // once per test class
    Setup()             // before each test of the class
      TestMethod1()
    TearDown()          // after each test of the class
    Setup()
      TestMethod2()
    TearDown()
  TestFixtureTearDown() // once per test class
AssemblyCleanup()       // once per assembly
```

用于标记这些方法的属性列在下表中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_17_Table_2_01.jpg)

当您想要对同一个函数进行多个不同数据集的测试时，您可以从数据源中检索它们。托管代码的单元测试框架使这成为可能，我们将在下一节中看到。

# 编写数据驱动的单元测试

如果您再看一下之前的测试，比如`TestIntersectsWith()`测试方法，您会发现我们尝试测试各种情况，比如一个矩形与其他几个矩形的交集，一些相交，一些不相交。这是一个简单的例子，在实践中，应该有更多的矩形需要测试，以覆盖所有可能的矩形交集情况。

一般来说，随着代码的发展，测试也会发展，您经常需要添加更多的测试数据集。与其像我们之前的例子中那样在测试方法中明确地编写数据，您可以从数据源中获取数据。然后，测试方法针对数据源中的每一行执行一次。托管代码的单元测试框架支持三种不同的场景。

## 属性数据

第一种选项是通过代码提供数据，但通过一个名为`DataRowAttribute`的属性。这个属性有一个构造函数，允许我们指定任意数量的参数。然后，这些参数按照相同的顺序转发到它所用于的测试方法的参数中。让我们看一个例子：

```cs
[DataTestMethod]
[DataRow(true, 3, 4, 5, 6)]
[DataRow(true, 5, 10, 20, 13)]
[DataRow(false, 11, 13, 15, 16)]
public void TestIntersectsWith_DataRows(
    bool result, 
    int left, int top, int right, int bottom)
{
    var rectangle = new Rectangle(1, 2, 10, 12);
    Assert.AreEqual(
        result,
        rectangle.IntersectsWith(
            new Rectangle(left, top, right, bottom)));
}
```

在这个例子中有几件事情需要注意。首先，用于指示这是一个数据驱动测试方法的属性是`DataTestMethodAttribute`。然而，为了向后兼容，也支持`TestMethodAttribute`，尽管不鼓励使用。第二件需要注意的事情是`DataRowAttribute`的使用。我们用它来提供几个矩形的数据，以及与测试方法中的参考矩形相交的预期结果。如前所述，该方法对数据源中的每一行执行一次，这种情况下，即`DataRow`属性的每次出现。

以下清单显示了执行测试方法的输出：

```cs
Test has multiple result outcomes
   4 Passed
Results
    1) TestIntersectsWith_DataRows
      Duration: 8 ms
    2) TestIntersectsWith_DataRows (True,3,4,5,6)
      Duration: < 1 ms
    3) TestIntersectsWith_DataRows (True,5,10,20,13)
      Duration: < 1 ms
    4) TestIntersectsWith_DataRows (False,11,13,15,16)
      Duration: < 1 ms
```

如果数据源中的一行使测试失败，则会报告这种情况，但是方法的执行将重复进行，直到数据源中的下一行。

## 动态数据

使用`DataRow`属性是一种改进，因为它使测试代码更简单，但并非最佳选择。稍微更好的选择是动态地从类的方法或属性中获取数据。这可以使用另一个名为`DynamicDataAttribute`的属性来实现。您必须指定数据源的名称和类型（方法或属性）。下面的代码示例：

```cs
public static IEnumerable<object[]> GetData()
{
    yield return new object[] { true, 3, 4, 5, 6 };
    yield return new object[] { true, 5, 10, 20, 13 };
    yield return new object[] { false, 11, 13, 15, 16 };
}
[DataTestMethod]
[DynamicData(nameof(GetData), DynamicDataSourceType.Method)]
public void TestIntersectsWith_DynamicData(
    bool result, 
    int left, int top, int right, int bottom)
{
    var rectangle = new Rectangle(1, 2, 10, 12);
    Assert.AreEqual(
        result,
        rectangle.IntersectsWith(
            new Rectangle(left, top, right, bottom)));
} 
```

在本例中，我们定义了一个名为`GetData()`的方法，该方法返回一个对象数组的可枚举序列。我们用矩形边界和与参考矩形的交集的结果填充这些数组。然后，在测试方法中，我们使用`DynamicData`属性，并向其提供提供数据的方法的名称和数据源类型（`DynamicDataSourceType.Method`）。实际的测试代码与前一个示例中的代码没有任何不同。

然而，这种替代方案也依赖于硬编码数据。最理想的解决方案是从外部数据源读取数据。

## 来自外部源的数据

测试数据可以从外部源获取，例如 SQL Server 数据库、CSV 文件、Excel 文档或 XML。为此，我们必须使用另一个名为`DataSourceAttribute`的属性。此属性有几个构造函数，允许您指定到源的连接字符串和其他必要的参数。

注意

在撰写本书时，此解决方案和此属性仅适用于.NET Framework，并且尚不支持.NET Core。

要编写一个从外部源获取数据的测试方法，您需要能够访问有关此数据源的信息。这可以通过`TestContext`对象来实现，该对象由框架作为参数传递给标有`AssemblyInitialize`或`ClassInitialize`属性的方法。获取对该对象的引用的一个更简单的解决方案是，在测试类中提供一个名为`TestContext`的公共属性，并将其类型设置为`TestContext`，如下面的代码所示。框架将自动使用对测试上下文对象的引用来设置它：

```cs
public TestContext TestContext { get; set; }
```

然后，我们可以使用上下文来访问数据源信息。在接下来的示例中，我们将重写测试方法，以从与测试应用程序位于同一文件夹中的名为`TestData.csv`的 CSV 文件中获取数据。该文件的内容如下：

```cs
expected,left,top,right,bottom
true,3,4,5,6
true,5,10,20,13
false,11,13,15,16
```

第一列是与参考矩形的交集的预期结果，每行中的其他值是矩形的边界。从此 CSV 文件中获取数据执行的测试方法如下所示：

```cs
[DataTestMethod]
[DataSource("Microsoft.VisualStudio.TestTools.DataSource.CSV",
          "TestData.csv",
          "TestData#csv",
          DataAccessMethod.Sequential)]
public void TestIntersectsWith_CsvData()
{
    var rectangle = new Rectangle(1, 2, 10, 12);
    bool result = Convert.ToBoolean(
      TestContext.DataRow["Expected"]);
    int left = Convert.ToInt32(TestContext.DataRow["left"]);
    int top = Convert.ToInt32(TestContext.DataRow["top"]);
    int right = Convert.ToInt32(TestContext.DataRow["right"]);
    int bottom = Convert.ToInt32(
        TestContext.DataRow["bottom"]);
    Assert.AreEqual(
        result,
        rectangle.IntersectsWith(
            new Rectangle(left, top, right, bottom)));
}
```

您可以看到，与以前的方法不同，此方法没有参数。数据可通过`TestContext`对象的`DataRow`属性获得，并且此方法对 CSV 文件中的每一行调用一次。

如果您不希望在源代码中指定数据源信息（例如连接字符串），则可以使用应用程序配置文件来提供。为此，您必须添加一个自定义部分，然后定义一个连接字符串（带有名称、字符串和提供程序名称）和数据源（带有名称、连接字符串名称、表名称和数据访问方法）。对于我们在前面示例中使用的 CSV 文件，`App.config`文件将如下所示：

```cs
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
   <configSections>
      <section name="microsoft.visualstudio.testtools"
               type="Microsoft.VisualStudio.TestTools.UnitTesting.TestConfigurationSection, Microsoft.VisualStudio.TestPlatform.TestFramework.Extensions"/>
   </configSections>
   <connectionStrings>
         <add name="MyCSVConn"
              connectionString="TestData.csv"
              providerName="Microsoft.VisualStudio.TestTools.DataSource.CSV" />
      </connectionStrings>
   <microsoft.visualstudio.testtools>
      <dataSources>
         <add name="MyCSVDataSource"
              connectionString="MyCSVConn"
              dataTableName="TestData#csv"
              dataAccessMethod="Sequential"/>
      </dataSources>
   </microsoft.visualstudio.testtools>
</configuration>
```

有了这个定义，我们唯一需要对测试方法进行的更改就是更改`DataSource`属性，指定来自`.config`文件的数据源的名称（在我们的示例中为`MyCSVDataSource`）。如下面的代码所示。

```cs
[DataTestMethod]
[DataSource("MyCSVDataSource")]
public void TestIntersectsWith_CsvData()
{
    /* ... */
}
```

要获取有关如何为各种类型的数据源提供连接字符串的更多信息，您应该阅读在线文档。

# 摘要

这本书的最后一章专门讲述了单元测试，这对于编写高质量的代码至关重要。我们从基本介绍单元测试开始，了解了微软用于编写单元测试的工具，包括托管代码的单元测试框架。我们看到了如何使用这个框架创建单元测试项目，无论是针对.NET Framework 还是.NET Core。然后我们看了单元测试框架的最重要特性，并学习了如何编写单元测试。在最后一节中，我们了解了数据驱动测试，并学习了如何使用各种数据源编写测试。

随着这本书在这里结束，我们作为作者，要感谢你抽出时间来阅读。通过撰写这本书，我们试图为您提供成为 C#语言专家所必需的一切。我们希望这本书对您学习和掌握 C#语言是一个宝贵的资源。

# 检验你所学到的内容。

1.  什么是单元测试，它的最重要的好处是什么？

1.  Visual Studio 提供了哪些工具来帮助编写单元测试？

1.  Visual Studio 的测试资源管理器提供了哪些功能？

1.  如何指定单元测试项目中的类包含单元测试？

1.  你可以使用哪些类和方法来执行断言？

1.  如何检查单元测试的代码覆盖率？

1.  如何编写测试夹具，使其每个测试类执行一次？每个方法的测试夹具又是怎样的？

1.  什么是数据驱动的单元测试？

1.  `DynamicDataAttribute`是做什么的？`DataSourceAttribute`又是什么？

1.  支持的测试数据外部来源有哪些？


# 第十八章：评估

# 章节 1

1.  C#语言的第一个版本 1.0 于 2002 年发布，与.NET Framework 1.0 和 Visual Studio .NET 2002 捆绑在一起。在撰写本书时，该语言的当前版本是 C# 8。

1.  CLI 是一种规范，描述了如何在不为特定架构重写的情况下，在不同的计算机平台上使用运行时环境。CLI 描述了四个主要组件：**公共类型系统**（**CTS**）、**公共语言规范**（**CLS**）、**虚拟执行系统**（**VES**）以及程序结构和内容的元数据。

1.  CIL 是一个平台中立的中间语言，代表了 CLI 定义的中间语言二进制指令集。当您编译程序的源代码时，编译器将其转换为 CIL 字节码，并生成 CLI 程序集。当执行 CLI 程序集时，字节码通过即时编译器传递，以生成本机代码，然后由计算机处理器执行。

1.  要查看程序集的内容，您必须使用反汇编器。反汇编器的示例包括与.NET Framework 一起分发的 ildasm.exe，或者 ILSpy，一个开源的.NET 程序集浏览器和反编译器。

1.  公共语言运行时是.NET Framework 对 VES 的实现。CLR 提供诸如内存管理、类型安全、垃圾回收、异常处理、线程管理等服务。

1.  BCL 是标准库的一个组件，提供了用于表示 CLI 内置类型、简单文件访问、自定义属性、字符串处理、格式化、集合、流等类型。

1.  当前的主要.NET 框架是.NET Framework、.NET Core 和 Xamarin。由于微软计划使.NET Core 成为用于构建桌面、服务器、Web、云和移动应用程序的唯一框架；.NET Framework 被放置在维护模式，并且只包括安全更新。

1.  程序集是部署、版本控制和安全性的基本单位。它们有两种形式：可执行文件（`.exe`）和动态链接库（`.dll`）。程序集是类型、资源和元信息的集合，形成一个逻辑功能单元。程序集的标识由名称、版本、文化和公钥令牌组成。

1.  GAC 是一个机器范围的代码缓存，它可以在应用程序之间共享程序集。其默认位置是`%windir%\Microsoft.NET\assembly`。Runtime Package Store 是.NET Core 应用程序的等效物。它可以实现更快的部署和更低的磁盘空间要求。通常，该存储在 macOS 和 Linux 上可用于`/usr/local/share/dotnet/store`，在 Windows 上可用于`C:/Program Files/dotnet/store`。

1.  为了编译和执行，C#程序必须包含一个包含名为`Main()`的静态方法的类。

# 章节 2

1.  C#中的内置整数类型是`byte`、`sbyte`、`ushort`、`short`、`uint`、`int`、`ulong`和`long`。

1.  `float`和`double`类型使用 2 的倒数来表示数字的小数部分。因此，它们无法准确表示诸如 1.23 或 19.99 之类的数字，而只能近似表示它们。尽管`double`具有 15 位精度，而`float`只有 7 位；但在执行重复计算时，精度损失会累积。`decimal`类型使用实数的十进制表示，计算速度要慢得多，但提供更好的精度。`decimal`类型具有 28 位精度，适用于金融应用等类别的应用程序，这是关键。

1.  字符串可以使用`+`运算符进行连接。除了连接，您还可以使用`String.Format()`静态方法或字符串插值来组成字符串，这是该方法的一种语法快捷方式。

1.  一些字符在字符串中具有特殊含义。这些称为转义序列，并以反斜杠（`\`）为前缀。例如单引号（`\'`）、双引号（`\"`）、换行字符（`\n`）和反斜杠（`\\`）。逐字字符串是以`@`标记为前缀的字符串。对于逐字字符串，编译器不解释转义序列。这使得编写多行文本或文件路径变得更容易。

1.  隐式类型变量使用`var`关键字声明，而不是实际类型，并且必须在声明时初始化。编译器从用于初始化它们的值或表达式中推断出实际类型。

1.  值类型和引用类型是 C#和.NET 中的两种主要类型类别。值类型的变量直接存储值。引用类型的变量存储指向（地址）包含实际对象的内存位置的引用。值类型具有值语义（简单来说，当你复制一个对象时，它的值被复制），引用类型具有值语义（当你复制一个对象时，它的引用被复制）。通常，值类型存储在堆栈上，引用类型存储在堆上，但这是一个实现细节，而不是类型的特征。

1.  装箱是将值类型存储在`object`中的过程，拆箱是将`object`的值转换为值类型的相反操作。

1.  可空类型是`System.Nullable<T>`的实例，它是一个可以表示基础`T`类型的值的泛型值类型，该类型只能是值类型，以及额外的空值。可空整数变量可以声明为`Nullable<int>`或`int?`。

1.  C#中有三种类型的数组。第一种类型是一维数组，它是单维数组。例如`int[6]`，它是一个包含 6 个整数的数组。第二种类型是多维数组，它是两个或更多维度的数组，最多 32 个。例如`int[2,3]`，它是一个具有 2 行 3 列的整数数组。第三种类型是交错数组，它是数组的数组。交错数组是一个一维数组，其元素是其他数组，每个数组可以是另一个维度。

1.  系统定义的类型转换有隐式转换（例如从`int`到`double`），显式转换（例如从`double`到`int`）。显式类型转换也称为强制转换，在两种类型之间进行转换时可能会丢失信息时是必要的。用户定义的转换可以通过为某种类型定义隐式或显式操作符或使用辅助类来实现。

# 第三章

1.  C#语言中的选择语句是`if`和`switch`。

1.  `switch`语句的`default`情况可以出现在列表的任何位置。在所有情况标签被评估之后，它总是最后被评估。

1.  `for`循环允许我们执行一段代码，只要布尔表达式评估为 true。`foreach`循环允许我们遍历实现`IEnumerable`接口的集合的元素。

1.  `while`循环是一个入口控制循环。这意味着只要指定的布尔表达式评估为 true，它就会执行一系列语句。在执行块之前检查表达式。`do-while`循环是一个出口控制循环。这意味着布尔表达式将在循环结束时被检查。这确保了`do-while`循环至少会执行一次，即使条件在第一次迭代中评估为 false。

1.  要从函数返回，可以使用`return`、`yield`或`throw`。前两个表示正常返回。`throw`语句表示由于执行流中的错误情况而返回。

1.  `break`语句可用于退出`switch`情况或终止循环的执行。它适用于所有循环：`for`、`while`、`do-while`和`foreach`。

1.  它表示方法、运算符或`get`访问器是一个迭代器，它出现在`return`或`break`语句之前。从迭代器方法返回的序列可以使用`foreach`语句消耗。`yield`语句使得可以在生成时返回值并在可用时消耗它们，这在异步上下文中特别有用。

1.  您可以通过`catch(Exception)`捕获函数调用的所有异常，这样您就可以访问有关异常的信息，或者使用简单的`catch`语句（不指定异常类型），这样您就无法获取有关异常的任何信息。

1.  `finally`块包含在`try`部分之后执行的代码。无论执行是否正常恢复或控制是否因`break`、`continue`、`goto`或`return`语句而离开`try`块，都会发生这种情况。

1.  .NET 中所有异常类型的基类是`System.Exception`类。

# 第四章

1.  类是指定对象形式的模板或蓝图。它包含操作该数据的数据和代码。对象是类的一个实例。类是用`class`关键字引入的，并定义了一个引用类型。结构是用`struct`关键字引入的，并定义了一个值类型。与类不同，结构不支持继承，不能有显式的默认构造函数，并且除非它们被声明为`const`或`static`，否则字段不能在声明时初始化。

1.  只读字段是使用`readonly`修饰符定义的字段。这样的字段只能在构造函数中初始化，其值以后不能被改变。

1.  表达式体定义是一种替代语法，通常用于方法和属性，它们只是评估表达式并可能返回评估结果。它们的形式是`member => expression`。它们支持所有类成员，不仅仅是方法，还有字段、属性、索引器、构造函数和终结器。表达式评估的结果值的类型必须与方法的返回类型匹配。

1.  默认构造函数是一个没有任何参数的类的构造函数。另一方面，静态构造函数是用`static`关键字定义的构造函数，没有参数或访问修饰符，并且不能被用户调用。当首次访问类的第一个静态成员时，CLR 会自动调用静态构造函数，或者在首次实例化类时，CLR 会自动调用静态构造函数。静态构造函数用于初始化静态字段。

1.  自动实现属性是编译器将提供私有字段和`get`和`set`访问器的属性。

1.  索引器是一个类成员，允许对象像数组一样被索引。索引器定义了`get`和`set`访问器，就像属性一样。索引器没有显式的名称。它是通过使用`this`关键字创建的。索引器有一个或多个可以是任何类型的参数。

1.  静态类是用`static`关键字声明的类。它只能包含静态成员，不能被实例化。静态类成员是使用类名而不是通过对象访问的。静态类基本上与非静态类相同，具有私有构造函数，并且所有成员都声明为`static`。

1.  可用的参数修饰符是`ref`、`out`和`in`。`ref`修饰符修改参数，使其成为参数的别名，参数必须是一个变量。它允许我们创建按引用调用的机制，而不是隐式的按值调用。`in`修饰符类似，它导致参数按引用传递，但不允许函数修改它。它基本上与`readonly ref`相同。`out`关键字也定义了按引用调用的机制，但它要求函数在返回之前初始化参数。它保证在指定的函数调用期间变量被赋值。

1.  具有可变数量参数的方法必须具有一个参数，该参数是由`params`关键字引导的一维数组。这不必是函数的唯一参数，但必须是最后一个参数。

1.  枚举是一组命名的整数常量。您必须使用`enum`关键字声明枚举。枚举是值类型。当我们想要为特定目的使用有限数量的整数值时，枚举非常有用。

# 第五章

1.  面向对象编程是一种范例，允许我们围绕对象编写程序。它的核心原则是抽象、封装、继承和多态。

1.  封装允许我们将类内部的数据隐藏在外部世界之外。封装很重要，因为它通过为不同组件定义最小的公共接口来减少它们之间的依赖关系。它还增加了代码的可重用性和安全性，并使代码更容易进行单元测试。

1.  继承是一种机制，通过它一个类可以继承另一个类的属性和功能。C#支持单继承，但仅适用于引用类型。

1.  虚方法是在基类中具有实现但可以在派生类中被重写的方法，这有助于更改或扩展实现细节。基类中的实现使用`virtual`关键字定义。派生类中的实现称为重写方法，并使用`override`关键字定义。

1.  您可以通过使用`sealed`关键字声明虚成员来防止派生类中的成员被重写。

1.  抽象类不能被实例化，这意味着我们不能创建抽象类的对象。抽象类使用`abstract`关键字声明。它们可以有抽象成员和非抽象成员。抽象成员不能是私有的，也不能有实现。抽象类必须为它实现的所有接口的所有成员提供实现（如果有的话）。

1.  接口定义了一个由所有实现接口的类型支持的契约。接口是使用`interface`关键字引入的类型，包含一组必须由实现接口的任何类或结构实现的成员。通常，接口只包含成员的声明，而不包含实现。从 C# 8 开始，接口可以包含默认方法。

1.  有两种类型的多态性：编译时多态性，由方法重载表示，以及运行时多态性。运行时多态性有两个方面。一方面，派生类的对象可以无缝地用作基类的对象，放在数组或其他类型的集合、方法参数和其他位置。另一方面，类可以定义虚方法，可以在派生类中重写。在运行时，CLR 将调用与对象的运行时类型相对应的虚成员的实现。当派生类的对象在基类的对象位置上使用时，对象的声明类型和运行时类型不同。

1.  重载方法是具有相同名称但具有不同类型或不同数量参数的方法。返回类型不考虑方法重载。运算符也可以重载。当一个或两个操作数是该类型时，类型可以为重载运算符提供自定义实现。使用`operator`关键字声明运算符。这样的方法必须是`public`和`static`。

1.  SOLID 原则包括：**单一责任原则（S）**，**开闭原则（O）**，**里氏替换原则（L）**，**接口隔离原则（I）**和**依赖注入原则（D）**。

# 第六章

1.  通用是用其他类型参数化的类型。通用提供可重用性，促进类型安全，并且可以提供更好的性能（通过避免值类型的装箱和拆箱）。

1.  用于为通用类型或方法参数化的类型称为类型参数。

1.  通用类的定义方式与非通用类相同，只是在类名后的尖括号内（如`<T>`）指定一个或多个类型参数的列表。通用方法也是如此；类型参数在类名后指定。

1.  类可以派生自通用类型。结构不支持显式继承，但可以实现任意数量的通用接口。

1.  构造类型是从通用类型构造的类型，通过用实际类型替换类型参数。例如，对于`Shape<T>`通用类型，`Shape<int>`是一个构造类型。

1.  协变类型参数是使用`out`关键字声明的类型参数。这样的类型参数允许接口方法具有比指定类型参数更派生的返回类型。

1.  逆变类型参数是使用`in`关键字声明的类型参数。这样的类型参数允许接口方法具有比指定类型参数更不派生的参数。

1.  类型参数约束是为类型参数指定的限制，通知编译器类型参数必须具有什么样的能力。应用约束会限制可以用于从通用类型构造类型的类型。

1.  `new()`类型约束指定类型必须提供公共默认构造函数。

1.  C# 8 中引入的类型参数约束是`notnull`。它只能在可空上下文中使用，否则编译器会生成警告。它指定类型参数必须是非空类型。它可以是非空引用类型（在 C#8 中）或非空值类型。

# 第七章

1.  包含通用集合的 BCL 命名空间是`System.Collections.Generic`。

1.  定义用于通用集合功能的所有其他接口的基本接口是`IEnumerable<T>`。

1.  通用集合优于非通用集合，因为它们提供类型安全性的好处，对值类型有更好的性能（因为它们避免了装箱和拆箱），并且在某些情况下，它们提供非通用集合中不可用的功能。

1.  `List<T>`通用类表示可以通过它们的索引访问的元素集合。`List<T>`与数组非常相似，只是集合的大小不是固定的，而是可变的，可以随着元素的添加或删除而增长或减少。您可以使用`Add()`，`AddRange()`，`Insert()`和`InsertRange()`添加元素。您可以使用`Remove()`，`RemoveAt()`，`RemoveRange()`，`RemoveAll()`和`Clear()`删除元素。

1.  `Stack<T>`通用类表示具有后进先出语义的集合。元素使用`Push()`方法添加到顶部，并使用`Pop()`方法从顶部移除。

1.  `Queue<T>`泛型类表示具有先进先出语义的集合。`Dequeue()`方法从队列的前端移除并返回项目。`Peek()`方法返回队列前端的项目，但不移除它。

1.  `LinkedList<T>`泛型类表示双向链表。它的元素是`LinkedListNode<T>`类型。要向链表添加元素，可以使用`AddFirst()`、`AddLast()`、`AddAfter()`和`AddBefore()`方法。

1.  `Dictionary<TKey, TValue>`泛型类表示键值对的集合，允许基于键进行快速查找。这个字典类的元素是`KeyValuePair<TKey, TValue>`类型。

1.  `HashSet<T>`泛型类表示一组不同的项目，可以以任何顺序存储在一起。哈希集在逻辑上类似于字典，其中值也是键。但是，与`Dictionary<TKey, TValue>`不同，`HashSet<T>`是一个非关联容器。

1.  `BlockingCollection<T>`是一个实现了`IProducerConsumerCollection<T>`接口定义的生产者-消费者模式的类。它实际上是`IProducerConsumerCollection<T>`接口的一个简单包装器，没有内部基础存储，但必须提供一个（实现了`IProducerConsumerCollection<T>`接口的集合）。如果没有提供实现，它默认使用`ConcurrentQueue<T>`类。它适用于需要边界和阻塞的场景。

# 第八章

1.  回调是作为参数传递给另一个函数以立即调用（同步回调）或在以后调用（异步回调）的函数的函数（或更一般地说，任何可执行代码）。委托是一种强类型的回调。

1.  使用`delegate`关键字定义委托。声明看起来像函数签名，但实际上编译器引入了一个可以持有方法引用的类，其签名与委托的签名匹配。事件是使用`event`关键字声明的委托类型的变量。

1.  C#中有两种元组：引用元组，由`System.Tuple`类表示，和值元组，由`System.ValueTuple`结构表示。引用元组最多只能容纳八个元素，而值元组可以容纳任意数量的元素，但至少需要两个。值元组可以具有编译时命名字段，并且具有更简单但更丰富的语法来创建、赋值、解构和比较值。

1.  命名元组是具有字段名称的值元组。这些名称是字段`Item1`、`Item2`等的同义词，但仅在源代码级别可用。

1.  模式匹配是检查值是否具有特定形状以及在匹配成功时从值中提取信息的过程。它可以与`is`和`switch`表达式一起使用。

1.  空值不匹配类型模式，无论变量的类型如何。可以在具有类型模式匹配的`switch`表达式中添加一个用于匹配空值的`switch` case 标签，以专门处理空值。使用`var`模式时，空值始终匹配。因此，在使用`var`模式时，必须添加显式的空值检查，因为值可能为空。

1.  .NET 中用于处理正则表达式的类是`System.Text.RegularExpressions`命名空间中的`Regex`类。默认情况下，它使用 UTF-8 编码进行字符串匹配。

1.  `Match()`方法检查输入字符串中与正则表达式匹配的子字符串，并返回第一个匹配项。`Matches()`方法执行相同的搜索，但返回所有匹配项。

1.  扩展方法是扩展类型功能而不改变其源代码的方法。它们很有用，因为它们允许扩展而不改变实现，创建派生类型或重新编译代码，一般来说。

1.  扩展方法被定义为静态方法，属于静态、非嵌套、非泛型类，它们的第一个参数是它们扩展的类型，前面加上`this`关键字。

# 第九章

1.  栈是编译器分配的相对较小的内存段，用于跟踪运行应用程序所需的内存。栈具有 LIFO 语义，并随着程序执行调用函数或从函数返回而增长和缩小。另一方面，堆是程序可能在运行时用来分配内存的大内存段，在.NET 中由 CLR 管理。通常，值类型的对象分配在栈上，引用类型的对象分配在堆上。

1.  托管堆有三个内存段，称为代。它们被命名为代 0、1 和 2。代 0 包含小的、通常是短寿命的对象，比如局部变量或在函数调用的生命周期内实例化的对象。代 1 包含在代 0 的内存回收中幸存下来的小对象。代 2 包含在代 1 的内存回收中幸存下来的长寿命小对象和大对象（总是分配在这个段上）。

1.  垃圾收集有三个阶段。首先，垃圾收集器构建所有活动对象的图形，以便找出仍在使用的对象和可能被删除的对象。其次，将要压缩的对象的引用被更新。第三，死对象被移除，幸存的对象被压缩。通常，包含大对象的大对象堆不会被压缩，因为移动大块数据会产生性能成本。

1.  终结器是一个类的特殊方法（与类名相同，但前缀为`~`），应该处理类拥有所有权的非托管资源。当对象被回收时，垃圾收集器会调用这个方法。这个过程是非确定性的，这是终结和处理之间的关键区别。后者是一个确定性的过程，发生在显式调用`Dispose()`方法时（对于实现了`IDisposable`接口的类）。

1.  `GC.SuppressFinalize()`方法请求 CRL 不要调用指定对象的终结器。通常在实现`IDisposable`接口时调用这个方法，以便非托管资源不会被处理两次。

1.  `IDisposable`是一个接口，有一个名为`Dispose()`的方法，定义了对象的确定性处理的模式。

1.  `using`语句表示对实现`IDisposable`接口的类型的对象进行确定性处理的简写语法。`using`语句引入了在语句中定义的变量的作用域，并确保在退出作用域之前正确处理对象。实际的处理细节取决于资源是值类型、可空值类型、引用类型还是动态类型。

1.  可以使用平台调用服务（Platform Invocation Services，或 P/Invoke）在 C#中调用来自本机 DLL 的函数。为此，必须定义一个与本机函数签名匹配的`static` `extern`方法（使用等效的托管类型作为其参数）。这个托管函数必须用`DllImport`属性修饰，该属性定义了运行时调用本机函数所需的信息。

1.  不安全代码是 CLR 无法验证其安全性的代码。不安全代码使得可以使用指针类型并支持指针算术。不安全代码不一定是危险的，但您完全有责任确保不会引入指针错误或安全风险。使用不安全代码的典型场景包括调用从本机 DLL 或 COM 服务器导出的需要指针类型作为参数的函数，并优化一些性能关键的算法。

1.  使用`unsafe`关键字定义不安全代码，可以应用于类型（类、结构、接口和委托）、类型成员（方法、字段、属性、事件、索引器、运算符、实例构造函数和静态构造函数）和语句块。

# 第十章

1.  函数式编程的主要特征是不可变性（对象具有不变的状态）和无副作用的函数（函数不修改值或状态在它们的局部范围之外）。函数式编程的优点包括以下几点：首先，代码更容易理解和维护，因为函数不改变状态，只依赖于它们接收的参数。其次，由于同样的原因，代码更容易测试。第三，实现并发更简单和更有效，因为数据是不可变的，函数没有副作用，避免了数据竞争。

1.  高阶函数是一个接受一个或多个函数作为参数、返回一个函数或两者兼有的函数。

1.  C#提供了将函数作为参数传递、从函数返回函数、将函数分配给变量、将函数存储在数据结构中、定义匿名函数、嵌套函数以及测试函数引用是否相等的能力。所有这些特性使 C#成为一种被称为将函数视为一等公民的语言。

1.  Lambda 表达式是一种方便的编写匿名函数的方式。这是一段代码，可以是一个表达式或一个或多个行为像函数一样的语句，并且可以被分配给一个委托。因此，lambda 表达式可以作为参数传递给函数或从函数返回。它们是编写 LINQ 查询、将函数传递给高阶函数（包括应该由`Task.Run()`异步执行的代码）以及创建表达式树的一种方便的方式。Lambda 表达式由 lambda 声明运算符`=>`分隔成两部分。左部是参数列表，右部是一个表达式或一个语句。Lambda 表达式的一个例子是`n => n%2==1`。

1.  Lambda 表达式中变量作用域的规则如下：首先，lambda 表达式中引入的变量在 lambda 之外是不可见的。其次，lambda 不能捕获封闭方法中的`in`、`ref`或`out`参数。第三，lambda 捕获的变量在委托被垃圾回收之前不会被垃圾回收，即使它们本来应该超出作用域。第四，最后，lambda 表达式的返回语句仅与 lambda 所代表的匿名方法有关，并不会导致封闭方法返回。

1.  LINQ 是一组技术，使开发人员能够以一致的方式查询多种数据源。LINQ 标准查询操作符是一组在实现`IEnumerable<T>`或`IQueryable<T>`的序列上操作的扩展方法。LINQ 查询语法基本上是标准查询操作符的语法糖。编译器将用查询语法编写的查询转换为使用标准查询操作符的查询。查询语法比标准查询操作符更简单、更易读，但它们在语义上是等价的。然而，并非所有的标准查询操作符在查询语法中都有等价物。

1.  `Select()`方法将序列的每个元素投影到一个新形式中。这需要一个选择器，即一个转换函数，为集合的每个元素产生一个新值。然而，当集合的元素本身是集合时，通常需要将它们展平为单个集合。这就是`SelectMany()`方法所做的事情。

1.  部分函数应用是将具有*N*个参数和一个参数的函数进行处理，并在将参数固定为函数的一个参数后返回另一个具有*N-1*个参数的函数的过程。这种技术是柯里化的相反，柯里化是将具有*N*个参数的函数进行处理，并将其分解为接受一个参数的*N*个函数的过程。

1.  幺半群是具有单一可结合二元运算和单位元素的代数结构。任何具有这两个元素的 C#类型都是幺半群。

1.  单子是封装在值之上的一些功能的容器。单子有两个操作：第一个将一个值`v`转换为封装它的容器（`v -> C(v)`）。在函数式编程中，这个函数被称为返回。第二个将两个容器展平为一个单一的容器（`C(C(v)) -> C(v)`）。在函数式编程中，这被称为绑定。一个单子的例子是带有 LINQ 查询运算符`SelectMany()`的`IEnumerable<T>`。

# 第十一章

1.  在.NET 中，部署的单位是程序集。程序集是一个文件（可执行文件或动态链接库），其中包含 MSIL 代码以及有关程序集内容的元数据，以及可选的资源。

1.  反射是运行时类型发现和对其进行更改的过程。这意味着我们可以在运行时检索有关类型、其成员和属性的信息。反射使得可以轻松构建可扩展的应用程序；执行私有或具有其他访问级别的类型和成员，否则这些类型和成员将无法访问，这对于测试很有用；在运行时修改现有类型或创建全新类型并使用它们执行代码；以及通常在运行时更改系统行为，通常使用属性。

1.  提供有关类型的元信息的类型是`System.Type`。可以使用`GetType()`方法、`Type.GetType()`静态方法或 C#的`typeof`运算符创建此类型的实例。

1.  共享程序集旨在被多个应用程序使用，通常位于全局程序集缓存（GAC）下，这是程序集的系统存储库。私有程序集旨在被单个应用程序使用，并存储在应用程序目录或其子目录中。共享程序集必须具有强名称并强制版本约束；这些要求对于私有程序集并非必需。

1.  在.NET 中，程序集可以在以下上下文中加载：加载上下文（包含从 GAC、应用程序目录或其子目录加载的程序集）、从其他路径加载的程序集的加载上下文、仅用于反射目的加载的反射上下文，或者根本没有上下文（例如从字节数组加载程序集时）。

1.  早期绑定是在编译时创建程序集依赖关系（引用）的过程。这使得编译器可以完全访问程序集中可用的类型。晚期绑定是在运行时加载程序集的过程，在这种情况下，编译器无法访问程序集的内容。然而，这对于构建可扩展的应用程序非常重要。

1.  动态语言运行时是.NET 平台的一个组件，它定义了一个运行时环境，该环境在 CLR 之上添加了一组服务，以便使动态语言能够在 CLR 上运行，并为静态类型的语言添加动态特性。

1.  `dynamic`类型是静态类型，意味着在编译时将变量分配给`dynamic`类型。但是，它们绕过了静态类型检查。这意味着对象的实际类型只在运行时才知道，编译器无法知道也无法强制执行对该类型对象执行的任何操作。您可以调用任何带有任何参数的方法，编译器不会检查也不会抱怨；但是，如果操作无效，运行时将抛出异常。`dynamic`类型通常用于在 Interop 程序集不可用时简化对 COM 对象的使用。

1.  属性是从`System.Attribute`抽象类派生的类型，提供有关程序集、类型和成员的元信息。这些元信息由编译器、CLR 或使用反射服务读取它们的工具消耗。属性在方括号中指定，例如`[SerializableAttribute]`。属性的命名约定是类型名称总是以`Attribute`一词结尾。C#语言提供了一种语法快捷方式，允许在不带后缀`Attribute`的情况下指定属性的名称，例如`[Serializable]`。

1.  要创建用户定义的属性，必须从`System.Attribute`类型派生，并遵循将类型后缀命名为`Attribute`的命名约定。

# 第十二章

1.  当需要执行一些长时间运行的、CPU 密集型的代码时，手动创建一个专用线程是首选。另一个选项是使用`TaskCreationOptions.LongRunning`创建一个任务，或者在大多数高级场景下，编写一个自定义任务调度程序。

1.  最有效的同步技术是不使用内核对象而是用户模式对象的技术。为了原子地在文件和内存中写入某个值，关键部分是最合适的技术，并且通过 C#语言的`lock`关键字可用。

1.  `Task.Delay` API 是最合适的延迟，因为它在指定的毫秒数后*调度*继续执行的代码，同时让线程在此期间被重用。相反，操作系统的`Sleep` API 在.NET 中暴露为`Thread.Sleep`，它会暂停线程的执行一定的毫秒数，但会使线程无法被重用。

1.  Task 库提供了`WaitHandle.WaitAny`和`WaitHandle.WaitAll`方法，分别在*任何*或*所有*操作完成时立即调用继续执行的代码。可以在返回的任务完成后立即访问任务结果。

1.  `TaskCompletionSource`是一个用于创建和控制`Task`的类。它可以用于将任何异步行为（如 CLR 事件）转换为基于任务的操作。客户端代码可以等待从`TaskCompletionSource`获得的任务，而不是订阅事件。

1.  `Task`库提供了预构建的`Task.CompletedTask`来返回一个空的`Task`，以及`Task.FromResult`、`Task.FromCanceled`和`Task.FromException`方法来创建返回结果、报告取消或抛出异常的任务。

1.  通过在`Task`构造函数中指定`TaskCreationOptions.LongRunning`可以创建长时间运行的任务。

1.  需要使用`Control.Invoke`（或 WPF 中的`Dispatcher.Invoke`）可以通过`Control.InvokeRequired`（或 WPF 中的`Dispatcher.CheckAccess()`）进行验证，并取决于用于访问资源的库是否已经在主线程中调度了结果。如果库已经包含了任务，并且库作者没有调用`Task.ConfigureAwait(false)`，那么可以直接使用结果，因为在`await`关键字之后执行的继续操作是由 UI 框架提供的同步上下文在主线程中调用的。

1.  `ConfigureAwait`方法可用于避免在进程中使用同步上下文时发生的无用调度操作。这通常由 UI 框架和 ASP.NET 应用程序创建。`ConfigureAwait`的主要用户是不需要访问只能从主线程使用的应用程序对象的库开发人员。

1.  首先必须验证异步操作是否在主线程中完成（例如，通过在 Windows Forms 中使用`Control.InvokeRequired`或在 WPF 中使用`Dispatcher.CheckAccess()`）。如果在不同的线程中完成，需要通过`Control.Invoke`或`Dispatcher.Invoke`访问 UI。

# 第十三章

1.  `System.IO`命名空间中与系统对象一起工作的最重要的类是`Path`用于路径，`File`和`FileInfo`用于文件，`Directory`和`DirectoryInfo`用于目录。

1.  连接路径的首选方法是使用`Path.Combine()`静态方法。

1.  可以使用`Path.GetTempPath()`静态方法检索当前用户的临时文件夹的路径。

1.  `File`和`FileInfo`类提供类似的功能，但`File`是一个静态类，`FileInfo`是一个非静态类。同样，`Directory`是一个静态类，`DirectoryInfo`是一个非静态类，尽管它们的功能类似。

1.  要创建目录，可以使用`Create()`和`CreateSubdirectory()`方法。前者在其直接父目录存在时创建目录。后者创建一个子目录，以及必要时一直到根目录的所有其他子目录。要枚举目录，使用`EnumerateDirectories()`方法，它检索一个可枚举的目录集合，在整个集合返回之前可以枚举。有多个重载用于各种搜索选项。

1.  .NET 中流的三个类别是后备存储（表示字节序列的源或目的地的流）、装饰器（从另一个流中读取或写入数据，以某种方式转换它）、适配器（实际上不是流，而是帮助我们以比字节更高级别的方式处理数据源的包装器）。

1.  .NET 中流的基类是`System.IO.Stream`类。这是一个提供从流中读取和写入的方法和属性的抽象类。其中许多是抽象的，并在派生类中实现。

1.  默认情况下，`BinaryReader`和`BinaryWriter`都使用 UTF-8 编码处理字符串。但是，它们都有重载的构造函数，允许使用`System.Text.Encoding`类指定另一个编码。

1.  `System.Xml.Serialization`命名空间中的`XmlSerializer`类可用于序列化和反序列化数据。`XmlSerializer`通过将类型的所有公共属性和字段序列化为 XML 来工作。它使用一些默认设置，例如类型变为节点，属性和字段变为元素。类型、属性或字段的名称成为节点或元素的名称，字段或属性的值成为其文本。

1.  .NET Core 附带的 JSON 序列化器称为`System.Text.Json`。对于.NET Framework 和.NET Standard 项目，它作为 NuGet 包提供，名称相同。您可以使用`JsonSerializer.Serialize()`静态方法来序列化数据，使用`JsonSerializer.Deserialize<T>()`静态方法来反序列化数据。您可以使用特定属性来控制序列化过程。另一方面，如果您想更多地控制写入或读取的内容，可以使用`Utf8JsonWriter`和`Utf8JsonReader`类。

# 第十四章

1.  可能会引发异常的代码必须放在`try`块中。

1.  在`catch`块中，您可能主要想尝试恢复错误。恢复策略可能非常不同，可能从向用户报告友好的错误到使用不同参数重复操作。记录是`catch`块中执行的另一个典型操作。

1.  在`catch`块中指定的异常类型捕获与相同类型或任何派生类型匹配的异常。因此，层次结构中较低的异常必须最后指定。在任何情况下，如果顺序不正确，C#编译器将生成错误。

1.  通过在`catch`语句中指定变量名，您可以访问异常对象。它提供了诸如消息和其他信息的重要信息，在记录错误时非常宝贵。异常对象还可以在创建新的更具体的异常时用作内部异常参数。

1.  在检查异常对象后，您可能会意识到无法对操作进行任何恢复。在这种情况下，更合适的是让异常继续传递给调用者。这可以通过使用无参数的`throw`语句来完成，或者通过在构造函数中传递异常对象来创建并抛出新异常。

1.  `finally`块用于声明一个无论`try`块中指定的代码是失败还是成功都必须执行的代码块。

1.  当您不需要被通知`try`块内部代码的失败时，可以指定一个不带`catch`的`finally`块。`finally`代码将在任何情况下执行。

1.  首次异常代表异常在非常早期阶段的情况，即它们被抛出并在跳转到其处理程序之前。调试器可能会在这些异常处停止，从而更准确地指示潜在的错误。

1.  Visual Studio 调试器允许我们选择我们想要在其中停止的首次异常。这可以通过**异常设置**窗口完成。

1.  在应用程序即将崩溃之前触发`UnhandledException`事件。此事件可用于向用户提供更好的建议，记录错误，甚至自动重新启动应用程序。

# 第十五章

1.  通过启用 C# 8 可空引用类型功能并在代码中装饰引用类型，您将大大减少代码中`NullReferenceException`异常的发生。

1.  访问数组中的最后一项的新简洁语法是`[¹]`，它利用了`System.Index`类型。

1.  在 switch 表达式中，丢弃（`_`）字符等同于`default`，通常用于 switch 语句中。

1.  C# 8 引入了异步处理特性，以在处理资源时提供异步行为。这样，我们可以等待`DisposeAsync`方法的异步关闭操作，避免在`Dispose`中使用`Task.Wait`方法的危险。

1.  空合并赋值`??=`用于在左侧（在我们的示例中为`orders`）不为 null 时避免执行赋值右侧（`GetOrders()`方法）的代码。

1.  为了能够与`async foreach`一起迭代，一个序列必须表现出一种无法使用`IEnumerable`和`IEnumerator`接口及其通用对应项来完成的异步行为。新的`IAsyncEnumerable<T>`和`IAsyncEnumerator<T>`接口专门设计用于支持`async foreach`语句使用的异步行为。

# 第十六章

1.  `global.json`文件用于确定在给定目录树中将使用哪个 SDK。您可以使用`dotnet new globaljson`命令在解决方案根文件夹（或任何父文件夹）中创建此文件，并手动编辑它以匹配`dotnet --info`命令返回的版本之一。

1.  `Path.Combine`方法是在 Windows 和 Linux 上连接路径的最佳方法，两者使用不同的路径分隔符。这种方法也非常方便，可以避免在连接相对路径时出现错误，并且可以避免重复或省略分隔符。

1.  符合.NET Standard 规范的库与支持它的任何框架都是二进制兼容的。当您需要在不同的框架之间共享代码时，请验证它们支持的最新版本的.NET Standard，并创建一个使用它的库。如果您需要使用的 API 不受所需版本的.NET Standard 支持，您可以改变策略，创建单独的库，并将它们打包在一个单独的 NuGet 包中。包清单将需要将每个程序集与库可以运行的特定框架、平台或架构相关联。

1.  由于新的项目文件格式，现在可以从一个项目复制所需的`PackageReference`标签到另一个项目。当解决方案打开时，也可以在 Visual Studio 中执行此操作，并且一旦文件保存，NuGet 包将自动恢复。

1.  在分析了架构影响之后，第一步是将当前解决方案升级到最新版本的.NET Framework，至少是 4.7.2 版本。

1.  为了最小化启动时间，.NET Core 3 提供了两个新的发布选项。第一个是**AOT**编译，它立即生成程序集代码，大大减少了对**JIT**编译器的需求。第二个是启用**Quick JIT**编译器，它在运行时使用，比传统的**JIT**编译器更快，但生成的代码不太优化。

# 第十七章

1.  单元测试是一种软件测试类型，其中测试单个代码单元，以验证它们是否按照设计要求工作。单元测试有助于在开发周期的早期识别和修复错误，因此有助于节省时间和金钱。它有助于开发人员更好地理解代码，并允许他们更容易地进行更改。它通过要求代码更模块化来帮助代码重用。它可以作为项目文档。它还有助于调试，因为当测试失败时，只需要检查和调试最新的更改。

1.  用于单元测试的 Visual Studio 工具包括**Test Explorer**（您可以在其中查看、运行、调试和分析测试）、用于托管代码的 Microsoft 单元测试框架、代码覆盖工具（确定单元测试覆盖的代码量）和 Microsoft Fakes 隔离框架（允许您为类和方法创建替代品）。

1.  Visual Studio 中的**Test Explorer**允许您查看可用的单元测试，按不同级别（项目、类等）分组。您可以从**Test Explorer**运行和调试单元测试，并查看它们的执行结果。

1.  要指定一个类包含单元测试，必须使用`TestClass`属性对其进行修饰。包含单元测试的方法必须使用`TestMethod`属性进行修饰。

1.  用于执行断言的类称为`Assert`，并且位于`Microsoft.VisualStudio.TestTools.UnitTesting`命名空间中。它包含许多静态方法，例如`AreEqual()`、`AreNotEqual()`、`IsTrue()`、`IsFalse()`、`AreSame()`、`AreNotSame()`、`IsNull()`和`IsNotNull()`。

1.  代码覆盖率可以根据**测试资源管理器**或**测试**顶级菜单中的可用单元测试来确定。结果可在**代码覆盖率结果**窗格中查看。

1.  您可以通过提供使用`ClassInitialize`和`ClassCleanup`属性修饰的方法来提供每个类执行一次的固定装置。前者在执行所有测试之前每个类执行一次，后者在执行所有测试之后执行一次。对于在每个单元测试之前和之后执行的固定装置，您必须提供使用`TestInitialize`和`TestCleanup`属性修饰的方法。

1.  数据驱动的单元测试意味着编写从外部源（如文件或数据库）获取测试数据的单元测试。然后，测试方法针对数据源中的每一行执行一次。

1.  `DynamicData`属性允许您指定单元测试类的方法或属性作为数据源。`DataSource`属性允许您指定外部数据源。

1.  Microsoft 单元测试框架支持的数据驱动测试的外部数据源包括 SQL 数据库、CSV 文件、Excel 文档和 XML 文档。
