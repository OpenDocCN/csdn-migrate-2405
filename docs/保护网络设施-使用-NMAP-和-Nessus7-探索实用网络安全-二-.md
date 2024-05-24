# 保护网络设施：使用 NMAP 和 Nessus7 探索实用网络安全（二）

> 原文：[`annas-archive.org/md5/7D3761650F2D50B30F8F36CD4CF5CB9C`](https://annas-archive.org/md5/7D3761650F2D50B30F8F36CD4CF5CB9C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：报告分析和确认

在本章中，我们将涵盖以下内容：

+   理解 Nmap 输出

+   理解 Nessus 输出

+   如何使用 Nmap 和其他工具确认 Nessus 漏洞

# 介绍

在本章中，我们将介绍使用 Nmap 和 Nessus 生成的报告的各种方法。我们还将看一下使用 Nmap 确认 Nessus 报告的漏洞的方法。始终需要确认扫描器报告的漏洞，因为有可能扫描器报告了假阳性漏洞。确认这些漏洞将允许管理团队专注于已确认的漏洞，而不是浪费资源在已报告的假阳性上。Nmap 和 Nessus 生成不同格式的报告，允许用户根据其要求进行选择。

# 理解 Nmap 输出

Nmap 根据它从远程主机接收到的响应来显示结果。扫描的主机越多，打印在屏幕上的结果就越复杂。当主机数量增加时，在终端或命令提示符中打印这些结果变得不可能。为了解决这个问题，Nmap 支持各种报告格式，可以根据用户的要求使用。存储 Nmap 输出的最简单方法之一是使用`>>`运算符，后面跟着一个文本文件名，比如`output.txt`。这将允许 Nmap 将所有内容转发到那个文本文件。即使对于 10 个以上的主机，文本文件的内容也变得难以分析。Nmap 还提供了大量冗长和调试信息，以及端口扫描，这可能会使这个过程变得更加复杂。操作系统的检测和指纹识别为这些数据增加了更多的垃圾。

以下命令用于在 IP 地址`192.168.75.128`上运行 SYN 扫描，并将显示的输出存储到`output.txt`文件中。由于命令提示符在相同的文件夹中运行，因此可以在`C:\Users\admin`文件夹中找到此文件。此外，您可以通过在双引号中提及文件的绝对路径来将此文件存储在任何位置：

```
Nmap –sS –Pn192.168.65.128>> output.txt
```

让我们通过以下截图来看看结果如何被复制到文本文件中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/3a70314e-1c1a-4a40-8cb7-5db9ef5ce80a.png)

导航到 Nmap 安装文件夹并找到`output.txt`文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/da88a502-c8df-4724-8f24-a18522e6bfb7.png)

您可以使用任何文本编辑器打开此文件。我个人推荐 Notepad++，因为它允许您对文本文件进行复杂的分析，并以分隔的方式显示它们：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/5d234020-0813-4438-b954-9d5f231dc44a.png)

Nmap 允许用户使用命令行标志定义输出格式。以下列表解释了 Nmap 允许的不同标志： 

+   **交互式输出**：这是直接显示在终端或命令提示符中的输出类型。这不需要任何特殊的命令提示符参数或标志，因为这是基本的默认输出格式。这个结果不会被存储或保存在任何位置；只有在命令提示符或终端没有关闭的情况下才能访问这个输出。

+   **正常输出**（`-oN`）：这个输出允许用户将交互式输出保存到用户选择的文件中。根据用户选择的冗长级别，这个报告选项进一步削减了交互式输出扫描中不必要的冗长数据。这将允许用户通过省略不需要的数据来更好地查看端口扫描结果。如果用户需要性能数据，比如扫描时间和警报，这不是正确的格式选择。此外，您可以通过提及绝对路径或启动具有相同路径的命令提示符来指定文件夹位置。

+   **XML 输出**（`-oX`）：上传 Nmap 数据到各种工具和网站需要此类型的输出。一旦将此格式上传到任何工具，然后由解析器解析，以便我们可以理解输出中的各种数据类型并相应地对数据进行分离。有许多可用作开源的 XML 解析器，这些解析器是由各种工具 OEM 定制构建的。

+   **Grepable 输出**（`-oG`）：此格式允许用户对生成的输出执行简单的操作，例如`grep`，`awk`，`cut`和`diff`。该格式遵循为每个主机创建单行输出的结构，并带有适当的分隔符，以便用户可以使用操作系统中的简单现有工具来分隔和分析结果。Notepad++实用程序就是这样一个例子，它允许基于分隔符的分隔，可以用于创建更有意义的报告。

+   **Script kiddie**（`-oS`）：此格式以脚本形式打印输出。

+   **以所有格式保存**（`-oA`）：此标志允许用户以前面提到的三种格式（`-oN`，`-oX`和`-oG`）生成输出。用户可以简单地使用此标志一次性获得所有三种报告格式，并将其保存在提供的位置的文件中，而不是执行三次不同的扫描以获得输出格式。

Nmap 还提供了作为扫描结果的一部分的各种其他详细信息，其中一些可以通过可用的详细选项来控制。以下是由详细选项产生的一些额外数据：

+   **扫描完成时间估计**：Nmap 还提供性能数据，例如以分钟为单位的扫描完成时间，这使用户可以了解 Nmap 执行扫描所需的时间。Nmap 会在时间间隔内更新用户有关所花时间和正在执行的任务以及完成百分比的信息。这使用户可以监视更大网络的网络扫描并偶尔改善脚本的执行时间。

+   **开放端口**：在未启用详细信息的正常扫描中，所有开放端口都会显示在扫描结束时。相反，如果启用了详细信息，则每个开放端口在检测到时都会立即显示。

+   **附加警告**：Nmap 还会显示在扫描过程中发生的任何警告或错误，无论端口扫描是否需要额外时间，还是与扫描的正常行为有任何差异。这将允许用户检查任何网络限制并相应地采取行动。

+   **OS 检测信息**：Nmap 中的 OS 检测是使用基于 TCP ISN 和 IP ID 预测的签名检测进行的。如果启用了详细信息，并选择了 OS 检测选项，Nmap 将显示这些 OS 的预测。

+   **主机状态**：Nmap 还会在运行时打印主机的状态，指示主机是活动的还是已关闭的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/e644259a-ed97-4e8c-bbde-944690164a8f.png)

可以与详细信息一起使用的一些选项来控制输出中显示的数据如下：

+   **调试输出**：调试模式是 Nmap 提供的另一个附加标志选项，可帮助用户进一步了解端口扫描过程的数据。可以通过在详细信息语法后附加`-d`来启用此选项。此外，还可以通过在详细信息语法后附加`-d9`来设置要启用的调试级别，范围为 1 至 9。这是最高级别的调试，提供有关正在执行的端口扫描的大量技术数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/40095613-b813-43df-81b0-ac88d46b5078.png)

+   **数据包跟踪**：此选项允许用户获取 Nmap 正在发送的每个数据包的跟踪。这将使用户能够详细了解扫描。可以通过在详细信息语法后附加`--packet-trace`来配置此选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/2d7612e5-ee64-431e-a436-cf8e1792cee2.png)

# 准备就绪

为了完成此活动，您必须满足计算机上的以下先决条件：

1.  您必须安装 Nmap。

1.  您必须对要执行扫描的主机具有网络访问权限。

要安装 Nmap，可以按照第二章中提供的说明进行操作，*了解网络扫描工具*。这将允许您下载兼容版本的 Nmap 并安装所有必需的插件。为了检查您的计算机是否安装了 Nmap，请打开命令提示符并输入`Nmap`。如果 Nmap 已安装，您将看到类似以下的屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/c7b49d51-14eb-4652-80bd-3dd2c34acfcb.png)

如果您没有看到上述屏幕，请将命令提示符控件移动到 Nmap 安装的文件夹（`C:\Program Files\Nmap`）中重试相同步骤。如果这样做后仍然看不到屏幕，请删除并重新安装 Nmap。

为了填充扫描将要执行的主机上的开放端口，您需要对该主机具有网络级访问权限。通过向主机发送 ping 数据包来检查您是否可以访问主机是一种简单的方法。但是，如果在该网络中禁用了 ICMP 和 ping，则此方法仅适用。在禁用 ICMP 的情况下，活动主机检测技术各不相同。我们将在本书的后续部分中详细介绍这一点。

为了获得上述输出，我们需要安装虚拟机。为了运行虚拟机，我建议使用 VMware 的 30 天试用版本，可以从[`www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html`](https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html)下载并安装。

对于测试系统，读者可以从[`information.rapid7.com/download-metasploitable-2017.html`](https://information.rapid7.com/download-metasploitable-2017.html)下载 Metasploitable（Rapid 7 提供的一个易受攻击的虚拟机）。执行以下步骤打开 Metasploitable。这提供了各种组件，如操作系统、数据库和易受攻击的应用程序，这将帮助我们测试本章的配方：

1.  解压下载的 Metasploitable 软件包：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/3386810f-b74e-4cb6-bddb-553bc6cf9265.png)

1.  使用安装的 VMware Workstation 或 VMware Player 打开`.vmx`文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/1e6aa6bb-35a6-4bf4-994f-7ac81c473ac0.png)

1.  使用`msfadmin`/`msfadmin`作为用户名和密码登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/5f5b0990-5c5c-4b7e-b877-fa7234a9334b.png)

# 如何操作…

执行以下步骤：

1.  在命令提示符中打开 Nmap。

1.  在命令提示符中输入以下语法以获取交互式输出：

```
Nmap -sS -Pn 192.168.103.129
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/c768eace-d3cd-4c46-89f9-56f2160a8fec.png)

1.  在命令提示符中输入以下语法以获取正常输出：

```
Nmap -sS -Pn 192.168.103.129 -oN output
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/4b1aeb28-33b2-4591-ae84-c90e6b75f721.png)

您可以导航到`system32`文件夹，找到输出文件并用文本编辑工具打开它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/525cbe28-55c1-4c60-a635-6d337cab2861.png)

1.  在命令提示符中输入以下语法以获取 XML 输出：

```
Nmap -sS -Pn 192.168.103.129 -oX  output
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/0b3bc66a-3613-406d-a08e-2f2abe1e2fc3.png)

您可以导航到`system32`文件夹，找到输出文件并用文本编辑工具打开它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/448f4fb1-c55b-4dda-932a-2a5c7e097cb0.png)

1.  在命令提示符中输入以下语法以获取脚本小子输出：

```
Nmap -sS -Pn 192.168.103.129 -oS  output
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/a6ea532e-8151-4e14-b15c-eb2952e2f9a9.png)

您可以导航到`system32`文件夹，找到输出文件并用文本编辑工具打开它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/92de9919-2d00-4089-b78f-ec0fed19577a.png)

1.  在命令提示符中输入以下语法以获取 grepable 格式的输出：

```
Nmap -sS -Pn 192.168.103.129 -v -oG output
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/77fc0b87-e02c-461a-993a-aef195d25014.png)

您可以导航到`Windows`文件夹，找到输出文件并用文本编辑工具打开它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/54f8693a-27ee-48d1-ac09-359550f61f45.png)

1.  在命令提示符中输入以下语法以获取启用详细信息的所有格式的输出：

```
Nmap -sS -Pn 192.168.103.129 -v-oA  output
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/ad2aa4cf-ee5f-47a4-9779-e373d5794928.png)

您可以导航到`Windows`文件夹，找到输出文件并用文本编辑工具打开它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/11e0bd24-44d9-4942-827c-abba222680ce.png)

# 它是如何工作的...

这些不同的格式帮助用户利用报告进行多种操作，并以不同的方式分析报告。端口扫描结果代表侦察的关键阶段，这使用户可以进一步规划漏洞扫描和检测活动。然后将这些报告上传到不同的工具和站点进行进一步分析和扫描。值得一提的是，Nmap 是各种漏洞扫描软件的后台实用程序。生成这些报告后，这些工具使用它们来执行进一步的操作。

# 了解 Nessus 输出

Nessus 更多地是一个面向企业的工具。报告更全面，用户友好。Nessus 提供基于文档和结构的报告。可以通过在扫描结果页面右上角的“导出”下拉菜单中选择所需的格式来导出这些报告：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/6ec6bfc4-c127-49e1-b0ce-520a3a6d8894.png)

在这里，我们将介绍 Nessus 支持的报告格式。

# Nessus

这种格式允许用户以`.nessus`格式导入结果。这是一种只能使用 Nessus 解析的格式。它允许用户下载扫描结果，然后将其导入 Nessus 进行任何类型的分析。

# HTML

Nessus 提供了一个 HTML 文件格式的扫描报告的良好示例，这是一个独立的文件，可以在任何浏览器中打开以查看结果。该报告还允许在不同部分之间进行导航，以便用户可以轻松阅读大型报告。这些 HTML 报告也可以定制下载以下报告：

+   执行摘要报告：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/2ea39a0e-64eb-4ba3-a1c6-5a50e7e63b4f.png)

+   自定义报告，漏洞和修复措施按主机分组

+   自定义报告，漏洞和修复措施按插件分组

HTML 报告包含以下部分：

+   **目录**：这列出了按主机和建议漏洞的所需导航窗格。这些包含了复杂报告中的进一步细节，如合规审计：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/4182584a-9542-4be6-bec4-0b847d74b05b.png)

+   **按主机的漏洞**：此部分包括按主机的实际漏洞。这遵循报告每个主机的所有漏洞，然后转移到下一个主机的格式。这进一步从每个主机的漏洞数量和风险评级的简单摘要开始。这包括**扫描信息**，如**开始时间**和**结束时间**，以及**主机信息**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/4661874c-07ed-4079-9c40-37e51d1b2df4.png)

每个漏洞包括以下部分，其详细信息已在第五章中描述，*配置审计*：

+   插件 ID

+   简介

+   描述

+   解决方案

+   风险因素

+   参考

+   插件信息和输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/9ba73cb0-1d4f-4829-b41a-0dd13abb6bfc.png)

# CSV

CSV 是一种用于在表格中存储数据的简单格式，稍后可以导入到数据库和诸如 Excel 之类的应用程序中。这允许用户将报告导出为`.csv`文件，可以使用 Excel 等工具打开。以下是一个示例 CSV 报告的截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/0c10d923-52cc-4b8a-bd22-c2d20318cdc6.png)

它包含与 HTML 格式中提到的类似部分。

# Nessus 数据库

这是 Nessus 专有的自定义数据库格式。这是一种加密格式，用于存储扫描的详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/a27da4a1-07bf-4e6f-9cd5-6b7780fb145c.png)

导入 Nessus 时需要创建和使用密码。

# 准备就绪

为了执行此操作，您必须满足计算机上的以下先决条件：

1.  您必须安装 Nessus。

1.  您必须能够访问要执行扫描的主机的网络。

要安装 Nesus，您可以按照第二章中提供的说明。这将允许您下载兼容版本的 Nessus 并安装所有必需的插件。要检查您的计算机是否已安装 Nessus，请打开搜索栏并搜索`Nessus Web 客户端`。一旦找到并点击，它将在默认浏览器窗口中打开：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/296b1bae-d6e6-4ecc-bb14-9f115a61fc06.png)

如果您确定 Nessus 已正确安装，可以直接从浏览器使用`https://localhost:8834` URL 打开 Nessus Web 客户端。如果找不到**Nessus Web 客户端**，您应该删除并重新安装 Nessus。有关删除 Nessus 和安装说明，请参阅第二章，*了解网络扫描工具*。如果找到**Nessus Web 客户端**但无法在浏览器窗口中打开它，则需要检查 Nessus 服务是否在 Windows 服务实用程序中运行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/e16bb391-a138-42bd-96f3-51d9238aec2e.png)

您可以根据需要使用服务实用程序进一步启动和停止 Nessus。为了进一步确认使用命令行界面进行安装，您可以导航到安装目录以查看和访问 Nessus 的命令行实用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/dbeed0a4-3cb3-4d5a-a27f-b6a5369011a9.png)

建议始终具有管理员级别或根级别凭据，以便为扫描仪提供对所有系统文件的访问权限。这将允许扫描仪执行更深入的扫描，并与非凭证扫描相比，生成更好的结果，因为没有适当的权限，系统将无法访问所有文件和文件夹。策略合规模块仅在 Nessus 的付费版本中可用，例如 Nessus 专业版或 Nessus 管理器。为此，您将需要从 tenable 购买激活密钥，并在设置页面中更新，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/90147f33-b14b-44d3-8224-3510ab2325b5.png)

点击编辑按钮打开一个窗口，输入一个新的激活码，你将从 tenable 购买：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/1034f750-69d3-42e0-beb1-4a8e7252fe81.png)

为了测试扫描，我们需要安装一个虚拟机。为了运行虚拟机，我建议使用 VMware 的 30 天试用版，可以从[`www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html`](https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html)下载并安装。

对于测试系统，读者可以参考上一篇文章的*准备就绪*部分下载 Metasploitable。

# 如何做…

执行以下步骤：

1.  打开 Nessus Web 客户端。

1.  使用您在安装过程中创建的用户登录 Nessus 客户端。

1.  对虚拟机执行简单的网络扫描并打开扫描结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/87245a45-d5e8-4f48-9590-1ddd53a82d56.png)

1.  导航到导出功能，并选择 Nessus 格式以下载报告的`.nessus`版本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/adff5c34-2e6e-46ee-be70-55c8fa512397.png)

1.  导航到导出功能，并选择 Nessus 格式以下载报告的 HTML 版本，选择所需的选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/3e53f918-4016-4844-ad6c-47b54201a12a.png)

1.  导航到导出功能，并选择 Nessus 格式以下载报告的 CSV 版本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/f49b7a21-6f82-4808-a6a7-1f8cb89f809b.png)

1.  导航到导出功能，并选择 Nessus 格式以下载报告的 Nessus DB 版本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/02a7a670-0038-44ab-ae4c-447a65b21761.png)

输入所需的密码，然后单击**导出**以下载带有扩展名`.db`的 Nessus DB 文件。

# 它是如何工作的...

Nessus 支持的报告格式允许用户以多种方式呈现报告。如果用户希望以安全的方式存储扫描结果，他们可以使用加密的 DB 格式。如果用户希望直接共享报告，他们可以使用报告的 HTML 格式。对于进一步的分析，他们可以使用 CSV 格式将报告结果导入工具或软件。如果用户需要与其他管理员共享扫描结果，他们可以使用`.nessus`格式，管理员可以将文件导入其自己的 Nessus 并进行进一步分析。

对于 CSV 报告，如果有多个 CSV 报告并且用户需要在 Windows 中合并所有报告，他们可以从包含所有 CSV 文件的文件夹中打开命令提示符，并使用`copy *.csv <新文件名>.csv`命令，从而获得一个合并的 CSV 单个文件。进一步的过滤和去除重复项并排序允许您创建一个线性报告。

# 如何使用 Nmap 和其他工具确认 Nessus 漏洞

Nessus 报告的大多数漏洞都是基于签名和值的，Nessus 根据插件中的代码做出决定。需要使用手动技术（如 Nmap 脚本或特定端口的开源工具）来确认这些漏洞。这将使管理团队能够将精力集中在消除实际漏洞而不是错误阳性上。此外，有时 Nessus 会报告已经应用了解决方法的漏洞，因为 Nessus 只检查插件中提到的条件，无法识别任何其他偏差。在这个食谱中，我们将查看使用 Nmap 和其他开源工具验证 Nessus 报告的多个漏洞的设置。

为了创建这个食谱，我们将在 Metasploitable 2 的易受攻击的虚拟机上执行一个演示基本网络扫描（请查看*准备就绪*部分以下载此内容）。扫描完成后，查看结果将显示共计七个关键、五个高、18 个中等和七个低漏洞。在 Nessus 报告的漏洞中，我们将尝试手动确认以下漏洞：

+   **绑定外壳后门检测**：这是 Nessus 报告的关键风险漏洞。该漏洞指出远程主机上的一个端口允许网络上的任何用户在易受攻击的虚拟机上以 root 权限运行外壳。我们将使用 Windows Telnet 实用程序来确认这个漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/82e11413-d8ca-4787-978e-13de2a841d1d.png)

+   **SSL 版本 2 和 3 协议检测**：这是 Nessus 报告的高风险漏洞。该漏洞涉及使用遗留的 SSL 协议，如 SSL 版本 2 和版本 3，已知会导致多个漏洞。我们将使用 Nmap 脚本来确认这个漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/e4808bc8-293b-4b13-b41c-acbad7d1520e.png)

+   **Apache Tomcat 默认文件**：这是 Nessus 报告的中等风险漏洞。该漏洞提到了安装 Apache 工具时创建的各种默认文件。这些文件仍然可以在网络上供任何用户使用，无需身份验证。我们将使用 Web 浏览器（在这种情况下是 Chrome）来确认这个漏洞。

# 准备就绪

为了创建这个设置，您需要按照前面的食谱“理解 Nmap 输出”和“理解 Nessus 输出”的*准备就绪*部分中提到的所有步骤进行操作。

# 如何做到…

执行以下步骤：

1.  要确认绑定外壳后门检测，打开 Windows 的命令提示符并输入以下命令：

```
telnet 192.168.103.129 1524
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/6bb22868-f00a-41b7-ae86-9a47a3c8497b.png)

1.  执行后，用户直接登录到远程计算机，无需提供任何身份验证：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/fe9dd893-7b9f-4e4b-91d2-6c5bab9ddcea.png)

1.  为了确认用户的权限，我们将使用标准的 Linux 命令`id`来确认漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/fb2a317f-7068-4b5c-a47d-8f64200a416c.png)

这个命令显示 UID 和 GID 都是`0`，代表着一个 root 用户，因此我们可以确认这个漏洞是严重的，因为它允许任何远程用户在没有任何认证的情况下登录到机器上。这意味着这个漏洞是可以确认的。

1.  对于 SSL v2 和 SSL v3，我们可以通过使用 Nmap 的 Poodle 确认脚本来确定正在运行的版本，因为只有 SSL v3 容易受到 Poodle 攻击。在命令提示符中打开 Nmap。

1.  输入以下命令来确定远程服务器是否容易受到 SSL Poodle 攻击：

```
Nmap -sV –script ssl-poodle -p 25 192.168.103.129
```

*![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/3cea245b-5eaf-48af-ba88-86e03210f383.png) *

由于 Nmap 没有显示任何结果，让我们检查一下`ssl-enum-ciphers`脚本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/ddb99f1b-745d-429d-8b82-04b61288fbee.png)

即使`enum-ciphers`脚本也没有返回任何结果，所以我们可以得出结论，Nmap 无法使用 SSL 密码与端口进行协商。因此，我们可以将漏洞标记为误报。如果在端口`25`上使用 Telnet 也收到类似的响应，我们也可以确认相同的情况。这意味着端口`25`正在运行非 SSL 明文协议，并且插件对此报告了误报。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/74571dd0-0cec-4a24-942d-705134f4a20f.png)

1.  要确认 Apache 默认文件，请访问 Nessus 在漏洞输出部分提到的 URL：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/8ea41469-d1a4-4a64-8c31-61eebd51406c.png)

1.  打开浏览器，然后在地址栏中输入`http://192.168.103.129:8180/tomcat-docs/index.html`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/47d46f0b-1571-4202-8fcf-4d4c71395a69.png)

这显示了默认的文档文件夹，确认了服务器上默认文件的存在。这表明这个漏洞是可以确认的。

# 工作原理...

这些漏洞可以根据其风险进行识别，然后确认，从而使分析人员能够将他们的努力优先放在他们试图确认的漏洞上。识别这些误报需要努力，因为你必须实际利用漏洞并检查它是否可行。为了做到这一点，分析人员必须决定他们愿意为了修复漏洞而付出多少努力。例如，如果漏洞是端口`1406`上运行着 SQL 服务对网络中的所有人都是开放的，分析人员就必须决定是只检查开放的端口还是尝试使用默认服务账户或弱密码登录到 SQL 服务。


# 第七章：理解 Nessus 和 Nmap 的自定义和优化

在本章中，我们将涵盖以下内容：

+   理解 Nmap 脚本引擎及其自定义

+   理解 Nessus 审计策略及其自定义

# 介绍

从前几章可以清楚地看出，Nmap 脚本引擎和 Nessus 的合规性审计策略是执行全面审计和检查的重要组成部分。用户非常重要的是要了解这些组件的工作原理以及各种定制技术，以执行特定操作。在本章中，我们将详细了解 Nmap 脚本引擎和 Nessus 审计文件的构成，以创建自定义文件并执行特定操作。

# 理解 Nmap 脚本引擎及其自定义

Nmap 脚本引擎用于运行用户编写的自定义脚本，以自动执行网络级别的操作。通常，Nmap 脚本以`.nse`扩展名结尾。这些脚本用于执行以下任务：

+   **主机和端口发现**：Nmap 被广泛使用的整个目的是执行简单的任务，以检查远程主机是在线还是离线，以及端口的当前状态。

+   **版本检测**：Nmap 具有各种应用程序和服务签名的数据库，这些签名与从端口接收的响应进行检查，以识别端口上运行的服务，有时还包括特定版本。

+   **受影响的漏洞**：Nmap 脚本引擎允许用户确定特定端口/服务是否容易受到特定已披露的漏洞的攻击。它取决于用户编写的脚本，从正在运行的服务中查询数据，并根据响应发送自定义数据包，以确定端口/服务是否实际上容易受到攻击。Nmap 脚本使用 Lua 编程语言，我们将在本文中研究一些语法，以编写自定义脚本。所有 Nmap 脚本分为以下类别：

+   `认证`：这类脚本处理与任何身份验证相关的检查，例如默认用户名和密码登录，匿名和空登录。

+   `广播`：这类脚本用于动态添加新发现的主机，这些主机将由 Nmap 进行扫描，允许用户同时执行完整的网络发现和扫描。

+   `暴力`：这类脚本用于进行暴力破解攻击，猜测各种服务的密码，例如 HTTP、数据库、FTP 等。

+   `默认`：这类脚本与所有未在命令行中指定的特定脚本一起运行。

+   `发现`：这类脚本用于获取有关网络服务及其在网络中的共享资源的更多信息。

+   `dos`：这类脚本可能是 Nmap 脚本中最不受欢迎的。这些脚本用于测试导致**拒绝服务**（DoS）攻击的漏洞，通过使服务崩溃。

+   `利用`：这些脚本用于利用特定漏洞。

+   `外部`：这类脚本使用外部资源来执行给定的任务。例如，对于任何与 DNS 相关的脚本，Nmap 将不得不查询本地 DNS 服务器。

+   `模糊器`：这类脚本用于生成随机有效载荷，以利用特定服务。服务对这些有效载荷的响应可用于确定特定服务是否容易受到攻击。

+   `侵入式`：这类脚本用于直接利用漏洞。这些扫描必须在侦察后的后期阶段使用。

+   `恶意软件`：这类脚本允许用户确定远程主机是否受到任何恶意软件的影响或是否有任何后门打开。

+   `安全`：这类脚本用于获取网络中所有人都可以访问的数据，例如横幅、密钥等。

+   `version`：此类别的脚本用于识别和确定远程主机上运行的服务的版本。

+   `vuln`：此类别的脚本用于验证特定的漏洞。

# 语法

以下是在`nmap`命令中执行脚本所需的参数：

+   `--script <filename>|<category>|<directory>|<expression>`：此参数允许用户指定要执行的脚本，其中文件名、类别、目录和表达式依次跟随以帮助用户选择脚本。为了执行这些脚本，它们需要存在于 Nmap 安装目录的脚本文件夹中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/60a02da9-406e-4cc6-8a64-23a31ab3a179.png)

此处使用的通用语法如下：

```
nmap  --script afp-ls.nse <host>
```

+   `--script-args`：如果需要，这允许用户向`nmap`命令传递输入。此处使用的通用语法如下：

```
nmap  --script afp-ls.nse --script-args <arguments> <host>
```

+   `--script-args-file`：这允许用户将文件输入上传到`nmap`命令。此处使用的通用语法如下：

```
nmap  --script afp-ls.nse --script-args-file <filename/path> <host>
```

+   `--script-help <filename>|<category>|<directory>|<expression>`：此参数允许用户获取有关可用脚本的更多信息。此处使用的通用语法如下：

```
nmap  --script-help <filename>
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/70239522-5a6d-4a63-83b3-46fcf5f2cb66.png)

由于输出量很大，我们将其保存到名为`output.txt`的文件中，保存在`D`驱动器中。在文本编辑器中打开`output`文件以查看帮助消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/ea65fd18-b17f-42cf-9223-231847d7fa0e.png)

+   `--script-trace`：如果使用，此参数将允许用户查看脚本执行的网络通信：

```
nmap  --script afp-ls.nse –script-trace <hostname>
```

+   `--script-updatedb`：用于更新 Nmap 使用的脚本数据库。此处使用的通用语法如下：

```
nmap  --script-updatedb
```

# 环境变量

以下是准备 Nmap 脚本时使用的环境变量：

+   `SCRIPT_PATH`：描述脚本的路径

+   `SCRIPT_NAME`：描述脚本的名称

+   `SCRIPT_TYPE`：此变量用于描述脚本为远程主机调用的规则类型

以下是一个简单 Nmap 脚本的结构：

```
//Rule section
portrule = function(host, port)
    return port.protocol == "tcp"
            and port.number == 25
            and port.state == "open"
end

//Action section
action = function(host, port)
    return "smtp port is open"
end
```

# 脚本模板

Nmap 脚本基本上分为三个部分，这里进行了讨论。我们将使用[`svn.nmap.org/nmap/scripts/smtp-enum-users.nse`](https://svn.nmap.org/nmap/scripts/smtp-enum-users.nse)中的脚本作为示例来定义这些类别中的数据：

+   `Head`**：此部分包含脚本的描述性和依赖性相关数据，以下是各种支持的组件：

+   `description`：此字段充当脚本的元数据，并描述有关脚本功能的重要信息，以便用户使用。它尝试通过发出`VRFY`、`EXPN`或`RCPT TO`命令来枚举 SMTP 服务器上的用户。此脚本的目标是发现远程系统中的所有用户帐户。脚本将输出找到的用户名列表。如果强制进行身份验证，脚本将停止查询 SMTP 服务器。如果在测试目标主机时发生错误，将打印错误以及在错误发生之前找到的任何组合的列表。用户可以指定要使用的方法及其顺序。脚本将忽略重复的方法。如果未指定，脚本将首先使用`RCPT`，然后使用`VRFY`和`EXPN`。如下所示是指定要使用的方法和顺序的示例：

```
description = [[
<code>smtp-enum-users.methods={EXPN,RCPT,VRFY}</code>
]]
```

+   +   `Categories`：此字段允许用户通过提及脚本所属的类别来映射脚本的性质。如前文所述，我们可以使用`smtp-enum-users.nse`脚本中的以下语法来提及类别：

```
categories = {"auth","external","intrusive"}
```

+   +   `author`：此字段允许脚本的作者提供有关自己的信息，如姓名、联系信息、网站、电子邮件等：

```
author = "Duarte Silva <duarte.silva@serializing.me>"
```

+   +   `license`: 此字段用于提及分发脚本所需的任何许可证详细信息，以及标准 Nmap 安装：

```
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
```

+   +   `dependencies`: 该字段定义了脚本的运行级别，这意味着如果任何脚本依赖于其他脚本的输出，可以在此处提及，从而允许依赖脚本首先执行。然后可以将此输出传递给脚本二：

```
dependencies = {"dependant script"}
```

+   +   **脚本库**: Nmap 脚本引擎使用变量允许在类似服务上构建不同的脚本。通过使用库的依赖项，作者可以编写全面且小型的脚本。以下表格解释了一些扫描库：

| Ajp | cassandra |
| --- | --- |
| Amqp | citrixxml |
| asn1 | Comm |
| base32 | Creds |
| base64 | Cvs |
| Bin | Datafiles |
| Bit | Dhcp |
| Bitcoin | dhcp6 |
| Bittorrent | Dns |
| Bjnp | Dnsbl |
| Brute | Dnssd |
| Eigrp | Drda |
| ftp | Eap |

作为参考，我们可以查看[`svn.nmap.org/nmap/scripts/smtp-enum-users.nse`](https://svn.nmap.org/nmap/scripts/smtp-enum-users.nse)上的脚本，以了解库是如何定义的：

```
local nmap = require "nmap"
local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unpwdb = require "unpwdb"
```

这些库中定义了各种函数，我们可以使用以下语法传递参数：`<function name>(arg1, arg2, arg3)`。例如，`smtp.check_reply("MAIL", response)`。

+   `Rules`: 脚本规则用于根据 true 或 false 的布尔结果确定是否要扫描远程主机。只有在规则返回 true 时才会扫描主机。以下是脚本对主机应用的规则：

+   `prerule()`: 该规则在对主机执行扫描之前执行

+   `hostrule(host),portrule(host, port)`: 这些规则在使用提供的脚本扫描每组主机后执行

+   `postrule()`: 该规则在所有主机扫描完成后执行

以下是示例脚本`smtp-enum-users.nse`中使用的规则：

```
portrule = shortport.port_or_service({ 25, 465, 587 },
  { "smtp", "smtps", "submission" })
```

+   `Action`: 该部分包括脚本执行的操作。一旦执行操作，它将根据用户所见的特定结果返回一个特定的结果。以下是示例脚本`smtp-enum-users.nse`的操作部分：

```
action = function(host, port)
  local status, result = go(host, port)
  -- The go function returned true, lets check if it
  -- didn't found any accounts.
  if status and #result == 0 then
    return stdnse.format_output(true, "Couldn't find any accounts")
  end
```

其中一些库要求脚本以特定格式存在，并且必须使用 NSEDoc 格式。我们将在本教程中看到如何将脚本适应这样的格式。在本教程中，我们将看到如何创建一个脚本，以确定远程主机上是否存在默认的 Tomcat 文件。

# 准备工作

要完成此活动，您必须满足计算机上的以下先决条件：

+   您必须安装 Nmap。

+   您必须对要执行扫描的主机具有网络访问权限。

要安装 Nmap，可以按照第二章中提供的说明进行操作，*了解网络扫描工具*。这将允许您下载兼容版本的 Nmap 并安装所有必需的插件。要检查您的计算机是否安装了 Nmap，请打开命令提示符并键入`nmap`。如果安装了 Nmap，您将看到类似以下的屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/58b4bc25-560e-4230-861a-2eda23875c0b.png)

如果您没有看到上述屏幕，请将命令提示符控制移动到 Nmap 安装的文件夹（`C:\Program Files\Nmap`）中，然后重试相同的步骤。如果在此之后仍未看到上述屏幕，请删除并重新安装 Nmap。

为了填充要进行扫描的主机上的开放端口，您需要对该特定主机具有网络级访问权限。通过向主机发送 ping 数据包来检查您是否可以访问特定主机的一种简单方法是通过 ICMP。但是，如果在该网络中禁用了 ICMP 和 ping，则此方法仅在 ICMP 和 ping 启用时才有效。如果禁用了 ICMP，则活动主机检测技术会有所不同。我们将在本书的后面部分更详细地讨论这个问题。

为了获得所示的输出，您需要安装一个虚拟机。为了能够运行虚拟机，我建议使用 VMware 的 30 天试用版本，可以从[`www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html`](https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html)下载并安装。

对于测试系统，读者可以从[`information.rapid7.com/download-metasploitable-2017.html`](https://information.rapid7.com/download-metasploitable-2017.html)下载 Metasploitable（Rapid 7 提供的一个易受攻击的虚拟机）。按照以下步骤打开 Metasploitable。这提供了各种组件，如操作系统、数据库和易受攻击的应用程序，这将帮助我们测试本章的示例。按照以下说明开始：

1.  解压下载的 Metasploitable 软件包

1.  使用安装的 VMware Workstation 或 VMware Player 打开`.vxm`文件

1.  使用`msfadmin`/`msfadmin`作为用户名和密码登录

# 如何做...

执行以下步骤：

1.  打开文本编辑器，并定义三个部分，`Head`，`Rule`和`Action`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/7234afd7-a4be-4868-8191-d8f5d1f5e9b7.png)

1.  让我们从`Head`部分开始。以下是在`Head`部分中需要提到的参数，使用以下代码：

```
-- Head
description = [[Sample script to check whether default apache files are present]]
author = "Jetty"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}
-- Rule
-- Action
```

1.  现在，让我们使用以下代码定义脚本运行所需的库：

```
local shortport = require "shortport"
local http = require "http"
```

为了使脚本编写端口规则，我们需要使用`shortport`和`http`。我们使用`shortport`生成端口规则，使用`http`简化与 HTTP 和 HTTPS 页面的通信。

1.  现在让我们从规则部分开始，引入`shortport`库中包含的`shortport`规则。这允许 Nmap 在端口打开时调用操作：

```
portrule = shortport.http
```

1.  一旦`Head`和`Rule`部分完成，我们所要做的就是定义`action`页面来执行决定性操作，并确定 URI 中提到的位置是否存在默认的 Tomcat 文档。

```
action = function(host, port)
    local uri = "/tomcat-docs/index.html"
    local response = http.get(host, port, uri)
    if ( response.status == 200 ) then
        return response.body
    end
end
```

在操作部分，我们正在定义需要检查默认文件的 URI。我们使用`http.get`函数获取响应，并将其保存在变量 response 中。然后，我们设置了一个 if 条件来检查从服务器接收到的 HTTP 响应是否包含 HTTP 代码 200，这表示页面已成功获取。现在，为了实际查看网页的内容，我们使用`response.body`打印接收到的响应。

1.  现在让我们尝试执行我们写的脚本，以检查它是否工作或需要故障排除。以下是脚本的截图。将其保存到 Nmap 安装目录中的 scripts 文件夹中，名称为`apache-default-files.nse`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/645fc1ae-2ab8-499a-944e-74e5c54e979c.png)

使用以下语法执行脚本：

```
nmap --script apache-default-files 192.168.75.128 -p8180 -v
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/54eb4550-9ad3-4ed7-9534-029d37dd3294.png)

上述截图显示脚本已成功执行，并且检索到的页面是 Apache Tomcat 的默认页面。这意味着主机易受攻击。现在，我们可以将返回变量的值更改为易受攻击，而不是打印如此繁重的输出。

并不总是得出 200 响应意味着远程主机易受攻击的结论，因为响应可能包含自定义错误消息。因此，建议包括基于正则表达式的条件来得出相同的结论，然后相应地返回响应。

1.  让我们进一步装饰脚本的格式，并为其编写脚本文档，通过在`Head`部分添加以下行：

```
---
-- @usage
-- nmap --script apache-default-files` <target>
-- @output
-- PORT   STATE SERVICE
-- |_apache-default-files: Vulnerable
```

脚本现在看起来像这样：

```
-- Head
description = [[Sample script to check whether default apache files are present]]
author = "Jetty"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

---
-- @usage
-- nmap --script apache-default-files` <target>
-- @output
-- PORT   STATE SERVICE
-- |_apache-default-files: Vulnerable

local shortport = require "shortport"
local http = require "http"

-- Rule
portrule = shortport.http

-- Action
action = function(host, port)
    local uri = "/tomcat-docs/index.html"
    local response = http.get(host, port, uri)
    if ( response.status == 200 ) then
        return "vulnerable"
    end
end
```

1.  将脚本保存在 Nmap 安装目录的`scripts`文件夹中，并使用以下语法执行它：

```
nmap --script apache-default-files 192.168.75.128 -p8180 -v
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/a5c16d9e-47f8-46e9-bd01-6c7c3cff4559.png)

# 工作原理...

您可以使用类似的技术通过使用复杂的库和 Lua 语言的多个函数来创建复杂的脚本。可以使用`-A`参数基于端口和可用服务一起执行这些脚本。这将减少用户在提及每个所需脚本方面的工作量。

# 了解 Nessus 审计策略及其自定义

Nessus 审计文件由自定义基于 XML 的规则组成，用于执行各种平台的配置审计。这些文件允许用户执行当前配置的值和基于正则表达式的比较，并确定存在的差距。通常，预期这些审计文件是根据行业标准基线准备的，以便显示实际的合规差距，并且管理团队可以同时进行加固和合规工作。自定义审计文件应保存为扩展名`.audit`。

以下是审计文件中检查的通用语法：

```
<item>
 name                       : " "
 description            :  " "
 info                           : " "
 value                        : " "
</item>
```

我们将查看一些 Windows 的标准检查，以便了解各种通用和自定义检查。所有默认检查都以`<item>`开头，所有自定义检查都以`<custom_item>`开头：

+   **值数据**：审计文件中的关键字可以根据`value_data`标签分配数据。此部分描述了可以在审计文件中定义的不同关键字以及它们可以保存的值。`value_data`的数据类型为 DWORD。`value_data`还可以使用算术符号（如`||`、`&&`等）来提供复杂表达式：

+   `Check_type`：此属性用于比较从远程主机获取的值是否为策略值，并根据配置的属性返回结果。此属性的某些版本如下：

+   `CHECK_EQUAL`

+   `CHECK_EQUAL_ANY`

+   `CHECK_NOT_EQUAL`

+   `CHECK_GREATER_THAN`

+   `CHECK_GREATER_THAN_OR_EQUAL`

+   **信息**：这是一个可选字段，用于添加有关正在执行的检查的信息。其语法如下：

```
info: "Password policy check"
```

+   +   **调试**：此关键字可用于获取用于排除故障的信息。这会生成关于检查执行的逐步数据，允许作者了解错误。

+   **访问控制列表格式**（**ACL**）：此设置部分包含可以保存值以检测所需 ACL 设置是否已应用于文件的关键字。ACL 格式支持六种不同类型的访问列表关键字，如下：

+   文件访问控制检查（`file_acl`）

+   注册表访问控制检查（`registry_acl`）

+   服务访问控制检查（`service_acl`）

+   启动权限控制检查（`launch_acl`）

+   访问权限控制检查（`access_acl`）

前述关键字可用于定义特定用户的文件权限，以下是相关类型。这些权限类别可能对不同的关键字有不同的更改：

+   +   +   `Acl_inheritance`

+   `Acl_apply`

+   `Acl_allow`

+   `Acl_deny`

这些关键字对文件夹有不同的权限集。以下是可以使用`file_acl`的语法：

```
<file_acl: ["name"]>
<user: ["user_name"]>
acl_inheritance: ["value"]
acl_apply: ["value"]
</user>
</acl>
```

可以通过将`file_acl`替换为相应的关键字来使用所有其他关键字的类似语法。

+   **项目**：项目是检查类型，并可用于执行预定义的审计检查。这减少了语法，因为策略是预定义的，并且在此处使用属性进行调用。以下是项目的结构：

```
<item>
name: ["predefined_entry"]
value: [value]
</item>
```

该值可以由用户定义，但名称需要与预定义策略中列出的名称匹配。以下是我们将在此处使用的一些关键字和标记，以创建自定义的 Windows 和 Unix 审计文件。

+   +   `check_type`：每个审计文件都以`check_type`标签开头，其中可以定义操作系统和版本。一旦审计文件完成，需要关闭此标签以标记审计文件的结束：

```
<check_type:"Windows" version:" ">
```

+   +   `name`: `name`属性需要与预定义策略中的名称相同，以便从预定义策略中获取逻辑：

```
name: "max_password_age"
```

+   +   `type`: 类型变量保存了用于特定检查的策略项的名称：

```
type: PASSWORD_POLICY
```

+   +   `description`: 此属性保存了检查的用户定义名称。这可以是任何有助于识别检查中正在进行的操作的内容：

```
description: " Maximum password age"
```

+   +   `info`: 此属性通常用于保存逻辑，以便用户了解检查中执行的操作：

```
info: "Maximum password age of 60 days is being checked."
```

+   +   `Value`: 此属性是 DWORD 类型，包括要与主机上的远程值进行比较的策略值：

```
Value: "8"
```

+   +   `cmd`: 这个属性保存了要在远程系统上执行的命令，以获取正在检查的项目的值：

```
cmd : "cat /etc/login.defs | grep -v ^# | grep PASS_WARN_AGE | awk {'print $2'}"
```

+   +   `regex`: 此属性可用于执行基于正则表达式的远程值比较。然后可以将其与策略值进行比较，以确保检查成功，即使配置存储在不同的格式中：

```
regex: "^[\\s]*PASS_WARN_AGE\\s+"
```

+   +   `expect`: 此策略项包括预期在设备上配置的基线策略值。否则，它用于报告配置中的差距：

```
expect: "14"
```

+   +   `Custom_item`: 自定义审核检查是由用户使用 NASL 定义的，并根据检查中提供的说明由 Nessus 合规性解析器解析的内容。这些自定义项目包括自定义属性和自定义数据值，这将允许用户定义所需的策略值并相应地准备审核文件。

+   +   `value_type`: 此属性包括当前检查允许的不同类型的值：

```
value_type: POLICY_TEXT
```

+   +   `value_data`: 此属性包括可以输入检查的数据类型，例如：

+   `value_data: 0`

+   `value_data: [0..20]`

+   ``value_data: [0..MAX]``

+   +   `Powershell_args`: 此属性包括要传递并在 Windows 系统上执行的`powershell.exe`的参数。

+   +   `Ps_encoded_args`: 此属性用于允许将 PowerShell 参数或文件作为 Base 64 字符串传递给 PowerShell，例如，`powershell_args`：

```
'DQAKACIAMQAwACADFSIGHSAPFIUGHPSAIUFHVPSAIUVHAIPUVAPAUIVHAPIVdAA7AA0ACgA='
ps_encoded_args: YES
```

在这个教程中，我们将创建一个 Windows 审核文件，以检查系统分区中的可用磁盘空间。

# 准备就绪

为了完成这个活动，您需要满足机器上的以下先决条件：

+   您必须安装 Nessus。

+   您必须能够访问要执行扫描的主机的网络。

要安装 Nessus，您可以按照第二章中提供的说明进行操作，*了解网络扫描工具*。这将允许您下载兼容版本的 Nessus 并安装所有必需的插件。要检查您的机器是否安装了 Nessus，请打开搜索栏并搜索`Nessus Web Client`。找到并点击后，它将在默认浏览器窗口中打开：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/5dc7b848-dfca-4316-887a-23e05f3f02a9.png)

如果您确定 Nessus 已正确安装，您可以直接从浏览器使用[`localhost:8834`](https://localhost:8834) URL 打开 Nessus Web Client。如果找不到 Nessus Web Client，则应删除并重新安装 Nessus。有关删除 Nessus 和安装说明，请参阅第二章，*了解网络扫描工具*。如果找到了 Nessus Web Client，但无法在浏览器窗口中打开它，则需要检查 Windows 服务实用程序中是否正在运行 Nessus 服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/f211ae06-4290-4975-a07d-28364f939dbe.png)

您可以根据需要使用**服务**实用程序进一步启动和停止 Nessus。为了进一步确认安装使用命令行界面，您可以导航到安装目录以查看和访问 Nessus 命令行实用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/1608a738-cc85-492b-8c6c-b99bec8f9c8e.png)

建议始终使用管理员级别或根级别凭据，以便为扫描仪提供对所有系统文件的访问权限。这将允许扫描仪执行更深入的扫描，并与非凭证扫描相比提供更好的结果。策略合规模块仅在 Nessus 的付费版本中可用，例如 Nessus 专业版或 Nessus 管理器。为此，您将需要从 Tenable 购买激活密钥，并在**设置**页面中更新它，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/e44b9c48-f69e-4854-908b-39593c054a3a.png)

单击编辑按钮打开窗口，并输入您从 Tenable 购买的新激活码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/9ec08ae1-cd0d-422c-aefb-35e6864c8d4a.png)

# 如何操作…

执行以下步骤：

1.  打开 Notepad++或任何文本编辑器。

1.  为了创建一个自定义项目的 Windows 检查，我们需要用`custom_item`标签开始和结束检查：

```
<custom_item>

</custom_item>
```

1.  现在，我们需要识别所需的元数据属性并定义它们。在这种情况下，我们将使用`description`和`info`：

```
<custom_item>

 description: "Free disk space in system partition#C drive"
 info: "Powershell command will output the free space available on C drive"

</custom_item>
```

1.  现在，我们需要定义我们需要执行的检查类型。Nessus 在 PowerShell 上执行所有 NASL Windows 命令，因此检查的类型将是`AUDIT_POWERSHELL`：

```
<custom_item>

type: AUDIT_POWERSHELL
 description: "Free disk space in system partition#C drive"
 info       : "Powershell command will output the free space available on C drive"

</custom_item>
```

1.  现在，我们需要定义检查支持的值类型和值数据。在这种情况下，我们将选择策略类型，并将`0`设置为`MAX`：

```
<custom_item>

type: AUDIT_POWERSHELL
 description: "Free disk space in system partition#C drive"
 info       : "Powershell command will output the free space available on C drive"
 value_type: POLICY_TEXT
 value_data: "[0..MAX]"

</custom_item>
```

1.  现在，我们需要传递要由 PowerShell 执行的命令以获取`C`驱动器中的可用空间：

```
<custom_item>

 type: AUDIT_POWERSHELL
 description: "Free disk space in system partition#C drive"
 info       : "Powershell command will output the free space available on C drive"
 value_type: POLICY_TEXT
 value_data: "[0..MAX]"
 powershell_args   : 'Get-PSDrive C | Select-Object Free'

</custom_item>
```

1.  由于我们没有将编码命令传递给 PowerShell，因此我们需要使用`ps_encoded_args`属性定义相同的内容：

```
<custom_item>

 type: AUDIT_POWERSHELL
 description: "Free disk space in system partition#C drive"
 info       : "Powershell command will output the free space available on C drive"
 value_type: POLICY_TEXT
 value_data: "[0..MAX]"
 powershell_args   : 'Get-PSDrive C | Select-Object Free'
 ps_encoded_args: NO

</custom_item>
```

1.  由于它不需要任何精炼，命令的输出就足够了，这样我们就知道有多少可用空间，我们还将定义`only_show_cmd_output: YES`属性：

```
<custom_item>

 type: AUDIT_POWERSHELL
 description: "Free disk space in system partition#C drive"
 info       : "Powershell command will output the free space available on C drive"
 value_type: POLICY_TEXT
 value_data: "[0..MAX]"
 powershell_args   : 'Get-PSDrive C | Select-Object Free'
 ps_encoded_args: NO
 only_show_cmd_output: YES

</custom_item>
```

正如我们所看到的，所有审计文件都以`check_type`开头和结尾，我们将前面的代码封装在其中：

```
<check_type:"windows" version:"2">
<custom_item>

 type: AUDIT_POWERSHELL
 description: "Free disk space in system partition#C drive"
 info       : "Powershell command will output the free space available on C drive"
 value_type: POLICY_TEXT
 value_data: "[0..MAX]"
 powershell_args   : 'Get-PSDrive C | Select-Object Free'
 ps_encoded_args: NO
 only_show_cmd_output: YES

</custom_item>
</check_type>
```

1.  将文件保存为扩展名为`.audit`的文件到您的系统上，并使用安装过程中创建的凭据登录 Nessus：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/594ff581-be4b-47af-acd5-1fb956410b23.png)

1.  打开策略选项卡，然后单击使用高级扫描模板创建新策略。填写必要的细节，如策略名称和描述：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/86531ad3-6ac6-476b-a8a8-ea30e3e958c8.png)

1.  导航到**合规**部分，并在筛选合规搜索栏中搜索自定义 Windows：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/057a34b4-2e9a-4737-b857-73a25553f5d2.png)

1.  选择上传自定义 Windows 审计文件选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/f67dd9d9-c8e9-4643-9ef9-95430cc7d5fe.png)

1.  单击添加文件并上传您创建的审计文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/6e672acf-a813-44b6-830a-b47221880031.png)

1.  为了执行合规审计，您将需要输入 Windows 凭据。导航到凭据部分，然后单击 Windows 选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/880a9dcd-36f5-4389-801d-a0743f50a7d4.png)

1.  保存策略并导航到“我的扫描”页面创建新的扫描。

1.  导航到用户定义的策略部分，并选择我们创建的自定义 Windows 审计策略：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/74e2901c-abf7-4207-b995-8713c9e77526.png)

1.  填写必要的细节，如扫描名称和受影响的主机，并启动扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/529d00e4-6624-4283-ae5f-e34607cf1de1.png)

# 工作原理...

这些自定义审计文件可用于审计多个平台，因为 NASL 支持多个平台的关键工作和属性，这些值是自定义的，特定于这些平台的配置。这使用户可以轻松创建审计文件并根据其要求和基线自定义它们，以执行配置审计并识别这些差距。以下是 Nessus 支持执行配置审计的平台列表：

+   Windows:

+   Windows 2003 Server

+   Windows 2008 Server

+   Windows Vista

+   Windows 7

+   Unix:

+   Solaris

+   Linux

+   FreeBSD/OpenBSD/NetBSD

+   HP/UX

+   AIX

+   macOS X

+   其他平台：

+   思科

+   SCADA


# 第八章：物联网、SCADA/ICS 的网络扫描

在本章中，我们将介绍以下内容：

+   SCADA/ICS 简介

+   使用 Nmap 扫描 SCADA/ICS

+   使用 Nessus 扫描 SCADA/ICS 系统

# SCADA/ICS 简介

用于管理和执行各种工业操作的自动化技术，如线路管理控制和操作控制，属于运营技术的一部分：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/e3913d61-6a60-4811-9f78-1a954cf3f935.jpg)

工业控制系统（ICS）涵盖了运营技术领域的一个很大部分，用于监控和控制各种操作，如自动化生产，硬件系统的控制和监控，通过控制水位和核设施的流量来调节温度。大多数 ICS 的使用都是在非常关键的系统中，这些系统需要始终可用。

用于 ICS 的硬件有两种类型，即可编程逻辑控制器（PLC）或离散过程控制系统（DPC），这些系统又由监控和数据采集（SCADA）系统管理。SCADA 通过提供基于界面的控制，而不是用户手动输入每个命令，使得管理 ICS 系统变得容易。这使得这些系统的管理变得强大且简单，从而实现了非常高的可用性：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/b15571b5-980d-44d4-aee4-78094a62e801.jpg)

主要组件如下：

+   SCADA 显示单元基本上是一个为管理员提供交互界面的组件，用于查看、验证和修改要传递给 ICS 系统的各种命令。这使用户可以远程控制 ICS 系统，而无需实际在现场。例如，远程管理员可以使用 Web 门户管理建筑物中所有恒温器的配置。

+   控制单元充当 SCADA 显示单元和远程终端单元之间的桥梁。控制单元始终需要将来自远程终端单元的数据实时发送到 SCADA 显示单元。这是为了通知管理员任何故障，以便查看和修复以确保系统的高可用性。

+   远程终端单元（RTU）可以是可编程逻辑控制器（PLC）（一种制造业标准计算机，用于处理和执行指令），它连接多个设备到 SCADA 网络，使它们能够从远距离监控和管理。RT、控制单元和 SCADA 显示单元之间的连接不需要是有线网络，也可以是无线网络。

保护这些 SCADA 系统非常重要，因为简单的配置错误可能导致实际工业制造环境中的灾难。有许多开源工具可用于此目的。Nmap 就是这样一种工具，它允许用户为 SCADA/ICS 系统端口扫描编写自定义脚本。此外，分析人员可以使用 Metasploit 模块来利用 SCADA/ICS 环境中的这些漏洞。

以下是一些可以用于识别和利用 SCADA/ICS 系统问题的 Metasploit 模块：

| 供应商 | 系统/组件 | Metasploit 模块 |
| --- | --- | --- |
| 7-Technologies | IGSS | `exploit/windows/scada/igss9_igssdataserver_listall.rb` |
|  |  | `exploit/windows/scada/igss9_igssdataserver_rename.rb` |
|  |  | `exploit/windows/scada/igss9_misc.rb` |
|  |  | `auxiliary/admin/scada/igss_exec_17.rb` |
| AzeoTech | DAQ Factory | `exploit/windows/scada/daq_factory_bof.rb` |
| 3S | CoDeSys | `exploit/windows/scada/codesys_web_server.rb` |
| BACnet | OPC Client | `exploit/windows/fileformat/bacnet_csv.rb` |
|  | 操作工作站 | `exploit/windows/browser/teechart_pro.rb` |
| Beckhoff | TwinCat | `auxiliary/dos/scada/beckhoff_twincat.rb` |
| 通用电气 | D20 PLC | `辅助/收集/d20pass.rb` |
|  |  | `不稳定模块/辅助/d20tftpbd.rb` |
| Iconics | Genesis32 | `利用/Windows/SCADA/iconics_genbroker.rb` |
|  |  | `利用/Windows/SCADA/iconics_webhmi_setactivexguid.rb` |
| Measuresoft | ScadaPro | `利用/Windows/SCADA/scadapro_cmdexe.rb` |
| Moxa | 设备管理器 | `利用/Windows/SCADA/moxa_mdmtool.rb` |
| RealFlex | RealWin SCADA | `利用/Windows/SCADA/realwin.rb` |
|  |  | `利用/Windows/SCADA/realwin_scpc_initialize.rb` |
|  |  | `利用/Windows/SCADA/realwin_scpc_initialize_rf.rb` |
|  |  | `利用/Windows/SCADA/realwin_scpc_txtevent.rb` |
|  |  | `利用/Windows/SCADA/realwin_on_fc_binfile_a.rb` |
|  |  | `利用/Windows/SCADA/realwin_on_fcs_login.rb` |
| Scadatec | Procyon | `利用/Windows/SCADA/procyon_core_server.rb` |
| 施耐德电气 | CitectSCADA | `利用/Windows/SCADA/citect_scada_odbc.rb` |
| SielcoSistemi | Winlog | `利用/Windows/SCADA/winlog_runtime.rb` |
| 西门子 Technomatix | FactoryLink | `利用/Windows/SCADA/factorylink_cssservice.rb` |
|  |  | `利用/Windows/SCADA/factorylink_vrn_09.rb` |
| Unitronics | OPC 服务器 | `利用/利用/Windows/浏览器/teechart_pro.rb` |

还有许多开源工具可以执行这些操作。其中一个工具是 PLCScan。

PLCScan 是一个用于识别 PLC 设备的实用程序，使用端口扫描方法。它识别先前记录的各种 SCADA/PLC 设备的特定端口接收到的数据包。它使用一组后端脚本来执行这些操作。

使用自动化脚本扫描控制系统可能是一项繁琐的任务，因为它们很容易崩溃。大多数 SCADA/ICS 系统都是传统系统，使用传统软件，不太适合更换，并且没有足够的硬件来进行自动化。这导致了许多漏洞。

# 使用 Nmap 扫描 SCADA/ICS

Nmap 提供多个脚本，其功能还允许用户创建多个自定义脚本来识别网络中存在的 SCADA 系统。这使分析人员能够创建特定的测试用例来测试 SCADA 系统。最新的 Nmap 脚本库中默认提供的一些脚本如下：

+   `s7-info.nse`：用于枚举西门子 S7 PLC 设备并收集系统名称、版本、模块和类型等信息。此脚本的工作方式类似于 PLCScan 实用程序。

+   `modbus-discover.nse`：枚举 SCADA Modbus **从机 ID**（**sids**）并收集从机 ID 号和从机 ID 数据等信息。Modbus 是各种 PLC 和 SCADA 系统使用的协议。

我们将在接下来的示例中看到这些脚本的语法和用法。

# 准备就绪

为了完成这项活动，您必须满足计算机上的以下先决条件：

1.  您必须安装 Nmap。

1.  您必须能够访问要执行扫描的主机的网络。

为了安装 Nmap，您可以按照第二章中提供的说明进行操作，*了解网络扫描工具*。这将允许您下载兼容版本的 Nmap 并安装所有必需的插件。为了检查您的计算机是否安装了 Nmap，请打开命令提示符并输入`Nmap`。如果 Nmap 已安装，您将看到类似以下的屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/95eda7ea-df62-4f79-aa2b-6ada58156fec.png)

如果您没有看到上述屏幕，请尝试将命令提示符控制移动到 Nmap 安装的文件夹中（`C:\Program Files\Nmap`）重试相同步骤。如果这样做后仍然没有看到屏幕，请删除并重新安装 Nmap。

为了对要扫描的主机上的开放端口进行填充，您需要对该特定主机具有网络级别的访问权限。通过向主机发送 ping 数据包来检查您是否可以访问特定主机是一种简单的方法。但是，如果在该网络中禁用了 ICMP 和 ping，则此方法将无效。在禁用 ICMP 的情况下，活动主机检测技术也会有所不同。我们将在本书的后续部分详细讨论这一点。

此外，为了创建一个测试环境，在 Kali 操作系统上安装 Conpot，这是一个著名的蜜罐，按照提供的说明进行：[`github.com/mushorg/conpot`](https://github.com/mushorg/conpot)。

安装 Conpot 后，使用以下命令在系统上运行 Conpot：

```
sudoconpot --template default
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/e98561b0-1d57-4419-b2eb-9cdeb995a1bb.png)

# 如何做…

执行以下步骤：

1.  在命令提示符中打开 Nmap。

1.  在命令提示符中输入以下语法以获取`scripts7-info.nse`脚本的扫描结果：

```
Nmap --script s7-info.nse -p 102 192.168.75.133
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/238ea376-de5b-4ac4-bb3b-62ea604348f7.png)

您可以观察到扫描器已经检测到系统是`西门子，SIMATIC，S7-200`设备。

1.  在命令提示符中输入以下语法以获取`modbu-discover.nse`脚本的扫描结果：

```
Nmap --script modbus-discover.nse --script-args='modbus-discover.aggressive=true' -p 502 192.168.75.133
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/9d2ccc78-9a9b-4504-81bc-680a65e5d0dc.png)

此模块还发现设备是`西门子，SIMATIC，S7-200`。

# 工作原理...

这些 Nmap 脚本允许用户识别 SCADA 系统正在使用的特定端口。例如，如前面的示例所示，端口`102`和`502`是可以用来确定网络中是否有任何 SIMATIC 设备的特定端口。分析人员可以扫描整个网络以查找端口`102`和`502`，一旦找到，他们可以执行服务扫描以检查其中是否有任何相关的 SCADA 软件在运行。

# 还有更多...

在任何给定的情况下，如果 Nmap 中的默认脚本没有完成工作，那么用户可以从 GitHub 或其他资源下载其他开发人员开发的自定义 Nmap 脚本，并将它们粘贴到 Nmap 安装文件夹的脚本文件夹中以使用它们。例如，从链接[`github.com/jpalanco/Nmap-scada`](https://github.com/jpalanco/nmap-scada)克隆文件夹，以便在脚本文件夹中粘贴多个其他 SCADA 系统，以便您可以使用 Nmap 运行它们：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/e0c8f2a8-c05b-4b06-9d32-6b3b94710cfc.png)

# 使用 Nessus 扫描 SCADA/ICS 系统

Nessus 有一个插件系列-大约有 308 页-可以用来对 SCADA/ICS 设备进行扫描。您可以在这里浏览插件系列：[`www.tenable.com/plugins/nessus/families/SCADA`](https://www.tenable.com/plugins/nessus/families/SCADA)。这些插件会根据插件中的签名检查给定设备，以识别任何已经确定的漏洞。

# 准备工作

为了完成这个活动，您必须满足机器上的以下先决条件：

1.  您必须安装 Nessus。

1.  您必须能够访问要执行扫描的主机。

要安装 Nessus，您可以按照第二章中提供的说明进行操作，*了解网络扫描工具*。这将允许您下载兼容版本的 Nessus 并安装所有必需的插件。为了检查您的机器是否安装了 Nessus，打开搜索栏并搜索`Nessus Web Client`。一旦找到并点击，它将在默认浏览器窗口中打开：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/bae6fe25-723e-4f72-817b-e6f49ea3a5f6.png)

如果您确定 Nessus 已正确安装，可以直接从浏览器使用`https://localhost:8834` URL 打开 Nessus Web 客户端。如果找不到**Nessus Web 客户端**，应删除并重新安装 Nessus。有关删除 Nessus 和安装说明，请参阅第二章，*了解网络扫描工具*。如果找到了 Nessus Web 客户端，但无法在浏览器窗口中打开它，则需要检查 Nessus 服务是否在 Windows 服务实用程序中运行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/9693a50a-c0ff-4fcf-a05e-9750a552b8b7.png)

此外，您可以根据需要使用服务实用程序启动和停止 Nessus。为了进一步确认此安装是否使用命令行界面，您可以导航到安装目录以查看和访问 Nessus 的命令行实用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/68a960bb-a1da-4406-b8a8-382c0c0a1d19.png)

建议始终具有管理员级别或根级别凭据，以便为扫描仪提供对所有系统文件的访问权限。这将使扫描仪能够执行更深入的扫描，并生成比非凭证扫描更好的结果。策略合规模块仅在 Nessus 的付费版本（如 Nessus 专业版或 Nessus 管理器）中可用。为此，您将需要从 tenable 购买激活密钥，并在设置页面中更新它，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/cf26a27c-ff9e-486b-9b93-3973287c1d30.png)

单击编辑按钮打开窗口，并输入您从 tenable 购买的新激活码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/fa42788e-4a0d-4397-a904-fa3135baf8a1.png)

此外，您可以安装 Conpot，如前面的食谱中所述。此食谱还需要安装 Kali Linux 操作系统。您可以从[`www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html`](https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html)下载虚拟机，从[`www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/`](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/)下载 Kali Linux。

# 如何做..

执行以下步骤：

1.  打开 Nessus Web 客户端。

1.  使用您在安装期间创建的用户登录到 Nessus 客户端。

1.  点击**策略**选项卡，然后选择**创建新策略**。然后，选择**基本网络扫描**模板：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/5fbf2c37-64c2-4808-893b-3f167cb2cc79.png)

通过在**发现**选项卡中更改端口扫描的设置，指定范围为`1-1000`。这将允许扫描仪快速完成扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/6ac3380f-85d6-44e4-854a-fb0a593050bc.png)

1.  确保在**评估**的**常规**设置类别的准确性选项卡中未选择执行彻底测试：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/1eb01e0e-f7be-43da-b52c-c9b99d3eeed5.png)

这将确保 PLC 或您正在执行扫描的任何其他设备不会受到由于产生的流量而产生的任何影响。您还可以设置高级设置，以确保生成的流量最小：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/7a720c6e-7c68-4fb6-a31a-ab35603da82c.png)

1.  确保**插件**选项卡中存在 SCADA 插件，否则获得的结果将仅适用于非 SCADA 端口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/1c4a4315-f76f-4be6-bbbc-9f38773ada58.png)

1.  保存策略，并从`我的扫描`文件夹中选择**新扫描**。转到**用户定义**策略部分，并选择策略：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/c3d76b19-9c29-487e-b071-75ba03fba3c2.png)

1.  选择策略并填写所需的详细信息。然后，启动扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/aa49ec49-43aa-4766-8280-9f9f0dd37c65.png)

1.  等待扫描完成并打开结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/d714fcbd-dce6-4c8d-9902-d8a15e748b41.png)

上述结果表明扫描成功，并且 Nessus 发现了两个与 SCADA 相关的漏洞：

+   ICCP/COTP（ISO 8073）协议检测：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/b98ec24b-2204-4e05-8bb8-121d26722571.png)

+   Modbus/TCP 线圈访问：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/92e4e5c7-307e-469e-b7a5-8810c47921c6.png)

# 工作原理...

这些扫描结果将允许用户进行进一步分析，以检查系统中已知的漏洞。从中，用户可以向管理员建议所需的补丁。必须始终确保所有 SCADA 连接都是加密的端到端，否则仅限于执行点对点连接。

# 还有更多...

可以使用 Metasploit 模块执行类似的检查。打开我们在虚拟机中安装的 Kali Linux，并在终端中输入以下命令：

```
msfconsole
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/017f3def-86d3-4aa4-8261-d7ee6ab0481e.png)

这用于打开 Metasploit 控制台。还有一个名为 Armitage 的 Metasploit 的 GUI 版本可用。要查找适用于 SCADA 的各种 Metasploit 模块，请输入以下命令：

```
searchscada
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/26d4d87a-00af-4d18-9abd-77f61335422c.png)

如前面的屏幕截图所示，Metasploit 支持的 SCADA 的各种模块已加载。让我们尝试对 Modbus 进行特定搜索，看看支持哪些模块：

```
searchmodbus
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/9a3859da-12ca-4a15-a1c5-92f86f763ddd.png)

从前面的屏幕截图中，您可以使用`modbusdetect`来识别端口`502`上是否运行 Modbus，使用以下语法：

```
use auxiliary/scanner/scada/modbusdetect
```

通过使用`show options`填写所需的详细信息来识别相同的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/0ead76e5-177e-4af2-9109-f3603c01aae3.png)

使用以下命令将 RHOSTS 设置为`192.168.75.133`并运行 exploit：

```
set RHOSTS 192.168.75.133
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/78d54dad-e59c-4cdb-932a-4a6795f3ad8e.png)

前面的屏幕截图显示模块已经检测到端口`502`上存在 Modbus。


# 第九章：漏洞管理治理

今天的技术环境正在以极快的速度发生变化。几乎每天都会有一些新技术的引入并在短时间内获得流行。尽管大多数组织确实适应了快速变化的技术，但他们往往没有意识到新技术的使用会改变组织的威胁环境。虽然组织的现有技术环境可能已经存在漏洞，但引入新技术可能会在技术环境中增加更多的 IT 安全风险。

为了有效地减轻所有风险，重要的是在整个组织中实施强大的*漏洞管理计划*。本章将介绍一些基本的治理概念，这些概念将有助于为实施漏洞管理计划奠定坚实的基础。本章的关键学习要点如下：

+   安全基础知识

+   了解安全评估的需求

+   列出漏洞管理的业务驱动因素

+   计算投资回报率

+   建立上下文

+   制定和推出漏洞管理政策和程序

+   渗透测试标准

+   行业标准

# 安全基础知识

安全是一个主观的问题，设计安全控制通常是具有挑战性的。一个特定的资产可能需要更多的保护来保持数据的机密性，而另一个资产可能需要确保最高的完整性。在设计安全控制时，同样重要的是在控制的有效性和最终用户的使用便利性之间取得平衡。本节在进一步介绍更复杂的概念之前，介绍了一些基本的安全基础知识。

# CIA 三角

**机密性**、**完整性**和**可用性**（通常称为**CIA**）是信息安全的三个关键原则。虽然有许多因素有助于确定系统的安全状况，但机密性、完整性和可用性是其中最突出的。从信息安全的角度来看，任何给定的资产都可以根据其机密性、完整性和可用性的价值进行分类。本节在概念上强调了 CIA 的重要性，并提供了实际示例和针对每个因素的常见攻击。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/4049cecd-bc54-494b-9819-70c00b2f5276.png)

# 机密性

单词*机密性*的词典含义是：保持秘密或私人的状态。在信息安全的背景下，机密性意味着保持信息免受未经授权的访问，这是信息安全的主要需求之一。以下是一些我们经常希望保持机密的信息的例子：

+   密码

+   个人识别号码

+   信用卡号、到期日期和 CVV

+   商业计划和蓝图

+   财务信息

+   社会安全号码

+   健康记录

机密性的常见攻击包括：

+   **数据包嗅探**：这涉及拦截网络数据包，以非法获取网络中流动的信息

+   **密码攻击**：包括猜测密码、使用暴力或字典攻击破解密码等

+   **端口扫描和 ping 扫描**：端口扫描和 ping 扫描用于识别给定网络中的活动主机，然后对活动主机进行一些基本的指纹识别

+   **垃圾箱搜寻**：这涉及搜索和挖掘目标组织的垃圾箱，试图可能获得敏感信息

+   **肩窥**：这是一个简单的行为，任何站在你身后的人都可能偷看你输入的密码

+   **社会工程**：社会工程是操纵人类行为以提取敏感信息的行为

+   网络钓鱼和网络诱骗：这涉及向受害者发送虚假和欺骗性的电子邮件，冒充身份，并欺骗受害者提供敏感信息。

+   窃听：这类似于数据包嗅探，但更多地与电话对话的监视有关。

+   键盘记录：这涉及在受害者的系统上安装一个秘密程序，记录并发送受害者输入的所有按键。

# 完整性

信息安全背景下的完整性是指信息的质量，意味着一旦生成的信息不应该被任何未经授权的实体篡改。例如，如果一个人使用在线银行向他的朋友发送*X*金额的钱，他的朋友在他的账户中确切地收到*X*金额，那么交易的完整性就是完整的。如果交易在中间被篡改，朋友收到*X + (n)*或*X - (n)*金额，那么交易的完整性就被认为在交易过程中被篡改了。

对完整性的常见攻击包括：

+   莎莉米攻击：当单一攻击被分割或分解为多个小攻击，以避免被检测，这被称为莎莉米攻击。

+   数据篡改攻击：这涉及在数据输入到系统之前或期间未经授权地修改数据。

+   信任关系攻击：攻击者利用实体之间的信任关系获得未经授权的访问。

+   中间人攻击：攻击者连接到通信渠道，拦截流量，并篡改数据。

+   会话劫持：使用中间人攻击，攻击者可以劫持已经建立的合法活动会话。

# 可用性

可用性原则规定，如果授权个人请求资源或信息，它应该在没有任何中断的情况下可用。例如，一个人想要使用在线银行设施下载他的银行账单。由于某种原因，银行的网站关闭了，这个人无法访问。在这种情况下，可用性受到影响，因为这个人无法在银行的网站上进行交易。从信息安全的角度来看，可用性和保密性以及完整性一样重要。出于任何原因，如果请求的数据在规定时间内不可用，可能会造成严重的有形或无形的影响。

对可用性的常见攻击包括以下内容：

+   拒绝服务攻击：在拒绝服务攻击中，攻击者向目标系统发送大量请求。请求的数量如此之大，以至于目标系统无法响应。这导致目标系统的失败，并且来自所有其他合法用户的请求都被拒绝。

+   SYN 洪水攻击：这是一种拒绝服务攻击的一种类型，攻击者向目标发送大量的 SYN 请求，目的是使其无响应。

+   分布式拒绝服务攻击：这与拒绝服务攻击非常相似，不同之处在于用于攻击的系统数量。在这种类型的攻击中，攻击者使用数百甚至数千个系统来淹没目标系统。

+   电力攻击：这种类型的攻击涉及对电力单元的故意修改，目的是造成停电并使目标系统崩溃。

+   服务器房环境攻击：服务器房间是温度控制的。任何故意干扰服务器房间环境的行为都可能导致关键服务器系统崩溃。

+   自然灾害和事故：这包括地震、火山喷发、洪水等，或任何意外的人为错误。

# 识别

认证通常被认为是与系统交互的第一步。然而，认证之前是识别。主体可以通过识别的过程来声明身份，从而启动问责制。为了启动**认证、授权和问责制**（**AAA**）的过程，主体必须向系统提供一个身份。输入密码、刷 RFID 门禁卡或留下指纹印记是提供个人身份的最常见和简单的方式之一。在没有身份的情况下，系统无法将认证因素与主体相关联。在确定主体的身份之后，随后执行的所有操作都将针对主体进行记录，包括信息系统跟踪基于身份的活动，而不是个人。计算机无法区分人类。然而，计算机可以很好地区分用户帐户。它清楚地知道一个用户帐户与所有其他用户帐户不同。然而，仅仅声称一个身份并不暗示访问或权限。主体必须首先证明其身份才能获得对受控资源的访问。这个过程被称为识别。

# 认证

验证和测试所声称的身份是否正确和有效被称为**认证过程**。为了进行认证，主体必须提供与之前建立的身份完全相同的附加信息。密码是用于认证的最常见类型的机制之一。

以下是通常用于认证的一些因素：

+   **你所知道的东西**：*你所知道的*因素是用于认证的最常见因素。例如，密码或简单的**个人识别号码**（**PIN**）。然而，它也是最容易被破坏的。

+   **你所拥有的东西**：*你所拥有的*因素指的是智能卡或物理安全令牌等物品。

+   **你所是的东西**：*你所是的*因素指的是使用你的生物特征进行认证的过程。例如，使用指纹或视网膜扫描进行认证。

识别和认证总是作为一个单一的两步过程一起使用。

提供身份是第一步，提供认证因素是第二步。没有这两者，主体无法获得对系统的访问。单独的元素在安全方面都是没有用的。

对认证的常见攻击包括：

+   暴力破解：暴力破解攻击涉及尝试特定字符集的所有可能的排列和组合，以获取正确的密码

+   **认证不足：**使用弱密码策略的单因素认证使应用程序和系统容易受到密码攻击

+   **弱密码恢复验证**：这包括对密码恢复机制（如安全问题、OTP 等）的不充分验证

# 授权

一旦主体成功认证，下一个逻辑步骤是获得对分配资源的授权访问。

成功授权后，经过认证的身份可以请求访问对象，前提是它具有必要的权限和特权。

访问控制矩阵是用于评估和比较主体、对象和预期活动的最常见技术之一。如果主体被授权，那么特定的操作是允许的，如果主体未经授权，则被拒绝。

需要注意的是，被识别和认证的主体不一定被授予访问任何东西的权利和特权。访问权限是基于主体的角色和需要知道的基础上授予的。识别和认证是访问控制的全有或全无方面。

以下表格显示了一个样本访问控制矩阵：

| | **资源** |
| --- | --- |
| **用户** | **文件 1** | **文件 2** |
| 用户 1 | 读取 | 写入 |
| 用户 2 | - | 读取 |
| 用户 3 | 写入 | 写入 |

从前面的样本访问控制矩阵中，我们可以得出以下结论：

+   用户 1 无法修改文件 1

+   用户 2 只能读取文件 2，而不能读取文件 1

+   用户 3 可以读取/写入文件 1 和文件 2

对授权的常见攻击包括以下内容：

+   **授权蔓延**：授权蔓延是一个术语，用来描述用户故意或无意地获得了比实际需要更多的权限

+   **水平特权升级**：当用户能够绕过授权控制并获得与同级别用户相同的特权时，就发生了水平特权升级

+   **垂直特权升级**：当用户能够绕过授权控制并获得更高层次用户的特权时，就发生了垂直特权升级

# 审计

审计或监视是指跟踪和/或记录主体在系统上进行身份验证后的行为的过程。审计还可以帮助监视和检测系统上的未经授权或异常活动。审计包括捕获和保留主体及其对象的活动和/或事件，以及记录维护操作环境和安全机制的核心系统功能的活动和/或事件。

审计日志中需要捕获的最小事件如下：

+   用户 ID

+   用户名

+   时间戳

+   事件类型（如调试、访问、安全）

+   事件详情

+   源标识符（如 IP 地址）

捕获系统事件并创建日志的审计跟踪可以用于评估系统的健康和性能。在系统故障的情况下，可以使用事件日志追溯根本原因。日志文件还可以为重新创建事件的历史、追溯入侵或系统故障提供审计跟踪。大多数操作系统、应用程序和服务都具有某种本地或默认的审计功能，至少可以提供最基本的事件。

对审计的常见攻击包括以下内容：

+   **篡改日志**：包括未经授权修改审计日志

+   **未经授权访问日志**：攻击者可以未经授权访问日志，意图提取敏感信息

+   **通过审计日志进行拒绝服务**：攻击者可以发送大量垃圾请求，意图填满日志，进而填满磁盘空间，导致拒绝服务攻击

# 会计

只有在责任制得到良好维护时，任何组织才能成功实施其安全策略。保持责任制可以帮助追究主体的所有行为。任何给定的系统可以根据其追踪和证明主体身份的能力来说是有效的。

各种机制，如审计、认证、授权和识别，有助于将人类与他们执行的活动联系起来。

仅使用密码作为身份验证的形式会产生很大的疑虑和妥协空间。有许多轻松的方法可以破解密码，这就是为什么它们被认为是最不安全的身份验证形式。当多种身份验证因素（如密码、智能卡和指纹扫描）结合使用时，身份盗窃或妥协的可能性会大大降低。

# 不可否认

不可否认是指主体无法否认活动或事件发生的保证。不可否认可以防止主体声称未发送消息、未执行操作或未导致事件的发生。

可以帮助实现不可否认性的各种控制如下：

+   数字证书

+   会话标识符

+   交易日志

例如，一个人可以向他的同事发送一封威胁性的电子邮件，然后简单地否认他发送了这封电子邮件的事实。这是一种否认的情况。然而，如果电子邮件被数字签名，这个人就不会有机会否认他的行为。

# 漏洞

非常简单地说，漏洞只是系统中的一个弱点或保障/对策中的一个弱点。如果漏洞被成功利用，可能会导致目标资产的损失或损害。一些常见的漏洞示例如下：

+   系统上设置弱密码

+   在系统上运行的未打补丁的应用程序

+   缺乏输入验证导致 XSS

+   缺乏数据库验证导致 SQL 注入

+   未更新的防病毒签名

漏洞可能存在于硬件和软件层。感染恶意软件的 BIOS 是硬件漏洞的一个例子，而 SQL 注入是最常见的软件漏洞之一。

# 威胁

任何可能导致不良结果的活动或事件都可以被视为威胁。威胁是任何可能故意或无意地造成损害、中断或完全丧失资产的行为。

威胁的严重程度可以根据其影响来确定。威胁可以是有意的，也可以是意外的（由于人为错误）。它可以由人、组织、硬件、软件或自然引起。一些常见的威胁事件如下：

+   病毒爆发的可能性

+   电力浪涌或故障

+   火灾

+   地震

+   洪水

+   关键财务交易中的打字错误

# 暴露

威胁代理可能会利用漏洞并造成资产损失。容易受到这种资产损失的影响被称为**暴露**。

暴露并不总是意味着威胁确实发生。这只是意味着如果给定系统存在漏洞，威胁可能会利用它，那么可能会发生潜在的暴露。

# 风险

风险是威胁利用漏洞对资产造成伤害的可能性或可能性。

风险可以用以下公式计算：

*风险=可能性*影响*

通过这个公式，很明显风险可以通过减少威胁代理或减少漏洞来降低。

当风险实现时，威胁代理或威胁事件利用了漏洞并对一个或多个资产造成了伤害或泄露。安全的整个目的是通过消除漏洞和阻止威胁代理和威胁事件暴露资产来防止风险的实现。不可能使任何系统完全没有风险。然而，通过制定对策，可以将风险降低到组织风险承受能力的可接受水平。

# 保障

*保障*或*对策*是减轻或减少漏洞的任何事物。保障是减轻或消除风险的唯一手段。重要的是要记住，保障、安全控制或对策可能并不总是涉及采购新产品；有效利用现有资源也可以帮助产生保障。

以下是一些保障的例子：

+   在所有系统上安装防病毒软件

+   安装网络防火墙

+   安装闭路电视并监控场所

+   部署安全警卫

+   安装温度控制系统和火灾警报

# 攻击向量

攻击向量只是攻击者可以访问目标系统的路径或手段。为了破坏系统，可能存在多个攻击向量。以下是一些攻击向量的例子：

+   攻击者通过利用应用程序中的 SQL 注入漏洞，获取了数据库中的敏感数据

+   攻击者通过获得对数据库系统的物理访问来获取对敏感数据的访问

+   攻击者利用 SMB 漏洞在目标系统上部署了恶意软件

+   攻击者通过对系统凭证进行暴力攻击获得了管理员级别的访问权限

总结我们所学的术语，我们可以说资产受到威胁，这些威胁利用漏洞导致暴露，这是一种可以通过保障来减轻的风险。

# 了解安全评估的需求

许多组织在设计和实施各种安全控制方面投入了大量时间和成本。一些甚至遵循“深度防御”的原则部署了多层次的控制。实施强大的安全控制当然是必要的；然而，测试部署的控制是否确实按预期工作同样重要。

例如，一个组织可能选择部署最新和最好的防火墙来保护其边界。防火墙管理员某种方式错误配置了规则。所以，无论防火墙有多好，如果它没有正确配置，仍然会允许不良流量进入。在这种情况下，对防火墙规则进行彻底测试和/或审查将有助于识别和消除不需要的规则，并保留所需的规则。

每当开发新系统时，都会严格和彻底地进行质量保证（QA）测试。这是为了确保新开发的系统按照业务需求和规格正确运行。与此同时，测试安全控制也是至关重要的，以确保它们按规定运行。安全测试可以是不同类型的，如下一节所讨论的。

# 安全测试的类型

根据上下文和服务目的，安全测试可以按多种方式进行分类。以下图表显示了安全测试类型的高级分类：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/0d740afc-08c0-45c3-ba3e-3879c2be2e1e.png)

# 安全测试

安全测试的主要目标是确保控制正常运行。测试可以是自动扫描、使用工具进行渗透测试和手动尝试揭示安全漏洞的组合。需要注意的是，安全测试不是一次性活动，应定期进行。在规划安全控制测试时，应考虑以下因素：

+   可用于安全测试的资源（硬件、软件和熟练的人力）

+   受控系统和应用程序的重要性评级

+   实施控制的机制出现技术故障的概率

+   控制配置错误可能危及安全的概率

+   可能影响控制性能的技术环境中的任何其他变化、升级或修改

+   测试控制所需的难度和时间

+   测试对正常业务运营的影响

只有确定了这些因素，才能设计和验证全面的评估和测试策略。该策略可能包括定期的自动化测试和手动测试。例如，电子商务平台可能每周进行自动漏洞扫描，并在扫描检测到新漏洞时立即向管理员发送警报通知。自动扫描一旦配置和触发，就需要管理员的干预，因此可以经常进行扫描。

安全团队可能选择通过内部或外部顾问进行固定费用的手动渗透测试来补充自动扫描。安全测试可以每季度、每半年或每年进行，以优化成本和工作量。

不幸的是，许多安全测试计划都是简单地将新的高级工具指向网络中可用的系统，从而以杂乱无章和临时的方式开始的。测试计划应该经过深思熟虑的设计，并使用基于风险的方法对系统进行严格的例行测试。

当然，安全测试的结果没有经过仔细审查就不能被称为完整。工具可能会产生很多误报，只有通过手动审查才能消除。对安全测试报告的手动审查还有助于确定漏洞的严重程度，与目标环境的相关性。

例如，自动扫描工具可能会检测到公开托管的电子商务应用程序和简单的内部帮助和支持门户网站中的跨站脚本。在这种情况下，尽管漏洞在两个应用程序中是相同的，但前者的风险更大，因为它面向互联网，用户比后者更多。

# 漏洞评估与渗透测试

漏洞评估和渗透测试经常可以互换使用。然而，它们在服务目的上是不同的。为了理解这两个术语之间的区别，让我们考虑一个现实世界的例子。

有一家银行位于城市郊区的一处相当隐蔽的地方。有一伙强盗打算抢劫这家银行。强盗开始计划如何执行他们的计划。其中一些人装扮成普通顾客访问银行，并注意到了一些事情：

+   银行只有一名手无寸铁的保安

+   银行有两个入口和三个出口

+   没有安装闭路电视摄像头

+   储物柜隔间的门看起来很薄弱

有了这些发现，强盗只是进行了漏洞评估。现在，只有当他们真正抢劫银行时，才能确定这些漏洞是否能够在现实中被利用来成功执行抢劫计划。如果他们抢劫银行并成功利用了这些漏洞，他们就会进行渗透测试。

因此，简而言之，检查系统是否容易受攻击是漏洞评估，而实际利用易受攻击的系统是渗透测试。组织可以根据需要选择执行其中一个或两者。然而，值得注意的是，如果没有首先进行全面的漏洞评估，渗透测试就不可能成功。

# 安全评估

安全评估只是对系统、应用程序或其他测试环境的安全性进行详细审查。在安全评估期间，受过训练的专业人员进行风险评估，发现目标环境中可能存在的潜在漏洞，可能导致妥协，并根据需要提出建议。

安全评估通常包括使用测试工具，但超出了自动扫描和手动渗透测试。它们还包括对周围威胁环境的全面审查，现在和未来可能的风险，以及目标环境的资产价值。

安全评估的主要输出通常是一份详细的评估报告，面向组织的高层管理人员，以非技术性语言包含评估结果。它通常以精确的建议和改进目标环境安全状况的建议结束。

# 安全审计

安全审计通常采用与安全评估相似的许多技术，但需要由独立的审计员执行。组织的内部安全人员进行例行安全测试和评估。然而，安全审计与这种方法不同。安全评估和测试是组织内部的，旨在发现潜在的安全漏洞。

审计类似于评估，但是旨在向相关第三方证明安全控制的有效性。审计确保在测试控制有效性时没有利益冲突。因此，审计倾向于提供对安全状况的完全公正的观点。

安全评估报告和审计报告可能看起来相似；然而，它们是为不同的受众而设计的。审计报告的受众主要包括高级管理人员、董事会、政府机构和其他相关利益相关者。

审计分为两种主要类型：

+   **内部审计**：组织的内部审计团队执行内部审计。内部审计报告面向组织的内部受众。确保内部审计团队具有完全独立的报告线，以避免与他们评估的业务流程产生利益冲突。

+   **外部审计**：由信任的外部审计公司进行外部审计。外部审计具有更高的外部有效性，因为外部审计师几乎与被评估的组织没有任何利益冲突。有许多公司进行外部审计，但大多数人认为所谓的*四大*审计公司具有最高的可信度：

+   安永

+   德勤

+   普华永道

+   毕马威

这些公司进行的审计通常被大多数投资者和监管机构认可。

# 漏洞管理的业务驱动因素

为了证明实施任何控制的投资是绝对必要的，业务驱动因素是绝对必要的。业务驱动因素定义了为什么需要实施特定的控制。用于证明漏洞管理计划的典型业务驱动因素在以下部分中进行了描述。

# 监管合规性

十多年来，几乎所有企业都变得高度依赖技术的使用。从金融机构到医疗机构，对数字系统的使用有了很大的依赖。这反过来促使行业监管机构提出了组织需要遵守的强制性要求。不遵守监管机构规定的任何要求都会受到严重罚款和禁令。

以下是一些要求组织进行漏洞评估的监管标准：

+   **萨班斯-奥克斯法案**（**SOX**）

+   **对承诺审计准则的声明 16**（**SSAE 16/SOC 1**）

+   **服务组织控制**（**SOC**）2/3

+   **支付卡行业数据安全标准**（**PCI DSS**）

+   **健康保险可移植性和责任法案**（**HIPAA**）

+   **格拉姆-利奇-布莱利合规性**（**GLBA**）

+   **联邦信息系统控制审计手册**（**FISCAM**）

# 满足客户需求

今天的客户在选择从技术服务提供商那里获得什么样的服务时变得更加挑剔。某个客户可能在世界的某个地方运营，而某些法规要求进行漏洞评估。技术服务提供商可能位于另一个地理区域，但必须执行漏洞评估以确保所服务的客户符合规定。因此，客户可以明确要求技术服务提供商进行漏洞评估。

# 对某些欺诈/事件的回应

全球各地的组织不断受到来自不同地点的各种类型的攻击。其中一些攻击成功并对组织造成潜在损害。基于内部和/或外部欺诈/攻击的历史经验，组织可能选择实施完整的漏洞管理计划。

例如，像火一样蔓延的 WannaCry 勒索软件利用了 Windows 系统的 SMB 协议中的一个漏洞。这种攻击必定会触发许多受影响组织实施漏洞管理计划。

# 获得竞争优势

让我们考虑这样一个情景，有两个技术供应商在销售类似的电子商务平台。一个供应商拥有非常强大和有文档记录的漏洞管理计划，使他们的产品天然具有抵御常见攻击的能力。第二个供应商的产品非常好，但没有漏洞管理计划。一个明智的客户肯定会选择第一个供应商的产品，因为该产品是根据强大的漏洞管理流程开发的。

# 保护关键基础设施

这是所有先前业务驱动因素中最重要的一个。一个组织可能会主动选择实施漏洞管理计划，无论是否必须遵守任何法规或满足任何客户需求。在安全方面，主动方法比被动方法更有效。

例如，一个组织可能拥有客户的付款细节和个人信息，并且不希望将这些数据置于未经授权的披露风险之中。一个正式的漏洞管理计划将帮助组织识别所有可能的风险，并制定控制措施以减轻风险。

# 计算投资回报率

设计和实施安全控制通常被视为成本开销。向管理层证明实施某些安全控制的成本和努力往往是具有挑战性的。这时可以考虑估算漏洞管理计划的投资回报。这可能是相当主观的，并且基于定性和定量分析。

虽然投资回报率的计算可能会因环境的复杂性而变得复杂，但让我们从一个简单的公式和例子开始：

*投资回报率（ROI）=（投资收益 - 投资成本）* 100/投资成本*

为了简化理解，让我们假设组织内有 10 个系统需要纳入漏洞管理计划的监管范围。所有这 10 个系统都包含敏感的业务数据，如果它们受到攻击，组织可能会遭受 75,000 美元的损失以及声誉损失。现在，组织可以通过利用价值 25,000 美元的资源来设计、实施和监控漏洞管理计划。因此，投资回报率将如下：

*投资回报率（ROI）=（75,000 - 25,000）* 100/25,000 = 200%*

在这种情况下，实施漏洞管理计划的投资回报率为 200%，这确实是对高级管理层批准的一个很好的理由。

前面的例子是一个简化的例子，旨在理解投资回报率的概念。然而，在实际情况下，组织在计算漏洞管理计划的投资回报率时可能需要考虑更多因素，包括：

+   该计划的范围是什么？

+   需要多少资源（人员数量）来设计、实施和监控该计划？

+   作为该计划的一部分是否需要采购任何商业工具？

+   在计划的任何阶段是否需要任何外部资源（合同资源）？

+   将整个计划完全外包给可信赖的第三方供应商是否可行且具有成本效益？

# 设定背景

变化从来都不容易和顺利。组织内的任何变化通常需要广泛的规划、范围界定、预算和一系列批准。在没有先前安全经验的组织中实施完整的漏洞管理计划可能非常具有挑战性。许多业务部门都会明显抵制，并对该计划的可持续性提出质疑。除非漏洞管理计划深入融入组织文化，否则它永远不会成功。与任何其他重大变化一样，可以通过以下部分描述的两种不同方法来实现这一点。

# 自下而上

自下而上的方法是基层员工发起行动来实施新的倡议。在漏洞管理计划的背景下，自下而上的方法中的行动流程看起来类似于以下内容：

1.  系统管理员团队的初级成员在其中一个系统中识别出一些漏洞

1.  他向主管报告，并使用免费工具扫描其他系统以查找类似的漏洞

1.  他整合了所有发现的漏洞并向主管报告

1.  然后主管向高层管理层报告漏洞

1.  高层管理忙于其他活动，因此未能优先考虑漏洞修复

1.  系统管理员团队的主管试图在有限的资源帮助下修复一些漏洞

1.  一组系统仍然存在漏洞，因为没有人对修复它们感兴趣

在前述情景中，我们可以注意到所有的活动都是不经过计划和临时的。初级团队成员在没有得到高层管理的多少支持的情况下自发进行了漏洞评估。这种方法在长期内永远不会成功。

# 自上而下

与自下而上的方法不同，自上而下的方法效果更好，因为它是由高层管理发起、指导和管理的。使用自上而下的方法实施漏洞管理计划，行动流程将如下所示：

1.  高层管理决定实施漏洞管理计划

1.  管理层计算投资回报率并检查可行性

1.  然后管理层准备了漏洞管理计划的政策程序指南和标准

1.  管理层为计划的实施和监控分配预算和资源

1.  中层管理和基层员工随后遵循政策和程序来实施该计划

1.  该计划受到监控，并且指标与高层管理共享

如前述情景中所述的自上而下方法实施漏洞管理计划具有更高的成功概率，因为它是由高层管理发起和推动的。

# 政策与程序与标准与指南

从治理的角度来看，了解政策、程序、标准和指南之间的区别是很重要的。请注意以下图表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/651aeb91-8e85-488e-ac0e-074075567c84.png)

+   **政策**：政策始终是其他文件中的最高级别。政策是一种反映高层管理意图和方向的高层声明。一旦发布，组织内的每个人都必须遵守政策。政策的例子包括互联网使用政策、电子邮件政策等。

+   **标准**：标准只是一种可接受的质量水平。标准可以用作实施政策的参考文件。标准的一个例子是 ISO27001。

+   **程序**：程序是一系列详细的步骤，用于完成特定任务。通常以**标准操作程序**（**SOP**）的形式实施或参考。程序的一个例子是用户访问控制程序。

+   **指南**：指南包含额外的建议或建议，不是强制性遵循的。它们是最佳实践，根据情况可能或可能不遵循。指南的一个例子是 Windows 安全加固指南。

# 漏洞评估政策模板

以下是一个漏洞评估政策模板的示例，概述了政策层面的漏洞评估的各个方面：

**<公司名称>**漏洞评估政策

|  | 名称 | 标题 |
| --- | --- | --- |
| 创建者 |  |  |
| 审查者 |  |  |
| 批准者 |  |  |

**概述**

本节是对漏洞管理的高层次概述。

漏洞评估是识别和量化给定环境中的安全漏洞的过程。它是信息安全状况的评估，指出潜在的弱点，并在必要时提供适当的缓解程序，以消除这些弱点或将其降低到可接受的风险水平。

通常，漏洞评估遵循以下步骤：

1.  在系统中创建资产和资源清单

1.  为资源分配可量化的价值和重要性

1.  识别每个已识别资源的安全漏洞或潜在威胁

1.  优先处理并消除最重要资源的最严重漏洞

**目的**

本节是说明撰写政策的目的和意图。

本政策的目的是提供一种标准化的方法来进行安全审查。该政策还确定了在漏洞识别闭环过程中的角色和责任。

**范围**

本节定义了政策适用的范围；它可以包括内部网、外部网，或者组织基础设施的一部分。

漏洞评估可以针对**<公司名称>**内的任何资产、产品或服务进行。

**政策**

**团队**在**指定**的权威下负责漏洞评估流程的开发、实施和执行。

**公司名称**网络内的所有网络资产将全面接受定期或持续的漏洞评估扫描。

将使用集中式漏洞评估系统。使用任何其他工具来扫描或验证漏洞必须经**指定**书面批准。

**公司名称**内的所有人员和业务单位都应配合对其拥有的系统进行的任何漏洞评估。

**公司名称**内的所有人员和业务单位也应配合**团队**开发和实施补救计划。

**指定**可能指示与第三方安全公司合作，对**公司**的关键资产进行漏洞评估。

**漏洞评估流程**

本节提供了一个指向详细说明漏洞评估流程的外部程序文档的指针。

有关更多信息，请参阅漏洞评估流程。

**例外**

很可能，出于一些合理的理由，一些系统需要排除在本政策范围之外。本节说明了获取此政策例外的流程。

对于本政策的任何例外，例如免除漏洞评估流程，必须通过安全例外流程获得批准。有关更多详细信息，请参阅安全例外政策。

**执行**

本节旨在强调违反此政策的影响。

任何**公司名称**的员工如果违反了该政策，可能会受到纪律处分，包括解雇和潜在的法律诉讼。

**相关文件**

本节用于提供组织内任何其他相关政策、程序或指南的参考。

以下文件被该政策引用：

+   漏洞评估程序

+   安全例外政策

**修订历史**

| **日期** | **修订号** | **修订详细信息** | **修订者** |
| --- | --- | --- | --- |
| MM/DD/YYYY | Rev #1 | 变更描述 | <姓名/职称> |
| MM/DD/YYYY | Rev #2 | 变更描述 | <姓名/职称> |

本节包含有关谁创建了该政策、时间戳和修订的详细信息。

**词汇表**

本节包含了政策中使用的所有关键术语的定义。

# 渗透测试标准

渗透测试不仅仅是一个单一的活动，而是一个完整的过程。有几个标准可以指导渗透测试过程中应遵循的步骤。本节旨在介绍渗透测试生命周期以及一些业界公认的渗透测试标准。

# 渗透测试生命周期

渗透测试不仅仅是使用随机工具来扫描目标漏洞，而是一个涉及多个阶段的注重细节的过程。以下图表显示了渗透测试生命周期的各个阶段：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/bb719597-0de8-434c-8cf2-3cf4c91ceca9.png)

1.  **信息收集阶段**：信息收集阶段是渗透测试生命周期中的第一个和最重要的阶段。在我们可以探索目标系统的漏洞之前，收集有关目标系统的信息至关重要。收集的信息越多，成功渗透的可能性就越大。如果不正确地了解目标系统，就不可能精确地针对漏洞。信息收集可以分为两种类型：

+   **被动信息收集**：在被动信息收集中，不与目标直接接触。例如，可以从公开可用的来源（如搜索引擎）获取有关目标的信息。因此，不会与目标直接接触。

+   **主动信息收集**：在主动信息收集中，会与目标直接接触以探测信息。例如，对网络中的活动主机进行 ping 扫描实际上会向每个目标主机发送数据包。

1.  **枚举**：一旦获得有关目标的基本信息，下一个阶段就是为了获取更多详细信息而进行枚举。例如，在信息收集阶段，我们可能会有网络中活动 IP 的列表。现在我们需要枚举所有这些活动 IP，并可能获得以下信息：

+   目标 IP 上运行的操作系统

+   每个目标 IP 上运行的服务

+   发现的服务的确切版本

+   用户帐户

+   文件共享等

1.  **获取访问权限**：一旦信息收集和枚举工作彻底完成，我们将对目标系统/网络有一个详细的蓝图。基于这个蓝图，我们现在可以计划发动各种攻击来破坏并获取对目标系统的访问权限。

1.  特权升级：我们可能会利用目标系统中的特定漏洞并获得对其的访问权限。然而，很可能访问权限受到限制。我们可能希望获得完整的管理员/根级别访问权限。可以采用各种特权升级技术来将访问权限从普通用户提升到管理员/根用户。

1.  **维持访问**：到目前为止，我们可能已经获得了对目标系统的高特权访问。然而，该访问可能只持续一段时间，只在特定期间。如果我们想要获得对目标系统相同的访问权限，我们不希望再次重复所有的努力。因此，使用各种技术，我们可以使我们对受损系统的访问持久化。

1.  **覆盖踪迹**：在完成和记录所有渗透之后，我们可能希望清除痕迹和痕迹，包括在妥协中使用的工具和后门。根据渗透测试协议，可能需要或不需要进行此阶段。

# 行业标准

在实施安全控制时，我们可以利用几个定义明确且经过验证的行业标准。这些标准和框架提供了一个基线，可以根据组织的特定需求进行定制。以下部分讨论了一些行业标准。

# 开放式 Web 应用程序安全项目测试指南

OWASP 是“开放式 Web 应用程序安全项目”的缩写。这是一个社区项目，经常从意识的角度发布前 10 个应用程序风险。该项目建立了一个坚实的基础，以在 SDLC 的所有阶段整合安全性。

OWASP 前 10 项目通过评估顶级攻击向量和安全弱点以及它们与技术和业务影响的关系，从根本上评估应用程序安全风险。OWASP 还提供了有关如何识别、验证和纠正应用程序中每个漏洞的具体说明。

尽管 OWASP 前 10 项目只关注常见的应用程序漏洞，但它确实为开发人员和审计人员提供了额外的指南，以有效管理 Web 应用程序的安全性。这些指南可以在以下位置找到：

+   **最新测试指南**：[`www.owasp.org/index.php/OWASP_Testing_Guide_v4_Table_of_Contents`](https://www.owasp.org/index.php/OWASP_Testing_Guide_v4_Table_of_Contents)

+   **开发人员指南**：[www.owasp.org/index.php/Guide](http://www.owasp.org/index.php/Guide)

+   **安全代码审查指南**：[www.owasp.org/index.php/Category:OWASP_Code_Review_Project](https://www.owasp.org/index.php/Category:OWASP_Code_Review_Project)

OWASP 前 10 名列表定期进行修订。最新的前 10 名列表可以在以下网址找到：[`www.owasp.org/index.php/Top_10_2017-Top_10`](https://www.owasp.org/index.php/Top_10_2017-Top_10)。

# 框架的好处

以下是 OWASP 的主要特点和好处：

+   当应用程序针对 OWASP 前 10 名进行测试时，可以确保满足最低的安全要求，并且应用程序对大多数常见的 Web 攻击具有抵抗力。

+   OWASP 社区开发了许多安全工具和实用程序，用于执行自动化和手动应用程序测试。一些最有用的工具包括 WebScarab、Wapiti、CSRF Tester、JBroFuzz 和 SQLiX。

+   OWASP 制定了一个测试指南，提供了技术或供应商特定的测试指南；例如，对 Oracle 的测试方法与对 MySQL 的方法不同。这有助于测试人员/审计人员选择最适合的测试目标系统的程序。

+   它有助于在开发的所有阶段设计和实施安全控制，确保最终产品本质上是安全和强大的。

+   OWASP 在整个行业范围内具有可见性和接受度。OWASP 前 10 名也可以与其他 Web 应用程序安全行业标准进行映射。

# 渗透测试执行标准

渗透测试执行标准（PTES）是由渗透测试行业中最聪明的头脑和权威专家创建的。它包括渗透测试的七个阶段，并可用于对任何环境进行有效的渗透测试。有关方法的详细信息可以在以下网址找到：[`www.pentest-standard.org/index.php/Main_Page.`](http://www.pentest-standard.org/index.php/Main_Page.)

此标准详细说明的渗透测试的七个阶段如下（来源：[www.pentest-standard.org](http://www.pentest-standard.org/index.php/Main_Page)）：

1.  前期交互

1.  情报收集

1.  威胁建模

1.  漏洞分析

1.  利用

1.  后期利用

1.  报告

这些阶段的每一个都在 PTES 网站上提供了详细说明，以及详细说明每个阶段所需的具体思维导图。这允许将 PTES 标准定制以匹配正在测试的环境的测试要求。只需点击思维导图中的项目，即可访问有关每个步骤的更多详细信息。

# 框架的好处

以下是 PTES 的主要特点和好处：

+   这是一个非常全面的渗透测试框架，涵盖了渗透测试的技术和操作方面，如范围扩大、报告和保护渗透测试人员的利益和权利

+   它详细说明了执行许多必要任务的方法，以准确测试环境的安全状况

+   它是由经验丰富的渗透测试专家为渗透测试人员准备的，这些专家每天都在执行这些任务

+   它包括最常见的技术以及不太常见的技术

+   它易于理解，并且可以轻松适应安全测试需求

# 摘要

在本章中，我们熟悉了一些绝对的安全基础知识，以及构建漏洞管理程序的一些基本治理概念。在下一章中，我们将学习如何设置一个进行漏洞评估的环境。

# 练习

+   探索如何计算安全控制的投资回报率

+   熟悉 PTES 标准
