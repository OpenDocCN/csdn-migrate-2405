# Ansible 快速启动指南（一）

> 原文：[`zh.annas-archive.org/md5/5ed89b17596e56ef11e7d3cab54e2924`](https://zh.annas-archive.org/md5/5ed89b17596e56ef11e7d3cab54e2924)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

这是一本面向初学系统管理员的 Ansible 指南。它旨在适当地介绍 Ansible 作为自动化和配置管理工具。本书的读者在结束时应该能够通过从真实样本代码中学习每个模块的功能来掌握 Ansible playbook 和模块的基本用法，以帮助实现基础设施和任务的自动化和编排。本书还包含一些额外的高级技巧，供那些希望走得更远并与 Ansible 社区合作的人学习。

# 这本书是为谁准备的

这本书适用于三个主要受众。首先是与 Linux、Windows 或 Mac OS X 打交道的系统管理员。这包括那些在裸机、虚拟基础设施或基于云的环境上工作的人。然后是网络管理员，那些在分布式专有网络设备上工作的人。最后是 DevOps。本书可以帮助他们充分了解他们将部署应用程序的系统的行为，使他们能够相应地编码或建议可以使他们的应用程序受益的修改。

# 本书涵盖的内容

第一章，*什么是 Ansible?*，是对 Ansible 的介绍，并将其与其他配置管理工具进行了比较。

第二章，*Ansible 设置和配置*，解释了如何在多个系统上设置和配置 Ansible。

第三章，*Ansible 清单和 playbook*，是对 Ansible 清单和 playbook 的介绍和概述。

第四章，*Ansible 模块*，涵盖了 Ansible 最常用的模块，并提供了真实样本使用代码。

第五章，*Ansible 自动化基础设施*，列举了 Ansible 在多个基础设施中的用例。

第六章，*用于配置管理的 Ansible 编码*，包含了编写 Ansible playbook 的最佳实践。

第七章，*Ansible Galaxy 和社区角色*，是对 Ansible 社区角色、用法和贡献的介绍。

第八章，*Ansible 高级功能*，是对 Ansible 的一些高级功能的概述，例如 Vault、插件和容器。

# 充分利用本书

在阅读本书之前，您应该对 Linux shell 有基本的了解，并具备一些系统管理技能，以便能够跟随实际示例。此外，一些基本的编码技能在处理 YAML playbooks 时将非常有用。作为可选要求，具备一些基本的配置管理知识将有助于简化本书中的许多要点。

为了能够运行大部分代码，我们建议在至少两台 Linux 机器、一台 Windows 机器和一台 Mac OS X 上运行虚拟环境。对于网络设备测试，您可能需要一个测试网络设备或一些虚拟网络设备。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便将文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择 SUPPORT 选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本的软件解压或提取文件夹：

+   Windows 系统使用 WinRAR/7-Zip

+   Mac 系统使用 Zipeg/iZip/UnRarX

+   Linux 系统使用 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Ansible-Quick-Start-Guide`](https://github.com/PacktPublishing/Ansible-Quick-Start-Guide)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还有来自我们丰富的书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781789532937_ColorImages.pdf.`](https://www.packtpub.com/sites/default/files/downloads/9781789532937_ColorImages.pdf)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。以下是一个例子：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```
$link = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
$script = "$env:temp\ConfigureRemotingForAnsible.ps1"

(New-Object -TypeName System.Net.WebClient).DownloadFile($link, $script)
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
$link = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
$script = "$env:temp\ConfigureRemotingForAnsible.ps1"

(New-Object -TypeName System.Net.WebClient).DownloadFile($link, $script)
```

任何命令行输入或输出都以以下方式编写：

```
sudo apt install -y expect
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单中的单词或对话框中的单词会以这种形式出现在文本中。以下是一个例子：“从管理面板中选择系统信息。”

警告或重要提示会出现在这样的形式中。提示和技巧会以这种形式出现。


# 第一章：什么是 Ansible？

工业革命之后，引入了自动化，使已经高效的机械更加高效。这导致了工业建筑、车辆转向和稳定以及室内环境控制等许多其他发展。之后，信息革命开始，启动了一个新的优化过程。这一阶段旨在减少技术过程中的人为干预，并提高生产率。

如今，自动化已经成为各个领域的常态。它始于简单的管理员脚本，旨在简化和加快日常任务，并迅速发展成为完整的配置管理工具。这种快速发展背后的原因是市场需求的增加、基础架构和应用程序的扩展，以及新技术的出现，如持续集成、持续开发和机器配置，这些都需要更复杂的设置和配置。

按照本质，系统和网络管理员倾向于减少重复任务，简化复杂任务，并尽快转移到下一个任务。起初，有一些简单的脚本，如 Bash 或 PowerShell，能够优化标准环境中的任务。之后，出现了更长、更复杂的脚本，涉及 Python 或 Ruby 等高级编程语言。这些旨在解决跨多个平台或复杂环境中的任务，并使用自动化和编排工具来管理基础架构，使企业能够在一夜之间大幅增长，提供更多要求更高和更复杂的服务。管理员的角色是管理这种增长，并相应地采取行动，以确保无缝的用户体验。

本章将概述 Ansible。我们将演示 Ansible 现在是管理中大型基础架构的必备平台，而不是拥有物理、部分虚拟或混合的私有和公共云。其他自动化工具在安装、使用、速度和灵活性方面提供不同的优势，因此对于初次使用者来说，选择最合适的自动化工具可能会有些棘手。Ansible、Chef、Puppet 和 SaltStack 是市场上可用的主要配置管理工具。每个工具都遵循不同的部署、配置和管理机器的方法，以降低复杂性，提高速度、可靠性和合规性。本章将涵盖以下主题：

+   自动化工具的市场研究

+   介绍 Ansible 作为配置管理和任务编排工具

+   探索 Ansible 在操作系统、架构和云平台上的功能

+   Ansible 项目和 Tower 概述

# IT 配置管理市场

目前市场上主要使用的配置管理工具是 Ansible、Chef、Puppet 和 SaltStack。每个工具都有其优缺点，因此根据所重视的功能或首选的编程语言，找到合适的工具可能会有些挑战。在本节中，我们将简要介绍每个工具，并解释为什么我们在本书中选择了 Ansible。

Chef 是一个开源的客户端-服务器配置管理工具。它使用 Ruby 和**特定领域语言**（**DSL**）提供灵活的基础设施自动化框架，用于管理主机。这涵盖了所有类型的主机，包括裸机、虚拟机或云上的主机。由于其在大型云部署中的灵活性、稳定性和可靠性，Chef 在代码开发人员中非常常见。然而，设置和学习其功能可能会有一定挑战，因此新用户可能需要一些时间才能完全掌握它。

Puppet 是一个基于 Ruby 的配置管理和编排工具。它遵循主代理架构，需要被控制的主机需要安装 Puppet 代理来进行管理。Puppet 具有强大的自动化和报告功能，通过其用户界面，可以进行任务提交和主机实时报告。与 Chef 一样，Puppet 对于新用户来说设置和配置可能具有挑战性。执行个性化和复杂任务需要对 Ruby 和 DSL 有所了解。

Puppet 和 Chef 是两个最古老的配置管理平台。它们都使用 Ruby 和 DSL 来控制其代理。

SaltStack 是一个用 Python 编写的平台，旨在实现高速主代理通信。它的配置管理任务是用**另一种标记语言**（**YAML**）编码的。主服务器（或多个主服务器）使用 SSH 协议来控制代理/从属服务器。SaltStack 非常可扩展，意味着它可以很好地响应环境变化，易于使用，并且拥有强大的社区。另一方面，它的安装对于新用户来说可能很困难，其用户界面开发不够完善，它专注于 Linux，对其他操作系统的覆盖率一般，并且其文档缺乏良好的管理。

SaltStack 与 Ansible 非常相似。它们都使用易于使用的编程语言，即 Python 和 YAML。此外，SaltStack 和 Ansible 都能够快速执行任务，因为它们依赖 SSH 向主机发送命令。

与其他工具相比，Ansible 是一个相对较新的工具。它旨在简化任务自动化和编排的复杂性。它基于 Python 构建，并使用 YAML 来编写其作业，这是一种非常简单且接近英语的语言。这使得新用户可以轻松理解并自己编写。Ansible 不需要在主机上安装代理。它支持推送和拉取模型，通过 SSH 协议向其 Linux 节点发送命令，以及通过 WinRM 协议向其 Windows 节点发送命令。它可以无缝地部署和配置 VM、应用程序和容器，并且可以轻松扩展以适应环境的增长。它安装和配置简单，学习如何使用和编写其脚本也相对容易。Ansible 不需要安装代理，这提高了其通信速度。它在配置管理任务方面非常先进，但也可以作为基础设施编排工具。然而，它需要主节点的额外权限。用户很容易因多个任务而最终产生多个脚本，这可能会令人困惑，并且与较老的工具相比，它缺乏良好的 GUI 和成熟的平台。

这些工具每个都是为特定受众构建的。它们具有许多成熟的功能，以满足用户的独特需求，无论是简化其日常任务、提高生产率、加快主机配置，还是填补混合环境中的差距。

我们选择在本书中涵盖 Ansible，以使其具有未来的可持续性。我们都可以同意，Ansible 是一个新平台，因此它的设计和可定制性不如许多其他工具，但很容易看出 Ansible 的崛起速度。我们不仅谈论它支持的新技术数量，它正在引入和增强的模块数量，Ansible Galaxy 论坛上存在的社区支持，或 GitHub 项目的分支和收藏库。我们还在关注它在市场上的受欢迎程度和需求。

Red Hat 在 2015 年 10 月收购了 Ansible，并坚信 Ansible 是 IT 自动化和 DevOps 交付的领导者，具有简化混合云、OpenStack 环境和基于容器的服务管理的能力。“Ansible 在 IT 自动化和 DevOps 方面是明显的领导者，并帮助 Red Hat 在我们创建无摩擦 IT 的目标中迈出了重要的一步。”- Joe Fitzgerald，Red Hat 管理副总裁

如下图所示，Ansible 的使用频率比以往任何时候都要高，该图显示了每年从 Debian 存储库下载每个工具的主要软件包的数量：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/da553a37-4ff2-4e8c-aae3-a32d0e3c4ab2.png)

上图是 Debian 存储库上 Ansible、Puppet、Chef 和 SaltStack 受欢迎程度统计数据。它是使用以下链接生成的：[`qa.debian.org/popcon-graph.php?packages=ansible%2C+puppetmaster%2C+salt-master%2C+libchef-ruby&show_installed=on&want_legend=on&want_ticks=on&from_date=2010&to_date=2018&hlght_date=&date_fmt=%25Y-%25m&beenhere=1.`](https://qa.debian.org/popcon-graph.php?packages=ansible%2C+puppetmaster%2C+salt-master%2C+libchef-ruby&show_installed=on&want_legend=on&want_ticks=on&from_date=2010&to_date=2018&hlght_date=&date_fmt=%25Y-%25m&beenhere=1) 此链接可用于生成关于其他 Debian 软件包的时间图。

# Ansible：简单、轻量、强大

Ansible 是一种领先的编排平台，可以实现自动化、主机配置管理和应用程序和虚拟机的部署。Ansible 可以自动化一系列 IT 基础设施功能，从简单的、日常的、重复的任务到机器配置或 DevOps 应用程序的持续集成和部署。它非常灵活，可以覆盖裸机、虚拟机和平台，以及公共或私有云环境。Ansible 还可以管理交换机、路由器和防火墙等网络设备。它还可以覆盖应用程序的设置、数据库管理系统的配置和行为、软件包管理器和简单的用户应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/ee9b9318-5f50-4cdb-939b-207ff447e152.png)

Ansible 标志如果这是你第一本关于配置管理的书，你正在寻找一种简单易行的方法，那么你来对地方了。

在 Linux 上使用系统的软件包管理器从发行存储库安装 Ansible 只需一条命令就足够了。另一种方法是使用 Python 的 PyPI 软件包管理器进行更快、更简单的安装。之后，它可以简单地用类似的方式执行任何命令。我们建议在更复杂或更大的环境中采取额外的步骤，编辑 Ansible 配置文件，使其读取`/etc/ansible/ansible.conf`，填写清单，并添加一些组变量。Ansible 不需要在客户端安装代理，但通过一些额外的步骤，可以使连接更加安全。Ansible 使用 YAML，这是一种简单的配置管理语言，用于 Ansible playbooks，它是一种人类可读的编码语言，因此可以轻松编写脚本。在发送特定任务的命令时，Ansible 服务器将 YAML 代码转换为实际的配置代码，以便立即在客户端上执行。

在本书的大多数教程中，服务器和 Linux 客户端将使用基于 Debian 的系统。配置文件的位置和包名称可能会因发行版而异。

Ansible 主机服务器是唯一的机器，必须满足推荐的计算资源，以便正确运行引擎。由于它是无代理的，客户端只接收以命令形式在系统上直接执行的任务。一些 Ansible 模块可能会通过从一台机器向另一台机器发送数据来消耗相当多的网络流量。这是执行任务所需的最低流量量，因为 Ansible 只使用了一小部分流量来将命令提交给主机。

Ansible 的快速增长使其成为一个非常强大的工具。它现在被认为是市场上领先的自动化引擎。通过其庞大的社区支持（Ansible Galaxy 和 GitHub 项目）和红帽公司的专有管理附加组件（Ansible Tower），用户可以选择各种角色、模块和附加组件，可以自动化每一个可以想象的 IT 任务。

Ansible 为其用户提供以下功能：

+   系统配置管理

+   遵循最佳 DevOps 实践的敏捷应用部署

+   简化的编排和自动化

+   零停机，持续部署

+   云原生应用的支持

+   简单且优化的容器采用

+   在自动化任务中嵌入安全性和合规性策略

+   简化的主机配置

+   支持多层部署

+   支持异构 IT 基础设施

+   支持多层计算机架构

+   支持基础设施即服务（IaaS）部署

+   支持平台即服务（PaaS）部署

+   支持快速增长环境的可扩展性

+   支持推送和拉取模型进行任务执行

+   服务器之间快速共享主机事实，以实现更好的冗余和性能

+   配置各种网络设备

+   存储设备的管理和监控

+   数据库管理系统的控制

每个新版本都附带的 Ansible 模块更新是对官方支持的技术和功能的很好指示。这些模块允许用户编写更简单的 playbook 来执行更复杂的任务。

# Ansible 编排和自动化

随着 IT 基础设施的快速增长和应用部署方式的转变，IT 管理员的任务在规模和复杂性上都有所增加。Ansible 无缝地将编排和配置管理合并在一个非常方便的平台中，使 IT 管理员能够定义一组选定的节点、应用程序和网络设备，以期望的状态进行配置，明确指出应采取哪些行动以消除重复和减少复杂性。Ansible 可以以多种方式使用，我们将在下一节中介绍。

# 编排

除了配置管理外，Ansible 还提供高端编排。这使得多个配置任务之间的交互的组织和管理变得有条不紊。它简化和整理了复杂和混乱的配置管理和管理任务。根据基础设施的状态和用户的需求，应用程序和数据版本化的行为，Ansible 编排通常会通过将适当的服务和策略配置到失败的组件中，使其正常工作，将基础设施恢复到期望的状态。

在处理 DevOps 类任务时，如应用程序的持续集成和部署（CI/CD）或基础设施即代码（IaC），IT 编排可能变得非常复杂。Ansible 能够将这些任务转换为自动化工作流程，运行一系列以明确定义结构的 playbook，包括各种 Ansible 预定义模块、插件和 API，以与任意数量的主机、设备和服务通信、执行命令和报告事实。

# 自动化一切

Ansible 是更好的基础设施自动化、应用部署和配置的途径。这是自动化和现代化 IT 环境的开源方法。Ansible 是使 IT 管理员能够自动化其日常任务的关键，从而释放他们的时间，使他们能够专注于提供优质服务。这不仅影响 IT 部门，还影响整个业务。以下图表显示了 Ansible 多功能的影响范围：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/52e874c7-a3a9-4786-a3e5-0936b2438927.png)

# 配置

使用 Ansible 进行实例配置涵盖了裸金属机器和服务器的配置和设置。它依赖于其预定义的 API 来创建和配置本地虚拟化基础设施。它还可以管理混合、私有和公共云实例、资源和应用程序。Ansible 可以自动安装和配置应用程序及其库。它使用 OS 引导程序和 kickstart 脚本来启动裸金属机器配置，使用非常简单的 playbooks 和内置模块。使用相同的简单 playbooks 和不同的模块，Ansible 也可以非常轻松地在公共、私有或混合云中配置实例、网络和虚拟机。

# 配置管理

利用 playbooks 和清单的功能，IT 管理员可以使用 Ansible 在多个主机、网络设备和应用程序上执行更新、补丁或配置修改。Playbooks 以简单的、人类可读的术语描述基础设施，供其他人使用，并且可以在运行 Ansible 的任何机器上使用的可机器解析的代码。Ansible 配置的执行是状态驱动的，这意味着它不需要检查系统或服务状态来知道如何调整以增加任务的可靠性。

# 应用部署

当我们谈论由 Ansible 管理的应用程序时，我们谈论的是完整的生命周期控制。任何有权访问 Ansible 服务器节点的用户，从 IT 管理员到应用程序开发人员和项目经理，都可以管理应用程序的所有方面。Ansible 接收应用程序包，将其部署到所有生产服务器上，设置并配置并启动它。它甚至可以测试该包并报告其状态。这个功能涵盖了多层应用程序，允许无停机滚动以实现无缝的应用程序更新。

# 持续交付和持续集成

Ansible 确保开发人员和 IT 管理员都能获得稳定的环境，以实现应用程序的持续交付和集成。尽可能自动化应用程序的周转意味着对应用程序用户来说，这是快速且不易察觉的。Ansible 的自动化和编排是多层和多步骤的，这允许对操作和主机进行更精细的控制。我们可以编写 Playbooks 来管理应用程序的持续集成和交付，同时确保各种组件的期望状态，例如负载均衡器和多个服务器节点。

# Ansible 项目和 Ansible Tower

在被 Red Hat 收购后，Ansible 继续提供一个名为 Ansible 项目的免费开源平台。Red Hat 创建了专有的管理附加组件，提供对基础设施的高级控制和集中管理，称为 Ansible Tower。Red Hat 运行着由 Ansible Engine 和 Ansible Tower 组成的 Ansible 自动化平台。这个产品是 Red Hat 的主要项目之一，得到了完全的支持。

# Ansible 项目

Ansible 项目是来自原始公司 AnsibleWorks 的功能的积累。它是一个由社区构建的自动化引擎。它是免费的、开源的，任何人都可以在任何 Linux 操作系统上下载或安装，使用软件包管理器、源代码编译或 Python PyPI。它非常简单、强大且无需代理。

使用 Ansible 自动化引擎，用户不需要任何第三方应用程序或接口。他们可以简单地发送命令或编写 playbook 并直接执行到引擎。这允许用户访问各种预定义的模块、插件和 API，作为管理各种 IT 任务和网络对象的构建块。由于它是无代理的，Ansible 依赖于 SSH 来管理 Linux 主机，以及 WinRM 来管理 Windows 主机。SSH 协议也用于控制一些网络设备。一些更不寻常的设备或云和虚拟化服务需要使用 Ansible 预定义的 API 来帮助管理或访问它们。

节点可以根据其 IP 地址或主机名进行定义；对于后者，我们将不得不依赖 DNS 服务器或本地 DNS 文件。API 用于与公共或私有云等第三方服务进行通信。模块构成了 Ansible 最大的预定义功能库，允许用户将长而复杂的任务简化为 playbook 中的几行。它们涵盖了大量的任务、系统、软件包、文件、数据存储、API 调用、网络设备配置等。最后，Ansible 插件用于改进 Ansible 的核心功能，例如快速主机缓存，以避免在网络上收集事实。

# Ansible Tower

Ansible Tower 是坐落在 Ansible 项目引擎之上的 Red Hat 专有层。它由许多附加组件和模块组成，由 REST API 和 Web 服务组成，它们共同创建一个友好的 Web 界面，作为一个自动化中心，IT 管理员可以从中选择要在多台机器上执行的一些任务或 playbook。它仍然依赖于 Ansible 引擎发送命令和收集报告。Ansible Tower 巧妙地收集任务的状态和来自主机的报告。所有这些数据都显示在 Ansible 仪表板上，显示主机、清单的状态以及最近的作业、活动和快照：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/149d79ca-1129-4060-9eb8-3115f435d77f.png)Ansible Tower 只能安装在 Red Hat 7、CentOS 7 和 Ubuntu 14.04/16.04 LTS 上。

随着环境的增长，Ansible Tower 可以扩展，并根据情况实时显示主机、任务和 playbook 的所有状态。它突出显示了成功的 playbook 作业，以及未能运行的作业，以便排除任何问题。在其多 playbook 工作流中，用户可以创建 playbook 的流水线，按顺序在任何类型的清单上使用一个或多个用户凭据，并在个性化的时间表上执行。启用流水线，IT 管理员可以通过将复杂操作（应用程序提供、使用容器进行持续部署、运行测试工作流）分解为更小的任务，使用流水线，并根据输出（成功或失败）运行特定的 play，从而自动化复杂操作。

Ansible Tower 提供了一个智能清单平台，可以从任何来源获取主机清单，包括公共或私有云，或本地 CMDB。智能清单构建主机缓存，允许用户根据主机的事实运行 playbook，这些事实是与主机相关的信息和属性，由 Ansible 收集。它还允许您设置内置通知，通过电子邮件、短信和第三方平台（如 Slack 或 Hipchat）上的推送通知，关于任务、工作流和 playbook 的状态。Ansible Tower 还允许对例行更新、设备打补丁和自定义备份计划选项进行任务调度。下图显示了由 Red Hat 提供的完整 Ansible 引擎的层次结构：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/c4c8f129-a00d-4572-82e3-3f6aef853c42.png)

目前，Red Hat Ansible Tower 提供了一个为期 30 天的试用许可证，供用户进行实践探索和测试其功能。任何用户都可以使用它来决定他们的环境是否会从中受益。

在本书中，我们将主要关注开源的 Ansible Engine，因为它是免费的并且对每个人都是可访问的。我们认为学习 Ansible 必须从基本的无界面版本开始，以更好地理解工具的内部机制。读者可以轻松地通过已经掌握的引擎技能迁移到 Ansible Tower。

有许多开源解决方案提供了一些 Ansible Tower 的功能。其中最常见的是 Ansible Semaphore，可以在 [`github.com/ansible-semaphore/semaphore`](https://github.com/ansible-semaphore/semaphore) 上找到。

# 总结

在本章中，我们介绍了 Ansible 并列出了其主要特性以及在正确使用时可以为用户提供的优势。我们还讨论了由 RedHat 开发和支持的 Ansible Tower 企业版。在第二章 *Ansible 设置和配置* 中，我们将开始真正的学习。我们将从设置 Ansible 开始，并展示配置它的最佳方法，以便进行测试。

# 参考资料

本章的参考资料如下：

+   Ansible 网站：[`www.ansible.com/`](https://www.ansible.com/)

+   Red Hat 网站：[`www.redhat.com/en/technologies/management/ansible`](https://www.redhat.com/en/technologies/management/ansible)

+   Puppet 网站：[`puppet.com/`](https://puppet.com/)

+   Chef 网站：[`www.chef.io/chef/`](https://www.chef.io/chef/)

+   SaltStack 网站：[`saltstack.com/`](https://saltstack.com/)


# 第二章：Ansible 设置和配置

由于 Ansible 是无代理的，与其他配置管理平台不同，它只需要在主节点上安装。由于它没有守护程序、数据库依赖和持续运行的服务，Ansible 也特别轻量。

在介绍了 Ansible 之后，我们现在将看看在您的环境中安装 Ansible 的不同方法，比如裸机、云和使用 Docker 容器。我们还将看看如何在多个 Linux 操作系统上安装 Ansible，包括从软件包管理器和源码安装。最后，我们将看看如何准备和配置主机，使其可以被 Ansible 控制。本章将涵盖以下内容：

+   Ansible 主节点和基本 Linux 安装

+   Ansible 容器设置

+   Ansible 源码安装

+   Ansible AWS 实例设置

+   Ansible 配置

+   Linux 和 Windows 客户端上的 Ansible 配置

# Ansible 主节点安装

Ansible 使用**安全外壳**（**SSH**）和 WinRM 来管理其主机客户端。所有安装都发生在管理节点或主节点上，或者在需要冗余时可能在多个节点上。我们将继续从源码安装 Ansible，就像在两个主要的 Linux 系列上使用 Python PyPI 一样：Debian（包括 Debian、Linux Mint、Kali Linux、Ubuntu 和 Ubuntu Mate）和 Red Hat（包括 Red Hat、Fedora、CentOS 和 Scientific Linux）。我们还将看看 Mac OS X 的 Ansible 安装过程，Python PyPI 以及如何从源码安装。我们将涵盖云使用和容器化的 Ansible。

如果可以选择，我们建议在 Red Hat、CentOS、Debian、Ubuntu 和 Mac OS X 上使用默认的软件包管理器。使用软件包管理器可以安装最新稳定版本的 Ansible。Python PyPI 也可以依赖于其提供最新稳定版本的 Ansible，特别是在使用旧的 LTS 或稳定的 Linux 版本时。

在云环境中使用，有许多社区实例可供选择。我们建议使用最受欢迎的实例以及相应的版本。

# 先决条件

在这方面，Ansible 非常棒。对于 Linux 软件包安装，你只需要 Python 2（版本 2.6 或更高）或 Python 3（版本 3.5 或更高）。对于源码安装，我们可能需要开发套件，比如 Debian 系列的`build-essential`软件包，或者 Red Hat 系列的`Development Tools`组软件包。

大多数 Linux 操作系统的软件包管理器在安装 Ansible 时会自动下载适当的 Python 版本及其依赖项。

对于 Mac OS X，安装 Homebrew 和 Xcode 应该就可以了。请记住，这些是安装 Ansible 软件包所需的要求。

在使用 Mac OS X 上的 Ansible 之前，您需要以 root 用户身份运行一个命令，以允许自己控制超过 15 个主机。这与同时处理文件的限制有关。命令是`sudo launchctl limit maxfiles unlimited`。

关于 Ansible 容器安装，我们需要一个容器引擎。在我们的情况下，我们将使用 Docker，或者任何等效平台，比如 Singularity 或 Shifter。对于云安装，我们只需要一个 SSH 客户端来连接到 AWS 实例。其他云提供商，如 Google Cloud Platform 或 Microsoft Azure，也支持 Ansible 实例。

你可以在任何平台上创建自己定制的云实例。我们的建议适用于绝大多数使用情况，我们相信 AWS 支持和社区实例经过了许多用户的测试，它们是尽可能稳定和可靠的。其他要求没有在这里提到，因为它们对于 Ansible 的主要功能和模块并不是严格必要的，而是针对非常特定的插件和模块。当我们讨论这些模块和插件时，我们会涵盖它们。

# Red Hat、CentOS 和 Fedora 软件包安装

如果您使用 Yellowdog Updater, Modified (Yum)，则需要额外的步骤，因为 Ansible 不位于默认的 RHEL 存储库中。正如您在过去安装工具时可能遇到的那样，通常需要在使用软件包管理器安装工具之前安装**企业 Linux 的额外软件包**（**EPEL**）。这是一个非常简单的步骤。我们首先需要从 Fedora Project 网站下载`epel-release` `rpm`文件：[`fedoraproject.org/wiki/EPE`](http://fedoraproject.org/wiki/EPEL)[L](http://fedoraproject.org/wiki/EPEL)。然后，我们需要使用`rpm`进行安装，如下所示：

```
sudo rpm -i epel-release-latest-7.noarch.rpm
```

从 EPEL 下载的工具实际上并未经过 Red Hat 质量工程师的测试，因此在生产服务器上下载时需要额外小心，因为可能会影响支持。

Ansible 引擎存储库（可在[`access.redhat.com/articles/3174981`](https://access.redhat.com/articles/3174981)找到）是另一个有效的存储库，可用于下载 Ansible 的最新版本。要仅使用 Red Hat Linux 访问其软件包，我们首先需要启用它，如下所示：

```
sudo subsription-manager repos --enable rhel-7-server-ansible-2.5-rpms
```

之后，软件包管理器将需要更新其缓存，即软件包列表。我们使用 Yum 来执行此操作，如下所示：

```
sudo yum update
```

与使用 Yum 安装任何其他软件包一样，我们需要将`ansible`指定为`install`选项的输入：

```
sudo yum install ansible
```

大多数 Red Hat 系列操作系统应该接受这些命令来设置 Ansible。 Fedora 18 及更高版本具有下一代软件包管理器**Dandified Yum**（**DNF**）。这是从 Fedora 22 开始的默认软件包管理器。使用 RPM 安装 EPEL 软件包后，我们需要运行以下命令来更新 DNF 软件包列表：

```
sudo dnf -y update
```

然后，我们使用以下命令安装 Ansible：

```
sudo dnf -y install ansible
```

使用 Red Hat 系列操作系统，可以通过获取适当的 RPM 文件并使用 RPM 进行安装来安装 Ansible。首先，我们需要从 Ansible 发布链接下载适当的 RPM 文件：[`releases.ansible.com/ansible/rpm/`](https://releases.ansible.com/ansible/rpm/)。下载所需的 Ansible 版本的 RPM 文件，并按以下方式安装：

```
sudo rpm -Uvh ansible-2.5.5-1.el7.ans.noarch.rpm
```

如果需要，RPM 文件也可以轻松地从源代码构建并安装。我们建议使用官方 GitHub Ansible 存储库。首先，我们需要使用 Git 获取项目文件夹。我们可能需要已经安装了 Git 才能轻松下载它：

```
git clone https://github.com/ansible/ansible.git
cd ansible
```

然后，我们需要构建 Ansible 的`rpm`文件，并使用相同的命令进行安装：

```
make rpm
sudo rpm -Uvh rpm-build/ansible-*.noarch.rpm
```

# Debian 软件包安装

对于 Debian 用户，您可能已经知道，如果要使用工具的最新版本，需要运行最新的稳定或测试版本的 Debian 操作系统。不建议使用测试版本，但有些人使用。由于 Debian 非常可靠，操作系统管理员倾向于设置 Debian 服务器，然后多年多年地忘记它，因为它继续按照预期的方式运行，没有任何问题。通常，管理员倾向于运行许多旧的、稳定的 Debian 版本。如果您想要使用最新的 Ansible 版本及其所有优点、模块和插件，我们不建议使用这些旧版本，除非您进行替代安装（使用 PyPI、源安装或通过容器）。

我们将使用 Debian 9（Stretch），因为它是最新的 Debian 稳定版本。Debian 9 允许您使用许多 Ubuntu 软件包源来安装 Ansible。我们可以将 DEB 行添加到`source.list`文件中，也可以将**个人软件包存档**（**PPA**）添加到列表中。首先，我们需要安装软件属性包：

```
sudo apt-get install -y software-properties-common
```

然后，我们使用文本编辑器并将以下 DEB 添加到`/etc/apt/source.list`中：

```
deb http://ppa.launchpad.net/ansible/ansible/ubuntu trusty main
```

在源文件的末尾添加 DEB 行的更快方法如下：`echo "deb http://ppa.launchpad.net/ansible/ansible/ubuntu trusty main" >> /etc/apt/source.list`

然后通过将其密钥添加到`apt`来验证链接：

```
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 93C4A3FD7BB9C367
```

对于最新的 Debian 版本，也可以直接使用 PPA 存储库，方法是将链接添加到 APT 存储库：`sudo apt-add-repository ppa:ansible/ansible`

通常，添加存储库需要您更新软件包管理器缓存：

```
sudo apt update
```

然后我们可以安装 Ansible：

```
sudo apt install -y ansible
```

在后续章节中，大多数教程都是在已安装并使用 Python PyPI 更新的 Debian 8（Jessie）上进行的。这与在操作系统的最新版本上安装 Ansible 的任何其他标准方式一样稳定，最新且可靠。

# Ubuntu 软件包安装

在最新版本上安装 Ansible 的最佳方法是为 Ubuntu 添加 Ansible PPA `ppa:ansible/ansible`（`launchpad.net/~ansible/+archive/ubuntu/ansible`）。这应该使用以下命令添加：

```
sudo apt-add-repository ppa:ansible/ansible
```

添加 PPA 存储库需要您确认密钥服务器设置。通过按*Enter*键来接受。

然后我们需要更新软件包管理器缓存，也称为系统软件包索引，如下所示：

```
sudo apt update
```

最后，我们可以安装 Ansible：

```
sudo apt install ansible
```

# macOS X 软件包安装

在 MAC OS X 系统上安装 Ansible 可以使用两种工具之一来实现。第一种使用 Python PyPI，将在以下部分中描述。第二种使用 Mac OS X 开源软件包管理系统 Homebrew（brew.sh）。在本节中，我们将描述如何使用 Homebrew 安装 Ansible。

要能够使用 Homebrew，我们首先需要确保它已安装，因为它不是默认的系统应用程序。您需要使用 Ruby 编译器将其构建到系统中。为此，您还需要安装 Xcode（在此处找到：[developer.apple.com/xcode/](http://developer.apple.com/xcode/)），并接受其用户许可协议。然后在其终端上运行以下命令：

```
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

这个命令可能需要一些时间，具体取决于您的互联网访问和计算机速度。

然后我们可以使用 Homebrew 来安装 Ansible：

```
brew install ansible
```

# Python PyPI 安装

要能够使用 PyPI 安装 Ansible，我们首先需要安装 PyPI。它可以使用大多数软件包管理器轻松安装，其中一些在以下部分中概述。

Red Hat Yum 安装如下实现：

```
sudo yum install -y python-pip
```

Debian APT 安装使用以下命令：

```
sudo apt install -y python-pip
```

对于其他 Linux 系统，使用 Python：

```
sudo easy_install pip
```

Mac OS X Homebrew 安装如下：

```
brew install python-pip
```

从 PyPI 存储库中，通过安装 PyPI：

```
sudo pip install ansible
```

我们也可以使用 GitHub 源获取最新的开发版本：

```
sudo pip install git+https://github.com/ansible/ansible.git@devel
```

要使用 PyPI 选择特定版本的 Ansible，我们可以使用以下命令：`sudo pip install ansible==2.4.0`。要升级到最新版本，我们可以添加`--upgrade`选项，使命令如下：`sudo pip install ansible --upgrade`。

# 源 GitHub 或 tarball 安装

能够从源代码构建 Ansible 对于在不常见的环境中使用的用户或者对于那些有一些特殊要求的用户是有帮助的，比如在不需要软件包管理器或者受限于 Ansible 的最新稳定版本的情况下设置 Ansible。使用 Ansible 的开发版本（或 beta 版）总是会使用户面临不稳定的模块和插件的风险，但也允许提前访问未来的模块。

要获取 Ansible 的源包，我们可以使用两种不同的方法：下载`.tar`文件，或者克隆项目的 GitHub 存储库。Ansible 项目源文件位于其发布页面（`releases.ansible.com/ansible/`）中，GitHub 源可以从官方 GitHub 项目（`github.com/ansible/ansible`）中克隆。

要下载 tarball 文件，请使用您喜欢的文件获取工具（如 curl、wget 或 axel）：

```
wget -c https://releases.ansible.com/ansible/ansible-2.6.0rc3.tar.gz
```

然后我们需要解压 tarball：

```
tar -xzvf  ./ansible-2.6.0rc3.tar.gz
```

或者，我们可以使用 Git 在本地克隆 GitHub 项目。我们需要确保系统上已安装 Git，然后我们可以开始克隆。此过程在以下片段中显示了一些系统。

以下命令行显示了如何在红帽系列的 Linux 上安装`git`：

```
sudo yum install -y git
```

以下命令行显示了如何在 Debian 系列的 Linux 上安装`git`：

```
sudo apt install -y git
```

以下命令行显示了如何在 Mac OS X 上安装`git`：

```
brew install git
```

在所有系统上，要克隆 Ansible GitHub 项目：

```
git clone https://github.com/ansible/ansible.git --recursive
```

然后我们需要开始构建 Ansible，可以通过获取 tarball 或从 GitHub 获取源代码：

```
cd ./ansible*
```

为了确保轻松满足构建 Ansible 的所有要求，我们将使用 Python PyPI。在前面的部分中涵盖了多个系统上的 PyPI 安装。对于本节，我们将使用`easy_install`，它只需要您在系统上安装一个版本的 Python：

```
sudo easy_install pip
```

现在我们安装 Python 要求：

```
sudo pip install -r ./requirements.txt
```

我们需要按照以下方式设置环境才能使用 Ansible：

```
source ./hacking/env-setup
```

在使用 GitHub 项目时更新 Ansible 可能会更加棘手。我们需要按以下方式拉取项目及其子模块：

```
git pull --rebase
git submodule update --init --recursive
```

每次执行这些命令时，我们需要确保环境已正确设置：

```
echo "export ANSIBLE_HOSTS=/etc/ansible/hosts" >> ~/.bashrc
echo "source ~/ansible/hacking/env-setup" >> ~/.bashrc
```

当 Ansible 源位于的位置时，环境源的位置可能会发生变化。Ansible 清单（通常位于`/etc/ansible/hosts`）及其配置文件（通常位于`/etc/ansible/ansible.cfg`）也可以更改以适应权限限制或为 Ansible 用户提供更容易访问以启用修改或限制它们。这将在本章后面更详细地介绍。

# Ansible Docker 容器安装

在容器上使用 Ansible 需要运行容器引擎。有多种选择可用的容器，最著名的是 Docker、Kubernetes 和 Red Hat OpenShift。在本书中，我们只会涵盖 Docker。我们需要在托管 Ansible 容器的机器上运行 Docker 引擎。Docker 安装信息可以在其官方文档中找到：[`docs.docker.com/install/`](https://docs.docker.com/install/)。这涵盖了大量操作系统。

在这里，我们假设 Docker 引擎已安装，并且当前用户已添加到 Docker 组，以便他们可以在机器上管理本地 Docker 容器。您还可以选择通过选择您熟悉的任何系统来构建自己的容器作为源镜像。确保您已安装所有要求。以下是 Linux Alpine 上的基本 Dockerfile 示例，这是容器中使用的最轻的系统之一：

```
FROM alpine:3.7

RUN echo "#### Setting up the environment for the build dependencies ####" && \
set -x && apk --update add --virtual build-dependencies \
    gcc musl-dev libffi-dev openssl-dev python-dev

RUN echo "#### Update the OS package index and tools ####" && \
    apk update && apk upgrade

RUN echo "#### Setting up the build dependecies ####" && \
   apk add --no-cache bash curl tar openssh-client \
    sshpass git python py-boto py-dateutil py-httplib2 \
    py-jinja2 py-paramiko py-pip py-yaml ca-certificates 

RUN echo "#### Installing Python PyPI ####" && \
    pip install pip==9.0.3 && \
    pip install python-keyczar docker-py

RUN echo "#### Installing Ansible latest release and cleaning up ####" && \
    pip install ansible –upgrade \
    apk del build-dependencies && \
    rm -rf /var/cache/apk/*

RUN echo "#### Initializing Ansible inventory with the localhost ####" && \
    mkdir -p /etc/ansible/library /etc/ansible/roles /etc/ansible/lib /etc/ansible/ && \
    echo "localhost" >> /etc/ansible/hosts

ENV HOME                      /home/ansible
ENV PATH                      /etc/ansible/bin:$PATH
ENV PYTHONPATH                /etc/ansible/lib
ENV ANSIBLE_ROLES_PATH        /etc/ansible/roles
ENV ANSIBLE_LIBRARY           /etc/ansible/library
ENV ANSIBLE_SSH_PIPELINING                True
ENV ANSIBLE_GATHERING                     smart
ENV ANSIBLE_HOST_KEY_CHECKING             false
ENV ANSIBLE_RETRY_FILES_ENABLED           false 

RUN adduser -h $HOME ansible -D \
   && chown -R ansible:ansible $HOME

RUN echo "ansible ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers \
    && chmod 0440 /etc/sudoers

WORKDIR $HOME
USER ansible

ENTRYPOINT ["ansible"]       
```

然后使用 Docker 上的`build`函数构建容器：

```
docker build -t dockerhub-user/ansible .
```

构建可能需要一些时间来完成。然后我们可以尝试以几种不同的方式运行我们的 Ansible 容器，这取决于我们将如何使用它。例如，我们可以验证容器上的 Ansible 版本：

```
docker run --rm -it -v ~:/home/ansible dockerhub-user/ansible --version
```

我们还可以运行一个 ping 任务：

```
docker run --rm -it -v ~:/home/ansible \
 -v ~/.ssh/id_rsa:/ansible/.ssh/id_rsa \
 -v ~/.ssh/id_rsa.pub:/ansible/.ssh/id_rsa.pub \
 dockerhub-user/ansible -m ping 192.168.1.10
```

通过将我们的 Dockerfile 代码的`ENTRYPOINT`从`[ansible]`更改为`[ansible-playbook]`，我们可以创建一个脚本，可以使用我们的容器来工作，就好像安装了`docker-playbook`一样。这将在第三章中进一步解释，*Ansible 清单和 Playbook*。创建一个名为`ansible-playbook`的脚本，并使用以下代码将其添加到`PATH`环境变量中：

```
#!/bin/bash
 -v ~/.ssh/id_rsa:/ansible/.ssh/id_rsa \
 -v ~/.ssh/id_rsa.pub:/ansible/.ssh/id_rsa.pub \
 -v /var/log/ansible/ansible.log \
 dockerhub-user/ansible "$@"
```

确保脚本具有执行权限，可以使用`chmod +x`命令行。它可以被复制或符号链接到`/usr/local/bin/`，以自动将其添加到`PATH`。

可以使用以下脚本在`inventory`文件夹中的特定主机上执行 playbook：

```
Ansibleplaybook play tasks.yml -i inventory/hosts
```

# AWS 上的 Ansible 实例

有多个公共云提供商，例如 Google Cloud Platform 或 Microsoft Azure，提供与**Amazon Web Services**（**AWS**）相同的服务。在本节中，我们不会涵盖安装过程的大部分，因为实例已经预安装和配置。

相反，本节将是一个简短的逐步指南，介绍如何在 AWS 上设置已经存在的 Ansible 实例。首先，我们需要访问 AWS 帐户的 EC2 仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/20266992-496c-41a4-96b5-155e4f81680e.png)

然后，我们选择启动一个新实例并寻找`Ansiblemaster`实例。注意不要选择 Ansible Tower 实例之一：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/b1d11c61-095c-4ecd-9f4c-823a7ebe0b01.png)

然后，我们选择要分配给我们的实例的计算资源数量：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/311b2028-80f8-4ee7-ace2-2dd07da4c8b0.png)

然后，我们添加要由实例使用的磁盘空间，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/5c0bd940-f7b3-4449-a440-5172b9a14171.png)

然后确认并启动实例：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/b6f01939-5d18-4a74-86b2-e3b3508b7c7f.png)

我们可以创建一个新的 SSH 访问密钥，也可以使用旧的密钥：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/79fc442d-bc35-4748-966f-011f47a2959f.png)

在我们的本地终端上，我们设置密钥文件的权限并使用 SSH 访问该实例：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/43dbae09-025a-426f-92fe-8c6f3a27508b.png)

我们可以检查 Ansible 的版本和配置。我们可以随时将其更新到必要或最新的稳定版本。以下打印屏幕显示了如何使用实例 OS 包管理器从一个 Ansible 版本切换到另一个版本。首先，我们确定当前安装的版本：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/57ee3aca-6e76-441a-a19a-fdba3d65b761.png)

然后，我们运行完整的系统软件更新：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/46d02e81-653e-4122-b071-b7b9af232453.png)

最后，完成更新过程后，我们重新确认 Ansible 版本：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/b7ca36c7-981a-49d3-bc4e-f434cb50ba12.png)

最后，我们可以使用新安装的 Ansible 在我们的 AWS 环境中协调任务。

# 主节点基本配置

Ansible 配置主要存储在`ansible.cfg`配置文件中，通常位于大多数系统包管理器和 Python PyPI 安装中的`/etc/ansible/ansible.cfg`。它也可以位于安装 Ansible 的用户的主目录中，或者`ANSIBLE_CONFIG`环境变量指向的任何位置。在本节中，我们将介绍可以使用 Ansible 修改的最有用的配置，以使您的生活更轻松。

使用您喜欢的文本编辑器打开您的`ansible.cfg`文件，可以是 CLI 模式（使用 vi 或 nano）或 GUI 模式（使用 Gedit 或 Atom）：

```
sudo nano /etc/ansible/ansible.cfg
```

不用担心使用哪种文本编辑器，总会有人不同意。使用您最舒适的那个。

许多人会同意，Ansible 的默认配置对于正常使用是可以的。安装后可以立即使用 Ansible。

从 Ansible 2.4 版本开始，有一个命令行`ansible-config`，允许用户列出已启用的选项及其值，以更快地检查其配置。禁用的配置选项通过使用井号`#`或分号`;`来实现。分号`;`通常用于引入已启用的选项。

您可以随时访问 Ansible 示例配置文件，查看选项的使用方式。示例可以在以下链接找到：[raw.githubusercontent.com/ansible/ansible/devel/examples/ansible.cfg](http://raw.githubusercontent.com/ansible/ansible/devel/examples/ansible.cfg)。

Ansible 的配置文件分为几个部分。我们将集中在`[defaults]`一般部分。我们将从介绍此部分中的基本参数开始。

+   清单：这是指示 Ansible 托管清单的文件的参数。在大多数系统上，它指向`/etc/ansible/hosts`，如下所示：

```
inventory = /etc/ansible/hosts
```

+   `roles_path`：这是一个参数，用于指示 Ansible playbook 应该在系统默认位置之外查找附加角色：

```
roles_path = /etc/ansible/roles
```

+   `log_path`：这是一个参数，用于指示 Ansible 应该存储其日志的位置。确保运行 Ansible 的用户有权限在指定的位置上写入。示例如下：

```
log_path = /var/log/ansible.log
```

+   `retry_files_enabled`：这是一个参数，用于启用重试功能，允许 Ansible 在播放书失败时创建一个`.retry`文件。最好保持此参数禁用，除非您确实需要它。这是因为它会创建多个文件，并且会在 Ansible 日志和仪表板的播放书执行状态部分中记录已经记录的旧失败任务。以下是禁用该参数的示例：

```
retry_files_enabled = False
```

+   `host_keychecking`：这是一个参数，其推荐值取决于环境。通常，它用于不断变化的环境，旧机器被删除，新机器取代它们的位置。它更频繁地用于云或虚拟化环境，其中虚拟机和部署实例取代了旧机器的 IP 地址。Ansible 为这些机器保存了一个密钥以防止安全问题。禁用此参数将使 Ansible 忽略与`known_hosts`密钥相关的错误消息：

```
host_key_checking = False
```

+   `forks`：这是一个参数，用于定义对客户端主机执行的并行任务数量。默认数量为五，以节省资源和网络带宽。如果有足够的资源和大带宽来为许多主机提供服务，可以将其提高到最大主机数量，如下所示：

```
forks = 10
```

+   `sudo_user`和`ask_sudo_pass`：这两个是遗留参数。在当前版本的 Ansible 中仍然可以使用它们，但它们不太可靠。建议在创建 Ansible 清单中的组时设置这些参数——这将在下一章节中详细解释，但示例如下：

```
sudo_user = install
ask_sudo_pass = True
```

+   `remote_port`：这是一个参数，用于指示客户端主机上 SSH 要使用的端口。这也是一个最好在清单组中设置的参数：

```
remote_port = 22
```

+   `nocolor`：这是一个可选参数。它允许您为 Ansible 任务和播放书显示不同的颜色，以指示错误和成功：

```
nocolor = 0
```

以下参数涉及与主机`[ssh_connection]`的 SSH 连接。

`pipelining`：此参数启用了减少执行模块所需的 SSH 操作次数的功能。这是通过执行 Ansible 模块而无需实际文件传输来实现的，可以极大地提高 Ansible 的性能。它要求在所有受管主机的`/etc/sudoers`中禁用 requiretty。其使用示例如下：

```
pipelining = True  
```

`scp_if_ssh`和`transfer_method`参数：这两个参数负责主节点和客户端主机之间的文件传输。选择`smart`值允许 Ansible 在传输文件时选择最合适的协议，从而在 SFTP 和 SCP 之间进行选择：

```
scp_if_ssh = smart
transfer_method = smart
```

以下两个示例涉及到 SSH 连接的持久性，`[persistent_connection]`。我们只涵盖了连接的超时和失败重试。SSH 超时可以通过编辑这两个参数的值来设置，首先是：

```
connect_timeout = 30
```

其次：

```
connect_retry_timeout = 15
```

最后，让我们来看一下`[colors]`颜色选择。在`[default]`部分启用颜色功能时，此部分将被激活。它允许您为各种输出状态选择不同的颜色。在使用特殊显示或帮助解决色盲问题时可能会有所帮助：

```
warn = bright purple
error = red
debug = dark gray
ok = green
changed = yellow
skip = cyan
```

另外，我们不应忘记 Ansible 依赖 SSH 与其客户端进行通信。在主节点上应进行配置，以创建一个 SSH 密钥，然后将其复制到所有客户端主机上，以实现无密码远程访问。这有助于消除明文保存的密码，并实现任务的完全自动化。创建 SSH 密钥可以是简单的，也可以是更复杂和更安全的。我们将选择简单的选项：

```
ssh-keygen -t rsa
```

在接受密钥并将密码留空时，继续按回车键：

```
ssh-copyid user@host1
```

这个任务可能有点乏味和非常手动。在尝试解决 SSH 密钥和身份验证问题时，使用`expect`命令进行脚本编写可能非常方便。首先，我们需要确保`expect`已安装，因为它通常不是默认安装的。以下示例展示了各种操作系统的此过程。

这个命令行显示了如何在红帽 Linux 系统上安装 Expect 工具：

```
sudo yum install -y expect-devel
```

这个命令行显示了如何在 Debian 家族的 Linux 上安装 Expect 工具：

```
sudo apt install -y expect
```

这个命令行显示了如何在 MAC OS X 上安装 Expect 工具：

```
brew install expect
```

然后，我们可以创建一个包含以下内容的脚本文件：

```
#!/usr/bin/expect -f
set login "install"
set addr [lindex $argv 0]
set pw [lindex $argv 1]
spawn ssh-copy-id $login@$addr
expect "*yes/no*" {
 send "yes\r"
 expect "*?assword*" { send "$pw\r" }
 } "*?asswor*" { send "$pw\r" }
interact
```

这个脚本应该有执行权限才能执行。然后可以与另一个循环脚本一起使用，以在已知 IP 地址范围或主机名的多台机器上执行。

```
#!/bin/bash
password=`cat /root/installpassword.txt`
for j in 10 11 12 13 14 15 16 17 18 19 20
do
 ./expectscript 192.168.1.$j $password
done
```

或者，我们可以使用编排工具来执行相同的任务。让我们使用 Ansible 通过简单的`copy`和`shell`模块来帮助客户端配置：

```
ansible all -m copy -a "src=~ /.ssh/id_rsa.pub dest=/tmp/id_rsa.pub" --ask-pass -c install
ansible all -m shell -a "cat /tmp/id_rsa.pub >> /home/install/.ssh/authorized_keys" --ask-pass -c install
```

`install`用户可以是在所有客户端主机上创建的特殊用户，以允许使用 Ansible 进行简单的 SSH 远程访问。有关如何设置此用户的更多详细信息，请参见以下标题。

# Linux 客户端节点配置

客户机上唯一重要的工具是 OpenSSH 服务器。所有新版本的 Linux 默认使用 SSH 作为主要的远程访问方法。

为了确保一切就绪，SSH 服务应始终运行，并且系统防火墙应允许 SSH 服务的端口通过。默认情况下，这是端口 22。但是，这可以更改，而且这个更改也应该在主机 Ansible 清单中记录下来。

对于 Linux 客户端，Ansible 管理的任何额外配置更多地是遵循最佳实践准则，而不是严格必要的。额外的配置可以确保由 Ansible 管理的远程客户端是完全自动化的、安全可访问的，并且在运行自动化任务时不需要管理员干预。

以下配置是可选的 - 您可以选择适合您的配置。添加您认为有用的配置，忽略其他配置。

当手头有凭据时，Ansible 可以远程管理系统使用任何特权用户。然而，混合普通用户、具有远程访问权限的用户和管理用户可能会很混乱。如果用户在 Ansible 发送任务的同时执行任务，回溯可能会很棘手。我们建议添加一个新的系统用户，其唯一目的是被 Ansible 用来控制主机。我们赋予这个用户超级用户权限，并使其访问无密码，以进一步增强自动化。这个用户可以在特定清单组的所有主机上是相同的，以在清单组级别进行配置。

您还可以通过 NFS 和 SMB 在主机和 Ansible 服务器之间创建共享文件夹，以减少向主机传输数据时的负载。这个任务使得主机负责从挂载的共享文件夹中复制数据，而 Ansible 负责其他任务，特别是当 forks 的值设置为一个较高的数字时。

# Windows 客户端节点配置

除了 Linux 主机，Ansible 还能够远程管理 Microsoft Windows 主机。这包括 Windows Desktop 7、8 和 10，以及 Windows Server 2008、2008 R2、2012、2012 R2 和 2016。

Windows 客户端需要您安装以下应用程序的特定版本：

+   PowerShell 3.0 或更高版本

+   .NET 4.0

这两个要求在大多数 Windows 版本上都得到满足，除了 Windows 7 和 Windows Server 2008。

有一个由 Ansible 制作的 PowerShell 脚本，可以自动安装缺少的要求，可在以下链接找到：[`github.com/PacktPublishing/Ansible-QuickStart-Guide/blob/master/Chapter2/Upgrade_Powershell.ps1`](https://github.com/PacktPublishing/Ansible-QuickStart-Guide/blob/master/Chapter2/Upgrade_Powershell.ps1)。

为了能够执行此脚本，或任何其他第三方脚本，我们需要将执行策略从受限制改为无限制，运行我们的脚本，然后将策略改回受限制。使用 Windows PowerShell，使用本地或域管理员凭据运行以下命令：

```
$link = "https://raw.githubusercontent.com/jborean93/ansible-windows/master/scripts/Upgrade-PowerShell.ps1"
$script = "$env:temp\Upgrade-PowerShell.ps1"
$username = "Admin"
$password = "secure_password"

(New-Object -TypeName System.Net.WebClient).DownloadFile($link, $script)
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

&$script -Version 5.1 -Username $username -Password $password -Verbose

Set-ExecutionPolicy -ExecutionPolicy Restricted -Force

$reg_winlogon_path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $reg_winlogon_path -Name AutoAdminLogon -Value 0
Remove-ItemProperty -Path $reg_winlogon_path -Name DefaultUserName -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $reg_winlogon_path -Name DefaultPassword -ErrorAction SilentlyContinue
```

然后，在所有 Windows 系统上，第二个脚本是必不可少的，用于配置 WinRM 以激活并监听 Ansible 命令。此脚本可从以下链接下载：[`github.com/PacktPublishing/Ansible-QuickStart-Guide/blob/master/Chapter2/ConfigureRemotingForAnsible.ps1`](https://github.com/PacktPublishing/Ansible-QuickStart-Guide/blob/master/Chapter2/ConfigureRemotingForAnsible.ps1)。

同样，此脚本也需要特权访问，并且执行策略应该是无限制的。运行以下代码：

```
$link = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
$script = "$env:temp\ConfigureRemotingForAnsible.ps1"

(New-Object -TypeName System.Net.WebClient).DownloadFile($link, $script)

powershell.exe -ExecutionPolicy ByPass -File $script
```

如果没有出现错误，Ansible 现在应该能够管理这些机器了。

对于 Windows 主机也是一样的。我们可能需要创建一个仅由 Ansible 使用的本地或域管理员来自由执行命令。其凭据也可以在主机清单组中配置。这可以使用 Ansible Vault 进行安全保护，以防止密码以明文形式写入。

# 总结

在本章中，我们看了如何为多个系统准备环境，以便能够安装 Ansible。我们还考虑了在 Linux 或 Windows 中哪些配置选项最有用。现在我们已经学会了如何设置和配置 Ansible，我们准备开始学习其功能特性。在下一章中，我们将介绍 Ansible playbook 和清单，以更好地理解编排是如何工作的。

# 参考资料

+   Ansible 文档：[`docs.ansible.com/`](https://docs.ansible.com/)


# 第三章：Ansible 清单和 playbook

现在我们已经安装了 Ansible，可以继续进行下一个里程碑。我们现在将探索两个主要功能：Ansible 清单，用于客户端主机组织，以及 Ansible playbooks，演示如何编写 Ansible play 脚本。这两个功能的结合是 Ansible 自动化和编排的基础。本章将介绍如何使用 Ansible 进行快速命令或模块。我们还将看看如何使用其清单来识别和配置主机的访问权限，并将它们静态或动态地分组。最后，我们将介绍 Ansible playbook，并查看其操作、处理程序和变量。我们将涵盖以下主题：

+   使用手动设置主机的简单 Ansible 命令

+   设置我们的第一个 Ansible 静态清单

+   设置和配置组清单

+   设置和配置动态清单

+   Ansible playbook 概述和用法

+   Ansible playbook 最佳实践

+   高级 Ansible playbook 功能

# Ansible 上的基本临时命令

在自动化或编排任务时，Ansible 主要与 playbooks 一起使用，以允许子任务被脚本化并组织在一个方便的管道中。然而，Ansible 也有各种临时命令。这些允许在主机上执行模块，无论它们如何被识别。

安装了 Ansible 之后，可以直接使用临时命令行。可以通过使用原始模块或一些简单的模块（如`ping`或`shell`）来轻松测试它。举个快速的例子，每个 Ansible 实例都可以使用以下命令对自己进行 ping 测试：

```
ansible localhost -m ping
```

我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/74a77b4d-21f1-4c4c-bd5e-8ba11452699b.png)`-m`选项表示任务运行时将使用的模块名称。

有些人可能会质疑 Ansible 临时命令的用处。实际上，它们是测试任务深度的一种很好的方式，从而更容易逐步调试更大任务的较小部分，并捕获错误位置或排除慢请求。对于初学者来说，运行简单的命令可能有助于通过解决简单的任务来掌握工具的基本操作，并逐步提升到更复杂的任务——在开始奔跑之前最好先学会走路。

Ansible 临时命令最常见的用途是运行原始命令。原始命令基本上是要发送到主机或主机的任何 Bash 或 PowerShell 代码：

```
ansible localhost -a "echo 'Hello automated World'"
```

执行命令后，将出现类似以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/d2e5bbab-664b-449e-ad31-69b21f13539b.png)

让我们尝试在不同的主机上运行一个命令。为此，我们需要主机的 IP 地址或完全合格的主机名，以及一个可以复制 SSH 密钥的用户。这可以通过物理复制密钥到用户的`~/.ssh`文件夹来完成，也可以使用第二章中提到的`ssh-copyid`命令来完成，*Ansible 设置和配置*。之后，我们运行以下原始命令来获取有关主机的信息：

```
ansible 192.168.10.10 -a "uname -a" -u setup
```

这个临时命令将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/403e9087-8b8a-4c1f-918b-2be8d9ab2b06.png)

或者，我们可以尝试让主机执行需要超级用户权限的提升任务：

```
ansible 192.168.10.10 -a "apt update" -u setup --become
```

执行上述命令时，输出应该如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/e771ea35-e758-41d8-a7ae-52595b1fc952.png)

如果我们在不使用`--become`选项的情况下使用这个命令，它将失败，并显示`permission denied`错误消息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/bb228bf1-d11b-4c0b-8bbf-00a8f4685143.png)

可以使用 Ansible 模块执行相同的任务。为此，我们使用`-m`选项，后面跟着模块的名称和`-a`选项后的参数，如下例所示：

```
ansible 192.168.10.10 -m apt -a "update_cache=yes" -u setup --become
```

Ansible 还允许您使用`--become`选项以另一个用户身份运行任务，将当前用户提升为超级用户，然后选择要用于运行命令的用户。也可以使用`-e`选项并在其输入中定义变量来完成。两个命令如下：

```
ansible 192.168.10.10 -a "whoami" -u setup --become --become-user user1
ansible 192.168.10.10 -a "whoami" -u setup -e "ansible_user=user1 become=true"
```

执行上述 playbook 时，输出应如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/0ca3ee88-6294-408f-bfaa-59eb7715d795.png)

临时命令也可以用于快速向多台机器传输文件。我们可以使用原始命令，依赖于`scp`或`rsync`，也可以使用 Ansible 的`copy`模块。为了能够在多个主机上执行任务，我们建议使用快速静态清单。可以通过向`/etc/ansible/hosts`文件或 Ansible 配置文件指向的任何其他位置添加几行来完成。文件应如下所示：

```
[servers]
192.168.10.10
192.168.10.11
192.168.10.12
```

将三个主机分组到`servers`名称下，允许我们通过调用它们的组名来在所有三个主机上运行任务。这在以下示例中显示：

```
ansible servers -m copy -a "src=/home/user/file.txt dest=/home/setup/file.txt" -u setup
```

有些任务非常简单，编写 playbook 来完成它们是巨大的时间浪费。此外，任何 Ansible 临时命令都可以转换为 playbook——Ansible 用户可以在将其添加到 playbook 管道或工作流之前尝试一些命令并验证其参数。这是故障排除和在运行时应用快速更新或修复的好方法。以下示例显示了如何通过将 forks 的数量设置为一（使用`-f`选项）逐个重新启动 Web 服务器的副本。这逐个应用重启命令：

```
ansible servers -m service -a "name=httpd state=restarted" -u setup –become -f 1
```

# Ansible 清单

远比所有其他配置管理和编排工具简单。基本上是一个包含主机客户端的 IP 地址、完全合格的主机名或短主机名列表的简单`.ini`文件。有时还包含定义主机某些方面的额外变量。通常，主机以组名放在两个方括号之间组织，例如`[Group1]`。

添加新主机与添加新行到主机文件一样简单，确保它在正确的组中，并且具有管理所需的正确变量。

在默认的 Ansible 配置文件中，清单文件位于`/etc/ansible/hosts`。它是一个`.ini`文件，包含简单的文本和基本结构，由部分、属性和值组成。然而，作为默认位置并不意味着它是最佳位置。在许多情况下，无法编辑位于家目录之外的文件的非根用户可以使用 Ansible。我们建议在用户的家目录内的文件夹中放置所有 Ansible 配置文件。这意味着这些用户可以更改其配置以适应其需求。除了更改 Ansible 配置文件以指向不同的清单位置，我们还可以通过添加`-i`选项，后跟清单文件的位置，来在执行 Ansible 临时命令或 playbook 时选择清单文件：

```
sudo nano /etc/ansible/ansible.cfg
inventory = /home/user1/ansible/hosts
```

或者，我们可以使用以下

```
ansible -m ping -i ~/ansible/hosts
```

Ansible 清单不仅用于安排类似的主机；在编排任务时也更加有用。将提供相同类型服务的多个主机（如 Web 服务器、数据库控制器或 Web API）分组到一个组中，可以实现更智能和高效的组控制。良好的主机分类意味着在对特定服务应用修复或优化时可以更精确。主机可以属于多个组，以便它们可以响应发送到它们拥有的每个特定方面的每个任务：

```
[webserver]
192.168.10.10
192.168.10.12

[mysqldb]
192.168.10.10
192.168.10.20

[fileserver]
192.168.10.11
192.168.10.20
```

Ansible 有两种清单：静态和动态。在小到中等规模的环境或基础设施中，静态清单应该足够了。然而，当主机数量非常多时，任务可能变得复杂，错误可能开始出现。动态清单依赖于第三方服务，比如 AWS EC2、Rackspace 和 OpenStack，来提供清单。总是有可能通过脚本填充 Ansible 静态主机清单文件，如果你知道你在做什么，这可能会很方便。

当向 Ansible 清单文件添加具有相似模式的主机时，我们可以通过将不同模式更改为计数块来简化其语法，如下面的示例所示。

这是原始清单：

```
[servers]
node0.lab.edu
node1.lab.edu
node2.lab.edu
node3.lab.edu
node4.lab.edu
```

这是简化的清单：

```
[servers]
Node[0:4].lab.edu
```

这种清单语法不仅限于特定格式的数字。它也可以用于字母枚举，即`[a:z]`或`[A:Z]`，或具有特定数字的数字，如`[001:250]`。它可以放置在主机名的任何位置。

首先让我们谈谈 Ansible 静态清单。顾名思义，它是一个文本文件中的静态主机组织。默认情况下，它是一个非常简单的`.ini`文件，结构化为带有值的行：

```
node0.lab.edu

[lab1servers]
node1.lab.edu
node2.lab.edu

[lab2servers]
node3.lab.edu
```

或者，它可以是一个 YAML 文件，结构化为 Python 脚本结构：

```
all:
   hosts:
        node0.lab.edu
   children:
        lab1servers:
            hosts:
                 node1.lab.edu
                 node2.lab.edu
        lab2server:
            hosts:
                 node3.lab.edu
```

我们的大多数清单示例将以`.ini`文件格式编写。虽然 YAML 格式看起来更漂亮、更整洁，但在`.ini`格式中编写起来更容易、更快。

主机清单应该对各种类型和形状的主机都具有容忍性。Ansible 清单可以通过引入主机和组变量来容纳这些差异。这基本上是一种定义每个主机或组的特定方面以帮助 Ansible 进行管理的方式。主机变量非常特定于主机，只能影响该主机。最常定义的主机变量如下：

+   `ansible_user`：这个值定义了 Ansible 将使用哪个用户来管理主机。它的功能与`-u`选项相同，该选项用于临时命令。

+   `ansible_host`：有些主机可能不在 DNS 服务器中，或者我们可能想要给它们不同的名称。这个变量允许我们指向主机的 IP 地址，而不用检查我们选择在清单中如何命名它。

+   `ansible_port`：这也被称为`host1:port`。当主机通过某个端口而不是默认端口可访问时使用。

+   `ansible_connection`：这在`ssh`之间变化，是默认连接；`local`，用于与本地机器通信；和`docker`，用于在依赖于本地机器的 Docker 客户端的 Docker 容器中直接运行命令。我们将在第八章中更详细地介绍 Ansible Docker 的用法，*Ansible 高级特性*。

+   `ansible_become`：当存在时，此选项会强制主机以提升的特权（`sudo`）执行所有命令。

+   `ansible_become_user`：这允许 Ansible 以特定用户而不是远程访问用户的身份运行命令。

+   `ansible_ssh_pass`：这指定要用于访问主机的密码。这是不推荐的，因为用户的密码将以明文形式写入。下一个选项更好。

+   `ansible_ssh_private_key_file`：此选项指定要用于访问此 VM 的私有 SSH 密钥的位置。这比以明文形式写入密码更安全。

这是一个示例配置：

```
ansibleserv ansible_connection: local fileserver
ansible_host: 192.168.10.10 ansible_port:22
node1.lab.edu ansible user: setup 
ansible_ssh_private_key:/home/user/node1.key
node2.lab.edu ansible_become: yes
ansible_become_user: user1
```

一些主机变量可以在组标志下定义，特别是当主机共享相同的管理员用户名或 SSH 密钥时。组特定的变量以与主机变量相同的方式定义，以非常简单的文本格式。然而，组变量有一个额外的特性：它们可以以两种方式定义，要么在清单文件中，要么在单独的文件中。默认情况下，Ansible 会在`/etc/ansible/group_vars/`文件夹中查找它们。

在清单文件中定义组变量应该如下所示：

```
[labserver]
node0.lab.edu
node1.lab.edu

[labserver:vars]
ansible_connection=ssh
ansible_port=22
```

在单个主机上运行任务，或者在已定义其变量的组的一部分上运行任务时，这些变量将被应用到主机上，就好像它们是主机变量一样。

主机组也可以在`.ini`文件中使用`:children`后缀和 YAML 文件中的`children:`条目进行组织。这是在 INI 格式中的样子：

```
[webservers]
node0.lab.edu
node1.lab.edu

[fileserver]
node2.lab.edu
node3.lab.edu

[server:children]
webservers
fileserver
```

应用于父组的任何变量都会被展开到每个子组或子组的主机上。但是，子组的变量会覆盖父变量：

```
[servers:vars]
ansible_user=setup
ansible_private_ssh_key=/home/user/ansible.key
```

Ansible 推荐的方法是通过将组变量存储在远离清单文件的`group_vars`文件夹中的单独的 YAML 或 JSON 文件中进行定义。我们主要将使用 YAML 格式的组变量文件，如下所示：

```
/etc/ansible/group_vars/webserver
/etc/ansible/group_vars/fileserver
```

每个文件看起来如下：

```
---
ansible_user=setup
ansible_private_ssh_key=/home/user/ansible.key
```

主机也可以在 YAML 文件中存储它们的变量。默认情况下，这些文件位于`/etc/ansible/host_vars/`文件夹中。它们与组变量文件具有相同的结构。

在 playbook 目录中定义的变量会覆盖清单目录中的变量。我们将在下一节仔细研究 playbook 目录。

Ansible 还支持从其他第三方框架（如云提供商、LDAP 服务器或 Cobbler）导入清单。对于这些情况，需要在选择清单后使用 Ansible 执行特定的导入脚本。这开始了 Ansible 与第三方 API 之间的通信，返回清单列表。在填写了适当的第三方服务器或 API 的`.ini`文件参数后，执行应该发生。

# Ansible playbook

现在事情开始变得有趣起来了。使用 Ansible playbooks，我们将能够实现配置管理、编排、提供和部署。Playbook 脚本使用 Ansible 临时命令以更有组织的方式，类似于 shell 脚本安排 shell 命令来执行系统上的任务，但比那更高级。Ansible playbooks 可以在裸机、虚拟环境或云上设置和配置复杂的环境。它可以对多层机器进行部署；应用系统、设备和应用程序补丁和修复；从主机或监控服务收集数据；并相应地发送立即操作到服务器、网络设备和负载均衡器。所有这些任务可以委托给其他服务器。

Playbooks 以 YAML 数据序列化格式编码。这是一种人类可读的格式，允许开发人员更轻松地共享他们的代码，并作为团队项目的一部分更好地组织。与传统的编码/脚本语言相比，YAML 是一种非常简单的语言。

没有 Ansible 模块的支持，playbooks 不能做太多事情，你可以从 Ansible Galaxy 获取模块，也可以自己构建。模块将在下一章节中详细解释。Playbook 脚本运行多个*plays*。每个 play 执行多个*tasks*，这些 tasks 由 Ansible 清单中的选定主机上的多个模块组成，或者来自外部清单，如果选择了这个选项。这些模块应用特定的配置更改、更新或修复到选定的主机，取决于模块的性质。一个简单的 playbook 运行一个 play，其中包含一个模块来更新软件包管理器缓存，如下所示：

```
nano ./playbook/apt_cache.yml
```

然后，我们用以下代码填充它：

```
---
- name: playbook to update Debian Linux package cache
  hosts: servers
  tasks:
  - name: use apt to update its cache
    become: yes
    apt:
       update_cache: yes
```

在编写文件时，YAML 要求非常严格的文件结构。对于 playbook 文件的成功，对齐良好的操作参数非常重要。

我们保存文件，然后运行`ansible-playbook`命令如下：

```
ansible-playbook playbooks/apt-cache.yml
```

playbook 执行的以下输出显示了 playbook 是否对主机进行了更改：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/c4ff726e-e56a-4bf6-9d3e-52236844a51b.png)

如您所见，我们的简单剧本中执行了一个名为收集事实的任务。这是运行模块设置的任务，它收集有关所讨论的主机或主机的所有有用信息。

当不需要时，禁用*gathering facts*任务可以提高剧本的性能。在定义播放时，可以通过添加`gather_facts: False`来实现这一点。

让我们试着分解剧本脚本的结构。首先，让我们解释`name`选项。这是一个可选参数，但强烈建议使用。当将一个简单而有意义的句子写入`name`选项时，它有助于提供有用的剧本描述，以改进用户沟通。在运行剧本时，它也很有帮助，以便查看哪些剧本已经完成，哪些还在处理中。没有使用`name`选项的剧本输出如下所示：

```
---
- hosts: servers
  gather_facts: False
  tasks:
  - apt:
        update_cache: yes
    become: yes
```

执行上述剧本时，输出应如下所示：![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/ecb764c3-0fe8-48ac-b4e2-5e8d88e91cb6.png)

然后是`hosts`参数或行。这用于指向应在其上运行剧本的清单，可以指定特定的组或主机，或者两者兼而有之。在剧本的同一级别内，我们可以在其下填写其他参数。这些参数可以是主机或组变量，用于强制执行其清单文件中配置的参数。当我们在行主机下定义它们时，这些变量可以是特定于播放的：

```
---
- name: playbook to update Debian Linux package cache
  hosts: servers
  remote_user: setup
  become: yes
  tasks:
```

当我们在任务内部定义它们时，它们也可以是特定于任务的：

```
---
- name: playbook to update Debian Linux package cache
  hosts: servers
  tasks:
  - name: use apt to update its cache
    apt:
       update_cache: yes
    become: yes
    become_user: setup
```

然后我们转到任务列表，这基本上是要按顺序执行的列表模块。与剧本类似，可以使用`name:`参数为每个任务命名。这对于文档编写和跟踪任务状态都是强烈推荐的：

```
tasks:
   - name: use apt to update its cache
      apt: update_cache=yes
```

如果任务失败，剧本执行将因失败而停止。在运行非关键任务时，我们可以始终添加`ignore_errors: True`参数来绕过这一点：

```
tasks:
   - name: use apt to update its cache
      apt:
         update_cache: yes
     ignore_errors: True
```

从前面两个示例中可以看出，每个任务的动作行可以以两种不同的方式使用：要么分解，要么一行。您可以根据自己的需求选择使用哪种方式。

最后，处理程序是使剧本独立和自动化的主要因素，用户的交互更少。它们有能力识别变化并相应地采取行动。它们是控制系统行为并运行响应这些行为需求的一种方式：

```
  tasks:
  - name: use apt to update its cache
    apt:
        update_cache: yes
    become: yes
    notify: pkg_installable

 handlers:
  - name: pkg_installable
    apt:
        name: htop
        state: latest
    become: yes
```

执行上述剧本时，输出应如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/bc82679e-452d-4db7-b266-91465d2f475d.png)处理程序也可以放置在监听模式中的任务之前，以便在多个任务触发时启用动作执行。

高级的 Ansible 剧本脚本包括条件和循环语句，为开发人员提供了各种逻辑和模式，可以在他们的剧本中使用。

例如，`when`参数是使用条件实现任务控制的一种方式。考虑以下示例，仅当在正确的 Linux 系列上运行时才运行应用程序更新：

```
  tasks:
  - name: use apt to update all apps for Debian family
    apt:
        name: "*"
        state: latest
        update_cache: yes
    become: yes
    when: ansible_os_family == "Debian"

  - name: use yum to update all apps for Red Hat family
    yum:
        name: '*'
        state: latest
    become: yes
    when: ansible_os_family == "Red Hat"
```

`when`参数条件不仅限于从主机系统收集的值，还可以从任务的执行状态中收集，可以是以下之一：

+   结果失败

+   结果成功

+   结果已被跳过

还有其他各种使用剧本条件的方法。我们将在后面的章节中讨论这些。

循环语句也可以使用。为此，我们将使用`loop`参数。在某些情况下，当我们想对多个条目应用操作时，我们使用`vars:`参数，如下例所示：

```
  tasks:
  - name: use apt to install multiple apps
    apt:
        name: '{{ app }}'
        state: latest
        update_cache: yes
    vars:
        app:
        - htop
        - mc
        - nload
    become: yes
```

这也可以使用`loop`参数完成：

```
  tasks:
  - name: use apt to install multiple apps
    apt:
        name: '{{ item }}'
        state: latest
        update_cache: yes
    loop:
        - htop
        - mc
        - nload
    become: yes
```

在这一章中，我们只是涉及了 Ansible playbook 冰山一角。还有许多更高级的自定义和参数，我们无法在本书中涵盖。Ansible 以其整洁和良好维护的文档而闻名，因此我们建议您查阅更多信息。

# 总结

在本章中，我们看到了如何使用 Ansible 运行快速和简单的命令。然后我们看了一下 Ansible 是如何管理其主机清单的，这有助于我们理解其 playbook 脚本。我们发现了 playbook 的结构以及它们如何用于编排任务。在下一章中，我们将了解 Ansible 模块，并学习它们在 playbook 中执行的所有任务中的重要性。我们将研究 Linux 和 Windows 系统模块，一些网络设备，以及各种可视化和云管理器。

# 参考资料

+   Ansible 博客：[`www.ansible.com/blog`](https://www.ansible.com/blog)

+   Ansible 文档：[`docs.ansible.com/ansible/latest`](https://docs.ansible.com/ansible/latest)

+   Vagrant 和 Ansible 实验室 GitHub 仓库：[`github.com/xanmanning/vagrant-ansible-lab`](https://github.com/xanmanning/vagrant-ansible-lab)


# 第四章：Ansible 模块

为了掌握 Ansible playbook，我们需要了解模块以及它们的用途。Ansible 模块是定义每个 playbook 执行的操作的基本组件。每个模块都被设置为执行一个任务。它们被设计为能够平稳运行，因为它们的所有依赖和要求都被覆盖了。Ansible 模块使用户能够管理多个操作系统、服务、应用程序、数据库、软件包管理器、虚拟化基础设施数据存储和云环境。在本章中，我们将涵盖以下内容：

+   Ansible 模块的使用概述

+   Ansible Linux 模块及其变种

+   实施 Ansible Windows 模块

+   一个常见的构造器：Ansible 网络模块

+   三大云服务提供商的 Ansible 云模块

# Ansible 模块概述

在安装 Ansible 时，用户还将收到一组非常方便的模块。这个集合被称为模块库。这是一个预定义的函数和操作列表，当使用 Ansible 时可以调用，无论是通过临时命令还是运行 playbook。Ansible 用户不仅限于预定义的 Ansible 模块；他们可以很容易地使用 Python 和 JSON 脚本编写自己的模块。与 Ansible 安装一起提供的模块可能被称为任务插件或库插件，但不要将它们误认为实际的 Ansible 插件，这些是允许 Ansible 与其他系统交互的脚本，这是另一章的主题。

Ansible 模块库附带了自己的机器库。使用`ansible-doc`命令，后跟模块的名称，以了解有关其如何使用以及其输出变量的更多信息：

```
ansible-doc apt
```

要列出所有可用的模块，请使用`-l`选项：

```
ansible-doc -l
```

使用模块非常简单。您需要识别模块的名称，然后根据需要输入其参数。并非所有模块都需要参数输入（例如，ping 模块不需要），但大多数模块都需要。对于其他模块，输入参数是可选的，可能允许您个性化操作，比如 Windows 重启模块的情况。例如，让我们看看如何在临时命令和 playbook 模式下执行模块。

# 临时命令与 playbook：ping 模块

如前所述，Ansible 临时命令可用于快速检查，例如运行`ping`命令以检查主机是否正常运行。命令应如下所示：

```
ansible servers -m ping
```

命令的输出将类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/11804c49-8b16-4132-bec9-e4a2660d4cbe.png)

`ping`模块也可以作为更大脚本的一部分在 playbook 中使用，其中`ping`的结果可以被传递为另一个动作的条件。playbook 代码如下：

```
---
- name: Ping module playbook usage
  hosts: servers
  gather_facts: false
  tasks:
    - name: ping the local servers
      ping:
```

这段代码的输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/c2791629-6003-4de6-a25d-0447e964012a.png)

# 临时命令与 playbook：win_reboot 模块

临时命令可以简单地执行，如下面的两个例子所示：

```
ansible winservers -m win_reboot

ansible win servers -m win_reboot –args="msg='Reboot initiated by remote admin' pre_reboot_delay=5"
```

任一命令的结果输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/cf8a919f-c1b1-4375-b052-9363b380e35c.png)

这个 playbook 文件包含了使用相同模块重新启动主机的两种方式：

```
---
- name: Reboot Windows hosts
  hosts: winservers
  fast_gathering: false
  tasks:
    - name: restart Windows hosts with default settings
      win_reboot

    - name: restart Windows hosts with personalized 
      settings
      win_reboot:
        msg: "Reboot initiated by remote admin"
        pre_reboot_delay: 5
```

生成的 playbook 输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/d4910b37-1e9f-48df-a472-074a56dc2680.png)

# 临时命令与 playbook：copy 模块

Ansible `copy`模块可以在临时模式下用于快速运行复制作业：

```
ansible servers -m copy --args="src=./file1.txt dest=~/file1.txt"
```

这个命令的输出应该如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/5656b15f-31ec-45c1-b6a2-300fea96440d.png)

或者，这可以在包含各种选项以获得个性化结果的 playbook 中使用：

```
---
- name: copy a file to hosts
  hosts: servers
  become: true
  fast_gathering: false
  tasks:
    - name: copy a file to the home directory of a user
      copy:
         src: ./file1.txt
         dest: ~/file1.txt
         owner: setup
         mode: 0766
```

# Ansible 模块返回值

返回值是监视和管理任务执行的关键特性。管理员可以确定每个操作的状态，并相应地运行其他任务，无论是修复、改进还是跟进更大的工作。Ansible 模块配备了各种返回值。每个模块都会有通用值和一些额外的特定于模块执行的特定值。这些额外的返回值可以用于许多功能。在 Ansible 中，大多数返回值用作 playbook 条件和循环的输入。这种脚本允许对操作和任务进行流水线处理，以实现自动化配置管理。Ansible 基本上收集了模块执行的有关操作的所有有用输出数据，并将其整理成作为返回值呈现的变量。

没有必要学习这些模块的所有返回值；您可以使用`ansible-doc`命令轻松获取有关每个模块的非常好的文档。或者，使用`module index`查阅官方 Ansible 文档。

至于最常见的返回值，我们可以确定以下内容：

+   `stdout 或 stdout_lines`：这是一个变量，包含使用执行模块（如`raw`、`command`、`shell`或`win_shell`）执行的命令的标准输出。`stdout_lines`具有与`stdout`相同的值和字符串，但它们具有更有组织的输出——一个人类可读的文本分成行。

+   `stderr`或`stderr_lines`：这与`stdout`具有相同的输出源，但这是错误消息输出。如果执行的命令返回错误消息，它将存储在这个变量中。`stderr_lines`也具有与`stderr`相同的输出字符串，但更有组织成行。

+   `changed`：这是返回值，指示任务或操作的状态是否对目标主机进行了更改。它将包含一个`True`或`False`的布尔值。

+   `failed`：这是另一个状态更新返回值，指示任务或操作是否失败。它也是一个布尔值，可以是`True`或`False`。

+   `skipped`：这是另一个状态返回值，指示任务是否已被跳过。当任务由 playbook 条件触发并且条件未满足时会发生这种情况。与其他状态返回值一样，它是一个布尔变量。

+   `rc`：这代表**返回码**。它包含由命令执行模块执行的命令生成的返回码。

+   `results`：这是一个值，在没有循环的任务中不存在。它应该包含用于循环的每个项目的正常模块`result`列表。

+   `invocation`：这是一个包含详细说明模块如何被调用的值。

+   `backup_file`：这是一个值，当模块具有特定的`backup=no|yes`选项时会填充。它指出备份文件创建的位置。

+   `msg`：这是一个包含模块生成的消息的值，发送给 Ansible 用户。

在执行任务时，通用值使用寄存器进行收集，然后通过 playbook 条件函数调用或使用调试器打印：

```
---
- name: Restart Linux hosts if reboot is required after updates
  hosts: servers
  gather_facts: false
  tasks:
    - name: check for updates
      become: yes
      become_method: sudo
      apt: update_cache=yes

    - name: apply updates
      become: yes
      become_method: sudo
      apt: upgrade=yes 

    - name: check if reboot is required
      become: yes
      become_method: sudo
      shell: "[ -f /var/run/reboot-required ]"
      failed_when: False
      register: reboot_required
      changed_when: reboot_required.rc == 0
      notify: reboot

  handlers:
    - name: reboot
      command: shutdown -r now "Ansible triggered reboot after system updated"
      async: 0
      poll: 0
      ignore_errors: true
```

这个 playbook 将有以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/e34e1ccb-dc74-4672-a8b0-e1e4407b9f99.png)

使用调试器，我们可以轻松地指定我们希望打印一个或所有返回值。Playbook 任务应该如下所示：

```
    - name: apply updates
      become: yes
      become_method: sudo
      apt: upgrade=yes
      register: output

    - name: print system update status return value
      debug:
           var: output.changed
```

Ansible 还收集一些额外的值，用于内部 Ansible 功能。这些值是`ansible_facts`、`exception`、`warning`和`deprecations`。它们可以由一些模块添加，以后从寄存器变量中删除并由 Ansible 收集。

# Ansible Linux 模块

我们将从探索 Linux 模块开始。这些是用于管理运行在 Linux 环境上的操作系统、软件包、应用程序和服务的最常用模块的选择。我们将涵盖两个大的 Linux 家族，Debian 和 Red Hat。在本节中，我们将简要概述模块及其有用的功能和特性。我们还将查看此模块的一个有趣用途的 playbook 示例。

我们不会涵盖 Ansible 版本中支持的所有可用模块。您可以通过运行 ansible-doc 命令或在模块索引部分的官方 Ansible 文档中找到这些模块的完整文档。在本书中，我们将尝试涵盖一些执行某些任务所需的社区和 galaxy 模块。

一些模块需要在远程主机上安装一些特定的技术。这些要求中的大多数通常作为基本系统实用程序预安装，而您可以通过使用另一个可以执行类似工作的工具来解决其他问题。例如，当您使用`apt`模块时，要求主机上安装了`aptitude`。Ansible 将使用`apt-get`来执行作业，并向用户发出警告消息，指出 aptitude 不可用。如果未满足要求，Ansible 将确保通知用户。

在使用新模块之前，请务必仔细阅读其文档，并检查是否满足了所有的要求，以确保安全。

# Linux 系统模块

以下是管理 Linux 系统最有用的 Ansible 模块列表。

# 用户管理模块

如其名称所示，此模块用于 Linux 系统上的用户管理。例如，我们将创建一个名为`install`的系统用户的 playbook，以便稍后用于管理远程机器。playbook 脚本如下：

```
---
- name: Linux Module running
  hosts: servers
  become: yes
  gather_facts: false
  tasks:
    - name: create a system user to be used by Ansible
      user:
        name: install
        state: present
        shell: /bin/bash
        group: sudo
        system: yes
        hidden: yes
        ssh_key_file: .ssh/id_rsa
        expires: -1
```

在运行 playbook 时，如果需要额外的输出，可以始终添加`-v`或`-vvv`。以下截图显示了正常运行和使用`-v`选项的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/a9b5b82c-7bc8-4d3b-8021-f67c12025d69.png)

相同的模块也可以用来删除用户，可以通过将他们的状态更改为 absent 或者通过将他们的 shell 更改为`/bin/nologin`来禁用他们。对于一些集群环境，系统共享的一些用户必须具有相同的 UID 才能通过作业处理程序运行任务。`uid`选项可以允许特定用户在创建主机时具有一组特定的 UID，尽管这并不推荐。

模块有许多特殊的返回值，可以与其他模块进行流水线处理。最有用的模块如下：

+   `home`：显示用户的主目录

+   `ssh_public_key`：允许将密钥打印到文件中以供多种用途使用

+   `uid`：显示新创建用户的 UID

# 组管理模块

组模块具有与用户模块相同的输入类型，但影响主机组。这是一个基本模块，用于创建、修改和删除组。它需要三个基本命令来管理组：`groupdadd`、`groupdell`和`groupmod`。

使用非常简单。playbook 脚本应该如下所示：

```
    - name: create a new group
      group:
        name: clustergroup
        state: present
        gid: 1040
```

# 主机名模块

这是另一个简单的模块，它的工作是更改主机名。为了使这个模块更加有趣，我们将使用一些 playbook 功能。此模块需要一个输入，即新的主机名，并更改远程主机的主机名。我们可以使用 playbook 预定义变量`{{ inventory_hostname }}`。此变量调用 Ansible 清单的主机名，并将其与 playbook 一起使用。

首先，我们需要更改清单文件如下所示：

```
[servers]
server0  ansible_host=192.168.10.10     
server1  ansible_host=192.168.10.11    
server2  ansible_host=192.168.10.12
```

然后，我们使用以下的 playbook：

```
    - name: change hostname
      hostname:
        name: "{{ inventory_hostname }}"
```

执行 playbook 后，您可以使用 adhoc Ansible 命令进行简单测试：

```
ansible -m shell -a hostname servers
```

结果应该如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/bd46debc-d9c1-446f-9208-63c539a7d49e.png)

# sysctl 控制模块

这是一个管理`sysctl`属性的模块。由于这个模块可以改变一些内核行为，让我们确保它安全。我们将进行一个配置，使 Linux 服务器充当网关。在本节中，我们不会深入讨论“IPtables”规则。我们将使用一个通用的示例配置，并尝试通过`sysctl`模块应用它。

运行该模块的 playbook 应包含以下内容：

```
    - name: enable IP forwarding on IP version 4
      sysctl:
         name: net.ipv4.ip_forward
         value: 1
        sysctrl_set: yes
        state: present
       reload: yes 
```

当需要在更改后运行`sysctl -p`时，需要一个重新加载选项。通过设置正确的防火墙规则，这个任务将使主机能够从一个网络接口路由数据包到另一个网络接口。

# 服务管理模块

这使得 Linux 系统服务管理：启动、停止、重新加载、重新启动，并启用其系统引导启动。例如，我们将确保所有主机都运行并启用`ntp`（即**网络时间服务**）：

```
    - name: start and enable ntp service
      service:
          name: ntp
          state: started
          enabled: yes
```

# systemd 模块

对于更高级的服务管理，我们可以使用`systemd`作为服务的替代方案。`systemd`模块应该能够在所有 Linux 操作系统上管理服务，因为它具有包含许多有用服务数据的状态特殊返回值的优势。这里展示了一个使用它的示例 playbook：

```
    - name: start and enable ntp service using systemd
      systemd:
        name: ntp
        state: started
        enabled: yes
        masked: no
        daemon_reload: yes
      register: systemd

    - debug:
        var: systemd.status.Description
```

playbook 输出应如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/0d96f8ad-ebf0-4a6b-91fb-0f21b9af94c5.png)

# 内核黑名单管理模块

这个模块允许您管理内核模块和驱动程序的黑名单，这些驱动程序和库将在系统启动时从内核设备驱动程序初始化中排除。对于我们的示例 playbook，当使用 Nvidia GPU 时，我们将执行最常见的黑名单操作之一——黑名单`nouveau`驱动程序：

```
    - name: addling nouveau nvidia driver to the kernel    
      blaklist
      kernel_blacklist:
         name: nouveau
         state: present
```

# cron job 编辑模块

`cron`模块类似于`at`命令，但它为任务的执行提供了更多的时间选项，因为`cron`模块允许您管理`cron.d`和`crontab`。该模块允许创建和删除 crontab 条目以及创建环境变量。至于 playbook 示例，我们将创建一个`cron job`，确保共享文件夹内容具有正确的权限：

```
    - name: setup a cron job
      cron:
         name: "shared folder permission enforcer"
         hour: 0
         minute: 0
         day: *
         job: "chmod -R 777 /media/shared"
         state: present
```

当处理环境变量（如`PATH`或`HOME`）时，这个模块也很方便，用于 crontab 条目：

```
- name: link the cron PATH variable with a new binaries location
  cron:
    name: PATH
    env: yes
    value: /usr/local/app/bin
```

# SSH 授权密钥管理模块

这个模块管理 Linux 主机中特定用户帐户的 SSH 授权密钥。使用 playbook，我们将设置一个新的授权密钥：

```
    - name: add a new authorise SSH key to the user 
     install
      authorized_key:
          user: install
          state: present
          key: "{{ lookup('file', '/home/install
          /.ssh/id_rsa.pub') }}"
```

这个模块支持许多特殊的返回值。它们可以像其他返回值一样用于收集有关主机的关键数据。

# Git 使用模块

这个模块帮助从 Git 存储库部署工具或配置文件。该模块要求远程主机上安装了`git`工具才能正常工作。作为 playbook，我们将克隆 GitHub 上可用的最新版本的 Ansible：

```
    - name: clone Ansible from github
      git:
        repo: https://github.com/ansible/ansible.git
        dest: /usr/local/ansible
        clone: yes
        update: yes 
```

执行该 playbook 应如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/131e42ad-6ef4-42ba-9852-9ab73b796ee7.png)

`git`模块支持一些特殊的返回值，帮助您监视项目的状态。

# SELinux 控制模块

在 Red Hat 环境中，管理 SELinux 甚至在一台机器上都可能是一件麻烦事，更不用说在一系列主机上了。这个 Ansible 模块帮助用户配置 SELinux 模式和策略。

这个模块以及其他一些模块在执行任务后可能需要重新启动。Ansible 将始终让用户知道是否需要重新启动。一些高级模块可能具有集成选项，如果主机需要重新启动，它将自动启动重新启动。

作为一个快速的 playbook 示例，我们将要求 Ansible 使 SELinux 处于宽松模式：

```
    - name: change SELinux to permissive
      selinux:
        policy: targeted
        state: permissive
```

该模块需要在远程主机上安装`libselinux-python`库才能正常工作。该模块还具有自己的特殊返回值，可用作处理程序或其他相关模块的输入。

# Linux 命令模块

在本节中，我们将解决特别复杂的 Linux 命令或者不想搜索模块的任务，或者想使用自己的技术的情况。Ansible 提供了一系列命令执行模块，帮助您向远程主机发送命令。您想要管理环境的方式取决于您；Ansible 只是一个工具，可以使您的工作更加高效。

# 运行原始命令模块

与其他命令模块相比，这个模块在命令行交付方面是最简单的。它基本上通过 SSH 将命令原样发送到远程主机，没有标题或选项。它不支持管道或处理程序，但在将 PowerShell 命令发送到配置为由 Ansible 管理的 Windows 主机时可以使用。

在使用`raw`模块引导 Python 到机器上时，应禁用事实收集。在 playbook 语法中，`become`选项，选择哪个用户将运行任务，与`raw`模块不兼容，因此当命令需要 root 权限时，我们可能需要在命令前添加`sudo`。

使用此模块的简单 playbook 可能如下所示：

```
    - name: run a simple command
      raw: echo "this was written by a raw Ansible 
      module!!" >> ~/raw.txt
```

# 命令执行模块

该模块具有与原始命令模块相同的功能，但更为优化。它允许多个选项，并且可以使用其返回值进行其他任务。作为 playbook 的示例，我们将运行一个命令，然后收集其输出以供以后使用：

```
    - name: run a simple command
      command: cat ~/raw.txt
      register: rawtxt

    - debug: var=rawtxt.stdout
```

playbook 的输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/0061df25-2ae2-40b5-bb4a-c8524e955fb2.png)

该模块缺乏理解特殊环境变量（如`$PATH`）、Linux 管道和重定向特殊字符的能力。如果这对于您的特定用例是必要的，请使用列表中的下一个模块`shell`。

# shell 命令模块

这个模块是最方便的命令模块之一。它不仅允许您运行命令，还可以运行 shell 脚本，并允许您指定工作目录和要执行命令行的 bash 的位置。默认情况下，该模块在`/bin/sh` shell 上运行所有远程命令。以下 playbook 提供了一个很好的例子：

```
    - name: run a simple shell script
      shell: ./shell_script.sh >> ~/shell.txt
      args:
          chdir: /usr/local/
          creates: ~/shell.txt
          executable: /bin/csh
```

Shell 还有一些非常有用的返回值。

# 脚本执行模块

这是另一个在远程节点上运行 shell 脚本的模块。然而，它首先将位于 Ansible 主机上的脚本传输到远程主机，然后再执行它们。该模块在远程主机的 shell 环境中运行脚本，就好像是由主机上的本地用户运行的一样。

该模块支持运行其他类型的脚本，例如 Python、Perl 或 Ruby。看一下以下示例 playbook，展示如何使用它：

```
    - name: execute a script on a remote host
      script: ./shell_script.py –some-argumets "42"
      args:
          creates: ~/shell.txt
          executable: python
```

该模块的功能类似于原始命令模块。它也支持 Windows 远程主机。

# expect 脚本模块

如果您熟悉 expect 脚本编写，这是一个类似的模块，但更简单，规模更大。这是一种处理交互式命令的方式，例如更改密码和 SSH 问题。更改用户密码的 playbook 示例如下：

```
    - name: change user1 password
      expect:
        command: passwd user1
        responses:
          (?i)password: "Ju5tAn07herP@55w0rd":
```

该模块需要在远程主机上安装`pexpect`和`python`。

# Linux 软件包模块

在本节中，我们将展示两种类型的软件包管理器：用于操作系统和编程语言。

# Apt 软件包管理器模块

该模块管理 Debian 家族的软件包，包括 Debian、Ubuntu、LinuxMint、KaliLinux 等。它要求您在远程主机上安装`aptitude`、`python-apt`和`python3-apt`才能正常工作。它具有多个选项和功能，可个性化软件包的安装、删除、升级和索引更新。以下 playbook 仅显示了其中一些功能：

```
    - name: install some packages on a Debian OS
      apt:
          name: "{{ pkg }}"
          state: latest
          update_cache: yes
      vars:
          pkg:
          - aha
          - htop
```

该模块有一些额外的辅助模块，用于帮助额外的存储库和用于受信任证书的密钥。它还具有一些特殊的返回值。

# DNF 软件包管理器模块

该模块控制 Red Hat 家族的新软件包管理器，包括 Red Hat、Fedora、CentOS 和 Scientific Linux。它帮助在本地索引中安装、升级、删除和搜索软件包。以下 playbook 显示了如何使用它：

```
    - name: install a package using dnf
      dnf:
          name: htop
          state: latest
```

该模块要求您在机器上安装`python`、`python-dnf`和`dnf`本身才能正常工作。

# Yum 软件包管理器模块

Yum 是原始的 Red Hat 软件包管理器，今天仍在使用。它还有自己的模块来管理它。与`dnf`一样，它有助于管理软件包和软件包组。以下 playbook 显示了如何启用存储库，然后使用此模块从中安装工具：

```
    - name: add epel repo using yum
      yum:
           name: https://dl.fedoraproject.org/pub/epel
           /epel-release-latest-7.noarch.rpm
          state: present  
        - name: install ansible using yum
          yum:
           name: ansible
           state: present
```

# Homebrew 软件包管理器

Homebrew 是 macOS X 最著名的开源软件包管理器。该模块是为了帮助远程管理 Homebrew 软件包而制作的。可以使用一个简单的 playbook 在 macOS X 上删除软件包：

```
    - name: remove a package using homebrew
      homebrew:
         name: htop
         state: absent
         update_homebrew: yes
```

# PyPI Python 软件包管理器模块

这是我们的第一个语言软件包管理器，可能是最著名的。它管理 Python 软件包和库。它具有各种选项，以满足与 Python 库相关的各种不同要求。要运行此模块，我们需要确保 PyPI 已安装在远程主机上。以下示例 playbook 将显示其中一些：

```
    - name: install a python library from the default 
   repo
      pip:
         name: numpy
         version: 0.3
    - name: install a python library from a github
      pip:
         name: https://github.com/jakubroztocil/httpie
         /archive/master.tar.gz 
```

# Cpanm Perl 软件包管理器模块

与`pip`模块一样，此模块管理 Perl 软件包管理器**Comprehensive Perl Archive Network**（**CPAN**）。它的使用方式相同；您可以从默认存储库或 Web 或本地存档文件安装库或软件包。要运行此模块，我们需要确保远程主机上安装了`cpanminus`。如下示例 playbook 中所示：

```
    - name: install a Perl library on a Linux host
      cpanm:
         name: IO
```

# Linux 文件模块

Linux 文件管理模块具有一些共享特性，可以在多个模块中找到。您可以使用一个模块执行由三个不同操作组成的任务。在本节中，我们将只讨论主要模块，并简要介绍可以执行类似功能的模块。

# 文件和文件夹管理模块

文件模块基本上是管理一切与文件和文件夹组织有关的工具，包括创建、删除、符号链接创建、权限和所有权。

我们已将文件模块链接到**访问控制列表**（**ACL**）模块，这是一个仅在 Linux 环境中的文件和文件夹的权限和所有权上工作的模块，以显示一些任务可以合并。这在以下 playbook 中显示：

```
    - name: create a file with some specific acl
      file:
         path: /usr/local/script.py
         state: touch
         owner: user1
         group: developers
         mode: 0755

    - name: change acl of a file
      acl:
         path: /usr/local/script.py
         entity: user2
         permission: w
         state: present
```

# 数据分发模块（copy、unarchive 和 get_url）

`copy`模块用于将文件从 Ansible 主机传输到远程主机或在远程主机内部进行本地传输。然后是`unarchive`，这是一个存档提取器，然后将文件传输到选定的主机。`get_url`模块基本上是从 Web 位置下载文件作为 HTTP、HTTPS 或 FTP 文件。以下 playbook 显示了如何使用每个模块来实现目标：

```
    - name: copy file from within a remote host
      copy:
         src: /usr/local/script.py
         dest: /home/user1/script.py
         remote_src: yes
         owner: user1
         group: developers
         mode: 0755

    - name: extract an archive into remote hosts
      unarchive:
         src: ~/archive.tar.gz
         dest: /usr/local/
         owner: user1
         group: developers
         mode: 0755

    - name: download an ansible archive to remote hosts
      get_url:
         url: https://github.com/ansible/ansible/archive
         /v2.6.1.tar.gz
         dest: /usr/local/ansible_v2.6.1.tar.gz
         mode: 0777
```

`copy`模块支持备份选项，这在复制配置文件时非常有用；如果出现错误，用户可以随时恢复到原始状态。但是，unarchive 需要在主机上安装`gtar`和`unzip`。所有这些模块都具有特殊的返回值，显示有关任务状态的信息。

# 数据收集模块（fetch）

这是一个颠倒了之前模块功能的模块。此模块有助于从远程主机收集文件并将它们存储在 Ansible 主机中。在收集应用程序和服务日志、用户配置或系统相关文件时非常方便。例如，我们将尝试从每个主机收集一些文件，并将它们组织在主 Ansible 主机中：

```
    - name: Collect user files from remote hosts
      fetch:
         src: /home/user1/.profile
         dest: /home/alibi/user1-profile-{{ 
          inventory_hostname }}
         flat: yes 
```

在管理远程 Windows 主机时，此模块也受支持。它具有可以在您自己的风险下停用以加快传输速度的校验和验证过程。

# 文件编辑模块（lineinfile、replace 和 blockinfile）

这些是您需要执行由工具（如`awk`或`sed`）具有的出色配置文件管理技能的唯一三个模块。`lineinfile`模块查找文件中的特定行并用预定义的正则表达式替换它。`replace`模块替换文件中特定模式的所有实例，`blockinfile`在文件中两个标记行之间插入、修改或删除一个或多个文本行。我们将这三个模块合并在一起，因为它们具有类似的基本功能，但每个模块在执行任务时都有专门的功能。以下 playbook 示例将展示如何使用每个模块来执行特定任务：

```
     - name: change a sudo user to no longer need 
       password with config testing
      lineinfile:
         path: /etc/sudoers
         regexp: '^%sudo\s'
         line: '%sudo ALL=(ALL) NOPASSWD: ALL'
         state: present
         validate: '/usr/sbin/visudo -cf %s'

     - name: change all static ethernet config to use a 
       higher mtu
      replace:
         path: /etc/network/interfaces
         regexp: '^mtu 1400$'
         line: 'mtu 9000'
         backup: yes
         validate: 'systemd reload networking'

     - name: change a static ethernet configuration
      replace:
         path: /etc/network/interfaces
         block: |
             iface eth1 inet dhcp
                   dns-nameserver 8.8.8.8
                   dns-nameserver 8.8.4.4
                   mtu 9000
         backup: yes
         validate: 'systemd reload networking'
```

# Linux 网络模块

在这一部分，我们将发现一些 Linux 系统网络管理模块。

# 网络接口管理模块

此模块是管理 Linux 主机中的`/etc/network/interfaces`文件的一种方式。基本上，它允许您创建、修改和删除网络接口配置。此配置特定于每个标识的网络接口；它不会更改未指定的接口。以下 playbook 向您展示如何对特定接口进行更改：

```
    - name: Change mtu to 1500 for eth1 interface
      Interfaces_file:
         dest: /etc/network/interfaces
         iface: eth1
         option: mtu
         value: 1500
         backup: yes
         state: present
```

如果此任务返回其返回值，用户可以轻松地识别有关接口更改配置的所有信息。

对于更高级的网络管理，请查看`nmcli`模块。它可以管理各种连接和设备类型：以太网、团队、债券和 VLAN。

# 防火墙 UFW 管理模块

这是一个用于 Linux 防火墙 UFW 的 Ansible 管理模块。它基本上管理端口、协议和 IPS 防火墙权限。一个启用特定协议端口的示例 playbook 可以编写如下：

```
    - name: add port 5000 for iperf testing on all hosts
      ufw:
         rule: allow
         port: 5000
         proto: tcp
```

此模块需要在远程主机上安装`ufw`命令行工具。

# HAProxy 控制模块

这是一个管理 HAProxy 服务器的模块，通过套接字命令命令它们启用、禁用、排空和设置后端服务器的权重。禁用一些 HAProxy 服务器的命令示例如下：

```
    - name: disable a haproxy backend host
      haproxy:
         state: disabled
         host: '{{ inventory_hostname }}'
         socket: /usr/loca/haproxy/haproxy.sock
         backend: www
         wait: yes
```

# 唤醒 LAN 触发模块

这是一个打开当前关闭的主机的模块。此功能要求 Ansible 已经收集了有关主机的事实并存储了它们的 MAC 地址信息。以下是一个展示如何使用此模块的 playbook 代码：

```
 - name: start powered off hosts
 wakeonlan:
 mac: "{{ hostvars[inventory_hostname].ansible_default_ipv4.macaddress }}"
 port: 8
 delegate_to: localhost
```

# Linux 存储模块

Ansible 确实提供了一些特定于 Linux 的存储设备和卷管理。

# 文件系统管理模块

此模块在处理虚拟化基础设施时非常方便，但也可以用于裸金属设置。在远程主机上必须已经存在一个磁盘，然后才能使用此模块进行管理。在虚拟环境中，Ansible 或其他管理工具允许您自动将磁盘添加到主机，然后使用此模块进行管理。以下是使用此模块格式化磁盘的 playbook 示例：

```
    - name: create a filesystem from a newly added disk
      filesystem:
         fstype: ext4
         dev: /dev/sdc1
```

查看`lvg`和`lvol`模块，用于 LVM 卷和组管理。在使用虚拟化环境时，LVM 可以简化磁盘管理，特别是处理需要收缩和扩展磁盘空间的系统。

# 设备挂载模块

这可以作为文件系统的补充模块。它对于管理特定主机系统上的卷挂载也非常有用。这个模块管理`/etc/fstab`：

```
    - name: mount the recently added volume to the system
      mount:
         path: /media/disk1
         fstype: ext4
         boot: yes
         state: mounted
         src: /dev/sdc1
```

这个模块还可以处理挂载网络驱动器。这可能需要您安装额外的工具，如 NFS 和 SMB 客户端。

# 磁盘分区模块

这是一个控制分区工具的模块，用于帮助设备分区、收集它们的信息或将它们保存为返回值。以下示例 playbook 显示了如何删除一个分区：

```
    - name: remove a no longer needed partition
      mount:
         device: /dev/sdc
         number: 1
         state: absent
```

# GlusterFS 控制模块

这是一个 Ansible 模块，用于管理跨主机集群的 GlusterFS 卷。它使用户能够根据需要添加、删除、启动、停止和调整卷。以下示例 playbook 显示了如何创建一个新卷：

```
    - name: create a new GlusterFS volume
      gluster_volume:
         status: present
         name: gluster1
         bricks: /bridkes/brik1/g1
         rebalance: yes
         cluster:
            - 192.168.10.10
            - 192.168.10.11
            - 192.168.10.12
         run_once: true
```

# Ansible Windows 模块

从 Linux 模块转移到现在探索的模块，这些模块是 Ansible 用来管理 Windows 桌面和服务器的。确保已经按照准备步骤确保 Windows 主机已准备好被 Ansible 控制。

# Windows 系统模块

让我们从控制 Windows 系统并允许用户管理其不同方面的模块开始。

# Windows 用户和组管理模块

这两个模块用于管理 Windows 主机本地机器的用户和组。以下 playbook 示例显示了如何将每个模式添加到 Windows 主机：

```
---
- name: Windows Module running
  hosts: winservers
  gather_facts: false
  tasks:
    - name: create a new group dev
      win_group:
         name: developers
         description: Development department group
         state: present

    - name: create a new user in the dev group
      win_user:
         name: winuser1
         password: Ju5t@n0th3rP@55w0rd
         state: present
         groups:
             - developers
```

# Windows 注册表编辑模块

Ansible 通过`win_regedit`模块提供对 Windows 主机注册表的远程管理。这允许您创建、编辑和删除注册表键及其值。以下 playbook 显示了如何通过注册表禁用 Windows 自动更新：

```
    - name: disable Windows auto-update
      win_regedit:
         path: HKLM:SOFTWARE\Policies\Microsoft\Windows
         \WindowsUpdate\AU
         name: NoAutoUpdate
         data: 1
         type: binary
```

# Windows 服务管理模块

这个模块允许 Ansible 用户管理和查询 Windows 主机服务。以下是一个 Ansible playbook，展示了如何禁用 Windows 更新服务（不建议，但很方便知道）：

```
    - name: disable Windows update service
      win_service:
         name: wuauserv
         state: stopped
         start_mode: disabled
```

这个模块有返回值，提供有关服务状态的信息。

# Windows 更新和功能管理模块（win_updates、win_hotfix 和 win_feature）

Ansible 使用三个互补模块`win_updates`、`win_hotfix`和`win_feature`来管理 Windows 更新、热修复和功能。这些模块使用系统默认服务和工具，通过命令它们在 playbook 上应用一组任务。以下示例 playbook 有三个示例，演示了如何使用每个模块来安装或启用 Microsoft 工具、修复或功能：

```
    - name: install updates for Windows related    
    applications and tools
      win_updates:
         category_names: 
             - Applications
             - Tools
         state: installed
         reboot: no
      become: yes
      become_user: SYSTEM

    - name: install a specific Windows Hotfix
      win_hotfix:
         hotfix_kb: KB4088786 
         source: C:\hotfixes\windows10.0-kb4088786-
       x64_7e3897394a48d5a915b7fbf59ed451be4b07077c.msu
         state: present

    - name: enable Hyper-V and Write Filter features
      win_feature:
         name: 
             - Hyper-V
             - Unified-Write-Filter
         state: present
```

这些模块的执行会生成特殊的返回值。这些是自动化维护 Windows 主机的关键特性。

这三个模块需要以域或本地管理员组的用户凭据运行。

# Windows Wake-on-LAN 触发模块

就像 Linux 主机的 Wake-on-LAN 模块一样，这个模块将使用它们的 MAC 地址来关闭 Windows 主机。一个示例 Playbook 如下：

```
    - name: start powered off Windows hosts
      win_wakeonlan:
         mac: "{{  
hostvars[inventory_hostname].ansible_default_ipv4.macaddress }}"
         port: 8
      delegate_to: remote_system
```

这个模块将向特定 MAC 地址发送 Wake-on-LAN 魔术数据包。只有配置为接受数据包的主机才会响应。需要 BIOS 或操作系统配置来启用 Wake-on-LAN。

# Windows 防火墙管理模块

这个模块与 Windows 主机的本地防火墙交互，以配置其规则。以下 playbook 显示了如何启用 VNC 协议：

```
    - name: enable the VNC port on the host local 
      firewall
      win_firewall_rule:
         name: VNC
         localport: 5900
         protocol: udp
         direction: in
         action: allow
         state: present
         enabled: yes
```

这个模块也需要由本地或域管理员执行。

# Windows 软件包模块

与 Linux 和统一应用程序安装的所有软件包管理器相比，Windows 主机应用程序管理可能会变得复杂。Ansible 使用其模块来规避这些挑战。

# Chocolatey 控制模块

Chocolatey 是 Windows 系统的第三方软件包管理器。它允许用户使用标准命令安装、删除和更新大量的 Windows 应用程序。Ansible 提供了一个模块，确保 Chocolatey 已安装在系统上，然后开始使用它从其软件包库（[`chocolatey.org/packages`](https://chocolatey.org/packages)）安装所选工具。以下是一个展示`win_chocolatey`模块多种用法的示例 playbook：

```
    - name: setup the latest version of firefox
      win_chocolatey:
         name: firefox
         state: latest

    - name: update all chocolatey installed tools
      win_chocolatey:
         name: all
         state: latest

    - name: remove 7zip
      win_chocolatey:
         name: 7zip
         state: absent
```

# Windows 软件包管理器

这是一个用于安装和删除 MSI 或 EXE 文件的软件包的 Ansible 模块。它允许您使用不同的来源安装软件包，可以是本地计算机、网络共享驱动器或网络。以下示例 playbook 显示了如何安装 Atom：

```
    - name: install atom editor on Windows hosts
      win_package:
         path: C:\app\atom.msi
         arguments: /install /norestart
         state: present
```

该模块替换了旧的、不稳定的模块，如`win_msi`。

# Windows 命令模块

就像 Linux 一样，当需要输入自己的命令并且没有模块可以简化任务时，命令模块可以使任务更加简单。Ansible 提供了以下模块，允许您向远程 Windows 主机发送特定命令。

# Windows 命令模块（win_shell 和 win_command）

这两个 Ansible 模块是向 Windows 主机发送任何 PowerShell 或 bash 命令的最佳方式。`win_shell`模块更适用于运行脚本和长或多行命令，而`command`更适用于运行可能需要额外参数的常规命令。以下 playbook 显示了一个示例代码：

```
    - name: run a PowerShell script on a working 
     directory
      win_shell: C:\scripts\PSscript.ps1
         args:
            chdir: C:\Users\winuser1\Workspace

    - name: execute a PowerShell command on remote 
      Windows hosts
      win_command: (get-service wuauserv | select status 
       | Format-Wide | Out-String).trim()
      register: output

    - debug: var=output.stdout
```

# Windows 任务调度模块

Windows 主机可以通过调度未来任务来进行时间管理。这是一种创建、编辑和删除 Windows 计划任务的方法。以下是 playbook 上的任务调度示例：

```
    - name: schedule running a PowerShell script a 
     specific time
      win_scheduled_task: 
         name: PowerShellscript
         description: Run a script at a specific time
         actions:
         - path: C:\Windows\System32\WindowsPowerShell
           \v1.0\powershell.exe
           arguments: -ExecutionPolicy Unrestricted 
        -NonInteractive -File
         triggers:
         - type: logon
        state: present
        enabled: yes
```

# Windows 文件模块

使用 Ansible 管理 Windows 主机的文件和文件夹与在 Linux 系统上一样简单。它提供了一组模块，满足所有管理需求。

# Windows 文件和文件夹管理模块

这是一个在远程 Windows 主机上创建、更新和删除文件和文件夹的模块。这个示例 playbook 展示了如何管理 Windows 系统上的文件和文件夹：

```
    - name: add a new file
      win_file: 
          path: C:\scripts\PSscript2.ps1
          state: touch
    - name: remove a folder
      win_file: 
          path: C:\scripts\TestScripts
          state: absent
```

该模块不会更改文件权限。要做到这一点，您需要使用`win_share`模块。

# Windows 数据共享模块

这是`win_file`的补充模块。该模块设置、修改和删除 Windows 文件和文件夹的共享权限。这是一个展示远程 Windows 主机上特定文件夹的示例配置的 playbook：

```
 - name: add a new file
 win_share:
 name: devscript
 description: Developers scripts shared folder 
 path: C:\scripts
 list: yes
 full: developers
 read: devops
 deny: marketing
```

该模块仅支持 Windows 8 和 Windows 2012 及更高版本。

# Windows 文件编辑模块

这是 Ansible 模块`lineinfile`的 Windows 版本。它基本上执行相同的任务，根据正则表达式更改文件的特定行，但它专门用于 Windows 主机。以下是一个示例 playbook：

```
    - name: remove a folder
      win_lineinfile: 
          path: C:\scripts\PSscript.ps1
          regexp: '^service='
          line: 'service=wuauserv'
```

# Windows 数据发送模块（win_copy、win_robocopy 和 win_get_url）

这些模块负责将文件传输到 Windows 远程主机。每个模块都有自己的方法将文件传输到目的地。`win_copy`模块将文件从本地计算机或远程主机复制到远程主机的特定位置。`win_robocopy`模块类似于`rsync`，用于同步远程主机内两个文件夹的内容。它可以作为备份解决方案非常方便。`win_get_url`模块将 URL 作为输入，将文件下载到指定位置。

以下 playbook 显示了一些示例案例：

```
    - name: copy a file from one location to other within 
      the Windows hosts
      win_copy: 
          src: C:\scripts\PSscript.ps1
          dest: C:\applications\PSscript.ps1
          remote_src: yes

    - name: backup scripts folder 
      win_copy: 
          src: C:\scripts\
          dest: D:\backup\scripts
          recurse: yes

    - name: backup scripts folder 
      win_get_url: 
          url: https://www.github.com/scripts
          /winscript2.ps1
          dest: C:\scripts\ winscript2.ps1
```

# Ansible 网络模块

使用 Ansible 管理网络设备从未如此简单。拥有一个 playbook，所有模块的统一语言使得专有网络设备的管理非常简单，不需要您学习特定供应商的工具和编程语言。网络管理现在是自动化配置管理策略的一部分。

这是目前由 Ansible 支持的网络专有设备列表：Arista、Avi Networks、Cisco、Citrix NetScaler、Cumulus、Dell EMC、F5、华为、Infoblox、Juniper、Nokia、Mellanox、Lenovo、Palo Alto Networks 和 Pluribus。我们将无法涵盖所有控制这些设备的模块，这可能需要一本专门的书！

作为无代理，Ansible 使用 SSH 和 HTTPS 与设备通信。

对于这一部分，我们只涵盖了 Cisco 标准设备。我们需要为它们创建一个特殊的清单：

```
[ciscosw]
switch0            ansible_hosts=192.168.10.250
switch1            ansible_hosts=192.168.10.251
switch2            ansible_hosts=192.168.10.252

[ciscosw:vars]
ansible_connection=network_cli
ansible_user=admin
ansible_become=yes
ansible_become_method=enable
ansible_network_os=ios
ansible_user=user1
ansible_ssh_pass= "ju5t@n0th3rp@55"
```

还有其他方法可以隐藏 YAML 文件中的明文密码；我们将在接下来的章节中看看它们，关于 Ansible Vault。

# 网络数据传输模块（net_get 和 network_put）

这两个模块允许在控制主机和多个网络设备之间更轻松地传输配置文件。它们可以用于备份或集中配置。这些模块依赖于`scp`命令的功能来进行传输。以下 playbook 中有一个示例：

```
---
- name: Network Module running
  hosts: ciscosw
  tasks:
    - name: backup a running configuration for a cisco 
     switch
      net_get:
          src: running_cfg_{{ inventory_hostname }}.txt
```

# Cisco IOS 命令模块

这个模块帮助用户向运行 IOS 的 Cisco 设备发送命令，可以是路由器、交换机、接入点或防火墙。这个模块还有一个选项，可以在返回超时之前等待条件。以下是一个在 Cisco 设备上执行命令的 playbook 示例：

```
- name: check on the switch network interfaces status
  ios_command:
      commands: show interfaces brief
      wait_for: result[0] contains Loopback0
```

# Cisco ISO 系统配置模块

这个模块允许用户修改 Cisco 设备的 IOS 运行配置。以下示例 playbook 将展示我们如何修改 Cisco 交换机的一些配置：

```
- name: change switch hostname to match the one set in the inventory
  ios_config:
      ines: hostname {{ inventory_hostname }}

- name: change IP helper config for DHCP requests sent into the device
  ios_config:
      lines: ip helper-address 192.168.10.1
```

# Cisco IOS 接口管理模块

这个模块管理 Cisco 网络交换机的接口配置。在以下简单的 playbook 中，我们将配置一个接口并启用它：

```
- name: configure a gigabit interface and make ready to use
  ios_interface:
      name: GigabitEthernet0/1
      description: lab-network-link
      duplex: full
      speed: 1000
      mtu: 9000
      enabled: True
      state: up        
```

# Cisco IOS 静态路由控制模块

正如其名称所示，这个模块管理 Cisco 网络设备上的静态路由配置。我们将在以下示例 playbook 中设置一个静态路由开关：

```
- name: setup a static route on CISCO switches
  ios_static_route:
      prefix: 192.168.11.0
      mask: 255.255.255.0
      next_hop: 192.168.10.1
      state: present
```

# Cisco IOS VLAN 管理模块

这个模块允许在 Cisco 交换机上配置 VLAN。这个示例 playbook 展示了如何将一些网络接口添加到一个 VLAN 中：

```
- name: Add new lab VLAN
  ios_vlan:
      vlan_id: 45
      name: lab-vlan
      state: present

- name: Add network interface to the lab VLAN
  ios_vlan:
      vlan_id: 45
      nterfaces:
         - GigabitEthernet0/1
         - GigabitEthernet0/2
```

# Ansible 云模块

Ansible 已经使得管理虚拟化和云基础设施变得非常容易。它有超过 300 个模块，运行多个 API，旨在涵盖各种云提供商，如亚马逊网络服务、谷歌云平台、OpenStack、微软 Azure、Digital Ocean 和 Linode。这些模块管理环境的多个方面，包括主机的操作系统、网络连接、计算资源和主机配置。

在使用 Ansible 模块与云或虚拟环境时，建议使用动态清单进行更好的管理。

# VMware 模块

Ansible 提供了一系列模块来实现 VMware 基础设施的自动化管理。

我们需要安装`pyVmomi` Python SDK：

```
pip install pyvmomi
```

这些模块用于管理 VMware ESX、ESXi 和 vCenter 服务器。在本节中，我们将描述一些参与管理 VMware 基础设施的最有用的模块。

需要一个清单文件来托管一些数据中心信息：

```
---
[vms:vars]
datacenter: "vcenter.lab.edu"
vcenter_hostname: "vcenter.lab.edu"
vcenter_username: "admin"
vcenter_password: "@dm1np@55w0rd"

[vms]
vm0
vm1
vm2

[esxi_hostname]
esxihost1         esxihost1.lab.edu
esxihost2         esxihost2.lab.edu
```

# VMware 虚拟机管理模块（vmware_guest 和 vsphere_guest）

这个模块允许创建、修改和删除虚拟机。它们还允许对指定的虚拟机进行状态和资源控制，包括电源状态修改和自定义。以下 playbook 示例展示了如何基于模板创建虚拟机：

```
---
- name: VMware Module running
  hosts: vms
  tasks:
    - name: create a new virtual machine from a template
      vmware_guest:
          hostname: "{{ vcenter_hostname }}"
          username: "{{ vcenter_username }}"
          password: "{{ vcenter_password }}"
          validate_certs: False
          folder: /lab-folder
         name: "{{ inventory_hostname }}"
         state: poweredon
         template: debian8_temp
         disk:
         - size_gb: 15
           type: thin
           datastore: labdatastore1
         hardware:
            memory_mb: 1024
            num_cpus: 2
            num_cpu_cores_per_socket: 2
            scsi: paravirtual
            max_connections: 5
            hotadd_cpu: True
            hotremove_cpu: True
            hotadd_memory: True
            hotremove_memory: True
            version: 11
         cdrom:
             type: iso
            iso_path: "[ labdatastore1] /iso_folder/debian8.iso"
         networks:
         - name: Lab Network
         wait_for_ip_address: yes
     delegate_to: localhost
```

`vsphere_guest`模块与`vmware_guest`执行相同的任务，但它是一个不太稳定的传统模块，不支持`vmare_guest`那么多的功能。

# VMware 虚拟机快照管理模块

这个 Ansible 模块实现了虚拟机的自动快照管理。以下 playbook 示例展示了如何在虚拟机上拍摄快照：

```
    - name: create a virtual machine snapshot
      vmware_guest_snapshot:
          hostname: "{{ vcenter_hostname }}"
          username: "{{ vcenter_username }}"
          password: "{{ vcenter_password }}"
          datacentre: vcenter.lab.edu
          validate_certs: False
          folder: /lab-folder
          name: "{{ inventory_hostname }}"
          state: present
          snapshot_name: Post_Fixes
          description: Fixes_done_on_vm
      delegate_to: localhost
```

在处理 VMware 模块时，大小写敏感度非常重要，特别是在处理虚拟机快照时。在稍后调用快照时，请确保其名称完全相同。

# VMware 虚拟机 shell 执行模块

以下模块允许用户通过使用 VMware 工具在虚拟机操作系统上运行命令：

```
    - name: run a command on a running virtual machine
      vmware_guest_snapshot:
          hostname: "{{ vcenter_hostname }}"
          username: "{{ vcenter_username }}"
          password: "{{ vcenter_password }}"
          datacentre: vcenter.lab.edu
          validate_certs: False
          folder: /lab-folder
          vm_id: "{{ inventory_hostname }}"
          vm_username: setup
          vm_password: "@P@55w0rd"
          vm_shell: /bin/service
          vm_shell_args: networking restart
      delegate_to: localhost
```

# VMware 主机电源状态控制模块

该模块管理 VMware 基础设备。ESX/ESXi 主机是计算资源存储的地方。该模块管理主机的电源状态。在维护、更新或修复后安排重启时，这可能非常方便。以下示例 playbook 显示了如何使用该模块：

```
    - name: restart ESXi host
      vmware_guest_snapshot:
          hostname: "{{ vcenter_hostname }}"
          username: "{{ vcenter_username }}"
          password: "{{ vcenter_password }}"
          validate_certs: no
          esxi_hostname: esxihost1.lab.edu
          state: reboot-host
      delegate_to: localhost
```

# Docker 模块

最近的 Ansible 版本引入了几个专门用于 Docker 容器管理的模块。要使用 Docker 的 Ansible 模块，管理主机应安装以下 Python 软件包：

```
pip install 'docker-py>=1.7.0'

pip install 'docker-compose>=1.7.0'
```

在处理 Docker 容器时，最好使用动态清单。

Ansible 最近引入了一个新功能，可以在不使用 Dockerfile 的情况下构建容器。`ansible-container`模块构建容器并通过 playbook 进行部署。

# Docker 容器管理模块

该模块管理在本地计算机或其他主机上运行的 Docker 容器的生命周期。以下 playbook 显示了该模块的工作原理：

```
---
- name: Docker Module running
  hosts: local
  tasks:
    - name: create a container
      docker_container:
          name: debianlinux
          image: debian:9
          pull: yes
          state: present

    - name: start a container
      docker_container:
          name: debianlinux
          state: started
          devices:
            - "/dev/sda:/dev/xvda:rwm"

    - name: stop a container
       docker_container:
          name: debianlinux
          state: stopped
```

# Docker 镜像管理模块

该模块对容器开发者非常有用。它有助于构建、加载、拉取和推送容器镜像到仓库或将容器存档为 tar 文件。以下 playbook 示例显示了可以使用该模块执行的一些可能任务：

```
     - name: pull a container image
       docker_image:
          name: ubuntu:18.04
          pull: yes

     - name: push a container image to docker hub
       docker_image:
          name: labimages/ubuntu
          repository: labimages/ubuntu
          tag: lab18
          push: yes

     - name: remove a container image
       docker_image:
          name: labimages/ubuntu
          state: absent
          tag: lab16
```

# Docker 登录模块

该模块允许用户登录到 DockerHub 或私有仓库。以下 playbook 显示了如何实现这一点：

```
     - name: login to DockerHub
       docker_login:
          username: labuser1
          password: "L@bp@55w0rd"
          email: user1@lab.edu
```

# Amazon AWS 模块

Ansible 允许自动化您的 AWS 云环境，通过大量专门用于 AWS 服务的模块实现实例的动态配置和智能扩展。在本节中，我们将只关注 Amazon AWS EC2。有大量的模块库来管理其他 AWS 服务和其他云提供商的服务，可以在 Ansible 模块索引中找到。

作为先决条件，强烈建议您拥有动态清单。还建议您将访问和秘密密钥存储在`vars_file`中，并可能使用 Ansible Vault 进行保护：

```
---
ec2_access_key: "a_key"
ec2_secret_key: "another_key"
```

您还需要在控制机上安装`boto` Python 库，以与 AWS 服务进行交互：

```
pip install boto
```

# AWS EC2 实例管理模块

该模块允许创建和终止 AWS EC2 实例。以下 playbook 显示了如何创建新的 AWS EC2 实例：

```
---
- name: AWS Module running
  hosts: localhost
  gather_facts: False
  tasks:
    - name: create a new AWS EC2 instance
      ec2:
          key_name: ansible_key
          instance_type: t2.micro
          image: ami-6b3fd60c
          wait: yes
          group: labservers
          count: 2
          vpc_subnet_id: subnet-3ba41052
          assign_public_ip: yes
```

# AWS WC2 AMI 管理模块

该模块有助于注册新的 EC2 AMI 镜像，以便稍后用于实例创建。它还允许在不再需要时注销旧镜像。以下示例 playbook 显示了如何注册 EC2 AMI 镜像：

```
    - name: register an AWS AMI image
      ec2_ami:
          instance_id: i-6b3fd61c
          wait: yes
          name: labami
          tags:
             Name: LabortoryImage
             Service: LabScripts
```

# AWS EC2 密钥管理模块

该模块有助于管理 EC2 密钥对。它有助于创建和删除密钥。以下示例 playbook 向您展示了如何创建密钥：

```
    - name: create an EC@ key pair
      ec2_key:
          name: ansible2-key
          key_material: "{{ lookup('file', '/home/admin
          /.ssh/id_rsa') }}"
          state: present
```

# 总结

在本章中，我们尽量展示了尽可能多的有用模块，并提供了日常活动的示例，以及基于我们的经验的个人评论。更多模块和更高级的功能可以在官方 Ansible 文档中找到。在这里，我们只讨论了官方支持和维护的模块；不可能涵盖社区中所有可用的模块，Ansible Galaxy 平台上的模块，或者 GitHub 项目的全部范围。如果你能想到本章未讨论的任务，可以放心，肯定会有人在其他地方有解决方法。Ansible 拥有开源世界中最大的社区之一；请随意使用。

在下一章中，我们将使用一些工具来进行一些真正的自动化。我们将混合和匹配各种模块在 playbooks 中执行一个复杂的 playbook 来执行通常的日常任务。

# 参考资料

+   Ansible 官方文档网站：[`docs.ansible.com/`](https://docs.ansible.com/)

+   Ansible 模块索引：[`docs.ansible.com/ansible/latest/modules/list_of_all_modules.html`](https://docs.ansible.com/ansible/latest/modules/list_of_all_modules.html)

+   Chocolatey 软件包库：[`chocolatey.org/packages`](https://chocolatey.org/packages)
