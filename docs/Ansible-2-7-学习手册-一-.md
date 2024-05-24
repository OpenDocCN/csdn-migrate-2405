# Ansible 2.7 学习手册（一）

> 原文：[`zh.annas-archive.org/md5/89BF78DDE1DEE382F084F8254DF8B8DD`](https://zh.annas-archive.org/md5/89BF78DDE1DEE382F084F8254DF8B8DD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

信息技术领域是一个快速发展的领域，始终试图加速。为了跟上这一步伐，公司需要能够快速行动并频繁迭代。直到几年前，这主要适用于软件，但现在我们开始看到以类似速度开发基础设施的必要性。未来，我们将需要以软件本身的速度改变我们运行软件的基础设施。

在这种场景下，许多技术（如软件定义的一切，例如存储、网络和计算）将至关重要，但这些技术需要以同样可扩展的方式进行管理，而这种方式将涉及使用 Ansible 和类似产品。

今天，Ansible 非常相关，因为与竞争产品不同，它是无代理的，可以实现更快的部署、更高的安全性和更好的可审计性。

# 本书适用对象

本书适用于希望使用 Ansible 2 自动化其组织基础架构的开发人员和系统管理员。不需要有关 Ansible 的先前知识。

# 本书涵盖内容

第一章，*开始使用 Ansible*，讲解了如何安装 Ansible。

第二章，*自动化简单任务*，讲解了如何创建简单的 Playbook，让您能够自动化一些您每天已经执行的简单任务。

第三章，*扩展至多个主机*，讲解了如何以易于扩展的方式处理 Ansible 中的多个主机。

第四章，*处理复杂部署*，讲解了如何创建具有多个阶段和多台机器的部署。

第五章，*走向云端*，讲解了 Ansible 如何与各种云服务集成，以及如何简化您的生活，为您管理云端。

第六章，*从 Ansible 获取通知*，讲解了如何设置 Ansible 以向您和其他利益相关者返回有价值的信息。

第七章，*创建自定义模块*，讲解了如何创建自定义模块以利用 Ansible 给予你的自由。

第八章，*调试和错误处理*，讲解了如何调试和测试 Ansible 以确保您的 Playbook 总是有效的。

第九章，*复杂环境*，讲解了如何使用 Ansible 管理多个层次、环境和部署。

第十章，*介绍企业级 Ansible*，讲解了如何从 Ansible 管理 Windows 节点，以及如何利用 Ansible Galaxy 来最大化您的生产力。

第十一章，*开始使用 AWX*，解释了 AWX 是什么以及如何开始使用它。

第十二章，*与 AWX 用户、权限和组织一起工作*，解释了 AWX 用户和权限管理的工作原理。

# 要充分利用本书

本书假定您具有 UNIX shell 的基本知识，以及基本的网络知识。

# 下载示例代码文件

您可以从 [www.packt.com](http://www.packt.com) 的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问 [www.packt.com/support](http://www.packt.com/support) 并注册，以便将文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册，网址为 [www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载完成后，请确保使用最新版本的软件解压或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，网址为 [`github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition`](https://github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition)。如果代码有更新，将在现有的 GitHub 存储库中更新。

我们还有来自丰富书籍和视频目录的其他代码包可供使用。请查看：**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。以下是一个示例："`sudo` 命令是一个众所周知的命令，但通常以更危险的形式使用。"

代码块设置如下：

```
- hosts: all 
  remote_user: vagrant
  tasks: 
    - name: Ensure the HTTPd package is installed 
      yum: 
        name: httpd 
        state: present 
      become: True 
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项将加粗显示：

```
- hosts: all 
  remote_user: vagrant
  tasks: 
    - name: Ensure the HTTPd package is installed 
      yum: 
        name: httpd 
        state: present 
      become: True
```

任何命令行输入或输出都按如下方式编写：

```
$ sudo dnf install ansible
```

警告或重要提示如下。

技巧和提示如下。

# 联系我们

我们始终欢迎读者的反馈。

**一般反馈**：如果您对本书的任何方面有疑问，请在邮件主题中提及书名，并发送邮件至`customercare@packtpub.com`。

**勘误**：尽管我们已尽一切努力确保内容准确无误，但错误难免会发生。如果您在本书中发现错误，我们将不胜感激。请访问 [www.packt.com/submit-errata](http://www.packt.com/submit-errata)，选择您的书籍，点击勘误提交表链接，并输入详细信息。

**盗版**：如果您在互联网上发现我们作品的任何形式的非法副本，我们将不胜感激您提供位置地址或网站名称。请通过`copyright@packt.com`联系我们，并提供材料链接。

**如果您有兴趣成为作者**：如果您有专业知识并对撰写或为书籍做贡献感兴趣，请访问 [authors.packtpub.com](http://authors.packtpub.com/)。

# 评论

请留下您的评论。当您阅读并使用了本书后，为何不在您购买的网站上留下评论呢？潜在的读者可以看到并使用您的客观意见来做出购买决定，我们在 Packt 公司可以了解您对我们产品的看法，而我们的作者也可以看到您对他们的书的反馈。谢谢！

欲了解有关 Packt 的更多信息，请访问 [packt.com](http://www.packt.com/)。


# 第一章：第一节：使用 Ansible 创建 Web 服务器

本节将帮助您创建简单的 Playbooks，使您能够自动化一些您每天已经执行的简单任务。

本节包括以下章节：

+   第一章，*开始使用 Ansible*

+   第二章，*自动化简单任务*


# 第二章：使用 Ansible 入门

**信息和通信技术**（**ICT**）通常被描述为一个快速增长的行业。我认为 ICT 行业最好的特质与其能够以超高速度增长无关，而是与其能够以惊人的速度革新自身和世界其他部分的能力有关。

每隔 10 到 15 年，该行业都会发生重大转变，每次转变都会解决之前非常难以管理的问题，从而带来新的挑战。此外，在每次重大转变中，许多先前迭代的最佳实践被归类为反模式，并创建了新的最佳实践。虽然这些变化可能看起来无法预测，但这并不总是正确的。显然，不可能准确地知道将发生什么变化以及何时会发生，但通常观察拥有大量服务器和许多代码行的公司可以揭示下一步的走向。

当前的转变已经在亚马逊网络服务(Amazon Web Services, AWS)、Facebook 和谷歌等大公司中发生。这是实施 IT 自动化系统来创建和管理服务器。

在本章中，我们将涵盖以下主题：

+   IT 自动化

+   什么是 Ansible？

+   安全外壳

+   安装 Ansible

+   使用 Vagrant 创建测试环境

+   版本控制系统

+   使用 Ansible 与 Git

# 技术要求

为了支持学习 Ansible，建议拥有一台可以安装 Vagrant 的机器。使用 Vagrant 将允许您尝试许多操作，甚至是破坏性操作，而不必担心。

此外，建议拥有 AWS 和 Azure 帐户，因为其中一些示例将在这些平台上展示。

本书中的所有示例都可以在 GitHub 仓库中找到：[`github.com/PacktPublishing/-Learning-Ansible-2.X-Third-Edition/`](https://github.com/PacktPublishing/-Learning-Ansible-2.X-Third-Edition/)。

# IT 自动化

**IT 自动化**在更广泛的意义上是指帮助管理 IT 基础设施（服务器、网络和存储）的过程和软件。在当前的转变中，我们正在支持大规模实施这些过程和软件。

在 IT 历史的早期阶段，服务器数量很少，需要很多人来确保它们正常工作，通常每台机器需要多于一个人。随着时间的推移，服务器变得更可靠、更容易管理，因此可以有一个系统管理员管理多个服务器。在那个时期，管理员手动安装软件，手动升级软件，并手动更改配置文件。这显然是一个非常耗时且容易出错的过程，因此许多管理员开始实施脚本和其他手段来简化他们的生活。这些脚本通常非常复杂，而且不太容易扩展。

在本世纪初，由于公司的需求，数据中心开始快速增长。虚拟化有助于降低成本，而且许多这些服务都是 Web 服务，这意味着许多服务器彼此非常相似。此时，需要新的工具来替代以前使用的脚本：配置管理工具。

**CFEngine** 是在上世纪九十年代展示配置管理功能的第一个工具；最近，除了 Ansible 还有 Puppet、Chef 和 Salt。

# IT 自动化的优点

人们常常疑惑 IT 自动化是否真的带来足够的优势，考虑到实施它存在一些直接和间接的成本。IT 自动化的主要好处包括：

+   快速提供机器的能力

+   能够在几分钟内从头开始重建一台机器的能力

+   能够追踪对基础设施进行的任何更改

凭借这些优点，通过减少系统管理员经常执行的重复操作，可以降低管理 IT 基础设施的成本。

# IT 自动化的缺点

与任何其他技术一样，IT 自动化也存在一些缺点。从我的角度来看，这些是最大的缺点：

+   自动化曾经用于培训新的系统管理员的所有小任务。

+   如果发生错误，它将在所有地方传播。

第一个的结果是需要采取新的方法来培训初级系统管理员。

第二个问题更棘手。有很多方法来限制这种损害，但没有一种方法能完全防止。以下是可用的缓解选项：

+   **始终备份**：备份无法防止你毁掉你的机器 - 它们只能使恢复过程成为可能。

+   **始终在非生产环境中测试你的基础设施代码（playbooks/roles）**：公司已经开发了不同的流程来部署代码，通常包括开发、测试、暂存和生产等环境。使用相同的流程来测试您的基础设施代码。如果有一个有错误的应用程序到达生产环境，可能会有问题。如果有一个有错误的 playbook 到达生产环境，情况就可能变得灾难性。

+   **始终对基础设施代码进行同行评审**：一些公司已经引入了对应用代码的同行评审，但很少有公司对基础设施代码进行同行评审。如我之前所说，在我看来，基础设施代码比应用代码更加关键，所以你应该始终对基础设施代码进行同行评审，无论你是否对应用代码进行同行评审。

+   **启用 SELinux**：SELinux 是一个安全内核模块，在所有 Linux 发行版上都可用（默认情况下安装在 Fedora、Red Hat Enterprise Linux、CentOS、Scientific Linux 和 Unbreakable Linux 上）。它允许您以非常细粒度的方式限制用户和进程权限。我建议使用 SELinux 而不是其他类似模块（如 AppArmor），因为它能够处理更多情况和权限。SELinux 将防止大量损坏，因为如果配置正确，它将阻止执行许多危险命令。

+   **以有限权限账户运行 playbook**：尽管用户和特权升级方案在 Unix 代码中已经存在了 40 多年，但似乎并不多有公司使用它们。对于所有你的 playbook 使用有限用户，并仅在需要更高权限的命令时提升权限，这样做将有助于防止在尝试清理应用程序临时文件时意外清除机器。

+   **使用水平特权升级**：`sudo` 命令是众所周知的，但通常以更危险的形式使用。`sudo` 命令支持 `-u` 参数，允许您指定要模拟的用户。如果您必须更改属于另一个用户的文件，请不要升级到 `root`，而是升级到该用户。在 Ansible 中，您可以使用 `become_user` 参数来实现这一点。

+   **尽可能不要同时在所有机器上运行 playbook**：分阶段的部署可以帮助您在为时已晚之前检测到问题。许多问题在开发、测试、暂存和 QA 环境中无法检测到。其中大多数与在这些非生产环境中无法正确模拟的负载相关。您刚刚添加到 Apache HTTPd 或 MySQL 服务器的新配置可能从语法上来说是完全正确的，但对您的生产负载下的特定应用程序来说可能是灾难性的。分阶段的部署将允许您在实际负载下测试您的新配置，而不会在出现问题时造成停机。

+   **避免猜测命令和修改器**：许多系统管理员会尝试记住正确的参数，并在记不清楚时尝试猜测。我也经常这样做，但这是非常危险的。查看手册页或在线文档通常不会花费您两分钟，而且通常通过阅读手册，您会发现您不知道的有趣笔记。猜测修改器是危险的，因为您可能会被非标准的修改器所愚弄（即 `-v` 不是 `grep` 的详细模式，而 `-h` 不是 MySQL CLI 的 `help` 命令）。

+   **避免容易出错的命令**：并非所有命令都是平等创建的。一些命令（远远）比其他命令更危险。如果你可以假设一个基于 `cat` 的命令是安全的，那么你必须假设一个基于 `dd` 的命令是危险的，因为它执行文件和卷的复制和转换。我见过有人在脚本中使用 `dd` 来将 DOS 文件转换为 Unix（而不是 `dos2unix`）等许多其他非常危险的例子。请避免这样的命令，因为如果出了问题，可能会导致巨大的灾难。

+   **避免不必要的修改器**：如果你需要删除一个简单的文件，使用 `rm ${file}`，而不是 `rm -rf ${file}`。后者经常被那些已经学会*确保安全，总是使用* `rm -rf` 的用户执行，因为在他们过去的某个时候，他们曾经需要删除一个文件夹。如果 `${file}` 变量设置错误，这将防止你删除整个文件夹。

+   **始终检查变量未设置时可能发生的情况**：如果你想删除文件夹的内容，并且你使用 `rm -rf ${folder}/*` 命令，那你就是在找麻烦。如果某种原因导致 `${folder}` 变量未设置，shell 将读取一个 `rm -rf /*` 命令，这是致命的（考虑到 `rm -rf /` 命令在大多数当前操作系统上不起作用，因为它需要一个 `--no-preserve-root` 选项，而 `rm -rf /*` 将按预期工作）。我使用这个特定的命令作为示例，因为我见过这样的情况：变量是从一个由于一些维护工作而关闭的数据库中提取出来的，然后给该变量赋了一个空字符串。接下来会发生什么，可能很容易猜到。如果你不能阻止在危险的地方使用变量，至少检查它们是否为空，然后再使用。这不会挽救你免受每一个问题的困扰，但可能会避免一些最常见的问题。

+   **仔细检查你的重定向**：重定向（连同管道）是 Unix shell 中最强大的元素。它们也可能非常危险：一个 `cat /dev/rand > /dev/sda` 可以摧毁一个磁盘，即使一个基于 `cat` 的命令通常被忽视，因为它通常不危险。始终仔细检查包含重定向的所有命令。

+   **尽可能使用特定的模块**：在这个列表中，我使用了 shell 命令，因为很多人会试图将 Ansible 当作一种分发它们的方式：这不是。Ansible 提供了很多模块，我们将在本书中看到它们。它们将帮助你创建更可读、可移植和安全的 playbooks。

# IT 自动化的类型

有很多方法可以对 IT 自动化系统进行分类，但迄今为止最重要的是与配置如何传播有关。基于此，我们可以区分基于代理的系统和无代理的系统。

# 基于代理的系统

基于代理的系统有两个不同的组件：一个**服务器**，和一个称为**代理**的客户端。

只有一个服务器，它包含了整个环境的所有配置，而代理与环境中的机器数量一样多。

在某些情况下，可能会出现多个服务器以确保高可用性，但要将其视为单个服务器，因为它们将以相同的方式配置。

客户端定期会联系服务器，以查看是否存在其机器的新配置。如果有新配置存在，客户端将下载并应用它。

# 无代理系统

在无代理系统中，不存在特定的代理。无代理系统并不总是遵循服务器/客户端范式，因为可能存在多个服务器，甚至可能有与服务器数量相同的服务器和客户端。通信是由服务器初始化的，它将使用标准协议（通常是通过 SSH 和 PowerShell）联系客户端。

# 基于代理与无代理系统

除了先前概述的差异之外，还有其他由于这些差异而产生的对比因素。

从安全性的角度来看，基于代理的系统可能不太安全。由于所有机器都必须能够启动与服务器机器的连接，因此这台机器可能比无代理情况下更容易受到攻击，而后者通常位于不会接受任何传入连接的防火墙后面

从性能的角度来看，基于代理的系统存在使服务器饱和的风险，因此部署可能较慢。还需要考虑到，在纯代理系统中，不可能立即向一组机器推送更新。它将不得不等待这些机器进行检查。因此，多个基于代理的系统已经实现了超出带外方式来实现这些功能。诸如 Chef 和 Puppet 之类的工具是基于代理的，但也可以在没有集中式服务器的情况下运行，以扩展大量的机器，分别称为**无服务器 Chef**和**无主 Puppet**。

无代理系统更容易集成到已有的基础设施（褐地）中，因为客户端会将其视为普通的 SSH 连接，因此不需要额外的配置。

# 什么是 Ansible？

**Ansible**是一种无代理 IT 自动化工具，由前红帽公司的员工 Michael DeHaan 于 2012 年开发。Ansible 的设计目标是尽可能精简、一致、安全、高度可靠和易于学习。Ansible 公司于 2015 年 10 月被红帽公司收购，现在作为红帽公司的一部分运营。

Ansible 主要使用 SSH 以推送模式运行，但您也可以使用 `ansible-pull` 运行 Ansible，在每个代理上安装 Ansible，本地下载 playbooks，并在各个机器上运行它们。如果有大量的机器（大量是一个相对的术语；但在这种情况下，将其视为大于 500 台），并且您计划并行部署更新到机器上，则可能是正确的方法。正如我们之前讨论过的，无论是代理模式还是无代理系统都有其优缺点。

在下一节中，我们将讨论安全外壳（SSH），这是 Ansible 和 Ansible 理念的核心部分。

# 安全外壳

**安全外壳**（也称为 **SSH**）是一种网络服务，允许您通过完全加密的连接远程登录并访问外壳。今天，SSH 守护程序已成为 UNIX 系统管理的标准，取代了未加密的 telnet。SSH 协议的最常用实现是 OpenSSH。

在过去几年中，微软已为 Windows 实现了 OpenSSH。我认为这证明了 SSH 所处的事实标准情况。

由于 Ansible 以与任何其他 SSH 客户端相同的方式执行 SSH 连接和命令，因此未对 OpenSSH 服务器应用特定配置。

要加快默认的 SSH 连接，您可以始终启用 `ControlPersist` 和管道模式，这使得 Ansible 更快速、更安全。

# 为什么选择 Ansible？

我们将在本书的过程中尝试比较 Ansible 与 Puppet 和 Chef，因为许多人对这些工具有很好的经验。我们还将具体指出 Ansible 如何解决与 Chef 或 Puppet 相比的问题。

Ansible、Puppet 和 Chef 都是声明性的，期望将一台机器移动到配置中指定的期望状态。例如，在这些工具中的每一个中，为了在某个时间点启动服务并在重新启动时自动启动，您需要编写一个声明性的块或模块；每次工具在机器上运行时，它都会努力获得您的 **playbook**（Ansible）、**cookbook**（Chef）或 **manifest**（Puppet）中定义的状态。

在简单水平上，工具集之间的差异很小，但随着情况的增多和复杂性的增加，您会开始发现不同工具集之间的差异。在 Puppet 中，您不设置任务执行的顺序，Puppet 服务器会在运行时决定序列和并行执行，这使得最终可能出现难以调试的错误变得更加容易。要利用 Chef 的功能，您需要一个优秀的 Ruby 团队。您的团队需要擅长 Ruby 语言，以定制 Puppet 和 Chef，而且使用这两种工具会有更大的学习曲线。

与 Ansible 不同的是。它在执行顺序上使用了 Chef 的简单性 - 自上而下的方法 - 并允许你以 YAML 格式定义最终状态，这使得代码极易阅读和易于理解，无论是从开发团队到运维团队，都能轻松掌握并进行更改。在许多情况下，即使没有 Ansible，运维团队也会被给予 playbook 手册，以便在遇到问题时执行指令。Ansible 模仿了那种行为。如果由于其简单性而最终使你的项目经理更改 Ansible 代码并将其提交到 Git，也不要感到惊讶！

# 安装 Ansible

安装 Ansible 相当快速简单。你可以直接使用源代码，从 GitHub 项目 ([`github.com/ansible/ansible`](https://github.com/ansible/ansible)) 克隆；使用系统的软件包管理器进行安装；或者使用 Python 的软件包管理工具 (**pip**)。你可以在任何 Windows 或类 Unix 系统上使用 Ansible，比如 macOS 和 Linux。Ansible 不需要任何数据库，也不需要运行任何守护程序。这使得维护 Ansible 版本和升级变得更容易，而且没有任何中断。

我们想要称呼我们将要安装 Ansible 的机器为 Ansible 工作站。有些人也将其称为指挥中心。

# 使用系统的软件包管理器安装 Ansible

可以使用系统的软件包管理器安装 Ansible，就我个人而言，如果你的系统软件包管理器至少提供了 Ansible 2.0，这是首选选项。我们将研究通过 **Yum**、**Apt**、**Homebrew** 和 **pip** 安装 Ansible。

# 通过 Yum 安装

如果你正在运行 Fedora 系统，你可以直接安装 Ansible，因为从 Fedora 22 开始，Ansible 2.0+ 可以在官方仓库中找到。你可以按照以下步骤安装它：

```
    $ sudo dnf install ansible
```

对于 RHEL 和基于 RHEL 的系统（CentOS、Scientific Linux 和 Unbreakable Linux），版本 6 和 7 在 EPEL 仓库中有 Ansible 2.0+，因此在安装 Ansible 之前，你应该确保已启用 EPEL 仓库，步骤如下：

```
    $ sudo yum install ansible
```

在 RHEL 6 上，你必须运行 `$ sudo rpm -Uvh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm` 命令来安装 EPEL，而在 RHEL 7 上，`$ sudo yum install epel-release` 就足够了。

# 通过 Apt 安装

Ansible 可用于 Ubuntu 和 Debian。要在这些操作系统上安装 Ansible，请使用以下命令：

```
    $ sudo apt-get install ansible
```

# 通过 Homebrew 安装

你可以使用 Homebrew 在 Mac OS X 上安装 Ansible，步骤如下：

```
    $ brew update
    $ brew install ansible
```

# 通过 pip 安装

你可以通过 pip 安装 Ansible。如果你的系统上没有安装 pip，先安装它。你也可以在 Windows 上使用以下命令行使用 pip 安装 Ansible：

```
    $ sudo easy_install pip
```

现在你可以使用 `pip` 安装 Ansible，步骤如下：

```
    $ sudo pip install ansible
```

安装完 Ansible 后，运行 `ansible --version` 来验证是否已经安装：

```
    $ ansible --version
```

从上述命令行输出中，你将得到许多行，如下所示：

```
ansible 2.7.1
 config file = /etc/ansible/ansible.cfg
 configured module search path = [u'/home/fale/.ansible/plugins/modules', u'/usr/share/ansible/plugins/modules']
 ansible python module location = /usr/lib/python2.7/site-packages/ansible
 executable location = /bin/ansible
 python version = 2.7.15 (default, Oct 15 2018, 15:24:06) [GCC 8.1.1 20180712 (Red Hat 8.1.1-5)]
```

# 从源代码安装 Ansible

如果前面的方法不适合您的用例，您可以直接从源代码安装 Ansible。从源代码安装不需要任何 root 权限。让我们克隆一个存储库并激活 `virtualenv`，它是 Python 中的一个隔离环境，您可以在其中安装包而不会干扰系统的 Python 包。存储库的命令和结果输出如下：

```
    $ git clone git://github.com/ansible/ansible.git
    Cloning into 'ansible'...
    remote: Counting objects: 116403, done.
    remote: Compressing objects: 100% (18/18), done.
    remote: Total 116403 (delta 3), reused 0 (delta 0), pack-reused 116384
    Receiving objects: 100% (116403/116403), 40.80 MiB | 844.00 KiB/s, done.
    Resolving deltas: 100% (69450/69450), done.
    Checking connectivity... done.
    $ cd ansible/
    $ source ./hacking/env-setup
    Setting up Ansible to run out of checkout...
    PATH=/home/vagrant/ansible/bin:/usr/local/bin:/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin:/home/vagrant/bin
    PYTHONPATH=/home/vagrant/ansible/lib:
    MANPATH=/home/vagrant/ansible/docs/man:
    Remember, you may wish to specify your host file with -i
    Done!
```

Ansible 需要安装一些 Python 包，您可以使用 `pip` 安装。如果您的系统没有安装 pip，请使用以下命令进行安装。如果您没有安装 `easy_install`，您可以在 Red Hat 系统上使用 Python 的 `setuptools` 包安装它，或者在 macOS 上使用 Brew 安装：

```
    $ sudo easy_install pip
    <A long output follows>
```

安装了 `pip` 后，使用以下命令行安装 `paramiko`、`PyYAML`、`jinja2` 和 `httplib2` 包：

```
    $ sudo pip install paramiko PyYAML jinja2 httplib2
    Requirement already satisfied (use --upgrade to upgrade): paramiko in /usr/lib/python2.6/site-packages
    Requirement already satisfied (use --upgrade to upgrade): PyYAML in /usr/lib64/python2.6/site-packages
    Requirement already satisfied (use --upgrade to upgrade): jinja2 in /usr/lib/python2.6/site-packages
    Requirement already satisfied (use --upgrade to upgrade): httplib2 in /usr/lib/python2.6/site-packages
    Downloading/unpacking markupsafe (from jinja2)
      Downloading MarkupSafe-0.23.tar.gz
      Running setup.py (path:/tmp/pip_build_root/markupsafe/setup.py) egg_info for package markupsafe
    Installing collected packages: markupsafe
      Running setup.py install for markupsafe
        building 'markupsafe._speedups' extension
        gcc -pthread -fno-strict-aliasing -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic -D_GNU_SOURCE -fPIC -fwrapv -DNDEBUG -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic -D_GNU_SOURCE -fPIC -fwrapv -fPIC -I/usr/include/python2.6 -c markupsafe/_speedups.c -o build/temp.linux-x86_64-2.6/markupsafe/_speedups.o
        gcc -pthread -shared build/temp.linux-x86_64-2.6/markupsafe/_speedups.o -L/usr/lib64 -lpython2.6 -o build/lib.linux-x86_64-2.6/markupsafe/_speedups.so
    Successfully installed markupsafe
    Cleaning up...
```

默认情况下，Ansible 将运行在开发分支上。您可能想要切换到最新的稳定分支。使用以下 `$ git branch -a` 命令来检查最新的稳定版本。

复制您想要使用的最新版本。

在撰写时，版本 2.0.2 是最新版本。使用以下命令行检查最新版本：

```
    [node ansible]$ git checkout v2.7.1
    Note: checking out 'v2.0.2'.
    [node ansible]$ ansible --version
    ansible 2.7.1 (v2.7.1 c963ef1dfb) last updated 2018/10/25 20:12:52 (GMT +000)
```

您现在已经准备好了 Ansible 的工作设置。从源代码运行 Ansible 的一个好处是您可以立即享受到新功能，而不必等待软件包管理器为您提供它们。

# 使用 Vagrant 创建测试环境

为了学习 Ansible，我们需要制作相当多的 playbooks 并运行它们。

直接在您的计算机上执行此操作将非常危险。因此，我建议使用虚拟机。

可以在几秒钟内使用云提供商创建测试环境，但通常更有用的是在本地拥有这些机器。为此，我们将使用 Vagrant，这是 Hashicorp 公司提供的一款软件，允许用户独立快速地设置虚拟环境，与本地系统上使用的虚拟化后端无关。它支持许多虚拟化后端（在 Vagrant 生态系统中被称为 *Providers*），例如 Hyper-V、VirtualBox、Docker、VMWare 和 libvirt。这使您可以在任何操作系统或环境中使用相同的语法。

首先，我们将安装 `vagrant`。在 Fedora 上，运行以下代码就足够了：

```
    $ sudo dnf install -y vagrant  
```

在 Red Hat/CentOS/Scientific Linux/Unbreakable Linux 上，我们需要先安装 `libvirt`，然后启用它，然后从 Hashicorp 网站安装 `vagrant`：

```
$ sudo yum install -y qemu-kvm libvirt virt-install bridge-utils libvirt-devel libxslt-devel libxml2-devel libvirt-devel libguestfs-tools-c
$ sudo systemctl enable libvirtd
$ sudo systemctl start libvirtd
$ sudo rpm -Uvh https://releases.hashicorp.com/vagrant/2.2.1/vagrant_2.2.1_x86_64.rpm
$ vagrant plugin install vagrant-libvirt
```

如果您使用的是 Ubuntu 或 Debian，您可以使用以下代码进行安装：

```
    $ sudo apt install virtualbox vagrant
```

对于以下示例，我将虚拟化 CentOS 7 机器。这是出于多种原因；主要原因如下：

+   CentOS 是免费的，与 Red Hat、Scientific Linux 和 Unbreakable Linux 完全兼容。

+   许多公司将 Red Hat/CentOS/Scientific Linux/Unbreakable Linux 用于其服务器。

+   这些发行版是唯一内置 SELinux 支持的发行版，正如我们之前所见，SELinux 可以帮助你使环境更加安全。

为了测试一切是否顺利，我们可以运行以下命令：

```
$ sudo vagrant init centos/7 && sudo vagrant up
```

如果一切顺利，你应该期待一个以这样结尾的输出：

```
==> default: Configuring and enabling network interfaces...
default: SSH address: 192.168.121.60:22
default: SSH username: vagrant
default: SSH auth method: private key
==> default: Rsyncing folder: /tmp/ch01/ => /vagrant
```

所以，你现在可以执行`vagrant ssh`，你会发现自己在刚刚创建的机器中。

当前文件夹中将有一个`Vagrant`文件。在这个文件中，你可以使用`vagrant init`创建指令来创建虚拟环境。

# 版本控制系统

在本章中，我们已经遇到了表达式**基础设施代码**来描述将创建和维护您的基础设施的 Ansible 代码。我们使用基础设施代码这个表达式来区分它与应用代码，后者是组成您的应用程序、网站等的代码。这种区别是为了清晰起见，但最终，这两种类型都是软件能够读取和解释的一堆文本文件。

因此，版本控制系统将会给你带来很多帮助。它的主要优点如下：

+   多人同时在同一项目上工作的能力。

+   进行简单方式的代码审查的能力。

+   拥有多个分支用于多个环境（即开发、测试、QA、暂存和生产）的能力。

+   能够追踪更改，以便我们知道更改是何时引入的，以及是谁引入的。这样一来，几个月或几年后，就更容易理解为什么那段代码存在。

这些优点是由现有的大多数版本控制系统提供给你的。

版本控制系统可以根据它们实现的三种不同模型分为三大类：

+   本地数据模型

+   客户端-服务器模型

+   分布式模型

第一类别，即本地数据模型，是最古老的（大约在 1972 年左右）方法，用于非常特定的用例。这种模型要求所有用户共享相同的文件系统。它的著名示例有**Revision Control System**（**RCS**）和**Source Code Control System**（**SCCS**）。

第二类别，客户端-服务器模型，后来（大约在 1990 年左右）出现，并试图解决本地数据模型的限制，创建了一个遵循本地数据模型的服务器和一组客户端，这些客户端与服务器而不是与存储库本身打交道。这个额外的层允许多个开发人员使用本地文件并将它们与一个集中式服务器同步。这种方法的著名示例是 Apache **Subversion**（**SVN**）和**Concurrent Versions System**（**CVS**）。

第三类别，即分布式模型，于二十一世纪初出现，并试图解决客户端-服务器模型的限制。事实上，在客户端-服务器模型中，您可以脱机工作，但需要在 *在线* 提交更改。分布式模型允许您在本地存储库上处理所有事务（如本地数据模型），并以轻松的方式合并不同机器上的不同存储库。在这种新模型中，可以执行与客户端-服务器模型中的所有操作相同的操作，而且还能够完全脱机工作，以及在同行之间合并更改而不必通过集中式服务器。这种模型的示例包括 BitKeeper（专有软件）、Git、GNU Bazaar 和 Mercurial。

只有分布式模型才能提供的一些额外优势，例如以下内容：

+   即使服务器不可用也可以进行提交、浏览历史记录以及执行任何其他操作的可能性。

+   更容易管理不同环境的多个分支。

当涉及基础设施代码时，我们必须考虑到管理您的基础设施代码的基础设施本身经常保存在基础设施代码中。这是一个递归的情况，可能会引发问题。分布式版本控制系统将防止此问题发生。

关于管理多个分支的简易性，虽然这不是一个硬性规则，但通常分布式版本控制系统比其他类型的版本控制系统具有更好的合并处理能力。

# 使用 Ansible 与 Git

出于我们刚刚看到的原因，以及由于其巨大的流行度，我建议始终使用 Git 作为您的 Ansible 存储库。

我总是向我交谈的人提供一些建议，以便 Ansible 充分利用 Git：

+   **创建环境分支**：创建环境分支，例如开发、生产、测试和预发布，将使您能够轻松跟踪不同环境及其各自的更新状态。我经常建议将主分支保留给开发环境，因为我发现很多人习惯直接向主分支推送新更改。如果您将主分支用于生产环境，人们可能会无意中将更改推送到生产环境，而他们本想将其推送到开发环境。

+   **始终保持环境分支稳定**：拥有环境分支的一个重要优势是可以在任何时刻从头开始销毁和重建任何环境。只有在环境分支处于稳定（非破损）状态时才能实现这一点。

+   **使用功能分支**：为特定的长期开发功能（如重构或其他大的更改）使用不同的分支，这样您就可以在 Git 存储库中保持日常运营，而您的新功能正在进行中（这样您就不会失去对谁做了什么以及何时做了什么的追踪）。

+   **经常推送**：我总是建议人们尽可能经常*推送提交*。这将使 Git 成为版本控制系统和备份系统。我经常看到笔记本电脑损坏、丢失或被盗，其中有数天或数周的未推送工作。不要浪费你的时间——经常推送。而且，经常推送还会更早地检测到合并冲突，合并冲突总是在早期检测到时更容易处理，而不是等待多个更改。

+   **在进行更改后始终部署**：我见过开发人员在基础架构代码中进行更改后，在开发和测试环境中进行了测试，推送到生产分支，然后去吃午饭的情况。他的午餐并不愉快。他的一位同事无意中将代码部署到生产环境（他当时试图部署他所做的小改动），而且没有准备好处理其他开发人员的部署。生产基础架构崩溃了，他们花了很多时间弄清楚一个小小的改动（部署者知道的那个）怎么可能造成如此大的混乱。

+   **选择多个小的更改而不是几个大的更改**：尽可能进行小的更改将使调试更容易。调试基础架构并不容易。没有编译器可以让您看到“明显的问题”（即使 Ansible 执行您的代码的语法检查，也不会执行其他测试），而且查找故障的工具并不总是像您想象的那样好。基础架构即代码范例是新的，工具还不像应用程序代码的工具那样好。

+   **尽量避免二进制文件**：我总是建议将二进制文件保存在 Git 存储库之外，无论是应用程序代码存储库还是基础架构代码存储库。在应用程序代码示例中，我认为保持存储库轻量化很重要（Git 以及大多数版本控制系统对二进制大对象的性能表现不佳），而在基础架构代码示例中，这是至关重要的，因为你会受到诱惑，想要在其中放入大量二进制对象，因为往往将二进制对象放入存储库比找到更干净（和更好）的解决方案更容易。

# 总结

在这一章中，我们已经了解了什么是 IT 自动化，它的优缺点，你可以找到什么样的工具，以及 Ansible 如何融入这个大局。我们还看到了如何安装 Ansible 以及如何创建一个 Vagrant 虚拟机。最后，我们分析了版本控制系统，并谈到了 Git 如何在正确使用时为 Ansible 带来的优势。

在下一章中，我们将开始看到我们在本章中提到的基础架构代码，而不是详细解释它是什么以及如何编写它。我们还将看到如何自动化那些你可能每天都要进行的简单操作，比如管理用户，管理文件和文件内容。


# 第三章：自动化简单任务

如前一章所述，Ansible 可用于创建和管理整个基础架构，也可集成到已经运行的基础架构中。

在本章中，我们将涵盖以下主题：

+   YAML

+   使用 Playbook

+   Ansible 速度

+   Playbook 中的变量

+   创建 Ansible 用户

+   配置基本服务器

+   安装和配置 Web 服务器

+   发布网站

+   Jinja2 模板

首先，我们将讨论**YAML Ain't Markup Language**（**YAML**），这是一种人类可读的数据序列化语言，广泛用于 Ansible。

# 技术要求

您可以从本书的 GitHub 存储库下载所有文件：[`github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter02`](https://github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter02)。

# YAML

YAML，像许多其他数据序列化语言（如 JSON）一样，有着极少的基本概念：

+   声明

+   列表

+   关联数组

声明与任何其他语言中的变量非常相似，如下所示：

```
name: 'This is the name'
```

要创建列表，我们将使用`-`：

```
- 'item1' 
- 'item2' 
- 'item3' 
```

YAML 使用缩进来在逻辑上将父项与子项分隔开来。因此，如果我们想创建关联数组（也称为对象），我们只需要添加一个缩进：

```
item: 
  name: TheName 
  location: TheLocation 
```

显然，我们可以将它们混合在一起，如下所示：

```
people:
  - name: Albert 
    number: +1000000000 
    country: USA 
  - name: David 
    number: +44000000000 
    country: UK 
```

这些是 YAML 的基础知识。YAML 可以做得更多，但目前这些就足够了。

# 你好 Ansible

正如我们在前一章中看到的，可以使用 Ansible 自动化您可能每天已经执行的简单任务。

让我们从检查远程机器是否可达开始；换句话说，让我们从对机器进行 ping 开始。这样做的最简单方法是运行以下命令：

```
$ ansible all -i HOST, -m ping 
```

在这里，`HOST`是您拥有 SSH 访问权限的机器的 IP 地址、**Fully Qualified Domain Name**（**FQDN**）或别名（您可以使用像我们在上一章中看到的 **Vagrant** 主机）。

在`HOST`之后，逗号是必需的，因为否则，它不会被视为列表，而是视为字符串。

在这种情况下，我们执行了针对我们系统上的虚拟机：

```
$ ansible all -i test01.fale.io, -m ping 
```

你应该收到类似这样的结果：

```
test01.fale.io | SUCCESS => {
    "changed": false,
    "ping": "pong"
}
```

现在，让我们看看我们做了什么以及为什么。让我们从 Ansible 帮助开始。要查询它，我们可以使用以下命令：

```
$ ansible --help 
```

为了更容易阅读，我们已删除了与我们未使用的选项相关的所有输出：

```
Usage: ansible <host-pattern> [options]

Options:
  -i INVENTORY, --inventory=INVENTORY, --inventory-file=INVENTORY
                        specify inventory host path or comma separated host
                        list. --inventory-file is deprecated
  -m MODULE_NAME, --module-name=MODULE_NAME
                        module name to execute (default=command)
```

所以，我们所做的是：

1.  我们调用了 Ansible。

1.  我们指示 Ansible 在所有主机上运行。

1.  我们指定了我们的清单（也称为主机列表）。

1.  我们指定了要运行的模块（`ping`）。

现在我们可以 ping 服务器，让我们尝试`echo hello ansible!`，如下命令所示：

```
$ ansible all -i test01.fale.io, -m shell -a '/bin/echo hello ansible!' 
```

你应该收到类似这样的结果：

```
test01.fale.io | CHANGED | rc=0 >>
hello ansible!
```

在此示例中，我们使用了一个额外的选项。让我们检查 Ansible 帮助以查看它的作用：

```
Usage: ansible <host-pattern> [options]
Options:
  -a MODULE_ARGS, --args=MODULE_ARGS
                        module arguments
```

从上下文和名称可以猜到，`args` 选项允许你向模块传递额外的参数。某些模块（如 `ping`）不支持任何参数，而其他模块（如 `shell`）将需要参数。

# 使用 playbooks

**Playbooks** 是 Ansible 的核心特性之一，告诉 Ansible 要执行什么。它们就像 Ansible 的待办事项列表，包含一系列任务；每个任务内部链接到一个称为 **模块** 的代码片段。Playbooks 是简单易读的 YAML 文件，而模块是可以用任何语言编写的代码片段，条件是其输出格式为 JSON。你可以在一个 playbook 中列出多个任务，这些任务将由 Ansible 串行执行。你可以将 playbooks 视为 Puppet 中的清单、Salt 中的状态或 Chef 中的菜谱的等价物；它们允许你输入你想在远程系统上执行的任务或命令列表。

# 研究 playbook 的结构

Playbooks 可以具有远程主机列表、用户变量、任务、处理程序等。你还可以通过 playbook 覆盖大部分配置设置。让我们开始研究 playbook 的结构。

我们现在要考虑的 playbook 的目的是确保 `httpd` 包已安装并且服务已 **启用** 和 **启动**。这是 `setup_apache.yaml` 文件的内容：

```

- hosts: all 
  remote_user: vagrant
  tasks: 
    - name: Ensure the HTTPd package is installed 
      yum: 
        name: httpd 
        state: present 
      become: True 
    - name: Ensure the HTTPd service is enabled and running 
      service: 
        name: httpd 
        state: started 
        enabled: True 
      become: True
```

`setup_apache.yaml` 文件是一个 playbook 的示例。文件由三个主要部分组成，如下所示：

+   `hosts`: 这列出了我们要针对哪个主机或主机组运行任务。hosts 字段是必需的。Ansible 使用它来确定哪些主机将成为列出任务的目标。如果提供的是主机组而不是主机，则 Ansible 将尝试根据清单文件查找属于它的主机。如果没有匹配项，Ansible 将跳过该主机组的所有任务。`--list-hosts` 选项以及 playbook (`ansible-playbook <playbook> --list-hosts`) 将告诉你准确地 playbook 将运行在哪些主机上。

+   `remote_user`: 这是 Ansible 的配置参数之一（例如，`tom' - remote_user`），告诉 Ansible 在登录系统时使用特定用户（在本例中为 `tom`）。

+   `tasks`: 最后，我们来到了任务。所有 playbook 应该包含任务。任务是你想执行的一系列操作。一个 `tasks` 字段包含了任务的名称（即，用户关于任务的帮助文本）、应该执行的模块以及模块所需的参数。让我们看一下在 playbook 中列出的单个任务，如前面代码片段所示。

本书中的所有示例将在 CentOS 上执行，但是对同一组示例进行少量更改后也可以在其他发行版上运行。

在上述情况下，有两个任务。`name`参数表示任务正在做什么，并且主要是为了提高可读性，正如我们在 playbook 运行期间将看到的那样。`name`参数是可选的。`yum`和`service`模块有自己的一组参数。几乎所有模块都有`name`参数（有例外，比如`debug`模块），它表示对哪个组件执行操作。让我们看看其他参数：

+   `state`参数在`yum`模块中保存了最新的值，它表示应该安装`httpd`软件包。执行的命令大致相当于`yum install httpd`。

+   在`service`模块的场景中，带有`started`值的`state`参数表示`httpd`服务应该启动，它大致相当于`/etc/init.d/httpd`启动。在此模块中，我们还有`enabled`参数，它定义了服务是否应该在启动时启动。

+   `become: True`参数表示任务应该以`sudo`访问权限执行。如果`sudo`用户的文件不允许用户运行特定命令，那么当运行 playbook 时，playbook 将失败。

你可能会问，为什么没有一个包模块能够在内部确定架构并根据系统的架构运行`yum`、`apt`或任何其他包选项。Ansible 将包管理器的值填充到一个名为`ansible_pkg_manager`的变量中。

一般来说，我们需要记住，在不同操作系统中具有通用名称的软件包的数量是实际存在的软件包数量的一个很小的子集。例如，`httpd`软件包在 Red Hat 系统中称为`httpd`，但在基于 Debian 的系统中称为`apache2`。我们还需要记住，每个包管理器都有自己的一组选项，使其功能强大；因此，使用明确的包管理器名称更合理，这样终端用户编写 playbook 时就可以使用完整的选项集。

# 运行 playbook

现在，是时候（是的，终于！）运行 playbook 了。为了指示 Ansible 执行 playbook 而不是模块，我们将不得不使用一个语法非常类似于我们已经看到的`ansible`命令的不同命令（`ansible-playbooks`）：

```
$ ansible-playbook -i HOST, setup_apache.yaml
```

如您所见，除了在 playbook 中指定的主机模式（已消失）和模块选项（已被 playbook 名称替换）之外，没有任何变化。因此，要在我的机器上执行此命令，确切的命令如下：

```
$ ansible-playbook -i test01.fale.io, setup_apache.yaml 
```

结果如下：

```
PLAY [all] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [test01.fale.io]

TASK [Ensure the HTTPd package is installed] *************************
changed: [test01.fale.io]

TASK [Ensure the HTTPd service is enabled and running] ***************
changed: [test01.fale.io]

PLAY RECAP ***********************************************************
test01.fale.io                : ok=3 changed=2 unreachable=0 failed=0
```

哇！示例运行成功。现在让我们检查一下`httpd`软件包是否已安装并且现在正在机器上运行。要检查 HTTPd 是否已安装，最简单的方法是询问`rpm`：

```
$ rpm -qa | grep httpd 
```

如果一切正常工作，你应该有如下输出：

```
httpd-tools-2.4.6-80.el7.centos.1.x86_64
httpd-2.4.6-80.el7.centos.1.x86_64
```

要查看服务的状态，我们可以询问`systemd`：

```
$ systemctl status httpd
```

预期结果如下所示：

```
httpd.service - The Apache HTTP Server
 Loaded: loaded (/usr/lib/systemd/system/httpd.service; enabled; vendor preset: disabled)
 Active: active (running) since Tue 2018-12-04 15:11:03 UTC; 29min ago
 Docs: man:httpd(8)
 man:apachectl(8)
 Main PID: 604 (httpd)
 Status: "Total requests: 0; Current requests/sec: 0; Current traffic: 0 B/sec"
 CGroup: /system.slice/httpd.service
 ├─604 /usr/sbin/httpd -DFOREGROUND
 ├─624 /usr/sbin/httpd -DFOREGROUND
 ├─626 /usr/sbin/httpd -DFOREGROUND
 ├─627 /usr/sbin/httpd -DFOREGROUND
 ├─628 /usr/sbin/httpd -DFOREGROUND
 └─629 /usr/sbin/httpd -DFOREGROUND 
```

根据 playbook，已达到最终状态。让我们简要地看一下 playbook 运行过程中确切发生了什么：

```
PLAY [all] ***********************************************************
```

此行建议我们将从这里开始执行 playbook，并且将在所有主机上执行：

```
TASK [Gathering Facts] ***********************************************
ok: [test01.fale.io]
```

`TASK` 行显示任务的名称（在本例中为`setup`）以及其对每个主机的影响。有时，人们会对`setup`任务感到困惑。实际上，如果您查看 playbook，您会发现没有`setup`任务。这是因为在执行我们要求的任务之前，Ansible 会尝试连接到机器并收集有关以后可能有用的信息。正如您所看到的，该任务结果显示为绿色的`ok`状态，因此成功了，并且服务器上没有发生任何更改：

```
TASK [Ensure the HTTPd package is installed] *************************
changed: [test01.fale.io]

TASK [Ensure the HTTPd service is enabled and running] ***************
changed: [test01.fale.io]
```

这两个任务的状态是黄色的，并拼写为`changed`。这意味着这些任务已执行并成功，但实际上已更改了机器上的某些内容：

```
PLAY RECAP ***********************************************************
test01.fale.io : ok=3 changed=2 unreachable=0 failed=0
```

最后几行是 playbook 执行情况的总结。现在让我们重新运行任务，然后查看两个任务实际运行后的输出：

```
PLAY [all] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [test01.fale.io]

TASK [Ensure the HTTPd package is installed] *************************
ok: [test01.fale.io]

TASK [Ensure the HTTPd service is enabled and running] ***************
ok: [test01.fale.io]

PLAY RECAP ***********************************************************
test01.fale.io                : ok=3 changed=0 unreachable=0 failed=0
```

正如您所预期的那样，所涉及的两个任务的输出为`ok`，这意味着在运行任务之前已满足了所需状态。重要的是要记住，许多任务（例如**收集事实**任务）会获取有关系统特定组件的信息，并不一定会更改系统中的任何内容；因此，这些任务之前没有显示更改的输出。

在第一次和第二次运行时，`PLAY RECAP`部分显示如下。在第一次运行时，您将看到以下输出：

```
PLAY RECAP ***********************************************************
test01.fale.io                : ok=3 changed=2 unreachable=0 failed=0
```

第二次运行时，您将看到以下输出：

```
PLAY RECAP ***********************************************************
test01.fale.io                : ok=3 changed=0 unreachable=0 failed=0
```

如您所见，区别在于第一个任务的输出显示`changed=2`，这意味着由于两个任务而更改了系统状态两次。查看此输出非常有用，因为如果系统已达到其所需状态，然后您在其上运行 playbook，则预期输出应为`changed=0`。

如果您在这个阶段考虑了**幂等性**这个词，那么您是完全正确的，并且值得表扬！幂等性是配置管理的关键原则之一。维基百科将幂等性定义为一个操作，如果对任何值应用两次，则其结果与仅应用一次时相同。您在童年时期遇到的最早的例子是对数字`1`进行乘法运算，其中`1*1=1`每次都成立。

大多数配置管理工具都采用了这个原则，并将其应用于基础架构。在大型基础架构中，强烈建议监视或跟踪基础架构中更改任务的数量，并在发现异常时警告相关任务；这通常适用于任何配置管理工具。在理想状态下，你只应该在引入新的更改时看到更改，比如对各种系统组件进行**创建**、**删除**、**更新**或**删除**（**CRUD**）操作。如果你想知道如何在 Ansible 中实现它，继续阅读本书，你最终会找到答案的！

让我们继续。你也可以将前面的任务写成如下形式，但是从最终用户的角度来看，任务非常易读（我们将此文件称为`setup_apache_no_com.yaml`）：

```
--- 
- hosts: all 
  remote_user: vagrant
  tasks: 
    - yum: 
        name: httpd 
        state: present 
      become: True 
    - service: 
        name: httpd 
        state: started 
        enabled: True 
      become: True
```

让我们再次运行 playbook，以发现输出中的任何差异：

```
$ ansible-playbook -i test01.fale.io, setup_apache_no_com.yaml
```

输出将如下所示：

```
PLAY [all] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [test01.fale.io]

TASK [yum] ***********************************************************
ok: [test01.fale.io]

TASK [service] *******************************************************
ok: [test01.fale.io]

PLAY RECAP ***********************************************************
test01.fale.io                : ok=3 changed=0 unreachable=0 failed=0
```

如你所见，区别在于可读性。在可能的情况下，建议尽可能简化任务（**KISS**原则：**保持简单，笨拙**），以确保长期保持脚本的可维护性。

现在我们已经看到了如何编写一个基本的 playbook 并对其运行到主机，让我们看看在运行 playbooks 时会帮助你的其他选项。

# Ansible 详细程度

任何人首先选择的选项之一是调试选项。为了了解在运行 playbook 时发生了什么，你可以使用详细（`-v`）选项运行它。每个额外的`v`将为最终用户提供更多的调试输出。

让我们看一个使用这些选项调试简单`ping`命令（`ansible all -i test01.fale.io, -m ping`）的示例：

+   `-v`选项提供了默认输出：

```
Using /etc/ansible/ansible.cfg as config file
test01.fale.io | SUCCESS => {
    "changed": false, 
    "ping": "pong"
}
```

+   `-vv`选项会提供有关 Ansible 环境和处理程序的更多信息：

```
ansible 2.7.2
  config file = /etc/ansible/ansible.cfg
  configured module search path = [u'/home/fale/.ansible/plugins/modules', u'/usr/share/ansible/plugins/modules']
  ansible python module location = /usr/lib/python2.7/site-packages/ansible
  executable location = /bin/ansible
  python version = 2.7.15 (default, Oct 15 2018, 15:24:06) [GCC 8.1.1 20180712 (Red Hat 8.1.1-5)]
Using /etc/ansible/ansible.cfg as config file
META: ran handlers
test01.fale.io | SUCCESS => {
    "changed": false, 
    "ping": "pong"
}
META: ran handlers
META: ran handlers
```

+   `-vvv`选项提供了更多信息。例如，它显示 Ansible 用于在远程主机上创建临时文件并在远程运行脚本的`ssh`命令。完整脚本可在 GitHub 上找到。

```
ansible 2.7.2
  config file = /etc/ansible/ansible.cfg
  configured module search path = [u'/home/fale/.ansible/plugins/modules', u'/usr/share/ansible/plugins/modules']
  ansible python module location = /usr/lib/python2.7/site-packages/ansible
  executable location = /bin/ansible
  python version = 2.7.15 (default, Oct 15 2018, 15:24:06) [GCC 8.1.1 20180712 (Red Hat 8.1.1-5)]
Using /etc/ansible/ansible.cfg as config file
Parsed test01.fale.io, inventory source with host_list plugin
META: ran handlers
<test01.fale.io> ESTABLISH SSH CONNECTION FOR USER: None
<test01.fale.io> SSH: EXEC ssh -C -o ControlMaster=auto -o 
...
```

现在我们了解了在运行 playbook 时发生了什么，使用详细`-vvv`选项。

# playbook 中的变量

有时，在 playbook 中设置和获取变量是很重要的。

很多时候，你会需要自动化多个类似的操作。在这些情况下，你将想要创建一个可以使用不同变量调用的单个 playbook，以确保代码的可重用性。

另一个情况下变量非常重要的案例是当你有多个数据中心时，一些值将是特定于数据中心的。一个常见的例子是 DNS 服务器。让我们分析下面的简单代码，这将向我们介绍设置和获取变量的 Ansible 方法：

```
- hosts: all 
  remote_user: vagrant
  tasks: 
    - name: Set variable 'name' 
      set_fact: 
        name: Test machine 
    - name: Print variable 'name' 
      debug: 
        msg: '{{ name }}' 
```

让我们以通常的方式运行它：

```
$ ansible-playbook -i test01.fale.io, variables.yaml
```

你应该看到以下结果：

```
PLAY [all] *********************************************************

TASK [Gathering Facts] *********************************************
ok: [test01.fale.io]

TASK [Set variable 'name'] *****************************************
ok: [test01.fale.io]

TASK [Print variable 'name'] ***************************************
ok: [test01.fale.io] => {
 "msg": "Test machine"
}

PLAY RECAP *********************************************************
test01.fale.io              : ok=3 changed=0 unreachable=0 failed=0 
```

如果我们分析刚刚执行的代码，应该很清楚发生了什么。我们设置了一个变量（在 Ansible 中称为 `facts`），然后用 `debug` 函数打印它。

当你使用这个扩展版本的 YAML 时，变量应该总是用引号括起来。

Ansible 允许你以许多不同的方式设置变量 - 也就是说，通过传递一个变量文件，在 playbook 中声明它，使用 `-e / --extra-vars` 参数将它传递给 `ansible-playbook` 命令，或者在清单文件中声明它（我们将在下一章中深入讨论这一点）。

现在是时候开始使用 Ansible 在设置阶段获取的一些元数据了。让我们开始查看 Ansible 收集的数据。为此，我们将执行以下代码：

```
$ ansible all -i HOST, -m setup 
```

在我们特定的情况下，这意味着执行以下代码：

```
$ ansible all -i test01.fale.io, -m setup 
```

显然我们也可以用 playbook 来做同样的事情，但这种方式更快。另外，对于 `setup` 情况，你只需要在开发过程中看到输出以确保使用正确的变量名称来达到你的目标。

输出将会是类似这样的。完整的代码输出可在 GitHub 上找到。

```
test01.fale.io | SUCCESS => {
    "ansible_facts": {
        "ansible_all_ipv4_addresses": [
            "192.168.121.190"
        ], 
        "ansible_all_ipv6_addresses": [
            "fe80::5054:ff:fe93:f113"
        ], 
        "ansible_apparmor": {
            "status": "disabled"
        }, 
        "ansible_architecture": "x86_64", 
        "ansible_bios_date": "04/01/2014", 
        "ansible_bios_version": "?-20180531_142017-buildhw-08.phx2.fedoraproject.org-1.fc28", 
        ...
```

正如你从这个大量选项的列表中所看到的，你可以获得大量的信息，并且你可以像使用任何其他变量一样使用它们。让我们打印操作系统的名称和版本。为此，我们可以创建一个名为 `setup_variables.yaml` 的新 playbook，内容如下：

```

- hosts: all
  remote_user: vagrant
  tasks: 
    - name: Print OS and version
      debug:
        msg: '{{ ansible_distribution }} {{ ansible_distribution_version }}'
```

使用以下代码运行它：

```
$ ansible-playbook -i test01.fale.io, setup_variables.yaml
```

这将给我们以下输出：

```
PLAY [all] *********************************************************

TASK [Gathering Facts] *********************************************
ok: [test01.fale.io]

TASK [Print OS and version] ****************************************
ok: [test01.fale.io] => {
 "msg": "CentOS 7.5.1804"
}

PLAY RECAP *********************************************************
test01.fale.io              : ok=2 changed=0 unreachable=0 failed=0 
```

如你所见，它按预期打印了操作系统的名称和版本。除了之前看到的方法之外，还可以使用命令行参数传递变量。实际上，如果我们查看 Ansible 帮助，我们会注意到以下内容：

```
Usage: ansible <host-pattern> [options]

Options:
  -e EXTRA_VARS, --extra-vars=EXTRA_VARS
                        set additional variables as key=value or YAML/JSON, if
                        filename prepend with @
```

在 `ansible-playbook` 命令中也存在相同的行。让我们创建一个名为 `cli_variables.yaml` 的小 playbook，内容如下：

```
---
- hosts: all
  remote_user: vagrant
  tasks:
    - name: Print variable 'name'
      debug:
        msg: '{{ name }}'
```

使用以下代码执行它：

```
$ ansible-playbook -i test01.fale.io, cli_variables.yaml -e 'name=test01'
```

我们将会收到以下内容：

```
 [WARNING]: Found variable using reserved name: name

PLAY [all] *********************************************************

TASK [Gathering Facts] *********************************************
ok: [test01.fale.io]

TASK [Print variable 'name'] ***************************************
ok: [test01.fale.io] => {
 "msg": "test01"
}

PLAY RECAP *********************************************************
test01.fale.io              : ok=2 changed=0 unreachable=0 failed=0 
```

如果我们忘记添加额外参数来指定变量，我们将会这样执行它：

```
$ ansible-playbook -i test01.fale.io, cli_variables.yaml
```

我们将会收到以下输出：

```
PLAY [all] *********************************************************

TASK [Gathering Facts] *********************************************
ok: [test01.fale.io]

TASK [Print variable 'name'] ***************************************
fatal: [test01.fale.io]: FAILED! => {"msg": "The task includes an option with an undefined variable. The error was: 'name' is undefined\n\nThe error appears to have been in '/home/fale/Learning-Ansible-2.X-Third-Edition/Ch2/cli_variables.yaml': line 5, column 7, but may\nbe elsewhere in the file depending on the exact syntax problem.\n\nThe offending line appears to be:\n\n tasks:\n - name: Print variable 'name'\n ^ here\n"}
 to retry, use: --limit @/home/fale/Learning-Ansible-2.X-Third-Edition/Ch2/cli_variables.retry

PLAY RECAP *********************************************************
test01.fale.io : ok=1 changed=0 unreachable=0 failed=1
```

现在我们已经学会了 playbook 的基础知识，让我们使用它们从头开始创建一个 Web 服务器。为此，让我们从创建一个 Ansible 用户开始，然后从那里继续。

在前面的示例中，我们注意到一个**警告**弹出，通知我们正在重新声明一个保留变量（name）。截至 Ansible 2.7，完整的保留变量列表如下：`add`、`append`、`as_integer_ratio`、`bit_length`、`capitalize`、`center`、`clear`、`conjugate`、`copy`、`count`、`decode`、`denominator`、`difference`、`difference_update`、`discard`、`encode`、`endswith`、`expandtabs`、`extend`、`find`、`format`、`fromhex`、`fromkeys`、`get`、`has_key`、`hex`、`imag`、`index`、`insert`、`intersection`、`intersection_update`、`isalnum`、`isalpha`、`isdecimal`、`isdigit`、`isdisjoint`、`is_integer`、`islower`、`isnumeric`、`isspace`、`issubset`、`issuperset`、`istitle`、`isupper`、`items`、`iteritems`、`iterkeys`、`itervalues`、`join`、`keys`、`ljust`、`lower`、`lstrip`、`numerator`、`partition`、`pop`、`popitem`、`real`、`remove`、`replace`、`reverse`、`rfind`、`rindex`、`rjust`、`rpartition`、`rsplit`、`rstrip`、`setdefault`、`sort`、`split`、`splitlines`、`startswith`、`strip`、`swapcase`、`symmetric_difference`、`symmetric_difference_update`、`title`、`translate`、`union`、`update`、`upper`、`values`、`viewitems`、`viewkeys`、`viewvalues`、`zfill`。

# 创建 Ansible 用户

当您创建一台机器（或从任何托管公司租用一台机器）时，它只带有`root`用户，或其他用户，如`vagrant`。让我们开始创建一个 Playbook，确保创建一个 Ansible 用户，可以使用 SSH 密钥访问它，并且能够代表其他用户（`sudo`）执行操作而无需密码。我们经常将此 Playbook 称为 `firstrun.yaml`，因为我们在创建新机器后立即执行它，但之后我们不再使用它，因为出于安全原因，我们会禁用默认用户。我们的脚本将类似于以下内容：

```
--- 
- hosts: all 
  user: vagrant 
  tasks: 
    - name: Ensure ansible user exists 
      user: 
        name: ansible 
        state: present 
        comment: Ansible 
      become: True
    - name: Ensure ansible user accepts the SSH key 
      authorized_key: 
        user: ansible 
        key: https://github.com/fale.keys 
        state: present 
      become: True
    - name: Ensure the ansible user is sudoer with no password required 
      lineinfile: 
        dest: /etc/sudoers 
        state: present 
        regexp: '^ansible ALL\=' 
        line: 'ansible ALL=(ALL) NOPASSWD:ALL' 
        validate: 'visudo -cf %s'
      become: True
```

在运行之前，让我们稍微看一下。我们使用了三个不同的模块（`user`、`authorized_key` 和 `lineinfile`），这些我们从未见过。

`user` 模块，正如其名称所示，允许我们确保用户存在（或不存在）。

`authorized_key` 模块允许我们确保某个 SSH 密钥可以用于登录到该机器上的特定用户。此模块不会替换已为该用户启用的所有 SSH 密钥，而只会添加（或删除）指定的密钥。如果您想改变此行为，可以使用 `exclusive` 选项，它允许您删除在此步骤中未指定的所有 SSH 密钥。

`lineinfile` 模块允许我们修改文件的内容。它的工作方式与**sed**（流编辑器）非常相似，您指定用于匹配行的正则表达式，然后指定要用于替换匹配行的新行。如果没有匹配的行，则该行将添加到文件的末尾。

现在让我们使用以下代码运行它：

```
$ ansible-playbook -i test01.fale.io, firstrun.yaml
```

这将给我们带来以下结果：

```
PLAY [all] *********************************************************

TASK [Gathering Facts] *********************************************
ok: [test01.fale.io]

TASK [Ensure ansible user exists] **********************************
changed: [test01.fale.io]

TASK [Ensure ansible user accepts the SSH key] *********************
changed: [test01.fale.io]

TASK [Ensure the ansible user is sudoer with no password required] *
changed: [test01.fale.io]

PLAY RECAP *********************************************************
test01.fale.io              : ok=4 changed=3 unreachable=0 failed=0
```

# 配置基本服务器

在为 Ansible 创建了具有必要权限的用户之后，我们可以继续对操作系统进行一些其他小的更改。为了更清晰，我们将看到每个动作是如何执行的，然后我们将查看整个 playbook。

# 启用 EPEL

**EPEL** 是企业 Linux 中最重要的仓库，它包含许多附加软件包。它也是一个安全的仓库，因为 EPEL 中的任何软件包都不会与基本仓库中的软件包发生冲突。

要在 RHEL/CentOS 7 中启用 EPEL，只需安装 `epel-release` 软件包即可。要在 Ansible 中执行此操作，我们将使用以下内容：

```
- name: Ensure EPEL is enabled 
  yum: 
    name: epel-release 
    state: present 
  become: True 
```

如您所见，我们使用了 `yum` 模块，就像我们在本章的第一个示例中所做的那样，指定了软件包的名称以及我们希望它存在。

# 安装 SELinux 的 Python 绑定

由于 Ansible 是用 Python 编写的，并且主要使用 Python 绑定来操作操作系统，因此我们需要安装 SELinux 的 Python 绑定：

```
- name: Ensure libselinux-python is present 
  yum: 
    name: libselinux-python 
    state: present 
  become: True 
- name: Ensure libsemanage-python is present 
  yum: 
    name: libsemanage-python 
    state: present 
  become: True 
```

这可以用更短的方式编写，使用循环，但我们将在下一章中看到如何做到这一点。

# 升级所有已安装的软件包

要升级所有已安装的软件包，我们将需要再次使用 `yum` 模块，但是使用不同的参数；实际上，我们将使用以下内容：

```
- name: Ensure we have last version of every package 
  yum: 
    name: "*" 
    state: latest 
  become: True 
```

正如您所看到的，我们已将 `*` 指定为软件包名称（这代表了一个通配符，用于匹配所有已安装的软件包），并且 `state` 参数为 `latest`。这将会将所有已安装的软件包升级到可用的最新版本。

您可能还记得，当我们谈到 `present` 状态时，我们说它将安装最新可用版本。那么 `present` 和 `latest` 之间有什么区别？`present` 将在未安装软件包时安装最新版本，而如果软件包已安装（无论版本如何），它将继续前进而不进行任何更改。`latest` 将在未安装软件包时安装最新版本，并且如果软件包已安装，它将检查是否有更新版本可用，如果有，则 Ansible 将更新软件包。

# 确保 NTP 已安装、配置并运行

要确保 NTP 存在，我们使用 `yum` 模块：

```
- name: Ensure NTP is installed 
  yum: 
    name: ntp 
    state: present 
  become: True
```

现在我们知道 NTP 已安装，我们应该确保服务器使用我们想要的 `timezone`。为此，我们将在 `/etc/localtime` 中创建一个符号链接，该链接将指向所需的 `zoneinfo` 文件：

```
- name: Ensure the timezone is set to UTC 
  file: 
    src: /usr/share/zoneinfo/GMT 
    dest: /etc/localtime 
    state: link 
  become: True 
```

如您所见，我们使用了 `file` 模块，指定它需要是一个链接（`state: link`）。

要完成 NTP 配置，我们需要启动 `ntpd` 服务，并确保它将在每次后续引导时运行：

```
- name: Ensure the NTP service is running and enabled 
  service: 
    name: ntpd 
    state: started 
    enabled: True 
  become: True 
```

# 确保 FirewallD 存在并已启用

您可以想象，第一步是确保 FirewallD 已安装：

```
- name: Ensure FirewallD is installed 
  yum: 
    name: firewalld 
    state: present 
  become: True
```

由于我们希望在启用 FirewallD 时不会丢失 SSH 连接，因此我们将确保 SSH 流量始终可以通过它传递：

```
- name: Ensure SSH can pass the firewall 
  firewalld: 
    service: ssh 
    state: enabled 
    permanent: True 
    immediate: True 
  become: True
```

为此，我们使用了`firewalld`模块。此模块将采用与`firewall-cmd`控制台非常相似的参数。您将需要指定要通过防火墙的服务，是否要立即应用此规则以及是否要将规则设置为永久性规则，以便在重新启动后规则仍然存在。

您可以使用`service`参数指定服务名称（如`ssh`），也可以使用`port`参数指定端口（如`22/tcp`）。

现在我们已经安装了 FirewallD，并且确保我们的 SSH 连接将存活，我们可以像对待其他任何服务一样启用它：

```
- name: Ensure FirewallD is running 
  service: 
    name: firewalld 
    state: started 
    enabled: True 
  become: True 
```

# 添加自定义 MOTD。

要添加 MOTD，我们将需要一个模板，该模板将对所有服务器都相同，并且一个任务来使用该模板。

我发现为每个服务器添加 MOTD 非常有用。如果你使用 Ansible，那就更有用了，因为你可以用它来警告用户系统的更改可能会被 Ansible 覆盖。我通常的模板叫做`motd`，内容如下：

```
                This system is managed by Ansible 
  Any change done on this system could be overwritten by Ansible 

OS: {{ ansible_distribution }} {{ ansible_distribution_version }} 
Hostname: {{ inventory_hostname }} 
eth0 address: {{ ansible_eth0.ipv4.address }} 

            All connections are monitored and recorded 
     Disconnect IMMEDIATELY if you are not an authorized user
```

这是一个`jinja2`模板，它允许我们使用在 playbooks 中设置的每个变量。这也允许我们使用后面将在本章中看到的复杂的条件和循环语法。为了从 Ansible 中的模板填充文件，我们将需要使用以下命令：

```
- name: Ensure the MOTD file is present and updated 
  template: 
    src: motd 
    dest: /etc/motd 
    owner: root 
    group: root 
    mode: 0644 
  become: True 
```

`template`模块允许我们指定一个本地文件（`src`），该文件将被`jinja2`解释，并且此操作的输出将保存在远程机器上的特定路径（`dest`）中，将由特定用户（`owner`）和组（`group`）拥有，并且将具有特定的访问模式（`mode`）。

# 更改主机名。

为了保持简单，我发现将机器的主机名设置为有意义的内容很有用。为此，我们可以使用一个非常简单的 Ansible 模块叫做`hostname`：

```
- name: Ensure the hostname is the same of the inventory 
  hostname: 
    name: "{{ inventory_hostname }}" 
  become: True
```

# 复审并运行 playbook。

把所有事情都放在一起，我们现在有了以下 playbook（为简单起见称为`common_tasks.yaml`）：

```
--- 
- hosts: all 
  remote_user: ansible 
  tasks: 
    - name: Ensure EPEL is enabled 
      yum: 
        name: epel-release 
        state: present 
      become: True 
    - name: Ensure libselinux-python is present 
      yum: 
        name: libselinux-python 
        state: present 
      become: True 
  ...
```

由于这个`playbook`相当复杂，我们可以运行以下命令：

```
$ ansible-playbook common_tasks.yaml --list-tasks 
```

这要求 Ansible 以更简洁的形式打印所有任务，以便我们可以快速查看`playbook`执行的任务。输出应该类似于以下内容：

```
playbook: common_tasks.yaml
 play #1 (all): all TAGS: []
 tasks:
 Ensure EPEL is enabled TAGS: []
 Ensure libselinux-python is present TAGS: []
 Ensure libsemanage-python is present TAGS: []
 Ensure we have last version of every package TAGS: []
 Ensure NTP is installed TAGS: []
 Ensure the timezone is set to UTC TAGS: []
 Ensure the NTP service is running and enabled TAGS: []
 Ensure FirewallD is installed TAGS: []
 Ensure FirewallD is running TAGS: []
 Ensure SSH can pass the firewall TAGS: []
 Ensure the MOTD file is present and updated TAGS: []
 Ensure the hostname is the same of the inventory TAGS: []
```

现在我们可以使用以下命令运行`playbook`：

```
$ ansible-playbook -i test01.fale.io, common_tasks.yaml
```

我们将收到以下输出。完整的代码输出可在 GitHub 上找到。

```
PLAY [all] ***************************************************

TASK [Gathering Facts] ***************************************
ok: [test01.fale.io]

TASK [Ensure EPEL is enabled] ********************************
changed: [test01.fale.io]

TASK [Ensure libselinux-python is present] *******************
ok: [test01.fale.io]

TASK [Ensure libsemanage-python is present] ******************
changed: [test01.fale.io]

TASK [Ensure we have last version of every package] **********
changed: [test01.fale.io]
...
```

# 安装和配置 web 服务器。

现在我们已经对操作系统进行了一些通用更改，让我们继续实际创建 web 服务器。我们将这两个阶段拆分开来，以便我们可以在每台机器之间共享第一个阶段，并仅将第二个应用于 Web 服务器。

对于这个第二阶段，我们将创建一个名为`webserver.yaml`的新 playbook，内容如下：

```
--- 
- hosts: all 
  remote_user: ansible
  tasks: 
    - name: Ensure the HTTPd package is installed 
      yum: 
        name: httpd 
        state: present 
      become: True 
    - name: Ensure the HTTPd service is enabled and running 
      service: 
        name: httpd 
        state: started 
        enabled: True 
      become: True 
    - name: Ensure HTTP can pass the firewall 
      firewalld: 
        service: http 
        state: enabled 
        permanent: True 
        immediate: True 
      become: True 
    - name: Ensure HTTPS can pass the firewall 
      firewalld: 
        service: https 
        state: enabled 
        permanent: True 
        immediate: True 
      become: True  
```

正如您所看到的，前两个任务与本章开头示例中的任务相同，最后两个任务用于指示 FirewallD 允许`HTTP`和`HTTPS`流量通过。

让我们用以下命令运行这个脚本：

```
$ ansible-playbook -i test01.fale.io, webserver.yaml 
```

这导致以下结果：

```
PLAY [all] *************************************************

TASK [Gathering Facts] *************************************
ok: [test01.fale.io]

TASK [Ensure the HTTPd package is installed] ***************
ok: [test01.fale.io]

TASK [Ensure the HTTPd service is enabled and running] *****
ok: [test01.fale.io]

TASK [Ensure HTTP can pass the firewall] *******************
changed: [test01.fale.io]

TASK [Ensure HTTPS can pass the firewall] ******************
changed: [test01.fale.io]

PLAY RECAP *************************************************
test01.fale.io      : ok=5 changed=2 unreachable=0 failed=0 
```

现在我们有了一个网页服务器，让我们发布一个小型的、单页的、静态的网站。

# 发布网站

由于我们的网站将是一个简单的单页网站，我们可以很容易地创建它，并使用一个 Ansible 任务发布它。为了使这个页面稍微有趣些，我们将使用一个模板创建它，这个模板将由 Ansible 填充一些关于机器的数据。发布它的脚本将被称为 `deploy_website.yaml`，并且将具有以下内容：

```
--- 
- hosts: all 
  remote_user: ansible
  tasks: 
    - name: Ensure the website is present and updated 
      template: 
        src: index.html.j2 
        dest: /var/www/html/index.html 
        owner: root 
        group: root 
        mode: 0644 
      become: True  
```

让我们从一个简单的模板开始，我们将其称为 `index.html.j2`：

```
<html> 
    <body> 
        <h1>Hello World!</h1> 
    </body> 
</html>
```

现在，我们可以通过运行以下命令来测试我们的网站部署：

```
$ ansible-playbook -i test01.fale.io, deploy_website.yaml 
```

我们应该收到以下输出：

```
PLAY [all] ***********************************************

TASK [Gathering Facts] ***********************************
ok: [test01.fale.io]

TASK [Ensure the website is present and updated] *********
changed: [test01.fale.io]

PLAY RECAP ***********************************************
test01.fale.io    : ok=2 changed=1 unreachable=0 failed=0
```

如果您现在在浏览器中打开 IP/FQDN 测试机，您会找到 **Hello World!** 页面。

# Jinja2 模板

**Jinja2** 是一个广泛使用的、功能齐全的 Python 模板引擎。让我们看一些语法，这些语法将帮助我们使用 Ansible。本段不是官方文档的替代品，但其目标是教会您在使用 Ansible 时会非常有用的一些组件。

# 变量

正如我们所见，我们可以通过使用 `{{ VARIABLE_NAME }}` 语法简单地打印变量内容。如果我们想要打印数组的一个元素，我们可以使用 `{{ ARRAY_NAME['KEY'] }}`，如果我们想要打印对象的一个属性，我们可以使用 `{{ OBJECT_NAME.PROPERTY_NAME }}`。

因此，我们可以通过以下方式改进我们之前的静态页面：

```
<html> 
    <body> 
        <h1>Hello World!</h1> 
        <p>This page was created on {{ ansible_date_time.date }}.</p> 
    </body> 
</html>
```

# 过滤器

有时，我们可能想稍微改变字符串的样式，而不需要为此编写特定的代码；例如，我们可能想要将一些文本大写。为此，我们可以使用 Jinja2 的一个过滤器，比如 `{{ VARIABLE_NAME | capitalize }}`。Jinja2 有许多可用的过滤器，您可以在 [`jinja.pocoo.org/docs/dev/templates/#builtin-filters`](http://jinja.pocoo.org/docs/dev/templates/#builtin-filters) 找到完整的列表。

# 条件语句

在模板引擎中，您可能经常发现有条件地打印不同的字符串的可能性是有用的，这取决于字符串的内容（或存在）。因此，我们可以通过以下方式改进我们的静态网页：

```
<html> 
    <body> 
        <h1>Hello World!</h1> 
        <p>This page was created on {{ ansible_date_time.date }}.</p> 
{% if ansible_eth0.active == True %} 
        <p>eth0 address {{ ansible_eth0.ipv4.address }}.</p> 
{% endif %} 
    </body> 
</html> 
```

正如您所看到的，我们已经添加了打印 `eth0` 连接的主 IPv4 地址的能力，如果连接是 `active` 的话。通过条件语句，我们还可以使用测试。

有关内置测试的完整列表，请参阅 [`jinja.pocoo.org/docs/dev/templates/#builtin-tests`](http://jinja.pocoo.org/docs/dev/templates/#builtin-tests)。

因此，为了获得相同的结果，我们也可以写成以下形式：

```
<html> 
    <body> 
        <h1>Hello World!</h1> 
        <p>This page was created on {{ ansible_date_time.date }}.</p> 
{% if ansible_eth0.active is equalto True %} 
        <p>eth0 address {{ ansible_eth0.ipv4.address }}.</p> 
{% endif %} 
    </body> 
</html> 
```

有很多不同的测试可以帮助您创建易于阅读、有效的模板。

# 循环

`jinja2` 模板系统还提供了创建循环的功能。让我们为我们的页面添加一个功能，它将打印每个设备的主 IPv4 网络地址，而不仅仅是 `eth0`。然后我们将有以下代码：

```
<html> 
    <body> 
        <h1>Hello World!</h1> 
        <p>This page was created on {{ ansible_date_time.date }}.</p> 
        <p>This machine can be reached on the following IP addresses</p> 
        <ul> 
{% for address in ansible_all_ipv4_addresses %} 
            <li>{{ address }}</li> 
{% endfor %} 
        </ul> 
    </body> 
</html> 
```

正如您所看到的，如果您已经了解 Python 的语法，那么对于循环语句的语法是熟悉的。

这几页关于 Jinja2 模板化编程的内容并不能替代官方文档。实际上，Jinja2 模板比我们在这里看到的要更强大。这里的目标是为您提供最常用于 Ansible 的基本 Jinja2 模板。

# 摘要

在本章中，我们开始学习 YAML，并了解了 playbook 是什么，它如何工作以及如何使用它来创建 Web 服务器（和静态网站的部署）。我们还看到了多个 Ansible 模块，例如`user`、`yum`、`service`、`FirewalID`、`lineinfile`和`template`模块。在章节的最后，我们重点关注了模板。

在下一章中，我们将讨论库存，以便我们可以轻松地管理多台机器。


# 第四章：第二节：在生产环境中部署 Playbooks

这一部分将帮助您创建具有多个阶段和多台机器的部署。它还将解释 Ansible 如何与各种云服务集成以及如何通过管理云来简化您的生活。

这一部分包含以下章节：

+   第三章，*扩展到多个主机*

+   第四章，*处理复杂部署*

+   第五章，*转向云端*

+   第六章，*从 Ansible 获取通知*


# 第五章：扩展到多个主机

在之前的章节中，我们在命令行中指定了主机。在只有一个主机要处理时，这样做效果很好，但是当管理多个服务器时，效果就不太好了。在本章中，我们将看到如何利用库存来管理多个服务器。此外，我们还将介绍主机变量和组变量等主题，以便轻松快速地设置类似但不同的主机。我们将讨论**Ansible**中的循环，它允许您减少编写的代码量，同时使代码更易读。

在本章中，我们将涵盖以下主题：

+   使用库存文件

+   使用变量

# 技术要求

您可以从本书的 GitHub 仓库下载所有文件，网址为[`github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter03`](https://github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter03)。

# 使用库存文件

**库存文件**是 Ansible 的真相之源（还有一个名为**动态库存**的高级概念，我们稍后会介绍）。它遵循 **INI** 格式，并告诉 Ansible 用户提供的远程主机是否真实。

Ansible 可以并行运行其任务对多个主机进行操作。为了做到这一点，您可以直接将主机列表传递给 Ansible，使用库存文件。对于这样的并行执行，Ansible 允许您在库存文件中对主机进行分组；文件将组的名称传递给 Ansible。Ansible 将在库存文件中搜索该组，并对该组中列出的所有主机运行其任务。

您可以使用 `-i` 或 `--inventory-file` 选项将库存文件传递给 Ansible，后跟文件路径。如果您未明确指定任何库存文件给 Ansible，则 Ansible 将从 `ansible.cfg` 的 `host_file` 参数的默认路径获取，默认路径为 `/etc/ansible/hosts`。

使用 `-i` 参数时，如果值是一个列表（至少包含一个逗号），它将被用作库存列表，而如果变量是字符串，则将其用作库存文件路径。

# 基本库存文件

在深入概念之前，让我们先看一下一个称为`hosts`的基本库存文件，我们可以在这个文件中使用，而不是在之前的示例中使用的列表：

```
test01.fale.io
```

Ansible 可以在库存文件中使用 FQDN 或 IP 地址。

现在，我们可以执行与上一章相同的操作，调整 Ansible 命令参数。

例如，要安装 Web 服务器，我们使用了这个命令：

```
$ ansible-playbook -i test01.fale.io, webserver.yaml 
```

相反，我们可以使用以下内容：

```
$ ansible-playbook -i hosts webserver.yaml 
```

正如您所看到的，我们已经用库存文件名替换了主机列表。

# 库存文件中的组

当我们遇到更复杂的情况时，清单文件的优势就会显现出来。假设我们的网站变得更加复杂，现在我们需要一个更复杂的环境。在我们的示例中，我们的网站将需要一个 MySQL 数据库。此外，我们决定有两台 web 服务器。在这种情况下，根据我们的基础设施中的角色对不同的机器进行分组是有意义的。

Ansible 允许我们创建一个类似 INI 文件的文件，其中包含组（INI 部分）和主机。这是我们的主机文件将要更改为的内容：

```
[webserver] 
ws01.fale.io 
ws02.fale.io 

[database] 
db01.fale.io 
```

现在我们可以指示播放书只在某个组中的主机上运行。在上一章中，我们为我们的网站示例创建了三个不同的播放书：

+   `firstrun.yaml` 是通用的，必须在每台机器上运行。

+   `common_tasks.yaml` 是通用的，必须在每台机器上运行。

+   `webserver.yaml` 是特定于 web 服务器的，因此不应在任何其他机器上运行。

由于唯一特定于服务器组的文件是 `webserver.yaml`，所以我们只需要更改它。为此，让我们打开 `webserver.yaml` 文件并将内容从 **`- hosts: all`** 更改为 `- hosts: webserver`。

只有这三个播放书，我们无法继续创建我们的环境，有三个服务器。因为我们还没有一个设置数据库的播放书（我们将在下一章中看到），我们将完全为两台 web 服务器（`ws01.fale.io` 和 `ws02.fale.io`）提供服务，并且，对于数据库服务器，我们只提供基本系统。

在运行 Ansible 播放书之前，我们需要为环境提供支持。为此，请创建以下 vagrant 文件：

```
Vagrant.configure("2") do |config|
  config.vm.define "ws01" do |ws01|
    ws01.vm.hostname = "ws01.fale.io"
  end
  config.vm.define "ws02" do |ws02|
    ws02.vm.hostname = "ws02.fale.io"
  end
  config.vm.define "db01" do |db01|
    db01.vm.hostname = "db01.fale.io"
  end
  config.vm.box = "centos/7"
end
```

通过运行 `vagrant up`，Vagrant 将为我们生成整个环境。在一段时间后，Vagrant 在 shell 中输出一些内容后，应该会还给你命令提示符。当这种情况发生时，请检查最后几行是否有错误，以确保一切如预期般进行。

现在我们已经为环境提供了支持，我们可以继续执行 `firstrun` 播放书，这将确保我们的 Ansible 用户存在并且具有正确的 SSH 密钥设置。为此，我们可以使用以下命令运行它：

```
$ ansible-playbook -i hosts firstrun.yaml 
```

以下将是结果。完整的输出文件可在 GitHub 上找到：

```
PLAY [all] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws01.fale.io]
ok: [ws02.fale.io]
ok: [db01.fale.io]

TASK [Ensure ansible user exists] ************************************
changed: [ws02.fale.io]
changed: [db01.fale.io]
changed: [ws01.fale.io]
...
```

正如你所看到的，输出与我们收到的单个主机非常相似，但在每个步骤中每个主机都有一行。在这种情况下，所有机器处于相同的状态，并且执行了相同的步骤，所以我们看到它们都表现得一样，但是在更复杂的场景中，你可以看到不同的机器在同一步骤上返回不同的状态。我们也可以执行另外两个播放书，结果类似。

# 清单文件中的正则表达式

当你有大量服务器时，给它们起一个可预测的名字是常见和有用的，例如，将所有网络服务器命名为`wsXY`或`webXY`，或者将数据库服务器命名为`dbXY`。如果你这样做，你可以减少主机文件中的行数，增加其可读性。例如，我们的主机文件可以简化如下：

```
[webserver] 
ws[01:02].fale.io 

[database] 
db01.fale.io 
```

在这个例子中，我们使用了`[01:02]`，它将匹配第一个数字（在我们的例子中是`01`）和最后一个数字（在我们的例子中是`02`）之间的所有出现。在我们的案例中，收益并不巨大，但如果你有 40 台网络服务器，你可以从主机文件中减少 39 行。

在这一部分中，我们已经看到了如何创建清单文件，如何向 Ansible 清单添加组，如何利用范围来加快清单创建过程，并如何针对清单运行 Ansible playbook。现在我们将看到如何在清单中设置变量以及如何在我们的 playbooks 中使用它们。

# 使用变量

Ansible 允许你以多种方式定义变量，从 playbook 中的变量文件，通过使用`-e`/`--extra-vars`选项从 Ansible 命令传递它。你也可以通过将其传递给清单文件来定义变量。你可以在清单文件中的每个主机，整个组或在清单文件所在目录中创建一个变量文件来定义变量。

# 主机变量

可以为特定主机声明变量，在主机文件中声明它们。例如，我们可能希望为我们的网络服务器指定不同的引擎。假设一个需要回复到一个特定的域，而另一个需要回复到不同的域名。在这种情况下，我们会在以下主机文件中执行：

```
[webserver] 
ws01.fale.io domainname=example1.fale.io 
ws02.fale.io domainname=example2.fale.io 

[database] 
db01.fale.io 
```

每次我们使用此清单执行 playbook 时，Ansible 将首先读取清单文件，并将根据每个主机分配`domainname`变量的值。这样，所有在网络服务器上运行的 playbook 将能够引用`domainname`变量。

# 组变量

有些情况下，你可能想要设置一个整个组都有效的变量。假设我们想要声明变量`https_enabled`为`True`，并且其值必须对所有网络服务器都相等。在这种情况下，我们可以创建一个`[webserver:vars]`部分，因此我们将使用以下主机文件：

```
[webserver] 
ws01.fale.io 
ws02.fale.io 

[webserver:vars] 
https_enabled=True 

[database] 
db01.fale.io 
```

请记住，如果相同的变量在两个空间中都声明了，主机变量将覆盖组变量。

# 变量文件

有时，你需要为每个主机和组声明大量的变量，主机文件变得难以阅读。在这些情况下，你可以将变量移动到特定的文件中。对于主机级别的变量，你需要在`host_vars`文件夹中创建一个与你的主机同名的文件，而对于组变量，你需要使用组名作为文件名，并将它们放置在`group_vars`文件夹中。

因此，如果我们想要复制先前基于主机变量使用文件的示例，我们需要创建 `host_vars/ws01.fale.io` 文件，内容如下：

```
domainname=example1.fale.io 
```

然后我们创建 `host_vars/ws02.fale.io` 文件，内容如下：

```
domainname=example2.fale.io 
```

而如果我们想要复制基于组变量的示例，我们将需要具有以下内容的 `group_vars/webserver` 文件：

```
https_enabled=True 
```

清单变量遵循一种层次结构；在其顶部是公共变量文件（我们在上一节 *使用清单文件* 中讨论过），它将覆盖任何主机变量、组变量和清单变量文件。接下来是主机变量，它将覆盖组变量；最后，组变量将覆盖清单变量文件。

# 用清单文件覆盖配置参数

你可以直接通过清单文件覆盖一些 Ansible 的配置参数。这些配置参数将覆盖所有其他通过 `ansible.cfg`、环境变量或在 playbooks 中设置的参数。传递给 `ansible-playbook/ansible` 命令的变量优先级高于清单文件中设置的任何其他变量。

以下是一些可以从清单文件覆盖的参数列表：

+   `ansible_user`：该参数用于覆盖与远程主机通信所使用的用户。有时，某台机器需要不同的用户；在这种情况下，这个变量会帮助你。例如，如果你是从 *ansible* 用户运行 Ansible，但在远程机器上需要连接到 *automation* 用户，设置 `ansible_user=automation` 就会实现这一点。

+   `ansible_port`：该参数将用用户指定的端口覆盖默认的 SSH 端口。有时，系统管理员选择在非标准端口上运行 SSH。在这种情况下，你需要通知 Ansible 进行更改。如果在你的环境中 SSH 端口是 22022 而不是 22，你将需要使用 `ansible_port=22022`。

+   `ansible_host`：该参数用于覆盖别名的主机。如果你想通过 DNS 名称（即：`ws01.fale.io`）连接到 `10.0.0.3` 机器，但由于某些原因 DNS 未能正确解析主机，你可以通过设置 `ansible_host=10.0.0.3` 变量，强制 Ansible 使用该 IP 而不是 DNS 解析出的 IP。

+   `ansible_connection`：这指定了到远程主机的连接类型。值可以是 SSH、Paramiko 或本地。即使 Ansible 可以使用其 SSH 守护程序连接到本地机器，但这会浪费大量资源。在这些情况下，你可以指定 `ansible_connection=local`，这样 Ansible 将打开一个标准 shell 而不是 SSH。

+   `ansible_private_key_file`：此参数将覆盖用于 SSH 的私钥；如果您想为特定主机使用特定密钥，则这将非常有用。常见的用例是，如果您的主机分布在多个数据中心、多个 AWS 区域或不同类型的应用程序中。在这种情况下，私钥可能不同。

+   `ansible__type`：默认情况下，Ansible 使用 `sh` shell；您可以使用 `ansible_shell_type` 参数覆盖此行为。将其更改为 `csh`、`ksh` 等将使 Ansible 使用该 shell 的命令。如果您需要执行一些 `csh` 或 `ksh` 脚本，并且立即处理它们会很昂贵，那么这可能会有所帮助。

# 使用动态清单

有些环境中，你有一个系统可以自动创建和销毁机器。我们将在第五章，*云之旅*中看到如何使用 Ansible 完成这个任务。在这种环境中，机器列表变化非常快，维护主机文件变得复杂。在这种情况下，我们可以使用动态清单来解决这个问题。

动态清单背后的想法是 Ansible 不会读取主机文件，而是执行一个返回主机列表的脚本，并以 JSON 格式返回给 Ansible。这允许您直接查询您的云提供商，询问在任何给定时刻运行的整个基础设施中的机器列表。

通过 Ansible，已经提供了大多数常见云提供商的许多脚本，可以在[`github.com/ansible/ansible/tree/devel/contrib/inventory`](https://github.com/ansible/ansible/tree/devel/contrib/inventory)找到，但如果您有不同的需求，也可以创建自定义脚本。Ansible 清单脚本可以用任何语言编写，但出于一致性考虑，动态清单脚本应使用 Python 编写。请记住，这些脚本需要直接可执行，因此请记得为它们设置可执行标志（`chmod + x inventory.py`）。

接下来，我们将查看可以从官方 Ansible 仓库下载的 Amazon Web Services 和 DigitalOcean 脚本。

# Amazon Web Services

要允许 Ansible 从**Amazon Web Services**（**AWS**）收集关于您的 EC2 实例的数据，您需要从 Ansible 的 GitHub 仓库下载以下两个文件：[`github.com/ansible/ansible`](https://github.com/ansible/ansible)。

+   `ec2.py` 清单脚本

+   `ec2.ini` 文件包含了您的 EC2 清单脚本的配置。

Ansible 使用**Boto**，AWS Python SDK，通过 API 与 AWS 进行通信。为了允许此通信，您需要导出 `AWS_ACCESS_KEY_ID` 和 `AWS_SECRET_ACCESS_KEY` 变量。

你可以以两种方式使用清单：

+   通过 `-i` 选项将其直接传递给 `ansible-playbook` 命令，并将 `ec2.ini` 文件复制到您运行 Ansible 命令的当前目录。

+   将`ec2.py`文件复制到`/etc/ansible/hosts`，并使用`chmod +x`使其可执行，然后将`ec2.ini`文件复制到`/etc/ansible/ec2.ini`。

`ec2.py`文件将根据地区、可用区、标签等创建多个组。您可以通过运行`./ec2.py --list`来检查清单文件的内容。

让我们看一个使用 EC2 动态清单的示例 playbook，它将简单地 ping 我的帐户中的所有机器：

```
ansible -i ec2.py all -m ping
```

由于我们执行了 ping 模块，我们期望配置的帐户中可用的机器会回复我们。由于我当前帐户中只有一台带有 IP 地址 52.28.138.231 的 EC2 机器，我们可以期望它会回复，实际上我的帐户上的 EC2 回复如下：

```
52.28.138.231 | SUCCESS => { 
    "changed": false, 
    "ping": "pong" 
} 
```

在上面的示例中，我们使用`ec2.py`脚本而不是静态清单文件，并使用`-i`选项和 ping 命令。

类似地，您可以使用这些清单脚本执行各种类型的操作。例如，您可以将它们与您的部署脚本集成，以找出单个区域中的所有节点，并在执行区域部署时部署到这些节点（一个区域表示一个数据中心）在 AWS 中。

如果您只想知道云中的 web 服务器是什么，并且您已经使用某种约定对它们进行了标记，您可以通过使用动态清单脚本来过滤掉标记来实现。此外，如果您有未涵盖的特殊情况，您可以增强它以提供所需的节点集以 JSON 格式，并从 playbooks 中对这些节点进行操作。如果您正在使用数据库来管理您的清单，您的清单脚本可以查询数据库并转储 JSON。它甚至可以与您的云同步，并定期更新您的数据库。

# DigitalOcean

正如我们在[`github.com/ansible/ansible/tree/devel/contrib/inventory`](https://github.com/ansible/ansible/tree/devel/contrib/inventory)中使用 EC2 文件从 AWS 中提取数据一样，我们可以对 DigitalOcean 执行相同的操作。唯一的区别是我们必须获取`digital_ocean.ini`和`digital_ocean.py`文件。

与以前一样，如果需要，我们需要调整`digital_ocean.ini`选项，并将 Python 文件设置为可执行。你唯一可能需要更改的选项是`api_token`。

现在我们可以尝试 ping 我在 DigitalOcean 上预配的两台机器，如下所示：

```
ansible -i digital_ocean.py all -m ping 
```

正如预期的那样，我帐户中的两个 droplets 响应如下：

```
188.166.150.79 | SUCCESS => { 
    "changed": false, 
    "ping": "pong" 
} 
46.101.77.55 | SUCCESS => { 
    "changed": false, 
    "ping": "pong" 
} 
```

我们现在已经看到从许多不同的云提供商检索数据是多么容易。

# 在 Ansible 中使用迭代器

您可能已经注意到，到目前为止，我们从未使用过循环，因此每次我们必须执行多个相似的操作时，我们都会多次编写代码。其中一个示例是`webserver.yaml`代码。

实际上，这是`webserver.yaml`文件的最后一部分：

```
    - name: Ensure HTTP can pass the firewall 
      firewalld: 
        service: http 
        state: enabled 
        permanent: True 
        immediate: True 
      become: True 
    - name: Ensure HTTPS can pass the firewall 
      firewalld: 
        service: https 
        state: enabled 
        permanent: True 
        immediate: True 
      become: True 
```

如你所见，`webserver.yaml`代码的最后两个块执行的操作非常相似：确保防火墙的某个端口是打开的。

# 使用标准迭代 - with_items

重复的代码本身并非问题，但它不具备可扩展性。

Ansible 允许我们使用迭代来提高代码的清晰度和可维护性。

为了改进上述代码，我们可以使用简单的迭代：`with_items`。

这使我们能够对项目列表进行迭代。在每次迭代中，列表的指定项目将在 item 变量中可用。这使我们能够在单个块中执行多个类似的操作。

因此，我们可以将`webserver.yaml`代码的最后一部分更改为以下内容：

```
    - name: Ensure HTTP and HTTPS can pass the firewall 
      firewalld: 
        service: '{{ item }}' 
        state: enabled 
        permanent: True 
        immediate: True 
      become: True
      with_items:
        - http
        - https
```

我们可以按照以下方式执行它：

```
ansible-playbook -i hosts webserver.yaml
```

我们收到以下内容：

```
PLAY [all] *********************************************************

TASK [Gathering Facts] *********************************************
ok: [ws01.fale.io]
ok: [ws02.fale.io]

TASK [Ensure the HTTPd package is installed] ***********************
ok: [ws02.fale.io]
ok: [ws01.fale.io]

TASK [Ensure the HTTPd service is enabled and running] *************
ok: [ws01.fale.io]
ok: [ws02.fale.io]

TASK [Ensure HTTP and HTTPS can pass the firewall] *****************
ok: [ws01.fale.io] (item=http)
ok: [ws02.fale.io] (item=http)
ok: [ws01.fale.io] (item=https)
ok: [ws02.fale.io] (item=https)

PLAY RECAP *********************************************************
ws01.fale.io                : ok=5 changed=0 unreachable=0 failed=0 
ws02.fale.io                : ok=5 changed=0 unreachable=0 failed=0
```

如您所见，输出与先前执行略有不同。事实上，在具有循环操作的行上，我们可以看到在`Ensure HTTP and HTTPS can pass the firewall`块的特定迭代中处理的`item`。

我们现在已经看到我们可以对项目列表进行迭代，但是 Ansible 还允许我们进行其他类型的迭代。

# 使用嵌套循环 - with_nested

有些情况下，您必须对列表中的所有元素与其他列表中的所有项进行迭代（笛卡尔积）。一个非常常见的情况是当您必须在多个路径中创建多个文件夹时。在我们的例子中，我们将在用户`alice`和`bob`的主目录中创建文件夹`mail`和`public_html`。

我们可以使用`with_nested.yaml`文件中的以下代码片段来实现；完整的代码可在 GitHub 上找到：

```

- hosts: all 
  remote_user: ansible
  vars: 
    users: 
      - alice 
      - bob 
    folders: 
      - mail 
      - public_html 
  tasks: 
    - name: Ensure the users exist 
      user: 
        name: '{{ item }}' 
      become: True 
      with_items: 
        - '{{ users }}' 
    ...
```

使用以下方式运行此命令：

```
ansible-playbook -i hosts with_nested.yaml 
```

我们收到以下结果。完整的输出文件可在 GitHub 上找到：

```
PLAY [all] *******************************************************

TASK [Gathering Facts] *******************************************
ok: [db01.fale.io]
ok: [ws02.fale.io]
ok: [ws01.fale.io]

TASK [Ensure the users exist] ************************************
changed: [db01.fale.io] => (item=alice)
changed: [ws02.fale.io] => (item=alice)
changed: [ws01.fale.io] => (item=alice)
changed: [db01.fale.io] => (item=bob)
changed: [ws02.fale.io] => (item=bob)
changed: [ws01.fale.io] => (item=bob)
...
```

如您所见，Ansible 在所有目标机器上创建了用户 alice 和 bob，并且还为这两个用户在所有机器上的文件夹`$HOME/mail`和`$HOME/public_html`。

# 文件通配符循环 - with_fileglobs

有时，我们希望对某个特定文件夹中的每个文件执行操作。如果你想要从一个文件夹复制多个文件到另一个文件夹中，这可能会很方便。为此，你可以创建一个名为`with_fileglobs.yaml`的文件，其中包含以下代码：

```
--- 
- hosts: all 
  remote_user: ansible
  tasks: 
    - name: Ensure the folder /tmp/iproute2 is present 
      file: 
        dest: '/tmp/iproute2' 
        state: directory 
      become: True 
    - name: Copy files that start with rt to the tmp folder 
      copy: 
        src: '{{ item }}' 
        dest: '/tmp/iproute2' 
        remote_src: True 
      become: True 
      with_fileglob: 
        - '/etc/iproute2/rt_*' 
```

我们可以按照以下方式执行它：

```
ansible-playbook -i hosts with_fileglobs.yaml 
```

这导致了以下输出。完整的输出文件可在 GitHub 上找到。

```
PLAY [all] *****************************************************

TASK [Gathering Facts] *****************************************
ok: [db01.fale.io]
ok: [ws02.fale.io]
ok: [ws01.fale.io]

TASK [Ensure the folder /tmp/iproute2 is present] **************
changed: [ws02.fale.io]
changed: [ws01.fale.io]
changed: [db01.fale.io]

TASK [Copy files that start with rt to the tmp folder] *********
changed: [ws01.fale.io] => (item=/etc/iproute2/rt_realms)
changed: [db01.fale.io] => (item=/etc/iproute2/rt_realms)
changed: [ws02.fale.io] => (item=/etc/iproute2/rt_realms)
changed: [ws01.fale.io] => (item=/etc/iproute2/rt_protos)
...
```

至于我们的目标，我们已经创建了`/tmp/iproute2`文件夹，并用`/etc/iproute2`文件夹中文件的副本填充了它。这种模式经常用于创建配置的备份。

# 使用整数循环 - with_sequence

许多时候，你需要对整数进行迭代。一个例子是创建十个名为`fileXY`的文件夹，其中`X`和`Y`是从`1`到`10`的连续数字。为此，我们可以创建一个名为`with_sequence.yaml`的文件，其中包含以下代码：

```
--- 
- hosts: all 
  remote_user: ansible 
  tasks: 
  - name: Create the folders /tmp/dirXY with XY from 1 to 10 
    file: 
      dest: '/tmp/dir{{ item }}' 
      state: directory 
    with_sequence: start=1 end=10 
    become: True 
```

与大多数 Ansible 命令不同，我们可以在对象上使用单行符号和标准 YAML 多行符号，`with_sequence` 只支持单行符号。

然后，我们可以使用以下命令执行它：

```
ansible-playbook -i hosts with_sequence.yaml 
```

我们将收到以下输出：

```
PLAY [all] *****************************************************

TASK [Gathering Facts] *****************************************
ok: [ws02.fale.io]
ok: [ws01.fale.io]
ok: [db01.fale.io]

TASK [Create the folders /tmp/dirXY with XY from 1 to 10] ******
changed: [ws01.fale.io] => (item=1)
changed: [db01.fale.io] => (item=1)
changed: [ws02.fale.io] => (item=1)
changed: [ws01.fale.io] => (item=2)
changed: [db01.fale.io] => (item=2)
changed: [ws02.fale.io] => (item=2)
changed: [ws01.fale.io] => (item=3)
...
```

Ansible 支持更多类型的循环，但由于它们的使用要少得多，你可以直接参考官方文档了解循环：[`docs.ansible.com/ansible/playbooks_loops.html`](http://docs.ansible.com/ansible/playbooks_loops.html)。

# 摘要

在本章中，我们探讨了大量的概念，将帮助您将基础设施扩展到单个节点之外。我们从用于指示 Ansible 关于我们机器的清单文件开始，然后我们介绍了如何在运行相同命令的多个异构主机上拥有主机特定和组特定的变量。然后，我们转向由某些其他系统（通常是云提供商）直接填充的动态清单。最后，我们分析了 Ansible playbook 中的多种迭代方式。

在下一章中，我们将以更合理的方式结构化我们的 Ansible 文件，以确保最大的可读性。为此，我们引入了角色，进一步简化了复杂环境的管理。
