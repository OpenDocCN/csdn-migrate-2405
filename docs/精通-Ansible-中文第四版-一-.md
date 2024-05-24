# 精通 Ansible 中文第四版（一）

> 原文：[`zh.annas-archive.org/md5/F58519F0D978AE01B8EEFA01F4E150D0`](https://zh.annas-archive.org/md5/F58519F0D978AE01B8EEFA01F4E150D0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎阅读《精通 Ansible》，这是您全面更新的指南，介绍了 Ansible 提供的最有价值的高级功能和功能——自动化和编排工具。本书将为您提供所需的知识和技能，真正理解 Ansible 在基本水平上的功能，包括自 3.0 版本发布以来的所有最新功能和变化。这将使您能够掌握处理当今和未来复杂自动化挑战所需的高级功能。您将了解 Ansible 工作流程，探索高级功能的用例，解决意外行为，通过定制扩展 Ansible，并了解 Ansible 的许多新的重要发展，特别是基础设施和网络供应方面。

# 本书适合对象

本书适用于对 Ansible 核心元素和应用有一定了解，但现在希望通过使用 Ansible 来应用自动化来提高他们的技能的 Ansible 开发人员和运维人员。

# 本书涵盖的内容

[*第一章*]，《Ansible 的系统架构和设计》，介绍了 Ansible 在工程师代表执行任务时的内部细节，它是如何设计的，以及如何使用清单和变量。

[*第二章*]，《从早期的 Ansible 版本迁移》，解释了从 Ansible 2.x 迁移到 3.x 及更高版本时将经历的架构变化，如何使用 Ansible 集合，以及如何构建自己的集合——对于熟悉早期 Ansible 版本的任何人来说，这是必读的。

[*第三章*]，《使用 Ansible 保护您的秘密》，探讨了加密数据和防止秘密在运行时被揭示的工具。

[*第四章*]，《Ansible 和 Windows-不仅仅适用于 Linux》，探讨了将 Ansible 与 Windows 主机集成，以在跨平台环境中实现自动化的方法。

[*第五章*]，《使用 AWX 进行企业基础设施管理》，概述了强大的、开源的图形化管理框架 AWX，以及在企业环境中如何使用它。

[*第六章*]，《解锁 Jinja2 模板的强大功能》，阐述了 Jinja2 模板引擎在 Ansible 中的各种用途，并讨论了如何充分利用其功能。

[*第七章*]，《控制任务条件》，解释了如何更改 Ansible 的默认行为，定制任务错误和更改条件。

[*第八章*]，《使用角色组合可重用的 Ansible 内容》，解释了如何超越在主机上执行松散组织的任务，而是构建干净、可重用和自包含的代码结构，称为角色，以实现相同的最终结果。

[*第九章*]，《故障排除 Ansible》，带您了解可以用于检查、内省、修改和调试 Ansible 操作的各种方法。

[*第十章*]，《扩展 Ansible》，介绍了通过模块、插件和清单来源添加新功能的各种方法。

[*第十一章*]，《通过滚动部署减少停机时间》，解释了常见的部署和升级策略，以展示相关的 Ansible 功能。

[*第十二章*]，《基础设施供应》，研究了用于创建管理基础设施的云基础设施提供商和容器系统。

*第十三章*，*网络自动化*，描述了使用 Ansible 自动化网络设备配置的进展。

# 为了充分利用本书

要跟随本书提供的示例，您需要访问能够运行 Ansible 的计算机平台。目前，Ansible 可以在安装了 Python 2.7 或 Python 3（3.5 及更高版本）的任何机器上运行（Windows 支持控制机，但仅通过在较新版本上运行的 Linux 发行版中的**Windows 子系统 Linux（WSL）**层支持—有关详细信息，请参见*第四章*，*Ansible 和 Windows-不仅适用于 Linux*）。支持的操作系统包括（但不限于）Red Hat、Debian、Ubuntu、CentOS、macOS 和 FreeBSD。

本书使用 Ansible 4.x.x 系列版本。Ansible 安装说明可在[`docs.ansible.com/ansible/latest/installation_guide/intro_installation.html`](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)找到。

一些示例使用了 Docker 版本 20.10.8。Docker 安装说明可在[`docs.docker.com/get-docker/`](https://docs.docker.com/get-docker/)找到。

本书中的一些示例使用了**Amazon Web Services（AWS）**和 Microsoft Azure 上的帐户。有关这些服务的更多信息，请访问[`aws.amazon.com/`](https://aws.amazon.com/)和[`azure.microsoft.com`](https://azure.microsoft.com)。我们还深入探讨了使用 Ansible 管理 OpenStack，并且本书中的示例是根据此处的说明针对 DevStack 的单个*一体化*实例进行测试：[`docs.openstack.org/devstack/latest/`](https://docs.openstack.org/devstack/latest/)。

最后，*第十三章**，网络自动化*，在示例代码中使用了 Arista vEOS 4.26.2F 和 Cumulus VX 版本 4.4.0—请参见此处获取更多信息：[`www.arista.com/en/support/software-download`](https://www.arista.com/en/support/software-download)和[`www.nvidia.com/en-gb/networking/ethernet-switching/cumulus-vx/`](https://www.nvidia.com/en-gb/networking/ethernet-switching/cumulus-vx/)。如果您使用本书的数字版本，我们建议您自己输入代码或从书的 GitHub 存储库中访问代码（下一节中提供了链接）。这样做将帮助您避免与复制和粘贴代码相关的任何潜在错误。

# 下载示例代码文件

您可以从 GitHub 上下载本书的示例代码文件，网址为[`github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition`](https://github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition)。如果代码有更新，将在 GitHub 存储库中进行更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。请查看！

# 实际代码演示

本书的实际代码演示视频可在[`bit.ly/3vvkzbP`](https://bit.ly/3vvkzbP)观看。

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图和图表的彩色图片。您可以在这里下载：`static.packt-cdn.com/downloads/9781801818780_ColorImages.pdf`。

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码字词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如：“本书将假定`ansible.cfg`文件中没有设置会影响 Ansible 默认操作的设置”

代码块设置如下：

```
---
plugin: amazon.aws.aws_ec2
boto_profile: default
```

任何命令行输入或输出都将按照以下格式编写：

```
ansible-playbook -i mastery-hosts --vault-id 
test@./password.sh showme.yaml -v
```

**粗体**：表示一个新术语，一个重要的词，或者屏幕上看到的词。例如，菜单或对话框中的词以**粗体**显示。这是一个例子：“您只需导航到您的个人资料首选项页面，然后单击**显示 API 密钥**按钮。”

提示或重要说明

以这种方式出现。


# 第一部分：Ansible 概述和基本原理

在本节中，我们将探讨 Ansible 的基本原理，并建立一个健全的基础，以便开发 playbooks 和工作流程。我们还将审查和解释您将发现的变化，如果您熟悉旧版的 Ansible 2.x 发布。

本节包括以下章节：

+   *第一章*, *Ansible 的系统架构和设计*

+   *第二章*, *从早期的 Ansible 版本迁移*

+   *第三章*, *使用 Ansible 保护您的秘密*

+   *第四章*, *Ansible 和 Windows-不仅仅适用于 Linux*

+   *第五章*, *使用 AWX 进行企业基础设施管理*


# 第一章：Ansible 的系统架构和设计

本章详细探讨了**Ansible**的架构和设计，以及它如何代表您执行任务。我们将介绍清单解析的基本概念以及数据的发现方式。然后，我们将进行 playbook 解析。我们将详细介绍模块准备、传输和执行。最后，我们将详细介绍变量类型，并找出变量的位置、使用范围以及在多个位置定义变量时确定优先级的方式。所有这些内容将被覆盖，以奠定掌握 Ansible 的基础！

在本章中，我们将涵盖以下主题：

+   Ansible 版本和配置

+   清单解析和数据源

+   Playbook 解析

+   执行策略

+   模块传输和执行

+   Ansible 集合

+   变量类型和位置

+   魔术变量

+   访问外部数据

+   变量优先级（并将其与变量优先级排序互换）

# 技术要求

为了跟随本章中提出的示例，您需要一台运行**Ansible 4.3**或更高版本的 Linux 机器。几乎任何 Linux 版本都可以。对于那些对细节感兴趣的人，本章中提出的所有代码都是在**Ubuntu Server 20.04 LTS**上测试的，除非另有说明，并且在 Ansible 4.3 上进行了测试。本章附带的示例代码可以从 GitHub 上下载：[`github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter01`](https://github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter01)。

查看以下视频以查看代码实际操作：[`bit.ly/3E37xpn`](https://bit.ly/3E37xpn)。

# Ansible 版本和配置

假设您已在系统上安装了 Ansible。有许多文档介绍了如何安装 Ansible，适用于您可能使用的操作系统和版本。但是，重要的是要注意，新于 2.9.x 的 Ansible 版本与所有早期版本都有一些重大变化。对于阅读本书的每个人，都曾接触过 2.9.x 及更早版本的 Ansible 的*第二章*，*从早期的 Ansible 版本迁移*详细解释了这些变化，以及如何解决这些变化。

本书将假定使用 Ansible 版本 4.0.0（或更高版本），配合 ansible-core 2.11.1（或更新版本），这两者都是必需的，并且是撰写时的最新版本。要发现已安装 Ansible 的系统上使用的版本，请使用`--version`参数，即`ansible`或`ansible-playbook`，如下所示：

```
ansible-playbook --version
```

此命令应该给出与*图 1.1*类似的输出；请注意，该屏幕截图是在 Ansible 4.3 上进行的，因此您可能会看到与您的`ansible-core`软件包版本相对应的更新版本号（例如，对于 Ansible 4.3.0，这将是 ansible-core 2.11.1，这是所有命令将返回的版本号）：

![图 1.1 - 一个示例输出，显示了 Linux 系统上安装的 Ansible 版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_01_01.jpg)

图 1.1 - 一个示例输出，显示了 Linux 系统上安装的 Ansible 版本

重要提示

请注意，`ansible`是用于执行临时单个任务的可执行文件，而`ansible-playbook`是用于处理 playbook 以编排多个任务的可执行文件。我们将在本书的后面介绍临时任务和 playbook 的概念。

Ansible 的配置可以存在于几个不同的位置，将使用找到的第一个文件。搜索涉及以下内容：

+   `ANSIBLE_CFG`：如果设置了此环境变量，则会使用它。

+   `ansible.cfg`：这位于当前工作目录中。

+   `~/.ansible.cfg`：这位于用户的主目录中。

+   `/etc/ansible/ansible.cfg`：系统的默认中央 Ansible 配置文件。

某些安装方法可能包括将`config`文件放置在其中一个位置。查看一下是否存在这样的文件，并查看文件中的设置，以了解 Ansible 操作可能会受到影响的情况。本书假设`ansible.cfg`文件中没有设置会影响 Ansible 的默认操作。

# 清单解析和数据源

在 Ansible 中，没有清单就不会发生任何事情。即使在本地主机上执行的临时操作也需要清单-尽管该清单可能只包括本地主机。清单是 Ansible 架构的最基本构建块。在执行`ansible`或`ansible-playbook`时，必须引用清单。清单是存在于运行`ansible`或`ansible-playbook`的同一系统上的文件或目录。清单的位置可以在运行时使用`--inventory-file (-i)`参数或通过在 Ansible `config`文件中定义路径来定义。

清单可以是静态的或动态的，甚至可以是两者的组合，Ansible 不限于单个清单。标准做法是将清单分割成逻辑边界，例如暂存和生产，允许工程师对暂存环境运行一组操作，然后跟随着对生产清单集运行相同的操作。

可以包括变量数据，例如如何连接到清单中特定主机的具体细节，以及以各种方式包含清单，我们将探讨可用的选项。

## 静态清单

静态清单是所有清单选项中最基本的。通常，静态清单将包含一个`ini`格式的单个文件。还支持其他格式，包括 YAML，但您会发现当大多数人开始使用 Ansible 时，通常会使用`ini`。以下是描述单个主机`mastery.example.name`的静态清单文件的示例：

```
mastery.example.name 
```

就是这样。只需列出清单中系统的名称。当然，这并没有充分利用清单所提供的所有功能。如果每个名称都像这样列出，所有操作都必须引用特定的主机名，或者特殊的内置`all`组（顾名思义，包含清单中的所有主机）。在开发跨您的基础设施中的不同环境的 playbook 时，这可能会非常繁琐。至少，主机应该被分组。

一个很好的设计模式是根据预期功能将系统分组。起初，如果您的环境中单个系统可以扮演许多不同的角色，这可能看起来很困难，但这完全没问题。清单中的系统可以存在于多个组中，甚至组中还可以包含其他组！此外，在列出组和主机时，可以列出没有组的主机。这些主机必须在定义任何其他组之前列出。让我们在之前的示例基础上扩展我们的清单，增加一些更多的主机和分组，如下所示：

```
[web] 
mastery.example.name 

[dns] 
backend.example.name 

[database] 
backend.example.name 

[frontend:children] 
web 

[backend:children] 
dns 
database 
```

在这里，我们创建了一个包含一个系统的三个组，然后又创建了两个逻辑上将所有三个组合在一起的组。是的，没错：您可以有组的组。这里使用的语法是`[groupname:children]`，这表明给 Ansible 的清单解析器，名为`groupname`的这个组只是其他组的分组。

在这种情况下，`children`是其他组的名称。这个清单现在允许针对特定主机、低级别的角色特定组或高级别的逻辑分组编写操作，或者两者的任意组合。

通过使用通用的组名，比如`dns`和`database`，Ansible play 可以引用这些通用组，而不是明确的主机。工程师可以创建一个清单文件，用预生产阶段环境中的主机填充这些组，另一个清单文件用于生产环境中这些组的版本。当在预生产或生产环境中执行时，playbook 的内容不需要更改，因为它引用了存在于两个清单中的通用组名。只需引用正确的清单以在所需的环境中执行它。

## 清单排序

在 Ansible 2.4 版本中，添加了一个新的 play-level 关键字`order`。在此之前，Ansible 按照清单文件中指定的顺序处理主机，并且即使在更新的版本中，默认情况下仍然如此。但是，可以为给定的 play 设置`order`关键字的以下值，从而得到主机的处理顺序，如下所述：

+   `inventory`：这是默认选项。它只是意味着 Ansible 会像以往一样进行处理，按照`inventory`文件中指定的顺序处理主机。

+   `reverse_inventory`：这导致主机按照`inventory`文件中指定的相反顺序进行处理。

+   `sorted`：按名称按字母顺序处理主机。

+   `reverse_sorted`：按照字母顺序的相反顺序处理主机。

+   `shuffle`：主机以随机顺序处理，每次运行都会随机排序。

在 Ansible 中，使用的字母排序也称为词典排序。简单地说，这意味着值按字符串排序，字符串从左到右处理。因此，假设我们有三个主机：`mastery1`，`mastery11`和`mastery2`。在这个列表中，`mastery1`首先出现在字符位置`8`是`1`。然后是`mastery11`，因为位置`8`的字符仍然是`1`，但现在在位置`9`有一个额外的字符。最后是`mastery2`，因为字符`8`是`2`，而`2`在`1`之后。这很重要，因为从数字上来看，我们知道`11`大于`2`。但是，在这个列表中，`mastery11`在`mastery2`之前。您可以通过在主机名上添加前导零来轻松解决这个问题；例如，`mastery01`，`mastery02`和`mastery11`将按照它们在这个句子中列出的顺序进行处理，解决了词典排序的问题。

## 清单变量数据

清单不仅提供系统名称和分组，还可以传递有关系统的数据。这些数据可能包括以下内容：

+   用于在模板中使用的特定于主机的数据

+   用于任务参数或条件的特定于组的数据

+   调整 Ansible 与系统交互的行为参数

变量是 Ansible 中强大的构造，可以以各种方式使用，不仅仅是这里描述的方式。在 Ansible 中几乎可以包括变量引用的每一件事。虽然 Ansible 可以在设置阶段发现有关系统的数据，但并非所有数据都可以被发现。使用清单定义数据可以扩展这一点。请注意，变量数据可以来自许多不同的来源，一个来源可能会覆盖另一个。我们将在本章后面介绍变量优先级的顺序。

让我们改进现有的示例清单，并向其中添加一些变量数据。我们将添加一些特定于主机和特定于组的数据：

```
[web] 
mastery.example.name ansible_host=192.168.10.25 

[dns] 
backend.example.name 

[database] 
backend.example.name 

[frontend:children] 
web 

[backend:children] 
dns 
database 

[web:vars] 
http_port=88 
proxy_timeout=5 

[backend:vars] 
ansible_port=314 

[all:vars] 
ansible_ssh_user=otto 
```

在这个例子中，我们将`mastery.example.name`的`ansible_host`定义为`192.168.10.25`的 IP 地址。`ansible_host`变量是一个**行为清单变量**，旨在改变 Ansible 在与此主机操作时的行为方式。在这种情况下，该变量指示 Ansible 使用提供的 IP 地址连接到系统，而不是使用`mastery.example.name`进行名称的 DNS 查找。在本节的末尾列出了许多其他行为清单变量，以及它们的预期用途。

我们的新清单数据还为 web 和 backend 组提供了组级变量。web 组定义了`http_port`，可以在**NGINX**配置文件中使用，并且`proxy_timeout`，可能用于确定**HAProxy**的行为。backend 组利用了另一个行为清单参数，指示 Ansible 使用端口`314`连接到此组中的主机，而不是默认的`22`。

最后，引入了一个构造，通过使用内置的`all`组在清单中的所有主机之间提供变量数据。在这个特定的例子中，我们指示 Ansible 在连接到系统时以`otto`用户登录。这也是一个行为变化，因为 Ansible 的默认行为是以在控制主机上执行`ansible`或`ansible-playbook`的用户相同的用户名登录。

以下是行为清单变量及其意图修改的行为的列表：

+   `ansible_host`：这是 Ansible 将要连接的 DNS 名称或 Docker 容器名称。

+   `ansible_port`：这指定了 Ansible 将用于连接清单主机的端口号，如果不是默认值`22`。

+   `ansible_user`：这指定了 Ansible 将用于与清单主机连接的用户名，无论连接类型如何。

+   `ansible_password`：这用于为认证到清单主机提供密码给 Ansible，与`ansible_user`一起使用。仅用于测试目的 - 您应该始终使用保险库来存储诸如密码之类的敏感数据（请参阅*第三章*，*使用 Ansible 保护您的秘密*）。

+   `ansible_ssh_private_key_file`：这用于指定将用于连接到清单主机的 SSH 私钥文件，如果您没有使用默认值或`ssh-agent`。

+   `ansible_ssh_common_args`：这定义了要附加到`ssh`、`sftp`和`scp`的默认参数的 SSH 参数。

+   `ansible_sftp_extra_args`：这用于指定在 Ansible 调用时将传递给`sftp`二进制文件的附加参数。

+   `ansible_scp_extra_args`：这用于指定在 Ansible 调用时将传递给`scp`二进制文件的附加参数。

+   `ansible_ssh_extra_args`：这用于指定在 Ansible 调用时将传递给`ssh`二进制文件的附加参数。

+   `ansible_ssh_pipelining`：此设置使用布尔值来定义是否应该为此主机使用 SSH 流水线。

+   `ansible_ssh_executable`：此设置覆盖了此主机的 SSH 可执行文件的路径。

+   `ansible_become`：这定义了是否应该在此主机上使用特权升级（`sudo`或其他）。

+   `ansible_become_method`：这是用于特权升级的方法，可以是`sudo`、`su`、`pbrun`、`pfexec`、`doas`、`dzdo`或`ksu`之一。

+   `ansible_become_user`：这是通过特权升级要切换到的用户，通常在 Linux 和 Unix 系统上是 root。

+   `ansible_become_password`：这是用于特权升级的密码。仅用于测试目的；您应该始终使用保险库来存储诸如密码之类的敏感数据（请参阅*第三章*，*使用 Ansible 保护您的秘密*）。

+   `ansible_become_exe`：这用于设置所选升级方法的可执行文件，如果您没有使用系统定义的默认方法。

+   `ansible_become_flags`：这用于设置传递给所选升级可执行文件的标志（如果需要）。

+   `ansible_connection`：这是主机的连接类型。候选项包括`local`、`smart`、`ssh`、`paramiko`、`docker`或`winrm`（我们将在本书的后面更详细地讨论这个）。在任何现代 Ansible 发行版中，默认设置为`smart`（这会检测是否支持`ControlPersist` SSH 功能，如果支持，则使用`ssh`作为连接类型；否则，它会回退到`paramiko`）。

+   `ansible_docker_extra_args`：这用于指定将传递给给定清单主机上的远程 Docker 守护程序的额外参数。

+   `ansible_shell_type`：这用于确定问题清单主机的 shell 类型。默认为`sh`风格的语法，但可以设置为`csh`或`fish`以适用于使用这些 shell 的系统。

+   `ansible_shell_executable`：这用于确定问题清单主机的 shell 类型。默认为`sh`风格的语法，但可以设置为`csh`或`fish`以适用于使用这些 shell 的系统。

+   `ansible_python_interpreter`：这用于手动设置清单中给定主机上 Python 的路径。例如，某些 Linux 发行版安装了多个 Python 版本，确保设置正确的版本非常重要。例如，主机可能同时拥有`/usr/bin/python27`和`/usr/bin/python3`，这用于定义将使用哪个版本。

+   `ansible_*_interpreter`：这用于 Ansible 可能依赖的任何其他解释语言（例如 Perl 或 Ruby）。这将用指定的解释器二进制替换解释器二进制。

## 动态清单

静态清单非常好，对许多情况可能足够。然而，有时静态编写的主机集合管理起来太过繁琐。考虑清单数据已经存在于不同系统中的情况，例如 LDAP、云计算提供商或内部配置管理数据库（清单、资产跟踪和数据仓库）系统。复制这些数据将是浪费时间和精力，在按需基础设施的现代世界中，这些数据很快就会变得陈旧或变得灾难性不正确。

当您的站点超出单一剧本集的范围时，可能需要动态清单源的另一个例子。多个剧本存储库可能会陷入持有相同清单数据的多个副本，或者必须创建复杂的流程来引用数据的单个副本。可以轻松利用外部清单来访问存储在剧本存储库之外的常见清单数据，以简化设置。幸运的是，Ansible 不仅限于静态清单文件。

动态清单源（或插件）是 Ansible 在运行时调用的可执行文件，用于发现实时清单数据。这个可执行文件可以访问外部数据源并返回数据，或者它可以只解析已经存在但可能不符合`ini/yaml` Ansible 清单格式的本地数据。虽然可能并且很容易开发自己的动态清单源，我们将在后面的章节中介绍，但 Ansible 提供了越来越多的示例清单插件。这包括但不限于以下内容：

+   OpenStack Nova

+   Rackspace Public Cloud

+   DigitalOcean

+   Linode

+   Amazon EC2

+   Google Compute Engine

+   Microsoft Azure

+   Docker

+   Vagrant

许多这些插件都需要一定程度的配置，比如 EC2 的用户凭据或者**OpenStack Nova**的认证端点。由于无法为 Ansible 配置额外的参数以传递给清单脚本，因此脚本的配置必须通过从已知位置读取的`ini`配置文件或者从用于执行`ansible`或`ansible-playbook`的 shell 环境中读取的环境变量来管理。另外，请注意，有时这些清单脚本需要外部库才能正常运行。

当`ansible`或`ansible-playbook`指向清单源的可执行文件时，Ansible 将使用单个参数`--list`执行该脚本。这样，Ansible 可以获取整个清单的列表，以便构建其内部对象来表示数据。一旦数据构建完成，Ansible 将使用不同的参数执行脚本，以发现每个主机的变量数据。在此执行中使用的参数是`--host <hostname>`，它将返回特定于该主机的任何变量数据。

清单插件的数量太多，我们无法在本书中详细介绍每一个。然而，设置和使用几乎所有这些插件都需要类似的过程。因此，为了演示该过程，我们将介绍如何使用 EC2 动态清单。

许多动态清单插件都作为`community.general`集合的一部分安装，默认情况下，当您安装 Ansible 4.0.0 时会安装该集合。尽管如此，使用任何动态清单插件的第一步是找出插件属于哪个集合，并在必要时安装该集合。EC2 动态清单插件作为`amazon.aws`集合的一部分安装。因此，您的第一步将是安装此集合-您可以使用以下命令完成：

```
ansible-galaxy collection install amazon.aws
```

如果一切顺利，您应该在终端上看到与*图 1.2*中类似的输出。

![图 1.2 - 使用 ansible-galaxy 安装 amazon.aws 集合的安装](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_01_02.jpg)

图 1.2 - 使用 ansible-galaxy 安装 amazon.aws 集合的安装

每当您安装新的插件或集合时，都建议阅读附带的文档，因为一些动态清单插件需要额外的库或工具才能正常运行。例如，如果您参考[`docs.ansible.com/ansible/latest/collections/amazon/aws/aws_ec2_inventory.html`](https://docs.ansible.com/ansible/latest/collections/amazon/aws/aws_ec2_inventory.html)中`aws_ec2`插件的文档，您将看到该插件需要`boto3`和`botocore`库才能运行。安装这些库将取决于您的操作系统和 Python 环境。然而，在 Ubuntu Server 20.04（以及其他 Debian 变体）上，可以使用以下命令完成：

```
sudo apt install python3-boto3 python3-botocore
```

以下是上述命令的输出：

![图 1.3 - 为 EC2 动态清单脚本安装 Python 依赖项](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_01_03.jpg)

图 1.3 - 为 EC2 动态清单脚本安装 Python 依赖项

现在，查看插件的文档（通常情况下，您还可以通过查看代码和任何附带的配置文件来找到有用的提示），您会注意到我们需要以某种方式向此脚本提供我们的 AWS 凭据。有几种可能的方法可以做到这一点-一个例子是使用`awscli`工具（如果已安装）来定义配置，然后从您的清单中引用此配置文件。例如，我使用以下命令配置了我的默认 AWS CLI 配置文件：

```
aws configure
```

输出将类似于以下屏幕截图（出于明显原因，已删除了安全细节！）：

![图 1.4 - 使用 AWS CLI 实用程序配置 AWS 凭据](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_01_04.jpg)

图 1.4 - 使用 AWS CLI 实用程序配置 AWS 凭据

完成这些操作后，我们现在可以创建我们的清单定义，告诉 Ansible 使用哪个插件，并向其传递适当的参数。在我们的示例中，我们只需要告诉插件使用我们之前创建的默认配置文件。创建一个名为`mastery_aws_ec2.yml`的文件，其中包含以下内容：

```
---
plugin: amazon.aws.aws_ec2
boto_profile: default
```

最后，我们将通过使用`-graph`参数将我们的新清单插件配置传递给`ansible-inventory`命令来测试它：

```
ansible-inventory -i mastery_aws_ec2.yml –-graph
```

假设您在 AWS EC2 中运行了一些实例，您将看到类似以下的输出：

![图 1.5 - 动态清单插件的示例输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_01_05.jpg)

图 1.5 - 动态清单插件的示例输出

哇！我们有我们当前 AWS 清单的列表，以及插件执行的自动分组的一瞥。如果您想进一步了解插件的功能，并查看每个主机分配的所有清单变量（其中包含有用的信息，包括实例类型和大小），请尝试将`-list`参数传递给`ansible-inventory`，而不是`-graph`。

有了 AWS 清单，您可以立即使用它来针对这个动态清单运行单个任务或整个 playbook。例如，要使用`ansible.builtin.ping`模块检查 Ansible 对清单中所有主机的身份验证和连接性，您可以运行以下命令：

```
ansible -i mastery_aws_ec2.yml all -m ansible.builtin.ping
```

当然，这只是一个例子。然而，如果您对其他动态清单提供程序遵循这个过程，您应该能够轻松地使它们工作。

在*第十章*，*扩展 Ansible*中，我们将开发自己的自定义清单插件，以演示它们的操作方式。

## 运行时清单添加

就像静态清单文件一样，重要的是要记住，Ansible 将在每次`ansible`或`ansible-playbook`执行时解析这些数据一次，而且只有一次。这对于云动态源的用户来说是一个相当常见的绊脚石，经常会出现 playbook 创建新的云资源，然后尝试将其用作清单的一部分。这将失败，因为在 playbook 启动时，该资源不是清单的一部分。然而，一切并非都已经丧失！提供了一个特殊的模块，允许 playbook 临时将清单添加到内存中的清单对象，即`ansible.builtin.add_host`模块。

该模块有两个选项：`name`和`groups`。`name`选项应该很明显；它定义了 Ansible 在连接到这个特定系统时将使用的主机名。`groups`选项是一个逗号分隔的组列表，您可以将其添加到这个新系统中。传递给该模块的任何其他选项都将成为该主机的主机变量数据。例如，如果我们想要添加一个新系统，命名为`newmastery.example.name`，将其添加到`web`组，并指示 Ansible 通过 IP 地址`192.168.10.30`连接到它。这将创建一个类似以下的任务：

```
- name: add new node into runtime inventory 
  ansible.builtin.add_host: 
    name: newmastery.example.name 
    groups: web 
    ansible_host: 192.168.10.30 
```

这个新主机将可供使用 - 无论是通过提供的名称还是通过`web`组 - 用于`ansible-playbook`执行的其余部分。然而，一旦执行完成，除非它已被添加到清单源本身，否则该主机将不可用。当然，如果这是一个新创建的云资源，下一个从该云源获取动态清单的`ansible`或`ansible-playbook`执行将会捕获到新的成员。

## 清单限制

如前所述，每次执行`ansible`或`ansible-playbook`都将解析其所提供的整个清单。即使应用了限制，这也是真实的。简单地说，通过使用`--limit`运行时参数来运行`ansible`或`ansible-playbook`来在运行时应用限制。该参数接受一个模式，本质上是应用于清单的掩码。整个清单被解析，每次 play 时，所提供的限制掩码都限制了 play 只针对已指定的模式运行。

让我们以前的清单示例，并演示有限制和无限制时 Ansible 的行为。如果您还记得，我们有一个特殊的组`all`，我们可以用它来引用清单中的所有主机。假设我们的清单写在当前工作目录中，文件名为`mastery-hosts`，我们将构建一个 playbook 来演示 Ansible 正在操作的主机。让我们将这个 playbook 写成`mastery.yaml`：

```
--- 
- name: limit example play 
  hosts: all
  gather_facts: false 

  tasks: 
    - name: tell us which host we are on 
      ansible.builtin.debug: 
        var: inventory_hostname 
```

`ansible.builtin.debug`模块用于打印文本或变量的值。在本书中，我们将经常使用这个模块来模拟在主机上实际执行的工作。

现在，让我们执行这个简单的 playbook，而不提供限制。为了简单起见，我们将指示 Ansible 使用本地连接方法，这将在本地执行，而不是尝试 SSH 到这些不存在的主机。运行以下命令：

```
ansible-playbook -i mastery-hosts -c local mastery.yaml
```

输出应该与*图 1.6*类似：

![图 1.6 - 在未应用限制的清单上运行简单的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_01_06.jpg)

图 1.6 - 在未应用限制的清单上运行简单的 playbook

如您所见，`backend.example.name`和`mastery.example.name`主机都被操作了。现在，让我们看看如果我们提供一个限制会发生什么，也就是说，通过运行以下命令来限制我们的运行只针对前端系统：

```
ansible-playbook -i mastery-hosts -c local mastery.yaml --limit frontend
```

这一次，输出应该与*图 1.7*类似：

![图 1.7 - 在应用了限制的清单上运行简单的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_01_07.jpg)

图 1.7 - 在应用了限制的清单上运行简单的 playbook

在这里，我们可以看到这次只有`mastery.example.name`被操作了。虽然没有视觉线索表明整个清单已被解析，但如果我们深入研究 Ansible 代码并检查清单对象，我们确实会发现其中的所有主机。此外，我们将看到每次查询对象时限制是如何应用的。

重要的是要记住，无论在 play 中使用的主机模式，还是在运行时提供的限制，Ansible 都会在每次运行时解析整个清单。事实上，我们可以通过尝试访问`backend.example.name`的`ansible_port`变量数据来证明这一点，这个系统在其他情况下会被我们的限制掩盖。让我们稍微扩展一下我们的 playbook，并尝试访问`backend.example.name`的`ansible_port`变量：

```
--- 
- name: limit example play 
  hosts: all 
  gather_facts: false 

  tasks: 
    - name: tell us which host we are on 
      ansible.builtin.debug: 
        var: inventory_hostname 

    - name: grab variable data from backend 
      ansible.builtin.debug: 
        var: hostvars['backend.example.name']['ansible_port'] 
```

我们仍然会通过与上一次运行相同的命令来应用我们的限制，这将限制我们的操作仅限于`mastery.example.name`：

![图 1.8 - 演示即使应用了限制，整个清单仍然被解析](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_01_08.jpg)

图 1.8 - 演示即使应用了限制，整个清单仍然被解析

我们已成功访问了主机变量数据（通过组变量）的系统，否则会被限制。这是一个重要的技能，因为它允许更高级的场景，比如将任务指向一个被限制的主机。此外，可以使用委托来操纵负载均衡器；这将在升级系统时将系统置于维护模式，而无需将负载均衡器系统包含在限制掩码中。

# playbook 解析

清单来源的整个目的是有系统可以操作。操作来自 playbook（或者，在 Ansible 即席执行的情况下，简单的单任务 play）。您应该已经对 playbook 的构建有基本的了解，因此我们不会花太多时间来介绍；但是，我们将深入探讨 playbook 的解析方式的一些具体细节。具体来说，我们将涵盖以下内容：

+   操作顺序

+   相对路径假设

+   播放行为键

+   为 play 和任务选择主机

+   播放和任务名称

## 操作顺序

Ansible 旨在尽可能地让人类理解。开发人员努力在人类理解和机器效率之间取得最佳平衡。为此，几乎可以假定 Ansible 中的所有操作都是按自上而下的顺序执行的；也就是说，文件顶部列出的操作将在文件底部列出的操作之前完成。话虽如此，还有一些注意事项，甚至有一些影响操作顺序的方法。

playbook 只有两个主要操作可以完成。它可以运行一个 play，或者它可以从文件系统的某个地方包含另一个 playbook。这些操作的完成顺序只是它们在 playbook 文件中出现的顺序，从上到下。重要的是要注意，虽然操作是按顺序执行的，但在任何执行之前整个 playbook 和任何包含的 playbook 都会被完全解析。这意味着任何包含的 playbook 文件必须在 playbook 解析时存在-它们不能在较早的操作中生成。这是特定于 playbook 包含的，但不一定适用于可能出现在 play 中的任务包含，这将在后面的章节中介绍。

在 play 中，还有一些更多的操作。虽然 playbook 严格按照自上而下的顺序排列，但 play 具有更细致的操作顺序。以下是可能的操作列表以及它们将发生的顺序：

+   变量加载

+   事实收集

+   `pre_tasks`执行

+   从`pre_tasks`执行通知的处理程序

+   角色执行

+   任务执行

+   从角色或任务执行通知的处理程序

+   `post_tasks`执行

+   从`post_tasks`执行通知的处理程序

以下是一个示例 play，其中显示了大部分这些操作：

```
--- 
- hosts: localhost 
  gather_facts: false 

  vars: 
    - a_var: derp 

  pre_tasks: 
    - name: pretask 
      debug: 
        msg: "a pre task" 
      changed_when: true 
      notify: say hi 

  roles: 
    - role: simple 
      derp: newval 

  tasks: 
    - name: task 
      debug: 
        msg: "a task" 
      changed_when: true 
      notify: say hi

  post_tasks: 
    - name: posttask 
      debug: 
        msg: "a post task" 
      changed_when: true 
      notify: say hi 
  handlers:
    - name: say hi
      debug:
        msg: hi
```

无论这些块在剧本中列出的顺序如何，前面代码块中详细说明的顺序就是它们将被处理的顺序。处理程序（即可以由其他任务触发并导致更改的任务）是一个特殊情况。有一个实用模块`ansible.builtin.meta`，可以用来在特定点触发处理程序的处理：

```
- ansible.builtin.meta: flush_handlers 
```

这将指示 Ansible 在继续下一个任务或播放中的下一个操作块之前，在那一点处理任何待处理的处理程序。了解顺序并能够通过`flush_handlers`影响顺序是在需要编排复杂操作时必须具备的另一个关键技能；例如，诸如服务重启对顺序非常敏感的情况。考虑服务的初始部署。

play 将有修改`config`文件并指示应该在这些文件更改时重新启动服务的任务。play 还将指示服务应该在运行。第一次发生这个 play 时，`config`文件将更改，并且服务将从未运行变为运行。然后，处理程序将触发，这将导致服务立即重新启动。这可能会对服务的任何使用者造成干扰。最好在最后一个任务之前刷新处理程序，以确保服务正在运行。这样，重新启动将在初始启动之前发生，因此服务将启动一次并保持运行。

## 相对路径假设

当 Ansible 解析一个 playbook 时，可以对 playbook 中的语句引用的项目的相对路径做出一些假设。在大多数情况下，诸如要包含的变量文件、要包含的任务文件、要包含的 playbook 文件、要复制的文件、要渲染的模板和要执行的脚本等的路径都是相对于引用它们的文件所在的目录的。让我们通过一个示例 playbook 和目录列表来探讨这一点，以演示文件的位置：

+   目录结构如下：

```
. 
├── a_vars_file.yaml 
├── mastery-hosts 
├── relative.yaml 
└── tasks 
├── a.yaml 
└── b.yaml 
```

+   `a_vars_file.yaml`的内容如下：

```
--- 
something: "better than nothing" 
```

+   `relative.yaml`的内容如下：

```
--- 
- name: relative path play 
hosts: localhost 
gather_facts: false 

vars_files: 
    - a_vars_file.yaml

tasks: 
- name: who am I 
ansible.builtin.debug: 
msg: "I am mastery task" 
- name: var from file 
      ansible.builtin.debug:         
var: something 

- ansible.builtin.include: tasks/a.yaml 
```

+   `tasks/a.yaml`的内容如下：

```
--- 
- name: where am I 
ansible.builtin.debug: 
msg: "I am task a" 

- ansible.builtin.include: b.yaml 
```

+   `tasks/b.yaml`的内容如下：

```
---
- name: who am I
  ansible.builtin.debug:
msg: "I am task b" 
```

使用以下命令执行 playbook：

```
ansible-playbook -i mastery-hosts -c local relative.yaml
```

输出应类似于*图 1.9*：

![图 1.9 - 运行利用相对路径的 playbook 的预期输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_01_09.jpg)

图 1.9 - 运行利用相对路径的 playbook 的预期输出

在这里，我们可以清楚地看到对路径的相对引用以及它们相对于引用它们的文件的位置。在使用角色时，还有一些额外的相对路径假设；然而，我们将在后面的章节中详细介绍。

## Play 行为指令

当 Ansible 解析一个 play 时，它会寻找一些指令，以定义 play 的各种行为。这些指令与`hosts:`指令在同一级别编写。以下是一些在 playbook 的这一部分中可以定义的一些更常用键的描述列表：

+   `any_errors_fatal`：这是一个布尔指令，用于指示 Ansible 将任何失败都视为致命错误，以防止尝试进一步的任务。这会改变默认行为，其中 Ansible 将继续执行，直到所有任务完成或所有主机失败。

+   `connection`：这个字符串指令定义了在给定 play 中使用哪种连接系统。在这里做出的一个常见选择是`local`，它指示 Ansible 在本地执行所有操作，但使用清单中系统的上下文。

+   `collections`：这是在 play 中用于搜索模块、插件和角色的集合命名空间列表，可以用来避免输入**完全限定的集合名称**（**FQCNs**）的需要 - 我们将在*第二章*中了解更多，*从早期 Ansible 版本迁移*。请注意，这个值不会被角色任务继承，因此您必须在`meta/main.yml`文件中为每个角色单独设置它。

+   `gather_facts`：这个布尔指令控制 Ansible 是否执行操作的事实收集阶段，其中一个特殊任务将在主机上运行，以揭示关于系统的各种事实。跳过事实收集 - 当您确定不需要任何已发现的数据时 - 可以在大型环境中节省大量时间。

+   `Max_fail_percentage`：这个数字指令类似于`any_errors_fatal`，但更加细致。它允许您定义在整个操作被停止之前，您的主机可以失败的百分比。

+   `no_log`：这是一个布尔指令，用于控制 Ansible 是否记录（到屏幕和/或配置的`log`文件）给定的命令或从任务接收的结果。如果您的任务或返回涉及机密信息，这一点非常重要。这个键也可以直接应用于一个任务。

+   `port`：这是一个数字指令，用于定义连接时应使用的 SSH 端口（或任何其他远程连接插件），除非这已经在清单数据中配置。

+   `remote_user`：这是一个字符串指令，定义了在远程系统上使用哪个用户登录。默认设置是以与启动`ansible-playbook`的相同用户连接。

+   `serial`：此指令接受一个数字，并控制在移动到播放中的下一个任务之前，Ansible 将在多少个系统上执行任务。这与正常操作顺序有很大的改变，在正常操作顺序中，任务在移动到下一个任务之前会在播放中的每个系统上执行。这在滚动更新场景中非常有用，我们将在后面的章节中讨论。

+   `become`：这是一个布尔指令，用于配置是否应在远程主机上使用特权升级（`sudo`或其他内容）来执行任务。此键也可以在任务级别定义。相关指令包括`become_user`、`become_method`和`become_flags`。这些可以用于配置升级的方式。

+   `strategy`：此指令设置用于播放的执行策略。

本书中的示例 playbooks 将使用许多这些键。

有关可用播放指令的完整列表，请参阅[`docs.ansible.com/ansible/latest/reference_appendices/playbooks_keywords.html#play`](https://docs.ansible.com/ansible/latest/reference_appendices/playbooks_keywords.html#play)上的在线文档。

## 执行策略

随着 Ansible 2.0 的发布，引入了一种控制播放执行行为的新方法：*strategy*。策略定义了 Ansible 如何在一组主机上协调每个任务。每个策略都是一个插件，Ansible 带有三种策略：linear、debug 和 free。线性策略是默认策略，这是 Ansible 一直以来的行为方式。在执行播放时，给定播放的所有主机执行第一个任务。

一旦它们全部完成，Ansible 就会移动到下一个任务。串行指令可以创建批处理主机以这种方式操作，但基本策略保持不变。在执行下一个任务之前，给定批次的所有目标都必须完成一个任务。调试策略使用了前面描述的相同的线性执行模式，只是这里，任务是在交互式调试会话中运行，而不是在没有任何用户干预的情况下运行到完成。这在测试和开发复杂和/或长时间运行的自动化代码时特别有价值，您需要分析 Ansible 代码运行时的行为，而不仅仅是运行它并希望一切顺利！

自由策略打破了这种传统的线性行为。使用自由策略时，一旦主机完成一个任务，Ansible 将立即为该主机执行下一个任务，而不必等待其他主机完成。

这将发生在集合中的每个主机和播放中的每个任务。每个主机将尽可能快地完成任务，从而最大限度地减少每个特定主机的执行时间。虽然大多数 playbooks 将使用默认的线性策略，但也有一些情况下，自由策略会更有优势；例如，在跨大量主机升级服务时。如果播放需要执行大量任务来执行升级，从关闭服务开始，那么每个主机尽可能少地遭受停机时间就更为重要。

允许每个主机独立地尽快地通过播放，将确保每个主机只在必要的时间内停机。如果不使用自由策略，整个集合将会在集合中最慢的主机完成任务所需的时间内停机。

由于自由策略不协调主机之间的任务完成，因此不可能依赖在一个主机上生成的数据在另一个主机上的后续任务中可用。不能保证第一个主机已经完成生成数据的任务。

执行策略被实现为一个插件，因此任何希望为项目做出贡献的人都可以开发自定义策略来扩展 Ansible 的行为。

## 播放和任务的主机选择

大多数播放定义的第一件事（当然是名称之后）是播放的主机模式。这是用于从清单对象中选择主机以运行任务的模式。一般来说，这很简单；主机模式包含一个或多个块，指示主机、组、通配符模式或**正则表达式**（**regex**）用于选择。块之间用冒号分隔，通配符只是一个星号，正则表达式模式以波浪号开头：

```
hostname:groupname:*.example:~(web|db)\.example\.com 
```

高级用法可以包括组索引选择，甚至是组内的范围：

```
webservers[0]:webservers[2:4] 
```

每个块都被视为包含块；也就是说，找到在第一个模式中的所有主机都被添加到在下一个模式中找到的所有主机中，依此类推。但是，可以使用控制字符来改变它们的行为。使用和符号定义了基于包含的选择（存在于两个模式中的所有主机）。

感叹号的使用定义了一个基于排除的选择（存在于先前模式中的所有主机，但不在排除模式中）：

+   `webservers:&dbservers`：主机必须同时存在于`webservers`和`dbservers`组中。

+   `webservers:!dbservers`：主机必须存在于`webservers`组中，但不能存在于`dbservers`组中。

一旦 Ansible 解析模式，它将根据需要应用限制。限制以限制或失败的主机的形式出现。此结果将存储在播放的持续时间内，并且可以通过`play_hosts`变量访问。在执行每个任务时，将咨询此数据，并且可能会对其施加额外的限制以处理串行操作。当遇到故障时，无论是连接失败还是执行任务失败，故障主机都将被放置在限制列表中，以便在下一个任务中绕过该主机。

如果在任何时候，主机选择例程被限制为零个主机，播放执行将停止并显示错误。这里的一个警告是，如果播放配置为具有`max_fail_precentage`或`any_errors_fatal`参数，那么在满足此条件的任务之后，播放簿执行将立即停止。

## 播放和任务名称

虽然不是严格必要的，但将您的播放和任务标记为名称是一个好习惯。这些名称将显示在`ansible-playbook`的命令行输出中，并且如果将`ansible-playbook`的输出定向到日志文件中，这些名称也将显示在日志文件中。任务名称在您想要指示`ansible-playbook`从特定任务开始并引用处理程序时也会派上用场。

在命名播放和任务时，有两个主要要考虑的点：

+   播放和任务的名称应该是唯一的。

+   小心可以在播放和任务名称中使用的变量类型。

通常，为播放和任务命名是一个最佳实践，可以帮助快速确定问题任务可能位于播放簿、角色、任务文件、处理程序等层次结构中的位置。当您首次编写一个小型的单片播放簿时，它们可能看起来并不重要。然而，随着您对 Ansible 的使用和信心的增长，您很快会为自己命名任务而感到高兴！当任务名称重复时，在通知处理程序或从特定任务开始时，唯一性更为重要。当任务名称重复时，Ansible 的行为可能是不确定的，或者至少是不明显的。

以唯一性为目标，许多播放作者将寻求使用变量来满足这一约束。这种策略可能效果很好，但作者需要注意引用的变量数据的来源。变量数据可以来自各种位置（我们将在本章后面介绍），并且分配给变量的值可以多次定义。为了播放和任务名称的缘故，重要的是要记住，只有那些在播放解析时间可以确定值的变量才会正确解析和呈现。如果引用的变量的数据是通过任务或其他操作发现的，那么变量字符串将显示为未解析的输出。让我们看一个利用变量来命名播放和任务的示例播放：

```
---
- name: play with a {{ var_name }}
  hosts: localhost
  gather_facts: false
  vars:
  - var_name: not-mastery
  tasks:
  - name: set a variable
    ansible.builtin.set_fact:
      task_var_name: "defined variable"
  - name: task with a {{ task_var_name }}
    ansible.builtin.debug:
      msg: "I am mastery task"
- name: second play with a {{ task_var_name }}
  hosts: localhost
  gather_facts: false
  tasks:
  - name: task with a {{ runtime_var_name }}
    ansible.builtin.debug:
      msg: "I am another mastery task" 
```

乍一看，您可能期望至少`var_name`和`task_var_name`能够正确呈现。我们可以清楚地看到`task_var_name`在使用之前被定义。然而，凭借我们的知识，即播放在执行之前会被完全解析，我们知道得更多。使用以下命令运行示例播放：

```
ansible-playbook -i mastery-hosts -c local names.yaml
```

输出应该看起来像*图 1.10*：

![图 1.10 - 一个播放运行，显示在执行之前未定义变量时在任务名称中使用变量的效果](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_01_10.jpg)

图 1.10 - 一个播放运行，显示在执行之前未定义变量时在任务名称中使用变量的效果

正如您在*图 1.10*中所看到的，唯一正确呈现的变量名称是`var_name`，因为它被定义为静态播放变量。

# 模块传输和执行

一旦播放被解析并确定了主机，Ansible 就准备执行一个任务。任务由名称（这是可选的，但仍然很重要，如前面提到的），模块引用，模块参数和任务控制指令组成。在 Ansible 2.9 及更早版本中，模块由单个唯一名称标识。然而，在 Ansible 2.10 及更高版本中，集合的出现（我们将在下一章中更详细地讨论）意味着 Ansible 模块名称现在可以是非唯一的。因此，那些有先前 Ansible 经验的人可能已经注意到，在本书中，我们使用`ansible.builtin.debug`而不是在 Ansible 2.9 及更早版本中使用的`debug`。在某些情况下，您仍然可以使用短形式的模块名称（如`debug`）；但是，请记住，具有自己名为`debug`的集合的存在可能会导致意想不到的结果。因此，Ansible 在其官方文档中的建议是尽快开始与长形式的模块名称交朋友 - 这些被官方称为 FQCNs。我们将在本书中使用它们，并将在下一章中更详细地解释所有这些。除此之外，后面的章节将详细介绍任务控制指令，因此我们只关注模块引用和参数。

## 模块引用

每个任务都有一个模块引用。这告诉 Ansible 要执行哪个工作。Ansible 被设计为可以轻松地允许自定义模块与播放一起存在。这些自定义模块可以是全新的功能，也可以替换 Ansible 自身提供的模块。当 Ansible 解析一个任务并发现要用于任务的模块的名称时，它会在一系列位置中查找所请求的模块。它查找的位置也取决于任务所在的位置，例如，是否在一个角色内部。

如果任务位于一个角色内，Ansible 首先会在任务所在的角色内部名为`library`的目录树中查找模块。如果在那里找不到模块，Ansible 会在与主要剧本（由`ansible-playbook`执行引用的剧本）相同级别的目录中查找名为`library`的目录。如果在那里找不到模块，Ansible 最终会在配置的库路径中查找，该路径默认为`/usr/share/ansible/`。可以在 Ansible 的`config`文件或通过`ANSIBLE_LIBRARY`环境变量中配置此库路径。

除了之前已经确定为 Ansible 几乎自问世以来的有效模块位置之外，Ansible 2.10 和更新版本的出现带来了*Collections*。Collections 现在是模块可以组织和与他人共享的关键方式之一。例如，在之前的示例中，我们查看了 Amazon EC2 动态清单插件，我们安装了一个名为`amazon.aws`的集合。在该示例中，我们只使用了动态清单插件；但是，安装集合实际上安装了一整套模块供我们用于自动化 Amazon EC2 上的任务。如果您运行了本书中提供的命令，该集合将安装在`~/.ansible/collections/ansible_collections/amazon/aws`中。如果您在那里查看，您将在`plugins/modules`子目录中找到模块。您安装的其他集合将位于类似的目录中，这些目录的名称是根据安装的集合命名的。

这种设计使模块能够与集合、角色和剧本捆绑在一起，可以快速轻松地添加功能或修复问题。

## 模块参数

模块的参数并非总是必需的；模块的帮助输出将指示哪些参数是必需的，哪些是可选的。模块文档可以通过`ansible-doc`命令访问，如下所示（在这里，我们将使用`debug`模块，这是我们已经用作示例的模块）：

```
ansible-doc ansible.builtin.debug
```

*图 1.11*显示了您可以从此命令中期望的输出类型：

![图 1.11 - 运行在 debug 模块上的 ansible-doc 命令的输出示例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_01_11.jpg)

图 1.11 - 运行在 debug 模块上的 ansible-doc 命令的输出示例

如果您浏览输出，您将找到大量有用的信息，包括示例代码，模块的输出以及参数（即选项），如*图 1.11*所示。

参数可以使用**Jinja2**进行模板化，在模块执行时将被解析，允许在以后的任务中使用在先前任务中发现的数据；这是一个非常强大的设计元素。

参数可以以`key=value`格式或更符合 YAML 本机格式的复杂格式提供。以下是展示这两种格式的参数传递给模块的两个示例：

```
- name: add a keypair to nova 
  openstack.cloudkeypair: cloud={{ cloud_name }} name=admin-key wait=yes 

- name: add a keypair to nova 
  openstack.cloud.keypair:    
    cloud: "{{ cloud_name }}"     
    name: admin-key     
    wait: yes 
```

在这个例子中，这两种格式将导致相同的结果；但是，如果您希望将复杂参数传递给模块，则需要使用复杂格式。一些模块期望传递列表对象或数据的哈希；复杂格式允许这样做。虽然这两种格式对于许多任务都是可以接受的，但是复杂格式是本书中大多数示例使用的格式，因为尽管其名称如此，但实际上更容易阅读。

## 模块黑名单

从 Ansible 2.5 开始，系统管理员现在可以将他们不希望对剧本开发人员可用的 Ansible 模块列入黑名单。这可能是出于安全原因，为了保持一致性，甚至是为了避免使用已弃用的模块。

模块黑名单的位置由 Ansible 配置文件的`defaults`部分中找到的`plugin_filters_cfg`参数定义。默认情况下，它是禁用的，建议的默认值设置为`/etc/ansible/plugin_filters.yml`。

目前，该文件的格式非常简单。它包含一个版本头，以便将来更新文件格式，并列出要过滤掉的模块列表。例如，如果您准备过渡到 Ansible 4.0，当前使用的是 Ansible 2.7，您会注意到 `sf_account_manager` 模块将在 Ansible 4.0 中被完全移除。因此，您可能希望将其列入黑名单，以防止任何人在推出 Ansible 4.0 时创建会出错的代码（请参阅[`docs.ansible.com/ansible/devel/porting_guides/porting_guide_2.7.html`](https://docs.ansible.com/ansible/devel/porting_guides/porting_guide_2.7.html)）。因此，为了防止内部任何人使用这个模块，`plugin_filters.yml` 文件应该如下所示：

```
---
filter_version:'1.0'
module_blacklist:
  # Deprecated – to be removed in 4.0
  - sf_account_manager
```

尽管这个功能在帮助确保高质量的 Ansible 代码得到维护方面非常有用，但在撰写本文时，这个功能仅限于模块。它不能扩展到其他任何东西，比如角色。

## 传输和执行模块

一旦找到一个模块，Ansible 就必须以某种方式执行它。模块的传输和执行方式取决于一些因素；然而，通常的过程是在本地文件系统上定位模块文件并将其读入内存，然后添加传递给模块的参数。然后，在内存中的文件对象中添加来自 Ansible 核心的样板模块代码。这个集合被压缩、Base64 编码，然后包装在一个脚本中。接下来发生的事情取决于连接方法和运行时选项（例如将模块代码留在远程系统上供审查）。

默认的连接方法是 `smart`，通常解析为 `ssh` 连接方法。在默认配置下，Ansible 将打开一个 SSH 连接到远程主机，创建一个临时目录，然后关闭连接。然后，Ansible 将再次打开一个 SSH 连接，以便将内存中的包装 ZIP 文件（本地模块文件、任务模块参数和 Ansible 样板代码的结果）写入到我们刚刚创建的临时目录中的文件，并关闭连接。

最后，Ansible 将打开第三个连接，以执行脚本并删除临时目录及其所有内容。模块的结果以 JSON 格式从 `stdout` 中捕获，Ansible 将适当地解析和处理。如果任务有一个 `async` 控制，Ansible 将在模块完成之前关闭第三个连接，并在规定的时间内再次 SSH 到主机上，以检查任务的状态，直到模块完成或达到规定的超时时间。

### 任务性能

关于 Ansible 如何连接到主机的前面讨论导致每个任务对主机有三个连接。在一个任务数量较少的小环境中，这可能不是一个问题；然而，随着任务集的增长和环境规模的增长，创建和拆除 SSH 连接所需的时间也会增加。幸运的是，有几种方法可以缓解这种情况。

第一个是 SSH 功能 `ControlPersist`，它提供了一个机制，当首次连接到远程主机时创建持久套接字，可以在后续连接中重用，从而绕过创建连接时所需的一些握手。这可以大大减少 Ansible 打开新连接所花费的时间。如果运行 Ansible 的主机平台支持它，Ansible 会自动利用这个功能。要检查您的平台是否支持这个功能，请参考 SSH 的 `ControlPersist` 手册页。

可以利用的第二个性能增强功能是 Ansible 的一个特性，称为流水线。流水线适用于基于 SSH 的连接方法，并在 Ansible 配置文件的 `ssh_connection` 部分进行配置：

```
[ssh_connection] 
pipelining=true 
```

这个设置改变了模块的传输方式。与其打开一个 SSH 连接来创建一个目录，再打开一个连接来写入组合模块，再打开第三个连接来执行和清理，Ansible 会在远程主机上打开一个 SSH 连接。然后，在这个实时连接上，Ansible 会将压缩的组合模块代码和脚本输入，以便执行。这将连接数从三个减少到一个，这真的可以累积起来。默认情况下，为了与许多启用了`sudoers`配置文件中的`requiretty`的 Linux 发行版保持兼容性，流水线作业被禁用。

利用这两种性能调整的组合可以使您的 playbooks 保持快速，即使在扩展环境中也是如此。但是，请记住，Ansible 一次只会处理与配置为运行的 forks 数量相同的主机。Forks 是 Ansible 将分裂为与远程主机通信的工作进程的进程数量。默认值是五个 forks，这将一次处理最多五个主机。随着环境规模的增长，您可以通过调整 Ansible 配置文件中的`forks=`参数或使用`ansible`或`ansible-playbook`的`--forks (-f)`参数来提高这个数字，以处理更多的主机。

# 变量类型和位置

变量是 Ansible 设计的一个关键组成部分。变量允许动态的 play 内容和在不同的清单集中重复使用 play。除了最基本的 Ansible 使用之外，任何其他用途都会使用变量。了解不同的变量类型以及它们的位置以及学习如何访问外部数据或提示用户填充变量数据，是掌握 Ansible 的关键之一。

## 变量类型

在深入了解变量的优先级之前，首先我们必须了解 Ansible 可用的各种类型和子类型的变量，它们的位置以及可以在哪里使用。

第一个主要的变量类型是**清单变量**。这些是 Ansible 通过清单获取的变量。这些可以被定义为特定于`host_vars`、单个主机或适用于整个组的`group_vars`的变量。这些变量可以直接写入清单文件，通过动态清单插件传递，或者从`host_vars/<host>`或`group_vars/<group>`目录加载。

这些类型的变量可用于定义 Ansible 处理这些主机或与这些主机运行的应用程序相关的站点特定数据的行为。无论变量来自`host_vars`还是`group_vars`，它都将被分配给主机的`hostvars`，并且可以从 playbooks 和模板文件中访问。可以通过简单地引用名称来访问主机自己的变量，例如`{{ foobar }}`，并且可以通过访问`hostvars`来访问另一个主机的变量；例如，要访问`examplehost`的`foobar`变量，可以使用`{{ hostvars['examplehost']['foobar'] }}`。这些变量具有全局范围。

第二个主要的变量类型是**角色变量**。这些变量是特定于角色的，并且被角色任务所利用。然而，值得注意的是，一旦一个角色被添加到一个 playbook 中，它的变量通常可以在 playbook 的其余部分中访问，包括在其他角色中。在大多数简单的 playbooks 中，这并不重要，因为角色通常是一个接一个地运行的。但是当 playbook 结构变得更加复杂时，记住这一点是值得的；否则，由于在不同的角色中设置变量可能会导致意外行为！

这些变量通常作为**角色默认值**提供，即它们旨在为变量提供默认值，但在应用角色时可以轻松覆盖。当引用角色时，可以同时提供变量数据，无论是覆盖角色默认值还是创建全新的数据。我们将在后面的章节中更深入地介绍角色。这些变量适用于执行角色的所有主机，并且可以直接访问，就像主机自己的`hostvars`一样。

第三种主要的变量类型是**play 变量**。这些变量在 play 的控制键中定义，可以直接通过`vars`键或通过`vars_files`键从外部文件获取。此外，play 可以通过`vars_prompt`与用户交互地提示变量数据。这些变量应在 play 的范围内使用，并在 play 的任何任务或包含的任务中使用。这些变量适用于 play 中的所有主机，并且可以像`hostvars`一样被引用。

第四种变量类型是**任务变量**。任务变量是由执行任务或在 play 的事实收集阶段发现的数据制成的。这些变量是特定于主机的，并添加到主机的`hostvars`中，并且可以像这样使用，这也意味着它们在发现或定义它们的点之后具有全局范围。可以通过`gather_facts`和**事实模块**（即不改变状态而是返回数据的模块）发现这种类型的变量，通过`register`任务键从任务返回数据中填充，或者由使用`set_fact`或`add_host`模块的任务直接定义。还可以通过使用`pause`模块的`prompt`参数与操作员交互地获取数据并注册结果：

```
- name: get the operators name 
  ansible.builtin.pause: 
    prompt: "Please enter your name" 
  register: opname 
```

额外变量，或者`extra-vars`类型，是在执行`ansible-playbook`时通过`--extra-vars`命令行提供的变量。变量数据可以作为`key=value`对的列表，一个带引号的 JSON 数据，或者一个包含在变量数据中定义的 YAML 格式文件的引用：

```
--extra-vars "foo=bar owner=fred" 
--extra-vars '{"services":["nova-api","nova-conductor"]}' 
--extra-vars @/path/to/data.yaml 
```

额外变量被认为是全局变量。它们适用于每个主机，并在整个 playbook 中具有范围。

## 魔术变量

除了前面列出的变量类型，Ansible 还提供了一组值得特别提及的变量 - **魔术变量**。这些变量在运行 playbook 时始终设置，无需显式创建。它们的名称始终保留，不应用于其他变量。

魔术变量用于向 playbooks 本身提供有关当前 playbook 运行的信息，并且在 Ansible 环境变得更大更复杂时非常有用。例如，如果您的 play 需要有关当前主机属于哪些组的信息，`group_names`魔术变量将返回它们的列表。同样，如果您需要使用 Ansible 配置服务的主机名，`inventory_hostname`魔术变量将返回在清单中定义的当前主机名。一个简单的例子如下：

```
---
- name: demonstrate magic variables
  hosts: all
  gather_facts: false
  tasks:
    - name: tell us which host we are on
      ansible.builtin.debug:
        var: inventory_hostname
    - name: tell us which groups we are in
      ansible.builtin.debug:
        var: group_names
```

与 Ansible 项目中的所有内容一样，魔术变量都有很好的文档记录，您可以在官方 Ansible 文档中找到它们的完整列表以及它们包含的内容[`docs.ansible.com/ansible/latest/reference_appendices/special_variables.html`](https://docs.ansible.com/ansible/latest/reference_appendices/special_variables.html)。魔术变量使用的一个实际例子是：例如，从空白模板设置新一组 Linux 服务器的主机名。`inventory_hostname`魔术变量直接从清单中提供了我们需要的主机名，无需另一个数据源（或者例如连接到**CMDB**）。类似地，访问`groups_names`允许我们定义在单个 playbook 中应在给定主机上运行哪些 play - 例如，如果主机在`webservers`组中，则安装**NGINX**。通过这种方式，Ansible 代码可以变得更加灵活和高效；因此，这些变量值得特别一提。

# 访问外部数据

角色变量、play 变量和任务变量的数据也可以来自外部来源。Ansible 提供了一种机制，可以从**控制机器**（即运行`ansible-playbook`的机器）访问和评估数据。这种机制称为**查找插件**，Ansible 附带了许多这样的插件。这些插件可以用于通过读取文件查找或访问数据，在 Ansible 主机上生成并本地存储密码以供以后重用，评估环境变量，从可执行文件或 CSV 文件中导入数据，访问`Redis`或`etcd`系统中的数据，从模板文件中呈现数据，查询`dnstxt`记录等。语法如下：

```
lookup('<plugin_name>', 'plugin_argument') 
```

例如，要在`ansible.builtin.debug`任务中使用`etcd`中的`mastery`值，执行以下命令：

```
- name: show data from etcd 
  ansible.builtin.debug:     
    msg: "{{ lookup('etcd', 'mastery') }}" 
```

查找在引用它们的任务执行时进行评估，这允许动态数据发现。要在多个任务中重用特定查找并在每次重新评估它时，可以使用查找值定义 playbook 变量。每次引用 playbook 变量时，查找将被执行，随时间可能提供不同的值。

# 变量优先级

正如您在上一节中学到的，有几种主要类型的变量可以在多种位置定义。这引发了一个非常重要的问题：当相同的变量名称在多个位置使用时会发生什么？Ansible 有一个加载变量数据的优先级，因此，它有一个顺序和定义来决定哪个变量会获胜。变量值覆盖是 Ansible 的高级用法，因此在尝试这样的场景之前，完全理解语义是很重要的。

## 优先级顺序

Ansible 定义了以下优先顺序，靠近列表顶部的优先级最高。请注意，这可能会因版本而变化。实际上，自 Ansible 2.4 发布以来，它已经发生了相当大的变化，因此如果您正在从旧版本的 Ansible 进行升级，值得进行审查：

1.  额外的`vars`（来自命令行）总是优先。

1.  `ansible.builtin.include`参数。

1.  角色（和`ansible.builtin.include_role`）参数。

1.  使用`ansible.builtin.set_facts`定义的变量，以及使用`register`任务指令创建的变量。

1.  在 play 中包含的变量`ansible.builtin.include_vars`。

1.  任务`vars`（仅针对特定任务）。

1.  块`vars`（仅适用于块内的任务）。

1.  Role `vars`（在角色的`vars`子目录中的`main.yml`中定义）。

1.  Play `vars_files`。

1.  Play `vars_prompt`。

1.  Play `vars`。

1.  主机事实（以及`ansible.builtin.set_facts`的缓存结果）。

1.  `host_vars` playbook。

1.  `host_vars`清单。

1.  清单文件（或脚本）定义的主机`vars`。

1.  `group_vars` playbook。

1.  `group_vars`清单。

1.  `group_vars/all` playbook。

1.  `group_vars/all`清单。

1.  清单文件（或脚本）定义的组`vars`。

1.  角色默认值。

1.  命令行值（例如，`-u REMOTE_USER`）。

Ansible 每次发布都会附带一个移植指南，详细说明您需要对代码进行哪些更改，以便它能够继续按预期运行。在升级 Ansible 环境时，审查这些内容非常重要-这些指南可以在[`docs.ansible.com/ansible/devel/porting_guides/porting_guides.html`](https://docs.ansible.com/ansible/devel/porting_guides/porting_guides.html)找到。

## 变量组优先级排序

先前的优先级排序列表在编写 Ansible playbook 时显然是有帮助的，并且在大多数情况下，很明显变量不应该冲突。例如，`var`任务显然胜过`var` play，所有任务和实际上，plays 都是唯一的。同样，清单中的所有主机都是唯一的；因此，清单中也不应该有变量冲突。

然而，有一个例外，即清单组。主机和组之间存在一对多的关系，因此任何给定的主机都可以是一个或多个组的成员。例如，假设以下代码是我们的清单文件：

```
[frontend]
host1.example.com
host2.example.com
[web:children]
frontend
[web:vars]
http_port=80
secure=true
[proxy]
host1.example.com
[proxy:vars]
http_port=8080
thread_count=10
```

在这里，我们有两个假想的前端服务器，`host1.example.com`和`host2.example.com`，在`frontend`组中。这两个主机都是`web`组的`children`，这意味着它们被分配了清单中的组变量`http_port=80`。`host1.example.com`也是`proxy`组的成员，该组具有相同名称的变量，但是不同的赋值：`http_port=8080`。

这两个变量分配都在`group_vars`清单级别，因此优先顺序并不定义获胜者。那么，在这种情况下会发生什么？

事实上，答案是可预测的和确定的。`group_vars`的赋值按照组名称的字母顺序进行（如*清单排序*部分所述），最后加载的组将覆盖所有之前处理的组的变量值。

这意味着来自`mastery2`的任何竞争变量将胜过其他两个组。然后，来自`mastery11`组的变量将优先于`mastery1`组的变量，因此在创建组名称时请注意这一点！

在我们的示例中，当组按字母顺序处理时，`web`在`proxy`之后。因此，`web`的`group_vars`赋值将胜过任何先前处理的组的赋值。让我们通过这个示例 playbook 运行之前的清单文件来查看行为：

```
---
- name: group variable priority ordering example play
  hosts: all
  gather_facts: false
  tasks:
    - name: show assigned group variables
      vars:
        msg: |
             http_port:{{ hostvars[inventory_hostname]['http_port'] }}
             thread_count:{{ hostvars[inventory_hostname]['thread_count'] | default("undefined") }}
             secure:{{ hostvars[inventory_hostname]['secure'] }}
       ansible.builtin.debug:
         msg: "{{ msg.split('\n') }}"
```

让我们尝试运行以下命令：

```
ansible-playbook -i priority-hosts -c local priorityordering.yaml
```

我们应该得到以下输出：

![图 1.12 - 一个展示变量如何在清单组级别被覆盖的 playbook 运行](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_01_12.jpg)

图 1.12 - 一个展示变量如何在清单组级别被覆盖的 playbook 运行

如预期的那样，清单中两个主机的`http_port`变量的赋值都是`80`。但是，如果不希望出现这种行为怎么办？假设我们希望`proxy`组的`http_port`值优先。不得不重新命名组和所有相关引用以更改组的字母数字排序将是痛苦的（尽管这样也可以！）。好消息是，Ansible 2.4 引入了`ansible_group_priority`组变量，可以用于处理这种情况。如果没有明确设置，此变量默认为`1`，不会改变清单文件的其余部分。

让我们将其设置如下：

```
[proxy:vars]
http_port=8080
thread_count=10
ansible_group_priority=10
```

现在，当我们使用与之前相同的命令运行相同的 playbook 时，请注意`http_ort`的赋值如何改变，而所有不巧合的变量名称都会像以前一样表现：

![图 1.13 - ansible_group_priority 变量对巧合组变量的影响](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_01_13.jpg)

图 1.13 - ansible_group_priority 变量对巧合组变量的影响

随着清单随基础设施的增长，一定要利用这个功能，优雅地处理组之间的任何变量分配冲突。

## 合并哈希

在前一节中，我们关注了变量将如何覆盖彼此的优先级。Ansible 的默认行为是，对于变量名的任何覆盖定义将完全掩盖该变量的先前定义。但是，这种行为可以改变一种类型的变量：哈希变量。哈希变量（或者在 Python 术语中称为字典）是一组键和值的数据集。每个键的值可以是不同类型的，并且甚至可以是复杂数据结构的哈希本身。

在一些高级场景中，最好只替换哈希的一部分或添加到现有哈希中，而不是完全替换哈希。要解锁这种能力，需要在 Ansible 的`config`文件中进行配置更改。配置条目是`hash_behavior`，它可以取值`replace`或`merge`。设置为`merge`将指示 Ansible 在出现覆盖场景时合并或混合两个哈希的值，而不是假定默认的`replace`，它将完全用新数据替换旧的变量数据。

让我们通过一个示例来了解这两种行为。我们将从加载了数据的哈希开始，并模拟提供了作为更高优先级变量的哈希的不同值的情况。

这是起始数据：

```
hash_var: 
  fred: 
    home: Seattle 
    transport: Bicycle 
```

这是通过`include_vars`加载的新数据：

```
hash_var: 
  fred: 
    transport: Bus 
```

默认行为下，`hash_var`的新值将如下所示：

```
hash_var: 
  fred: 
    transport: Bus 
```

然而，如果我们启用`merge`行为，我们将得到以下结果：

```
hash_var: 
  fred: 
    home: Seattle 
    transport: Bus 
```

在使用`merge`时，甚至还有更多微妙和未定义的行为，因此强烈建议只在绝对必要时使用此设置 - 默认情况下禁用是有充分理由的！

# 总结

虽然 Ansible 的设计侧重于简单和易用性，但架构本身非常强大。在本章中，我们涵盖了 Ansible 的关键设计和架构概念，如版本和配置、playbook 解析、模块传输和执行、变量类型和位置以及变量优先级。

您了解到 playbook 包含变量和任务。任务将称为模块的代码片段与参数链接在一起，这些参数可以由变量数据填充。这些组合从提供的清单来源传输到选定的主机。对这些构建块的基本理解是您可以掌握所有 Ansible 事物的平台！

在下一章中，您将详细了解 Ansible 4.3 中的重大新功能，特别是我们在本章中提到的 Ansible 集合和 FQCNs。

# 问题

1.  清单对于 Ansible 的重要性是什么？

a）它是 Ansible 配置管理数据库的一部分。

b）它用于审计您的服务器。

c）它告诉 Ansible 在哪些服务器上执行自动化任务。

d）以上都不是。

1.  在处理频繁变化的基础设施（如公共云部署）时，Ansible 用户必须定期手动更新他们的清单。这是真的还是假的？

a）真 - 这是唯一的方法。

b）假 - 动态清单是为了这个目的而发明的。

1.  默认情况下，Ansible 按照清单中的顺序处理主机？

a）按字母顺序

b）按字典顺序

c）随机顺序

d）按照它们在清单中出现的顺序

1.  默认情况下，简单 playbook 中的 Ansible 任务是按照什么顺序执行的？

a）按照它们被写入的顺序，但必须在所有清单主机上完成每个任务，然后才能执行下一个任务。

b）以最优化的顺序。

c）按照它们被写入的顺序，但一次只能在一个清单主机上进行。

d）其他

1.  哪种变量类型具有最高优先级，可以覆盖所有其他变量来源？

a）清单变量

b）额外变量（来自命令行）

c）角色默认值

d）通过`vars_prompt`获取变量源

1.  特殊的 Ansible 变量名称只在运行时存在是什么？

a）特殊变量

b）运行时变量

c）魔术变量

d）用户变量

1.  如果您想从 playbook 中访问外部数据，您会使用什么？

a）查找插件

b）查找模块

c）查找可执行文件

d）查找角色

1.  对于大多数非 Windows 主机，Ansible 首选的默认传输机制是什么？

a）REST API

b）RabbitMQ

c）RSH

d）SSH

1.  清单变量可以用来做什么？

a）在清单中为每个主机或主机组定义唯一数据。

b）声明您的 playbook 变量。

c）为清单主机定义连接参数。

d）都是（a）和（c）。

1.  如何覆盖系统上的默认 Ansible 配置？

通过在任何位置创建 Ansible 配置文件，并使用`ANSIBLE_CFG`环境变量指定此位置。

b）通过在当前工作目录中创建名为`ansible.cfg`的文件。

c）通过在您的主目录中创建一个名为`~/.ansible.cfg`的文件。

d）以上任何一种。


# 第二章：从早期的 Ansible 版本迁移

随着**Ansible**多年来的发展，某些问题已经出现在开发和管理 Ansible 代码库的团队面前。在许多方面，这些问题是 Ansible 自身增长和成功的代价，并且导致需要以稍微不同的方式构建代码。事实上，任何有一点之前版本 Ansible 经验的人都会注意到，我们在本书中提供的示例代码看起来有些不同，还有一个新术语**集合**。

在本章中，我们将详细解释这些变化以及它们是如何产生的。然后，我们将通过一些实际示例带您了解这些变化在现实世界中是如何工作的，最后教会您如何将您可能拥有的任何现有或旧版 playbook 迁移到 Ansible 4.3 及更高版本。

具体来说，在本章中，我们将涵盖以下主题：

+   Ansible 4.3 的变化

+   从早期的 Ansible 安装升级

+   从头开始安装 Ansible

+   什么是 Ansible 集合？

+   使用`ansible-galaxy`安装额外的模块

+   如何将旧版 playbook 迁移到 Ansible 4.3（入门）

# 技术要求

要按照本章中提供的示例，您需要一台运行**Ansible 4.3**或更新版本的 Linux 机器。几乎任何 Linux 发行版都可以。对于那些感兴趣的人，本章中提供的所有代码都是在**Ubuntu Server 20.04 LTS**上测试的，除非另有说明，并且在**Ansible 4.3**上测试。本章附带的示例代码可以从 GitHub 的以下网址下载：[`github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter02`](https://github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter02)。我们将使用我们在*第十章*中开发的模块，*扩展 Ansible*，来向您展示如何构建自己的集合，因此确保您有本书附带代码的副本是值得的。

查看以下视频以查看代码实际操作：[`bit.ly/3DYi0Co`](https://bit.ly/3DYi0Co)

# Ansible 4.3 的变化

虽然我们在*第一章*中提到了这个话题，*Ansible 的系统架构和设计*，但重要的是我们更深入地了解这些变化，以帮助您充分理解 Ansible 4.3 与之前版本的不同之处。这将帮助您大大提高编写良好 playbook 的能力，并维护和升级您的 Ansible 基础设施——这是掌握 Ansible 4.3 的必要步骤！

首先，稍微了解一下历史。正如我们在前一章中讨论的那样，Ansible 在设计上具有许多优点，这些优点导致了其迅速增长和接受。其中许多优点，比如无代理设计和易于阅读的 YAML 代码，仍然保持不变。事实上，如果您阅读自 2.9 版本以来的 Ansible 发布的更改日志，您会发现自那个版本以来，核心 Ansible 功能几乎没有什么值得注意的变化，而所有的开发工作都集中在另一个领域。

毫无疑问，Ansible 的模块是其最大的优势之一，任何人，从个人贡献者到硬件供应商和云提供商，都可以提交自己的模块，这意味着到 2.9 版本时，Ansible 包含了成千上万个用于各种用途的模块。

这本身对于管理项目的人来说成了一个头疼的问题。比如说一个模块出现了 bug 需要修复，或者有人给现有的模块添加了一个很棒的新功能，可能会很受欢迎。Ansible 发布本身包含了所有的模块，简而言之，它们与 Ansible 本身的发布紧密耦合。这意味着为了发布一个新模块，必须发布一个全新版本的 Ansible 给社区。

结合数百个模块开发人员的问题和拉取请求，管理核心 Ansible 代码库的人确实头疼不已。很明显，虽然这些模块是 Ansible 成功的重要组成部分，但它们也负责在发布周期和代码库管理中引起问题。需要的是一种将模块（或至少是大部分模块）与 Ansible 引擎的发布解耦的方法——我们在本书的*第一章*中运行的核心 Ansible 运行时的系统架构和设计。

因此，**Ansible 内容集合**（或简称集合）诞生了。

## Ansible 内容集合

虽然我们很快会更深入地研究这些内容，但需要注意的重要概念是，集合是 Ansible 内容的一种包格式，对于本讨论来说，这意味着所有那些成千上万的模块。通过使用集合分发模块，特别是那些由第三方编写和维护的模块，Ansible 团队有效地消除了核心 Ansible 产品的发布与使其对许多人如此有价值的模块之间的耦合。

当你安装了，比如**Ansible 2.9.1**，你实际上安装了一个给定版本的 Ansible 二进制文件和其他核心代码，以及那个时候提交和批准包含的所有模块。

现在，当我们谈论安装 Ansible 4.3 时，我们实际上指的是：

Ansible 4.3.0 现在是一个包，其中包含（在撰写本文时）85 个模块、插件和其他重要功能的集合，这将让尽可能多的人在他们需要安装更多集合之前开始他们的 Ansible 之旅。简而言之，这是一个*入门*集合包。

这里重要的是，Ansible 4.3.0 *不*包含任何实际的自动化运行时。如果你孤立地安装了 Ansible 4.3.0，你实际上无法运行 Ansible！幸运的是，这是不可能的，Ansible 4.3.0 依赖于一个当前称为**ansible-core**的包。这个包包含了 Ansible 语言运行时，以及一小部分核心插件和模块，比如`ansible.builtin.debug`，我们在*第一章*中的示例中经常使用的。*Ansible* *的系统架构和设计*。

每个 Ansible 包的发布都会依赖于特定版本的 ansible-core，以便它始终与正确的自动化引擎配对。例如，Ansible 4.3.0 依赖于 ansible-core >= 2.11 and < 2.12。

Ansible 已经开始使用语义化版本控制来管理 Ansible 包本身，从 3.0.0 版本开始。对于还没有接触过语义化版本控制的人来说，可以简单地解释如下：

+   Ansible 4.3.0：这是一个新的 Ansible 包的第一个语义化版本发布。

+   Ansible 4.0.1：这个版本（以及所有右边数字变化的所有版本）将只包含向后兼容的错误修复。

+   Ansible 4.1.0：这个版本（以及所有中间数字变化的所有版本）将包含向后兼容的新功能，可能还包括错误修复。

+   Ansible 5.0.0：这将包含破坏向后兼容性的更改，被称为主要发布。

ansible-core 包不采用语义化版本控制，因此预计 Ansible 5.0.0 将依赖于 ansible-core >= 2.12。请注意，这个 ansible-core 的发布，不受语义化版本控制，可能包含破坏向后兼容性的更改，因此在我们掌握的过程中，了解 Ansible 现在的版本化方式的这些细微差别是很重要的。

重要说明

最后，请注意，ansible-core 包在 2.11 版本中从 ansible-base 更名，因此如果您看到对 ansible-base 的引用，请知道它只是 ansible-core 包的旧名称。

所有这些变化都是经过长时间计划和执行的。虽然它们的实施旨在尽可能顺利地为现有的 Ansible 用户提供服务，但需要解决一些问题，首先是您实际上如何安装和升级 Ansible，我们将在下一节中详细讨论。

# 从早期的 Ansible 安装升级

将 Ansible 拆分为两个相互依赖的包给包维护者带来了一些麻烦。虽然 CentOS 和 RHEL 的包很容易获得，但目前没有 Ansible 4.3.0 或 ansible-core 2.11.1 的当前包。快速查看 CentOS/RHEL 8 的 EPEL 包目录，最新的 Ansible RPM 版本是 2.9.18。官方的 Ansible 安装指南进一步说明：

自 Ansible 2.10 for RHEL 目前不可用，继续使用 Ansible 2.9。

随着包维护者研究各种升级路径和打包技术的利弊，这种情况将随着时间的推移而发生变化，但在撰写本文时，如果您想立即开始使用 Ansible 4.3.0，最简单的方法是使用 Python 打包技术 **pip** 进行安装。然而，我们所做的并不是升级，而是卸载后重新安装。

## 卸载 Ansible 3.0 或更早版本

Ansible 包结构的根本变化意味着，如果您的控制节点上安装了 Ansible 3.0 或更早版本（包括任何 2.x 版本），很遗憾，您不能只是升级您的 Ansible 安装。相反，您需要在安装后删除现有的 Ansible 安装。

提示

与卸载任何软件一样，您应该确保备份重要文件，特别是中央 Ansible 配置文件和清单，以防它们在卸载过程中被删除。

删除软件包的方法取决于您的安装方式。例如，如果您在 CentOS 8 上通过 RPM 安装了 Ansible 2.9.18，可以使用以下命令删除它：

```
sudo dnf remove ansible
```

同样，在 Ubuntu 上可以运行以下命令：

```
sudo apt remove ansible
```

如果您之前使用 `pip` 安装了 Ansible，可以使用以下命令删除它：

```
pip uninstall ansible
```

简而言之，您如何在控制节点上安装 Ansible 3.0（或更早版本）并不重要。即使您使用 `pip` 安装了它，并且您将使用 pip 安装新版本，您在做任何其他操作之前必须先卸载旧版本。

当有新的 Ansible 版本可用时，建议查看文档，看看升级是否仍然需要卸载。例如，安装 Ansible 4.3 之前需要卸载 Ansible 3.0，部分原因是 ansible-base 包更名为 ansible-core。

一旦您删除了早期版本的 Ansible，您现在可以继续在控制节点上安装新版本，我们将在下一节中介绍。

# 从头安装 Ansible

如前一节所讨论的，Ansible 4.3 主要是使用一个名为 **pip** 的 Python 包管理器进行打包和分发的。这可能会随着时间的推移而发生变化，但在撰写本文时，您需要使用的主要安装方法是通过 pip 进行安装。现在，可以说大多数现代 Linux 发行版已经预装了 Python 和 pip。如果因为任何原因你卡住需要安装它，这个过程在官方网站上有详细说明：[`pip.pypa.io/en/stable/installing/`](https://pip.pypa.io/en/stable/installing/)。

一旦您安装了 pip，安装 Ansible 的过程就像运行这个命令一样简单，而且美妙的是，这个命令在所有操作系统上都是相同的（尽管请注意，在某些操作系统上，您的`pip`命令可能被称为`pip3`，以区分可能共存的 Python 2.7 和 Python 3 版本）：

```
sudo pip install ansible
```

当然，这个命令有一些变化。例如，我们给出的命令将为系统上的所有用户安装可用的最新版本的 Ansible。

如果您想测试或坚持使用特定版本（也许是为了测试或资格认证目的），您可以使用以下命令强制 pip 安装特定版本：

```
sudo pip install ansible==4.3.0
```

这第二个命令将确保在您的系统上为所有用户安装 Ansible 4.3.0，而不管哪个是最新版本。我们还可以进一步进行;要安装 Ansible 但仅适用于您的用户帐户，您可以运行以下命令：

```
pip install --user ansible
```

一个特别方便的技巧是，当您开始使用 pip 时，您可以使用 Python 虚拟环境来隔离特定版本的 Python 模块。例如，您可以创建一个用于 Ansible 2.9 的虚拟环境如下：

1.  使用以下命令在适当的目录中创建虚拟环境：

```
virtualenv ansible-2.9
```

这将在运行命令的目录中创建一个新的虚拟环境，环境（及包含它的目录）将被称为`ansible-2.9`。

1.  激活虚拟环境如下：

```
source ansible-2.9/bin/activate
```

1.  现在您已经准备安装 Ansible 2.9。要安装 Ansible 2.9 的最新版本，我们需要告诉`pip`安装大于（或等于）2.9 但小于 2.10 的版本，否则它将只安装 Ansible 4.3：

```
pip install 'ansible>=2.9,<2.10'
```

1.  现在，如果您检查您的 Ansible 版本，您应该会发现您正在运行 2.9 的最新次要版本：

```
ansible --version
```

使用虚拟环境的缺点是您需要记住每次登录到 Ansible 控制机时运行*步骤 2*中的`source`命令。但好处是您可以在一个单独的虚拟环境中重复上述过程，如下所示，使用 Ansible 4.3：

```
virtualenv ansible-4.3
source ansible-4.3/bin/activate
pip install 'ansible>=4.3,<4.4'
ansible --version
```

这样做的好处是，您现在可以随意在两个版本的 Ansible 之间切换，只需发出适当环境的适当源命令，然后以通常的方式运行 Ansible。如果您正在从 Ansible 2.9 迁移到 4.3 的过程中，或者有一些尚未能正常工作但您仍然需要的旧代码，这可能特别有用，直到您有时间进行必要的更改。

最后，如果您想要升级您的新安装的 Ansible，您只需要根据您的安装方法发出适当的`pip`命令。例如，如果您为所有用户安装了 Ansible，您将发出以下命令：

```
sudo pip install -U ansible
```

如果您只为您的用户帐户安装了它，命令将类似：

```
pip install -U ansible
```

现在，如果您正在虚拟环境中工作，您必须记住先激活环境。一旦完成，您可以像以前一样升级：

```
source ansible-2.9/bin/activate
pip install -U ansible
```

请注意，前面的示例将把安装在 Ansible 2.9 环境中的任何内容升级到最新版本，目前是 4.0。另外，需要注意的一点是，正如在前面的部分*从早期的 Ansible 安装升级*中讨论的那样，这将破坏安装。要升级到最新的次要版本，记住您可以像在此环境中安装 Ansible 时那样指定版本标准：

```
pip install -U 'ansible>=2.9,<2.10'
```

当然，您也可以将版本约束应用于任何其他示例。它们的使用方式不仅限于虚拟环境。

希望到目前为止，您应该已经对如何安装 Ansible 4.3 有了相当好的了解，无论是从头开始，还是从早期安装升级。完成这些工作后，是时候我们来看看**Ansible 集合**了，因为它们是所有这些变化的驱动力。

# 什么是 Ansible 集合？

Ansible 集合代表了与 Ansible 发布的传统的单片式方法的重大分歧，在某一时刻，与 Ansible 可执行文件一起发布了超过 3600 个模块。可以想象，这使得 Ansible 发布变得难以管理，并且意味着最终用户必须等待完全新的 Ansible 发布才能获得对单个模块的功能更新或错误修复——显然这是一种非常低效的方法。

因此，Ansible 集合诞生了，它们的前提非常简单：它们是一种用于构建、分发和消费多种不同类型的 Ansible 内容的机制。当您首次从 Ansible 2.9 或更早版本迁移时，您对 Ansible 集合的体验将以模块的形式呈现。正如我们在本章前面讨论的那样，我们所说的 Ansible 4.3 实际上是一个包，包含大约 85 个集合……它根本不包含 Ansible 可执行文件！这些集合中的每一个都包含许多不同的模块，有些由社区维护，有些由特定供应商维护。Ansible 4.3 依赖于 ansible-core 2.11.x，该软件包包含了 Ansible 可执行文件和核心的`ansible.builtin`模块（如`debug`、`file`和`copy`）。

让我们更详细地看一下集合的结构，以便更充分地理解它们的工作方式。每个集合都有一个由两部分组成的名称：命名空间和集合名称。

例如，`ansible.builtin`集合的命名空间是`ansible`，集合名称是`builtin`。同样，在*第一章*，*Ansible 的系统架构和设计*中，我们安装了一个名为`amazon.aws`的集合。在这里，`amazon`是命名空间，`aws`是集合名称。所有命名空间必须是唯一的，但集合名称可以在命名空间内相同（因此您理论上可以有`ansible.builtin`和`amazon.builtin`）。

虽然您可以以多种方式使用集合，包括简单地在本地构建和安装它们，或直接从 Git 存储库中构建和安装它们，但集合的中心位置是 Ansible Galaxy，您将在这里找到所有包含在 Ansible 4.3 软件包中的集合，以及更多其他集合。Ansible Galaxy 网站可在[`galaxy.ansible.com`](https://galaxy.ansible.com)访问，并且有一个命令行工具（我们在第一章中看到过，*Ansible 的系统架构和设计*）称为`ansible-galaxy`，可用于与该网站交互（例如，安装集合）。我们将在本章的其余部分广泛使用此工具，因此您将有机会更加熟悉它。

您可以使用 GitHub 凭据登录 Ansible Galaxy 自由创建自己的帐户，当您这样做时，您的命名空间将自动创建为与您的 GitHub 用户名相同。您可以在这里了解更多关于 Ansible Galaxy 命名空间的信息：[`galaxy.ansible.com/docs/contributing/namespaces.html`](https://galaxy.ansible.com/docs/contributing/namespaces.html)。

现在您已经了解了 Ansible 集合名称是如何创建的，让我们更深入地了解一下集合是如何组合和工作的。

## Ansible 集合的结构

理解集合在幕后如何工作的最简单方法是为自己构建一个简单的集合，所以让我们开始吧。与 Ansible 的所有方面一样，开发人员已经为集合制定了一个强大而易于使用的系统，如果您已经有使用 Ansible 角色的经验，您会发现集合的工作方式类似。然而，如果您没有，不用担心；我们将在这里教会您所需了解的一切。

集合由一系列目录组成，每个目录都有一个特殊的名称，旨在容纳特定类型的内容。这些目录中的任何一个都可以是空的；您不必在集合中包含所有类型的内容。实际上，集合中只有一个强制性文件！Ansible 甚至提供了一个工具来帮助您构建一个空的集合，以便开始使用。让我们现在使用它来创建一个新的空集合，以便学习，通过运行以下命令：

```
ansible-galaxy collection init masterybook.demo 
```

当您运行此命令时，您应该看到它创建了以下目录树：

```
masterybook/
|-- demo
    |-- README.md
    |-- docs
    |-- galaxy.yml
    |-- plugins
        |-- README.md
    |-- roles
```

您可以从前面的目录树中看到，此命令使用我们的 `masterybook` 命名空间创建了一个顶级目录，然后创建了一个名为 `demo` 的集合子目录。然后创建了两个文件和三个目录。

其目的如下：

+   `README.md`：这是集合的 README 文件，应为第一次查看模块代码的任何人提供有用的信息。

+   `docs`：此目录用于存储集合的一般文档。所有文档都应采用 Markdown 格式，并且不应放在任何子文件夹中。模块和插件仍应使用 Python 文档字符串嵌入其文档，我们将在*第十章*中学习更多关于此的内容，*扩展 Ansible*。

+   `galaxy.yml`：这是集合结构中唯一强制性的文件，包含构建集合所需的所有信息，包括版本信息、作者详细信息、许可信息等。之前运行的命令创建的文件是一个完整的模板，其中包含注释以解释每个参数，因此您应该发现很容易浏览并根据您的要求完成它。

+   `plugins`：此目录应包含您开发的所有 Ansible 插件。模块也应包含在单独的模块/子目录中，您需要在插件文件夹下创建。我们将在*第十章*中学习有关为 Ansible 创建插件和模块的内容，*扩展 Ansible*。

+   `roles`：在 Ansible 3.0 之前，Ansible Galaxy 只用于分发角色：可重复使用的 Ansible 代码集，可以轻松地分发和在其他地方使用以解决常见的自动化挑战。我们将在*第八章*中学习有关角色的所有内容，*使用角色组合可重复使用的 Ansible 内容*，所以如果您还没有遇到它们，现在不用担心。角色仍然可以使用 Ansible Galaxy 进行分发，但也可以包含在集合中，这在未来可能会成为常态。

除此之外，集合还可以包含以下内容：

+   `tests`：此目录用于存储与发布之前测试 Ansible 集合相关的文件，并且要包含在顶层 Ansible 包中，集合必须通过 Ansible 测试流程。您不需要在内部使用自己的集合时执行此操作，但是如果您希望将其包含在主要 Ansible 包中，您将需要完成开发过程的这一部分。更多详细信息请参阅：[`docs.ansible.com/ansible/latest/dev_guide/developing_collections.html#testing-collections`](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html#testing-collections)。

+   `meta/runtime.yml`：此文件和目录用于指定有关集合的重要元数据，例如所需 ansible-core 包的版本，以及各种命名空间路由和重定向段，以帮助从 Ansible 2.9 及更早版本（其中没有命名空间）迁移到 Ansible 4.3 及更高版本。

+   `playbooks`：此目录将在将来的 Ansible 版本中得到支持，以包含与集合一起使用的 playbooks，尽管在撰写本文时，官方文档尚不完整。

现在您已经创建并理解了集合目录结构，让我们向其中添加我们自己的模块。完成后，我们将对其进行打包，然后安装到我们的系统上，并在 playbook 中使用它：这是对集合工作原理的完整端到端测试。我们将从《第十章》《扩展 Ansible》中借用模块代码，所以在这个阶段不用担心深入理解这段代码，因为它在那里有完整的解释。完整的代码清单有好几页长，所以我们不会在这本书中重复它。下载本书附带的代码或参考《第十章》《扩展 Ansible》中的代码清单，获取`remote_copy.py`模块代码。它包含在本书附带的示例代码的`Chapter10/example08/library`目录中。

在`plugins/`目录中创建一个`modules/`子目录，并在其中添加`remote_copy.py`代码。

当您查看了`galaxy.yml`中的信息后，可以随意在其中添加您自己的姓名和其他细节，然后就完成了！这就是创建您的第一个集合的全部内容。它真的非常简单，一组文件放在一个井然有序的目录结构中。

提示

如本章前面讨论的那样，预期 Ansible 集合遵循语义化版本控制，因此在创建和构建自己的模块时，请务必采用这一点。

您完成的模块目录结构应该是这样的：

```
masterybook/
|-- demo
    |-- README.md
    |-- docs
    |-- galaxy.yml
    |-- plugins
        |-- modules
            |-- remote_copy.py
        |-- README.md
    |-- roles
```

当所有文件就位后，就该构建您的集合了。这非常简单，只需切换到与`galaxy.yml`所在的同一集合顶级目录，并运行以下命令：

```
cd masterybook/demo
ansible-galaxy collection build
```

这将创建一个 tarball，其中包含您的集合文件，您现在可以根据需要使用它！您可以立即将其发布到 Ansible Galaxy，但首先，让我们在本地测试一下看看它是否有效。

默认情况下，Ansible 将集合存储在您的家目录下的`~/.ansible/collections`中。然而，由于我们正在测试刚刚构建的集合，让我们稍微改变一下 Ansible 的行为，并将其安装在本地目录中。

要尝试这个，为一个简单的测试 playbook 创建一个新的空目录，然后创建一个名为`collections`的目录，用于安装我们新创建的集合：

```
mkdir collection-test
cd collection-test
mkdir collections
```

默认情况下，Ansible 不会知道要在这个目录中查找集合，因此我们必须覆盖其默认配置，告诉它在这里查找。在您的目录中，创建一个新的`ansible.cfg`文件（如果存在，该文件始终被读取并覆盖任何中央配置文件中的设置，例如`/etc/ansible/ansible.cfg`）。该文件应包含以下内容：

```
[defaults]
collections_paths=./collections:~/.ansible/collections:/usr/share/ansible/collections
```

这个配置指令告诉 Ansible 在检查系统上的默认位置之前，先在当前目录下的 collections 子目录中查找。

现在您已经准备好安装之前构建的集合了。假设您是在家目录中构建的，那么安装它的命令如下：

```
ansible-galaxy collection install ~/masterybook/demo/masterybook-demo-1.0.0.tar.gz -p ./collections
```

如果您探索本地的`collections`目录，您应该会发现它现在包含了您之前创建的集合，以及在构建过程中创建的一些额外文件。

最后，让我们创建一个简单的 playbook 来使用我们的模块。作为《第十章》《扩展 Ansible》的一个预告，这个模块在 Ansible 控制的系统上执行一个简单的文件复制，所以让我们在一个公共可写目录（例如`/tmp`）中创建一个测试文件，并让我们的模块开始复制。考虑以下 playbook 代码：

```
---
- name: test remote_copy module
  hosts: localhost
  gather_facts: false
  tasks:
  - name: ensure foo
    ansible.builtin.file:
      path: /tmp/rcfoo
      state: touch
  - name: do a remote copy
    masterybook.demo.remote_copy:
      source: /tmp/rcfoo
      dest: /tmp/rcbar
```

我们的 playbook 中有两个任务。一个使用`ansible.builtin`集合中的文件模块来创建一个空文件，供我们的模块复制。第二个任务使用我们的新模块，使用完全限定的集合名称来引用它，来复制文件。

你可以以正常方式运行这个 playbook 代码。例如，要对本地机器运行它，运行以下命令：

```
ansible-playbook -i localhost, -c local collection_test.yml
```

注意`localhost`清单项后的逗号。这告诉 Ansible 我们在命令行上列出清单主机，而不必创建本地清单文件-当你测试代码时，这是一个很方便的小技巧！如果一切顺利，你的 playbook 运行应该如*图 2.1*所示。

![图 2.1-运行示例 playbook 对我们的演示集合的输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_02_01.jpg)

图 2.1-运行示例 playbook 对我们的演示集合的输出

恭喜你，你刚刚创建、构建并运行了你的第一个 Ansible 集合！当然，集合通常比这更复杂，并且可能包含许多模块、插件，甚至角色和其他工件，正如前面所述。但是，要开始，这就是你需要知道的全部。

当你对你的集合满意时，你最后的一步很可能是将其发布到 Ansible Galaxy。假设你已经登录到 Ansible Galaxy 并创建了你的命名空间，你只需要导航到你的个人资料首选项页面，然后点击**显示 API 密钥**按钮，如*图 2.2*所示：

![图 2.2-从 Ansible Galaxy 获取你的 API 密钥](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_02_02.jpg)

图 2.2-从 Ansible Galaxy 获取你的 API 密钥

然后，你可以将这个 API 密钥输入到`ansible-galaxy`命令行工具中，以发布你的集合。例如，要发布本章的集合，你可以运行以下命令：

```
ansible-galaxy collection publish ~/masterybook/demo/masterybook-demo-1.0.0.tar.gz --token=<API key goes here>
```

这就结束了我们对集合及其构建和使用的介绍。正如我们提到的，有几种安装集合的方法，而且现在 Ansible 模块已经分布在各种集合中。在下一节中，我们将看看如何找到你需要的模块，以及如何在你的自动化代码中安装和引用集合。

# 使用 ansible-galaxy 安装额外模块

当你使用集合时，大部分时间你不会自己构建它们。在撰写本书时，Ansible Galaxy 上已经有 780 个可用的集合，而在你阅读本书时可能会有更多。尽管如此，作者个人认为，当我们能亲自动手时，我们学得更好，因此，开发我们自己的，尽管简单，集合是我们研究它们是如何组合和引用的绝佳方式。

然而，现在让我们专注于查找并使用 Ansible 上已有的集合，因为这很可能是你大部分时间的关注点。正如我们已经提到的，Ansible 4.3 包括一组集合，让你开始自动化之旅，以及与 ansible-core 包一起包含的`ansible.builtin`集合。

如果你想查看在你的系统上安装 Ansible 4.3 时安装了哪些集合，只需运行以下命令：

```
ansible-galaxy collection list
```

这将返回一个格式为`<namespace>.<collection>`的所有已安装集合的列表，以及它们的版本号。请记住，集合现在与你安装的 Ansible 版本无关，因此你可以升级它们而不必升级整个 Ansible 安装。我们很快将会看到这一点。作为 Ansible 的一部分安装的所有集合的完整列表也可以在这里找到：[`docs.ansible.com/ansible/latest/collections/index.html`](https://docs.ansible.com/ansible/latest/collections/index.html)。

当您需要特定目的的模块时，值得注意的是，集合通常以名称命名，以便为您提供有关其包含内容的线索。例如，假设您想要使用 Ansible 在亚马逊网络服务中执行一些云配置; 快速浏览集合索引会发现两个可能的候选项：`amazon.aws`集合和`community.aws`集合。同样，如果您想要自动化 Cisco IOS 交换机的功能，`cisco.ios`集合看起来是一个很好的起点。您可以在 Ansible 文档网站上探索每个集合中的模块，或者通过使用`ansible-doc`命令来探索集合中的模块。例如，要列出`cisco.ios`集合中包含的所有模块，您可以运行以下命令：

```
ansible-doc -l cisco.ios
```

`community.*`包旨在提供与 Ansible 2.9 中存在的相同功能，自然而然地具有更新的模块和插件版本，从而帮助您在不太痛苦的情况下将 playbook 从早期的 Ansible 版本移植过来。

当然，如果您在 Ansible 4.3 包中找不到所需的内容，您可以简单地转到 Ansible Galaxy 网站找到更多内容。

一旦确定了您在 playbook 开发中需要的集合，就是安装它们的时候了。我们已经在前一节中看到，我们可以直接从磁盘上的本地文件安装集合。在*第一章*，*Ansible 的系统架构和设计*中，我们运行了以下命令：

```
ansible-galaxy collection install amazon.aws
```

这安装了最新版本的`amazon.aws`集合直接从 Ansible Galaxy。你们中的鹰眼可能会想，“等等，`amazon.aws`已经作为 Ansible 4.3 包的一部分包含在内了。”的确是这样。然而，Ansible 及其集合的解耦特性意味着我们可以自由安装和升级集合版本，而无需升级 Ansible。的确，当我们运行前面的命令时，它将最新版本的`amazon.aws`安装在用户本地集合路径（`~/.ansible/collections`）内，因为这是默认设置。请注意，这与我们在本章前面测试自己的集合时观察到的行为不同，因为我们专门创建了一个 Ansible 配置文件，指定了不同的集合路径。

通过使用`ansible-galaxy`命令运行另一个集合列表，我们可以找出发生了什么，只是这一次我们只会过滤`amazon.aws`集合：

```
ansible-galaxy collection list amazon.aws
```

输出将类似于这样：

![图 2.3 - 列出已安装集合的多个版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_02_03.jpg)

图 2.3 - 列出已安装集合的多个版本

在这里，我们可以看到这个集合的`1.3.0`版本是与我们的 Ansible 安装一起安装的，但稍后的`1.4.0`版本安装在我家目录的`.ansible/collections`文件夹中，在 playbook 引用它并从我的用户帐户运行时，后者优先。请注意，从此系统上的其他用户帐户运行的 playbook 只会看到`1.3.0`版本的集合，因为这是系统范围内安装的，它们通常不会引用我家目录中的文件夹。

正如您所期望的，您可以在安装集合时指定您想要的版本。如果我想要安装`amazon.aws`集合的最新开发版本，我可以使用以下命令在本地安装它：

```
ansible-galaxy collection install amazon.aws:==1.4.2-dev9 --force
```

`--force`选项是必需的，因为`ansible-galaxy`不会覆盖发布版本的集合与开发版本，除非您强制它这样做-这是一个明智的安全预防措施！

除了从本地文件和 Ansible Galaxy 安装集合外，您还可以直接从 Git 存储库安装它们。例如，要安装假设的 GitHub 存储库的`stable`分支上的最新提交，您可以运行以下命令：

```
ansible-galaxy collection install git+https://github.com/jamesfreeman959/repo_name.git,stable
```

这里有许多可能的排列组合，包括访问私有 Git 存储库甚至本地存储库。

所有这些都是安装集合的完全有效的方式。然而，想象一下，您的 playbook 需要十个不同的集合才能成功运行。您最不想做的事情就是每次在新的地方部署自动化代码时都要运行十个不同的`ansible-galaxy`命令！而且，这很容易失控，不同的主机上可能有不同的集合版本。

幸运的是，Ansible 在这方面也为您着想，`requirements.yml`文件（在较早版本的 Ansible 中存在，并在集合成为现实之前用于从 Ansible Galaxy 安装角色）可以用于指定要安装的一组集合。

例如，考虑以下`requirements.yml`文件：

```
---
collections:
- name: geerlingguy.k8s
- name: geerlingguy.php_roles
  version: 1.0.0
```

该文件描述了对两个集合的要求。两者的命名空间都是`geerlingguy`，集合分别称为`k8s`和`php_roles`。`k8s`集合将安装最新的稳定版本，而`php_roles`集合只会安装`1.0.0`版本，而不管最新发布版本是什么。

要安装`requirements.yml`中指定的所有要求，只需运行以下命令：

```
ansible-galaxy install -r requirements.yml
```

该命令的输出应该类似于*图 2.4*：

![图 2.4 - 使用 requirements.yml 文件安装集合](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_02_04.jpg)

图 2.4 - 使用 requirements.yml 文件安装集合

从此输出中可以看出，我们在`requirements.yml`文件中指定的两个集合都已安装到了适当的版本。这是捕获 playbook 的集合要求的一种非常简单而强大的方式，并且可以一次性安装它们所有，同时保留需要的正确版本。

在这个阶段，您应该对 Ansible 4.3 中的重大变化有一个牢固的理解，特别是集合，如何找到适合您自动化需求的正确集合以及如何安装它们（甚至如何创建自己的集合如果需要）。在本章的最后部分，我们将简要介绍如何将您的 playbook 从 2.9 版本及更早版本迁移到 Ansible 4.3。

# 如何将传统 playbook 迁移到 Ansible 4.3（入门）

没有两个 Ansible playbook（或角色或模板）是相同的，它们的复杂程度从简单到复杂各不相同。然而，它们对于其作者和用户来说都很重要，随着从 Ansible 2.9 到 4.0 的主要变化，本书没有一个关于如何将您的代码迁移到更新的 Ansible 版本的入门就不完整。

在我们深入研究这个主题之前，让我们来看一个例子。在 2015 年关于 Ansible 1.9 版本的第一版书中，出现了一个示例，使用一个小的 Ansible playbook 渲染了一个**Jinja2**模板。我们将在本书的*第六章*中学习关于这段代码的更新版本，*解锁 Jinja2 模板的力量*，但现在让我们看看原始代码。名为`demo.j2`的模板如下：

```
setting = {{ setting }} 
{% if feature.enabled %} 
feature = True 
{% else %} 
feature = False 
{% endif %} 
another_setting = {{ another_setting }}
```

渲染此模板的 playbook 如下所示：

```
--- 
- name: demo the template 
  hosts: localhost 
  gather_facts: false  
  vars: 
    setting: a_val 
    feature: 
      enabled: true
    another_setting: b_val  
  tasks: 
    - name: pause with render 
      pause: 
        prompt: "{{ lookup('template', 'demo.j2') }}"
```

这是第一版书中出现的完全相同的代码，它是为 Ansible 1.9 编写的，所以在过渡到 4.3 时发生了很多变化，你可能会原谅认为这段代码永远不会在 Ansible 4.3 上运行。然而，让我们确切地做到这一点。我们将使用以下命令运行此代码：

```
ansible-playbook -i localhost, -c local template-demo.yaml
```

在 Ansible 4.3 上运行此命令的输出，使用 ansible-core 2.11.1，看起来像*图 2.5*：

![图 2.5 - 在 Ansible 4.3 上运行本书第一版的示例 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_02_05.jpg)

图 2.5 - 在 Ansible 4.3 上运行本书第一版的示例 playbook

如果您问为什么这样做，以及为什么要详细介绍集合，当最初为 Ansible 1.9 编写的代码在 4.3 中不经修改仍然有效时，您将得到原谅。Ansible 4.3 是专门编码的，以为用户提供尽可能少痛苦的路径，甚至在 Ansible 2.10 的迁移指南中都明确指出：

*您的 playbook 应该继续工作，无需任何更改*。

只要模块名称保持唯一，这一点就会成立。然而，现在没有任何阻止模块名称冲突的东西——它们现在只需要在自己的集合中保持唯一。因此，例如，我们在前面的 playbook 中使用了`pause`模块，在 Ansible 4.3 中它的**完全限定集合名称**（**FQCN**）是`ansible.builtin.pause`。前面的代码之所以有效是因为我们的集合中没有其他叫做`pause`的模块。然而，请考虑我们在本章前面创建的`masterybook.demo`集合。没有任何阻止我们在这里创建一个叫做`pause`的自己的模块，它做一些完全不同的事情。Ansible 怎么知道选择哪个模块呢？

答案来自 Ansible 本身，它已经编码以搜索构成 Ansible 4.3 包的所有集合；因此，对`pause`的引用解析为`ansible.builtin.pause`。它永远不会解析为`masterybook.demo.pause`（假设我们创建了该模块），因此如果我们想在任务中使用我们的假设模块，我们需要使用 FQCN。

Ansible 在这个话题上的建议是始终在您的代码中使用 FQCN，以确保您从模块名称冲突中永远不会收到意外的结果。但是，如果您想要避免在一组任务中输入大量内容怎么办？例如，如果您不得不重复输入`masterybook.demo.remote_copy`，那就太多输入了。

答案以 playbook 中在 play 级别定义的新`collections:`关键字的形式呈现。当我们在本章前面测试我们新构建的集合时，我们使用了 FCQN 来引用它。然而，同样的 playbook 也可以写成以下形式：

```
---
- name: test remote_copy module
  hosts: localhost
  gather_facts: false
  collections:
    - masterybook.demo
  tasks:
  - name: ensure foo
    ansible.builtin.file:
      path: /tmp/rcfoo
      state: touch
  - name: do a remote copy
    remote_copy:
      source: /tmp/rcfoo
      dest: /tmp/rcbar
```

请注意`collections:`关键字在 play 级别上的存在。这本质上为未通过 FQCN 指定的引用创建了一个有序的*搜索路径*。因此，我们已经指示我们的 play 在搜索包含的命名空间之前，搜索`masterybook.demo`命名空间的模块、角色和插件。实际上，您可以将`ensure foo`任务中的模块引用从`ansible.builtin.file`更改为`file`，play 仍将按预期工作。`collections`指令不会覆盖这些内部命名空间搜索路径，它只是在其前面添加命名空间。

值得注意的是，当您开始使用角色（我们将在本书后面介绍），play 中指定的集合搜索路径不会被角色继承，因此它们都需要手动定义。您可以通过在角色中创建一个`meta/main.yml`文件来为角色定义集合搜索路径，该文件可以包含例如以下内容：

```
collections:
  - masterybook.demo
```

此外，重要的是要提到，这些集合搜索路径不会影响您可能在集合中包含的查找、过滤器或测试等项目。例如，如果我们在我们的集合中包含了一个查找，无论`play`或`role`中是否出现`collections`关键字，都需要使用 FQCN 来引用它。最后，请注意，您必须始终像本章前面演示的那样安装您的集合。在您的代码中包含`collections`关键字并不会导致 Ansible 自动安装或下载这些集合；它只是它们的搜索路径。

总的来说，您可能会发现在整个代码中使用 FQCN 会更容易，但本节的重要教训是，虽然在您的代码中使用 FQCN 是最佳实践，但目前并不是强制的，如果您正在升级到 Ansible 4.3，您不必逐个更新您曾经编写的所有剧本中对模块、插件等的引用。您可以随时进行这样的操作，但最好是这样做。

当然，如果我们回顾自 2.7 版发布以来发生的所有 Ansible 变化，这本书的第三版就是基于这个版本，那么变化是很多的。然而，它们只会影响特定剧本，因为它们涉及特定剧本方面的特定行为，或者某些模块的工作方式。的确，一些模块会因为较新的 Ansible 版本的发布而被弃用和移除，新的模块会被添加进来。

每当您想要升级您的 Ansible 安装时，建议您查看 Ansible 为每个版本发布的移植指南。它们可以在这里找到：[`docs.ansible.com/ansible/devel/porting_guides/porting_guides.html`](https://docs.ansible.com/ansible/devel/porting_guides/porting_guides.html)。

至于我们在本章开始时提到的例子，您可能会发现您的代码根本不需要任何修改。然而，最好是计划升级，而不是简单地希望一切顺利，只是碰到一些意外行为，破坏了您的自动化代码。

希望本章关于剧本移植的部分已经向您展示了如何处理在您的剧本中引入集合，并为您提供了一些指引，指出您在升级 Ansible 时应该寻求指导的地方。

# 总结

自本书上次发布以来，Ansible 已经发生了许多变化，但最显著的变化（预计会影响到阅读本书的每个人）是引入集合来管理模块、角色、插件等，并将它们与 Ansible 的核心版本分离。对 Ansible 代码最明显的变化可能是引入 FQCNs 以及需要安装集合（如果它们不是 Ansible 4.3 包的一部分）。

在本章中，您了解了在 Ansible 中引入集合的原因，以及它们如何影响从您的剧本代码到您安装、维护和升级 Ansible 本身的一切。您了解到集合很容易从头开始构建，甚至了解了如何构建自己的集合，然后看看如何为您的剧本安装和管理集合。最后，您学会了将您的 Ansible 代码从早期版本移植的基础知识。

在下一章中，您将学习如何在使用 Ansible 时保护秘密数据。

# 问题

1.  集合可以包含：

a) 角色

b) 模块

c) 插件

d) 以上所有

1.  集合意味着 Ansible 模块的版本与 Ansible 引擎的版本无关。

a) 真

b) 假

1.  Ansible 4.3 包括：

a) 包括 Ansible 自动化引擎。

b) 依赖于 Ansible 自动化引擎。

c) 与 Ansible 自动化引擎毫无关系。

1.  可以直接从 Ansible 2.9 升级到 Ansible 4.3。

a) 真

b) 假

1.  在 Ansible 4.3 中，模块名称在不同的命名空间之间是唯一的。

a) 真

b) 假

1.  为了确保您始终访问您打算的正确模块，您现在应该开始在您的任务中使用以下哪个？

a) 完全合格的域名

b) 简短的模块名称

c) 完全合格的集合名称

d) 以上都不是

1.  哪个文件可以用来列出从 Ansible Galaxy 获取的所有所需集合，以确保在需要时可以轻松安装它们？

a) `site.yml`

b) `ansible.cfg`

c) `collections.yml`

d) `requirements.yml`

1.  当您在 Ansible Galaxy 上创建帐户以贡献您自己的集合时，您的命名空间是：

a) 随机生成的。

b) 由您选择。

c) 根据你的 GitHub 用户 ID 自动生成。

1.  集合存储在哪种常见的文件格式中？

a) `.tar.gz`

b) `.zip`

c) `.rar`

d) `.rpm`

1.  你如何列出安装在你的 Ansible 包中的所有集合？

a) `ansible --list-collections`

b) `ansible-doc -l`

c) `ansible-galaxy --list-collections`

d) `ansible-galaxy collections list`


# 第三章：使用 Ansible 保护您的机密

机密信息是要保密的。无论是云服务的登录凭据还是数据库资源的密码，它们之所以是机密，是有原因的。如果它们落入错误的手中，它们可以被用来发现商业机密、客户的私人数据、为恶意目的创建基础设施，甚至更糟。所有这些都可能会给您和您的组织带来大量的时间、金钱和头疼！在第二版这本书出版时，只能够将敏感数据加密在外部保险柜文件中，并且所有数据必须完全以加密或未加密的形式存在。每次运行 playbook 时只能使用一个单一的 Vault 密码，这意味着无法将您的机密数据分隔开，并为不同敏感性的项目使用不同的密码。现在一切都已经改变，playbook 运行时允许使用多个 Vault 密码，以及在否则普通的**YAML Ain't Markup Language**（**YAML**）文件中嵌入加密字符串的可能性。

在本章中，我们将描述如何利用这些新功能，并通过以下主题保持您的机密安全使用 Ansible：

+   加密数据在静止状态下

+   创建和编辑加密文件

+   使用加密文件执行`ansible-playbook`

+   将加密数据与普通 YAML 混合

+   在操作时保护机密

# 技术要求

为了跟随本章节中提供的示例，您需要一台运行**Ansible 4.3**或更新版本的 Linux 机器。几乎任何 Linux 版本都可以使用——对于那些对细节感兴趣的人，本章中提供的所有代码都是在 Ubuntu Server 20.04 **长期支持版**（**LTS**）上测试的，除非另有说明，并且在 Ansible 4.3 上测试。本章附带的示例代码可以从 GitHub 上下载，**统一资源定位符**（**URL**）为：[`github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter03`](https://github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter03)。

查看以下视频以查看代码的实际操作：[`bit.ly/2Z4xB42`](https://bit.ly/2Z4xB42)

# 加密数据在静止状态下

作为配置管理系统或编排引擎，Ansible 具有强大的功能。为了发挥这种力量，有必要将机密数据委托给 Ansible。一个每次连接都提示操作员输入密码的自动化系统并不高效——事实上，如果您不得不坐在那里一遍又一遍地输入密码，它几乎不是完全自动化的！为了最大限度地发挥 Ansible 的功能，机密数据必须被写入一个文件，Ansible 可以读取并从中利用数据。

然而，这样做存在风险！您的机密信息以明文形式存储在文件系统中。这是一种物理风险，也是一种数字风险。从物理上讲，计算机可能被夺走，并且被仔细检查以获取机密数据。从数字上讲，任何能够突破其限制的恶意软件都能够读取您的用户帐户可以访问的任何数据。如果您使用源代码控制系统，那么存储库所在的基础设施同样面临风险。

幸运的是，Ansible 提供了一种保护数据在静止状态下的方法。这种方法就是**Vault**。这种方法允许对文本文件进行加密，以便它们以加密格式存储在静止状态下。没有密钥或大量的计算能力，数据是无法被破译的，但仍然可以在 Ansible plays 中像未加密数据一样轻松使用。

在处理数据加密时需要学习的关键课程包括以下内容：

+   有效的加密目标

+   使用多个密码和保险柜**标识符**（**ID**）保护不同的数据

+   创建新的加密文件

+   加密现有的未加密文件

+   编辑加密文件

+   更改文件的加密密码

+   解密加密文件

+   在未加密的 YAML 文件中内联加密数据（例如，一个 playbook）

+   在引用加密文件时运行`ansible-playbook`

## Vault ID 和密码

在**Ansible 2.4**发布之前，一次只能使用一个 Vault 密码。虽然你可以在多个位置存储多个目的的多个密码，但只能使用一个密码。这对于较小的环境显然是可以接受的，但随着 Ansible 的采用增加，对更好和更灵活的安全选项的需求也在增加。例如，我们已经讨论过 Ansible 可以通过清单中的组来管理开发和生产环境。可以预期这些环境将具有不同的安全凭据。同样，你期望核心网络设备具有不同的凭据。事实上，这是一个很好的安全实践。

鉴于此，使用 Vault 仅用一个主密码保护任何秘密似乎是不合理的。Ansible 2.4 引入了 Vault ID 的概念作为解决方案，虽然目前旧的单密码命令仍然有效，但建议在命令行上使用 Vault ID。每个 Vault ID 必须有一个与之关联的单个密码，但多个秘密可以共享相同的 ID。

Ansible Vault 密码可以来自以下三个来源之一：

+   用户输入的字符串，当需要时 Ansible 会提示输入

+   一个包含 Vault 密码的纯文本文件（显然，这个文件必须保持安全！）

+   一个可执行文件，用于获取密码（例如，从凭证管理系统）并将其输出为 Ansible 读取的单行

这三个选项的语法大致相似。如果你只有一个 Vault 凭证，因此不使用 ID（尽管如果你愿意的话，你也可以使用 ID，这是强烈推荐的，因为你可能以后希望添加第二个 Vault ID），那么你将输入以下代码行来运行一个 playbook 并提示输入 Vault 密码：

```
ansible-playbook --vault-id @prompt playbook.yaml
```

如果你想从文本文件中获取 Vault 密码，你将运行以下命令：

```
ansible-playbook --vault-id /path-to/vault-password-text-file playbook.yaml
```

最后，如果你使用可执行脚本，你将运行以下命令：

```
ansible-playbook --vault-id /path-to/vault-password-script.py playbook.yaml
```

如果你正在使用 ID，只需在密码来源前面添加 ID，然后加上`@`字符——例如，如果你的 vault 的 ID 是`prod`，那么前面的三个例子变成了以下内容：

```
ansible-playbook --vault-id prod@prompt playbook.yaml
ansible-playbook --vault-id prod@/path-to/vault-password-text-file playbook.yaml
ansible-playbook --vault-id prod@/path-to/vault-password-script.py playbook.yaml
```

这些可以组合成一个命令，如下所示：

```
ansible-playbook --vault-id prod@prompt testing@/path-to/vault-password-text-file playbook.yaml
```

我们将在本章的其余部分中使用`vault-id`命令行选项。

## Vault 可以加密的内容

Vault 功能可用于加密 Ansible 使用的任何**结构化数据**。这可以是 Ansible 在操作过程中使用的几乎任何 YAML（或**JavaScript 对象表示**（**JSON**））文件，甚至是一个未加密的 YAML 文件中的单个变量，例如 playbook 或角色。Ansible 可以处理的加密文件的示例包括以下内容：

+   `group_vars/`文件

+   `host_vars/`文件

+   `include_vars`目标

+   `vars_files`目标

+   `--extra-vars`目标

+   角色变量

+   角色默认值

+   任务文件

+   处理程序文件

+   `copy`模块的源文件（这些是列表中的一个例外——它们不必是 YAML 格式的）

如果一个文件可以用 YAML 表示并且可以被 Ansible 读取，或者如果一个文件要用`copy`模块传输，那么它就是 Vault 中加密的有效文件。因为整个文件在休息时都是不可读的，所以在选择要加密的文件时应该小心谨慎。对文件的任何源控制操作都将使用加密内容进行，这将使对文件进行审查变得非常困难。

作为最佳实践，应该尽可能少地加密数据，这甚至可能意味着将一些变量单独移到一个文件中。正是出于这个原因，Ansible 2.3 添加了`encrypt_string`功能到`ansible-vault`，允许将单独的秘密内联放置在否则未加密的 YAML 中，从而使用户无需加密整个文件。我们将在本章后面介绍这个功能。

# 创建和编辑加密文件

要创建新文件，Ansible 提供了一个名为`ansible-vault`的程序。该程序用于创建和与 Vault 加密文件交互。创建加密文件的子命令是`create`，您可以通过运行以下命令查看此子命令下可用的选项：

```
ansible-vault create --help
```

该命令的输出如下截图所示：

![图 3.1 - 创建 Ansible Vault 实例时可用的选项](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_01.jpg)

图 3.1 - 创建 Ansible Vault 实例时可用的选项

要创建新文件，您需要提前知道两件事。第一是`ansible-vault`将用于加密文件的密码，第二是文件名本身。提供了这些信息后，`ansible-vault`将启动一个文本编辑器（如在`EDITOR`环境变量中定义的那样 - 在许多情况下默认为`vi`或`vim`）。保存文件并退出编辑器后，`ansible-vault`将使用提供的密码作为`AES256`密码对文件进行加密。

让我们通过几个示例来创建加密文件。首先，我们将创建一个并在提示输入密码时进行操作，然后我们将提供一个`password`文件，最后，我们将创建一个可执行文件来提供密码。

### 密码提示

让`ansible-vault`在运行时从用户那里请求密码是开始创建 vault 的最简单方法，因此让我们通过一个简单的示例来创建一个包含我们想要加密的变量的 vault。运行以下命令创建一个新的 vault，并在提示输入密码时：

```
ansible-vault create --vault-id @prompt secrets.yaml
```

输出应该类似于这样：

![图 3.2 - 在提示输入密码时创建一个新的 Ansible Vault 实例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_02.jpg)

图 3.2 - 在提示输入密码时创建一个新的 Ansible Vault 实例

输入密码后，我们的编辑器将打开，我们可以将内容放入文件中，如下截图所示：

![图 3.3 - 使用 vim 编辑器向新的 Ansible Vault 实例添加内容](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_03.jpg)

图 3.3 - 使用 vim 编辑器向新的 Ansible Vault 实例添加内容

在我的系统上，配置的编辑器是**Vim**。您的系统可能不同，如果您对默认选择不满意，可以将您喜欢的编辑器设置为`EDITOR`环境变量的值。

现在，我们保存文件。如果我们尝试使用以下命令读取内容，我们会发现它们实际上是加密的：

```
cat secrets.yaml
```

这只是一个小的头部提示，供 Ansible 稍后使用，如下截图所示：

![图 3.4 - 显示我们的新 Ansible Vault 实例的内容，这些内容在静止状态下是加密的](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_04.jpg)

图 3.4 - 显示我们的新 Ansible Vault 实例的内容，这些内容在静止状态下是加密的

从标题中可以看出，`AES256`用于 vault 加密，这意味着只要您在创建 vault 时使用了一个好密码，您的数据就非常安全。

### 密码文件

要使用带有密码文件的`ansible-vault`，您首先需要创建这样一个文件。只需将密码回显到文件中即可。完成后，您现在可以在调用`ansible-vault`创建另一个加密文件时引用此文件。通过运行以下命令来尝试：

```
echo "my long password" > password_file
ansible-vault create --vault-id ./password_file more_secrets.yaml
```

这应该看起来像以下截图所示的输出：

![图 3.5 - 使用密码文件创建 Ansible Vault 实例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_05.jpg)

图 3.5 - 使用密码文件创建 Ansible Vault 实例

当你运行上述命令时，你会注意到你没有被要求输入密码 - 这次，保险库的密码是`my long password`字符串，它已经从`password_file`的内容中读取。默认编辑器将打开，此时可以像以前一样写入数据。

### 密码脚本

最后一个例子使用了一个密码脚本。这对于设计一个系统很有用，其中密码可以存储在一个中央系统中，用于存储凭据并与 playbook 树的贡献者共享。每个贡献者可以有自己的密码用于共享凭据存储，从中检索 Vault 密码。我们的例子将会简单得多：只是一个简单的输出到`STDOUT`，带有一个密码。这个文件将保存为`password.sh`。现在使用以下内容创建这个文件：

```
#!/bin/sh
echo "a long password"
```

为了让 Ansible 使用这个脚本，它必须被标记为可执行 - 对它运行以下命令以使其成为可执行文件：

```
chmod +x password.sh
```

最后，您可以通过运行以下命令创建一个使用`a long password`作为输出的新保险库，这是我们简单脚本的输出：

```
ansible-vault create --vault-id ./password.sh even_more_secrets.yaml
```

这个过程的输出应该看起来像这样：

![图 3.6 - 使用简单密码脚本创建 Ansible Vault 实例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_06.jpg)

图 3.6 - 使用简单密码脚本创建 Ansible Vault 实例

自己尝试一下，看看它是如何工作的 - 你应该发现`ansible-vault`创建了一个使用`a long password`密码的保险库，正如脚本写入`STDOUT`的那样。你甚至可以尝试使用以下命令进行编辑：

```
ansible-vault edit --vault-id @prompt even_more_secrets.yaml
```

当提示时，现在你应该输入`a long password` - 然后你就可以成功编辑保险库了！

## 加密现有文件

之前的例子都涉及使用`create`子命令创建新的加密文件。但是如果我们想要获取一个已建立的文件并对其进行加密呢？也存在一个子命令来实现这一点。它被命名为`encrypt`，您可以通过运行以下命令查看此子命令的选项：

```
ansible-vault encrypt --help
```

输出将类似于下面截图中显示的内容：

![图 3.7 - Ansible Vault encrypt 子命令的可用选项](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_07.jpg)

图 3.7 - Ansible Vault encrypt 子命令的可用选项

与`create`一样，`encrypt`需要一个`password`（或密码文件或可执行文件）和要加密的文件的路径。一旦接收到适当的密码，编辑器就会打开，这次我们的原始内容以明文的形式已经对我们可见。

请注意，要加密的文件必须已经存在。

让我们通过加密我们从*第一章*中得到的现有文件来演示一下，*Ansible 的系统架构和设计*，名为`Chapter01/example09/a_vars_file.yaml`。将此文件复制到一个方便的位置，然后使用以下命令对其进行加密：

```
ansible-vault encrypt --vault-id ./password.sh a_vars_file.yaml
```

这个过程的输出应该类似于下面截图中显示的内容：

![图 3.8 - 使用 Ansible Vault 加密现有变量文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_08.jpg)

图 3.8 - 使用 Ansible Vault 加密现有变量文件

在这个例子中，我们可以在调用`encrypt`之前和之后看到文件内容，在此之后内容确实被加密了。与`create`子命令不同，`encrypt`可以操作多个文件，轻松地在一个操作中保护所有重要数据。只需列出要加密的所有文件，用空格分隔。

尝试加密已加密的文件将导致错误。

## 编辑加密文件

一旦文件被`ansible-vault`加密，就不能直接编辑。在编辑器中打开文件会显示加密数据。对文件进行任何更改都会损坏文件，Ansible 将无法正确读取内容。我们需要一个子命令，首先解密文件的内容，允许我们编辑这些内容，然后在保存回文件之前加密新内容。这样的子命令存在于`edit`中，您可以通过运行以下命令查看此子命令的可用选项：

```
ansible-vault edit --help
```

输出应该看起来类似于以下截图所示的内容：

![图 3.9 – Ansible Vault 编辑子命令的可用选项](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_09.jpg)

图 3.9 – Ansible Vault 编辑子命令的可用选项

正如我们已经看到的，我们的编辑器将以明文打开，我们可以看到我们的内容。所有我们熟悉的`vault-id`选项都回来了，以及要编辑的文件。因此，我们现在可以使用以下命令编辑刚刚加密的文件：

```
ansible-vault edit --vault-id ./password.sh a_vars_file.yaml
```

请注意，`ansible-vault`使用临时文件作为文件路径打开我们的编辑器。当您保存并退出编辑器时，临时文件将被写入，然后`ansible-vault`将对其进行加密并将其移动以替换原始文件。以下截图显示了我们以前加密的 vault 的未加密内容可供编辑：

![图 3.10 – 编辑我们以前加密的 Ansible Vault](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_10.jpg)

图 3.10 – 编辑我们以前加密的 Ansible Vault

您可以在编辑器窗口中看到的临时文件（`…/tmp6ancaxcu.yaml`）将在`ansible-vault`成功加密文件后被删除。

## 加密文件的密码轮换

随着贡献者的进出，定期更改用于加密您的机密的密码是一个好主意。加密的安全性取决于密码的保护程度。`ansible-vault`提供了一个`rekey`子命令，允许我们更改密码，您可以通过运行以下命令探索此子命令的可用选项：

```
ansible-vault rekey --help
```

输出应该看起来类似于以下截图所示的内容：

![图 3.11 – Ansible Vault 重新生成子命令的可用选项](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_11.jpg)

图 3.11 – Ansible Vault 重新生成子命令的可用选项

`rekey`子命令的操作方式与`edit`子命令类似。它接受一个可选的密码、文件或可执行文件，以及一个或多个要重新生成的文件。然后，您需要使用`--new-vault-id`参数来定义一个新密码（如果需要，还可以定义 ID），同样可以通过提示、文件或可执行文件来定义。让我们通过以下命令重新生成我们的`a_vars_file.yaml`文件，并将 ID 更改为`dev`，暂时我们将提示输入新密码，尽管我们知道我们可以使用我们的密码脚本获取原始密码：

```
ansible-vault rekey --vault-id ./password.sh --new-vault-id dev@prompt a_vars_file.yaml
```

输出应该看起来类似于以下截图所示的内容：

![图 3.12 – 重新生成现有的 Ansible Vault 并同时更改 ID](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_12.jpg)

图 3.12 – 重新生成现有的 Ansible Vault 并同时更改 ID

请记住，所有具有**相同 ID**的加密文件都需要具有匹配的密码（或密钥）。确保同时重新生成具有相同 ID 的所有文件。

## 解密加密文件

如果在某个时候，不再需要加密数据文件，`ansible-vault`提供了一个子命令，可用于删除一个或多个加密文件的加密。这个子命令（令人惊讶地）被命名为`decrypt`，您可以通过运行以下命令查看此子命令的选项：

```
ansible-vault decrypt --help
```

输出应该看起来类似于以下截图所示的内容：

![图 3.13 – Ansible Vault 解密子命令的可用选项](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_13.jpg)

图 3.13 – Ansible Vault 解密子命令的可用选项

再次，我们有我们熟悉的`--vault-id`选项，然后是一个或多个要解密的文件路径。让我们通过运行以下命令解密我们刚刚重新生成的文件：

```
ansible-vault decrypt --vault-id dev@prompt a_vars_file.yaml
```

如果成功，你的解密过程应该看起来像以下截图所示：

![图 3.14–解密现有保险库](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_14.jpg)

图 3.14–解密现有保险库

在下一节中，我们将看到如何在引用加密文件时执行`ansible-playbook`。

# 使用加密文件执行 ansible-playbook

为了使用我们的加密内容，我们首先需要告诉`ansible-playbook`如何访问它可能遇到的任何加密数据。与`ansible-vault`不同，后者仅用于处理文件加密或解密，`ansible-playbook`更通用，它不会默认假设它正在处理加密数据。幸运的是，我们在之前示例中熟悉的所有`--vault-id`参数在`ansible-playbook`中的工作方式与在`ansible-vault`中的工作方式完全相同。Ansible 将在 playbook 执行期间将提供的密码和 ID 保存在内存中。

现在让我们创建一个名为`show_me.yaml`的简单 playbook，它将打印出我们在之前示例中加密的`a_vars_file.yaml`中变量的值，如下所示：

```
--- 
- name: show me an encrypted var 
  hosts: localhost 
  gather_facts: false 

  vars_files: 
    - a_vars_file.yaml 

  tasks: 
    - name: print the variable 
      ansible.builtin.debug: 
        var: something 
```

现在，让我们运行 playbook 并看看会发生什么。注意我们如何以与`ansible-vault`完全相同的方式使用`--vault-id`参数；两个工具之间保持连续性，因此你可以应用你在本章早些时候学到的关于使用`--vault-id`的一切。如果你之前没有完成这一步，请使用以下命令加密你的变量文件：

```
chmod +x password.sh
ansible-vault encrypt --vault-id dev@./password.sh a_vars_file.yaml
```

完成后，现在使用以下命令运行 playbook—注意`--vault-id`参数的存在，与之前类似：

```
ansible-playbook -i mastery-hosts --vault-id dev@./password.sh showme.yaml
```

完成后，你的输出应该看起来像以下截图所示：

![图 3.15–运行包含加密的 Ansible Vault 实例的简单 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_15.jpg)

图 3.15–运行包含加密的 Ansible Vault 实例的简单 playbook

正如你所看到的，playbook 成功运行并打印出变量的未加密值，即使我们包含的源变量文件是一个加密的 Ansible Vault 实例。当然，在真正的 playbook 运行中，你不会将秘密值打印到终端上，但这演示了从保险库中访问数据有多么容易。

到目前为止，在我们的所有示例中，我们已经创建了作为外部实体的保险库—这些文件存在于 playbook 之外。然而，将加密的保险库数据添加到一个否则未加密的 playbook 中是可能的，这样可以减少我们需要跟踪和编辑的文件数量。让我们看看在下一节中如何实现这一点。

# 混合加密数据与普通 YAML

在发布 Ansible 2.3 之前，安全数据必须加密在一个单独的文件中。出于我们之前讨论的原因，希望尽可能少地加密数据。现在通过`ansible-vault`的`encrypt_string`子命令可以实现这一点（并且还可以节省作为 playbook 一部分的太多个别文件的需要），它会生成一个加密字符串，可以放入 Ansible YAML 文件中。让我们以以下基本 playbook 作为示例：

```
---
- name: inline secret variable demonstration
  hosts: localhost
  gather_facts: false
  vars:
    my_secret: secure_password
  tasks:
    - name: print the secure variable
      ansible.builtin.debug:
        var: my_secret
```

我们可以使用以下命令运行这段代码（尽管不安全！）：

```
ansible-playbook -i mastery-hosts inline.yaml
```

当这个 playbook 运行时，输出应该类似于以下截图所示：

![图 3.16–运行包含敏感数据的未加密 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_16.jpg)

图 3.16–运行包含敏感数据的未加密 playbook

现在，显然不能像这样留下一个安全密码的明文。因此，我们将使用`ansible-vault`的`encrypt_string`子命令对其进行加密。如果您想查看运行此子命令时可用的选项，可以执行以下命令：

```
ansible-vault encrypt_string --help
```

该命令的输出应该与下面截图中显示的类似：

![图 3.17 – Ansible Vault 的 encrypt_string 子命令的可用选项](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_17.jpg)

图 3.17 – Ansible Vault 的 encrypt_string 子命令的可用选项

因此，如果我们想要为我们的`my_secret`变量使用`test` Vault ID 和我们之前为密码创建的`password.sh`脚本，创建一个加密的文本块，我们将运行以下命令：

```
chmod +x password.sh
ansible-vault encrypt_string --vault-id test@./password.sh "secure_password" --name my_secret
```

这些命令的输出将为您提供要包含在现有 playbook 中的加密字符串，下面的截图中显示了一个示例：

![图 3.18 – 使用 Ansible Vault 将变量加密为安全字符串](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_18.jpg)

图 3.18 – 使用 Ansible Vault 将变量加密为安全字符串

现在，我们可以将该输出复制粘贴到我们的 playbook 中，确保我们的变量不再是人类可读的，就像下面的截图中演示的那样：

![图 3.19 – 在现有的 playbook 中用加密字符串数据替换未加密的变量](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_19.jpg)

图 3.19 – 在现有的 playbook 中用加密字符串数据替换未加密的变量

尽管我们现在直接在我们的 playbook 中嵌入了一个 Ansible Vault 加密的变量，但我们可以像以前一样使用适当的`--vault-id`运行此 playbook—下面的命令将在这里使用：

```
ansible-playbook -i mastery-hosts --vault-id test@./password.sh inline.yaml
```

您将观察到 playbook 正在运行，并且可以访问信息，就像任何其他 vault 数据一样，并且您的输出应该与下面的截图中显示的类似：

![图 3.20 – 运行包含加密字符串的 Ansible playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_20.jpg)

图 3.20 – 运行包含加密字符串的 Ansible playbook

您可以看到，当所有数据对世界都是公开的时，playbook 的运行方式与我们第一次测试时完全相同！然而，现在，我们已经成功地将加密数据与一个否则未加密的 YAML playbook 混合在一起，而无需创建单独的 Vault 文件。

在下一节中，我们将更深入地探讨与 Ansible Vault 一起运行 playbook 的一些操作方面。

# 在操作时保护秘密

在本章的前一节中，我们讨论了如何在文件系统上保护您的秘密。然而，这并不是在操作 Ansible 与秘密时唯一关注的问题。这些秘密数据将用于任务作为模块参数、循环输入或任何其他事情。这可能导致数据传输到远程主机，记录到本地或远程日志文件，甚至显示在屏幕上。本章的这一部分将讨论在操作过程中保护您的秘密的策略。

## 传输到远程主机的秘密

正如我们在*第一章*中所学到的，*Ansible 的系统架构和设计*，Ansible 将模块代码和参数组合起来，并将其写入远程主机上的临时目录。这意味着您的秘密数据通过网络传输，并写入远程文件系统。除非您使用的是**安全外壳**（**SSH**）或**安全套接字层**（**SSL**）加密的**Windows 远程管理**（**WinRM**）之外的连接插件，否则通过网络传输的数据已经加密，防止您的秘密被简单窥视发现。如果您使用的是除 SSH 之外的连接插件，请注意数据在传输时是否加密。强烈建议使用任何未加密的连接方法。

一旦数据传输完成，Ansible 可能会以明文形式将这些数据写入文件系统。如果不使用流水线传输（我们在*第一章*中了解过，*Ansible 的系统架构和设计*），或者如果已经指示 Ansible 通过`ANSIBLE_KEEP_REMOTE_FILES`环境变量保留远程文件，就会发生这种情况。没有流水线传输，Ansible 将模块代码和参数写入一个临时目录，该目录将在执行后立即删除。如果在写出文件和执行之间失去连接，文件将保留在远程文件系统上，直到手动删除。如果明确指示 Ansible 保留远程文件，即使启用了流水线传输，Ansible 也会写入并保留远程文件。在处理高度敏感机密信息时，应谨慎使用这些选项，尽管通常情况下，只有 Ansible 在远程主机上进行身份验证的用户（或通过特权升级成为的用户）应该可以访问剩余的文件。简单地删除远程用户的`~/.ansible/tmp/`路径中的任何内容就足以清除机密信息。

## 记录到远程或本地文件的机密信息

当 Ansible 在主机上运行时，它将尝试将操作记录到`syslog`（如果使用了冗长度级别 3 或更高）。如果这个操作是由具有适当权限的用户执行的，它将导致在主机的`syslog`文件中出现一条消息。此消息包括模块名称和传递给该命令的参数，其中可能包括您的机密信息。为了防止这种情况发生，存在一个名为`no_log`的操作和任务键。将`no_log`设置为`true`将阻止 Ansible 将操作记录到`syslog`。

Ansible 还可以被指示在本地记录其操作。这可以通过 Ansible 配置文件中的`log_path`或通过名为`ANSIBLE_LOG_PATH`的环境变量来控制。默认情况下，日志记录是关闭的，Ansible 只会记录到`STDOUT`。在`config`文件中打开日志记录会导致 Ansible 将其活动记录到`logpath` `config`设置中定义的文件中。

或者，将`ANSIBLE_LOG_PATH`变量设置为可以被运行`ansible-playbook`的用户写入的路径，也会导致 Ansible 将操作记录到该路径。此日志的冗长度与屏幕显示的冗长度相匹配。默认情况下，屏幕上不显示任何变量或返回细节。在冗长度级别为 1（`-v`）时，返回数据将显示在屏幕上（可能也会显示在本地日志文件中）。将冗长度调到级别 3（`-vvv`）时，输入参数也可能会显示。由于这可能包括机密信息，因此`no_log`设置也适用于屏幕显示。让我们以前面显示加密机密信息的示例，并在任务中添加一个`no_log`键，以防止显示其值，如下所示：

```
--- 
- name: show me an encrypted var 
  hosts: localhost 
  gather_facts: false 

  vars_files: 
    - a_vars_file.yaml 

  tasks: 
    - name: print the variable 
      ansible.builtin.debug: 
        var: something 
      no_log: true 
```

我们将以与以前相同的方式执行此操作手册（但增加了冗长度，如使用`-v`标志指定的那样），通过运行以下命令来执行——如果需要的话，请记得先加密变量文件：

```
ansible-playbook -i mastery-hosts --vault-id test@./password.sh showme.yaml -v
```

我们应该看到我们的机密数据受到了保护，即使我们故意尝试使用`ansible.builtin.debug`打印它，如下面的屏幕截图所示：

![图 3.21 – 加密变量文件并运行一个保护敏感数据的操作手册](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_03_21.jpg)

图 3.21 – 加密变量文件并运行一个保护敏感数据的操作手册

正如您所看到的，Ansible 对自身进行了审查，以防止显示敏感数据。`no_log` 键可用作指令，用于操作、角色、块或任务。

这就结束了我们对 Ansible Vault 的操作使用的介绍，也结束了对 Ansible Vault 主题的讨论——希望本章对教会您如何在使用 Ansible 进行自动化时保护敏感数据方面是有用的。

# 总结

在本章中，我们介绍了 Ansible 如何有效且安全地处理敏感数据，利用最新的 Ansible 功能，包括使用不同密码保护不同数据和将加密数据与普通 YAML 混合。我们还展示了这些数据在静止状态下的存储方式以及在使用时如何处理这些数据，只要小心谨慎，Ansible 就可以保护您的秘密。

您学会了如何使用`ansible-vault`工具来保护敏感数据，包括创建、编辑和修改加密文件以及提供 Vault 密码的各种方法，包括提示用户、从文件获取密码和运行脚本来检索密码。您还学会了如何将加密字符串与普通 YAML 文件混合，以及这如何简化 playbook 布局。最后，您学会了使用 Ansible Vault 的操作方面，从而防止 Ansible 将数据泄漏到远程日志文件或屏幕显示。

在我们的下一章中，我们将探讨如何将 Ansible 的强大功能应用于 Windows 主机，以及如何利用这一功能。

# 问题

1.  Ansible Vault 使用哪种加密技术在静止状态下加密您的数据？

a) 三重 DES/3DES

b) MD5

c) AES

d) Twofish

1.  Ansible Vault 实例必须始终存在为 playbook 本身的单独文件：

a) 真

b) 假

1.  在运行 playbook 时，您可以从多个 Ansible Vault 实例中摄取数据：

a) 真

b) 假

1.  在执行使用 Vault 加密数据的 playbook 时，您可以提供密码：

a) 在 playbook 启动时进行交互

b) 使用仅包含密码的明文文件

c) 使用脚本从另一个来源检索密码

d) 以上所有

1.  在 playbook 运行期间，Ansible 永远不会将 vault 数据打印到终端：

a) 真

b) 假

1.  您可以使用以下任务参数防止 Ansible 在 playbook 运行期间无意中将 vault 数据打印到终端：

a) `no_print`

b) `no_vault`

c) `no_log`

1.  中断的 playbook 运行可能会在远程主机上留下敏感的未加密数据：

a) 真

b) 假

1.  在运行时用于区分不同 vault（可能具有不同密码）的是什么？

a) Vault 名称

b) Vault ID

c) Vault 标识符

d) 以上都不是

1.  您可以使用哪个 Ansible 命令编辑现有的加密 vault？

a) `ansible-vault vi`

b) `ansible-vault change`

c) `ansible-vault update`

d) `ansible-vault edit`

1.  为什么您可能不希望在 vault 中混合敏感和非敏感数据？

a) 这样做会使得难以运行`diff`命令并查看**版本控制系统**（**VCS**）中的更改。

b) 只允许在 Ansible Vault 中放置敏感数据。

c) Ansible Vault 的容量有限。

d) Ansible Vault 使得访问受保护的数据变得困难。
