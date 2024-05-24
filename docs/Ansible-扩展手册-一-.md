# Ansible 扩展手册（一）

> 原文：[`zh.annas-archive.org/md5/DD4A78955A79B5BC82C4E9415A3280DB`](https://zh.annas-archive.org/md5/DD4A78955A79B5BC82C4E9415A3280DB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

随着大多数公司转向云端，基础设施需求呈指数增长。不断增长的数据和存储、分析和处理这些数据所需的大量计算能力增加了基础设施需求。随着互联网服务用户数量不断增加，以及伴随着数据挖掘竞赛而带来的海量数据涌入，大数据和云服务开辟了新的数据中心并扩展了现有的数据中心。此外，随着基础设施不断扩展和需求不断增加，以及保持 99.9%的正常运行时间承诺，自动化管理基础设施成为当务之急。DevOps 很快成为一种必要性，市场上涌现出大量的 DevOps 工具。Ansible 是这样一种开源解决方案，它将编排、配置管理和应用程序部署功能结合在一起。

Ansible 是一种 IT 自动化工具，可以让您管理基础设施作为代码。它帮助您部署应用程序并管理配置，从而使生活更轻松。它是一个建立在 Python 上的开源项目，并拥有强大的社区支持。在大多数情况下，Ansible 足以满足您的大部分需求。有许多模块和插件可用，Ansible 使一切看起来如此简单。编写和理解 playbooks 非常顺畅。

本书旨在面向已经具有 Ansible 工作知识的高级用户，我们将讨论 Ansible 暴露的各种扩展点，以及如何利用它们来满足我们的需求。本书详细介绍了 Ansible Python API、Ansible 模块和 Ansible 插件。通过现实生活场景，本书演示了如何扩展 Ansible 以满足您的需求。本书将带您逐步了解如何填补空白，成为 Ansible 的专家。

# 本书内容

第一章, *开始使用 Ansible*，是一个介绍性章节，向您介绍了 Ansible，并鼓励您成为一个高级用户。它向您介绍了 Ansible 的架构，并给出了选择 Ansible 作为基础设施和配置管理工具的理由。

第二章, *了解 Ansible 模块*，介绍了编写 Ansible 模块的基础知识。它向您介绍了 AnsibleModule 样板。本章还帮助您使用 Bash 和 Python 开发示例 Ansible 模块。

第三章 *深入了解 Ansible 模块*，介绍了如何处理 Ansible 模块中的参数。它还通过开发自定义 Ansible 模块的场景带您了解收集基础设施信息的过程。

第四章 *探索 API*，详细介绍了 Ansible 的 Python API，以编程方式运行 Ansible，并讨论了 Ansible 提供的各种扩展点。它深入讨论了插件加载器、运行器、Playbooks 和回调等主题。

第五章 *深入了解 Ansible 插件*，涵盖了不同插件的代码级别。它还演示了如何通过几个示例编写自己的 Ansible 插件。

第六章 *将所有内容整合在一起-集成*，涵盖了 Ansible 的各种配置选项，从而使用户充分利用该工具。本章介绍了 Ansible Galaxy，这是一个分享角色的平台。它带领读者了解了如何贡献给 Ansible 并分发他们的模块和插件的过程。

第七章 *成为大师-完整配置指南*，包含了可以利用 Ansible 的强大功能执行所需任务的实际场景。还包括了可以进一步使用 Ansible 作为基础设施和配置管理工具的场景。

# 本书所需内容

要充分利用本书，您需要以下内容：

+   Linux 发行版（Fedora/Ubuntu）

+   Ansible

+   Python

# 本书适合对象

本书非常适合熟悉 Ansible 和 Python 编程但不了解如何自定义 Ansible 的开发人员和管理员。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："配置文件中由`library`变量指定的路径，位于`/etc/ansible/ansible.cfg`。"

代码块设置如下：

```
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
**exten => s,102,Voicemail(b100)**
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都会以以下方式书写：

```
**# cp /usr/src/asterisk-addons/configs/cdr_mysql.conf.sample**
 **/etc/asterisk/cdr_mysql.conf**

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中显示为这样：“通过使用菜单中的**添加角色**选项并提供所需的凭据，Galaxy 将从您的 GitHub 存储库导入角色，并在 Galaxy 平台上为整个社区提供。”

### 注意

警告或重要提示会显示在这样的框中。

### 提示

提示和技巧会显示为这样。


# 第一章：使用 Ansible 入门

随着技术的进步，计算变得越来越复杂。随着每天制造出更好的硬件，计算系统的复杂性也增加了。分布式计算开始蓬勃发展，很快就发明了“云”。软件变得微不足道，管理它变得痛苦。开发周期加快，手动测试和部署很快就过时了，因此需要自动化。如果您正在阅读本书，您可能了解自动化的重要性，无论是用于测试应用程序还是管理整个基础设施。

随着负载的增加和基础设施的不断扩展，系统管理员已经不再是简单的手工艺人，手动配置每个系统，而是开始一次管理成千上万个系统。无论环境有多大，您都需要一个可靠的系统来管理所有这些。地理分散的工作场所和不断增长的基础设施几乎不可能跟踪库存并手动配置和管理每台机器。快速的开发周期和缩短的上市时间留下了很少的错误余地，并且抛弃了手动流程。

管理整个基础设施、部署构建、加快流程的关键，同时跟踪变化的方法是拥有一个用户友好、学习曲线小、可以根据您的需求进行插件化的系统。最重要的是，您要保持专注，花更多时间管理基础设施和流程，而不是自动化脚本和管理工具本身。在众多可用的解决方案中，Ansible 是一个具有许多有趣功能的工具。它易于扩展，并且对于 90%的用户需求可以立即使用。本书重点关注剩下的 10%。

在本章中，我们将探讨：

+   为什么选择 Ansible？

+   为什么要扩展 Ansible？

+   Ansible 架构

+   扩展 Ansible

# 为什么选择 Ansible？

在市场上有很多可用的工具，您如何选择最适合您需求的工具？在选择满足您需求的工具时，应该考虑哪些因素？可能会有一些问题浮现，比如：

+   投资回报率（ROI）是指金钱、时间和精力方面的回报是什么？

+   我能得到什么样的工具支持？

+   有哪些潜在的安全风险？

+   这个工具足够灵活，可以插入我的基础设施吗？

+   覆盖范围是什么？我的所有需求都得到了满足吗？

如果你有这些疑问，我将试着站在 Ansible 的角度来回答。

+   Ansible 是免费的。你唯一需要投入的是一些时间和精力。Ansible 的 playbooks 基于 YAML，因此非常容易阅读、理解和维护，学习曲线很小。模块隐藏了底层的复杂性。

+   Ansible 是开源的。因此，有整个社区来支持你。你可以提交问题，甚至自己修复问题，因为你始终可以访问代码。

+   与大多数基于代理的解决方案不同，Ansible 完全基于 SSH 工作，无需代理。因此，你可以坐下来放松，因为在你的生产系统上不需要额外的软件包。

+   Ansible 提供了一个非常好的 API，你可以使用它来构建适合你需求的 Ansible 模块，然后将其插入到你的基础设施中。

+   Ansible 可以满足 90%的用户需求，剩下的 10%有着完善的 API 和社区支持，可以构建自己的模块，从而增加覆盖范围。

如果你对以上论点感到满意，并愿意尝试一下 Ansible，继续阅读。

# 为什么要扩展 Ansible？

Ansible 在各种情境下都很方便使用——作为配置管理工具和部署自动化工具，以及用于供应和编排。它默认提供了许多插件和模块，可以用于构建 playbooks。你可以使用 Ansible 来管理整个基础设施，就像大多数软件开发项目一样。**基础设施即代码**（IAC）将软件开发的原则应用到配置管理中。

人们喜欢 Ansible 是因为它简单易用，清晰地分离了关注点。它不会强迫你遵循特定的配置管理方式，而是为你设计基础设施即代码（IAC）解决方案提供了完美的构建模块，以满足你的特定需求。

有很多原因可以扩展 Ansible。这可能包括添加缺失的功能，根据自己的需求修改/增强现有功能。由于 Ansible 是一个开源的、社区驱动的项目，不是所有的东西都能一次性集成进去。效用和需求之间总是存在权衡。如果某个特定功能的用户不多，对项目维护者来说，支持它就会成为负担。

## 需要新的东西吗？

因此，您可能会遇到这样的情况：Ansible 以其现有的模块和插件的原始形式不足以满足您的要求。你会怎么做？更换工具？寻找其他选项？甚至因为无法预见即将发生的事情而诅咒自己的运气，现在你需要改变一切？

好吧，答案是否定的。Ansible 提供了一个非常好的 API 和样板，您可以使用它们根据自己的需求编写自己的 Ansible 模块或插件。构建 Ansible 模块很容易。由于 Ansible 是社区驱动的，如果您觉得更多的人可能会遇到与您遇到的相同问题，甚至可以为所需的模块提交功能请求。如果您是开发人员，您可以简单地编写自己的 Ansible 模块或插件，并与社区分享。为您的模块发送拉取请求，并与项目维护者进行讨论。希望该模块将被合并并在将来的 Ansible 版本中提供。

在本书中，我们将看到如何根据要求扩展 Ansible，并通过为一个开源项目，特别是 Ansible，做出贡献来分发定制内容。

## 公司范围的抽象

将基础设施视为代码提供了许多优势，但也有成本。您团队的成员并非都愿意攀登学习曲线。因此，只有少数人将成为诸如 Ansible 之类的任何配置管理工具的强大用户，并且他们将成为整个团队的瓶颈。

良好的 IAC 实施应该使每个人都能轻松地与基础设施互动，部署新软件，提供资源并将组件编织在一起。尽可能将细节抽象化，行为应该清晰，定义应该是可导航的。还应该存在一种将任何问题追溯到高级配置的简单方法。

为了实现这一点，可以开发可以抽象细节并提供人们可以直接使用并获得结果的接口的插件和模块。这将帮助每个人迅速掌握并与基础设施互动。

您可以创建模块和插件，使您的日常任务变得简单。您可以将这些共享为实用程序，任何公司成员都可以使用它们来执行类似的任务。这将需要一些开发人员的努力，但将使即使不那么强大的用户也能充分利用他们的基础设施。

## 深入了解 Ansible

基础设施逐渐增长到一个点，你最终放弃手动管理，并开始感受到需要更好的方式来管理不断增长的复杂性。

一种方法是花费大量时间寻找合适的工具，然后最终采用完整的配置管理解决方案，并费尽心思地改变问题以适应现有解决方案。显然，这种方法是有缺陷的。

另一种方法是保持简单，并逐步利用现有工具的力量，当它们确实给你带来立即的优势时。

Ansible 更适合于后一种方法。它写得很好，提供了清晰的关注点分离和简单的模型。事实上，你可以选择在多大程度上参与其中。它允许你重用社区提供的组件，同时保持控制。

你可以利用 Ansible 提供的各种扩展点来构建适合你需求的模块和插件。重用已有的插件和模块，并根据需要创建自己的，可以更多地控制你的基础设施。

# 为 Ansible 做贡献

Ansible 是一个托管在 GitHub 上的开源项目。如果你有 GitHub 账号，你可以轻松地 fork Ansible 存储库并开始为项目做贡献（Ansible 代码：[`github.com/ansible/ansible`](https://github.com/ansible/ansible)）。

你可以在自己的账户中 fork 项目，克隆它，然后进行更改并向项目所有者发送拉取请求。这适用于所有开源项目。

如果你不知道从哪里开始贡献，你也可以查看存储库中的*Issues*部分。*Issues*部分包含了使用该工具的人们的 bug 报告和功能请求。你可以选择验证和修复问题，然后将你的补丁作为针对问题的拉取请求发送给项目所有者。

补丁经过审查流程，只有在项目维护者批准后，补丁才会合并。一旦合并，该功能将对用户可用。

# Ansible 架构

尽管我们假设读者对 Ansible 有一定的了解，但通过简要概述 Ansible 架构仍然很有用，以便更好地理解各种扩展点。

Ansible 是一种无代理配置管理系统，这意味着受管主机上不必运行特殊软件。Ansible 通常通过普通 SSH 连接到其目标，复制所有必要的代码，并在目标机器上运行。无代理是 Ansible 相对于其他解决方案的主要优势之一。这减少了在目标机器上安装所需代理的设置开销，同时减少了安全风险，因为不需要安装额外的软件包或代理。

核心的 Ansible 组件包括：

+   **清单**：目标

+   **变量**：关于目标主机的信息

+   **连接**：如何与目标主机通信

+   **Runner**：连接到目标并执行操作

+   **Playbook**：要在目标主机上执行的配方

+   **Facts**：关于目标的动态信息

+   **模块**：实现操作的代码

+   **回调**：收集 playbook 操作的结果

以下图显示了 Ansible 的架构：

![Ansible architecture](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-asb/img/B04624_01-01.jpg)

## Ansible 组件的简要概述

让我们更仔细地看一下 Ansible 组件。

## Ansible runner

Ansible 的核心是**runner**。runner 允许您在一个或多个主机上执行操作并收集结果。

runner 使用清单选择要连接的主机。清单还可以将一组变量与每个主机关联起来。然后可以通过 playbook 和其他 Ansible 组件（如连接插件）访问这些变量。

### 连接插件

连接插件（默认为 SSH 连接）可以使用特定的主机变量来确定如何连接到远程主机。变量可能包括诸如要用于连接到远程主机的用户名，非默认端口号等信息。

### Playbook

转到另一个组件，**playbook**是最重要的之一，因为所有的配方都是以 Ansible playbook 的形式编写的。Playbooks 被建模为一组 plays，每个 play 定义了要在一组远程主机上执行的一组任务。play 还定义了任务将被执行的环境。

### 角色

Playbook 可以分解为**角色**以便更好地组织。角色有助于模块化 playbook 任务。这些角色可以稍后包含在针对特定主机组的播放中。例如，如果您的基础设施涉及 Web 服务器和代理服务器，每个都需要一组常见的任务（准备系统），然后是特定类型的任务（设置和配置 Web/代理服务器），这些可以简单地分解为角色，然后可以针对特定主机运行。常见任务可以针对所有主机定义，在此时 Web 服务器和代理服务器角色可以针对各自的主机组执行。

### 变量

Ansible 架构中的另一个重要组件是**变量**。变量可用于提取常见值并对共享的 playbook 片段进行参数化。它们还可以用于根据它们共享的某些特性对主机进行分类。

### 事实

由于每个主机都可以提供大量关于自身的信息，手动管理它们并不是一种推荐的做法。因此，Ansible 在其软件中包含了一个称为**facts**的特殊变量。

事实变量由设置模块提供，并在每个主机上隐式执行（除非明确禁用）。此变量在运行程序开始在远程主机上执行 playbook 之前收集有关远程主机的信息。

### 运行程序

现在我们已经有了 Ansible playbook，并且已经收集了关于远程主机组的所有事实，运行程序开始执行。运行程序变量通过将操作代码复制到目标机器并在执行操作代码之前准备环境来在远程主机上执行特定操作（如在 Ansible playbook 中指定的）。

一旦运行程序评估并执行任务，它会清理从远程主机复制的代码，最后通过**回调**报告状态。

# Playbook 表现力

为了促进配置的一种相对声明性和描述性结构，playbook 语言的表现力是有限的。然而，Ansible 并没有过分努力地模拟严格的声明性配置。Ansible plays 被建模为任务的顺序执行，仅受变量的影响。

有几种技巧可以允许您在 playbooks 中插入复杂的逻辑，以及一些稍后将看到的扩展点，可以让您实现您想要的内容。

## 扩展 Ansible

Ansible 提供了各种扩展点，可用于扩展 Ansible 并使其适应您的定制需求。它有四个主要入口点，您可以在其中放入您的代码：

+   **自定义事实脚本**：从远程主机收集自定义事实

+   **Ansible 模块**：实际基础设施更改的执行器

+   **插件**：扩展了 Ansible 执行生命周期

+   **Python API**：颠倒了控制并从您的自定义工具中利用了 Ansible 的部分功能

### 自定义事实脚本

动态清单可能提供有关基础设施以及其如何分组和管理的一些知识，但它并不提供有关实际事物状态的视图。

在每次 Ansible 运行之前，都会收集有关针对 playbook 执行的基础设施的事实。这收集了有关主机的大量信息，并且如果需要，可以在 Ansible playbook 本身中稍后使用。

但是，您可能会发现自己处于这样一个位置：作为事实收集过程的一部分收集的默认事实不够。为了解决这个问题，Ansible 允许您在事实收集阶段的一部分运行自定义代码，就在 Ansible 执行 play 之前。

### 模块

模块定义了可以在基础设施上执行的原始操作。它们允许您从 playbook 中精确描述要做什么。它们可以封装复杂的高级任务，例如与某些外部基础设施组件进行交互，并部署虚拟机或整个环境。

模块是定制 Ansible 的关键。模块可以用任何编程语言编写，并且如果合适，它们可以使用 Ansible 本身来执行其操作的细节。

本书的相当部分专门讨论了构建 Ansible 模块。

### 插件

术语**插件**将一些扩展点分组在一起，这些扩展点深入连接到 Ansible 核心，并以强大的方式扩展其行为。

目前可用的 Ansible 插件如下：

+   操作插件

+   回环插件

+   回调插件

+   连接插件

+   过滤器插件

+   Vars 插件

插件将在第四章“探索 API”和第五章“Ansible 插件深入研究”中详细介绍，您将在这里学习有关插件的所有必要知识，包括如何实现它们并构建自己的插件。

### Python API

Ansible Python API 允许您将 Ansible 用作库，从而可以从您的自定义配置管理解决方案（无论是什么）中直接使用 Ansible 擅长的东西。您可以以编程方式运行 Ansible playbooks。

Python API 也可以从其他 Ansible 扩展中使用；我们将在本书中突出重要部分。

# 总结

阅读完本章后，您可能会被诱惑将 Ansible 用作配置管理和编排工具。也许我们还给了您选择 Ansible 作为 IAC 解决方案的理由。本章向您介绍了 Ansible 及其功能和用例的简要介绍。它使您熟悉了 Ansible 架构、Ansible 的不同组件以及 Ansible 提供的各种扩展点。本章还带您了解了参与到一个 Ansible 项目的过程。

在下一章中，您将学习有关 Ansible 模块的知识。本章将带您了解在开始编写 Ansible 模块之前需要了解的内容，并指导您编写您的第一个模块。本章还将教您一些在开发 Ansible 模块时应遵循的最佳实践。此外，本章将为本书后面将涵盖的更高级主题奠定基础，其中包括您可以利用 Ansible 的力量的真实场景。


# 第二章：了解 Ansible 模块

Ansible 模块是可以使用 Ansible API 或通过 Ansible Playbook 调用的可重用代码片段。模块是 Ansible 的支柱。这些都是可以用任何语言编写的简单代码片段。

本章将介绍如何编写 Ansible 模块。本章分为四个部分：

+   编写你的第一个 Ansible 模块

+   模块编写助手

+   提供事实

+   测试和调试模块

# 编写你的第一个 Ansible 模块

Ansible 模块可以用任何语言编写，尽管在编写模块时需要遵守一些规定。具体如下：

+   模块必须只输出有效的 JSON。

+   模块应该是一个文件中自包含的，以便被 Ansible 自动传输。

+   尽量包含尽可能少的依赖项。如果存在依赖关系，请在模块文件顶部记录它们，并在导入失败时使模块引发 JSON 错误消息。

## 执行环境

要编写自己的 Ansible 模块，首先需要了解执行环境（即脚本将在何处以及如何执行）。

Ansible 在目标机器上执行脚本或播放。因此，您的脚本或已编译的二进制文件将被复制到目标机器上，然后执行。请注意，Ansible 只是简单地复制模块文件和生成的代码到目标机器上，并且不会尝试解决任何必要的依赖关系。因此，建议在您的 Ansible 模块文件中尽量包含尽可能少的依赖项。模块中的任何依赖关系都需要得到适当的记录，并在执行 Ansible 播放期间或之前进行处理。

## 步骤 1 - 模块放置

一旦您的模块文件准备好，您需要确切地知道应该将它放在哪里，以便在 Ansible 剧本中使用该模块。

您可以将您的模块放在 Ansible 寻找模块的不同位置：

+   在配置文件中由`library`变量指定的路径，位于`/etc/ansible/ansible.cfg`

+   由命令行中的`–module-path`参数指定的路径

+   在 Ansible 剧本的根目录下的`library`目录内

+   如果使用，位于角色的`library`目录内

## 编写基本的 Bash 模块

由于 Ansible 模块可以用任何语言编写，我们将首先尝试用 Bash 编写一个简单的 Ansible 模块。

我们将编写的第一个 Bash 模块将简单地检查目标机器的正常运行时间，并按照任何 Ansible 模块所需的格式返回输出。我们将命名该模块为`chkuptime`，并编写一个 playbook 来在目标机器上执行相同的模块。

该模块将被放置在 Ansible playbook 根目录中的`library`目录中，并将被 Ansible 自动包含。

以下是一个基本的 Bash 模块，用于检查目标机器的正常运行时间：

**Bash 模块代码**：(`library/chkuptime`)

```
#!/bin/bash

# The module checks for system uptime of the target machine.
# It returns a JSON output since an Ansible module should
# output a Valid JSON.

if [ -f "/proc/uptime" ]; then
    uptime=`cat /proc/uptime`
    uptime=${uptime%%.*}
    days=$(( uptime/60/60/24 ))
    hours=$(( uptime/60/60%24 ))
    uptime="$days days, $hours hours"
else
    uptime=""
fi

echo -e "{\"uptime\":\""$uptime"\"}"
```

为了让 Ansible 在执行 Ansible playbook 时包含上述模块代码，我们将其放在 Ansible playbook 根目录中的`library`目录中。

为了针对目标主机组运行这个模块，我们将创建一个名为`hosts`的清单文件，其中包括目标机器的分组列表。为了测试该模块，我们只对一个目标主机运行它。

现在，我们将创建一个 Ansible play 来执行新创建的模块。我们将 play 命名为`basic_uptime.yml`。

`basic_uptime.yml`

```
---
- hosts: remote
  user: rdas

  tasks:
    - name: Check uptime
      action: chkuptime
      register: uptime

    - debug: var=uptime
```

Playbook 的目录结构：

```
.
├── basic_uptime.yml
├── group_vars
├── hosts
├── library
│   └── chkuptime
└── roles
```

清单文件（`hosts`）

```
[remote]
192.168.122.191
```

现在，我们运行这个 play，它应该返回目标机器的正常运行时间：

```
**[rdas@localhost ]$ ansible-playbook -i hosts basic_uptime.yml**

**PLAY [remote] *******************************************************************

**GATHERING FACTS *****************************************************************
**ok: [192.168.122.191]**

**TASK: [Check uptime] ************************************************************
**ok: [192.168.122.191]**

**TASK: [debug var=uptime] ********************************************************
**ok: [192.168.122.191] => {**
 **"var": {**
 **"uptime": {**
 **"invocation": {**
 **"module_args": "",**
 **"module_name": "chkuptime"**
 **},**
 **"uptime": "0 days, 4 hours"**
 **}**
 **}**
**}**

**PLAY RECAP **********************************************************************
**192.168.122.191            : ok=3    changed=0    unreachable=0    failed=0** 

```

## 读取参数

如果你注意到上述模块，它不接受任何参数。让我们称这样的模块为`静态`模块。该模块在功能和行为上非常有限；否则，输出无法被改变。该模块将在目标机器上执行并返回固定的输出。如果用户期望以其他形式输出，这个模块就没有用了。该模块对用户没有灵活性。用户要想得到自己想要的输出，要么就得寻找这个模块的替代品（如果有的话），要么就得自己编写一个。

为了使模块更加灵活，它应该能够响应用户的要求，根据需要修改输出，或者至少提供用户可以与之交互的方式。这是通过允许模块接受参数来实现的。用户在运行时指定这些参数的值。

模块所期望的参数应该是明确定义的。参数也应该有良好的文档记录-既用于代码文档，也用于生成模块文档。参数类型和默认值（如果有）应该明确定义。

由于模块可以用任何语言编写，因此在代码级别上，Ansible 模块接受参数的方式可能不同。然而，无论模块是用什么语言编写的，从 Ansible playbook 传递参数的方式都保持不变。在 Bash 中，参数存储在按顺序编号的变量中。例如，第一个参数为$1，第二个参数为$2，依此类推。然而，参数类型和参数的默认值需要在代码中处理。Ansible 提供了一个 Python API，它提供了更好的处理参数的方式。它允许您明确定义参数的类型，强制要求参数，甚至为参数指定默认值。本章后面将介绍通过 Python API 处理参数。

我们将扩展上一个模块，以接受用户参数以更详细的格式打印系统运行时间。使用`detailed`标志，用户可以请求以完整的方式打印运行时间（即天，小时，分钟，秒），如果省略`detailed`标志，则保留先前的格式（即天，小时）。

以下是`chkuptime`模块的扩展，它根据用户指定的`detailed`标志返回输出：

**Bash 模块**：(`library/chkuptime`)

```
#!/bin/bash

# The module checks for system uptime of the target machine.
# The module takes in 'detailed' bool argument from the user
# It returns a JSON output since an Ansible module should
# output a Valid JSON.

source $1

if [ -f "/proc/uptime" ]; then
    uptime=`cat /proc/uptime`
    uptime=${uptime%%.*}
    days=$(( uptime/60/60/24 ))
    hours=$(( uptime/60/60%24 ))
    if [ $detailed ]; then
        minutes=$(( uptime/60%60 ))
        seconds=$(( uptime%60 ))
        uptime="$days days, $hours hours, $minutes minutes, $seconds seconds"
    else
        uptime="$days days, $hours hours"
    fi
else
    uptime=""
fi

echo -e "{\"uptime\":\""$uptime"\"}"
```

在 Ansible play 中唯一需要更改的是在调用模块时传递一个 Bool 类型的`detailed`参数。

Ansible Play `(uptime_arg.yml)`

```
---
- hosts: remote
  user: rdas

  tasks:
    - name: Check uptime
      action: chkuptime detailed=true
      register: uptime

- debug: var=uptime
```

执行 play 后，我们得到以下输出：

```
**[rdas@localhost bash-arg-example]$ ansible-playbook -i hosts uptime_arg.yml**
**PLAY [remote] *******************************************************************

**GATHERING FACTS *****************************************************************
**ok: [192.168.122.191]**

**TASK: [Check uptime] ************************************************************
**ok: [192.168.122.191]**

**TASK: [debug var=uptime] ********************************************************
**ok: [192.168.122.191] => {**
 **"var": {**
 **"uptime": {**
 **"invocation": {**
 **"module_args": "detailed=true",**
 **"module_name": "chkuptime"**
 **},**
 **"uptime": "1 days, 2 hours, 2 minutes, 53 seconds"**
 **}**
 **}**
**}**

**PLAY RECAP **********************************************************************
**192.168.122.191            : ok=3    changed=0    unreachable=0    failed=0** 

```

如果将输出与上一个 Ansible play 的输出进行比较，现在的运行时间包括了分钟和秒，而在上一个示例中是缺少的。通过设置`detailed`标志为 false，也可以使用新模块来实现先前的输出。

## 处理错误

您已经学会了如何创建自定义模块和读取用户输入。由于模块旨在在目标机器上执行某些功能，有时可能会失败。失败的原因可能是从目标机器上的权限问题到无效的用户输入，或其他任何原因。无论原因是什么，您的模块都应该能够处理错误和失败，并返回带有适当信息的错误消息，以便用户了解根本原因。所有失败都应该通过在返回数据中包含`failed`来明确报告。

例如，让我们创建一个简单的模块，接受用户输入的进程名称，并返回指定服务是否在目标机器上运行。如果服务正在运行，它将简单地返回一个包含请求进程的进程 ID 的消息。如果没有，它将通过将`failed`设置为`true`来明确失败模块执行。

以下是一个包含`failed`在返回数据中并明确失败模块执行的示例模块：

模块`library/chkprocess`

```
#!/bin/bash

# This module checks if the pid of the specified
# process exists. If not, it returns a failure msg

source $1

pid=`pidof $process`
if [[ -n $pid ]]; then
    printf '{
        "msg" : "%s is running with pid %s",
        "changed" : 1
    }' "$process" "$pid"
else
    printf '{
        "msg" : "%s process not running",
        "failed" : "True"
    }' "$process"
fi
```

**Ansible play** `chkprocess.yml`

```
---
- hosts: remote
  user: rdas

  tasks:
    - name: Check if process running
      action: chkprocess process=httpd
      register: process

    - debug: msg="{{ process.msg }}"
```

正如您所看到的，我们将检查指定的`httpd`进程是否在目标主机上运行。如果没有，这应该会导致 Ansible 运行失败。

现在让我们执行针对目标机器的 Ansible play：

```
**[rdas@localhost process-bash]$ ansible-playbook -i hosts chkprocess.yml**
**PLAY [remote] *******************************************************************

**GATHERING FACTS *****************************************************************
**ok: [192.168.122.191]**

**TASK: [Check if process running] ************************************************
**failed: [192.168.122.191] => {"failed": "True"}**
**msg: httpd process not running**

**FATAL: all hosts have already failed -- aborting**

**PLAY RECAP **********************************************************************
 **to retry, use: --limit @/home/rdas/chkprocess.retry**

**192.168.122.191            : ok=1    changed=0    unreachable=0    failed=1** 

```

正如您可能注意到的，由于`httpd`进程未在目标主机上运行，Ansible 按照请求失败了运行。此外，还显示了一个有意义的消息，以通知用户失败的根本原因。

# 在 Python 中创建 Ansible 模块

在这一点上，您已经熟悉了编写 Ansible 模块的基本概念。我们还讨论了一些用 Bash 编写的示例 Ansible 模块。

虽然可以用任何语言编写 Ansible 模块，但 Ansible 为用 Python 编写的模块提供了更友好的环境。

在不同语言中编写模块时，如上所述，处理参数、处理失败、检查输入等任务都是在模块代码中处理的。在 Python 中，Ansible 提供了一些辅助工具和语法糖来执行常见任务。例如，您不需要像在之前的示例中所示的那样解析参数。

Ansible 提供的常见例程能够处理返回状态、错误、失败和检查输入。这种语法糖来自 AnsibleModule 样板。使用 AnsibleModule 样板，您可以以更高效的方式处理参数和返回状态。这将帮助您更多地集中精力在模块上，而不必对输入进行明确的检查。

让我们更好地理解 AnsibleModule 样板。

## AnsibleModule 样板

为了从 AnsibleModule 样板中受益，您只需要导入`ansible.module_utils.basic`。

将导入放在文件末尾，并确保您的实际模块主体包含在传统的`main`函数中。

AnsibleModule 样板还为模块参数提供了一种规范语言。它允许您指定参数是可选的还是必需的。它还处理了一些数据类型，如枚举。

在下面的代码中，模块接受一个强制参数`username`，由设置`required=True`指定：

```
    module = AnsibleModule(
        argument_spec = dict(
            username = dict(required=True)
        )
    )   
    username = module.params.get('username')
    module.exit_json(changed=True, msg=str(status))
```

对象`module`使用一个常见的函数`exit_json`，它返回`true`并向 Ansible 返回一个成功消息。`module`对象提供了一组常见的函数，例如：

+   `run_command`：此函数运行外部命令并获取返回代码，`stdout`，`stderr`

+   `exit_json`：此函数向 Ansible 返回一个成功消息

+   `fail_json`：此函数返回一个失败和错误消息给 Ansible

参数可以通过`module.params`实例变量访问。每个参数都将有一个键值对。

`AnsibleModule`助手，在解析参数时，将执行一系列验证和请求类型转换。参数规范字典描述了模块的每个可能的参数。参数可以是可选的或必需的。可选参数可以有默认值。此外，可以使用`choice`关键字限制特定参数的可能输入。

# 模块文档

如果你正在编写一个模块，正确地记录它是非常重要的。文档是对模块功能更好理解所必需的。建议始终记录一个模块。

你所需要做的就是在你的模块文件中包含一个`DOCUMENTATION`全局变量，如下面的代码所示。该变量的内容应该是有效的 YAML。

```
DOCUMENTATION = """
---
module: chkuser
version_added: 0.1
short_description: Check if user exists on the target machine
options:
    username:
        decription:
            - Accept username from the user
        required: True
"""
```

可以使用`ansible-doc`命令阅读此文档。不幸的是，目前这仅适用于基于 Python 的模块。

除了详细说明每个选项的文档外，还可以提供一些可能涵盖模块的一些基本用例的示例。这可以通过添加另一个名为`EXAMPLES`的全局变量来完成。

```
EXAMPLES = """
#Usage Example
    - name: Check if user exists
      action: chkuser username=rdas
"""
```

让我们在一个检查目标机器上的用户是否存在的 Ansible 模块中实现 AnsibleModule 样板和上述文档。

以下是一个使用 AnsibleModule 样板构建的示例 Ansible 模块`chkuser`。该模块还包含模块文档以及使用示例：

**模块名称**：`chkuser`

```
#!/bin/python

DOCUMENTATION = """
---
module: chkuser
version_added: 0.1
short_description: Check if user exists on the target machine
options:
    username:
        decription:
            - Accept username from the user
        required: True
"""

EXAMPLES = """
#Usage Example
    - name: Check if user exists
      action: chkuser username=rdas
"""

def is_user_exists(username):
    try:
        import pwd
        return(username in [entry.pw_name for entry in pwd.getpwall()])
    except:
        module.fail_json(msg='Module pwd does not exists')

def main():
    module = AnsibleModule(
        argument_spec = dict(
            username = dict(required=True)
        )
    )   
    username = module.params.get('username')
    exists = is_user_exists(username)
    if exists:
        status = '%s user exists' % username
    else:
        status = '%s user does not exist' % username
    module.exit_json(changed=True, msg=str(status))

from ansible.module_utils.basic import *
main()
```

要使用这个模块，我们创建一个 Ansible play，将用户名作为参数传递给`chkuser`模块，如下面的代码所示：

**Ansible Play**：`chkuser.yml`

```
---
- hosts: remote
  user: rdas

  tasks:
    - name: Check if user exists
      action: chkuser username=rdas
      register: user

debug: msg="{{ user.msg }}
```

对目标机器执行 play 会返回一条消息，说明查询的用户是否存在于目标机器上。

# 测试和调试模块

编写模块很容易，但仅仅开发一个模块是不够的。您需要测试模块是否在所有情况下都能按预期执行所有操作。

第一次尝试很难成功。在工作时尝试一些东西是一种常见的技巧。这是为什么动态编程和具有短编辑和执行周期的编程环境变得非常流行的主要原因之一。

下一节，*快速本地执行*，涉及到在尽可能与您的 Ansible 环境隔离的情况下运行您的模块的问题。这在早期开发和调试过程中非常有帮助。

# 快速本地执行

在开发模块时，您可能希望缩短编辑/运行周期，并跳过实际通过 Ansible 执行模块的开销。正如我们在之前的 Bash 示例中看到的那样，执行环境非常简单，直接运行脚本直到正确是非常直接的。

然而，使用 AnsibleModule 样板的 Python 模块会变得更加棘手。

Ansible 在 Python 脚本的幕后进行了一些黑魔法，以便不需要在目标机器上安装 Ansible 组件。您可以通过采用两个简单的技巧来探索这种技术：

```
#!/bin/python

import sys

def main():
    module = AnsibleModule(
        argument_spec = dict()
    )
    f = open('/tmp/magicmirror', 'w')
    print >>f, file(sys.argv[0]).read()
    module.exit_json(changed=True)

from ansible.module_utils.basic import *
main()
```

在本地执行此模块将生成文件`/tmp/magicmirror`，其中包含已经通过对 Ansible 运行时进行了增强的代码。这使您能够从共享功能中受益，并避免在目标机器上引入依赖项。

另一种方法是在控制主机上设置环境变量`ANSIBLE_KEEP_REMOTE_FILES=1`，以防止 Ansible 清理远程机器，不删除生成的 Ansible 脚本，然后可以用于调试您的模块。

# 最佳实践

通过遵循一些最佳实践，模块始终可以在开发过程中得到改进。这有助于在需要时保持模块的卫生和易于理解和扩展。应该遵循的一些最佳实践包括：

+   模块必须是自包含的

+   将依赖项减少到最低限度

+   在`msg`键中写入错误原因

+   尽量只返回有用的输出

开发模块最重要的部分是不要忘记它应该返回有效的 JSON。

# 总结

在本章中，您学习了编写模块的基础知识。您了解了模块的放置位置以及在开发自定义模块时需要牢记的事项。您学习了如何在 Bash 中编写模块，并了解了 AnsibleModule 样板，因此最终开发了在 Bash 和 Python 中的示例 Ansible 模块。本章还涵盖了应该遵循的最佳实践。

在下一章中，您将了解错误处理，并通过一个真实场景，您可以创建一个 Ansible 模块并利用 Ansible 的强大功能。下一章还将涵盖一些复杂的数据结构与 Ansible。


# 第三章：深入了解 Ansible 模块

已经学习了基础知识，本章将带您深入了解 Ansible 的更高级主题，例如：

+   使模块支持在干扰模式下安全执行

+   了解如何在 Ansible 模块中解析参数

+   处理复杂参数和数据结构

+   一个现实生活场景，您可以利用 Ansible 的强大功能创建一个定制模块以满足您的需求

# 干扰（检查模式）

因此，您决定编写自己的模块，根据用户输入对系统进行一些配置更改。考虑到代码必须在生产环境中运行，能够运行尚未发布的配置的模拟非常重要。您不仅可能希望在应用它们之前知道您的配置是否正确，而且您可能还想了解 Playbook 执行将涉及哪些更改。

由于 Ansible 不知道模块执行的后果，它只是按照 Playbook 的指示。在干扰模式下，它将简单地打印出所有它将执行的模块并跳过实际执行。如果模块不支持检查模式，则在执行期间检查模式下简单地跳过该模块。

模块对系统状态或目标机器的任何更改的详细信息很有用。但是，Ansible 只能通过要求模块执行模拟并返回状态更改确认来了解这一点。您的 Ansible Playbook 中可能有一些任务使用一些返回输出的模块。这些可能存储在变量中，并且后续模块执行取决于它们。

为了告诉 Ansible 模块支持检查模式并且可以在干扰模式下安全运行，只需在 Ansible 模块中将`supports_check_mode`标志设置为 true。可以按如下方式完成：

```
module = AnsibleModule(
    argument_spec = dict(
        # List of arguments
    ),  
    supports_check_mode = True
)
```

模块中的前述代码使模块能够以干扰模式执行。您可以使用以下命令在检查模式下运行您的 Ansible Playbook：

```
**ansible-playbook playook.yml --check**

```

这将对所有支持检查模式的模块进行干扰，并在不实际进行更改的情况下报告目标机器上可能进行的任何更改。

# 加载模块

在深入编写 Ansible 模块之前，有必要了解 Ansible 在运行时如何加载模块。了解模块如何加载到 Ansible 中可以让你理解代码流程并调试可能在运行时发生的问题。要理解这一点，你必须了解 Ansible playbook 是如何执行的。

正如你已经知道的，Ansible playbooks 是使用`ansible-playbook`二进制文件执行的，它接受一些参数，如清单文件和要运行的 Ansible play。如果你查看`ansible-playbook`的源代码，你会注意到以下导入：

```
import ansible.constants as C
```

`constants.py`文件是将配置加载到 Ansible 中的主要文件之一。它包含各种配置，如模块和插件将被加载到 Ansible 的默认路径。

这个文件负责定义 Ansible 加载配置的顺序。配置加载到 Ansible 中的默认顺序是：

1.  **ENV**：环境变量。

1.  **CWD**：当前工作目录（执行 Ansible playbook 的目录）。

1.  **主页**：然后从用户的主目录中的配置文件中加载配置。此配置文件名为`~/.ansible.cfg`。

1.  **全局配置文件**：Ansible 将全局配置文件放在`/etc/ansible/ansible.cfg`中。

Ansible 使用在前述顺序中找到的配置。

该文件还设置了一些默认配置值，这些值对于 Ansible 执行 playbook 是必需的。其中一些默认配置值是：

+   `forks`：默认的 forks 数量设置为`5`

+   `remote_user`：这个值设置为控制节点上的活动用户

+   `private_key_file`：设置要用于与目标主机通信的默认私钥

+   `Timeout`：默认值设置为`10`

# 利用 Ansible

上一章介绍了`AnsibleModule`的样板，它允许你编写自己的 Ansible 模块，接受参数并返回结果。在继续开发 Ansible 模块之前，本节将从代码层面详细探讨`AnsibleModule`的样板。

## 深入了解 AnsibleModule 样板

正如在前一章中讨论的那样，`AnsibleModule`的样板可以通过简单地导入`ansible.module_utils.basic`语句来使用。

一旦为`AnsibleModule`类创建了对象，对象的一些属性就会被设置，包括在创建`AnsibleModule`对象时指定的`argument_spec`属性。默认情况下，`supports_check_mode`属性设置为`false`，`check_invalid_arguments`设置为`true`。

`AnsibleModule`类使用`load_params`方法将参数和参数加载到`params`变量中。以下是`load_params`方法的源代码：

```
def _load_params(self):
    ''' read the input and return a dictionary and the arguments string '''
    args = MODULE_ARGS
    items   = shlex.split(args)
    params = {}
    for x in items:
        try:
            (k, v) = x.split("=",1)
        except Exception, e:
            self.fail_json(msg="this module requires key=value arguments (%s)" % (items))
        if k in params:
            self.fail_json(msg="duplicate parameter: %s (value=%s)" % (k, v))
        params[k] = v
    params2 = json_dict_unicode_to_bytes(json.loads(MODULE_COMPLEX_ARGS))
    params2.update(params)
    return (params2, args)
```

正如您所看到的，`params`是一个字典。Python 允许您使用`get`方法从字典中读取与键对应的值。因此，如果您需要访问任何参数，可以简单地在`params`字典变量上使用`get`方法。这就是 Ansible 读取和接受模块中的参数的方式。

现在您已经学会了如何开发模块，接受参数并处理错误，让我们在实际情况中实现这些知识。

所以，假设您拥有一个庞大的基础架构，一切都运行良好。您已经有一个很好的配置管理系统，以及一个监控系统，可以跟踪所有机器的情况，并在发生故障时通知您。一切都很顺利，直到有一天，您需要审计您的基础架构。您需要每台机器的详细信息，比如 BIOS 详细信息、制造商和序列号等系统规格。

一种简单的解决方案是在每台机器上运行`dmidecode`并整理收集到的数据。嗯，在单独的机器上运行`dmidecode`并整理细节是一件麻烦的事情。让我们利用 Ansible 的力量来处理这种情况。

学会了如何创建模块后，您可以使用 Python 库`dmidecode`并编写自己的模块，然后在整个基础架构上运行。额外的好处是您可以将数据以机器可解析的形式，比如 JSON，保存下来，以后可以用来生成报告。

让我们将模块命名为`dmidecode`，并将其放在 Ansible 剧本根目录中的`library`目录中。以下是`dmidecode`模块的源代码：

```
import dmidecode
import json

def get_bios_specs():
    BIOSdict = {}
    BIOSlist = []
    for item in dmidecode.bios().values():
        if type(item) == dict and item['dmi_type'] == 0:
            BIOSdict["Name"] = str((item['data']['Vendor']))
            BIOSdict["Description"] = str((item['data']['Vendor']))
            BIOSdict["BuildNumber"] = str((item['data']['Version']))
            BIOSdict["SoftwareElementID"] = str((item['data']['BIOS Revision']))
            BIOSdict["primaryBIOS"] = "True"
            BIOSlist.append(BIOSdict)
    return BIOSlist

def get_proc_specs():
    PROCdict = {}
    PROClist = []
    for item in dmidecode.processor().values():
        if type(item) == dict and item['dmi_type'] == 4:
            PROCdict['Vendor'] = str(item['data']['Manufacturer']['Vendor'])
            PROCdict['Version'] = str(item['data']['Version'])
            PROCdict['Thread Count'] = str(item['data']['Thread Count'])
            PROCdict['Characteristics'] = str(item['data']['Characteristics'])
            PROCdict['Core Count'] = str(item['data']['Core Count'])
            PROClist.append(PROCdict)
    return PROClist

def get_system_specs():
    SYSdict = {}
    SYSlist = []
    for item in dmidecode.system().values():
        if item['dmi_type'] == 1:
            SYSdict['Manufacturer'] = str(item['data']['Manufacturer'])
            SYSdict['Family'] = str(item['data']['Family'])
            SYSdict['Serial Number'] = str(item['data']['Serial Number'])
            SYSlist.append(SYSdict)
    return SYSlist

def main():
    module = AnsibleModule(
        argument_spec = dict(
            save = dict(required=False, default=False, type='bool'),
        )
    )
    # You can record all data you want. For demonstration purpose, the #example records only the first record.
    dmi_data = json.dumps({
        'Hardware Specs' : {
            'BIOS' : get_bios_specs()[0],
            'Processor' : get_proc_specs()[0],
            'System' : get_system_specs()[0]
        }
    })
    save = module.params.get('save')
    if save:
        with open('dmidecode.json', 'w') as dfile:
            dfile.write(str(dmi_data))
    module.exit_json(changed=True, msg=str(dmi_data))

from ansible.module_utils.basic import *
main()
```

正如您所看到的，我们正在收集处理器规格、BIOS 规格和系统规格等数据；您可以根据个人需求随时扩展模块。

该模块接受来自用户的布尔参数`save`，如果设置为`true`，将把结果写入远程机器上的 JSON 文件。

您可能会注意到模块在开头有一个导入行`import dmidecode`。该语句导入了`dmidecode` Python 库。该库由`python-dmidecode`软件包提供。由于模块依赖于`dmidecode` Python 库，因此需要在目标机器上安装该库。这可以在 Ansible playbook 中处理。

依赖项可以在`global_vars`文件中指定，并且可以在 Ansible playbook 中使用变量名。这样做是为了防止在依赖项发生更改时对 Ansible play 进行更改。可以在`global_vars`目录中指定如下：

`global_vars/all`

```
# Dependencies
dependencies:
    - python-dmidecode
    - python-simplejson
```

因此，Ansible 模块已准备就绪，并且依赖项已得到处理。现在，您需要创建 Ansible play，该 play 将在目标机器上执行`dmidecode`模块。让我们将 Ansible 命名为`play dmidecode.yml`。

```
---
- hosts: remote
  user: root

  tasks:
    - name: Install dependencies
      yum: name={{ item }} state=latest
      with_items:
        - "{{ dependencies }}"

    - name: Test dmidecode
      action: dmidecode save=True
      register: dmi_data

   - debug: var=dmi_data['msg']
```

执行 Ansible playbook 将在远程主机组上运行`dmidecode`模块。由于`save`设置为`true`，这将在远程主机上创建一个包含所需信息的`dmidecode.json`文件。

# 复杂参数

由于 Ansible 模块只是另一种可以接受和解析参数的代码，可能会有一个问题，即它是否能够处理复杂的变量集。尽管 Ansible 用作部署、编排和配置管理工具，但它设计用于处理简单参数，仍然能够处理复杂变量。这是一个高级主题，由于通常不使用，本节将简要介绍它。

您已经学会了如何向 Ansible 模块传递参数。但是，复杂参数的处理方式不同。

## 读取复杂参数

让我们以复杂变量`complex_var`为例，通常情况下，我们在`group_vars/all`中定义它。

```
# Complex Variable
complex_var:
    key0: value0
    key1:
      - value1
      - value2
```

前面的变量是字典类型（即键值对）。为了使 Ansible 模块解析这种类型的参数，我们需要对模块中传递复杂变量的方式和它们的解析方式进行一些更改。我们编写一个自定义模块，接受这个复杂变量作为参数，并打印与关联键对应的值。我们将该模块命名为`complex`。

以下是`complex.py`模块的代码：

**Ansible 模块：** `library/complex.py`

```
#!/usr/bin/python

def main():
    module = AnsibleModule(
        argument_spec = dict(
            key0 = dict(required=True),
            key1 = dict(required=False, default=[])
        )
    )
    module.exit_json(changed=False, out='%s, %s' %
        (module.params['key0'], module.params['key1']))

from ansible.module_utils.basic import *
main()
```

前面的模块接受复杂变量并打印它们对应的键的关联值。复杂变量如何传递给 Ansible 模块在 Ansible play 中指定。

以下是 Ansible playbook，它接受复杂参数并将它们传递给复杂模块：

**Ansible play:** `complex.yaml`

```
---
- hosts: localhost
  user: rdas

  tasks:
    - name: print complex variable key values
      action: complex
      args: '{{ complex_var }}'
      register: res

    - debug: msg='{{res.out}}'
```

当执行 Ansible playbook 时，分别打印与键`key0`和`key1`关联的值。

# 总结

在本章中，您了解了如何通过引入`supports_check_mode`标志使您的模块支持干运行。您还了解了在 Ansible 中如何处理参数。本章涵盖了一个真实场景，其中使用自定义 Ansible 模块对基础设施进行硬件审计。本章还简要介绍了如何在 Ansible 中处理复杂变量。

在下一章中，您将了解 Ansible 插件，为什么它们是必需的，以及它们如何适用于一般的 Ansible 结构。本章还将介绍 Python 插件 API。


# 第四章：探索 API

Ansible 插件是一个高级话题。有各种插件可用于 Ansible。本章将简要介绍不同的 Python API 和查找插件，并探讨它们如何适应通用的 Ansible 架构。

Ansible 在很多方面都是可插拔的。可能存在一些业务逻辑组件不太适合的情况。因此，Ansible 提供了可以用于满足您业务需求的扩展点。Ansible 插件是另一个这样的扩展点，您可以构建自己的插件来扩展 Ansible 以满足您的业务逻辑。

# Python API

在探索插件之前，了解 Ansible Python API 很重要。Ansible Python API 可用于以下用途：

+   控制节点

+   响应各种 Python 事件

+   根据需求编写各种插件

+   还可以将来自各种外部数据存储的清单数据插入其中

Ansible 的 Python API 允许以编程方式运行 Ansible。通过 Python API 以编程方式运行 Ansible 具有以下优势：

+   **更好的错误处理**：由于一切都是 Python，因此很容易在发生错误时进行处理。这样可以通过提供更好的上下文，在发生错误时更好地控制和信心。

+   **扩展 Ansible**：正如您在之前的运行中可能已经注意到的，一个缺点是，默认情况下，Ansible 只是将输出写入`stdout`，并不会将任何内容记录到文件中。为了解决这个问题，您可以编写自己的自定义插件，将输出保存到文件或数据库以供将来参考。

+   **未知变量**：可能存在只有在运行时才能完全了解所需变量的情况，例如，在 Ansible 执行期间在云上启动实例的 IP。使用 Python API 以编程方式运行 Ansible 可以解决这个问题。

现在您已经了解了使用 Python API 进行 Ansible 的优势，让我们来探索 Python API，并看看如何通过 API 与 Ansible 进行交互。

本章将介绍三个最重要的广泛使用的类：

+   **Runner**：用于执行单个模块

+   **Playbook**：帮助执行 Ansible playbook

+   **回调**：在控制节点上获取运行结果

让我们深入了解这些类是什么，并探索各种扩展点。

## Runner

`runner`类是 Ansible 的核心 API 接口。`runner`类用于执行单个模块。如果有一个需要执行的单个模块，例如`setup`模块，我们可以使用`runner`类来执行此模块。

### 提示

可以在同一个 Python 文件中有多个`runner`对象来运行不同的模块。

让我们来探索一个示例代码，其中`runner`类将用于在本地主机上执行`setup`模块。这将打印有关本地主机的许多详细信息，例如时间、操作系统（发行版）、IP、子网掩码以及硬件详细信息，例如架构、空闲内存、已用内存、机器 ID 等等。

```
from ansible import runner

runner = runner.Runner(
    module_name = 'setup',
    transport = 'local'
)

print runner.run()
```

这将在本地主机上执行`setup`模块。这相当于运行以下命令：

```
**ansible all -i "localhost," -c local -m setup**

```

要在远程主机或一组主机上运行上述模块，可以在清单中指定主机，然后将其作为参数传递给`runner`对象，以及应用于登录远程机器的远程用户。您还可以指定主机的模式，特别是需要执行模块的主机。这是通过将模式参数传递给`runner`对象来完成的。

### 提示

您还可以使用`module_args`键传递模块参数。

例如，如果您需要获取设置为`store1.mytestlab.com`、`store2.mytestlab.com`、`store12.mytestlab.com`等的远程主机的内存详细信息，可以简单地以以下方式实现：

```
from ansible import runner

runner = runner.Runner(
    module_name = 'setup',
    pattern = 'store*',
    module_args = 'filter=ansible_memory_mb'
)

print runner.run()
```

上述代码将在所有十二个主机上执行`setup`模块，并打印每个主机可访问的内存状态。可访问的主机将列在“contacted”下，而不可访问的主机将列在“dark”下。

除了上面讨论的参数外，`runner`类通过其接受的参数提供了大量的接口选项。以下是源代码中定义的一些参数及其用途的列表：

| 参数/默认值 | 描述 |
| --- | --- |
| `host_list=C.DEFAULT_HOST_LIST` | 示例：`/etc/ansible/hosts`，传统用法 |
| `module_path=None` | 示例：`/usr/share/ansible` |
| `module_name=C.DEFAULT_MODULE_NAME` | 示例：`copy` |
| `module_args=C.DEFAULT_MODULE_ARGS` | 示例："`src=/tmp/a dest=/tmp/b`" |
| `forks=C.DEFAULT_FORKS` | 并行级别 |
| `timeout=C.DEFAULT_TIMEOUT` | SSH 超时 |
| `pattern=C.DEFAULT_PATTERN` | 哪些主机？示例："all" `acme.example.org` |
| `remote_user=C.DEFAULT_REMOTE_USER` | 例如：“`username`” |
| `remote_pass=C.DEFAULT_REMOTE_PASS` | 例如：“`password123`”或使用密钥时为“`None`” |
| `remote_port=None` | 如果 SSH 在不同的端口上 |
| `private_key_file=C.DEFAULT_PRIVATE_KEY_FILE` | 如果不使用密钥/密码 |
| `transport=C.DEFAULT_TRANSPORT` | “`SSH`”，“`paramiko`”，“`Local`” |
| `conditional=True` | 仅在此事实表达式评估为`true`时运行 |
| `callbacks=None` | 用于输出 |
| `sudo=False` | 是否运行 sudo |
| `inventory=None` | 对清单对象的引用 |
| `environment=None` | 在命令内部使用的环境变量（作为`dict`） |
| `complex_args=None` | 除了`module_args`之外的结构化数据，必须是`dict` |

## Playbook

正如您在之前的章节中学到的那样，Playbook 是以 YAML 格式运行的一系列指令或命令。Ansible 的 Python API 提供了一个丰富的接口，通过`PlayBook`类运行已创建的 playbooks。

您可以创建一个`PlayBook`对象，并将现有的 Ansible playbook 作为参数传递，以及所需的参数。需要注意的一点是，多个 play 不会同时执行，但是 play 中的任务可以根据请求的 forks 数量并行执行。创建对象后，可以通过调用`run`函数轻松执行 Ansible playbook。

您可以创建一个`Playbook`对象，稍后可以使用以下模板执行：

```
pb = PlayBook(
    playbook = '/path/to/playbook.yaml',
    host_list = '/path/to/inventory/file',
    stats = 'object/of/AggregateStats',
    callbacks = 'playbookCallbacks object',
    runner_callbacks = 'callbacks/used/for/Runner()'
)
```

这里需要注意的一件事是，`PlayBook`对象需要至少传递四个必需的参数。这些是：

+   `playbook`：Playbook 文件的路径

+   `stats`：保存每个主机发生的事件的聚合数据

+   `callbacks`：Playbook 的输出回调

+   `runner_callbacks`：`runner` API 的回调

您还可以在`0`-`4`的范围内定义详细程度，这是`callbacks`和`runner_callbacks`对象所需的。如果未定义详细程度，则默认值为`0`。将详细程度定义为`4`相当于在命令行中执行 Ansible playbook 时使用`-vvvv`。

例如，您有名为`hosts`的清单文件和名为`webservers.yaml`的 playbook。要使用 Python API 在清单主机上执行此 playbook，您需要创建一个带有所需参数的`PlayBook`对象。您还需要要求详细输出。可以按以下方式完成：

```
from ansible.playbook import PlayBook
from ansible import callbacks
VERBOSITY = 4
pb = PlayBook(
    playbook = 'webservers.yaml',
    host_list = 'hosts',
    stats = callbacks.AggregateStats(),
    callbacks = callbacks.PlaybookCallbacks(verbose=VERBOSITY),
    runner_callbacks = callbacks.PlaybookRunnerCallbacks(
                        callbacks.AggregateStats(),
                        verbose=VERBOSITY)
)

pb.run()
```

这将在 `hosts` 清单文件中指定的远程主机上执行 `webservers.yaml` playbook。

要在本地执行相同的 playbook，就像之前在 `runner` 对象中所做的那样，您需要在 `PlayBook` 对象中传递参数 `transport=local` 并删除 `host_list` 参数。

除了讨论过的参数，PlayBook 还接受更多。 

以下是 `PlayBook` 对象接受的所有参数列表，以及它们的目的：

| 参数 | 描述 |
| --- | --- |
| `playbook` | playbook 文件的路径 |
| `host_list` | 文件的路径，如 `/etc/ansible/hosts` |
| `module_path` | Ansible 模块的路径，如 `/usr/share/ansible/` |
| `forks` | 期望的并行级别 |
| `timeout` | 连接超时 |
| `remote_user` | 如果在特定 play 中未指定，则以此用户身份运行 |
| `remote_pass` | 使用此远程密码（对所有 play）而不是使用 SSH 密钥 |
| `sudo_pass` | 如果 `sudo=true` 并且需要密码，则为 sudo 密码 |
| `remote_port` | 如果在主机或 play 中未指定，默认的远程端口 |
| `transport` | 如何连接未指定传输方式的主机（本地，paramiko 等） |
| `callbacks` | playbook 的输出回调 |
| `runner_callbacks` | 更多的回调，这次是为 runner API |
| `stats` | 包含关于每个主机发生的事件的聚合数据 |
| `sudo` | 如果没有在每个 play 中指定，请求所有 play 使用 `sudo` 模式 |
| `inventory` | 可以指定而不是 `host_list` 来使用预先存在的清单对象 |
| `check` | 不要更改任何内容；只是尝试检测一些潜在的更改 |
| `any_errors_fatal` | 当其中一个主机失败时立即终止整个执行 |
| `force_handlers` | 即使任务失败，仍然通知并运行处理程序 |

## 回调

Ansible 提供了在主机上运行自定义回调的钩子，因为它调用各种模块。回调允许我们记录已启动或已完成的事件和操作，并从模块执行中聚合结果。Python API 提供了用于此目的的回调，可以在其默认状态下使用，也可以用来开发自己的回调插件。

回调允许执行各种操作。回调也可以被利用作为 Ansible 的扩展点。在 Python API 中包装 Ansible 时，一些最常用的回调操作是：

+   `AggregateStats`：顾名思义，`AggregateStats`保存了在剧本运行期间围绕每个主机活动的汇总统计信息。`AggregateStats`的对象可以作为`PlayBook`对象中`stats`的参数传递。

+   `PlaybookRunnerCallbacks`：`PlaybookRunnerCallbacks`的对象用于`Runner()`，例如，当使用`Runner` API 接口执行单个模块时，将使用`PlaybookRunnerCallbacks`返回任务状态。

+   `PlaybookCallbacks`：`PlaybookCallbacks`的对象由 Python API 的 playbook API 接口在从 Python API 执行 playbook 时使用。这些回调被`/usr/bin/ansible-playbook`使用。

+   `DefaultRunnerCallbacks`：当没有为`Runner`指定回调时，将使用`DefaultRunnerCallbacks`。

+   `CliRunnerCallbacks`：这扩展了`DefaultRunnerCallbacks`并覆盖了事件触发函数，基本上优化用于`/usr/bin/ansible`。

# Ansible 插件

插件是本书尚未涉及的另一个扩展点。此外，即使在互联网上，关于插件的文档也非常有限。

插件是下一章将涵盖的一个高级主题。然而，了解插件背后的 Python API 是很重要的，以便了解插件的工作原理以及如何扩展插件。

## PluginLoader

正如代码文档所述，`PluginLoader`是从配置的插件目录加载插件的基类。它遍历基于播放的目录列表、配置的路径和 Python 路径，以搜索插件。第一个匹配项被使用。

`PluginLoader`的对象接受以下参数：

+   `class_name`：插件类型的特定类名

+   `required_base_class`：插件模块所需的基类

+   `package`：包信息

+   `config`：指定配置的默认路径

+   `subdir`：包中的所有子目录

+   `aliases`：插件类型的替代名称

对于每个 Ansible 插件，都有一个定义的类名需要使用。在`PluginLoader`中，这个类由`required_base_class`标识。Ansible 插件的不同类别以及它们的基本名称列在下表中：

| 插件类型 | 类名 |
| --- | --- |
| 动作插件 | `ActionModule` |
| 缓存插件 | `CacheModule` |
| 回调插件 | `CallbackModule` |
| 连接插件 | `Connection` |
| Shell 插件 | `ShellModule` |
| 查找插件 | `LookupModule` |
| 变量插件 | `VarsModule` |
| 过滤器插件 | `FilterModule` |
| 测试插件 | `TestModule` |
| 策略插件 | `StrategyModule` |

# 总结

本章带您了解了 Ansible 的 Python API，并向您介绍了更高级的使用 Ansible 的方法。这包括执行单个任务而不创建整个 playbook，以及以编程方式执行 playbook。

本章还从技术角度向您介绍了 Ansible Python API 的各种组件，探索了各种扩展点和利用它们的方法。

本章还为下一章奠定了基础，下一章将深入探讨 Ansible 插件。下一章将利用本章所学知识来创建自定义的 Ansible 插件。我们将在接下来的章节中探索不同的 Ansible 插件，并指导您编写自己的 Ansible 插件。


# 第五章：深入了解 Ansible 插件

前一章向您介绍了 Python API 以及 Ansible 提供的各种扩展点。当您到达本章时，您应该已经知道 Ansible 如何加载插件。前一章列出了不同类型的 Ansible 插件。

本章深入探讨了 Ansible 插件是什么，以及如何编写自定义的 Ansible 插件。在本章中，我们将详细讨论不同类型的 Ansible 插件，并在代码级别上进行探索。一起，我们将通过 Ansible Python API，使用扩展点来编写自己的 Ansible 插件。

如前一章所述，插件按以下方式分类：

+   查找插件

+   动作插件

+   缓存插件

+   回调插件

+   连接插件

+   变量插件

+   过滤器插件

这些插件中，最常用的是查找插件、回调插件、变量插件、过滤器插件和连接插件。让我们逐个探索这些插件。

# 查找插件

查找插件旨在从不同来源读取数据并将其提供给 Ansible。数据源可以是控制节点上的本地文件系统，也可以是外部数据源。这些数据源也可以是 Ansible 本身不原生支持的文件格式。

如果您决定编写自己的查找插件，您需要将其放入以下一个目录中，以便 Ansible 在执行 Ansible playbook 时捡起它。

+   项目`Root`中名为`lookup_plugins`的目录

+   在`~/.ansible/plugins/lookup_plugins/`或

+   /usr/share/ansible_plugins/lookup_plugins/

默认情况下，Ansible 中已经有许多查找插件可用。让我们讨论一些最常用的查找插件。

## 查找插件文件

这是 Ansible 中最基本的查找插件类型。它通过控制节点上的文件内容进行读取。然后可以将从文件中读取的数据传递给 Ansible playbook 作为变量。在其最基本形式中，文件查找的使用方法在以下 Ansible playbook 中进行了演示：

```
---
- hosts: all
  vars:
    data: "{{ lookup('file', './test-file.txt') }}"
  tasks:
- debug: msg="File contents {{ data }}"
```

上述 playbook 将从 playbook 根目录中的本地文件`test-file.txt`中读取数据到变量`data`中。然后，这个变量被传递给`task: debug`模块，并使用数据变量将其打印在屏幕上。

## 查找插件 - csvfile

`csvfile`查找插件设计用来从控制节点上的 CSV 文件中读取数据。这个查找模块设计为接受几个参数，如下所述：

| 参数 | 默认值 | 描述 |
| --- | --- | --- |
| `file` | `ansible.csv` | 要从中读取数据的文件。 |
| `delimiter` | TAB | CSV 文件中使用的分隔符。通常是'`,`'。 |
| `col` | `1` | 列号（索引）。 |
| `default` | 空字符串 | 如果在 CSV 文件中找不到请求的键，则返回此值 |

让我们以读取以下 CSV 文件中的数据为例。CSV 文件包含不同城市的人口和面积详情：

```
File: city-data.csv
City, Area, Population
Pune, 700, 2.5 Million
Bangalore, 741, 4.3 Million
Mumbai, 603, 12 Million
```

这个文件位于 Ansible play 的控制节点的根目录下。要从这个文件中读取数据，使用了`csvfile`查找插件。以下的 Ansible play 尝试从之前的 CSV 文件中读取孟买的人口。

**Ansible Play**：`test-csv.yaml`

```
---
- hosts: all 
  tasks:
    - debug:
        msg="Population of Mumbai is {{lookup('csvfile', 'Mumbai file=city-data.csv delimiter=, col=2')}}"
```

## 查找插件 - dig

`dig`查找插件可以用来对**FQDN**（**完全合格域名**）运行 DNS 查询。您可以通过使用插件支持的不同标志来自定义查找插件的输出。在其最基本的形式中，它返回给定 FQDN 的 IP。

这个插件依赖于`python-dns`包。这应该安装在控制节点上。

以下的 Ansible play 解释了如何获取任何 FQDN 的 TXT 记录：

```
---
- hosts: all 
  tasks:
    - debug: msg="TXT record {{ lookup('dig', 'yahoo.com./TXT') }}" 
    - debug: msg="IP of yahoo.com {{lookup('dig', 'yahoo.com', wantlist=True)}}"
```

之前的 Ansible play 将在第一步获取 TXT 记录，并在第二步获取与 FQDN `yahoo.com`相关联的任何 IP。

还可以使用 dig 插件执行反向 DNS 查找，方法是使用以下语法：

```
**- debug: msg="Reverse DNS for 8.8.8.8 is {{ lookup('dig', '8.8.8.8/PTR') }}"**

```

## 查找插件 - ini

`ini`查找插件设计用来读取`.ini`文件中的数据。一般来说，`ini`文件是在定义的部分下的键-值对的集合。`ini`查找插件支持以下参数：

| 参数 | 默认值 | 描述 |
| --- | --- | --- |
| `type` | `ini` | 文件类型。目前支持两种格式 - ini 和 property。 |
| `file` | `ansible.ini` | 要读取数据的文件名。 |
| `section` | `global` | 需要从`ini`文件中读取指定键的部分。 |
| `re` | `False` | 如果键是正则表达式，将其设置为`true`。 |
| `default` | 空字符串 | 如果在`ini`文件中找不到请求的键，则返回此值。 |

以以下`ini`文件为例，让我们尝试使用`ini`查找插件读取一些键。文件名为`network.ini`：

```
[default]
bind_host = 0.0.0.0
bind_port = 9696
log_dir = /var/log/network

[plugins]
core_plugin = rdas-net
firewall = yes 
```

以下 Ansible play 将从`ini`文件中读取键：

```
---
- hosts: all
  tasks:
      - debug: msg="core plugin {{ lookup('ini', 'core_plugin file=network.ini section=plugins') }}"
      - debug: msg="core plugin {{ lookup('ini', 'bind_port file=network.ini section=default') }}"
```

`ini`查找插件也可以用于通过不包含部分的文件读取值，例如 Java 属性文件。

# 循环-迭代的查找插件

有时您可能需要一遍又一遍地执行相同的任务。这可能是安装软件包的各种依赖项的情况，或者多个输入经过相同的操作，例如检查和启动各种服务。就像任何其他编程语言提供了迭代数据以执行重复任务的方法一样，Ansible 也提供了一种清晰的方法来执行相同的操作。这个概念被称为循环，并由 Ansible 查找插件提供。

Ansible 中的循环通常被标识为以`with_`开头的循环。Ansible 支持许多循环选项。以下部分讨论了一些最常用的循环选项。

## 标准循环-with_items

这是 Ansible 中最简单和最常用的循环。它用于对项目列表进行迭代并对其执行某些操作。以下 Ansible play 演示了使用`with_items`查找循环的用法：

```
---
- hosts: all 
  tasks:
    - name: Install packages
      yum: name={{ item }} state=present
      with_items:
        - vim
        - wget
        - ipython
```

`with_items`循环支持使用哈希，您可以在 Ansible playbook 中使用项目`<keyname>`来访问变量。以下 playbook 演示了使用`with_items`来迭代给定哈希：

```
---
- hosts: all 
  tasks:
    - name: Create directories with specific permissions
      file: path={{item.dir}} state=directory mode={{item.mode | int}}
      with_items:
        - { dir: '/tmp/ansible', mode: 755 }
        - { dir: '/tmp/rdas', mode: 755 }
```

前面的 playbook 将创建两个具有指定权限集的目录。如果您仔细查看从`item`中访问`mode`键时，存在一个名为`int`的代码块。这是一个`jinja2`过滤器，用于将字符串转换为整数。

## 直到循环-until

这个循环与任何其他编程语言的实现相同。它至少执行一次，并且除非达到特定条件，否则会继续执行。

让我们看一下以下代码，以了解`do-until`循环：

```
- **name**: Clean up old file. Keep only the latest 5 
  **action**: shell /tmp/clean-files.sh 
  **register**: number 
  **until**: number.stdout.find('5') != -1 
  **retries**: 6 
  **delay**: 10
```

`clean-files.sh`脚本对指定目录执行清理操作，并仅保留最新的五个文件。在每次执行时，它会删除最旧的文件，并在清理的目录中返回剩余文件的数量作为`stdout`的输出。脚本看起来像这样：

```
#!/bin/bash 

**DIR_CLEAN**='/tmp/test' 
cd $DIR_CLEAN 
**OFNAME**=`ls -t | tail -1` 
rm -f $OFNAME 
**COUNT**=`ls | wc -w` 
echo $COUNT
```

此操作将重试最多六次，间隔为 10。一旦在数字寄存器变量中找到 5，循环就会结束。

如果未明确指定“重试”和“延迟”，在这种情况下，默认情况下任务将重试三次，间隔五次。

## 创建自己的查找插件

上一章介绍了 Python API，并解释了 Ansible 如何加载各种插件以用于 Ansible play。本章涵盖了一些已经可用的 Ansible 查找插件，并解释了如何使用这些插件。本节将尝试复制`dig`查找的功能，以获取给定 FQDN 的 IP 地址。这将在不使用`dnspython`库的情况下完成，并将使用 Python 的基本 socket 库。以下示例仅演示了如何编写自己的 Ansible 查找插件：

```
import socket

class LookupModule(object):

    def __init__(self, basedir=None, **kwargs):
        self.basedir = basedir

    def run(self, hostname, inject=None, **kwargs):
        hostname = str(hostname)
        try:
            host_detail = socket.gethostbyname(hostname)
        except:
            host_detail = 'Invalid Hostname'
        return host_detail
```

上述代码是一个查找插件；让我们称之为`hostip`。

如您所见，存在一个名为`LookupModule`的类。只有当存在一个名为`LookupModule`的类时，Ansible 才将 Python 文件或模块识别为查找插件。该模块接受一个名为 hostname 的参数，并检查是否存在与之对应的 IP（即，是否可以解析为有效的 IP 地址）。如果是，则返回请求的 FQDN 的 IP 地址。如果不是，则返回“无效的主机名”。

要使用此模块，请将其放置在 Ansible play 根目录下的`lookup_plugins`目录中。以下 playbook 演示了如何使用新创建的`hostip`查找：

```
---

- hosts: all 
  tasks:
    - debug:
        msg="{{lookup('hostip', item, wantlist=True)}}"
      with_items:
        - www.google.co.in
        - saliux.wordpress.com
        - www.twitter.com
```

上述 play 将循环遍历网站列表，并将其作为参数传递给`hostip`查找插件。这将返回与请求的域关联的 IP。您可能已经注意到，还有一个名为`wantlist=True`的参数在调用`hostip`查找插件时也被传递进去。这是为了处理多个输出（即，如果有多个值与请求的域关联，这些值将作为列表返回）。这样可以轻松地对输出值进行迭代。

# 回调插件

回调是 Ansible 中最广泛使用的插件之一。它们允许您在运行时对 Ansible 运行的事件做出响应。回调是一种最常定制的插件类型。

尽管有一些通用的回调插件，但您肯定会自己编写一个来满足您的需求。这是因为每个人对数据想要做什么有不同的看法。Ansible 不仅仅是一个限于配置管理和编排的工具。您可以做更多的事情，例如，在 Ansible play 期间收集数据并稍后处理它们。回调提供了一个广阔的可能性探索空间。这一切取决于您对结果的期望。

这一部分不是通过现有的回调模块，而是更专注于编写一个。

从前面的章节中，以一个场景为例，您创建了自己的`dmidecode`模块，该模块在目标机器上执行并返回硬件规格的 JSON。该模块还支持一个标志，允许您将此结果存储在目标机器上的 JSON 文件中。

看看这种情况，有两个主要问题：

+   您没有 playbook 执行的日志。一切都在`stdout`上。

+   即使在调用`dmidecode`模块时将保存标志设置为 true，结果也会存储在目标机器上，而不是控制节点上。在 playbook 执行后，您将不得不从每个目标主机单独收集这些 JSON 文件。

第一点是您在生产环境中绝对不希望出现的问题。您总是希望有 Ansible play 的日志。这将使您能够在 playbook 执行期间追溯任何失败。Ansible 代码存储库中已经有一些通用的回调插件可供此目的使用。您可以在[`github.com/ansible/ansible/tree/devel/lib/ansible/plugins/callback`](https://github.com/ansible/ansible/tree/devel/lib/ansible/plugins/callback)找到一些现有的回调模块。如果它们满足您的需求，您可以选择其中之一。本节将不讨论现有的回调模块。

第二点是人们选择开发自己的回调插件的一个主要原因。它解决了你实际想要对数据做什么的问题。在这种情况下，该模块收集系统信息，以备后续审计之用。在其他情况下，您可能仍希望处理收集到的信息和 Ansible play 的日志，以确定失败的原因，生成报告，跟踪生产变更等。可能有许多可能性。

本节将通过创建一个自定义回调插件来解决第二点，该插件可以帮助您从目标机器获取 JSON 数据，该数据是使用您在第三章中创建的`dmidecode`模块生成的。*深入了解 Ansible 模块*。

在深入编写回调模块之前，了解回调模块的工作原理非常重要。

回调模块在播本执行期间发生的事件上起作用。Ansible 支持的常用事件包括：

+   `runner_on_failed`

+   `runner_on_ok`

+   `runner_on_skipped`

+   `runner_on_unreachable`

+   `runner_on_no_hosts`

+   `playbook_on_start`

以`runner_`开头的事件名称特定于任务。以`playbook_`开头的事件名称特定于整个播本。显然，事件名称是不言自明的；因此，我们不会详细介绍每个事件的含义。

如前一章所述，回调插件应该有一个名为`CallbackModule`的类，否则 Ansible 将无法识别它作为回调插件。Python API 要求`CallbackModule`类来识别模块作为回调插件。这是为了区分不同的 Python 文件，因为不同的 Python 模块可能驻留在同一目录中，回调插件可能正在使用同一目录中的一个 Python 模块的方法。

在讨论了事件和类的要求之后，现在是时候动手了。让我们继续编写一个非常基本的回调插件，与第三章中创建的`dmidecode`模块，*深入了解 Ansible 模块*进行集成。

如果你还记得，Ansible 播本将 JSON 输出记录在名为`dmi_data`的寄存器中。然后通过调试模块在`stdout`上回显这些数据。因此，在播本执行期间，回调模块需要查找`dmi_data`键。该键将包含输出的 JSON 数据。回调插件将尝试在控制节点上将这些 JSON 数据转储到一个 JSON 文件中，并将其命名为目标机器的 IP 或 FQDN，后跟`.json`扩展名。回调模块名为`logvar`，需要放置在 Ansible 播本根目录下的`callback_plugins`目录中。

```
import json

class CallbackModule(object):

    ''' 
    This logs the debug variable 'var' and writes it in a JSON file
    '''

    def runner_on_ok(self, host, result):
        try:
            if result['var']['dmi_data[\'msg\']']:
                fname = '%s.json' % host
                with open(fname, 'w') as ofile:
                    json.dump(result['var']['dmi_data[\'msg\']'], ofile)
        except:
            pass
```

在将上述模块放置在 Ansible play 根目录中的`callback_plugins`目录中后，执行`dmidecode` playbook 将导致输出文件命名为`<taget>.json`。这些文件包含由`dmidecode`模块返回的目标机器的`dmidecode`信息。

# Var 插件

在编写 Ansible play 时，您肯定会使用一些变量。它可能是特定于主机的`host_vars`或常用的`group_vars`。从这些变量中读取的任何数据并馈送到 Ansible playbook 都是使用 var 插件完成的。

var 插件由类名`VarModule`标识。如果您在代码级别上探索 var 插件，在类内部有三种方法：

+   `run`：此方法应返回特定于主机的变量以及从其成员组计算出的变量

+   `get_host_vars`：返回特定于主机的变量

+   `get_group_vars`：返回特定于组的变量

# 连接插件

连接插件定义了 Ansible 如何连接到远程机器。Ansible 可以通过定义 playbooks 来在各种平台上执行操作。因此，对于不同的平台，您可能需要使用不同的连接插件。

默认情况下，Ansible 附带`paramiko_ssh`，本机 SSH 和本地连接插件。还添加了对 docker 的支持。还有其他不太知名，不太常用的连接插件，如 chroot，jail zone 和 libvirt。

连接插件由其类连接标识。

让我们在代码级别上探索 Paramiko 连接插件。连接类包含四种主要方法。这些方法又调用了一些私有函数来进行一些操作。主要方法是：

+   `exec_command`：此方法在远程目标上运行请求的命令。您可能需要使用`sudo`运行命令的要求，默认情况下需要一个 PTY。Paramiko 通过默认传递`pty=True`来处理这个问题。

+   `put_file`：此方法接受两个参数 - `in_path`和`out_path`。此函数用于从本地控制器节点复制文件到远程目标机器。

+   `fetch_file`：这种方法类似于`put_file`方法，也接受两个参数 - `in_path`和`out_path`。该方法用于从远程机器获取文件到本地控制器节点。

+   `Close`：此函数在操作完成时终止连接。

# 过滤器插件

Ansible 支持 Jinja2 模板化，但为什么不使用 Jinja2 过滤器？您想要它；Ansible 有它！

过滤器插件是 Jinja2 模板过滤器，可用于将模板表达式从一种形式修改或转换为另一种形式。Ansible 已经默认提供了一组 Jinja2 过滤器。例如，`to_yaml`和`to_json`。Ansible 还支持从已格式化的文本中读取数据。例如，如果您已经有一个需要从中读取数据的 YAML 文件或 JSON 文件，您可以使用`from_json`或`from_yaml`过滤器。

您还可以选择使用`int`过滤器将字符串转换为整数，就像在*循环-迭代的查找插件*部分中创建具有定义权限的目录时所示的那样。

让我们讨论如何以及在哪里可以实现过滤器，以便更充分地利用 Ansible。

## 使用带条件的过滤器

在运行脚本时，可能会出现一种情况，根据上一步的结果，您需要执行特定的步骤。这就是条件出现的地方。在正常编程中，您可以使用`if-else`条件语句。在 Ansible 中，您需要检查上一条命令的输出，并在`when`子句中应用过滤器，如下面的代码所示：

```
---
- hosts: all 
  tasks:
    - name: Run the shell script
      shell: /tmp/test.sh
      register: output

    - name: Print status
    - debug: msg="Success"
      when: output|success

    - name: Print status
    - debug: msg="Failed"
      when: output|failed
```

在上述脚本中，shell 脚本`test.sh`的执行结果存储在寄存器变量 output 中。如果状态是成功，任务将打印`Success`；否则，将打印`Failed`。

## 版本比较

此过滤器可用于检查目标主机上安装的请求应用程序的版本。它返回`True`或`False`状态。版本比较过滤器接受以下运算符：

```
<, lt, <=, le, >, gt, >=, ge, ==, =, eq, !=, <>, ne
```

## IP 地址过滤器

IP 地址过滤器可用于检查提供的字符串是否为有效的 IP 地址。甚至可以指定您要检查的协议：IPv4 或 IPv6。

以下过滤器将检查 IP 地址是否为有效的 IPv4 地址：

```
{{ host_ip | ipv4 }}
```

同样，可以通过使用以下方式来检查 IP 地址是否为有效的 IPv6 地址：

```
{{ host_ip | ipv6 }}
```

## 理解代码

Ansible 通过查找名为`FilterModule`的类来识别 Python 模块为过滤器插件。在这个类内部存在一个名为`filters`的方法，它将过滤器映射到它们在`FilterModule`类之外的对应文件中。

如果您选择自己编写过滤器插件，以下是过滤器插件的结构：

```
# Import dependencies

def custom_filter(**kwargs):
    # filter operation code

class FilterModule(object):
    def filter(self):
        return {
            'custom_filter': custom_filter
        }   
```

在前面的示例代码中，在`FilterModule`类内部的过滤器方法中，`custom_filter`键映射到类外部的`custom_filter`函数。

`custom_filter`函数包含实际的过滤器实现代码。Ansible 只是加载`FilterModule`类并浏览定义的过滤器。然后将定义的过滤器提供给最终用户使用。

在 Ansible 代码库中，任何关于过滤器的新建议通常都会添加到过滤器插件内部的`core.py`文件中。

# 摘要

本章继续了第四章*探索 API*的内容，并介绍了 Ansible 插件的 Python API 在各种 Ansible 插件中的实现方式。在本章中，我们详细讨论了各种类型的插件，从实现角度和代码层面进行了讨论。本章还演示了如何通过编写自定义查找和回调插件来编写示例插件。现在，您应该能够为 Ansible 编写自己的自定义插件。

下一章将探讨如何配置 Ansible，并将到目前为止讨论的所有内容整合在一起。本章还将指导您如何共享您的插件和角色，并探索一些最佳实践。


# 第六章：将所有内容整合在一起-集成

当您到达本章时，您将根据自己的需求成功创建自己的自定义模块和插件。现在，您可能会想知道接下来是什么？

Ansible 是一个伟大的社区产品。它为每个人提供了许多模块和插件。现在您已经熟悉了 Python API，已经编写了一个 Ansible 模块，可能还有一个插件，现在是时候回馈社区了。由于您有一些无法满足原生 Ansible 的需求，很可能其他人也需要进一步的帮助。让我们看看可以以各种方式回馈社区。

本章将介绍如何配置 Ansible 以集成您的模块到现有的 Ansible 库中。本章还将介绍如何分发您的模块并帮助改进 Ansible。

# 配置 Ansible

要充分利用 Ansible，有必要正确配置 Ansible。虽然默认设置对大多数用户来说已经足够，但高级用户可能希望微调一些东西并进行一些更改。

全局持久设置在位于`/etc/ansible/ansible.cfg`的 Ansible 配置文件中定义。但是，您也可以将自定义配置文件放在 Ansible play 的根目录或用户的主目录中。还可以通过设置环境变量来更改设置。

有这么多配置 Ansible 的方法，一个重要的问题就是，Ansible 如何优先考虑配置文件？在执行 playbook 过程中，它如何选择要使用的配置？

在 Ansible 版本 1.9 中，配置按以下顺序处理：

+   `ANSIBLE_CONFIG`：环境变量

+   `ansible.cfg`：从中调用 Ansible 的当前工作目录

+   `.ansible.cfg`：配置文件存储在用户的主目录中

+   `/etc/ansible/ansible.cfg`：如果找不到其他配置文件，则为默认配置文件

Ansible 将按照上述顺序处理配置。在执行过程中将使用找到的第一个配置。为了保持一切清晰，Ansible 不会合并配置文件。所有文件都是分开保存的。

## 环境配置

通过设置环境变量，您可以覆盖从配置文件加载的任何现有配置。在当前版本的 Ansible 中，环境配置具有最高优先级。要找到 Ansible 支持的环境变量的完整列表，您需要查看源代码。以下列表包含一些您应该了解的环境变量，以便使您的模块和插件正常工作：

| 环境变量 | 默认值 |
| --- | --- |
| `ANSIBLE_ACTION_PLUGINS` | `~/.ansible/plugins/action:/usr/share/ansible/plugins/action` |
| `ANSIBLE_CACHE_PLUGINS` | `~/.ansible/plugins/cache:/usr/share/ansible/plugins/cache` |
| `ANSIBLE_CALLBACK_PLUGINS` | `~/.ansible/plugins/callback:/usr/share/ansible/plugins/callback` |
| `ANSIBLE_CONNECTION_PLUGINS` | `~/.ansible/plugins/connection:/usr/share/ansible/plugins/connection` |
| `ANSIBLE_LOOKUP_PLUGINS` | `~/.ansible/plugins/lookup:/usr/share/ansible/plugins/lookup` |
| `ANSIBLE_INVENTORY_PLUGINS` | `~/.ansible/plugins/inventory:/usr/share/ansible/plugins/inventory` |
| `ANSIBLE_VARS_PLUGINS` | `~/.ansible/plugins/vars:/usr/share/ansible/plugins/vars` |
| `ANSIBLE_FILTER_PLUGINS` | `~/.ansible/plugins/filter:/usr/share/ansible/plugins/filter` |
| `ANSIBLE_KEEP_REMOTE_FILES` | `False` |
| `ANSIBLE_PRIVATE_KEY_FILE` | `None` |

### 注意

**有趣的事实**

如果在管理节点上安装了 cowsay，Ansible playbook 运行将使用 cowsay 并使输出更有趣。如果您不希望启用 cowsay，只需在配置文件中设置`nocows=0`。

# 贡献给 Ansible

在开始为 Ansible 做贡献之前，重要的是要知道在哪里以及如何做出贡献以及要做出什么样的贡献。为了减少重复劳动，您需要与社区保持联系。可能会出现这样的情况，您想要处理的功能已经被其他人处理，或者您认为可以修复的错误已经被其他人接手并正在处理。此外，可能会出现您需要社区帮助来完成某些任务的情况；也许您在某个地方卡住了，有一些未解答的问题。这就是社区发挥作用的地方。Ansible 有自己的 IRC 频道和邮件列表用于这些目的。

你可以加入`#ansible`频道，地址是[irc.freenode.net](http://irc.freenode.net)，在那里你可以与社区成员交谈，讨论功能，并获得帮助。这是人们互相在线聊天的地方。对于没有 IRC 客户端的用户，他们可以通过[`webchat.freenode.net/`](https://webchat.freenode.net/)连接 Web UI。然而，由于 Ansible 是一个全球社区，不是所有成员都会全天候可用，你的问题可能得不到答复。如果是这样，你可以向邮件列表发送邮件，这样问题更有可能引起核心开发人员和高级用户的注意。

你可能想加入以下邮件列表：

+   Ansible 项目列表：[`groups.google.com/forum/#!forum/ansible-project`](https://groups.google.com/forum/#!forum/ansible-project)（一个用于分享 Ansible 技巧和提问的一般用户讨论邮件列表）

+   Ansible 开发列表：[`groups.google.com/forum/#!forum/ansible-devel`](https://groups.google.com/forum/#!forum/ansible-devel)（讨论正在进行的功能，建议功能请求，获取扩展 Ansible 的帮助）

+   Ansible 公告列表：[`groups.google.com/forum/#!forum/ansible-announce`](https://groups.google.com/forum/#!forum/ansible-announce)（一个只读列表，分享有关 Ansible 新版本发布的信息）

Ansible 是一个托管在 GitHub 上的开源项目。任何拥有 GitHub 账户的人都可以为 Ansible 项目做出贡献。该项目通过 GitHub 拉取请求接受贡献。

# Galaxy-分享角色

为你想要自动化的任务编写一个 playbook 可以帮助你每次部署时节省时间和精力。如果你能与社区分享角色，这也可以为其他人节省时间。

Ansible 提供了一个很好的平台来分享你的操作。Galaxy 是一个平台，你可以在其中分享预打包的工作单元作为“角色”，这些角色可以集成或放入 playbooks 中使用。一些角色可以直接放入，而其他一些可能需要进行一些调整。此外，Galaxy 为每个共享的角色提供了可靠性评分。你可以从许多可用的角色中进行选择，对它们进行评分和评论。

角色托管在 GitHub 上。Galaxy 允许与 GitHub 集成，您可以使用现有的 GitHub 帐户登录到 Galaxy 并分享角色。要分享您的角色，请创建一个 GitHub 存储库，克隆它，并在克隆的存储库中初始化一个 Galaxy 角色。可以使用以下代码来完成：

```
$ ansible-galaxy init <role-name> --force
```

这将创建一个组织代码所需的目录结构。然后，您可以使用此目录结构创建一个 Ansible 角色。一旦您的角色准备就绪，请在 playbook 中对其进行测试，并验证其是否按预期工作。然后，您可以将其推送到 GitHub 存储库中。

将代码上传到 Galaxy，您需要使用您的 GitHub 帐户登录到 Galaxy 平台（[`galaxy.ansible.com`](https://galaxy.ansible.com)）。通过使用菜单中的**添加角色**选项并提供所需的凭据，Galaxy 将从您的 GitHub 存储库导入角色，并使其在 Galaxy 平台上对整个社区可用。

您可能还希望为存储库应用标签，Galaxy 默认将其视为版本号。这允许用户在不同版本之间进行选择。如果没有指定标签，用户将始终只能下载 GitHub 存储库上最新的可用代码。

# Galaxy-最佳实践

在编写任何您可能希望通过 Galaxy 分享的角色时，应遵循一些最佳实践，以确保最终用户一切顺利运行：

+   始终记录您所做的任何内容，并将其放在`README.md`文件中。这是最终用户在使用角色时所参考的文件。

+   明确包含和列出所有依赖项。不要假设任何内容。

+   使用角色名称作为变量的前缀。

+   在分享之前测试角色。您进行的测试越多，出现故障的可能性就越小。

这些最佳实践也适用于您在一般情况下对 Ansible 的任何贡献。无论您是开发模块或插件，还是编写计划与社区共享的角色，这些实践都可以确保一切顺利进行。虽然这不是强制性的，但强烈建议遵循这些最佳实践，以便为他人提供贡献变得更加容易，并在以后需要时理解和扩展。

# 分享模块和插件

到了这个阶段，您将开发自己的 Ansible 模块或插件。现在，您希望与朋友和陌生人分享，并帮助他们简化他们的任务。您可能还希望合作开发一个模块或插件，并需要公众的帮助。

GitHub 是一个很好的开发者协作平台之一。您可以在 GitHub 上创建一个存储库并将代码推送到其中。您可以将模块代码与 Ansible playbook 一起使用，演示您刚刚开发的模块或插件的使用方法。

GitHub 允许人们为一个项目做出贡献。通常将代码放在 GitHub 上是一个好主意，因为它提供了许多优势。除了鼓励协作性，它还提供版本控制，您可以在需要时回滚更改，并跟踪过去对代码库所做的任何更改。在协作过程中，您可以通过查看建议的更改来选择要解决的拉取请求以及要忽略的拉取请求，从而允许您对存储库进行控制。

## 将模块加入 Ansible

Ansible 模块托管在 Ansible 的两个单独的子存储库中，即：

+   `ansible-modules-core`

+   `ansible-modules-extras`

模块存储库`ansible-modules-core`包含了与 Ansible 一起提供的最受欢迎的模块。这些是最常用的核心模块，对于解决系统的基本功能至关重要。该存储库包含了几乎每个 Ansible 正常运行所需的基本功能。该存储库不直接接受模块提交。但是，如果您遇到任何错误，可以报告并修复错误。

模块存储库`ansible-modules-extras`是`ansible-modules`的一个子集，其中包含优先级较低的模块（即不能被视为核心模块的模块）。新模块将提交到此存储库。根据模块的受欢迎程度和完整性，模块可以晋升为核心模块。

作为托管在 GitHub 上的开源项目，Ansible 通过 GitHub 拉取请求接受贡献。要将您的模块加入 Ansible，您需要了解 GitHub 拉取请求的工作原理：

+   将 Ansible 项目从[`github.com/ansible/ansible-modules-extras`](https://github.com/ansible/ansible-modules-extras)或[`github.com/ansible/ansible-modules-core`](https://github.com/ansible/ansible-modules-core)分叉到您的 GitHub 帐户。

+   在[`github.com/ansible/ansible-modules-extras/issues`](https://github.com/ansible/ansible-modules-extras/issues)或[`github.com/ansible/ansible-modules-core/issues`](https://github.com/ansible/ansible-modules-core/issues)上为您要解决的功能提交问题。如果您要修复错误，应该已经存在一个针对该错误的问题。如果没有，请创建一个并分配给自己。

+   将您的模块或修复错误的补丁推送到您刚创建的错误编号。

+   提出一个拉取请求到源存储库（即 Ansible）。

完成后，审阅人员将验证代码，审查它，并检查它是否解决了问题。审查后，您可能会收到一些评论或更改请求，您需要进行修复。在您的代码合并之前可能会有多次迭代。

如果您的模块或插件合并到 Ansible 存储库中，它将在下一个版本中对所有 Ansible 用户可用。

# 将插件引入 Ansible

如前一章所述，Ansible 插件根据其功能被分类为不同的组，如操作、回调、查找等。与模块不同，Ansible 插件是 Ansible 存储库本身的一部分。没有像 extras 和 core 这样的不同存储库。您可以直接在 Ansible 存储库中提出问题，在邮件列表上讨论，并在获得批准后提交拉取请求。

以下链接列出了 Ansible 存储库中的现有插件：

[`github.com/ansible/ansible/tree/devel/lib/ansible/plugins`](https://github.com/ansible/ansible/tree/devel/lib/ansible/plugins)

## 需要记住的要点

提交新模块时，有几件事情需要牢记：

+   始终讨论您提出的功能。这将帮助您节省时间和精力，以防该功能已经在进行中。

+   并非您提出的所有功能都会被接受。始终会根据用例和模块/插件的带来的价值进行评估。

+   维护您编写的模块/插件是一个好的实践。

+   积极地解决并修复针对您的模块报告的任何错误。这将使您的模块更加可靠。

+   尽量使您的模块尽可能通用（即，它应该接受用户参数并相应地进行调整，为用户提供更大的灵活性）。尽管如此，它应该专注于创建时的特定任务。这会增加被接受的机会。

# 最佳实践

到目前为止，您应该已经熟悉并习惯了使用 Ansible Python API。您甚至可能拥有自己的 Ansible 模块或插件，希望与社区分享。在与社区分享您的模块、插件和角色时，您应该遵循以下几项最佳实践：

+   在提交拉取请求之前始终测试您的模块。

+   尽量使您的模块尽可能通用。

+   始终记录您所创建的任何内容，无论是模块、插件还是在 Galaxy 上共享的 Ansible 角色。

+   明确列出任何依赖关系。

+   在邮件列表和 IRC 频道上继续讨论。积极参与可以提高您的知名度。

# 总结

本章涵盖了配置您的 Ansible 环境以及如何将您的模块和插件放入 Ansible 存储库的主题。它还涉及了如何通过 Git 分发您的模块。本章还向您介绍了 Galaxy 平台，这是 Ansible 提供的一个服务，用于分享您的角色。本章还提供了最佳实践的指导，并介绍了在提交模块时应该牢记的各种事项。

下一章将带您通过一系列场景，演示 Ansible 可以派上用场的情况。本章还将整合前几章所涵盖的内容，将其结合起来，并呈现一个场景，让您了解如何充分利用 Ansible。


# 第七章：成为大师-完整配置指南

当你到达这一章时，你已经通过了本书范围内的所有概念。本章将建立在前几章学到的一切基础之上，并为你提供 Ansible 可以派上用场的真实用例。本章将向你展示如何使用 Ansible 来解决简单和复杂的问题和场景。

# 一个 playbook，不同的应用程序，多个目标

你可能会遇到不同环境需要不同设置或部署步骤的情况，例如，部署到不同的环境，如开发、QA、阶段或生产。部署方案可能会有小的变化，例如，Web 应用的 QA 实例指向本地数据库的实例，而生产部署指向不同的数据库服务器。

另一种情况可能是你需要部署一个你为不同发行版构建的应用程序（例如，基于 RPM 和基于 Debian 的发行版）。在这种情况下，部署将不同，因为这两个平台使用不同的应用程序管理器。基于 RPM 的发行版使用 Yum 或 DNF 软件包管理实用程序，而基于 Debian 的发行版使用 DPKG 实用程序进行软件包管理。此外，创建的结果软件包也会有所不同-一个是`.rpm`，另一个是`.deb`。

在这种情况下，即使目标平台不同，部署方案或配置也不同，所有这些都可以通过定义角色在一个 playbook 中处理。

让我们来看几个实际的场景。在第一个场景中，你需要部署一个由后端数据库（MySQL）和前端 Web 应用程序组成的应用程序。Web 应用程序查询后端数据库，并根据用户的请求提供数据。Web 应用程序和 MySQL 数据库都需要部署在不同的机器上。

让我们将安装和配置任务分为两类：

+   **系统准备**: 这是 Web 应用系统和数据库服务器的常见任务。两个系统都需要先准备好进行安装。准备工作可能涉及配置存储库和更新系统等任务。

+   **部署**: 这包括部署数据库和 Web 应用程序，然后进行所需的任何配置更改。

如果你分析这些类别，系统准备对两个系统都是通用的，而部署作业对每个应用程序都是特定的。在这种情况下，你可以将作业分成角色。你可以有三个角色 - 一个“通用”角色，它在两台机器上执行，以及一个分别用于数据库和 Web 应用程序的角色。这使得 Ansible playbook 更加模块化和易于维护。

以下是根据上述问题陈述的分析编写的 Ansible playbook：

`db-webapp-role.yaml`

```
---

- hosts: all 
  user: root
  roles:
    - { role: common }

- hosts: database
  user: root
  roles:
    - { role: database }

- hosts: webapp
  user: root
  roles:
    - { role: webapp }
```

前面的 playbook 调用不同的角色 - `common`，`webapp`和`database`，并在相应的主机组上执行它们。`common`角色在所有主机组上执行（即在`webapp`和`database`上）。然后在特定主机组上执行各个角色。以下是前面的 play 调用的角色：

**角色**：`common`

```
---
- name: Create hosts file for each machine
  template: src hosts.j2 dest=/etc/hosts

- name: Copy Repo file
  copy: src=local-tree.repo dest=/etc/yum.repos.d/

- name: Update the system
  yum: name=* state=latest
```

这是一个“通用”角色，将在所有目标主机上执行。它配置一个仓库，为目标机器提供软件包和依赖项。该角色配置此仓库，并将目标机器上安装的所有软件包更新为它们的最新版本。

以下角色将仅在清单文件中数据库组指定的主机上执行。这将安装 MySQL 数据库并复制配置文件，该文件将配置数据库并在目标主机上创建所需的表。它还将确保 MYSQL 服务在目标主机上运行。根据 Ansible play，此角色将在“通用”角色成功完成后在目标主机上执行：

**角色**：`database`

```
---
- name: Install MySQL databse server
  yum: name=mysql state=present

- name: Start MySQL service
  service: name=mysqld status=started

- name: Create a directory to copy the setup script
  file: path=/temp/configdb state=directory mode=0755

- name: Copy script to create database tables
  copy: src=configdb.sh dest=/temp/configdb

- name: Run configdb.sh to create database tables
  shell: configdb.sh chdir=/temp/configdb
```

以下角色专用于在清单文件中的 webapp 组上部署 Web 应用程序。根据 Ansible play，在“通用”角色成功完成后，该角色将执行：

**角色**：`webapp`

```
---
- name: Install HTTP server
  yum: name=httpd state=present

- name: Start httpd service
  service: name=httpd state=started

- name: Create temporary directory to copy over the rpm 
  file: path=/temp/webapp state=directory mode=0755

- name: Copy the application package to the target machine
  copy: src=webapp-2.4.16-1.fc22.x86_64 dest=/temp/webapp

- name: Install the webapp
  command: yum install -y ./webapp-2.4.16-1.fc22.x86_64 chdir=/temp/webapp

- name: Copy configuration script
  copy: src=configweb.sh dest=/temp/webapp

- name: Execute the configuration script
  shell: configweb.sh chdir=/temp/webapp
```

# 使用标签的 Ansible 角色

Ansible playbook 旨在是模块化的，并且可以在需要时在不同环境中使用。为此，引入了角色。然而，仅使用角色可能不足够，因为您可能希望在同一主机上的不同环境中使用不同的角色。好的，这听起来有点混乱。让我们来看一个场景。

您可以将您的 Ansible playbook 与持续部署系统集成，这有助于开发人员在开发周期中随时部署应用程序。在此周期中，他们可能希望以适合开发阶段的方式设置系统并配置应用程序。由于应用程序正在开发中，部署到开发环境时可能并非所有功能都已完成。但是，一旦应用程序完成，开发人员可能希望完全运行 Ansible 以复制生产或 QE 环境，从而确保应用程序在生产主机上以所需的所有设置运行。在这种情况下，存在两个不同的环境 - 开发和 QE-ready。

由于部署在同一主机上，并且可以执行多个角色，因此可以使用标签。您可以将角色与标签配对。因此，通过从命令行指定标签，Ansible 知道要执行哪个角色。

演示这一点的一种简单方法如下。假设您有一个应用程序，当需要在开发环境中部署时，您可以从 Git Hub 存储库克隆代码并运行 `install.sh` 脚本。同样，在开发环境中，您有一些放松的安全策略，比如 SeLinux 设置为宽松模式。当将同一应用程序传递给 QE 时，应该将其打包为 RPM 然后安装。此外，不允许放松安全策略，因此 SeLinux 需要保持强制模式。由于开发人员将拥有一个开发实例，因此他们将不得不在同一实例上执行两个角色。在这种情况下，开发人员可以使用标签根据需要使用不同的角色来部署应用程序。

以下是一个包含演示先前场景的角色的 Ansible playbook：

**角色**：`development`

```
---

- name: Create directory to clone git repo
  file: path=/tmp/gitrepo state=directory mode=0755

- name: Clone Git repo
  git: repo={{ item }} dest=/tmp/gitrepo
  with_items:
    - "{{ git_repo }}"

- name: Set selinux to permissive
  selinux: policy=targeted state=permissive

- name: Run install.sh to deploy application
  shell: install.sh chdir=/tmp/gitrepo/example
```

**角色**：`qe_ready`

```
---

- name: Make directory to store RPM 
  file: path=/tmp/deploy state=directory mode=0755

- name: Download the RPM to Directory
  get_url: url={{ item }} dest=/tmp/deploy
  with_items:
    - "{{ rpm_link }}"

- name: Install RPM 
  command: yum install -y *.rpm chdir=/tmp/deploy

- name: Set Selinux to Enforcing
  selinux: policy=targeted state=enforcing
```

上述两个角色是同一个 Ansible playbook 的一部分，并将根据您指定的标签按需调用。以下 Ansible play 演示了如何将角色绑定到特定标签：

Ansible Play：`demo-tag.yaml`

```
---

- hosts: application
  user: rdas
  sudo: yes 
  roles:
    - { role: development, tags: ['development'] }
    - { role: qe_ready, tags: ['qe'] }
```

`development` 角色现在绑定到 `development` 标签，而 `qe_ready` 角色绑定到 `qe` 标签。可以通过在命令中使用 `-t` 标志来指定标签来执行 Ansible playbook：

```
**# ansible-playbook -i hosts -t development demo-tag.yaml**

```

# 获取基础设施信息并将其集中托管

在之前的章节中，您创建了一个`dmidecode`模块，从目标机器收集系统信息并返回 JSON 输出。该模块还允许您切换一个名为"save"的标志为`true`，如果您希望将输出存储在目标机器上的 JSON 文件中。

在各自的目标机器上存储系统信息并没有太大意义，因为数据仍然驻留在目标机器上，要访问数据，需要登录到不同的机器，然后解析相应的 JSON 文件。为了解决这个问题，本书向您介绍了回调函数，它有助于获取 JSON 数据并将其存储为 JSON 文件在控制器节点上（即您执行 Ansible playbook 的节点）。

然而，即使这样做了，问题仍未完全解决。您确实设法从基础设施节点收集了数据，但可访问性仍然是一个问题。

+   需要访问控制器机器才能访问所有文件

+   在现实世界的情况下，您无法向每个人授予访问权限

+   即使您计划授予某些人访问权限，您的可用性仍然是一个瓶颈

为了解决这个问题，一个解决方案可以是将所有这些 JSON 文件托管到一个中央服务器上，从那里可以下载所需的 JSON 文件，解析它们并生成报告。然而，这个问题的更好解决方案可以是将数据索引到一个中央的 Elasticsearch 实例中，然后通过 RESTful API 提供数据。

### 注意

**Elasticsearch**是建立在 Apache Lucene 之上的开源搜索引擎。Elasticsearch 用 Java 编写，并在内部使用 Lucene 进行索引和搜索。它旨在通过在简单的 RESTful API 后面隐藏 Lucene 的复杂性来使全文搜索变得容易。

来源：[www.elastic.co](http://www.elastic.co)的 Elasticsearch 文档。

本章不会深入讨论 Elasticsearch 是什么以及它的功能如何，因为这超出了本书的范围。有关 Elasticsearch 的详细信息，您可以参考在线文档或*精通 ElasticSearch*（[`www.packtpub.com/web-development/mastering-elasticsearch-second-edition`](https://www.packtpub.com/web-development/mastering-elasticsearch-second-edition)），由*Packt Publishing*出版。

关于在 Elasticsearch 中索引数据并通过 HTTP 提供服务的问题，API 可以是解决问题的方法。为了使其工作，您将需要编写一个回调插件，与 Elasticsearch 实例交互并索引 JSON 数据，然后可以通过 API 提供服务。Python 提供了一个名为`pyes`的库，用于与 Elasticsearch 实例交互。

让我们将回调插件命名为`loges.py`，并将其存储在 Ansible play 根目录中的`callback_plugins`目录中，如下面的代码所示：

```
from pyes import *
import json

# Change this to your Elasticsearch URL
ES_URL = '10.3.10.183:9200'

def index_elasticsearch(host, result):
    '''  index results in elasticsearch '''
    # Create connection object to Elasticsearch instance
    conn = ES(ES_URL)
    # Create index 'infra' if not present. Used for the first function call
    if not conn.indices.exists_index('infra'):
        conn.indices.create_index('infra')
    # Index results in Elasticsearch.
    # infra: index name
    # dmidecode: document type
    # host: ID
    conn.index(result, 'infra', 'dmidecode', host)
    print 'Data added to Elasticsearch'

class CallbackModule(object):
    ''' 
    This adds the result JSON to ElasticSearch database
    '''
    def runner_on_ok(self, host, result):
        try:
            if result['var']['dmi_data[\'msg\']']:
                index_elasticsearch(host, result['var']['dmi_data[\'msg\']'])
        except:
            pass
```

创建了这个回调插件之后，如果您运行 Ansible play `dmidecode.yaml`，在成功运行后，JSON 输出将被索引到 Elasticsearch 实例中，并且应该可以通过 API 访问。数据将被索引到名为`infra`的索引中，文档类型为`dmidecode`。每个索引的文档都将有一个唯一的 ID，在这种情况下，将是`Hostname`或`IP`，取决于适用的情况。

# 创建刚启动实例的动态清单

Ansible playbook，甚至是单独的模块，通常针对清单文件中常指定的目标主机执行。它们最基本的用途是拥有一个静态清单文件（例如 hosts），其中包含要执行 Ansible play 的所有目标主机 IP 或主机名的列表。然而，在现实世界中，事情可能并不是这么简单。例如，您可能需要在云上启动一个新实例 - 比如 OpenStack 或 AWS - 或启动一个基本的虚拟机，然后使用 Ansible playbook 部署您的应用程序。在这种情况下，目标 IP 在实例启动之前是未知的，因此静态清单文件将无法达到目的。

以编程方式运行 Ansible 并使用 Ansible API 的主要好处之一是处理运行时变量，比如这种情况下的目标 IP。这是一个场景，您可以充分利用 Python API 来运行 Ansible playbook，同时创建一个动态清单。

为了生成动态清单文件，可以使用 Jinja2 模板。Jinja2 完全受 Ansible 支持，可以用于创建任何您想要的模板。Jinja2 本身是一个广泛的主题，无法在本书的范围之内详细介绍。然而，这个特定的场景将涉及 Jinja2 以及如何与 Ansible 一起使用。在上述情况下，Jinja2 模板将用于在运行时渲染清单文件。

让我们重新访问第四章中的示例，*探索 API*，在那里一个 Ansible playbook，`webserver.yaml`，在一个清单文件`hosts`上被以编程方式执行。与第四章中的示例相反，下面的示例中清单文件将在运行时渲染。这在执行端到端自动化时非常方便，从启动实例到部署应用程序。

```
from ansible.playbook import PlayBook
from ansible.inventory import Inventory
from ansible import callbacks
from ansible import utils

import jinja2
from tempfile import NamedTemporaryFile
import os

# Boilerplace callbacks for stdout/stderr and log output

utils.VERBOSITY = 0
playbook_cb = callbacks.PlaybookCallbacks(verbose=utils.VERBOSITY)
stats = callbacks.AggregateStats()
runner_cb = callbacks.PlaybookRunnerCallbacks(stats, verbose=utils.VERBOSITY)

# [Mock] Launch instance and return instance IP

def launch_instance(number):
    '''
    Launch instances on OpenStack and return a list of instance IPs

    args:
        number: Number of instances to launch
    return:
        target: List containing IPs of launched instances

    This is a dummy function and does not contain code for launching instances
    Launching an instance on OpenStack, AWS or a virtual machine is beyond the
    scope of this book. The example focuses on creating a dynamic inventory
    file to be used by Ansible.
    '''
    # return 2 IPs as the caller requested launching 2 instances.
    target = ['192.168.10.20', '192.168.10.25']
    return target

# Dynamic Inventory

inventory = """ 
[remote]
{% for elem in public_ip_address  %}
{{ elem }}
{% endfor %}
"""
target = launch_instance(2)
inventory_template = jinja2.Template(inventory)
rendered_inventory = inventory_template.render({
    'public_ip_address' : target
})

# Create a temporary file and write the template string to it
hosts = NamedTemporaryFile(delete=False)
hosts.write(rendered_inventory)
hosts.close()

pb = PlayBook(
    playbook = 'webserver.yaml',
    host_list = hosts.name,
    remote_user = 'rdas',
    stats = stats,
    callbacks=playbook_cb,
    runner_callbacks=runner_cb,
    private_key_file='id_rsa.pem'
)

results = pb.run()

playbook_cb.on_stats(pb.stats)

print results
```

在上面的示例中，`launch_instance`函数仅用于表示可以启动实例或虚拟机的一些代码。当调用该函数时，它返回与启动实例关联的 IP 列表。返回的列表被缓存在一个变量`target`中，然后用于渲染清单文件。以下代码部分...：

```
inventory = """ 
[remote]
{% for elem in public_ip_address  %}
{{ elem }}
{% endfor %}
"""
```

...是由以下代码渲染的 Jinja2 模板：

```
inventory_template = jinja2.Template(inventory)
rendered_inventory = inventory_template.render({
    'public_ip_address' : target
})
```

然后使用以下代码将渲染的清单写入临时文件：

```
hosts = NamedTemporaryFile(delete=False)
hosts.write(rendered_inventory)
hosts.close()
```

这将在运行时创建一个包含目标机器 IP 的清单文件（新启动的实例），这些 IP 是由`launch_instance`方法返回的。

# 通过堡垒主机使用 Ansible

在现实世界中，生产服务器通常配置为阻止来自其私有网络之外的 SSH 连接。这是为了减少可能的攻击向量的数量，同时将访问点保持在最低限度。这有助于限制访问，创建更好的日志记录，并增加安全性。这是一种常见的安全实践，通过使用堡垒主机来实现。

堡垒主机专门设计用来抵御攻击。通常，堡垒主机只运行一个服务。其他服务要么被移除，要么被禁用，以最小化威胁。

在这种情况下，有了堡垒主机，Ansible 无法直接从控制节点 SSH 到目标主机。它需要通过堡垒主机代理其命令，以便到达目标机器。

要实现这一点，您只需要修改 Ansible 播放根目录中的三个文件：

+   `hosts`：清单文件

+   `ansible.cfg`：Ansible 的配置文件

+   `ssh.cfg`：SSH 配置

清单文件包括一个名为`bastion`的组，以及通常的目标主机。以下代码是一个示例清单`hosts`文件：

```
[bastion]
10.68.214.8

[database_servers]
172.16.10.5
172.16.10.6
```

由于 Ansible 几乎在所有操作中都使用 SSH，下一步是配置 SSH。SSH 本身允许我们根据需求自定义设置。要为特定的 Ansible play 配置 SSH，你需要在 Ansible playbook 的根目录中创建一个`ssh.cfg`文件，内容如下：

```
Host 172.16.*
  ProxyCommand  ssh -q -A rdas@10.68.214.8 nc %h:%p
Host *
  ControlMaster    auto
  ControlPath    ~/.ssh/mux-%r@%h:%p
  ControlPersist    15m
```

上述 SSH 配置将通过我们的堡垒主机`10.68.214.8`代理到网络`172.16.*`中的所有节点的所有命令。控制设置`ControlPersist`允许 SSH 重用已建立的连接，从而提高性能并加快 Ansible playbook 的执行速度。

现在 SSH 已配置好，你需要告诉 Ansible 使用这个 SSH 配置。为此，你需要在 Ansible play 的根目录中创建一个`ansible.cfg`文件，内容如下：

```
[ssh_connection]
ssh_args = -F ssh.cfg
control_path = ~/.ssh/mux-%r@%h:%p
```

Ansible 现在将使用上述配置来使用`ssh.cfg`作为 SSH 配置文件，因此通过堡垒主机代理命令。

# 快乐的管理者=快乐的你

到目前为止，本章已经讨论了如何实施 Ansible 进行管理、部署和配置。好吧，还有一个问题仍然存在 - 报告。

在长时间的 playbook 执行结束时，你可能已经部署了应用程序，也可能已经有了基础设施的审计数据，或者 playbook 设计的任何其他内容。此外，你可能还有 playbook 执行的日志。然而，假设在一天结束时，有人要求你提供一个报告。现在你必须坐下来创建报告，并填写 Excel 电子表格，因为这是你的经理要求的 - 对事物状态的概述。这也是可以通过扩展 Ansible 再次实现的事情。

所以，你运行了一个 playbook，得到的是`stdout`上的运行日志。现在的问题是：如何将其制作成 Excel 报告？是的，你猜对了 - 回调插件来拯救你。你可以编写自己的自定义回调插件，可以帮助你记录 Ansible play 的结果并创建电子表格。这将减少手动创建报告的工作量。

报告可能因不同的用例而异，因为没有一个报告适用于所有情况。因此，你将不得不为你想要生成的不同类型的报告编写回调插件。有些人喜欢基于 HTML 的报告，而有些人喜欢 Excel 电子表格。

以下示例重用了来自第三章的`dmidecode`模块，*深入了解 Ansible 模块*。该模块用于生成 JSON 输出，非常适合机器处理。然而，JSON 并不是人们愿意手动阅读报告的格式。将数据表示为 Excel 电子表格更有意义，因为将报告创建为电子表格更易于阅读，并能一目了然地呈现完整的图片。即使是非技术背景的人也可以轻松地从 Excel 表中读取数据。

以下是一个回调模块，它创建一个 Excel 表格，读取执行`dmidecode`模块生成的 JSON 输出，并将每个主机的数据追加到 Excel 电子表格中。它是用 Python 编写的，并使用`openpyxl`库来创建 Excel 电子表格。

```
#!/bin/python
import openpyxl
import json
import os

PATH = '/tmp'

def create_report_file():
    ''' Create the initial workbook if not exists
    '''
    os.chdir(PATH)
    wb = openpyxl.Workbook()
    sheet = wb.get_active_sheet()
    sheet.title = 'Infrastructure'
    sheet['A1'] = 'Machine IP'
    sheet['B1'] = 'Serial No'
    sheet['C1'] = 'Manufacturer'
    fname = 'Infra-Info.xlsx'
    wb.save(fname)
    return fname

def write_data(host, serial_no, manufacturer):
    ''' Write data to Excel '''
    os.chdir(PATH)
    wb = openpyxl.load_workbook('Infra-Info.xlsx')
    sheet = wb.get_sheet_by_name('Infrastructure')
    rowNum = sheet.max_row + 1 
    sheet.cell(row=rowNum, column=1).value = host
    sheet.cell(row=rowNum, column=2).value = serial_no
    sheet.cell(row=rowNum, column=3).value = manufacturer
    wb.save('tmp-Infra-Info.xlsx')

def rename_file():
    os.chdir(PATH)
    os.remove('Infra-Info.xlsx')
    os.rename('tmp-Infra-Info.xlsx', 'Infra-Info.xlsx')

def extract_data(host, result_json):
    ''' Write data to the sheet
    '''
    serial_no = result_json['Hardware Specs']['System']['Serial Number']
    manufacturer = result_json['Hardware Specs']['System']['Manufacturer']
    if not os.path.exists('/tmp/Infra-Info.xlsx'):
        create_report_file()
    write_data(host, serial_no, manufacturer)
    rename_file()

class CallbackModule(object):

    def runner_on_ok(self, host, result):
        try:
            if result['var']['dmi_data[\'msg\']']:
                extract_data(host, result['var']['dmi_data[\'msg\']'])
        except:
            pass
```

前面的回调模块只是一个示例，展示了如何将数据表示为 Excel 电子表格并生成报告。可以根据需要扩展回调模块以填写更多细节。前面的模块只添加了主机、序列号和主机制造商。

请注意，由于上述回调模块将数据追加到同一 Excel 电子表格中，因此 Ansible 应该一次执行一个主机的任务。因此，您应该将 fork 设置为`1`。

这可以通过使用`--forks`标志来实现。以下代码片段展示了 Ansible playbook 的执行方式：

```
**ansible-playbook -i hosts dmidecode.yaml --forks 1**

```

这是生成的 Excel 报告：

![快乐的经理=快乐的你](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-asb/img/B04624_07_01.jpg)

# 摘要

本章带领您走过了各种真实场景，展示了 Ansible 的用途以及如何扩展 Ansible 以满足您的需求。本章从 Ansible 的基础知识开始，比如定义角色和使用标签。然后逐渐深入到更复杂的场景，构建在前几章的示例基础上。本章还包括了一个非常常见的场景，即 Ansible 需要自定义配置以通过堡垒主机代理任务。本章还让您了解了如何利用 Ansible 来自动化一些例行任务，比如报告。

总的来说，本章结合了前几章学到的知识，并提供了相同知识的真实场景和用例。
