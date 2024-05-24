# C# 和 .NET Core 测试驱动开发（三）

> 原文：[`zh.annas-archive.org/md5/32CD200F397A73ED943D220E0FB2E744`](https://zh.annas-archive.org/md5/32CD200F397A73ED943D220E0FB2E744)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：持续集成和项目托管

在第四章中，我们探讨了.NET Core 和 C#可用的各种单元测试框架，然后详细探讨了 xUnit.net 框架。然后我们转向第五章中的数据驱动单元测试，这有助于创建可以使用来自不同数据源加载的数据执行的单元测试。在第六章中，我们详细解释了依赖项模拟，其中我们通过*Moq 框架*创建了模拟对象。

有效的 TDD 实践可以帮助提供有用和深刻的反馈，评估软件项目的代码库质量。通过持续集成，构建自动化和代码自动化测试的过程被提升到了一个新的水平，允许开发团队充分利用现代源代码版本控制系统中提供的基本和高级功能。

正确的持续集成设置和实践会产生有益的持续交付，使软件项目的开发过程能够在项目的生命周期中被交付或部署到生产环境。

在本章中，我们将探讨持续集成和持续交付的概念。本章将涵盖以下主题：

+   持续集成

+   持续交付

+   GitHub 在线项目托管

+   基本的 Git 命令

+   配置 GitHub WebHooks

+   TeamCity 持续集成平台

# 持续集成

**持续集成**（**CI**）是软件开发实践，软件项目的源代码每天由软件开发团队的成员集成到存储库中。最好在开发过程的早期阶段开始。代码集成通常由 CI 工具执行，该工具使用自动构建脚本对代码进行验证。

在开发团队中，通常有多个开发人员在项目的不同部分上工作，项目的源代码托管在存储库中。每个开发人员可以在他们的计算机上拥有主分支或主线的本地版本或工作副本。

负责某个功能的开发人员会对本地副本进行更改，并使用一组准备好的自动化测试来测试代码，以确保代码能够正常工作并不会破坏任何现有的工作功能。一旦可以验证，本地副本将更新为存储库中的最新版本。如果更新导致任何冲突，这些冲突需要在最终提交或集成工作之前解决。

源代码存储库通过保留源文件的快照和版本以及随时间所做的更改，有助于充分对项目的代码库进行版本控制。开发人员可以在必要时恢复或检出以前的提交版本。存储库可以在团队基础设施上本地托管，例如拥有现场**Microsoft Team Foundation Server**或云存储库，例如**GitHub**、**Bitbucket**和其他许多存储库。

# CI 工作流

CI 要求建立适当的工作流程。CI 的第一个重要组成部分是建立一个可工作的源代码存储库。这是为了跟踪项目贡献者所做的所有更改，并协调不同的活动。

为了实现一个稳健和有效的 CI 设置，需要涵盖并正确设置以下领域。

# 单一的源代码存储库

为了有效地使用源代码存储库，所有成功构建项目的所需文件都应该放在一个单一的源代码存储库中。这些文件应该包括源文件、属性文件、数据库脚本和架构，以及第三方库和使用的资产。

其他配置文件也可以放在存储库中，特别是开发环境配置。这将确保项目上的开发人员拥有一致的环境设置。开发团队的新成员可以轻松地使用存储库中可用的配置来设置他们的环境。

# 构建自动化

CI 工作流程的构建自动化步骤是为了确保项目代码库中的更改被检测并自动进行测试和构建。构建自动化通常是通过构建脚本完成的，这些脚本分析需要进行的更改和编译。源代码应该经常构建，最好是每天或每晚。提交的成功与否是根据代码库是否成功构建来衡量的。

构建自动化脚本应该能够在有或没有测试的情况下构建系统。这应该在构建中进行配置。无论开发人员的集成开发环境是否具有内置的构建管理，都应该在服务器上配置一个中央构建脚本，以确保项目可以构建并在开发服务器上轻松运行。

# 自动化测试

代码库应该具有自动化测试，覆盖了大部分可能的测试组合，使用相关的测试数据。自动化测试应该使用适当的测试框架，可以覆盖软件项目的所有层或部分。

通过适当的自动化测试，源代码中的错误可以在自动化构建脚本运行时轻松被检测到。将自动化测试整合到构建过程中将确保良好的测试覆盖率，并提供失败或通过测试的报告，以便便于重构代码。

# 相同的测试和生产环境

为了确保顺利的 CI 体验，重要的是要确保测试和生产环境是相同的。两个环境应该具有类似的硬件和操作系统配置，以及环境设置。

此外，对于使用数据库的应用程序，测试和生产环境应该具有相同的版本。运行时和库也应该是相似的。然而，有时可能无法在每个生产环境实例中进行测试，比如桌面应用程序，但必须确保在测试中使用生产环境的副本。

# 每日提交

代码库的整体健康状况取决于成功运行的构建过程。项目的主干应该经常更新，以便开发人员提交。提交代码的开发人员有责任确保在推送到存储库之前对代码进行测试。

在开发人员的提交导致构建失败的情况下，不应该拖延。可以回滚以在提交更改之前独立修复问题。项目的主干或主分支应该始终保持良好状态。通常更喜欢每日提交更改。

# CI 的好处

将 CI 纳入开发流程中对开发团队非常有价值。CI 流程提供了许多好处，下面将解释其中一些。

# 快速发现错误

通过 CI 流程，自动化测试经常运行，可以及时发现并修复错误，从而产生高质量的健壮系统。CI 不会自动消除系统中的错误；开发人员必须努力编写经过充分测试的清洁代码。然而，CI 可以促进及时发现本来可能会进入生产环境的错误。

# 提高生产力

通过 CI，开发团队的整体生产力可以得到提高，因为开发人员可以摆脱单调或手动的任务，这些任务已经作为 CI 过程的一部分自动化了。开发人员可以专注于开发系统的功能。

# 降低风险

有时，由于固有的复杂性，软件项目往往会因为对需求的低估和其他问题而超出预算和时间表。CI 可以帮助减少与软件开发相关的风险。通过频繁的代码提交和集成，可以建立项目状态的更清晰的图像，并且可以轻松地隔离和处理任何潜在问题。

# 促进持续交付

对于使用 CI 的开发团队，持续或频繁的部署变得相对容易。这是因为新功能或需求可以快速交付和部署。这将允许用户对产品提供充分和有用的反馈，这可以用来进一步完善软件并提高质量。

# CI 工具

有许多可用的 CI 工具，每个工具都具有不同的功能，可以促进简单的 CI 并为部署流水线提供良好的结构。选择 CI 工具取决于几个因素，包括：

+   开发环境、程序语言、框架和应用架构

+   开发团队的构成、经验水平、技能和能力

+   部署环境设置、操作系统和硬件要求

接下来将解释一些流行和最常用的 CI 工具。这些 CI 工具在有效使用时可以帮助开发团队在软件项目中达到质量标准。

# 微软 Team Foundation Server

微软**Team Foundation Server**（**TFS**）是一个集成的服务器套件，包含一组协作工具，以提高软件开发团队的生产力。TFS 提供可以与 IDE（如**Visual Studio**、**Eclipse**等）集成的工具和代码编辑器。

TFS 提供了一套工具和扩展，可以促进流畅的 CI 过程。使用 TFS，可以自动化构建、测试和部署应用程序。TFS 通过支持各种编程语言和源代码存储库，提供了很大的灵活性。

# TeamCity

**TeamCity**是 JetBrains 的企业级 CI 工具。它支持捆绑的.NET CLI，并且与 TFS 类似，它提供了自动化部署和组合构建的支持。TeamCity 可以通过 IDE 的可用插件在服务器上验证和运行自动化测试，然后再提交代码。

# Jenkins

**Jenkins**是一个开源的 CI 服务器，可以作为独立运行或在容器中运行，或通过本地系统包安装。它是自包含的，能够自动化测试、构建相关任务和应用部署。通过一组链式工具和插件，Jenkins 可以与 IDE 和源代码存储库集成。

# 持续交付

**持续交付**是 CI 的续篇或延伸。它是一组软件开发实践，确保项目的代码可以部署到与生产环境相同的测试环境。持续交付确保所有更改都是最新的，并且一旦更改通过自动化测试，就可以立即发货和部署到生产环境。

众所周知，实践 CI 将促进团队成员之间的良好沟通，并消除潜在风险。开发团队需要进一步实践持续交付，以确保他们的开发活动对客户有益。这可以通过确保应用程序在开发周期的任何阶段都可以部署和准备好生产来实现。

通过开发团队成员的有效沟通和协作，可以实现持续交付。这要求应用程序交付过程的主要部分通过开发和完善的部署管道进行自动化。在任何时候，正在开发的应用程序都应该可以部署。产品所有者或客户将确定应用程序何时部署。

# 持续交付的好处

通过持续交付，可以提高软件开发团队的生产率，同时降低将软件应用程序发布到生产环境的成本和周转时间。以下是您的团队应该实践持续交付的原因。

# 降低风险

类似于 CI，持续交付有助于降低通常与软件发布和部署相关的风险。这可以确保零停机和应用程序的高可用性，因为经常进行的更改会定期集成并准备投入生产。

# 质量软件产品

由于测试、构建和部署过程的自动化，软件产品可以很快地提供给最终用户。用户将能够提供有用和宝贵的反馈意见，这些意见可以用来进一步完善和提高应用程序的质量。

# 降低成本

由于开发和部署过程的不同部分自动化，软件项目开发和发布成本可以大大降低。这是因为与增量和持续变更相关的成本被消除。

# GitHub 在线项目托管

GitHub 是一个源代码托管平台，用于版本控制，允许开发团队成员协作和开发软件项目，无论他们的地理位置在哪里。GitHub 目前托管了多个不同编程语言的开源和专有项目。

GitHub 提供了基本和高级功能，使协作变得更加容易。它本质上是一个基于 Web 的源代码存储库或托管服务，使用 Git 作为版本控制系统，基于 Git 的分布式版本控制行为。

有趣的是，像**Microsoft**、**Google**、**Facebook**和**Twitter**这样的顶级公司在 GitHub 上托管他们的开源项目。基本上，任何 CI 工具都可以与 GitHub 一起使用。这使得开发团队可以根据预算选择 CI 工具。

除了 GitHub 提供的源代码托管服务外，还可以通过 GitHub 免费托管公共网页。这个功能允许 GitHub 用户创建与托管的开源项目相关的个人网站。

GitHub 支持公共和私人项目存储库托管。任何人都可以查看公共存储库的文件和提交历史，而私人存储库的访问仅限于添加的成员。GitHub 上的私人存储库托管是需要付费的。

# 项目托管

要创建项目存储库并使用 GitHub 的功能，您需要首先创建一个 GitHub 帐户。这可以通过访问[`github.com`](https://github.com)来完成。成功创建帐户后，您可以继续创建项目存储库。

GitHub 存储库用于组织项目文件夹、文件和资产。文件可以是图像、视频和源文件。在 GitHub 中，存储库通常会有一个包含项目简要描述的`README`文件。还可以向项目添加软件许可文件。

以下步骤描述了如何在 GitHub 中创建一个新存储库：

1.  使用创建的帐户登录 GitHub。

1.  转到[`github.com/`](https://github.com/)的新页面，或者在屏幕右上角，账户的头像或个人资料图片旁边，单击+图标。

1.  会显示一个下拉菜单，您可以在其中选择新存储库：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/cae41656-4b6d-42cb-95b1-463cdab802b9.png)

1.  将存储库命名为 `LoanApplication` 并提供项目描述。

1.  选择公共，使存储库可以公开访问。

1.  选择使用 README 初始化此存储库，以在项目中包括 `README` 文件。

1.  最后，单击创建存储库以创建和初始化存储库：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/1783a922-7346-4ca5-bd3f-e8f17e64633c.png)

# 使用 GitHub Flow 进行分支

GitHub 有一个基于分支的工作流程，称为**GitHub Flow**，为开发团队提供了很好的支持和工具，以便频繁地协作和部署项目。

GitHub Flow 便于以下操作：

+   从新的或现有存储库创建分支

+   创建、编辑、重命名、移动或删除文件

+   根据约定的更改从分支发送拉取请求

+   根据需要在分支上进行更改

+   当分支准备好合并时合并拉取请求

+   通过在拉取请求或分支页面上使用删除按钮进行清理和清理分支

从项目创建分支是 Git 的核心，并且是 GitHub 流程的扩展，这是 GitHub Flow 的核心概念。**分支**用于尝试新概念和想法，或用于修复功能。分支是存储库的不同版本。

创建新分支时，通常的做法是从主分支创建分支。这将在那个时间点创建主分支中包含的所有文件和配置的副本。分支在技术上独立于主分支，因为在分支上进行的更改不会影响主分支。但是，可以从主分支拉取新的更新到分支，并且可以将在分支上进行的更更合并回主分支。

GitHub 上的以下图表进一步解释了项目分支的 GitHub 流程，其中对分支进行的提交更改通过拉取请求合并到主分支：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/0fc03b93-395a-45ac-af19-8d52984d823c.png)

主分支必须始终可以随时部署。创建的分支上的更改应该只在拉取请求打开后合并到主分支。更改将在通过必要的验证和自动化测试后进行仔细审查和接受。

要从之前创建的 `LoanApplication` 存储库创建新分支，请执行以下步骤：

1.  导航到存储库。

1.  单击位于文件列表顶部的下拉菜单，标题为分支：主。

1.  在新分支文本框中键入提供有关分支的有意义信息的描述性分支名称。

1.  单击带有分支名称的突出显示的链接以创建分支：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/ec790570-c4e7-4972-910e-f1777864c909.png)

目前，新创建的分支和主分支完全相同。您可以开始对创建的分支进行更改，添加和修改源文件。更改直接提交到分支而不是主分支。

提交更改有助于正确跟踪随时间对分支所做的更改。每次要提交更改时都会提供提交消息。提交消息提供了对更改内容的详细描述。始终提供提交消息很重要，因为 Git 使用提交跟踪更改。这可以便于在项目上进行轻松的协作，提交消息提供了更改历史记录。

在存储库中，每个提交都是一个独立的更改单元。如果由于提交而导致工作代码库中断，或者提交引入错误，可以回滚提交。

# 拉取请求

无论您对代码库所做的更改是小还是大，您都可以在项目开发过程中的任何时候发起拉取请求。拉取请求对于 GitHub 中的协作至关重要，因为它们促进了提交的讨论和审查。

要打开拉取请求，请单击“新拉取请求”选项卡。您将被带到拉取请求页面，在那里您可以为请求提供评论或描述，并单击“新拉取请求”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/2fee4803-9d87-4e08-afdc-6432e1c79df4.png)

当您发起拉取请求时，项目的所有者或维护者将收到有关待定更改和您意图进行合并的通知。在对分支所做的更改进行适当审查后，可以提供必要的反馈以进一步完善代码。拉取请求显示了文件的差异以及您的分支和主分支的内容。如果所做的贡献被认为是可以接受的，它们将被接受并合并到主分支中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/c82db3eb-38cd-403a-a9d8-cceb8bd5d7aa.png)

# 审查更改和合并

拉取请求发起后，参与的团队成员对更改进行审查，并根据存储库的当前位置提供评论。您可以在拉取请求保持打开状态时继续进行更改，并且与审查相关的任何评论都将显示在统一的拉取请求视图上。评论以 markdown 编写，包含预格式化的文本块、图像和表情符号。

一旦拉取请求经过审查并被接受，它们将被合并到主分支中。可以按以下步骤在 GitHub 中合并请求。单击“合并拉取请求”按钮将更改合并到主分支中。然后单击“确认合并”，这将将分支上的提交合并到主分支中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/ad16d568-f7cf-4473-88e2-7fd68cbedbca.png)

GitHub 中保存了拉取请求的历史记录，可以在以后进行搜索，以确定为什么发起了拉取请求，同时提供对已进行的审查和添加的评论的访问。

# 基本的 Git 命令

Git 是一种**分布式版本控制系统**（**DVCS**）。Git 的分支系统非常强大，使其在其他版本控制系统中脱颖而出。使用 Git，可以创建项目的多个独立分支。分支的创建、合并和删除过程是无缝且非常快速的。

Git 极大地支持无摩擦的上下文切换概念，您可以轻松地创建一个分支来探索您的想法，创建和应用补丁，进行提交，合并分支，然后稍后切换回您正在工作的早期分支。使用的分支工作流程将决定是否为每个功能或一组功能创建一个分支，同时在分支之间轻松切换以测试功能。

通过为生产、测试和开发设置不同的分支，您的开发可以得到组织并且高效，从而控制进入每个分支的文件和提交的流程。通过拥有良好的存储库结构，您可以轻松快速地尝试新的想法，并在完成后删除分支。

Git 具有丰富的有用命令集，掌握后可以完全访问其内部，并允许基本和高级源代码版本控制操作。Git 为 Windows、Macintosh 和 Linux 操作系统提供命令行界面和图形用户界面客户端。命令可以从 Mac 和 Linux 上的终端运行，而在 Windows 上有 Git Bash，用于从命令行运行 Git 的仿真器。

Git 上的可用命令用于执行源代码存储库的初始设置和配置，共享和更新项目，分支和合并，以及各种与源代码版本控制相关的操作。

# 配置命令

有一组命令可用于配置用户信息，这些命令跨越安装了 Git 的计算机上的所有本地存储库。`git config`命令用于获取和设置全局存储库选项。它接受`--global`选项，后跟要从全局`.gitconfig`文件中获取或设置的特定配置。

要设置将附加到所有提交事务的全局用户名，请运行以下命令：

```cs
git config --global user.name "[name]"
```

也可以设置全局用户电子邮件地址。这将将设置的电子邮件地址附加到所有提交事务。运行以下命令来实现这一点：

```cs
git config --global user.email "[email address]"
```

为了美观，可以使用以下命令启用命令行输出的颜色：

```cs
git config --global color.ui auto
```

# 初始化存储库命令

`git init` 命令用于创建一个空的 Git 存储库，以及重新初始化现有存储库。运行`git init` 命令时，会创建一个`.git` 目录，以及用于保存对象、`refs/heads`、`refs/tags`、模板文件和初始 HEAD 文件的子目录，该文件引用主分支的 HEAD。在其最简单的形式中，`git init` 命令传递存储库名称，这将创建一个具有指定名称的存储库：

```cs
git init [repository-name]
```

要更新并选择新添加的模板或将存储库重新定位到另一个位置，可以在现有存储库中重新运行`git init`。该命令不会覆盖存储库中已有的配置。完整的`git init` 命令概要如下：

```cs
git init [-q | --quiet] [--bare] [--template=<template_directory>] 
 [--separate-git-dir <git dir>]  [--shared[=<permissions>]] [directory] 
```

让我们详细讨论前面的命令：

+   当使用`-q` 或 `--quiet` 选项时，将打印错误和警告消息，而其他输出消息将被抑制。

+   `--bare` 选项用于创建一个裸存储库。

+   `--template=<template_directory>` 用于指定要使用模板的文件夹。

+   `--separate-git-dir=<git dir>` 用于指示存储库的目录或路径，或者在重新初始化的情况下，移动存储库的路径。

+   `--shared[=(false|true|umask|group|all|world|everybody|0xxx)]` 选项用于通知 Git 存储库将被多个用户共享。属于同一组的用户可以推送到存储库中。

使用`git clone` 命令，可以将现有存储库克隆到新目录中。该命令为克隆存储库中的所有分支创建远程跟踪分支。它将下载项目及其整个版本历史。`git clone` 命令可以通过传递存储库的 URL 作为选项来简单使用：

```cs
git clone [url]
```

传递给命令的 URL 将包含传输协议的信息、远程服务器的地址和存储库路径。Git 支持的协议有 SSH、Git、HTTP 和 HTTPS。该命令还有其他选项可以传递给它，以配置要克隆的存储库。

# 更改命令

Git 有一组有用的命令，用于检查存储库中文件的状态，审查对文件所做的更新，并提交对项目文件所做的更改。

`git status` 命令用于显示存储库的工作状态。该命令基本上提供了已更改并准备提交的文件的摘要。它显示了当前 HEAD 提交和索引文件之间存在差异的文件路径。它还显示了索引文件和工作树之间存在差异的文件路径，以及当前未被 Git 跟踪但未在`.gitignore` 文件中添加的文件路径：

```cs
git status
```

`git add` 命令使用工作树中找到的内容来更新索引。它基本上是将文件内容添加到索引中。它用于添加现有路径的当前内容。它可以用于删除树中不再存在的路径，或者添加工作树中所做更改的部分内容。

通常的做法是在执行提交之前多次运行该命令。它会添加文件的内容，就像在运行命令时的那样。它接受用于调整其行为的选项：

```cs
git add [file]
```

`git commit` 命令用于将索引的内容与用户提供的提交消息一起记录或存储到提交中，以描述对项目文件所做的更改。在运行该命令之前，必须使用`git add` 添加更改。

该命令灵活，使用允许不同的选项来记录更改。一种方法是将具有更改的文件列为提交命令的参数，这会告诉 Git 忽略在索引中暂存的更改，并存储列出的文件的当前内容。

此外，可以使用`-a`开关与该命令一起使用，以添加索引中列出但不在工作树中的所有文件的更改。开关`-m`用于指定提交消息：

```cs
git commit -m "[commit message]"
```

有时，希望显示索引和工作树之间的差异或更改，两个文件或 blob 对象之间可用的更改。`git diff`命令用于此目的。当传递`--staged`选项给命令时，Git 显示暂存和最后一个文件版本之间的差异：

```cs
git diff
```

`git rm`命令从工作树和索引中删除文件。要删除的文件作为命令的选项传递。作为参数传递给命令的文件将从工作目录中删除并标记为删除。当传递`--cached`选项给命令时，Git 不会从工作目录中删除文件，而是从版本控制中删除它：

```cs
git rm [files]
```

`git reset`命令可用于取消暂存并保留已在存储库中暂存的文件的内容。该命令用于将当前`HEAD`重置为指定状态。此外，它还可以根据指定的选项修改索引和工作树。

该命令有三种形式。第一和第二种形式用于从树复制条目到索引，而最后一种形式用于将当前分支`HEAD`设置为特定提交：

```cs
git reset [-q] [<tree-ish>] [--] <paths>…​
git reset (--patch | -p) [<tree-ish>] [--] [<paths>…​]
git reset [--soft | --mixed [-N] | --hard | --merge | --keep] [-q] [<commit>]
```

# 分支和合并命令

`git branch`命令是 Git 版本控制系统的核心。它用于在存储库中创建、移动、重命名、删除和列出可用的分支。该命令有几种形式，并接受用于设置和配置存储库分支的不同选项。在 Bash 上运行`git branch`命令，不指定选项时，将列出存储库中可用的分支。这类似于使用`--list`选项。

要创建一个新分支，使用`git branch`命令并将分支名称作为参数运行：

```cs
git branch [branch name]
```

`--delete`选项用于删除指定的分支，`--copy`选项用于创建指定分支的副本以及其`reflog`。

要将工作树或分支中的文件更新为另一个工作树中可用的内容，使用`git checkout`命令。该命令用于切换分支或恢复工作树文件。与`git branch`类似，它有几种形式并接受不同的选项。

当使用分支名称作为参数运行该命令时，Git 切换到指定的分支，更新工作目录，并将 HEAD 指向该分支：

```cs
git checkout [branch name]
```

如前一节所述，分支概念允许开发团队尝试新想法，并从现有项目创建新版本。分支的美妙之处在于能够将一个分支的更改合并到另一个分支中，实质上是将分支或开发线连接或合并在一起。

在 Git 中，`git merge`命令用于将从一个分支创建的开发分支集成到单个分支中。例如，如果有一个从主分支创建的开发分支来测试某个功能，当运行`git merge [分支名称]`命令时，Git 将追溯对该分支所做的更改。这是因为它是从主分支分出的，直到最新的分支，并将这些更改存储在主分支上的新提交中：

```cs
git merge [branch name]
git merge --abort
git merge -- continue
```

经常，合并过程可能会导致不同分支的文件之间发生冲突。运行`git merge --abort`命令将中止合并过程并将分支恢复到合并前的状态。解决了遇到的冲突后，可以运行`git merge --continue`重新运行合并过程。

# 配置 GitHub WebHooks

**WebHook**是通过 HTTP POST 传递的事件通知。WebHook 通常被称为 Web 回调或 HTTP 推送 API。WebHook 提供了一种机制，应用程序可以实时将数据传递给其他应用程序。

WebHook 与常规 API 不同之处在于，它没有通过轮询数据来获取最新数据的持续资源利用。当数据可用时，订阅者或消费应用程序将通过已在 WebHook 提供程序注册的 URL 接收数据。WebHook 对数据提供程序和消费者都是有效且高效的。

# 消费 WebHooks

要从 WebHook 接收通知或数据，消费应用程序需要向提供程序注册一个 URL。提供程序将通过 POST 将数据传递到 URL。URL 必须从网络公开访问并可达。

WebHook 提供程序通常通过 HTTP POST 以 JSON、XML 或作为多部分或 URL 编码的表单数据的形式传递数据。订阅者 URL 上的 API 的实现将受到 WebHook 提供程序使用的数据传递模式的影响。

经常会出现需要调试 WebHooks 的情况。这可能是为了解决错误。由于 WebHooks 的异步性质，有时可能会有挑战。首先，必须理解来自 WebHook 的数据。可以使用能够获取和解析 WebHook 请求的工具来实现这一点。根据对 WebHook 数据结构和内容的了解，可以模拟请求以测试 URL API 代码以解决问题。

在从 WebHook 消费数据时，重要的是要注意安全性，并将其纳入消费应用程序的设计中。因为 WebHook 提供程序将 POST 数据到的回调 URL 是公开可用的，所以可能会受到恶意攻击。

一种常见且简单的方法是在 URL 中附加一个强制身份验证令牌，每次请求都将对其进行验证。还可以围绕 URL 构建基本身份验证，以在接受和处理数据之前验证发起 POST 的一方。或者，如果请求签名已经在提供程序端实现，提供程序可以对每个 WebHook 请求进行签名。每个发布的请求的签名将由消费者进行验证。

根据订阅者生成事件的频率，WebHooks 可能会引发大量请求。如果订阅者未能正确设计以处理这样大量的请求，这可能会导致资源利用率高，无论是带宽还是服务器资源。当资源被充分利用并用完时，消费者可能无法处理更多请求，导致消费应用程序的拒绝服务。

# GitHub WebHook

在 GitHub 中，WebHooks 用作在事件发生时向外部 Web 服务器发送通知的手段。GitHub WebHooks 允许您设置托管在 GitHub 上的项目以订阅[www.github.com](http://www.github.com)平台上可用的所需事件。当事件发生时，GitHub 将向配置的端点发送有效负载。

WebHooks 可以在任何存储库或组织级别进行配置。成功配置后，每当触发订阅的事件或操作时，WebHook 都将被触发。GitHub 允许为存储库或组织的每个事件创建多达 20 个 WebHooks。安装后，WebHooks 可以在存储库或组织上触发。

# 事件和负载

在 GitHub 的 WebHook 配置点，您可以指定要从 GitHub 接收请求的事件。GitHub 中的 WebHook 请求数据称为有效负载。最好只订阅所需数据的事件，以限制从 GitHub 发送到应用程序服务器的 HTTP 请求。默认情况下，即使在 GitHub 上创建的 WebHook 也订阅了`push`事件。事件订阅可以通过 GitHub Web 或 API 进行修改。

以下表格中解释了 GitHub 上可订阅的一些可用事件：

| **事件** | **描述** |
| --- | --- |
| `push` | 这是默认事件，当对存储库进行 Git 推送时引发。这还包括通过更新引用的 API 操作进行的编辑标签或分支和提交 |
| `create` | 每当创建分支或标签时引发。 |
| `delete` | 每当删除分支或标签时引发。 |
| `issues` | 每当分配问题，取消分配，加标签，取消标签，打开，编辑，里程碑，取消里程碑，关闭或重新打开时引发。 |
| `repository` | 每当创建，删除（仅限组织挂钩），存档，取消存档，公开或私有化存储库时引发。 |
| `*` | 这是通配符事件，表示应通知 URL 以获取任何事件。 |

GitHub 上所有可用事件的完整列表可在[`developer.github.com/webhooks/`](https://developer.github.com/webhooks/)上找到。

`push`事件具有包含更详细信息的有效负载。GitHub 中的每个事件都具有特定的有效负载格式，用于描述该事件所需的信息。除了特定于事件的特定字段外，每个事件在有效负载中都包括触发事件的用户或发送者。

有效负载还包括发生事件的存储库或组织以及与事件相关的应用程序。有效负载大小不能超过 5 MB。产生有效负载大小超过 5 MB 的事件将不会触发。传递到 URL 的有效负载通常包含几个标头，其中一些在以下表格中进行了解释。创建新 WebHook 时，GitHub 会向配置的 URL 发送 ping，作为 WebHook 配置成功的指示：

| **标题** | **描述** |
| --- | --- |
| `User-Agent` | 发起请求的用户代理。这将始终具有前缀`Github-Hookshot`。 |
| `X-GitHub-Event` | 包含触发交付的事件名称。 |
| `X-GitHub-Delivery` | 用于标识交付的 GUID。 |
| `X-Hub-Signature` | 此标头包含响应正文的 HMAC 十六进制摘要。如果 WebHook 配置了密钥，则将发送此标头。标头的内容使用`sha1 hash`函数和密钥作为 HMAC 密钥生成。 |

# 设置您的第一个 WebHook

要配置 WebHook，我们将使用之前创建的`LoanApplication`存储库。单击存储库的设置页面，单击 Webhooks，然后单击添加 Webhook：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/ec26cece-7d41-4bc6-95a3-bfca75bf8c3b.png)

GitHub 将要求您对操作进行身份验证。提供您的 GitHub 帐户密码以继续。将加载 WebHook 配置页面，在那里您可以配置 WebHook 的选项：

1.  在有效负载 URL 字段中，提供 Web 应用程序服务器的端点。由于我们将从 Visual Studio 运行`LoanApplication`，我们将使用以下 URL：`http://localhost:54113/API/webhook`。

1.  将内容类型下拉菜单更改为 application/json，以允许 GitHub 通过 POST 以 JSON 发送有效负载。

1.  接下来，选择“让我选择单个事件”选项。这将显示所有可用 WebHook 事件的完整列表。

1.  选择您希望 WebHook 订阅的事件。

1.  最后，单击**添加 Webhook**按钮，完成配置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/b97675f1-e44e-42a9-8f1b-ba2fb96c5776.png)

创建 WebHook 后，GitHub 将尝试向 WebHook 中配置的 URL 发送 ping。指定的 URL `http://localhost:54113/api/webhook` 是本地开发，不是公开可用的。因此，GitHub 无法访问，导致 WebHook 请求失败：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/49e0be46-65e8-444e-a98e-1f099a77f7a7.png)

为了将开发环境暴露给 GitHub 以使其可访问互联网，我们可以使用**Ngrok**，这是一个用于暴露本地 Web 服务器的公共 URL 的工具。转到[`ngrok.com/download`](https://ngrok.com/download)下载适用于您操作系统的 Ngrok。

运行以下命令告诉 Ngrok 将端口`54113`暴露到互联网上：

```cs
ngrok http -host-header="localhost:54113" 54113
```

Ngrok 将创建一个公共 URL，可访问并转发到开发 PC 上指定的端口。在这种情况下，Ngrok 生成了`http://d73c1ef5.ngrok.io`作为将转发到端口`54113`的 URL：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/fe7fb1cc-5047-411e-bd21-54370828ea77.png)

接下来，更新之前创建的 WebHook 的有效负载 URL 为`http://d73c1ef5.ngrok.io/api/webhook`。单击“更新 WebHook”按钮以保存更改。在“最近的交付”选项卡下，单击未能交付的有效负载的 GUID。这将打开一个屏幕，显示 JSON 有效负载，包括请求和响应。

单击“重新交付”按钮。这将显示一个对话框，询问您是否要重新交付有效负载。单击“是，重新交付此有效负载”按钮。这将尝试将 JSON 有效负载 POST 到有效负载 URL 字段中指定的新端点。这次，有效负载交付将成功，HTTP 响应代码为`200`，表示端点已成功联系：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/12d0e466-f986-4972-8f42-e63c11de1f64.png)

您可以编写消费者 Web 应用程序以按照您的意愿处理有效负载数据。成功配置后，GitHub 将在 WebHook 订阅的任何事件引发时将有效负载 POST 到端点。

# TeamCity CI 平台

TeamCity 是 JetBrains 推出的一个独立于平台的 CI 工具。它是一个用户友好的 CI 工具，专门为软件开发人员和工程师设计。TeamCity 是一个强大而功能强大的 CI 工具，因为它能够充分优化集成周期。

TeamCity 还可以在不同平台和环境上同时并行运行构建。使用 TeamCity，您可以获得有关代码质量、构建持续时间甚至创建自定义指标的定制统计信息。它具有运行代码覆盖率和查找重复项的功能。

# TeamCity 概念

在本节中，将解释 TeamCity 中经常使用的一些基本术语。这是为了理解成功配置构建步骤以及质量连续过程所需的一些概念。让我们来看看一些基本术语：

+   **项目**：这是正在开发的软件项目。它可以是一个发布或特定版本。此外，它包括构建配置的集合。

+   **构建代理**：这是执行构建过程的软件。它独立安装在 TeamCity 服务器之外。它们可以都驻留在同一台机器上，也可以在运行相似或不同操作系统的不同机器上。对于生产目的，通常建议它们都安装在不同的机器上以获得最佳性能。

+   **TeamCity 服务器**：TeamCity 服务器监视构建代理，同时使用兼容性要求将构建分发到连接的代理，并报告进度和结果。结果中的信息包括构建历史记录、日志和构建数据。

+   **构建**：这是创建软件项目的特定版本的过程。触发构建过程会将其放入构建队列，并在有可用代理运行时启动。构建代理在构建完成后将构建产物发送到 TeamCity 服务器。

+   **构建队列**：这是一个包含已触发但尚未启动的构建的列表。TeamCity 服务器读取待处理构建的队列，并在代理空闲时将构建分发给兼容的构建代理。

+   **构建产物**：这些是构建生成的文件。这些可以包括`dll`文件、可执行文件、安装程序、报告、日志文件等。

+   **构建配置**：这是描述构建过程的一组设置。这包括 VCS 根、构建步骤和构建触发器。

+   **构建步骤**：构建步骤由与构建工具集成的构建运行器表示，例如 MSBuild，代码分析引擎和测试框架，例如 xUnit.net。构建步骤本质上是要执行的任务，可以包含顺序执行的许多步骤。

+   **构建触发器**：这是一组规则，触发某些事件的新构建，例如当 VCS 触发新构建时，当 TeamCity 检测到配置的 VCS 根中的更改时。

+   **VCS 根**：这是一组版本控制设置，包括源路径、凭据和其他定义 TeamCity 与版本控制系统通信方式的设置。

+   **更改**：这是对项目源代码的修改。当更改已提交到版本控制系统但尚未包含在构建中时，对于某个构建配置，更改被称为待处理更改。

# 安装 TeamCity 服务器

TeamCity 可以在开发团队的服务器基础设施上本地托管，也可以通过与云解决方案集成来托管 TeamCity。这允许虚拟机被配置以运行 TeamCity。TeamCity 安装将包括服务器安装和默认的构建代理。

要安装 TeamCity 服务器，请转到 JetBrains 下载站点，获取 TeamCity 服务器的免费专业版，该版本附带免费许可密钥，可解锁 3 个构建代理和 100 个构建配置。如果您使用 Windows 操作系统，请运行捆绑了 Tomcat Java JRE 1.8 的下载`.exe`。按照对话框提示提取和安装 TeamCity 核心文件。

在安装过程中，您可以设置 TeamCity 将监听的端口，也可以将其保留为默认的`8080`。如果安装成功，TeamCity 将在浏览器中打开，并提示您通过在服务器上指定数据目录位置来完成安装过程。指定路径并单击“继续”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/b00f61fc-a20d-4a35-a237-6c9e9230ea17.png)

在数据目录位置路径初始化后，您将进入数据库选择页面，在该页面上，您将有选择任何受支持的数据库的选项。选择内部（HSQLDB）并单击“继续”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/05532102-4ddf-410e-85ff-f09b3e93ac84.png)

数据库配置将需要几秒钟，然后您将看到许可协议页面。接受许可协议并单击“继续”按钮。下一页是管理员帐户创建页面。使用所需的凭据创建帐户以完成安装。安装完成后，您将被引导到概述页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/7f576b08-af3d-4e25-9925-ba7709abb491.png)

# TeamCity CI 工作流

TeamCity 构建生命周期描述了服务器和代理之间的数据流。这基本上是传递给代理的信息以及 TeamCity 检索结果的过程。工作流描述了为项目配置的构建步骤是如何端到端执行的：

1.  TeamCity 服务器检测 VCS 根中的更改，并将其持久化到数据库中。

1.  构建触发器注意到数据库中的更改并将构建添加到队列中。

1.  TeamCity 服务器将队列中的构建分配给兼容的空闲构建代理。

1.  构建代理执行构建步骤。在执行构建步骤期间，代理将构建进度报告发送到服务器。构建代理将构建进度报告发送到 TeamCity 服务器，以允许实时监控构建过程。

1.  构建代理在构建完成后将构建产物发送到 TeamCity 服务器。

# 配置和运行构建

基本上，项目应包含运行成功构建所需的配置和项目属性。使用 TeamCity CI 服务器，可以自动化运行测试、执行环境检查、编译、构建，并提供可部署版本的项目。

安装的 TeamCity 服务器可以在安装期间指定的端口上本地访问。在这种情况下，我们将使用`http://localhost:8060`。要创建一个 TeamCity 项目，请转到服务器 URL 并使用之前创建的凭据登录。点击“项目”菜单，然后点击“创建项目”按钮。

您将看到创建项目的几个选项，可以从存储库、手动创建，或连接到 GitHub、Bitbucket 或 Visual Studio Team Services 中的任何一个。点击“来自 GitHub.com”按钮，将 TeamCity 连接到我们之前在 GitHub 上创建的`LoanApplication`存储库：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/822c68c9-b100-4914-b97d-e1a7bc1db8a2.png)

**添加连接**对话框显示了 TeamCity 将连接到 GitHub。需要创建一个新的 GitHub OAuth 应用程序才能成功将 TeamCity 连接到 GitHub。要在 GitHub 中创建新的 OAuth 应用程序，请执行以下步骤：

1.  转到[`github.com/settings/applications/new`](https://github.com/settings/applications/new)。

1.  在主页 URL 字段中，提供 TeamCity 服务器的 URL：`http://localhost:8060`。

1.  在授权回调 URL 中提供`http://localhost:8060/oauth/github/accessToken.html`。

1.  点击“注册应用程序”按钮完成注册。将为您创建新的客户端密钥和客户端 ID：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/c22bc375-7ebb-4be0-8cae-a8a4ff68e247.png)

1.  创建的新客户端 ID 和客户端密钥将用于填写 TeamCity 上添加连接对话框中的字段，以创建从 TeamCity 到 GitHub 的连接。点击“保存”按钮保存设置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/5647f0d2-7fe4-4e6b-b598-49a9e4b0093c.png)

1.  下一步是授权 TeamCity 访问 VCS。点击“登录 GitHub”按钮即可完成。将显示一个页面，您必须授权 TeamCity 访问 GitHub 帐户中的公共和私有存储库。点击“授权”完成流程。

1.  TeamCity 将启动到 GitHub 的连接，以检索可以选择的可用存储库列表。您可以筛选列表以选择所需的存储库：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/c1b4cd33-b1dc-4121-827f-c91eccd445db.png)

1.  TeamCity 将验证与所选存储库的连接。如果成功，将显示“创建项目”。在此页面上，将显示项目和构建配置名称。如果需要，可以进行修改。点击“继续”按钮继续进行项目设置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/d6ae2ec9-1eb6-4a07-a6fd-48a12a03e947.png)

1.  在下一个屏幕上，TeamCity 将扫描连接的存储库以查找可用的配置构建步骤。您可以点击“创建构建步骤”按钮添加构建步骤：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/dc7ee611-53ce-4ae6-9b25-715412134b99.png)

1.  在新的构建步骤屏幕上，您必须从下拉菜单中选择构建运行程序。

1.  为构建步骤指定一个描述性名称。

1.  然后选择要构建运行程序执行的命令。填写所有其他必填字段

1.  点击保存按钮保存构建步骤：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/0b5ea0f5-99b2-4a42-ba57-1e21abc60196.png)

1.  保存构建步骤后，将显示可用构建步骤的列表，您可以按照相同的步骤添加更多构建步骤。此外，您可以重新排序构建步骤，并通过单击“自动检测构建步骤”按钮来检测构建步骤。

1.  配置构建步骤后，您可以通过单击 TeamCity 网页顶部菜单上的运行链接来运行构建。这将重定向到构建结果页面，您可以在那里查看构建的进度，随后审查或编辑构建配置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/b2cf317b-51ea-4584-a517-412c6b142bec.png)

# 总结

在本章中，我们广泛探讨了 CI 的概念，这是一种软件开发实践，可以帮助开发团队频繁地集成其代码。开发人员预计每天多次检查代码，然后由 CI 工具通过自动化构建过程进行验证。

还讨论了 CI 的常见术语，用于持续交付。我们解释了如何在 GitHub 和在线托管平台上托管软件项目的步骤，然后讨论了基本的 Git 命令。

探讨了创建 GitHub WebHooks 以配置与构建管理系统集成的过程。最后，给出了安装和配置 TeamCity CI 平台的逐步说明。

在下一章中，我们将探讨 Cake Bootstrapper 并配置 TeamCity 以使用名为 Cake 的跨平台构建自动化系统来清理、构建和恢复软件包依赖项并测试我们的`LoanApplication`项目。


# 第八章：创建持续集成构建流程

持续反馈、频繁集成和及时部署，这些都是持续集成实践带来的结果，可以极大地减少与软件开发过程相关的风险。开发团队可以提高生产率，减少部署所需的时间，并从持续集成中获得巨大的好处。

在第七章中，*持续集成和项目托管*，我们设置了 TeamCity，一个强大的持续集成工具，简化和自动化了管理源代码检入和更改、测试、构建和部署软件项目的过程。我们演示了在 TeamCity 中创建构建步骤，并将其连接到我们在 GitHub 上的`LoanApplication`项目。TeamCity 具有内置功能，可以连接到托管在 GitHub 或 Bitbucket 上的软件项目。

CI 流程将许多不同的步骤整合成一个易于重复的过程。这些步骤根据软件项目类型而有所不同，但有一些步骤是常见的，并适用于大多数项目。可以使用构建自动化系统自动化这些步骤。

在本章中，我们将配置 TeamCity 使用名为**Cake**的跨平台构建自动化系统，来清理、构建、恢复软件包依赖，并测试`LoanApplication`解决方案。本章后面，我们将探讨在**Visual Studio Team Services**中使用 Cake 任务创建构建步骤。我们将涵盖以下主题：

+   安装 Cake 引导程序

+   使用 C#编写构建脚本

+   Visual Studio 的 Cake 扩展

+   使用 Cake 任务创建构建步骤

+   使用 Visual Studio Team Services 进行 CI

# 安装 Cake 引导程序

**Cake**是一个跨平台的构建自动化框架。它是一个用于编译代码、运行测试、复制文件和文件夹，以及运行与构建相关任务的构建自动化框架。Cake 是开源的，源代码托管在 GitHub 上。

Cake 具有使文件系统路径操作变得简单的功能，并具有操作 XML、启动进程、I/O 操作和解析 Visual Studio 解决方案的功能。可以使用 C#领域特定语言自动化 Cake 构建相关活动。

它采用基于依赖的编程模型进行构建自动化，通过该模型，在任务之间声明依赖关系。基于依赖的模型非常适合构建自动化，因为大多数自动化构建步骤都是幂等的。

Cake 真正实现了跨平台；其 NuGet 包 Cake.CoreCLR 允许它在 Windows、Linux 和 Mac 上使用.NET Core 运行。它有一个 NuGet 包，可以在 Windows 上依赖.NET Framework 4.6.1 运行。此外，它可以使用 Mono 框架在 Linux 和 Max 上运行，建议使用 Mono 版本 4.4.2。

无论使用哪种 CI 工具，Cake 在所有支持的工具中都具有一致的行为。它广泛支持大多数构建过程中使用的工具，包括**MSBuild**、**ILMerge**、**Wix**和**Signtool**。

# 安装

为了使用 Cake 引导程序，需要安装 Cake。安装 Cake 并测试运行的简单方法是克隆或下载一个`.zip`文件，即位于[`github.com/cake-build/example`](https://github.com/cake-build/example)的 Cake 构建示例存储库。示例存储库包含一个简单的项目和运行 Cake 脚本所需的所有文件。

在示例存储库中，有一些感兴趣的文件——`build.ps1`和`build.sh`。它们是引导程序脚本，确保 Cake 所需的依赖项与 Cake 和必要的文件一起安装。这些脚本使调用 Cake 变得更容易。`build.cake`文件是构建脚本；构建脚本可以重命名，但引导程序将默认定位`build.cake`文件。`tools.config`/`packages.config`文件是包配置，指示引导程序脚本在`tools`文件夹中安装哪些 NuGet 包。

解压下载的示例存储库存档文件。在 Windows 上，打开 PowerShell 提示符并通过运行`.\build.ps1`执行引导程序脚本。在 Linux 和 Mac 上，打开终端并运行`.\build.sh`。引导程序脚本将检测到计算机上未安装 Cake，并自动从 NuGet 下载它。

根据引导程序脚本的执行，在 Cake 下载完成后，将运行下载的示例`build.cake`脚本，该脚本将清理输出目录，并在构建项目之前恢复引用的 NuGet 包。运行`build.cake`文件时，它应该清理测试项目，恢复 NuGet 包，并运行项目中的单元测试。`运行设置`和`测试运行摘要`将如下截图所示呈现：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/e9b68fa6-ed2f-4c07-9fa0-ec76e1c8f5a3.png)

蛋糕引导程序可以通过从托管在 GitHub 上的*Cake 资源*存储库（[`github.com/cake-build/resources`](https://github.com/cake-build/resources)）下载并安装，其中包含配置文件和引导程序。引导程序将下载 Cake 和构建脚本所需的必要工具，从而避免在源代码存储库中存储二进制文件。

# PowerShell 安全

通常，PowerShell 可能会阻止运行`build.ps1`文件。您可能会在 PowerShell 屏幕上收到错误消息，指出由于系统上禁用了运行脚本，无法加载`build.ps1`。由于 PowerShell 中默认的安全设置，对文件的运行限制。

打开 PowerShell 窗口，将目录更改为之前下载的 Cake 构建示例存储库的文件夹，并运行`.\build.ps1`命令。如果系统上的执行策略未从默认值更改，这应该会给您以下错误：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/08df4a59-479c-4116-b56b-2ac333187ca5.png)

要查看系统上当前的执行策略配置，请在 PowerShell 屏幕上运行`Get-ExecutionPolicy -List`命令；此命令将呈现一个包含可用范围和执行策略的表格，就像以下屏幕上显示的那样。根据您运行 PowerShell 的方式，您的实例可能具有不同的设置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/3b30ec57-3e5b-4581-b016-e25dc5028bdd.png)

要更改执行策略以允许随后运行脚本，运行`Set-ExecutionPolicy RemoteSigned -Scope Process`命令，该命令旨在将进程范围从未定义更改为`RemoteSigned`。运行该命令将在 PowerShell 屏幕上显示一个警告并提示您的 PC 可能会面临安全风险。输入*Y*以确认并按*Enter*。运行命令时，PowerShell 屏幕上显示的内容如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/46d76460-53de-4899-90e8-9fd74d557941.png)

这将更改 PC 的执行策略并允许运行 PowerShell 脚本。

# 蛋糕引导程序安装步骤

安装 Cake 引导程序的步骤对于不同平台是相似的，只有一些小的差异。执行以下步骤设置引导程序。

# 步骤 1

导航到 Cake 资源存储库以下载引导程序。对于 Windows，下载 PowerShell `build.ps1`文件，对于 Mac 和 Linux，下载`build.sh` bash 文件。

在 Windows 上，打开一个新的 PowerShell 窗口并运行以下命令：

```cs
Invoke-WebRequest https://cakebuild.net/download/bootstrapper/windows -OutFile build.ps1
```

在 Mac 上，从新的 shell 窗口运行以下命令：

```cs
curl -Lsfo build.sh https://cakebuild.net/download/bootstrapper/osx
```

在 Linux 上，打开一个新的 shell 来运行以下命令：

```cs
curl -Lsfo build.sh https://cakebuild.net/download/bootstrapper/linux
```

# 步骤 2

创建一个 Cake 脚本来测试安装。创建一个`build.cake`文件；应该放在与`build.sh`文件相同的位置：

```cs
var target = Argument("target", "Default");

Task("Default")
  .Does(() =>
{
  Information("Installation Successful");
});

RunTarget(target);
```

# 步骤 3

现在可以通过调用 Cake 引导程序来运行*步骤 2*中创建的 Cake 脚本。

在 Windows 上，您需要指示 PowerShell 允许运行脚本，方法是更改 Windows PowerShell 脚本执行策略。由于执行策略，PowerShell 脚本执行可能会失败。

要执行 Cake 脚本，请运行以下命令：

```cs
./build.ps1
```

在 Linux 或 Mac 上，您应该运行以下命令，以授予当前所有者执行脚本的权限：

```cs
chmod +x build.sh
```

运行命令后，可以调用引导程序来运行*步骤 2*中创建的 Cake 脚本：

```cs
./build.sh
```

# 使用 C#编写构建脚本

使用 Cake 自动化构建和部署任务可以避免与项目部署相关的问题和头痛。构建脚本通常包含构建和部署源代码以及配置文件和项目的其他工件所需的步骤和逻辑。

使用 Cake 资源库上可用的示例`build.cake`文件可以作为编写项目的构建脚本的起点。但是，为了实现更多功能，我们将介绍一些基本的 Cake 概念，以便编写用于自动化构建和部署任务的健壮脚本。

# 任务

在 Cake 的构建自动化的核心是任务。Cake 中的**任务**是用于按照所需的顺序执行特定操作或活动的简单工作单元。Cake 中的任务可以具有指定的条件、相关依赖项和错误处理。

可以使用`Task`方法来定义任务，将任务名称或标题作为参数传递给它：

```cs
Task("Action")
    .Does(() =>
{
    // Task code goes here
});
```

例如，以下代码片段中的`build`任务会清理`debugFolder`文件夹以删除其中的内容。运行任务时，将调用`CleanDirectory`方法：

```cs
var debugFolder = Directory("./bin/Debug");

Task("CleanFolder")
    .Does(() =>
{
    CleanDirectory(debugFolder);
});
```

Cake 允许您使用 C#在任务中使用异步和等待功能来创建异步任务。实质上，任务本身将以单个线程同步运行，但任务中包含的代码可以受益于异步编程功能并利用异步 API。

Cake 具有`DoesForEach`方法，可用于将一系列项目或产生一系列项目的委托作为任务的操作添加。当将委托添加到任务时，委托将在任务执行后执行：

```cs
Task("LongRunningTask")
    .Does(async () => 
    {
        // use await keyword to multi thread code
    }); 
```

通过将`DoesForEach`链接到`Task`方法来定义`DoesForEach`，如以下代码片段所示：

```cs
Task("ProcessCsv")
    .Does(() => 
{ 
})
.DoesForEach(GetFiles("**/*.csv"), (file) => 
{ 
    // Process each csv file. 
});
```

# TaskSetup 和 TaskTeardown

`TaskSetup`和`TaskTeardown`用于包装要在执行每个任务之前和之后执行的构建操作。当执行诸如配置初始化和自定义日志记录等操作时，这些方法尤其有用：

```cs
TaskSetup(setupContext =>
{
    var taskName =setupContext.Task.Name;
    // perform action
});

TaskTeardown(teardownContext =>
{
    var taskName =teardownContext.Task.Name;
    // perform action
});
```

与任务的`TaskSetup`和`TaskTeardown`类似，Cake 具有`Setup`和`Teardown`方法，可用于在第一个任务之前和最后一个任务之后执行操作。这些方法在构建自动化中非常有用，例如，当您打算在运行任务之前启动一些服务器和服务以及在运行任务后进行清理活动时。应在`RunTarget`之前调用`Setup`或`Teardown`方法以确保它们正常工作：

```cs
Setup(context =>
{
    // This will be executed BEFORE the first task.
});

Teardown(context =>
{
    // This will be executed AFTER the last task.
});
```

# 配置和预处理指令

Cake 操作可以通过使用环境变量、配置文件和将参数传递到 Cake 可执行文件来进行控制。这是基于指定的优先级，配置文件会覆盖环境变量和传递给 Cake 的参数，然后覆盖在环境变量和配置文件中定义的条目。

例如，如果您打算指定工具路径，即 cake 在恢复工具时检查的目录，您可以创建`CAKE_PATHS_TOOLS`环境变量名称，并将值设置为 Cake 工具文件夹路径。

在使用配置文件时，文件应放置在与`build.cake`文件相同的目录中。可以在配置文件中指定 Cake 工具路径，就像在以下代码片段中一样，它会覆盖环境变量中设置的任何内容：

```cs
[Paths]
Tools=./tools
```

Cake 工具路径可以直接传递给 Cake，这将覆盖环境变量和配置文件中设置的内容：

```cs
cake.exe --paths_tools=./tools
```

Cake 具有默认用于配置条目的值，如果它们没有使用任何配置 Cake 的方法进行覆盖。这里显示了可用的配置条目及其默认值，以及如何使用配置方法进行配置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/b93d2441-cac2-4442-87b4-81d5c56b2bcb.png)

*预处理器指令*用于在 Cake 中引用程序集、命名空间和脚本。预处理器行指令在脚本执行之前运行。

# 依赖关系

通常，您将创建依赖于其他任务完成的任务；为了实现这一点，您可以使用`IsDependentOn`和`IsDependeeOf`方法。要创建依赖于另一个任务的任务，请使用`IsDependentOn`方法。在以下构建脚本中，Cake 将在执行`Task2`之前执行`Task1`：

```cs
Task("Task1")
    .Does(() =>
{
});

Task("Task2")
    .IsDependentOn("Task1")
    .Does(() =>
{
});

RunTarget("Task2");
```

使用`IsDependeeOf`方法，您可以定义具有相反关系的任务依赖关系。这意味着依赖于任务的任务在该任务中定义。前面的构建脚本可以重构为使用反向关系：

```cs
Task("Task1")
    .IsDependeeOf("Task2")
    .Does(() =>
{
});

Task("Task2")
    .Does(() =>
{
});

RunTarget("Task2");
```

# 标准

在 Cake 脚本中使用标准允许您控制构建脚本的执行流程。**标准**是必须满足才能执行任务的谓词。标准不会影响后续任务的执行。标准用于根据指定的配置、环境状态、存储库分支和任何其他所需选项来控制任务执行。

最简单的形式是使用`WithCriteria`方法来指定特定任务的执行标准。例如，如果您只想在下午清理`debugFolder`文件夹，可以在以下脚本中指定标准：

```cs
var debugFolder = Directory("./bin/Debug");

Task("CleanFolder")
    .WithCriteria(DateTime.Now.Hour >= 12)
    .Does(() =>
{
    CleanDirectory(debugFolder);
});

RunTarget("CleanFolder");
```

您可以有一个任务的执行取决于另一个任务；在以下脚本中，`CleanFolder`任务的标准将在创建任务时设置，而`ProcessCsv`任务评估的标准将在任务执行期间进行：

```cs
var debugFolder = Directory("./bin/Debug");

Task("CleanFolder")
    .WithCriteria(DateTime.Now.Hour >= 12)
    .Does(() =>
{
    CleanDirectory(debugFolder);
});

Task("ProcessCsv")
    .WithCriteria(DateTime.Now.Hour >= 12)
    .IsDependentOn("CleanFolder")
    .Does(() => 
{ 
})
.DoesForEach(GetFiles("**/*.csv"), (file) => 
{ 
    // Process each csv file. 
});

RunTarget("ProcessCsv");
```

一个更有用的用例是编写一个带有标准的 Cake 脚本，检查本地构建并执行一些操作，以清理、构建和部署项目。将定义四个任务，每个任务执行一个要执行的操作，第四个任务将链接这些操作在一起：

```cs
var isLocalBuild = BuildSystem.IsLocalBuild
Task("Clean")
    .WithCriteria(isLocalBuild)
    .Does(() =>
    {
        // clean all projects in the soution
    });

Task("Build")   
    .WithCriteria(isLocalBuild)
    .Does(() =>
    {    
        // build all projects in the soution
    });

Task("Deploy")    
    .WithCriteria(isLocalBuild)
    .Does(() => 
    {
        // Deploy to test server
    });    

Task("Main")
    .IsDependentOn("Clean")
    .IsDependentOn("Build")
    .IsDependentOn("Deploy")    
    .Does(() => 
    {
    });
RunTarget("Main");
```

# Cake 的错误处理和最终块

Cake 具有错误处理技术，您可以使用这些技术从错误中恢复，或者在构建过程中发生异常时优雅地处理异常。有时，构建步骤调用外部服务或进程；调用这些外部依赖项可能会导致错误，从而导致整个构建失败。强大的构建应该在不停止整个构建过程的情况下处理这些异常。

`OnError`方法是一个任务扩展，用于在构建中生成异常时执行操作。您可以在`OnError`方法中编写代码来处理错误，而不是强制终止脚本：

```cs
Task("Task1")
.Does(() =>
{
})
.OnError(exception =>
{
    // Code to handle exception.
});
```

有时，您可能希望忽略抛出的错误并继续执行生成异常的任务；您可以使用`ContinueOnError`任务扩展来实现这一点。使用`ContinueOnError`方法时，您不能与之一起使用`OnError`方法：

```cs
Task("Task1")
    .ContinueOnError()
    .Does(() =>
{
});
```

如果您希望报告任务中生成的异常，并仍然允许异常传播并采取其课程，请使用`ReportError`方法。如果由于任何原因，在`ReportError`方法内引发异常，则会被吞噬：

```cs
Task("Task1")
    .Does(() =>
{
})
.ReportError(exception =>
{  
    // Report generated exception.
});
```

此外，您可以使用`DeferOnError`方法将任何抛出的异常推迟到执行的任务完成。这将确保任务在抛出异常并使脚本失败之前执行其指定的所有操作：

```cs
Task("Task1")
    .Does(() => 
{ 
})
.DeferOnError();
```

最后，您可以使用`Finally`方法执行任何操作，而不管任务执行的结果如何：

```cs
Task("Task1")
    .Does(() =>
{
})
.Finally(() =>
{  
    // Perform action.
});
```

# LoanApplication 构建脚本

为了展示 Cake 的强大功能，让我们编写一个 Cake 脚本来构建`LoanApplication`项目。Cake 脚本将清理项目文件夹，还原所有包引用，构建整个解决方案，并运行解决方案中的单元测试项目。

以下脚本设置要在整个脚本中使用的参数，定义目录和任务以清理`LoanApplication.Core`项目的`bin`文件夹，并使用`DotNetCoreRestore`方法恢复包。可以使用`DotNetCoreRestore`方法来还原 NuGet 包，该方法又使用`dotnet restore`命令：

```cs
//Arguments
var target = Argument("target", "Default");
var configuration = Argument("configuration", "Release");
var solution = "./LoanApplication.sln";

// Define directories.
var buildDir = Directory("./LoanApplication.Core/bin") + Directory(configuration);

//Tasks
Task("Clean")
    .Does(() =>
{
    CleanDirectory(buildDir);
});

Task("Restore-NuGet-Packages")
    .IsDependentOn("Clean")
    .Does(() =>
{
    Information("Restoring NuGet Packages");
    DotNetCoreRestore();
});
```

脚本的后部分包含使用`DotNetCoreBuild`方法构建整个解决方案的任务，该方法使用`DotNetCoreBuildSettings`对象中提供的设置使用`dotnet build`命令构建解决方案。使用`DotNetCoreTest`方法执行测试项目，该方法使用`DotNetCoreTestSettings`对象中提供的设置在解决方案中的所有测试项目中运行测试使用`dotnet test`：

```cs
Task("Build")
    .IsDependentOn("Restore-NuGet-Packages")
    .Does(() =>
{
    Information("Build Solution");
    DotNetCoreBuild(solution,
           new DotNetCoreBuildSettings()
                {
                    Configuration = configuration
                });    
});

Task("Run-Tests")
    .IsDependentOn("Build")
    .Does(() =>
{
     var testProjects = GetFiles("./LoanApplication.Tests.Units/*.csproj");
        foreach(var project in testProjects)
        {
            DotNetCoreTool(
                projectPath: project.FullPath, 
                command: "xunit", 
                arguments: $"-configuration {configuration} -diagnostics -stoponfail"
            );
        }        
});

Task("Default")
    .IsDependentOn("Run-Tests");

RunTarget(target);
```

Cake Bootstrapper 可用于通过从 PowerShell 窗口调用引导程序来运行 Cake `build`文件。当调用引导程序时，Cake 将使用`build`文件中可用的任务定义来开始执行定义的构建任务。执行开始时，执行的进度和状态将显示在 PowerShell 窗口中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/f8e37ddb-c164-41c2-abe8-970cd23436d6.png)

每个任务的执行进度将显示在 PowerShell 窗口中，显示 Cake 当前正在进行的所有活动。当构建执行完成时，将显示脚本中每个任务的执行持续时间，以及所有任务的总执行时间： 

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/f3ff87ae-4cca-4ff6-af6d-349cca93578a.png)

# Visual Studio 的 Cake 扩展

**Visual Studio 的 Cake 扩展**为 Visual Studio 带来了对 Cake 构建脚本的语言支持。该扩展支持新模板、任务运行器资源管理器以及引导 Cake 文件的功能。可以在**Visual Studio Market Place**下载**Visual Studio 的 Cake 扩展**（[`marketplace.visualstudio.com/items?itemName=vs-publisher-1392591.CakeforVisualStudio`](https://marketplace.visualstudio.com/items?itemName=vs-publisher-1392591.CakeforVisualStudio)）。

从市场下载的`.vsix`文件本质上是一个`.zip`文件。该文件包含要安装在 Visual Studio 中的 Cake 扩展的内容。运行下载的`.vsix`文件时，它将为 Visual Studio 2015 和 2017 安装 Cake 支持：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/44266f77-d110-417f-802c-419f313badbc.png)

# Cake 模板

安装扩展后，在创建新项目时，Visual Studio 的可用选项中将添加一个**Cake 模板**。该扩展将添加四种不同的 Cake 项目模板类型：

+   **Cake Addin**：用于创建 Cake Addin 的项目模板

+   **Cake Addin Unit Test Project**：用于为 Cake Addin 创建单元测试的项目模板，其中包括作为指南的示例

+   **Cake Addin Unit Test Project (empty)**：用于为 Cake Addin 创建单元测试的项目模板，但不包括示例

+   **Cake Module**：此模板用于创建 Cake 模块，并附带示例

以下图片显示了不同的 Cake 项目模板：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/420aa26e-2963-4359-9099-9b91652d4bd4.png)

# 任务运行器资源管理器

在使用 Cake 脚本进行构建自动化的 Visual Studio 解决方案中，当发现`build.cake`文件时，Cake 任务运行器将被触发。Cake 扩展激活了**任务运行器资源管理器**集成，允许您在 Visual Studio 中直接运行包含的绑定的 Cake 任务。

要打开任务运行器资源管理器，请右键单击 Cake 脚本（`build.cake`文件）并从显示的上下文菜单中选择任务运行器资源管理器；它应该打开任务运行器资源管理器，并在窗口中列出 Cake 脚本中的所有任务：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/90fca57a-1b4f-4e76-9030-19108af3d10f.png)

有时，当右键单击 Cake 脚本时，任务运行器资源管理器可能不会显示在上下文菜单中。如果是这样，请单击“查看”菜单，选择“其他窗口”，然后选择“任务运行器资源管理器”以打开它：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/8e34532d-c3e6-44fb-b723-90f17796f45a.png)

通过安装 Cake 扩展，Visual Studio 的构建菜单现在将包含一个 Cake 构建的条目，可以用来安装 Cake 配置文件、PowerShell 引导程序和 Bash 引导程序，如果它们在解决方案中尚未配置的话：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/2f14889e-ae82-4070-814c-8b7b4d65276e.png)

现在，您可以通过双击或右键单击并选择运行，直接从任务运行器资源管理器中执行每个任务。任务执行的进度将显示在任务运行器资源管理器上：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/5eee7748-df49-4e1b-af88-28164eb99a52.png)

# 语法高亮显示

Cake 扩展为 Visual Studio 添加了语法高亮显示功能。这是 IDE 的常见功能，其中源代码以不同的格式、颜色和字体呈现。源代码高亮显示是基于定义的组、类别和部分进行的。

安装扩展后，任何带有`.cake`扩展名的文件都可以在 Visual Studio 中打开，并具有完整的任务和语法高亮显示。目前，Visual Studio 中的`.cake`脚本文件没有 IntelliSense 支持；预计这个功能将在以后推出。

以下截图显示了在 Visual Studio 中对`build.cake`文件进行的语法高亮显示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/91d2d1b8-f0c5-4f95-9dfb-35315eea0dde.png)

# 使用 Cake 任务来构建步骤

使用任务运行器资源管理器来运行用 Cake 脚本编写的构建任务更加简单和方便。这通常是通过 Visual Studio 的 Cake 扩展或直接调用 Cake 引导文件来完成的。然而，还有一种更有效的替代方法，那就是使用 TeamCity CI 工具来运行 Cake 构建脚本。

TeamCity 构建步骤可用于执行 Cake 脚本作为构建步骤执行过程的一部分。让我们按照以下步骤为`LoanApplication`项目创建执行 Cake 脚本的构建步骤：

+   单击添加构建步骤以打开新的构建步骤窗口。

+   在运行器类型中，选择 PowerShell，因为 Cake 引导文件将由 PowerShell 调用。

+   在文本字段中为构建步骤命名。

+   在脚本选项中，选择文件。这是因为它是一个`.ps1`文件，将被调用，而不是一个直接的 PowerShell 脚本。

+   要选择脚本文件，请单击树图标；这将加载 GitHub 上托管的项目中可用的文件和文件夹。在显示的文件列表中选择`build.ps1`文件。

+   单击保存按钮以保存更改并创建构建步骤：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/55758bfb-c70e-49d9-b120-f950f7425b29.png)

新的构建步骤应该出现在 TeamCity 项目中配置的可用构建步骤列表中。在参数描述选项卡中，将显示有关构建步骤的信息，显示运行器类型和要执行的 PowerShell 文件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/b8d97cca-24a1-4f19-a4b8-dfd909135d89.png)

# 使用 Visual Studio Team Services 进行 CI

**Microsoft Visual Studio Team Services**（**VSTS**）是**Team Foundation Server**（**TFS**）的云版本。它提供了让开发人员协作进行软件项目开发的出色功能。与 TFS 类似，它提供了易于理解的服务器管理体验，并增强了与远程站点的连接。

VSTS 为实践 CI 和**持续交付**（**CD**）的开发团队提供了出色的体验。它支持 Git 存储库进行源代码控制，易于理解的报告以及可定制的仪表板，用于监视软件项目的整体进展。

此外，它还具有内置的构建和发布管理功能，规划和跟踪项目，使用*Kanban*和*Scrum*方法管理代码缺陷和问题。它同样还有一个内置的维基用于与开发团队进行信息传播。

您可以通过互联网连接到 VSTS，使用开发人员需要已创建的 Microsoft 帐户。但是，组织中的开发团队可以配置 VSTS 身份验证以与**Azure Active Directory**（**Azure AD**）一起使用，或者设置 Azure AD 以具有 IP 地址限制和多因素身份验证等安全功能。

# 在 VSTS 中设置项目

要开始使用 VSTS，请转到[`www.visualstudio.com/team-services/`](https://www.visualstudio.com/team-services/)创建免费帐户。如果您已经创建了 Microsoft 帐户，可以使用该帐户登录，或者使用您组织的 Active Directory 身份验证。您应该被重定向到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/47bff39b-f14e-4e83-9638-d90678de1ded.png)

在 VSTS 中，每个帐户都有自己定制的 URL，其中包含一个团队项目集合，例如，[`packt.visualstudio.com`](https://packt.visualstudio.com)。您应该在字段中指定 URL，并选择要与项目一起使用的版本控制。VSTS 目前支持 Git 和 Team Foundation 版本控制。单击“继续”以继续进行帐户创建。

创建帐户后，单击“项目”菜单导航到项目页面，然后单击“新建项目”创建新项目。这将加载项目创建屏幕，在那里您将指定项目名称，描述，要使用的版本控制以及工作项过程。单击“创建”按钮完成项目创建：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/c166cb04-a50b-43a5-98a5-8cc789625d85.png)

项目创建完成后，您将看到“入门”屏幕。该屏幕提供了克隆现有项目或将现有项目推送到其中的选项。让我们导入我们之前在 GitHub 上创建的`LoanApplication`项目。单击“导入”按钮开始导入过程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/6116c3a9-7bff-45d9-9b4a-07044998d00d.png)

在导入屏幕上，指定源类型和 GitHub 存储库的 URL，并提供 GitHub 登录凭据。单击“导入”按钮开始导入过程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/fc0bb721-bf03-4094-b64d-2cfc5089e6bb.png)

您将看到一个显示导入进度的屏幕。根据要导入的项目的大小，导入过程可能需要一些时间。当过程完成时，屏幕上将显示“导入成功”消息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/6aa3a2ed-e618-4606-a49b-2ba51a47b5cb.png)

单击“单击此处导航到代码视图”以查看 VSTS 导入的文件和文件夹。文件屏幕将显示项目中可用的文件和文件夹以及提交和日期详细信息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/edcc131d-73b7-4004-bfc3-7e2884dc8ffd.png)

# 在 VSTS 中安装 Cake

Cake 在 VSTS 中有一个扩展，允许您相对容易地直接从 VSTS 构建任务运行 Cake 脚本。安装了扩展后，Cake 脚本就不必像在 TeamCity 中运行 Cake 脚本时那样使用 PowerShell 来运行。

在 Visual Studio Marketplace 上导航到 Cake Build 的 URL：[`marketplace.visualstudio.com/items/cake-build.cake`](https://marketplace.visualstudio.com/items/cake-build.cake)。点击“获取免费”按钮开始将 Cake 扩展安装到 VSTS 中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/6d34143d-ba22-49af-8745-47065a3df190.png)

单击“获取免费”按钮将重定向到 VSTS Visual Studio | Marketplace 集成页面。在此页面上，选择要安装 Cake 的帐户，然后单击“安装”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/947534b0-a686-443c-988a-be18ff447e97.png)

安装成功后，将显示一条消息，说明一切都已设置，类似于以下截图中的内容。点击“转到帐户”按钮，将您重定向到 VSTS 帐户页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/b070cbca-7837-40dd-9ccf-6833033490e7.png)

# 添加构建任务

成功将 Cake 安装到 VSTS 后，您可以继续配置代码的构建方式以及软件的部署方式。VSTS 提供了简单的方法来构建您的源代码并发布您的软件。

要创建由 Cake 提供支持的 VSTS 构建，请单击“生成和发布”，然后选择“生成”子菜单。这将加载构建定义页面；单击此页面上的+新建按钮，开始构建创建过程。

将显示一个屏幕，选择存储库，如下截图所示。屏幕提供了从不同来源选择存储库的选项：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/544cb5b4-077e-422e-a531-7cc654d56472.png)

选择存储库来源后，单击“继续”按钮以加载模板屏幕。在此屏幕上，您可以选择用于配置构建的构建模板。VSTS 为各种支持的项目类型提供了特色模板。每个模板都配置了与模板项目相关的构建步骤：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/e63b9142-6916-4a5f-8188-5cd14f45db18.png)

向下滚动到模板列表的底部，或者在搜索框中简单地输入`Empty`以选择空模板。将鼠标悬停在模板上以激活“应用”按钮，然后单击该按钮，以继续到任务创建页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/1ba64504-80ab-4d87-b810-054e4f38e9c0.png)

当任务屏幕加载时，单击+按钮以向构建添加任务。滚动浏览显示的任务模板列表，选择 Cake，或使用搜索框过滤到 Cake。单击“添加”按钮，将 Cake 任务添加到构建阶段可用任务列表中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/d407e556-07ea-4bd5-876c-d191b8a749c7.png)

添加 Cake 任务后，单击任务以加载属性屏幕。单击“浏览”按钮以选择包含`LoanApplication`项目的构建脚本的`build.cake`文件，以与构建任务关联。您可以修改显示名称并更改目标和详细程度属性。此外，如果有要传递给 Cake 脚本的参数，可以在提供的字段中提供它们：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/e46ff1de-a080-497a-ab65-c83afea895a1.png)

单击“保存并排队”菜单，然后选择“保存并排队”，以确保创建的构建将在托管代理上排队。这将加载构建定义和排队屏幕，您可以在其中指定注释和代理队列：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/e95a8519-58e3-4077-9499-e3ae3f19339a.png)

托管代理是运行构建作业的软件。使用托管代理是执行构建的最简单和最简单的方法。托管代理由 VSTS 团队管理。

如果构建成功排队，您应该会收到屏幕上显示构建编号的通知，指出构建已排队：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/396d581f-b7cd-45c5-9965-d83a83a5448c.png)

单击构建编号以导航到构建执行页面。托管代理将处理队列并执行队列中构建的配置任务。构建代理将显示构建执行的进度。执行完成后，将报告构建的成功或失败。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/6ddaec63-edb0-41ea-96a6-8b422da65ba3.png)

VSTS 提供了巨大的好处，并简化了 CI 和 CD 过程。它提供了工具和功能，允许不同的 IDE 轻松集成，并使端到端的开发和项目测试相对容易。

# 摘要

在本章中，我们详细探讨了 Cake 构建自动化。我们介绍了安装 Cake 和 Cake Bootstrapper 的步骤。之后，我们探讨了编写 Cake 构建脚本和任务创建的过程，并提供了可用于各种构建活动的示例任务。

此外，我们为`LoanApplication`项目创建了一个构建脚本，其中包含了清理、恢复和构建解决方案中所有项目以及构建解决方案中包含的单元测试项目的任务。

后来，我们在 TeamCity 中创建了一个构建步骤，通过使用 PowerShell 作为运行器类型来执行 Cake 脚本。在本章的后面，我们介绍了如何设置 Microsoft Visual Studio Team Services，安装 Cake 到 VSTS，并配置了一个包含 Cake 任务的构建步骤。

在最后一章中，我们将探讨如何使用 Cake 脚本执行 xUnit.net 测试。在本章的后面，我们将探讨.NET Core 版本控制、.NET Core 打包和元包。我们将为 NuGet 分发打包`LoanApplication`项目。


# 第九章：测试和打包应用程序

在第八章中，*创建持续集成构建流程*，我们介绍了 Cake 自动化构建工具的安装和设置过程。此外，我们广泛演示了使用 Cake 编写构建脚本的过程，以及其丰富的 C#领域特定语言。我们还介绍了在 Visual Studio 中安装 Cake 扩展，并使用*任务资源管理器*窗口运行 Cake 脚本。

CI 流程为软件开发带来的好处不言而喻；它通过早期和快速检测，促进了项目代码库中错误的轻松修复。使用 CI，可以自动化运行和报告单元测试项目的测试覆盖率，以及项目构建和部署。

为了有效地利用 CI 流程的功能，代码库中的单元测试项目应该运行，并且应该由 CI 工具生成测试覆盖报告。在本章中，我们将修改 Cake 构建脚本，以运行我们的一系列 xUnit.net 测试。

在本章后面，我们将探讨.NET Core 版本控制以及它对应用程序开发的影响。最后，我们将为在.NET Core 支持的各种平台上分发的`LoanApplication`项目进行打包。之后，我们将探讨如何将.NET Core 应用程序打包以在 NuGet 上共享。

本章将涵盖以下主题：

+   使用 Cake 执行 xUnit.net 测试

+   .NET Core 版本控制

+   .NET Core 包和元包

+   用于 NuGet 分发的打包

# 使用 Cake 执行 xUnit.net 测试

在第八章中，*创建持续集成构建流程*，在*LoanApplication 构建脚本*部分，我们介绍了使用 Cake 自动化构建脚本创建和运行构建步骤的过程。使用 xUnit 控制台运行程序和 xUnit 适配器，可以更轻松地从 Visual Studio IDE、Visual Studio Code 或任何其他适合构建.NET 和.NET Core 应用程序的 IDE 中获取单元测试的测试结果和覆盖率。然而，为了使 CI 流程和构建流程完整和有效，单元测试项目应该作为构建步骤的一部分进行编译和执行。

# 在.NET 项目中执行 xUnit.net 测试

Cake 对运行 xUnit.net 测试有很好的支持。Cake 有两个别名，用于运行不同版本的 xUnit.net 测试——xUnit 用于运行早期版本的 xUnit.net，xUnit2 用于 xUnit.net 的版本 2。要使用别名的命令，必须在`XUnit2Settings`类中指定到 xUnit.net 的**ToolPath**，或者在`build.cake`文件中包含工具指令，以指示 Cake 从 NuGet 获取运行 xUnit.net 测试所需的二进制文件。

以下是包含 xUnit.net 工具指令的语法：

```cs
#tool "nuget:?package=xunit.runner.console"
```

Cake 的`XUnit2Alias`有不同形式的重载，用于运行指定程序集中的 xUnit.net 版本测试。该别名位于 Cake 的`Cake.Common.Tools.XUnit`命名空间中。第一种形式是`XUnit2(ICakeContext, IEnumerable<FilePath>)`，用于在`IEnumerable`参数中运行指定程序集中的所有 xUnit.net 测试。以下脚本显示了如何使用`GetFiles`方法将要执行的测试程序集获取到`IEnumerable`对象，并将其传递给`XUnit2`方法：

```cs
#tool "nuget:?package=xunit.runner.console"

Task("Execute-Test")  
    .Does(() =>
    {
        var assemblies = GetFiles("./LoanApplication.Tests.Unit/bin/Release/LoanApplication.Tests.Unit.dll");
        XUnit2(assemblies);    
    });
```

`XUnit2(ICakeContext, IEnumerable<FilePath>, XUnit2Settings)`别名类似于第一种形式，还增加了`XUnit2Settings`类，用于指定 Cake 应该如何执行 xUnit.net 测试的选项。以下代码片段描述了用法：

```cs
#tool "nuget:?package=xunit.runner.console"

Task("Execute-Test")  
    .Does(() =>
    {
        var assemblies = GetFiles("./LoanApplication.Tests.Unit/bin/Release/LoanApplication.Tests.Unit.dll");
        XUnit2(assemblies,
         new XUnit2Settings {
            Parallelism = ParallelismOption.All,
            HtmlReport = true,
            NoAppDomain = true,
            OutputDirectory = "./build"
        });
    });
```

另外，`XUnit2`别名允许传递字符串的`IEnumerable`，该字符串应包含要执行的 xUnit.net 版本 2 测试项目的程序集路径。形式为`XUnit2(ICakeContext, IEnumerable<string>)`，以下代码片段描述了用法：

```cs
#tool "nuget:?package=xunit.runner.console"

Task("Execute-Test")  
    .Does(() =>
    {
        XUnit2(new []{
        "./LoanApplication.Tests.Unit/bin/Release/LoanApplication.Tests.Unit.dll",
        "./LoanApplication.Tests/bin/Release/LoanApplication.Tests.dll"
    });
    });
```

# 在.NET Core 项目中执行 xUnit.net 测试

为了成功完成构建过程，重要的是在解决方案中运行测试项目，以验证代码是否正常工作。通过使用`DotNetCoreTest`别名，相对容易地在.NET Core 项目中运行 xUnit.net 测试，使用`dotnet test`命令。为了访问**dotnet-xunit**工具的其他功能，最好使用`DotNetCoreTool`运行测试。

在.NET Core 项目中，通过运行`dotnet test`命令来执行单元测试。该命令支持编写.NET Core 测试的所有主要单元测试框架，前提是该框架具有测试适配器，`dotnet test`命令可以集成以公开可用的单元测试功能。

使用 dotnet-xunit 框架工具运行.NET Core 测试可以访问 xUnit.net 中的功能和设置，并且是执行.NET Core 测试的首选方式。要开始，应该通过编辑`.csproj`文件并在`ItemGroup`部分包含`DotNetCliToolReference`条目，将 dotnet-xunit 工具安装到.NET Core 测试项目中。还应该添加`xunit.runner.visualstudio`和`Microsoft.NET.Test.Sdk`包，以便能够使用`dotnet test`或`dotnet xunit`命令执行测试：

```cs
<ItemGroup>
  <DotNetCliToolReference Include="dotnet-xunit" Version="2.3.1" />
  <PackageReference Include="xunit" Version="2.3.1" />
  PackageReference Include="xunit.runner.visualstudio" Version="2.3.1" />
</ItemGroup>
```

此外，还有其他参数可用于在使用`dotnet xunit`命令执行.NET Core 单元测试时自定义 xUnit.net 框架的行为。可以通过在终端上运行`dotnet xunit --help`命令来显示这些参数及其用法。

Cake 具有别名，可用于调用 dotnet SDK 命令来执行 xUnit.net 测试。`DotNetCoreRestore`别名使用`dotnet restore`命令还原解决方案中使用的 NuGet 包。此外，`DotNetCoreBuild`别名负责使用`dotnet build`命令构建.NET Core 解决方案。使用`DotNetCoreTest`别名执行测试项目中的单元测试，该别名使用`dotnet test`命令。请参见以下 Cake 片段，了解别名的用法。

```cs
var configuration = Argument("Configuration", "Release"); 

Task("Execute-Restore")  
    .Does(() =>
    {
        DotNetCoreRestore();
    });

Task("Execute-Build")  
    .IsDependentOn("Execute-Restore")
    .Does(() =>
    {
        DotNetCoreBuild("./LoanApplication.sln"
           new DotNetCoreBuildSettings()
                {
                    Configuration = configuration
                }
        );
    });

Task("Execute-Test")  
    .IsDependentOn("Execute-Build")
    .Does(() =>
    {
        var testProjects = GetFiles("./LoanApplication.Tests.Unit/*.csproj");
        foreach(var project in testProjects)
        {
            DotNetCoreTest(
                project.FullPath,
                new DotNetCoreTestSettings()
                {
                    Configuration = configuration,
                    NoBuild = true
                }
            );
        }
 });

```

另外，可以使用`DotNetCoreTool`别名来执行.NET Core 项目的 xUnit.net 测试。`DotNetCoreTool`是 Cake 中的通用别名，可用于执行任何 dotnet 工具。这是通过提供工具名称和必要的参数（如果有）来完成的。`DotNetCoreTool`公开了`dotnet xunit`命令中可用的其他功能，从而灵活地调整单元测试的执行方式。使用`DotNetCoreTool`别名时，需要手动将命令行参数传递给别名。请参见以下片段中别名的用法：

```cs
var configuration = Argument("Configuration", "Release");  

Task("Execute-Test")  
    .Does(() =>
    {
        var testProjects = GetFiles("./LoanApplication.Tests.Unit/*.csproj");
        foreach(var testProject in testProjects)
        {
            DotNetCoreTool(
                projectPath: testProject.FullPath, 
                command: "xunit", 
                arguments: $"-configuration {configuration} -diagnostics -stoponfail"
            );
        }
    });
```

# .NET Core 版本

对.NET Core SDK 和运行时进行版本控制使得平台易于理解，并且具有更好的灵活性。.NET Core 平台本质上是作为一个单元分发的，其中包括不同发行版的框架、工具、安装程序和 NuGet 包。此外，对.NET Core 平台进行版本控制可以在不同的.NET Core 平台上实现并行应用程序开发，具有很大的灵活性。

从.NET Core 2.0 开始，使用了易于理解的顶级版本号来对.NET Core 进行版本控制。一些.NET Core 版本组件一起进行版本控制，而另一些则不是。然而，从 2.0 版本开始，对.NET Core 发行版和组件采用了一致的版本控制策略，其中包括网页、安装程序和 NuGet 包。

.NET Core 使用的版本模型基于框架的运行时组件`[major].[minor]`版本号。与运行时版本号类似，SDK 版本使用带有额外独立`[patch]`的`[major].[minor]`版本号，该版本号结合了 SDK 的功能和补丁语义。

# 版本原则

截至.NET Core 2.0 版本，采用了以下原则：

+   将所有.NET Core 发行版版本化为*x.0.0*，例如第一个版本为 2.0.0，然后一起向前发展

+   文件和软件包名称应清楚地表示组件或集合及其版本，将版本分歧调和留给次要和主要版本边界

+   高阶版本和链接多个组件的安装程序之间应存在清晰的沟通。

此外，从.NET Core 2.0 开始，共享框架和相关运行时、.NET Core SDK 和相关.NET Core CLI 以及`Microsoft.NETCore.App`元包的版本号被统一了。使用单个版本号可以更容易地确定在开发机器上安装的 SDK 版本以及在将应用程序移动到生产环境时应该使用的共享框架版本。

# 安装程序

每日构建和发布的下载符合新的命名方案。从.NET Core 2.0 开始，下载中提供的安装程序 UI 也已修改，以显示正在安装的组件的名称和版本。命名方案格式如下：

```cs
[product]-[component]-[major].[minor].[patch]-[previewN]-[optional build #]-[rid].[file ext]
```

此外，格式详细显示了正在下载的内容，其版本，可以在哪种操作系统上使用，以及它是否可读。请参见下面显示的格式示例：

```cs
dotnet-runtime-2.0.7-osx-x64.pkg                    # macOS runtime installer
dotnet-runtime-2.0.7-win-x64.exe                    # Windows SDK installer
```

安装程序中包含的网站和 UI 字符串的描述保持简单、准确和一致。有时，SDK 版本可能包含多个运行时版本。在这种情况下，当安装过程完成时，安装程序 UX 仅在摘要页面上显示 SDK 版本和已安装的运行时版本。这适用于 Windows 和 macOS 的安装程序。

此外，可能需要更新.NET Core 工具，而不一定需要更新运行时。在这种情况下，SDK 版本会增加，例如到 2.1.2。下次更新时，运行时版本将增加，例如，下次更新时，运行时和 SDK 都将作为 2.1.3 进行发布。

# 软件包管理器

.NET Core 平台的灵活性使得分发不仅仅由微软完成；其他实体也可以分发该平台。该平台的灵活性使得为 Linux 发行版所有者分发安装程序和软件包变得容易。同时，也使得软件包维护者可以轻松地将.NET Core 软件包添加到其软件包管理器中。

最小软件包集的详细信息包括`dotnet-runtime-[major].[minor]`，这是具有特定 major+minor 版本组合的.NET 运行时，并且在软件包管理器中可用。`dotnet-sdk`包括前向 major、minor、patch 版本以及更新卷。软件包集中还包括`dotnet-sdk-[major].[minor]`，这是具有最高指定版本的共享框架和最新主机的 SDK，即`dotnet-host`。

# Docker

与安装程序和软件包管理器类似，docker 标签采用命名约定，其中版本号放在组件名称之前。可用的 docker 标签包括以下运行时版本：

+   `1.0.8-runtime`

+   `1.0.8-sdk`

+   `2.0.4-runtime`

+   `2.0.4-sdk`

+   `2.1.1-runtime`

+   `2.1.1-sdk`

当包含在 SDK 中的.NET Core CLI 工具被修复并重新发布时，SDK 版本会增加，例如，当版本从 2.1.1 增加到版本 2.1.2。此外，重要的是要注意，SDK 标签已更新以表示 SDK 版本而不是运行时。基于此，运行时将在下次发布时赶上 SDK 版本编号，例如，下次发布时，SDK 和运行时将都采用版本号 2.1.3。

# 语义版本控制

.NET Core 使用语义版本控制来描述.NET Core 版本中发生的更改的类型和程度。**语义版本控制**（**SemVer**）使用`MAJOR.MINOR.PATCH`版本模式：

```cs
MAJOR.MINOR.PATCH[-PRERELEASE-BUILDNUMBER]
```

SemVer 的`PRERELEASE`和`BUILDNUMBER`部分是可选的，不是受支持的版本的一部分。它们专门用于夜间构建、从源目标进行本地构建和不受支持的预览版本。

当旧版本不再受支持时，采用现有依赖项的较新`MAJOR`版本，或者切换兼容性怪癖的设置时，将递增版本的`MAJOR`部分。每当现有依赖项有较新的`MINOR`版本，或者有新的依赖项、公共 API 表面积或新行为添加时，将递增`MINOR`。每当现有依赖项有较新的`PATCH`版本、对较新平台的支持或有错误修复时，将递增`PATCH`。

当`MAJOR`被递增时，`MINOR`和`PATCH`被重置为零。同样，当`MINOR`被递增时，`PATCH`被重置为零，而`MAJOR`不受影响。这意味着每当有多个更改时，受影响的最高元素会被递增，而其他部分会被重置为零。

通常，预览版本的版本会附加`-preview[number]-([build]|"final")`，例如，2.1.1-preview1-final。开发人员可以根据.NET Core 的两种可用发布类型**长期支持**（**LTS**）和**当前**，选择所需的功能和稳定级别。

LTS 版本是一个相对更稳定的平台，支持时间更长，而新功能添加得更少。当前版本更频繁地添加新功能和 API，但允许安装更新的时间较短，提供更频繁的更新，并且支持时间比 LTS 更短。

# .NET Core 软件包和 metapackages

.NET Core 平台是作为一组通常称为 metapackages 的软件包进行发布的。该平台基本上由 NuGet 软件包组成，这有助于使其轻量级且易于分发。.NET Core 中的软件包提供了平台上可用的原语和更高级别的数据类型和常用实用程序。此外，每个软件包直接映射到一个具有相同名称的程序集；`System.IO.FileSystem.dll`程序集是`System.IO.FileSystem`软件包。

.NET Core 中的软件包被定义为细粒度。这带来了巨大的好处，因为在该平台上开发的应用程序的结果是印刷小，只包含在项目中引用和使用的软件包。未引用的软件包不会作为应用程序分发的一部分进行发布。此外，细粒度软件包可以提供不同的操作系统和 CPU 支持，以及仅适用于一个库的特定依赖关系。.NET Core 软件包通常与平台支持一起发布。这允许修复作为轻量级软件包更新进行分发和安装。

以下是.NET Core 可用的一些 NuGet 软件包：

+   `System.Runtime`：这是.NET Core 软件包，包括`Object`、`String`、`Array`、`Action`和`IList<T>`。

+   `System.Reflection`：此软件包包含用于加载、检查和激活类型的类型，包括`Assembly`、`TypeInfo`和`MethodInfo`。

+   `System.Linq`：用于查询对象的一组类型，包括`Enumerable`和`ILookup<TKey,TElement>`。

+   `System.Collections`：用于通用集合的类型，包括`List<T>`和`Dictionary<TKey,TValue>`。

+   `System.Net.Http`：用于 HTTP 网络通信的类型，包括`HttpClient`和`HttpResponseMessage`。

+   `System.IO.FileSystem`：用于读取和写入本地或网络磁盘存储的类型，包括**文件**和**目录**。

在您的.Net Core 项目中引用软件包相对容易。例如，如果您在项目中包含`System.Reflection`，则可以在项目中引用它，如下所示：

```cs
<Project Sdk="Microsoft.NET.Sdk">
<PropertyGroup>
<TargetFramework>netstandard2.0</TargetFramework>
</PropertyGroup>
<ItemGroup>
<PackageReference Include="System.Reflection" Version="4.3.0" />
</ItemGroup>
</Project> 
```

# Metapackage

**元包**是除了项目中已引用的目标框架之外，添加到.NET Core 项目中的引用或依赖关系。例如，您可以将`Microsoft.NETCore.App`或`NetStandard.Library`添加到.NET Core 项目中。

有时，需要在项目中使用一组包。这是通过使用元包来完成的。元包是经常一起使用的一组包。此外，元包是描述一组或一套包的 NuGet 包。当指定框架时，元包可以为这些包创建一个框架。

当您引用一个元包时，实质上是引用了元包中包含的所有包。实质上，这使得这些包中的库在使用 Visual Studio 进行项目开发时可以进行智能感知。此外，这些库在项目发布时也将可用。

在.NET Core 项目中，元包是由项目中的目标框架引用的，这意味着元包与特定框架强烈关联或绑定在一起。元包可以访问已经确认和测试过可以一起工作的一组包。

.NET Standard 元包是`NETStandard.Library`，它构成了.NET 标准中的一组库。这适用于.NET 平台的不同变体：.NET Core、.NET Framework 和 Mono 框架。

`Microsoft.NETCore.App`和`Microsoft.NETCore.Portable.Compatibility`是主要的.NET Core 元包。`Microsoft.NETCore.App`描述了构成.NET Core 分发的库集，并依赖于`NETStandard.Library`。

`Microsoft.NETCore.Portable.Compatibility`描述了一组 facade，使得基于 mscorlib 的**可移植类库**（**PCLs**）可以在.NET Core 上工作。

# Microsoft.AspNetCore.All 元包

`Microsoft.AspNetCore.All`是 ASP.NET Core 的元包。该元包包括由 ASP.NET Core 团队支持和维护的包，Entity Framework Core 支持的包，以及 ASP.NET Core 和 Entity Framework Core 都使用的内部和第三方依赖项。

针对 ASP.NET Core 2.0 的可用默认项目模板使用`Microsoft.AspNetCore.All`包。ASP.NET Core 版本号和 Entity Framework Core 版本号与`Microsoft.AspNetCore.All`元包的版本号相似。ASP.NET Core 2.x 和 Entity Framework Core 2.x 中的所有可用功能都包含在`Microsoft.AspNetCore.All`包中。

当您创建一个引用`Microsoft.AspNetCore.All`元包的 ASP.NET Core 应用程序时，.NET Core Runtime Store 将可供您使用。.NET Core Runtime Store 公开了运行 ASP.NET Core 2.x 应用程序所需的运行时资源。

在部署过程中，引用的 ASP.NET Core NuGet 包中的资源不会与应用程序一起部署，这些资源位于.NET Core Runtime Store 中。这些资源经过预编译以提高性能，加快应用程序启动时间。此外，排除未使用的包是可取的。这是通过使用包修剪过程来完成的。

要使用`Microsoft.AspNetCore.All`包，应将其添加为.NET Core 的`.csproj`项目文件的引用，就像以下 XML 配置中所示：

```cs
<Project Sdk="Microsoft.NET.Sdk.Web">

  <PropertyGroup>
    <TargetFramework>netcoreapp2.0</TargetFramework>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.All" Version="2.0.0" />
  </ItemGroup>

</Project>
```

# NuGet 分发的打包

.NET Core 的灵活性不仅限于应用程序的开发，还延伸到部署过程。部署.NET Core 应用程序可以采用两种形式——**基于框架的部署**（**FDD**）和**独立部署**（**SCD**）。

使用 FDD 方法需要在开发应用程序的计算机上安装系统范围的.NET Core。安装的.NET Core 运行时将被应用程序和在该计算机上部署的其他应用程序共享。

这使得应用程序可以在不同版本或安装的 .NET Core 框架之间轻松移植。此外，使用此方法时，部署将是轻量级的，只包含应用程序的代码和使用的第三方库。使用此方法时，为应用程序创建了 `.dll` 文件，以便可以从命令行启动。

SCD 允许您将应用程序与运行所需的 .NET Core 库和 .NET Core 运行时一起打包。实质上，您的应用程序不依赖于部署计算机上已安装的 .NET Core 的存在。

使用此方法时，可执行文件（本质上是平台特定的 .NET Core 主机的重命名版本）将作为应用程序的一部分打包。在 Windows 上，此可执行文件为 `app.exe`，在 Linux 和 macOS 上为 `app`。与使用 *依赖于框架的方法* 部署应用程序时一样，为应用程序创建了 `.dll` 文件，以便启动应用程序。

# dotnet publish 命令

`dotnet publish` 命令用于编译应用程序，并在将应用程序和依赖项复制到准备部署的文件夹之前检查应用程序的依赖项。执行该命令是准备 .NET Core 应用程序进行部署的唯一官方支持的方式。概要在此处：

```cs
dotnet publish [<PROJECT>] [-c|--configuration] [-f|--framework] [--force] [--manifest] [--no-dependencies] [--no-restore] [-o|--output] [-r|--runtime] [--self-contained] [-v|--verbosity] [--version-suffix]

dotnet publish [-h|--help]
```

运行命令时，输出将包含 `.dll` 程序集中包含的**中间语言**（**IL**）代码，包含项目依赖项的 `.deps.json` 文件，指定预期共享运行时的 `.runtime.config.json` 文件，以及从 NuGet 缓存中复制到输出文件夹中的应用程序依赖项。

命令的参数和选项在此处解释：

+   `PROJECT`：用于指定要编译和发布的项目，默认为当前文件夹。

+   -c|--configuration：用于指定构建配置的选项，可取 `Debug` 和 `Release` 值，默认值为 `Debug`。

+   -f|--framework <FRAMEWORK>：目标框架选项，与命令一起指定时，将为目标框架发布应用程序。

+   --force：用于强制解析依赖项，类似于删除 `project.assets.json` 文件。

+   -h|--help：显示命令的帮助信息。

+   --manifest <PATH_TO_MANIFEST_FILE>：用于指定要在修剪应用程序发布的软件包时使用的一个或多个目标清单。

+   --no-dependencies：此选项用于忽略项目对项目的引用，但会还原根项目。

+   --no-restore：指示命令不执行隐式还原。

+   -o|--output <OUTPUT_DIRECTORY>：用于指定输出目录的路径。如果未指定该选项，则默认为 FDD 的 `./bin/[configuration]/[framework]/` 或 SCD 的 `./bin/[configuration]/[framework]/[runtime]`。

+   -r|--runtime <RUNTIME_IDENTIFIER>：用于为特定运行时发布应用程序，仅在创建 SCD 时使用。

+   --self-contained：用于指定 SCD。当指定运行时标识符时，默认值为 true。

+   -v|--verbosity <LEVEL>：用于指定 `dotnet publish` 命令的详细程度。允许的值为 `q[uiet]`、`n[ormal]`、`m[inimal]`、`diag[nostic]` 和 `d[etailed]`。

+   --version-suffix <VERSION_SUFFIX>：用于指定在项目文件的版本字段中替换星号 (`*`) 时要使用的版本后缀。

命令的使用示例是在命令行上运行 `dotnet publish`。这将发布当前文件夹中的项目。要发布本书中使用的 `LoanApplication` 项目，可以运行 `dotnet publish` 命令。这将使用项目中指定的框架发布应用程序。ASP.NET Core 应用程序依赖的解决方案中的项目将与之一起构建。请参阅以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/6e3b3ee4-f49d-48dd-aefc-4d7c53f9f986.png)

在`netcoreapp2.0`文件夹中创建了一个`publish`文件夹，其中将复制所有编译文件和依赖项：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/71dacc7f-c199-41f2-a5bb-a3985c070d53.png)

# 创建一个 NuGet 软件包

**NuGet**是.NET 的软件包管理器，它是一个开源的软件包管理器，为构建在.NET Framework 和.NET Core 平台上的应用程序提供了更简单的版本控制和分发库的方式。NuGet 库是.NET 的中央软件包存储库，用于托管包作者和消费者使用的所有软件包。

使用.NET Core 的`dotnet pack`命令可以轻松创建 NuGet 软件包。运行此命令时，它会构建.NET Core 项目，并从中创建一个 NuGet 软件包。打包的.NET Core 项目的 NuGet 依赖项将被添加到`.nuspec`文件中，以确保在安装软件包时它们被解析。显示以下命令概要：

```cs
dotnet pack [<PROJECT>] [-c|--configuration] [--force] [--include-source] [--include-symbols] [--no-build] [--no-dependencies]
 [--no-restore] [-o|--output] [--runtime] [-s|--serviceable] [-v|--verbosity] [--version-suffix]

dotnet pack [-h|--help]
```

这里解释了命令的参数和选项：

+   `PROJECT`用于指定要打包的项目，可以是目录的路径或`.csproj`文件。默认为当前文件夹。

+   `c|--configuration`：此选项用于定义构建配置。它接受`Debug`和`Release`值。默认值为`Debug`。

+   `--force`：用于强制解析依赖项，类似于删除`project.assets.json`文件。

+   `-h|--help`：显示命令的帮助信息。

+   `-include-source`：用于指定源文件包含在 NuGet 软件包的`src`文件夹中。

+   `--include-symbols`：生成`nupkg`符号。

+   `--no-build`：这是为了指示命令在打包之前不要构建项目。

+   `--no-dependencies`：此选项用于忽略项目对项目的引用，但恢复根项目。

+   `--no-restore`：这是为了指示命令不执行隐式还原。

+   `-o|--output <OUTPUT_DIRECTORY>`：用于指定输出目录的路径，以放置构建的软件包。

+   `-r|--runtime <RUNTIME_IDENTIFIER>`：此选项用于指定要为其还原软件包的目标运行时。

+   `-s|--serviceable`：用于在软件包中设置可服务标志。

+   `-v|--verbosity <LEVEL>`：用于指定命令的详细程度。允许的值为`q[uiet]`、`m[inimal]`、`n[ormal]`、`d[etailed]`和`diag[nostic]`。

+   `--version-suffix <VERSION_SUFFIX>`：用于指定在项目文件的版本字段中替换星号(`*`)时要使用的版本后缀。

运行`dotnet pack`命令将打包当前目录中的项目。要打包`LoanApplication.Core`项目，可以运行以下命令：

```cs
dotnet pack C:\LoanApplication\LoanApplication.Core\LoanApplication.Core.csproj --output nupkgs
```

运行该命令时，`LoanApplication.Core`项目将被构建并打包到项目文件夹中的`nupkgs`文件中。将创建`LoanApplication.Core.1.0.0.nupkg`文件，其中包含打包项目的库：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/15b74cee-dd94-4076-b5dc-faa7f6040573.png)

应用程序打包后，可以使用`dotnet nuget push`命令将其发布到 NuGet 库。为了能够将软件包推送到 NuGet，您需要注册 NuGet API 密钥。在上传软件包到 NuGet 时，这些密钥需要作为`dotnet nuget push`命令的选项进行指定。

运行`dotnet nuget push LoanApplication.Core.1.0.0.nupkg -k <api-key> -s https://www.nuget.org/`命令将创建的 NuGet 软件包推送到库中，从而使其他开发人员可以使用。运行该命令时，将建立到 NuGet 服务器的连接，以在您的帐户下推送软件包：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/601521bb-89f1-45a2-bf67-f262cb128c78.png)

将软件包推送到 NuGet 库后，登录您的帐户，您可以在已发布软件包的列表中找到推送的软件包：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/680b6ae6-3f27-4c89-af9b-224ae44623d1.png)

当您将软件包上传到 NuGet 库时，其他程序员可以直接从 Visual Studio 使用 NuGet 软件包管理器搜索您的软件包，并在其项目中添加对库的引用。

# 总结

在本章中，我们首先使用 Cake 执行了 xUnit.net 测试。此外，我们广泛讨论了.NET Core 的版本控制、概念以及它对.NET Core 平台应用开发的影响。之后，我们为 NuGet 分发打包了本书中使用的`LoanApplication`项目。

在本书中，您已经经历了一次激动人心的 TDD 之旅。使用 xUnit.net 单元测试框架，TDD 的概念被介绍并进行了广泛讨论。还涵盖了数据驱动的单元测试，这使您能够使用不同数据源的数据来测试您的代码。

Moq 框架被用来介绍和解释如何对具有依赖关系的代码进行单元测试。TeamCity CI 服务器被用来解释 CI 的概念。Cake，一个跨平台构建系统被探讨并用于创建在 TeamCity 中执行的构建步骤。此外，另一个 CI 工具 Microsoft VSTS 被用来执行 Cake 脚本。

最后，有效地使用 TDD 在代码质量和最终应用方面是非常有益的。通过持续的实践，本书中解释的所有概念都可以成为您日常编程例行的一部分。
