# C#9 和 .NET5 软件架构（七）

> 原文：[`zh.annas-archive.org/md5/83D8F5A1D11ACA866E980121BEEF9AAA`](https://zh.annas-archive.org/md5/83D8F5A1D11ACA866E980121BEEF9AAA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十九章：使用工具编写更好的代码

正如我们在*第十七章*中看到的，*C# 9 编码的最佳实践*，编码可以被视为一种艺术，但编写易懂的代码更像是哲学。在那一章中，我们讨论了作为软件架构师需要遵守的实践。在本章中，我们将描述代码分析的技术和工具，以便您为项目编写出良好的代码。

本章将涵盖以下主题：

+   识别写得好的代码

+   理解可以在过程中使用的工具，以使事情变得更容易

+   应用扩展工具来分析代码

+   在分析后检查最终代码

+   用例——在发布应用程序之前实施代码检查

在本章结束时，您将能够确定要将哪些工具纳入软件开发生命周期，以便简化代码分析。

# 技术要求

本章需要使用 Visual Studio 2019 免费的 Community Edition 或更高版本。您可以在[`github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5/tree/master/ch19`](https://github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5/tree/master/ch19)找到本章的示例代码。

# 识别写得好的代码

很难定义代码是否写得好。*第十七章*中描述的最佳实践肯定可以指导您作为软件架构师为团队定义标准。但即使有了标准，错误也会发生，而且您可能只会在代码投入生产后才发现它们。因为代码不符合您定义的所有标准而决定在生产中重构代码并不是一个容易的决定，特别是如果涉及的代码正常运行。有些人得出结论，写得好的代码就是在生产中正常运行的代码。然而，这肯定会对软件的生命周期造成损害，因为开发人员可能会受到那些非标准代码的启发。

因此，作为软件架构师，您需要找到方法来强制执行您定义的编码标准。幸运的是，如今我们有许多工具可以帮助我们完成这项任务。它们被视为静态代码分析的自动化。这种技术被视为改进开发的软件和帮助开发人员的重大机会。

您的开发人员将通过代码分析而进步的原因是，您开始在代码检查期间在他们之间传播知识。我们现在拥有的工具也有同样的目的。更好的是，通过 Roslyn，它们可以在您编写代码时执行此任务。Roslyn 是.NET 的编译器平台，它使您能够开发一些用于分析代码的工具。这些分析器可以检查样式、质量、设计和其他问题。

例如，看看下面的代码。它毫无意义，但您仍然可以看到其中存在一些错误：

```cs
using System;
static void Main(string[] args)
{
    try
    {
        int variableUnused = 10;
        int variable = 10;
        if (variable == 10)
        {
             Console.WriteLine("variable equals 10");
        }
        else
        {
            switch (variable)
            {
                case 0:
                    Console.WriteLine("variable equals 0");
                    break;
            }
        }
    }
    catch
    {
    }
} 
```

这段代码的目的是向您展示一些工具的威力，以改进您正在交付的代码。让我们在下一节中研究每一个工具，包括如何设置它们。

# 理解和应用可以评估 C#代码的工具

Visual Studio 中代码分析的演变是持续的。这意味着 Visual Studio 2019 肯定比 Visual Studio 2017 等版本具有更多用于此目的的工具。

您（作为软件架构师）需要处理的问题之一是*团队的编码风格*。这肯定会导致对代码的更好理解。例如，如果您转到**Visual Studio 菜单**，**工具->选项**，然后在左侧菜单中转到**文本编辑器->C#**，您将找到设置如何处理不同代码样式模式的方法，而糟糕的编码风格甚至被指定为**代码样式**选项中的错误，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_19_01.png)

图 19.1：代码样式选项

前面的截图表明**避免未使用的参数**被视为错误。

在这种改变之后，与本章开头呈现的相同代码的编译结果是不同的，您可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_19_02.png)

图 19.2：代码样式结果

您可以导出您的编码样式配置并将其附加到您的项目，以便它遵循您定义的规则。

Visual Studio 2019 提供的另一个好工具是**分析和代码清理**。使用此工具，您可以设置一些代码标准，以清理您的代码。例如，在下面的截图中，它被设置为删除不必要的代码：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_19_03.png)

图 19.3：配置代码清理

运行代码清理的方法是通过在**解决方案资源管理器**区域中右键单击选择它，然后在要运行它的项目上运行。之后，此过程将在您拥有的所有代码文件中运行：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_19_04.png)

图 19.4：运行代码清理

在解决了代码样式和代码清理工具指示的错误之后，我们正在处理的示例代码有一些最小的简化，如下所示：

```cs
using System;
try
{
    int variable = 10;
    if (variable == 10)
    {
        Console.WriteLine("variable equals 10");
    }
    else
    {
        switch (variable)
        {
            case 0:
                Console.WriteLine("variable equals 0");
                break;
        }
    }
}
catch
{
} 
```

值得一提的是，前面的代码有许多改进仍需要解决。Visual Studio 允许您通过安装扩展来为 IDE 添加附加工具。这些工具可以帮助您提高代码质量，因为其中一些是为执行代码分析而构建的。本节将列出一些免费选项，以便您可以决定最适合您需求的选项。当然还有其他选项，甚至是付费选项。这里的想法不是指示特定的工具，而是给您一个对它们能力的概念。

要安装这些扩展，您需要在 Visual Studio 2019 中找到**扩展**菜单。以下是**管理扩展**选项的截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_19_05.png)

图 19.5：Visual Studio 2019 中的扩展

有许多其他很酷的扩展可以提高您的代码和解决方案的生产力和质量。在此管理器中搜索它们。

选择要安装的扩展后，您需要重新启动 Visual Studio。大多数扩展在安装后很容易识别，因为它们修改了 IDE 的行为。其中，Microsoft Code Analysis 2019 和 SonarLint for Visual Studio 2019 可以被认为是不错的工具，并将在下一节中讨论。

# 应用扩展工具来分析代码

尽管在代码样式和代码清理工具之后交付的示例代码比我们在本章开头呈现的代码要好，但显然远远不及*第十七章*中讨论的最佳实践。在接下来的章节中，您将能够检查两个扩展的行为，这些扩展可以帮助您改进这段代码：Microsoft Code Analysis 2019 和 SonarLint for Visual Studio 2019。

## 使用 Microsoft Code Analysis 2019

这个扩展由 Microsoft DevLabs 提供，是对我们过去自动化的 FxCop 规则的升级。它也可以作为 NuGet 包添加到项目中，因此可以成为应用程序 CI 构建的一部分。基本上，它有超过 100 个规则，用于在您输入代码时检测代码中的问题。

例如，仅通过启用扩展并重新构建我们在本章中使用的小样本，代码分析就发现了一个新的问题需要解决，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_19_06.png)

图 19.6：代码分析用法

值得一提的是，我们在*第十七章*中讨论了空的`try-catch`语句的使用作为反模式。因此，如果能以这种方式暴露这种问题，对代码的健康将是有益的。

## 应用 SonarLint for Visual Studio 2019

SonarLint 是 Sonar Source 社区的开源倡议，用于在编码时检测错误和质量问题。它支持 C#、VB.NET、C、C++和 JavaScript。这个扩展的好处是它提供了解决检测到的问题的解释，这就是为什么我们说开发人员在使用这些工具时学会了如何编写良好的代码。查看以下屏幕截图，其中包含对样本代码进行的分析：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_19_07.png)

图 19.7：SonarLint 使用

我们可以验证此扩展能够指出错误，并且如承诺的那样，对每个警告都有解释。这不仅有助于检测问题，还有助于培训开发人员掌握良好的编码实践。

# 在分析后检查最终代码

在分析了两个扩展之后，我们终于解决了所有出现的问题。我们可以检查最终代码，如下所示：

```cs
using System;
try
{
    int variable = 10;
    if (variable == 10)
    {
        Console.WriteLine("variable equals 10");
    }
    else
    {
        switch (variable)
        {
            case 0:
                Console.WriteLine("variable equals 0");
                break;
            default:
                Console.WriteLine("Unknown behavior");
                break;
        }
    }
}
catch (Exception err)
{
    Console.WriteLine(err);
} 
```

正如您所看到的，前面的代码不仅更容易理解，而且更安全，并且能够考虑编程的不同路径，因为`switch-case`的默认值已经编程。这种模式也在*第十七章* *C# 9 编码最佳实践*中讨论过，因此可以轻松地通过使用本章中提到的一个（或全部）扩展来遵循最佳实践。

# 用例-在发布应用程序之前评估 C#代码

在*第三章* *使用 Azure DevOps 记录需求*中，我们在平台上创建了 WWTravelClub 存储库。正如我们在那里看到的，Azure DevOps 支持持续集成，这可能很有用。在本节中，我们将讨论 DevOps 概念和 Azure DevOps 平台之所以如此有用的更多原因。

目前，我们想介绍的唯一一件事是，在开发人员提交代码后，但尚未发布时分析代码的可能性。如今，在面向应用程序生命周期工具的 SaaS 世界中，这仅仅是由于我们拥有一些 SaaS 代码分析平台才可能实现的。此用例将使用 Sonar Cloud。

Sonar Cloud 对于开源代码是免费的，并且可以分析存储在 GitHub、Bitbucket 和 Azure DevOps 中的代码。用户需要在这些平台上注册。一旦您登录，假设您的代码存储在 Azure DevOps 中，您可以按照以下文章中描述的步骤创建您的 Azure DevOps 和 Sonar Cloud 之间的连接：[`sonarcloud.io/documentation/analysis/scan/sonarscanner-for-azure-devops/`](https://sonarcloud.io/documentation/analysis/scan/sonarscanner-for-azure-devops/)。

在设置 Azure DevOps 中项目与 Sonar Cloud 之间的连接后，您将拥有一个类似以下的构建管道：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_19_08.png)

图 19.8：Azure 构建管道中的 Sonar Cloud 配置

值得一提的是，C#项目没有 GUID 号码，而 Sonar Cloud 需要这个。您可以使用此链接（[`www.guidgenerator.com/`](https://www.guidgenerator.com/)）轻松生成一个，并且需要将其放置在以下屏幕截图中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_19_09.png)

图 19.9：SonarQube 项目 GUID

一旦构建完成，代码分析的结果将在 Sonar Cloud 中呈现，如下屏幕截图所示。如果您想浏览此项目，可以访问[`sonarcloud.io/dashboard?id=WWTravelClubNet50`](https://sonarcloud.io/dashboard?id=WWTravelClubNet50)：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_19_10.png)

图 19.10：Sonar Cloud 结果

此时，经过分析的代码尚未发布，因此在发布系统之前，这对于获得下一个质量步骤非常有用。您可以将此方法用作在提交期间自动化代码分析的参考。

# 总结

本章介绍了可以用来应用*C# 9 编码最佳实践*中描述的最佳编码实践的工具。我们看了 Roslyn 编译器，它使开发人员在编码的同时进行代码分析，并且我们看了一个用例，即在发布应用程序之前评估 C#代码，该应用程序在 Azure DevOps 构建过程中实现代码分析使用 Sonar Cloud。

一旦您将本章学到的一切应用到您的项目中，代码分析将为您提供改进您交付给客户的代码质量的机会。这是作为软件架构师角色中非常重要的一部分。

在下一章中，您将使用 Azure DevOps 部署您的应用程序。

# 问题

1.  软件如何被描述为写得很好的代码？

1.  什么是 Roslyn？

1.  什么是代码分析？

1.  代码分析的重要性是什么？

1.  Roslyn 如何帮助进行代码分析？

1.  什么是 Visual Studio 扩展？

1.  为代码分析提供的扩展工具有哪些？

# 进一步阅读

以下是一些网站，您将在其中找到有关本章涵盖的主题的更多信息：

+   [`marketplace.visualstudio.com/items?itemName=VisualStudioPlatformTeam.MicrosoftCodeAnalysis2019`](https://marketplace.visualstudio.com/items?itemName=VisualStudioPlatformTeam.MicrosoftCodeAnalysis20)

+   [`marketplace.visualstudio.com/items?itemName=SonarSource.SonarLintforVisualStudio2019`](https://marketplace.visualstudio.com/items?itemName=SonarSource.SonarLintforVisualStudio2019)

+   [`github.com/dotnet/roslyn-analyzers`](https://github.com/dotnet/roslyn-analyzers)

+   [`docs.microsoft.com/en-us/visualstudio/ide/code-styles-and-code-cleanup`](https://docs.microsoft.com/en-us/visualstudio/ide/code-styles-and-code-cleanup)

+   [`sonarcloud.io/documentation/analysis/scan/sonarscanner-for-azure-devops/`](https://sonarcloud.io/documentation/analysis/scan/sonarscanner-for-azure-devops/)

+   [`www.guidgenerator.com/`](https://www.guidgenerator.com/)


# 第二十章：理解 DevOps 原则

DevOps 是一个每个人都在学习和实践的过程。但作为软件架构师，您需要理解并传播 DevOps，不仅作为一个过程，而且作为一种理念。本章将涵盖您开发和交付软件所需的主要概念、原则和工具。

在考虑 DevOps 理念时，本章将专注于所谓的**服务设计思维**，即将您设计的软件视为向组织/部分组织提供的服务。这种方法的主要收获是您的软件为目标组织提供的价值最为重要。此外，您不仅提供可工作的代码和修复错误的协议，还提供了您的软件构思的所有需求的解决方案。换句话说，您的工作包括满足这些需求所需的一切，例如监控用户满意度并在用户需求变化时调整软件。最后，更容易监控软件以发现问题和新需求，并迅速修改以适应不断变化的需求。

服务设计思维与我们在*第四章* *决定最佳基于云的解决方案*中讨论的**软件即服务**（**SaaS**）模型紧密相关。事实上，基于 Web 服务提供解决方案的最简单方式是提供 Web 服务的使用作为服务，而不是销售实现它们的软件。

本章将涵盖以下主题：

+   描述 DevOps 是什么，并查看如何在 WWTravelClub 项目中应用它的示例

+   理解 DevOps 原则和部署阶段以利用部署过程

+   理解使用 Azure DevOps 进行持续交付

+   定义持续反馈，并讨论 Azure DevOps 中相关工具

+   理解 SaaS 并为服务场景准备解决方案

+   用例 - 使用 Azure Pipelines 部署我们的软件包管理应用程序

与其他章节不同，WWTravelClub 项目将在主题中呈现，并且我们将在章节结束时提供额外的结论，让您有机会了解如何实施 DevOps 理念。所有展示 DevOps 原则的截图都来自本书的主要用例，因此您将能够轻松理解 DevOps 原则。在本章结束时，您将能够根据服务设计思维原则设计软件，并使用 Azure Pipelines 部署应用程序。

# 技术要求

本章需要安装 Visual Studio 2019 社区版或更高版本，并安装所有 Azure 工具。您可能还需要一个 Azure DevOps 帐户，如*第三章* *使用 Azure DevOps 记录需求*中所述。还需要一个免费的 Azure 帐户。如果您尚未创建，*第一章* *了解软件架构的重要性*中的*创建 Azure 帐户*子章节解释了如何创建。本章使用与*第十八章* *使用单元测试案例和 TDD 测试代码*相同的代码，可在此处找到：[`github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5`](https://github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5)。

# 描述 DevOps

DevOps 源自*开发和运维*这两个词的结合，因此这个过程简单地统一了这两个领域的行动。然而，当您开始更深入地研究它时，您会意识到仅仅连接这两个领域是不足以实现这一理念的真正目标的。

我们还可以说，DevOps 是回答当前人类关于软件交付的需求的过程。

微软的首席 DevOps 经理 Donovan Brown 对 DevOps 有一个精彩的定义：*DevOps 是人员、流程和产品的结合，以实现向最终用户持续交付价值*。[`donovanbrown.com/post/what-is-devops`](http://donovanbrown.com/post/what-is-devops)。

持续向我们的最终用户交付价值的方法，使用流程、人员和产品：这是对 DevOps 哲学的最佳描述。我们需要开发和交付以客户为导向的软件。一旦公司的所有部门都明白关键点是最终用户，作为软件架构师，您的任务就是提供能够促进交付过程的技术。

值得一提的是，本书的所有内容都与这种方法相关。这绝不是了解一堆工具和技术的问题。作为软件架构师，您必须明白，这总是一种更快地为最终用户带来解决方案的方式，与他们的真实需求联系在一起。因此，您需要学习 DevOps 原则，这将在本章讨论。

# 了解 DevOps 原则

将 DevOps 视为一种哲学，值得一提的是，有一些原则可以使这个过程在您的团队中运行良好。这些原则是持续集成、持续交付和持续反馈。

微软有一个专门的网页来定义 DevOps 概述、文化、实践、工具及其与云的关系。请查看[`azure.microsoft.com/en-us/overview/what-is-devops/`](https://azure.microsoft.com/en-us/overview/what-is-devops)。

在许多书籍和技术文章中，DevOps 以无限符号表示。这个符号代表软件开发生命周期中持续方法的必要性。在整个周期中，您需要计划、构建、持续集成、部署、运营、获得反馈，然后重新开始。这个过程必须是协作的，因为每个人都有同样的关注点——为最终用户提供价值。除了这些原则，作为软件架构师，您还需要决定最适合这种方法的最佳软件开发流程。我们在*第一章* *理解软件架构的重要性*中讨论了这些流程。

## 定义持续集成

当您开始构建企业解决方案时，协作是更快地完成任务和满足用户需求的关键。版本控制系统，正如我们在*第十七章* *C# 9 编码最佳实践*中讨论的那样，对于这个过程至关重要，但工具本身并不能完成工作，特别是如果工具没有很好地配置。

作为软件架构师，**持续集成**（**CI**）将帮助您对软件开发协作有一个具体的方法。当您实施它时，一旦开发人员提交他们的代码，主要代码就会自动构建和测试。

应用 CI 的好处在于可以激励开发人员尽快合并他们的更改，以最小化合并冲突。此外，他们可以共享单元测试，这将提高软件的质量。

在 Azure DevOps 中设置 CI 非常简单。在构建管道中，您可以通过编辑配置找到该选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_01.png)

图 20.1：启用持续集成复选框

值得一提的是，如果您的解决方案设置了单元测试和功能测试，一旦提交代码，它将自动编译和测试。这将使您的主分支在团队的每次提交后都保持稳定和安全。

CI 的关键点是能够更快地识别问题。当您允许他人测试和分析代码时，您将有这个机会。DevOps 方法的唯一帮助是确保这一切尽快发生。

# 了解使用 Azure DevOps 进行持续交付

一旦你的应用程序的每次提交都构建完成，并且这段代码经过了单元测试和功能测试，你可能也想要持续部署它。这不仅仅是配置工具的问题。作为软件架构师，你需要确保团队和流程准备好进行这一步。但让我们首先检查如何启用使用案例的第一个部署场景。

## 使用 Azure 管道部署我们的包管理应用程序

在本节中，我们将为在*第十八章*末尾定义的 DevOps 项目配置自动部署到 Azure App Service 平台。Azure DevOps 也可以自动创建新的 Web 应用程序，但为了防止配置错误（可能会消耗所有免费信用），我们将手动创建它，并让 Azure DevOps 只是部署应用程序。所有必需的步骤都被组织成各种小节，如下所示。

### 创建 Azure Web 应用程序和 Azure 数据库

可以通过以下简单的步骤定义 Azure Web 应用程序：

1.  转到 Azure 门户，并选择**应用服务**，然后点击**添加**按钮创建一个新的 Web 应用程序。填写所有数据如下：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_02.png)

图 20.2：创建 Azure Web 应用程序

1.  显然，你可以使用你已经拥有的**资源组**和对你来说最方便的区域。对于**运行时堆栈**，请选择与你在 Visual Studio 解决方案中使用的相同的.NET Core 版本。

1.  现在，如果你有足够的信用，让我们为应用程序创建一个 SQL Server 数据库，并将其命名为`PackagesManagementDatabase`。如果你没有足够的信用，不要担心——你仍然可以测试应用程序部署，但当它尝试访问数据库时，应用程序将返回错误。请参考*第九章*的*关系数据库*小节，了解如何创建 SQL Server 数据库。

### 配置你的 Visual Studio 解决方案

一旦你定义了 Azure Web 应用程序，你需要按照以下简单的步骤配置应用程序在 Azure 中运行：

1.  如果你定义了 Azure 数据库，你需要在你的 Visual Studio 解决方案中有两个不同的连接字符串，一个用于开发的本地数据库，另一个用于你的 Azure Web 应用程序。

1.  现在，在你的 Visual Studio 解决方案中打开`appsettings.Development.json`和`appsettings.json`，如下所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_03.png)

图 20.3：在 Visual Studio 中打开设置

1.  然后，将`appsettings.json`的整个`ConnectionStrings`节点复制到`appsettings.Development.json`中，如下所示：

```cs
"ConnectionStrings": {
        "DefaultConnection": "Server=(localdb)....."
}, 
```

1.  现在你在开发设置中有本地连接字符串，所以你可以将`appsettings.json`中的`DefaultConnection`更改为 Azure 数据库之一。

1.  转到 Azure 门户中的数据库，复制连接字符串，并用你在定义数据库服务器时获得的用户名和密码填写它。

1.  最后，本地提交你的更改，然后与远程存储库同步。现在，你的更改已经在 DevOps 管道上处理，以获得一个新的构建。

### 配置 Azure 管道

最后，通过以下步骤配置 Azure 管道，自动在 Azure 上交付你的应用程序：

1.  通过点击 Visual Studio **Team Explorer**窗口的**连接**选项卡中的**管理连接**链接，将 Visual Studio 与你的 DevOps 项目连接起来。然后，点击 DevOps 链接进入你的在线项目。

1.  修改`PackagesManagementWithTest`构建管道，添加一个单元测试步骤之后的进一步步骤。实际上，我们需要一个准备所有文件以在 ZIP 文件中部署的步骤。

1.  点击`PackagesManagementWithTest`管道的**编辑**按钮，然后转到文件末尾并写入以下内容：

```cs
- task: PublishBuildArtifacts@1 
```

1.  当新任务上方出现**设置**链接时，点击它来配置新任务：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_04.png)

图 20.4：配置发布构建构件窗格

1.  接受默认的**发布路径**，因为它已与将部署应用程序的任务的路径同步，插入构件名称，然后选择**Azure 管道**作为位置。保存后，管道将启动，并且新添加的任务应该成功。

1.  部署和其他发布构件被添加到称为**发布管道**的不同管道中，以将它们与构建相关的构件解耦。使用**发布管道**，您无法编辑`.yaml`文件，但您将使用图形界面进行操作。

1.  单击**发布**左侧菜单选项卡以创建新的**发布管道**。一旦单击**添加新管道**，您将被提示添加第一个阶段的第一个任务。事实上，整个发布管道由不同的阶段组成，每个阶段都包含一系列任务。虽然每个阶段只是一系列任务，但阶段图可以分支，我们可以在每个阶段后添加几个分支。这样，我们可以部署到每个需要不同任务的不同平台。在我们的简单示例中，我们将使用单个阶段。

1.  选择**部署 Azure 应用服务**任务。一旦添加此任务，您将被提示填写缺少的信息。

1.  单击**错误链接**并填写缺少的参数：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_05.png)

图 20.5：配置发布阶段

1.  选择您的订阅，然后，如果出现授权按钮，请单击它以**授权**Azure 管道访问您的订阅。然后，选择 Windows 作为部署平台，最后，从**应用服务名称**下拉列表中选择您创建的应用服务。任务设置在编写时会自动保存，因此您只需为整个管道单击**保存**按钮。

1.  现在，我们需要将此管道连接到源构件。单击**添加构件**按钮，然后选择**构建**作为源类型，因为我们需要将新的发布管道与我们的构建管道创建的 ZIP 文件连接起来。将出现设置窗口：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_06.png)

图 20.6：定义要发布的构件

1.  从下拉列表中选择我们之前的构建管道，并将**最新**保留为版本。接受**源别名**中的建议名称。

1.  我们的发布管道已经准备就绪，可以直接使用。您刚刚添加的源构件的图像在其右上角包含一个触发图标，如下所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_07.png)

图 20.7：准备发布的构件

1.  如果单击触发图标，您将有选项在新构建可用时自动触发发布管道：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_08.png)

图 20.8：启用持续部署触发器

1.  保持其禁用；我们可以在完成并手动测试发布管道后启用它。

正如我们之前提到的，为了准备自动触发，我们需要在应用程序部署之前添加一个人工批准任务。

### 为发布添加手动批准

由于任务通常由软件代理执行，我们需要在手动作业中嵌入人工批准。让我们按照以下步骤添加它：

1.  单击**阶段 1**标题右侧的三个点：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_09.png)

图 20.9：向阶段添加人工批准

1.  然后，选择**添加无代理作业**。添加无代理作业后，单击**添加**按钮并添加**手动干预**任务。以下屏幕截图显示了**手动干预**设置：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_10.png)

图 20.10：配置阶段的人工批准

1.  为操作员添加说明，并在**通知用户**字段中选择您的帐户。

1.  现在，使用鼠标拖动整个**无代理作业**并将其放置在应用程序部署任务之前。它应该看起来像这样：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_11.png)

图 20.11：设置人工批准部署任务列表

1.  完成！点击左上角的**保存**按钮保存管道。

现在，一切都准备好了，可以创建我们的第一个自动发布。

### 创建发布

一旦你准备好了一切，新的发布可以按照以下步骤准备和部署：

1.  点击**创建发布**按钮开始创建新的发布，如下截图所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_12.png)

图 20.12：创建新发布

1.  验证**源别名**是否是最后一个可用的，添加**发布描述**，然后点击**创建**。不久后，你应该会收到一封发布批准的电子邮件。点击其中包含的链接，进入批准页面：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_13.png)

图 20.13：批准发布

1.  点击**批准**按钮批准发布。等待**部署**完成。你应该看到所有任务都成功完成，如下截图所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_14.png)

图 20.14：发布部署

1.  你已经运行了你的第一个成功的发布管道！

在现实项目中，发布管道将包含一些额外的任务。事实上，应用程序（在实际生产环境中部署之前）会在一个分级环境中进行部署，在那里进行测试。因此，可能在这次首次部署之后，会有一些手动测试，手动授权进行生产部署，以及最终的生产部署。

## 多阶段环境

与**持续交付**（**CD**）相关的方法需要保证每次新部署都能保持生产环境的安全。为此，需要采用多阶段管道。下面的截图显示了一种常见阶段的方法，使用书籍用例作为演示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_15.png)

图 20.15：使用 Azure DevOps 发布阶段

正如你所看到的，这些阶段是使用 Azure DevOps 发布管道进行配置的。每个阶段都有其自己的目的，这将提高最终交付产品的质量。让我们来看看这些阶段：

+   **开发/测试：**这个阶段是开发人员和测试人员用来构建新功能的。这个环境肯定是最容易暴露出错误和不完整功能的环境。

+   **质量保证：**这个环境为团队中与开发和测试无关的领域提供了新功能的简要版本。项目经理、市场营销、供应商等可以将其用作研究、验证甚至预生产的区域。此外，开发和质量团队可以保证新版本的正确部署，考虑到功能和基础设施。

+   **生产：**这是客户运行其解决方案的阶段。根据 CD 的要求，一个良好的生产环境的目标是尽快更新。更新的频率会根据团队规模而有所不同，但有一些方法是这个过程每天发生多次。

采用这三个部署应用程序的阶段将影响解决方案的质量。它还将使团队能够拥有更安全的部署过程，减少风险，提高产品的稳定性。这种方法乍看起来可能有点昂贵，但如果没有它，糟糕的部署结果通常会比这个投资更昂贵。

除了所有的安全性，你还必须考虑多阶段的情况。你可以设置管道，只有在定义的授权下，你才能从一个阶段移动到另一个阶段：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_16.png)

图 20.16：定义预部署条件

正如你在前面的截图中所看到的，设置预部署条件非常简单，而且你可以在下面的截图中看到，有多个选项来自定义授权方法。这使你有可能完善 CD 方法，确切地满足你所处理的项目的需求。

以下屏幕截图显示了 Azure DevOps 提供的预部署批准选项。您可以定义可以批准阶段并为其设置策略的人员，即在完成流程之前重新验证批准者身份。作为软件架构师，您需要确定适合使用此方法创建的项目的配置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_17.png)

图 20.17：预部署批准选项

值得一提的是，尽管这种方法远比单阶段部署好得多，但 DevOps 管道将引导您作为软件架构师进入另一个监控阶段。持续反馈将是一个令人难以置信的工具，我们将在下一节讨论这种方法。

# 定义持续反馈和相关的 DevOps 工具

一旦您在上一节描述的部署方案中完美运行的解决方案，反馈将对您的团队至关重要，以了解发布的结果以及版本对客户的运行情况。为了获得这种反馈，一些工具可以帮助开发人员和客户，将这些人聚集在一起，加快反馈过程。让我们来看看这些工具。

## 使用 Azure Monitor Application Insights 监控软件

**Azure Monitor Application Insights**是软件架构师需要持续反馈的工具。值得一提的是，应用程序洞察是 Azure Monitor 的一部分，它还包括警报、仪表板和工作簿等更广泛的监控功能。一旦您将应用程序连接到它，您就会开始收到有关对软件的每个请求的反馈。这使您不仅能够监视所做的请求，还能够监视数据库性能、应用程序可能遭受的错误以及处理时间最长的调用。

显然，将此工具插入到您的环境中将会产生成本，但工具提供的便利将是值得的。值得注意的是，对于简单的应用程序，甚至可能是免费的，因为您支付的是数据摄入费用，而有免费配额。此外，您需要了解，由于存储数据在**应用程序洞察**中的所有请求都在单独的线程中运行，因此性能成本非常小。

值得注意的是，一些服务，如应用服务、函数等，在初始创建过程中将有添加应用程序洞察的选项，因此您可能已经在阅读本书时创建了它。即便如此，下面的屏幕截图显示了您如何在您的环境中轻松创建一个工具。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_18.png)

图 20.18：在 Azure 中创建应用程序洞察资源

如果您想使用 Visual Studio 在应用程序中设置应用程序洞察，您可能会发现这篇微软教程有用：[`docs.microsoft.com/en-us/azure/azure-monitor/learn/dotnetcore-quick-start#configure-app-insights-sdk`](https://docs.microsoft.com/en-us/azure/azure-monitor/learn/dotnetcore-quick-start#configure-app-insi)。

例如，假设您需要分析应用程序中花费更多时间的请求。将应用程序洞察附加到您的 Web 应用程序的过程非常简单：只需在设置 Web 应用程序时立即完成。如果您不确定应用程序洞察是否已为您的 Web 应用程序配置，可以使用 Azure 门户进行查找。导航到**应用服务**并查看**应用程序洞察**设置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_19.png)

图 20.19：在应用服务中启用应用程序洞察

界面将让您有机会为您的 Web 应用程序创建或附加一个已创建的监视服务。值得一提的是，您可以将多个 Web 应用程序连接到同一个 Application Insights 组件。以下截图显示了如何将 Web 应用程序添加到已创建的 Application Insights 资源中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_20.png)

图 20.20：在应用服务中启用应用洞察

一旦您为您的 Web 应用程序配置了 Application Insights，您将在应用服务中找到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_21.png)

图 20.21：应用服务中的应用洞察

一旦它连接到您的解决方案，数据收集将持续进行，您将在组件提供的仪表板中看到结果。您可以在两个地方找到这个屏幕：

+   与您配置 Application Insights 的地方相同，在 Web 应用程序门户内

+   在 Azure 门户中，浏览 Application Insights 资源后：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_22.png)

图 20.22：应用洞察的实际应用

这个仪表板让您了解失败的请求、服务器响应时间和服务器请求。您还可以打开可用性检查，它将从 Azure 数据中心中的任何一个向您选择的 URL 发出请求。

但 Application Insights 的美妙之处在于它对系统进行了深入的分析。例如，在下面的截图中，它正在向您反馈网站上的请求次数。您可以通过排名来分析哪些请求处理时间更长，或者哪些请求更频繁：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_23.png)

图 20.23：使用 Application Insights 分析应用程序性能

考虑到这个视图可以以不同的方式进行过滤，并且您在 Web 应用程序中发生事件后立即收到信息，这无疑是一个定义持续反馈的工具。这是您可以使用 DevOps 原则实现客户需求的最佳方式之一。

Application Insights 是一个技术工具，正是您作为软件架构师需要的，用于监视现代应用程序的真实分析模型。它是基于用户在您正在开发的系统上的行为的持续反馈方法。

## 使用测试和反馈工具启用反馈

在持续反馈过程中另一个有用的工具是由微软设计的测试和反馈工具，旨在帮助产品所有者和质量保证用户分析新功能。

使用 Azure DevOps，您可以通过在每个工作项内选择一个选项来为您的团队请求反馈，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_24.png)

图 20.24：使用 Azure DevOps 请求反馈

一旦您收到反馈请求，您可以使用测试和反馈工具来分析并向团队提供正确的反馈。您将能够将该工具连接到您的 Azure DevOps 项目，从而在分析反馈请求时获得更多功能。值得一提的是，这个工具是一个需要安装的网页浏览器扩展。以下截图显示了如何为测试和反馈工具设置 Azure DevOps 项目 URL：

您可以从[`marketplace.visualstudio.com/items?itemName=ms.vss-exploratorytesting-web`](https://marketplace.visualstudio.com/items?itemName=ms.vss-exploratorytesting-web)下载此工具。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_25.png)

图 20.25：将测试和反馈连接到 Azure DevOps 组织

这个工具非常简单。您可以截图、记录一个过程，甚至做一个笔记。以下截图显示了您如何在截图中轻松写下一条消息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_26.png)

图 20.26：使用测试和反馈工具提供反馈

好处是您可以在会话时间轴中记录所有这些分析。正如您在下一个截图中所看到的，您可以在同一个会话中获得更多反馈，这对分析过程很有帮助：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_27.png)

图 20.27：使用测试和反馈工具提供反馈

一旦您完成了分析并连接到 Azure DevOps，您将能够报告错误，创建任务，甚至开始一个新的测试用例：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_28.png)

图 20.28：在 Azure DevOps 中打开错误

创建的错误结果可以在 Azure DevOps 的**工作项**面板上进行检查。值得一提的是，您不需要 Azure DevOps 开发人员许可证即可访问环境中的这一区域。这使您作为软件架构师能够将这个基本而有用的工具传播给您所拥有的解决方案的许多关键用户。以下截图显示了一旦您将其连接到 Azure DevOps 项目后工具创建的错误：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_20_29.png)

图 20.29：Azure DevOps 中新报告的错误

拥有这样的工具对于获得项目的良好反馈是很重要的。但是，作为软件架构师，您可能需要找到加速这个过程的最佳解决方案。本书中探讨的工具是加速这一过程的好方法。每当您需要在开发过程中实施一个新步骤时，您都可以考虑这种方法。持续反馈是开发软件过程中的一个重要步骤，它将不断获得新功能。另一个可以利用 DevOps 的非常重要的方法是 SaaS。让我们在下一节中了解更多。

# 了解 SaaS

作为服务销售/使用软件涉及到一组更广泛的解决方案设计原则，称为**服务设计思维**。服务设计思维不仅仅是一种软件开发技术和/或软件部署方法，而且它影响到几个业务领域，即组织和人力资源、软件开发流程，最后是硬件基础设施和软件架构。

在接下来的小节中，我们将简要讨论我们列出的每个业务领域的影响，而在最后一个小节中，我们将专门关注 SaaS 部署模型。

## 使您的组织适应服务场景

第一个组织影响来自于需要优化软件对目标组织的价值。这需要一个人力资源或团队负责规划和监控软件对目标组织的影响，以最大化软件增加的价值。这种战略角色不仅在初始设计阶段需要，而且在应用的整个生命周期中都需要。事实上，这个角色负责保持软件与目标组织不断变化的需求保持一致。

另一个重要的影响领域是人力资源管理。事实上，由于主要优先考虑的是软件增加的价值（而不是利用现有资源和能力），人力资源必须根据项目需求进行调整。这意味着在需要时立即获取新人员，并通过适当的培训开发所需的能力。

下一小节涉及软件开发中涉及的所有流程的影响。

## 在服务场景中开发软件

影响软件开发流程的主要约束是需要将软件调整到组织的需求。这种需求可以通过基于 CI/CD 方法的任何敏捷方法来满足。有关 CI/CD 的简要介绍，请参阅《第三章》《使用 Azure DevOps 组织您的工作》部分，《使用 Azure DevOps 记录需求》。值得指出的是，任何设计良好的 CI/CD 周期都应包括处理用户反馈和用户满意度报告。

此外，为了优化软件增加的价值，最佳实践是组织阶段，其中开发团队（或其中的一部分）与系统用户密切联系，以便开发人员更好地理解软件对目标组织的影响。

在编写功能和非功能需求时，始终要记住软件的附加值。因此，有必要使用“用户故事”注释“为什么”和“如何”它们对价值的贡献。需求收集过程在“第二章”，“非功能需求”中讨论。

更多技术含义将在下一小节中讨论。

## 服务场景的技术含义

在服务场景中，硬件基础设施和软件架构都受到三个主要原则的约束，这是将软件调整到组织需求的要求的直接结果，即以下内容：

+   需要监视软件以发现可能由系统故障或软件使用/用户需求变化引起的任何问题。这意味着从所有硬件/软件组件中提取健康检查和负载统计。用户执行的操作统计数据也可以提供有关组织需求变化的良好线索，具体来说，是用户和应用程序在每个操作实例上花费的平均时间，以及每个操作实例在单位时间（天、周或月）内执行的次数。

+   还需要监控用户满意度。可以通过在每个应用程序屏幕上添加链接到易于填写的用户满意度报告页面来获得有关用户满意度的反馈。

+   最后，有必要快速调整硬件和软件，以适应每个应用模块接收的流量以及组织需求的变化。这意味着以下内容：

+   极度关注软件的模块化

+   保持数据库引擎变更的可能性，并更喜欢面向服务的架构（SOA）或基于微服务的解决方案，而不是单片软件

+   为新技术敞开大门

使硬件易于调整意味着允许硬件扩展，这又意味着要么采用云基础设施，要么采用硬件集群，或者两者兼而有之。同样重要的是要保持对云服务供应商变化的可能性，这意味着将对云平台的依赖封装在少量软件模块中。

通过选择最佳技术来实现每个模块，可以实现软件附加值的最大化，这意味着能够混合不同的技术。这就是容器化技术（如 Docker）发挥作用的地方。 Docker 和相关技术在以下进行了描述：

+   第五章，将微服务架构应用于企业应用程序

+   第六章，Azure 服务布局

+   第七章，Azure Kubernetes 服务

总之，我们列出的所有要求都趋向于本书中描述的大多数先进技术，如云服务、可扩展的 Web 应用程序、分布式/可扩展数据库、Docker、Kubernetes、SOA 和微服务架构。

如何为服务环境准备软件的更多细节将在下一节中给出，而下一小节专门关注 SaaS 应用程序的优缺点。

## 决定何时采用 SaaS 解决方案

SaaS 解决方案的主要吸引力在于其灵活的付款模式，它提供以下优势：

+   您可以避免放弃大笔投资，转而选择更实惠的月度付款

+   您可以从一个便宜的系统开始，然后只有在业务增长时才转向更昂贵的解决方案

然而，SaaS 解决方案还提供其他优势，即以下内容：

+   在所有云解决方案中，您可以轻松扩展您的解决方案

+   应用程序会自动更新

+   由于 SaaS 解决方案是通过公共互联网提供的，因此可以从任何位置访问它们

不幸的是，SaaS 的优势是有代价的，因为 SaaS 也有一些不可忽视的缺点，即以下内容：

+   您的业务严重依赖于 SaaS 提供商，他们可能会停止提供服务和/或以您不接受的方式进行修改。

+   通常，您无法实现任何定制，只能使用 SaaS 供应商提供的少数标准选项。然而，有时 SaaS 供应商也提供添加自定义模块的可能性，这些模块可以由他们或您编写。

总之，SaaS 解决方案提供了有趣的优势，但也存在一些缺点，因此作为软件架构师，您必须进行详细分析以决定如何采用它们。

接下来的部分将解释如何调整软件以在服务场景中使用。

## 为服务场景准备解决方案

首先，*为服务场景准备解决方案*意味着专门为云和/或分布式环境设计。这意味着要考虑可伸缩性、容错性和自动故障恢复。

前面三点的主要影响与*状态*的处理方式有关。无状态的模块实例易于扩展和替换，因此您应该仔细规划哪些模块是无状态的，哪些模块有状态。此外，正如*第九章*中所解释的，您必须记住写入和读取操作的扩展方式完全不同。读取操作更容易通过复制进行扩展，而写入操作在关系数据库中扩展不佳，通常需要 NoSQL 解决方案。

在分布式环境中，高可伸缩性阻止了使用分布式事务和一般同步操作。因此，只能通过基于异步消息的更复杂技术来实现数据一致性和容错性，例如以下内容：

+   一种技术是将要发送的所有消息存储在队列中，以便在出现错误或超时时可以重试异步传输。消息可以在收到接收确认时或模块决定中止产生消息的操作时从队列中移除。

+   另一个问题是处理同一消息由于超时导致多次接收的可能性。

+   如果需要，可以使用乐观并发和事件溯源等技术来最小化数据库中的并发问题。乐观并发在*第十五章*的用例的*定义数据层*子部分中有解释，而事件溯源则与其他数据层内容一起在*第十二章*的*使用 SOLID 原则来映射您的领域*部分中描述。

前面列表中的前两点与其他分布式处理技术一起在*第五章*的*如何处理.NET Core 微服务*部分中详细讨论。

容错性和自动故障恢复要求软件模块实现健康检查接口，云框架可能会调用这些接口，以验证模块是否正常工作，或者是否需要被终止并由另一个实例替换。ASP.NET Core 和所有 Azure 微服务解决方案都提供基本的即插即用健康检查，因此开发人员不需要关心它们。然而，可以通过实现一个简单的接口来添加更详细的自定义健康检查。

如果您的目标是可能更改某些应用程序模块的云提供商，则难度会增加。在这种情况下，对云平台的依赖必须封装在只有少数模块中，并且过于严格依赖特定云平台的解决方案必须被丢弃。

如果您的应用程序是为服务场景设计的，则一切都必须自动化：新版本的测试和验证，应用程序所需的整个云基础设施的创建以及应用程序在该基础设施上的部署。

所有云平台都提供语言和设施来自动化整个软件 CI/CD 周期，即构建代码，测试代码，触发手动版本批准，硬件基础设施创建和应用程序部署。

Azure Pipelines 允许完全自动化列出的所有步骤。*第十八章*中的用例*使用单元测试用例和 TDD 测试代码*展示了如何使用 Azure Pipelines 自动化所有步骤，包括软件测试。下一节中的用例将展示如何在 Azure Web Apps 平台上自动化应用程序部署。

在 SaaS 应用程序中，自动化扮演着更为基础的角色，因为必须通过客户订阅自动触发为每个新客户创建新租户的整个过程。更具体地说，多租户 SaaS 应用程序可以通过三种基本技术实现：

+   所有客户共享相同的硬件基础设施和数据存储。这种解决方案最容易实现，因为它需要实现标准的 Web 应用程序。然而，这只适用于非常简单的 SaaS 服务，因为对于更复杂的应用程序来说，确保存储空间和计算时间在用户之间均匀分配变得越来越困难。此外，随着数据库变得越来越复杂，保持不同用户的数据安全隔离也变得越来越困难。

+   所有客户共享相同的基础设施，但每个客户都有自己的数据存储。此选项解决了上一个解决方案的所有数据库问题，并且很容易自动化，因为创建新租户只需要创建新数据库。此解决方案提供了一种简单的方式来定义定价策略，将其与存储消耗联系起来。

+   每个客户都有自己的私人基础设施和数据存储。这是最灵活的策略。从用户的角度来看，它唯一的缺点是更高的价格。因此，只有在每个用户所需的计算能力达到最低阈值以上时才方便。它更难自动化，因为必须为每个新客户创建整个基础设施，并在其上部署应用程序的新实例。

无论选择哪种策略，您都需要能够随着消费者增加而扩展您的云资源。

如果您还需要确保您的基础设施创建脚本可以跨多个云提供商使用，那么一方面，您不能使用太特定于单个云平台的功能，另一方面，您需要一种独特的基础设施创建语言，可以转换为更常见的云平台的本地语言。 Terraform 和 Ansible 是描述硬件基础设施的两种非常常见的选择。

# WWTravelClub 项目方法

在本章中，WWTravelClub 项目的屏幕截图显示了实施良好的 DevOps 周期所需的步骤。WWTravelClub 团队决定使用 Azure DevOps，因为他们了解到该工具对于获得整个周期的最佳 DevOps 体验至关重要。

需求是使用用户故事编写的，可以在 Azure DevOps 的**工作项**部分找到。代码放在 Azure DevOps 项目的存储库中。这两个概念在*第三章*中*使用 Azure DevOps 记录需求*中有解释。

用于完成任务的管理生命周期是 Scrum，在*第一章*《理解软件架构的重要性》中介绍。这种方法将实施分为 Sprints，这迫使需要在每个周期结束时交付价值。使用本章学到的持续集成设施，每当团队完成对存储库主分支的开发时，代码都将被编译。

一旦代码被编译和测试，部署的第一阶段就完成了。第一阶段通常被称为开发/测试，因为您可以为内部测试启用它。Application Insights 和测试与反馈可以用于获取新版本的第一反馈。

如果新版本的测试和反馈通过，那么就是时候进入第二阶段，质量保证。Application Insights 和测试与反馈现在可以再次使用，但现在是在一个更稳定的环境中。

循环以在生产阶段部署的授权结束。这无疑是一个艰难的决定，但 DevOps 表明您必须持续这样做，以便从客户那里获得更好的反馈。Application Insights 仍然是一个有用的工具，因为您可以监视新版本在生产中的演变，甚至将其与过去的版本进行比较。

这里描述的 WWTravelClub 项目方法可以用于许多其他现代应用程序开发生命周期。作为软件架构师，您必须监督这个过程。工具已经准备就绪，取决于您是否做对了！

# 总结

在本章中，我们了解到 DevOps 不仅是一堆技术和工具，用于连续交付软件，而且是一种哲学，可以实现对您正在开发的项目的最终用户持续交付价值。

考虑到这种方法，我们看到持续集成、持续交付和持续反馈对 DevOps 的目的至关重要。我们还看到 Azure、Azure DevOps 和 Microsoft 工具如何帮助您实现目标。

我们描述了*服务设计思维*原则和 SaaS 软件部署模型。现在，您应该能够分析这些方法对组织的所有影响，并且您应该能够调整现有的软件开发流程和硬件/软件架构，以利用它们提供的机会。

我们还解释了软件周期、云硬件基础架构配置和应用程序部署的自动化的需求和涉及的技术。

一旦您实施了所示的示例，您应该能够使用 Azure Pipelines 自动化基础架构配置和应用程序部署。本章以 WWTravelClub 为例阐明了这种方法，实现了 Azure DevOps 内的 CI/CD，并使用 Application Insights 和测试与反馈工具进行技术和功能反馈。在现实生活中，这些工具将使您能够更快地了解您正在开发的系统的当前行为，因为您将对其进行持续反馈。

在下一章中，我们将详细了解持续集成，这在服务场景和 SaaS 应用程序的维护中起着基础性的作用。

# 问题

1.  什么是 DevOps？

1.  什么是持续集成？

1.  什么是持续交付？

1.  什么是持续反馈？

1.  构建和发布管道之间有什么区别？

1.  在 DevOps 方法中，Application Insights 的主要目的是什么？

1.  测试与反馈工具如何帮助 DevOps 的过程？

1.  服务设计思维的主要目标是什么？

1.  服务设计思维是否要求充分利用公司已有的所有能力？

1.  为什么完全自动化对 SaaS 应用程序的生命周期至关重要？

1.  是否可以使用平台无关的语言定义硬件云基础架构？

1.  什么是首选的 Azure 工具，用于整个应用程序生命周期的自动化？

1.  如果两个 SaaS 供应商提供相同的软件产品，您应该使用最可靠的还是最便宜的？

1.  在服务场景中，可伸缩性是唯一重要的要求吗？

# 进一步阅读

这些是一些网站，您可以在本章涵盖的主题中找到更多信息：

+   [`donovanbrown.com/`](http://donovanbrown.com/)

+   [`azure.microsoft.com/en-us/overview/what-is-devops/`](https://azure.microsoft.com/en-us/overview/what-is-devops/)

+   [`www.packtpub.com/networking-and-servers/devops-fundamentals-video`](https://www.packtpub.com/networking-and-servers/devops-fundamentals-video)

+   [`docs.microsoft.com/en-us/azure/devops/learn/what-is-devops`](https://docs.microsoft.com/en-us/azure/devops/learn/what-is-devops)

+   [`azuredevopslabs.com/labs/devopsserver/exploratorytesting/`](https://azuredevopslabs.com/labs/devopsserver/exploratorytesting/)

+   [`docs.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview`](https://docs.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview)

+   [`marketplace.visualstudio.com/items?itemName=ms.vss-exploratorytesting-web`](https://marketplace.visualstudio.com/items?itemName=ms.vss-exploratorytesting-web)

+   [`docs.microsoft.com/en-us/azure/devops/test/request-stakeholder-feedback`](https://docs.microsoft.com/en-us/azure/devops/test/request-stakeholder-feedback)

+   [`docs.microsoft.com/en-us/azure/devops/pipelines/?view=azure-devops`](https://docs.microsoft.com/en-us/azure/devops/pipelines/?view=azure-devops)

+   [`www.terraform.io/`](https://www.terraform.io/)

+   [`www.ansible.com/`](https://www.ansible.com/)


# 第二十一章：应用 CI 场景的挑战

**持续集成**（**CI**）有时被视为 DevOps 的先决条件。在上一章中，我们讨论了 CI 的基础知识以及 DevOps 对其的依赖。它的实施也在*第二十章*“理解 DevOps 原则”中进行了介绍。但与其他实践章节不同，本章的目的是讨论如何在实际场景中启用 CI，考虑到您作为软件架构师需要处理的挑战。

本章涵盖的主题如下：

+   理解 CI

+   持续集成和 GitHub

+   了解在使用 CI 时面临的风险和挑战

+   理解 WWTravelClub 项目在本章的方法

与上一章类似，在解释本章内容时，将介绍 WWTravelClub 的示例，因为用于说明 CI 的所有屏幕截图都来自它。除此之外，我们将在本章末尾提供结论，以便您能够轻松理解 CI 的原则。

到本章结束时，您将能够决定是否在项目环境中使用 CI。此外，您将能够定义成功使用此方法所需的工具。

# 技术要求

本章需要 Visual Studio 2019 社区版或更高版本。您可能还需要一个 Azure DevOps 帐户，如*第三章*“使用 Azure DevOps 记录需求”中所述。您可以在以下网址找到本章的示例代码：[`github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5`](https://github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5)。

# 理解 CI

一旦您开始使用 Azure DevOps 这样的平台，启用 CI 肯定会很容易，当然，只需点击相应的选项即可，就像我们在*第二十章*“理解 DevOps 原则”中所看到的那样。因此，技术并不是实施这一流程的阿喀琉斯之踵。

以下截图显示了使用 Azure DevOps 启用 CI 有多么容易。通过点击构建管道并对其进行编辑，您将能够设置触发器，以便在一些点击后启用 CI：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_21_01.png)

图 21.1：启用持续集成触发器

事实是，CI 将帮助您解决一些问题。例如，它将迫使您测试您的代码，因为您需要更快地提交更改，这样其他开发人员就可以使用您正在编程的代码。

另一方面，您不能只是在 Azure DevOps 中启用 CI 构建。当然，一旦您提交了更改并完成了代码，您就可以启动构建的可能性，但这远非意味着您的解决方案中有可用的 CI。

作为软件架构师，您需要更多地关注这一点的原因与对 DevOps 的真正理解有关。正如在*第二十章*“理解 DevOps 原则”中所讨论的，向最终用户提供价值的需求将始终是决定和制定开发生命周期的良好方式。因此，即使启用 CI 很容易，但启用此功能对最终用户的真正业务影响是什么？一旦您对这个问题有了所有的答案，并且知道如何减少其实施的风险，那么您就能够说您已经实施了 CI 流程。

值得一提的是，CI 是一个原则，可以使 DevOps 工作更加高效和快速，正如在*第二十章* *理解 DevOps 原则*中所讨论的那样。然而，一旦你不确定你的流程是否足够成熟，可以启用持续交付代码，DevOps 肯定可以在没有它的情况下运行。更重要的是，如果你在一个还不够成熟以处理其复杂性的团队中启用 CI，你可能会导致对 DevOps 的误解，因为在部署解决方案时，你可能会开始遇到一些风险。关键是，CI 不是 DevOps 的先决条件。一旦启用了 CI，你可以在 DevOps 中加快速度。然而，你可以在没有它的情况下实践 DevOps。

这就是为什么我们要专门为 CI 增加一个额外的章节。作为软件架构师，你需要了解开启 CI 的关键点。但在我们检查这个之前，让我们学习另一个工具，可以帮助我们进行持续集成 - GitHub。

# 持续集成和 GitHub

自从 GitHub 被微软收购以来，许多功能已经发展，并且提供了新的选项，增强了这个强大工具的功能。可以使用 Azure 门户网站，特别是使用 GitHub Actions 来检查这个集成。

GitHub Actions 是一组工具，用于自动化软件开发。它可以在任何平台上快速启用 CI/持续部署（CD）服务，使用 YAML 文件定义工作流程。你可以将 GitHub Actions 视为 Azure DevOps Pipelines 的替代方案。然而，值得一提的是，你可以使用 GitHub Actions 自动化任何 GitHub 事件，在 GitHub Marketplace 上有数千种可用的操作：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_21_02.png)

图 21.2：GitHub Actions

通过 GitHub Actions 界面创建构建.NET Core Web 应用程序的工作流程非常简单。正如你在前面的截图中所看到的，已经创建了一些工作流程来帮助我们。我们下面的 YAML 是通过在**.NET Core**下点击**设置此工作流程**选项生成的：

```cs
name: .NET Core
on:
  push:
    branches: [ master ]
  pull_request:
    branches: [ master ]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup .NET Core
      uses: actions/setup-dotnet@v1
      with:
        dotnet-version: 3.1.301
    - name: Install dependencies
      run: dotnet restore
    - name: Build
      run: dotnet build --configuration Release --no-restore
    - name: Test
      run: dotnet test --no-restore --verbosity normal 
```

通过下面的调整，可以构建本章特定创建的应用程序。

```cs
name: .NET Core Chapter 21
on:
  push:
    branches: [ master ]
  pull_request:
    branches: [ master ]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup .NET Core
      uses: actions/setup-dotnet@v1
      with:
        dotnet-version: 5.0.100-preview.3.20216.6
    - name: Install dependencies
      run: dotnet restore ./ch21 
    - name: Build
      run: dotnet build ./ch21 --configuration Release --no-restore
    - name: Test
      run: dotnet test ./ch21 --no-restore --verbosity normal 
```

如你所见，一旦脚本更新，就可以检查工作流程的结果。如果你愿意，也可以启用持续部署。这只是定义正确脚本的问题：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_21_03.png)

图 21.3：使用 GitHub Actions 进行简单应用程序编译

微软专门提供文档来介绍 Azure 和 GitHub 的集成。在[`docs.microsoft.com/en-us/azure/developer/github`](https://docs.microsoft.com/en-us/azure/developer/github)查看。

作为软件架构师，你需要了解哪种工具最适合你的开发团队。Azure DevOps 为启用持续集成提供了一个很好的环境，GitHub 也是如此。关键在于，无论你决定选择哪个选项，一旦启用 CI，你将面临风险和挑战。让我们在下一个主题中看看它们。

# 了解使用 CI 时的风险和挑战

现在，你可能会考虑风险和挑战，作为避免使用 CI 的一种方式。但是，如果它可以帮助你创建更好的 DevOps 流程，为什么我们要避免使用它呢？这不是本章的目的。本节的目的是帮助你作为软件架构师，减轻风险，并找到通过良好的流程和技术来应对挑战的更好方式。

本节将讨论的风险和挑战列表如下：

+   持续生产部署

+   生产中的不完整功能

+   测试中的不稳定解决方案

一旦你有了处理这些问题的技术和流程，就没有理由不使用 CI。值得一提的是，DevOps 并不依赖于 CI。然而，它确实可以使 DevOps 工作更加顺畅。现在，让我们来看一下它们。

## 禁用持续生产部署

持续生产部署是一个过程，在提交了新的代码片段并经过一些管道步骤后，你将在**生产**环境中拥有这段代码。这并非不可能，但是很难且成本高昂。此外，你需要一个成熟的团队来实现它。问题在于，大多数在互联网上找到的演示和示例都会向你展示一个快速部署代码的捷径。CI/CD 的演示看起来如此简单和容易！这种*简单性*可能会暗示你应该尽快开始实施。然而，如果你再多考虑一下，如果直接部署到生产环境，这种情况可能是危险的！在一个需要 24 小时、7 天全天候可用的解决方案中，这是不切实际的。因此，你需要担心这一点，并考虑不同的解决方案。

第一个是使用多阶段场景，如*第二十章*中所述，*理解 DevOps 原则*。多阶段场景可以为你构建的部署生态系统带来更多的安全性。此外，你将有更多的选择来避免不正确的部署到生产环境，比如预部署批准：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_21_04.png)

图 21.4：生产环境安全的多阶段场景

值得一提的是，你可以构建一个部署管道，通过这个工具更新所有的代码和软件结构。然而，如果你有一些超出这种情况的东西，比如数据库脚本和环境配置，一个不正确的发布可能会对最终用户造成损害。此外，生产环境何时更新的决定需要计划，并且在许多情况下，所有平台用户需要被通知即将发生的变化。在这些难以决定的情况下使用*变更管理*程序。

因此，将代码交付到生产环境的挑战将让你考虑一个时间表。无论你的周期是每月、每天，甚至每次提交。关键点在于你需要创建一个流程和管道，确保只有良好和经过批准的软件在生产阶段。然而，值得注意的是，你离开部署的时间越长，以前部署版本和新版本之间的偏差就会越大，一次推出的变化也会越多。你能够更频繁地管理这一点，就越好。

## 不完整的功能

当你的团队的开发人员正在创建一个新的功能或修复一个错误时，你可能会考虑生成一个分支，以避免使用为持续交付设计的分支。分支可以被认为是代码存储库中可用的功能，以启用独立的开发线，因为它隔离了代码。如下截图所示，使用 Visual Studio 创建一个分支非常简单：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_21_05.png)

图 21.5：在 Visual Studio 中创建分支

这似乎是一个不错的方法，但让我们假设开发人员认为实现已经准备好部署，并且刚刚将代码合并到主分支。如果这个功能还没有准备好，只是因为遗漏了一个需求呢？如果错误导致了不正确的行为呢？结果可能是发布一个不完整的功能或不正确的修复。

避免主分支中出现损坏的功能甚至不正确的修复的一个好的做法是使用拉取请求。拉取请求将让其他团队开发人员知道你开发的代码已经准备好合并。以下截图显示了如何使用 Azure DevOps 创建一个你所做更改的**新拉取请求**：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_21_06.png)

图 21.6：创建拉取请求

一旦创建了拉取请求并确定了审阅者，每个审阅者都将能够分析代码，并决定这段代码是否足够健康，可以合并到主分支中。以下截图显示了使用比较工具来分析更改的方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_21_07.png)

图 21.7：分析拉取请求

一旦所有的批准都完成了，你就可以安全地将代码合并到主分支，就像你在下面的截图中所看到的那样。要合并代码，你需要点击“完成合并”。如果 CI 触发器已启用，就像在本章前面所示的那样，Azure DevOps 将启动一个构建流水线：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_21_08.png)

图 21.8：合并拉取请求

毫无疑问，如果没有这样的流程，主分支将遭受大量可能会造成损害的糟糕代码，尤其是在 CD 的情况下。值得一提的是，代码审查在 CI/CD 场景中是一个很好的实践，也被认为是创建高质量软件的绝佳实践。

你需要关注的挑战是确保只有完整的功能才会呈现给最终用户。你可以使用特性标志原则来解决这个问题，这是一种确保只有准备好的功能呈现给最终用户的技术。我们再次强调的不是 CI 作为一种工具，而是作为一种在每次需要为生产交付代码时定义和使用的过程。

值得一提的是，在控制环境中的特性可用性方面，特性标志比使用分支/拉取请求要安全得多。两者都有各自的用处，但拉取请求是关于在 CI 阶段控制代码质量，而特性标志是在 CD 阶段控制特性可用性。

## 一个不稳定的测试解决方案

考虑到你已经减轻了本主题中提出的另外两个风险，你可能会发现在 CI 之后出现糟糕的代码是不太常见的。确实，早前提到的担忧肯定会减轻，因为你正在处理一个多阶段的情景，并且在推送到第一个阶段之前进行了拉取请求。

但是有没有一种方法可以加速发布的评估，确保这个新版本已经准备好供利益相关者测试？是的，有！从技术上讲，你可以在第十八章“使用单元测试用例和 TDD 测试你的代码”和第二十二章“功能测试自动化”中找到这样做的方法。

在这两章讨论中，自动化软件的每一个部分都是不切实际的，考虑到所需的努力。此外，在用户界面或业务规则经常变化的情况下，自动化的维护成本可能更高。虽然这是一个艰难的决定，作为软件架构师，你必须始终鼓励自动化测试的使用。

为了举例说明，让我们看一下下面的截图，它显示了由 Azure DevOps 项目模板创建的 WWTravelClub 的单元测试和功能测试样本：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_21_09.png)

图 21.9：单元测试和功能测试项目

在第十一章“设计模式和.NET 5 实现”中介绍了一些架构模式，比如 SOLID，以及一些质量保证方法，比如同行评审，这些方法会给你比软件测试更好的结果。

然而，这些方法并不否定自动化实践。事实上，所有这些方法都将有助于获得稳定的解决方案，特别是在运行 CI 场景时。在这种环境中，你能做的最好的事情就是尽快检测错误和错误行为。正如前面所示，单元测试和功能测试都将帮助你做到这一点。

单元测试将在构建流水线期间帮助你发现业务逻辑错误。例如，在下面的截图中，你会发现一个模拟错误，导致单元测试未通过而取消了构建：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_21_10.png)

图 21.10：单元测试结果

获得此错误的方法非常简单。您需要编写一些不符合单元测试检查的代码。一旦提交，假设您已经启用了持续部署触发器，代码将在流水线中构建。我们创建的 Azure DevOps 项目向导提供的最后一步之一是执行单元测试。因此，在构建代码之后，将运行单元测试。如果代码不再符合测试，您将收到错误。

同时，以下截图显示了在**开发/测试**阶段功能测试中出现的错误。此时，**开发/测试**环境存在一个错误，被功能测试迅速检测到：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_21_11.png)

图 21.11：功能测试结果

但这不是在 CI/CD 过程中应用功能测试的唯一好处，一旦您用这种方法保护了其他部署阶段。例如，让我们看一下 Azure DevOps 中**Releases**流水线界面的以下截图。如果您查看**Release-9**，您将意识到，由于此错误发生在**开发/测试**环境中发布之后，多阶段环境将保护部署的其他阶段：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_21_12.png)

图 21.12：多阶段环境保护

CI 过程成功的关键是将其视为加速软件交付的有用工具，并且不要忘记团队始终需要为最终用户提供价值。采用这种方法，之前介绍的技术将为您的团队实现其目标提供令人难以置信的方式。

# 理解 WWTravelClub 项目的方法

在这一章中，展示了 WWTravelClub 项目的截图，示范了采用更安全的方法来实现 CI 的步骤。即使将 WWTravelClub 视为假设的情景，建立它时也考虑了一些问题：

+   CI 已启用，但多阶段场景也已启用。

+   即使有多阶段场景，拉取请求也是确保只有高质量代码会出现在第一阶段的一种方式。

+   为了在拉取请求中做好工作，进行了同行评审。

+   同行评审检查，例如在创建新功能时是否存在功能标志。

+   同行评审检查在创建新功能期间开发的单元测试和功能测试。

上述步骤不仅适用于 WWTravelClub。作为软件架构师，您需要定义一种方法来确保安全的 CI 场景。您可以将此作为起点。

# 总结

本章介绍了在软件开发生命周期中启用 CI 的重要性，考虑到您作为软件架构师决定为解决方案使用它时将面临的风险和挑战。

此外，本章介绍了一些可以使这个过程更容易的解决方案和概念，例如多阶段环境、拉取请求审查、功能标志、同行评审和自动化测试。理解这些技术和流程将使您能够在 DevOps 场景中引导项目朝着更安全的行为方向发展。

在下一章中，我们将看到软件测试的自动化是如何工作的。

# 问题

1.  什么是 CI？

1.  没有 CI，你能有 DevOps 吗？

1.  在非成熟团队启用 CI 的风险是什么？

1.  多阶段环境如何帮助 CI？

1.  自动化测试如何帮助 CI？

1.  拉取请求如何帮助 CI？

1.  拉取请求只能与 CI 一起使用吗？

# 进一步阅读

以下是一些网站，您可以在其中找到有关本章涵盖主题的更多信息：

+   有关 CI/CD 的官方微软文档：

+   [`azure.microsoft.com/en-us/solutions/architecture/azure-devops-continuous-integration-and-continuous-deployment-for-azure-web-apps/`](https://azure.microsoft.com/en-us/solutions/architecture/azure-devops-continuous-integration-and-con)

+   [`docs.microsoft.com/en-us/azure/devops-project/azure-devops-project-github`](https://docs.microsoft.com/en-us/azure/devops-project/azure-devops-project-github)

+   [`docs.microsoft.com/en-us/aspnet/core/azure/devops/cicd`](https://docs.microsoft.com/en-us/aspnet/core/azure/devops/cicd)

+   [`docs.microsoft.com/en-us/azure/devops/repos/git/pullrequest`](https://docs.microsoft.com/en-us/azure/devops/repos/git/pullrequest)

+   Azure 和 GitHub 集成：

+   [`docs.microsoft.com/en-us/azure/developer/github`](https://docs.microsoft.com/en-us/azure/developer/github)

+   关于 DevOps 的优秀 Packt 材料：

+   [`www.packtpub.com/virtualization-and-cloud/professional-microsoft-azure-devops-engineering`](https://www.packtpub.com/virtualization-and-cloud/professional-microsoft-azure-devops-engineering)

+   [`www.packtpub.com/virtualization-and-cloud/hands-devops-azure-video`](https://www.packtpub.com/virtualization-and-cloud/hands-devops-azure-video)

+   [`www.packtpub.com/networking-and-servers/implementing-devops-microsoft-azure`](https://www.packtpub.com/networking-and-servers/implementing-devops-microsoft-azure )

+   关于 Azure Pipelines 的一些新信息：

+   [`devblogs.microsoft.com/devops/whats-new-with-azure-pipelines/`](https://devblogs.microsoft.com/devops/whats-new-with-azure-pipelines/)

+   关于功能标志的解释：

+   [`martinfowler.com/bliki/FeatureToggle.html`](https://martinfowler.com/bliki/FeatureToggle.html)


# 第二十二章：功能测试的自动化

在之前的章节中，我们讨论了单元测试和集成测试在软件开发中的重要性，并讨论了它们如何确保代码库的可靠性。我们还讨论了单元测试和集成测试如何成为所有软件生产阶段的组成部分，并且在每次代码库修改时运行。

还有其他重要的测试，称为功能测试。它们仅在每个冲刺结束时运行，以验证冲刺的输出实际上是否满足与利益相关者达成的规格。

本章专门致力于功能测试以及定义、执行和自动化它们的技术。更具体地，本章涵盖以下主题：

+   理解功能测试的目的

+   在 C#中使用单元测试工具自动化功能测试

+   用例-自动化功能测试

在本章结束时，您将能够设计手动和自动测试，以验证冲刺产生的代码是否符合其规格。

# 技术要求

在继续本章之前，建议您阅读*第十八章*，*使用单元测试用例和 TDD 测试您的代码*。

本章需要 Visual Studio 2019 的免费社区版或更高版本，并安装了所有数据库工具。在这里，我们将修改*第十八章*中的代码，*使用单元测试用例和 TDD 测试您的代码*，该代码可在[`github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5`](https://github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5)上找到。

# 理解功能测试的目的

在*第十八章*中，*使用单元测试用例和 TDD 测试您的代码*，我们讨论了自动测试的优势，如何设计它们以及它们的挑战。功能测试使用与单元测试和集成测试相同的技术和工具，但它们与它们不同之处在于它们仅在每个冲刺结束时运行。它们的基本作用是验证当前版本的整个软件是否符合其规格。

由于功能测试还涉及**用户界面**（**UI**），它们需要进一步的工具来模拟用户在 UI 中的操作方式。我们将在整个章节中进一步讨论这一点。需要额外工具的需求并不是 UI 带来的唯一挑战，因为 UI 也经常发生重大变化。因此，我们不应设计依赖于 UI 图形细节的测试，否则我们可能会被迫在每次 UI 更改时完全重写所有测试。这就是为什么有时放弃自动测试并回归手动测试会更好。

无论是自动还是手动，功能测试都必须是一个正式的过程，用于以下目的：

+   功能测试代表了利益相关者和开发团队之间合同的最重要部分，另一部分是验证非功能规格。这份合同的形式化方式取决于开发团队和利益相关者之间关系的性质：

+   在供应商-客户关系的情况下，功能测试成为每个冲刺的供应商-客户业务合同的一部分，由为客户工作的团队编写。如果测试失败，那么冲刺将被拒绝，供应商必须进行补充冲刺以解决所有问题。

+   如果没有供应商-客户业务关系，因为开发团队和利益相关者属于同一家公司，那么就没有业务合同。在这种情况下，利益相关者与团队一起编写一份内部文件，正式规定了冲刺的要求。如果测试失败，通常不会拒绝冲刺，而是使用测试结果来驱动下一个冲刺的规格。当然，如果失败率很高，冲刺可能会被拒绝并且需要重复。

+   在每个冲刺结束时运行的正式功能测试可以防止之前冲刺取得的结果被新代码破坏。

+   在使用敏捷开发方法时，保持更新的功能测试库是获得最终系统规范的正式表示的最佳方式，因为在敏捷开发过程中，最终系统的规范并不是在开发开始之前决定的，而是系统演变的结果。

由于最初阶段的前几个冲刺的输出可能与最终系统有很大不同，因此不值得花费太多时间编写详细的手动测试和/或自动化测试。因此，您可以将用户故事限制为仅有几个示例，这些示例将被用作软件开发的输入和手动测试。

随着系统功能变得更加稳定，值得投入时间编写详细和正式的功能测试。对于每个功能规范，我们必须编写验证其在极端情况下操作的测试。例如，在取款用例中，我们必须编写验证所有可能性的测试：

+   资金不足

+   卡已过期

+   凭证错误

+   重复的错误凭证

以下图片勾勒了整个过程及所有可能的结果：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_22.1.png)

图 22.1：取款示例

对于手动测试，对于前述每个场景，我们必须给出每个操作涉及的所有步骤的详细信息，以及每个步骤的预期结果。

一个重要的决定是是否要自动化所有或部分功能测试，因为编写模拟人操作与系统 UI 交互的自动化测试非常昂贵。最终决定取决于测试实施的成本除以预期使用次数。

在 CI/CD 的情况下，同一个功能测试可以被执行多次，但不幸的是，功能测试严格地与 UI 的实现方式相关联，而在现代系统中，UI 经常发生变化。因此，在这种情况下，测试与完全相同的 UI 执行不超过几次。

为了克服与 UI 相关的所有问题，一些功能测试可以被实施为**皮下测试**，也就是绕过 UI 的测试。例如，ASP.NET Core 应用程序的一些功能测试可以直接调用控制器动作方法，而不是通过浏览器发送实际请求。

不幸的是，皮下测试无法验证所有可能的实现错误，因为它们无法检测 UI 本身的错误。此外，在 Web 应用程序的情况下，皮下测试通常受到其他限制的影响，因为它们绕过了整个 HTTP 协议。

特别是在 ASP.NET Core 应用程序的情况下，如果我们直接调用控制器动作方法，就会绕过整个 ASP.NET Core 管道，该管道在将请求传递给正确的动作方法之前处理每个请求。因此，身份验证、授权、CORS 和 ASP.NET Core 管道中其他中间件的行为将不会被测试分析。

Web 应用程序的完整自动化功能测试应该执行以下操作：

1.  在要测试的 URL 上启动实际浏览器

1.  等待页面上的任何 JavaScript 执行完成

1.  然后，向浏览器发送命令，模拟人操作的行为

1.  最后，在与浏览器的每次交互之后，自动化测试应该等待任何由交互触发的 JavaScript 完成

虽然存在浏览器自动化工具，但是如前所述，使用浏览器自动化实现的测试非常昂贵且难以实现。因此，ASP.NET Core MVC 建议的方法是使用.NET HTTP 客户端向 Web 应用程序的实际副本发送实际的 HTTP 请求，而不是使用浏览器。一旦 HTTP 客户端接收到 HTTP 响应，它会将其解析为 DOM 树，并验证它是否收到了正确的响应。

与浏览器自动化工具的唯一区别是，HTTP 客户端无法运行任何 JavaScript。然而，其他测试可以添加以测试 JavaScript 代码。这些测试基于特定于 JavaScript 的测试工具，如**Jasmine**和**Karma**。

下一节将解释如何使用.NET HTTP 客户端自动化 Web 应用程序的功能测试，而最后一节将展示功能测试自动化的实际示例。

# 使用 C#中的单元测试工具来自动化功能测试

自动化功能测试使用与单元测试和集成测试相同的测试工具。也就是说，这些测试可以嵌入到与我们在*第十八章*中描述的 xUnit、NUnit 或 MSTests 项目中。然而，在这种情况下，我们必须添加进一步的工具，这些工具能够与 UI 进行交互和检查。

在本章的其余部分，我们将专注于 Web 应用程序，因为它们是本书的主要焦点。因此，如果我们正在测试 Web API，我们只需要`HttpClient`实例，因为它们可以轻松地与 XML 和 JSON 格式的 Web API 端点进行交互。

对于返回 HTML 页面的 ASP.NET Core MVC 应用程序，交互更加复杂，因为我们还需要用于解析和与 HTML 页面 DOM 树交互的工具。`AngleSharp` NuGet 包是一个很好的解决方案，因为它支持最先进的 HTML 和最小的 CSS，并且具有用于外部提供的 JavaScript 引擎（如 Node.js）的扩展点。然而，我们不建议在测试中包含 JavaScript 和 CSS，因为它们严格绑定到目标浏览器，所以最好的选择是使用 JavaScript 特定的测试工具，可以直接在目标浏览器中运行它们。

使用`HttpClient`类测试 Web 应用程序有两个基本选项：

+   **分段应用程序**。一个`HttpClient`实例通过互联网/内联网连接到实际的*分段*Web 应用程序，与所有其他正在进行软件测试的人一起。这种方法的优势在于你正在测试*真实内容*，但是测试更难构思，因为你无法控制每个测试之前应用程序的初始状态。

+   **受控应用程序**。一个`HttpClient`实例连接到一个本地应用程序，该应用程序在每次单独的测试之前都被配置、初始化和启动。这种情况与单元测试场景完全类似。测试结果是可重现的，每个测试之前的初始状态是固定的，测试更容易设计，并且实际数据库可以被更快、更容易初始化的内存数据库替换。然而，在这种情况下，你离实际系统的运行很远。

一个好的策略是使用**受控应用程序**，在这里你完全控制初始状态，用于测试所有极端情况，然后使用**分段应用程序**来测试*真实内容*上的随机平均情况。

接下来的两个部分描述了这两种方法。这两种方法的唯一区别在于你如何定义测试的固定装置。

## 测试分段应用程序

在这种情况下，您的测试只需要一个`HttpClient`的实例，因此您必须定义一个有效的夹具，提供`HttpClient`的实例，避免耗尽 Windows 连接的风险。我们在*第十四章*的*.NET Core HTTP 客户端*部分中遇到了这个问题，*应用 Service-Oriented Architectures with .NET Core*。可以通过使用`IHttpClientFactory`管理`HttpClient`实例并通过依赖注入注入它们来解决这个问题。

一旦我们有了一个依赖注入容器，我们就可以使用以下代码片段来丰富它，以有效地处理`HttpClient`实例：

```cs
services.AddHttpClient(); 
```

在这里，`AddHTTPClient`扩展属于`Microsoft.Extensions.DependencyInjection`命名空间，并且在`Microsoft.Extensions.Http` NuGet 包中定义。因此，我们的测试夹具必须创建一个依赖注入容器，调用`AddHttpClient`，最后构建容器。以下的夹具类完成了这个工作（如果您不记得夹具类，请参考*第十八章*的*使用单元测试用例和 TDD 测试准备和拆卸高级场景*部分）：

```cs
public class HttpClientFixture
{
    public HttpClientFixture()
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection
            .AddHttpClient();
         ServiceProvider = serviceCollection.BuildServiceProvider();
    }
    public ServiceProvider ServiceProvider { get; private set; }
} 
```

在上述定义之后，您的测试应该如下所示：

```cs
public class UnitTest1:IClassFixture<HttpClientFixture>
{
    private readonly ServiceProvider _serviceProvider;
    public UnitTest1(HttpClientFixture fixture)
    {
        _serviceProvider = fixture.ServiceProvider;
    }
    [Fact]
    public void Test1()
    {
        var factory = 
            _serviceProvider.GetService<IHttpClientFactory>())

            HttpClient client = factory.CreateClient();
            //use client to interact with application here

    }
} 
```

在`Test1`中，一旦获得了一个 HTTP 客户端，您可以通过发出 HTTP 请求来测试应用程序，然后通过分析应用程序返回的响应来测试应用程序。有关如何处理服务器返回的响应的更多细节将在*用例*部分中给出。

接下来的部分解释了如何测试在受控环境中运行的应用程序。

## 测试受控应用程序

在这种情况下，我们在测试应用程序中创建一个 ASP.NET Core 服务器，并使用`HTTPClient`实例对其进行测试。`Microsoft.AspNetCore.Mvc.Testing` NuGet 包包含了我们创建 HTTP 客户端和运行应用程序的服务器所需的一切。

`Microsoft.AspNetCore.Mvc.Testing`包含一个夹具类，用于启动本地 Web 服务器并提供用于与其交互的客户端。预定义的夹具类是`WebApplicationFactory<T>`。泛型`T`参数必须实例化为您的 Web 项目的`Startup`类。

测试看起来像以下的类：

```cs
public class UnitTest1 
    : IClassFixture<WebApplicationFactory<MyProject.Startup>>
{
    private readonly 
        WebApplicationFactory< MyProject.Startup> _factory;
    public UnitTest1 (WebApplicationFactory<MyProject.Startup> factory)
    {
        _factory = factory;
    }
    [Theory]
    [InlineData("/")]
    [InlineData("/Index")]
    [InlineData("/About")]
    ....
    public async Task MustReturnOK(string url)
    {
        var client = _factory.CreateClient();
        // here both client and server are ready
        var response = await client.GetAsync(url);
        //get the response
        response.EnsureSuccessStatusCode(); 
        // verify we got a success return code.
    }
    ...
    ---
} 
```

如果您想分析返回页面的 HTML，还必须引用`AngleSharp` NuGet 包。我们将在下一节的示例中看到如何使用它。在这种类型的测试中处理数据库的最简单方法是用内存数据库替换它们，这样可以更快地自动清除每当本地服务器关闭和重新启动时。

这可以通过创建一个新的部署环境，比如`AutomaticStaging`，以及一个特定于测试的关联配置文件来完成。创建了这个新的部署环境后，转到应用程序的`Startup`类的`ConfigureServices`方法，并找到您添加`DBContext`配置的地方。一旦找到了那个地方，在那里添加一个`if`，如果应用程序在`AutomaticStaging`环境中运行，则用类似于这样的东西替换您的`DBContext`配置：

```cs
services.AddDbContext<MyDBContext>(options =>  options.UseInMemoryDatabase(databaseName: "MyDatabase")); 
```

作为替代方案，您还可以将清除标准数据库的所有必需指令添加到从`WebApplicationFactory<T>`继承的自定义夹具的构造函数中。请注意，删除所有数据库数据并不像看起来那么容易，因为存在完整性约束。您有各种选择，但没有一种适用于所有情况：

1.  删除整个数据库并使用迁移重新创建它，即`DbContext.Database.Migrate()`。这总是有效的，但速度慢，并且需要具有高权限的数据库用户。

1.  禁用数据库约束，然后以任何顺序清除所有表。这种技术有时不起作用，并且需要具有高权限的数据库用户。

1.  按正确顺序删除所有数据，因此不违反所有数据库约束。如果您保持一个有序的删除列表，其中包含数据库增长时添加到数据库的所有表，这并不难。这个删除列表是一个有用的资源，您也可以用它来修复数据库更新操作中的问题，并在生产数据库维护期间删除旧条目。不幸的是，这种方法在很少出现的循环依赖的情况下也会失败，例如一个具有指向自身的外键的表。

我更喜欢方法 3，并且只在由于循环依赖引起的困难的罕见情况下才返回到方法 2。作为方法 3 的示例，我们可以编写一个从`WebApplicationFactory<Startup>`继承的 fixture，删除*第十八章*中应用程序的所有测试记录，*使用单元测试用例和 TDD 测试您的代码*。

如果您不需要测试身份验证/授权子系统，则删除包、目的地和事件的数据就足够了。删除顺序很简单；首先必须删除事件，因为没有任何依赖于它们，然后我们可以删除依赖于目的地的包，最后删除目的地本身。代码非常简单：

```cs
public class DBWebFixture: WebApplicationFactory<Startup>
{
    public DBWebFixture() : base()
    {
        var context = Services
            .GetService(typeof(MainDBContext))
                as MainDBContext;
        using (var tx = context.Database.BeginTransaction())
        {
            context.Database
                .ExecuteSqlRaw
                    ("DELETE FROM dbo.PackgeEvents");
            context.Database
                .ExecuteSqlRaw
                    ("DELETE FROM dbo.Packges");
            context.Database
                 .ExecuteSqlRaw
                    ("DELETE FROM dbo.Destinations");
            tx.Commit();
        }
    }
} 
```

我们从继承自`WebApplicationFactory<Startup>`的服务中获取`DBContext`实例，因此可以执行数据库操作。从表中同时删除所有数据的唯一方法是通过直接的数据库命令。因此，在这种情况下，我们无法使用`SaveChanges`方法将所有更改封装在单个事务中，我们被迫手动创建事务。

您可以通过将其添加到下一章的用例中来测试上面的类，该用例基于*第十八章*的代码，*使用单元测试用例和 TDD 测试您的代码*。

# 用例 - 自动化功能测试

在本节中，我们将向*第十八章*的 ASP.NET Core 测试项目中添加一个简单的功能测试。我们的测试方法基于`Microsoft.AspNetCore.Mvc.Testing`和`AngleSharp` NuGet 包。请制作整个解决方案的新副本。

测试项目已经引用了`test`下的 ASP.NET Core 项目和所有必需的 xUnit NuGet 包，因此我们只需要添加`Microsoft.AspNetCore.Mvc.Testing`和`AngleSharp` NuGet 包。

现在，让我们添加一个名为`UIExampleTest.cs`的新类文件。我们需要`using`语句来引用所有必要的命名空间。更具体地说，我们需要以下内容：

+   使用 PackagesManagement;：这是引用应用程序类所需的。

+   使用 Microsoft.AspNetCore.Mvc.Testing;：这是引用客户端和服务器类所需的。

+   使用 AngleSharp;和使用 AngleSharp.Html.Parser;：这是引用`AngleSharp`类所需的。

+   System.IO：这是为了从 HTTP 响应中提取 HTML 所需的。

+   使用 Xunit：这是引用所有`xUnit`类所需的。

总结一下，整个`using`块如下：

```cs
using PackagesManagement;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using Microsoft.AspNetCore.Mvc.Testing;
using AngleSharp;
using AngleSharp.Html.Parser;
using System.IO; 
```

我们将使用前面*测试受控应用程序*部分介绍的标准 fixture 类来编写以下测试类：

```cs
public class UIExampleTestcs:
         IClassFixture<WebApplicationFactory<Startup>>
{
    private readonly
       WebApplicationFactory<Startup> _factory;
    public UIExampleTestcs(WebApplicationFactory<Startup> factory)
    {
       _factory = factory;
    }
} 
```

现在，我们准备为主页编写一个测试！这个测试验证主页 URL 返回成功的 HTTP 结果，并且主页包含指向包管理页面的链接，即`/ManagePackages`相对链接。

基本原则是理解自动化测试不应依赖 HTML 的细节，而是必须验证逻辑事实，以避免在每次应用程序 HTML 进行小修改后频繁更改。这就是为什么我们只验证必要的链接是否存在，而不对它们的位置施加约束。

让我们称我们的主页测试为`TestMenu`：

```cs
[Fact]
public async Task TestMenu()
{
    var client = _factory.CreateClient();
    ...
    ...         
} 
```

每个测试的第一步是创建一个客户端。然后，如果测试需要分析一些 HTML，我们必须准备所谓的`AngleSharp`浏览上下文：

```cs
//Create an angleSharp default configuration
var config = Configuration.Default;
//Create a new context for evaluating webpages 
//with the given config
var context = BrowsingContext.New(config); 
```

配置对象指定选项，如 cookie 处理和其他与浏览器相关的属性。此时，我们已经准备好需要主页：

```cs
var response = await client.GetAsync("/"); 
```

作为第一步，我们验证收到的响应是否包含成功的状态代码，如下所示：

```cs
response.EnsureSuccessStatusCode(); 
```

在不成功的状态代码的情况下，前面的方法调用会引发异常，从而导致测试失败。需要从响应中提取 HTML 分析。以下代码显示了一种简单的方法：

```cs
string source = await response.Content.ReadAsStringAsync(); 
```

现在，我们必须将提取的 HTML 传递给我们之前的`AngleSharp`浏览上下文对象，以便它可以构建 DOM 树。以下代码显示了如何做到这一点：

```cs
var document = await context.OpenAsync(req => req.Content(source)); 
```

`OpenAsync`方法使用`context`中包含的设置执行 DOM 构建活动。构建 DOM 文档的输入由作为`OpenAsync`参数传递的 lambda 函数指定。在我们的情况下，`req.Content(...)`从客户端接收的响应中传递给`Content`方法的 HTML 字符串构建了 DOM 树。

一旦获得`document`对象，我们可以像在 JavaScript 中一样使用它。特别是，我们可以使用`QuerySelector`来查找具有所需链接的锚点：

```cs
var node = document.QuerySelector("a[href=\"/ManagePackages\"]"); 
```

现在只剩下验证`node`不为空了：

```cs
Assert.NotNull(node); 
```

我们做到了！如果您想分析需要用户登录或其他更复杂场景的页面，您需要在 HTTP 客户端中启用 cookie 和自动 URL 重定向。这样，客户端将表现得像一个正常的浏览器，存储和发送 cookie，并在收到`Redirect` HTTP 响应时转到另一个 URL。这可以通过将选项对象传递给`CreateClient`方法来实现，如下所示：

```cs
var client = _factory.CreateClient(
    new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect=true,
        HandleCookies=true
    }); 
```

通过前面的设置，您的测试可以执行普通浏览器可以执行的所有操作。例如，您可以设计需要 HTTP 客户端登录并访问需要身份验证的页面的测试，因为`HandleCookies=true`允许客户端存储身份验证 cookie，并在所有后续请求中发送。

# 摘要

本章解释了功能测试的重要性，以及如何定义详细的手动测试，以在每个迭代的输出上运行。此时，您应该能够定义自动测试，以验证在每个迭代结束时，您的应用程序是否符合其规格。

然后，本章分析了何时值得自动化一些或所有功能测试，并描述了如何在 ASP.NET Core 应用程序中自动化它们。

最后一个示例展示了如何使用`AngleSharp`编写 ASP.NET Core 功能测试来检查应用程序返回的响应。

## 结论

在讨论了使用 C# 9 和.NET 5 开发解决方案的最佳实践和方法以及 Azure 中最新的云环境之后，您终于到达了本书的结尾。

正如您在职业生涯中可能已经注意到的那样，按时、按预算开发软件并满足客户需求的功能并不简单。本书的主要目的不仅在于展示软件开发周期基本领域的最佳实践，还演示了如何使用所提到的工具的功能和优势，以帮助您设计可扩展、安全和高性能的企业应用程序，并考虑智能软件设计。这就是为什么本书涵盖了每个广泛领域中的不同方法，从用户需求开始，到生产中的软件，不断部署和监控。

谈到持续交付软件，本书强调了编码、测试和监控解决方案的最佳实践的必要性。这不仅仅是开发一个项目的问题；作为软件架构师，您将对您在软件停用之前所做的决定负责。现在，由您决定最适合您情况的实践和模式。

# 问题

1.  在快速 CI/CD 周期的情况下，自动化 UI 功能测试总是值得的吗？

1.  ASP.NET Core 应用程序的皮下测试的缺点是什么？

1.  编写 ASP.NET Core 功能测试的建议技术是什么？

1.  检查服务器返回的 HTML 的建议方式是什么？

# 进一步阅读

+   `Microsoft.AspNetCore.Mvc.Testing` NuGet 包和`AngleSharp`的更多详细信息可以在它们各自的官方文档中找到，网址分别为[`docs.microsoft.com/en-US/aspnet/core/test/integration-tests`](https://docs.microsoft.com/en-US/aspnet/core/test/integration-tests)和[`anglesharp.github.io/`](https://anglesharp.github.io)。

+   对 JavaScript 测试感兴趣的读者可以参考 Jasmine 文档：[`jasmine.github.io/`](https://jasmine.github.io)。

| **分享您的经验**感谢您抽出时间阅读本书。如果您喜欢这本书，请帮助其他人找到它。在[`www.amazon.com/dp/1800566042`](https://www.amazon.com/dp/1800566042)上留下评论。 |
| --- |


# 第二十三章：答案

# 第一章

1.  软件架构师需要了解任何可以帮助他们更快解决问题并确保他们能够创建更高质量软件的技术。

1.  Azure 提供并不断改进许多组件，软件架构师可以在解决方案中实现这些组件。

1.  最佳的软件开发过程模型取决于您所拥有的项目、团队和预算的类型。作为软件架构师，您需要考虑所有这些变量，并了解不同的过程模型，以便满足环境的需求。

1.  软件架构师要注意任何可能影响性能、安全性、可用性等的用户或系统需求。

1.  所有这些，但非功能性需求需要更多关注。

1.  设计思维和设计冲刺是帮助软件架构师准确定义用户需求的工具。

1.  用户故事在我们想要定义功能需求时很好。它们可以快速编写，并通常不仅提供所需的功能，还提供解决方案的验收标准。

1.  缓存、异步编程和正确的对象分配。

1.  为了检查实现是否正确，软件架构师将其与已经设计和验证的模型和原型进行比较。

# 第二章

1.  纵向和横向。

1.  是的，您可以自动部署到已定义的 Web 应用程序，或者直接使用 Visual Studio 创建一个新的 Web 应用程序。

1.  通过最小化空闲时间来利用可用的硬件资源。

1.  代码行为是确定性的，因此很容易调试。执行流程模仿了顺序代码的流程，这意味着更容易设计和理解。

1.  因为正确的顺序可以最大程度地减少填写表单所需的手势数量。

1.  因为它允许以独立于操作系统的方式操作路径文件。

1.  它可以与多个.NET Core 版本一起使用，也可以与经典.NET 框架的多个版本一起使用。

1.  控制台、.NET Core 和.NET 标准类库；ASP.NET Core、测试和微服务。

# 第三章

1.  不，它适用于多个平台。

1.  自动、手动和负载测试计划。

1.  是的，它们可以 - 通过 Azure DevOps feeds。

1.  管理需求并组织整个开发过程。

1.  史诗工作项代表由多个功能组成的高级系统子部分。

1.  父子关系。

# 第四章

1.  当您从本地解决方案迁移或者拥有基础设施团队时，IaaS 是一个不错的选择。

1.  PaaS 是在团队专注于软件开发的系统中快速安全地交付软件的最佳选择。

1.  如果您打算提供的解决方案是由知名厂商提供的，比如 SaaS，您应该考虑使用它。

1.  在构建新系统时，无服务器绝对是一个选择，如果您没有专门从事基础设施的人员，并且不想担心可伸缩性。

1.  Azure SQL Server 数据库可以在几分钟内启动，之后您将拥有 Microsoft SQL Server 的所有功能。

1.  Azure 提供了一组名为 Azure 认知服务的服务。这些服务提供了视觉、语音、语言、搜索和知识的解决方案。

1.  在混合场景中，您可以灵活决定系统的每个部分的最佳解决方案，同时尊重解决方案未来的发展路径。

# 第五章

1.  代码的模块化和部署的模块化。

1.  不。其他重要优势包括很好地处理开发团队和整个 CI/CD 周期，以及轻松有效地混合异构技术的可能性。

1.  帮助我们实现弹性通信的库。

1.  一旦在开发机器上安装了 Docker，您就可以开发、调试和部署 Docker 化的.NET Core 应用程序。您还可以将 Docker 映像添加到使用 Visual Studio 处理的 Service Fabric 应用程序中。

1.  编排器是管理微服务和微服务集群中的节点的软件。Azure 支持两个相关的编排器：Azure Kubernetes 服务和 Azure Service Fabric。

1.  因为它解耦了通信中发生的参与者。

1.  消息代理。它负责服务与服务之间的通信和事件。

1.  同一条消息可能会被接收多次，因为发送方在超时之前没有收到接收确认，因此发送方会再次发送消息。因此，接收一条消息一次或多次的效果必须相同。

# 第六章

1.  可靠服务是本机的 Azure Service Fabric 服务。但是，Azure Service Fabric 也可以托管其他类型的服务，例如 Docker 化服务。

1.  无状态和有状态。无状态服务用于实现不需要存储任何状态的微服务，而有状态服务用于实现需要存储状态信息的微服务。

1.  这是`HostBuilder`方法，您可以在其中放置您的依赖注入容器。

1.  暴露给集群外部流量并通过集群的 URI 访问的对象。

1.  为了在有状态服务中实现*分片*的写入/修改并行性。

1.  使用只读端点。通过提供`ServiceReplicaListener`的`IEnumerable`可以添加自定义通信协议。

# 第七章

1.  由于服务需要将通信分派到 Pod，因为 Pod 没有稳定的 IP 地址。

1.  服务了解 TCP/IP 等低级协议，但大多数 Web 应用程序依赖于更复杂的 HTTP 协议。这就是为什么 Kubernetes 提供了称为`Ingresses`的更高级实体，这些实体建立在服务之上。

1.  Helm 图表是组织模板和安装包含多个`.yaml`文件的复杂 Kubernetes 应用程序的一种方法。

1.  是的，使用`---`分隔符。

1.  使用`livenessProbe`。

1.  因为 Pod 没有稳定的位置，无法依赖于它们当前运行的节点的存储。

1.  `StatefulSet`通信可以被分片以实现写/更新并行性。

# 第八章

1.  借助依赖于数据库的提供程序。

1.  通过将它们称为`Id`或使用`Key`属性进行装饰。这也可以通过流畅的配置方法完成。

1.  使用`MaxLength`和`MinLength`属性。

1.  类似于以下内容：`builder.Entity<Package>().HasIndex(m => m.Name);`。

1.  使用类似于以下内容的东西：

```cs
builder.Entity<Destination>()
.HasMany(m => m.Packages)
.WithOne(m => m.MyDestination)
.HasForeignKey(m => m.DestinationId)
.OnDelete(DeleteBehavior.Cascade); 
```

1.  Add-Migration 和 Update-Database。

1.  不，但您可以使用`Include` LINQ 子句或在配置`DbContext`时使用`UseLazyLoadingProxies`选项强制包含它们。

1.  是的，谢谢`Select` LINQ 子句。

1.  通过调用`context.Database.Migrate()`。

# 第九章

1.  不，它是一个可以用作缓存或其他内存存储需求的内存字典。

1.  是的，它们是。本章的大部分部分都致力于解释为什么。

1.  写操作。

1.  NoSQL 数据库的主要弱点是它们的一致性和事务性，而它们的主要优势是性能，特别是在处理分布式写入时。

1.  最终一致性前缀，会话，有界不一致性，强一致性。

1.  不，它们在分布式环境中效率不高。基于 GUID 的字符串性能更好，因为它们的唯一性是自动的，不需要同步操作。

1.  `OwnsMany`和`OwnsOne`。

1.  是的，可以。一旦使用`SelectMany`，索引就可以用于搜索嵌套对象。

# 第十章

1.  Azure Functions 是 Azure 的 PaaS 组件，允许您实现 FaaS 解决方案。

1.  您可以使用不同的语言编写 Azure Functions，例如 C＃，F＃，PHP，Python 和 Node。您还可以使用 Azure 门户和 Visual Studio Code 创建函数。

1.  Azure Functions 有两种计划选项。第一个计划是按照您使用的数量收费的消耗计划。第二个计划是应用服务计划，您可以在该计划中与函数的需求共享应用服务资源。

1.  在 Visual Studio 中部署函数的过程与 Web 应用程序部署相同。

1.  我们可以通过许多方式触发 Azure 函数，例如使用 Blob 存储，Cosmos DB，事件网格，事件中心，HTTP，Microsoft Graph 事件，队列存储，服务总线，定时器和 Webhooks。

1.  Azure Functions v1 需要.NET Framework 引擎，而 v2 需要.NET Core 2.2，v3 需要.NET Core 3.1 和.NET 5。

1.  每个 Azure 函数的执行都可以通过应用程序洞察监控。在这里，您可以检查处理所需的时间，资源使用情况，错误以及每个函数调用中发生的异常。

# 第十一章

1.  设计模式是解决软件开发中常见问题的好方法。

1.  设计模式为我们在开发中面临的典型问题提供了代码实现，设计原则则帮助您在实现软件架构时选择最佳选项。

1.  生成复杂对象而无需在您将要使用它们的类中定义它们的生成器模式将有所帮助。

1.  工厂模式在您有多种来自相同抽象的对象并且在编码开始时不知道哪个对象需要被创建时非常有用。

1.  单例模式在软件执行期间需要只有一个实例的类时非常有用。

1.  代理模式用于在需要提供控制对另一个对象的访问时。

1.  命令模式用于执行将影响对象行为的*命令*。

1.  当您需要向一组其他对象提供有关对象的信息时，发布者/订阅者模式非常有用。

1.  DI 模式在实现控制反转原则时非常有用。

# 第十二章

1.  专家使用的语言和单词含义的变化。

1.  域映射。

1.  不；整个通信都通过实体即聚合根进行。

1.  因为聚合代表部分-整体层次结构。

1.  只有一个，因为存储库是以聚合为中心的。

1.  应用层操作存储库接口。存储库实现被注册到依赖注入引擎中。

1.  在单个事务中协调对多个聚合的操作。

1.  更新和查询的规范通常非常不同，特别是在简单的 CRUD 系统中。其最强形式的原因主要是优化查询响应时间。

1.  依赖注入。

1.  不；必须进行严格的影响分析，以便我们可以采用它。

# 第十三章

1.  不，因为在这种方法中会有大量重复的代码，这将在维护时造成困难。

1.  代码重用的最佳方法是创建库。

1.  是的。您可以在以前创建的库中找到已经创建的组件，然后通过创建可以在将来重用的新组件来增加这些库。

1.  .NET 标准是一种规范，允许.NET 的不同框架之间的兼容性，从.NET Framework 到 Unity。 .NET Core 是一种.NET 实现，是开源的。

1.  通过创建一个.NET 标准库，您将能够在不同的.NET 实现中使用它，例如.NET Core，.NET Framework 和 Xamarin。

1.  您可以使用面向对象的原则（继承，封装，抽象和多态）实现代码重用。

1.  泛型是一种复杂的实现，通过定义一个在编译时将被具体类型替换的占位符，简化了具有相同特征的对象的处理方式。

1.  这个问题的答案由 Immo Landwerth 在 dotnet 博客上得到了很好的解释：[`devblogs.microsoft.com/dotnet/the-future-of-net-standard/`](https://devblogs.microsoft.com/dotnet/the-future-of-net-standard/)。基本答案是，.NET 5.0（以及未来的版本）需要被认为是未来共享代码的基础。

1.  当您重构代码时，您正在以更好的方式编写它，尊重该代码将处理的数据的输入和输出的合同。

# 第十四章

1.  不，因为这将违反服务对请求的反应必须依赖于请求本身的原则，而不是依赖于先前与客户端交换的其他消息/请求。

1.  不，因为这将违反互操作性约束。

1.  可以。`POST`的主要操作必须是创建，但删除可以作为副作用执行。

1.  三，即头部和正文的 Base64 编码加上签名。

1.  从请求体中。

1.  使用`ApiController`属性。

1.  `ProducesResponseType`属性。

1.  使用`Route`和`Http<verb>`属性。

1.  类似于`services.AddHttpClient<MyProxy>()`。

# 第十五章

1.  开发人员错误页面和开发人员数据库错误页面，生产错误页面，主机，HTTPS 重定向，路由，身份验证和授权以及端点调用者。

1.  不。

1.  错误。可以在同一个标签上调用多个标签助手。

1.  `ModelState.IsValid`。

1.  `@RenderBody()`.

1.  我们可以使用`@RenderSection("Scripts", required: false)`。

1.  我们可以使用`return View("viewname", ViewModel)`。

1.  三。

1.  不；还有`ViewState`字典。

# 第十六章

1.  这是一个 W3C 标准：在符合 W3C 的浏览器中运行的虚拟机的组装。

1.  一个 Web UI，其中动态 HTML 是在浏览器本身中创建的。

1.  根据当前浏览器 URL 选择页面。

1.  一个带有路由的 Blazor 组件。因此，Blazor `router`可以选择它。

1.  定义 Blazor 组件类的.NET 命名空间。

1.  一个本地服务，负责存储和处理所有与表单相关的信息，比如验证错误和 HTML 输入的更改。

1.  `OnInitialized`或`OnInitializedAsync`。

1.  回调和服务。

1.  Blazor 与 JavaScript 交互的方式。

1.  获取对组件或 HTML 元素实例的引用。

# 第十七章

1.  可维护性使您有机会快速交付您设计的软件。它还允许您轻松修复错误。

1.  圈复杂度是一种检测方法具有的节点数的度量标准。数字越高，影响越糟。

1.  版本控制系统将保证您的源代码的完整性，使您有机会分析您所做的每次修改的历史。

1.  垃圾收集器是.NET Core/.NET Framework 系统，它监视您的应用程序并检测您不再使用的对象。它处理这些对象以释放内存。

1.  `IDisposable`接口首先很重要，因为它是一种确定性清理的良好模式。其次，它在需要由程序员处理的实例化对象的类中是必需的，因为垃圾收集器无法处理它们。

1.  .NET Core 在其某些库中封装了一些设计模式，以一种可以保证更安全的代码的方式，比如依赖注入和构建器。

# 第十八章

1.  因为大多数测试必须在任何软件更改后重复进行。

1.  因为在单元测试和其关联的应用程序代码中发生完全相同错误的概率非常低。

1.  当测试方法定义多个测试时使用`[Theory]`，而当测试方法只定义一个测试时使用`[Fact]`。

1.  `Assert`。

1.  `Setup`，`Returns`和`ReturnsAsync`。

1.  是的；使用`ReturnAsync`。

# 第十九章

1.  良好编写的代码是任何精通该编程语言的人都可以处理、修改和发展的代码。

1.  Roslyn 是在 Visual Studio 内部用于代码分析的.NET 编译器。

1.  代码分析是一种考虑代码编写方式的实践，在编译之前检测不良实践。

1.  代码分析可以发现即使是表面上良好的软件中出现的问题，例如内存泄漏和不良的编程实践。

1.  Roslyn 可以在设计时检查您的代码风格、质量、可维护性、设计和其他问题。这是在设计时完成的，因此您可以在编译代码之前检查错误。

1.  Visual Studio 扩展是在 Visual Studio 内部运行的工具。这些工具可以在某些情况下帮助您，其中 Visual Studio IDE 没有适合您使用的功能。

1.  微软代码分析，SonarLint 和 Code Cracker。

# 第二十章

1.  DevOps 是持续向最终用户交付价值的方法。为了成功地做到这一点，必须进行持续集成、持续交付和持续反馈。

1.  持续集成允许您在每次提交更改时检查您正在交付的软件的质量。您可以通过在 Azure DevOps 中启用此功能来实现这一点。

1.  持续交付允许您在确保所有质量检查都通过了您设计的测试之后部署解决方案。Azure DevOps 通过提供相关工具来帮助您实现这一目标。

1.  持续反馈是在 DevOps 生命周期中采用工具，使得在性能、可用性和应用程序的其他方面快速获得反馈成为可能。

1.  构建管道将让您运行用于构建和测试应用程序的任务，而发布管道将为您提供定义应用程序在每种情况下如何部署的机会。

1.  应用程序洞察是一个有用的工具，用于监视您部署的系统的健康状况，这使其成为一个出色的持续反馈工具。

1.  测试和反馈是一种工具，允许利益相关者分析您正在开发的软件，并与 Azure DevOps 建立连接，以打开任务甚至错误。

1.  最大化软件为目标组织提供的价值。

1.  不；它需要获得最大化软件增加值所需的所有能力。

1.  因为当新用户订阅时，其租户必须自动创建，并且因为新软件更新必须分发到所有客户的基础设施。

1.  是的；Terraform 就是一个例子。

1.  Azure 管道。

1.  您的业务依赖于 SaaS 供应商，因此其可靠性至关重要。

1.  不；可伸缩性和容错性以及自动故障恢复同样重要。

# 第二十一章

1.  这是一种方法，确保代码存储库中的每个提交都经过构建和测试。这是通过频繁地将代码合并到主体代码中来完成的。

1.  是的，您可以单独拥有 DevOps，然后稍后启用持续集成。您也可以在没有持续交付的情况下启用持续集成。您的团队和流程需要准备好并密切关注这一点。

1.  您可能会误解 CI 为持续交付过程。在这种情况下，您可能会对生产环境造成损害。在最坏的情况下，您可能会有一个尚未准备好但已部署的功能，您可能会在客户的糟糕时刻停止，或者甚至由于不正确的修复而遭受糟糕的副作用。

1.  多阶段环境在启用 CI-CD 时保护生产环境免受糟糕的发布。

1.  自动化测试可以预测预览场景中的错误和不良行为。

1.  拉取请求允许在提交到主分支之前进行代码审查。

1.  不；拉取请求可以帮助您在任何开发方法中，其中 Git 是您的源代码控制。

# 第二十二章

1.  不；这取决于用户界面的复杂性以及其变化频率。

1.  ASP.NET Core 管道不会被执行，而是直接将输入传递给控制器。

1.  使用`Microsoft.AspNetCore.Mvc.Testing` NuGet 包。

1.  使用`AngleSharp` NuGet 包。
