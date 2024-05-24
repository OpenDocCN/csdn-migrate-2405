# PHP 微服务（二）

> 原文：[`zh.annas-archive.org/md5/32377e38e7a2e12adc56f6a343e595a0`](https://zh.annas-archive.org/md5/32377e38e7a2e12adc56f6a343e595a0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：测试和质量控制

在本章中，我们将看一下在开发过程之前、期间和之后可以使用的不同测试方法。正如你所知，测试你的应用程序可以避免未来出现问题，并为你提供更好的项目概述。

# 在你的应用程序中使用测试的重要性

在我们的应用程序中使用测试非常重要，因为这些步骤可以避免（或至少减少）未来可能出现的问题或错误，因为我们是人类，在开发过程中可能会犯错误，或者因为项目结构不正确，甚至开发人员的理解与客户的要求不符。

测试过程将有助于提高代码质量和功能的理解，进行回归测试以避免在持续集成中包含旧问题，并减少完成项目所需的时间。

测试用于减少应用程序中的失败或错误。开发团队花费大量时间进行错误修复，根据错误的发现时间不同，影响可能会更大或更小。以下图片显示了与开发阶段相关的错误修复的相对成本：

![在应用程序中使用测试的重要性](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_04_01.jpg)

在开发中使用测试方法的原因是我们可以在开发的早期阶段发现代码中的错误，这样我们将花费更少的时间进行错误修复。

## 微服务测试

基于微服务的应用程序测试的挑战不在于测试每个单独的微服务，而在于集成和数据一致性。基于微服务的应用程序将需要开发人员对微服务架构及其工作流程有更好的理解，以便能够在其上进行测试。这是因为需要检查每个微服务的信息和功能，以及微服务之间的通信点。

在微服务上使用的测试如下：

+   **单元测试**：在所有基于微服务的应用程序中，甚至在单体应用程序中，都需要使用单元测试。通过使用它，我们将检查方法或代码模块的必要功能。

+   **集成测试**：单元测试仅检查孤立的组件，因此我们还需要检查方法之间的行为。我们将使用集成测试来检查同一微服务中方法之间的行为，因此微服务之间的调用将需要被模拟。

+   **API 测试**：微服务架构依赖于它们之间的通信。对于每个微服务，需要建立一个 API；这就像使用该微服务的*合同*。通过这种测试，我们将检查每个微服务的合同是否有效，并且所有微服务是否互相配合。

+   **端到端测试**：这些测试保证了应用程序的质量，没有任何模拟方法或调用。将运行测试来评估所有必需微服务之间的功能。在这些测试期间有一些规则可以避免问题：

+   端到端测试很难维护，因此只测试最重要的功能；其余功能使用单元测试

+   通过模拟对微服务的调用，可以测试用户功能

+   测试环境必须保持清洁，因为测试非常依赖数据，因此先前的测试可能会操纵数据，然后下一个测试

一旦我们知道如何根据微服务进行应用程序测试，我们将看一些在开发过程中进行测试的策略。

# 测试驱动开发

**测试驱动开发**（**TDD**）是敏捷哲学的一部分，它似乎解决了应用程序不断发展和成长以及代码变得混乱时常见的开发人员问题。开发人员修复问题以使其运行，但我们添加的每一行代码都可能是一个新的错误，甚至可能破坏其他功能。

TDD 是一种学习技术，它帮助开发人员以迭代、增量和建构主义的方式了解他们将构建的应用程序的领域问题：

+   **迭代**，因为该技术始终重复相同的过程以获得价值

+   **增量**，因为对于每个迭代，我们有更多的单元测试可供使用

+   **建构主义**，因为我们可以立即测试我们正在开发的一切，以便我们可以获得即时反馈

此外，当我们完成每个单元测试或迭代开发后，我们可以忘记它，因为它将在整个开发过程中保留，帮助我们通过单元测试记住领域问题。这对健忘的开发人员是一个很好的方法。

非常重要的是要理解 TDD 包括四个方面：分析、设计、开发和测试。换句话说，进行 TDD 就是理解领域问题并正确分析问题，良好设计应用程序，良好开发和测试。需要明确的是，TDD 不仅仅是实现单元测试，而是整个软件开发过程。

TDD 完全匹配基于微服务的项目，因为在大型项目中使用微服务是将其分成小微服务，我们的功能就像由通信渠道连接的小项目的聚合。项目的大小与使用 TDD 无关，因为在这种技术中，您将每个功能划分为小示例，为此，项目的大小无关紧要，甚至当我们的项目被微服务分割时更是如此。此外，微服务仍然比单块项目更好，因为单元测试的功能是在微服务中组织的，这将帮助开发人员知道他们可以从哪里开始使用 TDD。

## 如何进行 TDD？

进行 TDD 并不难，我们只需要遵循一些步骤并通过改进我们的代码来重复它们，并检查我们没有破坏任何东西：

1.  **编写单元测试**：它需要是可能的最简单和最清晰的测试，并且一旦完成，它必须失败；这是强制性的，如果它没有失败，那意味着我们做错了什么。

1.  **运行测试**：如果有错误（测试失败），这是开发最小代码以通过测试的时刻；只需做必要的事情，不要编写额外的代码。一旦开发了最小代码以通过测试，再次运行测试；如果通过了，就进入下一步，如果没有，修复它并再次运行测试。

1.  **改进测试**：如果您认为可以改进您编写的代码，那就去做并再次运行测试。如果您认为它是完美的，那就编写一个新的单元测试。

以下图片说明了 TDD 的口号--**红**，**绿**，**重构**：

![如何进行 TDD？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_04_02.jpg)

要进行 TDD，需要在实现函数之前编写测试；如果先开始实现然后再编写测试，那就不是 TDD，只是测试。

如果我们在开始开发应用程序后创建单元测试，那么我们正在进行经典测试，并且没有充分利用 TDD 的好处。编写单元测试将帮助您确保在开发过程中您对领域问题的抽象理解是正确的。

显然，进行测试总比不进行测试要好，但进行 TDD 仍然比仅进行经典测试要好。

## 为什么我应该使用 TDD？

TDD 是对问题的答案，比如“我应该从哪里开始？”，“我该如何做？”，“我如何编写可以修改而不会破坏任何东西的代码？”，以及“我如何知道我必须实现什么？”。

目标不是毫无意义地编写许多单元测试，而是根据要求正确设计 TDD。在 TDD 中，我们不是考虑实现功能，而是考虑与域问题相关的功能的良好示例，以消除域问题造成的歧义。

换句话说，我们应该通过 TDD 在 X 个示例中复制特定功能或用例，直到我们得到必要的示例来描述该功能或任务，而不会产生歧义或误解。

### 提示

TDD 可能是记录应用程序的最佳方法。

使用其他软件开发方法时，我们开始思考架构将是什么样子，将使用什么模式，微服务之间的通信将如何进行，但如果一旦我们计划了所有这些，我们意识到这是不必要的呢？我们要花多长时间才能意识到？我们将花费多少精力和金钱？

TDD 通过在许多迭代中创建小示例来定义我们应用程序的架构，直到我们意识到什么是架构。这些示例将逐渐向我们展示应该遵循的步骤，以便定义最佳结构、模式或要使用的工具，从而避免在应用程序的最初阶段浪费资源。

这并不意味着我们在没有架构的情况下工作。显然，我们必须知道我们的应用程序是网站还是移动应用，并使用适当的框架（您可以在第二章中了解哪种框架适合您的需求，*开发环境*），还要知道应用程序中的互操作性将是什么；在我们的情况下，它将是基于微服务的应用程序。因此，它将支持我们开始创建第一个单元测试。TDD 将成为我们开发应用程序的指南，并且将通过单元测试产生一个没有歧义的架构。

TDD 并非万能良药；换句话说，它对资深开发人员和初级开发人员的效果并不相同，但对整个团队都是有用的。让我们看看使用 TDD 的一些优势：

+   代码重用：这样可以仅使用必要的代码来通过第二阶段（绿色）的测试来创建每个功能。它可以让你看到是否有更多的功能使用相同的代码结构或特定功能的部分；因此，它可以帮助你重用先前编写的代码。

+   团队合作更容易：它让你对团队同事充满信心。一些架构师或资深开发人员不信任经验不足的开发人员，他们需要在提交更改之前检查他们的代码，从而在这一点上造成瓶颈，因此 TDD 帮助我们相信经验较少的开发人员。

+   增加沟通：增加团队同事之间的沟通。沟通更加流畅，因此团队可以分享他们在单元测试中反映的对项目的知识。

+   避免过度设计：不要在最初阶段过度设计应用程序。正如我们之前所说，进行 TDD 可以让你逐渐了解应用程序的概况，避免在项目中创建无用的结构或模式，也许在将来的阶段会被废弃。

+   单元测试是最好的文档：了解特定功能的最佳方法是阅读其单元测试，这有助于我们理解它的工作原理，而不是人类的语言。

+   在设计阶段发现更多用例：在每个测试中，您都将了解功能应该如何更好地工作，以及功能可能具有的所有可能阶段。

+   **增加了工作完成的感觉**：在每次提交代码时，您会感到它被正确地完成了，因为其余的单元测试都通过了，所以您不必担心破坏其他功能。

+   **提高软件质量**：在重构步骤中，我们努力使代码更高效和可维护，验证在更改后整个项目仍然正常工作。

## TDD 算法

遵循 TDD 算法的技术概念和步骤是简单明了的，通过实践来改进实现它的正确方式。正如我们之前所看到的，只有三个步骤：红、绿和重构。

### 红 - 编写单元测试

即使代码尚未编写，也可以编写测试，您只需考虑是否可以在实现之前编写规范。因此，在第一步中，您应该考虑开始编写的单元测试不像单元测试，而像功能的示例或规范。

在 TDD 中，这个示例或规范并不是固定的；换句话说，单元测试可以在将来进行修改。在开始编写第一个单元测试之前，需要考虑**被测试软件**（**SUT**）将是什么样子，以及它将如何工作。我们需要考虑 SUT 代码将是什么样子，以及我们将如何检查它是否按我们想要的方式工作。

TDD 的工作方式首先让我们设计更舒适和清晰的东西，如果它符合要求的话。

### 绿 - 使代码工作

一旦示例编写完成，我们必须编写最少的代码使其通过测试；换句话说，设置单元测试为绿色。代码是否丑陋且未经优化并不重要，这将是我们在接下来的步骤和迭代中的任务。

在这一步中，重要的是只编写满足要求的必要代码，而不是不必要的东西。这并不意味着不考虑功能性地编写，而是考虑到它的高效性。看起来很容易，但您会意识到第一次会写出额外的代码。

如果您专注于这一步，您将考虑到关于 SUT 行为的不同输入的新问题。然而，您应该坚定不移地避免编写与当前功能相关的其他功能的额外代码。作为一个经验法则，不要编写新功能，而是做笔记，以便在未来的迭代中将它们转换为功能。

### 重构 - 消除冗余

重构不同于重写代码。您应该能够在不改变行为的情况下改变设计。

在这一步中，您应该消除代码中的重复，并检查代码是否符合良好实践的原则，考虑效率、清晰度和代码的未来可维护性。这部分取决于每个开发人员的经验。

### 提示

良好重构的关键是采取小步骤。

重构功能的最佳方式是改变一小部分并执行所有可用的测试，如果它们通过了，继续进行下一个小部分，直到你对得到的结果满意。

# 行为驱动开发

**行为驱动开发**（**BDD**）是一种扩展 TDD 技术并将其与其他设计思想和业务分析相结合的过程，以便提供给开发人员以改进软件开发。

在 BDD 中，我们测试场景和类的行为，以满足可以由许多类组成的场景。

使用 DSL 非常有用，以便客户、项目所有者、业务分析师或开发人员使用共同的语言。目标是拥有一个像我们在第三章中看到的那样的普遍语言，*应用设计*，在领域驱动设计部分。

## 什么是 BDD？

正如我们之前所说，BDD 是一种基于 TDD 和 ATDD 的敏捷技术，促进了项目整个团队之间的协作。

BDD 的目标是让整个团队了解客户的需求，让客户知道团队其他成员从他们的规范中理解了什么。大多数情况下，当项目开始时，开发人员和客户的观点并不相同，在开发过程中客户意识到也许他们没有解释清楚，或者开发人员没有正确理解，因此需要更多时间来更改代码以满足客户的需求。

因此，BDD 是使用规则或通用语言以人类语言编写测试用例，以便客户和开发人员能够理解。它还为测试定义了 DSL。

## 它是如何工作的？

需要将功能定义为用户故事（我们将在本章的 ATDD 部分解释这是什么），并检查它们的验收标准。

一旦用户故事被定义，我们必须专注于使用 DSL 描述项目行为的可能场景。步骤是：给定（上下文），当（事件发生），然后（结果）。

总之，为用户故事定义的场景为验收标准提供了检查功能是否完成的依据。

### Cucumber 作为 BDD 的 DSL

Cucumber 是一个 DSL 工具，它执行以纯文本形式制作的示例作为自动测试，利用 BDD 的好处，将业务层和技术结合在一起，以了解用户最看重的功能，并在定义用例测试和记录项目的同时开发它们。

### 提示

Cucumber 最重要的是让开发人员和客户有相同的理解。

**Gherkin**是 Cucumber 使用的语言，它允许您将项目的规范翻译成接近人类语言，以便客户或其他没有技术技能的人能够理解。这个工具和语言可以用于 BDD 和 ATDD。让我们看一个样本代码：

```php
    Feature: Search secrets 
     In order to find secrets 
     Users should be able to search for near secrets 

     Scenario: Search secrets by distance 
       Given there are 996 secrets in the game which are no closer than 100 
       meters from me 
       And there are 4 secrets SEC001, SEC005, SEC054, SEC121 that are 
       within 100 
       meters from me 
       When I search for closer secrets 
       Then I should see the following secrets: 
         | Secret code | 
         | SEC001      | 
         | SEC005      | 
         | SEC054      | 
         | SEC121      | 

```

这样可以让我们定义软件行为，而不用说出它是如何实现的。同时，它也让我们能够在编写自动测试用例的同时记录功能。使用 Cucumber 的优势如下：

+   易于阅读

+   易于理解

+   易于解析

+   易于讨论

DSL 在代码中有三个工具可以理解和处理的步骤；它们如下：

1.  **给定**：这是将系统设置为适当状态以检查测试的必要步骤。

1.  **当**：这是用户必须执行的必要步骤来激活功能。

1.  **然后**：这指的是系统中发生变化的事物。在这里，我们能够看到它是否符合我们的期望。

此外，还有两个可选的步骤：**And**和**But**，它们可以在**Given**或**Then**中使用，当您需要超过一句话来满足要求时。

在本章中，我们将看到如何使用一个名为 Selenium 的工具来进行 BDD。这是另一个 DSL 工具，但是它是面向 Web 开发而不是纯文本的。

# 验收测试驱动开发

也许项目中最重要的方法是**验收测试驱动开发**（**ATDD**）或**故事测试驱动开发**（**STDD**）；它是 TDD，但在不同的层面上。

验收（或客户）测试是项目满足客户需求的业务要求的书面标准。它们是由项目所有者编写的示例（就像 TDD 中的示例）。它是每次迭代开发的开始，是 Scrum 和敏捷开发之间的桥梁。

在 ATDD 中，我们以一种与传统方法不同的方式开始项目的实施。用人类语言编写的业务需求被一些团队成员和客户商定的可执行文件所取代。这并不是要替换整个文档，而只是部分需求。

使用 ATDD 的优势如下：

+   它提供了真实的例子和一个团队可以理解领域的共同语言

+   它使我们能够正确识别领域规则

+   可以在每次迭代中知道用户故事是否完成

+   工作流程从最初的步骤开始

+   开发直到团队定义并接受了测试才开始

## 用户故事

ATDD 的用户故事在名称或描述方面类似于用例，但工作方式不同。用户故事不定义需求，避免了人类语言的歧义问题。目标是让团队的其他成员能够无问题地理解这个想法。

每个用户故事都是关于客户对应用程序的期望的清晰简洁的例子列表。故事的名称是一个人类语言的句子，定义了功能必须做什么。考虑以下例子：

+   搜索我们位置周围的可用秘密

+   检查我们已经存储的秘密

+   检查战斗中谁是赢家

他们的目标是倾听客户并帮助他们定义他们对应用程序的期望。用户故事应该清晰明了，没有歧义，并且应该用人类语言而不是技术语言编写；客户应该能够理解他们所说的话。

一旦我们定义了一个用户故事，就会出现一些问题，这些问题应该通过为每个故事关联验收测试来回答。例如，对于*检查战斗中谁是赢家*的故事，一些可能的问题如下所列：

+   如果他们平局了会发生什么？

+   赢家会得到什么？

+   输家会失去什么？

+   一场战斗需要多长时间？

可能的验收测试如下：

+   如果他们平局了，没有人会赢或输任何东西；他们会保留他们的秘密

+   赢家将获得 10 分，并从输家的口袋里得到一个秘密

+   输家将给赢家一个秘密

+   一场战斗需要掷三次骰子

也许一个用户故事的问题和答案会产生新的用户故事，添加到待办列表中。

## ATDD 算法

ATDD 的算法类似于 TDD，但覆盖的人员比开发人员更多。换句话说，进行 ATDD 时，每个故事的测试是在一个会议上编写的，该会议包括项目所有者、开发人员和 QA 技术人员，因为团队必须理解需要做什么以及为什么需要这样做，以便他们可以看到代码应该做什么。以下图片显示了 ATDD 的循环：

![ATDD 算法](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_04_03.jpg)

### 讨论

ATDD 算法的起点是讨论。在这一步中，业务与客户进行会议，澄清应用程序应该如何工作，分析师应该从对话中创建用户故事。此外，他们应该能够解释每个用户故事的满意条件，以便被翻译成例子，就像我们在用户故事部分解释的那样。

会议结束时，例子应该清晰简洁，这样我们就可以得到一个用户故事的例子列表，以满足客户审查和理解的所有需求。此外，团队将对项目有一个概览，以便理解用户故事的业务价值，如果用户故事太大，可以将其分成小的用户故事，获得第一个迭代的第一个用户故事。

### 提炼

高级验收测试由客户和开发团队编写。在这一步中，从讨论步骤中得到的测试用例的编写开始，并且团队可以参与讨论并帮助澄清信息或指定其真实需求。

测试应该覆盖在讨论步骤中发现的所有示例，并在这个过程中可以添加额外的测试；一点一点地我们正在更好地理解功能。

在这一步结束时，我们将获得以人类语言编写的必要测试，以便团队（包括客户）能够理解他们在下一步将要做什么。这些测试可以用作文档。

### 开发

在开发步骤中，验收测试用例开始由开发团队和项目所有者开发。在这一步骤中要遵循的方法与 TDD 相同--开发人员应该创建一个测试并观察它失败（红色），然后开发最少的代码行以通过测试（绿色）。一旦验收测试通过，就应该进行验证和测试，准备好交付。

在这个过程中，开发人员可能会发现需要添加到测试中的新场景，甚至，如果需要大量工作，它可能会被推到用户故事中。

在这一步结束时，我们将拥有一个通过验收测试的软件，甚至可能还有更全面的测试。

### 演示

通过运行验收测试用例并手动探索新功能的特性来展示创建的功能。演示完毕后，团队讨论用户故事是否做得恰当，是否满足产品所有者的需求，并决定是否可以继续下一个故事。

# 工具

现在您已经更多地了解了 TDD 和 BDD，是时候解释一些可以在开发工作流程中使用的工具了。有很多可用的工具，但我们只会解释最常用的工具。

## Composer

Composer 是一个用于管理软件依赖关系的 PHP 工具。您只需要声明项目所需的库，Composer 将管理它们，在必要时安装和更新它们。这个工具只有一些要求--如果您有 PHP 5.3.2+，您就可以开始了。如果缺少某个要求，Composer 会提醒您。

您可以在开发机器上安装这个依赖管理器，但由于我们使用的是 Docker，我们将直接在我们的**PHP-FPM**（**FastCGI 进程管理器**）容器中安装它。在 Docker 中安装 Composer 非常容易；您只需要向 Dockerfile 添加以下规则：

```php
    RUN curl -sS https://getcomposer.org/installer 
    | php -- --install-dir=/usr/bin/ --filename=composer 

```

## PHPUnit

我们项目中需要的另一个工具是 PHPUnit，一个单元测试框架。在我们的情况下，我们将使用 4.0 版本。与之前一样，我们将把这个工具添加到我们的 PHP-FPM 容器中，以保持我们的开发机器干净。如果您想知道为什么除了 Docker 之外我们不在开发机器上安装任何东西，答案很明确--将所有东西放在容器中将帮助您避免与其他项目的冲突，并且可以灵活地更改版本而不必过于担心。

作为一个快速的方法，您可以在您的`PHP-FPM` `Dockerfile`中添加以下`RUN`命令，这样您就可以安装并准备使用最新的 PHPUnit 版本了：

```php
    RUN curl -sSL https://phar.phpunit.de/phpunit.phar -o 
    /usr/bin/phpunit && chmod +x /usr/bin/phpunit 

```

上述命令将在您的容器中安装最新的 Composer 版本，但推荐的安装方式是通过 Composer。打开您的`composer.json`文件并添加以下行：

```php
    "phpunit/phpunit": "4.0.*",
```

一旦您更新了`composer.json`文件，您只需要在容器命令行中执行 Composer 更新，Composer 就会为您安装 PHPUnit。

既然我们的要求都准备好了，现在是时候安装我们的 PHP 框架并开始做一些 TDD 的工作了。稍后，我们将继续更新我们的 Docker 环境，加入新的工具。

在前几章中，我们谈到了一些 PHP 框架，并选择了 Lumen 作为我们的示例。请随意将所有示例调整为您喜欢的框架。我们的源代码将存储在容器中，但在开发的这一阶段，我们不希望容器是不可变的。我们希望我们对代码所做的每一次更改都能立即在我们的容器中使用，因此我们将使用容器作为存储卷。

要创建一个包含我们的源代码并将其用作存储卷的容器，我们只需要编辑我们的`docker-compose.yml`文件，并为我们的每个微服务创建一个源容器，如下所示：

```php
    source_battle: 
       image: nginx:stable 
       volumes: 
           - ../source/battle:/var/www/html 
       command: "true" 

```

上述代码片段创建了一个名为`source_battle`的容器映像，并存储了我们的 battle 源代码（位于`docker-compose.yml`文件当前路径的`../source/battle`）。一旦我们有了我们的源代码容器，我们可以编辑每个服务并分配一个卷。例如，我们可以将以下行添加到我们的`microservice_battle_fpm`和`microservice_battle_nginx`容器描述中：

```php
    volumes_from: 
               - source_battle 

```

我们的 battle 源代码将在我们的源容器的`/var/www/html`路径中可用，安装 Lumen 的剩下步骤是执行一个简单的 Composer 命令。首先，您需要确保您的基础设施已经准备好了：

```php
**$ docker-compose up**

```

上述命令启动我们的容器并将日志输出到标准 IO。现在我们确信一切都已经准备就绪，我们需要进入我们的 PHP-FPM 容器并安装 Lumen。

### 提示

如果您需要知道每个容器分配的名称，可以在终端上执行`docker ps`并复制容器名称。例如，我们将输入以下命令进入 battle PHP-FPM 容器：

```php
**$ docker exec -it docker_microservice_battle_fpm_1 /bin/bash**

```

上述命令在您的容器中打开一个交互式 shell，以便您可以做任何您想做的事情。让我们用一个命令安装 Lumen：

```php
**# cd /var/www/html && composer create-project --prefer-dist laravel/lumen .**

```

对每个微服务重复上述命令。

现在您已经准备好开始进行单元测试并编写应用程序代码了。

### 单元测试

单元测试是一小段代码，它在已知的上下文中使用其他代码，以便我们可以检查我们正在测试的代码是否有效。Lumen 默认带有 PHPUnit；因此，我们只需要将所有测试添加到 tests 文件夹中。框架安装默认带有一个非常小的示例文件--`ExampleTest.php`--您可以在其中尝试单元测试。为了开始单元测试，直到您更加熟悉创建单元测试，选择一个您的微服务源代码，并创建`app/Dummy.php`文件，内容如下：

```php
<?php 
namespace App;

class Dummy 
{ 
} 

```

### 提示

开始单元测试的最简单方法是每次在代码中创建一个新类时，您都可以为测试创建一个新类。以这种方式工作，您将记住您的新类需要用单元测试进行覆盖。例如，想象一下您需要一个`Battle`类；因此，当您创建该类时，您还可以在`tests`文件夹中创建一个以`Test`为前缀的新类。

在理想的情况下，所有代码都应该由单元测试覆盖，但我们知道这是一个奇怪的情况。大多数情况下，如果幸运的话，您的代码覆盖率将达到 70%或 80%。我们鼓励您保持代码完全覆盖，但如果不可能，至少覆盖核心功能。有两种创建单元测试的方法：

+   **先测试，后编码：**在我们看来，当您有足够的时间开发项目时，这种工作流程更好。首先，创建测试，以确保您真正了解每个新功能。在测试就位后，您将编写必要的最小代码以通过测试。以这种方式编码，您将思考什么使您的代码有效，以及什么可能使您的代码失败。

+   **先写代码，后写测试：** 当您没有太多时间进行单元测试时，这是一个非常常见的工作流程。您像往常一样创建您的代码，一旦完成，就创建单元测试。这种方法会创建一个不太健壮的代码，因为您是将单元测试适应已创建的代码，而不是相反。

请记住，测试代码的时间非常重要；这是一项长期投资。在开始时花费时间将使您的代码更加健壮，并消除未来的错误。

### 运行测试

您可能想知道如何运行和检查您的测试。别担心，这很简单。您只需要进入您的 PHP-FPM 容器之一。例如，要进入 Battle PHP-FPM 容器，请打开终端并执行以下命令：

```php
**$ docker exec -it docker_microservice_battle_fpm_1 /bin/bash**

```

执行上述命令后，您将进入容器。现在是时候确保您的当前路径是`/var/www/html`文件夹。完成上一步后，您可以在该文件夹中执行 phpunit。所有这些操作都可以使用以下命令完成：

```php
**# cd /var/www/html**
**# ./vendor/bin/phpunit**

```

`phpunit`命令将读取`phpunit.xml`文件。这个 XML 描述了我们的测试存储在哪里，并执行所有测试。执行此命令将为我们提供一个漂亮的屏幕，显示我们的测试通过或失败的结果。

### 断言

断言是在已知上下文中的语句，我们期望在代码中的某个时刻为真，并且这是单元测试的核心。断言用于测试用例内，一个测试用例可以包含多个断言。在 PHPUnit 中，创建测试非常简单，您只需要在方法名称前添加`test`前缀。简单吧？为了澄清所有这些概念，让我们看一些您可以在单元测试中使用的断言及其示例。随时创建更复杂的测试，直到您熟悉 PHPUnit 为止。

### assertArrayHasKey

`assertArrayHasKey(mixed $key, array $array[, string $message = ''])`断言检查`$array`是否具有`$key`元素。想象一下，您有一个生成并返回某种配置数据的方法，并且有一个特定由`storage`标识的元素，您需要确保它始终存在。将以下方法添加到我们的`Dummy`类中以模拟配置生成：

```php
    public static function getConfigArray() 
    { 
      return [ 
           'debug'   => true, 
           'storage' => [ 
               'host' => 'localhost', 
               'port' => 5432, 
               'user' => 'my-user', 
               'pass' => 'my-secret-password' 
           ] 
       ]; 
    } 

```

现在我们可以以任何方式测试此`getConfigArray`的响应：

```php
    public function testFailAssertArrayHasKey() 
    { 
       $dummy = new App\Dummy(); 

       $this->assertArrayHasKey('foo', $dummy::getConfigArray()); 
    } 

```

上面的测试将检查`getConfigArray`返回的数组是否具有由`foo`标识的元素，在我们的示例中失败了：

```php
    public function testPassAssertArrayHasKey() 
    { 
       $dummy = new App\Dummy(); 

       $this->assertArrayHasKey('storage', $dummy::getConfigArray()); 
    } 

```

在这种情况下，此测试将确保`getConfigArray`返回由`storage`标识的元素。如果由于某种原因您将来更改`getConfigArray`方法的实现，此测试将帮助您确保您至少继续接收由`storage`标识的数组元素。

你可以使用`assertArrayNotHasKey()`作为`assertArrayHasKey`的反向操作；它使用相同的参数。

### assertClassHasAttribute

`assertClassHasAttribute(string $attributeName, string $className[, string $message = ''])`断言检查我们的`$className`是否已定义`$attributeName`。修改我们的`Dummy`类并添加一个新属性，如下所示：

```php
    public $foo; 

```

现在我们可以使用以下测试来测试此公共属性的存在：

```php
    public function testAssertClassHasAttribute() 
    { 
      $this->assertClassHasAttribute('foo', App\Dummy::class); 
      $this->assertClassHasAttribute('bar', App\Dummy::class); 
    } 

```

上面的代码将通过`foo`属性的检查，但在检查`bar`属性时将失败。

您可以使用`assertClassNotHasAttribute()`作为`assertClassHasAttribute`的反向操作；它使用相同的参数。

### assertArraySubset

`assertArraySubset(array $subset, array $array[, bool $strict = '', string $message = ''])`断言检查给定的`$subset`是否在我们的`$array`中可用：

```php
    public function testAssertArraySubset() 
    { 
       $dummy = new App\Dummy(); 

       $this->assertArraySubset(['storage' => 'failed-test'], 
       $dummy::getConfigArray()]); 
    } 

```

上面的示例测试将失败，因为`['storage' => 'failed-test']`子集不存在于我们的`getConfigArray`方法的响应中。

### assertClassHasStaticAttribute

`assertClassHasStaticAttribute(string $attributeName, string $className[, string $message = ''])`断言检查给定`$className`中静态属性的存在。我们可以向我们的`Dummy`类添加一个静态属性，如下所示：

```php
    public static $availableLocales = [ 
           'en_GB', 
           'en_US', 
           'es_ES', 
           'gl_ES' 
    ]; 

```

有了这个静态属性，我们可以自由地测试`$availableLocales`的存在：

```php
    public function testAssertClassHasStaticAttribute() 
    { 
      $this->assertClassHasStaticAttribute('availableLocales', 
      App\Dummy::class); 
    } 

```

如果需要断言相反的情况，可以使用`assertClassNotHasStaticAttribute();`它使用相同的参数。

### assertContains()

有时您需要检查一个集合是否包含特定元素。您可以使用`assertContains()`函数来实现：

+   `assertContains(mixed $needle, Iterator|array $haystack[, string $message = ''])`

+   `assertNotContains(mixed $needle, Iterator|array $haystack[, string $message = ''])`

+   `assertContainsOnly(string $type, Iterator|array $haystack[, boolean $isNativeType = null, string $message = ''])`

+   `assertNotContainsOnly(string $type, Iterator|array $haystack[, boolean $isNativeType = null, string $message = ''])`

+   `assertContainsOnlyInstancesOf(string $classname, Traversable|array $haystack[, string $message = ''])`

### assertDirectory()和 assertFile()

PHPUnit 不仅允许您测试应用程序的逻辑，还可以测试文件夹和文件的存在和权限。所有这些都可以通过以下断言实现：

+   `assertDirectoryExists(string $directory[, string $message = ''])`

+   `assertDirectoryNotExists(string $directory[, string $message = ''])`

+   `assertDirectoryIsReadable(string $directory[, string $message = ''])`

+   `assertDirectoryNotIsReadable(string $directory[, string $message = ''])`

+   `assertDirectoryIsWritable(string $directory[, string $message = ''])`

+   `assertDirectoryNotIsWritable(string $directory[, string $message = ''])`

+   `assertFileEquals(string $expected, string $actual[, string $message = ''])`

+   `assertFileNotEquals(string $expected, string $actual[, string $message = ''])`

+   `assertFileExists(string $filename[, string $message = ''])`

+   `assertFileNotExists(string $filename[, string $message = ''])`

+   `assertFileIsReadable(string $filename[, string $message = ''])`

+   `assertFileNotIsReadable(string $filename[, string $message = ''])`

+   `assertFileIsWritable(string $filename[, string $message = ''])`

+   `assertFileNotIsWritable(string $filename[, string $message = ''])`

+   `assertStringMatchesFormatFile(string $formatFile, string $string[, string $message = ''])`

+   `assertStringNotMatchesFormatFile(string $formatFile, string $string[, string $message = ''])`

您的应用程序是否依赖于可写文件才能工作？别担心，PHPUnit 会帮你解决。您可以在测试中添加`assertFileIsWritable()`，这样下次有人删除您在断言中指定的文件时，测试将失败。

### assertString()

在某些情况下，您需要检查一些字符串的内容。例如，如果您的代码生成序列码，您可以检查生成的代码是否符合您的规格。您可以使用以下断言来处理字符串：

+   `assertStringStartsWith(string $prefix, string $string[, string $message = ''])`

+   `assertStringStartsNotWith(string $prefix, string $string[, string $message = ''])`

+   `assertStringMatchesFormat(string $format, string $string[, string $message = ''])`

+   `assertStringNotMatchesFormat(string $format, string $string[, string $message = ''])`

+   `assertStringEndsWith(string $suffix, string $string[, string $message = ''])`

+   `assertStringEndsNotWith(string $suffix, string $string[, string $message = ''])`

### assertRegExp()

`assertRegExp(string $pattern, string $string[, string $message = ''])`断言对您非常有用，因为您可以在一个断言中使用所有的正则表达式功能。让我们向我们的 Dummy 类添加一个静态函数：

```php
    public static function getRandomCode() 
    { 
      return 'CODE-123A'; 
    } 

```

这个新函数返回一个静态字符串代码。随意增加生成的复杂性。要测试这个生成的字符串代码，您现在可以在测试类中做如下操作：

```php
    public function testAssertRegExp() 
    { 
       $this->assertRegExp('/^CODE\-\d{2,7}[A-Z]$/', 
       App\Dummy::getRandomCode()); 
    } 

```

正如您所看到的，我们正在使用简单的正则表达式来检查`getRandomCode`生成的输出。

### assertJson()

在使用微服务时，您可能会与 JSON 请求和响应密切合作。因此，非常重要的是您有能力测试我们的 JSON。您可以将 JSON 作为文件或字符串：

+   `assertJsonFileEqualsJsonFile()`

+   `assertJsonStringEqualsJsonFile()`

+   `assertJsonStringEqualsJsonString()`

### 布尔断言

可以使用以下方法检查布尔结果或类型：

+   `assertTrue(bool $condition[, string $message = ''])`

+   `assertFalse(bool $condition[, string $message = ''])`

### 类型断言

有时您需要确保元素是特定类的实例或具有特定的内部类型。您可以在测试中使用以下断言：

+   `assertInstanceOf($expected, $actual[, $message = ''])`

+   `assertInternalType($expected, $actual[, $message = ''])`

### 其他断言

PHPUnit 具有大量的断言，如果没有以下一些断言应用于您的功能的结果或对象状态，您的测试将无法完成：

+   `assertCount($expectedCount, $haystack[, string $message = ''])`

+   `assertEmpty(mixed $actual[, string $message = ''])`

+   `assertEquals(mixed $expected, mixed $actual[, string $message = ''])`

+   `assertGreaterThan(mixed $expected, mixed $actual[, string $message = ''])`

+   `assertGreaterThanOrEqual(mixed $expected, mixed $actual[, string $message = ''])`

+   `assertInfinite(mixed $variable[, string $message = ''])`

+   `assertLessThan(mixed $expected, mixed $actual[, string $message = ''])`

+   `assertLessThanOrEqual(mixed $expected, mixed $actual[, string $message = ''])`

+   `assertNan(mixed $variable[, string $message = ''])`

+   `assertNull(mixed $variable[, string $message = ''])`

+   `assertObjectHasAttribute(string $attributeName, object $object[, string $message = ''])`

+   `assertSame(mixed $expected, mixed $actual[, string $message = ''])`

您可以在 PHPUnit 网站上找到有关您可以在其中使用的断言的更多信息，即[`phpunit.de/`](https://phpunit.de/)。

### 从头开始的单元测试

此时，您可能对单元测试感到更加舒适，并且希望尽快开始编写您的应用程序，因此让我们开始测试吧！

我们的微服务应用程序使用地理定位来查找秘密和其他玩家。这意味着您的位置微服务将需要一种方法来计算两个地理空间点之间的距离。我们还需要根据起始点获取最接近的存储点的列表（它们可以是最接近的用户或秘密）。由于这是一个核心功能，您需要确保我们描述的内容经过充分测试。

在我们的应用程序中，定位有自己的服务。因此，使用您的 IDE 打开位置微服务的源代码，并创建`app/Http/Controllers/LocationController.php`文件，内容如下：

```php
    <?php 

    namespace App\Http\Controllers; 

    use Illuminate\Http\Request; 

    class LocationController extends Controller 
    { 

    } 

```

上述代码已在 Lumen 中创建了我们的位置控制器，并且正如我们之前提到的，一旦我们创建了这个类，我们需要为我们的单元测试创建一个类似的类。为了做到这一点，您只需要创建`tests/app/Http/Controllers/LocationControllerTest.php`文件。正如您所看到的，我们甚至在复制文件夹结构；这是最好的方法，可以轻松知道我们正在为哪个类进行测试。

我们希望开始为距离计算和允许我们根据特定地理位置点获取最接近的秘密的功能创建测试。一种方法是创建两个不同的测试。因此，请使用以下代码填充您的`LocationControllerTest.php`：

```php
    <?php 

    use Laravel\Lumen\Testing\DatabaseTransactions; 

    class LocationControllerTest extends TestCase 
    { 
      public function testDistance() 
      { 
      } 

      public function testClosestSecrets() 
      { 
      } 
    } 

```

我们没有向我们的测试类添加任何特殊内容，我们只声明了两个测试。

让我们从`testDistance()`开始。在这个测试中，我们希望确保给定两个地理空间点之间的计算距离对我们的目的来说足够准确。在单元测试中，你需要开始描述已知的场景——作为点，我们选择了伦敦（纬度：`51.50`，经度：`-0.13`）和阿姆斯特丹（纬度：`52.37`，经度：`4.90`）。这两个城市之间的已知距离大约为 358.06 公里，这是我们希望从我们的距离计算器中得到的结果。让我们用以下代码填充我们的测试：

```php
    public function testDistance() 
    { 
      $realDistanceLondonAmsterdam = 358.06; 

      $london = [ 
           'latitude'  => 51.50, 
           'longitude' => -0.13 
      ]; 

      $amsterdam = [ 
           'latitude'  => 52.37, 
           'longitude' => 4.90 
      ]; 

      $location = new App\Http\Controllers\LocationController(); 

      $calculatedDistance = $location->getDistance($london, $amsterdam); 

      $this->assertClassHasStaticAttribute('conversionRates', 
      App\Http\Controllers\LocationController::class); 
      $this->assertEquals($realDistanceLondonAmsterdam, 
                          $calculatedDistance); 
    } 

```

在上述代码片段中，我们定义了已知的场景，我们两点的位置和它们之间的已知距离。一旦我们准备好了已知的场景，我们创建了一个`LocationController`的实例，并使用定义的`getDistance`函数来获得我们想要测试的结果。一旦我们得到了结果，我们测试我们的`LocationController`是否有一个`conversionRate`静态属性，我们可以用它来将距离转换为不同的单位。我们最后并且最重要的断言检查了计算出的距离与这两点之间的已知距离之间的匹配。我们已经准备好了基本的测试，现在是时候开始编写我们的`getDistance`函数了。

两个地理空间点之间的距离计算可以用非常不同的方式计算。你可以在这里使用策略模式，但为了保持示例简单，我们将在控制器内的不同函数中编写不同的计算算法。

打开你的`LocationController`并添加一些辅助代码：

```php
    const ROUND_DECIMALS = 2; 

    public static $conversionRates = [ 
       'km'    => 1.853159616, 
       'mile'  => 1.1515 
    ]; 

    protected function convertDistance($distance, $unit = 'km') 
    { 
      switch (strtolower($unit)) { 
        case 'mile': 
          $distance = $distance * self::$conversionRates['mile']; 
          break; 
        default : 
          $distance = $distance * self::$conversionRates['km']; 
          break; 
      } 

      return round($distance, self::ROUND_DECIMALS); 
    } 

```

在上述代码中，我们定义了我们的转换率、一个我们可以用来四舍五入结果的常量，以及一个简单的转换函数。我们将稍后使用这个`convertDistance`函数。

我们计算距离的第一个方法是使用欧几里得函数来得到我们的结果。一个简单的实现如下所示：

```php
public function getEuclideanDistance($pointA, $pointB, $unit = 'km') 
    { 
       $distance = sqrt( 
           pow(abs($pointA['latitude'] - $pointB['latitude']), 2) + pow(abs($pointA['longitude'] - $pointB['longitude']), 2) 
       ); 

       return $this->convertDistance($distance, $unit); 
    } 

```

现在我们的算法准备好了，我们可以将其添加到我们的`getDistance`函数中，如下所示：

```php
    public function getDistance($pointA, $pointB, $unit = 'km') 
    { 
      return $this->getEuclideanDistance($pointA, $pointB, $unit); 
    } 

```

此时，你已经准备好了一切，可以开始测试了。进入位置容器，在`/var/www/html`中运行 PHPUnit。这是我们的第一次尝试；PHPUnit 的结果将是失败，应用程序的输出将告诉你问题所在。在我们的情况下，失败的主要原因是我们使用的算法对我们的应用程序来说不够准确。我们不能部署这个版本的应用程序，因为它未通过测试，我们必须更改我们的测试或实现测试的代码。

正如我们之前提到的，有多种计算两点之间距离的方法，每种方法都可能更或者更少准确。我们尝试的第一个实现失败了，因为它用于平面，而我们的世界是一个球体。

再次打开你的`LocationController`，并使用 haversine 计算创建一个新的距离实现：

```php
    public function getHaversineDistance($pointA, $pointB, $unit = 'km') 
    { 
      $distance = rad2deg( 
           acos( 
               (sin(deg2rad($pointA['latitude'])) * 
               sin(deg2rad($pointB['latitude']))) + 
               (cos(deg2rad($pointA['latitude'])) * 
               cos(deg2rad($pointB['latitude'])) * 
               cos(deg2rad($pointA['longitude'] - 
               $pointB['longitude']))) 
           ) 
       ) * 60; 

      return $this->convertDistance($distance, $unit); 
    } 

```

如你所见，这个距离计算函数稍微复杂一些，考虑了我们世界的球形形式。更改`getDistance`函数以使用我们的新算法：

```php
    return $this->getHaversineDistance($pointA, $pointB, $unit); 

```

现在再次运行 PHPUnit，一切应该没问题；测试将通过，我们的代码已经准备好投入生产。

使用单元测试和 TDD，流程总是一样的：

1.  创建测试。

1.  让你的代码通过测试。

1.  运行测试，如果测试失败，从第 2 步重新开始。

我们想要在我们的位置微服务中拥有的另一个功能是获取我们当前位置附近最近的秘密。打开`LocationControllerTest`文件并添加以下代码：

```php
    public function testClosestSecrets() 
    { 
      $currentLocation = [ 
           'latitude'  => 40.730610, 
           'longitude' => -73.935242 
      ]; 

      $location = new App\Http\Controllers\LocationController(); 

      $closestSecrets = $location->getClosestSecrets($currentLocation); 
      $this->assertClassHasStaticAttribute('conversionRates', 
      App\Http\Controllers\LocationController::class); 
      $this->assertContainsOnly('array', $closestSecrets); 
      $this->assertCount(3, $closestSecrets); 

       // Checking the first element 
       $currentElement = array_shift($closestSecrets); 
       $this->assertArraySubset(['name' => 'amber'], $currentElement); 

       // Second 
       $currentElement = array_shift($closestSecrets); 
       $this->assertArraySubset(['name' => 'ruby'], $currentElement); 

       // Third 
       $currentElement = array_shift($closestSecrets); 
       $this->assertArraySubset(['name' => 'diamond'], $currentElement); 
    } 

```

在上述代码片段中，我们定义了我们的当前位置（纽约），并要求我们的实现给我们一个最近秘密的列表。我们的位置实现将有一个秘密的缓存列表，我们知道它们的位置（这将帮助我们知道正确的顺序）。

打开`LocationController.php`，首先添加一个秘密的缓存列表。在现实世界中，我们没有硬编码的值，但对于测试目的来说，这已经足够了：

```php
    public static $cacheSecrets = [ 
       [ 
           'id' => 100, 
           'name' => 'amber', 
           'location' => ['latitude'  => 42.8805, 'longitude' => -8.54569, 
           'name'      => 'Santiago de Compostela'] 
       ], 
       [ 
           'id' => 100, 
           'name' => 'diamond', 
           'location' => ['latitude'  => 38.2622, 'longitude' => -0.70107,
           'name'      => 'Elche'] 
       ], 
       [ 
           'id' => 100, 
           'name' => 'pearl', 
           'location' => ['latitude'  => 41.8919, 'longitude' => 12.5113, 
           'name'      => 'Rome'] 
       ], 
       [ 
           'id' => 100, 
           'name' => 'ruby', 
           'location' => ['latitude'  => 53.4106, 'longitude' => -2.9779, 
           'name'      => 'Liverpool'] 
       ], 
       [ 
           'id' => 100, 
           'name' => 'sapphire', 
           'location' => ['latitude'  => 50.08804, 'longitude' => 14.42076, 
           'name'      => 'Prague'] 
       ], 
    ]; 

```

一旦我们准备好秘密列表，我们可以添加我们的`getClosestSecrets`函数如下：

```php
    public function getClosestSecrets($originPoint) 
    { 
      $closestSecrets    = [];
      $preprocessClosure = function($item) use($originPoint) { 
        return $this->getDistance($item['location'], $originPoint); 
      };  

       $distances = array_map($preprocessClosure, self::$cacheSecrets); 

       asort($distances); 

       $distances = array_slice($distances, 0, 
         self::MAX_CLOSEST_SECRETS, true); 

       foreach ($distances as $key => $distance) { 
         $closestSecrets[] = self::$cacheSecrets[$key]; 
       } 

       return $closestSecrets; 
    } 

```

在这段代码中，我们使用我们的缓存秘密列表来计算原点与我们每个秘密点之间的距离。一旦我们有了距离，我们就对结果进行排序并返回最接近的三个。

在我们的位置容器中运行 PHPUnit 将显示所有测试都已通过，这让我们有信心将代码部署到生产环境。

未来的提交可能会对距离计算或最接近功能进行更改，并且可能会破坏我们的测试。幸运的是，有一个单元测试覆盖它们，PHPUnit 会发出警报，因此您可以开始重新思考代码实现。

让您的想象力飞翔，并测试一切--从简单和小的情况到您能想象到的任何奇怪和模糊的情况。想法是您的应用程序将会崩溃，并且会非常严重，在半夜或者在您度假期间。除了尽可能添加尽可能多的测试以确保您在生产中的发布足够稳定以减少破坏风险之外，您无能为力。

## Behat

Behat 是一个开源的行为驱动开发框架。所有 Behat 测试都是用简单的英语编写，并包装成可读的场景。该框架使用 Gherkin 语法，受到了 Ruby 工具 Cucumber 的启发。Behat 的主要优势在于，大多数测试场景都可以被任何人理解。

### 安装

使用 Composer 可以轻松安装 Behat。您只需要编辑每个微服务的`composer.json`，并添加一行新的`"behat/behat" : "3.*"`。您的`require-dev`定义将如下所示：

```php
    "require-dev": { 
      "fzaninotto/faker": "~1.4", 
      "phpunit/phpunit": "~4.0", 
      "behat/behat": "3.*" 
    }, 

```

一旦您更新了`dev`要求，您需要进入每个 PHP-FPM 容器并运行 Composer：

```php
**# cd /var/www/html && composer update**

```

### 测试执行

运行 Behat 就像运行 PHPUnit 一样简单。您只需要进入 PHP-FPM 容器，转到`/var/www/html`文件夹，并运行以下命令：

```php
**# vendor/bin/behat**

```

### 从头开始的 Behat 示例

我们微服务应用程序的关键功能之一是查找秘密。用户应该能够保存这些秘密，为此，他们需要一个钱包。因此，让我们在用户微服务中编写我们的用户故事：

```php
Feature: Secrets wallet 
 In order to play the game 
 As a user 
 I need to be able to put found secrets into a wallet 

 Scenario: Finding a single secret 
    Given there is an "amber" 
    When I add the "amber" to the wallet 
    Then I should have 1 secret in the wallet 

 Scenario: Finding two secrets 
    Given there is an "amber" 
    And there is a "diamond" 
    When I add the "amber" to the wallet 
    And I add the "diamond" to the wallet 
    Then I should have 2 secrets in the wallet 

```

正如你所看到的，该测试可以被项目中的任何人理解，从开发人员到利益相关者。每个测试场景总是具有相同的格式：

```php
Scenario: Some description of the scenario 
 Given some context 
 When some event 
 Then the outcome 

```

您可以向上述基本模板添加一些修饰词（and 或 but）以增强场景描述。在这一点上，您的场景准备就绪后，可以将其保存为`features/wallet.feature`文件。

第一次在项目中开始编写 Behat 测试时，您需要使用以下命令初始化套件：

```php
**# vendor/bin/behat --init**

```

上述命令将创建 Behat 运行场景测试所需的文件。我们将使用的主要文件是`features/bootstrap/FeatureContext.php`；这个文件将成为我们的测试环境。

一旦我们的`FeatureContext`文件就位，就该开始创建我们的场景步骤了。例如，将以下方法放入您的`FeatureContext`中：

```php
    /** 
    * @Given there is a(n) :arg1 
    */ 
    public function thereIsA($arg1) 
    { 
       throw new PendingException(); 
    } 

```

### 提示

Behat 使用文档块来定义步骤、步骤转换和钩子。

在上述代码片段中，我们告诉 Behat，`thereIsA()`函数匹配每个`Given there is a(n)`步骤。在我们的示例中，该定义将匹配以下情况中的步骤：

+   假设有一块琥珀

+   有一颗钻石

我们需要映射每个场景步骤，以便我们的`FeatureContext`最终如下：

```php
    <?php 

     use Behat\Behat\Context\Context; 
     use Behat\Behat\Tester\Exception\PendingException; 
     use Behat\Gherkin\Node\PyStringNode; 
     use Behat\Gherkin\Node\TableNode; 

    /** 
    * Defines application features from the specific context. 
    */ 
    class FeatureContext implements Context 
    { 
      private $secretsCache; 
      private $wallet; 

      public function __construct() 
      { 
        $this->secretsCache = new SecretsCache(); 
        $this->wallet = new Wallet($this->secretsCache); 
      } 

      /** 
      * @Given there is a(n) :secret 
      */ 
      public function thereIsA($secret) 
      { 
        $this->secretsCache->setSecret($secret); 
      } 

      /** 
      * @When I add the :secret to the wallet 
      */ 
      public function iAddTheToTheWallet($secret) 
      { 
        $this->wallet->addSecret($secret); 
      } 

      /** 
      * @Then I should have :count secret(s) in the wallet 
      */ 
      public function iShouldHaveSecretInTheWallet($count) 
      { 
         PHPUnit_Framework_Assert::assertCount( 
           intval($count), 
           $this->wallet 
         ); 
      } 
    } 

```

我们的测试使用需要定义的外部类。这些类实现了我们的逻辑，并且例如故意创建了`features/bootstrap/SecretsCache.php`，其中包含以下内容：

```php
    <?php 
    final class SecretsCache 
    { 
      private $secretsMap = []; 

      public function setSecret($secret) 
      { 
         $this->secretsMap[$secret] = $secret; 
      } 

      public function getSecret($secret) 
      { 
        return $this->secretsMap[$secret]; 
      } 
    } 

```

您还需要创建`features/bootstrap/Wallet.php`，其中包含以下示例代码：

```php
    <?php 
    final class Wallet implements \Countable 
    { 
      private $secretsCache; 
      private $secrets; 

      public function __construct(SecretsCache $secretsCache) 
      { 
        $this->secretsCache = $secretsCache; 
      } 

      public function addSecret($secret) 
      { 
        $this->secrets[] = $secret; 
      } 

      public function count() 
      { 
        return count($this->secrets); 
      } 
    } 

```

前两个类是我们测试的实现，正如你所看到的，它们具有在钱包中存储秘密的逻辑。现在，如果你在控制台上运行 `vendor/bin/behat`，这个工具将检查所有我们的测试场景，并让我们确信我们的代码将按我们想要的方式运行。

这是使用 Behat 测试应用程序的一个简单示例。在我们的 GitHub 存储库中，你可以找到更具体的示例。另外，随时探索 Behat 生态系统；你可以找到多个工具和扩展，可以帮助你测试你的应用程序。

## Selenium

Selenium 是一套用于自动化多平台上的 Web 浏览器的工具，并且可以作为浏览器扩展使用，或者可以安装在服务器上来运行我们的浏览器测试。Selenium 的主要优势在于你可以轻松地记录完整的用户旅程并从记录中创建测试。这个测试可以稍后添加到你的流水线中，以便在每次提交时执行，以发现回归。

### Selenium WebDriver

WebDriver 是你可以用来从其他工具运行浏览器测试的 API。它是一个强大的测试环境，通常放置在专用服务器上，等待运行浏览器测试。

### Selenium IDE

Selenium IDE 是一个 Firefox 扩展，允许你记录、编辑和调试浏览器测试。这个插件不仅是一个录制工具，还是一个带有自动完成功能的完整 IDE。你甚至可以使用 IDE 记录和创建测试，然后用 WebDriver 稍后运行它们。

大多数情况下，Selenium 被用作补充测试工具，从另一个测试框架执行。例如，你可以通过 Mink 项目（[`mink.behat.org/en/latest/`](http://mink.behat.org/en/latest/)）来改进你的 Behat 测试。这个项目是不同浏览器驱动程序的包装器，所以你可以在 BDD 工作流中使用它们。

我们将在第七章 *Security*中讨论我们应用程序的部署。我们将学习如何自动化所有这些测试，并将它们集成到我们的 CI/CD 工作流中。

# 总结

在本章中，你学习了在应用程序中使用测试的重要性，诸如 Behat 和 Selenium 之类的工具，以及关于实现驱动开发。在下一章中，你将学习错误处理、依赖管理和微服务框架。


# 第五章：微服务开发

在最后几章中，我们解释了如何安装 Docker、Composer 和 Lumen，这对每个微服务都是必要的。在本章中，我们将开发*查找秘密*应用程序的一些部分。

在本章中，我们将开发一些更关键的部分，例如路由、中间件、与数据库的连接、队列以及查找秘密应用程序的微服务之间的通信，这样您将能够在将来开发应用程序的其余部分。

我们的应用程序结构将包括以下四个微服务：

+   **User:** 管理注册和账户操作。它还负责存储和管理我们的秘密钱包。

+   **Secrets:** 在世界各地生成随机秘密，并允许我们获取有关每个秘密的信息。

+   **Location:** 检查最近的秘密和用户。

+   **Battle:** 管理用户之间的战斗。它还修改钱包以在战斗后添加和删除秘密。

# 依赖管理

依赖管理是一种方法论，允许您声明项目所需的库，并使其更容易安装或更新。PHP 最知名的工具称为**Composer**。在之前的章节中，我们对这个工具进行了简要概述。

对于我们的项目，我们将需要为每个微服务使用单个 Composer 设置。当我们安装 Lumen 时，Composer 为我们完成了工作并创建了配置文件，但现在我们将详细解释它是如何工作的。

一旦我们安装了 Docker 并且我们在 PHP-FPM 容器中，我们需要工作，就需要生成`composer.json`文件。这是 Composer 的配置文件，我们在其中定义我们的项目和所有依赖项：

```php
    {
      "name": "php-microservices/user",
      "description": "Finding Secrets, User microservice",
      "keywords": ["finding secrets", "user", "microservice", "Lumen" ],
      "license": "MIT",
      "type": "project",
      "require": {
        "php": ">=5.5.9",
        "laravel/lumen-framework": "5.2.*",
        "vlucas/phpdotenv": "~2.2"
      },
      "require-dev": {
        "fzaninotto/faker": "~1.4",
        "phpunit/phpunit": "~4.0",
        "behat/behat": "3.*"
      },
      "autoload": {
        "psr-4": {
            "App": "app/"
        }
      },
      "autoload-dev": {
        "classmap": [
            "tests/",
            "database/"
        ]
      }
    }
```

`composer.json`文件的前 6 行（名称、描述、关键字、许可证和类型）用于识别项目。如果您在任何存储库中分享项目，它将是公开的。

`"require"`部分定义了项目中需要的必需库以及每个库的版本。`"require-dev"`非常类似，但它们是需要在开发机器上安装的库（例如，任何测试库）。

`"autoload"`和`"autoload-dev"`定义了我们的类将如何加载以及要映射到项目的不同用途的文件夹。

创建了这个文件后，我们可以在我们的机器上执行以下命令：

```php
**composer install**

```

此时，Composer 将检查我们的设置，并下载所有必需的库，包括 Lumen。

还有其他工具，但它们没有被使用得那么多，也不够灵活。

# 路由

路由是应用程序入口点（请求）和执行逻辑的源代码中的特定类和方法之间的映射。例如，您可以在应用程序中定义`/users`路由和`Users`类中的`list()`方法之间的映射。一旦您放置了这个映射，一旦您的应用程序收到对`/users`路由的请求，它将执行`Users`类中`list()`方法中的所有逻辑。路由允许 API 消费者与您的应用程序进行交互。在微服务中，最常用的是 RESTful 约定，我们将遵循它。

+   **HTTP 方法**：

+   **GET:** 用于检索有关指定实体或实体集合的信息。数据量不重要；我们将使用 GET 来获取一个或多个结果，还可以使用过滤器来过滤结果。

+   **POST:** 用于在应用程序中输入信息。它还用于发送新信息以创建新事物或发送消息。

+   **PUT:** 用于更新已存储在应用程序中的整个实体。

+   **PATCH:** 用于部分更新已存储在应用程序中的实体。

+   **DELETE:** 用于从应用程序中删除实体。

Lumen 中的路由文件位于`app/Http/routes.php`，因此我们将为每个微服务有一个路由文件。对于`User`微服务，我们将有以下端点：

```php
    $app->group([
        'prefix' => 'api/v1',
        'namespace' => 'App\Http\Controllers'],
        function ($app) {
            $app->get('user', 'UserController@index');
            $app->get('user/{id}', 'UserController@get');
            $app->post('user', 'UserController@create');   
            $app->put('user/{id}', 'UserController@update');
            $app->delete('user/{id}', 'UserController@delete');
            $app->get('user/{id}/location', 
            'UserController@getCurrentLocation');
            $app->post('user/{id}/location/latitude/{latitude}
            /longitude/{longitude}', 
            'UserController@setCurrentLocation');
        }
    );
```

在前面的代码中，我们为`User`微服务定义了我们的路由。

在 Lumen 中，API 的版本可以在路由文件中通过包含'prefix'来指定。这个框架还允许我们为同一个微服务拥有不同的 API 版本，因此我们不需要修改现有的方法来在不同的版本中使用。

`'namespace'`为同一组中包含的所有方法定义了相同的命名空间。以下行定义了每个入口点：

```php
    $app->get('user/{id}', 'UserController@get');
```

例如，前面的方法包含在前缀为`'api/v1'`的组中；动词是 GET，入口点是`user/{id}`，因此可以通过执行 HTTP GET 调用`http://localhost:8080/api/v1/user/123`来检索。`UserController@get`参数定义了我们需要在哪里开发此调用的逻辑--在这种情况下，它在控制器`UserController`和名为`get`的方法中。

在 Lumen 中，存储所有控制器的标准文件夹是`app/Http/Controllers`，因此您只需要使用 IDE 创建`app/Http/Controllers/UserController.php`文件，并包含以下内容：

```php
    <?php
    namespace App\Http\Controllers;
    use Illuminate\Http\Request;
    class UserController extends Controller
    {
      public function index(Request $request)
      {
        return response()->json(['method' => 'index']);
      }
      public function get($id)
      {
        return response()->json(['method' => 'get', 'id' => $id]);
      }
      public function create(Request $request)
      {
        return response()->json(['method' => 'create']);
      }
      public function update(Request $request, $id)
      {
        return response()->json(['method' => 'update', 'id' => $id]);
      }
      public function delete($id)
      {
        return response()->json(['method' => 'delete', 'id' => $id]);
      }
      public function getCurrentLocation($id)
      {
        return response()->json(['method' => 'getCurrentLocation',
                                'id' => $id]);
      }
      public function setCurrentLocation(Request $request, $id,
                                         $latitude, $longitude)
      {
        return response()->json(['method' => 'setCurrentLocation',
                                 'id' => $id, 'latitude' => $latitude,
                                 'longitude' => $longitude]);
      }
    }
```

前面的代码定义了我们在`app/Http/routes.php`文件中指定的所有方法。例如，我们返回一个简单的 JSON 来测试每个路由是否正常工作。

### 提示

请记住，微服务之间通信使用的主要语言是 JSON，因此我们所有的响应都需要是 JSON 格式。

在 Lumen 中，返回 JSON 响应非常容易；您只需要使用响应实例的`json()`方法，如下所示：

```php
    return response()->json(['method' => 'update', 'id' => $id]);
```

如果我们`$id`变量中存储的值是`123`，则前面的句子将返回一个格式良好的 JSON 响应：

```php
    {
      "method" : "update",
      "id" : 123
    }
```

现在，我们已经为我们的`User`微服务做好了一切准备。

也许，您想知道在我们的容器环境中，`User`微服务的`get()`方法分配了什么 URI。找到它非常容易--只需打开`docker-compose.yml`文件，您就可以找到`microservice_user_nginx`容器的端口映射。我们设置的端口映射表明我们的本地主机 8084 端口将重定向请求到容器的 80 端口。总之，我们的 URI 将是`http://localhost:8084/api/v1/get/123`。

## Postman

我们基于微服务的应用程序将不会有前端部分；API Rest 的目标是创建可以被不同平台（Web、iOS 或 Android）调用的微服务，只需调用路由文件中可用的方法；因此，为了执行对我们微服务的调用，我们将使用 Postman。这是一个工具，允许您执行包括您需要的参数在内的不同调用。使用 Postman，可以保存方法以便将来使用。

您可以从[`www.getpostman.com`](https://www.getpostman.com)下载或安装 Postman，如下所示：

![Postman](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_05_01.jpg)

Postman 工具概述

正如您在前面的 Postman 工具截图中所看到的，它具有许多功能，比如保存请求或设置不同的环境；但是现在，我们只需要知道执行调用我们应用程序的基本功能，如下所示：

1.  设置动词--GET、POST、PUT、PATCH 或 DELETE。有些框架无法重现 PUT 或 PATCH 调用，因此您需要设置动词 POST，并包含一个键为`_method`值为 PUT 或 PATCH 的参数。

1.  设置请求 URL。这是我们应用程序的期望入口点。

1.  如果需要，添加更多参数--例如，用于过滤结果的参数。对于 POST 调用，Body 按钮将被启用，以便您可以在请求正文中发送参数，而不是在 URL 中发送。

1.  点击发送以执行调用。

1.  响应将显示状态代码和秒数。

## 中间件

正如我们在前面的章节中所解释的，中间件在基于微服务的应用程序中非常有用。让我们解释一下如何使用它们使用 Lumen。

Lumen 有一个目录用于放置所有的中间件，因此我们将在`User`微服务上创建一个中间件，以检查消费者是否具有提供的`API_KEY`以与我们的应用程序通信。

### 提示

为了识别我们的消费者，我们建议您使用`API_KEY`。这种做法将避免不受欢迎的消费者使用我们的应用程序。

假设我们向客户提供了一个值为`RSAy430_a3eGR`的`API_KEY`，并且在每个请求中都需要发送这个值。我们可以使用中间件来检查是否提供了这个`API_KEY`。创建一个名为`App\Http\Middleware\ApiKeyMiddleware.php`的文件，并将以下代码放入其中：

```php
    <?php
    namespace App\Http\Middleware;
    use Closure;

    class ApiKeyMiddleware
    {
      const API_KEY = 'RSAy430_a3eGR';
      public function handle($request, Closure $next)
      {
        if ($request->input('api_key') !== self::API_KEY) {
            die('API_KEY invalid');
        }
        return $next($request);
      }
    }
```

一旦我们创建了我们的中间件，我们必须将其添加到应用程序中。为此，请在`bootstrap/app.php`文件中包含以下行：

```php
    $app->middleware([App\Http\Middleware\ApiKeyMiddleware::class]);
    $app->routeMiddleware(['api_key' => App\Http\Middleware
    \ApiKeyMiddleware::class]);
```

现在，我们可以将中间件添加到`routes.php`文件中。它可以放在不同的地方；您可以将它放在单个请求中，甚至整个组中，如下所示：

```php
    $app->group([
        **'middleware' => 'api_key'**, 
        'prefix' => 'api/v1',
        'namespace' => 'App\Http\Controllers'],
        function($app) {
            $app->get('user', 'UserController@index');
            $app->get('user/{id}', 'UserController@get');
            $app->post('user', 'UserController@create');
```

在 Postman 上试试看；向`http://localhost:8084/api/v1/user`发出 HTTP POST 调用。您将看到一个消息，上面写着`API_KEY invalid`。现在做同样的调用，但添加一个名为`API_KEY`值为`RSAy430_a3eGR`的参数；请求通过中间件并到达函数。

# 实现微服务调用

既然我们知道如何发出调用，让我们创建一个更复杂的例子。我们将构建我们的战斗系统。如前几章所述，战斗是两名玩家之间为了从失败者那里获取秘密而进行的战斗。我们的战斗系统将由三轮组成，在每一轮中都会进行一次掷骰子；赢得大多数轮次的用户将成为赢家，并从失败者的钱包中获得一个秘密。

### 提示

我们建议使用一些测试开发实践（TDD、BDD 或 ATDD），正如我们之前解释的那样；您可以在前面的章节中看到一些例子。在本章中，我们不会再包含更多的测试。

在 Battle 微服务中，我们可以在`BattleController.php`文件中创建一个用于战斗的函数；让我们看一个有效的结构方法：

```php
    public function duel(Request $request) 
    {
        return response()->json([]);
    }
```

不要忘记在`routes.php`文件中添加端点，将 URI 链接到我们的方法：

```php
    $app->post('battle/duel', 'BattleController@duel');
```

在这一点上，Battle 微服务的`duel`方法将可用；用 Postman 试试看。

现在，我们将实现决斗。我们需要为骰子创建一个新的类。为了存储一个新的类，我们将在根目录下创建一个名为`Algorithm`的新文件夹，文件`Dice.php`将包含骰子方法：

```php
    <?php
    namespace App\Algorithm;
    class Dice
    {
        const TOTAL_ROUNDS   = 3;
        const MIN_DICE_VALUE = 1;
        const MAX_DICE_VALUE = 6;
        public function fight()
        {
            $totalRoundsWin = [
                'player1' => 0,
                'player2' => 0
            ];

            for ($i = 0; $i < self::TOTAL_ROUNDS; $i++) {
                $player1Result = rand(
                    self::MIN_DICE_VALUE,
                    self::MAX_DICE_VALUE
                );
                $player2Result = rand(
                    self::MIN_DICE_VALUE,
                    self::MAX_DICE_VALUE
                );
                $roundResult = ($player1Result <=> $player2Result);
                if ($roundResult === 1) {
                    $totalRoundsWin['player1'] = 
                    $totalRoundsWin['player1'] + 1;
                } else if ($roundResult === -1) {
                    $totalRoundsWin['player2'] = 
                    $totalRoundsWin['player2'] + 1;
                }
            }

            return $totalRoundsWin;
        }
    }
```

一旦我们开发了`Dice`类，我们将从`BattleController`中调用它，以查看谁赢得了战斗。首先要做的是在`BattleController.php`文件的顶部包含`Dice`类，然后我们可以创建一个我们将用于决斗的算法实例（这是一个很好的做法，以便在将来更改决斗系统；例如，如果我们想要使用基于能量点或卡牌游戏的决斗，我们只需要更改`Dice`类为新的类）。

`duel`函数将返回一个 JSON，其中包含战斗结果。请查看`BattleController.php`中包含的新突出显示的代码：

```php
    <?php
    namespace App\Http\Controllers;
    use Illuminate\Http\Request;
    **use App\Algorithm\Dice;**

    class BattleController extends Controller
    {
 **protected $battleAlgorithm = null;**
 **protected function setBattleAlgorithm()**
 **{**
 **$this->battleAlgorithm = new Dice();**
 **}**

        /** ... Code omitted ... **/

 **public function duel(Request $request)**
 **{**
 **$this->setBattleAlgorithm();**
**$duelResult = $this->battleAlgorithm->fight();** 
 **return response()->json(**
 **[**
 **'player1'     => $request->input('userA'),**
**                     'player2'     => $request->input('userB'),**
**                     'duelResults' => $duelResult**
**                 ]**
**            );**
 **}**
    }
```

试试使用 Postman；记住这是一个 HTTP POST 请求到 URI `http://localhost:8081/api/v1/battle/duel`（注意我们在 Docker 上设置了端口 8081 用于战斗微服务），并且需要发送参数`userA`和`userB`，其中包含您想要的用户名。如果一切正确，您应该会收到类似于这样的响应：

```php
    {
        "player1": "John",
        "player2": "Joe",
        "duelResults": {
            "player1": 2,
            "player2": 1
        }
    }
```

## 请求生命周期

请求生命周期是请求被返回给消费者作为响应之前的地图。了解这个过程是很有趣的，以避免在请求过程中出现问题。每个框架都有自己的请求方式，但它们都非常相似，并遵循一些像 Lumen 一样的基本步骤：

1.  每个请求都由`public/index.php`管理。它没有太多的代码，只是加载由 Composer 生成的自动加载程序定义，并从`bootstrap/app.php`创建应用程序的实例。

1.  请求被发送到 HTTP 内核，它定义了一些必要的事情，比如错误处理、日志记录、应用环境和其他在请求执行之前应该添加的必要任务。HTTP 内核还定义了请求在检索应用程序之前必须通过的中间件列表。

1.  一旦请求通过了 HTTP 内核并到达应用程序，它就会到达路由并尝试将其与正确的路由匹配。

1.  它执行控制器和对应路由的代码，并创建并返回一个响应对象。

1.  HTTP 头和响应对象内容被返回给客户端。

这只是请求-响应工作流程的一个基本示例；真实的过程更加复杂。你应该考虑到 HTTP 内核就像一个大黑匣子，它做了一些对开发者来说并不可见的事情，所以理解这个例子对本章来说已经足够了。

## 使用 Guzzle 进行微服务之间的通信

在微服务中最重要的事情之一是它们之间的通信。大多数情况下，单个微服务并没有消费者所请求的所有信息，因此微服务需要调用不同的微服务来获取所需的数据。

例如，遵循最后一个例子，对两个用户之间的决斗，如果我们想在同一个调用中提供有关战斗中包含的所有用户的信息，并且我们在 Battle 微服务中没有特定的方法来获取用户信息，我们可以从用户微服务中请求用户信息。为了实现这一点，我们可以使用 PHP 核心功能 cURL，或者使用一个包装 cURL 的外部库，提供一个更简单的接口，比如`GuzzleHttp`。

要在我们的项目中包含`GuzzleHttp`，我们只需要在 Battle 微服务的`composer.json`文件中添加以下行：

```php
    {
        // Code omitted
        "require": {
            "php": ">=5.5.9",
            "laravel/lumen-framework": "5.2.*",
            "vlucas/phpdotenv": "~2.2",
 **"guzzlehttp/guzzle": "~6.0"**
        },
        // Code omitted
    }
```

一旦我们保存了更改，我们可以进入我们的 PHP-FPM 容器并运行以下命令：

```php
**cd /var/www/html && compose update**

```

`GuzzleHttp`将被安装并准备在项目中使用。

为了从`User`微服务中获取用户信息，我们将构建一个方法，将信息提供给`Battle`微服务。目前，我们将把用户信息存储在数据库中，所以我们有一个数组来存储它。在`User`微服务的`app/Http/Controllers/UserController.php`中，我们将添加以下行：

```php
    <?php

    namespace App\Http\Controllers;
    use Illuminate\Http\Request;
    class UserController extends Controller
    {
        **protected $userCache = [**
            **1 => [**
 **'name' => 'John',**
 **'city' => 'Barcelona'**
 **],**
 **2 => [**
 **'name' => 'Joe',**
                **'city' => 'Paris'**
            **]**
        **];**

        /** ... Code omitted ... **/

        **public function get($id)**
        **{**
            **return response()->json(**
 **$this->userCache[$id]**
 **);**
        **}**

        /** ... Code omitted ... **/
    }
```

您可以通过在 Postman 上进行 GET 调用`http://localhost:8084/api/v1/user/2`来测试这种新方法；你应该会得到类似这样的东西：

```php
    {
        "name": "Joe",
        "city": "Paris"
    }
```

一旦我们知道获取用户信息的方法是有效的，我们将从`Battle`微服务中调用它。出于安全原因，Docker 上的每个容器都与其他容器隔离，除非您在`docker-composer.yml`文件的链接部分指定要连接。要这样做，使用以下方法：

+   停止 Docker 容器：

```php
 **docker-compose stop**

```

+   通过添加以下行来编辑`docker-compose.yml`文件：

```php
      microservice_battle_fpm:
          build: ./microservices/battle/php-fpm/
          volumes_from:
          - source_battle
          links:
              - autodiscovery
     **- microservice_user_nginx**
          expose:
              - 9000
          environment:
              - BACKEND=microservice-battle-nginx
              - CONSUL=autodiscovery
```

+   启动 Docker 容器：

```php
 **docker-compose start**

```

从现在开始，`Battle`微服务应该能够看到`User`微服务，所以让我们调用`User`微服务以获取来自 Battle 微服务的用户信息。为此，我们需要在`BattleController.php`文件中包含`GuzzleHttp\Client`，并在 duel 函数中创建一个 Guzzle 实例来使用它：

```php
    <?php
    namespace App\Http\Controllers;
    use Illuminate\Http\Request;
    use App\Algorithm\Dice;
    **use GuzzleHttp\Client;**

    class BattleController extends Controller
    {
        **const USER_ENDPOINT = 'http://microservice_user_nginx/api
        /v1/user/';**
        /** ... Code omitted ... **/

        public function duel(Request $request)
        {
            $this->setBattleAlgorithm();
            $duelResult = $this->battleAlgorithm->fight();
            **$client = new Client(['verify' => false]);**
**            $player1Data = $client->get(                          
            self::USER_ENDPOINT . $request->input('userA'));**
**            $player2Data = $client->get(                          
            self::USER_ENDPOINT . $request->input('userB'));**

            return response()->json(
                [
                    'player1' => **json_decode($player1Data->getBody())**,
                    'player2' => **json_decode($player2Data->getBody())**,
                    'duelResults' => $duelResult
                ]
            );
        }
    }
```

修改完成后，我们可以通过在 Postman 上执行与之前相同的调用来再次测试它--`http://localhost:8081/api/v1/battle/duel`（记得进行 HTTP POST 调用，并发送参数`userA`值为 1 和`userB`值为 2）。响应应该类似于这样（请注意，这次用户信息来自`User`微服务，尽管我们正在调用`Battle`微服务）：

```php
    {
        "player1": {
            "name": "John",
            "city": "Barcelona"
        },
        "player2": {
            "name": "Joe",
            "city": "Paris"
        },
        "duelResults": {
            "player1": 0,
            "player2": 3
        }
    }
```

# 数据库操作

在前几章中，我们解释了您可以为应用程序拥有单个或多个数据库。这是微服务的优势之一；当您意识到某个微服务负载过大时，您可以将数据库分成单个数据库用于特定的微服务，从而实现单个微服务的扩展。

对于我们的示例，我们将为 secrets 微服务创建一个单独的数据库。对于存储软件，我们决定使用**Percona**（一个 MySQL 分支），但请随意使用您喜欢的任何数据库。

在 Docker 中创建数据库容器非常简单。我们只需要编辑我们的`docker-compose.yml`文件，并将`microservice_secret_fpm`服务的链接部分更改为以下内容：

```php
    links:
        - autodiscovery
        - microservice_secret_database
```

在我们所做的更改中，我们告诉 Docker 现在我们的`microservice_secret_fpm`可以与我们的`microservice_secret_database`容器进行通信。让我们创建我们的数据库容器。要做到这一点，我们只需要在`docker-compose.yml`文件中定义服务，如下所示：

```php
    microservice_secret_database:
        build: ./microservices/secret/database/
        environment:
            - CONSUL=autodiscovery
            - MYSQL_ROOT_PASSWORD=mysecret
            - MYSQL_DATABASE=finding_secrets
            - MYSQL_USER=secret
            - MYSQL_PASSWORD=mysecret
        ports:
            - 6666:3306
```

在上述代码中，我们告诉应用程序 Docker 可以在哪里找到`Dockerfile`，我们在其中设置了一些环境变量，并且我们正在将我们机器的端口 6666 映射到容器上的默认 Percona 端口。关于 Docker 和 Percona 官方镜像的一个重要事项是，使用一些特殊的环境变量，容器将为您创建数据库和一些用户。

您可以在我们的 Docker GitHub 存储库中找到所有所需的文件，标签为`chapter-05-basic-database`。

现在我们的容器准备就绪，是时候设置我们的数据库了。Lumen 为我们提供了一个工具来进行迁移和管理迁移，因此我们可以知道我们的数据库是否是最新的，如果我们正在与团队合作。**迁移**是一个用于在我们的数据库中创建和回滚操作的脚本。

要在 Lumen 中进行迁移，首先需要进入您的 secrets PHP-FPM 容器。要做到这一点，您只需要打开终端并执行以下命令：

```php
**docker exec -it docker_microservice_secret_fpm_1 /bin/bash**

```

上述命令将在容器中创建一个交互式终端，并运行 bash 控制台，以便您可以开始输入命令。请确保您在项目根目录下：

```php
**cd /var/www/html**

```

一旦您在项目根目录下，您需要创建一个迁移；可以通过以下命令完成：

```php
**php artisan make:migration create_secrets_table**

```

上述命令将在`database/migrations/2016_11_09_200645_create_secrets_table.php`文件中创建一个空的迁移模板，如下所示：

```php
    <?php
    use Illuminate\Database\Schema\Blueprint;
    use Illuminate\Database\Migrations\Migration;
    class CreateSecretsTable extends Migration
    {
        public function up()
        {
        }
        public function down()
        {
        }
    }
```

上述代码片段是由 artisan 命令生成的示例。如您所见，迁移脚本中有两种方法。在`up()`方法中编写的所有内容都将在执行迁移时使用。在执行回滚时，`down()`方法中的所有内容将用于撤消您的更改。让我们用以下内容填充我们的迁移脚本：

```php
    <?php
    use Illuminate\Database\Schema\Blueprint;
    use Illuminate\Database\Migrations\Migration;
    class CreateSecretsTable extends Migration
    {
        public function up()
        {
            Schema::create(
                'secrets', 
                function (Blueprint $table) {
                    $table->increments('id');
                    $table->string('name', 255);
                    $table->double('latitude');
                    $table->double('longitude')
                        ->nullable();
                    $table->string('location_name', 255);
                    $table->timestamps();
                }
            );
        }
        public function down()
        {
            Schema::drop('secrets');
        }
    }
```

上述示例非常容易理解。在`up()`方法中，我们正在创建一个带有一些列的 secrets 表。这是创建表的一种快速简单的方法，类似于使用`CREATE TABLE` SQL 语句。我们的`down()`方法将撤消所有更改，而在我们的情况下，撤消更改的方法是从我们的数据库中删除 secrets 表。

现在，您可以通过以下命令从终端执行迁移：

```php
**php artisan migrate
Migrated: 2016_11_09_200645_create_secrets_table**

```

迁移命令将运行我们迁移脚本的`up()`方法并创建我们的 secrets 表。

如果您需要了解迁移脚本的执行状态，您可以执行`php artisan migrate:status`，输出将告诉您当前状态：

```php
    +------+----------------------------------------+
    | Ran? | Migration                              |
    +------+----------------------------------------+
    | Y     | 2016_11_09_200645_create_secrets_table |
    +------+----------------------------------------+
```

在这一点上，您可以连接到您的机器的 6666 端口，使用您喜欢的数据库客户端；我们的数据库已经准备好在我们的应用程序中使用。

现在想象一下，您需要对数据库所做的更改进行回滚；在 Lumen 中很容易做到，您只需要运行以下命令：

```php
**php artisan migrate:rollback**

```

一旦我们创建了表，我们可以通过在 Lumen 上进行种子或手动填充我们的表。我们建议您使用种子，因为这是一种轻松跟踪任何更改的方法。要填充我们的新表，我们只需要创建一个新文件`database/seeds/SecretsTableSeeder.php`，其中包含以下内容：

```php
    <?php
    use Illuminate\DatabaseSeeder;
    class SecretsTableSeeder extends Seeder
    {
        public function run()
        {
            DB::table('secrets')->delete();
            DB::table('secrets')->insert([
                [
                    'name' => 'amber', 
                    'latitude' => 42.8805, 
                    'longitude' => -8.54569, 
                    'location_name' => 'Santiago de Compostela'
                ],
                [
                    'name' => 'diamond', 
                    'latitude' => 38.2622, 
                    'longitude' => -0.70107,
                    'location_name' => 'Elche'
                ],
                [
                    'name' => 'pearl', 
                    'latitude' => 41.8919,
                    'longitude' => 2.5113, 
                    'location_name' => 'Rome'
                ],
                [
                    'name' => 'ruby', 
                    'latitude' => 53.4106, 
                    'longitude' => -2.9779, 
                    'location_name' => 'Liverpool'
                ],
                [
                    'name' => 'sapphire', 
                    'latitude' => 50.08804, 
                    'longitude' => 14.42076, 
                    'location_name' => 'Prague'
                ]
            ]);
        }
    }
```

在前面的类中，我们定义了一个`run()`方法，每当我们想要向数据库中填充一些数据时，它都会被执行。在我们的示例中，我们添加了我们在应用程序中硬编码的不同秘密。现在我们的`SecretsTableSeeder`类已经准备好了，我们需要编辑`database/seeds/DatabaseSeeder.php`，以调用我们的自定义 seeder。如果您更改`run()`方法以匹配以下代码片段，您的微服务将具有一些数据：

```php
    public function run()
    {
        $this->call('SecretsTableSeeder');
    }
```

一旦一切就绪，现在是执行 seeder 的时候了，所以再次进入 secrets PHP-FPM 容器，并运行以下命令：

```php
**php artisan db:seed**

```

### 提示

如果`artisan`抛出一个错误，告诉您找不到表，那是由于 composer 自动加载系统。执行`composer dump-autoload`将解决您的问题，然后您可以再次运行`artisan`命令而不会出现任何问题。

在这一点上，您将创建并填充了您的秘密表，其中包含一些示例记录。

在 Lumen 中使用数据库是开箱即用的，并使用 Eloquent 作为 ORM。

**对象关系映射**（**ORM**）是一种编程模型，它将数据库表转换为实体，使开发人员的工作更容易，使他们能够更快地进行基本查询并使用更少的代码。

我们建议在将来要将数据库迁移到不同系统时使用 ORM，以避免语法问题。正如您所知，SQL 语言之间有一些差异--例如，获取确定数量的行的方式：

```php
SELECT * FROM secrets LIMIT 10 //MySQL
SELECT TOP 10 * FROM secrets //SqlServer
SELECT * FROM secrets WHERE rownum<=10; //Oracle
```

因此，如果您使用 ORM，您不需要记住 SQL 语法，因为它抽象了开发人员与数据库操作的关系，开发人员只需要考虑开发。

以下是 ORM 的优势：

+   数据访问层中的安全性防御攻击

+   与数据库一起工作很容易和快速

+   您使用的数据库并不重要

在开发公共 API 时，建议使用 ORM，以避免安全问题，并使查询对团队的其他成员更容易和更清晰。

要设置您的 Lumen 项目与 Eloquent 一起工作，您只需要打开`bootstrap/app.php`文件，并取消注释以下行（大约在第 28 行附近）：

```php
    $app->withEloquent();
```

此外，您需要设置位于`.env.example`文件中的数据库参数，您可以在每个微服务的根文件夹中找到它。编辑文件完成后，您需要将其重命名为`.env`（从文件名中删除`.example`）：

```php
    DB_CONNECTION=mysql
    DB_HOST=microservice_secret_database
    DB_PORT=3306
    DB_DATABASE=finding_secrets
    DB_USERNAME=secret
    DB_PASSWORD=mysecret
```

正如您所看到的，我们在 Docker 中设置的数据库、用户名和密码在数据库操作部分的开始时已经设置好了。

为了使用我们的数据库，我们需要创建我们的模型，因为我们有一个`finding_secrets`数据库，所以在`app/Models/Secret.php`文件中拥有一个秘密模型是有意义的：

```php
    <?php
    namespace App\Model;
    use Illuminate\Database\Eloquent\Model;
    class Secret extends Model
    {
        protected $table    = 'secrets';
        protected $fillable = [
            'name', 
            'latitude', 
            'longitude',                            
            'location_name'
        ];
    }
```

上面的代码非常容易理解；我们只需要定义我们的模型类和数据库`$table`之间的关系以及`$fillable`字段的列表。这是您的模型所需的最少内容。

Fractal 是一个为我们的 RESTful API 提供演示和转换层的库。使用这个库将使我们的响应保持一致，美观和干净。要安装这个库，我们只需要打开我们的 PHP-FPM 容器的`composer.json`，将`"league/fractal": "⁰.14.0"`添加到所需元素的列表中，并执行`composer update`。

### 提示

安装 fractal 的另一种方法是在您的 PHP-FMP 终端上运行以下命令：`composer require league/fractal`。请注意，此命令将使用最新版本，可能与我们的示例不兼容。

现在安装了 fractal，现在是时候定义我们的秘密转换器了。您可以将转换器视为一种简单的方式，将模型转换为一个一致的响应。在您的 IDE 中创建`app/Transformers/SecretTransformer.php`文件，并插入以下内容：

```php
    <?php
    namespace App\Transformers;
    use App\Model\Secret;
    use League\Fractal\Transformer\Abstract;
    class SecretTransformer extends TransformerAbstract
    {
        public function transform(Secret $secret)
        {
            return [
                'id'        => $secret->id,
                'name'      => $secret->name,
                'location'  => [
                    'latitude'  => $secret->latitude,
                    'longitude' => $secret->longitude,
                    'name'      => $secret->location_name
                ]
            ];
        }
    }
```

从上述代码中可以看出，我们正在指定秘密模型的转换，因为我们希望所有位置都被分组，所以我们在位置密钥内添加了秘密的所有位置信息。将来，如果您需要添加新字段或修改结构，现在一切都在一个地方，将会让作为开发人员的生活变得轻松。

为了示例目的，我们将修改我们的 secrets 控制器的 index 方法，以使用 fractal 从数据库返回响应。打开您的`app/Http/Controllers/SecretController.php`并插入以下用法：

```php
    use App\Model\Secret;
    use App\Transformers\SecretTransformer;
    use League\Fractal\Manager;
    use League\Fractal\Resource\Collection;
```

现在，您需要更改`index()`如下：

```php
    public function index(
        Manager $fractal, 
        SecretTransformer $secretTransformer, 
        Request $request)
    {
        $records = Secret::all();
        $collection = new Collection(
            $records, 
            $secretTransformer
        );
        $data = $fractal->createData($collection)
            ->toArray();

        return response()->json($data);
    }
```

首先，我们在方法签名中添加了一些我们将需要的对象实例，由于 Lumen 内置了依赖注入，我们不需要做任何额外的工作。它们将准备好在我们的方法内使用。我们的方法定义了以下内容：

+   从数据库获取所有秘密记录

+   使用我们的转换器创建一个秘密集合

+   fractal 库从我们的集合创建一个数据数组

+   我们的控制器将我们转换后的集合作为 JSON 返回

如果您在 Postman 中尝试，响应将类似于这样：

```php
    {
        "data": [
            {
                "id": 1,
                "name": "amber",
                "location": {
                    "latitude": 42.8805,
                    "longitude": -8.54569,
                    "name": "Santiago de Compostela"
                }
            },

            /** Code omitted ** /
            {
                "id": 5,
                "name": "sapphire",
                "location": {
                    "latitude": 50.08804,
                    "longitude": 14.42076,
                    "name": "Prague"
                }
            }
        ]
    }
```

我们所有的记录现在以一致的方式从数据库返回，所有都在我们的`"data"`响应键内具有相同的结构。

# 错误处理

在接下来的部分中，我们将解释如何验证我们微服务中的输入数据以及如何处理可能的错误。过滤我们收到的请求非常重要，不仅是为了通知消费者请求无效，还要避免安全问题或我们不希望的参数。

## 验证

Lumen 有一个很棒的验证系统，所以我们不需要安装任何东西来验证我们的数据。请注意，以下验证规则可以放在`routes.php`或控制器内的每个函数中。我们将在函数内使用它以更清晰地使用。

要使用我们的数据库进行验证系统，我们需要对其进行配置。这非常简单；我们只需要在根目录中创建一个`config/database.php`文件（和文件夹），并插入以下代码：

```php
    <?php
    return [
        'default'     => 'mysql',
        'connections' => [
            'mysql' => [
                'driver'    => 'mysql',
                'host'      => env('DB_HOST'),
                'database'  => env('DB_DATABASE'),
                'username'  => env('DB_USERNAME'),
                'password'  => env('DB_PASSWORD'),
                'collation' => 'utf8_unicode_ci'
            ]
        ]
    ];
```

然后，您需要在`bootstrap/app.php`文件中添加数据库行：

```php
    $app->withFacades();
    $app->withEloquent();
    **$app->configure('database');**

```

完成此操作后，Lumen 验证系统已准备就绪。因此，让我们编写规则来验证创建`Secrets`微服务上的新秘密的 POST 方法：

```php
    public function create(Request $request)
    {
        **$this->validate(**
 **$request,**
 **[**
 **'name'          => 'required|string|unique:secrets,name',**
 **'latitude'      => 'required|numeric',**
**            'longitude'     => 'required|numeric',**
**            'location_name' => 'required|string'**
 **]**
**        );**

```

在上述代码中，我们确认参数应该通过规则。字段`'name'`是必需的；它是一个字符串，而且在`secrets`表中应该是唯一的。字段`'latitude'`和`'longitude'`是数字且也是必需的。此外，`'location_name'`字段也是必需的，它是一个字符串。

### 提示

在 Lumen 文档中（[`lumen.laravel.com/docs`](https://lumen.laravel.com/docs)），您可以查看所有可用的选项来验证您的输入。

您可以在 Postman 中尝试它；创建一个带有以下`application/json`参数的 POST 请求来检查插入失败（请注意，您也可以像表单数据键值一样发送它）：

```php
    {
        "name": "amber",
        "latitude":"1.23",
        "longitude":"-1.23",
        "location_name": "test"
    }
```

上述请求将尝试验证一个与之前记录相同名称的新密钥。根据我们的验证规则，我们不允许消费者创建具有相同名称的新密钥，因此我们的微服务将以`422`错误响应，并返回以下内容：

```php
    {
        "name": [
            "The name has already been taken."
        ]
    }
```

请注意，状态码（或错误码）对于通知您的消费者其请求发生了什么非常重要；如果一切正常，应该返回`200`状态码。Lumen 默认返回`200`状态码。

在第十一章*最佳实践和约定*中，我们将看到您可以在应用程序中使用的所有可用代码的完整列表。

一旦验证规则通过，我们应该将数据保存在数据库中。这在 Lumen 中非常简单，只需这样做：

```php
    $secret = Secret::create($request->all());
    if ($secret->save() === false) {
        // Manage Error
    }
```

完成后，我们将在数据库中获得我们的新记录。Lumen 提供了其他方法来创建其他任务，如填充、更新或删除。

## 管理异常

有必要知道，我们必须管理应用程序中发生的可能错误。为此，Lumen 为我们提供了可以使用的异常列表。

因此，现在我们将尝试在尝试调用另一个微服务时获得异常。为此，我们将从用户微服务调用密钥微服务。

请记住，出于安全原因，如果您没有将一个容器与另一个容器链接起来，它们就无法相互看到。编辑您的`docker-compose.yml`，并从`microservice_user_fpm`到`microservice_secret_nginx`添加链接，如下所示：

```php
    microservice_user_fpm:
        build: ./microservices/user/php-fpm/
        volumes_from:
            - source_user
        links:
            - autodiscovery
 **- microservice_secret_nginx**
        expose:
            - 9000
        environment:
            - BACKEND=microservice-user-nginx
            - CONSUL=autodiscovery
```

现在，您应该再次启动您的容器：

```php
**docker-compose start**

```

还要记住，我们需要像之前在`Battle`微服务和`User`微服务上一样安装`GuzzleHttp`，以便调用`Secret`微服务。

我们将在`User`微服务中创建一个新的函数，以显示`user`钱包中保存的秘密。

将此添加到`app/Http/routes.php`：

```php
    $app->get(
        'user/{id}/wallet', 
        'UserController@getWallet'
    );
```

然后，我们将创建一个从`user`钱包中获取秘密的方法--例如，看一下这个：

```php
    public function getWallet($id)
    {
        /* ... Code ommited ... */
        $client = new Client(['verify' => false]);
        try {
            $remoteCall = $client->get(
                'http://microservice_secret_nginx                                       /api/v1/secret/1');
        } catch (ConnectException $e) {
            /* ... Code ommited ... */
            throw $e;
        } catch (ServerException $e) {
            /* ... Code ommited ... */
        } catch (Exception $e) {
            /* ... Code ommited ... */
        }
          /* ... Code ommited ... */
    }
```

我们正在调用`Secret`微服务，但我们将修改 URI 以获得`ConnectException`，所以请修改它：

```php
    $remoteCall = $client->get(
        **'http://this_uri_is_not_going_to_work'
    **);
```

在 Postman 上试一试；您将收到一个`ConnectException`错误。

现在，再次正确设置 URI，并在密钥微服务端放入一些错误代码：

```php
    public function get($id)
    {
      this_function_does_not_exist();
    }
```

上述代码将为密钥微服务返回错误**500**；但我们是从`User`微服务调用它，所以现在我们将收到`ServerException`错误。

在 Lumen 中，通过捕获它们来处理所有异常的类是`Handler`类（位于`app/Exceptions/Handler.php`）。这个类有两个定义的方法：

+   `report()`: 这允许我们将异常发送到外部服务--例如，一个集中的日志系统。

+   `render()`: 这将我们的异常转换为 HTTP 响应。

我们将更新`render()`方法以返回自定义错误消息和错误码。想象一下，我们想捕获 Guzzle 的`ConnectException`并返回一个更友好和易于管理的错误。看一下以下代码：

```php
    /** Code omitted **/
    use SymfonyComponentHttpFoundationResponse;
    use GuzzleHttpExceptionConnectException;

    /** Code omitted **/

    public function render($request, Exception $e)
    {
        switch ($e) {
            case ($e instanceof ConnectException) :
                return response()->json(
                    [
                        'error' => 'connection_error',
                        'code'  => '123'
                    ],
                    Response::HTTP_SERVICE_UNAVAILABLE
                );
                break;
            default :
                return parent::render($request, $e);
               break;
        }   
    }
```

在这里，我们正在检测 Guzzle 的`ConnectException`并提供自定义的错误消息和代码。使用这种策略有助于我们知道哪里出了问题，并允许我们根据我们正在处理的错误采取行动。例如，我们可以将代码`123`分配给所有连接错误；因此，当我们检测到这个问题时，我们可以避免其他服务的级联故障或通知开发人员。

# 异步和队列

在微服务中，队列是帮助提高性能和减少执行时间的最重要的事情之一。

例如，如果您需要在客户完成应用程序的注册流程时向客户发送电子邮件，应用程序不需要立即发送它；它可以放入队列中，在服务器不太忙的时候几秒钟后发送。此外，它是异步的，因为客户不需要等待电子邮件。应用程序将显示消息*注册完成*，并且电子邮件将被放入队列并同时处理。

另一个例子是当您需要处理非常繁重的工作负载时，您可以有一台专用的硬件更好的机器来执行这些任务。

最著名的内存数据结构存储之一是**Redis**。您可以将其用作数据库、缓存层、消息代理，甚至作为队列存储。Redis 的关键点之一是它支持不同的结构类型，例如字符串、哈希、列表和有序集等。这个软件被设计成易于管理和具有高性能，因此它是 Web 行业的事实标准。

Redis 的主要用途之一是作为缓存存储。您可以永久存储数据，也可以添加过期时间，而无需担心何时需要删除数据；Redis 会为您完成。由于易用性、良好的支持和可用的库，Redis 适用于任何规模的项目。

我们将在`User`微服务上构建一个示例，使用基于 Redis 的队列发送电子邮件。

Lumen 为我们提供了使用数据库的队列系统；但也有其他选项可用，可以使用外部服务。在我们的示例中，我们将使用 Redis，因此让我们看看如何在 Docker 上安装它。

打开`docker-compose.yml`并添加以下容器描述：

```php
    microservice_user_redis:
        build: ./microservices/user/redis/
        links:
            - autodiscovery
        expose:
            - 6379
        ports:
            - 6379:6379
```

您还需要更新`microservice_user_fpm`容器的链接部分以匹配以下内容：

```php
    links:
        - autodiscovery
        - microservice_secret_nginx
        - microservice_user_redis
```

在前面的代码片段中，我们为 Redis 定义了一个新的容器，并将其链接到`microservice_user_fpm`容器。现在打开`microservices/user/redis/Dockerfile`文件，并添加以下代码以使最新的 Redis 版本可用：

```php
    FROM redis:latest
```

要在我们的 Lumen 项目中使用 Redis，我们需要通过 composer 安装一些依赖项。因此，打开您的`composer.json`，并将以下行添加到所需部分，然后在用户 PHP-FPM 容器内执行 composer update：

```php
    "predis/predis": "~1.0",
    "illuminate/redis": "5.2.*"
```

对于电子邮件支持，您只需要将以下行添加到 composer.json 文件的 require 部分：

```php
    "illuminate/mail": "5.2.*"
```

安装完 Redis 后，我们需要设置环境。首先，我们需要在`.env`文件中添加以下行：

```php
    QUEUE_DRIVER=redis
    CACHE_REDIS_CONNECTION=default
    REDIS_HOST=microservice_user_redis
    REDIS_PORT=6379
    REDIS_DATABASE=0
```

现在，我们需要在`config/database.php`文件中添加 Redis 配置；如果您添加了其他数据库（例如 MySQL），请将其放在那之后，但在返回数组内部：

```php
    <?php
    return [
        'redis' => [
            'client'  => 'predis',
            'cluster' => false,
            'default' => [
                'host'     => env('REDIS_HOST', 'localhost'),
                'password' => env('REDIS_PASSWORD', null),
                'port'     => env('REDIS_PORT', 6379),
                'database' => env('REDIS_DATABASE', 0),
            ],
        ]
    ];
```

还需要将`vendor/laravel/lumen-framework/config/queue.php`文件复制到`config/queue.php`。

最后，不要忘记在`bootstrap/app.php`文件上注册所有内容，并添加以下行，这样我们的应用程序就能够读取我们刚刚设置的配置了：

```php
    $app->register(
        Illuminate\Redis\RedisServiceProvider::class
    );
    $app->configure('database');
    $app->configure('queue');
```

现在，我们将解释如何在我们的`User`微服务中构建一个队列。想象一下，在应用程序中，当创建新用户时，我们希望将第一个秘密作为礼物赠送给他们；因此，在用户创建之后，我们将调用秘密微服务以获取用户的第一个秘密。这不是一个优先级很高的任务，这就是为什么我们将使用队列来执行此任务的原因。

创建一个新文件`app/Jobs/GiftJob.php`，其中包含以下代码：

```php
    <?php
    namespace AppJobs;
    use GuzzleHttpClient;
    class GiftJob extends Job
    {
        public function __construct()
        {
        }

        public function handle()
        {
            $client = new Client(['verify' => false]);
            $remoteCall = $client->get(
                'http://microservice_secret_nginx                                                     /api/v1/secret/1'
            );
            /* Do stuff with the return from a remote service, for 
            example save it in the wallet */
        }
    }
```

您可以修改类构造函数以向作业传递数据，例如，包含所有用户信息的对象实例。

现在，我们需要从我们的`app/Http/Controllers/UserController.php`控制器实例化作业：

```php
**    use AppJobsGiftJob;**
    public function create(Request $request)
    {
        /* ... Code omitted (validate & save data) ... */
     **$this->dispatch(new GiftJob());**
        /* ... Code omitted ... */
    }
```

一旦队列任务完成，我们必须在后台启动队列工作程序。以下代码将为您完成这项工作，并且它将一直运行直到线程死亡，您可以添加一个监督程序来确保队列继续工作：

```php
    php artisan queue:work
```

您可以通过调用`http://localhost:8084/api/v1/user`在 Postman 上尝试一下。一旦您调用此方法，Lumen 将把工作放在 Redis 上，并且它将可供队列工作者使用。一旦工作者从 Redis 获取并处理任务，您将在终端中看到以下下一个消息：

```php
**    [2016-11-13 17:59:23] Processed: AppJobsGiftJob**

```

Lumen 为我们提供了更多的队列可能性。例如，您可以为队列设置优先级，为作业指定超时，甚至为任务设置延迟。您可以在 Lumen 文档中找到这些信息。

# 缓存

许多时候，消费者请求相同的内容，应用程序返回相同的信息。在这种情况下，缓存是避免不断处理相同请求并更快地返回所需数据的解决方案。

缓存用于不经常更改的数据，以便在不处理请求的情况下获得预先计算的响应。工作流程如下：

1.  消费者第一次请求某些信息时，应用程序会处理请求并获取所需的数据。

1.  它将请求所需的数据保存在缓存中，并设置我们定义的过期时间。

1.  它将数据返回给消费者。

下一次消费者请求某些内容时，您需要执行以下操作：

1.  检查请求是否在应用程序缓存中，并且尚未过期。

1.  返回缓存中的数据。

因此，在我们的示例中，我们将在位置微服务中使用缓存，以避免多次请求最接近的秘密。

我们应用程序中需要使用缓存层的第一件事是具有一个带有 Redis 的容器（您可以在其他地方找到其他缓存软件，但我们决定使用 Redis，因为它非常容易安装和使用）。打开`docker-compose.yml`文件，并添加新的容器定义，如下所示：

```php
    microservice_location_redis:
        build: ./microservices/location/redis/
        links:
            - autodiscovery
        expose:
            - 6379
        ports:
            - 6380:6379
```

一旦我们添加了容器，您需要更新`microservice_location_fpm`定义的链接部分，以连接到我们的新 Redis 容器，如下所示：

```php
    links:
        - autodiscovery
     **- microservice_location_redis**

```

在这种情况下，我们的`docker/microservices/location/redis/Dockerfile`文件将只包含以下内容（如果需要，可以随意向容器添加更多内容）：

```php
    FROM redis:latest
```

不要忘记执行`docker-compose stop`以成功终止所有容器，并使用`docker-compose up -d`再次启动它们以应用我们的更改。您可以通过在终端中执行`docker ps`来检查新容器是否正在运行。

现在是时候对我们的位置微服务源代码进行一些更改，以使用我们的新缓存层。我们需要做的第一个更改是在`composer.json`中；将以下所需的库添加到`"require"`部分：

```php
    "predis/predis": "~1.0",
    "illuminate/redis": "5.2.*"
```

一旦您对`composer.json`文件进行更改，请记得执行`composer update`以获取库。

现在，打开位置微服务的`.env`文件，添加 Redis 设置，如下所示：

```php
    CACHE_DRIVER=redis
    CACHE_REDIS_CONNECTION=default
    REDIS_HOST=microservice_location_redis
    REDIS_PORT=6379
    REDIS_DATABASE=0
```

由于我们的环境变量现在已设置好，我们需要创建`config/database.php`，内容如下：

```php
    <?php
    return [
        'redis' => [
            'client'  => 'predis',
            'cluster' => false,
            'default' => [
                'host'     => env('REDIS_HOST', 'localhost'),
                'password' => env('REDIS_PASSWORD', null),
                'port'     => env('REDIS_PORT', 6379),
                'database' => env('REDIS_DATABASE', 0),
            ],
        ]
    ];
```

在上述代码中，我们定义了如何连接到我们的 Redis 容器。

Lumen 没有缓存配置，因此您可以将`vendor/laravel/lumen-framework/config/cache.php`文件复制到`config/cache.php`中。

我们需要对`bootstrap/app.php`进行一些小的调整--取消注释`$app->withFacades();`并添加以下行：

```php
    $app->configure('database');
    $app->configure('cache');
    $app->register(
        Illuminate\Redis\RedisServiceProvider::class
    );
```

我们将更改我们的`getClosestSecrets()`方法，以使用缓存而不是每次计算最接近的秘密。打开`app/Http/Controllers/LocationController.php`文件，并添加缓存所需的使用：

```php
**use Illuminate\Support\FacadesCache;** 
        /* ... Omitted code ... */
    **const DEFAULT_CACHE_TIME = 1;**

    public function getClosestSecrets($originPoint)
    {
     **$cacheKey = 'L' . $originPoint['latitude'] .                   
        $originPoint['longitude'];**
        **$closestSecrets = Cache::remember(
            $cacheKey,
            self::DEFAULT_CACHE_TIME,
            function () use($originPoint) {**
                $calculatedClosestSecrets = [];
                $distances = array_map(
                    function($item) use($originPoint) {
                        return $this->getDistance(
                            $item['location'], 
                            $originPoint
                        );
                    }, 
                    self::$cacheSecrets
                );
                asort($distances);
                $distances = array_slice(
                    $distances, 
                    0,
                    self::MAX_CLOSEST_SECRETS, 
                    true
                );
                foreach ($distances as $key => $distance) {
                    $calculatedClosestSecrets[] = 
                    self::$cacheSecrets[$key];
                }

                return $calculatedClosestSecrets;
         **});**
 **return $closestSecrets;**
    }
    /* ... Omitted code ... */
```

在上述代码中，我们通过添加缓存层改变了方法的实现；因此，我们首先使用`remember()`检查我们的缓存，而不是总是计算最接近的点。如果缓存中没有返回任何内容，我们进行计算并存储结果。

在 Lumen 缓存中保存数据的另一个选项是使用`Cache::put('key', 'value', $expirationTime);`，其中`$expirationTime`可以是以分钟为单位的时间（整数）或日期对象。

### 提示

密钥由您定义，因此一个好的做法是生成一个您可以记住的密钥，以便将来重新生成。在我们的示例中，我们使用`L`（表示位置），然后是`纬度`和`经度`来定义密钥。然而，如果您要保存一个 ID，它应该作为密钥的一部分包含在内。

在 Lumen 中，与我们的缓存层一起工作很容易。

要从缓存中获取元素，可以使用`"get"`。它允许两个参数--第一个是指定您想要的密钥（必需的），第二个是在缓存中未存储密钥时要使用的值（显然是可选的）：

```php
    $value = Cache::get('key', 'default');
```

存储数据的类似方法是`Cache::forever($cacheKey, $cacheValue);`，这个调用将永久地将$cacheValue 存储在我们的缓存层中，直到您删除或更新它。

如果您没有为存储的元素指定过期时间，那么了解如何删除它们就很重要。在 Lumen 中，如果您知道分配给元素的$cacheKey，可以使用`Cache::forget($cacheKey);`来删除它。如果需要删除缓存中存储的所有元素，可以使用简单的`Cache::flush();`来实现。

# 总结

在本章中，您已经学会了如何开发基于微服务的应用程序的不同部分。现在，您已经具备了处理数据库存储、缓存、微服务之间的通信、队列以及从入口点到应用程序（路由）的请求工作流程以及数据验证的必要知识，直到将数据提供给消费者的时间。在下一章中，您将学习如何监控您的应用程序，以避免和解决应用程序执行过程中发生的问题。
