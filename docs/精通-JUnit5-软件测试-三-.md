# 精通 JUnit5 软件测试（三）

> 原文：[`zh.annas-archive.org/md5/6006963f247d852b0fdc6daf54c18ce5`](https://zh.annas-archive.org/md5/6006963f247d852b0fdc6daf54c18ce5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：从需求到测试用例

*程序测试可以用来显示错误的存在，但永远不能用来显示错误的不存在！- Edsger Dijkstra*

本章提供了一些知识基础，旨在帮助软件工程师编写有意义的测试用例。这个过程的起点是理解正在测试的系统的要求。没有这些信息，设计和实施有价值的测试是不可行的。在实际编写测试之前，可能会执行几个动作，即测试计划和测试设计。一旦我们开始测试编码过程，我们需要牢记一套编写正确代码的原则，以及一套要避免的反模式和坏味道。所有这些信息都以以下部分的形式在本章中提供：

+   **要求的重要性**：本节概述了软件开发过程，从提出需要由软件系统满足的一些需求开始，然后经过几个阶段，通常包括分析、设计、实施和测试。

+   **测试计划**：在软件项目开始时可以生成一个名为*测试计划*的文档。本节根据 IEEE 829 测试文档标准审查了测试计划的结构。正如我们将发现的那样，测试计划的完整陈述是一个非常细粒度的过程，特别适用于团队之间的沟通对项目成功至关重要的大型项目。

+   **测试设计**：在开始编写测试代码之前，考虑这些测试的蓝图总是一个好的做法。在本节中，我们回顾了设计我们的测试时需要考虑的主要方面。我们强调测试数据（预期结果），这些数据为测试断言提供支持。在这方面，我们回顾了一些黑盒数据生成技术（等价分区和边界分析）和白盒（测试覆盖）。

+   **软件测试原则**：本节提供了一组可以帮助我们编写测试的最佳实践。

+   **测试反模式**：最后，还审查了相反的一面：在编写我们的测试用例时要避免的模式和代码坏味道。

# 要求的重要性

软件系统是为满足一组消费者（最终用户或客户）的某种需求而构建的。理解这些需求是软件工程中最具挑战性的问题之一，因为消费者的需求通常是模糊的（特别是在项目的早期阶段）。此外，这些需求在项目的整个生命周期中也经常发生深刻的变化。弗雷德·布鲁克斯（Fred Brooks），一位著名的软件工程师和计算机科学家，在他的开创性著作《神话般的程序员月度（1975）》中定义了这个问题：

*构建软件系统中最困难的部分是准确决定要构建什么。概念工作中没有其他部分像确立详细的技术要求那样困难……如果做错了，没有其他部分会像这样严重地瘫痪最终的系统。后来纠正这一点也是最困难的。*

无论如何，消费者的需求都是任何软件项目的试金石。从这些需求中，可以得出一系列功能。我们将功能定义为软件系统功能的高级描述。从每个功能中，应该派生出一个或多个要求（功能性和非功能性）。要求是关于软件的一切，以满足消费者的期望。场景（真实生活的例子而不是抽象描述）对于为要求描述添加细节是有用的。软件系统的要求组和/或功能列表通常被称为规范。

在软件工程中，定义需求的阶段被称为需求引出。在这个阶段，软件工程师需要澄清他们试图解决的问题是什么。在这个阶段结束时，开始对系统进行建模是一种常见做法。为此，通常会使用建模语言（通常是 UML）来创建一组图表。UML 图表，通常适用于引出阶段的是用例图（系统功能的模型及其与涉及的参与者的关系）。

并不是所有的软件项目都会进行建模。例如，敏捷方法更多地基于素描原则，而不是正式的建模策略。

需求在分析阶段应该进行细化。在这个阶段，已经陈述的需求被分析，以解决不完整、模糊或矛盾的问题。因此，在这个阶段很可能会继续建模，例如使用高级类图，尚未与任何特定技术相关联。一旦分析清楚（也就是系统的“是什么”），我们需要找出“如何”来实现它。这个阶段被称为设计。在设计阶段，项目的指导方针应该被建立。为此，软件系统的架构通常是从需求中派生出来的。建模技术再次被广泛应用于设计的不同方面。在这一点上可以使用一系列 UML 图，包括结构图（组件、部署、对象、包和配置文件图）和行为图（活动、通信、序列或状态图）。从设计开始，实际的实现（即编码）可以开始了。

在设计阶段进行的建模量因不同因素而异，包括生产软件的公司类型和规模（跨国公司、中小企业、政府等）、开发过程（瀑布、螺旋、原型、敏捷等）、项目类型（企业、开源等）、软件类型（定制软件、商业现成软件等）甚至参与人员的背景（经验、职业等）。总的来说，设计需要被理解为软件工程师在项目中参与的不同角色之间的沟通方式。通常情况下，项目越大，基于不同建模图的细粒度设计就越必要。

关于测试，为了制定适当的测试计划（有关详细信息，请参见下一节），我们需要再次使用需求引出的数据，即需求和/或功能列表。换句话说，为了验证我们的系统，我们需要事先知道我们对它有什么期望。除了验证，进行一些验证也是可取的（根据 Boehm 的说法：我们是否在构建正确的产品？）。这是必要的，因为有时候规定的内容（功能和需求）与消费者的实际需求之间存在差距。因此，验证是一种高级别的评估方法，为了进行验证，最终消费者可以参与其中（在部署软件系统后验证软件系统）。所有这些想法都在下图中描述：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00136.jpeg)

软件工程通用开发过程

迄今为止，所提出的术语（沟通、需求引出、分析、设计、实施/测试和部署）没有通用的工作流程。在前面的图表中，它遵循线性流程，然而，在实践中，它可以遵循迭代、演进或并行的工作流程。

为了说明软件工程不同阶段可能涉及的潜在问题（分析、设计、实施等），值得回顾一下经典卡通《项目真正的运作方式》。这张图片的原始来源不详（有追溯到 1960 年代的版本）。2007 年，一个名为《项目卡通》的网站出现了（[`www.projectcartoon.com/`](http://www.projectcartoon.com/)），允许定制原始卡通的新场景。以下图表是该网站提供的卡通的 1.5 版本：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00137.jpeg)

项目的真正运作方式，版本 1.5（由[www.projectcartoon.com](http://www.projectcartoon.com)创建的插图）

如果我们思考这张图片，我们会发现问题的根源来自需求，客户在开始时解释得很糟糕，而项目负责人理解得更糟糕。从那时起，整个软件工程过程就变成了“传话游戏”。解决所有这些问题超出了本书的范围，但作为一个良好的开始，我们需要特别关注需求，它指导整个过程，当然也包括测试。

# 测试计划

测试路径的第一步可以是生成一个名为*测试计划*的文档，这是进行软件测试的蓝图。这份文件描述了测试工作的目标、范围、方法、重点和分配。准备这样的文件的过程是思考软件系统验证需求的一个有用方式。同样，当 SUT 的规模和涉及的团队很大时，这份文件尤其有用，因为不同角色的工作分离使得沟通成为项目成功的潜在障碍。

创建测试计划的一种方法是遵循 IEEE 829 测试文档标准。尽管这个标准对大多数软件项目来说可能太过正式，但值得审查这个标准提出的指南，并在我们的软件项目中使用需要的部分（如果有的话）。IEEE 829 提出的步骤如下：

1.  **分析产品**：这部分强调了从消费者需求中提取系统需求的理解。正如已经解释的那样，如果没有关于软件的信息，就不可能测试软件。

1.  **设计测试策略**：计划的这一部分包括几个部分，包括：

+   定义测试范围，即要测试的系统组件（在范围内）和不测试的部分（超出范围）。正如后面所解释的，全面的测试是不可行的，我们需要仔细选择要测试的内容。这不是一个简单的选择，它可以由不同的因素决定，例如精确的客户要求、项目预算和时间安排，以及涉及的软件工程师的技能。

+   确定测试类型，即应该进行哪些级别的测试（单元、集成、系统、验收）以及哪种测试策略（黑盒、白盒、非功能性）。

+   记录风险，即可能在项目中引起不同问题的潜在问题。

1.  **定义测试目标**：在计划的这一部分中，列出了要测试的功能列表，以及测试每个功能的目标。

1.  **定义测试标准**：这些标准通常由两部分组成，即：

+   暂停标准，例如在多少失败的测试中，新功能的开发将暂停，直到团队解决所有失败。

+   退出标准，例如应通过的关键测试的百分比，以便继续进行下一阶段的开发。

1.  **资源规划**：计划的这一部分致力于总结进行测试活动所需的资源。这可能是人员、设备或基础设施。

1.  **计划测试环境**：它由将要执行测试的软件和硬件设置组成。

1.  **日程安排和估算**：在这个阶段，经理们应该将整个项目分解为小任务，估算工作量（人月）。

1.  **确定测试交付物**：确定必须维护以支持测试活动的所有文档。

可以看出，测试计划是一个复杂的任务，通常由经理在大型项目中执行。在本章的其余部分，我们将继续探讨如何编写测试用例，但从最接近实际测试编码的角度来看。

# 测试设计

为了正确设计测试，我们需要具体定义需要实现的内容。为此，重要的是要记住测试的通用结构，已在第一章中解释过，*关于软件质量和 Java 测试的回顾*。因此，对于每个测试，我们需要定义：

+   测试装置是什么，也就是 SUT 中进行测试所需的状态？这是在测试的开始阶段称为设置。在测试结束时，测试装置可能在拆卸阶段被释放。

+   SUT 是什么，如果我们正在进行单元测试，它的 DOC(s)是什么？单元测试应该是独立的，因此我们需要为 DOC(s)定义测试替身（通常是模拟对象或间谍）。

+   断言是什么？这是测试的关键部分。没有断言，我们无法声称测试实际上已经完成。为了设计断言，值得回顾一下它的通用结构。简而言之，断言包括比较一些预期值（测试数据）和从 SUT 获得的实际结果。如果任何一个断言是负面的，测试将被宣布为失败（测试判决）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00138.jpeg)

测试用例和断言的一般模式

测试数据在测试过程中起着至关重要的作用。测试数据的来源通常被称为测试预言，通常可以从需求中提取。然而，还有一些其他常用的测试预言来源，例如：

+   产生预期输出的不同程序（反向关系）。

+   提供近似结果的启发式或统计预言。

+   基于人类专家经验的价值观。

此外，测试数据可以根据底层测试技术进行推导。当使用黑盒测试时，也就是说，使用一些输入来执行特定的基于需求的测试，并期望得到一些输出时，可以采用不同的技术，例如等价分区或边界分析。另一方面，如果我们使用白盒测试，结构将是我们测试的基础，因此测试覆盖率将是选择最大化这些覆盖率的测试输入的关键。在接下来的章节中，将对这些技术进行审查。

# 等价分区

等价分区（也称为等价类分区）是一种黑盒技术（即，它依赖于系统的需求），旨在减少应该针对 SUT 执行的测试数量。这项技术最早由 Glenford Myers 于 1978 年定义为：

“*将程序的输入域划分为有限数量的类[集合]的技术，然后确定一组精心选择的最小测试用例来代表这些类。*”

换句话说，等价类划分提供了一个标准来回答问题*我们需要多少测试*？*。其思想是将所有可能的输入测试数据（通常是大量的组合）划分为一组我们假定 SUT 以相同方式处理的值。我们称这些值的集合为等价类。其思想是测试等价类中的一个代表值就足够了，因为假定所有值都是以相同方式被 SUT 处理的。

通常，对于给定的 SUT，等价类可以分为两种类型：有效和无效的输入。等价类划分测试理论确保只需要一个每个分区的测试用例来评估程序对相关分区的行为（有效和无效类）。以下过程描述了如何系统地进行给定 SUT 的等价类划分：

1.  首先，我们确定 SUT 的所有可能有效输入的域。要找出这些值，我们依赖于规范（特性或功能需求）。我们假定 SUT 能够正确处理这些值（有效的等价类）。

1.  如果我们的规范规定等价类的某些元素被不同方式处理，它们应该分配到另一个等价类。

1.  这个域之外的值可以被视为另一个等价类，这次是无效输入。

1.  对于每个等价类，选择一个代表值。这个决定是一个启发式过程，通常基于测试人员的经验。

1.  对于每个测试输入，还选择适当的测试输出，有了这些值，我们就能完成我们的测试用例（测试练习和断言）。

# 边界分析

任何程序员都知道，错误经常出现在等价类的边界上（例如，数组的初始值，给定范围的最大值等）。边界值分析是一种方法，它通过查看测试输入的边界来补充等价类划分。它是由国家标准与技术研究所（NIST）在 1981 年定义的：

“*一种选择技术，其中测试数据被选择为位于输入域[或输出范围]类、数据结构和过程参数的‘边界’上*”。

总之，要在我们的测试中应用边界值分析，我们需要准确评估我们的 SUT 在等价类的边界上。因此，通常使用这种方法派生两个测试用例：等价类的上界和下界。

# 测试覆盖

测试覆盖是对 SUT 中为任何测试所执行的代码的比例。测试覆盖对于发现 SUT 中未经测试的部分非常有用。因此，它可以作为完美的白盒技术（结构性）来补充黑盒（功能性）。一般规定，80%或以上的测试覆盖率被认为是合理的。

有不同的 Java 库，可以简单地进行测试覆盖，例如：

+   Cobertura（[`cobertura.github.io/cobertura/`](http://cobertura.github.io/cobertura/)）：这是一个开源的报告工具，可以使用 Ant、Maven 或直接使用命令行执行。

+   EclEmma（[`www.eclemma.org/`](http://www.eclemma.org/)）：这是一个用于 Eclipse 的开源代码覆盖工具。从 Eclipse 4.7（Oxygen）开始，EclEmma 已经集成在 IDE 中。以下截图显示了 EclEmma 在 Eclipse 中如何突出显示 Java 类的代码覆盖率：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00139.jpeg)

Eclipse 4.7（Oxygen）中使用 EclEmma 进行测试覆盖

+   JaCoCo（[`www.jacoco.org/jacoco/`](http://www.jacoco.org/jacoco/)）：这是一个由 EclEmma 团队基于另一个名为 EMMA（[`emma.sourceforge.net/`](http://emma.sourceforge.net/)）的旧覆盖库创建的开源代码覆盖库。JaCoCo 可以作为 Maven 依赖使用。

+   Codecov ([`codecov.io/`](https://codecov.io/))：这是一个提供友好的代码覆盖率网络仪表板的云解决方案。对于开源项目来说是免费的。

# 软件测试原则

详尽测试是指一种测试方法，它使用所有可能的测试输入组合来验证软件系统。这种方法只适用于微小的软件系统或具有有限数量可能操作和允许数据的组件。在大多数软件系统中，验证每种可能的排列和输入组合是不可行的，因此详尽测试只是一种理论方法。

因此，有人说软件系统中的缺陷无法被证明。这是由计算机科学先驱 Edsger W. Dijkstra 所说的（见本章开头的引用）。因此，测试最多只是抽样，它必须在任何软件项目中进行，以减少系统故障的风险（参见第一章，*关于软件质量和 Java 测试的回顾*，回顾软件缺陷分类）。由于我们无法测试所有内容，我们需要进行适当的测试。在本节中，我们将回顾一系列编写有效和高效测试用例的最佳实践，即：

+   **测试应该简单**：编写测试的软件工程师（称之为测试人员、程序员、开发人员或其他）应该避免尝试测试自己的程序。在测试方面，对于问题“谁监视守夜人？”的正确答案应该是没有人。我们的测试逻辑应该足够简单，以避免任何形式的元测试，因为这将导致逻辑之外的递归问题。间接地，如果我们保持测试简单，我们还会获得另一个理想的特性：测试将更容易维护。

+   **不要实现简单的测试**：制作简单的测试是一回事，实现 getter 或 setter 等虚拟代码是另一回事。如前所述，测试最多只是抽样，我们不能浪费宝贵的时间评估我们代码库的这种部分。

+   **易于阅读**：第一步是为我们的测试方法提供一个有意义的名称。此外，由于 JUnit 5 的`@DisplayName`注解，我们可以提供丰富的文本描述，定义测试的目标，而不受 Java 命名约束的限制。

+   单一责任原则：这是计算机编程的一个通用原则，规定每个类应该负责单一功能。它与内聚性的度量密切相关。在编写测试时，实现这一原则非常重要：单个测试应该只涉及特定的系统需求。

+   **测试数据是关键**：如前所述，从 SUT 得到的预期结果是测试的核心部分。正确管理这些数据对于创建有效的测试至关重要。幸运的是，JUnit 5 提供了丰富的工具箱来处理测试数据（参见第四章，*使用高级 JUnit 功能简化测试*中的*参数化测试*一节）。

+   **单元测试应该执行得非常快**：对于单元测试持有的一个普遍接受的经验法则是，单元测试的持续时间最多应该是一秒。为了实现这一目标，还需要单元测试适当地隔离 SUT，正确地加倍其 DOCs。

+   **测试必须可重复**：缺陷应该被重现多次，以便开发人员找到错误的原因。这是理论，但不幸的是这并不总是适用。例如，在多线程 SUT（实时或服务器端软件系统）中，可能会发生竞争条件。在这些情况下，可能会出现非确定性的缺陷（通常称为*heisenbugs*）。

+   **我们应该测试正面和负面的情况**：这意味着我们需要编写测试，以评估预期结果的输入条件，但我们也需要验证程序不应该执行的操作。除了满足其要求，程序还必须经过测试，以避免不需要的副作用。

+   **测试不能仅仅为了覆盖率而进行**：仅仅因为代码的所有部分都被一些测试触及，我们不能保证这些部分已经得到了彻底的测试。要想成为真实，测试必须以降低风险的方式进行分析。

# 测试的心理学

从心理学角度来看，测试的目标应该是执行软件系统，以发现缺陷。理解这一主张的动机可以在我们测试的成功中产生巨大的差异。

人类往往是以目标为导向的。如果我们进行测试以证明程序没有错误，我们往往会选择测试数据，这些数据很少引起程序故障的可能性。另一方面，如果目标是证明程序存在错误，我们将增加发现错误的可能性，为程序增加更多的价值。因此，测试通常被认为是一个破坏性的过程，因为测试人员应该证明 SUT 存在错误。

此外，试图证明软件中存在错误是一个可行的目标，而试图证明它们的不存在，正如前面所解释的，是不可能的。再次，心理学研究告诉我们，当人们知道一个任务是不可行的时，他们的表现会很差。

# 测试反模式

在软件设计中，模式是解决重复问题的可重用解决方案。其中有很多，包括单例、工厂、构建器、外观、代理、装饰器或适配器等。反模式也是模式，但是不受欢迎的。关于测试，了解一些这些反模式是值得的，以避免它们在我们的测试中出现：

+   **二等公民**：测试代码包含大量重复的代码，使其难以维护。

+   **免费搭车**（也称为*搭便车*）：不是编写一个新的方法来验证另一个特性/要求，而是在现有的测试中添加一个新的断言。

+   **快乐路径**：只验证预期结果，而不测试边界和异常。

+   **当地英雄**：一个依赖于特定本地环境的测试。这种反模式可以用短语“在我的机器上可以运行”来概括。

+   **隐藏的依赖**：在测试运行之前需要一些现有数据填充的测试。

+   **链式测试**：必须按特定顺序运行的测试，例如，将 SUT 更改为下一个预期状态。

+   **嘲弄**：一个单元测试包含太多的测试替身，以至于 SUT 根本没有被测试，而是从测试替身中返回数据。

+   **无声接收器**：即使发生意外异常，测试也能通过的测试。

+   **检查员**：一种违反封装的测试，对 SUT 的任何重构都需要在测试中反映这些变化。

+   **过度设置**：需要大量设置才能开始执行阶段的测试。

+   **肛门探测器**：一种测试，必须使用不健康的方式来执行其任务，比如使用反射读取私有字段。

+   **没有名称的测试**：测试方法的名称没有清晰地指示正在测试什么（例如，在错误跟踪工具中的标识符）。

+   **慢吞吞**：持续时间超过几秒的单元测试。

+   **闪烁的测试**：测试中包含竞争条件，使其不时失败。

+   **等待观察**：一个需要等待特定时间（例如`Thread.sleep()`）才能验证某些预期行为的测试。

+   **不恰当的共享装置**：测试使用测试装置，甚至不需要设置/拆卸。

+   巨人：一个包含大量测试方法的测试类（上帝对象）。

+   湿地：创建持久数据的测试，但在完成时没有清理。

+   布谷鸟：一个单元测试在实际测试之前建立某种固定装置，但随后测试以某种方式丢弃了这个固定装置。

+   秘密捕手：一个测试没有进行任何断言，依赖于抛出异常并由测试框架报告为失败。

+   环境破坏者：一个测试需要使用给定的环境变量（例如，一个允许同时执行的自由端口号）。

+   分身：将被测试的代码部分复制到一个新的类中，以便测试可见。

+   母鸡：一个不仅仅满足测试需求的固定装置。

+   测试一切：不应该违反单一职责原则的测试。

+   线击手：一个没有对 SUT 进行任何真正验证的测试。

+   连体双胞胎：被称为“单元测试”但实际上是集成测试，因为 SUT 和 DOC 之间没有隔离。

+   说谎者：一个测试并不测试原本应该测试的内容。

# 代码异味

代码异味（在软件中称为“坏味道”）是源代码中不希望出现的症状。代码异味本身并不是问题，但它们可能表明附近存在某种问题。

如前所述，测试应该简单易读。因此，代码异味在任何情况下都不应该存在于我们的测试中。总的来说，通用的代码异味在我们的测试中可能会被避免。一些最常见的代码异味包括以下内容：

+   重复的代码：克隆的代码在软件中总是一个坏主意，因为它违反了“不要重复自己”的原则（DRY）。在测试中，这个问题甚至更糟，因为测试逻辑必须非常清晰。

+   高复杂度：太多的分支或循环可能被潜在地简化为更小的部分。

+   长方法：一个变得过于庞大的方法总是有问题的，当这个方法是一个测试时，这是一个非常糟糕的症状。

+   不合适的命名约定：变量、类和方法的名称应该简洁。使用非常长的标识符被认为是一种坏味道，但过度使用短（或无意义）的标识符也是如此。

# 总结

测试设计的起点应该是需求列表。如果这些需求尚未被正式引出，至少我们需要了解 SUT 功能，这反映了软件的需求。从这一点出发，可以采取几种策略。通常情况下，达到我们的目标没有唯一的路径，最终目标应该是降低项目的风险。

本章回顾了一个旨在创建有效和高效测试用例的过程。这个过程涉及需求分析、测试计划的定义、测试用例的设计，最后编写测试用例。我们应该意识到，尽管软件测试是技术任务，但它涉及一些重要的人类心理因素。软件工程师和测试人员应该了解这些因素，以便遵循最佳实践，并避免常见的错误。

在第七章“测试管理”中，我们将了解在一个活跃的软件项目中如何管理软件测试活动。首先，我们将回顾在常见的软件开发过程中（如瀑布、螺旋、迭代、敏捷或测试驱动开发）何时以及如何进行测试。然后，我们将审查旨在在 JUnit 5 的上下文中自动化软件开发过程的服务器端基础设施（如 Jenkins 或 Travis）。最后，我们将学习如何使用所谓的问题跟踪系统和测试报告库跟踪 Jupiter 测试发现的缺陷。


# 第七章：测试管理

重要的是不停地质疑。

*- 阿尔伯特·爱因斯坦*

这是本书的最后一章，其目标是指导如何理解软件测试活动在一个活跃的软件项目中是如何管理的。为了达到这个目的，本章分为以下几个部分：

+   **软件开发过程**：在本节中，我们研究了在不同方法论中何时执行测试：**行为驱动开发**（**BDD**）、**测试驱动开发**（**TDD**）、**先测试开发**（**TFD**）和**最后测试开发**（**TLD**）。

+   **持续集成**（**CI**）：在本节中，我们将了解持续集成，这是软件开发实践，其中构建、测试和集成的过程是持续进行的。这个过程的常见触发器通常是向源代码库（例如 GitHub）提交新更改（补丁）。此外，在本节中，我们将学习如何扩展持续集成，回顾持续交付和持续部署的概念。最后，我们介绍了目前两个最重要的构建服务器：Jenkins 和 Travis CI。

+   **测试报告**：在本节中，我们将首先了解 xUnit 框架通常报告测试执行的 XML 格式。这种格式的问题在于它不易阅读。因此，有一些工具可以将这个 XML 转换成更友好的格式，通常是 HTML。我们回顾了两种替代方案：Maven Surefire Report 和 Allure。

+   **缺陷跟踪系统**：在本节中，我们回顾了几个问题跟踪系统：JIRA、Bugzilla、Redmine、MantisBT 和 GitHub 问题。

+   **静态分析**：在本节中，一方面我们回顾了几种自动化分析工具（*linters*），如 Checkstyle、FindBugs、PMD 和 SonarQube。另一方面，我们描述了几种同行评审工具，如 Collaborator、Crucible、Gerrit 和 GitHub 拉取请求审查。

+   **将所有部分整合在一起**：为了结束本书，在最后一节中，我们展示了一个完整的示例应用程序，在这个应用程序中，使用了本书中介绍的一些主要概念进行了不同类型的测试（单元测试、集成测试和端到端测试）。

# 软件开发过程

在软件工程中，软件开发过程（也称为软件开发生命周期）是指用于创建软件系统所需的活动、行为和任务的工作流程。正如在第六章中介绍的，*从需求到测试用例*，任何软件开发过程中通常的阶段包括：

+   *what*的定义：需求获取、分析和用例建模。

+   *how*的定义：结构和行为图的系统架构和建模。

+   实际的软件开发（编码）。

+   使软件可供使用的一系列活动（发布、安装、激活等）。

在整个软件开发过程中设计和实施测试的时间安排导致了不同的测试方法论，即（见列表后的图表）：

+   **行为驱动开发**（**BDD**）：在分析阶段开始时，软件消费者（最终用户或客户）与开发团队的一些成员（通常是项目负责人、经理或分析师）进行了对话。这些对话用于具体化场景（即，具体示例以建立对系统功能的共同理解）。这些示例构成了使用工具（如 Cucumber）开发验收测试的基础（有关更多详细信息，请参阅第五章，*JUnit 5 与外部框架的集成*）。在 BDD 中描述验收测试（例如，在 Cucumber 中使用 Gherkin）产生了准确描述应用程序功能的自动化测试和文档。BDD 方法自然地与迭代或敏捷方法论对齐，因为很难事先定义需求，并且随着团队对项目的了解而不断发展。

术语*敏捷*是在 2001 年敏捷宣言的诞生时被推广的（[`agilemanifesto.org/`](http://agilemanifesto.org/)）。它是由 17 位软件从业者（Kent Beck、James Grenning、Robert C. Martin、Mike Beedle、Jim Highsmith、Steve Mellor、Arie van Bennekum、Andrew Hunt、Ken Schwaber、Alistair Cockburn、Ron Jeffries、Jeff Sutherland、Ward Cunningham、Jon Kern、Dave Thomas、Martin Fowler 和 Brian Marick）撰写的，并包括一系列 12 条原则，以指导迭代和以人为中心的软件开发过程。基于这些原则，出现了几种软件开发框架，如 SCRUM、看板或极限编程（XP）。

+   **测试驱动开发**（**TDD**）：TDD 是一种方法，其中测试在实际软件设计之前被设计和实施。其思想是将分析阶段获得的需求转化为具体的测试用例。然后，软件被设计和实施以通过这些测试。TDD 是 XP 方法的一部分。

+   **测试优先开发**（**TFD**）：在这种方法中，测试是在设计阶段之后但实际实施 SUT 之前实施的。这样可以确保在实际实施之前正确理解了软件单元。这种方法在统一过程中得到遵循，这是一种流行的迭代和增量软件开发过程。**统一过程**（**RUP**）是统一过程的一个知名框架实现。除了 TFD，RUP 还支持其他方法，如 TDD 和 TLD。

+   **测试后开发**（**TLD**）：在这种方法论中，测试的实施是在实际软件（SUT）的实施之后进行的。这种测试方法遵循经典的软件开发流程，如瀑布（顺序）、增量（多瀑布）或螺旋（风险导向的多瀑布）。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00140.jpeg)

软件开发过程中的测试方法

到目前为止，这些术语没有普遍接受的定义。这些概念不断发展和辩论，就像软件工程本身一样。请将其视为一个提议，适用于大量的软件项目。

关于谁负责编写测试，有一个普遍接受的共识。广泛建议 SUT 开发人员应编写单元测试。在某些情况下，特别是在小团队中，这些开发人员还负责其他类型的测试。

此外，独立测试组的角色（通常称为测试人员或 QA 团队）也是一种常见的做法，特别是在大型团队中。这种角色分离的目标之一是消除可能存在的利益冲突。我们不能忘记，从生理学角度来看，测试被理解为一种破坏性的活动（目标是发现缺陷）。这个独立的测试组通常负责集成、系统和非功能测试。在这种情况下，两组工程师应该密切合作；在进行测试时，开发人员应该随时准备纠正错误并尽量减少未来的错误。

最后，通常会在异构组中进行高级别的验收测试，包括非程序员（客户、业务分析、管理人员等）与软件工程师或测试人员（例如，在 Cucumber 中实现步骤定义）。

# 持续集成

CI 的概念最早是由 Grady Booch（美国软件工程师，与 Ivar Jacobson 和 James Rumbaugh 一起开发 UML 而闻名）于 1991 年首次提出的。**极限编程**（**XP**）方法采用了这个术语，使其非常流行。根据 Martin Fowler 的说法，CI 的定义如下：

*持续集成是一个软件开发实践，团队成员经常集成他们的工作，通常每个人至少每天集成一次 - 导致每天多次集成。每次集成都由自动构建（包括测试）进行验证，以尽快检测到集成错误。*

在 CI 系统中，我们可以识别出不同的部分。首先，我们需要一个源代码存储库，这是一个文件存档，用于托管软件项目的源代码，通常使用版本控制系统。如今，首选的版本控制系统是 Git（最初由 Linus Torvalds 开发），而不是较早的解决方案，如 CVS 或 SVN。在撰写本文时，领先的版本控制存储库是 GitHub（[`github.com/`](https://github.com/)），正如其名称所示，它是基于 Git 的。此外，还有其他选择，如 GitLab（[`gitlab.com`](https://gitlab.com)）、BitBucket（[`bitbucket.org/`](https://bitbucket.org/)）或 SourceForge（[`sourceforge.net/`](https://sourceforge.net/)）。后者曾经是领先的开发平台，但现在使用较少。

源代码存储库的副本与开发人员的本地环境同步。编码工作是针对这个本地副本进行的。开发人员应该每天提交新的更改（称为*补丁*）到远程存储库。频繁的提交可以避免由于对同一文件的相互修改而导致的冲突错误。

CI 的基本理念是每次提交都应该执行构建并测试带有新更改的软件。因此，我们需要一个自动化这个过程的服务器端基础设施。这个基础设施被称为构建服务器（或直接 CI 服务器）。目前最重要的两个构建服务器是 Jenkins 和 Travis CI。它们的详细信息将在下一小节中提供。作为构建过程的结果，构建服务器应该通知原始开发人员的处理结果。如果测试成功，补丁将合并到代码库中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00141.jpeg)

持续集成过程

靠近 CI，术语 DevOps 已经蓬勃发展。DevOps 来自*开发*和*运维*，它是一个强调项目软件中不同团队之间沟通和协作的软件开发过程的名称：开发（软件工程）、QA（**质量保证**）和运维（基础设施）。DevOps 这个术语也指的是一个工作职位，通常负责构建服务器的设置、监控和运行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00142.jpeg)

DevOps 处于开发、运维和 QA 之间

如下图所示，CI 的概念可以扩展到：

+   **持续交付**：当 CI 管道正确完成时，至少一个软件发布将部署到测试环境（例如，将 SNAPSHOT 工件部署到 Maven 存档器）。在此阶段，还可以执行验收测试。

+   **持续部署**：作为自动化工具链的最后一步，软件的发布可以发布到生产环境（例如，将 Web 应用程序部署到每个提交的生产服务器，以通过完整的管道）。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00143.jpeg)

持续集成、持续交付和持续部署链

# Jenkins

Jenkins ([`jenkins.io/`](https://jenkins.io/))是一个开源的构建服务器，支持构建、部署和自动化任何项目。Jenkins 是用 Java 开发的，可以通过其 Web 界面轻松管理。Jenkins 实例的全局配置包括关于 JDK、Git、Maven、Gradle、Ant 和 Docker 的信息。

Jenkins 最初是由 Sun Microsystems 于 2004 年开发的 Hudson 项目。在 Sun 被 Oracle 收购后，Hudson 项目被分叉为一个开源项目，并更名为 Jenkins。Hudson 和 Jenkins 这两个名字都是为了听起来像典型的英国男仆名字。其想法是它们帮助开发人员执行乏味的任务，就像一个乐于助人的男仆一样。

在 Jenkins 中，构建通常由版本控制系统中的新提交触发。此外，构建可以由其他机制启动，例如定期的 cron 任务，甚至可以通过 Jenkins 界面手动启动。

Jenkins 由于其插件架构而具有很高的可扩展性。由于这些插件，Jenkins 已经扩展到由大量第三方框架、库、系统等组成的丰富插件生态系统。这是由开源社区维护的。Jenkins 插件组合可在[`plugins.jenkins.io/`](https://plugins.jenkins.io/)上找到。

在 Jenkins 的核心，我们找到了作业的概念。作业是由 Jenkins 监控的可运行实体。如此屏幕截图所示，Jenkins 作业由四个组成：

+   **源代码管理**：这是源代码存储库（Git、SVN 等）的 URL

+   **构建触发器**：这是启动构建过程的机制，例如源代码存储库中的新更改、外部脚本、定期等。

+   **构建环境**：可选设置，例如在构建开始前删除工作空间，卡住时中止构建等。

+   **作业步骤的集合**：这些步骤可以使用 Maven、Gradle、Ant 或 shell 命令完成。之后，可以配置后构建操作，例如存档工件、发布 JUnit 测试报告（我们将在本章后面描述此功能）、电子邮件通知等。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00144.jpeg)

Jenkins 作业配置

配置作业的另一种有趣方式是使用 Jenkins *pipeline*，它是使用 Pipeline DSL（基于 Groovy 的特定领域语言）描述构建工作流程。Jenkins 管道描述通常存储在一个名为 Jenkinsfile 的文件中，该文件可以受源代码存储库的控制。简而言之，Jenkins 管道是由步骤组成的阶段的声明性链。例如：

```java
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'make'
            }
        }
        stage('Test') {
            steps {
                sh 'make check'
                junit 'reports/**/*.xml'
            }
        }
        stage('Deploy') {
            steps {
                sh 'make publish'
            }
        }
    }
}
```

# Travis CI

Travis CI ([`travis-ci.org/`](https://travis-ci.org/))是一个分布式构建服务器，用于构建和测试托管在 GitHub 上的软件项目。Travis 支持无需收费的开源项目。

Travis CI 的配置是使用名为*.travis.yaml*的文件完成的。该文件的内容使用不同的关键字进行结构化，包括：

+   `language`：项目语言，即 java、node_js、ruby、python 或 php 等（完整列表可在[`docs.travis-ci.com/user/languages/`](https://docs.travis-ci.com/user/languages/)上找到）。

+   `sudo`：如果需要超级用户权限（例如安装 Ubuntu 软件包）的标志值。

+   `dist`：可以在 Linux 环境（Ubuntu Precise 12.04 或 Ubuntu Trusty 14.04）上执行构建。

+   `addons`：apt-get 命令的基本操作的声明性快捷方式。

+   `install`：Travis 构建生命周期的第一部分，其中完成所需依赖项的安装。可以选择使用`before_install`来启动此部分。

+   `script`：构建的实际执行。此阶段可以选择由`before_script`和`after_script`包围。

+   `deploy`：最后，可以选择在此阶段进行构建的部署。此阶段有其自己的生命周期，由`before_deploy`和`after_deploy`控制。

YAML 是一种轻量级标记语言，由于其简约的语法，广泛用于配置文件。最初它被定义为 Yet Another Markup Language，但后来被重新定义为 YAML Ain't Markup Language，以区分其作为数据导向的目的。

```java
.travis.yaml:
```

```java
language: java
sudo: false
dist: trusty

addons:
    firefox: latest
    apt:
        packages:
            - google-chrome-stable
    sonarcloud:
        organization: "bonigarcia-github"
        token:
            secure: "encripted-token"

before_script:
    - export DISPLAY=:99.0
    - sh -e /etc/init.d/xvfb start &
    - sleep 3

script:
    - mvn test sonar:sonar
    - bash <(curl -s https://codecov.io/bash)
```

Travis CI 提供了一个 Web 仪表板，我们可以在其中检查使用 Travis CI 生成的当前和过去构建的状态，这些构建是在我们的 GitHub 帐户中使用 Travis CI 的项目中生成的：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00145.jpeg)

Travis CI 仪表板

# 测试报告

从其最初版本开始，JUnit 测试框架引入了一种 XML 文件格式来报告测试套件的执行情况。多年来，这种 XML 格式已成为报告测试结果的*事实*标准，在 xUnit 家族中广泛采用。

这些 XML 可以由不同的程序处理，以以人类友好的格式显示结果。这就是构建服务器所做的事情。例如，Jenkins 实现了一个名为`JUnitResultArchiver`的工具，它解析作业测试执行产生的 XML 文件为 HTML。

尽管这种 XML 格式已经变得普遍，但并没有普遍的正式定义。JUnit 测试执行器（例如 Maven，Gradle 等）通常使用自己的 XSD（XML 模式定义）。例如，在 Maven 中，这种 XML 报告的结构如下图所示。请注意，测试套件由一组属性和一组测试用例组成。每个测试用例可以声明为失败（具有某些断言失败的测试），跳过（忽略的测试）和错误（具有意外异常的测试）。如果测试套件的主体中没有出现这些状态中的任何一个，那么测试将被解释为成功。最后，对于每个测试用例，XML 还存储标准输出（*system-out*）和标准错误输出（*system-err*）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00146.jpeg)

Maven Surefire XML 报告的模式表示

`rerunFailure`是 Maven Surefire 为重试不稳定（间歇性）测试而实现的自定义状态（[`maven.apache.org/surefire/maven-surefire-plugin/examples/rerun-failing-tests.html`](http://maven.apache.org/surefire/maven-surefire-plugin/examples/rerun-failing-tests.html)）。

关于 JUnit 5，用于运行 Jupiter 测试的 Maven 和 Gradle 插件（分别为`maven-surefire-plugin`和`junit-platform-gradle-plugin`）遵循此 XML 格式编写测试执行结果。在接下来的部分中，我们将看到如何将此 XML 输出转换为人类可读的 HTML 报告。

# Maven Surefire 报告

默认情况下，`maven-surefire-plugin`生成来自测试套件执行的 XML 结果为`${basedir}/target/surefire-reports/TEST-*.xml`。可以使用插件`maven-surefire-report-plugin`轻松将此 XML 输出解析为 HTML。为此，我们只需要在`pom.xml`的报告子句中声明此插件，如下所示：

```java
<reporting>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-surefire-report-plugin</artifactId>
            <version>${maven-surefire-report-plugin.version}</version>
        </plugin>
    </plugins>
</reporting>
```

这样，当我们调用 Maven 生命周期以进行文档（`mvn site`）时，测试结果的 HTML 页面将包含在总体报告中。

查看报告的示例，使用 GitHub 存储库示例中的项目`junit5-reporting`（[`github.com/bonigarcia/mastering-junit5`](https://github.com/bonigarcia/mastering-junit5)）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00147.jpeg)

由 maven-surefire-report-plugin 生成的 HTML 报告

# Allure

Allure（[`allure.qatools.ru/`](http://allure.qatools.ru/)）是一个轻量级的开源框架，用于为不同的编程语言生成测试报告，包括 Java，Python，JavaScript，Ruby，Groovy，PHP，.NET 和 Scala。总的来说，Allure 使用 XML 测试输出并将其转换为 HTML5 丰富报告。

Allure 支持 JUnit 5 项目。这可以使用 Maven 和 Gradle 来完成。关于 Maven，我们需要在`maven-surefire-plugin`中注册一个监听器。这个监听器将是类 AllureJunit5（位于库`io.qameta.allure:allure-junit5`中），它基本上是 JUnit 5 的`TestExecutionListener`的实现。正如在第二章中所描述的，*JUnit 5 的新功能*，`TestExecutionListener`是 Launcher API 的一部分，用于接收有关测试执行的事件。总的来说，这个监听器允许 Allure 在生成 JUnit 平台时编译测试信息。这些信息由 Allure 存储为 JSON 文件。之后，我们可以使用插件`io.qameta.allure:allure-maven`从这些 JSON 文件生成 HTML5。命令是：

```java
mvn test
mvn allure:serve
```

我们的`pom.xml`的内容应包含以下内容：

```java
<dependencies>
    <dependency>
        <groupId>io.qameta.allure</groupId>
        <artifactId>allure-junit5</artifactId>
        <version>${allure-junit5.version}</version>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.junit.jupiter</groupId>
        <artifactId>junit-jupiter-api</artifactId>
        <version>${junit.jupiter.version}</version>
        <scope>test</scope>
    </dependency>
</dependencies>

<build>
    <plugins>
        <plugin>
            <artifactId>maven-surefire-plugin</artifactId>
            <version>${maven-surefire-plugin.version}</version>
            <configuration>
                <properties>
                    <property>
                        <name>listener</name>
                        <value>io.qameta.allure.junit5.AllureJunit5</value>
                    </property>
                </properties>
                <systemProperties>
                    <property>
                        <name>allure.results.directory</name>
                        <value>${project.build.directory}/allure-results</value>
                    </property>
                </systemProperties>
            </configuration>
            <dependencies>
                <dependency>
                    <groupId>org.junit.platform</groupId>
                    <artifactId>junit-platform-surefire-provider</artifactId>
                    <version>${junit.platform.version}</version>
                </dependency>
                <dependency>
                    <groupId>org.junit.jupiter</groupId>
                    <artifactId>junit-jupiter-engine</artifactId>
                    <version>${junit.jupiter.version}</version>
                </dependency>
            </dependencies>
        </plugin>
        <plugin>
            <groupId>io.qameta.allure</groupId>
            <artifactId>allure-maven</artifactId>
            <version>${allure-maven.version}</version>
        </plugin>
    </plugins>
</build>
```

使用 Gradle 也可以完成相同的过程，这次使用等效的插件`io.qameta.allure:allure-gradle`。总的来说，我们的`build.gradle`文件的内容应包含：

```java
buildscript {
    repositories {
        jcenter()
        mavenCentral()
    }
    dependencies {
        classpath("org.junit.platform:junit-platform-gradle-plugin:${junitPlatformVersion}")
        classpath("io.qameta.allure:allure-gradle:${allureGradleVersion}")
    }
}

apply plugin: 'io.qameta.allure'

dependencies {
    testCompile("org.junit.jupiter:junit-jupiter-api:${junitJupiterVersion}")
    testCompile("io.qameta.allure:allure-junit5:${allureJUnit5Version}")
    testRuntime("org.junit.jupiter:junit-jupiter-engine:${junitJupiterVersion}")
}
```

以下图片显示了使用上述步骤生成的 Allure 报告的几个屏幕截图（使用 Maven 或 Gradle 生成的最终结果相同）。该示例项目称为`junit5-allure`，通常托管在 GitHub 上。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00148.jpeg)

在 JUnit 5 项目中生成的 Allure 报告

# 缺陷跟踪系统

缺陷跟踪系统（也称为 bug 跟踪系统，bug 跟踪器或问题跟踪器）是一个软件系统，用于跟踪软件项目中报告的软件缺陷。这种系统的主要好处是提供开发管理，bug 报告甚至功能请求的集中概览。通常还会维护一个待处理项目列表，通常称为积压。

有许多可用的缺陷跟踪系统，既有专有的也有开源的。在本节中，我们简要介绍了几个最知名的系统：

+   **JIRA**（[`www.atlassian.com/software/jira`](https://www.atlassian.com/software/jira)）：这是由 Atlasian 创建的专有缺陷跟踪系统。除了错误和问题跟踪外，它还提供了管理功能，如 SCRUM 和 Kanban 板，用于查询问题的语言（JIRA 查询语言），与外部系统的集成（例如 GitHub，Bitbucket），以及通过 Atlasian Marketplace（[`marketplace.atlassian.com/`](https://marketplace.atlassian.com/)）的插件机制来扩展 JIRA 的插件。

+   **Bugzilla**（[`www.bugzilla.org/`](https://www.bugzilla.org/)）：这是由 Mozilla 基金会开发的开源基于 Web 的缺陷跟踪系统。在其功能中，我们可以找到用于改善性能和可伸缩性的数据库，用于搜索缺陷的查询机制，集成电子邮件功能以及用户角色管理。

+   **Redmine**（[`www.redmine.org/`](http://www.redmine.org/)）：这是一个开源的基于 Web 的缺陷跟踪系统。它提供了维基，论坛，时间跟踪，基于角色的访问控制，或者用于项目管理的甘特图。

+   **MantisBT**（[`www.mantisbt.org/`](https://www.mantisbt.org/)）：它是另一个开源的、基于 Web 的缺陷跟踪系统，旨在简单而有效。其中的特点包括事件驱动的插件系统，允许官方和第三方扩展，多通道通知系统（电子邮件、RSS 订阅、Twitter 插件等），或基于角色的访问控制。

+   **GitHub issues**（[`guides.github.com/features/issues/`](https://guides.github.com/features/issues/)）：它是集成在每个 GitHub 存储库中的跟踪系统。GitHub issues 的方法是提供一个通用的缺陷跟踪系统，用于任务调度、讨论，甚至使用 GitHub issues 进行功能请求。每个问题都可以使用可自定义的标签系统进行分类，参与者管理和通知。

# 静态分析

这本即将完成的书主要关注软件测试。毫不奇怪，JUnit 就是关于测试的。但正如我们在第一章中所看到的，*关于软件质量和 Java 测试的回顾*，尽管软件测试是**验证和验证**（**V&V**）中最常见的活动，但并不是唯一的类型。另一个重要的活动组是静态分析，在这种活动中没有执行软件测试。

可以将不同的活动归类为静态分析。其中，自动化软件分析是一种相当廉价的替代方案，可以帮助显著提高内部代码质量。在本章中，我们将回顾几种自动化软件分析工具，即**linters**：

+   **Checkstyle**（[`checkstyle.sourceforge.net/`](http://checkstyle.sourceforge.net/)）：它分析 Java 代码遵循不同的规则，如缺少 Javadoc 注释，使用魔术数字，变量和方法的命名约定，方法的参数长度和行长度，导入的使用，一些字符之间的空格，类构造的良好实践，或重复的代码。它可以作为 Eclipse 或 IntelliJ 插件等使用。

+   **FindBugs**（[`findbugs.sourceforge.net/`](http://findbugs.sourceforge.net/)）：它在 Java 代码中查找三种类型的错误：

+   正确性错误：明显的编码错误（例如，类定义了`equal(Object)`而不是`equals(Object)`）。

+   不良实践：违反推荐最佳实践（丢弃异常、滥用 finalize 等）。

+   可疑错误：混乱的代码或以导致错误的方式编写（例如，类`literal`从未被使用，switch 穿透，未经确认的类型转换和多余的空指针检查）。

+   **PMD**（[`pmd.github.io/`](https://pmd.github.io/)）：它是一个跨语言的静态代码分析器，包括 Java、JavaScript、C++、C#、Go、Groovy、Perl、PHP 等。它有许多插件，包括 Maven、Gradle、Eclipse、IntelliJ 和 Jenkins。

+   **SonarQube**（[`www.sonarqube.org/`](https://www.sonarqube.org/)）：它（以前只是 Sonar）是一个基于 Web 的、开源的持续质量评估仪表板。它支持多种语言，包括 Java、C/C++、Objective-C、C#等。提供重复代码、代码异味、代码覆盖率、复杂性和安全漏洞的报告。SonarQube 有一个名为**SonarCloud**（[`sonarcloud.io/`](https://sonarcloud.io/)）的分布式版本。它可以在开源项目中免费使用，通过在`.travis.yml`中进行几行配置，包括 SonarCloud 组织标识符和安全令牌，与 Travis CI 实现无缝集成。这些参数可以在将 SonarCloud 帐户与 GitHub 关联后，在 SonarCloud Web 管理面板中获取。

```java
addons:
    sonarcloud:
        organization: "bonigarcia-github"
        token:
            secure: "encrypted-token"
```

之后，我们只需要使用 Maven 或 Gradle 调用 SonarCloud：

```java
script:
    - mvn test sonar:sonar
```

```java
script:
    - gradle test sonarQube
```

下图显示了 SonarCloud 仪表板，用于上一章节中描述的示例应用程序“Rate my cat!”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00149.jpeg)

SonarCloud 报告应用程序“Rate my cat!”

在许多软件项目中广泛采用的另一种分析静态技术是**同行审查**。这种方法在时间和精力方面相当昂贵，但正确应用时，可以保持非常高水平的内部代码质量。如今有许多旨在简化软件代码库的同行审查过程的工具。其中，我们找到了以下工具：

+   **Collaborator**（[`smartbear.com/product/collaborator/`](https://smartbear.com/product/collaborator/)）：SmartBear 公司创建的同行代码（和文档）审查专有工具。

+   **Crucible**（[`www.atlassian.com/software/crucible`](https://www.atlassian.com/software/crucible)）：Atlassian 创建的企业产品的本地代码审查专有工具。

+   **Gerrit**（[`www.gerritcodereview.com/`](https://www.gerritcodereview.com/)）：基于 Web 的开源代码协作工具。可以通过 GerritHub（[`gerrithub.io/`](http://gerrithub.io/)）与 GitHub 存储库一起使用。

+   **GitHub 拉取请求审查**（[`help.github.com/articles/about-pull-request-reviews/`](https://help.github.com/articles/about-pull-request-reviews/)）：在 GitHub 中，拉取请求是向第三方存储库提交贡献的一种方法。作为 GitHub 提供的协作工具的一部分，拉取请求允许以简单和集成的方式进行审查和评论。

# 将所有部分整合在一起

在本书的最后一节中，我们将通过一个实际示例回顾本书涵盖的一些主要方面。为此，我们将开发一个完整的应用程序，并使用 JUnit 5 实现不同类型的测试。

# 功能和需求

我们应用程序的历史始于一个热爱猫的假设人物。这个人拥有一群猫，他/她希望从外部世界得到关于它们的反馈。因此，这个人（我们从现在开始称之为*客户*）与我们联系，要求我们实现一个满足他/她需求的 Web 应用程序。该应用程序的名称将是“Rate my cat!”。在与客户的对话中，我们得出了应用程序开发的以下功能列表：

+   **F1**：每个用户应通过观看其名称和图片对猫的列表进行评分。

+   **F2**：每个用户应使用星级机制（从`0.5`到`5`星）对每只猫进行一次评分，还可以选择包括每只猫的评论。

作为我们开发过程中分析阶段的一部分，这些功能被细化为以下**功能需求**（**FR**）列表：

+   **FR1**：应用程序向最终用户呈现猫的列表（由名称和图片组成）。

+   **FR2**：每只猫都可以单独评分。

+   **FR3**：对猫进行评分的范围是从`0.5`到`5`（星）的区间。

+   **FR4**：除了每只猫的数字评分外，用户还应包括一些评论。

+   **FR5**：每个最终用户只能对每只猫（评论和/或星级）评分一次。

# 设计

由于我们的应用程序相当简单，我们决定在这里停止分析阶段，而不将我们的需求建模为用例。相反，我们继续使用经典的三层模型对 Web 应用程序进行高层架构设计：表示层、应用（或业务）逻辑和数据层。关于应用逻辑，如下图所示，需要两个组件。第一个称为`CatService`负责所有在需求列表中描述的评分操作。第二个称为`CookiesServices`用于处理 HTTP Cookies，需要实现 FR5*：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00150.jpeg)

“Rate my cat!”应用程序的高层架构设计

在这个阶段，我们能够决定实现我们的应用程序所涉及的主要技术：

+   Spring 5：这将是我们应用程序的基础框架。具体来说，我们使用 Spring Boot 通过 Spring MVC 简化我们的 Web 应用程序的创建。此外，我们使用 Spring Data JPA 使用简单的 H2 数据库来持久化应用程序数据，并使用 Thymeleaf ([`www.thymeleaf.org/`](http://www.thymeleaf.org/))作为模板引擎（用于 MVC 中的视图）。最后，我们还使用 Spring Test 模块以简单的方式进行容器内集成测试。

+   JUnit 5：当然，我们不能使用与 JUnit 5 不同的测试框架来进行我们的测试用例。此外，为了提高我们断言的可读性，我们使用 Hamcrest。

+   Mockito：为了实现单元测试用例，我们将使用 Mockito 框架，在几个容器外的单元测试中将 SUT 与其 DOCs 隔离开来。

+   Selenium WebDriver：我们还将使用 Selenium WebDriver 实现不同的端到端测试，以便从 JUnit 5 测试中执行我们的 Web 应用程序。

+   GitHub：我们的源代码存储库将托管在公共 GitHub 存储库中。

+   Travis CI：我们的测试套件将在每次提交新补丁到我们的 GitHub 存储库时执行。

+   Codecov：为了跟踪我们测试套件的代码覆盖率，我们将使用 Codecov。

+   SonarCloud：为了提供对我们源代码内部质量的完整评估，我们通过 SonarCloud 补充我们的测试过程进行一些自动静态分析。

这里的屏幕截图显示了应用程序 GUI 的操作。本节的主要目标不是深入挖掘应用程序的实现细节。有关详细信息，请访问[`github.com/bonigarcia/rate-my-cat`](https://github.com/bonigarcia/rate-my-cat)上的应用程序的 GitHub 存储库。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00151.jpeg)

应用程序 Rate my cat 的屏幕截图！

用于实现此示例的图片已从[`pixabay.com/`](https://pixabay.com/)上的免费图库中下载。

# 测试

现在让我们专注于这个应用程序的 JUnit 5 测试。我们实现了三种类型的测试：单元测试、集成测试和端到端测试。如前所述，对于单元测试，我们使用 Mockito 来隔离 SUT。我们决定使用包含不同 JUnit 5 测试的 Java 类来对我们应用程序的两个主要组件（`CatService`和`CookiesServices`）进行单元测试。

考虑第一个测试（称为`RateCatsTest`）。如代码所示，在这个类中，我们将类`CatService`定义为 SUT（使用注解`@InjectMocks`），将类`CatRepository`（由`CatService`使用依赖注入）定义为 DOC（使用注解`@Mock`）。这个类的第一个测试（`testCorrectRangeOfStars`）是一个参数化的 JUnit 5 测试的示例。这个测试的目标是评估`CatService`内的 rate 方法（方法`rateCate`）。为了选择这个测试的测试数据（输入），我们遵循黑盒策略，因此我们使用需求定义的信息。具体来说，*FR3*规定了用于评价猫的评分机制的星级范围。遵循边界分析方法，我们选择输入范围的边缘，即 0.5 和 5。第二个测试用例（`testCorrectRangeOfStars`）也测试相同的方法（`rateCat`），但这次测试评估了 SUT 在超出范围的输入时的响应（负面测试场景）。然后，在这个类中实现了另外两个测试，这次旨在评估*FR4*（即，还使用评论来评价猫）。请注意，我们使用 JUnit 5 的`@Tag`注解来标识每个测试及其相应的需求：

```java
package io.github.bonigarcia.test.unit;

import static org.hamcrest.CoreMatchers.*equalTo*;
import static org.hamcrest.MatcherAssert.*assertThat*;
import static org.hamcrest.text.IsEmptyString.*isEmptyString*;
import static org.junit.jupiter.api.Assertions.*assertThrows*;
import static org.mockito.ArgumentMatchers.*any*;
import static org.mockito.Mockito.*when*;

import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import io.github.bonigarcia.Cat;
import io.github.bonigarcia.CatException;
import io.github.bonigarcia.CatRepository;
import io.github.bonigarcia.CatService;
import io.github.bonigarcia.mockito.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("Unit tests (black-box): rating cats")
@Tag("unit")
class RateCatsTest {

    @InjectMocks
    CatService catService;

    @Mock
    CatRepository catRepository;

    // Test data
    Cat dummy = new Cat("dummy", "dummy.png");
    int stars = 5;
    String comment = "foo";

    @ParameterizedTest(name = "Rating cat with {0} stars")
    @ValueSource(doubles = { 0.5, 5 })
    @DisplayName("Correct range of stars test")
    @Tag("functional-requirement-3")
    void testCorrectRangeOfStars(double stars) {
        *when*(catRepository.save(dummy)).thenReturn(dummy);
        Cat dummyCat = catService.rateCat(stars, dummy);
        *assertThat*(dummyCat.getAverageRate(), *equalTo*(stars));
    }

    @ParameterizedTest(name = "Rating cat with {0} stars")
    @ValueSource(ints = { 0, 6 })
    @DisplayName("Incorrect range of stars test")
    @Tag("functional-requirement-3")
    void testIncorrectRangeOfStars(int stars) {
        *assertThrows*(CatException.class, () -> {
            catService.rateCat(stars, dummy);
        });
    }

    @Test
    @DisplayName("Rating cats with a comment")
    @Tag("functional-requirement-4")
    void testRatingWithComments() {
        *when*(catRepository.findById(*any*(Long.class)))
            .thenReturn(Optional.*of*(dummy));
        Cat dummyCat = catService.rateCat(stars, comment, 0);
        *assertThat*(catService.getOpinions(dummyCat).iterator().next()
           .getComment(), *equalTo*(comment));
    }

    @Test
    @DisplayName("Rating cats with empty comment")
    @Tag("functional-requirement-4")
    void testRatingWithEmptyComments() {
        *when*(catRepository.findById(*any*(Long.class)))
            .thenReturn(Optional.*of*(dummy));
        Cat dummyCat = catService.rateCat(stars, dummy);
        *assertThat*(catService.getOpinions(dummyCat).iterator().next()
            .getComment(), *isEmptyString*());
    }

}
```

接下来，单元测试评估了 cookies 服务（*FR5*）。为此，以下测试使用`CookiesService`类作为 SUT，这次我们将模拟标准的 Java 对象，即操作 HTTP Cookies 的`javax.servlet.http.HttpServletResponse`。检查此测试类的源代码，我们可以看到第一个测试方法（称为`testUpdateCookies`）练习了服务方法`updateCookies`，验证了 cookies 的格式是否符合预期。接下来的两个测试（`testCheckCatInCookies`和`testCheckCatInEmptyCookies`）评估了服务的`isCatInCookies`方法，使用了积极的策略（即输入猫与 cookie 的格式相对应）和消极的策略（相反的情况）。最后，最后两个测试（`testUpdateOpinionsWithCookies`和`testUpdateOpinionsWithEmptyCookies`）练习了 SUT 的`updateOpinionsWithCookiesValue`方法，遵循相同的方法，即使用有效和空 cookie 检查 SUT 的响应。所有这些测试都是按照白盒策略实施的，因为它的测试数据和逻辑完全依赖于 SUT 的特定内部逻辑（在这种情况下，cookie 的格式和管理方式）。

这个测试并不是按照纯白盒方法进行的，因为它的目标是在 SUT 内部练习所有可能的路径。它可以被视为白盒，因为它直接与实现相关联，而不是与需求相关联。

```java
package io.github.bonigarcia.test.unit;

import static org.hamcrest.CoreMatchers.*containsString*;
import static org.hamcrest.CoreMatchers.*equalTo*;
import static org.hamcrest.CoreMatchers.*not*;
import static org.hamcrest.MatcherAssert.*assertThat*;
import static org.hamcrest.collection.IsEmptyCollection.*empty*;
import static org.mockito.ArgumentMatchers.*any*;
import static org.mockito.Mockito.*doNothing*;
import java.util.List;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import io.github.bonigarcia.Cat;
import io.github.bonigarcia.CookiesService;
import io.github.bonigarcia.Opinion;
import io.github.bonigarcia.mockito.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("Unit tests (white-box): handling cookies")
@Tag("unit")
@Tag("functional-requirement-5")
class CookiesTest {
    @InjectMocks
    CookiesService cookiesService;
    @Mock
    HttpServletResponse response;

    // Test data
    Cat dummy = new Cat("dummy", "dummy.png");
    String dummyCookie = "0#0.0#_";

    @Test
    @DisplayName("Update cookies test")
    void testUpdateCookies() {
        *doNothing*().when(response).addCookie(*any*(Cookie.class));
        String cookies = cookiesService.updateCookies("", 0L, 0D, "", 
          response);
        *assertThat*(cookies,                         
 *containsString*(CookiesService.*VALUE_SEPARATOR*));
        *assertThat*(cookies, 
 *containsString*(Cookies.*CA**T_SEPARATOR*));
    }

    @Test
    @DisplayName("Check cat in cookies")
    void testCheckCatInCookies() {
        boolean catInCookies = cookiesService.isCatInCookies(dummy,
            dummyCookie);
        *assertThat*(catInCookies, *equalTo*(true));
    }

    @DisplayName("Check cat in empty cookies")
    @Test
    void testCheckCatInEmptyCookies() {
        boolean catInCookies = cookiesService.isCatInCookies(dummy, "");
        *assertThat*(catInCookies, *equalTo*(false));
    }

    @DisplayName("Update opinions with cookies")
    @Test
    void testUpdateOpinionsWithCookies() {
        List<Opinion> opinions = cookiesService
            .updateOpinionsWithCookiesValue(dummy, dummyCookie);
        *assertThat*(opinions, *not*(*empty*()));
    }

    @DisplayName("Update opinions with empty cookies")
    @Test
    void testUpdateOpinionsWithEmptyCookies() {
        List<Opinion> opinions = cookiesService
            .updateOpinionsWithCookiesValue(dummy, "");
        *assertThat*(opinions, *empty*());
    }

}
```

让我们继续下一个类型的测试：集成测试。对于这种类型的测试，我们将使用 Spring 提供的容器内测试功能。具体来说，我们使用 Spring 测试对象`MockMvc`来评估我们的应用程序的 HTTP 响应是否符合客户端的预期。在每个测试中，不同的请求被练习，以验证响应（状态码和内容类型）是否符合预期：

```java
package io.github.bonigarcia.test.integration;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*get*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*post*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*content*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*status*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@DisplayName("Integration tests: HTTP reponses")
@Tag("integration")
@Tag("functional-requirement-1")
@Tag("functional-requirement-2")

class WebContextTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    @DisplayName("Check home page (GET /)")
    void testHomePage() throws Exception {
        mockMvc.perform(*get*("/")).andExpect(*status*().isOk())
            .andExpect(*content*().contentType("text/html;charset=UTF-8"));
    }

    @Test
    @DisplayName("Check rate cat (POST /)")
    void testRatePage() throws Exception {
        mockMvc.perform(*post*("/").param("catId", "1").param("stars", "1")
            .param("comment", "")).andExpect(*status*().isOk())
            .andExpect(*content*().contentType("text/html;charset=UTF-8"));
    }

    @Test
    @DisplayName("Check rate cat (POST /) of an non-existing cat")
    void testRatePageCatNotAvailable() throws Exception {
        mockMvc.perform(*post*("/").param("catId", "0").param("stars", "1")
            .param("comment", "")).andExpect(*status*().isOk())
           .andExpect(*content*().contentType("text/html;charset=UTF-8"));
    }

    @Test
    @DisplayName("Check rate cat (POST /) with bad parameters")
    void testRatePageNoParameters() throws Exception {
        mockMvc.perform(*post*("/")).andExpect(*status*().isBadRequest());
    }

}
```

最后，我们还使用 Selenium WebDriver 实施了几个端到端测试。检查此测试的实现，我们可以看到这个测试同时使用了两个 JUnit 5 扩展：`SpringExtension`（在 JUnit 5 测试生命周期内启动/停止 Spring 上下文）和`SeleniumExtension`（在测试方法中注入 WebDriver 对象，用于控制 Web 浏览器）。特别是，在一个测试中我们使用了三种不同的浏览器：

+   PhantomJS（无头浏览器），以评估猫的列表是否在 Web GUI 中正确呈现（FR1）。

+   Chrome，通过应用程序 GUI 对猫进行评分（FR2）。

+   Firefox，使用 GUI 对猫进行评分，但结果出现错误（FR2）。

```java
package io.github.bonigarcia.test.e2e;

import static org.hamcrest.CoreMatchers.*containsString*;
import static org.hamcrest.CoreMatchers.*equalTo*;
import static org.hamcrest.MatcherAssert.*assertThat*;
import static org.openqa.selenium.support.ui.ExpectedConditions.*elementToBeClickable*;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.*RANDOM_PORT*;
 import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.phantomjs.PhantomJSDriver;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import io.github.bonigarcia.SeleniumExtension;

@ExtendWith({ SpringExtension.class, SeleniumExtension.class })
@SpringBootTest(webEnvironment = *RANDOM_PORT*)
@DisplayName("E2E tests: user interface")
@Tag("e2e")
public class UserInferfaceTest {
    @LocalServerPort
    int serverPort;

    @Test
    @DisplayName("List cats in the GUI")
    @Tag("functional-requirement-1")
    public void testListCats(PhantomJSDriver driver) {
        driver.get("http://localhost:" + serverPort);
        List<WebElement> catLinks = driver
            .findElements(By.*className*("lightbox"));
        *assertThat*(catLinks.size(), *equalTo*(9));
    }

    @Test
    @DisplayName("Rate a cat using the GUI")
    @Tag("functional-requirement-2")
    public void testRateCat(ChromeDriver driver) {
        driver.get("http://localhost:" + serverPort);
        driver.findElement(By.*id*("Baby")).click();
        String fourStarsSelector = "#form1 span:nth-child(4)";
        new WebDriverWait(driver, 10)                     
            .until(*elementToBeClickable
*                (By.*cssSelector*(fourStarsSelector)));
        driver.findElement(By.*cssSelector*(fourStarsSelector)).click();
        driver.findElement(By.*xpath*("//*[@id=\"comment\"]"))
            .sendKeys("Very nice cat");
        driver.findElement(By.*cssSelector*("#form1 > button")).click();
        WebElement sucessDiv = driver
            .findElement(By.*cssSelector*("#success > div"));
        *assertThat*(sucessDiv.getText(), *containsString*("Your vote for               
            Baby"));
    }

    @Test
    @DisplayName("Rate a cat using the GUI with error")
    @Tag("functional-requirement-2")
    public void testRateCatWithError(FirefoxDriver driver) {
        driver.get("http://localhost:" + serverPort);
        driver.findElement(By.*id*("Baby")).click();
        String sendButtonSelector = "#form1 > button";
        new WebDriverWait(driver, 10).until(
 *elementToBeClickable*(By.*cssSelector*(sendButtonSelector)));
        driver.findElement(By.*cssSelector*(sendButtonSelector)).click();
        WebElement sucessDiv = driver
            .findElement(By.*cssSelector*("#error > div"));
        *assertThat*(sucessDiv.getText(), *containsString*(
            "You need to select some stars for rating each cat"));
    }

}
```

为了更容易追踪测试执行，在所有实施的测试中，我们使用`@DisplayName`选择了有意义的测试名称。此外，对于参数化测试，我们使用元素名称来细化每次测试执行的测试名称，具体取决于测试输入。以下是在 Eclipse 4.7（Oxygen）中执行测试套件的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00152.jpeg)

在 Eclipse 4.7 中执行应用程序“评价我的猫！”的测试套件

如前所述，我们使用 Travis CI 作为构建服务器，在开发过程中执行我们的测试。在 Travis CI 的配置（文件`.travis.yml`）中，我们设置了两个额外的工具，以增强我们应用程序的开发和测试过程。一方面，Codecov 提供了全面的测试覆盖报告。另一方面，SonarCloud 提供了完整的静态分析。这两个工具都由 Travis CI 触发，作为持续集成构建过程的一部分。因此，我们可以评估应用程序的测试覆盖率和内部代码质量（如代码异味、重复块或技术债务），以及我们的开发过程。

以下图片显示了 Codecov 提供的在线报告的屏幕截图（SonarCloud 提供的报告在本章的前一部分中呈现）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00153.jpeg)\

Codecov 报告应用程序 Rate my cat！

最后但并非最不重要的是，我们在 GitHub 存储库的`README`中使用了几个*徽章*。具体来说，我们为 Travis CI（最后构建过程的状态）、SonarCloud（最后分析的状态）和 Codecov（最后代码覆盖分析的百分比）添加了徽章：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00154.jpeg)

GitHub 应用程序 Rate my cat！的徽章

# 总结

在本章中，我们回顾了测试活动管理方面的几个问题。首先，我们了解到测试可以在软件开发过程（软件生命周期）的不同部分进行，这取决于测试方法论：BDD（在需求分析之前定义验收测试），TDD（在系统设计之前定义测试），TFD（在系统设计之后实现测试）和 TLD（在系统实现之后实现测试）。

CI 是在软件开发中越来越多地使用的一个过程。它包括对代码库的自动构建和测试。这个过程通常是由源代码存储库中的新提交触发的，比如 GitHub、GitLab 或 Bitbucket。CI 扩展到持续交付（当发布到开发环境）和持续部署（当不断地部署到生产环境）。我们回顾了当今最常用的两个构建服务器：Jenkins（*CI 作为服务*）和 Travis（内部）。

有一些其他工具可以用来改进测试的管理，例如报告工具（如 Maven Surefire Report 或 Allure）或缺陷跟踪系统（如 JIRA、Bugzilla、Redmine、MantisBT 和 GitHub 问题）。自动静态分析是测试的一个很好的补充，例如使用诸如 Checkstyle、FindBugs、PMD 或 SonarQube 之类的代码检查工具，以及同行审查工具，如 Collaborator、Crucible、Gerrit 和 GitHub 拉取请求审查。

为了结束这本书，本章的最后一部分介绍了一个完整的 Web 应用程序（名为*Rate my cat!*）及其相应的 JUnit 5 测试（单元测试、集成测试和端到端测试）。它包括使用本书中介绍的不同技术开发和评估的 Web 应用程序，即 Spring、Mockito、Selenium、Hamcrest、Travis CI、Codecov 和 SonarCloud。
