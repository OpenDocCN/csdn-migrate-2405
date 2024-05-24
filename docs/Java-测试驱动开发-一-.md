# Java 测试驱动开发（一）

> 原文：[`zh.annas-archive.org/md5/ccd393a1b3d624be903cafab189c1930`](https://zh.annas-archive.org/md5/ccd393a1b3d624be903cafab189c1930)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

测试驱动开发已经存在一段时间了，但仍然有许多人没有采用它。其原因在于 TDD 很难掌握。尽管理论很容易理解，但要真正熟练掌握它需要大量的实践。本书的作者们已经练习 TDD 多年，并将尝试将他们的经验传授给您。他们是开发人员，并相信学习一些编码实践的最佳方式是通过代码和不断的实践。本书遵循相同的理念。我们将通过练习来解释所有的 TDD 概念。这将是一次通过 Java 开发应用到 TDD 最佳实践的旅程。最终，您将获得 TDD 黑带，并在您的软件工艺工具包中多了一个工具。

# 这本书适合谁

如果您是一名经验丰富的 Java 开发人员，并希望实现更有效的系统和应用程序编程方法，那么这本书适合您。

# 要充分利用本书

本书中的练习需要读者拥有 64 位计算机。本书提供了所有所需软件的安装说明。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，并按照屏幕上的说明进行操作。

文件下载后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/Windows 7-Zip

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Test-Driven-Java-Development-Second-Edition`](https://github.com/PacktPublishing/Test-Driven-Java-Development-Second-Edition)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/TestDrivenJavaDevelopmentSecondEdition_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/TestDrivenJavaDevelopmentSecondEdition_ColorImages.pdf)[.](http://www.packtpub.com/sites/default/files/downloads/Bookname_ColorImages.pdf)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子："在这个测试中，我们定义了当调用`ticTacToe.play(5, 2)`方法时，期望出现`RuntimeException`。"

代码块设置如下：

```java
public class FooTest {
  @Rule
  public ExpectedException exception = ExpectedException.none();
  @Test
  public void whenDoFooThenThrowRuntimeException() {
    Foo foo = new Foo();
    exception.expect(RuntimeException.class);
    foo.doFoo();
  }
}
```

任何命令行输入或输出都是这样写的：

```java
    $ gradle test
```

**粗体**：表示一个新术语、一个重要词或屏幕上看到的词。例如，菜单或对话框中的单词会在文本中出现。这是一个例子："IntelliJ IDEA 提供了一个非常好的 Gradle 任务模型，可以通过点击 View|Tool Windows|Gradle 来访问。"

警告或重要说明会出现在这样的形式中。

提示和技巧会出现在这样的形式中。

# 联系我们

我们始终欢迎读者的反馈。

**一般反馈**：发送电子邮件至`feedback@packtpub.com`，并在主题中提及书名。如果您对本书的任何方面有疑问，请发送电子邮件至`questions@packtpub.com`。

**勘误**：尽管我们已经尽最大努力确保内容的准确性，但错误是难免的。如果您在本书中发现错误，请向我们报告。请访问[www.packtpub.com/submit-errata](http://www.packtpub.com/submit-errata)，选择您的书籍，点击勘误提交表格链接，并输入详细信息。

**盗版**：如果您在互联网上发现我们作品的任何非法副本，请提供给我们地址或网站名称，我们将不胜感激。请通过`copyright@packtpub.com`与我们联系，并附上材料链接。

**如果您有兴趣成为作者**：如果您在某个专业领域有专长，并且有兴趣撰写或为一本书做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com/)。

# 评论

请留下评论。在阅读并使用本书后，为什么不在购买书籍的网站上留下评论呢？潜在读者可以看到并使用您的客观意见来做出购买决定，我们在 Packt 可以了解您对我们产品的看法，我们的作者也可以看到您对他们书籍的反馈。谢谢！

有关 Packt 的更多信息，请访问[packtpub.com](https://www.packtpub.com/)。


# 第一章：我为什么要关心测试驱动开发？

这本书是由开发人员为开发人员编写的。因此，大部分学习将通过代码进行。每一章都将介绍一个或多个测试驱动开发（TDD）实践，并我们将通过解决 kata 来尝试掌握它们。在空手道中，kata 是一种练习，您可以在其中多次重复一个动作，每次都有一点改进。遵循相同的哲学，我们将从一章到下一章进行小而显著的改进。您将学会如何更好地设计和编码，减少上市时间，始终获得最新的文档，通过高质量的测试获得高代码覆盖率，并编写有效的代码。

每次旅行都有一个开始，这次也不例外。我们的目的地是具有 TDD 黑带的 Java 开发人员。

为了知道我们要去哪里，我们将不得不讨论并找到一些问题的答案，这些问题将定义我们的旅程。什么是 TDD？它是一种测试技术，还是其他东西？应用 TDD 的好处是什么？

本章的目标是获得 TDD 的概述，了解它是什么，并了解它为从业者提供的好处。

本章将涵盖以下主题：

+   理解 TDD

+   什么是 TDD？

+   测试

+   模拟

+   可执行文档

+   没有调试

# 为什么 TDD？

您可能是在敏捷或瀑布环境中工作。也许您有经过多年的艰苦工作经过实战检验的明确定义的程序，或者您刚刚开始自己的创业公司。无论情况如何，您可能至少面临以下一种或多种痛苦、问题或导致交付失败的原因：

+   您的团队在需求、规格或用户故事的创建过程中被排除在外

+   大多数，如果不是所有的测试都是手动的，或者根本没有测试

+   即使您有自动化测试，它们也无法检测到真正的问题

+   自动化测试是在项目提供任何真正价值的时候编写和执行的

+   总是有比花时间进行测试更紧急的事情

+   团队在测试、开发和功能分析部门之间分裂，他们经常不同步

+   由于担心会破坏某些东西，无法重构代码

+   维护成本太高

+   上市时间太长

+   客户觉得交付的东西不是他们要求的

+   文档永远不是最新的

+   您害怕部署到生产环境，因为结果是未知的

+   由于回归测试运行时间太长，通常无法部署到生产环境

+   团队花费太多时间试图弄清楚某个方法或类的作用

TDD 并不能神奇地解决所有这些问题。相反，它让我们走上了解决问题的道路。没有银弹，但如果有一种开发实践可以在许多层面上产生巨大影响，那就是 TDD。

TDD 加快了上市时间，使重构更容易，有助于创建更好的设计，并促进了更松散的耦合。

除了直接的好处外，TDD 还是许多其他实践的先决条件（持续交付就是其中之一）。更好的设计、编写良好的代码、更快的上市时间、最新的文档和扎实的测试覆盖率，是您通过应用 TDD 将实现的一些结果。

掌握 TDD 并不容易。即使学习了所有的理论，经历了最佳实践和反模式，旅程也刚刚开始。TDD 需要时间和大量的实践。这是一次漫长的旅程，不会在这本书中结束。事实上，它永远不会真正结束。总是有新的方法可以变得更加熟练和更快。然而，尽管成本很高，但好处更大。花足够的时间与 TDD 一起的人声称没有其他开发软件的方式。我们是其中之一，我们确信您也会成为其中之一。

我们坚信学习编码技术的最佳方式是通过编码。你不可能在地铁上读完这本书去上班。这不是一本可以在床上读的书。你必须动手编码。

在这一章中，我们将从基础知识开始；从下一章开始，你将通过阅读、编写和运行代码来学习。我们想说，当你完成这本书时，你将成为一名经验丰富的 TDD 程序员，但这是不正确的。在这本书结束时，你将对 TDD 感到舒适，并且在理论和实践上有一个坚实的基础。其余的取决于你，以及你在日常工作中应用它所建立的经验。

# 理解 TDD

此时，你可能会对自己说，“好吧，我明白 TDD 会给我带来一些好处，但 TDD 到底是什么？”TDD 是在实际实现之前编写测试的简单过程。这是传统方法的颠倒，传统方法是在编写代码之后进行测试。

# 红-绿-重构

TDD 是一个依赖于非常短的开发周期重复的过程。它基于**极限编程**（**XP**）的测试优先概念，鼓励简单的设计和高度的信心。驱动这一周期的过程被称为**红-绿-重构**。

这个过程本身很简单，它由几个重复的步骤组成：

1.  编写一个测试

1.  运行所有测试

1.  编写实现代码

1.  运行所有测试

1.  重构

1.  运行所有测试

由于测试是在实际实现之前编写的，所以它应该失败。如果没有失败，那么测试是错误的。它描述了已经存在的东西，或者写错了。在编写测试时处于绿色状态是一个假阳性的迹象。这样的测试应该被移除或重构。

在编写测试时，我们处于红色状态。当测试的实现完成时，所有测试都应该通过，然后我们就处于绿色状态了。

如果最后一个测试失败了，那么实现是错误的，应该进行更正。要么我们刚刚完成的测试是不正确的，要么该测试的实现未满足我们设定的规范。如果除了最后一个测试之外的任何测试都失败了，那么我们就破坏了一些东西，应该撤销更改。

当这种情况发生时，自然的反应是花费尽可能多的时间来修复代码，以确保所有测试都通过。然而，这是错误的。如果修复不是在几分钟内完成的，最好的做法是撤销更改。毕竟，不久前一切都是正常的。明显破坏了某些东西的实现显然是错误的，那么为什么不回到起点，重新考虑正确的实现方式呢？这样，我们浪费了几分钟在错误的实现上，而不是浪费更多的时间来纠正一开始就不正确的东西。现有的测试覆盖范围（不包括最后一个测试的实现）应该是神圣的。我们通过有意的重构来改变现有的代码，而不是作为修复最近编写的代码的一种方式。

不要使最后一个测试的实现最终化，而是提供足够的代码让这个测试通过。

以任何你想要的方式编写代码，但要快。一旦一切都是绿色的，我们就有信心有一种测试的安全网。从这一刻起，我们可以开始重构代码。这意味着我们正在使代码变得更好、更优化，而不是引入新功能。在重构进行时，所有测试都应该始终通过。

如果在重构过程中，其中一个测试失败了，说明重构破坏了现有的功能，和之前一样，改动应该被撤销。此时，我们不仅不改变任何功能，也不引入任何新的测试。我们所做的只是不断地改进代码，同时持续运行所有的测试，确保没有出现问题。同时，我们正在证明代码的正确性，减少未来的维护成本。

重构完成后，这个过程会重复。这是一个非常短的循环的无尽循环。

# 速度是关键

想象一场乒乓球比赛（或乒乓球）。比赛非常快速；有时甚至连专业运动员打比赛时都很难跟上球的速度。TDD 非常类似。TDD 老手往往不会在乒乓球桌的任一边花费超过一分钟的时间（测试和实现）。编写一个简短的测试并运行所有测试（乒），编写实现并运行所有测试（乓），编写另一个测试（乒），编写该测试的实现（乓），重构并确认所有测试都通过（得分），然后重复——乒，乓，乒，乓，乒，乓，得分，再发球。不要试图编写完美的代码。相反，尽量保持球的运动，直到你认为是时候得分（重构）。

从测试切换到实现（反之亦然）的时间应该以分钟（如果不是秒）计算。

# 这不是关于测试

**T**在**TDD**中经常被误解。TDD 是我们处理设计的方式。它是一种迫使我们在编写代码之前思考实现和代码需要做什么的方式。它是一种专注于需求和一次只实现一件事的方式——组织你的思绪并更好地结构代码。这并不意味着 TDD 产生的测试是无用的——它们远非如此。它们非常有用，它们让我们能够以极快的速度开发，而不用担心会出现问题。特别是在重构时。能够在重组代码的同时确保没有破坏任何功能，对其质量是一个巨大的提升。

TDD 的主要目标是可测试的代码设计，测试只是一个非常有用的副产品。

# 测试

尽管 TDD 的主要目标是代码设计的方法，测试仍然是 TDD 非常重要的一个方面，我们应该清楚地了解两大类技术，如下所示：

+   黑盒测试

+   白盒测试

# 黑盒测试

黑盒测试（也称为**功能测试**）将被测试的软件视为黑盒，不了解其内部。测试使用软件接口，并尝试确保它们按预期工作。只要接口的功能保持不变，即使内部发生了变化，测试也应该通过。测试人员知道程序应该做什么，但不知道它是如何做到的。黑盒测试是传统组织中最常用的测试类型，这些组织通常有一个独立的测试部门，特别是当测试人员不擅长编码并且难以理解时。这种技术为被测试的软件提供了外部视角。

黑盒测试的一些优点如下：

+   它对大段代码非常有效

+   不需要访问代码、理解代码和编写代码的能力

+   它为用户和开发者提供了分离的视角

黑盒测试的一些缺点如下：

+   它提供了有限的覆盖范围，因为只执行了一小部分测试场景

+   由于测试人员对软件内部知识的缺乏，可能导致测试效率低下

+   可能导致盲目覆盖，因为测试人员对应用程序的了解有限

如果测试驱动开发，通常以验收标准的形式进行，后来作为应该开发的定义。

自动化的黑盒测试依赖于某种形式的自动化，如 BDD。

# 白盒测试

白盒测试（也称为透明盒测试、玻璃盒测试、透明盒测试和结构测试）查看被测试软件的内部，并将这些知识作为测试过程的一部分。例如，如果在某些条件下应该抛出异常，测试可能希望重现这些条件。白盒测试需要对系统和编程技能有内部知识。它提供了对被测试软件的内部视角。

白盒测试的一些优点如下：

+   它在发现错误和问题方面非常有效

+   对被测试软件内部的了解对于彻底测试是有益的

+   它可以发现隐藏的错误

+   它鼓励程序员的内省

+   它有助于优化代码

+   由于对软件内部知识的要求，可以获得最大的覆盖率

白盒测试的一些缺点如下：

+   它可能无法发现未实现或缺失的功能

+   它需要对被测试软件的内部有高级别的了解

+   它需要代码访问

+   测试通常与生产代码的实现细节紧密耦合，导致在重构代码时出现不希望的测试失败

白盒测试几乎总是自动化的，并且在大多数情况下采用单元测试的形式。

当白盒测试在实施之前进行时，它采用 TDD 的形式。

# 质量检查和质量保证之间的区别

测试方法也可以通过它们试图实现的目标来区分。这些目标通常在质量检查（QC）和质量保证（QA）之间分开。虽然 QC 专注于缺陷识别，QA 试图防止它们。QC 是产品导向的，旨在确保结果符合预期。另一方面，QA 更专注于确保质量内建的过程。它试图确保以正确的方式完成正确的事情。

虽然在过去，质量检查在质量保证方面起着更重要的作用，但随着 TDD、ATDD 和后来的 BDD 的出现，焦点已经开始转向质量保证。

# 更好的测试

无论是使用黑盒测试、白盒测试还是两者兼而有之，它们的编写顺序都非常重要。

需求（规格和用户故事）在实现它们的代码之前编写。它们首先定义了代码，而不是相反。测试也是如此。如果它们是在代码完成后编写的，以某种方式，那么代码（以及它实现的功能）正在定义测试。由已经存在的应用程序定义的测试是有偏见的。它们倾向于确认代码的功能，而不是测试客户的期望是否得到满足，或者代码是否按预期行为。与手动测试相比，情况就不那么明显，因为它通常由一个独立的 QC 部门（尽管通常被称为 QA）进行（即使它通常被称为 QA）。他们倾向于在与开发人员隔离的测试定义上工作。这本身就会导致由于不可避免的沟通不良和“警察综合症”而引起的更大问题，测试人员不是试图帮助团队编写具有内建质量的应用程序，而是在过程结束时找到错误。我们越早发现问题，修复它们就越便宜。

以 TDD 方式编写的测试（包括其变体，如 ATDD 和 BDD）是试图从一开始就开发具有内建质量的应用程序。这是为了避免一开始就出现问题。

# 模拟

为了让测试快速运行并提供持续反馈，代码需要以这样一种方式组织，即方法、函数和类可以很容易地被替换为模拟和存根。这种类型的实际代码替换的常用术语是**测试替身**。执行速度可能会受到外部依赖的严重影响；例如，我们的代码可能需要与数据库通信。通过模拟外部依赖，我们能够大大提高速度。整个单元测试套件的执行时间应该以分钟计算，如果不是秒。以便易于模拟和存根的方式设计代码，迫使我们通过关注点的分离来更好地构建代码。

比速度更重要的是消除外部因素的好处。设置数据库、Web 服务器、外部 API 和其他可能需要的依赖项，既耗时又不可靠。在许多情况下，这些依赖项甚至可能不可用。例如，我们可能需要创建一个与数据库通信并让其他人创建模式的代码。没有模拟，我们需要等到模式设置好为止。

无论是否有模拟，代码都应该以便于用另一个依赖项替换的方式编写。

# 可执行文档

TDD（以及良好结构的测试）的另一个非常有用的方面是文档。在大多数情况下，通过查看测试来了解代码的功能要比查看实现本身容易得多。某些方法的目的是什么？看看与之相关的测试。应用程序 UI 的某些部分的期望功能是什么？看看与之相关的测试。以测试形式编写的文档是 TDD 的支柱之一，值得进一步解释。

（传统）软件文档的主要问题是大部分时间都不是最新的。一旦代码的某部分发生变化，文档就停止反映实际情况。这种情况几乎适用于任何类型的文档，需求和测试用例受到的影响最大。

需要记录代码的必要性通常表明代码本身写得不好。此外，无论我们如何努力，文档都不可避免地会过时。

开发人员不应依赖系统文档，因为它几乎永远不会是最新的。此外，没有文档能够提供与代码本身一样详细和最新的描述。

使用代码作为文档并不排除其他类型的文档。关键是要避免重复。如果通过阅读代码可以获取系统的细节，其他类型的文档可以提供快速指南和高层概述。非代码文档应该回答诸如系统的一般目的是什么，系统使用了哪些技术等问题。在许多情况下，一个简单的`README`就足以为开发人员提供快速入门。项目描述、环境设置、安装以及构建和打包说明等部分对新手非常有帮助。从那时起，代码就是圣经。

实现代码提供了所有所需的细节，而测试代码则充当了对生产代码背后意图的描述。

测试是可执行的文档，TDD 是创建和维护它的最常见方式。

假设某种形式的持续集成（CI）正在使用，如果测试文档的某部分不正确，它将失败并很快被修复。持续集成解决了测试文档不正确的问题，但并不能确保所有功能都有文档记录。因此（以及其他许多原因），测试文档应该以 TDD 的方式创建。如果在编写实现代码之前将所有功能定义为测试，并且所有测试执行成功，那么测试就可以作为开发人员可以使用的完整和最新的信息源。

我们应该怎么处理团队的其他成员？测试人员、客户、经理和其他非编码人员可能无法从生产和测试代码中获取必要的信息。

正如我们之前看到的，黑盒测试和白盒测试是最常见的两种测试类型。这种区分很重要，因为它也将测试人员分为那些知道如何编写或至少阅读代码的人（白盒测试）和那些不知道的人（黑盒测试）。在某些情况下，测试人员可以做两种类型的测试。然而，更多的情况是，他们不知道如何编码，因此开发人员可以使用的文档对他们来说是无用的。如果需要将文档与代码解耦，单元测试就不是一个好选择。这就是 BDD 出现的原因之一。

BDD 可以为非编码人员提供必要的文档，同时仍然保持 TDD 和自动化的优势。

客户需要能够定义系统的新功能，以及能够获取有关当前系统所有重要方面的信息。该文档不应该太技术化（代码不是选项），但它仍然必须始终保持最新。BDD 叙述和场景是提供这种类型文档的最佳方式之一。作为验收标准（在编写代码之前编写），经常执行（最好在每次提交时），并用自然语言编写的能力使 BDD 故事不仅始终保持最新，而且可供不想检查代码的人使用。

文档是软件的一个组成部分。与代码的任何其他部分一样，它需要经常进行测试，以确保它准确和最新。

具有准确和最新信息的唯一经济有效的方法是拥有可集成到 CI 系统中的可执行文档。

TDD 作为一种方法论是朝着这个方向前进的好方法。在低级别上，单元测试是最合适的。另一方面，BDD 提供了一种在功能级别上工作的好方法，同时保持了使用自然语言所实现的理解。

# 不要调试

我们（本书的作者）几乎从不调试我们正在处理的应用程序！

这个说法可能听起来很自大，但事实如此。我们几乎从不调试，因为很少有理由调试应用程序。当测试在编写代码之前编写，并且代码覆盖率很高时，我们可以非常有信心地认为应用程序按预期工作。这并不意味着使用 TDD 编写的应用程序没有错误-它们有。所有应用程序都有。然而，当发生这种情况时，通过简单查找未被测试覆盖的代码来隔离它们是很容易的。

测试本身可能不包括某些情况。在这种情况下，行动就是编写额外的测试。

通过高代码覆盖率，通过测试找到某个错误的原因比花时间逐行调试要快得多。

# 总结

在本章中，您了解了 TDD 实践的一般理解以及 TDD 是什么以及它不是什么。您了解到它是通过一个称为红-绿-重构的短小可重复的周期来设计代码的一种方式。失败是一种预期状态，不仅应该被接受，而且应该在整个 TDD 过程中得到强制执行。这个周期是如此短，以至于我们可以以很快的速度从一个阶段转移到另一个阶段。

在代码设计是主要目标的同时，整个 TDD 过程中创建的测试是一项宝贵的资产，应该被充分利用，并严重影响我们对传统测试实践的看法。我们经历了最常见的那些实践，比如白盒测试和黑盒测试，试图将它们放入 TDD 的视角，并展示它们可以互相带来的好处。

您发现模拟是编写测试时经常必不可少的重要工具。最后，我们讨论了测试如何可以和应该被用作可执行文档，以及 TDD 如何可以使调试变得不那么必要。

现在我们已经掌握了理论知识，是时候建立开发环境，概述和比较不同的测试框架和工具了。


# 第二章：工具、框架和环境

“我们成为我们所看到的。我们塑造我们的工具，然后我们的工具塑造我们。”

- 马歇尔·麦克卢汉

正如每个士兵都了解他的武器一样，程序员必须熟悉开发生态系统和使编程更加容易的工具。无论您是否已经在工作或家中使用这些工具中的任何一个，都值得看看它们的特点、优势和劣势。让我们概述一下我们现在可以找到的关于以下主题的内容，并构建一个小项目来熟悉其中一些。

我们不会详细介绍这些工具和框架，因为这将在接下来的章节中进行。我们的目标是让您快速上手，并为您提供它们的简要概述以及它们的功能和使用方法。

本章将涵盖以下主题：

+   Git

+   虚拟机

+   构建工具

+   集成开发环境

+   单元测试框架

+   Hamcrest 和 AssertJ

+   代码覆盖工具

+   模拟框架

+   用户界面测试

+   行为驱动开发

# Git

Git 是最流行的版本控制系统。因此，本书中使用的所有代码都存储在 Bitbucket（[`bitbucket.org/`](https://bitbucket.org/)）中。如果您还没有安装 Git，请安装 Git。所有流行操作系统的发行版都可以在以下网址找到：[`git-scm.com`](http://git-scm.com)。

Git 有许多图形界面可用；其中一些是 Tortoise（[`code.google.com/p/tortoisegit`](https://code.google.com/p/tortoisegit)）、Source Tree（[`www.sourcetreeapp.com`](https://www.sourcetreeapp.com)）和 Tower（[`www.git-tower.com/`](http://www.git-tower.com/)）。

# 虚拟机

虽然它们不是本书的主题，但虚拟机是一个强大的工具，在良好的开发环境中是一等公民。它们在隔离系统中提供动态和易于使用的资源，因此可以在需要时使用和丢弃。这有助于开发人员专注于他们的任务，而不是浪费时间从头开始创建或安装所需的服务。这就是为什么虚拟机在这里找到了位置的原因。我们希望利用它们让您专注于代码。

为了在使用不同操作系统时拥有相同的环境，我们将使用 Vagrant 创建虚拟机，并使用 Docker 部署所需的应用程序。我们选择 Ubuntu 作为我们示例中的基本操作系统，只是因为它是一种流行的常用的类 Unix 发行版。大多数这些技术都是跨平台的，但偶尔您可能无法按照这里找到的说明进行操作，因为您可能使用其他操作系统。在这种情况下，您的任务是找出 Ubuntu 和您的操作系统之间的差异，并相应地采取行动。

# Vagrant

Vagrant 是我们将用于创建开发环境堆栈的工具。这是一种简单的方法，可以使用预配置的虚拟机初始化准备就绪的虚拟机，而只需付出最少的努力。所有的虚拟机和配置都放在一个文件中，称为`Vagrant`文件。

以下是创建一个简单 Ubuntu 虚拟机的示例。我们额外配置了使用 Docker 安装 MongoDB（Docker 的使用将很快解释）。我们假设您的计算机上已安装了 VirtualBox（[`www.virtualbox.org`](https://www.virtualbox.org)）和 Vagrant（[`www.vagrantup.com`](https://www.vagrantup.com)），并且您有互联网访问。

在这种特殊情况下，我们正在创建一个 Ubuntu 64 位实例，使用 Ubuntu box（`ubuntu/trusty64`）并指定 VM 应该有 1GB 的 RAM：

```java
  config.vm.box = "ubuntu/trusty64" 

  config.vm.provider "virtualbox" do |vb| 
  vb.memory = "1024" 
  end 
```

接下来，我们将在 Vagrant 机器中公开 MongoDB 的默认端口，并使用 Docker 运行它：

```java
  config.vm.network "forwarded_port", guest: 27017, host: 27017 
  config.vm.provision "docker" do |d| 
    d.run "mongoDB", image: "mongo:2", args: "-p 27017:27017" 
  end 
```

最后，为了加快 Vagrant 的设置速度，我们正在缓存一些资源。您应该安装名为`cachier`的插件。有关更多信息，请访问：[`github.com/fgrehm/vagrant-cachier`](https://github.com/fgrehm/vagrant-cachier)。

```java
  if Vagrant.has_plugin?("vagrant-cachier") 
    config.cache.scope = :box 
  end 
```

现在是时候看它运行了。第一次运行通常需要几分钟，因为需要下载和安装基本框和所有依赖项：

```java
$> vagrant plugin install vagrant-cachier
$> git clone https://bitbucket.org/vfarcic/tdd-java-ch02-example-vagrant.git
$> cd tdd-java-ch02-example-vagrant$> vagrant up
```

运行此命令时，您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/beed715c-3901-41ea-8d2a-97d563266fc0.png)

请耐心等待执行完成。完成后，您将拥有一个新的 Ubuntu 虚拟机，其中已经安装了 Docker 和一个 MongoDB 实例。最棒的部分是所有这些都是通过一个命令完成的。

要查看当前运行的 VM 的状态，可以使用`status`参数：

```java
$> vagrant status
Current machine states:
default                   running (virtualbox)

```

可以通过`ssh`或使用 Vagrant 命令访问虚拟机，如以下示例：

```java
$> vagrant ssh
Welcome to Ubuntu 14.04.2 LTS (GNU/Linux 3.13.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

 System information disabled due to load higher than 1.0

 Get cloud support with Ubuntu Advantage Cloud Guest:
 http://www.ubuntu.com/business/services/cloud

 0 packages can be updated.
 0 updates are security updates.

vagrant@vagrant-ubuntu-trusty-64:~$  
```

最后，要停止虚拟机，请退出虚拟机并运行`vagrant halt`命令：

```java
$> exit
$> vagrant halt
 ==> default: Attempting graceful shutdown of VM...
$>  
```

访问以下网址获取 Vagrant 框的列表或有关配置 Vagrant 的更多详细信息：[`www.vagrantup.com`](https://www.vagrantup.com)。

# Docker

设置环境后，是时候安装我们需要的服务和软件了。这可以通过 Docker 来完成，Docker 是一种简单且便携的方式，可以在隔离的容器中运行许多应用程序和服务。我们将使用它来安装所需的数据库、Web 服务器以及本书中需要的所有其他应用程序，这些都将在使用 Vagrant 创建的虚拟机中进行。事实上，之前创建的 Vagrant 虚拟机已经有一个使用 Docker 运行 MongoDB 实例的示例。

让我们再次启动 VM（我们之前使用`vagrant halt`命令停止了它），还有 MongoDB：

```java
$> vagrant up
$> vagrant ssh
vagrant@vagrant-ubuntu-trusty-64:~$ docker start mongoDB
mongoDB
vagrant@vagrant-ubuntu-trusty-64:~$ docker ps
CONTAINER ID        IMAGE           COMMAND                    CREATED
360f5340d5fc        mongo:2         "/entrypoint.sh mong..."   4 minutes ago

STATUS              PORTS                      NAMES
Up 4 minutes        0.0.0.0:27017->27017/tcp   mongoDB
vagrant@vagrant-ubuntu-trusty-64:~$ exit

```

使用`docker start`启动了容器；使用`docker ps`列出了所有正在运行的进程。

通过使用这种程序，我们能够在眨眼之间复制一个全栈环境。您可能想知道这是否像听起来的那样令人敬畏。答案是肯定的，它确实如此。Vagrant 和 Docker 允许开发人员专注于他们应该做的事情，而不必担心复杂的安装和棘手的配置。此外，我们额外努力为您提供了在本书中复制和测试所有代码示例和演示所需的所有步骤和资源。

# 构建工具

随着时间的推移，代码往往会在复杂性和规模上增长。这是软件行业的本质。所有产品都在不断发展，并且在产品的整个生命周期中都会实施新的要求。构建工具提供了一种尽可能简化项目生命周期管理的方法，通过遵循一些代码约定，例如以特定方式组织代码，并使用命名约定为您的类或由不同文件夹和文件组成的确定项目结构。

您可能熟悉 Maven 或 Ant。它们是处理项目的绝佳工具，但我们在这里是为了学习，所以决定使用 Gradle。Gradle 的一些优点是减少了样板代码，使文件更短、配置文件更易读。此外，Google 将其用作构建工具。它得到了 IntelliJ IDEA 的支持，非常容易学习和使用。通过添加插件，大多数功能和任务都可以实现。

精通 Gradle 不是本书的目标。因此，如果您想了解更多关于这个令人敬畏的工具，请访问其网站（[`gradle.org/`](http://gradle.org/)）并阅读您可以使用的插件和可以自定义的选项。要比较不同的 Java 构建工具，请访问：[`technologyconversations.com/2014/06/18/build-tools/`](https://technologyconversations.com/2014/06/18/build-tools/)。

在继续之前，请确保 Gradle 已安装在您的系统上。

让我们分析 `build.gradle` 文件的相关部分。它以 Groovy 作为描述语言，以简洁的方式保存项目信息。这是我们的项目构建文件，由 IntelliJ 自动生成：

```java
apply plugin: 'java'
sourceCompatibility = 1.7
version = '1.0'
```

由于这是一个 Java 项目，所以应用了 Java 插件。它带来了常见的 Java 任务，如构建、打包、测试等。源兼容性设置为 JDK 7。如果我们尝试使用此版本不支持的 Java 语法，编译器将会报错：

```java
repositories { 
    mavenCentral() 
} 
```

Maven Central（[`search.maven.org/`](http://search.maven.org/)）保存了我们的所有项目依赖项。本节告诉 Gradle 从哪里获取它们。Maven Central 仓库对于这个项目已经足够了，但如果有的话，您可以添加自定义仓库。Nexus 和 Ivy 也受支持：

```java
dependencies { 
    testCompile group: 'junit', name: 'junit', version: '4.12' 
} 
```

最后，这是项目依赖项的声明方式。IntelliJ 决定使用 JUnit 作为测试框架。

Gradle 任务很容易运行。例如，要从命令提示符中运行测试，我们可以简单地执行以下操作：

```java
gradle test  
```

可以通过从 IDEA 中运行 Gradle 工具窗口中的 `test` 任务来完成。

测试结果存储在位于 `build/reports/tests` 目录中的 HTML 文件中。

以下是通过运行 `gradle test` 生成的测试报告：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/3faba178-b0f0-487c-bf82-a7656f5e7f51.png)

# 集成开发环境

由于将涵盖许多工具和技术，我们建议使用 IntelliJ IDEA 作为代码开发工具。主要原因是这个**集成开发环境**（**IDE**）可以在没有繁琐配置的情况下工作。社区版（IntelliJ IDEA CE）带有许多内置功能和插件，使编码变得简单高效。它会根据文件扩展名自动推荐可以安装的插件。由于我们选择了 IntelliJ IDEA 作为本书的工具，因此您将在引用和步骤中找到与其操作或菜单相关的内容。如果读者使用其他 IDE，应该找到模拟这些步骤的正确方法。请参阅：[`www.jetbrains.com/idea/`](https://www.jetbrains.com/idea/) 了解如何下载和安装 IntelliJ IDEA 的说明。

# IDEA 演示项目

让我们创建演示项目的基本布局。本章将使用该项目来说明所有涉及的主题。Java 将是编程语言，Gradle（[`gradle.org/`](http://gradle.org/)）将用于运行不同的任务集，如构建、测试等。

让我们在 IDEA 中导入包含本章示例的存储库：

1.  打开 IntelliJ IDEA，选择从版本控制中检出，然后点击 Git。

1.  在 Git 存储库 URL 中输入 `https://bitbucket.org/vfarcic/tdd-java-ch02-example-junit.git`，然后点击克隆。确认 IDEA 的其余问题，直到从 Git 存储库克隆出带有代码的新项目。

导入的项目应该看起来类似于以下图片：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/4f24bf69-eaa5-4aac-8877-275f383e142f.png)

现在我们已经设置好了项目，是时候来看一下单元测试框架了。

# 单元测试框架

在本节中，展示并简要评论了两个最常用的 Java 单元测试框架。我们将通过比较使用 JUnit 和 TestNG 编写的测试类来重点关注它们的语法和主要特性。尽管存在细微差异，但这两个框架都提供了最常用的功能，主要区别在于测试的执行和组织方式。

让我们从一个问题开始。什么是测试？我们如何定义它？

测试是一个可重复的过程或方法，用于验证在确定的情况下，对于确定的输入，期望预定义的输出或交互的被测试目标的正确行为。

在编程方法中，根据其范围，有几种类型的测试——功能测试、验收测试和单元测试。接下来，我们将更详细地探讨每种类型的测试。

单元测试是关于测试小代码片段的。让我们看看如何测试一个单独的 Java 类。这个类非常简单，但足够我们的兴趣：

```java
public class Friendships { 
  private final Map<String, List<String>> friendships = 
     new HashMap<>(); 

  public void makeFriends(String person1, String person2) { 
    addFriend(person1, person2); 
    addFriend(person2, person1); 
  } 

  public List<String> getFriendsList(String person) { 
    if (!friendships.containsKey(person)) { 
      return Collections.emptyList(); 
    } 
    return friendships.get(person)
  } 

  public boolean areFriends(String person1, String person2) { 
    return friendships.containsKey(person1) &&  
        friendships.get(person1).contains(person2); 
  } 

  private void addFriend(String person, String friend) { 
    if (!friendships.containsKey(person)) { 
      friendships.put(person, new ArrayList<String>()); 
    } 
    List<String> friends = friendships.get(person); 
    if (!friends.contains(friend)) { 
      friends.add(friend); 
    } 
  } 
} 
```

# JUnit

JUnit（[`junit.org/`](http://junit.org/)）是一个简单易学的编写和运行测试的框架。每个测试都被映射为一个方法，每个方法都应该代表一个特定的已知场景，在这个场景中，我们的代码的一部分将被执行。代码验证是通过比较预期输出或行为与实际输出来完成的。

以下是用 JUnit 编写的测试类。有一些场景缺失，但现在我们只关注展示测试的样子。我们将在本书的后面专注于测试代码的更好方法和最佳实践。

测试类通常包括三个阶段：设置、测试和拆卸。让我们从为测试设置所需数据的方法开始。设置可以在类或方法级别上执行：

```java
Friendships friendships; 

@BeforeClass 
public static void beforeClass() { 
  // This method will be executed once on initialization time 
} 

@Before 
public void before() { 
  friendships = new Friendships(); 
  friendships.makeFriends("Joe",",," "Audrey"); 
  friendships.makeFriends("Joe", "Peter"); 
  friendships.makeFriends("Joe", "Michael"); 
  friendships.makeFriends("Joe", "Britney"); 
  friendships.makeFriends("Joe", "Paul"); 
}
```

`@BeforeClass`注解指定一个方法，在类中的任何测试方法之前运行一次。这是一个有用的方法，可以进行一些通用设置，大多数（如果不是全部）测试都会用到。

`@Before`注解指定一个方法，在每个测试方法之前运行。我们可以使用它来设置测试数据，而不必担心之后运行的测试会改变该数据的状态。在前面的示例中，我们实例化了`Friendships`类，并向`Friendships`列表添加了五个样本条目。无论每个单独的测试将进行何种更改，这些数据都将一遍又一遍地重新创建，直到所有测试都完成。

这两个注解的常见用法包括设置数据库数据、创建测试所需的文件等。稍后，我们将看到如何使用模拟来避免外部依赖。然而，功能测试或集成测试可能仍然需要这些依赖，`@Before`和`@BeforeClass`注解是设置它们的好方法。

数据设置好后，我们可以进行实际的测试：

```java
@Test 
public void alexDoesNotHaveFriends() { 
  Assert.assertTrue("Alex does not have friends", 
     friendships.getFriendsList("Alex").isEmpty()); 
} 

@Test 
public void joeHas5Friends() { 
  Assert.assertEquals("Joe has 5 friends", 5, 
     friendships.getFriendsList("Joe").size()); 
} 

@Test 
public void joeIsFriendWithEveryone() { 
  List<String> friendsOfJoe =  
    Arrays.asList("Audrey", "Peter", "Michael", "Britney", "Paul"); 
  Assert.assertTrue(friendships.getFriendsList("Joe")
     .containsAll(friendsOfJoe)); 
} 
```

在这个例子中，我们使用了一些不同类型的断言。我们确认`Alex`没有任何朋友，而`Joe`是一个非常受欢迎的人，有五个朋友（`Audrey`、`Peter`、`Michael`、`Britney`和`Paul`）。

最后，一旦测试完成，我们可能需要进行一些清理工作：

```java
@AfterClass 
public static void afterClass() { 
  // This method will be executed once when all test are executed 
} 

@After 
public void after() { 
  // This method will be executed once after each test execution 
} 
```

在我们的例子中，在`Friendships`类中，我们不需要清理任何东西。如果有这样的需要，这两个注解将提供该功能。它们的工作方式类似于`@Before`和`@BeforeClass`注解。`@AfterClass`在所有测试完成后运行一次。`@After`注解在每个测试后执行。这将每个测试方法作为一个单独的类实例运行。只要我们避免全局变量和外部资源，比如数据库和 API，每个测试都是与其他测试隔离的。在一个测试中所做的任何事情都不会影响其他测试。

完整的源代码可以在`FriendshipsTest`类中找到，网址为[`bitbucket.org/vfarcic/tdd-java-ch02-example-junit`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-junit)。

# TestNG

在 TestNG（[`testng.org/doc/index.html`](http://testng.org/doc/index.html)）中，测试被组织在类中，就像 JUnit 一样。

为了运行 TestNG 测试，需要以下 Gradle 配置（`build.gradle`）：

```java
dependencies { 
   testCompile group: 'org.testng', name: 'testng', version: '6.8.21' 
} 

test.useTestNG() { 
// Optionally you can filter which tests are executed using 
//    exclude/include filters 
// excludeGroups 'complex' 
} 
```

与 JUnit 不同，TestNG 需要额外的 Gradle 配置，告诉它使用 TestNG 来运行测试。

以下的测试类是用 TestNG 编写的，反映了我们之前用 JUnit 做的事情。重复的导入和其他无聊的部分被省略了，以便专注于相关部分：

```java
@BeforeClass 
public static void beforeClass() { 
  // This method will be executed once on initialization time 
} 

@BeforeMethod 
public void before() { 
  friendships = new Friendships(); 
  friendships.makeFriends("Joe", "Audrey"); 
  friendships.makeFriends("Joe", "Peter"); 
  friendships.makeFriends("Joe", "Michael"); 
  friendships.makeFriends("Joe", "Britney"); 
  friendships.makeFriends("Joe", "Paul"); 
} 
```

您可能已经注意到了 JUnit 和 TestNG 之间的相似之处。两者都使用注解来指定某些方法的目的。除了不同的名称（`@Beforeclass`与`@BeforeMethod`），两者之间没有区别。然而，与 JUnit 不同，TestNG 会为所有测试方法重用相同的测试类实例。这意味着测试方法默认情况下不是隔离的，因此在`before`和`after`方法中需要更多的注意。

断言也非常相似：

```java
public void alexDoesNotHaveFriends() { 
  Assert.assertTrue(friendships.getFriendsList("Alex").isEmpty(), 
      "Alex does not have friends"); 
} 

public void joeHas5Friends() { 
  Assert.assertEquals(friendships.getFriendsList("Joe").size(), 
      5, "Joe has 5 friends"); 
} 

public void joeIsFriendWithEveryone() { 
  List<String> friendsOfJoe = 
    Arrays.asList("Audrey", "Peter", "Michael", "Britney", "Paul");
  Assert.assertTrue(friendships.getFriendsList("Joe")
      .containsAll(friendsOfJoe)); 
} 
```

与 JUnit 相比，唯一显著的区别是`assert`变量的顺序。虽然 JUnit 的断言参数顺序是**可选消息**、**预期值**和**实际值**，TestNG 的顺序是实际值、预期值和可选消息。除了我们传递给`assert`方法的参数顺序不同之外，JUnit 和 TestNG 之间几乎没有区别。

您可能已经注意到缺少`@Test`。TestNG 允许我们在类级别上设置它，从而将所有公共方法转换为测试。

`@After`注解也非常相似。唯一显著的区别是 TestNG 的`@AfterMethod`注解，其作用方式与 JUnit 的`@After`注解相同。

如您所见，语法非常相似。测试被组织成类，并且使用断言进行测试验证。这并不是说这两个框架之间没有更重要的区别；我们将在本书中看到其中一些区别。我邀请您自行探索 JUnit（[`junit.org/`](http://junit.org/)）和 TestNG（[`testng.org/`](http://testng.org/)）。

前面例子的完整源代码可以在[`bitbucket.org/vfarcic/tdd-java-ch02-example-testng`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-testng)找到。

到目前为止，我们编写的断言只使用了测试框架。然而，有一些测试工具可以帮助我们使它们更加美观和易读。

# Hamcrest 和 AssertJ

在前一节中，我们概述了单元测试是什么，以及如何使用两个最常用的 Java 框架编写单元测试。由于测试是我们项目的重要组成部分，为什么不改进我们编写测试的方式呢？一些很酷的项目出现了，旨在通过改变断言的方式来增强测试的语义。结果，测试更加简洁易懂。

# Hamcrest

**Hamcrest**添加了许多称为**匹配器**的方法。每个匹配器都设计用于执行比较操作。它足够灵活，可以支持自己创建的自定义匹配器。此外，JUnit 自带对 Hamcrest 的支持，因为其核心包含在 JUnit 分发中。您可以轻松开始使用 Hamcrest。但是，我们希望使用功能齐全的项目，因此我们将在 Gradle 的文件中添加一个测试依赖项：

```java
testCompile 'org.hamcrest:hamcrest-all:1.3' 
```

让我们将 JUnit 中的一个断言与 Hamcrest 中的等效断言进行比较：

+   JUnit 的`assert`：

```java
List<String> friendsOfJoe = 
  Arrays.asList("Audrey", "Peter", "Michael", "Britney", "Paul");
Assert.assertTrue( friendships.getFriendsList("Joe")
    .containsAll(friendsOfJoe)); 
```

+   Hamcrest 的`assert`：

```java
assertThat( 
  friendships.getFriendsList("Joe"), 
  containsInAnyOrder("Audrey", "Peter", "Michael", "Britney", "Paul") 
); 
```

正如你所看到的，Hamcrest 更具表现力。它具有更大范围的断言，可以避免一些样板代码，同时使代码更易于阅读和更具表现力。

这是另一个例子：

+   JUnit 的`assert`：

```java
Assert.assertEquals(5, friendships.getFriendsList("Joe").size()); 
```

+   Hamcrest 的`assert`：

```java
assertThat(friendships.getFriendsList("Joe"), hasSize(5)); 
```

您会注意到两个区别。首先是，与 JUnit 不同，Hamcrest 几乎总是直接使用对象。在 JUnit 的情况下，我们需要获取整数大小并将其与预期数字（`5`）进行比较；而 Hamcrest 具有更大范围的断言，因此我们可以简单地使用其中一个（`hasSize`）与实际对象（`List`）一起使用。另一个区别是，Hamcrest 具有与实际值相反的顺序，实际值是第一个参数（就像 TestNG 一样）。

这两个例子还不足以展示 Hamcrest 所提供的全部潜力。在本书的后面，将会有更多关于 Hamcrest 的例子和解释。访问[`hamcrest.org/`](http://hamcrest.org/)并探索其语法。

完整的源代码可以在`FriendshipsHamcrestTest`类中找到，网址为[`bitbucket.org/vfarcic/tdd-java-ch02-example-junit`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-junit)。

# AssertJ

**AssertJ**的工作方式类似于 Hamcrest。一个主要的区别是 AssertJ 断言可以连接起来。

要使用 AssertJ，必须将依赖项添加到 Gradle 的依赖项中：

```java
testCompile 'org.assertj:assertj-core:2.0.0' 
```

让我们将 JUnit 断言与 AssertJ 进行比较：

```java
Assert.assertEquals(5, friendships.getFriendsList("Joe").size()); 
List<String> friendsOfJoe = 
   Arrays.asList("Audrey", "Peter", "Michael", "Britney", "Paul");
Assert.assertTrue(  friendships.getFriendsList("Joe")
   .containsAll (friendsOfJoe) 
); 
```

在 AssertJ 中，相同的两个断言可以连接成一个：

```java
assertThat(friendships.getFriendsList("Joe")) 
  .hasSize(5) 
  .containsOnly("Audrey", "Peter", "Michael", "Britney", "Paul");
```

这是一个不错的改进。不需要有两个单独的断言，也不需要创建一个包含预期值的新列表。此外，AssertJ 更易读，更容易理解。

完整的源代码可以在`FriendshipsAssertJTest`类中找到，网址为[`bitbucket.org/vfarcic/tdd-java-ch02-example-junit`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-junit)。

现在我们已经有了运行的测试，我们可能想要查看我们的测试生成的代码覆盖率是多少。

# 代码覆盖率工具

我们编写测试并不意味着它们很好，也不意味着它们覆盖了足够的代码。一旦我们开始编写和运行测试，自然的反应就是开始提出以前无法回答的问题。我们的代码的哪些部分得到了适当的测试？我们的测试没有考虑到哪些情况？我们测试得足够吗？这些和其他类似的问题可以通过代码覆盖率工具来回答。它们可以用于识别我们的测试未覆盖的代码块或行；它们还可以计算代码覆盖的百分比并提供其他有趣的指标。

它们是用于获取指标并显示测试和实现代码之间关系的强大工具。然而，与任何其他工具一样，它们的目的需要明确。它们不提供关于质量的信息，而只提供我们的代码中已经测试过的部分。

代码覆盖率显示测试执行期间是否到达了代码行，但这并不是良好测试实践的保证，因为测试质量不包括在这些指标中。

让我们来看看用于计算代码覆盖率的最流行的工具之一。

# JaCoCo

Java 代码覆盖率（JaCoCo）是一个用于测量测试覆盖率的知名工具。

要在我们的项目中使用它，我们需要在 Gradle 配置文件`build.gradle`中添加几行：

1.  为 JaCoCo 添加 Gradle`plugin`：

```java
apply plugin: 'jacoco'
```

1.  要查看 JaCoCo 的结果，请从命令提示符中运行以下命令：

```java
gradle test jacocoTestReport
```

1.  相同的 Gradle 任务可以从 Gradle 任务 IDEA 工具窗口运行。

1.  最终结果存储在`build/reports/jacoco/test/html`目录中。这是一个可以在任何浏览器中打开的 HTML 文件：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/2d6b19f8-0fbc-4101-88d0-46a046cd900a.png)

本书的后续章节将更详细地探讨代码覆盖率。在那之前，可以访问[`www.eclemma.org/jacoco/`](http://www.eclemma.org/jacoco/)获取更多信息。

# 模拟框架

我们的项目看起来很酷，但它太简单了，远非一个真正的项目。它仍然没有使用外部资源。Java 项目需要数据库，因此我们将尝试引入它。

测试使用外部资源或第三方库的代码的常见方法是什么？模拟是答案。模拟对象，或者简单地说是模拟，是一个可以用来替代真实对象的模拟对象。当依赖外部资源的对象被剥夺时，它们非常有用。

实际上，在开发应用程序时根本不需要数据库。相反，您可以使用模拟来加快开发和测试，并且只在运行时使用真实的数据库连接。我们可以专注于编写类并在集成时考虑它们，而不是花时间设置数据库和准备测试数据。

为了演示目的，我们将介绍两个新类：`Person`类和`FriendCollection`类，它们旨在表示人和数据库对象映射。持久性将使用 MongoDB 进行（[`www.mongodb.org/`](https://www.mongodb.org/)）。

我们的示例将有两个类。`Person`将表示数据库对象数据；`FriendCollection`将是我们的数据访问层。代码是自解释的。

让我们创建并使用`Person`类：

```java
public class Person { 
  @Id
  private String name; 

  private List<String> friends; 

  public Person() { } 

  public Person(String name) { 
    this.name = name; 
    friends = new ArrayList<>(); 
  } 

  public List<String> getFriends() { 
    return friends; 
  } 

  public void addFriend(String friend) { 
    if (!friends.contains(friend)) friends.add(friend); 
  }
}
```

让我们创建并使用`FriendsCollection`类：

```java
public class FriendsCollection { 
  private MongoCollection friends; 

  public FriendsCollection() { 
    try { 
      DB db = new MongoClient().getDB("friendships"); 
      friends = new Jongo(db).getCollection("friends"); 
    } catch (UnknownHostException e) { 
      throw new RuntimeException(e.getMessage()); 
    } 
  } 

  public Person findByName(String name) { 
    return friends.findOne("{_id: #}", name).as(Person.class); 
  } 

  public void save(Person p) { 
    friends.save(p); 
  } 
} 
```

此外，还引入了一些新的依赖项，因此 Gradle 依赖块需要进行修改。第一个是 MongoDB 驱动程序，它用于连接到数据库。第二个是 Jongo，一个使访问 Mongo 集合非常简单的小项目。

`mongodb`和`jongo`的 Gradle 依赖如下：

```java
dependencies { 
    compile 'org.mongodb:mongo-java-driver:2.13.2' 
    compile 'org.jongo:jongo:1.1' 
} 
```

我们正在使用数据库，因此`Friendships`类也应该被修改。我们应该将一个映射更改为`FriendsCollection`并修改其余代码以使用它。最终结果如下：

```java
public class FriendshipsMongo { 
  private FriendsCollection friends; 

  public FriendshipsMongo() { 
    friends = new FriendsCollection(); 
  } 

  public List<String> getFriendsList(String person) { 
    Person p = friends.findByName(person); 
    if (p == null) return Collections.emptyList(); 
    return p.getFriends(); 
  } 

  public void makeFriends(String person1, String person2) { 
    addFriend(person1, person2); 
    addFriend(person2, person1); 
  } 

  public boolean areFriends(String person1, String person2) { 
    Person p = friends.findByName(person1); 
    return p != null && p.getFriends().contains(person2); 
  } 

  private void addFriend(String person, String friend) {
    Person p = friends.findByName(person); 
    if (p == null) p = new Person(person); 
    p.addFriend(friend); 
    friends.save(p); 
  } 
} 
```

完整的源代码可以在[`bitbucket.org/vfarcic/tdd-java-ch02-example-junit`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-junit)存储库中的`FriendsCollection`和`FriendshipsMongo`类中找到。

现在我们的`Friendships`类已经可以与 MongoDB 一起工作，让我们看看如何使用模拟来测试它的一种可能方式。

# Mockito

Mockito 是一个允许轻松创建测试替身的 Java 框架。

Gradle 依赖如下：

```java
dependencies { 
  testCompile group: 'org.mockito', name: 'mockito-all', version: '1.+' 
} 
```

Mockito 通过 JUnit 运行。它为我们创建了所有必需的模拟对象，并将它们注入到具有测试的类中。有两种基本方法；通过自己实例化模拟对象并通过类构造函数将它们注入为类依赖项，或者使用一组注解。在下一个示例中，我们将看到如何使用注解来完成。

为了使一个类使用 Mockito 注解，它需要使用`MockitoJUnitRunner`运行。使用该运行程序简化了该过程，因为您只需向要创建的对象添加注解即可：

```java
@RunWith(MockitoJUnitRunner.class) 
public class FriendshipsTest { 
... 
} 
```

在您的测试类中，被测试的类应该用`@InjectMocks`注解。这告诉 Mockito 要将模拟对象注入哪个类：

```java
@InjectMocks 
FriendshipsMongo friendships; 
```

从那时起，我们可以指定在类内部的特定方法或对象，即`FriendshipsMongo`，将被替换为模拟对象：

```java
@Mock 
FriendsCollection friends; 
```

在这个例子中，`FriendshipsMongo`类中的`FriendsCollection`将被模拟。

现在，我们可以指定在调用`friends`时应返回什么：

```java
Person joe = new Person("Joe"); 
doReturn(joe).when(friends).findByName("Joe"); 
assertThat(friends.findByName("Joe")).isEqualTo(joe); 
```

在这个例子中，我们告诉 Mockito 当调用`friends.findByName("Joe")`时返回`joe`对象。稍后，我们使用`assertThat`来验证这个假设是正确的。

让我们尝试在之前没有 MongoDB 的类中做与之前相同的测试：

```java
@Test 
public void joeHas5Friends() { 
  List<String> expected = 
    Arrays.asList("Audrey", "Peter", "Michael", "Britney", "Paul"); 
  Person joe = spy(new Person("Joe")); 

  doReturn(joe).when(friends).findByName("Joe"); 
  doReturn(expected).when(joe).getFriends(); 

  assertThat(friendships.getFriendsList("Joe")) 
    .hasSize(5) 
    .containsOnly("Audrey", "Peter", "Michael", "Britney", "Paul"); 
} 
```

在这个小测试中发生了很多事情。首先，我们指定`joe`是一个间谍。在 Mockito 中，间谍是真实对象，除非另有规定，否则使用真实方法。然后，我们告诉 Mockito 当`friends`方法调用`getFriends`时返回`joe`。这种组合允许我们在调用`getFriends`方法时返回`expected`列表。最后，我们断言`getFriendsList`返回预期的名称列表。

完整的源代码可以在[`bitbucket.org/vfarcic/tdd-java-ch02-example-junit`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-junit)存储库中的`FriendshipsMongoAssertJTest`类中找到。

我们将在后面使用 Mockito；在本书中，您将有机会更加熟悉它和一般的模拟。有关 Mockito 的更多信息，请访问[`mockito.org/`](http://mockito.org/)。

# EasyMock

EasyMock 是一种替代的模拟框架。它与 Mockito 非常相似。然而，主要区别在于 EasyMock 不创建`spy`对象，而是模拟对象。其他区别是语法上的。

让我们看一个 EasyMock 的例子。我们将使用与 Mockito 示例相同的一组测试用例：

```java
@RunWith(EasyMockRunner.class) 
public class FriendshipsTest { 
  @TestSubject 
  FriendshipsMongo friendships = new FriendshipsMongo(); 
  @Mock(type = MockType.NICE) 
  FriendsCollection friends;
}
```

基本上，运行器与 Mockito 运行器的功能相同：

```java
@TestSubject 
FriendshipsMongo friendships = new FriendshipsMongo(); 

@Mock(type = MockType.NICE) 
FriendsCollection friends; 
```

`@TestSubject`注解类似于 Mockito 的`@InjectMocks`，而`@Mock`注解表示要以类似于 Mockito 的方式模拟的对象。此外，类型`NICE`告诉模拟返回空值。

让我们比较一下我们用 Mockito 做的一个断言：

```java
@Test 
public void mockingWorksAsExpected() { 
  Person joe = new Person("Joe"); 
  expect(friends.findByName("Joe")).andReturn(joe); 
  replay(friends); 
  assertThat(friends.findByName("Joe")).isEqualTo(joe); 
} 
```

除了语法上的小差异外，EasyMock 唯一的缺点是需要额外的指令`replay`。它告诉框架应用先前指定的期望。其余几乎相同。我们指定`friends.findByName`应返回`joe`对象，应用该期望，并最后断言实际结果是否符合预期。

在 EasyMock 版本中，我们使用 Mockito 的第二个测试方法如下：

```java
@Test 
public void joeHas5Friends() { 
  List<String> expected = 
  Arrays.asList("Audrey", "Peter", "Michael", "Britney", "Paul"); 
  Person joe = createMock(Person.class); 

  expect(friends.findByName("Joe")).andReturn(joe); 
  expect(joe.getFriends()).andReturn(expected); 
  replay(friends); 
  replay(joe); 

  assertThat(friendships.getFriendsList("Joe")) 
    .hasSize(5)
    .containsOnly("Audrey", "Peter", "Michael", "Britney", "Paul"); 
}
```

与 Mockito 相比，EasyMock 几乎没有区别，只是 EasyMock 没有间谍。根据上下文，这可能是一个重要的区别。

尽管这两个框架都很相似，但有一些细节使我们选择 Mockito 作为框架，这将在本书中使用。

有关此断言库的更多信息，请访问[`easymock.org/`](http://easymock.org/)。

完整的源代码可以在`FriendshipsMongoEasyMockTest`类中找到，该类位于[`bitbucket.org/vfarcic/tdd-java-ch02-example-junit`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-junit)存储库中。

# 模拟的额外功能

前面介绍的两个项目都不涵盖所有类型的方法或字段。根据应用的修饰符，如静态或最终，类、方法或字段可能超出 Mockito 或 EasyMock 的范围。在这种情况下，我们可以使用 PowerMock 来扩展模拟框架。这样，我们可以模拟只能以棘手方式模拟的对象。但是，使用 PowerMock 时应该谨慎，因为使用它提供的许多功能通常是设计不良的标志。如果您正在处理遗留代码，PowerMock 可能是一个不错的选择。否则，尽量设计您的代码，以便不需要 PowerMock。我们稍后会向您展示如何做到这一点。

有关更多信息，请访问[`code.google.com/p/powermock/`](https://code.google.com/p/powermock/)。

# 用户界面测试

尽管单元测试可以并且应该覆盖应用程序的主要部分，但仍然需要进行功能和验收测试。与单元测试不同，它们提供了更高级别的验证，并且通常在入口点执行，并且严重依赖于用户界面。最终，我们创建的应用程序在大多数情况下都是由人类使用的，因此对应用程序行为的信心非常重要。通过测试应用程序从真实用户的角度来看应该做什么，可以实现这种舒适状态。

在这里，我们将尝试通过用户界面提供功能和验收测试的概述。我们将以网络为例，尽管还有许多其他类型的用户界面，如桌面应用程序、智能手机界面等。

# Web 测试框架

本章中已经测试了应用程序类和数据源，但仍然缺少一些东西；最常见的用户入口点——网络。大多数企业应用程序，如内部网或公司网站，都是使用浏览器访问的。因此，测试网络提供了重要的价值，帮助我们确保它正在按预期进行操作。

此外，公司正在花费大量时间进行长时间和繁重的手动测试，每次应用程序更改时都要进行测试。这是一种浪费时间，因为其中许多测试可以通过工具（如 Selenium 或 Selenide）进行自动化和无人监督地执行。

# Selenium

Selenium 是一个用于 Web 测试的强大工具。它使用浏览器来运行验证，并且可以处理所有流行的浏览器，如 Firefox、Safari 和 Chrome。它还支持无头浏览器，以更快的速度和更少的资源消耗测试网页。

有一个`SeleniumIDE`插件，可以用来通过记录用户执行的操作来创建测试。目前，它只支持 Firefox。遗憾的是，尽管以这种方式生成的测试提供了非常快速的结果，但它们往往非常脆弱，并且在长期内会引起问题，特别是当页面的某些部分发生变化时。因此，我们将坚持不使用该插件的帮助编写的代码。

执行 Selenium 最简单的方法是通过`JUnitRunner`运行它。

所有 Selenium 测试都是通过初始化`WebDriver`开始的，这是用于与浏览器通信的类：

1.  让我们从添加 Gradle 依赖开始：

```java
dependencies { 
  testCompile 'org.seleniumhq.selenium:selenium-java:2.45.0' 
} 
```

1.  例如，我们将创建一个搜索维基百科的测试。我们将使用 Firefox 驱动程序作为我们的首选浏览器：

```java
WebDriver driver = new FirefoxDriver(); 
```

`WebDriver`是一个可以用 Selenium 提供的众多驱动程序之一实例化的接口：

1.  要打开一个 URL，指令如下：

```java
driver.get("http://en.wikipedia.org/wiki/Main_Page");
```

1.  页面打开后，我们可以通过其名称搜索输入元素，然后输入一些文本：

```java
WebElement query = driver.findElement(By.name("search")); 
query.sendKeys("Test-driven development"); 
```

1.  一旦我们输入我们的搜索查询，我们应该找到并点击 Go 按钮：

```java
WebElement goButton = driver.findElement(By.name("go")); 
goButton.click();
```

1.  一旦到达目的地，就是验证，在这种情况下，页面标题是否正确的时候了：

```java
assertThat(driver.getTitle(), 
  startsWith("Test-driven development"));
```

1.  最后，一旦我们使用完毕，`driver`应该被关闭：

```java
driver.quit(); 
```

就是这样。我们有一个小但有价值的测试，可以验证单个用例。虽然

关于 Selenium 还有很多要说的，希望这为您提供了

有足够的信息来认识到它的潜力。

访问[`www.seleniumhq.org/`](http://www.seleniumhq.org/)获取更多信息和更复杂的`WebDriver`使用。

完整的源代码可以在`SeleniumTest`类中的[`bitbucket.org/vfarcic/tdd-java-ch02-example-web`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-web)存储库中找到。

虽然 Selenium 是最常用的与浏览器一起工作的框架，但它仍然是非常低级的，需要大量的调整。Selenide 的诞生是基于这样一个想法，即如果有一个更高级的库可以实现一些常见模式并解决经常重复的需求，那么 Selenium 将会更有用。

# Selenide

关于 Selenium 我们所看到的非常酷。它为我们提供了探测应用程序是否正常运行的机会，但有时配置和使用起来有点棘手。Selenide 是一个基于 Selenium 的项目，提供了一个良好的语法来编写测试，并使它们更易读。它为您隐藏了`WebDriver`和配置的使用，同时仍然保持了高度的定制性：

1.  与我们到目前为止使用的所有其他库一样，第一步是添加 Gradle 依赖：

```java
dependencies { 
    testCompile 'com.codeborne:selenide:2.17' 
}
```

1.  让我们看看如何使用 Selenide 编写之前的 Selenium 测试

相反。语法可能对那些了解 JQuery 的人来说很熟悉([`jquery.com/`](https://jquery.com/))：

```java
public class SelenideTest { 
  @Test 
  public void wikipediaSearchFeature() throws 
      InterruptedException { 

    // Opening Wikipedia page 
    open("http://en.wikipedia.org/wiki/Main_Page"); 

    // Searching TDD 
    $(By.name("search")).setValue("Test-driven development"); 

    // Clicking search button 
    $(By.name("go")).click(); 

    // Checks 
    assertThat(title(),
      startsWith("Test-driven development")); 
  } 
} 
```

这是一种更具表现力的测试编写方式。除了更流畅的语法之外，这段代码背后还发生了一些事情，需要额外的 Selenium 代码行。例如，单击操作将等待直到相关元素可用，并且只有在预定义的时间段过期时才会失败。另一方面，Selenium 会立即失败。在当今世界，许多元素通过 JavaScript 动态加载，我们不能指望一切立即出现。因此，这个 Selenide 功能被证明是有用的，并且可以避免使用重复的样板代码。Selenide 带来了许多其他好处。由于 Selenide 相对于 Selenium 提供的好处，它将成为我们在整本书中选择的框架。此外，有一个完整的章节专门介绍了使用这个框架进行 Web 测试。访问[`selenide.org/`](http://selenide.org/)获取有关在测试中使用 Web 驱动程序的更多信息。

无论测试是用一个框架还是另一个框架编写的，效果都是一样的。运行测试时，Firefox 浏览器窗口将出现并按顺序执行测试中定义的所有步骤。除非选择了无头浏览器作为您的驱动程序，否则您将能够看到测试过程。如果出现问题，将提供失败跟踪。除此之外，我们可以在任何时候拍摄浏览器截图。例如，在失败时记录情况是一种常见做法。

完整的源代码可以在`SelenideTest`类中找到

[`bitbucket.org/vfarcic/tdd-java-ch02-example-web`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-web) 仓库中。

掌握了基本的 Web 测试框架知识，现在是时候简要了解一下 BDD 了。

# 行为驱动开发

**行为驱动开发**（**BDD**）是一种旨在在整个项目过程中保持对利益相关者价值的关注的敏捷过程。BDD 的前提是，需求必须以每个人都能理解的方式编写，无论是业务代表、分析师、开发人员、测试人员、经理等等。关键在于拥有一组独特的工件，每个人都能理解和使用——一系列用户故事。故事由整个团队编写，并用作需求和可执行测试用例。这是一种以无法通过单元测试实现的清晰度执行 TDD 的方式。这是一种以（几乎）自然语言描述和测试功能的方式，并使其可运行和可重复。

一个故事由场景组成。每个场景代表一个简洁的行为用例，并使用步骤以自然语言编写。步骤是场景的前提条件、事件和结果的序列。每个步骤必须以`Given`、`When`或`Then`开头。`Given`用于前提条件，`When`用于操作，`Then`用于执行验证。

这只是一个简要介绍。有一个完整的章节，第八章，*BDD - 与整个团队一起工作*，专门介绍了这个主题。现在是时候介绍 JBehave 和 Cucumber 作为许多可用框架之一，用于编写和执行故事。

# JBehave

JBehave 是一个用于编写可执行和自动化的验收测试的 Java BDD 框架。故事中使用的步骤通过框架提供的几个注解绑定到 Java 代码：

1.  首先，将 JBehave 添加到 Gradle 依赖项中：

```java
dependencies { 
    testCompile 'org.jbehave:jbehave-core:3.9.5' 
}
```

1.  让我们通过一些示例步骤：

```java
@Given("I go to Wikipedia homepage") 
public void goToWikiPage() { 
  open("http://en.wikipedia.org/wiki/Main_Page"); 
} 
```

1.  这是`Given`类型的步骤。它代表需要满足的前提条件，以便成功执行一些操作。在这种情况下，它将打开一个维基百科页面。现在我们已经指定了我们的前提条件，是时候定义一些操作了：

```java
@When("I enter the value $value on a field named $fieldName")
public void enterValueOnFieldByName(String value, String fieldName) { 
  $(By.name(fieldName)).setValue(value); 
} 
@When("I click the button $buttonName") 
public void clickButonByName(String buttonName){ 
  $(By.name(buttonName)).click(); 
} 
```

1.  正如您所看到的，操作是使用`When`注释定义的。在我们的情况下，我们可以使用这些步骤来为字段设置一些值或单击特定按钮。一旦操作完成，我们可以处理验证。注意

通过引入参数，步骤可以更加灵活：

```java
@Then("the page title contains $title") 
public void pageTitleIs(String title) { 
  assertThat(title(), containsString(title)); 
} 
```

使用`Then`注释声明验证。在这个例子中，我们正在验证页面标题是否符合预期。

这些步骤可以在[`bitbucket.org/vfarcic/tdd-java-ch02-example-web`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-web)存储库中的`WebSteps`类中找到。

一旦我们定义了我们的步骤，就是使用它们的时候了。以下故事结合了这些步骤，以验证所需的行为：

```java
Scenario: TDD search on wikipedia 
```

它以命名场景开始。名称应尽可能简洁，但足以明确识别用户案例；仅供信息目的：

```java
Given I go to Wikipedia homepage 
When I enter the value Test-driven development on a field named search 
When I click the button go 
Then the page title contains Test-driven development 
```

正如您所看到的，我们正在使用之前定义的相同步骤文本。与这些步骤相关的代码将按顺序执行。如果其中任何一个被停止，执行也将停止，该场景本身被视为失败。

尽管我们在故事之前定义了我们的步骤，但也可以反过来，先定义故事，然后是步骤。在这种情况下，场景的状态将是挂起的，这意味着缺少所需的步骤。

这个故事可以在[`bitbucket.org/vfarcic/tdd-java-ch02-example-web`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-web)存储库中的`wikipediaSearch.story`文件中找到。

要运行这个故事，执行以下操作：

```java
$> gradle testJBehave
```

故事运行时，我们可以看到浏览器中正在发生的操作。一旦完成，将生成执行结果的报告。它可以在`build/reports/jbehave`中找到：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/dca745ce-04ef-448e-a573-18d765ad28e2.png)

JBehave 故事执行报告

为了简洁起见，我们排除了运行 JBehave 故事的`build.gradle`代码。完成的源代码可以在[`bitbucket.org/vfarcic/tdd-java-ch02-example-web`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-web)存储库中找到。

有关 JBehave 及其优势的更多信息，请访问[`jbehave.org/`](http://jbehave.org/)。

# Cucumber

Cucumber 最初是一个 Ruby BDD 框架。如今它支持包括 Java 在内的多种语言。它提供的功能与 JBehave 非常相似。

让我们看看用 Cucumber 写的相同的例子。

与我们到目前为止使用的任何其他依赖项一样，Cucumber 需要在我们开始使用它之前添加到`build.gradle`中：

```java
dependencies { 
    testCompile 'info.cukes:cucumber-java:1.2.2' 
    testCompile 'info.cukes:cucumber-junit:1.2.2' 
} 
```

我们将使用 Cucumber 的方式创建与 JBehave 相同的步骤：

```java
@Given("^I go to Wikipedia homepage$") 
public void goToWikiPage() { 
  open("http://en.wikipedia.org/wiki/Main_Page"); 
} 

@When("^I enter the value (.*) on a field named (.*)$") 
public void enterValueOnFieldByName(String value, 
    String fieldName) { 
  $(By.name(fieldName)).setValue(value); 
} 

@When("^I click the button (.*)$") 
public void clickButonByName(String buttonName) { 
  $(By.name(buttonName)).click(); 
} 

@Then("^the page title contains (.*)$") 
public void pageTitleIs(String title) { 
  assertThat(title(), containsString(title)); 
} 
```

这两个框架之间唯一显着的区别是 Cucumber 定义步骤文本的方式。它使用正则表达式来匹配变量类型，而 JBehave 则是根据方法签名推断它们。

这些步骤代码可以在[`bitbucket.org/vfarcic/tdd-java-ch02-example-web`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-web)存储库中的`WebSteps`类中找到：

让我们看看使用 Cucumber 语法编写的故事是什么样子的：

```java
Feature: Wikipedia Search 

  Scenario: TDD search on wikipedia 
    Given I go to Wikipedia homepage 
    When I enter the value Test-driven development on a field named search 
    When I click the button go 
    Then the page title contains Test-driven development 
```

请注意，几乎没有区别。这个故事可以在[`bitbucket.org/vfarcic/tdd-java-ch02-example-web`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-web)存储库中的`wikipediaSearch.feature`文件中找到。

您可能已经猜到，要运行 Cucumber 故事，您只需要运行以下 Gradle 任务：

```java
$> gradle testCucumber
```

结果报告位于`build/reports/cucumber-report`目录中。这是前面故事的报告：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/00ef22c3-dab2-47a2-a9b5-9677e2487c12.png)

Cucumber 故事执行报告

完整的代码示例可以在[`bitbucket.org/vfarcic/tdd-java-ch02-example-web`](https://bitbucket.org/vfarcic/tdd-java-ch02-example-web)存储库中找到。

有关 Cucumber 支持的语言列表或任何其他详细信息，请访问[`cukes.info/`](https://cukes.info/)。

由于 JBehave 和 Cucumber 都提供了类似的功能，我们决定在本书的其余部分中都使用 JBehave。还有一个专门的章节介绍 BDD 和 JBehave。

# 总结

在这一章中，我们暂时停止了 TDD，并介绍了许多在接下来的章节中用于代码演示的工具和框架。我们从版本控制、虚拟机、构建工具和 IDE 一直设置到如今常用的测试工具框架。

我们是开源运动的坚定支持者。秉承这种精神，我们特别努力地选择了每个类别中的免费工具和框架。

现在我们已经设置好了所有需要的工具，在下一章中，我们将深入探讨 TDD，从 Red-Green-Refactor 过程-TDD 的基石开始。


# 第三章：红绿重构——从失败到成功直至完美

“知道不足以;我们必须应用。愿意不足以;我们必须去做。”

- 李小龙

**红绿重构**技术是**测试驱动开发**（**TDD**）的基础。这是一个乒乓球游戏，在这个游戏中，我们以很快的速度在测试和实现代码之间切换。我们会失败，然后我们会成功，最后，我们会改进。

我们将通过逐个满足每个需求来开发一个井字棋游戏。我们将编写一个测试并查看是否失败。然后，我们将编写实现该测试的代码，运行所有测试，并看到它们成功。最后，我们将重构代码并尝试使其更好。这个过程将重复多次，直到所有需求都成功实现。

我们将从使用 Gradle 和 JUnit 设置环境开始。然后，我们将深入了解红绿重构过程。一旦我们准备好设置和理论，我们将通过应用的高级需求。

一切准备就绪后，我们将立即进入代码——逐个需求。一切都完成后，我们将查看代码覆盖率，并决定是否可以接受，或者是否需要添加更多测试。

本章将涵盖以下主题：

+   使用 Gradle 和 JUnit 设置环境

+   红绿重构过程

+   井字棋的需求

+   开发井字棋

+   代码覆盖率

+   更多练习

# 使用 Gradle 和 JUnit 设置环境

您可能熟悉 Java 项目的设置。但是，您可能以前没有使用过 IntelliJ IDEA，或者您可能使用的是 Maven 而不是 Gradle。为了确保您能够跟上练习，我们将快速浏览一下设置。

# 在 IntelliJ IDEA 中设置 Gradle/Java 项目

本书的主要目的是教授 TDD，因此我们不会详细介绍 Gradle 和 IntelliJ IDEA。两者都是作为示例使用的。本书中的所有练习都可以使用不同的 IDE 和构建工具来完成。例如，您可以使用 Maven 和 Eclipse。对于大多数人来说，遵循本书中提出的相同指南可能更容易，但选择权在您手中。

以下步骤将在 IntelliJ IDEA 中创建一个新的 Gradle 项目：

1.  打开 IntelliJ IDEA。单击创建新项目，然后从左侧菜单中选择 Gradle。然后，单击下一步。

1.  如果您使用的是 IDEA 14 及更高版本，则会要求您输入 Artifact ID。键入`tdd-java-ch03-tic-tac-toe`，然后单击两次“下一步”。将`tdd-java-ch03-tic-tac-toe`输入为项目名称。然后，单击“完成”按钮：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/5fd91dbe-7381-43e8-a2c3-c64d6b955ea6.png)

在新项目对话框中，我们可以观察到 IDEA 已经创建了`build.gradle`文件。打开它，你会看到它已经包含了 JUnit 依赖项。由于这是本章中我们选择的框架，因此我们不需要进行额外的配置。默认情况下，`build.gradle`设置为使用 Java 1.5 作为源兼容性设置。您可以将其更改为任何您喜欢的版本。本章的示例不会使用 Java 5 版本之后的任何功能，但这并不意味着您不能使用其他版本，例如 JDK 8 来解决练习。

我们的`build.gradle`文件应该如下所示：

```java
apply plugin: 'java' 

version = '1.0' 

repositories { 
  mavenCentral()
} 

dependencies { 
  testCompile group: 'junit', name: 'junit', version: '4.11' 
} 
```

现在，剩下的就是创建我们将用于测试和实现的包。从项目对话框中，右键单击以弹出上下文菜单，然后选择 New|Directory。键入`src/test/java/com/packtpublishing/tddjava/ch03tictactoe`，然后单击“确定”按钮以创建测试包。重复相同的步骤，使用`src/main/java/com/packtpublishing/tddjava/ch03tictactoe`目录创建实现包。

最后，我们需要创建测试和实现类。在`src/test/java`目录中的`com.packtpublishing.tddjava.ch03tictactoe`包内创建`TicTacToeSpec`类。这个类将包含所有我们的测试。在`src/main/java`目录中的`TicTacToe`类中重复相同的操作。

你的项目结构应该类似于以下截图中呈现的结构：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/862be672-6457-43c7-b2e0-bad2d7b0925b.png)

源代码可以在`00-setup`分支的`tdd-java-ch03-tic-tac-toe` Git 存储库中找到，网址为[`bitbucket.org/vfarcic/tdd-java-ch03-tic-tac-toe/branch/00-setup`](https://bitbucket.org/vfarcic/tdd-java-ch03-tic-tac-toe/branch/00-setup)。

始终将测试与实现代码分开。

好处如下：这样可以避免意外地将测试与生产二进制文件打包在一起；许多构建工具期望测试位于特定的源目录中。

一个常见的做法是至少有两个源目录。实现代码应该位于`src/main/java`，测试代码位于`src/test/java`。在更大的项目中，源目录的数量可能会增加，但实现和测试之间的分离应该保持不变。

Maven 和 Gradle 等构建工具期望源目录、分离以及命名约定。

就是这样。我们准备使用 JUnit 作为首选的测试框架，使用 Gradle 进行编译、依赖、测试和其他任务，开始开发我们的井字游戏应用程序。在第一章中，*为什么我应该关心测试驱动开发？*，你首次遇到了红-绿-重构过程。由于它是 TDD 的基石，并且是本章练习的主要目标，可能是一个好主意在开始开发之前更详细地了解一下。

# 红-绿-重构过程

红-绿-重构过程是 TDD 的最重要部分。这是主要支柱，没有它，TDD 的其他方面都无法运行。

名称来自于代码在循环中所处的状态。在红色状态下，代码不起作用；在绿色状态下，一切都按预期工作，但不一定是最佳方式。重构是一个阶段，我们知道功能已经得到了充分的测试覆盖，因此我们有信心对其进行更改并使其更好。

# 编写测试

每个新功能都以测试开始。这个测试的主要目标是在编写代码之前专注于需求和代码设计。测试是一种可执行文档，以后可以用来理解代码的功能或意图。

此时，我们处于红色状态，因为测试执行失败。测试对代码的期望与实现代码实际执行的不一致。更具体地说，没有代码满足最后一个测试的期望；我们还没有编写它。在这个阶段，所有测试实际上都通过了，但这是一个问题的迹象。

# 运行所有测试，并确认最后一个测试失败

确认最后一个测试失败，确认测试不会误以为没有引入新代码而通过。如果测试通过，那么该功能已经存在，或者测试产生了错误的积极结果。如果是这种情况，测试实际上总是独立于实现而通过，那么它本身是毫无价值的，应该被移除。

测试不仅必须失败，而且必须因为预期的原因而失败。在这个阶段，我们仍然处于红色阶段。测试已经运行，最后一个测试失败了。

# 编写实现代码

这个阶段的目的是编写代码，使最后一个测试通过。不要试图让它完美，也不要花太多时间。如果它写得不好或者不是最佳的，那也没关系。以后会变得更好。我们真正想做的是创建一种以测试形式确认通过的安全网。不要试图引入任何上一个测试中没有描述的功能。要做到这一点，我们需要回到第一步，从新的测试开始。然而，在所有现有测试都通过之前，我们不应该编写新的测试。

在这个阶段，我们仍处于红色阶段。虽然编写的代码可能会通过所有测试，但这个假设尚未得到确认。

# 运行所有测试

非常重要的是运行所有的测试，而不仅仅是最后编写的测试。我们刚刚编写的代码可能使最后一个测试通过，同时破坏了其他东西。运行所有的测试不仅确认了最后一个测试的实现是正确的，而且确认了它没有破坏整个应用程序的完整性。整个测试套件的缓慢执行表明测试编写不好或者代码耦合度太高。耦合阻止了外部依赖的轻松隔离，从而增加了测试执行所需的时间。

在这个阶段，我们处于绿色状态。所有的测试都通过了，应用程序的行为符合我们的预期。

# 重构

虽然所有之前的步骤都是强制性的，但这一步是可选的。尽管重构很少在每个周期结束时进行，但迟早会被期望，如果不是强制的。并不是每个测试的实现都需要重构。没有规则告诉你何时重构何时不重构。最佳时间是一旦有一种感觉，代码可以以更好或更优的方式重写时。

什么构成重构的候选？这是一个难以回答的问题，因为它可能有很多答案——难以理解的代码、代码片段的不合理位置、重复、名称不清晰的目的、长方法、做太多事情的类等等。列表可以继续下去。无论原因是什么，最重要的规则是重构不能改变任何现有功能。

# 重复

一旦所有步骤（重构是可选的）完成，我们就重复它们。乍一看，整个过程可能看起来太长或太复杂，但实际上并不是。有经验的 TDD 从业者在切换到下一步之前写一到十行代码。整个周期应该持续几秒钟到几分钟。如果时间超过这个范围，测试的范围就太大，应该分成更小的块。快速失败，纠正，重复。

有了这些知识，让我们通过使用红-绿-重构过程开发的应用程序的要求。

# 井字游戏要求

井字游戏通常由年幼的孩子玩。游戏规则相当简单。

井字游戏是一种纸笔游戏，供两名玩家*X*和*O*轮流在 3×3 的网格中标记空格。成功在水平、垂直或对角线上放置三个相应标记的玩家获胜。

有关游戏的更多信息，请访问维基百科（[`en.wikipedia.org/wiki/Tic-tac-toe`](http://en.wikipedia.org/wiki/Tic-tac-toe)）。

更详细的要求将在以后提出。

这个练习包括创建一个与需求相对应的单个测试。测试后面是满足该测试期望的代码。最后，如果需要，对代码进行重构。应该重复相同的过程，直到满意为止，然后转移到下一个需求，直到所有需求都完成。

在现实世界的情况下，您不会得到如此详细的要求，但是可以直接进行既是要求又是验证的测试。然而，在您熟悉 TDD 之前，我们必须将需求与测试分开定义。

尽管所有的测试和实现都已经提供，但请一次只阅读一个需求，并自己编写测试和实现代码。完成后，将您的解决方案与本书中的解决方案进行比较，然后转到下一个需求。没有唯一的解决方案；您的解决方案可能比这里提供的更好。

# 开发井字棋

您准备好编码了吗？让我们从第一个需求开始。

# 需求 1-放置棋子

我们应该首先定义边界和什么构成了一个棋子的无效放置。

一个棋子可以放在 3×3 棋盘的任何空位上。

我们可以将这个需求分成三个测试：

+   当一个棋子被放置在*x*轴之外的任何地方，就会抛出`RuntimeException`

+   当一个棋子被放置在*y*轴之外的任何地方，就会抛出`RuntimeException`

+   当一个棋子被放在一个已占用的空间上时，就会抛出`RuntimeException`

正如您所看到的，与第一个需求相关的测试都是关于验证输入参数的。在需求中没有提到应该对这些棋子做什么。

在我们进行第一个测试之前，有必要简要解释一下如何使用 JUnit 测试异常。

从 4.7 版本开始，JUnit 引入了一个名为`Rule`的功能。它可以用于执行许多不同的操作（更多信息可以在[`github.com/junit-team/junit/wiki/Rules`](https://github.com/junit-team/junit/wiki/Rules)找到），但在我们的情况下，我们对`ExpectedException`规则感兴趣：

```java
public class FooTest {
  @Rule
  public ExpectedException exception = ExpectedException.none();
  @Test
  public void whenDoFooThenThrowRuntimeException() {
    Foo foo = new Foo();
    exception.expect(RuntimeException.class);
    foo.doFoo();
  }
} 
```

在这个例子中，我们定义了`ExpectedException`是一个规则。稍后在`doFooThrowsRuntimeException`测试中，我们指定我们期望在`Foo`类实例化后抛出`RuntimeException`。如果在之前抛出，测试将失败。如果在之后抛出，测试就成功了。

`@Before`可以用来注释一个在每个测试之前运行的方法。这是一个非常有用的功能，例如我们可以实例化一个在测试中使用的类，或者执行一些其他类型的在每个测试之前运行的操作：

```java
private Foo foo; 

@Before 
public final void before() { 
  foo = new Foo(); 
} 
```

在这个例子中，`Foo`类将在每个测试之前实例化。这样，我们就可以避免在每个测试方法中实例化`Foo`的重复代码。

每个测试都应该用`@Test`进行注释。这告诉`JunitRunner`哪些方法构成测试。它们中的每一个都将以随机顺序运行，所以确保每个测试都是自给自足的，并且不依赖于其他测试可能创建的状态：

```java
@Test 
public void whenSomethingThenResultIsSomethingElse() { 
  // This is a test method 
} 
```

有了这个知识，您应该能够编写您的第一个测试，并跟随着实现。完成后，将其与提供的解决方案进行比较。

为测试方法使用描述性的名称。

其中一个好处是它有助于理解测试的目标。

在尝试弄清楚为什么一些测试失败或者测试覆盖率应该增加更多测试时，使用描述测试的方法名称是有益的。在测试之前应该清楚地设置条件，执行什么操作，以及预期的结果是什么。

有许多不同的方法来命名测试方法。我偏好的方法是使用 BDD 场景中使用的给定/当/那么语法来命名它们。`给定`描述（前）条件，`当`描述动作，`那么`描述预期结果。如果一个测试没有前提条件（通常使用`@Before`和`@BeforeClass`注解设置），`给定`可以被省略。

不要仅依靠注释提供有关测试目标的信息。注释在从您喜爱的 IDE 执行测试时不会出现，也不会出现在 CI 或构建工具生成的报告中。

除了编写测试，你还需要运行它们。由于我们使用 Gradle，它们可以从命令提示符中运行：

```java
    $ gradle test
```

IntelliJ IDEA 提供了一个非常好的 Gradle 任务模型，可以通过点击 View|Tool Windows|Gradle 来访问。它列出了所有可以使用 Gradle 运行的任务（其中之一就是`test`）。

选择权在你手中-你可以以任何你认为合适的方式运行测试，只要你运行所有测试。

# 测试-板边界 I

我们应该首先检查一个棋子是否放在 3x3 棋盘的边界内：

```java
package com.packtpublishing.tddjava.ch03tictactoe;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class TicTacToeSpec {
  @Rule
  public ExpectedException exception = ExpectedException.none();
  private TicTacToe ticTacToe;

  @Before
  public final void before() {
    ticTacToe = new TicTacToe();
  }
  @Test
  public void whenXOutsideBoardThenRuntimeException() {
    exception.expect(RuntimeException.class);
    ticTacToe.play(5, 2);
  }
} 
```

当一个棋子被放置在*x*轴之外的任何地方时，会抛出`RuntimeException`。

在这个测试中，我们定义了当调用`ticTacToe.play(5, 2)`方法时，会抛出`RuntimeException`。这是一个非常简短和简单的测试，使其通过也应该很容易。我们所要做的就是创建`play`方法，并确保当`x`参数小于 1 或大于 3（棋盘是 3x3）时抛出`RuntimeException`。你应该运行这个测试三次。第一次，它应该失败，因为`play`方法不存在。一旦添加了它，它应该失败，因为没有抛出`RuntimeException`。第三次，它应该成功，因为与这个测试对应的代码已经完全实现。

# 实施

现在我们清楚了什么时候应该抛出异常，实现应该很简单：

```java
package com.packtpublishing.tddjava.ch03tictactoe;

public class TicTacToe {
  public void play(int x, int y) {
    if (x < 1 || x > 3) {
      throw new RuntimeException("X is outside board");
    }
  }
}
```

正如你所看到的，这段代码除了让测试通过所需的最低限度之外，没有别的东西。

一些 TDD 实践者倾向于将最小化理解为字面意义。他们会让`play`方法只有`throw new RuntimeException();`这一行。我倾向于将最小化理解为在合理范围内尽可能少。

我们不添加数字，也不返回任何东西。这一切都是关于非常快速地进行小的更改。（记住乒乓球游戏吗？）目前，我们正在进行红绿步骤。我们无法做太多来改进这段代码，所以我们跳过了重构。

让我们继续进行下一个测试。

# 测试-板边界 II

这个测试几乎与上一个测试相同。这次我们应该验证*y*轴：

```java
@Test
public void whenYOutsideBoardThenRuntimeException() {
  exception.expect(RuntimeException.class);
  ticTacToe.play(2, 5);
}
```

当一个棋子被放置在*y*轴之外的任何地方时，会抛出`RuntimeException`。

# 实施

这个规范的实现几乎与上一个相同。我们所要做的就是如果`y`不在定义的范围内，则抛出异常：

```java
public void play(int x, int y) {
  if (x < 1 || x > 3) {
    throw new RuntimeException("X is outside board");
  } else if (y < 1 || y > 3) {
    throw new RuntimeException("Y is outside board");
  }
}
```

为了让最后一个测试通过，我们必须添加检查`Y`是否在棋盘内的`else`子句。

让我们为这个要求做最后一个测试。

# 测试-占用的位置

现在我们知道棋子是放在棋盘边界内的，我们应该确保它们只能放在未占用的空间上：

```java
@Test 
public void whenOccupiedThenRuntimeException() { 
  ticTacToe.play(2, 1); 
  exception.expect(RuntimeException.class); 
  ticTacToe.play(2, 1); 
} 
```

当一个棋子被放在一个已占用的空间上时，会抛出`RuntimeException`。

就是这样；这是我们的最后一个测试。一旦实现完成，我们就可以认为第一个要求已经完成了。

# 实施

要实现最后一个测试，我们应该将放置的棋子的位置存储在一个数组中。每次放置一个新的棋子时，我们应该验证该位置是否被占用，否则抛出异常：

```java
private Character[][] board = {
  {'\0', '\0', '\0'},
  {'\0', '\0', '\0'},
  {'\0', '\0', '\0'}
};

public void play(int x, int y) {
  if (x < 1 || x > 3) {
    throw new RuntimeException("X is outside board");
  } else if (y < 1 || y > 3) {
    throw new RuntimeException("Y is outside board");
  }
  if (board[x - 1][y - 1] != '\0') {
    throw new RuntimeException("Box is occupied");
  } else {
    board[x - 1][y - 1] = 'X';
  }
}
```

我们正在检查所玩的位置是否被占用，如果没有被占用，我们将数组条目值从空（`\0`）更改为占用（`X`）。请记住，我们仍然没有存储是谁玩的（`X`还是`O`）。

# 重构

到目前为止，我们所做的代码满足了测试设置的要求，但看起来有点混乱。如果有人阅读它，就不清楚`play`方法的作用。我们应该通过将代码移动到单独的方法中来重构它。重构后的代码将如下所示：

```java
public void play(int x, int y) {
  checkAxis(x);
  checkAxis(y);
  setBox(x, y);
}

private void checkAxis(int axis) {
  if (axis < 1 || axis > 3) {
    throw new RuntimeException("X is outside board");
  }
}

private void setBox(int x, int y) {
  if (board[x - 1][y - 1] != '\0') {
    throw new RuntimeException("Box is occupied");
  } else {
    board[x - 1][y - 1] = 'X';
  }
}
```

通过这种重构，我们没有改变`play`方法的功能。它的行为与以前完全相同，但新代码更易读。由于我们有测试覆盖了所有现有功能，所以不用担心我们可能做错了什么。只要所有测试一直通过，重构没有引入任何新的行为，对代码进行更改就是安全的。

源代码可以在`01-exceptions` Git 存储库的`tdd-java-ch03-tic-tac-toe`分支中找到[`bitbucket.org/vfarcic/tdd-java-ch03-tic-tac-toe/branch/01-exceptions`](https://bitbucket.org/vfarcic/tdd-java-ch03-tic-tac-toe/branch/01-exceptions)。

# 需求 2-添加双人支持

现在是时候开始规范哪个玩家即将轮到他出手了。

应该有一种方法来找出下一个应该出手的玩家。

我们可以将这个需求分成三个测试：

+   第一轮应该由玩家`X`来玩

+   如果上一轮是由`X`玩的，那么下一轮应该由`O`玩。

+   如果上一轮是由`O`玩的，那么下一轮应该由`X`玩。

到目前为止，我们还没有使用任何 JUnit 的断言。要使用它们，我们需要从`org.junit.Assert`类中`import`静态方法：

```java
import static org.junit.Assert.*;
```

在`Assert`类内部，方法的本质非常简单。它们中的大多数以`assert`开头。例如，`assertEquals`比较两个对象-`assertNotEquals`验证两个对象不相同，`assertArrayEquals`验证两个数组相同。每个断言都有许多重载的变体，以便几乎可以使用任何类型的 Java 对象。

在我们的情况下，我们需要比较两个字符。第一个是我们期望的字符，第二个是从`nextPlayer`方法中检索到的实际字符。

现在是时候编写这些测试和实现了。

在编写实现代码之前编写测试。

这样做的好处如下-它确保编写可测试的代码，并确保为每一行代码编写测试。

通过先编写或修改测试，开发人员在开始编写代码之前专注于需求。这是与在实施完成后编写测试相比的主要区别。另一个好处是，有了先验测试，我们避免了测试作为质量检查而不是质量保证的危险。

# 测试- X 先玩

玩家`X`有第一轮：

```java
@Test
public void givenFirstTurnWhenNextPlayerThenX() {
  assertEquals('X', ticTacToe.nextPlayer());
}
```

第一轮应该由玩家`X`来玩。

这个测试应该是不言自明的。我们期望`nextPlayer`方法返回`X`。如果你尝试运行这个测试，你会发现代码甚至无法编译。那是因为`nextPlayer`方法甚至不存在。我们的工作是编写`nextPlayer`方法，并确保它返回正确的值。

# 实施

没有真正的必要检查是否真的是玩家的第一轮。就目前而言，这个测试可以通过始终返回`X`来实现。稍后的测试将迫使我们完善这段代码：

```java
public char nextPlayer() {
  return 'X';
}
```

# 测试- O 在 X 之后玩

现在，我们应该确保玩家在变化。在`X`完成后，应该轮到`O`，然后再次是`X`，依此类推：

```java
@Test
public void givenLastTurnWasXWhenNextPlayerThenO() {
  ticTacToe.play(1, 1);
  assertEquals('O', ticTacToe.nextPlayer());
}
```

如果上一轮是由`X`玩的，那么下一轮应该由`O`玩。

# 实施

为了追踪谁应该下一步出手，我们需要存储上一次出手的玩家：

```java
private char lastPlayer = '\0';

public void play(int x, int y) {
  checkAxis(x);
  checkAxis(y);
  setBox(x, y);
  lastPlayer = nextPlayer();
}

public char nextPlayer() {
  if (lastPlayer == 'X') {
    return 'O';
  }
  return 'X';
}
```

你可能开始掌握了。测试很小，很容易写。有了足够的经验，应该只需要一分钟，甚至几秒钟来编写一个测试，编写实现的时间也不会超过这个时间。

# 测试- X 在 O 之后玩

最后，我们可以检查`O`下完棋后是否轮到`X`下棋。

如果最后一步是由`O`下的，那么下一步应该由`X`下。

没有什么可以做来满足这个测试，因此这个测试是无用的，应该被丢弃。如果你写这个测试，你会发现它是一个错误的阳性。它会在不改变实现的情况下通过；试一下。写下这个测试，如果它成功了而没有写任何实现代码，就把它丢弃。

源代码可以在`tdd-java-ch03-tic-tac-toe` Git 存储库的`02-next-player`分支中找到[`bitbucket.org/vfarcic/tdd-java-ch03-tic-tac-toe/branch/02-next-player`](https://bitbucket.org/vfarcic/tdd-java-ch03-tic-tac-toe/branch/02-next-player)。

# 需求 3 - 添加获胜条件

现在是根据游戏规则来处理获胜的时候了。与之前的代码相比，这部分工作变得有点繁琐。我们应该检查所有可能的获胜组合，如果其中一个被满足，就宣布获胜者。

玩家通过首先连接棋盘的一侧或角落到另一侧的友方棋子线来获胜。

为了检查友方棋子线是否连接，我们应该验证水平、垂直和对角线。

# 测试 - 默认情况下没有赢家

让我们从定义`play`方法的默认响应开始：

```java
@Test
public void whenPlayThenNoWinner() {
  String actual = ticTacToe.play(1,1);
  assertEquals("No winner", actual);
}
```

如果没有满足获胜条件，那么就没有赢家。

# 实施

默认返回值总是最容易实现的，这个也不例外：

```java
public String play(int x, int y) {
  checkAxis(x);
  checkAxis(y);
  setBox(x, y);
  lastPlayer = nextPlayer();
  return "No winner";
}
```

# 测试 - 获胜条件 I

现在我们已经声明了默认响应是“没有赢家”，是时候开始处理不同的获胜条件了：

```java
@Test
public void whenPlayAndWholeHorizontalLineThenWinner() {
  ticTacToe.play(1, 1); // X
  ticTacToe.play(1, 2); // O
  ticTacToe.play(2, 1); // X
  ticTacToe.play(2, 2); // O
  String actual = ticTacToe.play(3, 1); // X
  assertEquals("X is the winner", actual);
}
```

玩家赢得比赛当整个水平线被他的棋子占据。

# 实施

为了完成这个测试，我们需要检查是否有任何水平线被当前玩家的标记填满。直到此刻，我们并不关心棋盘数组上放了什么。现在，我们不仅需要介绍哪些棋盘格子是空的，还需要介绍哪个玩家下的棋：

```java
public String play(int x, int y) {
  checkAxis(x);
  checkAxis(y);
  lastPlayer = nextPlayer();
  setBox(x, y, lastPlayer);
  for (int index = 0; index < 3; index++) {
    if (board[0][index] == lastPlayer
        && board[1][index] == lastPlayer
        && board[2][index] == lastPlayer) {
      return lastPlayer + " is the winner";
    }
  }
  return "No winner";
}
private void setBox(int x, int y, char lastPlayer) {
  if (board[x - 1][y - 1] != '\0') {
    throw new RuntimeException("Box is occupied");
  } else {
    board[x - 1][y - 1] = lastPlayer;
  }
}
```

# 重构

前面的代码满足了测试，但不一定是最终版本。它达到了尽快实现代码覆盖率的目的。现在，既然我们有了测试来保证预期行为的完整性，我们可以重构代码了：

```java
private static final int SIZE = 3;

public String play(int x, int y) {
  checkAxis(x);
  checkAxis(y);
  lastPlayer = nextPlayer();
  setBox(x, y, lastPlayer);
  if (isWin()) {
    return lastPlayer + " is the winner";
  }
  return "No winner";
}

private boolean isWin() {
  for (int i = 0; i < SIZE; i++) {
    if (board[0][i] + board[1][i] + board[2][i] == (lastPlayer * SIZE)) {
      return true;
    }
  }
  return false;
}
```

这个重构后的解决方案看起来更好。`play`方法保持简短易懂。获胜逻辑被移动到一个单独的方法中。我们不仅保持了`play`方法的目的清晰，而且这种分离还允许我们将获胜条件的代码与其余部分分开发展。

# 测试 - 获胜条件 II

我们还应该检查是否通过填充垂直线来获胜：

```java
@Test
public void whenPlayAndWholeVerticalLineThenWinner() {
  ticTacToe.play(2, 1); // X
  ticTacToe.play(1, 1); // O
  ticTacToe.play(3, 1); // X
  ticTacToe.play(1, 2); // O
  ticTacToe.play(2, 2); // X
  String actual = ticTacToe.play(1, 3); // O
  assertEquals("O is the winner", actual);
}
```

玩家赢得比赛当整个垂直线被他的棋子占据。

# 实施

这个实现应该类似于之前的实现。我们已经有了水平验证，现在我们需要做垂直验证：

```java
private boolean isWin() {
  int playerTotal = lastPlayer * 3;
  for (int i = 0; i < SIZE; i++) {
    if (board[0][i] + board[1][i] + board[2][i] == playerTotal) {
      return true;
    } else if (board[i][0] + board[i][1] + board[i][2] == playerTotal) {
      return true;
    }
  }
  return false;
}
```

# 测试 - 获胜条件 III

现在水平和垂直线都已经覆盖，我们应该把注意力转移到对角线组合上：

```java
@Test 
public void whenPlayAndTopBottomDiagonalLineThenWinner() {
  ticTacToe.play(1, 1); // X
  ticTacToe.play(1, 2); // O
  ticTacToe.play(2, 2); // X
  ticTacToe.play(1, 3); // O
  String actual = ticTacToe.play(3, 3); // X
  assertEquals("X is the winner", actual);
}
```

玩家赢得比赛当整个从左上到右下的对角线被他的棋子占据。

# 实施

由于只有一条线符合要求，我们可以直接检查它，而不需要任何循环：

```java
private boolean isWin() {
  int playerTotal = lastPlayer * 3;
  for (int i = 0; i < SIZE; i++) {
    if (board[0][i] + board[1][i] + board[2][i] == playerTotal) {
      return true;
    } else if (board[i][0] + board[i][1] + board[i][2] == playerTotal) {
      return true;
    } 
  } 
  if (board[0][0] + board[1][1] + board[2][2] == playerTotal) { 
    return true; 
  }   
  return false; 
} 
```

# 代码覆盖率

在整个练习过程中，我们没有使用代码覆盖工具。原因是我们希望您专注于红-绿-重构模型。您编写了一个测试，看到它失败，编写了实现代码，看到所有测试都成功执行，然后在看到机会使代码更好时重构了代码，然后重复了这个过程。我们的测试覆盖了所有情况吗？这是 JaCoCo 等代码覆盖工具可以回答的问题。您应该使用这些工具吗？可能只有在开始时。让我澄清一下。当您开始使用 TDD 时，您可能会错过一些测试或者实现超出了测试定义的内容。在这些情况下，使用代码覆盖是从自己的错误中学习的好方法。随着您在 TDD 方面的经验增加，您对这些工具的需求将会减少。您将编写测试，并编写足够的代码使其通过。无论是否使用 JaCoCo 等工具，您的覆盖率都会很高。由于您会对不值得测试的内容做出有意识的决定，因此只有少量代码不会被测试覆盖。

诸如 JaCoCo 之类的工具主要是作为一种验证实现代码后编写的测试是否提供足够覆盖率的方式。通过 TDD，我们采用了不同的方法，即倒置顺序（先编写测试，再实现）。

尽管如此，我们建议您将 JaCoCo 作为学习工具，并自行决定是否在将来使用它。

要在 Gradle 中启用 JaCoCo，请将以下内容添加到`build.gradle`中：

```java
apply plugin: 'jacoco'
```

从现在开始，每次运行测试时，Gradle 都会收集 JaCoCo 指标。这些指标可以使用`jacocoTestReport` Gradle 目标转换为漂亮的报告。让我们再次运行测试，看看代码覆盖率是多少：

```java
$ gradle clean test jacocoTestReport
```

最终结果是报告位于`build/reports/jacoco/test/html`目录中。结果将取决于您为此练习制定的解决方案。我的结果显示指令覆盖率为 100%，分支覆盖率为 96%；缺少 4%是因为没有测试案例中玩家在 0 或负数的方框上下棋。该情况的实现已经存在，但没有特定的测试覆盖它。总的来说，这是一个相当不错的覆盖率。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/ad410f3d-0ec5-4109-a35a-0e9ca579d7d7.png)

JaCoCo 将被添加到源代码中。这可以在`05-jacoco`分支的` tdd-java-ch03-tic-tac-toe` Git 存储库中找到，网址为[`bitbucket.org/vfarcic/tdd-java-ch03-tic-tac-toe/branch/05-jacoco`](https://bitbucket.org/vfarcic/tdd-java-ch03-tic-tac-toe/branch/05-jacoco)。

# 测试 - 获胜条件 IV

最后，还有最后一个可能的获胜条件要解决：

```java
@Test
public void whenPlayAndBottomTopDiagonalLineThenWinner() {
  ticTacToe.play(1, 3); // X
  ticTacToe.play(1, 1); // O
  ticTacToe.play(2, 2); // X
  ticTacToe.play(1, 2); // O
  String actual = ticTacToe.play(3, 1); // X
  assertEquals("X is the winner", actual);
}
```

当整个对角线从左下到右上的线被玩家的棋子占据时，玩家获胜。

# 实现

这个测试的实现应该几乎与上一个相同：

```java
private boolean isWin() {
  int playerTotal = lastPlayer * 3;
  for (int i = 0; i < SIZE; i++) {
    if (board[0][i] + board[1][i] + board[2][i] == playerTotal) {
      return true;
    } else if (board[i][0] + board[i][1] + board[i][2] == playerTotal) {
      return true;
    }
  }
  if (board[0][0] + board[1][1] + board[2][2] == playerTotal) {
    return true;
  } else if (board[0][2] + board[1][1] + board[2][0] == playerTotal) {
    return true;
  }
  return false;
}
```

# 重构

我们处理可能的对角线获胜的方式，计算看起来不对。也许重新利用现有的循环会更有意义：

```java
private boolean isWin() {
  int playerTotal = lastPlayer * 3;
  char diagonal1 = '\0';
  char diagonal2 = '\0';
  for (int i = 0; i < SIZE; i++) {
    diagonal1 += board[i][i];
    diagonal2 += board[i][SIZE - i - 1];
    if (board[0][i] + board[1][i] + board[2][i]) == playerTotal) {
      return true;
    } else if (board[i][0] + board[i][1] + board[i][2] == playerTotal) {
      return true;
    }
  }
  if (diagonal1 == playerTotal || diagonal2 == playerTotal) {
    return true;
  }
  return false;
}
```

源代码可以在` tdd-java-ch03-tic-tac-toe` Git 存储库的`03-wins`分支中找到，网址为[`bitbucket.org/vfarcic/tdd-java-ch03-tic-tac-toe/branch/03-wins`](https://bitbucket.org/vfarcic/tdd-java-ch03-tic-tac-toe/branch/03-wins)。

现在，让我们来看最后一个要求。

# 要求 4 - 平局条件

唯一缺少的是如何处理平局结果。

当所有方框都填满时，结果是平局。

# 测试 - 处理平局情况

我们可以通过填满棋盘上的所有方框来测试平局结果：

```java
@Test
public void whenAllBoxesAreFilledThenDraw() {
  ticTacToe.play(1, 1);
  ticTacToe.play(1, 2);
  ticTacToe.play(1, 3);
  ticTacToe.play(2, 1);
  ticTacToe.play(2, 3);
  ticTacToe.play(2, 2);
  ticTacToe.play(3, 1);
  ticTacToe.play(3, 3);
  String actual = ticTacToe.play(3, 2);
  assertEquals("The result is draw", actual);
}
```

# 实现

检查是否为平局非常简单。我们只需要检查棋盘上的所有方框是否都填满了。我们可以通过遍历棋盘数组来做到这一点：

```java
public String play(int x, int y) {
  checkAxis(x);
  checkAxis(y);
  lastPlayer = nextPlayer();
  setBox(x, y, lastPlayer);
  if (isWin()) {
    return lastPlayer + " is the winner";
  } else if (isDraw()) {
    return "The result is draw";
  } else {
    return "No winner";
  }
}

private boolean isDraw() {
  for (int x = 0; x < SIZE; x++) {
    for (int y = 0; y < SIZE; y++) {
      if (board[x][y] == '\0') {
        return false;
      }
    }
  }
  return true;
}
```

# 重构

尽管`isWin`方法不是最后一个测试的范围，但它仍然可以进行更多的重构。首先，我们不需要检查所有的组合，而只需要检查与最后一个放置的棋子位置相关的组合。最终版本可能如下所示：

```java
private boolean isWin(int x, int y) {
  int playerTotal = lastPlayer * 3;
  char horizontal, vertical, diagonal1, diagonal2;
  horizontal = vertical = diagonal1 = diagonal2 = '\0';
  for (int i = 0; i < SIZE; i++) {
    horizontal += board[i][y - 1];
    vertical += board[x - 1][i];
    diagonal1 += board[i][i];
    diagonal2 += board[i][SIZE - i - 1];
  }
  if (horizontal == playerTotal
      || vertical == playerTotal
      || diagonal1 == playerTotal
      || diagonal2 == playerTotal) {
    return true;
  }
  return false;
} 
```

重构可以在任何时候的代码的任何部分进行，只要所有测试都成功。虽然通常最容易和最快的是重构刚刚编写的代码，但是回到前天、上个月甚至几年前编写的代码也是非常受欢迎的。重构的最佳时机是当有人看到使其更好的机会时。不管是谁编写的或者何时编写的，使代码更好总是一件好事。

源代码可以在`04-draw` Git 存储库的`tdd-java-ch03-tic-tac-toe`分支中找到，网址为[`bitbucket.org/vfarcic/tdd-java-ch03-tic-tac-toe/branch/04-draw`](https://bitbucket.org/vfarcic/tdd-java-ch03-tic-tac-toe/branch/04-draw)。

# 更多练习

我们刚刚开发了一个（最常用的）井字棋游戏变体。作为额外的练习，从维基百科（[`en.wikipedia.org/wiki/Tic-tac-toe`](http://en.wikipedia.org/wiki/Tic-tac-toe)）中选择一个或多个变体，并使用红-绿-重构程序实现它。完成后，实现一种能够玩`O`的回合的人工智能。由于井字棋通常导致平局，当 AI 成功达到任何`X`的移动组合时，可以认为 AI 已经完成。

在做这些练习时，记得要快速并进行乒乓对打。最重要的是，记得要使用红-绿-重构程序。

# 总结

我们成功地使用红-绿-重构过程完成了我们的井字棋游戏。这些例子本身很简单，你可能没有问题跟随它们。

本章的目标不是深入研究复杂的东西（这将在后面进行），而是养成使用称为红-绿-重构的短而重复的循环习惯。

我们学到了开发某物最简单的方法是将其分解成非常小的块。设计是从测试中出现的，而不是采用大量的前期方法。没有一行实现代码是在没有先编写测试并看到它失败的情况下编写的。通过确认最后一个测试失败，我们确认它是有效的（很容易出错并编写一个始终成功的测试），并且我们即将实现的功能不存在。测试失败后，我们编写了该测试的实现。在编写实现时，我们试图使其尽可能简化，目标是使测试通过，而不是使解决方案最终化。我们重复这个过程，直到我们感到有必要重构代码。重构不会引入任何新功能（我们没有改变应用程序的功能），但会使代码更加优化，更易于阅读和维护。

在下一章中，我们将更详细地阐述在 TDD 环境中什么构成了一个单元，以及如何根据这些单元的创建测试。
