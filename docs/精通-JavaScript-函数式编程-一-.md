# 精通 JavaScript 函数式编程（一）

> 原文：[`zh.annas-archive.org/md5/C4CB5F08EDA7F6C7DED597C949390410`](https://zh.annas-archive.org/md5/C4CB5F08EDA7F6C7DED597C949390410)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在计算机编程中，范式层出不穷：一些例子包括命令式编程、结构化（*少用 goto*）编程、面向对象编程、面向方面编程和声明式编程。最近，对一种可以说比大多数（如果不是全部）上述范式更古老的范式重新产生了兴趣——函数式编程。**函数式编程**（**FP**）强调编写函数，并以简单的方式连接它们，以产生更易理解和更易测试的代码。因此，鉴于今天的 Web 应用程序的复杂性增加，逻辑上会对更安全、更清洁的编程方式产生兴趣。

对 FP 的兴趣与 JavaScript 的发展息息相关。尽管 JavaScript 的创建有些仓促（据说是由 Netscape 的 Brendan Eich 在 1995 年仅用了 10 天完成），但今天它是一种标准化和迅速增长的语言，具有比大多数其他类似流行语言更先进的特性。这种语言的普及性，现在可以在浏览器、服务器、手机等各种设备上找到，也推动了对更好的开发策略的兴趣。此外，即使 JavaScript 本身并不是作为一种函数语言而构思的，事实上它提供了你在这种方式下所需的所有功能，这也是一个优点。

还必须说一下，FP 并没有被广泛应用于工业中，可能是因为它有一定的难度，被认为是*理论性*而不是*实用性*，甚至*数学性*，可能使用的词汇和概念对开发人员来说是陌生的——函子？单子？折叠？范畴论？虽然学习所有这些理论肯定会有所帮助，但也可以说，即使对上述术语一无所知，你也可以理解 FP 的原则，并看到如何将其应用于你的编程。

FP 不是你必须独自完成的事情，没有任何帮助。有许多库和框架，以不同程度融合了 FP 的概念。从 jQuery 开始（其中包括一些 FP 概念），经过 Underscore 及其近亲 LoDash，或其他库如 Ramda，再到更完整的 Web 开发工具如 React 和 Redux，Angular，或 Elm（一种 100%的函数语言，可以编译成 JavaScript），用于编码的功能性辅助工具列表不断增长。

学习如何使用 FP 可能是一项值得投资的事情，即使你可能无法使用其所有方法和技术，只要开始应用其中的一些方法，就会在编写更好的代码方面获得回报。你不需要从一开始就尝试应用 FP 的所有内容，也不需要试图放弃语言中的每一个非函数特性。JavaScript 确实有一些不好的特性，但也有一些非常好和强大的特性。关键不是要抛弃你学到的和使用的一切，然后采用 100%的函数式方式；相反，指导思想是*演变，而不是革命*。在这个意义上，可以说我们要做的不是 FP，而是**有点函数式编程**（**SFP**），旨在融合不同的范式。

关于本书中代码风格的最后一点评论——确实有一些非常好的库，可以为你提供函数式编程工具：Underscore、LoDash、Ramda 等等。然而，我更倾向于避免使用它们，因为我想展示事物的真实运行方式。应用某个包中的给定函数很容易，但通过编写所有代码（如果你愿意，可以称之为*纯 FP*），我相信你可以更深入地理解事物。此外，正如我在某些地方所评论的，由于箭头函数和其他特性的强大和清晰，*纯 JS*版本甚至更容易理解！

# 本书涵盖的内容

在本书中，我们将以实际的方式涵盖**函数式编程**（**FP**），尽管有时我们会提到一些理论观点：

第一章，*成为函数式-几个问题*，讨论了函数式编程，给出了使用它的原因，并列出了您需要利用本书其余部分的工具。

第二章，*功能性思维-第一个例子*，将通过考虑一个常见的与 Web 相关的问题，并讨论几种解决方案，最终专注于一种功能性的方式，提供了函数式编程的第一个例子。

第三章，*从函数开始-核心概念*，将介绍函数式编程的核心概念：函数，以及 JavaScript 中的不同选项。

第四章，*行为得体-纯函数*，将考虑纯度和纯函数的概念，并展示它如何导致更简单的编码和更容易的测试。

第五章，*声明式编程-更好的风格*，将使用简单的数据结构来展示如何以声明式的方式工作，而不是以命令式的方式。

第六章，*生成函数-高阶函数*，将处理高阶函数，它们接收其他函数作为参数，并产生新的函数作为结果。

第七章，*转换函数-柯里化和部分应用*，将展示一些从早期函数中产生新的专门函数的方法。

第八章，*连接函数-管道和组合*，将展示如何通过连接先前定义的函数来构建新函数的关键概念。

第九章，*设计函数-递归*，将展示函数式编程中的关键概念递归如何应用于设计算法和函数。

第十章，*确保纯净性-不可变性*，将展示一些工具，可以通过提供不可变对象和数据结构来帮助您以纯净的方式工作。

第十一章，*实现设计模式-函数式方式*，将展示在以函数式方式编程时如何实现（或不需要！）几种流行的面向对象设计模式。

第十二章，*构建更好的容器-函数数据类型*，将展示更高级的函数模式，介绍类型、容器、函子、单子以及其他更高级的函数式编程概念。

我试图保持示例简单和贴近实际，因为我想专注于功能方面，而不是纠缠于这个或那个问题的复杂性。有些编程文本是针对学习某个框架，然后解决特定问题，看如何用所选工具完全解决它。 （事实上，在规划这本书的最初阶段，我曾经考虑过开发一个应用程序，该应用程序将使用我心目中的所有函数式编程的东西，但是没有办法将所有内容都放入一个项目中。夸张一点说，我感觉自己像是一名医生，试图找到一个可以应用他所有医学知识和治疗方法的病人！）因此，我选择展示大量的个别技术，这些技术可以在多种情况下使用。我不想建造一座房子，我想向您展示如何把砖块放在一起，如何连接线路等，这样您就可以根据需要应用任何内容。

# 您需要为本书做好准备

要理解本书中的概念和代码，您不需要比 JavaScript 环境和文本编辑器更多的东西。老实说，我甚至开发了一些完全在线工作的示例，使用诸如 JSFiddle（在[`jsfiddle.net/`](https://jsfiddle.net/)）之类的工具，绝对没有其他东西。

然而，您需要一些关于最新版本的 JavaScript 的经验，因为它包括一些功能，可以帮助编写更简洁、更紧凑的代码。我们将经常包含指向在线文档的指针，例如 MDN（Mozilla Development Network）上可用的文档，以帮助您获得更深入的知识。

# 这本书是为谁准备的

这本书面向具有良好的 JavaScript 工作知识的程序员，无论是在客户端（浏览器）还是服务器端（Node.JS）工作，他们有兴趣应用技术来编写更好、可测试、可理解和可维护的代码。一些计算机科学背景（包括例如数据结构）和良好的编程实践也会派上用场。

# 约定

在这本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“只需将要激活的图层的名称分配给`VK_INSTANCE_LAYERS`环境变量”。

代码块设置如下：

```js
{
 if( (result != VK_SUCCESS) || 
 (extensions_count == 0) ) { 
 std::cout << "Could not enumerate device extensions." << std::endl; 
 return false;
} 
```

任何命令行输入或输出都以以下方式编写：

```js
setx VK_INSTANCE_LAYERS VK_LAYER_LUNARG_api_dump;VK_LAYER_LUNARG_core_validation
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中出现，就像这样：“从管理面板中选择系统信息”。

警告或重要说明会出现在这样的框中。提示和技巧会出现在这样。


# 第一章：成为函数式编程者——几个问题

- 函数式编程（通常缩写为 FP）自古以来就存在，并且由于它在几个框架和库中的广泛使用，尤其是在 JavaScript 中的增加使用，它正在经历一种复兴。在本章中，我们将：

+   介绍一些函数式编程的概念，给出一点点它的意义

+   展示使用函数式编程所暗示的好处（和问题）

+   开始思考为什么**JavaScript**（**JS**）可以被认为是适合函数式编程的语言

+   了解你应该注意的语言特性和工具，以充分利用本书中的一切

所以，让我们开始问自己*什么是函数式编程？*并开始研究这个主题。

# 什么是函数式编程？

如果你回顾计算机历史，你会发现仍在使用的第二古老的编程语言 LISP，它的基础就是函数式编程。从那时起，出现了许多更多的函数式语言，并且函数式编程得到了更广泛的应用。但即便如此，如果你询问函数式编程是什么，你可能会得到两种截然不同的答案。

根据你问的人，你要么会得知它是一种现代的、先进的、开明的编程方法，超越了其他范式，要么会被告知它主要是一个理论上的东西，比好处更多的是复杂性，在实际世界中几乎不可能实现。而且，通常情况下，真正的答案不在极端之间，而是在其中某个地方。

对于琐事迷来说，仍在使用的最古老的语言是 FORTRAN，它于 1957 年出现，比 LISP 早了一年。LISP 之后不久又出现了另一种长寿的语言：面向业务编程的 COBOL。

# 理论与实践

在这本书中，我们不会以理论的方式来讨论函数式编程：我们的观点是，相反地，要展示一些函数式编程的技术和原则如何成功地应用于日常的 JavaScript 编程。但是，这很重要，我们不会以教条的方式来做这件事，而是以非常实际的方式。我们不会因为它们不符合函数式编程的学术期望而放弃有用的 JS 构造。我们也不会避免实际的 JS 特性，只是为了符合函数式编程的范式。事实上，我们几乎可以说我们将会做*SFP—**有点函数式编程*，因为我们的代码将是函数式编程特性和更经典的命令式和**面向对象编程**（**OOP**）的混合。

（这并不意味着我们会把所有的理论都丢在一边。我们会挑剔，只触及主要的理论要点，给一些词汇和定义，并解释核心的函数式编程概念...但我们始终会牢记帮助产生实际有用的 JS 代码的想法，而不是试图达到某种神秘的、教条式的函数式编程标准。）

OOP 一直是解决编写大型程序和系统的固有复杂性，以及开发清洁、可扩展、可伸缩的应用架构的一种方式。然而，由于今天的 Web 应用规模不断增长，所有代码库的复杂性也在不断增加。此外，JS 的新特性使得开发几年前甚至不可能的应用成为可能；例如，使用 Ionic、Apache Cordova 或 React Native 开发的移动（混合）应用，或者使用 Electron 或 NW.js 开发的桌面应用。JS 也已经迁移到了后端，使用 Node.js，因此今天语言的使用范围已经严重扩大，处理所有增加的复杂性对所有设计都是一种负担。

# 一种不同的思维方式

FP 意味着一种不同的编程方式，有时可能很难学习。在大多数语言中，编程是以命令式的方式进行的：程序是一系列语句，按照规定的方式执行，并通过创建对象并对它们进行操作来实现所需的结果，通常会修改对象本身。FP 是基于通过评估表达式来产生所需的结果，这些表达式由组合在一起的函数构建而成。在 FP 中，通常会传递函数（作为其他函数的参数，或作为某些计算的结果返回），不使用循环（而是选择递归），并且跳过副作用（例如修改对象或全局变量）。

另一种说法是，FP 关注的是*应该*做什么，而不是*如何*做。你不必担心循环或数组，而是在更高的层次上工作，考虑需要完成的任务。适应了这种风格之后，你会发现你的代码变得更简单、更短、更优雅，并且可以轻松进行测试和调试。然而，不要陷入将 FP 视为目标的陷阱！将 FP 仅视为达到目的的手段，就像所有软件工具一样。功能性代码并不仅仅因为是功能性的而好...使用 FP 编写糟糕的代码与使用其他技术一样可能！

# 函数式编程不是什么

既然我们已经说了一些关于 FP 是什么的事情，让我们也澄清一些常见的误解，并考虑一些 FP*不是*的事情：

+   **FP 不仅仅是学术的象牙塔之物**：它是真实的，基于它的*lambda 演算*是由阿隆佐·邱奇在 1936 年开发的，作为证明理论计算机科学中重要结果的工具。（这项工作比现代计算机语言早了 20 多年！）然而，FP 语言今天被用于各种系统。

+   **FP 不是面向对象编程（OOP）的对立面**：它也不是选择声明式或命令式编程的情况。你可以根据自己的需要混合使用，我们将在本书中进行这种混合，汇集所有最好的东西。

+   **学习 FP 并不是过于复杂**：一些 FP 语言与 JS 相比相当不同，但区别主要是语法上的。一旦你学会了基本概念，你会发现你可以在 JS 中获得与 FP 语言相同的结果。

还值得一提的是，一些现代框架，如 React+Redux 组合，包含了 FP 的思想。例如，在 React 中，视图（用户在某一时刻看到的内容）被认为是当前状态的函数。你使用函数来计算每个时刻必须生成的 HTML 和 CSS，以*黑盒*的方式思考。

同样，在 Redux 中，你会得到*actions*的概念，这些*actions*由*reducers*处理。一个*action*提供一些数据，而*reducer*是一个函数，以一种功能性的方式从当前状态和提供的数据中产生应用程序的新状态。

因此，无论是因为理论上的优势（我们将在接下来的部分中介绍这些优势）还是实际上的优势（比如能够使用最新的框架和库），考虑使用 FP 编码都是有意义的；让我们开始吧。

# 为什么使用函数式编程？

多年来，出现了许多编程风格和潮流。然而，FP 已经被证明相当有韧性，并且今天非常有趣。你为什么要关心使用 FP？问题应该首先是，*你想得到什么？*然后才是*FP 能帮你实现吗？*

# 我们需要的

我们当然可以同意以下关注点是普遍的。我们的代码应该是：

+   **模块化**：程序的功能应该被划分为独立的模块，每个模块包含执行程序功能的一个方面所需的内容。对模块或函数的更改不应影响代码的其余部分。

+   **可理解性**：程序的读者应该能够辨别其组件、它们的功能，并理解它们之间的关系，而不需要过多的努力。这与*可维护性*高度相关：你的代码将来必须进行维护，以改变或添加一些新功能。

+   **可测试性**：*单元测试*尝试测试程序的小部分，验证它们的行为与其余代码的独立性。你的编程风格应该有利于编写简化编写单元测试工作的代码。此外，单元测试就像文档，因为它们可以帮助读者理解代码应该做什么。

+   **可扩展性**：事实上，你的程序总有一天会需要维护，可能是为了添加新功能。这些更改应该对原始代码的结构和数据流只有最小的影响（如果有的话）。小的更改不应该意味着对代码进行大规模、严重的重构。

+   **可重用性**：*代码重用*的目标是通过利用先前编写的代码来节省资源、时间、金钱，并减少冗余。有一些特征有助于实现这一目标，比如*模块化*（我们已经提到过），再加上*高内聚*（模块中的所有部分都是相关的）、*低耦合*（模块之间相互独立）、*关注点分离*（程序的各部分应该尽可能少地重叠功能）、以及*信息隐藏*（模块内部的变化不应该影响系统的其余部分）。

# 我们得到了什么

那么，FP 是否能满足这五个特点呢？

+   在 FP 中，目标是编写独立的函数，它们被组合在一起以产生最终结果。

+   以函数式风格编写的程序通常更加清晰、更短、更容易理解。

+   函数可以单独进行测试，FP 代码在这方面有优势。

+   你可以在其他程序中重用函数，因为它们是独立的，不依赖于系统的其他部分。大多数函数式程序共享常见的函数，其中我们将在本书中考虑其中的一些。

+   函数式代码没有副作用，这意味着你可以通过研究函数来理解其目的，而不必考虑程序的其余部分。

最后，一旦你习惯了 FP 的方式，代码就会变得更容易理解和扩展。因此，似乎所有五个特点都可以通过 FP 来实现！

对于 FP 的原因，我建议阅读约翰·休斯的《为什么函数式编程很重要》（Why Functional Programming Matters）；它可以在网上找到[www.cs.kent.ac.uk/people/staff/dat/miranda/whyfp90.pdf](http://www.cs.kent.ac.uk/people/staff/dat/miranda/whyfp90.pdf)。虽然它不是针对 JS 的，但这些论点仍然很容易理解。

# 并非所有都是金子……

然而，让我们努力追求一点平衡。使用 FP 并不是一个能够自动使你的代码变得更好的“灵丹妙药”。一些 FP 解决方案实际上是棘手的，有些开发人员在编写代码后会兴高采烈地问“这段代码是做什么用的？”如果你不小心，你的代码可能会变得“只能写”，几乎不可能维护……这样就会失去“可理解性”、“可扩展性”和“可重用性”！

另一个缺点是：你可能会发现很难找到精通 FP 的开发人员。（快问：你见过多少招聘“寻找函数式编程员”的工作广告？）今天绝大多数的 JS 代码都是用命令式、非函数式的方式编写的，大多数编程人员习惯于这种工作方式。对于一些人来说，不得不转变思路，开始以不同的方式编写程序，可能会成为一个无法逾越的障碍。

最后，如果你试图完全采用函数式方法，你可能会发现自己与 JS 不合拍，简单的任务可能会变得难以完成。正如我们在开始时所说的，我们更愿意选择“有点函数式”，因此我们不会彻底拒绝任何不是 100%函数式的 JS 特性。我们希望使用 FP 来简化我们的编码，而不是使其更加复杂！

因此，虽然我会努力向你展示在你的代码中采用功能性的优势，但与任何改变一样，总会有一些困难。然而，我完全相信你能够克服这些困难，并且你的组织将通过应用 FP 开发出更好的代码。敢于改变！

# JavaScript 是功能性的吗？

大约在这个时候，你应该问另一个重要的问题：*JS 是一种功能性语言吗？*通常，在考虑 FP 时，提到的语言不包括 JS，但列出了一些常见的选项，比如 Clojure、Erlang、Haskell 或 Scala。然而，对于 FP 语言没有明确的定义，也没有一组确切的特性。主要的观点是，如果一种语言支持与 FP 相关的常见编程风格，那么你可以认为它是功能性的。

# JavaScript 作为一种工具

JS 是什么？如果你考虑像[www.tiobe.com/tiobe-index/](http://www.tiobe.com/tiobe-index/)或[`pypl.github.io/PYPL.html`](http://pypl.github.io/PYPL.html)这样的*流行指数*，你会发现 JS 一直处于*十大*流行之列。从更学术的角度来看，这种语言有点像混合体，具有来自几种不同语言的特性。几个库帮助了语言的发展，通过提供一些不那么容易获得的特性，比如类和继承（今天的 JS 版本确实支持类，但不久前还不是这样），否则必须通过一些*原型*技巧来模拟。

*JavaScript*这个名字是为了利用 Java 的流行而选择的——只是作为一种营销策略！它的第一个名字是*Mocha*；然后是*LiveScript*，然后才是*JavaScript*。

JS 已经发展成为非常强大的工具。但是，就像所有强大的工具一样，它可以帮助你产生出色的解决方案，也可以造成巨大的伤害。FP 可以被认为是一种减少或放弃语言中一些最糟糕部分的方式，并专注于以更安全、更好的方式工作。然而，由于现有的大量 JS 代码，你不能期望对语言进行大规模的重构，这将导致大多数网站失败。你必须学会接受好的和坏的，并简单地避免后者。

此外，JS 有各种各样的可用库，以许多方式完善或扩展语言。在本书中，我们将专注于单独使用 JS，但我们将参考现有的可用代码。

如果我们问 JS 是否实际上是功能性的，答案将是，再一次，有点。由于一些特性，如一流函数，匿名函数，递归和闭包，JS 可以被认为是功能性的——我们稍后会回到这个问题。另一方面，JS 有很多非函数式的方面，比如副作用（不纯性），可变对象和递归的实际限制。因此，当以一种功能性的方式编程时，我们将利用所有相关的 JS 语言特性，并尽量减少语言更传统部分造成的问题。从这个意义上讲，JS 将或不将是功能性的，取决于你的编程风格！

如果你想使用 FP，你应该决定使用哪种语言。然而，选择完全功能性的语言可能并不明智。今天，开发代码并不像只是使用一种语言那么简单：你肯定需要框架、库和其他各种工具。如果我们可以利用所有提供的工具，同时在我们的代码中引入 FP 工作方式，我们将得到最好的两种世界——不管 JS 是不是功能性！

# 使用 JavaScript 进行功能性编程

JS 经过多年的发展，我们将使用的版本（非正式地）称为 JS8，（正式地）称为 ECMAScript 2017，通常缩写为 ES2017 或 ES8；这个版本于 2017 年 6 月完成。之前的版本有：

+   ECMAScript 1，1997 年 6 月

+   ECMAScript 2，1998 年 6 月，基本上与上一个版本相同

+   ECMAScript 3，1999 年 12 月，带有几个新功能

+   ECMAScript 5 只在 2009 年 12 月出现（不，从来没有 ECMAScript 4，因为它被放弃了）

+   ECMAScript 5.1 于 2011 年 6 月发布

+   ECMAScript 6（或 ES6；后来更名为 ES2015）于 2015 年 6 月发布

+   ECMAScript 7（也是 ES7，或 ES2016）于 2016 年 6 月最终确定

+   ECMAScript 8（ES8 或 ES2017）于 2017 年 6 月最终确定

ECMA 最初代表欧洲计算机制造商协会，但现在这个名字不再被认为是一个首字母缩写。该组织负责的标准不仅仅是 JS，还包括 JSON、C#、Dart 等。请参阅其网站[www.ecma-international.org/](http://www.ecma-international.org/)。

您可以在[www.ecma-international.org/ecma-262/7.0/](http://www.ecma-international.org/ecma-262/7.0/)上阅读标准语言规范。每当我们在文本中提到 JS 而没有进一步的规定时，指的是 ES8（ES2017）。然而，在本书中使用的语言特性方面，如果您只使用 ES2015，您不会在本书中遇到问题。

没有浏览器完全实现 ES8；大多数提供较旧版本的 JavaScript 5（从 2009 年开始），其中包含 ES6、ES7 和 ES8 的一些功能。这将成为一个问题，但幸运的是，这是可以解决的；我们很快就会解决这个问题，并且在整本书中我们将使用 ES8。

事实上，ES2016 和 ES2015 之间只有一点点区别，比如`Array.prototype.includes`方法和指数运算符`**`。ES2017 和 ES2016 之间有更多的区别，比如`async`和`await`，一些字符串填充函数等，但它们不会影响我们的代码。

# JavaScript 的主要特点

JS 不是一种函数式语言，但它具有我们需要的所有功能，可以像函数式语言一样工作。我们将使用的语言的主要特点是：

+   函数作为一等对象

+   递归

+   箭头函数

+   闭包

+   展开

让我们看一些每一个的例子，解释为什么它们对我们有用。

# 函数作为一等对象

说函数是*一等对象*（也可以说是*一等公民*）意味着您可以对函数做任何其他对象可以做的事情。例如，您可以将函数存储在变量中，将其传递给函数，将其打印出来等等。这确实是进行 FP 的关键：我们经常会将函数作为参数（传递给其他函数）或将函数作为函数调用的结果返回。

如果您一直在进行异步 Ajax 调用，您已经在使用这个功能：*回调*是一个在 Ajax 调用完成后被调用并作为参数传递的函数。使用 jQuery，您可以写出类似以下的代码：

```js
$.get("some/url", someData, function(result, status) {
 // *check status, and do something*
 // *with the result*
});
```

`$.get()`函数接收一个回调函数作为参数，并在获得结果后调用它。

这个问题可以更现代化地通过使用 promises 或 async/await 来解决，但是为了我们的例子，旧的方法已经足够了。不过，我们将在第十二章的*构建更好的容器-功能数据类型*中讨论单子时，会回到 promises；特别是看看*意外的单子：promises*一节。

由于函数可以存储在变量中，您也可以这样写：

```js
var doSomething = function(result, status) {
 // *check status, and do something*
 // *with the result*
};
$.get("some/url", someData, doSomething);
```

在第六章中我们会看到更多的例子，*生成函数-高阶函数*，当我们考虑高阶函数时。

# 递归

这是开发算法的最有效工具，也是解决大类问题的重要辅助工具。其思想是一个函数在某一点可以调用*自身*，当*那个*调用完成后，继续使用它接收到的任何结果。这通常对某些类的问题或定义非常有帮助。最常引用的例子是阶乘函数（*n*的阶乘写作*n!*）对非负整数值的定义：

+   如果*n*为 0，则*n!=1*

+   如果*n*大于 0，则*n!=n*(n-1)!

*n!*的值是你可以按顺序排列 n 个不同元素的方式数。例如，如果你想把五本书排成一行，你可以选择其中任意一本放在第一位，然后以每种可能的方式排列其他四本，所以*5!=5*4!*。如果你继续处理这个例子，你会得到*5!=5*4*3*2*1=120*，所以*n!*是所有小于*n*的所有数字的乘积。

这可以立即转换为 JS 代码：

```js
function fact(n) {
 if (n === 0) {
 return 1;
 } else {
 return n * fact(n - 1);
 }
}
console.log(fact(5)); // *120*
```

递归将是算法设计的重要辅助工具。通过使用递归，您可以不使用任何`while`或`for`循环——虽然我们*不想*这样做，但有趣的是我们*能*！我们将把完整的第九章，*设计函数-递归*，用于设计算法和递归编写函数。

# 闭包

闭包是实现数据隐藏（使用私有变量）的一种方式，这导致了模块和其他很好的特性。关键概念是，当你定义一个函数时，它不仅可以引用自己的局部变量，还可以引用函数上下文之外的所有东西：

```js
function newCounter() {
    let count = 0;
 return function() {
 count++;
        return count;
 };
}
const nc = newCounter();
console.log(nc()); // *1*
console.log(nc()); // *2*
console.log(nc()); // *3*
```

即使`newCounter`退出后，内部函数仍然可以访问`count`，但该变量对您代码的任何其他部分都不可访问。

这不是 FP 的一个很好的例子——一个函数（在这种情况下是`nc()`）不应该在使用相同参数调用时返回不同的结果！

我们将发现闭包有几种用途：包括*记忆化*（见第四章，*行为良好-纯函数*，和第六章，*生成函数-高阶函数*）和*模块*模式（见第三章，*从函数开始-核心概念*，和第十一章，*实现设计模式-函数式方法*）。

# 箭头函数

箭头函数只是创建（无名）函数的一种更简洁的方式。箭头函数几乎可以在几乎任何地方使用经典函数，除了它们不能用作构造函数。语法要么是（`参数，另一个参数，...等）=> { *语句* }`，要么是（`参数，另一个参数，...等）=> *表达式*。第一种允许您编写尽可能多的代码；第二种是`{ return *表达式* }`的简写。我们可以将我们之前的 Ajax 示例重写为：

```js
$.get("some/url", data, (result, status) => {
 // *check status, and do something*
 // *with the result*
});
```

阶乘代码的新版本可能是：

```js
const fact2 = n => {
 if (n === 0) {
 return 1;
 } else {
 return n * fact2(n - 1);
 }
};
console.log(fact2(5)); // *also 120*
```

箭头函数通常被称为*匿名*函数，因为它们没有名称。如果您需要引用箭头函数，您必须将其分配给变量或对象属性，就像我们在这里做的那样；否则，您将无法使用它。我们将在第三章的*箭头函数*部分中看到更多内容，*从函数开始-核心概念*。

你可能会将后者写成一行代码——你能看到等价吗？

```js
const fact3 = n => (n === 0 ? 1 : n * fact3(n - 1));
console.log(fact3(5)); // again 120
```

使用这种更短的形式，您不必写`return`--它是暗示的。简短的评论：当箭头函数只有一个参数时，您可以省略括号。我通常更喜欢留下它们，但我已经应用了一个 JS 美化程序*prettier*到代码中，它会删除它们。是否包括它们取决于您！（有关此工具的更多信息，请查看[`github.com/prettier/prettier`](https://github.com/prettier/prettier)。）顺便说一句，我格式化的选项是`--print-width 75 --tab-width 4 --no-bracket-spacing`。

在λ演算中，函数`x => 2*x`将表示为*λx.2*x*--尽管有一些语法上的差异，但定义是类似的。具有更多参数的函数会复杂一些：*(x,y)=>x+y*将表示为*λx.λy.x+y.*我们将在第三章的*Lambda 和函数*部分，第七章的*柯里化*部分中看到更多关于这一点的内容。

# 扩展

传播运算符（参见[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Operators/Spread_operator`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Operators/Spread_operator)）允许您在需要多个参数、元素或变量的地方扩展表达式。例如，您可以替换函数调用中的参数：

```js
const x = [1, 2, 3];
function sum3(a, b, c) {
 return a + b + c;
}
const y = sum3(...x); // equivalent to sum3(1,2,3)
console.log(y); // 6
```

您还可以创建或加入数组：

```js
const f = [1, 2, 3];
const g = [4, ...f, 5]; // [4,1,2,3,5]
const h = [...f, ...g]; // [1,2,3,4,1,2,3,5]
```

它也适用于对象：

```js
const p = { some: 3, data: 5 };
const q = { more: 8, ...p }; // { more:8, some:3, data:5 }
```

您还可以使用它来处理期望单独参数而不是数组的函数。这种情况的常见示例是`Math.min()`和`Math.max()`：

```js
const numbers = [2, 2, 9, 6, 0, 1, 2, 4, 5, 6];
const minA = Math.min(...numbers); // *0*

const maxArray = arr => Math.max(...arr);
const maxA = maxArray(numbers); // *9*
```

您还可以编写以下*等式*。`.apply()`方法需要一个参数数组，而`.call()`则需要单独的参数：

```js
someFn.apply(thisArg, someArray) === someFn.call(thisArg, ...someArray);
```

如果您记不住`.apply()`和`.call()`需要哪些参数，这个记忆法可能会有所帮助：*A 代表*数组*，C 代表逗号*。有关更多信息，请参见[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/apply`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/apply)和[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/call`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/call)。

使用传播运算符有助于编写更短、更简洁的代码，我们将充分利用它。

# 我们如何使用 JavaScript？

这一切都很好，但正如我们之前提到的，几乎所有地方都可用的 JS 版本都不是 ES8，而是较早的 JS5。Node.js 是一个例外：它基于 Chrome 的 V8 高性能 JS 引擎，该引擎已经支持了几个 ES8 功能。尽管如此，截至今天，ES8 覆盖率并不是 100%，还有一些功能是您会错过的。（有关 Node 和 V8 的更多信息，请查看[`nodejs.org/en/docs/es6/`](https://nodejs.org/en/docs/es6/)。）

那么，如果您想使用最新版本进行编码，但可用的版本是较早、较差的版本，您该怎么办？或者，如果您的大多数用户可能使用不支持您想要使用的新功能的老版本浏览器，会发生什么？让我们看看一些解决方案。

如果您想在使用任何给定的新功能之前确保，可以查看[`kangax.github.io/compat-table/es6/`](https://kangax.github.io/compat-table/es6/)上的兼容性表。 （见图 1.1）。特别是对于 Node.js，请查看[`node.green/`](http://node.green/)。![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/12ef0eea-ad3a-4742-90ea-ca23a61426af.png)图 1.1 - JS 的最新版本尚未得到广泛和完全支持，因此在使用任何新功能之前，您需要进行检查

# 使用转换器

为了摆脱这种可用性和兼容性问题，你可以使用一些*转译器*。转译器将你的原始 ES8 代码转换为等效的 JS5 代码。（这是一种源到源的转换，而不是编译中的源到对象代码。）你可以使用 ES8 的高级特性编码，但用户的浏览器将接收 JS5 代码。转译器还可以让你跟上语言的即将推出的版本，尽管浏览器在桌面和移动设备上采用新标准需要时间。

如果你想知道*转译器*一词是从哪里来的，它是*translate*和*compiler*的混成词。在技术术语中有许多这样的组合：*email*（electronic+mail）、*emoticon*（emotion+icon）、*malware*（malicious+software）、或*alphanumeric*（alphabetic+numeric），以及其他几个。

JS 最常见的转译器是**Babel**（在[`babeljs.io/`](https://babeljs.io/)）和**Traceur**（在[`github.com/google/traceur-compiler`](https://github.com/google/traceur-compiler)）。使用**npm**或**Webpack**等工具，配置代码自动转译并提供给最终用户非常容易。你也可以在线尝试转译；参见图 1.2，这是使用 Babel 的在线环境的示例：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/a7fa9d5f-940d-4cdc-96a7-bce9af7f9471.png)图 1.2 - Babel 转译器将 ES8 代码转换为兼容的 JS5 代码

如果你更喜欢 Traceur，可以使用它的工具[`google.github.io/traceur-compiler/demo/repl.html#`](https://google.github.io/traceur-compiler/demo/repl.html#)，但你需要打开开发者控制台来查看运行代码的结果。（见图 1.3。）选择实验选项，以完全启用 ES8 支持：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/f80f873f-cff5-44af-97c9-96fbcf098652.png)图 1.3 - Traceur 转译器是 ES8 到 JS5 翻译的同样有效的选择使用转译器也是学习新 JS 特性的好方法。只需在左侧输入一些代码，然后在右侧看到等效的结果。或者，使用**命令行界面**（**CLI**）工具来转译源文件，然后检查生成的输出。

还有一个可能要考虑的选择：不使用 JS，而是选择微软的 TypeScript（在[`www.typescriptlang.org/`](http://www.typescriptlang.org/)），这是 JS 的超集，编译为 JS5。TypeScript 的主要优势是为 JS 添加（可选的）静态类型检查，有助于在编译时检测一些编程错误。注意：与 Babel 或 Traceur 一样，并非所有 ES8 都可用。

你也可以在不使用 TypeScript 的情况下获得类型检查，方法是使用 Facebook 的 Flow（参见[`flow.org/`](https://flow.org/)）。

如果选择使用 TypeScript，你也可以在它们的*playground*上在线测试；参见[`www.typescriptlang.org/play/`](http://www.typescriptlang.org/play/)。你可以设置选项来更严格或更宽松地检查数据类型，并且还可以立即运行你的代码。见图 1.4：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/e4f6e6bd-4c1a-439f-af51-e46644231b89.png)图 1.4 - TypeScript 添加了类型检查功能，使 JS 编程更安全

# 在线工作

有一些在线工具可以用来测试你的 JS 代码。查看**JSFiddle**（在[`jsfiddle.net/`](https://jsfiddle.net/)）、**CodePen**（在[`codepen.io/`](https://codepen.io/)）、或**JSBin**（在[`jsbin.com/`](http://jsbin.com/)）等等。你可能需要指定是否使用 Babel 或 Traceur；否则，新的 JS 特性将被拒绝。在图 1.5 中可以看到 JSFiddle 的示例：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/b03b9a3c-330a-4832-9369-eae76e96b47a.png)图 1.5 - JSFiddle 让你尝试 ES8 代码（还包括 HTML 和 CSS），而无需任何其他工具

# 测试

我们还将涉及测试，毕竟，这是 FP 的主要优势之一。为此，我们将使用 Jasmine（[`jasmine.github.io/`](https://jasmine.github.io/)），尽管我们也可以选择 Mocha（[`mochajs.org/`](http://mochajs.org/)）。

您可以使用 Karma（[`karma-runner.github.io`](https://karma-runner.github.io)）等运行器来运行 Jasmine 测试套件，但我选择了独立测试；有关详细信息，请参见[`github.com/jasmine/jasmine#installation`](https://github.com/jasmine/jasmine#installation)。

# 问题

1.1. **类作为一等对象**：我们看到函数是一等对象，但您知道*类*也是吗？（当然，谈论类作为*对象*听起来很奇怪……）研究这个例子，看看是什么使它起作用！注意：其中有一些故意奇怪的代码：

```js
 const makeSaluteClass = term =>
 class {
 constructor(x) {
 this.x = x;
 }

 salute(y) {
 console.log(`${this.x} says "${term}" to ${y}`);
 }
 };

 const Spanish = makeSaluteClass("HOLA");
 new Spanish("ALFA").salute("BETA");
 // *ALFA says "HOLA" to BETA*

 new (makeSaluteClass("HELLO"))("GAMMA").salute("DELTA");
 // *GAMMA says "HELLO" to DELTA*

 const fullSalute = (c, x, y) => new c(x).salute(y);
 const French = makeSaluteClass("BON JOUR");
 fullSalute(French, "EPSILON", "ZETA");
 // *EPSILON says "BON JOUR" to ZETA*
```

1.2. **阶乘错误**：我们定义的阶乘应该只计算非负整数。然而，我们编写的函数没有验证其参数是否有效。您能添加必要的检查吗？尽量避免重复冗余的测试！

1.3. **爬升阶乘**：我们的阶乘实现从*n*开始乘，然后是*n-1*，然后是*n-2*，依此类推，可以说是以*向下的方式*。您能否编写阶乘函数的新版本，它将以*向上*的方式循环？

# 总结

在本章中，我们已经了解了函数式编程的基础知识，以及一些历史、优势（也可能有一些可能的劣势，公平地说），为什么我们可以将其应用于 JavaScript，这通常不被认为是一种函数式语言，以及我们将需要哪些工具才能利用本书的其余部分。

在第二章中，“功能性思维-第一个例子”，我们将讨论一个简单问题的例子，并以*常见*的方式来看待它，最终以函数式的方式解决它，并分析这种工作方式的优势。


# 第二章：功能性思维 - 第一个例子

在第一章中，*成为功能性 - 几个问题*，我们讨论了 FP 是什么，提到了应用它的一些优势，并列出了一些我们在 JS 中需要的工具...但现在让我们把理论抛在脑后，从考虑一个简单的问题开始，以及如何以功能性的方式解决它。

在这一章中，我们将看到：

+   一个简单的、常见的、与电子商务相关的问题

+   用它们相关的缺陷解决它的几种常见方法

+   通过功能性的方式解决问题的方法

+   一个高阶解决方案，可以应用到其他问题上

+   如何对功能性解决方案进行单元测试

在未来的章节中，我们将回到这里列出的一些主题，所以我们不会深入细节。我们只会展示 FP 如何为我们的问题提供不同的观点，并留下更多细节以后再讨论。

# 问题 - 只做一次某事

让我们考虑一个简单但常见的情况。你开发了一个电子商务网站：用户可以填写他们的购物车，最后，他们必须点击一个“账单”按钮，这样他们的信用卡就会被收费。然而，用户不应该点击两次（或更多），否则他们将被多次计费。

你的应用程序的 HTML 部分可能会有这样的东西：

```js
<button id="billButton" onclick="billTheUser(some, sales, data)">Bill me</button>
```

而且，在你的脚本中，你可能会有类似这样的东西：

```js
function billTheUser(some, sales, data) {
 window.alert("Billing the user...");
 // *actually bill the user*
}
```

直接在 HTML 中分配事件处理程序，就像我做的那样，是不推荐的。相反，在*不显眼*的方式中，你应该通过代码分配处理程序。所以... *说话要做到，不要做到我做的那样*！

这只是对问题和你的网页的一个非常简单的解释，但对我们的目的来说已经足够了。现在让我们考虑一下如何避免重复点击那个按钮... *我们如何能够避免用户点击超过一次？*

# 一些不好的解决方案

好的，你能想到多少种方法来解决我们的问题？让我们讨论几种解决方案，并分析它们的质量。

# 解决方案＃1 - 希望一切顺利！

我们如何解决这个问题？第一个*解决方案*可能看起来像是一个笑话：什么都不做，告诉用户*不要*点击两次，然后希望一切顺利！你的页面可能看起来像图 2.1。

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/dee3094d-17b8-4d14-8b95-e3d3145d180a.png)图 2.1\. 页面的实际截图，只是警告您不要点击两次

这是一个回避问题的狡猾方法，但我见过一些网站只是警告用户不要多次点击的风险（见图 2.1），实际上并没有采取任何措施来防止这种情况... *用户被收费两次？我们警告过他们了...这是他们的错！*你的解决方案可能看起来就像下面的代码。

```js
<button id="billButton" onclick="billTheUser(some, sales, data)">Bill me</button>
<b>WARNING: PRESS ONLY ONCE, DO NOT PRESS AGAIN!!</b>
```

好吧，这实际上不是一个解决方案；让我们继续考虑更严肃的提议...

# 解决方案＃2 - 使用全局标志

大多数人可能首先想到的解决方案是使用一些全局变量来记录用户是否已经点击了按钮。你可以定义一个名为`clicked`的标志，初始化为`false`。当用户点击按钮时，如果`clicked`是`false`，你就把它改为`true`，并执行该函数；否则，你根本不做任何事情：

```js
let clicked = false;
.
.
.
function billTheUser(some, sales, data) {
 if (!clicked) {
        clicked = true;
 window.alert("Billing the user...");
 // *actually bill the user*
 }
}
```

关于不使用全局变量的更多好理由，

阅读[`wiki.c2.com/?GlobalVariablesAreBad`](http://wiki.c2.com/?GlobalVariablesAreBad)。

这显然有效，但有几个问题必须解决：

+   你正在使用一个全局变量，你可能会意外地改变它的值。全局变量不是一个好主意，无论是在 JS 还是其他语言中。

+   当用户重新开始购买时，你还必须记得重新将其初始化为`false`。如果你不这样做，用户将无法进行第二次购买，因为支付将变得不可能。

+   你将很难测试这段代码，因为它依赖于外部事物（也就是`clicked`变量）。

所以，这不是一个很好的解决方案...让我们继续思考！

# 解决方案＃3 - 移除处理程序

我们可以采用一种侧面的解决方案，而不是让函数避免重复点击，我们可能只是完全删除点击的可能性：

```js
function billTheUser(some, sales, data) {
    document.getElementById("billButton").onclick = null;
 window.alert("Billing the user...");
 // actually bill the user
}
```

这个解决方案也有一些问题：

+   代码与按钮紧密耦合，因此您将无法在其他地方重用它

+   您必须记住重置处理程序，否则用户将无法进行第二次购买

+   测试也会更加困难，因为您将不得不提供一些 DOM 元素

我们可以稍微改进这个解决方案，并通过在调用中提供后者的 ID 作为额外参数来避免将函数与按钮耦合在一起。（这个想法也可以应用于以下一些解决方案。）HTML 部分将是：

```js
<button
 id="billButton"
    onclick="billTheUser('billButton', some, sales, data)"
>
 Bill me
</button>;
```

（注意额外的参数）和被调用的函数将是：

```js
function billTheUser(buttonId, some, sales, data) {
    document.getElementById(buttonId).onclick = null;
 window.alert("Billing the user...");
 // actually bill the user
}
```

这个解决方案有点好。但是，本质上，我们仍然使用全局元素：不是变量，而是`onclick`值。因此，尽管有增强，这也不是一个很好的解决方案。让我们继续。

# 解决方案＃4-更改处理程序

对先前解决方案的变体将不是删除单击函数，而是改为分配一个新函数。当我们将`alreadyBilled()`函数分配给单击事件时，我们在这里使用函数作为一等对象：

```js
function alreadyBilled() {
 window.alert("Your billing process is running; don't click, please.");
}
```

```js
function billTheUser(some, sales, data) {
    document.getElementById("billButton").onclick = alreadyBilled;
 window.alert("Billing the user...");
 // actually bill the user
}
```

这个解决方案有一个好处：如果用户第二次点击，他们会收到一个警告，不要这样做，但他们不会再次被收费。（从用户体验的角度来看，这更好。）但是，这个解决方案仍然有与前一个相同的异议（代码与按钮耦合在一起，需要重置处理程序，更难的测试），所以我们不认为它很好。 

# 解决方案＃5-禁用按钮

一个类似的想法：不要删除事件处理程序，而是禁用按钮，这样用户就无法单击。您可能会有一个类似以下的函数。

```js
function billTheUser(some, sales, data) {
    document.getElementById("billButton").setAttribute("disabled", "true");
 window.alert("Billing the user...");
 // actually bill the user
}
```

这也有效，但我们仍然对先前的解决方案有异议（将代码与按钮耦合在一起，需要重新启用按钮，更难的测试），所以我们也不喜欢这个解决方案。

# 解决方案＃6-重新定义处理程序

另一个想法：不要改变按钮中的任何内容，让事件处理程序自己改变。诀窍在第二行；通过为`billTheUser`变量分配一个新值，我们实际上动态地改变了函数的功能！第一次调用函数时，它会执行其操作...但它也会通过将其名称赋给一个新函数而使自己消失：

```js
function billTheUser(some, sales, data) {
    billTheUser = function() {};
 window.alert("Billing the user...");
 // *actually bill the user*
}
```

解决方案中有一个特殊的技巧。函数是全局的，所以`billTheUser=...`这一行实际上改变了函数的内部工作方式；从那时起，`billTheUser`将成为新的（空）函数。这个解决方案仍然很难测试。更糟糕的是，您如何恢复`billTheUser`的功能，将其设置回原来的目标？

# 解决方案＃7-使用本地标志

我们可以回到使用标志的想法，但是不要使其全局（这是我们的主要异议），我们可以使用*立即调用的函数表达式（IIFE）*：我们将在第三章中看到更多关于这一点，*从函数开始-核心概念*，以及在第十一章中，*实施设计模式-功能方式*。通过这样做，我们可以使用闭包，因此`clicked`将局部于函数，而不会在任何其他地方可见：

```js
var billTheUser = (clicked => {
 return (some, sales, data) => {
        if (!clicked) {
            clicked = true;
 window.alert("Billing the user...");
 // *actually bill the user*
 }
 };
})(false);
```

看看`clicked`如何从最后的调用中获得其初始值`false`。

这个解决方案沿着全局变量解决方案的思路，但是使用私有的本地变量是一种增强。我们唯一找到的异议是，您将不得不重新设计需要以这种方式工作的每个函数。（正如我们将在下一节中看到的那样，我们的 FP 解决方案在某些方面与它相似。）好吧，这并不难做，但不要忘记*不要重复自己（D.R.Y）*的建议！

# 一个功能性的解决方案

让我们尝试更通用一些：毕竟，要求某个函数或其他函数只执行一次，这并不奇怪，而且可能在其他地方也需要！让我们建立一些原则：

+   原始函数（只能调用一次的函数）应该只执行那件事，而不是其他事情

+   我们不想以任何方式修改原始函数

+   我们需要一个新函数，只能调用原始函数一次

+   我们希望有一个通用解决方案，可以应用于任意数量的原始函数

先前列出的第一个原则是*单一职责原则*（S.O.L.I.D.中的*S*），它规定每个函数应负责单一功能。有关 S.O.L.I.D.的更多信息，请查看*Uncle Bob*（编写了这五个原则的 Robert C. Martin）的文章[`butunclebob.com/ArticleS.UncleBob.PrinciplesOfOod`](http://butunclebob.com/ArticleS.UncleBob.PrinciplesOfOod)。

我们能做到吗？是的；我们将编写一个*高阶函数*，我们将能够将其应用于任何函数，以生成一个只能工作一次的新函数。让我们看看！

# 一个高阶解决方案

如果我们不想修改原始函数，我们将创建一个高阶函数，我们将其有灵感地命名为`once()`。该函数将接收一个函数作为参数，并将返回一个只能工作一次的新函数。（我们将在第六章中看到更多的高阶函数；特别是，请参阅*Doing things once, revisited*部分。）

Underscore 和 LoDash 已经有一个类似的函数，被调用为`_.once()`。Ramda 还提供了`R.once()`，大多数 FP 库都包含类似的功能，因此您不必自己编写它。

我们的`once()`函数方式一开始似乎有些强制，但是当您习惯以 FP 方式工作时，您会习惯这种代码，并发现它非常易懂。

```js
const once = fn => {
 let done = false;
    return (...args) => {
 if (!done) {
 done = true;
            fn(...args);
 }
 };
};
```

让我们来看一下这个函数的一些要点：

+   第一行显示`once()`接收一个函数（`fn()`）作为其参数。

+   我们通过利用闭包定义了一个内部的私有`done`变量，就像之前的解决方案#7 一样。我们选择*不*将其称为`clicked`，因为您不一定需要点击按钮才能调用该函数；我们选择了一个更通用的术语。

+   `return (...args) => ...`这一行表示`once()`将返回一个带有一些（0、1 或更多）参数的函数。请注意，我们正在使用我们在第一章中看到的扩展语法，*成为函数式 - 几个问题*。在较旧版本的 JS 中，您必须使用`arguments`对象；有关更多信息，请参阅[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Functions/arguments`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Functions/arguments)。ES8 的方式更简单更短！

+   在调用`fn()`之前，我们先赋值`done = true`，以防该函数抛出异常。当然，如果您不想在函数成功结束之前禁用该函数，那么您可以将赋值移到`fn()`调用的下面。

+   设置完成后，我们最终调用原始函数。请注意使用扩展运算符传递原始`fn()`的任何参数。

那么我们该如何使用它呢？我们甚至不需要将新生成的函数存储在任何地方；我们可以简单地编写`onclick`方法，如下所示：

```js
<button id="billButton" onclick="once(billTheUser)(some, sales, data)">
 Bill me
</button>;
```

请注意语法！当用户点击按钮时，使用`(some, sales, data)`参数调用的函数不是`billTheUser()`，而是使用`billTheUser`作为参数调用`once()`的结果。该结果只能被调用一次。

请注意，我们的`once()`函数使用函数作为一等对象、箭头函数、闭包和展开操作符；回到第一章，*成为函数式编程 - 几个问题*，我们说我们会需要这些，所以我们信守承诺！我们在这一章中唯一缺少的是递归...但正如滚石乐队唱的那样，*你并不总是能得到你想要的！*

# 手动测试解决方案

我们可以运行一个简单的测试：

```js
const squeak = a => console.log(a, " squeak!!");
squeak("original"); // "original squeak!!"
squeak("original"); // "original squeak!!" squeak("original"); // "original squeak!!" const squeakOnce = once(squeak);
squeakOnce("only once"); // "only once squeak!!"
squeakOnce("only once"); // no output
squeakOnce("only once"); // no output
```

在 CodePen 上查看结果，或者查看图 2.2：

图 2.2 - 测试我们的 once()高阶函数

# 自动测试解决方案

手动运行测试不好；它会变得烦人、无聊，久而久之，就不再运行测试了。让我们做得更好一些，用 Jasmine 编写一些自动测试。按照[`jasmine.github.io/pages/getting_started.html`](https://jasmine.github.io/pages/getting_started.html)上的说明，我设置了一个独立的运行器：

```js
<!DOCTYPE html> <html> <head>
  <meta  charset="utf-8">
  <title>Jasmine Spec Runner v2.6.1</title>

 <link  rel="shortcut icon"  type="image/png"  href="lib/jasmine-2.6.1/jasmine_favicon.png">
  <link  rel="stylesheet"  href="lib/jasmine-2.6.1/jasmine.css">

  <script  src="lib/jasmine-2.6.1/jasmine.js"></script>
  <script  src="lib/jasmine-2.6.1/jasmine-html.js"></script>
  <script  src="lib/jasmine-2.6.1/boot.js"></script>

  <script  src="src/once.js"></script>
  <script  src="tests/once.test.1.js"></script> </head> <body> </body> </html>
```

`src/once.js`文件中有我们刚刚看到的`once()`定义，`tests/once.test.js`中有实际的测试套件：

```js
describe("once", () => {
 beforeEach(() => {
 window.myFn = () => {};
 spyOn(window, "myFn");
 });

 it("without 'once', a function always runs", () => {
 myFn();
 myFn();
 myFn();
 expect(myFn).toHaveBeenCalledTimes(3);
 });

 it("with 'once', a function runs one time", () => {
 window.onceFn = once(window.myFn);
 spyOn(window, "onceFn").and.callThrough();
 onceFn();
 onceFn();
 onceFn();
 expect(onceFn).toHaveBeenCalledTimes(3);
 expect(myFn).toHaveBeenCalledTimes(1);
 });
});
```

这里有几点需要注意：

+   为了监听一个函数，它必须与一个对象相关联。（或者，你也可以直接使用 Jasmine 的`.createSpy()`方法直接创建一个 spy。）全局函数与 window 对象相关联，所以`window.fn`是一种说法，即`fn`实际上是全局的。

+   当你对一个函数进行监听时，Jasmine 会拦截你的调用并注册函数被调用的次数、使用的参数以及调用的次数。所以，就我们所关心的而言，`window.fn`可以简单地是`null`，因为它永远不会被执行。

+   第一个测试只检查如果我们多次调用函数，它会被调用相应的次数。这很琐碎，但如果这没有发生，我们肯定做错了什么！

+   在第二组测试中，我们想要看到`once()`函数(`window.onceFn()`)被调用，但只调用一次。所以，我们告诉 Jasmine 监听`onceFn`，但让调用通过。对`fn()`的任何调用也会被计数。在我们的情况下，尽管调用了`onceFn()`三次，`fn()`只被调用了一次，这是我们预期的。

我们可以在图 2.3 中看到结果：

图 2.3 - 在 Jasmine 上运行自动测试我们的函数

# 一个更好的解决方案

在之前的解决方案中，我们提到每次第一次之后都做一些事情而不是默默地忽略用户的点击是一个好主意。我们将编写一个新的高阶函数，它接受第二个参数；一个从第二次调用开始每次都要调用的函数：

```js
const onceAndAfter = (f, g) => {
 let done = false;
 return (...args) => {
 if (!done) {
 done = true;
 f(...args);
        } else {
 g(...args);
 }
 };
};
```

我们已经在高阶函数中更进一步；`onceAndAfter`接受*两个*函数作为参数，并产生一个包含另外两个函数的第三个函数。

你可以通过为`g`提供一个默认值来使`onceAndAfter`更加强大，类似于`const onceAndAfter = (f, g = ()=>{})`...所以如果你不想指定第二个函数，它仍然可以正常工作，因为它会调用一个*什么都不做*的函数，而不是引起错误。

我们可以进行一个快速而简单的测试，与之前我们做的类似：

```js
const squeak = (x) => console.log(x, "squeak!!");
const creak = (x) => console.log(x, "creak!!");
const makeSound = onceAndAfter(squeak, creak);
makeSound("door"); // "door squeak!!"
makeSound("door"); // "door creak!!"
makeSound("door"); // "door creak!!"
makeSound("door"); // "door creak!!"
```

为这个新函数编写测试并不难，只是有点长：

```js
describe("onceAndAfter", () => {
 it("should call the first function once, and the other after", () => {
 func1 = () => {};
 spyOn(window, "func1");
 func2 = () => {};
 spyOn(window, "func2");
 onceFn = onceAndAfter(func1, func2);

 onceFn();
 expect(func1).toHaveBeenCalledTimes(1);
 expect(func2).toHaveBeenCalledTimes(0);

 onceFn();
 expect(func1).toHaveBeenCalledTimes(1);
 expect(func2).toHaveBeenCalledTimes(1);

 onceFn();
 expect(func1).toHaveBeenCalledTimes(1);
 expect(func2).toHaveBeenCalledTimes(2);

 onceFn();
 expect(func1).toHaveBeenCalledTimes(1);
 expect(func2).toHaveBeenCalledTimes(3);
 });
});
```

请注意，我们总是检查`func1`只被调用一次。同样，我们检查`func2`；调用次数从零开始（`func1`被调用的时间），然后每次调用都会增加一次。

# 问题

2.1\. **没有额外的变量**：我们的函数式实现需要使用一个额外的变量`done`来标记函数是否已经被调用。这并不重要...但你能在不使用任何额外变量的情况下做到吗？请注意，我们并没有告诉你*不*使用任何变量；这只是一个不添加新变量，比如`done`，只是一个练习！

2.2\. **交替函数**：在我们的`onceAndAfter()`函数的精神下，你能否编写一个`alternator()`高阶函数，它接受两个函数作为参数，并在每次调用时交替调用一个和另一个？预期的行为应该如下例所示：

```js
 let sayA = () => console.log("A");
 let sayB = () => console.log("B");

 let alt = alternator(sayA, sayB);
 alt(); // *A*
 alt(); // *B*
 alt(); // *A*
 alt(); // *B*
 alt(); // *A*
 alt(); // *B*
```

2.3\. **一切都有限制！**：作为`once()`的扩展，你能否编写一个高阶函数`thisManyTimes(fn,n)`，让你可以调用`fn()`函数最多`n`次，但之后不做任何操作？举个例子，`once(fn)`和`thisManyTimes`(fn,1)会产生完全相同行为的函数。

# 总结

在这一章中，我们看到了一个常见的简单问题，基于一个真实的情况，并在分析了几种通常的解决方法之后，我们选择了一个*功能性思维*的解决方案。我们看到了如何将 FP 应用到我们的问题上，我们还找到了一个更一般的高阶方法，我们可以将其应用到类似的问题上，而无需进行进一步的代码更改。我们看到了如何为我们的代码编写单元测试，以完成开发工作。最后，我们甚至提出了一个更好的解决方案（从用户体验的角度来看），并看到了如何编写代码以及如何对其进行单元测试。

在下一章第三章中，*从函数开始-核心概念*，我们将更深入地探讨函数，这是所有 FP 的核心。


# 第三章：开始学习函数 - 一个核心概念

在第二章中，*函数式思维 - 第一个例子*，我们讨论了一个函数式思维的例子，但现在让我们回到基础，复习一下函数。在第一章中，*成为函数式 - 几个问题*，我们提到两个重要的 JS 特性是函数作为一等对象和闭包。现在，在这一章中，让我们：

+   检查 JS 中定义函数的一些关键方式

+   详细讨论箭头函数，它们是最接近 lambda 演算函数的

+   介绍*currying*的概念

+   重新审视函数作为一等对象的概念

我们还将考虑几种函数式编程技术，比如：

+   注入，根据不同策略进行排序和其他用途

+   回调和 promises，引入*continuation passing* 风格

+   *Polyfilling* 和 *stubbing*

+   立即调用方案

# 关于函数的一切

让我们从 JS 中函数的简要回顾和它们与函数式编程概念的关系开始。我们可以从我们在之前章节提到的东西开始，关于函数作为一等对象，然后继续讨论它们在 JS 中的使用。

# 关于 lambda 和函数

用 lambda 演算的术语来看，一个函数可以看起来像*λx.2*x*。理解的是，*λ* 字符后面的变量是函数的参数，点后面的表达式是你将要替换为传递的任何值的地方。

如果你有时想知道参数和实参之间的区别，一些头韵的助记词可能会有所帮助：*Parameters are Potential, Arguments are Actual.* 参数是潜在值的占位符，将要传递的值，而实参是传递给函数的实际值。

应用一个函数意味着你向它提供一个实际的参数，并且通常是用括号来表示。例如，*(λx.2*x)(3)* 将被计算为 6。这些 lambda 函数在 JS 中的等价物是什么？这是一个有趣的问题！有几种定义函数的方式，并且并非所有的方式都有相同的含义。

一篇很好的文章展示了定义函数、方法等的多种方式，是*JavaScript 中函数的多种面孔*，由 Leo Balter 和 Rick Waldron 撰写，网址是[`bocoup.com/blog/the-many-faces-of-functions-in-javascript`](https://bocoup.com/blog/the-many-faces-of-functions-in-javascript)--去看看吧！

在 JS 中你可以用多少种方式定义一个函数？答案是，*可能比你想象的要多！* 至少，你可以写：

+   一个命名的函数声明：`function first(...) {...};`

+   一个匿名函数表达式：`var second = function(...) {...};`

+   一个命名的函数表达式：`var third = function someName(...) {...};`

+   一个立即调用的表达式：`var fourth = (function() { ...; return function(...) {...}; })();`

+   一个函数构造器：`var fifth = new Function(...);`

+   一个箭头函数：`var sixth = (...) => {...};`

如果你愿意的话，你还可以添加对象方法声明，因为它们实际上也意味着函数，但这已经足够了。

JS 还允许定义生成器函数，如`function*(...) {...}`，实际上返回一个`Generator`对象，以及真正是生成器和 promises 混合的`async`函数。我们不会使用这些类型的函数，但是可以在[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Statements/function*`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Statements/function*)和[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/async_function`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/async_function)了解更多--它们在其他情境中可能会有用。

所有这些定义函数的方式之间的区别是什么，为什么我们要在意？让我们一一讨论：

+   第一个定义，使用`function`关键字作为独立声明，可能是 JS 中最常用的方式，并定义了一个名为`first`的函数（即`first.name=="first"`）。由于*变量提升*，这个函数将在定义它的作用域中随处可访问。

在[`developer.mozilla.org/en-US/docs/Glossary/Hoisting`](https://developer.mozilla.org/en-US/docs/Glossary/Hoisting)上阅读更多关于变量提升的内容，并记住它只适用于声明，而不适用于初始化。

+   第二个定义，将函数赋值给一个变量，也会产生一个函数，但是是一个*匿名*的函数（即没有名称）。然而，许多 JS 引擎能够推断名称应该是什么，并设置`second.name=="second"`（检查下面的代码，显示了匿名函数没有被分配名称的情况）。由于赋值不会被提升，函数只有在赋值执行后才能访问。此外，你可能更喜欢用`const`来定义变量，而不是`var`，因为你不应该改变这个函数：

```js
var second = function() {};
console.log(second.name);
// "second"

var myArray = new Array(3);
myArray[1] = function() {};
console.log(myArray[1].name);
// ""
```

+   第三个定义与第二个相同，只是函数现在有了自己的名称：`third.name === "someName"`。

函数的名称在你想要调用它时是相关的，如果你计划进行递归调用也是相关的；我们将在第九章*Designing Functions - Recursion*中回到这一点。如果你只是想要一个用于回调的函数，你可以不用名称。但是请注意，命名函数在错误回溯中更容易被识别。

+   第四个定义，使用立即调用的表达式，让你可以使用闭包。内部函数可以以完全私有、封装的方式使用外部函数中定义的变量或其他函数。回到我们在第一章的*Closures*部分看到的计数器制作函数，我们可以写出以下内容：

```js
var myCounter = (function(initialValue = 0) {
    let count = initialValue;
 return function() {
        count++;
 return count;
 };
})(77);

myCounter(); // 78
myCounter(); // 79
myCounter(); // 80
```

仔细研究代码：外部函数接收一个参数（在这种情况下是 77），这个参数被用作`count`的初始值（如果没有提供初始值，我们从零开始）。内部函数可以访问`count`（因为闭包的原因），但是这个变量在其他地方是无法访问的。在所有方面，返回的函数是一个普通的函数；唯一的区别是它可以访问私有元素。这也是*module*模式的基础。

+   第五个定义是不安全的，你不应该使用它！你传递参数名称，然后将实际的函数体作为最后一个参数的字符串传递--并且使用了`eval()`的等价物来创建函数，这可能会导致许多危险的黑客攻击，所以不要这样做！只是为了激发你的好奇心，让我们看一个例子，重写我们在第一章的*Spread*部分中看到的非常简单的`sum3()`函数：

```js
var sum3 = new Function("x", "y", "z", "var t = x+y+z; return t;");
sum3(4, 6, 7); // 17
```

这种定义不仅不安全，而且还有一些其他怪癖，比如不会在创建上下文中创建闭包，而且总是全局的。查看[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function)了解更多信息，但请记住，使用这种方式创建函数不是一个好主意！

+   最后，使用箭头`=>`定义的最紧凑的方式来定义函数，我们将尽可能地尝试使用这种方式。我们将在下一节详细介绍。

# 箭头函数 - 现代的方式

即使箭头函数基本上与其他函数一样工作，但是与普通函数有一些重要的区别。这些函数可以隐式返回一个值，`this`的值不会被绑定，也没有`arguments`对象。让我们来看看这三点。

还有一些额外的区别：箭头函数不能用作构造函数，它们没有`prototype`属性，也不能用作生成器，因为它们不允许使用`yield`关键字。有关这些点的更多细节，请参阅[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Functions/Arrow_functions#No_binding_of_this`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Functions/Arrow_functions#No_binding_of_this)。

# 返回值

在 lambda 风格中，函数只包括一个结果。为了简洁起见，新的箭头函数提供了这种语法。当你写类似`(x,y,z) =>`的表达式时，会隐含一个返回。例如，以下两个函数实际上与我们之前展示的`sum3()`函数做的事情是一样的：

```js
const f1 = (x, y, z) => x + y + z;

const f2 = (x, y, z) => {
    return x + y + z;
};
```

如果你想返回一个对象，那么你必须使用括号，否则 JS 会认为代码是有意义的。

“风格问题：当你用只有一个参数定义箭头函数时，你可以省略它周围的括号。为了一致性，我更喜欢总是包括它们。然而，我使用的格式化工具，prettier，不赞成。随意选择你的风格！”

# 处理 this 值

JS 的一个经典问题是处理`this`的方式--它的值并不总是你期望的那样。ES2015 通过箭头函数解决了这个问题，它们继承了正确的`this`值，因此避免了问题。要看一个可能出现问题的例子，在下面的代码中，当超时函数被调用时，`this`将指向全局（`window`）变量，而不是新对象，所以你会在控制台中得到一个*未定义*：

```js
function ShowItself1(identity) {
 this.identity = identity;
 setTimeout(function() {
 console.log(this.identity);
 }, 1000);
}

var x = new ShowItself1("Functional");
// *after one second, **undefined** is displayed*
```

有两种经典的解决方法，使用老式的 JS5，以及箭头函数的工作方式：

+   一种解决方案使用了闭包，并定义了一个本地变量（通常命名为`that`或者有时是`self`），它将获得`this`的原始值，这样它就不会是未定义的

+   第二种方法使用`.bind()`，所以超时函数将绑定到正确的`this`值。

+   第三种更现代的方式只是使用箭头函数，所以`this`会得到正确的值（指向对象）而无需其他操作

我们还将使用`.bind()`。请参见 lambda 和 eta 部分。

让我们看看实际代码中的三种解决方案：

```js
function ShowItself2(identity) {
 this.identity = identity;
    let that = this;
 setTimeout(function() {
 console.log(that.identity);
 }, 1000);

 setTimeout(
 function() {
 console.log(this.identity);
 }.bind(this),
 2000
 );

 setTimeout(() => {
 console.log(this.identity);
 }, 3000);
}

var x = new ShowItself2("JavaScript");
// *after one second, "JavaScript"*
// *after another second, the same*
// *after yet another second, once again*
```

# 处理参数

在第一章中，*成为功能性-几个问题*，和第二章中，*思考功能性-第一个例子*，我们看到了一些使用扩展（`...`）运算符的用法。然而，我们将要做的最实际的用法，与处理参数有关；我们将在第六章中看到一些这方面的案例，*生成函数-高阶函数*。让我们回顾一下我们的`once()`函数：

```js
const once = func => {
 let done = false;
 return (...args) => {
 if (!done) {
 done = true;
 func(...args);
 }
 };
};
```

为什么我们要写`return (...args) =>`，然后是`func(...args)`？关键在于处理可变数量（可能为零）的参数的更现代方式。在旧版本的 JS 中，你是如何处理这种代码的？答案与`arguments`对象有关（*不是*数组！），它允许你访问传递给函数的实际参数。

有关更多信息，请阅读[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Functions/arguments.`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Functions/arguments)

在 JS5 及更早版本中，如果我们希望函数能够处理任意数量的参数，我们必须编写以下代码：

```js
function somethingElse() {
 // *get arguments and do something*
}

function listArguments() {
 console.log(arguments);
 var myArray = Array.prototype.slice.call(arguments);
 console.log(myArray);
 somethingElse.apply(null, myArray);
}

listArguments(22, 9, 60);
// (3) [22, 9, 60, callee: function, Symbol(Symbol.iterator): function]
// (3) [22, 9, 60]
```

第一个日志显示`arguments`实际上是一个对象；第二个日志对应一个简单的数组。另外，注意调用`somethingElse()`所需的复杂方式，需要使用`.apply()`。

在 ES8 中等价的代码是什么？答案要简短得多，这就是为什么我们将在整个文本中看到使用扩展运算符的几个例子：

```js
function listArguments2(...args) {
 console.log(args);
 somethingElse(...args);
}

listArguments2(12, 4, 56);
// (3) [12, 4, 56]
```

要记住的要点是：

+   通过编写`listArguments2(...args)`，我们立即并清楚地表达了我们的新函数接收多个（可能为零）参数。

+   你无需做任何事情就可以得到一个数组。控制台日志显示`args`确实是一个数组，不需要进一步操作。

+   编写`somethingElse(...args)`比之前必须使用的替代方法（使用`.apply()`）更清晰。

顺便说一下，ES8 中仍然可以使用`arguments`对象。如果你想从中创建一个数组，有两种替代方法可以做到，而不必使用`Array.prototype.slice.call`的技巧：

+   使用`.from()`方法，并写`var myArray=Array.from(arguments)`

+   或者更简单地说，比如`var myArray=[...arguments]`，这展示了扩展操作符的另一种用法。

当我们涉及到高阶函数时，编写处理其他函数的函数，可能具有未知数量的参数，将会很普遍。ES8 提供了一种更简洁的方法来做到这一点，这就是为什么你必须习惯这种用法；这是值得的！

# 一个参数还是多个参数？

还可以编写返回函数的函数，在第六章中，我们将看到更多的这种情况。例如，在 lambda 演算中，你不会写带有多个参数的函数，而只会使用一个参数，通过应用一种叫做“柯里化”的东西（为什么要这样做？先留着这个想法；我们会讲到的）。

柯里化得名于哈斯克尔·柯里，他发展了这个概念。请注意，他也因函数式编程语言*Haskell*的名字而被铭记；双重认可！

例如，我们之前看到的对三个数字求和的函数，将被写成如下形式：

```js
const altSum3 = x => y => z => x + y + z;
```

为什么我改变了函数的名字？简单地说，因为这与之前的函数*不*相同。尽管它可以用来产生与我们之前函数完全相同的结果，但它在一个重要的方面有所不同：你如何使用它？比如，对数字 1、2 和 3 求和？你将不得不写成：

```js
altSum3(1)(2)(3); // 6
```

在继续阅读之前先自我测试一下，并思考一下：如果你写成`altSum3(1,2,3)`会返回什么？

提示：它不会是一个数字！要获得完整答案，请继续阅读。

这是如何工作的？分开多次调用可能会有所帮助；这是 JS 解释器实际计算前面表达式的方式：

```js
let fn1 = altSum3(1);
let fn2 = fn1(2);
let fn3 = fn2(3);
```

从功能上来说！调用`altSum3(1)`的结果，根据定义，是一个函数，由于闭包的原因，等效于：

```js
let fn1 = y => z => 1 + y + z;
```

我们的`altSum3()`函数旨在接收一个参数，而不是三个！这次调用的结果`fn1`也是一个单参数函数。当你执行`fn1(2)`时，结果再次是一个函数，同样只有一个参数，等效于：

```js
let fn2 = z => 1 + 2 + z;
```

当你计算`fn2(3)`时，最终返回一个值；太好了！正如我们所说，这个函数做的是我们之前看到的相同类型的计算，但是以一种内在不同的方式。

你可能会认为柯里化只是一个奇特的技巧：谁会只想使用单参数函数呢？当我们考虑如何在第八章中连接函数-流水线和组合，或者第十二章中构建更好的容器-函数数据类型时，你会明白这样做的原因，下一步传递多个参数将不可行。

# 函数作为对象

“头等对象”的概念意味着函数可以被创建、分配、更改、作为参数传递，或者作为其他函数的结果返回，就像你可以对待数字或字符串一样。让我们从它们的定义开始。当你以通常的方式定义一个函数时：

```js
function xyzzy(...) { ... }
```

这（几乎）等同于写成：

```js
var xyzzy = function(...) { ... }
```

除了*hoisting*。JS 将所有定义移动到当前范围的顶部，但不包括赋值；因此，使用第一个定义，您可以从代码的任何位置调用`xyzzy(...)`，但使用第二个定义，直到执行赋值之后才能调用该函数。

看到与巨型洞穴冒险游戏的类似之处了吗？在任何地方调用`xyzzy(...)`并不总是有效！如果您从未玩过这个著名的互动小说游戏，请尝试在线游戏--例如，在[`www.web-adventures.org/cgi-bin/webfrotz?s=Adventure`](http://www.web-adventures.org/cgi-bin/webfrotz?s=Adventure)或[`www.amc.com/shows/halt-and-catch-fire/colossal-cave-adventure/landing`](http://www.amc.com/shows/halt-and-catch-fire/colossal-cave-adventure/landing)。

我们想要表达的观点是，函数可以分配给变量--并且如果需要，还可以重新分配。同样，我们可以在需要时*现场*定义函数。我们甚至可以在不命名它们的情况下执行此操作：与常见表达式一样，如果仅使用一次，则不需要命名它或将其存储在变量中。

# 一个 React+Redux 减速器

我们可以看到另一个涉及分配函数的例子。正如我们在本章前面提到的，React+Redux 通过分派由减速器处理的操作来工作。通常，减速器包括带有开关的代码：

```js
function doAction(state = initialState, action) {
 let newState = {};
 switch (action.type) {
 case "CREATE":
 // *update state, generating newState,*
 // *depending on the action data*
 // *to create a new item*
 return newState;
 case "DELETE":
 // *update state, generating newState,*
 // *after deleting an item*
 return newState;
 case "UPDATE":
 // *update an item,*
 // *and generate an updated state*
 return newState;
 default:
 return state;
 }
}
```

为`state`提供`initialState`作为默认值是初始化全局状态的简单方法。不要注意这个默认值；对于我们的示例来说并不重要，我只是为了完整性而包含它。

通过利用存储函数的可能性，我们可以构建一个*调度表*并简化前面的代码。首先，我们将使用每种操作类型的函数代码初始化一个对象。基本上，我们只是采用前面的代码，并创建单独的函数：

```js
const dispatchTable = {
 CREATE: (state, action) => {
 // *update state, generating newState,*
 // *depending on the action data*
 // *to create a new item*
 return newState;
 },
 DELETE: (state, action) => {
 // *update state, generating newState,*
 // *after deleting an item*
 return newState;
 },
 UPDATE: (state, action) => {
 // *update an item,*
 // *and generate an updated state*
 return newState;
 }
};
```

我们已经将处理每种类型的操作的不同函数存储为对象中的属性，该对象将作为调度表。该对象仅创建一次，并且在应用程序执行期间保持不变。有了它，我们现在可以用一行代码重写操作处理代码：

```js
function doAction2(state = initialState, action) {
 return dispatchTable[action.type]
 ? dispatchTableaction.type
 : state;
}
```

让我们来分析一下：给定操作，如果`action.type`与调度对象中的属性匹配，我们执行相应的函数，该函数取自存储它的对象。如果没有匹配，我们只需返回当前状态，就像 Redux 要求的那样。如果我们不能处理函数（存储和调用它们）作为一等对象，这种代码是不可能的。

# 一个不必要的错误

然而，通常会有一个常见的（尽管实际上是无害的）错误。您经常会看到这样的代码：

```js
fetch("some/remote/url").then(function(data) {
 processResult(data);
});
```

这段代码是做什么的？这个想法是获取远程 URL，并在数据到达时调用一个函数--这个函数本身调用`processResult`并将`data`作为参数。也就是说，在`then()`部分，我们希望一个函数，给定`data`，计算`processResult(data)`...我们已经有这样一个函数了吗？

一点点理论：在λ演算术语中，我们将λx.func x 替换为一个函数--这称为 eta 转换，更具体地说是 eta 缩减。（如果您要以另一种方式进行操作，那将是 eta 抽象。）在我们的情况下，这可以被认为是一种（非常非常小的！）优化，但它的主要优势是更短，更紧凑的代码。

基本上，我们可以应用的规则是，每当您看到以下内容时： 

```js
function someFunction(someData) { 
 return someOtherFunction(someData);
}
```

您可以用`someOtherFunction`替换它。因此，在我们的示例中，我们可以直接写下面的内容：

```js
fetch("some/remote/url").then(processResult);
```

这段代码与以前的方式完全相同（或者，由于避免了一个函数调用，可能稍微更快），但更容易理解...或者不是？

这种编程风格称为 pointfree 风格或*暗示*风格，其主要特点是您从不为每个函数应用指定参数。这种编码方式的优势在于，它有助于编写者（以及代码的未来读者）思考函数本身及其含义，而不是在低级别上处理数据并与之一起工作。在较短的代码版本中，没有多余或无关的细节：如果您了解所调用的函数的作用，那么您就了解了完整代码的含义。在我们的文本中，我们通常（但不一定总是）以这种方式工作。

Unix/Linux 用户可能已经习惯了这种风格，因为当他们使用管道将命令的结果作为输入传递给另一个命令时，他们就以类似的方式工作。当您编写类似 ls | grep doc | sort 的内容时，ls 的输出是 grep 的输入，后者的输出是 sort 的输入--但是输入参数没有写在任何地方；它们是暗示的。我们将在第八章的*PointFree Style*部分中回到这一点，*连接函数 - 管道和组合*。

# 使用方法

然而，有一种情况您应该注意：如果您正在调用对象的方法会发生什么？如果您的原始代码是这样的：

```js
fetch("some/remote/url").then(function(data) {
 myObject.store(data);
});
```

然后，看似明显的转换后的代码会失败：

```js
fetch("some/remote/url").then(myObject.store);
```

为什么？原因是在原始代码中，调用的方法绑定到一个对象（`myObject`），但在修改后的代码中，它没有绑定，它只是一个`free`函数。然后我们可以通过使用`bind()`以简单的方式来修复它：

```js
fetch("some/remote/url").then(myObject.store.bind(myObject));
```

这是一个通用解决方案。处理方法时，您不能只是分配它；您必须使用`.bind(`以便正确的上下文可用。像这样的代码：

```js
function doSomeMethod(someData) { 
 return someObject.someMethod(someData);
}
```

应该转换为：

```js
const doSomeMethod = someObject.someMethod.bind(someObject);
```

在[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_objects/Function/bind`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_objects/Function/bind)上阅读有关`.bind()`的更多信息。

这看起来相当笨拙，不太优雅，但是这是必需的，以便方法将与正确的对象关联。我们将在第六章中看到这种应用，*生成函数 - 高阶函数*。即使这段代码看起来不太好看，但是每当您必须使用对象（记住，我们并没有说我们会尝试完全 FP 代码，并且如果其他构造使事情变得更容易，我们将接受其他构造）时，您必须记住在以 pointfree 风格传递它们之前绑定方法。

# 使用 FP 方式的函数

实际上有几种常见的编码模式实际上利用了 FP 风格，即使您不知道。让我们来看看它们，并指出代码的功能方面，这样您就可以更加习惯这种编码风格。

# 注入 - 整理它

`Array.prototype.sort()`方法提供了将函数作为参数传递的第一个示例。如果您有一个字符串数组，并且想对其进行排序，您可以使用以下代码。例如，要按字母顺序对彩虹颜色数组进行排序：

```js
var colors = [
 "violet",
 "indigo",
 "blue",
 "green",
 "yellow",
 "orange",
 "red"
];
colors.sort();
console.log(colors);
// *["blue", "green", "indigo", "orange", "red", "violet", "yellow"]*
```

请注意，我们不必为`.sort()`调用提供任何参数，但数组被完美地排序了。默认情况下，此方法根据其 ASCII 内部表示对字符串进行排序。因此，如果您使用此方法对数字数组进行排序，它将失败，因为它将决定 20 必须介于 100 和 3 之间，因为*100*在*20*之前--被视为字符串！--而后者在*3*之前...这需要修复！下面的代码显示了问题。

```js
var someNumbers = [3, 20, 100];
someNumbers.sort();
console.log(someNumbers);
// ***[100, 20, 3]***
```

但是，让我们暂时忘记数字，继续排序字符串。我们要问自己：如果我们想按适当的区域设置规则对一些西班牙单词（*palabras*）进行排序，会发生什么？我们将对字符串进行排序，但结果无论如何都不正确：

```js
var palabras = ["ñandú", "oasis", "mano", "natural", "mítico", "musical"];
palabras.sort();
console.log(palabras);
// *["mano", "musical", "mítico", "natural", "oasis", "ñandú"]* -- ***wrong result***!
```

对于语言或生物学爱好者，英文中的`"ñandú"`是`"rhea"`，一种类似鸵鸟的奔跑鸟。以`"ñ"`开头的西班牙语单词并不多，我们碰巧在我的国家乌拉圭有这些鸟，所以这就是这个奇怪单词的原因！

糟糕！在西班牙语中，`"ñ"`位于`"n"`和`"o"`之间，但`"ñandú"`最终被排序。此外，`"mítico"`（英文中为`"mythical"`；请注意带重音的`"i"`）应该出现在`"mano"`和`"musical"`之间，因为应该忽略波浪号。解决这个问题的适当方法是为`sort()`提供一个比较函数。在这种情况下，我们可以使用`localeCompare()`方法：

```js
palabras.sort((a, b) => a.localeCompare(b, "es"));
console.log(palabras);
// *["mano", "mítico", "musical", "natural", "ñandú", "oasis"]*
```

`a.localeCompare(b,"es")`调用比较字符串`a`和`b`，如果`a`应该在`b`之前，则返回负值，如果`a`应该在`b`之后，则返回正值，如果`a`和`b`相同，则返回 0--但是，根据西班牙（`"es"`）排序规则。现在事情变得正确了！通过引入一个易懂的名称的新函数，代码可能会变得更清晰：

```js
const spanishComparison = (a, b) => a.localeCompare(b, "es");

palabras.sort(spanishComparison);
// *sorts the palabras array according to Spanish rules:*
// *["mano", "mítico", "musical", "natural", "ñandú", "oasis"]*
```

在接下来的章节中，我们将讨论 FP 如何让您以更声明式的方式编写代码，生成更易理解的代码，这种小的改变有所帮助：代码的读者在到达排序时，即使没有注释，也会立即推断出正在做什么。

通过注入不同的比较函数来改变`sort()`函数的工作方式，实际上是*策略*设计模式的一个案例。我们将在第十一章中看到更多关于这一点的内容，*实现设计模式-函数式方法*。

以参数形式提供排序函数（以非常 FP 的方式！）还可以帮助解决其他一些问题，例如：

+   `sort()`只适用于字符串。如果要对数字进行排序（就像我们之前尝试的那样），您必须提供一个进行数字比较的函数。例如，您可以编写类似`myNumbers.sort((a,b) => a-b)`的东西

+   如果要按给定属性对对象进行排序，您将使用一个与之进行比较的函数。例如，您可以按年龄对人进行排序，类似于`myPeople.sort((a,b) => a.age - b.age)`的方式

有关`localeCompare()`的更多可能性，请参阅[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/String/localeCompare`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/String/localeCompare)。您可以指定要应用的区域设置规则，要放置大写/小写字母的顺序，是否忽略标点符号等等--但要小心；并非所有浏览器都支持所需的额外参数。

这是一个简单的例子，您可能以前使用过--但毕竟是 FP 模式。让我们继续讨论函数作为参数的更常见用法，当您进行 Ajax 调用时。

# 回调，承诺和继续

可能是将函数作为一等对象使用的最常见例子与回调和承诺有关。在 Node.JS 中，读取文件是通过类似以下方式异步完成的：

```js
const fs = require("fs");
fs.readFile("someFile.txt", (err, data) => {
 if (err) {
 console.error(err); // *or throw an error, or otherwise handle the problem*
 } else {
 console.log(data.toString());
 }
});
```

`readFile()`函数需要一个回调，在这个例子中只是一个匿名函数，当文件读取操作完成时调用。

使用更现代的编程风格，您可以使用承诺或 async/await。例如，在进行 Ajax 网络服务调用时，使用更现代的`fetch()`函数，您可以编写类似以下代码的内容：

```js
fetch("some/remote/url")
    .then(data => {
 // *Do some work with the returned data*
 })
    .catch(error => {
 // *Process all errors here*
 });
```

请注意，如果您定义了适当的`processData(data)`和`processError(error)`函数，代码可以缩短为`fetch("some/remote/url").then(processData).catch(processError)`，就像我们之前看到的那样。

# Continuation Passing Style

在前面的代码中，您调用一个函数，同时传递另一个函数，该函数在输入/输出操作完成时将被执行，可以被视为 CPS - *Continuation Passing Style*的一种情况。这种编码方式是什么？一个解释方式是，如果使用`return`语句是被禁止的，您将如何编程？

乍一看，这可能看起来是一个不可能的情况。然而，我们可以摆脱困境，只要我们同意这一点：允许您将回调传递给被调用的函数，因此当该过程准备返回给调用者时，它将调用传递的回调，而不是实际返回。在这些条件下，回调为被调用的函数提供了继续过程的方式，因此称为*Continuation*。我们现在不会深入讨论这个问题，但在第九章中，*设计函数 - 递归*，我们将深入研究它。特别是，CPS 将有助于避免重要的递归限制，正如我们将看到的那样。

研究如何使用 continuations 有时是具有挑战性的，但总是可能的。这种编码方式的一个有趣优势是，通过自己指定过程如何继续，您可以超越所有通常的结构（`if`，`while`，`return`等）并实现您可能想要的任何机制。这在某些类型的问题中可能非常有用，其中过程不一定是线性的。当然，这也可能导致您发明任何一种控制结构，远比您可能想象的使用`GOTO`语句更糟糕！图 3.1 显示了这种做法的危险！

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/577e359e-169d-429c-b927-d468d5aa63fd.png)图 3.1：如果您开始干扰程序流程，最糟糕的情况会是什么？

（注：这张 XKCD 漫画可以在 https://xkcd.com/292/上在线获取。）

您不仅限于传递单个 continuation。与 promises 一样，您可以提供两个或更多的备用回调。顺便说一句，这也可以提供另一个问题的解决方案：您如何处理异常？如果我们简单地允许函数抛出错误，那将意味着隐含地返回给调用者 - 而我们不希望这样。解决方法是提供一个备用回调（即不同的 continuation），以便在抛出异常时使用（在第十二章中，*构建更好的容器 - 函数数据类型*，我们将找到另一个解决方案，使用*Monads*）：

```js
function doSomething(a, b, c, normalContinuation, errorContinuation) {
 let r = 0;
 // *... do some calculations involving a, b, and c,*
 // *and store the result in r*

 // *if an error happens, invoke:*
 // *errorContinuation("description of the error")*

 // *otherwise, invoke:*
 // *normalContinuation(r)*
}
```

# Polyfills

能够动态分配函数（就像您可以为变量分配不同的值一样）还可以让您在定义*polyfills*时更有效地工作。

# 检测 Ajax

让我们回到 Ajax 开始出现的时候。鉴于不同的浏览器以不同的方式实现了 Ajax 调用，您总是需要围绕这些差异编码：

```js
function getAjax() {
 let ajax = null;
    if (window.XMLHttpRequest) {
 // *modern browser? use XMLHttpRequest*
 ajax = new XMLHttpRequest();

 } else if (window.ActiveXObject) {
 // *otherwise, use ActiveX for IE5 and IE6*
 ajax = new ActiveXObject("Microsoft.XMLHTTP");

 } else {
 throw new Error("No Ajax support!");
 }

 return ajax;
}
```

这个方法有效，但意味着你需要为每次调用重新执行 Ajax 检查，即使测试的结果永远不会改变。有一种更有效的方法，它涉及使用函数作为一等对象。我们可以定义*两个*不同的函数，只测试一次条件，然后将正确的函数分配给以后使用：

```js
(function initializeGetAjax() {
 let myAjax = null;
 if (window.XMLHttpRequest) {
 // *modern browsers? use XMLHttpRequest*
 myAjax = function() {
 return new XMLHttpRequest();
 };

 } else if (window.ActiveXObject) {
 // *it's ActiveX for IE5 and IE6*
 myAjax = function() {
 new ActiveXObject("Microsoft.XMLHTTP");
 };

 } else {
 myAjax = function() {
 throw new Error("No Ajax support!");
 };
 }

    window.getAjax = myAjax;
})();
```

这段代码展示了两个重要的概念。首先，我们可以动态分配一个函数：当这段代码运行时，`window.getAjax`（即全局`getAjax`变量）将根据当前浏览器获得三种可能的值之一。当您稍后在代码中调用`getAjax()`时，正确的函数将执行，而无需进行任何进一步的浏览器检测测试。

第二个有趣的想法是我们定义了`initializeGetAjax`函数，并立即运行它——这种模式称为 IIFE，代表*Immediately Invoked Function Expression*。函数运行后，会*自我清理*，因为它的所有变量都是局部的，在函数运行后甚至都不存在了。我们以后会更多地了解这一点。

# 添加缺失的函数

这种在运行时定义函数的想法，也使我们能够编写*polyfills*，提供其他缺失的函数。例如，假设我们不是写代码像：

```js
if (currentName.indexOf("Mr.") !== -1) {
 // *it's a man*
 ...
}
```

你会更喜欢使用更新、更清晰的方式，只需写：

```js
if (currentName.includes("Mr.")) {
 // *it's a man*
 ...
}
```

如果你的浏览器不提供`.includes()`会发生什么？再一次，我们可以在运行时定义适当的函数，但只有在需要时才这样做。如果`.includes()`可用，你什么都不用做，但如果它缺失了，你就定义一个提供完全相同功能的 polyfill。

你可以在 Mozilla 的开发者网站上找到许多现代 JS 功能的 polyfill。例如，我们用于 includes 的 polyfill 直接取自[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/String/includes`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/String/includes)。

```js
if (!String.prototype.includes) {
    String.prototype.includes = function(search, start) {
 "use strict";
 if (typeof start !== "number") {
 start = 0;
 }
 if (start + search.length > this.length) {
 return false;
 } else {
 return this.indexOf(search, start) !== -1;
 }
 };
}
```

当这段代码运行时，它会检查`String`原型是否已经有了 includes 方法。如果没有，它会给它分配一个执行相同工作的函数，所以从那时起，你就可以使用`.includes()`而不用再担心了。

直接修改标准类型的原型对象通常是不被赞同的，因为本质上它相当于使用全局变量，因此容易出错。然而，在这种情况下，为一个已经被广泛认可和已知的函数编写 polyfill，几乎不太可能引起任何冲突。

最后，如果你认为之前展示的 Ajax 示例已经老掉牙了，考虑一下：如果你想使用更现代的`fetch()`方式来调用服务，你会发现并不是所有的现代浏览器都支持它（查看[`caniuse.com/#search=fetch`](http://caniuse.com/#search=fetch)来验证），你也需要使用一个 polyfill，比如[`github.com/github/fetch`](https://github.com/github/fetch)上的 polyfill。研究一下代码，你会发现它基本上使用了之前描述的相同方法，来检查是否需要一个 polyfill，并创建它。

# Stubbing

这是一个在某些方面类似于 polyfill 的用例：根据环境的不同，让函数执行不同的工作。这个想法是做*stubbing*，这是测试中的一个概念，意思是用另一个函数替换一个函数，这个函数执行一个更简单的工作，而不是执行实际的工作。

一个常见的情况是使用日志函数。你可能希望应用程序在开发时进行详细的日志记录，但在生产时不发出任何声音。一个常见的解决方案是写一些类似于以下的东西：

```js
let myLog = someText => {
    if (DEVELOPMENT) {
 console.log(someText); // *or some other way of logging*
 } else {
 // do nothing
 }
}
```

这样做是有效的，但就像关于 Ajax 检测的示例一样，它做的工作比需要的要多。

关于 Ajax 检测，它做的工作比需要的要多，因为它每次都要检查应用程序是否处于开发状态。如果我们将日志函数 stub out，这样它就不会实际记录任何东西，我们可以简化代码（并获得一个非常非常小的性能提升！）：

```js
let myLog;
if (DEVELOPMENT) {
 myLog = someText => console.log(someText);
} else {
 myLog = someText => {};
}
```

我们甚至可以用三元运算符做得更好：

```js
const myLog = DEVELOPMENT
 ? someText => console.log(someText)
 : someText => {};
```

这有点晦涩，但我更喜欢它，因为它使用了`const`，它是不可修改的。

考虑到 JS 允许调用函数时传递比参数更多的参数，并且当我们不处于开发状态时`myLog()`不做任何事情，我们也可以写`() => {}`，它也可以正常工作。然而，我更喜欢保持相同的签名，这就是为什么我指定了`someText`参数，即使它不会被使用；由你决定！

# 立即调用

还有另一种常见的函数用法，通常在流行的库和框架中看到，它让你从其他语言中带入 JS（甚至是旧版本！）一些模块化的优势。通常的写法是像下面这样：

```js
(function() {
 // *do something...*
})();
```

另一种等效的样式是`(function(){ ... }())` - 注意函数调用的括号放置不同。两种样式都有他们的粉丝；选择适合你的那种，但要保持一致。

你也可以使用相同的样式，但将一些参数传递给函数，这些参数将用作其参数的初始值：

```js
(function(a, b) {
 // *do something, using the*
 // *received arguments for a and b...*
})(some, values);
```

最后，你也可以从函数中返回一些东西：

```js
let x = (function(a, b) {
 // *...return an object or function*
})(some, values);
```

模式本身被称为，正如我们提到的，*立即调用函数表达式* - 通常简化为 IIFE，发音为*iffy*。这个名字很容易理解：你正在定义一个函数并立即调用它，所以它立即执行。为什么要这样做，而不是简单地内联编写代码呢？原因与作用域有关。

注意函数周围的括号。这有助于解析器理解我们正在写一个表达式。如果你省略了第一组括号，JS 会认为你正在写一个函数声明而不是调用。括号也作为一个视觉提示，所以你的代码读者会立即认出 IIFE。

如果你在 IIFE 内定义了任何变量或函数，由于 JS 的函数作用域，这些定义将是内部的，你的代码的任何其他部分都无法访问它。想象一下，你想写一些复杂的初始化，比如下面的例子：

```js
function ready() { ... }
function set() { ... }
function go() { ... }
// *initialize things calling ready(),*
// *set() and go() appropriately*
```

可能出什么问题？问题在于你可能（不小心）有一个与这三个函数中的任何一个同名的函数，提升会意味着*后面*的函数会被调用：

```js
function ready() {
 console.log("ready");
}
function set() {
 console.log("set");
}
function go() {
 console.log("go");
}
ready();
set();
go();

function set() {
 console.log("UNEXPECTED...");
}
// *"ready"*
// *"UNEXPECTED"*
// *"go"*
```

哎呀！如果你使用了 IIFE，问题就不会发生。此外，三个内部函数甚至不会对代码的其余部分可见，这有助于保持全局命名空间的污染较少：

```js
(function() {
 function ready() {
 console.log("ready");
 }
 function set() {
 console.log("set");
 }
 function go() {
 console.log("go");
 }
 ready();
 set();
 go();
})();

function set() {
 console.log("UNEXPECTED...");
}
// *"ready"*
// *"set"*
// *"go"*
```

要看一个涉及返回值的例子，我们可以重新访问第一章中的例子，*成为函数式 - 几个问题*，并编写以下内容，这将创建一个单一的计数器：

```js
const myCounter = (function() {
 let count = 0;
 return function() {
 count++;
 return count;
 };
})();
```

然后，每次调用`myCounter()`都会返回一个递增的计数 - 但没有任何其他部分的代码会覆盖内部的`count`变量，因为它只能在返回的函数内部访问。

# 问题

3.1 **未初始化的对象？**React+Redux 程序员通常编写*action creators*来简化稍后由 reducer 处理的操作的创建。操作是对象，必须包括一个`type`属性，用于确定你正在分派的操作的类型。下面的代码应该做到这一点，但你能解释意外的结果吗？

```js
 const simpleAction = t => {
 type: t;
 };

 console.log(simpleAction("INITIALIZE"));
 // ***undefined***
```

3.2\. **箭头函数允许吗？**如果你使用箭头函数来定义`listArguments()`和`listArguments2()`，而不是我们使用的*经典*方式，使用`function`关键字，一切都会一样吗？

3.3\. **一行代码。**一些节省代码行数的程序员建议将`doAction2()`重写为一行代码...尽管格式不让它看起来如此！你认为这样正确吗？

```js
 const doAction3 = (state = initialState, action) =>
 (dispatchTable[action.type] && 
 dispatchTableaction.type) ||
 state;
```

# 总结

在本章中，我们讨论了 JS 中定义函数的几种方式，主要关注箭头函数，它比标准函数有几个优点，包括更简洁。我们展示了*柯里化*的概念（我们稍后会重新讨论），考虑了函数作为一等对象的一些方面，最后考虑了几种 JS 技术，这些技术在概念上完全是 FP。

在第四章中，*行为得当 - 纯函数*，让我们更深入地探讨函数，从而引入*纯函数*的概念，这将使我们的编程风格更好。


# 第四章：行为得当-纯函数

在第三章中，*从函数开始-核心概念*，我们将函数视为 FP 中的关键元素，详细介绍了箭头函数，并介绍了一些概念，如注入、回调、填充和存根。现在，在这一章中，我们将有机会重新审视或应用其中一些想法，同时我们也...

+   考虑*纯度*的概念，以及为什么我们应该关心*纯函数*

+   审查*引用透明性*的概念

+   认识到副作用所暗示的问题

+   展示纯函数的一些优势

+   描述不纯函数的主要原因

+   找到减少不纯函数数量的方法

+   专注于测试纯函数和不纯函数的方法

# 纯函数

纯函数的行为方式与数学函数相同，并提供各种好处。如果函数满足两个条件，可以认为函数是纯的：

+   **给定相同的参数，函数总是计算并返回相同的结果**，无论调用多少次，或者在什么条件下调用它。这个结果值不能依赖于任何*外部*信息或状态，这些信息在程序执行期间可能会发生变化，并导致它返回不同的值。函数结果也不能依赖于 I/O 结果、随机数或其他外部变量，这些变量不是直接可控的值。

+   **在计算其结果时，函数不会引起任何可观察的*副作用***，包括输出到 I/O 设备，对象的突变，函数外部程序状态的改变等等。

如果你愿意，你可以简单地说纯函数不依赖于，也不修改其范围之外的任何东西，并且总是对相同的输入参数返回相同的结果。

在这个背景下还有一个词叫做*幂等性*，但它并不完全相同。一个幂等函数可以被调用任意次，并且总是产生相同的结果。然而，这并不意味着函数没有副作用。幂等性通常在 RESTful 服务的背景下提到，并且一个简单的例子展示了纯度和幂等性之间的区别。一个`PUT`调用会导致数据库记录被更新（一个副作用），但如果你重复调用，元素将不会被进一步修改，因此数据库的全局状态不会再发生变化。

我们还可以引用一个软件设计原则，并提醒自己函数应该*只做一件事，只做一件事，而且只做那件事*。如果一个函数做了其他事情，并且有一些隐藏的功能，那么对状态的依赖将意味着我们无法预测函数的输出，并且会让开发人员的工作变得更加困难。

让我们更详细地了解这些条件。

# 引用透明性

在数学中，*引用透明性*是一种属性，它允许您用其值替换表达式，而不改变您正在进行的任何操作的结果。

*引用透明性*的对应物是*引用不透明性*。引用不透明的函数不能保证始终产生相同的结果，即使使用相同的参数调用。

举个简单的例子，当优化编译器决定进行*常量折叠*并替换句子时：

```js
var x = 1 + 2 * 3;
```

与：

```js
var x = 1 + 6;
```

或者，更好的是，直接使用：

```js
var x = 7;
```

为了节省执行时间，它利用了所有数学表达式和函数（根据定义）都是引用透明的事实。另一方面，如果编译器无法预测给定表达式的输出，它将无法以任何方式优化代码，计算将不得不在运行时进行。

在λ演算中，如果你用函数的计算值替换涉及函数的表达式的值，这个操作被称为β（beta）规约。请注意，你只能安全地对引用透明的函数进行这样的操作。

所有算术表达式（涉及数学运算符和函数）都是引用透明的：*22*9*总是可以被 198 替换。涉及 I/O 的表达式不是透明的，因为它们的结果在执行之前无法知道。出于同样的原因，涉及日期和时间相关函数或随机数的表达式也不是透明的。

关于 JS 函数，你可能会自己编写一些不满足*引用透明*条件的函数。事实上，函数甚至不需要返回一个值，尽管 JS 解释器会在这种情况下返回一个未定义的值。

有些语言区分函数和过程，预期函数返回某个值，而过程不返回任何东西，但 JS 不是这种情况。此外，有些语言提供手段来确保函数是引用透明的。

如果你愿意的话，你可以将 JS 函数分类为：

+   **纯函数**：它们根据其参数返回一个值，并且没有任何副作用

+   **副作用**：它们不返回任何东西（实际上，JS 让这些函数返回一个`undefined`值，但这在这里并不重要），但会产生某种副作用

+   **具有副作用的函数**：意味着它们返回一些值（这些值可能不仅取决于函数参数，还涉及副作用）

在 FP 中，非常强调第一组引用透明函数。不仅编译器可以推断程序行为（从而能够优化生成的代码），而且程序员也可以更容易地推断程序和其组件之间的关系。反过来，这可以帮助证明算法的正确性，或者通过用等效函数替换一个函数来优化代码。

# 副作用

什么是*副作用*？我们可以将其定义为在执行某些计算或过程期间发生的状态变化或与外部元素（用户、网络服务、另一台计算机等）的交互。

对于这个意义的范围可能存在一些误解。在日常语言中，当你谈论*副作用*时，这有点像谈论*附带损害*--对于给定行动的一些*意外*后果。然而，在计算中，我们包括函数外的每一个可能的效果或变化。如果你编写一个旨在执行`console.log()`调用以显示一些结果的函数，即使这正是你首先打算让函数执行的，它也会被视为副作用！

# 通常的副作用

有（太多！）被认为是副作用的事情。在 JS 编程中，包括前端和后端编码，你可能会发现更常见的副作用包括：

+   改变全局变量。

+   改变接收的对象。

+   进行任何类型的 I/O，比如显示警报消息或记录一些文本。

+   处理和更改文件系统。

+   更新数据库。

+   调用网络服务。

+   查询或修改 DOM。

+   触发任何外部进程。

+   最后，只是调用一些其他函数，这些函数恰好会产生自己的副作用。你可以说不纯度是具有传染性的：调用不纯的函数的函数会自动变得不纯！

有了这个定义，让我们开始考虑什么会导致函数不纯（或者*引用不透明*，正如我们所看到的）。

# 全局状态

在所有前述观点中，最常见的原因是使用非本地变量，与程序的其他部分共享全局状态。由于纯函数根据定义，始终返回相同的输出值，给定相同的输入参数，如果函数引用其内部状态之外的任何东西，它就会自动变得不纯。此外，这对于调试是一个障碍，要理解函数的作用，你必须了解状态如何得到其当前值，这意味着要理解程序的所有过去历史：这并不容易！

```js
let limitYear = 1999;

const isOldEnough = birthYear => birthYear <= limitYear;

console.log(isOldEnough(1960)); // true
console.log(isOldEnough(2001)); // false
```

`isOldEnough()`函数正确检测一个人是否至少 18 岁，但它依赖于一个外部变量（该变量仅适用于 2017 年）。除非你知道外部变量及其值是如何得到的，否则你无法知道函数的作用。测试也很困难；你必须记住创建全局`limitYear`变量，否则所有的测试都将无法运行。尽管函数可以工作，但实现并不是最佳的。

这个规则有一个例外。看看下面的情况：`circleArea`函数，它根据半径计算圆的面积，是纯的还是不纯的？

```js
const PI = 3.14159265358979;
const circleArea = r => PI * Math.pow(r, 2); // or PI * r ** 2
```

尽管函数正在访问外部状态，但`PI`是一个常数（因此不能被修改），允许在`circleArea`中替换它而不改变功能，因此我们应该接受函数是纯净的。对于相同的参数，函数将始终返回相同的值，因此满足我们的纯度要求。

即使你使用`Math.PI`而不是我们定义的常数（顺便说一句，这是一个更好的主意），参数仍然是相同的；常数是不能改变的，所以函数保持纯净。

# 内部状态

这个概念也适用于内部变量，其中存储了本地状态，然后用于将来的调用。在这种情况下，外部状态没有改变，但是有一些副作用意味着未来从函数返回的值会有所不同。让我们想象一个`roundFix()`四舍五入函数，它考虑到是否已经过多地向上或向下四舍五入，所以下次它将以另一种方式四舍五入，使累积差异更接近零：

```js
const roundFix = (function() {
 let accum = 0;
 return n => {
 // *reals get rounded up or down*
 // *depending on the sign of accum*
 let nRounded = accum > 0 ? Math.ceil(n) : Math.floor(n);
 console.log("accum", accum.toFixed(5), " result", nRounded);
 accum += n - nRounded;
 return nRounded;
 };
})();
```

关于这个函数的一些评论：

+   `console.log()`行只是为了这个例子; 它不会包含在真实世界的函数中。它列出了到目前为止的累积差异，以及它将返回的结果：给定数字四舍五入的结果。

+   我们正在使用 IIFE 模式，这是我们在`myCounter()`示例中看到的，在第三章的*立即调用*部分，*从函数开始-核心概念*，以便获得隐藏的内部变量。

+   `nRounded`的计算也可以写成`Mathaccum > 0 ? "ceil": "floor"`--我们测试`accum`来看要调用什么方法（`"ceil"`或`"floor"`），然后使用`Object["method"]`表示法间接调用`Object.method()`。我们使用的方式更清晰，但我只是想提醒你，如果你碰巧发现这种其他编码风格。

仅使用两个值（认出它们吗？）运行此函数显示，对于给定的输入，结果并不总是相同。控制台日志的*结果*部分显示了值是如何四舍五入的，向上还是向下：

```js
roundFix(3.14159); // *accum  0.00000    result 3*
roundFix(2.71828); // *accum  0.14159    result 3*
roundFix(2.71828); // *accum -0.14013    result 2*
roundFix(3.14159); // *accum  0.57815    result 4*
roundFix(2.71828); // *accum -0.28026    result 2*
roundFix(2.71828); // *accum  0.43802    result 3*
roundFix(2.71828); // *accum  0.15630    result 3*
```

第一次，`accum`是零，所以 3.14159 被舍入，`accum`变成了`0.14159`，对我们有利。第二次，因为`accum`是正数（意味着我们一直在我们的利益上四舍五入），所以 2.71828 被舍入为 3，现在`accum`变成了负数。第三次，相同的 2.71828 值被舍入为 2，因为累积的差值是负的；我们得到了相同输入的不同值！其余的例子类似；你可以得到相同的值被舍入为上或下，取决于累积的差异，因为函数的结果取决于它的内部状态。

这种使用内部状态的方式，是为什么许多 FPers 认为使用对象可能是不好的。在 OOP 中，我们开发人员习惯于存储信息（属性）并将它们用于未来的计算。然而，这种用法被认为是不纯的，因为尽管传递相同的参数，重复的方法调用可能返回不同的值。

# 参数突变

你还需要意识到一个不纯的函数可能会修改它的参数。在 JS 中，参数是按值传递的，除了数组和对象，它们是按引用传递的。这意味着对函数参数的任何修改都会影响原始对象或数组的实际修改。这可能会更加模糊，因为有几种*mutator*方法，它们根据定义改变了底层对象。例如，假设你想要一个函数，它会找到一个字符串数组的最大元素（当然，如果它是一个数字数组，你可以简单地使用`Math.max()`而无需进一步操作）。一个简短的实现可能如下所示：

```js
const maxStrings = a => a.sort().pop();

let countries = ["Argentina", "Uruguay", "Brasil", "Paraguay"];
console.log(maxStrings(countries)); // ***"Uruguay"***
```

该函数确实提供了正确的结果（如果你担心外语，我们已经在第三章的*注入：解决问题*部分看到了解决方法，*从函数开始-核心概念*），但它有一个缺陷：

```js
console.log(countries);  // ***["Argentina", "Brasil", "Paraguay"]***
```

糟糕的是，原始数组被修改了；这是根据定义的副作用！如果你再次调用`maxStrings(countries)`，而不是返回与之前相同的结果，它会产生另一个值；显然，这不是一个纯函数。在这种情况下，一个快速的解决方法是对数组的副本进行操作（我们可以使用扩展运算符来帮助），但我们将在第十章中处理更多避免这类问题的方法，*确保纯度-不可变性*：

```js
const maxStrings2 = a => [...a].sort().pop();

let countries = ["Argentina", "Uruguay", "Brasil", "Paraguay"];
console.log(maxStrings2(countries)); *// "Uruguay"*
console.log(countries); // *["Argentina", "Uruguay", "Brasil", "Paraguay"]*
```

# 麻烦的函数

最后，一些函数也会引起问题。例如，`Math.random()`是不纯的：它不总是返回相同的值--如果它这样做了，它肯定会打破它的目的！此外，对该函数的每次调用都会修改全局*种子*值，从而计算下一个*随机*值。

*随机*数字实际上是由内部函数计算的，因此根本不是随机的（如果你知道使用的公式和种子的初始值），这意味着*伪随机*可能更合适。

例如，考虑这个生成随机字母（`"A"`到`"Z"`）的函数：

```js
const getRandomLetter = () => {
 const min = "A".charCodeAt();
 const max = "Z".charCodeAt();
 return String.fromCharCode(
 Math.floor(Math.random() * (1 + max - min)) + min
 );
};
```

这个函数不接受任何参数，但是预期每次调用都会产生*不同*的结果，这清楚地表明这个函数是不纯的。

查看我写的`getRandomLetter()`函数的解释，请访问[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/random`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/random)，以及[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String)的`.charCodeAt()`方法。

调用函数会继承不纯性。如果一个函数使用了不纯的函数，它立即变得不纯。我们可能想要使用`getRandomLetter()`来生成随机文件名，还可以选择给定的扩展名：

```js
const getRandomFileName = (fileExtension = "") => {
 const NAME_LENGTH = 12;
 let namePart = new Array(NAME_LENGTH);
 for (let i = 0; i < NAME_LENGTH; i++) {
 namePart[i] = getRandomLetter();
 }
 return namePart.join("") + fileExtension;
};
```

在第五章中，*声明式编程——更好的风格*，我们将看到一种更加函数式的初始化数组`namePart`的方法，使用`map()`。

由于它使用了`getRandomLetter()`，`getRandomFileName()`也是不纯的，尽管它的表现如预期：

```js
console.log(getRandomFileName(".pdf"));  // *"SVHSSKHXPQKG.pdf"*
console.log(getRandomFileName(".pdf"));  // *"DCHKTMNWFHYZ.pdf"*
console.log(getRandomFileName(".pdf"));  // *"GBTEFTVVHADO.pdf"*
console.log(getRandomFileName(".pdf"));  // *"ATCBVUOSXLXW.pdf"*
console.log(getRandomFileName(".pdf"));  // *"OIFADZKKNVAH.pdf"*
```

记住这个函数；我们稍后会在本章解决单元测试问题的一些方法，并稍作修改以帮助解决这个问题。

对于访问当前时间或日期的函数，不纯性的考虑也适用，因为它们的结果将取决于外部条件（即一天中的时间），这是应用程序的*全局状态*的一部分。我们可以重写我们的`isOldEnough()`函数，以消除对全局变量的依赖，但这并没有太大帮助：

```js
const isOldEnough2 = birthYear =>
 birthYear <= new Date().getFullYear() - 18;

console.log(isOldEnough2(1960)); // true
console.log(isOldEnough2(2001)); // false
```

一个问题已经被解决了——新的`isOldEnough2()`函数现在更加*安全*。此外，只要你不在新年前夕的午夜附近使用它，它将始终返回相同的结果，因此你可以说，用 19 世纪象牙皂的广告语来说，它是*约 99.44%纯*。然而，一个不便仍然存在：你该如何测试它？如果你今天写了一些测试，明年它们可能会开始失败。我们将不得不努力解决这个问题，我们稍后会看到如何解决。

还有其他一些不纯的函数，比如那些引起 I/O 的函数。如果一个函数从某个来源获取输入（网络服务、用户本身、文件等），显然返回的结果可能会有所不同。你还应该考虑 I/O 错误的可能性，因此同一个函数，调用同一个服务或读取同一个文件，可能在某个时候失败，原因是超出了它的控制范围（你应该假设你的文件系统、数据库、套接字等可能不可用，因此给定的函数调用可能产生错误，而不是预期的恒定、不变的答案）。即使是一个纯输出的、通常安全的语句，比如`console.log()`，它在内部并不会改变任何东西（至少在可见的方式上），但它确实会产生一些影响，因为用户看到了变化：产生的输出。

这是否意味着我们永远无法编写需要随机数、处理日期或进行 I/O 的程序，并且还使用纯函数？一点也不——但这意味着有些函数不会是纯函数，它们会有一些我们需要考虑的缺点；我们稍后会回到这个问题。

# 纯函数的优势

使用纯函数的主要优势，源于它们没有任何副作用。当你调用一个纯函数时，你不需要担心任何事情，除了你传递给它的参数。而且更重要的是，你可以确信你不会造成任何问题或破坏其他任何东西，因为函数只会处理你给它的东西，而不会处理外部来源。但这并不是它们唯一的优势；让我们看看更多。

# 执行顺序

从这一章中我们所说的另一个角度来看，纯函数可以被称为*健壮*的。你知道它们的执行——无论以哪种顺序——都不会对系统产生任何影响。这个想法可以进一步扩展：你可以并行评估纯函数，放心地得出结果不会与单线程执行中得到的结果有所不同。

不幸的是，JS 在并行编程方面限制了我们很多。我们可能会以非常有限的方式使用 Web Workers，但这大概就是它的极限了。对于 Node.js 开发人员，集群模块可能会有所帮助，尽管它并不是线程的替代品，只允许您生成多个进程以利用所有可用的 CPU 核心。总之，您不会得到诸如 Java 的线程之类的设施，因此在 JS 术语中，并行化并不是 FP 的优势。

当您使用纯函数时，需要牢记的另一个考虑因素是，没有明确的需要指定它们应该被调用的顺序。如果您使用数学，例如*f(2)+f(5)*这样的表达式总是与*f(5)+f(2)*相同；顺便说一下，这被称为*交换律*。然而，当您处理不纯函数时，这可能不成立，就像下面的代码所示：

```js
var mult = 1;
const f = x => {
 mult = -mult;
 return x * mult;
};

console.log(f(2) + f(5)); //  3
console.log(f(5) + f(2)); // -3
```

对于之前显示的不纯函数，您不能假设计算*f(3)+f(3)*会产生与*2*f(3)*相同的结果，或者*f(4)-f(4)*实际上会是零；检查一下！更常见的数学属性都泡汤了...

为什么您应该关心呢？当您编写代码时，无论是否愿意，您总是牢记着您学到的那些属性，比如交换律。因此，虽然您可能认为这两个表达式应该产生相同的结果，并相应地编写代码，但是对于不纯函数，您可能会遇到令人惊讶的难以修复的难以发现的错误。

# 记忆化

由于纯函数对于给定的输入始终产生相同的输出，您可以缓存函数的结果，避免可能昂贵的重新计算。这个过程，即仅在第一次评估表达式，并缓存结果以供以后调用，称为*记忆化*。

我们将在第六章中回到这个想法，*生成函数 - 高阶函数*，但让我们看一个手工完成的例子。斐波那契序列总是被用来举例，因为它简单，而且隐藏的计算成本。这个序列的定义如下：

+   对于*n*=0，*fib*(*n*)=0

+   对于*n*=1，*fib*(*n*)=1

+   对于*n*>1，*fib*(*n*)=*fib*(*n*-2)+*fib*(*n*-1)

斐波那契的名字实际上来自*filius Bonacci*，或者*Bonacci 的儿子*。他最著名的是引入了我们今天所知的 0-9 数字的使用，而不是繁琐的罗马数字。他将以他命名的序列作为解答引入了一个涉及兔子的谜题！

如果您计算一下，序列从 0 开始，然后是 1，从那一点开始，每个项都是前两个项的和：再次是 1，然后是 2，3，5，8，13，21，依此类推。通过递归编程这个系列很简单--尽管我们将在第九章中重新讨论这个例子，*设计函数 - 递归*。下面的代码，是对定义的直接翻译，将会这样做：

```js
const fib = (n) => {
 if (n == 0) {
 return 0;
 } else if (n == 1) {
 return 1;
 } else {
 return fib(n - 2) + fib(n - 1);
 }
}
//
console.log(fib(10)); // *55, a bit slowly*
```

如果您真的喜欢一行代码，您也可以写成`const fib = (n) => (n<=1) ? n : fib(n-2)+fib(n-1)`--您明白为什么吗？但更重要的是...值得失去清晰度吗？

如果您尝试使用这个函数来增加`n`的值，很快就会意识到存在问题，计算开始花费太多时间。例如，在我的机器上，这是我测得的一些时间，以毫秒为单位--当然，您的情况可能有所不同。由于函数速度相当快，我不得不运行 100 次计算，对`n`的值在 0 到 40 之间。即使如此，对于较小的`n`值，时间确实非常短暂；只有从 25 开始，我得到了有趣的数字。图表（见图 4.1）显示了指数增长，这预示着不祥的事情。

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/e2ac008e-f09e-49d5-9d43-78a74620c31c.png)图 4.1：fib()递归函数的计算时间呈指数增长。

如果我们绘制出计算`fib(6)`所需的所有调用的图表，你会注意到问题。每个节点代表计算`fib(n)`的调用：我们只在节点中记录`n`的值。除了`n`=0 或 1 的调用外，每个调用都需要进一步的调用；参见图 4.2：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/ccd25b95-8da3-4bc6-8d25-3eb16a5e4029.png)图 4.2：计算 fib(6)所需的所有计算显示出大量重复

延迟增加的原因变得很明显：例如，`fib(2)`的计算在四个不同的场合重复进行，而`fib(3)`本身被计算了三次。鉴于我们的函数是纯函数，我们可以存储计算出的值，避免一遍又一遍地进行数字计算。可能的版本如下：

```js
let cache = [];
const fib2 = (n) => {
 if (cache[n] == undefined) {
 if (n == 0) {
 cache[0] = 0;
 } else if (n == 1) {
 cache[1] = 1;
 } else {
 cache[n] = fib2(n - 2) + fib2(n - 1);
 }
 }
    return cache[n];
}

console.log(fib2(10)); // *55, as before, but more quickly!*
```

最初，缓存是空的。每当我们需要计算`fib2(n)`的值时，我们都会检查它是否已经计算过。如果不是，我们进行计算，但有一个小变化：我们不会立即返回值，而是先将其存储在缓存中，然后再返回。这意味着不会重复进行计算：在我们为特定的`n`计算了`fib2(n)`之后，未来的调用将不会重复这个过程，而只是返回之前已经计算过的值。

一些简短的注释：

+   我们手动进行了函数的记忆化，但我们可以使用高阶函数来实现，我们将在第六章中看到，*生成函数 - 高阶函数*。完全可以对函数进行记忆化，而无需改写它。

+   使用全局变量作为缓存不是一个很好的做法；我们可以使用 IIFE 和闭包来隐藏缓存；你看到了吗？在第三章的*立即调用*部分中查看`myCounter()`示例，回顾我们如何做到这一点。

当然，你不需要为程序中的每个纯函数都这样做。你只会对频繁调用、需要花费重要时间的函数进行这种优化 - 如果情况不是这样的话，额外的缓存管理时间将会比你期望节省的时间更多！

# 自我文档化

纯函数还有另一个优势。由于函数需要处理的一切都通过其参数给出，没有任何隐藏的依赖关系，所以当你阅读其源代码时，你已经拥有了理解函数目标所需的一切。

额外的优势：知道一个函数不会访问除了其参数之外的任何东西，会让你更有信心使用它，因为你不会意外地产生一些副作用，函数将会完成的唯一事情，就是你已经通过文档学到的。

单元测试（我们将在下一节中介绍）也可以作为文档，因为它们提供了在给定特定参数时函数返回的示例。大多数程序员都会同意，最好的文档是充满示例的，每个单元测试都可以被视为这样一个示例。

# 测试

纯函数的另一个优势 - 也是最重要的之一 - 与单元测试有关。纯函数只负责以其输入产生输出。因此，当你为纯函数编写测试时，你的工作会简化得多，因为不需要考虑上下文，也不需要模拟状态。

你可以简单地专注于提供输入和检查输出，因为所有函数调用都可以在与*世界其他部分*独立的情况下重现。我们将在本章后面更多地了解测试纯函数和不纯函数。

# 不纯函数

如果你决定完全放弃所有种类的副作用，你的程序只能使用硬编码的输入...并且无法显示计算结果！同样，大多数网页将变得无用；你将无法进行任何网络服务调用，或者更新 DOM；你只能有静态页面。对于服务器端的 JS，你的 Node.JS 代码将变得非常无用，无法进行任何 I/O...

在 FP 中减少副作用是一个很好的目标，但我们不能过分追求！所以，让我们想想如何避免使用不纯的函数，如果可能的话，以及如何处理它们，寻找最好的方法来限制或限制它们的范围。

# 避免不纯的函数

在本章的前面，我们看到了不纯函数更常见的原因。现在让我们考虑如何最小化它们的数量，如果完全摆脱它们并不现实的话。

# 避免使用状态

关于使用全局状态--获取和设置--解决方案是众所周知的。关键在于：

+   将全局状态所需的内容作为参数提供给函数

+   如果函数需要更新状态，它不应该直接这样做，而是应该产生状态的新版本，并返回它

+   如果有的话，将由调用者负责获取返回的状态并更新全局状态

这是 Redux 用于其 reducer 的技术。reducer 的签名是`(previousState, action) => newState`，意味着它以状态和动作作为参数，并返回一个新的状态作为结果。更具体地说，reducer 不应该简单地改变`previousState`参数，它必须保持不变（我们将在第十章中看到更多关于这一点的内容，*确保纯度-不可变性*）。

关于我们第一个版本的`isOldEnough()`函数，它使用了一个全局的`limitYear`变量，改变很简单：我们只需要将`limitYear`作为函数的参数提供。有了这个改变，函数就会变得纯净，因为它只会使用它的参数来产生结果。更好的是，我们应该提供当前年份，让函数来计算，而不是强制调用者这样做：

```js
const isOldEnough3 = (currentYear, birthYear) => birthYear <= currentYear-18;
```

显然，我们将不得不改变所有调用以提供所需的`limitYear`参数（我们也可以使用柯里化，正如我们将在第七章中看到的，*转换函数-柯里化和部分应用*）。初始化`limitYear`的值的责任仍然在函数之外，但我们已经成功避免了一个缺陷。

我们也可以将这个解决方案应用到我们特殊的`roundFix()`函数中。你还记得，这个函数通过累积由四舍五入引起的差异来工作，并根据累加器的符号决定是向上还是向下舍入。我们无法避免使用这个状态，但我们可以将四舍五入部分与累积部分分开。因此，我们的原始代码（减去注释和日志）将从以下内容更改：

```js
const roundFix1 = (function() {
 let accum = 0;
 return n => {
 let nRounded = accum > 0 ? Math.ceil(n) : Math.floor(n);
 accum += n - nRounded;
 return nRounded;
 };
})();
```

至于：

```js
const roundFix2 = (a, n) => {
 let r = a > 0 ? Math.ceil(n) : Math.floor(n);
 a += n - r;
 return {a, r};
};
```

你会如何使用这个函数？初始化累加器，将其传递给函数，并在之后更新，现在都是调用者代码的责任。你会有类似以下的东西：

```js
let accum = 0;

// *...some other code...*

let {a, r} = roundFix2(accum, 3.1415);
accum = a;
console.log(accum, r); // 0.1415 3
```

请注意：

+   `accum`现在是应用程序的全局状态的一部分

+   由于`roundFix2()`需要它，当前的累加器值在每次调用时都会被提供

+   调用者负责更新全局状态，而不是`roundFix2()`

请注意使用解构赋值，以便允许函数返回多个值，并且可以轻松地将每个值存储在不同的变量中。更多信息，请查看[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Operators/Destructuring_assignment`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Operators/Destructuring_assignment)。

这个新的`roundFix2()`函数是完全纯粹的，可以很容易地进行测试。如果你想要隐藏累加器不被应用程序的其他部分访问，你仍然可以像其他示例中一样使用闭包，但这将再次在你的代码中引入不纯性；你决定！

# 注入不纯的函数

如果一个函数变得不纯，因为它需要调用一些其他函数，而这些函数本身是不纯的，解决这个问题的方法是在调用中注入所需的函数。这种技术实际上为您的代码提供了更多的灵活性，并允许更容易地进行未来更改，以及更简单的单元测试。

让我们考虑一下我们之前看到的随机文件名生成器函数。问题的关键在于它使用`getRandomLetter()`来生成文件名：

```js
const getRandomFileName = (fileExtension = "") => {
 ...
 for (let i = 0; i < NAME_LENGTH; i++) {
 namePart[i] = getRandomLetter();
 }
 ...
};
```

解决这个问题的方法是用一个注入的外部函数替换不纯的函数：

```js
const getRandomFileName2 = (fileExtension = "", randomLetterFunc) => {
 const NAME_LENGTH = 12;
 let namePart = new Array(NAME_LENGTH);
 for (let i = 0; i < NAME_LENGTH; i++) {
 namePart[i] = randomLetterFunc();
 }
 return namePart.join("") + fileExtension;
};
```

现在，我们已经从这个函数中移除了固有的不纯性。如果我们愿意提供一个预定义的伪随机函数，实际上返回固定、已知的值，我们将能够轻松地对这个函数进行单元测试；我们将在接下来的示例中看到。函数的使用将会改变，我们需要编写：

```js
let fn = getRandomFileName2(".pdf", getRandomLetter);
```

如果这种方式让你困扰，你可能想为`randomLetterFunc`参数提供一个默认值，如下所示：

```js
const getRandomFileName2 = (
 fileExtension = "",
 randomLetterFunc = getRandomLetter
) => {
 ...
};
```

或者你也可以通过部分应用来解决这个问题，就像我们将在第七章中看到的那样，*转换函数 - 柯里化和部分应用*。

这实际上并没有避免使用不纯的函数。在正常使用中，你将调用`getRandomFileName()`并提供我们编写的随机字母生成器，因此它将表现为一个不纯的函数。然而，为了测试目的，如果你提供一个返回预定义（即非随机）字母的函数，你将能够更轻松地测试它是否纯粹。

但是原始问题函数`getRandomLetter()`呢？我们可以应用相同的技巧，编写一个新版本，如下所示：

```js
const getRandomLetter = (getRandomInt = Math.random) => {
 const min = "A".charCodeAt();
 const max = "Z".charCodeAt();
 return String.fromCharCode(
 Math.floor(getRandomInt() * (1 + max - min)) + min
 );
};
```

在正常使用中，`getRandomFileName()`会调用`getRandomLetter()`而不提供任何参数，这意味着被调用的函数将按照预期的随机方式行事。但是，如果我们想要测试函数是否符合我们的预期，我们可以运行它，使用一个返回我们决定的任何内容的注入函数，让我们彻底测试它。

这个想法实际上非常重要，对其他问题有广泛的应用。例如，我们可以提供一个函数来直接访问 DOM，而不是直接访问 DOM。对于测试目的，可以简单地验证被测试的函数是否真的做了它需要做的事情，而不是真的与 DOM 进行交互（当然，我们必须找到其他方法来测试那些与 DOM 相关的函数）。这也适用于需要更新 DOM、生成新元素和进行各种操作的函数，你只需使用一些中间函数。

# 你的函数是纯的吗？

让我们通过考虑一个重要的问题来结束这一节：你能确保一个函数实际上是纯的吗？为了展示这个任务的困难，我们将回到我们在前几章中看到的简单的`sum3()`函数。你会说这个函数是纯的吗？它看起来是！

```js
const sum3 = (x, y, z) => x + y + z;
```

让我们看看，这个函数除了它的参数之外没有访问任何东西，甚至不尝试修改它们（即使它可能...或者可能吗？），不进行任何 I/O 或使用我们之前提到的任何不纯的函数或方法...会出什么问题呢？

答案与检查你的假设有关。例如，谁说这个函数的参数应该是数字？你可能会对自己说“好吧，它们可以是字符串...但是函数仍然是纯的，不是吗？”，但是对于这个（肯定是邪恶的！）答案，看看下面的代码。

```js
let x = {};
x.valueOf = Math.random;

let y = 1;
let z = 2;

console.log(sum3(x, y, z)); // 3.2034400919849431
console.log(sum3(x, y, z)); // 3.8537045249277906
console.log(sum3(x, y, z)); // 3.0833258308458734
```

观察我们如何将一个新函数分配给`x.valueOf`方法，我们充分利用了函数是一级对象的事实。在第三章的*一个不必要的错误*部分中，可以了解更多相关信息。

嗯，`sum3()`应该是纯的...但它实际上取决于你传递给它的参数！你可能会安慰自己，认为肯定没有人会传递这样的参数，但边缘情况通常是错误的根源。但你不必放弃纯函数的想法。添加一些类型检查（TypeScript 可能会派上用场），你至少可以防止一些情况--尽管 JS 永远不会让你完全确定你的代码*总是*是纯的！

# 测试-纯函数与不纯函数

我们已经看到纯函数在概念上比不纯函数更好，但我们不能开始一场消灭代码中所有不纯性的运动。首先，没有人能否认副作用是有用的，或者至少是不可避免的：你需要与 DOM 交互或调用 Web 服务，而没有办法以纯粹的方式做到这一点。因此，与其抱怨你必须允许不纯性，不如尝试构建你的代码，以便隔离不纯函数，并让你的代码尽可能地好。

有了这个想法，你将能够为各种函数编写单元测试，无论是纯函数还是不纯函数。编写纯函数和不纯函数的单元测试是不同的，因为在处理纯函数或不纯函数时，其难度和复杂性也不同。对于前者编写测试通常相当简单，并遵循基本模式，而对于后者通常需要搭建和复杂的设置。因此，让我们通过看看如何测试这两种类型的函数来结束本章。

# 测试纯函数

鉴于我们已经描述的纯函数的特性，你的大部分单元测试可能会很简单：

+   使用给定的一组参数调用函数

+   验证结果是否与预期相匹配

让我们从一些简单的例子开始。测试`isOldEnough()`函数将比需要访问全局变量的版本更复杂。另一方面，最后一个版本`isOldEnough3()`不需要任何东西，因为它接收了两个参数，所以测试起来很简单：

```js
describe("isOldEnough", function() {
 it("is false for people younger than 18", () => {
 expect(isOldEnough3(1978, 1963)).toBe(false);
 });

 it("is true for people older than 18", () => {
 expect(isOldEnough3(1988, 1965)).toBe(true);
 });

 it("is true for people exactly 18", () => {
 expect(isOldEnough3(1998, 1980)).toBe(true);
 });
});
```

我们编写的另一个纯函数同样简单，但需要注意精度。如果我们测试`circleArea`函数，我们必须使用 Jasmine 的`.toBeCloseTo()`匹配器，它允许在处理浮点数时进行近似相等。除此之外，测试基本相同：使用已知参数调用函数，并检查预期结果。

```js
describe("circle area", function() {
 it("is zero for radius 0", () => {
 let area = circleArea(0);
 expect(area).toBe(0);
 });

 it("is PI for radius 1", () => {
 let area = circleArea(1);
 expect(area).toBeCloseTo(Math.PI);
 });

 it("is approximately 12.5664 for radius 2", () => {
 let area = circleArea(2);
 expect(area).toBeCloseTo(12.5664);
 });
});
```

毫无困难！测试运行报告对两个套件都成功（见图 4.3）：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/aa0a1952-14ab-403c-a802-19ad03979492.png)图 4.3：一对简单纯函数的成功测试运行

因此，我们不必担心纯函数，让我们继续处理不纯函数，将它们转换为纯函数的等价物。

# 测试纯化函数

当我们考虑`roundFix`特殊函数时，它需要使用状态来累积由于舍入而产生的差异，我们通过将当前状态作为附加参数提供，并使函数返回两个值：舍入后的值和更新后的状态，从而生成了一个新版本：

```js
const roundFix2 = (a, n) => {
 let r = a > 0 ? Math.ceil(n) : Math.floor(n);
 a += n - r;
 return {a, r};
};
```

这个函数现在是纯的，但测试它需要验证不仅返回的值，还有更新的状态。我们可以基于之前的实验来进行测试。再次，我们必须使用`toBeCloseTo()`来处理浮点数，但对于整数，我们可以使用`toBe()`，它不会产生舍入误差：

```js
describe("roundFix2", function() {
 it("should round 3.14159 to 3 if differences are 0", () => {
 let {a, r} = roundFix2(0.0, 3.14159);
 expect(a).toBeCloseTo(0.14159);
 expect(r).toBe(3);
 });

 it("should round 2.71828 to 3 if differences are 0.14159", () => {
 let {a, r} = roundFix2(0.14159, 2.71828);
 expect(a).toBeCloseTo(-0.14013);
 expect(r).toBe(3);
 });

 it("should round 2.71828 to 2 if differences are -0.14013", () => {
 let {a, r} = roundFix2(-0.14013, 2.71828);
 expect(a).toBeCloseTo(0.57815);
 expect(r).toBe(2);
 });

 it("should round 3.14159 to 4 if differences are 0.57815", () => {
 let {a, r} = roundFix2(0.57815, 3.14159);
 expect(a).toBeCloseTo(-0.28026);
 expect(r).toBe(4);
 });
});
```

我们注意到包括了几种情况，积累的差异为正、零或负，并检查在每种情况下是否四舍五入。我们当然可以进一步进行，对负数进行四舍五入，但思路很清楚：如果你的函数将当前状态作为参数，并更新它，与纯函数测试的唯一区别是你还必须测试返回的状态是否符合你的期望。

现在让我们考虑测试的另一种方式，对于我们纯净的`getRandomLetter()`变体；让我们称之为`getRandomLetter2()`。这很简单；你只需要提供一个函数，它本身会产生*随机*数字。（在测试术语中，这种函数被称为*存根*）。存根的复杂性没有限制，但你会希望保持它简单。

然后，我们可以根据对函数工作原理的了解进行一些测试，以验证低值产生`A`，接近 1 的值产生`Z`，因此我们可以有一点信心，不会产生额外的值。此外，中间值（大约 0.5）应该产生字母在字母表中间的位置。然而，请记住，这种测试并不是很好；如果我们替换了一个同样有效的`getRandomLetter()`变体，新函数可能完全正常工作，但由于不同的内部实现，可能无法通过这个测试！

```js
describe("getRandomLetter2", function() {
 it("returns A for values close to 0", () => {
 let letterSmall = getRandomLetter2(() => 0.0001);
 expect(letterSmall).toBe("A");
 });

 it("returns Z for values close to 1", () => {
 let letterBig = getRandomLetter2(() => 0.99999);
 expect(letterBig).toBe("Z");
 });

 it("returns a middle letter for values around 0.5", () => {
 let letterMiddle = getRandomLetter2(() => 0.49384712);
 expect(letterMiddle).toBeGreaterThan("G");
 expect(letterMiddle).toBeLessThan("S");
 });

 it("returns an ascending sequence of letters for ascending values", () => {
 let a = [0.09, 0.22, 0.6];
 const f = () => a.shift(); // impure!!

 let letter1 = getRandomLetter2(f);
 let letter2 = getRandomLetter2(f);
 let letter3 = getRandomLetter2(f);
 expect(letter1).toBeLessThan(letter2);
 expect(letter2).toBeLessThan(letter3);
 });
});
```

测试我们的文件名生成器可以通过使用存根来以类似的方式进行。我们可以提供一个简单的存根，按顺序返回`"SORTOFRANDOM"`的字母（这个函数是相当不纯的；知道为什么吗？）。因此，我们可以验证返回的文件名是否与预期的名称匹配，以及返回的文件名的一些其他属性，例如其长度和扩展名：

```js
describe("getRandomFileName", function() {
 let a = [];
 let f = () => a.shift();

 beforeEach(() => {
 a = "SORTOFRANDOM".split("");
 });

 it("uses the given letters for the file name", () => {
 let fileName = getRandomFileName("", f);
 expect(fileName.startsWith("SORTOFRANDOM")).toBe(true);
 });

 it("includes the right extension, and has the right length", () => {
 let fileName = getRandomFileName(".pdf", f);
 expect(fileName.endsWith(".pdf")).toBe(true);
 expect(fileName.length).toBe(16);
 });
});
```

测试*纯化*的不纯函数与测试最初纯函数非常相似。现在，我们将不得不考虑一些真正不纯函数的情况，因为正如我们所说的，几乎可以肯定，你迟早会使用这样的函数。

# 测试不纯函数

首先，让我们回到我们的`getRandomLetter()`函数。有了对其实现的内部知识（这被称为*白盒测试*，与*黑盒测试*相对，后者我们对函数代码本身一无所知），我们可以*监视*（Jasmine 术语）`Math.random()`方法，并设置一个*模拟*函数，它将返回我们想要的任何值。

我们可以重新审视我们在上一节中进行的一些测试用例。在第一个案例中，我们将`Math.random()`设置为返回 0.0001，并测试它是否实际被调用，以及最终返回是否为`A`。在第二个案例中，为了多样化，我们设置了`Math.random()`可以被调用两次，返回两个不同的值。我们还验证了函数被调用了两次，而且两个结果都是`Z`。第三个案例展示了检查`Math.random()`（或者说，我们的模拟函数）被调用了多少次的另一种方式：

```js
describe("getRandomLetter", function() {
 it("returns A for values close to 0", () => {
 spyOn(Math, "random").and.returnValue(0.0001);
 let letterSmall = getRandomLetter();
 expect(Math.random).toHaveBeenCalled();
 expect(letterSmall).toBe("A");
 });

 it("returns Z for values close to 1", () => {
 spyOn(Math, "random").and.returnValues(0.98, 0.999);
 let letterBig1 = getRandomLetter();
 let letterBig2 = getRandomLetter();
 expect(Math.random).toHaveBeenCalledTimes(2);
 expect(letterBig1).toBe("Z");
 expect(letterBig2).toBe("Z");
 });

 it("returns a middle letter for values around 0.5", () => {
 spyOn(Math, "random").and.returnValue(0.49384712);
 let letterMiddle = getRandomLetter();
 expect(Math.random.calls.count()).toEqual(1);
 expect(letterMiddle).toBeGreaterThan("G");
 expect(letterMiddle).toBeLessThan("S");
 });
});
```

当然，你不会随意发明任何测试。据说，你会从所需的`getRandomLetter()`函数的描述开始工作，这个描述是在你开始编码或测试之前编写的。在我们的情况下，我假装那个规范确实存在，并且明确指出，例如，接近 0 的值应该产生`A`，接近 1 的值应该返回`Z`，并且函数应该对升序的`random`值返回升序的字母。

现在，你如何测试原始的`getRandomFileName()`函数，即调用不纯的`getRandomLetter()`函数的函数？这是一个更加复杂的问题....你有什么期望？你无法知道它将会给出什么结果，因此你无法编写任何`.toBe()`类型的测试。你可以测试一些预期结果的属性。而且，如果你的函数涉及某种形式的随机性，你可以重复测试多次，以增加捕获错误的机会：

```js
describe("getRandomFileName, with an impure getRandomLetter function", function() {
 it("generates 12 letter long names", () => {
 for (let i = 0; i < 100; i++) {
 expect(getRandomFileName().length).toBe(12);
 }
 });

 it("generates names with letters A to Z, only", () => {
 for (let i = 0; i < 100; i++) {
 let n = getRandomFileName();
 for (j = 0; j < n.length; n++) {
 expect(n[j] >= "A" && n[j] <= "Z").toBe(true);
 }
 }
 });

 it("includes the right extension if provided", () => {
 let fileName1 = getRandomFileName(".pdf");
 expect(fileName1.length).toBe(16);
 expect(fileName1.endsWith(".pdf")).toBe(true);
 });

 it("doesn't include any extension if not provided", () => {
 let fileName2 = getRandomFileName();
 expect(fileName2.length).toBe(12);
 expect(fileName2.includes(".")).toBe(false);
 });
});
```

我们没有向`getFileName()`传递任何随机字母生成函数，因此它将使用原始的、不纯的函数。我们对一些测试运行了一百次，作为额外的保险。

在测试代码时，永远记住*没有证据*不是*证据的缺失*。即使我们的重复测试成功了，也不能保证，使用其他随机输入时，它们不会产生意外的、迄今未被发现的错误。

让我们进行另一个*属性*测试。假设我们想测试一个洗牌算法；我们可以决定实现 Fisher-Yates 版本，按照以下的方式。按照实现，该算法是双重不纯的：它不总是产生相同的结果（显然！）并且修改了它的输入参数：

```js
const shuffle = arr => {
 const len = arr.length;
 for (let i = 0; i < len - 1; i++) {
 let r = Math.floor(Math.random() * (len - i));
 [arr[i], arr[i + r]] = [arr[i + r], arr[i]];
 }
 return arr;
};

var xxx = [11, 22, 33, 44, 55, 66, 77, 88];
console.log(shuffle(xxx));
// ***[55, 77, 88, 44, 33, 11, 66, 22]***
```

有关此算法的更多信息--包括对不慎的程序员造成的一些问题--请参阅[`en.wikipedia.org/wiki/Fisher-Yates_shuffle`](https://en.wikipedia.org/wiki/Fisher-Yates_shuffle)。

你如何测试这个算法？考虑到结果是不可预测的，我们可以检查其输出的属性。我们可以使用已知的数组调用它，然后测试它的一些属性：

```js
describe("shuffleTest", function() {
 it("shouldn't change the array length", () => {
 let a = [22, 9, 60, 12, 4, 56];
 shuffle(a);
 expect(a.length).toBe(6);
 });

 it("shouldn't change the values", () => {
 let a = [22, 9, 60, 12, 4, 56];
 shuffle(a);
 expect(a.includes(22)).toBe(true);
 expect(a.includes(9)).toBe(true);
 expect(a.includes(60)).toBe(true);
 expect(a.includes(12)).toBe(true);
 expect(a.includes(4)).toBe(true);
 expect(a.includes(56)).toBe(true);
 });
});
```

我们不得不以这种方式编写单元测试的第二部分，因为正如我们所看到的，`shuffle()`会修改输入参数。

# 问题

4.1\. **极简主义函数**：函数式程序员有时候倾向于以极简主义的方式编写代码。你能检查这个斐波那契函数的版本，并解释它是否有效，如果有效，是如何有效的吗？

```js
 const fib2 = n => (n < 2 ? n : fib2(n - 2) + fib2(n - 1));
```

4.2\. **一个廉价的方法**：下面这个版本的斐波那契函数非常高效，不会进行任何不必要或重复的计算。你能看出来吗？建议：尝试手工计算`fib4(6)`，并与本书前面给出的例子进行比较：

```js
 const fib4 = (n, a = 0, b = 1) => (n === 0 ? a : fib4(n - 1, b, a 
 + b));
```

4.3 **洗牌测试**：你如何为`shuffle()`编写单元测试，以测试它在具有*重复*值的数组上是否正确工作？

4.4\. **违反规律**：使用`.toBeCloseTo()`非常实用，但可能会引发一些问题。一些基本的数学属性是：

一个数字应该等于它自己：对于任何数字*a*，*a*应该等于*a*

+   如果数字*a*等于数字*b*，那么*b*应该等于*a*

+   如果*a*等于*b*，*b*等于*c*，那么*a*应该等于*c*

+   如果*a*等于*b*，*c*等于*d*，那么*a*+*c*应该等于*b*+*d*

+   如果*a*等于*b*，*c*等于*d*，那么*a***c*应该等于*b***d*

+   如果*a*等于*b*，*c*等于*d*，那么*a*/*c*应该等于*b*/*d*

`.toBeCloseTo()`是否也满足所有这些属性？

# 总结

在本章中，我们介绍了*纯函数*的概念，并研究了它们为什么重要。我们还看到了*副作用*造成的问题，这是不纯函数的原因之一；考虑了一些*净化*这些不纯函数的方法，最后，我们看到了对纯函数和不纯函数进行单元测试的几种方法。

在第五章中，*声明式编程 - 更好的风格*，我们将展示 FP 的其他优势：如何以声明式的方式进行编程，以更高的层次编写更简单、更强大的代码。
