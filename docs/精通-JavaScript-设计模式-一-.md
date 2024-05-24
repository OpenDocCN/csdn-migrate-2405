# 精通 JavaScript 设计模式（一）

> 原文：[`zh.annas-archive.org/md5/C01E768309CC6F31A9A1148399C85D90`](https://zh.annas-archive.org/md5/C01E768309CC6F31A9A1148399C85D90)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

JavaScript 正逐渐成为世界上最流行的语言之一。然而，它作为一种玩具语言的历史意味着开发人员往往忽视良好的设计。设计模式是一个很好的工具，可以提出一些经过验证的解决方案。

# 本书内容

本书分为两个主要部分，每个部分包含多个章节。本书的第一部分，我们将称之为*第一部分*，涵盖了 GoF 书中的经典设计模式。

第一章，*Designing for Fun and Profit*，介绍了设计模式是什么，以及为什么我们有兴趣使用设计模式。我们还将谈谈 JavaScript 的一些历史，以便让您了解历史背景。

第二章，*Organizing Code*，探讨了如何创建用于组织代码的经典结构，如命名空间、模块和类，因为 JavaScript 缺乏这些构造作为一等公民。

第三章，*Creational Patterns*，涵盖了《四人组模式》书中概述的创建模式。我们将讨论这些模式如何适用于 JavaScript，而不是《四人组》书写作时流行的语言。

第四章，*Structural Patterns*，研究了创建模式。我们将检查《四人组模式》书中的结构模式。

第五章，*Behavioral Patterns*，讨论了行为模式。这些是《四人组模式》书中我们将研究的最后一组模式。这些模式控制了将类连接在一起的不同方式。

*第二部分*着眼于 GoF 书中未涵盖或特定于 JavaScript 的模式。

第六章，*Functional Programming*，涵盖了函数式编程语言中的一些模式。我们将看看如何在 JavaScript 中使用这些模式来改进代码。

第七章，*Reactive Programming*，探讨了 JavaScript 中回调模型编程所涉及的问题。它提出了响应式编程，一种基于流的事件方法，作为可能的解决方案。

第八章，*Application Patterns*，研究了创建单页面应用程序的各种模式。我们将提供清晰度，并探讨如何使用使用每种现有模式的库，以及创建我们自己的轻量级框架。

第九章，*Web Patterns*，探讨了一些适用于 Web 应用程序的模式。我们还将研究一些关于将代码部署到远程运行时（如浏览器）的模式。

第十章，*Messaging Patterns*，涵盖了消息传递是一种强大的通信技术，可在应用程序内部甚至之间进行通信。在本章中，我们将研究一些关于消息传递的常见结构，并讨论为什么消息传递如此有用。

第十一章，*Microservices*，涵盖了微服务，这是一种以惊人的速度增长的方法。本章探讨了这种编程方法背后的思想，并建议在使用这种方法构建时要牢记的一些模式。

第十二章，*Patterns for Testing*，讨论了构建软件的困难，以及构建优质软件的双重困难。本章提供了一些模式，可以使测试过程变得更容易一些。

第十三章 , *高级模式* , 解释了一些模式，比如面向方面的编程在 JavaScript 中很少被应用。我们将探讨这些模式如何在 JavaScript 中应用以及是否应该应用它们。

第十四章 , *ECMAScript-2015/2016 今日解决方案* , 涵盖了一些工具，允许您在今天使用未来版本 JavaScript 的功能。我们将研究微软的 TypeScript 以及 Traceur。

# 本书所需内容

本书不需要专门的软件。JavaScript 可以在所有现代浏览器上运行。有用于驱动各种工具的独立 JavaScript 引擎，如 C++（V8）和 Java（Rhino），这些工具包括 Node.js，CouchDB，甚至 Elasticsearch。这些模式可以应用于这些技术中的任何一个。

# 本书适合对象

本书非常适合希望在 JavaScript 中获得面向对象编程专业知识和 ES-2015 新功能以提高网页开发技能并构建专业质量网页应用的开发者。

# 约定

在本书中，您会发现一些区分不同信息种类的文本样式。以下是一些这些样式的示例和它们的含义解释。

文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄会以以下形式显示: "您会注意到我们明确定义了 `name` 字段。"

代码块设置如下:

```js
let Castle = function(name){
 this.name = name;
}
Castle.prototype.build = function(){ console.log(this.name);}
let instance1 = new Castle("Winterfell");
instance1.build();
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示:

```js
let Castle = function(name){
 this.name = name;
}
 **Castle.prototype.build = function(){ console.log(this.name);}** 

let instance1 = new Castle("Winterfell");
instance1.build();
```

任何命令行输入或输出都以以下形式书写:

```js
ls -1| cut -d \. -f 2 -s | sort |uniq
```

**新术语**和**重要词汇**以粗体显示。屏幕上看到的词语，例如菜单或对话框中的词语，会以这样的形式出现在文本中: "要访问它们，有一个菜单项，位于**工具** | **Chrome 中的开发者工具** | **工具** | **Firefox 中的 Web 开发者** 下。"

### 注意

警告或重要提示会以这样的形式出现在一个框中。

### 提示

提示和技巧会出现在这样的形式中。


# 第一章：为了乐趣和利润而设计

JavaScript 是一种不断发展的语言，从诞生以来已经走过了很长的路。可能比其他任何一种编程语言都更随着万维网的发展而成长和变化。本书的主题是探索如何使用良好的设计原则编写 JavaScript。本书的前言包含了对书中各节的详细解释。

在本章的前半部分，我们将探讨 JavaScript 的历史，以及它如何成为今天重要的语言。随着 JavaScript 的发展和重要性的增长，对其构建应用严格方法的需求也在增长。设计模式可以是一个非常有用的工具，帮助开发可维护的代码。本章的后半部分将专门讨论设计模式的理论。最后，我们将简要地看一下反模式。

本章的主题如下：

+   JavaScript 的历史

+   什么是设计模式？

+   反模式

# 通往 JavaScript 的道路

我们永远不会知道语言最初是如何产生的。它是从一系列在梳理仪式中发出的咕哝声和喉音慢慢演变而来的吗？也许它是为了让母亲和她们的后代进行交流而发展起来的。这两种理论都是不可能证明的。在那个重要的时期，没有人在场观察我们的祖先。事实上，缺乏经验证据导致巴黎语言学会禁止进一步讨论这个话题，认为它不适合进行严肃的研究。

## 早期

幸运的是，编程语言在最近的历史中得到了发展，我们能够看到它们的成长和变化。JavaScript 是现代编程语言中历史最有趣的之一。在 1995 年 5 月的 10 天里，网景的一名程序员写下了现代 JavaScript 的基础。

当时，网景正参与与微软的浏览器战争。网景的愿景远不止于开发一个浏览器。他们想要创建一个完整的分布式操作系统，利用 Sun Microsystems 最近发布的 Java 编程语言。Java 是 C++的更现代的替代品。然而，网景没有对 Visual Basic 有所回应。Visual Basic 是一种更容易使用的编程语言，面向经验较少的开发人员。它避开了 C 和 C++编程中的一些困难，如内存管理。Visual Basic 也避免了严格的类型检查，总体上更加灵活。下面是 JavaScript 的时间线图：

![早期](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00001.jpg)

Brendan Eich 被委托开发网景的回应 VB。该项目最初被命名为 Mocha，但在网景 2.0 测试版发布之前被更名为 LiveScript。到全面发布时，Mocha/LiveScript 已更名为 JavaScript，以便与 Java 小程序集成。Java 小程序是在浏览器中运行的小型应用程序。它们与浏览器本身有不同的安全模型，因此在与浏览器和本地系统的交互方面受到限制。如今很少见到小程序，因为它们的许多功能已经成为浏览器的一部分。当时 Java 正处于流行的浪潮中，与之有关的任何关系都被夸大了。

多年来，这个名称引起了很多混淆。JavaScript 是一种与 Java 非常不同的语言。JavaScript 是一种解释性语言，具有松散的类型，主要在浏览器上运行。Java 是一种编译成字节码的语言，然后在 Java 虚拟机上执行。它在许多场景中都有适用性，从浏览器（通过 Java 小程序的使用）到服务器（Tomcat，JBoss 等），到完整的桌面应用程序（Eclipse，OpenOffice 等）。在大多数外行人的想法中，混淆仍然存在。

JavaScript 原来真的非常有用，可以与 Web 浏览器进行交互。很快，微软也将 JavaScript 引入其 Internet Explorer 中，以补充 VBScript。微软的实现被称为 JScript。

到 1996 年末，很明显 JavaScript 将成为不久的将来的获胜网络语言。为了限制实现之间的语言偏差，Sun 和 Netscape 开始与**欧洲计算机制造商协会**（**ECMA**）合作，制定了未来版本的 JavaScript 需要遵守的标准。标准很快发布（从标准组织的运作速度来看，非常快），于 1997 年 7 月发布。如果你还没有看到 JavaScript 的足够多的名称，标准版本被称为**ECMAScript**，这个名称在一些圈子里仍然存在。

不幸的是，标准只规定了 JavaScript 的核心部分。在浏览器战争激烈的同时，很明显，任何坚持只使用 JavaScript 基本实现的供应商都会很快被抛在后面。与此同时，还在进行大量工作，以建立浏览器的标准**文档对象模型**（**DOM**）。DOM 实际上是一个可以使用 JavaScript 进行操作的网页 API。

多年来，每个 JavaScript 脚本都会尝试确定其运行的浏览器。这将决定如何处理 DOM 中的元素，因为每个浏览器之间存在显著的差异。执行简单操作所需的代码混乱程度是传奇的。我记得曾经阅读过一篇为期一年的 20 篇系列文章，介绍如何开发一个在 Internet Explorer 和 Netscape Navigator 上都能工作的**Dynamic HTML**（**DHTML**）下拉菜单。现在，可以通过纯 CSS 实现相同的功能，甚至无需使用 JavaScript。

### 注意

DHTML 在 20 世纪 90 年代末和 21 世纪初是一个流行的术语。它实际上指的是在客户端执行某种动态内容的任何网页。随着 JavaScript 的流行，几乎每个页面都变得动态化，这个术语已经不再使用。

幸运的是，JavaScript 标准化的努力在幕后继续进行。ECMAScript 的第 2 版和第 3 版分别在 1998 年和 1999 年发布。看起来各方对 JavaScript 感兴趣的各方可能终于达成了一些共识。2000 年初开始了 ECMAScript 4 的工作，这将是一个重大的新版本。

## 暂停

然后，灾难来临了。ECMAScript 工作中涉及的各个团体对 JavaScript 的发展方向存在重大分歧。微软似乎对标准化工作失去了兴趣。这在一定程度上是可以理解的，因为那个时候 Netscape 自毁了，Internet Explorer 成为了事实上的标准。微软实现了 ECMAScript 4 的部分内容，但并非全部。其他人实现了更全面的支持，但由于市场领导者不支持，开发人员也不愿意使用它们。

多年过去了，没有达成共识，也没有新的 ECMAScript 发布。然而，正如经常发生的那样，互联网的发展无法被主要参与者之间的意见分歧所阻止。诸如 jQuery，Prototype，Dojo 和 Mootools 等库弥合了浏览器之间的主要差异，使跨浏览器开发变得更加容易。与此同时，应用程序中使用的 JavaScript 数量大幅增加。

## GMail 的方式

转折点也许是 2004 年 Google 发布 GMail 应用程序。尽管**异步 JavaScript 和 XML**（**AJAX**）背后的技术在 GMail 发布时已经存在了大约五年，但它并没有被广泛使用。当 GMail 发布时，我完全被它的流畅度所震撼。我们已经习惯了避免完整重新加载的应用程序，但在当时，这是一场革命。为了使这样的应用程序工作，需要大量的 JavaScript。

### 注

AJAX 是一种通过客户端从服务器检索小数据块而不是刷新整个页面的方法。这种技术允许更具交互性的页面，避免了完整页面重新加载的冲击。

GMail 的流行是一个正在酝酿已久的变革的触发器。不断增加的 JavaScript 接受度和标准化推动我们超越了 JavaScript 作为一种合适语言的临界点。直到那时，JavaScript 的使用大多用于对页面进行微小更改和验证表单输入。我和人们开玩笑说，在 JavaScript 的早期，唯一使用的函数名称是`Validate()`。

诸如 GMail 这样对 AJAX 有很大依赖并且避免完整页面重新加载的应用程序被称为**单页面应用**或**SPA**。通过最小化页面内容的更改，用户可以获得更流畅的体验。通过仅传输**JavaScript 对象表示**（**JSON**）负载而不是 HTML，还可以最小化所需的带宽。这使得应用程序看起来更加敏捷。近年来，关于简化 SPA 创建的框架取得了巨大进步。AngularJS，backbone.js 和 ember 都是模型视图控制器风格的框架。它们在过去两三年里获得了极大的流行，并提供了一些有趣的模式使用。这些框架是多年来一些非常聪明的人对 JavaScript 最佳实践进行实验的演变。

### 注

JSON 是 JavaScript 的一种人类可读的序列化格式。近年来它变得非常流行，因为它比以前流行的 XML 格式更容易和不那么繁琐。它缺少 XML 的许多伴随技术和严格的语法规则，但在简单性方面弥补了这一点。

与使用 JavaScript 的框架同时，语言本身也在不断发展。2015 年发布了一个备受瞩目的 JavaScript 新版本，这个版本已经在开发了一些年头。最初被称为 ECMAScript 6，最终的名称变成了 ECMAScript-2015。它带来了一些对生态系统的重大改进。浏览器供应商们正在争相采用这一标准。由于向代码库添加新的语言特性的复杂性，再加上并非所有人都在浏览器的前沿，一些其他编译成 JavaScript 的语言正在变得流行。CoffeeScript 是一种类似 Python 的语言，旨在提高 JavaScript 的可读性和简洁性。由 Google 开发的 Dart 被谷歌推广为 JavaScript 的最终替代品。它的构造解决了传统 JavaScript 中不可能的一些优化。在 Dart 运行时足够流行之前，谷歌提供了一个 Dart 到 JavaScript 的转换器。TypeScript 是微软的一个项目，它向 JavaScript 添加了一些 ECMAScript-2015 甚至一些 ECMAScript-201X 的语法，以及一个有趣的类型系统。它旨在解决大型 JavaScript 项目所面临的一些问题。

讨论 JavaScript 历史的目的有两个：首先，重要的是要记住语言不是在真空中发展的。人类语言和计算机编程语言都会根据使用环境而发生变异。人们普遍认为因纽特人有很多词来描述“雪”，因为在他们的环境中雪是如此普遍。这可能是真的，也可能不是，这取决于你对这个词的定义，以及谁构成了因纽特人。然而，在狭窄领域中，有很多例子表明特定领域的词汇会不断演变以满足精确定义的要求。我们只需看一下专业烹饪店，就会看到许多我们这样的外行人会称之为平底锅的各种变体。

萨皮尔-沃夫假说是语言学领域内的一种假设，它认为语言不仅受到使用环境的影响，而且语言也会影响其环境。也被称为语言相对论，该理论认为一个人的认知过程会因语言的构造方式而有所不同。认知心理学家基思·陈提出了一个引人入胜的例子。在一次观看量极高的 TED 演讲中，陈博士提出了一种有力的正相关关系，即缺乏未来时态的语言与高储蓄率之间存在着强烈的正相关关系（[`www.ted.com/talks/keith_chen_could_your_language_affect_your_ability_to_save_money/transcript`](https://www.ted.com/talks/keith_chen_could_your_language_affect_your_ability_to_save_money/transcript)）。陈博士得出的假设是，当你的语言没有很强的将现在和未来联系起来的意识时，这会导致更加鲁莽的行为。

因此，了解 JavaScript 的历史将使人更好地理解何时何地使用 JavaScript。

我探索 JavaScript 历史的第二个原因是，看到如此受欢迎的工具如何迅速地发展是非常迷人的。在撰写本文时，距离 JavaScript 首次构建已经大约 20 年了，它的流行程度增长迅猛。还有什么比在一个不断发展的语言中工作更令人兴奋的呢？

## JavaScript 无处不在

自 GMail 革命以来，JavaScript 已经大幅增长。重新燃起的浏览器战争，将 Internet Explorer 和 Edge 对抗 Chrome 和 Firefox，导致了构建许多非常快速的 JavaScript 解释器。全新的优化技术已经部署，不足以看到 JavaScript 编译为机器本地代码以获得额外的性能。然而，随着 JavaScript 的速度增加，使用它构建的应用程序的复杂性也在增加。

JavaScript 不再仅仅是用于操作浏览器的语言。流行的 Chrome 浏览器背后的 JavaScript 引擎已经被提取出来，现在是许多有趣项目的核心，比如 Node.js。Node.js 最初是一种高度异步的编写服务器端应用程序的方法。它已经大大发展，并有一个非常活跃的社区支持。使用 Node.js 运行时已经构建了各种各样的应用程序。从构建工具到编辑器都是基于 Node.js 构建的。最近，微软 Edge 的 JavaScript 引擎 ChakraCore 也开源，并可以嵌入 Node.js 作为 Google 的 V8 的替代品。Firefox 的等效物 SpiderMonkey 也是开源的，并正在进入更多的工具中。

JavaScript 甚至可以用来控制微控制器。Johnny-Five 框架是非常流行的 Arduino 的编程框架。它为编程这些设备带来了比传统的低级语言更简单的方法。使用 JavaScript 和 Arduino 打开了一系列可能性，从构建机器人到与现实世界的传感器进行交互。

所有主要的智能手机平台（iOS、Android 和 Windows Phone）都有使用 JavaScript 构建应用程序的选项。平板电脑领域也大同小异，支持使用 JavaScript 进行编程。甚至最新版本的 Windows 提供了使用 JavaScript 构建应用程序的机制。这个插图展示了 JavaScript 可能的一些事情：

![JavaScript 无处不在](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00002.jpg)

JavaScript 正在成为世界上最重要的语言之一。尽管语言使用统计数据 notoriously difficult to calculate，但每一个试图开发排名的来源都将 JavaScript 列在前十名中：

| 语言指数 | JavaScript 的排名 |
| --- | --- |
| Langpop.com | 4 |
| Statisticbrain.com | 4 |
| Codeval.com | 6 |
| TIOBE | 8 |

更有趣的是，大多数这些排名表明 JavaScript 的使用正在上升。

长话短说，JavaScript 将在未来几年成为一种重要的语言。越来越多的应用程序是用 JavaScript 编写的，它是任何类型的 Web 开发的通用语言。流行的 Stack Overflow 网站的开发者 Jeff Atwood 创建了 Atwood's Law，关于 JavaScript 的广泛应用：

> *"任何可以用 JavaScript 编写的应用程序，最终都会用 JavaScript 编写" - Atwood's Law, Jeff Atwood*

这一观点一次又一次地被证明是正确的。现在有编译器、电子表格、文字处理器——你说的都有——都是用 JavaScript 编写的。

随着使用 JavaScript 的应用程序变得越来越复杂，开发人员可能会遇到许多与传统编程语言中相同的问题：我们如何编写这个应用程序以适应变化？

这引出了对应用程序进行适当设计的需求。我们不能再简单地把一堆 JavaScript 放入一个文件中，然后希望它能正常工作。我们也不能依赖于 jQuery 等库来拯救自己。库只能提供额外的功能，对应用程序的结构没有任何贡献。现在必须要注意如何构建应用程序以使其具有可扩展性和适应性。现实世界是不断变化的，任何不能适应变化世界的应用程序都可能被抛在脑后。设计模式在构建适应性强的应用程序方面提供了一些指导，这些应用程序可以随着业务需求的变化而变化。

# 什么是设计模式？

在大多数情况下，想法只适用于一个地方。例如，在烹饪中添加花生酱确实只是一个好主意，而在缝纫中不是。然而，偶尔也可能会发现一个好主意在原始用途之外也有适用性。这就是设计模式背后的故事。

1977 年，克里斯托弗·亚历山大、Sara Ishikawa 和 Murray Silverstein 撰写了一本关于城市规划中所谓的设计模式的重要书籍，名为《模式语言：城镇、建筑、建筑》。

这本书描述了一种用于讨论设计共性的语言。在书中，模式被描述如下：

> “这种语言的元素被称为模式实体。每个模式描述了我们环境中反复出现的问题，然后以这样一种方式描述了解决这个问题的核心，以便您可以使用这个解决方案一百万次，而不必两次以相同的方式做。” ——克里斯托弗·亚历山大

这些设计模式是如何布局城市以提供城市和乡村生活的混合，或者如何在住宅区中建造环路道路作为交通缓和措施的，如下图所示。

![什么是设计模式？](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00003.jpg)

即使对于那些对城市规划不感兴趣的人来说，这本书也提出了一些关于如何构建我们的世界以促进健康社会的迷人想法。

Erich Gamma、Richard Helm、Ralph Johnson 和 John Vlissides 利用克里斯托弗·亚历山大和其他作者的作品作为灵感来源，写了一本名为《设计模式：可重用面向对象软件的元素》的书。当一本书在计算机科学课程中非常有影响力时，通常会被赋予一个昵称。例如，大多数计算机科学毕业生会知道，如果你谈论《龙书》（《编译原理》, 1986），你指的是哪本书。在企业软件中，《蓝皮书》是众所周知的埃里克·埃文斯关于领域驱动设计的书。设计模式书是如此重要，以至于通常被称为 GoF 书，或者四人帮书，因为它有四位作者。

这本书概述了 23 种用于面向对象设计的模式。它将这些模式分为三大类：

+   **创建**：这些模式概述了对象可以被创建和它们的生命周期如何被管理的多种方式

+   **行为**：这些模式描述了对象如何相互交互

+   **结构**：这些模式描述了向现有对象添加功能的各种不同方式

设计模式的目的不是指导你如何构建软件，而是提供解决常见问题的方法。例如，许多应用程序需要提供某种撤销功能。这个问题在文本编辑器、绘图程序甚至电子邮件客户端中都很常见。解决这个问题已经做过很多次了，因此有一个通用的解决方案会很好。命令模式提供了这样一个通用解决方案。它建议跟踪应用程序中执行的所有操作，作为命令的实例。这个命令将有前进和后退操作。每次处理一个命令时，它都会被放入队列中。当需要撤销一个命令时，只需简单地从命令队列中弹出顶部的命令并执行其撤销操作。

设计模式提供了一些关于如何解决常见问题的提示，比如撤销问题。它们是从解决同一个问题的数百次迭代中提炼出来的。设计模式可能并不完全是你所面临问题的正确解决方案，但至少应该提供一些指导，以更轻松地实现解决方案。

### 注意

我的一位顾问朋友曾经告诉我一个关于在新公司开始任务的故事。经理告诉他们，他认为团队没有太多工作要做，因为他们早早地为开发人员购买了《设计模式》一书，并且他们实现了每一个设计模式。我的朋友听到这个消息很高兴，因为他按小时收费。错误应用设计模式支付了他的长子大学教育的大部分费用。

自《设计模式》一书出版以来，有大量文献涉及列举和描述设计模式。有关特定领域的设计模式的书籍，也有涉及大型企业系统模式的书籍。维基百科的软件设计模式类别包含了 130 种不同的设计模式。然而，我认为许多条目并不是真正的设计模式，而是编程范式。

在大多数情况下，设计模式是简单的构造，不需要复杂的库支持。虽然大多数语言都有模式库，但你不需要花大量金钱购买这些库。根据需要实现模式。拥有一本昂贵的库会让你盲目地应用模式，只是为了证明花了钱。即使你有钱，我也不知道有任何用于提供模式支持的 JavaScript 库。当然，GitHub 上有大量有趣的 JavaScript 项目，所以可能有一些我不知道的库。

有人建议设计模式应该是自发的。也就是说，通过以智能的方式编写软件，可以看到模式从实现中出现。我认为这可能是一个准确的说法，但它忽略了通过试错来实现这些实现的实际成本。了解设计模式的人更有可能早期发现自发的模式。教导初级程序员有关模式是一个非常有用的练习。早期了解可以应用哪种模式或模式作为一种捷径。完整的解决方案可以更早地到达，并且减少错误。

# 反模式

如果在良好的软件设计中可以找到常见模式，那么在糟糕的软件设计中也可以找到模式吗？当然可以！有许多方法可以做错事情，但大多数都已经做过。要以前所未有的方式搞砸，需要真正的创造力。

可惜的是，很难记住多年来人们犯过的所有错误。在许多重大项目结束时，团队会坐下来撰写一份名为“经验教训”的文件。这份文件包含了项目中可能出现的问题，甚至可能概述了如何避免这些问题的建议。不幸的是，这些文件只在项目结束时才被制作。到那时，许多关键人员已经离开，剩下的人必须试图记住项目早期的经验教训，这可能是几年前的事了。最好在项目进行过程中制作这份文件。

一旦完成，文件就会被归档，准备供下一个项目使用。至少，这是理论。大部分情况下，文件被归档后就再也没有被使用过。很难创造出全球适用的经验教训。所学到的经验教训往往只对当前项目或完全相同的项目有用，而这几乎不会发生。

然而，通过查看来自各种项目的多份文件，模式开始显现。正是通过这种方法，威廉·布朗、拉斐尔·马尔沃、斯基普·麦考密克和汤姆·莫布雷，合称为“新生四杰”，参照了最初的四杰，撰写了关于反模式的最初著作。这本书《反模式：重构软件、架构和危机项目》不仅概述了代码问题，还概述了围绕代码的管理过程中的反模式。

概述的模式包括一些幽默命名的模式，如“Blob 和 Lava Flow”。Blob，也被称为上帝对象，是指一个对象不断增长，承担了应用程序逻辑的大部分责任。Lava Flow 是一种随着项目变老而出现的模式，没有人知道代码是否仍在使用。开发人员不敢删除代码，因为它可能在某处被使用，或者将来可能会再次有用。书中还描述了许多其他值得探索的模式。与模式一样，反模式也是从编写代码中出现的，但在这种情况下，是失控的代码。

本书不涵盖 JavaScript 反模式，但值得记住的是，过度应用设计模式是一种反模式之一。

# 摘要

设计模式有着丰富而有趣的历史。从最初作为帮助描述如何构建结构以让人们共同生活的工具，它们已经发展成适用于许多领域。

自从将设计模式应用于编程的开创性工作以来已经过去了十年。此后，已经开发出了大量新的模式。其中一些模式是通用模式，如《设计模式》一书中概述的那些，但更多的是非常具体的模式，专为在狭窄领域中使用而设计。

JavaScript 也有着有趣的历史，正在迎来成熟。随着服务器端 JavaScript 的兴起和大型 JavaScript 应用程序变得普遍，构建 JavaScript 应用程序需要更多的细心。在大多数现代 JavaScript 代码中很少看到模式被正确地应用。

依靠设计模式提供的教导来构建现代 JavaScript 模式，可以让我们兼得两全。正如艾萨克·牛顿所说：

> “如果我看得更远一些，那是因为我站在巨人的肩膀上。”

模式为我们提供了易于访问的支持。 

在下一章中，我们将探讨一些在 JavaScript 中构建结构的技术。JavaScript 的继承系统与大多数其他面向对象的语言不同，这为我们提供了机会和限制。我们将看到如何在 JavaScript 世界中构建类和模块。


# 第一部分：经典设计模式

组织代码

创造模式

结构模式

行为模式



# 第二章：组织代码

在本章中，我们将看看如何将 JavaScript 代码组织成可重用、可理解的代码块。语言本身并不适合这种模块化，但多年来出现了许多组织 JavaScript 代码的方法。本章将论证需要拆分代码，然后逐步介绍创建 JavaScript 模块的方法。

我们将涵盖以下主题：

+   全局范围

+   对象

+   原型继承

+   ECMAScript 2015 类

# 代码块

任何人学习编程的第一件事就是无处不在的 Hello World 应用程序。这个简单的应用程序将“hello world”的某种变体打印到屏幕上。取决于你问的人，hello world 这个短语可以追溯到 20 世纪 70 年代初，当时它被用来演示 B 编程语言，甚至可以追溯到 1967 年，当时它出现在 BCL 编程指南中。在这样一个简单的应用程序中，无需担心代码的结构。事实上，在许多编程语言中，hello world 根本不需要结构。

对于 Ruby，情况如下：

```js
 **#!/usr/bin/ruby** 

 **puts "hello world"** 

```

对于 JavaScript（通过 Node.js），情况如下：

```js
 **#!/usr/local/bin/node** 

 **console.log("Hello world")** 

```

最初使用极其简单的技术来编程现代计算机。许多最初的计算机在解决问题时都被硬编码。它们不像我们今天拥有的通用计算机那样。相反，它们被构建为仅解决一个问题，例如解码加密文本。存储程序计算机最早是在 1940 年代末开发的。

最初用于编程这些计算机的语言通常非常复杂，通常与二进制密切相关。最终，创建了越来越高级的抽象，使编程更加易于访问。随着这些语言在 50 年代和 60 年代开始形成，很快就显而易见地需要一些方法来划分大块代码。

部分原因是为了保持程序员的理智，他们无法一次记住整个大型程序。然而，创建可重用的模块也允许在应用程序内部甚至在应用程序之间共享代码。最初的解决方案是利用语句，它们跳转程序的流程控制从一个地方到另一个地方。多年来，这些 GOTO 语句被大量依赖。对于一个不断受到有关使用 GOTO 语句的警告的现代程序员来说，这似乎是疯狂的。然而，直到第一批编程语言出现几年后，结构化编程才发展成为取代 GOTO 语法的形式。

结构化编程基于 Böhm-Jacopini 定理，该定理指出有一类相当大的问题，其答案可以使用三个非常简单的构造来计算：

+   子程序的顺序执行

+   两个子程序的条件执行

+   重复执行子程序，直到条件为真

敏锐的读者会认识到这些构造是正常的执行流程，一个分支或`if`语句和一个循环。

Fortran 是最早的语言之一，最初构建时没有支持结构化编程。然而，结构化编程很快被采纳，因为它有助于避免意大利面式代码。

Fortran 中的代码被组织成模块。模块是松散耦合的过程集合。对于那些来自现代面向对象语言的人来说，最接近的概念可能是模块就像一个只包含静态方法的类。

模块对于将代码分成逻辑分组非常有用。但是，它并没有为实际应用程序提供任何结构。面向对象语言的结构，即类和子类，可以追溯到 Ole-Johan Dahl 和 Kristen Nygaard 在 1967 年撰写的一篇论文。这篇论文将成为 Simula-67 的基础，这是第一种支持面向对象编程的语言。

虽然 Simula-67 是第一种具有类的语言，但与早期面向对象编程相关的最多讨论的语言是 Smalltalk。这种语言是在 20 世纪 70 年代在著名的施乐**帕洛阿尔托研究中心**（**PARC**）秘密开发的。它于 1980 年作为 Smalltalk-80 向公众发布（似乎所有具有历史意义的编程语言都以发布年份作为版本号的前缀）。Smalltalk 带来的是语言中的一切都是对象，甚至像 3 这样的文字数字也可以对它们执行操作。

几乎每种现代编程语言都有一些类的概念来组织代码。通常，这些类将属于一个称为命名空间或模块的更高级结构。通过使用这些结构，即使是非常大的程序也可以分成可管理和可理解的块。

尽管类和模块具有丰富的历史和明显的实用性，JavaScript 直到最近才支持它们作为一流构造。要理解为什么，只需简单地回顾一下 JavaScript 的历史，从第一章，*为了乐趣和利润而设计*，并意识到对于其最初的目的来说，拥有这样的构造将是多余的。类是注定要失败的 ECMAScript 4 标准的一部分，它们最终成为了 ECMAScript 2015 标准的一部分。

在本章中，我们将探讨一些在 JavaScript 中重新创建其他现代编程语言中的经典类结构的方法。

# 全局范围有什么问题？

在基于浏览器的 JavaScript 中，您创建的每个对象都分配给全局范围。对于浏览器，这个对象简单地称为**window**。通过在您喜欢的浏览器中打开开发控制台，可以很容易地看到这种行为。

### 提示

**打开开发控制台**

现代浏览器内置了一些非常先进的调试和审计工具。要访问它们，有一个菜单项，位于**工具** | **Chrome 开发者工具** | **工具** | **Firefox Web 开发者**下，以及直接在菜单下方的**F12 开发者工具**在 Internet Explorer 中。还存在用于访问工具的键盘快捷键。在 Windows 和 Linux 上，*F12*是标准的，在 OSX 上，使用`Option` + `Command` + `I`。

开发工具中有一个控制台窗口，可以直接访问当前页面的 JavaScript。这是一个非常方便的地方，可以测试小代码片段或访问页面的 JavaScript。

打开控制台后，输入以下代码：

```js
> var words = "hello world"
> console.log(window.words);
```

这将导致`hello world`打印到控制台。通过全局声明单词，它会自动附加到顶层容器：window。

在 Node.js 中，情况有些不同。以这种方式分配变量实际上会将其附加到当前模块。不包括`var`对象将会将变量附加到`global`对象上。

多年来，您可能听说过使用全局变量是一件坏事。这是因为全局变量很容易被其他代码污染。

考虑一个非常常见的变量名，比如`index`。在任何规模可观的应用程序中，这个变量名可能会在多个地方使用。当任一代码片段使用该变量时，它会导致另一代码片段出现意外结果。重用变量是可能的，甚至在内存非常有限的系统中也可能很有用，比如嵌入式系统，但在大多数应用程序中，在单个范围内重用变量以表示不同的含义是难以理解的，也是错误的根源。

使用全局作用域变量的应用程序也容易受到其他代码的攻击。从其他代码改变全局变量的状态是微不足道的，这可能会使攻击者暴露登录信息等机密信息。

最后，全局变量给应用程序增加了很多复杂性。将变量的范围减小到代码的一小部分可以让开发人员更容易理解变量的使用方式。当范围是全局时，对该变量的更改可能会影响到代码的其他部分。对变量的简单更改可能会影响整个应用程序。

一般来说，应该避免使用全局变量。

# JavaScript 中的对象

JavaScript 是一种面向对象的语言，但大多数人在使用它时并不会充分利用其面向对象的特性。JavaScript 使用混合对象模型，它既有原始值，也有对象。JavaScript 有五种原始类型：

+   未定义

+   空值

+   布尔值

+   字符串

+   数字

在这五个值中，只有两个是我们期望的对象。另外三个，布尔值、字符串和数字都有包装版本，它们是对象：Boolean、String 和 Number。它们以大写字母开头进行区分。这与 Java 使用的模型相同，是对象和原始值的混合。

JavaScript 还会根据需要对原始值进行装箱和未装箱。

在这段代码中，您可以看到 JavaScript 原始值的装箱和未装箱版本在工作：

```js
var numberOne = new Number(1);
var numberTwo = 2;
typeof numberOne; //returns 'object'
typeof numberTwo; //returns 'number'
var numberThree = numberOne + numberTwo;
typeof numberThree; //returns 'number'
```

在 JavaScript 中创建对象是微不足道的。可以在这段代码中看到在 JavaScript 中创建对象的过程：

```js
var objectOne = {};
typeof objectOne; //returns 'object'
var objectTwo = new Object();
typeof objectTwo; //returns 'object'
```

因为 JavaScript 是一种动态语言，向对象添加属性也非常容易。甚至可以在创建对象之后进行。这段代码创建了对象：

```js
var objectOne = { value: 7 };
var objectTwo = {};
objectTwo.value = 7;
```

对象包含数据和功能。到目前为止，我们只看到了数据部分。幸运的是，在 JavaScript 中，函数是一等对象。函数可以传递并且函数可以分配给变量。让我们尝试向我们在这段代码中创建的对象添加一些函数：

```js
var functionObject = {};
functionObject.doThings = function() {
  console.log("hello world");
}
functionObject.doThings(); //writes "hello world" to the console
```

这种语法有点痛苦，一次分配一个对象。让我们看看是否可以改进创建对象的语法：

```js
var functionObject = {
  doThings: function() {
    console.log("hello world");
  }
}
functionObject.doThings();//writes "hello world" to the console
```

这种语法看起来，至少对我来说，是一种更清晰、更传统的构建对象的方式。当然，可以以这种方式在对象中混合数据和功能：

```js
var functionObject = {
  greeting: "hello world",
  doThings: function() {
    console.log(this.greeting);
  }
}
functionObject.doThings();//prints hello world
```

在这段代码中有几点需要注意。首先，对象中的不同项使用逗号而不是分号分隔。那些来自其他语言如 C#或 Java 的人可能会犯这个错误。下一个值得注意的是，我们需要使用`this`限定符来从`doThings`函数内部访问`greeting`变量。如果我们在对象中有多个函数，情况也是如此，如下所示：

```js
var functionObject = {
  greeting: "hello world",
  doThings: function() {
    console.log(this.greeting);
    this.doOtherThings();
  },
  doOtherThings: function() {
    console.log(this.greeting.split("").reverse().join(""));
  }
}
functionObject.doThings();//prints hello world then dlrow olleh
```

`this`关键字在 JavaScript 中的行为与您从其他 C 语法语言中所期望的不同。`this`绑定到函数的所有者中。但是，函数的所有者有时并不是您所期望的。在前面的示例中，`this`绑定到`functionObject`对象，但是如果函数在对象之外声明，这将指向全局对象。在某些情况下，通常是事件处理程序，`this`会重新绑定到触发事件的对象。

让我们看一下以下代码：

```js
var target = document.getElementById("someId");
target.addEventListener("click", function() {
  console.log(this);
}, false);
```

`this`采用目标的值。熟悉`this`的值可能是 JavaScript 中最棘手的事情之一。

ECMAScript-2015 引入了`let`关键字，可以替代`var`关键字来声明变量。`let`使用块级作用域，这是大多数语言中常用的作用域。让我们看一个它们之间的例子：

```js
for(var varScoped =0; varScoped <10; varScoped++)
{
  console.log(varScoped);
}
console.log(varScoped +10);
for(let letScoped =0; letScoped<10; letScoped++)
{
  console.log(letScoped);
}
console.log(letScoped+10);
```

使用 var 作用域版本，您可以看到变量在块外继续存在。这是因为在幕后，`varScoped`的声明被提升到代码块的开头。在代码的`let`作用域版本中，`letScoped`仅在`for`循环内部作用域，因此一旦离开循环，`letScoped`就变为未定义。在使用`let`或`var`的选择时，我们倾向于始终使用`let`。有些情况下，您确实希望使用 var 作用域，但这些情况寥寥无几。

我们已经建立了一个相当完整的模型，来展示如何在 JavaScript 中构建对象。但是，对象并不等同于类。对象是类的实例。如果我们想要创建多个`functionObject`对象的实例，我们就没那么幸运了。尝试这样做将导致错误。在 Node.js 的情况下，错误将如下所示：

```js
let obj = new functionObject();
TypeError: object is not a function
  at repl:1:11
  at REPLServer.self.eval (repl.js:110:21)
  at repl.js:249:20
  at REPLServer.self.eval (repl.js:122:7)
  at Interface.<anonymous> (repl.js:239:12)
  at Interface.EventEmitter.emit (events.js:95:17)
  at Interface._onLine (readline.js:202:10)
  at Interface._line (readline.js:531:8)
  at Interface._ttyWrite (readline.js:760:14)
  at ReadStream.onkeypress (readline.js:99:10)
```

这里的堆栈跟踪显示了一个名为`repl`的模块中的错误。这是在启动 Node.js 时默认加载的读取-执行-打印循环。

每次需要一个新实例时，都必须重新构建对象。为了避免这种情况，我们可以使用函数来定义对象，就像这样：

```js
let ThingDoer = function(){
  this.greeting = "hello world";
  this.doThings = function() {
    console.log(this.greeting);
    this.doOtherThings();
  };
  this.doOtherThings = function() {
    console.log(this.greeting.split("").reverse().join(""));
  };
}
let instance = new ThingDoer();
instance.doThings(); //prints hello world then dlrow olleh
```

这种语法允许定义构造函数，并从该函数创建新对象。没有返回值的构造函数是在创建对象时调用的函数。在 JavaScript 中，构造函数实际上返回创建的对象。您甚至可以通过将它们作为初始函数的一部分来使用构造函数来分配内部属性，就像这样：

```js
let ThingDoer = function(greeting){
  this.greeting = greeting;
  this.doThings = function() {
    console.log(this.greeting);
  };
}
let instance = new ThingDoer("hello universe");
instance.doThings();
```

# 给我建立一个原型

如前所述，直到最近，JavaScript 没有支持创建真正的类。虽然 ECMAScript-2015 为类带来了一些语法糖，但底层的对象系统仍然与过去一样，因此看到我们如何在没有这些语法糖的情况下创建对象仍然具有指导意义。使用前一节中的结构创建的对象有一个相当大的缺点：创建多个对象不仅耗时，而且占用内存。以相同方式创建的每个对象都是完全独立的。这意味着用于保存函数定义的内存不会在所有实例之间共享。更有趣的是，您甚至可以重新定义类的单个实例，而不改变所有实例。这在这段代码中得到了证明：

```js
let Castle = function(name){
  this.name = name;
  this.build = function() {
    console.log(this.name);
  };
}
let instance1 = new Castle("Winterfell");
let instance2 = new Castle("Harrenhall");
instance1.build = function(){ console.log("Moat Cailin");}
instance1.build(); //prints "Moat Cailin"
instance2.build(); //prints "Harrenhall" to the console
```

以这种方式改变单个实例的功能，或者实际上是以任何已定义的对象的方式，被称为**monkey** **patching**。人们对这是否是一种良好的做法存在分歧。在处理库代码时，它肯定是有用的，但它会带来很大的混乱。通常认为更好的做法是扩展现有类。

在没有适当的类系统的情况下，JavaScript 当然没有继承的概念。但是，它确实有一个原型。在 JavaScript 中，对象在最基本的层面上是一个键和值的关联数组。对象上的每个属性或函数都简单地定义为这个数组的一部分。您甚至可以通过使用数组语法访问对象的成员来看到这一点，就像这里所示的那样：

```js
let thing = { a: 7};
console.log(thing["a"]);
```

### 提示

使用数组语法访问对象的成员可以是一种非常方便的方法，可以避免使用 eval 函数。例如，如果我有一个名为`funcName`的字符串，我想在对象`obj1`上调用它，那么我可以这样做`obj1[funcName]()`，而不是使用可能危险的 eval 调用。Eval 允许执行任意代码。在页面上允许这样做意味着攻击者可能能够在其他人的浏览器上输入恶意脚本。

当创建对象时，它的定义是从原型继承的。奇怪的是，每个原型也是一个对象，所以甚至原型也有原型。好吧，除了作为顶级原型的对象。将函数附加到原型的优势在于只创建一个函数的副本；节省内存。原型有一些复杂性，但您肯定可以在不了解它们的情况下生存。要使用原型，您只需将函数分配给它，如下所示：

```js
let Castle = function(name){
  this.name = name;
}
Castle.prototype.build = function(){ console.log(this.name);}
let instance1 = new Castle("Winterfell");
instance1.build();
```

需要注意的一件事是只有函数分配给原型。诸如`name`之类的实例变量仍然分配给实例。由于这些对每个实例都是唯一的，因此对内存使用没有真正的影响。

在许多方面，原型语言比基于类的继承模型更强大。

如果以后更改对象的原型，则共享该原型的所有对象都将使用新函数进行更新。这消除了关于猴子打字的一些担忧。此行为的示例如下：

```js
let Castle = function(name){
  this.name = name;
}
Castle.prototype.build = function(){
  console.log(this.name);
}
let instance1 = new Castle("Winterfell");
Castle.prototype.build = function(){
  console.log(this.name.replace("Winterfell", "Moat Cailin"));
}
instance1.build();//prints "Moat Cailin" to the console
```

在构建对象时，您应该确保尽可能利用原型对象。

现在我们知道了原型，JavaScript 中构建对象的另一种方法是使用`Object.create`函数。这是 ECMAScript 5 中引入的新语法。语法如下：

```js
Object.create(prototype [, propertiesObject ] )
```

创建语法将基于给定的原型构建一个新对象。您还可以传递一个`propertiesObject`对象，该对象描述了创建的对象上的附加字段。这些描述符包括许多可选字段：

+   `可写`：这决定了字段是否可写

+   `可配置`：这决定了文件是否应该从对象中移除或在创建后支持进一步配置

+   `可枚举`：这决定了属性在对象属性枚举期间是否可以被列出

+   `值`：这决定了字段的默认值

还可以在描述符中分配`get`和`set`函数，这些函数充当其他内部属性的 getter 和 setter。

使用`object.create`为我们的城堡，我们可以像这样使用`Object.create`构建一个实例：

```js
let instance3 = Object.create(Castle.prototype, {name: { value: "Winterfell", writable: false}});
instance3.build();
instance3.name="Highgarden";
instance3.build();
```

您会注意到我们明确定义了`name`字段。`Object.create`绕过了构造函数，因此我们在前面的代码中描述的初始赋值不会被调用。您可能还注意到`writeable`设置为`false`。其结果是对`name`的重新分配为`Highgarden`没有效果。输出如下：

```js
Winterfell
Winterfell
```

# 继承

对象的一个好处是可以构建更复杂的对象。这是一个常见的模式，用于任何数量的事情。JavaScript 中没有继承，因为它是原型的性质。但是，您可以将一个原型中的函数组合到另一个原型中。

假设我们有一个名为`Castle`的基类，并且我们想将其定制为一个更具体的类`Winterfell`。我们可以通过首先将所有属性从`Castle`原型复制到`Winterfell`原型来实现。可以这样做：

```js
let Castle = function(){};
Castle.prototype.build = function(){console.log("Castle built");}

let Winterfell = function(){};
Winterfell.prototype.build = Castle.prototype.build;
Winterfell.prototype.addGodsWood = function(){}
let winterfell = new Winterfell();
winterfell.build(); //prints "Castle built" to the console
```

当然，这是一种非常痛苦的构建对象的方式。您被迫确切地知道基类有哪些函数来复制它们。可以像这样天真地抽象化：

```js
function clone(source, destination) {
  for(var attr in source.prototype){ destination.prototype[attr] = source.prototype[attr];}
}
```

如果你对对象图表感兴趣，这显示了**Winterfell**在这个图表中如何扩展**Castle**：

![继承](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00004.jpg)

这可以很简单地使用如下：

```js
let Castle = function(){};
Castle.prototype.build = function(){console.log("Castle built");}

let Winterfell = function(){};
clone(Castle, Winterfell);
let winterfell = new Winterfell();
winterfell.build();
```

我们说这是天真的，因为它没有考虑到许多潜在的失败条件。一个完整的实现是相当广泛的。jQuery 库提供了一个名为`extend`的函数，它以健壮的方式实现了原型继承。它大约有 50 行代码，处理深层复制和空值。这个函数在 jQuery 内部被广泛使用，但它也可以成为你自己代码中非常有用的函数。我们提到原型继承比传统的继承方法更强大。这是因为可以从许多基类中混合和匹配位来创建一个新的类。大多数现代语言只支持单一继承：一个类只能有一个直接的父类。有一些语言支持多重继承，然而，这是一种在运行时决定调用哪个版本的方法时增加了很多复杂性的做法。原型继承通过在组装时强制选择方法来避免许多这些问题。

以这种方式组合对象允许从两个或更多不同的基类中获取属性。有许多时候这是很有用的。例如，代表狼的类可能从描述狗的类和描述四足动物的另一个类中获取一些属性。

通过使用以这种方式构建的类，我们可以满足几乎所有构建类系统包括继承的要求。然而，继承是一种非常强的耦合形式。在几乎所有情况下，最好避免继承，而选择一种更松散的耦合形式。这将允许类在对系统的其余部分影响最小的情况下被替换或更改。

# 模块

现在我们有了一个完整的类系统，很好地解决了之前讨论过的全局命名空间问题。同样，JavaScript 没有对命名空间的一流支持，但我们可以很容易地将功能隔离到等同于命名空间的东西中。在 JavaScript 中有许多不同的创建模块的方法。我们将从最简单的开始，并随着进展逐渐添加一些功能。

首先，我们只需要将一个对象附加到全局命名空间。这个对象将包含我们的根命名空间。我们将命名我们的命名空间为`Westeros`；代码看起来就像这样：

```js
Westeros = {}
```

这个对象默认附加到顶层对象，所以我们不需要做更多的事情。一个典型的用法是首先检查对象是否已经存在，然后使用该版本而不是重新分配变量。这允许你将你的定义分散在许多文件中。理论上，你可以在每个文件中定义一个单一的类，然后在交付给客户或在应用程序中使用之前，在构建过程的一部分将它们全部汇集在一起。这个简短的形式是：

```js
Westeros = Westeros || {}
```

一旦我们有了这个对象，只需要将我们的类分配为该对象的属性。如果我们继续使用`Castle`对象，那么它看起来会像这样：

```js
let Westeros = Westeros || {};
Westeros.Castle = function(name){this.name = name}; //constructor
Westeros.Castle.prototype.Build = function(){console.log("Castle built: " +  this.name)};
```

如果我们想要构建一个多于单层深度的命名空间层次结构，也很容易实现，就像这段代码中所示的那样：

```js
let Westeros = Westeros || {};
Westeros.Structures = Westeros.Structures || {};
Westeros.Structures.Castle = function(name){ this.name = name}; //constructor
Westeros.Structures.Castle.prototype.Build = function(){console.log("Castle built: " +  this.name)};
```

这个类可以被实例化并且以类似于之前例子的方式使用：

```js
let winterfell = new Westeros.Structures.Castle("Winterfell");
winterfell.Build();
```

当然，使用 JavaScript 有多种构建相同代码结构的方法。构建前面的代码的一种简单方法是利用创建并立即执行函数的能力：

```js
let Castle = (function () {
  function Castle(name) {
    this.name = name;
  }
  Castle.prototype.Build = function () {
    console.log("Castle built: " + this.name);
  };
  return Castle;
})();
Westros.Structures.Castle = Castle;
```

这段代码似乎比之前的代码示例要长一些，但由于其分层性质，我觉得更容易理解。我们可以像前面的代码中所示的那样，在相同的结构中使用它们来创建一个新的城堡：

```js
let winterfell = new Westeros.Structures.Castle("Winterfell");
winterfell.Build();
```

使用这种结构进行继承也相对容易。如果我们定义了一个`BaseStructure`类，它是所有结构的祖先，那么使用它会像这样：

```js
let BaseStructure = (function () {
  function BaseStructure() {
  }
  return BaseStructure;
})();
Structures.BaseStructure = BaseStructure;
let Castle = (function (_super) {
  **__extends(Castle, _super);** 

  function Castle(name) {
    this.name = name;
    _super.call(this);
  }
  Castle.prototype.Build = function () {
    console.log("Castle built: " + this.name);
  };
  return Castle;
})(BaseStructure);
```

您会注意到，当闭包被评估时，基本结构被传递到`Castle`对象中。代码中的高亮行使用了一个叫做`__extends`的辅助方法。这个方法负责将函数从基本原型复制到派生类中。这段特定的代码是由 TypeScript 编译器生成的，它还生成了一个看起来像这样的`extends`方法：

```js
let __extends = this.__extends || function (d, b) {
  for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
  function __() { this.constructor = d; }
  __.prototype = b.prototype;
  d.prototype = new __();
};
```

我们可以继续使用我们采用的相当巧妙的闭包语法来实现整个模块。如下所示：

```js
var Westeros;
(function (Westeros) {
  (function (Structures) {
    let Castle = (function () {
      function Castle(name) {
        this.name = name;
      }
       Castle.prototype.Build = function () {
         console.log("Castle built " + this.name);
       };
       return Castle;
     })();
     Structures.Castle = Castle;
  })(Westeros.Structures || (Westeros.Structures = {}));
  var Structures = Westeros.Structures;
})(Westeros || (Westeros = {}));
```

在这个结构中，您可以看到我们之前探讨过的创建模块的相同代码。在单个模块中定义多个类也相对容易。这可以在这段代码中看到：

```js
var Westeros;
(function (Westeros) {
  (function (Structures) {
    let Castle = (function () {
      function Castle(name) {
        this.name = name;
      }
      Castle.prototype.Build = function () {
        console.log("Castle built: " + this.name);
        var w = new Wall();
      };
      return Castle;
    })();
    Structures.Castle = Castle;
 **var Wall = (function () {** 

 **function Wall() {** 

 **console.log("Wall constructed");** 

 **}** 

 **return Wall;** 

 **})();** 

 **Structures.Wall = Wall;** 

  })(Westeros.Structures || (Westeros.Structures = {}));
  var Structures = Westeros.Structures;
})(Westeros || (Westeros = {}));
```

高亮代码在模块内创建了第二个类。在每个文件中定义一个类也是完全允许的。因为代码在盲目重新分配之前检查`Westeros`的当前值，所以我们可以安全地将模块定义分割成多个文件。

高亮部分的最后一行显示了在闭包之外暴露类。如果我们想要创建只在模块内部可用的私有类，那么我们只需要排除那一行。这实际上被称为揭示模块模式。我们只暴露需要全局可用的类。尽可能将功能保持在全局命名空间之外是一个很好的做法。

# ECMAScript 2015 类和模块

到目前为止，我们已经看到在 ECMAScript-2015 之前的 JavaScript 中完全可以构建类甚至模块。显然，这种语法比如 C#或 Java 等语言更复杂。幸运的是，ECMAScript-2015 为创建类提供了一些语法糖的支持：

```js
class Castle extends Westeros.Structures.BaseStructure {
  constructor(name, allegience) {
    super(name);
    ...
  }
  Build() {
    ...
    super.Build();
  }
}
```

ECMAScript-2015 还为 JavaScript 带来了一个经过深思熟虑的模块系统。还有一些用于创建模块的语法糖，看起来像这样：

```js
module 'Westeros' {
  export function Rule(rulerName, house) {
    ...
    return "Long live " + rulerName + " of house " + house;
  }
}
```

由于模块可以包含函数，当然也可以包含类。ECMAScript-2015 还定义了模块导入语法和支持从远程位置检索模块。导入模块看起来像这样：

```js
import westeros from 'Westeros';
module JSON from 'http://json.org/modules/json2.js';
westeros.Rule("Rob Stark", "Stark");
```

一些这种语法糖在任何支持完整 ECMAScript-2015 的环境中都是可用的。在撰写本文时，所有主要浏览器供应商对 ECMAScript-2015 的类部分都有很好的支持，所以几乎没有理由不使用它，除非你不得不支持古老的浏览器。

# 最佳实践和故障排除

在理想的世界中，每个人都可以在从一开始就制定标准的绿地项目上工作。然而，情况并非如此。经常情况下，你可能会发现自己处于一个遗留系统的一部分，其中有一堆非模块化的 JavaScript 代码。

在这些情况下，简单地忽略非模块化的代码直到真正需要升级它可能是有利的。尽管 JavaScript 很受欢迎，但 JavaScript 的许多工具仍然不够成熟，这使得很难依赖编译器来找出 JavaScript 重构引入的错误。自动重构工具也受到 JavaScript 动态特性的复杂性的影响。然而，对于新代码，正确使用模块化的 JavaScript 可以非常有助于避免命名空间冲突并提高可测试性。

如何安排 JavaScript 是一个有趣的问题。从网页的角度来看，我采取了将 JavaScript 与网页保持一致的方法。因此，每个页面都有一个关联的 JavaScript 文件，负责该页面的功能。此外，页面之间共同的组件，比如网格控件，被放置在一个单独的文件中。在编译时，所有文件都被合并成一个单独的 JavaScript 文件。这有助于在保持小型代码文件的同时减少浏览器向服务器发出的请求次数。

# 总结

有人说计算机科学中只有两件真正困难的事情。这些问题的具体内容因说话者而异。经常是一些与缓存失效和命名有关的变体。如何组织代码是其中很大一部分的命名问题。

作为一个团体，我们似乎已经坚定地接受了命名空间和类的概念。正如我们所见，JavaScript 中没有直接支持这两个概念。然而，有无数种方法可以解决这个问题，其中一些方法实际上提供的功能比传统的命名空间/类系统更强大。

JavaScript 的主要问题是要避免用大量名称相似但不相关的对象污染全局命名空间。将 JavaScript 封装成模块是朝着编写可维护和可重用代码的关键步骤。

随着我们的前进，我们会看到许多复杂的接口排列在 JavaScript 的世界中变得更加简单。原型继承，起初似乎很困难，但它是简化设计模式的巨大工具。



# 第三章：创建模式

在上一章中，我们详细研究了如何构建一个类。在本章中，我们将研究如何创建类的实例。表面上看，这似乎是一个简单的问题，但我们如何创建类的实例可能非常重要。

我们非常努力地创建我们的代码，使其尽可能解耦。确保类对其他类的依赖最小是构建一个可以随着使用软件的人的需求变化而流畅变化的系统的关键。允许类之间关系过于紧密意味着变化会像涟漪一样在它们之间传播。

一个涟漪并不是一个巨大的问题，但随着你不断引入更多的变化，涟漪会累积并产生干涉模式。很快，曾经平静的表面就变成了无法辨认的添加和破坏节点的混乱。我们的应用程序中也会出现同样的问题：变化会放大并以意想不到的方式相互作用。我们经常忽视耦合的一个地方就是在对象的创建中：

```js
let Westeros;
(function (Westeros) {
  let Ruler = (function () {
    function Ruler() {
      this.house = new Westeros.Houses.Targaryen();
    }
    return Ruler;
  })();
  Westeros.Ruler = Ruler;
})(Westeros || (Westeros = {}));
```

在这个类中，你可以看到统治者的家与`Targaryen`类紧密耦合。如果这种情况发生改变，那么这种紧密耦合就必须在很多地方进行改变。本章讨论了一些模式，这些模式最初是在《设计模式：可复用面向对象软件的元素》一书中提出的。这些模式的目标是改善应用程序中的耦合程度，并增加代码重用的机会。这些模式如下：

+   抽象工厂

+   建造者

+   工厂方法

+   单例

+   原型

当然，并非所有这些都适用于 JavaScript，但随着我们逐步了解创建模式，我们会了解到这一切。

# 抽象工厂

这里介绍的第一个模式是一种创建对象套件的方法，而不需要知道对象的具体类型。让我们继续使用前一节中介绍的统治王国的系统。

对于所讨论的王国，统治家族的更换频率相当高。很可能在更换家族时会有一定程度的战斗和斗争，但我们暂且不予理会。每个家族都会以不同的方式统治王国。有些人看重和平与宁静，以仁慈的领导者统治，而另一些则以铁腕统治。一个王国的统治对于一个人来说太大了，所以国王会将一些决定交给一个叫做国王之手的副手。国王也会在一些事务上得到一个由一些精明的领主和贵妇组成的议会的建议。

我们描述的类的图表如下：

![抽象工厂](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00005.jpg)

### 提示

**统一建模语言**（**UML**）是由对象管理组开发的标准化语言，用于描述计算机系统。该语言中有用于创建用户交互图、序列图和状态机等的词汇。对于本书的目的，我们最感兴趣的是类图，它描述了一组类之间的关系。

整个 UML 类图词汇量很大，超出了本书的范围。然而，维基百科上的文章[`en.wikipedia.org/wiki/Class_diagram`](https://en.wikipedia.org/wiki/Class_diagram)以及 Derek Banas 的优秀视频教程[`www.youtube.com/watch?v=3cmzqZzwNDM`](https://www.youtube.com/watch?v=3cmzqZzwNDM)都是很好的介绍。

问题在于，由于统治家族甚至统治家族成员经常变动，与 Targaryen 或 Lannister 等具体家族耦合会使我们的应用程序变得脆弱。脆弱的应用程序在不断变化的世界中表现不佳。

解决这个问题的方法是利用抽象工厂模式。抽象工厂声明了一个接口，用于创建与统治家族相关的各种类。

这种模式的类图相当令人生畏：

![抽象工厂](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00006.jpg)

抽象工厂类可能对统治家族的各个实现有多个。这些被称为具体工厂，它们每个都将实现抽象工厂提供的接口。具体工厂将返回各种统治类的具体实现。这些具体类被称为产品。

让我们首先看一下抽象工厂接口的代码。

没有代码？实际上确实如此。JavaScript 的动态特性消除了描述类所需的接口的需要。我们将直接创建类，而不是使用接口：

![抽象工厂](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00007.jpg)

JavaScript 不使用接口，而是相信您提供的类实现了所有适当的方法。在运行时，解释器将尝试调用您请求的方法，并且如果找到该方法，就会调用它。解释器只是假设如果您的类实现了该方法，那么它就是该类。这就是所谓的**鸭子类型**。

### 注意

**鸭子类型**

鸭子类型的名称来源于 Alex Martelli 在 2000 年发布的一篇文章，他在*comp.lang.python*新闻组中写道：

*换句话说，不要检查它是否是一只鸭子：检查它是否像一只鸭子一样嘎嘎叫，像一只鸭子一样走路，等等，具体取决于您需要用来玩语言游戏的鸭子行为的子集。*

我喜欢 Martelli 可能是从*Monty Python and the Holy Grail*的巫师狩猎片段中借用了这个术语。虽然我找不到任何证据，但我认为这很可能，因为 Python 编程语言的名称就来自于 Monty Python。

鸭子类型是动态语言中的强大工具，可以大大减少实现类层次结构的开销。然而，它确实引入了一些不确定性。如果两个类实现了具有根本不同含义的同名方法，那么就无法知道调用的是正确的方法。例如，考虑以下代码：

```js
class Boxer{
  function punch(){}
}
class TicketMachine{
  function punch(){}
}
```

这两个类都有一个`punch()`方法，但显然意义不同。JavaScript 解释器不知道它们是不同的类，并且会愉快地在任何一个类上调用 punch，即使其中一个没有意义。

一些动态语言支持一种通用方法，当调用未定义的方法时会调用该方法。例如，Ruby 有`missing_method`，在许多情况下都被证明非常有用。截至目前，JavaScript 目前不支持`missing_method`。然而，ECMAScript 2016，即 ECMAScript 2015 的后续版本，定义了一个称为`Proxy`的新构造，它将支持动态包装对象，借助它可以实现一个等价的`missing_method`。

## 实现

为了演示抽象工厂的实现，我们首先需要一个`King`类的实现。这段代码提供了该实现：

```js
let KingJoffery= (function () {
  function KingJoffery() {
  }
  KingJoffery.prototype.makeDecision = function () {
    …
  };
  KingJoffery.prototype.marry = function () {
    …
  };
  return KingJoffery;
})();
```

### 注意

这段代码不包括第二章*组织代码*中建议的模块结构。在每个示例中包含模块代码是乏味的，你们都是聪明的人，所以如果你们要真正使用它，就知道把它放在模块中。完全模块化的代码可以在分发的源代码中找到。

这只是一个普通的具体类，实际上可以包含任何实现细节。我们还需要一个同样不起眼的`HandOfTheKing`类的实现：

```js
let LordTywin = (function () {
  function LordTywin() {
  }
  LordTywin.prototype.makeDecision = function () {
  };
  return LordTywin;
})();
```

具体的工厂方法如下：

```js
let LannisterFactory = (function () {
  function LannisterFactory() {
  }
  LannisterFactory.prototype.getKing = function () {
    return new KingJoffery();
  };
  LannisterFactory.prototype.getHandOfTheKing = function ()
  {
    return new LordTywin();
  };
  return LannisterFactory;
})();
```

这段代码只是实例化所需类的新实例并返回它们。不同统治家族的另一种实现将遵循相同的一般形式，可能如下所示：

```js
let TargaryenFactory = (function () {
  function TargaryenFactory() {
  }
  TargaryenFactory.prototype.getKing = function () {
    return new KingAerys();
  };
  TargaryenFactory.prototype.getHandOfTheKing = function () {
    return new LordConnington();
  };
  return TargaryenFactory;
})();
```

在 JavaScript 中实现抽象工厂比其他语言要容易得多。然而，这样做的代价是失去了编译器检查，它强制要求对工厂或产品进行完整的实现。随着我们继续学习其他模式，你会注意到这是一个常见的主题。在静态类型语言中有很多管道的模式要简单得多，但会增加运行时失败的风险。适当的单元测试或 JavaScript 编译器可以缓解这种情况。

要使用抽象工厂，我们首先需要一个需要使用某个统治家族的类：

```js
let CourtSession = (function () {
  function CourtSession(abstractFactory) {
    this.abstractFactory = abstractFactory;
    this.COMPLAINT_THRESHOLD = 10;
  }
  CourtSession.prototype.complaintPresented = function (complaint) {
    if (complaint.severity < this.COMPLAINT_THRESHOLD) {
      this.abstractFactory.getHandOfTheKing().makeDecision();
    } else
    this.abstractFactory.getKing().makeDecision();
  };
  return CourtSession;
})();
```

现在我们可以调用这个`CourtSession`类，并根据传入的工厂注入不同的功能：

```js
let courtSession1 = new CourtSession(new TargaryenFactory());
courtSession1.complaintPresented({ severity: 8 });
courtSession1.complaintPresented({ severity: 12 });

let courtSession2 = new CourtSession(new LannisterFactory());
courtSession2.complaintPresented({ severity: 8 });
courtSession2.complaintPresented({ severity: 12 });
```

尽管静态语言和 JavaScript 之间存在差异，但这种模式在 JavaScript 应用程序中仍然适用且有用。创建一组共同工作的对象对于许多情况都是有用的；每当一组对象需要协作提供功能但可能需要整体替换时。当试图确保一组对象一起使用而不进行替换时，这也可能是一个有用的模式。

# 建造者

在我们的虚构世界中，有时需要构建一些相当复杂的类。这些类包含了根据构建方式不同的接口实现。为了简化这些类的构建并将构建类的知识封装在消费者之外，可以使用建造者。多个具体建造者降低了实现中构造函数的复杂性。当需要新的建造者时，不需要添加构造函数，只需要插入一个新的建造者。

锦标赛是一个复杂类的例子。每个锦标赛都有一个复杂的设置，涉及事件、参与者和奖品。这些锦标赛的大部分设置都是相似的：每一个都有比武、射箭和混战。从代码中的多个位置创建锦标赛意味着构建锦标赛的责任被分散。如果需要更改初始化代码，那么必须在许多不同的地方进行更改。

通过使用构建器模式，可以避免这个问题，因为它集中了构建对象所需的逻辑。不同的具体构建器可以插入到构建器中，以构建不同的复杂对象。构建器模式中各个类之间的关系如下所示：

![构建器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00008.jpg)

## 实施

让我们进去看一些代码。首先，我们将创建一些实用类，它们将表示比赛的各个部分，如下面的代码所示：

```js
let Event = (function () {
  function Event(name) {
    this.name = name;
  }
  return Event;
})();
Westeros.Event = Event;

let Prize = (function () {
  function Prize(name) {
    this.name = name;
  }
  return Prize;
})();
Westeros.Prize = Prize;

let Attendee = (function () {
  function Attendee(name) {
    this.name = name;
  }
  return Attendee;
})();
Westeros.Attendee = Attendee;
```

比赛本身是一个非常简单的类，因为我们不需要显式地分配任何公共属性：

```js
let Tournament = (function () {
  this.Events = [];
  function Tournament() {
  }
  return Tournament;
})();
Westeros.Tournament = Tournament;
```

我们将实现两个创建不同比赛的构建器。下面的代码中可以看到：

```js
let LannisterTournamentBuilder = (function () {
  function LannisterTournamentBuilder() {
  }
  LannisterTournamentBuilder.prototype.build = function () {
    var tournament = new Tournament();
    tournament.events.push(new Event("Joust"));
    tournament.events.push(new Event("Melee"));
    tournament.attendees.push(new Attendee("Jamie"));
    tournament.prizes.push(new Prize("Gold"));
    tournament.prizes.push(new Prize("More Gold"));
    return tournament;
  };
  return LannisterTournamentBuilder;
})();
Westeros.LannisterTournamentBuilder = LannisterTournamentBuilder;

let BaratheonTournamentBuilder = (function () {
  function BaratheonTournamentBuilder() {
  }
  BaratheonTournamentBuilder.prototype.build = function () {
    let tournament = new Tournament();
    tournament.events.push(new Event("Joust"));
    tournament.events.push(new Event("Melee"));
    tournament.attendees.push(new Attendee("Stannis"));
    tournament.attendees.push(new Attendee("Robert"));
    return tournament;
  };
  return BaratheonTournamentBuilder;
})();
Westeros.BaratheonTournamentBuilder = BaratheonTournamentBuilder;
```

最后，导演，或者我们称之为`TournamentBuilder`，只需拿起一个构建器并执行它：

```js
let TournamentBuilder = (function () {
  function TournamentBuilder() {
  }
  TournamentBuilder.prototype.build = function (builder) {
    return builder.build();
  };
  return TournamentBuilder;
})();
Westeros.TournamentBuilder = TournamentBuilder;
```

再次，您会看到 JavaScript 的实现比传统的实现要简单得多，因为不需要接口。

构建器不需要返回一个完全实现的对象。这意味着您可以创建一个部分填充对象的构建器，然后允许对象传递给另一个构建器来完成。一个很好的现实世界类比可能是汽车的制造过程。在装配线上的每个工位都只组装汽车的一部分，然后将其传递给下一个工位组装另一部分。这种方法允许将构建对象的工作分配给几个具有有限责任的类。在我们上面的例子中，我们可以有一个负责填充事件的构建器，另一个负责填充参与者的构建器。

在 JavaScript 的原型扩展模型中，构建器模式是否仍然有意义？我认为是的。仍然存在需要根据不同的方法创建复杂对象的情况。

# 工厂方法

我们已经看过抽象工厂和构建器。抽象工厂构建了一组相关的类，而构建器使用不同的策略创建复杂对象。工厂方法模式允许类请求接口的新实例，而不是类决定使用接口的哪个实现。工厂可能使用某种策略来选择要返回的实现：

![工厂方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00009.jpg)

有时，这种策略只是接受一个字符串参数或检查一些全局设置来充当开关。

## 实施

在我们的 Westworld 示例世界中，有很多时候我们希望将实现的选择推迟到工厂。就像现实世界一样，Westworld 拥有丰富多彩的宗教文化，有数十种不同的宗教崇拜各种各样的神。在每种宗教中祈祷时，必须遵循不同的规则。有些宗教要求献祭，而其他宗教只要求给予礼物。祈祷类不想知道所有不同的宗教以及如何构建它们。

让我们开始创建一些不同的神，可以向他们献祷。这段代码创建了三个神，包括一个默认的神，如果没有指定其他神，祷告就会落在他身上：

```js
let WateryGod = (function () {
  function WateryGod() {
  }
  WateryGod.prototype.prayTo = function () {
  };
  return WateryGod;
})();
Religion.WateryGod = WateryGod;
let AncientGods = (function () {
  function AncientGods() {
  }
  AncientGods.prototype.prayTo = function () {
  };
  return AncientGods;
})();
Religion.AncientGods = AncientGods;

let DefaultGod = (function () {
  function DefaultGod() {
  }
  DefaultGod.prototype.prayTo = function () {
  };
  return DefaultGod;
})();
Religion.DefaultGod = DefaultGod;
```

我避免了为每个神明的任何实现细节。您可以想象任何您想要填充`prayTo`方法的传统。也没有必要确保每个神都实现了`IGod`接口。接下来，我们需要一个工厂，负责构建不同的神：

```js
let GodFactory = (function () {
  function GodFactory() {
  }
  GodFactory.Build = function (godName) {
    if (godName === "watery")
      return new WateryGod();
    if (godName === "ancient")
      return new AncientGods();
    return new DefaultGod();
  };
  return GodFactory;
})();
```

您可以看到，在这个例子中，我们接受一个简单的字符串来决定如何创建一个神。它可以通过全局或更复杂的对象来完成。在 Westeros 的一些多神教中，神明有明确定的角色，如勇气之神、美丽之神或其他方面的神。必须祈祷的神不仅由宗教决定，还由祈祷的目的决定。我们可以用`GodDeterminant`类来表示这一点，如下所示：

```js
let GodDeterminant = (function () {
  function GodDeterminant(religionName, prayerPurpose) {
    this.religionName = religionName;
    this.prayerPurpose = prayerPurpose;
  }
  return GodDeterminant;
})();
```

工厂将被更新以接受这个类，而不是简单的字符串。

最后，最后一步是看看这个工厂将如何被使用。这很简单，我们只需要传入一个表示我们希望观察的宗教的字符串，工厂将构造正确的神并返回它。这段代码演示了如何调用工厂：

```js
let Prayer = (function () {
  function Prayer() {
  }
  Prayer.prototype.pray = function (godName) {
  GodFactory.Build(godName).prayTo();
  };
  return Prayer;
})();
```

再次，JavaScript 中肯定需要这样的模式。有很多时候，将实例化与使用分开是有用的。由于关注点的分离和注入假工厂以允许测试`Prayer`也很容易，测试实例化也非常简单。

继续创建不带接口的更简单模式的趋势，我们可以忽略模式的接口部分，直接使用类型，这要归功于鸭子类型。

工厂方法是一种非常有用的模式：它允许类将实例化的实现选择推迟到另一个类。当存在多个类似的实现时，这种模式非常有用，比如策略模式（参见第五章 ，*行为模式*），并且通常与抽象工厂模式一起使用。工厂方法用于在抽象工厂的具体实现中构建具体对象。抽象工厂模式可能包含多个工厂方法。工厂方法无疑是一种在 JavaScript 领域仍然适用的模式。

# 单例

单例模式可能是最常被滥用的模式。它也是近年来不受青睐的模式。为了看到为什么人们开始建议不要使用单例模式，让我们看看这个模式是如何工作的。

当需要全局变量时使用单例是可取的，但单例提供了防止意外创建复杂对象的保护。它还允许推迟对象实例化直到第一次使用。

单例的 UML 图如下所示：

![单例](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00010.jpg)

这显然是一种非常简单的模式。单例充当类的实例的包装器，单例本身作为全局变量存在。在访问实例时，我们只需向单例请求包装类的当前实例。如果类在单例中尚不存在，通常会在那时创建一个新实例。

## 实施

在我们在维斯特洛大陆的持续示例中，我们需要找到一个只能有一个东西的情况。不幸的是，这是一个经常发生冲突和敌对的土地，所以我最初想到的将国王作为单例的想法根本行不通。这也意味着我们不能利用其他明显的候选人（首都，王后，将军等）。然而，在维斯特洛大陆的最北部，有一堵巨大的墙，用来阻挡一位古老的敌人。这样的墙只有一堵，将其放在全局范围内应该没有问题。

让我们继续在 JavaScript 中创建一个单例：

```js
let Westros;
(function (Westeros) {
  var Wall = (function () {
 **function Wall() {** 

 **this.height = 0;** 

 **if (Wall._instance)** 

 **return Wall._instance;** 

 **Wall._instance = this;** 

 **}** 

    Wall.prototype.setHeight = function (height) {
      this.height = height;
    };
    Wall.prototype.getStatus = function () {
      console.log("Wall is " + this.height + " meters tall");
    };
 **Wall.getInstance = function () {** 

 **if (!Wall._instance) {** 

 **Wall._instance = new Wall();** 

 **}** 

 **return Wall._instance;** 

 **};** 

    Wall._instance = null;
    return Wall;
  })();
  Westeros.Wall = Wall;
})(Westeros || (Westeros = {}));
```

该代码创建了墙的轻量级表示。单例在两个突出显示的部分中进行了演示。在像 C#或 Java 这样的语言中，我们通常会将构造函数设置为私有，以便只能通过静态方法`getInstance`来调用它。然而，在 JavaScript 中我们没有这个能力：构造函数不能是私有的。因此，我们尽力而为，从构造函数中返回当前实例。这可能看起来很奇怪，但在我们构造类的方式中，构造函数与任何其他方法没有区别，因此可以从中返回一些东西。

在第二个突出部分中，我们将静态变量`_instance`设置为 Wall 的新实例（如果还没有）。如果`_instance`已经存在，我们将返回它。在 C#和 Java 中，这个函数需要一些复杂的锁定逻辑，以避免两个不同的线程同时尝试访问实例时出现竞争条件。幸运的是，在 JavaScript 中不需要担心这个问题，因为多线程的情况不同。

## 缺点

单例在过去几年中声名狼藉。它们实际上是被吹捧的全局变量。正如我们讨论过的，全局变量是不合理的，可能导致许多错误。它们也很难通过单元测试进行测试，因为实例的创建不能轻易被覆盖，测试运行器中的任何并行性都可能引入难以诊断的竞争条件。我对它们最大的担忧是单例承担了太多的责任。它们不仅控制自己，还控制它们的实例化。这是对单一责任原则的明显违反。几乎每一个可以使用单例解决的问题，都可以通过其他机制更好地解决。

JavaScript 使问题变得更糟。由于构造函数的限制，无法创建单例的清晰实现。这与单例的一般问题结合在一起，使我建议在 JavaScript 中应避免使用单例模式。

# 原型

本章中的最后一个创建模式是原型模式。也许这个名字听起来很熟悉。它确实应该：这是 JavaScript 支持继承的机制。

我们研究了用于继承的原型，但原型的适用性不一定局限于继承。复制现有对象可以是一个非常有用的模式。有许多情况下，能够复制构造对象是很方便的。例如，通过保存利用某种克隆创建的先前实例，很容易地维护对象状态的历史。

## 实施

在维斯特洛，我们发现家庭成员经常非常相似；正如谚语所说：“有其父必有其子”。随着每一代的诞生，通过复制和修改现有家庭成员来创建新一代比从头开始建造要容易得多。

在第二章中，*组织代码*，我们看了如何复制现有对象，并介绍了一个非常简单的克隆代码：

```js
function clone(source, destination) {
  for(var attr in source.prototype){
    destination.prototype[attr] = source.prototype[attr];}
}
```

这段代码可以很容易地改变，以便在类内部使用，返回自身的副本：

```js
var Westeros;
(function (Westeros) {
  (function (Families) {
    var Lannister = (function () {
      function Lannister() {
      }
      **Lannister.prototype.clone = function () {** 

 **var clone = new Lannister();** 

 **for (var attr in this) {** 

 **clone[attr] = this[attr];** 

 **}** 

 **return clone;** 

 **};** 

      return Lannister;
    })();
    Families.Lannister = Lannister;
  })(Westeros.Families || (Westeros.Families = {}));
  var Families = Westeros.Families;
})(Westeros || (Westeros = {}));
```

代码的突出部分是修改后的克隆方法。它可以这样使用：

```js
let jamie = new Westeros.Families.Lannister();
jamie.swordSkills = 9;
jamie.charm = 6;
jamie.wealth = 10;

let tyrion = jamie.clone();
tyrion.charm = 10;
//tyrion.wealth == 10
//tyrion.swordSkill == 9
```

原型模式允许只构造一次复杂对象，然后克隆成任意数量的仅略有不同的对象。如果源对象不复杂，那么采用克隆方法就没有太多好处。在使用原型方法时，必须注意依赖对象。克隆是否应该是深层的？

原型显然是一个有用的模式，也是 JavaScript 从一开始就形成的一个组成部分。因此，它肯定是任何规模可观的 JavaScript 应用程序中会看到一些使用的模式。

# 提示和技巧

创建模式允许在创建对象时实现特定行为。在许多情况下，比如工厂，它们提供了可以放置横切逻辑的扩展点。也就是说，适用于许多不同类型对象的逻辑。如果你想要在整个应用程序中注入日志，那么能够连接到工厂是非常有用的。

尽管这些创建模式非常有用，但不应该经常使用。您的大部分对象实例化仍应该是改进对象的正常方法。虽然当你有了新的工具时，把一切都视为钉子是很诱人的，但事实是每种情况都需要有一个具体的策略。所有这些模式都比简单使用`new`更复杂，而复杂的代码更容易出现错误。尽量使用`new`。

# 总结

本章介绍了创建对象的多种不同策略。这些方法提供了对创建对象的典型方法的抽象。抽象工厂提供了构建可互换的工具包或相关对象集合的方法。建造者模式提供了解决参数问题的解决方案。它使得构建大型复杂对象变得更加容易。工厂方法是抽象工厂的有用补充，允许通过静态工厂创建不同的实现。单例是一种提供整个解决方案可用的类的单个副本的模式。这是迄今为止我们所见过的唯一一个在现代软件中存在一些适用性问题的模式。原型模式是 JavaScript 中常用的一种模式，用于基于其他现有对象构建对象。

我们将在下一章继续对经典设计模式进行考察，重点关注结构模式。



# 第四章：结构模式

在上一章中，我们探讨了多种创建对象的方法，以便优化重用。在本章中，我们将研究结构模式；这些模式关注于通过描述对象可以相互交互的简单方式来简化设计。

再次，我们将限制自己只研究 GoF 书中描述的模式。自 GoF 出版以来，已经确定了许多其他有趣的结构模式，我们将在本书的第二部分中进行研究。

我们将在这里研究的模式有：

+   适配器

+   桥接

+   组合

+   装饰器

+   外观

+   享元

+   代理

我们将再次讨论多年前描述的模式是否仍然适用于不同的语言和不同的时代。

# 适配器

有时需要将圆销子放入方孔中。如果你曾经玩过儿童的形状分类玩具，你可能会发现实际上可以把圆销子放入方孔中。孔并没有完全填满，把销子放进去可能会很困难：

![适配器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00011.jpg)

为了改善销子的适配，可以使用适配器。这个适配器完全填满了孔，结果非常完美：

![适配器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00012.jpg)

在软件中经常需要类似的方法。我们可能需要使用一个不完全符合所需接口的类。该类可能缺少方法，或者可能有我们希望隐藏的额外方法。在处理第三方代码时经常会出现这种情况。为了使其符合您代码中所需的接口，可能需要使用适配器。

适配器的类图非常简单，如下所示：

![适配器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00013.jpg)

实现的接口看起来不符合我们在代码中想要的样子。通常的解决方法是简单地重构实现，使其看起来符合我们的要求。然而，有一些可能的原因无法这样做。也许实现存在于我们无法访问的第三方代码中。还有可能实现在应用程序的其他地方使用，接口正好符合我们的要求。

适配器类是一个薄薄的代码片段，实现所需的接口。它通常包装实现类的私有副本，并通过代理调用它。适配器模式经常用于改变代码的抽象级别。让我们来看一个快速的例子。

## 实施

在 Westeros 的土地上，许多贸易和旅行都是通过船只进行的。乘船旅行不仅比步行或骑马更危险，而且由于风暴和海盗的不断出现，也更加危险。这些船只不是皇家加勒比公司用来在加勒比海周游的那种船只；它们是粗糙的东西，看起来更像是 15 世纪欧洲探险家所驾驶的。

虽然我知道船只存在，但我对它们的工作原理或如何操纵船只几乎一无所知。我想很多人和我一样。如果我们看看 Westeros 的船只接口，它看起来很吓人：

```js
interface Ship{
  SetRudderAngleTo(angle: number);
  SetSailConfiguration(configuration: SailConfiguration);
  SetSailAngle(sailId: number, sailAngle: number);
  GetCurrentBearing(): number;
  GetCurrentSpeedEstimate(): number;
  ShiftCrewWeightTo(weightToShift: number, locationId: number);
}
```

我真的希望有一个更简单的接口，可以抽象掉所有繁琐的细节。理想情况下是这样的：

```js
interface SimpleShip{
  TurnLeft();
  TurnRight();
  GoForward();
}
```

这看起来像是我可能会弄清楚的东西，即使我住在离最近的海洋有 1000 公里远的城市。简而言之，我想要的是对船只进行更高级别的抽象。为了将船只转换为 SimpleShip，我们需要一个适配器。

适配器将具有 SimpleShip 的接口，但它将在 Ship 的包装实例上执行操作。代码可能看起来像这样：

```js
let ShipAdapter = (function () {
  function ShipAdapter() {
    this._ship = new Ship();
  }
  ShipAdapter.prototype.TurnLeft = function () {
    this._ship.SetRudderAngleTo(-30);
    this._ship.SetSailAngle(3, 12);
  };
  ShipAdapter.prototype.TurnRight = function () {
    this._ship.SetRudderAngleTo(30);
    this._ship.SetSailAngle(5, -9);
  };
  ShipAdapter.prototype.GoForward = function () {
    //do something else to the _ship
  };
  return ShipAdapter;
})();
```

实际上，这些功能会更加复杂，但这并不重要，因为我们有一个简单的接口来展示给世界。所呈现的接口也可以设置为限制对基础类型的某些方法的访问。在构建库代码时，适配器可用于隐藏内部方法，只向最终用户呈现所需的有限功能。

使用这种模式，代码可能看起来像这样：

```js
var ship = new ShipAdapter();
ship.GoForward();
ship.TurnLeft();
```

你可能不想在客户端类的名称中使用适配器，因为它泄露了一些关于底层实现的信息。客户端不应该知道它们正在与适配器交谈。

适配器本身可能会变得非常复杂，以调整一个接口到另一个接口。为了避免创建非常复杂的适配器，必须小心。构建几个适配器是完全可以想象的，一个在另一个之上。如果发现适配器变得太大，那么最好停下来检查适配器是否遵循单一责任原则。也就是说，确保每个类只负责一件事。一个从数据库中查找用户的类不应该包含向这些用户发送电子邮件的功能。这责任太大了。复杂的适配器可以被复合对象替换，这将在本章后面探讨。

从测试的角度来看，适配器可以用来完全包装第三方依赖。在这种情况下，它们提供了一个可以挂接测试的地方。单元测试应该避免测试库，但它们可以确保适配器代理了正确的调用。

适配器是简化代码接口的非常强大的模式。调整接口以更好地满足需求在无数地方都是有用的。这种模式在 JavaScript 中肯定很有用。用 JavaScript 编写的应用程序往往会使用大量的小型库。通过将这些库封装在适配器中，我能够限制我直接与库交互的地方的数量；这意味着可以轻松替换这些库。

适配器模式可以稍微修改，以在许多不同的实现上提供一致的接口。这通常被称为桥接模式。

# 桥接

桥梁模式将适配器模式提升到一个新的水平。给定一个接口，我们可以构建多个适配器，每个适配器都充当到不同实现的中介。

我遇到的一个很好的例子是，处理两个提供几乎相同功能并且在故障转移配置中使用的不同服务。两个服务都没有提供应用程序所需的确切接口，并且两个服务提供不同的 API。为了简化代码，编写适配器以提供一致的接口。适配器实现一致的接口并提供填充，以便可以一致地调用每个 API。再举一个形状分类器的比喻，我们可以想象我们有各种不同的销子，我们想用它们来填充方形孔。每个适配器填补了缺失的部分，并帮助我们得到一个良好的适配：

![Bridge](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00014.jpg)

桥梁是一个非常有用的模式。让我们来看看如何实现它：

![Bridge](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00015.jpg)

在前面的图表中显示的适配器位于实现和所需接口之间。它们修改实现以适应所需的接口。

## 实现

我们已经讨论过，在维斯特洛大陆上，人们信仰多种不同的宗教。每个宗教都有不同的祈祷和献祭方式。在正确的时间进行正确的祈祷有很多复杂性，我们希望避免暴露这种复杂性。相反，我们将编写一系列可以简化祈祷的适配器。

我们需要的第一件事是一些不同的神，我们可以向他们祈祷：

```js
class OldGods {
  prayTo(sacrifice) {
    console.log("We Old Gods hear your prayer");
  }
}
Religion.OldGods = OldGods;
class DrownedGod {
  prayTo(humanSacrifice) {
    console.log("*BUBBLE* GURGLE");
  }
}
Religion.DrownedGod = DrownedGod;
class SevenGods {
  prayTo(prayerPurpose) {
    console.log("Sorry there are a lot of us, it gets confusing here. Did you pray for something?");
  }
}
Religion.SevenGods = SevenGods;
```

这些类应该看起来很熟悉，因为它们基本上是在上一章中找到的相同类，它们被用作工厂方法的示例。但是，您可能会注意到，每种宗教的`prayTo`方法的签名略有不同。当构建像这里的伪代码中所示的一致接口时，这可能会成为一个问题：

```js
interface God
{
  prayTo():void;
}
```

那么让我们插入一些适配器，作为我们拥有的类和我们想要的签名之间的桥梁：

```js
class OldGodsAdapter {
  constructor() {
    this._oldGods = new OldGods();
  }
  prayTo() {
    let sacrifice = new Sacrifice();
    this._oldGods.prayTo(sacrifice);
  }
}
Religion.OldGodsAdapter = OldGodsAdapter;
class DrownedGodAdapter {
  constructor() {
    this._drownedGod = new DrownedGod();
  }
  prayTo() {
    let sacrifice = new HumanSacrifice();
    this._drownedGod.prayTo(sacrifice);
  }
}
Religion.DrownedGodAdapter = DrownedGodAdapter;
class SevenGodsAdapter {
  constructor() {
    this.prayerPurposeProvider = new PrayerPurposeProvider();
    this._sevenGods = new SevenGods();
  }
  prayTo() {
    this._sevenGods.prayTo(this.prayerPurposeProvider.GetPurpose());
  }
}
Religion.SevenGodsAdapter = SevenGodsAdapter;
class PrayerPurposeProvider {
  GetPurpose() { }
  }
Religion.PrayerPurposeProvider = PrayerPurposeProvider;
```

这些适配器中的每一个都实现了我们想要的`God`接口，并抽象了处理三种不同接口的复杂性，每种接口对应一个神。

要使用桥梁模式，我们可以编写如下代码：

```js
let god1 = new Religion.SevenGodsAdapter();
let god2 = new Religion.DrownedGodAdapter();
let god3 = new Religion.OldGodsAdapter();

let gods = [god1, god2, god3];
for(let i =0; i<gods.length; i++){
  gods[i].praryTo();
}
```

这段代码使用桥梁为众神提供一致的接口，以便它们可以被视为平等的。

在这种情况下，我们只是包装了单个神并通过代理方法调用它们。适配器可以包装多个对象，这是另一个有用的地方可以使用适配器。如果需要编排一系列复杂的对象，那么适配器可以承担一些责任，为其他类提供更简单的接口。

你可以想象桥梁模式是多么有用。它可以与上一章介绍的工厂方法模式很好地结合使用。

这种模式在 JavaScript 中仍然非常有用。正如我在本节开始时提到的，它对于以一致的方式处理不同的 API 非常有用。我已经用它来交换不同的第三方组件，比如不同的图形库或电话系统集成点。如果您正在使用 JavaScript 在移动平台上构建应用程序，那么桥梁模式将成为您的好朋友，可以帮助您清晰地分离通用代码和特定于平台的代码。因为 JavaScript 中没有接口，所以桥梁模式比其他语言中的适配器更接近 JavaScript。实际上，它基本上是一样的。

桥梁还可以使测试变得更容易。我们可以实现一个虚拟桥梁，并使用它来确保对桥梁的调用是正确的。

# 组合

在上一章中，我提到我们希望避免对象之间的紧密耦合。继承是一种非常强的耦合形式，我建议使用组合代替。组合模式是这种情况的一个特例，其中组合被视为可与组件互换。让我们探讨一下组合模式的工作原理。

以下类图包含了构建复合组件的两种不同方式：

![Composite](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00016.jpg)

在第一个中，复合组件由各种组件的固定数量构建。第二个组件是由一个不确定长度的集合构建的。在这两种情况下，父组合中包含的组件可以与组合的类型相同。因此，一个组合可以包含其自身类型的实例。

组合模式的关键特征是组件与其子组件的可互换性。因此，如果我们有一个实现了`IComponent`的组合，那么组合的所有组件也将实现`IComponent`。这可能最好通过一个例子来说明。

## 例子

树结构在计算中非常有用。事实证明，分层树可以表示许多事物。树由一系列节点和边组成，是循环的。在二叉树中，每个节点包含左右子节点，直到我们到达称为叶子的终端节点。

虽然维斯特洛的生活很艰难，但也有机会享受宗教节日或婚礼等事物。在这些活动中，通常会大量享用美味食物。这些食物的食谱与您自己的食谱一样。像烤苹果这样的简单菜肴包含一系列成分：

+   烘焙苹果

+   蜂蜜

+   黄油

+   坚果

这些成分中的每一个都实现了一个我们称之为`IIngredient`的接口。更复杂的食谱包含更多的成分，但除此之外，更复杂的食谱可能包含复杂的成分，这些成分本身是由其他成分制成的。

在维斯特洛南部，一道受欢迎的菜肴是一种甜点，与我们所说的提拉米苏非常相似。这是一个复杂的食谱，其中包含以下成分：

+   奶油

+   蛋糕

+   打发奶油

+   咖啡

当然，奶油本身是由以下成分制成的：

+   牛奶

+   糖

+   鸡蛋

+   香草

奶油是一个复合成分，咖啡和蛋糕也是。

组合对象上的操作通常会通过代理传递给所有包含的对象。

## 实现

这段代码展示了一个简单的成分，即叶子节点：

```js
class SimpleIngredient {
  constructor(name, calories, ironContent, vitaminCContent) {
    this.name = name;
    this.calories = calories;
    this.ironContent = ironContent;
    this.vitaminCContent = vitaminCContent;
  }
  GetName() {
    return this.name;
  }
  GetCalories() {
    return this.calories;
  }
  GetIronContent() {
    return this.ironContent;
  }
  GetVitaminCContent() {
    return this.vitaminCContent;
  }
}
```

它可以与具有成分列表的复合成分互换使用：

```js
class CompoundIngredient {
  constructor(name) {
    this.name = name;
    this.ingredients = new Array();
  }
  AddIngredient(ingredient) {
    this.ingredients.push(ingredient);
  }
  GetName() {
    return this.name;
  }
  GetCalories() {
    let total = 0;
    for (let i = 0; i < this.ingredients.length; i++) {
      total += this.ingredients[i].GetCalories();
    }
    return total;
  }
  GetIronContent() {
    let total = 0;
    for (let i = 0; i < this.ingredients.length; i++) {
      total += this.ingredients[i].GetIronContent();
    }
    return total;
  }
  GetVitaminCContent() {     let total = 0;
    for (let i = 0; i < this.ingredients.length; i++) {
      total += this.ingredients[i].GetVitaminCContent();
    }
    return total;
  }
}
```

复合成分循环遍历其内部成分，并对每个成分执行相同的操作。当然，由于原型模型，无需定义接口。

要使用这种复合成分，我们可以这样做：

```js
let egg = new SimpleIngredient("Egg", 155, 6, 0);
let milk = new SimpleIngredient("Milk", 42, 0, 0);
let sugar = new SimpleIngredient("Sugar", 387, 0,0);
let rice = new SimpleIngredient("Rice", 370, 8, 0);

let ricePudding = new CompoundIngredient("Rice Pudding");
ricePudding.AddIngredient(egg);
ricePudding.AddIngredient(rice);
ricePudding.AddIngredient(milk);
ricePudding.AddIngredient(sugar);

console.log("A serving of rice pudding contains:");
console.log(ricePudding.GetCalories() + " calories");
```

当然，这只显示了模式的一部分。我们可以将米布丁用作更复杂食谱的成分：米布丁馅饼（在维斯特洛有一些奇怪的食物）。由于简单和复合版本的成分具有相同的接口，调用者不需要知道两种成分类型之间有任何区别。

组合是 JavaScript 代码中广泛使用的模式，用于处理 HTML 元素，因为它们是树结构。例如，jQuery 库提供了一个通用接口，如果您选择了单个元素或一组元素。当调用函数时，实际上是在所有子元素上调用，例如：

```js
$("a").hide()
```

这将隐藏页面上的所有链接，而不管调用`$("a")`实际找到多少元素。组合是 JavaScript 开发中非常有用的模式。

# 装饰者

装饰器模式用于包装和增强现有类。使用装饰器模式是对现有组件进行子类化的替代方法。子类化通常是一个编译时操作，是一种紧密耦合。这意味着一旦子类化完成，就无法在运行时进行更改。在存在许多可能的子类化可以组合的情况下，子类化的组合数量会激增。让我们看一个例子。

Westeros 骑士所穿的盔甲可以是非常可配置的。盔甲可以以多种不同的风格制作：鳞甲、板甲、锁子甲等等。除了盔甲的风格之外，还有各种不同的面罩、膝盖和肘部关节，当然还有颜色。由板甲和面罩组成的盔甲的行为与带有面罩的锁子甲是不同的。然而，你可以看到，存在大量可能的组合；明显太多的组合无法显式编码。

我们所做的是使用装饰器模式实现不同风格的盔甲。装饰器使用与适配器和桥接模式类似的理论，它包装另一个实例并通过代理调用。然而，装饰器模式通过将要包装的实例传递给它来在运行时执行重定向。通常，装饰器将作为一些方法的简单传递，对于其他方法，它将进行一些修改。这些修改可能仅限于在将调用传递给包装实例之前执行附加操作，也可能会改变传入的参数。装饰器模式的 UML 表示如下图所示：

![Decorator](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00017.jpg)

这允许对装饰器修改哪些方法进行非常精细的控制，哪些方法保持为简单的传递。让我们来看一下 JavaScript 中该模式的实现。

## 实施

在这段代码中，我们有一个基类`BasicArmor`，然后由`ChainMail`类进行装饰：

```js
class BasicArmor {
  CalculateDamageFromHit(hit) {
    return hit.Strength * .2;
  }
  GetArmorIntegrity() {
    return 1;
  }
}

class ChainMail {
  constructor(decoratedArmor) {
    this.decoratedArmor = decoratedArmor;
  }
  CalculateDamageFromHit(hit) {
    hit.Strength = hit.Strength * .8;
    return this.decoratedArmor.CalculateDamageFromHit(hit);
  }
  GetArmorIntegrity() {
    return .9 * this.decoratedArmor.GetArmorIntegrity();
  }
}
```

`ChainMail`装甲接受符合接口的装甲实例，例如：

```js
export interface IArmor{
  CalculateDamageFromHit(hit: Hit):number;
  GetArmorIntegrity():number;
}
```

该实例被包装并通过代理调用。`GetArmorIntegiry`方法修改了基础类的结果，而`CalculateDamageFromHit`修改了传递给装饰类的参数。这个`ChainMail`类本身可以被装饰多层装饰器，直到实际为每个方法调用调用了一长串方法。当然，这种行为对外部调用者来说是不可见的。

要使用这个装甲装饰器，请看下面的代码：

```js
let armor = new ChainMail(new Westeros.Armor.BasicArmor());
console.log(armor.CalculateDamageFromHit({Location: "head", Weapon: "Sock filled with pennies", Strength: 12}));
```

利用 JavaScript 重写类的单个方法来实现这种模式是很诱人的。事实上，在本节的早期草案中，我本打算建议这样做。然而，这样做在语法上很混乱，不是一种常见的做法。编程时最重要的事情之一是要记住代码必须是可维护的，不仅是对你自己，也是对其他人。复杂性会导致混乱，混乱会导致错误。

装饰器模式是一种对继承过于限制的情况非常有价值的模式。这些情况在 JavaScript 中仍然存在，因此该模式仍然有用。

# Façade

Façade 模式是适配器模式的一种特殊情况，它在一组类上提供了简化的接口。我在适配器模式的部分提到过这样的情景，但只在`SimpleShip`类的上下文中。这个想法可以扩展到提供一个抽象，围绕一组类或整个子系统。Façade 模式在 UML 形式上看起来像下面的图表：

![Façade](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00018.jpg)

## 实施

如果我们将之前的`SimpleShip`扩展为整个舰队，我们就有了一个创建外观的绝佳示例。如果操纵一艘单独的船很困难，那么指挥整个舰队将更加困难。需要大量微妙的操作，必须对单独的船只下达命令。除了单独的船只外，还必须有一位舰队上将，并且需要在船只之间协调以分发补给。所有这些都可以被抽象化。如果我们有一系列代表舰队方面的类，比如这些：

```js
let Ship = (function () {
  function Ship() {
  }
  Ship.prototype.TurnLeft = function () {
  };
  Ship.prototype.TurnRight = function () {
  };
  Ship.prototype.GoForward = function () {
  };
  return Ship;
})();
Transportation.Ship = Ship;

let Admiral = (function () {
  function Admiral() {
  }
  return Admiral;
})();
Transportation.Admiral = Admiral;

let SupplyCoordinator = (function () {
  function SupplyCoordinator() {
  }
  return SupplyCoordinator;
})();
Transportation.SupplyCoordinator = SupplyCoordinator;
```

那么我们可以构建一个外观，如下所示：

```js
let Fleet = (function () {
   function Fleet() {
  }
  Fleet.prototype.setDestination = function (destination) {
    **//pass commands to a series of ships, admirals and whoever else needs it** 

  };

  Fleet.prototype.resupply = function () {
  };

  Fleet.prototype.attack = function (destination) {
    **//attack a city** 

  };
  return Fleet;
})();
```

外观在处理 API 时非常有用。在细粒度 API 周围使用外观可以创建一个更简单的接口。API 的抽象级别可以提高，使其更符合应用程序的工作方式。例如，如果您正在与 Azure blob 存储 API 交互，您可以将抽象级别从处理单个文件提高到处理文件集。而不是编写以下内容：

```js
$.ajax({method: "PUT",
url: "https://settings.blob.core.windows.net/container/set1",
data: "setting data 1"});

$.ajax({method: "PUT",
url: "https://settings.blob.core.windows.net/container/set2",
data: "setting data 2"});

$.ajax({method: "PUT",
url: "https://settings.blob.core.windows.net/container/set3",
data: "setting data 3"});
```

可以编写一个外观，封装所有这些调用并提供一个接口，如下所示：

```js
public interface SettingSaver{
  Save(settings: Settings); //preceding code in this method
  Retrieve():Settings;
}
```

如您所见，外观在 JavaScript 中仍然很有用，并且应该是您工具箱中保留的模式。

# 蝇量级

拳击中有一个 49-52 公斤之间的轻量级级别，被称为蝇量级。这是最后一个建立的级别之一，我想它之所以被命名为蝇量级，是因为其中的拳击手很小，就像苍蝇一样。

蝇量级模式用于对象实例非常多，而这些实例之间只有轻微差异的情况。在这种情况下，大量通常指的是大约 10,000 个对象，而不是 50 个对象。然而，实例数量的截止点高度依赖于创建对象的成本。

在某些情况下，对象可能非常昂贵，系统在超载之前只需要少数对象。在这种情况下，引入蝇量级在较小数量上将是有益的。为每个对象维护一个完整的对象会消耗大量内存。似乎大部分内存也被浪费地消耗掉了，因为大多数实例的字段具有相同的值。蝇量级提供了一种通过仅跟踪与每个实例中的某个原型不同的值来压缩这些数据的方法。

JavaScript 的原型模型非常适合这种情况。我们可以简单地将最常见的值分配给原型，并在需要时覆盖各个实例。让我们看一个例子。

## 实施

再次回到维斯特洛（你是否为我选择了一个单一的主要问题领域感到高兴？），我们发现军队中充满了装备不足的战斗人员。在这些人中，从将军的角度来看，实际上没有太大的区别。当然，每个人都有自己的生活、抱负和梦想，但在将军眼中，他们都已经成为简单的战斗自动机。将军只关心士兵们打得多好，他们是否健康，是否吃饱。我们可以在这段代码中看到简单的字段集：

```js
let Soldier = (function () {
  function Soldier() {
    this.Health = 10;
    this.FightingAbility = 5;
    this.Hunger = 0;
  }
  return Soldier;
})();
```

当然，对于一支由 10,000 名士兵组成的军队，跟踪所有这些需要相当多的内存。让我们采用另一种方法并使用一个类：

```js
class Soldier {
  constructor() {
    this.Health = 10;
    this.FightingAbility = 5;
    this.Hunger = 0;
  }
}
```

使用这种方法，我们可以将对士兵健康的所有请求推迟到原型。设置值也很容易：

```js
let soldier1 = new Soldier();
let soldier2 = new Soldier();
console.log(soldier1.Health); //10
soldier1.Health = 7;
console.log(soldier1.Health); //7
console.log(soldier2.Health); //10
delete soldier1.Health;
console.log(soldier1.Health); //10
```

您会注意到我们调用删除来删除属性覆盖，并将值返回到父值。

# 代理

本章介绍的最后一个模式是代理。在前一节中，我提到创建对象是昂贵的，我们希望避免创建过多的对象。代理模式提供了一种控制昂贵对象的创建和使用的方法。代理模式的 UML 如下图所示：

![代理](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00019.jpg)

正如你所看到的，代理模式反映了实际实例的接口。它被替换为所有客户端中的实例，并且通常包装类的私有实例。代理模式可以在许多地方发挥作用：

+   昂贵对象的延迟实例化

+   保护秘密数据

+   远程方法调用的存根

+   在方法调用之前或之后插入额外的操作

通常一个对象实例化是昂贵的，我们不希望在实际使用之前就创建实例。在这种情况下，代理可以检查它的内部实例，并且如果尚未初始化，则在传递方法调用之前创建它。这被称为延迟实例化。

如果一个类在设计时没有考虑到安全性，但现在需要一些安全性，可以通过使用代理来提供。代理将检查调用，并且只有在安全检查通过的情况下才会传递方法调用。

代理可以简单地提供一个接口，用于调用其他地方调用的方法。事实上，这正是许多网络套接字库的功能，将调用代理回到 Web 服务器。

最后，可能有些情况下，将一些功能插入到方法调用中是有用的。这可能是参数日志记录，参数验证，结果更改，或者其他任何事情。

## 实现

让我们看一个需要方法拦截的 Westeros 示例。通常情况下，液体的计量单位在这片土地的一边和另一边差异很大。在北方，人们可能会买一品脱啤酒，而在南方，人们会用龙来购买。这导致了很多混乱和代码重复，但可以通过包装关心计量的类来解决。

例如，这段代码是用于估算运输液体所需的桶数的桶计算器：

```js
class BarrelCalculator {
  calculateNumberNeeded(volume) {
    return Math.ceil(volume / 157);
  }
}
```

尽管它没有很好的文档记录，但这个版本以品脱作为体积参数。创建一个代理来处理转换：

```js
class DragonBarrelCalculator {
  calculateNumberNeeded(volume) {
    if (this._barrelCalculator == null)
      this._barrelCalculator = new BarrelCalculator();
    return this._barrelCalculator.calculateNumberNeeded(volume * .77);
  }
}
```

同样，我们可能为基于品脱的桶计算器创建另一个代理：

```js
class PintBarrelCalculator {
  calculateNumberNeeded(volume) {
    if (this._barrelCalculator == null)
      this._barrelCalculator = new BarrelCalculator();
    return this._barrelCalculator.calculateNumberNeeded(volume * 1.2);
  }
}
```

这个代理类为我们做了单位转换，并帮助减轻了一些关于单位的混乱。一些语言，比如 F#，支持单位的概念。实际上，它是一种类型系统，覆盖在简单的数据类型上，如整数，防止程序员犯错，比如将表示品脱的数字加到表示升的数字上。在 JavaScript 中，没有这样的能力。然而，使用 JS-Quantities（[`gentooboontoo.github.io/js-quantities/`](http://gentooboontoo.github.io/js-quantities/)）这样的库是一个选择。如果你看一下，你会发现语法非常痛苦。这是因为 JavaScript 不允许操作符重载。看到像将一个空数组添加到另一个空数组一样奇怪的事情（结果是一个空字符串），也许我们可以感谢 JavaScript 不支持操作符重载。

如果我们想要防止在有品脱而认为有龙时意外使用错误类型的计算器，那么我们可以停止使用原始类型，并为数量使用一种类型，一种类似于贫穷人的计量单位：

```js
class PintUnit {
  constructor(unit, quantity) {
    this.quanity = quantity;
  }
}
```

这可以作为代理中的一个保护使用：

```js
class PintBarrelCalculator {
  calculateNumberNeeded(volume) {
    if(PintUnit.prototype == Object.getPrototypeOf(volume))
      //throw some sort of error or compensate
    if (this._barrelCalculator == null)
      this._barrelCalculator = new BarrelCalculator();
    return this._barrelCalculator.calculateNumberNeeded(volume * 1.2);
  }
}
```

正如你所看到的，我们最终得到了基本上与 JS-Quantities 相同的东西，但是以更 ES6 的形式。

代理模式在 JavaScript 中绝对是一个有用的模式。我已经提到它在生成存根时被 Web 套接字库使用，但它在无数其他位置也很有用。

# 提示和技巧

本章介绍的许多模式提供了抽象功能和塑造接口的方法。请记住，每一层抽象都会引入成本。函数调用会变慢，但对于需要理解您的代码的人来说，这也更加令人困惑。工具可以帮助一点，但跟踪一个函数调用穿过九层抽象从来都不是一件有趣的事情。

同时要小心在外观模式中做得太多。很容易将外观转化为一个完全成熟的管理类，这很容易变成一个负责协调和执行一切的上帝对象。

# 总结

在本章中，我们已经看了一些用于构造对象之间交互的模式。它们中的一些模式相互之间相当相似，但它们在 JavaScript 中都很有用，尽管桥接模式实际上被简化为适配器。在下一章中，我们将通过查看行为模式来完成对原始 GoF 模式的考察。

