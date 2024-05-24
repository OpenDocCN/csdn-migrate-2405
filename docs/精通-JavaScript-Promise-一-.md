# 精通 JavaScript Promise（一）

> 原文：[`zh.annas-archive.org/md5/9D521BCA2BC828904B069DC1B0B0683B`](https://zh.annas-archive.org/md5/9D521BCA2BC828904B069DC1B0B0683B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

在这本书中，我们将探讨 JavaScript 中承诺的概念和实现。这本书有一个不断发展的上下文，将引导你从初学者水平达到承诺的专家水平。本书的每一章都会为你提供一个实现特定目标的概要，帮助你实现并量化你在每一章中吸收的知识量。

所有章节的整个堆栈都是设计成这样，以至于当你阅读它时，书会随着你的阅读而发展。本书的每一章都分为两部分：一部分是概念构建部分，另一部分是实验部分，你将能够尝试概念的片段，有时是代码，有时是最佳实践，有时是图片。

前四章基本上是理论知识，为你提供了 JavaScript 和承诺的坚实基础。所以，如果你是一个新手，对 JavaScript 或承诺一无所知，这些章节你会学到很多。本书的其他章节更侧重于技术，你将了解承诺在 WinRT，Angular.js，jQuery 和 Node.js 中的实现。所以，如果你是一个专业人士，已经有了关于承诺的一些想法，你可以直接跳到第五章，*WinRT 中的承诺*，但我建议你阅读所有章节，以便更好地理解本书。

我们将首先介绍 JavaScript 以及它从 90 年代末到 21 世纪初的起伏。我们将关注异步编程是什么以及 JavaScript 是如何使用它的。接下来，我将介绍承诺及其影响以及它是如何实现的。为了使本书有趣并为您提供更多知识，我将向您展示承诺如何在 Java 这种最成熟的面向对象编程语言中占据一席之地。这个附加内容将作为一个旁路，并以更有效的方式阐明概念。

随后，本书的流程将引导你了解一些最常用的 JavaScript 库中承诺的实现。我们将看到一个示例代码，了解这些库的工作机制。最后，我们将在最后一章中总结本书，向你展示 JavaScript 接下来会发生什么，为什么在过去几年中它获得了如此多的关注，以及 JavaScript 可能的未来。

# 本书内容涵盖

第一章，*Promises.js*，涵盖了 JavaScript 的历史以及它是如何成为现代应用程序开发中领先的技术的。我们将讨论为什么在 90 年代初需要 JavaScript 以及这种语言在其存在期间是如何经历起伏的。

第二章，*JavaScript 异步模型*，解释了编程模型是什么以及它们如何在不同的语言中实现，从简单的编程模型到同步模型到异步模型。我们还将看到任务是如何在内存中组织的，以及它们将如何根据它们的轮次和优先级进行服务，以及编程模型是如何决定要服务哪个任务的。

第三章，*Promise 范式*，涵盖了 promise 的范式及其背后的概念。我们将学习 promise 的概念知识、deferred、常见的 promise 序列以及 promise 如何在解耦业务逻辑和应用程序逻辑中提供帮助。我们还将学习 promise 与事件发射器之间的关系以及它们之间的关系的概念。

第四章，*实现 Promise*，讨论了为什么要实现 promise 以及为什么选择 Java 作为本章的核心主题。Java 比任何其他编程语言都有更丰富的功能，并且它还有更好的异步行为机制。本章是我们开始掌握 promise 的旅程的起点。

第五章，*WinRT 中的 Promise*，解释了如何在 WinRT 中实现 promise。我们将看到 promise 在 Windows 平台上的演变以及它如何为不同的 Windows-based 设备做出贡献。

第六章，*Node.js 中的 Promise*，介绍了 Node.js 是什么，这个最令人惊叹的库是如何演变而来的，是谁创建的，以及它如何帮助我们创建实时 web 应用。我们将看到 Q，这是向 Node.js 提供 promise 的最佳方式。我们将了解如何使用 Q，然后我们将看到使用 Q 与 Node.js 结合的不同方法。

第七章，*Angular.js 中的 Promise*，解释了 promise 将在 Angular.js 中如何实现，它是如何演变的，以及 promise 将如何帮助实现为实时 web 应用程序组成的应用程序。我们还将看到 Q 库的功能以及使用代码实现的 Angular.js 中的 promise，并学习如何在下一个应用程序中使用它们。

第八章，*jQuery 中的 Promise*，讨论了 jQuery 是如何开始成形的，以及它是如何成为现代 web 开发的基本元素的。我们将学习如何构建基本的 jQuery 文档以及如何调用嵌入到 HTML 文件中的函数。我们将了解为什么我们开始在 jQuery 中使用 deferred 和 promise，以及它们如何帮助我们创建基于 web 平台和便携设备的尖端应用程序。

第九章，*JavaScript – 未来已来*，介绍了 JavaScript 是如何改变游戏规则的，以及它有着光明的前途。我们还将探讨为什么 JavaScript 具有很大的倾向性和可采用性，这将引导它在计算机科学的几乎每个领域达到下一个使用水平。

# 本书所需材料

如果您是希望了解更多关于 JavaScript 的有趣事实以使您的生活更轻松的软件工程师，这本书适合您。简单而吸引人的语言，配以叙述和代码示例，使这本书易于理解和应用其实践。本书从 JavaScript 承诺的介绍开始，以及它是如何随时间演变的。然后，您将学习 JavaScript 异步模型以及 JavaScript 如何处理异步编程。接下来，您将了解承诺范式及其优势。最后，本书将向您展示如何在 WinRT、jQuery 和 Node.js 等平台上实现承诺，这些平台在项目开发中使用。

为了更好地掌握本书内容，您应该了解基本的编程概念、JavaScript 的基本语法以及良好的 HTML 理解。

# 本书适合对象

本书适用于所有希望在其下一个项目中应用承诺范式并从中获得最佳结果的软件/网页工程师。这本书包含了 JavaScript 中承诺的所有基本和高级概念。这本书也可以作为已经在项目中使用承诺并希望改进当前知识的工程师的参考。

这本书是前端工程师的宝贵资源，同时也为希望确保代码在项目中无缝协作的后端工程师提供了学习指南。

# 约定

在这本书中，你会发现有许多文本样式，用以区分不同类型的信息。以下是这些样式的一些示例及其含义解释。

文本中的代码词汇、数据库表名、文件夹名、文件名、文件扩展名、路径名、假网址、用户输入和 Twitter 账号等，将按如下格式展示：“`click`函数将调用（或执行）我们传递给它的回调函数。”

一段代码如下所示：

```js
Q.fcall(imException)
.then(
    // first handler-fulfill
    function() { },

);
```

任何命令行输入或输出都将按如下格式书写：

```js
D:\> node –v
D:\> NPM  –v

```

**新术语**和**重要词汇**以粗体显示。您在屏幕上看到的词汇，例如在菜单或对话框中，将以如下格式出现在文本中：“它应该变成绿色并显示**成功**消息。”

### 注意

警告或重要说明以如下框格式出现。

### 提示

技巧和建议将如此展示。

# 读者反馈

读者反馈对我们来说总是受欢迎的。让我们知道您对这本书的看法——您喜欢或不喜欢的地方。读者反馈对我们很重要，因为它帮助我们开发出您会真正从中获益的标题。

要给我们一般性反馈，只需电子邮件`<feedback@packtpub.com>`，并在消息主题中提及书籍的标题。

如果您在某个话题上有专业知识，并且有兴趣撰写或贡献一本书，请查看我们的作者指南：[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然您已经成为 Packt 书籍的骄傲所有者，我们有很多事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的账户上下载所有您购买的 Packt Publishing 书籍的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接通过电子邮件发送给您。

## 错误

虽然我们已经尽一切努力确保我们内容的准确性，但错误确实会发生。如果您在我们的某本书中发现错误——可能是文本或代码中的错误——我们将非常感谢您能向我们报告。这样做，您可以节省其他读者的挫折感，并帮助我们提高本书后续版本的质量。如果您发现任何错误，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**错误提交****表单**链接，并输入您错误的详细信息。一旦您的错误得到验证，您的提交将被接受，错误将被上传到我们的网站，或添加到该标题的错误部分现有的错误列表中。

要查看之前提交的错误，请前往[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，在搜索框中输入书籍名称。所需信息将在**错误**部分下出现。

## 盗版

互联网上版权材料的盗版是一个持续存在的问题，涵盖所有媒体。在 Packt，我们非常重视我们版权和许可的保护。如果您在互联网上以任何形式发现我们作品的非法副本，请立即提供给我们位置地址或网站名称，以便我们可以寻求补救措施。

请通过`<copyright@packtpub.com>`联系我们，附上疑似盗版材料的链接。

我们感谢您在保护我们的作者和我们提供有价值内容的能力方面所提供的帮助。

## 问题

如果您在本书的任何方面遇到问题，您可以联系`<questions@packtpub.com>`，我们会尽力解决问题。


# 第一章： Promises.js

在今天的世界里，计算机编程语言正在变得更加先进，使用技术的方法也在发生变化。这是由于技术随着商业和他们需求的变化而不断涌现。电子商务的广泛扩展导致大学、研究人员和工业界投资于生成最新技术和工具，从而导致了许多新计算机语言的产生。

然而，JavaScript 并非如此。它相对较新。现代编程景观至少三次使用并抛弃了它，现在它被广泛接受为开发现代、可扩展和实时网络应用的工具。

在 90 年代中期，点 com 时代诞生了，正是在这个时候，公司想要主导一个名为网络空间的新市场。尽管这是一个虚拟的地方，没有实体存在，但争夺主导地位的战争达到了顶峰。Netscape 通信公司想要自己的轻量级解释语言，以补充 Java，并吸引非专业程序员。这项任务交给了布兰登·艾 ich，他开发了名为"Mocha"的 JavaScript 的第一版。正式地，当 1995 年 9 月在 Netscape 的浏览器中以 2.0 测试版首次发布时，它被称为 LiveScript。

然而，当版本 2.0 B3 推出时，名称改为了 JavaScript。自 1995 年以来，JavaScript 经历了许多起伏。它的被采用、被拒绝和再次被采用的故事。在其推出后不久，JavaScript 在整个行业中获得了非常流行的响应。每个主要公司都为其增长做出了贡献，并对其进行微调以满足自己的需求。

# JavaScript 的衰落与崛起

网景浏览器见证了 90 年代末至 2000 年初 JavaScript 的衰落。网页开发的面孔正在成熟，但很少有人还对投资 JavaScript 感兴趣。

是 Mozilla 基金会发布了第一个开源浏览器 Firefox，自 2002 年初至 2003 年初以来，该基础是前 Netscape 浏览器的继承者。他们在自己的产品中再次使用了 JavaScript。2004 年，谷歌推出了**异步 JavaScript 和 XML** (**AJAX**)。这导致了许多技术的基础，并通过最小化服务器调用，使黑白的前端和服务器之间的通信变得容易。

# 谷歌对 JavaScript 的贡献

谷歌在 JavaScript 的演变、发展和应用方面的贡献超过了任何其他组织。正是谷歌在其旗舰浏览器 Chrome 中引入了 V8 引擎。V8 是浏览器的核心引擎，由于 smart usage of JavaScript，浏览器更快、更健壮，并适应于网页和安卓设备。

2009 年，基于与 Chrome 相同的 V8 引擎的 Node.js 问世。这是 JavaScript 的服务器端，但比 90 年代末 Netscape 引入的要好得多和先进。Node.js 的全局理念是开发非阻塞的**输入/输出**（**I/O**），并且用几行代码，服务器可以在给定的时间段内服务于多达 20K 的客户端。

在 Node.js 之后，一个名为 MEAN 栈的开发栈被引入，它是由 MongoDB、Express.js、Angular.js 和 Node.js 的首字母缩写而成；其中 MongoDB 是文档型的，NoSQL 是基于 JavaScript 的数据库，Express.js 用于表示层，Angular.js 用于应用程序的前端开发，Node.js 作为运行整个节目的服务器。

# Promises.js 是做什么的？

那些了解服务器端脚本在 I/O 事件中如何执行的人知道，从驱动器读取或写入数据是阻塞性的，也就是说，在其执行期间，服务器端语言不能执行其他操作，即使是客户端。好吧，有了 Promises.js，这种情况就不再存在了。Promises.js 利用非阻塞策略进行 I/O 操作，所以使用你的网络应用程序的客户端可以自由地执行任何他们想执行的其他任务，而无需等待数据读/写操作完成。

# 承诺是什么？

当一个操作的完成返回一个最终的值时，它代表一个**承诺**。如果我们把承诺比作人类之间的约定，它将帮助我们理解计算机编程中特别是在 JavaScript 角度的承诺概念。每个承诺都是两个或更多方之间交付一些值给另一方的约定。这个值可以是具体的或无形的，但承诺必须有所回报。直到承诺得到满足，它才处于未满足的状态。然而，当所说的承诺已经完成，承诺就被认为是得到了满足。如果承诺没有如预期那样交付，那么这个承诺就被认为是失败的。

那么，什么是承诺？根据官方定义：

> 承诺是一个具有 then 方法的对象或函数，其行为符合此规范，代表异步操作的最终结果。

这个定义的来源是[`www.slideshare.net/wookieb/callbacks-promises-generators-asynchronous-javascript`](http://www.slideshare.net/wookieb/callbacks-promises-generators-asynchronous-javascript)的第 21 张幻灯片。

# 我们为什么需要在 JS 中使用承诺？

Promises.js 是一个 JavaScript 库，它承诺进行异步 I/O 操作，如文件读写。每当涉及到 I/O 的所有操作的回调方法，它们都必须是异步的。这个额外的回调参数使我们的输入和返回值是什么的想法变得混乱。它从不与控制流原语一起工作。它也不处理由回调方法抛出的错误。

因此，我们需要处理回调方法抛出的错误，但也要小心不要处理回调方法抛出的错误。到这一步，我们的代码将变成一个错误处理的混乱局面。

尽管处理错误代码如此混乱，我们仍然面临着一个额外回调参数悬而未决的问题。Promises 通过自然地处理错误，不使用回调参数来编写更干净的代码来帮助你。

# 软件先决条件

在开始第二章，*JavaScript 异步模型*之前，你必须掌握一组先决概念，这将使你更好地理解在哪里使用 Promises.js，以及它如何在你的近期或即将到来的项目中节省时间和精力。下一节将详细说明这些概念是什么，以及我们如何将它们作为我们理解承诺的基础。

本书的先决条件是你对过程编程有深入的了解，并且必须掌握基本的 JavaScript 知识。由于本书旨在深入理解概念（promise）及其在不同技术中的使用，因此你还需要对 HTML 有非常深入的了解，以及如何嵌入你的代码。

对基本编程的理解将帮助你一旦完成任何章节/部分后，就能在样例代码的帮助下开始实验。在这本书中，我试图使每一个部分都自解释，每一个代码示例都是一个独立的脚本/程序，尽最大可能地展示。然而，在需要的地方，我们添加了一段代码或算法，以更清晰地表达我们的观点。

## 开始之前你需要了解的环境

使用本书中的代码，你不需要任何额外的软件/集成开发环境（IDE）来开始。要尝试本书中提供的代码，你只需要使用免费的软件/IDE，如 Notepad++或任何其他首选的开源 GPL 或 GNU 产品。

另外，为了查看你的代码结果，你需要一个像谷歌的 Chrome 或 Mozilla 的 Firefox 这样的网络浏览器。对于与微软技术相关的一些示例，你需要 Internet Explorer 9 或更高版本。

# 未来（Future）、承诺（promise）和延迟（delay）

未来（Future）、承诺（promise）和延迟（delay）描述了一个作为代理来获取最初未知的值的代理对象，其值尚未计算完成。它们通常被称作某些并发编程语言中用于同步的构造。

丹尼尔·P·弗里德曼和戴维·怀斯在 1975 年提出了“承诺”这个术语。彼得·希巴德称其为“最终”。承诺这个术语是由利斯科夫和希拉提出的，尽管他们用“call-stream”这个名字来指代流水线机制。承诺这个术语指的是在任何所述操作完成时，将获得一个最终值。同样，值也可以被视为最终值，因为它只有在任何事件发生时才会产生。因此，这两个术语同时指的是同一个事实。

未来（Future）、承诺（Promise）和延迟（Delay）这些术语经常可以互换使用。实现这些术语有一些核心的区别。未来被认为是变量的只读占位符视图，而承诺是一个可写单分配容器，设置未来的值。

在许多情况下，未来承诺是一起创建的。简单来说，未来是一个值，承诺是一个函数，用来设置这个值。未来重新运行异步函数（承诺）的值；未来设置值也称为**解析**、**满足**或**绑定**。

## 承诺流水线

使用未来（Future）可以显著降低分布式系统中的延迟；例如，在编程语言 E 和 Joule 中，承诺（Promise）使得承诺流水线（Promise pipelining）成为可能，而在 Argus 语言中，这被称为**call-stream**。

这里需要注意的一点是，承诺流水线应该与支持并行消息传递但不支持流水线的系统的并行异步消息传递区分开来。它还应该与演员系统中的流水线消息处理区分开来，在演员系统中的流水线消息处理中，一个演员可以在完成当前消息的处理之前指定并开始执行下一个消息的行为。

## 只读视图

只读视图在解析时允许读取其值，但不允许您解析它，从而使获得只读视图的未来成为可能。

只支持只读视图与最小权限原则保持一致。

只读视图允许您将值设置为仅限于需要设置它的主体。异步消息（带有结果）的发件人收到结果的只读承诺，而消息的目标收到解决器。

# 承诺的状态

承诺基于三种状态。每种状态都有其重要性，可以根据需要驱动一定级别的结果。这可以帮助程序员根据需要进行选择。承诺的这三种状态如下：

+   **挂起**：这是承诺的初始状态。

+   **满足**：这代表一个成功操作的承诺状态。

+   **拒绝**：这代表一个失败操作的承诺状态。

一旦承诺被满足或拒绝，它就是不可变的（也就是说，它永远不能再改变）。

参照前面讨论的概念，现在很清楚承诺是什么以及如何使用它及其全部潜力。

# 我们如何在本书中保持 Promises.js 的适用性？

本书将涵盖 Promises.js 与每种实现承诺概念的主要技术的使用。这本书被仔细地分成章节，以介绍、讨论和解释在该特定技术中使用承诺的方法。每个章节都有其独立的代码示例，以便更好地理解 Promises.js 的最佳使用和其结果。

本书的例子将假设操作系统的选择完全由您自主决定。这可能因读者而异，取决于他的/她的许可证。

所有代码都清晰地打印出来，带有说明和注释，以便更好地理解。此外，本书还提供了一份电子副本，列出了按其相应章节/部分分类的每一行代码。

# 浏览器兼容性

Promises 支持扩展到许多现代浏览器，但并非全部。有关它支持的浏览器的手册参考，请参阅桌面和移动屏幕分辨率：

+   桌面兼容性：

    | 特性 | Chrome | Firefox | Internet Explorer | Opera | Safari |
    | --- | --- | --- | --- | --- | --- |
    | 基本支持 | 36 | 31 | 直到 IE 11 不支持。在 Edge 中添加 | 27 | 8 |

+   移动兼容性：

    | 特性 | 安卓 | Firefox 移动版（Gecko） | IE 移动版 | Opera 移动版 | Safari 移动版 | 安卓版 Chrome |
    | --- | --- | --- | --- | --- | --- | --- |
    | 基本支持 | 4.4.4 | 31 | Edge | 不支持 | 不支持 | 42 |

# 总结

在本章中，我们学习了 JavaScript 的起源以及它是如何发展成为现代应用开发中的领先技术的。我们讨论了为什么 90 年代初需要 JavaScript，以及这种语言在其存在期间是如何经历起伏的。

我们还将看到科技公司的投资如何有助于创建、开发和演变 JavaScript，使其成为动态和快速增长的网络、移动和实时应用市场的关键参与者。

承诺概念的适应将使 JavaScript 变得更强有力，并将帮助开发者和工程师以高效的方式编写更好的代码。

在下一章中，我们将了解异步模型以及它是如何与 JavaScript 更好地配合的。这将帮助我们理解如何采用并在各种语言中实现 Promises.js。


# 第二章：JavaScript 异步模型

在本章中，我们将探讨异步编程背后的模型，为什么需要它，以及如何在 JavaScript 中实现它。

我们还将学习编程模型及其重要性，从简单的编程模型到同步模型，再到异步模型。由于我们主要关注的是 JavaScript，它采用了一种异步编程模型，因此我们将比其他模型更详细地讨论它。

让我们从模型及其重要性开始。

模型基本上是在编程语言的编译器/解释器中设计和管理逻辑的模板，以便软件工程师可以在编写软件时使用这些逻辑。我们使用的每种编程语言都是基于某种编程模型设计的。由于软件工程师被要求解决一个特定问题或自动化任何特定服务，他们根据需要采用编程语言。

没有固定的规则将特定的语言分配给创建产品。工程师根据需要采用任何语言。

# 编程模型

理想情况下，我们将关注三种主要的编程模型，如下所述：

+   首先是单线程同步模型

+   第二种是多线程模型

+   第三种是异步编程模型

由于 JavaScript 采用异步模型，我们将更详细地讨论它。然而，让我们先解释一下这些编程模型是什么，以及它们如何为最终用户提供便利。

## 单线程同步模型

单线程同步模型是一种简单的编程模型或单线程同步编程模型，其中一个任务接着另一个任务。如果有任务队列，首先优先考虑第一个任务，依此类推。如下所示，这是完成事情的最简单方式：

![单线程同步模型](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_02_01.jpg)

单线程同步编程模型是`Queue`数据结构的一个最佳示例，遵循**先进先出**（**FIFO**）规则。该模型假设如果当前正在执行**任务 2**，那么必须在**任务 1**顺利完成且所有输出如预测或所需后才能进行。这种编程模型仍然支持为简单设备编写简单的程序。

## 多线程同步模型

与单线程编程不同，在多线程编程中，每个任务都在一个单独的线程中执行，因此多个任务需要多个线程。线程由操作系统管理，可能在具有多个进程或多个核心的系统上并发运行。

似乎很简单的多线程是由操作系统或在其上执行的程序管理的；它是一个复杂且耗时的工作，需要线程之间进行多级通信，以无死锁和错误地完成任务，正如下面的图表所示：

![多线程同步模型](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_02_02.jpg)

一些程序使用多个进程而不是多个线程来实现并行，尽管编程细节不同。

## 异步编程模型

在异步编程模型中，任务在单一控制线程中相互交织。

这个单一的线程可能包含多个嵌入线程，每个线程可能包含几个连续链接的任务。与线程情况相比，这个模型更简单，因为程序员总是知道在内存中给定时间槽执行任务的优先级。

考虑一个任务，在这个任务中，操作系统（或操作系统中的应用程序）使用某种场景来决定分配给一个任务多少时间，然后再给其他任务同样的机会。操作系统从一项任务中夺取控制并传递给另一项任务的行为称为**抢占**。

### 注意

多线程同步模型也被称为**抢占式多任务处理**。当它是异步的时候，它被称为**协作式多任务处理**。

![异步编程模型](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_02_03.jpg)

在线程系统中，优先挂起一个线程并把另一个线程放到执行上的优先权不在程序员手中；这是基础程序控制的。通常，它是由操作系统本身控制的，但异步系统并非如此。

在异步系统中，线程的执行和挂起控制完全由程序员决定，线程除非被明确要求改变状态，否则不会改变其状态。

### 具有异步编程模型的密度

具有异步编程模型的所有特性，它也有其需要处理的密度。

由于执行控制和优先级分配掌握在程序员手中，他/她必须将每个任务组织成一系列更小的立即执行的步骤。如果一个任务使用了另一个任务的输出，那么依赖任务必须被设计成能够将其输入作为一系列不连续的位来接受；程序员就是这样在自己的任务中编织并设定优先级的。异步系统的灵魂在于，当任务被迫等待或被阻塞时，它能够远远超越同步系统。

### 为什么我们需要阻塞任务？

一个任务被强制阻塞的更常见原因是因为它正在等待执行 I/O 或与外部设备进行数据传输。普通的 CPU 处理数据传输的速度比任何网络链接都要快，这使得在 I/O 上花费了大量时间的同步程序被阻塞。因此，这样的程序也被称为**阻塞程序**。

异步模型的整个理念是避免浪费 CPU 时间并避免阻塞数据。当一个异步程序遇到一个在同步程序中通常会被阻塞的任务时，它将执行其他仍能取得进展的任务。因此，异步程序也被称为**非阻塞程序**。

Since the asynchronous program spends less time waiting and roughly giving an equal amount of time to every task, it supersedes synchronous programs.

与同步模型相比，异步模型在以下场景中表现最佳：

+   There are a large number of tasks, so it's likely that there is always at least one task that can make progress

+   The tasks perform lots of I/O, causing a synchronous program to waste lots of time blocking, when other tasks are running

+   The tasks are largely independent from one another, so there is little need for intertask communication (and thus for one task to wait for another)

keeping all the preceding points in mind, it will almost perfectly highlight a typical busy network, say a web server in a client-server environment, where each task represents a client requesting some information from the server. In such cases, an asynchronous model will not only increase the overall response time, but also add value to the performance by serving more clients (requests) at a time.

### Why not use some more threads?

At this point, you may ask why not add another thread by not relying on a single thread. Well, the answer is quite simple. The more the threads, the more memory it will consume, which in turn will create low performance and a higher turnaround time. Using more threads doesn't only come with a cost of memory, but also with effects on performance. With each thread, a certain overhead is linked to maintain the state of that particular thread, but multiple threads will be used when there is an absolute need of them, not for each and every other thing.

# Learning the JavaScript asynchronous model

keeping this knowledge in mind, if we see what the JavaScript asynchronous model is, we can now clearly relate to an asynchronous model in JavaScript and understand how it's implemented.

In non-web languages, most of the code we write is synchronous, that is, blocking. JavaScript does its stuff in a different way.

JavaScript 是一种单线程语言。我们已经知道单线程的真正含义，为了简单起见——同一个脚本的两部分不能同时运行。在浏览器中，JavaScript 与许多其他进程共享一个线程。这些“内联进程”可能因浏览器而异，但通常，**JavaScript**（**JS**）与绘制、更新样式和处理用户操作（这些进程中的一个活动会延迟其他进程）处于同一个队列中。

如图片所示，每当在浏览器中执行异步（非阻塞）脚本时，它会按照执行模式从上到下进行。从页面加载开始，脚本会进入文档对象，在那里创建 JavaScript 对象。然后脚本进入解析阶段，在这个阶段所有的节点和 HTML 标签都被添加。解析完成后，整个脚本作为异步（非阻塞）脚本加载到内存中。

![学习 JavaScript 异步模型](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_02_04.jpg)

## 如何用 JavaScript 实现异步模型

JavaScript 使用一个循环事件，其周期被称为“滴答声”（类似于时钟），因为它在 CPU 规定的 时间片段内运行。解释器负责检查每个滴答声是否需要执行异步回调。所有其他的同步操作都在同一个滴答声内进行。传递的时间值没有保证——无法知道下一次滴答声将会在什么时候，所以我们通常说回调会“尽快”运行；尽管如此，一些调用甚至可能会被放弃。

在 JavaScript 中，实现异步模型的核心方式有四种。这四种方法不仅有助于提高程序的性能，还有助于代码的更容易维护。这四种方法如下：

+   回调函数

+   事件监听器

+   发布/订阅模式

+   承诺对象

## JavaScript 中的回调

在 JavaScript 中，函数是一等公民，这意味着它们可以被当作对象对待，由于它们本身就是对象，所以它们可以做普通对象能做的一切，比如这些：

+   存储在变量中

+   作为其他函数的参数传递

+   在函数内创建

+   在处理了一些数据机制的负载后作为函数的返回值

回调函数，也称为高阶函数，是一个被传递到另一个函数（让我们称这个其他函数为`otherFunction`）作为参数的函数，回调函数在`otherFunction`内部被调用（执行）。

本质上，回调函数是一种模式（一个解决常见问题的既定方案），因此使用回调函数也称为回调模式。因为函数是一等对象，所以我们可以在 JavaScript 中使用回调函数。

由于函数是一等对象，我们可以在 JavaScript 中使用回调函数，但回调函数是什么呢？回调函数背后的想法来源于函数式编程，它使用函数作为参数来实现回调函数，就像把普通变量作为参数传递给函数一样简单。

一个常见的回调函数用法可以在以下代码行中看到：

```js
$("#btn_1).click().click.function() {
alert ("Button one was clicked");
});
```

以下代码解释了自身：

+   我们把一个函数作为`click`函数的参数

+   `click`函数将会调用（或执行）我们传递给它的回调函数

这是 JavaScript 中回调函数的典型用法，实际上，它在 jQuery 中得到了广泛应用。我们将在第八章*jQuery 中的 Promise*中更详细地研究 jQuery 中的 promise。

### 阻塞函数

当我们讨论 JavaScript 中的阻塞函数是什么以及应该如何实现它时，我们中的许多人实际上并不清楚地理解我们所说的 JavaScript 中的阻塞函数是什么意思。

作为人类，我们的头脑被设计成可以同时做很多事情，比如在读这本书的时候，你意识到了你周围的环境，你可以在思考和打字的同时进行，你可以在开车的时候和人交谈。

这些例子是为多线程模型准备的，但在我们的人体中有没有任何阻塞函数呢？答案是有的。我们有一个阻塞函数，正因为如此，我们的头脑和体内都有其他活动；它会在纳米秒级的短暂瞬间停止。这个阻塞函数叫做打喷嚏。当任何人类打喷嚏时，与头脑和身体相关的所有函数都会在纳米秒级的短暂瞬间被阻塞。人们很少注意到这一点。JavaScript 的阻塞函数也是如此。

# JavaScript 中的回调函数机制

这里的问题是，回调函数究竟是如何工作的？

众所周知，在 JS 中函数就像是一等对象，我们可以像变量一样传递它们，将它们作为函数返回，并在其他函数中使用它们。

当我们把一个回调函数作为参数传递给另一个函数时，我们只传递了函数定义。我们并没有在参数中执行函数。我们也没有用执行括号`()`来传递函数，因为我们在执行函数时才会这样做。

由于包含函数在其参数中有回调函数作为函数定义，它可以在任何时候执行回调。

需要注意的是，回调函数并不会立即执行。它是“回调”的，仍然可以通过参数对象在包含函数中稍后访问。

## 实现回调函数的基本规则

在实现回调函数时，有一些基本规则你需要记住。

回调通常很简单，但如果你正在编写自己的回调函数，你应该熟悉这条规则。以下是你在处理回调函数时必须考虑的一些关键要点：

+   使用命名或匿名函数作为回调

+   将参数传递给回调函数

+   在执行回调之前确保它是一个函数

## 处理回调地狱

由于 JavaScript 使用回调函数来处理异步控制流，嵌套回调的工作可能会变得混乱，而且大多数时候，会变得无法控制。

在编写回调或从任何其他库使用它时，需要非常小心。

如果不正确处理回调，会发生以下情况：

```js
func1(param, function (err, res)) {
    func1(param, function (err, res)) {
        func1(param, function (err, res)) {
            func1(param, function (err, res)) {
                func1(param, function (err, res)) {
                    func1(param, function (err, res)) {
                        //do something
                    });
                });
            });
        });
    });
});
```

前一种情况通常被称为**回调地狱**。这在 JavaScript 中很常见，这让工程师们痛苦不堪。这也使得代码对于其他团队成员来说难以理解，对于后续使用来说难以维护。最糟糕的是，它让工程师混淆，难以记住在哪里传递控制权。

以下是回调地狱的快速提醒：

+   永远不要让你的函数没有名字。给你的函数一个可理解且有意义的名字。这个名字必须表明它是一个执行某些操作的回调函数，而不是在主函数的参数中定义一个匿名函数。

+   让你的代码看起来不那么可怕，更容易编辑、重构和以后黑客攻击。大多数工程师在思考流程中编写代码，对代码的美观性关注较少，这使得代码的后期维护变得困难。使用在线工具，如[`www.jspretty.com`](http://www.jspretty.com)，为你的代码添加可读性。

+   将你的代码分成模块；不要在一个模块中编写所有的逻辑。相反，编写简短有意义的模块，这样你可以导出一个执行特定工作的代码段。然后，你可以将该模块导入到你的大型应用程序中。这种方法还可以帮助你在类似的应用程序中重用代码，从而使你的模块形成一个完整的库。

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)下载您购买的所有 Pact Publishing 书籍的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接通过电子邮件发送给您。

# 事件

事件是在执行特定操作时产生的信号。JavaScript 能够意识到这些信号并做出相应响应。

事件是在用户进行操作时以恒定流发出的消息。事件通常基于用户行为，如果编程得当，它们会按照指导行动。如果没有处理事件的处理程序，那么任何事件都是无用的。

由于 JavaScript 为程序员/工程师提供了漂亮的控制，它们处理事件、监控和响应事件的能力。你处理事件的能力越强，你的应用程序将越交互式。

## 事件处理机制

JavaScript 中实现事件有两大传统方式。第一种是通过 HTML 使用属性，第二种是通过脚本。

为了让你的应用程序响应用户的动作，你需要做以下的事情：

1.  决定应该监控哪个事件。

1.  设置在事件发生时触发函数的事件处理程序。

1.  编写为事件提供适当响应的函数。

事件处理程序总是由 on 感知的事件名称，例如，由事件处理程序处理的点击事件，`onClick()`。这个事件处理程序导致一个函数运行，而该函数为事件提供响应。

### DOM – 事件捕获和事件冒泡

**文档对象模型**（**DOM**）使得检测事件和为它们分配相关事件处理程序变得容易得多。这使用事件捕获和事件冒泡这两个概念来实现这一目的。让我们看看每个如何帮助检测和为正确的事件分配正确的处理程序。

捕获事件指的是事件在到达目的地文档的过程中的通信。同时，它具有捕获或拦截此事件的能力。

这使得整个往返过程逐渐向下到其树包含的元素，直到它达到自身。

相反，事件冒泡是事件捕获的逆过程。在冒泡中，事件首先被最内层的元素捕获和处理，然后传播到外层元素。

### 最常见的事件处理程序列表

有一系列事件处理程序需要根据不同的需求和情况进行使用，但让我们添加一些更常见和常规的事件处理程序。

### 注意

请记住，一些事件处理程序可能因浏览器而异，当涉及到 Microsoft 的 Internet Explorer 或 Mac 的 Safari 时，这个规范变得更加有限。

以下列表非常方便且自解释。为了更有效地使用这个列表，我建议程序员/工程师将其记下来以供参考。

| 事件类别 | 事件将何时被触发 | 事件处理程序 |
| --- | --- | --- |
| 浏览器事件 | 页面完成加载 | `Onload` |
|  | 页面从浏览器窗口中移除 | `Onunload` |
|  | JavaScript 抛出错误 | `Onerror` |
| 鼠标事件 | 用户点击某个元素 | `onclick` |
|  | 用户双击元素 | `ondblclick` |
|  | 鼠标按钮在元素上按下 | `onmousedown` |
|  | 鼠标按钮在元素上释放 | `onmouseup` |
|  | 鼠标指针移动到元素上 | `onmouseover` |
|  | 鼠标指针离开一个元素 | `Onmouseout` |
| 键盘事件 | 一个键被按下 | `onkeydown` |
|   | 释放一个键 | `onkeyup` |
|   | 按下并释放一个键 | `Onkeypress` |
| 表单事件 | 元素从指针或通过标签导航获得焦点 | `onfocus` |
|   | 元素失去焦点 | `onblur` |
|   | 用户在文本或文本区域字段中选择类型 | `onselect` |
|   | 用户提交表单 | `onsubmit` |
|   | 用户重置表单 | `onreset` |
|   | 元素失去焦点且自获得焦点以来内容已更改 | `onchange` |

如前所述，这些都是最常见的事件处理列表。有一个单独的规格列表是为微软的 Internet Explorer 准备的，可以在[`msdn.microsoft.com/en-us/library/ie/ms533051(v=vs.85).aspx`](http://msdn.microsoft.com/en-us/library/ie/ms533051(v=vs.85).aspx)找到。

事件兼容性的完整列表可以在以下链接找到：

可以在[`www.quirksmode.org/dom/events/index.html`](http://www.quirksmode.org/dom/events/index.html)找到兼容性信息。

## 事件响应中触发函数

JavaScript 事件需要触发以获得响应。事件处理程序负责响应此类事件，但正确触发事件有四种常用方法：

+   JavaScript 伪协议

+   内联事件处理程序

+   作为对象属性的处理程序

+   事件监听器

## JavaScript 中的事件类型

在 JavaScript 中有很多不同类型的事件，其中一些如下：

+   接口事件

+   鼠标事件

+   表单事件

+   万维网联盟（W3C）事件

+   微软事件

+   火狐事件

### 接口事件

接口事件是由用户的动作触发的。当用户点击任何元素时，他/她总是触发一个点击事件。当点击元素有特定的目的时，会引发一个额外的事件接口。

### 鼠标事件

当用户将鼠标移动到链接区域时，会触发 mouseover 事件。当他/她点击它时，会触发 click 事件。

### 表单事件

表单识别提交和重置事件，当用户提交或重置表单时会预测性地触发这些事件。提交事件是任何表单验证脚本的关键。

### 万维网联盟（W3C）事件

当文档的 DOM 结构发生变化时触发 W3C 事件。最通用的是`DOMSubtreeModified`事件，该事件在 HTML 元素以下的 DOM 树被触发时触发。

[DOM 2 事件规格](http://www.w3.org/TR/2000/REC-DOM-Level-2-Events-20001113/events.html#Events-eventgroupings-mutationevents)可以在[`www.w3.org/TR/2000/REC-DOM-Level-2-Events-20001113/events.html#Events-eventgroupings-mutationevents`](http://www.w3.org/TR/2000/REC-DOM-Level-2-Events-20001113/events.html#Events-eventgroupings-mutationevents)找到。

### 微软事件

微软创建了许多自定义事件处理规格，这些规格（当然）只能在它的平台上运行。这可以在[`msdn.microsoft.com/en-us/library/ie/ms533051(v=vs.85).aspx`](http://msdn.microsoft.com/en-us/library/ie/ms533051(v=vs.85).aspx)找到。

### 火狐事件

火狐有自己的规格，可以在[`developer.mozilla.org/en/docs/Web/API/Event`](https://developer.mozilla.org/en/docs/Web/API/Event)找到。

# 发布者/订阅者

事件是另一种异步回调执行完成时进行通信的解决方案。一个对象可以成为发射器并发布其他对象可以监听的事件。这是观察者模式的绝佳例子。

这种方法的本质与“事件监听器”相似，但比后者更好，因为我们可以通过查看“消息中心”来找出有多少信号存在以及每个信号的订阅者数量，从而运行监控程序。

## 观察者模式的简要描述

观察者提供了对象之间非常松散的耦合。这提供了向收听它的人广播更改的能力。这种广播可能是针对单个观察者，也可能是一群等待收听的观察者。主题维护一个观察者的列表，以便广播更新。主题还提供了一个接口，供对象注册自己。如果它们不在列表中，主题不在乎谁或什么在听它。这是主题与观察者解耦的方式，允许轻松替换一个观察者另一个观察者，甚至是主题，只要它保持相同的事件序列。

### 观察者的正式定义

以下是对观察者的定义：

|   | *定义对象之间的一对多依赖关系，以便当一个对象改变状态时，所有依赖的对象都会自动通知并更新。* |   |
| --- | --- | --- |
|   | --*四人帮* |

这个定义来源于*设计模式：可重用对象导向软件的元素*，*Addison-Wesley 专业出版社*第 20 页。

### 拉模型和推模型

当你创建一个主题/观察者关系时，你希望向主题发送信息；有时，这些信息可能很简单，或者有时，可能是附加信息。这也可能发生，即你的观察者发送了一小部分信息，作为回应，你的主题查询更多的信息。

当你发送大量信息时，这被称为**推**模型，而当观察者查询更多信息时，这被称为**拉**模型。

|   | *拉模型强调主题对其观察者的无知，而推模型则假设主题了解其观察者需求的某些方面。推模型可能导致观察者更难以复用，因为主题类对观察者类做出了假设，这些假设可能并不总是正确的。另一方面，拉模型可能因为观察者类必须在没有主题帮助的情况下确定发生了什么变化而不够高效。* |   |
| --- | --- | --- |
|   | --*四人帮* |

这个定义来源于*设计模式：可重用对象导向软件的元素*，*Addison-Wesley 专业出版社*第 320 页。

#### 观察者/推-发布模式的诞生

这种观察者/推送发布模式提供了一种思考如何维持应用程序不同部分之间关系的方式。这也让我们知道我们应用程序的哪个部分应该用观察者和主题来替换，以实现最大性能和可维护性。在使用此模式特别是在 JavaScript 中时，以及其他语言一般要注意以下几点：

+   使用这种模式，可以将应用程序分解为更小、耦合度更低的部分，以改善代码管理和提高可重用性。

+   观察者模式最适合在需要保持相关对象之间一致性，而不使类紧密耦合的情况下使用。

+   由于观察者和主题之间的动态关系，它提供了极大的灵活性，当应用程序的不同部分紧密耦合时，可能不容易实现。

#### 观察者/推送发布模式的缺点

由于每个模式都有其代价，这个模式也是如此。最常见的是，由于其松耦合性质，有时难以维护对象的状态和追踪信息流路径，导致未订阅此信息的人员向主题接收不相关信息。

以下是一些常见的缺点：

+   通过将发布者与订阅者解耦，有时可能难以获得保证，我们的应用程序的特定部分可能如我们期望的那样运行。

+   此模式的另一个缺点是，订阅者不知道彼此的存在，并且对在发布者之间切换的成本视而不见。

+   由于订阅者和发布者之间的动态关系，更新依赖关系可能难以追踪。

# Promise 对象

Promise 对象是实现异步编程模型的最后一个主要概念。我们将研究 Promise 作为一种设计模式。

Promise 是 JavaScript 中相对较新的概念，但它已经存在很长时间，并在其他语言中得到实现。

Promise 是一个包含两个主要属性的抽象，这使得它们更易于使用：

+   您可以为一个 Promise 附加多个回调。

+   值和状态（错误）被传递下去

+   由于这些属性，Promise 使使用回调的常见异步模式变得容易。

可以将 Promise 定义为：

> *Promise 是由一个对象传递给另一个对象的可观察令牌。Promise 包装了一个操作，并在操作成功或失败时通知它们的观察者。*

此定义的来源是 *设计模式：可重用对象导向软件的元素*，*Addison-Wesley 专业出版社*。

由于本书的范围围绕 Promise 以及它的实现方式，我们将在第三章*Promise 范式*中详细讨论它。

# 总结 – 异步编程模型

到目前为止，我们已经看到了 JavaScript 中异步模型是如何实现的。这是理解 JavaScript 有自己的异步编程模型实现的一个核心方面，并且它在异步编程模型中使用了大量的核心概念。

+   异步模式非常重要。在浏览器中，应该异步执行非常耗时的操作，以避免浏览器无响应的时间；最好的例子就是 Ajax 操作。

+   在服务器端，由于环境是单线程的，所以执行异步模式。因此，如果你允许同步执行所有的 HTTP 请求，服务器性能将急剧下降，很快就会失去响应性。

+   这些都是简单的理由，说明了为什么在现代应用程序的各个方面都广泛接受 JavaScript 的实现。像 MongoDB 这样的数据库，Node.js 作为服务器端 JavaScript，Angular.js 和 Express.js 作为前端，以及逻辑构建工具，都是 JavaScript 在整个行业中如何被大量实施的一个例子。它们的堆栈通常被称为 MEAN 堆栈（MongoDB、Angular.js、Express.js 和 Node.js）。

# 总结

在这一章中，我们学习了编程模型是什么以及它们在不同语言中是如何实现的，从简单的编程模型到同步模型，再到异步模型。

我们还看到了任务是如何在内存中组织的，以及它们是如何根据它们的顺序和优先级来服务的，以及编程模型是如何决定要服务哪个任务的。

我们已经了解了在 JavaScript 中异步编程模型是如何工作的，以及为什么学习异步模型的动态对于编写更好的、可维护的、健壮的代码是必要的。

这一章还解释了 JavaScript 的主要概念是如何实现的，以及它们在应用程序开发中从不同角度扮演的角色。

我们还将看到回调、事件和观察者在 JavaScript 中的应用，以及这些核心概念如何推动当今的应用程序开发场景。

在下一章第三章，*承诺范式*，我们将深入学习承诺以及它是如何帮助使应用程序更加健壮和可扩展的。


# 第三章．承诺范式

在这一章中，我们将重点关注承诺范式是什么，它起源于何处，语言如何实现它，以及它能为我们的生活解决哪些问题。

我们已经在第一章，*Promises.js*中简要讨论了承诺模式的起源。在这一章中，我们将更详细地探讨这个主题，以一种通用的方式，以便阐明不同语言中采用承诺的逻辑和理论，特别是它如何帮助我们今天在现代编程中。

# 回调，重新审视

在之前的章节中，你已经学习了 JavaScript 机制是如何工作的。JavaScript 的单线程模型有其局限性，可以通过更好地使用回调来控制。然而，像回调地狱这样的场景真的推动工程师去寻找并实现一种更好的回调控制方法，以最大化程序的性能，同时仍保持在单线程内。回调是一个可以作为另一个函数的参数传递给它的函数，当它被调用时执行。

使用回调绝对没有错，但处理异步事件还有许多其他选项。承诺是处理异步事件的一种方式，其效率要高于其家族中的许多其他异步工具。

为了更清楚地了解为什么我们在异步编程中需要实现 Promises.js，我们需要了解承诺和延迟对象背后的概念。

# 承诺

与 JavaScript 的异步事件一起工作的好处是，即使程序没有正在进行它需要工作的值，它也会继续执行。这种情况被称为未完成工作中的已知值。这可能会使得在 JavaScript 中处理异步事件具有挑战性。

承诺是一种编程结构，表示一个尚不可知的值。JavaScript 中的承诺让我们能够以并行的方式编写异步代码，就像同步代码一样。

# 延迟

延迟是一个代表尚未执行的工作的对象，而承诺是一个代表尚未知晓的值的对象。

这些对象提供了一种方式，用于照顾注册多个回调到一个自管理的回调队列中，调用回调队列，以及传递任何同步函数的成功或失败状态。

# 承诺和延迟之间有什么关系？

直到现在，在第二章，*JavaScript 异步模型*中，我们讨论了承诺及其工作原理。让我们看看承诺和延迟是如何工作的：

1.  每个延迟对象都有一个承诺作为未来结果的代理。

1.  延迟对象可以通过其调用者解决或拒绝，这使得承诺与解决器分离，而承诺是异步函数返回的值。

1.  承诺可以被多个消费者接收，每个消费者都会不断地观察到解决结果，而解决器/延迟器可以被任何数量的用户接收，第一个解决它的用户将解决承诺。

# 承诺 API 的标准行为

关于承诺/提案的规范很少，必须实现概念的真正实现。这些规范是实现承诺的关键，任何库/语言都必须遵守它以实现真正的实现。

一个承诺如下：

+   当一个操作完成时，承诺返回一个最终的值。

+   一个承诺有三种状态：未完成（当一个承诺等待被处理时），已完成（当一个承诺已完成并获得了所需的结果），最后，失败（当承诺的结果已获得，但不是所期望的）。

+   承诺有一个`then`属性，必须是一个函数，并且必须返回一个承诺。为了完成一个承诺，必须调用`fulfilledHandler`，`errorHandler`和`progressHandler`。

+   通过承诺，回调处理程序返回履行值从返回的承诺。

+   承诺值必须是持久的。这应该保持一个状态，在该状态下，值必须被保留。

本 API 不定义承诺是如何创建的。它只提供了一个必要的接口，承诺提供给承诺消费者与之交互。实现者可以自由定义承诺是如何生成的。一些承诺可能提供它们自己的函数来履行承诺，其他承诺可能通过对承诺消费者不可见的机制来履行。承诺本身可能还包括其他一些方便的方法。

# 交互式承诺

交互式承诺是通过向其武器库中添加两个更多函数`get`和`call`来扩展承诺，从而为范式添加更多价值：

+   `get(propertyName)`：这个函数请求从承诺的目标中获得给定的属性。它还返回一个承诺，提供从承诺的目标中声明的属性的值。

+   `call(functionName, arg1, arg2…)`：这个函数请求在承诺的目标上调用给定的方法/函数。它还返回一个承诺，提供所请求函数调用的返回值。

# 承诺的状态和返回值

从第一章，*Promises.js*，我们已经知道承诺基于三种状态。让我们根据承诺范式复习这些状态。

承诺有三种状态：

+   未完成的承诺

+   已完成的承诺

+   失败的承诺

承诺存在于这三个状态之一。

承诺的开始是从一个未完成的状态。这是由于承诺是一个未知值的代理。

当承诺充满它等待的值时，它处于已完成的 state。如果它返回一个异常，承诺将被标记为失败。

承诺可能从未满足状态转移到满足或失败状态。观察者（或等待的对象/事件）在承诺被拒绝或满足时收到通知。一旦承诺被拒绝或解决，其输出（值或状态）就不能被修改。

下面的代码片段可以帮助你比理论更容易地理解：

```js
// Promise to be filled with future value
var futureValue = new Promise();

// .then() will return a new promise
var anotherFutureValue = futureValue.then();

// Promise state handlers (must be a function ).
// The returned value of the fulfilled / failed handler will be the value of the promise.
futureValue.then({

    // Called if/when the promise is fulfilled
    fulfilledHandler: function() {},

    // Called if/when the promise fails
    errorHandler: function() {},

    // Called for progress events (not all implementations of promises have this)
    progressHandler: function() {}
});
```

# 常见的序列模式

承诺和延迟对象使我们能够将简单任务与复杂任务结合在一起，从而实现对它们序列的精细控制。

如前所述，延迟对象代表尚未执行的工作，而承诺对象代表当前未知的值。这个概念帮助我们编写类似同步代码的异步 JavaScript。

承诺使相对容易地将小功能抽象化，这些功能跨多个异步任务共享。让我们看看承诺使更容易的常见序列模式：

+   堆叠

+   并行

+   顺序

## 堆叠

堆叠在任何应用程序中将多个处理程序绑定到同一个承诺事件。这有助于以更简洁的方式绑定多个处理程序，以便在代码中给出顺序控制。以下是堆叠和绑定处理器的示例：

```js
var req = $.ajax(url);
  req.done(function () {
      console.log('your assigned Request has been completed');
  });

  //Somewhere in the application
  req.done(function (retrievedData) {
      $('#contentPlaceholder').html(retrievedData);
  });
```

## 并行

并行简单地要求多个承诺返回单个承诺，该承诺通知它们多个完成。

使用并行序列，你可以编写多个承诺以返回单个承诺。在并行序列中，一组异步任务并发执行并返回一个承诺，当所有任务成功或失败时返回一个承诺（在失败的情况下）。

下面是一个显示并行序列返回单个承诺的一般代码片段：

```js
$.when(task01, task02).done(function () {
      console.log('taskOne and taskTwo were finished');
});
```

为了更清楚地理解，这里有一个处理并行序列的示例函数：

```js
function testPromiseParallelSequence(tasks)
{

    var results = [];  //an array of async tasks 

    //tasks.map() will map all the return call was made.

    taskPromises = tasks.map(function(task) 
    {
        return task();
    }); //returning all the promise
```

## 顺序

如果一个动作的输出是另一个动作的输入，则需要按顺序执行动作。HTTP 请求就是这样一个例子，其中一个动作是另一个动作的输入。顺序还允许您将代码的一部分控制权传递给另一部分。

它按照应用程序的需求或需要排队以供服务的任务范围执行任务。

以下是一个通用示例，其中一个序列处理并将控制权传递给另一个序列作为输入：

```js
// seq1 and seq2 represents sequence one and two respectively
var seq1, seq2, url; 
url = 'http://sampleurl.com;
seq1 = $.ajax(url);
   seq2 = seq1.then(

    function (data) {
        var def = new $.Deferred();

        setTimeout(function () {
            console.log('Request completed');
            def.resolve();
        },1000);

      return def.promise();
  },

    function (err) {
        console.log('sequence 1 failed: Ajax request');
    }
  );
  seq2.done(function () {
      console.log('Sequence completed')
      setTimeout("console.log('end')",500);
  });
```

# 解耦事件和应用程序逻辑

承诺提供了一种有效的方法来解耦事件和应用程序逻辑。这使得事件的实现和应用程序逻辑更容易构建，维护也更可销售。

![解耦事件和应用程序逻辑](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_03_01.jpg)

一种简单的方法，展示承诺如何解耦事件和业务逻辑

承诺的持久性重要性在于它不是一个“EventEmitter”，但可以通过智能实现转换为一个。但话说回来，它将是一个残废的。

## 承诺作为事件发射器

使用 promises 作为事件发射器的问题在于它的组合。它是 promises 中的事件进展无法与 EventEmitter 很好地组合。而 promises 链和事件进展，另一方面，无法做到这一点。Q 库的实现放弃了进展，以估计为代价在 v2 中。这就是为什么进展从未包含在 ECMAScript 6 中的原因。我们将在第九章，*JavaScript – The Future Is Now*中学习关于这些新兴技术的许多内容。

回到我们的话题，即如何通过 promises 解耦事件和应用程序逻辑，我们可以通过同时传递值来使用事件触发 promises 的解析/失败，从而使我们能够解耦。以下是代码：

```js
var def, getData, updateUI, resolvePromise;
// The Promise and handler
def = new $.Deferred();

updateUI = function (data) {
    $('p').html('I got the data!');
    $('div').html(data);
};
getData = $.ajax({
          url: '/echo/html/', 
          data: {
              html: 'testhtml', 
              delay: 3
          }, 
          type: 'post'
    })
    .done(function(resp) {
        return resp;
    })
    .fail(function (error) {
        throw new Error("Error getting the data");
    });

// Event Handler
resolvePromise = function (ev) {
    ev.preventDefault();
    def.resolve(ev.type, this);
    return def.promise();
};

// Bind the Event
$(document).on('click', 'button', resolvePromise);

def.then(function() {
    return getData;   
})
.then(function(data) {
    updateUI(data);
})
.done(function(promiseValue, el) {
    console.log('The promise was resolved by: ', promiseValue, ' on ', el);
});
// Console output: The promise was resolved by: click on <button> </button>
```

以下代码的参考资料可在[`jsfiddle.net/cwebbdesign/NEssP/2`](http://jsfiddle.net/cwebbdesign/NEssP/2)找到。

# promises 规定不要做什么

Promises 明确指出在实现 promises 范式时不要做什么。我们在第二章，《JavaScript 异步模型》中看到了大部分这些规则。让我们从 promises 范式中看看这些，以刷新我们的记忆。

在实现 promises 时，无论您使用哪种实现，都必须考虑以下两种做法：

+   避免进入回调地狱

+   避免使用未命名的 promises

## 避免进入回调地狱

我们已经了解到回调是什么以及如何处理它们。回调是实现异步模型的绝佳方式，但它们也有自己的代价。在某些时候，回调变得难以管理，这个时刻在你开始深入回调时到来。你越深入，处理起来就越困难，从而导致你陷入回调地狱的场景。

所有 promises 实现都简单而明智地解决了这个问题。

![避免进入回调地狱](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_03_02.jpg)

解决回调地狱的便捷方法

## 避免使用未命名的 promises

正如我们在第二章，《JavaScript 异步模型》中所见，使用未命名的 promises 可能造成巨大问题，并且会花费比编写和测试普通函数更多的时间。在某些情况下，不给出函数名称是好的，也是推荐的，但留下未命名的 promise 并不是一个好的实践。

如果有人认为匿名函数难以处理，那么不合理命名的函数难以理解和支持。我建议您在实际编写代码之前制定一个合适的、预先决定的命名约定，并且应该做得很好。我更喜欢使用微软风格的驼峰命名法，其中函数的起始名是小写的，而连接名是大写的。

# Promises 和异常

考虑一个在承诺范式内抛出异常的函数。如果您试图查看异常抛出函数发生了什么，您将找不到任何踪迹或日志。您在屏幕或控制台上看不到任何输出。为什么？原因隐藏在承诺的基本知识中。

承诺被设计成产生两种类型的输出-承诺要么被实现，要么被拒绝。因此，自然地，它不会在任何输出流中出现，因为承诺没有被设计成产生除了这两个预定义状态之外的任何其他输出。然而，并不是承诺没有提供任何处理异常的设施。实际上，它通过实现适当的处理程序来捕获异常并在任何所需的输出流中显示原因，提供了一种健壮的方法来显示和处理此类异常。

在大多数承诺范式中，异常是通过`fail`和`then`处理的。处理程序因库而异，也因语言而异。在许多高级高级语言中，错误和异常处理是自动管理的，不会增加太多代码，也无需明确告诉编译器/解释器，但在那些没有自动处理的库和语言中，您必须编写显式的代码来手动处理异常。

在这一点上，值得注意的是我们使用了 Q 中的一些代码，只是为了让您理解异常处理也是承诺实现的一部分，以及如果发生异常，如何处理异常。在我们下一章中，我们将重点介绍如何在其他库和语言中实现承诺。

回到主题，像许多其他实现一样，Q 有自己的承诺处理机制。

考虑这段代码即将抛出异常：

```js
function imException()
{
throw "imException";

}//end of code
```

由于这不是使用 Q 处理承诺异常的正确实现，将根本没有任何输出，如果我们想要根据 Q 中承诺范式的实现来处理它，我们将想要添加一个拒绝处理程序。

让我们以 Q 为例，看看我们是否可以使用其`fcall()`方法添加相同的函数：

```js
Q.fcall(imException);
```

这个方法调用不是用来处理异常的，所以它不会显示任何东西。要处理它，我们需要添加一个拒绝处理程序，以帮助我们跟踪和监视异常。

## 失败方法

处理异常的最简单方法是使用`fail`。让我们重构我们的代码以实现`fail`方法：

```js
// code view before exception handler
Q.fcall(imException);

//code after exception handler
Q.fcall(imException) .fail(function(err) { console.log(err); });
```

## 然后方法

通常，我们会使用`then`来处理承诺链。这将接收两个参数，并根据这些处理器的返回承诺执行之一：

```js
Q.fcall(imException)
.then(
    // first handler-fulfill
    function() { }, 

    // second handler -reject
    function(err) {
        console.log(err);
    }
);
```

第一个参数是一个完成方法，第二个是拒绝处理程序，如前所示的代码。使用这些简单技术，Q 实现了异常处理。

# 处理承诺异常的最佳实践

承诺提供了一种令人印象深刻的方式来处理异常。承诺中的异常处理相当简单且易于实现，几乎所有库和实现都支持一种通用的实现方式。以下是一些处理异常的最佳实践：

## 使您的异常有意义

为了最大化性能和可维护性，抛出可理解的错误。最佳实践是拒绝一个承诺，并用错误实例来拒绝它。养成不拒绝错误对象或原始值的习惯。

## 监视、预期并处理异常

关注错误对执行流程的影响。最佳实践是预料你处理程序中的失败。你越擅长预见，你对执行流程的控制就会越好。总是考虑您的拒绝处理程序是否应该由解析处理程序中的失败调用，或者是否应该有不同的行为。

## 保持干净

当你处理完异常后， error occurs as soon as possible. When the chain of promises is processed and a result has been delivered in either rejected or fulfilled state, terminate the chain and clean up the unused thread. This will help not only in optimizing the throughput of code but also in creating manageable outputs.

Mozilla 为其承诺中的错误处理有自己的实现，这可以在[`developer.mozilla.org/en-US/docs/Mozilla/JavaScript_code_modules/Promise.jsm/Promise`](https://developer.mozilla.org/en-US/docs/Mozilla/JavaScript_code_modules/Promise.jsm/Promise)中看到。

# 选择承诺时的考虑

在开始使用承诺库之前，有许多因素你应该记住。并不是所有的承诺实现都是一样的。它们在提供的 API 实用程序、性能以及有时行为方面都各不相同。

承诺/提案只是概述了承诺的拟议行为，而不是实现规范。这导致不同的库提供不同的功能集。它们之间的区别如下：

+   所有的承诺/赞美都有`then()`；函数，并且它们 API 中还有各种不同的功能。此外，它们仍然能够与其他承诺进行交换。

+   在承诺/兼容库中，抛出的异常被翻译为一个拒绝，并且`errorHandler()`方法用异常调用。

由于不同的实现，当使用返回或期望承诺/兼容的库时，存在互操作性问题。

选择承诺库可能会有所权衡。每个库都有自己的优点和缺点，完全取决于您根据特定用例和项目需求决定使用什么。

# 摘要

在本章中，我们介绍了承诺（promise）的范式及其背后的概念。我们讲解了承诺、延迟（deferred）、常见的承诺链以及承诺如何帮助解耦业务逻辑和应用逻辑的概念性知识。我们还讲解了承诺与事件发射器（event emitters）之间的关系及其背后的理念。

由于本章的性质，我们现在可以根据所获得的知识选择我们应该使用的承诺库。

在我们下一章中，我们将探讨不同编程语言中承诺（promise）的实现，并检查它们为开发人员和最终用户带来的便利。


# 第四章：实现承诺

在上一章中，第三章，*承诺范式*，我们看到了承诺及其理论是如何结合在一起，形成软件工程范式的一个全新的惊人的图片，尤其是在当今现代异步应用开发生命周期中。

在本章中，我们将开始实验如何通过实现承诺来形成这个概念。为什么我们需要了解它的实现？这个问题的答案很简单；我们需要了解我们迄今为止开发的这个概念是否真实，以及这个概念有多少是真正适用的。另外，通过这些承诺的小实现，我们将绘制我们基础的基石，以便在后面的章节中在其他技术中使用承诺。那么，让我们来看看我们将如何进行这个实现阶段。

# 如何实现承诺

到目前为止，我们已经了解了承诺的概念、它的基本组成部分以及它在几乎所有实现中提供的一些基本功能，但是这些实现是如何使用它的呢？嗯，其实很简单。每种实现，无论是作为一种语言还是一种库，都会映射承诺的基本概念。然后，它将其映射到一个编译器/解释器或代码中。这使得编写的代码或函数以承诺的范式行为，最终呈现出它的实现。

承诺现在已经成为了许多语言的标准包的一部分。显而易见的是，它们根据自己的需求以自己的方式实现了它。我们将在本章中详细探讨这些语言是如何实现承诺的概念。

# 在 Java 中的实现

Java 是世界上最受欢迎和最受尊敬的编程语言之一，并在全球各地的数百万设备上使用。除了 Java 之外，无需再说什么，它是工程师在创建使用多线程和受控异步模式和行为的应用程序软件时的首选。Java 是少数几种默认在编译器中实现异步行为的语言之一，这有助于程序员编写健壮、可扩展和可维护的软件。

## Java 的 util 包

自然地，Java 对承诺的概念及其实现有更广泛的接受。在 `java.util.concurrent` 包中，关于承诺及其实现有很多实现。我们挑选了一些有助于实现承诺或与该概念相匹配的接口和类。

### Java 实现承诺的机制

在 `java.util.concurrent` 包中，有许多接口和类可以帮助我们编写并发和异步代码，但有一些特定的接口和库是专门用于这个承诺/未来的实现。

`java.util.concurrent` 包是并发编程（正如其名）的家园，也是几个小型标准化扩展框架的家园。它还帮助实现一些在正常情况下难以工作的核心类。

### `java.util.concurrent` 核心组件

`java.util.concurrent` 包中包含许多类和组件，但使其特别适合于并发工作的核心组件包括：

![The core components of java.util.concurrent](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_04_01.jpg)

`java.util.concurrent` 包的核心组件

#### Executor

`Executor` 是一个简单的标准化接口，通常用于定义自定义线程子系统。这些子系统包括线程池、异步 I/O 和基于任务的轻量级框架。

在线程中创建的任务可以在线程中执行“相同的任务执行线程”或在新线程中执行；这也可以在调用执行的线程中顺序或并发执行。无论执行模式任务采用哪个线程，都完全取决于使用的具体 `Executor` 类。

`ExecutiveService` 接口提供了一个完全堆叠的异步任务框架。这个接口是为了处理池中的多个任务，包括控制 `Executor` 的关闭、管理不同池中的队列以及任务的调度。还有一些与 `ExecutiveService` 一起工作以添加对延迟和周期性任务执行支持的关联。其中之一是 `ScheduledExecutorService`，它是一个子接口，与 `ExecutiveService` 接口一起管理延迟和周期性任务的执行。

另一个接口称为 `ExecutorService` 接口，它提供方法来安排任何表示为可调用函数的执行。

#### 队列

当谈到队列时，首先浮现的想法是**先进先出**（**FIFO**）模式。就像其他语言以自己的方式应用这种数据结构一样，Java 通过使用来自其 `java.util.concurrent` 包的 `ConcurrentLinkedQueue` 类，将其视为一个高效、可扩展的线程安全、非阻塞的 FIFO 队列。在同一包中，五种实现支持 `BlockingQueue` 接口。

`BlockingQueue` 接口是一个队列，具有高级的等待机制。在所有之前的处理完成之前，它保持队列不进入进一步处理。在存储元素时，它也等待空间使队列可用。

以下是 `BlockingQueue` 接口的五种实现：

+   `LinkedBlockingQueue`

+   `ArrayBlockingQueue`

+   `SynchronousQueue`

+   `PriorityBlockingQueue`

+   `DelayQueue`

我们将在下一节讨论一些这些相关实现。

### Timing

由于`util`是工具包，它有以类和接口形式存在的控制，帮助工程师使用他们日常例行的事情。这样一个包就是方法或接口的时间。这是为了执行某些指令操作，最终，当操作完成时，它们会自己超时。

我们中的大多数人已经意识到会话创建和会话超时的重要性，特别是那些从事 Web 编程的程序员。会话跟踪是一个独立的主题，与本章的结构并没有太大关系，因此我们将把重点回到时间话题上。

这个打包就像是 Java 程序的定时带。在任何引擎中，定时带的作用是确保某些机械操作在指定时间内完成；这个包也是如此。它控制函数的时效性和非确定性等待。需要记住的是，所有这些方法在每种情况下都使用超时。这有助于线程定义方法在线程池中花费的时间，并节省实际程序以实现可伸缩性。

### 同步器

Java 提供了一个低级别的线程创建和执行，以便程序员可以轻松地处理和修改线程级控制。在早期版本中，线程的控制被认为是处理最困难的话题，因为与线程的自动控制相比，有很多线程和它们同步的手动控制。在这个时候，Java 在控制多个线程方面比它的竞争语言先进得多，但线程的操作对于 Java 工程师来说仍然是一项相当艰巨的任务。

在 Java 的后续版本中，这个问题被认为是寻找规律的最重要问题，最终，在版本 7 的出现时，编译器已经解决了工程师面临的大部分问题。

在当前版本，即版本 8 中，有五个类帮助实现同步：

+   `Semaphore`类是一个经典的并发工具，已经存在很长时间了（[`docs.oracle.com/javase/7/docs/api/java/util/concurrent/Semaphore.html`](http://docs.oracle.com/javase/7/docs/api/java/util/concurrent/Semaphore.html)）

+   `CountDownLatch`类是一个非常简单但又常见的工具，用于阻塞直到给定的信号、事件或其他线程中执行的操作被处理（[`docs.oracle.com/javase/7/docs/api/java/util/concurrent/CountDownLatch.html`](http://docs.oracle.com/javase/7/docs/api/java/util/concurrent/CountDownLatch.html)）

+   `CyclicBarrier`类是一个可重置的多路同步点，这在某些并行编程风格中非常有用（[`docs.oracle.com/javase/7/docs/api/java/util/concurrent/CyclicBarrier.html`](http://docs.oracle.com/javase/7/docs/api/java/util/concurrent/CyclicBarrier.html)）

+   `Phaser`类提供了一种更灵活的屏障形式，可用于控制多个线程之间的分阶段计算([`docs.oracle.com/javase/7/docs/api/java/util/concurrent/Phaser.html`](http://docs.oracle.com/javase/7/docs/api/java/util/concurrent/Phaser.html))

+   `Exchanger`类允许两个线程在汇合点交换对象，在许多流水线设计中很有用([`docs.oracle.com/javase/7/docs/api/java/util/concurrent/Exchanger.html`](http://docs.oracle.com/javase/7/docs/api/java/util/concurrent/Exchanger.html))

### 并发集合

`Concurrent`包为多线程环境提供了实现，并具有以下实现。

由于它具有更具体的同步设施，其中一些类使用前缀`Concurrent`来强调它提供的额外设施。还有一些更为突出的例子：

+   `ConcurrentHashMap`

+   `ConcurrentSkipListMap`

+   `ConcurrentSkipListSet`

+   `CopyOnWriteArrayList`

+   写入后复制数组集（CopyOnWriteArraySet）

并发集合的优点是其安全的线程，而不是被单一的锁定机制忽视。只有在`ConcurrentHashMap`的情况下，它才允许任何数量的并发读取以及并发写入。那么，我们为什么还要使用同步类呢？答案是它们在防止使用单个锁对集合的所有访问方面非常有用，但这有代价，并且可扩展性较差。

在其他情况下，如果有多个线程排队访问一个公共集合，建议使用当前版本的类，而当集合是不共享的或者在持有其他锁时可以访问时，则使用未同步的锁。

## Java 实现承诺的方式

Java 通过其承诺类和接口实现承诺范式。尽管它的异步行为是 Java 的核心和旗舰特性之一，但以下是 Java 中承诺实现的成分：

+   接口：

    +   完成服务（CompletionService）

    +   `ExecutorService`

    +   `Future`

+   类：

    +   `Delayed`

    +   延迟队列（DelayQueue）

    +   `FutureTask`

### 完成服务（CompletionService）

`CompletionService`接口作为一项服务，用于区分新异步任务与已完成任务的结果。这个过程很简单：生产者添加执行的任务。对于消费者来说，这个接口接收完成的任务并按它们被标记为完成时的顺序处理它们的结果。这个服务可用于许多并发操作，如管理异步 I/O。异步 I/O 的机制是任务提交在程序的一部分或程序集或系统中，然后在不同程序的部分执行。提交顺序可能与最初请求的顺序不同。

异步 I/O 的机制是，它在程序的一部分，如缓冲区中读取任务并存储起来。

这可以是一个单一的程序（如浏览器），或者是一组程序（如操作系统线程池）。线程处理者决定哪个线程需要首先执行。

这个接口依赖于一个单独的执行器，或者实际上执行任务，因此`CompletionService`接口只管理一个内部的完成队列。接口实现时，需要一个类来完成这个功能，`ExecutorCompletionService`类提供了这样的功能。

### `ExecutorService`

`ExecutorService`接口有两个主要角色要执行——一个是提供管理异步任务终止的方法，另一个是提供可以产生跟踪未来值的方法。这种跟踪可以针对一个或多个异步任务进行。

使用`Executor`管理`ExecutorService`：

+   `ExecutorService`继承了`Executor`，提供了管理终止和生成未来值的方法，以跟踪进度。

+   当`ExecutorService`关闭时，它会拒绝所有新任务。它们已经通过两种不同的方法加载：

    +   `shutdown()`

    +   `shutdownNow()`

`shutdown()`方法允许内存中的任务完成它们的状态，然后终止它们。同时，它防止内存进入并处理任何即将到来的任务。另一方面，`shutdownnow()`并不提供这样的自由；它只是立即终止内存中的所有内容。这也完全拒绝了新任务在内存中的进入，通过使现有线程无效来实现。

这两种方法各有其重要性，但由于它们都与现有任务的终止有关，因此在使用时必须非常小心，并充分理解潜在的后果。

以下代码片段来自原始的 Java 文档，具体内容可在[`docs.oracle.com/javase/7/docs/api/java/util/concurrent/ExecutorService.html`](http://docs.oracle.com/javase/7/docs/api/java/util/concurrent/ExecutorService.html)找到：

```js
class NetworkService implements Runnable {
  private final ServerSocket serverSocket;
  private final ExecutorService pool;

  public NetworkService(int port, int poolSize)throws IOException {
    serverSocket = new ServerSocket(port);
    pool = Executors.newFixedThreadPool(poolSize);
  }

  public void run() { // run the service
    try {
      for (;;) {
        pool.execute(new Handler(serverSocket.accept()));
      }
    } catch (IOException ex) {
      pool.shutdown();
    }
  }
}

class Handler implements Runnable {
  private final Socket socket;
  Handler(Socket socket) { this.socket = socket; }
  public void run() {
    // read and service request on socket
  }
}
```

以下方法通过两个阶段关闭`ExecutorService`接口：首先，通过调用 shutdown 来拒绝新任务，然后如有必要，调用`shutdownNow()`来取消任何挂起的任务：

```js
void shutdownAndAwaitTermination(ExecutorService pool) {
  pool.shutdown(); // Disable new tasks from being submitted
  try {
    // Wait a while for existing tasks to terminate
    if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
      pool.shutdownNow(); // Cancel currently executing tasks
      // Wait a while for tasks to respond to being cancelled
      if (!pool.awaitTermination(60, TimeUnit.SECONDS))
        System.err.println("Pool did not terminate");
    }
  } catch (InterruptedException ie) {
    // (Re-)Cancel if current thread also interrupted
    pool.shutdownNow();
    // Preserve interrupt status
    Thread.currentThread().interrupt();
  }
}
```

### `Future`

在 Java 中，`future`代表了异步计算结果的值。提供了跟踪结果状态的方法。这些方法表明当前状态是等待还是其他状态。

问题是，你只能通过`get`或者计算完成时才能获取结果。

取消可以通过 cancel 方法完成；这非常容易记住。使用取消方法可以取消`Future`值。

你也可以通过调用该方法检查任务是否正常完成或被取消。一旦计算完成，就不能取消了；这让我们觉得很有希望，就像承诺的概念一样。

你也可以使用`Future`来取消任务。尽管这并不是一个很好的方法，如果你想要这么做，那么你可以声明许多类型的`Future`对象，并要求方法返回 null；就这样！你的任务再次被取消了。这必须在任务最终计算之前完成。

以下是代码片段：

```js
interface ArchiveSearcher { String search(String target); }

class App { 

  ExecutorService executor = ...ArchiveSearcher searcher = ...
  void showSearch(final String target)throws InterruptedException {
    Future<String> future
    = executor.submit(new Callable<String>() {
      public String call() {
        return searcher.search(target);
      }});
    displayOtherThings(); // do other things while searching
    try {
      displayText(future.get()); // use future
    } catch (ExecutionException ex) { cleanup(); return; }
  }
}
```

`FutureTask`类是实现`Future`并实现`Runnable`的`Future`的实现，因此可以由`Executor`执行。例如，使用 submit 的先前构造可以替换为以下内容：

```js
FutureTask<String> future =
  new FutureTask<String>(new Callable<String>() {
    public String call() {
    return searcher.search(target);
  }});
executor.execute(future);
```

### 延迟和 DelayedQueue

`Delay`是一个使用标记来标记在延迟之后进行操作的对象的接口。

`DelayedQueue`是一个用于收集所有延迟/过期的对象的无限队列。由于它是一个队列，必须有一个延迟已经很久很久的头元素。

由于它是一个队列，并且与`queue`数据结构相似，它有一个称为头部的起始点和一个称为脚部的结束点。当说到未来时，我们在这里提到的队列有一个值，它已经由于失败的承诺或未实现的承诺而过期。

如果没有找到这样的元素，在过期发生时，轮询会返回 null 吗？嗯，当方法`getDelay(TimeUnit.NANOSECONDS)`返回的值小于或等于零时，它就会发生。以这种方式过期的元素不能被移除，所以它们被视为正常元素。

### `FutureTask`

`FutureTask`是可取消的异步计算。这是`Future`的基本提供者，它从开始一个方法到取消它都加载了方法。这也有助于检索计算的结果，因为它是实现，当计算完成时可以提取结果。不用说，一旦计算出结果，它就不能被拉回或更改，因为这是一个承诺。

### 总结 Java 和 Promises.js

如果我们总结一下前面的讨论，很清楚 Java 在处理 Promises.js 方面有更清晰的方法和实现。它是一种处理异步行为成熟的方式，特别是，它在处理多线程方面的表现远胜于其他语言。然而，每种实现都有它的缺点，Java 也是如此，这是可以接受的，因为你不能简单地复制和粘贴理论，就像任何编译器/解释器一样。开源社区贡献了少数更多支持的框架/库来补充它的实现。

# 向 JDeferred 打个招呼

受到 jQuery 中承诺实现的启发，一些 Java 工程师开始开发一个名为`JDeferred`的库。它通过留下`java.util.concurrent`包中的巨大漏洞，实现了承诺的概念。这是`JDeferred`工作的简要介绍。让我们深入了解它是什么以及与其他市场上可用的实现相比的独特优势。

就像 jQuery 有一个延迟对象一样，`JDeferred`也是设计成与 Java 编译器的行为和联系相似。`JDeferred`不仅与 jQuery 的承诺实现相似，而且还将其支持扩展到了 Android Deferred Object。第八章，*jQuery 中的承诺*是专门讨论 jQuery 及其机制和承诺工作的章节，所以我们现在可以跳过这部分，看看 Android Deferred Object 是什么，以及它如何融入承诺的实现。

## 关于 Android Deferred Object 说几句

当我们讨论`JDeferred`时，如果不展示 Android Deferred Object 及其属性的存在，那是不公平的。Android Deferred Object 是一个工具，或者更简单地说，它是一个可链式的工具对象，实际上可以为 Android 领域做所有相同的事情。它可以在单个回调队列中注册多个回调；它可以调用回调队列并在处理后执行。它还可以将成功或失败的状态传达给等待的任何函数；无论它是一个同步函数还是一个异步函数都不重要。

其工作相当直接。你从一个异步执行的函数中得到一个承诺。由于我们可以围绕承诺进行操作，因此你可以附加回调以获取关于成功或失败的通知。无论这部分程序是同步执行还是异步执行，当它如预期般完成时，承诺会被调用以解决任何错误，它调用`rejected`参数。

### 用例 1——任务的对象成功和失败回调

比如说你需要一个异步的 HTTP 请求。使用 Android Deferred Object 的一个简单方法是将请求包装到`DeferredAsyncTask`中，并将回调附加到你的操作上。以下是这种场景的代码：

```js
new DeferredAsyncTask<HttpResponse,HttpResponse,Void>() {
  protected abstract Resolved doInBackground() throws Exception {
    //do your async code here
  }
}
.done( new ResolveCallback<HttpResponse> {
  public void onResolve(HttpResponse resolved) {
    //your success code here
  }
})
.fail ( new RejectCallback<HttpResponse> {
  public void onReject(HttpResponse rejected) {
     //your failure code here
  }
});
```

前述代码的参考可以在[`github.com/CodeAndMagic/android-deferred-object`](https://github.com/CodeAndMagic/android-deferred-object)找到。

### 用例 2——合并多个承诺

此用例最适合当你需要将多个已执行的承诺合并成一个单一的承诺，通过将它们作为一个单一的承诺来合并。一个方便的方法是调用`DeferredObject.when`方法：

```js
Promise<A1,B1,C1> p1 = new DeferredAsyncTask<A1,B1,C1>() { ... }; 
Promise<A2,B2,C2> p1 = new DeferredAsyncTask<A2,B2,C2>() { ... };
Promise<A3,B3,C3> p3 = new DeferredAsyncTask<A3,B3,C3>() { ... };
//when gives you a new promise that gets triggered when all the merged promises are resolved or one of them fails
DeferredObject.when(p1,p2,p3)
.done(new ResolveCallback<MergedPromiseResult3<A1,A2,A3>() {
  public void onResolve(MergedPromiseResult3<A1,A2,A3> resolved){
    Log.i(TAG, "got: " + resolved.first() + resolved.second() + resolved.third());
  }
})
.fail(new RejectCallback<MergedPromiseReject>() {
  public void onReject(MergedPromiseReject rejected) {
    //failure handling here
  }
})
.progress(new ProgressCallback<MergedPromiseProgress>() {
  public void onProgress(final MergedPromiseProgress progress){
    //you get notified as the merged promises keep coming in
  }
});
//Merging doesn't stop you do add individual callbacks for promises that are in the merge
p1.done(...).fail(...)
//Or even merging them in another way
DeferredObject.when(p1,p2).done(...).fail(...)
```

# JDeferred 的机制

回到我们 JDeferred 的核心讨论，这个实现几乎采纳了来自承诺的所有特性，并被认为比其他任何库都更符合承诺。我们将看看它提供哪些特性，以及它们是如何在内部实现的。

## JDeferred 的特性

`JDeferred`的实现提供了展示 Java 中承诺范式的所有必要方法。它具有诸如延迟对象和承诺、承诺回调、多个承诺、可调用和可运行方法以及 Java 的泛型支持等特性。

以下表格总结了特性及其可用的实现：

| 特性 | 可用的实现 |
| --- | --- |
| 延迟对象和承诺 | N/A |
| 承诺回调 | `.then(…)``.done(…)``.fail(…)``.progress(…)``.always(…)` |
| 多个承诺 | `.when(p1, p2, p3, …).then(…)` |
| 可调用和可运行包装器 | `.when(new Runnable() {…})` |
| Java 泛型支持 | `Deferred<Integer, Exception, Double> deferred;``deferred.resolve(10);``deferred.reject(new Exception());``deferred.progress(0.80);` |

## 使用 JDeferred 玩转代码

现在我们将探讨一些这个实现的常见示例，这些示例最常被使用。我们将讨论以下主题：

+   延迟对象和承诺

+   延迟管理器

+   可运行和可调用

+   `wait()`和`waitSafely()`

+   过滤器

+   管道

### 延迟对象和承诺

以下代码将帮助你理解`JDeferred`如何实现延迟对象和承诺。这段代码附有注释，以便更好地理解：

```js
//creating new deferred object by calling method DeferredObject();

Deferred deferredObj = new DeferredObject();

//now its time to make some promise
Promise promise = deferredObj.promise();

promise.done(new DoneCallback() {

  public void onDone(Object result) {
    //some code here
  }

}).fail(new FailCallback() {
  public void onFail(Object rejection) {
    //some more code
  }
}).progress(new ProgressCallback() {
  public void onProgress(Object progress) {
    //some code here

  }
}).always(new AlwaysCallback() {
  public void onAlways(State state, Object result, Object rejection) {
    //some code here

  }
});
```

### 延迟管理器

延迟管理器是一种简单的方式来管理你的延迟对象。调用延迟管理器的默认方法，然后添加你想要的承诺数量：

```js
//create Deferred Manager's object
DeferredManager theDeferredManager = new DefaultDeferredManager();

// uncomment this to specify Executor

// DeferredManager theDeferredManager = new DefaultDeferredManager(myExecutorService);

//add and initialize number of promises

Promise pm1, pm2, pm3;
theDeferredManager.when(p1, p2, p3)

// or you can add here .done(…)
//or you can add the fail here using   .fail(…)
```

### 可运行和可调用

可运行和可调用，与承诺一样好，可以用如下方式使用：

```js
DeferredManager theDeferredManager = new DefaultDeferredManager();

theDeferredManager.when(new Callable<Integer>()

{
  public Integer call() {
    // return something
    // or throw a new exception
  }

}).done(new DoneCallback<Integer>() {
  public void onDone(Integer result) {
    ...
  }

}).fail(new FailCallback<Throwable>() {
  public void onFail(Throwable e) {
    ...
  }

});
```

如果你想要做以下事情，你可以使用`DeferredCallable`和`DeferredRunnable`：

+   通知关于可调用或可运行的进度

+   你想让你的`Deferred`对象

以下是一个示例代码：

```js
final Deferred deferred = ...
Promise ThePromise = deferred.promise();
ThePromise.then(…);

Runnable runable = new Runnable() {

  public void run() {
    while (…) {
      deferred.notify(myProgress);
    }
    deferred.resolve("done");
  }
}
```

扩展`DeferredRunnable`：

```js
DeferredManager theDeferredManager = …;
theDeferredManager.when(new DeferredRunnable<Double>(){
  public void run() {
    while (…) {
      notify(myProgress);
    }
  }
}).then(…);
```

### `wait()`和`waitSafely()`

`wait()`和`waitSafely()`函数是`JDeferred`想要控制所有异步任务的部分。这并不推荐，但在某些情况下非常有用：

```js
Promise promise = theDeferredManager.when(...)
  .done(...) //when done
  .fail(...) // when fail

synchronized (p)
  while (promise.isPending()) {
    try {
      promise.wait();
    } catch (InterruptedException e) { ... }
  }
}
```

上述代码的快捷方式如下：

```js
Promise promise = theDeferredManager.when(...)
  .done(...)
  .fail(...)

try {
  promise.waitSafely(); //replaced waitSafely(); 
} catch (InterruptedException e) {
  ... 
}
```

### 过滤器

以下是我们将用于过滤承诺和延迟对象的代码：

```js
Deferred d = …;
Promise promise = d.promise();
Promise filtered = promise.then(new DoneFilter<Integer, Integer>() {
  public Integer filterDone(Integer result)
    return result * 10;
  }
});

filtered.done(new DoneCallback<Integer>{
  public void onDone(Integer result) {
    // result would be original * 10
```

### 管道

`JDeferred`中的管道也是按顺序进行异步任务计算的：

```js
Deferred d = ...;
Promise promise = d.promise();

promise.then(new DonePipe<Integer, Integer, Exception, Void>() {
  public Deferred<Integer, Exception, Void> pipeDone(Integer result) {
    if (result < 100) {
      return new DeferredObject<Integer, Void, Void>().resolve(result);
    } else {
    return new DeferredObject<Integer, Void, Void>().reject(new Exception(...));
    }
  }
}).done(...).fail(...);

d.resolve(80) -> done!
d.resolve(100) -> fail!
```

# Ultimate JDeferred

正如你所看到的，这是使用承诺的 Java 的一个更强大的实现。当谈到实现承诺范式时，Java 非常强大。

实际上，Java 本身就有很多强大的功能，但当谈到适当的实现时，这样的框架可以帮助我们。因为它们是社区维护的，所以在质量方面存在问题，你可能会找到未测试和未经验证的代码，这可能会浪费你的时间。然而，与 jQuery 相比，`JDeferred`的实现几乎相同。

# 摘要

在本书的这一章节中，我们实际上已经开始掌握 Promise 的旅程了。这一章节涵盖了为什么我们要实现 Promise 以及为什么我们选择 Java 作为本章节的核心。Java 的功能比任何其他编程语言都要丰富，并且它也非常努力地使其与异步行为的自动化保持更多或 less 相似。我们详细探讨了 Java 的`util.concurrent`类的核心组件，并通过这些组件我们看到了来自 Java 在线文档的许多实际例子。由于 Java 由于我们所看到的限制而不能完全实现承诺范式，因此有一个开源库，其行为与承诺范式完全一样。`JDeferred`通过充分利用实现承诺的核心价值观（如`future`、`deferred`等）消除了我们心中的其他疑虑。

在下一章中，我们将通过一个更实用的例子来加深对 WinRT 中 Promise 的理解。


# 第五章：WinRT 中的承诺

在过去的四章中，我们花费时间加强我们的概念并确保我们的思维基础与承诺保持一致。从这一章开始，我们将探索在不同技术中的承诺。我们将了解这些技术是如何采用该概念的，它们为何采用它，以及承诺与这些技术有何关联。我们将查看一些相关技术的代码库，以便获得第一手知识，了解如何在实际环境中实现承诺。

# WinRT 简介

我们对技术的第一次关注是 WinRT。WinRT 是什么？它是 Windows Runtime 的简称。这是由微软提供的一个平台，用于构建适用于 Windows 8+操作系统的应用程序。它支持在 C++/ICX、C#（C#）、VB.NET、TypeScript 和 JavaScript 中进行应用程序开发。

微软将 JavaScript 作为其主要的、一等公民工具之一，用于开发跨浏览器应用程序以及开发相关设备。我们现在完全了解使用 JavaScript 的利弊，这使我们来到了实现承诺使用的地方。

您猜对了！在本章中，我们将重点介绍如何在 WinRT 上实现承诺，这是实现的需要，以及如何实现。我们还将根据需要查看一些代码，以了解承诺在这些平台上表现如何，以及如何实际使用它。

# WinRT 的演变

随着 Windows 8 的发布，微软发布了其著名且最常使用的操作系统 Windows 的全新架构。这个架构适用于所有设备和平台，包括手机、平板电脑、可穿戴设备等。由于这种单例方法，应用程序开发需要一个统一的方法，因此微软在其平台上添加了更多的工具和语言，从这个角度来看，JavaScript for Windows，或者 Win，就出现在了舞台上。

您可能会问，为什么它们采用了 JavaScript，而不是其他语言来扩展其网络编程的武器库？答案在于 JavaScript 的结构。在前几章中，我们了解到 JavaScript 被认为是基于网络编程的最佳工具，并且在许多场景中非常有用。微软已经利用了这种力量，并将其嵌入到 WinRT 平台中。通过添加这个平台，微软在其竞争对手中占据了优势，因为它现在可以接触到更多知道可以使用 JavaScript 为微软编程并且可以将作品展示给大量用户的程序员。

# 关于 WinJS 的一些细节

WinJS 作为一款开源的 JavaScript 库发布，由微软根据 Apache 许可证发布。最初，它旨在用于构建 Windows 应用商店的软件，但后来，它被广泛接受用于所有浏览器上。现在，它与 HTML5 结合使用，为基于 Brewers 的以及 Windows 应用商店的应用程序构建。

它最初是在 2014 年 4 月 4 日的 2014 年微软 Build 开发者大会上宣布的，自那时以来，它经历了从 1.0 到 3.0 版本的演变，其 SDK 内部功能和实现满满。

# WinJS – 它的目的和发行历史

WinJS 1.0 最初与 Windows 8.0 一起发布。以下是到目前为止值得注意的发行版本。发行历史如下：

| 发行名称 | 目的/重点领域 |
| --- | --- |
| WinJS 1.0 | 这是作为 Windows 8.0 的 JavaScript 库发布的。 |
| WinJS 2.0 for Windows 8.1 | 这是更新版本，在 GitHub 上发布为 Apache License。 |
| 为 Windows 的 WinJS Xbox 1.0 | 这是专门为 Xbox one for Windows 发布的。 |
| WinJS Phone 2.1 for Windows Phone 8.1 | 这是为 Windows phone 开发平台发布的。 |
| WinJS 3.0 | 这是于 2014 年 9 月发布的，用于改进跨平台功能、JavaScript 模块化和通用控件设计。 |

## WinJS on GitHub

由于 WinJS 是一个开源软件，它托管在 GitHub 上，作为 MSTF，微软开放技术。我假设你知道 GitHub 是什么以及它的用途；如果不知道，请查看[`github.com/`](https://github.com/)。

WinJS 的在线仓库分为三个基本部分：

+   WinJS 是用 TypeScript 编写的，可以在[`github.com/winjs/winjs`](https://github.com/winjs/winjs)找到。

+   用 JS 编写的 WinJS 模块，可以在[`github.com/winjs/winjs-modules`](https://github.com/winjs/winjs-modules)看到。

+   WinJS bower 是用 JS 编写的，可以在[`github.com/winjs/winjs-bower`](https://github.com/winjs/winjs-bower)找到。

这些仓库中的代码不断更新，全球程序员 24/7 提交错误修复，这是开源项目的唯一魅力。基础仓库位于[`github.com/winjs`](https://github.com/winjs)。

使用在线模拟器，你可以在[`try.buildwinjs.com`](http://try.buildwinjs.com)尝试 WinJS。

# HTML5，CSS3 和 JavaScript

HTML5、CSS3 和 JS 是 Web 应用程序开发的默认模型，原因之一非常强大。它们都不仅仅是技术；它们是标准。曾经有过这样的时代，公司习惯于推出自己的平台，并为程序员使用他们的平台提供许多赏金。在那个时代，对于开发者来说，在所有浏览器上保持应用程序的标准是一场噩梦，因此，很多时间都花在了项目的兼容性上，而不是实际特性的开发上。W3C 和其他标准维护机构解决了这一挫折，并开始研究行业主要玩家都能接受的标准。他们将使用这些作为基础，而不是为每个微小需求开发自己的标准。这导致了 HTML5 和 CSS3 的演变。由于 JavaScript 已经存在，并且被认为是浏览器的语言，因此它与剩下的两种技术结合，成为专有和开源项目的默认技术包。

现在，每个平台都可以使用这些，但语法上有一些微小的区别。这对程序员和工程师来说是一个福音，因为他们现在可以专注于解决业务问题，而不是兼容性。

# HTML5、CSS3 和 JavaScript 的 WT

WT 平台上的 JavaScript 允许程序员使用 HTML 和 CSS 构建应用程序。许多使用 JavaScript 的 WT 应用程序类似于为网站编写标记。除此之外，WT 上的 JavaScript 提供了一些附加功能，并引入了在这个平台上可以使用的一些不同方式。由于 WT 上 JavaScript 的实现平台之间有所不同，它在很大程度上采用了微软的风格，其中，利用默认的 JS 属性，WT 为 JavaScript 增加了一些额外功能。这提供了对触摸的增强支持，以及对 UI（用户界面）的外观和感觉更多的控制。这也提供了诸如`DatePicker`、`TimePicker`和`ListView`的控制器，以及对 WinJS 的专有访问。

# 需要将承诺与 WT 集成

JS 是 WT 平台上的主要语言之一。除了 JS 的好处，还有一些缺点。正如我们在上一章的讨论中所知，回调地狱是添加承诺的核心原因，这里也是如此。WT 也面临了同样的问题，但它通过将其实现为承诺来解决得足够快。对于 WT 的 JS，承诺是游戏规则的改变者，因为它使得编写健壮、可扩展、可维护的 Windows 平台应用程序变得容易。虽然 WT 不是第一个实现承诺的，但它是最快采用该概念并实现它的之一。

事实上，JavaScript 程序员开始使用 WT JS for Windows，由于它的高度可采用性，许多专业人士加入了这个社区。

# 使用异步编程时遇到的问题

只是为了刷新你的记忆，在第二章，*JavaScript 异步模型*中，我们学习了关于异步编程的大量知识，它是什么，以及 JS 是如何实现它的。我们都知道使用 JS 的问题在于它已经发展出了很高的复杂性，因为它在大多数操作中严重依赖于回调。在第二章，*JavaScript 异步模型*的*处理回调地狱*部分，我们看到如果回调变得无法控制，几乎不可能调试代码。那时提出了承诺范式来解决这个问题。当应用于 WT 时，JS 也有同样的情况。

# 启动承诺

Windows 库中为 JS 提供的异步 API 表示为承诺，如 common JS 承诺/提案所定义。一个人可以通过包括一个错误处理程序使他的代码更加健壮，这被认为是调试最重要的方面，正因为如此，许多 JavaScript 开发者更愿意使用承诺。

启动此快速入门的先决条件。

# 编写一个返回承诺的函数

以下是使用该示例代码，你可以有效地理解如何在 WT 中实现承诺。按照以下步骤操作：

1.  创建一个名为`IamPromise`的空白 Windows 运行时应用。

1.  添加一个`input`元素。

1.  添加一个显示 URL 结果的`div`元素。

1.  在`default.css`中添加样式说明，为应用程序添加一些呈现。

1.  为`input`元素添加一个更改处理程序。

1.  在更改处理程序中调用`xhr`。

1.  构建和调试应用程序，然后输入一个网址。

1.  在 VS2013 中用 JS 创建一个 WT 应用。

1.  添加一个`input`元素。

1.  在 HTML 中，使用以下代码创建一个`input`元素：

    ```js
    <div>
    <input id="inputUrl" />
    <!—the input id above is called input URL -- >
    </div>

    Add a DIV element that displays the result for the URL.

    <div id="ResultDiv">Result</div>
    <!—the div id named here as ResultDiv -- >

    Add the styling instructions to "default.css".

    input {
      // add your style statements here
    }
    ```

## 为输入元素添加一个更改处理程序。

使用以下代码了解`WinJS.Utilities.Ready`函数，该函数在 DOM 内容加载后的立即事件被调用。这是在页面解析后，但在所有资源都被加载之前的：

```js
WinJS.Utilities.ready(function () {

  // get the element by id
  var input = document.getElementById("inputUrl");
  // add our event listener here
  input.addEventListener("change", changeHandler);

}, false);
```

在更改处理程序中调用`xhr`。

在更改处理程序中通过传递用户输入的 URL 来调用`xhr`。之后，用结果更新`div`元素。`xhr`函数是返回承诺的函数。我们还可以使用承诺的`then`或`done`函数来更新 UI（用户界面），但在 WT 规范中`then()`和`done()`的使用之间有一个区别。`then()`函数在`xhr`函数成功返回或通过`XmlHttpRequest`产生错误时立即执行。相反，`done()`函数除了保证抛出未在函数内部处理的任何错误外，与`then()`函数相同：

```js
function changeHandler(e) {
  var input = e.target;
  var resDiv = document.getElementById("ResultDiv");

  WinJS.xhr({ url: e.target.value }).then(function completed(result) {
    if (result.status === 200) {
      resDiv.style.backgroundColor = "lightGreen";
      resDiv.innerText = "Success";
    }
  });
}
```

最后，是时候测试你的代码了。构建和调试应用程序，然后输入一个 URL。如果 URL 有效，那么在我们这个例子中名为`ResultDiv`的`div`元素应该变绿并显示**成功**消息。如果输入了错误的 URL，代码将不会做任何事情。

### 提示

在这里要记住的一点是，在输入 URL 后，可能需要在输入控件外部进行点击，以便发生更改事件。这通常不是情况，但作为一个提示，这是获取 promise 未来值的一个更简单的方法。

现在，第二好的部分来了——处理错误。

# 错误处理

使用 promise 的最佳部分是，错误处理和调试变得更加简单。仅仅通过添加几个函数，你不仅可以精确定位代码中的错误位置，还可以在控制台或浏览器上获取相关的错误日志。你不必总是添加`alert()`来调查错误的性质和位置。

同样的规则适用于我们之前的代码，我们可以在`then()`内部添加一个错误函数。记得在之前的代码中，当发生错误时，并没有显示错误吗？但是这次不同了。我们将添加一个错误处理程序，如果发现任何错误，它将把成功的背景颜色改为红色：

```js
function changeHandler(e) {
  var input = e.target;
  var resDiv = document.getElementById("ResultDiv");

  WinJS.xhr({url: e.target.value}).then(
    function fulfilled (result) {
      if (result.status === 200) {
        resDiv.style.backgroundColor = "lightGreen";
        resDiv.innerText = "Successfully returned the Promise ";
      }
    },
    // our error handler Function

    function error(e) {
      resDiv.style.backgroundColor = "red";

      if (e.message != undefined) {  // when the URL is incorrect or blank.
        resDiv.innerText = e.message;
      }

      else if (e.statusText != undefined) { // If  XmlHttpRequest was made.
        resDiv.innerText = e.statusText;
      }

      else {
        resDiv.innerText = "Error";
      }
    });
}
```

构建和调试应用程序，并输入 URL。如果 URL 正确，将显示成功，否则按钮将变红并显示错误消息。

### 提示

请注意，在前面的函数中，`error(e)`，我们将`e`参数与一个消息连接起来。采用这种做法将错误转换为字符串，因为它将显示更易理解的消息，这将帮助你调试和排除错误。

# 使用 then()和 done()函数链式调用 promise

就像规格一样，你不仅可以使用`then`和`done`函数来完成一个任务，还可以将它作为链式调用。这样，你也可以在代码内部创建自己的条件，使你的代码更加强大、优化和逻辑性。尽管如此，还是有一些限制，这也是逻辑上的限制。你可以添加多个`then()`，比如`then().then().then()`，但你不能这样做：`then().done().then()`。你可能会想知道背后的逻辑。每次`then()`都会返回一个 promise，你可以输入到下一个`then()`函数中，但当你添加`done()`时，它返回`undefined`，这打破了 promise 的逻辑，然而你从这样的链中得不到任何东西。

所以，简而言之，你可以这样做：`then().then().done()`。

然而，你不能这样做：`then().done().then()`。

这样的操作的通用示例可能如下所示：

```js
FirstAsync()
    .then(function () { return SecondAsync(); })
    .then(function () { return ThirdAsync(); })
    .done(function () { finish(); });
```

同时，要记住的是，如果你没有在`done()`中添加错误处理程序，而且操作出现错误，它会抛出异常，这将消耗整个事件循环。即使写在`try catch`块中，你也无法捕获这样的异常，而唯一能获取它的方式是通过`window.onerror()`。

然而，如果你不使用`then()`添加错误处理程序，情况就不会这样。它不会抛出异常，因为它不是这样设计的，相反，它只会返回一个处于错误状态的承诺，这可能会对后续的链式操作或处理输出造成更大的损害。所以，无论是使用`then()`还是`done()`，都要添加错误处理程序。

## 示例 1A —— 使用两个异步函数将网页下载到文件中

使用这个示例，我们将能够将网页下载到文件中。有几种方法可以做到这一点。最简单的方法是让浏览器为您保存文件，但这将是浏览器根据我们的指令行事的能力，而不是我们代码的能力。此外，您可以想象这个简单的操作如何很容易地解释如何使用两个异步方法来完成。

现在，来看看下面的代码：

```js
//WinJs code

WinJS.Utilities.startLog();

// Allocate the URI where to get the download the file.
var AllocatedUri = new Windows.Foundation.UriExample("http://www.packt.com");

// Get the folder for temporary files.
var temporaryFolder = Windows.Storage.ApplicationData.current.temporaryFolder;

// Create the temp file asynchronously.
temporaryFolder.createFileAsync("temporary.text", Windows.Storage.CreationCollisionOption.replaceExisting)
  .then(function (tempFile) {

    // lets start the download operation if the createFileAsync call succeeded

    var Iamdownloader = new Windows.Networking.BackgroundTransfer.BackgroundDownloader();
    var transfer = Iamdownloader.createDownload(uriExample, tempFile);
      return transfer.startAsync();
    })
    .then(

      //Define the function to use when the download completes successfully
      function (result) {
        WinJS.log && WinJS.log("File was download successfully ");
      });
```

再次，我们现在将解释每一行代码的作用。

有三个主要方法需要强调：`createFileAsync`、`startAsync`和`then`。

第一个`then`函数获取结果。然后将结果传递给处理函数。`BackgroundDownloader`方法创建下载操作，`startAsync`创建启动下载的例程。在这里，你可以看到`startAsync`是返回承诺的那个，我们将通过在第一个完成中返回`startAsync()`的值来将其与第二个`then()`链接起来。第二个`then()`负责完成处理程序，其参数包含下载操作。

## 示例 1B —— 使用 startAsync 将网页下载到文件中

另一种链式调用`then()`和`done()`函数的方法是，通过编写进度函数来跟踪异步操作的进度。由于这一点，我们不仅可以跟踪进度，还可以通过添加错误函数来获得很多关于错误条件的信息。

在下一个示例中，我们将看到如何使用`startAsync`函数和错误处理程序异步地将网页下载到文件中。这个示例的输出将与前一个相同，但机制稍有不同：

```js
// Allocate the URI where to get the download the file.
var AllocatedUri = new Windows.Foundation.Uri("http://www.packt.com");

// Get the folder for temporary files.
var temporaryFolder = Windows.Storage.ApplicationData.current.temporaryFolder;

// Create the temp file asynchronously.
temporaryFolder.createFileAsync("tempfile.txt", Windows.Storage.CreationCollisionOption.replaceExisting)
  .then(function (tempFile) {

    // lets start the download operation if the createFileAsync call succeeded

    var Iamdownloader = new Windows.Networking.BackgroundTransfer.BackgroundDownloader();
    var transfer = Iamdownloader.createDownload(uriExample, tempFile);
    return transfer.startAsync();
  })
  .then(
    //Define the function to use when the download completes successfully
    function (result) {
      WinJS.log && WinJS.log("File was download successfully ");
    },

    // this is where we add the error handlers which displays
    function (err) {
      WinJS.log && WinJS.log("File download failed.");
    },
    // Define the progress handling function.
    function (progress) {
      WinJS.log && WinJS.log("Bytes retrieved: " + progress.progress.bytesReceived);
    });
```

这段代码的唯一区别是正确添加了错误处理程序，这使得错误处理变得简单且易于阅读。

# 总结

在本章中，我们学习了承诺如何在 WinRT 中实现。我们看到了承诺在 Windows 平台上的演变以及它如何为不同的 Windows 设备做出贡献。我们还看到了它如何帮助 Windows 游戏机以及为 Windows 商店创建基于 Windows 的应用程序。

正是承诺的适应性使其在所有主要的前沿技术中找到了一席之地。即使是像微软这样的技术巨头也无法忽视它的存在，并且能够在当前和未来的技术中给予充分的关注和范围。

在下一章中，我们将学习承诺是如何在增长最快的服务器端 JavaScript 之一——Node.js 中实现的。


# 第六章：Node.js 中的承诺

在上一章中，我们学习了 WinRT 中的承诺以及它们是如何使用微软平台来实现的。承诺的概念比其他语言有更广泛的覆盖。这是开源技术中增长最快的概念之一。

在本章中，我们将讨论一种正在彻底改变现代网络开发进程并增强我们实时网络方法的 JavaScript 实现。这项令人惊叹的技术被称为 Node.js，它是一个用 JavaScript 编写的平台，基于 Google 的 V8 引擎。Node.js 中的承诺比其他任何平台或实现都要有趣、演变快和富有成效。让我们深入了解 Node.js 中的承诺能为我们实时网络提供什么。

# V8 引擎 – 机械结构

一个只有 F1 赛车手和跑车制造商才知道的术语，在 2008 年 Google 首次推出其惊人的网络浏览器 Google Chrome 时，被引入到了网络浏览器中。

就像许多现实生活中的产品和它们的机制被计算机行业复制和描绘一样，V8 引擎是近年来此类建模的真实例子之一。由于本书的重点是承诺，所以我们简要地看看 V8 引擎实际上是什么。

V8 引擎是一个非传统的带有八个气缸安装在曲轴上以产生额外马力的引擎。这个引擎比 V6（另一种 V 型引擎）更平稳，比 V12 引擎更便宜。

# Google Chrome 中的 V8 引擎

使 Google 在网络浏览器竞赛中位居首位的开源项目就是 Google Chrome。Chrome 是基于一种独特设计的 JavaScript 引擎 V8 构建的。基于 V8，Chrome 在很短的时间内就获得了全球用户的热烈欢迎和关注。它最初于 2008 年 9 月 2 日发布。然而，这个 V8 JavaScript 引擎究竟做了什么，使它比其他任何程序都更快、更出色呢？它并不涉及将高级语言解释器编译成机器代码。它基本上跳过了代码解释的中间部分，并将高级代码直接转换为机器代码。这就是 Chrome 之所以如此快速的原因：

![Google Chrome 中的 V8 引擎](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_06_02.jpg)

# Node.js 的发展

自从 Google Chrome 作为开源网络浏览器发布以来，人们开始对它产生兴趣。这种迅速的兴趣主要有两个原因。从普通用户的视角来看，它比任何其他网络浏览器都要快得多，而从开发者的视角来看，它通过将高级指令瞬间转换为机器代码，去除了完整的编译器或解释器的中间层，从而革命化了浏览器技术。

许多开发者开始探索代码库，寻找他们参与的解决方案的可能性，并充分利用这个新的、令人惊叹的代码库。

Ryan Dahl 是那些想尝试 V8 JavaScript 引擎的开发者之一，当时他在 Joyent 工作，忙于解决问题。问题是在上传过程中让浏览器知道还剩多少时间。受到最近发布的 V8 和 Ruby 的 Mongrel web 服务器的影响，他起草了后来演变成 Node.js 的代码基础。

# 关于 Node.js 的简要介绍

Dahl 创建的是现代 web 应用开发中的一个全新概念——Node.js 的第一个版本。

简单来说，Node.js 的服务器端 JavaScript 是基于谷歌的 V8 引擎构建的。Node.js 是一个基于事件和非阻塞 I/O 的平台。它轻量级、高效，最适合用于运行在分布式设备上的数据密集型实时 web 应用。

# 下载并安装 Node.js

你可以从 Node.js 的官方网站 [`nodejs.org/download`](http://nodejs.org/download) 下载 Node.js。

Node.js 适用于多种平台。选择你的操作系统，安装程序将引导你完成剩余步骤。

Node.js 作为开源项目也托管在 GitHub 上，位于 [`github.com/joyent/node`](https://github.com/joyent/node)，供全世界的开发者贡献其发展和开发。

安装说明非常简单易懂，只需按照与你的操作系统相关的安装程序操作。这个过程非常直接，无需太多麻烦即可完成。你只需要按照屏幕上的提示操作即可。

# Node 包管理器——NPM

使用 Node.js 的一个最大优点是 NPM（Node Package Manager），即 Node 包管理器。这是开发者通过更快的共享代码库来协作想法的有效方式。然而，这并不是全部。NPM 最好的用途之一是下载并安装一个称为**包**的不同简单代码目录。这可以通过简单地输入命令（如 `npm install express`）轻松完成，这将下载并在你的机器上安装整个包。每个包都有一个 `.json` 文件，其中包含有关该包的元数据。在类 Unix 环境中，Node 包管理器不仅可以帮助下载和设置其他包，还可以更新 Node.js 本身。

NPM 也是 Node.js 在 JavaScript 开发者社区中变得越来越受欢迎的另一个原因。与其他语言相比，在其他语言中上传库和二进制文件是非常耗时且需要权限的。而 NPM 是一个更快、更少关注权限的模型，吸引了开发者上传并与其他社区成员分享他们的作品。

有关 NPM 的更多信息以及如何贡献你的代码，请访问 [`www.npmjs.com/`](https://www.npmjs.com/)。

在后面的章节中，我们将看到 NPM 如何帮助我们安装和使用我们选择的包，以及使用 NPM 工作是多么的快速和流畅。

# 环境选择

Node.js 在平台独立性方面具有所有安装，设置和库，适用于目前可用的所有主要操作系统。它适用于所有基于 Unix 的操作系统，以及 Mac 和 Windows 平台。由于我们主要关注让您了解 Node.js 与承诺之间的联系，因此我们将基于 Windows 7（任何版本）平台进行代码示例，因为它是广泛可用的，并且 Node.js 在 Windows 7 上也可用且稳定。此外，它非常简单且节省时间。

### 提示

请记住，使用基于 Windows 的系统对代码及其输出没有任何影响。这对于任何操作系统都是相同的，没有任何更改。您可以毫不犹豫地将在任何其他操作系统上使用相同的代码库。

# 为 Node.js 设置环境

让我们熟悉一下环境以及如何使用 Node.js 完成事情。首先，最重要的是，我们必须知道如何设置以编译代码并在我们的机器上运行。

如果您阅读此部分，则假定您已经在计算机上安装了 Node.js 的最新版本；否则，请参阅前面的部分以下载和安装 Node.js。

在您设置 Node.js 之后，通过输入以下命令检查您计算机上可用的 Node.js 和 NPM 版本：

```js
D:\> node –v
D:\> NPM  –v

```

输出应该与以下截图类似：

![为 Node.js 设置环境](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_06_03.jpg)

检查 Node.js 和 NPM 的版本

请注意，当前的 Node.js 版本是 0.10.31，当前的 NPM 版本是 1.4.23。我们的示例将基于这些版本，不会低于这些版本。

# 一个简单的 Node 服务器

现在，我们已经准备好进行一些实验，让我们尝试一个简单的 node 服务器。为此，您只需要两款软件。一个是默认的文本编辑器，如 Windows 中的记事本或 Ubuntu 中的 Nano，以及一个网络浏览器。对于网络浏览器，我们建议使用 Google Chrome，因为它在所有平台上都很容易获得，并且与 Node.js 原生兼容。

所以，在您喜欢的文本编辑器中输入以下代码：

```js
// simple server written in Nodejs
// This server would be running on default IP http://127.0.0.1
var http = require('http');
http.createServer(function (request, response) 
{
  response.writeHead(200, {'Content-Type': 'text/plain'}); // this defines the MIME type of content
  response.end('Hello World\n'); // this is the browser's output. 
}).listen(1337, '127.0.0.1'); // 1337 is the port number where the browser is listing to this request. 
console.log('Server running at http://127.0.0.1:1337/'); //This line will show at command prompt  
```

使用任何名字以`.js`扩展名保存文件。在我们的示例中，我们使用名称`server_example.js`。将此文件保存在目录（例如`Promises_in_Node`）中，然后打开您的终端程序。对于 Windows，它是命令提示符。导航到您保存文件的目录，并输入以下命令：

![一个简单的 Node 服务器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_06_04.jpg)

如果代码没有错误，它将编译并在屏幕上显示以下输出：

![一个简单的 Node 服务器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_06_05.jpg)

现在，打开 Chrome 浏览器，在地址栏输入`http://127.0.0.1:1337/`并按下*Enter*键。这个屏幕会显示 Node.js 服务器的成功输出：

![一个简单的 Node 服务器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_06_06.jpg)

就是这些！现在您已经准备好深入研究 Node.js 中的承诺。

# 到目前为止我们所学的

让我们总结一下我们已经学到了什么。我们了解了 V8 引擎是什么，以及它是如何由 Google Chrome 作为 JavaScript 引擎开发的，Node.js 是什么，以及它是如何作为一个问题解决技术发展成为一个完整的应用程序开发平台的。我们学习了 Node 包管理器以及如何在 Node.js 应用程序开发中使用它。然后我们学习了如何下载 Node.js，如何安装它，以及开发 Node.js 时需要考虑的依赖项，最后，我们学习了如何使用 Node.js 编写简单的服务器并在浏览器中查看其输出。这是一个检查点，如果你对 Node.js 仍然感到困惑，请再次阅读，然后继续。

接下来的部分将让您更好地了解 Node.js 和承诺，以及承诺为何在 Node.js 开发者中获得如此多的尊重。

# 使用 Q 库的 Node.js

在第二章《JavaScript 异步模型》中，我们讨论了回调地狱是什么以及我们如何使用承诺来处理它。每种语言的实现也会有所不同。Node.js 也是如此。Node.js 中的承诺是以一种不同的方式实现的。在 Node.js 中，承诺不仅用于处理回调地狱，如果一个函数不能返回一个值或抛出一个异常，它也可以轻松地传递一个承诺。这与我们之前看到的章节有些不同。从 Node.js 的角度来看，一个承诺是一个代表返回值或能够抛出异常的对象，此外，它还可以作为远程对象的代理来提高延迟。

让我们来看一下下面的代码：

```js
process_one(function (value1) {
    process_two(value1, function(value2) {
        process_three(value2, function(value3) {
            process_four(value3, function(value4) {
                // Do something with value4 
            });
        });
    });
});
```

乱七八糟，不是吗？不仅乱七八糟，而且非常令人困惑，难以维护。现在，看看使用承诺以下的代码：

```js
Q.fcall(process_one)
.then(process_two)
.then(process_three)
.then(process_four)
.then(function (value4) {
    // Do something with value4 
})
.catch(function (error) {
    // Error Handler
})
.done();
```

现在，这段代码更清晰、更高效，并且有一个额外的特点，即隐式的错误传播，就像我们在 Java 中的`try`-`catch`和`finally`块一样，捕获任何不必要的异常，并在遇到意外条件时防止程序完全崩溃。

回调方法被称为控制反转，它是一个能够接受回调而不是返回值的函数。这种机制可以更容易地被描述为“不要调用我，我会调用你”的说法。

Q 中的承诺有一个非常特别的倾向，因为它清楚地使输入参数与控制流程参数独立。只有在使用和创建 API 时，尤其是在变长参数、剩余参数和展开参数方面，才能真正看到它的真正好处。

# 继续学习 Q

在简要介绍了 Node.js 和 Q 之后，让我们看看如何开发应用程序。首先，我们需要获取 Q 库以设置其模块。

使用 Node 包管理器，按照以下截图安装 Q 库：

![使用 Q 前进](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_06_07.jpg)

正如你所见，提示说它的`q`版本是 1.2.0，这是稳定版本，也向后兼容。我们将使用这个版本作为本章所有示例的依据。

在我们的环境和过去的升级中，我们现在可以尝试一些常见的、富有成效的承诺特性。

承诺有一个`then`方法，你可以用它来获取最终的返回值（满足）或抛出异常（拒绝）。到现在，我们都在阅读这本书的前几章后知道了这一点。

```js
iPromiseSomething() .then(function (value) { //your code }, function (reason) { //your code } );
```

以下是前面的代码行是如何工作的：

+   如果`iPromiseSomething`返回一个稍后得到满足的承诺，并带有返回值，第一个函数（满足处理器）将被调用

+   如果`iPromiseSomething`函数后来被抛出的异常拒绝，第二个函数（拒绝处理器）将被调用，并带有异常

正如你所见，承诺的解决总是异步的，这意味着满足或拒绝处理器总是在事件循环的下一轮（即 Node.js 中的`process.nextTick`）被调用。这种机制确保在满足或拒绝处理器被执行之前，它总是返回一个值。

# 在 Q 中的传播

`then`方法总是返回一个承诺，该承诺要么被处理，要么被拒绝。

在我们的示例代码中，我们将输出分配给`reapPromise`变量，它将持有该值：

```js
var reapPromise  = getInputPromise()
.then(function (input) {
}, function (reason) {
});
```

`reapPromise`变量是任一处理器的返回值的新的承诺。只有一个处理器会被调用，并且它将负责以函数的形式解决`reapPromise`，该函数只能返回一个值（一个未来的值）或抛出一个异常。

无论情况如何，都可能有以下几种结果：

+   如果你在处理器中返回一个值，`reapPromise`将被满足

+   如果在处理器中抛出了异常，`reapPromise`将被拒绝

+   如果在处理器中返回一个承诺，`reapPromise`将变成那个承诺

+   因为它将成为一个新的承诺，所以它在管理延迟、组合结果或从错误中恢复时将很有用。

如果`getInputPromise()`承诺被拒绝，而你忘记了拒绝处理器，错误将传递给`reapPromise`：

```js
var reapPromise = getInputPromise()
.then(function (value) {
});
```

如果输入承诺得到满足，而你失败了满足处理器，值将传递给`reapPromise`：

```js
var reapPromise = getInputPromise()
.then(null, function (error) {
});
```

当你只对处理错误感兴趣时，Q 承诺提供了一个 fail 简写：

```js
var reapPromise = getInputPromise()
.fail(function (error) {
});
```

如果你只为现代引擎编写 JavaScript 或者使用 CoffeeScript，你可以使用 catch 而不是 fail。

承诺还提供了一个`fin`函数，它类似于一个`finally`子句。当`getInputPromise()`返回的承诺要么返回一个值，要么抛出一个错误时，最终处理器将被调用，不带任何参数。

`getInputPromise()`返回的值或抛出的错误，除非最终处理失败，否则会直接传递给`reapPromise`；如果最终处理返回一个承诺，可能会延迟：

```js
var reapPromise = getInputPromise()
.fin(function () {
});
```

简而言之：

+   如果处理程序返回一个值，该值将被忽略

+   如果处理程序抛出错误，错误将传递给`reapPromise`

+   如果处理程序返回一个承诺，`reapPromise`将被推迟

最终的值或错误与立即返回的值或抛出的错误有相同的效果；一个值将被忽略，一个错误将被传递。

因此，当我们寻找传播时，我们需要记住我们从返回值中想看到什么。在使用 Q 的传播时，`then`、`fail`和`fin`函数是记住的关键。

### 提示

如果你为现代引擎写 JavaScript，你可能用`finally`代替`fin`。

# 链式和嵌套承诺

记得在第二章中学习过的承诺链吗？*JavaScript 异步模型*，我们了解了所有关于链式调用和回调地狱处理的事情？使用 Q 的 Node.js 版本与此相同。

在 Node.js 中使用 Q 链式承诺有两种方法：一种是在处理程序内部链式承诺，另一种是在其外部。

假设我们同时在做很多事情，我们可以像这样设置承诺链：

```js
f1_promise()
    .then(function() { return s1_promise(); })
    .then(function() { return t1_promise();  })
        ...
    .then(function() { return nth_promise();    });
```

所以，我们可以说`ANY_promise()`函数可以包含一些行为，这将返回一个承诺对象，最终返回一个结果。一旦真实结果返回，它将触发链中的下一个函数。

现在看起来不错，如果你想在异步函数中设置一个点，并在我们获得结果后再执行链中下一个承诺的行为，那会怎样？

Q 针对此问题有一个解决方案。使用`.defer()`和`deferred.resolve()`，你可以以更加可管理和可预测的方式得到结果。

# Q 中的序列

链式调用（chaining）之外，序列（sequences）也是另一种按照你的意愿来组织结果的方法。序列是一种预定义的方式来获得你所期望的场景结果。为了更紧密地控制结果并生成它们，Q 提供了一种独特的序列方式。

假设你有多个生成承诺的函数，它们都需要按顺序运行。你可以像这个例子这样手动完成：

```js
return seq(startValue).then(secondValue).then(thirdValue);
```

你必须确保每个`then()`都必须与其他`then();`在序列中，以保持序列。否则，序列将会中断，你将无法稍后获得另一个值。

另一种方法是动态地指导你的序列。这可能会更快，但在执行代码时需要更多的注意力，因为不可预测的代码可能会损害整个序列。

这是一个动态实现的代码片段：

```js
var funcs = [startValue, secondValue, thirdValue];

var result = Q(startValue); 
funcs.forEach(function (f) {
    result = result.then(f);
});
return result;
```

如果这看起来你使用了太多的代码行，使用`reduce`：

```js
return func.reduce(function (tillNow, f) {
    return tillNow.then(f); 
}, Q(startValue));
```

# Q 的组合

有了 Q，你在 Node.js 中就有了一个独特的功能，如果你想组合一个承诺列表的数组，就可以写出更干净、易管理的代码。这可以帮助你以更易管理的方式编写更复杂级别的顺序数据结构。我们如何达到这个目标呢？使用`all`。考虑以下示例：

```js
return Q.all([
    eventAdd(2, 2),
    eventAdd (10, 20)
]);
```

`Q.all([func1(), func2()]);`函数将是前述代码的通用形式。你也可以使用`spread`来替换`then`。我们可以用 Q 替换另一个新东西吗？事实上不行！`spread`函数将值扩散到完成处理器的参数中。对于拒绝处理器，它将获取失败的第一个信号。因此，任何注定要首先失败的承诺都将由拒绝处理器处理：

```js
function eventAdd (var1, var2) { 
    return Q.spread([var1, var2], function (var1, var2) {
        return a + b;
    })
}

Q.spread(). Call all initially

return getUsr() .then(function (userName) { return [username, getUser(userName)]; }) .spread(function (userName, user) {
});
```

调用函数时，它将返回`allSettled`。在这个函数内部，一个承诺将被作为数组返回，该数组持有值。当这个承诺被履行时，该数组包含原始承诺的履行值，在相同的序列中这些承诺。美妙的是，如果任何承诺被拒绝，它将立即被拒绝，而不是等待其他人到来并分享他们的状态：

```js
Q.allSettled(promises)
.then(function (results) {
    results.forEach(function (result) {
        if (result.state === "fulfilled") {
            var value = result.value;
        } else {
            var reason = result.reason;
        }
    });
});
```

`any`函数接受一个承诺数组，返回一个由第一个被履行的承诺实现的承诺，或者在所有给定的承诺都被拒绝时被拒绝：

```js
Q.any(promises).then(function (firstPromise) {
    // list of any of the promises that were fulfilled. 
}, function (error) {
    // All of the promises were rejected. 
});
```

# 如何在 Node.js 中处理 Q 错误

有时，承诺创建错误时会发生拒绝。这些错误足够聪明，可以避开分配来处理这些错误的处理程序。因此，我们需要明确地处理它们。

让我们看看以下片段，看看它如何被处理：

```js
return scenario().then(function (value) {
    throw new Error("I am your error mesg here .");
}, function (error) {
    // We only get here if scenario fails 
});
```

为什么会出现这种情况？假设承诺之间的并行性和`try`/`catch`，在我们尝试执行`scenario()`时，错误处理器代表`scenario()`的`catch`，而履行处理器代表`try`/`catch`块之后的代码。现在，这段代码需要自己的`try`/`catch`块。

`try`/`catch`块对于那些为一些主要语言编写代码的人来说并不是一个新概念。由于 Node.js 基于 JavaScript，而 Q 此刻正在处理它，所以语法可能有点不同，但功能基本上与以下代码相同：

```js
Q.
try(function()
    {return scneario().then(function(value)throw new Error("im your thrown error");)} )
.catch({ function (error)
    {console.error("i am catched",error)} 
});
```

简单来说，在承诺方面，这意味着你在串联你的拒绝处理程序。

# 使用承诺进行进度管理

与其他库不同，承诺有一个独特的通信能力。如果你想让它与你交谈，它可以更新你的进度。最好是，这些是通过开发者编程的方式，在指定的时间间隔内通知他们进展情况。我们可以通过使用我们最喜欢的`then()`函数来实现：

```js
return uploadFile()
.then(function () {
    // Success uploading the file 
}, function (err) {
    // There was an error, and we get the reason for error 
}, function (progress) {
    // this is where I am reporting back my progress. executed 
});
```

使用 Q 有很多优点。对于这个特定主题，它提供了一个简短的调用进度，通过使用`*.progress();`，将我们的努力减少到只有一行。

```js
return uploadFile().progress(function (progress) {
    // We get notified of the upload's progress 
});
```

# 到达承诺链的末端

当我们谈论结束一个承诺链时，我们必须确保在任何错误没有在结束前得到处理，因为如果处理不当，它会被重新抛出并报告。

这是一个临时解决方案。我们正在探索使未处理的错误可见，而无需任何显式处理的方法。

所以，返回的代码如下所示：

```js
return hoo()
.then(function () {
    return "foo";
});
Or we can do It like this:
hoo()
.then(function () {
    return "bar";
})
.done();
```

我们为什么要这样做？我们为什么需要以这种方式调用机制？答案非常简单，你必须结束链或必须将其返回给另一个承诺。这是因为处理程序捕获错误，这是一个不幸的模式，异常可能会被忽视。

偶尔，你需要从零开始创建一个承诺。这是很正常的；你可以自己创建一个承诺，或者从另一个链中获取它。无论哪种情况，都要考虑到这是一个开始。使用 Q，你可以以多种方式创建新的承诺。以下是一些示例：

```js
Q.fcall(); 
//Using this function fcall you can create and  call other //functions, along with Promise functions. To do that simply //follow this syntax 
return Q.fcall(function () {
    return 10; 
});
```

不仅如此，`fcall();`还可以用来获取一个异常处理的承诺，它看起来像以下代码片段：

```js
return Q.fcall(function () {
    throw new Error("I am an error");
});
```

由于`fcall();`可以调用函数，甚至可以调用承诺函数，因此它使用`eventualAdd();`函数来添加两个数字：

```js
return Q.fcall(eventualAdd, 2, 2);
```

# 基于回调的承诺与基于 Q 的承诺

假设你必须与基于回调而不是基于承诺的接口进行交互，你的选择会是什么？答案是 Q 提供了`Q.nfcall()`和`friends();`，但大多数时候，我们不得不依赖`deferred`：

```js
var deferred = Q.defer();
FS.readFile("hoo.txt", "utf-8", function (error, text) {
    if (error) {
        deferred.reject(new Error(error));
    } else {
        deferred.resolve(text);
    }
});
return deferred.promise;
```

通常，我们可以像这样实现它：

```js
//normal way of handling rejected promises.
deferred.reject(new Error("Can't do it"));
//this is how we do it
var rejection = Q.fcall(function () {
    throw new Error("Can't do it");
});
deferred.resolve(rejection);
```

## 关于延迟、超时和通知的一些话

有时候，我们想要让函数的输出有一定的延迟或比正常情况更慢。这时我们正在等待某个事件的发生，比如在强度指示器中检查密码的强度。

对于所有这些需求，Q 提供了一系列函数来给你这种控制。这些函数包括：

+   `Q.delay()`

+   `Q.notify()`

+   `deferred.notify()`

前面的函数不仅能够在需要时创建延迟，还能在延迟可能发生时进行通知。如果你想要推迟通知，可以使用`deferred.notify()`来实现目的。

## Q.delay()

以下代码是`Q.delay`的简化实现：

```js
function delay(ms) {
    var deferred = Q.defer();
    setTimeout(deferred.resolve, ms);
    return deferred.promise;
}
```

## Q.timeout()

使用`Q.timeout`的简单方法：

```js
function timeout(promise, ms) {
    var deferred = Q.defer();
    Q.when(promise, deferred.resolve);
    delay(ms).then(function () {
        deferred.reject(new Error("Timed out"));
    });
    return deferred.promise;
}
```

## deferred.notify()

最后，你可以使用`deferred.notify()`向承诺发送进度通知。

在浏览器中有一个 XML HTTP 请求的包装器：

```js
function requestOkText(url) {
    var request = new XMLHttpRequest();
    var deferred = Q.defer();
    request.open("GET", url, true);
    request.onload = onload;
    request.onerror = onerror;
    request.onprogress = onprogress;
    request.send();

    function onload() {
        if (request.status === 200) {
            deferred.resolve(request.responseText);
        } else {
            deferred.reject(new Error("Status code was " + request.status));
        }
    }

    function onerror() {
        deferred.reject(new Error("Can't XHR " + JSON.stringify(url)));
    }

    function onprogress(event) {
        deferred.notify(event.loaded / event.total);
    }

    return deferred.promise;
}
```

以下是如何使用这个`requestOkText`函数的示例：

```js
requestOkText("http://localhost:5000")
.then(function (responseText) {
    // If the HTTP response returns 200 OK, log the response text. 
    console.log(responseText);
}, function (error) {
    // If there's an error or a non-200 status code, log the error. 
    console.error(error);
}, function (progress) {
    // Log the progress as it comes in. 
    console.log("Request progress: " + Math.round(progress * 100) + "%");
});
```

# Q.Promise() – 创建承诺的另一种方法

`Q.Promise`是一个承诺创建的 API，它的功能与 deferred 概念相同，但不会引入另一个概念实体。

让我们用`Q.Promise`重写前面的`requestOkText`示例：

```js
function requestOkText(url) {
    return Q.Promise(function(resolve, reject, notify) {
        var request = new XMLHttpRequest();
        request.open("GET", url, true);
        request.onload = onload;
        request.onerror = onerror;
        request.onprogress = onprogress;
        request.send();

        function onload() {
            if (request.status === 200) {
                resolve(request.responseText);
            } else {
                reject(new Error("Status code was " + request.status));
            }
        }
        function onerror() {
            reject(new Error("Can't XHR " + JSON.stringify(url)));
        }
        function onprogress(event) {
            notify(event.loaded / event.total);
        }
    });
}
```

如果`requestOkText`抛出异常，返回的承诺将被拒绝，并以抛出的异常作为其拒绝的原因。

# Q 的静态方法

对 promises 对象的类型转换是必须的，并且你必须将不同来源生成的 promises 转换为 Q 类型的 promises。这是因为一个简单的事实，即不是所有的 promise 库都提供与 Q 相同的保证，当然也不提供所有相同的方法。

```js
//using when 
return Q.when(AmIAvalueOrPromise, function (value) {
}, function (error) {
});
//The following are equivalent:
return Q.all([a, b]);
return Q.fcall(function () {
    return [a, b];
})
.all();
```

大多数库只提供部分功能的 `then` 方法。另一方面，Q 与其他库非常不同：

```js
return Q($.ajax(...))
.then(function () {
});
```

如果你得到的 promise 不是由你的库提供的 Q 类型的 promise，你应该使用 Q 函数来包装它。你甚至可以使用 `Q.invoke();` 作为简写，如下面的代码所示：

```js
return Q.invoke($, 'ajax', ...)
.then(function () {
});
```

# Promise 作为代理

一个区分 promise 的奇妙之处在于，它不仅可以作为本地对象，也可以作为远程对象的代理。有一些方法让你自信地使用属性或调用函数。所有这些交换都返回 promises，以便它们可以被链式调用。

以下是可以用作 promise 代理的函数列表：

| 直接操作 | 使用 promise 作为代理 |
| --- | --- |
| `value.foo` | `promise.get("foo")` |
| `value.foo = value` | `promise.put("foo", value)` |
| `delete value.foo` | `promise.del("foo")` |
| `value.foo(...args)` | `promise.post("foo", [args])` |
| `value.foo(...args)` | `promise.invoke("foo", ...args)` |
| `value(...args)` | `promise.fapply([args])` |
| `value(...args)` | `promise.fcall(...args)` |

你可以通过使用这些函数而不是 `then()` 来减少往返，如果 promise 是远程对象的代理。

即使在本地对象的情况下，这些方法也可以作为特别简单的满足处理器的简写。例如，你可以替换：

```js
return Q.fcall(function () {
    return [{ foo: "bar" }, { foo: "baz" }];
})
.then(function (value) {
    return value[0].foo;
});
```

以下代码：

```js
return Q.fcall(function () {
    return [{ foo: "bar" }, { foo: "baz" }];
})
.get(0)
.get("foo");
```

# 熟悉 Node.js —— Q 方式

当你使用遵循 Node.js 回调模式的功能时，其中回调以 `function(err, result)` 的形式出现，Q 提供了一些有利的服务函数来适应它们之间。最重要的两个函数是：`Q.nfcall()` 和 `Q.nfapply()`：

+   `Q.nfcall()`：Node.js 函数调用

    ```js
    return Q.nfcall(FS.readFile, "foo.txt", "utf-8");
    ```

+   `Q.nfapply()`：Node.js 函数应用

    ```js
    return Q.nfapply(FS.readFile, ["foo.txt", "utf-8"]);
    ```

它们都用于调用具有类似 Node.js 外观的函数，以便它们可以生成 promises。

# 解绑及其解决方案

当你使用方法而不是简单函数时，你很可能会轻易遇到常见的问题，即传递一个方法到另一个函数（如 `Q.nfcall`）会解除方法与其所有者的绑定。Q 也提供了它的服务，以便你可以避免这个问题，通过采用这两种方式之一：

+   使用 `Function.prototype.bind()`

+   使用 Q 提供的这些方法：

    ```js
    return Q.ninvoke(redisClient, "get", "user:1:id"); // node invoke
    return Q.npost(redisClient, "get", ["user:1:id"]); // node post
    ```

还有一种创建可重用包装器的方法，使用：

+   `Q.denodeify`：

    ```js
    //using Q.denodeify
    var readFile = Q.denodeify(FS.readFile);
    return readFile("foo.txt", "utf-8");
    ```

+   `Q.nbind`：

    ```js
    // Q.nbind
    var redisClientGet = Q.nbind(redisClient.get, redisClient);
    return redisClientGet("user:1:id");
    ```

# Q 对跟踪堆栈的支持

Q 还扩展了对长堆栈跟踪的可选支持；这帮助开发者通过提供错误的整个原因和拒绝原因，而不仅仅是简单地停止，没有意义或可读的错误。

下面的函数就是这样一个例子，其中错误没有以有意义的方式处理，当有人尝试执行这段代码时，他/她经历了没有意义且无法追踪的错误：

```js
function TheDepthOfMyCode() {
  Q.delay(100).done(function explode() {
    throw new Error("hello I am your error Stack!");
  });
}
TheDepthOfMyCode ();
```

这将给我们一个看起来原始且不怎么有用的堆栈跟踪，类似于这样：

```js
Error: hello I am your error Stack!
 at explode (/path/to/test.js5:166)
 at _fulfilled (/path/to/test.js:q:54)
 at resolvedValue.promiseDispatch.done (/path/to/q.js:923:20)
 at makePromise.promise.promiseDispatch (/path/to/q.js:400:23)
 at pending (/path/to/q.js:397:39)
 at process.startup.processNextTick.process._tickCallback (node.js:244:9)

```

然而，如果你通过设置`Q.longStackSupport = true`来启用这个功能，那么这将给我们一个看起来类似这样的有用的堆栈跟踪：

```js
Error: hello I am your error Stack!
 at explode (/path/to/test.js:3:11)
From previous event:
 at theDepthsOfMyProgram (/path/to/test.js:2:16)
 at Object.<anonymous> (/path/to/test.js:7:1)

```

与大多数时候不同，在 JavaScript 中，我们使用断点或使用`alert()`来查看错误发生在哪里，这相当令人沮丧且耗时。Q 不仅给了我们一种优雅的方式来到达错误发生的地方，而且整个跟踪也可以被阅读和分析来解决问题。

### -   提示

在 Node.js 中，这个特性也可以通过设置`Q_DEBUG`环境变量来启用：

```js
Q_DEBUG=1 node server.js
```

这将启用 Q 的每个实例的长堆栈支持：

# 制作基于承诺的动作

从 Q 开始，执行返回 promises 的动作。比如说，把 Node.js 动作`http.get`作为承诺动作：

```js
// using-promise.js
var httpGet = function (opts) {
     var deferred = Q.defer();
     http.get(opts, deferred.resolve);
     return deferred.promise;
};
```

稍后，你可以使用：`httpGet(...).then(function (res) {...});`，但你需要确保函数返回 promises。第一个`Q.defer()`返回一个空承诺和对其的操作集合。`deferred.promise`是空承诺，它固定了一个特定的值：

```js
// promise-resolve-then-flow.js
var deferred = Q.defer();
deferred.promise.then(function (obj) {
    console.log(obj);
});

deferred.resolve("Hello World");
```

这将`Hello World`打印到控制台。通常，你可以将普通的回调动作转换为：

```js
// promise-translate-action.js
action(arg1, arg2, function (result) {
    doSomething(result);
});
```

承诺动作：

```js
// promise-translate-action.js
var promiseAction = function (arg1, arg2) {
    var deferred = Q.defer();
    action(arg1, arg2, deferred.resolve);
    return deferred.promise;
}

promiseAction(arg1, arg2).then(function (result) {
    doSomething(result);
});
```

# 对象处理 promises

我们学到了很多关于承诺如何帮助对象处理的知识，无论是本地对象还是远程对象。正如前面提到的，`then`回调可以使用结果以任何方式。此外，每个处理都被分解为属性访问或函数调用的基本操作，例如：

```js
// object-unsued.js
httpGet(url.parse("http://abc.org")).then(function (response) {
    return response.headers["location"].replace(/^http:/, "");
}).then(console.log);
```

## 原始访问的分解

-   `Q`可以分解每个原始访问的连续动作。让我们看一下以下的代码：

```js
// object-decomposed.js
httpGet(url.parse("http://abc.org")).then(function (response) {
    return response.headers;
}).then(function (handlers) {
    return handlers["location"];
}).then(function (location) {
    return location.replace(/^http:/, "");
}).then(console.log);
```

关于 Q 的 promises 还有一个好处。它们有一个支持原始访问的承诺方法。

通过它们，分解的动作也翻译为：

```js
// object.primitive.js
httpGet(url.parse("http://example.org"))
    .get("handlers").get("location").post("replace", [/^http:/, ""])
    .then(console.log);
```

# 查看重访

`view()`方法帮助将所有值镜像到基于 Q 的 promises 中，而无需任何区分，无论是来自一个值还是任何其他函数。有两种方法可以实现这一点：

+   `promise.post(name)`

+   `promise.send(name)`

这会将 promise 值的操作方法转换为方法结果的 promise。

`view()`的结果拥有 promise 值的所有方法。你可以在`view()`的`then`回调中使用`view`，例如：

```js
// object-view.js
Q.resolve(new Date()).view().then(function (dateView) {
    return dateView.toTimeString().then(function (str) {
        return /\((.*)\)/.exec(str)[0]
    });
}).then(console.log);
```

# 放弃一个 promise

我们之前看到了如何使用`done();`，但这里它以一种全面的影响出现。

使用`done();`，我们可以结束我们的承诺并放弃我们的程序。我总是有一种方法来链接承诺：

```js
then().then().done();
```

如果承诺已经被验证（并且在之前没有捕获到错误），`done()`函数将强制产生一个无法捕获的错误（例如，`setTimeout(function () {throw ex;}, 0)`）。

在 Node.js REPL 中，运行`Q.reject("uncaught").done()`，然后以错误退出。

如果错误已经传递到`done()`函数，你可以认为这只是编程中的一个错误（并不是异常状态）。

# 量子工具箱（Q）用于 Node.js

在这一章中，我们了解到承诺在 Node.js 中使用起来越来越方便。以下是由 Q 为 Node.js 提供的主要工具集合：

+   `Q.nfapply(fs.readFile, [filename, encoding]).then(console.log);`

+   `Q.nfcall(fs.readFile, filename, encoding).then(console.log);`

+   `Q.nfbind(fs.readFile)(filename, encoding).then(console.log);`

+   `Q.npost(fs, "readFile", [filename, encoding]).then(console.log);`

+   `Q.nsend(fs, "readFile", filename, encoding).then(console.log);`

Q 还有更多功能，但前面提到的是一些最好用、最常用、最合理的用法，这些可以帮助我们编写更易管理、更干净、更具有动态控制的机制。

# 总结

这一章从开始到结束都是一次美妙的旅程，并且从一开始就教导我们关于 Node.js 的知识。我们没有选择用计算机科学术语来解释东西，而是直接深入到了 V8 引擎的机械部分，从那里我们看到了真实世界对象如何映射到计算中。

我们学习了 Node.js 是什么，这个最惊人的库是从哪里开始的，是谁建造的，以及为什么和如何它帮助我们创建实时 web 应用。

然后我们转向了 Q，这是向 Node.js 提供承诺的最佳方式。我们看到了如何安装 Q，然后我们看到了与 Node.js 一起使用 Q 的不同方法。我们也实现了使用 Q 作为 Node.js 的承诺实现的目标。

这一章将鼓励你开始在 Node.js 上工作，特别是如何利用 Q 作为 Node.js 的承诺库。

在下一章中，我们将深入探讨 Angular.js 的世界以及它是如何实现承诺（promises）的。
