# 精通 JavaScript 高性能（一）

> 原文：[`zh.annas-archive.org/md5/582AFDEF15013377BB79AB8CEA3B2B47`](https://zh.annas-archive.org/md5/582AFDEF15013377BB79AB8CEA3B2B47)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

欢迎来到*精通 JavaScript 高性能*。在这本书中，我们已经以帮助任何 JavaScript 开发者，无论他们是新手上路还是经验丰富的老手的方式，覆盖了 JavaScript 性能。本书涵盖常见的性能瓶颈、如何在代码中寻找性能问题以及如何轻松纠正它们。

我们还回顾了优化我们的 JavaScript 代码的现代方法，不仅依靠对 JavaScript 的深入了解，还使用工具帮助我们优化代码。这些工具包括 Gulp 和 Node.js，它们有助于创建性能出色的构建，还有 Jasmine，一个 JavaScript 单元测试框架，有助于发现 JavaScript 中的应用程序流程问题。我们还使用 Apple Xcode 调试工具对 HTML 和 JavaScript 的混合应用程序进行调试。

# 本书内容概览

第一章，*追求速度*，解释了为什么需要更快的 JavaScript，讨论了为什么 JavaScript 代码传统上运行较慢，并展示了可以帮助我们编写更快 JavaScript 的代码编辑器类型，而无需改变我们的编码风格。

第二章，*使用 JSLint 提高代码性能*，探讨了 JavaScript 中的性能修复，并介绍了 JSLint，一个非常好的 JavaScript 验证和优化工具。

第三章，*理解 JavaScript 构建系统*，教你 JavaScript 构建系统及其在 JavaScript 性能测试和部署中的优势。

第四章，*检测性能*，介绍了 Google 的开发工具选项，并包含使用网络检查器改进我们的 JavaScript 代码性能的复习。

第五章，*操作符、循环和定时器*，解释了 JavaScript 语言中的操作符、循环和定时器，并展示了它们对性能的影响。

第六章，*构造函数、原型和数组*，涵盖了 JavaScript 语言中的构造函数、原型和数组，并展示了它们对性能的影响。

第七章，*避免操作 DOM*，包含有关编写高性能 JavaScript 的 DOM 复习，并展示了如何优化我们的 JavaScript 以使我们的网络应用程序渲染得更快。我们还将查看 JavaScript 动画并测试性能与现代 CSS3 动画相比。

第八章，*Web Workers 和 Promises*，展示了 Web Workers 和 Promises。这一章还教你如何使用它们，包括它们的局限性。

在第九章，*为 iOS 混合应用优化 JavaScript*中，涵盖了为移动 iOS 网络应用（也称为混合应用）优化 JavaScript。另外，我们查看了 Apple Web Inspector，并了解如何在 iOS 开发中使用它。

在第十章，*应用性能测试*中，我们介绍了 Jasmine，一个允许我们单元测试 JavaScript 代码的 JavaScript 测试框架。

# 本书你需要什么

对于这本书，你需要对 JavaScript 有基本的了解，知道如何在 JavaScript 中编写函数和变量，知道如何使用 HTML 和 CSS 等基本网络技术，以及使用 Chrome 开发者工具或 Firebug 等 Web 检查器进行一些基本的调试技能。

你需要一个文本编辑器，最好是能用于 HTML 和 JavaScript 编码的；可用的选择在第一章，*速度的必要性*中有所覆盖。选择编辑器和你在工作的系统中的管理权限由你自己决定，这也取决于你的预算。另外，第九章，*为 iOS 混合应用优化 JavaScript*，严格涵盖了 iOS 开发中的 JavaScript；为此，你需要一份 Xcode 和基于 Intel 的 Mac。如果你没有这些，你仍然可以阅读，但理想情况下，完成这项工作大多数需要使用 Mac。

# 本书面向谁

这本书是为中级 JavaScript 开发者编写的。如果你对用 JavaScript 进行单元测试和编写自己的框架有经验，并能够理解 JavaScript 中的基于实例与基于静态的区别，那么这本书可能不适合你。另外，如果你对 JavaScript 非常陌生——比如，“我怎么使用函数？”——我建议你也寻找一本 JavaScript 初学者的书。

然而，如果你已经对 JavaScript 有所了解，但新手于 node 风格性能测试、grunt 或 gulp 项目部署，以及 JavaScript 中的单元测试，或者如果你想知道如何更快地编写 JavaScript，或者如果你只是想阻止你的代码库落后，而无需重新工作你的编码风格，那么你读对了书。

# 约定

在这本书中，你会发现有许多种文本样式，用以区分不同类型的信息。以下是一些这些样式的例子，以及它们含义的解释。

文本中的代码词汇、数据库表名、文件夹名、文件名、文件扩展名、路径名、假 URL、用户输入和 Twitter 处理显示如下："为了解决这个问题，现代浏览器已经实现了新的控制台函数，称为`console.time`和`console.timeEnd`。"

代码块如下所示：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Jasmine Spec Runner v2.1.3</title>
```

**新术语**和**重要词汇**以粗体显示。例如，您在屏幕上、菜单或对话框中看到的词汇，在文本中以这种方式出现：“点击**下一页**按钮将您带到下一页。”

### 注意

警告或重要说明以这样的盒子形式出现。

### 提示

技巧和窍门就像这样出现。

# 读者反馈

来自我们读者的反馈总是受欢迎的。让我们知道您对这本书的看法——您喜欢什么或者可能不喜欢什么。读者反馈对我们来说非常重要，以开发您真正能从中获得最大收益的标题。

要向我们提供一般性反馈，只需发送电子邮件到`<feedback@packtpub.com>`，并在您消息的主题中提及书籍的标题。

如果您在某个主题上具有专业知识，并且有兴趣撰写或贡献一本书，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)上的作者指南。

# 客户支持

现在您已经成为 Packt 书籍的骄傲拥有者，我们有很多东西可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)账户下载所有您购买的 Packt 书籍的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册以便将文件直接通过电子邮件发送给您。

## 下载本书的彩色图像

我们还为您提供了一个包含本书中使用的屏幕截图/图表彩色图像的 PDF 文件。彩色图像将帮助您更好地理解输出的变化。您可以从以下链接下载此文件：[`www.packtpub.com/sites/default/files/downloads/7296OS_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/7296OS_ColorImages.pdf)。

## 错误

虽然我们已经尽一切努力确保我们内容的准确性，但是错误确实会发生。如果您在我们的某本书中发现了一个错误——也许是在文本或代码中——我们将非常感谢您能向我们报告。通过这样做，您可以节省其他读者的时间并帮助我们改进本书的后续版本。如果您发现任何错误，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**错误报告****表单**链接，并输入您错误的详细信息。一旦您的错误得到验证，您的提交将被接受，错误将被上传到我们的网站，或添加到该标题的错误部分现有的错误列表中。任何现有的错误可以通过选择您的标题从[`www.packtpub.com/support`](http://www.packtpub.com/support)查看。

## 盗版

互联网上的版权材料侵权是一个持续存在的问题，所有媒体都受到影响。 Packt 出版社非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何非法副本，无论以何种形式，请立即提供位置地址或网站名称，以便我们可以采取补救措施。

如果您发现任何疑似侵权的材料，请通过`<copyright@packtpub.com>`联系我们，并提供材料的链接。

我们感谢您在保护我们的作者和我们为您提供有价值内容的能力方面所提供的帮助。

## 疑问

如果您在阅读本书的过程中遇到任何问题，可以通过`<questions@packtpub.com>`联系我们，我们会尽最大努力解决问题。


# 第一章：速度的必要性

在本章中，我们将学习为何需要更快地执行 JavaScript，讨论为何 JavaScript 代码传统上较慢，并了解哪些代码编辑器可以让我们在不改变编码风格的情况下编写更快的 JavaScript。

# 网站一直很快吗？

似乎不久前，网站性能虽然重要，但对大多数网站来说并不是必需的。在网络早期，拥有一个真正慢的网站是很常见的——这并不是因为连接速度、服务器位置或所使用的浏览器。在许多情况下，这是因为用于渲染或为页面创建功能的 JavaScript 代码执行得很慢，*非常*慢。这主要是因为当时缺乏 JavaScript 的压缩工具和调试器，以及对今天常用的常见 JavaScript 实践的了解不足。

用户可以接受页面内容总是很慢，这主要是因为大多数用户使用 56K 调制解调器拨号到他们的**互联网服务提供商**（**ISP**）。连接过程中的哔哔声提醒用户。然后，突然间，用户在桌面上收到通知，告知连接已建立，然后根据是 Windows 95 上的 Internet Explorer 4 还是 NeXTStep 机器上的 Netscape Navigator，迅速打开默认的网页浏览器。这个过程是一样的，以及花费 2 分 42 秒做三明治，等待 HotBot 加载的时间。

随着时间的推移，用户开始体验谷歌，突然间，页面速度和加载时间似乎吸引了更多用户的注意力。然而，即便在今天，谷歌主搜索网站的简洁主题也能让整个网站的代码快速下载。无论互联网连接速度如何，根据 Safari 的时间线工具显示，整个过程仅需 1.36 秒，如下面的屏幕截图所示，这清楚地告诉我们哪些资源下载最快，哪些最慢。

这部分原因是，现代浏览器中使用的工具当时并不适用于 Internet Explorer 或 Netscape Navigator。在调试的早期阶段，JavaScript 结果是通过 JavaScript 警告进行调试的，因为当时没有现代工具。此外，今天的开发者工具集比简单的文本编辑器先进得多。

在下面的屏幕截图中，我们将向您展示使用 Safari 的网络检查器测量的网站下载速度：

![网站一直很快吗？](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_01_01.jpg)

## 变得更快

JavaScript 本质上是一种相当容易构建的语言。JavaScript 的一个优点是，JavaScript 是一种解释型语言，这意味着即使代码开发完成，仍可以根据项目规格部署和使用代码。

非编译代码既有优点也有缺点。由于无需编译，开发者可以很快地用全栈 web 应用程序构建一个网页，在非常短的时间内完成。这也对新手或中级开发者非常友好，总的来说，这让 web 项目的招聘变得稍微容易一些。

现在，不使用编译型语言的问题在于 JavaScript 是动态解释执行的，常见的错误往往被开发者忽略；即使代码看似运行正常，也可能并非高效运行。在开发工具主要是 Windows 上的记事本和网页浏览器的时代，任何错误都只能由用户发现，而与代码性能相关的问题则被排除在外。

今天，我们在 JavaScript 技能之上拥有各种工具集和构建系统。重要的是要理解，深入掌握 JavaScript 知识可以帮助你编写和审查更好的 JavaScript 代码，但在许多情况下，我们作为开发者毕竟只是凡人，会犯一些常见错误，影响我们的 JavaScript 代码——例如，在函数开始括号后不添加空格，或者忘记在代码语句末尾添加分号。

为给定项目选择一个合适的编辑器，该编辑器包括在编写 JavaScript 的第一行代码之前进行基本错误检查，可以显著提高我们代码库的性能和质量，而无需学习 JavaScript 内部工作原理的任何新知识。

## 选择有效的编辑器

选择一个好的编辑器可以在代码质量和编程效率方面有很大影响，如前文所述，我们开发者是人类，会犯错误，即使开发者的技能水平再高，也容易写出糟糕的 JavaScript 代码。所以，了解何时适合使用一种编辑器而非另一种对我们来说非常重要。为了说明这一点，我将把不同的 JavaScript 代码编辑器分为以下四个类别：

+   集成开发环境

+   中档编辑器

+   轻量级编辑器

+   基于云的编辑器

每种类型的编辑器都有其自身的优点和缺点，我们将讨论在什么情况下使用一种编辑器而不是另一种，从最大的编辑器开始。目的是展示在 JavaScript 开发中，何时适合从大型代码编辑器切换到小型编辑器。

### 集成开发环境

**集成开发环境**（**IDE**）是高级的软件工具，它们不仅提供代码编辑功能，还包括代码组织工具、内置测试工具、代码优化脚本、源代码控制集成，以及通常深度的代码提示和完成支持。

使用 IDE 的缺点是，IDE 被设计成在文件更新时不断检查代码，而在代码被编写时，这会导致编辑器在某些时候变得迟缓和不响应，在较慢的系统上使用起来痛苦不堪。通常，JavaScript 开发者倾向于不喜欢这些 IDE 的迟缓，转而使用其他更快速的编辑器。

当大型项目启动时，这可能会造成问题，用户使用了一个不适合以正确方式结构化 JavaScript 的编辑器。通常建议当项目只需要进行一些小的调整时，你应从 IDE 开始，然后逐步向下。

在接下来的部分，我们将讨论一些流行的 JavaScript IDE。

#### 微软 Visual Studio IDE

如果有一个软件与“IDE”这个术语直接相关，那微软的 Visual Studio 就是其中之一。下面这张截图展示了微软 Visual Studio IDE：

![微软 Visual Studio IDE](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_01_02.jpg)

它支持多种语言，包括 HTML、CSS 和 JavaScript，同时还能处理诸如 C#、Visual Basic、Python 等语言。在 JavaScript 方面，Visual Studio 会在项目的 JavaScript 代码流中深入检查，寻找许多轻量级编辑器找不到的小错误。

对于 JavaScript 开发者来说，微软 Visual Studio Express 版对于 Web 项目应该已经足够强大。

#### JetBrain 的 WebStorm IDE

对于那些不喜欢 ASP.NET、寻找专用 JavaScript IDE 的 JavaScript 开发者，以及需要 Mac 或 Linux 解决方案的用户，不妨看看下面截图中 JetBrain 的 WebStorm IDE：

![JetBrain 的 WebStorm IDE](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_01_03.jpg)

这个 IDE 主要针对 JavaScript 开发，它能处理*任何*你抛给它的 JavaScript 技术：node、AngularJS、jQuery……WebStorm 支持的技术列表长篇累牍。它还提供了完整的代码提示和错误检查支持，与 Visual Studio 类似，并且它具有非常强大的源代码控制支持，包括 Git、SVN，甚至还有微软的 Team Foundation Server。

现在让我们看看 JetBrains 旗下的 WebStorm，与 IntelliJ IDEA 相比，它是一个较低级别的 IDE，而 IntelliJ IDEA 是 JetBrains 针对*每种*语言推出的旗舰编辑器。下面这张截图展示了 IntelliJ IDEA 编辑器的用户界面：

![JetBrain 的 WebStorm IDE](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_01_03a.jpg)

通常，IDEA 以其作为 Java 专用 IDE 而闻名，但它包含了与 WebStorm 相同的工具以及更多其他工具。与 Visual Studio 一样，它能够处理多种语言，但这以牺牲性能为代价。例如，如果我们在一台较慢的系统上同时在这两个环境中工作，我们可能会发现在日常处理 JavaScript 项目时 IDEA 比 WebStorm 有更多的延迟。

同样，这是由于 IDE 需要运行许多后台功能来优化我们的代码，这在 IDEA 上更为明显；因此，再次强调，一开始使用 IDE 建立良好的代码结构是非常好的，但随着时间推移，我们在一个慢速编辑器中反复工作时，我们需要一些更快的、已经设置好的良好基础的东西。

考虑到这一点，许多没有看到 IDE 性能问题的开发者倾向于坚持他们选择的 IDE；然而，其他开发者转向了下一节中提到的编辑器。

### 中档编辑器

中档编辑器非常适合已经度过早期开发阶段的项目，或者是非常小的项目。早期使用集成开发环境（IDE）的一个例外是小型项目。这些通常是基于内容管理系统（如 WordPress、Joomla、Drupal 等）的网站，其中大部分 JavaScript 代码已经为开发者编写并经过测试。

它们还适用于轻量级的代码提示，有些可以连接到源代码库或 FTP，以上传代码。这些与 IDE 真正的区别在于编辑器的速度和缺乏代码质量特性。许多这类编辑器只查找代码中的明显错误，例如在 JavaScript 中遗漏分号。尽管如此，它们是非常有用的全能编辑器。

#### Panic 的 Coda 编辑器

Coda 是一个仅限 Mac 的编辑器，但它支持 HTML、CSS 和 JavaScript 编码。下面的屏幕截图展示了 Coda 的用户界面：

![Panic 的 Coda 编辑器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_01_04a.jpg)

它还支持 Python 和 PHP，但它不是专门用于独立运行非 Web 代码的。它还具有手动验证 JavaScript 的特性，而不是持续的，因此，再次强调，有些支持可以提高你的 JavaScript 和 Web 代码，但在你编写代码时，它并不总是完全检查错误。

#### 微软 WebMatrix 编辑器

WebMatrix 是微软在中档类别中的更轻量级网站编辑器。它支持 Git 和团队基金会服务器，以及 ASP.NET 项目、PHP 和 NodeJS。WebMatrix 的用户界面可以在下面的屏幕截图中看到：

![微软 WebMatrix 编辑器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_01_04_.jpg)

WebMatrix 是中档编辑器的一个例子，在选择要为项目使用的编辑器时，你可能需要考虑编辑器的特性。

例如，如果你需要支持 Python 的 Mac 系统，那么 Coda 是一个不错的选择，而 WebMatrix 则提供了一套不同的特性，包括 ASP.NET 支持。这是中档编辑器中的一个常见主题，其中许多编辑器实际上是设计来完成某些事情，并提供尽可能最小的代码支持，同时使编辑器尽可能快速。

对于这类编辑器，我们可以看到它们允许我们轻松连接到现有项目，并在相对快速的编辑器中进行一些代码检查。

### 轻量级编辑器

有时我们作为 JavaScript 开发者*根本不在乎*项目使用的后端平台，只需要一个简单的文本编辑器来编写一点 JavaScript 代码或更新一个 HTML 文件。这时轻量级编辑器就能派上用场。

#### Sublime Text 编辑器

Sublime Text 是一个非常流行、跨平台的轻量级编辑器。其用户界面如下截图所示：

![Sublime Text 编辑器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_01_05.jpg)

它因启动和使用的速度以及一些基本编辑功能（如语言高亮提示和多语言支持的基本代码提示）而闻名。

它还有一个自己的包管理器叫做**包控制**，这个功能可以让您扩展 Sublime Text，以自动化一些常见的代码编辑和编译过程。尽管刚下载时非常轻量级，但它允许开发者添加所需的常见插件，以适应他们的开发工作流程。

#### Notepad++编辑器

Notepad++编辑器的用户界面如下截图所示：

![Notepad++编辑器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_01_06.jpg)

在 Windows 平台上，有一个专为 Windows 平台设计的 JavaScript 编辑器——Notepad++。与 Sublime Text 类似，Notepad++主要用作文本编辑器，并支持插件，但它不像 Sublime Text 那样使用包管理器，因此即使支持插件，应用程序的运行速度也非常快。它还支持一些项目文件的代码提示，包括 JavaScript。

在这些编辑器或任何其他轻量级编辑器的情况下，由于它们通常不包含代码验证功能，因此它们在后台运行验证，可以轻松快速地进行代码更新，但存在编写速度慢或损坏代码的风险。

### 基于云的编辑器

最后，基于云或网络的编辑器是网络开发者工具箱中的新工具。它们允许开发者在浏览器中作为网页浏览器的插件或纯粹在线编辑代码库，使开发者能够在任何操作系统平台上工作，包括 Chrome OS、iPad 或 Android 操作系统，而这些系统你可能不会考虑用 JavaScript 来编写！

在浏览器中编写代码的优势在于，项目代码托管在线上，无论是 Git 还是编辑器托管服务。一些插件编辑器允许您像其他任何编辑器一样从计算机的硬盘驱动器上工作，但它们是用 HTML 和 JavaScript 编写的，带有后端（如 Python、PHP 或 ASP.NET），就像其他任何网站一样。

通常，这些编辑器在功能上属于中等水平的编辑器。然而，其中一些在功能上非常有限，除了无需安装编辑器即可在线使用之外，这就是它们属于这个类别的原因。接下来的部分将举几个流行的云编辑器的例子。

#### Cloud9 编辑器

Cloud9 编辑器，可从[`c9.io/`](http://c9.io/)获得，是一个通用的 Web 应用程序 IDE，但也是一个基于云计算的应用程序，支持 HTML5、PHP、Node.js、Rails、Python/Django 和 WordPress。以下屏幕截图显示了 Cloud9 编辑器的用户界面：

![Cloud9 编辑器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_01_07.jpg)

它还允许从 Git URL 或 GitHub 项目中克隆，因此你可以选择让您的代码托管在 Cloud9 中，或与您的 Git 仓库同步。

Cloud9 的另一个功能是从浏览器中支持 iOS 模拟器的虚拟机，以及为 Node.js 提供控制台支持——这一切都在浏览器中完成。

#### Codenvy 编辑器

另一个在线集成开发环境（IDE）——Codenvy——可访问[`codenvy.com/`](http://codenvy.com/)。其用户界面可从以下屏幕截图中看到：

![Codenvy 编辑器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_01_08.jpg)

这个编辑器与 Cloud9 非常相似，但它托管云服务项目，如谷歌的 App Engine。它还可以为 Android 构建应用程序，同时为 AngularJS 或 jQuery 等流行库提供完整的 JavaScript 支持。

云编辑器的一个问题是，当项目涉及 JavaScript 库时，在线编辑器可能无法识别库特定的 JavaScript 或 HTML 标签约定，因此在选择云编辑器时，考虑功能非常重要。

对于云编辑器，你可以看到它们遵循中等水平的编辑器功能集，但允许快速连接和更新现有项目。

# 总结

在本章中，我们回顾了 JavaScript 性能的历史，并学习了它是如何成为开发者和企业关注焦点的。我们还回顾了四种 JavaScript 代码编辑器的类型，现在我们理解了如何从大型集成开发环境（IDE）迁移到全新项目的轻量级编辑器，以及对于小更新和改动如何使用轻量级编辑器。

在下一章中，我们将探讨在使用轻量级编辑器时如何保持代码的高性能质量。


# 第二章：使用 JSLint 提高代码性能

在本章中，我们将学习如何确认 JavaScript 中的性能修复，并将学习 JSLint。有两个非常好的 JavaScript 验证和优化工具，我们将学习如何使用这两个工具以及如何设置选项以获得最佳代码性能优化结果。

因此，在本章中，我们将涵盖以下主题：

+   检查 JavaScript 代码性能

+   什么是 JavaScript 代码检查？

+   使用 JSLint

# 检查 JavaScript 代码性能

在我们谈论如何提高 JavaScript 性能之前，我们必须问自己一个关于代码改进实际上如何提高 JavaScript 应用程序速度的难题。在 JavaScript 开发的早期阶段，许多性能改进主要是基于已知的 JavaScript 编码标准实现的，关注未声明变量的全局变量，保持变量范围一致，等等，而没有太多的验证超出网站内部可见性的任何东西。

今天，我们有新的 API 可以利用这个问题，为代码的小部分提供解决方案。

## 关于 console time API

为了解决这个问题，现代浏览器实现了新的控制台函数，称为`console.time`和`console.timeEnd`。这两个函数的作用是允许开发人员为`console.time`和`console.timeEnd`函数指定一个标签，测量`time`和`timeEnd`实例之间的代码块所需的时间，最后，在控制台中显示结果。

让我们看看如何在实际例子中使用`console.time()`和`console.timeEnd()`。在这里，在我们的`02_01.js`示例文件中，我们有一个简单的代码块，使用`new`关键字在`for`循环内部创建 100 个简单的 JavaScript 对象，如下面的屏幕截图所示：

![关于 console time API](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_01.jpg)

### 提示

**下载示例代码**

您可以从您购买的所有 Packt 书籍的账户中下载这些示例代码文件[`www.packtpub.com`](http://www.packtpub.com)。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接通过电子邮件发送给您。

正如我们在第 5 行所看到的，我们调用了`console.time`函数，在其内部作为参数，我们有代码块的`100 objects in For Loop`字符串标签。然后在第 7 行，我们添加了一个`NewObj`对象构造函数。接着，在第 11 行，我们有一个简单的 JavaScript`for`循环，创建了`100`个`NewObj`构造函数的实例，从第 13 行的`for`循环中的每个实例传递值。最后，在第 16 行，我们使用与`time`实例开始时声明的相同标签结束时间块，调用`console.timeEnd`函数。

让我们在浏览器中尝试这个代码；我将使用 Google Chrome，但任何现代浏览器，如最新版本的 Firefox、Internet Explorer 或 Safari，都应该可以。我们将打开浏览器 URL 中的`about:blank`，以便我们可以有一个简单的工作环境，然后我们将打开我们的网络检查器或浏览器调试器，将代码片段粘贴到我们的控制台中，并按下*Enter*。以下是在我的浏览器中显示的结果：

![关于控制台时间 API](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_02.jpg)

如果我们看输出中`undefined`行之前的部分，我们可以看到在`console.time`函数中定义的标签输出：`100 objects in For loop: 0.274ms`。所以，有了这些确切的数据，我们可以直观地看到我们编写的代码块需要`0.274ms`的 JavaScript 解释器来处理这部分代码。很好，但如果我们调整我们的代码使其更有效率，比如说，将我们的`for`循环改为停止在`10`而不是`100`。那么，这是我们示例文件中`02_02.js`文件的更新代码样本：

![关于控制台时间 API](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_03.jpg)

在这里，我们在第 5、11、12 和 16 行改变了`for`循环的迭代次数；让我们运行这段代码，看看会出现什么情况，如下面的屏幕截图所示：

![关于控制台时间 API](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_04.jpg)

我们现在可以看出，将`for`循环的迭代次数从`100`次减少到`10`次，我们的处理时间从`0.274ms`降低到了`0.099ms`。我们知道这个性能测试 API 在评估我们的 JavaScript 代码性能时非常有帮助，因此我们可以想象将这个方法应用到更大型的应用中。

## 何时使用 console.time

`console.time()`方法允许开发者了解哪些代码会影响性能，哪些不会。`console.time()`方法基于你使用的浏览器、操作系统和系统硬件来提供结果。如果你运行了前面代码片段，它们应该接近于本书中给出的值，但很可能由于小的偏差而不是完全相同。

所以，在使用`console.time()`时，把它当作一个指南而不是一个确切的结果。当我们通过书籍使用`console.time()`方法时，这里列出的结果和你根据你的工作环境得到的结果可能会有所不同。然而，你应该能保持一致地看到使用`console.time()`方法后性能的总体提升。

现在我们已经掌握了性能测试的知识，我们将开始学习 JavaScript 中常见的性能瓶颈，但在深入这些概念之前，我们将先了解有助于评估过程的工具。

# 什么是 JavaScript 代码格式化？

在讨论 JSLint 之前，我们需要讨论一下代码检查器（linters）的一般概念，它们是什么以及它们如何影响 JavaScript 的性能。简单地说，lint 就是一个代码验证检查器。它允许开发者指向一个代码文件，并检查从空格问题到纯粹的代码错误等错误或潜在问题。

代码检查器通常会接收文件的正文并构建一个源树。在 JavaScript 的情况下，这可以是全局变量、函数、原型、数组等对象。创建树后，分析器会取源树的某些部分并报告任何分析器会标记的内容。最后，任何在运行 linter 之前标记的规则读者或参数将寻找任何忽略的选项并生成最终报告。

常见的 JavaScript 选项规则读者可能包括检查 EcmaScript 3、允许空格、允许 `continue` 关键字、允许 `if` 语句的非严格条件等设置。

## 关于 JSLint

JSLint 是一个由 JavaScript 编写的 JavaScript 代码分析工具，由 Douglas Crockford 编写，他还帮助在软件开发中普及了 JSON。正如第一章《速度的必要性》所提到的，JSLint 可以用多种方式使用。许多集成开发环境（IDE）的功能不仅仅是编辑代码，其中一些功能包括错误检查等，在某些情况下，IDE 会使用 JSLint 的一个版本。

在本章中，我们将讨论如何使用官方 JSLint 在线网站 [`www.jslint.com/`](http://www.jslint.com/)，如下面的屏幕截图所示：

![关于 JSLint](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_05.jpg)

## 使用 JSLint

使用 JSLint 非常简单，你只需要一些 JavaScript 并将你的代码文件粘贴到 JSLint 中。让我们尝试一个小的代码样本，如下面的屏幕截图所示，你可以在示例文件中参考它作为 `02_03.js` 文件：

![使用 JSLint](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_06.jpg)

现在，让我们将我们的代码粘贴到 [`www.JSLint.com`](http://www.JSLint.com) 输入框中，并点击**JSLint** 按钮。立即，我们应该在网站上看到底部的**JSLint** 按钮下出现一个错误列表，如下面的屏幕截图所示：

![使用 JSLint](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_07.jpg)

请参阅以下剩余错误：

![使用 JSLint](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_08.jpg)

## 审查错误

在查看这些错误之前，让我们看看错误列表的底部；我们会看到一个错误：`Stopping. (52% scanned)`。这是一个警告，JSLint 找到了如此多的错误，以至于 JSLint 的分析工具 simply gave up 审查错误。在审查 JSLint 消息时，记住这个错误很重要；因为只有 52% 的代码被审查，在我们修复它们之后，可能还会出现额外的错误。

好的，现在我们已经理解了 JSLint 的限制，让我们来修正这些错误。在处理 JSLint 时，从上往下处理错误列表，所以错误 1 是`意外字符'(空格)'。`那么这是什么意思呢？为了说明，JSLint 对 JavaScript 文件中的空格方式非常挑剔。JavaScript 解释器假设在某些 JavaScript 对象和变量中具有特定的空格。

这段空白空间出现在代码中的其他错误之前，所以我们可以假设这个错误出现在任何代码出现之前，实际上确实如此。如果我们查看`02_03.js`文件，实际上第 4 行是导致问题的地方，这是注释头和我们的`my_count`全局变量之间的空格。

## 配置杂乱的空格

我们可以通过两种方式解决我们的空格错误：我们可以逐行审查并更正，或者如果我们使用压缩工具，我们可以告诉 JSLint 忽略空行和不必要的行。为此，我们将导航到页面底部的**选项**，并将**杂乱空格**选项设置为**true** *.*这将告诉 JSLint 忽略与代码解释直接关联的任何空格问题，如下面的截图所示：

![配置杂乱的空格](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_09.jpg)

一旦设置为**true**，我们将在选项下面看到一个新的面板出现，叫做**JSLint 指令**。**JSLint 指令**面板提供了一个 JSLint 在审查代码之前将传递的参数的快速列表，在执行验证器之前。在这里看到指令非常有帮助，如果我们试图在其他 JSLint 实例中复制粘贴这个配置，比如说在一个构建系统中……关于这一点稍后会详细说明。

在忽略杂乱空格后，我们可以重新运行 JSLint 并看到错误列表的更新，如下所示：

![配置杂乱的空格](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_10.jpg)

现在，我们检查一下 JSLint 检测到的代码量。这次，如果我们看看最后一个错误，可以看到 JSLint 在`84%`的地方停了下来，这比以前好多了，但我们还有提升的空间。让我们看看第一个新的错误。在错误列表的顶部，我们可以看到错误提示`'my_count'在定义之前就被使用了。`这是在**错误**面板的第 5 行，第 1 个字符。

这表明我们忘记在`my_count`变量之前声明`var`，所以让我们按照下面的截图进行更新，在第 5 行给`my_count`添加`var`，然后让我们重新运行 JSLint。您可以在练习文件中参考更新，文件名为`02_03_01`.js`：

![配置杂乱的空格](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_11.jpg)

接下来，在我们更新后的代码中重新运行 JSLint 后，让我们看看接下来的两行。第一行显示`Unexpected TODO comment`。这相当直接；在 JSLint 中，我们可以指定允许**TODO comments**在我们的 JavaScript 代码中，这非常方便！让我们允许这个，因为我们现在只是在 JSLint 中改进我们的代码，现在不是完成文件的时候。请查看我突出显示的选项，您可以在其中设置是否允许 TODO：

![配置杂乱的空格](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_12.jpg)

现在，我们在**选项**面板中设置**TODO 注释**为**true**；接下来，让我们看看剩下的错误。

## 了解 use strict 语句

所以，现在留在我们 JSLint 错误列表中的是以下截图所示。接下来我们看到的是`Missing 'use strict' statement.`。现在，如果你之前没有在 JavaScript 中看到过`use strict`语句，我会解释：

![了解 use strict 语句](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_13.jpg)

`use strict`语句是提示浏览器在运行时读取 JavaScript 时启用*严格模式*的提示。这允许通常作为警告显示的错误在我们的浏览器中作为错误返回。在代码中使用`use strict`语句的另一个优点是，它允许 JavaScript 解释器运行得更快，因为它假设代码已经过优化和彻底测试。这告诉 JavaScript 解释器这里的代码已经正确编写，解释器在运行时不必对代码进行那么多检查。

使用`use strict`语句并不难实现，我们可以在每个函数内的任何代码前添加它，像这样：

![了解 use strict 语句](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_14.jpg)

我们也可以在全球范围内在完整的 JavaScript 文件中包含它，通过在代码的第一行上方添加它，如下面的截图所示：

![了解 use strict 语句](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_15.jpg)

关于`use strict`语句，有一点需要了解的是，JSLint*更倾向于*在函数级别设置`use strict`语句（如第一个`use strict`示例中所示）。这样做的想法是，它正确地为`use strict`语句设置了作用域，以便根据函数更好地进行代码测试和分析，但两种方式在 JavaScript 中都是正确的。

让我们结束这些剩余的问题，在我们的`TODO`注释下；在第 9 行，我们将添加`"use strict"`，然后在我们`console.log`语句之后的第 10 行添加一个分号。完成后，它应该类似于以下截图：

![了解 use strict 语句](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_16.jpg)

## 在 JSLint 中使用控制台

我们几乎完成了这段代码。然而，在执行它时，我们会得到一个错误列表，其中第一行可能看起来很奇怪，它指出：`'console'在定义之前就被使用了。`在**错误**面板中。JSLint 可以验证可能不为浏览器设计的 JavaScript；这可能是 Node.js 脚本，例如。为了启用浏览器对象，我们需要在我们的 JSLint**选项**面板中启用**控制台，警告，...**和**浏览器**选项；我们可以将这些设置为**真**，如下面的截图所示：

![在 JSLint 中使用控制台](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_17.jpg)

启用这些功能后，让我们重新运行脚本；剩下的错误应该很简单。第一个错误抱怨说我们应该`将这个与之前的'var'语句结合起来。`。我们可以删除`number1`和`number2`变量，简单地赋值`my_count = 42;`。

最后，我们的`if`语句需要做一些工作。首先，JSLint 抱怨我们在`if`语句中使用了一个松散的条件（比较时使用双等号）。如果我们使用三元等号进行比较，我们会同时比较类型。这样做，我们的代码将比以前更快地进行比较。另外，`if`语句没有在条件代码周围包含括号，这可能会减慢解释器的速度，所以让我们添加它们。我们的最终代码应该类似于以下截图：

![在 JSLint 中使用控制台](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_18.jpg)

现在让我们通过 JSLint 重新运行我们的最终代码，我们应该看到一个这样的屏幕：

![在 JSLint 中使用控制台](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_02_19.jpg)

我们可以看到，现在在 JSLint 中没有错误，我们还可以看到一个**函数报告**面板，指示变量作用域作为一个注解，说明哪些变量对文件是全局的，以及哪些变量和函数存在于函数内部，包括我们的匿名函数示例。

在结束本章之前，让我们尝试在`2_03_01.js`和`02_03_03.js`代码文件上使用`console.time`方法，将`console.time`函数包裹起来。我这边前者的时间是`0.441ms`，而使用 JSLint 优化的代码是`0.211ms`! 还不错；*性能翻倍*！

# 摘要

在本章中，我们学习了`console.time`和`console.timeEnd`方法的基本知识，我们还了解了 JSLint 以及它如何提高我们的 JavaScript 性能。在下一章中，我们将快速查看 JSLint，并通过将其集成到构建系统中来亲自动手！


# 第三章：理解 JavaScript 构建系统

在本章中，我们将学习 JavaScript 构建系统及其对 JavaScript 性能测试和部署的优势。我们还将利用上一章中关于 JSLint 的知识，将 JavaScript 代码测试整合到我们的构建系统中。

总之，本章将涵盖以下内容：

+   什么是构建系统？

+   搭建我们的构建系统

+   创建分发

# 什么是构建系统？

通常，**构建系统**是一个自动化过程，它帮助开发者编写干净优化的代码。我们可能会认为这样的事情会在所有编程语言中都是标准的。现在，编译语言通常有一个编译器；**编译器**根据语言规范编写的一个程序，创建与目标机器兼容的输出代码。

## 通过示例编译代码

编译器通常在处理代码文件时通过一个规格。为了防止编译器因坏代码而崩溃，编译器设置了许多错误检查器，在编译器崩溃之前发出警报，从而阻止编译过程。现在一些 IDE 允许你在尝试运行代码之前发现一些错误。下面的屏幕截图显示了一个简单的 Xcode Swift 文件在编辑时进行检查的情况：

![通过示例编译代码](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_01.jpg)

在不深入 iOS 开发的技术细节的情况下，我们可以看到，在 Swift 中分配常量变量时，如果尝试像前一张截图那样更改变量，我的代码会标志一个错误。

现在，如果我将`let authors_name`常量更改为动态的`var`变量（就像在 JavaScript 中一样），错误本身会纠正，如下面的屏幕截图所示，并在 IDE 中删除显示的错误：

![通过示例编译代码](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_02.jpg)

## 在 JavaScript 构建系统中进行错误检查

在过去，像 Dreamweaver 这样的 JavaScript 和 HTML 内容的 HTML 编辑器，自早期网页代码编辑器创建以来就这样做了。

在 Xcode 中为编译语言所做的与在 JavaScript IDE 中所做的略有不同。对于编译语言，必须修复错误才能运行代码文件；这通常被认为是静态类型检查。然而，JavaScript 即使出错，也可以运行，甚至可以用`try-catch`块覆盖。简单地说，正如第二章《使用 JSLint 提高代码性能》中所述，JavaScript 是一种解释型语言，是唯一真正在运行时测试错误的语言。

考虑到这一点，像 Dreamweaver、WebStorm 或 Visual Studio 这样的编辑器是如何检查错误的呢？嗯，如果你记得在第二章，*使用 JSLint 提高代码性能*，我们看到了如何通过 linting 工具提供有关 JavaScript 代码中潜在或可验证错误的反馈；这返回了一个错误列表。

在集成开发环境（IDE）中，编辑器是按照这个思路编写的，它取每个错误并显示与 JavaScript 文件中的相关行和列关联的错误。

因此，要建立一个构建系统，我们需要像使用[`jslint.com/`](http://jslint.com/)一样加入这种错误检查，但要以更自动化的方式。这使得轻量级编辑器能够使用在更昂贵、更重的集成开发环境（IDE）中使用的相同检查工具。

## 超出编码标准的优化

就像我们章节开头提到的 Xcode 示例一样，我们希望我们的最终输出为我们的项目进行了优化；为此，我们将把最小化添加到我们的构建系统中，允许我们保留一个开发者版本或源项目，保存在一个带有发行版目录的另一个目录中。简单地说，最小化允许我们对 JavaScript 代码进行压缩，使我们的网络应用程序下载更快，运行更高效。

这在我们使用源代码控制来维护项目时会有帮助，它允许我们快速获取一个优化过的、但不易调试的稳定发行版，并使用我们源代码目录中的文件进行调试。

现在作为 JavaScript 开发者，我们甚至可以添加其他可能需要的项目的最小化构建选项，例如为我们的项目图像目录添加一个图像优化器，或者压缩我们的 CSS 文件，并在我们的 JavaScript 文件顶部添加信息注释块。通过压缩我们的 JavaScript，JavaScript 解释器不必猜测我们代码中的空白距离，这产生了更高效、性能更好的代码。

## 使用 Gulp.js 从头开始创建构建系统

现在我们已经介绍了构建系统及其使用原因，让我们创建一个简单的构建系统。我们的目标是创建一个从源目录生成的发行版构建，一个优化后且适用于生产的副本。我们还将整合 JSLint，正如我们从上一章学到的，以便在我们创建构建时检查我们的代码，以发现开发过程中可能遗漏的任何潜在问题。

在本章中，我们将创建一个用于测试我们的 JavaScript 项目的构建系统。我们还将把最小化整合到我们的构建系统中，并将文件复制到我们的构建目录。所以当我们准备部署时，我们的代码库已经准备好部署了。

在开始这个项目之前，我们需要了解一些与 JavaScript 相关的特定技术，特别是我们想要考虑的构建系统；我们将特别处理如 Node.js、NPM、Grunt 和 Gulp 等技术。如果你只是听说过这些，或者可能曾经摆弄过其中的一些但从未深入了解过，不用担心；我们将逐一了解这些技术，并了解它们的优缺点。

### Node.js

**Node.js** 是一个为你的操作系统设计的 JavaScript 解释器。对于 JavaScript 开发者来说，JavaScript 代码像 Java 或 C#这样的后端代码基础这样的概念可能看起来很奇怪，但已经证明以新的创造性的方式工作。例如，Node.js 开发者社区创建了插件，以创建基于 JavaScript 的定制桌面应用程序。

这使得 JavaScript 处于一个全新的位置。当传统的应用程序开发人员抱怨 JavaScript 时，主要抱怨之一就是 JavaScript 无法读取或写入硬盘文件，这对于编程语言来说通常是一个非常基本的功能。Node.js 允许自定义对象与操作系统交互。这些对象包括`FS`或`FileSystem`等，可以读写文件，并且基本上类似于 Web 浏览器中的控制台。

对于这个项目，我们不会深入讨论 Node.js（那是另一本书的内容），但我们将在我们的操作系统中安装 Node.js，这样我们就可以运行和测试我们的构建系统。所以让我们下载 Node.js 并开始吧。首先，导航到[`nodejs.org/`](http://nodejs.org/)，并点击下面的绿色**INSTALL**按钮，如图所示：

![Node.js](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_03.jpg)

Node.js 是跨平台的，所以这些指令大部分对你应该是有用的。我将使用一个带有 OS X 的 Mac 来进行这个安装介绍。对于大多数平台，Node.js 将带有`.pkg`或`.exe`安装向导，如图所示：

![Node.js](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_04.jpg)

从这里开始，跟随向导操作，接受用户许可并安装给所有用户。通过为所有用户安装，我们允许 Node.js 拥有完整的系统访问权限，这是我们所希望的，因为 Node.js 的一些插件可能需要某些单个用户或非管理员无法访问的功能。

当你完成 Node.js 的安装后，请注意安装程序设置的路径；如果你将来想要删除 Node.js，请查看以下屏幕截图，以查看安装程序将 Node.js 添加到了哪里：

![Node.js](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_05.jpg)

#### 测试 Node.js 安装

为了确保 Node.js 被正确安装，我们希望检查两件事。第一件事是检查 Node.js 在终端中是否可以正常工作。为了验证安装，我们将检查已安装的 Node.js 的当前版本。

首先，让我们打开终端（或者如果使用 Windows 的话，打开命令提示符），并插入如下截图所示的`node --version`命令，然后按*Enter*键：

![测试 Node.js 安装](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_06.jpg)

如果成功，我们应该在终端的下一行看到版本号（在我的情况下，它是`v0.10.32`；当你尝试这个时，你的版本可能比我版本号还要新），如下面的截图所示：

![测试 Node.js 安装](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_07.jpg)

#### 测试 Node 包管理器的安装

太棒了！现在，要检查完整安装的下一个事项是 Node 包管理器是否也已安装。在测试之前，让我解释一下 Node 包管理器是什么，特别是对于那些可能不知道它是什么以及我们为什么需要它的那些人。

##### 关于 Node 包管理器

**Node 包管理器**（NPM）连接到 NPM 注册表，这是 Node.js 的在线软件库存储库。通过使用 NPM，我们可以快速设置 JavaScript 构建系统，并自动为我们的基于 HTML 的 JavaScript 项目安装库，这使我们能够确保我们的 JavaScript 库与每个库的最新版本保持更新。

NPM 还有一个网站，你可以使用它在[`www.npmjs.org`](https://www.npmjs.org)上研究各种 JavaScript 库。下面的截图也显示了这一点：

![关于 Node 包管理器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_08.jpg)

##### 在终端中检查 NPM 安装

现在，为了检查我们的 NPM 安装，我们将直接调用 NPM，这应该会返回已安装的 NPM 模块的`help`目录。要做到这一点，只需打开终端并插入`npm`命令。现在，我们应该看到我们的终端窗口充满了 NPM 帮助文档和示例终端命令，如下面的截图所示：

![在终端中检查 NPM 安装](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_09.jpg)

##### 使用 NPM 的基础知识

学习使用 NPM 是一个相对简单的过程。在我们为项目设置 NPM 之前，我们需要做的第一件事是创建一个项目根目录；我将这个作为第一个项目的`npm_01`，但你可以给你的根目录命名你喜欢的任何名字。现在，我们将打开终端并将我们的`bash`目录更改为我创建的目录的路径。

在终端中更改工作目录的命令是`Change Directory`或`cd`。使用`cd`非常简单；只需输入以下命令：

```js
cd [~/path/to/project_dir]

```

在这里需要注意的是，终端在 Mac 和 Linux 上总是指向你的用户主目录，并且`~`键是一个快速指向你路径的快捷方式。例如，如果你的文件夹在你的用户名下的文档目录中，使用 cd 的示例路径可能是`cd ~/Documents/[你的项目路径]`。

### 提示

如果终端信息过于杂乱，你可以使用“clear”命令来清除终端内容，而不改变你的目录。

#### 使用 NPM 安装 jQuery

一个常见的 JavaScript 库是 jQuery，NPM 上一个非常受欢迎的库。我们甚至可以在 [npmjs.org](http://npmjs.org) 上查看它的仓库信息，地址为 [`www.npmjs.org/package/jquery`](https://www.npmjs.org/package/jquery)。

![使用 NPM 安装 jQuery](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_10.jpg)

如果我们查看这个页面，可以看到一个命令，用于我们的终端，`npm install jQuery`。那么，让我们在终端中输入这个命令，并按*Enter*键看看会发生什么。

### 提示

如果你是 Mac 或 Linux 用户，你可以将一个文件夹拖放到终端中，它会在你输入`cd`命令后自动为你写入该文件夹的路径。

在终端中，看起来有些文件已经被下载了，如下面的截图所示：

![使用 NPM 安装 jQuery](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_11.jpg)

现在，如果我们打开我们的项目目录，我们可以看到一个新的名为`node_modules`的文件夹已经创建。在这个文件夹中，又创建了一个名为`jquery`的文件夹。下面是`jquery`文件夹内容的截图：

![使用 NPM 安装 jQuery](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_12.jpg)

在`jquery`文件夹中，有一些有趣的文件。我们有一个`README.md`（`.md`是 markdown 的缩写，一种文本格式）文件，解释了 jQuery。

这个文件夹中有两个 JSON 文件，一个叫做`bower.json`，另一个叫做`package.json`。`package.json`文件处理 NPM 包的信息，而`bower.json`文件处理任何依赖包，并在安装请求时通知 NPM 也包含这些依赖包。

如果你想知道`bower.json`文件的作用，它本质上是一种从仓库更新源代码的另一种方式。与 NPM 注册表类似，`bower.json`文件使用它自己的注册表；不同的是，它可以使用项目中的 JSON 文件，并根据存储在 JSON 文件中的设置进行更新。

最后，最重要的两个文件夹是`src`文件夹（或源文件夹）和`dist`文件夹（或分发文件夹）。这种文件结构是 NPM 的一种常见约定，其中项目的源代码和调试信息保存在`src`文件夹中，而最终的测试输出保存在`dist`文件夹中。

由于我们不调试 jQuery 的源代码，我们真正需要担心的是`dist`文件夹，我们可以在其中找到`jquery.js`文件和`jquery.min.js`文件——这些通常在 jQuery 项目中使用的库文件。了解这一点对于我们的构建系统很重要，因为我们将需要将这些文件复制到我们的构建系统的分发文件夹中。

# 设置我们的构建系统

既然我们已经了解了 Node.js 和 NPM 的基础知识，那么让我们实际构建一个构建系统。我们需要将我们的终端指向项目的根目录，然后我们需要安装我们的构建系统（也称为任务运行器）。

## 关于 Grunt.js 和 Gulp.js

Node.js 构建系统属于两个主要的构建系统库：Grunt 和 Gulp。在很多情况下，Grunt 是 Node.js 项目的默认构建系统。

### Grunt 任务运行器

最初，Grunt 是为了自动化 JavaScript 和 Web 开发中的任务而设计的，由于它的可用性，许多开发者都创建了插件；您可以在下面屏幕截图中查看 Grunt 的插件存储库：

![Grunt 任务运行器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_13.jpg)

### 关于 Gulp

Gulp 是另一个 Node.js 的构建系统；使用 Gulp 的优势在于它是异步的，通常比 Grunt 更快地运行自动化任务。由于这本书都是关于性能的，我们将用 Gulp 作为我们的构建系统的示例。这并不意味着 Grunt 不好；它可以创建与 Gulp.js 一样的构建系统，但它可能没有 Gulp 快。

像 Grunt 一样，Gulp 也有一个插件参考页面，可以在[`gulpjs.com/plugins/`](http://gulpjs.com/plugins/)找到，并在下面的屏幕截图中显示：

![关于 Gulp](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_14.jpg)

#### 安装 Gulp

要安装 Gulp，我们将打开我们的终端，并在提示符中输入以下内容：

```js
sudo npm install --global gulp

```

这将全局安装 Gulp 到我们的 Node.js 和 NPM 资源路径。如果我们正在运行 Windows 系统，`sudo`不在 Windows Shell 中，因此我们需要以管理员身份运行命令提示符。现在，如果一切顺利，我们应该看到一大堆文件的网络请求，并且我们的终端应该返回到下面屏幕截图中显示的提示符：

![安装 Gulp](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_15.jpg)

在我们系统的所有文件夹中安装了全局（“全局”意味着安装在系统中的所有文件夹中）的 Gulp 依赖之后，我们可以安装我们的开发依赖，这些依赖使得我们的构建系统在上传到源代码控制时更加便携。本质上，这些依赖必须存在于我们项目的根文件中，以使我们的构建系统能够在项目目录中运行。

我们可以通过在终端中输入以下代码来完成此操作（再次说明，对于 Mac/Linux 用户是`sudo`，对于 Windows 用户是**以管理员身份运行**）：

```js
sudo npm install --save-dev gulp

```

如果成功，你的`bash`提示符应该再次出现，拉取许多 URL 源并安装到你的项目`gulp`下的`node_modules`目录中，如下面的屏幕截图所示：

![安装 Gulp](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_16.jpg)

#### 创建一个 gulpfile

`gulpfile`是 Gulp 检查以在项目目录的根目录运行一系列任务的文件。要创建一个，我们将创建一个简单的名为`gulpfile.js`的 JavaScript 文件（注意文件名的大小写）。在文件中，我们将将 Gulp 作为一个变量引用，并创建一个名为`Default`的默认任务。

这是我们每个`gulpfile.js`都需要运行的主要任务；在内部，我们可以包含其他任务或输出日志消息，就像在网页浏览器中一样。作为一个简单的 Gulp 任务的代码示例，如下面的屏幕截图所示：

![创建一个 gulpfile](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_17.jpg)

#### 运行一个 Gulp 项目

运行一个 Gulp 项目很简单。在你的项目根目录中，在终端中输入`gulp`并按*Enter*。你应该看到你的终端中的输出，如下面的屏幕截图所示：

![运行一个 Gulp 项目](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_18.jpg)

这很好。如果我们查看终端输出的第四行，我们应该会看到我们的输出信息为**默认任务运行**。干得好！这和我们为`Default`任务在`gulpfile.js`中创建的`console.log`信息是一样的。

所以你可能会问，这一切都是如何帮助优化 JavaScript 代码的？嗯，如果你记得第二章，*使用 JSLint 提高代码性能*，我们使用 JSLint 来审查 JavaScript 代码，进行改进，并优化文件。如果我们能在复制文件并通过 JSLint 进行压缩（甚至测试压缩后的代码）的同时运行这个测试工具呢？嗯，我们可以，这就是使用构建系统的目的。

使用构建系统，我们在修改代码之前会对其进行改进和优化，甚至在我们将其部署为网络应用程序之前。

## 将 JSLint 集成到 Gulp 中

之前，我们谈到了 Gulp 的插件页面；其中一个插件就是 JSLint 插件，安装过程相当简单。首先，查看位于[`www.npmjs.org/package/gulp-jslint/`](https://www.npmjs.org/package/gulp-jslint/)的 JSLint 插件页面，如下所示：

![将 JSLint 集成到 Gulp 中](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_19.jpg)

所以，以安装 Gulp 同样的方式，我们将运行页面上的`npm`命令，但会包括`sudo`以获取管理员权限和`-g`命令。这是一个全局标志，以将 JSLint 安装到整个系统，如下所示：

```js
sudo npm install -g gulp-jslint

```

接下来，我们将安装我们项目的开发依赖，所以我们再次在终端中指向我们项目的根目录，然后输入我们的`npm`命令，但这次加上`-save-dev`标志，如下所示：

```js
sudo npm install -save-dev gulp-jslint

```

为了验证安装，我们可以检查我们项目目录中的`node_modules`文件夹，并看到`gulp-jslint`文件夹，如下所示：

![将 JSLint 集成到 Gulp 中](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_20.jpg)

## 测试我们的示例文件

现在，我们的构建系统需要一个源文件，我在添加到新创建的`src`项目目录时编写了一个示例。我还没有测试这个，如下所示：

![测试我们的示例文件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_21.jpg)

我们有一个简单的儿童 JavaScript 类，它根据调用原型函数来显示消息；相当基础，并且确实有一些预期的错误，让我们找出来。让我们回到`gulpfile.js`；我用一些 JSLint 示例对其进行了更新，使用了我们在第二章中提到的相同的常用选项。看看下面更新的`gulpfile.js`文件：

![测试我们的示例文件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_22.jpg)

在第 6 行和第 7 行，我们可以看到诸如`gulp.src()`和`pipe()`这样的约定。`src`函数是一个 Gulp 特定的函数，它使用 JavaScript 数组设置源文件或文件；`pipe`函数，也是与 Gulp 相关的，允许我们创建一个任务列表，该列表将源文件从`gulp.src()`通过我们的构建系统进行*管道*。这里的第 5 行到第 19 行展示了一个新的`gulp.task`，称为 JSLint。如果我们看第 9 行到第 12 行，我们可以看到与[JSLint.com](http://JSLint.com)相同的选项；选项名称可以在页面上选择不同选项时页面的底部找到 JSLint 指令。

在第 22 行，我们在我们的*默认*任务之后添加了一个数组，将我们的*JSLint*任务名称添加到数组中。我们可以在這裡添加多个任务，但现在我们只需要 lint 任务。现在让我们运行脚本并检查我们的终端。

![测试我们的示例文件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_23.jpg)

太好了！终端中显示的红色线条报告了脚本中的错误，给我们提供了终端中的 lint 反馈，正如我们所看到的，我们忘记了一些常见的事情，比如使用*use strict*，漏掉分号等等。因此，我们可以看到如何使用 Node.js 和 Gulp 在构建过程中自动化测试我们的代码。

## 创建分发

把最好的部分留到最后，让 Gulp 处理 JavaScript 源代码的压缩，将输出复制到`dist`文件夹，然后对输出进行测试*校验*。我已经修改了`ExampleScript.js`文件，修复了之前发现的大部分问题。

现在我们需要为 Gulp 下载一个名为**Uglify**的压缩工具，可在[`www.npmjs.org/package/gulp-uglify`](https://www.npmjs.org/package/gulp-uglify)找到。这是 Gulp 项目常用的 JavaScript 压缩器；它的安装很容易，遵循与安装 Gulp 本身和为 Gulp 安装 JSLint 相同的程序。安装此工具的以下命令：

```js
sudo npm install --save-dev gulp-uglify

```

现在我已经用一个新的压缩任务更新了我们的`gulpfile.js`，并将其添加到数组中，如下面的屏幕截图所示：

![创建分发](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_24.jpg)

现在，在终端窗口中运行 Gulp，注意输出（如下面的屏幕截图所示）；在 finder 文件夹中，你将在你的根项目文件夹的`dist`目录中看到一个全新的压缩文件，同时保留你的开发者源文件，并获得性能 linting！

![创建分发](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_03_25.jpg)

# 总结

在本章中，我们学习了如何使用 Node.js 和 Gulp 创建一个简单的 JavaScript 构建系统。我们还探索了其他插件，并查看了 Grunt 任务运行器，它与 Gulp 类似，但包含更多用于你工作的插件。

构建系统能极大地提高你的性能，而不需要太多的努力；请记住 gulp 文件可以被重新用于其他项目，因此尝试并找出最适合你项目的工具。

在下一章，我们将学习如何使用 Chrome 的**开发者工具**选项来更好地优化我们的 Web 应用程序代码的技巧和窍门。


# 第四章：检测性能

在本章中，我们将介绍我们的工作环境以及所需的工具；我们还将介绍 Google Chrome Web 检查器中的功能和 JavaScript 优化工具，并创建一些测试样本，展示如何使用和测试 JavaScript 和 HTML 页面代码。

我们将在本章涵盖以下主题：

+   一般的 Web 检查器

+   元素面板

+   网络面板

+   时间线面板

+   配置文件面板

+   资源面板

+   审计面板

+   控制台面板

# 一般的 Web 检查器

在深入探索 Chrome 的 Web 检查器之前，重要的是要注意，有许多不同的 Web 检查器用于不同的网络浏览器，通常由浏览器的供应商开发，用于调试网页的应用内容和性能。

重要的是要理解，为了使开发者能够正确地调试 Web 应用程序，他们应该使用检测到问题的浏览器的检查器。

## Safari Web 检查器

Apple 的 Web 检查器是基于 WebKit 的检查器，为 Safari 而建。Web 检查器与 Chrome 的 Web 检查器非常相似。我们将在第九章，*为 iOS 混合应用优化 JavaScript*中更详细地介绍 Safari **Web 检查器**，主要是因为 Safari 的**Web 检查器**可以在 iOS 开发中调试 Web 内容。

Apple 对其工具的文档相当全面，网址为[`developer.apple.com/safari/tools/`](https://developer.apple.com/safari/tools/)，如下次截图所示：

![Safari Web 检查器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_01.jpg)

## Firefox 开发者工具

Mozilla 的 Firefox 网络浏览器也有自己的检查器。最初，Firefox 是唯一带有检查器的浏览器；它被称为 Firebug，作为插件开发，并未包含在主浏览器中。

自从 Firefox 3 问世以来，Mozilla 不仅为其自己的浏览器开发了浏览器检查器，而且还作为 Firefox OS 的调试工具，Firefox OS 是 Mozilla 的移动操作系统，使用 HTML5 进行应用程序开发。Firefox **开发者**工具还允许对相对较新甚至实验性的 HTML5 和 JavaScript 开发进行调试。

我们可以在 Mozilla 的开发者网络[`developer.mozilla.org/en-US/docs/Tools`](https://developer.mozilla.org/en-US/docs/Tools)上找到更多关于 Firefox **开发者**工具允许的开发者类型的信息，如下次截图所示：

![Firefox 开发者工具](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_02.jpg)

## Internet Explorer 开发者工具

在过去，Internet Explorer 被认为是网络开发者工具箱中的黑羊。在 Internet Explorer 11 问世之前，微软为 Internet Explorer 6 及以上版本提供了一个简单的 DOM 检查器插件；虽然它对 Internet Explorer 的浏览器问题非常有帮助，但其功能集落后于其他供应商的检查工具。

自从 Internet Explorer 11 发布以来，微软正定位自己支持 HTML 开发超过过去的力度，其新的**F12 开发者工具**正是如此。**F12 开发者工具**中的大多数功能与 Chrome 的**开发者工具**和 Safari 的**网络检查器**一样好，随着更多的发布，预计未来会有更多的功能。我们可以阅读更多关于如何使用这些工具的信息在[`msdn.microsoft.com/en-us/library/ie/bg182326(v=vs.85).aspx`](http://msdn.microsoft.com/en-us/library/ie/bg182326(v=vs.85).aspx)，如图下一个屏幕截图所示：

![Internet Explorer 开发者工具](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_03.jpg)

## Chrome 的开发者工具

Chrome 的检查器最初是使用开源 WebKit 浏览器的 Web 检查器开发的，该检查器在某个时候也被苹果的 Safari 使用。后来，当 Chrome 决定将 WebKit 分叉为称为 Blink 的自家浏览器运行时，Google 从零开始为 Blink 重建了检查器，优化了用户界面并添加了在开源 Webkit 检查器中找不到的功能。

重建检查器的另一个原因是 Chrome for Android 和 Chrome OS 应用的引入。这允许开发人员访问特定于那些平台上的 JavaScript 基础控制台对象。它还提供优化响应式内容的功能，以及在设备上不存在的移动内容调试工具。

由于这里提到的丰富功能，我们将介绍如何为 Chrome 使用网络检查器。如果你关心了解另一个检查器的功能，请参考前面提到的链接并研究本章列出的主题。

最后，Chrome 的新功能更新周期相当频繁，尤其是其名为 Chrome Canary 的 Chrome 测试版本，它本质上启用了任何早期速度提升的实验性功能的 Chrome。您可以在[`www.google.com/intl/en/chrome/browser/canary.html`](https://www.google.com/intl/en/chrome/browser/canary.html)下载 Canary，如图下一个屏幕截图所示：

![Chrome 的开发者工具](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_04.jpg)

**Chromium 的开发者工具**包含了许多更高级的功能，这些功能通常在 Firefox 的**开发者工具**中可以找到。在本章中，我将使用 Chrome 的默认**开发者工具**，但请也查看 Chromium 的**开发者工具**，以了解未来将提供哪些功能。

查看[`developer.chrome.com/devtools`](https://developer.chrome.com/devtools)了解**Chrome 开发者工具概览**，如图下一个屏幕截图所示：

![Chrome 的开发者工具](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_05.jpg)

### 熟悉 Chrome 的开发者工具

要安装 Chrome 的**开发者工具**，从[`www.chrome.com/`](http://www.chrome.com/)下载 Chrome，就这样！Chrome 的**开发者工具**随 Chrome 一起提供，无需额外的安装。

首先，在 Chrome 中打开一个新窗口并输入`about:blank`在 Omnibox（或地址栏）中。接下来，使用快捷键*Ctrl* + *Shift* + *I*（或在 Mac 上的*Command* + *Option* + *I*）打开**开发者工具**。我们应该看到一个空白屏幕，**开发者工具**显示在上方，如下面的屏幕截图所示：

![熟悉 Chrome 的开发者工具](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_06.jpg)

默认情况下，Chrome 的**开发者工具**将以工具栏模式显示，如前所示，或者在自己的窗口中；如果你想要解挂或重新挂起**开发者工具**，选择工具栏按钮。

按下工具栏按钮可以让我们将**开发者工具**挂接到浏览器窗口的侧面。你可以找到以下屏幕截图中标志的工具栏按钮：

![熟悉 Chrome 的开发者工具](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_07.jpg)

**开发者工具**分为不同的面板，显示在窗口顶部，每个面板包含不同的功能和 Web 应用程序的调试选项。我们将重点关注 JavaScript 特定的面板，但我们会简要介绍每个面板，以便不熟悉它们的人了解。

#### 元素面板

**元素**面板显示 HTML 页面的源代码和 DOM 浏览器，允许开发人员检查 DOM 的变化。我们可以通过将鼠标悬停在 DOM 树上，或者按照以下屏幕截图中指示使用放大镜来高亮显示元素：

![元素面板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_08.jpg)

#### 网络面板

**网络**面板显示页面下载速度的所有资源及其包含的代码。让我们通过访问[`www.packtpub.com/`](http://www.packtpub.com/)并打开**网络**面板（位于**元素**旁边）来测试一下。按照以下屏幕截图所示，点击面板左上角的录制按钮：

![网络面板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_09.jpg)

现在，让我们刷新页面并按记录按钮。我们可以看到网页上的哪些页面资源需要更长时间来加载。在考虑用 JavaScript 加载资源时，这是很重要的。如果我们针对 DOM 中尚不存在的元素或脚本，可能会发生错误。

如果我们看下面的屏幕，我们可以看到在[`www.packtpub.com/`](http://www.packtpub.com/)上，`blog-banner.png`图像的加载时间最长。

![网络面板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_10.jpg)

我们也可以选择一个资源；让我们点击其中一个图像资源。（我会选择`blog-banner.png`，这可能在你的页面上存在也可能不存在。如果你在首次加载时测试，给网站几秒钟加载的时间）。当我们选择它时，我们可以看到一个新的子面板出现，如果它是一个图形，则显示图像预览；如果它是一个 JavaScript 或 JSON 文件，则显示源代码。

我们在子面板中也有标签页，其中一个叫做**响应**。这提供了由 DevTools 找到的 POST 事件资源的信息。我们还有一个叫做**头信息**的标签页。**头信息**标签页显示对该文件的请求信息，包括（更重要的是）图像是否使用任何服务器端缓存。在此例中，我们的`blog-banner.png`文件有一个`Cache-control: max-age`值，表示最大缓存年龄为`3153600000`秒，即十年。我们还可以看到完整的`请求 URL`，注意到它使用了一个`cloudfront.net` URL，因此我们可以推断出图像使用亚马逊 S3 进行缓存和分发，如下所示的两个截图所示：

![网络面板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_11.jpg)

#### 源代码面板

在此我们将学习关于**源代码**面板的内容，通过以下几个方面来帮助理解：

##### 调试器基本用法

**源代码**面板是大多数 JavaScript 开发者的家园；这是我们调试 JavaScript 应用程序的地方。使用它相当简单；点击左上角附近**监视表达式**选项的上暂停按钮，如下所示的截图：

![调试器基本用法](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_12.jpg)

###### 测试调试器

让我们尝试使用调试器。打开我们代码包中 Packt Publishing 网站提供的`Chapter_4`文件夹内的`01`文件夹。在其中，我们可以看到一个非常简单的代码示例，我们还有一个 HTML5 的`index.html`页面，如下所示的源代码视图：

![测试调试器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_13.jpg)

我们可以看到，我们有一个非常空的网页，给`body`标签添加了一些样式；我们还添加了一个`main.js`外部 JavaScript 文件，处理我们页面的所有逻辑。我们接下来要做的就是检查一个包含`while`循环的函数。

循环将在`document.body`标签中添加`paragraphTag`变量，每个变量都有一个名为全局变量`my_integer`的索引变量，该变量位于`while`循环外的`loopingTo5k()`函数中。这在第 14 行被调用，由一个`window.onload`事件触发，如下所示的下一个截图显示了`main.js`的源代码视图：

![测试调试器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_14.jpg)

有了我们的源代码，让我们在 Chrome 中打开**源代码**面板运行我们的页面。如果我们看屏幕，我们可以看到一串数字按顺序向下移动，最后在文档的最后一行结束于**5000**。

让我们在我们的**源代码**面板上选择`main.js`文件，为我们的源代码第 8 行添加一个断点，看看**源代码**面板能做什么。现在我们设置了断点，让我们刷新页面。当我们这样做时，我们可以看到页面变灰，顶部有一个黄色注释，表示我们在调试器中暂停，我们`main.js`文件中的第#8 行用蓝色高亮，表示调试器暂停的位置。

我们还可以看到**作用域变量**选项，它显示了给定作用域在执行时的所有属性和对象；在这个例子中，作用域在`loopingTo5k()`函数内部。为了获取更多信息，我们可以参考**源代码**面板的右侧部分，查看局部树以获取信息，或者我们可以在我们的代码文件中悬停鼠标以获取更多信息。如以下所示，我在我的函数作用域中突出了`document.body`对象，在 JavaScript 中创建了一个新的段落对象。

![测试调试器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_15.jpg)

当我们完成调试时，我们可以按下**源代码**面板中突出显示的蓝色播放按钮，或者我们可以通过播放按钮旁边的控件**单步跳过**我们的函数，然后继续下一个函数。请记住，如果我们有进一步的断点，它们将会在我们网页中的源文件中更远的地方断开。要删除断点，我们可以将它们拖离我们的行号列，然后按下播放按钮，继续不进行调试。

###### 使用调试器关键字

在 JavaScript 编程中，一个鲜为人知的特性是**调试器**关键字；它是一个非常简单的助手函数。当运行代码时，它会触发**源代码**面板或其他连接的 JavaScript 调试器自动断开；这在审查大量代码库或在特定行上遇到问题时非常有帮助。

假设在我们的示例代码中，有一个 while 循环，导致在`my_integer`的`555`次迭代时我们的代码出现问题。如果我们不得不逐步执行这个，这将需要按下 555 次播放按钮才能到达那里。然而，有一个解决办法。

为了演示这一点，我在代码包中保存了一个这些源文件的副本，并将其保存在 Packt Publishing 网站提供的`02`文件夹中，在`第三章`文件夹中的`练习文件`文件夹中。我在这里的代码中只做了一个改动：在 12 至 14 行中添加了一个条件`if`语句，确保`my_integer`等于`555`。如果应用此更改，我可以通过简单地写一个带有分号的`debugger`来调用调试器，如下所示：

![使用调试器关键字](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_16.jpg)

现在调用`debugger`变得简单了。让我们再次加载带有调试器代码的我们的`index.html`文件，这里我们可以看到，在不设置断点的情况下，我们的**源代码**面板自动检测到行并设置了断点，而没有遍历每个循环（如下所示）：

![使用调试器关键字](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_17.jpg)

#### 时间线面板

在这里，我们将通过以下方面来学习**时间线**面板：

##### 使用时间线面板

**时间线**面板允许我们检测与 JavaScript 相关的整个网页性能；它还允许我们检查浏览器渲染事件。要使用**时间线**面板，我们只需要点击录制按钮，然后在 Chrome 中重新加载页面。

在**时间线**检查器中，**时间线**面板显示了四种类型的事件。这些是**加载**、**脚本**、**渲染**和**绘制**事件。我已经加载了前面章节中讨论的示例文件（`02`），展示了事件如何通过**时间线**面板运行，如下面的屏幕截图所示：

![使用时间线面板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_18.jpg)

##### 加载事件

**加载**事件处理请求和响应；通常这些事件包括加载外部脚本和文件以及页面数据离开时的`POST`请求。加载事件还包括 HTML 代码的初始解析。在 Google Chrome 的**时间线**中，这些事件显示为蓝色。

##### **脚本**事件

**脚本**事件发生在浏览器读取和解释 JavaScript 代码时。在**时间线**面板中，您可以展开一个**脚本**事件，并查看函数在浏览器中接收的时间点。在 Google Chrome 中，**脚本**事件显示为黄色线条。

##### 渲染事件

**渲染**事件发生在图像文件和脚本影响 DOM 时；这可以是在`image`标签中没有指定大小的图像被加载时，或者在页面加载后 JavaScript 文件更新页面 CSS 时。

##### 绘制事件

**绘制**事件是最后一种类型的事件，通常用于更新 UI。与**渲染**事件不同，**绘制**事件发生在浏览器在屏幕上重新绘制图像时。对于桌面 JavaScript 开发来说，**绘制**事件通常不是问题，但在我们开始关注移动网页浏览器时，这个问题就变得非常严重了。

通常，当元素的显示从原始状态更新时，会强制执行**绘制**事件。它们也可以由元素更新触发，例如元素的`top`或`left`定位。

#### **配置文件**面板

**配置文件**面板帮助开发者分析网页的 CPU 配置文件，并拍摄 JavaScript 使用的堆快照。CPU 配置文件快照在检查大型复杂应用程序时很有帮助，可以查看哪些文件可能会在对象大小方面引起问题。

JavaScript 堆快照是一份编译的页面整体 JavaScript 中找到的对象清单。这不仅包括我们编写的代码，还包括浏览器内置的代码，如文档或控制台对象，给出了应用程序中所有可能的对象的总体列表。

使用**配置文件**面板与**时间线**面板类似；选择**拍摄堆快照**或**收集 JavaScript CPU 配置文件**选项，然后点击**开始**，接着重新加载页面。在下面的屏幕截图中，我选择了**收集 JavaScript CPU 配置文件**选项：

![Profile 面板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_19.jpg)

#### 资源面板

**资源**面板列出了与正在查看的网页相关的所有文件，这些文件可以通过**开发者工具**选项进行排序；开发者可以单独查看每个文件。它还显示页面上的图像以及它们的属性，如**尺寸**、**文件大小**、**MIME 类型**和源**URL**。

更重要的是，**资源**面板是浏览器数据存储的所有内容的家，包括**Web SQL**、**IndexedDB**、**本地存储**、**会话存储**和**Cookies**。用户可以在浏览器的存储数据中查看页面的**键**-**值**对值。这对于测试存储状态和在 JavaScript 代码中存储值非常有帮助。

查看键值对很容易；在**资源**面板中，选择存储类型并查看键值表，如下所示 screenshot using Packt Publishing's website while viewing local storage:

![资源面板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_20.jpg)

#### 审计面板

在这里，我们将通过以下方面了解**审计**面板。

##### 与 Audits 面板交互

**审计**面板*审计*整个网页的应用程序**网络利用率**和整体**网页性能**；这是浏览器提供的**开发者工具**选项中更容易使用和更直观的面板之一。使用**审计**面板也很简单。首先，再次打开 Packt 出版社的网站，使用**开发者工具**选项选择**审计**面板，然后检查**选择所有**选项；这将测试网络速度和整体网页性能。最后，确保在点击**运行**按钮之前将单选按钮设置为**重新加载页面并在加载时进行审计**。这将确保审计测试正确地检查网络使用情况，而不是缓存状态，正如以下屏幕截图所示：

![与 Audits 面板交互](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_21.jpg)

##### 获取 JavaScript 质量建议

如果我们只检查 JavaScript 性能，请取消选中**网络利用率**选项并运行测试；如果我们正在为应用程序的特定点进行测试，我们需要记住这一点。我们需要将单选按钮切换到**审计当前状态**，然后点击**运行**以获取 Web 应用程序当前状态的建议。让我们在[`www.packtpub.com/`](https://www.packtpub.com/)上运行测试，然后在**结果**下选择文件。让我们查看以下屏幕截图中显示的性能改进建议：

![获取 JavaScript 质量建议](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_22.jpg)

如果我们仔细观察，可以看到非常易读的建议，这些建议与我们页面的 JavaScript 代码有关，影响整个页面的性能。在这种情况下，审核检测到 3 个内联脚本，并建议将内联脚本移动以提高性能。还提供了有关页面中包含的 CSS 规则中有多少未使用（至少在这个页面上）的反馈。它还告诉我们 CSS 中是否使用了供应商前缀，而没有使用网络标准属性。所有这些建议都非常有帮助。

#### 控制台面板

最后一个开箱即用的面板是**控制台**面板。这是这里最简单的面板，但也是 JavaScript 开发者花费最多时间的面板。现在我的假设是我们对这个面板已经相当熟悉了，所以我不会深入讲解这个面板。我们可以在控制台中测试代码，并在页面中搜索对象、DOM 元素和属性。例如，假设我在 Packt Publishing 的网站上输入以下内容到控制台：

```js
document.body.classList
```

这应该在下一行返回一个 JavaScript 数组，显示我们可以使用的所有类名，并且它确实显示了一个名为`with-logo`的类名，如下面的屏幕截图所示：

![控制台面板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_04_23.jpg)

**控制台**面板和 Chrome 中的**控制台**API 在 Chrome 的**开发者工具**中功能不断进化。为了跟上一些新工具的步伐，请查看 Chrome 的 DevTools 控制台 API 页面，该页面位于[`developer.chrome.com/devtools/docs/console`](https://developer.chrome.com/devtools/docs/console)，展示了如何使用控制台进行自定义输出，例如`console.table()`和`console.profile()`，使在控制台中的开发变得更加容易。

# 总结

在本章中，我们探索了随 Google Chrome**开发者工具**消费者版本提供的基面板；许多这些工具也适用于其他检查器和其他开发者工具（本章前面也已涵盖）。我鼓励您阅读有关每个工具的内容，并看看在其他检查器以及在 Chrome 的**开发者工具**中代码是如何被检查的。

在下一章中，我们将进入没有任何帮助的 JavaScript 性能编程。


# 第五章：操作符、循环和定时器

在前面的章节中，我们回顾了 JavaScript 开发中使用的基本工具。我们查看了 IDE、代码编辑器以及*JSLint*，这是一个不仅显示我们代码存在问题的 JavaScript 代码验证器，而且它还给出了警告和建议，帮助我们改进代码。

我们还学习了`console.time`和`console.timeEnd`方法，这些方法允许我们快速测试代码执行性能。最后，我们学习了创建一个基本构建系统，以确保我们的最终代码库经过优化且无错误。

需要说明的是，所有这些工具和技术都是编写高性能代码的关键，这不是因为你知道 JavaScript，而是因为你不了解 JavaScript。JavaScript 是一种任何人都可以上手并开始编写代码而无需了解面向对象编程或了解如**模型-视图-控制器**（**MVC**）这样的模式的语言；然而，多年来，它已经被修改以适应这些更高级的编程概念（无论是以哪种方式）。

一个易于使用的语言的副作用是，很容易编写错误或者甚至非优化代码；如果我们编写复杂的 JavaScript，这种效应会翻倍甚至翻三倍。正如前面章节中提到的，JavaScript 开发人员的一个普遍特征是我们*是人类，会犯错误*。这很大程度上只是开发者意识不足，这就是为什么使用构建系统和代码检查器（如 JSLint）如此重要，在我们编写完美的、高性能的 JavaScript 之前，这些工具可以帮我们解决问题。

在本章中，我们将抛开工具和构建系统，直接深入研究 JavaScript 性能概念，将主题内容分布在两章中，从以下主题开始：

+   操作符

+   循环

+   定时器

# 操作符

在本节中，我们将学习使用比较操作符高效地创建`for`循环的方法。

## 比较操作符

比较操作符`==`是 JavaScript 开发中常见的操作符（通常在`if`语句中）；它将一个对象与另一个对象相等，并返回一个布尔值，（`true`或`false`）。这个操作符相当直接，在 C 语言基础的编程语言中非常普遍。

正因为如此，很容易利用这个操作符并在大型代码库中使用它。这个现实的真相是，等于操作符与使用`===`严格比较操作符相比，速度较慢，后者还比较对象类型以及对象的值。由于 JavaScript 解释器不需要在检查相等性之前确认类型，所以它的运行速度比双等号操作符要快。

### 严格比较更快吗？

让我们用`console.time`方法来测试一下。在下面的截图中有一个`05_01.js`代码示例；我们也可以在这本书的示例文件中看到这个示例，这些文件由 Packt Publishing 提供，可以在其网站上找到：

![严格比较更快吗？](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_05_01.jpg)

在这里，我们有 5 行、6 行和 7 行上的三个变量；其中两个变量是浮点数，引用π值，最后一个变量是具有相同π值的字符串。然后我们在第 12 行的匿名函数中有一个`test`变量，该变量使用双等号运算符将我们的浮点数相等。在第 9 行和第 14 行，我们分别包围了函数的`console.time`和`console.timeEnd`函数。

让我们在 Chrome 浏览器中运行这个；首先打开 Chrome，然后从**更多工具**选项中的`about:blank`标签中打开**开发者工具**，接着在**源**面板右侧的**代码片段**选项卡中打开。**代码片段**选项卡就像一个用于测试 JavaScript 代码的画纸；在选项卡内容区域右键点击，选择**新建**。给你的片段起个名字，并复制示例中的代码，如下所示：

![严格比较更快吗？](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_05_02.jpg)

接下来，在左侧边栏中点击代码片段，然后点击**运行**。你会注意到控制台出现在**开发者工具**窗口的底部。我们还可以看到一个`Check PI: 0.016ms`的控制台消息。这告诉我们，在这个简单评估上运行比较运算符需要 0.016 毫秒来完成。如果我们更改比较运算符，用严格比较运算符来看看结果会怎样呢？

在更改运算符后，我们可以看到我们的第二个`console.time`消息是`Check PI: 0.007ms`。这个例子很简单，当然，但它证明了使用严格类型检查和严格比较运算符可以使代码运行得更快。

![严格比较更快吗？](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_05_03.jpg)

# 循环

在本节中，我们将详细学习创建`for`循环的有效方法。

## 循环如何影响性能

循环是遍历大量数据块或对象的一种非常常见方式，或者遍历 DOM 对象或数据片的每个实例。比如说我们有一个简单的循环，它生成一个`p`段落标签，并在页面内部以`i`整数循环的文本值，最大限制为`9000`。让我们来看一下下面的代码样本，了解一下是如何实现的。我创建了一个简单的 HTML5 页面，其中包含一个`script`标签，包含了第 10 行的代码，如下所示：

![循环如何影响性能](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_05_04.jpg)

那么，这段代码处理起来为什么这么费劲呢？首先，如果我们看第 17 行，可以看到一个名为`ptag`的变量，它被创建用来在我们的 DOM 中创建一个空段落标签。然后，我们在循环中应用整数的当前值到`ptag`变量的`innerText`属性；最后，我们用循环中指定的那个点的值创建新的段落标签，并将其应用到 DOM 中。为了进行性能测试，我们还用`console.time`包装方法将`for`循环包裹起来，以检查性能速度。如果我们用 Chrome 运行这个，我们应该能得到一个包含`for`循环中创建的每个数字的页面以及一个带有`process time`标签的`console.time`方法，如下面的屏幕截图所示：

![循环如何影响性能](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_05_05.jpg)

查看我们的`process time`标签，我们可以看到处理这段代码大约需要 18 毫秒才能完成。这并不好，但我们可以让它变得更好；让我们更新我们的代码，将`ptag`变量和我们的`i`整数变量移出`for`循环，这样它们就不会在每次`for`循环迭代时重新创建。让我们通过更新我们的代码来看看这样做会是什么样子，如下面的屏幕截图所示：

![循环如何影响性能](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_05_06.jpg)

请注意，在第 16 行，我们将`i`和`ptag`变量移出了循环，我们正在循环中重新分配创建的值和对象，而不是为每次循环迭代创建一个独特的范围。如果我们重新运行我们的页面，我们应该看到相同的`body`标签用比以前稍小的性能数字更新；在以下情况下，它应该在 15-17 毫秒的范围内运行：

![循环如何影响性能](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_05_07.jpg)

## 逆向循环性能神话

在 JavaScript 开发者圈中似乎出现了一个新想法，即逆向`for`循环的概念。逆向`for`循环就像一个循环，但循环是倒计时的，而不是正向计数的。

逆向循环背后的想法是，通过倒计数，一些 JavaScript 解释器可以更快地运行循环。让我们测试一下这个想法，看看它是否能实际上提高`for`循环的速度。首先，让我们创建一个`for`循环，从`9000`开始正向计数；我们不会在`for`循环中包含任何逻辑，除了添加一个名为`result`的外部变量。

使用我们的`result`变量进行递增，我们可以确定我们是否正在按应有的方式计数，并在`9000`末端触发一行代码，无论是*逆向*循环还是标准的`for`循环都是如此。在我们这个案例中，一个`console.timeEnd`函数，如以下代码所示，位于其自己的 HTML 页面中，页面底部有一个`script`标签。

![逆向循环性能神话](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_05_08.jpg)

让我们看看代码示例。在第 13 行，我们可以看到我们在开始`for`循环之前声明了我们的`result`变量，而在第 14 行，我们开始了带有名为`Time Up`的标签的`console.time`包装方法。在第 15 行，我们开始`for`循环并在第 16 行增加`result`。最后，在第 18 行，我们有一个条件，我们询问结果是否等于 9000，并在第 19 行执行我们的`timeEnd`函数。

如果我们把我们的`for`循环脚本放在`body`标签内加载页面，我们的**开发者工具**中的控制台应该输出以下信息：

![逆序循环性能神话](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_05_09.jpg)

所以，我们的`console.time`对象告诉我们，在 Google Chrome 中，最大值为`9000`的标准`for`循环大约需要 0.15 毫秒来处理。HTML 页面上没有其他内容，这确保了网络延迟不是因素。这是我们比较逆序循环的好基准。

现在，让我们测试一个逆序的`for`循环；在这里，我们创建了`for`循环的更新版本，包括我们的`result`变量。这与前面的过程类似，但让我们看看下一张截图中的代码示例：

![逆序循环性能神话](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_05_10.jpg)

如果我们看这个代码示例的第 15 行，我们可以看到我们稍微修改了这一行，使得循环是倒数而不是正数。我们首先将增量变量`i`（在这个例子中）设置为 9000 的值，然后我们测试`i`是否大于 0。如果是，我们将`i`的值减一。

在第 17 行，我们仍然像以前一样增加我们的`result`变量。这样，而不是使用`for`循环的递减变量`i`，`result`变量在循环外作为我们的计数器存在，是递增的。这被称为*逆序*循环。当`result`在第 18 行等于 9000 时，然后在第 19 行执行`console.timeEnd`函数。

让我们在 Chrome 浏览器的**开发者工具**选项中测试一下，看看我们得到什么值，如下所示：

![逆序循环性能神话](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_05_11.jpg)

所以，我们可以在**开发者工具**中看到我们的结果，我们的逆序循环处理时间大约是 0.16 毫秒，与`for`循环相比并没有太大差异。在许多情况下，除非我们需要为一个项目倒数，否则大多数 JavaScript 项目中不需要逆序`for`循环。

# 定时器

在这里，我们将详细学习如何优化 JavaScript 定时器。

## 定时器是什么，它们如何影响性能？

定时器是 JavaScript 的内置函数，它允许执行内联 JavaScript 代码，或者在 JavaScript 应用程序的生命周期的某个特定时间点之后调用函数，或者在应用程序的生命周期内重复调用。

定时器是 JavaScript 开发者工具箱中一个非常好的工具，但它们在性能方面也有自己的问题。考虑一下这样的事实：JavaScript 语言是单线程的，这意味着我们应用程序中的每一行代码都不能与应用程序中的另一行代码同时执行。为了解决这个问题，我们使用一个内置函数`setTimeout`。

`setTimeout`方法有两个参数来延迟代码块的执行；第一个参数要么是我们代码的函数名或者独立的 JavaScript 代码行，后面跟着一个整数，指定我们想要延迟代码执行的程度，单位是毫秒。

从表面上看，`setTimeout`函数可能看起来无害，但考虑一下这个。假设我们有两个函数，每个函数都由一个`setTimeout`函数触发，每个函数都有一个`for`循环，该循环将`for`循环的递增值输出到控制台窗口。每个函数将有一个不同的最大值，较低计数的函数将在第一个较大函数的`for`循环稍微之后调用。让我们来看看这里的代码示例：

![定时器是什么以及它们如何影响性能？](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_05_12.jpg)

我们可以看到这是一个带有我们代码的 script 标签的空的 HTML5 页面，在第 9 行。在第 13 行和第 20 行，我们有两个相似函数的开始：一个叫`delay300000()`，另一个叫`delay3000()`，每个函数都包含一个`for`循环，该循环使用`console.info`语句将循环的每一步输出到控制台。`console.info`语句是一种控制台打印类型，它简单地将控制台行格式化为表示信息的样式。

现在，在第 27 行，我们在一个`window.onload`函数内触发这两个函数，较大的延迟函数在页面加载后 50 毫秒调用，较短的函数稍后在第 150 毫秒调用。我们试试在 Chrome 中运行这个，并看看在 Dev Tools 中会发生什么，如下图所示：

![定时器是什么以及它们如何影响性能？](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_05_13.jpg)

在这里，我们可以注意到当我们把这些行输出到控制台时会有明显的延迟。我们也可以看到我们在给定的超时时间内触发了这两个函数。在前面的截图中，我们可以看到我们的`delay3000()`直到我们的较大函数`delay300000()`完成后才被触发。

### 处理单线程

遗憾的是，用纯 JavaScript，我们根本无法“多线程”同时运行这两个函数，但我们可以在我们的代码中加入类似`回调`的方法。`回调`方法就是一个当函数完成时触发的 JavaScript 函数。让我们设置我们的`delay300000()`函数，一旦它完成，就调用我们的`delay3000()`方法。下面就是这样做的样子：

![处理单线程](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_05_14.jpg)

查看我们的代码示例，我们可以在第 13 行看到我们添加了一个名为`callback`的参数。重要的是要知道，在这里，我们`callback`方法的命名并不重要，但包含一个函数占位符参数是重要的。我们的占位函数，将作为我们的回调函数，是`Delay3000()`。

注意我们如何在第 22 行将`Delay3000`大写。这样做的目的是指示 JavaScript 解释器这是一个**构造函数**，一个需要在内存中初始化的函数。这是通过将函数名称的第一个字母大写来实现的。您可能还记得从第二章，*使用 JSLint 提高代码性能*，如果我们使用大写函数名，JSLint 将返回警告，它认为使用了构造函数，即使它是一个普通函数。为了不让我们的解释器猜疑，我们希望确保我们正在编写我们意图中的函数和对象。

最后，我们通过移除`delay3000`的额外`setTimeout`，更新了我们的`onload`函数的逻辑，并在`delay300000()`函数中的`setTimeout`函数里添加了重新命名的`Delay3000`（没有括号）作为参数。让我们再次在浏览器中运行这个，并查看我们的控制台的输出。

如果我们滚动到控制台日志的底部（在处理初始`delay300000()`函数调用之后），我们可以看到我们的`Delay3000`日志消息在完成初始函数后出现。使用回调是高效管理应用程序线程并确保重负载应用程序正确加载堆叠的好方法，让你在初始函数完成后传递参数。

### 关闭循环

最后，正如我们在`callback`方法示例中看到的，出于性能原因，通常不建议使用大规模的循环。总是寻找更好的、更有效的方法来分解大循环，并调用其他函数来帮助平衡工作负载。

此外，我鼓励大家去了解一下 JavaScript **promises**，这是 EcmaScript 6 的一个特性。虽然在这个书的写作时期，它还不足以讨论，因为承诺仍然处于实验阶段。我鼓励你，亲爱的读者，继续跟进，了解当它最终定型时，将取代 JavaScript 中回调的继任者。您可以在 Mozilla 开发者网络网站上了解更多关于承诺的信息：[`developer.mozilla.org/en-US/`](https://developer.mozilla.org/en-US/)。

# 总结

在本章中，我们学习了条件语句以及严格的比较如何帮助我们的 JavaScript 在运行时表现更好。我们还学习了循环以及如何优化循环，防止在`for`循环中重复不需要的对象，从而使我们的代码尽可能高效。

最后，我们还学习了在 JavaScript 应用程序中关于定时器和单线程的知识，以及如何使用回调来使我们的代码在过度加载的情况下也能尽可能流畅地运行。接下来，我们将讨论数组和原型创建的性能，并找出如何在 JavaScript 中最佳地使用它们。


# 第六章：构造函数、原型和数组

既然我们已经熟悉了在没有 linter 或 IDE 测试代码的情况下优化 JavaScript，是时候深入研究更复杂的优化了，特别是当涉及到内存和对象创建时。在本章中，我们将探讨使用构造函数、原型和数组来优化大型 JavaScript 代码库。

我们计划在本书中覆盖以下主题：

+   使用构造函数和实例函数构建

+   使用原型实现替代构造函数

+   数组性能

# 使用构造函数和实例函数构建

在这里，我们将通过以下方式学习使用构造函数和实例函数：

## 闲言碎语

根据技能水平，跟随本书的我们中的一些人可能知道 JavaScript 中的原型，也可能不知道。如果你是那些听说过 JavaScript 中的原型但不是每天都在使用它们的读者，你不必担心，因为我们很快就会覆盖基本概念以及如何将它们应用于 JavaScript 性能。

如果你是那些知道闭包、继承、父子关系等概念的人，觉得自己属于后一种情况，因此想跳过这一章，我会鼓励你继续阅读，至少要浏览一下这一章，因为，作为 JavaScript 开发者，我们在使用 JavaScript 多年的时间里，往往会忘记一些常见的概念，而只是专注于影响我们性能的因素。

## 函数名称的维护

仔细观察下面这个简单的函数，看看你是否发现了这个函数的什么异常之处。

![函数名称的维护](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_06_01.jpg)

现在，当我们查看代码时，我们可以看到一个名为`AuthorName`的简单函数，它包含`author`参数。该函数使用了一个在第二章，*使用 JSLint 提高代码性能*中讨论的`use strict`语句，该语句强制**开发者工具**或其他类似检查器将该作用域中的任何警告视为错误。然后我们使用`return`关键字返回`author`参数。

这看起来相当正常；然而，让许多 JavaScript 开发者困惑的是函数名称的结构。注意`AuthorName`以大写字母*A*开头。在 JavaScript 中，当我们用大写字母声明一个函数名时，我们实际上是在告诉 JavaScript 解释器我们正在声明一个构造函数。

构造函数就是一个 JavaScript 函数，它的工作方式与其他任何函数都一样。我们甚至可以使用简单的`console.log`函数将作者的姓名打印到控制台，如下所示，使用**开发者工具**:

![函数名称的维护](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_06_02.jpg)

如果我们在这个`about:blank` **开发者工具**控制台或者带有以下代码的空白 HTML 页面中运行这个，我们会看到与预期一样的控制台输出，正如我们期望的那样。问题是，为了有效地使用构造函数，我们需要使用`new`关键字。

现在你可能会问，我们如何确定我们现有的 JavaScript 代码是否使用了构造函数。想象一个非常大的代码库，到处都是函数；如果连**开发者工具**选项都没有告诉我们需要使用`new`关键字而不是`static`函数调用的实例，我们如何检查这一点呢？

幸运的是，有一个方法。如果我们回忆在第二章*使用 JSLint 提高代码性能*中，JSLint 可以告诉我们是否需要使用`new`关键字。我已经添加了前面的代码示例，并在 JSLint 中启用了`console`和`browser`对象。查看 JSLint 在下述屏幕快照中呈现的错误：

![函数名称的维护](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_06_03.jpg)

正如我们从 JSLint 看到的，在第 11 行我们得到了一个错误，`Missing 'new'`作为唯一的错误，这表明我们有一个构造函数，我们需要像这样使用它。

## 理解实例

现在解决这个问题的简单方法是将`AuthorName`函数的名称更改为驼峰命名法；也就是说，我们将`A`更改为小写（`a`）。但在这里我们要将其表示为一个实例，你可能要问为什么？嗯，在 JavaScript 中，每当我们编写一个对象、变量、函数、数组等时，我们都在创建对象。

通过使用实例，我们可以降低对象的使用。在 JavaScript 中，实例在内存中只计算一次。例如，假设我们使用一个`document.getElementById()`方法。每个用该对象保存的变量都只有一次内存计数，但如果它在用`new`关键字声明的对象中，这个计数只计算一次，而不是为每次`getElementById()`的出现重复使用。使用`new`关键字，我们可以创建我们构造函数（在这个例子中是`AuthorName`）的一个实例，允许我们以通常的方式重用那个函数。

### 使用'new'创建实例

创建一个新的实例相当简单；我们只需调用一个新的实例来运行一个函数，如以下屏幕快照所示，在我们的`console.log`函数第 11 行使用`new`关键字：

![使用'new'创建实例](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_06_04.jpg)

如果我们在一个空白页面或一个简单的 HTML 页面中运行这段代码，我们会发现我们的日志输出方式并不如我们所期望。但在**开发者工具**的**控制台**面板中，我们可以看到一个对象返回`AuthorName {}`。这告诉我们，我们实际上是在记录一个新对象实例，而不是作者的名字。

为了正确显示这个名字，我们需要一个关键字来声明对构造函数实例的引用。为此，我们将使用`this`关键字；在 JavaScript 中，`this`是对执行作用域中确切点的引用。

在 JavaScript 中，`this`关键字指的是在脚本执行时使用时的作用域和变量。例如，当在函数中使用`this`关键字时，它可以引用与它处于同一作用域（或嵌套在函数中）的变量。通过使用`this`关键字，我们可以指向代码执行中某个点的变量和对象。

一个**作用域**就是一个拥有它自己变量和属性的 JavaScript 代码块。作用域可以包括单个 JavaScript 对象的全球化作用域，也就是说，一个完整的 JavaScript 文件，一个函数级作用域，其中变量和属性是在函数内部设置的，或者，如前面讨论的，一个构造函数，因为构造函数是一个函数。

让我们用`this`关键字重写我们的`AuthorName`构造函数，以便我们可以引用我们的作用域并在**控制台**面板中打印我们的值。我们需要在构造函数内部创建一个初始化器，以便返回我们的作用域变量。初始化器（有时称为`init`函数）在我们的构造函数内部指定某些变量并在创建时分配属性。

在这里，我们使用`this`关键字前缀来创建一个变量，以表示我们正在引用我们构造函数内的实例，后跟我们称为`init`的函数，这等于一个函数，就像我们使用变量来声明一个函数一样。让我们在下一张截图中看看这段代码：

![使用 'new' 创建实例](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_06_05.jpg)

看看第 13 行和第 15 行；在第 13 行，我们声明了一个名为`author1`的变量，它使用`new AuthorName`构造函数并带有`Chad Adams`字符串参数。在这个例子中，`author1`是`AuthorName`构造函数的一个实例，其唯一参数是`Chad Adams`。

还请注意，在第 15 行我们的`console.log`中，有一个名为`init()`的函数，它是我们的构造函数的一个内部函数。我们也可以在我们的构造函数中创建其他函数，例如像下面所示打印自定义日志消息：

![使用 'new' 创建实例](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_06_06.jpg)

正如我们在第 11 行所看到的，我们现在添加了一个`helloInfo()`函数，它属于我们的`AuthorName`构造函数，该函数使用`author`参数打印出一条自定义消息。然后，在第 20 行，我们通过简单地调用构造函数来调用这个函数，而没有使用`console.log`，这个构造函数有自己的`console.info`函数。

这有助于我们将逻辑局限于我们代码库中的一个单一对象，并使我们的代码井然有序。这称为面向对象；它在代码复用方面非常出色，但可能会在 JavaScript 的性能方面引起问题。让我们试一个例子。在这里，我们有两个相同的代码示例，每个都包裹在一个`console.time`和`console.timeEnd`函数中。下面的截图显示了我们的审查代码和渲染代码的结果时间：

![使用 'new' 创建实例](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_06_07.jpg)

所以，我们在这里的总时间大约是 2.5 毫秒。这还不算太坏，但现在让我们看看如果我们使用简单的非构造函数会发生什么，以及渲染相同输出的速度会是怎样的。如图所示，我把我们的构造函数拆分开来，创建了两个独立的函数。

我还以与我们的`console.log`函数完全相同的方式在次要函数中调用主要的`authorName`函数来打印作者的姓名。让我们运行下面截图中显示的更新后的代码，看看这比我们的构造函数方法是运行得更快还是更慢。然而，要记住，根据我们的系统速度和浏览器，结果可能会有所不同。

![使用 'new' 创建实例](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_06_08.jpg)

所以，使用静态函数我们的结果一直在 4 毫秒左右，这比我们用实例构建的对象要长。所以，在 JavaScript 中使用静态函数而不是原型函数是一个很好的用法！

# 使用原型实现替代构造函数

在这里，我们将学习关于使用原型实现替代构造函数的概念。

## 从内存的角度理解原型

我们介绍了如何在构造函数内部创建实例函数，也学习了使用`this`关键字在内部使用作用域。但是，还有一件事要介绍：在构造函数外部为构造函数添加另一个实例方法的能力，这在很多方面都有帮助。首先，它允许我们作为开发者，在需要时在预写的构造函数外部创建函数。接下来，它还保持了我们的内存使用量小。在深入这个话题之前，让我们重新调整我们的构造函数代码以使用原型，如图所示：

![从内存的角度理解原型](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_06_09.jpg)

现在看看这个更新后的代码，我们可以看到构造函数已经被移除，但被拉出构造函数：它们然后被移动到`AuthorName`函数的原型中，使用的是之前用过的同一个函数名。现在，您可以看到，在 10 行和 13 行，我们可以在我们的原型函数中使用`this`，因为我们正在引用我们构造函数的实例来打印那个实例的特定变量。

## 原型和构造函数哪个更快？

你可能会再次注意到，我在第 16 行到第 22 行再次添加了`console.time`和`console.timeEnd`函数到我们的函数调用中。那么你觉得原型相比于标准的构造函数会更快还是更慢呢？嗯，接下来我们可以在下一个屏幕截图中查看结果：

![哪个更快，原型还是构造函数？](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_06_10.jpg)

哇，与使用构造方法的 2.1 毫秒相比，原型在触发时需要 4.2 毫秒；这里发生了什么？我们本质上是在构造器之后创建了函数。输出很慢，但这是可以预料到的，因为原型的意图是与构造器一起使用。

在这个时候，我们可能会想：“哇，我从来不知道这些，我再也不会编写原型了！”现在，在我们开始从项目文件中删除原型之前，我想解释一下原型的可扩展性。确实，当为构造函数调用原型时，它们可能会更慢……“在小规模上”。我说的“在小规模上”是什么意思？嗯，像这个特定例子这样的小规模原型使用，我们可以看到原型的运行速度比传统的构造方法慢。

现在这里有个问题；对于更大的项目，大规模应用中的构造器可能有 50 个函数、200 个函数等等。当我们一次又一次地调用这些大的构造器时，仅调用构造器的实例在内存方面就会变得相当昂贵，因为它必须准备包含在内的所有函数。

通过使用原型方法，最初的构造器调用只会在内存中存储一次。对于小规模的原型使用，由于我们像使用简单的静态函数一样原地使用内存，所以性能提升并不明显，但是一旦设置好，它就会保存在内存中，不需要像静态 JavaScript 函数那样被重新召回或重新处理。

关于原型继承还有一点，虽然其使用可能会导致性能问题，但对于大型代码库来说，它可能非常有帮助。如果一个项目有范围担忧或使用可能引起冲突的库，可以考虑使用命名空间。这与原型类类似，但函数像简单的静态函数一样，以命名空间前缀来防止冲突。

# 数组性能

我们通常在处理性能问题时不会考虑数组，但在这里值得一提。首先，大型数组在处理大量数据时可能会很乱，并且是性能的消耗者。通常在数组方面，我们只需要担心两件事：搜索和数组大小。

## 优化数组搜索

让我们创建一个包含很多值的数组；在这里，我创建了一个名为`myArray`的数组，其中包含 1001 个值，以及数组的键和索引的字符串值。你可以在上面的网站的`Chapter_6`文件夹中的`06_09.js`文件中找到完整的版本。以下是整个数组的代码样本的一部分：

![优化数组搜索](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_06_11.jpg)

在数组中查找值有两种方法；第一种使用`indexOf()`函数，这是一个数组特定的函数，查找每个值并返回搜索到的值的索引。另一种方法是直接指定索引值，返回该值（假设我们知道需要值的索引）。

让我们尝试一个实验，我们将使用一个预制的`myArray`，包含 1001 个值，并使用`indexOf()`函数遍历它们，然后再用一个数组遍历。我们在`myArray`后面附上了代码，并用`console.time`和`console.timeEnd`函数包围了此代码块，如下所示，在 Chrome **开发者工具**中呈现时间：

![优化数组搜索](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_06_12.jpg)

这表明我们搜索这个大型数组的结果大约是 5.9 毫秒。现在，为了我们的比较，我将保留我们的`indexFound`变量，尽管我们可以简单地指定我们需要的数组值的索引。我们还将使用相同的索引值搜索，即`541`。让我们像这样更新我们的代码，并在 Chrome **开发者工具**中查看我们的结果：

![优化数组搜索](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_06_13.jpg)

看起来我们的结果大大缩短了我们的索引搜索性能时间。所以，当你在 JavaScript 中构建数组时，只有在你需要的时候才使用`indexOf`，并且尽可能直接调用索引。那么时间输出为什么会有这么大的差异呢？很简单；在第二个例子中，我们手动指定了数组的位置，而不是让 JavaScript 自己查找键。这加快了 JavaScript 解释器遍历我们的数组并提供值的速度。

# 总结

在本章中，我们学习了构造函数的正确使用方法。我们学习了使用`new`关键字在 JavaScript 中创建实例，并发现我们可以在同时作用域我们的代码时通过构造函数加速静态代码。

我们学习了原型以及它们在大应用程序中扩展得很好，而在小项目中添加的价值很少。最后，我们还学习了数组搜索以及使用`indexOf`函数时的性能损失。

在下一章中，我们将学习如何编写我们的 JavaScript 代码来优化我们的文档对象模型（DOM）以适应我们的项目。


# 第七章：不要碰 DOM

在本章中，我们将回顾与编写高性能 JavaScript 相关的 DOM，并了解如何优化我们的 JavaScript 以使我们的网络应用程序可见地更快渲染。

我们还将查看 JavaScript 动画，并测试它们与现代 CSS3 动画的性能；我们还将测试与页面关联的绘制重绘事件在 DOM 中，并快速测试可能影响性能的滚动事件。

我们将在本章中涵盖以下主题：

+   为什么担心 DOM？

+   我们需要一个 MV- whatever 库吗？

+   使用 `createElement` 函数创建新对象

+   动画元素

+   理解绘制事件

+   讨厌的鼠标滚动事件

# 为什么担心 DOM？

**文档对象模型**（**DOM**）是我们 HTML 内容在网络浏览器中的呈现方式。这并不完全相同于源代码；DOM 是我们源代码的实时更新版本，当我们在大纲浏览器中对网络应用程序的页面进行更新时。

我们可以说，优化快速的 JavaScript 肯定有助于我们的应用程序运行和表现更好，正如我们在之前的章节中学到的。但重要的是要理解，DOM 对 JavaScript 性能的重要性不亚于理解如何优化一个 `for` 循环。

在 Web 的早期时代，我们作为网络开发者并没有过多考虑 DOM。如果我们思考一下 JavaScript 的发展历程，我们可以看到网络开发世界发生了许多变化。如果我们回忆起谷歌之前的网络时代，我们知道网站相当简单，用户交互主要限于超链接标签和一个偶尔的 JavaScript `window.alert()` 函数以显示某种应用程序交互。

随着时间的推移，我们遇到了 Web 2.0，或者说，**异步 JavaScript 和 XML**（**AJAX**）诞生的时刻。如果你不熟悉 AJAX，我想总结一下：AJAX 网络应用程序允许开发人员从外部源拉取内容，通常是 XML 文件，（这是 AJAX 中的 X）。

使用 AJAX，网站内容突然变得动态，这意味着开发人员不必依赖后端技术来刷新带有更新数据的网络页面。突然之间，对更强大的 JavaScript 需求应运而生。企业和他们的客户不再希望网站以页面闪烁（或使用后端技术通过 `POST` 提交方法更新页面）的方式响应，尤其是像 Google Maps 和 Gmail 这样的网站，它们似乎在推动网络作为软件平台而非桌面操作系统平台的想法。

# 我们需要一个 MV- whatever 库吗？

如今，我们有框架可以帮助处理这类应用程序的繁重工作；AngularJS、Backbone.js、Knockout.js 和 jQuery 是几个想到的库。

然而，对于这本书，我们将坚持使用原生的 JavaScript，原因有两点。第一个原因是，许多这样的库都有自己的书籍，讨论性能和各种经验级别，这些都是很好的，但超出了本书的范围。第二个原因是，大多数开发者通常不需要这些库来构建项目。

请记住，这里提到的所有 JavaScript 库，以及网络上找到的所有库，都是 JavaScript！对于大多数项目，我们不应该需要一个库来使项目按照我们想要的方式构建；此外，这些库中有很多额外的代码。

我的意思是，这些库带有可能不需要的特性和功能，除非库是模块化的，否则很难在不删除不需要的功能的情况下使用它。如果你在一个团队环境中工作，其他人可能正在为应用程序的某些区域使用共享库，这些区域可能使用一些功能，但不是全部。

我们将在第九章*为 iOS 混合应用优化 JavaScript*中探讨移动 JavaScript 性能。我们会发现这些库变得更加沉重。现在话说回来，让我们看看一些常见的 DOM 破坏方式，以及如何使其表现更好。

# 使用`createElement`函数创建新对象

在这里，我们将学习如何使用`createElement`函数以及以下三个主题来创建新对象：

+   绕过`createElement`函数

+   使用`createElement`函数工作

+   何时使用`createElement`函数

## 绕过`createElement`函数

在 JavaScript 中，我们可以使用`document.createElement()`函数创建新的页面元素，并使用`document.createTextNode()`函数在生成的元素内部放置文本对象。通常，创建新元素以将其注入我们的 DOM 可能会消耗一些渲染资源，以及如果生成了多个元素，交互性能也会受到影响。

## 使用`createElement`函数工作

让我们测试一下`createElement`函数将内容渲染到屏幕上的效果。这是我们的测试：我们将使用`for`循环创建一个包含大量数据的表格。我们将使用文本对象填充表格单元格，该文本对象包含`for`循环迭代的计数。然后，我们将查看一个使用不同代码实现的创建相同效果的替代版本，并比较两者。让我们看看使用`createElement`函数的第一个选项，如下所示：

![使用 createElement 函数工作](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_01.jpg)

在这里，我们有一个简单的 HTML5 页面，在`head`部分有一些格式化的 CSS 样式，在第 21 行有一个空的占位符`div`元素，其`id`设置为`datainsert`。在第 25 行，我们有一个`匿名函数`，在加载到浏览器后立即运行；在第 26 行，我们开始一个`console.time`函数，以开始计算我们的 JavaScript 执行时间。然后我们在第 27 行创建一个表格元素变量`tableElem`；在第 28 到 31 行，我们设置一些属性，以帮助格式化我们的表格。

然后在第 33 行，我们开始我们的`for`循环；在`for`循环的作用域内，我们创建一个表格行元素、一个表格单元元素和一个文本节点，以将文本插入到我们生成的表格单元中，从第 35 行的`cellContent`变量开始，第 36 行的`tableTr`变量，第 37 行的`tableTd`变量。在第 39-41 行，我们将生成的单元格添加到表格中，并继续循环`10000`次。最后，我们将表格元素添加到页面上的`datainsert` div 元素中，以渲染我们的内容。让我们在浏览器中运行这个，并看看使用 Chrome **开发者工具**选项渲染内容需要多长时间。

![使用 createElement 函数工作](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_02.jpg)

如我们所见，这需要相当多的处理时间，在大约 140 毫秒的 Chrome 中，这是一个相当长的渲染时间。你可以在构建消息客户端或显示 JSON 数据时考虑这样做。无论什么情况，使用`createElement`函数的成本是相当大的，应该只在小范围内使用。

生成这种表格数据的其他方法，但不使用`createElement`函数，是使用`innerHTML`属性。这个属性提供了一种简单的方法，可以完全替换元素的 contents，并且赋值的方式与给变量赋值相同。当使用`innerHTML`属性时，你可以不刷新页面就改变页面的内容。这可以使你的网站感觉更快、对用户输入更有响应性。这个属性也可以使用`+=`附加运算符进行追加。知道了这个，我们可以以稍微不同的方式构建我们的代码基础。我们所做的是在下面的屏幕截图中显示：

![使用 createElement 函数工作](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_03.jpg)

这个布局应该与我们的`createElement`函数示例非常相似。在第 21 行，我们有一个相同的`datainsert` div；在第 25 行，我们的`匿名函数`开始执行。现在在第 28 行，我们看到有些不同；在这里，我们可以看到一个名为`tableContents`的字符串变量的开始，它是一个带有与前一个示例相同属性的 HTML 表格的开始。这就像我们之前使用`createElement`函数一样，只不过这次我们使用了一个 JavaScript 字符串形式的 HTML 标记，而不是一个 DOM 对象。

接下来，在第 30 行，我们开始我们的`for`循环，并将`tableContents`字符串与添加了表格行和表格单元格的新字符串一起附加，将 for 循环的迭代次数插入到单元格中，再次计数为 10,000 次。

当循环在第 35 行完成时，我们将我们的字符串附加以表格的闭合括号。最后，在第 37 行和 38 行，我们使用`innerHTML`属性，将我们的表格写入`datainsert` div 元素的`innerHTML`属性中。让我们在浏览器中运行这个例子并查看其处理时间。

![使用 createElement 函数工作](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_04.jpg)

这次我们的表格渲染时间大约为 40 毫秒，这比我们使用`createElement`函数的速度快了近四倍。这是一个巨大的速度提升！在 Chrome 中视觉效果也更快。

## 何时使用 createElement 函数？

尽管`createElement`函数速度较慢，但在生成复杂布局的 HTML 时，有时它会更 helpful，复杂的应用程序会生成比`innerHTML`属性可以样式化容纳的更多元素。

如果确实如此，这更多的是为了方便开发团队在修改元素类型时的可用性和易用性，而不是为了更新满足应用程序需求的完整字符串。无论如何，如果您需要创建 HTML 元素，`innerHTML`属性总是更快的。

# 动画化元素

在*Web 2.0*时代，JavaScript 的一个更加令人印象深刻的使用方式出现了，当时 AJAX 正在变得越来越受欢迎；另一种有趣的想法以 JavaScript 动画的形式出现。这些动画是通过简单地反复迭代一个元素的样式来创建的，该元素使用`setInterval`函数设置左上角位置，然后在元素达到终点后撤销它。这使得 div 似乎在页面上进行了微调或动画化。

## 以传统方式动画化

大多数 JavaScript 开发者都熟悉使用流行的 DOM 操作库 jQuery 进行动画制作，使用`animate`函数创建 DOM 动画。但是，由于我们在这本书中讨论的是纯 JavaScript，让我们来看一个从零开始构建的例子。查看以下屏幕截图中的代码：

![以传统方式动画化](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_05.jpg)

在这个例子中，我仅仅使用 JavaScript 创建了一个 WebKit 友好的动画（这意味着这只能在 Google Chrome 和 Apple Safari 浏览器中正确显示）。在第 7 行，我们设置了一些基本样式，包括一个带有`id`为`dot`的黑点 div 元素。

现在在第 27 行和 28 行，我们分别声明了`dot`和`i`变量。然后，在第 31 行，我们创建了一个名为`interval`的变量，这实际上是一个传递给`setInterval`函数的参数。在此代码中，它是每毫秒一次，这在第 38 行显示。在`setInterval`函数内部，我们将`i`变量的计数增加`1`，并更新`dot`元素的位置。最后，当`i`变量的值严格等于`450`时，我们使用`clearInterval`函数清除我们的`interval`变量，从而停止`setInterval`函数进一步处理。如果我们看看这个，我们可以在浏览器中使用纯 JavaScript 看到一个简单的动画淡入淡出。这在下方的屏幕截图中显示：

![老式动画](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_06.jpg)

现在，你可能会认为以这种方式创建`setInterval`函数可能是个问题，你可能是对的。幸运的是，我们现在作为开发者在创建这类动画时，为我们的 HTML5 应用程序有了另一种选择！

## 使用 CSS3 动画

让我们用仅 CSS3 和 JavaScript 来重建这个例子，以触发动画。再次，我们仅仅为 WebKit 内核浏览器进行样式设计，仅为简化。下面屏幕截图所示的是更新后的代码样本：

![使用 CSS3 动画](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_07.jpg)

通过这个例子，我们可以看到我们的 JavaScript 代码行要少得多，这是件好事；它使我们的内容样式纯粹基于 CSS，而不是使用 JavaScript 逻辑来样式化内容。

现在，在 JavaScript 方面，我们可以看到我们在第 39 行使用了相同类型的`匿名函数`，不同的是，我们设置了一个超时时间，以触发`dot`元素添加一个激活类属性，从而在 CSS3 中触发动画。这在我们示例的第 19 至 30 行中显示。

## 不公平的性能优势

在这本书中的许多代码示例中，我使用了`console.time`和`console.timeEnd`来回顾性能，这个例子也不例外。你可能注意到了，我将每个动画示例都包裹在一个`time`和`timeEnd`函数中，以测量处理时间正如下面的屏幕截图所示，它有点片面：

![不公平的性能优势](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_08.jpg)

正如我们在之前的屏幕截图中所看到的，JavaScript 处理时间大约是 1900 毫秒，而 CSS3 动画大约是 0.03 毫秒。现在，在得出 CSS3 方法更好的结论之前，我们必须记住，我们仅用 CSS3 来渲染页面，而 JavaScript 只处理动画的触发。这仍然更有效率，但应注意 JavaScript 处理的是更少的代码。

现在对于新浏览器，这是构建内容动画的推荐方式，因为迄今为止已经看到了性能改进，无论是由 JavaScript 还是其他方式实现的。然而，一些项目需要支持旧浏览器，这些项目可能无法访问 CSS3 转换和动画，或者我们在升级应用程序的动画部分的同时仍然保持兼容性。以下是在使用与之前相同的基于 JavaScript 的动画时实现这一点的一种方法：

![不公平的性能优势](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_09.jpg)

在这里，我们修改了最初的 JavaScript 示例，通过更新`dot`元素的位置；然而，我们在第 17 行和第 18 行添加了两条 CSS。第一个是一个`-webkit-transform`和`translate3d`属性，它只设置元素不改变位置；在旧浏览器或非 webkit 重点浏览器上，这个属性将被忽略。但在这里，它只是将元素的位置设置为初始位置，这听起来很傻，实际上也确实如此！

这实际上告诉 DOM 运行时，这需要作为一个独特的图形进程运行；它还告诉浏览器设备上的**图形处理单元**（**GPU**）快速绘制这个元素！同样的可以说对于`will-change`，这是一个类似的属性，它做的和`translate3d`属性一样的事情，不同的是它不是更新位置，而是告诉 GPU 以非常高的频率重新绘制这个元素，并期待它在 DOM 中发生变化。现在，这种做法被称为将元素添加到合成层。我们将在第九章，*为 iOS 混合应用优化 JavaScript*中更深入地介绍合成层。但现在，这就是我们在这里做的事情；这样，新浏览器仍然可以使用遗留的 JavaScript 动画获得一些视觉速度提升。

# 理解绘制事件

绘制事件是 DOM 事件，它会导致 Web 浏览器在 DOM 用 JavaScript 更新时绘制网页。对于内存较低的浏览器来说，这可能是一个问题，因为绘制事件需要大量的处理和图形渲染才能在大规模显示更新。

## 如何检查绘制事件？

通常，您可以在 Web Inspector 的时间线视图中找到绘制事件。由于绘制事件在 Web 浏览器中执行页面的过程中按时间顺序显示，因此在 Chrome 的**开发者工具**选项中这些显示略有不同。

打开 Chrome 的**开发者工具**选项，点击抽屉图标（它在**开发者工具**选项上方的右侧齿轮图标旁边）。接下来，在抽屉中打开**渲染**标签，然后点击**显示绘制矩形**选项。完成后，刷新页面。页面加载时，我们会看到页面的不同区域被绿色突出显示。这些是正在加载屏幕上的绘制事件。以下是一个使用我们的动画并显示在 Chrome 的**开发者工具**选项中启用绘制矩形的示例：

![如何检查绘制事件？](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_10.jpg)

注意绿色正方形在页面加载时出现，以及在动画完成时再次出现。这是因为 DOM 仅在页面加载或动画结束时重绘浏览器窗口。

偶尔，项目可以仅使用 JavaScript 创建相当复杂的动画。为了找出我们的 JavaScript 逻辑错误，并确保绘制事件没有造成问题，我们可以在 Chrome 的**开发者工具**中使用连续页面重绘功能。

## 测试绘制事件

为了测试这个，我们设置了一个带有内置错误的 JavaScript 动画，如图所示：

![测试绘制事件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_11.jpg)

这应该与我们在本章中构建的早期动画看起来非常相似。但如果我们查看第 35 至 38 行，我们可以看到有一个条件`else if`语句，检查我们的递增变量`i`是否在 250-258 范围内；如果是，`dot`元素的`left``style`将被移除。

当我们运行这个测试时，动画达到这个点时我们应该会遇到一个闪烁。我们可以通过在 Chrome 的**开发者工具**中启用连续页面重绘来验证这是否真的是一个 JavaScript 问题。

为此，打开**开发者工具**选项，打开抽屉，点击抽屉中的**渲染**标签。然后我们可以检查**启用连续页面重绘**和**显示绘制矩形**选项。当我们这样做时，我们的网页应该显示一个绿色覆盖层，并在浏览器窗口的右上角显示一个信息框。以下屏幕截图显示了这一点：

![测试绘制事件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_12.jpg)

现在，当我们重新加载页面，动画再次播放时，我们的`dot`元素应该在整个动画期间显示一个绿色的矩形框。这是 Chrome 强制页面不断重绘以更新动画。正如我们所看到的，即使在我们的预设错误发生时，矩形框仍然在点上，这表明了一个 JavaScript 问题。如果这是一个真正的绘制问题，当重绘出现问题时，矩形框会消失。

# 讨厌的鼠标滚动事件

绘制事件（或缺乏 thereof）并不是当你使用 JavaScript 工作时影响网络应用程序性能的唯一问题。对浏览器窗口或文档应用的滚动事件可能会对应用程序造成混乱；不断通过滚动鼠标触发事件，更不用说触发多个事件，永远都不是一个好主意。

如果我们正在编写一个应用程序，我们知道我们的应用程序是否有多个事件添加。但如果我们被交了一个需要更新的网络应用程序，Chrome 的**开发者工具**中有一个工具，可以让我们 visually check for scroll events。

让我们创建一个简单的示例来展示这个功能是如何工作的，以及它在尝试优化 DOM 界面时在寻找什么。为此，我创建了一个`mousewheel`事件，它将捕获鼠标指针相对于页面的*X*和*Y*坐标，并在具有`id`为`txtfield`的输入字段中打印出来；每当 I 移动鼠标滚轮时，它都会触发。让我们看看以下代码示例：

![讨厌的鼠标滚动事件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_13.jpg)

从这里我们可以看到页面本身相当轻，但在第 23 行，我们可以看到`mousewheel`事件监听器在起作用，使用`getMouseLocation`函数在第 26 行添加了一个持续的事件。然后在第 27 行，我们的具有`id`为`txtfield`的输入字段被分配了一个字符串，其中包含鼠标事件信息，抓取鼠标指针的`X`和`Y`坐标并将其应用于`txtfield`的值。现在让我们看看**开发者工具**如何突出显示滚动性能问题。

打开抽屉，打开**渲染**标签，然后点击**显示潜在的滚动瓶颈**。这将突出显示在 JavaScript 中分配了滚动事件的块区域；下面是我们示例在启用过滤器时的样子：

![讨厌的鼠标滚动事件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_14.jpg)

现在，这本身在性能方面并不是太糟糕，但是具有多个鼠标移动事件的应用程序可能会潜在地引起问题，如果移动区域重叠，问题会更严重。如果我们将在文本区域中添加相同的事件监听器并从文档中删除监听器，我们会在**开发者工具**过滤器中看到多个滚动监听器的实例吗？让我们通过查看本章最终示例文件`07_08.html`的输出来找到答案：

![讨厌的鼠标滚动事件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_07_15.jpg)

当然不是！正如我们所看到的，即使在一个元素上启用了`mousewheel`事件，整个页面也会被突出显示。由于`mousewheel`事件可以在 DOM 的顶部进行检查，即使一个应用程序只关注一个`mousewheel`事件的很小元素，整个页面也会受到影响。

因此，记住`mousewheel`事件是很重要的，因为它们可能会潜在地减慢您页面的性能。

# 总结

在本章中，我们介绍了 JavaScript 如何影响 DOM 的性能；我们回顾了`createElement`函数，并学习了如何更好地编写我们的 JavaScript 以优化从代码生成元素。

我们还回顾了 JavaScript 动画，并将其性能与现代 CSS3 动画进行了比较。我们还学习了如何优化现有或遗留的 JavaScript 动画。

最后，我们回顾了在 DOM 中处理绘图事件，并了解了当 JavaScript 对其进行操作后，DOM 是如何重新绘制其内容的；我们还介绍了 `mousewheel` 事件，并看到了它们如何可能导致 DOM 的性能下降。

在下一章中，我们将探讨 JavaScript 性能提升的新伙伴：*web 工作者*，以及如何让 JavaScript 表现得像一个多线程应用程序。


# 第八章：Web 工作者和承诺

在之前的章节中，我们解决了一些在通用 JavaScript 开发中常见性能问题。现在，我们来到了一个假设我们的项目可以支持新 JavaScript 特性的点，我们可以使代码比以前表现得更好。

这就是 Web 工作者和承诺发挥作用的地方。在本章中，我们将探讨两者并了解如何以及何时使用它们。我们还将发现它们的局限性，并理解它们在提高高性能 JavaScript 方面的优势。

# 首先理解局限性

在深入探讨 Web 工作者和承诺之前，我们需要了解与 JavaScript 语言本身有关的一个问题。如前几章所述，JavaScript 是单线程的，无法支持同时运行两个或更多方法。

多年来，作为 JavaScript 开发者，我们实际上从未真正关心过线程，更不用说本书中介绍的 JavaScript 内存问题了。我们的代码大部分存在于浏览器中，在同一页面内以内联方式运行，或者与同一服务器上的文件外部链接，以实现基本网页功能。

随着 Web 的发展，原本的前端编码对于高性能应用程序变得越来越必要，处理更大 JavaScript 应用程序的新方法也应运而生。今天，我们将这些新特性视为 ECMAScript 5 特性集的一部分。

在 ECMAScript 5 中，许多这些特性被整合到许多人认为的 HTML5 堆栈中。这个堆栈包括 HTML5（`DOCTYPE`和`HTML`标签）、CSS 3.0 版本和 ECMAScript 5。

这些技术使得 Web 比 AJAX 和 XHTML 开发时代强大得多。局限性在于这些特性是尖端技术，可能与所有浏览器都兼容，也可能不兼容。因此，在项目实施之前，使用这些新特性通常需要仔细思考。

我们从第二章*使用 JSLint 提高代码性能*开始就已经讨论过这些特性，包括`use strict`声明，它强制浏览器在 JavaScript 代码有严格书写或编码错误时抛出错误。也许你会问，既然`use strict`在所有浏览器中都得不到支持，我们为什么还要使用它。`use strict`声明的技巧在于，当为老浏览器编写时，它显示为一个字符串并被忽略。

这是一件好事，因为即使它在老浏览器中被忽略，我们仍然可以使用这个新特性并编写更高效的代码。不幸的是，这并不能推广到 ECMAScript 5 的所有特性；这包括 Web 工作者和承诺。

因此，在本章中，让我们记住，从现在开始，在处理代码示例时，我们需要将测试和编码集中在像 Google Chrome、Opera、Firefox 或苹果的 Safari 这样的较新浏览器上，甚至包括遵循相同标准的 Internet Explorer 的新版本。

# 网页工作者

网页工作者为我们这些 JavaScript 开发者提供了一种构建多线程 JavaScript 应用程序的方法；这项技术在较新的浏览器中可行，因为我们有一个名为**工作者**的对象。工作者对象本质上是一个外部的 JavaScript 文件，我们向其传递逻辑。

现在，这可能看起来有点奇怪。自从 JavaScript 诞生以来，我们不是一直在使用外部 JavaScript 文件吗？这个观点是正确的，但是网页工作者在浏览器处理 DOM 中文件执行的方式上有点新。让我们看看以下示例图表，了解浏览器如何读取文件：

![网页工作者](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_08_01.jpg)

所以，这里我们有一个单线程 JavaScript 应用程序，一个`DOMContentLoaded`事件，紧接着是`window.onload`事件，然后是简单命名的函数：`function1`、`function2`、`function3`分别触发。现在，如果我们的`function2()`函数执行一些复杂的`for`循环，比如计算 500 万次π，而`console.log(Shakespeare)`正在检查时间呢？好的，我们可以从以下图表中看到：

![网页工作者](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_08_02.jpg)

正如我们所看到的，一旦浏览器调用`function2()`，它会锁定并挂起，直到它能完成其执行，（假设运行代码的系统有足够的内存来执行）。现在要修复这个问题的一个简单方法可能是说：“嘿，也许我们不需要检查时间，或者也许我们只想计算一次π以提高性能。”。但是，如果我们别无选择，只能以这种方式编写代码呢？也许我们的应用程序必须那样工作，因此我们被迫编写一个复杂、性能缓慢的函数，这个函数执行缓慢；为了应用程序的成功，具有这种逻辑的函数必须触发。

好吧，如果我们必须要构建这样的应用程序，我们的解决方案就是网页工作者。让我们看看这与我们的单线程图表相比是如何工作的：

![网页工作者](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_08_03.jpg)

在我们的示例中，我们可以看到在图表中创建了一个新的工作者，它指向一个名为`worker.js`的外部 JavaScript 工作者文件。那个工作者以消息的形式发送一个响应。使用网页工作者，消息是我们在宿主脚本和工作者数据之间传递数据的方式。它的工作方式与 JavaScript 中的任何其他事件类似，都使用`onmessage`事件。

那么，在编码应用程序中这是怎样的呢？嗯，让我们找出答案！

以下屏幕快照中的代码示例以与前面图表类似的方式构建：

![网页工作者](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_08_04.jpg)

正如我们所看到的，这是一个简单的 HTML5 页面，在第 11 行有一个`script`标签。在第 13 行，我们首先声明了一个名为`function1()`的函数，它将信息消息打印到控制台；在第 15 行，我们开始一个新的定时器，以查看我们的工作者有多快。它被恰当地称为一个`Worker`。

接下来，在第 18 行我们声明了`function2()`；现在事情变得有趣了。首先，在第 19 行，我们声明了一个名为`func2_Worker`的变量；这个变量的命名并不重要，但最好是指明你的变量实际上是什么。在这个例子中，我在变量后添加了`_Worker`后缀，然后使用大写的`Worker`关键词创建一个新的网络工作者。

在括号内，我们添加了一个字符串，文件名，使用我们工作者文件的相对路径，名为`08_01-worker.js`。让我们来看看工作者文件内部。

![Web workers](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_08_05.jpg)

正如我们所看到的，工作者文件非常简单。在第 1 行声明了一个全局对象叫做`onmessage`，并将其赋值为一个带有`for`循环的函数。值得注意的是，我们还可以通过`self`和`this`关键词来引用这个上下文（例如：`self.onmessage`）。您可能注意到了我们还有一个名为`oEvent`的参数，它是任何通过`data`属性传递给工作者的数据的占位符。我们可以在第 3 行的`postMessage`函数中看到这一点。

`postMessage`函数是 ECMAScript 的内置函数，它要么向指定的工作者发送数据，要么如果没有分配工作者，它就会向任何可能监听的父级 JavaScript 工作者发送消息。现在让我们回到我们的根 HTML 页面脚本，看看第 20 行；这在下面的屏幕截图中显示：

![Web workers](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_08_06.jpg)

我们可以看到，通过调用我们的`func2_Worker`工作者变量，我们可以使用该工作者的`onmessage`属性，并在我们的根页面上调用一个函数；在这个例子中，您需要使用在工作者中使用的`oEvent`参数将消息记录到控制台。

这是很好的。但是我们是如何传递数据的呢？嗯，这很简单。第 24 行使用了`func2_Worker`变量，但利用了之前提到的`postMessage`函数。因为我们已经将工作者变量分配给了这个`postMessage`函数，这将把数据参数传递给我们的`oEvent`参数，在我们的`worker.js`文件中使用；在这个例子中，它是一个字符串，写着，“处理高性能的 JavaScript 工作者...”。

最后，在第 32 行和第 35 行，我们有两个事件监听器。一个是用于`DOMContentLoaded`事件，如我们图表中所示，是我们在执行线程中首先调用的函数，它只是输出一个日志消息，表明 DOM 已加载；这之后是我们的`window.onload`函数，它也打印一个日志消息，但它还会在页面加载时按顺序触发函数 1、2 和 3。让我们在浏览器中加载这个，并使用 Chrome 的**开发者工具**选项来看看会发生什么。查看控制台面板中的输出，它将类似于以下屏幕截图：

![Web 工作者](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_08_07.jpg)

嗯，这可不是个好迹象，因为我们可以看到控制台出现一个错误。`DOM Loaded`和`Page Loaded`日志消息出现，以及`function1(): Called.`之后，我们得到`Uncaught SecurityError: Failed to construct 'Worker': Script at (file:url) cannot be accessed from origin 'null'`错误消息。

那么这意味着什么呢？首先，我们必须明白使用 web 工作者类似于使用 AJAX。如果你的代码不在服务器上，那么在系统之间共享或收集数据时存在安全风险。现在这并不是错误的，但在测试我们的代码时，我们需要在本地服务器上测试，如 Apache 或 IIS，这样可以使用 HTTP 保护我们的内容。在 Chrome 中，还有另一种禁用此警告的方法，但这只适用于有限的测试。

## 使用本地服务器测试工作者

可以在 OS X 和 Linux 上快速使用 Python 创建本地服务器；如果你不是 Python*大师*，不要担心，因为这只是一个在几秒钟内启动服务器的终端代码片段。

首先，打开终端并设置其路径；这应该是你的文件所在的路径。你可以通过使用更改目录命令或`cd`来实现。以下是一个将路径设置为活动用户桌面路径的示例，使用*tilde*键：

```js
cd ~/Desktop

```

一旦完成，我们可以使用以下简单的单行 Python 命令来启动服务器，该命令调用一个内置的简单服务器方法：

```js
python -m SimpleHTTPServer

```

一旦我们按下*Enter*键，我们就可以启动服务器了。我们可以在 Chrome 中输入`http://127.0.0.1:8000`来查看服务器根目录；我们应该 then 看到一个可以访问的文件列表。另外，如果你需要关闭服务器，你可以退出终端，或者使用*CTRL* + *Z*手动杀死服务器。

![使用本地服务器测试工作者](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_08_08.jpg)

现在去打开 HTML 文件，从`worker.js`文件中调用工作者脚本。我们应该然后在 Chrome 的**开发者工具**中的控制台面板看到一千行代码迭代我们的"for 循环"从我们的工作者 JavaScript 文件中。

我们还可以看到，在第五行控制台中，`console.timeEnd`函数停止了约 0.5 毫秒，说明它在处理循环之前被调用。这显示在以下屏幕截图中：

![使用本地服务器测试工作者](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_08_09.jpg)

在继续之前，让我们检查一下在下一个代码示例中，这个流程在工作者外部会运行多长时间。我们在页面本身重新创建了循环的逻辑，而没有使用网页工作者。我们仍然使用`console.time`函数来测试线程运行到`function3()`被触发的时间。让我们看一下下面的代码并进行复习：

![使用本地服务器测试工作者](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_08_10.jpg)

所以，在第 19 行，我们移除了对工作者文件的引用，这是一个`.js`文件，并将`for`循环移到了页面中。在这里，它会循环一千次并在控制台打印。现在在第 32 行，我们有一个`window.load`事件监听器，我们按顺序调用我们的函数，分别是 1、2 和 3。

然后我们再次使用`console.time`函数来跟踪一个过程持续的时间。由于这个代码示例现在是单线程的，我们应该看到`timeEnd`函数触发的时间更长。让我们运行我们的代码并查看下一个屏幕截图：

![使用本地服务器测试工作者](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_08_11.jpg)

不错啊！在这里，我们的时间比我们的多线程工作者示例要长得多，比我们的网页工作者大约慢 70 毫秒。这并不是一个坏的提升，虽然很小，但仍然有帮助。现在，工作者的一个问题是在主线程上触发下一个函数需要花费很长时间。我们需要有一种方式在函数异步完成时调用一个函数，为此我们有了 JavaScript 承诺。

# 承诺

JavaScript 承诺也是优化我们 JavaScript 代码的一种新方法；承诺的理念是你有一个函数被链接到主函数，并且按照编写顺序依次执行。这是它的结构。首先，我们使用`Promise`对象创建一个新的对象，在括号内写入主函数，并将新的承诺对象赋值给一个变量。

在继续之前需要注意的一点是，JavaScript 承诺是 EcmaScript 6 特定的。因此，在这个部分，我们需要在我们的代码中测试一个准备好 EcmaScript 6 的浏览器，比如 Google Chrome。

接下来，在我们的`promise`变量中，我们使用`then`关键字，实际上它的工作方式就像一个函数。但它只在我们的根承诺函数完成时才会触发。此外，我们可以将`then`关键字一个接一个地链接起来，并依次异步执行 JavaScript，以确保我们承诺中的作用域变量，当然会承诺传递给下一个`then`函数这些变量将具有设置的值。让我们看一个示例承诺，看看这是如何工作的：

![承诺](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_08_12.jpg)

在我们的代码示例中，有一个 HTML5 页面带有内嵌的`script`标签。我们页面上有两个元素，我们通过`button`标签的`makeAPromise()`函数附加的`onclick`事件进行交互或查看，在第 13 行。在第 15 行，我们有一个带有`id`为`results`的`div`标签，其内部 HTML 保持为空。

接下来，在第 19 行我们创建了`makeAPromise`函数，并在第 20 行设置了一个名为`promiseCount`的`count`变量。现在，就在这里创建我们的 promise。在第 22 行，我们创建了一个名为`promiseNo1`的变量，并将其赋值为一个新的`Promise`对象。在这里，你可以注意到我们是如何开始用一个`function`作为参数来打开括号的，这从第 23 行开始，我们在该函数内部有一个`resolve`参数。我们稍后再讨论这个问题。

在我们的`Promise`函数中，有一个简单的`for`循环，将`for`循环的值乘以`5`，然后`then`函数将其赋值给我们的`promiseCount`变量。为了完成我们的`Promise`对象的函数，注意一个新的关键字，`resolve`！`resolve`关键字是一种专门用于 promise 的返回类型；它设置了 promise 的返回值。还有其他一些 promise 返回类型，如`reject`，如果我们想要的话，它可以让我们返回一个失败值。然而，在这个例子中，我们保持简单，只使用`resolve`。

现在，如果你记得第 23 行，我们的`Promise`函数有一个内部函数，带有`resolve`参数。虽然这看起来可能有点奇怪，但它是我们使 promise 工作所必需的；通过在函数中添加`resolve`，我们告诉我们的 promise 我们需要在`Promise`函数内部使用`resolve`函数。例如，如果我们需要`resolve`和`reject`，我们会写成`function (resolve, revoke) {}`。

回到第 29 行，我们将我们的`resolve`赋值为一个字符串，输出我们的值并填充我们的`div`，但我们这里不赋值`innerHTML`属性；这是通过我们的`promiseNo1.then`函数来完成的。这个像是一个跟随 promise 的`resolve`函数的函数。

最后，在第 32 行，我们调用了我们`promiseNo1`变量的实例，使用了`then`函数，并再次用它自己的内部函数包装了括号。我们可能会注意到，在第 33 行，我们传递了一个名为`promiseCount`的参数。这是我们第 22 行声明的`Promise`函数中的`resolve`值。我们然后在第 33 行再次使用它，在那里我们将我们的`results div`元素赋值给它的`innerHTML`属性。

## 测试一个真正的异步 promise

对于这个简单的例子，我们可以看到 promise 的结构以及当链式调用时每个触发是如何需要的；当我们链式调用 promise 时，我们可以看到即使我们创建了一些导致执行延迟的单线程 JavaScript 代码，promise 仍然可以触发链式函数。在这个例子中，是一个`setTimeout`函数；让我们来看看下面屏幕截图中显示的新代码样本：

![测试一个真正的异步 promise](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_08_13.jpg)

在这个简单的例子中，我们可以看到承诺链如何在不断线的情况下工作。在这里，我们在第 20 行设置了一个`timerCount`变量；然后我们将打印出在第 15 行找到的空的`results` `div`元素。接下来，通过重用我们的`promiseNo1`变量及其自己的承诺实例，我们创建了一个`for`循环，使用`Math.random()`随机化`timerCount`，当循环完成时，它允许生成一个随机数，然后乘以 10000。

最后，我们使用解决函数返回我们的承诺，它链式地连接到第 31 行的`then`函数；在这里，我们有一个名为 response 的参数作为我们的`resolve`函数的值。现在在第 33 行，我们有一个名为`totalCount`的变量，其中我们有 response 参数和`timerCount`函数相加。

接下来，我们创建了一个`setTimeout`函数，它使用我们声明的`totalCountvariable`变量设置的时间将`results` `div`元素附加第二行，同时仍然将`timerCount`函数作为我们的超时值。现在，我们链的最后一部分是第 40 行的另一个`then`函数。在这里，我们再次附加`results` `div`元素，但请注意，我们是从我们的第二个链式`then`函数打印的。让我们看看在 Chrome 中这是如何工作的，如下面的屏幕截图所示：

![测试一个真正的异步承诺](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_08_14.jpg)

看看输出。在这里，我们可以看到，每次点击按钮，我们都会为承诺链的每个点得到一个数字计数。我们有`First count`上的值为`0`，`Third count`上有随机较大的数字。等等！那是第三次计数吗？是的，请注意第三次计数在第一次之后；这表明，即使我们在等待 for 循环处理时，第三个承诺也在继续。

在下一行，我们看到一个更大的数字值，在我们的行中注明了`Second count`；如果我们继续点击按钮，我们应该看到一个一致的模式。使用承诺可以帮助我们在不需要在链中立即获得特定值的情况下多线程代码。我们还可以通过使用承诺将一些代码从我们的主 JavaScript 线程中移除，从而获得性能上的好处。

# 总结

在本章中，我们回顾了如何使用网络工人，以及网络工人在实际应用中在技术和概念上的局限性。我们还使用了 JavaScript 承诺，在这里我们学习了与承诺相关的常见关键词，如`respond`和`revoke`。我们看到了如何使用`then`函数将我们的承诺与主应用程序线程同步，以创建一个多线程的 JavaScript 函数。

在下一章中，我们将了解从像 iOS 和 Android 这样的移动设备工作如何影响我们的性能以及如何在设备上调试性能。


# 第九章：优化 iOS 混合应用中的 JavaScript

在本章中，我们将探讨优化 iOS 网络应用（也称为混合应用）中 JavaScript 的过程。我们将查看一些常见的调试和优化 JavaScript 及页面性能的方法，无论是在设备的网络浏览器中，还是在独立应用的网络视图中。

此外，我们将查看 Apple Web Inspector，并了解如何将其用于 iOS 开发。最后，我们还将对建立混合应用有所了解，并学习帮助更好地为 iOS 构建以 JavaScript 为重点的应用的工具。此外，我们还将了解一个类，它可能有助于我们进一步学习。

我们将在本章中学习以下主题：

+   准备进行 iOS 开发

+   iOS 混合开发

# 准备进行 iOS 开发

在用 Xcode 示例开始本章并使用 iOS 模拟器在 JavaScript 性能书籍中之前，我将展示一些本地代码，并使用尚未在本课程中介绍的工具。无论平台如何，移动应用开发都是各自的书籍。在覆盖 iOS 项目的构建时，我将简要概述设置项目和编写*非 JavaScript*代码以将我们的 JavaScript 文件引入混合 iOS WebView 进行开发的过程。这是必要的，因为 iOS 对其基于 HTML5 的应用进行安全保护的方式。使用 HTML5 的 iOS 应用可以进行调试，要么从服务器上，要么直接从应用上，只要该应用的项目在主机系统（意味着开发者的机器）上以调试设置进行构建和部署。

本书的读者不需要从一开始就了解如何构建本地应用。这是完全可以接受的，因为你可以复制粘贴，并跟随我一起进行。但我将展示代码，让我们达到测试 JavaScript 代码的阶段，所使用的代码将是渲染您内容的最小和最快可能的代码。

所有这些代码示例都将在 Packt Publishing 的网站上以某种类型的 Xcode 项目解决方案的形式托管，但它们也将在此处展示，如果您想要跟随，而不依赖代码示例。现在说到这里，让我们开始…

# iOS 混合开发

Xcode 是苹果公司提供的用于开发 iOS 设备和 Macintosh 系统桌面设备的 IDE。作为一个 JavaScript 编辑器，它的功能相当基础，但 Xcode 应该主要用作项目工具集之外，针对 JavaScript 开发者的工具。它为 JavaScript、HTML 和 CSS 提供基本的代码提示，但不止这些。

要安装 Xcode，我们需要从 Mac App Store 开始安装过程。近年来，苹果公司将它的 IDE 移到了 Mac App Store，以便为开发者更快地更新，进而为 iOS 和 Mac 应用程序提供更新。安装过程很简单；只需用你的 Apple ID 登录 Mac App Store 并下载 Xcode；你可以在顶部搜索它，或者如果你在右侧栏查看流行免费下载，你可以找到一个到 Xcode Mac App Store 页面的链接。一旦你到达这个页面，点击**安装**，如下图所示：

![iOS 混合开发](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_11.jpg)

重要的是要知道，为了本章节的简单起见，我们将不会将应用程序部署到设备上；所以如果你对此感到好奇，你需要积极参与苹果的开发者计划。该计划的费用为每年 99 美元，或者 299 美元的企业许可，允许将应用程序部署在 iOS 应用商店之外。

如果你好奇想了解更多关于部署到设备的信息，本章节的代码将在设备上运行，前提是你的证书已经设置好。

关于这方面的更多信息，请查看苹果公司在线的 iOS 开发者中心文档：[`developer.apple.com/library/ios/documentation/IDEs/Conceptual/AppDistributionGuide/Introduction/Introduction.html#//apple_ref/doc/uid/TP40012582`](https://developer.apple.com/library/ios/documentation/IDEs/Conceptual/AppDistributionGuide/Introduction/Introduction.html#//apple_ref/doc/uid/TP40012582)。

安装完成后，我们可以打开 Xcode 并查看 iOS 模拟器；我们可以通过点击**XCode**，然后点击**打开开发者工具**，然后点击**iOS 模拟器**来实现。第一次打开 iOS 模拟器时，我们将看到一个 iOS 设备的模拟，如下图所示。注意这是一个模拟，*不是*一个真实的 iOS 设备（即使它感觉非常接近）。

![iOS 混合开发](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_12.jpg)

对于在外部应用程序中工作的 JavaScript 开发者来说，一个很酷的技巧是，他们可以快速地拖放 HTML 文件。由于这个原因，模拟器将打开移动版 Safari，iPhone 和 iPad 的内置浏览器，并像在 iOS 设备上一样渲染页面；这在测试页面并在将其部署到 Web 服务器之前非常有帮助。

## 设置简单的 iOS 混合应用程序

内置混合应用程序上的 JavaScript 性能可能会比在移动版 Safari 上的相同页面慢得多。为了测试这一点，我们将使用苹果公司的新编程语言**Swift** 构建一个非常简单的网络浏览器。Swift 是一种准备好的 iOS 语言，JavaScript 开发者应该会感到很熟悉。

Swift 本身遵循类似于 JavaScript 的语法，但与 JavaScript 不同，变量和对象可以赋予类型，从而实现更强大，更精确的编码。在这方面，Swift 遵循类似于可以在*ECMAScript 6*和*TypeScript*编码实践风格中看到的语法。如果您正在查看这些新语言，我鼓励您也查看 Swift。

现在让我们创建一个简单的网页视图，也称为**UIWebView**，这是在 iOS 应用中创建网页视图的类。首先，让我们创建一个新的 iPhone 项目；我们使用 iPhone 来保持我们的应用程序简单。打开 Xcode 并选择**创建新的 XCode 项目**项目；然后，如以下屏幕截图所示，选择**单视图应用程序**选项并点击**下一步**按钮。

![设置简单的 iOS 混合应用程序](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_13.jpg)

在向导的下一页中，将产品名设置为`JS_Performance`，语言设置为**Swift**，设备设置为**iPhone**；组织名称应该会根据您在 OS 中的账户名称自动填充。组织标识符是用于我们应用程序的反向域名唯一标识符；这可以是您认为合适的任何内容。为了说明目的，以下是我的设置：

![设置简单的 iOS 混合应用程序](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_14.jpg)

一旦您的项目名称设置完成，点击**下一步**按钮，并将其保存在您选择的文件夹中，**Git 仓库**保持未选中状态。完成后，在**项目导航器**中选择**Main.storyboard**，您可以在左侧面板中找到它。现在我们应该处于故事板视图中。让我们打开**对象库**，它可以在右下角的子标签中找到，该子标签中有一个圆形内的方形图标。

在右下角的搜索栏中在**对象库**中搜索`Web View`，然后将其拖动到代表我们 iOS 视图的方形视图中。

![设置简单的 iOS 混合应用程序](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_15.jpg)

在使用 Swift 链接 HTML 页面之前，我们需要考虑另外两件事；我们需要设置约束条件，因为本地 iOS 对象将被拉伸以适应各种 iOS 设备窗口。要填充空间，您可以通过在 Mac 键盘上选择**UIWebView**对象并按*Command* + *Option* + *Shift* + *=* 来添加约束。现在您应该看到一个蓝色的边框短暂地出现在您的 UIWebView 周围。

最后，我们需要将我们的**UIWebView**连接到我们的 Swift 代码；为此，我们需要打开**助手编辑器**通过按*Command* + *Option* + *Return*在键盘上。我们应该看到**ViewController.swift**在**Storyboard**旁边的侧边栏中打开。要作为代码变量链接此内容，请右键点击（或选项点击**UIWebView**对象），然后按住鼠标左键拖动**UIWebView**到**ViewController.swift**代码中的第 12 行在**助手编辑器**中。以下图表显示了这一点：

![设置简单的 iOS 混合应用程序](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_19.jpg)

完成这些步骤后，会出现一个弹窗。现在保持所有内容与默认设置相同，但将名称设置为`webview`；这将是我们 UIWebView 的变量引用。完成后，保存你的`Main.storyboard`文件，然后导航到你的`ViewController.swift`文件。

现在查看下面的截图中显示的 Swift 代码，并将其复制到项目中；重要的是第 19 行的文件名和类型被加载到网络视图中；在这个例子中，这是`index.html`。

![设置简单的 iOS 混合应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_16.jpg)

显然，我们没有`index.html`文件，所以让我们创建一个。点击**文件**，然后选择**新建**，接着选择**新建文件**选项。接下来，在**iOS**下选择**空应用程序**，然后点击**下一步**完成向导。将文件保存为`index.html`，然后点击**创建**。现在打开`index.html`文件，并将以下代码输入到 HTML 页面中：

```js
<br />Hello <strong>iOS</strong>
```

现在点击**运行**（主 iOS 任务栏中的播放按钮），我们应该能在我们自己的应用中看到我们的 HTML 页面，如下所示：

![设置简单的 iOS 混合应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_17.jpg)

太棒了！我们用 Swift 构建了一个 iOS 应用（即使它是一个简单的应用）。让我们创建一个结构化的 HTML 页面；我们将用下面的截图中显示的 HTML 覆盖我们的`Hello iOS`文本：

![设置简单的 iOS 混合应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_18.jpg)

在这里，我们使用标准的`console.time`函数，在完成后向我们的 UIWebView 页面打印一条消息；如果我们点击 Xcode 中的**运行**，我们将在加载时看到`循环完成`的消息。但我们如何获取我们的性能信息呢？我们如何在 HTML 页面中的第 14 行的`console.timeEnd`函数代码？

## 使用 Safari 网络检查器进行 JavaScript 性能

苹果为 UIWebView 提供了网络检查器，而且这个检查器与桌面 Safari 的检查器相同。它很容易使用，但有一个问题：检查器只适用于从 Xcode 项目中启动的 iOS 模拟器和设备。这个限制是由于对混合应用可能包含的敏感 JavaScript 代码的安全担忧，如果可见可能会被利用。

让我们检查一下我们项目的内嵌 HTML 页面控制台。首先，在您的 Mac 上打开桌面 Safari 并启用开发者模式。启动**偏好设置**选项。在**高级**标签下，确保已选中**在菜单栏中显示开发菜单**选项，如下面的截图所示：

![使用 Safari 网络检查器进行 JavaScript 性能测试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_20.jpg)

接下来，让我们重新运行我们的 Xcode 项目，启动 iOS 模拟器，然后重新运行我们的页面。一旦我们的应用在显示**循环完成**结果时运行，打开桌面 Safari 并点击**开发**，然后**iOS 模拟器**，接着点击**index.html**。

如果你仔细看，当你将鼠标悬停在`index.html`上时，iOS 模拟器的 UIWebView 会以蓝色高亮显示；如下的截图显示了一个可见的页面：

![使用 Safari 网络检查器进行 JavaScript 性能测试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_21.jpg)

在**index.html**上释放鼠标后，Safari 的**网络检查器**窗口会出现，显示我们混合型 iOS 应用的 DOM 和控制台信息。Safari 的**网络检查器**在功能集上与 Chrome 的**开发者工具**相当相似；在**开发者工具**中使用的面板在**网络检查器**中也是以图标的形式存在的。

现在让我们在**网络检查器**中选择**控制台**面板。在这里，我们可以看到完整的控制台窗口，包括我们在`for`循环中包含的`Timer` `console.time`函数测试。正如我们在以下截图中看到的，循环在 iOS 中处理了 0.081 毫秒。

![使用 Safari 网络检查器进行 JavaScript 性能测试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_22.jpg)

## UIWebView 与 Mobile Safari 比较

如果我们想将我们的代码移动到 Mobile Safari 进行测试呢？这很容易；如前所述，我们可以将`index.html`文件拖放到我们的 iOS 模拟器中，然后操作系统将打开移动版 Safari 并为我们加载页面。

准备好之后，我们需要重新连接 Safari**网络检查器**到**iOS 模拟器**并重新加载页面。完成后，我们可以看到我们的`console.time`函数要快一些；这次大约是 0.07 毫秒，比 UIWebView 快了 0.01 毫秒左右，如图所示：

![UIWebView 与 Mobile Safari 比较](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_23.jpg)

对于一个小应用来说，这在性能上的差别很小。但是，随着应用越来越大，这些 JavaScript 处理过程的延迟会越来越长。

我们还可以使用 Safari 的**网络检查器**工具中的调试检查器来调试应用。在 Safari 的**网络检查器**顶部菜单栏中点击**调试器**。我们可以通过点击行号来在我们的嵌入式脚本中添加一个断点，然后使用*Command* + *R*刷新页面。在下面的截图中，我们可以看到在页面加载时断点发生，我们可以在右侧面板中看到我们的作用域变量：

![UIWebView 与 Mobile Safari 比较](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_24.jpg)

我们还可以使用时间线检查器来检查页面加载时间。在**网络检查器**顶部点击**时间线**，现在我们将看到一个类似于 Chrome 的**开发者工具**中的**资源**标签页的时间线。让我们用键盘上的*Command* + *R*刷新我们的页面；时间线然后处理页面。

注意，在几秒钟后，**网络检查器**中的时间线在页面完全加载时停止，所有 JavaScript 处理过程也停止。这是当你使用 Safari 的网络检查器而不是 Chrome 的开发者工具时的一个很好的功能。

![UIWebView 与 Mobile Safari 比较](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_25.jpg)

## 提高混合性能的常见方法

使用混合应用程序，我们可以使用我们在前面的章节中学到的所有提高性能的技术：使用像 Grunt.js 或 Gulp.js 这样的构建系统，使用 JSLint 更好地优化我们的代码，在 IDE 中编写代码以创建我们应用程序更好的结构，并帮助检查我们代码中的任何多余代码或未使用的变量。

我们可以使用最佳性能实践，例如使用字符串来应用 HTML 页面（如`innerHTML`属性），而不是创建对象并以此方式将它们应用到页面上，等等。

不幸的是，混合应用程序的性能不如原生应用程序的事实仍然成立。现在，不要让这使您沮丧，因为混合应用程序确实有很多优点！其中一些如下：

+   它们（通常）比使用原生代码更快地构建

+   它们更容易定制

+   它们允许快速为应用程序制作原型

+   它们比找到一个原生开发者更容易地交接给其他 JavaScript 开发者

+   它们是便携式的；它们可以针对其他平台（需要一些修改）重新用于 Android 设备、Windows 现代应用、Windows Phone 应用、Chrome OS，甚至是 Firefox OS。

+   他们可以使用像*Cordova*这样的辅助库与原生代码交互

然而，在某个时刻，应用程序的性能将受到设备硬件的限制，建议您转向原生代码。但是，我们如何知道何时转移呢？嗯，这可以通过使用**颜色混合层**来实现。**颜色混合层**选项在设备显示上应用一个覆盖层，突出显示性能较慢的区域，例如，用绿色表示良好性能，用红色表示性能较差；颜色越深，性能影响就越大。

使用 Xcode 重新运行您的应用程序，然后在 iOS 模拟器的 Mac OS 工具栏中选择**调试**，然后选择**颜色混合层**。一旦我们这样做，我们就可以看到 iOS 模拟器显示了一个绿色覆盖层；这显示了 iOS 处理我们的渲染视图所使用的内存量，包括本地和非本地代码，如下图所示：

![提高混合性能的常见方法](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_26.jpg)

目前，我们可以看到大部分都是绿色覆盖层，除了状态栏元素，这些元素占用更多的渲染内存，因为它们覆盖了网页视图，并且必须反复在这些对象上重新绘制。

让我们将我们的项目复制一份，命名为`JS_Performance_CBL`，然后用下面的代码样本更新我们的`index.html`代码，如下图所示：

![提高混合性能的常见方法](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_27.jpg)

在这里，我们有一个简单的页面，里面有一个空的 div；我们还有一个带有`onclick`函数的按钮，该函数名为`start`。我们的`start`函数将使用`setInterval`函数不断更新高度，每毫秒增加一次高度。我们的空 div 还使用内联`style`标签分配了一个背景渐变。

移动设备上 CSS 背景渐变通常是一个巨大的性能负担，因为它们可能会在 DOM 更新自己时反复重新渲染。其他一些问题包括监听事件；一些较早或较低端的设备没有足够的 RAM 来为页面应用事件监听器。通常，为 HTML 应用`onclick`属性是一个好习惯，无论是内联还是通过 JavaScript。

回到渐变示例，让我们在 iOS 模拟器中运行此操作，在点击我们的 HTML 按钮触发 JavaScript 动画后启用**颜色混合层**。

![提高混合性能的常见方法](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_09_28.jpg)

不出所料，我们现在看到我们扩展的 div 元素有一个红色覆盖层，这表明这是一个确认的性能问题，这是无法避免的。为了解决这个问题，我们需要移除 CSS 渐变背景，它将再次显示为绿色。然而，如果我们必须包括一个渐变，以符合设计规范，那么就需要一个本地版本。

面对这些问题之类的 UI 问题，了解正常开发工具和 Web 检查器之外的工具非常重要，并利用提供更好分析代码的移动平台工具。现在，在我们结束这一章之前，请注意 iOS 网络视图的某些具体事项。

## WKWebView 框架

在撰写本文时，苹果公司宣布了 WebKit 框架，这是一个旨在用更先进、性能更好的网络视图替换 UIWebView 的第一方 iOS 库；这是为了用整体性能更优的应用程序替换依赖 HTML5 和 JavaScript 的应用程序。

被称为**WKWebView**的 WebKit 框架，是开发者圈子里的新一代网络视图，可以添加到项目中。WKWebView 也是这个框架的基础类名。这个框架包括许多功能，使原生 iOS 开发者能够利用这些功能。这包括监听可以触发原生 Objective-C 或 Swift 代码的函数调用。对于我们这样的 JavaScript 开发者来说，它还包括一个更快的 JavaScript 运行时*Nitro*，自 iOS6 的 Mobile Safari 以来一直包含在内。

混合应用程序一直运行得比本地代码差。但是，借助 Nitro JavaScript 运行时，HTML5 在性能上与本地应用程序平起平坐，前提是我们视图不会像我们颜色混合层示例中那样消耗太多渲染内存。

然而，WKWebView 确实存在局限性；它只能用于 iOS8 或更高版本，并且不像 UIWebView 那样内置 Storyboard 或 XIB 支持。因此，如果你是 iOS 开发新手，使用这个框架可能会遇到问题。**Storyboards** 仅仅是特定方式编写的 XML 文件，用于渲染 iOS 用户界面，而**XIB**文件是 Storyboard 的前身。XIB 文件只允许一个视图，而 Storyboards 允许多个视图，并且可以链接它们。

如果你正在开发一个 iOS 应用，我鼓励你联系你的 iOS 开发负责人，并鼓励在项目中使用 WKWebView。

更多信息，请查看 Apple 网站上关于 WKWebView 的文档：[`developer.apple.com/library/IOs/documentation/WebKit/Reference/WKWebView_Ref/index.html`](https://developer.apple.com/library/IOs/documentation/WebKit/Reference/WKWebView_Ref/index.html)。

# 总结

在本章中，我们学习了如何使用 HTML5 和 JavaScript 为 iOS 创建混合应用的基本知识；我们学习了如何在运行应用的 iOS 模拟器中连接 Safari 网络检查器到我们的 HTML 页面。我们还查看了 iOS 模拟器的颜色混合层，并了解了如何从我们的 JavaScript 代码中测试性能，以解决设备渲染性能问题。

现在我们到了最后关头。就像所有上线到生产环境的 JavaScript web 应用一样，我们需要对我们的 JavaScript 和 web 应用代码进行烟雾测试，看看在最终部署之前是否需要进行任何最后的优化。这将在下一章讨论。


# 第十章：应用性能测试

在这本书中，我们已经介绍了各种增加 JavaScript 应用程序性能的方法，这些方法贯穿于项目生命周期的不同阶段。这包括从在项目生命周期的各个阶段选择合适的编辑器，将 JavaScript 检测器整合到帮助我们证明在部署前 JavaScript 的活动中，使用构建系统，以及创建部署包或构建，将最终代码与开发者友好的代码库分离。

编写高性能 JavaScript 的真正秘诀不在于我们头脑中的 JavaScript 知识量，而在于了解语言本身的“痛点”；其中一些痛点包括`for`循环、对象创建、不包含严格操作符、定时器等。此外，这一类别还包括将这些工具整合到我们的代码中，以便在部署之前更好地检查代码。

与所有主要网络应用程序项目一样，这里总是有一些形式的预飞检查，即一个最终的待办事项列表，在一个网络应用程序上线之前。如果我们到目前为止已经涵盖了本书中介绍的工具，我们的 JavaScript 应该足够稳定以供部署。但是在这里，我们将再进一步。

在本章中，我们将探讨**Jasmine**，一个允许我们以我们还未意识到的方式测试代码的 JavaScript 测试框架。与过去的线性检测工具（如 JSLint）不同，这些测试将依赖于应用程序的属性类型，也依赖于我们尚未介绍的概念：JavaScript 中的单元测试。

简而言之，我们将涵盖以下主题：

+   什么是 JavaScript 中的单元测试？

+   使用 Jasmine 进行单元测试

# 什么是 JavaScript 中的单元测试？

单元测试，简单来说，是一种应用程序框架或工具集，旨在以独特的方式测试 JavaScript 或其他任何编程语言的代码。单元测试通常涵盖标准线性检测器中不存在的错误检查。它们被设计用来检查特定于应用程序的错误。在其他编程语言中，单元测试通常被设计用来检查项目的类和模型，以确保应用程序运行高效且正确。

现在，JavaScript 和单元测试实践从未被很好地联系在一起，这主要是由于 JavaScript 的动态性质。阻碍它们联系的因素包括开发人员无意中创建的许多错误，将错误的值传递给不应该有特定变量类型的变量，当应用程序的对象属性需要数字时分配一个字符串，等等。

然而，对于使用 JavaScript 的客户端应用程序，无论它们是在网页浏览器中的网页上，还是在移动应用程序的网页视图中托管，测试变得越来越必要。现在有数十个针对 JavaScript 测试设计的框架，但在这里，我将介绍一个特别名为 Jasmine 的框架。请记住，还有其他测试框架，如 Mocha 或 QUnit，但我们将介绍 Jasmine，因为它不需要第三方框架即可运行。

# Jasmine 的单元测试

Jasmine 是一个 JavaScript 单元测试框架；它允许我们编写不依赖于外部库（如 jQuery）的 JavaScript。这对于需要非常小的内存占用的应用程序很有帮助，例如我们在第九章中讨论的 iOS 上的 JavaScript 应用程序，*为 iOS 混合应用程序优化 JavaScript*. 它还限制了代码仅限于我们编写的代码，并且由于当前构建的另一个供应商库中的框架而没有错误。

## 安装和配置

Jasmine 可以通过多种方式安装；我们可以使用 node 包管理器或 NPM，这与我们在第三章中构建我们的 Gulp.js 构建系统的结构类似，*理解 JavaScript 构建系统*. 但是我们首先需要下载该框架的独立版本。我将使用版本 2.1.3，这是框架的最新稳定版本，可以在 [`github.com/jasmine/jasmine/releases`](https://github.com/jasmine/jasmine/releases) 找到。要下载，请点击 Jasmine 框架 GitHub 页面上的绿色 `.zip` 文件按钮，如下所示：

![安装和配置](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_10_01.jpg)

一旦我们下载了 Jasmine 的独立版本，我们可以检查它是否可以正常工作；独立版本包含一些已经设置好单元测试的示例 JavaScript。要运行 Jasmine 中的单元测试集，我们需要构建一个 `SpecRunner` 页面。`SpecRunner` 是一个显示单元测试结果的 Jasmine 特定 HTML 页面。如果我们打开独立版本的 `SpecRunner.html` 文件在浏览器中，我们应该看到以下屏幕截图所示的示例测试结果，演示了所有已通过的测试：

![安装和配置](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_10_02.jpg)

在设置测试之前，我们需要测试一些代码。我创建了一些面向对象的 JavaScript，它严重依赖于特定的 JavaScript 类型，例如数字和布尔值，这些类型在整个应用程序中都有使用。该应用程序是一个非常简单的银行应用程序，它将客户数据返回给一个简单的 HTML 页面，但它结构足够复杂，类似于大型应用程序。我们将使用 Jasmine 来检查类型，确保传递的数据有效，并验证应用程序正在按照预期输出客户数据。

## 审查项目代码库

我们将使用以下代码样本进行项目。花点时间看看这里展示的代码。像往常一样，本书中所有的代码样本都可以在 Packt Publishing 的网站上找到。

![审查项目代码库](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_10_03.jpg)

我们这里有很多代码要测试，但不必担心！在我们开始使用 Jasmine 之前，让我们慢慢回顾一下。在第 1 至 7 行，我们有一个 JavaScript 枚举类型，用于性别类型，允许我们预定义客户类型的值。在这个例子中，值可以是`Male`、`Female`或`Alien`。从第 10 行开始是我们的`BankDB`对象（也被认为是 JavaScript 类）；这实际上不是一个数据库，但在实际应用程序中它可能与一个数据库相连。

`BankDB`函数是一个基于实例的对象，意味着它需要特定类型的参数才能正常工作，我们可以在第 56 行的`newCustomer`中找到该参数。这个 JavaScript 对象包含了一个 JavaScript 对象表示法，为新的客户条目分配值。可以把这个看作是收银员在使用系统时返回的一小部分 JSON。

最后，在第 66 至 72 行，我们使用该用户的数据创建请求，然后将数据附加到内嵌网页的`document.body`语句中，并进行了一些轻微的样式和格式化。

在我们开始编写测试之前，让我们在一个自我包含的页面中查看这个。我在关闭`body`标签之前的空 HTML 页面中添加这个。打开页面并查看结果，如下屏幕快照所示：

![审查项目代码库](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_10_04.jpg)

正如我们所看到的，我们的应用程序显示了所有正确信息，除了客户名显示为`Mr. e`，而不是在`10_01.js`文件的 58 行指示的`Mr. Leonard Adams`。同时，注意在我们的 Chrome**开发者工具**选项中，我们没有收到任何错误，也没有真正的性能延迟。尽管如此，通过客户名的输出我们知道有些问题。为纠正此问题，我们将对应用程序进行单元测试。

## 审查应用程序的规格以编写测试

编写单元测试时，需要有明确的指导方针来编写测试；在前一个屏幕快照中显示的代码样本的情况下，我们想要确保我们的测试遵循几条规则，为了帮助我们编写这些测试，我们将使用下面表格中列出的规则和我们的代码。

考虑以下列表作为应用程序规格，或基于此构建应用程序的文档。让我们看看表格和我们的代码应该如何处理使用中的数据：

| 测试编号 | 测试描述 |
| --- | --- |
| ![审查项目代码库](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_10_03.jpg) |
| 第二测试 | 新客户数据测试：`客户名应位于数组对象中，（例如['FirstName', 'LastName']）。` |
| ``` |
| ``` |
| ``` |
| ``` |

根据这个列表，我们需要我们的数据值通过这六个测试，以确保 JavaScript 应用程序正常工作。为此，我们将使用 Jasmine 编写一个**spec**。在 Jasmine 框架中，spec 文件就是一个加载了待测试 JavaScript 的 JavaScript 文件，该文件被加载到一个包含 Jasmine 测试框架和待测试文件的 HTML 页面中。在这里，我们可以看到这个组合页面的样子；在基于 Jasmine 的测试中，通常称之为`SpecRunner`页面：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Jasmine Spec Runner v2.1.3</title>

    <link rel="shortcut icon" type="image/png" href="lib/jasmine-2.1.3/jasmine_favicon.png">
    <link rel="stylesheet" href="lib/jasmine-2.1.3/jasmine.css">

    <script src="img/jasmine.js"></script>
    <script src="img/jasmine-html.js"></script>
    <script src="img/boot.js"></script>

    <!-- include source files here... -->
    <script src="img/Chapter_10_01.js"></script>

    <!-- include spec files here... -->
    <script src="img/Chapter_10_01Spec.js"></script>

  </head>

  <body>
  </body>
</html>
```

在这里，我们可以看到`SpecRunner.html`页面，并注意到我们在头部标签中首先加载了 Jasmine 框架，然后是我们在前一章节中提到的名为`Chapter_10_01.js`的测试脚本，其后是我们命名为`Chapter_10_01_Spec.js`的 spec 文件，以保持一致性。

注意，如果我们打开 Chrome 的**开发者工具**在我们的`SpecRunner.html`页面中，我们可以看到来自我们的`10_01.js`文件的几个错误，我们在其中使用`document.body`语句附上客户数据。使用 DOM 的 JavaScript 可能会对 Jasmine 和其他 JavaScript 测试框架造成问题，因此请确保使用特定于应用程序的代码进行测试，而不是用户界面代码。

## 使用 Jasmine 编写测试

在 Jasmine 中，有三个特定于测试框架的关键词我们需要知道。第一个是`describe`；`describe`在测试中就像一个类。它将我们的测试组织在一个容器中，以便稍后引用。在我们的应用程序规范的前一个列表中，我们可以将`New Customer data test`作为我们的`describe`值。

第二个关键词是`it`；`it`是一个 Jasmine 函数，它接受两个参数，一个我们用作测试描述的字符串。例如，一个`it`测试可能包含一个描述，如`Customer's ID should be a number`。这告诉审查测试的用户我们到底在测试什么。另一个参数是一个函数，如果需要，我们可以在其中注入代码或设置代码。请记住，所有这些都在同一个页面中运行，所以如果我们想更改任何变量，或者为测试更改原型，我们可以在运行测试之前在这个函数中完成。请注意，在编写测试时，我们不需要修改代码以正确测试；这只有在没有代码样本供审查时才这样做。

需要记住的最后一个关键字是`expect`；`expect`是 Jasmine 特有的函数，它接受一个值并与另一个值进行比较。在 Jasmine 中，这是通过`expect`函数的一部分，即`toEqual`函数来完成的。可以这样想每个测试：`我们期望 newCustomer.customerID 的 typeof 等于一个数字`。如果我们考虑一下，这实际上很简单，但是在规格文件中它会是什么样子呢？如果我们看下面的屏幕快照，我们可以看到我们的`Chapter_10_01Spec.js`文件，每个测试都为 Jasmine 而写：

![使用 Jasmine 编写测试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_10_05.jpg)

在这里，我们可以看到我们的测试是如何编写的；在第 2 行，我们有我们的`describe`关键字，它将我们的测试包裹在一个容器中，如果我们有一个更大的测试文件。我们所有的测试，从我们的文档规格，都可以在每一个`it`关键字中找到；测试 1 在第 4 行，第 5 行我们有第一个测试的`expect`关键字检查`newCustomers.CustomerID`的类型，我们期望的是一个`number`。

请注意，被比较的类型使用的是字符串而不是数字，正如你会在控制台中所期望的那样。这是因为`typeof`，JavaScript 关键字，用于返回变量的类型，它返回的是使用字符串的类型名；所以，为了与之匹配，我们在这里也使用带有类型名的字符串。

我们可以在随后的行中看到，我们使用相同的比较方式为其他每个测试添加了剩余的测试。完成后，让我们打开`SpecRunner.html`页面；我们可以在以下屏幕快照中查看我们的测试在**规格列表**视图中的表现：

![使用 Jasmine 编写测试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_10_06.jpg)

哎呀！这里有三处错误，这可不是什么好事。在这里，我们期望只有一个错误，即客户名称显示不正确。但是，我们的单元测试发现我们的应用程序规格并没有按照它被写的那样执行。在 Jasmine 框架中，这个页面布局相当常见；在初始加载时，你会看到完整的错误列表。如果你想要看到所有通过和失败的测试列表，我们可以点击顶部的**规格列表**，我们将看到如前屏幕快照所示的完整列表。

在这里失败的测试在浏览器中会显示为红色，成功的显示为绿色。你也可以看到绿色圆圈和红色 X 标记，这表明在**失败**视图和**规格列表**视图中通过了多少测试和失败了多少。

## 修复我们的代码

现在我们的测试代码可以正常工作，我们可以修改它以确保它正常工作。为此，我们需要更新`10_01.js`文件和`newCustomer`数据，这在`10_01.js`文件的第 56 到 63 行。让我们回顾一下我们的示例客户数据出了什么问题：

+   第一个失败的测试是 2，它要求将客户的名字创建为对象数组，第一个名字作为数组项，第二个名字作为对象数组的第二个项

+   第二个失败的是测试 3，它要求`customerBalance`是一个数字类型。

+   第三个错误是测试 6，它要求客户的婚姻状况是一个布尔值而不是一个字符串。

让我们更新一下我们的`newCustomer`数据；你可以看到我在下面的截图中已经那样做了：

![修复我们的代码](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_10_07.jpg)

一旦我们在`10_01.js`文件中更新了`newCustomer`信息，我们应该能够重新运行 Jasmine 并重新测试我们的代码样本。如果所有测试都通过，我们将看到默认的**规格列表**显示所有结果为绿色；让我们像下面截图中一样重新打开我们的页面，看看我们的测试是否通过：

![修复我们的代码](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_10_08.jpg)

不错，所有的六个规格都通过了！工作做得很好！通过确保我们应用程序中的所有数据都使用了正确的类型，我们不仅可以确保我们的 JavaScript 应用程序运行良好，而且可以确保其运行具有高度的准确性，正如它被预期那样使用。

当应用程序偏离开发者的设计时，它们可能会导致性能问题并影响应用程序的整体稳定性。在 Jasmine 中，我们可以看到测试的完成时间；注意最后测试的性能比出错的那次要快得多。在下面的截图中，我们有最终的应用程序页面，没有错误，正如 Chrome 中的**开发者工具**选项所显示的那样：

![修复我们的代码](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-hiperf/img/7296OS_10_09.jpg)

在这里要注意的最后一个事实是 JavaScript 开发者可以使用的不同方法。一种方法是**测试驱动开发**（**TDD**）方法，我们在编写应用程序代码之前先编写我们的测试。许多 JavaScript 开发者测试应用程序的另一种方法称为**行为驱动开发**（**BDD**）方法。这种方法通过先编写应用程序代码然后与应用程序互动来工作，这包括打开一个弹出窗口并确认代码如预期那样工作。

这两种方法都是构建应用程序的有效方法，但对于必须准确的数据的 JavaScript 应用程序，TDD 是最佳选择！

# 总结

在本书中，我们介绍了 JavaScript 应用程序单元测试的基础知识。我们介绍了 Jasmine，一个针对 JavaScript 的行为驱动单元测试框架。我们一起创建了一个现实世界的应用程序，它没有技术错误，但却导致了应用程序问题。

我们回顾了如何阅读和编写应用程序规格，以及如何使用应用程序规格编写 Jasmine 测试。然后我们将我们的测试代码与我们的代码运行，并迅速更新了我们的客户数据以反映规格，使我们的单元测试通过。最后，我们了解到对代码进行单元测试可以提高我们的 JavaScript 性能，同时也将应用程序的风险降到最低。
