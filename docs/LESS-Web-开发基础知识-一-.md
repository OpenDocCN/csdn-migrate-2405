# LESS Web 开发基础知识（一）

> 原文：[`zh.annas-archive.org/md5/E32D57C9868AAE081EFB9D0BCBCFBAE6`](https://zh.annas-archive.org/md5/E32D57C9868AAE081EFB9D0BCBCFBAE6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在 1999 年 HTML 4.01 引入后，Web 发生了快速变化。许多新设备，如平板电脑和手机，应运而生。移动互联网变得更快、更便宜和更稳定。W3C 于 2007 年启动了 HTML5 工作组。2012 年 12 月，W3C 将 HTML5 指定为候选推荐标准。HTML5 与 CSS3 一起工作。如今，所有主要浏览器（Chrome、Safari、Firefox、Opera、IE）都支持 HTML5。

CSS3 的影响是巨大的。如今，CSS3 不仅用于为 HTML 文档设置样式，而且在设计的责任方面也扮演着重要的角色。最后但并非最不重要的是，CSS3 通过动画和过渡等功能扩展了 CSS。

我们不需要外部 Flash 组件来进行复杂的动画。看看[`www.hongkiat.com/blog/css3-animation-transition-demos/`](http://www.hongkiat.com/blog/css3-animation-transition-demos/)或查看以下截图中的有趣的猫头鹰：

![前言](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_Preface_01.jpg)

在前面的截图中，猫头鹰仅使用 HTML5 和 CSS3 构建。通过按下按钮，实时版本可以眨眼和看。

响应式设计允许您使用只有一个代码库构建网站的一个版本，该版本在不同设备上（如手机、平板电脑和台式机）运行良好并且外观良好。不需要为不同的移动和台式机版本构建任何技术原因，如下图所示：

![前言](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_Preface_02.jpg)

有了所有这些新东西，CSS（或 Web）开发人员的工作变得更加复杂。Web 开发人员需要了解复杂的 CSS3、浏览器和设备之间的差异、动画和其他样式效果。编写正确和功能性的 CSS 代码将是第一要务；使这些代码可读、可维护并在所有主要浏览器上运行将是第二要务。CSS 文件在开发和维护过程中会变得越来越混乱。CSS 没有修改现有值或重用常见样式的能力。此外，在 CSS 中无法进行数学运算或定义变量。这就是 Less 的用武之地。

**Less**（**Leaner CSS**）是由 Alexis Sellier 设计的动态样式表语言。它始于 2010 年，现在由 Less 核心团队维护和扩展。Less 帮助您使 CSS 代码可维护、可重用，并防止代码重复。

在本书中，您将学习如何编写、编译和理解 Less。我们将帮助您更快、更具成本效益地进行 Web 开发。您将获得将 Less 集成到当前和新项目中的实用技巧。阅读本书后，您将能够使用 Less 编写清晰和可读的 CSS3。与花费时间调试特定设备或浏览器的复杂 CSS 代码相比，您可以更多地关注真正的设计任务。

您的客户将对您的先进和稳定的设计感到满意。这将减少开发和维护时间，从而降低设计成本。

Less 通过函数和变量扩展了 CSS。从语义上讲，有效的 CSS 也是有效的 Less。最初的 Less 版本是用 Ruby 编写的；现在，Less 是用 JavaScript 编写的。

Less 被称为 CSS 预编译器。这意味着最终产品将用于生产。在这种情况下，最终产品将是有效的、紧凑的和可读的 CSS 代码。此外，预编译的 Less 代码也可以实时编译。Less 提供了服务器端和客户端选项来实现这一点。通过现代 Web 浏览器中的 LESS.js 进行实时客户端编译，可以轻松进行测试。服务器端编译还提供了使用 Less 构建应用程序以及创建动态 CSS 的机会。

此外，其他人也知道 Less 的强大。Twitter 的 Bootstrap 和 Roots 等项目都依赖于 Less。这些项目使用 Less 构建了清晰和可扩展的框架。您不能忽视这一证据。停止编写带有错误和浏览器缺陷的繁琐 CSS，并通过阅读本书了解 Less。

Less 是开源的，根据 Apache 许可证授权。在撰写本书时，最新版本是 1.7。Less 的源代码将在 GitHub 上维护。每个人都可以为其做出贡献。你可以免费使用 Less。

# 本书涵盖内容

第一章，“用 Less 改进 Web 开发”，展示了 CSS3 如何为网页设计师带来了高级功能，如渐变、过渡和动画。它还解释了 CSS 代码变得更加复杂和难以维护。Less 帮助你使你的 CSS 可维护、可重用，并防止代码重复。

第二章，“使用变量和混合”，解释了为什么变量允许你在一个地方指定广泛使用的值，然后在整个样式表中重复使用它们，从而使全局更改变得像改变一行代码一样容易。混合允许你将一个类的所有属性嵌入到另一个类中，只需将类名包含为其属性之一。本章还解释了参数化混合是什么以及如何使用它们。

第三章，“嵌套规则、操作和内置函数”，解释了使用嵌套规则来使继承清晰，并使样式表更短。本章还解释了如何创建属性之间的复杂关系以及如何使用 Less 的内置函数。

第四章，“避免重复造轮子”，教你 Less 代码和混合可以变得复杂，因为它们处理不同的浏览器和设备。本章还解释了预构建的混合和其他帮助你（重新）使用它们的来源。

第五章，“在你自己的项目中集成 Less”，教你如何为新项目组织文件，或者准备使用 Less 的项目。

第六章，“Bootstrap 3、WordPress 和其他应用”，解释了 Bootstrap 是什么，并展示了使用 Less 与 Bootstrap 的优势。本章还教你如何使用 Less 构建 Web 应用程序或将其集成到你的 WordPress 主题中。

# 你需要什么

为了理解并充分利用本书的内容，我们希望你之前已经用 CSS 构建过网站。需要基本的 CSS 理解。理解 CSS 选择器和 CSS 优先级将帮助你充分利用本书。我们还将在第一章中简要介绍这些 CSS 方面。理解在 JavaScript 等函数式语言中使用函数和参数的基础知识将是有价值的，但不是必需的。如果你对函数和参数一无所知，不要惊慌。本书包含清晰的示例。即使没有任何（函数式）编程知识，你也可以学会如何使用 Less，本书将帮助你做到这一点。最重要的技能将是学习的意愿。

本书的所有章节都包含示例和示例代码。运行和测试这些示例将帮助你发展你的 Less 技能。你需要一个现代的网络浏览器，如 Google Chrome 或 Mozilla Firefox 来运行这些示例。使用任何首选的文本或 CSS 编辑器来编写你的 Less 代码。

# 这本书是为谁准备的

每个与 CSS 一起工作并希望在真正的设计任务上花更多时间的网页设计师都应该阅读这本书。无论你是初学者网页设计师还是使用 CSS 多年的人，都将从阅读本书中受益，并学会如何利用 Less。我们还推荐这本书给现代网页设计和计算机科学的教师和学生。Less 不依赖于平台、语言或 CMS。如果你使用 CSS，你可以并且会从 Less 中受益。

# 约定

在本书中，您会发现许多不同类型信息的文本样式。以下是一些样式的示例，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL 和用户输入显示如下：“请注意，在这种情况下，ID 是以`#`开头的唯一选择器；相同 HTML 元素的选择器`[id=]`算作属性。”

代码块设置如下：

```less
.box-shadow(@style, @c) when (iscolor(@c)) {
  -webkit-box-shadow: @style @c;
  -moz-box-shadow:    @style @c;
  box-shadow:         @style @c;
}
.box-shadow(@style, @alpha: 50%) when (isnumber(@alpha)) {
  .box-shadow(@style, rgba(0, 0, 0, @alpha));
}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```less
.box-shadow(@style, @c) when (iscolor(@c)) {
  -webkit-box-shadow: @style @c;
  -moz-box-shadow:    @style @c;
  box-shadow:         @style @c;
}
.box-shadow(@style, @alpha: 50%) when (isnumber(@alpha)) {
  .box-shadow(@style, rgba(0, 0, 0, @alpha));
}
```

任何命令行输入或输出都是这样写的：

```less
# lessc -c styles.less > styles.css

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“点击**下一步**按钮会将您移动到下一个屏幕。”

### 注意

警告或重要提示会出现在这样的框中。

### 提示

技巧和窍门会出现在这样的样式中。


# 第一章：使用 Less 改进 Web 开发

在现代网页设计中，无法想象没有 CSS。有了 CSS3，网页设计师可以依赖于高级功能，如渐变、过渡和动画。另一方面，CSS 代码变得更加复杂和难以维护。*Less*是一种 CSS 预处理器，它使用现代编程语言的概念扩展了 CSS。Less 使您能够在编写 CSS 时使用变量、函数、操作，甚至规则或选择器嵌套。*Less*帮助您使用**不要重复自己**（**DRY**）原则编写 CSS。DRY 原则防止您在代码中重复任何信息。

本章将涵盖以下主题：

+   CSS3 介绍

+   将 Less 编译成 CSS

+   供应商特定规则

+   CSS3 圆角、动画和渐变

+   使用 box-sizing border-box

+   服务器端编译和使用 GUI

# 使用 CSS3 为您的 HTML 设置样式

在网页设计中，您将使用 HTML 来描述文档的结构，使用 CSS 语言来描述它们的呈现，包括字体、颜色和布局。当前标准的 HTML5 和 CSS3 版本适用于大多数现代浏览器和移动设备。CSS3 通过其他新的选择器、文本效果、背景渐变和动画扩展了旧的 CSS。CSS3 的强大功能、新功能以及在使用 HTML5 和 CSS3 的移动设备上的高接受度使它们成为现代网页设计的标准。HTML5 和 CSS3 的组合非常适合构建响应式网站，因为它们在手机（和其他设备）上的高接受度。

HTML5 和 CSS3 一起引入了许多新功能。在本书中，您将了解到学习它们概念时最重要的功能。

## 使用 CSS 选择器为您的 HTML 设置样式

使用*Less*（和 CSS），您可以使用**选择器**来为您的 HTML 代码设置样式。CSS 选择器是用于识别应该设置样式的网页 HTML 元素的模式或名称。CSS 选择器在编写*Less*代码时起着重要作用。

对于`body p.article {color:red}`，这里的选择器是`body p.article`。选择器不仅仅指一个元素。它们可以指向多个元素，不同的选择器可以指向同一个元素。例如，单个`p`选择器指的是所有的`p 元素`，包括具有`.article`类的`p 元素`。在冲突的情况下，**级联**和**特异性**决定应该应用哪些样式。在编写*Less*代码时，我们应该牢记上述规则。*Less*使得编写复杂的 CSS 变得更容易，而不会改变您的网站外观。它不会对最终的 CSS 引入任何限制。使用*Less*，您可以编辑结构良好的代码，而不是改变最终 CSS 的效果。

CSS3 引入了许多新的和方便的选择器。其中之一是`:nth-child(n)`，它使得在 HTML 文档中可以对每四个段落的`p`标签进行样式设置成为可能。这样的选择器为 CSS3 添加了强大的功能。现在我们能够仅使用 CSS 执行操作，而在过去我们需要 JavaScript 或硬编码样式（或至少需要类）。这也是学习*Less*的原因之一。强大的选择器将使 CSS 变得更加重要，但 CSS 代码也变得繁琐和难以维护。*Less*将在 CSS 中解决这个问题，甚至使复杂的代码变得灵活和易于维护。

### 注意

请访问[`developer.mozilla.org/en-US/docs/Web/CSS/Reference#Selectors`](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference#Selectors)获取完整的 CSS 选择器列表。

## CSS 中的特异性、继承和级联

在大多数情况下，许多 CSS 样式可以应用于同一个 HTML 元素，但只有一个样式会获胜。*W3C 规范*描述了哪些 CSS 样式具有最高优先级并最终将被应用。您可以在以下部分找到这些规范。

关于重要性顺序的规则在 CSS3 中并没有发生重大变化。它们被简要提及，以帮助你理解*Less*/CSS 中一些常见的陷阱以及如何解决它们。迟早，你会遇到这样的情况，你试图将 CSS 样式应用到一个元素，但它的效果却看不见。你会重新加载，拔头发，一遍又一遍地检查拼写错误，但什么都不会有用。这是因为在大多数情况下，你的样式将被另一个具有更高优先级的样式所覆盖。

CSS 中级联的全局规则如下：

+   找到适用于所讨论的元素和属性的所有 CSS 声明。

+   **内联样式**具有最高的特异性，除了`!important`。CSS 中的`!important`语句是一个用于增加声明权重的关键字。`!important`语句添加在 CSS 属性值的末尾。之后，检查是谁设置了声明；作者设置的样式比用户或浏览器（默认）定义的样式具有更高的特异性。默认意味着样式是由 Web 浏览器设置的，作者样式是由网页中的 CSS 定义的，用户样式是由用户通过其 Web 浏览器的设置设置的。用户的重要性高于默认值，而带有`!important`语句的代码（参见第二章，*使用变量和混合*中的*Less*含义）将始终具有最高的特异性。请注意，像 Firefox 这样的浏览器有选项来禁用页面以使用其他替代的用户定义字体。在这里，用户设置将覆盖网页的 CSS。这种覆盖页面设置的方式不是 CSS 优先级的一部分，除非它们使用`!important`设置。

+   计算特异性，这将在下一节中讨论。

+   如果两个或更多规则具有相同的优先级和特异性，则最后声明的规则获胜。

作为*Less*/CSS 设计师，你在大多数情况下将使用计算的 CSS 特异性。

### CSS 特异性的工作原理

每个 CSS 声明都有一个特异性，这将根据声明的类型和选择器的使用来计算。内联样式将始终具有最高的特异性，并且将始终被应用（除非被前两个级联规则覆盖）。在实践中，你不应该在许多情况下使用内联样式，因为它会违反 DRY 原则。它还会阻止你在一个集中的位置上更改样式，并阻止你使用*Less*进行样式设置。

内联样式声明的一个示例如下所示：

```less
<p style="color:#0000ff;">
```

之后，选择器中 ID 的数量将是计算特异性的下一个指标。`#footer #leftcolumn {}`选择器有 2 个 ID，`#footer {}`选择器有 1 个 ID，依此类推。

### 提示

请注意，在这种情况下，ID 是以`#`开头的唯一选择器；相同 HTML 元素的选择器`[id=]`计为一个**属性**。这意味着`div.#unique {}`有 1 个 ID，而`div[id="unique"] {}`有 0 个 ID 和 1 个属性。

如果两个声明的 ID 数量相等，则选择器中**类**、**伪类**和**属性**的数量将很重要。类以点开头。例如，`.row`是一个类。伪类，比如`:hover`和`:after`，以冒号开头，而属性，当然，是`href`、`alt`、`id`等。

`#footer a.alert:hover {}`选择器得分为 2（1 个类和 1 个伪类），而`#footer div.right a.alert:hover {}`选择器得分为 3（2 个类和 1 个伪类）。

如果这两个声明的值相等，我们可以开始计算**元素**和**伪元素**。最新的变量将使用双冒号（`::`）定义。伪元素允许作者引用其他无法访问的信息，比如`::first-letter`。下面的例子展示了它是如何工作的。

`#footer div a{}`选择器得分为 2（2 个元素），而`#footer div p a {}`选择器得分为 3（3 个元素）。

当你的样式没有直接应用时，你现在应该知道该怎么做了。在大多数情况下，使你的选择器更具体以使你的样式应用。例如，如果`#header p{}`不起作用，那么你可以尝试添加`#header #subheader p{}` ID，一个`#header p.head{}`类，等等。

当级联和`!important`规则无法给出明确的答案时，特异性计算似乎是一项困难且耗时的工作。虽然*Less*在这里无法帮助你，但诸如 Firebug（和其他开发者工具）之类的工具可以使特异性可见。下面是使用 Firebug 的一个示例，其中具有最高特异性的选择器显示在屏幕顶部，被覆盖的样式被划掉：

![CSS 特异性的工作原理](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-01-01.jpg)

Firebug 中特异性的示例

## 使用灵活盒子构建你的布局

**Flexbox 布局**（也称为灵活盒子）是 CSS3 的一个新特性。它在创建响应式和灵活的布局方面非常有用。Flexbox 提供了根据不同屏幕分辨率动态更改布局的能力。它不使用浮动，并包含不会与其内容折叠的边距。不幸的是，目前主要浏览器对 Flexbox 布局的支持并不完整。我们关注 Flexbox 是因为它的强大，而且作为 CSS 的一个重要特性，我们也可以使用*Less*来生成和维护它。你可以在[`gist.github.com/bassjobsen/8068034`](https://gist.github.com/bassjobsen/8068034)上访问一组用于 CSS3 Flexbox 的*Less* mixin。你可以使用这些 mixin 来使用*Less*创建 Flexbox 布局，而不使用重复的代码。

这些 mixin 现在不会被详细解释，但以下示例显示了*Less*如何减少创建 flex 容器所需的代码。使用 CSS，你可能会使用以下代码：

```less
div#wrapper {
  display: -webkit-flex;
  display: -moz-flex;
  display: -ms-flexbox;
  display: -ms-flex;
  display: flex;
}
```

### 提示

**下载示例代码**

你可以从你在[`www.packtpub.com/`](http://www.packtpub.com/)的帐户中下载你购买的所有 Packt 图书的示例代码文件。如果你在其他地方购买了这本书，你可以访问[`www.packtpub.com/support/`](http://www.packtpub.com/support/)并注册，以便直接通过电子邮件接收文件。

然而，如果你使用*Less*，可以通过插入以下代码行来产生相同的效果：

```less
div#wrapper { .flex-display; }
```

你可以使用 Google Chrome 来测试你的 Flexbox 布局。在撰写本书时，Firefox 和 Internet Explorer IE11 也提供了对 Flexbox 布局的全面或更好的支持。之所以提到 Flexbox，是因为它们有潜力在未来的网页设计中扮演重要角色。目前，它们超出了本书的范围。本书将重点介绍如何使用*Less*、CSS 媒体查询和网格来创建响应式和灵活的布局。

### 注意

请访问[`developer.mozilla.org/en-US/docs/Web/Guide/CSS/Flexible_boxes`](https://developer.mozilla.org/en-US/docs/Web/Guide/CSS/Flexible_boxes)获取更多信息、示例和浏览器兼容性。

# 编译 Less

在深入研究 CSS 理论之后，你最终可以开始使用*Less*。如前所述，它与 CSS 具有相同的语法。这意味着任何 CSS 代码实际上也是有效的*Less*代码。使用*Less*，你可以生成可以用于样式化你的网站的 CSS 代码。从*Less*制作 CSS 的过程称为**编译**，你可以通过**服务器端**或**客户端**编译*Less*代码。本书中给出的示例将使用客户端编译。在这里，客户端指的是在浏览器中加载代码，并使用本地机器的资源将*Less*代码编译成 CSS 代码。本书使用客户端编译，因为这是最容易入门的方式，同时也足够好用于开发你的*Less*技能。

### 提示

需要注意的是，客户端编译的结果仅用于演示目的。对于生产环境，特别是在考虑应用程序性能时，建议使用服务器端的**预编译**。*Less*捆绑了一个基于**Node.js**的编译器，还有许多其他的 GUI 可用于预编译你的代码。这些 GUI 将在本章末讨论。

## 开始使用 Less

最后，你可以开始使用*Less*了。你需要做的第一件事是从[`www.lesscss.org/`](http://www.lesscss.org/)下载*Less*。在本书中，将使用版本 1.6 的`less.js`。下载后，应该创建一个 HTML5 文档。它应该包括`less.js`和你的第一个*Less*文件。

请注意，你可以从[www.packtpub.com](http://www.packtpub.com)上本书的可下载文件中下载示例，包括`less.js`的副本。

首先，看一下这个简单但结构良好的 HTML5 文件：

```less
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">

  <title>Example code</title>
  <meta name="description" content="Example code">
  <meta name="author" content="Bass Jobsen">

  <link rel="stylesheet/less" type="text/css" href="less/styles.less" />
   <script src="img/less.js" type="text/javascript"></script>
</head>

<body>
<h1>Less makes me Happy!</h1>
</body>
</html>
```

你可以看到，使用以下代码将*Less*文件添加到了这个文档中：

```less
<link rel="stylesheet/less" type="text/css" href="less/styles.less" />
```

当使用`rel="stylesheet/less"`时，代码将与样式表相同。在*Less*文件之后，你可以使用以下代码调用`less.js`：

```less
<script src="img/less.js" type="text/javascript"></script>
```

事实上，这就是你开始的全部内容！

为了保持清晰，暂时忽略了`html5shiv`（可以在[`code.google.com/p/html5shiv/`](http://code.google.com/p/html5shiv/)访问）和**Modernizr**（可以在[`modernizr.com/`](http://modernizr.com/)访问）。这些脚本为旧版浏览器如 IE7 和 IE8 添加了对新的 CSS3 和 HTML5 特性的支持和检测。预计你将使用现代浏览器，如 Mozilla Firefox，Google Chrome，或 IE8 之后的任何版本。这些浏览器将完全支持 HTML5、CSS3 和**媒体查询**，这在阅读本书和做练习时是需要的。

### 提示

你已经知道在大多数情况下只能在开发和测试中使用`less.js`；仍然有一些情况可以在生产中使用`less.js`的客户端。为了支持旧版浏览器的`less.js`，你可以尝试使用 es5-shim（[`github.com/es-shims/es5-shim/`](https://github.com/es-shims/es5-shim/)）。

现在，在浏览器中打开`http://localhost/index.html`。你会看到**Less makes me Happy!**标题文字以默认的字体和颜色显示。之后，你应该在你喜欢的文本编辑器中打开`less/styles.less`。*Less*和 CSS 的语法在这里没有区别，所以你可以在这个文件中输入以下代码：

```less
h1{color:red;}
```

接着，重新加载你的浏览器。你应该会看到标题文字变成了红色。

从上面的代码中，`h1`是选择器，用于选择你的 HTML 中的`H1`属性。`color`属性已经在大括号中设置为`red`。这些属性将被应用到你的选择器上，就像 CSS 一样。

### 提示

不需要运行一个 web 服务器。在浏览器中导航到你的硬盘上的`index.html`就足够了。不幸的是，这对所有浏览器都不起作用，所以最好使用 Mozilla Firefox。本书中的示例使用的是`http://localhost/map/`，但根据你的情况，可以替换为类似于`file:///map/`或`c:\map\`的内容。

## 使用自动重新加载的观察功能

`less.js`文件有一个**watch**功能，它会检查你的文件是否有更改，并在发现更改时重新加载你的浏览器视图。使用起来非常简单。执行以下步骤：

1.  在你想要打开的 URL 后面添加`#!watch`。

1.  在`index.html`后面添加`#!watch`，然后重新加载浏览器窗口。

1.  所以，在浏览器中打开`http://localhost/index.html#!watch`，开始编辑你的*Less*文件。你的浏览器将在不需要重新加载的情况下反映你的更改。

1.  现在在你的文本编辑器中打开`less/styles.less`。在这个文件中，写入`#h1{color:red;}`然后保存文件。

1.  现在你应该导航到你的浏览器，应该会看到**Less makes me Happy!**以红色显示。

1.  重新排列你的屏幕，以便在同一个窗口中同时看到文本编辑器和浏览器。

1.  此外，如果你在`less/styles.less`中将`red`改为`blue`，你会发现浏览器跟踪这些更改，并在文件保存后以蓝色显示**Less makes me Happy!**。

相当酷，不是吗？

### 提示

本代码示例中使用颜色名称而不是十六进制值。例如，代码使用`red`而不是`#ff0000`。基本颜色名称由 less.js 转换为它们的十六进制值，并写入 CSS 中。在本书中，始终使用命名颜色。

## 调试你的代码

由于我们只是人类，我们容易犯错或打字错误。能够看到你的错误并调试你的代码是很重要的。如果你的*Less*文件包含错误，它根本无法编译。因此，一个小小的打字错误会破坏整个文档的样式。

使用`less.js`也很容易进行调试。要使用调试或允许`less.js`显示错误，可以将以下代码添加到你的`index.html`中：

```less
  <link rel="stylesheet/less" type="text/css" href="less/styles.less" />
  <script type="text/javascript">less = { env: 'development' };</script>
  <script src="img/less.js" type="text/javascript"></script>
```

如你所见，带有`less = { env: 'development' };`的这一行是新的。这一行包含`less`作为`less.js`使用的 JavaScript 变量。实际上，这是一个全局*Less*对象，用于将一些设置解析给`less.js`。本书中将使用的唯一设置是`env: 'development'`。有关更多设置，请查看以下网站：[`lesscss.org/#client-side-usage-browser-options`](http://lesscss.org/#client-side-usage-browser-options)。

### 提示

`env: 'development'`还可以防止*Less*缓存。Less 不会在浏览器缓存中缓存文件。相反，文件会被缓存在浏览器的本地存储中。如果`env`设置为`production`，这种缓存可能会产生意想不到的结果，因为更改和保存的文件不会被编译。

要尝试这个新设置，再次编辑`less/styles.less`并删除一个大括号，以创建`h1{color:red`形式的无效语法，然后保存文件。

在你的浏览器中，你将看到一个如下截图的页面：

![调试你的代码](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-01-02.jpg)

Less 解析错误示例

除了**语法错误**之外，还会显示**名称错误**。在名称错误的情况下，可能会使用未声明的函数或变量。

可以在全局*Less*对象中设置其他调试设置，也可以将设置附加到 URL 中。例如，你可以通过将以下代码添加到你的 HTML 文件中来指定`dumpLineNumbers`设置：

```less
<script type="text/javascript">less = { env: 'development',dumpLineNumbers: "mediaQuery"
 };</script>
```

或者，你可以在 URL 中添加`!dumpLineNumbers:mediaQuery`。这个设置可以让其他工具在*Less*源文件中找到错误的行号。将此选项设置为`mediaQuery`可以使 FireBug 或 Chrome 开发工具可用于错误报告。类似地，将其设置为`comments`可以使 FireLess 等工具实现相同的功能。例如，使用 FireLess 可以使 Firebug 显示*Less*原始文件名和*Less*生成的 CSS 样式的行号。

FireBug、Chrome 开发工具或默认浏览器检查元素功能（可以通过右键单击浏览器屏幕访问）也可以用来查看和评估编译后的 CSS。CSS 显示为内联 CSS，包裹在`<style type="text/css" id="less:book-less-styles">`标签中。在以下截图中给出的示例中，你将看到一个 ID，其值为`less:book-less-styles`。这个 ID 的值是根据`book/less/styles.less` *Less*文件的路径和名称自动生成的：

![调试你的代码](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-01-03.jpg)

Less 生成的 CSS 样式

### 本书中使用的示例代码

在本书中，你会找到许多代码示例。除非另有说明，这些示例的格式总是先显示*Less*代码，然后是编译后的 CSS 代码。例如，你可以在*Less*中编写以下代码行：

```less
mixin() {
color: green;
}
p {
.mixin();
}
```

此代码将被编译为以下 CSS 语法：

```less
p {
color: green;
}
```

# Less 中的第一个布局

您必须首先在浏览器中打开`first.html`（从本书的可下载文件中）然后在文本编辑器中打开`less/first.less`。在浏览器中，您将看到一个页眉、正文和页脚的表示。

正如预期的那样，`less/first.less`包含了*Less*代码，将由`less.js`编译器转换为有效的 CSS。此文件中的任何错误都将停止编译器并抛出错误。尽管*Less*代码与普通 CSS 代码显示出一些相似之处，但这里描述的过程与直接编辑 CSS 完全不同。

以下截图显示了在 Web 浏览器中打开时此布局的外观：

![Less 中的第一个布局](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-01-04.jpg)

Less 中的第一个布局

## 供应商特定规则

CSS3 引入了**供应商特定规则**，为您提供了编写一些仅适用于一个浏览器的附加 CSS 的可能性。乍一看，这似乎与您的期望恰恰相反。您想要的是一套标准和实用性，适用于每个浏览器的相同效果和解释的标准 HTML 和 CSS 集。供应商特定规则旨在帮助我们实现这一乌托邦。供应商特定规则还为我们提供了标准属性和替代语法的早期实现。最后但并非最不重要的是，这些规则允许浏览器实现专有的**CSS 属性**，否则这些属性将没有工作标准（并且可能永远不会成为标准）。

出于这些原因，供应商特定规则在 CSS3 的许多新功能中起着重要作用。例如，**动画属性**、**border-radius**和**box-shadow**都依赖于供应商特定规则。

供应商使用以下前缀：

+   **WebKit**: `-webkit`

+   **Firefox**: `-moz`

+   **Opera**: `-o`

+   **Internet Explorer**: `-ms`

## 使用 border-radius 构建圆角

边框半径是一个新的 CSS3 属性，它将使许多网页开发人员感到高兴。使用 border-radius，您可以给 HTML 元素设置圆角。在以前的几年中，已经看到了许多使用图像和透明度来实现圆角的实现。然而，这些方法不够灵活，难以维护。

实施需要供应商特定规则，尽管圆角不能用一行代码处理，但它的使用确实使圆角处理变得更加容易。

要给一个元素设置 10 像素半径的圆角，您可以使用带有供应商特定规则的 CSS 代码，如下所示：

```less
-webkit-border-radius: 10px;
-moz-border-radius: 10px;
border-radius: 10px;
```

对于具有不同半径的圆角，使用一个由空格分隔的值列表：`10 px 5px 20px 15px;`。半径的顺序是：左上，右上，右下和左下。牢记这些规则，您将看到*Less*如何保持您的代码整洁。

您可以在浏览器中打开本章下载部分的`roundedcorners.html`，并在文本编辑器中打开`less/roundedcorners.less`。在浏览器中，您将看到一个具有圆角的页眉、正文和页脚的表示。

`less/roundedcorners.less`中页眉的 CSS 如下所示：

```less
#header{
background-color: red;
-webkit-border-radius: 10px;
-moz-border-radius: 10px;
border-radius: 10px;
}
```

您可以看到使用供应商特定规则，圆角已经创建为 10 像素的半径。如果您使用 CSS，您将不得不为页眉、页脚和正文重复供应商特定规则三次。为了更改这些规则或添加供应商，您还必须三次更改相同的代码。起初，您可能会想，“为什么不将选择器分组？”，类似于以下代码的方式：

```less
#header, #content, #footer{
-webkit-border-radius: 10px;
-moz-border-radius: 10;
border-radius: 10px;
}
```

前面的代码在编写 CSS 或*Less*代码时在语法上是正确的，但随着代码库的增长，维护起来并不容易。基于属性对选择器进行分组在阅读和维护代码时是没有意义的。这样的结构也会引入许多重复和无结构的相同选择器的用法。

使用*Less*，你可以高效地解决这些问题。通过创建所谓的**混合**，你可以解决前面提到的问题。对于边框半径，你可以使用以下代码：

```less
.roundedcornersmixin()
{
-webkit-border-radius: 10px;
-moz-border-radius: 10px;
border-radius: 10px;
}
```

要使用这个混合，你将使用以下代码将其作为选择器的属性调用：

```less
#header{
background-color: red;
.roundedcornersmixin();
}
```

这个*Less*代码的编译 CSS 现在将如下所示：

```less
#header{
background-color: red;
-webkit-border-radius: 10px;
-moz-border-radius: 10px;
border-radius: 10px;
}
```

观察`less/roundedcorners.less`文件中的原始代码，你会发现前面的代码无法适用于`#content`。内容的边框半径是 20 像素，而不是用于页眉和页脚的 10 像素。再次，*Less*帮助我们高效地解决了这个问题。混合可以像在函数式编程中调用函数一样带参数调用。这意味着结合值和对该值的引用，可以调用混合以设置属性。在这个例子中，这将改变为以下代码：

```less
.roundedcornersmixin(@radius: 10px){
-webkit-border-radius: @radius;
-moz-border-radius: @radius;
border-radius: @radius;
}
```

在`.roundedcornersmixin(@radius: 10px)`混合中，`@radius`是我们的参数，其默认值将是`10px`。

从这个点开始，你可以在你的代码中使用混合。`.roundedcornersmixin(50px);`语句将设置半径为 50 像素的角，而`.roundedcornersmixin();`语句将使用默认值 10 像素进行相同的操作。

使用这个，你可以重写`less/roundedcorners.less`，使其变成以下代码：

```less
/* mixins */
.roundedcornersmixin(@radius: 10px){
-webkit-border-radius: @radius;
-moz-border-radius: @radius;
border-radius: @radius;
}
#header{
background-color: red;
.roundedcornersmixin();
}
#content{
background-color: white;
min-height: 300px;
.roundedcornersmixin(20px);
}
#footer{
background-color: navy;
.roundedcornersmixin();
}
```

### 提示

下载部分的`less/roundedcornersmixins.less`文件包含了这段代码的副本。要使用这个，你还必须在 HTML 文件中将引用更改为`<link rel="stylesheet/less" type="text/css" href="less/groundedcornersmixins.less" />`。

请注意，这段代码省略了 HTML 中`div`和`body`标签的一般样式。这些样式只是用来使演示看起来好看，并没有真正有用地展示*Less*。

重写*Less*代码后，重新加载浏览器或观察它是否应用了`#!watch`技巧。你会发现输出结果完全相同。这向你展示了如何使用*Less*以更高效的结构化代码获得相同的结果。

# 使用 CSS 重置来防止跨浏览器问题

在谈论 CSS 中的**层叠**时，无疑会提到浏览器默认设置比作者首选样式具有更高的优先级。在编写*Less*代码时，你将覆盖浏览器的默认样式。换句话说，任何你没有定义的东西都将被分配一个默认样式，这是由浏览器定义的。这种行为在许多跨浏览器问题中起着重要作用。为了防止这些问题，你可以执行**CSS 重置**。最著名的浏览器重置是 Eric Meyer 的 CSS 重置（可在[`meyerweb.com/eric/tools/css/reset/`](http://meyerweb.com/eric/tools/css/reset/)访问）。

CSS 重置会覆盖浏览器的默认样式规则，并为样式创建一个起点。这个起点在所有（或大多数）浏览器上看起来和行为都是一样的。在本书中，使用的是 normalize.css v2。Normalize.css 是 CSS 重置的现代、HTML5-ready 替代方案，可以从[`necolas.github.io/normalize.css/`](http://necolas.github.io/normalize.css/)下载。它让浏览器更一致地渲染所有元素，并使它们符合现代标准。

要使用 CSS 重置，您可以使用*Less*的`@import`指令。使用`@import`，您可以在主*Less*文件中包含其他*Less*文件。语法是`@import "{filename}";`。默认情况下，指令的搜索路径从主文件的目录开始。虽然可以设置替代搜索路径（通过设置*Less*环境的路径变量），但本书中不会使用。

本书中的示例*Less*文件将在代码的前几行包含`@import "normalize.less";`。再次强调，您应该特别注意这种解决方案的利润！

如果要更改或更新 CSS 重置，您只需替换一个文件。如果您必须管理或构建多个项目，那么您应该这样做，那么您可以简单地重用完整的重置代码。

## 创建背景渐变

CSS3 中的一个新功能是在元素的背景颜色中添加**渐变**的可能性。这可以替代复杂的代码和图像回退。

可以定义不同类型的渐变并使用两种或两种以上颜色。在下图中，您将看到不同颜色的背景渐变：

![创建背景渐变](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-01-05.jpg)

渐变示例（来自[W3schools.com](http://W3schools.com)）

在下一个示例中，您可以使用两种颜色的线性渐变。背景渐变使用供应商特定的规则。

您可以利用圆角示例中的示例代码来添加渐变。

第一步是复制或打开`less/gradient.less`，并在该文件开头添加一个新的 mixin，如下面的代码所示：

```less
/* Mixin */
.gradient (@start: black, @stop: white,@origin: left) {
    background-color: @start;
    background-image: -webkit-linear-gradient(@origin, @start, @stop);
     background-image: -moz-linear-gradient(@origin, @start, @stop);
    background-image: -o-linear-gradient(@origin, @start, @stop);
    background-image: -ms-linear-gradient(@origin, @start, @stop);
    background-image: linear-gradient(@origin, @start, @stop);
}
```

这将从左侧（`@origin`）到右侧创建渐变，颜色从`@start`到`@stop`。这个 mixin 有默认值。

IE9（及其早期版本）不支持渐变。可以通过添加`background-color: @start;`来添加回退，这将为旧版浏览器创建统一的彩色背景。

在将 mixin 添加到您的代码后，您可以按照以下代码为我们的`#header`，`#body`和`#footer`选择器调用它：

```less
#header{
background-color: red;
.roundedcornersmixin();
.gradient(red,lightred);
}
#content{
background-color: white;
min-height: 300px;
.roundedcornersmixin(20px);
.gradient();
}
#footer{
background-color: navy;
.roundedcornersmixin(20px);
.gradient(navy,lightblue);
}
```

例如，如果您将*Less*文件重命名为`less/gradient.less`，您还必须更改 HTML 文件中的引用为以下代码：

```less
<link rel="stylesheet/less" type="text/css" href="less/gradient.less" />
```

如果您现在在浏览器中加载 HTML 文件，您的结果应该如下截图所示：

![创建背景渐变](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-01-04.jpg)

来自示例代码的标题，内容和页脚中的渐变

# CSS 过渡，变换和动画

CSS3 中的另一个新功能是过渡，变换和动画的存在。这些功能可以替代现有或新网页中的动画图像，Flash 动画和 JavaScript。过渡，变换和动画之间的区别并不是微不足道的。**动画**是由一系列`@keyframes`构建的，其中每个`@keyframes`处理元素在时间上的不同状态。**过渡**也描述了元素在开始和结束之间的状态。过渡大多是由 CSS 更改触发的，例如鼠标悬停在元素上。

为了搞清楚事情，重要的是要记住即将按下的按钮。按钮将有两种状态：按下和未按下。没有过渡和动画，我们只能对这些状态进行样式设置。按钮的颜色是白色，当您将鼠标悬停在其上时，其颜色变为红色。（在 CSS 术语中，通过添加`:hover`伪类，其状态变为悬停。）在这种情况下，过渡描述了悬停按钮如何变为红色。例如，从白色到红色的颜色变化在两秒内（使其在一半时变为粉红色）表明颜色变化的开始是缓慢的，并随着时间的推移变化更快。在这里使用动画使我们能够描述按钮在开始和结束之间的每个时间间隔的状态。例如，您不必将颜色从白色变为红色，而是变化涵盖了所有状态，从白色、蓝色、绿色，最终到红色。

**转换**改变元素的位置和外观。它们不依赖于元素的状态。一些可能的转换是**缩放**、**平移**（移动）和**旋转**。

在实践中，我们在大多数情况下都会使用动画、转换和/或过渡的组合。同样，在这种情况下，特定于供应商的规则将发挥重要作用。

现在，我们的示例将添加一个转换。

使用带有圆角和渐变的示例代码，将以下代码复制到`less/transition.less`，或者打开`less/transition.less`并将以下代码添加到文件的开头：

```less
/* Mixin */
.transition (@prop: all, @time: 1s, @ease: linear) {
-webkit-transition: @prop @time @ease;
-moz-transition: @prop @time @ease;
-o-transition: @prop @time @ease;
-ms-transition: @prop @time @ease;
transition: @prop @time @ease;
}
```

这个**mixin**有三个变量；第一个是您将要更改的**属性**(`@prop`)。这可以是`height`、`background-color`、`visibility`等。默认值`all`不应在生产代码中使用，因为这会对性能产生负面影响。`@time`设置以毫秒或秒为单位的持续时间，并在其后附加`s`。最后一个变量`@ease`设置**transition-timing-function 属性**。此函数描述了属性的值，假设其某个百分比已经完成。transition-timing-function 属性描述了过渡的完成度随时间的函数。将其设置为`linear`会显示从开始到结束相同速度的效果，而`ease`会以较慢的速度开始和结束，并在中间速度更快。预定义的函数有`ease`、`linear`、`ease-in`、`ease-out`、`ease-in-out`、`step-start`和`step-end`。

现在，您可以编辑`less/transition.less`以使用此**mixin**。当您悬停在页面上时，您可以设置 body 的背景颜色。请注意，您不需要使用过渡来更改渐变颜色，而是更改`background-color`属性。您使用`background-color`是因为`transition-duration`对渐变没有可见效果。`background-color`过渡的代码如下：

```less
#content{
background-color: white;
min-height: 300px;
.roundedcornersmixin(20px);
.transition(background-color,5s);
}
#content:hover{
background-color: red;
}
```

如果您将*Less*文件重命名为`less/transition.less`，您还必须更改 HTML 文件中的引用为以下代码：

```less
 <link rel="stylesheet/less" type="text/css" href="less/transition.less" />
```

如果您在浏览器中加载 HTML 文件，您将能够在浏览器中看到结果。将鼠标悬停在内容上，您将看到它在 5 秒内从白色变为红色。

最后，可以添加一个旋转标题的第二个示例。在这个示例中，您将使用`@keyframes`。使用`@keyframes`会比较复杂。因此，在这种情况下，您可以定义一些特定于供应商的规则，并将这些动画属性添加到`#header:`如下：

```less
@-moz-keyframes spin { 100% { -moz-transform: rotate(360deg); } }
@-webkit-keyframes spin { 100% { -webkit-transform: rotate(360deg); } }
@keyframes spin { 100% { -webkit-transform: rotate(360deg); transform:rotate(360deg); } }
#header{
    -webkit-animation:spin 4s linear infinite;
    -moz-animation:spin 4s linear infinite;
    animation:spin 4s linear infinite;
}
```

您可以将上述代码添加到我们的示例文件中，或者打开`less/keyframes.less`。

如果您将*Less*文件重命名为`less/keyframes.less`，您还必须更改 HTML 文件中的引用为以下代码：

```less
 <link rel="stylesheet/less" type="text/css" href="less/keyframes.less" />
```

现在，在浏览器中加载 HTML 文件并观看您的结果。很神奇，不是吗？通过一点创造性思维，您将看到只使用 CSS3 就可以创建旋转的风车或眨眼的猫头鹰的可能性。然而，首先应该更详细地解释这里使用的代码。如前所述，在许多情况下，您会组合**动画**和**转换**。在这个例子中，您还可以对转换效果进行动画处理。要理解发生了什么，代码可以分为三个部分。

第一部分是`@keyframes`，如下面的代码所示，它描述了 CSS 属性（在这种情况下是转换）的值作为**动画**完成百分比的函数：

```less
@keyframes spin { 100% { -webkit-transform: rotate(360deg); transform:rotate(360deg); } }
```

这些**关键帧**被赋予了名称引用`spin`，这不是一个特殊效果，而只是一个选择的名称。在前面的例子中，描述了 100%完成的状态。在这种状态下，动画元素应该旋转 360 度。

这个旋转是需要我们关注的第二部分。**转换**描述了元素在空间中的位置或尺寸。在这个例子中，位置由围绕轴的旋转度数描述，100%时为 360 度，50%时为 180 度，25%时为 90 度，依此类推。

第三部分是动画本身，由`animation:spin 4s linear infinite;`描述。这是动画属性的子属性的设置的简写表示法。实际上，您可以将其写成以下代码，不包括供应商特定的规则：

```less
animation-name: spin;
animation-duration: 4s;
animation-timing-function:linear;
animation-iteration-count:  infinite;
```

您可以使用这三个部分来构建完整的动画。完成后，您可以扩展它。例如，添加一个额外的关键帧，使时间曲线非线性，如下所示：

```less
@keyframes spin {
50% { transform: rotate(10deg);}
100% {transform: rotate(360deg); }
 }
```

您可以使用`background-color`添加第二个属性。不要忘记删除渐变以查看其效果。如下面的代码所示：

```less
@-moz-keyframes spin {
50% { transform: rotate(10deg); background-color:green;}
100% { transform: rotate(360deg); }
 }
//.gradient(red,yellow);
```

您可能已经注意到，在这里并没有完全实现使用*Less*的利润。由于其可变动画名称，您将不得不重复编写`@keyframes`定义。在第四章中，*避免重复造轮子*，将为您提供一个解决方案。

不幸的是，浏览器对过渡、转换和动画的支持并不理想，并且在各个浏览器之间存在差异。谷歌 Chrome 不支持 CSS 3D 转换，火狐缺乏对 CSS 滤镜的支持，IE9（以及更早的版本）根本不支持它们。为了解决这个问题，许多开发人员寻求 jQuery 来支持他们的动画。`jQuery.animate()`函数允许我们使用 JavaScript 更改元素的 CSS 属性。您仍然可以使用*Less*来设置初始 CSS。一个替代方案是使用`animate.css`（您可以在[`github.com/daneden/animate.css`](https://github.com/daneden/animate.css)上访问）；这个跨浏览器的 CSS 动画库可以转换为*Less*代码，并带有 jQuery 回退。

# 盒模型

**box-sizing**属性是设置用于计算元素尺寸的 CSS 框模型的属性。实际上，box-sizing 在 CSS 中并不新鲜，但是将代码切换到`box-sizing: border-box`将使您的工作变得更加容易。使用`border-box`设置时，元素宽度的计算包括边框宽度和填充。因此，更改边框或填充不会破坏您的布局。您可以在下载文件中的`boxsizing.html`中找到本节中使用的代码的副本。

如今，大多数网页设计都使用网格。网格将设计分成相等大小的列。这有助于使事情清晰，并构建响应式界面。根据可用的屏幕尺寸（或宽度），您可以以相同列的不同表示形式显示内容和导航。

为了处理不同的屏幕尺寸，网站的某些部分将具有流体宽度或高度。其他元素，如边框、装订线和空白处，应具有固定宽度。流体宽度作为屏幕宽度（或视口）的百分比与固定宽度的组合变得复杂。这种复杂性是因为浏览器对元素的填充和边距使用不同的计算。

为了让您看到这一点，请看以下示例。已创建了一个宽度为 500 像素的容器。在这个容器内，您可以添加两行，并将第二行分成两部分，宽度为 50%（或一半）。

```less
<div class="wrapper" style="width:300px;">
  <div style="background-color:red;width;100%;">1</div>
  <div style="background-color:green;width:50%;float:left;">2</div>
  <div style="background-color:blue;width:50%;float:right;">3</div>
</div>
```

现在看起来应该像以下的截图：

![Box-sizing](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-01-07.jpg)

一个 HTML 包装器

当前的结构直到您添加一些填充时并不会出现问题，这些填充用于在第二行的两列之间构建一些空间或边框（在 HTML 包装器图像中的数字*2*和*3*）。填充和边框将破坏我们的布局，如下所示：

```less
<div class="wrapper" style="width:300px;">
<div style="background-color:red;width:100%;">1</div>
<div style="background-color:green;width:50%;float:left;border:5px solid yellow;">2</div>
<div style="background-color:blue;width:50%;border:5px solid yellow;float:right;">3</div>
</div>
<br>
<div class="wrapper" style="width:300px;">
<div style="background-color:red;width;100%;">1</div>
<div style="background-color:green;float:left;width:50%;padding-right:5px;"><div style="background-color:yellow;">2</div></div>
<div style="background-color:blue;width:50%;padding-right:5px;float:right;">3</div>
</div>
```

最后，这段代码的输出应该看起来像以下的截图：

![Box-sizing](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-01-08.jpg)

由于填充和边框而导致的破碎布局

可以执行类似的操作，只是包装器可以包装在额外的包装器内。然后，`box-sizing: border-box;`声明可以应用于此。现在，结果应该看起来像以下的截图：

![Box-sizing](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-01-09.jpg)

使用 box-sizing: border-box 的布局

如您所见，填充和边框被父元素减去了 50%。这将使计算变得更容易。当然，一旦父容器包装器具有固定宽度，您可以自行进行计算。如果父元素有 300 像素，那么这个 50%将是 150 像素。减去填充和边框的宽度将给出列的固定大小。当父元素具有流体宽度（视口的百分比）时，这种方法不起作用。流体布局随着屏幕宽度的变化而变化。如果您的屏幕变小，那么所有元素也会变小，百分比保持不变。通过为所有可能的屏幕尺寸进行计算，找到允许所有元素对齐的列的真实大小，您将很快发现这是一个漫长、具有挑战性和艰巨的过程。

因此，您应该在本书的所有示例中使用`box-sizing: border-box;`。请注意，box-sizing 也必须按照供应商特定的规则进行定义，如下所示：

```less
-webkit-box-sizing: border-box;
-moz-box-sizing: border-box;
box-sizing: border-box;
```

在这个例子中，*Less*代码将如下所示：

```less
// Box sizing mixin
.box-sizing(@boxmodel) {
  -webkit-box-sizing: @boxmodel;
     -moz-box-sizing: @boxmodel;
          box-sizing: @boxmodel;
}
// Reset the box-sizing
*,
*:before,
*:after {
  .box-sizing(border-box);
}
```

### 提示

这段代码已经被添加到一个名为`boxsizing.less`的单独文件中。从现在开始，我们的*Less*文件的基础将包含以下代码：

```less
@import: "normalize.less";
@import: "boxsizing.less";
```

在接下来的章节中，您将学习更多关于如何将您的*Less*代码组织成文件。

# 服务器端编译

您已经迈出了*Less*开发的前几步。如前所述，已经使用了客户端编译。然而，**客户端**编译与`less.js`不应该在真实的网站上使用。这是因为尽管使您的开发变得简单和快速，但为每个页面请求（或实际上，每个用户的初始页面加载）编译您的*Less*文件实际上会减慢您的网站速度。

对于生产环境，需要编译您的文件并将最终的 CSS 文件提供给浏览器。术语**服务器端**可能有些误导。在这种情况下，服务器端意味着编译后的 CSS 代码被发送到客户端浏览器，而不是*Less*代码，它必须在客户端浏览器中由 less.js 编译后显示。您应该预编译您的*Less*代码。通过将*less.js*的结果复制粘贴到一个文件中，并在 HTML 文件中包含这个文件作为 CSS 文件，您应该会得到相同的效果，只是您的 CSS 没有被最小化。

*Less*捆绑了一个命令行编译器。使用以下命令安装和使用它非常简单：

```less
 >> npm install -g less
 >> lessc styles.less styles.css

```

Node JavaScript 平台的软件包管理器是 **npm**。Node 可以在没有浏览器的情况下运行 JavaScript 脚本。Node 和 npm 可在 Windows、Mac OS X 和其他 Unix/*nix 机器上运行。您可以通过访问 [`nodejs.org/download/`](http://nodejs.org/download) 找到适用于您平台的 Node.js 源代码或预构建安装程序。要安装 npm，请阅读 README 文件中的说明，网址为 [`www.npmjs.org/doc/README.html`](https://www.npmjs.org/doc/README.html)。

使用 `–help` 函数获取以下命令行编译器可用的选项列表：

```less
 >> lessc –help

```

`lessc styles.less styles.css` 将 `styles.less` 编译为 `styles.css`。在成功编译后，HTML 中指向 `styles.css` 的链接将如下显示：

```less
<link rel="stylesheet/css" type="text/css" href="styles.css">
```

## 压缩和最小化你的 CSS

编译后，CSS 代码是干净且可读的。在将此代码投入生产时，您必须压缩和最小化它以增加加载速度并节省带宽。**压缩** 和 **最小化** CSS 代码的基本步骤是删除注释、空格和其他不必要的代码。结果可能不容易被人类阅读，但这并不重要，因为您可以使用 *Less* 文件来更新或修改 CSS。

*Less* 命令行编译器有两个选项用于压缩和最小化。第一个选项（**-x** 或 `–yui-compress`）使用 **YUI CSS 压缩器**（可以在 [`yui.github.io/yuicompressor/css.html`](http://yui.github.io/yuicompressor/css.html) 访问），第二个选项（`--clean-css`）使用 **clean-css**（可以在 [`github.com/GoalSmashers/clean-css`](https://github.com/GoalSmashers/clean-css) 访问）。你不能同时使用这两个选项。**Clean-css** 声称更快，直到最近，你可能不会在压缩中发现太大的差异。通过编译前面示例中的 `keyframes.less`，包括 `normalize.less` 和 `boxsizing.less`，结果将为 4377 字节。使用 clean-css，这将减少到 3516 字节，而 YUI 则为 3538 字节。自 *Less* 版本 1.5.0 起，clean-css 是编译器的默认选项。

## 图形用户界面

有些人会更喜欢使用 **图形用户界面**（**GUI**）而不是命令行编译。有许多 GUI 可用于不同平台，以编辑和编译您的 *Less* 代码。这里无法提及所有 GUI。相反，以下是一些最显著的正面 GUI 的列表：

+   WinLess 是 Windows 上的 *Less* GUI。

+   SimpLESS 是一个跨平台的编辑器和编译器，具有许多功能，包括自动向您的代码添加供应商特定规则。

+   CodeKIT 是 Mac（OS X）的 GUI。它可以编译许多语言，包括 *Less*。它包括优化和浏览器预览。

+   最后提到的是 Crunch! Crunch! 也是一个跨平台的编译器和编辑器。

在选择 *Less* 开发的 GUI 时，始终检查它使用的 `less.js` 版本。一些 GUI 是建立在较旧版本的 `less.js` 上，并不支持最新的功能。

使用 Visual Studio 的 Web 开发人员应该查看 **Web Essentials**。Web Essentials 扩展了 Visual Studio 的许多新功能，包括 *Less*。此外，其他 IDE（如 **PHPStorm**）也内置了 *Less* 编译器。Eclipse 也有 *Less* 插件。

# 总结

在本章中，您刷新并扩展了关于 CSS3 的知识。您学会了如何在客户端上编译您的*Less*代码。此外，您已经编写了允许您在*Less*中拥有圆角、渐变和动画的代码，因此您现在可以见证使用*Less*的利润，并采取关键的初始步骤来组织和规划您的新项目。您了解了为什么要使用 CSS 重置，如何将其编译成*Less*代码，以及 box-sizing border-box 如何使您的工作更轻松。您还了解了 mixin 是什么，如何使用它，以及如何使用`@import`指令导入*Less*文件。最后但同样重要的是，您已经学会了什么是服务器端编译以及如何使用 GUI。

在下一章中，您将学习如何在*Less*中使用变量以及如何构建和使用复杂的 mixin。


# 第二章：使用变量和混合

在本章中，你将更详细地学习*Less*，了解更多关于变量和混合的知识。*Less*中的**变量**可以在代码中的任何地方重复使用。虽然它们通常在一个地方定义，但也可以在代码的其他地方被覆盖。它们用于定义常用值，这些值只能在一个地方编辑一次。基于**不要重复自己**（**DRY**）原则，常用值将帮助你构建更易于维护的网站。**混合**用于设置类的属性。它们将任务捆绑在一行代码中，并且可重复使用。你将学习如何在项目中创建、使用和重复使用它们，并且编写更好的 CSS 而不重复代码。

本章将涵盖以下主题：

+   对你的代码进行注释

+   使用变量

+   值的转义

+   使用混合

# 注释

注释使你的代码清晰易读。重要的是你能够清楚地理解它们。这就是为什么本章以一些注释的注解和示例开始的原因。

### 提示

在考虑文件大小、下载时间和性能时，不要吝啬你的注释。在编译和最小化最终的 CSS 代码过程中，注释和其他布局结构将被有效地移除。你可以在需要的地方添加注释以便理解和可读性。

在*Less*中，你可以像编写 CSS 代码时一样添加注释。注释行放在`/* */`之间。*Less*还允许以`//`开头的单行注释。

使用*Less*，你将会在最终样式表中保留这些注释，除了单行注释，它们不会被打印出来。**最小化器**会在你的最终**编译样式表**中移除这些注释。以下代码中可以看到一个例子：

```less
/* comments by Bass
.mixins() { ~"this mixin is commented out"; }
*/
```

## 嵌套注释

虽然*Less*，像 PHP 或 JavaScript 一样，不允许嵌套注释，但以`//`开头的单行注释是允许的，并且可以与正常的注释语法混合使用。以下代码片段中展示了这一点：

```less
/*
//commented out
*/
```

## 特殊注释

最小化器定义了一种特殊的注释语法，有时允许将重要注释（如许可通知）包含在最小化的输出中。你可以使用这种语法在样式表的顶部写一些版权声明。使用干净的 CSS 和*Less*的`clean-css`命令行编译器的默认最小化器，你应该在`/*! !*/`之间放置这个重要的命令，如下例所示：

```less
 /*!
very important comment!
         !*/
```

# 变量

*Less*中的变量帮助你保持文件的组织和易于维护。它们允许你在一个地方指定广泛使用的值，然后在整个*Less*代码中重复使用它们。最终样式表的属性可以通过变量设置。所以，想象一下，你不再需要在样式表中搜索特定颜色或值的每个声明了。所有这些是如何工作的呢？变量将以`@`开头并具有一个名称。这样的变量示例包括`@color`、`@size`和`@tree`。在写名称时，你可以使用任何字母数字字符、下划线和破折号。这意味着`@this-is-variable-name-with-35-chars`是一个有效的变量名。

### 提示

尽管本书中的变量名使用了字母数字字符、下划线和破折号，但规范允许使用任何字符，有一些例外。这些规范源自 CSS 语法（你可以在[`www.w3.org/TR/CSS21/grammar.html`](http://www.w3.org/TR/CSS21/grammar.html)查看）。以破折号开头的名称保留给供应商特定规则，而空格已经用于将类名相互分隔。使用转义是可能且允许的，这在（编程）语言中非常罕见。然而，空格的转义是不可能的。`NULL`也是不允许的。

不幸的是，在*Less*中使用`@`是有歧义的。正如您在第一章中所见，混合使用的参数也以`@`开头。这还不是全部。由于有效的 CSS 代码也是有效的*Less*代码，因此还会有以`@`开头的 CSS 媒体查询声明。上下文将清楚地表明`@`用于声明变量。如果上下文不够清晰，本书中将明确提到`@`的含义。

您可以为变量赋值，这将被称为声明。值可以包含任何对 CSS 属性有效的值。

您可以使用冒号（`:`）为变量赋值。声明以分号（`;`）结束。以下示例将说明这一点：

```less
@width: 10px;
@color: blue;
@list: a b c d;
@csv-list: a, b, c, d;
@escaped-value: ~"dark@{color}";
```

在变量声明之后，您可以在代码中的任何位置使用该变量来引用其值。这使得变量在编程*Less*代码时非常强大。查看本书的可下载代码中的本章示例代码，以更好地理解。

## 组织您的文件

正如您所见，您只需声明一次变量，就可以在代码中的任何地方使用它。因此，要对变量进行更改，您也只需更改一次。示例代码在名为`less/variables.less`的单独文件中定义了变量。组织文件是一个很好的做法。如果您想要进行更改，现在您知道该去哪里查找了。

回想一下第一章中的**CSS 重置**和**边框盒模型**，您的主*Less*文件现在将如下代码片段所示：

```less
@import "less/normalize.less";
@import "less/boxsizing.less";
@import "less/mixins.less";
@import "less/variables.less";
```

在这里，`@import`语句从文件中导入代码到主*Less*文件中。文件名用引号括起来，后面跟着一个分号。除了*Less*文件，您还可以导入普通的 CSS 文件，这些文件不会被处理为*Less*指令；这将在第五章中详细解释，*将 Less 集成到您自己的项目中*。

现在您应该在浏览器中打开`http://localhost/index.html`。您将看到一个简单的网站布局，其中包含标题、内容块、侧边菜单和三列页脚，如下面的屏幕截图所示。所有布局项都有蓝色的装饰。之后，打开您喜欢的文本编辑器中的`less/variables.less`。

![组织您的文件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-02-01.jpg)

使用*Less*构建的布局

您很好奇，我敢打赌您也打开了其他文件。不要被其中的代码复杂性吓到。这些代码和布局用于展示在单个位置定义的广泛使用的变量的强大功能。这可以通过比几行代码更现实和复杂的示例更好地展示出来。请放心，所有其他代码很快就会向您解释这一点。在您知晓之前，所有这些代码对您来说都将非常熟悉。

首先，在您之前打开的`less/variables.less`文件中的`@darkcolor: darkgreen;`行中，将`darkblue`更改为`darkgreen`。之后，观察浏览器中的结果。如果您还没有使用`#!watch`功能，请重新加载浏览器。

布局现在将显示为绿色。如果您之前还不确定，现在应该明白了。在实践中，您不会使用一行代码来更改整个网站，但这个示例展示了*Less*可以如何使您的工作更轻松。

想象一下，您已经完成了您的深绿色网站的工作，并向老板展示了它。"干得好！"他说，但他也告诉您："我知道我要求绿色，但如果您不介意，我更喜欢红色的网站"。现在，您微笑着，只需在`less/variables.less`文件中的`@darkcolor: darkgreen;`行中将`darkgreen`更改为`darkred`。

正如您所见，您的 HTML 是干净和直接的，没有内联 CSS 甚至类名。现在有一个新的问题；您将不得不以聪明和适当的方式命名、声明和保存您的变量。在这样做时，保持一致和清晰是非常重要的。在组织您的变量时，始终遵循相同的策略，使用命名约定和在上下文不够清晰的地方添加注释。请记住，任何人都应该能够在任何时候接管您的工作而无需进一步的说明。为了实现这一点，您将不得不深入了解变量。

## 命名您的变量

您应该始终给您的变量起有意义和描述性的名称。像`@a1`和`@a2`这样的变量名称会被编译，但选择得不好。当变量数量增加或者您需要在代码中做一些深层次的更改时，您将不知道或者记得`@a2`被用于什么。您将不得不查找它的上下文，以找到它在您的*Less*文件中的使用，或者更糟糕的是，检查您的 HTML 元素，以找到哪些 CSS 规则被应用在它上面，以便找到*Less*上下文。在这种不幸的情况下，您将回到原点。

好的命名示例包括`@nav-tabs-active-link-hover-border-color`和`@dark-color`。这些变量是有意义和描述性的，因为它们的名称试图描述它们的功能或用途，而不是它们的值。这种命名过程也被称为**语义命名**。因此，在这种情况下，`@dark-color`比`@red`更好，而在某些情况下，您可以更具体地使用`@brand-color`。这可以描述网站的一些品牌颜色，就像前面的例子一样。如果品牌颜色从深红色变为浅绿色，那么`@brand-color: lightgreen;`仍然是有意义的。然而，`@dark-color: lightgreen;`或`@red: lightgreen;`就不太合适了。

如您所见，变量名中使用连字符来分隔单词。这些名称被称为**连字符名称**。您应该使用小写字母。使用连字符名称并没有严格的规则；所谓的**驼峰命名法**也被使用，并且被许多程序员认为是可接受的替代方式。在驼峰命名法中，您将使用类似`@navTabsActiveLinkHoverBorderColor`和`@darkColor`的命名。无论是连字符名称还是驼峰名称都可以提高可读性。

### 提示

在编写 CSS 和 HTML 代码时，您会使用连字符连接的双词术语和小写的类名、ID 和字体名称，以及其他内容。这些规则并不总是严格的，也不是按照惯例遵循的。本书在编写*Less*代码时遵循这种约定，因此使用了连字符名称。

无论您喜欢驼峰命名法还是连字符名称都不是很重要。当您选择了驼峰命名法或连字符名称之后，保持一致并在整个*Less*文件中使用相同的命名方式是很重要的。

### 提示

当进行计算时，连字符名称可能会引起一些麻烦。您将需要一些额外的空格来解决这个问题。当您声明`@value`减一时，`@value-1`将被读作一个单独的变量，而不是`@value -1`。

## 使用变量

如果您的项目不断增长，将为每个 CSS 属性值添加一个变量将变得不可能，因此您将不得不选择哪些值应该是变量，哪些不应该是。在这个过程中并没有严格的规则。在接下来的章节中，您将找到一些明确的指导来做出这些选择。

首先，您应该尝试找到在您的代码中多次使用的属性值。在创建变量时，重复使用是合适的。示例代码中的`@dark-color`变量就是这种属性值的一个很好的例子。

其次，您可以创建用于自定义设置的属性的变量。示例代码中的`@basic-width`变量就是这种属性的一个例子。

最后，你应该考虑为可重用的组件创建变量。看看我们的示例，你可以在其他项目中重用页眉。为了实现这一点，你应该创建一个新的`less/header.less`文件，并使用以下代码将其导入到你的主文件中：

```less
@import "less/header.less";
```

## 组织变量

为了使组件可重用，你可以为每个组件或函数创建*Less*文件，并安排变量以适应这些文件。为了演示这一点，将示例代码拆分为`less/header.less`，`less/content.less`和`less/footer.less`。

`less/header.less`文件现在将包含以下代码：

```less
header
{
   background-color: @header-dark-color;
   min-height: @header-height;
   padding: 10px;

   .center-content;
   .border-radius(15px);
   .box-shadow(0 0 10px, 70%);

   h1 {color: @header-light-color;}
 }
```

注意，`@dark-color`已被重命名为`@header-dark-color`。在浏览器中打开`http://localhost/project.html`，并在文本编辑器中打开`less/project.less`文件，以查看所有更改及其影响。

现在，在你的`less/project.less`文件中使用`@import "header.less";`包含`less/header.less`文件，并在`less/variablesproject.less`文件中创建一个页眉部分，如下所示：

```less
/* header */
@header-dark-color: @dark-color;
@header-light-color: @light-color;
@header-height: 75px;
```

`@header-dark-color: @dark-color;`语句将`@dark-color;`的值赋给`@header-dark-color`。之后，你将对`less/content.less`和`less/footer.less`做同样的操作。正如你所看到的，`http://localhost/project.html`在你的更改后仍然看起来一样。

现在，在你的文本编辑器中打开`less/variablesproject.less`文件，并将页脚部分更改为以下代码：

```less
/* footer */
@footer-dark-color: darkgreen;
@footer-light-color: lightgreen;
@footer-height: 100px;
@footer-gutter: 10px;
```

在你的浏览器中，你现在将看到带有绿色页脚的布局。

## 最后声明获胜

在第一章中，你已经了解了**CSS 层叠**，最后一条规则指出，如果其他规则的输出相等，最后声明的值将获胜。*Less*使用相同的策略，变量的最后声明将在所有前面的代码中使用。在下面的代码中，你将看到属性值设置为`2`，符合最后声明获胜的规则：

```less
@value: 1;
.class{
property: @value;
}
@value: 2;
```

```less
Compiles into:
.class{
property: 2;
}
```

事实上，*Less*首先读取你的所有代码。当变量的值被使用时，实际上只使用最后分配或最后读取的值。最后声明获胜的事实只会影响在相同作用域中定义的声明。

在大多数编程语言中，作用域由编译器可以独立运行的代码部分定义。函数和类可以有自己的作用域。在*Less*中，mixin 有自己的作用域。混合将在本章后面更详细地讨论。

以下代码向你展示了，根据在 mixin 作用域内声明的值，属性值设置为`3`：

```less
@value: 1;
.mixin(){
  @value: 3;
  property: @value;
}
.class{
  .mixin;
}
@value: 2;Compiles to:
.class{
property: 3;
}
```

上述代码意味着你不能在编译过程中更改变量。这使得这些变量成为理论上的**常量**。将这与你代码中数学值 pi 的定义进行比较，它始终是相同的。你只需定义`PI`一次，`PI = 3.14`将在你的代码中，并且在运行代码时保持不变。因此，变量应该只声明一次。

变量的**重声明**和最后声明获胜的规则将在许多*Less*项目和代码的定制中使用。

为了演示重声明，创建一个新的`less/customized.less`文件，并将以下代码写入其中：

```less
@import "styles.less";
@dark-color: black;
@basic-width: 940px;
```

在`customized.html`文件中引用`customized.less`文件，如下所示：

```less
<link rel="stylesheet/less" type="text/css" href="less/customized.less" />
```

现在在浏览器中加载`customized.html`文件。正如你所看到的，你只用了三行代码就创建了一个定制版本的布局！

## 变量声明不是静态的

尽管变量的行为类似于常量，但它们的**声明**不一定是不可改变的或静态的。首先，你可以将一个变量的值赋给另一个变量，如下面的代码所示：

```less
@var2 : 1;
@var1 : @var2;
@var2 : 3;
```

`@var1`的值现在是`3`而不是`1`。请理解，你不需要创建某种**引用**，因为最后声明获胜的规则在这里适用。`@var1`变量将获得最后声明的`@var2`变量的值。

在示例代码中，您还会发现`@light-color: lighten(@dark-color,40%);`的声明。`lighten()`函数是*Less*的所谓内置函数。第三章，*嵌套规则、操作和内置函数*，将介绍内置函数。使用`lighten()`函数将`@light-color`设置为基于`@dark-color`计算的颜色值。您还应该注意`@dark-color`的最后一个声明，因为这用于颜色计算。

动态声明变量值可以提供灵活性，但请记住，您只能在声明后声明一次值，并且不能在声明后更改它。

## 懒加载

在从变量切换到混合器之前，您应该首先了解**懒加载**。在计算机编程中，这意味着推迟对象的初始化，直到需要它为止。懒加载是急切加载的相反。对于*Less*来说，这意味着变量是懒加载的，不必在实际使用之前声明。

试图理解理论方面固然很好，但现在是时候通过以下示例了解它们在实践中是如何工作的：

```less
.class {
  property: @var;
}
@var: 2;
```

上述代码编译为以下代码：

```less
.class {
  property: 2;
}
```

# 转义值

*Less*是 CSS 的扩展。这意味着*Less*在遇到无效的 CSS 或在编译期间评估有效的 CSS 时会出错。一些浏览器使用无效的 CSS 定义属性。众所周知的例子包括`property: ms:somefunction()`之类的东西。其中一些规则可以被供应商特定的规则替换。重要的是要注意，*Less*中无效的属性值不会被编译。

CSS3 中的新函数`calc()`是 CSS 中进行简单数学运算的一种本地 CSS 方式，可以替代任意长度的值。

在这两种情况下，*Less*在编译或导入时都无法给我们正确的值。

```less
@aside-width: 80px;
.content {
width: calc(100% -  @aside-width)
}
```

上述代码编译为以下代码：

```less
.content {
  width: calc(20%);
}
```

从上述代码中，`@aside-width: 80px;`是声明一个名为`aside-width`的变量。这个变量得到了 80 像素的值。关于变量的更多信息将在接下来的章节中介绍。然而，更重要的是，现在上述结果是错误的（或者至少不如预期），因为`calc()`函数应该在渲染时进行评估。在渲染时，`calc()`函数有能力混合单位，比如百分比和像素。在上述代码中，`.content`被分配了`100%`的可用空间的宽度（换句话说，所有可用空间）减去`80px`（像素）。

**转义**这些值将防止这些问题。在*Less*中，您可以通过将值放在用波浪号(`~)前面的引号(`""`)之间来转义值。因此，在这个例子中，您应该写`width: ~"calc(100% - @{aside-width})"`。

请注意，大括号放在`aside-width`的变量名中，这被称为**字符串插值**。在转义的值中，任何在引号之间的内容都会被原样使用，几乎没有变化。唯一的例外是**插值变量**。

字符串是字符序列。在*Less*和 CSS 中，引号之间的值是字符串。没有转义，*Less*会将其字符串编译成 CSS 字符串。

例如，`width: "calc(100 – 80px)"`在 CSS 中没有意义，`width: calc(100% - @aside-width)`也是如此，因为`@aside-width`没有意义。

因此，通过转义和字符串插值，您可以从以下代码片段开始：

```less
@aside-width: 80px;
.content{
    width: ~"calc(100% - @{aside-width});"
}
```

上述代码将编译为以下代码：

```less
.content {
  width: calc(100% - 80px);
}
```

### 提示

在使用`calc()`函数的特定情况下，*Less*编译器具有**strict-math**选项（自 1.4 版本以来使用）。这与命令行中的`–strict-math=on`或在 JavaScript 中使用`strictMath: true`一起使用。当打开 strict-math 选项时，`calc(100% - @aside-width);`的宽度将被编译为`width: calc(100% - 80px);`。请注意，在 1.6、1.7 和 2.0 版本的开发过程中，对这个**strict-math**选项进行了许多更改。

# 混合

混合在*Less*中扮演着重要角色。在第一章中讨论圆角示例时，您已经看到了混合。混合从面向对象编程中获取其命名。它们看起来像函数式编程中的函数，但实际上像 C 宏一样起作用。*Less*中的混合允许您通过简单地将类名包含为其属性之一，将一个类的所有属性嵌入到另一个类中，如下面的代码所示：

```less
.mixin(){
  color: red;
      width: 300px;
  padding: 0 5px 10px 5px;
}
p{
.mixin();
}
```

前面的代码将被编译为以下代码：

```less
p{
  color: red;
  width: 300px;
  padding: 0 5px 10px 5px;
}
```

在网站上使用的最终 CSS 代码中，每个`<p>`段落标记都将使用`mixin()`函数中定义的属性进行样式设置。优点是您可以在不同的类上应用相同的混合。正如在圆角示例中所看到的，您只需要声明一次属性。

尝试打开本章可下载文件中的`less/mixins.less`。在本书的示例中，所有混合都保存在一个文件中。在这个文件中，您可以根据它们的功能来安排您的混合。将它们分组到一个文件中可以防止我们在删除或替换其他功能*Less*文件时破坏代码。您的项目中包含了`sidebar.less`和`content.less`的示例，这两个文件都使用了 border-radius 混合。如果我们现在替换`sidebar.less`，您不会破坏`content.less`。当然，您也不希望在代码中两次使用相同类型的混合。

`less/boxsizing.less`中的 box-sizing 混合将被视为一个特例。box-sizing 混合影响所有元素，您希望能够完全替换 box-sizing 模型。

`less/mixins.less`文件包含四个混合，将在以下部分中讨论。box-shadow 和 clearfix 混合也具有**嵌套**等复杂结构，但这些混合将在下一章中进一步详细解释。

## 基本混合

您已经看到了圆角混合。基本混合看起来像 CSS 中的类定义。混合在类内部调用并赋予这些类其属性。

在`less/mixins.less`文件中的示例代码中，您将找到`.center-content`混合，它将`margin`属性的值设置为`0 auto`。这个混合用于居中对齐标题、内容包装器和页脚。

### 提示

请注意，这些居中内容混合并不是唯一的解决方案。一个通用的包装器可以一次性居中对齐标题、内容包装器和页脚，也适用于这个示例布局。这个混合的名称也可以讨论。当您决定不再居中内容时，这个混合的名称将不再有任何意义。

删除`margin: 0 auto;`属性，实际上是从混合中使内容居中。然后应该重新加载浏览器中的`index.html`以查看效果。

## 参数化混合

如前所述，混合在函数式编程中扮演函数的角色，因此，作为函数，它们可以被参数化。参数是与混合结合使用的值，参数的名称在混合内部用作其值的引用。以下代码向您展示了一个使用参数化混合的示例：

```less
.mixin(@parameter){
  property: @parameter;
}
.class1 {.mixin(10);}
.class2 {.mixin(20);}
```

前面的代码被编译为以下代码：

```less
.class1 {
  property: 10;
}

.class2 {
  property: 20;
}
```

前面的示例显示了参数化如何使混合非常强大。它们可以根据输入值设置属性。

### 默认值

参数具有可选的默认值，可以使用`.mixins(@parameter:defaultvalue);`来定义。要了解这是如何工作的，您应该考虑`less/mixins.less`文件中的`border-radius`混合，如下面的代码所示：

```less
.border-radius(@radius: 10px)
{
  -webkit-border-radius: @radius;
  -moz-border-radius: @radius;
  border-radius: @radius;
}
```

请注意，这里的默认值是`10px`。

## 命名和调用

在本书中，混合物具有有意义和描述性的名称，就像变量名称一样，这些名称是用连字符分隔的。为混合物使用有意义和描述性的名称使您的代码对其他人更易读，更易于维护。参数和变量都以`@`符号开头。上下文应该清楚地表明正在讨论的是变量还是混合参数。

为了更好地理解，请考虑以下代码：

```less
@defaulvalue-parameter1 :10;
.mixin(@parameter1: @defaulvalue-parameter1)
{
  property: @parameter1;
}
.class {
 .mixin
}
```

这段代码可以编译成以下代码：

```less
.class{
  property: 10;
}
```

请注意，这里的`@defaulvalue-parameter1`是一个变量。

以下代码还说明了混合的范围：

```less
@defaulvalue-parameter1 :10;
.mixin(@parameter1: @defaulvalue-parameter1){
  property: @parameter1;
}
.class {
  .mixin
}
 @parameter1 : 20;
```

这段代码可以编译成以下代码：

```less
.class{
  property: 10;
}
```

在这里，`@parameter1`的最后一个声明在混合的范围之外，所以属性仍然设置为`10`。

## 多个参数

混合物的多个参数可以用逗号或分号分隔。函数式程序员通常使用逗号作为**分隔符**。在*Less*中，分号更受青睐。逗号在这里实际上有一个模棱两可的作用，因为它们不仅用于分隔参数，还用于分隔**csv 列表**中的列表项。

`.mixin(a,b,c,d)`调用使用四个参数调用混合物，同样`.mixin(a;b;c;d)`调用也是一样。现在，考虑一下您使用`.mixin(a,b,c;d)`调用混合物的情况。这里只使用了两个参数，第一个参数是一个包含三个项目的列表。如果参数列表中至少有一个分号，则唯一的分隔符将是分号。下面的代码向您展示了在参数列表中添加额外分号的效果：

```less
.mixin(@list){
   property: @list;
}
.class{ mixin(a,b,c,d;);}//see the extra semi-colon!
```

这段代码可以编译成以下代码：

```less
.class{
   property: a, b, c, d;
}
```

没有这个额外的分号，你调用一个带有四个参数的混合物。在这种情况下，编译器会抛出一个错误：**RuntimeError: No matching definition was found for .mixin(a, b, c, d)**。实际上，你需要的是一个包含`.mixin(@a,@b,@c,@d)`的混合物。

在前面的例子中，已经明确表示*Less*中允许具有相同名称的混合物。当找到具有相同名称的不同混合物时，编译器仅使用具有正确数量参数的混合物，或者在找不到匹配的混合物时抛出错误。这种形式的参数匹配可以与各种编程语言中的**方法重载**进行比较。

如果一个混合调用匹配多个混合，如下面的代码所示，那么编译器将使用所有匹配的混合：

```less
 .mixin(@a){
        property-a: @a;
}

.mixin(@b){
        property-b: @b;
}

class{
      .mixin(value);
}
```

这段代码编译成以下代码：

```less
class {
  property-a: value;
  property-b: value;
}
```

## 更复杂的线性渐变背景混合

现在您已经有足够的理论知识来构建更复杂的混合物。在这个例子中，您将为我们布局的页脚列添加三种颜色的**背景渐变**指令。

最终结果应该如下截图所示：

![更复杂的线性渐变背景混合](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-02-02.jpg)

使用*Less*构建的线性渐变背景

这些渐变背景被选择是因为它们的复杂性和随时间变化的充分记录。最终结果将是一个复杂的混合，肯定不完美，但可以显著改善结果。您可以肯定，您将不得不不时更改您的渐变混合，因为旧浏览器的支持下降，新浏览器，规范的变化和新的见解。请参考[`developer.mozilla.org/en-US/docs/Web/Guide/CSS/Using_CSS_gradients`](https://developer.mozilla.org/en-US/docs/Web/Guide/CSS/Using_CSS_gradients)获取更多示例。

你无法阻止这些必要的更改，但你可以最小化花在保持你的混合器最新的时间。*Less*保证了你所有的背景渐变都是基于同一个混合器定义在一个地方。

在基本层面上，CSS 中的背景渐变被定义为图像。因此，它们被应用在**background-image 属性**上。

在本书中，渐变是在`background-image`属性上设置的。其他示例（其他地方和其他书中）可能会在`background`属性上设置它们。它们的定义没有区别。CSS 为背景定义了不同的属性，如`background-image`、`background-color`、`background-size`和`background-position`。`background`属性是它们所有的缩写。当你将`background`属性的第一个值定义为图像，或者在这种情况下是渐变时，所有其他属性值都设置为它们的默认值。

你开始你的混合器，列出以下**要求**：

+   你需要一个参数来设置你的渐变的方向，你将使用角度。

+   你的渐变将由三种颜色组成

+   之后，你定义一个浏览器列表和你需要支持的浏览器版本

现在，你可以定义你的混合器的前几行如下：

```less
.backgroundgradient(@deg: 0deg; @start-color: green; @between-color:yellow; @end-color: red; @between:50%)
{
background-image: linear-gradient(@deg, @start-color, @between-color @between, @end-color);
}
```

![更复杂的线性渐变背景混合](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-02-04.jpg)

展示 45 度渐变线如何工作的一种方法。这是从[`dev.w3.org/csswg/css-images-3/`](http://dev.w3.org/csswg/css-images-3/)中获取的，版权所有 2013 W3C，2013 年 9 月 11 日

背景混合器有五个参数，如下：

+   第一个参数描述了以度为单位的方向。度数的数量给出了垂直和渐变方向之间的角度。方向的描述从底部开始。在底部，角度为 0 度，描述了从底部到顶部的渐变。然后角度顺时针转到 90 度点，描述了从左到右的渐变，依此类推。

+   接下来的三个参数是你的渐变的三种颜色，这是为它设置的默认值。

+   第五个也是最后一个参数定义了中间颜色的真实值。这里的百分比是应用渐变的元素宽度的百分比。第一个和最后一个颜色默认为 0 和 100。

现代浏览器，如 IE 11 版本，Firefox 16+版本，Opera 12.10+版本，Safari 7+版本和 Chrome 26+版本，支持这些背景图像属性。对于较旧的浏览器，必须添加特定于供应商的规则。这里的第一个问题是特定于供应商的规则使用了不同的方式来定义角度。为了补偿这一点，你可以使用以下代码对 90 度进行校正：

```less
.backgroundgradient(@deg: 0deg; @start-color: green; @between-color:yellow; @end-color: red; @between:50%){
  @old-angel: @deg – 90deg;
  -ms-background-image: linear-gradient(@old-angel , @start-color, @between-color @between, @end-color);
  background-image: linear-gradient(@deg, @start-color, @between-color @between, @end-color);
}
```

`-ms background-image`属性被 IE10 使用，因为较旧版本的 IE 无法支持背景图像。或者，你可以添加一个滤镜来支持双色渐变。在使用这个滤镜时，不支持与回退图像的组合，所以你必须选择基于 webkit 的浏览器，比如 Chrome 和 Safari，它们使用`-webkit-linear-gradient`；然而，如果你必须支持这些浏览器的旧版本，你将不得不使用`-webkit-gradient`。请注意，`-webkit-gradient`有一个不寻常的语法。例如，你的最终混合器可能看起来像以下代码：

```less
.backgroundgradient(@degrees: 0deg; @start-color: green; @between-color:yellow; @end-color: red; @between:50%){
  background-image: -moz-linear-gradient(@degrees, @start-color 0%, @between-color @between, @end-color 100%);
  background: -webkit-gradient(linear, left top, left bottom, color-stop(0%, @start-color), color-stop(@between,@between-color), color-stop(100%,@end-color));
  background-image : -webkit-linear-gradient(@degrees, @start-color 0%, @between-color @between, @end-color 100%);
  background-image: -o-linear-gradient(@degrees, @start-color 0%, @between-color @between, @end-color 100%);
  background-image: -ms-linear-gradient(@degrees, @start-color 0%, @between-color @between, @end-color 100%);
  background-image: linear-gradient((@degrees - 90deg), @start-color 0%, @between-color @between, @end-color 100%);
  filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='@startcolor', endColorstr='@endcolor',GradientType=0 );
}
```

前面的代码表明，即使使用*Less*，我们的代码仍然可能很复杂。除非这种复杂性可以支持不同的浏览器，你可以看到使用*Less*的优势，它允许你只在一个地方处理这段代码。

前面示例中的代码可以在`directivebackgrounds.html`和`less/directivebackgrounds.less`中找到。如果你想知道在经历了这一切之后为什么还要使用 CSS 背景渐变，那么请看一下[`lea.verou.me/css3patterns/`](http://lea.verou.me/css3patterns/)，看看有什么可能性。

## 特殊变量-@arguments 和@rest

*Less*定义了两个特殊变量。`@arguments`变量是第一个，包含传递的所有参数的列表。`@arguments`变量存在于 mixin 内部。在*Less*中，列表是用空格分隔的，所以你可以用`@arguments`来设置可以由值列表设置的属性。像`margin`和`padding`这样的属性在它们的简写表示法中接受列表，如下面的代码所示：

```less
.setmargin(@top:10px; @right:10px; @bottom: 10px; @left 10px;){
  margin: @arguments;
}
p{
.setmargin();
}
```

这段代码可以编译成以下代码：

```less
p {
  margin: 10px 10px 10px 10px;
}
```

第二个特殊变量是`@rest`。`@rest...`将调用者的前面参数后的所有奇数参数绑定到一个列表中。通过这样做，`@rest...`可以让 mixin 使用无限的参数列表。请注意，这三个结束点是语法的一部分。下面的代码显示了`@rest...`将`@a`变量后的所有奇数参数绑定到`property2`属性：

```less
.mixin(@a,@rest...) {
  property1: @a;
             property 2: @rest;
}
element {
    .mixin(1;2;3;4);
}
```

这段代码将被编译成以下代码：

```less
element {

  property1: 1;

  property2: 2 3 4;

}
```

你还应该考虑使用`@rest...`作为 csv 列表。为此，你可以将`less/mixinswithdirectivebackgrounds.less`中的`.backgroundgradient` mixin 重写为以下代码：

```less
.backgroundgradient(@deg: 0; @colors...) {
    background-repeat: repeat-x;
    background-image: -webkit-linear-gradient(@deg, @colors);
    background-image: -moz-linear-gradient(@deg, @colors);
    background-image: linear-gradient(@deg, @colors);
}
```

现在，这个 mixin 将接受一个无限的颜色列表，你可以用以下代码来使用它：

```less
div#content {        .backgroundgradient(0;blue,white,black,pink,purple,yellow,green,orange);
}
```

以下图显示了使用这个背景 mixin 的代码的结果：

![特殊变量-@arguments 和@rest](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-02-03.jpg)

## 返回值

如果你习惯于函数式编程，甚至了解数学函数，你会期望 mixin 有一个**返回值**。这只是意味着把`x`放进去，得到`y`。Mixin 没有返回值，但你可以使用它们的作用域模仿这种行为。在 mixin 中定义的变量将被复制到**调用者的作用域**，除非变量已经在调用者的作用域中定义。下面的例子将说明这一点：

```less
.returnmixin(){
        @par1: 5;
        @par2: 10;
}
.mixin(){
	@par2: 5; // protected for overwriting
        property1: @par1; // copied from returnmixin's scope
        property2: @par2;
        .returnmixin();
}

element{
.mixin();
}
```

这段代码将被编译成以下代码：

```less
element {
  property1: 5;
  property2: 5;
}
```

如果你看前面的例子，你可以将`property2: @par2;`与一个函数比较，比如`property2 = returnmixin();`。

### 提示

使用作用域来模仿返回值也可以应用在 mixin 上。在另一个 mixin 中定义的 mixin 可以在调用者的作用域中使用。然而，这些不像变量那样受作用域的保护！这个过程被称为**解锁**。目前，解锁不在本书的范围之内。

## 改变 mixin 的行为

为了使 mixin 更加灵活，影响它们的输出基于它们的输入参数将是有用的。*Less*提供了不同的机制来实现这一点。

### 开关

假设你有一个 mixin，`color();`应该根据上下文将颜色属性设置为白色或黑色。使用`@context: light;`声明设置上下文，并声明两个具有相同名称的 mixin，如下面的代码所示：

```less
.color(light)
{
      color: white;
}
.color(dark)
{
      color: black;
}
```

现在你可以在你的代码中使用`.color(@context);` mixin，它将把你的类的`color`属性设置为白色或黑色，取决于声明给`@context`的值。现在这可能看起来没什么用，但在你不断发展的项目中会很有用。看一下 Bootflat 项目[`www.flathemes.com/`](http://www.flathemes.com/)。这个项目提供了 Twitter 的 Bootstrap 的颜色变体。**Twitter 的 Bootstrap**是基于*Less*的**CSS 框架**。Bootflat 定义了两种样式，其中一种样式基于改进的 Bootstrap 3.0 样式，另一种样式是一个去掉了圆角的 Square UI 样式。这个项目使用一个开关来编译两种不同的样式。

### 参数匹配

*Less*允许具有相同名称的不同 mixin。如果有这样的 mixin，那么与调用者的参数列表匹配的每个 mixin 都将被使用。参考以下颜色 mixin：

```less
.color(@color)
{
  color: @color;
}
.color(@color1,@color2)
{
  color: gray;
}
```

在前面的代码中定义的颜色混合，`.color(white)`编译成`color: white;`，而`.color(white,black)`将给出`color: gray;`。请注意，`.color(white);`调用不匹配`.color(@color1,@color2)`混合，因为它需要两个参数，所以编译器没有使用它。

### 守卫混合

*Less*中也可以有相同名称和相同参数数量的混合。在这种情况下，所有匹配项都会被使用，如下例所示：

```less
.color(@color){
        color: @color;
        display: block;
}

.color(@color) {
        color: blue;
}
.class{
  .color(white)
}
```

这段代码将被编译成以下代码：

```less
.class{
  color: #ffffff;
  display: block;
  color: blue;
}
```

### 提示

还要注意*Less*将命名颜色`white`转换为`#ffffff;`。

在这种情况下，两个`color`声明是没有意义的。*Less*不会过滤掉重复声明，除非它们以完全相同的方式使用。

**守卫**可以用来防止重复定义的混合带来的麻烦。守卫是在关键字后面跟着一个条件定义的。当条件为真时，使用混合。以下示例清楚地说明了这一点：

```less
mixin(@a) when (@<1){
    color: white;
}
mixin(@a) when (@>=1){
    color: black;
}
.class {
   mixin(0);
}
.class2 {
    mixin(1);
}
```

这段代码将被编译成以下代码：

```less
.class {
  color: white;
}
.class2 {
  color: black;
}
```

守卫可以像编程中的*if*语句一样使用。比较运算符如`>`、`>=`、`=`, `=<`和`<`可以使用。一个或多个条件可以用逗号分隔的方式组合在一起，如果其中一个为真，则为真。

关键字`and`可以用来在两个条件都为真时评估为真，例如，`when @a>1` `and` `@<5`。最后，条件可以用关键字`not`否定，例如，`when (not a = red)`。

### 提示

如果您之前使用过 CSS 媒体查询，那么您一定会意识到守卫的作用方式与 CSS 中的媒体查询相同。

最后，守卫条件也可以包含内置函数。这些函数将在下一章中讨论，并在它们不是参数列表的一部分时作用于所有定义的变量。守卫条件的内置函数可以在以下代码中看到：

```less
@style: light;
.mixin(@color) when is_color(@color) and (@style = light) {
  color: pink;
}
.class() {
  mixin(red);
}
```

这段代码可以编译成以下代码：

```less
.class {
  color: pink;
}
```

在`@style: dark;`或`mixin(1);`的情况下，没有匹配项。

### 使用守卫和参数匹配来构建循环

当*Less*找不到**匹配的混合**时，它会继续到下一个评估并不会中断。这可以与守卫和参数匹配结合使用来构建循环。举个例子，想象有 10 个**类**，每个类都包含一个编号的背景图片。`.class1`类的`background-image`属性值设置为`background-1.png`，`.class2`类将`background-image`属性的值设置为`background-2.png`，依此类推，如下代码所示：

```less
.setbackground(@number) when (@number>0){
  .setbackground( @number - 1 );
  .class@{number} { background-image: ~"url(backgroundimage-@{number}.png)"; }
}
.setbackground(10);
```

这段代码可以编译成以下代码：

```less
.class1 {
  background-image: url(backgroundimage-1.png);
}
.class2 {
  background-image: url(backgroundimage-2.png);
}
...
.class10 {
  background-image: url(backgroundimage-10.png);
}
```

当您第一次看到最后一个混合时，它可能看起来很复杂，但如果您尝试自己评估混合，您会发现它实际上包含了您之前学到的很多东西。

在前面的代码中，`setbackground`混合调用了自身。程序员会称这为**递归**。这里发生了什么？

`.setbackground(10);`调用匹配了`.setbackground(@number)`混合，当`@number>0`时，请利用这一点。`.setbackground( @number - 1 );`的第一次评估也匹配了混合。这意味着编译器再次运行混合。这将重复直到`@number -1`为`0`；再也找不到匹配项。现在编译器将读取停止位置之后的内容，以使用混合。

最后一次停在`@number = 1`，所以它会评估`@numer = 1`条件下的`.class@{number} { background-image: ~"url(backgroundimage-@{number}.png)"; }`声明。当它之前停止时，是在`@number = 2`。所以，它会评估`@numer = 2`条件下的`.class@{number} { background-image: ~"url(backgroundimage-@{number}.png)"; }`声明，依此类推。当我们回到`@numer = 10`时，所有代码都已经编译完成。所以，编译器停止了。

除了保护和参数匹配，上面的示例还包含了`.class@{number}`类声明中的插值属性，以及在声明`~"url(backgroundimage-@{number}.png)";`时进行转义的字符串插值示例。混合还显示了在执行计算时需要使用额外的空格。因此，`@number - 1`不会被计算为一个`@number-1`变量。

## `!important`关键字

本章以关于*Less*中`!important`关键字的说明结束。在声明中使用`!important`会使该声明在两个或更多选择器匹配同一元素时具有最高的优先级。`!important`关键字会覆盖内联样式，如下面的代码所示：

```less
<style>
p{color:green !important;}
</style>
<p style="color:red;">green</p>
```

上述代码将显示为绿色文本。正如示例所示，您可以使用`!important`来更改内联 CSS 源的样式，这是您无法编辑的。它还可以用于确保样式始终被应用。然而，请谨慎使用`!important`，因为覆盖`!important`的唯一方法是使用另一个`!important`。在*Less*中不正确或不必要地使用`!important`将使您的代码混乱且难以维护。

在*Less*中，您不仅可以在属性中使用`!important`，还可以在混合中使用它。当为某个混合设置`!important`时，该混合的所有属性都将使用`!important`关键字声明。这可以在以下代码中看到：

```less
.mixin(){property1: 1;property2: 2;
}
.class{
.mixin() !important;
}
```

此代码将编译为以下代码：

```less
.class{
  property1: 1 !important;
  property2: 2 !important;
}
```

# 总结

在本章中，您学习了关于变量和混合的知识。您已经看到了在一个地方定义变量和混合将减少您的代码并使其易于维护。

在下一章中，您将学习更多关于混合和如何嵌套和扩展它们的知识。您还将了解*Less*的内置函数。内置函数可用于操纵混合和代码其他部分中的值。


# 第三章：嵌套规则，操作和内置函数

在本章中，你将学习*Less*如何帮助你更直观地组织你的 CSS 选择器，使继承清晰，并使你的样式表更短。你还将学习操作和内置函数。操作让你能够添加、减去、除以和乘以属性值和颜色。它们还让你有能力在属性之间创建复杂的关系。你还将学习如何在你的*Less*代码中使用内置函数来设置变量或保护。

本章将涵盖以下主题：

+   嵌套 CSS 规则

+   使用操作

+   在你的代码中使用内置函数

+   使用混合中的内置函数

# 导航结构

通过本章的示例，你将逐步扩展第二章中的布局，*使用变量和混合*，并使用导航结构。你将通过使用*Less*来为 HTML 列表设置样式来构建这个导航结构。这个导航结构形成了布局侧边栏中的菜单。

最终结果将如下截图所示：

![导航结构](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465-03-01.jpg)

使用*Less*构建的最终导航菜单

# 嵌套规则

你将使用第二章中的布局示例，*使用变量和混合*，来更详细地研究*规则的嵌套*。

为了做到这一点，你首先必须在浏览器中打开`http://localhost/index.html`，然后在你的文本编辑器中打开`less/sidebar.less`。

锚点被添加到菜单项中。这意味着侧边栏的 HTML 代码现在看起来像以下代码：

```less
<aside id="sidemenu">
  <h2>Side menu</h2>
  <ul>
      <li><a href="page1.html">item 1</a></li>
      <li><a href="page2.html">item 1</a></li>
  </ul>
</aside>
```

你需要为 CSS 中的不同元素设置每个规则的选择器，如下面的代码所示：

```less
#sidebar h2{
  color: black;
  font-size: 16px;
}
#sidebar ul li a{
  text-decoration: none;
  color: green;
}
```

正如你所看到的，`ul`（包括`li`元素和`a`锚点）元素和`h2`元素都是具有`#sidemenu` ID 的`aside`元素的子元素。CSS 并没有反映这种关系，因为它目前的格式如前面的代码所示。*Less*将帮助你在你的代码中反映这种关系。在*Less*中，你可以写下以下代码：

```less
#sidebar{
  h2{
    color: black;
    font-size: 16px;
  }
  ul{
    li{
      a{
        text-decoration: none;
        color: green;
      }
    }
  }
}
```

前面的代码将直接编译成以下 CSS 语法：

```less
#sidebar h2 {
  color: black;
  font-size: 16px;
}
#sidebar ul li a {
  text-decoration: none;
  color: green;
}
```

你编译后的*Less*代码的结果 CSS 与你原始的 CSS 代码完全相同。在*Less*中，你只需一次引用`#sidemenu` ID，由于`h2`和`ul`嵌套在`#sidemenu`中，你的代码结构是直观的，并且反映了你的 HTML 代码的**DOM 结构**。

为了保持你的代码整洁，一个新的`less/sidebar.less`文件已经被创建。它包含了前面的*Less*代码。当然，这个文件也应该被导入到`less/styles.less`中，使用以下代码行：

```less
@import "sidebar.less";
```

请注意，侧边栏被包裹在语义化的 HTML5 `aside`元素中，而不是`div`元素中。虽然这更语义化，但你会发现在你做出这些改变后，你的侧边栏已经浮动到了左侧。要解决这个问题，打开你的文本编辑器中的`less/content.less`。通过研究*Less*代码中 CSS 选择器的嵌套，你会发现`.wrapper`容器中嵌套了`aside float:right;`。如果你将这个`aside`规则移到`#content`容器中，语法应该如下所示：

```less
#content {
  //two third of @basic-width
  width:(@basic-width * 2 / 3);
  float:left;
  min-height:200px;
  aside {
    float:right;
  }
}
```

在`less/content.less`文件中，你还会发现一行`h2 { color: @content-dark-color; }`，这与你在`aside`元素中看到的是相反的。`h2`规则仍然会被`#sidebar h2{ color: black; }`覆盖。最终的规则包含了一个`#sidebar`选择器，因此它具有更高的**CSS 特异性**，正如第一章所解释的那样。

检查*Less*文件，例如`less/header.less`，再次牢记关于 CSS 选择器嵌套的全新见解。你会发现嵌套已经经常被使用。例如，在`less/header.less`中，`h1`元素的属性是通过嵌套设置的。

对这些文件进行适当的检查还将向您展示混合可以嵌套在类和其他混合中的方式。

## 混合和类

混合的名称应该总是以括号结尾；否则，它就是一个普通的**类**。*Less*中的混合和类都可以嵌套。考虑以下示例*Less*代码的区别：

```less
.class-1{
  property-1: a;
}
.class-2{
  .class-1;
  property-2: b;
}
```

这段代码将被编译成以下代码：

```less
.class-1 {
  property-1: a;
}
.class-2 {
  property-1: a;
  property-2: b;
}
```

您可以看到`.class-1`的属性如何被复制到编译后的 CSS 中的`.class-2`中。当您在*Less*中在`.class-1`后面添加括号并将其变成混合时，现在您应该考虑以下代码：

```less
.mixin(){
  property-1: a;
}
.class-2{
 .mixin;
  property-2: b;
}
```

这段代码将被编译成以下 CSS 代码：

```less
.class-2 {
  property-1: a;
  property-2: b;
}
```

让我们回到侧边导航菜单的示例。当您的菜单准备好时，您会发现`h2`标题元素内的“导航”文本毫无意义。除非您视力受损并使用屏幕阅读器，否则您可以轻松地看到侧边菜单是网站的导航。因此，您可以隐藏此标题，但应该保持对**屏幕阅读器**可见。设置`display:none`将使元素对屏幕阅读器不可见，而`visibility:hidden`也会隐藏元素，但仍会占用空间，因此可能会搞乱我们的设计。设置`clip`属性将有助于解决这种情况。您可以通过访问[`a11yproject.com/posts/how-to-hide-content/`](http://a11yproject.com/posts/how-to-hide-content/)了解更多详情。

根据优先规则，您可以使用*Less*编写以下类：

```less
.screenreaders-only {
  clip: rect(1px, 1px, 1px, 1px);
  position: absolute;
  border:0;
}
```

将前述类添加到`less/boxsizing.less`中，并将此文件重命名为`less/basics.less`。还请不要忘记重命名`less/styles.less`中的导入语句。现在，您可以使用以下*Less*代码来隐藏侧边栏菜单中的`h2`标题元素：

```less
#sidebar{
  h2{
    color: black;
    font-size: 16px;
 .screenreaders-only;
  }
}
```

执行这些步骤并将*Less*代码编译为 CSS 代码后，侧边导航现在将如下截图所示：

![混合和类](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465-03-02.jpg)

带有隐藏标题文本的样式化导航菜单

由于`.screenreaders-only`是一个类而不是混合，并且类被编译到最终的 CSS 中，因此不仅可以使用`.screenreaders-only`类将其属性添加到*Less*中的其他类中，还可以直接在 HTML 中使用该类，如下面的代码行所示：

```less
<div class="screenreaders-only">Only readable for screen readers</div>
```

在使用*Less*时，您经常需要根据项目的 HTML 结构选择特定编译的*Less*类和更通用的解决方案，该解决方案将应用于 HTML 代码中的一个类。不幸的是，在这些情况下，没有单一的解决方案。一般来说，特定于 DOM 的代码将生成更多的 CSS 代码，但也会保持 HTML 的清晰，并为您提供生成更多语义 HTML 代码的机会。对于这个选项，重用您的*Less*代码并不总是简单的。

将您的*Less*语法编译为类，并在 HTML 中使用它们将使您的代码更具可重用性。另一方面，它会由于这些类而搞乱您的 HTML。此外，CSS 效果与 HTML 结构之间的关系变得不那么严格。这使得维护或更改变得更加困难。

## 变量

在`less/variables.less`中，您应该定义一个侧边栏的部分，如下面的代码所示：

```less
/* side bar */
@header-color: black;
@header-font-size: 16px;
/* menu */
@menu-background-color: white;
@menu-font-color: green;
@menu-hover-background-color: darkgreen;
@menu-hover-font-color: white;
@menu-active-background-color: lightgreen;
@menu-active-font-color: white;
```

使用前面的变量，`less/sidebar.less`中的*Less*代码现在将如下所示：

```less
#sidebar{
  h2{
    color: @header-color;
    font-size: @header-font-size;
    .screenreaders-only;
  }
  ul{
    li{
      a{
        text-decoration: none;
        color: @menu-font-color;
        background-color: @menu-background-color;
        }
    }
  }
}
```

## 类和命名空间

在完成菜单之前，用于样式化菜单的*Less*代码将首先更改为类。这里已经讨论了需要考虑的要点。导航是一个通用结构，可以在许多项目中使用。在类结构中，它可以用来为任何 HTML 列表设置样式。

请为`less/nav.less`创建一个新文件，并将以下代码写入其中：

```less
.nav{
  li{
    a{
      text-decoration: none;
      color: @menu-font-color;
      background-color: @menu-background-color;
      }
  }
}
```

现在，您可以通过将`.nav`类添加到每个 HTML 列表（`ul`或`ol`）中，将我们 HTML 文档中的每个 HTML 列表转换为导航结构。可以使用以下代码行来实现：

```less
<ul class="nav">
```

请注意，使用这个*Less*代码，列表不能嵌套，列表中的项目应包含锚点（链接）。这些要求使得这段代码在您的其他项目中可以轻松地被（重新）使用。*Less*还提供了定义**命名空间**的可能性。命名空间可以使您的代码更具可移植性，并且与 CSS ID 选择器的定义方式相同。命名空间以`#`开头，如下面的代码所示：

```less
#lessnamespace {
  .nav {
    //code from  less/nav.less here
  }
}
```

`#lessnamespace`命名空间现在可以作为示例使用，如下面的代码所示：

```less
#sidebar {
  ul{
    #lessnamespace > .nav;
  }
}
```

实际上，命名空间与 ID 选择器没有区别。`#lessnamespace`命名空间也可以直接在您的 HTML 代码中使用，尽管在大多数情况下这并没有什么用，如下面的代码所示：

```less
<div id="lessnamespace">
  <ul class="nav">
    ...
  </ul>
</div>
```

HTML 要求每个 ID 只能定义一次，因此除非将 ID 附加到 body，否则不能在 HTML 文档中多次使用前面的 HTML 代码。然而，前面的代码表明，即使为自定义 HTML DOM 结构专门编写了*Less*代码，也可以在其他项目中重用。

在之前定义的`#lessnamespace`命名空间中，`.nav`是一个使直接使用成为可能的类。当`.nav`被更改为 mixin 时，它只能在*Less*中被重用，如下面的代码所示：

```less
#namespace {
  .nav(){
    li{
      width:100%;
    }
  }
}
#sidebar {
  ul{
    #namespace > .nav;
  }
}
```

这段代码将直接编译成以下代码：

```less
#sidebar ul li {
  width: 100%;
}
```

# 操作数字、颜色和变量

*Less*支持基本算术运算：加法（`+`）、减法（`-`）、乘法（`*`）和除法（`/`）。在 strict-math 模式下，操作应放在括号之间。您可以对变量、值和数字进行操作。这些将帮助您建立变量之间的关系。

打开`less/footer.less`立即看到您使用的操作，如下面的代码所示，以及它的好处：

```less
footer {
  div {
    float: left;
  width: ((@basic-width / 3 ) - @footer-gutter);
  }
}
```

在前面的代码中，`/`符号（除法）被用来使页脚列占可用宽度的三分之一（由`@basic-width`设置）。在代码中使用操作感觉如此自然，以至于您可能甚至没有意识到您一直在使用它们。*Less*使用正常的**顺序优先级**，您可以添加额外的括号来明确设置优先级并避免混淆。例如，在*Less*中，*3 + 3 * 3*得到*12*。因此，*(3 + 3) * 3*等于*18*，如下面的代码所示：

```less
.mixin(){
  property1: (3 + 3 * 3);
  property2: ((3 + 3) * 3);
}
.class {
.mixin;
}
```

这段代码将编译成以下代码：

```less
.class {
  property1: 12;
  property2: 18;
}
```

*Less*操作也可以用于颜色处理，可以对不同单位的值和颜色进行操作，如下面的代码所示：

```less
@color: yellow;
.mixin(){
  property1: (100px * 4);
  property2: (6% * 1px);
  property3: (#ffffff - #111111);
  property4: (@color / 10%)
}
.class {
.mixin;
}
```

这段代码将编译成以下代码：

```less
.class {
  property1: 400px;
  property2: 6%;
  property3: #eeeeee;
  property4: #1a1a00;
}
```

# &符号

`&`符号在*Less*中扮演着特殊而重要的角色。它指的是当前选择器的父级，您可以使用它来颠倒嵌套顺序，扩展或合并类。您将看到下面的示例将告诉您比千言万语还要多的内容：

```less
.class1
{
  .class2{
    property: 5;
  }
}

.class1
{
  .class2 & {
    property: 5;
  }
}
```

这段代码将编译成以下代码：

```less
.class1 .class2 {
  property: 5;
}
.class2 .class1 {
  property: 5;
}
```

您可以看到当您在`.class2`后使用`&`符号时，它变成了`.class1`的父级。`&`符号也可以用来引用超出 mixin 范围的嵌套。

`&`符号也可以用来嵌套和附加**伪类**到一个类。稍后，您将看到您还可以用它来附加类。一个简单的例子是为链接添加一个由鼠标悬停触发的`:hover`伪类，如下面的代码所示：

```less
.hyperlink{
  color: blue;
  &:hover {
    color: red;
  }
}
```

这段代码可以编译成以下代码：

```less
.hyperlink {
  color: blue;
}
.hyperlink:hover {
  color: red;
}
```

现在，在文本编辑器中打开`less/mixins.less`，找到**clearfix mixin**。clearfix mixin 使用`&`符号将`:hover`、`:after`和`:before`伪类附加到您的元素上，如下面的代码所示：

```less
.clearfix() {
  &:before,
  &:after {
    content: " "; /* 1 */
    display: table; /* 2 */
  }
  &:after {
    clear: both;
  }
}
```

有了关于`&`符号的这些新知识，您现在可以轻松理解如何通过`:hover`和`:active`（`.active`）状态扩展示例导航菜单，下面的代码显示了您的扩展代码将是什么样子：

```less
.nav {
    li {
      a {
        text-decoration: none;
        color: @menu-font-color;
        &:hover {
          color:@menu-hover-font-color;
          background-color:@menu-hover-background-color;
        }

      width:100%;
      display: block;
      padding: 10px 0 10px 10px;
      border: 1px solid @menu-border-color;
      margin-top: -1px;// prevent double border      
    }
    &.active {
      a {
        color:@menu-active-font-color;
        background-color:@menu-active-background-color;
      }
    }
    &:first-child a {
      border-radius: 15px 15px 0 0;
    }
    &:last-child a{
      border-radius: 0 0 15px 15px;
    }

  }

  list-style: none outside none;
  padding:0;
}
```

在浏览器中打开`http://localhost/indexnav.html`以检查前面语法的结果。

`extend`伪类是*Less*伪类，使用与 CSS 伪类相同的语法。`extend`伪类将选择器添加到**扩展选择器**列表中。将选择器添加到不同类的选择器列表中，使选择器具有与扩展类相同的属性。还记得之前示例中的`.hyperlink`类吗？如果您扩展此类，那么两个类将具有相同的属性：

```less
.hyperlink{
  color: blue;
  &:hover {
    color: red;
  }
}
       .other-hyperlink:extend(.hyperlink){};
```

此代码将编译为以下代码：

```less
.hyperlink,
.other-hyperlink {
  color: blue;
}
.hyperlink:hover {
  color: red;
}
```

请注意，嵌套的`:hover`伪类未在`.other-hyperlink`中涵盖。要扩展包括扩展样式的嵌套元素的类，必须在选择器末尾添加`all`关键字，如下面的代码所示：

```less
.other-hyperlink:extend(.hyperlink all){};
```

现在，此代码将编译为以下代码：

```less
.hyperlink,

.other-hyperlink {

  color: blue;

}

.hyperlink:hover,

.other-hyperlink:hover {

  color: red;

}
```

在嵌套`：extend`语句的情况下，您必须使用`&`符号作为引用，如下面的代码所示：

```less
.other-hyperlink{
  &:extend(.hyperlink);
};
```

尽管`extend`语法模仿伪类的语法，但只要在选择器末尾添加`:extend`，两者就可以结合使用，如下面的代码所示：

```less
.other-hyperlink:hover:extend(.hyperlink){};
```

# 属性合并

**属性合并**在属性接受**逗号分隔值**（**CSV**）时非常有用。您将在 CSS3 中大多数情况下找到这种类型的属性，其中边框、背景和过渡接受 CSV 列表。但是，您还会发现老式的`font-family`参数接受由逗号分隔的字体名称列表。通过在名称后添加加号（`+`）来合并属性，如下面的代码所示：

```less
.alternative-font()
{
  font-family+: Georgia,Serif;
}
.font()
{
  font-family+: Arial;
  .alternative-font;
}
body {
.font;
}
```

此代码将编译为以下代码：

```less
body {
  font-family: Arial, Georgia,Serif;
}
```

# 内置函数

*Less*支持许多方便的**内置函数**。内置函数可用于在混合中操作*Less*值并设置变量的值。最后但同样重要的是，它们还可以用于**守卫表达式**。您可以通过访问[`lesscss.org/functions/`](http://lesscss.org/functions/)找到完整的函数列表。

在本章中，您不会找到所有这些函数，但您将学习如何使用来自所有不同组的函数。函数可以根据其输入和输出类型进行分组，其中这些类型是数学函数、颜色函数、列表函数、字符串函数和类型函数。还有一小部分函数无法使用前述分类进行分组。

## JavaScript

*Less*函数首先映射本机**JavaScript 函数**和代码，因为*Less*是用 JavaScript 编写的。目前，JavaScript 表达式仍然可以在*Less*代码中作为值进行评估，但这种能力可能会在将来的版本中被移除。在您的*Less*代码中使用 JavaScript 代码时，应该将 JavaScript 代码包装在反引号之间，如下面的代码所示：

```less
@max: ~"`Math.max(10,100)+'px'`";
p {
  width: @max;
}
```

包含 JavaScript 代码的*Less*代码将编译为以下 CSS 代码：

```less
p {

  width: 100px;

}
```

尽管可能，但尽量避免在代码中使用 JavaScript。用其他语言编写的**Less 编译器**无法评估此代码，因此您的代码不具备可移植性，并且更难以维护。

如果您的目的没有内置的*Less*函数可用，尝试用*Less*代码编写您需要的等效代码。自 1.6 版本以来，有一个`max()`函数，以前可以使用以下代码：

```less
.max(@a,@b) when (@a>=@b){@max:@a;}
.max(@a,@b) when (@b>@a){@max:@b;}
```

特别是在使用 JavaScript 环境时要小心在您的*Less*代码中。此外，诸如`document.body.height`之类的值在您编译的无状态 CSS 中毫无意义。

## 列表函数

`Extract()`和`length()`是用于获取 CSV 列表的值和长度的函数。这些函数可以一起用于作为数组在 CSV 列表上进行**迭代**。

还记得在第二章中用于设置侧边栏导航中的链接前景图像的循环吗？在这里，您将使用相同的技术在链接之前添加图标。

此示例使用了来自 Font Awesome 的图标。Font Awesome 是一种使用可缩放矢量图标的图标字体，可以通过 CSS 进行操作。图标可以很容易地通过 CSS 进行缩放或着色；此外，加载字体只需要一个 HTTP 请求来获取所有图标。请参阅[`fontawesome.io/`](http://fontawesome.io/)获取更多信息。

要使用 Font Awesome，首先通过将以下代码添加到 HTML 文档的头部来引用其源：

```less
<link href="//netdna.bootstrapcdn.com/font-awesome/4.0.3/css/font-awesome.css" rel="stylesheet">
```

### 注意

Font Awesome 和其他图标字体也可以使用*Less*集成和编译到您的项目中。您将在第四章中学习如何做到这一点，*避免重复造轮子*。

在您的 HTML 中，现在可以使用以下代码行：

```less
<i class="fa fa-camera-retro"></i> fa-camera-retro
```

图标是使用 CSS 的`:before`伪类添加的，因此前面的 HTML 代码也可以通过以下*Less*代码进行样式设置，而无需使用类：

```less
i:before {
  font-family:'FontAwesome';
  content:"\f083";
}
```

### 提示

可以通过访问[`astronautweb.co/snippet/font-awesome/`](http://astronautweb.co/snippet/font-awesome/)找到 Font Awesome 图标及其 CSS 内容值的列表。

有了关于图标字体的这些信息，您可以构建一个循环，将图标添加到导航的列表项中，如下面的代码所示：

```less
@icons: "\f007","\f004","\f108","\f112","\f072","\f17c";
.add-icons-to-list(@i) when (@i > 0) {
  .add-icons-to-list((@i - 1));
  @icon_: e(extract(@icons, @i));
  li:nth-child(@{i}):before {
    font-family:'FontAwesome';
     content: "@{icon_}\00a0";
  }
}
.add-icons-to-list(length(@icons));
```

在`@icon_: e(extract(@icons, @i));`行中，`e()`是一个**字符串函数**，这个函数相当于使用`~""`进行转义。还请注意，在`content: "@{icon_}\00a0";`语句中，`\00a0`只是添加了一个额外的空格，用于将图标与链接分隔开。

`@icons` CSV 列表中的图标是随机选择的。`add-icons-to-list()` mixin 的递归调用从`.add-icons-to-list(length(@icons));`调用开始，其中`length(@icons)`返回`@icons`中的项目数。

将添加图标到列表项的循环的*Less*代码应该添加到`less/navicons.less`中。在添加代码后，打开`http://localhost/indexnavicons.html`查看结果，结果应该如下屏幕截图所示：

![列表函数](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465-03-03.jpg)

使用 Less 和 Font Awesome 构建的图标化超链接

在前面的屏幕截图中，图标列表仅用于演示目的，在实际情况下，这些图标甚至与超链接没有关联。这种关系的缺失使得很难找到任何用例。但是，凭借你们的创造力，我敢打赌你们能找到一个。请记住，CSS 仅用于演示，不能修改 HTML，因此无法使用*Less*设置链接本身。但是，可以创建超链接和已存在的图标之间的关系，如下面的代码所示：

```less
#content a[href*="linux"]:before {
  font-family:'FontAwesome';
  content: "\f17c\00a0";
}
```

在这里，`a[href*="linux"]`是一个选择器，用于选择所有`href`属性中包含`linux`单词的锚点。在将上述代码添加到`less/styles.less`后，可以在`http://localhost/index.html`上查看结果。

## 使用颜色函数

*Less*颜色函数可以分为**颜色定义**、**混合、操作**和**通道操作**的函数。

颜色是在**颜色通道**中定义的。RGB 颜色有三个通道：红色、绿色和蓝色。CSS2 使用这个 RGB 定义来声明颜色，CSS3 为颜色声明添加了新的定义。这些新的定义，如 HSL 和 HSV，实际上只是 RGB 值的转换。CSS3 颜色设置方法应该更直观和用户友好。例如，HSL 在这种情况下定义了三个通道的颜色，即色调、饱和度和亮度。*Less*具有用于不同类型颜色定义的通道操作的内置函数。*Less*还支持不同类型的颜色定义。自 CSS3 以来，您可以将颜色值声明为十六进制颜色、RGB 颜色、RGBA 颜色（带有额外 alpha 通道的 RGB 颜色，用于设置不透明度）、HSL 颜色和 HSLA 颜色（带有额外 alpha 通道的 HSL 颜色，也用于设置不透明度）。当然，您可以使用预定义的跨浏览器颜色名称。

*Less*颜色定义的编译颜色值并不总是在 CSS 代码中定义为十六进制颜色；如果可能的话，颜色定义的输出与 CSS 值匹配，如下面的代码所示：

```less
.selector {

 color1: rgb(32,143,60);

 color2: rgba(32,143,60,50%);

 color3: hsl(90, 100%, 50%);

}
```

编译后，上述*Less*代码变为以下 CSS 代码：

```less
.selector {

  color1: #208f3c;

  color2: rgba(32, 143, 60, 0.5);

  color3: #80ff00;

}
```

颜色是网站设计和样式的基本部分。颜色函数可以帮助您设计您的**调色板**并使其具有动态性。例如，它们将用于为元素赋予比背景颜色更深的边框颜色，或者为元素赋予基于单个输入颜色的对比颜色。

## `darken()`和`lighten()`函数

`darken()`和`lighten()`函数是两个颜色函数，可用于获得输入颜色的较暗或较亮的变体。您已经看到这些函数如何在第二章的示例布局中使用，*使用变量和混合*。现在，您可以在先前构建的网站导航菜单上应用这些函数。

请在文本编辑器中打开`less/variablesnav.less`，并根据以下方式定义依赖于主`@menucolor`参数的菜单变量：

```less
@menucolor: green;
@menu-background-color: white;
@menu-font-color: @menucolor;
@menu-border-color: darken(@menucolor,10%);
@menu-hover-background-color: darken(@menucolor,10%);
@menu-hover-font-color: white;
@menu-active-background-color: lighten(@menucolor,10%);
@menu-active-font-color: white;
```

完成后，通过在浏览器中打开`http://localhost/indexnav.html`来检查您的更改。现在，您可以通过仅更改`@menucolor`变量定义的颜色来修改导航的外观。您还会发现，将`@menucolor`设置为浅色，如粉红色或黄色，会使您的字体由于背景颜色和字体颜色之间的**对比度**不够高而无法阅读。高对比度在网页设计中起着重要作用。高对比度的设计有助于满足**可访问性**标准。高对比度不仅有助于视觉障碍或色盲人士，也影响正常视力的人，因为人类天生喜欢高对比度的颜色设计。这种偏好在您网站的第一印象中起着作用。

计算正确的对比度并不总是容易的。此外，在这种情况下，您不希望在更改基本颜色后不得不更改所有字体颜色。*Less*的`contrast()`函数将帮助您选择一种颜色，可以在有色背景下轻松看到。根据 WCAG 2.0（[`www.w3.org/TR/2008/REC-WCAG20-20081211/#relativeluminancedef`](http://www.w3.org/TR/2008/REC-WCAG20-20081211/#relativeluminancedef)），此函数比较**亮度**值而不是颜色的明亮度。`luma()`函数本身也是一个内置的颜色函数。

`contrast()`函数接受四个参数。第一个参数定义要与之比较的颜色；在这种特殊情况下，这是背景颜色。第二和第三个参数定义暗色和亮色，默认为黑色和白色。第四个和最后一个参数设置一个阈值。默认情况下，此阈值设置为 43%，并定义了亮度（感知亮度）。超过阈值的颜色被视为亮色，`contrast()`返回已在第二个参数中定义的暗色。

现在，重新打开`less/variablesnav.less`，并根据以下代码更改导航字体颜色：

```less
@menucolor: green;
@menu-background-color: white;
@menu-font-color: contrast(@menucolor);
@menu-border-color: darken(@menucolor,10%);
@menu-hover-background-color: darken(@menucolor,10%);
@menu-hover-font-color: contrast(@menu-hover-background-color);
@menu-active-background-color: lighten(@menucolor,10%);
@menu-active-font-color: contrast(@menu-active-background-color);
```

要查看更多效果，请将`@menucolor`变量更改为不同的颜色，如`yellow`、`pink`、`darkgreen`或`black`，并通过打开`http://localhost/indexnav.html`来观察变化。请记住，最浅的颜色是白色，最深的是黑色，因此`darken(black,10%);`或`lighten(white,10%);`不会产生任何效果。

## 颜色操作

如前所述，*Less*为您提供了许多操作颜色的功能。本书不涉及**色彩理论**，因此只处理了一些颜色操作的示例。您可以通过访问[`www.packtpub.com/article/introduction-color-theory-lighting-basics-blender`](http://www.packtpub.com/article/introduction-color-theory-lighting-basics-blender)获取更多关于色彩理论的信息。

### 颜色操作

通过`darken()`、`lighten()`和`contrast()`函数，您已经了解了一些颜色操作。其他操作包括`saturate()`、`desaturate()`、`fadein()`、`fadeout()`、`fade()`、`spin()`、`mix()`和`grayscale()`。

前面提到的函数接受一个或多个颜色值，以百分比作为输入参数，并返回一个颜色。请注意，颜色范围从白色到黑色，不会环绕。因此，无法像前面提到的那样使黑色变暗，使其变成白色。

如果颜色定义包含百分比，则操作会将其转换为输入参数的绝对百分比。因此，`darken(hsl(90, 80%, 50%), 20%)`变为`#4d8a0f`；相当于`hsl(90, 80%,30%)`而*不是*`hsl(90, 80%,10%)`。当然，您会看到相同的效果，因为您操作了定义饱和度的第二通道。例如，`desaturate(hsl(45, 65%, 40%), 50%)`编译为`#756e57;`，相当于`hsl(45, 15%, 40%)`。

`mix()`函数是颜色操作的最后一个示例。其他函数留作练习。

```less
@color: mix(blue, yellow, 50%);
.class {
color: @color;
}
```

这将再次变成以下内容：

```less
.class {
  color: #808080;
}
```

这种混合也将显示在以下图像中：

![颜色操作](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465-03-04.jpg)

如何使用`mix(blue, yellow, 50%)`来呈现蓝色和黄色的混合

## 使用 Less 进行颜色混合

颜色混合函数根据两个输入颜色计算新的颜色，其中函数对输入颜色的颜色通道应用基本操作，如减法。可用的函数，也称为混合模式，包括`multiply()`、`screen()`、`overlay()`、`softlight()`、`hardlight()`、`difference()`、`exclusion()`、`average()`和`negation()`。使用图层图像编辑器（如 Photoshop 或 GIMP）的用户将会认识到这些函数。

`difference()`函数按通道逐个通道地从第一个颜色中减去第二个颜色，如下所示：

```less
@color: difference(orange, red, 50%);
.class {
color: @color;
}
```

前面的代码将变成以下代码：

```less
.class {
  color:  #00a500;
}
```

以下图显示了橙色和红色混合的效果：

![使用 Less 进行颜色混合](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465-03-05.jpg)

使用`difference(orange, red, 50%)`来呈现橙色和红色的混合

## 类型函数

类型函数评估输入值的类型，并在类型匹配函数时返回`true`。可用的函数包括`isnumber()`、`isstring()`、`iscolor()`、`iskeyword()`、`isurl()`、`ispixel()`、`isem()`、`ispercentage()`和`isunit()`。以下代码显示了一些示例函数：

```less
isnumber("string"); // false
isnumber(1234); // true
isnumber(56px); // true
iscolor(#ff0); // true
iscolor(blue); // true
iscolor("string"); // false
ispixel(1234); // false
ispixel(56px); // true
```

类型函数在定义守卫时非常有用。请考虑以下语法：

```less
.mixin() when isprecentage(@value) {
  width: 25%;
}
.mixin() when ispixel(@value) {
  width: (@value / 4 );
}
```

`default()`函数是另一个内置函数，不属于函数类。`default()`函数可以在守卫内使用，并在没有其他 mixin 与调用者匹配时返回`true`。您可以将默认 mixin 添加到前面的 mixin 中，如下所示：

```less
.mixin() when ispercentage(@value) {
  width: 25%;
}
.mixin() when ispixel(@value) {
  width: (@value / 4 );
}
.mixin() when (default()) {
  display: none;
}
```

# box-shadow mixin

通过学习*Less*，您现在可以理解、构建和评估任何复杂的*Less*代码。为了证明这一点，请打开`less/mixins.less`，看一下 box-shadow mixin（最初发布在[lesscss.org](http://lesscss.org)上），代码如下：

```less
.box-shadow(@style, @c) when (iscolor(@c)) {
  -webkit-box-shadow: @style @c;
  -moz-box-shadow:    @style @c;
  box-shadow:         @style @c;
}
.box-shadow(@style, @alpha: 50%) when (isnumber(@alpha)) {
  .box-shadow(@style, rgba(0, 0, 0, @alpha));
}
```

要完全理解这些混合，您将需要了解 CSS3 中**box-shadow**的基础知识。box-shadow 属性接受阴影的 CSV 列表。阴影由两到四个长度值和一个颜色组成。前两个长度值描述与框的中心相关的垂直和水平偏移量。这些值是必需的，但可以设置为`0`以获得围绕框的等大小阴影。最后的值是可选的，并设置模糊半径和扩展半径。默认情况下，模糊和扩展半径都为`0`，并产生一个锐利的阴影，其中扩展半径等于模糊半径。

现在您应该能够评估这个混合。您将看到这些混合形成了一个保护。两个混合都接受两个参数。第一个参数是长度向量，如前所述；第二个是颜色或百分比。如果您回忆一下`isnumber(40%)`的调用会评估为`true`，尽管最后有百分号。调用`rgba(0, 0, 0, @alpha)`将根据`@alpha`的值给出灰色的阴影。如果您将第二个参数定义为颜色，比如`blue`或`#0000ff`，`iscolor(@c)`保护将评估为`true`，并且第一个混合将使用您定义的颜色进行编译。

# 摘要

在本章中，您使用*Less*构建了一个导航菜单。导航包含了悬停、对比颜色和图标等内容，所有这些都可以通过几个基本设置来设置。您已经学会了如何在*Less*中使用嵌套规则、混合和内置函数。在本章的结尾，您已经理解并使用了复杂的*Less*代码。所有这些新获得的知识将在下一章中非常有用。在下一章中，您将学习如何查找和构建可重用的*Less*代码。这将帮助您更快地工作并获得更好的结果。
