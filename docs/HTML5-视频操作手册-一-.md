# HTML5 视频操作手册（一）

> 原文：[`zh.annas-archive.org/md5/E8CC40620B67F5E68B6D72199B86F6A9`](https://zh.annas-archive.org/md5/E8CC40620B67F5E68B6D72199B86F6A9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

HTML5 多媒体开发食谱将向您展示如何像专业人士一样使用最新的前端 Web 技术。您将了解 HTML5 与以往所有版本的量子飞跃差异以及其重要性。无论您是经验丰富的专业人士还是完全新手，本书都为您提供了下一步的路线图。

从 HTML5 的新特性概述开始，我们迅速转向实际示例。从那里，我们继续探索，一直到最前沿的实验。关于新的 HTML5 规范有很多要了解的地方。本书审查了规范摘录，并将其与当前使用的示例相关联。本书融合了丰富的理论、实用性、代码示例、屏幕截图、商业智慧和其他资源的链接，这将使热心的开发人员一次又一次地回到这本书中。HTML5 多媒体开发食谱是最新前端 Web 开发技术的必备指南。

# 这本书涵盖了什么

在第一章，为丰富媒体应用程序进行结构化，我们将通过分析浏览器支持来开始检查 HTML5 的就绪状态。然后我们将奠定如何成功使用 HTML5 的新元素的基础。

第二章，支持内容，让我们重新思考开发人员用来创建容纳各种类型内容的通用容器的方法。

第三章，使用 CSS 进行样式设置，演示了如何使用 CSS3 来支持 HTML5。我们还将看看现代与传统浏览器中的样式设置以及预期的效果。

第四章，创建可访问体验，不是典型的 508 节的重复。相反，我们将使用一些最新的技术来支持我们的在线体验。

第五章，学会喜爱表单，我们将仔细研究新的 HTML5 输入类型。还包括分析哪些浏览器支持每种新类型。

第六章，使用 Canvas 开发丰富媒体应用程序，是整本书中最具前瞻性的章节。讨论将集中在如何为这种新型交互开发，并包括一些令人惊讶的浏览器支持统计数据。

第七章，使用 JavaScript 进行交互，充满了扩展新的 HTML5 音频和视频元素的示例。为这个做好准备！

第八章，拥抱音频和视频，我们深入探讨核心的 HTML 音频和视频体验。我们将构建自己的播放器，同时支持可访问性。

第九章，数据存储，详细介绍了 HTML5 的一个独特方面以及如何使用它。示例包括使用 JSON、SQL 和 GeoLocation。

# 你需要为这本书做好准备

这本书的要求很简单：您真正需要的只是一台连接互联网的计算机、一个网络浏览器和一个代码编辑器。耐心和幽默感也不会有害。

# 这本书适合谁

HTML5 已成为最受欢迎的新工作关键词。无论您是在找新工作还是只是想在当前组织中迈出下一步，了解如何使用这项新技术将给您带来优势。

# 约定

在本书中，您将找到一些区分不同类型信息的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码示例如下所示：“新的`<header>`通常用于存储诸如标志、公司口号和通常与骑头相关的其他类型的品牌。”

代码块设置如下：

```html
<div id="search-form">
<form role="search" method="get" id="searchform" action="http://devinsheaven.com/" >
<div>
<label for="s">Search for:</label>
<input type="text" value="" name="s" id="s" />
<input type="submit" id="searchsubmit" value="Search" />
</div>
</form>
</div>

```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```html
<body>
<header>
<hgroup>
<h1>Roxane is my name.</h1>
<h2>Developing websites is my game.</h2>
</hgroup>
</header>
<nav role="navigation">
<ul>
<li><a href="#About">About</a></li>
<li><a href="#Work">Work</a></li>
</ul>
</nav>
</body>

```

**新术语**和**重要单词**会以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的方式出现在文本中：“从 Vimeo 主菜单中选择**工具 | 嵌入此视频**。”

### 注意

警告或重要提示会显示在这样的框中。

### 提示

提示和技巧会显示为这样。


# 第一章：为丰富媒体应用程序进行结构化

在本章中，我们将涵盖：

+   设置 HTML5 测试区域

+   使用`header`标签来放置标志和网站标题

+   使用`nav`标签创建目录

+   使用`section`标签来结构化页面的区域

+   使用`aside`标签对齐图形

+   使用`aside`标签显示多个侧边栏

+   实现`footer`标签

+   应用`outline`算法

+   在 HTML5 中创建时尚的推广页面

# 介绍

> “谁敢，谁赢。”- 未知

不要听信那些否定者：HTML5 的许多方面已经准备就绪，等待我们使用。尽管一些人可能认为，没有一个遥远的日期可以开始使用这一系列新技术。事实上，下一代网络标记并不是遥远的梦想，它已经在这里，准备探索和使用。

没有网站可以在没有至少一些简单的超文本标记语言的情况下存在。这种开放技术非常重要。如果你多年来一直在使用 HTML 来创建和发布网站和应用程序，你可能会觉得自己现在已经掌握了这种语言。你已经知道语义标记、内容、表现和行为的分离以及无障碍问题的好处。事情可能会感到有点乏味。你已经准备好迎接新的挑战了。

或者你可能是一位年轻的开发者，正在建立你的第一个网站，需要了解如何使用最新和最伟大的技术，并对未来的网络开发有所了解。

无论哪种方式，你的道路是清晰的：在你现有的 HTML 和相关技术编码能力的基础上，这本书将推动你的技能到下一个水平，并迅速让你创造出以前 HTML 无法做到的惊人的东西。

如果你感到自满，请继续阅读。事实上，现在是成为网络开发人员最激动人心的时刻。更丰富的界面、互联网的普及以及移动设备的兴起正是你正在寻找的新挑战。

幸运的是，HTML5、大量的层叠样式表和一点 JavaScript 可以迎接这些新挑战。网络开发的最新创新使得这是在线出版商的新黄金时代。对于我们许多人来说，经历了一段低迷之后，我们现在迅速发现，为网络开发是有趣的！毕竟，HTML5 代表了进化，而不是革命。

在几个成功的知名客户项目中，我使用了一种自定义的 JavaScript 方法来部署 HTML5 的方面，并仍然支持包括微软 Internet Explorer 6 在内的旧版浏览器。

在这些食谱中，你将学习这种强大的方法以及如何在真实的、实时的生产环境中使用许多仍在发展中的 HTML5 标准和功能。

当我们使用 HTML5 开发时，我们将语义命名的基本原则（将事物命名为它们是什么，而不是它们看起来是什么）提升到一个全新的水平。这是使 HTML5 与其所有前身不同的关键因素。在本书的过程中，你会发现自己重新思考和优化许多你的代码命名约定。

尽管来自 Web 超文本应用技术工作组（WHATWG）的 HTML5 建议推荐计划要到 2022 年才全面实施，但由于前瞻性的浏览器制造商，现在就开始使用它并获得更好的语义命名、增强的可访问性等好处是完全没有问题的。

所以让我们开始吧！

在本章中，我们将向你展示如何设置你的开发环境，包括使用适当的`DOCTYPE`和要使用的浏览器，以及如何使用特定的新标签，包括：

+   `<header>` - 一组介绍性或导航性的辅助工具

+   `<nav>` - 用于导航列表

+   `<section>` - 用于区分页面的不同区域

+   `<aside>` - 用于对齐特定元素

+   `<footer>` - 页面或部分的底部信息

最后，我们将把所有这些元素放在一起，用 HTML5 创建一个时尚的专业宣传页面。

# 设置 HTML5 测试区域

如果我们要使用 HTML5 构建新的令人兴奋的项目，我们需要为成功做好准备。毕竟，我们希望确保我们构建的内容对我们自己和我们的客户来说能够以可预测的方式显示和行为。让我们用一个代码编辑器和至少一个网络浏览器来构建一个测试套件。

## 准备工作

我们需要一些东西才能开始。至少，我们都需要一个代码编辑器和一个浏览器来查看我们的工作。经验丰富的专业人士知道我们确实需要一系列反映我们受众使用情况的浏览器。我们想要以他们的方式看到事物。我们*需要*以他们的方式看到事物。

## 如何做...

许多网络开发人员说他们能够使用像 Notepad（适用于 Microsoft Windows）或 TextEdit（适用于 Mac OSX）这样的纯文本软件编写代码。这很好，但尽管有这样的吹嘘，我们不知道有哪个网络开发人员实际上每天都这样工作。

大多数人使用一些开发应用程序，比如 Adobe Dreamweaver（适用于 Windows 和 Mac）或 Aptana Studio（适用于 Windows、Mac 和 Linux）或 Coda（我个人偏好，只适用于 Mac）或 TextMate（同样只适用于 Mac）。

让我们开始下载至少一个这些应用程序：

+   Adobe Dreamweaver: [`adobe.com/products/dreamweaver`](http://adobe.com/products/dreamweaver)

+   Aptana Studio: [`aptana.com`](http://aptana.com)

+   Coda: [`panic.com/coda`](http://panic.com/coda)

+   TextMate: [`macromates.com`](http://macromates.com)

这里显示了最常见的网络编辑器的应用程序图标：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_01_01.jpg)

## 它是如何工作的...

为了让我们创建的代码正确显示，我们需要一个网络浏览器——可能不止一个。并非所有的浏览器都是一样的。正如我们将看到的，一些浏览器需要一些额外的帮助来显示一些 HTML5 标签。以下是我们至少会使用的浏览器。

如果你在 Mac 上使用 OSX，Apple Safari 已经安装。如果你是微软 Windows 用户，Internet Explorer 已经安装。

如果你使用 iPhone 或 Android 等现代移动设备进行开发，它已经安装了至少一个浏览器。

由于我们将在桌面上进行实际编码，让我们从以下位置下载一些浏览器开始。注意：Microsoft Internet Explorer 仅适用于 PC。

+   Apple Safari: [`apple.com/safari`](http://apple.com/safari)

+   Google Chrome: [`google.com/chrome`](http://google.com/chrome)

+   Mozilla Firefox: [`getfirefox.com`](http://getfirefox.com)

+   Microsoft Internet Explorer: [`windows.microsoft.com/en-US/windows/products/internet-explorer`](http://windows.microsoft.com/en-US/windows/products/internet-explorer)

这里显示了最常见的桌面网络浏览器的应用程序图标：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_01_02.jpg)

## 还有更多...

为什么我们需要不止一个浏览器？有两个原因：

+   这些应用程序有不同的渲染引擎，并以稍微不同的方式解释我们的代码。这意味着无论我们的代码多么有效或出于良好意图，有时浏览器的行为是不可预测的。我们必须为此做好计划并保持灵活。

+   我们无法总是预测我们的受众会安装哪个浏览器以及在哪个设备上，所以作为开发者，我们需要超前一步来最好地满足他们的需求以及我们自己的需求。

### WebKit 渲染引擎

幸运的是，Safari 和 Chrome 使用相同的 WebKit 渲染引擎。iPhone 和 iPad 的移动 Safari，以及 Android 移动设备的网络浏览器，都使用 WebKit 渲染引擎的一个版本。

### Gecko 渲染引擎

Firefox 及其移动版本都使用 Gecko 渲染引擎。

### Trident 渲染引擎

我只是想告诉你我的感受。必须让你明白：微软已经多次改变和更新了它的 Internet Explorer 渲染引擎 Trident，这让我们作为开发人员的生活相当困难。我们经常感觉自己在瞄准一个移动的目标。随着 Internet Explorer 10 的到来，似乎这种情况不会很快改变。

## 另请参见

Camino（仅限 Mac）和 Opera（适用于 Microsoft Windows，Apple OSX，Linux 和移动设备）都是出色的替代浏览器，支持 HTML5 的许多功能。考虑将这些浏览器添加到您的测试套件中。

+   Camino: [`caminobrowser.org`](http://caminobrowser.org)

+   Opera: [`opera.com`](http://opera.com)

这里显示了 Camino 和 Opera 网页浏览器的应用程序图标：

![另请参见测试区，HTML5Trident 渲染引擎](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_01_03.jpg)

既然我们有了开发环境和不止一个浏览器，让我们创建一些代码吧！

### 提示

**渐进增强**

我们将使用渐进增强的概念构建我们的页面，这意味着从普通的 HTML 标记开始，然后添加 CSS 进行呈现，最后添加一点 JavaScript 进行行为。我们听到的最好的类比之一是，基本的 HTML 就像黑白电视。添加 CSS 就像添加颜色，添加 JavaScript 有点像添加高清。

# 使用标题标签用于标识和网站标题

> “`<header>`元素表示一组介绍性或导航性的辅助信息。`<header>`元素通常包含该部分的标题（`<h1> - <h6>`元素或`<hgroup>`元素），但这不是必需的。`<header>`元素还可以用于包装部分的目录、搜索表单或任何相关的标识。” - WHATWG 的 HTML5 草案标准 - [`whatwg.org/html5`](http://whatwg.org/html5)

## 准备就绪

你会注意到 HTML5 的第一件事是`DOCTYPE`。如果你是网页开发的老手，你会很高兴地知道我们不再需要使用这样冗长复杂的`DOCTYPE`了：

`<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">`

或者：

`<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">`

或者：

`<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Frameset//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-frameset.dtd">`

HTML5 消除了 Strict，Transitional 和 Frameset `DOCTYPEs`的需要。实际上，它完全消除了`DOCTYPES`的需要。没有`DOCTYPES`，较旧版本的 Internet Explorer 会进入 Quirks 模式，没有人想要那样。相反，我们可以使用简单的：

`<!DOCTYPE html>`

最后，一个`DOCTYPE`统治它们所有。

让我们从一个基本的页面结构开始，这是我们都应该熟悉的：

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title></title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
</body>
</html>

```

引号是为了创建有效的 XHTML 而必需的，但由于 HTML5 不与 XML 耦合，这些在 HTML5 规范中是可选的。然而，作者建议尽可能使用引号引用属性。

敏锐的眼睛还会注意到`<meta name="viewport" content="width=device-width, initial-scale=1.0">`。目前它对我们来说还没有太大作用，但在移动设备上预览您的工作时将是至关重要的。

关闭标签也是可选的。虽然这是一个好习惯，但您应该权衡它是否值得开发时间和增加的页面权重。

你还会注意到一个条件注释，检查用户是否在使用 Internet Explorer。如果是的话，我们告诉浏览器执行 Remy Sharp 的"HTML5 Shiv"脚本，简单地告诉 IE 要表现良好：`<article>, <aside>, <audio>, <canvas>, <command>, <datalist>, <details>, <embed>, <figcaption>, <figure>, <footer>, <header>, <hgroup>, <keygen>, <mark>, <meter>, <nav>, <output>, <progress>, <rp>, <ruby>, <section>, <source>, <summary>, <time>, <video>, <wbr>`。

该死的 Internet Explorer。它缺乏纪律。

## 如何做...

我们将为一位名叫 Roxane 的年轻开发人员创建一个单页专业网页作品集。假设 Roxane 是一位有才华的网页开发人员，就像你一样。她值得拥有一个与她的才华相称的专业单页作品集网站，你也一样。请随意在以下示例中用你的信息替换她的信息。

让我们首先使用第一个新的`<header>`标签来定义我们整个页面的最顶部区域。

顺便说一句，我们将在新的`<header>`标签中使用新的`<hgroup>`标签来包含标题。

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Roxane</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<header>
<hgroup>
<h1>Roxane is my name.</h1>
<h2>Developing websites is my game.</h2>
</hgroup>
</header>
</body>
</html>

```

> "`<hgroup>`元素表示一个部分的标题。当标题具有多个级别时，例如副标题、替代标题或标语时，该元素用于对一组`<h1> - <h6>`元素进行分组。" - WHATWG 的 HTML5 草案标准 - [`whatwg.org/html5`](http://whatwg.org/html5)

## 工作原理...

新的`<header>`通常用于存储诸如标志、公司口号和通常与页眉相关的其他类型的品牌。它通常是 HTML5 页面上的第一个块级元素，并且通常用于像`<h1>, <h2>`等标题。结果是一个更具语义的代码基础，可以构建更多内容。

## 还有更多...

在 HTML5 之前，浏览器软件以及谷歌、雅虎和必应等主要搜索引擎都会给所有的`<div>`赋予相同的权重。但是我们知道，`<div id="header">`的意图并不像新的`<header>`那样明显。相反，HTML5 规范更倾向于用事物的实际*名称*来命名事物。现在，HTML5 认识到并不是所有的`<div>`都是一样的，它用更语义化的术语来替换一些`<div>`，比如新的`<header>`、`<nav>`和`<footer>`，以获得更多的数据丰富性。

### 在其他地方使用<header>

有趣的是，页眉不是唯一可以使用新的`<header>`标签的地方。在 HTML5 中，将新的`<header>`标签放在几乎任何块级元素内也是完全可以接受的。

### 内容，而不是位置

新的`<header>`标签通常出现在网页顶部，但并不总是必须出现在那里。请记住，从语义上讲，新的`<header>`标签是由其内容而不是其位置来定义的。

### 语义化命名

语义化的命名也使我们作为网页开发人员的工作更加容易。像新的`<footer>`标签这样的东西的意图，如果像模糊的`<div id="belowleft">`那样标记，就会更加明显。

### 提示

**语义化命名的关键**

以事物的本质来命名，而不是它们的外观。

## 另请参阅

我们将继续参考 WHATWG 的 HTML5 草案标准，网址为[`whatwg.org/specs/web-apps/current-work/multipage`](http://whatwg.org/specs/web-apps/current-work/multipage)，因为它是 HTML5 演变的重要指南。

# 使用 nav 标签创建目录

> "`<nav>`元素表示一个导航部分，只有由主要导航块组成的部分才适合使用`<nav>`元素。" - WHATWG 的 HTML5 草案标准 - [`whatwg.org/html5`](http://whatwg.org/html5)

就像新的`<header>`标签取代了过时的命名约定`<div id="header">`一样，我们也可以用简单的新的`<nav>`标签来取代`<div id="nav">`。这样更有意义，不是吗？我们也这么认为。

## 准备工作

我们将添加主要导航栏，就像我们经常在网页上看到的那样。这使用户可以轻松地从页面到页面，或者在这种情况下，从同一页面到另一页面。Roxane 想要展示她的个人简历信息、工作样本和联系方式，所以我们将使用这些作为我们的锚点。

## 如何做...

让我们使用两个最典型的元素来创建我们的导航栏：

1.  一个无序列表

1.  附带的超文本链接

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Roxane</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<header>
<hgroup>
<h1>Roxane is my name.</h1>
<h2>Developing websites is my game.</h2>
</hgroup>
</header>
<nav>
<ul>
<li><a href="#About">About</a></li>
<li><a href="#Work">Work</a></li>
<li><a href="#Contact">Contact</a></li>
</ul>
</nav>
</body>
</html>

```

## 工作原理...

以前，我们可能会使用类似`<div id="nav">`这样的东西来存储我们的导航列表。但是在 HTML5 中，新的`<nav>`标签就足够了。

当我们应用 CSS 时，我们会浮动这些列表项，并使它们看起来更像传统的网页导航栏。

## 还有更多...

更语义化地命名事物的美妙之处在于，现在我们页面的部分确实做到了我们认为它们应该做的事情——`<header>`包含标题信息，`<nav>`包含导航辅助信息，等等。避免混淆。

### 在其他地方使用`<nav>`

像`<header>`，`<nav>`可以出现在页面的多个位置。

### 更语义化=更好

还要记住，更语义化的命名通常会导致更短、更精简的代码。毕竟，`<nav>`肯定比常见的`<div id="nav">`更短。而且对人类和机器来说更有意义。这意味着我们需要写的东西更少，这节省了我们的时间。这也意味着浏览器需要解释和显示的代码更少，这节省了下载和渲染时间。它还为内容赋予了意义和结构，类似于大纲为研究论文赋予了意义和结构。每个人都受益。

### 仍在发展

最初，新的`<nav>`元素只用于“主要”导航块。然而，HTML5 的主要推动者 Ian Hickson 更新了规范，改为“重要”导航块。

## 另请参阅

由于它仍在不断发展，鼓励您为 HTML5 的发展做出贡献，帮助塑造这种语言。加入 WHATWG 的`<help@whatwg.org>`邮件列表，提出建议和提问。注册说明请参见：[`whatwg.org/mailing-list#help`](http://whatwg.org/mailing-list#help)。

# 使用 section 标签来结构化页面的区域

> “`<section>`元素表示一个通用的文档内容块或应用程序块。在这种情况下，`<section>`是内容的主题分组，通常带有一个标题。”- WHATWG 的 HTML5 草案标准 - http://whatwg.org/html5

## 准备工作

让我们为 Roxane 的单页面作品集网站的每个主要区域添加新的`<section>`标签。这些`<section>`将被用作容器，每个都有一个标题和通用内容，其中包含她的个人简介信息、作品示例和联系方式。

## 如何做...

使用新的`<section>`标签可能会有些棘手。有一些它不是的东西，但只有一些它是的东西。

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Roxane</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<header>
<hgroup>
<h1>Roxane is my name.</h1>
<h2>Developing websites is my game.</h2>
</hgroup>
</header>
<nav>
<ul>
<li><a href="#About">About</a></li>
<li><a href="#Work">Work</a></li>
<li><a href="#Contact">Contact</a></li>
</ul>
</nav>
<section id="About">
<h3>About</h3>
<p>I'm a front-end developer who's really passionate about making ideas into simply dashing websites.</p>
<p>I love practical, clean design, web standards give me joyful chills, and good usability tickles the butterflies in my stomach.</p>
</section>
<section id="Work">
<h3>Work</h3>
<p>sample 1</p>
<p>sample 2</p>
<p>sample 3</p>
</section>
<section id="Contact">
<h3>Contact</h3>
<p>email</p>
<p>phone</p>
<p>address</p>
</section>
</body>
</html>

```

## 如何做...

我们使用新的`<section>`标签不是作为`<div>`的通用替代，而是以语义上正确的方式作为一个相关的分组，通常包含一个标题。

## 还有更多...

如果内容分组没有关联，那么它可能不应该是一个`<section>`。考虑使用`<div>`代替。

### Section 不等于 div

记住：如果没有`<header>`，那可能就不需要`<section>`。使用`<section>`对内容进行分组，但对于纯粹出于样式原因对项目进行分组时使用`<div>`。

### 部分指南

仍然不确定是否使用`<section>`是正确的标签？请记住以下准则：

+   您是单纯用于样式或脚本吗？那就是一个`<div>`。

+   如果有其他更合适的标签，请使用它。

+   只有在内容开头有一个标题时才使用它。

### 仍在发展

HTML5 是一个不断发展的标准集。WHATWG 最新的指导建议：

> “鼓励作者在有意义地对元素的内容进行合成时，使用`<article>`元素而不是`<section>`元素。”

发布关于页面？那可能是一个很好的`<section>`候选。

## 另请参阅

新的`<section>`标签也可以支持引用属性以进行引用。

# 使用 aside 标签对齐图形

> “`<aside>`元素表示页面的一个部分，其中包含与`<aside>`元素周围的内容有间接关系的内容，并且可以被视为与该内容分开。”- WHATWG 的 HTML5 草案标准 - [`whatwg.org/html5`](http://whatwg.org/html5)

## 准备工作

让我们以一种常见的方式使用新的`<aside>`标签：创建一个侧边栏，其中列出了 Roxane 最近阅读的缩略图图像。

## 如何做...

在过去，我们将图像或列表浮动到文本的右侧或左侧。这仍然有效，但现在我们可以更好地利用 HTML5 中改进的语义，通过使用新的`<aside>`标签来实现类似的视觉效果。让我们使用：

+   有序列表

+   缩略图

+   书名

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Roxane</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<header>
<hgroup>
<h1>Roxane is my name.</h1>
<h2>Developing websites is my game.</h2>
</hgroup>
</header>
<nav>
<ul>
<li><a href="#About">About</a></li>
<li><a href="#Work">Work</a></li>
<li><a href="#Contact">Contact</a></li>
</ul>
</nav>
<section id="About">
<h3>About</h3>
<p>I'm a front-end developer who's really passionate about making ideas into simply dashing websites.</p>
<p>I love practical, clean design, web standards give me joyful chills, and good usability tickles the butterflies in my stomach.</p>
</section>
<section id="Work">
<h3>Work</h3>
<p>sample 1</p>
<p>sample 2</p>
<p>sample 3</p>
</section>
<section id="Contact">
<h3>Contact</h3>
<p>email</p>
<p>phone</p>
<p>address</p>
</section>
<aside>
<h4>What I'm Reading</h4>
<ul>
<li><img src="img/2688OS_MockupCover.jpg" alt="Inkscape 0.48 Essentials for Web Designers"> Inkscape 0.48 Essentials for Web Designers</li>
<li><img src="img/0042_MockupCover_0.jpg" alt="jQuery 1.4 Reference Guide"> jQuery 1.4 Reference Guide</li>
<li><img src="img/9881OS_MockupCover.jpg" alt="Blender 2.5 Lighting and Rendering"> Blender 2.5 Lighting and Rendering</li>
<li><img src="img/9881OS_MockupCover.jpg" alt="Blender 2.5 Lighting and Rendering"> Blender 2.5 Lighting and Rendering</li>
</ul>
</aside>
</body>
</html>

```

注意：在这种情况下，ALT 标签周围需要引号以确保有效性。

## 它是如何工作的...

`<aside>`标签有效地用于放置诸如图像和文本之类的项目，这些项目通常比主要页面内容不太重要。

## 还有更多...

从语义上讲，`<aside>`类似于侧边栏。这并不一定指的是位置，而是指与内容有关的内容。

### 并非所有的<section>都是一样的

虽然`<section>`是一块相关内容，但是将`<header>, <nav>, <footer>`和`<aside>`视为`<section>`的专门类型。

### 记住的提示

内容可以在没有`<aside>`标签的情况下存在，但`<aside>`标签不能没有内容。

### 除了`<aside>`之外

`<aside>`标签的定义已经扩展，不仅包括与其相关的`<article>`的信息，还包括与网站本身相关的信息，如博客列表。

## 另请参阅

Jeremy Keith 撰写了出色的《HTML5 For Web Designers》，被认为是您需要了解新技术的最少知识。在这里找到它：[`books.alistapart.com/products/html5-for-web-designers`](http://books.alistapart.com/products/html5-for-web-designers)。

# 使用`<aside>`标签显示多个侧边栏

> "`<aside>`元素代表页面的一部分，其中包含与`<aside>`元素周围的内容有关的内容，可以被视为与该内容分开的内容。" - WHATWG 的 HTML5 草案标准 - [`whatwg.org/html5`](http://whatwg.org/html5)

## 准备工作

似乎每个博客和许多其他类型的网站都有侧边栏，其中包含各种信息。在这里，我们将使用新的`<aside>`标签为 Roxane 的单页面作品集网站添加一个额外的侧边栏。

## 如何做...

Roxane 想让人们知道她还可以在哪里联系到她，你也是。让我们使用`<aside>`标签创建一个侧边栏，并吸引人们关注她的网站：

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Roxane</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<header>
<hgroup>
<h1>Roxane is my name.</h1>
<h2>Developing websites is my game.</h2>
</hgroup>
</header>
<nav>
<ul>
<li><a href="#About">About</a></li>
<li><a href="#Work">Work</a></li>
<li><a href="#Contact">Contact</a></li>
</ul>
</nav>
<section id="About">
<h3>About</h3>
<p>I'm a front-end developer who's really passionate about making ideas into simply dashing websites.</p>
<p>I love practical, clean design, web standards give me joyful chills, and good usability tickles the butterflies in my stomach.</p>
</section>
<section id="Work">
<h3>Work</h3>
<p>sample 1</p>
<p>sample 2</p>
<p>sample 3</p>
</section>
<section id="Contact">
<h3>Contact</h3>
<p>email</p>
<p>phone</p>
<p>address</p>
</section>
<aside>
<h4>What I'm Reading</h4>
<ul>
<li><img src="img/2688OS_MockupCover.jpg" alt="Inkscape 0.48 Essentials for Web Designers"> Inkscape 0.48 Essentials for Web Designers</li>
<li><img src="img/0042_MockupCover_0.jpg" alt="jQuery 1.4 Reference Guide"> jQuery 1.4 Reference Guide</li>
<li><img src="img/9881OS_MockupCover.jpg" alt="Blender 2.5 Lighting and Rendering"> Blender 2.5 Lighting and Rendering</li>
</ul>
</aside>
<aside>
<h4>Elsewhere</h4>
<p>You can also find me at:</p>
<ul>
<li><a href="http://linkedin.com/in/">LinkedIn</a></li>
<li><a href="http://twitter.com/">Twitter</a></li>
<li><a href="http://facebook.com/">Facebook</a></li>
</ul>
</aside>
</body>
</html>

```

## 它是如何工作的...

在我们之前成功使用`<aside>`标签的基础上，我们再次使用它来对齐主要信息之后的信息。

## 还有更多...

只是因为设计需要侧边栏，并不意味着自动使用`<aside>`标签。在考虑位置之前，请仔细考虑您的内容。

### 引用适合`<aside>`

引用在新闻文章中很常见，因此是包含在`<aside>`标签中的主要候选项。

### 记住验证

我们需要在这些锚点周围添加引号以使它们有效。

## 另请参阅

Bruce Lawson 和 Remy Sharp 共同撰写了出色的*Introducing HTML5*参考资料，网址为：[`peachpit.com/store/product.aspx?isbn=0321687299`](http://peachpit.com/store/product.aspx?isbn=0321687299)

# 实施页脚标签

> "`<footer>`元素代表已完成文档或其最近祖先分段内容的页脚。" - WHATWG 的 HTML5 草案标准 - [`whatwg.org/html5`](http://whatwg.org/html5)

## 准备工作

我们都在网页上使用页脚 - 通常用于次要导航等。这包含了通常在页面底部看到的所有信息，如版权声明、隐私政策、使用条款等。与新的`<header>`标签一样，新的`<footer>`标签可以出现在多个位置。

## 如何做...

在这种情况下，我们将使用新的`<footer>`标签将 Roxane 的版权信息放在页面底部。

### 提示

这是一个可以增长的

记住：版权并不意味着您有权复制它！

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Roxane</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<header>
<hgroup>
<h1>Roxane is my name.</h1>
<h2>Developing websites is my game.</h2>
</hgroup>
</header>
<nav>
<ul>
<li><a href="#About">About</a></li>
<li><a href="#Work">Work</a></li>
<li><a href="#Contact">Contact</a></li>
</ul>
</nav>
<section id="About">
<h3>About</h3>
<p>I'm a front-end developer who's really passionate about making ideas into simply dashing websites.</p>
<p>I love practical, clean design, web standards give me joyful chills, and good usability tickles the butterflies in my stomach.</p>
</section>
<section id="Work">
<h3>Work</h3>
<p>sample 1</p>
<p>sample 2</p>
<p>sample 3</p>
</section>
<section id="Contact">
<h3>Contact</h3>
<p>email</p>
<p>phone</p>
<p>address</p>
</section>
<aside>
<h4>What I'm Reading</h4>
<ul>
<li><img src="img/2688OS_MockupCover.jpg" alt="Inkscape 0.48 Essentials for Web Designers"> Inkscape 0.48 Essentials for Web Designers</li>
<li><img src="img/0042_MockupCover_0.jpg" alt="jQuery 1.4 Reference Guide"> jQuery 1.4 Reference Guide</li>
<li><img src="img/9881OS_MockupCover.jpg" alt="Blender 2.5 Lighting and Rendering"> Blender 2.5 Lighting and Rendering</li>
<footer> tagimplementing</ul>
</aside>
<aside>
<h4>Elsewhere</h4>
<p>You can also find me at:</p>
<ul>
<li><a href="http://linkedin.com/in/">LinkedIn</a></li>
<li><a href="http://twitter.com/">Twitter</a></li>
<li><a href="http://facebook.com/">Facebook</a></li>
</ul>
</aside>
<footer>
<h5>All rights reserved. Copyright Roxane.</h5>
</footer>
</body>
</html>

```

## 它是如何工作的...

尽管这个`<footer>`位于 Roxane 的单页面作品集网站的底部，但它也可以在页面的其他位置使用，比如放在`<section>`标签的底部，用来包含作者、发布日期等信息。这样做比以前的`<div id="footer">`更灵活。在这种情况和许多其他情况下，HTML5 的新标签允许我们根据内容而不是布局的需要来放置适当的标签。

## 还有更多...

HTML5 规范建议作者信息包含在新的`<footer>`标签中，无论`<footer>`是`<section>`或`<article>`的一部分，甚至在页面底部都是如此。

### 这通常发生

绝大多数情况下，您会在文档顶部使用`<header>`标签，在底部使用`<footer>`标签，在侧边使用`<aside>`标签。

### 灵活的页脚内容

当`<footer>`元素包含整个部分时，它们代表附录、索引、长的版权声明、冗长的许可协议等内容。

### 更灵活的页脚内容

新的`<footer>`标签也可以包含作者归属、相关文档的链接、版权等信息。

## 另请参阅

Mark Pilgrim 创建了一个很棒的免费在线 HTML5 参考资料*Dive Into HTML5*，网址是：[`diveintohtml5.org`](http://diveintohtml5.org)。

# 应用大纲算法

幸运的是，HTML5 现在可以在浏览器中组装页面的大纲，因此搜索引擎以及辅助技术可以更好地理解它们。我们将使用 HTML5 大纲工具：[`gsnedders.html5.org/outliner`](http://gsnedders.html5.org/outliner)

## 准备就绪

要使用 HTML5 大纲工具，我们可以使用存储在本地计算机上的 HTML 或通过 URL 可见的代码。确保在本地保存我们一直在创建的代码，或者将其上传到一个公共可访问的 Web 服务器以进行此步骤。

## 如何做...

让我们确保将此文档保存在本地硬盘或远程服务器上。我们将访问[`gsnedders.html5.org/outliner`](http://gsnedders.html5.org/outliner)来创建我们的大纲。

使用我们之前的代码示例，我们可以生成以下代码大纲：

1.  Roxane 是我的名字。

1.  无标题部分

1.  关于

1.  工作

1.  联系方式

1.  我在读什么

1.  其他地方

1.  保留所有权。版权 Roxane。

## 它是如何工作的...

> "它是根据 DOM 树的节点遍历来定义的，按照树的顺序，每个节点在遍历期间被访问时都会被*进入*和*退出*。" - WHATWG

## 还有更多...

假设任何标题后面的内容都与该标题相关。因此，我们可以使用许多新的 HTML5 标签，如`<section>`，明确地展示相关内容的开始和结束。

### 你确定吗？

如果 HTML5 大纲工具显示"无标题部分"之类的消息，您应该重新考虑如何使用每个标签，并确保您的方法符合规范的意图。

### 一个例外

"无标题部分"的消息应该被视为警告而不是错误。虽然`<section>`和其他新的 HTML5 标签需要一个标题标签，但在`<nav>`区域没有标题标签也是完全有效的。

### 记住辅助功能

创建的大纲确保我们创建的代码符合 W3C 的标记标准，以及 WAI-ARIA 等辅助需求的高级技术。

### 提示

良好的辅助功能设计是良好的网页设计。

## 另请参阅

[`html5doctor.com`](http://html5doctor.com)网站是一个由七位思想领袖撰写的出色的互动参考资料，包括 Rich Clark、Bruce Lawson、Jack Osborne、Mike Robinson、Remy Sharp、Tom Leadbetter 和 Oli Studholme。

# 在 HTML5 中创建时尚的推广页面

我们的朋友 Roxane 的单页面作品集网站已经使用了许多新的 HTML5 元素。她准备向世界展示她是一位有远见的网页开发人员，准备应对高级项目。

## 准备就绪

我们已经通过组装单页面作品集网站的大部分内容做好了准备。虽然现在还不太时尚，但当我们在其上添加 CSS 时，这将真正地融合在一起，并且会变得和我们的想象一样时尚。

## 如何做到这一点...

到目前为止，这是我们拥有的代码。它符合万维网联盟的 HTML5 和第 508 条款的可访问性测试。这个未经样式化的代码应该可以在任何现代 Web 浏览器上轻松查看，无论是在桌面上还是移动设备上。

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Roxane</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<header>
<hgroup>
<h1>Roxane is my name.</h1>
<h2>Developing websites is my game.</h2>
</hgroup>
</header>
<nav>
<ul>
<li><a href="#About">About</a></li>
<li><a href="#Work">Work</a></li>
<li><a href="#Contact">Contact</a></li>
</ul>
</nav>
<section id="About">
<h3>About</h3>
<p>I'm a front-end developer who's really passionate about making ideas into simply dashing websites.</p>
<p>I love practical, clean design, web standards give me joyful chills, and good usability tickles the butterflies in my stomach.</p>
</section>
<section id="Work">
<h3>Work</h3>
<p>sample 1</p>
<p>sample 2</p>
<p>sample 3</p>
</section>
<section id="Contact">
<h3>Contact</h3>
<p>email</p>
<p>phone</p>
<p>address</p>
</section>
<aside>
<h4>What I'm Reading</h4>
<ul>
<li><img src="img/2688OS_MockupCover.jpg" alt="Inkscape 0.48 Essentials for Web Designers"> Inkscape 0.48 Essentials for Web Designers</li>
<li><img src="img/0042_MockupCover_0.jpg" alt="jQuery 1.4 Reference Guide"> jQuery 1.4 Reference Guide</li>
<li><img src="img/9881OS_MockupCover.jpg" alt="Blender 2.5 Lighting and Rendering"> Blender 2.5 Lighting and Rendering</li>
</ul>
</aside>
<aside>
<h4>Elsewhere</h4>
<p>You can also find me at:</p>
<ul>
<li><a href="http://linkedin.com/in/">LinkedIn</a></li>
<li><a href="http://twitter.com/">Twitter</a></li>
<li><a href="http://facebook.com/">Facebook</a></li>
</ul>
</aside>
<footer>
<h5>All rights reserved. Copyright Roxane.</h5>
</footer>
</body>
</html>

```

## 它是如何工作的...

对于开发人员或设计师来说，单页面作品集网站非常合理，因为所有信息都可以快速地展示给招聘职位的人员，比如人力资源团队或招聘人员。

## 还有更多...

这正是 Roxane 需要展示她是一个有远见的开发人员，学会运用下一代 Web 标准的专业单页面作品集网站。

### 尝试不使用 shiv

作为一个实验，在代码中关闭“HTML5 Shiv”JavaScript 引用，看看各个版本的 Internet Explorer 如何处理我们的新 HTML5 标签。

### 移动优先

在创建这个和其他网站时，请记得考虑移动显示。几乎没有理由阻止整个群体的人看到您的内容。

### IE 邪恶？

在过去的 15 年左右，我们花了很多时间和精力抨击微软的 Internet Explorer，因为它缺乏标准支持，对盒模型的解释也有 bug。即将推出的 IE10 使我们更接近一个更统一的 Web 开发世界，但我们仍然需要数年的时间才能摆脱对 IE 的诅咒。

## 另请参阅

要获取大量单页面作品集和其他网站的灵感，请访问[`onepagelove.com`](http://onepagelove.com)画廊。

未经样式化的单页面作品集在大多数主流现代桌面 Web 浏览器上的显示：

![另请参阅](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_01_04.jpg)


# 第二章：支持内容

在本章中，我们将涵盖：

+   构建博客`article`

+   使用`mark`元素突出显示文本

+   使用`time`元素

+   指定`article`的`pubdate`

+   使用`article`元素显示评论块

+   使用@font-face 动态添加字体

+   向字体添加阴影效果

+   对字体应用渐变效果

+   使用`figure`标签注释视觉元素

# 介绍

> “在网络上，一个人不应该被他的肤色所判断，而应该被他的内容所判断。”- 互联网迷因

HTML5 和以往所有版本的 HTML 之间最重要的区别之一是，在以前，我们构建了通用的`<div>`和其他这样的通用容器，而对其中的内容知之甚少。随着 HTML5 的出现，这一切都结束了。为了根据规范语义化地正确，我们需要知道内容是什么，这样我们才能用最合适的新元素标签将其包裹起来。虽然这可能意味着我们开发者需要以不同的方式思考，但新的挑战正是我们在这里的原因。在本章中，我们将通过使用 HTML5 的几个新元素来看一些例子，来看如何做到这一点。

> “在冲突的情况下，考虑用户优先于作者优先于实施者优先于规范制定者优先于理论纯度。”- 代表团的优先级

在本章中，我们将向您展示如何使用新的`<article>`元素来标记博客文章和评论，向`<article>`添加有意义的发布日期，使用新的`<mark>`元素来突出显示文本，以及如何使用新的`<figure>`元素注释视觉元素。然后，我们将转向一些使用字体替换技术对文本进行新样式处理的方法，以及向文本添加阴影和渐变。

# 构建博客文章

> “`<article>`元素代表文档、页面、应用程序或站点中的一个独立的组成部分，原则上是独立可分发或可重用的，例如在联合中。这可以是一个论坛帖子，一篇杂志或报纸文章，一篇博客条目，一个用户提交的评论，一个交互式小部件或小工具，或任何其他独立的内容项。”- WHATWG 的 HTML5 草案标准 - [`whatwg.org/html5`](http://whatwg.org/html5)

## 准备就绪

博客条目是新的`<article>`元素的完美候选对象，它专为联合内容而设计。

对于这个配方，让我们从识别博客`<article>`的主要元素开始：通常有一个标题，以标题标签的形式，博客条目本身包括几个段落，也许还有一个或多个图片，通常还包括作者的姓名和其他相关的元数据。请注意，这是所有自包含的相关内容。

## 如何做...

我们将继续使用新的 HTML5`<header>`和`<footer>`元素。标题、条目和元信息应该分别包含在它们自己独特的标签中，比如`<h2>`、多个`<p>`和新的`<footer>`。

让我们从一个与上一章非常相似的基础开始，并两次添加我们的新`<article>`元素：

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Blog Title</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<article>
<header>
<h2>Headline</h2>
</header>
<p>First paragraph</p>
<p>Second paragraph</p>
<footer>Meta information.</footer>
</article>
<article>
<header>
<h2>Headline</h2>
</header>
<p>First paragraph</p>
<p>Second paragraph</p>
<footer>Meta information.</footer>
</article>
</body>
</html>

```

### 让你的代码减肥？

准备好受惊吓了吗？想要大开眼界吗？在 HTML5 规范中，`<html>`、`<head>`和`<body>`标签（以及它们的闭合标签）现在是可选的。当然，你可以把它们留在那里，你的页面也会验证通过，但为什么我们要这样做呢？如果从之前的代码中移除它们，我们就得到了简约的：

```html
<!DOCTYPE html>
<meta charset="UTF-8">
<title>Blog Title</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<article>
<header>
<h2>Headline</h2>
</header>
<p>First paragraph</p>
<p>Second paragraph</p>
<footer>Meta information.</footer>
</article>
<article>
<header>
<h2>Headline</h2>
</header>
<p>First paragraph</p>
<p>Second paragraph</p>
<footer>Meta information.</footer>
</article>

```

不相信？将该代码通过万维网联盟的验证器运行：[`validator.w3.org`](http://validator.w3.org)，你会看到它在浏览器中正确显示。

好吧，别那么快。问题在于删除这些元素会破坏我们的屏幕阅读器代码。哦哦。第一次打击。此外，删除`<body>`标签会破坏我们为 Internet Explorer 启用的新 HTML5 JavaScript。第二次打击。你猜怎么着？你能看到它来了，对吧？是的，删除`<html>`标签会删除页面的语言。就是这样：第三次打击。

那么，让我们把这些元素加回去，好吗？

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Blog Title</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<article>
<header>
<h2>Headline</h2>
</header>
<p>First paragraph</p>
<p>Second paragraph</p>
<footer>Meta information.</footer>
</article>
<article>
<header>
<h2>Headline</h2>
</header>
<p>First paragraph</p>
<p>Second paragraph</p>
<footer>Meta information.</footer>
</article>
</body>
</html>

```

好了，这样就好多了。

## 它是如何工作的...

记住，新的`<article>`元素是一个相关信息的集合，旨在通过 RSS 或其他方式进行合成。

## 还有更多...

更丰富、更有意义的语义可能是 HTML5 最重要的目标。这对机器更好，对作者更好，最重要的是，对我们的观众更好。

### 验证作为一种辅助，而不是一种支撑

正如我们之前看到的，删除`<html>`和`<head>`和`<body>`标签会呈现一个仍然有效的页面。这就引出了验证器的有效性问题。与 XML 世界不同，HTML5 可以使用不正确的语法，但仍然可以正常呈现。

作者在可能的情况下会尽力验证他的代码。不必对验证器盲目追求，但这总是一个很好的质量控制检查。而且，您的代码越接近有效，浏览器显示您的工作的机会就越大。

### Eric Meyer 的有趣之处

作者喜欢 CSS 大师 Eric Meyer 对验证器的看法：

![Eric Meyer 的有趣之处](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_02_01.jpg)

### 在哪里找到验证器

您可以在以下位置充分利用代码验证器：

+   [`validator.nu`](http://validator.nu)

+   [`validator.w3.org`](http://validator.w3.org)

## 另请参阅

Kristina Halvorson 的书《网络内容策略》([`contentstrategy.com`](http://contentstrategy.com))自发布以来就成为了经典之作。在这本书中，明尼阿波利斯公司 Brain Traffic 的首席执行官 Halvorson 清楚地定义了如何为在线观众创建和提供有用和可用的内容的过程。

# 使用标记元素突出显示文本

> “`<mark>`元素代表文档中标记或突出显示的一段文本，用于参考目的，因为它在另一个上下文中具有相关性。当在引文或其他文本块中使用时，它表示原本不存在的但已经添加以引起读者注意的突出显示，这在原始作者编写文本块时可能并未被认为重要，但现在却受到了以前意想不到的审查。当在文档的主要文本中使用时，它表示由于其可能与用户当前活动相关而被突出显示的文档的一部分。”- WHATWG 的 HTML5 草案标准 - [`whatwg.org/html5`](http://whatwg.org/html5)

## 准备就绪

在查看搜索结果时，您经常会发现您搜索的术语被突出显示。我们现在可以使用更有意义的`<mark>`元素，而不是依赖于语义上毫无意义的标签。

## 如何做...

在这个示例中，您将看到[HTML5doctor.com](http://HTML5doctor.com)有一个如何使用新的`<mark>`元素突出显示搜索结果术语的示例。这不仅为样式提供了有用的语义钩子，也为跟踪结果的机器提供了语义钩子。

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title></title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<h1>716,000,000 search results for the query "<mark>HTML5</mark>"</h1>
<section id="search-results">
<article>
<h2><a href="http://en.wikipedia.org/wiki/HTML_5"> <mark>HTML5</mark> - Wikipedia, the free encyclopedia</a></h2>
<p><mark>HTML5</mark> is the next major revision of <mark>HTML</mark> ("hypertext markup language"), the core markup language of the World Wide Web. The WHATWG started work on the ... <a href="http://en.wikipedia.org/wiki/HTML_5"> Read more</a></p>
</article>
<article>
<h2><a href="http://dev.w3.org/html5/spec/Overview.html"> <mark>HTML5</mark></a></h2>
<p>A vocabulary and associated APIs for <mark>HTML</mark> and XHTML. Editor's Draft 16 August 2009\. Latest Published Version: http://w3.org/TR/<mark>html5</mark>/; Latest Editor's ... <a href="http://dev.w3.org/html5/spec/Overview.html"> Read more</a></p>
</article>
</section>
</body>
</html>

```

添加一个简单的样式声明，比如：

```html
<style type="text/css">
mark {background-color: yellow; font-weight: bold;}
</style>

```

在`<head>`部分帮助我们呈现这些突出显示的文本：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_02_02.jpg)

## 它是如何工作的...

新的`<mark>`元素只是简单地突出显示一个词或短语，以吸引读者的注意。要做到这一点，只需在相应的层叠样式表中指定`<mark>`为粗体、斜体或以某种方式突出显示。

## 还有更多...

当然，您可以标记和样式搜索结果页面，使用`<b>`或`<i>`甚至`<span>`标签来指示搜索是为哪个术语进行的，但是这些标签只影响呈现层。它们缺乏含义。新的`<mark>`元素可以实现相同的视觉效果，同时为您的标记添加额外的含义。事实上，新的`<mark>`元素非常有用。

### <Mark>长寿繁荣

新的`<mark>`元素的另一个很好的用途是突出显示日历选择器中的日期，正如我们经常在任何基于日期的预订系统网站上看到的[Priceline.com](http://Priceline.com)。

[Priceline.com](http://Priceline.com)在预订行程时默认突出显示当前日期。与使用语义上毫无意义的标签来实现这一点不同，新的`<mark>`元素可能是一个完美的选择。

![<Mark>长寿繁荣](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_02_03.jpg)

### 等待浏览器

在撰写本文时，新的`<mark>`元素尚未得到任何网络浏览器的全面支持。尽管额外的语义含义可能对机器读者来说并不明显，我们仍然可以将新的`<mark>`元素作为样式上的“钩子”使用，直到有一天它的含义得到各种浏览器的全面支持。

### “未来证明”是一个词吗？

请记住，HTML5 的新元素试图为我们的标记添加额外的含义。目标绝不是剥夺含义或破坏页面。有了这个想法，我们就更容易接受像新的`<mark>`元素这样的尚未被浏览器完全实现的新元素。即使它的含义机器尚未完全理解，将其添加到我们的页面中并使其“未来证明”绝对不会有害。

## 另请参阅

2001 年，Carrie Bickner 为纽约公共图书馆的分支机构准备了“纽约公共图书馆在线样式指南”（[`legacy.www.nypl.org/styleguide`](http://legacy.www.nypl.org/styleguide)），用于更新他们的网站。在这本开创性的出版物中，Bickner 通过将内容（标记）、呈现（层叠样式表）和行为（JavaScript）分开，为 Web 标准提出了理由。这本出版物在当时非常具有前瞻性，并且在许多年内都在使用中。

# 使用时间元素

> "`<time>`元素表示 24 小时制的时间，或者是普通公历日历中的精确日期，可选地包括时间和时区偏移。" - WHATWG 的 HTML5 草案标准 - [`whatwg.org/html5`](http://whatwg.org/html5)

## 准备就绪

新的`<time>`元素是显示时间或特定日期的强大方式。

## 如何做到...

在这个示例中，我们将显示对人类和机器都可读的日期和时间。让我们看看四个例子。

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title></title>
<!--[if lt IE 9]><script src=http://html5shiv.googlecode.com/svn/trunk/html5.js> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<article>
<header>
<h2>Headline</h2>
<time datetime="2010-11-29">November 29, 2010</time>
</header>
<p>First paragraph</p>
<p>Second paragraph</p>
<footer>Meta information.</footer>
</article>
<article>
<header>
<h2>Headline</h2>
<time datetime="2010-11-29">Nov. 29</time>
</header>
<p>First paragraph</p>
<p>Second paragraph</p>
<footer>Meta information.</footer>
</article>
<article>
<header>
<h2>Headline</h2>
<time datetime="2010-11-29">the date this was written</time>
</header>
<p>First paragraph</p>
<p>Second paragraph</p>
<footer>Meta information.</footer>
</article>
<article>
<header>
<h2>Headline</h2>
<time datetime="2010-11-29T11:34">the date and time this was written</time>
</header>
<p>First paragraph</p>
<p>Second paragraph</p>
<footer>Meta information.</footer>
</article>
</body>
</html>

```

## 它是如何工作的...

我们可以使用新的`<time>`元素来指示特定的日期、时间或两者兼而有之。

## 还有更多...

新的`<time>`元素指定了一个确切的时间点，而不是一个时间段。

### 奇怪的规则

新的`<time>`元素的一个有趣方面是，您不能使用公元前的日期。您也不能使用像“2010 年 11 月”这样的日期。我们指定的日期必须是一个正的、具体的日期，而不是一个相对的日期。HTML5 工作组继续解决这一看似武断的限制。

### <time>的时间将会到来

浏览器显示新的`<time>`元素，但目前并没有对其进行任何特殊处理。

### 永远记住 SEO

时间。我们为什么如此着迷？在网络上关注时间和日期的一个非常有效的原因是搜索引擎优化。SEO 曾经被视为一种只有黑帽巫师才能理解的神秘巫术，现在已经成为每个人在网上的责任。您花时间编写良好的代码，并期望作者创作值得阅读的内容。现在再进一步，确保您的目标受众实际上可以找到您花时间创建的内容。新的`<time>`元素只是搜索引擎吸引注意力到最新内容的方式之一。

## 另请参阅

新的 HTML5`<time>`元素是微格式运动的一个可能的补充。微格式承诺为我们的标记添加额外的语义含义。虽然它还不是官方标准，但微格式正在逐渐得到 Web 开发社区的接受。在[Microformats.org](http://Microformats.org)了解更多。

# 指定文章的发布日期

> "`pubdate`属性是一个布尔属性。如果指定了，它表示元素给出的日期和时间是最近祖先`<article>`元素的发布日期和时间，或者，如果元素没有祖先`<article>`元素，则是整个文档的发布日期和时间。" - WHATWG 的 HTML5 草案标准 - [`whatwg.org/html5`](http://whatwg.org/html5)

## 准备好了

当新的`<time>`元素存在于新的`<article>`元素中时，新的`pubdate`是新的`<time>`元素的属性。它允许我们在呈现发布日期和时间时更加精确。

## 如何做...

在这个配方中，我们将在上一个配方中介绍的新的`<time>`元素的基础上，添加新的可选的`pubdate`属性来显示我们的发布日期。

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title></title>
<!--[if lt IE 9]><script src=http://html5shiv.googlecode.com/svn/trunk/html5.js> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<article>
<header>
<h2>Headline</h2>
<p>Published on <time datetime="2010-11-29" pubdate> November 29, 2010</time> in the something category.</p>
</header>
<p>First paragraph</p>
<p>Second paragraph</p>
<footer></footer>
</article>
<article>
<header>
<h2>Headline</h2>
<p>Published on <time datetime="2010-11-28" pubdate> November 28, 2010</time> in the something category.</p>
</header>
<p>First paragraph</p>
<p>Second paragraph</p>
<footer></footer>
</article>
</body>
</html>

```

## 它是如何工作的...

`Pubdate`只是一个二进制变量，或者布尔属性，用来表示某事的发布时间。

## 还有更多...

您可以将`pubdate`视为向已经提供额外信息的元素`(<time>)`添加额外信息。这就像圣代上的樱桃。谁不喜欢圣代上的樱桃呢？

### 仍在等待浏览器

通过包括新元素`<mark>, <time>`和`pubdate`，我们正在变得非常前瞻性，因为没有一个浏览器完全支持它们 - *但是*。

![仍在等待浏览器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_02_04.jpg)

像 Firefox 这样的现代浏览器可以原生显示新的`<time>`元素和`pubdate`属性，无需样式。

### 额外学分

如果您想符合 XML 语法，可以将新的`pubdate`布尔属性编码为`<time datetime="2010-11-29" pubdate="pubdate">`。

### 让我们结束混淆

尽管 HTML5 仍然很新，但对于新的`pubdate`布尔属性已经存在一些混淆。有些人认为它应该根据您的计算机时钟或服务器生成发布日期。这不是它的作用。它的作用是生成一个机器可读的发布日期，无论您在其后放置什么文本，都是有用的。

## 参见

Tantek Celik 在[`favelets.com`](http://favelets.com)创建了一个非常有用的网站，其中包含各种"书签"或浏览器 JavaScript 命令。使用这些命令可以在同一个窗口中验证 HTML5、CSS 和锚点等。非常有帮助！

# 使用文章元素显示评论块

> "`<article>`元素表示文档、页面、应用程序或站点中的独立组成部分，原则上是独立可分发或可重用的，例如在联合传播中。这可以是论坛帖子、杂志或报纸文章、博客条目、用户提交的评论、交互式小部件或小工具，或任何其他独立的内容项。" - WHATWG 的 HTML5 草案标准 - [`whatwg.org/html5`](http://whatwg.org/html5)

## 准备好了

我们当然可以提出使用新的`<article>`元素来标记博客评论的理由。在这个配方中，我们将这样做。

## 如何做...

让我们使用新的`<article>`元素来标记一块博客评论。

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title></title>
<!--[if lt IE 9]><script src=http://html5shiv.googlecode.com/svn/trunk/html5.js> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<article>
<header>
<h3>Comment by: <a href="http://dalejcruse.com">Dale J Cruse</a></h3>
<p>On <time datetime="2010-11-29">November 29, 2010</time></p>
</header>
<p>The is the first paragraph of my comment</p>
<p>The is the second paragraph of my comment</p>
<footer>
<p><small>Creative Commons Attribution-ShareAlike License</small></p>
</footer>
</article>
<article>
<header>
<article element> usedsteps<h3>Comment by: <a href="http://dalejcruse.com">Dale J Cruse</a></h3>
<p>On <time datetime="2010-11-29">November 29, 2010</time></p>
</header>
<p>The is the first paragraph of my comment</p>
<p>The is the second paragraph of my comment</p>
<footer>
<p><small>Creative Commons Attribution-ShareAlike License</small></p>
</footer>
</article>
</body>
</html>

```

## 它是如何工作的...

"等一下，"你在想。"一个博客评论不是一个`<article>!"`你大喊道。别那么快，伙计。如果我们分析一下博客评论的组成部分，我们会发现与其他`<article>`相同的元素。

## 还有更多...

顺便说一句，让我们看看以前的`<footer>`中的新`<small>`元素。以前，`<small>`是一个表示小号文本的表现元素。不再是这样了！现在`<small>`已经重新定义为这样使用：

> “`<small>`元素代表所谓的‘小字体’，如法律声明和警告。” - WHATWG 的 HTML5 草案标准 - [`whatwg.org/html5`](http://whatwg.org/html5)

### 博客评论

由于博客评论及其评论源可以用于联合，更有理由使用新的`<article>`元素。

### 值得注意的是

评论。几乎每个值得一读的博客都有评论。无论是我们自己的网站还是我们自己的博客内容管理系统，我们都应该像对待博客文章本身一样细心对待评论的代码。

### 机会在你手中

[Disqus.com](http://Disqus.com)是最广泛使用的博客评论插件的在线主页。发布者可以轻松地将其整合到他们的网站中，而无需太多编程工作。那么，这对我们意味着什么呢？无论您使用 Disqus 还是其他任何评论系统，都需要有人开发那些代码，对吧？那么最好是你自己！

## 另请参阅

Josh Duck 创建了巧妙而有用的 HTML5 元素周期表，网址是：[`joshduck.com/periodic-table.html`](http://joshduck.com/periodic-table.html)。在那里，Josh 巧妙地将类似的新元素分组，如根元素、文本级语义、文档部分等等！

# 使用@font-face 动态添加字体

不久以前，我们设计师和开发人员只能选择少数“网页安全”字体来显示文本。如果我们想要以不被认为“安全”的字体显示文本，我们就会将其制作成图片。这很愚蠢，但我们别无选择。现在我们有了选择。字体终于在网页上得到了解放。

良好的排版对于任何设计都是必不可少的，而新的@font-face 功能让我们嵌入字体供浏览器使用。虽然技术上不属于 HTML5 的一部分，但这个 CSS3 属性太重要了，不容忽视。

## 做好准备

对于这个配方，让我们找一个有趣的字体，并将其嵌入为一个简单的标志。下面是一些寻找免费和付费字体的好网站的链接。例如，让我们看看作者个人作品集的早期版本，网址是[`dalejcruse.com`](http://dalejcruse.com)。

## 如何做...

在网页上显示自定义字体有几种方法，但我们将检查并使用一种能够在现代、传统甚至移动浏览器中运行的可靠方法。

让我们前往@Font-Face 生成器[`fontsquirrel.com/fontface/generator`](http://fontsquirrel.com/fontface/generator)。

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_02_05.jpg)

使用@font-face Kit 生成器向导，我们可以上传字体（这里是“League Gothic”），并确保您使用的字体已经被授权合法使用。

上传后，生成器将把您的字体转换为多种文件格式。下载所有这些文件，并保存到您希望它们显示的服务器上。所需的只是两个样式：

1.  引用@font-face 文件

1.  将新字体分配给我们想要使用的元素。

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title></title>
<!--[if lt IE 9]><script src=http://html5shiv.googlecode.com/svn/trunk/html5.js> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
@font-face {font-family: 'LeagueGothic'; src: url('fonts/league_gothic-webfont.eot'); src: local(''), url('fonts/league_gothic-webfont.woff') format('woff'), url('fonts/league_gothic-webfont.ttf') format('truetype'), url('fonts/league_gothic-webfont.svg#webfontdrbhz05x') format('svg');
h1 {font-family: 'LeagueGothic'; font-size: 124px; line-height: 124px; margin: 355px 0 -25px 0; text-transform: uppercase;}
</style>
</head>
<body>
<h1>Dale J Cruse</h1>
</body>
</html>

```

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_02_06.jpg)

然后炸药爆炸了。

## 它是如何工作的...

新的@font-face 功能允许我们在网页服务器上保存各种格式的字体文件，并使用 CSS 引用它们进行显示。这样，字体文件就成为了另一个资产，就像图片一样。

## 还有更多...

浏览器在网页上显示时使用自己专有的字体文件。通过下载和引用每种可能的格式，我们确保现代浏览器如 Firefox、Chrome 和 Safari，以及传统浏览器如 Internet Explorer 和甚至移动浏览器都能显示我们想要的字体。

### 不要偷

确保您使用的字体已经被授权在网上显示。偷东西不酷。

### 火狐浏览器提示

记得将想要使用的字体存储在与您的唯一域名相同的服务器上。一些浏览器（我在说你，Firefox）不喜欢您尝试跨域引用字体。

### Paul Irish 很棒

为了给予应有的赞扬，我们使用的 CSS 方法来调用各种本地存储的字体文件是由 Paul Irish 在他的帖子"Bulletproof @font-face Implementation Syntax"中开发的：[`paulirish.com/2009/bulletproof-font-face-implementation-syntax`](http://paulirish.com/2009/bulletproof-font-face-implementation-syntax)。

## 另请参阅

有一些很棒的资源可以在网上找到免费和付费字体，包括：

+   Fontdeck - [`fontdeck.com`](http://fontdeck.com)

+   Kernest - [`kernest.com`](http://kernest.com)

+   The League of Moveable Type - [`theleagueofmoveabletype.com`](http://theleagueofmoveabletype.com)

+   Typekit - [`typekit.com`](http://typekit.com)

+   Typotheque - [`typotheque.com/fonts`](http://typotheque.com/fonts)

+   Web Fonts - [`webfonts.fonts.com`](http://webfonts.fonts.com)

+   Webfonts.info - [`webfonts.info`](http://webfonts.info)

+   Webtype - [`webtype.com`](http://webtype.com)

# 向字体添加投影效果

很久以前，似乎网络设计师和开发人员给每个可视元素都添加了投影效果。几乎就像他们是按照投影效果的数量来获得报酬一样。幸运的是，那个时代已经过去了。今天，只有最时尚的设计师和开发人员知道要非常节制地添加投影效果。让我们看看如何只使用 CSS 来做到这一点。

## 准备工作

要开始，让我们使用之前的例子，并简单地为作者的投影效果添加一个非常微妙的投影效果，来自作者之前版本的作品集网站 [`dalejcruse.com`](http://dalejcruse.com)。

## 如何做...

在这个示例中，我们将使用一些小心的样式来为我们的一些文本添加一个有品味的投影效果。

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title></title>
<!--[if lt IE 9]><script
src=http://html5shiv.googlecode.com/svn/trunk/html5.js>
</script>[endif]-->
<meta name="viewport" content="width=device-width,
initial-scale=1.0">
<style>
@font-face {
font-family: 'LeagueGothic';
src: url('fonts/league_gothic-webfont.eot');
src: local(''), url('fonts/league_gothic-webfont.woff')
format('woff'), url('fonts/league_gothic-webfont.ttf')
format('truetype'), url('fonts/league_gothic-
webfont.svg#webfontdrbhz05x') format('svg');
}
h1 {font-family: 'LeagueGothic'; font-size: 124px;
line-height: 124px; margin: 355px 0 -25px 0;
text-transform: uppercase; text-shadow: black 1px 1px 0;}
</style>
</head>
<body>
<h1>Dale J Cruse</h1>
</body>
</html>

```

## 它是如何工作的...

text-shadow CSS 属性在现代浏览器中显示一个微妙的黑色投影效果，向右和向下各一个像素。虽然在作者的作品集网站上非常微妙，但如果我们将背景和字体颜色都设置为白色，效果会更加明显。

当背景和文本颜色都设置为白色时，我们在这里看到的只是黑色的投影效果，向右和向下各一个像素。由于 IE 不支持 text-shadow，这在该浏览器中将呈现为纯白色。这可能不是你想要的。

![它是如何工作的...字体投影效果，添加](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_02_07.jpg)

## 还有更多...

除了"黑色"这样的绝对颜色值，我们还可以使用十六进制值如"#000"，甚至是带有半透明 alpha 通道的 RGBA 值。

### 浏览器支持

像 Chrome 2+、Firefox 3.1+、Opera 9.5+ 和 Safari 1.1+ 这样的现代浏览器都支持 text-shadow CSS 属性。这首歌现在已经很老了，但可以说 Internet Explorer 不支持它。

### 伴随着巨大的力量...

尽管只使用 CSS 就能够为文本添加投影效果，但不要认为这是一种滥用的许可。我们不想回到网络上到处都是投影效果的丑陋时代。相反，要善用你的力量。

### 对所有读者的请求

为了可读性起见，考虑只将投影效果应用于标题或页眉字体。将其应用于正文文字会变得乏味和不可读。你不想成为因过度使用和滥用投影效果而臭名昭著的人。

## 另请参阅

Google 发布了 WebFont Loader 开源 JavaScript 库，以更好地控制浏览器加载网络字体的方式。查看超简单的实现方法：[`code.google.com/apis/webfonts/docs/webfont_loader.html`](http://code.google.com/apis/webfonts/docs/webfont_loader.html)。

# 将渐变效果应用于字体

让我们拿出之前的例子，并再添加一层：一个微妙的渐变效果。

## 准备工作

我们唯一需要的额外东西是一个便携式网络图形图像，我们可以通过 CSS 引用。

## 如何做...

在这个示例中，我们将添加一个 .png 图像文件，具有 alpha 透明度，以在我们的标题上创建一个时髦的渐变效果。

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title></title>
<!--[if lt IE 9]><script src=http://html5shiv.googlecode.com/svn/trunk/html5.js> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
@font-face {font-family: 'LeagueGothic'; src: url('fonts/league_gothic-webfont.eot'); src: local(''), url('fonts/league_gothic-webfont.woff') format('woff'), url('fonts/league_gothic-webfont.ttf') format('truetype'), url('fonts/league_gothic-webfont.svg#webfontdrbhz05x') format('svg');
}
h1 {font-family: 'LeagueGothic'; font-size: 124px; line-height: 124px; margin: 355px 0 -25px 0; text-transform: uppercase; text-shadow: black 1px 1px 0; position: relative;}
h1 span {background: url(gradient.png) repeat-x; display: block; height: 124px; position: absolute; width: 100%;}
</style>
</head>
<body>
<h1><span></span>Dale J Cruse</h1>
</body>
</html>

```

注意我们`<h1>`标签中额外的`<span>`。这就是我们放置图像的地方。

## 它是如何工作的...

通过简单地在文本上叠加一些透明度的图像，我们已经微妙地改变了文本的外观，使其呈现出渐变效果。

## 还有更多...

你的想象力是这种效果的唯一限制。你可以创建淡入淡出、金属效果、垂直或水平条纹，甚至斑马条纹！

### 提示

**小心**

记住：仅仅因为你可以，不代表你应该。请谨慎使用文本渐变效果。

## 另请参阅

要了解一个美丽的渐变效果覆盖在字体上的例子，请查看 Alex Clarke 关于土星的卫星土卫二的大学项目的标题：[`hagablog.co.uk/demos/enceladus/index.html`](http://hagablog.co.uk/demos/enceladus/index.html)。当你欣赏视觉设计时，不要忘记查看源代码，看看 Alex 非常详细记录的 HTML5 代码。

# 使用 figure 和 figcaption 标签注释视觉元素

> “`<figure>`元素表示一些流内容，可选地带有标题，它是自包含的，通常作为文档主流的单个单元引用。因此，该元素可用于注释插图、图表、照片、代码清单等，这些内容是从文档的主要内容中引用的，但是可以在不影响文档流的情况下，移动到主要内容之外，例如页面的侧边，专用页面或附录。” - WHATWG 的 HTML5 草案标准 - [`whatwg.org/html5`](http://whatwg.org/html5)
> 
> “元素的第一个`<figcaption>`子元素（如果有的话）表示`<figure>`元素内容的标题。如果没有子`<figcaption>`元素，则没有标题。” - WHATWG 的 HTML5 草案标准 - [`whatwg.org/html5`](http://whatwg.org/html5)

## 准备工作

你已经看过无数次了：一张图片下面有某种文本标题。通常它在页面的一侧。以前，我们只是将其标记为一张图片，下面有某种文本容器。现在，我们有更富语义的新的`<figure>`元素来处理它。让我们看看如何做到。

## 如何做...

有两种方法可以实现这个效果：

1.  没有标题

1.  带标题

首先让我们尝试没有标题的情况：

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title></title>
<!--[if lt IE 9]><script src=http://html5shiv.googlecode.com/svn/trunk/html5.js> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<figure>
<img src="img/2688OS_MockupCover.jpg" alt="Inkscape 0.48 for Web Designers">
</figure>
</body>
</html>

```

现在让我们添加标题：

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title></title>
<!--[if lt IE 9]><script src=http://html5shiv.googlecode.com/svn/trunk/html5.js>
</script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<figure>
<img src="img/2688OS_MockupCover.jpg" alt="Inkscape 0.48 for Web Designers">
<figcaption>Inkscape 0.48 for Web Designers</figcaption>
</figure>
</body>
</html>

```

为多个图像添加一个标题也很容易。注意多个`img`标签和只有一个`<figcaption>`。

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title></title>
<!--[if lt IE 9]><script src=http://html5shiv.googlecode.com/svn/trunk/html5.js> </script>[endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<figure> elementvisual elements, annotating<figure>
<img src="img/2688OS_MockupCover.jpg" alt="Inkscape 0.48 for Web Designers">
<img src="img/0042_MockupCover_0.jpg" alt="jQuery 1.4 Reference Guide">
<figcaption>Recent bestsellers from Packt Publishing</figcaption>
</figure>
</body>
</html>

```

## 它是如何工作...

一些样式使得`<figcaption>`显示在新的`<figure>`元素中的图像下方。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_02_08.jpg)

## 还有更多...

记住，新的`<figure>`元素用于你想要显示在其相应主文本旁边的内联内容。

### 分组是好的

新的`<figure>`元素可以包含文本、图像、音频、视频、插图、图表、代码清单，以及除了主要内容之外几乎任何值得被分组在一起的东西。

### 语义也很重要

带标题的内联内容在书籍、报纸和杂志中经常出现。自网络早期以来，我们一直能够做到同样的事情，但现在新的`<figure>`元素给了我们一个更有语义的“钩子”来进行样式设置，而不是诉诸于类名。

### <figure> vs <aside>

那么`<figure>`和`<aside>`之间有什么区别？我们应该使用新的`<figure>`元素来放置位置不重要的基本内容。然而，新的`<aside>`元素是用于相关但不是必要的内容。我们在挑刺吗？也许。但你是那种对细节苛刻的网页开发者，对吧？

## 另请参阅

要了解 HTML5 与所有以前版本的 HTML 有何不同的更详细描述，请参阅维基百科条目：[`en.wikipedia.org/wiki/HTML5`](http://en.wikipedia.org/wiki/HTML5)。


# 第三章：使用 CSS 进行样式设置

在本章中，我们将涵盖：

+   将元素设置为`display:block`

+   设置`nav`块元素的样式

+   使用 background-size 控制背景外观

+   使用`border-radius`添加圆角

+   包括多个背景图像

+   为图像添加阴影

+   为 Internet Explorer 浏览器设计样式

# 介绍

> “谢谢你带来的美好时光，IE6。在@Mix 上见，我们将展示 IE 天堂的一小部分。-微软的 Internet Explorer 团队”-来自[`ie6funeral.com`](http://ie6funeral.com)上线上看到的 IE6 葬礼的挽歌。

你已经接受了以不同的方式思考 HTML 的挑战。接下来，你将被挑战扩展你的层叠样式表知识。除此之外，我们还将挑战一些关于跨浏览器显示的假设。如果你——和你的客户——认为网站在每个浏览器中应该看起来一样，我们将改变一些人的想法。但如果你已经知道跨浏览器显示的谬误，你将成为帮助改变其他人想法的人。

在我们做任何这些事情之前，我们需要问自己和我们的客户一个简单的问题：网站在每个浏览器中需要看起来完全一样吗？*需要吗？*对于简洁的一字答案，请访问[`dowebsitesneedtolookexactlythesameineverybrowser.com`](http://dowebsitesneedtolookexactlythesameineverybrowser.com) 在 Chrome、Firefox、Opera 或 Safari 等现代浏览器中。

![介绍](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_01.jpg)

还要检查像 Internet Explorer 6 这样的旧版浏览器：

![介绍](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_02.jpg)

我的朋友们，这就是一个已经过时的浏览器。看着某物死去并不是很美观，是吗？

很明显，网站在不同的浏览器上显示不同。问题是：那又怎样？那有关系吗？应该吗？为什么？

我们很少有人在无菌实验室里工作，我们对我们创造的东西的显示有 100%的创造控制。甚至更少的人有时间或意愿为每个浏览器创建单独的定制体验。肯定有一个中间的方法。这里有一句作者真的很喜欢的老话：

> “真相在中间。”- Avadhoot Patwardhan

在这种情况下，事实是你将不得不与你的客户合作，无论他们是业务所有者、项目经理，还是任何付钱让你为他们创建网站的人。但是，坐视不管，听着这些人告诉我们如何做我们的工作的日子已经结束了。如果你知道有更好、更快、更有效的开发方式，你必须说出来。这是你的责任。如果你不这样做，没有人会为你说话。这对你不利，对你的客户不利，对行业也不利。不要成为那个人。

相反，你将不得不向你的客户解释为什么一些浏览器显示的东西略有不同，以及为什么这是完全可以接受的。以下是作者在实际业务情况中使用过的一些策略：

1.  向客户证明为旧版浏览器（特别是 IE6）提供支持将需要更长的时间。准备好证明为该浏览器开发可能需要你时间的四分之一。打击客户的痛处（钱包），那个人通常会让步。

1.  强调用户体验即使 IE 没有其他浏览器拥有的每个圆角或过渡效果，也可以保持完全相同。

### 提示

用户体验*始终*胜过花里胡哨的外观。

CSS 并不是 HTML5 规范的正式部分。事实上，它值得有自己的书。但在这一章中，作者将向你展示真实世界的例子，说明其他人如何使用 CSS 通过将元素显示为块级、模拟导航栏、使用多个背景图像、应用圆角以及高级样式，如添加阴影，并为 Internet Explorer 浏览器设计样式。

让我们开始吧！

# 将元素设置为 display:block

默认情况下，现代浏览器将新的 HTML5 元素分配为`display:block`。但是默认情况下，旧版浏览器和大多数版本的 Internet Explorer 会自动回退到`display:inline`。如果您之前使用过 CSS，您可以提前看到问题。我们要做的第一件事是在问题出现之前解决它。

## 做好准备

首先，让我们识别 HTML5 中的所有新元素。这些包括：

+   `<article>`

+   `<aside>`

+   `<audio>`

+   `<canvas>`

+   `<command>`

+   `<datalist>`

+   `<details>`

+   `<embed>` - 不是一个新标签，但它最终在 HTML5 中验证了

+   `<figcaption>`

+   `<figure>`

+   `<footer>`

+   `<header>`

+   `<hgroup>`

+   `<keygen>`

+   `<mark>`

+   `<meter>`

+   `<nav>`

+   `<output>`

+   `<progress>`

+   `<rp>`

+   `<rt>`

+   `<ruby>`

+   `<section>`

+   `<source>`

+   `<summary>`

+   `<time>`

+   `<video>`

+   `<wbr>`

## 如何做...

我们将从我们通常的页面框架开始，并添加一个样式，使所有这些新元素都`display:block`。

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Blog Title</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<style>
article, aside, audio, canvas, command, datalist, details, embed, figcaption, figure, footer, header, hgroup, keygen, mark, meter, nav, output, progress, rp, rt, ruby, section, source, summary, time, video, wbr {display:block;}
</style>
</head>
<body>
</body>
</html>

```

好了。这并不难。事实上，这些也可以包含在 CSS 重置文件中。

## 它是如何工作的...

使用 CSS，我们将所有新的 HTML5 元素设置为块级元素，确保更可预测的浏览器行为。

## 还有更多...

尽管现代浏览器已经将这些新的 HTML5 标签显示为块级元素，但在我们的样式表中再次声明它们为`display:block`并不会有任何问题。在这里，小心总比后悔好。

### 没有必要重复和重复和重复和重复和重复

注意：我们应该在每个页面上引用的外部样式表中包含这个简短的样式，而不是在每个页面的顶部内联显示它。最好只声明一次，让它在您网站的其余部分中生效，而不是一遍又一遍地重复。

### 只需一次样式

使用这个简单的样式声明一次，我们可以确保我们的现代、传统和移动浏览器在显示新的 HTML5 元素时行为更加可预测。

### 过去的回声

出于某种原因，一些开发人员不想学习 HTML5。你会听到他们说一些关于规范还没有准备好，在所有浏览器中还没有完全支持，以及你需要像 CSS 或 JavaScript 这样的“黑客”来使其工作的无稽之谈。这都是无稽之谈。不要理会他们的抱怨。你真正听到的是恐龙灭绝的声音。如果恐龙决心通过自己的不作为将自己灭绝，那就让它灭绝吧。只有强者才能生存。

有助于记住，进化是分阶段进行的。并非所有生物都会突然一起进化。与恐龙不同，你可以决定你是想现在、以后还是根本不想进化。你可以决定你想站在历史的哪一边。

## 另见

我们没有引发火灾。它一直在燃烧。自世界开始转动以来。杰弗里·泽尔德曼的《与糟糕的浏览器说再见》一文于 2001 年发表后，在 Web 开发世界引起了轰动。在这篇文章中，泽尔德曼，现在被广泛认为是 Web 标准运动的奠基人，激励了一代 Web 设计师和开发人员使用 CSS 进行 Web 呈现，并抛弃破损的传统浏览器。阅读这篇开创性的宣言：[`alistapart.com/articles/tohell`](http://alistapart.com/articles/tohell)。

# 样式化导航块元素

在创建 HTML5 规范时，进行了分析，并确定最常用的元素之一是`<div id="nav">`或`<div id="navigation">`。在 HTML5 中不再需要这样做。相反，我们有了语义丰富的`<nav>`。现在让我们开始为其添加样式。

## 做好准备

让我们看看[`css3maker.com`](http://css3maker.com)网站如何使用新的语义丰富的`<nav>`元素。

![准备好的<nav>元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_03.jpg)

## 如何做...

如果我们查看主页的源代码，我们会找到这段代码：

```html
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>CSS3.0 Maker | CSS3.0 Generator | CSS 3.0 Generator </title>
<link href="style/style.css" rel="stylesheet" type="text/css" />
<script type="text/javascript" src="img/CreateHTML5Elements.js"></script>
</head>
<body>
<div class="main_wrapper">
<nav> elementstyling<div id="wrapper">
<nav class="clearfix">
<ul>
<li class="frest"><a href="index.html" title="CSS 3.0 Maker" class="active">Home</a></li>
<li><a href="border-radius.html" title="Border Radius"> Border Radius</a></li>
<li><a href="css-gradient.html" title="Gradient">Gradient</a></li>
<li><a href="css3-transform.html" title="CSS 3.0 Transform">CSS Transform</a></li>
<li><a href="css3-animation.html" title="CSS 3.0 Animation">CSS Animation</a></li>
<li><a href="css3-transition.html" title="CSS 3.0 Transition">CSS Transition</a></li>
<li><a href="css-3-rgba.html" title="CSS 3.0 RGBA">RGBA</a></li>
<li><a href="text-shadow.html" title="Text Shadow">Text Shadow</a></li>
<li><a href="box-shadow.html" title="Box Shadow">Box Shadow</a></li>
<li><a href="text-rotation.html" title="Text Rotation">Text Rotation</a></li>
<li><a href="font-face.html" title="@Font Face">@Font Face</a></li>
</ul>
</nav>
</div>
</div>
</body>
</html>

```

请注意，到目前为止，HTML 标记非常简单。[`css3maker.com`](http://css3maker.com)团队创建了一个页面包装器，然后使用了新的`<nav>`元素来包含具有所有典型导航元素的无序列表。简单吧？接下来让我们关注他们是如何进行样式设置的。

```html
<style>
nav {
background: url("../images/box_bg.png") repeat scroll 0 0 transparent;
border-radius: 5px;
margin-bottom: 8px;
margin-right: 5px;
}
<nav> elementstylingnav ul {
display: block;
list-style: none outside none;
margin: 0;
padding: 0 0 0 5px;
}
nav ul li.frest {
border-left-width: 0;
}
nav ul li {
border-right: 1px solid #1D1C1C;
display: inline;
float: left;
margin: 0;
padding: 0;
}
nav ul li a {
color: #000;
display: inline;
float: left;
font-size: 13px;
height: 35px;
line-height: 35px;
padding: 0 10px;
text-shadow: 0 -1px 2px #737373;
-webkit-transition: All 0.50s ease;
-moz-transition: All 1s ease;
-o-transition: All 1s ease;
}
</style>

```

## 它是如何工作的...

新的`<nav>`元素不仅成为我们无序列表的容器，还为 Web 浏览器提供了额外的含义和可访问性增强。通过浮动`<nav>`元素并显示我们的无序列表而不带列表样式，这使我们能够水平显示我们的导航栏。

## 还有更多...

我们还看到了新的 CSS3 `transition`属性的使用。简单地说，这是一个新的浏览器鼠标悬停效果，以前只能用 Flash 或 JavaScript 实现。现在，CSS 可以改变元素的外观，当鼠标移动到它上面时。

由于`transition`属性在浏览器制造商中只有实验性支持，你会看到以单破折号为前缀的供应商特定前缀，比如：

+   `-webkit`（对 Safari 和 Chrome）

+   `-moz`（对于 Firefox）

+   `-o`（对 Opera）

此外，Internet Explorer 有自己的供应商前缀，即`-ms`。令人费解的是，Chrome 既可以处理`-webkit`前缀，也可以处理自己的`-chrome`前缀。

这些破折号只是表示浏览器制造商正在进行支持的工作。请记住，HTML5 和 CSS3 是不断发展的规范。我们现在可以开始使用它们的元素，但完全支持还没有到位。就像我们在为未来做饭一样。

### 浏览器支持

支持新的`<nav>`元素的 Web 浏览器：

![浏览器支持](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_04.jpg)

### 文本阴影很酷

在前面的代码示例中，你还会注意到对我们在上一章中深入讨论的新 CSS3 `text-shadow`属性的巧妙使用。

## 另请参阅

[`cSS3maker.com`](http://cSS3maker.com)网站是任何需要这些新 CSS 属性的浏览器特定前缀的 CSS3 开发人员的绝佳资源：

+   边框半径

+   渐变

+   CSS 变换

+   CSS 动画

+   CSS 过渡

+   RGBA

+   文本阴影

+   盒阴影

+   文本旋转

+   @font-face

# 使用 background-size 控制背景外观

使用 CSS3，我们现在有一种方法来指定背景图像的大小。我们可以用像素、宽度和高度或百分比来指定这个大小。当你把大小指定为百分比时，大小是相对于我们使用 background-origin 指定的区域的宽度或高度的。

![使用 background-size 控制背景外观](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_05.jpg)

## 准备就绪

让我们看一个真实世界的例子，[`miessociety.org`](http://miessociety.org)，这是一个由设计师 Scott Thomas 创建的 Simple Honest Work 代理机构的美丽网站，致力于保护建筑师路德维希·密斯·凡德罗的遗产。

## 如何做...

如果我们查看样式表的源代码，我们会看到作者为`body`创建了一个规则，然后指定任何使用的背景图像都会覆盖整个`body`。

作者还为每个页面指定了一个背景图像，通过给每个`body`元素附加一个`ID`。

## 它是如何工作的...

在这里，我们看到创作者们使用了一些简单的样式，包括新的`background-size`属性，来拉伸一个大的背景图像横跨整个页面，无论您的显示器大小或分辨率如何。

```html
<style>
background appearance controlbackground-size property, workingbody {
background: transparent no-repeat scroll 50% 50%;
background-repeat: no-repeat;
background-size: cover;
margin: 0px;
padding: 0px;
}
body#body_home {
background-attachment: inherit;
background-image: url(http://miessociety.org/site_media/library/ img/crownhall_index.jpg);
background-position: 50% 0%;
}
</style>

```

## 还有更多...

新的`background-size`元素通常以像素、宽度和高度或百分比来指定。在密斯·凡德罗协会网站的例子中，我们看到作者使用了术语"cover"，这使背景图像能够拉伸以"覆盖"整个画布。聪明。

### 浏览器支持

支持新的`background-size`属性的 Web 浏览器：

![浏览器支持 background-size 属性 about](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_06.jpg)

### 在 IE 中可接受

那么，当我们在不支持的浏览器中查看使用`background-size`的网站时会发生什么？在这里，我们可以看到 Internet Explorer 10 之前的版本无法拉伸背景图像，而是简单地用黑色填充了剩下的画布。这是一个完美的例子，即使在每个浏览器中看起来都不一样，但仍然提供了完全令人满意的用户体验。没有一个网站浏览者——即使是使用 IE6 的人——可以合理地抱怨他们没有按照作者的意图体验网站。

![IE 中可接受](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_07.jpg)

### Simple Scott 简直太棒了

在这一部分，我们使用了 Mies van der Rohe Society 网站的真实示例，使用了新的 CSS3 `background-size`属性，并注意到网站作者如何巧妙地适应了旧浏览器的使用。

## 另请参阅

[`html5rocks.com`](http://html5rocks.com)网站提供交互式演示、代码播放器、示例和逐步教程，以开发和磨练您的新技术技能。有趣的是，该网站是一个您可以贡献的开源项目。学习它，分享它，回报社会！

# 使用`border-radius`添加圆角

`border-radius`很可能会成为 CSS3 中最常用的新属性。由于 Web 上使用了许多按钮和包含元素的圆角，`border-radius`使得通过 CSS 轻松实现，而不是依赖于图像。以下是如何做到的。

## 准备好了

让我们来看看[`devinsheaven.com`](http://devinsheaven.com)，这是 iPhone 应用设计师和开发者 Devin Ross 的作品和著作。具体来说，我们将研究 Devin 如何设计他的搜索字段。

![准备好 border-radiusabout](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_08.jpg)

## 如何做...

查看 Devin 的代码源，我们看到简单、直接的表单标记，包括所有典型的元素：包装器、表单、标签和两个输入。

```html
<div id="search-form">
<form role="search" method="get" id="searchform" action="http://devinsheaven.com/" >
<div>
<label for="s">Search for:</label>
<input type="text" value="" name="s" id="s" />
<input type="submit" id="searchsubmit" value="Search" />
</div>
</form>
</div>

```

但是，Devin 在他的样式表中接下来做的事情实现了现代浏览器中的圆角：

```html
<style>
#navigation-bar #search-form {
background: none repeat scroll 0 0 white;
border-radius: 4px;
margin-left: 180px;
margin-top: 12px;
padding: 2px 6px;
position: absolute;
width: 250px;
}
</style>

```

## 它是如何工作的...

Devin 为搜索表单`ID`指定了四像素的`border-radius`，这样可以使其所有四个角都按相同的量变圆。也可以分别指定每个角的`border-radius`。

## 还有更多...

有趣的是，Opera 浏览器将支持新的 CSS3 `border-radius`属性，而无需浏览器特定前缀。干得好，Opera！谢谢！

### 浏览器支持

支持新的`border-radius`样式的 Web 浏览器：

![浏览器支持](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_09.jpg)

### IE 中可接受

那么，当在不支持的浏览器中查看 Devin 设计精美的网站时会发生什么？Internet Explorer 8 及更早版本简单地忽略了`border-radius`属性，并使角变成了方形。再次强调，这是完全可以接受的，但通常需要您向客户解释为什么像素完美并不总是一个现实的目标。

在 Internet Explorer 8 中查看 Devin 的天堂网站。请注意方形搜索表单边框。

![IE 中可接受](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_10.jpg)

### Devin 的天堂到 11

在这一部分，我们演示了[`devinsheaven.com`](http://devinsheaven.com)如何使用新的 CSS3 `border-radius`属性微妙地使搜索字段的角变圆。我们还看了作者对浏览器特定前缀的使用，以及作者选择如何处理像 Internet Explorer 8 及更早版本这样的旧浏览器。

## 另请参阅

要了解更多关于新的 CSS3 `border-radius`属性的出色用法，请访问[`houseofbuttons.tumblr.com`](http://houseofbuttons.tumblr.com)。它包括许多设计和开发灵感。

# 包括多个背景图像

[`benthebodyguard.com`](http://benthebodyguard.com)在 2010 年 12 月首次亮相时，引起了互联网的轰动。作者使用单页面布局讲述了一个名叫 Ben 的虚构法国保镖的互动故事。当滚动浏览这个长页面时，多个背景帮助讲述了即将发布的 iPhone 应用的故事。

## 准备好了

让我们查看[`benthebodyguard.com`](http://benthebodyguard.com)，并滚动浏览动画。

![准备就绪](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_11.jpg)

## 如何做到的...

让我们专注于源代码的一部分，看看网站作者如何利用多个背景。

```html
<!doctype html>
<html class="" lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
<title>Ben the Bodyguard. Coming soon to iPhone® and iPod touch®</title>
<meta name="author" content="Ben the Bodyguard">
<link rel="stylesheet" href="css/style.php?v=1">
</head>
<body class="index">
<div id="container">
<div id="hide-wrapper">
<header>
<img id="comingDecember" alt="Ben the Bodyguard is coming for iPhone and iPod touch in january 2011" src="img/red_stamp.png">
<h1>A Frenchman <br>protecting your secrets.<br> Yes, seriously.</h1>
<h3>Ben the Bodyguard</h3>
<p>Protecting your passwords, photos, contacts<br> and other sensitive stuff on your iPhone or iPod touch</p>
</header>
<div id="ben">
<div id="speechBubbleWrapper">
<div id='speechBubble'></div>
</div>
<div id="ben-img"></div>
</div>
<div id="hotel">
<div id="hotelanimation"></div>
</div>
<div id="bridge"></div>
<div id="train"></div>
<div id="hideBenInBeginning"></div>
<div id="city">
<div id="thief"></div>
<div id="stolen"></div>
<div id="yakuza"></div>
</div>
</div>
</div>
</body>
</html>

```

到目前为止，除了几个空的`divs`之外，没有什么特别的。这些是作者用来讲故事的多个背景图像的容器。您的容器可以包括文本、图像、视频等。

## 它是如何工作的...

通过为每个`div`指定背景图像，网站作者使用了多个 PNG 文件背景图像，以创建一个无缝交互式的在线体验。

## 还有更多...

Mighty 的朋友们创建了一系列迷你网站，以展示我们在上一章中谈到的一些新的排版可能性。Frank Chimero 在[`lostworldsfairs.com/atlantis`](http://lostworldsfairs.com/atlantis)创建了一个单页网站，它的工作方式与`http://benthebodyguard.com`网站的多个背景相似。当您滚动浏览这个长页面时，您的头像会下降到亚特兰蒂斯失落的城市。

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_12.jpg)

### 内容在哪里？

查看 Atlantis Lost Worlds Fair 迷你网站的源代码，我们看到了类似的方法，其中包含了多个空的`divs`。

```html
<!doctype html>
<html lang="en" class="no-js">
<head>
<meta charset="utf-8">
<title>Atlantis World's Fair</title>
<meta name="Author" content="Friends of Mighty">
<link rel="stylesheet" href="css/all.min.css">
</head>
<body>
<div id="back_to"><a href="http://lostworldsfairs.com">Lost World's Fairs</a></div>
<div id="header">
<div id="img_doc"></div>
<div id="img_ship"></div>
<div class="container">
<p id="txt_below">Below</p>
</div>
<div id="backwave"></div>
<div id="frontwave"></div>
</div>
<div id="tube">
<div class="tube_container">
<div id="tube_dude" class="tube_container"></div>
</div>
<div class="tube_container">
<div id="tube_overlay"></div>
<div id="tube_backtop"></div>
<div id="tube_back"></div>
<div id="tube_fronttop"></div>
<div id="tube_frontbottom"></div>
<div id="tube_front"></div>
</div>
</div>
<div id="depthfinder"><span id="depth-o-meter">0</span> <span id="txt_k">k</span> Leagues</div>
<div id="depthscale"></div>
<div id="content">
<section id="depth1">
<div class="container">
<div id="welcomesign" class="bringFront">
<header>
<h1><span id="txt_date">1962</span> <span id="txt_atlantis">Atlantis</span> <span id="txt_worldsfair">Worlds Fair</span></h1>
<p id="txt_taglines"><span id="txt_worldsfaircircle">The World's Fair</span> <span id="txt_imaginationflag">The Depths Of Imagination</span></p>
</header>
</div>
<aside id="info_1" class="dyk-right">
<div class="didyouknow">
<img src="img/dyk-info.png" alt="info" height="30" width="30"/>
<h4>Did You Know</h4>
<p>Atlantis was<br/> originally built on<br/> the floor of the<br/> sea in 722 BCE<br/> by amphibious<br/> herbivores</p>
</div>
</aside>
</div>
</section>
</div>
</body>
</html>

```

### 让我们坦率一点

Chimero 使用了与[`benthebodyguard.com`](http://benthebodyguard.com)网站类似的方法，为这些本来是空的`divs`指定了背景图像，以创建一种无缝的体验。

## 另请参阅

HTML5 中有很多新东西，就像是最好的技术圣诞节一样。通过访问[`html5test.com`](http://html5test.com)来跟踪您的浏览器支持哪些元素。通过多种浏览器访问该网站会产生令人警醒的结果。

# 为图像添加阴影

以前，像图像下方或周围的阴影这样的视觉效果只能通过使用第二个图像来实现阴影，或者将阴影本身作为图像的一部分来实现。问题在于，如果您想要调整阴影，您必须重新裁剪它。让我们看看使用 CSS3 的现代智能方法。

## 准备就绪

查看[`thebox.maxvoltar.com`](http://thebox.maxvoltar.com)上的视觉元素周围迷人而微妙的阴影。作者 Tim Van Damme 已经应用了新的 CSS3 `box-shadow`属性。

![准备就绪](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_13.jpg)

## 如何做到的...

让我们检查样式，看看 Tim 是如何实现这种美观简单的效果的：

```html
<style>
section {
background: none repeat scroll 0 0 #EAEEF1;
border: 1px solid #FFFFFF;
box-shadow: 0 2px 10px rgba(0, 0, 0, 0.5);
margin: 0 auto;
padding: 49px;
position: relative;
width: 300px;
z-index: 50;
}
</style>

```

除了其他样式之外，我们可以清楚地看到`box-shadow`属性指定了阴影的颜色和扩散距离。

## 它是如何工作的...

新的 CSS3 `box-shadow`属性的语法与`text-shadow`属性相同。也就是说，网站作者在照片周围应用了一个阴影，该阴影在右侧有两个像素，在底部有十个像素，透明度为 50%。

### 浏览器支持

支持新的`box-shadow`样式的 Web 浏览器。

![浏览器支持](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_14.jpg)

### 无知是福

不支持新的 CSS `box-shadow`属性的浏览器只会忽略该规则，不会显示阴影。外观略有改变，但用户体验不会受到影响。没有伤害，也没有犯规。

### The Box 的 Box-shadow

在本节中，我们演示了作者 Tim Van Damme 如何使用新的 CSS3 `box-shadow`属性在他的采访网站周围创建微妙的阴影效果。

## 另请参阅

在为自己的项目创建样式表时，您可以完全控制创建一个 CSS 来统治它们所有，或者为移动和/或打印机友好页面创建单独的定制体验。但是当您没有完全控制时会发生什么？那么知道我们有像[`printfriendly.com`](http://printfriendly.com)这样的工具来为我们完成这项工作就很好。

# 为 Internet Explorer 浏览器设置样式

现在作者强烈主张为现代浏览器提供最佳的 CSS3 体验，让旧版本的 IE 随心所欲。如果在旧浏览器中某个元素缺少圆角或阴影，作者并不在乎。但事实上，你的客户可能在乎。让我们打开潘多拉魔盒，谈谈如何适应过时的浏览器。

## 准备工作

我们将研究一系列特定的方法，以使 IE 在使用新的 CSS3 属性时表现正常，比如`border-radius, box-shadow`和`text-shadow`。

## Border-radius

在旧版本的 IE 中可以实现圆角。让我们访问[`htmlremix.com/css/curved-corner-border-radius-cross-browser`](http://htmlremix.com/css/curved-corner-border-radius-cross-browser)来了解如何做到这一点。在那里，我们将学习如何在样式表中包含`.htc`行为：

```html
<style>
.curved {
-moz-border-radius: 10px;
-webkit-border-radius: 10px;
behavior: url(border-radius.htc);
}
<style>

```

注意，`.htc`文件是代码膨胀，这种行为会导致你的 CSS 无法验证。

## Box-shadow

我们可以通过使用专有的滤镜来强制 IE 显示`box-shadows`：

```html
<style>
.box-shadow {
-moz-box-shadow: 2px 2px 2px #000;
-webkit-box-shadow: 2px 2px 2px #000;
filter: progid:DXImageTransform.Microsoft.Shadow(color='#000', Direction=145, Strength=3);
}
</style>

```

不幸的是，你必须调整那个滤镜才能实现阴影的方向和深浅。请注意，这个滤镜不如新的 CSS3 `box-shadow`属性强大。

## Text-shadow

似乎在 IE 9 之前的版本中使`text-shadow`生效的唯一方法是使用像[`scriptandstyle.com/submissions/text-shadow-in-ie-with-jquery-2`](http://scriptandstyle.com/submissions/text-shadow-in-ie-with-jquery-2)这样的 jQuery 插件通过 JavaScript 来实现。请注意，强制 JavaScript 执行 CSS 的工作永远不是一个好方法，这种技术只会导致代码膨胀。

## 注意

虽然在旧版本的 IE 中可能实现几种类似 CSS3 的效果，但并不推荐。每一种都需要额外的开发类型，并且可能影响浏览器性能。使用时要谨慎。

## 另请参阅

Kyle Weems 创建了一个令人捧腹的周漫画系列，讽刺了 Web 标准世界中的一切，网址是[`cssquirrel.com`](http://cssquirrel.com)。HTML5，CSS3，Twitter，可访问性以及在这些领域中具有重要影响力的人物都成了 Kyle 经常扭曲幽默感的对象。

![另请参阅](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_03_15.jpg)
