# HTML5 和 CSS 响应式 Web 设计（一）

> 原文：[`zh.annas-archive.org/md5/BF3881984EFC9B87954F91E00BDCB9A3`](https://zh.annas-archive.org/md5/BF3881984EFC9B87954F91E00BDCB9A3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

响应式网页设计提供了一个单一的解决方案，可以在手机、桌面电脑和各种设备上都呈现出色。它会自动根据用户屏幕的大小做出响应，为今天和明天的设备提供最佳的体验。

这本书涵盖了响应式网页设计的每一个重要方面。此外，它通过应用 HTML5 和 CSS3 提供的最新和最有用的技术，扩展了响应式设计方法，使设计比以往更精简和更易维护。它还解释了编写和交付代码、图像和文件的常见最佳实践方法。

如果你能理解 HTML 和 CSS，你就能构建一个响应式网页设计。

# 这本书涵盖了什么

第一章，“响应式网页设计的要点”，是对编写响应式网页设计的关键要素进行快速介绍。

第二章，“媒体查询-支持不同的视口”，涵盖了关于 CSS 媒体查询的一切：它们的功能、语法以及你可以使用它们的各种方式。

第三章，“流动布局和响应式图像”，向你展示如何编写比例布局和响应式图像，并全面探讨了 Flexbox 布局。

第四章，“HTML5 用于响应式网页设计”，涵盖了 HTML5 的所有语义元素、文本级语义和可访问性考虑。我们还介绍了如何使用 HTML5 在页面中插入视频和音频。

第五章，“CSS3-选择器、排版、颜色模式和新功能”，深入探讨了 CSS 的无限可能性：选择器、HSLA 和 RGBA 颜色、网页排版、视口相对单位等等。

第六章，“用 CSS3 创建令人惊叹的美学”，涵盖了 CSS 滤镜、框阴影、线性和径向渐变、多重背景，以及如何将背景图像定位到高分辨率设备。

第七章，“使用 SVG 实现分辨率独立性”，解释了我们在文档中使用 SVG 以及作为背景图像的一切所需，以及如何使用 JavaScript 与它们交互。

第八章，“过渡、变换和动画”，我们的 CSS 开始动起来，探讨了如何使用 CSS 进行交互和动画。

第九章，“用 HTML5 和 CSS3 征服表单”，网页表单一直很难处理，但最新的 HTML5 和 CSS3 功能使它们比以往更容易处理。

第十章，“接近响应式网页设计”，探讨了在着手进行响应式网页设计之前的基本考虑因素，并提供了一些最后一刻的智慧金点子，以帮助你在响应式探索中取得成功。

# 你需要为这本书做些什么

+   文本编辑器

+   永远绿色的浏览器

+   对平庸笑话的偏爱

# 这本书适合谁

你是在写两个网站吗：一个是为移动设备，一个是为更大的显示器？或者你已经实现了你的第一个“RWD”，但是在努力将它们整合在一起？如果是这样，那么《使用 HTML5 和 CSS3 进行响应式网页设计第二版》将为你提供一切你需要的，让你的网站更上一层楼。

你需要一些 HTML 和 CSS 知识来跟上进度，但是关于响应式设计和制作出色网站的一切你都能在这本书中找到！

# 惯例

在本书中，您将找到许多文本样式，用以区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“我们可以通过在`<head>`中添加这个片段来轻松解决之前的问题。”

代码块设置如下：

```html
img {
    max-width: 100%;
}
```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，显示在文本中，如：“最简单的情况下，您选择一个 URL，然后点击**开始测试**。”

### 注意

警告或重要说明显示在这样的框中。

### 提示

技巧和窍门显示如下。


# 第一章：响应式网页设计的基本要素

仅仅几年前，网站可以以固定宽度构建，预期所有最终用户都会获得相当一致的体验。这个固定宽度（通常为 960 像素宽或周围）对于笔记本电脑屏幕来说并不太宽，而具有大分辨率显示器的用户只是在两侧有大量的边距。

但是在 2007 年，苹果的 iPhone 引领了第一个真正可用的手机浏览体验，人们访问和互动网络的方式永远改变了。

在这本书的第一版中，曾经指出过：

> “在 2010 年 7 月至 2011 年 7 月的 12 个月内，全球移动浏览器使用率从 2.86％上升到 7.02％。”

在 2015 年中期，同一统计系统（[gs.statcounter.com](http://gs.statcounter.com)）报告称，这一数字已上升至 33.47％。作为对比，北美的移动设备占比为 25.86％。

无论从任何角度来看，移动设备的使用量都在不断增加，而与此同时，27 英寸和 30 英寸的显示器现在也很常见。现在，浏览网络的最小屏幕和最大屏幕之间的差异比以往任何时候都要大。

值得庆幸的是，对于不断扩大的浏览器和设备环境，有一个解决方案。使用 HTML5 和 CSS3 构建的响应式网页设计可以使网站在多个设备和屏幕上“只需工作”。它使网站的布局和功能能够响应其环境（屏幕大小，输入类型，设备/浏览器功能）。

此外，使用 HTML5 和 CSS3 构建的响应式网页设计可以在无需基于服务器的后端解决方案的情况下实现。

# 开始我们的探索

无论您是响应式网页设计，HTML5 还是 CSS3 的新手，还是已经很熟练，我希望这一章能够达到两个目的中的一个。

如果您已经在响应式网页设计中使用 HTML5 和 CSS3，这一章应该作为一个快速和基本的复习。或者，如果您是新手，可以将其视为一种基本的“训练营”，涵盖基本要素，以便我们都在同一页面上。

在本章结束时，我们将涵盖您需要编写完全响应式网页的所有内容。

您可能想知道其他九章为什么在这里。在本章结束时，这一点也应该显而易见。

以下是本章的内容：

+   定义响应式网页设计

+   如何设置浏览器支持级别

+   关于工具和文本编辑器的简要讨论

+   我们的第一个响应式示例：一个简单的 HTML5 页面

+   视口`meta`标签的重要性

+   如何使图像按比例缩放到其容器

+   编写 CSS3 媒体查询以创建设计断点

+   我们基本示例的不足之处

+   为什么我们的旅程才刚刚开始

# 定义响应式网页设计

术语“响应式网页设计”是由 Ethan Marcotte 于 2010 年创造的。在他的开创性的*A List Apart*文章中（[`www.alistapart.com/articles/responsive-web-design/`](http://www.alistapart.com/articles/responsive-web-design/)），他将三种现有技术（灵活的网格布局，灵活的图像/媒体和媒体查询）整合成一种统一的方法，并将其命名为响应式网页设计。

## 简而言之，响应式网页设计

响应式网页设计是以最相关的格式呈现网页内容，以适应视口和访问设备。

在其初期，典型的响应式设计是从“桌面”固定宽度设计开始构建的。然后，内容被重新排列或删除，以使设计在较小的屏幕上工作。然而，流程发展并且变得明显，从设计到内容和开发，一切都在相反的方向工作得更好；从较小的屏幕开始，逐渐扩展。

在我们开始之前，我想在继续之前讨论一些主题；浏览器支持和文本编辑器/工具。

# 设置浏览器支持级别

响应式网页设计的普及和普遍性使其比以往更容易向客户和利益相关者推销。大多数人对响应式网页设计有一些了解。一个单一的代码库可以在所有设备上完美运行的概念是一个令人信服的提议。

在开始响应式设计项目时，几乎总会出现一个问题，那就是浏览器支持的问题。由于浏览器和设备的变种如此之多，支持每一个浏览器的变种并不总是切实可行。也许时间是一个限制因素，也许是金钱。也许两者都是。

通常情况下，浏览器越老，为了与现代浏览器获得功能或美学上的平等，需要的工作和代码就越多。因此，通过分层体验并仅为更有能力的浏览器提供增强的视觉和功能，可能更有意义，也更快。

在本书的上一版中，花了一些时间来介绍如何为非常老的仅限桌面浏览器提供支持。在这一版中，我们将不再介绍。

当我在 2015 年中写这篇文章时，Internet Explorer 6、7 和 8 几乎已经消失。即使 IE 9 在全球浏览器市场上的份额只有 2.45%（IE 10 只有 1.94%，而 IE 11 正在稳步上升）。如果你别无选择，只能为 Internet Explorer 8 及以下版本开发，我对你表示同情，但我必须坦率地告诉你，这本书中你可以使用的内容将不会太多。

对于其他人来说，你应该向你的客户/资助者解释为什么为不景气的浏览器开发可能是一个错误，并且在各个方面，主要为现代浏览器和平台投入开发时间和资源是明智的财务决策。

然而，真正重要的统计数据只有你自己的。除了极端情况外，我们构建的网站应该至少在每个常见的浏览器中都是功能性的。除了基本功能外，对于任何网络项目来说，提前决定你想要完全增强体验的平台，以及你愿意让视觉/功能异常的平台。

你还会发现，从最简单的“基本水平”体验开始，并增强（一种被称为**渐进增强**的方法）比从相反的方向解决问题更容易——首先构建最终体验，然后尝试为能力较弱的平台提供后备（一种被称为**优雅降级**的方法）。

为了说明为什么提前知道这一点很重要，考虑一下，如果你不幸有 25%的网站访问者使用 Internet Explorer 9（例如），你需要考虑该浏览器支持哪些功能，并相应地调整你的解决方案。如果大量用户使用旧的移动电话平台，比如 Android 2，同样需要谨慎。你可以考虑一个“基本”体验，这将取决于项目。

如果没有合适的数据，我会应用一个简单而粗糙的逻辑来确定是否应该花时间开发特定的平台/浏览器版本：如果开发和支持浏览器 X 的成本超过了浏览器 X 上的用户创造的收入/收益；不要为浏览器 X 开发特定的解决方案。

这很少是一个你是否能够“修复”旧平台/版本的问题。问题是你是否应该。

在考虑哪些平台和浏览器版本支持哪些功能时，如果你还没有，要熟悉[`caniuse.com`](http://caniuse.com)网站。它提供了一个简单的界面，用于确定我们将在整个过程中查看的功能的浏览器支持情况。

![设置浏览器支持级别](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_01_01.jpg)

## 关于工具和文本编辑器的简短说明。

使用什么文本编辑器或 IDE 系统来构建响应式网页设计并不重要。如果最简单的文本编辑器可以让你高效地编写 HTML、CSS 和 JavaScript，那就完全没问题。同样，并没有必需的工具是必不可少的，以便让响应式网页设计顺利进行。你实际上只需要一些能让你编写 HTML、CSS 和 JavaScript 的东西。无论你偏好 Sublime Text、Vim、Coda、Visual Studio 还是记事本 - 都无关紧要。只需使用最适合你的工具。

然而，现在有更多的工具（通常是免费的）可以消除建站过程中许多手动和耗时的任务。例如，CSS 处理器（Sass、LESS、Stylus、PostCSS）可以帮助组织代码、变量、颜色处理和算术。像 PostCSS 这样的工具还可以自动完成可怕且无趣的工作，比如 CSS 供应商前缀。此外，“Linting”和验证工具可以在你工作时检查你的 HTML、JavaScript 和 CSS 代码是否符合标准，消除许多浪费时间的拼写错误或语法错误。

新的工具不断涌现，并且它们不断改进。因此，虽然我们会在进行中提到一些相关和有益的工具，但要知道可能会有更好的东西即将出现。因此，在我们的示例中，我们不会依赖于除基于标准的 HTML 和 CSS 之外的任何东西。然而，你应该尽可能使用任何工具来快速可靠地生成你的前端代码。

# 我们的第一个响应式示例

在第一段中，我承诺到本章结束时，你将知道构建完全响应式网页所需的一切。到目前为止，我只是在围绕手头的问题进行讨论。是时候付诸行动了。

### 注意

**代码示例**

你可以通过访问[rwd.education/download.zip](http://rwd.education/download.zip)或通过 GitHub [`github.com/benfrain/rwd`](https://github.com/benfrain/rwd)来下载本书中的所有代码示例。值得知道的是，在整个章节中构建的个别示例中，代码下载只提供了示例的最终版本。例如，如果你下载了第二章, *媒体查询-支持不同的视口*的代码示例，这些示例将是在第二章, *媒体查询-支持不同的视口*结束时的状态。除了文本中提供的中间状态外，不提供其他中间状态。

## 我们的基本 HTML 文件

我们将从一个简单的 HTML5 结构开始。现在不用担心每一行都做了什么（特别是`<head>`的内容，我们将在第四章中详细介绍，*响应式网页设计的 HTML5*）。

暂时，只需专注于`<body>`标签内的元素。我相当确定那里没有什么看起来太不寻常的东西；一些 div，一个用于标志的图形，一张图片（看起来很美味的烤饼），一两段文字和一列项目的列表。

以下是代码的摘要版本。为了简洁起见，我已经在下面的代码中删除了段落文字，因为我们只需要关注结构。但是，你应该知道这是一个食谱，描述了如何制作司康饼；典型的英式蛋糕。

如果你想看完整的 HTML 文件，可以从[rwd.education](http://rwd.education)网站下载。

```html
<!doctype html>
<html class="no-js" lang="en">
    <head>
        <meta charset="utf-8">
        <title>Our first responsive web page with HTML5 and CSS3</title>
        <meta name="description" content="A basic responsive web page – an example from Chapter 1">
        <link rel="stylesheet" href="css/styles.css">
    </head>
    <body>
        <div class="Header">
            <a href="/" class="LogoWrapper"><img src="img/SOC-Logo.png" alt="Scone O'Clock logo" /></a>
            <p class="Strap">Scones: the most resplendent of snacks</p>
        </div>
        <div class="IntroWrapper">
            <p class="IntroText">Occasionally maligned and misunderstood; the scone is a quintessentially British classic.</p>
            <div class="MoneyShot">
                <img class="MoneyShotImg" src="img/scones.jpg" alt="Incredible scones" />
                <p class="ImageCaption">Incredible scones, picture from Wikipedia</p>
            </div>
        </div>
        <p>Recipe and serving suggestions follow.</p>
        <div class="Ingredients">
            <h3 class="SubHeader">Ingredients</h3>
            <ul>

            </ul>
        </div>
        <div class="HowToMake">
            <h3 class="SubHeader">Method</h3>
            <ol class="MethodWrapper">

            </ol>
        </div>
    </body>
</html>
```

默认情况下，网页是灵活的。如果你打开示例页面，即使在这一点上（没有媒体查询的情况下），调整浏览器窗口大小，你会看到文本会根据需要重新排列。

在不同的设备上呢？没有任何 CSS 的情况下，在 iPhone 上的呈现如下：

![我们的基本 HTML 文件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_01_02.jpg)

正如你所看到的，它在 iPhone 上呈现得像一个“正常”的网页。原因是 iOS 默认将网页呈现为 980px 宽，并将其缩小到视口中。

浏览器的可视区域在技术上被称为**viewport**。视口很少等同于设备的屏幕尺寸，特别是在用户可以调整浏览器窗口大小的情况下。

因此，从现在开始，当我们提到网页的可用空间时，我们通常会使用这个更准确的术语。

我们可以通过在`<head>`中添加以下片段来轻松解决之前的问题：

```html
<meta name="viewport" content="width=device-width">
```

这个 viewport `meta`标签是一种非标准（但事实上的标准）的告诉浏览器如何呈现页面的方式。在这种情况下，我们的 viewport `meta`标签实际上是在说“使内容以设备的宽度呈现”。实际上，最好的办法可能是直接向您展示这一行对适用设备的影响：

![我们的基本 HTML 文件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_01_03.jpg)

太好了！现在文本以更“原生”的大小呈现和流动了。让我们继续。

我们将在第二章中介绍`meta`标签及其各种设置和变体（以及相同功能的基于标准的版本），*媒体查询-支持不同的视口*。

## 驯服图片

他们说一张图片胜过千言万语。在我们的示例页面中写了这么多关于烤饼干的内容，却没有展示这些美味的图片。我要在页面顶部添加一张烤饼干的图片；一种“英雄”图片，吸引用户阅读页面。

![驯服图片](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_01_04.jpg)

哦！那张漂亮的大图片（宽度为 2000px）强制我们的页面呈现得有点乱。我们需要解决这个问题。我们可以通过 CSS 为图片添加固定宽度，但问题在于我们希望图片能够根据不同的屏幕尺寸进行缩放。

例如，我们的 iPhone 示例宽度为 320px，所以我们可以将该图片的宽度设置为 320px，但是如果用户旋转屏幕会发生什么呢？320px 宽的视口现在变成了 480px 宽。幸运的是，通过一行 CSS 代码很容易实现图片的流动，使其可以根据容器的可用宽度进行缩放。

我现在要创建`css/styles.css` CSS 文件，并将其链接到 HTML 页面的头部。

这是我要添加的第一件事。通常我会设置一些其他默认值，我们将在后面的章节中讨论这些默认值，但是为了我们的目的，我很乐意只用这个来开始：

```html
img {
    max-width: 100%;
}
```

现在当页面刷新后，我们看到的更接近我们预期的东西。

![驯服图片](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_01_05.jpg)

这个基于`max-width`的规则的作用只是规定所有的图片的宽度最大为 100%（即它们应该扩展到 100%的大小，不再更大）。如果包含元素（如`body`或者它所在的`div`）的宽度小于图片的固有宽度，图片将简单地缩放到最大可用空间。

### 提示

**为什么不简单地使用 width: 100%？**

要使图片流动，您也可以使用更常用的 width 属性。例如，`width: 100%`，但这会产生不同的效果。当使用`width`属性时，图片将以该宽度显示，而不考虑其固有大小。在我们的示例中，结果将是 logo（也是一张图片）拉伸以填满其容器的 100%。对于比图片（如我们的 logo）宽得多的容器，这会导致图片过大。

太好了。现在一切都按预期布局。无论视口大小如何，都没有内容横向溢出页面。

然而，如果我们在更大的视口中查看页面，基本样式开始变得字面上和比喻上都被拉伸了。看一下大约在 1400px 大小的示例页面：

![驯服图片](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_01_06.jpg)

哦，天哪！事实上，即使在大约 600px 宽的时候，它开始受到影响。在这一点上，如果我们能重新安排一些东西就会很方便。也许调整一下图片的大小并将其放在一边。也许改变一些字体大小和元素的背景颜色。

幸运的是，我们可以通过使用 CSS 媒体查询来轻松实现所有这些功能，以使事情按照我们的意愿进行弯曲。

## 进入媒体查询

正如我们已经确定的那样，在 600px 宽的某个点之后，我们当前的布局开始显得拉伸。让我们使用 CSS3 媒体查询根据屏幕宽度调整布局。媒体查询允许我们根据一些条件（例如屏幕宽度和高度）应用特定的 CSS 规则。

### 提示

**不要将断点设置为流行的设备宽度**

“断点”是用来定义响应式设计应该显著改变的点。

当人们开始使用媒体查询时，常见的做法是在设计中设置特定于当时流行设备的断点。当时通常是 iPhone（320px x 480px）和 iPad（768px x 1024px）定义了这些“断点”。

那种做法当时是一个糟糕的选择，现在甚至更糟。问题在于，通过这样做，我们是在为特定的屏幕尺寸定制设计。我们需要一个响应式设计——不管查看它的屏幕尺寸是多大，它都能够适应；而不是只在特定尺寸下才能看起来最好。

因此，让内容和设计本身决定断点的相关性。也许你的初始布局在 500px 宽及以上开始看起来不对，也许是 800px。你自己的项目设计应该决定何时需要断点。

我们将在第二章中涵盖整个 CSS 媒体查询范围，*媒体查询-支持不同的视口*，巧妙地命名为**媒体查询**。

然而，为了将我们的基本示例整理成形，我们将集中讨论一种媒体查询类型；最小宽度媒体查询。在这种类型的媒体查询中，只有在视口达到最小定义宽度时，才会应用其中的 CSS 规则。可以使用一系列不同的长度单位来指定确切的最小宽度，包括百分比、em、rem 和 px。在 CSS 中，最小宽度媒体查询的写法如下：

```html
@media screen and (min-width: 50em) {
    /* styles */
}
```

`@media`指令告诉浏览器我们正在开始一个媒体查询，`screen`部分（在这种情况下，声明“屏幕”在技术上并不需要，但我们将在下一章中详细处理这个问题）告诉浏览器这些规则应该适用于所有屏幕类型，`and (min-width: 50em)`告诉浏览器这些规则应该限制在所有大于 50em 大小的视口上。

### 提示

我相信是 Bryan Rieger ([`www.slideshare.net/bryanrieger/rethinking-the-mobile-web-by-yiibu`](http://www.slideshare.net/bryanrieger/rethinking-the-mobile-web-by-yiibu))首先写道：

> *"对媒体查询的支持的缺失实际上是第一个媒体查询。"*

他的意思是，我们写的第一条规则，除了媒体查询之外，应该是我们的“基本”规则，然后我们可以为更有能力的设备增强这些规则。

目前，只需意识到这种方法首先强调我们最小的屏幕，并允许我们根据设计的需要逐步添加细节。

### 修改示例以适应更大的屏幕

我们已经确定我们的设计在大约 600px/37.5rem 宽度时开始受到影响。

因此，让我们通过一个简单的示例来混合一下，展示在不同的视口尺寸下如何布局不同的内容。

### 提示

几乎所有的浏览器都有一个默认的文本大小为 16px，所以你可以通过将 px 值除以 16 来轻松地将宽度转换为 rems。我们将在第二章中讨论为什么你可能想要这样做，*媒体查询-支持不同的视口*。

首先，我们将阻止主要的“英雄”图像变得过大，并将其保持在右侧。然后介绍文本可以位于左侧。

然后我们将有主要的文本部分，描述如何制作烤饼的“方法”，位于左侧，下面有一个小的方框部分，详细介绍右侧的配料。

所有这些变化都可以通过在媒体查询中封装这些特定样式来相对简单地实现。以下是添加相关样式后的情况：

![修改示例以适应更大的屏幕](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_01_07.jpg)

在较小的屏幕上，它看起来基本上与以前一样，但一旦视口达到 50rem 或更宽，它就会调整到新的布局。

以下是添加的布局样式：

```html
@media screen and (min-width: 50rem) {
    .IntroWrapper {
        display: table;
        table-layout: fixed;
        width: 100%;
    }

    .MoneyShot,
    .IntroText {
        display: table-cell;
        width: 50%;
        vertical-align: middle;
        text-align: center;
    }

    .IntroText {
        padding: .5rem;
        font-size: 2.5rem;
        text-align: left;
    }

    .Ingredients {
        font-size: .9rem;
        float: right;
        padding: 1rem;
        margin: 0 0 .5rem 1rem;
        border-radius: 3px;
        background-color: #ffffdf;
        border: 2px solid #e8cfa9;
    }

    .Ingredients h3 {
        margin: 0;
    }
}
```

这并不太糟糕，是吗？只需很少的代码，我们就建立了一个可以根据视口大小做出响应并在需要时提供更合适布局的页面。通过添加更多的样式，页面看起来甚至更加舒适。有了这些，我们基本的响应式页面现在在 iPhone 上看起来是这样的：

![修改示例以适应更大的屏幕](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_01_08.jpg)

就像上面的 50rem 宽度一样：

![修改示例以适应更大的屏幕](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_01_09.jpg)

这些进一步的视觉装饰并没有增加对响应式发生的理解，因此我在这里省略了它们，但如果你想查看相关代码，请在[`rwd.education`](http://rwd.education)或[`github.com/benfrain/rwd`](https://github.com/benfrain/rwd)下载本章代码。

这只是一个非常基本的示例，但它已经包含了构建响应式网页设计的基本方法论。

重申我们所涵盖的基本要点；从“基础”样式开始，这些样式可以在任何设备上使用。然后随着视口大小和/或功能的增加逐渐添加增强功能。

### 注意

你可以在这里找到 CSS 媒体查询（Level 3）的完整规范：[`www.w3.org/TR/css3-mediaqueries/`](http://www.w3.org/TR/css3-mediaqueries/)

这里还有一个 CSS 媒体查询（Level 4）的工作草案：[`dev.w3.org/csswg/mediaqueries-4/`](http://dev.w3.org/csswg/mediaqueries-4/)

# 我们示例的不足之处

在本章中，我们已经涵盖了基本响应式 HTML5 和 CSS3 驱动的网页的所有基本组成部分。

但你我都知道，这个基本的响应式示例很少是我们要构建的限制。也不应该反映我们能够构建的限制。

如果我们希望我们的页面对不同的光照条件做出响应怎么办？当人们使用不同的指向设备（例如手指而不是鼠标）时，链接的大小会发生变化怎么办？如果我们想要简单地使用 CSS 来实现动画和移动视觉元素呢？

然后是标记。我们如何使用更多语义元素来标记页面；文章、部分、菜单等，或者制作具有内置验证的表单（无需 JavaScript）？如果我们想要在不同的视口上更改元素的视觉顺序呢？

别忘了图片。在这个示例中，我们有流体图片，但如果人们在手机上访问这个页面，他们将需要下载一个大的图形（宽度为 2000 像素），而这个图形只会以其中的一小部分显示在他们的手机上。这将使页面加载速度比必要的慢得多。肯定有更好的办法吧？

那么标志和图标呢？在这个示例中，我们使用了 PNG，但我们可以轻松地使用**可伸缩矢量图形**（**SVG**）来享受具有分辨率独立性的图形。这样它们看起来会非常清晰，无论查看屏幕的分辨率如何。

希望你有时间留下来，因为这些正是我们将在接下来的章节中回答的问题。

# 总结

干得好，现在你知道并理解了创建完全响应式网页所需的基本要素。然而，正如我们刚刚发现的，有很多地方可以改进。

但这没关系。我们不只是想要能够制作称职的响应式网页设计，我们还想要能够创造“最佳体验”。所以让我们继续努力吧。

首先，我们将深入了解所有三级和四级 CSS 媒体查询所提供的内容。我们已经看到网页如何响应视口宽度，但现在我们可以做的远不止这些，而且很快会有更多有趣的东西出现在你的浏览器中。让我们去看一看。


# 第二章：媒体查询-支持不同的视口

在上一章中，我们简要介绍了响应式网页的基本组件：流体布局、流体图像和媒体查询。

本章将详细介绍媒体查询，希望能够提供充分理解它们的能力、语法和未来发展所需的一切。

在本章中，我们将：

+   了解为什么响应式网页设计需要媒体查询

+   了解媒体查询语法

+   学习如何在`link`标签中使用媒体查询，以及在 CSS 文件中使用 CSS `@import`语句和媒体查询本身

+   了解我们可以测试的设备功能

+   使用媒体查询来促进视觉变化，取决于可用的屏幕空间

+   考虑媒体查询是否应该被分组在一起或根据需要编写

+   了解`meta`视口标签，以便在 iOS 和 Android 设备上使媒体查询按预期工作

+   考虑未来媒体查询规范提出的功能

CSS3 规范由许多模块组成。媒体查询（Level 3）只是其中之一。媒体查询允许我们根据设备的功能来定位特定的 CSS 样式。例如，只需几行 CSS，我们就可以根据视口宽度、屏幕宽高比、方向（横向或纵向）等来改变内容的显示方式。

媒体查询被广泛实现。除了古老版本的 Internet Explorer（8 及以下）之外，几乎所有浏览器都支持它们。简而言之，没有任何理由不使用它们！

### 提示

W3C 的规范经过一系列的批准过程。如果你有一天空闲，可以去看看它们在[`www.w3.org/2005/10/Process-20051014/tr`](http://www.w3.org/2005/10/Process-20051014/tr)上的官方解释。简化版本是，规范从**工作草案**（**WD**）到**候选推荐**（**CR**），再到**建议推荐**（**PR**），最后在许多年后到达 W3C 推荐（REC）。比其他模块更成熟的模块通常更安全使用。例如，CSS 变换模块 Level 3（[`www.w3.org/TR/css3-3d-transforms/`](http://www.w3.org/TR/css3-3d-transforms/)）自 2009 年 3 月以来一直处于 WD 状态，而它的浏览器支持要比 CR 模块如媒体查询差得多。

# 为什么响应式网页设计需要媒体查询

CSS3 媒体查询使我们能够将特定的 CSS 样式定位到特定的设备功能或情况上。如果你前往 W3C 的 CSS3 媒体查询模块规范（[`www.w3.org/TR/css3-mediaqueries/`](http://www.w3.org/TR/css3-mediaqueries/)），你会看到这是他们对媒体查询的官方介绍：

> “媒体查询由媒体类型和零个或多个表达式组成，用于检查特定媒体特征的条件。可以在媒体查询中使用的媒体特征包括'宽度'、'高度'和'颜色'。通过使用媒体查询，演示可以根据特定范围的输出设备进行定制，而不改变内容本身。”

没有媒体查询，我们将无法仅使用 CSS 大幅改变网站的视觉效果。它们使我们能够编写防御性的 CSS 规则，以预防诸如纵向屏幕方向、小或大视口尺寸等情况。

尽管流体布局可以在很大程度上实现设计，但考虑到我们希望覆盖的屏幕尺寸范围，有时我们需要更全面地修改布局。媒体查询使这成为可能。把它们看作是 CSS 的基本条件逻辑。

## CSS 中的基本条件逻辑

真正的编程语言都有一些设施，可以处理两种或更多可能的情况。这通常采用条件逻辑的形式，以`if/else`语句为典型。

如果编程术语让你的眼睛发痒，不要害怕；这是一个非常简单的概念。每当你去咖啡馆时让朋友帮你点餐时，你可能都在规定条件逻辑，“如果他们有三重巧克力松饼，我就要一个，如果没有，我就要一块胡萝卜蛋糕”。这是一个简单的条件语句，有两种可能的结果（在这种情况下同样好）。

在撰写本文时，CSS 不支持真正的条件逻辑或编程特性。循环、函数、迭代和复杂的数学仍然完全属于 CSS 处理器的领域（我是否提到了一本关于 Sass 预处理器的精彩书籍，名为*Sass and Compass for Designers*？）。然而，媒体查询是 CSS 中允许我们编写基本条件逻辑的一种机制。通过使用媒体查询，其中的样式根据是否满足某些条件而作用域。

### 注意

**编程特性即将到来**

CSS 预处理器的流行使得负责 CSS 规范的人们开始注意到这一点。现在有一个 CSS 变量的 WD 规范：[`www.w3.org/TR/css-variables/`](http://www.w3.org/TR/css-variables/)

然而，目前浏览器支持仅限于 Firefox，因此目前真的不值得考虑在实际中使用。

# 媒体查询语法

CSS 媒体查询是什么样的，更重要的是，它是如何工作的？

在任何 CSS 文件的底部输入以下代码，并预览相关的网页。或者，你可以打开`example_02-01`：

```html
body {
  background-color: grey;
}
@media screen and (min-width: 320px) {
  body {
    background-color: green;
  }
}
@media screen and (min-width: 550px) {
  body {
    background-color: yellow;
  }
}
@media screen and (min-width: 768px) {
  body {
    background-color: orange;
  }
}
@media screen and (min-width: 960px) {
  body {
    background-color: red;
  }
}
```

现在，在浏览器中预览文件并调整窗口大小。页面的背景颜色将根据当前的视口大小而变化。我们将很快介绍语法的工作原理。首先，重要的是要知道如何以及在哪里可以使用媒体查询。

## 链接标签中的媒体查询

自 CSS2 以来一直在使用 CSS 的人会知道，可以使用`<link>`标签的媒体属性来指定样式表适用的设备类型（例如，`screen`或`print`）。考虑以下示例（你会将其放在你的标记的`<head>`标签中）：

```html
<link rel="style sheet" type="text/css" media="screen" href="screen-styles.css">
```

媒体查询增加了根据设备的能力或特性来定位样式的能力，而不仅仅是设备类型。把它看作是对浏览器的一个问题。如果浏览器的答案是“true”，那么封闭的样式将被应用。如果答案是“false”，它们就不会。媒体查询不仅仅询问浏览器“你是屏幕吗？”——就像我们只能用 CSS2 来问的那样——媒体查询问得更多。相反，媒体查询可能会问，“你是屏幕，你是纵向的吗？”让我们以此为例：

```html
<link rel="stylesheet" media="screen and (orientation: portrait)" href="portrait-screen.css" />
```

首先，媒体查询表达式询问类型（你是屏幕吗？），然后是特性（你的屏幕是纵向的吗？）。`portrait-screen.css`样式表将应用于任何具有纵向屏幕方向的屏幕设备，并对其他设备忽略。通过在媒体查询的开头添加 not，可以颠倒任何媒体查询表达式的逻辑。例如，以下代码将否定我们之前例子中的结果，将文件应用于任何不是纵向屏幕的屏幕：

```html
<link rel="stylesheet" media="not screen and (orientation: portrait)" href="portrait-screen.css" />
```

# 组合媒体查询

也可以将多个表达式串联在一起。例如，让我们扩展我们之前的一个例子，并将文件限制为视口大于 800 像素的设备。

```html
<link rel="stylesheet" media="screen and (orientation: portrait) and (min-width: 800px)" href="800wide-portrait-screen.css" />
```

此外，我们可以有一个媒体查询列表。如果列出的任何查询为 true，则将应用该文件。如果没有一个为 true，则不会应用。以下是一个例子：

```html
<link rel="stylesheet" media="screen and (orientation: portrait) and (min-width: 800px), projection" href="800wide-portrait-screen.css" />
```

这里有两点需要注意。首先，逗号分隔每个媒体查询。其次，在投影后，你会注意到括号中没有尾随的特性/值组合。这是因为在没有这些值的情况下，媒体查询将应用于所有媒体类型。在我们的例子中，样式将应用于所有投影仪。

### 提示

你应该知道，可以使用任何 CSS 长度单位来指定媒体查询。**像素**（**px**）是最常用的，但**ems**（**em**）和**rems**（**rem**）同样适用。关于每种单位的优点，我在这里写了更多内容：[`benfrain.com/just-use-pixels`](http://benfrain.com/just-use-pixels)

因此，如果你想在 800px（但以 em 单位指定）处设置断点，只需将像素数除以 16。例如，800px 也可以指定为 50em（800 / 16 = 50）。

## 使用@import 的媒体查询

我们还可以使用 CSS 的`@import`功能将样式表有条件地加载到现有样式表中。例如，以下代码将导入名为`phone.css`的样式表，前提是设备基于屏幕，并且视口最大为 360 像素：

```html
@import url("phone.css") screen and (max-width:360px);
```

请记住，使用 CSS 的`@import`功能会增加 HTTP 请求（影响加载速度），因此请谨慎使用此方法。

## CSS 中的媒体查询

到目前为止，我们已经将它们作为链接到我们将放置在 HTML 的`<head></head>`部分中的 CSS 文件，并作为`@import`语句。但是，更有可能的是，我们将希望在 CSS 样式表中使用媒体查询。例如，如果我们将以下代码添加到样式表中，它将使所有`h1`元素变为绿色，前提是设备的屏幕宽度为 400 像素或更小：

```html
@media screen and (max-device-width: 400px) {
  h1 { color: green }
}
```

首先，我们指定要使用`@media`规则的媒体查询，然后指定要匹配的类型。在前面的示例中，我们只想将封闭的规则应用于屏幕（例如不适用于`print`）。然后，在括号内输入查询的具体内容。然后像任何 CSS 规则一样，我们打开大括号并编写所需的样式。

在这一点上，我可能需要指出的是，在大多数情况下，实际上不需要指定`screen`。这是规范中的关键点：

> *“媒体查询提供了适用于所有媒体类型的简写语法；关键字'all'可以省略（以及末尾的'and'）。也就是说，如果媒体类型没有明确给出，它就是'all'。”*

因此，除非你想要针对特定媒体类型的样式，否则可以省略`screen and`部分。这是我们从现在开始在示例文件中编写媒体查询的方式。

## 媒体查询可以测试什么？

在构建响应式设计时，最常使用的媒体查询通常与设备的视口宽度（`width`）有关。根据我的经验，我发现除了分辨率和视口高度偶尔需要使用外，几乎没有必要使用其他功能。但是，以防万一需要，这里是媒体查询级别 3 可以测试的所有功能列表。希望其中一些能引起你的兴趣：

+   `width`：视口宽度。

+   `height`：视口高度。

+   `device-width`：渲染表面的宽度（对于我们的目的，这通常是设备的屏幕宽度）。

+   `device-height`：渲染表面的高度（对于我们的目的，这通常是设备的屏幕高度）。

+   `orientation`：此功能检查设备是纵向还是横向。

+   `aspect-ratio`：基于视口宽度和高度的宽高比。16:9 的宽屏显示可以写为`aspect-ratio: 16/9`。

+   `device-aspect-ratio`：此功能类似于`aspect-ratio`，但是基于设备渲染表面的宽度和高度，而不是视口。

+   `color`：每个颜色分量的位数。例如，`min-color: 16`将检查设备是否具有 16 位颜色。

+   `color-index`：设备颜色查找表中的条目数。值必须是数字，不能为负数。

+   `monochrome`：此功能测试单色帧缓冲区中每像素的位数。值将是一个数字（整数），例如，`monochrome: 2`，不能为负数。

+   `resolution`：此功能可用于测试屏幕或打印分辨率；例如，`min-resolution: 300dpi`。它还可以接受每厘米的点数；例如，`min-resolution: 118dpcm`。

+   `scan`：这可以是渐进式或隔行扫描功能，主要适用于电视。例如，720p 高清电视（720p 中的 p 表示“渐进式”）可以使用`scan: progressive`进行定位，而 1080i 高清电视（1080i 中的 i 表示“隔行扫描”）可以使用`scan: interlace`进行定位。

+   `grid`：此功能指示设备是基于网格还是位图。

所有前述功能，除了`scan`和`grid`，都可以用`min`或`max`进行前缀处理以创建范围。例如，考虑以下代码片段：

```html
@import url("tiny.css") screen and (min-width:200px) and (max-width:360px);
```

在这里，宽度应用了最小（`min`）和最大（`max`）来设置一个范围。tiny.css 文件只会被导入到视口宽度最小为 200 像素，最大为 360 像素的屏幕设备中。

### 注意

**CSS 媒体查询级别 4 中弃用的功能**

值得注意的是，媒体查询级别 4 的草案规范弃用了一些功能（[`dev.w3.org/csswg/mediaqueries-4/#mf-deprecated`](http://dev.w3.org/csswg/mediaqueries-4/#mf-deprecated)）；其中最明显的是`device-height`、`device-width`和`device-aspect-ratio`。浏览器将继续支持这些查询，但建议您不要编写使用它们的新样式表。

# 使用媒体查询来改变设计

由于它们的本质，样式表中更下面的样式（对我们来说是 CSS 文件）会覆盖更上面的等效样式（除非更上面的样式更具体）。因此，我们可以在样式表的开头设置基本样式，适用于我们设计的所有版本（或者至少提供我们的“基本”体验），然后在文档中进一步使用媒体查询来覆盖相关部分。例如，我们可能选择在有限的视口中将导航链接设置为纯文本（或者只是较小的文本），然后使用媒体查询来在更大的视口中覆盖这些样式，以便在更大的空间可用时为我们提供文本和图标。

让我们看看这在实践中是什么样子（`example_02-02`）。首先是标记：

```html
<a href="#" class="CardLink CardLink_Hearts">Hearts</a>
<a href="#" class="CardLink CardLink_Clubs">Clubs</a>
<a href="#" class="CardLink CardLink_Spades">Spades</a>
<a href="#" class="CardLink CardLink_Diamonds">Diamonds</a>
```

现在 CSS：

```html
.CardLink {
    display: block;
    color: #666;
    text-shadow: 0 2px 0 #efefef;
    text-decoration: none;
    height: 2.75rem;
    line-height: 2.75rem;
    border-bottom: 1px solid #bbb;
    position: relative;
}

@media (min-width: 300px) {
    .CardLink {
        padding-left: 1.8rem;
        font-size: 1.6rem;
    }
}

.CardLink:before {
    display: none;
    position: absolute;
    top: 50%;
    transform: translateY(-50%);
    left: 0;
}

.CardLink_Hearts:before {
    content: "♥";
}

.CardLink_Clubs:before {
    content: "♣";
}

.CardLink_Spades:before {
    content: "♠";
}

.CardLink_Diamonds:before {
    content: "♦";
}

@media (min-width: 300px) {
    .CardLink:before {
        display: block;
    }
}
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接通过电子邮件发送给您。

这是一个小视口中链接的屏幕截图：

![使用媒体查询来改变设计](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_02_01.jpg)

这是它在较大的视口中的截图：

![使用媒体查询来改变设计](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_02_02.jpg)

## 任何 CSS 都可以包含在媒体查询中

重要的是要记住，您通常在 CSS 中编写的任何内容也可以包含在媒体查询中。因此，可以使用媒体查询在不同情况下（通常是不同的视口大小）完全改变站点的布局和外观。

## HiDPI 设备的媒体查询

媒体查询的另一个常见用例是在高分辨率设备上查看站点时更改样式。考虑这个：

```html
@media (min-resolution: 2dppx) {
  /* styles */
}
```

在这里，我们的媒体查询指定，我们只希望封闭的样式应用于屏幕分辨率为 2 像素每像素单位（2dppx）的情况。这将适用于 iPhone 4 等设备（苹果的 HiDPI 设备被称为“Retina”）以及大量的 Android 设备。您可以通过减少 dppx 值来将该媒体查询应用于更广泛的设备范围。

### 提示

在编写最小分辨率媒体查询时，确保运行有一个添加前缀的工具，以提供相关的供应商前缀，以获得尽可能广泛的支持。如果现在对供应商前缀这个术语不太理解，也不用担心，因为我们将在下一章更详细地讨论这个主题。

# 组织和编写媒体查询的考虑

在这一点上，我们将进行一个简短的偏离，考虑作者在编写和组织他们的媒体查询时可以采取的一些不同方法。每种方法都有一些好处和一些权衡，因此至少了解这些因素是值得的，即使您认为它们对您的需求基本上无关紧要。

## 链接到不同的 CSS 文件，带有媒体查询

从浏览器的角度来看，CSS 被认为是“渲染阻塞”的资源。浏览器需要在渲染页面之前获取和解析链接的 CSS 文件。

然而，现代浏览器足够聪明，可以区分哪些样式表（在头部链接的带有媒体查询的样式表）需要立即分析，哪些可以推迟到初始页面渲染之后再进行。

对于这些浏览器，链接到不适用媒体查询的 CSS 文件（例如，如果屏幕太小，媒体查询不适用）可以在初始页面加载后“推迟”，从而提供一些性能优势。

关于这个主题，Google 的开发者页面上有更多内容：[`developers.google.com/web/fundamentals/performance/critical-rendering-path/render-blocking-css`](https://developers.google.com/web/fundamentals/performance/critical-rendering-path/render-blocking-css)

然而，我想特别提醒您注意这一部分：

> “...请注意，“渲染阻塞”只是指浏览器是否必须在该资源上保持页面的初始渲染。无论哪种情况，浏览器都会下载 CSS 资源，尽管对于非阻塞资源，它的优先级较低。”

再次强调，所有链接的文件仍然会被下载，只是如果它们不立即应用，浏览器不会延迟页面的渲染。

因此，现代浏览器加载一个响应式网页（查看`example_02-03`）时，会下载链接了不同媒体查询的四个不同样式表（以适应不同的视口范围），但可能只会在渲染页面之前解析适用的样式表。

## 分离媒体查询的实际性

尽管我们刚刚了解到分割媒体查询的过程可能会带来一些好处，但将不同的媒体查询样式分开到不同的文件中并不总是有很大的实际优势（除了个人偏好和/或代码的分隔）。

毕竟，使用单独的文件会增加呈现页面所需的 HTTP 请求的数量，这反过来可能会使页面在某些其他情况下变慢。在网络上没有什么是容易的！因此，这实际上是一个问题，评估您的网站的整体性能，并在不同设备上测试每种情况。

我对此的默认立场是，除非项目有足够的时间进行性能优化，否则这是我寻求性能提升的最后一个地方。只有当我确定：

+   所有图像都已经压缩

+   所有脚本都被连接并进行了最小化

+   所有资产都以 gzip 方式提供

+   所有静态内容都通过 CDN 进行缓存

+   所有多余的 CSS 规则已被删除

也许那时我会开始考虑将媒体查询拆分成单独的文件以获得性能提升。

### 提示

gzip 是一种压缩和解压缩文件格式。任何好的服务器都应该允许对 CSS 等文件进行 gzip 压缩，这将大大减小文件在从服务器到设备的传输过程中的大小（在这一点上，它被解压缩为其原生格式）。您可以在维基百科上找到 gzip 的一个很好的摘要：[`en.wikipedia.org/wiki/Gzip`](http://en.wikipedia.org/wiki/Gzip)

## 嵌套媒体查询“内联”

除了极端情况外，我建议在现有样式表中添加媒体查询，与“正常”的规则一起。

如果您愿意这样做，还有一个考虑因素：媒体查询应该在相关选择器下声明吗？还是分离出一个单独的代码块，包含所有相同的媒体查询？我很高兴你问了。

# 合并媒体查询还是根据需要编写媒体查询？

我喜欢在原始的“正常”定义下编写媒体查询。例如，假设我想要根据视口宽度在样式表的不同位置更改一些元素的宽度，我会这样做：

```html
.thing {
    width: 50%;
}

@media screen and (min-width: 30rem) {
    .thing {
        width: 75%;
    }
}

/* A few more styles would go between them */

.thing2 {
    width: 65%;
}

@media screen and (min-width: 30rem) {
    .thing2 {
        width: 75%;
    }
}
```

这乍一看似乎是疯狂的。我们有两个媒体查询都与屏幕最小宽度为 30rem 有关。重复相同的`@media`声明肯定是冗长和浪费的吧？我应该主张将所有相同的媒体查询分组到一个单独的代码块中，就像这样：

```html
.thing {
    width: 50%;
}

.thing2 {
    width: 65%;
}

@media screen and (min-width: 30rem) {
    .thing {
        width: 75%;
    }
    .thing2 {
        width: 75%;
    }
}
```

这当然是一种方法。然而，从维护的角度来看，我觉得这更加困难。没有“正确”的方法，但我更喜欢为单个选择器定义一条规则，并在其后立即定义该规则的任何变体（例如在媒体查询中的更改）。这样我就不必搜索单独的代码块，找到与特定选择器相关的声明。

### 注意

通过 CSS 预处理器和后处理器，这甚至可以更加方便，因为媒体查询的“变体”可以直接嵌套在规则集中。我的另一本书*Sass and Compass for Designers*中有一个完整的章节介绍这个。

从冗长的角度来看，对前一种技术提出异议似乎是公平的。单单文件大小就足以成为不以这种方式编写媒体查询的理由了吧？毕竟，没有人希望为用户提供一个臃肿的 CSS 文件。然而，简单的事实是，gzip 压缩（应该压缩服务器上的所有可能的资源）将这种差异减少到完全可以忽略的程度。我过去做过各种测试，所以如果您想了解更多信息，请访问：[`benfrain.com/inline-or-combined-media-queries-in-sass-fight/`](http://benfrain.com/inline-or-combined-media-queries-in-sass-fight/)。最重要的是，如果您宁愿直接在标准样式之后编写媒体查询，我认为您不应该担心文件大小。

### 提示

如果您想直接在原始规则之后编写媒体查询，但希望所有相同的媒体查询定义合并为一个，那么有许多构建工具（在撰写本文时，Grunt 和 Gulp 都有相关插件）可以实现这一点。

# viewport meta 标签

为了充分利用媒体查询，您希望较小的屏幕设备以其原生尺寸显示网页（而不是在 980px 窗口中渲染，然后您必须放大和缩小）。

2007 年苹果发布 iPhone 时，他们引入了一个名为 viewport `meta`的专有`meta`标签，Android 和越来越多的其他平台现在也支持这个标签。viewport `meta`标签的目的是为了让网页与移动浏览器通信，告诉它们希望如何渲染页面。

在可预见的未来，任何您希望响应式的网页，并在小屏设备上良好呈现的网页，都需要使用这个`meta`标签。

### 提示

**在模拟器和仿真器上测试响应式设计**

尽管在真实设备上测试开发工作是无法替代的，但 Android 有模拟器，iOS 有仿真器。

对于一丝不苟的人来说，模拟器只是模拟相关设备，而仿真器实际上试图解释原始设备代码。

Windows、Linux 和 Mac 的 Android 模拟器可通过下载和安装 Android**软件开发工具包**（**SDK**）免费获取，网址为[`developer.android.com/sdk/`](http://developer.android.com/sdk/)。

iOS 模拟器仅适用于 Mac OS X 用户，并作为 Xcode 软件包的一部分（可从 Mac App Store 免费获取）。

浏览器本身也在其开发工具中包含了不断改进的模拟移动设备的工具。Firefox 和 Chrome 目前都有特定的设置来模拟不同的移动设备/视口。

viewport `<meta>`标签添加在 HTML 的`<head>`标签中。它可以设置为特定宽度（例如，我们可以指定为像素）或作为比例，例如`2.0`（实际大小的两倍）。以下是 viewport `meta`标签的示例，设置为显示浏览器为实际大小的两倍（200％）：

```html
<meta name="viewport" content="initial-scale=2.0,width=device-width" />
```

让我们分解前面的`<meta>`标签，以便我们了解发生了什么。`name="viewport"`属性是显而易见的。然后，`content="initial-scale=2.0`部分表示“将内容缩放到原始大小的两倍”（其中 0.5 表示原始大小的一半，3.0 表示原始大小的三倍，依此类推），而`width=device-width`部分告诉浏览器页面的宽度应等于设备宽度。

`<meta>`标签还可以用于控制用户在页面上放大和缩小的程度。此示例允许用户放大到设备宽度的三倍，缩小到设备宽度的一半：

```html
<meta name="viewport" content="width=device-width, maximum-scale=3, minimum-scale=0.5" />
```

您还可以完全禁用用户缩放，尽管缩放是一个重要的辅助工具，但在实践中很少会适用：

```html
<meta name="viewport" content="initial-scale=1.0, user-scalable=no" />
```

`user-scalable=no` 是相关部分。

好了，我们将缩放比例更改为`1.0`，这意味着移动浏览器将以其视口的 100％呈现页面。将其设置为设备的宽度意味着我们的页面应该在所有支持的移动浏览器的宽度的 100％呈现。对于大多数情况，这个`<meta>`标签是合适的：

```html
<meta name="viewport" content="width=device-width,initial-scale=1.0" />
```

### 提示

注意到 viewport `meta`元素的使用越来越多，W3C 正在努力将相同的功能引入 CSS。前往[`dev.w3.org/csswg/css-device-adapt/`](http://dev.w3.org/csswg/css-device-adapt/)，了解有关新的`@viewport`声明的所有信息。这个想法是，您可以在 CSS 中写`@viewport { width: 320px; }`，而不是在标记的`<head>`部分中写`<meta>`标签。这将把浏览器宽度设置为 320 像素。然而，浏览器支持有限，尽管为了尽可能覆盖所有基础并尽可能具有未来的性能，您可以使用`meta`标签和`@viewport`声明的组合。

到目前为止，您应该已经对媒体查询及其工作原理有了扎实的掌握。然而，在我们完全转移到另一个话题之前，我认为考虑一下媒体查询的下一个版本可能会有什么可能性是很好的。让我们来偷偷看一眼！

# 媒体查询 4 级

在撰写本文时，虽然 CSS 媒体查询 4 级有一个草案规范（[`dev.w3.org/csswg/mediaqueries-4/`](http://dev.w3.org/csswg/mediaqueries-4/)），但草案中的功能并没有得到很多浏览器的实现。这意味着虽然我们将简要介绍此规范的亮点，但它非常不稳定。在使用这些功能之前，请确保检查浏览器支持并仔细检查语法更改。

目前，虽然 4 级规范中还有其他功能，但我们只关注脚本、指针和悬停以及亮度。

## 脚本媒体特性

在 HTML 标签上设置一个类来指示默认情况下没有 JavaScript，然后在 JavaScript 运行时用不同的类替换该类是一种常见做法。这提供了一个简单的能力来根据新的 HTML 类分叉代码（包括 CSS）。具体来说，使用这种做法，你可以编写特定于启用 JavaScript 的用户的规则。

这可能会让人困惑，所以让我们考虑一些示例代码。默认情况下，这将是在 HTML 中编写的标签：

```html
<html class="no-js">
```

当 JavaScript 在页面上运行时，它的第一个任务之一将是替换`no-js`类：

```html
<html class="js">
```

完成后，我们可以编写特定的 CSS 规则，这些规则只在 JavaScript 存在时才适用。例如，`.js .header { display: block; }`。

然而，CSS Media Queries Level 4 的脚本媒体特性旨在提供一种更标准的方式直接在 CSS 中执行此操作：

```html
@media (scripting: none) {
    /* styles for when JavaScript not working */
}
```

当 JavaScript 存在时：

```html
@media (scripting: enabled) {
    /* styles for when JavaScript is working */
}
```

最后，它还旨在提供确定 JavaScript 是否存在但仅在最初时。W3C 规范中给出的一个例子是，可以最初布置打印页面，但之后没有 JavaScript 可用。在这种情况下，你应该能够这样做：

```html
@media (scripting: initial-only) {
    /* styles for when JavaScript works initially */
}
```

这个功能的当前编辑草案可以在这里阅读：[`dev.w3.org/csswg/mediaqueries-4/#mf-scripting`](http://dev.w3.org/csswg/mediaqueries-4/#mf-scripting)

## 交互媒体特性

以下是 W3C 对指针媒体特性的介绍：

> *“指针媒体特性用于查询指针设备（如鼠标）的存在和准确性。如果设备有多个输入机制，则指针媒体特性必须反映“主要”输入机制的特性，由用户代理确定。”*

指针特性有三种可能的状态：`none`，`coarse`和`fine`。

`粗糙`指针设备可能是触摸屏设备上的手指。然而，它也可以是游戏控制台上没有鼠标那样精细控制的光标。

```html
@media (pointer: coarse) {
    /* styles for when coarse pointer is present */
}
```

`fine`指针设备可能是鼠标，但也可能是触控笔或任何未来的精细指针机制。

```html
@media (pointer: fine) {
    /* styles for when fine pointer is present */
}
```

就我而言，浏览器越早实现这些指针特性越好。目前，要知道用户是否有鼠标、触摸输入或两者都有是非常困难的。以及他们在任何时候使用的是哪一个。

### 提示

最安全的做法总是假设用户使用基于触摸的输入，并相应地调整用户界面元素的大小。这样，即使他们使用鼠标，也不会难以轻松使用界面。然而，如果你假设鼠标输入，并且无法可靠地检测触摸以修改界面，可能会导致困难的体验。

对于同时开发触摸和指针的挑战的很好概述，我推荐 Patrick H. Lauke 的这组幻灯片*Getting touchy*：[`patrickhlauke.github.io/getting-touchy-presentation/`](https://patrickhlauke.github.io/getting-touchy-presentation/)

在这里阅读这个功能的编辑草案：[`dev.w3.org/csswg/mediaqueries-4/#mf-interaction`](http://dev.w3.org/csswg/mediaqueries-4/#mf-interaction)

## 悬停媒体特性

正如你所想象的，悬停媒体特性测试用户在屏幕上悬停元素的能力。如果用户有多个输入设备（例如触摸和鼠标），则使用主要输入的特性。以下是可能的值和示例代码：

对于没有悬停能力的用户，我们可以以`none`的值为他们定制样式。

```html
@media (hover: none) {
    /* styles for when the user cannot hover */
}
```

对于可以悬停但必须执行重要操作来启动它的用户，可以使用`on-demand`。

```html
@media (hover: on-demand) {
    /* styles for when the user can hover but doing so requires significant effort */
}
```

对于可以悬停的用户，可以单独使用`hover`。

```html
@media (hover) {
    /* styles for when the user can hover */
}
```

请注意，还有`any-pointer`或`any-hover`媒体特性。它们类似于前面的 hover 和 pointer，但测试任何可能的输入设备的功能。

## 环境媒体特性

如果我们能够根据环境特征（如环境光水平）来改变我们的设计，那不是挺好的吗？这样，如果用户在较暗的房间里，我们可以降低所使用颜色的亮度。或者相反，在更明亮的阳光下增加对比度。环境媒体特性旨在解决这些问题。请考虑以下示例：

```html
@media (light-level: normal) {
    /* styles for standard light conditions */
}
@media (light-level: dim) {
    /* styles for dim light conditions */
}
@media (light-level: washed) {
    /* styles for bright light conditions */
}
```

请记住，目前很少有这些 Level 4 媒体查询的实现。在我们能够安全使用它们之前，规范很可能会发生变化。然而，了解未来几年我们将拥有哪些新功能是有用的。

阅读此功能的编辑草案：[`dev.w3.org/csswg/mediaqueries-4/#mf-environment`](http://dev.w3.org/csswg/mediaqueries-4/#mf-environment)

# 摘要

在本章中，我们学习了什么是 CSS3 媒体查询，如何在 CSS 文件中包含它们，以及它们如何帮助我们创建响应式网页设计。我们还学习了如何使用`meta`标签使现代移动浏览器呈现页面，就像我们想要的那样。

然而，我们也了解到，单独使用媒体查询只能提供一个适应性的网页设计，从一个布局切换到另一个布局。而不能实现一个真正响应式的设计，能够平稳地从一个布局过渡到另一个布局。为了实现我们的最终目标，我们还需要利用流动布局。它们将允许我们的设计在媒体查询处理的断点之间灵活变化。在下一章中，我们将介绍如何创建流动布局，以平滑过渡我们的媒体查询断点之间的变化。


# 第三章：流式布局和响应式图片

亿万年前，在时间的迷雾中（嗯，是在 20 世纪 90 年代晚期），网站通常以百分比定义宽度。这些基于百分比的宽度可以流畅地调整到屏幕上，并被称为流式布局。

在之后的几年里，即在 2000 年代中期到晚期，人们对固定宽度设计产生了干扰（我责怪那些固执的印刷设计师和他们对像素完美精度的痴迷）。如今，当我们构建响应式网页设计时，我们需要回顾流式布局，并记住它们提供的所有好处。

在第二章, *媒体查询-支持不同的视口*中，我们最终承认，虽然媒体查询允许我们的设计适应不同的视口大小，但通过从一组样式切换到另一组样式，我们需要一些能力在媒体查询提供的“断点”之间灵活调整我们的设计。通过编写“流式”布局，我们可以完美地满足这种需求；它将轻松地拉伸以填补媒体查询断点之间的空白。

2015 年，我们有比以往任何时候都更好的方法来构建响应式网站。现在有一个名为**Flexible Box**（或者更常见的称为**Flexbox**）的新 CSS 布局模块，它现在有足够的浏览器支持，可以在日常使用中使用。

它不仅可以提供流式布局机制。想要轻松地居中内容，更改标记的源顺序，并以相关的轻松方式创建令人惊叹的布局？Flexbox 是适合您的布局机制。本章的大部分内容涉及 Flexbox，涵盖了它所提供的所有令人难以置信的功能。

现在，有了指定的方法和语法，可以向设备发送最相关版本的图像以适应其视口。我们将在本章的最后一节中了解响应式图片的工作原理以及如何使其为我们工作。

在本章中，我们将涵盖：

+   如何将固定像素尺寸转换为比例尺寸

+   考虑现有的 CSS 布局机制及其不足之处

+   了解 Flexbox 布局模块及其提供的好处

+   学习响应式图片的分辨率切换和艺术方向的正确语法

# 将固定像素设计转换为流式比例布局

在像 Photoshop、Illustrator、Fireworks（已故）或 Sketch 这样的程序中制作的图形合成都有固定的像素尺寸。在将设计重新创建为浏览器中的流式布局时，开发人员需要将设计转换为比例尺寸。

有一个非常简单的公式可以将固定尺寸布局转换为响应式/流式等价物，这是响应式网页设计之父 Ethan Marcotte 在他 2009 年的文章*Fluid Grids*（[`alistapart.com/article/FLUIDGRIDS`](http://alistapart.com/article/FLUIDGRIDS)）中提出的：

*目标/上下文=结果*

如果任何类似数学的东西让您感到不安，可以这样想：将您想要的东西的单位除以它所在的单位。理解这一点将使您能够将任何固定尺寸布局转换为响应式/流式等价物。

考虑一个专为桌面设计的非常基本的页面布局。在理想的情况下，我们总是会从较小的屏幕布局转移到桌面布局，但为了说明比例，我们将从后往前看这两种情况。

这是布局的图像：

![将固定像素设计转换为流式比例布局](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_01.jpg)

布局宽度为 960 像素。页眉和页脚都是布局的全宽。左侧区域宽度为 200 像素，右侧区域宽度为 100 像素。即使我的数学能力有限，我也可以告诉您中间部分将宽 660 像素。我们需要将中间和侧面区域转换为比例尺寸。

首先，左侧。它的宽度是 200 个单位（目标）。将该尺寸除以 960 个单位（上下文），我们得到一个结果：.208333333\. 现在，每当我们用这个公式得到结果时，我们需要将小数点向右移动两位。这将给我们 20.8333333%。这是将 200px 描述为 960px 的百分比。

好了，中间部分呢？660（目标）除以 960（上下文）给我们.6875\. 将小数点向右移动两位，我们得到 68.75%。最后，右侧部分。100（目标）除以 960（上下文）给我们.104166667\. 移动小数点，我们得到 10.4166667%。就是这么困难。跟我说：目标，除以上下文，等于结果。

为了证明这一点，让我们在浏览器中快速构建基本布局块。您可以在`example_03-01`中查看布局。这是 HTML：

```html
<div class="Wrap">
    <div class="Header"></div>
    <div class="WrapMiddle">
        <div class="Left"></div>
        <div class="Middle"></div>
        <div class="Right"></div>
    </div>
    <div class="Footer"></div>
</div>
```

这是 CSS：

```html
html,
body {
    margin: 0;
    padding: 0;
}

.Wrap {
    max-width: 1400px;
    margin: 0 auto;
}

.Header {
    width: 100%;
    height: 130px;
    background-color: #038C5A;
}

.WrapMiddle {
    width: 100%;
    font-size: 0;
}

.Left {
    height: 625px;
    width: 20.8333333%;
    background-color: #03A66A;
    display: inline-block;
}

.Middle {
    height: 625px;
    width: 68.75%;
    background-color: #bbbf90;
    display: inline-block;
}

.Right {
    height: 625px;
    width: 10.4166667%;
    background-color: #03A66A;
    display: inline-block;
}

.Footer {
    height: 200px;
    width: 100%;
    background-color: #025059;
}
```

如果您在浏览器中打开示例代码并调整页面大小，您会发现中间部分的尺寸保持相互成比例。您还可以通过调整`.Wrap`值的最大宽度来使布局的边界尺寸变大或变小（在示例中设置为`1400px`）。

### 提示

如果您查看标记并想知道为什么我没有使用`header`，`footer`和`aside`等语义元素，那就不用担心。第四章，*响应式 Web 设计的 HTML5*，详细介绍了这些语义 HTML5 元素。

现在，让我们考虑一下如何在较小的屏幕上具有相同的内容，然后转换为我们已经看到的布局。您可以在`example_03-02`中查看此布局的最终代码。

想法是，对于较小的屏幕，我们将有一个单独的内容'管道'。左侧区域将只能作为'离屏'区域查看；通常是菜单区域或类似的区域，位于可视屏幕区域之外，当按下菜单按钮时滑入。主要内容位于页眉下方，然后右侧部分位于其下方，最后是页脚区域。在我们的示例中，我们可以通过单击页眉的任何位置来显示左侧菜单区域。通常，在真正制作这种设计模式时，会使用菜单按钮来激活侧边菜单。

### 提示

为了在文档的 body 上切换类，我使用了一点 JavaScript。不过这并不是'production ready'，因为我们在 JavaScript 中使用了'click'作为事件处理程序，理想情况下，我们应该有一些触摸的准备（以消除 iOS 设备上仍然存在的 300 毫秒延迟）。

正如您所期望的那样，当将这与我们新掌握的媒体查询技能相结合时，我们可以调整视口和设计，布局就会自动地从一个布局移动到另一个布局，并在两者之间拉伸。

我不打算在这里列出所有的 CSS，它都在`example_03-02`中。不过，这里有一个例子——左侧部分：

```html
.Left {
    height: 625px;
    background-color: #03A66A;
    display: inline-block;
    position: absolute;
    left: -200px;
    width: 200px;
    font-size: .9rem;
    transition: transform .3s;
}

@media (min-width: 40rem) {
    .Left {
        width: 20.8333333%;
        left: 0;
        position: relative;
    }
}
```

您可以看到，首先是在没有媒体查询的情况下，小屏幕布局。然后，在较大的屏幕尺寸上，宽度变得成比例，定位相对，左值设置为零。我们不需要重新编写诸如`height`，`display`或`background-color`之类的属性，因为我们不会改变它们。

这是进步。我们已经结合了我们所学的两种核心响应式 Web 设计技术；将固定尺寸转换为比例，并使用媒体查询来针对视口大小调整 CSS 规则。

### 提示

在我们之前的例子中有两件重要的事情需要注意。首先，您可能想知道是否严格需要包括小数点后的所有数字。虽然这些宽度最终将被浏览器转换为像素，但它们的值将被保留用于未来的计算（例如，更准确地计算嵌套元素的宽度）。因此，我总是建议保留小数点后的数字。

其次，在一个真实的项目中，如果 JavaScript 不可用并且我们需要查看菜单的内容，我们应该做一些准备。我们在第八章中详细处理这种情况，*过渡，变换和动画*。

## 我们为什么需要 Flexbox？

我们现在将详细介绍使用 CSS 弹性盒布局，或者更常见的 Flexbox。

然而，在我们这样做之前，我认为首先考虑现有布局技术的不足是明智的，比如内联块，浮动和表格。

## 内联块和空格

使用内联块作为布局机制的最大问题是它在 HTML 元素之间渲染空格。这不是一个错误（尽管大多数开发人员都希望有一种理智的方法来删除空格），但这意味着一些方法来删除不需要的空格，对我来说，这大约是 95%的时间。有很多方法可以做到这一点，在前面的例子中，我们使用了“字体大小为零”的方法；这种方法并非没有问题和局限性。但是，与其列出使用内联块时去除空格的每种可能的解决方法，不如查看这篇由无法抑制的 Chris Coyier 撰写的文章：[`css-tricks.com/fighting-the-space-between-inline-block-elements/`](http://css-tricks.com/fighting-the-space-between-inline-block-elements/)。

还值得指出的是，没有简单的方法在内联块内垂直居中内容。使用内联块，也没有办法让两个兄弟元素中一个具有固定宽度，另一个自动填充剩余空间。

## 浮动

我讨厌浮动。我说了。它们的好处是它们在各处的工作相当一致。然而，有两个主要的烦恼。

首先，当以百分比指定浮动元素的宽度时，它们的计算宽度在各个浏览器中并不一致（有些浏览器向上舍入，有些向下舍入）。这意味着有时部分内容会意外地下降到其他部分下面，而其他时候它们可能会在一侧留下令人恼火的间隙。

其次，通常需要“清除”浮动，以防止父框/元素坍塌。这很容易做到，但它不断提醒我们，浮动从来不是用作强大的布局机制。

## 表格和表格单元格

不要混淆`display: table`和`display: table-cell`与等效的 HTML 元素。这些 CSS 属性仅模仿其基于 HTML 的兄弟的布局。它们绝对不会影响 HTML 的结构。

我发现使用 CSS 表格布局非常有用。首先，它们可以在元素之间实现一致和强大的垂直居中。此外，设置为`display: table`的元素内部设置为`display: table-cell`的元素可以完美地空出空间；它们不像浮动元素那样遇到四舍五入的问题。您还可以获得对 Internet Explorer 7 的全面支持！

然而，也有局限性。通常需要在项目周围包装额外的元素（为了获得完美的垂直居中的乐趣，表格单元格必须存在于设置为表格的元素内）。还不可能将设置为`display: table-cell`的项目包装到多行中。

总之，所有现有的布局方法都有严重的局限性。幸运的是，有一种新的 CSS 布局方法可以解决这些问题，还有更多。吹号声响起，铺开红地毯。Flexbox 来了。

# 介绍 Flexbox

Flexbox 解决了上述每种显示机制的不足。以下是它的超级功能的简要概述：

+   它可以轻松地垂直居中内容

+   它可以改变元素的视觉顺序

+   它可以自动在框内对齐和排列元素，自动分配它们之间的可用空间。

+   它可以让你看起来年轻 10 岁（可能不是，但在少量经验测试中（我）已经证明可以减轻压力）

## 通往 Flexbox 的崎岖之路

在达到我们今天拥有的相对稳定版本之前，Flexbox 经历了几次重大迭代。例如，考虑从 2009 年版本（[`www.w3.org/TR/2009/WD-css3-flexbox-20090723/`](http://www.w3.org/TR/2009/WD-css3-flexbox-20090723/)）到 2011 年版本（[`www.w3.org/TR/2011/WD-css3-flexbox-20111129/`](http://www.w3.org/TR/2011/WD-css3-flexbox-20111129/)），再到我们基于的 2014 年版本（[`www.w3.org/TR/css-flexbox-1/`](http://www.w3.org/TR/css-flexbox-1/)）。语法差异很大。

这些不同的规范意味着有三个主要的实现版本。您需要关注多少取决于您需要的浏览器支持级别。

## Flexbox 的浏览器支持

让我们先说清楚：Internet Explorer 9、8 或更低版本都不支持 Flexbox。

对于您可能想要支持的其他所有内容（几乎所有移动浏览器），都有一种方法可以享受 Flexbox 的大多数（如果不是全部）功能。您可以在[`caniuse.com/`](http://caniuse.com/)上查看支持信息。

在我们深入 Flexbox 之前，我们需要进行一个简短但必要的偏离。

### 把前缀留给别人

我希望一旦您看到了 Flexbox 的一些示例，您会欣赏到它的实用性，并感到有能力使用它。然而，手动编写支持每个不同 Flexbox 规范所需的所有必要代码是一项艰巨的任务。这里有一个例子。我将设置三个与 Flexbox 相关的属性和值。考虑一下：

```html
.flex {
    display: flex;
    flex: 1;
    justify-content: space-between;
}
```

这就是最新语法中属性和值的样子。然而，如果我们想要支持 Android 浏览器（v4 及以下）和 IE 10，实际上需要的是：

```html
.flex {
    display: -webkit-box;
    display: -webkit-flex;
    display: -ms-flexbox;
    display: flex;
    -webkit-box-flex: 1;
    -webkit-flex: 1;
        -ms-flex: 1;
            flex: 1;
    -webkit-box-pack: justify;
    -webkit-justify-content: space-between;
        -ms-flex-pack: justify;
            justify-content: space-between;
}
```

有必要写出所有这些，因为在过去几年里，随着浏览器发布了新功能的实验版本，它们都带有“供应商前缀”。每个供应商都有自己的前缀。例如，微软的是`-ms-`，WebKit 的是`-webkit-`，Mozilla 的是`-moz-`，等等。对于每个新功能，这意味着需要编写同一属性的多个版本；首先是供应商前缀版本，然后是官方的 W3C 版本。

这个咒语在 Web 历史上的结果是 CSS 看起来像前面的例子。这是在尽可能多的设备上使功能正常工作的唯一方法。如今，供应商很少添加前缀，但在可预见的未来，我们必须接受许多现有浏览器仍然需要前缀来启用某些功能的现实。这让我们回到了 Flexbox，这是供应商前缀的一个极端例子，不仅有多个供应商版本，还有不同的功能规范。记住并理解您需要以当前格式和每个以前的格式编写的所有内容并不是一件有趣的事情。

我不知道你怎么想，但我宁愿把时间花在做一些更有意义的事情上，而不是每次都写出那么多东西！简而言之，如果您打算愤怒地使用 Flexbox，请花时间设置自动前缀解决方案。

#### 选择您的自动前缀解决方案

为了保持理智，准确且轻松地向 CSS 添加供应商前缀，使用某种形式的自动前缀解决方案。目前，我更喜欢 Autoprefixer（[`github.com/postcss/autoprefixer`](https://github.com/postcss/autoprefixer)）。它快速、易于设置且非常准确。

大多数设置都有 Autoprefixer 的版本；您不一定需要基于命令行的构建工具（例如 Gulp 或 Grunt）。例如，如果您使用 Sublime Text，有一个版本可以直接从命令面板中使用：[`github.com/sindresorhus/sublime-autoprefixer`](https://github.com/sindresorhus/sublime-autoprefixer)。Atom、Brackets 和 Visual Studio 也有 Autoprefixer 的版本。

从这一点开始，除非必须说明一个观点，否则在代码示例中将不再有供应商前缀。

# 灵活起来

Flexbox 有四个关键特性：**方向**，**对齐**，**排序**和**灵活性**。我们将通过一些示例来介绍所有这些特性以及它们之间的关系。

这些示例故意简单化；只是移动一些框和它们的内容，以便我们可以理解 Flexbox 的工作原理。

## 完美垂直居中的文本

请注意，这个第一个 Flexbox 示例是`example_03-03`：

![完美垂直居中的文本](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_15.jpg)

这是标记：

```html
<div class="CenterMe">
    Hello, I'm centered with Flexbox!
</div>
```

这是样式整个 CSS 规则：

```html
.CenterMe {
    background-color: indigo;
    color: #ebebeb;
    font-family: 'Oswald', sans-serif;
    font-size: 2rem;
    text-transform: uppercase;
    height: 200px;
    display: flex;
    align-items: center;
    justify-content: center;
}
```

该规则中的大多数属性/值对仅仅是设置颜色和字体大小。我们感兴趣的三个属性是：

```html
.CenterMe {    
    /* other properties */
    display: flex;
    align-items: center;
    justify-content: center;
}
```

如果您没有使用 Flexbox 或相关的 Box Alignment 规范中的任何属性（[`www.w3.org/TR/css3-align/`](http://www.w3.org/TR/css3-align/)），这些属性可能看起来有点陌生。让我们考虑每个属性的作用：

+   `display: flex`：这是 Flexbox 的基础。这仅仅是将项目设置为 Flexbox（而不是块、内联块等）。

+   `align-items`：这在 Flexbox 中沿交叉轴对齐项目（在我们的示例中垂直居中文本）。

+   `justify-content`：这设置了内容的主轴居中。对于 Flexbox 行，您可以将其视为文字处理器中设置文本左对齐、右对齐或居中的按钮（尽管我们很快将看到更多`justify-content`的值）。

好的，在我们深入了解 Flexbox 的属性之前，我们将考虑一些更多的示例。

### 提示

在其中一些示例中，我使用了谷歌托管的字体'Oswald'（并回退到无衬线字体）。在第五章中，*CSS3 – 选择器、排版、颜色模式和新功能*，我们将看看如何使用`@font-face`规则链接到自定义字体文件。

## 偏移项目

想要一个简单的导航项目列表，但其中一个偏移了一边？

这是它的样子：

![偏移项目](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_02.jpg)

这是标记：

```html
<div class="MenuWrap">
    <a href="#" class="ListItem">Home</a>
    <a href="#" class="ListItem">About Us</a>
    <a href="#" class="ListItem">Products</a>
    <a href="#" class="ListItem">Policy</a>
    <a href="#" class="LastItem">Contact Us</a>
</div>
```

这是 CSS：

```html
.MenuWrap {
    background-color: indigo;
    font-family: 'Oswald', sans-serif;
    font-size: 1rem;
    min-height: 2.75rem;
    display: flex;
    align-items: center;
    padding: 0 1rem;
}

.ListItem,
.LastItem {
    color: #ebebeb;
    text-decoration: none;
}

.ListItem {
    margin-right: 1rem;
}

.LastItem {
    margin-left: auto;
}
```

怎么样，没有一个浮动、内联块或表格单元格！当您在包裹元素上设置`display: flex;`时，该元素的子元素就成为了 flex 项目，然后使用 flex 布局模型进行布局。这里的神奇属性是`margin-left: auto`，它使该项目在该侧使用所有可用的边距。

## 颠倒项目的顺序

想要颠倒项目的顺序吗？

![颠倒项目的顺序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_03.jpg)

只需在包裹元素上添加`flex-direction: row-reverse;`并将偏移项上的`margin-left: auto`更改为`margin-right: auto`：

```html
.MenuWrap {
    background-color: indigo;
    font-family: 'Oswald', sans-serif;
    font-size: 1rem;
    min-height: 2.75rem;
    display: flex;
    flex-direction: row-reverse;
    align-items: center;
    padding: 0 1rem;
}

.ListItem,
.LastItem {
    color: #ebebeb;
    text-decoration: none;
}

.ListItem {
    margin-right: 1rem;
}

.LastItem {
    margin-right: auto;
}
```

### 如果我们想要它们垂直布局呢？

简单。在包裹元素上更改为`flex-direction: column;`并删除自动边距：

```html
.MenuWrap {
    background-color: indigo;
    font-family: 'Oswald', sans-serif;
    font-size: 1rem;
    min-height: 2.75rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 0 1rem;
}

.ListItem,
.LastItem {
    color: #ebebeb;
    text-decoration: none;
}
```

### 列反转

想要它们以相反的方向堆叠吗？只需更改为`flex-direction: column-reverse;`就可以了。

### 注意

您应该知道有一个`flex-flow`属性，它是设置`flex-direction`和`flex-wrap`的快捷方式。例如，`flex-flow: row wrap;`会将方向设置为行，并设置换行。然而，至少在最初，我发现更容易分别指定这两个设置。`flex-wrap`属性在最旧的 Flexbox 实现中也不存在，因此可能会在某些浏览器中使整个声明无效。

## 不同的媒体查询内的不同 Flexbox 布局

正如其名称所示，Flexbox 本质上是灵活的，所以在较小的视口上，我们选择列出项目，并在空间允许时选择行样式布局。这对 Flexbox 来说非常简单：

```html
.MenuWrap {
    background-color: indigo;
    font-family: 'Oswald', sans-serif;
    font-size: 1rem;
    min-height: 2.75rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 0 1rem;
}

@media (min-width: 31.25em) {
    .MenuWrap {
        flex-direction: row;
    }    
}

.ListItem,
.LastItem {
    color: #ebebeb;
    text-decoration: none;
}

@media (min-width: 31.25em) {
    .ListItem {
        margin-right: 1rem;
    }
    .LastItem {
        margin-left: auto;
    }
}
```

您可以将其视为`example_03-05`。确保调整浏览器窗口大小以查看不同的布局。

## 内联弹性

Flexbox 有一个内联变体，以补充内联块和内联表格。你可能已经猜到了，它是`display: inline-flex;`。由于它美丽的居中能力，你可以用很少的努力做一些古怪的事情。

![内联弹性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_04.jpg)

这是标记：

```html
<p>Here is a sentence with a <a href="http://www.w3.org/TR/css-flexbox-1/#flex-containers" class="InlineFlex">inline-flex link</a>.</p>
```

这是那个的 CSS：

```html
.InlineFlex {
    display: inline-flex;
    align-items: center;    
    height: 120px;
    padding: 0 4px;
    background-color: indigo;
    text-decoration: none;
    border-radius: 3px;
    color: #ddd;
}
```

当项目被匿名设置为`inline-flex`（例如，它们的父元素没有设置为`display: flex;`）时，它们保留元素之间的空白，就像 inline-block 或 inline-table 一样。然而，如果它们在一个 flex 容器中，那么空白将被移除，就像在表格中的 table-cell 项目一样。

当然，你并不总是需要在 Flexbox 中居中项目。有许多不同的选项。让我们现在来看看这些。

## Flexbox 对齐属性

如果你想玩玩这个例子，你可以在`example_03-07`找到它。记住你下载的例子代码将会在我们完成这一部分时的位置，所以如果你想“跟着做”，你可能更喜欢删除示例文件中的 CSS，然后重新开始。

理解 Flexbox 对齐的重要事情是轴的概念。有两个轴要考虑，'主轴'和'交叉轴'。每个代表什么取决于 Flexbox 的方向。例如，如果你的 Flexbox 的方向设置为`row`，主轴将是水平轴，交叉轴将是垂直轴。

相反，如果你的 Flexbox 方向设置为`column`，主轴将是垂直轴，交叉轴将是水平轴。

规范([`www.w3.org/TR/css-flexbox-1/#justify-content-property`](http://www.w3.org/TR/css-flexbox-1/#justify-content-property))提供了以下插图来帮助作者：

![Flexbox 对齐属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_11.jpg)

这是我们示例的基本标记：

```html
<div class="FlexWrapper">
    <div class="FlexInner">I am content in the inner Flexbox.</div>
</div>
```

让我们设置基本的 Flexbox 相关样式：

```html
.FlexWrapper {
    background-color: indigo;
    display: flex;
    height: 200px;
    width: 400px;
}

.FlexInner {
    background-color: #34005B;
    display: flex;
    height: 100px;
    width: 200px;
}
```

在浏览器中，这产生了这个效果：

![Flexbox 对齐属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_06.jpg)

好了，让我们来测试一下这些属性的效果。

### align-items 属性

`align-items`属性将项目在交叉轴上定位。如果我们将这个属性应用到我们的包裹元素上，就像这样：

```html
.FlexWrapper {
    background-color: indigo;
    display: flex;
    height: 200px;
    width: 400px;
    align-items: center;
}
```

正如你所想象的，盒子中的项目垂直居中：

![align-items 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_05.jpg)

相同的效果将应用于任何数量的子元素。

### align-self 属性

有时，你可能只想将一个项目拉到不同的对齐方式。单独的 flex 项目可以使用`align-self`属性来对齐自己。在这一点上，我将删除之前的对齐属性，将另外两个项目添加到标记中（它们已经被赋予了`.FlexInner` HTML 类），并在中间的项目上添加另一个 HTML 类（`.AlignSelf`），并使用它来添加`align-self`属性。此时查看 CSS 可能更具说明性：

```html
.FlexWrapper {
    background-color: indigo;
    display: flex;
    height: 200px;
    width: 400px;
}
.FlexInner {
    background-color: #34005B;
    display: flex;
    height: 100px;
    width: 200px;
}

.AlignSelf {
    align-self: flex-end;
}
```

这是在浏览器中的效果：

![align-self 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_07.jpg)

哇！Flexbox 真的让这些变化变得微不足道。在这个例子中，`align-self`的值被设置为`flex-end`。在看主轴上的对齐之前，让我们考虑一下我们可以在交叉轴上使用的可能值。

### 可能的对齐值

对于交叉轴对齐，Flexbox 有以下可能的值：

+   `flex-start`：将元素设置为`flex-start`会使其从其 flex 容器的“起始”边开始

+   `flex-end`：设置为`flex-end`会将元素对齐到 flex 容器的末尾

+   `center`：将其放在 flex 容器的中间

+   `baseline`：设置容器中所有 flex 项目，使它们的基线对齐

+   `stretch`：使项目拉伸到其 flex 容器的大小（在交叉轴上）

### 注意

使用这些属性有一些特殊之处，所以如果有什么不顺利的地方，总是参考规范中的任何边缘情况场景：[`www.w3.org/TR/css-flexbox-1/`](http://www.w3.org/TR/css-flexbox-1/)。

### justify-content 属性

主轴上的对齐由`justify-content`控制（对于非 Flexbox/block-level 项目，还提出了`justify-self`属性（[`www.w3.org/TR/css3-align/`](http://www.w3.org/TR/css3-align/)）。`justify-content`的可能值包括：

+   `flex-start`

+   `flex-end`

+   `center`

+   `space-between`

+   `space-around`

前三个正是你现在所期望的。然而，让我们看看`space-between`和`space-around`的作用。考虑这个标记：

```html
<div class="FlexWrapper">
    <div class="FlexInner">I am content in the inner Flexbox 1.</div>
    <div class="FlexInner">I am content in the inner Flexbox 2.</div>
    <div class="FlexInner">I am content in the inner Flexbox 3.</div>
</div>
```

然后考虑这个 CSS。我们将三个 flex 项（`FlexInner`）的宽度分别设置为 25%，并由一个设置为 100%宽度的 flex 容器（`FlexWrapper`）包裹。

```html
.FlexWrapper {
    background-color: indigo;
    display: flex;
    justify-content: space-between;
    height: 200px;
    width: 100%;
}
.FlexItems {
    background-color: #34005B;
    display: flex;
    height: 100px;
    width: 25%;
}
```

由于这三个项目只占用了可用空间的 75%，`justify-content`解释了我们希望浏览器如何处理剩余空间。`space-between`的值在项目之间放置相等的空间，而`space-around`则将其放置在周围。也许这里的屏幕截图会有所帮助：这是`space-between`。

![justify-content 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_08.jpg)

如果我们切换到`space-around`，会发生什么呢？

![justify-content 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_09.jpg)

我认为这两个值非常方便。

### 提示

Flexbox 的各种对齐属性目前正在被规范为 CSS Box Alignment Module Level 3。这应该为其他显示属性（如`display: block;`和`display: table;`）提供相同的基本对齐功能。规范仍在进行中，因此请查看[`www.w3.org/TR/css3-align/`](http://www.w3.org/TR/css3-align/)的状态。

## flex 属性

我们已经在这些 flex 项上使用了`width`属性，但也可以使用`flex`属性定义宽度或'灵活性'。为了说明这一点，考虑另一个例子；相同的标记，但是为项目修改了 CSS：

```html
.FlexItems {
    border: 1px solid #ebebeb;
    background-color: #34005B;
    display: flex;
    height: 100px;
    flex: 1;
}
```

`flex`属性实际上是指定三个单独属性的一种简写方式：`flex-grow`、`flex-shrink`和`flex-basis`。规范在[`www.w3.org/TR/css-flexbox-1/`](http://www.w3.org/TR/css-flexbox-1/)中更详细地涵盖了这些单独的属性。然而，规范建议作者使用`flex`简写属性，这就是我们在这里使用的，明白了吗？

![flex 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_13.jpg)

对于 flex 项，如果存在`flex`属性（并且浏览器支持），则使用该属性来调整项目的大小，而不是宽度或高度值（如果存在）。即使在`flex`属性之后指定了宽度或高度值，它仍然没有效果。让我们看看每个值的作用。

+   `flex-grow`（传递给 flex 的第一个值）是与其他 flex 项相关的，当有空闲空间时，flex 项可以增长的量

+   `flex-shrink`是与其他 flex 项相关的，当没有足够的空间时，flex 项可以缩小的量

+   `flex-basis`（传递给 Flex 的最后一个值）是 flex 项的基础大小

虽然可能只写`flex: 1`，但我建议将所有值写入`flex`属性。我认为这样更清楚你的意图。例如：`flex: 1 1 auto`表示项目将占用可用空间的 1 部分，当空间不足时它也会缩小 1 部分，而弹性的基础大小是内容的固有宽度（如果没有弹性，内容的大小将是多少）。

让我们再试一下：`flex: 0 0 50px`表示此项目既不会增长也不会缩小，其基础大小为 50px（因此无论有多少空闲空间，它都将是 50px）。`flex: 2 0 50%`呢？这将占用两个'部分'的可用空间，它不会缩小，其基础大小为 50%。希望这些简短的例子能让 flex 属性变得更加清晰。

### 提示

如果将`flex-shrink`值设置为零，则 flex 基础实际上就像最小宽度一样。

您可以将`flex`属性视为设置比例的一种方式。每个 flex 项设置为 1，它们各自占据相等的空间：

![flex 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_10.jpg)

好了，为了测试这个理论，让我们修改标记中的 HTML 类：

```html
<div class="FlexWrapper">
    <div class="FlexItems FlexOne">I am content in the inner Flexbox 1.</div>
    <div class="FlexItems FlexTwo">I am content in the inner Flexbox 2.</div>
    <div class="FlexItems FlexThree">I am content in the inner Flexbox 3.</div>
</div>
```

然后这是修改后的 CSS：

```html
.FlexItems {
    border: 1px solid #ebebeb;
    background-color: #34005B;
    display: flex;
    height: 100px;
}

.FlexOne {
    flex: 1.5 0 auto;
}

.FlexTwo,
.FlexThree {
    flex: 1 0 auto;
}
```

在这种情况下，`FlexOne`占据了`FlexTwo`和`FlexThree`占据的 1.5 倍空间。

这种简写语法确实非常有用，可以快速建立项目之间的关系。例如，如果有请求说，“这需要比其他项目宽 1.8 倍”，您可以很容易地使用 flex 属性满足该请求。

希望非常强大的 flex 属性现在开始有点意义了？

我可以写上关于 Flexbox 的章节！我们可以看很多例子。然而，在我们继续本章的另一个主题（响应式图片）之前，我还有两件事想与您分享。

## 简单的粘性页脚

假设您希望在内容不足以将其推到底部时，页脚位于视口底部。以前实现这一点总是很麻烦，但使用 Flexbox 很简单。考虑以下标记（可以在`example_03-08`中查看）：

```html
<body>
    <div class="MainContent">
        Here is a bunch of text up at the top. But there isn't enough content to push the footer to the bottom of the page.
    </div>
    <div class="Footer">
        However, thanks to flexbox, I've been put in my place.
    </div>
</body>
```

这是 CSS：

```html
html,
body {
    margin: 0;
    padding: 0;
}

html {
    height: 100%;
}

body {
    font-family: 'Oswald', sans-serif;
    color: #ebebeb;
    display: flex;
    flex-direction: column;
    min-height: 100%;
}

.MainContent {
    flex: 1;
    color: #333;
    padding: .5rem;
}

.Footer {
    background-color: violet;
    padding: .5rem;
}
```

在浏览器中查看并测试向`.MainContentdiv`添加更多内容。您会发现当内容不足时，页脚会固定在视口底部。当有足够内容时，它会显示在内容下方。

这是因为我们的`flex`属性设置为在有空间时增长。由于我们的 body 是一个 100%最小高度的 flex 容器，主内容可以扩展到所有可用空间。很美。

## 更改源顺序

自 CSS 诞生以来，在网页中切换 HTML 元素的视觉顺序只有一种方法。通过将元素包装在设置为`display: table`的东西中，然后在元素之间切换`display`属性，即在`display: table-caption`（将其放在顶部），`display: table-footer-group`（将其发送到底部）和`display: table-header-group`（将其发送到`display: table-caption`下方的项目）。然而，尽管这种技术很强大，但这是一个幸运的意外，而不是这些设置的真正意图。

然而，Flexbox 内置了视觉源重新排序。让我们看看它是如何工作的。

考虑这个标记：

```html
<div class="FlexWrapper">
    <div class="FlexItems FlexHeader">I am content in the Header.</div>
    <div class="FlexItems FlexSideOne">I am content in the SideOne.</div>
    <div class="FlexItems FlexContent">I am content in the Content.</div>
    <div class="FlexItems FlexSideTwo">I am content in the SideTwo.</div>
    <div class="FlexItems FlexFooter">I am content in the Footer.</div>
</div>
```

您可以在这里看到包装器中的第三个项目具有`FlexContent`的 HTML 类-想象一下这个`div`将保存页面的主要内容。

好的，让我们保持简单。我们将为更容易区分各个部分添加一些简单的颜色，并使这些项目按照它们在标记中出现的顺序一个接一个地排列。

```html
.FlexWrapper {
    background-color: indigo;
    display: flex;
    flex-direction: column;
}

.FlexItems {
    display: flex;
    align-items: center;
    min-height: 6.25rem;
    padding: 1rem;
}

.FlexHeader {
    background-color: #105B63;    
}

.FlexContent {
    background-color: #FFFAD5;
}

.FlexSideOne {
    background-color: #FFD34E;
}

.FlexSideTwo {
    background-color: #DB9E36;
}

.FlexFooter {
    background-color: #BD4932;
}
```

在浏览器中呈现如下：

![更改源顺序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_16.jpg)

现在，假设我们想要交换`.FlexContent`的顺序成为第一项，而不改变标记。使用 Flexbox 很简单，只需添加一个属性/值对：

```html
.FlexContent {
    background-color: #FFFAD5;
    order: -1;
}
```

`order`属性让我们简单而明智地修改 Flexbox 中项目的顺序。在这个例子中，值为`-1`表示我们希望它在所有其他项目之前。

### 提示

如果您想频繁切换项目的顺序，我建议更加声明性地为每个添加一个顺序号。当您将它们与媒体查询结合使用时，这样做会使事情变得更容易理解。

让我们将我们的新源顺序更改功能与一些媒体查询结合起来，以在不同尺寸下产生不同的布局和不同的顺序。

### 注意

注意：您可以在`example_03-09`中查看此完成的示例。

由于通常认为将主要内容放在文档开头是明智的，让我们将标记修改为这样：

```html
<div class="FlexWrapper">
    <div class="FlexItems FlexContent">I am content in the Content.</div>
    <div class="FlexItems FlexSideOne">I am content in the SideOne.</div>
    <div class="FlexItems FlexSideTwo">I am content in the SideTwo.</div>
    <div class="FlexItems FlexHeader">I am content in the Header.</div>
    <div class="FlexItems FlexFooter">I am content in the Footer.</div>
</div>
```

首先是页面内容，然后是我们的两个侧边栏区域，然后是页眉，最后是页脚。由于我将使用 Flexbox，我们可以按照对文档有意义的顺序来构造 HTML，而不管需要如何在视觉上布局。

对于最小的屏幕（在任何媒体查询之外），我将按照这个顺序进行：

```html
.FlexHeader {
    background-color: #105B63;
    order: 1;
}

.FlexContent {
    background-color: #FFFAD5;
    order: 2;
}

.FlexSideOne {
    background-color: #FFD34E;
    order: 3;
}

.FlexSideTwo {
    background-color: #DB9E36;
    order: 4;
}

.FlexFooter {
    background-color: #BD4932;
    order: 5;
}
```

这在浏览器中给我们的是这样的：

![更改源顺序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_12.jpg)

然后，在断点处，我切换到这个：

```html
@media (min-width: 30rem) {
    .FlexWrapper {
        flex-flow: row wrap;
    }
    .FlexHeader {
        width: 100%;
    }
    .FlexContent {
        flex: 1;
        order: 3;
    }
    .FlexSideOne {
        width: 150px;
        order: 2;
    }
    .FlexSideTwo {
        width: 150px;
        order: 4;
    }
    .FlexFooter {
        width: 100%;
    }
}
```

这在浏览器中给我们的是这样的：

![更改源顺序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_03_14.jpg)

### 注意

在这个例子中，使用了快捷方式`flex-flow: row wrap`。这允许 flex 项目换行到多行。这是支持较差的属性之一，因此，取决于需要多远的支持，可能需要将内容和两个侧边栏包装在另一个元素中。

## 总结 Flexbox

使用 Flexbox 布局系统时有无限的可能性，由于其固有的“灵活性”，它非常适合响应式设计。如果你以前从未使用过 Flexbox 构建任何东西，所有新的属性和值可能看起来有点奇怪，有时很容易实现以前需要更多工作的布局。要根据最新版本的规范检查实施细节，请确保查看[`www.w3.org/TR/css-flexbox-1/`](http://www.w3.org/TR/css-flexbox-1/)。

我认为你会喜欢使用 Flexbox 构建东西。

### 注意

紧随灵活盒子布局模块之后的是网格布局模块 1 级：[`www.w3.org/TR/css3-grid-layout/`](http://www.w3.org/TR/css3-grid-layout/)。

与 Flexbox 相比，它相对不成熟（就像 Flexbox 的早期历史一样，网格布局已经经历了一些重大变化），因此我们在这里不会详细讨论它。然而，这绝对是一个值得关注的属性，因为它向我们承诺了更多的布局能力。

# 响应式图片

根据用户设备和环境的特点为用户提供适当的图像一直是一个棘手的问题。这个问题在响应式网页设计的出现时就被突显出来，其本质是为每个设备提供单一的代码库。

## 响应式图片的固有问题

作为作者，你无法知道或计划每个可能访问你网站的设备。只有浏览器知道在它提供和渲染内容时使用它的设备的特点（例如屏幕尺寸和设备功能）。

相反，只有作者（你和我）知道我们拥有哪些图像的版本。例如，我们可能有同一图像的三个版本。小，中，大：每个版本都有不同的尺寸，以涵盖各种屏幕尺寸和密度的情况。浏览器不知道这一点。我们必须告诉它。

总结这个难题，我们知道我们拥有的图像是一半的解决方案，浏览器知道访问网站的设备的特点以及最合适的图像尺寸和分辨率是另一半的解决方案。

我们如何告诉浏览器我们拥有哪些图像，以便它可以为用户选择最合适的图像？

在响应式网页设计的最初几年，没有指定的方法。幸运的是，现在我们有了嵌入内容规范：[`html.spec.whatwg.org/multipage/embedded-content.html`](https://html.spec.whatwg.org/multipage/embedded-content.html)。

嵌入内容规范描述了处理图像的简单分辨率切换（以便在更高分辨率屏幕上接收图像的更高分辨率版本）和“艺术方向”情况的方法，即作者希望用户根据一些设备特性（比如媒体查询）看到完全不同的图像。

演示响应式图像示例是棘手的。在单个屏幕上无法欣赏到特定语法或技术加载的不同图像。因此，接下来的示例将主要是代码，你只能相信我，它将在支持的浏览器中产生你需要的结果。

让我们看看你可能需要响应式图片的两种最常见情况。这些是在需要不同分辨率时切换图像，以及根据可用的视口空间改变图像。

## 使用 srcset 进行简单的分辨率切换

假设你有图像的三个版本。它们看起来都一样，只是一个是为较小的视口而设计的较小尺寸或分辨率，另一个是为中等尺寸视口而设计的，最后一个更大的版本适用于其他任何视口。以下是我们如何让浏览器知道我们有这三个版本可用。

```html
<img src="img/scones_small.jpg" srcset="scones_medium.jpg 1.5x, scones_large.jpg 2x" alt="Scones taste amazing">
```

这是响应式图片中最简单的情况，所以让我们确保语法完全合理。

首先，`src`属性，你可能已经熟悉了，这里有一个双重作用；它指定了图像的小尺寸 1x 版本，如果浏览器不支持`srcset`属性，它也充当备用图像。这就是为什么我们在小图像上使用它。这样，忽略`srcset`信息的旧浏览器将得到最小且性能最佳的图像。

对于理解`srcset`的浏览器，我们在该属性后提供了一个逗号分隔的图像列表，供浏览器选择。在图像名称（如`scones_medium.jpg`）之后，我们发出了一个简单的分辨率提示。在这个例子中，使用了 1.5x 和 2x，但任何整数都是有效的。例如，3x 或 4x 也可以（只要你能找到适当分辨率的屏幕）。

然而，这里存在一个问题；一个 1440 像素宽，1x 屏幕的设备将得到与 480 像素宽，3x 屏幕相同的图像。这可能是期望的效果，也可能不是。

## 使用 srcset 和 sizes 进行高级切换

让我们考虑另一种情况。在响应式网页设计中，图像在较小的视口上可能是整个视口宽度，但在较大的尺寸上可能只有视口宽度的一半。第一章中的主要示例，“响应式网页设计的基本要素”，就是一个典型的例子。以下是我们如何向浏览器传达这些意图的方式：

```html
<img srcset="scones-small.jpg 450w, scones-medium.jpg 900w" sizes="(min-width: 17em) 100vw, (min-width: 40em) 50vw" src="img/scones-small.jpg" alt="Scones">
```

在图像标签内部，我们再次使用`srcset`。然而，这一次，在指定图像之后，我们添加了一个带有 w 后缀的值。这告诉浏览器图像有多宽。在我们的例子中，我们有一个宽度为 450 像素的图像（名为`scones-small.jpg`）和一个宽度为 900 像素的图像（名为`scones-medium.jpg`）。重要的是要注意，这个带有`w`后缀的值并不是一个“真实”的尺寸。它只是对浏览器的一种指示，大致相当于“CSS 像素”的宽度。

### 提示

CSS 中究竟是什么定义了像素？我自己也想知道。然后我在[`www.w3.org/TR/css3-values/`](http://www.w3.org/TR/css3-values/)找到了解释，但后悔了。

当我们考虑`sizes`属性时，这个带有`w`后缀的值更有意义。`sizes`属性允许我们向浏览器传达我们图像的意图。在我们之前的例子中，第一个值相当于“对于至少宽度为 17em 的设备，我打算显示大约 100vw 宽的图像”。

### 注意

如果一些使用的单位，比如 vh（其中 1vh 等于视口高度的 1%）和 vw（其中 1vw 等于视口宽度的 1%）不合理，请务必阅读第五章，“CSS3 – 选择器，排版，颜色模式和新特性”。

第二部分有效地是，“嗨，浏览器，对于至少 40em 宽的设备，我只打算以 50vw 的宽度显示图像”。这可能看起来有点多余，直到你考虑 DPI（或 DPR，设备像素比）。例如，在一个 320px 宽的设备上，分辨率为 2 倍（如果以全宽度显示需要 640px 宽的图像），浏览器可能会决定 900px 宽的图像实际上更合适，因为它是满足所需尺寸的第一个选项。

### 你说浏览器可能会选择一张图像而不是另一张？

重要的是要记住，`sizes`属性只是对浏览器的提示。这并不一定意味着浏览器总是会遵守。这是一件好事。相信我，真的是。这意味着将来，如果浏览器有一种可靠的方式来确定网络条件，它可能会选择提供一张图像而不是另一张，因为在那时它知道的事情我们在这个时候作为作者可能无法知道。也许用户在他们的设备上设置了“只下载 1x 图像”或“只下载 2x 图像”的选项；在这些情况下，浏览器可以做出最佳选择。

与浏览器决定相反的是使用`picture`元素。使用这个元素可以确保浏览器提供你要求的确切图像。让我们看看它是如何工作的。

## 使用 picture 元素进行艺术指导

你可能会发现自己处于的最后一种情况是，你有不同的图像适用于不同的视口尺寸。例如，再次考虑我们基于蛋糕的例子，来自第一章，“响应式网页设计的基本原理”。也许在最小的屏幕上，我们想要一个特写的司康饼，上面有大量果酱和奶油。对于更大的屏幕，也许我们有一个更宽的图像想要使用。也许是一张装满各种蛋糕的桌子的全景照。最后，对于更大的视口，也许我们想要看到一个村庄街道上的蛋糕店的外部，人们坐在外面吃蛋糕和喝茶（我知道，听起来像天堂，对吧？）。我们需要三种在不同视口范围内最合适的图像。以下是我们如何使用`picture`解决这个问题的方法：

```html
<picture>
    <source media="(min-width: 30em)" srcset="cake-table.jpg">
    <source media="(min-width: 60em)" srcset="cake-shop.jpg">
    <img src="img/scones.jpg" alt="One way or another, you WILL get cake.">
</picture>
```

首先，要注意的是，当你使用`picture`元素时，它只是一个包装器，用于方便其他图像进入`img`标签。如果你想以任何方式样式化图像，应该关注的是`img`。

其次，在这里，`srcset`属性的工作方式与前面的示例完全相同。

第三，`img`标签提供了你的备用图像，也是如果浏览器理解`picture`但没有匹配的媒体定义时将显示的图像。只是为了非常清楚；不要在`picture`元素内省略`img`标签，否则事情就会变得不好。

`picture`的关键区别在于我们有一个`source`标签。在这里，我们可以使用媒体查询样式表达式明确告诉浏览器在匹配情况下使用哪个资源。例如，前面示例中的第一个告诉浏览器，“嘿，如果屏幕宽度至少为 30em，就加载`cake-table.jpg`图像”。只要条件匹配，浏览器就会忠实地遵守。

### 方便新潮的图像格式

作为一个额外的好处，`picture`还可以帮助我们提供图像的其他格式。'WebP'（更多信息请参阅[`developers.google.com/speed/webp/`](https://developers.google.com/speed/webp/)）是一种新的格式，许多浏览器不支持（[`caniuse.com/`](http://caniuse.com/)）。对于那些支持的浏览器，我们可以提供该格式的文件，对于不支持的浏览器，我们可以提供更常见的格式：

```html
<picture>
    <source type="image/webp" srcset="scones-baby-yeah.webp">
    <img src="img/scones-baby-yeah.jpg" alt="Again, you WILL eat cake.">
</picture>
```

希望现在这已经变得更加简单明了。我们不再使用`media`属性，而是使用`type`（我们将在第四章中更多地使用 type 属性，*响应式 Web 设计的 HTML5*），尽管它更常用于指定视频来源（可能的视频来源类型可以在[`html.spec.whatwg.org/multipage/embedded-content.html`](https://html.spec.whatwg.org/multipage/embedded-content.html)找到），但在这里允许我们定义 WebP 作为首选图像格式。如果浏览器可以显示它，它将显示，否则它将获取`img`标签中的默认图像。

### 提示

有很多旧版浏览器永远无法使用官方的 W3C 响应式图像。除非有特定原因不这样做，我的建议是允许内置的回退功能发挥作用。使用一个合理大小的回退图像为他们提供良好的体验，并允许更有能力的设备享受增强的体验。

# 总结

在本章中，我们涵盖了很多内容。我们花了相当多的时间来熟悉 Flexbox，这是最新、最强大、现在也得到了很好支持的布局技术。我们还介绍了如何根据我们需要解决的问题，为我们的用户提供任意数量的替代图像。通过使用`srcset`、`sizes`和`picture`，我们的用户应该始终能够获得最适合他们需求的图像，无论是现在还是将来。

到目前为止，我们已经看了很多 CSS 及其一些新兴的可能性和能力，但只有在响应式图像中，我们才看到了更现代的标记。让我们下一步来解决这个问题。

下一章将全面介绍 HTML5。它提供了什么，与上一个版本相比有什么变化，以及在很大程度上，我们如何最好地利用其新的语义元素来创建更清晰、更有意义的 HTML 文档。
