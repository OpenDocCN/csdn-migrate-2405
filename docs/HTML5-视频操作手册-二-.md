# HTML5 视频操作手册（二）

> 原文：[`zh.annas-archive.org/md5/E8CC40620B67F5E68B6D72199B86F6A9`](https://zh.annas-archive.org/md5/E8CC40620B67F5E68B6D72199B86F6A9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：创建可访问的体验

在本章中，我们将涵盖：

+   测试浏览器支持

+   添加跳转导航

+   添加元标记

+   使用标签中的语义描述供屏幕阅读器使用

+   提供备用站点视图

+   使用`hgroup`创建可访问的标题区域

+   为不支持的浏览器显示备用内容

+   使用 WAI-ARIA

# 介绍

> “良好的可访问性设计是良好的网页设计。”

到目前为止，我们已经讨论了很多关于语义网页编码的内容，以及 HTML5 允许我们将这种命名方法提升到一个以前无法达到的新水平。我们的讨论大部分集中在语义网页编码如何使我们作为网页开发人员的工作更容易、更快速和更有意义。

在本章中，我们将关注语义网页编码如何改善我们的受众在网上的体验。现在，应用语义标签——有意义的标签而不仅仅是表现性的标签——对于屏幕阅读器以及依赖它们来浏览我们创建的网站、应用程序和界面的人来说变得更加重要。

如果您曾经为军方、学术机构或从美国联邦政府获得资金的任何人编写过网站、应用程序或界面，您一定听说过第 508 条。

与 HTML 或 CSS 验证不同，第 508 条验证的工作方式不同。在 HTML 或 CSS 中，代码要么有效，要么无效。这是二进制的。但在第 508 条中不是这样。在这种情况下，有三种不同级别的验证，每一级别都更难达到。

在本章中，我们将讨论如何使用 HTML5 来测试浏览器支持，添加跳转导航和元标记，使用标签中的语义描述来供屏幕阅读器使用，提供备用站点视图，使用新的 HTML5 `hgroup`元素来创建可访问的标题区域，为不支持的浏览器显示备用内容，并使用 WAI-ARIA。

现在，让我们开始吧！

# 测试浏览器支持

让我们从使用由 Faruk Ates 和 Paul Irish 开发的开源 Modernizr 项目开始：[`modernizr.com`](http://modernizr.com)。根据该网站，Modernizr 使用特性检测来测试当前浏览器对即将推出的特性的支持情况。

### 提示

Modernizr 概念旨在进行特性检测，而不是浏览器检测。这是一个微妙但重要的区别。与其做出广泛的假设，Modernizr 方法检测浏览器支持的特性。

![测试浏览器支持](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_04_01.jpg)

## 如何做…

下载 Modernizr JavaScript 文件并在您的标记的`head`部分引用它。然后将“no-js”类添加到您的`body`元素中，就像这样：

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Title</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<script src="img/modernizr-1.6.min.js"></script>
</head>
<body class="no-js">
</body>
</html>

```

## 它是如何工作的…

在您的标记中包含该脚本和简单的 body 类，使 Modernizr 能够检测 Web 浏览器支持以下哪些项目。然后它将添加类和 JavaScript API 来检测对某些特性的支持。如果给定浏览器不支持这些特性，Modernizr 就不会添加它们。

+   @font-face

+   Canvas

+   Canvas 文本

+   HTML5 音频

+   HTML5 视频

+   rgba()

+   hsla()

+   border-image:

+   border-radius:

+   box-shadow:

+   text-shadow:

+   不透明度：

+   多重背景

+   灵活的盒模型

+   CSS 动画

+   CSS 列

+   CSS 渐变

+   CSS 反射

+   CSS 2d 转换

+   CSS 3d 转换

+   CSS 过渡

+   地理位置 API

+   localStorage

+   sessionStorage

+   SVG

+   SMIL

+   SVG 裁剪

+   内联 SVG

+   拖放

+   hashchange

+   X 窗口消息

+   历史管理

+   applicationCache

+   触摸事件

+   Web 套接字

+   Web Workers

+   Web SQL 数据库

+   WebGL

+   IndexedDB

+   输入类型

+   输入属性

## 还有更多…

现代化 2 Beta 中的新功能是能够自定义 JavaScript 下载。所以现在，如果您不关心特定功能（比如拖放），您可以取消选择它，而不让 Modernizr 检查它。在这里阅读更多信息：[`modernizr.github.com/Modernizr/2.0-beta`](http://modernizr.github.com/Modernizr/2.0-beta)。

### 展望未来

来自网站：

> "Modernizr 是一个小巧简单的 JavaScript 库，它可以帮助你利用新兴的 Web 技术（CSS3、HTML5），同时仍然对尚未支持这些新技术的旧浏览器保持精细的控制。"

### Modernizr 的真正作用

Modernizr 不会添加或启用浏览器中原生不存在的功能。例如，如果你的浏览器不支持输入属性，Modernizr 不会自动为你的浏览器添加这个功能。这是不可能的。它只是让你作为开发者知道你可以使用什么。

### 出于正确的原因

有些网页开发者使用 Modernizr 是因为他们在某篇文章中读到他们应该使用它。这没问题，但你比他们聪明。你看到了在浏览器中检测这些功能如何更好地告诉你如何提供无障碍体验，如果浏览器不原生支持某些属性。你真聪明，也很帅！

## 另请参阅

作者 Gil Fink 为微软写了简单而简洁的文章["使用 Modernizr 检测 HTML5 功能"](http://"Detecting) *HTML5 Features Using Modernizr"*，供进一步阅读，网址为[`blogs.microsoft.co.il/blogs/gilf/archive/2011/01/09/detecting-html5-features-using-modernizr.aspx`](http://blogs.microsoft.co.il/blogs/gilf/archive/2011/01/09/detecting-html5-features-using-modernizr.aspx)。

# 添加跳过导航

跳过重复元素如导航对使用屏幕阅读器的人是有益的。想象一下，当访问一个网站时，你需要读完每一个导航元素才能继续查看主要内容。那会很烦人，不是吗？对于使用屏幕阅读器的人来说也是一样。让我们看看如何不让我们的一部分受众感到烦恼的简单方法。

## 准备工作

在这个例子中，我们要做的是创建一个简单但特殊的不可见锚点，这样我们的屏幕阅读器朋友就可以选择跳过我们的导航，直接进入我们的网站内容。

## 如何做...

如果你在 HTML 方面有一段时间了，你肯定曾经创建过跳过导航。它可能看起来像这样：

```html
<a class="skip" href="#content">Skipnav</a>

```

你的 CSS 可能包括这样的内容来使锚点不可见：

```html
.skip {display: none}

```

包含主要内容的第一个`div`然后包含了另一个看起来像这样的不可见锚点：

```html
<h2><a name="content"></a></h2>

```

多年来一切都很顺利。它一直工作得很好。在 HTML5 中也应该工作，对吧？嗯，猜猜看？它不工作。让我们看看为什么。

## 它是如何工作的...

在 HTML5 中，锚点标签的`name`属性不再有效。还记得我在第一章中说的关于创建 HTML5 规范的方法是“铺平牛路”的吗？嗯，这次不是。这次牛路已经被移除了。所以现在我们要做的是：

我们将保留最初的标记：

```html
<a class="skip" href="#content">Skipnav</a>

```

我们将保留隐藏锚点的 CSS 代码：

```html
.skip {display: none}

```

但这次我们在第二部分标记中要做的不同：

```html
<h2 id="content"></h2>

```

当我们移除了锚点时，我们将其`name`属性从`ID`重命名并添加到`h2`中。现在它有效，并符合 HTML5 规范。很简单！

## 还有更多...

跳过导航的能力是我们开发者可以做的最常见的事情之一，也是最容易实现的，以支持我们不同能力的受众。考虑重新访问你开发过的旧网站，更新（或添加）跳过导航，将`DOCTYPE`切换到 HTML5，你就可以使用最新的技术，同时支持无障碍。

### 完整的浏览器支持

跳过导航是所有主要网页浏览器都支持的一个变化。作者在这本书中很少有机会这样说，所以这真是一种解脱！

### 少即是多

在不久的将来，当屏幕阅读器得到更新时，我们将能够使用 Web 可访问性倡议-可访问丰富互联网应用程序角色，并使用新的`nav`元素来实现跳过导航的功能。更少的标记等于更好的！

[`webstandards.org`](http://webstandards.org)网站采用了一种有趣的方法，只有在视力用户悬停在上面时才显示跳过`nav`。

![Less equals more](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_04_02.jpg)

## 另请参阅

[`html5accessibility.com`](http://html5accessibility.com)是一个很棒的资源，提供有关新的 HTML5 元素在 Web 浏览器中的可访问支持以及为使用辅助技术的人提供信息。

# 添加元标签

> “语言标签标识了人类为了向其他人传达信息而说、写或以其他方式传达的自然语言。计算机语言明确排除在外。HTTP 在 Accept-Language 和 Content-Language 字段中使用语言标签。”- 万维网联盟的超文本传输协议规范

## 准备工作

如果您正在考虑您或您客户网站的可访问性（您应该考虑！），您将希望确保使用屏幕阅读器的人能够以您打算的语言阅读到您的信息。我们将看看如何做到这一点。

## 如何做...

首先，确定您希望网站阅读的语言。它可以是英语、法语、克林贡语或任何组合。请参阅最受欢迎的内容语言列表：[`devfiles.myopera.com/articles/554/httpheaders-contentlang-url.htm`](http://devfiles.myopera.com/articles/554/httpheaders-contentlang-url.htm)。

## 它是如何工作的...

我们已经在我们的通用模板中有一个英语内容语言元标签：

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Title</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
<script src="img/modernizr-1.6.min.js"></script>
</head>
<body class="no-js">
</body>
</html>

```

简单的`<html lang="en">`就是我们需要确保我们的网站将以英语阅读。将其更改为其他语言可能没有那么简单。对于法语，请使用`<html lang="fr>`，如果您是《星际迷航》的忠实粉丝，请使用`<html lang="x-klingon">`。请注意，克林贡语示例中的`x-前缀`表示实验性语言。

## 还有更多...

您还可以使用类似`<html lang="en, fr">`的方式指定多种语言，用于英语和法语。请注意在值周围使用引号，因为我们引用了多个值。

### 你在说什么？

> 注意：“如果未指定 Content-Language，则默认情况下内容适用于所有语言受众。这可能意味着发件人不认为它是特定于任何自然语言，或者发件人不知道它是为哪种语言而设计的。”- 万维网联盟的超文本传输协议规范

### 一切都归结为 SEO

指定内容语言对搜索引擎也有益，使它们能够解析我们打算使用的语言的内容。我们中谁不需要更多的搜索引擎优化呢？

### 我做到了吗？

如果您没有指定元语言，最糟糕的情况会是什么？什么都不会发生，对吗？错。事实证明，如果我们没有指定元语言，我们的宿敌 Internet Explorer 的旧版本将尝试猜测您的意图是什么语言。正如我们已经看到的，有时 IE 的猜测是错误的。根据这篇文章，无害的用户输入可能会变成活动的 HTML 并执行，导致安全漏洞：[`code.google.com/p/doctype/wiki/ArticleUtf7`](http://code.google.com/p/doctype/wiki/ArticleUtf7)。

## 另请参阅

[`section508.gov`](http://section508.gov)是美国法典第 508 条规定的官方网站。尽管我们网页开发人员主要关注第 508 条如何适用于网络，但实际上它是一套更广泛的法律，定义了我们美利坚合众国如何适应那些在虚拟世界和现实世界中具有不同能力的人。

# 在标签中使用语义化描述供屏幕阅读器使用

语义网页开发的方法不仅对于我们这些开发网站、应用程序和界面的人有意义，对于那些使用和互动我们创建的体验的人也有意义。

## 准备好了

让我们回顾一些 HTML5 规范中的新的更语义化的标签。

## 如何做...

新的 HTML5 标签包括：

+   `<article>` 

+   `<aside>` 

+   `<audio>` 

+   `<canvas>` 

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

## 它是如何工作的...

在那个列表中，以下新标签可以支持文本：

+   `<article>`

+   `<aside>` 

+   `<datalist>` 

+   `<details>` 

+   `<figcaption>` 

+   `<figure>` 

+   `<footer>` 

+   `<header>` 

+   `<hgroup>` 

+   `<keygen>` 

+   `<mark>` 

+   `<nav>` 

+   `<output>` 

+   `<section>` 

+   `<source>` 

+   `<summary>` 

+   `<time>` 

+   `<wbr>` 

该列表代表了绝大多数新的 HTML5 标签。使用这些更语义化的标签将为屏幕阅读器增加额外的含义和智能。

## 还有更多...

以下新标签还为我们提供了创造更丰富和更语义化的体验的机会：

+   `<audio>` 

+   `<embed>` 

+   `<progress>` 

+   `<video>` 

### 始终改进

调查一下您已经发布的具有辅助功能要求的项目。如果您仍然能够更新它们，这是一个重温它们并添加更多语义上有意义的标记的绝佳机会。记住：一个网站或应用程序或界面已经发布并不意味着您不能以后再次访问它。如果一个项目在发布时是一个失败，那么现在是更新它然后重新发布的绝佳时机。谁知道呢？它可能会变成一个完美的作品，让您得到另一份工作！得分！

### 良好的 SEO 语义

使用越来越多的语义化和有意义的标签不仅对使用屏幕阅读器的人有益，而且对搜索引擎优化也有益，因为搜索引擎将能够更智能地解析和理解您的代码。

### Greg 终于学会了

语义网页开发对其他开发人员也有好处。如果您在一个`<nav>`标签中编写了一个区域，那么当前在您团队上的另一个开发人员或将来在您项目上工作的开发人员将立即理解您的意图。作者曾经与一个开发人员合作，他使用了毫无意义的命名，比如`<div id="banana">`，而这与香蕉毫无关系。那个开发人员认为这是一种通过成为唯一知道某些标签含义的工作保障。不幸的是，当他在几年后编辑他以前创建的东西时，这种方法对他来说变得痛苦，因为他记不起它的含义。教训是什么？不要惹自己以后生气！

## 另请参阅

[`caniuse.com`](http://caniuse.com) 提供了 HTML5、CSS3、SVG 等在桌面和移动浏览器中的兼容性表。该网站是一个宝贵的辅助工具，可以帮助理解哪些新标签可以被支持。它不断更新，不仅值得收藏，还值得反复参考。

# 提供备用网站视图

驻剑桥马萨诸塞州的网站开发者 Ethan Marcotte 创建了一种他称之为“响应式网页设计”的方法，以支持具有不同尺寸显示屏的台式电脑以及移动设备 - 所有这些只需一个代码库。虽然这种方法并非必需，但可以视为朝着创建可访问体验的另一步。让我们更仔细地看看他的方法。

## 准备好了

Marcotte 在 2010 年 5 月 25 日的 A List Apart 期刊上发表了这篇文章：[`alistapart.com/articles/responsive-web-design`](http://alistapart.com/articles/responsive-web-design)。阅读这篇文章将让您提前了解本节的其余内容。

## 如何做...

让我们仔细观察 Jon Hicks 的作品集[`hicksdesign.co.uk`](http://hicksdesign.co.uk)，这是 Marcotte 方法的一个出色示例。

在 27 英寸显示器上以全宽度查看 Hicks 的作品集。

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_04_03.jpg)

调整窗口大小会导致网站从四列变为三列：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_04_04.jpg)

进一步调整窗口大小会导致网站从三列变为两列：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_04_05.jpg)

进一步调整窗口大小会导致网站从两列变为一列：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_04_06.jpg)

## 它是如何工作的...

通过在样式表中使用灵活网格以及`min-width`和`max-width`值，Hicks 创建了一个可以轻松适应不同显示尺寸的体验。让我们看看它是如何实现的。

## 还有更多...

这种新的灵活前端网页开发方式使我们能够创建不受设备分辨率限制的体验。多亏了 Marcotte，我们不再被迫为每个设备创建单独的体验。当前状态：一次编码，到处展示。

我们从一个可以适应任何屏幕空间的流体网格开始，灵活的图像，以及让媒体查询根据分辨率和视口提供独特样式表的方式。

这是一个样本媒体查询：

```html
@media screen and (max-width: 600px) {
body {
font-size: 80%;
}
#content-main {float: none; width: 100%;}
}

```

你可以很容易地看到，当设备的最大宽度为 600 像素时，我们告诉`body`以 80%的高度显示字体。我们还指定 content-main `div`将成为 100%宽度的单列。如果设备的最大宽度为 601 像素或更多，这些规则将被忽略。请注意，由于这个媒体查询指定了屏幕，如果用户打印页面，这些规则也将被忽略。

### 最小宽度

正如你可以想象的那样，如果我们能够为窄宽度指定样式，你也可以为更宽的宽度指定其他样式，比如：

```html
@media screen and (min-width: 1024px)

```

请注意，我们仍然在媒体查询中针对屏幕进行定位，但现在我们说只有在视口*大于*1024 像素时才应用一些样式。

### 我的数学老师是对的

那些习惯于使用像 Grid960 这样的刚性固定网格布局系统的人可能会发现使用灵活网格一开始是一种心理挑战。正如 Marcotte 所解释的：

> "网格的每个方面——以及放置在其上的元素——都可以相对于其容器表达为一个比例。"

我们可以将基于像素的宽度转换为百分比，以保持我们的比例不变，无论显示的大小如何。让我们从一个简单的例子开始：假设我们的`header`宽度为 600 像素，我们想在一个宽度为 1200 像素的设备上显示它。如果方程式是目标 ÷ 上下文 = 结果，那么 600 ÷ 1200 = .5。我们的 CSS 会是这样的：

```html
header {width: 50%; /* 600px / 1200px = .5 */}

```

这很容易。但是如果你想在 960 像素宽度上显示一个不同的`header`，那怎么办呢？简单的除法运算得出：510 ÷ 960 = .53125。我们可以这样调整我们的 CSS：

```html
header {width: 53.125%; /* 510px / 960px = .53125 */}

```

通过将每个宽度定义为整体的一部分来重复这个过程，你将很快实现对多种设备的响应式显示。

### 更大总是更好吗？

流体图像甚至更容易，因为不需要进行数学计算。相反，只需包括：

```html
img {max-width: 100%;}

```

在你的样式表中，这些图片将永远不会超出你的显示屏或设备的宽度。

将这三种技术结合在一起，可以为多个平台、浏览器甚至屏幕阅读器上的用户创造几乎无缝的网站体验。

## 另请参阅

2011 年，Marcotte 在[`books.alistapart.com/products/responsive-web-design`](http://books.alistapart.com/products/responsive-web-design)上出版了关于响应式网页设计的权威书籍。

# 使用 hgroup 创建可访问的页眉区域

记得`hgroups`吗？当然记得。在前一章中，我们将其作为一种逻辑上组合相关标题标签的方式进行了讨论。现在，我们将看看这个新的 HTML5 元素如何带来额外的可访问性益处。

## 准备工作

之前，我们以 Roxane 的作品集为例：

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Roxane</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
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

在过去，我们可能会这样编写她网站的主体区域：

```html
<body>
<div>
<div>
<h1>Roxane is my name.</h1>
<h2>Developing websites is my game.</h2>
</div>
</div>
</body>

```

## 如何做...

对于屏幕阅读器来说，过时的第二个例子在语义上毫无意义。它不知道那些标题标签除了在同一个`div`中之外还有其他任何相关性。

## 它是如何工作的...

现在，由于 WHATWG 的 HTML5 草案标准在[`whatwg.org/html5`](http://whatwg.org/html5)，我们和屏幕阅读器都知道`hgroup`是相关标题的分组。那又怎样？如果你不能依靠视觉来知道这些标题是相关的，你难道不希望有其他机制 - 比如屏幕阅读器 - 来让你知道它们是相关的吗？

## 另请参阅

[`diveintoaccessibility.org`](http://diveintoaccessibility.org)是一个了解 508 部分和可访问性标准的绝妙的 30 天逐步资源。作者 Mark Pilgrim（也是[`diveintohtml5.org`](http://diveintohtml5.org)的*Dive Into HTML5*的作者）提供了易于理解的提示，按照人员、残疾、设计原则、Web 浏览器和发布工具分类。该网站已经存在几年了，但由于多年来可访问性标准并没有发生太大变化，因此仍然是一种宝贵的免费资源。

# 为不支持的浏览器显示替代内容

一些新的 HTML5 元素是如此新，以至于并非所有桌面浏览器都支持它们。那么我们怎么能假设所有屏幕阅读器都会支持它们呢？

## 准备就绪

幸运的是，我们可以放心地知道屏幕阅读器将支持常见的文本标签，比如：

+   `<h1>`

+   `<h2>`

+   `<h3>`

+   `<h4>`

+   `<h5>`

+   `<h6>`

+   `<p>`

+   `<ul>`

+   `<ol>`

+   `<li>`

+   `<dl>`

+   `<dt>`

+   `<dd>`

以及其他预期的内容。但是对于那些新的 HTML5 元素，比如：

+   `<文章>`

+   `<旁白>`

+   `<音频>`

+   `<画布>`

+   `<数据列表>`

+   `<详情>`

+   `<说明>`

+   `<图>`

+   `<页脚>`

+   `<头>`

+   `<hgroup>`

+   `<标记>`

+   `<表计>`

+   `<导航>`

+   `<输出>`

+   `<进度>`

+   `<部分>`

+   `<摘要>`

+   `<时间>`

+   `<视频>`

这些是否会向用户传达我们的意思？如果是，那太棒了。但如果不是，用户会得到什么信息？这是否有意义？我们肯定会同意，我们最不希望的是通过我们的新标签提供更少的含义。即使盲人也能看到这将是一个史诗般的失败。

## 如何做...

在撰写本文时，许多 HTML5 元素至少提供了与屏幕阅读器相同数量的语义信息。让我们更具体地看看每个新元素：

+   `<文章>` - 与`div`具有相同的语义信息。

+   `<旁白>` - 与`div`具有相同的语义信息。

+   `<详情>` - 与`div`具有相同的语义信息。

+   `<说明>` - 与`div`具有相同的语义信息。

+   `<图>` - 与`div`具有相同的语义信息。

+   `<页脚>` - 与`div`具有相同的语义信息。

+   `<头>` - 与`div`具有相同的语义信息。

+   `<hgroup>` - 与`div`具有相同的语义信息。

+   `<表计>` - 与`div`具有相同的语义信息。

+   `<导航>` - 与`div`具有相同的语义信息。

+   `<输出>` - 与`div`具有相同的语义信息。

+   `<进度>` - 与`div`具有相同的语义信息。

+   `<部分>` - 与`div`具有相同的语义信息。

+   `<摘要>` - 与`div`具有相同的语义信息。

然而，对于其他新的 HTML5 元素，它们对屏幕阅读器的含义并不那么清晰：

+   `<音频>` - 语义信息似乎是一致的，但是火狐浏览器在内置滑块控件上有问题，IE 9 只有部分播放/暂停支持，Opera 有良好的键盘支持，但没有实际的辅助技术支持。

+   `<画布>` - 对辅助技术几乎没有可用的语义信息。任何依赖新的 HTML `<canvas>`元素传达信息的人都必须极度谨慎。有意使用它会让观众无法进入。

+   `<数据列表>` - 仅在 Opera 中可通过键盘访问。

+   `<标记>` - 不提供额外的语义信息。

+   `<时间>` - 仅在 Opera 中存在键盘访问的 bug。

+   `<video>`-语义信息似乎是一致的，但 Firefox 在内置滑块控件上有问题，Internet Explorer 9 只有部分播放/暂停支持，Opera 具有良好的键盘支持，但没有实际的辅助技术支持。

## 它是如何工作的...

目前，直到屏幕阅读器能够跟上所有新的 HTML5 元素，我们在决定使用哪些新标签以及我们打算用它们传达什么含义给使用辅助技术的人时，必须谨慎。

## 另请参阅

Emily Lewis 对 HTML 和 CSS 以及可用性、语义和可访问性都感到兴奋。她是我们需要更多的对前端 Web 开发世界充满热情的倡导者。请参阅她出色的“Web 可访问性和 WAI-ARIA 入门”了解如何开始思考可访问性的未来，网址为[`msdn.microsoft.com/en-us/scriptjunkie/ff743762.aspx`](http://msdn.microsoft.com/en-us/scriptjunkie/ff743762.aspx)。

# 使用 WAI-ARIA

通过使用技术，我们已经开发出了在浏览器窗口中动态更新信息的方法，而无需手动从服务器刷新页面。对于有视力的人来说，这是一个福音，可以更快地检索信息并以更有用的方式呈现。但是当一个人看不见时会发生什么？他们如何知道页面上的信息已经以任何方式更新，而无需刷新页面，重新显示其内容，并让辅助技术再次完整地读给他们听？

## 准备就绪

可访问的丰富互联网应用程序（WAI-ARIA）是一项新兴的技术规范，就像 HTML5 的许多新语义标签一样，它迫使我们真正思考我们的内容以及我们想要如何向我们的受众呈现它。我们可以使用 WAI-ARIA 来定义角色、属性和状态，以帮助我们定义我们的元素应该做什么。

WAI-ARIA 概述位于[`w3.org/WAI/intro/aria`](http://w3.org/WAI/intro/aria)，基于 Marcotte 的响应式 Web 设计方法。

![准备就绪](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_04_07.jpg)

## 如何做到这一点...

还记得我们在 Roxane 的作品集中包含了新的 HTML5 `nav`元素吗？以下是我们如何使用 WAI-ARIA 添加额外的含义：

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Roxane</title>
<!--[if lt IE 9]><script src="img/html5.js"> </script>[endif]-->
</head>
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
<li><a href="#Contact">Contact</a></li>
</ul>
</nav>
</body>
</html>

```

因为并非每个浏览器都理解`nav`标签，也并非每个浏览器都理解它的角色。WAI-ARIA 为我们提供了这样做的方法。`role="navigation"`被称为“地标角色”，对于无视力的人来说，它就像现实世界中的实际地标一样：它让他们知道自己在哪里。

## 它是如何工作的...

现在，即使没有视力的人也可以通过这些地标角色意识到页面上的变化。WAI-ARIA 通过“监视”更新来通知用户这些动态页面变化。与其重新阅读整个屏幕，只呈现新信息。

## 还有更多...

WAI-ARIA 允许我们创建复杂的、数据驱动的对象，如下拉菜单、选项卡、滑块、文件树等，这些是多年来有视力的用户已经习惯的，并且通过使用这些角色，即使那些无法看到内容更新的人也会被通知它已经这样做了。

### 仍在等待浏览器支持

总是有一个陷阱，对吧？在这种情况下，陷阱是，就像本书中描述的许多其他 HTML5 功能一样，WAI-ARIA 并不是所有辅助技术浏览器完全支持的。无论我们作为开发人员多么勤奋和善意，如果我们的目标受众没有具有 WAI-ARIA 支持的最新浏览器，他们将无法获得我们希望他们获得的信息。

### 这就是我的作用

还有一个问题：错误使用 WAI-ARIA 实际上可能会使情况变得更糟。如果比你水平低的开发人员将`role="navigation"`分配给一些经常更新但允许用户跳过导航的内容，那么用户将永远不会知道信息正在更新。幸运的是，这可能永远不会发生在你身上，因为你会在同行代码审查中发现这个错误。伟大的力量伴随着巨大的责任。

### 优先考虑无障碍

如果您正在开发网站，并且必须支持残疾人士，那么从最初的启动会议开始，必须非常小心，以确保满足他们的需求。最成功的无障碍项目是从一开始就考虑到人们的需求。试图在最后添加一系列功能只会让自己和项目失败。我们要么让人们和项目成功，要么让它们失败。你会选择哪一个？

## 另请参阅

有关如何使用 WAI-ARIA 构建更易访问的网络的更多阅读，请参阅 Scott Gilbertson 的这篇出色的 WebMonkey 文章：[`webmonkey.com/2010/11/can-wai-aria-build-a-more-accessible-web`](http://webmonkey.com/2010/11/can-wai-aria-build-a-more-accessible-web)。

后来，Gilbertson 又撰写了一篇关于使用 ARIA 角色为网站设计样式的绝佳资源：[`webmonkey.com/2011/01/styling-webpages-with-arias-landmark-roles`](http://webmonkey.com/2011/01/styling-webpages-with-arias-landmark-roles)。


# 第五章：学会喜欢表单

在本章中，我们将涵盖：

+   显示占位符文本

+   为表单字段添加自动对焦

+   使用 HTML5 和 CSS3 对表单进行样式设置

+   使用电子邮件输入类型

+   使用 URL 输入类型添加 URL

+   使用数字标签

+   使用范围标签

+   创建搜索字段

+   创建一个选择器来显示日期和时间

# 介绍

> "我们已经遇到了敌人，他就是我们自己。" - Pogo

无聊。乏味。无聊。为什么当网页用户在网上看到交互式表单时，他们的眼睛会发直，头脑会麻木？这位作者认为，问题至少部分在于安排表单字段的信息架构师，而在较小程度上在于编码的前端开发人员。

诚然，表单并不性感。但是如果你是一个网页开发人员（如果你正在阅读这篇文章，很可能是这样），那么你的职业生涯中可能会有某个时候被要求标记和设计某种形式的表单。如果你害怕编写那个表单，想象一下你在用户身上制造的恐惧。现在结束了。

你已经成熟，并寻求值得这种成熟的新挑战。如果我们能停止担心并学会喜欢表单，那么我们的受众实际上也更有可能喜欢它们。

在本章中，我们将看一些 HTML5 用于交互式表单的实际例子，包括显示占位符文本，为表单字段添加自动对焦，使用 HTML5 和 CSS3 对表单进行样式设置，使用电子邮件输入类型，使用 URL 输入类型添加 URL，使用数字标签，使用范围标签，创建搜索字段，以及创建一个选择器来显示日期和时间。

现在让我们开始吧！

# 显示占位符文本

我们想要检查的第一个新的 HTML5 表单功能是本地显示占位符文本的能力。

## 如何做...

我们都曾使用过 - 甚至创建过 - 表单占位符文本。但现在有了 HTML5，我们将以稍有不同且更有效的方式来做。Packt Publishing 网站具有搜索整个网站或仅搜索书籍/电子书的功能。

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_05_01.jpg)

一旦用户点击这两个表单字段中的一个，占位符文本就会消失。

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_05_02.jpg)

这是通过使用值属性来显示占位符文本的传统方法：

```html
<form action='/search'>
<div id="search-site">
<input type="text" class="form-text" name='keys' value="Search entire site" onclick='clearIf(this, "Search entire site")'/>
</div>
<div id="search-button-site">
<input type="image" src="img/search- button.png">
</div>
</form>
<form action='/books'>
<div id="search-books">
<input type="text" class="form-text" name='keys' value="Search only books/eBooks" onclick='clearIf(this, "Search only books/eBooks")'/>
</div>
<div id="search-button-books">
<input type="image" src="img/search- button.png">
</div>
</form>

```

使用`placeholder`属性而不是`value`会导致：

```html
<form action='/search'>
<div id="search-site">
<input type="text" class="form-text" name='keys' placeholder="Search entire site" onclick='clearIf(this, "Search entire site")'/>
</div>
<div id="search-button-site">
<input type="image" src="img/search- button.png">
</div>
</form>
<form action='/books'>
<div id="search-books">
<input type="text" class="form-text" name='keys' placeholder="Search only books/eBooks" onclick='clearIf(this, "Search only books/eBooks")'/>
</div>
<div id="search-button-books">
<input type="image" src="img/search- button.png">
</div>
</form>

```

## 它是如何工作的...

`placeholder`属性可以取代`value`属性来在表单中显示占位符文本。在这种情况下，开发人员添加了一个`onclick`事件处理程序来适应旧版浏览器。这是另一个例子，优秀的语义增加了标签的额外含义。

## 还有更多...

记住 - 并计划 - 当用户点击每个表单字段时，占位符文本本身将消失。如果用户在不填写表单字段的情况下点击其他地方，`placeholder`将重新出现。

### 仅文本

`placeholder`属性只能包含文本。我们不能在其中包含其他标记、图像或任何其他元素。

### 拥抱斜体

默认情况下，占位符文本将以斜体显示。不幸的是，没有很好的方法来改变这一点。与其对头撞墙，不如事先知道这一点，并说服你的设计师，文本*应该*是斜体，并让他专注于真正重要的事情。

### 浏览器支持

支持新的`placeholder`属性的 Web 浏览器。

![浏览器支持](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_05_03.jpg)

## 另请参阅

Build Guild 是全国网页人员的每月聚会。使用 HTML5（并使用占位符属性！）在[`buildguild.org`](http://buildguild.org)构建，开发人员可以每隔几周聚在一起喝酒聊天。已经在城市建立了本地分会，例如：德克萨斯州阿比林；纽约州奥尔巴尼；蒙大拿州比灵斯；密歇根州大急流城；康涅狄格州哈特福德；肯塔基州路易斯维尔；威斯康星州密尔沃基；纽约市，纽约州；宾夕法尼亚州费城；宾夕法尼亚州匹兹堡；密苏里州圣路易斯；马萨诸塞州塞勒姆。

如果你所在地区还没有 Build Guild，请创建一个！联系网站所有者[`buildguild.org`](http://buildguild.org)开始！胡子是可选的。

# 为表单字段添加自动对焦

过去，我们不得不依赖 JavaScript 来为特定的表单字段添加输入焦点，但现在不再需要了！现在我们可以在 HTML5 中本地实现这个功能！

## 如何做...

Ally Creative 在他们的联系表单中有效地使用了`autofocus`功能，网址是[`allycreative.net/contact`](http://allycreative.net/contact)。

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_05_04.jpg)

## 它是如何工作的...

他们是这样做的：

```html
<form action="" method="post">
<ol id="left">
<li>
<label for="contact-name" class="label-fade">Jane Doe of ACME Corporation</label>
<input type="text" id="contact-name" name="contact-name" title="Name / Business" autofocus /></li>
<li>
<label for="contact-mail" class="label- fade">jane.doe@acme.com</label>
<input type="text" id="contact-mail" name="contact-mail" title="E-mail Addy" /></li>
<li>
<label for="contact-phone" class="label-fade">541 / 567- 5309</label>
<input type="text" id="contact-phone" name="contact-phone" title="Phone Number" /></li>
<li>
<label for="contact-budget" class="label-fade">Project Budget</label>
<input type="text" id="contact-budget" name="contact-budget" title="Budget" /></li>
<li><input type="hidden" id="contact-human" name="contact-human" title="Human" /></li>
</ol>
<ol id="right">
<li>
<label for="contact-subject" class="label-fade">Subject</label>
<input type="text" id="contact-subject" name="contact-subject" title="Budget" /></li>
<li>
<label for="contact-body" id="textarea-label" class="label- fade">Say something.</label>
<textarea id="contact-body" name="contact-body" title="Contact Copy"></textarea></li>
<li class="f-right"><span id="required"></span> <input type="image" src="img/button.png" id="submit-button" alt="Submit!" /></li>
</ol>
</form>

```

Ally Creative 的开发人员只需将`autofocus`属性应用于联系人姓名的表单字段，并添加适当的样式来改变背景颜色，就创建了一个流畅、互动的表单，用户很容易完成。

## 还有更多...

新的 HTML5 `autofocus`属性旨在适用于所有表单控件。所以无论你是收集用户的姓名、地址、电话号码还是其他数据，都要聪明地使用`autofocus`的能力！

### 每页一个

请记住，每个页面只能设置一个表单字段为`autofocus`。

### 旧浏览器

一会儿，你会看到目前只有两个现代浏览器支持`autofocus`。幸运的是，旧浏览器会简单地忽略这个属性。考虑到像`autofocus`这样的工具可以丰富那些能看到它的用户的体验，而不会损害或降低那些使用较差浏览器的用户体验。无害，无犯。

### 浏览器支持

支持新的`autofocus`属性的 Web 浏览器：

![浏览器支持](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_05_05.jpg)

## 另请参阅

Mozilla 的“HTML5 的人”视频系列介绍了 HTML5 运动的许多领军人物。Remy Sharpe，我们在其他地方使用过的“HTML5 *Shim*”的作者，是一位 JavaScript 工匠。当他描述新 HTML5 规范的最喜欢的方面时，这应该不足为奇：

“对我来说，HTML5 最令人兴奋的方面是 JavaScript API 的深度。向 Joe Bloggs 解释，实际上这个新规范的 HTML 并不是大部分 HTML；它主要是 JavaScript，这是相当棘手的。”

阅读并观看完整的采访：[`hacks.mozilla.org/2011/01/people-of-html5-remy-sharp`](http://hacks.mozilla.org/2011/01/people-of-html5-remy-sharp)。

# 使用 HTML5 和 CSS3 为表单设置样式

作者见过的使用 HTML5 和 CSS3 创建表单的最简单但最美丽的例子之一是加拿大 FoundationSix 的，网址是[`foundationsix.com/contact`](http://foundationsix.com/contact)。他们是这样做的。

![使用 HTML5 和 CSS3 为表单设置样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_05_06.jpg)

## 如何做...

FoundationSix 团队从一个相当简单的联系表单标记开始。请注意，出于篇幅考虑，这个例子中省略了冗长的国家下拉列表。

## 它是如何工作的...

```html
<form id="contactf6" method="post" action="http://foundationsix.com/index.php" enctype="multipart/form-data" >
<fieldset id="contactinfo">
<ul>
<li>
<label for="name">Name</label>
<input id="name" name="name" type="text" class="required">
</li>
<li>
<label for="email">Email</label>
<input id="email" name="email" type="text" class="required email">
</li>
<li>
<label for="website">Website</label>
<input id="website" name="website" type="text" class="required">
</li>
<li>
<label for="country">Country</label>
<select id="country" name="country" class="selectors">
<option selected value="">Please Select...</option>
</select>
</li>
</ul>
</fieldset>
<fieldset id="natureinfo">
<ul>
<li class="selectli">
<label for="nature">Nature</label>
<select id="nature" name="nature" class="selectors">
<option selected value="Get A Quote">Get A Quote</option>
<option value="Get More Info">Get More Info</option>
<option value="Say Hello">Say Hello</option>
</select>
</li>
<li class="selectli showmore">
<label for="scope">Scope</label>
<select id="scope" name="scope" class="selectors">
<option selected value="">Please Select...</option>
<option value="Complete Website Design">Complete Website Design</option>
<option value="Design Only">Design Only</option>
<option value="Coding Only">HTML / CSS Coding Only</option>
<option value="Other">Other</option>
</select>
</li>
<li class="selectli showmore">
<label for="budget">Budget</label>
<select id="budget" name="budget" class="selectors">
<option selected value="">Please Select...</option>
<option value="$2,500-$5,000">$2,500-$5,000</option>
<option value="$5,000-$7,500">$5,000-$7,500</option>
<option value="$7,500-$10,000">$7,500-$10,000</option>
<option value="$10,000-$15,000">$10,000-$15,000</option>
<option value="$15,000-$20,000">$15,000-$20,000</option>
<option value="$20,000-$50,000">$20,000-$50,000</option>
<option value="$50,000+">$50,000+</option>
</select>
</li>
<li class="selectli showmore">
<label for="timeframe">Timeframe</label>
<select id="timeframe" name="timeframe" class="selectors">
<option selected value="">Please Select...</option>
<option value="Right Away">Right Away</option>
<option value="Within 1 Month">Within 1 Month</option>
<option value="Within 2 Months">Within 2 Months</option>
<option value="Within 3 Months">Within 3 Months</option>
<option value="Within 6 Months">Within 6 Months</option>
<option value="Don't Know Yet">Don't Know Yet</option>
</select>
</li>
</ul>
</fieldset>
<fieldset id="message">
<ul>
<li>
<label for="messagetext">Message</label>
<textarea id="messagetext" name="message"></textarea>
</li>
</ul>
</fieldset>
<div id="submitbutton"><input type="submit" name="submit"></div>
</form>

```

团队为这个联系页面提供了一个特殊的样式表。请注意它是多么干净，只定义了必要的值，而省略了任何多余的东西。

```html
html {
background: url(../img/sitebg.jpg) repeat; -webkit-font-smoothing: antialiased;
}
body {
color: #8a8a8a; font: 13px/19px "Helvetica Neue", Arial, Helvetica, Geneva, sans-serif; background: url(../img/subbg.jpg) repeat-x;
}
#contactform {
float: left; width: 498px; margin-bottom: 40px;
}
#formtop {
height: 97px; width: 498px; background: url(../img/formtop.png) no-repeat;
}
#formtop h1 {
text-indent: -9999px; width: 445px; height: 57px; margin: 0 auto; background: url(../img/formheader.png) no-repeat; position: relative; top: 39px;
}
#formcontent {
background-image: url(../img/formrepeat.png); width: 498px; background-position: 1px;
}
form {
width: 445px; margin: 0 auto;
}
form label {
font: 13px "ClarendonRoman", Georgia, Times, serif; color: #525250; letter-spacing: 2px; text-transform: uppercase; float: left; position: relative; top: 4px;
}
form label.error {
text-transform: none; letter-spacing: 0; color: #a21714; font: 15px "SeanRegular", Courier New, Courier New, Courier6, monospace; margin-top: -10px; clear: both; padding: 0px 0px 10px 21px; background: url(../img/errow.png) no-repeat 0 0;
}
form ul {
padding-top: 10px;
}
form ul li {
padding-top: 10px; clear: both; overflow: hidden;
}
form ul li.selectli {
padding-bottom: 10px;
}
form select, form input {
float: right;
}
form input {
border-bottom: 1px dashed #989895; border-right: none; border-left: none; border-top: none; color: #4f4f4f; background: none; outline: none; position: relative; bottom: 13px; font: 16px "SeanRegular", Courier New, Courier New, Courier6, monospace; letter-spacing: 1px;
}
form input:focus {
border-bottom: 1px dashed #000; -webkit-transition:border 0.3s ease-in; -moz-transition:border 0.3s ease-in; -o-transition:border 0.3s ease-in; transition:border 0.3s ease-in;
}
form select {
width: 300px;
}
input#name {
width: 370px;
}
input#email {
width: 360px;
}
input#website {
width: 340px;
}
fieldset#contactinfo {
padding-bottom: 23px; border-bottom: 1px solid #a7a7a4;
}
fieldset#natureinfo {
margin-top: 4px;
}
fieldset#message {
background: url(../img/messagebar.png) top no-repeat; width: 445; margin-top: 25px;
background: url(../img/messagebar.png) top no-repeat; width: 445; margin-top: 25px;
}
fieldset#message label {
display: none;
}
textarea#messagetext {
margin-top: 4px; width: 445px; height: 150px; border: none; background: none; outline: none; resize: none; overflow: auto; color: #4f4f4f; font: 16px "SeanRegular", Courier New, Courier New, Courier6, monospace; letter-spacing: 1px; float: left; display: block;
}
#submitbutton {
float: right;
}
#submitbutton input {
cursor: pointer; background: url(../img/submit.png) no-repeat; width: 445px; height: 86px; border: none; text-indent: -9999px; position: relative; bottom: 10px;
}
#submitbutton input:hover {
background-position: 0 -86px;
}
span#formbottom {
background: url(../img/formbottom.png) no-repeat; width: 498px; height: 108px; display: block;
}
#othercontact {
float: right; width: 566px; margin-bottom: 40px;
}
#map {
width: 552px; height: 269px; background: url(../img/map.jpg) center no-repeat rgb(233,233,228); background: url(../img/map.jpg) center no-repeat rgba(255,255,255,0.3); padding: 6px; border: 1px solid rgb(249,249,248); border: 1px solid rgba(255,255,255,0.7); margin-bottom: 28px; position: relative;
}
span#mappointer {
width: 77px; height: 80px; display: block; position: absolute; top: 66px; left: 257px; background-image: url(../img/map-pin.png);
}
section.subcontact {
float: left; width: 267px; position: relative; padding-left: 3px; border-top: 6px solid #d3d2c5; -webkit-transition:border 0.4s ease-in; -moz-transition:border 0.4s ease-in; -o-transition:border 0.4s ease-in; transition:border 0.4s ease-in;
float: left; width: 267px; position: relative; padding-left: 3px; border-top: 6px solid #d3d2c5; -webkit-transition:border 0.4s ease-in; -moz-transition:border 0.4s ease-in; -o-transition:border 0.4s ease-in; transition:border 0.4s ease-in;
}
section.subcontact:hover {
border-top: 6px solid #cc7b58; -webkit-transition:border 0.3s ease-in; -moz-transition:border 0.3s ease-in; -o-transition:border 0.3s ease-in; transition:border 0.3s ease-in;
}
section.subcontact h2 {
padding-top: 17px; color: #5a5a5a; font: 20px "ClarendonRoman", Georgia, Times, serif; margin-bottom: 10px; letter-spacing: -0.05em;
}
section.subcontact p {
margin-bottom: 16px; width: 260px;
}
section.subcontact.subright {
position: relative; left: 25px;
}
ul.iconlist {
padding-top: 6px;
}
ul.iconlist li {
padding: 12px 25px; border-top: 1px dashed #b2b2ab;
}
li#mapicon {
background: url(../img/icons/map.png) no-repeat 0 14px;
}
li#emailicon {
background: url(../img/icons/mail.png) no-repeat 0 13px;
}
li#vcardicon {
background: url(../img/icons/card.png) no-repeat 0 13px;
}
li#twittericon {
background: url(../img/icons/twitter.png) no-repeat 0 13px;
}
li#docicon {
background: url(../img/icons/doc.png) no-repeat 3px 13px;
}

```

## 还有更多...

大部分情况下，为 HTML5 添加层叠样式表就像为 XHTML 或以前版本的 HTML 添加 CSS 一样。只是现在我们有额外的标签需要跟踪。

### 提示

请记住，HTML5 和 CSS3 是两回事。人们经常把它们混在一起——就像他们对“Web 2.0”这个术语做的那样，直到这个术语最终失去了所有意义（如果它确实有任何意义的话）。我们会滥用“HTML5”这个术语，以至于最终失去所有意义吗？或者它已经发生了？只有你才能防止森林火灾。

### 旧浏览器

在为 HTML5 设置样式时，我们需要注意两件事：

1.  当一些新元素还不被所有浏览器支持时，如何为其设置样式。

1.  当新的 HTML5 元素在任何给定的浏览器中不被支持时，备用方案是什么样子的。

### 测试，测试，测试

在样式化 HTML5 时，关键是在浏览器中进行测试。为了我们的客户和整个网络开发的利益，我们被迫了解在浏览器中发生的事情，并根据我们的经验进行调整。

### 关于伪类

CSS3 提供了一些新的伪类，用于区分必填表单字段和非必填字段。我们将把这些与内置的 HTML5 表单验证结合起来：

+   `:required` - 让我们根据所需的内容来设置字段样式

+   `:optional` - 让我们根据所需的内容来设置字段样式

+   `:valid` - 将与表单验证一起使用

+   `:invalid` - 将与表单验证一起使用

+   `:in-range` - 适用于最小和最大字符，比如电话号码

+   `:out-of-range` - 适用于最小和最大字符，比如电话号码

## 另请参阅

如果您想尝试使用 CSS3 来样式化 HTML5，Blue Griffon 的开发人员创建了[`bluegriffon.org`](http://bluegriffon.org)，这是一个新的所见即所得的网络内容编辑器。该工具支持多种语言，允许用户在不太考虑代码的情况下使用网络标准。

# 使用电子邮件输入类型

HTML5 支持的众多新输入类型之一是`email`。有多少次您使用`<input type="text" />`构建表单，意图收集电子邮件地址？现在我们可以使用更具语义的东西！稍后，我们将看到这也支持表单验证。

## 如何做...

以前的 FoundationSix 示例可以很容易地转换为这种新的输入类型。而不是：

```html
<li>
<label for="email">Email</label>
<input id="email" name="email" type="text" class="required email">
</li>

```

我们可以简单地更改输入类型，最终得到：

```html
<li>
<label for="email">Email</label>
<input id="email" name="email" type="email" class="required email">
</li>

```

在视觉上，`<input type="email" />`标签看起来与`<input type="text" />`完全相同。区别在于浏览器对信息的处理方式。

## 工作原理...

将类型从`"text"`更改为`"email"`允许较新的浏览器验证用户输入的是否真的是有效的电子邮件地址。请注意，服务器无法确定电子邮件帐户是否处于活动状态，只能确定地址本身是否格式良好。

## 还有更多...

那么，如果提交的电子邮件地址无效会发生什么？事实上，情况仍未明朗。Opera 浏览器有一个实验性的错误消息，Firefox 有自己的实验性附加组件。不幸的是，这是一个灰色地带，我们必须耐心等待浏览器以一致的方式处理它。

### 浏览器支持

但是关于`<input type="email" />`的酷炫之处在于：浏览器支持它！嗯，有点。即使不理解`<input type="email" />`的浏览器也会默认回到`<input type="text" />`，所以它仍然有效。太棒了！

### 无需 JavaScript

正如我们将在其他情况下看到的那样，HTML5 中的`<input type="email" />`允许我们停止使用 JavaScript 来实现类似的结果。我们不再需要使用行为层来弥补标记或表现层的不足。

### 验证的发展

表单验证已经从互联网的开始发展。在最早期，开发人员被迫使用诸如 CGI 脚本之类的技术来提交表单并完全重绘结果页面。只有在页面提交到服务器之后，用户才能知道他们的信息是否被接受。如果没有，他们就必须重新开始。

随着时间的推移，开发人员学会了使用 AJAX 来执行表单的客户端验证。这很有效，但重要的工作落在了 JavaScript 身上。当 JavaScript 被关闭或需要满足无障碍要求时，这就带来了挑战。

现在有了 HTML5，一些验证可以在浏览器中进行，而不需要将信息发送到服务器或依赖 JavaScript。虽然不如 AJAX 解决方案那样强大，但这种类型的验证可以捕获许多最常见的错误类型。

# 使用 URL 输入类型添加 URL

HTML5 支持的许多新输入类型之一是`URL`。你有多少次构建了一个使用`<input type="text" />`的表单，意图收集一个网站地址？现在我们可以使用更语义上正确的东西！稍后我们将看到这也支持表单验证。

## 如何做...

以前的 FoundationSix 示例也可以轻松转换为这种新的输入类型。而不是：

```html
<li>
<label for="website">Website</label>
<input id="website" name="website" type="text" class="required">
</li>

```

我们可以简单地更改输入类型，最终得到：

```html
<li>
<label for="website">Website</label>
<input id="website" name="website" type="URL" class="required">
</li>

```

与`<input type="email" />`一样，`<input type="URL" />`标签在视觉上看起来与`<input type="text" />`相同。不同之处再次在于浏览器对输入的信息的处理方式。

## 工作原理...

将类型从`"text"`更改为`"URL"`允许更新的浏览器验证用户输入的是否实际上是一个有效的网站地址。请注意，服务器无法确定网站是否活动，只能确定地址本身是否格式良好。

## 还有更多...

那么，如果提交的网站地址无效会发生什么？事实上，这里的情况还不明朗。不幸的是，这是一个灰色地带，我们需要耐心等待，直到浏览器以一致的方式处理它。

### 浏览器支持

但是，关于`<input type="URL" />`的酷事在于：浏览器支持它！嗯，有点。即使不理解`<input type="URL" />`的浏览器也会默认回到`<input type="text" />`，所以它仍然有效。太棒了！

### 无需 JavaScript

正如我们将在其他情况下看到的那样，HTML5 中的`<input type="URL" />`允许我们停止使用 JavaScript 来实现类似的结果。我们不再需要使用行为层来弥补标记或表示层的不足。

### 接下来是什么？

随着浏览器的发展，将来我们可能会看到一些实现，允许浏览器对`<input type="URL" />`做一些更智能的事情，比如预取一个网站图标以在评论字段中显示。时间会告诉我们。

## 另请参阅

乐队 Arcade Fire 与电影制作人 Chris Milk 合作，为 Chrome 浏览器创建了基于乐队歌曲"We *Used To Wait"*的互动在线电影"The Wilderness Downtown"，网址为[`thewildernessdowntown.com`](http://thewildernessdowntown.com)，完全使用 HTML5 和 CSS3。该网站因其使用画布、HTML5 视频、谷歌地图等而成为有史以来最受关注的 HTML5 体验之一。

# 使用数字标签

HTML5 现在允许用户在一系列数字中进行选择。例如，如果您希望您的观众购买商品，您可能希望他们使用整数。毕竟，谁会订购 2 双鞋半？

## 如何做...

如果我们继续以购买鞋子的例子，我们可以开发一个这样的表单：

```html
<form>
<label>How many shoes would you like to purchase?<label>
<input type="number" name="quantity" min="2" max="6" step="2" value="2" size="4" />
</form>

```

请注意，在`input`中，我们可以选择性地指定可以订购的最小数量（2）和最大数量（6）。在这种情况下，`step`允许我们确保用户只能以成对的方式订购鞋子，而`value`设置了显示的初始数量。然后，`size`控制`input`框的宽度。

## 工作原理...

指定`<input type="number">`将显示带有上下箭头的新表单控件，允许用户增加和减少字段中的值。这些通常被称为“微调器”或“微调框”。您还可以设置此字段的增量：

![工作原理...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_05_07.jpg)

## 还有更多...

新的`<input type="number" />`标签在在线电子商务之外还有用途。例如，我们可以想象一个非营利组织使用它来设置一个允许用户捐赠固定金额的表单。由于组织有时会为不同的捐款金额提供奖品，表单可以被创建为只允许以这些最低增量输入。

### 浏览器支持

目前`<input type="number" />`只受 Opera 以及基于 Webkit 的浏览器（如 Chrome 和 Safari）支持。但是关于`<input type="number" />`有个很酷的事情：像`<input type="email" />`和`<input type="URL" />`一样，其他浏览器也支持它！嗯，有点。就像这些标签一样，即使不理解`<input type="number" />`的浏览器也会默认回到`<input type="text" />`，所以它仍然有效。太棒了！

### 没有 JavaScript

正如我们将在其他示例中看到的那样，HTML5 中的`<input type="number" />`允许我们停止使用 JavaScript 来实现类似的结果。我们不再需要使用行为层来弥补标记或表现层的不足。

# 使用 range 标签

HTML5 现在允许我们创建一种全新的输入方式。range 标签创建了一个滑块控件，允许用户在一系列值中进行选择。这以前很困难，但现在不是了！看看吧！

## 如何做...

有趣的是，我们可以使用几乎与数字示例中相同的代码，只是将输入类型更改为`"range"`。以下是如何做到的：

```html
<form>
<label>How many shoes would you like to purchase?<label>
<input type="range" name="quantity" min="2" max="6" step="2" value="2" />
</form>

```

请注意，我们可以使用相同的可选`min、max、step、value`和`size`属性。

## 它是如何工作的...

指定`<input type="range">`将显示带有滑块的新表单控件，允许用户增加和减少字段中的值：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_05_08.jpg)

## 还有更多...

`<input type="range">`标签还有许多其他用途，远远超出了电子商务。实际上，由于我们看不到当前选择的值，购物可能不是这个新标签的最佳用途。作者可以想象使用`<input type="range">`用于基于 Web 的音乐播放应用程序，用户可以在不必看到特定音量数字的情况下，直观地增加或减少音量。

### 使用时要小心

不幸的是，没有非 JavaScript 的方法来显示范围输入标签的当前选择值。希望随着 HTML5 的进一步定义和更多浏览器支持其原生控件，我们将能够更好地控制它。在那之前，请谨慎使用。

### 没有 JavaScript

正如我们将在其他示例中看到的那样，HTML5 中的`<input type="range" />`允许我们停止使用 JavaScript 来实现类似的结果。我们不再需要使用行为层来弥补标记或表现层的不足。

### 浏览器支持

与`<input type="number" />`一样，目前`<input type="range" />`只受 Opera 以及基于 Webkit 的浏览器（如 Chrome 和 Safari）支持。但是关于`<input type="range" />`有个很酷的事情：像`<input type="email" />`、`<input type="URL" />`和`<input type="number" />`一样，其他浏览器也支持它！嗯，有点。就像这些标签一样，即使不理解`<input type="range" />`的浏览器（Firefox，我在看你！）也会默认回到`<input type="text" />`，所以它仍然有效。太棒了！

## 另请参阅

Mozilla 的“HTML5 的人”视频系列展示了 HTML5 运动的许多主要声音。作者 Bruce Lawson 非常有趣和权威，尤其是当他批评将 HTML5 用作泛指相关但不同技术的术语时：

> “客户和记者将使用'HTML5'来表示 CSS 3/在 iThings 上运行的视频/地理位置启用的应用程序。这是新的'Web 2.0'。但我们从业者需要搞清楚我们的命名。没有 HTML5 图像转换，就像没有 CSS 语义一样-说有这些东西表明你没有理解 2001 年关于分离样式和内容的备忘录。”

阅读并观看完整的采访：[`hacks.mozilla.org/2011/01/people-of-html5-bruce-lawson`](http://hacks.mozilla.org/2011/01/people-of-html5-bruce-lawson)。

# 创建搜索字段

HTML5 支持的许多新输入类型之一是`search`。您有多少次构建了一个使用`<input type="text" />`的表单，打算允许用户搜索网站？现在我们可以使用更具语义的东西。

## 如何做...

让我们使用占位属性构建一个快速搜索字段。到目前为止，您已经熟悉了这种过时的方法：

```html
<form>
<input name="something" type="text" value="keyword" />
<input type="submit" value="Search" />
</form>

```

我们都做过无数次了，对吧？好吧，让我们试试这个：

```html
<form>
<input name="something" type="search" placeholder="keyword" />
<input type="submit" value="Search" />
</form>

```

发现了区别吗？我们的类型已从`text`更改为`search`，占位文本不再使用 value 标记。这对我们开发人员以及搜索引擎和辅助技术更有意义。

## 它是如何工作的...

指定`<input type="search">`将在 Opera 以及 Chrome 和 Safari 等基于 Webkit 的浏览器中显示带有圆角的新表单字段：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_05_09.jpg)

## 还有更多...

圆角搜索框是苹果在 OSX 上以及 iPad 和 iPhone 上推广的设计方法。苹果正在逐渐成为移动体验的思想领袖，以及 HTML5 的最积极的倡导者之一。

### 为什么要修复完美？

当然，可以覆盖新的 HTML5 搜索字段的默认圆角样式，但为什么呢？它已经看起来很酷了！

### 浏览器支持

这已经成为一个熟悉的叮嘱，但是就像`<input type="email" />`和`<input type="URL" />`和`<input type="number" />`和`<input type="range" />`一样，您可以放心，如果浏览器不原生理解`<input type="search" />`，它将继续像`<input type="text" />`一样进行处理。

### 搜索结果

新的`search`规范还支持新的`results`属性，以在下拉列表中显示已搜索的术语。

## 另请参阅

别管子弹在[`nevermindthebullets.com`](http://nevermindthebullets.com)是一个互动在线游戏，专门用来演示微软 Internet Explorer 9 能够处理的 HTML5 和 CSS3 功能，包括：@font-face；`<canvas>`动画；`<header>`和`<section>`布局；JavaScript 加速；CSS3 2D 变换；CSS3 多背景；可编辑内容；`<audio>`音轨播放器；`<video>`播放器。

# 创建一个选择器来显示日期和时间

每个飞机、火车和汽车租赁网站都将拥有某种时间/日期选择器。终于有了一个语义方法来处理这个问题，所以让我们看看如何使用 HTML5 创建这些`input`类型。

### 提示

截至目前，只有 Opera 浏览器完全支持这些新的`input`标签。

## 如何做到...

HTML5 实际上有六种不同的新`input`，可以控制日期和时间。简而言之，它们是：

+   `<input type="date" />`

+   `<input type="datetime" />`

+   `<input type="datetime-local" />`

+   `<input type="month" />`

+   `<input type="time" />`

+   `<input type="week" />`

这些`input`类型可以被认为是彼此的变体。作为开发人员，我们的工作是选择最适合您收集的数据的那种。

## 它是如何工作的...

对于日期选择器：

```html
<form>
<input type="date"/>
</form>

```

对于日期/时间选择器：

```html
<form>
<input type="datetime"/>
</form>

```

对于本地日期/时间选择器：

```html
<form>
<input type="datetime-local"/>
</form>

```

对于月/年选择器：

```html
<form>
<input type="month"/>
</form>

```

对于时间选择器：

```html
<form>
<input type="time"/>
</form>

```

对于周选择器：

```html
<form>
<input type="week"/>
</form>

```

## 还有更多...

鼓励您尝试每个新的基于日历的`input`标签，以确定哪个最适合您特定的网站或应用程序。

### 浏览器支持

截至目前，只有 Opera 完全支持这些新的`input`标签。随着时间的推移，其他浏览器预计会赶上。一旦我们拥有完全可样式化的基于日期/时间的`input`方法，那将是一个真正快乐的日子。

与此同时，其他浏览器将默认显示这些`input`类型为纯文本框。它们仍然可以工作，但不会像我们希望的那样漂亮。耐心点，小草 hopper。记住，我们正在处理最新的技术——而不是完全成熟、经过验证和批准的方法。

### 如果一切都失败了

User Agent Man 撰写了一篇关于当你需要备用计划时该怎么做的文章，当这些各种新的 HTML5 `input`标签不按你期望的方式工作时。查看完整文章：[`useragentman.com/blog/2010/07/27/cross-browser-html5-forms-using-modernizr-webforms2-and-html5widgets`](http://useragentman.com/blog/2010/07/27/cross-browser-html5-forms-using-modernizr-webforms2-and-html5widgets)。

## 另请参阅

[Forrst.com](http://Forrst.com)是由 Kyle Bragger 使用 HTML5 创建的一个很棒的在线资源。Forrst 是一个充满活力的网络开发者和设计师社区，他们相信通过分享和建设性地批评彼此的工作，可以增加他们对网站创建工艺的知识、技能和热情。我们很欣赏他们的工作态度。


# 第六章：使用 Canvas 开发丰富的媒体应用程序

在本章中，我们将涵盖：

+   设置`canvas`环境

+   理解 2D 渲染上下文

+   动态处理形状

+   使用`canvas`为图像绘制边框

+   圆角

+   创建交互式可视化

+   弹跳球

+   创建备用内容

# 介绍

> “我更喜欢画画而不是说话。画画更快，也给谎言留下的空间更少。”- 勒·柯布西耶

这可能是整本书中最实验性的一章。在接下来的配方中，我们将真正推动这组配方所能实现的极限。

### 注意

请注意，随着时间的推移，实验性的新`canvas`元素规范可能会发生变化。请将这组配方视为出版时可能的情况的快照。

在网站上放置一张图片是如此容易，我们现在认为这是理所当然的。通过代码，你只需告诉浏览器显示一张图片，就完成了。所有这些似乎都像是小孩子的游戏。目前，一些浏览器实际上可以使用新的`canvas`元素动态创建图像。所有繁重的工作都交给了 JavaScript。

新的开源`canvas`元素的很酷之处不仅在于你可以动态地创建图像，而且用户的操作也可以实时地创建新的图像，而无需插件。听起来很棒，对吧？在许多方面确实如此，但它也让我们使用辅助技术的朋友们感到束手无策。

### 提示

如果你使用的浏览器不支持新的`canvas`元素会发生什么？基本上什么都不会发生。浏览器只是不会显示它。这就是为什么你需要特别小心这项技术，不要在新的`canvas`元素中放置任何你的网站或应用程序绝对依赖的东西。你还必须考虑备用内容。

支持`canvas`的浏览器包括：

![介绍](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_06_01.jpg)

### 提示

在继续使用新的`canvas`元素进行开发之前，请确保你对 HTML 和 JavaScript 有扎实的基础。对面向对象编程感到舒适肯定也是有好处的。

在本章中，我们将看到设置`canvas`环境的真实例子，理解 2D 渲染上下文，动态处理形状，使用`canvas`为图像绘制边框，圆角，创建交互式可视化，弹跳球以及创建备用内容。

现在，让我们开始吧！

# 设置`canvas`环境

创建新的`canvas`元素很容易。

## 如何做...

看看这是多么简单：

```html
<!DOCTYPE html>
<html>
<head>
<title>Canvas</title>
<meta charset="utf-8" />
</head>
<body>
<canvas id="FirstCanvas" width="800" height="600">
<!-- Fallback code goes here -->
</canvas>
</body>
</html>

```

## 它是如何工作的...

当然，我们可以使用任何需要的高度和宽度尺寸，但是我们需要开始的是这组简单的标签。

### 提示

你可能会认为我们可以使用 CSS 来控制高度和宽度，但要抵制这种诱惑。因为新的`canvas`元素包含一个 2D 渲染上下文，这种方法可能会导致不可预测的行为。

## 还有更多...

接下来，我们将调用新的`canvas`元素 JavaScript API，同时调用 jQuery：

```html
<!DOCTYPE html>
<html>
<head>
<title>Canvas</title>
<meta charset="utf-8" />
<script src="img/ jquery.min.js"></script>
<script>
$(document).ready(function() {
var canvas = document.getElementById("FirstCanvas");
var ctx = canvas.getContext("2d");
});
</script>
</head>
<body>
<canvas id="FirstCanvas" width="800" height="600">
<!-- Fallback code goes here -->
</canvas>
</body>
</html>

```

### 他很聪明

> “让我完全明确一件事：当你使用`canvas`时，你并不是在`canvas`元素本身上绘图。相反，你实际上是在通过 JavaScript API 访问`canvas`元素的 2D 渲染上下文上绘图。”- Rob Hawkes

### 我在说什么？

苹果最早在 OSX Dashboard 中引入了新的`canvas`元素。后来它在 Safari 和 Chrome 等 web 浏览器中实现，其他浏览器也纷纷效仿。从那时起，它已成为 HTML5 规范的正式部分。

### `<canvas>`的下一步是什么？

现在，我们只是勉强触及了新的`canvas`元素所能做到的一小部分。现在和将来，我们将使用它来创建动画，图表，图表，绘图应用程序，图形和用户界面。你会想到什么呢？

## 另请参阅

开发者 Martin Angelov 为 Tutorial Zine 撰写了一篇名为《使用 Canvas 和 jQuery 创建 HTML5 幻灯片》的很棒的指南：[`tutorialzine.com/2010/09/html5-canvas-slideshow-jquery`](http://tutorialzine.com/2010/09/html5-canvas-slideshow-jquery)。在这篇文章中，Martin 演示了如何将新的 canvas 元素与 jQuery 结合使用，这是最流行的 JavaScript 框架，以创建一个非常互动的图像幻灯片。

# 理解 2d 渲染上下文

重要的是要理解，新的`canvas`元素实际上是一个在浏览器中绘制位图图像的“表面”。

## 如何做...

像这样定义一个`canvas`标签只是讲了一半的故事：

```html
<!DOCTYPE html>
<html>
<head>
<title>Canvas</title>
<meta charset="utf-8" />
</head>
<body>
<canvas id="FirstCanvas" width="800" height="600">
<!-- Fallback code goes here -->
</canvas>
</body>
</html>

```

## 它是如何工作的...

单独的 HTML5 代码什么也做不了。我们必须使用 JavaScript 来使文档对象模型检索 2d 渲染上下文，以便让一些事情发生：

```html
<script>
$(document).ready(function() {
var canvas = document.getElementById("FirstCanvas");
var ctx = canvas.getContext("2d");
});
</script>

```

公平地说，如果 HTML 中没有`canvas`标签，那么这一点 JavaScript 也不会起作用。

## 还有更多...

你可能会想到这个名字。如果有一个 2d 渲染上下文，那么可能也有一个 3d 渲染上下文吧？简短的答案是肯定的。但更详细的答案并不那么简单。

虽然在理论上存在 3d 渲染上下文，但在本出版物发表时，没有浏览器支持它。所以如果新的`canvas`元素以 3d 方式渲染，但没有人看到它，它真的做了什么吗？

### 你可以掌握<canvas>

2d 上下文为新的`canvas`元素使用了许多不同的绘图上下文，这些语法应该对熟悉 CSS 和 JavaScript 的人来说看起来非常熟悉。

### X，见 Y

在绘制时，请记住浏览器窗口左上角的 X 和 Y 轴。数值向下增加。

### 尊重我的权威！

万维网联盟的 HTML5`Canvas` 2d 上下文规范可以在这里找到：[`dev.w3.org/html5/2dcontext`](http://dev.w3.org/html5/2dcontext)。在那里，我们可以深入了解诸如符合性要求、`canvas`状态、变换、合成、颜色和样式、线条样式、阴影、简单形状、复杂形状、焦点管理、文本、图像、像素操作、绘图模型、示例等更多信息。

## 另请参阅

Steve Fulton 和 Jeff Fulton 为 O'Reilly Books 撰写了《HTML5 Canvas》一书。虽然本章将为您提供大约 30 页有价值的新`canvas`元素配方，但 Fulton 的书大约有 400 页。把它当作是本章结束后的资源。在这里查看：[`oreilly.com/catalog/0636920013327`](http://oreilly.com/catalog/0636920013327)。

# 动态处理形状

让我们来看看允许新的`canvas`元素绘制矩形的 JavaScript 函数。

## 如何做...

```html
fillRect(x,y,width,height)
strokeRect(x,y,width,height)

```

按顺序：

```html
fillRect(x,y,width,height)

```

画一个填充的矩形。接下来，

```html
strokeRect(x,y,width,height)

```

在矩形周围画出一个轮廓。

现在，让我们画一些形状。

## 它是如何工作...

我们将从我们的基本`canvas`代码开始，并整合我们的新函数：

```html
<!DOCTYPE html>
<html>
<head>
<title>Canvas</title>
<meta charset="utf-8" />
<script src="img/ jquery.min.js"></script>
<script>
$(document).ready(function() {
var canvas = document.getElementById("FirstCanvas");
var ctx = canvas.getContext("2d");
ctx.strokeRect(10, 10, 396, 236);
ctx.fillStyle = "red";
ctx.fillRect(11, 11, 100, 100);
ctx.fillStyle = "white";
ctx.fillRect(111, 11, 34, 100);
ctx.fillStyle = "red";
ctx.fillRect(156, 11, 249, 100);
ctx.fillStyle = "white";
ctx.fillRect(11, 111, 394, 34);
ctx.fillStyle = "red";
ctx.fillRect(11, 145, 100, 100);
ctx.fillStyle = "white";
ctx.fillRect(111, 145, 34, 100);
ctx.fillStyle = "red";
ctx.fillRect(156, 145, 249, 100);
});
</script>
</head>
<body>
<canvas id="FirstCanvas" width="416" height="256">
<p>Flag of Denmark</p>
</canvas>
</body>
</html>

```

我们创建的东西类似于丹麦的国旗！

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_06_02.jpg)

## 还有更多...

这个例子一开始可能并不令人印象深刻，但当你记住我们几乎没有使用任何 HTML 和 CSS 就创建了一张图片时，新的`canvas`元素开始看起来相当令人印象深刻。

### 任何你想要的方式

请注意，虽然我们使用了颜色名称（“white”和“red”），我们也可以使用十六进制值或 RGB 甚至 HSL！使用对你和你的互动项目最有意义的内容。

### 类似于表格？

将此示例的颜色和大小规格几乎视为我们过去用于布局的老式`tables`。虽然肯定不同，但在这种情况下确实有一些相似之处。

### 首先成为一个正方形

掌握矩形是在掌握设置元素本身的能力之后，重要的第一个`canvas`技术。理解这种方法的基础将帮助你掌握接下来几个配方的基础。

## 另请参阅

另一本将近 400 页的书是 Rob Hawkes 的《Foundation HTML5 Canvas: For Games and Entertainment》，来自 Friends of Ed。在这本书中，Hawkes 为那些刚接触新的“画布”元素的人，一直到最有经验的专家提供了一个提升技能的出版物。听起来像你认识的人吗？在这里查看：[`friendsofed.com/book.html?isbn=1430232919`](http://friendsofed.com/book.html?isbn=1430232919)。

# 使用画布为图像绘制边框

让我们仔细看看使用新的“画布”元素绘制图像周围边框的超级简单方法。

## 如何做...

首先，我们将从基本的“画布”代码开始，并添加一行新的代码来绘制边框：

```html
<!DOCTYPE html>
<html>
<head>
<title>Canvas</title>
<meta charset="utf-8" />
<script src="img/ jquery.min.js"></script>
<script>
$(document).ready(function() {
var canvas = document.getElementById("FirstCanvas");
var ctx = canvas.getContext("2d");
ctx.strokeRect(10, 20, 100, 100);
});
</script>
</head>
<body>
<canvas id="FirstCanvas" width="800" height="600">
<!-- Fallback code goes here -->
</canvas>
</body>
</html>

```

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_06_03.jpg)

## 它是如何工作的...

JavaScript 的那一行告诉浏览器创建一个矩形，从新的“画布”元素的左边 10 像素，顶部 20 像素开始。它绘制了一个 100 像素的正方形框。

## 还有更多...

这很好，但如果我们希望边框是除了默认颜色之外的任何其他颜色，我们需要指定它：

```html
<!DOCTYPE html>
<html>
<head>
<title>Canvas</title>
<meta charset="utf-8" />
<script src="img/ jquery.min.js"></script>
<script>
$(document).ready(function() {
var canvas = document.getElementById("myCanvas");
var ctx = canvas.getContext("2d");
ctx.strokeStyle = "rgb(0, 128, 0)";
ctx.strokeRect(10, 20, 100, 100);
});
</script>
</head>
<body>
<canvas id="myCanvas" width="600" height="600">
<!-- Fallback code goes here -->
</canvas>
</body>
</html>

```

在这种情况下，我们使用`strokeStyle`来指定纯绿色的 RGB 颜色。

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_06_04.jpg)

### 首先是样式

### 提示

如果你打算为边框设置样式，你需要在浏览器绘制边框之前指定。如果你在之后指定样式，浏览器将会忽略它。

### 许多颜色值都可以使用

我们刚刚使用的样式属性是 RGB，但该方法也适用于颜色（例如“绿色”）、十六进制值、HSL 和 RGBA。

### 我喜欢大边框，我无法否认

如果没有指定边框宽度，浏览器将自动绘制一个像素的边框。以下是如何更改它的方法：

```html
<!DOCTYPE html>
<html>
<head>
<title>Canvas</title>
<meta charset="utf-8" />
<script src="img/ jquery.min.js"></script>
<script>
$(document).ready(function() {
var canvas = document.getElementById("myCanvas");
var ctx = canvas.getContext("2d");
ctx.lineWidth = 10;
ctx.strokeStyle = "rgb(0, 128, 0)";
ctx.strokeRect(10, 20, 100, 100);
});
</script>
</head>
<body>
<canvas id="myCanvas" width="600" height="600">
<!-- Fallback code goes here -->
</canvas>
</body>
</html>

```

就是这么简单：

![我喜欢大边框，我无法否认](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_06_05.jpg)

## 另请参阅

[`rgraph.net`](http://rgraph.net)是一个专门为新的“画布”元素设计的图形库。它允许您轻松创建各种图表类型：条形图、双极图、圆环图、漏斗图、甘特图、水平条形图、LED 显示、折线图、仪表、里程表、饼图、进度条、玫瑰图、散点图和传统的雷达图，使用 HTML5、`canvas`和 JavaScript。

# 圆角

到目前为止，我们已经使用方形或矩形形状创建了图像和边框。接下来，我们将看看如何使用新的“画布”元素通过 JavaScript 来使这些图像和边框的角变圆。

## 如何做...

圆角的能力不是`canvas`的本机功能，但 Rob Hawkes 是一个非常聪明的人，他想出了如何实现它的方法。这就是 Rob 做的事情，在这里解释：[`rawkes.com/blog/2010/12/11/rounded-corners-in-html5-canvas`](http://rawkes.com/blog/2010/12/11/rounded-corners-in-html5-canvas).

```html
<!DOCTYPE html>
<html>
<head>
<title>Canvas</title>
<meta charset="utf-8" />
<script src="img/ jquery.min.js"></script>
<script>
$(document).ready(function() {
var canvas = $("#myCanvas");
var context = canvas.get(0).getContext("2d");
var rectX = 10;
var rectY = 10;
var rectWidth = 100;
var rectHeight = 100;
var cornerRadius = 15;
context.lineJoin = "round";
context.lineWidth = cornerRadius;
context.strokeStyle = "rgb(0, 128, 0)";
context.strokeRect(rectX+(cornerRadius/2), rectY+(cornerRadius/2), rectWidth-cornerRadius, rectHeight-cornerRadius);
});
</script>
</head>
<body>
<canvas id="myCanvas" width="600" height="600">
<!-- Fallback code goes here -->
</canvas>
</body>
</html>

```

## 它是如何工作的...

首先，Rob 选择了一个稍微不同的方法来调用 2d“画布”渲染上下文，但他的方法也完全有效。看看：

```html
$(document).ready(function() {
var canvas = $("#myCanvas");
var context = canvas.get(0).getContext("2d");

```

Rob 代码的下一部分应该看起来非常熟悉：他设置了图像的 X 和 Y 坐标，它的大小，然后是边框半径：

```html
var rectX = 10;
var rectY = 10;
var rectWidth = 100;
var rectHeight = 100;
var cornerRadius = 15;

```

然后 Rob 调用了连接线和他想要使用的特定边框半径的能力。假装直到你成功为止！

```html
context.lineJoin = "round";
context.lineWidth = cornerRadius;

```

最后是边框的颜色（仍然是绿色！）和将所有内容联系在一起的最后一小部分脚本：

```html
context.strokeStyle = "rgb(0, 128, 0)";
context.strokeRect(rectX+(cornerRadius/2), rectY+(cornerRadius/2), rectWidth-cornerRadius, rectHeight-cornerRadius);

```

## 还有更多...

现在 Rob-如果你也在跟着做-可以成为一个拥有美丽圆角图像的摇滚明星。

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_06_06.jpg)

### 就像学术能力测试一样

### 提示

记住：`lineWidth`对于新的“画布”元素来说就像 border-radius 对 CSS 来说一样。它们都实现了同样的功能-但是方式完全不同。

### IE 呢？

可以使用 ExplorerCanvas 库在 Internet Explorer 6-8 中支持一些新的“画布”元素的功能：[`code.google.com/p/explorercanvas.`](http://code.google.com/p/explorercanvas.)

### 我们正在奠定基础

在本章的大部分食谱中，我们只使用了新的`canvas`元素在浏览器中绘制静态形状，而没有使用图像。这可能看起来毫无事件，甚至可能违反直觉。重点是为您提供这种新能力的坚实基础，以便您可以扩展它，使用新的`canvas`元素创建游戏，可视化数据，并允许用户动态绘制对象。

## 另请参阅

Mozilla 的“HTML5 的人”视频系列中有许多 HTML5 运动的领军人物。John Foliot 是 HTML5 中媒体元素无障碍子委员会的联合主席。当他为这些技术当前浏览器支持的状况感到懊恼时，这一点应该不足为奇：

> “我认为 HTML5 开始提供的许多东西对所有用户都有好处，包括使用辅助技术的用户。然而，许多承诺的东西在所有浏览器中尚不受支持，相关技术——辅助技术——还有很长的路要走才能利用这一好处。”

阅读并观看完整的采访：[`hacks.mozilla.org/2011/02/people-of-html5-john-foliot`](http://hacks.mozilla.org/2011/02/people-of-html5-john-foliot).

# 创建交互式可视化

Carbon Five 团队面临着一个艰巨的任务：创建他们的技能和兴趣的物理图。他们可能从办公室的墙开始，但很快意识到新的`canvas`元素带来的新能力将允许交互性，并且可以根据此进行结论。以下是他们在这里所做的：[`carbonfive.github.com/html5-playground/interest-map/interest-map.html.`](http://carbonfive.github.com/html5-playground/interest-map/interest-map.html.)

![创建交互式可视化](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_06_07.jpg)

## 如何做...

### 提示

在按照本食谱操作时，查看源代码将非常有帮助：[view-source:http://carbonfive.github.com/html5-playground/interest-map/interest-map.html](http://view-source:http://carbonfive.github.com/html5-playground/interest-map/interest-map.html)

Carbon Five 团队提醒我们，画布并不是 HTML5 规范的正式部分，他们使用 HTML4.01 Transitional DOCTYPE 创建了这个交互式可视化。

```html
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">

```

以下是他们在 JavaScript 和新的`canvas`元素中所做的一些详细内容。他们从一些变量开始，比如卡片样式。在这里，他们做了几件事情：设置背景颜色，创建黑色边框，卡片的宽度，以及围绕它的阴影的值。

```html
var CARD_STYLE = { fill:'rgb(240,240,240)',stroke:'rgb(0,0,0)',width:.05, shadow:{x:0, y:4, blur:4, color:'rgba(0, 0, 0, 0.3)'} };

```

下一个变量对于了解 CSS 的人来说应该很熟悉。在这里，设置了卡片的字体重量、大小、字体、颜色等等：

```html
var CARD_FONT = {font:'bold 8pt Courier', color:'#555', yoffset:10, height:14};

```

接下来，他们设置了与边距、宽度、高度、比例、半径、阴影等相关的几个变量。

```html
var MARGIN = [75,75,75,100], WIDTH = 1000-MARGIN[1]-MARGIN[3], HEIGHT = 650-MARGIN[0]-MARGIN[2], CARD_SCALE=.75, CARD_RADIUS = 40, TAG_RADIUS = 50, CACHE_RADIUS=70, CLEAR_RADIUS = 50, ITERATIONS = 20, DEGREE = .5, CARD_SHADOW = 2, AXIS_ANIM=700;

```

最后，他们为技能、人员和人员与技能矩阵设置了变量。不幸的是，这些代码块太长，无法在此重新发布。

## 它是如何工作的...

变量本身并不会有太大作用，除非它们有函数来对其进行操作。

在初始化显示后，Carbon Five 团队使用更多的函数，比如在 2D`canvas`渲染元素上绘制：

```html
function draw(t) {
var ctx = el('display').getContext('2d');
ctx.clearRect(0,0,ctx.canvas.width,ctx.canvas.height);
ctx.save(); ctx.globalAlpha = 1 - .75*arrow_visibility;
each( cards, function(card) {
var t0=card.tween(t); x = MARGIN[3] + card.lx + (card.x-card.lx)*t0, y = MARGIN[0] + card.ly + (card.y-card.ly)*t0;
draw_card( ctx, x, y, card.index);
});
ctx.restore();
if ( arrow_visibility > 0 ) {
ctx.save(); ctx.globalAlpha = arrow_visibility;
each( PEOPLE, function(p) { draw_interest_arrow(ctx,p,t); });
ctx.restore();
if (over_person) draw_over_arrow(ctx,over_person,t);
}
draw_axes(ctx);
}

```

以及创建名称标签：

```html
function nametag( ctx, cardx, cardy, person, r, interest ) {
ctx.save(); ctx.translate( cardx, cardy ); ctx.rotate( r + .4*(Math.random()-.5) );
ctx.translate( -TAG_RADIUS - + 4*Math.random(), 0 ); ctx.rotate( -r );
draw_nametag( ctx, person, interest );
ctx.restore();
}

```

并绘制箭头：

```html
function draw_arrow( ctx, length, head_length, head_width ) {
var cx1 = .9*(length - head_length), cy1 = .2*head_width, cx2 = (length - head_length), cy2=.2*head_width;
ctx.beginPath();
ctx.moveTo(0,0);
ctx.bezierCurveTo( cx1, cy1, cx2, cy2, length-head_length, head_width );
ctx.lineTo( length, 0 ); ctx.lineTo( length-head_length, -head_width );
ctx.bezierCurveTo( cx2, -cy2, cx1, -cy1, 0, 0 );
ctx.closePath();
}

```

## 还有更多...

已经设置了变量和函数，最后要做的就是在 HTML 中调用`canvas`元素本身，为其提供一个运行的空间：

```html
<canvas id="display" width="1000" height="650"></canvas>

```

### 两个出租人的邪恶

在旧网页时代，Carbon Five 团队可以选择将他们的地图放在物理墙上，或者为计算机显示创建静态图像。虽然任何一种方式都可以渲染得和使用新的`canvas`元素一样好，但它们都不允许团队像新的`canvas`元素那样提取有价值的信息。

### 备用内容呢？

有趣的是，Carbon Five 在这种情况下没有在新的“画布”元素中使用任何回退内容。这是一个你需要仔细权衡的方法，因为那些使用旧浏览器或辅助技术的人将什么也看不到，真的什么也看不到。Carbon Five 在这个内部项目中得以成功。你能吗？

### 接受他的提议。

在[`blog.carbonfive.com/2011/02/17/visualizing-skillsets-in-html5-canvas-part-1`](http://blog.carbonfive.com/2011/02/17/visualizing-skillsets-in-html5-canvas-part-1)上写关于这个项目时，Carbon Five 的开发者亚历克斯·克鲁克山甚至提出为前五个以合理格式提供数据的人创建可视化地图。截至发布日期，尚不清楚是否有人接受了他的提议。

## 另请参阅

雅各布·赛德林用他的新画布元素可视化了乐队 Radiohead 的歌曲“Idioteque”，这首歌来自专辑“Kid A”，网址是：[`nihilogic.dk/labs/canvas_music_visualization`](http://nihilogic.dk/labs/canvas_music_visualization)。雅各布正在挑战“画布”元素和 JavaScript 的极限，这就是为什么我们认为他很棒！

# 弹跳一个球

我们已经看过如何使用新的“画布”元素绘制形状，接下来我们将把注意力转向让这些形状移动起来。作者文森·鲁弗斯向我们展示了如何做到这一点。

## 如何做...

我们将从我们通常的`canvas` HTML 代码开始：

```html
<!DOCTYPE html>
<html>
<head>
<title>Canvas</title>
<meta charset="utf-8" />
</head>
<body>
<canvas id="FirstCanvas" width="800" height="600">
<!-- Fallback code goes here -->
</canvas>
</body>
</html>

```

接下来是独特的部分：JavaScript。在这里，文森选择了一个稍微不同的方法来调用 2D“画布”渲染上下文，但他的方法也完全有效。看看：

```html
<script>
var context;
function init()
{
context= myCanvas.getContext('2d');
context.beginPath();
context.fillStyle="#0000ff";
// Draws a circle of radius 20 at the coordinates 100, 100 on the canvas
context.arc(100,100,20,0,Math.PI*2,true); context.closePath();
context.fill();
}
</script>

```

将这些代码放在一起，应该是这样的。请注意，添加了一个`onLoad`函数到`body`标签。

```html
<!DOCTYPE html>
<html>
<head>
<title>Canvas</title>
<meta charset="utf-8" />
<script src="img/ jquery.min.js"></script>
<script>
var context;
function init()
{
context= myCanvas.getContext('2d');
context.beginPath();
context.fillStyle="#0000ff";
// Draws a circle of radius 20 at the coordinates 100, 100 on the canvas
context.arc(100,100,20,0,Math.PI*2,true); context.closePath();
context.fill();
}
</script>
</head>
<body onLoad="init();">
<canvas id="myCanvas" width="300" height="300">
<!-- Fallback code goes here -->
</canvas>
</body>
</html>

```

然后渲染这个蓝色的球：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_06_08.jpg)

## 它是如何工作的...

到目前为止，文森的代码非常简单。我们看到他是如何调用 2D“画布”渲染上下文的。接下来他设置了填充的颜色：

```html
context.fillStyle="#0000ff";

```

然后画一个距离顶部和左边 100 像素的弧线，并用他已经设置的蓝色填充它：

```html
context.arc(100,100,20,0,Math.PI*2,true); context.closePath();
context.fill();

```

但现在我们只有一个蓝色的球静静地坐在那里。接下来，文森向我们展示了如何使用变量和一个名为`draw`的新函数让它移动。

## 还有更多...

```html
<!DOCTYPE html>
<html>
<head>
<title>Canvas</title>
<meta charset="utf-8" />
<script src="img/ jquery.min.js"></script>
<script>
var context;var x=100;var y=200;var dx=5;var dy=5;
function init()
{
context= myCanvas.getContext('2d');
setInterval(draw,10);
}
function draw()
{
context.beginPath();
context.fillStyle="#0000ff";
// Draws a circle of radius 20 at the coordinates 100, 100 on the canvas
context.arc(x,y,20,0,Math.PI*2,true);
context.closePath();
context.fill();
x+=dx;
y+=dy;
}
</script>
</head>
<body onLoad="init();">
<canvas id="myCanvas" width="300" height="300" >
</canvas>
</body>
</html>

```

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_06_09.jpg)

正如你所看到的，球在运动，但只是画了一条直线超出了“画布”的边缘。文森解释了原因：

> “这是因为每次调用`draw()`函数时，它都会在新的坐标处画一个圆圈，而不会移除旧的圆圈。这就是`getContext`对象的工作原理，所以这不是一个 bug；它实际上并没有移动圆圈，而是每次调用函数时在新的坐标处画一个圆圈。”

### 重新开始

文森向我们展示了一种方法，可以在新的“画布”元素绘制每一个新的圆圈时擦除旧的圆圈：

```html
<script>
var context;
var x=100;
var y=200;
var dx=5;
var dy=5;
function init()
{
context= myCanvas.getContext('2d');
setInterval(draw,10);
}
function draw()
{
context.clearRect(0,0, 300,300);
context.beginPath();
context.fillStyle="#0000ff";
// Draws a circle of radius 20 at the coordinates 100, 100 on the canvas
context.arc(x,y,20,0,Math.PI*2,true);
context.closePath();
context.fill();
x+=dx;
y+=dy;
}
</script>

```

现在，球似乎向右下方超出了“画布”的边界。

### 不要把我困住

为了确保球保持在“画布”的边界内，文森编写了一些逻辑来检查 x 和 y 坐标是否超出了“画布”的尺寸。如果超出了，他就让球改变方向。

```html
<script>
var context;
var x=100;
var y=200;
var dx=5;
var dy=5;
function init()
{
context= myCanvas.getContext('2d');
setInterval(draw,10);
}
function draw()
{
context.clearRect(0,0, 300,300);
context.beginPath();
context.fillStyle="#0000ff";
// Draws a circle of radius 20 at the coordinates 100, 100 on the canvas
context.arc(x,y,20,0,Math.PI*2,true);
context.closePath();
context.fill();
// Boundary Logic
if( x<0 || x>300) dx=-dx;if( y<0 || y>300) dy=-dy;x+=dx;y+=dy;
}
</script>

```

现在，球应该在“画布”的四个边上不断地弹跳。

![不要把我困住](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-vid-hwt/img/1048_06_10.jpg)

### 这是一个成长的过程

正如文森在他引人入胜的教程中提醒我们的那样，弹跳的球乍看起来可能很简单，但实际上这是一个关键的技术，需要理解才能开发任何新的 HTML5“画布”元素游戏。

## 另请参阅

可以在 Yuri Vishnevsky 的[`weavesilk.com`](http://weavesilk.com)上看到用户生成的图形的一个美丽的例子。该网站使用新的`canvas`元素作为生成艺术实验的一部分。一些生成的图像非常漂亮，Yuri 已经将它们作为令人惊叹的桌面背景图像提供。还计划推出 iPhone 和 iPad 版本。

# 创建回退内容

> “当作者使用`canvas`元素时，他们还必须提供内容，当呈现给用户时，传达与位图`canvas`本质上相同的功能或目的。此内容可以放置为`canvas`元素的内容。`canvas`元素的内容（如果有）是元素的回退内容。”- WHATWG HTML5 规范

如果有人查看您的精彩新`canvas`应用程序的浏览器使用较旧的浏览器，并且无法识别您的编码天赋会发生什么？或者当有人使用辅助技术时会发生什么？让我们来看看。

## 如何做到...

如果出于某种原因，用户的浏览器不支持新的`canvas`元素，作为开发人员，我们要为他们提供有价值的东西。

在这里我们可以使用图像作为回退。

```html
<canvas id="clock" width="200" height="200">
<img src="img/clock.gif" width="200" height="200" alt="clock"/>
</canvas>

```

或者文本：

```html
<canvas id="clock" width="200" height="200">
<p>clock</p>
</canvas>

```

或者几乎任何其他元素。

## 它是如何工作的...

到目前为止，您已经熟悉了`alt`标签如何用于图像文件：如果图像文件不显示或用户依赖辅助技术，`alt`标签至少为他们提供了一个有价值的文本标签，代表他们所错过的内容。新的`canvas`元素的回退内容是一个类似的概念，但它能够做到并且比只是一个`alt`标签更有价值。

## 还有更多...

支持新的`canvas`元素的浏览器将忽略容器内的内容，并正常呈现新的`canvas`元素。

### 谢谢，Mozilla

> 如果需要回退内容，必须使用一些 CSS 技巧来掩盖 Safari 中的回退内容（应该只呈现`canvas`），并且还要掩盖 IE 中的 CSS 技巧本身（应该呈现回退内容）。- [Mozilla.org](http://Mozilla.org)

### 我们将如何处理可访问性？

规范作者和 HTML5 社区普遍认为新的`canvas`元素只是部分成熟。让使用辅助技术的人置身于寒冷中似乎不是正确的做法。敬请关注。

### 我们准备好使用<canvas>了吗？

许多开发人员认为新的`canvas`元素的可访问性是新 HTML5 规范中的最后一个关键点。由于几乎没有有意义的回退功能，这个新元素似乎还没有准备好投入使用。
