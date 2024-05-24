# 响应式 Web 设计指南（一）

> 原文：[`zh.annas-archive.org/md5/50CFC4166B37BD720D7E83B7A7DE4DFD`](https://zh.annas-archive.org/md5/50CFC4166B37BD720D7E83B7A7DE4DFD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

响应式网页设计已经席卷了网页设计行业。这不是一个潮流，而是一种规范；现在人们通常期望网站是响应式的。你可能已经在博客、论坛、Facebook 和 Twitter 上读到并参与了很多关于响应式网页设计的讨论。同样，你希望你的网站也是响应式的，以便在任何屏幕尺寸上都能呈现出色。因此，这就是你要找的书。

本书教你如何通过示例、技巧和最佳实践来构建出色的响应式网站，并且教你如何编写代码和组织项目。此外，你还将学习如何使用 CSS 预处理器 LESS 和 Sass，这可以让你编写更精简的样式规则。

# 本书涵盖内容

第一章, *响应式网页设计*，探讨了响应式网页设计背后的基本原则，解释了构建响应式网站的基本技术，并介绍了一些响应式框架以及使用它们的优势。

第二章, *网页开发工具*，帮助你准备、安装和设置软件来运行项目和构建响应式网站。

第三章, *使用 Responsive.gs 构建简单响应式博客*，介绍了 Responsive.gs 框架，并使用多个 HTML5 元素和 Responsive.gs 网格系统构建了博客的 HTML 结构。

第四章, *增强博客外观*，编写 CSS 样式规则来增强博客的外观和感觉。你还将学习如何使用部分样式表模块化管理博客样式，并将它们编译到一个单一样式表中。

第五章, *使用 Bootstrap 开发作品集网站*，使用 Bootstrap 框架组件构建作品集网站，包括网格系统、按钮和表单。我们还将学习如何使用 Bower 来管理项目库。

第六章, *使用 LESS 打磨响应式作品集网站*，探讨并教授了使用多个 LESS 特性，比如嵌套、变量和混合，来编写更精简和可重用的样式规则，最终打磨出响应式作品集网站。

第七章, *使用 Foundation 构建响应式商务网站*，使用 Foundation 框架的网格系统和组件为创业企业构建一个响应式网站。

第八章, *扩展 Foundation*，教你如何使用 Sass 和 SCSS 语法，比如变量、混合和函数，来编写可维护和可重用的响应式创业网站的样式。

附录, *测验答案*，包含了本书中多项选择测验的答案。

# 你需要准备什么

你需要对 HTML 和 CSS 有基本的了解；至少，你应该知道什么是 HTML 元素，以及如何用 CSS 对 HTML 元素进行基本的样式设置。对 HTML5、CSS3 和命令行有一定的熟悉和经验，虽然不是必需的，但会对本书的最大收益有很大帮助。我们将详细解释每一步和所有的技巧，以及一些实用的提示和参考资料。

此外，你还需要一台运行 Windows、OS X 或 Ubuntu 的计算机；一个互联网浏览器（最好是 Google Chrome 或 Mozilla Firefox）；以及一个代码编辑器（在本书中，我们将使用 Sublime Text）。

# 本书适合谁

*通过实例学习响应式网页设计初学者指南第二版*通过实际示例教读者如何构建出色的响应式网站，并通过深入的解释逐步引导读者完成整个过程。这是一本完美的书，适合任何想要快速学习和构建响应式网站的人，无论读者的熟练程度如何，即新手或经验丰富的网页设计师。

# 部分

在本书中，您会经常看到几个标题（行动时间，刚刚发生了什么？，快速测验和尝试）。

为了清晰地说明如何完成一个过程或任务，我们使用以下部分：

# 行动时间 - 标题

1.  行动 1

1.  行动 2

1.  行动 3

指示通常需要一些额外的解释，以确保它们有意义，因此它们后面跟着这些部分：

## *刚刚发生了什么？*

本节解释了您刚刚完成的任务或指示的工作方式。

您还会在书中找到一些其他学习辅助工具，例如：

## 快速测验 - 标题

这些是旨在帮助您测试自己理解的简短的多项选择题。

## 尝试一下英雄 - 标题

这些是实际的挑战，给您提供了实验您所学内容的想法。

# 约定

您还会发现一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“Responsive.gs 附带的`boxsizing.htc`文件将应用与 CSS3`box-sizing`属性相似的功能。”

代码块设置如下：

```html
* { 
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box;
  *behavior: url(/scripts/boxsizing.htc); 
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```html
* { 
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box;
 *behavior: url(/scripts/boxsizing.htc); 
}
```

任何命令行输入或输出都以以下方式编写：

```html
cd \xampp\htdocs\portfolio
bower init

```

**新** **术语**和**重要** **单词**以粗体显示。例如，屏幕上看到的单词，例如菜单或对话框中的单词，会出现在文本中，如下所示：“检查**Source Map**选项，以生成样式表的源映射文件，在调试时会对我们有所帮助。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会出现在这样的样式中。


# 第一章：响应式网页设计

*我仍然记得，小时候，手机只有一个微小的单色屏幕。那时我们能做的只是打电话、发短信和玩简单的游戏。如今，移动设备在许多方面都有了巨大的进步。*

*新的移动设备具有不同的屏幕尺寸；一些甚至具有更高的 DPI 或分辨率。大多数新的移动设备现在配备了触摸屏，使我们可以方便地使用手指轻触或滑动与设备进行交互。屏幕方向可以在纵向和横向之间切换。与旧设备相比，软件也更加强大。特别是移动浏览器现在能够呈现和显示与桌面电脑浏览器一样好的网页。*

*此外，过去几年移动用户的数量激增。现在我们可以看到周围有很多人花费数小时使用他们的移动设备，手机或平板电脑，进行诸如在外出时经营业务或简单的互联网浏览等活动。移动用户的数量未来可能会继续增长，甚至可能超过桌面用户的总数。*

*也就是说，移动设备改变了网络，改变了人们使用互联网和享受网站的方式。移动设备的这些进步和不断增长的移动互联网使用量引发了一个新的构建网站的范式的问题，即如何在不同情况下构建可访问且功能良好的网站。这就是**响应式网页设计**的用武之地。*

在本章中，我们将涵盖以下主题：

+   简要了解响应式网页设计、视口 meta 标签和 CSS3 媒体查询的基础知识

+   在接下来的章节中，我们将使用响应式框架来构建响应式网站

# 简而言之，响应式网页设计

响应式网页设计是网页设计和开发社区中讨论最多的话题之一。因此，我相信你们很多人对它有一定程度的了解。

伊桑·马科特是首次提出“响应式网页设计”这个术语的人。他在他的文章*响应式网页设计*（[`alistapart.com/article/responsive-web-design/`](http://alistapart.com/article/responsive-web-design/)）中建议，网页应该无缝地调整和适应用户查看网站的环境，而不是专门针对特定平台进行处理。换句话说，网站应该是响应式的，无论在哪种屏幕尺寸上查看，都应该能够呈现。

以时代网站（[`time.com/`](http://time.com/)）为例。网页在桌面浏览器上的大屏幕上和移动浏览器上的有限可视区域上都能很好地适应。布局会随着视口大小的变化而变化和适应。如下截图所示，在移动浏览器上，标题的背景颜色是深灰色，图片按比例缩小，并且出现了一个“点击”栏，时代隐藏了最新新闻、杂志和视频栏目：

![响应式网页设计简介](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00219.jpeg)

构建响应式网站有两个组成部分，即**视口 meta 标签**和**媒体查询**。

## 视口 meta 标签

在智能手机如 iPhone 成为主流之前，每个网站都是建立在大约 1000 像素宽或 980 像素宽的基础上，然后缩小以适应手机屏幕，最终导致网站无法阅读。因此，`<meta name="viewport">`被创建出来。

简而言之，视口`meta`标签用于定义浏览器中网页的比例和可见区域（视口）。以下代码是视口 meta 标签的示例：

```html
<meta name="viewport" content="width=device-width, initial-scale=1">
```

上述视口`meta`标签规范将网页视口宽度定义为跟随设备。它还定义了在首次打开网页时网页缩放为 1:1，使得网页内容的大小和尺寸保持不变；它们不应该被放大或缩小。

为了更好地理解视口 meta 标签对网页布局的影响，我创建了两个网页进行比较；一个添加了视口 meta 标签，另一个没有。您可以在以下截图中看到差异：

![视口 meta 标签](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00220.jpeg)

在上图中显示的第一个网站使用了与我们之前代码示例中完全相同的视口 meta 标签规范。由于我们指定了`width=device-width`，浏览器会认识到网站视口与设备屏幕大小相同，因此不会压缩网页以适应整个屏幕。`initial-scale=1`将保持标题和段落的原始大小。

在第二个网站的示例中，由于我们没有添加视口`meta`标签，浏览器假定网页应该完全显示。因此，浏览器强制整个网站适应整个屏幕区域，使得标题和文本完全不可读。

### 关于屏幕大小和视口的说明

您可能在许多网页设计论坛或博客上发现视口和屏幕大小经常可以互换地提到。但实际上，它们是两个不同的东西。

屏幕大小指的是设备的实际屏幕大小。例如，13 英寸的笔记本电脑通常具有 1280*800 像素的屏幕大小。而视口描述的是浏览器中显示网站的可视区域。以下图示说明了这一点：

![关于屏幕大小和视口的说明](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00221.jpeg)

## 媒体查询

CSS 中的媒体类型模块使我们能够将样式规则定位到特定的媒体上。如果您以前创建过打印样式表，那么您肯定熟悉媒体类型的概念。CSS3 引入了一个称为媒体查询的新媒体类型，它允许我们在指定的视口宽度范围内应用样式，也被称为断点。

以下是一个简单的例子；当网站的视口大小为`480px`或更小时，我们将网站的`p`字体大小从`16px`减小到`14px`。

```html
p { 
font-size: 16px;
}
@media screen and (max-width: 480px) {
p {
    font-size: 14px;
}
} 
```

以下图示说明了上述代码：

![媒体查询](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00222.jpeg)

我们还可以使用`and`运算符结合多个视口宽度范围。根据我们之前的例子，我们可以将`p`字体大小设置为`14px`，当视口大小在`480px`和`320px`之间时，如下所示：

```html
@media screen and (min-width: 320px) and (max-width: 480px) {
p {
font-size: 11px;
  }
}
```

### 注意

**视口和媒体查询参考**

在构建响应式网站时，我们将处理视口 meta 标签和媒体查询。Packt Publishing 出版了一本专门的书籍，*使用 HTML5 和 CSS3 构建响应式网页设计*，*Ben Frein*，*Packt Publishing*，其中更详细地介绍了这两个方面。我建议将其作为本书的伴读书籍。

# 对响应式框架的一瞥

构建响应式网站可能是非常繁琐的工作。在构建响应式网站时需要考虑许多测量标准，其中之一就是创建响应式网格。

网格帮助我们构建具有正确对齐的网站。如果您以前使用过 960.gs（[`960.gs/`](http://960.gs/)），这是一个流行的 CSS 框架之一，您可能已经体验过通过在元素中添加预设类（如`grid_1`或`push_1`）来组织网页布局是多么容易。

然而，960.gs 网格是以固定单位像素（`px`）设置的，这在构建响应式网站时是不适用的。我们需要一个以百分比（`%`）单位设置网格的框架来构建响应式网站；我们需要一个响应式框架。

响应式框架提供了构建响应式网站的基本组件。通常，它包括用于组装响应式网格的类、用于排版和表单输入的基本样式，以及一些样式来解决各种浏览器的怪癖。一些框架甚至通过一系列样式进一步创建常见的设计模式和网页用户界面，如按钮、导航栏和图像滑块。这些预定义的样式使我们能够更快地开发响应式网站，减少麻烦。以下是使用响应式框架构建响应式网站的几个其他原因：

+   **浏览器兼容性**: 确保网页在不同浏览器上的一致性真的比开发网站本身更令人痛苦和苦恼。然而，有了框架，我们可以最小化处理浏览器兼容性问题的工作。框架开发人员很可能在公开发布之前在各种桌面浏览器和移动浏览器上测试了框架，这些浏览器环境最受限制。

+   **文档**: 一般来说，框架还附带有全面的文档，记录了使用框架的方方面面。文档对于初学者开始学习框架非常有帮助。当我们与团队合作时，文档也是一个很大的优势。我们可以参考文档让每个人都在同一页面上，并遵循标准的编码规范。

+   **社区和扩展**: 一些流行的框架，如 Bootstrap 和 Foundation，有一个活跃的社区，帮助解决框架中的错误并扩展功能。jQuery UI Bootstrap ([`jquery-ui-bootstrap.github.io/jquery-ui-bootstrap/`](http://jquery-ui-bootstrap.github.io/jquery-ui-bootstrap/))可能是一个很好的例子。jQuery UI Bootstrap 是一组 jQuery UI 小部件的样式，以匹配 Bootstrap 原始主题的外观和感觉。现在很常见的是找到基于这些框架的免费 WordPress 和 Joomla 主题。

在本书的过程中，我们将使用三种不同的响应式框架 Responsive.gs、Bootstrap 和 Foundation 构建三个响应式网站。

## 响应式.gs 框架

Responsive.gs ([`responsive.gs/`](http://responsive.gs/))是一个轻量级的响应式框架，压缩后仅为 1KB。Responsive.gs 基于宽度为 940px，并以 12、16 和 24 列的三种变体构建。此外，Responsive.gs 还附带了 box-sizing polyfill，它在 Internet Explorer 6、7 和 8 中启用了 CSS3 的 box-sizing，并使其在这些浏览器中表现得体面。

### 注意

Polyfill 是一段代码，它使某些 Web 功能和能力在浏览器中不是原生内置的情况下能够使用。通常，它解决了旧版本的 Internet Explorer 的问题。例如，您可以使用 HTML5Shiv ([`github.com/aFarkas/html5shiv`](https://github.com/aFarkas/html5shiv))，以便在 Internet Explorer 6、7 和 8 中识别新的 HTML5 元素，如`<header>`、`<footer>`和`<nav>`。

### 关于 CSS 框模型的说明

被归类为块级元素的 HTML 元素本质上是通过 CSS 绘制的具有内容宽度、高度、边距、填充和边框的框。在 CSS3 之前，我们在指定框时面临着一些限制。例如，当我们指定一个`<div>`标签的宽度和高度为`100px`时，如下所示：

```html
div { 
  width: 100px;
  height: 100px;
}
```

浏览器将`div`呈现为`100px`的正方形框，如下图所示：

![关于 CSS 框模型的说明](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00223.jpeg)

然而，只有在没有添加填充和边框的情况下才会成立。由于框有四个边，填充为 10px（`padding: 10px;`）实际上会为宽度和高度增加 20px——每个边增加 10px，如下图所示：

![关于 CSS 框模型的说明](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00224.jpeg)

虽然它占据页面上的空间，但元素的边距空间是在元素外部保留的，而不是作为元素本身的一部分；因此，如果我们给元素设置背景颜色，边距区域将不会采用该颜色。

### CSS3 盒模型

CSS3 引入了一个名为`box-sizing`的新属性，它允许我们指定浏览器应如何计算 CSS 盒模型。我们可以在`box-sizing`属性中应用几个值。

| 值 | 描述 |
| --- | --- |
| `content-box` | 这是盒模型的默认值。此值指定填充和边框框的厚度在指定的宽度和高度之外，正如我们在前面的部分中所演示的那样。 |
| `border-box` | 此值将执行与`content-box`相反的操作；它将包括填充和边框框作为盒子的宽度和高度。 |
| `padding-box` | 在撰写本书时，此值是实验性的，并且最近才被添加。此值指定了盒子的尺寸。 |

在本书的每个项目中，我们将使用`border-box`值，以便我们可以轻松确定网站的盒子尺寸。让我们以前面的例子来理解这一点，但这次我们将`box-sizing`模型设置为`border-box`。如前表所述，`border-box`值将保留盒子的宽度和高度为`100px`，而不管填充和边框的添加。下图显示了两种不同值的输出之间的比较，`content-box`（默认值）和`border-box`：

![CSS3 box sizing](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00225.jpeg)

在本书中，我们将使用 Responsive.gs，并在接下来的两章中更多地探索它，以构建一个简单的响应式博客。

## Bootstrap 框架

Bootstrap（[`getbootstrap.com/`](http://getbootstrap.com/)）最初是由 Mark Otto（[`markdotto.com/`](http://markdotto.com/)）开发，并最初仅用于 Twitter 内部使用。简而言之，Bootstrap 随后免费向公众发布。

### 注意

Bootstrap 长期以来一直与 Twitter 相关联，但自作者离开 Twitter 并且 Bootstrap 本身已经超出了他的预期，Bootstrap 现在成为了自己的品牌（[`blog.getbootstrap.com/2012/09/29/onward/`](http://blog.getbootstrap.com/2012/09/29/onward/)）。

如果参考最初的开发，响应式功能尚未添加。由于对创建响应式网站的需求不断增加，它在版本 2 中被添加。

Bootstrap 相比 Responsive.gs 还带有许多其他功能。它内置了预设的用户界面样式，包括网站上常用的按钮、导航栏、分页和表单等常见用户界面，因此在启动新项目时无需从头开始创建它们。此外，Bootstrap 还配备了一些自定义的 jQuery 插件，如图像滑块、轮播、弹出框和模态框。

您可以以多种方式使用和自定义 Bootstrap。您可以直接通过 CSS 样式表自定义 Bootstrap 主题及其组件，通过 Bootstrap 自定义和下载页面（[`getbootstrap.com/customize/`](http://getbootstrap.com/customize/)），或者使用 Bootstrap LESS 变量和混合，用于生成样式表。

在本书中，我们将在第五章中深入了解 Bootstrap，*使用 Bootstrap 开发投资组合网站*，以及第六章中，*使用 LESS 打磨响应式投资组合网站*，来构建一个响应式投资组合网站。

## Foundation 框架

Foundation（[`foundation.zurb.com/`](http://foundation.zurb.com/)）是由总部位于加利福尼亚的设计机构 ZURB 创建的框架。与 Bootstrap 类似，Foundation 不仅是一个响应式 CSS 框架；它还附带了预设的网格、组件和许多 jQuery 插件，以呈现交互式功能。

一些知名品牌，如 McAfee（[`www.mcafee.com/common/privacy/english/slide.html`](http://www.mcafee.com/common/privacy/english/slide.html)），这是最受尊敬的计算机防病毒品牌之一，已经使用 Foundation 构建了他们的网站。

Foundation 样式表由 Sass 提供支持，Sass 是基于 Ruby 的 CSS 预处理器。我们将在本书的最后两章中更多地讨论 Sass 以及 Foundation 的特性；在那里，我们将为一家初创公司开发一个响应式网站。

### 提示

有许多人抱怨响应式框架中的代码过多；由于 Bootstrap 等框架被广泛使用，它必须涵盖每种设计场景，因此会带有一些您网站可能不需要的额外样式。幸运的是，我们可以通过使用正确的工具（如 CSS 预处理器）和遵循适当的工作流程来轻松解决这个问题。

坦率地说，并没有完美的解决方案；使用框架并不适合每个人。一切都取决于您的需求、您网站的需求，特别是您客户的需求和预算。实际上，您将不得不权衡这些因素，以决定是否使用响应式框架。Jem Kremer 在她的文章*Responsive Design Frameworks: Just Because You Can, Should You?*（[`www.smashingmagazine.com/2014/02/19/responsive-design-frameworks-just-because-you-can-should-you/`](http://www.smashingmagazine.com/2014/02/19/responsive-design-frameworks-just-because-you-can-should-you/)）中对此进行了广泛讨论。

## CSS 预处理器简介

Bootstrap 和 Foundation 都使用 CSS 预处理器来生成它们的样式表。Bootstrap 使用 LESS（[`lesscss.org/`](http://lesscss.org/)）——尽管官方最近才发布了对 Sass 的支持。相反，Foundation 只使用 Sass 来生成其样式表（[`sass-lang.com/`](http://sass-lang.com/)）。

CSS 预处理器并不是一种全新的语言。如果您了解 CSS，您应该立即适应 CSS 预处理器。CSS 预处理器通过允许使用变量、函数和操作等编程功能来简单地扩展 CSS。

以下是我们使用 LESS 语法编写 CSS 的示例：

```html
@color: #f3f3f3;

body {
  background-color: @color;
}
p {
  color: darken(@color, 50%);
}
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

当编译前面的代码时，它会取出我们定义的`@color`变量并将其值放入输出中，如下所示：

```html
body {
  background-color: #f3f3f3;
}
p {
  color: #737373;
}
```

该变量可在整个样式表中重复使用，这使我们能够保持样式一致性并使样式表更易于维护。

在构建响应式网站的过程中，我们将进一步使用和探索 CSS 预处理器 LESS 和 Sass，以及 Bootstrap(第五章, *使用 Bootstrap 开发作品集网站*和第六章, *使用 LESS 打磨作品集网站*)和 Foundation(第七章, *使用 Foundation 创建企业响应式网站*和第八章, *扩展 Foundation*)。

## 尝试一下——深入了解响应式网页设计

我们在这里对响应式网页设计的讨论虽然重要，但只是冰山一角。关于响应式网页设计，有很多内容超出了我们最近在前几节中涵盖的内容。我建议你花些时间更深入地了解响应式网页设计，包括概念、技术细节和一些限制，以消除任何疑虑。

以下是一些最佳参考资料的推荐：

+   Ethan Martcotte 的《Responsive Web Design》([`alistapart.com/article/responsive-web-design`](http://alistapart.com/article/responsive-web-design))，这是一切的开始

+   另一个好的起点是 Rachel Shillcock 的《Responsive Web Design》([`webdesign.tutsplus.com/articles/responsive-web-design--webdesign-15155`](http://webdesign.tutsplus.com/articles/responsive-web-design--webdesign-15155))

+   Ian Yates 的《Don't Forget the Viewport Meta Tag》([`webdesign.tutsplus.com/articles/quick-tip-dont-forget-the-viewport-meta-tag--webdesign-5972`](http://webdesign.tutsplus.com/articles/quick-tip-dont-forget-the-viewport-meta-tag--webdesign-5972))

+   Rachel Andrew 的《How To Use CSS3 Media Queries To Create a Mobile Version of Your Website》([`www.smashingmagazine.com/2010/07/19/how-to-use-css3-media-queries-to-create-a-mobile-version-of-your-website/`](http://www.smashingmagazine.com/2010/07/19/how-to-use-css3-media-queries-to-create-a-mobile-version-of-your-website/))

+   阅读有关使用 HTML5 图片元素的响应式图片的未来标准的文章《Responsive Images Done Right: A Guide To <picture> And srcset》作者是 Eric Portis ([`www.smashingmagazine.com/2014/05/14/responsive-images-done-right-guide-picture-srcset/`](http://www.smashingmagazine.com/2014/05/14/responsive-images-done-right-guide-picture-srcset/))

+   一些使数据表响应式的方法的总结 ([`css-tricks.com/responsive-data-table-roundup/`](http://css-tricks.com/responsive-data-table-roundup/))

## 快速测验——响应式网页设计的主要组件

Q1. 在他的文章中，我们在本章中已经提到了两次，Ethan Marcotte 提到了构成响应式网站的主要技术要素。这些主要组件是什么？

1.  视口元标记和 CSS3 媒体查询。

1.  流体网格、灵活图片和媒体查询。

1.  响应式图片、断点和 polyfills。

Q2. 什么是视口？

1.  设备的屏幕尺寸。

1.  网页呈现的区域。

1.  设置网页视口大小的元标记。

Q3. 以下哪一种是声明 CSS3 媒体查询的正确方式？

1.  `@media (max-width: 320px) { p{ font-size:11px; }}`

1.  `@media screen and (max-device-ratio: 320px) { div{ color:white; }}`

1.  `<link rel="stylesheet" media="(max-width: 320px)" href="core.css" />`

# 响应式网页设计的灵感来源

现在，在我们跳入下一章并开始构建响应式网站之前，花些时间寻找响应式网站的想法和灵感可能是个好主意；看看它们是如何构建的，以及在桌面浏览器和移动浏览器上布局是如何组织的。

网站经常重新设计以保持新鲜是很常见的事情。因此，我们最好直接去策划网站的网站，而不是制作一堆网站截图，因为由于重新设计，这些截图可能在接下来的几个月内就不再相关了，以下是去的地方：

+   MediaQueries ([`mediaqueri.es/`](http://mediaqueri.es/))

+   Awwwards ([`www.awwwards.com/websites/responsive-design/`](http://www.awwwards.com/websites/responsive-design/))

+   CSS Awards ([`www.cssawards.net/structure/responsive/`](http://www.cssawards.net/structure/responsive/))

+   WebDesignServed ([`www.webdesignserved.com/`](http://www.webdesignserved.com/))

+   Bootstrap Expo ([`expo.getbootstrap.com/`](http://expo.getbootstrap.com/))

+   Zurb Responsive ([`zurb.com/responsive`](http://zurb.com/responsive))

# 摘要

在本章中，我们简要介绍了响应式网页设计背后的故事，以及视口元标签和 CSS3 媒体查询，这些构成了响应式网站。本章还总结了我们将使用以下框架来进行三个项目的工作：Responsive.gs，Bootstrap 和 Foundation。

使用框架是快速建立响应式网站的更简单的方法，而不是从头开始构建所有内容。然而，正如前面提到的，使用框架也有一些负面影响。如果做得不好，最终结果可能会出现问题。网站可能会被填充并卡在不必要的样式和 JavaScript 中，最终导致网站加载缓慢且难以维护。

我们需要设置合适的工具；它们不仅会促进项目的进行，还将帮助我们使网站更易于维护，这就是我们将在下一章中要做的事情。


# 第二章：Web 开发工具

*每个专业人士都有一套工具，可以简化他们的工作并完成任务。同样，我们也需要我们自己的工具来构建响应式网站。因此，在我们开始本书中的项目之前，我们需要准备以下工具。*

我们需要准备的工具包括：

+   用于编写代码的代码编辑器

+   一个编译器，将编译 CSS 预处理器语法为纯 CSS

+   在开发阶段本地托管网站的本地服务器

+   一个 Bower 来管理网站库

# 选择一个代码编辑器

一旦我们开始编写 HTML、CSS 和 JavaScript 代码，我们就需要一个代码编辑器。代码编辑器是开发网站的必不可少的工具。从技术上讲，你只需要文本编辑器，比如 OS X 中的 TextEdit 或 Windows 中的记事本来编写和编辑代码。然而，使用代码编辑器可以减少眼睛的刺激。

类似于 Microsoft Word，专门设计用于使单词和段落格式更直观，代码编辑器设计有一组特殊功能，可以改善代码编写体验，如语法高亮、自动补全、代码片段、多行选择，并支持大量语言。语法高亮将以不同的颜色显示代码，增强代码的可读性，并使查找代码中的错误变得容易。

我的个人偏好是 Sublime Text（[`www.sublimetext.com/`](http://www.sublimetext.com/)），这也是我在这本书中将要使用的。Sublime Text 是一个跨平台的代码编辑器，适用于 Windows、OS X 和 Linux。可以免费下载进行无限期评估。

### 注意

请记住，虽然 Sublime Text 允许我们无限期免费评估，但有时可能会提示您购买许可证。如果你开始感到烦恼，请考虑购买许可证。

## Sublime Text Package Control

我最喜欢 Sublime Text 的一件事是 Package Control，我们可以方便地从 Sublime Text 中搜索、安装、列出和删除扩展。但是，Package Control 并不是 Sublime Text 的预装软件。因此，假设你已经安装了 Sublime Text（我认为你应该已经安装了），我们将在 Sublime Text 中安装 Package Control。

# 行动时间-安装 Sublime Text Package Control

执行以下步骤安装 Sublime Text Package Control；这将允许我们轻松安装 Sublime Text 扩展：

1.  在 Sublime Text 中通过 Sublime Text 控制台是安装 Package Control 的最简单方法。在 Sublime Text 中导航到**View** | **Console**菜单以打开控制台。现在你应该看到一个新的输入字段出现在底部，如下面的截图所示：![行动时间-安装 Sublime Text Package Control](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00226.jpeg)

1.  由于 Sublime Text 3 进行了大规模的改动，几乎改变了整个 API，Package Control 现在分为两个版本，一个是 Sublime Text 2，另一个是 Sublime Text 3。每个版本都需要不同的代码来安装 Package Control。如果你使用的是 Sublime Text 2，复制代码从[`sublime.wbond.net/installation#st2`](https://sublime.wbond.net/installation#st2)。如果你使用的是 Sublime Text 3，复制代码从[`sublime.wbond.net/installation#st3`](https://sublime.wbond.net/installation#st3)。

1.  将你从第 2 步复制的代码粘贴到控制台输入字段中，如下面的截图所示：![行动时间-安装 Sublime Text Package Control](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00227.jpeg)

1.  按下*Enter*运行代码，最终安装 Package Control。请记住，这个过程可能需要一段时间，具体取决于您的互联网连接速度。

## *刚刚发生了什么？*

我们刚刚安装了 Package Control，可以轻松搜索、安装、列出和删除 Sublime Text 中的扩展。您可以通过**命令面板…**访问 Package Control，方法是导航到**工具** | **命令面板…**菜单。或者，您可以按键快捷方式更快地访问它。Windows 和 Linux 用户可以按*Ctrl* + *Shift* + *P*，而 OS X 用户可以按*Command* + *Shift* + *P*。然后，搜索**命令面板…**以列出 Package Control 的所有可用命令。

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00228.jpeg)

## 尝试一下-安装 LESS 和 Sass 语法高亮包

如第一章所述，我们将在本书的两个项目中使用这些 CSS 预处理器来编写样式。已经安装了 Sublime Text 和 Package Control，现在可以轻松安装 Sublime Text 包，以便为 LESS 和 Sass/SCSS 语法启用颜色高亮。继续并按照我们刚刚展示的说明安装 LESS 和 Sass/SCSS 包，它们的语法可以在以下位置找到：

+   Sublime Text 的 LESS 语法（[`github.com/danro/LESS-sublime`](https://github.com/danro/LESS-sublime)）

+   Sass 和 SCSS 的语法高亮（[`github.com/P233/Syntax-highlighting-for-Sass`](https://github.com/P233/Syntax-highlighting-for-Sass)）

## 设置本地服务器

在开发网站时，有一个本地服务器在我们的计算机上设置并运行是必要的。当我们使用本地服务器存储我们的网站时，我们可以通过浏览器在`http://localhost/`上访问它，并且我们也可以在手机浏览器和平板电脑上访问它，在`file:///`协议下运行网站时是不可能的。此外，一些脚本可能只能在 HTTP 协议（`http://`）下运行。

有许多应用程序可以通过几次点击轻松设置本地服务器，XAMPP（[`www.apachefriends.org/`](https://www.apachefriends.org/)）是本书中将要使用的应用程序。

# 操作时间-安装 XAMPP

XAMPP 适用于 Windows、OS X 和 Linux。从[`www.apachefriends.org/download.html`](https://www.apachefriends.org/download.html)下载安装程序；根据您当前使用的平台选择安装程序。每个平台都有不同的安装程序和不同的扩展名；Windows 用户将获得`.exe`，OSX 用户将获得`.dmg`，而 Linux 用户将获得`.run`。按照以下步骤在 Windows 中安装 XAMPP：

1.  启动 XAMPP`.exe`安装程序。

1.  如果 Windows 用户帐户控制提示**是否允许以下程序更改此计算机？**，请单击**是**。![操作时间-安装 XAMPP](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00229.jpeg)

1.  当**XAMPP 设置向导**窗口出现时，单击**下一步**开始设置。

1.  XAMPP 允许我们选择要安装的组件。在这种情况下，我们的 Web 服务器要求是最低限度的。我们只需要 Apache 来运行服务器，因此我们取消其他选项。（注意：**PHP**选项是灰色的；它无法取消选中）：![操作时间-安装 XAMPP](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00230.jpeg)

1.  确认要安装的组件后，单击**下一步**按钮继续。

1.  将提示您安装 XAMPP 的位置。让我们将其保留在默认位置`C:\xampp`，然后单击**下一步**。

1.  然后，简单地点击**下一步**，直到安装 XAMPP 的过程完成。等待过程完成。

1.  安装完成后，您应该会看到窗口上显示**安装 XAMPP 的设置已经完成**。单击**完成**按钮以完成流程并关闭窗口。

按照以下步骤在 OS X 中安装 XAMPP：

1.  对于 OS X 用户，打开 XAMPP`.dmg`文件。一个新的**Finder**窗口应该出现，其中包含实际的安装程序文件，通常命名为`xampp-osx-*-installer`（星号（`*`）代表 XAMPP 版本），如下图所示：![执行操作-安装 XAMPP](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00231.jpeg)

1.  双击**安装程序**文件开始安装。XAMPP 需要您的计算机凭据来运行安装程序。因此，请输入您的计算机名称和密码，然后单击**确定**以授予访问权限。

1.  然后会出现**XAMPP 设置向导**窗口；单击**下一步**开始设置。

1.  与 Windows 列出每个项目的组件不同，OS X 版本只显示两个组件，即**XAMPP 核心文件**和**XAMPP 开发人员文件**。在这里，我们只需要**XAMPP 核心文件**，其中包括我们需要运行服务器的 Apache、MySQL 和 PHP。因此，取消选择**XAMPP 开发人员**选项，然后单击**下一步**按钮继续。![执行操作-安装 XAMPP](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00232.jpeg)

1.  您将收到提示，XAMPP 将安装在`Applications`文件夹中。与 Windows 不同，此目录无法编辑。因此，单击**下一步**继续。

1.  然后，只需单击**下一步**按钮，继续下两个对话框以开始安装 XAMPP。等待直到完成。

1.  安装完成后，您将看到**安装 XAMPP 的设置已完成**显示在窗口中。单击**完成**按钮完成流程并关闭窗口。

执行以下步骤在 Ubuntu 中安装 XAMPP：

1.  下载 Linux 版 XAMPP 安装程序。安装程序以`.run`扩展名提供，适用于 32 位和 64 位系统。

1.  打开终端并导航到安装程序下载的文件夹。假设它在`Downloads`文件夹中，输入：

```html
cd ~/Downloads
```

1.  使用`chmod u+x`使`.run`安装程序文件可执行，然后输入`.run`安装程序文件名：

```html
chmod u+x xampp-linux-*-installer.run
```

1.  使用`sudo`命令执行文件，后跟`.run`安装程序文件位置，如下所示：

```html
sudo ./xampp-linux-x64-1.8.3-4-installer.run
```

1.  第 4 步的命令将弹出**XAMPP 设置向导**窗口。单击**下一步**继续，如下图所示：![执行操作-安装 XAMPP](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00233.jpeg)

1.  安装程序允许您选择要在计算机上安装的组件。与 OS X 版本类似，选项中显示了两个组件：**XAMPP 核心文件**（包含 Apache、MySQL、PHP 和一堆其他运行服务器的东西）和**XAMPP 开发人员文件**。由于我们不需要**XAMPP 开发人员文件**，因此我们可以取消选择它，然后单击**下一步**按钮。

1.  安装程序将向您显示将在`/opt/lampp`中安装 XAMPP。文件夹位置无法自定义。只需单击**下一步**按钮继续。

1.  单击**下一步**按钮，继续下两个对话框屏幕以安装 XAMPP。

## *刚刚发生了什么？*

我们刚刚在计算机上使用 MAMP 设置了本地服务器。您现在可以通过浏览器访问`http://localhost/`地址访问本地服务器。但是，对于 OS X 用户，地址是您的计算机用户名后跟`.local`。假设您的用户名是 john，本地服务器可以通过`john.local`访问。每个平台的本地服务器目录路径都不同。

+   在 Windows：`C:\xampp\htdocs`

+   在 OSX：`/Applications/XAMPP/htdocs`

+   在 Ubuntu：`/opt/lampp/htdocs`

### 提示

Ubuntu 用户可能希望更改权限并在桌面上创建一个`symlink`文件夹以便方便地访问`htdocs`文件夹。为此，您可以通过终端从桌面位置运行`sudo chown username:groupname /opt/lampp/htdocs`命令。将`username`和`groupname`替换为您自己的。

`ln -s /opt/lamp/htdocs`文件夹是我们必须放置项目文件夹和文件的位置。从现在开始，我们将简称这个文件夹为`htdocs`。XAMPP 还配备了一个图形应用程序，您可以在其中打开和关闭服务器，如下图所示：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00234.jpeg)

### 注意

Ubuntu 用户，您需要运行`sudo /opt/lampp/manager-linux.run`或`manager-linux-x64.run`。

## 选择 CSS 预处理器编译器

由于我们将使用 LESS 和 Sass 来生成响应式网站的样式表，我们将需要一个工具来将它们编译或转换成普通的 CSS 格式。

在 CSS 预处理器刚刚开始流行的时候，编译它们的唯一方法是通过命令行，这可能是当时许多人甚至不愿尝试 CSS 预处理器的绊脚石。幸运的是，现在我们有很多应用程序具有良好的图形界面来编译 CSS 预处理器；以下是供您参考的列表：

| 工具 | 语言 | 平台 | 价格 |
| --- | --- | --- | --- |
| --- | --- | --- | --- |
| WinLESS（[`winless.org/`](http://winless.org/)） | LESS | Windows | 免费 |
| SimpLESS（[`wearekiss.com/simpless`](http://wearekiss.com/simpless)） | LESS | Windows，OSX | 免费 |
| ChrunchApp（[`crunchapp.net`](http://crunchapp.net)） | LESS | Windows，OSX | 免费 |
| CompassApp（[`compass.handlino.com`](http://compass.handlino.com)） | Sass | Windows，OSX，Linux | $10 |
| Prepros（[`alphapixels.com/prepros/`](http://alphapixels.com/prepros/)） | LESS，Sass 等 | Windows，OSX | Freemium（$24） |
| Codekit（[`incident57.com/codekit/`](https://incident57.com/codekit/)） | LESS，Sass 等 | OSX | $29 |
| Koala（[`koala-app.com/`](http://koala-app.com/)） | LESS，Sass 等 | Windows，OSX，Linux | 免费 |

我将尽可能涵盖多个平台。无论您使用哪个平台，您都可以跟随本书中的所有项目。因此，我们将使用 Koala。它是免费的，并且可以在 Windows，OSX 和 Linux 这三个主要平台上使用。

在每个平台上安装 Koala 非常简单。

## 开发浏览器

理想情况下，我们必须在尽可能多的浏览器中测试我们的响应式网站，包括 Firefox Nightly（[`nightly.mozilla.org/`](http://nightly.mozilla.org/)）和 Chrome Canary（[`www.google.com/intl/en/chrome/browser/canary.html`](http://www.google.com/intl/en/chrome/browser/canary.html)）等测试版浏览器。这是为了确保我们的网站在不同环境中运行良好。然而，在开发过程中，我们可能会选择一个主要的浏览器进行开发，并作为网站应该如何展示的参考点。

在这本书中，我们将使用 Chrome（[`www.google.com/intl/en/chrome/browser/`](https://www.google.com/intl/en/chrome/browser/)）。我认为 Chrome 不仅运行速度快，而且也是一个非常强大的网页开发工具。Chrome 带有一套领先于其他浏览器的工具。以下是我在开发响应式网站时 Chrome 中两个我最喜欢的工具。

### 源映射

使用 CSS 预处理器的一个缺点是在调试样式表时。由于样式表是生成的，浏览器引用 CSS 样式表时，我们会发现很难发现代码在 CSS 预处理器样式表中的确切位置。

我们可以告诉编译器生成包含代码实际编写位置的注释，但源映射更优雅地解决了这个问题。与其生成一堆最终污染样式表的注释，我们可以在编译 CSS 预处理器时生成一个`.map`文件。通过这个`.map`文件，启用源映射的浏览器（如 Chrome）在检查元素时将能够直接指向源代码，如下面的截图所示：

![源映射](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00235.jpeg)

正如您从前面的屏幕截图中所看到的，左侧显示的 Chrome DevTools 启用了源映射，直接指向了允许我们轻松调试网站的`.less`文件。而右侧显示的源映射被禁用，因此它指向`.css`，调试网站将需要一些努力。

源映射功能在最新版本的 Chrome 中默认启用。因此，请确保您的 Chrome 是最新的。

### 移动模拟器

在真实设备上测试响应式网站，如手机或平板电脑，是无法替代的。每个设备都有其自身的优点；一些因素，如屏幕尺寸、屏幕分辨率和移动浏览器的版本，都会影响网站在设备上的显示。然而，如果不可能的话，我们可以使用移动模拟器作为替代方案。

Chrome 还附带了一个开箱即用的移动模拟器。该功能包含许多移动设备的预设值，包括 iPhone、Nexus 和 Blackberry。此功能不仅模拟设备的用户代理，还打开了许多设备规格，包括屏幕分辨率、像素比、视口大小和触摸屏。这个功能对于在开发早期调试我们的响应式网站非常有用，而不需要实际的移动设备。

移动模拟器可以通过 Chrome DevTool 的**控制台**抽屉中的**模拟**选项卡访问，如下面的屏幕截图所示：

![Mobile emulator](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00236.jpeg)

在 Chrome 内置的移动模拟器中，我们不需要再从第三方应用程序或 Chrome 扩展中设置另一个模拟器。在这里，我们将使用它来测试我们的响应式网站。

### 提示

Firefox 也有类似于 Chrome 移动模拟器的功能，尽管它只有很少的功能。您可以通过导航到**工具** | **Web 开发人员** | **响应式设计视图**菜单来启用此功能。

# 使用 Bower 管理项目依赖

我们将需要一些库来管理 Bower 的项目依赖关系。在 Web 开发环境中，我们将库称为一组代码，通常是 CSS 和 JavaScript，用于在网站上添加功能。通常，网站依赖于特定的库来实现其主要功能。例如，如果我建立一个用于转换货币的网站，该网站将需要 Account.js（[`josscrowcroft.github.io/accounting.js/`](http://josscrowcroft.github.io/accounting.js/)）；这是一个方便的 JavaScript 库，用于将常规数字转换为带有货币符号的货币格式。

通常，我们可能在单个网站上添加大约五个或更多的库，但是维护网站中使用的所有库，并确保它们都是最新的可能会变得繁琐。这就是 Bower 有用的地方。

Bower（[`bower.io/`](http://bower.io/)）是一个前端包管理器。它是一个方便的工具，可以简化我们在项目中添加、更新和删除库或依赖项（项目所需的库）的方式。Bower 是一个 Node.js 模块，因此我们首先必须在计算机上安装 Node.js（[`nodejs.org/`](http://nodejs.org/)）才能使用 Bower。

# 执行以下操作-安装 Node.js

执行以下步骤在 Windows、OS X 和 Ubuntu（Linux）中安装 Node.js。您可以直接跳转到您正在使用的平台的部分。

执行以下步骤在 Windows 中安装 Node.js：

1.  从 Node.js 下载页面（[`nodejs.org/download/`](http://nodejs.org/download/)）下载 Node.js Windows 安装程序。选择适合您 Windows 系统的 32 位或 64 位版本，以及`.msi`或`.exe`安装程序。

### 提示

**32 位或 64 位**

请按照此页面查看您的 Windows 计算机是运行在 32 位还是 64 位系统上[`windows.microsoft.com/en-us/windows/32-bit-and-64-bit-windows`](http://windows.microsoft.com/en-us/windows/32-bit-and-64-bit-windows)。

1.  运行安装程序（`.exe`或`.msi`文件）。

1.  单击 Node.js 欢迎消息的**下一步**按钮。

1.  通常情况下，当您安装软件或应用程序时，您将首先收到应用程序的许可协议提示。阅读完许可协议后，单击**我接受许可协议中的条款**，然后单击**下一步**按钮继续。

1.  然后，系统会提示您选择 Node.js 应安装的文件夹。将其保留为默认文件夹，即`C:\Program Files\nodejs\`。

1.  如下截图所示，安装程序然后会提示您是否要自定义要安装的项目。将其保留原样，然后单击**下一步**按钮继续，如下截图所示：![执行操作-安装 Node.js](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00237.jpeg)

1.  然后，单击**安装**按钮开始安装 Node.js。

1.  安装过程非常快速；只需几秒钟。如果看到通知显示**Node.js 已成功安装**，则可以单击**完成**按钮关闭安装窗口。

执行以下步骤在 OS X 中安装 Node.js：

1.  下载 OS X 的 Node.js 安装程序，其扩展名为`.pkg`。

1.  安装程序将向您显示欢迎消息，并显示将安装 Node.js 的位置（`/usr/local/bin`），如下截图所示：![执行操作-安装 Node.js](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00238.jpeg)

1.  然后，安装程序会显示用户许可协议。如果您已阅读并同意许可协议，请单击**同意**按钮，然后单击**下一步**按钮。

1.  OS X 的 Node.js 安装程序允许您在安装到计算机之前选择要安装的 Node.js 功能。在这里，我们将安装所有功能；只需单击**安装**按钮即可开始安装 Node.js，如下截图所示：![执行操作-安装 Node.js](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00239.jpeg)

### 注意

如果要自定义 Node.js 安装，请单击左下角的**自定义**按钮，如前面的截图所示。

执行以下步骤在 Ubuntu 中安装 Node.js：

在 Ubuntu 中安装 Node.js 非常简单。Node.js 可以通过 Ubuntu 的**高级打包工具**（**APT**）或`apt-get`安装。如果您使用的是 Ubuntu 13.10 版本或更高版本，可以启动终端并依次运行以下两个命令：

```html
sudo apt-get install nodejs
sudo apt-get install npm

```

如果您使用的是 Ubuntu 13.04 或更早版本，请改为运行以下命令：

```html
sudo apt-get install -y python-software-properties python g++ make
sudo add-apt-repository ppa:chris-lea/node.js
sudo apt-get update
sudo apt-get install nodejs

```

## *刚刚发生了什么？*

我们刚刚安装了 Node.js 和`npm`命令，这使我们能够稍后通过**Node.js 软件包管理器**（**NPM**）使用 Bower。`npm`命令行现在应该可以通过 Windows 命令提示符或 OS X 和 Ubuntu 终端访问。运行以下命令测试`npm`命令是否有效：

```html
npm -v

```

此命令返回计算机中安装的 NPM 版本，如下截图所示：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00240.jpeg)

此外，对于 Windows 用户，您可能会在命令提示符窗口顶部看到一条消息，显示**您的环境已设置为使用 Node.js 和 npm**，如下截图所示：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00241.jpeg)

这表明您可以在命令提示符中执行`node`和`npm`命令。由于我们已经设置了 Node.js 和`npm`正在运行，现在我们将安装 Bower。

## 英雄试试看-熟悉命令行

在本书中，我们将使用许多命令行来安装 Bower 以及 Bower 包。然而，如果您像我一样来自图形设计背景，在那里我们主要使用图形应用程序，第一次操作命令行可能会感到非常尴尬和令人生畏。因此，我建议您花时间熟悉基本的命令行。以下是一些值得参考的参考资料：

+   *设计师的命令行介绍* 由 Jonathan Cutrell 撰写（[`webdesign.tutsplus.com/articles/a-designers-introduction-to-the-command-line--webdesign-6358`](https://webdesign.tutsplus.com/articles/a-designers-introduction-to-the-command-line--webdesign-6358)）

+   《终端导航：温和介绍》由 Marius Masalar 撰写（[`computers.tutsplus.com/tutorials/navigating-the-terminal-a-gentle-introduction--mac-3855`](https://computers.tutsplus.com/tutorials/navigating-the-terminal-a-gentle-introduction--mac-3855)）

+   *Windows 命令提示符介绍* 由 Lawrence Abrams 撰写（[`www.bleepingcomputer.com/tutorials/windows-command-prompt-introduction/`](http://www.bleepingcomputer.com/tutorials/windows-command-prompt-introduction/)）

+   *Linux 命令介绍* 由 Paul Tero 撰写（[`www.smashingmagazine.com/2012/01/23/introduction-to-linux-commands/`](http://www.smashingmagazine.com/2012/01/23/introduction-to-linux-commands/)）

# 行动时间 - 安装 Bower

执行以下步骤安装 Bower：

1.  如果使用 Windows，请打开命令提示符。如果使用 OS X 或 Ubuntu，请打开终端。

1.  运行以下命令：

```html
npm install -g bower

```

### 注

如果在 Ubuntu 中安装 Bower 遇到问题，请使用 `sudo` 运行命令。

## *刚刚发生了什么？*

我们刚刚在计算机上安装了 Bower，这使得 `bower` 命令可用。我们在前面的命令中包含的 `-g` 参数是为了全局安装 Bower，这样我们就能在计算机的任何目录中执行 `bower` 命令。

## Bower 命令

安装了 Bower 之后，我们可以访问一组命令行来操作 Bower 的功能。我们将在终端中运行这些命令，或者在 Windows 中使用命令提示符，就像我们用 `npm` 命令安装 Bower 一样。所有命令都以 `bower` 开头，后面跟着命令关键字。以下是我们可能经常使用的命令列表：

| 命令 | 功能 |
| --- | --- |
| `bower install <library-name>` | 将库安装到项目中。当我们执行此功能时，Bower 会创建一个名为 `bower_components` 的新文件夹来保存所有库文件。 |
| `bower list` | 列出项目中所有已安装的包名称。该命令还会显示新版本（如果有的话）。 |
| `bower init` | 将项目设置为 Bower 项目。该命令还会创建 `bower.json`。 |
| `bower uninstall <library-name>` | 从项目中移除库名称。 |
| `bower version <library-name>` | 检索已安装的库版本。 |

### 注

你可以运行 `bower --help` 来获取完整的命令列表。

## 快速测验 - 网站开发工具和命令行

Q1\. 我们刚刚安装了 Sublime Text 和 Package Control。Package Control 用于什么？

1.  用于轻松安装和移除 Sublime Text 包。

1.  用于安装 LESS 和 Sass/SCSS 包。

1.  用于在 Sublime Text 中管理包。

Q2\. 我们还安装了 XAMPP。我们为什么需要安装 XAMPP？

1.  用于本地托管网站。

1.  用于本地开发网站。

1.  用于本地项目管理。

# 总结

在本章中，我们安装了 Sublime Text、XAMPP、Koala 和 Bower。所有这些工具将有助于我们构建网站。现在我们已经准备好了工具，我们可以开始着手项目了。所以，让我们继续下一章，开始第一个项目。


# 第三章：使用 Responsive.gs 构建一个简单的响应式博客

*在上一章中，我们安装了一些软件，这些软件将为我们的项目提供便利。在这里，我们将开始我们的第一个项目。在这个项目中，我们将构建一个响应式博客。*

*拥有博客对于一家公司来说是必不可少的。甚至一些财富 500 强公司，如联邦快递([`outofoffice.van.fedex.com/`](http://outofoffice.van.fedex.com/))，微软([`blogs.windows.com/`](https://blogs.windows.com/))和通用汽车([`fastlane.gm.com/`](http://fastlane.gm.com/))都有官方企业博客。博客是公司发布官方新闻以及与客户和大众联系的重要渠道。使博客具有响应式设计是使博客更易于读者访问的途径，这些读者可能通过手机或平板等移动设备访问网站。*

*由于我们在这个第一个项目中要构建的博客不会那么复杂，所以这一章对于刚接触响应式网页设计的人来说是一个理想的章节。*

*那么让我们开始吧。*

总之，在本章中，我们将涵盖以下主题：

+   深入了解 Responsive.gs 组件

+   审查博客蓝图和设计

+   整理网站文件和文件夹

+   查看 HTML5 元素以进行语义标记

+   构建博客标记

# Responsive.gs 组件

正如我们在第一章中提到的，*响应式网页设计*，Responsive.gs 是一个轻量级的 CSS 框架。它只包含构建响应式网站的最基本要求。在本节中，我们将看到 Responsive.gs 包含了什么。

## 类

Responsive.gs 附带了一系列可重复使用的类，用于形成响应式网格，使网页设计师更容易更快地构建网页布局。这些类包含经过精心校准和测试的预设样式规则。因此，我们可以简单地将这些类放入 HTML 元素中以构建响应式网格。以下是 Responsive.gs 中的类列表：

| 类名 | 用法 |
| --- | --- |
| `container` | 我们使用这个类来设置网页容器并将其对齐到浏览器窗口的中心。然而，这个类并不给出元素的宽度。Responsive.gs 给了我们根据需要设置宽度的灵活性。 |

| `row`，`group` | 我们使用这两个类来包装一组列。这两个类都设置了所谓的自清除浮动，以解决由 CSS `float`属性引起的一些布局问题。查看以下参考资料，了解有关 CSS `float`属性以及它可能对网页布局造成的问题的更多信息：

+   Louis Lazaris 的*CSS 浮动属性之谜*([`www.smashingmagazine.com/2009/10/19/the-mystery-of-css-float-property/`](http://www.smashingmagazine.com/2009/10/19/the-mystery-of-css-float-property/))

+   Chris Coyier 的*关于浮动的一切*([`css-tricks.com/all-about-floats/`](http://css-tricks.com/all-about-floats/))

|

| `col` | 我们使用这个类来定义网页的列。这个类设置了 CSS `float`属性。因此，任何设置了这个类的元素都必须包含在设置了`row`或`group`类的元素中，以避免 CSS `float`属性引起的问题。 |
| --- | --- |
| `gutters` | 我们使用这个类来在前面设置了`col`类的列之间添加空间。 |
| `span_{x}` | 这个类定义了列宽。因此，我们与`col`类一起使用这个类。Responsive.gs 有三种网格变体，这使我们在组织网页布局时更加灵活。Responsive.gs 有 12、16 和 24 列格式。这些变体设置在三个单独的样式表中。如果你下载了 Responsive.gs 包，然后解压缩，你会发现三个名为`responsive.gs.12col.css`、`responsive.gs.16col.css`和`responsive.gs.24col.css`的样式表。这些样式表之间唯一的区别是其中定义的`span_`类的数量。显然，24 列格式的样式表有最多的`span_{x}`类；该类从`span_1`到`span_24`。如果你需要更大的灵活性来划分你的页面，那么使用 Responsive.gs 的 24 列格式是一个好选择。尽管每列可能太窄。 |
| `clr` | 此类用于解决浮动问题。我们在使用行类不合适的情况下使用此类。 |

现在，让我们看看如何在示例中应用它们，以发现它们真正的作用。很多时候，你会看到一个网页被分成多列结构。以我们的示例为例；我们可以这样构建一个包含两列内容的网页：

```html
<div class="container">
<div class="row gutters">
  <div class="col span_6">
    <h3>Column 1</h3>
    <p>Lorem ipsum dolor sit amet, consectetur adipisicing    
elit. Veniam, enim.</p>
  </div>
  <div class="col span_6">
    <h3>Column 2</h3>
    <p>Lorem ipsum dolor sit amet, consectetur adipisicing
elit. Reiciendis, optio.</p>
  </div>
</div>
</div>
```

从上面的代码片段中可以看出，我们首先添加了包裹所有内容的`container`。然后，紧随其后的是带有`row`类的`div`，用于包裹列。同时，我们还添加了`gutters`类，以便在两列之间留出空白空间。在这个例子中，我们使用了 12 列格式。因此，为了将页面分成两个相等的列，我们为每个列添加了`span_6`类。这意味着`span_{x}`类的数量应该等于 12、16 或 24，以便根据我们使用的变体使列覆盖整个容器。因此，如果我们使用了 16 列格式，我们可以添加`span_8`。

在浏览器中，我们将看到以下输出：

![The classes](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00242.jpeg)

# 使用 HTML5 元素进行语义标记

保罗·博格在他的文章《语义代码：什么？为什么？怎么？》中写道：（[`boagworld.com/dev/semantic-code-what-why-how/`](http://boagworld.com/dev/semantic-code-what-why-how/)）

> *HTML 最初是用来描述文档内容的手段，而不是为了使其外观上令人愉悦。*

与传统的报纸或杂志等明显是为人类而设计的内容发布不同，网络既被人类阅读，也被搜索引擎和屏幕阅读器等机器阅读，这些机器帮助视觉受损的人浏览网站。因此，使我们的网站结构具有语义是非常鼓励的。语义标记使这些机器更好地理解内容，也使内容在不同格式下更易访问。

因此，HTML5 在使网络更具语义的使命中引入了一堆新元素。以下是我们将用于博客的元素列表：

| 元素 | 描述 |
| --- | --- |
| `<header>` | `<header>`元素用于指定一个部分的头部。虽然这个元素通常用于指定网站的头部，但也适合用于指定文章头部，例如我们放置标题和其他支持文章的部分。我们可以在单个页面中多次使用`<header>`。 |
| `<nav>` | `<nav>`元素用于表示网站的主要导航或页面部分的一组链接。 |
| `<article>` | `<article>`元素相当不言自明。该元素指定网站的文章，如博客条目或主页内容。 |
| `<main>` | `<main>`元素定义了部分的主要部分。这个元素可以用来做一些事情，比如包装文章内容。 |
| `<figure>` | `<figure>`元素用于指定文档中的图表、插图和图片。`<figure>`元素可以与`<figcaption>`一起使用，以添加图表的标题（如果需要的话）。 |
| `<figcaption>` | 如前所述，`<figcaption>`表示文档图表的标题。因此，它必须与`<figure>`元素一起使用。 |
| `<footer>` | 与`<header>`元素类似，`<footer>`元素通常用于指定网站页脚。但它也可以用来表示部分的结束或最低部分。 |

### 提示

参考这个速查表[`websitesetup.org/html5-cheat-sheet/`](http://websitesetup.org/html5-cheat-sheet/)，了解 HTML5 中的更多新元素。

## HTML5 搜索输入类型

除了新元素，我们还将在博客中添加一种特定的新输入类型，搜索。顾名思义，搜索输入类型用于指定搜索输入。在桌面浏览器中，您可能看不到明显的区别。您可能也不会立即看到搜索输入类型如何为网站和用户带来优势。

搜索输入类型将提升移动用户的体验。iOS、Android 和 Windows Phone 等移动平台已经配备了上下文屏幕键盘。键盘会根据输入类型而改变。您可以在下面的屏幕截图中看到，键盘显示了**搜索**按钮，让用户更方便地进行搜索：

![HTML5 搜索输入类型](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00243.jpeg)

### HTML5 placeholder 属性

HTML5 引入了一个名为`placeholder`的新属性。规范描述了这个属性作为一个短提示（一个词或短语），旨在在控件没有值时帮助用户进行数据输入，如下面的例子所示：

```html
<input type="search" name="search_form " placeholder="Search here…"> 
```

您会看到`placeholder`属性中的**在这里搜索…**显示在输入字段中，如下面的屏幕截图所示：

![HTML5 placeholder 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00244.jpeg)

过去，我们依赖 JavaScript 来实现类似的效果。如今，有了`placeholder`属性，应用程序变得简单得多。

## HTML5 在 Internet Explorer 中

这些新的 HTML 元素使我们的文档标记更具描述性和意义。不幸的是，Internet Explorer 6、7 和 8 将无法识别它们。因此，无法应用到这些元素的选择器和样式规则；就好像这些新元素没有包含在 Internet Explorer 字典中一样。

这就是一个名为 HTML5Shiv 的 polyfill 发挥作用的地方。我们将包括 HTML5Shiv（[`github.com/aFarkas/html5shiv`](https://github.com/aFarkas/html5shiv)）来使 Internet Explorer 8 及更低版本认识这些新元素。阅读 Paul Irish 的以下帖子（[`paulirish.com/2011/the-history-of-the-html5-shiv/`](http://paulirish.com/2011/the-history-of-the-html5-shiv/)）了解 HTML5Shiv 背后的历史；它是如何发明和发展的。

此外，旧版的 Internet Explorer 无法渲染 HTML5 中的`placeholder`属性中的内容。幸运的是，我们可以使用一个 polyfill（[`github.com/UmbraEngineering/Placeholder`](https://github.com/UmbraEngineering/Placeholder)）来模拟旧版 Internet Explorer 中`placeholder`属性的功能。我们以后也会在博客中使用它。

## 在 Responsive.gs 包中查看 polyfills

Responsive.gs 还附带了两个 polyfills，以启用 Internet Explorer 6、7 和 8 中不支持的某些功能。从现在开始，让我们把这些浏览器版本称为“旧版 Internet Explorer”，好吗？

### 盒模型 polyfills

第一个 polyfill 是通过名为`boxsizing.htc`的**HTML 组件**（**HTC**）文件提供的。

HTC 文件与 JavaScript 非常相似，通常与 Internet Explorer 专有的 CSS 属性`behavior`一起使用，以为 Internet Explorer 添加特定功能。Responsive.gs 附带的`boxsizing.htc`文件将应用与 CSS3 `box-sizing`属性类似的功能。

Responsive.gs 在样式表中包含了`boxsizing.htc`文件，如下所示：

```html
* { 
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box;
  *behavior: url(/scripts/boxsizing.htc); 
}
```

如上面的代码片段所示，Responsive.gs 应用了`box-sizing`属性，并在通配符选择器中包含了`boxsizing.htc`文件。这个通配符选择器也被称为通配符选择器；它选择文档中的所有元素，也就是说，在这种情况下，`box-sizing`将影响文档中的所有元素。

### 注意

`boxsizing.htc`文件路径必须是绝对路径或相对于 HTML 文档的路径，以使填充脚本起作用。这是一个技巧。这是我们强制使用的东西，以使旧版 Internet Explorer 表现得像现代浏览器一样。像上面的 HTC 文件一样使用并不符合 W3C 标准。 

请参考微软关于 HTC 文件的页面（[`msdn.microsoft.com/en-us/library/ms531018(v=vs.85).aspx`](http://msdn.microsoft.com/en-us/library/ms531018(v=vs.85).aspx)）。

### CSS3 媒体查询填充

Responsive.gs 附带的第二个填充脚本是`respond.js`（[`github.com/scottjehl/Respond`](https://github.com/scottjehl/Respond)），它将"神奇地启用"CSS3 `respond.js`以使其立即可用。无需配置；我们可以简单地在`head`标签中链接脚本，如下所示：

```html
<!--[if lt IE 9]>
<script src="img/respond.js"></script>
<![endif]-->
```

在上面的代码中，我们将脚本封装在`<!--[if lt IE 9]>`中，以便脚本只在旧版 Internet Explorer 中加载。

# 检查博客的线框图

建立网站与建造房子很相似；我们需要在堆砌所有砖块之前检查每个角落的规格。因此，在我们着手建立博客之前，我们将检查博客的线框图，看看博客的布局是如何排列的，以及将在博客上显示的内容。

让我们来看一下下面的线框图。这个线框图展示了在桌面屏幕上查看博客布局时的情况：

![检查博客的线框图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00245.jpeg)

正如在上面的截图中所示，博客将是简单明了的。在页眉中，博客将有一个标志和一个搜索表单。在页眉下方，依次放置菜单导航、博客文章、用于导航到下一个或上一个文章列表的分页和页脚。

博客文章通常包括标题、发布日期、文章的特色图片和文章摘要。这个线框图是博客布局的抽象。我们将用它作为博客布局将如何排列的视觉参考。因此，尽管我们在前面的线框图中只显示了一篇文章，但实际上我们稍后会在实际博客中添加更多的文章。

当视口宽度被挤压时，以下是博客布局：

检查博客的线框图

当视口宽度变窄时，博客布局会自适应。值得注意的是，当我们改变布局时，我们不应该改变内容流和 UI 层次结构。确保桌面版和移动版之间的布局一致性将帮助用户快速熟悉网站，无论他们在哪里查看网站。如上面的线框图所示，我们仍然按照相同的顺序设置了 UI，尽管它们现在是垂直堆叠以适应有限的区域。

这个线框图值得一提的是，导航变成了一个 HTML 下拉选择。在建立博客的过程中，我们将讨论如何做到这一点。

现在，我们已经准备好工具并检查了博客布局，我们准备开始项目。我们将从创建和组织项目目录和资产开始。

# 组织项目目录和文件

通常，我们将不得不链接到某些文件，比如样式表和图片。不幸的是，网站并不聪明；它们无法自行找到这些文件。因此，我们必须正确设置文件路径，以避免链接错误。

这就是为什么在构建网站时拥有有组织的目录和文件是至关重要的。当我们在一个由许多人组成的团队中进行非常大型的项目，并且需要处理数十到数百个文件时，这将变得非常重要。管理不善的目录可能会让团队中的任何人都发疯。

有组织良好的目录将帮助我们最小化潜在的链接错误。这也将使项目在未来更易于维护和扩展。

# 创建和组织项目目录和资产的行动时间

执行以下步骤来设置项目的工作目录：

1.  转到`htdocs`文件夹。作为提醒，这个文件夹是位于本地服务器中的文件夹：

+   在 Windows 中的`C:\xampp\htdocs`

+   在 OSX 中的`/Applications/XAMPP/htdocs`

+   在 Ubuntu 中的`/opt/lampp/htdocs`

1.  创建一个名为`blog`的新文件夹。从现在开始，我们将把这个文件夹称为项目目录。

1.  创建一个名为`css`的新文件夹来存储样式表。

1.  创建一个名为`image`的新文件夹来存储图片。

1.  创建一个名为`scripts`的新文件夹来存储 JavaScript 文件。

1.  创建一个名为`index.html`的新文件；这个 HTML 文件将是博客的主页。从[`responsive.gs/`](http://responsive.gs/)下载 Responsive.gs 软件包。该软件包以`.zip`格式提供。解压缩软件包以释放其中的文件。在那里，你会发现许多文件，包括样式表和 JavaScript 文件，正如你从以下截图中所看到的：![Time for action – creating and organizing project directories and assets](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00247.jpeg)

Responsive.gs 中的文件

1.  将`responsive.gs.12col.css`移动到项目目录的`css`文件夹中；这是我们需要的 Responsive.gs 唯一的样式表。

1.  将`boxsizing.htc`移动到项目目录的`scripts`文件夹中。

1.  Responsive.gs 软件包中的`respond.js`文件已过时。让我们从 GitHub 存储库（[`github.com/scottjehl/Respond/blob/master/src/respond.js`](https://github.com/scottjehl/Respond/blob/master/src/respond.js)）下载最新版本的 Respond.js，并将其放在项目目录的`scripts`文件夹中。

1.  从[`github.com/aFarkas/html5shiv`](https://github.com/aFarkas/html5shiv)下载 HTML5Shiv。将 JavaScript 文件`html5shiv.js`放在`scripts`文件夹中。

1.  我们还将使用由 James Brumond 开发的占位符填充（[`github.com/UmbraEngineering/Placeholder`](https://github.com/UmbraEngineering/Placeholder)）。James Brumond 为不同的场景开发了四种不同的 JavaScript 文件。

1.  我们将在这里使用的脚本是`ie-behavior.js`，因为这个脚本专门针对 Internet Explorer。下载脚本（[`raw.githubusercontent.com/UmbraEngineering/Placeholder/master/src/ie-behavior.js`](https://raw.githubusercontent.com/UmbraEngineering/Placeholder/master/src/ie-behavior.js)）并将其重命名为`placeholder.js`，以使其更明显地表明这个脚本是一个占位符填充。将其放在项目目录的`scripts`文件夹中。

1.  博客将需要一些图像作为帖子的特色图像。在本书中，我们将使用以下屏幕截图中显示的图像，这些图像是由 Levecque Charles（[`twitter.com/Charleslevecque`](https://twitter.com/Charleslevecque)）和 Jennifer Langley（[`jennifer-langley.squarespace.com/photography/`](https://jennifer-langley.squarespace.com/photography/)）连续拍摄的：![行动时间-创建和组织项目目录和资产](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00248.jpeg)

### 提示

在 Unsplash（[`unsplash.com/`](http://unsplash.com/)）上找到更多免费的高清图像。

1.  我们将为博客添加一个网站图标。网站图标是一个小图标，出现在浏览器标签旁边的标题旁边，这对于读者快速识别博客将会很有帮助。以下是一个屏幕截图，显示了 Chrome 中的一些固定标签。我敢打赌，你仍然能够通过查看网站图标来识别这些标签中的网站：![行动时间-创建和组织项目目录和资产](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00249.jpeg)

Google Chrome 固定标签

1.  此外，我们还将添加 iOS 图标。在 iPhone 和 iPad 等苹果设备上，我们可以将网站固定在主屏幕上，以便快速访问网站。这就是苹果图标派上用场的地方。iOS（iPhone/iPad 操作系统）将显示我们提供的图标，如下面的屏幕截图所示，就像是一个本地应用程序：![行动时间-创建和组织项目目录和资产](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00250.jpeg)

将网站添加到 iOS 主屏幕

1.  这些图标包含在随本书提供的源文件中。将这些图标复制并粘贴到我们刚刚在步骤 5 中创建的图像文件夹中，如下面的屏幕截图所示：![行动时间-创建和组织项目目录和资产](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00251.jpeg)

### 提示

使用 AppIconTemplate 快速轻松地创建网站图标和 iOS 图标。

AppIconTemplate（[`appicontemplate.com/`](http://appicontemplate.com/)）是一个 Photoshop 模板，可以让我们轻松设计图标。该模板还附带了 Photoshop 操作，可以通过几次点击生成图标。

## *刚刚发生了什么？*

我们刚刚为这个项目创建了一个目录，并将一些文件放入了该目录。这些文件包括 Responsive.gs 样式表和 JavaScript 文件、图像和图标，以及一些 polyfill。我们还创建了一个`index.html`文件，这将是博客的主页。此时，项目目录应包含如下屏幕截图中显示的文件：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00252.jpeg)

当前的工作目录中的文件和文件夹

## 尝试使目录结构更有组织性

许多人对如何组织他们项目的目录结构有自己的偏好。在上一节中显示的只是一个例子，是我个人管理该项目目录的方式。

尝试进一步使目录更有组织，并满足您对组织的个人偏好。一些常见的想法如下：

+   缩短文件夹名称，即`js`和`img`，而不是 JavaScript 和 Image

+   将`js`、`img`和`css`文件夹全部放在一个名为`assets`的新文件夹中

## 小测验-使用 polyfill

在本书的早些时候，我们讨论了 polyfill，并提到了一些我们将在博客中实现的 polyfill 脚本。

Q1.你认为何时使用 polyfill 会更合适？

1.  当博客在 Internet Explorer 6 中查看时。

1.  当浏览器不支持该功能时。

1.  当我们需要在网站上添加新功能时。

1.  我们可以随时使用它。

# 博客 HTML 结构

我们在上一节中已经介绍了项目目录和文件的结构。现在让我们开始构建博客标记。正如我们提到的，我们将使用一些 HTML5 元素来形成更有意义的 HTML 结构。

# 行动时间-构建博客

执行以下步骤来构建博客：

1.  打开我们在上一节*行动时间-创建和组织项目目录和资产*的第 6 步中创建的`index.html`文件。让我们从添加最基本的 HTML5 结构开始，如下所示：

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Blog</title>
</head>
<body>

</body>
</html>
```

在这里，设置`DOCTYPE`，它已经被简化到最低形式。HTML5 中的`DOCTYPE`格式现在比其 HTML4 对应格式更短更干净。然后，我们设置页面的语言，这里设置为`en`（英语）。您可以根据自己的语言更改它；在[`en.wikipedia.org/wiki/List_of_ISO_639-1_codes`](http://en.wikipedia.org/wiki/List_of_ISO_639-1_codes)上找到您本地语言的代码。

我们还将字符编码设置为`UTF-8`，以使浏览器能够将 Unicode 字符（如`U+20AC`）呈现为可读格式`€`。

1.  在`head`标签中的`charset`元标签下方，添加以下 meta：

```html
<meta http-equiv="X-UA-Compatible" content="IE=edge">
```

Internet Explorer 有时会表现得很奇怪，突然切换到兼容模式，并以 Internet Explorer 8 和 7 中查看的方式呈现页面。这个 meta 标签的添加将阻止这种情况发生。它将强制 Internet Explorer 以最新标准的最高支持度呈现页面。

1.  在`http-equiv`元标签下方，添加以下 meta 视口标签：

```html
<meta name="viewport" content="width=device-width, initial-scale=1">
```

正如我们在第一章中提到的*响应式网页设计*，前面的视口 meta 标签规范定义了网页视口宽度，以跟随设备视口大小。它还定义了在首次打开网页时的网页比例为 1:1。

1.  使用`link`标签将苹果图标链接如下：

```html
<link rel="apple-touch-icon" href="image/icon.png">
```

根据苹果的官方说明，通常需要包含多个图标源，以满足 iPhone、iPad 和具有 Retina 屏幕的设备。这对我们的博客实际上并不是必要的。诀窍在于，我们通过单一来源提供所需的最大尺寸，即 512 像素，如前面的屏幕截图所示。

### 注意

前往苹果文档，为 Web Clip 指定网页图标（[`developer.apple.com/library/ios/documentation/AppleApplications/Reference/SafariWebContent/ConfiguringWebApplications/ConfiguringWebApplications.html`](https://developer.apple.com/library/ios/documentation/AppleApplications/Reference/SafariWebContent/ConfiguringWebApplications/ConfiguringWebApplications.html)），以供进一步参考。

1.  在标题下方添加描述 meta 标签，如下所示：

```html
<meta name="description" content="A simple blog built using Responsive.gs">
```

1.  博客的描述将显示在**搜索引擎结果页面**（**SERP**）中。在这一步中，我们将构建博客标题。首先，让我们添加 HTML5 的`<header>`元素以及用于样式的类，以包装标题内容。在`body`标签中添加以下内容：

```html
<header class="blog-header row">

</header>
```

1.  在我们在第 9 步中添加的`<header>`元素中，添加一个新的`<div>`元素，带有`container`和`gutters`类，如下所示：

```html
<header class="blog-header row">
<div class="container gutters">

</div>
</header>
```

参考本章前面显示的表格，`container`类将使博客标题内容居中于浏览器窗口，而`gutters`类将在下一步中添加的列之间添加间距。

1.  在新的列中创建一个包含博客标志/名称的`<div>`元素，以及 Responsive.gs 的`col`和`span_9`类，将`<div>`元素设置为列并指定宽度。不要忘记添加类以添加自定义样式：

```html
<header class="blog-header row">
<div class="container gutters">
       <div class="blog-name col span_9">
<a href="/">Blog</a>
</div>
</div>
</header>
```

1.  参考博客线框图，我们将在博客标志/名称旁边放置一个搜索表单。因此，使用 Responsive.gs 的`col`和`span_3`类以及输入搜索类型创建另一个新的列。在标志标记下方添加以下`<div>`元素：

```html
<header class="blog-header row">
<div class="container gutters">
       <div class="blog-name col span_9">
   <a href="/">Blog</a>
</div>
<div class="blog-search col span_3">
           <div class="search-form">
             <form action="">
 <input class="input_full" type="search"      placeholder="Search here...">
  </form>
            </div>
   </div>
</div>
</header>
```

正如我们在本章前面提到的，我们使用了一个输入搜索类型来提供更好的用户体验。这个输入将显示移动屏幕键盘，带有一个特殊的键，允许用户点击**搜索**按钮并立即运行搜索。我们还使用 HTML5 的`placeholder`属性添加占位文本，向用户显示他们可以通过输入框在博客中进行搜索。

1.  构建完头部博客后，我们将构建博客导航。在这里，我们将使用 HTML5 的`nav`元素来定义一个新的导航部分。创建一个带有支持样式的`nav`元素。在头部构建下方添加`nav`元素如下：

```html
...     
</div>
</header> 
<nav class="blog-menu row">

</nav>
```

1.  在`nav`元素内，创建一个带有`container`类的`div`元素，将导航内容对齐到浏览器窗口的中心：

```html
<nav class="blog-menu">
<div class="container">
</div>
</nav>
```

1.  根据线框图，博客将在链接菜单上有五个项目。我们将使用`ul`元素布置这些链接。在容器内添加链接，如下所示的代码片段：

```html
<nav class="blog-menu row">
  <div class="container">
       <ul class="link-menu">
         <li><a href="/">Home</a></li>
         <li><a href="#">Archive</a></li>
         <li><a href="#">Books</a></li>
         <li><a href="#">About</a></li>
         <li><a href="#">Contact</a></li>
      </ul>
</div>
</nav>
```

1.  完成导航构建后，我们将构建博客内容部分。根据线框图，内容将包括一系列文章。首先，让我们添加 HTML5 的`<main>`元素，将内容包裹在导航下方如下：

```html
...
</ul>  
</nav>
<main class="blog-content row">

</main>
```

我们使用`<main>`元素，因为我们认为文章是博客的主要部分。

1.  与其他博客部分一样——头部和导航——我们添加一个容器`<div>`将博客文章对齐到中心。在`<main>`元素内添加这个`<div>`元素：

```html
<main class="blog-content row">
   <div class="container">

</div>
</main>
```

1.  现在我们将创建博客文章的标记。把博客文章想象成一篇文章。因此，在这里我们将使用`<article>`元素。在第 17 步中添加的容器`<div>`内添加`<article>`元素如下：

```html
<main class="blog-content row">
<div class="container">
  <article class="post row">

  </article>
</div>
</main>
```

1.  如前所述，`<header>`元素不仅限于定义头部。博客也可以用来定义一个部分的头部。在这种情况下，除了博客头部，我们将使用`<header>`元素来定义包含文章标题和发布日期的文章头部部分。

1.  在文章元素内添加`<header>`元素：

```html
<article class="post row">
<header class="post-header">
<h1 class="post-title">
<a href="#">Useful Talks &amp; Videos for Mastering CSS</a>
  </h1>
      <div class="post-meta">
     <ul>
        <li class="post-author">By John Doe</li>
        <li class="post-date">on January, 10 2014</li>
     </ul>
     </div>
</header>
</article>
```

1.  一图胜千言。因此，使用图片来支持文章是常态。在这里，我们将在文章头部下方显示图片。我们将特色图片与文章摘要一起分组，作为文章摘要，如下所示：

```html
...
 </header>
 <div class="post-summary">
<figure class="post-thumbnail">
<img src="img/village.jpg" height="1508" width="2800" alt="">
</figure>
<p class="post-excerpt">Lorem ipsum dolor sit amet,   consectetur adipisicing elit. Aspernatur, sequi, voluptatibus, consequuntur vero iste autem aliquid qui et rerum vel ducimus ex enim quas!...<a href="#">Read More...</a></p>
  </div>
</article>
```

随后添加几篇文章。可选地，你可以在其他文章中排除特色图片。

1.  添加了一堆文章后，我们现在将添加文章分页。分页是一种常见的页面导航形式，允许我们跳转到下一个或上一个文章列表。通常，分页位于最后一篇文章项之后的页面底部。

博客的分页包括两个链接，用于导航到下一页和上一页，以及一个小节用于放置页面数字，显示用户当前所在的页面。

1.  在最后一篇文章后添加以下代码：

```html
...
</article>
<div class="blog-pagination">
<ul>
  <li class="prev"><a href="#">Prev. Posts</a></li>
  <li class="pageof">Page 2 of 5</li>
  <li class="next"><a href="#">Next Posts</a></li>
</ul>
</div>
```

1.  最后，我们将构建博客页脚。我们可以使用 HTML5 的`<footer>`元素来定义博客页脚。页脚结构与头部相同。页脚将有两列；分别包含博客页脚链接（或者，我们称之为次要导航）和版权声明。这些列将被包裹在一个`<div>`容器内。在主要部分添加以下页脚，如下所示：

```html
      …
</main> 
<footer class="blog-footer row">
   <div class="container gutters">
     <div class="col span_6">
<nav id="secondary-navigation"  class="social-   media">
          <ul>
           <li class="facebook">
<a href="#">Facebook</a>
  </li>
           <li class="twitter">
<a href="#">Twitter</a></li>
           <li class="google">
<a href="#">Google+</a>
   </li>
         </ul>
       </nav>
     </div>
   <div class="col span_6">
<p class="copyright">&copy; 2014\. Responsive  Blog.</p>
   </div>
   </div>
</footer>
```

## *刚刚发生了什么？*

我们刚刚完成了博客的 HTML 结构——头部、导航、内容和页脚。假设你一直在密切关注我们的指示，你可以在`http://localhost/blog/`或`http://{coputer-username}.local/blog/`中访问博客。

然而，由于我们还没有应用任何样式，你会发现博客看起来很简单，布局还没有组织好：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00253.jpeg)

当前阶段的博客外观

我们将在下一章中为博客添加样式。

## 英雄试试看-创建更多博客页面

在本书中，我们只构建了博客的主页。但是，您可以通过创建更多页面来扩展博客，例如添加关于页面、单篇文章内容页面和带有联系表单的页面。您可以重用本章中构建的 HTML 结构。删除`<main>`元素内的任何内容，并根据需要替换为内容。

## 快速测验-HTML5 元素

让我们以有关 HTML5 的简单问题结束本章：

Q1. `<header>`元素用于什么？

1.  它用于表示网站页眉。

1.  它用于表示一组介绍和导航辅助。

Q2. `<footer>`元素用于什么？

1.  它用于表示网站页脚。

1.  它用于表示部分的结束或最低部分。

Q3. 在单个页面内允许多次使用`<header>`和`<footer>`元素吗？

1.  是的，只要语义上合乎逻辑。

1.  不，这被认为是多余的。

# 总结

在本章中，我们开始了我们的第一个项目。在本章的早些时候，我们探讨了 Responsive.gs 组件，了解了 Responsive.gs 如何构建响应式网格，以及用于塑造网格的类。

我们还讨论了 HTML5，包括新元素，即在不支持特定功能的浏览器中模仿 HTML5 功能的 polyfills。然后，我们使用 HTML5 构建博客标记。

在下一章中，我们将更多关注使用 CSS3 标记博客，并添加一些 JavaScript。我们还将调试博客，以解决在旧版 Internet Explorer 中出现的错误。


# 第四章：增强博客外观

*在前一章中，我们使用 HTML5 元素从标题部分到页脚部分构建了博客标记。然而，博客目前还是没有样式的。如果你在浏览器中打开博客，你只会看到它是空的；我们还没有编写样式来完善它的外观。*

*在本章的过程中，我们将专注于使用 CSS 和 JavaScript 装饰博客。我们将使用 CSS3 来添加博客样式。CSS3 带来了许多新的 CSS 属性，如`border-radius`、`box-shadow`和`box-sizing`，使我们能够装饰网站而无需添加图片和额外的标记。*

*然而，如前所述，CSS 属性仅适用于最新的浏览器版本。Internet Explorer 6 到 8 无法识别这些 CSS 属性，并且无法在浏览器中输出结果。因此，作为补充，我们还将利用一些 polyfill 来使我们的博客在旧版 Internet Explorer 中呈现出色。*

*这将是一个充满冒险的章节。让我们开始吧。*

在本章中，我们将涵盖以下主题：

+   研究 CSS3 属性和 CSS 库，我们将在博客中使用

+   使用 Koala 编译和压缩样式表和 JavaScript

+   采用移动优先的方法撰写博客样式规则

+   优化博客以适应桌面

+   使用 polyfill 在 Internet Explorer 中修复博客

# 使用 CSS3

CSS3 配备了期待已久的属性，`border-radius`和`box-shadow`，简化了在 HTML 中呈现圆角和阴影的旧方法。除此之外，它还带来了一种新类型的伪元素，使我们能够通过 HTML5 的`placeholder`属性来样式化输入字段中显示的占位文本。

让我们看看它们是如何工作的。

## 使用 CSS3 创建圆角

回到 90 年代，创建圆角是很复杂的。添加大量的 HTML 标记，切割图像，并制定多行样式规则是不可避免的，正如 Ben Ogle 在[`benogle.com/2009/04/29/css-round-corners.html`](http://benogle.com/2009/04/29/css-round-corners.html)的文章中所述。

CSS3 使得使用`border-radius`属性创建圆角变得更加简单，以下是一个例子：

```html
div {
  width: 100px; height: 100px;
  border-radius: 30px;
}
```

上述样式规则将使盒子的角变圆（阅读第一章中的*关于 CSS 盒模型的一些话*部分，*响应式网页设计*），每个角为`30px`，如下图所示：

![使用 CSS3 创建圆角](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00254.jpeg)

此外，我们还可以只将特定的角进行圆角处理。例如，以下代码片段将只圆角处理右上角：

```html
div {
  width: 100px; height: 100px;
  border-top-right-radius: 30px;
}
```

## 创建阴影

与创建圆角类似，过去在网站中创建阴影效果时不可避免地需要使用图片。现在，通过引入`box-shadow`属性，添加阴影效果变得更加容易。`box-shadow`属性由五个参数（或值）组成：

第一个参数指定了阴影的位置。这个参数是可选的。将值设置为`inset`，让阴影出现在盒子内部，或者留空以在外部显示阴影。

第二个参数指定了盒子的**阴影垂直**和**水平距离**。

第三个参数指定了**阴影模糊**，使阴影变淡；数字越大，产生的阴影就越大但也更加淡化。

第四个参数指定了**阴影扩展**；这个值与阴影模糊值略有矛盾。这个值会放大，同时也加强阴影的深度。

最后一个参数指定了颜色。颜色可以是任何网络兼容的颜色格式，包括 Hex、RGB、RGBA 和 HSL。

延续前面的例子，我们可以添加`box-shadow`，如下所示：

```html
div {
  width: 100px;
  height: 100px;
  border-radius: 30px;
  box-shadow: 5px 5px 10px 0 rgba(0,0,0,0.5);
}
```

上述代码将输出阴影，如下图所示：

![使用 CSS3 创建阴影](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00255.jpeg)

如果要在框内显示阴影，请在开头添加`inset`，如下：

```html
div {
  width: 100px;
  height: 100px;
  border-radius: 30px;
  box-shadow: inset 5px 5px 10px 0 rgba(0,0,0,0.5);
}
```

### 提示

CSS3 的`box-shadow`属性可以以许多创造性的方式应用，以下是 Paul Underwood 的一个示例，供您参考：

[`www.paulund.co.uk/creating-different-css3-box-shadows-effects`](http://www.paulund.co.uk/creating-different-css3-box-shadows-effects)

## CSS3 浏览器支持和厂商前缀的使用

`border-radius`和`box-shadow`属性在许多浏览器中得到了很好的实现。从技术上讲，如果我们只针对最新的浏览器版本，就不需要包括所谓的厂商前缀。

然而，如果我们打算在最早期的浏览器版本中启用这两个属性`border-radius`和`box-shadow`，在这些浏览器版本中，如 Safari 3、Chrome 4 和 Firefox 3，它们仍然被浏览器供应商标记为实验性的，需要添加厂商前缀。每个浏览器的前缀如下：

+   `-webkit-`：这是基于 WebKit 的浏览器前缀，目前包括 Safari、Chrome 和 Opera。

+   `-moz-`：这是 Mozilla Firefox 的前缀。

+   `-ms-`：这是 Internet Explorer 的前缀。但自 Internet Explorer 9 以来，Internet Explorer 已经支持`border-radius`和`box-shadow`，无需添加此前缀。

让我们继续我们之前的例子（再次）。通过添加厂商前缀以适应 Chrome、Safari 和 Firefox 的最早版本，代码如下：

```html
div {
  width: 100px;
  height: 100px;
  -webkit-border-radius: 30px;
  -moz-border-radius: 30px;
  border-radius: 30px;
  -webkit-box-shadow: 5px 5px 10px 0 rgba(0,0,0,0.5);
  -moz-box-shadow: 5px 5px 10px 0 rgba(0,0,0,0.5);
  box-shadow: 5px 5px 10px 0 rgba(0,0,0,0.5);
}
```

代码可能会变得有点长；但这仍然比应对复杂的标记和多个样式规则要好。

### 注意

**Chrome 及其新的浏览器引擎 Blink**

Chrome 决定分叉 WebKit，并在其上构建自己的浏览器引擎，名为 Blink（[`www.chromium.org/blink`](http://www.chromium.org/blink)）。Opera 之前放弃了其初始引擎（Presto）以使用 WebKit，现在也跟随 Chrome 的动向。Blink 取消了厂商前缀的使用，因此我们不会找到`-blink-`前缀或类似的前缀。在 Chrome 的最新版本中，Chrome 默认禁用实验性功能。但是，我们可以通过`chrome://flags`页面中的选项来启用它。

## 自定义占位符文本样式

随着 HTML5 的加入，占位符属性带来了如何自定义占位符文本的问题。默认情况下，浏览器以浅灰色显示占位符文本。例如，我们如何更改颜色或字体大小？

在撰写本文时，每个浏览器在这方面都有自己的方式。基于 WebKit 的浏览器，如 Safari、Chrome 和 Opera，使用`::-webkit-input-placeholder`。而 Internet Explorer 10 使用`:-ms-input-placeholder`。另一方面，Firefox 4 到 18 使用`伪类` `:-moz-placeholder`，但自 Firefox 19 以来已被伪元素`::-moz-placeholder`（注意双冒号）所取代，以符合标准。

这些选择器不能在单个样式规则中同时使用。因此，以下代码片段将不起作用：

```html
input::-webkit-input-placeholder,
input:-moz-placeholder,
input::-moz-placeholder,
input:-ms-input-placeholder { 
  color: #fbb034;
}
```

它们必须在单个样式规则声明中声明，如下：

```html
input::-webkit-input-placeholder {
  color: #fbb034; 
}
input:-moz-placeholder {
  color: #fbb034;
}
input::-moz-placeholder {
  color: #fbb034;
}
input:-ms-input-placeholder { 
  color: #fbb034;
}
```

这绝对是低效的；我们只是为了达到相同的输出而添加了额外的行。目前还没有其他可行的选择。对于样式化占位符的标准仍在讨论中（请参阅[`wiki.csswg.org/ideas/placeholder-styling`](http://wiki.csswg.org/ideas/placeholder-styling)和[`wiki.csswg.org/spec/css4-ui#more-selectors`](http://wiki.csswg.org/spec/css4-ui#more-selectors)中的 CSSWG 讨论了解更多细节）。

## 使用 CSS 库

区分 CSS 库和 CSS 框架的基本事情是它所解决的问题。例如，CSS 框架，如 Blueprint ([`www.blueprintcss.org/`](http://www.blueprintcss.org/))，旨在作为新网站的基础或起点。它通常附带各种库的组件，以涵盖许多情况。另一方面，CSS 库解决的是非常具体的问题。一般来说，CSS 库也不受限于特定的框架。`Animate.css` ([`daneden.github.io/animate.css/`](http://daneden.github.io/animate.css/)) 和 `Hover.css` ([`ianlunn.github.io/Hover/`](http://ianlunn.github.io/Hover/)) 就是两个完美的例子。它们都是 CSS 库。它们可以与任何框架一起使用。

在这里，我们将把两个 CSS 库整合到博客中，即`Normalize` ([`necolas.github.io/normalize.css/`](http://necolas.github.io/normalize.css/)) 和 `Formalize` ([`formalize.me/`](http://formalize.me/))。这些 CSS 库将标准化不同浏览器中的基本元素样式，并最小化可能意外发生的样式错误。

# 使用 Koala

一旦我们探索了这个项目中要包含的所有内容，让我们设置工具将它们整合在一起。在第一章中，*响应式网页设计*，我们已经安装了 Koala。Koala 是一个免费的开源开发工具，具有许多功能。在这个第一个项目中，我们将使用 Koala 来将样式表和 JavaScript 编译成一个文件，并将代码压缩以得到更小的文件大小。

我们将在博客中包含大约五个样式表。如果我们分别加载所有这些样式表，浏览器将不得不发出五个 HTTP 请求，如下面的截图所示：

![使用 Koala 工作](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00256.jpeg)

如前面的截图所示，浏览器执行了五个 HTTP 请求来加载所有样式表，总共大小为 24.4 KB，需要大约 228 毫秒来加载。

将这些样式表合并成一个文件并压缩其中的代码将加快页面加载速度。样式表也会变得显著更小，最终也会节省带宽消耗。

如下面的截图所示，浏览器只执行了一个 HTTP 请求；样式表大小减小到 13.5KB，加载时间只需 111 毫秒。与前面的例子相比，页面加载速度提高了约 50%：

![使用 Koala 工作](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00257.jpeg)

### 提示

**加快网站性能的最佳实践：**

前往 YSlow！性能规则 ([`developer.yahoo.com/performance/rules.html`](https://developer.yahoo.com/performance/rules.html)) 或 Google PageSpeed Insight 规则 ([`developers.google.com/speed/docs/insights/rules`](https://developers.google.com/speed/docs/insights/rules))，了解除了合并样式表和 JavaScript 之外，使网站加载更快的进一步步骤。

# 行动时间 - 将项目目录整合到 Koala 并合并样式表

在本节中，我们将整合配置好的 Koala 来编译和输出样式表，执行以下步骤：

1.  在`css`文件夹中创建一个名为`main.css`的新样式表。这是主要的样式表，我们将在其中为博客编写自己的样式规则。

1.  创建一个名为`style.css`的新样式表。

1.  下载`normalize.css` ([`necolas.github.io/normalize.css/`](http://necolas.github.io/normalize.css/))，并将其放入项目目录的`css`文件夹中。

1.  下载`formalize.css` ([`formalize.me/`](http://formalize.me/))，并将其放入项目目录的`css`文件夹中。

1.  在 Sublime Text 中打开`style.css`。

1.  使用`@import`规则按以下顺序导入支持的样式表，如下所示：

```html
@import url("css/normalize.css");
@import url("css/formalize.css");
@import url("css/responsive.gs.12col.css");
@import url("css/main.css");
@import url("css/responsive.css");
```

1.  启动 Koala。然后，将项目目录拖放到 Koala 侧边栏中。Koala 将显示并列出可识别的文件，如下截图所示：![行动时间-将项目目录整合到 Koala 中并合并样式表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00258.jpeg)

1.  选择`style.css`并选中**自动编译**，以便在 Koala 检测到其中的更改时自动编译`style.css`。查看以下截图：![行动时间-将项目目录整合到 Koala 中并合并样式表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00259.jpeg)

1.  选择**合并导入**选项，让 Koala 将样式表中的内容（包括`style.css`中包含的内容）与`@import`规则合并。查看以下截图：![行动时间-将项目目录整合到 Koala 中并合并样式表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00260.jpeg)

1.  将**输出样式**设置为**压缩**。查看以下截图：![行动时间-将项目目录整合到 Koala 中并合并样式表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00261.jpeg)

这将把样式规则压缩成一行，最终会使`style.css`文件大小变小。

1.  单击**编译**按钮。查看以下截图：![行动时间-将项目目录整合到 Koala 中并合并样式表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00262.jpeg)

这将编译`style.css`并生成一个名为`style.min.css`的新文件作为输出。

1.  打开`index.html`并链接`style.min.css`，使用以下代码：

```html
<link href="style.min.css" rel="stylesheet">
```

## *刚刚发生了什么？*

我们刚刚在 Koala 中整合了项目目录。我们还创建了两个新的样式表，分别是`main.css`和`style.css`。我们还使用`@import`规则将五个样式表，包括`main.css`，合并到了`style.css`文件中。我们合并了这些文件，并生成了一个名为`style.min.css`的新样式表，它可以在`style.css`中找到，如下截图所示：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00263.jpeg)

最后，我们在`index.html`中链接了压缩后的样式表`style.min.css`。

## 英雄试试看-重命名输出

`style.min.css`是 Koala 设置的默认名称；它会在每个压缩输出中插入后缀`min`。虽然这是压缩的 Web 源文件、样式表和 JavaScript 最流行的命名约定，但 Koala 允许您重命名输出以匹配您的个人喜好。要这样做，请单击以下截图中用圆圈标出的编辑图标：

![英雄试试看-重命名输出](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00264.jpeg)

以下是一些您可以尝试的替代命名想法：

+   `style-min.css`（带有破折号）

+   `styles.min.css`（带有`s`）

+   `blog.css`（指的是网站名称）

然而，如果您决定重命名输出而不是像我们在前面的步骤中那样管理`style.min.css`，请不要忘记更改`<link>`元素中指向样式表的名称。

## 快速测验-网站性能规则

Q1. 以下哪条规则不是用于改善网站性能的规则？

1.  压缩资源，如 CSS 和 JavaScript。

1.  压缩图像文件。

1.  利用浏览器缓存。

1.  使用 CSS 简写属性。

1.  使用 CDN 传递 Web 资源。

# 首先考虑移动端

在我们动手编写代码之前，让我们谈谈移动优先的方法，这将驱动我们在写部分博客样式规则时的决定。

移动优先是 Web 设计社区中的热词之一。移动优先是一种新的思维方式，用于构建今天的网站，也指导着构建针对移动使用优化的网站的模式。正如第一章中所述，*响应式 Web 设计*，移动用户正在增加，桌面不再是用户访问 Web 的主要平台。

移动优先的概念驱使我们在构建网站块时考虑和优先考虑移动使用，包括我们如何组合样式规则和媒体查询。此外，采用移动优先思维，正如 Brad Frost 在他的博客文章中所展示的（[`bradfrostweb.com/blog/post/7-habits-of-highly-effective-media-queries/`](http://bradfrostweb.com/blog/post/7-habits-of-highly-effective-media-queries/)），允许生成比另一种方式（从桌面到移动）更精简的代码。在这里，我们将首先优化和处理移动端的博客，然后再增强到桌面版本。

移动优先不在本书的范围之内。以下是一些我推荐的进一步了解这个主题的来源：

+   Luke Wroblewski 的《Mobile First》（[`www.abookapart.com/products/mobile-first`](http://www.abookapart.com/products/mobile-first)）

+   Brad Frost 的《Mobile First Responsive Web Design》（[`bradfrostweb.com/blog/web/mobile-first-responsive-web-design/`](http://bradfrostweb.com/blog/web/mobile-first-responsive-web-design/)）

+   Jeremy Girard 的《Building a Better Responsive Website》（[`www.smashingmagazine.com/2013/03/05/building-a-better-responsive-website/`](http://www.smashingmagazine.com/2013/03/05/building-a-better-responsive-website/)）

# 组合博客样式

在前面的章节中，我们添加了第三方样式，奠定了博客外观的基础。从本节开始，我们将为博客编写自己的样式规则。我们将从页眉开始，然后逐步到页脚。

# 采取行动-组合基本样式规则

在这一部分，我们将编写博客的基本样式。这些样式规则包括内容字体系列，字体大小，以及其中的许多元素。

首先，我个人认为使用默认系统字体如 Arial 和 Times 非常无聊。

### 注意

由于浏览器支持和字体许可限制，我们只能使用用户操作系统中安装的字体。因此，十多年来，我们在网页上只能使用非常有限的字体选择，许多网站使用相同的一组字体，如 Arial，Times，甚至 Comic Sans。所以，是的，这些都是无聊的字体。

如今，随着`@font-face`规范的进步，以及在网页上使用字体的许可，我们现在能够在网站上使用用户计算机字体选择之外的字体。现在也有更大的免费字体集合可以嵌入到网页中，比如我们可以在 Google Font（[`www.google.com/fonts`](http://www.google.com/fonts)）、Open Font Library（[`openfontlibrary.org/`](http://openfontlibrary.org/)）、Font Squirrel（[`www.fontsquirrel.com`](http://www.fontsquirrel.com)）、Fonts for Web（[`fontsforweb.com/`](http://fontsforweb.com/)）和 Adobe Edge Web Font（[`edgewebfonts.adobe.com/`](https://edgewebfonts.adobe.com/)）中找到的字体。

我真的鼓励网页设计师更多地探索使用自定义字体在他们的网站上构建更丰富的网站的可能性。

执行以下步骤来组合基本样式规则：

1.  为了使我们的博客看起来更加清新，我们将从 Google Font 库中使用一些自定义字体。Google Font 让我们能够在网页上使用字体变得更加容易。Google 已经解决了编写语法的麻烦，同时确保字体格式在所有主要浏览器中兼容。

### 注意

说到这一点，可以参考 Paul Irish 的文章，“Bulletproof @font-face syntax”（[`www.paulirish.com/2009/bulletproof-font-face-implementation-syntax/`](http://www.paulirish.com/2009/bulletproof-font-face-implementation-syntax/)），以获取有关在所有浏览器中工作的 CSS3 `@font-face` 语法的进一步帮助。

1.  此外，我们不会被字体许可证所困扰，因为 Google 字体是完全免费的。我们所要做的就是按照此页面中的说明添加一个特殊的样式表[`developers.google.com/fonts/docs/getting_started#Quick_Start`](https://developers.google.com/fonts/docs/getting_started#Quick_Start)。在我们的情况下，在主要样式表链接之前添加以下链接：

```html
<link href='http://fonts.googleapis.com/css?family=Droid+Serif:400,700,400italic,700italic|Varela+Round' rel='stylesheet'>
```

这样做后，我们将能够使用 Droid Serif 字体系列，以及 Varela Round；请在以下网页中查看这些字体样本和字符：

+   Droid Serif（[`www.google.com/fonts/specimen/Droid+Serif`](http://www.google.com/fonts/specimen/Droid+Serif)）

+   Varela Round（[`www.google.com/fonts/specimen/Varela+Round`](http://www.google.com/fonts/specimen/Varela+Round)）

1.  将整个元素框大小设置为`border-box`。在`main.css`中添加以下行（以及下一步中的其他行）：

```html
* { 
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box;
  *behavior: url(/scripts/boxsizing.htc);
}
```

1.  我们将设置博客的主要字体，即适用于博客整个内容的字体。在这里，我们将使用 Google 字体的 Droid Serif。在`@import`样式表列表之后添加以下样式规则：

```html
body {
  font-family: "Droid Serif", Georgia, serif;
  font-size: 16px;
}
```

1.  我们将为标题（`h1`，`h2`，`h3`，`h4`，`h5`和`h6`）应用不同的字体系列，以使其与正文内容区分开来。在这里，我们将应用从 Google 字体收集中带来的第二个自定义字体系列，Varela Round。

1.  将以下行添加到标题应用 Varela Round：

```html
h1, h2, h3, h4, h5, h6 {
    font-family: "Varela Round", Arial, sans-serif;
    font-weight: 400;
}
```

### 注意

默认情况下，浏览器将标题的粗细设置为`bold`或`600`。然而，Varela Round 只有普通字重，相当于`400`。因此，如前面的代码片段所示，我们还将`font-weight`设置为`400`，以防止所谓的*faux-bold*。

有关 faux-bold 的更多信息，请参阅 A List Apart 文章*Say No to Faux Bold*（[`alistapart.com/article/say-no-to-faux-bold`](http://alistapart.com/article/say-no-to-faux-bold)）。

1.  在这一步中，我们还将自定义默认的锚标签或链接样式。我个人偏好去掉默认链接样式的下划线。

### 注意

即使 Google 也删除了其搜索结果的下划线（[`www.theverge.com/2014/3/13/5503894/google-removes-underlined-links-site-redesign`](http://www.theverge.com/2014/3/13/5503894/google-removes-underlined-links-site-redesign)）。

此外，我们还将链接颜色更改为`#3498db`。它是蓝色的，但比默认链接样式中应用的蓝色更为柔和，如下面的截图所示：

![行动时间-撰写基本样式规则](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00265.jpeg)

1.  添加以下行以更改默认链接颜色：

```html
a {
    color: #3498db;
    text-decoration: none;
}
```

1.  我们还将设置链接的悬停状态颜色。当鼠标光标悬停在链接上时，将显示这种颜色。在这里，我们将链接悬停颜色设置为`#2a84bf`，这是我们在第 4 步中设置的颜色的较暗版本。请看下面的截图：![行动时间-撰写基本样式规则](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00266.jpeg)

1.  添加以下行以设置链接在悬停状态时的颜色，如下所示：

```html
a:hover {
    color: #2a84bf;
}
```

1.  使用以下样式规则使图像具有流体性，如下所示：

```html
img {
  max-width: 100%;
  height: auto;
}
```

此外，这些样式规则将防止图像在实际图像宽度大于容器时超出容器。

### 注意

有关流体图像的更多详细信息，请参阅 A List Apart 文章*Fluid Images*（[`alistapart.com/article/fluid-images`](http://alistapart.com/article/fluid-images)）。

## *刚刚发生了什么？*

我们刚刚添加了一些样式规则，用于处理博客中的一些元素，即标题、链接和图像。在这个阶段，除了内容和标题中的字体系列更改以及链接颜色之外，博客中还没有出现明显的差异。请看下面的截图：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00267.jpeg)

## 尝试一下-自定义链接颜色

请注意，链接颜色`#2a84bf`是我个人的选择。在选择颜色时有许多考虑因素，例如品牌、受众和内容。链接不一定要是`#2a84bf`。例如，星巴克网站（[`www.starbucks.co.id/about-us/pressroom`](http://www.starbucks.co.id/about-us/pressroom)）中的链接颜色是绿色，这与其品牌身份有关。

因此，不要害怕探索和尝试新的颜色。以下是一些颜色想法：

![尝试一下英雄-自定义链接颜色](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00268.jpeg)

接下来，我们将组合博客标题和导航样式规则。样式规则将主要通过元素的类应用。因此，在继续之前，请参考第二章*网页开发工具*，查看我们在元素中添加的类名和 ID。

# 行动时间-使用 CSS 增强标题和导航外观

步骤如下：

1.  打开`main.css`。

1.  使用`padding`在标题周围添加一些空白，并将标题颜色设置为`#333`，如下所示：

```html
.blog-header {
padding: 30px 15px;
background-color: #333;
}
```

1.  为了使标志看起来突出，我们将使用 Varela Round 字体，这是我们用于标题的相同字体系列。我们还会使它变大，并将所有字母转换为大写，如下所示：

```html
 .blog-name {
  font-family: "Varela Round", Arial, sans-serif;
  font-weight: 400;
  font-size: 42px;
  text-align: center;
  text-transform: uppercase;
}
```

1.  标志链接颜色目前为`#2a84bf`，这是我们为链接`<a>`设置的常用颜色。这种颜色与背景颜色不搭配。让我们将颜色改为白色，如下所示：

```html
.blog-name a {
    color: #fff;
}
```

1.  设置搜索输入样式，如下所示：

```html
.search-form input {
  height: 36px;
  background-color: #ccc;
  color: #555;
  border: 0;
  padding: 0 10px;
  border-radius: 30px;
}
```

这些样式规则设置了输入颜色、边框颜色和背景颜色。它将输入变成了如下所示的东西：

![行动时间-使用 CSS 增强标题和导航外观](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00269.jpeg)

1.  如前面的屏幕截图所示，占位文本几乎无法阅读，因为颜色与输入背景颜色融为一体。因此，让我们将文本颜色变得更深一些，如下所示：

```html
.search-form input::-webkit-input-placeholder {
  color: #555;
}
.search-form input:-moz-placeholder {
  color: #555;  
}
.search-form input::-moz-placeholder {
  color: #555;  
}
.search-form input:-ms-input-placeholder {  
  color: #555;
}
```

如果您使用 OS X 或 Ubuntu，您将看到突出显示当前目标时输入的发光颜色，如下面的屏幕截图所示：

![行动时间-使用 CSS 增强标题和导航外观](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00270.jpeg)

在 OS X 中，发光颜色是蓝色。在 Ubuntu 中，它将是橙色。

1.  我想要去掉这种发光效果。发光效果在技术上通过`box-shadow`显示。因此，为了去除这种效果，我们只需将输入的`box-shadow`设置为`none`，如下所示：

```html
.search-form input:focus {
  -webkit-box-shadow: none;
  -moz-box-shadow: none;
  box-shadow: none;
}
```

值得注意的是，发光效果是**用户体验**（**UX**）设计的一部分，告诉用户他们当前正在输入字段中。如果用户只能用键盘浏览网站，这种 UX 设计尤其有帮助。

1.  因此，我们将不得不创建一种效果，以带来类似的用户体验作为替代。在这里，我们将通过使输入背景颜色变浅来替换我们去除的发光效果。以下是此步骤的完整代码：

```html
.search-form input:focus {
  -webkit-box-shadow: none;
  -moz-box-shadow: none;
  box-shadow: none;
  background-color: #bbb;
}
```

如下面的屏幕截图所示，当焦点在输入时，输入背景颜色会变浅：

![行动时间-使用 CSS 增强标题和导航外观](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00271.jpeg)

1.  我们将为导航编写样式。首先，将菜单对齐到中心，并在导航的顶部和底部添加一些空白，使用`margin`。看一下以下代码：

```html
.blog-menu {
  margin: 30px 0;
  text-align: center;
}
```

1.  删除`<ul>`的左侧填充，如下所示：

```html
.blog-menu ul {
  padding-left: 0;
}
```

1.  在菜单之间添加一些空白，并删除列表符号，如下所示：

```html
.blog-menu li {
  margin: 15px;
  list-style-type: none;
}
```

1.  自定义菜单颜色和字体，如下所示：

```html
.blog-menu a {
  color: #7f8c8d;
  font-size: 18px;
   text-transform: uppercase;
   font-family: "Varela Round", Arial, sans-serif;
}
.blog-menu a:hover {
    color: #3498db;
}
```

## *刚刚发生了什么？*

我们刚刚装饰了标题和导航。与我们在本节前面讨论的以移动设备为先的思维方式相对应，我们首先将样式定位到优化博客在移动设备上的呈现。

激活 Chrome 移动模拟器，您会发现博客已经针对较小的屏幕尺寸进行了优化；标志和菜单，如下截图所示，与其左对齐相比，已对齐到中心：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00272.jpeg)

## 尝试一下-自定义页眉

博客页眉给予了深色，`#333`。我完全理解这种颜色可能对你们中的一些人来说很无聊。因此，可以自由定制颜色以及标志和搜索输入字段的样式。以下是一些想法：

+   使用 CSS3 渐变或图像作为页眉背景

+   通过 CSS 图像替换方法用图像替换标志

+   减少搜索输入边框半径，更改背景颜色，并调整占位符文本颜色

在处理了博客页眉和导航之后，我们继续处理博客内容部分。内容部分包括博客文章项目和博客分页。

# 行动时间-使用 CSS 增强内容部分的外观

执行以下步骤来设置博客内容的样式：

1.  在内容部分的所有四周添加空白，使用`padding`和`margin`，如下所示

```html
.blog-content {
  padding: 15px;
  margin-bottom: 30px;
} 
```

1.  使用一些空白和边框来分隔每篇博客文章，如下所示：

```html
.post {
  margin-bottom: 60px;
  padding-bottom: 60px;
  border-bottom: 1px solid #ddd;
}
```

1.  将标题对齐到中心，稍微调整标题字体大小，并使用以下样式规则更改颜色：

```html
.post-title {
  font-size: 36px;
  text-align: center;
  margin-top: 0;
}
.post-title a {
  color: #333;
}
.post-title a:hover {
  color: #3498db;
}
```

1.  在标题下面，我们有`post-meta`，其中包括文章作者姓名和文章发布日期。与标题类似，我们还调整字体大小和空白，并更改字体颜色，如下所示：

```html
.post-meta {
  font-size: 18px;
  margin: 20px 0 0;
  text-align: center;
  color: #999;
}
.post-meta ul {
  list-style-type: none;
  padding-left: 0;
}
.post-meta li {
  margin-bottom: 10px;
}
```

1.  正如您在下面的截图中所看到的，由于所有边缘的 margin，文章缩略图看起来又小又挤：![行动时间-使用 CSS 增强内容部分的外观](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00273.jpeg)

1.  让我们移除这些 margin，如下所示：

```html
.post-thumbnail {
  margin: 0;
}
```

如下截图所示，一些图片有标题：

![行动时间-使用 CSS 增强内容部分的外观](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00274.jpeg)

1.  让我们对其进行样式设置，使其看起来与其他内容有所不同，并且显示它是一个图片标题。添加以下代码来设置标题的样式：

```html
.post-thumbnail figcaption {
  color: #bdc3c7;
  margin-top: 15px;
  font-size: 16px;
  font-style: italic;
}
```

1.  调整文章摘录的字体大小、颜色和行高，如下所示：

```html
.post-excerpt {
  color: #555;
  font-size: 18px;
  line-height: 30px;
}
```

1.  从这一步开始，我们将编写博客分页的样式。首先，让我们对字体大小、字体系列、空白、位置和对齐进行一些调整，如下所示：

```html
.blog-pagination {
  text-align: center;
  font-size: 16px;
  position: relative;
  margin: 60px 0;
}
.blog-pagination ul {
  padding-left: 0;
}
.blog-pagination li,
.blog-pagination a {
  display: block;
  width: 100%;
}
.blog-pagination li {
  font-family: "Varela Round", Arial, sans-serif;
  color: #bdc3c7;
  text-transform: uppercase;
  margin-bottom: 10px;
}
```

1.  将分页链接装饰成圆角边框，如下所示：

```html
.blog-pagination a {
  -webkit-border-radius: 30px;
  -moz-border-radius: 30px;
  border-radius: 30px;
  color: #7f8c8d;
  padding: 15px 30px;
  border: 1px solid #bdc3c7;
}
```

1.  当鼠标悬停在链接上时指定链接的装饰，如下所示：

```html
.blog-pagination a:hover {
  color: #fff;
  background-color: #7f8c8d;
  border: 1px solid #7f8c8d;
}
```

1.  最后，使用以下样式规则将页面编号指示器放置在分页链接的顶部：

```html
.blog-pagination .pageof {
  position: absolute;
  top: -30px;
}
```

## *刚刚发生了什么？*

我们刚刚对博客内容部分进行了样式设置，包括页面导航（分页），以下截图显示了内容部分的外观：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00275.jpeg)

## 尝试一下-改进内容部分

我们在内容部分应用的大多数样式规则都是装饰性的。这不是您必须强制遵循的东西。请随意改进样式以符合您的个人品味。

您可以进行以下修改：

+   自定义文章标题字体系列和颜色

+   为文章图片应用边框颜色或圆角

+   更改分页边框颜色，或使背景更加丰富多彩

接下来，我们将为博客的最后一部分-页脚进行样式设置。

# 行动时间-使用 CSS 增强页脚部分的外观

执行以下步骤来增强页脚的样式：

1.  调整页脚字体、颜色和 margin，如下所示：

```html
.blog-footer {
  background-color: #ecf0f1;
  padding: 60px 0;
  font-family: "Varela Round", Arial, sans-serif;
  margin-top: 60px;
}
.blog-footer,
.blog-footer a {
  color: #7f8c8d;
}
```

1.  页脚包含社交媒体链接。让我们调整包括 margin、padding、对齐、颜色和空白的样式，如下所示：

```html
.social-media {
  margin: 0 0 30px;
}
.social-media ul {
  margin: 0;
  padding-left: 0;
}
.social-media li {
  margin: 0 8px 10px;
  list-style: none;
}
.social-media li,
.social-media a {
  font-size: 18px;
}
.social-media a:hover {
  color: #333;
}
```

1.  将 margin-top 设置为版权容器之外。

```html
.copyright {
  margin-top: 0;
}
```

1.  将页脚内容对齐到中心，如下所示：

```html
.social-media,
.copyright {
  text-align: center;
}
```

## *刚刚发生了什么？*

我们刚刚为页脚部分添加了样式规则，下面的截图显示了博客页脚的外观：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00276.jpeg)

# 优化博客以适应桌面

目前博客已经针对移动端或窄视口大小进行了优化。如果你在更大的视口大小下查看，你会发现一些元素位置不正确或未正确对齐。例如，博客标志和导航目前对齐到中间，如下截图所示：

![优化博客以适应桌面](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00277.jpeg)

根据我们在第三章中展示的蓝图，*使用 Responsive.gs 构建简单响应式博客*，标志应该对齐到左侧，每个菜单链接应该内联显示。在接下来的步骤中，我们将通过媒体查询来修复这些问题；我们将优化博客以适应桌面视图。

# 行动时间-为桌面编写样式规则

执行以下步骤为桌面编写样式规则：

1.  在 Sublime Text 中打开`responsive.css`。

1.  添加以下媒体查询：

```html
@media screen and (min-width: 640px) {
  // add style rules here
}
```

我们将在接下来的步骤中添加所有的样式规则到这个媒体查询中。这个媒体查询规定将应用样式规则在视口宽度从 640 像素及以上的范围内。

1.  将博客标志对齐到左侧，如下所示：

```html
.blog-name {
  text-align: left;
  margin-bottom: 0;
}
```

1.  将导航菜单、文章元数据和社交媒体的列表项内联显示，如下所示：

```html
.blog-menu li,
.post-meta li,
.social-media li {
      display: inline;
}
```

1.  增加文章标题的大小，如下所示：

```html
.post-title {
  font-size: 48px;
}
```

1.  同时，将博客分页链接内联显示，如下所示：

```html
.blog-pagination li,
.blog-pagination a {
  display: inline;
}
```

1.  将分页页码指示器放在初始位置——与博客分页链接一起，如下所示：

```html
.blog-pagination .pageof {
  position: relative;
  top: 0;
  padding: 0 20px;
}
```

1.  将页脚中的社交媒体链接对齐到左侧，版权声明对齐到右侧，如下所示：

```html
.social-media {
  text-align: left;
}
.copyright {
  text-align: right;
}
```

## *刚刚发生了什么？*

我们刚刚添加了适用于桌面视图的样式规则。如果你现在在大于 640 像素的视口宽度下查看博客，你应该会发现博客中的元素，如标志和导航菜单，处于它们通常的位置，如下截图所示：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00278.jpeg)

# 使用 polyfills 使 Internet Explorer 更强大

使用辉煌的 CSS3 和 HTML5 功能会带来一个后果：布局在旧的 Internet Explorer 中失败并且破碎，如下截图所示：

![使用 polyfills 使 Internet Explorer 更强大](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00279.jpeg)

如果你对此满意，可以跳过这一部分，立即转到下一个项目。然而，如果你感到有冒险精神，让我们继续这一部分并修复这些错误。

# 行动时间-使用 polyfills 修补 Internet Explorer

执行修补 Internet Explorer 的步骤：

1.  我们在 scripts 文件夹中有一些 polyfills，分别是`html5shiv.js`，`respond.js`和`placeholder.js`。让我们将这些脚本合并成一个文件。

1.  首先，创建一个名为`polyfills.js`的新 JavaScript 文件，用于保存这些 polyfill 脚本的内容。

1.  在 Sublime Text 中打开`polyfills.js`。

1.  添加以下行来导入 polyfill 脚本：

```html
// @koala-prepend "html5shiv.js"
// @koala-prepend "respond.js"
// @koala-prepend "placeholder.js"
```

### 注意

`@koala-prepend`指令是 Koala 专有的导入 JavaScript 文件的指令。在 Koala 文档页面[`github.com/oklai/koala/wiki/JS-CSS-minify-and-combine`](https://github.com/oklai/koala/wiki/JS-CSS-minify-and-combine)中了解更多信息。

1.  在 Koala 中，选择`polyfills.js`，并点击**Compile**按钮，如下截图所示：![行动时间-使用 polyfills 修补 Internet Explorer](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00280.jpeg)

通过这一步，Koala 将生成名为`polyfills.min.js`的压缩文件。

1.  在`index.html`中，在`</head>`之前链接`polyfills.js`，如下所示：

```html
<!--[if lt IE 9]>
<script type="text/javascript" src="img/polyfills.min.js"></script>
<![endif]-->
```

### 注意

由于这个脚本只在 Internet Explorer 8 及以下版本中需要，我们用 Internet Explorer 条件注释`<!--[if lt IE 9]>`将它们封装起来，如你在前面的代码片段中所见。

有关 Internet Explorer 条件注释的更多信息，请参考 QuirksMode 文章[`www.quirksmode.org/css/condcom.html`](http://www.quirksmode.org/css/condcom.html)。

## *发生了什么？*

我们刚刚在博客中应用了 polyfills 来修复 Internet Explorer 在 HTML5 和媒体查询中的渲染问题。这些 polyfills 可以立即使用。刷新 Internet Explorer，就完成了！请看下面的屏幕截图：

发生了什么？

样式规则已经应用，布局已经就位，占位文本也在那里。

## 来吧英雄-为 Internet Explorer 完善博客

我们将结束这个项目。但是，正如您从前面的屏幕截图中所看到的，仍然有许多问题需要解决，以使博客在旧版 Internet Explorer 中的外观与最新浏览器一样好。例如：

+   参考前面的屏幕截图，占位文本目前是对齐到顶部的。您可以修复它，使其垂直居中对齐。

+   您还可以应用一个名为 CSS3Pie 的 polyfill（[`css3pie.com/`](http://css3pie.com/)），它可以在 Internet Explorer 中实现 CSS3 边框半径，使搜索输入字段的外观与最新的浏览器版本一样圆角。

# 总结

我们完成了第一个项目；我们使用 Responsive.gs 构建了一个简单的响应式博客。博客的最终结果可能对您来说并不那么吸引人。特别是在旧版 Internet Explorer 中，它也远非完美；正如前面提到的，仍然有许多问题需要解决。不过，我希望您能从这个过程中获得一些有用的东西，包括其中的技术和代码。

总之，在本章中，我们已经增强和完善了博客的 CSS3，使用 Koala 来合并和最小化样式表和 JavaScript 文件，并应用了 polyfills 来修复 Internet Explorer 在 HTML5 和 CSS3 中的问题。

在下一章中，我们将开始第二个项目。我们将探索另一个框架，以构建一个更广泛和响应式的网站。
