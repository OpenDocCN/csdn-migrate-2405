# 精通响应式 Web 设计（二）

> 原文：[`zh.annas-archive.org/md5/14CB11AB973C4F1BAA6102D9FEAB3F3B`](https://zh.annas-archive.org/md5/14CB11AB973C4F1BAA6102D9FEAB3F3B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：移动优先还是桌面优先？

在我多年的响应式网站设计和构建经验中，我发现为了更好地查看内容和消息，在线框和设计阶段使用桌面优先方法更容易可视化事物。

由于桌面优先方法允许我们在给定布局中看到更多内容，因此我们可以将提供给我们的内容的层次结构转化为代表该层次结构的布局。在 320 像素宽的小画布上进行此操作比需要更困难。

当您完成了这种层次结构，它将在小屏设备上保持不变，唯一改变的是布局。

*最佳实践*建议首先构建移动，但许多网络专业人员实际上并不知道为什么我们首先构建*移动*。双关语。

所以，让我们澄清一下。我们首先构建移动的原因是由 Luke Wroblewski 提到的三个原则，他实际上在 2009 年创造了*移动优先*这个术语。您会注意到这些原则都与 HTML、CSS 和/或 JavaScript 无关。换句话说，您不是因为 HTML、CSS 或 JavaScript 的任何优势而首先构建移动。有关更多信息，请访问[`www.lukew.com/ff/entry.asp?933`](http://www.lukew.com/ff/entry.asp?933)。

考虑以下几点：

+   **移动正在爆炸**：嗯，移动已经爆炸了。这基本上意味着人们更容易、更快速、更方便地使用移动设备访问网络。因此，如果您首先构建与移动设备兼容的网站，就有更好的机会提供更好的用户体验，并被更多人查看，而不是拥有仅限桌面的网站/应用程序。

+   **移动迫使您专注**：由于移动设备屏幕上的空间比桌面屏幕上的空间少得多，因此有必要进行优先排序。这意味着最重要的任务和/或消息需要立即可见。

+   **移动扩展了您的能力**：移动设备具有桌面设备没有的功能：GPS、加速计、多点触控输入、语音识别、前后摄像头等。在进行移动优先时，您可以使用这些先进技术来创建更丰富、更令人兴奋的体验。

现在您有了最终设计，现在您需要将该设计实施到 HTML、CSS 和 JavaScript 中。在这个阶段，您应该使用移动优先方法，并考虑我们之前提到的三个原因：

+   构建移动优先意味着您的网站/应用程序可以被更多人看到

+   这使您优先考虑内容

+   如果需要，它将允许您使用移动设备的高级功能和能力

在本章中，我们将涵盖以下主题：

+   在桌面优先视图中创建您的设计，但使用移动优先进行实施。

+   移动优先和桌面优先媒体查询的 Sass 混合。

+   处理旧版浏览器。

+   如何处理高密度屏幕。

+   为什么 RWD 有时并不一定是正确的解决方案。

+   使用 RWD 改造旧网站。

# 在桌面优先视图中创建您的设计，但使用移动优先进行实施

让我们看看一些术语，以便我们在同一页面上：

+   **线框**：这是使用仅轮廓的非常基本的布局的视觉表示。没有颜色，没有品牌，也没有任何定义的样式。

+   **设计/构图**：这是一个带有颜色、品牌和样式的*充实*线框。它是最终页面/站点/应用程序的非常接近表示（通常说，接近最终产品的 95%）而不涉及任何标记或任何类型的编码。

+   **HTML 模拟或 HTML 模板**：这是当设计已经被实现到一个实际的 HTML 页面中，带有 CSS 和—有时—JavaScript。它只能在浏览器中查看。它几乎是页面/站点/网络应用的最终产品的精确表示（接近 99%）。

术语明确后，让我们继续。

一些专业人士，包括我在内，建议使用更现代和高效的技术来创建视觉资产，以优化线框和设计/构图过程中的时间。诸如样式瓷砖、情绪板、元素拼贴和原子设计等技术与传统的线框和设计/构图方法有所不同。它们提供了独立于屏幕宽度、技术甚至内容创建的布局和样式的探索机会。

在本书的范围内，我们将专注于如何在掌握 HTML5 和 CSS3 的**响应式网页设计**（**RWD**）的初期阶段最大化利用时间的同时，仍然可以利用传统线框和设计/构图方法的一些内容。

## 为什么要以桌面优先的方式创建设计？

以桌面优先的方式创建设计的原因很简单：房地产（空间）。

作为设计师，我们需要以视觉方式反映内容的层次结构。为了实现这一点，我们使用许多设计原则，如节奏、接近性、空白、模式、对比、平衡、网格、对称等等。

当我们创建线框或设计/构图的画布足够大，可以尝试不同的排列和布局，我们就有了必要的灵活性来探索可以代表所述内容层次结构的不同方式。

例如，我们正在使用一个 12 列网格，我们提供的内容决定了以下内容层次结构：

+   这家企业希望用户能够提供他们的电子邮件 ID 以接收我们的新闻通讯。

+   我们希望展示编辑部选择的*特色文章*。

有了前面的内容层次结构，我们可以立即开始构想不同的布局来传达这个层次结构：

+   为了让用户提供他们的电子邮件地址，我们将创建一个带有标题、段落、电子邮件输入类型和按钮的表单。这个表单将位于页眉下方的左上角，并且可能有三到四列的宽度。我认为可能四列太宽了，但让我们先画线框看看感觉如何，以及这可能会有什么可用性、可访问性和可读性问题或好处。

+   对于*特色文章*，我们将使用剩余的列。如果电子邮件表单是三列宽，我们将使用剩下的九列；如果电子邮件表单是四列宽，我们将只使用剩下的八列。特色文章有更多的内容，如标题、作者、日期、类别、摘要、缩略图和指向完整文章的链接。

在我们的设计/线框应用程序中有一个宽敞的画布，我们可以尝试这些不同的方法，并最终得出一个合理的建议布局，以满足企业或利益相关者的要求，并且代表内容层次结构。

以移动优先的方式创建这样一个布局几乎是不可能的。小型房地产屏幕非常受限制和有限。但当事情开始增长时，我们需要每次考虑特定断点时进行这个探索过程。

### 提示

实际上，我们在这一点上不应该考虑断点（无意冒犯），因为内容而不是特定的设备宽度决定了需要添加新断点的位置。

一旦我们定义了反映内容层次结构的布局，我们就会处于一个良好的位置，因为当这些内容在较小的屏幕上重新排列时，无论宽度是多少，层次结构都将保持完整。

## 为什么要以移动优先的方式实施？

首先澄清一个术语：*implement*意味着根据线框图或设计/构图创建一个带有 CSS 和必要时 JavaScript 的 HTML 模型。

本章开头提到的原因是回答“为什么要首先使用移动设备实施？”记住：移动设备正在爆炸（实际上已经爆炸了），移动设备迫使你集中注意力，并扩展了你的能力。

除了第二个前提（这是一个巨大的*也许*）之外，这些原因都无法通过桌面优先实现。

让我们换个话题，转向一个更加技术性的主题，这将帮助我们了解 Sass mixin 如何帮助我们掌握移动设备优先和桌面优先方法。

因此，让我们回顾一下。使用桌面优先来创建你的设计和线框图。有一个大画布可以让我们探索不同的布局，并正确安排内容的层次结构。当需要实施（创建 HTML 模型）时，使用移动设备优先。

# 移动设备优先和桌面优先媒体查询的 Sass mixin

对于我们的示例，在本书中我们将使用两种类型的 Sass mixin：一种使用`min-width`属性的移动设备优先 mixin，另一种使用`max-width`属性的桌面优先 mixin。我们已经在第一章中看到了以下 mixin 及其工作原理，*利用 Sass 实现响应式网页设计的强大功能*，但这里是一个复习。

## 移动设备优先 mixin

我们将使用以下移动设备优先 mixin：

```html
@mixin forLargeScreens($media) {
    @media (min-width: $media/16+em) { @content; }
}
```

这就是我们使用它的方式：

```html
header {
   //Properties for small screens
    width: 50%;
    background: red;
    @include forLargeScreens(640) {
      //Properties for large screens
        width: 100%;
        background: blue;
    }
}
```

这编译成以下内容：

```html
header {
    width: 50%;
    background: red;
}

@media (min-width: 40em) {
    header {
        width: 100%;
        background: blue;
    }
}
```

## 桌面优先 mixin

这是我们将要使用的桌面优先 mixin：

```html
@mixin forSmallScreens($media) {
    @media (max-width: $media/16+em) { @content; }
}
```

这就是我们使用它的方式：

```html
header {
    //Properties for large screens
    width: 100%;
    background: purple;
    @include forSmallScreens(640) {
      //Properties for small screens
        width: 50%;
        background: yellow;
    }
}
@include forSmallScreens

```

这编译成以下内容：

```html
header {
    width: 100%;
    background: purple;
}

@media (max-width: 40em) {
    header {
        width: 50%;
        background: yellow;
    }
}
```

### 提示

使用这些 mixin 的好处是，非常容易找出正在使用的方法，因为我们可以在整个 SCSS 文件中看到`forLargeScreens`或`forSmallScreens`这个术语被重复使用。如果其他人要编辑我们最初做的任何工作，他们将清楚地了解我们用哪种方法构建了我们的站点/应用，只需扫描 SCSS 文件。

# 处理旧版浏览器

在“移动设备优先还是桌面优先？”的问题中，有一个领域我们需要涵盖一下，那就是旧版浏览器。每个项目，每个客户及其相应的分析（如果有的话，他们应该有），都有不同的要求，影响我们应该如何处理那些旧版浏览器。

如果你是用桌面优先的方法构建的，你当前的工作流程应该保持不变，因为这几乎就是在响应式网页设计变得几乎是强制性之前我们一直在做的事情。

这意味着你仍然会使用类似这样的东西：

```html
header {
    //Desktop-first declaration
    width: 50%;
    @include forSmallScreens(768) {
      //Target small screens (mobile devices)
      width: 100%; }
}
```

这编译成以下内容：

```html
header {
    width: 50%;
}

@media (max-width: 48em) {
    header {
      width: 100%;
    }
}
```

IE7 和 IE8 不支持媒体查询，但前面的代码将正常工作，因为`header { width: 50%; }`规则不在媒体查询内。

然而，如果你是以移动设备为先，那么`header { width: 50%; }`将在媒体查询内，因此 IE7 和 IE8 将无法看到该规则：

```html
.article {
    //Mobile-first declaration
    width: 100%;
    //IE7 and IE8 won't be able to see this rule.
    @include forLargeScreens(768) {
      width: 50%;
    }
}
```

这编译成以下内容：

```html
header {
    width: 100%;
}

@media (min-width: 48em) { 
    header {
      width: 50%;
    }
}
```

那么你该怎么办？解决方案非常简单：使用`Respond.js`脚本。

## 如何使用 Respond.js 进行 RWD

`Respond.js`是一种称为*polyfill*的脚本。根据最初提出这个术语的人 Remy Sharp 的说法，polyfill 是一段代码，提供了我们，网页开发人员，期望浏览器本地提供的技术。

在网页设计和开发中，polyfill 比 JavaScript 实现更丰富，例如 Scott Jehl 的`Respond.js`。但我们也可以说 CSS 中也有 polyfill，例如 Eric Meyer 的著名的`reset.css`和 Nicolas Gallagher 和 Jonathan Neal 的`Normalize.css`。

`Respond.js`脚本是一种 polyfill，使旧版浏览器（IE6/7/8）支持它们从未支持过的特定 CSS 功能：媒体查询。

您可以从[`github.com/scottjehl/Respond`](https://github.com/scottjehl/Respond)下载`Respond.js`。

### 提示

尽管我建议使用 polyfill，但我们需要注意网站/应用程序需要进行额外的 HTTP 请求以获取此 JavaScript 文件。我们的网站/应用程序发出的请求越少，它们就会越快，从而带来许多好处，如改善用户体验和积极的 SEO 影响。

因此，您需要做以下事情：

+   确保对`Respond.js`的调用在调用 CSS 文件之后*（希望只有一个 CSS 文件）*。

+   调用`Respond.js`脚本。

### 提示

性能最佳实践建议将非必要的脚本放在标记的底部，就在关闭的`</body>`标签之前。由于`Respond.js`针对的是旧版浏览器，让我们继续这样做。将脚本放在标记底部的另一个好处是有助于避免阻塞页面的渲染。

这是我们的示例 HTML：

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Mastering RWD with HTML5 &amp; CSS3</title>
    <link href="styles.css" rel="stylesheet">
</head>
<body>
    <header>Logo goes here…</header>
    <article>Content goes here…</article>
    <script src="img/respond.min.js"></script>
</body>
</html>
```

在我们的`styles.scss`文件中，我们输入以下行：

```html
//Mobile-first declaration
article { background: red;
    //Target screens 640px wide and larger
    @include forLargeScreens(640) {
        & { background: green; }
  }
}
```

这编译为以下内容：

```html
article {
    background: red;
}

@media (min-width: 40em) {
    article {
         background: green; 
    }
}
```

因此，当您调整 IE7 或 IE8 浏览器窗口大小时，如果窗口宽度为 640 像素或更小，则它将能够显示红色背景，如果窗口为 641 像素或更大，则显示绿色背景。

## IE 特定样式表的时代已经过去

自从我开始编写 CSS 以来，我一直避免创建 IE 特定的样式表。这样做的原因很简单：

+   **文件管理**：在进行生产时，文件越少，每个过程就越顺利；更不用说更不容易出错。

+   **可扩展性**：如果需要添加、删除或编辑样式，您和您的团队知道最终的更改需要出现在您的主要且唯一的 CSS 文件中，我们的情况下是 SCSS 文件。

+   **组织**：在添加、删除或编辑正确的 CSS 文件（在我们的情况下是 SCSS 文件）中的 IE 特定样式时，让每个人都保持一致。

+   **性能**：少一个 HTTP 请求是一件好事，非常好的事情。无论多么小，我们为性能所做的任何事情都可以为良好的用户体验带来很大帮助；更不用说快速的网站对 SEO 有好处。

### 不使用 IE 特定样式表的其他好处

在旧版浏览器中，当它们尝试下载 IE 特定的样式表时，页面渲染不会被阻塞。此外，故障排除更容易。那么我们该使用什么呢？

有几种方法可以通过将所有内容放在一个样式表中来处理 IE：

+   使用 CSS hack（不建议）。

+   使用`Modernizr.js`。

+   在`<html>`标签中使用条件类。

让我们再谈谈一个流行的方法，使用条件类。

#### 在`<html>`标签中使用条件类

Paul Irish 在 2008 年的文章（[`www.paulirish.com/2008/conditional-stylesheets-vs-css-hacks-answer-neither/`](http://www.paulirish.com/2008/conditional-stylesheets-vs-css-hacks-answer-neither/)）指定了一个我推荐的方法，原因有几个：

+   它很容易实现；只需将此标记块复制并粘贴到我们的 HTML 文件顶部即可。

+   这并不具有侵入性，因为没有任何人需要处理额外的文件（用户、浏览器、服务器和我们）。

+   它不需要 JavaScript 即可工作；如果访问者无法使用或禁用 JavaScript，一切仍将正常工作。

这是我使用的一个：

```html
<!--[if IE 8]> <html class="no-js ie8" lang="en"> <![endif]-->
<!--[if IE 9]> <html class="no-js ie9" lang="en"> <![endif]-->
<!--[if gt IE 9]><!--><html class="no-js" lang="en"><!--<![endif]-->
```

### 提示

IE10 及以上不再支持*条件注释*，这就是条件类标记中没有提及 IE10 的原因。

有了前面的条件类，针对特定 IE（此示例中为 IE7）的定位如下：

```html
.ie7 nav li {
    float: left;
}
```

如果我们需要针对所有 IE 进行定位，我们会这样做：

```html
.ie7, .ie8, .ie9 {
    nav li {
        float: left;
    }
}
```

这编译为以下内容：

```html
.ie7 nav li, .ie8 nav li, .ie9 nav li {
    float: left;
}
```

对于所有其他浏览器，我们会这样做：

```html
nav {
    display: flex;
}
```

无论您使用哪种方法，`Modernizr.js`或条件类，都是个人偏好。使用这两种方法中的任何一种都是*正确的*做法。

记住，无论如何都要避免 CSS hack。作为网页设计师和网页开发人员，我们有责任为每个人创造一个更好的网络。

# 如何处理高密度屏幕

网络上有很多文章解释了**每英寸点数**（DPI），**每英寸像素**（PPI）和**密度无关像素**（DP/DiP）是什么。虽然了解这些技术和术语的复杂细节可能很重要，但让我们把本书的范围限制在高密度屏幕的基础和我们需要了解的内容上。

## 位图还是矢量适用于高密度屏幕？

像 SVG、图标字体或常规字体这样的矢量是数学方程的视觉表示，因此无论它们的大小如何，它们永远不会失去质量。

为了使位图图像在高密度屏幕上显示良好，我们必须导出*正常质量*图像的高分辨率版本。这意味着我们需要为我们计划使用的每个位图图像创建两个文件（或更多）：一个用于非高密度屏幕（标准液晶显示器，旧 TFT 监视器，一些电视等）的正常质量图像，以及一个（或更多）用于高密度屏幕（例如任何*视网膜*设备和 Super AMOLED 显示器）的高质量图像。

这就是良好的设计判断发挥作用的地方，因为有时我们可能并不一定需要每次都导出两个（或更多）位图图像。

当我们必须考虑高密度屏幕时，有几种技术可以用来处理图像。这些技术在《第六章》*响应式网页设计中的图像和视频处理*中有详细解释。

# 有时 RWD 并不一定是正确的解决方案

例如，大多数旅行网站的预订部分。这类网站管理的大量信息和类型使得响应式网站变得非常困难。当访问谷歌搜索结果中排名前八的旅行网站时，我看到了以下情况：

+   [`www.kayak.com/`](http://www.kayak.com/)

+   **主页**：响应

+   **预订页面**：不响应

+   [`www.expedia.com/`](http://www.expedia.com/)

+   **主页**：响应

+   **预订页面**：响应

+   [`www.hotwire.com/`](https://www.hotwire.com/)

+   **主页**：不响应

+   **预订页面**：响应

+   [`www.travelocity.com/`](http://www.travelocity.com/)

+   **主页**：响应

+   **预订页面**：响应

+   [`www.orbitz.com/`](http://www.orbitz.com/)

+   **主页**：不响应

+   **预订页面**：不响应

+   [`www.priceline.com/`](http://www.priceline.com/)

+   **主页**：不响应

+   **预订页面**：不响应

+   [`www.tripadvisor.in/`](http://www.tripadvisor.in/)

+   **主页**：不响应

+   **预订页面**：不响应

+   [`www.hipmunk.com/`](https://www.hipmunk.com/)

+   **主页**：不响应

+   **预订页面**：不响应

以下是我们的一些发现的简要列表：

+   自从 Expedia 收购了 Travelocity，它们共享相同的平台。区别在于品牌定位；因此，我将考虑这两个网站为一个。

+   七个网站中有五个（71％）的主页不响应。

+   七个网站中有五个（71％）的预订页面不响应。

+   七个网站中只有一个（Expedia/Travelocity）是完全响应的（14％）。

+   七个网站中有四个（57％）根本没有 RWD。

我们可以得出结论，最受欢迎的旅行网站尚未完全采用 RWD，但有些是固定宽度和响应式布局的混合体。这就是为什么所有这些网站都有单独的移动应用程序。对于它们来说，RWD 可能不是优先考虑的，因此它们依赖于它们的移动应用程序来弥补这一不足。

尽管这在今天已经非常罕见，但有时我们可能需要构建一个不响应的网站或页面。实际上，今天有一些页面是不响应的。

CodePen 是最受欢迎的前端沙箱之一，而 CodePen 的编辑器不是响应式的。为什么？因为它不需要。开发人员很少会使用手机去 CodePen 编写 HTML、Sass 和 JavaScript。

话虽如此，如果您需要构建一个不需要响应的站点/页面，就 CSS 网格系统而言，有两个很好的选择：

+   使用我们的老朋友，960 网格系统（[`960.gs/`](http://960.gs/)）。

+   使用 1140 网格系统（[`www.1140px.com/`](http://www.1140px.com/)）。

有几件事需要考虑：

+   960 网格系统针对 1024px 宽的屏幕。

+   1140 网格系统针对 1280px 宽的屏幕。

+   1140 网格系统默认包含媒体查询，因此我们需要考虑并决定是最好保留它们还是最好删除它们以减小文件大小并减少 IE6-IE9 中的选择器限制。

因为我一直认为 960 网格系统左右各有 10px 的填充使内容离主容器的边缘太近，我在每一侧增加了 10 个像素，将填充增加到 20px，将 960 网格系统变成了 980 网格系统。从现在开始，我们将称其为 980GS。

# 使用 RWD 改装旧网站

如果有必要，我们需要准备使非响应式或固定宽度的站点/应用程序变得响应式。

有两种改装非响应式或固定宽度的站点/应用程序的方法。一种是使用**自适应 Web 设计**（**AWD**）技术，使用绝对单位（即像素）。另一种是使用 RWD，并使用非常简单的公式将所有像素值转换为百分比。

无论我们使用哪种技术，我们都必须使用桌面优先的方法，因为我们处理的站点只适用于宽屏。这意味着我们将在媒体查询中使用`max-width`属性。

在我们查看两种改装技术之前，我们需要一个基础页面来开始。

## 基础页面

您在此处看到的图形与 12 列 980GS 布局成比例。浏览器窗口宽度为 1024px，页面宽度为 980px：

![基础页面](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_03_01.jpg)

### 提示

我们灰色的主容器宽度为 980px，左右已经有 10px 的填充。这意味着内部的部分总是需要加起来等于**960px**。

以下是容器的组件：

+   灰色的主容器宽度为 980px，左右各有 10px 的填充。

+   绿色的**头部**和红色的**页脚**分别为 960px 或 12 列宽：940px 带有左右各 10px 的边距。

+   蓝色的**导航**部分宽度为 240px 或 3 列：220px 带有 10px 的左边距和右边距。

+   黄色的**内容**部分宽度为 710px 或 9 列：700px 带有 10px 的右边距。

+   白色的间距宽度为 20px，即**导航**右边距为 10px，**内容**左边距为 10px。

+   因此，*220px 导航 + 710px 内容 + 20px 间距 + 10px 边距 = 960px*。

## HTML

这是代表我们基础页面的标记：

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Retrofitting with Adaptive Web Design</title>
    <link href="css/styles.css" rel="stylesheet">
</head>
<body>
    <main class="container_12 clear">
      <header class="grid_12">Header</header>
      <nav class="grid_3">Nav</nav>
      <section class="grid_9">Content</section>
      <footer class="grid_12">Footer</footer>
    </main>
</body>
</html>
```

## CSS/SCSS

关于我们的 CSS/SCSS，我们只需要创建一个部分，即包含固定宽度网格的`_980gs.scss`文件。

然后，我们将创建一个`styles.scss`文件，我们将执行以下操作：

+   导入`_980gs.scss`文件。

+   包括我们简单的桌面优先 Sass mixin 来处理媒体查询。

+   使用`max-width`属性创建所有必要的媒体查询。

+   将其编译为`styles.css`并在我们的页面中使用。

### 创建 _980gs.scss 文件

`_980gs.scss`文件包含基本网格，如下所示：

```html
//Globals
*, *:before, *:after {
    box-sizing: border-box;
}

//Container
.container_12 {
    width: 980px;
    padding: 0 10px;
    margin: auto; 
}

//Grid >> Global
.grid {
    &_1, &_2, &_3, &_4, &_5, &_6, &_7, &_8, &_9, &_10, &_11, &_12 {
      float: left;
      margin: 0 10px;
    }
}

//Grid >> 12 Columns
.container_12 {
    .grid_1  { width: 60px; }
    .grid_2  { width: 140px; }
    .grid_3  { width: 220px; }
    .grid_4  { width: 300px; }
    .grid_5  { width: 380px; }
    .grid_6  { width: 460px; }
    .grid_7  { width: 540px; }
    .grid_8  { width: 620px; }
    .grid_9  { width: 700px; }
    .grid_10 { width: 780px; }
    .grid_11 { width: 860px; }
    .grid_12 { width: 940px; }
}

//Clear Floated Elements - http://davidwalsh.name/css-clear-fix
.clear, .row {
    &:before,
    &:after { content: ''; display: table; }
    &:after { clear: both; }
}

//Use rows to nest containers
.row { margin-bottom: 10px;
    &:last-of-type { margin-bottom: 0; }
}
//Legacy IE
.clear { zoom: 1; }
```

# 使用 AWD 进行改装

与 RWD 不同，其宽度是流体和弹性的（ems 和百分比），因此术语*相对单位*，在 AWD 中，宽度是固定的（像素）。因此，我们使用术语*绝对单位*，当我们调整浏览器窗口大小时，元素将*捕捉*到这些固定宽度。

在 AWD 中，我们几乎每个宽度都使用像素，甚至我们的媒体查询也是如此。

## 创建 styles.scss 文件

我们要做的第一件事是在`styles.scss`文件中导入部分`_980gs.scss`文件：

```html
//Retrofitting with Adaptive Web Design
@import "980gs";

```

然后，我们将包含我们简单的桌面优先 mixin 来处理媒体查询。然而，请记住我之前提到过这个 mixin 是可扩展的，如果我们想要的话，我们可以使它编译基于像素的值？我们所需要做的就是从除法`$media/16+em`中移除值`/16+em`：

```html
//Retrofitting with Adaptive Web Design
@import "980gs";

//Desktop-first Media Query Mixin
@mixin forSmallScreens($media) {
 @media (max-width: $media) { @content; }
}

```

以下规则仅用于样式目的，以实现我们在之前截图中看到的相同设计：

```html
//Retrofitting with Adaptive Web Design
@import "980gs";

//Desktop-first Media Query Mixin
@mixin forSmallScreens($media) {
    @media (max-width: $media) { @content; }
}

//Basic styling
.container_12 {
 background: #aaa;
 font-size: 30px;
 text-shadow: 0 1px 1px rgba(black,.5);
}
header { background: #429032; }
nav { background: #2963BD; }
section { background: #c90; }
footer { background: #c03; }

//Give heights to elements for better perception of sections
header, footer { height: 150px; }
nav, section { height: 440px; }

```

此时，我们的页面宽度为 980px，看起来和最初看到的截图一样。

让我们定义基本页面*捕捉*的宽度：

+   在 980px 时，我们将把页面捕捉到 768px。

+   在 768px 时，我们将把页面捕捉到 640px。

+   在 640px 时，我们将把页面捕捉到 480px。

+   在 480px 时，我们将把页面捕捉到 320px。

这就是乐趣开始的地方。让我们通过为每个部分创建媒体查询来开始改造这个页面。

### 980px 到 768px（AWD）

以下媒体查询针对 768px：

```html
.container_12 {
  @include forSmallScreens(980px) {
 width: 768px;
 }
    .grid_12 { //Header and Footer sections
      @include forSmallScreens(980px) {
 width: 728px;
 }
  }
  .grid_3 { //Nav section
    @include forSmallScreens(980px) {
 width: 200px;
 }
  }
  .grid_9 { //Content section
    @include forSmallScreens(980px) {
 width: 508px;
 }
  }
}
```

诚然，从 980px 到 768px，书中的差异有点难以察觉，但相信我，以下截图完全代表了浏览器窗口宽 980px，页面宽 768px：

![980px 到 768px（AWD）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_03_02.jpg)

正如你所看到的，一旦屏幕宽度达到 980px，我们的主容器（`.container_12`）的宽度就从 980px 变为 768px。我们的主容器左右各有 10px 的填充，因此所有其他部分的宽度应该加起来匹配 748px。

让我们来看看。

我们的**Header**和**Footer**使用相同的类`.grid_12`，现在宽度为 728px。因此，如果我们加上：*728px + 10px 左边距 + 10px 右边距 = 748px*。

如果我们将**Nav**（`.grid_3`）和**Content**（`.grid_9`）部分的宽度相加：

+   *200px Nav + 508px Content = 708px*

+   *708px + 20px gutter = 728px*

+   *728px + Nav 的左边距 10px + Content 的右边距 10px = 748px*

跟着我，我保证这会非常有趣。

### 768px 到 640px（AWD）

以下媒体查询针对 640px：

```html
.container_12 {
    @include forSmallScreens(980px) {
      width: 768px;
  }
    @include forSmallScreens(768px) {
 width: 640px;
 }
    .grid_12 { //Header and Footer sections
      @include forSmallScreens(980px) {
        width: 728px;
      }
      @include forSmallScreens(768px) {
 width: 600px;
 }
    }
    .grid_3 { //Nav section
      @include forSmallScreens(980px) {
        width: 200px;
      }
      @include forSmallScreens(768px) {
 width: 160px;
 }
    }
    .grid_9 { //Content section
      @include forSmallScreens(980px) {
        width: 508px;
      }
      @include forSmallScreens(768px) {
 width: 420px;
 }
    }
}
```

好的，这个布局现在是单列页面。我们开始看到一些结果了。不错！

![768px 到 640px（AWD）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_03_03.jpg)

再次，请记住，我们的主容器左右各有 10px 的填充，因此所有其他部分的宽度应该加起来匹配 620px。

让我们确保我们的数字加起来：

我们的**Header**和**Footer**使用相同的类`.grid_12`，现在宽度为 600px。因此，如果我们加上：*600px + 10px 左边距 + 10px 右边距 = 620px*。

如果我们将**Nav**（`.grid_3`）和**Content**（`.grid_9`）部分的宽度相加：

+   *160px Nav + 420px Content = 580px*

+   *580px + 20px gutter = 600px*

+   *600px + Nav 的左边距 10px + Content 的右边距 10px = 620px*

让我们把这个页面变得更小！

### 640px 到 480px（AWD）

以下媒体查询针对 480px：

```html
.container_12 {
    @include forSmallScreens(980px) {
      width: 768px;
    }
    @include forSmallScreens(768px) {
      width: 640px;
    }
    @include forSmallScreens(640px) {
 width: 480px;
 }
    .grid_12 { //Header and Footer sections
      @include forSmallScreens(980px) {
        width: 728px;
      }
      @include forSmallScreens(768px) {
        width: 600px;
      }
    }
    .grid_3 { //Nav section
      @include forSmallScreens(980px) {
        width: 200px;
      }
      @include forSmallScreens(768px) {
        width: 160px;
      }
    }
    .grid_9 { //Content section
      @include forSmallScreens(980px) {
        width: 508px;
      }
      @include forSmallScreens(768px) {
        width: 420px;
      }
    }
    .grid_3,
 .grid_9,
 .grid_12 {
 @include forSmallScreens(640px) {
 width: 440px;
 }
 }
}
```

我们取得了一些应得的进展！在这里，浏览器窗口宽 640px，页面宽 480px：

![640px 到 480px（AWD）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_03_04.jpg)

请记住，我们的主容器左右各有 10px 的填充，因此所有其他部分的宽度应该加起来匹配 460px。

现在，我们将从 2 列布局更改为 1 列布局。这意味着所有部分现在具有完全相同的宽度。

这也意味着在我们的 SCSS 文件中，我们可以为所有三个类创建一个单一的媒体块：

```html
.grid_3,
.grid_9,
.grid_12 {
    @include forSmallScreens(640px) {
      width: 440px;
    }
}
```

现在，让我们确保我们的数字加起来：

我们的**Header**，**Nav**，**Content**和**Footer**部分现在宽度为 440px，依次堆叠在一起。因此，如果我们加上：*所有部分的 440px + 10px 左边距 + 10px 右边距 = 460px*。

我们来了，这个谜题的最后一块！

### 480px 到 320px（AWD）

以下媒体查询针对 320px：

```html
.container_12 {
    @include forSmallScreens(980px) {
      width: 768px;
    }
    @include forSmallScreens(768px) {
      width: 640px;
    }
    @include forSmallScreens(640px) {
      width: 480px;
    }
    @include forSmallScreens(480px) {
 width: 320px;
 padding: 0;
 }
    .grid_12 { //Header and Footer sections
      @include forSmallScreens(980px) {
        width: 728px;
      }
      @include forSmallScreens(768px) {
        width: 600px;
      }
    }
    .grid_3 { //Nav section
      @include forSmallScreens(980px) {
        width: 200px;
      }
      @include forSmallScreens(768px) {
        width: 160px;
      }
      @include forSmallScreens(640px) {     
        height: 50px; //This is only for styling
      }
    }
    .grid_9 { //Content section
      @include forSmallScreens(980px) {
        width: 508px;
      }
      @include forSmallScreens(768px) {
        width: 420px;
      }
    }
    .grid_3,.grid_9,.grid_12 {
      @include forSmallScreens(640px) {
        width: 440px;
      }
 @include forSmallScreens(480px) {
 width: 300px;
 }
    }
}
```

我们来了！在这个屏幕截图中，浏览器窗口宽度为 320px，内容也是 320px 宽，非常合适：

![480px 到 320px（AWD）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_03_05.jpg)

我们已经知道我们的主容器左右各有 10 像素的填充。在这种情况下，我们将去掉填充以获得这 20 像素，因为我们的屏幕空间现在非常小：

```html
@include forSmallScreens(480px) {
    width: 320px;
    padding: 0;
}
```

左右各 10 像素的间距现在将由其他部分的左右边距创建。这意味着每个部分的宽度应为 300 像素。

添加新的 320 像素断点很容易：

```html
.grid_3,
.grid_9,
.grid_12 {
    @include forSmallScreens(640px) {
      width: 440px;
    }
    @include forSmallScreens(480px) {
 width: 300px;
 }
}
```

现在，让我们确保我们的数字加起来：

我们的**标题**、**导航**、**内容**和**页脚**部分现在都是 300 像素宽，依次堆叠在一起。所以如果我们加上：*所有部分的 300 像素 + 10 像素左边距 + 10 像素右边距 = 320 像素*。

就是这样。我们现在已经使用 AWD 技术将固定宽度页面改为响应式。

最终的 SCSS 如下：

```html
.container_12 {
    @include forSmallScreens(980px) {
      width: 768px;
    }
    @include forSmallScreens(768px) {
      width: 640px;
    }
    @include forSmallScreens(640px) {
      width: 480px;
    }
    @include forSmallScreens(480px) {
 width: 320px; padding: 0;
 }
    .grid_12 { //Header and Footer sections
      @include forSmallScreens(980px) {
        width: 728px;
      }
      @include forSmallScreens(768px) {
        width: 600px;
      }
    }
    .grid_3 { //Nav section
      @include forSmallScreens(980px) {
        width: 200px;
      }
      @include forSmallScreens(768px) {
        width: 160px;
      }
      @include forSmallScreens(640px) {     
        height: 50px; //This is only for styling
      }
    }
    .grid_9 { //Content section
      @include forSmallScreens(980px) {
        width: 508px;
      }
      @include forSmallScreens(768px) {
        width: 420px;
      }
    }
    .grid_3, .grid_9, .grid_12 {
      @include forSmallScreens(640px) {
        width: 440px;
      }
 @include forSmallScreens(480px) {
 width: 300px;
 }
    }
}
```

它编译成以下 CSS：

```html
@media (max-width: 980px) {
    .container_12 {
      width: 768px;
    }
}
@media (max-width: 768px) {
    .container_12 {
      width: 640px;
    }
}
@media (max-width: 640px) {
    .container_12 {
      width: 480px;
    }
}
@media (max-width: 480px) {
    .container_12 {
      width: 320px;
      padding: 0;
  }
}
@media (max-width: 980px) {
    .container_12 .grid_12 {
      width: 728px;
    }
}
@media (max-width: 768px) {
    .container_12 .grid_12 {
      width: 600px;
    }
}
@media (max-width: 980px) {
    .container_12 .grid_3 {
      width: 200px;
    }
}
@media (max-width: 768px) {
    .container_12 .grid_3 {
      width: 160px;
    }
}
@media (max-width: 640px) {
    .container_12 .grid_3 {
      height: 50px;
    }
}
@media (max-width: 980px) {
    .container_12 .grid_9 {
      width: 508px;
    }
}
@media (max-width: 768px) {
    .container_12 .grid_9 {
      width: 420px;
    }
}
@media (max-width: 640px) {
    .container_12 .grid_3, .container_12 .grid_9,.container_12 .grid_12 {
      width: 440px;
    }
}
@media (max-width: 480px) {
    .container_12 .grid_3,.container_12 .grid_9,.container_12 .grid_12 {
      width: 300px;
  }
}
```

### 提示

正如你所看到的，我们的最终 CSS 文件中重复了几个断点。这是 Sass 的一个问题。然而，这实际上并不是一个问题，也不是我们需要担心的事情，因为当服务器对该文件进行 gzip 压缩时，它将以最大限度进行压缩。如果我们最小化最终输出（无论如何我们都应该这样做），我们将进一步压缩文件。重复的`@media`断点对性能几乎没有任何影响。

现在，让我们看看使用百分比和 RWD 改装相同页面的样子。

# 使用 RWD 进行改装

我们刚刚看到了如何使用像素来实现 AWD。通过 RWD 和一个非常简单的方程，我们可以使用相对单位（在我们的情况下是百分比）来改装网站。更不用说这将比使用 AWD 要容易得多。

## RWD 的魔法公式

由 Ethan Marcotte 发现/创造，他创造了*响应式网页设计*这个术语，RWD 的魔法公式是一个非常简单的方程：

（目标 ÷ 上下文）x 100 = 结果 %

在我们开始将像素转换为百分比之前，我们需要看看我们的*上下文*将是哪个宽度。

## 主容器

我们的上下文将是页面的主容器`.container_12`，最大宽度为 980 像素。然而，主容器和列之间存在一个问题，将这个 980 像素的上下文变成 960 像素。请注意`.container_12`部分的左右 10 像素填充和`.grid`规则中的左右 10 像素边距：

```html
.container_12 {
    width: 980px;
    padding: 0 10px;
    margin: auto; 
}
.grid {
    &_1, &_2, &_3, &_4, &_5, &_6, &_7, &_8, &_9, &_10, &_11, &_12 {
      float: left;
      margin: 0 10px;
    }
}
```

`.grid`规则中的 10 像素左右边距意味着所有列的宽度都增加了 20 像素。所以，例如，宽度为 940 像素的标题和页脚实际上是 960 像素宽。`box-sizing: border-box;`属性只考虑减去盒模型内部的内容（填充），而不考虑外部的内容（边距）。

一个解决方案是去掉`.container_12`的左右 10 像素填充，并在`.grid`规则中增加左右边距为 20 像素，以保持间距；否则，列会相互接触。

现在，间距变得更宽，这可能不是出于设计目的，而且——信不信由你——在最宽的容器中会多出 1 像素。在我们的情况下，它会添加到标题和页脚中。

作为设计师，我知道如果不得不处理这些问题，我是不想要的。

第二种解决方案更简单：将上下文设为 960 像素。这样，我们可以全局去掉多余的 10 像素，而不会影响主容器和列的完整性，由于我们得到的是百分比，所以结果几乎相同。

换句话说：*(960 像素 ÷ 980 像素) x 100 = 97.95918367346939% (97.95%)*

这实际上等同于：*(940 像素 ÷ 960 像素) x 100 = 97.91666666666667% (97.91%)*

在第二种解决方案中，1 像素的问题确实会发生，但是在调整浏览器宽度时会在随机宽度时发生。然而，在第一种解决方案中，1 像素的问题是永久性的，无论浏览器的宽度如何。

弄清楚这一点后，我们将把所有基于像素的宽度转换为使用 960 像素作为上下文的百分比。

## 标题和页脚部分

**Header**和**Footer**部分的宽度都是 940px。知道它们的上下文是 960px，让我们继续使用魔术公式找到它们的百分比宽度：*(940px ÷ 960px) x 100 = 97.91666666666667%*。

你可能会问自己，“这么多小数点有必要吗？”不是所有的小数点，但至少建议使用两位。

所以我们最终得到**Header**和**Footer**部分为 97.91%。

一些开发人员建议使用所有小数，并让浏览器决定要使用多少。过去，我决定挑战这个建议，只使用两位小数来看看会发生什么。自从我开始使用两位小数以来，在任何浏览器中都没有遇到任何不良行为或宽度问题。

Firefox 和 IE11 会将多余的小数点截断为两位。另一方面，Chrome 会保留所有小数点。我建议至少使用两位小数，这也是我们在书中使用的方式，以保持简单和简洁。但是，如果您更喜欢使用所有小数点，那就尽管去做！这在这一点上是个人偏好的问题。

### 提示

避免四舍五入值，并让浏览器处理小数点。这样做也可以让您专注于最重要的事情：高效并尝试为用户创造令人难忘的体验。

## Nav 部分

为了找到**Nav**部分的百分比宽度，我们同样使用 960px 作为上下文：*(220px ÷ 960px) x 100 = 22.91666666666667%*。

使用两位小数，我们最终得到**Nav**部分为 22.91%。

## Content 部分

为了找出**Content**部分的百分比宽度，我们的公式看起来几乎一样。唯一的区别是我们正在改变第一个值，即**Content**部分的宽度（以像素为单位）：*(700px ÷ 960px) x 100 = 72.91666666666667%*。

仅使用两位小数，我们最终得到**Content**部分为 72.91%。

这就是我们初始的改装 RWD SCSS 文件的样子：

```html
.container_12 {
    .grid_12 { //Header and Footer sections
      width: 97.91%;
    }
    .grid_3 { //Nav section
      width: 22.91%;
    }
    .grid_9 { //Content section
       width: 72.91%;
    }
}
```

现在，让我们退一步，先处理一些其他基于像素的宽度。还记得主容器`.container_12`左右各有 10px 的填充吗？我们也需要将这 10px 转换为百分比。

使用我们的魔术公式，我们这样做：

*(10px ÷ 960px) x 100 = 1.041666666666667%*。

仅使用两位小数，我们最终得到左右填充为 1.04%。

让我们将这个值添加到我们的 SCSS 中：

```html
.container_12 {
    width: 980px;
    padding: 0 1.04%;
    margin: auto; 
}
.container_12 {
    .grid_12 { //Header and Footer sections
      width: 97.91%;
    }
    .grid_3 { //Nav section
      width: 22.91%;
    }
    .grid_9 { //Content section
       width: 72.91%;
    }
}
```

此外，我们所有的列左右各有 10px 的边距。由于我们已经知道 10px 等于 1.04%，让我们将这个值添加到我们 SCSS 中的所有列中：

```html
.container_12 {
    width: 980px;
    padding: 0 1.04%;
    margin: auto; 
}
.grid {
 &_1, &_2, &_3, &_4, &_5, &_6, &_7, &_8, &_9, &_10, &_11, &_12 {
 float: left;
 margin: 0 1.04%;
 }
}
.container_12 {

    .grid_12 { //Header and Footer sections
      width: 97.91%;
    }
    .grid_3 { //Nav section
      width: 22.91%;
    }
    .grid_9 { //Content section
       width: 72.91%;
    }
}
```

现在，我们有一个宽度为 1024px 的浏览器窗口，一个宽度为 980px 的布局，以及所有列都具有相应的百分比值。实际上，这几乎是不可能的，除非查看代码以在固定宽度和基于百分比的布局之间进行视觉区分。

我们做得很好！

![Content 部分](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_03_01.jpg)

让乐趣开始吧。让我们添加我们的第一个媒体查询。

### 980px 到 768px（RWD）

以下媒体查询针对 768px：

```html
.container_12 {
    width: 980px;
    padding: 0 1.04%;
    margin: auto; 
}
.grid {
    &_1, &_2, &_3, &_4, &_5, &_6, &_7, &_8, &_9, &_10, &_11, &_12 {
 float: left;
      margin: 0 1.04%;
    }
}
.container_12 {
    @include forSmallScreens(980px) {
 width: 768px;
 }
    .grid_12 { //Header and Footer sections
      width: 97.91%;
    }
    .grid_3 { //Nav section
      width: 22.91%;
    }
    .grid_9 { //Content section
       width: 72.91%;
    }
}
```

由于**Header**、**Footer**、**Nav**和**Content**部分的宽度、填充和边距现在都以百分比设置，我们不必为它们声明任何媒体查询——至少目前还不需要，因为布局还没有改变。

当我们调整浏览器窗口大小时，**Header**、**Footer**、**Nav**和**Content**部分会自动响应，按比例缩小，正确对齐，并适应主容器`.container_12`的新宽度，而不会破坏布局。如下截图所示：

![980px 到 768px（RWD）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_03_02.jpg)

太棒了！

让我们添加另一个断点。

### 768px 到 640px（RWD）

在以下断点（640px）中，我们的布局将变为单列。因此，我们将添加一个新的媒体查询，使**Nav**和**Content**部分与**Header**和**Footer**部分一样宽，并使它们堆叠在一起。

以下媒体查询针对 640px，并使**Nav**和**Content**部分全宽：

```html
.container_12 {
    width: 980px;
    padding: 0 1.04%;
    margin: auto;
}
.grid {
    &_1, &_2, &_3, &_4, &_5, &_6, &_7, &_8, &_9, &_10, &_11, &_12 {
        float: left;
        margin: 0 1.04%;
    }
}
.container_12 {
    @include forSmallScreens(980px) {
        width: 768px;
    }
    @include forSmallScreens(768px) {
 width: 640px;
 }
    .grid_12 { //Header and Footer sections
      width: 97.91%;
    }
    .grid_3 { //Nav section
      width: 22.91%;
    }
    .grid_9 { //Content section
      width: 72.91%;
    }
    .grid_3, .grid_9 { //Nav and Content sections
 @include forSmallScreens(640px) {
 width: 97.91%;
 }
 }
}
```

好的，我们现在有了单列布局。还不错，还不错！

![768px 到 640px（RWD）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_03_03.jpg)

### 640px 到 480px（RWD）

现在我们的宽度已经缩小到 480px，单列布局不会改变，只有所有容器的宽度会改变。

以下媒体查询针对 480px：

```html
.container_12 {
  width: 980px;
  padding: 0 1.04%;
  margin: auto; 
}
.grid {
    &_1, &_2, &_3, &_4, &_5, &_6, &_7, &_8, &_9, &_10, &_11, &_12 {
 float: left;
      margin: 0 1.04%;
    }
}
.container_12 {
    @include forSmallScreens(980px) {
      width: 768px;
    }
    @include forSmallScreens(768px) {
      width: 640px;
    }
    @include forSmallScreens(640px) {
 width: 480px;
 }
    .grid_12 { //Header and Footer sections
      width: 97.91%;
    }
    .grid_3 { //Nav section
      width: 22.91%;
      @include forSmallScreens(640px) {     
        height: 50px; //This is only for styling
      }
    }
    .grid_9 { //Content section
       width: 72.91%;
    }
    .grid_3, .grid_9 { //Nav and Content sections
 @include forSmallScreens(640px) {
 width: 97.91%;
 }
 }
}
```

我们的布局变窄了，我们需要做的就是添加一个新的媒体查询，就这样！不需要在其他容器上瞎折腾；它们都完美地适应了我们定义的任何宽度。

![640px 到 480px（RWD）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_03_04.jpg)

### 480px 到 320px（RWD）

最后，我们解决了 320px 的宽度，而不修改单列布局。我们去掉了`.container_12`上的填充，以利用所有可用的屏幕空间。

以下媒体查询针对 320px：

```html
.container_12 {
    width: 980px;
    padding: 0 1.04%;
    margin: auto;
}
.grid {
    &_1, &_2, &_3, &_4, &_5, &_6, &_7, &_8, &_9, &_10, &_11, &_12 {
 float: left;
    margin: 0 1.04%;  }
}
.container_12 {
    @include forSmallScreens(980px) {
      width: 768px;
    }
    @include forSmallScreens(768px) {
      width: 640px;
    }
    @include forSmallScreens(640px) {
      width: 480px;
    }
    @include forSmallScreens(480px) {
 width: 320px; padding: 0;
 }
    .grid_12 { //Header and Footer sections
      width: 97.91%;
    }
    .grid_3 { //Nav section
      width: 22.91%;
      @include forSmallScreens(640px) {     
        height: 50px; //This is only for styling
      }
    }
    .grid_9 { //Content section
       width: 72.91%;
    }
    .grid_3, .grid_9 {
      @include forSmallScreens(640px) {
        width: 97.91%;
      }
    }
}
```

再次，我们不必添加任何内容到**Header**、**Footer**、**Nav**和**Content**部分，因为它们现在都是 97.91%宽。这使它们具有响应性，我们不必担心其他任何事情。

![480px 到 320px（RWD）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_03_05.jpg)

最终的 SCSS，结合所有断点和宽度，如下所示：

```html
.container_12 {
    width: 980px;
    padding: 0 1.04%;
    margin: auto;
}
.grid {
    &_1, &_2, &_3, &_4, &_5, &_6, &_7, &_8, &_9, &_10, &_11, &_12 {
        float: left;
        margin: 0 1.04%;
    }
}
.container_12 {
    @include forSmallScreens(980px) {
        width: 768px;
    }
    @include forSmallScreens(768px) {
        width: 640px;
    }
    @include forSmallScreens(640px) {
        width: 480px;
    }
    @include forSmallScreens(480px) {
        width: 320px; padding: 0;
    }
    .grid_12 { //Header and Footer sections
      width: 97.91%;
    }
    .grid_3 { //Nav section
      width: 22.91%;
    }
    .grid_9 { //Content section
      width: 72.91%;
    }
    .grid_3, .grid_9 { //Nav and Content sections
        @include forSmallScreens(640px) {
            width: 97.91%;
        }
    }
}
```

它编译成以下 CSS：

```html
.container_12 {
    width: 980px;
    padding: 0 1.04%;
    margin: auto;
}

.grid_1, .grid_2, .grid_3, .grid_4, .grid_5, .grid_6, .grid_7, .grid_8, .grid_9, .grid_10, .grid_11, .grid_12 {
    float: left;
    margin: 0 1.04%;
}

@media (max-width: 980px) {
    .container_12 {
      width: 768px;
    }
}
@media (max-width: 768px) {
    .container_12 {
      width: 640px;
    }
}
@media (max-width: 640px) {
    .container_12 {
      width: 480px;
    }
}
@media (max-width: 480px) {
    .container_12 {
      width: 320px;
      padding: 0;
    }
}
.container_12 .grid_12 {
    width: 97.91%;
}
.container_12 .grid_3 {
    width: 22.91%;
}
.container_12 .grid_9 {
    width: 72.91%;
}
@media (max-width: 640px) {
    .container_12 .grid_3, .container_12 .grid_9 {
      width: 97.91%;
    }
}
```

正如你所看到的，使用 RWD 比 AWD 来改造站点的代码要少得多。当然，这些例子是对站点/应用布局的极端简化，但现在你已经了解了在使用 AWD 或 RWD 时做出决定的基本概念。

# 总结

在本章中，我们讨论了很多有趣的内容。我们看到，使用桌面优先来创建设计和线框图是有益的，因为拥有一个大画布可以让我们探索不同的布局，并正确安排内容的层次结构。

在创建 HTML 模型时，使用移动优先更好，因为移动友好的站点将具有更广泛的覆盖范围，允许专注的内容，并利用移动设备的技术。

我们能够使用魔术公式对固定宽度的站点进行 AWD 和 RWD 的改造。我们还讨论了 RWD 的好处，因为它需要的代码要少得多。然而，对旅行网站的分析清楚地告诉我们，RWD 有时并不是正确的解决方案。

我们还看到了`Respond.js`如何用于使旧版浏览器支持媒体查询，如果我们采用移动优先的方法构建。使用条件类是一种很好的技术，因为它不会侵入，很容易实现，并且没有 JavaScript 依赖。

在下一章中，我们将讨论 RWD 世界中一些最有趣的主题：CSS 网格、CSS 框架和 Flexbox 的强大。 

让我们开始吧！


# 第四章：CSS 网格、CSS 框架、UI 工具包和 Flexbox 用于 RWD

**响应式网页设计** (**RWD**)为所有构建响应式网站和应用程序的人引入了一层新的工作。当我们必须在不同设备和不同尺寸上测试我们的工作时，无论内容在哪里中断，我们都需要添加一个断点并重新测试。

这可能会发生很多次。因此，构建网站或应用程序将比以前花费更多的时间。

为了使事情更有趣，作为网页设计师和开发人员，我们需要注意内容在不同尺寸上的布局以及网格如何帮助我们将内容结构化到不同的布局中。

既然我们提到了网格，你有没有问过自己，“我们到底用网格做什么？”

借用设计行业的一些术语来回答这个问题，我们使用网格来让内容具有节奏、比例和平衡。目标是让使用我们网站/应用的人对我们的内容有更愉快的体验，因为它将更容易扫描（节奏）、更容易阅读（比例）和有组织（平衡）。

为了加快设计和构建过程，同时保持所有内容在不同尺寸下正确格式化，许多作者和公司创建了包含网格以及许多其他功能和样式的 CSS 框架和 CSS 网格，可以通过使用简单的类名来利用。

随着时间的推移，浏览器开始支持越来越多的 CSS3 属性，比如 Flexbox，使用布局将变得更加容易。这将使 CSS 框架中的网格几乎变得不必要。

让我们看看 CSS 网格、CSS 框架、UI 工具包和 Flexbox 是什么，以及它们如何帮助我们实现 RWD。

在本章中，我们将涵盖以下主题：

+   什么是网格？

+   CSS 网格

+   CSS 网格在 RWD 中的优缺点

+   CSS 框架

+   UI 工具包

+   CSS 框架在 RWD 中的优缺点

+   创建自定义 CSS 网格

+   使用自定义 CSS 网格构建示例页面

+   使用 Flexbox

+   使用 Flexbox 构建示例页面

# 什么是网格？

网格是一组视觉指南（垂直、水平或两者兼有，因此称为*网格*），它们有助于定义元素的放置位置。一旦元素被放置，我们就得到了一个*布局*。

使用网格的好处是放置在上面的元素将在页面上具有和谐的流动，增强用户体验，提高可读性、布局一致性和元素之间的良好比例。

# CSS 网格

CSS 网格基本上是由形成列的垂直指南的组合。这些列的属性在 CSS 文件中定义。该文件包含一个具有特定宽度的类列表，与特定网格构建的列数相匹配。

我们在第三章中已经见过了，当时我们使用**980 Grid System** (**980GS**)来改造一个旧的固定宽度站点。这是 SCSS 文件：

```html
*, *:before, *:after {
    box-sizing: border-box;
}

//Container
.container-12 {
     width: 980px;
     padding: 0 10px;
     margin: auto;
}
//Grid >> Global
.grid {
    &-1, &-2, &-3, &-4, &-5, &-6, &-7, &-8, &-9, &-10, &-11, &-12 {
        float: left;
        margin: 0 10px;
    }
}
//Grid >> 12 Columns
.container-12 {
    .grid-1  { width: 60px; }
    .grid-2  { width: 140px; }
    .grid-3  { width: 220px; }
    .grid-4  { width: 300px; }
    .grid-5  { width: 380px; }
    .grid-6  { width: 460px; }
    .grid-7  { width: 540px; }
    .grid-8  { width: 620px; }
    .grid-9  { width: 700px; }
    .grid-10 { width: 780px; }
    .grid-11 { width: 860px; }
    .grid-12 { width: 940px; }
}
//Clear Floated Elements - http://davidwalsh.name/css-clear-fix
.clear, .row {
    &:before,
    &:after { content: ''; display: table; }
    &:after { clear: both; }
}
//Use rows to nest containers
.row { margin-bottom: 10px;
    &:last-of-type { margin-bottom: 0; }
}
//Legacy IE
.clear { zoom: 1; }
```

### 提示

记住，我们将 960GS 变成了 980GS，因为内容看起来离主容器的边缘太近，主容器的左右各有 10px 的间距。因此，我们在每一侧都添加了 10px，并将主容器的宽度设为 980px。

因为我们正在使用 HTML5 和 CSS3 掌握 RWD，让我们看看相同的 980GS，使用百分比使其流动起来。

RWD 的魔法公式是*(目标 ÷ 上下文) x 100 = 结果 %*。

在这种情况下，我们的上下文是 980px，如下所示：

```html
//Container
.container-12 {
    width: 100%;
    max-width: 980px;
    padding: 0 1.02%;
    margin: auto;
}
//Grid >> Global
.grid {
    &-1, &-2, &-3, &-4, &-5, &-6, &-7, &-8, &-9, &-10, &-11, &-12 {
        float: left;
        margin: 0 1.02%;
    }
}
//Grid >> 12 Columns
.container-12 {
    .grid-1  { width: 6.12%; }
    .grid-2  { width: 14.29%; }
    .grid-3  { width: 22.45%; }
    .grid-4  { width: 30.61%; }
    .grid-5  { width: 38.78%; }
    .grid-6  { width: 46.94%; }
    .grid-7  { width: 55.10%; }
    .grid-8  { width: 63.27%; }
    .grid-9  { width: 71.43%; }
    .grid-10 { width: 79.59%; }
    .grid-11 { width: 87.76%; }
    .grid-12 { width: 95.92%; }
}
//Clear Floated Elements - http://davidwalsh.name/css-clear-fix
.clear, .row {
  &:before,
  &:after { content: ''; display: table; }
  &:after { clear: both; }
}
//Use rows to nest containers
.row { margin-bottom: 10px;
  &:last-of-type { margin-bottom: 0; }
}
//Legacy IE
.clear { zoom: 1; }
```

在网页设计中，网格通常由 12 或 16 列组成。960GS 几乎是最著名的之一，尽管它一直是一个固定宽度的网格。但其他作者已经将其移植成流动的，比如*Fluid 960 Grid System*，但不是响应式的。960GS 还有 24 列的选项，但不像 12 列版本那么受欢迎。

还有其他用于网页设计的网格，它们没有定义的框架宽度或列数，而是可以有无限数量的列，比如基于**自适应 Web 设计**（**AWD**）的*无框网格*。这意味着主容器的宽度*捕捉*到由它容纳的列数计算出的特定断点。

## CSS 网格用于 RWD 的优缺点

列出 CSS 网格用于 RWD 的优缺点的想法是，当我们计划使用某种类型的网格时，我们应该能够做出最明智的决定。这有助于澄清客户的期望和我们自己的期望，因为使用某种网格将影响时间表、设计、布局和许多 UX 因素。

优点如下：

+   布局元素变得更容易，因为列作为放置的指南。

+   如果使用预先构建的 CSS 网格，则无需进行任何数学计算来处理列和间距宽度。这已经由网格的作者处理了。

+   我们可以更快地构建，因为我们只需要在我们的 HTML 容器中添加特定的类，而大部分布局将立即发生。

+   了解网页设计中的网格相对简单，因此在已建立的项目中增强/编辑其他人的标记和代码比如果根本没有使用 CSS 网格要少痛苦。

+   如果网格是响应式或自适应的，我们就不必太担心断点。

+   如果我们使用第三方 CSS 网格，任何跨浏览器问题都已经得到解决。

缺点如下：

+   一些 CSS 网格的学习曲线比其他的陡峭。

+   对于许多 CSS 网格，我们被锁定在作者创建的命名约定中。

+   我们可能需要改变/调整我们编写 HTML 的方式。

+   有太多 CSS 网格可供选择，对一些人来说可能会感到不知所措。

+   如果我们的内容在网格不支持的某些点上中断，我们必须花时间修改原始网格以适应每种情况。

# CSS 框架

CSS 框架是一组预构建功能，基本上帮助加快 Web 前端开发。这些 CSS 框架的作者已经处理了许多重要但细微的细节，因此决定使用它们的人可以专注于手头的任务，同时将许多决定留给 CSS 框架本身。

许多开发人员和设计师相信（我也是）任何 CSS 框架的真正价值在于它们的 CSS 网格，有时我们会不遗余力地提取 CSS 网格并自定义它以满足我们的需求。

在本书中，我们将专注于 CSS 网格来掌握 RWD，而不是从 CSS 框架或 UI 工具包中剥离一个（如果它确实提供一个）。我们很快就会谈到这一点。

以下列表描述了一些 CSS 框架的特点和特征：

+   CSS 框架专注于基于 Web 的开发，而不是原生移动应用程序。

+   CSS 框架总是提供 CSS 网格。

+   许多 UI 工具包还提供用户界面组件（就像 UI 工具包一样），例如滑块、分页、导航栏、排版、按钮等，以 HTML 和 CSS 的形式。

+   CSS 框架和面向 Web 的 UI 工具包都可以称为*前端框架*。

# UI 工具包

与 CSS 框架类似，还有另一种称为 UI 工具包的前端框架。然而，UI 工具包可以是一种独特的类型。

说实话，有时很难区分 CSS 框架和 UI 工具包。但不要过多地深究哪一个是哪一个，重要的是要理解我们首先为什么使用它们以及它们如何帮助我们构建更好、更快速的响应式网站和应用程序。

以下列表描述了一些 UI 工具包的特点和特征：

+   基本上有两种类型的 UI 工具包：一种是使用 Web 技术（HTML 和 CSS）构建的，可以用来原型化基于 Web 的应用程序，另一种是由（通常是）Photoshop（PSD）文件制作的，用来帮助设计本机移动应用程序的模拟和设计。

+   很少有面向网络的 UI 工具包提供某种网格。

+   UI 工具包专注于提供用户界面组件，如滑块、分页、导航栏、对话框、覆盖/模态、按钮、排版、工具提示、列表、手风琴、选项卡系统、旋转木马/幻灯片、表单等。

+   在面向网络的 UI 工具包中，架构非常模块化。这意味着每个组件都可以并入任何 CSS 框架。

# RWD 的 CSS 框架的优缺点

以 RWD 作为我们在布局与屏幕房地产方面做出的任何决定的主要驱动力，让我们来看看 CSS 框架的优点和不足之处：

优点如下：

+   它们非常有用，可以快速构建响应式原型，而不是显示静态线框。

+   跨浏览器问题已经得到解决。

+   它们以一种好的方式，迫使你创建基于网格的布局。

+   它们为构建提供了一个坚实的起点。

+   模块化允许你手动选择你想要的组件。例如，你可以只使用 CSS 网格模块，或者你可以使用`forms`模块。

+   更改样式以适应你的设计相对容易。

+   如果你对 CSS 不太擅长，你仍然可以使用 CSS 框架来实现自己的设计。

缺点如下：

+   它们可能会用你永远不会使用的 CSS 来膨胀你的项目。

+   如果你决定使用整个 CSS 框架，它们的占用空间很大。

+   你可能需要改变你的习惯和编写 HTML 和 CSS 的方式，以适应你正在使用的 CSS 框架。

+   它们可能会持有自己的观点，所以如果你不喜欢事物的命名方式，你几乎没有选择自定义。

+   定制 CSS 框架是可行的，但可能非常耗时和危险。将一个名称更改为其他名称，几乎没有办法知道对框架的其他部分会产生什么影响。

+   如果默认样式没有改变以适应你的品牌/设计，你的网站或应用将不会是独特的，看起来会像其他人的，失去了用户的信任。

+   如果需要构建简单的东西，使用 CSS 框架就太过了。

+   每个网站/应用程序或项目都是不同的，所以你可能最终会花费大量时间为每个项目更改和覆盖属性。

+   他们试图解决每一个前端问题。

现在我们已经看到了 CSS 网格、CSS 框架和 UI 工具包的优缺点，是时候做出决定并回答这个问题了：哪种方法对 RWD 最好？

答案并不是最令人鼓舞的，我承认，但这是事实：这取决于情况。

如果我们是自由职业者，自己做所有事情，或者在一个非常小的团队中工作，也许根本不需要使用任何框架。我们可以根据主要框架建立的原则自定义构建一些东西。显然，我们希望自动化任何重复的过程，以便高效利用我们的时间。

但如果我们在一个庞大的团队中工作，一个由内部和离岸资源组成的网络专业人士的大熔炉，也许使用框架会有所帮助。这是因为每个人都需要遵守框架的结构，以确保一切都是一致的。

# 创建自定义 CSS 网格

由于我们正在掌握 RWD，我们有奢侈的创造我们自己的 CSS 网格。然而，我们需要聪明地工作，而不是努力地工作。所以我们要做的是利用*可变网格系统*应用程序，并将其结果与我们自己的方法相结合，制作一个移动优先、流动、自定义构建和坚实的 CSS 网格，从中我们可以创建强大的响应式设计。

让我们列出我们的 CSS 网格需求：

+   它应该有 12 列。

+   它应该是 1200 像素宽，以适应 1280 像素的屏幕。

+   它应该是流体的，使用相对单位（百分比）来定义列和间距。

+   它应该使用移动优先方法。

+   它应该使用 SCSS 语法。

+   它应该可以重复使用在其他项目中。

+   它应该简单易懂。

+   它应该很容易扩展。

这就是我们的 1200 像素宽和 12 列宽 20px 的网格的样子：

![创建自定义 CSS 网格](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_04_00.jpg)

左右两侧的填充都是 10px。我们将在此过程结束时将这 10px 转换为百分比。

## 进行数学计算

我们将使用 RWD 魔法公式：*(目标 ÷ 上下文) x 100 = 结果 %*。

我们的上下文将是 1200px。所以让我们转换一个列：*80 ÷ 1200 x 100 = 6.67%*。

对于两列，我们必须考虑 20px 的间距。换句话说，我们不能说两列确切地是 160px。这并不完全正确。

两列分别是：*80px + 20px + 80px = 180px*。

现在让我们转换两列：*180 ÷ 1200 x 100 = 15%*。

对于三列，现在我们必须考虑两个间距：*80px + 20px + 80px + 20px + 80px = 280px*。

现在让我们转换三列：*280 ÷ 1200 x 100 = 23.33%*。

现在你能看到模式了吗？每次我们添加一列，我们只需要将值增加 100。这个值也包括了间距！

检查我们刚才看到的网格的屏幕截图，你可以看到列的值递增 100。

所以，所有的方程式如下：

```html
1   column:    80 ÷ 1200 x 100 = 6.67%
2   columns:  180 ÷ 1200 x 100 = 15%
3   columns:  280 ÷ 1200 x 100 = 23.33%
4   columns:  380 ÷ 1200 x 100 = 31.67%
5   columns:  480 ÷ 1200 x 100 = 40%
6   columns:  580 ÷ 1200 x 100 = 48.33%
7   columns:  680 ÷ 1200 x 100 = 56.67%
8   columns:  780 ÷ 1200 x 100 = 65%
9   columns:  880 ÷ 1200 x 100 = 73.33%
10  columns:  980 ÷ 1200 x 100 = 81.67%
11  columns: 1080 ÷ 1200 x 100 = 90%
12  columns: 1180 ÷ 1200 x 100 = 98.33%

```

让我们为 12 列网格创建 SCSS：

```html
//Grid 12 Columns
.grid {
    &-1  { width:6.67%; }
    &-2  { width:15%; }
    &-3  { width:23.33%; }
    &-4  { width:31.67%; }
    &-5  { width:40%; }
    &-6  { width:48.33%; }
    &-7  { width:56.67%; }
    &-8  { width:65%; }
    &-9  { width:73.33%; }
    &-10 { width:81.67%; }
    &-11 { width:90%; }
    &-12 { width:98.33%; }
}
```

### 提示

使用连字符（`-`）来分隔单词可以更容易地选择代码编辑时的术语。

## 添加 UTF-8 字符集指令和 Credits 部分

不要忘记在文件顶部包含 UTF-8 编码指令，让浏览器知道我们正在使用的字符集。让我们通过在顶部添加一个 Credits 部分来装饰我们的代码。代码如下：

```html
@charset "UTF-8";

/*
 Custom Fluid & Responsive Grid System
 Structure: Mobile-first (min-width)
 Syntax: SCSS
 Grid: Float-based
 Created by: Your Name
 Date: MM/DD/YY
*/

//Grid 12 Columns
.grid {
    &-1  { width:6.67%; }
    &-2  { width:15%; }
    &-3  { width:23.33%; }
    &-4  { width:31.67%; }
    &-5  { width:40%; }
    &-6  { width:48.33%; }
    &-7  { width:56.67%; }
    &-8  { width:65%; }
    &-9  { width:73.33%; }
    &-10 { width:81.67%; }
    &-11 { width:90%; }
    &-12 { width:98.33%; }
}
```

### 提示

注意 Credits 是用 CSS 样式注释注释的：`/* */`。这种类型的注释，取决于我们如何编译我们的 SCSS 文件，不会被剥离。这样，Credits 总是可见的，这样其他人就知道谁编写了文件。这对团队可能有用，也可能没有。此外，显示 Credits 对文件大小的影响是微不可见的。

## 包括 box-sizing 属性和移动优先 mixin

包括`box-sizing`属性允许浏览器的盒模型考虑容器内的填充；这意味着填充被减去而不是添加，从而保持了定义的宽度。

由于我们的自定义 CSS 网格的结构将是移动优先的，我们需要包括处理这一方面的 mixin：

```html
@charset "UTF-8";

/*
    Custom Fluid & Responsive Grid System
    Structure: Mobile-first (min-width)
    Syntax: SCSS
    Grid: Float-based
    Created by: Your Name
    Date: MM/DD/YY
*/

*, *:before, *:after {
 box-sizing: border-box;
}

//Moble-first Media Queries Mixin
@mixin forLargeScreens($width) {
 @media (min-width: $width/16+em) { @content }
}

//Grid 12 Columns
.grid {
    &-1  { width:6.67%; }
    &-2  { width:15%; }
    &-3  { width:23.33%; }
    &-4  { width:31.67%; }
    &-5  { width:40%; }
    &-6  { width:48.33%; }
    &-7  { width:56.67%; }
    &-8  { width:65%; }
    &-9  { width:73.33%; }
    &-10 { width:81.67%; }
    &-11 { width:90%; }
    &-12 { width:98.33%; }
}
```

## 主容器和将 10px 转换为百分比值

由于我们使用移动优先方法，我们的主容器默认情况下将是 100%宽；但我们还将给它一个最大宽度为 1200px，因为要求是创建这样大小的网格。

我们还将把 10px 转换为百分比值，所以使用 RWD 魔法公式：*10 ÷ 1200 x 100 = 0.83%*。

然而，正如我们之前看到的，10px，或者在这种情况下 0.83%，不足够的填充会使内容看起来离主容器的边缘太近。所以我们将填充增加到 20px：*20 ÷ 1200 x 100 = 1.67%*。

我们还将使用`margin: auto;`来水平居中主容器。

### 提示

没有必要声明零值来使顶部和底部边距水平居中。换句话说，`margin: 0 auto;`是不必要的。只需声明`margin: auto;`就足够了。

现在让我们包括这些值：

```html
@charset "UTF-8";

/*
    Custom Fluid & Responsive Grid System
    Structure: Mobile-first (min-width)
    Syntax: SCSS
    Grid: Float-based
    Created by: Your Name
    Date: MM/DD/YY
*/

*, *:before, *:after {
 box-sizing: border-box;
}

//Moble-first Media Queries Mixin
@mixin forLargeScreens($width) {
 @media (min-width: $width/16+em) { @content }
}

//Main Container
.container-12 {
 width: 100%;
 //Change this value to ANYTHING you want, no need to edit anything else.
 max-width: 1200px;
 padding: 0 1.67%;
 margin: auto;
}

//Grid 12 Columns
.grid {
    &-1  { width:6.67%; }
    &-2  { width:15%; }
    &-3  { width:23.33%; }
    &-4  { width:31.67%; }
    &-5  { width:40%; }
    &-6  { width:48.33%; }
    &-7  { width:56.67%; }
    &-8  { width:65%; }
    &-9  { width:73.33%; }
    &-10 { width:81.67%; }
    &-11 { width:90%; }
    &-12 { width:98.33%; }
}
```

### 提示

在`padding`属性中，如果我们输入`0.83%`或`.83%`都是一样的。我们可以省略零。保持我们的代码尽可能简洁是一种良好的实践。这与当我们使用十六进制简写值时的原理相同：`#3336699`和`#369`是一样的。

## 使其移动优先

在小屏幕上，所有列都将是 100%宽。由于我们使用的是单列布局，我们不使用间距；这意味着我们至少现在不必声明边距。

在 640px 处，网格将启动并为每个列分配相应的百分比，因此我们将在`40em`（640px）媒体查询中包含列并将它们浮动到左侧。在这一点上，我们需要间距。因此，我们声明左右填充为`.83%`。

### 提示

我任意选择了`40em`（640px）作为起点。记住要创建基于内容而不是设备的断点。

代码如下：

```html
@charset "UTF-8";

/*
    Custom Fluid & Responsive Grid System
    Structure: Mobile-first (min-width)
    Syntax: SCSS
    Grid: Float-based
    Created by: Your Name
    Date: MM/DD/YY
*/

*, *:before, *:after {
    box-sizing: border-box;
}

//Moble-first Media Queries Mixin
@mixin forLargeScreens($width) {
    @media (min-width: $width/16+em) { @content }
}

//Main Container
.container-12 {
    width: 100%;
    //Change this value to ANYTHING you want, no need to edit anything else.
    max-width: 1200px;
    padding: 0 1.67%;
    margin: auto;
}

//Grid
.grid {
 //Global Properties - Mobile-first
 &-1, &-2, &-3, &-4, &-5, &-6, &-7, &-8, &-9, &-10, &-11, &-12 {
 width: 100%;
 }
 @include forLargeScreens(640) { //Totally arbitrary width, it's only a starting point.
 //Global Properties - Large screens
 &-1, &-2, &-3, &-4, &-5, &-6, &-7, &-8, &-9, &-10, &-11, &-12 {
 float: left;
 margin: 0 .83%;
 }
 //Grid 12 Columns
 .grid {
 &-1  { width:6.67%; }
 &-2  { width:15%; }
 &-3  { width:23.33%; }
 &-4  { width:31.67%; }
 &-5  { width:40%; }
 &-6  { width:48.33%; }
 &-7  { width:56.67%; }
 &-8  { width:65%; }
 &-9  { width:73.33%; }
 &-10 { width:81.67%; }
 &-11 { width:90%; }
 &-12 { width:98.33%; }
 }
}

```

## 添加行和浮动清除规则

如果我们在 HTML 结构中使用行或向标签添加`.clear`类，我们可以在单个嵌套规则中使用`:before`和`:after`伪元素声明所有的浮动清除值。

### 提示

在声明伪元素时，使用单冒号或双冒号是一样的。双冒号是 CSS3 语法，单冒号是 CSS2.1 语法。这个想法是为了能够一眼区分它们，以便开发人员可以知道它们是在哪个 CSS 版本上编写的。然而，IE8 及以下版本不支持双冒号语法。

浮动清除技术是对 David Walsh 的 CSS 片段的改编（[`davidwalsh.name/css-clear-fix`](http://davidwalsh.name/css-clear-fix)）。

我们还为行添加了一个底部间距为 10px 的规则，以便将它们彼此分开，同时从最后一行中去除该间距，以避免在底部创建不必要的额外间距。最后，我们为旧版 IE 添加了清除规则。

现在让我们包括这些规则：

```html
@charset "UTF-8";

/*
    Custom Fluid & Responsive Grid System
    Structure: Mobile-first (min-width)
    Syntax: SCSS
    Grid: Float-based
    Created by: Your Name
    Date: MM/DD/YY
*/

*, *:before, *:after {
    box-sizing: border-box;
}

//Moble-first Media Queries Mixin
@mixin forLargeScreens($width) {
    @media (min-width: $width/16+em) { @content }
}

//Main Container
.container-12 {
    width: 100%;
    //Change this value to ANYTHING you want, no need to edit anything else.
    max-width: 1200px;
    padding: 0 1.67%;
    margin: auto;
}

//Grid
.grid {
    //Global Properties - Mobile-first
    &-1, &-2, &-3, &-4, &-5, &-6, &-7, &-8, &-9, &-10, &-11, &-12 {
        width: 100%;
    }
    @include forLargeScreens(640) { //Totally arbitrary width, it's only a starting point.
    //Global Properties - Large screens
    &-1, &-2, &-3, &-4, &-5, &-6, &-7, &-8, &-9, &-10, &-11, &-12 {
        float: left;
        margin: 0 .83%;
    }
    //Grid 12 Columns
    .grid {
        &-1  { width:6.67%; }
        &-2  { width:15%; }
        &-3  { width:23.33%; }
        &-4  { width:31.67%; }
        &-5  { width:40%; }
        &-6  { width:48.33%; }
        &-7  { width:56.67%; }
        &-8  { width:65%; }
        &-9  { width:73.33%; }
        &-10 { width:81.67%; }
        &-11 { width:90%; }
        &-12 { width:98.33%; }
    }
}

//Clear Floated Elements - http://davidwalsh.name/css-clear-fix
.clear, .row {
 &:before,
 &:after { content: ''; display: table; }
 &:after { clear: both; }
}

//Use rows to nest containers
.row { margin-bottom: 10px;
 &:last-of-type { margin-bottom: 0; }
}

//Legacy IE
.clear { zoom: 1; }

```

让我们回顾一下我们的 CSS 网格要求：

+   **12 列**：从`.grid-1`到`.grid-12`。

+   **为了适应 1280px 屏幕而设置为 1200px 宽**：`.container-12`容器的`max-width: 1200px;`

+   **流动和相对单位（百分比）用于列和间距**：百分比从 6.67%到 98.33%。

+   **移动优先**：我们添加了移动优先的 mixin（使用`min-width`）并将网格嵌套其中。

+   **SCSS 语法**：整个文件都是基于 Sass 的。

+   **可重用**：只要我们使用 12 列并且使用移动优先的方法，我们可以多次使用这个 CSS 网格。

+   **简单易用和理解**：类名非常直观。`.grid-6`网格用于跨越 6 列的元素，`.grid-7`用于跨越 7 列的元素，依此类推。

+   **易于扩展**：如果我们想使用 980px 而不是 1200px，我们只需要改变`.container-12 max-width`属性中的值。由于所有元素都使用相对单位（百分比），一切都会按比例适应新的宽度 - 无论是*任何*宽度。如果你问我，这真是太棒了。

# 使用自定义 CSS 网格构建示例页面

这是我们在这个例子中将要使用的 HTML：

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Mastering RWD with HTML5 &amp; CSS3</title>
    <link rel="stylesheet" href="css/site-styles.css">
    <!--[if lt IE 9]>
    <script src="img/html5.js">
	</script>
    <![endif]-->
</head>
<body>
    <h1>Basic Layout Using a Custom CSS Grid</h1>
    <main class="container-12 clear" role="main">
    <header class="grid-12" role="banner">Header (.grid-12)</header>
        <nav class="grid-4" role="navigation">Nav (.grid-4)</nav>
        <section class="grid-8">
          <div class="row">
              <div class="grid-6 black">.grid-6</div>
              <div class="grid-6 black">.grid-6</div>
          </div>
          <div class="row">
              <div class="grid-4 black">.grid-4</div>
              <div class="grid-4 black">.grid-4</div>
              <div class="grid-4 black">.grid-4</div>
          </div>
          <div class="row">
              <div class="grid-3 black">.grid-3</div>
              <div class="grid-3 black">.grid-3</div>
              <div class="grid-3 black">.grid-3</div>
              <div class="grid-3 black">.grid-3</div>
          </div>
          <div class="row">
              <div class="grid-2 black">.grid-2</div>
              <div class="grid-7 black">.grid-7</div>
              <div class="grid-3 black">.grid-3</div>
          </div>
          <p>Content (.grid-8)</p>
        </section>
    <footer class="grid-12" role="contentinfo">Footer (.grid-12)</footer>
    </main>
</body>
```

## 嵌套容器

请注意，有几个嵌套容器在它们自己的行内（黑色背景）。这里的想法是突出显示添加到 12 列的嵌套内容部分。

嵌套列是任何网格系统的主要优势。在这本书中，我们正在利用这种力量，以便不会以任何方式限制设计。

### 提示

我们使用 HTML5 Shiv polyfill 为 IE8 及以下版本添加 HTML5 支持。

在小屏幕上（320px 宽），容器如下所示：

![嵌套容器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_04_01.jpg)

在宽度为 40em（640px）及以上的大屏幕上，布局如下：

![嵌套容器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_04_02.jpg)

您可以在 CodePen 上看到我创建的演示[`codepen.io/ricardozea/pen/d6ab6e0293be9b6bac2e16ad37942ed5`](http://codepen.io/ricardozea/pen/d6ab6e0293be9b6bac2e16ad37942ed5)。

# 停止使用 CSS 网格，使用 Flexbox！

我打赌你没有看到这一点，哈！

事实上，Flexbox 是一种令人惊奇的 CSS 属性，它为布局提供了新的可能性。以下是关于 Flexbox 的一些事情：

+   它在现代浏览器中的浏览器支持是完美的。

+   IE8 和 IE9 不支持它。但不用担心，使用条件类技术来解决这两个浏览器非常简单，如第三章中提到的，*Mobile-first or Desktop-first?*

+   IE10 仅支持 2012 语法，但 Autoprefixer（在 Prepros 中）会自动为我们处理这些旧的供应商前缀。

+   在使用 Flexbox 时，我们需要小心，因为旧的`display: box;`语法会导致浏览器在布局中进行多次传递，从而降低性能。

+   相比之下，新/当前的语法`display: flex`;对性能没有任何影响。自从旧语法以来，浏览器性能问题现在已得到解决，所以我们应该没问题。

### 提示

Paul Irish 和 Ojan Vafai 在文章**Flexbox layout isn't slow**中对此进行了很好的解释，该文章可以在[`updates.html5rocks.com/2013/10/Flexbox-layout-isn-t-slow`](http://updates.html5rocks.com/2013/10/Flexbox-layout-isn-t-slow)找到。

让我们开始吧，好吗？

## 使用 Flexbox 构建示例页面

在下面的示例中，我们将使用 Flexbox 属性构建与使用自定义 CSS 网格构建的相同布局。这将帮助我们更好地理解 Flexbox 的强大之处，并最终*摆脱*完全使用 CSS 网格，同时在我们的 HTML 中保持更语义化的结构。

### 提示

Chris Coyer 的一篇很棒的文章**A Complete Guide to Flexbox**可以在[`css-tricks.com/snippets/css/a-guide-to-flexbox/`](https://css-tricks.com/snippets/css/a-guide-to-flexbox/)找到。

关于示例页面的一些注意事项：

+   我们在`<html>`元素中包含条件类，以支持旧版浏览器，并避免使用 JavaScript 文件依赖项从服务器请求。

+   由于我们不使用 CSS 网格，嵌套容器只会在其中显示术语**Content**。

+   我们将使用 HTML5 Shiv polyfill 来支持 IE8 对所有必要的 HTML5 标签。

+   由于 IE10 在 Flexbox 中存在一些数学计算问题，我们需要通过在`<html>`元素中添加`.ie10`类来定位它。我们将使用 Louis Lazaris 创建的一个简单脚本来实现这一点，该脚本位于 IE 排除条件注释中，以便 IE8/9 不运行该脚本。有关此脚本的所有信息可以在文章中找到：[`www.impressivewebs.com/ie10-css-hacks/`](http://www.impressivewebs.com/ie10-css-hacks/)。

### 提示

我们用于定位 IE10 的脚本不使用用户代理嗅探。UA 嗅探不被认为是一个好的做法。该脚本使用条件编译语句。有关`@cc_on`语句的更多信息可以在**Microsoft Developer Network** (**MSDN**)找到：[`msdn.microsoft.com/en-us/library/8ka90k2e(v=vs.94).aspx`](https://msdn.microsoft.com/en-us/library/8ka90k2e(v=vs.94).aspx)。

这是小屏幕（320px 宽）上 Flexbox 布局的样子：

![使用 Flexbox 构建示例页面](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_04_03.jpg)

这是大屏幕上的样子。这个屏幕宽度为 768px，但内容为`40em`（640px）：

![使用 Flexbox 构建示例页面](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_04_04.jpg)

### HTML

这是我们将在示例页面中使用的标记：

```html
<!DOCTYPE html>
<!--[if IE 8]> <html class="no-js ie8" lang="en"> <![endif]-->
<!--[if IE 9]> <html class="no-js ie9" lang="en"> <![endif]-->
<!--[if gt IE 9]><!--><html class="no-js" lang="en"><!--<![endif]-->
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Basic Layout Using Flexbox</title>
    <!--[if lt IE 9]>
      <script src="img/html5.js">
	  </script>
    <![endif]-->
	<!--[if !IE]><!-->
      <script>
        if (/*@cc_on!@*/false && document.documentMode === 10) {
          document.documentElement.className+=' ie10';
        }
      </script>
    <!--<![endif]-->
</head>
<body>
    <h1>Basic Layout Using Flexbox</h1>
    <main class="main-container" role="main">
        <header role="banner">Header</header>
        <!-- Flexible elements need to be wrapped in a container -->
        <div class="flex-container">
            <nav role="navigation">Nav</nav>
            <section>
                <div class="flex-container row-1">
                    <div class="level-1">content</div>
                    <div class="level-1">content</div>
                </div>
                <div class="flex-container row-2">
                    <div class="level-1">content</div>
                    <div class="level-1">content</div>
                    <div class="level-1">content</div>
                </div>
                <div class="flex-container row-3">
                    <div class="level-1">content</div>
                    <div class="level-1">content</div>
                    <div class="level-1">content</div>
                    <div class="level-1">content</div>
                </div>
                <div class="flex-container row-4">
                    <div class="level-1 content-a">content</div>
                    <div class="level-1 content-b">">content</div>
                    <div class="level-1 content-c">content</div>
                </div>
                <p>Content</p>
            </section>
        </div>
        <footer role="contentinfo">Footer</footer>
    </main>
</body>
</html>
```

### SCSS

SCSS 代码有几个部分与 CSS 网格中使用的代码类似。但是，有重要的区别。

让我们来分析一下。

我们将从创建 Credits 部分开始，`box-sizing: border-box;`参数用于考虑容器内部而不是外部的填充，首先是移动优先的 mixin 和主容器属性：

```html
/*
    Custom Fluid & Responsive Grid System
    Structure: Mobile-first (min-width)
    Syntax: SCSS
    Grid: Flexbox-based
    Created by: Your Name
    Date: MM/DD/YY
*/
*, *:before, *:after {
  box-sizing: border-box;
}
//Moble-first Media Queries Mixin
@mixin forLargeScreens($media) {
    @media (min-width: $media/16+em) { @content }
}
//Main container
.main-container {
    width: 100%;
    //Change this value to ANYTHING you want, no need to edit anything else
    max-width: 1200px;
    //Any value you want
    padding: 0 1.67%;
    margin: auto;
}
```

### 添加 Flexbox 容器

现在，让我们为 Flexbox 容器添加属性，该容器在某种程度上类似于 CSS 网格中的`.row`。代码如下：

```html
/*
    Custom Fluid & Responsive Grid System
    Structure: Mobile-first (min-width)
    Syntax: SCSS
    Grid: Flexbox-based
    Created by: Your Name
    Date: MM/DD/YY
*/
*, *:before, *:after {
    box-sizing: border-box;
}
//Moble-first Media Queries Mixin
@mixin forLargeScreens($media) {
    @media (min-width: $media/16+em) { @content }
}
//Main container
.main-container {
    width: 100%;
  //Change this value to ANYTHING you want, no need to edit anything else
    max-width: 1200px;
    //Any value you want
    padding: 0 1.67%;
    margin: auto;
}
//Flexbox container
.flex-container {
 margin-bottom: 10px;
 //Remove the margin from the last flexbox container
 &:last-of-type {
 margin-bottom: 0;
 }
 @include forLargeScreens(640) {
 display: flex;
 }
}

```

正如你所看到的，我们添加了`margin-bottom: 10px;`来分隔内容行。然而，我们在最后一个 Flexbox 容器上移除了该边距，以防止在末尾产生不必要的额外填充。

然后，我们将包含针对 640px（`40em`）屏幕宽度的移动优先 mixin。这意味着我们**只**会在大屏幕上使用 Flexbox，但在小屏幕上，我们不会使用它。

### 提示

如果所有列的宽度相等，则无需使用 Flexbox。在我们的示例中，小屏幕上的列宽度为 100%。

#### Flexbox 容器内的 DIV

现在，让我们在大屏幕上为列添加`.83%`的左右边距。在小屏幕上，列没有边距。记住*10px = 0.83%*。

我们将使用带有星号/星号的属性选择器，以便可以针对所有包含类名中至少一个值为`level-`的 DIV 进行定位。我们还将删除第一个容器的左边距和最后一个容器的右边距，以便我们的 DIV 与其父容器的边缘对齐。代码如下：

```html
/*
    Custom Fluid & Responsive Grid System
    Structure: Mobile-first (min-width)
    Syntax: SCSS
    Grid: Flexbox-based
    Created by: Your Name
    Date: MM/DD/YY
*/
*, *:before, *:after {
    box-sizing: border-box;
}
//Moble-first Media Queries Mixin
@mixin forLargeScreens($media) {
    @media (min-width: $media/16+em) { @content }
}
//Main container
.main-container {
    width: 100%;
    //Change this value to ANYTHING you want, no need to edit anything else
    max-width: 1200px;
    //Any value you want
    padding: 0 1.67%;
    margin: auto;
}
//Flexbox container
.flex-container {
    margin-bottom: 10px;
    //Remove the margin from the last flexbox container
    &:last-of-type {
        margin-bottom: 0;
    }
    @include forLargeScreens(640) {
        display: flex;
    }
}
//DIVs inside the flex container
[class*="level-"] {
 width: 100%;
 @include forLargeScreens(640) {
 margin: 0 .83%;
 }
 &:first-of-type { margin-left: 0; }
 &:last-of-type { margin-right: 0; }
}

```

### 标题、页脚、导航和部分容器

现在，标题和页脚部分在小屏幕和大屏幕上都是 100%宽，因此它们不需要任何特定的规则。然而，这个示例为标题和页脚部分添加了一些属性，但只是出于样式原因，而不是布局原因。尽管如此，导航和部分容器确实根据可用屏幕宽度具有特定的宽度。

在小屏幕上，导航和部分容器的宽度为 100%，而在大屏幕上它们并排显示；导航容器在大屏幕上宽度为 33%，右边距为 1.67%（相当于 20px）以创建间距。部分容器在大屏幕上宽度为 65.33%。这里是公式：*33% + 1.67% + 65.33 = 100%*。

让我们继续为导航和部分容器定义这些属性：

```html
/*
    Custom Fluid & Responsive Grid System
    Structure: Mobile-first (min-width)
    Syntax: SCSS
    Grid: Flexbox-based
    Created by: Your Name
    Date: MM/DD/YY
*/
*, *:before, *:after {
    box-sizing: border-box;
}
//Moble-first Media Queries Mixin
@mixin forLargeScreens($media) {
    @media (min-width: $media/16+em) { @content }
}
//Main container
.main-container {
    width: 100%;
    //Change this value to ANYTHING you want, no need to edit anything else
    max-width: 1200px;
    //Any value you want
    padding: 0 1.67%;
    margin: auto;
}
//Flexbox container
.flex-container {
    margin-bottom: 10px;
    //Remove the margin from the last flexbox container
    &:last-of-type {
        margin-bottom: 0;
    }
    @include forLargeScreens(640) {
        display: flex;
    }
}
//DIVs inside the flex container
[class*="level-"] {
 width: 100%;
 @include forLargeScreens(640) {
 margin: 0 .83%;
 }
 &:first-of-type { margin-left: 0; }
 &:last-of-type { margin-right: 0; }
}
//Nav
nav {
 width: 100%;
 @include forLargeScreens(640) {
 width: 33%;
 margin-right: 1.67%;
 }
}
//Content area
section {
 width: 100%;
 @include forLargeScreens(640) {
 width: 65.33%;
 }
}

```

### 嵌套容器

最后，对于这个示例，我们将为具有黑色背景的不同内容部分定义宽度，这样你就可以清楚地了解如何嵌套容器。

基本上，我们正在为该行的第一个和第三个内容区域`.content-a`和`.content-c`分配特定但不同的宽度。除非我们想要，否则不需要为第二个内容区域分配宽度。Flexbox 将使第二个容器完全占据第一个和第三个内容区域之间的所有剩余空间。

### 提示

IE10 在计算嵌套容器值时存在问题，因此我们需要为这些容器创建特定的宽度。我们将在为 IE8 和 IE9 创建的同一规则中包含 IE10 的宽度。

我使用任意值如 30%和 42%是为了向你展示，我们可以随意调整这些值，而 Flexbox 会尽量保持这些比例，只要有空间可用。

现在让我们为不同的嵌套容器添加这些属性：

```html
/*
    Custom Fluid & Responsive Grid System
    Structure: Mobile-first (min-width)
    Syntax: SCSS
    Grid: Flexbox-based
    Created by: Your Name
    Date: MM/DD/YY
*/
*, *:before, *:after {
    box-sizing: border-box;
}
//Moble-first Media Queries Mixin
@mixin forLargeScreens($media) {
    @media (min-width: $media/16+em) { @content }
}
.main-container {
    //Change this value to ANYTHING you want, no need to edit anything else.
    width: 100%;
    max-width: 1200px;
    //Any value you want
    padding: 0 1.67%;
    margin: auto;
}
//Flexbox container
.flex-container {
    margin-bottom: 10px;
    //Remove the margin from the last flexbox container
    &:last-of-type {
        margin-bottom: 0;
    }
    @include forLargeScreens(640) {
        display: flex;
    }
}
//DIVs inside the flex container
[class*="level-"] {
 width: 100%;
 @include forLargeScreens(640) {
 margin: 0 .83%;
 }
 &:first-of-type { margin-left: 0; }
 &:last-of-type { margin-right: 0; }
}
//Nav
nav {
 width: 100%;
 @include forLargeScreens(640) {
 width: 33%;
 margin-right: 1.67%;
 }
}
//Content area
section {
 width: 100%;
 @include forLargeScreens(640) {
 width: 65.33%;
 }
}
//Different width containers
.content- {
 @include forLargeScreens(640) {
 &a { width: 30%; }
 &c { width: 42%; }
 }
}

```

### 支持旧版 IE

使用 Flexbox 也会带来与 IE8、IE9 和 IE10 相关的注意事项。

与传统浏览器一样，调整数值并进行测试是获得最佳结果的关键。记住，网站在每个浏览器中不必看起来完全相同。

让我们澄清一些事情。类`.ie8`和`.ie9`来自`<html>`元素中的条件类。类`.ie10`来自 IE 排除条件注释中的脚本。因此，IE8 和 IE9 无法运行此脚本。但不用担心，解决方案很简单，你会看到的。让我们来看看它们。

#### 一条规则支配所有规则

我们首先要做的是为 IE8、IE9 和 IE10 创建一个规则。在这个规则中，我们将以百分比声明嵌套容器的宽度。事实上，我们也可以用像素声明这些宽度，但出于一致性的原因，我们将使用百分比，与所有其他响应式示例保持一致。

这就是那条规则……好吧，支配它们所有：

```html
/*
    Custom Fluid & Responsive Grid System
    Structure: Mobile-first (min-width)
    Syntax: SCSS
    Grid: Flexbox-based
    Created by: Your Name
    Date: MM/DD/YY
*/
*, *:before, *:after {
    box-sizing: border-box;
}
//Moble-first Media Queries Mixin
@mixin forLargeScreens($media) {
    @media (min-width: $media/16+em) { @content }
}
.main-container {
    //Change this value to ANYTHING you want, no need to edit anything else.
    width: 100%;
    max-width: 1200px;
    //Any value you want
    padding: 0 1.67%;
    margin: auto;
}
//Flexbox container
.flex-container {
    margin-bottom: 10px;
    //Remove the margin from the last flexbox container
    &:last-of-type {
        margin-bottom: 0;
    }
    @include forLargeScreens(640) {
        display: flex;
    }
}
//DIVs inside the flex container
[class*="level-"] {
    width: 100%;
    @include forLargeScreens(640) {
        margin: 0 .83%;
    }
    &:first-of-type { margin-left: 0; }
    &:last-of-type { margin-right: 0; }
}
//Nav
nav {
    width: 100%;
    @include forLargeScreens(640) {
        width: 33%;
        margin-right: 1.67%;
    }
}
//Content area
section {
    width: 100%;
    @include forLargeScreens(640) {
        width: 65.33%;
    }

}
//Different width containers
.content- {
    @include forLargeScreens(640) {
        &a { width: 30%; }
        &c { width: 42%; }
    }
}
//All IEs
.ie8, .ie9, .ie10 {
 //Exact values (desired width − 0.83% = result %) are commented, but they need tweaked to have one value for all IEs
 section {
 .row-1 .level-1 { width: 49.17%; }
 //Exact value is 32.17%
 .row-2 .level-1 { width: 32.20%; }
 //Exact value is 24.17%
 .row-3 .level-1 { width: 23.75%; }
 .row-4 {
 .content-a { width: 19.17%; }
 .content-b { width: 49.17%; }
 //Exact value is 29.17%
 .content-c { width: 28.3%; }
 }
 }
}

```

#### IE8 和 IE9 的规则

我们现在将声明处理 IE8 和 IE9 值的规则。我们声明`overflow: hidden;`来清除父容器中的浮动，即`.flex-container` DIVs。然后我们将 Nav 和 Content 部分浮动到左侧，并给它们一个高度；这个高度仅用于样式目的。

我们给 Nav 部分设置宽度和右边距为 1%，以保持简洁。我们也给 Content 部分分配了宽度。然后，我们使用 Footer 来清除浮动的 Nav 和 Content 部分，使用`clear: both;`和`zoom: 1;`参数以确保。

以下是 IE8/9 的 SCSS：

```html
/*
    Custom Fluid & Responsive Grid System
    Structure: Mobile-first (min-width)
    Syntax: SCSS
    Grid: Flexbox-based
    Created by: Your Name
    Date: MM/DD/YY
*/
*, *:before, *:after {
    box-sizing: border-box;
}
//Moble-first Media Queries Mixin
@mixin forLargeScreens($media) {
    @media (min-width: $media/16+em) { @content }
}
.main-container {
    //Change this value to ANYTHING you want, no need to edit anything else.
    width: 100%;
    max-width: 1200px;
    //Any value you want
    padding: 0 1.67%;
    margin: auto;
}
//Flexbox container
.flex-container {
    margin-bottom: 10px;
    //Remove the margin from the last flexbox container
    &:last-of-type {
        margin-bottom: 0;
    }
    @include forLargeScreens(640) {
        display: flex;
    }
}
//DIVs inside the flex container
[class*="level-"] {
    width: 100%;
    @include forLargeScreens(640) {
        margin: 0 .83%;
    }
    &:first-of-type { margin-left: 0; }
    &:last-of-type { margin-right: 0; }
}
//Nav
nav {
    width: 100%;
    @include forLargeScreens(640) {
        width: 33%;
        margin-right: 1.67%;
    }
}
//Content area
section {
    width: 100%;
    @include forLargeScreens(640) {
        width: 65.33%;
    }
}
//Different width containers
.content- {
    @include forLargeScreens(640) {
        &a { width: 30%; }
        &c { width: 42%; }
    }
}
//All IEs
.ie8, .ie9, .ie10 {
    //Exact values (desired width − 0.83% = result %) are commented, but they need tweaked to have one value for all IEs
    section {
        .row-1 .level-1 { width: 49.17%; }
        //Exact value is 32.17%
        .row-2 .level-1 { width: 32.20%; }
        //Exact value is 24.17%
        .row-3 .level-1 { width: 23.75%; }
        .row-4 {
          .content-a { width: 19.17%; }
          .content-b { width: 49.17%; }
          //Exact value is 29.17%
          .content-c { width: 28.3%; }
        }
    }
}
//IE8/9
.ie8, .ie9 {
 .flex-container { overflow: hidden; }
 nav, section { float: left; min-height: 440px; }
 nav { width: 29%; margin-right: 1%; }
 section { width: 70%; }
 footer { clear: both; zoom: 1; }
}

```

#### IE8 和 IE9 的特定规则

最后，我们通过一些规则来解决旧版浏览器的问题：为 IE8 制定一条规则，为 IE9 使用属性选择器制定另一条规则，适用于所有嵌套容器。

对于 IE8，我们给嵌套容器`display: inline-block;`而不是`float: left;`，以使嵌套容器的组在相应的行中居中。如果我们不这样做，所有行的右侧将会出现奇怪的间隙。我们还将声明左右边距为.2%。经过测试，任何更大的值都会使嵌套容器换行。

对于 IE9，我们将把嵌套容器浮动到左侧。

让我们来看看这两条规则：

```html
/*
  Custom Fluid & Responsive Grid System
    Structure: Mobile-first (min-width)
    Syntax: SCSS
    Grid: Flexbox-based
    Created by: Your Name
    Date: MM/DD/YY
*/
*, *:before, *:after {
    box-sizing: border-box;
}
//Moble-first Media Queries Mixin
@mixin forLargeScreens($media) {
    @media (min-width: $media/16+em) { @content }
}
.main-container {
    //Change this value to ANYTHING you want, no need to edit anything else.
    width: 100%;
    max-width: 1200px;
    //Any value you want
    padding: 0 1.67%;
    margin: auto;
}
//Flexbox container
.flex-container {
    margin-bottom: 10px;
    //Remove the margin from the last flexbox container
    &:last-of-type {
        margin-bottom: 0;
    }
  @include forLargeScreens(640) {
        display: flex;
    }
}
//DIVs inside the flex container
[class*="level-"] {
    width: 100%;
    @include forLargeScreens(640) {
        margin: 0 .83%;
    }
    &:first-of-type { margin-left: 0; }
    &:last-of-type { margin-right: 0; }
}
//Nav
nav {
    width: 100%;
    @include forLargeScreens(640) {
        width: 33%;
        margin-right: 1.67%;
    }
}
//Content area
section {
    width: 100%;
    @include forLargeScreens(640) {
        width: 65.33%;
    }
}
//Different width containers
.content- {
    @include forLargeScreens(640) {
        &a { width: 30%; }
        &c { width: 42%; }
    }
}
//All IEs
.ie8, .ie9, .ie10 {
    //Exact values (desired width − 0.83% = result %) are commented, but they need tweaked to have one value for all IEs
    section {
        .row-1 .level-1 { width: 49.17%; }
        //Exact value is 32.17%
        .row-2 .level-1 { width: 32.20%; }
        //Exact value is 24.17%
        .row-3 .level-1 { width: 23.75%; }
        .row-4 {
          .content-a { width: 19.17%; }
          .content-b { width: 49.17%; }
          //Exact value is 29.17%
          .content-c { width: 28.3%; }
        }
    }
}
//IE8/9
.ie8, .ie9 {
    .flex-container { overflow: hidden; }
    nav, section { float: left; min-height: 440px; }
    nav { width: 29%; margin-right: 1%; }
    section { width: 70%; }
    footer { clear: both; zoom: 1; }
}
//IE8
.ie8 {
 [class*="level-"] {
 display: inline-block;
 margin: 0 .2%;
 }
}
//IE9
.ie9 {
 [class*="level-"] { float: left; }
}

```

# 总结

在这一章中有很多内容需要消化，是吧？

然而，我们现在知道什么是网格，以及它的用途，这是我们许多人以前从未真正质疑过的东西。我们还更加了解 CSS 网格、CSS 框架和 UI 工具包；尽管你愿意使用它们，只要你清楚它们如何帮助我们在构建响应式网站和应用程序时更加高效。

使用传统的*浮动*技术创建我们的自定义 CSS 是一种识别模式的问题，其中添加新列只是通过增加 100 的值。现在，我们可以在任何宽度上创建一个 12 列网格。

借助 Flexbox，我们现在明白了响应式和流动布局的未来在哪里。由于有如此出色的浏览器支持，毫无疑问 Flexbox 是传统 CSS 网格的一个重要竞争者。在旧版浏览器中，使用条件类是支持复杂布局的一个不错的选择。此外，对于 IE10，我们需要使用条件编译脚本，只有 IE10 才能看到。因此，我们可以使用`.ie10`特定选择器来针对 IE10。

在下一章中，当我们谈论为小屏幕上的大手指构建响应式界面时，我们将深入了解可用性和用户体验的世界。是时候来测试那些大手指了！
