# 精通响应式 Web 设计（三）

> 原文：[`zh.annas-archive.org/md5/14CB11AB973C4F1BAA6102D9FEAB3F3B`](https://zh.annas-archive.org/md5/14CB11AB973C4F1BAA6102D9FEAB3F3B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：设计由大手指驱动的小 UI

触摸屏设备的普及并不新鲜，对于我们——网络/移动设计师和开发人员来说。因此，我们不会谈论市场份额、统计数据或分析数字。相反，我们将讨论我们需要考虑的事项，如目标大小、导航模式、导航图标、最佳实践和移动设备人体工程学。

在本章中，我们将涵盖以下主题：

+   小 UI 上的理想目标大小。

+   姿势模式和触摸区域。

+   RWD 需要考虑的基本准则。

+   RWD 的导航模式。

# 小 UI 上的理想目标大小

所有供应商对小屏幕设备上理想目标大小的规则和指南都有不同的集合。其中一些是以像素表示这些尺寸，其他的是以点表示，还有一些是以英寸、毫米或厘米为单位。

无论这些供应商使用的单位是什么，他们都同意一个基本概念：使目标大小足够大，以避免意外点击。这与菲茨定律相一致，该定律规定*目标越小，用户到达目标所需的时间就越长*。

显然，作为网页设计师，我们必须注意在我们的设计中*大*意味着什么，因此我们需要平衡目标大小的建议与良好的设计原则。我们的目标是让消息传达给用户，并且他们应该能够舒适地使用我们的界面。

需要记住的一件事是，RWD 的目标大小指南大多基于移动应用程序设计模式。让我们直奔主题。

成年人食指的平均宽度约为 16 毫米至 20 毫米。这接近 45px 至 57px。

根据*苹果的 iOS 人机界面指南*，推荐的最小目标大小为 44pt x 44pt。

### 提示

一些用户界面指南使用点和毫米作为测量单位的原因是为了提供一个与设备无关的一致比例尺。这是因为一个设备中的 1px 在另一个设备中不一定意味着确切的 1px。尽管如此，一些供应商确实提供了像素的指南，但主要是为了让我们了解元素的比例关系。

在过去，苹果确实建议他们的目标大小以像素为单位，44px x 44px，但当引入视网膜显示屏时，iPhone 3 的 1 像素变成了 iPhone 4 上的 4 像素。不再是 1:1 的比例。

这意味着在非视网膜设备上，44pt x 44pt 实际上是 44px x 44px，但在视网膜设备上是 88px x 88px。每次苹果发布具有更高密度屏幕的新设备时，这些像素值都会再次改变。

在 RWD 世界中，对于苹果设备或任何设备的屏幕密度有很好的理解是必不可少的。这样，我们在创建设计时总是可以考虑到这些技术细节，以免妨碍用户体验和我们网站和应用的可用性。

另一方面，*微软的 Windows 8 触摸指导*文档建议理想的目标大小为 7 毫米 x 7 毫米（40px x 40px）。如果准确性至关重要，例如关闭或删除，*Windows 8 触摸指导*指南建议目标大小为 9 毫米 x 9 毫米（50px x 50px）。此外，当屏幕空间有限且需要适应时，最小推荐的目标大小为 5 毫米 x 5 毫米（30px x 30px）。

这些尺寸适用于非高密度屏幕。

*Windows 8 触摸指导*指南甚至建议元素之间的最小填充：2 毫米（10px），无论目标大小如何（这很好）。

*Android 开发者*指南建议最小目标大小为 48dp，约为 9 毫米。推荐的最小和最大目标大小分别为 7 毫米和 10 毫米。

Android 开发者指南还建议元素之间的最小间距为 8dp。

### 提示

在这里，**dp**表示密度无关像素。这意味着在*正常*密度屏幕上，1dp 与 1px 相同。就像苹果使用点（pt）一样，他们试图定义一个全球和屏幕密度无关的单位。

还有*Ubuntu*文档建议界面元素不应小于 1 厘米（约 55px）。

正如我们所看到的，推荐的最小和最大目标尺寸因供应商而异。但它们之间的差距并不大。

我们可以从提到的所有目标尺寸中得出结论，即适当的尺寸为（在低密度屏幕上）：

+   推荐的目标尺寸为 48dp×48dp = 48px×48px。

+   最小目标尺寸为 5 毫米×5 毫米= 30px×30px。

+   最大目标尺寸为 10 毫米×10 毫米= 55px×55px。

+   任何元素之间的填充为 2 毫米= 10px。

# 姿势模式和触摸区域

无论我们的触摸目标的尺寸有多可用，如果它们没有放置在正确的位置，我们所有的努力基本上都是无用的。

我们不能谈论小型 UI 和大手指而不提到 Luke Wroblewski 在他的文章《响应式导航：优化跨设备触摸》中的广泛工作（[`www.lukew.com/ff/entry.asp?1649`](http://www.lukew.com/ff/entry.asp?1649)）。

## 姿势模式

在他的文章中，Luke 谈到了大多数用户在握住智能手机、平板电脑和触摸笔记本电脑时的姿势模式：

![姿势模式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_01.jpg)

这些模式使我们能够定义布局内容的最佳方式，以便易于使用和访问。

了解用户的姿势模式将使我们能够了解我们的目标何时可以是正确的大小，甚至如果屏幕空间不足，则可以略小一些，或者如果需要精度，则可以略大一些，因为当有人使用大拇指时与使用食指时是不同的。

## 触摸区域

Luke 还谈到了“触摸区域”，基本上是设备上易于或难以触及的区域，这取决于姿势。

在所有主要类型的设备（智能手机、平板电脑和触摸笔记本电脑）中，理想的触摸区域为深绿色，*ok*触摸区域为浅绿色，难以触及的区域为黄色：

![触摸区域](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_02.jpg)

在 RWD 中，要彻底改变单个页面的布局，更不用说许多页面（至少目前还没有）像独立的应用程序那样，需要大量的工作。此外，有很高的可能性会对用户体验产生负面影响，并保持内容层次结构。

RWD 与内容策略密切相关，因此无论我们的网站/应用程序在哪种设备上查看，都需要保留内容层次结构。我们需要确保元素本身足够大，以便大手指的人能够正确使用。这些元素包括链接、按钮、表单字段、导航项、任何类型的控件（如分页、手风琴中的展开/折叠控件、选项卡系统等）。

现在，在 RWD 中非常多用途的一个网站/应用程序元素是菜单按钮。

为了触发导航，有一个非常特殊的元素，UX 社区对此有非常强烈的意见：*汉堡*图标（≡）。目前，我们将称其为更通用的名称：*导航*图标。我将其称为*导航*图标，因为它不一定是汉堡图标/图形，它可以是另一种类型的图标或一个词。

导航图标的位置、行为和设计以及导航项本身的变化与设计师的数量一样多。对其他人有效的方法未必对我们有效，反之亦然。因此，测试成为决定用户感觉舒适的方法。

尽管如此，有一些导航图标的 UX 指南值得一提，我们将在接下来看到。

# 导航图标- RWD 要考虑的基本指南

导航图标可以用许多方式表示。响应式网页设计从移动应用中借鉴了模式，因为小屏幕应用和网站有许多相似的隐喻。

让我们来看看常见的导航图标模式：

+   汉堡包图标。

+   单词“菜单”。

+   汉堡包图标加上单词“菜单”。

## 汉堡包图标

这是迄今为止最流行的用于表示导航按钮的图标：≡。

汉堡包图标是由 Norm Cox 于 1981 年创建的。Norm 设计这个图标的初衷是“……模仿显示的菜单列表的外观。”（[`gizmodo.com/who-designed-the-iconic-hamburger-icon-1555438787`](http://gizmodo.com/who-designed-the-iconic-hamburger-icon-1555438787)）。

换句话说，汉堡包图标的真正名称是“列表”图标。

现在，如果我们想一想，汉堡包图标在语义上是正确的，因为它确切地代表了触发时显示的内容：一系列项目。然而，一些用户体验研究表明，汉堡包图标并不像我们想象的那么有效，但我们在响应式网站和移动应用中随处可见它。

尽管汉堡包图标有一些缺点，但几乎每个人都能在不久的将来认出这个图标代表导航。

关键是，只要我们遵循目标大小建议，并使导航栏内的链接在小屏幕上易于点击，使用汉堡包图标并没有什么问题。

优点如下：

+   它很容易被某些人群识别，尤其是年轻人。

+   在设计中占用很少的空间。

+   它不依赖语言。

+   使用 Unicode 字符 2261（≡）制作起来很容易，全球支持率达到 96%。

缺点如下：

+   它不容易被某些人群识别，尤其是年长者。

+   尽管非常流行，很多人很难理解汉堡包图标代表菜单。

+   它促进了低发现性，因为网站的导航通常会被隐藏。

如果您打算使用汉堡包图标，不要使用任何类型的图像或任何带有边框或框阴影的 CSS 技术。保持简单。您只需要使用 Unicode 字符 2261（≡）。

在接下来的示例中，我们将使用一个众所周知的技术来隐藏内容（有一些变化以适应我们的演示）：凯勒姆方法。这种方法绝不是任何欺骗或类似的东西；我们并不打算用这种方法欺骗我们的用户或搜索引擎。我们实际上非常注意通过将文本留在标记中来提高导航图标的可访问性，以便使用辅助技术的用户仍然可以访问菜单。考虑以下示例。

HTML 如下：

```html
<button class="hamburger-icon"><span>Menu</span></button>SCSS
//Hamburger Icon
.hamburger-icon  {
    //Basic styling, modify if you want
    font-size: 40px;
    color: #666;
    background: #efefef;
    padding: 0 10px;
    border-radius: 3px;
    cursor: pointer;
    //Hamburger Icon
    &:before {
        content: '≡';
    }
    //Hide the term Menu from displaying without sacrificing accessibility
    span {
        display: inline-block;
        width: 0;
        height: 0;
        text-indent: -100%;
        overflow: hidden;
        white-space: nowrap;

    }
}
```

结果如下：

![汉堡包图标](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_03.jpg)

### 提示

出于可访问性原因，单词“菜单”应始终包含在标记中。当使用辅助技术（AT）的用户将焦点放在汉堡包图标上时，屏幕阅读器将朗读单词“菜单”。此外，将单词“菜单”包含在`<span>`标记中允许我们隐藏单词，而不会损害链接的可访问性。

## 单词菜单

网上一些非正式测试表明，使用单词“菜单”是解决汉堡包图标缺点的最可信赖的解决方案。

然而，需要注意的是，许多作者进行的研究和测试，比较了汉堡包图标和单词“菜单”，可能会产生误导，因为它们测试的是不同的视觉语言：图标与单词。

要使这些测试完全可靠，它们必须测试图标与图标，单词与单词。例如，测试汉堡包图标与向下指的箭头或单词“菜单”与单词“导航”。

让我们来看看单词“菜单”的优缺点。

优点如下：

+   这是不言自明的。

+   几乎任何人群的任何人都可以理解它的含义。

+   它可以用于任何语言。

+   它在设计中占用的空间很小。

缺点如下：

+   它可能会与图标系统冲突，因为它是一个单词。

考虑以下示例。

这是 HTML：

```html
<button class="word-menu">Menu</button>
```

这是 CSS：

```html
//Word "Menu"
.word-menu {
    //Basic styling, modify if you want
    display: inline-block;
    padding: 16px 8px;
    color: #666;
    font: 12px Arial, "Helvetica Neue", Helvetica, sans-serif;
    background: #efefef;
    border-radius: 3px;
    cursor: pointer;
}
```

这就是结果：

![单词菜单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_04.jpg)

### 提示

在这个例子中，我使用了类名`.word-menu`来明确表示我对这本书的意图，但这不是为生产命名元素的正确方式。使用更有意义和通用的命名约定，例如`.menu-trigger`可能是一个替代方案。使用通用类名将允许我们在不改变标记的情况下使用任何导航图标设计。

## 汉堡图标加上单词菜单

汉堡图标与单词*菜单*讨论的一个替代方案是同时使用两者。一些人认为这样做可以兼顾两全。

优点是：

+   它是不言自明的。

+   几乎任何人都可以理解它的含义。

+   它可以用于任何语言。

+   它在设计中仍然占用很小的空间。

+   使用 Unicode 字符 2261（≡）很容易，全球支持率为 96%。

缺点是：

+   根据设计，单词*菜单*可能太小。

让我们看看我们可以用来表示这种模式的两种样式。

考虑以下示例。

HTML 如下：

```html
<button class="hamburger-icon-plus-menu style-1">Menu</button>
```

SCSS 如下：

```html
//Hamburger Icon Plus Word "Menu" – Style 1
.hamburger-icon-plus-menu {
    //Basic styling, modify if you want
    display: inline-block;
    font-family: Arial, "Helvetica Neue", Helvetica, sans-serif;
    background: #efefef;
    color: #666;
    border-radius: 3px;
    cursor: pointer;
}
.style-1 {
    padding: 16px 8px;
    font-size: 16px;
    //Hamburger Icon
    &:before {
        content: '≡ ';
    }
}
```

结果如下：

![汉堡图标加上单词菜单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_05.jpg)

### 提示

注意在`≡`后面的空格，这样可以在不使用任何边距的情况下将图标与单词“菜单”分开。

考虑以下示例。

HTML 是：

```html
<button class="hamburger-icon-plus-menu style-2">Menu</button>
```

SCSS 是：

```html
//Hamburger Icon plus Word "Menu" – Style 2
.hamburger-icon-plus-menu {
    //Basic styling, modify if you want
    display: inline-block;

    font-family: Arial, "Helvetica Neue", Helvetica, sans-serif;
    background: #efefef;
    color: #666;
    border-radius: 3px;cursor: pointer;
}
.style-2 {
    padding: 4px 12px 6px;
    font-size: 10px;
    line-height: .8;
    text-align: center;
    //Hamburger Icon
    &:before {
        display: block;
        content: '≡';
        font-size: 40px;
    }
}
```

这就是结果：

![汉堡图标加上单词菜单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_06.jpg)

您可以在[`codepen.io/ricardozea/pen/f4ddc6443bc060004b58a7301aae83db`](http://codepen.io/ricardozea/pen/f4ddc6443bc060004b58a7301aae83db)上看到我在 CodePen 中创建的演示。

# RWD 的导航模式

RWD 最令人费解的特点之一是导航。它可以简单也可以复杂，取决于我们的需求。

在这一部分，我将向您展示如何构建三种常用的导航模式：

+   **切换导航**：这是基于 Brad Frost 的*切换菜单*演示（[`codepen.io/bradfrost/pen/sHvaz/`](http://codepen.io/bradfrost/pen/sHvaz/)）。

+   **侧边或屏幕外导航**：这是基于 Austin Wulf 的 SitePoint *纯 CSS 屏幕外导航菜单*演示（[`codepen.io/SitePoint/pen/uIemr/`](http://codepen.io/SitePoint/pen/uIemr/)）。

+   **基于 Flexbox 的导航**：这是我们的自定义解决方案。

在我们查看每个细节之前，让我们澄清一下关于上述模式的一些特点：

## 设计

在小屏幕上，所有导航模式都使用汉堡图标作为触发器，除了基于 Flexbox 的导航。在大屏幕上，所有示例中的导航栏都是水平链接组，链接居中。

为了改善切换和侧边导航的可用性，汉堡图标会添加/删除类`.active`，以提供视觉提示，显示该项目已被点击。这是通过一点 jQuery 完成的。

包括 jQuery 是这些演示的一部分，因此需要调用它才能使它们工作。

## 范围

所示的标记仅用于菜单本身，元素和指令，如`<html>`标记和 HTML5 Doctype 已经被故意省略。

这些示例适用于所有主要浏览器，这些浏览器支持相对先进的 CSS3 属性。它们不使用 FastClick 脚本来消除移动设备默认的 300 毫秒延迟。

供应商前缀已被省略；毕竟，我们应该使用 Autoprefixer 来处理这些问题。

## 第三方演示

由于没有必要重复造轮子，以下示例基于其他作者的演示，例如 Brad Frost 和 Austin Wulf 的演示。

然而，所有原始演示都已被分叉并*大幅*缩放、增强、清理、优化、重新设计和移植到 Sass，以适应本书的范围和风格。换句话说，您将看到的标记和代码已经专门为您进行了大量定制。

让我们开始吧。

## 侧栏或屏幕外导航

这是迄今为止在 RWD 和移动应用中最常用的导航模式。它使用汉堡图标作为菜单的触发器，当点击时触发菜单。这时，主容器向右滑动以显示左侧的菜单，再向左滑动以隐藏它。

这个示例不依赖于 JavaScript 来工作。但是，它使用了一些非语义元素来使其工作：`<input>`和`<label>`元素。为了支持这种方法，它使用了`：checked`伪类，在各方面都有完美的支持。

这是我们的 HTML：

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="img/jquery.min.js"></script>
</head>
<body>
    <!-- Checkbox whose checked/unchecked states trigger the navigation -->
    <input type="checkbox" id="nav-trigger" class="nav-trigger">
    <!-- Hamburger icon -->
    <label for="nav-trigger" class="label-trigger"><span>Menu</span></label>
    <!-- Navigation -->
    <nav role="navigation">
        <ul class="menu">
            <li><a href="#">Link 1</a></li>
            <li><a href="#">Link 2</a></li>
            <li><a href="#">Link 3</a></li>
            <li><a href="#">Link 4</a></li>
            <li><a href="#">Link 5</a></li>
        </ul>
    </nav>
    <!-- Main container -->
    <main class="main-container" role="main">
        <h1>The "Off-Canvas" or "Off-Screen" Navigation</h1>
        <p>On <strong>small screens</strong>, the menu is triggered with a hamburger icon. The menu slides left/right.</p>
        <p>On <strong>large screens</strong> starting at 40em (640px), the menu is a horizontal nav.</p>
    </main>
</body>
</html>
```

这是我们的 SCSS：

```html
*, *:before, *:after { box-sizing: border-box; }
//Globals
html, body {
    height: 100%;
    width: 100%;
    margin: 0;
}
//Mobile-first Media Query Mixin
@mixin forLargeScreens($media) {
    @media (min-width: $media/16+em) { @content; }
}
//Mixin for animating the hamburger icon
@mixin animation-nav-icon ( $direction: left, $duration: .2s) {
    transition: $direction $duration;
}
//Menu itself
.menu {
    width: 100%;
    height: 100%;
    margin: 0;
    padding: 0;
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    left: 0;
    z-index: 0;
    list-style: none;
    @include forLargeScreens(640) {
        max-width: 980px;
        min-height: 50%;
        margin: 10px auto 0;
        position: relative;
        text-align: center;
        border: #999 1px dotted;
    }
    //List items
    li {
        width: 100%;
        border-bottom: 1px dotted #999;
        @include forLargeScreens(640) {
            display: inline;
            border: none;
        }
        //Links themselves
        a {
            display: block;
            padding: 1em;
            color: #2963BD;
            text-decoration: none;
            @include forLargeScreens(640) {
                display: inline-block;
            }
        }
    }
}
//Main Container
.main-container {
    max-width: 980px;
    min-height: 100%;
    margin: auto;
    padding: 20px 0 20px 80px;
    position: relative;
    top: 0;
    bottom: 100%;
    left: 0;
    z-index: 1;
    background: #eee;
    @include forLargeScreens(640) {
       padding: 20px;
    }
}
//Navigation Trigger - Hide the checkbox
.nav-trigger {
    position: absolute;
    clip: rect(0, 0, 0, 0);
}
//Label that triggers the checkbox
.label-trigger {
    position: fixed;
    left: 10px;
    top: 10px;
    z-index: 2;
    height: 50px;
    width: 50px;
    cursor: pointer;
    background: #fff;
    border-radius: 2px;
    border: 1px solid #ccc;
    //Hamburger icon
    &:before {
        display: block;
        padding-top: 25px;
        text-align: center;
        content: '≡';
        font-size: 3em;
        line-height: 0;
    }
    //Active hamburger icon
    &.active {
        background: #333;
        color: #fff;
    }
    //Hide the term 'Menu' from displaying without sacrificing accessibility
    span {
        display: inline-block;
        text-indent: -100%;
        overflow: hidden;
        white-space: nowrap;
    }
}
//Animate the menu
.nav-trigger {
    & + label {
        @include animation-nav-icon;
        //Hide the checkbox and label in large screens
        @include forLargeScreens(640) {
            display: none;
        }
    }
    //Animate the label when checkbox is checked
    &:checked + label {
        left: 215px;
    }
    //Animate the main container when checkbox is checked
    &:checked ~ .main-container {
        left: 200px;
        box-shadow: 0 0 5px 1px rgba(black, .15);
    }
}
//Animate the main container
.main-container {
    @include animation-nav-icon;
}
//Avoid horizontal scrollbars due to repositioning of elements
body, html { overflow-x: hidden; }
//Styling stuff not needed for demo
html, body { font-family: Arial, "Helvetica Neue", Helvetica, sans-serif; }
h1, p { margin: 0 auto 1em; }
p { line-height: 1.5; }
```

这是 jQuery 脚本：

```html
$(function() {
    //Set up the click behavior
    $(".label-trigger").click(function() {
        //Toggle the class .active on the hamburger icon
        $(this).toggleClass("active");
    });
});
```

让我们来看一下截图。

这是在*折叠*状态下小屏幕上的样子：

![侧栏或屏幕外导航](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_07.jpg)

这是在*展开*状态下的样子：

![侧栏或屏幕外导航](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_08.jpg)

这是在大屏幕上的样子：

![侧栏或屏幕外导航](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_09.jpg)

您可以在[`codepen.io/ricardozea/pen/fd504cbcf362069320d15a4ea8a88b27`](http://codepen.io/ricardozea/pen/fd504cbcf362069320d15a4ea8a88b27)看到我创建的演示。

## 切换导航

在切换模式中，当点击汉堡图标时，导航栏会下滑，链接会堆叠。再次点击汉堡图标时，导航栏会折叠。

HTML 如下：

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="img/jquery.min.js"></script>
</head>
<body>
    <!-- Hamburger icon -->
    <button class="menu-link"><span>Menu</span></button>
    <!-- Navigation -->
    <nav id="menu" class="menu" role="navigation">
        <ul>
            <li><a href="#">Link 1</a></li>
            <li><a href="#">Link 2</a></li>
            <li><a href="#">Link 3</a></li>
            <li><a href="#">Link 4</a></li>
            <li><a href="#">Link 5</a></li>
        </ul>
    </nav>
    <!-- Main container -->
    <main class="main-container" role="main">
        <h1>The Toggle Navigation</h1>
        <p>On <strong>small screens</strong>, the menu is triggered with a hamburger icon. The menu slides down/up.</p>
        <p>On <strong>large screens</strong> starting at 40em (640px), the menu is a horizontal nav.</p>
    </main>
</body>
</html>
```

SCSS 如下：

```html
*, *:before, *:after { box-sizing: border-box; }
//Mobile-first Media Query Mixin
@mixin forLargeScreens($media) {
    @media (min-width: $media/16+em) { @content; }
}
//General Styling
.main-container, .menu {
    width: 98%;
    max-width: 980px;
    margin: auto;
    padding: 20px;
    background: #eee;
}
//Link that triggers the menu
.menu-link {
//Change to float: left; if you want the hamburger menu on the left side
    float: right;
    margin: 0 1% 5px 0;
    padding: 1.5em 1em 1em;
    background: #f6f6f6;
    line-height: 0;
    text-decoration: none;
    color: #333;
    border-radius: 2px;
    cursor: pointer;
    //Hamburger icon
    &:before {
        display: block;
        padding: 10px 0;
        content: '≡';
        font-size: 3em;
        line-height: 0;
    }
    //Active hamburger icon
    &.active {
        background: #333;
        color: #fff;
    }
    //Hide the term 'Menu' from displaying without sacrificing accessibility
    span {
        display: inline-block; 
		text-indent: -100%;
        overflow: hidden;
        white-space: nowrap;
    }
    //On large screens hide the menu trigger
    @include forLargeScreens(640) {
        display: none;
    }
}
//If JavaScript is available, hide the menu.
.js .menu {
    overflow: hidden;
    max-height: 0;
    @include forLargeScreens(640) {
        max-height: inherit;
    }
}
//Menu itself
.menu {
    padding: 0;
    clear: both;
    transition: all .3s ease-out;
    //Define height of the menu
    &.active {
        max-height: 17em;
    }
    //Normalize the unordered list and add a bit of styling
    ul {
         margin: 0;
         padding: 0;
         list-style-type: none;
         border: 1px #999 dotted;
         border-bottom: none;
         text-align: center;
         //In large screens remove the border
        @include forLargeScreens(640) {
            background: #fff;
       }
    }
    //List items
    li {
      //Links themselves
      a {
         display: block;
         padding: 1em;
         border-bottom: 1px #999 dotted;
         text-decoration: none;
         color: #2963BD;
         background: #fff;
         @include forLargeScreens(640) {
            border: 0;
            background: none;
         }
      }
      //On large screens make links horizontal
      @include forLargeScreens(640) {
    display: inline-block;
    margin: 0 .20em;
       }
    }
}

//Styling stuff not needed for demo
body { font-family: Arial, "Helvetica Neue", Helvetica, sans-serif; }
p { line-height: 1.5; }
h1 { margin: 0; }
```

jQuery 如下：

```html
$(function() {
    //Add class .js to the body if JS is enabled
    $("body").addClass("js");
    //Set up the click behavior
    $(".menu-link").click(function() {
        //Toggle the class .active on the hamburger icon
        $(this).toggleClass("active");
       //Toggle the class .active on the menu to make it slide down/up
        $(".menu").toggleClass("active");
    });
});
```

让我们来看一下截图。

这是在小屏幕上*折叠*状态下的样子：

![切换导航](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_10.jpg)

这是*展开*状态下的样子：

![切换导航](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_11.jpg)

这是在大屏幕上的样子：

![切换导航](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_12.jpg)

您可以在[`codepen.io/ricardozea/pen/e91a5e6ea456d41f4128d9bd405ccaa0`](http://codepen.io/ricardozea/pen/e91a5e6ea456d41f4128d9bd405ccaa0)看到我创建的演示。

您还可以访问[`responsive-nav.com/`](http://responsive-nav.com/)了解漂亮的切换导航功能。

## 基于 Flexbox 的导航

这个使用 Flexbox 的自定义解决方案非常灵活，不一定需要使用媒体查询。另外两个菜单解决方案（切换导航和侧栏导航）需要媒体查询。

使用这个解决方案，菜单项会适应可用空间，使目标区域尽可能大，自动增强菜单的可用性。这个基于 Flexbox 的解决方案的另一个主要优点是它不依赖于 JavaScript。

这是 HTML：

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
    <nav role="navigation">
        <ul class="menu">
            <li><a href="#">Link 1</a></li>
            <li><a href="#">Link 2</a></li>
            <li><a href="#">Link 3</a></li>
            <li><a href="#">Link 4</a></li>
            <li><a href="#">Link 5</a></li>
        </ul>
    </nav>
    <!-- Main container -->
    <main class="main-container" role="main">
        <h1>The Flexbox-based Navigation</h1>
        <p>On both <strong>small and large screens</strong> the menu and its items are always visible.</p>
        <p>However, on <strong>small screens</strong> the links are more clearly defined and occupy all the available space.</p>
   </main>
</body>
</html>
```

现在是 SCSS：

```html
*, *:before, *:after { box-sizing: border-box; }
//Mobile-first Media Query Mixin
@mixin forLargeScreens($media) {
    @media (min-width: $media/16+em) { @content; }
}
//Menu itself
.menu {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-around;
    max-width: 980px;
    margin: auto;
    padding: 2px;
    list-style: none;
    border: #999 1px dotted;
    //List items
    li {
        //Expand to use any available space
        flex-grow: 1;
        margin: 3px;
        text-align: center;
        flex-basis: 100%;
        @include forLargeScreens(320) {
            flex-basis: 30%;
        }
        @include forLargeScreens(426) {
            flex-basis: 0;
        }
        //Links themselves
        a {
           display: block;
           padding: 1em;
           color: #2963bd;
           text-decoration: none;
           background: #eee;
           @include forLargeScreens(426) {
              background: none;
           }
        }
    }
}
//Main Container
.main-container {
    max-width: 980px;
    margin: auto;
    padding: 20px;
    background: #eee;
}

//Styling stuff not needed for demo
body { margin: 8px; font-family: Arial, "Helvetica Neue", Helvetica, sans-serif; }
p { line-height: 1.5; }
h1 { margin: 0; }
```

让我们来看一下截图。

这是在小屏幕（320px）上的样子：

![基于 Flexbox 的导航](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_13.jpg)

这是在小屏幕（426px）上的样子：

![基于 Flexbox 的导航](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_14.jpg)

这是在大屏幕（980px）上的样子：

![基于 Flexbox 的导航](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_05_15.jpg)

您可以在[`codepen.io/ricardozea/pen/022b38c6c395368ec4befbf43737e398`](http://codepen.io/ricardozea/pen/022b38c6c395368ec4befbf43737e398)看到我创建的演示。

# 总结

我们现在已经掌握了使用 HTML5 和 CSS3 进行 RWD 的一半。这是一个*巨大*的里程碑！非常感谢您走到这一步！

RWD 显然不仅仅是媒体查询、Sass 混合和 CSS 网格。它还涉及理解我们目标区域的不同尺寸，控件的位置（链接、按钮、表单字段等），以及不同设备中的触摸区域。

创建菜单按钮总会有不同的方法，只要确保功能在任何屏幕尺寸上都不会出现问题。一旦我们定义了菜单按钮的样式，我们就可以确定哪种导航模式最适合我们的内容和用户。

在菜单按钮或导航模式方面，实际上并没有一个单一的、最佳的解决方案；一切都取决于每个项目的具体条件。我建议的是，无论你构建什么，都要确保始终保持高水平的浏览器支持、可扩展性和性能，这样用户就可以获得很好的体验，客户/公司也可以实现其目标。

现在我们谈论性能，下一章我们将讨论 RWD 的“丑孩子”：图片。

让我们跳舞吧！


# 第六章：在响应式网页设计中使用图像和视频

我一直把图像称为**RWD**的“丑陋之子”。为什么？直到最后一刻，我总是试图避免处理它们。我要使用图像精灵吗？如果是的话，我应该将我的透明 PNG 导出为 8 位还是 24 位，或者 32 位？一些旧版 IE 不支持带有 alpha 通道的 PNG，所以我必须导出一个 GIF 精灵。我可以使用 SVG，但 IE8 及更早版本不支持 SVG。我可以使用图标字体，但如果图标字体加载失败会怎么样？那我就得查一些分析数据。有一种新的高密度屏幕的*iDevice*？现在我每次都得导出两个（或更多）图像。太好了！但我不能为小屏设备提供超过正常尺寸图像两倍大小的高质量图像！是的，它可能看起来很好，但下载速度会很慢，他们甚至在第一个 H1 加载之前就可能离开网站。

你明白了。这只是刚刚开始涉及响应式网页设计中媒体工作的冰山一角。

其中一些想法今天仍然非常活跃，但多年来我学到了一些常识，并且紧跟解决所有这些问题的技术，拥有一个简单直接的处理图像（和视频）的系统可以走得更远。

和其他章节一样，我们将保持简单但有意义。在涉及图像时并没有银弹，特别是在响应式网页设计中，我们可能整天都在这里，这绝对不是我们这本书想要的。我希望你尽快构建出色的响应式网站。但我鼓励你花一些时间研究更多关于响应式网页设计中图像的内容；这确实是网页设计和开发者社区中一个令人难忘的话题。

在本章中，我们将讨论以下主题：

+   导出图像并在保持图像质量的同时显著减小其最终文件大小的技巧。

+   如何使用`srcset`和`sizes`属性，以及`<picture>`元素。

+   使用`Retina.js`。

+   制作响应式视频。

+   使用`FitVids.js`。

+   使用矢量格式：图标字体和 SVG。

+   使用正确的 CSS 图像替换技术。

现在，这是我们在示例中要使用的图像：

![在响应式网页设计中使用图像和视频](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_06_01.jpg)

这些了不起的人物是中国少林寺的两位功夫大师。他们的名字是释德如和释德阳。

### 注意

*释德如和释德阳*由释德如（刘祥阳）拍摄，他是这张照片的唯一所有者和版权持有者，该照片是在少林寺前门拍摄的。它在维基百科上以 CC BY-SA 3.0 许可证发布。可以在[`en.wikipedia.org/wiki/Shaolin_Kung_Fu#/media/File:Shi_DeRu_and_Shi_DeYang.jpg`](http://en.wikipedia.org/wiki/Shaolin_Kung_Fu#/media/File:Shi_DeRu_and_Shi_DeYang.jpg)找到。

由于我们还在用 HTML5 和 CSS3*精通*响应式网页设计，我觉得这张照片与我们的使命非常契合。

我将要描述的功夫大师的原始图像的属性将有助于理解为响应式网页设计优化图像前后效果设定基线。

以下是原始图像的属性：

+   这是一张 24 位 JPG 图像。

+   文件大小为 556KB，但由于 JPG 算法的魔力而被压缩（解压后约为 12MB）。

+   尺寸为 2496 x 1664 像素，约为 4.15 百万像素。换个角度看，这张图像的分辨率比我客厅里的 55 英寸 LED 电视还要高。

在本书结束时，我向你保证两件事。一，你将绝对准备好构建响应式网站和应用。二，当是时候开始一个新项目时，你将从座位上站起来，并摆出这些大师们正在做的同样的姿势。

图像编辑超出了本书的范围，以下步骤将需要某种形式的图像处理。在这一点上，您可以使用您喜欢的图像编辑器。我个人使用 Adobe Fireworks（确实如此），但绝大多数人使用 Photoshop。

如果您不使用其中任何一个，您可以随时使用**GNU 图像处理软件**（**GIMP**）或 Paint.NET-两者都是免费的。您可以从这里下载它们：

+   GIMP：[`www.gimp.org/`](http://www.gimp.org/)

+   Paint.NET：[`www.getpaint.net/`](http://www.getpaint.net/)

您还可以使用在线图像编辑工具。但是，我必须承认，我从未使用过其中任何一个，所以我无法推荐任何一个。在这一点上，我可以说的是尝试其中一些，并选择最适合您需求的那个。

让我们开始吧。

# 用于 RWD 图像文件大小减小的提示

在设计中，创建图像副本的经验法则是从大到小进行，而不是相反。换句话说，图像越大，其后续副本的质量就越好。

## 调整大小

仅通过将图像从 2496 x 1664 像素调整为 1024 x 683 像素，文件大小现在为 331 KB。与 556 KB 相比，这几乎是文件大小的 40％减少。这是一个巨大的改进，但我们还没有到达目标。

## 模糊背景

模糊背景实际上本身就非常有效，但从*艺术指导*的角度来看，它还有另一个好处：它有助于吸引对图像的重要部分的注意力。

在模糊背景之后，文件现在重量为 185 KB。与 556 KB 相比，文件大小减少了约 67％。我们开始有所进展了。

这是带有模糊背景的新图像：

![模糊背景](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_06_02.jpg)

优化的巨大胜利！

## 暗化或变亮不重要的区域

暗化或变亮不重要的区域非常主观，许多人可能不一定同意。在特殊情况下，这个过程-就像背景模糊技术一样-可以帮助减小文件大小并突出图像的重要部分。

我们基本上试图通过暗化或变亮图像来减少颜色的数量，从而创建*纯色*区域，或者至少尽可能纯色。换句话说，我们正在减少对比度。谨慎使用这个技巧。

在我们的功夫宗师的情况下，在暗化背景中不重要的部分后，图像现在重量为 178 KB。诚然，这与以前的过程没有太大不同（只有 7 KB 的差异），但是我们可以从图像中提取的每一个千字节而不影响质量都是一件好事，178 KB 大约是文件大小的 68％减少。

这是在稍微暗化背景后图像的外观：

![暗化或变亮不重要的区域](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_06_03.jpg)

每一个千字节都很重要。

## 优化图像

这是过程的最后一步。这一步实际上可以分为两个较小的步骤。

### 使用 Adobe Fireworks（可选）

保存一个在质量与文件大小之间平衡的 JPG。没有确定的值可以始终应用于每个单独的图像。这一切都是即兴发生的。在执行此步骤时，您不希望以太低的质量保存图像，因为图像将经历另一个优化步骤。

我实际上要使用的是 Adobe 在 2013 年 5 月停止开发的软件：Fireworks。

Fireworks 以其优越的图像优化引擎而闻名，比起 Photoshop，我自己进行了测试，Fireworks 的压缩与质量总是表现最好。Fireworks 对于今天的网页设计流程和工作流程与任何其他图像编辑软件一样相关。因此，请放心使用它。

从 Fireworks 以 80％的质量导出图像后，功夫宗师的图像现在只有 71 KB。与原始的 556 KB 相比，文件大小减少了约 87％。

### 压缩图像

通过另一个图像优化工具运行图像，可以是一个独立的应用程序，如 Mac 的 ImageOptim 或 Windows 的 Radical Image Optimization Tool（RIOT），或者通过在线服务，如[`tinypng.com/`](https://tinypng.com/)或[`www.jpegmini.com/`](http://www.jpegmini.com/)。

我们将使用[`tinypng.com/`](https://tinypng.com/)在线图像压缩服务。在通过[`tinypng.com/`](https://tinypng.com/)从 Fireworks 导出的图像后，文件大小现在约为 52 KB，比原始的 556 KB 减少了约 91%。这对于图像优化来说是一个巨大的胜利。

### 提示

如果你没有先通过 Fireworks 运行图像，不要担心。即使您的图像可能会稍大一些，它仍然会被极大地优化，这是我们的目标。

这是 556 KB 图像和最终 52 KB 图像之间的前（左）后（右）比较：

![压缩图像](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_06_04.jpg)

# 第三方图像调整服务

我们必须承认，如果手动优化图像的过程在需要调整大小和优化许多图像的情况下可能会非常乏味和耗时，那么手动操作可能不是最佳选择。

有一些第三方和服务器端服务可以自动为我们完成这个过程。我们将把如何实现这些服务的教程留给另一本书。但是，我们将列出一些最受欢迎的服务，以便您在需要深入了解时有一个参考。

以下是一些第三方图像调整大小服务的示例：

+   **Sencha.io Src**来自 Sencha.com ([`www.sencha.com/learn/how-to-use-src-sencha-io/`](http://www.sencha.com/learn/how-to-use-src-sencha-io/))

+   **ReSRC**由 Dom Fee 和 Ed Thurgood ([`www.resrc.it/`](http://www.resrc.it/))

+   **WURFL** Image Tailor ([`web.wurfl.io/#wit`](http://web.wurfl.io/#wit))

以下是一些服务器端（`.htaccess`和/或`.php`）图像调整大小服务的示例：

+   Matt Wilcox 的自适应图像 ([`adaptive-images.com/`](http://adaptive-images.com/))

+   RESS.io ([`ress.io/`](http://ress.io/))

# <picture>元素和 srcset 和 sizes 属性

首先，我要说的是，在 RWD 中没有 100%的最佳解决方案。这是因为当前对推荐属性的支持不足，或者因为资产双重下载。尽管戴夫·牛顿在[`ww1.smashingmagzine.com/`](http://ww1.smashingmagzine.com/)的文章中，*如何避免响应式图像中的重复下载*，试图解决这个问题（[`www.smashingmagazine.com/2013/05/10/how-to-avoid-duplicate-downloads-in-responsive-images/`](http://www.smashingmagazine.com/2013/05/10/how-to-avoid-duplicate-downloads-in-responsive-images/)）。

然而，这种解决方案非常冗长。如果你必须处理许多图像，这种解决方案可能不是最佳选择，允许双重下载开始变得更有意义。每个项目都是不同的，因此尽可能做出最明智的决定非常重要。

一旦浏览器供应商决定完全支持这里提到的任何解决方案，就不需要担心双重下载或任何类型的 polyfill 了。

<picture>元素和 srcset 和 sizes 属性由**响应式图像社区组**（**RICG**）维护，现在已成为 HTML 规范的一部分。换句话说，我们可以在没有任何类型的 polyfill 的情况下使用它们，并且可以确信现代浏览器将支持它们。至少在某种程度上是这样。

我们需要使用 polyfill 的唯一原因是为了支持那些（传统和现代的）尚未实现对它们的支持的浏览器。

### 提示

`<picture>`元素和`srcset`属性都有一个针对不支持它们的浏览器的回退功能。您可以选择使用 polyfill，但不是必须的。如果您认为使用 polyfill 可以增强用户体验，那就尽管使用。阅读 Picturefill polyfill 的创建者 Scott Jehl 的这篇文章（[`www.filamentgroup.com/lab/to-picturefill.html`](http://www.filamentgroup.com/lab/to-picturefill.html)）。

现在有很多 polyfill，这里是我们今天可以使用的一些简要列表：

+   由 Scott Jehl 的 Picturefill（由 RICG 推荐：[`scottjehl.github.io/picturefill/`](http://scottjehl.github.io/picturefill/)）提供支持

+   由 Andrea Verlicchi 的 PicturePolyfill（[`verlok.github.io/picturePolyfill/`](http://verlok.github.io/picturePolyfill/)）提供支持

+   由 Alexander Farkas 的 respimage（[`github.com/aFarkas/respimage`](https://github.com/aFarkas/respimage)）提供支持

在 Web 设计和 Web 开发社区中，一些人强烈认为，考虑到新的 HTML 元素（`<picture>`）并不是解决我们在 RWD 中遇到的图像问题的解决方案。他们认为解决方案应该来自已经存在的`<img>`标签。

### 提示

`sizes`属性也可以与`<picture>`元素一起使用，但我们将专注于在`<img>`标签中使用`sizes`属性。

对我们来说很好，解决方案有两种。使用哪种方法来负责负责您的图像并不重要，重要的是您应该使用其中一种方法。如果您已经在使用，那太棒了。如果没有，不要担心。以下的解释将帮助您解决任何关于这个问题的疑问。

## 何时使用<picture>，何时使用 srcset

何时使用`<picture>`，何时使用`srcset`？这是一个非常合理的问题，我自己在第一次听到这些术语时也无法理解。所以我决定在俄亥俄州戴顿市的一次布拉德·弗罗斯特（Brad Frost）的研讨会上向他请教。

推荐的方法归结为这个概念：艺术指导。在响应式图像中，艺术指导基本上意味着您有不同的图像，以某种方式裁剪，以便图像的不太重要的部分被剔除，从而专注于重要的部分。

这与只调整相同的图像不同。当然，您可以使用任何您想要的方法，但为了保持简单，当您想要提供艺术指导图像时，可以使用`<picture>`元素，当您只想提供相同图像的调整版本时，可以使用`srcset`属性。

在我们深入标记之前，让我们看一个关于艺术指导图像与使用功夫宗师照片的调整图像的视觉示例：

![何时使用<picture>，何时使用 srcset](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_06_05.jpg)

让我们看看这里发生了什么。原始图像周围有很多空间，我们可以看到后面的树和建筑物。调整大小的版本保持了原始图像的所有方面和比例 1:1。

然而，艺术指导图像有很多不同之处。第一个艺术指导图像被裁剪以显示两位宗师的特写；第二个艺术指导图像被裁剪得更多，以突出对 Shi DeRu（左侧的宗师）的关注。我们本可以裁剪图像以便关注 Shi DeYang（右侧的宗师），但这是我想要给图像的“艺术指导”。这是一个主观的决定，但基于坚定的意图。

现在，让我们看看*Picturefill polyfill/script*的实际效果。

## 实施 Picturefill polyfill

我们需要做的第一件事是下载 JavaScript 文件，可以从[`github.com/scottjehl/picturefill/blob/2.3.0/dist/picturefill.min.js`](https://github.com/scottjehl/picturefill/blob/2.3.0/dist/picturefill.min.js)下载。

然后，我们需要做的就是将它包含在文档的`<head>`部分中：

```html
<!DOCTYPE html>
<!--[if IE 8]> <html class="no-js ie8" lang="en"> <![endif]-->
<!--[if IE 9]> <html class="no-js ie9" lang="en"> <![endif]-->
<!--[if gt IE 9]><!--><html class="no-js" lang="en"><!--<![endif]-->
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <script src="img/picturefill.min.js"></script>
    <title>Picturefill polyfill</title>
</head>
```

## 使用<picture>元素

使用`<picture>`元素时，您（作者）告诉浏览器在哪个断点使用哪个图像。这样做的好处是，我们可以通过使用媒体查询来精确定义何时显示某个图像。媒体查询的工作方式与 CSS 中使用的媒体查询完全相同，甚至看起来完全相同。

这是一个基本的`<picture>`片段的样子：

```html
<picture>
    <source srcset="images/grandmasters-small.jpg" media="(max-width: 40em)">
    <source srcset="images/grandmasters-medium.jpg" media="(max-width: 64em)">
    <source srcset="images/grandmasters-default.jpg">
    <img src="img/grandmasters-default.jpg" alt="Fallback image">
</picture>
```

即使使用了 polyfill，IE9 对`<picture>`元素也存在问题。尽管听起来很奇怪，但我们需要在 IE9 中插入一个`<video>`标签以正确工作。

这是为 IE9 修改后的标记样式：

```html
<picture>
 <!--[if IE 9]><video style="display: none;"><![endif]-->
    <source srcset="images/grandmasters-small-ad.jpg" media="(max-width: 40em)">
    <source srcset="images/grandmasters-medium-ad.jpg" media="(max-width: 64em)">
    <source srcset="images/grandmasters-default.jpg">
    <!--[if IE 9]></video><![endif]-->
    <img src="img/grandmasters-default.jpg" alt="Fallback image">
</picture>
```

正如您所看到的，我还突出显示了`<img src="img/grandmasters-default.jpg" alt="Fallback image">`标签。这是那些不支持`<picture>`元素的浏览器的回退图像。

请记住的一件事是，不久之前，这个回退图像在一些现代浏览器中导致了双重下载。我的最后测试显示，在 Chrome 和 Firefox 中并非如此，它们支持`<picture>`元素。因此，请确保您运行所有必要的测试，以查看您的情况，然后考虑解决方案，如果您需要支持那些旧版浏览器。

这是我在 CodePen 上创建的演示：[`codepen.io/ricardozea/pen/cf6c0965785d552bad5e200acb761ffe`](http://codepen.io/ricardozea/pen/cf6c0965785d552bad5e200acb761ffe)

## 使用`srcset`和`sizes`属性

`srcset`和`sizes`属性实际上来自`<picture>`规范，但在`<img>`元素中实现。使用`srcset`和`sizes`属性时，浏览器会决定在每种特定情况下使用哪个图像。如果需要，您还可以使用媒体查询，尽管不是必需的。单词`vw`表示*视口宽度*，用于让浏览器知道它应该根据视口宽度的百分比显示图像。如果看到类似`80vw`的东西，这意味着图像应该是当前视口宽度的 80%。

`w`描述符表示*图像的宽度*。如果看到类似`255w`的东西，浏览器将了解特定图像的宽度为 255px。

让我们看看带有`srcset`和`sizes`属性的`<img>`标签：

```html
<img src="img/grandmasters-default.jpg"
     srcset="images/grandmasters-small-rsz.jpg 255w,
             images/grandmasters-medium-rsz.jpg 511w"
     sizes="(min-width: 30em) 80vw, 100vw"
     alt="Mastering RWD with HTML5 and CSS3">
```

`rsz`这几个字母是*resize*一词的缩写。这是因为对于在 RWD 中只会被调整大小的图像，`srcset`属性使事情变得简单一些。

以下标记被截断，以便更容易专注于特定的解释。

我们首先看到的是已知的`src`属性，它充当回退图像：

```html
<img src="img/grandmasters-default.jpg"…

```

请记住，浏览器不理解`srcset`的话，将不会使用图像`grandmasters-default.jpg`。换句话说，在支持`srcset`的浏览器中，*默认*图像将是列表中的第一个图像。在我们的情况下，它是`grandmasters-small-rsz.jpg`。然后，我们看到`srcset`属性。

这就是魔术开始发生的地方：

```html
srcset="images/grandmasters-small-rsz.jpg 255w,images/grandmasters-medium-rsz.jpg 511w"

```

在这个例子中，我们的计划是在支持`srcset`的浏览器中显示两个不同的图像文件。这是通过用逗号分隔的图像列表来实现的。此外，每个图像后面定义的值是图像的宽度：

```html
images/grandmasters-small-rsz.jpg 255w

```

### 提示

我们也可以使用高度：

```html
grandmasters-small-rsz.jpg 170h
```

然而，最常见的用例是处理宽度并允许高度按比例调整，这样作者对图像有更多的控制。

向浏览器提供图像的大小将使其能够根据`sizes`片段中的媒体查询更明智地决定使用哪个图像：

```html
sizes="(min-width: 30em) 80vw, 100vw"
```

记住，`30em`等同于 480px。使用媒体查询`min-width: 30em`，浏览器经历以下过程：

+   如果我的视口是 30em（480px）或更小，则应显示宽度为 255px 的图像。在只有 480px 的视口中，没有必要显示宽度为 511px 的图像。这是浪费带宽！

+   但是，如果我的视口*大于*30em（480px），那么我应该显示宽度为 511px 的图像。

`sizes`属性的最后部分是视口宽度：`80vw, 100vw`。

```html
sizes="(min-width: 30em) 80vw, 100vw"
```

这意味着如果视口是 30em（480px）或更小，浏览器将以 80%的宽度显示图像。如果超过 30em（480px），它将以 100%的宽度显示图像。

最后，我们有`alt`属性：

```html
alt="Mastering RWD with HTML5 and CSS3">
```

为图像添加`alt`属性对于使用辅助技术的用户来说总是一个良好的可访问性实践。此外，如果图像没有加载，浏览器可以显示这个文本。

### 提示

属性的顺序并不重要。换句话说，你可以先使用`srcset`，然后是`alt`，然后是`sizes`，然后是`src`属性（或者反之亦然）。

### 使用 srcset 定位高密度屏幕

高密度屏幕将永远是 RWD 世界中我们无法摆脱的东西。所以如果你无法打败它们，就加入它们。

这是一个解决普通和高密度屏幕的片段：

```html
<img src="img/grandmasters-default.jpg"
     srcset="images/grandmasters-small-rsz.jpg 1x,images/grandmasters-medium-rsz.jpg 2x">
```

正如你所看到的，这是一个更短更简洁的标记。它真的很简单明了：在没有`srcset`支持的情况下使用备用图像。如果有支持，那么如果设备具有普通密度显示，则使用`1x`图像。如果设备具有高密度显示，那么必须使用`2x`图像。如果我们支持的设备密度甚至更高，就应该添加一个 3x 后缀。

`sizes`属性是不是必需的。如果你的设计或条件需要使用`sizes`属性，你可以自由使用它。

这是我在 CodePen 上为此创建的演示：[`codepen.io/ricardozea/pen/a13993f05a4cdc5f714a311a94f48a69`](http://codepen.io/ricardozea/pen/a13993f05a4cdc5f714a311a94f48a69)

## `<picture>`与`srcset`

一些网页设计师和开发人员表示，在 HTML 中使用媒体查询，就像我们在`<picture>`和`srcset`中看到的那样，违反了关注点分离的原则：样式和标记应始终保持分离，独立的资源。

正如我之前提到的，其他人认为新的 HTML 元素是不必要的，任何解决方案都应该基于增强和扩展已经存在的元素，比如`<img>`标签。

我只能说，在最后，这一切都无关紧要。重要的是，作为网页设计师和开发人员，我们应该利用我们手头的一切资源来让用户满意，创造令人难忘的体验，同时遵循持久实施的最佳实践。

# 使用 Retina.js 在运行时将 1x 图像替换为 2x 图像

`Retina.js`脚本是那些使事情变得更简单的脚本之一，有时你会想为什么响应式图像如此困难。

如果你还没有准备好处理`<picture>`和/或`srcset`和`sizes`属性，我不怪你。这很可怕，但我建议你继续努力理解这些工具，因为这是响应式图像的最新技术。

`Retina.js`脚本是由 Imulus 的人员开发的（[`imulus.com/`](http://imulus.com/)）。`Retina.js`脚本不仅仅是 JavaScript 解决方案；他们还有一个 Sass mixin，可以在不依赖 JavaScript 的情况下产生相同的结果。

让我们先看一下 JavaScript 解决方案。

## Retina.js - 一个 JavaScript 解决方案

使用这个脚本非常简单。我们需要从[`github.com/imulus/retinajs/blob/master/dist/retina.min.js`](https://github.com/imulus/retinajs/blob/master/dist/retina.min.js)下载脚本。

然后，我们将脚本放在 HTML 的底部，就在闭合的`<body>`标签之前：

```html
<!DOCTYPE html>
<!--[if IE 8]> <html class="no-js ie8" lang="en"> <![endif]-->
<!--[if IE 9]> <html class="no-js ie9" lang="en"> <![endif]-->
<!--[if gt IE 9]><!--><html class="no-js" lang="en"><!--<![endif]-->
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Retina.js - JavaScript Solution</title>
</head>
<body>
   ...
   <script src="img/retina.min.js"></script>
</body>
</html>
```

### 提示

`Retina.js`脚本不依赖于框架。换句话说，它不需要 jQuery 或 Mootools 或 Dojo 或任何框架来……嗯，工作。

然后，我们在我们的标记中添加一个图像：

```html
<!DOCTYPE html>
<!--[if IE 8]> <html class="no-js ie8" lang="en"> <![endif]-->
<!--[if IE 9]> <html class="no-js ie9" lang="en"> <![endif]-->
<!--[if gt IE 9]><!--><html class="no-js" lang="en"><!--<![endif]-->
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Retina.js - JavaScript Solution</title>
</head>
<body>
   <img src="img/grandmasters-default.jpg" alt="">
   <script src="img/retina.min.js"></script>
</body>
</html>
```

就是这样！我们不必对标记做任何事情，除非我们想要排除被替换的图像。我将在接下来的内容中解释如何做到这一点。

`Retina.js`的 JavaScript 解决方案的基本功能是查找页面中的图像，并在服务器上存在高分辨率版本时用高分辨率版本替换它们。

您需要在高分辨率图像的名称末尾加上`@2x`修饰符。

换句话说，如果您有以下图像：

```html
<img src="img/grandmasters-default.jpg" alt="">
```

Retina.js 用以下内容替换它：

```html
<img src="img/strong>.jpg" alt="">
```

只要服务器上存在`@2x`图像，`Retina.js`就会替换它。如果图像不存在，它就不会替换。

### 不包括图片

如果您已经排除或希望排除图像被`Retina.js`替换，您可以为图像添加`data-no-retina`属性：

```html
<img src="img/grandmasters-default.jpg" alt="" data-no-retina>
```

## Retina.js——Sass mixin 解决方案

嗯，这很奇怪——一个 JavaScript 解决方案，竟然也有 CSS 解决方案？太棒了！请注意，这个 Sass mixin 是用于应用背景高分辨率图片的。

Sass mixin 如下所示：

```html
@mixin at2x($path, $ext: "jpg", $w: auto, $h: auto) {
    $at1x_path: "#{$path}.#{$ext}";
    $at2x_path: "#{$path}@2x.#{$ext}";

  background-image: url("#{$at1x_path}");

    @media all and (-webkit-min-device-pixel-ratio : 1.5),
        all and (-o-min-device-pixel-ratio: 3/2),
        all and (min--moz-device-pixel-ratio: 1.5),
        all and (min-device-pixel-ratio: 1.5) {
          background-image: url("#{$at2x_path}");
          background-size: $w $h;
  }
}
```

使用方法非常简单：

```html
.hero {
    width: 100%;
    height: 510px;
    @include at2x('../images/grandmasters-default', jpg, 100%, auto);
}
```

我们需要声明**文件扩展名**、**宽度**和**高度**，用逗号分隔的值。前面的 Sass 代码片段将编译为这样：

```html
.hero {
    width: 100%;
    height: 510px;
    background-image: url("../images/grandmasters-default.jpg");
}
@media all and (-webkit-min-device-pixel-ratio: 1.5), all and (-o-min-device-pixel-ratio: 3 / 2), all and (min--moz-device-pixel-ratio: 1.5), all and (min-device-pixel-ratio: 1.5) {
    .hero {
        background-image: url("../images/grandmasters-default@2x.jpg");
        background-size: 100% auto;
    }
}
```

这是我在 CodePen 上创建的演示：[`codepen.io/ricardozea/pen/c3af015b325da6ee56cf59e660f3cc03`](http://codepen.io/ricardozea/pen/c3af015b325da6ee56cf59e660f3cc03)

### 提示

使用`background-size: 100% auto;`，背景图像将拉伸到其父容器的最大宽度。但是，如果容器更宽，图像将被重复。

# 使视频响应式

我们要讨论的视频是嵌入在我们的好朋友`<iframe>`元素中的视频，比如来自 YouTube、Vimeo、Dailymotion 等的视频。有几种方法可以使视频响应式，有些方法比其他方法更复杂。让我们来分解一下。

## 使用 HTML 和 CSS 创建响应式视频

YouTube 是一个令人惊叹的视频服务，使视频作者、网页设计师和开发人员的生活更加轻松。YouTube 负责视频的托管、流媒体和技术条件，这些条件包括不支持 Flash（iOS）或不支持`<video>`标签（旧版浏览器）的浏览器，这真是太棒了。

我们需要做的第一件事是创建一个容器来容纳视频。这个容器是我们将要操作的，以便在保持其宽高比的同时给视频所需的宽度：

```html
<div class="video-container"></div>

```

然后，我们创建一个用于嵌入视频的容器：

```html
<div class="video-container">
   <div class="embed-container"></div>
</div>
```

然后，我们嵌入视频，视频位于`<iframe>`元素中：

```html
<div class="video-container">
    <div class="embed-container">
        <iframe width="560" height="315" src="img/vpRsLPI400U" frameborder="0" allowfullscreen></iframe>
    </div>
</div>
```

好了，这就是我们的标记。现在，让我们从内到外处理 CSS。

让我们给`<iframe>`元素添加一些属性：

```html
.embed-container iframe {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
}
```

然后，让我们给`.embed-container`包装器添加一些上下文：

```html
.embed-container {
    position: relative;
    padding-bottom: 56.25%;
    padding-top: 35px; /* This padding is only needed for YouTube videos */
    height: 0;
    overflow: hidden;
}
```

现在`<iframe>`元素将被正确定位并占据其父容器的所有空间。父容器将确保视频可见，任何超出父容器的部分将被隐藏。

### 提示

对于 16:9 宽高比的视频，请使用`padding-bottom: 56.25%;`。

对于 4:3 宽高比的视频，请使用`padding-bottom: 75%;`。

现在我们需要做的就是定义整个东西的宽度。我们通过为外部容器**.video-container**添加宽度来实现这一点：

```html
.video-container {
    width: 80%; /* This can be any width you want */
}
```

## 使用 jQuery 创建响应式视频

如果您是 jQuery 的粉丝，这个插件适合您。当您需要在网站上已经发布的视频上进行改装，或者需要手动更新太多视频时，它也可能会派上用场。

这个插件叫做 FitVids.js。它是由 Chris Coyer 和 Paravel 的人开发的。使用 FitVids.js 非常简单。首先，我们需要从以下 URL 下载 FitVids JavaScript 文件：[`github.com/davatron5000/FitVids.js/blob/master/jquery.fitvids.js`](https://github.com/davatron5000/FitVids.js/blob/master/jquery.fitvids.js)

然后，在文档的`<head>`中调用 jQuery 和 FitVids.js 文件。最后，在我们的标记底部添加一个脚本来调用`fitVids`函数。基本上就是这样。

### 提示

`FitVids.js`的实际文件名是`jquery.fitvids.js`。这是我们将在示例中看到的文件名。

这是一个包含两个视频的 HTML 片段，分别来自 YouTube 和 Vimeo 的`<iframe>`：

```html
<!DOCTYPE html>
<!--[if IE 8]> <html class="no-js ie8" lang="en"> <![endif]-->
<!--[if IE 9]> <html class="no-js ie9" lang="en"> <![endif]-->
<!--[if gt IE 9]><!--><html class="no-js" lang="en"><!--<![endif]-->
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
<script src="img/jquery.min.js"></script>
<script src="img/jquery.fitvids.js"></script>
    <title>Responsive Videos with: jQuery Using FitVids.js</title>
</head>
<body>
    <h1>Responsive Videos with: jQuery Using FitVids.js</h1>
    <main class="main-container" role="main">
        <h2>YouTube</h2>
        <iframe width="560" height="315" src="img/vpRsLPI400U" frameborder="0" allowfullscreen></iframe>
        <h2>Vimeo</h2>
        <iframe width="560" height="315" src="img/101875373" frameborder="0" webkitAllowFullScreen mozallowfullscreen allowFullScreen></iframe>
    </main>
    <script>
 $(function(){
 //Look for all the videos inside this element and make them responsive
 $(".main-container").fitVids();
 });
 </script>
</body>
</html>
```

如果你对`FitVids.js`如何修改 DOM 以使视频响应式感兴趣，这是标记：

```html
<div class="fluid-width-video-wrapper" style="padding-top: 56.25%;">
    <iframe src="img/vpRsLPI400U" frameborder="0" allowfullscreen="" id="fitvid0"></iframe>
</div>
```

### 提示

**文档对象模型**（**DOM**）：当你读到或听到有人说*修改 DOM*时，基本上意味着*修改生成的 HTML*。

这是我在 CodePen 上为此创建的演示：[`codepen.io/ricardozea/pen/9e994c213c0eeb64ccd627e132778a42`](http://codepen.io/ricardozea/pen/9e994c213c0eeb64ccd627e132778a42)。

## 使用纯 JavaScript 响应式视频

如果你不使用 jQuery 或不想要任何框架依赖，但仍需要一个简单的 JavaScript 解决方案，最好的选择是使用 Todd Motto 开发的脚本：`Fluidvids.js`。

使用它也很简单。首先，我们需要下载 Fluidvids JavaScript 文件：[`github.com/toddmotto/fluidvids/blob/master/dist/fluidvids.min.js`](https://github.com/toddmotto/fluidvids/blob/master/dist/fluidvids.min.js)

然后，我们需要在文档的`<head>`元素中调用`fluidvis.js`文件。一旦我们完成这一步，我们在标记底部添加一个小的脚本片段。就是这样。脚本将阅读标记，修改 DOM，并使它找到的任何视频*响应式*。

### 提示

确保始终为`<iframe>`元素提供`width`和`height`值。否则，页面上会出现空白空间。

这是你需要使其工作的 HTML 片段：

```html
<!DOCTYPE html>
<!--[if IE 8]> <html class="no-js ie8" lang="en"> <![endif]-->
<!--[if IE 9]> <html class="no-js ie9" lang="en"> <![endif]-->
<!--[if gt IE 9]><!--><html class="no-js" lang="en"><!--<![endif]-->
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <script src="img/fluidvids.min.js"></script>
    <title>Responsive Videos with: Plain JavaScript - FluidVids.js</title>
</head>
<body>
    <h1>Responsive Videos with: Plain JavaScript - FluidVids.js</h1>
    <main class="main-container" role="main">
        <h2>YouTube</h2>
        <iframe width="560" height="315" src="img/vpRsLPI400U" frameborder="0" allowfullscreen></iframe>
        <h2>Vimeo</h2>
        <iframe width="560" height="315" src="img/101875373" frameborder="0" webkitAllowFullScreen mozallowfullscreen allowFullScreen></iframe>
    </main>
    <script>
 fluidvids.init({
 selector: ['iframe'],
 players: ['www.youtube.com', 'player.vimeo.com']
 });
 </script>
</body>
</html>
```

这是修改后的 DOM：

```html
<div class="fluidvids" style="padding-top: 56.2%;">
    <iframe src="img/vpRsLPI400U" width="560" height="315" frameborder="0" allowfullscreen class="fluidvids-item" data-fluidvids="loaded"></iframe>
</div>
```

这是我在 CodePen 上为此创建的演示：[`codepen.io/ricardozea/pen/fda7c2c459392c934130f28cc092dbbe`](http://codepen.io/ricardozea/pen/fda7c2c459392c934130f28cc092dbbe)

## 第三方服务来嵌入视频

我能说什么呢？你只需要将浏览器指向[`embedresponsively.com/`](http://embedresponsively.com/)，并选择你想要使用的视频服务的选项卡。让我们选择 Vimeo。输入你想要使其响应式的视频的 URL，点击**嵌入**按钮，然后，你需要使用的 HTML 和 CSS 就会出现在示例视频的正下方。

这是由[embedresponsively.com](http://embedresponsively.com)生成的用于关于 RWD 的 Dan Mall 视频的 HTML 和 CSS 片段（已经格式化以便阅读）：

HTML 如下：

```html
<div class='embed-container'>
    <iframe src='https://player.vimeo.com/video/101875373' frameborder='0' webkitAllowFullScreen mozallowfullscreen allowFullScreen></iframe>
</div>
```

CSS 如下：

```html
.embed-container {
    position: relative;
    padding-bottom: 56.25%;
    height: 0;
    overflow: hidden;
    max-width: 100%;
}
.embed-container iframe,
.embed-container object,
.embed-container embed {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
}
```

然而，使用以下片段，视频的容器看起来比应该高得多。为了使前面的片段正常工作，我们需要将嵌入容器包装在外部容器内。这是修改后的标记和 CSS。

HTML 如下：

```html
<div class="video-container">
    <div class='embed-container'>
        <iframe src='https://player.vimeo.com/video/101875373' frameborder='0' webkitAllowFullScreen mozallowfullscreen allowFullScreen></iframe>
   </div>
</div>

```

CSS 如下：

```html
.video-container {
 width: 100%;
}
.embed-container {
    position: relative;
    padding-bottom: 56.25%;
    height: 0;
    overflow: hidden;
    background: red;
}
.embed-container iframe,
.embed-container object,
.embed-container embed {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
     height: 100%;
}
```

`.video-container`包装器是我们操纵的，以便定义任何我们想要的宽度，同时保持视频的纵横比。现在，我们只需要将标记放在我们的 HTML 文档中，将 CSS 片段放在我们的 SCSS 文件中。

这是我在 CodePen 上为此创建的演示：[`codepen.io/ricardozea/pen/10262216eeb01fc9d3b3bedb9f27c908`](http://codepen.io/ricardozea/pen/10262216eeb01fc9d3b3bedb9f27c908)

# 矢量格式

我们将看到一些 HTML 和 CSS/SCSS 片段，以了解如何使用图标字体和**SVG**，但我们不会详细介绍这些资产的创建过程，因为这个过程超出了本节的范围。

## 矢量或位图/光栅图像

当人们询问矢量和位图/光栅图像之间的区别时，我经常听到的答案通常围绕着“如果你放大它，它不会失去质量。对移动设备也不用担心。”虽然这是真的，但它并没有完全回答这个问题。所以这里是区别：

**矢量图像**是由数学方程组成的文件。这些方程的结果由图形（线条、形状、颜色）表示。如果图像的大小以任何方式改变，这些方程的值将被重新计算，生成的图形将被重新绘制。

**位图或光栅图像**是由像素组成的文件。这些像素具有特定/定义的宽度、高度和颜色。如果图像被放大，像素就会被拉伸，这就是为什么图像看起来模糊或呈像素化的原因。

有了这些定义，让我们来谈谈用于 RWD 的一些矢量格式。矢量格式包括：

+   Web 字体

+   图标字体

+   SVG

让我们看看如何快速实现图标字体和 SVG；Web 字体将在下一章中讨论。

## 图标字体

图标字体基本上是一个字体文件，但它不是字母，而是图标。有些人喜欢图标字体（我喜欢），有些人对它们并不太喜欢，特别是因为 SVG 变得如此受欢迎。

让我们看看图标字体的优缺点。

一些优点是：

+   图标字体的文件大小很可能比它们的 SVG 对应文件要小。我们可以在单个字体文件中有更多的图标，而且它的重量要比有一个 SVG 精灵要轻得多。

+   图标字体的属性可以用于修改文本的任何属性，例如颜色、字体系列、字重等。毕竟，它是一个字体。这意味着我们不必学习任何新的语法或属性。

+   它们相对容易实现。一旦所有的`@font-face`属性被设置，调用一个图标字体只是在 HTML 中添加一个类，并在 CSS 中调用一个特定的 Unicode 点代码。

+   图标字体是矢量图形，因此它们在任何屏幕密度、屏幕尺寸和缩放级别上都保持最佳质量。

+   它们非常适合设计。一个单独的图标字体可以被包裹在一个有颜色的容器中，图标可以被保留（挖空），但仍然是相同的图标，不需要单独的文件。

一些缺点是：

+   更新自定义设计的图标可能需要一些工作，因为我们需要使用第三方应用程序来生成我们的图标字体文件。

+   图标字体只能使用单一颜色。我真的不认为这是一个缺点。

+   图标字体的主要缺点之一是，实现一个备用方案以防字体文件加载失败有点复杂，而且如果你问我，有点啰嗦。这种模式的名称是“字体卫士”。如果你想了解更多，请查看 Zach Leatherman 的文章*Bulletproof Accessible Icon Fonts*（[`www.filamentgroup.com/lab/bulletproof_icon_fonts.html`](http://www.filamentgroup.com/lab/bulletproof_icon_fonts.html)）。GitHub 仓库可以在[`github.com/filamentgroup/a-font-garde`](https://github.com/filamentgroup/a-font-garde)找到。

在使用图标字体时，我可以给你一些建议：

+   如果可能的话，避免在关键内容中使用它们。

+   在使用图标字体的元素中始终提供一个`title=""`属性。如果字体文件加载失败，至少可以看到标题标签中的文本。

+   如果你愿意，可以使用额外的 HTML 元素来容纳图标。如果图标字体文件加载失败，无论用户是否使用辅助技术，都可以使用图标字体代表的功能。

+   在我的多年经验中，我从未见过图标字体文件加载失败，但这并不意味着它不可能发生。因此，我建议及时查看服务器日志，以确定图标字体文件是否被下载。如果没有，那么您需要尽快解决这个问题。

然后我们来实现一个图标字体。

### 实现图标字体

获取图标字体文件的最快方法是使用像 IcoMoon.io 或 Fontello.com 这样的第三方网络应用程序。您也可以获得 Font Awesome 的副本。

### 提示

在考虑使用 Font Awesome 时要小心。使用一个包含数十个图标的完整字体文件，只使用其中的一小部分是浪费带宽的。如果你只打算使用少量图标字体，使用 IcoMoon.io 或 Fontello.com 进行自定义图标选择是一个更好的选择。

一旦你能解压提供的文件，你唯一需要的文件就是`.woff`文件。你只需要这个文件的原因是因为浏览器对`.woff`文件的支持一直可以追溯到 IE9。除非你想/需要支持旧版浏览器（桌面和移动端），你可以使用`.eot`、`.ttf`和`.svg`文件。

### 提示

我建议你保持简单，避免在尝试支持旧版浏览器中出现不必要的麻烦。他们只会得到文本而不是图标，或者在`title=""`属性中显示文本。

让我们将图标字体文件命名为`icon-font.woff`。创建一个`/fonts`文件夹，并将`icon-font.woff`文件保存在其中。这是我们要尝试实现的：一个带有左侧图标的浅蓝色链接，没有下划线，以及 40px Arial/Helvetica 字体：

![实现图标字体](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_06_06.jpg)

#### 使用伪元素

使用伪元素的好处是我们的源标记始终保持清晰。在这种情况下，我们将使用`:before`伪元素，但这种技术也适用于`:after`伪元素。

让我们来看一下构建。

这是 HTML 片段：

```html
<a href="#" class="icon icon-headphones" title="Headphones">Headphones</a>
```

这是 SCSS。我们需要的第一件事是一个 mixin 来处理任何自定义网络字体。在这种情况下，它是一个图标字体：

```html
//Web font mixin
@mixin fontFace($font-family, $file-path) {
    @font-face {
        font: {
            family: $font-family;
            weight: normal;
            style: normal;
        }
    src: url('#{$file-path}.woff') format('woff');
    }
}
```

### 提示

注意`font: {…}`块中的嵌套属性。通过这样做，我们保持代码的 DRY，并避免重复术语*font*用于以下实例：`font-family`、`font-weight`和`font-style`。

然后，我们使用*属性选择器*创建一条规则来处理图标字体的基本样式属性：

```html
//Icon Font specific rule
[class^="icon-"], [class*=" icon-"] {
    font: {
        family: icon-font, Arial, "Helvetica Neue", Helvetica, sans-serif;
        weight: normal;
        style: normal;
        variant: normal;
    }
    text-transform: none;
    line-height: 1;
    speak: none;
    // Improve Font Rendering
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}
```

### 提示

注意属性选择器中的`^`和`*`字符。第一个意味着*选择以术语* `icon-` *开头的元素*，第二个*选择包含术语* `icon-` *的元素*。

然后，我们需要调用`fontFace` mixin 来将字体引入编译后的 CSS 文件中：

```html
@include fontFace(icon-font, '/fonts/icon-font');
```

`fontFace` mixin 的好处是我们只需要声明字体名称，然后是文件路径。不需要声明文件扩展名；这由 mixin 来处理。

这将编译为：

```html
@font-face {
    font-family: icon-font;
    font-weight: normal;
  font-style: normal;
  src: url("/fonts/icon-font") format("woff");
}
```

这是使用`:before`使魔法发生的规则：

```html
.icon-headphones:before {
    content: "\e601";
    margin-right: 10px;
}
```

为了基本的样式增强，我们创建了另外两条规则。但是，它们并不是必需的。代码如下：

```html
.icon { font-size: 40px; }

a {
    padding: 5px;
    text-decoration: none;
    color: #2963BD;
    transition: .3s;
    &:hover { color: lighten(#2963BD,20); }
    &:focus { outline: 2px solid orange; }
}
```

最终编译的 CSS 如下：

```html
[class^="icon-"], [class*=" icon-"] {
    font-family: icon-font, Arial, "Helvetica Neue", Helvetica, sans-serif;
    font-weight: normal;
    font-style: normal;
    font-variant: normal;
    text-transform: none;
    line-height: 1;
    speak: none;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}
@font-face {
    font-family: icon-font;
    font-weight: normal;
    font-style: normal;
    src: url("https://s3-us-west-2.amazonaws.com/s.cdpn.io/9988/icon-font.woff") format("woff");
}

.icon-headphones:before {
    content: "\e601";
    margin-right: 10px;
}
.icon {
    font-size: 40px;
}
a {
    padding: 5px;
    text-decoration: none;
    color: #2963BD;
    -webkit-transition: .3s;
        transition: .3s;
}
a:hover {
    color: #6d9adf;
}
a:focus {
    outline: 2px solid orange;
}
```

这是我在 CodePen 上为此创建的演示：[`codepen.io/ricardozea/pen/e62b201350efe7f59f91c934f9fc30fa`](http://codepen.io/ricardozea/pen/e62b201350efe7f59f91c934f9fc30fa)

这是我在 CodePen 上创建的另一个演示，其中图标字体更加高级：[`codepen.io/ricardozea/pen/5a16adffb6565312506c47ca3df69358`](http://codepen.io/ricardozea/pen/5a16adffb6565312506c47ca3df69358)

#### 使用额外的 HTML 元素

老实说，使用额外的 HTML 元素有点违背了将内容与样式分离的原则，因为出于样式原因添加额外的 HTML 元素并不是一些开发人员推荐的做法。然而，我们也可以说图标本身确实是内容，而不是样式。无论如何，这是概述。

这是 HTML 片段：

```html
<a href="#" title="Headphones"><i class="icon-headphones" aria-hidden="true"></i>Headphones</a>
```

### 提示

为了隐藏屏幕阅读器中的不相关内容，我们使用`aria-hidden="true"`指令。

前面示例中的 SCSS 代码几乎相同，只是我们将`.icon`类中的`font-size: 10px;`声明移到`a`规则中，然后完全删除`.icon`类。你还会看到一些额外的属性，但只是出于样式原因。

最终的 SCSS 如下：

```html
//Web font mixin
@mixin fontFace($font-family, $file-path) {
    @font-face {
        font: {
        family: $font-family;
        weight: normal;
        style: normal;
    }
    src: url('#{$file-path}.woff') format('woff');
    }
}
//Icon Font specific rule
[class^="icon-"], [class*=" icon-"] {
    font: {
        family: icon-font, Arial, "Helvetica Neue", Helvetica, sans-serif;
        weight: normal;
        style: normal;
        variant: normal;
    }
    text-transform: none;
    line-height: 1;
    speak: none;
    // Improve Font Rendering
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}
@include iconFont(icon-font, '/fonts/icon-font');
.icon-headphones:before {
    content: "\e601";
    margin-right: 10px;
}
a {
   font-size: 40px;
    //Styling stuff
    padding: 5px;
    text-decoration: none;
    color: #2963BD;
    transition: .3s;
    &:hover { color: lighten(#2963BD,20); }
    &:focus { outline: 2px solid orange; }
}
```

编译后的 CSS 如下：

```html
[class^="icon-"], [class*=" icon-"] {
    font-family: icon-font, Arial, "Helvetica Neue", Helvetica, sans-serif;
    font-weight: normal;
    font-style: normal;
    font-variant: normal;
    text-transform: none;
    line-height: 1;
    speak: none;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}

@font-face {
    font-family: icon-font;
    font-weight: normal;
    font-style: normal;
    src: url("https://s3-us-west-2.amazonaws.com/s.cdpn.io/9988/icon-font.woff") format("woff");
}
.icon-headphones:before {
    content: "\e601";
    margin-right: 10px;
}

a {
    font-size: 40px;
    padding: 5px;
    text-decoration: none;
    color: #2963BD;
    -webkit-transition: .3s;
          transition: .3s;
}
a:hover {
    color: #6d9adf;
}
a:focus {
    outline: 2px solid orange;
}
```

这是我在 CodePen 上为此创建的演示：[`codepen.io/ricardozea/pen/8ca49cb06aeb070f4643f0a8e064126c`](http://codepen.io/ricardozea/pen/8ca49cb06aeb070f4643f0a8e064126c)。

## 可缩放矢量图形

SVG 图形非常快速地获得了令人难以置信的流行。浏览器支持度为 100%，甚至 Opera Mini 也支持 SVG 图像。让我们讨论一些 SVG 图像的优缺点：

SVG 的优点：

+   它们可以用文本编辑器创建和编辑。

+   它们 100%可访问。

+   它们可以有多种颜色。

+   它们对 SEO 友好，因为它们可以被索引。

+   由于它们是矢量图形，它们在任何屏幕密度、屏幕尺寸或缩放级别上都保持其质量。

+   它们可以被动画化，甚至是`<svg>`标签内的元素。

+   SVG 规范是由 W3C 开发的一个实际的开放标准。

+   这可能比使用字体进行图形更语义化。

+   第三方在线图标工具也可以导出为 SVG，除了图标字体。

+   现代浏览器中支持度为 100%。

SVG 的缺点：

+   一个 SVG 精灵文件可能比其图标字体对应文件更重。

+   如果需要支持旧版浏览器（IE8 及以下），则需要图像回退。

+   通常可以保存为 SVG 的软件会在最终文件中添加额外的不必要的标记，因此我们要么必须手动删除它，要么使用第三方优化工具为我们每个文件执行此操作。这反过来又给开发工作流程增加了另一层复杂性。

+   尽管 SVG 是用 XML 结构制作的，但需要相当高级的理解水平才能在文本编辑器中进行编辑。

SVG 文件基本上是一个 XML 格式的文件。这是耳机图形的标记样式：

```html
<svg  width="32" height="32" viewBox="0 0 32 32">
        <path id="left-ear-pad" d="M9 18h-2v14h2c0.55 0 1-0.45 1-1v-12c0-0.55-0.45-1-1-1z"/>
    <path id="right-ear-pad" d="M23 18c-0.55 0-1 0.45-1 1v12c0 0.6 0.5 1 1 1h2v-14h-2z"/>
        <path id="headband" d="M32 16c0-8.837-7.163-16-16-16s-16 7.163-16 16c0 1.9 0.3 3.8 1 5.464-0.609 1.038-0.958 2.246-0.958 3.5 0 3.5 2.6 6.4 6 6.929v-13.857c-0.997 0.143-1.927 0.495-2.742 1.012-0.168-0.835-0.258-1.699-0.258-2.584 0-7.18 5.82-13 13-13s13 5.8 13 13c0 0.885-0.088 1.749-0.257 2.584-0.816-0.517-1.745-0.87-2.743-1.013v13.858c3.392-0.485 6-3.402 6-6.929 0-1.29-0.349-2.498-0.958-3.536 0.62-1.705 0.958-3.545 0.958-5.465z"/>
</svg>
```

有许多使用 SVG 图像的方法：通过`<img>`、`<object>`、`<use>`或`<svg>`标签内联；作为 CSS 的背景图像；使用 Modernizr 在条件类中使用回退；或者使用 jQuery 或纯 JavaScript，使用第三方服务如 grumpicon.com 等。

为了保持简单，我们将专注于两种方法：

+   通过`<svg>`标签内联。

+   基于文件的`<img>`标签。

### 通过`<svg>`标签内联

内联 SVG 是许多网页设计师和开发人员的首选方法。我们可以使用 CSS 和 JavaScript 控制 SVG 的各个部分，这使得它非常适合动画效果。

内联 SVG 标记的一个缺点是图像不可缓存。换句话说，每次图像出现时，浏览器都必须读取 SVG 的 XML。如果页面上有太多的 SVG，这可能对页面速度和最终用户体验造成潜在的危害。因此，请注意页面的目标和使用您的网站/应用程序的访问者类型。

这是 SVG 耳机的 HTML 片段，内联在链接标签中：

```html
<a href="#">
    <svg  width="32" height="32" viewBox="0 0 32 32">
        <path id="left-ear-pad" d="M9 18h-2v14h2c0.55 0 1-0.45 1-1v-12c0-0.55-0.45-1-1-1z" />
    <path id="right-ear-pad" d="M23 18c-0.55 0-1 0.45-1 1v12c0 0.6 0.5 1 1 1h2v-14h-2z" />
        <path id="headband" d="M32 16c0-8.837-7.163-16-16-16s-16 7.163-16 16c0 1.9 0.3 3.8 1 5.464-0.609 1.038-0.958 2.246-0.958 3.5 0 3.5 2.6 6.4 6 6.929v-13.857c-0.997 0.143-1.927 0.495-2.742 1.012-0.168-0.835-0.258-1.699-0.258-2.584 0-7.18 5.82-13 13-13s13 5.8 13 13c0 0.885-0.088 1.749-0.257 2.584-0.816-0.517-1.745-0.87-2.743-1.013v13.858c3.392-0.485 6-3.402 6-6.929 0-1.29-0.349-2.498-0.958-3.536 0.62-1.705 0.958-3.545 0.958-5.465z"/>
    </svg>Headphones
</a>
```

为了控制其大小、与文本的距离和外观，我们添加以下 CSS：

```html
svg {
    width: 40px;
    height: 40px;
    margin-right: 10px;
    fill: #2963BD;
}
a {
    font-size: 40px;
    text-decoration: none;
    color:#2963BD;
}
```

### 提示

通过`<img>`标签调用的 SVG 文件*不受*CSS 的影响。如果要对其进行任何样式更改，必须在实际的 SVG 文件中进行更改，或者将 SVG 标记内联。

然而，这个标记有一个问题。它没有为旧版浏览器提供回退，特别是 IE8 及以下版本。让我们试着解决这个问题。

#### 为内联 SVG 提供回退图像给旧版浏览器

为内联 SVG 提供回退图像的两种方法。

##### 使用`<foreignObject>`和`<img>`标签

在`<svg>`标签内创建一个`<foreignObject>`元素，并包含调用回退图像的`<img>`标签：

```html
<a href="#">
    <svg   version="1.1" width="32" height="32" viewBox="0 0 32 32">
        <path d="M9 18h-2v14h2c0.55 0 1-0.45 1-1v-12c0-0.55-0.45-1-1-1z"/>
        <path d="M23 18c-0.55 0-1 0.45-1 1v12c0 0.6 0.5 1 1 1h2v-14h-2z"/>
        <path d="M32 16c0-8.837-7.163-16-16-16s-16 7.163-16 16c0 1.9 0.3 3.8 1 5.464-0.609 1.038-0.958 2.246-0.958 3.5 0 3.5 2.6 6.4 6 6.929v-13.857c-0.997 0.143-1.927 0.495-2.742 1.012-0.168-0.835-0.258-1.699-0.258-2.584 0-7.18 5.82-13 13-13s13 5.8 13 13c0 0.885-0.088 1.749-0.257 2.584-0.816-0.517-1.745-0.87-2.743-1.013v13.858c3.392-0.485 6-3.402 6-6.929 0-1.29-0.349-2.498-0.958-3.536 0.62-1.705 0.958-3.545 0.958-5.465z"/>
        <foreignObject>
 <img src="img/headphones.png" alt="Headphones">
 </foreignObject>
    </svg>Headphones
</a>
```

##### 使用`<image>`标签

众所周知，在 SVG 世界中没有`<image>`标签...或者有吗？在 SVG 世界中，是有的！这个解决方案与第一种方法非常相似。两个不同之处在于我们不使用`<foreignObject>`元素，并且使用`<image>`标签。这一切都在`<svg>`标签内部：

```html
<a href="#">
    <svg  width="32" height="32" viewBox="0 0 32 32">
        <path id="left-ear-pad" d="M9 18h-2v14h2c0.55 0 1-0.45 1-1v-12c0-0.55-0.45-1-1-1z" />
        <path id="right-ear-pad" d="M23 18c-0.55 0-1 0.45-1 1v12c0 0.6 0.5 1 1 1h2v-14h-2z" />
        <path id="headband" d="M32 16c0-8.837-7.163-16-16-16s-16 7.163-16 16c0 1.9 0.3 3.8 1 5.464-0.609 1.038-0.958 2.246-0.958 3.5 0 3.5 2.6 6.4 6 6.929v-13.857c-0.997 0.143-1.927 0.495-2.742 1.012-0.168-0.835-0.258-1.699-0.258-2.584 0-7.18 5.82-13 13-13s13 5.8 13 13c0 0.885-0.088 1.749-0.257 2.584-0.816-0.517-1.745-0.87-2.743-1.013v13.858c3.392-0.485 6-3.402 6-6.929 0-1.29-0.349-2.498-0.958-3.536 0.62-1.705 0.958-3.545 0.958-5.465z"/>
        <image src="img/headphones.png" xlink:href="" alt="Headphones">
    </svg>Headphones
</a>
```

现在，这个方法有效的原因是因为我们将 SVG 和 HTML 的特性结合到一个元素中。

SVG 的特点是`<image>`标签是 SVG 世界中的有效元素。现在，尽管听起来很奇怪，但所有浏览器都将`<image>`标签视为一个超出标准的标签，类似于 HTML 中的`<img>`标签。

HTML 的特点是，通常我们使用`src`属性来指向资源的位置。在 SVG 世界中，资源被称为`xlink:href`属性。如果我们添加一个指向资源的`src`属性，并且将`xlink:href`属性留空，那么旧版浏览器将看到备用图像，而现代浏览器不会，因为`xlink:href`属性是空的。

我建议坚持第二种方法；它更简洁，更省事。只要记住，我们使用`<image>`而不是`<img>`。另外，为了本书的目的，我在标记中保留了`xlink:href`属性，但这是可选的。如果它是空的，你可以根据需要完全删除它。

### 提示

在整本书中，我已经删除了自闭合标签的尾部斜杠`/>`，比如`<hr>`或`<img>`元素。在 HTML5 中，可以选择带或不带。然而，在 SVG 的`path`元素中，尾部斜杠**是必需的**，这就是为什么你在这些示例中看到它们的原因。

我刚刚提到的这些方法都不会在支持 SVG 的浏览器上导致双重下载。如果你问我，这是一个双赢的局面。

### 基于文件的 xlink:href 和 src 属性

SVG 是一种图像文件，因此在`<img>`中调用它是完全有效的：

```html
<img src="img/headphones.svg" alt="Headphones">
```

我们知道 SVG 在现代浏览器中有无缺的支持，但在旧版浏览器（IE8 及以下）中不显示先前的图像。

记得之前关于 SVG 和 HTML 中`xlink:href`和`src`属性的解释吗？嗯，我们要做的基本上和之前一样。不过，与其内联 SVG 标记，我们只是链接到一个 SVG 文件，同时为旧浏览器提供一个备用图像。

这个聪明的技巧是由 Alexey Ten 创建的。这是标记：

```html
<a href="#">
    <svg width="39" height="39">
        <image xlink:href="https://s3-us-west-2.amazonaws.com/s.cdpn.io/9988/headphones.svg" src="img/strong>" width="39" height="39">
    </svg>Headphones
</a>
```

**这里也有问题。Alexey 的技术不是问题，问题在于浏览器——特别是 IE9、10 和 11 以及 iOS 3 和 4。它们会同时下载 SVG 和备用图像。**

**如果这种双重下载对你来说是可以接受的，并且你理解后果，那就去做吧。尽管如此，记住在下一个项目中可以改进这样的事情。**

**这是我在 CodePen 上为此创建的演示：**

**[`codepen.io/ricardozea/pen/594e718f36976f8e77d4f9cf1640e29a`](http://codepen.io/ricardozea/pen/594e718f36976f8e77d4f9cf1640e29a)**

#### **学习 SVG 的其他来源**

**我们谈论 SVG 时，不能不提到当今网络设计和开发行业中最引人注目的三个名字：Amelia Bellamy-Royds、Sara Soueidan 和 Chris Coyer。Amelia 和 Chris 创建了我读过的关于如何使用带有备用的 SVG 的最完整指南之一，《A Complete Guide to SVG Fallbacks》([`css-tricks.com/a-complete-guide-to-svg-fallbacks/`](https://css-tricks.com/a-complete-guide-to-svg-fallbacks/))。**

**如果你想学习关于 SVG 的一切，Sara Soueidan 的博客是必读的：[`sarasoueidan.com/articles/`](http://sarasoueidan.com/articles/)。**

**# 总结

在这里，我们正在看着地平线，思考着`srcset`或`<picture>`？调整大小还是艺术方向？`Retina.js`还是 Sass mixin？FitVids 还是 FluidVids？图标字体还是 SVG？内联 SVG 还是基于文件的 SVG？什么是为我们的访客提供最佳体验的最佳方式？

是的，我知道这种感觉。你知道吗？这是一个好问题。否则，我们就不会学习如何掌握 RWD 了。

由于大多数时候我们只是调整图片大小，`srcset`是一个不错的选择。将我们的视频放入一个容器并加上几行 CSS，这样视频就能立即响应。太多的视频需要响应？没问题，`FitVids.js`可以通过一个单独的 jQuery 函数实现。图标字体比它们的大哥 SVG 文件要轻，但要注意服务器日志，以防图标字体文件没有下载。使用 SVG 始终是一个胜利，即使有双重下载，但要通过使用不同的技术不断提升水平，并与他人分享你的发现和经验。

让我们换个话题，谈谈一个迷人的主题，它可以决定你的响应式设计成败：排版。

让我们出发吧！**
