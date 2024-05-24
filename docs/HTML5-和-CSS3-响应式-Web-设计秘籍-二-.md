# HTML5 和 CSS3 响应式 Web 设计秘籍（二）

> 原文：[`zh.annas-archive.org/md5/C01303DDF6D777B47AE9F2BC988AE6B5`](https://zh.annas-archive.org/md5/C01303DDF6D777B47AE9F2BC988AE6B5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用响应式框架

在本章中，你将学习：

+   使用流体 960 网格布局

+   使用蓝图网格布局

+   使用三分之一规则的流体布局

+   尝试 Gumby，一个响应式 960 网格

+   Bootstrap 框架使响应式布局变得容易

# 介绍

布局框架在布局设计和开发中变得越来越有用和普遍。许多网页开发人员发现，通过将他们的设计调整到一个框架中，他们可以大大加快生产速度。

有许多好的框架，乍一看可能会觉得启动起来太费劲，否则你将不得不牺牲太多设计来适应别人的方法。至少，这是我一开始的想法。实际上，我发现学习和使用框架让我更专注于项目中我喜欢的部分，并帮助我更快地完成项目。实质上，使用框架可能会导致你的最终产品看起来像框架。有时，这可能并不是一个糟糕的想法，也就是说，拥有一个工具集，可以帮助你更快、更好地开发网站。有许多可用的框架；有些是基本的，需要你在设计和开发上投入更多时间，但你对最终产品有更多的控制；另一些提供更多的功能，但框架指导你的设计，如果没有完全重新设计，将很难改变。

那么，哪个框架适合你呢？答案当然是：这取决于项目需求。我建议在本章中尝试一些示例，并准备好一些工具来构建项目。

# 使用流体 960 网格布局

960 网格系统已经存在一段时间，并且已经被证明在快速部署新项目方面非常有用。它相当简单易学，学习曲线很快，你就可以开始使用它了。

唯一的问题是它不是响应式的。事实上，它的行为很像使用固定宽度表头的列跨越固定宽度表头的表格。它在 960 像素宽的窗口中布局得很好，就是这样，你只能在一个浏览器窗口尺寸下看到良好的视图。那么在一个关于响应式设计的书中为什么还要讨论 960 网格呢？答案是有些人非常喜欢它，以至于他们决定解决这个问题。

## 准备工作

这方面有很好的解决方案，希望你可以在本章中找到。跟着我，我会在这个示例中向你展示一个更简单的版本。960 网格系统的简单响应式版本实际上更准确地描述为**流体网格**。它用百分比宽度替换了大部分固定宽度网格元素，左浮动元素。这样做效果很好，但当列变窄时，阅读可能会变得困难。我们可以通过一些额外的 CSS 很容易地解决这个问题。

我们最终希望页面能够对屏幕变化做出更精细的响应，以更改网格在不同屏幕尺寸下的布局。

首先，去[`www.designinfluences.com/fluid960gs/`](http://www.designinfluences.com/fluid960gs/)获取流体 960 网格系统。然后，下载并解压存档文件。将存档的`CSS`文件夹中的`grid.css`文件复制到项目的`CSS`文件夹中。接下来，在你的`CSS`目录中创建一个名为`responsive.css`的新 CSS 文件。我们稍后会回到这个文件。

## 如何做...

在你的 IDE 中创建一个新的 HTML 文件。添加链接到`grid.css`文件和你的新 CSS 文件`responsive.css`。

```html
<link rel="stylesheet" href="css/grid.css" media="screen" />
<link rel="stylesheet" href="css/responsive.css" media="screen" />
```

接下来，在 HTML 主体中创建一些内容。然后，为了使流体 960 网格工作，首先添加一个包装的`div`元素，其中包含一个定义内部列数的类。对于这个示例，使用`containter_16`类，共有 16 个可用列。你还可以通过将`div`元素分配给`container_12`类来拥有 12 列。

在`container_16`元素内，首先创建一个头部的容器。创建一个带有`grid_16`类的新的`div`元素。你可能已经猜到了，`grid_16`类占据了整个`container_16` div 的宽度。这是一个相当好的猜测；你有 98%的正确率；它实际上占据了 98%的宽度，或者所有 16 列，外部有 2%的填充。如果你使用了`grid_11`类，它将占据 11 列，或者 66.75%的宽度，外部有 2%的填充。

为了创建新的一行，我们添加另一个`div`元素，这次使用`clear`类。这与键盘上的*Enter*键或某些编程语言中的换行符(`\n`)类似。在行之间需要添加`clear`元素，因为它们的位置是由`left:float`属性设置的，这个属性没有垂直空间。

```html
<div class="clear"></div>
```

同样的效果也可以通过使用简单的断点来实现，如下所示：

```html
<br class="clear"> 
```

你需要在每一行之间添加`clear` div 或断点。

现在，我们将专注于内容！在你的`clear`元素之后，添加六个新的`div`元素。给第一个元素添加`grid_3`类，第二个元素添加`grid_5`类，其余的元素添加`grid_2`类。顺序不重要，只要`grid_*`后面的数字加起来等于 16。在`div`元素中插入一些 Ipsum 填充文本([`lipsum.com`](http://lipsum.com))。你的代码会看起来像这样：

```html
<div class="container_16">
<div class="grid_16">
<h2>Fluid Grid</h2>
</div>
<div class="clear"></div>
<div class="grid_3">Loremipsum dolor sit amet...</div>
<div class="grid_5">Curabitursapien ante, pretium...</div>
<div class="grid_2">tiam quam tortor, necsagittis ...</div>
<div class="grid_2">Donecmollisconsequatarcuvel...</div>
<div class="grid_2">Nullam sit amet magna dui. In dictum...</div>
<div class="grid_2">Etiamsuscipitvariuspharetra...</div>
</div>
```

在下面的截图中，你可以看到流体网格在较小的视口上是如何崩溃的：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_04_01.jpg)

下一步是更新你的 CSS，为流体布局添加一些响应性。现在，打开你的 IDE 中的`responsive.css`文件进行编辑。添加媒体查询以覆盖较小的屏幕断点：`1024px`，`600px`和`420px`，如下面的代码片段所示：

```html
@media screen and (max-width:420px){...}
@media screen and (max-width:600px) and (min-width:421px){...}
@media screen and (max-width:1024px) and (min-width:601px){...}
```

我们的目的是创建一些新的 CSS，覆盖流体网格，并为内容元素创建新的固定断点。在较窄的宽度下，我们希望一个元素有更大的百分比宽度，或者固定宽度。为了进行覆盖，我们将在媒体查询中添加一个新的类：`.break-column`。

接下来，在`max-width:420px`媒体查询中，为`.break-column`元素类添加`min-width`值为`360px`。然后，在新的媒体查询中，`max-width:600px`和`min-width:421px`，添加`.grid_2.break-column`、`.grid_3.break-column`和`.grid_5.break-column`元素类以及它们的`width:48%`属性。在这三个媒体查询中最大的一个中，添加一个带有`width:30%`属性的类，后面跟着`!important`覆盖(确保它在分号之前插入)，如下面的代码片段所示：

```html
@media screen and (max-width:420px){
   .break-column{min-width:360px;} 
}
@media screen and (min-width:421px) and (max-width:600px){ 
   .grid_2.break-column, .grid_3.break-column, .grid_5.break-column{width:48%;}
}
@media screen and (max-width:1024px) and (min-width:601px){
   .break-column{width:30% !important;}
}
```

一个响应式流体网格的最后一步！再次打开你的 HTML 文件，并给每个六个`div`元素添加一个`break-column`类。食谱就完成了。刷新你的浏览器，或者打开 HTML 文件查看。当你缩小浏览器窗口或在移动设备上打开文件时，你会看到布局会根据较小的视图做出响应并优化布局。流体网格如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_04_02.jpg)

## 工作原理...

当你在浏览器中打开未更新的(流体和非响应式)HTML 文件时，你会看到六列，它们会在浏览器窗口或设备变小的时候保持它们相同的比例宽度。当在小窗口或移动设备中查看时，它会显示六列不可读的窄列。

添加媒体查询是通过覆盖`div`元素的样式属性来实现的。我用三种不同的方法演示了覆盖：首先，`min-width`方法覆盖了百分比宽度；接下来，由于`responsive.css`文件跟随`grid.css`文件，并且 CSS 是显式命名空间（`.grid_2.break-column`，`.grid_3.break-column`和`.grid_5.break-column`），它覆盖了在`grid.css`文件中声明的流体宽度，在最后一种情况下，`!important`声明会压倒所有其他覆盖级联。

# 使用 Blueprint 网格布局

**Blueprint CSS**框架是另一个流行的静态 CSS 网格系统。可能会有这样一种情况，你需要将静态 Blueprint CSS 网格框架变成你自己的响应式 Blueprint 框架。这个框架很容易分解成一个响应式布局。只需要插入一些简单的 CSS 断点，你就有了一个响应式框架。

## 做好准备

首先去获取 Blueprint CSS 框架。你可以在[`www.blueprintcss.org/`](http://www.blueprintcss.org/)下载它。这个框架与其他静态 CSS 网格框架类似。

## 如何做……

一旦你下载了 Blueprint 框架，解压文件并将`blueprint`文件夹复制到你的`CSS`目录中。接下来我们将开始构建 HTML 文件，以便与 Blueprint CSS 框架一起使用。在你的 IDE 中创建一个新的 HTML 文件。在 body 内部，添加一个标题，然后添加一个`hr`元素。

“啥？什么？”，你可能会问。这是一个水平规则——一个主题性的分隔符。让我解释一下。

在以前的 HTML 版本中，`hr`是一个水平规则。意思是它像一个分隔符一样起作用，但是在页面上放置一条水平线。它在 HTML5 中得到了升级，现在是一个主题性的分隔符。那么有什么区别呢？它本身仍然做着同样的事情，即在页面上放置一条水平线。然而，在过去它被用来定义布局，但现在它强调了主题或内容的变化。

然而，在 Blueprint CSS 中，`hr`元素被专门用来捕捉一行。好吗？让我们回到手头的任务。

在你的`hr`元素之后，你可以开始一行内容。首先为第一行创建一个三列布局。然后，在三个`div`元素中插入一些 Ipsum（[`Ipsum.com`](http://Ipsum.com)）文本。就像 960 Grid 一样，这就像一个表格`colspan`，你给`div`元素分配一个与你想要跨越的列数相对应的类。总列数是 22。前三个类将是：`span-7`，`span-8`和`span-7`。用另一个主题性的分隔符跟着同样的步骤：

```html
<h1>Blueprint CSS Framework Responsive<h2>
<hr>
  <div class="span-7">Loremipsum dolor sit amet, 
   consecteturadipiscingelit...</div>
  <div class="span-8">Etiamegettortorlectus, et 
   variusnibh...</div>
  <div class="span-7">Duis sit 
   ametfelislobortisfeliscommodolacinia...</div>
<hr>
```

在你的下一行中，添加两个大列。在它们中间添加两个带有类`span-15`和`span-7`的 div。在左侧的`div`元素中，添加一段 Ipsum 文本和一张图片。在右侧列中，添加一列 Ipsum 文本句子的无序列表。然后用一个水平规则关闭这一行：

```html
<hr />
<div class="span-15">
    <img src="img/test.jpg" class="top pull-1 left" alt="test">
    <p>Loremipsum dolor sit amet, consectetueradipiscingelit...</p>
</div>
<div class="span-7">
<ul>
<li>Loremipsum dolor sit amet, consectetueradipiscingelit...</li>
<li>Loremipsum dolor sit amet, consectetueradipiscingelit...</li>
<li>Loremipsum dolor sit amet, consectetueradipiscingelit...</li>
</ul>
</div>
<hr /> 
```

这是我们想要为这个配方构建的大部分 HTML。如果你想要更多，你可以在你下载的存档的`tests`文件夹中看到`sample.html`文件。

在你的 HTML 头部，添加链接到`css/Blueprint/`目录中的 Blueprint CSS 框架样式表。

接下来，让我们添加我们自己的样式表，使框架成为一个响应式的框架。在你的头部添加一个新的链接到新的样式表`responsive.css`。如果你还没有添加 CSS 文件，那么添加新的`responsive.css`样式表：

```html
<link rel="stylesheet" href="css/responsive.css"  >
```

打开`responsive.css`样式表。为最小的断点和下一个断点创建一个媒体查询。将媒体查询断点设置为`600px`和`1024px`，如下所示：

```html
@media screen and (max-width:600px) {...}
@media screen and (min-width:601px) and (max-width:1024px) {...}
```

在其中，我们将使用一种称为**属性选择器**的 CSS 技巧。这就像使用通配符`*`。为了使属性应用于 Blueprint CSS 网格中的所有列 span 类，比如`span-1`、`span-2`、`span-3`等，你可以这样写：`div[class*='span']{...}`。这是在 CSS 网格中进行响应式覆盖的一个很好的技巧。

在`600px`的媒体查询中，使用属性选择器添加 CSS，并添加一个宽度为`90%`。当浏览器窗口小于`600px`时，这将使所有的 span 扩展到 100%。在`1024px`的媒体查询中，使用宽度为`42%`。如果你期望得到像 100%和 50%这样的漂亮的整数，你可能会感到惊讶；但请记住，Blueprint CSS 已经添加了填充。

```html
@media screen and (max-width:600px){
   div[class*='span-']{width:90%;}
}
@media screen and (min-width:601px) and (max-width:1024px){
   div[class*='span-']{width:42%;} 
}
```

在浏览器中打开 HTML 文件或刷新屏幕，你会发现当你改变浏览器宽度时，这些 span 会自动调整到新的宽度。

当你达到`1024px`的断点时，你可能会注意到第二行留下了太多的空白空间。让我们来修复一下。在`1024px`的媒体查询中复制你的属性选择器 CSS 行，并将其粘贴在下面。在属性选择器后面添加一个`.wide`类。给它一个宽度为`90%`。

在你的 HTML 文件中，在第二个主题分隔符（`hr`）后的第一个 span 中添加一个`wide`类，其中包含图像。

这在最新的浏览器上效果很好，但在旧的浏览器上还不行。我们需要添加几行 CSS 代码，使其在更多的浏览器中起作用。在你的`responsive.css`文件中，在第一行添加`.container`类，并给它一个宽度为`960px`的属性。然后在每个媒体查询中添加相同的类，但将宽度更改为`100%`。

```html
.container{width:960px}
@media screen and (max-width:600px){
     div[class*='span-']{width:90%;}
     .container{width:100%}
}
@media screen and (min-width:601px) and (max-width:1024px){
     div[class*='span-']{width:42%;}   
     div[class*='span-'].wide{width:90%;}   
     .container{width:100%}
}
```

这将有助于防止在不支持媒体查询的旧浏览器中出现问题。

为了增加一些额外的乐趣，给这些 span 添加一些 CSS3 过渡效果。这将使受影响的 span 的宽度平滑地动画过渡。这些操作都是在任何媒体查询之外进行的。

```html
div[class*='span-']{

-moz-transition: width 0.1s; /* Firefox 4 */
-webkit-transition: width 0.1s; /* Safari and Chrome */
-o-transition: width 0.1s; /* Opera */
transition: width 0.1s;

}
```

有了这个额外的小提示，你可以在每个媒体查询中做一些更花哨的响应式设计。新的响应式蓝图如下截图所示：

![如何做....](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_04_03.jpg)

## 它是如何工作的...

为了使 Blueprint CSS 框架具有响应性，我们首先将其容器宽度从静态宽度更改为流体最大宽度，并在断点处添加了媒体查询。这个配方的关键成分是属性选择器，它允许我们向 CSS 抛出一个通配符，避免了需要重新编码每个 span 的属性。

# 使用三分之一规则的流体布局

**三分之一规则**是一种设计方法论，它规定如果一个布局或图像被水平或垂直地分成三部分，那么它会变得更有趣。就像与互联网相关的其他一切一样，关于它有无尽的讨论和辩论。对于本书的目的，我们只关心如何使它有用。

至少在我看来，搜索结果中没有基于三分之一规则的响应和流体布局的索引。然而，有一个基于三分之一规则的良好静态框架。它被称为**Golden Grid**。

## 准备工作

搜索`Golden Grid`，[`code.google.com/p/the-golden-grid/`](http://code.google.com/p/the-golden-grid/)应该是第一个结果。从顶部导航中，转到**Downloads**页面并获取最新版本。

## 如何做...

在提取的文件中查找`CSS/golden-base`目录。在其中，将`golden.css`文件复制到你的开发目录中。你将使用这个 CSS 文件作为你的布局基础框架。

在一个新的 HTML 文件中添加一个链接到`golden.css`样式表。

```html
<link rel="stylesheet" href="CSS/golden.css" media="screen, projection">
```

打开这个 CSS 文件并编辑`.main`类的属性。将`width:970px`更改为`max-width:970px`。这将打破静态页面模板，并允许外部包装随着浏览器窗口的缩小而调整。

当您打开`golden.css`样式表时，看一下它是如何工作的。它非常简单；三条垂直线，然后对于每个分区，将页面布局分成一半，然后再分成一半。类跨度从`70px`宽度开始，每次增加`80px`，直到填满它们的`width:950px;`属性。要将`width`属性分配给您的元素，请为其分配一个以字母`g`开头的类，加上宽度和`10px`的边距。这些还具有`float:left;`和`display:inline;`样式。因为它们是左浮动的内联元素，当它们水平空间用完时，它们将换行。由于它们是左浮动的，它们被左对齐，要将它们移动到右边，您可以在其前面放置空元素，或者使用框架的`.margin`类在其前面放置左边距。

边距的工作方式与网格跨度的宽度类似，它们以`80px`递增，唯一的区别是它们从`90px`开始而不是`70px`。这个差异在元素的`margin-left:10px`属性中得到了解决。

元素在行中对齐，就像我们在本章中使用的其他框架一样，它在开始新行之前使用一个元素来清除行的末尾。在这种情况下，框架使用一个带有`clear:both`属性的 div。

让我们现在回到编辑 HTML 文件，并使用“三分法则”创建一个响应式布局。我们将从创建一个静态布局开始。创建一个带有`width:100%`样式的标题（`H1`），然后添加三个`div`来清除新的行。

```html
<body>
<div class="g960"><h1>Golden Grid CSS Layout</h1></div>
   <div class="clear"></div>
   <div class="clear"></div>
   <div class="clear"></div>
</body>
```

在第一个清除`div`元素之后，添加一个带有类`.g960`的`div`元素，我们将在其中插入一个大图像，其中我们将创建响应特性。您可以参考第一章中的*使用百分比宽度调整图像大小*一节，了解如何使图像具有响应性：

```html
<div class="clear"></div>
<div class="g960">
<img src="img/robot-large.png" class="resp" alt="robot picture"/>
</div>
<div class="clear"></div>
```

在下一个断点之后，插入六个带有类`g160`的`div`元素。在每个内部，插入一段 Ipsum 文本。为了更具信息性的示例，用一个 80px 宽的类替换一个`.g160`元素。确保还包括边距类`ml80`，如下所示：

```html
<div class="clear"></div>
<div class="g160"><p>Loremipsum dolor sit amet...</p></div>
<div class="g160"><p>Loremipsum dolor sit amet...</p></div>
<div class="g160"><p>Loremipsum dolor sit amet...</p></div>
<div class="g160"><p>Loremipsum dolor sit amet...</p></div>
<div class="g80 ml80"><p>Loremipsum dolor sit amet...</p></div>
<div class="g160"><p>Loremipsum dolor sit amet...</p></div>
<div class="clear"></div>
```

这可能足够让 HTML 清楚地演示如何使其工作。现在让我们继续添加我们的 CSS，使其成为一个响应式设计。

在您的`CSS`目录中添加一个新的 CSS 文件，`responsive.css`，并在 HTML 头部链接到它。

```html
<link rel="stylesheet" href="CSS/responsive.css" media="screen, projection">
```

在这里，我们将添加一些 CSS 属性，使 CSS 框架具有响应性。首先，让我们处理一下那张大图片。当浏览器变小时，我们宁愿不让它保持大尺寸。

```html
.resp{
    width:100%; 
    height:auto;
}
```

接下来，在两个断点处添加媒体查询，`600px`用于移动设备，`1024px`用于平板电脑。您可以根据需要为更大的屏幕添加更多，但是对于这个示例，我们只涵盖了基础知识。

```html
@media screen and (max-width:600px){...}
@media screen and (min-width:601px) and (max-width:1024px){...}
```

对于所有小于`600px`的屏幕，我们希望所有`div`元素默认为屏幕的全宽度。不要忘记我们有带有左边距属性的类；我们将希望将它们缩小到零。为了使新的 CSS 尽可能简洁，让我们使用 CSS 属性选择器来通配选择所有网格类。添加`div[class*='g']{...}`并分配宽度为`90%`，以及`div[class*='ml'] {...}`来分配左边距为`0`。

```html
@media screen and (max-width:600px){
   div[class*='g']{width:96%;}
   div[class*='ml']{margin-left:0;}
}
```

对于屏幕范围从 600px 到 1024px，添加相同的内容，但将网格类的宽度更改为`48%`。对于这个`@media`查询，我们不希望每个元素都占据屏幕的一半。那将破坏这个响应式框架的所有乐趣。在您的属性选择器之后，添加`.wide`以为这个特殊的类添加一个不同的 CSS 属性。然后，给它一个宽度为`96%`。在您的 HTML 中，将`wide`类添加到标题和图像父`div`元素（它们是带有`g960`类的元素）。

```html
div[class*='g'].wide{width:96%;} 
```

以下截图说明了 Golden Grid 的行为：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_04_04.jpg)

## 它是如何工作的...

属性选择器为我们提供了一个巧妙的技巧，可以将刚性框架分割成有限的列跨度，变成整个屏幕的全宽。将这个与自定义媒体查询结合起来，只在较小的屏幕上改变 HTML，你就可以轻松地为所有尺寸创建一个响应式、可能视觉上引人注目的布局。这个技术也可以用于许多不同的框架。

## 还有更多...

让我们玩得更开心一点，把这个做得更深入一些。到目前为止，在这一章中，我们主要是在移动设备上制作静态框架。让我们一起做一个实验，让 Golden Grid 在大屏幕上显示时做一些酷炫的事情。为`1280px`断点添加一个新的媒体查询。

```html
@media screen and (min-width:1280px){...}
```

这个配方的额外部分深入探讨了属性选择器。一开始在您的 CSS 中看到基本逻辑可能有点令人不安，但请耐心等待，您将会发现一些新的工具，这些工具对您的工具箱非常有用。但首先让我们添加一些更多的内容和一个 HTML 结构。

复制您的 HTML 的最后一行，并将其附加到 HTML 页面中，就在您复制它的地方的右边。给它一个父`div`元素，类名为`g960`。在前面的`div`元素中，添加类名`last clear`。

```html
<div class="last clear"></div>
<div class="g960">
   <div class="g160"><p>Loremipsum dolor sit amet...</p></div>
   <div class="g160"><p>Loremipsum dolor sit amet...</p></div>
   <div class="g160"><p>Loremipsum dolor sit amet...</p></div>
   <div class="g160"><p>Loremipsum dolor sit amet...</p></div>
   <div class="g80 ml80"><p>Loremipsum dolor sit amet...</p></div>
   <div class="g160"><p>Loremipsum dolor sit amet...</p></div>
</div>
```

回到你的 CSS。属性选择器现在允许更多的条件，比如父元素、子元素和优先级。让我们使用这个来将 CSS 属性应用到由`.last` div 元素前面的网格元素。为了做到这一点，我们使用`~`符号；语法如下：

```html
DIV.preceding~DIV.following
```

我们希望当屏幕大于 1280px 时，这个元素变成右侧的一列，以最大化我们的视觉区域。

```html
div.last~div[class*='g']{position:absolute;right:0;top:0;width:14%;max-width:226px;}
```

接下来，我们希望所有的子元素都能很好地排列并占用可用空间，同时移除`ml`类的任何边距。这个语法与前面的类似，但使用了`>`符号；写法如下`DIV.parent>DIV.child`。

```html
div.last~div[class*='g']>div[class*='g']{display:block;float:none;width:100%;}
div.last~div[class*='g']>div[class*='ml']{margin-left:0;}
```

我们还需要防止包裹`g960`网格元素受到`max-width:1024px`媒体查询中通配符的影响。在`.lost` div 元素前面的网格 div 元素中添加相同的属性选择器，并给它一个宽度为`100%`，如下面的代码行所示：

```html
div.last~div[class*='g']{width:100%}
```

现在刷新您的浏览器窗口，并将其扩展到`1280px`断点之后。您会看到最后一行移动到侧边栏位置。谁说框架太死板，不能响应呢？

现在，您已经知道旧浏览器不支持媒体查询，所以既然我们关心我们所有的观众，我们希望给予那些忠实使用旧浏览器的用户一些关爱。复制`1280px`媒体查询断点的 CSS，并将其添加到一个仅适用于 IE9 之前的样式表中。然后在您的头部添加一个条件链接到样式表：

```html
<!--[if lt IE 9]>
  <link rel="stylesheet" type="text/css" href="IE8.css" />
<![endif]-->
```

这将解决旧浏览器支持问题，您的网站在旧浏览器中看起来仍然很好。

# 尝试 Gumby，一个响应式的 960 网格

Gumby 框架是对可靠的静态 960 网格框架的持续努力。它是由 Digital Surgeons 的友好人士为您带来的。框架本身已经更新，添加了许多新功能。当然，我们没有时间在这个教程中介绍所有的功能，所以我们将专注于框架的改进布局结构。

## 准备工作

让我们来看看 Gumby 960 响应式框架的网站[gumbyframework.com/](http://gumbyframework.com/)。当您浏览它时，您可以看到现代化的框架功能在其中的应用。布局在 767px 时很好地适应了移动版本，并且还将菜单转换为可用的移动导航。还包括了一些有用的 UI 元素，您会想花一些时间来熟悉它们。

点击导航栏上非常显眼的**下载 Gumby 2**按钮，获取 Gumby 的主版本存档。包含在包中的有 Photoshop 文件，帮助你设计布局，实际的框架 CSS，JavaScript，图像文件和示例 HTML 文件。`demo.html`文件可能是检查源代码并对框架的使用进行一些发现的好地方。

但是先把探索留到以后，让我们直接开始构建一个页面。

## 如何做…

在你的 HTML 编辑器中创建一个新页面。这个框架有一种简洁的方法，可以通过一个链接`css/imports.css`导入你的 CSS 脚本。在这个文件中，导入了不同的样式表。这是一个有用的概念，以防将来需要更改或添加样式表，你可以在这个 CSS 文件中进行控制。

```html
<link rel="stylesheet" href="css/imports.css">
```

CSS 看起来是这样的：

```html
@import url('gumby.hybrid.css');
@import url('ui.css');
@import url('style.css');
@import url('text.css');
```

为了不让你忘记，将你的链接添加到 jQuery 库和包含的 JavaScript 文件：`gumby.min.js`、`plugins.js`和`main.js`，直接放在页面末尾，紧接着`body`标签的闭合之前。你以后会需要这些。

```html
<script src="img/jquery.min.js"></script>
<script src="img/gumby.min.js"></script>
<script src="img/plugins.js"></script>
<script src="img/main.js"></script>
</body>
```

现在基础工作已经完成，让我们继续开发。Gumby 响应式网格框架可以使用 12 列或 16 列。首先建立一个 12 列的布局，然后我们将通过添加一个 16 层的部分使页面成为混合布局。

在你的 HTML body 中，添加一个带有`container`类的`div`元素。`container`类元素内的默认布局是 12 列。接下来，在`container`类元素内部，添加一个带有`row`类的新的`div`元素。`row`类元素封装了 12 列跨度的整个范围。在每一行中，你有 12 列跨度可以使用，来构建你的内容 div。

在`row`类元素内插入三个新的 div 元素，分别为`four columns`、`three columns`和`five columns`。列类可以是你的设计需要的任何数字，只要它们加在一起等于 12。类的数字标签决定了元素占据的列跨度数。在每个元素内部添加一个 Ipsum 填充文本段落([`ipsum.com`](http://ipsum.com))，以帮助更生动地演示布局。

```html
<div class="container">
        <div class="row">
<div class="four columns"><p>Loremipsum dolor sit amet, consecteturadipiscingelit. …</p></div>
<div class="three columns"><p>Loremipsum dolor sit amet, consecteturadipiscingelit. …</p></div>
<div class="five columns"><p>Loremipsum dolor sit amet, consecteturadipiscingelit. …</p></div>
        </div>
</div>
```

现在可以随意在浏览器中打开这个页面，看看它的样子。测试它的响应性，看看它在较小的屏幕上的表现如何。`columns`类的 CSS 如下所示：

```html
.column, .columns {
margin-left: 2.127663%;
float: left;
min-height: 1px;
position: relative;
-webkit-box-sizing: border-box;
-moz-box-sizing: border-box;
box-sizing: border-box;
}
```

数字类的 CSS 如下所示：

```html
.row .two.columns {
width: 14.893641%;
}
.row .three.columns {
width: 23.404293%;
}
.row .four.columns {
width: 31.914945%;
}
.row .five.columns {
width: 40.425597%;
}
....
And so on.
```

正如你所看到的，`columns`类给出了一个相对位置，并将元素浮动到左侧，带有填充和一些其他样式。

接下来添加另一个带有`row`类的`div`元素。在`row` div 内部，添加一个包含六个较小`div`元素的行。每个新的`div`元素将具有`two`和`columns`类。这两者将占据 12 列的跨度。在每个元素内部包含一个简短的文字段落。

```html
<div class="row">
<div class="two columns"><p>Loremipsum dolor sit amet...</p></div>
<div class="two columns"><p>Cum sociisnatoquepenatibus et...</p></div>
<div class="two columns"><p>eufacilisis sem. Phasellus...</p></div>
<div class="two columns"><p>Loremipsum dolor sit amet...</p></div>
<div class="two columns"><p>Cum sociisnatoquepenatibus et...</p></div>
<div class="two columns"><p>eufacilisis sem. Phasellus...</p></div>
</div>
```

在浏览器中，你可以看到它们很好地对齐成六列内容。当你调整到一个小的浏览器窗口时，你会看到它们跳转到 100%的宽度。

到目前为止，如果你设计的所有元素都浮动在屏幕的左侧，网格就会按照有序的方式工作。然而，情况并非总是如此；总会有内容需要右对齐、居中或其他任意对齐方式。别担心，Gumby 960 响应式框架已经考虑到了这一点。让我们添加一些更多的行，来演示如何做到这一点。

在第一行，我们将制作两个`div`元素，一个在左侧，一个在右侧。添加一个新的`row` div 元素，在其中添加两个`div`元素。给第一个`div`元素，它将位于屏幕左侧，添加类`two`和`columns`。有了这两个类，第一个`div`元素向左浮动并跨越两列。我们希望下一个`div`元素只占据六列，给它添加类`six`和`columns`。我们不希望这个下一个列向左浮动；相反，它应该在前一个`div`元素和自身之间留有一些空间。为了做到这一点，有一系列只有固定百分比左边距的类。在这种情况下，我们需要将元素向右推四列跨度。为此，添加类`push_four`。

```html
<div class="row">
<div class="two columns"><p>Loremipsum dolor sit amet...</p></div>
<div class="six columns push_four"><p>Consecteturadipiscingeli...</p>/div>
</div>
```

以下是`push_four`类的 CSS：

```html
.row .push_four {
margin-left: 36.170271%;
}
```

要使内容的列跨度*居中*，有一个特殊的类。我在引号中放置了 center，因为它并不真正居中，它是伪居中。Gumby Grid 不使用`text-align:center`或`float:center`属性，而是使用智能左边距系统。居中的`six column` div 元素的 CSS 如下所示：

```html
.row .six.centered {
margin-left: 25.531956%;
}
```

它遵循与数字类相同的模式，一个居中的`five column`行具有更大的左边距：`margin-left: 29.787282%`。

最后，在结束这个教程之前，让我们利用框架构建一个响应式菜单。这值得额外花点时间来展示框架中包含的响应式 UI 元素之一。

由于 CSS 已经构建好了，我们只需通过 HTML 来构建这个菜单。回到`container` div 元素的顶部，添加一个`row` div 元素。在`row` div 元素中添加一个`nav`元素，其`id`值为`"prettynav"`，并且具有`pretty navbarclearfix`类。接下来，在`nav`元素内部，添加一个`a href`标签，其`link`值等于`#`，一个`toggle`类，以及一个`data-for`值为`#prettynav&gt;ul`元素标签。在`a href`元素内部添加图像，该图像包含在`img`目录中，`img/icon_nav_toggle.gif`。

```html
<div class="row">
<nav class="pretty navbarclearfix" id="prettynav">
<a href="#" class="toggle" data-for="#prettynav&gt; ul"><img src="img/icon_nav_toggle.gif"></a>
</nav>
</div>
```

`a href`元素在移动版本的菜单中隐藏时，作为显示导航菜单的按钮起作用。

在`a href`元素之后，添加一个无序列表（`ul`），其中包含您导航的链接的列表项（`li`）：

```html
<ul>
  <li><a href="#">First Item</a></li>
  <li><a href="#">Second Item</a></li>
  <li><a href="#">Third Item</a></li>
  <li><a href="#">Fourth Item</a></li>
</ul>
```

这样就创建了一个不错的响应式菜单系统，这本身就足够令人兴奋了，但还有更多。您可以为每个菜单列表项添加一个子菜单。要添加一个子菜单，添加一个带有`dropdown`类的`div`元素。在该`div`元素内部，添加一个类似于父元素的子菜单`ul`。它们会自动转换为隐藏的子菜单！

```html
<li>
<a href="#">Second Item</a>
<div class="dropdown">
<ul>
<li><a href="#">Dropdown item</a></li>
<li><a href="#">Dropdown item</a></li>
</ul>
</div>
</li>
```

以下截图说明了 Gumby 框架：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_04_05.jpg)

## 它是如何工作的...

Gumby 960 Grid 框架旨在设计和构建一个优雅且易于布局和元素的框架。不需要太多了解如何使其工作。首先，学习如何对您的`div`元素进行分类，使其在框架内工作。其次，构建它。了解如何使用框架中包含的 UI 元素将需要更多的参与，但这将是值得您时间的。

# Bootstrap 框架使响应式布局变得简单

Bootstrap 框架（以前称为**Twitter Bootstrap**框架）与大多数其他框架不同，因为它是完全响应式的。您可以将其用作静态框架，也可以使用它们的附加文件快速部署完全响应式的站点。当您需要快速制作出色的站点，并且愿意对外部标准进行最小的设计调整时，这是一个很好的工具。

获取框架就像搜索“Bootstrap 框架”并转到第一个链接[`twitter.github.com/bootstrap/`](http://twitter.github.com/bootstrap/)，然后点击大的**下载 Bootstrap**按钮一样容易。该软件包包括 CSS 文件、图像和 JavaScript，但没有文档。然而，在他们的网站上有很多很好的在线文档，他们的示例源代码也非常连贯。这个步骤将帮助您开始使用 Bootstrap 框架。

## 准备工作

使用 Bootstrap 框架构建非常容易；您可以在几分钟内创建一个模板。话虽如此，让我们继续努力。创建一个新的 HTML 文件并开始。首先，在页眉中添加一个链接到 Bootstrap CSS 文件，这样我们偶尔可以看到我们的工作成果：

```html
<link href="css/bootstrap.css" rel="stylesheet" media="screen">
<link href="css/bootstrap-responsive.css" rel="stylesheet" media="screen">
```

让我们从一个带有顶部导航和内容的简单页面开始。导航将根据屏幕宽度做出响应，并为每个显示进行优化。导航`div`元素使用了几个类来实现期望的结果；它们是`navbarnavbar-inverse navbar-fixed-top`。在其中，添加一个带有`container`类的`div`元素。在`container`div 元素内，有一个按钮图形，它在移动版本中显示。点击后，它会显示菜单的移动版本。菜单以优化的方式显示在移动和桌面版本中。相当酷，对吧！

以下是一个示例菜单，展示了它是如何组合在一起的：

```html
<div class="navbarnavbar-inverse navbar-fixed-top">
     <div class="navbar-inner">
       <div class="container">
         <a class="btnbtn-navbar" data-toggle="collapse" data-target=".nav-collapse">
           <span class="icon-bar"></span>
           <span class="icon-bar"></span>
           <span class="icon-bar"></span>
         </a>
         <a class="brand" href="#">Project name</a>
         <div class="nav-collapse collapse">
           <ul class="nav">
             <li class="active"><a href="#">Home</a></li>
             <li><a href="#about">About</a></li>
             <li><a href="#contact">Contact</a></li>
           </ul>
         </div><!--/.nav-collapse -->
       </div>
     </div>
   </div>
```

然后，在页眉中插入一个指向 jQuery 库的链接。

```html
<script src="img/jquery-latest.min.js"  ></script>
```

然后，在 HTML 的底部，在闭合的`body`标签之前，添加一个指向`js/bootstrap.js`文件的链接。

```html
<script src="img/bootstrap.js"></script>
```

最后，如果您还没有直接将 JS 复制到您的`webroot`中，请这样做。

现在，检查您的时髦响应式导航。

那很棒，不是吗？既然我们都对 Bootstrap 框架感到兴奋，让我们开始做一些响应式内容布局的工作。接下来，让我们来构建 Bootstrap 称为基本营销网站的内容。

首先要做的是添加一个带有`container`类的`div`元素。如果您回顾我们的菜单，您会发现这个类是一个巧妙的可重复使用的布局元素，用于控制包含元素的响应式宽度。在`container`元素内，添加一个新的`div`元素并给它一个类，`hero-unit`。在`hero-unit`类内，添加一些您想要以大型广告牌样式显示在屏幕上的内容：

```html
<div class="container">
<div class="hero-unit">
<h1>Hello World</h1>
<p>Loremipsum dolor sit amet...</p>
</div> 
</div>
```

刷新浏览器，试试看。一切看起来都很好，而且不费吹灰之力。在下面，我们想要添加一些列的引人注目的文本。这开始看起来像一个不错的着陆页。你难道不为自己做这个而高兴吗？

Bootstrap 框架使用`div`元素和`row`类来勾勒其列跨度。因此，要创建新的*行*内容，添加一个带有`row`类的新`div`元素。在行内，您有 12 个跨度可用于将内容放入其中。对于这个步骤，让我们保持简单，所以在`row`div 元素内插入三个新的`div`元素，每个都带有`span4`类。在每个`span4`元素内，添加一个次级标题和一段 Ipsum ([`lipsum.com`](http://lipsum.com))的填充文本。

```html
<div class="row">
<div class="span4">
<h2>Header</h2>
<p>Loremipsum dolor sit amet, consecteturadipiscingelit...</p>
</div>
<div class="span4">
<h2>Header</h2>
<p>Loremipsum dolor sit amet, consecteturadipiscingelit...</p>
</div>
<div class="span4">
<h2>Header</h2>
<p>Loremipsum dolor sit amet, consecteturadipiscingelit......</p> 
</div>
```

打开浏览器窗口或刷新它，看看这个漂亮的布局是如何运行的。最新的行占据了三列，并在移动浏览器或宽度较小的窗口中很好地折叠成单列。

您可以复制整个`row`类元素和内部 HTML，并将其粘贴以添加一个全新的内容行，它会很好地运行。

既然我们已经做了一个好看的页面，而且没有费太大的力气，让我们为页面添加另一个级别。这部分是 Bootstrap 框架灵活性的绝佳演示。接下来，您将在页面上添加一个侧边导航。

在第二个`container`类元素中，将`hero-unit`和`row`元素包装在一个新的`div`元素中，并为该元素分配一个`span9`类。接下来，在新元素之前插入另一个带有`span3`类的`div`元素。这样就可以处理页面布局的变化；接下来我们将快速在其中构建一个菜单。

在你的`span3` div 类中添加一个新的`div`元素，并给它添加`well`和`sidebar-nav`类。这样可以为侧边导航添加一个漂亮的样式。现在，添加一个带有`nav`和`nav-list`类的无序列表(`ul`)到菜单列表中。你可以通过给列表项分配`nav-header`类来添加列表部分标题。在每个列表项中添加一个导航项的`href`链接：

```html
<div class="well sidebar-nav">
     <ul class="navnav-list">
          <li class="nav-header">Navigation 1</li>
          <li><a href="#">Nav Link</a></li>
          <li><a href="#">Nav Link</a></li>
          <li><a href="#">Nav Link</a></li>
          <li class="nav-header">Navigation 2</li>
          <li><a href="#">Nav Link</a></li>
          <li><a href="#">Nav Link</a></li>
          <li><a href="#">Nav Link</a></li>
     </ul>
</div>
```

你几乎完成了；在这个步骤中只剩下几个步骤。将你的两个新的`span*`元素包装在另一个带有`row`或`row-fluid`类的`div`元素中。最后，将包含摘要内容元素的`row` div 元素类名称更改为`row-fluid`。

```html
<div class="container">
           <div class="row">
             <div class="span3">
             <div class="well sidebar-nav">
                <ul class="navnav-list">
                  <li class="nav-header">Navigation 1</li>
                  <li><a href="#">Nav Link</a></li>
                  <li><a href="#">Nav Link</a></li>
                  <li><a href="#">Nav Link</a></li>
                  <li class="nav-header">Navigation 2</li>
                  <li><a href="#">Nav Link</a></li>
                       <li><a href="#">Nav Link</a></li>
                       <li><a href="#">Nav Link</a></li>
                   </ul>
               </div>

           </div>
           <div class="span9">
           <div class="hero-unit">
<h1>Hello World</h1>
     <p>Loremipsum dolor sit amet, consecteturadipiscingelit...</p>
       </div>
         <div class="row-fluid">
           <div class="span4">
             <h2>Header</h2>
             <p>Loremipsum dolor sit amet, consectetur adipiscing elit...</p>    
           </div>
           <div class="span4">
             <h2>Header</h2>
             <p>Loremipsum dolor sit amet, consecteturadipiscingelit...</p>    
           </div>
         </div>
       </div>
    </div>

</div>
```

恭喜，你完成了！现在你有了一个专业外观的响应式布局和设计的坚实基础。你只需要对此进行一些修改，就可以得到一个成品。以下截图显示了基本的 Bootstrap 框架：

![准备就绪](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_04_06.jpg)

## 工作原理...

就像魔术一样！不是开玩笑，Bootstrap 框架必须是我使用过的最简单和最周到的框架之一。一旦你熟悉了类和布局，通过这个配方和他们的文档，快速开发你的项目就变得非常容易。

有一些具体的事项我想讨论。首先是响应式菜单；`container`类中顶部的`div`元素是`button`，它只在移动版本中显示，其目的是在点击时以移动样式显示隐藏的菜单`div`元素`nav-collapse`。

这本身就为你提供了一个可用且非常优雅的响应式菜单的良好起点。然而，你会发现按钮本身不起作用，这是因为我们需要添加一些 JavaScript 来使这个战斗站完全运转。

响应式布局在幕后为你做了大量工作。你创建的每一列都占据了指定的列，但在移动浏览器或窄宽窗口中时，会很好地折叠成单列。

## 还有更多...

这个框架还有很多你可以做的事情。Bootstrap 框架中包含了丰富的元素、菜单、UI 功能和动画。花点时间深入了解框架，你会发现这是件值得的事情。学会这些之后，我发现我可以更快地部署新的工作，而且过程也不那么令人沮丧。


# 第五章：制作移动优先 Web 应用程序

在本章中，您将学习：

+   使用 Safari 开发人员工具的用户代理切换器

+   使用 Chrome 插件在 Chrome 中掩盖您的用户代理

+   使用浏览器调整大小插件

+   学习视口及其选项

+   为 jQuery Mobile 添加标签

+   在 jQuery Mobile 中添加第二个页面

+   在 jQuery Mobile 中制作列表元素

+   使用 jQuery Mobile 添加移动原生外观按钮

+   仅为移动浏览器添加移动样式表使用媒体查询

+   仅为移动浏览器添加 JavaScript

# 介绍

在本章中，我们将专注于移动优先响应式设计。这意味着首先为移动设备设计您的站点，然后为桌面应用程序应用变化甚至完全不同的外观。我们将介绍一些关于 jQuery Mobile 的配方，这是一个免费的开源移动 UI 元素和小部件库。此外，我们将构建一些客户端脚本来处理仅适用于移动设备的独特外观。

# 使用 Safari 开发人员工具的用户代理切换器

对于开发移动优先应用程序，您需要在本地部署它们并测试您开发的各种功能。到目前为止，我们已经使用了许多响应式 Web 配方，依赖于媒体查询来确定基于大小的布局，以提供站点的优化视图。这不是应用程序可以提供移动布局的唯一方式，还有更多。一种方法是通过**用户代理**来嗅探。

您可能已经了解用户代理，但让我们假设您不了解。此外，已经知道一切简单地违背了购买这本书的目的，不是吗？用户代理存在于请求标头中，并标识发出请求的客户端软件。它包含有关您的处理器、操作系统版本、浏览器、渲染引擎、IP 地址和其他标识信息的信息。

根据项目的需求或开发人员的偏好，一些网站被设计为为移动设备显示不同的模板文件，或者基于用户代理数据的其他细节。这种方法需要不同的服务器或客户端智能来读取用户代理并解释其数据，以提供该场景的演示。

所以你创建了一个新的 Web 应用程序，当用户代理详细信息为移动设备时，软件会显示移动模板。但是，您希望能够即时测试它，而不必启动 Web 服务器，因此下一个最好的方法是在 Safari 中使用用户代理掩码功能。

使用 Safari 浏览器用户代理切换器是双赢的，因为它不仅模仿了 iOS 设备上移动 Safari 浏览器的用户代理，还模仿了 Android 浏览器的用户代理。所以您可以放心，因为 Android 用户代理已更改为也是 Mobile Safari，只是为了让您的生活更轻松。他们真好。

### 提示

在您的工作范围中明确指定您将进行测试的浏览器和用户代理是一个很好的做法。

## 准备就绪

在苹果电脑上，它已经安装好了。你领先一步。所以等着 Windows 用户赶上吧。

苹果公司似乎不太可能继续为 Windows 开发 Safari。事实上，当您搜索`Safari Windows`时，第一个链接不是 Safari 主页，而是一个包含指向最新 Safari for Windows 版本 Safari 5.1.7 for Windows 链接的苹果支持页面，而不是最新版本（版本 6）。但是为了这个配方的目的，让我们继续。

## 如何做…

首先，打开 Safari 浏览器；您将要访问一个作为读取用户代理演示的网站。转到[`whatsmyuseragent.com`](http://whatsmyuseragent.com)，页面将显示您的用户代理的详细信息。

在 Safari 中，转到**Safari** | **首选项**，或按下*Command* `+` *,*。在**高级**选项卡中，选择**在菜单栏中显示开发菜单**复选框。您可以在以下截图中看到这一点：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_01.jpg)

现在菜单栏显示了菜单选项**开发**。单击它，然后选择**用户代理**；一个子菜单出现，其中包含不同的用户代理选项。这里有许多有用的选项，但对于这个教程，最有用的是**Safari iOS 5.1 - iPhone**和**Safari iOS 5.1 - iPad**（很可能您的版本可能不是 5.1）。这在下一个截图中有演示：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_02.jpg)

选择其中一个 iOS 版本；页面将自动刷新。您现在将看到新的用户代理信息，如下一个截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_03.jpg)

## 它是如何工作的...

我知道看起来好像没有发生什么，但发生的事情很重要。浏览器向服务器提供了关于您的计算机和浏览器的信息，并因此为您提供了不同的网页。您可以构建逻辑，为移动浏览器提供特殊的样式表、模板、脚本或完全不同的页面内容。

# 使用插件在 Chrome 中伪装您的用户代理

Chrome 浏览器拥有大量插件，您可以为几乎任何目的使用。让我们探索一个用户代理伪装插件来伪装您的用户代理。

为什么要“伪装”您的用户代理？这不诚实吗？好吧，我承认，是的。但这是为数不多的几种情况之一，结果确实证明了手段。此外，没有任何伤害；就像服务器发现您的浏览器在撒谎并感到被欺骗和受伤一样。伪装您的用户代理可以让您说服 Web 服务器，您的桌面浏览器实际上是移动浏览器。如果服务器相信您正在使用移动浏览器，并且其逻辑决定应该提供移动版本，那么您将得到移动版本。

## 准备工作

我们想找到一种方法，可以在不同的用户代理之间切换，并且希望它非常简单。事实上，我们希望它是浏览器上的一个按钮，我们可以按下并切换。那么我们从哪里可以得到这个令人惊叹的技术把戏？在 Chrome 网络商店！

我尝试了一些不同的 Chrome 浏览器插件，并找到了一个成为我响应式工具包中最喜欢的插件。Chrome 的**用户代理切换器**提供了一种快速切换全面用户代理列表的方法。要获得它，采取更简单的路径，搜索`Google UA Spoofer`。

## 如何做...

第一个搜索结果应该是指向 Chrome 网络商店中的用户代理切换器的链接。如果是的话，转到该链接，然后点击**添加到 Chrome**按钮。这就是您需要安装它的全部内容。使用它将更容易。

现在看看浏览器顶部的最上方部分，地址栏右侧，找到一个新图标，形状像一个小面具。当您点击它时，会弹出一个不同浏览器的菜单，其中包含可用版本的子菜单。我们测试过了，很容易。看下一个截图以证明：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_04.jpg)

## 它是如何工作的...

Chrome 用户代理欺骗浏览器插件拦截了请求头中的正常浏览器用户代理信息，并用欺骗的用户代理信息替换它。到目前为止，我们只是讨论了如何测试用户代理欺骗器。如何设计您的网站来处理不同的用户代理是一个完全不同的主题。

要看它的效果，请转到[`whatsmyuseragent.com/`](http://whatsmyuseragent.com/)，然后切换浏览器插件，从**iOS**切换到**iPhone**。您将看到用户代理信息更改为**iPhone**。尝试一些更多的实验，看看伪装的用户代理如何影响您喜欢的网站。

## 还有更多...

看看网络上一些流行的网站，你会看到它们如何处理不同的用户代理。有些提供不同的主题，有些将你的浏览器重定向到他们的移动版本的子域。例如，[`facebook.com`](http://facebook.com) 会将 iOS 用户代理重定向到[`m.facebook.com/?_rdr`](http://m.facebook.com/?_rdr)，而[`plus.google.com/`](https://plus.google.com/) 会将移动版本的网站重定向到[`plus.google.com/app/basic/stream`](https://plus.google.com/app/basic/stream)。

下面的截图显示了伪装用户代理如何显示页面的不同之处：

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_05.jpg)

# 使用浏览器调整大小插件

我会坦率地告诉你；这个教程是关于安装和使用我使用的浏览器调整大小插件。如果你有更好的选择，请告诉我。我在搜索后选择的插件叫做“Window Resizer”。

除了在目标设备上测试外，使用插件调整窗口大小是测试媒体查询的最准确方法。然而，这只是你应该对响应式网站进行的测试的一部分。在部署之前，一定要使用模拟器和实际设备进行测试。没有什么比部署一个现场网站后，有人提醒你它崩溃和燃烧更糟糕的了。

## 准备工作

谷歌是你的朋友。搜索`Window Resizer`。第一个搜索结果应该是 Chrome 网上应用店中的 Window Resizer 插件。就像夜晚的灯塔一样！它有五颗星，而且是免费的；你怎么能不点击那个链接呢？

## 如何做...

如果你跟着我走，你会发现自己在 Chrome 网上应用店的安装页面上。你会看到一个吸引人的、宽阔而宁静的深蓝色按钮，上面写着**+ 添加到 Chrome**。你被吸引住了，感觉需要点击它。你看到了蓝色，夜晚你仰望的天空，想着有一天你会走多远。你想着你的浏览器可以有多种不同的大小。你想着拖动窗口角落时的痛苦，试图猜测它的大小。你受不了了。点击按钮！

你的浏览器窗口上出现了一阵动作的飘忽。最后，蓝色按钮变成了绿色。你在这里完成了。

在你的浏览器窗口，一个看起来像一个微小浏览器窗口的新图标已经找到了它的位置，位于地址栏右侧。好奇心驱使你需要知道这个东西能做什么。

这几乎是测试不同媒体查询和网站响应式版本的几乎完美的方法，仅次于直接在目标设备上测试。

## 它是如何工作的...

使用这个按钮来测试你的响应式设计，达到像素级的精确度。当你点击它时，它会展示一个不同的浏览器窗口大小的列表。每一个都是完美测量的，会根据你的意愿调整你的浏览器大小。这个浏览器插件为你做所有的猜测和精确测量，因为它可以在点击按钮时直接影响浏览器窗口大小！见下面的截图：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_06.jpg)

# 学习视口及其选项

如果没有别的，可以说视口的目的是驯服移动浏览器窗口。视口对于确定你的移动浏览器如何呈现移动网页至关重要。

## 准备工作

如果你使用苹果电脑，可以通过从苹果下载 Xcode 来获得 iOS 模拟器。它是 Xcode 软件包的一部分。我通常通过使用 Spotlight 来找到它。按下*Command* + 空格键；Spotlight 搜索框会出现在屏幕右上角。开始输入`iOS Simulator`，它会出现在搜索结果中。点击它来启动 iOS 模拟器。

## 如何做...

打开之前从上一个配方项目中完成的响应式项目之一。我建议打开*使用媒体查询创建响应式宽度布局*配方中的[resp-width-layout-media-query.html](http://resp-width-layout-media-query.html)项目。

要在 Windows 上获得 iOS 模拟器，你需要在网上找到一个。经过搜索，我在[`iphone4simulator.com/`](http://iphone4simulator.com/)找到了一个好的模拟器，还有一个在[`iphonetester.com/`](http://iphonetester.com/)。要使用它们，你需要在将项目文件上传到 Web 主机之前，这个 Web 模拟器才能查看它。该模拟器无法读取你本地硬盘上的文件，除非你运行一个本地 Web 服务器。

首先，为了比较，在你的浏览器中查看文件。然后在你的 iPhone 模拟器中，输入文件的 URL，你会发现震惊和恐惧，因为你的网站看起来就像桌面版本一样。当我的早期响应式项目不按照我想要的方式工作时，我也经历了同样的挫败感。问题在于移动浏览器不知道你希望它的大小是多少。它很聪明，但不够机智。就像所有软件一样，它需要良好的指示。所以深呼吸，我们将一起解决它。问题在下面的截图中有所说明：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_07.jpg)

你可以通过配置 viewport 告诉移动浏览器它应该做什么。首先添加简单的 viewport `<meta>`标签：

```html
<meta name="viewport">
```

在我们继续之前，我应该告诉你一个警告。如果你不打算为移动设备设计页面，那就不要包含 viewport `<meta>`标签。它可能会对你的页面交付产生意想不到的后果。事实上，它可能只会显示你页面的一小部分，不允许观众放大或滚动查看整个页面。

现在我们将讨论它的选项。首先是宽度；我非常喜欢 K.I.S.S.原则（保持简短和简单）。除非你有特定的宽度要求，将设备宽度作为 viewport 宽度。这样，它将读取设备宽度并将其设置为页面宽度。设置特定的宽度，例如`1000px`，在 iPad 上看起来还可以，但在手机设备上会呈现得太宽，使小于该宽度的媒体查询无效。

```html
<meta name="viewport" content="width=device-width">
```

一旦你做出了改变，打开你的 iOS 模拟器的浏览器并查看文件。你可以在下面的截图中看到修复后的版本：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_08.jpg)

接下来，让我们谈谈缩放。假设你没有特殊要求，不要做任何奇怪的事情，比如以除了一之外的任何值开始缩放。在 viewport `<meta>`标签中添加初始缩放值`1`。

好的，我知道我说过不要做任何奇怪的事情，但只是为了演示，将你的初始比例改为`2`。刷新你的屏幕。

接下来，将其更改为`0.4`。请记住，这只是为了演示。请再次刷新你的屏幕。在纵向视图中，你会看到网页使用了小屏幕媒体查询。现在，更改模拟器的方向，使其进入横向模式。现在你会看到较大的媒体查询被激活。这是一个有趣的实验；现在将你的初始比例改回`1`。

最后，你是否希望你的观众能够使用多点触控缩放？使用 meta 属性`maximum-scale`来限制你想要允许的缩放程度。如果你不想允许缩放，将最大缩放设置为`1`。

```html
maximum-scale=1
```

## 它是如何工作的...

viewport `<meta>`标签最初是由苹果的 Safari 移动浏览器添加的，然后被添加到其他浏览器中。它用于定义页面应该以什么宽度进行阅读。当浏览器看到 viewport `<meta>`标签中定义了宽度属性时，它会以该宽度设置中定义的比例加载页面，再加上初始缩放属性。

# 为 jQuery Mobile 添加标签

这个示例深入到了一个新的响应式设计领域，即移动优先。移动优先，简而言之，意味着你首先设计网站的移动版本，然后对桌面进行修改。现在，这并不意味着你正在设计一个“仅限移动”的网站，只是移动端的布局和样式首先设计。

Mobile-first 可能需要重新思考你的设计，或者至少从不同的角度进行设计。但改变不是好事吗？我们不是可以通过尝试新的方法来改进我们的设计技能吗？达尔文主义不仅仅是适应变化的人才能生存吗？

所以让我们以开放的心态前进，尝试一些移动优先的开发。

## 准备工作

首先，跳转到 jQuery Mobile 网站。网址是[`jquerymobile.com`](http://jquerymobile.com)。否则，如果你像我一样懒得话，你可以简单地搜索`jQuery Mobile`。如果你不想搜索，因为你是我的特别朋友，我会提供直接链接。网站的直接链接是[`lmgtfy.com/?q=jquery+mobile&l=1`](http://lmgtfy.com/?q=jquery+mobile&l=1)。我甚至会为你缩短链接；访问[`bit.ly/TMpuB8`](http://bit.ly/TMpuB8)。

在这里，如果你想要在本地托管文件，你可以下载这个库（而且有一些非常好的理由可以这样做）；然而，对于这个示例，我们可以更加迅速地让其他人托管所有必要的文件。

jQuery Mobile 网站有大量的文档和示例。它甚至有下载构建器，所以你可以缩减必要的库，只使用那些运行你的移动 web 应用程序所需的文件。

## 如何做...

首先，在你的 IDE 中创建一个新的 HTML 文档。在头部添加 viewport `<meta>`标签：

```html
<meta name="viewport" content="width=device-width, initial-scale=1">
```

接下来，包括链接到 jQuery Mobile CSS 和 JavaScript 文件。

```html
<link rel="stylesheet" href="http://code.jquery.com/mobile/1.2.0/jquery.mobile-1.2.0.min.css" />
<script src="img/jquery-1.8.2.min.js"></script>
<script src="img/jquery.mobile-1.2.0.min.js"></script>
```

值得停下来进行一分钟的教学，并谈谈你的样式表。在前面的代码中，我们链接到了远程的 jQuery CSS。我建议你（如果你要在本地托管这个文件）保持原样，并在一个完全不同的样式表中添加你所有新的元素的 CSS。另外，如果你想对 jQuery 的 CSS 进行任何更改，添加另一个 CSS 文件并进行显式的命名空间覆盖，或者使用`!important`覆盖。将其命名为`jQuery-mobile-changes.css`之类的东西。我不认为你会需要这样做，但以防万一，这是一个处理的好方法。我建议这样做是因为当一个新版本的 jQuery 发布时，你不需要在升级时破坏你的网站。

这基本上涵盖了你的页眉大部分内容。现在让我们为页面创建一些基本内容。首先，让我们用一个`<div>`元素包裹页面：

```html
<body>
     <div>

     </div>
</body>
```

jQuery Mobile 的一个非常棒的特性是它使用标签，你可以将这些标签放在 HTML 元素中，这些元素不用来渲染你的页面。好处是你可以通过替换 jQuery Mobile 脚本和样式来在桌面站点上使用相同的模板。接下来，向包裹的`<div>`元素添加一些标签，告诉 jQuery Mobile 在这个页面上起作用。在元素中添加`data-role="page"`。

```html
<div data-role="page">
```

让我们通过构建一个示例文本页面来演示。

在一个`<div>`元素中添加一个新的`h1`标题。给`<div>`元素添加一个`data-role="header"`属性。然后，在浏览器中打开文件，查看 jQuery Mobile 主题。

```html
<div data-role="header">
   <h1>Adding tags for jQuery Mobile</h1>
</div>
```

这是一个很好的开始；让我们继续添加一些 jQuery Mobile 中页面结构的示例。

### 提示

你也可以为桌面版本给这些元素添加 ID 和类。

接下来，添加一个 body。添加一段填充文本，然后将段落包裹在一个`<div>`元素中。给`<div>`元素分配一个 HTML5 数据属性`data-role:"content"`。

```html
<div data-role="content">
  <p>
    Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean massa....
  </p>
</div>
```

同样地，添加一个页脚。在一个`<div>`元素中包裹一个简单的文本，然后在一个`<div>`元素中包裹一个`h4`标签。现在给这个`<div>`元素添加属性`data-role="footer"`：

```html
<div data-role="footer">
  <h4>The Footer</h4>
</div>
```

就是这样。jQuery Mobile 网站有很好的文档和示例，介绍了如何进一步使用他们的框架构建移动站点。在本章中，我们将继续介绍更多的 jQuery Mobile 示例。去看看吧。这是使用 jQuery Mobile 的页面效果：

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_09.jpg)

## 它是如何工作的...

jQuery Mobile 使用 HTML5 数据属性来触发标记和小部件的脚本。当您在元素中放置数据属性时，脚本将自动起作用。

# 在 jQuery Mobile 中添加第二个页面

在 jQuery Mobile 中有一个非常酷的功能，允许您将一个更大的 HTML 页面分成更小、可消化的部分。想象一下，您有一个包含大量内容的页面，您不希望强迫您的受众不断向下滚动阅读。考虑使用 jQuery Mobile 的多页面模板结构。移动设备上的网页用户体验与桌面上的网页用户体验非常不同。在旧的桌面 Web 上，经常说“内容为王”；现在 Web 是移动的，空间有限，所有内容很容易变得过多。您可能希望考虑限制每个页面显示的一些内容。在本示例中，我们将使用 jQuery Mobile 将包含大量数据的大页面分成更小的可消化部分。

## 准备工作

在上一个示例中，我们使用了 jQuery Mobile 标记构建了一个简单的页面。让我们找出那个示例的文件，并将其另存为一个新文件进行操作。这将作为本示例的起点。

## 如何操作...

在外部包裹的`<div>`元素（带有页面`data-role`）中添加 ID 为`p1`。这将帮助 jQuery 识别和在多页面元素之间进行过渡。

```html
<div data-role="page" id="p1">
```

您已经创建了 jQuery Mobile 将识别为多个页面中的第一个页面。让我们创建下一个页面。在闭合的`<body>`标签之前，创建新的开放和闭合的`<div>`元素。给这个`<div>`元素一个`data-role="page"`元素，就像之前的实例一样，并且 ID 为`p2`。

```html
<div data-role="page" id="p2">
```

这个页面将需要`data-role="header"`、`data-role="content"`和`data-role="footer"`，就像之前的`<div>`元素`data-role="page"`一样。您也可以简单地复制上一节并将其粘贴到`"p2"` `<div>`元素中。

```html
<div data-role="page" id="p2">
  <div data-role="header">
    <h1>The second page</h1>
  </div>
  <div data-role="content">
    <p> Lorem ipsum dolor sit amet...</p>
  </div>
  <div data-role="footer">
    <h4>The Footer</h4>
  </div>
</div>
```

我们几乎完成了；我们只需要将页面链接在一起。在`"p1"`内容中，在闭合的`<div>`元素之前，添加一个`href`锚标签，链接到`"#p2"`：

```html
<a href="#p2">Page 2</a>
```

在`"p2"` `<div>`元素中，在`data-role="content"` `<div>`元素内部，添加另一个链接，链接回第一个页面的 ID：

```html
<a href="#p1">Back to Page 1</a>
```

现在保存文件并启动它。您将看到它创建了一个漂亮且原生的移动网站。单击**页面**链接，您将看到多页面之间有平滑的淡入淡出过渡。您还会注意到返回按钮也可以正常工作。如果您仔细考虑，这种行为对于网站的原生应用外观和感觉非常有用。请查看下一个截图中的第一个页面：

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_10.jpg)

下面的截图显示了第二个页面：

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_11.jpg)

## 它是如何工作的...

jQuery Mobile 可以在单个 HTML 页面内加载多个页面，并将它们呈现为多个页面或子页面。要在它们之间进行链接，只需添加`HREF="#page"`。当单击该链接时，jQuery Mobile 将查找具有该 ID 的内部页面，并平滑地将其写入视口。

# 在 jQuery Mobile 中创建列表元素

让我第一个说：我喜欢无序列表。相反，我对“程序员艺术”表格有同样强烈的厌恶。事实上，我在与我一起工作的人中赢得了一个“表格销毁者”的名声。在 HTML 中几乎没有一组东西不能用一个好的列表来显示，这就是为什么我喜欢 jQuery Mobile 处理列表的方式。在我看来，jQuery Mobile 列表证明了为什么列表是呈现数据、菜单、导航等的优越方式。足够了解我对无序列表的异常迷恋，让我们一起来学习一下 jQuery Mobile 列表的使用方法。

## 准备工作

想想你在互联网上发布了多少糟糕的表格，以及所有那些废代码变成了多么可怕的东西。对于你过去的罪行，这已经是足够的警告了，让我们继续前进，制作一些 jQuery Mobile 列表！

## 如何做...

创建一个新页面，包含 jQuery Mobile 所需的必要头部信息。包括 viewport `<meta>`标签和链接到 jQuery Mobile 样式表、jQuery JavaScript，最后是 jQuery Mobile JavaScript。你可以在自己的服务器上托管这些文件，也可以使用[`code.jquery.com`](http://code.jquery.com)上托管的文件。

```html
<meta name="viewport" content="width=device-width, initial-scale=1"> 
<link rel="stylesheet" href="http://code.jquery.com/mobile/1.3.0-beta.1/jquery.mobile-1.3.0-beta.1.min.css" />
<script src="img/jquery-1.9.min.js"></script>
<script src="img/jquery.mobile-1.3.0-beta.1.min.js"></script>
```

接下来创建一个带有`data-role="page"`属性的`<div>`元素。这是一个 HTML5 属性，jQuery Mobile 用它来部署样式、元素和小部件。

```html
<div data-role="page"></div>
```

在那个`<div>`包裹中，创建一个你最喜欢的机器人的无序列表。

```html
<ul>
  <li>Hero 1</li>
  <li>Bender</li>
  <li>Optimus Prime</li>
  <li>Soundwave</li>
  <li>Wall-E</li>
  <li>Maximillian</li>
  <li>R2-D2</li>
  <li>GORT</li>
  <li>Cat Quadcopter</li>
  <li>Robocop</li>
  <li>The Maschinenmensch</li>
</ul>
```

现在不要启动这个。我们俩都知道这看起来就像一个普通的列表。如果你为桌面版本制作了一个单独的 CSS，你可以在那里为这个列表设置样式。

将属性`data-role="listview"`添加到你的无序列表中。现在你可以启动它，看看它看起来像一个样式化的机器人列表。

让我们继续。因为这是一个列表，而且我们喜欢列表，我们将继续使用它，并看看 jQuery Mobile 可以对其进行什么操作。添加另一个属性，`data-inset="true"`。现在你的列表周围有一个很酷的包边，所以每个项目不会延伸到屏幕的边缘。

有时，你可能会得到一个非常长的列表，比如当你制作一个酷机器人列表时，因为机器人很酷，你不想不断滚动来选择你最喜欢的机器人。jQuery Mobile 为此提供了一个内置解决方案，即过滤元素。通过添加一个新属性`data-filter="true"`来调用它。刷新你的移动浏览器；你会看到一个输入框在顶部输入`filtertext`元素。搜索小部件使用客户端搜索/过滤来过滤列表项。你将不再需要滚动到列表底部找到那个令人惊叹的机器人。

让我们把这个提升到下一个级别。如果我们想要能够根据一些我们不想显示的其他数据来过滤机器人，比如机器人制造商，我们可以为每个列表项添加属性`data-filtertext=""`。它看起来会像这样：

```html
<li data-filtertext="Mom's Robots"><a href="#">Bender</a></li>
<li data-filtertext="Hasbro"><a href="#">Optimus Prime</a></li>
```

请参见以下图示：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_12.jpg)

这个列表甚至可以通过在数据属性中分配一个主题来进行不同的样式设置。尝试向无序列表添加`data-theme="a"`。现在尝试使用字母`b`到`f`。每个字母都有一个不同的主题，你可以应用到列表上。

这是到目前为止我们使用的不同属性的无序列表。在下面的代码片段之后的图示展示了不同的主题效果。

```html
<ul data-role="listview" data-inset="true" data-filter="true" data-theme="g">
```

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_13.jpg)

接下来让我们看看当这些列表项变成链接时会发生什么。为每个项目添加一个`href`锚标签。

```html
<li><a href="#">Bender</a></li>
```

当你刷新屏幕时，你会看到它添加了图标来指示它是一个可点击的链接。然而，由于`href`链接到`#`，它不会加载一个新页面。请参见下面的屏幕截图以获得示例：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_14.jpg)

让我们把这个列表分成两组，“摧毁所有人类”组和“工作机器人”组。为第一组在列表顶部添加另一个列表项，带有属性`data-role="list-divider"`。

```html
<li data-role="list-divider">destroy all humans</li>
```

在列表中间再添加一个类似的列表项。

```html
<li data-role="list-divider">workerbot</li>
```

这在下一个截图中显示：

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_15.jpg)

如果这样做让你感觉良好，你可能会有必要将你的机器人组织成这些组。我们可以进一步采取这种冲动，使列表嵌套。在你刚刚制作的`list-divider`中添加一个`ul`元素，然后将机器人的`li`代码的前半部分剪切并粘贴到这个`ul`元素中。

```html
<li data-role="list-divider">destroy all humans
  <ul>
    <li><a href="#">Bender</a></li>
    <li><a href="#">Optimus Prime</a></li>
    <li><a href="#">Soundwave</a></li>
    <li><a href="#">Wall-E</a></li>
    <li><a href="#">Maximillian</a></li>
  </ul>
</li>
```

对下一个列表部分也做同样的操作。然后刷新以查看新的结果。查看下图：

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_16.jpg)

你可以给父列表项添加一个`h3`标题包裹，甚至在段落元素中添加一个描述。这些列表变得越来越花哨。参见下面的截图：

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_17.jpg)

所以让我们做最后一个列表特性，并称之为一个配方。这是一个处理列表的华丽小部件。你可以制作一个可折叠列表元素的列表。我们将改变`ul`和`li`列表项的属性。首先，使外部`ul`列表元素包含属性`data-role="collapsible-set"`、`data-theme="b"`和`data-content-theme="d"`。

```html
<ul data-role="collapsible-set" data-theme="b" data-content-theme="d">
```

那个`ul`元素的两个直接子`li`元素应该有属性`data-role="collapsible"`。

```html
<li data-role="collapsible"><h2>workerbots</h2><p>...<p>
```

给那个可折叠`li`列表项的子`ul`元素添加属性`data-role="listview"`和`data-filter="true"`。

```html
<ul data-role="listview" data-filter="true">
```

整个无序列表看起来是这样的：

```html
<ul data-role="collapsible-set" data-theme="b" data-content-theme="d">
  <li data-role="collapsible">
    <h2>destroy all humans</h2>
    <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Integer consectetur quam in nulla malesuada congue volutpat mi molestie. Quisque faucibus, nisi ut malesuada volutpat</p>
    <ul data-role="listview" data-filter="true">
      <li><a href="#">Bender</a></li>
      <li><a href="#">Optimus Prime</a></li>
      <li><a href="#">Soundwave</a></li>
      <li><a href="#">Wall-E</a></li>
      <li><a href="#">Maximillian</a></li>
    </ul>
  </li>
  <li data-role="collapsible" >
    <h3>workerbots</h3>
    <p>Nam eget congue nisi. Ut id ante ac ligula congue auctor a et lacus. Suspendisse varius sem sed elit tincidunt convallis.</p>
    <ul data-role="listview" data-filter="true">
      <li><a href="#">R2-D2</a></li>
      <li><a href="#">GORT</a></li>
      <li><a href="#">Cat Quadcopter</a></li>
      <li><a href="#">Robocop</a></li>
      <li><a href="#">The Maschinenmensch</a></li>
    </ul>
  </li>
</ul>
```

完成的列表已经在下图中显示：

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_18.jpg)

## 它是如何工作的...

太神奇了。除了做一个好的列表之外，你并不需要做太多事情。任何表格都无法做到这一点。只要在你的元素中使用 HTML5 数据属性，jQuery Mobile 就会承担大部分工作，将你的列表转换成一个时尚的、移动端原生外观的 Web 应用。jQuery Mobile 获取数据属性（不影响布局或样式），并从中重写移动版本的 HTML 和 CSS。

# 使用 jQuery Mobile 添加一个移动端原生外观的按钮

让我们制作按钮！制作按钮可能看起来是设计中非常微不足道的一部分，但相反，当你构建一个 Web 应用程序时，按钮可能是网站可用性的一个非常重要的部分。

jQuery Mobile 有一个令人印象深刻的按钮调用数组，它们都很容易使用。它们也可以在许多其他 jQuery Mobile 小部件中使用。此外，从链接创建按钮和从`form input`元素创建按钮一样容易。

## 准备工作

在你的 IDE 或文本编辑器中，启动一个新的 HTML 文档，并添加必要的头部标签。首先添加 viewport`<meta>`标签，然后添加链接到 jQuery Mobile CSS 和 JavaScript 库 jQuery 和 jQuery Mobile。

```html
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/1.2.0/jquery.mobile-1.2.0.min.css" />
<script src="img/jquery-1.8.2.min.js"></script>
<script src="img/jquery.mobile-1.2.0.min.js"></script>
```

在你的 HTML`<body>`标签中，添加一个带有 HTML5 属性`data-role="page"`的`<div>`元素。在其中，添加一个`h1`标题，并用带有`data-role="header"`属性的`<div>`元素包裹它。在标题元素之后，添加一个带有`data-role="content"`属性的`<div>`元素。参见下面的代码片段：

```html
<div data-role="page">
  <div data-role="header"><h1>There be buttons</h1></div>
  <div data-role="content">...</div>
</div>
```

## 如何操作...

让我们比较一些不同的方法来创建一个基本按钮。首先是 HTML5 元素`<button>`，各种`<input>`表单元素`button`和`submit`，以及一个`href`伪按钮。在你的内容`<div>`元素中放入每种按钮。

```html
<button>HTML5 Button</button>

<input type="button" value="Input Button" />

<input type="submit" value="Submit Button" />

<a href="#" data-role="button">Link button</a>
```

启动你的新页面。你会看到四个看起来完全相同的新按钮（除了文字）。你可以看到每种方法都是以相同的方式呈现的。这很令人印象深刻，因为你的模板文件的非移动版本可能需要你使用某种类型的`submit`元素（这并不完全是移动优先的，但没有人是完美的）。参见下面的截图：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_19.jpg)

现在让我们继续这个教程，演示如何使用 jQuery Mobile 向按钮添加图标。这是一个简单的、一步到位的过程；它使用了一个 HTML5 数据属性，即`data-icon`属性。在第一个按钮中，添加`data-icon="delete"`属性；在下一个按钮中，添加`data-icon="check"`属性；在下一个按钮中添加`data-icon="plus"`；最后，在这组按钮中的最后一个按钮中添加`data-icon="arrow-l"`属性。你可以在文档中找到可以放在其中的图标列表。

```html
<button data-icon="delete">HTML5 Button</button>

<input type="button" value="Input Button" data-icon="check" />

<input type="submit" value="Submit Button" data-icon="plus"/>

<a href="#" data-role="button" data-icon="arrow-l">Link button</a>
```

下面的屏幕截图显示了新的按钮：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_20.jpg)

你还可以通过添加`data-mini="true"`属性使按钮变小，并使用`data-iconpos`属性将图标定位在按钮的右、左、顶部或底部角落。否则，你可以使用`data-iconpos="notext"`属性仅显示图标。参见下面的屏幕截图：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_21.jpg)

这些 jQuery Mobile 按钮的默认行为是横跨整个屏幕。你可以通过添加`data-inline="true"`属性来改变这一点。

```html
<button data-icon="delete" data-mini="true" data-inline="true">HTML5 Button</button>

<input type="button" value="Input Button" data-icon="check" data-iconpos="right" data-inline="true"/>

<input type="submit" value="Submit Button" data-icon="plus" data-iconpos="top" data-inline="true"/>

<a href="#" data-role="button" data-icon="arrow-l" data-iconpos="notext" data-inline="true">Link button</a>
```

虽然有些混乱，但你可以在这里看到它的效果：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_22.jpg)

它们将变成内联元素，类似于以内联方式显示的列表项。我们几乎完成了，但还有一些有趣的地方。我们还可以轻松地创建按钮组。删除在上一节中添加的`data-inline="true"`属性。接下来，用`<div>`元素包装按钮元素，并添加`data-role="controlgroup"`属性。

```html
<div data-role="controlgroup">

  <button data-icon="delete" data-mini="true" >HTML5 Button</button>
  <input type="button" value="Input Button" data-icon="check" data-iconpos="right"/>

  <input type="submit" value="Submit Button" data-icon="plus" data-iconpos="top" />

  <a href="#" data-role="button" data-icon="arrow-l" data-iconpos="notext" >Link button</a>

</div>
```

现在你可以看到创造性按钮组的潜力，并将它们整齐地放在一起。让我们给按钮组添加一些更多的效果。如果你在`"controlgroup"` `<div>`元素中添加`data-type="horizontal"`，你会弄得一团糟。清理这一点的一种方法是将所有的`data-iconpos`属性改为`"notext"`。

最后，正如我们在之前的 jQuery Mobile 教程中所看到的，`data-theme`属性可以使你的按钮变得丰富多彩。为了快速展示这种效果，为每个按钮添加不同的`data-theme`属性（`a`、`b`、`c`、`e`）（我跳过了`d`，它看起来太像`c`）。这些在下一个屏幕截图中有所体现：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_23.jpg)

## 工作原理...

你真正需要知道的是如何使用哪些数据标签使 jQuery Mobile 识别 HTML 元素并将其转换为移动原生按钮。实际上，当你有正确的属性时，它会自动发生，并且无论应用于`submit`按钮的方法如何，它都能正常工作。jQuery Mobile 在 HTML5 属性上触发事件，并将 HTML 和样式添加到渲染的页面中。

# 在移动浏览器中仅使用媒体查询添加移动样式表

在这个教程中，我们希望能够在模板中仅供移动浏览器使用样式表。除了 JavaScript 之外，在客户端渲染中没有办法监听用户代理并为移动浏览器提供一些逻辑或特殊模板。让我们采用 K.I.S.S.方法，并尽可能接近媒体查询。

当然，有许多种方法可以编写 JavaScript 来检测用户代理，我们将在后面的教程中介绍，但现在让我们编写一个杀手级的媒体查询来锁定特定 CSS 的移动浏览器。在之前的教程中，我们的媒体查询是在样式表中执行的。这一次将会有所不同，因为我们将把它放在 HTML 头部链接中。改变是好的，不要担心。我们将媒体查询放在 HTML 链接到 CSS 文件中的原因是，我们希望只在特殊情况下调用该 CSS 文件。当你使用移动优先设计和 jQuery Mobile 等技术时，这个教程尤其有用。

## 准备工作

打开您方便的 IDE 并开始一个新的 HTML 页面。确保添加您的视口`<meta>`标签。如果您愿意，您可以在 HTML 主体中添加一个文字段落。

## 如何做...

在您的新 HTML 文件的`<body>`标签中，添加两个文字段落。每个都有不同的类（`class="a"`和`class="b"`）。这将是足够的 HTML 来演示媒体查询的工作。

```html
<p class="a">Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
<p class="b">Nulla ante tortor, rutrum eu sollicitudin eget, vehicula quis sem. Nullam cursus placerat luctus.</p>
```

现在回到`<head>`标签。首先，让我们添加视口`<meta>`标签。包括内容属性`"width=device-width"`。接下来，为字体添加一些简单的样式（`font-size: 100%`）。

```html
<style>
  html{font-size:100%}
</style>
```

接下来，我们将添加移动 CSS 样式表的链接和媒体查询。基本的样式表链接包含`rel="stylesheet"`和路径。添加它需要满足的条件。为`screen`和`max-device-width=320px`添加一个媒体查询。您的 CSS 链接应该如下所示：

```html
<link rel="stylesheet" media="screen and (max-device-width:320px)" href="mobile.css" />
```

在 HTML 文件中我们没有更多要做的事情，所以在同一个目录中创建一个 CSS 文件并将其命名为`mobile.css`。打开它进行编辑。我们在这里不需要做太多事情，只需要一行就足够了。为`b`类段落添加一行，并为字体大小添加一个属性`2rem`。REM 表示相对 EM，或者相对于根字体大小（如果您跳过了响应式排版配方）。

```html
p.b{font-size:2rem}
```

现在让我们试一试。在浏览器中打开您的 HTML 文件，然后在移动设备模拟器中打开它。在这里，您可以看到移动设备具有独特的呈现方式，`b`类段落的字体大小不同。请参阅以下屏幕截图中的这个配方：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_05_24.jpg)

## 它是如何工作的...

媒体查询的设计仅在具有 320px 或更低分辨率的设备上才会激活。大于这个值的任何值都会忽略（它仍然会下载）链接的 CSS 文件。您还可以为其他特定设备编写媒体查询。

# 仅为移动浏览器添加 JavaScript

在之前的配方中，我们在样式表链接中编写了一个媒体查询。这对于我们自己的移动优先响应式网页开发非常有用。然而，当使用专门针对移动平台的 JavaScript 代码，比如 jQuery Mobile 时，您可能不希望在桌面计算机上启动它们。让我们构建一个小的 JavaScript 代码，检测移动设备屏幕大小，然后为其部署 jQuery Mobile，但不适用于桌面设备。

## 准备好了

像 jQuery Mobile 这样的移动优先技术是在拥有服务器端技术时的惊人工具。它们需要服务器端逻辑才能发挥最佳作用。如果您没有幸运地获得了服务器端逻辑的访问权限，您可以使用一些客户端技巧来发挥您的魔力。

## 如何做...

如果您还没有浏览过 jQuery Mobile 的配方，请现在浏览一下；我们将重用我们已经使用过的配方之一。

打开之前使用 jQuery Mobile 创建的文件之一。您可以使用*使用 jQuery Mobile 添加移动原生外观按钮*的配方。如果您已经按照这个配方制作了一个移动的、原生外观的按钮，请使用它进行跟踪。

当我们上次看到这个文件时，jQuery Mobile 脚本将您的普通无聊的 HTML 按钮转换成了很酷的 jQuery Mobile 按钮。您所需要做的就是在您的元素中包含 HTML5 数据属性，然后 jQuery Mobile 会自动完成剩下的工作。那么如果您只想在移动设备上发生这种情况呢？

如果没有客户端脚本的魔力，你可能会遇到麻烦。我们首先希望脚本意识到它正在处理一个移动设备。一种方法是通过查询 DOM 元素的用户代理。我见过一些人这样做，但足够复杂以至于容易出错。所以，让我们检测设备屏幕的大小。大多数移动视口最多为 600 像素宽或更小；所以现在，如果您正在开发应用程序，并假设这是正确的最大尺寸，那么您是安全的。

所以让我们让脚本从 DOM 获取屏幕宽度；如果小于 600px，就获取 jQuery Mobile 脚本。首先，使用 jQuery，在文档加载时触发一个函数。

```html
$(document).ready(function(){
  //
});
```

在函数内部，编写一个条件语句；如果屏幕小于 600，则做某事。

```html
$(document).ready(function(){
  if (window.screen.width < 600){
    //Do something!
  };
});
```

这是一个很好的开始，但让我们更具体地谈谈“做某事”。我们希望脚本能够获取并运行 jQuery Mobile 脚本。一个很好的方法是使用 jQuery 的`$.getScript()`函数。所以把它放在`if`条件中，包括 jQuery Mobile 源 URL。

```html
$(document).ready(function(){
  if (window.screen.width < 600){
    $.getScript("http://code.jquery.com/mobile/1.2.0/jquery.mobile-1.2.0.min.js");
  };
});
```

现在在您的移动设备模拟器中加载页面。

## 它是如何工作的...

如果模拟器成功地欺骗了请求中的设备宽度，您将看到 HTML 页面的 jQuery Mobile 版本。在您的桌面浏览器中，无论浏览器窗口大小如何，您都无法加载 jQuery Mobile 脚本。

jQuery 的`$.getScript()`是一个将外部脚本加载到头部的函数。您可以像我们在示例中所做的那样使用它，有条件地加载外部 JavaScript，并在成功加载时执行其他函数。


# 第六章：优化响应式内容

在本章中，您将学习以下内容：

+   使用 IE 的开发者工具进行响应式测试

+   浏览器测试-使用插件

+   开发环境-获取免费的 IDE

+   虚拟化-下载 VirtualBox

+   为 Chrome 获取浏览器调整大小器

# 介绍

本章的食谱涵盖了广泛的主题。本章没有涵盖任何代码，但食谱属于更多功能性的范畴。本章更多地讨论了您将用于开发和测试代码的工具。在这里，我们将确保我们的代码按我们的意愿工作。虽然这个话题可能看起来不那么有趣，但它和磨练您的设计和开发技能一样重要。没有自信的吹嘘能让前端开发人员免受错误的影响，而在项目不断发展的过程中可能出现太多问题。请阅读这些食谱并尝试这些工具，它们将使您的工作更轻松，更不容易出现错误。

# 使用 IE 的开发者工具进行响应式测试

拥有响应式设计还包括为所有常见的浏览器优化设计，这无疑是响应式设计中最不令人兴奋的方面。没有办法美化这一点，许多 HTML5 和 CSS3 的特性甚至在未来版本的 Internet Explorer 中也得不到支持，而得到支持的特性有时可能会被错误地渲染。更疯狂的是，版本 7、8 和 9 的行为都不同，还有无数用户根本无法或不愿意更新他们的浏览器。还有一些公司投资于只能在旧版本的 Internet Explorer 上运行的网络软件的问题。这种缺乏更新已经被 Chrome 和 Firefox 等其他浏览器解决了；Internet Explorer 团队确实需要赶上。然而，因为您希望您的工作无论在哪个浏览器中都能看起来良好，这个责任就是您的，要让它在每个浏览器中都能正常工作。

## 准备工作

与项目中的客户和其他设计师讨论您想为 Internet Explorer 用户提供什么级别的支持。支持旧版本的 Internet Explorer 有几种可能的策略。讨论每种策略需要多少额外工作来支持旧版本的 Internet Explorer，应该花费多少钱，以及谁应该为此付费。您最不希望的是推出客户全新的网络项目，然后他们开始抱怨在他们喜爱的老旧浏览器中看起来有问题。

首先要问的问题是：您可以用 Internet Explorer F12 开发者工具做什么？答案是，您可以使用它来调试 Internet Explorer 显示您的代码的方式，并在不同版本的 Internet Explorer 之间切换，看看您的网站在每个版本中的效果如何。

## 如何做...

如果您不使用 Windows 计算机，您将无法本地获取 Internet Explorer F12 开发者工具。这并不意味着您可以简单地忘记为 IE 进行测试，希望您所做的工作有效。有许多网页和插件承诺准确模拟 IE 的多个版本的怪癖。我尝试过许多，发现没有一个能真正经得起与原始 IE 开发者工具的测试。因此，在经过多次尝试和失败后，我发现测试 IE 的唯一可靠方法，而不必购买几台计算机进行测试，就是使用虚拟化。我有几个 Windows 虚拟机实例，安装了不同版本的 Internet Explorer。我发现这是唯一确定的方法。如果您想了解如何开始虚拟化，请参阅本章中的*虚拟化-下载 VirtualBox*食谱。

所以一旦我们启动了 Windows 机器并更新到最新版本的 Internet Explorer，让我们看看 F12 开发者工具能为我们做些什么。要么按下键盘上的*F12*，要么点击屏幕右上角工具栏上的齿轮图标，显示 F12 开发者工具。这在下面的截图中有演示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_01.jpg)

在这里你可以做的第一件有用的事情是点击指针图标，将鼠标移动到浏览器窗口中行为异常的元素上。当鼠标移动时，你会看到你的鼠标移动到的元素周围有一个白色的边框。一旦你看到你想要检查的元素周围有白色边框，点击它；HTML 窗格将会把 HTML 代码的那一行带入左侧窗口的焦点，并在右侧显示其 CSS。在 CSS 窗格中，你可以编辑每个元素的 CSS 属性树。

如果你想添加一个 CSS 属性，点击**属性**按钮。通过向下滚动到页面底部，你可以为属性添加一个新的名称和值对。你可以使用这两个工具来测试不同的 CSS 属性变化或调试一些奇怪的 IE 行为。

另一个有用的工具是**浏览器模式**选择菜单。你可以使用这个工具在不同的浏览器版本之间切换。这是一个很好的工具，可以在工作中进行即时检查。在这里，你还可以测试你的 IE 特定样式表。你可以在下面的截图中看到这一点：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_02.jpg)

## 它是如何工作的...

根据 MSDN，F12 开发者工具代表文档对象模型（DOM）解释页面的实际方式，而不是你实际编写的代码。

## 还有更多...

你可能会遇到的另一个陷阱是，在设计一个可能作为内部软件或在内部网站的同一域名下访问的站点时。Internet Explorer 将使用 Internet Explorer 7 兼容视图作为默认的渲染视图。

兼容模式是 IE 8 中添加的一个功能，以便为旧标准开发的网站在新浏览器中仍然可以工作。通常，人们的浏览器被设置为在兼容模式下渲染内部网站。要使为 IE 7 构建的站点在最新的 Internet Explorer 中工作，你需要设置这个`<meta>`标签以在所需的渲染版本下进行渲染。为了强制浏览器始终使用最新的渲染引擎进行渲染，你需要指定以下`<meta>`标签以防止这种情况发生。

```html
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
```

# 浏览器测试 - 使用插件

在任何开发过程中，测试都是一件大事。对一些人来说，测试的概念被错误地视为工艺粗糙或工作的重要性不够的标志。这个想法是错误的。相反，严格和彻底的测试是确保软件接近完美状态的唯一途径。我觉得自己非常幸运能够与质量保证测试人员一起工作，他们的角色是测试开发团队的工作。在以前的生活中，我不得不做所有的测试工作，我可以说这是一种奢侈。

在这个教程中，我们将讨论测试的一个特定领域，即跨浏览器测试。不久以前，这个过程并不复杂，但同时也更具挑战性。为移动设备测试 Web 项目的想法并不常见；它根本不会被期望看起来相似，甚至显示相同的内容。因此，你需要测试的设备数量通常限于你可以在虚拟环境中启动的设备，并且它们都是台式设备。工具也是有限的，通常只是具有较旧浏览器版本的虚拟桌面。还记得那些拒绝放弃 IE6 的顽固的人吗？

进行浏览器测试的一种方法是简单地拿出信用卡，购买您认为可能在您的软件上查看的每个设备。我实际上从未遇到过任何人这样做，但我认为我给孩子们读的童话故事中有一两个讲述了这种现象发生的情况。对于为了赚钱而工作的人来说，这不是一个实际的解决方案。这导致了互联网上出现了付费和免费的跨浏览器测试工具市场。

## 准备工作

如果您开始认为这将是一个昂贵的步骤，那就冷静下来。没有必要去购买市场上的每一款新移动设备。有很多模拟器可以满足您的大部分需求。

## 操作步骤...

我已经在互联网上搜索并为您建立了一个免费测试工具列表。跟我一起浏览列表并查看它们。在浏览器标签中打开之前的响应式网页设计（RWD）项目文件中的一个。对于每个模拟器，您都需要通过在模拟浏览器的地址栏中输入文件来打开它。如果您还没有做过这些，或者只是没有方便的文件，请转到 Packt 网站并下载它们。继续进行模拟器。

首先让我们看看在线浏览器模拟器。转到[`theleggett.com/tools/webapptester`](http://theleggett.com/tools/webapptester)。在这里，您可以在 iOS 设备的 Web 模拟器上测试您的 RWD 网站。它可以读取您的本地文件。您可以在纵向和横向模式之间切换，并选择 iPhone 或 iPad。这很简单，您不需要安装任何复杂的应用程序或插件。如果您需要紧急情况下的测试，想要快速测试，并且不想安装任何东西，这是一个不错的选择。您可以在以下截图中看到模拟器的运行情况：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_03.jpg)

在[`ipadpeek.com`](http://ipadpeek.com)上还有一个方便的基于 Web 的 iOS 模拟器。您也可以在这里选择纵向与横向以及 iPad 与 iPhone（包括 iPhone 5）选项。这个模拟器也可以查看您的本地服务器。我一直在提到这一点，因为有太多基于 Web 的模拟器由于这个原因没有进入这个列表，包括一些商业模拟器。下一张截图显示了这个基于 Web 的模拟器：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_04.jpg)

接下来让我们看一些基于应用程序的浏览器测试工具。

Ripple 浏览器插件是一个非常好的测试工具。它可以在[`chrome.google.com/webstore/detail/ripple-emulator-beta`](https://chrome.google.com/webstore/detail/ripple-emulator-beta)下载。这个模拟器比其他模拟器更胜一筹。首先，它做的工作和其他模拟器一样（即模拟 iOS 设备），但它做得很好。这个模拟器比您需要的功能更多，但它将为您的网页应用的未来移动集成进行测试。让我们开始找到并安装 Ripple 浏览器插件。这很容易。只需搜索它。还记得以前的事情是多么困难吗？

一旦您进入 Google Chrome 网络商店，点击大蓝色按钮并安装浏览器插件。请参阅以下截图：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_05.jpg)

安装完成后，在你的 Chrome 浏览器的地址栏旁边会出现一个带有蓝色涟漪的新浏览器按钮。在浏览器中，打开你的响应式 Web 应用。接下来，点击**Ripple plugin**按钮，然后当弹出菜单询问是否要启用 Ripple 插件时，点击**Enable**。浏览器窗口的内容会转换为显示设备的模拟，显示你页面的移动版本。此外，你会注意到许多充满了惊人设置和工具的工具栏。让我们探索其中一些。大部分超出了我们正在做的范围，但你仍然应该注意这些。随着你开发更高级的移动 Web 应用，这些会派上用场。你可以在下一个截图中看到 Ripple 的众多设置。

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_06.jpg)

首先，点击屏幕左上角的菜单，以显示许多不同的移动设备。在下面，你可以选择横向或纵向方向。当你浏览不同的模拟设备时，你会发现有一个信息面板，其中会更新当前模拟设备的技术规格。测试完成后，只需再次点击 Ripple 按钮，然后选择**Disable**选项。

这个模拟器中还有许多其他很棒的工具，超出了本书的范围。花一些时间自己去发现一些有用的工具，以便将来在移动 Web 应用项目中使用。现在让我们继续下一个浏览器测试工具。

Opera Mobile Emulator 位于[`www.opera.com/developer/tools/mobile`](http://www.opera.com/developer/tools/mobile)。当我第一次看到它时，我几乎跳过它，因为它是 Opera。尽管它是一个严肃的浏览器项目，但我已经习惯于忽略它进行测试。它确实是一个值得尊重的移动设备浏览器。我很高兴我还是试了一下。我惊讶地发现它有许多选项，你真的可以用它来模拟许多设备。它实际上是一个很好的移动设备浏览器测试工具，可以在多个 Android 设备上测试项目。这是一个重要的声明；请注意我说的是 Android 设备，这意味着它只测试这些设备。但是，它确实允许你创建和保存自定义屏幕尺寸和设置。让我们直接安装它并设置一些自定义屏幕尺寸。

要找到它，使用你喜欢的搜索引擎，输入`Opera Mobile Emulator`。这应该会带你到一个页面，下载适用于你操作系统的 Opera Mobile Emulator（[`www.opera.com/developer/tools/mobile/`](http://www.opera.com/developer/tools/mobile/)）。下载并安装后，启动应用程序。

当应用程序加载时，你会看到屏幕左侧有许多定义好的设备可供选择。选择其中任何一个设备，然后点击**Launch**按钮。查看以下截图以进行演示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_07.jpg)

我们还可以创建自定义设备配置文件并保存它们。由于没有 iPhone 设备设置，我们将为 iPhone 设置一个自定义屏幕。从**Profile**列表中选择**Custom**。接下来，在**Resolution**下拉菜单中，选择分辨率为 320 x 480。然后在**Pixel Density**下拉菜单中，点击**Add**，添加`326`。现在点击**Launch**。你也可以点击**Save**或**Save As...**按钮来保存你的配置文件。iPhone 4 的尺寸为 640 x 960，iPhone 5 的尺寸为 640 x 1136。这在下面的截图中显示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_08.jpg)

Opera Mobile 浏览器的一个重要功能是您可以使用它来调试您的代码！要使用此工具，请下载并安装桌面设备的 Opera；转到[www.opera.com](http://www.opera.com)。接下来，打开它，然后在**菜单**下，转到**工具** | **高级** | **Opera Dragonfly**。在 Opera Dragonfly 中，在右侧窗口中，找到并单击**远程调试配置**按钮，然后单击**应用**。然后在您的移动浏览器模拟器中，在地址栏中输入`opera:debug`，然后单击**连接**。现在您可以调试您的移动代码。

# 开发环境-获取免费 IDE

在本书中，我经常提到在 IDE 中开发代码，或者集成开发环境。IDE 是开发人员创建和管理代码的工具集。有许多免费和付费的 IDE 可供您使用，以帮助生成优秀的代码。您应该选择哪个 IDE？这取决于许多因素。成本是一个重要因素；Visual Studio 可能需要花费数百美元，而对于额外的自动建议插件可能需要花费更多。昂贵的 IDE 只要有人为它们买单就很棒！

## 准备工作

对于这个步骤，让我们选择更简单、更便宜的路线，并安装一个好的免费 IDE。我曾经作为一名科学家工作了几年，因为十位科学家中有九位偏爱 NetBeans，所以您可能会猜测我使用 NetBeans。我可以告诉您，您的假设在经验上有 90%的概率是正确的。

您可能认为增强型记事本足以构建您的应用程序。这可能是真的；您的记事本足以编写一些代码。但使用开发环境带来的远不止是一个大型程序来编写您的代码。它还具有增强的项目组织、自动建议和社区开发的插件等功能，几乎可以适用于几乎所有类型的项目或特殊功能。

## 操作步骤…

要获取 NetBeans，您可以直接转到 NetBeans 网站[www.netbeans.org](http://www.netbeans.org)，然后单击大橙色**下载**按钮。下一页有一个网格选项，用于 NetBeans 下载；您可以选择 PHP 选项，或"All"选项以获取您需要的前端开发 IDE 软件包。但在下载任何内容之前，还有一个谜题。NetBeans 运行在 Java 上，而 OSX 和 Windows 都没有预装 Java。请参阅以下屏幕截图：

![操作步骤…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_09.jpg)

如果您已经安装了 Java 开发工具包，请继续下载和安装过程。如果没有，请转到 Java JDK 网站[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)（如果该网址无效，请搜索 Java JDK，然后单击**下载**链接）。在这里，您可以下载包含最新稳定 NetBeans 版本和 JDK 的软件包。这是一个很大的文件，所以开始下载并去喝杯咖啡。

展开下载的软件包；安装过程将负责安装 IDE 和 JDK。

接下来，打开 NetBeans。您应该在 IDE 的左侧窗格上看到文件和项目浏览器。如果没有，并且您无法打开任何项目，则说明未激活 Web 开发插件。打开**工具**菜单，然后选择**插件**。在**可用插件**中，找到 PHP 插件并激活它。您的 IDE 将要求重新启动。重新启动后，您将在 IDE 的左侧看到**项目**和**文件**窗格。如下图所示：

![操作步骤…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_10.jpg)

## 工作原理…

NetBeans 集成开发环境是用 Java 构建的，因此需要 JDK 才能运行。它作为基本 IDE；您可以下载并安装您特定项目所需的插件。此外，由于它是开源的，人们可以开发更多酷和有用的插件。测试、自动建议、语言和其他插件不断在开发中。因此，请尝试勇敢地尝试一些，看看它们是否能增强您的开发工作。

# 虚拟化 - 下载 VirtualBox

虚拟化是开发人员工具箱中的关键工具之一。它在开发过程的许多不同阶段中使用。我们在本文中的重点将放在测试上。但首先，我想提一下它如何在进程中进一步使用。设置虚拟机允许您在只提供和支持不同操作系统的商店中使用您首选的操作系统和工具集。例如，如果您需要使用 Visual Studio 但不想使用 Windows，您可以启动一个虚拟机并在其上开发应用程序。您还可以在虚拟机上使用 LAMP 堆栈并将其启动。

虚拟化是一个资源密集型的计算任务。当您运行带有 IDE、Web 服务器和远程桌面查看器的虚拟机时，很容易使系统变得缓慢，甚至可能使系统陷入停滞。因此，我的建议是在尝试加载多个虚拟机之前，先加载内存。

## 准备就绪

在继续进行新 VM 的简单任务之前，让我们探讨一下我们即将开始的背后的一些原因。第一个原因是 Internet Explorer。我还需要说什么吗？无论如何，对于未经培训的人，我会说。每当设计师不得不使他的美丽现代网站变得糟糕，以便在任何版本的 Internet Explorer 中运行时，都会有一种震撼人心的共同呻吟。在 IE9 中看起来不错是不够的；我们还需要使其在 IE8 中看起来体面。

为什么这是 Web 开发的现实？因为人们在升级时很慢；企业在这方面甚至更糟。要了解您网站访问者中使用的已弃用浏览器的比例，请安装 Google Analytics 并监视访问您页面的浏览器类型。您可能会惊讶地发现，有 20%的流量使用 Internet Explorer 7，您需要对其进行营销。您无法在同一台计算机上运行 IE7 和 IE9。因此，解决方案是开始可视化其问题。

为了能够测试您的网站以确保其优化，或者至少对每个旧版本的 Internet Explorer 进行降级，或者对移动设备进行响应，您可以使用虚拟化。为您需要测试的每个不同浏览器版本启动一个新的虚拟机。在本文的其余部分，我们将介绍创建新虚拟机的过程。

## 如何做到...

VirtualBox 是由 Oracle 提供的免费软件。还有其他虚拟化软件，如 VMware，它们是收费的。要下载 VirtualBox，请访问[www.VirtualBox.org](http://www.VirtualBox.org)并从**Downloads**页面下载。

一旦下载完成，安装过程就像其他任何东西一样简单。在 OS X 中，解压并将其拖放到`Applications`文件夹中。在 Windows 中，它提供不同的选项。此时我不会尝试任何棘手的事情；它将在默认选项下运行良好。两个版本都将在您的个人资料主目录中设置虚拟机的目录。

接下来，您将需要虚拟机上要安装的客户操作系统的操作系统安装光盘或磁盘映像（ISO）。当您准备好并且准备好您的 OS 安装软件时，请单击**Oracle VM VirtualBox Manager**左上角的**New**按钮。这将启动一个名为**New Virtual Machine Wizard**的向导。请参阅以下屏幕截图：

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_11.jpg)

在下一个屏幕上，您将被要求输入名称和操作系统类型。接下来，选择要为虚拟机分配的内存。推荐的基本内存大小为 192 MB。下一个屏幕会要求您创建新磁盘或使用现有磁盘。当从磁盘或镜像安装新操作系统时，您将要选择**创建新硬盘**。在下一个屏幕上，使用已经选择的默认选项**VDI**（VirtualBox 磁盘映像），然后选择**动态分配**。

然后，您将被要求命名包含虚拟映像的文件夹，以及虚拟磁盘的大小；默认大小为 10 GB。接下来是摘要页面，您可以在继续之前审查您的选择。到目前为止，我们只创建了虚拟机，相当于打开一个没有操作系统的新计算机。

为了完成我们已经开始的工作，我们需要启动您的新虚拟机并在其上安装 Windows。选择您的新虚拟机并启动它以启动**首次运行向导**。它会提示您选择安装介质；在这里选择您的磁盘或镜像 ISO。选择您的安装介质，继续到**摘要**页面，然后进行操作系统安装过程。由于这是一个虚拟驱动器，所以这个过程非常快。我会跳过安装 Windows 桌面操作系统软件的细节；这里没有秘密的最佳实践，只需点击默认选项并继续。

当我写那段文字时，我的虚拟机已经完成了操作系统的安装。我告诉过你它很快。一旦启动，您可以使用默认的浏览器版本或获取更新的版本。这取决于您项目的需求。我建议为 IE9、IE8，甚至 IE7 单独创建一个虚拟机。一旦它运行起来，您应该有一个良好、干净、正常工作的 Windows XP 版本。请参见以下截图：

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_12.jpg)

现在虚拟机已经安装了操作系统，启动浏览器并将其指向主机计算机的 IP 地址。如果您的本地 Web 服务器正在运行，并且没有在 VirtualBox 网络设置中进行修改，您应该能够看到您本地 Web 服务器上的文件。

您可以使用这个来测试您的网页设计，以确保桌面版本对所有桌面用户都能正常工作，甚至是那些使用 IE7 的用户。

您不再需要托管多个版本的 Chrome 或 Firefox，它们都已开始自动更新。旧版本的 Firefox 已经成为过去。

这涵盖了桌面测试。在我们进入下一章之前，让我们看看如何使用 VirtualBox 来测试移动设备。

在互联网上存在可下载的虚拟机，其中已经安装了 Android。我在[`www.android-x86.org/download`](http://www.android-x86.org/download)找到了一些可下载的资源。通过搜索`Android-v4.7z`，我在这里找到了一个好的下载链接：[`www.vmlite.com/index.php?option=com_kunena&func=view&catid=9&id=8838`](http://www.vmlite.com/index.php?option=com_kunena&func=view&catid=9&id=8838)。它提供了一个从[`www.vmlite.com/vmlite/VMLite-Android-v4.0.4.7z`](http://www.vmlite.com/vmlite/VMLite-Android-v4.0.4.7z)下载的链接。下载并将虚拟映像解压到您的硬盘。

让我们看看当我们用 VirtualBox 打开其中一个 Android 映像时会发生什么。在下载了 Android 映像后，启动一个新的虚拟映像。在选择操作系统类型时，从下拉列表中的操作系统列表中选择**Linux**，并选择**其他 Linux**作为**版本**。请参见以下截图以进行演示：

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_13.jpg)

在**虚拟硬盘**屏幕上，选择**使用现有硬盘**，然后在选择对话框中，浏览到您解压到驱动器的文件夹。其中有一个`*.vmdk`文件。选择它加载到您的新虚拟机中，并点击**继续**。

继续查看**摘要**页面之后，您的 Android 模拟器将启动并完全可操作。现在您可以在真正的 Android 模拟器上测试您的应用程序，如下一个屏幕截图所示：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_14.jpg)

## 它是如何工作的…

虚拟机允许您在一个通用类型的模拟计算机上安装操作系统。您可以在虚拟机上随时复制、编辑和删除虚拟机，并且可以轻松地在虚拟机之间切换。在这些虚拟机中，您可以做很多事情；拍摄快照，如果出了问题，就重新开始。使用虚拟机是一个很好的做法，不需要太担心让您的操作系统运行 Apache。

# 获取 Chrome 浏览器调整大小

想象一下，您不断地拖动浏览器窗口的底部角，左右调整大小，观察您最佳的视觉估计告诉您应该达到媒体查询断点的点，并通过显示网站的新优化显示来优雅地响应。您面临的一个远非微小的问题是，您不知道您的断点将会达到哪里，因为您对当前浏览器大小没有真正的概念，也没有可靠的方法将其设置为所需的大小。看起来很傻，不是吗？坐在您身后的同事也这么认为。

一定有更好的方法。有了！现在您可以阻止您的同事嘲笑您的浏览器窗口把戏。

## 准备工作

在互联网上有一些网站可以将您的浏览器调整为最流行的断点。然而，这些很难找到，也不可靠。我发现最好的选择是安装一个好的浏览器调整大小插件。

## 如何做…

我发现的最佳解决方案是 Chrome Window Resizer 插件。要在 Chrome 上获取它，请在您喜欢的搜索引擎中搜索`Window Resizer`，然后单击链接转到 Chrome Web Store 上的插件页面。单击大蓝色按钮，上面写着**添加到 Chrome**。

这是一个相当简短和简单的安装。按照流程操作，并在每次提示时选择“是”。在下一个屏幕截图中看到调整大小器的操作：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_15.jpg)

完成后，您将看到世界上最小的浏览器停靠在 Chrome 浏览器的地址栏旁边；不，开玩笑的，那是一个图标。当您单击它时，您将看到一个下拉菜单，其中包含不同的窗口大小。选择这些尺寸是因为它们是在互联网上最常见的屏幕尺寸。

如果您在您的网络项目中安装了 Google Analytics 等分析工具，您可以很好地了解您的观众是什么样子的。就这个教程而言，您会想要查看浏览器屏幕尺寸。导航到**受众**选项卡，并展开**技术**切换元素以显示**浏览器和操作系统**链接。您将看到受众浏览器的细分。在该页面上，将**主要维度：**更改为**屏幕分辨率**。现在您将能够看到站点访问者最常见的屏幕尺寸。这个工具应该能够让您了解在设计中需要集中关注的领域。请参阅以下屏幕截图：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_16.jpg)

### 提示

分析将为您提供有关用户屏幕的一些有用信息，但请记住，人们通常只使用其屏幕的一部分来浏览器窗口。

回到浏览器调整大小插件；在您的项目上尝试一些内置尺寸，看看它的响应。这个工具将是您响应式设计工具箱中的一个很好的测试工具。

除了设置的尺寸之外，您会发现下拉菜单还有一个**编辑分辨率**菜单项。在这里，您可以添加您在分析屏幕上发现的任何屏幕尺寸。根据我的分析报告，我可能想首先添加`1920 x 1080`，`960 x 1080`，`1772 x 1038`和`886 x 1038`。我在下一个屏幕截图中演示了这个选项：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_06_17.jpg)

## 它是如何工作的…

这个非常有用的工具可以直接插入到您的浏览器中，通过模拟不同的屏幕分辨率来发挥其作用。虽然好的软件有时看起来像是魔术，但它并不真的是魔术。通过分析工具，您可以为您网站的访问者屏幕设计特定的优化方案。


# 第七章：不显眼的 JavaScript

在本章中，您将学到：

+   不显眼地编写“Hello World”

+   使用事件监听器创建一个发光的“submit”按钮

+   当您悬停在按钮上时使按钮突出显示

+   使用不显眼的 jQuery 调整元素

+   使用不显眼的 JavaScript 掩盖密码

+   使用事件监听器来为图像阴影添加动画

# 介绍

不显眼的 JavaScript 的概念完全符合响应式设计。通过将交互层与演示层保持一定距离，您可以为您的 Web 应用程序构建很大程度的灵活性。因为移动设备有非常不同的输入方法，您可能需要通过不同的事件调用一个函数。您可能希望为页面创建一个桌面版本，并为移动版本使用 jQuery Mobile；通过使用不显眼的 JavaScript，使用相同的模板文件，这并不是一项困难的任务。

# 不显眼地编写“Hello World”

响应式设计的一个重要方面是交互。我们知道移动设备和台式机有非常不同的用户界面，我们不能期望我们的 JavaScript 交互脚本能在所有设备上运行。一个例子是`.mouseover()`或鼠标悬停事件监听器。鼠标不连接到触摸屏设备上，因此任何错误的`.mouseover()`事件尝试可能会作为`.click()`事件执行。解决方法是完全从模板中移除交互脚本。

## 准备工作

这种方法被称为“不显眼的 JavaScript”。在这里，您可以通过一系列事件监听器创建一个外部 JavaScript，而不是在 HTML 模板中嵌入`onclick()`之类的脚本。

## 如何做...

让我们从一个简单的例子开始；我们将只创建一个按钮和一个警报。许多 JavaScript 都是从测试开始的；实质上，我将创建一个事件监听器，然后用警报进行调试。我们首先创建一个带有简单`submit`按钮的 HTML 页面。

```html
<body>
<input type="submit">
</body>
```

就是这样，这是一个简单的任务，但并不是很令人兴奋。那只是一个基本的`submit`按钮，即使它没有提交任何内容。所以让我们一步一步地让它变得更有趣。首先在按钮上添加一些自定义文本，这样当页面准备好时，我们至少有一些期望会发生什么。我们添加`value="Say Hello"`。这对于`body`标签来说已经足够了，接下来我们在头部添加一个`script`标签：

```html
<script></script>
```

在脚本标签内，您需要添加一个事件来启动 JavaScript。否则，脚本将无法运行，没有`$(document).ready(function(){...});`函数：

```html
$(document).ready(function(){
//do something here
};
```

在这个函数内部，用一个监听器替换`//do something`，监听`:submit`按钮的点击事件，触发一个函数，以某种方式将 Hello World 显示在屏幕上：

```html
$(":submit").click(function() {
//write "Hello World"
});
```

到目前为止，我们已经创建了一个 JavaScript，它在页面加载时加载，并监听用户点击按钮的事件。当`click`事件发生时，一个函数执行，但现在该函数是空的。我们的下一个任务是创建一种方法，将“Hello World”文本添加到页面上。

在函数内部，我们希望将“Hello World”文本附加到`:submit`按钮的父元素上。由于`:submit`按钮是触发方法的对象，我们可以在 jQuery 中使用`$(this)`来引用它。要附加“Hello World”文本，使用 jQuery 的`.append()`方法：

```html
$(this).parent().append("Hello World");
```

jQuery 将“Hello World”文本附加到 HTML 的`body`标签的末尾。为了更好地控制文本的附加位置，将按钮包装在父`div`元素中。

在浏览器中打开 HTML 文件并测试按钮的功能。如果按下按钮没有使文本**Hello World**出现在按钮下方，那么就出了问题。回到教程中看看哪里出错了。

在继续之前，我们不能让文本保持原样。我们希望以后能够做更多事情。用一个包含`ID`属性`helloWorld`的段落标签标记它。

到目前为止，我们已经实现了我们的基本意图，点击按钮，写下 Hello World。这很好，但还不够好；因为我们总是要超额交付，不是吗？

在`.click()`事件函数之外，添加一个变量`foo`，表示字符串`Hello World`。接下来，用`foo`变量替换`.append(...)`函数内部的 Hello World 文本。从方法中删除文本并用变量替换它使得工作更容易，并且只是改进这个函数的一小步。刷新并测试你的页面，确保一切仍然正常。

在`body`标签内，我们现在将通过一个表单`input`元素将文本发送到脚本以个性化这个页面。在你的 HTML body 标签内，输入一个带有`id="bar"`和`placeholder="输入你的名字"`的文本`input`元素。

为了接收来自我们输入框的文本，我们需要在你的函数内添加一个新变量`bar`。将它设置为等于输入的值：

```html
var bar = $('input').val();
```

接下来，通过更改`.append()`方法来包括`foo`、`bar`和一些新文本，所有这些都包裹在一个可样式化的元素中：

```html
$(this).parent().append("<div class='newText'>" + bar + " says " + foo + "!</div>");
```

现在，当你刷新这个页面时，你会发现文本框已经添加了。尝试在输入框中输入你的名字并观察结果。

这很好，但不完整。现在是时候进行一些清理了。让我们通过一些我们想要避免的情景。我们不希望能够提交空输入或继续添加更多的**Hello World**行。

首先，处理空白输入框。让我们添加一个`if`条件来检查输入文本在附加到 HTML 之前是否为空。在获取输入值的行之后，添加一个新行，其中包含检查变量是否为空字符串的条件语句。这个条件包裹了`append`语句。还要为输入为空字符串时添加一个`else`语句。在其中，复制`.append()`方法，并提醒用户在文本输入中输入值的文本。

```html
var bar = $('input').val();
if (bar != ""){ 
$(this).parent().append("<div class='newText'>" + bar + " says " + foo + "!</div>");
} else { 
$(this).parent().append("Please enter a your name!") 
};
```

这将为您的表单添加一些验证，如果单击**提交**按钮时文本框为空，它将提醒用户输入姓名。还有两个清理项目，所以再等几分钟。

首先，我们希望附加的 HTML 每次重置。因此，在你的`if`条件语句之后，在`else`语句之前添加一行，删除之前添加的`.newText`元素。

```html
$(".newText").remove(); 
```

最后，在`if`条件结束之前，使用`.val()`方法重置输入表单的值为空。还要为文本输入添加一个`ID`属性，以将值连接到输入。

```html
$('input#fooBar').val("");
```

就是这样！我们有点过度了，但我们有一个相当不错的 Hello World 网络应用。

## 它是如何工作的...

不显眼的 JavaScript 通过在页面加载时加载脚本，并通过使用监听器等待页面上发生特定事件来运行。这可能需要调整你的写作方式，但能够将交互与呈现分开是有优势的。

# 创建一个发光的“提交”按钮，并添加事件监听器。

处理表单通常是大多数网页设计主题中被忽视的一个方面，尤其是响应式网页设计。通常非交易页面除了简单的**联系我们**页面外不使用表单，因此表单设计通常是事后想到的。然而，在交易电子商务和软件即服务行业中，表单是用户交互中最重要的元素。在这个世界中，响应式设计不仅仅是响应式布局和图片，还包括周到的交互。在这个示例中，我们可以想象一个用户处于表单流程的最后阶段，准备提交表单。

一个常见的情况是，一个人滑稽地点击 **submit** 按钮，然后看着页面似乎什么都没发生（但实际上是在执行表单的 `post` 操作），然后再次点击同一个按钮，一遍又一遍。在简单的 **联系我们** 场景中，这可能会生成一些额外的表单提交电子邮件，但在交易情况下，这可能会激活一长串的业务逻辑，并对其他流程造成干扰。

对于用户来说，有可能会有这样的想法，即在点击 **submit** 按钮后立即没有发生任何事情，说明出了问题，网站出现了故障；最终结果是放弃交易并损害了您网站的信任。您可以和应该做很多事情。其中之一是添加视觉提示，让用户知道他们已成功点击按钮，即将发生某些事情。考虑在幕后执行的交易以及所需的时间。如果您预计会有很长的等待时间，请注意您的用户可能不知道这一点。人们通常期望在互联网世界中得到即时满足，一切都是即时的，任何不是即时的东西都是有问题的。

## 准备工作

在 *以不显眼的方式编写 "Hello World"* 配方中，我们编写了一个简单的提交按钮函数。我们可以将其作为此配方的基本构建块。如果您没有这段代码，您可以在 Packt Publishing 的网站上找到它的最终版本（[`www.packtpub.com/`](http://www.packtpub.com/)）。

## 如何做到这一点...

首先，我们需要将提交函数的主要部分分离出来，放到一个由 `.click()` 事件函数调用的单独函数中。将函数内部的所有内容剪切出来，粘贴到 `$(document).ready(function() {...});` 函数之外。用新函数的函数调用替换您剪切出的所有内容。在函数调用中，使用 `.attr()` 方法将声明的变量 `foo` 与 `$(this)` 的 `ID` 值包含在一起。然后，将您粘贴的代码包裹在同名的新函数中，并将其分配为接收这两个变量。最后，向您的提交输入添加一个 `ID` 属性。您的代码应该类似于以下内容：

```html
$(document).ready(function(){ 
     var foo = "hello world "; 
     $(":submit").click(function(){ 
          formAction(foo,$(this).attr("id")); 
     }); 
}); 

function formAction(foo,id){ 
     var bar = $('input').val();
     if (bar != ""){ 
          $(".newText").remove(); 
          $("#" + id).parent().append("<div class='newText'>" + bar + " says " + foo + "!</div>"); 
          $('input#fooBar').val(""); 
      } else { 
          $(".newText").remove(); 
          $("#" + id).parent().append("<div class='newText'>Please enter a your name!</div>"); 
     };
};
```

首先，从 `formAction()` 函数中移除 `bar` 变量，并将其粘贴到 `.click()` 事件监听器函数中。这样可以在每次点击事件中构建变量。现在开始构建新函数；在 JavaScript 中添加一个名为 `buttonAnimate()` 的新函数，并在 `.click()` 事件监听器中的 `formAction()` 调用之后调用它。在 `buttonAnimate()` 函数调用中，发送 `bar` 变量。最后，将 `bar` 变量添加到 `formAction()` 函数调用和函数声明变量中。关键的发展是我们已经将输入值作为变量添加到了 `.click()` 事件监听器函数中，并将其发送到了两个函数调用中。

有了这个，我们现在可以开始编写一个新函数，用于在按钮上实现动画效果。休息一下，喝杯咖啡。我们将暂时转换方向，编写一些 CSS。

将样式表添加到您的项目中；在样式表中，添加两个类，`.valid` 和 `.invalid`，它们将分别对按钮的两种不同响应状态 `valid` 和 `invalid` 进行操作。`pass` 场景发生在提交表单时输入文本，`fail` 场景发生在在 `form` 元素中未输入文本的情况下按下 **submit** 按钮。

```html
.valid{...}
.invalid{...}
```

在 `valid` 状态下，我们已经在输入框中提交了表单。我们希望为代表正面状态的按钮添加 CSS；按钮已被激活，表示发生了某些正确的事情。我添加了边框、阴影、文本阴影、背景颜色、文本颜色和边框半径。这将足以表明发生了预期的事情。

```html
.valid{ 
     border:2px solid #000; 
     -webkit-box-shadow: 1px 1px 5px 3px #0000ff; 
     box-shadow: 1px 1px 5px 3px #0000ff; 
     text-shadow: 1px 1px 1px #666666; 
     filter: dropshadow(color=#666666, offx=1, offy=1); 
     background-color:rgb(150, 150, 255); 
     color:#ffffff; 
     -webkit-border-radius: 5px; 
     border-radius: 5px; 
}
```

我们将相同的 CSS 样式类型添加到`invalid`状态，用户在输入框中没有输入文本提交表单时。在这种情况下，我们希望给出视觉线索表明出了问题，并提示用户重新尝试。在这种情况下，橙色和红色是用来表示错误的好颜色。此外，我们还添加了一个带有过渡效果的 CSS 模糊效果。

```html
.invalid{ 
     border:2px solid #ffff00; 
     -webkit-box-shadow: 1px 1px 5px 3px rgb(255, 0, 0); 
     box-shadow: 1px 1px 5px 3px rgb(255, 0, 0); 
     background-color:rgb(255, 133, 0); 
     color:#ffffff; -webkit-border-radius: 
     5px; border-radius: 5px; 
     -webkit-filter: grayscale(0.1) blur(1px); 
     -webkit-transition: border 0.2s ease; 
     -moz-transition: border 0.2s ease; 
     -ms-transition: border 0.2s ease; 
     -o-transition: border 0.2s ease; 
     transition: border 0.2s ease; 
     text-shadow: 1px 1px 1px #666666; 
     filter: dropshadow(color=#666666, offx=1, offy=1); 
}
```

这就是我们为这个食谱要编写的所有 CSS。接下来，我们将编写 JavaScript 来将两种不同的样式连接到实际状态。在这个食谱的早些时候，我们创建了一个名为`buttonAnimate()`的空函数，它接收了变量`bar`，现在是时候构建它了。在其中，添加相同的`if`条件语句来检查`bar`是否为空字符串。如果是，将`valid`类添加到`submit`按钮，如果不是，则添加`invalid`类。添加`invalid`类会提醒用户出现了问题，需要采取行动。

```html
if(bar!= ""){ 
     $(":submit").addClass("valid"); 
} else { 
     $(":submit").addClass("invalid"); 
};
```

当采取适当的行动时，也就是当用户点击表单元素输入文本时，按钮应该被重置为其原始状态；从技术上讲，新添加的类应该被移除。代码如下：

```html
$('input#fooBar').focus(function(){ 
     $(":submit").removeClass('invalid') 
}); 
```

最后一点清理工作是从`if`和`else`条件的开头删除一个或两个类。在`submit`元素上使用`.removeClass()`方法两次来删除与要添加的类相反的类。

```html
function buttonAnimate(bar){ 
     if(bar!= ""){ 
          $(":submit").removeClass("invalid"); 
          $(":submit").addClass("valid"); 
     } else { 
          $(":submit").removeClass("valid"); 
          $(":submit").addClass("invalid"); 
          $('input#fooBar').focus(function(){ 
                $(":submit").removeClass('invalid') 
          }); 
     }; 
};
```

现在重新加载并测试页面，看看您创建的魔法。它将看起来像下面的截图：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_07_01.jpg)

## 它是如何工作的...

jQuery 是一个很棒的库，它可以帮助您快速创建出色的 Web 应用程序，而且代码很少。在旧的纯 JavaScript 世界中，这个功能会花费您更多的代码和时间。它有库函数来读取表单的值，轻松附加 HTML，并在 CSS 类之间切换。您只需要实现一些 jQuery 方法和 CSS，剩下的就交给它了。

# 当你悬停在按钮上时让它突出显示

有时，响应式设计中的一个大挑战是在要求只是构建足够好的东西时，能够真正超出交付一个项目。按钮是一个机会，您可以为令用户惊叹的产品提供额外的抛光。如果我们不是在超出交付，我们可以只是添加一个`:hover`选择器就完成了。然而，在这个食谱中，我们将制作一个在悬停时闪闪发光的按钮。

## 准备工作

了解过度交付的缺陷。超出要求是我们都应该努力追求的，但要注意不要设定无法满足的不合理期望，从而导致本来成功的项目失败。

在之前的食谱中，我们创建了一个带有按钮的表单，当您点击它时会有动画效果。对于这个食谱，您可以继续使用那段代码。您也可以去下载那个食谱的代码，或者下载这个食谱的代码。

或者您可以只是创建一个表单和按钮元素。这并不难。

## 如何做...

我们基本上是从一个页面开始，有两个表单元素；一个输入框和一个提交按钮。正如我之前提到的，这些是在之前的食谱中构建的；您也可以在这里构建它们。我们在食谱中构建的 JavaScript 将与新的交互一起工作，但不是必需的。`input`元素具有`id`属性`fooBar`，按钮具有`id`属性`submit`。

```html
<input id="fooBar" type="text" placeholder="Enter your name">
<input id="submit" type="submit" value="Say Hello">
```

让我们从使按钮的默认外观更有趣开始。在您的 CSS 中为`input#submit`元素添加样式。在样式中，添加蓝色背景颜色，白色字体颜色，8 点边框半径，14 像素字体大小和 5 像素和 8 像素的填充。可以使用以下代码完成：

```html
input#submit{ 
     background-color:blue; 
     color:white; 
     border-radius:8px; 
     font-size:14px; 
     padding:5px 8px; 
}
```

现在按钮的默认外观已经定义，让我们谈谈交互设计。在这里，我们进入使用 JavaScript 进行`.mouseover()`事件的实际优势，而不是使用 CSS 的`:hover`选择器。我想与`form`元素交互，并查询是否已输入文本。如果输入了文本，我们希望有一个特殊的视觉提示，表明表单已准备好提交；如果没有提交文本，强烈的视觉提示应告诉用户停下来，返回检查他们的表单。

首先，如果表单已准备好提交，按钮将似乎向鼠标指针延伸并变成绿色。CSS 将包括一个绿色的背景颜色，带有`!important`覆盖，一个盒子阴影和一个文本阴影。请参阅以下代码片段，了解确切的 CSS 语法：

```html
.buttonLight{
     background-color:green !important;
     -webkit-box-shadow: 1px 1px 2px 1px green;
     box-shadow: 1px 1px 2px 1px green;
     text-shadow: 1px 1px 2px #666666;
     filter: dropshadow(color=#666666, offx=1, offy=1);
            }
```

或者，如果表单输入为空，按钮将变成红色，并远离鼠标指针。这个 CSS 将有一个红色的背景颜色，带有`!important`覆盖，和一个内阴影，以及一个使文本模糊的文本阴影。

```html
.redButtonLight{
     background-color:red !important;
     -webkit-box-shadow:inset 1px 1px 3px 2px #663535;
     box-shadow:inset 1px 1px 3px 2px #663535;
     text-shadow: 0px 0px 2px #fff;
     filter: dropshadow(color=#fff, offx=0, offy=0);
}
```

这就是我们正在创建的 CSS 的范围。现在是时候构建交互性了。在您的头部，如果还没有这样做，请创建开头和结尾的`<script>`标签。首先，我们创建`(document).ready`监听器：

```html
     $(document).ready(function(){
          //do some things here
     });
```

这并没有做太多事情，但这是一个开始。让我们继续构建交互性。在`(document).ready`监听器函数内部，添加一个`.mouseover()`事件监听器和一个`.mouseout()`事件监听器。`.mouseover()`监听器替换了`hover`函数，并且将同时动画按钮并添加我们之前构建的 CSS 类之一，而`.mouseout()`监听器完成了`hover`函数，并最终移除了`.mouseover()`函数添加的`class`属性。

```html
$(document).ready(function(){
     $("#submit").mouseover(function(){
          //do something
     });
     $("#submit").mouseout(function(){
          //do something else
     });
});
```

继续前进，让我们首先构建`.mouseover()`事件监听器函数。在其核心，它执行两个功能；首先，它查询表单`input`元素的值，然后根据表单`input`元素的值更改`submit`按钮。第一部分，查询输入的值，将如下所示：

```html
if($('input').val()!="")
     //do something
} else {
     //do something else
}
```

当表单的值不是空字符串时，第一个条件应该创建新的变量，`classtoAdd = "buttonLight"`和`paddingAdd = "5px 8px 5px 9px"`。另一个条件，当表单的值是空字符串时，创建相同的变量，`classtoAdd = "redButtonLight"`和`paddingAdd = "5px 9px 5px 7px"`。这些将应用于函数的下一部分中的`submit`按钮。

函数的下一部分是通过`.animate()`方法开始动画按钮的不透明度和填充，并添加由`classtoAdd`变量确定的类。动画应该相当快，比如 100 毫秒。

```html
$("#submit").animate({opacity: 0.7, padding: paddingAdd},
100, function(){ 
     $("#submit").addClass(classtoAdd); 
});
```

这就是`.mouseover()`事件所需的全部内容。接下来需要的是`.mouseout()`函数的内部工作。同样，动画`submit`按钮的`position`和`padding`属性，但时间更长，然后移除`class`属性。

```html
$("#submit").mouseout(function(){ 
     $("#submit").animate({opacity: 1, padding :"5px 8px"}, 
     300, function(){ 
          $("#submit").removeClass(classtoAdd); 
     }); 
});
```

就是这样。启动页面，观察按钮的交互。以下截图说明了同样的内容：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_07_02.jpg)

## 工作原理...

这个配方使用事件监听器来替换简单的 CSS `:hover`选择器，后者只能使用有限的逻辑，而使用`.mouseover()`事件监听器可以针对表单`input`元素进行查询，以查看表单数据是否为空。根据页面的表单状态，脚本可以为按钮分配不同的 CSS 类。这为应用程序的客户端端增加了另一个逻辑层，并为您的应用程序增加了更丰富的交互性。

# 使用不显眼的 jQuery 调整元素大小

这个配方的目的是在您的项目中构建一个智能图像元素处理程序。这将是一个简单的元素，可以响应您的屏幕大小。我们可以用一个不显眼的 jQuery 脚本来完成所有这些。

在以前的配方中，我们使用 PHP 对服务器端脚本调整了图像的大小。这个配方将实现类似的结果，但是它将是客户端而不是服务器端，并且将用于移动优先响应式设计。

这个配方是移动优先响应式设计的一个好工具。例如，如果你想要一个缩小的图像来显示文档的加载，如果屏幕很大，脚本将用更大的图像版本替换图像。这种不显眼的特点意味着脚本可以通过向图像添加`class`属性来轻松调用。

## 准备工作

这个配方是从头开始的，所以你不需要下载任何东西就可以开始。但是，你需要连接到 jQuery 库才能使其工作。在你的头部，包括 jQuery 库在线的路径：

```html
<script src="img/div>

## How to do it...

Once you have your header set up with the path to the jQuery libraries, add a script element to the HTML header. Inside the `<script>` tags, we will shortly add some event listeners and a function that will resize an element.

In your HTML body, add a div element to wrap the child elements in the page. Give that the class `wrap`. Inside the `.wrap` div element, add two child div elements.

Inside one of those div elements, we will insert an image. We want to have two versions ready and available for the page to display, so open your image editing software (if you do not have one, go to [www.gimp.com](http://www.gimp.com) and download it) and create two versions, a large one and a small one, of the image you want displayed.

Name the two images `imagename-small` and `imagename-large`. The images I created for the recipe are `robot-small.png` and `robot-large.png`. Add the small image with an image element, and add to the image element the class, `scalable`.

```

<img src="img/robot-small.png" class="scalable" />

```html

Now that we have the basic HTML, let us do some slight CSS layout and styling. Add the `<style>` tag to your header. Inside, add a style for the `div.wrap` element to be `75%` wide. Float its first child element to the left and assign `50%` width. Do the opposite for the second child element. You can add different colored backgrounds to each just to see the division between the two elements. Finally, for `img`, add a responsive `100%` width and `auto` height. The CSS is displayed as follows:

```

div.wrap{width:75%;}

div.wrap div:first-child{float:left;width:50%;background-color:#ccc;}

div.wrap div:nth-child(2){float:right;width:50%;background-color:#666;}

div.wrap div img{width:100%;height:auto;}

```html

Now that the page layout is ready, it is time to build the JavaScript. The most important function, the utility function, to replace the image should be created next. It will be called from within a separate function with parameters of whether to replace it with the large or small version.

```

function replaceImage(size){...}

```html

Inside the function, first we need to see if the parameter sent is large or small. Create a simple `if` conditional statement with an `else` condition to check this.

```

if (size == 'small') {…} else {…};

```html

If the parameter is `small`, then the function works to replace the image in HTML with the small version. First, for the sake of preventing the function from replacing the small version with the small version unnecessarily, add another `if` condition to check if the `img` element with the class `scalable` has the string `large` in the `src` attribute using the `.indexOf()` method. If the `.indexOf()` method finds the string present, it will return the index number of where it is found in the `img.scalable` object. The specific `if` condition will ask if the index is greater than `1`; if it is greater than 1, the `if` condition would be true.

```

if($("img.scalable").attr("src").indexOf('large')>1){…}

```html

Inside the conditional statement, create a new variable, `newImageReplace`, this will create a string to set the `src` attribute to in the next line. Set the variable's value to get the `img.scalable` object's `src` attribute and replace the string section `-large.` with `-small.` (I included the trailing period just in case your original image name included `-large.`).

```

var newImageReplace = $("img.scalable").attr("src").replace("-large.", "-small.");

```html

The next line uses the `.attr()` method to update the value of the `img.scalable` object's `src` attribute to the value of the variable created earlier, `"robot-small.png"`.

```

$("img.scalable").attr({src:newImageReplace});

```html

That is it for the `if` conditional, and there is no method to act on as there is no `else` condition. Next, for the parent element's `else` condition, if the `size` parameter is not `small`, the function will do exactly the opposite as before. Use the `.indexOf()` method to check if the `small` image is present, and if so, change the `src` attribute to point to the `large` image.

```

} else {

if($("img.scalable").attr("src").indexOf('small')>1){

var newImageReplace =    $("img.scalable").attr("src").replace("-small.", "-large.");

$("img.scalable").attr({src:newImageReplace});

};

};

```html

This completes the most important action function. Now let us backtrack to create the function that calls it with the parameter. This function will have to get some intelligence about the screen width, therefore, call it `measureWindow()`. Inside, first gather the intelligence by measuring the window width into a variable called `getWindowWidth`. If the window width is small, say smaller than `600` px, and you want it to call up the small image, it should thus call the `replaceImage()` function with a parameter, `small`. If larger than `600` px, call the function with the parameter `large`.

```

function measureWindow(){

var getWindowWidth = $(window).width();

if (getWindowWidth < 600){

replaceImage("small");

} else {

replaceImage("large");

};

};

```html

That function which measures the screen width, and then calls the resize function, itself needs to be called. It does not just fire itself. And we would not want it to be constantly measuring the screen width. We only want it to occur in two scenarios. First, on page load, when we want to check if the screen is large, and quickly replace the low-resolution image with a higher one. For this instance, the call is as follows:

```

$(document).ready(function(){

measureWindow();

});

```html

The second scenario is when the screen width is changed by the user. We will use the `.resize()` listener to fire a function when the window is resized.

```

$(window).resize(function(){

measureWindow();

});

```html

Now we are really finished, and that was short enough. Launch the file and open your inspector or debugger to watch the image `src` change when you resize your screen below `600` px. You could build on this to deliver a few different sizes if you wanted.

## How it works...

This recipe gives a usable example of client-side responsive image delivery using unobtrusive JavaScript. It measures the screen width whenever there is some change, and updates the image source appropriately.

```

# 用不显眼的 JavaScript 屏蔽密码

处理密码屏蔽的最常见方法是在创建输入元素时使用密码类型。这是在桌面上使用时的最佳实践。然而，在移动设备上输入密码时，设备的触摸输入很容易出现输入错误。这些输入错误通常不会被捕捉到，因为你看不到加密的文本。这是 iOS 设计者真正做对的地方。他们创建了一个输入，其中输入文本在变成`*`之前短暂可见，或者在输入下一个字符时发生变化。

在这个配方中，我们将为您的密码输入创建一个模仿这个解决方案的密码输入。

你也可以使用这个表单元素来屏蔽其他表单条目。但是请确保你理解，底层的隐藏表单包含要传输的条目。除非你指定，否则它不是加密的。这只是防止密码在视觉上被看到。

## 准备工作

你不需要在本地获取任何文件就可以开始。只需要在头部包括 jQuery 库的链接。这将允许你连接到 jQuery 库并使用它们来扩展你的代码的功能。

```html
<script src="img/jquery-1.8.2.min.js"></script>
```

## 如何做...

第一项任务是在你的 HTML 主体中创建两个`input`元素。第一个具有密码的`type`和`ID`属性。这将是在表单中提交的加密版本，但最终将被隐藏起来。第二个将具有 ID`altDisplay`并被禁用，所以用户不能在其中点击。这个将显示在另一个上面，看起来像用户正在输入的那个。最后，我们将添加一个样式来隐藏密码字段。

这就是配方的 HTML 主体所需的一切，当然你可以根据需要添加其他表单元素。

在头部，添加一个 JavaScript `<script>`元素，在里面添加 jQuery `$(document).ready`函数。在里面，为`#password`输入添加一个`.keyup()`事件的监听器。这发生在按下键之后，当松开键时，事件触发。

但在我们进入这个教程的实质内容之前，有一个小障碍需要解决。首先，并非所有按下的键都是字母；还有*Shift*、*Tab*和功能键，还有*Delete*键。每个键都有一个数字标识符，您可以通过在控制台中记录`e.which`来找到它。您将需要这些数字键标识符来编写一个条件来过滤掉非字符`keyup`事件。

首先，我们应该制作一系列的`if`条件，以确保我们没有得到一个不是实际字符的按键。在其中，创建一个额外的`if`语句来检查*删除*（8）键是否未被输入。如果没有，我们可以继续处理常规字符`keyup`事件的功能，否则我们将需要添加功能来处理`delete keyup`事件（稍后会介绍）。

```html
$(document).ready(function(){
     $("#password").keyup(function(e){
          if (e.which!=16 && e.which!=27 && e.which!=91 &&e.which!=18 && e.which!=17 && e.which!=20 ){
               if (e.which!=8){
                    //do something for the character key
               }else{
                    //Do something for the delete key
               }}; 
          });
     });
```

在字符`keyup`的条件下，我们将获取两个输入字段的当前值，分别存入变量`altDisplayVal`和`passwordVal`中。获取`#altDisplay`输入中的值，并使用正则表达式将其所有值更改为`*`，并存储在`regAltDisplayVal`变量中。获取`#password`中的值，并取出最后一个字母放入一个新变量中，使用`.charAt()`方法。然后将这两个新变量相加，成为`#altDisplay`输入的新值。

```html
var altDisplayVal = $("#altDisplay").val();
var passwordVal = $("#password").val();
var regAltDisplayVal = altDisplayVal.replace(/./g,"*");
var passwordValLastLetter = passwordVal.charAt( passwordVal.length-1 );
$("#altDisplay").val(regAltDisplayVal + passwordValLastLetter);
```

这处理了`keyup`上的字符键，接下来让我们为删除键编写功能。删除键不同之处在于它会删除字符字符串中的最后一个字符。要处理删除键的 keyup 事件，请使用`.charAt()`方法获取`#password`输入中的最后一个字符，并将其保存在`delLast`变量中。

然后使用`.slice()`方法首先获取`delTxt`变量的倒数第二个字符。使用正则表达式将字符更改为`*`并将它们存储在`regDelTxt`变量中。最后，将`regDelTxt`和`delLast`变量添加到`#altDisplay`输入元素的新值中。

```html
var delLast = this.value.charAt(this.value.length-1);
var delTxt = this.value.slice(0,this.value.length-1);
var regDelTxt = delTxt.replace(/./g,"*");
$("#altDisplay").val(regDelTxt + delLast);
```

至此，JavaScript 部分已经完成。您现在可以启动页面，看到页面上的两个输入元素。在第一个输入元素中输入文本，然后它将作为`*`输入到第二个输入元素中。现在唯一的问题是，在页面上有两个并排的表单元素并不会使其成为 iOS 风格的密码元素。要使其真正起作用，我们需要将`#password`输入覆盖在`#altDisplay`上并使其不可见。您可以通过一些 CSS 来实现这一点，如下所示：

```html
div input:first-child{ 
     position: relative; 
     left: 131px; 
     background: transparent; 
     color: transparent; 
}
```

在这里，试试看。刷新屏幕后，您将只看到一个输入元素。当您在其中输入文本时，它会变成星号。

## 它是如何工作的...

这实际上并不改变提交的输入；它只是隐藏它，并将隐藏字段中的值转换为星号字符。这应该是 iOS 密码输入的一个很好的模仿。

# 使用事件侦听器来为图像阴影添加动画

由于这是最后一个教程，它应该是一个有趣的教程。这个教程会使用 jQuery 事件监听器和 CSS3 来使阴影随着鼠标移动而动。

这是一个简单的教程，但它仍然以响应的方式工作。图像将响应页面宽度，而 jQuery 是这样编写的，以至于它仍然在每次鼠标移动时测量图像位置和鼠标位置。

## 准备工作

这个教程需要您使用 jQuery。因此，在新文件的头部，添加一个指向 jQuery 库的链接。除此之外，您已经准备好了。

```html
<script src="img/jquery-1.8.2.min.js"></script>
```

## 如何做...

首先，使用一个带有类`wrap`的 div 元素创建 HTML 文件的主体。在其中，添加一个带有类`topRight`的图像。接下来是 CSS。

```html
<div class="wrap">
     <img class="topRight" src="img/robot-small.png"/>
</div>
```

添加 CSS 部分。首先，为 body 添加`text-align: center`样式。接下来，给`.wrap` div 元素一个宽度为`30%`，并自动水平宽度。代码片段如下所示：

```html
body{text-align:center;} 
.wrap{
     width:30%;
     margin:0 auto;
} 
.wrap img{ 
     width:100%; 
     height:auto; 
     margin:80px 1%; 
     border-radius:50%; 
     -webkit-border-radius:50%; 
     border:1px dotted #666; 
}
```

接下来的一组 CSS 是根据鼠标位置由 jQuery 脚本分配的图像类变化。每个都包含一个不同角度的`box-shadow`。命名不同的类`topLeft`，`topRight`，`bottomLeft`和`bottomRight`。每个都将具有`5`像素的阴影偏移，`2`像素的扩展和`2`像素的模糊半径。

```html
img.topLeft{
     border-top: 5px solid #666;
     border-right:5px solid #999;
     border-bottom: 5px solid #999;
     border-left:5px solid #666;
     -webkit-box-shadow: -5px -5px 2px 2px #666;
     box-shadow: -5px -5px 2px 2px #666;
}
img.topRight{
     border-top: 5px solid #666;
     border-right:5px solid #666;
     border-bottom: 5px solid #999;
     border-left:5px solid #999;
     -webkit-box-shadow: 5px -5px 2px 2px #666;
     box-shadow: 5px -5px 2px 2px #666;
}
img.bottomLeft{
     border-top: 5px solid #999;
     border-right:5px solid #999;
     border-bottom: 5px solid #666;
     border-left:5px solid #666;
     -webkit-box-shadow: -5px 5px 2px 2px #666;
     box-shadow: -5px 5px 2px 2px #666;
}
img.bottomRight{
     border-top: 5px solid #999;
     border-right:5px solid #666;
     border-bottom: 5px solid #666;
     border-left:5px solid #999;|
     -webkit-box-shadow: 5px 5px 2px 2px #666;
     box-shadow: 5px 5px 2px 2px #666;
}
```

到目前为止，工作得非常出色。现在是构建 JavaScript 的时候了。在您的`script`标签内部，创建标准的`$(document).ready`事件函数。然后，开始添加一个`.mousemove()`事件监听器函数到 body。在其中，为`.wrap img` div 元素的水平和垂直位置创建两个新变量`imgHorz`和`imgVert`。

```html
$("body").mousemove(function(e){
     var imgHorz = ($(".wrap img").offset().left);
     var imgVert = ($(".wrap img").offset().top);
});
```

接下来，在创建了变量之后，我们根据变量值与事件发生时鼠标位置的比较创建一些条件。如果结果为真，则在添加图像类之前删除所有 CSS 类。

```html
if(e.pageX < imgHorz && e.pageY < imgVert){ 
     $(".wrap img").removeClass();
     $(".wrap img").addClass("bottomRight");
};
```

然后，您将希望添加三个额外的`else`/`if`条件来添加其他类。以下代码片段显示了显示的四个条件：

```html
if(e.pageX < imgHorz && e.pageY < imgVert){
     $(".wrap img").removeClass(); 
     $(".wrap img").addClass("bottomRight");
} else if (e.pageX > imgHorz && e.pageY < imgVert) {
     $(".wrap img").removeClass(); 
     $(".wrap img").addClass("bottomLeft"); 
} else if(e.pageX > imgHorz && e.pageY > imgVert) { 
     $(".wrap img").removeClass(); 
     $(".wrap img").addClass("topLeft"); 
} else if(e.pageX < imgHorz && e.pageY > imgVert) { 
     $(".wrap img").removeClass(); 
     $(".wrap img").addClass("topRight"); 
};
```

然后，我们结束了 JavaScript。

最后一件事，我们还需要对 CSS 样式之间的过渡进行动画处理。因此，不要添加更多的 JavaScript，而是将 CSS 过渡添加到`.wrap img`元素（每个浏览器都需要自己的过渡命令）。

```html
-webkit-transition: all .5s linear; 
-o-transition: all .5s linear; 
-moz-transition: all .5s linear; 
-ms-transition: all .5s linear; 
-kthtml-transition: all .5s linear; 
transition: all .5s linear;
```

这是一个相当简单的配方，最终结果是一个有趣的图像元素，其中阴影跟随鼠标移动。以下截图是这个配方的示例：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_07_6_event_listener_animate_image_shadow.jpg)

## 它是如何工作的...

这个配方在每个`.mousemove()`事件上测量图像和鼠标的位置。每次事件的结果是将新的阴影应用于对象。现在重要的是要考虑哪些事件适合移动设备，哪些适合桌面设备。`.mousemove()`事件不起作用，因为移动设备上没有鼠标。从这里开始，我会参考第五章，“制作移动优先的 Web 应用程序”，以便在移动设备上加载 jQuery Mobile 等 JavaScript 的复习。

我们使用不显眼的 JavaScript 构建了简单的 UI 交互。我希望这些简单的脚本不仅是您可以在项目中实际使用的有用示例，而且还有效地演示了如何编写可以存在于模板文件之外的 JavaScript。当您将其与可以调用到移动设备的脚本的移动版本配对时，这将符合您的响应式设计。未来，这将帮助您创建更具响应性和流畅过渡的网络项目。

愿你们长寿而繁荣。
