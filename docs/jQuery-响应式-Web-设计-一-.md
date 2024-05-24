# jQuery 响应式 Web 设计（一）

> 原文：[`zh.annas-archive.org/md5/2079BD5EE1D24C66E7A412EFF9093F43`](https://zh.annas-archive.org/md5/2079BD5EE1D24C66E7A412EFF9093F43)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

网络不再仅限于桌面或笔记本设备。 网络技术现在已经传播到从大桌面监视器到平板电脑，智能手机，智能电视和户外显示器等各种设备。 它还增加了网站的功能和界面以及我们与其交互的方式。

制作*响应式*网站不再是可选项。 因此，现在是磨练我们使用网格系统框架来提供不同和丰富用户体验的发展技能的时候。

在本书中，我们使用 CSS3 和 jQuery 实现了这一切，它们提供了在不同设备、操作系统和不同浏览器版本之间进行良好集成的选择。 使用 jQuery 的另一个优势是通过使用协作社区维护的插件来加快开发速度。 我们不需要重新发明已经存在的东西！ 此外，改进总是受欢迎的，您对社区的贡献将有助于每个人。

# 本书内容

第一章，*探索响应式网页设计*，首先解释了通过为网站生成线框图来创建响应性的概念，并将其适应不同的屏幕。 本章还解释了移动优先的概念。

第二章，*设计响应式布局/网格*，帮助你创建灵活的网站结构，然后专注于解释响应式网格系统的使用以及其如何改进开发中的灵活性。

第三章，*构建响应式导航菜单*，对每种导航菜单模式进行了多方面分析和逐步实施；这有助于选择每种情况的正确选项。

第四章，*设计响应式文本*，解释了将文本转换为相对单位，然后定制成美丽且响应式的标题。

第五章，*准备图像和视频*，解释了处理不同格式的高分辨率图像。 然后继续解释在智能手机上查看图像时定向重要性的艺术。

第六章，*构建响应式图像滑块*，解释了四种不同的图像滑块插件及其实现，并展示了有用的触摸库以补充交互。

第七章，*设计响应式表格*，探讨了管理创建响应式表格的不同方法，解决不同屏幕尺寸调整宽度时面临的困难。

第八章，*实现响应式表单*，讨论了改善用户体验的表单元素特点以及在移动设备上填写表单的好的、响应式表单框架。

第九章，*测试响应性*，讨论了在各种浏览器和设备平台上进行响应性测试的方法，以预防意外行为。

第十章，*确保浏览器支持*，解释了备用方案以及为什么备用方案被认为是重要的。然后继续解释如何检测每个浏览器特性，以及为这些错误提供正确支持。

第十一章，*有用的响应插件*，展示了用于网站结构、菜单导航等不同插件，补充了其他章节中已经介绍过的解决方案。

第十二章，*优化网站性能*，解释了使用在线工具分析网站性能的主要方法，并推荐了改进结果的提示。

# 本书中需要的材料

通过阅读本书获得的所有知识，如果你已经有了想要转换成响应式网站的网站的想法，那么在章节练习中可以完成。

你需要的软件清单包括 Apache HTTP 服务器、Adobe Photoshop CS5 或更早版本、诸如 Sublime Text 2 之类的代码编辑器，以及 Firefox 和 Chrome 等互联网浏览器。另外，为了测试例子和练习，最好是有智能手机或平板电脑等移动设备。

# 本书适合对象

*使用 jQuery 和 CSS3 实现响应式 Web 设计*旨在吸引对构建设备无关网站感兴趣的网页设计师。对 jQuery、CSS3 和 HTML5 的一些了解将是有益的。

# 约定

在本书中，你会发现一些区分不同类型信息的文本样式。以下是一些样式的示例，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入以及 Twitter 用户名如下所示："HTML5 规范包括新的结构元素，如`header`、`nav`、`article`和`footer`。"

代码块设置如下：

```js
.orientation_landscape .div-example {
  border: 2px solid red;
}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目都使用**加粗**：

```js
<svg width="96" height="96">
  <image xlink:href="svg.svg" src="img/svg.png" width="96" height="96" />
</svg>
```

**新术语**和**重要词语**都使用加粗显示。你在屏幕上看到的词语，比如菜单或对话框中的，会在文本中这样显示："点击**下一步**按钮会将您带到下一个屏幕"。

### 注意

警告或重要提示会以这样的形式出现。

### 小贴士

小贴士和技巧会以这样的形式出现。


# 第一章：探索响应式网页设计

近来，在网站开发环境中，我们经常听到“响应式”这个词，不是吗？别担心，我们将一起看到它的真正含义及其对我们的网站开发的影响。

当开始开发过程时，影响决策的一个因素（有时被忽视）是我们需要用不同的设备和屏幕尺寸来预览网站布局的响应性。一些时间以前，我们习惯于使用一些网站尺寸的定义，例如 1024 像素。这是因为我们认为唯一访问内容的方式是在台式机上。但是，正如你所知，技术给我们带来了越来越多的设备（可以显示网站），改善了我们与网站互动的方式，比如大型台式机显示器、平板电脑、智能手机、智能电视、户外显示屏等等。

移动技术的这些进步和网站导航和查看技术的快速演变，推动大家重新审视网站的有限尺寸的概念，开始考虑一个可以自适应自身并为每种情况提供合适内容的结构。

在本章中，我们将学习：

+   理解响应式网页设计的概念

+   比较响应式、流动和自适应网站

+   使用媒体查询适应屏幕

+   移动优先概念和技巧

+   使用线框工具

+   在线框架中实践移动优先开发

# 理解响应式网页设计的概念

我不能在没有引用**伊桑·马科特**的情况下开始这个主题，他在 2011 年出版了《响应式网页设计》一书，这本书已成为前端社区许多其他书籍和文章的参考。

在我对马科特的书的理解中，响应式网页设计的含义是根据可用的屏幕区域为用户提供查看同一网站的不同体验。从技术上讲，它涉及以下三种主要技术的使用：

+   灵活的基于网格的布局

+   弹性图片和视频

+   聪明地使用 CSS 分割网站行为（媒体查询）

关于每种技术的更多细节将在稍后展示，但只是为了直观地澄清这个概念，让我们看看下面的例子，它在小设备（智能手机）上显示网站的左侧，中等设备（平板电脑）在中间，并在大屏幕（台式机）上显示网站的右侧：

![理解响应式网页设计的概念](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_01_01.jpg)

### 注意

还有许多挑战，不仅仅是创建流动的尺寸和应用一些媒体查询。

我们将在整本书中讨论许多次要和主要的挑战。其中一些是：

+   用触摸事件替换鼠标悬停事件

+   方便在表单字段中填充数据

+   优先考虑内容

+   网站加载优化

# 比较响应式、流动和自适应网站

响应式网页设计与流式设计有些不同。流式设计是自动调整网站的结构和尺寸（通过使用相对单位来设置宽度，如 em 或百分比），但并不为用户提供看到内容布局的多样化方法。

此外，可以说响应式网页设计并不是对所有移动设备挑战的唯一解决方案。正如我们之前所看到的，响应式网页设计只是一个想法，当实现正确时可以让用户获得更好的体验，但它可能并不适用于每个人或每种设备。这就是为什么我们应该提高对新技术的了解。

我非常喜欢的一句话是由*Aaron Gustafson*写的，《自适应网页设计》一书的作者：

> *"自适应网页设计是指创建适应用户能力（在形式和功能上）的界面。"*

### 注意

自适应网页设计只为新设备实现新的 HTML5 功能，以提供增强的体验。它在旧设备上缺少这些功能，确保基本设置仍然适用于它们。

有许多方法可以实现自适应特性。以下是实现它们的最常见做法：

+   使用 jQuery 插件在移动设备上启用触摸事件交互（更多内容请参见第六章,"构建响应式图像轮播")

+   将常见表格结构转换为响应式表格（更多内容请参见第七章,"设计响应式表格")

+   仅为桌面定制表单元素的视觉（更多内容请参见第八章,"实现响应式表单")

+   使用地理位置功能为用户提供更相关的内容

+   更改信息结构，设置正确的内容优先级

*Diego Eis*，一位巴西人，以传播一些最佳实践而享有盛誉，也是[Tableless.com.br](http://Tableless.com.br)网站的创始人，在他的一篇文章中对响应式网页设计和非响应式网页设计进行了精彩的比较。想象一下，如果我们计划前往两个或更多目的地，你肯定会准备许多服装组合，比如夹克、裤子、短裤和衬衫，这会导致一个大大的沉重的行李。这是因为你无法知道每个地方的气候情况。同样，为了应对所有情况，有时这可能会稍微降低网站的性能。

# 用媒体查询调整屏幕

*Luke Wroblewski*，知名网页设计书籍的作者，在许多文章中是很好的参考，最近发布了由技术公司宣布的设备尺寸分类：

+   4"-5"的智能手机

+   5"-6"的手机/平板混合设备

+   7"-8"的平板电脑

+   9"-10"的平板电脑

+   11"-17"的笔记本电脑和可转换设备（平板电脑/笔记本电脑）

+   20"-30"的台式电脑

例如智能手机等标签只是友好的标签，只要我们知道响应式网页设计使结构响应设备的屏幕分辨率，而不是设备类型。但是，我们必须分析是否最好为特定宽度提供不同的方法。这是此模块的改进功能，其中 CSS2.1 着重于媒体类型，如打印、屏幕和手持设备；在 CSS3 中，重点是媒体特性。

媒体查询大多数被使用，大多数浏览器原生支持（Firefox 3.6 及以上，Safari 4 及以上，Chrome 4 及以上，Opera 9.5 及以上，iOS Safari 3.2 及以上，Opera Mobile 10 及以上，Android 2.1 及以上，以及 Internet Explorer 9 及以上）。现在，问题来了：IE6-IE8 呢？对于这些浏览器，有一个被称为 **Respond** 的已知轻量级解决方案，在需要支持旧浏览器时非常有用（更多信息请参见 第十章 *，确保浏览器支持*）。

在这个主题上保持简洁，以下是我们在指定媒体查询时主要使用的特性：

+   宽度：`min-width` / `max-width`

+   高度：`min-height` / `max-height`

+   方向：它检查设备是纵向还是横向。

+   分辨率：例如，`min-resolution: 300dpi`

检查下面的 CSS 代码，以更好地理解媒体查询的使用和语法：

```js
/* Standard desktop screens */
@media only screen and (min-width:1025px) {
 CSS GOES HERE
}
/* Tablets */
@media only screen and (min-width:481px) and (max-width:1024px) {
 CSS GOES HERE
}
/* Smartphones */
@media only screen and (max-width:480px) {
 CSS GOES HERE
}
```

为了澄清这段代码，下图是对这段代码的视觉解释，其中显示布局可以根据设备屏幕的不同方式显示：

![通过媒体查询调整屏幕](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_01_02.jpg)

### 提示

**下载示例代码**

你可以从你在 [Packt 出版社](http://www.packtpub.com) 购买的所有 Packt 图书的账户中下载示例代码文件。如果你在其他地方购买了本书，你可以访问 [Packt 出版社的支持页面](http://www.packtpub.com/support) 并注册，直接将文件通过电子邮件发送给你。

# 移动优先

让我们从分析此项目的用例开始这一节：

![移动优先](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_01_03b.jpg)

当项目以桌面优先开始时，通常会出现这种结果，而网页设计则会用横幅或图片、不太相关的链接、动画等填充空白。我们可能忽略了用户遵循的明显和基本流程。我们知道有时这些其他项目看起来对项目很重要，但显然这个项目设计需要进行信息架构审查。

在上一个例子中，我们可以注意到（在右侧）与用户的简单沟通可以是多么的简单，减少视觉混乱可能会更有效。这就是趋势：简化。下面 *Bill DeRouchey* 的一句话概括了这一点：

> "首先设计移动应用程序迫使我们剥离至关重要的内容。"

### 注意

换句话说，移动优先对业务很有好处，因为客观性带来金钱。您将添加到您的网站的内容对最终用户来说是有价值的，是重要的。这些新功能的实施将允许访问者在移动时更快速、更直观地访问内容，从而获得更好的用户体验。

在这种情况下，当应用移动优先概念时，一个特定的链接只能在内部页面中找到。然而，主页的目标是引导用户到正确的页面，按照网站流量信息。对于不相关的链接，在这种情况下是可以接受的。

看一下以下屏幕截图，并注意桌面版本中关于信息组织和重要链接焦点的许多差异：

![移动优先](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_01_04.jpg)

# 使用线框工具

线框是一个视觉指南，帮助构建网站结构，其主要焦点在于功能、行为和内容的优先级。它应该是任何项目的第一步，因为它能更容易地分析信息架构和视觉元素的安排。

Wireframe.cc ([`wireframe.cc/`](http://wireframe.cc/)) 是开始我们项目的简单方式。这个工具非常适合快速创建低保真版本。对于详细的作品，有更好的工具，比如 Balsamiq Mockups 或 Pencil。

Wireframe.cc 的使用非常简单。进入工具的网站后，执行以下操作：

1.  在左上角选择设备。

1.  然后点击设置重新定义我们的容器宽度（如果有必要）。

1.  现在点击并拖动来绘制。

1.  在这之后，选择适当的样板。

1.  如果你选择了一个错误的样板，只需双击它进行编辑。

### 提示

当您完成使用线框时，不要忘记点击**保存**按钮，这将生成一个 URL 供进一步访问。

# 练习 1 - 在线框中练习移动优先开发

访问[`mediaqueri.es/`](http://mediaqueri.es/)，花点时间获得灵感。让我们通过应用移动优先概念为这些尺寸创建三个网站线框：智能手机、平板和台式机。

以下三个线框将被用作*练习 1*的参考：

![练习 1 - 在线框中练习移动优先开发](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_01_05.jpg)

# 总结

在本章中，我们回顾了响应式网页设计的概念。我们还学习了什么是移动优先。我们学习了媒体查询以及它们在我们网站实现中的不同之处。我们还创建了一个展示我们网站的线框。这将把我们连接到下一章，该章将对这个线框进行编码。

现在，通过学习如何使用三种不同的响应式网格系统：流体基准网格，1140 网格和我最喜欢的 Foundation4 网格，我们继续进行项目。同时，我们也会探讨如何通过使用 JavaScript 来调整网站的行为。所有这些主题将在下一章中进行解释。


# 第二章：设计响应式布局/网格

> “考虑网页响应式设计意味着考虑比例，而不是像素。”

*特伦特·沃尔顿*之前的引用总结了本章的思想，因为当我们在进行响应式设计时，我们必须考虑流动性、适应性，而不是追求像素完美。这就是检查每个像素的习惯正在快速衰落的原因。

但是，有两种方法可以解决这个问题并保持我们的网站响应性：

+   进行网站转换时使用一些数学方法以确保良好的结果

+   使用响应式网格系统，在其中选择一堆列，并使用相对尺寸保持代码在此列中

移动技术的这些进步以及网站技术的快速发展已经推动了每个人重新审视网站的有限尺寸概念，并开始考虑一个能够自适应并为每种情况提供所需内容的结构。

在本章中，我们将学习以下内容：

+   使用 JavaScript 调整网站

+   如何以百分比格式查看对象给结构带来的灵活性

+   如何吸收响应式网格系统的特点

+   如何编写三种不同的响应式网格

+   如何使用 Photoshop 网格模板

+   如何在开始之前设置`viewport`的`meta`标签

+   如何使用 Foundation4 Grid 实现线框

# 使用 JavaScript 调整网站

正如我们在前一章中看到的，我们可以使用媒体查询来识别当前可用的区域并呈现特定的设计自定义。这个属性非常有用，但在旧版浏览器中不起作用，比如 Internet Explorer 8 及更早版本。有两个主要解决方案我们将会深入了解，它们能很好地处理媒体查询：**Adapt.js** 和 **Respond.js**。

让我们进一步分析每种解决方案的特点，看看它提供了哪些功能，除了动态捕获设备尺寸（非常类似于`@media`查询）作为对需要支持旧版浏览器的项目的替代方案。

## Adapt.js

以下是 Adapt.js 的特点：

+   捕获浏览器的尺寸后，Adapt.js 仅在需要时提供所需的 CSS。

+   它拥有非常轻量级的文件

在采用之前应考虑以下几点：

+   这个分析浏览器窗口大小的过程是按需进行的，可能会出现短暂延迟，以渲染正确的 CSS。

+   脚本必须插入到代码的开头（在`head`标签中），页面的初始加载可能需要更长的时间。

Adapt.js 提供了一些默认的 CSS 文件和媒体查询作为建议，可以在我们的网站上使用。以下是[`adapt.960.gs/`](http://adapt.960.gs/)默认提供的文件：

![Adapt.js](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_01.jpg)

### 如何做

在您下载并将文件放置在项目中之后，将以下代码片段添加到`<head>`标签中。在下面的代码中，我们能够更改 CSS 文件的默认路径，动态适应的频率（一次或每次窗口更改时），以及基于范围的 CSS 文件：

```js
<noscript>
  <link rel="stylesheet" href="assets/css/mobile.min.css" />
</noscript>
<script>
  var ADAPT_CONFIG = {
    path: 'assets/css/',
    dynamic: true,
       range: [
    '0px    to 760px  = mobile.min.css',
    '760px  to 980px  = 720.min.css',
    '980px  to 1280px = 960.min.css',
    '1280px to 1600px = 1200.min.css',
    '1600px to 1940px = 1560.min.css',
    '1940px to 2540px = 1920.min.css',
    '2540px = 2520.min.css'
    ]
  };
</script>
<script src="img/adapt.min.js" />
```

## Respond.js

Respond.js 文件可以从[`github.com/scottjehl/Respond`](https://github.com/scottjehl/Respond)下载。以下是 Respond.js 的特点：

+   这种解决方案似乎比 Adaptive.js 更容易

+   它有一个轻量级文件

+   您需要首先检查浏览器是否真的需要此脚本，仅在需要时才执行它

+   有两个有用的 API 帮助我们调试

缺点如下：

+   它还在正确的时间执行正确的 CSS 选择方面存在一定的延迟

### 如何操作

在您下载并将文件放置在我们的项目中之后，只需在`head`标签中添加以下代码，它就会执行解决方案：

```js
<script src="img/respond.min.js">
```

### 提示

Respond.js 使用我们已经应该在代码中使用的`@media`查询，并动态应用样式。没有额外的工作！

# 百分比如何给结构提供灵活性

一些老网站，甚至是最近的网站，都不关心灵活的结构，仍然使用像素作为测量单位。像素为我们提供了更大的结构控制和精度。但是，现在，我们不再控制网站将在何处显示（正如我们在第一章中看到的，*探索响应式网页设计*），这引发了构建灵活结构的需求，其中元素可以拉伸并适应尺寸。

百分比始终按照其父元素中声明的值运行。因此，如果一个`div`标签的大小为 50%，其父元素的大小为 600 像素，则`div`标签的大小将为 300 像素，如下图所示：

![百分比如何给结构提供灵活性](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_02.jpg)

同样适用于百分比，其中其父元素的大小为对象的实际大小的 50%，则大小为 50%的`div`标签看起来像是 25%，保持比例。让我们看下面的图：

![百分比如何给结构提供灵活性](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_03.jpg)

但是，问题是：如果我们不设置父元素的宽度会怎样呢？*Maurício Samy Silva*在他的博客[`www.maujor.com/blog/2013/03/08/por-que-height-100-nao-funciona/`](http://www.maujor.com/blog/2013/03/08/por-que-height-100-nao-funciona/)中对此进行了很好的解释。在这种情况下，父元素会采用当前视口的默认宽度。换句话说，随着浏览器窗口的调整，此宽度会自动更改，这一事件正是赋予我们灵活结构的力量。

回到之前的例子，其中`div`设置为 50%，在可用区域内的视觉上看起来是一半大小，如下图所示：

![百分比如何给结构带来灵活性](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_04.jpg)

现在您已经了解了结构的流动性的重要性，另一个重要任务是将填充和边距以及百分比转换。例如，当我们需要在大屏幕上显示大的水平填充时，它会产生影响，因为如果同一个网站在智能手机上看到，并且填充已经定义为像素，它将在屏幕上占据大量空间。

我们可以为手机制定一个例外规则，减少这个空白空间。但是，试想一下，为所有元素做这项工作将需要多少努力！最好的选择是将此间距从像素转换为百分比。

## 将像素转换为百分比

将像素转换为百分比的主题很重要，因为这是魔法开始展现的地方；换句话说，我们将通过一个例子看到如何放弃像素的绝对大小并将其转换为百分比。如果我们的项目的目的是更好地控制元素的灵活性，那么应该特别使用将像素转换为百分比的过程。

让我们练习将以下基于像素的结构转换为百分比：

![将像素转换为百分比](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_05.jpg)

以下代码是前一个屏幕截图中详细信息的 CSS 代码示例：

```js
#wrap {
 width:960px;
}
#content {
 width:690px;
 float:left;
}
#right-sidebar {
 width:270px;
 float:left;
}
```

### 注意

让我们来看看这个神奇的公式：*目标 / 上下文 = 结果*。

在前述公式中，*目标* 是以像素为单位的原始元素宽度，在以下代码中为 `690`，*上下文* 是其容器的宽度，在此为 `960`，*结果* 是灵活的值：

```js
#wrap {
 width:100%; /* container 960 */
}
#content {
 width:71.875%; /* 690 ÷ 960 */
 float:left;
}
#right-sidebar {
 width:28.125%; /* 270 ÷ 960 */
 float:left;
}
```

### 提示

分享一点我的经验，我建议在结果之前放置原始值。当我们想再次转换大小并且忘记了原始像素值时，这将产生差异。

我还想强调不要四舍五入数学结果的重要性。这对于元素的灵活性至关重要，可以防止不希望的断裂。

以下图是转换为灵活结构的结果：

![将像素转换为百分比](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_06.jpg)

为了帮助简化此转换，有一个名为**Flexible Math**的工具，可以在 [`responsv.com/flexible-math/`](http://responsv.com/flexible-math/) 找到。只要基于父元素大小进行转换的像素计算（正如我们在前一节中看到的）。

还有另一种转换方式，即从 em 转换为字体大小和行高的像素，但我们将在第四章*设计响应式文本*中更详细地学习。虽然我们正在谈论 EM，但使用的神奇公式将是相同的，需要在其他确定的点上留意一些。

我们将在第五章中看到，*准备图像和视频*，不指定 `<img>` 标签的大小只是缩放图像的第一步。后来，我们将详细了解如何使图像流动，并且还有一些在每种情况下最适合显示图像和视频的方法。

如果我们在数学转换上有很多工作，并且它花费了很多时间，我们应该考虑另一种方法。有一种更方便和更快速的方法来获得这种灵活的结构，其名称是响应式网格系统，我们将在以下部分中看到。

# 什么是响应式网格系统？

网格系统本身可以被标记为开发工具包或一小组 CSS 文件，这些文件将帮助我们快速开发网站。其中一些具有固定宽度的列（可能会根据使用的工具而变化）。列是网格系统的最小度量单位。大多数网格系统包含 12-16 列。间隔是用于在列之间创建空间的边距。

此外，如果设计基于网格，网格系统会节省开发时间。有时，布局创建可能会受到列的限制，但这并不太常见。网格系统的优势在于它们帮助我们实现更好的可读性，并平衡视觉权重、灵活性和整体页面的凝聚性。

为了更好地理解网格系统的工作原理，请查看以下截图，并注意可以将标题区域的宽度测量为 12 列（全宽），而**侧边栏**区域仅为 3 列：

![什么是响应式网格系统？](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_07.jpg)

何时不应该使用网格？如果您的网站布局使用不规则的列尺寸和不规则的间距，则可能无法实现网格的实施。

现在问题来了：响应式网格系统和非响应式网格系统之间的主要区别是什么？

以下是响应式网格系统的特点：

+   它必须在不同尺寸下具有不同的特征

+   它必须在断点之间流动

+   它必须具有足够的控制权来决定哪些列会在哪一点转换

+   类应该在所有断点上都能理想地有意义

## 响应式网格系统

现在，我们将看到三种不同的应用系统，但为了我们渐进的理解，我想从描述较不复杂的系统开始，然后再描述具有更多选项和资源的系统。

### 提示

在选择最适合您项目的网格之前，请阅读所有这些网格系统。此外，还有其他类型的响应式网格，我尚未尝试在实际项目中实施。

### 流动基线网格系统

此开发工具包的目标是为响应式网站的开发提供便捷和灵活性。Fluid Baseline Grid 代码（[`fluidbaselinegrid.com/`](http://fluidbaselinegrid.com/)）简单、轻量、非侵入性，并且可以根据项目的需求进行定制。

此网格系统基于三列折叠布局：移动设备一列，平板电脑两列，桌面及以上三列。让我们看看它的用法。

要这样设置代码，我们只需在想要内容填充的结构中使用类 `g1`，然后对于两列使用 `g2`，三列使用 `g3`。看下面的代码示例：

```js
<div id="content">
    <div class="g2">
        ...
    </div>
    <div class="g3">
        ...
    </div>
    <div class="g1">
        ...
    </div>
</div>
```

以下是该代码的预览：

![Fluid Baseline Grid 系统](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_08.jpg)

现在，让我们先看一个网站示例，然后尝试使用类来编写结构：

![Fluid Baseline Grid 系统](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_09.jpg)

HTML 结果应该如下：

```js
<div id="content">
    <div class="g3">
        ...
    </div>
    <div class="g1">
        ...
    </div>
    <div class="g1">
        ...
    </div>
    <div class="g1">
        ...
    </div>
</div>
```

你注意到指南针图像在手机屏幕上是隐藏的吗？在这种情况下，解决方案是在手机 CSS 上隐藏轮播图，然后在平板电脑 CSS 上显示它（以及桌面）。

使用 Fluid Baseline Grid 的主要优势如下：

+   流式列

+   具有美观排版标准的基线网格

+   **响应式设计行为**

+   使用 Normalize.css 修复常见的浏览器不一致性

+   包含了开始所需的最少文件的简单文件结构

+   对 IE6/7/8 的 Polyfills 支持：Respond.js（媒体查询）和 html5shim（HTML5 元素）

**流式列**默认为最小三列折叠网格，列宽约为 31%，列之间的间隔为 2%。如果网站设计需要更多列，那也没问题，因为可以在 CSS 代码中进行更改。

**基线网格**为排版带来了跨浏览器的解决方案，改善了可读性，并在文本内部创建了更好的和谐。主要使用的字体是 Georgia 和 Futura，它们可以轻松更改以匹配项目的需求。

**Fluid Baseline Grid** 设计为移动优先，为我们的响应式设计实现提供了常见的断点。CSS 代码准备从小屏幕开始定制，并根据设备的可用区域在内容显示上建议差异。只要它基于列，Fluid Baseline Grid 就被分为：移动设备一列，平板电脑两列，桌面及其他设备三列。

### 1140 网格

1140 Grid（[`cssgrid.net/`](http://cssgrid.net/)）有一个简单的结构。它的目标是在定义每个主要元素的宽度时提供更高的代码开发效率。它被分为 12 列，这些列将根据您的偏好合并或不合并。但是，当设计这个项目时，宽度尺寸被限制在最大 1280 px。如果项目不需要在大设备上显示，1140 Grid 对于所有其他较小的尺寸都非常有效。

为了澄清，以下代码显示了您实际上可以这样做：

```js
<div class="container">
   <div class="row">
       <div class="onecol">
           ...
       </div>
       <div class="twocol">
           ...
       </div>
       <div class="threecol">
           ...
       </div>
       <div class="threecol last">
           ...
       </div>
   </div>
</div>
```

下面的图示展示了结果：

![1140 Grid](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_10.jpg)

作为我们知识吸收过程的一部分，让我们回到 Pixelab 示例并使用 1140 Grid 进行编码：

```js
<div id="container">
   <div class="row">
        ...
   </div>
   <div class="row">
        <div class="fourcol">
          ...
        </div>
        <div class="fourcol">
          ...
        </div>
        <div class="fourcol last">
          ...
        </div>
   </div>
</div>
```

行类将内部列居中，并将`1140px`定义为`max-width`。

类`.onecol`，`.twocol`，`.threecol`，`.fourcol`，`.fivecol`，`.sixcol`，`.sevencol`，`.eightcol`，`.ninecol`，`.tencol`，`.elevencol`和`.twelvecol`可用于每个列。此外，它们将在任何组合中使用，以便在行内添加的列总和为十二列或更少。在最后一个元素中，请记得也添加一个类`last`；这将去除额外的边距。

与 Fluid Baseline Grid 相比，其中一些少许不同之处是 1140 Grid 已经实现了更多的列（为开发者提供更多的选项），但是 Fluid Baseline Grid 的开发者们可以自由地在那里实现它。

除了简单的结构之外，1140 Grid 还因以下特点而备受关注：

+   准备好缩放图像的 CSS 代码。

+   百分比间距。

+   浏览器支持（除 IE6 外）

+   最小文件结构

+   可下载的 PS 模板

### Foundation4

Foundation4，[`foundation.zurb.com`](http://foundation.zurb.com)，是一个完整的框架，内含许多组件。它们是预定义的，并且被专业地样式化，将作为我们项目的基础。仅关注 Foundation4 的网格组件会让我们惊讶，因为它提供了许多选项。

由于下载区域的存在，这个框架是与众不同的，它展示了下面的截图所示的屏幕，因为它给了开发者们以最适合他们的方式开始他们的项目的自由（如果他们已经对网格有一些通用知识）：

![Foundation4](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_11.jpg)

但是，不用担心；如果你仍然在学习，它默认使用最常用的值，如 12 列和 62.5 em（1000 px）的最大屏幕尺寸。

Foundation4 中还有其他好的功能，如下所示：

+   预定义的 HTML 类。

+   小网格和大网格。

+   嵌套我们的网格。

+   偏移。

+   居中的列。

+   源顺序。

+   面向移动端。

+   支持浏览器的 Normalize 和 Modernizr 脚本。

+   不支持像 Internet Explorer 7 及更早版本的浏览器。此外，Internet Explorer 8 对网格和一些 UI 组件（如输入切换器）的支持有限。

+   要在 Internet Explorer 8 中使用 Foundation4，它推动开发者使用其之前版本的补充解决方案，该解决方案可在[`foundation.zurb.com/docs/support.html`](http://foundation.zurb.com/docs/support.html)找到。

该框架值得更多的关注，因为它有更多的选项和优势。这就是我们详细了解它们的原因。在接下来的例子中，我们将使用工具建议的 12 列作为参考。

Foundation4 拥有一堆预定义的 HTML 类，这些类对我们的开发很有帮助，因为所有的代码都已经创建好了，我们只需要通过类名来调用它。在下面的例子中，我们看到一个小类和元素将占据的列数：

```js
<div class="row">
 <div class="small-3 columns">...</div>
 <div class="small-6 columns">...</div>
 <div class="small-3 columns">...</div>
</div>
```

下图显示结果：

![Foundation4](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_12.jpg)

注意到 3、6 和 3 的和等于 12。另外，还有一个选项可以将类从`small`更改为`large`。如果我们交换这些类，当我们减小浏览器宽度达到 768 像素时，每个`<div>`标签将占据最大宽度。这两个类可能会同时出现——在小于 768 像素的小屏幕上显示内容——而在大屏幕上，宽度就像前面的示例中给出的那样。

在这种情况下，代码将如下所示：

```js
<div class="row">
 <div class="small-6 large-5 columns">...</div>
 <div class="small-6 large-7 columns">...</div>
</div>
```

Foundation4 Grid 允许我们嵌套到任何深度。这个技术通常用于执行相当复杂的设计实现，或者更好地定位表单元素。以下代码是其用法的一个示例：

```js
<div class="row">
 <div class="small-8 columns">8
   <div class="row">
     <div class="small-3 columns">3 Nested</div>
     <div class="small-9 columns">9 Nested</div>
   </div>
 </div>
 <div class="small-4 columns">4</div>
</div>
```

以下图显示结果：

![Foundation4](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_13.jpg)

我们可以使用`offset`在行中的列之间创建额外的间距。通过调整这个参数，我们可以对齐列的位置。记住，所有的 offset 都位于元素的左侧。同样，数字的和应该等于 12。让我们在下面的例子中看一下这个，第一个`div`标签填充了两列，然后有两列的偏移，然后另一个`div`标签填充了八列：

```js
<div class="row">
 <div class="large-2 columns">2</div>
 <div class="large-8 large-offset-2 columns">8, offset 2</div>
</div>
```

结果如下所示：

![Foundation4](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_14.jpg)

`centered column`类是用来将特定列（而不是内部内容）定位在行的中间的。Foundation4 提供了两个类：`large-centered`和`small-centered`。就像我们之前看到的，小版本将显示为前面没有被大版本覆盖的样子。例如，如果我们想要显示一个占据六列并且居中（适用于小屏幕和大屏幕）的`div`标签，我们应该在之前使用以下代码：

```js
<div class="row">
 <div class="small-6 small-centered columns">6 centered</div>
</div>
```

结果如下：

![Foundation4](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_15.jpg)

也许以下功能有点令人困惑，但当我们想要将源代码放置在相关内容的顶部时非常有用。要做到这一点，我们只需要使用`push`和`pull`类。以下功能也会分别影响每个版本（在函数前使用`small`或`large`，即`large-push-8`）或两个版本一起使用：

```js
<div class="row">
 <div class="small-4 push-8 columns">4</div>
 <div class="small-8 pull-4 columns">8, last</div>
</div>
```

以下是结果：

![Foundation4](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_16.jpg)

# Photoshop 网格模板

为了在创建设计时方便查看列，有一个名为 Guideguide 的 Photoshop 插件。

Guideguide 插件([`guideguide.me/`](http://guideguide.me/))支持一些版本的 Photoshop，包括：CS5、CS6 和 CC。但是，如果你使用 Photoshop CS4，该插件的 2.03 版本将可用，但不会再更新新功能。这是一个指导我们为 Photoshop 文档创建自定义参考线的工具。

安装 Guideguide 插件并创建一个空白文件后，当我们在 Photoshop 中进行访问时，它将打开下面截图中显示的窗口；我建议使用所示的初始值填充，如果您对网格不太熟悉的话：

![Photoshop 网格模板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_17.jpg)

然后，点击**GG**按钮，它会在我们的文档中创建参考线，在布局创建中非常有用。

# 在开始之前设置 viewport 的 meta 标签

`viewport`的`meta`标签通过显示可视区域的一部分来工作。这种配置在我们设计响应式网站时非常重要，因为如果没有它，移动设备浏览器将向用户显示网站的缩小版本。对于它的使用，没有标准的语法，但是所有常见的移动浏览器都支持以下标签：

```js
<meta name="viewport" content="width=device-width">
```

其他功能，比如`initial-scale`可以用来定义`viewport`的`meta`标签，可以阻止用户在网站中以放大模式打开，并且 `maximum-scale`会限制用户放大内容。以下代码是`viewport`限制用户体验的一个例子，不允许使用缩放功能：

```js
<meta content="width=device-width, initial-scale=1, maximum-scale=1" name="viewport">
```

# 2a 练习 - 为线框创建布局设计

现在，我们已经有了线框并了解如何操作网格的列，我们需要根据列中的主要元素调整线框，如下截图所示：

![2a 练习 - 为线框创建布局设计](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_18.jpg)

在那之后，该是时候给它上色，并设想为所有设备提供最佳的用户体验。

根据第一章中*练习 1*的线框，*探索响应式网站设计*，以下截图显示了布局设计的建议：

![2a 练习 - 为线框创建布局设计](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_19b.jpg)

当我们正在自定义主要元素时，请记住将其保持在指导方针内，这将使下一步更容易。否则，我们将花费比预期更多的时间来编码它。

下图显示了主要元素如何适应列：

![练习 2a – 为线框创建布局设计](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_20.jpg)

# 练习 2b – 使用 Foundation4 Grid 结构化我们的网站

在看到了一些响应式网格系统的使用（从简单解决方案开始，然后进入更完整的解决方案），让我们使用 Foundation4 Grid 来结构化我们的代码，快速创建响应，并且不需要编写一行 CSS 代码来完成。同时，请记得在 `<head>` 标签中配置视口。

使用 Foundation4 Grid，执行以下推荐步骤：

1.  开始编写 HTML 脚本。

1.  确定结构中的行并将 `row` 类添加到现有元素或新的 `div` 标记中。

1.  测量每个主要元素将填充多少列，并将此值设置为类中。

让我们看看以下 HTML 是如何完成的：

```js
<!DOCTYPE html>
<html lang="en">
<head>
 <meta charset="utf-8" />
 <meta name="viewport" content="width=device-width" />
 <title>Responsive Web Design using jQuery & CSS3</title>
 <link rel="stylesheet" href="css/foundation.css" />
</head>
<body>
 <header class="row">
   <a class="large-3 columns" href="#">LOGO</a>
   <nav class="large-9 columns">
     <ul>
       <li><a href="#">About</a></li>
       <li><a href="#">Training Options</a></li>
       <li><a href="#">Schedules</a></li>
       <li><a href="#">Rates</a></li>
       <li><a href="#">Contacts</a></li>
     </ul>
   </nav>
 </header>
 <div class="row">
   <section class="small-12 columns">
     <img src="img/960x230" alt="FPO for slideshow" />
   </section>
 </div>

 <div class="row">
   <section id="content" class="large-8 push-4 small-12 columns">
     <article>
         <h2>Page title</h2>
         <p>FPO text: Lorem ipsum dolor sit amet...</p>
         <p><a href="#" class="button learn-more">Learn more</a></p>
     </article>
     <article class="subcontent">
         <h2>Page subtitle</h2>
         <p>FPO text: Lorem ipsum dolor...</p>
     </article>
   </section>
   <aside class="large-4 pull-8 columns">
     <h2>Sidebar title</h2>

     <div class="row">
       <div class="small-4 large-12 columns">
<img src="img/aside-1.jpg" class="img-aside" />
     <span>FPO text: Lorem ipsum dolor...</span> <a href="#">See more</a></div>
       <div class="small-4 large-12 columns">
<img src="img/aside-2.jpg" class="img-aside" />
<span>FPO text: Lorem ipsum dolor...</span> <a href="#">See more</a></div>
       <div class="small-4 large-12 columns">
<img src="img/aside-3.jpg" class="img-aside" />
     <span>FPO text: Lorem ipsum dolor...</span> <a href="#">See more</a></div>
     </div>
   </aside>
 </div>

 <section id="banners" class="row">
   <div class="small-4 columns">Banner1</div>
   <div class="small-4 columns">Banner2</div>
   <div class="small-4 columns">Banner3</div>
 </section>

 <footer class="row">
   <p class="large-2 small-9 large-offset-8 columns">All rights reserved. 2013</p>
   <p class="large-2 small-3 columns">icons</p>
 </footer>
</body>
</html>
```

在这段代码中，我折断了一行额外的内容，使每一行都容易看到，并且还突出显示了网格使用的类。让我们观察每行的列之和：

1.  `small` = 12 列

1.  `small` = 12 列（4 + 4 + 4）和 `large` = 12 列（每行一个列）

1.  `small` = 12 列（4 + 4 + 4）

1.  `small` = 12 列和 `large` = 12 列（2 + 8 + 2）

以下截图显示了在大于 768 px 宽度的设备上没有编写任何 CSS 代码的结果：

![练习 2b – 使用 Foundation4 Grid 结构化我们的网站](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_21.jpg)

下图显示了在宽度小于 768 px 的设备上相同站点的屏幕截图：

![练习 2b – 使用 Foundation4 Grid 结构化我们的网站](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_02_22.jpg)

请放心；网站看起来仍然很糟糕，因为这只是项目的第一步。我们需要做一些视觉调整来完成我们的任务。

### 提示

我建议你搜索一些漂亮的图片来使用在你的网站上，改善它的外观和感觉。否则，您可以转到[`placehold.it/`](http://placehold.it/) 创建一个占位符来保留图片的空间。

这是一种很好的方法，可以避免修改解决方案附带的 CSS。在这种情况下，我们将创建一个新的 CSS 文件并将其包含在我们的网站上。在 `header` 部分，在 Zurb Foundation CSS 文件之后，包含您自己的 CSS 代码：

```js
<link rel="stylesheet" href="css/mystyle.css" />
```

在这个 CSS 中，我们将自定义分成三个部分，应用级联样式，并避免重复代码的部分：

+   两个版本

+   小版本（小于 768 px）

+   大版本（大于 768 px）

下面的代码用于从我们的网站开始定制。随意使用它，只要它只是匹配布局的建议。

```js
#banners div {
  text-align: center;
  height: 100px;
  line-height: 100px;
  background: #f65050;
}
#banners div:first-child {
  background: #7ddda3;
}
#banners div:last-child {
  background: #506ff6;
}
@media only screen and (max-width: 48em) {
  .subcontent,
  aside span {
    display: none;
  }
  aside .img-aside {
    display: block;
    margin: 0 auto;
  }
  aside div {
    text-align: center;
  }
}
@media only screen and (min-width: 48em) {
 aside .img-aside {
    float: left;
  }
}
```

# 摘要

在本章中，我们学习了三种使用 JavaScript 解决方案呈现特定 CSS 代码的不同方法：Adapt.js、Respond.js 和 Breakpoints.js。现在，我们也明白了如何通过数学运算将像素转换为百分比，并发现结果。我们还学习了什么是响应式网格系统，以及如何使用每种类型的响应式网格系统。

最后，我们开始使用网格（基于来自第一章的线框图，*探索响应式 Web 设计*），编写我们的网站，这与下一章相连接，下一章我们将涵盖不同的方法来实现响应式菜单导航，例如切换菜单、侧栏菜单（如 Facebook 等）等。


# 第三章：构建响应式导航菜单

当网站正在建设时，`header` 部分是一个重要的部分。在这个区域有一些常见的元素，如徽标、登录、导航选项、注册选项和搜索字段。但规划这个区域并不太容易，因为如果我们把所有元素放在一起，我们会给用户一个杂乱的导航。另一个选择是为我们的头部保留大量的空间，但这可能会在智能手机上遮挡更多的屏幕上方内容。预期的结果是占用少量的空间来处理您的标题，并有效地处理那个空间以显示这些元素。

在这一章中，我们将分析一些类型的导航菜单，在何种情况下以一种清晰直观的方式使用每种类型，并避免使用户感到沮丧。这就是为什么我们设计我们的导航菜单的方式，让用户能够轻松清晰地看到其中的主要和子项对我们很重要。

在这一章中，我们将：

+   设计一个改善可用性的菜单

+   查看最常用的响应式导航模式以及如何编写每种类型的代码

+   通过做练习来应用我们最近获得的知识

# 通过改善其可用性来设计一个菜单

在响应式网站上，特别是对于那些使用移动优先概念的网站，内容是用户访问我们网站的主要原因，所以我们必须提供一个合理的空间在屏幕上展示内容之前。

为了提供这个空间，我们需要更好地处理菜单的显示方式，以便根据设备提供另一种视图。

无论如何，目标都是相同的：使用户更容易找到他们正在寻找的内容，而不会对有用的区域产生重大影响。当菜单被组织好时，我们给了用户自由选择通过我们的网站导航到哪里的权利。

事实上，关于这两种界面之间的决斗（顶部和左侧导航菜单）没有一个答案。有时导航在一个上下文中运作良好；然而，在另一个上下文中可能不那么有效。要找出哪种导航最适合我们的站点，了解顶部和左侧导航菜单在哪些不同的上下文中效果最好是很重要的。让我们在五轮比赛中分析这场战斗：

+   **扫描**：在这方面，左侧导航菜单获胜，因为它占用更少的空间来显示所有项目，并且促进了垂直扫描（对用户更自然）。

+   **页面空间**：在这方面，顶部导航获胜，因为它使用最小的垂直空间，将内容区域保留给内容。

+   **项目优先级**：在这一轮中，顶部和左侧导航菜单之间打成平手。顶部导航的项目没有相同的权重，因为最左边的项目将在其他项目之前被阅读，但这取决于内容类型。

+   **可见性**：在这一轮中，顶部和左侧导航菜单之间存在一种平衡。顶部导航菜单更容易看到，因为它通常靠近标志。在左侧导航中，一些项目可能隐藏在折叠下面。

+   **主题和兴趣**：在这一轮中，顶部和左侧导航菜单之间存在一种平衡。如果我们的网站针对广泛的受众提供各种内容（例如电子商务网站），左侧导航菜单对这些用户更好，因为他们拥有各种兴趣，并且是选择要查看的项目的人。然而，对于特定主题，顶部导航菜单更合适，因为快速找到高优先级项目更为重要。

# 最常用的响应式导航模式

规划移动导航并不是一件容易的事情，因为我们需要以响应式的方式提供不显眼且快速访问特定内容，这取决于网站的目标。经过长时间的研究，*布拉德·弗罗斯特* 在他对流行菜单技术的研究中总结了一些趋势，并建立了菜单类型概念的模式。

根据他的文章（[`bradfrostweb.com/blog/web/responsive-nav-patterns/`](http://bradfrostweb.com/blog/web/responsive-nav-patterns/)），导航模式有：

+   顶部导航

+   底部锚点

+   切换菜单

+   选择菜单

+   仅底部

+   多重切换

+   切换和滑动

+   侧边栏

让我们检查每个，看看它们的样子，并了解哪种方法更适合你的项目。

## 顶部导航

顶部导航模式是因为它需要一点额外的工作而成为互联网上最受欢迎的模式。要实现这个解决方案，我们只需要保持菜单在顶部，正如我们在下面的截图中所看到的那样：

![顶部导航](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_03_01.jpg)

### 如何做…

在这种情况下，如前面的截图所示，在智能手机上显示菜单位于标志的上方。因此，让我们编写这个 HTML 脚本来理解这些变化：

```js
<nav id="site-nav">
  <ul>
    <li><a href="#">Home</a></li>
    <li><a href="#">About</a></li>
    <li><a href="#">Projects</a></li>
    <li><a href="#">Blog</a></li>
    <li><a href="#">Email</a></li>
  </ul>
</nav>
<h1 id="logo">LOGO</h1>
```

如果你喜欢重新排列这些元素（将标志显示在顶部然后是菜单），你需要反转元素的顺序，在代码中将 `<h1>` 标签移到 `<nav>` 标签之前。

不幸的是，`<nav>` 标签不受 Internet Explorer 8 及更低版本的支持。然而，这个标签有很好的语义含义，我推荐使用它。我们将在第十章中看到，*Ensuring Browser Support*，如何使用 `Html5shiv with Modernizr` 处理它。通过采用移动优先的概念，并在 CSS 中使用这个第一个代码块，我们可以自定义菜单的显示方式，通过填充水平区域来填充水平边距，并将菜单对齐到中心：

```js
/* mobile-first */
#site-nav ul {
  list-style: none;
  text-align: center;
  padding: 0;
}
#site-nav li {
  display: inline-block;
  margin: 0 5%;
  line-height: 1.5;
}
#logo {
  text-align: center;
  clear: both;
}
```

对于大于 768 像素的屏幕，菜单宽度减小到 70%，并向右浮动。此外，标志现在向左浮动，宽度为 30%，如下面的代码所示：

### 提示

这些百分比只是示例的一部分。

```js
/* desktop */
@media only screen and (min-width: 768px) {
 #site-nav ul {
   width: 70%;
   float: right;
 }
 #logo {
   float: left;
   width: 30%;
   clear: none;
 }
}
```

### 提示

实施起来非常简单，但是当菜单项超过三行时要小心，因为它将耗费大量重要区域。

## 页脚锚点

页脚锚点是一个聪明的解决方案，其主要目标是在不影响移动用户在小区域中看到我们的网站的情况下，为内容保留更多有用的空间。为此，需要将主菜单重新分配到页脚，并只在页眉中保留一个锚点链接，用户点击它时将聚焦于菜单。

以下截图表示了这种导航模式仅应用于智能手机，空间较小：

![页脚锚点](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_03_02.jpg)

### 如何做到这一点

让我们从第一个导航模式使用相同的 HTML 代码开始。但是现在我们将菜单移动到 DOM 的底部，就在`</body>`标签之前插入下面的链接，因为当用户点击它时，网站将聚焦于导航菜单：

```js
<a id="link-to-menu" href="#site-nav">☰ Menu</a>
```

### 注意

十进制代码`☰`是代表菜单的符号，因为它显示了一个有三条线的符号。

在智能手机的 CSS 代码中，我们需要：

+   为菜单项创建一个样式。一些开发人员喜欢逐行列出这些项目（便于触摸），但这取决于你。

+   为页眉按钮创建一个样式（将用户转到菜单）。

CSS 代码如下所示：

```js
/* mobile-first */
#site-nav ul {
  list-style: none;
  text-align: center;
  padding: 0;
}
#site-nav li a {
  display: block;
  border-top: 1px solid #CCC;
  padding: 3%;
}
#site-nav li:last-child a {
  border-bottom: 1px solid #CCC;
}
#link-to-menu {
  position: absolute;
  top: 10px;
  right: 10px;
}
```

对于平板电脑和桌面（屏幕宽度大于 768 px 的设备），最好的方法是隐藏此页眉按钮。现在，我们需要在页眉上展示菜单，而不对 HTML 做任何更改（我们只是将其移到页脚区域）。

让我们通过设置菜单位置在顶部并隐藏页眉按钮来实现以下代码：

```js
/* tablet and desktop */
@media only screen and (min-width: 768px) {
 #site-nav {
   position: absolute;
   top: 0;
   left: 30%;
   width: 70%;
 }
 #link-to-menu {
   display: none;
 }
 #site-nav li {
   display: inline-block;
   margin: 0 5%;
   padding: 0;
   width: 18%;
   border: none;
   line-height: 1.5;
 }
 #site-nav li a {
   display: inline;
   border: none;
   padding: 0;
 }
 #site-nav li a,
 #site-nav li:last-child a {
   border: none;
 }
}
```

## 切换菜单

切换导航模式与以前的模式比几乎具有相同的行为。真正的区别在于当用户点击页眉上的链接时，而不是将用户引导到锚定菜单，菜单会在页眉之后滑下来，从而为用户提供令人印象深刻的效果和快速访问主链接。它的实现相对容易，我们很快就会看到。

### 提示

为了提高动画性能，尝试使用`max-height`属性

### 响应式导航插件

响应式导航插件，[`responsive-nav.com/`](http://responsive-nav.com/)，是为小屏幕创建切换导航的轻量级解决方案。我们喜欢三个主要特点，它们是：

+   使用触摸事件（我们稍后会更好地理解它）和 CSS3 过渡效果

+   构建此插件时要考虑到无障碍，并与禁用 JavaScript 一起使用。该插件不需要任何外部库

+   适用于所有主要桌面和移动浏览器，包括 IE 6 及更高版本

### 如何做到这一点

下载此解决方案的文件后，让我们将以下代码插入到我们的 HTML 的`<head>`标签中：

```js
<link rel="stylesheet" href="css/responsive-nav.css">
<script src="img/responsive-nav.js"></script>
```

我们还将使用第一个示例的相同 HTML 代码，但是在 DOM 的`</body>`闭合标签之前，我们需要插入执行脚本的函数：

```js
<script>
var navigation = responsiveNav("#site-nav");
</script>
```

现在，让我们从页脚锚点模式中插入相同的菜单样式：

```js
nav ul {
  list-style: none;
  text-align: center;
  padding: 0;
}
.menu-item a {
  display: block;
  border-top: 1px solid #CCC;
  padding: 3%;
}
.menu-item:last-child a {
  border-bottom: 1px solid #CCC;
}
```

就是这样了。我们完成了。有一些可自定义的选项，可以增强我们的功能实现。随意测试其他选项，但默认情况下已设置为 CSS3 动画，显示时间为 400 毫秒，在自动生成的切换按钮之前显示，或者您可以按照以下方式定义您自己的设置：

```js
<script>
var navigation = responsiveNav("#site-nav", {
  customToggle: "#mybutton"
});
</script>
```

在下面的截图中，我们将看到**响应式导航**窗口正在使用，它在智能手机上更改菜单样式，并以不显眼的方式显示菜单：

![操作方法](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_03_03.jpg)

### 提示

切换按钮的定制和菜单中的橙色默认情况下不显示。这只是插件创建者在其演示中提出的建议之一。

## 选择菜单

一种显著减少菜单占用空间的方法是使用此模式，其中所有菜单项都包装在`<select>`标签中。它避免了一些对齐问题，并确保了跨浏览器解决方案。

然而，该方法存在影响可用性、可访问性和 SEO 的问题。乍一看，主导航菜单的选择菜单看起来不正确，因为它与设计不协调。也许用户会觉得这很尴尬，或者可能会与`select`表单元素混淆。

### TinyNav.js jQuery 插件

TinyNav.js jQuery 插件，[`tinynav.viljamis.com/`](http://tinynav.viljamis.com/)，非常有用，可以将`<ul>`或`<ol>`导航转换为小屏幕的选择下拉菜单，当用户选择一个选项时，它会自动导航到正确的页面，而无需额外努力。它还可能选择当前页面，并自动为该项目添加`selected="selected"`。

### 操作方法

让我们开始使用第一个导航模式的相同 HTML 代码。下载 TinyNav 插件后，我们将在`<head>`标签中包含以下代码：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/tinynav.min.js"></script>
```

并在`</body>`闭合标签之前包含以下代码：

```js
<script>
$(function () {
  $("#site-nav ul").tinyNav()
});
</script>
```

在我们的 CSS 文件中添加以下代码，该代码隐藏了此导航模式，并在平板电脑和台式机上设置了常见的菜单样式。此外，它还专门为宽度小于 767 px 的设备显示了解决方案：

```js
/* styles for desktop */
.tinynav {
  display: none;
}
#site-nav {
  float: right;
  width: 80%;
  padding: 0;
}
#site-nav li {
  display: inline-block;
  margin: 0 2%;
  padding: 0;
  width: 15%;
  text-align: center;
  line-height: 1.5;
}
/* styles for mobile */
@media screen and (max-width: 767px) {
  .tinynav {
    display: block;
  }
  #site-nav {
    display: none;
  }
}
```

TinyNav 还提供了一些选项，例如在`<select>`元素之前插入标签，将菜单选项设置为“活动”的当前页面，正如我之前提到的，并定义在之前未选择其他选项时`<select>`的起始值。在这里，我们可以看到如何使用这三个选项：

```js
$('#site-nav ul').tinyNav({
  active: 'selected',
  label: 'Menu',
  header: 'Navigation'
});
```

此导航模式可以在所有设备上实现，无需额外工作。在以下截图中显示的示例中，请注意插件仅影响小型设备：

![操作方法](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_03_04.jpg)

## 仅页脚

仅页脚导航类似于页脚锚点方法，除了`header`部分中的`link`锚点之外。

在使用此导航模式时要小心，因为用户可能找不到页脚上的菜单，每当他们想要访问其他菜单选项时，他们可能必须滚动到末尾。这种导航模式可能适用于内容较少且需要较少用户努力滚动的网站。

### 如何操作

简单地将菜单移到 DOM 的底部。

### 提示

请记住，如果我们像这样更改代码，它将直接影响所有设备上菜单的视觉定位。在应用此技术之前，请确保您的网站不会太长，因为大多数用户希望它位于网站顶部。

## 多重切换

多重切换模式几乎与切换菜单相同，因为它在头部之后也会滑动下来，但它是为复杂菜单而设计的，其中至少有一个嵌套子菜单。当用户点击头部按钮时，菜单就会弹出到内容上。如果用户点击父类别，则子菜单将滑动下来显示其子项。

### 如何操作

这是本示例中将使用的 HTML 代码。我们将使用`<input type="checkbox">`元素作为菜单的状态控制器（打开或关闭），并且用户不会看到它。稍后我将更详细地解释这个技术。

```js
<h1 id="logo">LOGO</h1>
<label class="link-to-menu" for="toggle" onclick>☰ Menu</label>
<input id="toggle" type="checkbox" />
<nav>
 <ul id="site-nav">
   <li><a href="" id="back" class="before"> Back</a></li>
   <li><a href="#">Home</a></li>
   <li><a href="#">About</a></li>
   <li class="current">
     <a href="#" class="contains-sub after">Projects</a>
   <ul class="submenu">
     <li><a href="#">Project 1</a></li>
     <li><a href="#">Project 2</a></li>
     <li><a href="#">Project 3</a></li>
   </ul></li>
   <li><a href="#">Blog</a></li>
   <li><a href="#">Email</a></li>
 </ul>
</nav>
```

下一步是自定义菜单样式。由于它需要大量代码，我强烈建议下载本书提供的整个 CSS 源代码作为此模式的建议。

让我解释一下可能会使您困惑的两段代码。在 CSS 文件的开头有带有值“ `\0025Bc`”（向下箭头）和“ `\0025C0`”（之前的箭头）的属性，它可能会呈现为箭头字符而不是此代码。此外，`#toggle`复选框应保留在页面中（我们不能只将其设置为 display:none），但不在可见区域内：

```js
.after:after {
  content: " \0025Bc";
  font-size: 0.5em;
}
.before:before {
  content: " \0025C0";
  font-size: 0.5em;
}
.link-to-menu {
  display: block;
  position: absolute;
  right: 0;
  top: 0;
  z-index: 100;
}
#toggle {
  left: -9999px;
  position: absolute;
  top: -9999px;
}
#site-nav ul {
  left: 0;
  list-style: none;
  position: absolute;
  right: 0;
  top: 4em;
  z-index: 10;
}
#site-nav a {
  display: block;
  height: 0;
  line-height: 0;
  overflow: hidden;
  text-decoration: none;
  transition: all 0.5s ease 0s;
}
```

在 CSS 代码中稍微中断一下，因为我想更详细地解释一下子菜单的`#toggle`复选框的功能。

当单击`link-to-menu`标签时，`<a>`标签将其高度设置为`3em`。此外，我们需要准备样式以增加链接的高度，因为 jQuery 将在具有`submenu`的`<li>`元素中输入`open`类：

```js
#toggle:checked ~ nav #site-nav a {
  line-height: 3em; height: 3em; border-bottom: 1px solid #999;
  position: relative; z-index: 1; }
  #toggle:checked ~ nav #site-nav .submenu li,
#toggle:checked ~ nav #site-nav .submenu a {
  height: 0; line-height: 0; transition: 0.5s; }
  #toggle:checked ~ nav #site-nav .submenu a {
  padding-left: 7%; background: #555; }
#toggle:checked ~ nav #site-nav .submenu.open li,
#toggle:checked ~ nav #site-nav .submenu.open a {
  height: 3em; line-height: 3em; }
```

还要记得在`<head>`标签中包含`jquery`库：

```js
<script src="img/jquery-1.9.1.min.js"></script>
```

几乎在 DOM 的末尾（`</body>`结束标记之前），我们将执行以下脚本来管理仅对子菜单插入`open`类的操作，以控制将显示哪个子菜单：

```js
<script>
$(document).ready(function() {
  $('a.contains-sub').click(function() {
    if($(this).siblings('ul').hasClass('open')){
      $(this).siblings('ul').removeClass('open');
    } else {
      $(this).siblings('ul').addClass('open');
    }
  return false;
  });
});
</script>
```

期望的视觉效果如下截图所示：

![如何操作](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_03_05.jpg)

## 切换和滑动

这种模式类似于多重切换模式，但不仅仅是切换子菜单，而且在单击顶级链接时，子菜单会从左向右滑动。有一个`back`链接以便用户导航。我真的很欣赏这种交互效果，它肯定会给用户留下深刻的印象。

### 如何做

让我们使用与多重切换模式相同的 HTML 代码进行此示例（包括从 `<head>` 标签调用 jQuery 脚本）。

关于 CSS 代码，我们将使用多重切换模式的相同代码，但在文件末尾插入以下代码。切换模式和滑动模式与多重切换模式的主要区别是子菜单的新箭头字符（右箭头）；子菜单显示在但不在可见区域上：

```js
.after:after {
  content: " \0025B6";
  font-size: 0.5em;
}
.submenu {
  position: absolute;
  left: -100%;
  top: 0;
  height: 100%;
  overflow: hidden;
  width: 100%;
  transition: all 0.75s ease 0s;
  z-index: 10;
}
.submenu.open {
  left: 0;
}
```

使用相同的建议，以下屏幕截图显示了在点击 **Projects** 链接之前和之后的确切时刻（在这种情况下，仅在智能手机上实现）：

![如何做](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_03_06.jpg)

在 DOM 几乎结束时（就在 `</body>` 结束标签之前），我们将执行几乎与之前看到的相同的脚本，但现在添加了一个功能。

以下是我们在之前的示例中使用的相同代码，用于菜单显示控制

```js
<script>
$(document).ready(function() {
  $('a.contains-sub').click(function() {
    if($(this).siblings('ul').hasClass('open')){
      $(this).siblings('ul').removeClass('open');
    } else {
      $(this).siblings('ul').addClass('open');
    }
    return false;
  });
```

以下代码的一部分处理添加/移除子菜单的`open`类的功能。每当通过点击父元素在元素中设置此类时，子菜单可能会水平滑动在屏幕上。

```js
  $('ul.submenu a.contains-sub').click(function() {
    if($(this).offsetParent('ul').hasClass('open')){
      $(this).offsetParent('ul').removeClass('open');
    } else {
      $(this).offsetParent('ul').addClass('open');
    }
    return false;
  });
});
</script>
```

## 侧栏菜单

如果你使用过 iPhone 应用或现在遵循侧栏菜单约定的任何其他应用，你就会在原生应用上看到一个侧栏面板。如果你点击菜单按钮，面板将滑动并占用部分有用的设备区域。

### jPanelMenu jQuery 插件

jPanelMenu 插件，[`jpanelmenu.com/`](http://jpanelmenu.com/)，是一个轻量级的 JavaScript 解决方案，它隐藏了您指定的菜单，并在我们单击头部按钮触发操作时显示它。jPanelMenu 有一些有趣的选项可供附加，例如带有持续时间和效果的动画、键盘快捷键和选择方向。我们很快将看到具有这些功能的示例。

所以，下面的屏幕截图是仅针对智能手机实现的侧栏菜单样式建议。像往常一样，我们保留原始的顶部菜单供平板电脑和台式机使用：

![jPanelMenu jQuery 插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_03_07.jpg)

### 如何做

让我们从 `<head>` 标签中开始包含以下 CSS：

```js
<link rel="stylesheet" href="css/style.css">
```

然后，我们将使用几乎与页脚导航模式相同的 HTML 代码，我们将菜单移动到 HTML 结构的最后部分（页脚区域），并在页面标题中插入以下链接，因为当用户点击它时，网站将专注于导航菜单：

```js
<header class="main">
  <a id="link-to-menu" href="#menu">☰ Menu</a>
  <nav id="site-nav">
    <ul>
      <li><a href="#">Home</a></li>
      <li><a href="#">About</a></li>
      <li><a href="#">Projects</a></li>
      <li><a href="#">Blog</a></li>
      <li><a href="#">Email</a></li>
    </ul>
  </nav>
</header>
```

下载 jPanelMenu 后，让我们在 `<head>` 标签中包含以下代码：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.jpanelmenu.min.js"></script>
```

也在`</body>`结束标签之前包括以下代码。此外，该插件还提供一些很酷的选项，如定义菜单出现时使用的效果、方向和持续时间，键盘快捷键以及一些回调函数：

```js
<script>
$(document).ready(function() {
  var jPM = $.jPanelMenu({
    menu: '#site-nav',
    openPosition: '33%',
    duration: '300',
    direction: 'left',
    openEasing: 'easy-in',
    trigger: '#link-to-menu'
  });
  jPM.on();
});
</script>
```

对于这种模式，不需要特定的 CSS 代码，但仍然需要创建我们自己的 CSS 样式来美观地显示菜单。

# 练习 3 - 使用切换菜单解决方案自定义菜单

在了解了八种响应式菜单及如何实现它们后，让我们选择切换菜单来在我们的网站上实现。

如果您正在建立自己的网站，请随意分析考虑每种菜单导航模式的所有功能，然后选择最佳选项。

# 总结

在本章中，我们学习了如何根据不同情况使顶部和左侧导航更有效。我们还学习了使用 CSS3 或 JavaScript 插件来实现八种不同的导航模式。

在下一章中，我们将介绍处理文本的响应式字体大小的方法。此外，我们将使用 CSS3 和三个很棒的 JavaScript 插件来自定义字体系列，为标题添加更多创意。


# 第四章：设计响应式文本

谈到响应式标题时，我们谈论的是灵活性。因此，在字体大小上使用固定的度量也应该是动态的。过去几年中它是如何实现的与现在的差别在于，早期我们只考虑了两种显示内容的方式：打印和屏幕。尽管时代变化，但对文本适应性的担忧仍然存在。

我们认为排版是我们设计的基础和我们 CSS 的支柱，因为我们网站的主要目标是通过回答用户的问题来向他们提供信息。避免创建十种不同的副标题样式是一个好的做法，为了做到这一点，我们必须根据我们网站的主题计划几个不同的标题。

在本章中，我们将学习：

+   理解并将文本转换为相对单位

+   盒子模型和段落间距

+   为漂亮的响应式标题自定义字体系列

+   自动管理字体大小

# 理解并将文本转换为相对单位

使用相对单位的主要优势之一是，当用户修改基本元素（来自浏览器）的字体大小时，所有字体大小都会按比例增加/减小，从而产生级联效应。

这些天，几乎每个浏览器都将基本元素`<html>`的默认设置设为 16 px。然而，如果用户想增大浏览器字体大小以便更容易阅读，这个值可以在用户端进行修改。

在谈论最常用的测量单位之前，我们想要强调两个单位，因为它们的流行度令人印象深刻，它们是：**vw**（视口宽度）和 **vh**（视口高度）。

这些视口单位在大多数常用的浏览器中仍然不太受欢迎，但我建议您随时关注[`www.w3.org/TR/css3-values/`](http://www.w3.org/TR/css3-values/)或[`caniuse.com/viewport-units`](http://caniuse.com/viewport-units)，因为这些单位使得根据浏览器大小调整字体大小的比例更加容易。

因此，最近最常用的相对单位在下一节中给出。

## 相对单位 – 百分比

百分比是相对于容器元素的，它更多用于创建结构，正如我们在第二章中所学到的 *设计响应式布局/网格*。然而，使用它设置我们的字体大小也没有问题。示例代码如下：

```js
body {
  font-size: 100%;  /* base 16px /*
}
p {
  font-size: 87.5%; /* 14px ÷ 16 */
}
```

一些开发人员更喜欢将正文的字体大小定义为固定的 62.5%（10 px）以便计算。在这种情况下，我们可以将子元素定义为 150% 代表 15 px，190% 代表 19 px，依此类推。虽然这种方法使得识别相应值更容易，但它可能只有在字体大小的第一级级联中有所帮助。

## 相对单位 – em

em 单位是相对于其父元素的计算字体大小。在下面的示例中，我们想要将子元素的字体大小转换为`20px`：

```js
body {
  font-size: 1em; /* base 16px /*
}
p {
  font-size: 1.25em; /* 20px ÷ 16 */
}
```

有一个非常好的网站帮助我们进行这个计算，[`pxtoem.com`](http://pxtoem.com)。让我们看看如何在以下截图中的组件上使用此工具；在左列中，我们定义基础字体，结果显示在中间的列中。此外，对于从 6px 到 24px 的不同尺寸，我们可以使用右列进行转换。

![相对单位 – em](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_04_01.jpg)

因此，请记住，在最终值前（当我们进行转换时）始终包含 px 值（正如我们在第二章中推荐的那样，*设计响应式布局/网格*）。我们强调这个提示，因为在处理字体大小时，有很多层叠样式。例如，考虑以下图：

![相对单位 – em](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_04_02.jpg)

## 相对单位 – rem

**rem** 来源于 CSS3，代表**根 em**，相对于根元素（或 HTML 元素）。换句话说，在`<html>`元素上重新定义字体大小，所有的 rem 单位都可能按比例缩放此基本元素，而不是其父元素。与 em 相比，这是唯一的区别。

让我们看看如何将前面图中的这些尺寸转换为 rem：

```js
body {
  font-size: 1em; /* base 16px /*
}
section,
section li strong {
  font-size: 14px; /*  fallback for IE8 or earlier  */
  font-size: 0.875rem; /* 14px ÷ 16 */
}
section li {
  font-size: 12px; /* fallback for IE8 or earlier  */
  font-size: 0.750rem; /* 12px ÷ 16 */
}
```

下面的做法可能节省大量时间，并有助于分析页面是否需要根据内容密度增加更多的空白空间。

尝试在所有主要结构开发之前编写文本排版的文档。我们通过生成包含所有主要 HTML 元素的模板文档，其中包含基于网站设计的正确样式表，来实现这一点。

# 使用 box-sizing 属性改进元素尺寸

所谓的**盒子模型**，如下面的屏幕截图所示，需要计算以找出包括边框和填充在内的元素的总宽度，现在已经过时了：

![使用 box-sizing 属性改进元素尺寸](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_04_08.jpg)

下面的示例显示了将有用区域分为两个带有每个容器边距百分比为 5％和 2px 边框的 div 的概念，这将使宽度计算更加困难：

```js
div.splitted {
  padding: 0 5%;
  border: 2px solid black;
  float: left;
  width: ?; /* real value= 50% - 10% - 4px */
}
```

在 CSS3 中，我们有`box-sizing`属性，其值为`border-box`，意味着此宽度值已经考虑了填充和边框尺寸。虽然在 Internet Explorer 浏览器的 8 版本及更高版本中运行良好，但该属性在 IE6 和 IE7 上并不完全有效。如果您需要为这些浏览器提供支持，有一个补丁可以完成这个补充任务，可以在[`github.com/Schepp/box-sizing-polyfill`](https://github.com/Schepp/box-sizing-polyfill)找到。

让我们看看它如何简化整个计算，以便在这个示例上工作：

```js
div.splitted {
  padding: 0 5%;
  width: 50%;
  border: 2px solid black;
  float: left;
}
```

我们可以看到在下面的代码中，我们可能在执行计算和分析屏幕上的干净或空白空间时更少遇到困难。此外，许多人将这种 `padding` 间距与 em 基于字体大小相关联，因为在某些情况下它可以避免比例计算。

```js
div.splitted {
  padding: 0 0.5em;
  width: 50%;
  border: 2px solid black;
  float: left;
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box;
}
```

目前，一些浏览器需要上述前缀，但通过这种方式使用它们，我们已经覆盖了它们。此外，同样的填充可能也适用于垂直间距；例如，请考虑以下代码：

```js
div.splitted {
  padding-top: 1em;
}
```

# 为了创建美丽的响应式标题，定制字体系列

字体允许您为用户创建更吸引人的网站，并始终保持主题风格，而无需制作大量标题图像，每个标题都有一个。

### 提示

选择字体非常重要，因为它可能会影响用户对内容的吸收，或者可能无法展示我们工作的一页或两页以上。

`@font-face` 是一个 CSS 规则，允许设计师使用未安装在用户机器上的非标准网络字体，并帮助快速更改所有标题。`@font-face` 方法的重大好处是它不会用图像替换常规字体，并且还为响应式网页设计提供所需的灵活性。

### 提示

`@font-face` 只支持使用 EOT 字体的 IE8 或更早版本。此外，Safari iOS 4.1 及更低版本仅支持 SVG 字体。我们将在下一个主题中看到如何轻松提供此支持。

我们真的推荐访问[`www.google.com/fonts`](http://www.google.com/fonts)这个网站，以查看各种字体，尤其是字体的作者。请在使用之前阅读每种字体的许可证，确保可以商业使用。

属性 `@font-face` 的基本用法是定义这个规则样式，`font-family` 是以后调用字体的标签，`src` 是字体的位置，以及 `font-weight`（对于普通字体不需要，但对于其他一切，如粗体和细体，都是必需的）。例如，请考虑以下代码：

```js
@font-face {
  font-family: "Kite One";
  src: url(/fonts/KiteOne-Regular.ttf);
}
```

然后，只需像其他样式规则中的任何其他字体一样使用它：

```js
p {
  font-family: "Kite One", Helvetica, Arial, sans-serif;
}
```

然而，还有其他更好的方法。我们将清楚地看到如何使用 Font Squirrel、Fit Text、Slabtext、Lettering 和 Responsive Measure。

## 使用 Font Squirrel 工具生成

Font Squirrel 有一个很棒的工具，允许我们获取桌面字体文件并生成其网络对应物。此外，为我们特定字体生成正确代码和文件的服务是完全免费*。

*只有服务是免费的。请记住，每个字体系列都有自己的许可证。强烈建议用户在使用之前阅读字体许可证。

在网站 [`www.fontsquirrel.com/tools/webfont-generator`](http://www.fontsquirrel.com/tools/webfont-generator) 上，我们可以找到关于其主要特性的更多信息，这些特性包括：

+   Font Squirrel 不需要很多 CSS 技能

+   它提供了一个额外的区域来提高加载性能（**专家**模式）

+   生成的代码/文件支持使用旧浏览器的用户

+   资源工具包完全免费

### 操作方法

首先访问 Font Squirrel 网站，然后点击 **添加字体** 以选择您的个人字体或已经拥有正确许可的字体。然后，选择 **基本** 选项（暂时），并下载您的工具包。

在解压下载的文件后，我们应该在 CSS 文件的开头添加以下代码。以下代码将允许 CSS 文件访问字体文件，并根据情况提供正确的字体：

```js
@font-face{
  font-family: 'kite_oneregular';
  src: url('kiteone-regular-webfont.eot');
  src: url('kiteone-regular-webfont.eot?#iefix') format('embedded-opentype'),
  url('kiteone-regular-webfont.woff') format('woff'),
  url('kiteone-regular-webfont.ttf') format('truetype'),
  url('kiteone-regular-webfont.svg#kite_oneregular) format('svg');
  font-weight: normal;
  font-style: normal;
}
```

每当我们想要使用新字体时，只需像使用 `@font-face` 规则一样调用它，如下面的代码所示：

```js
p {
  font-family: 'kite_oneregular', Helvetica, Arial, sans-serif;
}
```

如果我们回到下载页面，Font Squirrel 还将允许您获取字体的子集，通过选择 **优化** 和 **导出** 模式显著减小文件大小。为了展示这种显著性，我们添加了相同的 Kite One 字体，并尝试了所有三种设置。总结结果，字体文件中的字形（字符）的哈希直接与字节大小相关，并且我们想要添加多少资源。

**基本** 设置保留字符不变。 **优化** 设置将字符减少到大约 256 个。在某些情况下，Kite One 字体的字符少于这个数字时，不会进行优化。

通过选择 **专家** 模式并仅包括 **基本拉丁** 设置，然后手动添加我们需要的字符，我们可以看到最大的节省。

让我们尝试一起按照 **专家** Font Squirrel 设置的步骤来做：

1.  点击 **添加字体**，选择要使用的字体文件。

1.  在 **渲染** 下，取消选中 **修正垂直度量**。

1.  在 **字体格式** 下，如下截图所示，选择 **SVG** ：

1.  在 **子集** 下，勾选 **自定义子集...**。

1.  在 **Unicode 表** 下，仅选择 **基本拉丁**。

    ### 提示

    这假设字体只使用英文字符；对于其他语言，请仅添加您需要的字符。

    在某些网站上，诸如 **’**、**‘**、**“** 和 **”** 等符号也很重要，因此将它们复制并粘贴到 **单个字符** 字段中，如下图所示：

    ![操作方法](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_04_10.jpg)

1.  验证 **子集预览** 中生成的图像，如果需要可以进行调整。

1.  在确认您上传的字体符合网络嵌入的合法资格后，只需点击 **下载您的工具包**。

## FitText 插件

FitText 是一个使字体大小灵活的 jQuery 插件，它是一个越来越受欢迎的实用程序，使得灵活的显示类型更加易于使用。它通过缩放标题文本以填充父元素的宽度来工作。如果您想要快速演示此插件，以分析其灵活性有多惊人，您可以在插件网站 [`fittextjs.com/`](http://fittextjs.com/) 上查看其使用情况。

### 操作方法

在插件的 Github 网站[`github.com/davatron5000/FitText.js`](https://github.com/davatron5000/FitText.js)上下载此解决方案的文件后，让我们将以下代码插入到我们的 HTML 中：

```js
<h1 id="responsive_headline">My title using FitText</h1>
```

在 HTML 的底部（在`</body>`闭合标签之前），我们需要添加 jQuery 和 Fittext 库。然后，您必须执行应用于您的标题的插件：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.fittext.js"></script>
<script>
  $("#responsive_headline").fitText();
</script>
```

默认情况下，插件将设置字体大小为元素宽度的 1/10。有两种修改此标准字体大小控制的方法：配置压缩器和定义最小和最大尺寸。

通过使用压缩器，您将需要指定压缩值，例如，`1.2`可以更缓慢地调整文本大小，或者`0.8`可以更少地调整文本大小，如以下代码所示：

```js
<script>
$("#responsive_headline").fitText(1.2);
</script>
```

我们还可以通过定义最小和最大字体大小来修改此标准字体大小控制，以便在希望保留层次结构的情况下提供更多控制，如以下代码所示：

```js
<script>
$("#responsive_headline").fitText(1,{ minFontSize: '20px', maxFontSize: '40px' });
</script>
```

## SlabText 插件

SlabText 是一个插件，可以让您构建大、美丽且完全响应式的标题，从而使任何人都能够制作大、粗体且响应式的标题变得更容易。该脚本在调整每一行以填充可用的水平空间之前将标题拆分为行。每行设置的理想字符数通过将可用宽度除以像素字体大小来自动计算。

以下是其特点：

+   SlabText 插件完全响应式，并为具有完全响应式特性的手机而构建

+   **颜色控制** 选择部分的背景颜色、文本和文本阴影颜色

+   **额外选项** 设置一些填充，并确定文本阴影的长度和 **图像叠加** 通过 CSS3 背景剪辑上传图像并将其叠加到文本上

+   **字体控制** 选择您自己的字体，并对字体拥有最终控制权

+   **可克隆的** 根据需要克隆部分，并创建一大堆克隆

+   SlabText 插件允许您手动换行

+   它的压缩版本仅有 4 KB

+   它具有大量水平空间的标题，以在各种浏览器中更好地填充显示器

+   请务必在下载所有`@font-face`字体之后调用该脚本

因此，让我们从[`github.com/freqDec/slabText/`](https://github.com/freqDec/slabText/)下载此插件并进行实验。

### 如何操作

首先，我们需要为`header`标签添加一个 ID，以便在 JavaScript 中选择，然后在 HTML 代码的闭合`</body>`标签之前插入`<script>`标签。请考虑以下示例：

```js
<header>
  <h1 class="page-title">Linux commands: New users adds new users... fast & furious!</h1>
</header>
```

以下是提出解决方案的脚本：

```js
<script>
$(".page-title").slabText();
</script>
```

但是，与其保持自动化不如将行分解为不同的部分，修改用户感知和我们网站之间的通信：

```js
<header>
  <h1 id="specific-title"></h1>
</header>
```

脚本如下：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.slabtext.min.js"></script>
<script>
var stS = "<span class='slabtext'>",
    stE = "</span>",
    txt = [
      "Linux commands:",
      "Newusers",
      "adds new users...",
      "fast & furious!"];
$("#specific-title").html(stS + txt.join(stE + stS) + stE).slabText();
</script>
```

以下屏幕截图显示了两种状态，在运行强制手动换行代码之前（左侧）和之后（右侧）：

![如何做](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_04_04.jpg)

若要了解更多选项，请访问创建者的页面[`freqdec.github.io/slabText/`](http://freqdec.github.io/slabText/)。

## Lettering

Lettering 通过包装每个字符、单词或行，并添加一个类（创建一个可管理的代码）来提供完整的字母控制，以便快速访问 CSS 文件中的字符。它是一个基于 jQuery 的插件，可以更轻松地调整字符之间的间距，创建编辑设计等。

有两个相当令人印象深刻的网站，通过使用定制字母展示出良好的设计和大量的创意。请看以下示例，由[`lostworldsfairs.com/moon/`](http://lostworldsfairs.com/moon/)和[`lostworldsfairs.com/eldorado/`](http://lostworldsfairs.com/eldorado/)提供：

![Lettering](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_04_05.jpg)![Lettering](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_04_06.jpg)

### 如何做

从[`github.com/davatron5000/Lettering.js`](https://github.com/davatron5000/Lettering.js)下载 zip 文件后，让我们通过插入以下简单的 HTML 代码来练习使用这个工具，该代码将在稍后使用的类中使用：

```js
<h1 class="fancy-title">Page Title</h1>
```

然后，请记住在`<head>`标签中包含 jQuery 库，如下代码所示：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.lettering.js"></script>
```

在 HTML 底部（在`</body>`关闭标签之前），我们需要调用此脚本以指定此插件将影响哪个类：

```js
<script>
  $(document).ready(function() {
    $(".fancy-title").lettering();
  });
</script>
```

之前的代码将产生以下输出。看一下这些 span 并想象一下你在没有这个插件的情况下是如何构建它的：

```js
<h1 class="fancy-title">
  <span class="char1">P</span>
  <span class="char2">a</span>
  <span class="char3">g</span>
  <span class="char4">e</span>
  <span class="char5"></span>
  <span class="char6">T</span>
  <span class="char7">i</span>
  <span class="char8">t</span>
  <span class="char9">l</span>
  <span class="char10">e</span>
</h1>
```

现在，结构已经准备好接收这样的样式：

```js
<style type="text/css">
  h1 { font-family: 'Impact'; font-size:50px;
    text-transform:uppercase; text-shadow: 1px 1px 2px #666; }
  .char1, .word1, .line1 { color: purple; }
  .char2, .word2, .line2 { color: orange; }
  .char3, .word3, .line3 { color: yellow; }
  .char4, .line4 { color: blue; }
  .char5 { color: green; }
  .char6 { color: indigo; }
  .char7 { color: violet; }
  .char8 { color: gold; }
  .char9 { color: cyan; }
  .char10 { color: lime; }
</style>
```

此外，如果标题每个词（而不是字符）都有不同的样式，此插件可以通过定义参数`"words"`来处理，如下代码所示：

```js
<script>
  $(document).ready(function() {
    $(".fancy-title").lettering("words");
  });
</script>
```

考虑使用`<br />`分割每行的不同样式的情况如下：

```js
<h1 class="fancy-title">Page Title <br /> with long text</h1>
```

对于前面的场景，在脚本中唯一的区别将是参数`"lines"`：

```js
<script>
  $(document).ready(function() {
    $(".fancy-title").lettering("lines");
  });
</script>
```

因此，现在我们认为您想知道为什么要付出如此大的努力来创建一个样式，来测量距离，以及知道为每个元素增加多少字体是必要的。我们强烈建议使用在线工具 Kern.js。

### Kern.js 工具

Kern.js 是一个在线工具，与 Lettering.js 完美匹配，因为它提供了一个很好的界面，可以通过点击和拖动来调整字母间距、行高和字母位置。当你完成这项任务后，只需复制生成的 CSS 并在我们的样式表中使用即可。

### 如何使用

进入该工具的网站[`www.kernjs.com/`](http://www.kernjs.com/)后，在页面底部有一个链接：**拖动到书签栏以安装**。将其拖到书签栏将使在我们的网站上激活 Kern.js 工具更加容易。

使用该功能的要求包括在网站的`<head>`标签中包含特定版本 1.7.2 的 jQuery 和 Kern.js 库。Kern.js 脚本可在[`github.com/bstro/kern.js`](https://github.com/bstro/kern.js)下载。

```js
<script src="img/jquery-1.7.2.min.js"></script>
<script src="img/kern.min.js"></script>
```

当通过书签栏中的**Kernjs.com**链接打开网站时，可能会显示五个选项在页面顶部：

+   字距调整（水平间距）

+   字体大小的增加或减少

+   调整行高（垂直间距）

+   完全的字母放置调整

+   调整角度旋转

以下截图显示了这些选项：

![如何使用它](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_04_07.jpg)

一旦完成调整，只需点击检查按钮，将此视觉更改转换为准备复制并在站点上执行的代码。

当存在多个自定义元素时要小心，因为此代码可能会覆盖前一个。然而，有一种简单的方法可以避免进一步的问题：为元素规范定义一个类。以下代码是这种情况的一个示例：

```js
<h1 class="fancy-title">Page Title</h1>
```

## 响应式测量

Responsive Measure 是一个简单的脚本，允许您传入一个选择器（最好是您的主要内容将放置的容器），该选择器生成生成理想测量所需的理想字体大小，以便您的文本。听起来像是魔法吗？我们将在以下部分中看到如何定制此解决方案及其用法。

### 如何做到这一点

从[`github.com/jbrewer/Responsive-Measure`](https://github.com/jbrewer/Responsive-Measure)下载此解决方案的文件后，让我们将此代码插入到 DOM 开头的`<head>`标记中：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.rm.js"></script>
```

在 HTML 底部（在`</body>`结束标记之前），我们需要调用 Responsive Measure 脚本以执行操作。但是，在执行脚本之前，我们将澄清以下两种控制文本大小的方式：

+   **idealLineLength**：其默认值为`66`，但我们可以定义我们自己的特定值来表示一行中可以容纳多少个字符和空格。此外，最小字体大小设置为`16px`，最大设置为`300px`。参数`sampleText`可以帮助计算具有平均字符宽度的字符数。

    ### 提示

    要记住，每行 45-75 个字符的范围通常被认为是舒适阅读的安全范围。

    这里是前面提到的代码：

    ```js
    <script>
    $('section').responsiveMeasure({
      idealLineLength: 45,
      minimumFontSize: 16,
      maximumFontSize: 300,
      sampleText: "n"
    });
    </script>
    ```

+   **minimumFontSize 和 maximumFontSize**：通过将最小值定义为 13 和最大值定义为 30，例如，来改进字体大小的处理。此外，默认值`idealLineLength`有时可能会对结果产生一些影响。如果发生这种情况，请定义您自己的值并进行修复，就像我们刚刚在前面的代码中看到的那样。

    所以，以下是代码：

    ```js
    <script>
    $('section').responsiveMeasure({
      minimumFontSize: 13,
      maximumFontSize: 30,
      sampleText: "n"
    });
    </script>
    ```

# 练习 4 – 自定义主页标题

让我们分三步完成这个练习。第二步和第三步只是第一步的补充：

1.  使用 Font Squirrel 生成器创建您的字体面套件。然后，将其实现在您网站的`<h1>`标记上。如果您不知道要使用哪种字体，我建议您从 GoogleFont 网站下载 Kite One 字体。

1.  使用 Lettering 插件可以更好地控制标题的每个字母、单词或行。之后，增加第一个字母的颜色，将`.char1`类的`color`属性从你的 CSS 文件中修改。

1.  点击书签栏上的链接使用 Kern.js 工具。之后，点击工具栏上的第二个按钮，并选择第一个字母以增加其字体大小。然后，点击最后一个按钮生成代码并将其包含在你的 CSS 文件中。

# 概要

在本章中，我们已经看到了文本的响应式字体大小。此外，我们已经学会了通过使用 Font Squirrel、FitText、SlabText、Lettering 和 Responsive Measure 等解决方案来定制字体族的不同方法。这些解决方案为我们构建响应式网站时所需的图像支持和独立性提供了支持。

在下一章中，我们将讨论图片和视频，并学习如何将它们转换为适应不同设备的响应式和自适应媒体。此外，我们将看到如何考虑不同的播放器技术和设备来有效地处理视频。
