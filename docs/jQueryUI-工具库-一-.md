# jQueryUI 工具库（一）

> 原文：[`zh.annas-archive.org/md5/83BC153BFE50FD00C8D178D0546D71E6`](https://zh.annas-archive.org/md5/83BC153BFE50FD00C8D178D0546D71E6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

> "让我们面对现实吧——你真的需要在你的网站上拖放、可调整大小的窗口或可排序的列表吗…？"

如果答案是否定的，那么欢迎使用"jQuery Tools UI 库"！

jQuery Tools 是一个紧凑、功能强大的库，包含足够的组件来为任何网站提供最重要的功能。许多 UI 库包含大量组件，如列表框、范围、可排序列表等等。尽管这些可以用于构建各种在线应用程序，在公司内部网络中非常有用，但在构建普通网站时却不是很有用。

网站被设计用来呈现信息和外观良好——jQuery Tools 的设计旨在增强任何使用它们的网站，同时利用现代 JavaScript 技术所能提供的强大功能。使用 jQuery Tools，您不受任何预定义的 HTML、CSS 结构或严格的编程规则的约束——您可以将库包含在您的页面中，并立即开始使用其功能。这些工具被设计成可根据您的喜好进行定制，同时保持组成 JQuery Tools 核心功能。

如果你是 jQuery Tools 的新手，并且想要探索可用的功能，这本书就是为你准备的。通过简单易懂的逐步说明，你将找到启动使用这个库所需的一切，并发现如何只需几行代码就能实现一些复杂功能。

那么让我们开始吧...

# 本书涵盖的内容

第一章, *入门 jQuery Tools UI 库*，向读者介绍了这个被称为"缺失的 Web UI 库"的库。它解释了如何获得 jQuery Tools，概述了您将需要使用此功能开发网页所需的工具，并概述了一些在使用 jQuery Tools 时的最佳实践。

第二章, *与你的 UI 工具相处*，深入探讨了 jQuery Tools UI 库的每个部分，以及如何将基本工具实现到您的网站中。在 UI 库的每个部分中，都包含了一次性演示，以及使用该库可以实现的更高级的示例。

第三章, *表单工具*，介绍了 jQuery Tools 中的表单功能。它概述了如何提交和验证表单中的内容，以及如何使用`RangeInput`输入数字和使用`DateInput`输入日期。它还演示了如何确保所有内容都按照 HTML5 标准正确验证。

第四章，*jQuery 工具箱*，介绍了一小部分工具，这些工具在大多数情况下可以单独使用，也可以作为库中主要工具的一部分。它指出，尽管一些技术正在过时（由于 HTML、CSS3 和 JavaScript 的现代进步），但它们仍然可以在项目中执行一些有用的功能。

*在 WordPress 中使用 jQuery 工具* 是 Packt 网站上可供下载的额外 PDF，它附带在本书中。其中包含一些有关在内容管理系统的限制下使用 jQuery 工具的有用想法和示例。尽管示例是基于著名和流行的 WordPress™ 系统，但这些原则也可以轻松地应用于其他类似的系统。

# 这本书适合谁？

对于 jQuery 工具库的新手来说，这本书非常适合。假设你对该库没有任何先前知识，但可能有基本的 JavaScript 语法和概念知识。本书将使您掌握使用该库的基础知识，并了解如何使用它来构建引人注目、可定制的网页。

# 约定

在这本书中，你会发现一些不同种类信息之间的文本样式。以下是这些样式的一些示例，以及它们的含义解释。

文本中的代码字词显示如下："我们现在将构建一个名为 `myEffect` 的自定义效果，然后将其添加到叠加代码中。"

代码块设置如下：

```js
<!-- first overlay. id attribute matches our selector -->
<div class="simple_overlay" id="mies1">
<!-- large image -->
<img src="img/barcelona-pavilion-large.jpg" />
<!-- image details -->
<div class="details">
<h3>The Barcelona Pavilion</h3>
<h4>Barcelona, Spain</h4>
<p>The content ...</p>
</div>
</div>

```

当我们希望引起您对代码块的特定部分的注意时，相关行或项将以粗体显示：

```js
<!-- first overlay. id attribute matches our selector -->
<div class="simple_overlay" id="mies1">
<!-- large image -->
<img src="img/barcelona-pavilion-large.jpg" />
<!-- image details -->
<div class="details">
 <h3>The Barcelona Pavilion</h3>
<h4>Barcelona, Spain</h4>
<p>The content ...</p> 
</div>
</div>

```

**新术语**和**重要词汇**以粗体显示。屏幕上看到的字词，比如菜单或对话框中的内容，会以这种方式出现在文本中："点击**下一步**按钮将您移到下一个屏幕。"

### 注意

警告或重要提示会以这样的框形式出现。

### 提示

贴士和技巧会以这种形式出现。


# 第一章：入门

如果您在过去几年里构建了网页或使用 HTML 开发了网站，您很可能听说过 jQuery——也许您没有听说过 jQuery Tools。

全球的网络专业人士一直在努力使互联网变得更易用，他们使用 JavaScript 来试图克服 HTML 和 CSS 的一些缺点。jQuery 的力量和灵活性在于其看似简单的复杂性，使得浏览文档、选择页面元素和处理事件变得简单明了，同时消除了任何浏览器的差异。互联网上有许多基于 jQuery 的 UI 库可用。jQuery Tools 就是其中之一——虽然许多库旨在提供各种各样的功能，但 jQuery Tools 旨在提供在普通网站上最有用的功能，换句话说，不是基于 JavaScript 应用程序的站点。它的小尺寸掩盖了其强大和灵活性，在仅 4 KB 的空间内提供了大量功能。

在本章中，我们将学习：

+   jQuery Tools 的一点历史，以及其一些指导原则

+   如何下载和安装库，或者使用 CDN 链接

+   编写事件和使用 API 的一些最佳实践

那么，让我们开始吧...

# jQuery 工具的基础知识和规则：入门指南

> “面对现实吧——你真的需要拖放、可调整大小的窗口或可排序的列表吗…？”

如果答案是否定的，那么欢迎来到 jQuery Tools！jQuery Tools 旨在提供许多 Web 2.0 中常见的好用功能，可根据您的需求进行扩展、定制和样式化。工具的主要目的是提供一个功能的基本框架，只提供所需的功能，而不提供其他功能——API 框架可以用来以各种方式扩展工具。有了这个目标，让我们更详细地了解一下 jQuery Tools 的理念。

## HTML 的作用

jQuery Tools 库设计时具有高度的灵活性，可以逐步增强普通网站的功能，同时仍允许不支持 JavaScript 的浏览器。在使用工具集时，您不受任何特定 HTML 结构的限制；您可以自由地随意使用任何适当的元素，比如`ul, ol, div`或`dl`。了解您正在做什么，以及如何为特定需求选择正确的元素是至关重要的。同样可以使用根元素，比如`div`，虽然这并非强制性的。例如，您可以有一个包含 HTML、图片、表单和 Flash 对象的叠加信息的根元素。

## JavaScript 和 jQuery 的作用

尽管 JQuery Tools 库是使用 jQuery 构建的，但除了 FlashEmbed 之外，使用这些工具并不是使用 jQuery 的先决条件。虽然您可以在不需要任何 jQuery 先验知识的情况下使用这些工具，但它可以帮助扩展或增强库中的功能，以及在您的网站上。如果您想更深入地了解如何使用 jQuery 与工具，那么一个有用的起点是查看选择器和对象文字，例如以下示例：

```js
// two jQuery selectors and a configuration given as an object literal
$("#content ul.tabs").tabs("div.panes > div", {
// configuration variables
current: 'current',
effect: 'fade'
});

```

前述代码可以分为两部分——第一部分选择所有具有`tabs`类名的`ul`元素，这些元素包含在名为`content`的`div`中，类似于 CSS 的方式。然后，`tabs`功能设置为在直接包含在具有 CSS 样式类`panes`的`div`中的所有 div 元素上运行。在配置任何工具时，您可以使用类似的语法格式，尽管在键入正确数量的括号时要小心！无论您使用哪种工具，都需要将任何脚本包含在`$(document).ready()`块中，以便在适当的时间加载脚本——您可能会发现将脚本加载到网站的页脚中更可取（对于某些工具是必需的）。

## CSS 的角色

jQuery Tools 旨在允许网站设计者将代码从主要“块”中抽象出来，放入单独的样式表中。您会注意到，在可能的情况下使用了 CSS 样式名称。这使得代码的样式更加灵活，因为可以随意更改样式，而无需更改主要代码——尽管将 CSS 样式与 JavaScript 或 HTML 代码混合在一起并不是一种推荐的做法。例如，您可以在`tabs:`中为活动选项卡的实例设置样式。

```js
$("ul.tabs").tabs("div.panes > div", {current: 'active'});

```

之后，您可以使用以下 CSS 样式设置当前选项卡：

```js
ul.tabs .active {
color: '#fff';
fontWeight: bold;
background-position: 0 -40px;
}

```

这使您完全控制一个`tabs`实例的外观，甚至可以更改所使用的默认样式名称。如果您已经有现有的样式，否则会产生冲突，或者需要遵循特定的 CSS 命名约定，这将非常有用。

### 提示

jQuery Tools 网站托管了许多演示，其中包含可供您使用的 CSS 样式文件——值得查看这些内容，以了解有关样式工具基础知识的情况。所有演示都有完整的文档说明，并使用良好的 CSS 样式规范。

### 使用工具进行图形设计和演示

作为使用 jQuery Tools 的开发人员，您在网站样式设计方面拥有很高的自由度。这意味着您可以在设计中使用纯 CSS、图像，或两者混合使用。

#### 基于 CSS 的设计

在设计中使用纯 CSS 意味着对图片的依赖减少了，因为大多数（如果不是全部）的样式都可以通过纯 CSS 来处理。这在 CSS3 出现后尤其明显，CSS3 可以处理背景中的渐变等样式，而不需要图片。然而，这意味着虽然页面轻量且易于维护，但仅仅使用 CSS 并不能实现一切，至少在版本 2 之前是这样。CSS3 的出现开始改变这一点，尽管你最新的令人惊叹的设计可能在旧版浏览器中无法工作！

#### 基于图像的设计

如果图片更适合你的风格，那么最好的方法是使用图像精灵，这是 jQuery Tools 中的首选方法。精灵可以使用 CSS 精确定位，并且只要使用了适当的图像格式，它们将在大多数（如果不是全部）浏览器中显示。这使你能够实现完全符合你要求的外观和感觉，而不需要妥协，尽管这会使页面变得更重，并且如果在工具中有大量内容（比如悬浮层）时可能会更多地使用滚动条。

#### CSS 和基于图像的设计

这种方法让你兼顾了一切——CSS 可用于保持页面下载速度低，而在 CSS 样式在你的环境中不适用时，可以使用图片。jQuery Tools 在其演示中同时使用了两者，你在自己的设计中同样可以自由使用两者，无需对 CSS 编码进行限制或使用框架的要求。

# 使用开发工具

为了完成本书中的练习，你将需要一个文本编辑器。大多数 PC 都会自带一个——通常是 Microsoft Windows 上的记事本，或者 Mac OS X 上的 TextEdit。实际上有数千种免费或低成本的可用工具，功能各异。

如果你是一名现有的开发者，你可能已经有了自己喜欢的编辑器；对于那些新手来说，可以尝试几种编辑器，看看哪种更适合你。有一些功能我建议你启用或使用：

+   **查看行号：** 在验证和调试你编写的任何脚本时，此功能非常方便。在论坛上请求帮助时，这尤其有帮助，因为其他人可以指出任何有问题的行，并提供修复或解决方法。

+   **查看语法颜色：** 大多数编辑器默认会打开此功能。此功能使用不同的颜色显示代码，有助于识别不同的语法或破损的标记或 CSS 规则。

+   **文本换行：** 这使得编辑器可以将代码行自动换行到下一行，从而减少编辑长代码行时需要滚动的次数。这样做可以更轻松地滚动查看一个良好且正确缩进的代码块。

您可能还需要一个允许您使用 FTP 上传文件或查看本地目录的编辑器。这样可以避免在您的操作系统文件资源管理器中搜索文件，或者使用外部 FTP 应用程序获取文件副本，从而缩短编辑文件所需的时间。要查看实验和样本的结果，您将需要一个浏览器——jQuery Tools 使用 CSS3 样式，因此现代浏览器将提供最丰富和最具设计性的体验。这包括以下内容：

+   Firefox 2.0+

+   Internet Explorer 7+

+   Safari 3+

+   Opera 9+

+   Chrome 1+

所有这些浏览器都可以从互联网免费下载。如果您使用的是 Internet Explorer 或 Firefox，并且尚未安装它们，则强烈建议您还安装或激活所选浏览器的适当开发者工具栏：

+   **IE 开发者工具栏:** 可从 [`www.microsoft.com/download/en/details.aspx?id=18359`](http://www.microsoft.com/download/en/details.aspx?id=18359) 获取。

+   **Firebug:** Firefox 的开发者工具，可以从 [`www.getfirebug.com`](http://www.getfirebug.com) 下载。

+   **Chrome:** 这已经内置，可以通过右键单击元素并选择 **检查元素** 来激活。

+   **Safari:** 您可以在 Safari 的 **高级** 选项卡中激活其开发者工具栏。

+   **Opera:** 您可以从 [`www.opera.com/dragonfly/`](http://www.opera.com/dragonfly/) 下载其开发者工具栏。

在设计使用 jQuery Tools 的站点时，所有这些工具都将非常有助于帮助您调试脚本。

# 下载库

我们需要做的第一件事是从官方网站 ([`www.flowplayer.org/tools`](http://www.flowplayer.org/tools)) 获取 jQuery Tools 库的副本。

jQuery Tools 的模块化特性意味着您可以选择要下载的组件，或者选择下载整个库的副本。如果您希望尽可能使页面轻量化，这一点非常重要。

用于下载 jQuery Tools 库的目的有几个可用选项：您可以使用免费的 CDN 链接（即使用于生产），下载自定义版本，或者从 Github 区域下载未压缩版本。

如果在您的代码中包含此语句：

```js
<script src= "http://cdn.jquerytools.org/1.2.6/jquery.tools.min.js">
</script>

```

您将有以下工具可用：

+   jQuery 1.6.4

+   标签页

+   工具提示

+   可滚动的

+   叠加

无论用户位于地球的何处，工具都将以最佳性能加载。如果您已经在页面中包含了 jQuery，您可以简单地删除它并仅使用脚本的 `src` 语句（因为它已经包含了 jQuery），或者，如果您喜欢，可以插入不带 jQuery 链接的工具，例如：

```js
<script src= "http://cdn.jquerytools.org/1.2.6/all/jquery.tools.min.js">
</script>

```

然后单独引用 jQuery；最佳实践是使用谷歌的 CDN 链接，目前（撰写时）为：

```js
<script src= "http://ajax.googleapis.com/ajax/libs/jquery/1.6.4/jquery.min.js>
</script>

```

## 但我想要更多……使用 CDN 链接

如果你愿意，你可以使用提供的其他 CDN 链接之一来引用 jQuery Tools—CDN 表示 **内容传递网络**，这是一个允许全球快速提供内容的高速网络。

使用这种方法有几个优点：

+   如果你已经访问过使用了 jQuery Tools 的网站，那么它已经被缓存了，这意味着你不需要再次下载它。

+   内容通过世界各地的本地服务器提供，这降低了下载时间，因为你将从最近的服务器获取代码副本。

以下是一些可供你使用的链接，更多的链接可以在 jQuery Tools 网站上找到：

```js
<!-- UI Tools: Tabs, Tooltip, Scrollable and Overlay -->
<script src=
"http://cdn.jquerytools.org/1.2.6/tiny/jquery.tools.min.js">
</script>
<!-- ALL jQuery Tools. No jQuery library -->
<script src=
"http://cdn.jquerytools.org/1.2.6/all/jquery.tools.min.js">
</script>
<!-- jQuery Library + ALL jQuery Tools -->
<script src=
"http://cdn.jquerytools.org/1.2.6/full/jquery.tools.min.js">
</script>

```

为了本书的目的，你应该使用主 CDN 链接，这样我们就可以确保大家都在同一页面上。

# 自定义工具—使用下载构建器

jQuery Tools 的模块化设计允许你为你的项目选择所需的组件。如果你的项目不需要所有组件，那么只下载你需要的组件是一个很好的做法，以减少页面的权重并保持页面响应时间尽可能低。

下载构建器 ([`flowplayer.org/tools/download/index.html`](http://flowplayer.org/tools/download/index.html)) 会将你选择的工具压缩成一个文件—如果需要的话，这个文件中可以包含 jQuery。默认下载（在下页显示）包括主要工具，它们是 **Overlay, Tabs, Scrollable** 和 **Tooltips**—你可以将这些选择更改为仅下载你需要的特定项目的组件。你也可以选择同时包含 jQuery 1.6.4，这有助于减少页面加载时间，正如本章节前面所解释的那样。

## 使用 Firebug

如果你正在使用诸如 Firebug 这样的调试器，你可以通过从控制台运行以下命令来测试包含了哪些工具以及它们的版本：

```js
console.dir($.tools); 

```

你将会看到类似以下截图的内容：

![使用 Firebug](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-tl-ui-lib/img/7805_01_01.jpg)

你可以看到你所包含的每个工具以及其版本号。如果你深入研究这些全局设置，你将会看到每个工具的默认配置值（一个很好的文档来源！），这些值在本章节中的重要部分 *使用全局配置* 中有更详细的讨论。

![使用 Firebug](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-tl-ui-lib/img/7805_01_02.jpg)

## 包含和初始化工具

下一步是在你的页面上包含工具—你可以使用之前显示的其中一个 CDN 链接，或者使用下载构建器包含一个自定义版本。

然后你需要初始化这些工具—它们都遵循相同的模式，以 jQuery 选择器开头，然后是初始化函数（或构造函数），以及它的配置对象。以下是一个使用可滚动工具的示例，其中元素包含在 ID 为 `scroll:` 的元素中：

```js
$("#gallery").overlay({
fixed: true,
closeOnClick: false
})

```

使用 API 格式时，构造函数将始终返回 jQuery 对象，该对象是由选择器选择的元素集合，您可以继续使用它，如下面的代码片段所示：

```js
// return elements specified in the selector as a jQuery object
var elements = $("div.scrollable").scrollable();
elements.someOtherPlugin().Click(function() {
// do something when this element is clicked
});

```

### 使用全局配置

有时候你可能会发现你想要指定一个默认的配置值，这样你就可以避免在代码中重复设置相同的设置。jQuery Tools 有一个全局配置选项，`$.tools.[TOOL_NAME].conf`，它是：

```js
// all overlays use the "apple" effect by default
$.tools.overlay.conf.effect = "apple";

```

这意味着您不需要在 JavaScript 代码中包含它以进行 Overlay：

```js
// "apple" effect is now our default effect
$("a[rel]").overlay();

```

如果需要，您可以进行覆盖：

```js
$("a[rel]").overlay({effect: 'default'});

```

如果您想在全局级别更改多个配置选项，可以使用 jQuery 内置的`$.extend`方法：

```js
$.extend($.tools.overlay.conf, {
speed: 400,
effect: 'apple'
});

```

### 注意

各个工具的文档页面上可以找到各种配置设置的列表。

您可以使用类似于 Firebug 的工具来获取全局配置的更多详细信息，方法是键入以下命令`console.dir($.tools.overlay.conf)`；这将产生类似于此图像的图像：

![使用全局配置](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-tl-ui-lib/img/7805_01_03.jpg)

# 事件和 API 调用的最佳实践

在本节中，我们将查看每个工具的一些最佳实践，包括如何使用 API、编写事件以及使用 jQuery Tools 功能设计插件。

## 应用程序编程接口（API）

随着时间的推移，您会想要通过使用其 API 来扩展您对 jQuery Tools 的技能，该 API 旨在公开库中每个工具的方法和访问属性。API 将内部值隐藏在外部世界中，这是良好的编程实践。

首先，您需要为该工具创建 API 的实例，例如：

```js
//get access to the API
Var api = $("#scroller").data("scrollable")

```

您将注意到传递给`data`中括号的参数是该工具名称的参数，例如可以更改为`overlay`。当您创建了 API 实例后，可以通过调用其方法开始使用它：

```js
//do something upon scroll
api.onSeek(function() {
// inside callbacks the "this" variable is a reference
// to the API
console.info("current position is: " + this.getIndex())
});

```

您可以使用 Firebug 轻松查看 jQuery 工具正在使用的可用 API 方法，它可以作为信息的良好来源：

![应用程序编程接口（API）](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-tl-ui-lib/img/7805_01_04.jpg)

使用 API 意味着您不太可能需要所有 jQuery 的 DOM 方法，因为大多数您需要的方法都可以从工具内部获得。这包括检索信息的方法，以及设置值或调用操作的方法。

您甚至可以将方法链接到工具的 API 实例上，因为该方法将始终返回 API：

```js
// normal API coding that programmers are accustomed to
var index = $("#example").data("tabs").click(1).getIndex();

```

如果您的选择器返回多个实例并且您想要访问特定的 API，则可以执行以下操作：

```js
// select the correct instance with a jQuery selector
var api = $(".scrollable:eq(2)").data("scrollable");
//or with traversing methods. it is just a matter of taste
api = $(".scrollable").eq(2).data("scrollable");

```

## jQuery Tools 事件

在 API 中，每个工具都可以在特定时间点响应事件，这是需要完成某项操作的时刻。一个很好的例子是**Scrollable**—每次你滚动图片时，你都可以触发`onSeek`事件。每次发生这种情况时，你都可以添加自定义响应（或监听器）—如果你想要扩展工具的默认行为，这尤其有用。

### 注意

事件监听器通常被称为**回调**—这两个术语都是同样有效的。

### 在事件之前和之后

你可以为任何工具添加自定义功能，因为它们提供了用于此目的的 before 和 after 事件方法。这些操作也可以使用`onBefore`事件取消，例如在这个例子中，它使用了 tabs 的`onBeforeClick`回调：

```js
$("#example").tabs(".panes > div", {
// here is a "normal" configuration variable
current: 'active',
// here is a callback function that is called before the // tab is clicked
onBeforeClick: function(event, tabIndex) {
// the "this" variable is a pointer to the API. You can do // a lot with it.
var tabPanes = this.getPanes();
/*
By returning false here the default behavior is cancelled. This time another tab cannot be clicked when "terms" are not accepted
*/
return $(":checkbox[name=terms]").is(":checked");$( ":checkbox[name=terms]").is(":checked");
}
});

```

### 提供事件

有三种不同的方法可以提供工具的事件监听器：

#### 在配置中

第一种，也是最简单的选项是将事件监听器直接包含在你的代码中：

```js
$(".tabs").tabs({
// do your own stuff here
onClick: function() {
...
var tabPanes = this.getPanes();
}
});

```

使用这个选项的一个缺点是你无法在代码中指定同一个回调的多个实例。例如，在同一个配置中包含两个不同的`onClick`方法将导致错误。

### 注意

在前面的例子中，`this`变量是对 Tabs API 的引用。

#### 使用 jQuery 的绑定方法

第二种方法遵循了 jQuery 中使用的方法，您可以连续分配多个监听器：

```js
// first callback
$(".tabs").bind("onClick", function() {
// "this" is a reference to the DOM element
var ulElement = this;
...
// another one
}).bind("onClick", function() {
// another one
...
});

```

使用这种方法提供更大的灵活性，因为它允许你在代码中删除特定的事件监听器，或者在同一调用中绑定多个相同事件监听器的实例。在前面的例子中，CSS .tabs 选择器被设置为在任何使用该选择器的标签触发`onClick`事件时执行两个动作。工具还允许你在单个调用中将相同的事件监听器绑定到多个事件触发类型上：

```js
// the same event listener is called before and after
// a tab is clicked
$(".tabs").bind("onBeforeClick onClick", function() {
});

```

强烈建议你尽可能深入地熟悉这个功能，如果你还不熟悉事件绑定—在这个领域有大量的优秀参考资料可供使用。

#### 从 API 中提供监听器

工具还允许你从 API 内部提供一个或多个回调：

```js
// grab the API with jQuery's data method
var api = $(".tabs").data("tabs");
// supply an event listener
api.onBeforeClick(function() {
// supply another
}).onClick(function() {
...
});

```

你可以使用内部的`this`变量作为对任何工具 API 的引用，这样可以让你将多个事件监听器链接在一起；这对于尚未熟悉 jQuery 的开发人员来说更加合适：

```js
// loop through each instances
$(".tabs").each(function() {
...
// assign the onClick listener to a single instance
$(this).data("tabs").onClick(function() {
...
});
});

```

## 事件对象

如果你使用回调，值得注意的是工具遵循当前的 W3C 标准，将`event`对象作为每个回调函数的第一个参数传递：

```js
// the event object is the first argument for *all* callbacks
// in jQuery Tools
api.onClick(function(event) {
/* If you have multiple callbacks of the same type this prevents
the rest of the callbacks from being executed. */
event.stopImmediatePropagation();
...
// retrieve the value returned by the previous callback function
event.result;
event.result;
...
// whether CTRL, ALT, SHIFT, or ESC was being pressed
var alt = event.altKey,
ctrl = event.ctrlKey,
shift = event.shiftMey,
esc = event.metaKey;
...
// this is how to get the original triggering element, such
// as a handle to the scrollable navigator item that was clicked
// inside an onSeek event
var element = e.originalTarget || e.srcElement;
});

```

在 jQuery 工具的范围内，`preventDefault()`与从回调函数返回 false 是相同的；这被认为是取消默认事件的接受实践。

## 创建 jQuery 工具插件

这些工具被设计为与 jQuery 协同工作，这样你就可以创建基于 jQuery Tools 的插件。使用 jQuery，你可以轻松地修改或扩展工具的默认行为，并额外获得使用工具 API、以及使用任意数量的回调函数的好处。举个例子，这里是一个简单的插件示例，它使用 Google Analytics 来跟踪每次选定选项卡时的点击事件：

```js
// create jQuery plugin called "analytics"
$.fn.analytics = function(tracker) {
// loop through each tab and enable analytics
return this.each(function() {
// get handle to tabs API.
var api = $(this).data("tabs");
// setup onClick listener for tabs
api.onClick(function(event, index) {
tracker.trackEvent("tabs", "foo", index);
});
});
};

```

### 小贴士

如果你不熟悉编写 jQuery 插件，你可能会喜欢看看 Giulio Bai 撰写、Packt Publishing 出版的《jQuery 1.4. *插件开发入门指南*》。

在将插件包含到页面后，你可以按照以下方式使用插件，这遵循了开发插件的标准格式：

```js
// initialize tabs and the analytics plugin.
$("ul.tabs").tabs("div.panes > div").analytics(tracker);

```

jQuery Tools 要求先初始化选项卡，然后再初始化分析插件，所以你不能这样写：

```js
$("ul.tabs").analytics(tracker).tabs("div.panes > div");

```

## 使用 jQuery Tools 插件和特效

jQuery Tools 的设计允许你充分利用 jQuery 的链式调用功能，这意味着你可以创建链式模式，比如下面这样的：

```js
// initialize a few scrollables and add more features to them
$(".scroller").scrollable({circular: true}).navigator("#myNavi").autoscroll({interval: 4000});

```

在这里，基本的 Scrollable 调用将任何具有 `.scroller` 类的元素转换为可滚动的元素，而 Tools 的极简设计意味着你可以通过额外的代码或插件来扩展或修改行为，同时保持代码更易读，文件大小更小。最终结果是你可以在页面上设置多个可滚动元素，它们都使用相同的一行代码进行激活，但是包含自己的本地配置值（这也可以是全局的）。这种装饰器的哲学是 jQuery Tools（以及整个 jQuery）的一部分。大多数工具都带有许多可供下载的插件，或者如果需要的话，你也可以添加自己定制的插件。

### 特效

与大多数工具提供的插件体系结合使用，你还可以为某些工具设计自己的效果。这将允许你改变正在使用的工具的默认行为，而插件将用于扩展该行为。例如，你可以添加一个效果来控制叠加层的打开或关闭方式——其中的一个例子就是苹果效果，它带有叠加层：

```js
// use the "apple" effect for the overlays
$("a[rel]").overlay({effect: 'apple'});

```

使用额外效果意味着你可以将代码分离到单独的文件中，这样基础的覆盖代码会更小更有组织。然后你可以进一步创建更多效果，这些效果可以从单独的文件中引用，并根据需要插入到你的代码中。你还可以通过全局配置设置特定效果作为默认效果；这样可以减少在代码中每个实例中指定的需要。你也可以通过配置值实现相同的效果——如果你有一些在效果内部设置的值，你可以将它们设置为全局级别的默认应用，以便在使用此效果的每个实例中应用。例如，你可能在你的效果中设置了 `explosionSpeed` 值——以下代码将其转换为全局配置变量：

```js
$.tools.overlay.conf.explosionSpeed = 500;

```

值得一看的是 [`gsgd.co.uk/sandbox/jquery/easing/`](http://gsgd.co.uk/sandbox/jquery/easing/)，jQuery 缓动插件的主页；那里有许多效果，可以适用于 jQuery 工具。

# jQuery 工具的性能

jQuery 工具的一个关键设计特性，正如雅虎的五条最佳实践所述，是设计师应尽量减少必须下载的图像、样式表和脚本的数量。雅虎认为这是提高站点速度的关键，因为大多数时间花在站点上的是在前端。雅虎创建的五条规则，以及 jQuery 工具所遵循的规则，包括：

1.  减少 HTTP 请求的数量。

1.  尽可能使用 CDN 链接，将脚本合并到你的代码中。

1.  添加一个 `expires` 头。

1.  尽可能使用 GZIP 组件。

1.  通过压缩代码来最小化 JavaScript。

如果你在你的代码中包含以下脚本链接，你将能够遵守这五条规则：

```js
<script src="img/jquery.tools.min.js">
</script>

```

它们可以帮助显著提高你站点的性能，大约提高你网站性能的 70 到 80%！鼓励你使用提供的 CDN 链接，尤其是用于生产；如果你担心文件大小，你应该下载一个仅包含你真正需要的工具的组合脚本，并遵循本章中提到的原则。

## 减少 HTTP 请求的数量

一个好的做法是尽量减少站点中使用的单独 JavaScript 或 CSS 文件的数量——这有助于减少从不同来源获取内容所需的时间。这在 jQuery 工具中是允许的，当下载库的自定义版本或使用 CDN 链接时，它会使用一个组合的 JavaScript 文件。

## jQuery 工具可通过 CDN 获得。

有许多可用于使用的 CDN 链接——使用这些链接可以使效率提高 15 到 20%，与使用手动静态链接相比。

## 添加一个过期头部

JQuery Tools 的所有工具都设置了`expires`头，使它们可缓存；这将使每次访问站点的响应时间减少高达 50%。

## GZIP 组件

如果服务器启用了 gzip 压缩，那么这可以将文件大小减少高达 65%；当服务器启用了 gzip 压缩时，大多数现代浏览器声称能够处理 gzip 压缩。所有通过 CDN 链接提供的 jQuery Tools 下载都经过了 gzip 压缩，以帮助减少下载时间。

## JavaScript 的最小化处理

使用 Google Closure Compiler 对 jQuery Tools 脚本进行最小化处理，以减少文件大小并提高性能，因为这比简单地打包相同文件具有更高的压缩比。

# 摘要

在本章中，我们学习了：

+   jQuery Tools 的基础知识，以及它遵循的一些规则

+   如何下载库的副本或使用提供的 CDN 链接

+   使用 jQuery Tools 时编写事件和 API 调用的一些最佳实践

我们讨论了如何利用 jQuery Tool 的模块化特性，仅下载你项目所需的那些组件。我们还探讨了在设计使用 jQuery Tools 的页面或项目时应遵循的一些规则和最佳实践。

现在我们已经了解了 jQuery Tools 的基础知识和如何安装它，我们准备开始深入使用它，这是下一章的主题。


# 第二章：与您的 UI 工具相处

> "行动胜过言语……"

十六世纪作家米歇尔·德·蒙田经常被引用为发明了这个短语，作者认为这对于 jQuery Tools 来说非常恰当——毕竟，了解新工具的最佳方法就是尝试使用它们，对吗？

在上一章中，我们稍微了解了 jQuery Tools 的整体理念，并且强调了 JavaScript 代码的重要性不如工具的能力，通过更改 CSS 和改变所使用工具的一些配置选项来以多种不同的方式进行样式设置。

现在是时候详细了解这些工具中的一些了——本章（以及下一章）包含了使用各种工具展示的几个项目，并展示了通过使用 CSS 和最少的 JavaScript 可以实现的一些功能。

在本章中，我们将学习如何：

+   使用 Google 地图构建地图灯箱效果。

+   构建一个简单的图库，展示多张图片。

+   构建一个快速链接提示框，以允许购买一本书。

+   在类似拍立得的幻灯片中显示图像。

因此，就像有人曾经说过的那样……"我们还在等什么..?" 让我们开始吧……

### 注意

本章示例中列出的所有图像都包含在随书附带的代码下载中。

# UI 工具——一个模板

在我们详细查看示例之前，让我们先建立每个项目中将使用的基本框架。打开您喜爱的文本编辑器，然后复制以下代码：

```js
<!DOCTYPE html>
<html>
<head>
<title>jQuery Tools standalone demo</title>
<!-- include the Tools -->
<script src=
"http://ajax.googleapis.com/ajax/libs/jquery/1.6.4/jquery.min.js">
</script>
<script src=
"http://cdn.jquerytools.org/1.2.6/all/jquery.tools.min.js">
</script>
</head>
<body>
</body>
</html>

```

将此保存为模板——本书的演示示例使用了类似的格式，因此这将帮助您以后节省时间，当我们查看 jQuery Tools UI 库中提供的其他工具时。让我们从覆盖层开始。

# 什么是覆盖层？

覆盖层是 JavaScript 领域的重要部分——如果您想要引导访问者的注意力到您站点上的特定元素，那么这个工具将会非常有效。覆盖层可以用于显示几乎任何内容，例如不同样式的覆盖层用于显示产品，显示信息或警告框，或者显示复杂信息，所有这些都可以使用 jQuery Tools 的覆盖层来实现。

## 完美的眼睛糖果覆盖层

jQuery Tools 的覆盖层可以包含各种信息，例如视频、图像、地图等——所有内容都可以使用 CSS 进行样式设置。它具有各种功能，例如脚本框架、事件模型（在触发事件时执行操作）以及添加自定义效果。

## 用法

设置覆盖层的一般方式如下：

```js
// select one or more elements to be overlay triggers
$(".my_overlay_trigger").overlay({
// one configuration property
color: '#ccc',
// another property
top: 50
// ... the rest of the configuration properties
});

```

当您单击触发器之一时，它将打开由触发器的`rel`属性指定的覆盖层。

### 小贴士

值得一看的是[`flowplayer.org/tools/overlay/index.html`](http://flowplayer.org/tools/overlay/index.html)，其中详细介绍了覆盖层可用的所有可能配置选项。

让我们看看这在实践中是如何工作的——我们将构建一个简单的地图查看器，它使用 Google™ 地图和覆盖的“苹果”效果。

## 项目：构建 Google 地图的查看器

我们将利用这个概念开发一个灯箱效果，它使用 Google™ 地图，为一个客户提供他办公室位置的地图，但不想只在页面上显示一个简单的地图！

### 创建基本的 HTML 结构

此示例将使用 jQuery Tools 的覆盖工具，但使用的是“苹果”主题。示例中使用的所有图像都可以在附带本书的代码下载中找到。

还记得我们在本章开头设置的代码模板吗？现在复制一份并将其保存为您的覆盖项目文件，这样我们就可以添加覆盖演示的要点了。不过我们会对它做一个小小的改变——将`<body>`标签修改为如下内容：

```js
<body class="no-js">
...
</body>

```

这一点将随着我们演示的进行而变得更加清晰。

### 添加覆盖

接下来，让我们将覆盖触发器和覆盖的代码添加到`<body>`中：

```js
<!-- trigger elements -->
<a href="#link1" rel="#link1">Location of Packt's Office</a>
<!-- overlayed element -->
<div class="apple_overlay" id="link1">
<iframe width="675" height="480" frameborder="0" scrolling="no"
marginheight="0" marginwidth="0"
src="img/maps?q=B3+2PB&amp;hl=en&amp; sll=52.483277,-1.900152&amp;sspn=0.003679,0.009645&amp;vpsrc=0&amp; t=m&amp;ie=UTF8&amp;hq=&amp;hnear=Birmingham,+West+Midlands+B3+2PB, +United+Kingdom&amp;ll=52.484296,-1.90115&amp; spn=0.015681,0.025749&amp;z=14&amp;iwloc=A&amp;output=embed">
</iframe>
<p>Packt's office in Birmingham</p>
</div>

```

这遵循了所需的覆盖和触发器的正常结构，但增加了`<iframe>`标记，以处理外部内容。这里的触发器是`<a>`标记，当点击时，打开地图显示 Packt 办公室的位置，并在覆盖中显示它。

### 设置和配置覆盖的 JavaScript

添加的下一部分是非常重要的脚本——尽管调用覆盖功能的代码只有一行，但我们必须添加一块配置代码块，告诉它使用 expose 来隐藏页面内容，然后显示覆盖本身，并最终找到覆盖 HTML 中给定的 URL，并在屏幕上显示它。

在`</body>`标记之前，将以下代码添加到您的网页底部：

```js
<script>
$(function() {
$("a[rel][href!='']").overlay({
// some mask tweaks suitable for modal dialogs
mask: {
color: '#000',
loadSpeed: 200,
opacity: 0.8
},
effect: 'apple',
onBeforeLoad: function() {
var overlaid = this, overEl = this.getOverlay();
// grab wrapper element inside content
overEl.find(".contentWrap").load( this.getTrigger().attr("href"));
overEl.appendTo("body");
$(".close", this.getOverlay()).click(function(e){
overlaid.close();
});
}
});
});
</script>

```

### 添加样式和视觉效果

最后，我们需要添加一些样式，因为生成的页面看起来并不太漂亮！下面的代码对于显示覆盖是至关重要的，如果您想要不同颜色的覆盖，您可以随时更改使用的背景：

```js
<style>
/* body, a:active and : focus only needed for demo; these
can be removed for production use */
body { padding: 50px 80px; }
a:active { outline: none; }
:focus { -moz-outline-style: none; }
.apple_overlay {
/* initially overlay is hidden */
display: none;
/* growing background image */
background-image: url(white.png);
/* width after animation - height is auto-calculated */
width: 675px;
/* some padding to layout nested elements nicely */
padding: 25px;
margin: 20px;
}
/* default close button positioned on upper right corner */
.apple_overlay .close {
background-image: url(close.png);
position: absolute;
right: -10px;
top: -10px;
cursor: pointer;
height: 35px;
width: 35px;
}
#overlay {
height: 526px;
width: 675px;
}
div.contentWrap {
height: 526px;
width: 675px;
overflow: hidden;
}
a, body {
font-family: Arial, Tahoma, Times New Roman;
}
body.no-js a[rel] {
/* initially overlay is hidden if JavaScript is disabled */
display: none;
}
body.js .apple_overlay {
/* initially overlay is hidden if JavaScript is enabled */
display: none;
}
</style>

```

### 提示

值得注意的是，如果您想要更改背景，jQuery Tools 网站上有一些额外的背景可用于[`flowplayer.org/tools/overlay/index.html`](http://flowplayer.org/tools/overlay/index.html)，或者在附带本书的代码下载中。您也可以自己添加——查看一些网站上的演示，看看如何操作。

注意我们在原始 HTML 标记中使用了 `no-js`？其原因很简单：它保持了渐进增强，这意味着如果有人关闭了 JavaScript，覆盖仍然会隐藏，直到您点击触发链接为止！

现在覆盖将会起作用，您将看到类似于以下图像：

![添加样式和视觉效果](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-tl-ui-lib/img/7805_02_01.jpg)

这只是对覆盖层所能做的事情的皮毛。您可以添加自定义效果，设置为模态对话框显示，甚至显示不同的图像作为您的“覆盖层”，这可能是较小图像的放大版本，比如一本书。

# 工具提示 - 您所需要的唯一的网络基础知识

无可争辩地，第二重要的 UI 小部件是工具提示，其功能与覆盖层类似，因为它可以用于突出显示屏幕上的元素相关的重要信息，例如如何填写表单的提示，购买某物的快速链接提示，或者突出显示有关网站上正在讨论的概念的信息（类似于书籍中的脚注）。jQuery Tools 的工具提示在操作上与其他工具提示没有什么不同，但其设计使其非常强大和灵活。让我们更详细地看一看。

## 使用

工具提示设置非常简单，基本版本使用以下结构：

```js
<!-- elements with tooltips -->
<div id="demo">
<img src="img/image1.jpg" title="The tooltip text #1"/>
<img src="img/image2.jpg" title="The tooltip text #2"/>
<img src="img/image3.jpg" title="The tooltip text #3"/>
<img src="img/image4.jpg" title="The tooltip text #4"/>
</div>

```

注意到工具提示的技巧是，您可以以两种方式之一生成它们，一种是使用`title`属性，另一种是在工具提示触发器之后直接包含工具提示块。

### 提示

最好通过使用`[title]`属性来显示普通文本的工具提示。如果需要显示更多内容，或包含 HTML 格式，则使用手动方法，使用单独的 CSS 样式类或 ID 选择器。

调用工具提示可以非常简单，只需使用选择器元素，通常是包含作为工具提示显示的文本的`[title]`属性：

```js
$("[title]").tooltip();

```

如果您需要显示 HTML 元素，那么可以使用手动格式，它可以包含任意数量的 HTML，但是会在触发器之后立即使用元素：

```js
$(".trigger").tooltip();

```

我们可以进一步添加一些附加选项 - 幻灯片和动态插件。

### 提示

仅使用`[title]`属性并不建议；这将导致性能受到影响，因为 jQuery Tools 需要遍历每个实例，以查看是否应将其转换为工具提示。强烈建议使用样式类或 ID 来改善性能。

## 用幻灯片效果和动态插件打动每个人

标准工具的工具提示将起到作用，但至少存在一个固有限制 - 如果浏览器窗口调整大小会发生什么？默认情况下，工具提示不允许这样做，除非您添加“动态”插件；动态插件将考虑视口的边缘在哪里，并相应地“动态”地定位工具提示。为了获得额外的功能，您还可以让工具提示从顶部、左边、右边或底部滑入，而不仅仅是以相同的方向出现（从底部到顶部）。有关如何设置此附加功能的更多详细信息都可以在网站上找到。

与此同时，让我们来看一个项目，这个项目在书店或出版商的网站上都不会显得格格不入，您可以使用“快速链接”来获取有关书籍的更多信息和价格，以及购买副本。

## 项目：使用工具提示构建一本书的“立即购买”

你知道怎么做，你浏览到一个网站，看到一本你想要的书。你不想深入多个页面，只是为了购买它，对吧？我也是这样想的——输入工具提示的“快速链接”。我们将在悬停在书籍上时弹出一个小提示，这样您就可以直接点击**购买**按钮。

### 提示

所有图片都可作为附带书籍的代码下载的一部分获得，或者直接从 jQuery Tools 网站获取。

### 设置基本 HTML

去获取我们在本章开头设置的 HTML 模板的副本，这样我们就可以复制基本的触发器和工具提示 HTML，以使其起作用：

```js
<!-- trigger element. a regular workable link -->
<a id="download_now"><img src="img/book.jpg"></a>
<!-- tooltip element -->
<div class="tooltip">
<img src="img/book.jpg" />
<p class="bookavail">Book and eBook available now</p>
<dl>
<dt class="label">Book only price:</dt>
<dt class="price">£25.19 save 10%</dt>
<dt class="label">eBook only price:</dt>
<dt class="price">£16.14 save 15%</dt>
<dt class="buynow"><a href="http:///store/purchase?id=12345">
<img src="img/buy_button.png"></a>
</dt>
</dl>
</div>

```

值得注意的是，尽管代码没有连接到电子商务系统，但您可以轻松地进行调整：

```js
<tr>
<td></td>
<td><a href="http:///store/purchase?id=12345">
<img src="img/buy_button.png" /></a></td>
</tr>

```

### 添加工具提示 CSS 样式

现在，关键部分来了——样式。jQuery Tools 遵循最小 JavaScript 编码原则，更愿意让大部分工作由 CSS 完成。工具提示功能也不例外，因此让我们将其添加到`<head>`部分下面的代码中，以查看工具提示的效果：

```js
<style>
.tooltip { display: none; background: url(black_big.png);
height: 145px; padding: 35px 30px 10px 30px;
width: 310px; font-size: 11px; color: #fff; }
.tooltip img { float: left; margin: 0 5px 10px 0; }
.bookavail { margin-top: -5px; color: #f00; font-weight: bold;
font-size: 14px; }
dt.label { float: left; font-weight: bold; width: 100px; }
dt.price { margin-left: 210px; }
dt.buynow a img { margin-top: 10px; margin-left: 110px; }
</style>

```

### 注意

需要注意的是，`.tooltip`类提供了任何工具提示所需的基本 CSS；其余的 CSS 是针对此演示特定的。

#### 不过我们还需要一些样式..！

虽然上面的样式将产生一个可行的演示，但演示效果并不完美；我们需要添加额外的样式来微调一些元素的位置，并调整整体视图。将以下内容添加到您早期的样式表中：

```js
body { margin-top: 100px; margin-left: 200px; }
#booktip img { padding: 10px; opacity: 0.8;
filter: alpha(opacity=80); -moz-opacity: 0.8; }
.bookavail { margin-top: -5px; color: #f00; font-weight: bold;
font-size: 14px; }

```

### 配置工具提示

最后但同样重要的是，这是工具提示工作所需的 JavaScript 代码。这分为三个部分：

+   第一部分配置了屏幕上的工具提示外观

+   第二部分控制工具提示的淡入淡出

+   最后一部分调整了工具提示在屏幕上的位置，以适应当前浏览器窗口的尺寸（即，如果已调整大小或以全屏显示）

    ```js
    <script>
    $(document).ready(function() {
    $("#booktip").tooltip({
    effect: 'slide',
    position: 'top right',
    relative: true,
    // change trigger opacity slowly to 1.0
    onShow: function() {
    this.getTrigger().fadeTo("slow", 1.0);
    },
    // change trigger opacity slowly to 0.8
    onHide: function() {
    this.getTrigger().fadeTo("slow", 0.8);
    }
    }).dynamic({ bottom: { direction: 'down', bounce: true }});
    });
    </script>

    ```

对于一个简单的项目，效果可能非常显著——这是它应该看起来的样子：

![配置工具提示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-tl-ui-lib/img/7805_02_02.jpg)

当使用工具提示时，您可以尽情发挥效果——我曾见过一种效果是悬停在图像上时`div`滑出的效果；这可能看起来有点奇怪，但如果您仔细考虑，它与此处使用的效果相同。它仍然使用了来自 Tools 库的工具提示功能，唯一的区别（突显了 jQuery Tools 的真正威力）是使用的 CSS 样式！

# 对于其他一切——有可滚动的

如果您需要在您的网站上滚动信息，则需要查看 jQuery Tools 中提供的另一个组件：Scrollable。这个工具可以以许多不同的方式使用，例如视频库、产品目录和新闻滚动条——结构基本相同，但 jQuery Tools 的灵活性允许您使用 CSS 的强大功能来产生不同的设计。

## 用法

这是 Scrollable 的基本结构：

```js
<!-- "previous page" action -->
<a class="prev browse left">next</a>
<!-- root element for scrollable -->
<div class="scrollable">
<!-- root element for the items -->
<div class="items">
<!-- 1-3 -->
<div>
<img src="img/image1.jpg" />
<img src="img/image2.jpg" />
<img src="img/image3.jpg" />
</div>
<!-- 4-6 -->
<div>
<img src="img/image4.jpg" />
<img src="img/image5.jpg" />
<img src="img/image6.jpg" />
</div>
<!-- 7-9 -->
<div>
<img src="img/image7.jpg" />
<img src="img/image8.jpg" />
<img src="img/image9.jpg" />
</div>
</div>
</div>
<!-- "next page" action -->
<a class="next browse right">previous</a>

```

你会发现结构由多个图像组成，这些图像被分组在一起，用一些`div`标签包裹，还有额外的`div`标签来管理导航元素。虽然演示仅显示每组三张图片，但如果需要，您可以轻松地向每个组添加更多图片。

为了真正展示这个是如何工作的，让我们看一个例子，这个例子在一个假设的客户网站上并不出格，比如一个摄影师的网站。

## 项目：构建一个迷你画廊

客户有一些需要在他的网站上显示的图片——他希望能够滚动浏览每组图像，然后单击其中一个以在放大的查看器中显示它。听起来很简单，对吧？

### 设置基本的 HTML

要开始，让我们组合基本的 HTML 结构。打开您喜欢的文本编辑器，并粘贴以下内容： 

```js
<html>
<head>
</head>
<body>
<div id="swapframe">
<div id="viewer">
<div class="loadingspin">
<img src="img/loadinfo.gif" alt="Loading..." />
</div>
</div>
<div id="caption">x</div>
<div id="scrollablecontainer">
<a class="prev browse left"></a>
<div id="overscroll">
<div class="items">
<div class="item">
<div>
<a rel="odontoglossum"
href="images/odontoglossum.jpg">
<img src="img/odontoglossum_tn.jpg"
align="middle" />
</a>
</div>
<div>
<a rel="forest orchid"
href="images/forest%2520orchid.jpg">
<img src="img/forest%2520orchid_tn.jpg"
align="middle" />
</a>
</div>
<div>
<a rel="brassia" href="images/brassia.jpg">
<img src="img/brassia_tn.jpg"
align="middle" />
</a>
</div>
<div>
<a rel="paphiopedilum"
href=" images/paphiopedilum.jpg">
<img src="img/paphiopedilum_tn.jpg"
align="middle" />
</a>
</div>
<div>
<a rel="zygopetalum"
href=" images/zygopetalum.jpg">
<img src="img/zygopetalum_tn.jpg"
align="middle" />
</a>
</div>
</div>
<div class="item">
<div>
<a rel="cactus flower"
href=" images/cactus%2520flower.jpg">
<img src="img/cactus%2520flower_tn.jpg"
align="middle" />
</a>
</div>
<div>
<a rel="african violet"
href=" images/african%2520violet.jpg">
<img src="img/african%2520violet_tn.jpg"
align="middle" />
</a>
</div>
<div>
<a rel="pink camelia"
href=" images/pink%2520camelia.jpg ">
<img src="img/pink%2520camelia_tn.jpg"
align="middle" />
</a>
</div>
<div>
<a rel="red camelia"
href=" images/red%2520camelia.jpg ">
<img src="img/red%2520camelia_tn.jpg"
align="middle" />
</a>
</div>
<div>
<a rel="white camelia"
href=" images/white%2520camelia.jpg ">
<img src="img/white%2520camelia_tn.jpg"
align="middle" />
</a>
</div>
</div>
</div>
</div>
<a class="next browse right"></a>
</div>
</div>
</body>
</html>

```

在以前的例子中，我们使用了在本章开头创建的模板文件。这一次，我提供了整个示例，因为这里包含了一些额外的 HTML。我包括了一个加载动画的 GIF，以及一个图像说明的空间。

看起来很复杂，但实际上并不是——它遵循了上面显示的相同结构，但是在 HTML 代码中有一些额外的 DIV 包裹；这主要是为了让我们能够正确地在屏幕上定位结果，同时仍然保持每个元素在正确的位置。

### 时间展现一些 JavaScript 魔法

好的，现在我们已经有了结构，让我们加入 JavaScript 代码。将这两行复制到你的`<head>`区域：

```js
<script src=
"http://ajax.googleapis.com/ajax/libs/jquery/1.6.4/jquery.min.js">
</script>
<script src=
"http://cdn.jquerytools.org/1.2.6/all/jquery.tools.min.js">
</script>

```

这启动了对 jQuery 和 jQuery Tools 库的调用，因此您可以开始同时使用两者。这里是这个示例的关键部分，您可以将其复制粘贴到上面的代码下方：

```js
<script>
$(function(){
$.ajaxSetup({
cache: false,
dataType: "text html"
});
$(".loadingspin").bind('ajaxStart', function(){
$(this).show();
}).bind('ajaxComplete', function(){
$(this).hide();
});
$.fn.loadimage = function(src, f){
return this.each(function(){
$("<img />").attr("src", src).appendTo(this).each(function(){
this.onload = f;
});
});
}
$(".item img:first").load(function(){
var firstpic = $(".item a:first").attr("rel");
$("#caption").text(firstpic);
$("#viewer").empty().loadimage("images/" + firstpic + ".jpg").hide().fadeIn('fast');
});
$(".item a").unbind('click.pic').bind('click.pic', function(e){
e.preventDefault();
var picindex = $(this).attr("rel");
$("#caption").text(picindex);
$("#viewer").empty().loadimage("images/" + picindex + ".jpg").hide().fadeIn('fast');
});
$("#overscroll").scrollable();
$("a.browse").click(function(){
$("#swapframe").load("ajax/" + state + ".html").hide().fadeIn('fast');
});
</script>

```

这段代码提供了画廊和可滚动效果，当您点击 Scrollable 中的缩略图时，它会加载每个图像。您甚至可以添加一个选项效果，当您悬停在图像上时会淡出图像：

```js
<script type="text/javascript">
$(function(){
$('.item').children().hover(function() {
$(this).siblings().stop().fadeTo(500,0.5);
}, function() {
$(this).siblings().stop().fadeTo(500,1);
});
});

```

### 时间展现一些样式

如果您尝试运行以前的代码，它会工作，但看起来很糟糕——会有缺失的图像，并且您无法通过 Scrollable 进行导航，例如。这就是 jQuery Tools 的真正力量发挥作用的地方，大部分真正的工作实际上是在 CSS 样式中完成的：

```js
<style>
#scrollablecontainer { position: relative; top: -30px;
height: 52px; }
/* prev, next, up and down buttons */
a.browse { background:url(hori_large.png) no-repeat;
display: block; float: left; width: 30px; height: 30px;
float: left; margin: 10px; cursor: pointer; font-size: 1px;
}
/* right */
a.right { background-position: 0 -30px; clear: right;
margin-right: 0px;}
a.right:hover { background-position: -30px -30px; }
a.right:active { background-position: -60px -30px; }
/* left */
a.left { margin-left: 0; }
a.left:hover { background-position: -30px 0; }
a.left:active { background-position: -60px 0; }
/* disabled navigational button */
a.disabled { visibility: hidden !important; }
#overscroll { position: relative; float: left; width:
550px; height: 50px; border: 1px solid #ccc;
overflow: hidden; }
.items { position: absolute; clear: both; width: 20000em; }
.item { float: left; width: 550px; }
.item div { float: left; width: 100px; height: 40px;
margin: 5px; background: #ccc; }
</style>

```

这些样式对于设置基本效果非常重要，例如提供导航按钮和可滚动容器。

#### 一些额外的样式

然而，它可能需要一些额外的调整才能真正脱颖而出。现在让我们添加进去：

```js
<link href=
'http://fonts.googleapis.com/css?family=Cedarville+Cursive'
rel='stylesheet' type='text/css'>
<style>
#swapframe { height: 540px; width: 640px;
padding: 25px 25px 0 20px; margin: 0 auto;
background: transparent url(slideshow-bg.gif)
no-repeat; background-size: 680px 540px;}
#viewer { height: 355px; background: #000; }
.loadingspin { float: center; margin-top: auto;
margin-bottom: auto; }
#caption { position: relative; top: -10px; width: 200px;
margin: 0 auto; color: #000; text-align: center;
font-size: 30px; font-family: 'Cedarville Cursive',
cursive; padding-bottom: 35px; }
</style>

```

该代码将转换图库为可用的内容；它甚至包括一个手写字体用于标题，这使用了 Google™ 字体。如果一切顺利，你应该看到像下面这样的东西：

![一些额外的样式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-tl-ui-lib/img/7805_02_03.jpg)

这只是你可以使用滚动条做的一小部分。你可以进一步进行，甚至将滚动条与工具的其他元素结合起来，比如叠加层，这将展示出一个真正令人印象深刻的效果！

# Tabs in action

是时候来看看 jQuery Tools UI 工具部分的第四部分和最后一部分了 - 那就是标签。

标签可以被描述为互联网上最流行的用户界面之一。这是有道理的，因为它们易于使用并且在有限的空间内包含大量信息，然后您可以以更用户友好的方式对其进行组织。让我们稍微详细地看一下它们。

## 用法

标签的基本结构如下：

```js
<!-- the tabs -->
<ul class="tabs">
<li><a href="#">Tab 1</a></li>
<li><a href="#">Tab 2</a></li>
<li><a href="#">Tab 3</a></li>
</ul>
<!-- tab "panes" -->
<div class="panes">
<div>pane 1 content</div>
<div>pane 2 content</div>
<div>pane 3 content</div>
</div>

```

然后通过以下 JavaScript 调用来将它们激活为标签：

```js
$("ul.tabs").tabs("div.panes > div");

```

但是，等等；这不是 Scrollable 的基本代码吗？是的，有些相似之处。但是不，这绝对是标签的代码！这两个工具之间存在一些相似之处，但重要的是要注意它们不能互换使用。

话虽如此，现在是时候开始构建我们的下一个项目了。

## 项目：构建一个滚动幻灯片

我们将使用 Tab's Slideshow 插件的强大功能，构建一个可以在照片库网站上使用的演示文稿。它是一个样式为极化的幻灯片，但带有一些额外的功能。它将使用与 Scrollable 类似的图像，但采用不同的格式 - 这种格式可以很容易地放在大多数网站上。一些知名的互联网公司使用了类似的效果。

### 设置基本的 HTML

首先，让我们打开文本编辑器。从本章开头处复制模板代码，并添加以下行以创建 HTML 基础：

```js
<div id="caption"></div>
<!-- container for the slides -->
<div class="images">
<div>
<img class="slides" src="img/odontoglossum.jpg"
rel="odontoglossum" />
</div>
<div>
<img class="slides" src="img/forest orchid.jpg"
rel="forest orchid" />
</div>
<div>
<img class="slides" src="img/brassia.jpg"
rel="brassia" />
</div>
<div>
<img class="slides" src="img/paphiopedilum.jpg"
rel="paphiopedilum" />
</div>
</div>
<div id="galprevnext">
<div class="galleft">
<a class="galprevpic hideit"></a>
</div>
<div class="galright">
<a class="galnextpic hideit"></a>
</div>
</div>
<!-- the tabs -->
<div class="slidetabs">
<a href="#">1</a>
<a href="#">2</a>
<a href="#">3</a>
<a href="#">4</a>
</div>
<div id="playcontrols">
<img src="img/play.gif" />
<img src="img/stop.gif" />
</div>

```

这可以分为五个不同的部分，即标题、图片容器、画廊控制、选项卡和最后的播放器控制。

### 添加视觉效果

下一部分是非常重要的样式 - 这分为两个部分，首先是极化效果和幻灯片的必需代码：

```js
<link href=
'http://fonts.googleapis.com/css?family=Cedarville+Cursive'
rel='stylesheet' type='text/css'>
<style type="text/css">
body { padding-left:400px; padding-top: 50px; }
/* container for slides */
.images { border: 1px solid #ccc; position: relative;
height: 450px; width: 502px; float: left; margin: 15px;
cursor: pointer;
/* CSS3 tweaks for modern browsers */
-moz-border-radius: 5px;
-webkit-border-radius: 5px;
border-radius: 5px;
-moz-box-shadow: 0 0 25px #666;
-webkit-box-shadow: 0 0 25px #666;
box-shadow: 0 0 25px #666; }
/* single slide */
.images div { display: none; position: absolute; top: 0; left: 0;
margin: 3px; padding: 15px 30px 15px 15px;
height: 256px; font-size: 12px; }
/* tabs (those little circles below slides) */
.slidetabs { position: absolute; margin: 350px 600px 0 440px;
width: 100px; }
/* single tab */
.slidetabs a { width: 8px; height: 8px; float: left; margin: 3px;
background: url(navigator.png) 0 0 no-repeat;
display: block; font-size: 1px; color: #fff; }
/* mouseover state */
.slidetabs a:hover { background-position: 0 -8px; }
/* active state (current page state) */
.slidetabs a.current { background-position: 0 -16px; }
/* prev and next buttons */
.forward, .backward { float: left; margin-top: 120px;
background: #fff url(nav.png) no-repeat;
width: 35px; height: 35px;
cursor: pointer; z-index: 2; }
/* next */
.forward { background-position: -36px 0px ; }
.forward:hover,
.forward:active { background-position: -36px -36px; }
/* prev */
.backward:hover,
.backward:active { background-position: 0 -36px; }
/* disabled navigational button. is not needed when tabs
are configured with rotate: true */
.disabled { visibility: hidden !important; }
#caption { color: black; margin-left: 35px; margin-top: 345px;
position: absolute; width: 200px;
font-family: 'Cedarville Cursive', cursive;
font-size: 26px; }
.slides { border-width: 0; height:310px; width:466px; }
</style>

```

哇，那里有很多样式代码！其中大部分与幻灯片的定位有关，以及提供导航按钮和标题。

### 注意

您将在这里看到 CSS 样式的真正威力，因为极化效果完全是使用 CSS3 代码生成的；正因为如此，它在旧版浏览器中看起来不会那么壮观。但是 jQuery Tools 是关于使用 HTML5（和 CSS3），而不是旧版浏览器。如果需要，您仍然可以通过为合适的背景图像添加适当的样式来解决这个问题。

#### "嗯...我想要更多！"

当我开始为这本书写项目时，我并不完全满意——我想要更多。经过一些重新排列和调整，最终在 jQuery Tools 的另一位用户 Mudimo 的帮助下，我成功地额外添加了一些内容，基于他的一些优秀演示。

第一部分是添加一些按钮来控制幻灯片放映，这些按钮替换了可以添加的标准按钮，这些按钮可以从 jQuery Tools 站点上获得。将以下内容添加为额外的样式：

```js
<style>
#galprevnext { position: absolute; width: 640px; height: 539px; }
.galleftpic, .galrightpic { width: 270px; height: 539px;
cursor: pointer; }
.galleftpic { float: left; }
.galrightpic { float: right; }
.galprevpic, .galnextpic { display: block; position: absolute;
top: 140px; width: 30px; height: 30px;
margin: 0 10px; }
.galprevpic { float: left; background: url(prevnext.png) 0 0
no-repeat; margin-left: 9px; }
.galnextpic { float: right; background: url(prevnext.png)
-30px 0 no-repeat; margin-left: 100px; }
.hideit { visibility: hidden; cursor: arrow; }
.showit { visibility: visible; cursor: pointer; }
#galprevnext a { text-decoration: none; }
#galprevnext a:hover { color: #f00; }
#galprevnext a.current { color: #00f; }
#galprevnext .disabled { visibility: hidden; }
.galleft, .galright { height: 310px; margin-top: 35px;
position: absolute; width: 150px; }
.galleft { margin-left: 35px; }
.galright { margin-left: 360px; }
#playcontrols { clear: both; margin-left: 375px;
margin-top: 350px; padding-right: 40px;
position: absolute; }
</style>

```

您会注意到，这在可能的情况下尽量遵循将图像抽象出主要代码的标准，这是 jQuery Tools 的主要原则之一。他代码的第二部分是添加一点额外的 jQuery，它根据鼠标悬停在按钮上的情况将 CSS 样式从`hideit`更改为`showit`，然后再次更改回来（这两种样式控制按钮的可见性）。作为最后的调整，我们通过用样式化图标替换原始按钮并使用一点 CSS 将其放置在图片下方的导航器“点”旁边来添加一些额外的样式到播放器控件。

### 配置选项卡效果

我们进入代码的最后部分，即添加使所有这些都起作用所需的 JavaScript。将其添加到页面底部：

```js
$(function() {
$(".slidetabs").tabs(".images > div", {
// enable "cross-fading" effect
effect: 'fade',
fadeOutSpeed: "slow",
// start from the beginning after the last tab
rotate: true,
// here is a callback function that is called before the
// tab is clicked
onClick: function(event, tabIndex) {
var str = $("img").eq(tabIndex).attr("rel");
$("#caption").html(str);
}
// use the slideshow plugin, which has its own config
})
.slideshow({
prev: ".galleft",
next: ".galright"
});
});

```

这是代码的至关重要的部分——它配置选项卡效果以使用幻灯片插件，并从代码中提取`rel`标签中的文本，该文本用作标题。请注意，由于下一个和上一个按钮使用非默认 CSS 类名称，因此需要在幻灯片插件的配置选项中设置这些类名称，以便它知道如何正确运作。

#### 设置按钮可见性

还记得我之前决定添加的两个额外按钮吗？代码的接下来两个部分实现了两个目标；第一个控制了这两个按钮的可见性，第二个允许您停止和开始幻灯片放映。

如果我们看一下第一部分，它控制着可见性——jQuery 将样式从`hideit`更改为`showit`，从而在悬停在任何一个按钮上时，将可见性从隐藏更改为可见，然后再次改回隐藏：

```js
$(".galleft").mouseover(function(){
$(".galprevpic").removeClass('hideit').addClass('showit');
}).mouseout(function(){
$(".galprevpic").removeClass('showit').addClass('hideit');
});
$(".galright").mouseover(function(){
$(".galnextpic").removeClass('hideit').addClass('showit');
}).mouseout(function(){
$(".galnextpic").removeClass('showit').addClass('hideit');
});

```

然后，我们需要能够控制幻灯片放映的播放。我们可以通过为两个图像按钮添加事件处理程序来实现，如下所示：

```js
$("#playbutton").click(function(){
$(".slidetabs").data("slideshow").play();
});
$("#stopbutton").click(function(){
$(".slidetabs").data("slideshow").stop();
});

```

至此，如果一切顺利，您应该会看到类似以下截图的内容。jQuery Tools 中可用的工具都是无限可定制的，这个演示只是我们在这本书的框架内可能实现的小例子之一：

![设置按钮可见性](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-tl-ui-lib/img/7805_02_04.jpg)

# 总结

在本章中，我们看了一些使用 jQuery Tools 的主要组件（即 Scrollable、Overlay、Tooltips 和 Tabs）的示例。所有这些组件都可以无限定制，本章讨论的示例概述了如何使用 CSS 对每个工具的基本功能进行最小化，同时每个工具的总体架构允许根据需要进行大量定制，希望这为你的项目提供了一些灵感。

现在我们已经了解了四种主要工具，是时候把注意力转向作为工具库一部分的第二组工具了，即验证器（Validator）、日期输入（DateInput）和范围输入（RangeInput），它们将成为下一章的主题。


# 第三章：表单工具

问问自己一个问题：你喜欢填写表单吗？如果答案像我猜测的那样是否定的，那就加入大部分人的行列吧——没有什么比在网上填表格更糟糕的了，只有发现你输入了错误的内容，然后不得不回去更改…

输入 jQuery Tools 的表单工具！

这组 3 个有用的工具可能不像库中的其他工具那样受欢迎，但它们仍然发挥着重要作用。

在本章中，我们将学习以下内容：

+   如何使用验证器确保表单填写正确，或在不正确填写时显示错误信息

+   如何更新 DateInput 的基本样式，使用 jQuery UI 主题的元素

+   如何将范围输入转换为浏览器，以便您可以浏览一系列产品，并提供一些关于如何将其与其他工具组合使用的提示

那么…你还在等什么？让我们开始看一看验证器吧。

# 使用验证器

验证器可用于确保表单填写正确。验证器还可用于显示错误信息。

## 为什么要使用基本的验证器？

作为维基百科定义的填写表单的艺术，意味着你不能简单地提交任何垃圾的表单，或者说“垃圾进，垃圾出”的说法肯定是正确的。确保你输入的内容至少符合某种最低标准至关重要——其中一个可以帮助实现这一目标的工具是验证器。让我们更详细地看一下工具库中的这个组件。

### 注意

数据验证是确保程序运行在干净、正确和有用数据上的过程。

## 用法

验证器的基本代码分为两部分——第一部分是 HTML 结构，第二部分是对验证器工具的单行调用：

```js
<form id="myform" novalidate="novalidate">
<fieldset>
<h3>Sample registration form</h3>
<p> Enter bad values and then press the submit button. </p>
<p>
<label>email *</label>
<input type="email" name="email" required="required" />
</p>
<p>
<label>website *</label>
<input type="url" name="url" required="required" />
</p>
<p>
<label>name *</label>
<input type="text" name="name" pattern="[a-zA-Z ]{5,}" maxlength="30" />
</p>
<p>
<label>age</label>
<input type="number" name="age" size="4" min="5" max="50" />
</p>
<p id="terms">
<label>I accept the terms</label>
<input type="checkbox" required="required" />
</p>
<button type="submit">Submit form</button>
<button type="reset">Reset</button>
</fieldset>
</form>

```

一旦你设置好表单，接下来你需要在这里添加验证器的调用，以下是基本代码：

```js
$("#myform").validator();

```

### 注意

请注意，这包括在表单上添加`novalidate`属性——这是为了强制 IE 不尝试使用 HTML5 验证器，而是使用 jQuery Tools 中的验证器，这在较新版本的浏览器中起作用。

有了这个想法，让我们通过设置一个演示来实践一下，看看我们如何在表单中使用验证器。

## 项目：改进样式，并添加自定义字段验证器

我们将使用 jQuery Tools 网站提供的现有表单，并通过添加一些额外的验证器和对配置的更改来进行一些调整。

### 创建基本的 HTML 结构

打开你选择的文本编辑器，并复制以下代码进去——你会注意到它遵循了本书中大多数项目的相似模式：

```js
<!DOCTYPE html>
<html>
<head>
<title>jQuery Tools standalone demo</title>
<!-- include the Tools -->
<script src="img/jquery.tools.min.js"></script>
</head>
<body>
</body>
</html>

```

### 添加表单详情

好的。现在我们已经有了基本的结构，让我们开始填充一些细节。首先是表单内容，其中包含我们要验证的字段——所以在`<body>`标签之间复制以下代码：

```js
<form id="myform">
<fieldset>
<h3>Sample registration form</h3>
<span class="errorlabel">Oops - it seems there are some errors! Please check and correct them.</span>
<p> Enter bad values and then press the submit button. </p>
<p>
<label>email *</label>
<input type="email" name="email" id="email" required="required" />
</p>
<p>
<label>website *</label>
<input type="url" name="url" required="required" />
</p>
<p>
<label>name *</label>
<input type="text" name="name" pattern="[a-zA-Z ]{5,}" maxlength="30" />
</p>
<p>
<label>time *</label>
<input type="time" name="time" required="required" data- message="Please enter a valid time"/>
</p>
<p>
<label>age</label>
<input type="number" name="age" size="4" min="5" max="50" />
</p>
<p>
<label>password</label>
<input type="password" name="password" minlength="4" />
</p>
<p>
<label>password check</label>
<input type="password" name="check" data-equals="password" />
</p>
<p>
<label>filename *</label>
<input type="file" name="uploadfile" required="required" />
</p>
<p>
<input type="phone" name="phone" data-message="Please enter a valid US telephone number." required="required" pattern="(?:1-?)?(d{3})[-.]?(d{3})[-.]?(d{4})" />
</p>
<p>
<label>Gender</label>
<select value="" required="required" name="sex">
<option></option>
<option value="male">Male</option>
<option value="female">Female</option>
</select>
</p>
<p id="terms">
<label>I accept the terms</label>
<input type="checkbox" required="required" />
</p>
<button type="submit">Submit form</button>
<button type="reset" id="clearform">Reset</button>
</fieldset>
</form>

```

### 注意

请注意，代码中会出现许多额外的参数，例如电话输入字段中的模式属性。这些参数被 Validator 和/或其额外的自定义验证器用作验证访问网站的人输入的文本的基础。

### 设置表单样式

现在完成了，我们需要添加非常重要的样式 - 请注意，这包括一些额外的样式用于演示目的，但在您的实际项目中并非必需：

```js
<style>
/* body, a:active and : focus only needed for demo; these can be removed for production use */
body { padding: 50px 80px; }
a:active { outline: none; }
:focus { -moz-outline-style: none; }
/* form style */
#myform { background: #333 0 0; padding: 15px 20px; color:
#eee; width: 440px; margin: 0 auto; position: relative;
-moz-border-radius: 5px; -webkit-border-radius: 5px; border- radius: 5px; }
/* nested fieldset */
#myform fieldset { border: 0; margin: 0; padding: 0;
background: #333 url(logo-medium.png) no-repeat scroll
215px 40px; }
/* typography */
#myform h3 { color: #eee; margin-top: 0px; }
#myform p { font-size: 11px; }
/* input field */
#myform input { border: 1px solid #444; background-
color: #666; padding: 5px; color: #ddd; font-size: 12px;
text-shadow: 1px 1px 1px #000; -moz-border-radius: 4px;
-webkit-border-radius: 4px; border-radius: 4px; }
/* take care here: support for :focus and :active limited in some browsers!
#myform input:focus { color: #fff; background-color: #777; }
#myform input:active { background-color: #888; }
/* button */
#myform button { outline: 0; border: 1px solid #666; }
/* error message */
.error { font-size: 11px; color: #f00; display: none; }
.error p { margin:15px; margin-left: 20px; font-weight: bold; background-color: #fff; -moz-border-radius:4px;
-webkit-border-radius: 4px; padding: 2px; border-radius: 4px;}
/* field label */
label { display:block; font-size:11px; color:#ccc; }
#terms label { float: left; }
#terms input { margin: 0 5px; }
.invalid { -moz-box-shadow: 0 0 2px 2px #f00; -webkit-box-shadow: 0 0 2px 2px #f00; box-shadow: 0 0 2px 2px #f00; }
.errorlabel { display: none; font-size: 14px; font-weight: bold; color: #f00; }
.error img { position: absolute; margin: 15px 15px 15px 0;}
.errorhilite { border: 3px solid #f00; }
</style>
</head>

```

### 最终部分 - 脚本

需要的最后一部分是非常重要的脚本，让一切都能运转 - 因为这是一个相当长的脚本，我们将其分成几部分，从验证器开始。

#### 自定义验证器

虽然 Validator 将使用标准的 HTML4 和 HTML5 验证器，但只有在添加自定义验证器时，其功能才真正发挥作用，并且这些自定义验证器不是标准库的一部分。在此演示中，我们有五个自定义验证器的示例，因此将以下代码复制到您的网站中 - 这应该是页面的最后阶段，或者位于`<head>`区域，只要相应地使用`document.ready()`函数即可：

```js
<script>

```

此验证器对`<select>`下拉菜单执行检查：

```js
// custom Validator for <select> dropdowns
$.tools.validator.fn("select", "Select a value", function(input, value) {
return (value == 'none') ? false : true;
});

```

如果您想使用单选按钮，那么这是您需要使用的验证器代码：

```js
// custom Validator for radio buttons
$.tools.validator.fn("[group-required]", "At least one option needs to be selected.", function(input) {
var name = input.attr("group-required");
var group_members = $('input[name=' + name + ']');
var checked_count = group_members.filter(':checked').length;
if((checked_count == 0) && (group_members.first().attr('id') == input.attr('id'))) {
$('input[name=' + name + ']').click(function() {
validate_form.data("validator").reset($('input[name=' + name + ']'));
});
return false;
} else {
return true;
}
});

```

下面的验证器将对有效的时间进行模式匹配：

```js
// custom Validator for "time" input type
$.tools.validator.fn("[type=time]", function(el, value) {
return /^(2[0-4]|[01]?\d):[0-6]\d$/.test(value) ? true : "Please provide a valid time, using military format";
});

```

如果不遵守最小字符长度，此验证器将标记错误：

```js
// custom alidator based on minimum required length
$.tools.validator.fn("[minlength]", function(input, value) {
var min = input.attr("minlength");
if (isNaN(min)) {
return true; // not a valid minlength, so skip validation
} else {
return value.length >= min ? true : {
en: "Please provide at least " +min+ " character" + (min > 1 ? "s" : ""),
fi: "Kentän minimipituus on " +min+ " merkkiä"
};
}
});

```

如果上传的文件类型不是预先确定的类型之一，此验证器将显示错误：

```js
// custom validator based on a required filetype
$.tools.validator.fn("[type=file]", "Please choose a file with an allowed extensions", function(input, value) {
if ($(":file").val() != "") {
return /\.jpg\png\gif\pdf\doc\txt)$/.test(value);
} else {
return true;
}
});

```

验证器脚本的真正核心如下所示，其中包含对 jQuery Tools 的 Validator 功能的调用，以及一些额外的配置选项。依次，它们执行以下操作：

+   `position:` 它控制在屏幕上的位置上文将出现在哪里

+   `speed:` 它决定错误消息出现的速度快慢

+   `offset:` 它与位置一起使用，以微调屏幕上的位置

+   `errorClass` 和 `errorInputEvent:` 用于错误消息的 CSS 样式和输入有效性检查的触发器

+   `message:` 错误消息的文本，包括任何图片（如此处所示）

+   `inputEvent:` 每次用户“失焦”或移开元素时重新验证文本 - 这在特别用于检查`<select>`标签时使用

将此复制到您的脚本部分：

```js
$(document).ready(function () {
$("#myform").validator({
position: 'center right',
speed: 'slow',
offset: [0, 10],
errorClass: 'invalid',
errorInputEvent: 'keyup change',
message: '<div><img src=images/exclamation.png></div>',
inputEvent: "blur"
});
})

```

下一部分执行两个功能 - 第一个是设置验证器自动重新定位错误消息文本，如果窗口大小调整；第二个是在“onFail”触发器上添加红色边框，以便在提交按钮按下时正确验证的字段上：

```js
// get handle to the Validator API
var myForm = $("#myform"), api = myForm.data("validator");
api.reflow();
myForm.bind("onFail", function(e, errors) {
// we are only doing stuff when the form is submitted
if (e.originalEvent.type == 'submit') {
$(".errorlabel").css({ display: 'block'});
// loop through Error objects and add the border color
$.each(errors, function() {
var input = this.input;
input.css( 'errorhilite' ).focus(function() {
input.css( 'errorhilite' );
});
});
}
});

```

此脚本的最后部分是一个重置函数，清除任何验证不正确的字段上设置的红色边框：

```js
$("#clearform").click(function() {
myForm.reset();
$(".errorlabel").css({ display: 'none' });
// loop through Error objects and add the border color
$("input, select").each(function(index) {
$(this).css({ border: '' });
});
});
})
</script>

```

如果一切都正确运行，那么您应该看到类似下一个截图所示的表单。

![自定义验证器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-tl-ui-lib/img/7805_03_01.jpg)

## “这个 onFail 看起来很负面…”

是的，这是真的——Validator 的一个潜在缺点是它确实感觉非常片面，因为它只集中在输入条目失败时。然而，如果验证器确定所涉及的条目符合所需的模式，您可以包含代码来显示确认或消息。

### 注意

您应该注意，这目前仅仅是一个概念；它旨在作为您自己开发的起点，并且在投入生产使用之前需要彻底测试。

要做到这一点，你可以尝试以下方法：

1.  将以下内容添加到您的样式表中：

    ```js
    input.valid {
    background-image: url(images/accept.png);
    background-position: right top;
    background-repeat: no-repeat;
    }
    input.valid.invalid {
    background-image: none;
    }

    ```

1.  将这添加到您对 jQuery 的 JavaScript 调用中：

    ```js
    // use API to assign an event listener
    api.onSuccess(function(e, els) {
    $("input[required]").addClass('valid');
    // we don't want to submit the form. just show events.
    return false;
    });

    ```

1.  将这添加到您的 `reset` 方法的底部：

    ```js
    $('input').removeClass("valid");

    ```

1.  将此行添加到 Validator 的配置设置中：

    ```js
    errorInputEvent: 'keyup change',

    ```

代码并不完美——它有一些 bug，所以应该把它只视为您自己想法的起点。如果您实现了上面的代码，那么您应该会看到类似以下截图的东西：

!["这似乎非常负面，这个 onFail…"](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-tl-ui-lib/img/7805_03_02.jpg)

## Validator——最后的思考

这个演示只是展示了 Validator 能做什么的一小部分——Validator 可以与 jQuery Tools 的 Overlay 功能很好地配合，这样您就可以在对话框中显示错误，后面还有叠加层蒙版，例如。您甚至可以使用 jQuery UI 来提供对话框效果——使用 jQuery UI 的关键是先声明对 jQuery Tools 的调用，然后重新分配 Tools 中的 Tabs 对象以使用不同的命名约定，否则它将与 UI 冲突。

在下一节中，我们将介绍库中另一个重要的工具——DateInput。

# 使用 DateInput 使您的 HTML5 日期输入看起来和行为符合您的要求

HTML5 的出现带来了使用`<input type=date>`的能力，这消除了对额外功能的需求。然而，这仅在有限的范围内可用，因为它仅在 Safari 上有效——jQuery Tools 试图通过 DateInput 来弥补这一缺陷，这使得 HTML5 功能现在可以在所有现代浏览器上使用。让我们看看如何使用它。

## 用法

如果有一个需要最少 JavaScript 的示例，那么这可能是其中之一；DateInput 只需要两个字就可以工作，当然，除了调用库之外！以下是使 jQuery Tools 的 DateInput 工作所需的基本框架：

```js
<!-- include jQuery FORM Tools (or any other combination) -->
<script src="img/ jquery.tools.min.js">
</script>
<!-- dateinput styling -->
<link rel="stylesheet" type="text/css" href="dateinput.css"/>
<!-- HTML5 date input -->
<input type="date" />
<!-- make it happen -->
<script>
$(":date").dateinput();
</script>

```

考虑到这一点，现在是时候看一下使用 DateInput 的项目了——尽管这次，这将是一个有所不同的项目。

## 项目：样式和本地化

在为本书准备演示时，我最初想到的是展示一些 DateInput 功能的东西。然而，反思之后，我想做另一件事，那就是回答这个问题——"是否可以将 jQuery UI 主题的元素与 jQuery Tools 结合起来？"

这的灵感来自于 jQuery UI 提供的主题——主题是 DateInput 缺乏的一个方面。在这个项目中，我们将使用原始外观来为 DateInput 添加一些颜色，并进行本地化调整。

### 创建基本的 HTML

首先，让我们创建基本的 HTML 结构——打开文本编辑器，并将以下行复制为起点：

```js
<!DOCTYPE html>
<html>
<head>
<title>jQuery Tools standalone demo</title>
<!-- include the Tools -->
<script src="img/ jquery.tools.min.js"></script>
<!-- standalone page styling (can be removed) -->
<link rel="stylesheet" type="text/css" href="http:// static.flowplayer.org/tools/css/standalone.css"/>
<link rel="stylesheet" type="text/css" href="http://skin1.css">
<style>
</style>
</head>
<body>
<!-- HTML5 date input -->
<input type="date" name="mydate" data-value: "Today" />
<!-- make it happen -->
<script>
</script>
</body>
</html>

```

好的，这里没有什么复杂的；将其另存为您的基本 HTML 文件的副本，准备添加 CSS 和 JavaScript 代码。您会注意到与本书中其他项目的相似之处，在这些项目中需要最少的 HTML 来构建可用结构——DateInput 也不例外。

### 注意

请注意，这里使用了`<input type="date">`标签——虽然这是有效的 HTML5，但 jQuery 工具的美妙之处在于将其提供给所有现代浏览器，而不仅仅是接受 HTML5 的浏览器。如果由于任何原因 JavaScript 不可用，这实际上对于那些使用 Safari 的人会很好地降级！

### 设置 JavaScript

接下来，让我们添加我们将用于 DateInput 的 JavaScript：

```js
// the french localization
$.tools.dateinput.localize("fr", {
months: 'janvier,f&eacute;vrier,mars,avril, mai,juin,juillet,ao&ucirc;t,' +
'septembre,octobre,novembre,d&eacute;cembre',
shortMonths: 'jan,f&eacute;v,mar,avr,mai,jun, jul,ao&ucirc;,sep,oct,nov,d&eacute;c',
days: 'dimanche,lundi,mardi,mercredi, jeudi,vendredi,samedi',
shortDays: 'dim,lun,mar,mer,jeu,ven,sam'
});
$(":date").dateinput({
format: 'dddd, ddth mmmm yyyy',
lang: 'fr',
offset: [0, 30],
yearRange: [-20, 20]
});

```

这分为两部分——第一部分是 DateInput 的本地化代码，为月份和年份的天提供了法语语言的对应词。这被 DateInput 所使用——要激活它，需要使用`lang`属性，以及适当语言的正确两字母代码。

代码的第二部分是对 DateInput 的调用，其中指定了格式和所需语言（后者使用了本地化代码中的相同代码）。

### 添加样式

这可以说是 DateInput 中最重要的部分——样式。您会注意到在此项目开始时代码中包含了原始的`skin1.css`链接；这是为了说明原始样式可以被覆盖，并且不必总是试图重复发明轮子。您还需要从 jQueryUI 网站下载“Start”主题[`www.jqueryui.com`](http://www.jqueryui.com)；如果使用此样式技术，您需要参考此处，以提取构成您自定义样式的相关 CSS。将下面给出的代码复制到网页中的样式标签中：

```js
// body, a:active and : focus only needed for demo; these can be // removed for production use
body { padding:50px 80px; }
a:active { outline:none; }
:focus { -moz-outline-style:none; }
.date { width: 260px; }
#calroot { width:210px; }
#calhead { background: url("ui-bg_gloss- wave_75_2191c0_500x100.png") repeat-x scroll 50% 50% #2191C0;
border: 1px solid #4297D7; color: #EAF5F7; font-weight:
bold; -moz-border-radius: 4px; -webkit-border-radius:
4px; border-radius: 4px; }
#caltitle { font-size:14px; float:left; text-align:center;
width: 155px; line-height: 20px; color: #EAF5F7; font-
weight: bold; }
#calnext, #calprev { display:block; width: 16px; height:
20px; float:left; cursor:pointer; margin-top: 2px; }
#calnext {
background:transparent url(ui-icons_056b93_256x240.png)
no-repeat scroll center center; background-position:
-48px -192px; float:right; margin-right: 4px; }
#calprev {
background:transparent url(ui-icons_056b93_256x240.png)
no-repeat scroll center center; background-position:
-78px -192px; margin-left: 4px; }
#caldays { margin-top: 3px; }
#caldays span { display: block; float: left; width: 30px; text-align: center; }
/* single day */
.calweek a { background: url("ui-bg_gloss- wave_75_2191c0_500x100.png") repeat-x scroll 50% 50% #0078AE;
border: 1px solid #77D5F7; -moz-border-radius: 3px;
-webkit-border-radius: 3px; border-radius: 3px;
color: #FFFFFF; display: block; float: left; font-size: 11px;
font-weight: normal; height: 18px; line-height: 20px;
margin-left: 2px; outline: medium none; text-align:
center; text-decoration: none; width: 26px; }
/* current day */
#calcurrent, #caltoday {
background: url("ui-bg_gloss-wave_50_6eac2c_500x100.png")
repeat-x scroll 50% 50% #6EAC2C; border: 1px solid #ACDD4A; color: #FFF; font-weight: normal; outline: medium none; z-index:9999; }
/* today */
#caltoday {
background: url("images/ui-bg_gloss- wave_45_e14f1c_500x100.png") repeat-x scroll 50% 50% #6EAC2C;
border: 1px solid #ACDD4A; color: #000;
}

```

如果一切顺利，您将拥有一个外观类似于 jQuery UI 版本的日历，但可能没有相同数量的代码！以下是您应该看到的屏幕截图：

![添加样式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-tl-ui-lib/img/7805_03_03.jpg)

## 最后的想法

上面的代码并不完美——它是设计的一个概念，展示了在 DateInput 中使用 jQuery UI 主题元素时可能出现的情况。jQuery UI 有许多可用的主题，可以轻松地使用这些元素在您的代码中提供类似的效果。关键是要明白，我没有使用 jQuery UI 的 JavaScript，因为这会给您的网站添加大量额外的代码，这与 jQuery Tools 的整体理念相违背。尽管如此，没有什么能阻止您使用主题中的元素！

在主要的 jQuery Tools 网站上可以下载一个`skin`文件的最简版本—在某些方面，您可能会发现从这个版本开始工作比调整现有主题更可取。然而，这将大部分取决于您想要进行的更改—如果您没有进行太多更改，那么简单地覆盖现有的`skin`文件可能更明智，而不是为自己创建额外的工作。

# 用 RangeInput 控制您的 HTML5 范围输入

HTML5 的出现带来了许多可以与`<input>`命令一起使用的附加类型，例如`<input type="range">`。虽然这对开发人员来说可能是个好消息，但对于那些仍然必须使用旧浏览器的人来说，情况就不那么乐观了，因为这种效果只能在最新版本的浏览器中原生支持。

进入 jQuery Tools 的 RangeInput，它使得相同效果在所有浏览器中都可用（除了 IE5 和 IE6，因为这两个浏览器的市场份额现在已经很小，不支持这两个浏览器不会影响大多数网站的受众）。

## 为什么选择基本的 RangeInput？

jQuery Tools 旨在规范 HTML5 的`<input type="range">`功能在所有现代浏览器中的使用，以便在它被官方发布时就可以使用，并且大多数浏览器都默认支持它。由于 jQuery Tools 将大部分样式和内在功能抽象成了其 CSS 中，所以只需删除这一部分，即可使 HTML5 功能正常工作。

让我们更深入地了解一下，在正常环境中它是如何工作的。

## 使用

所有工具都遵循相同的基本原则，即需要最少的 JavaScript 来运行，而 CSS 样式提供了真正的功能——RangeInput 也不例外。基本格式分为三个部分—第一个是链接到提供 RangeInput 所需样式的 CSS，第二个是至少一个`<input>`语句（下面的代码显示了两个—同样的原则适用于两者），然后是从 Tools 库中调用 RangeInput：

```js
<!-- styling for the range -->
<link rel="stylesheet" type="text/css" href="range.css"/>
<!-- a couple of HTML5 range inputs with standard attributes -->
<input type="range" name="range1" min="50" max="500" step="20" value="100" />
<input type="range" name="range2" min="0" max="1500" step="50" value="450" />
<!-- select all range inputs and make them ranges -->
<script>
$(":range").rangeinput();
</script>

```

现在，大多数人可能认为 RangeInput 实际上应该用于从网站上显示的预设比例中获得一个值。这是一个完全合理的假设，但只是 RangeInput 可以做的一小部分。为了证明这一点，让我们看看构建可滚动产品画廊的项目——这个项目将显示一些书籍，可以轻松地用于零售网站，例如 Packt 的网站。

## 项目：构建产品画廊

我们将构建一个基本的可滚动产品画廊，这种样式曾经被 PC 制造商 Apple™在几年前使用过。这个项目的灵感来自于在线教程，来自[`jqueryfordesigners.com/slider-gallery/`](http://jqueryfordesigners.com/slider-gallery/) ，该教程解释了如何使用 jQuery 创建类似效果——这是一个展示 jQuery Tools 的 RangeInput 多功能性以及如何使用它产生相同效果的完美借口！

尽管基本框架将保持不变，但您随时可以根据需要轻松修改样式。让我们从设置基本结构开始。

### 设置基本的 HTML 结构

打开您选择的文本编辑器，并插入以下行，然后将其保存为您的 HTML 页面：

```js
<!DOCTYPE html>
<html>
<head>
<title>jQuery Tools standalone demo</title>
<!-- include the Tools -->
<script src="img/jquery.min.js">
</script>
<script src="img/rangeinput.js"></script>
</head>
<body>
<div id="wrap">
<!-- our scrollable element -->
<div id="scrollwrap">
<div id="scroll">
<ul>
</ul>
</div>
</div>
<!-- rangeinput that controls the scroll -->
<input type="range" max="2600" step="10" />
</div>
<script>
</script>
</body>
</html>

```

现在，我们有了基本的框架，让我们开始添加内容。

### 注意

您会注意到，在演示中，我们直接链接到了托管在 Github 上的 Tools 源文件。这是可以接受的，但仅供开发目的使用；如果您在生产环境中使用此内容，您将需要切换到使用 CDN 链接之一，或下载库的副本。

### 添加书籍图片

接下来是我们需要添加的书籍图片；我们总共使用 30 张。如果您想使用较少的图片，则可能需要修改滑块周围的样式，以适应所使用的图片数量的变化。

在您的代码中在`<ul> </ul>`标签之间添加以下内容：

```js
<li><img src="img/4569.jpg" /><span class="textfont">Test Book 1 </span></li>
<li><img src="img/6860.jpg" /><span>Test Book 2</span></li>
<li><img src="img/4408.jpg" /><span>Test Book 3</span></li>
<li><img src="img/6785.jpg" /><span>Test Book 4</span></li>
<li><img src="img/2305.jpg" /><span>Test Book 5</span></li>
<li><img src="img/1925.jpg" /><span>Test Book 6</span></li>
<li><img src="img/1308.jpg" /><span>Test Book 7</span></li>
<li><img src="img/5108.jpg" /><span>Test Book 8</span></li>
<li><img src="img/6884.jpg" /><span>Test Book 9</span></li>
<li><img src="img/4323.jpg" /><span>Test Book 10</span></li>
<li><img src="img/4569.jpg" /><span>Test Book 11</span></li>
<li><img src="img/6860.jpg" /><span>Test Book 12</span></li>
<li><img src="img/4408.jpg" /><span>Test Book 13</span></li>
<li><img src="img/6785.jpg" /><span>Test Book 14</span></li>
<li><img src="img/2305.jpg" /><span>Test Book 15</span></li>
<li><img src="img/1925.jpg" /><span>Test Book 16</span></li>
<li><img src="img/1308.jpg" /><span>Test Book 17</span></li>
<li><img src="img/5108.jpg" /><span>Test Book 18</span></li>
<li><img src="img/6884.jpg" /><span>Test Book 19</span></li>
<li><img src="img/4323.jpg" /><span>Test Book 20</span></li>
<li><img src="img/4569.jpg" /><span>Test Book 21</span></li>
<li><img src="img/6860.jpg" /><span>Test Book 22</span></li>
<li><img src="img/4408.jpg" /><span>Test Book 23</span></li>
<li><img src="img/6785.jpg" /><span>Test Book 24</span></li>
<li><img src="img/2305.jpg" /><span>Test Book 25</span></li>
<li><img src="img/1925.jpg" /><span>Test Book 26</span></li>
<li><img src="img/1308.jpg" /><span>Test Book 27</span></li>
<li><img src="img/5108.jpg" /><span>Test Book 28</span></li>
<li><img src="img/6884.jpg" /><span>Test Book 29</span></li>
<li><img src="img/4323.jpg" /><span>Test Book 30</span></li>

```

### 注意

在此示例中，我们使用 Packt 网站的图片——如果您愿意，您可以自由选择其他图片，但您需要保持相似的大小，或者调整样式以适应。

### 添加 JavaScript 功能

让我们继续添加 JavaScript 功能：

```js
// get handle to the scrollable DIV
var scroll = $("#scroll");
// initialize rangeinput
$(":range").rangeinput({
// slide the DIV along with the range using jQuery's css() method
onSlide: function(ev, step) {
scroll.css({left: -step + "px"});
},
// display progressbar
progress: true,
// the DIV is animated when the slider is clicked: function(e, i) {
scroll.animate({left: -i + "px"}, "fast");
},
// disable drag handle animation when slider is clicked
speed: 0
});

```

上面的代码创建了内部“滚动”`DIV`（即`#scroll`），然后使用 CSS 将其移动到适当的左右位置；这是通过使用 jQuery 的`.animate()`函数来提供更平滑的移动效果来实现的。

### 为画廊设置样式

在这个阶段，如果您运行代码，您将看不到太多的工作——因为 jQuery Tools 的真正威力实际上在于应用的 CSS 样式。

```js
<style>
// body, a:active and : focus only needed for demo; these can be // removed for production use
body { padding:50px 80px; }
a:active { outline:none; }
focus { -moz-outline-style:none; }
#wrap {
background:url("images/productbrowser.jpg") no-repeat scroll 0 0 transparent;
}
/* outermost element for the scroller (stays still) */
#scrollwrap {
position: relative;
overflow: hidden;
width: 620px;
height: 150px;
margin-bottom: 15px;
-moz-box-shadow: 0 0 20px #666;
-webkit-box-shadow: 0 0 20px #666;
border-radius: 4px 4px 0 0;
}
/* the element that moves forward/backward */
#scroll {
position:relative;
width:20000em;
overflow: hidden;
padding: 20px 100px;
height: 160px;
color: #fff;
text-shadow: 5px 1px 1px #000;
left: -100px;
}
#scroll span {
font-weight:bold;
font-family: sans-serif;
font-size: 12px;
float: left;
padding-right: 72px;
width: 30px;
}
slider {
background: transparent url("images/bkgrdhandle.png") no-repeat scroll 0 0 transparent;
position: relative;
cursor: pointer;
height: 17px;
width: 580px;
-moz-border-radius: 2px;
-webkit-border-radius: 2px;
border-radius: 2px
margin-top: -10px;
padding: 3px;
margin-left: 16px;
background-size: 581px auto;
}
handle {
-moz-border-radius: 14px;
-webkit-border-radius: 14px;
border-radius: 14px;
cursor: move;
display: block;
height: 18px;
position: absolute;
top: 0; width: 181px;
background: url("images/scroller.png") no-repeat scroll
0 0 transparent;
}
handle:active {
background-color: #00f;
}
range {
display:none;
}
#scroll ul {
list-style: none outside none;
margin: 0;
padding: 0;
position: absolute;
white-space: nowrap;
left: 40px;
}
#scroll ul li {
display: inline;
width: 80px;
}
#scroll ul li img {
padding-right: 20px;
}
</style>

```

如果一切正常，那么一旦您添加了样式，您应该会看到类似于这样的内容：

![为画廊设置样式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-tl-ui-lib/img/7805_03_04.jpg)

## 一些最后的评论

虽然这是为 30 本书的图像构建的，但这可能轻松地成为任何产品的图像——关键是确保使用的图像大小相同，或者调整 CSS 以确保宽度均匀。jQuery Tools 的美妙之处在于虽然 JavaScript 被保持最小化，几乎每个元素都可以使用 CSS 进行调整——RangeInput 也不例外。需要注意的是，尽管在此演示中使用了一些 CSS3 样式，但您可能会发现在一些旧版浏览器中无法运行；这是在您网站中使用此效果时要牢记的事情。毕竟，jQuery Tools 的核心理念是不断推进使用更多的 CSS3。

# 摘要

在本章中，我们看了一下 jQuery Tools 中三个不太为人知但依然重要的组件，即 Validator、DateInput 和 RangeInput。虽然这些组件可能不像其他组件那样广为人知或使用，但它们同样强大，特别是当你使用 CSS 进行自定义时，它们同样可以通过 jQuery 进行扩展（其他组件也可以）。我们稍微理论性地瞥了一眼如何使用 jQuery UI 中的元素来设置 DateInput 的样式——这里的效果可能需要一些调整；但仍然是展示可以做什么的有用方式，如果还使用了其他 jQuery UI 主题的元素的话。

在本书的第四和最后一章中，我们将深入探讨 Expose 和 FlashEmbed 的世界，它们本身并不一定单独使用，但仍然是 jQuery Tools 库的重要组成部分。
